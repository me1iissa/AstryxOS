//! Physical Memory Manager (PMM)
//!
//! Uses a bitmap allocator to track physical page frames (4 KiB each).
//! Processes the UEFI memory map to find usable regions.

use astryx_shared::{BootInfo, MemoryType};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// ── H2 diagnostic: recent-free ring ─────────────────────────────────────────
//
// Tracks the last RECENT_FREE_CAP frames returned to the PMM, together with
// the tick at which they were freed.  When `alloc_page_locked` hands out a
// frame, it checks whether that same frame appears in the ring within the last
// RECENT_FREE_WINDOW_TICKS ticks.  A hit means a frame was recycled too soon
// — the time-axis manifestation of H2 (TLB shootdown declared clean before
// invalidation committed, frame returned to PMM, re-allocated, alias stale
// TLB still points at it for the original virtual address).
//
// The ring is protected by PMM_LOCK (already held at every alloc_page_locked
// and free_page call), so no additional synchronisation is needed.
//
// RECENT_FREE_WINDOW_TICKS: 10 ms at TICK_HZ = 100 → 1 tick.  Using 2 ticks
// for safety margin; matches the W203 1 ms historical threshold scaled to the
// quarantine grace-period (≥1 full tick guaranteed by `on_cpu_tick`).

#[cfg(feature = "firefox-test-core")]
const RECENT_FREE_CAP: usize = 64;

#[cfg(feature = "firefox-test-core")]
const RECENT_FREE_WINDOW_TICKS: u64 = 2;

#[cfg(feature = "firefox-test-core")]
#[derive(Copy, Clone)]
struct RecentFreeEntry { phys: u64, freed_tick: u64 }

#[cfg(feature = "firefox-test-core")]
struct RecentFreeRing {
    entries: [RecentFreeEntry; RECENT_FREE_CAP],
    next: usize,
}

#[cfg(feature = "firefox-test-core")]
impl RecentFreeRing {
    const fn new() -> Self {
        Self {
            entries: [RecentFreeEntry { phys: 0, freed_tick: 0 }; RECENT_FREE_CAP],
            next: 0,
        }
    }
    fn push(&mut self, phys: u64, tick: u64) {
        self.entries[self.next] = RecentFreeEntry { phys, freed_tick: tick };
        self.next = (self.next + 1) % RECENT_FREE_CAP;
    }
    /// Return the entry for `phys` if it was freed within `window` ticks of
    /// `now`, or `None`.
    fn find(&self, phys: u64, now: u64, window: u64) -> Option<u64> {
        for e in &self.entries {
            if e.phys == phys && e.freed_tick != 0
                && now.saturating_sub(e.freed_tick) <= window
            {
                return Some(e.freed_tick);
            }
        }
        None
    }
}

#[cfg(feature = "firefox-test-core")]
// See FREE_SHADOW in mm/w215_diag.rs for a parallel direct-addressed
// tracer; future consolidation opportunity.
static RECENT_FREE_RING: Mutex<RecentFreeRing> = Mutex::new(RecentFreeRing::new());

/// H2 diagnostic counter: physical frames re-allocated within
/// `RECENT_FREE_WINDOW_TICKS` ticks of their most recent free.  A non-zero
/// value indicates that the PMM is recycling frames faster than the
/// quarantine grace-period guarantees — the time-axis condition for H2.
#[cfg(feature = "firefox-test-core")]
pub(crate) static PMM_ALLOC_RECENT_FREE: AtomicU64 = AtomicU64::new(0);

/// Page size: 4 KiB.
pub const PAGE_SIZE: usize = 4096;

/// Maximum physical memory we track: 4 GiB (1M pages).
const MAX_PAGES: usize = 1024 * 1024;

/// Bitmap: 1 bit per page. MAX_PAGES / 8 bytes.
const BITMAP_SIZE: usize = MAX_PAGES / 8;

/// Static bitmap for physical page tracking.
/// 0 = free, 1 = used/reserved.
static mut BITMAP: [u8; BITMAP_SIZE] = [0xFF; BITMAP_SIZE]; // Start all as used

/// Physical span (inclusive page bounds, byte addresses) reserved for the
/// UEFI bootstrap stack at `init`.  Zero until `init` runs (or when the live
/// stack is already higher-half, e.g. under the test harness).  Exposed via
/// [`bootstrap_stack_phys_span`] for the regression test and diagnostics.
static BOOTSTRAP_STACK_PHYS_FIRST: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static BOOTSTRAP_STACK_PHYS_LAST: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Lock for bitmap operations.
static PMM_LOCK: Mutex<()> = Mutex::new(());

/// Number of times [`alloc_page`] found the bitmap full and fell through to
/// the OOM killer.  Drives the rate-limited `[PMM/EXHAUSTED]` line and is read
/// by Test 750; monotone since boot.
static PMM_EXHAUSTED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Snapshot of [`PMM_EXHAUSTED_TOTAL`].
pub fn exhausted_count() -> u64 {
    PMM_EXHAUSTED_TOTAL.load(Ordering::Relaxed)
}

/// Total pages the allocator manages: every frame the firmware memory map
/// reported as `Available`, counted once at [`init`] and constant thereafter.
///
/// This is a property of the machine, not of occupancy — boot-time
/// reservations (kernel image, BootInfo, low 1 MiB, bootstrap stack, the
/// static kernel heap) do **not** subtract from it.  They are counted in
/// [`USED_PAGES`] and [`RESERVED_PAGES`] instead; see the accounting
/// invariant on [`USED_PAGES`].
static TOTAL_PAGES: AtomicU64 = AtomicU64::new(0);

/// Frames inside the [`TOTAL_PAGES`] domain whose bitmap bit is currently
/// set — allocated **and** reserved alike.
///
/// # Accounting invariant
///
/// ```text
/// free_page_count() == #{ p < MAX_PAGES : BITMAP bit p is clear }
/// ```
///
/// i.e. `TOTAL_PAGES - USED_PAGES` equals the number of frames `alloc_page`
/// can actually hand out.  `alloc_page` succeeds or fails on the bitmap
/// alone, so a counter that does not track the bitmap exactly is a counter
/// that reports free memory the allocator cannot produce.  Every path that
/// sets a bit must add here, and every path that clears one must subtract:
///
/// * [`alloc_page_locked`] / [`alloc_pages`] — `+1` / `+count`
/// * [`free_page`] — `-1`, and deliberately *not* on the refusal arms:
///   kernel-static, residual PTE refs and DMA-pinned leave the bit set, and
///   the double-free arm finds it already clear (see [`PMM_FREE_ALREADY_FREE`])
/// * the boot reservations in [`init`] and [`reserve_range`] — `+n` for the
///   `n` frames whose bit each one newly set
///
/// The bitmap starts entirely set (`0xFF`), so frames outside the firmware's
/// `Available` regions are never clear and never enter this count in either
/// direction.
static USED_PAGES: AtomicU64 = AtomicU64::new(0);

/// The subset of [`USED_PAGES`] that is permanently reserved rather than
/// dynamically allocated: the kernel image, the BootInfo handoff pages, the
/// low 1 MiB, the UEFI bootstrap stack, and every [`reserve_range`] caller
/// (the static kernel heap and its guard frames).
///
/// These frames are real RAM the allocator can never hand out, so
/// `/proc/meminfo` subtracts them from `MemTotal` — proc(5) defines
/// `MemTotal` as "total usable RAM (i.e., physical RAM minus a few reserved
/// bits and the kernel binary code)".  They stay inside [`TOTAL_PAGES`] and
/// [`USED_PAGES`] because the allocator's own invariant is about bitmap bits,
/// not about who owns them.
static RESERVED_PAGES: AtomicU64 = AtomicU64::new(0);

/// Next-fit cursor: byte index into BITMAP to start the next search.
/// Avoids O(N) scans from 0 when low physical frames are all in use.
static NEXT_FIT_BYTE: AtomicU64 = AtomicU64::new(0);

/// Diagnostic counter (firefox-test only): number of times `alloc_page`
/// returned a frame whose refcount was already non-zero at the moment of
/// allocation.  A non-zero count is a direct indicator of H1 (cache-vs-PMM
/// bitmap drift): the PMM believes a frame is free (bitmap bit clear) but
/// the refcount table still holds a live reference — indicating the previous
/// owner never called `page_ref_dec` before the frame was recycled.
#[cfg(feature = "firefox-test-core")]
static PMM_ALLOC_NONZERO_RC: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of `free_page` calls that were refused because the
/// frame still had residual PTE references (`pte_share_count > 0`) at the
/// moment of free.  Each refusal also leaks the frame for the remainder of
/// the boot — that is the conservative, race-free choice when the
/// invariant fails: the frame may still be reached through a stale PTE on
/// some sibling CPU, so handing it back to the allocator would resurface
/// the W215 use-after-recycle fault.
///
/// Always 0 on builds without the assertion (none currently; the assertion
/// is unconditional because the cost is a single atomic load on the free
/// path, dwarfed by the bitmap-clear under PMM_LOCK).
static PMM_FREE_RESIDUAL_REFS: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of `free_page` calls refused because the frame lies
/// inside the running kernel's own image (`.text`/`.rodata`/`.data`/`.bss`
/// — see `is_kernel_static_phys`). Every increment identifies a caller that
/// reached the free path (directly or via a "refcount hit zero" check) for
/// a frame the PMM must never recycle: kernel-static frames are mapped
/// read-only into user address spaces (`KUSER_SHARED_DATA`, vDSO) without
/// ever being `page_ref_inc`'d, so a refcount of zero is their PERMANENT
/// steady state, not a signal that the frame is free. This guard is the
/// single chokepoint that makes that distinction authoritative regardless
/// of which unmap/teardown path reached here — see `free_page`'s doc
/// comment for the full rationale. Always 0 in a correctly-behaving build;
/// a nonzero value means some path still needs its own backing-type check
/// tightened (this counter catches it without the frame ever actually
/// leaving the reserved pool).
static PMM_FREE_KERNEL_STATIC_REFUSED: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of [`free_page`] calls refused because the frame's
/// bitmap bit was already clear — i.e. a double free, or a free of a frame
/// inside the firmware `Available` domain that was never allocated.
///
/// Clearing an already-clear bit is idempotent, but the matching
/// `USED_PAGES` decrement is not: without this guard each such call
/// permanently raises the reported free-frame count by one while the bitmap
/// stands still, which is exactly the counter-vs-bitmap drift the accounting
/// invariant on [`USED_PAGES`] exists to exclude — reintroduced one page at a
/// time and invisibly, because the boot-time drift check has long since run.
///
/// Refusing the free instead makes a double free a detectable no-op: the
/// counter stays exact, the frame is not handed out twice, and every
/// increment here names a caller that freed a frame it did not own.  Always 0
/// in a correctly-behaving build.
static PMM_FREE_ALREADY_FREE: AtomicU64 = AtomicU64::new(0);

// ── Kernel image linker symbols ────────────────────────────────────────────
//
// The bootloader passes `kernel_size = kernel_data.len()`, which is the size
// of `kernel.bin` — a flat binary produced by `objcopy -O binary` from the
// ELF.  Per the ELF specification (System V ABI, ELF gABI §4, "Sections"),
// `objcopy -O binary` writes only sections that have both `SHF_ALLOC` and
// non-zero file content (i.e. `.text`, `.rodata`, `.data`, and instrumented
// coverage sections).  Sections of type `SHT_NOBITS` — notably `.bss` — are
// allocated at runtime but carry no file image, so their extent is **not**
// reflected in the flat binary's length and therefore not in `kernel_size`.
//
// The kernel linker script (`kernel/linker.ld`) exports `__kernel_end` as a
// 4 KiB-aligned symbol immediately after `.bss`, which is the true upper
// bound of the kernel image in physical memory.  Using it here closes the
// gap where BSS pages would otherwise be left in the PMM's free pool and
// handed out to subsequent allocators — producing frame aliasing between
// kernel statics and any in-memory page-cache, mmap, or per-process page
// table that subsequently allocates them.
//
// Reference: Intel SDM Vol. 3A §4.10.5 (paging-structure coherence) — frames
// backing kernel-resident structures must remain reserved against PMM
// recycling for the lifetime of any mapping that uses them.
extern "C" {
    static __kernel_end: u8;
}

/// Physical base address of the kernel image, latched in `init` from
/// `boot_info.kernel_phys_base`.  A value of 0 means PMM has not yet been
/// initialised.  Used by the W215 cache::insert protector.
static KERNEL_IMAGE_PHYS_BASE: AtomicU64 = AtomicU64::new(0);

/// Exclusive physical end of the kernel image (incl. .bss), latched in
/// `init` from the `__kernel_end` linker symbol.
static KERNEL_IMAGE_PHYS_END: AtomicU64 = AtomicU64::new(0);

/// Returns `(phys_base, phys_end_exclusive)` of the kernel image, in bytes.
/// Both values are page-aligned.  Returns `(0, 0)` if PMM is not yet
/// initialised; callers must treat that as "no protection active".
pub fn kernel_image_phys_range() -> (u64, u64) {
    (
        KERNEL_IMAGE_PHYS_BASE.load(Ordering::Relaxed),
        KERNEL_IMAGE_PHYS_END.load(Ordering::Relaxed),
    )
}

/// True if `phys` lies inside the kernel image's physical range (.text /
/// .rodata / .data / .bss), as latched at PMM init from the linker symbol.
///
/// The caller passes a page-aligned phys; the check is range-only, no
/// section discrimination (the kernel image is contiguous in physical
/// memory per the linker script + AstryxBoot handoff).
pub fn is_kernel_static_phys(phys: u64) -> bool {
    let base = KERNEL_IMAGE_PHYS_BASE.load(Ordering::Relaxed);
    let end = KERNEL_IMAGE_PHYS_END.load(Ordering::Relaxed);
    base != 0 && end != 0 && phys >= base && phys < end
}

/// Compute the inclusive `[first_page, last_page]` PMM page indices and
/// total byte size of the BootInfo struct at `BOOT_INFO_PHYS_BASE`, given
/// the compile-time `size_of::<BootInfo>()`.
///
/// Returns `(first_page, last_page, bytes)`.  Exposed for tests verifying
/// the CWE-787 fix (Test 267): the helper returns the same span used by
/// `init` to reserve BootInfo pages, plus the byte count so callers do not
/// duplicate the `size_of::<BootInfo>()` call site.  A caller may check
/// `last >= first + 1` to assert that BootInfo spans more than one page
/// (the structural condition that motivated the fix).
///
/// Uses `saturating_sub(1)` defensively: a zero-byte BootInfo is
/// structurally impossible (the struct has named fields), but the
/// arithmetic is hardened so a compiler bug or `#[repr(packed)]`
/// regression cannot produce a wrap to `u64::MAX` here.
pub fn boot_info_phys_page_span() -> (usize, usize, u64) {
    let bytes = core::mem::size_of::<BootInfo>() as u64;
    let first = (astryx_shared::BOOT_INFO_PHYS_BASE / PAGE_SIZE as u64) as usize;
    let last = ((astryx_shared::BOOT_INFO_PHYS_BASE + bytes.saturating_sub(1))
        / PAGE_SIZE as u64) as usize;
    (first, last, bytes)
}

/// Inclusive `(first_phys, last_phys)` byte-address span reserved for the UEFI
/// bootstrap stack at `init`, or `(0, 0)` if no firmware stack was reserved
/// (the live stack was already higher-half — e.g. under the test harness).
///
/// The BSP idle thread (TID 0) executes on this stack for the lifetime of the
/// system (the bootloader never installs a fresh stack and `proc::init` never
/// migrates TID 0 off it), so every page in this span MUST stay reserved
/// against the page allocator — handing one out lets its new owner overwrite
/// TID 0's saved `switch_context` frame and tear the next resume.
pub fn bootstrap_stack_phys_span() -> (u64, u64) {
    (
        BOOTSTRAP_STACK_PHYS_FIRST.load(Ordering::Relaxed),
        BOOTSTRAP_STACK_PHYS_LAST.load(Ordering::Relaxed),
    )
}

/// Runtime backstop for the bootstrap-stack reservation: verify the live RSP
/// still lies within the reserved span.
///
/// The reservation in [`init`] picks a fixed downward window below the RSP it
/// observed at PMM-init time.  Every later boot phase grows the BSP stack
/// *below* that point; if any descends past the reserved floor, that frame is a
/// FREE bootstrap-stack page the allocator could recycle — silently
/// re-introducing the torn-`switch_context`-frame fault.  Call this at the
/// deepest init point (the bottom of `kernel_main`-phase bring-up) so any
/// shortfall is a loud bugcheck rather than an intermittent recycle months
/// later.  No-op when no firmware-stack span was recorded (higher-half live
/// stack, e.g. the test harness) or when the live stack is already higher-half.
#[inline(never)]
pub fn bootstrap_stack_assert_rsp_reserved() {
    let (first, last) = bootstrap_stack_phys_span();
    if first == 0 && last == 0 {
        return; // no firmware stack reserved — nothing to police
    }
    let rsp: u64;
    // SAFETY: reading the stack pointer has no side effects.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)); }
    if rsp == 0 || rsp >= astryx_shared::KERNEL_VIRT_BASE {
        return; // live stack is higher-half (already PMM-reserved by construction)
    }
    // `last` is the first byte of the last reserved page; admit the whole page.
    let lo = first;
    let hi = last + (PAGE_SIZE as u64 - 1);
    if rsp < lo || rsp > hi {
        crate::ke::bugcheck::ke_bugcheck(
            crate::ke::bugcheck::BUGCHECK_BAD_KERNEL_RSP,
            rsp,
            lo,
            hi,
            0,
        );
    }
}

/// True if the page index is currently marked used in the PMM bitmap.
///
/// Intended for test assertions only.  Production code should not rely
/// on the bitmap state directly; allocate via `alloc_page` and inspect
/// the returned phys.  Takes the PMM lock internally.
pub fn is_page_used_for_test(page: usize) -> bool {
    if page >= MAX_PAGES {
        return false;
    }
    let _lock = PMM_LOCK.lock();
    // SAFETY: lock held, page index just bounds-checked.
    unsafe { is_page_used_locked(page) }
}

/// Initialize the PMM from the UEFI memory map.
pub fn init(boot_info: &BootInfo) {
    let _lock = PMM_LOCK.lock();
    let mut total_available = 0u64;
    // Frames this function reserves out of the `Available` domain.  Counted
    // here and published to RESERVED_PAGES/USED_PAGES at the end, rather than
    // subtracted from `total_available`: see the invariant on `USED_PAGES`.
    let mut boot_reserved = 0u64;

    for i in 0..boot_info.memory_map.entry_count as usize {
        let entry = &boot_info.memory_map.entries[i];

        if entry.memory_type == MemoryType::Available {
            let start_page = (entry.physical_start / PAGE_SIZE as u64) as usize;
            let page_count = entry.page_count as usize;

            for page in start_page..start_page + page_count {
                if page < MAX_PAGES {
                    // Count each frame once even if two map entries overlap:
                    // the bitmap starts all-set, so a frame already flipped
                    // free by an earlier entry is already in the tally.
                    // SAFETY: lock held, page index bounds-checked above.
                    unsafe {
                        if !is_page_used_locked(page) {
                            continue;
                        }
                        mark_page_free(page);
                    }
                    total_available += 1;
                }
            }
        }
    }

    // Compute the true kernel-image extent.
    //
    // The bootloader passes `kernel_size = kernel.bin file length`, which
    // omits the .bss section (NOBITS — no file content).  Read `__kernel_end`
    // from the linker script and translate its higher-half VMA back to its
    // physical LMA via `__kernel_end - KERNEL_VIRT_BASE`.  Take the maximum
    // of the bootloader-reported extent and the linker-derived extent so
    // either source can safely overstate (e.g. if the bootloader counts a
    // padded LOADER_DATA region) and the reservation still covers BSS.
    let kernel_start_phys = boot_info.kernel_phys_base;
    let bss_kernel_end_va = unsafe { &__kernel_end as *const u8 as u64 };
    let bss_kernel_end_phys = bss_kernel_end_va
        .saturating_sub(astryx_shared::KERNEL_VIRT_BASE);
    let bin_kernel_end_phys = kernel_start_phys.saturating_add(boot_info.kernel_size);
    let kernel_end_phys = core::cmp::max(bin_kernel_end_phys, bss_kernel_end_phys);
    let image_bytes = kernel_end_phys.saturating_sub(kernel_start_phys);

    crate::serial_println!(
        "[PMM] Kernel image: phys_base={:#x} bin_end={:#x} bss_end={:#x} reserved_end={:#x} ({} KiB)",
        kernel_start_phys,
        bin_kernel_end_phys,
        bss_kernel_end_phys,
        kernel_end_phys,
        image_bytes / 1024,
    );

    // Latch the kernel image phys range for the W215 cache::insert protector.
    // Uses the BSS-inclusive `kernel_end_phys` so the protector covers the
    // full kernel image including zero-initialised statics.
    KERNEL_IMAGE_PHYS_BASE.store(kernel_start_phys, Ordering::Relaxed);
    KERNEL_IMAGE_PHYS_END.store(kernel_end_phys, Ordering::Relaxed);

    // Mark kernel region as used (kernel image incl. .bss + 256 pages slack
    // for BootInfo and early structures placed past __kernel_end).
    let kernel_start = (kernel_start_phys / PAGE_SIZE as u64) as usize;
    let kernel_pages = ((image_bytes + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;
    for page in kernel_start..kernel_start + kernel_pages + 256 {
        if page < MAX_PAGES {
            // SAFETY: We hold the PMM lock and page is in bounds.
            //
            // Only frames that were free (i.e. inside the `Available` domain
            // and not already reserved) count towards `boot_reserved` — a
            // frame the firmware never offered was never in `total_available`
            // and must not be counted as used against it.
            unsafe {
                if !is_page_used_locked(page) {
                    mark_page_used(page);
                    boot_reserved += 1;
                }
            }
        }
    }

    // Reserve every page that backs the BootInfo struct (CWE-787 fix).
    //
    // The bootloader writes BootInfo at `BOOT_INFO_PHYS_BASE` (a fixed offset
    // past the kernel image).  UEFI's `ExitBootServices` memory map (UEFI
    // §7.2, `GetMemoryMap`) reports the underlying region as
    // `EfiBootServicesData`, which our converter maps to `Available` — so
    // without an explicit reservation the pages backing BootInfo can be
    // handed out to later allocators (heap, page-table walker, COW pool).
    //
    // BootInfo is *not* a single page.  Per `astryx_shared::BootInfo`, the
    // struct embeds `MemoryMapInfo { entries: [MemoryMapEntry; 256], .. }`.
    // With the current type layout (`MemoryMapEntry` = 24 B; 256 entries =
    // 6144 B; plus framebuffer + magic + entry_count + auxiliary u64s) the
    // total `size_of::<BootInfo>()` is ~6.2 KiB — straddling two 4 KiB
    // pages.  Reserving only the first page leaves the tail page eligible
    // for the heap allocator's linked-list metadata, which then clobbers
    // `framebuffer.{width,height,stride}` and the back end of
    // `memory_map.entries[]` (CWE-787, Out-of-Bounds Write of allocator
    // metadata into a structurally live but un-reserved region).
    //
    // Compute the inclusive page span: every page from
    // `BOOT_INFO_PHYS_BASE / PAGE_SIZE` through
    // `(BOOT_INFO_PHYS_BASE + size_of::<BootInfo>() - 1) / PAGE_SIZE`
    // inclusive, and mark them all used.  The size is known at compile
    // time, so no dependence on `boot_info.memory_map.entry_count` (the
    // entries array is statically sized at `MAX_MEMORY_MAP_ENTRIES = 256`
    // regardless of how many entries the bootloader populated).
    //
    // Threat model:
    //   - CWE-787 (Out-of-bounds Write) — heap allocator's intrusive
    //     freelist metadata is written into the un-reserved tail page of
    //     BootInfo, corrupting `framebuffer` and `memory_map` fields.
    //   - Manifests under heavy-diagnostic feature combinations
    //     (`firefox-test` + `w215-diag` + `d7-bss-watch` / `f3-watch`)
    //     where BSS extent pushes the dynamically-computed heap base into
    //     a range that intersects the un-reserved tail page.
    //
    // Refs: UEFI Specification §7.2 (GetMemoryMap / EfiBootServicesData);
    //       Intel SDM Vol. 3A §4.10.5 (paging-structure coherence — frames
    //       backing live kernel structures must remain reserved against
    //       PMM recycling).  See also defensive framebuffer-dimension
    //       clamp in `kernel/src/main.rs` (PR #371), retained as defence
    //       in depth: after this fix it is a no-op in practice but stays
    //       to bound the blast radius of any future similar oversight.
    // Single source-of-truth for the BootInfo phys span — `boot_info_phys_page_span`
    // owns the `size_of::<BootInfo>()` computation so call sites cannot
    // drift out of sync.
    let (boot_info_first_page, boot_info_last_page, boot_info_bytes) =
        boot_info_phys_page_span();
    let mut boot_info_reserved_pages = 0u64;
    for page in boot_info_first_page..=boot_info_last_page {
        if page < MAX_PAGES {
            // SAFETY: We hold the PMM lock and page is in bounds.
            //
            // `mark_page_used` is idempotent against an already-used bit
            // (it ORs the bit in), so any page already covered by the
            // kernel-image reservation above is harmless to re-mark.  We
            // still count towards `boot_reserved` only pages that were
            // previously free.
            //
            // The `is_page_used_locked == true` branch is silently no-op
            // (the bit is already set, idempotent OR); we just don't bump
            // `boot_info_reserved_pages` because that counter is "newly
            // reserved by this block" for the diagnostic line below.
            unsafe {
                if !is_page_used_locked(page) {
                    mark_page_used(page);
                    boot_reserved += 1;
                    boot_info_reserved_pages += 1;
                }
            }
        }
    }
    crate::serial_println!(
        "[PMM] BootInfo reservation: phys=[{:#x}..{:#x}) size={} B \
         pages={}..={} newly_reserved={} (CWE-787 fix)",
        astryx_shared::BOOT_INFO_PHYS_BASE,
        astryx_shared::BOOT_INFO_PHYS_BASE + boot_info_bytes,
        boot_info_bytes,
        boot_info_first_page,
        boot_info_last_page,
        boot_info_reserved_pages,
    );

    // Mark first 1 MiB as reserved (BIOS, VGA, etc.)
    //
    // Parts of this span are typically reported `Available` by the firmware
    // map, so it can take real frames out of `total_available`; the rest was
    // never offered and is already set.  Counting only the newly-set bits
    // keeps `boot_reserved` equal to the number of `Available` frames this
    // function withdrew.
    for page in 0..256 {
        // SAFETY: We hold the PMM lock and page is in bounds.
        unsafe {
            if !is_page_used_locked(page) {
                mark_page_used(page);
                boot_reserved += 1;
            }
        }
    }

    // Reserve the UEFI bootstrap stack against the PMM (torn-switch-frame fix).
    //
    // The bootloader `jmp`s to the kernel WITHOUT installing a fresh stack, so
    // the kernel — and forever after the BSP idle thread (TID 0) — executes on
    // the firmware-provided stack (UEFI §2.3.4: the boot-time stack lives in
    // EfiBootServicesData / EfiConventionalMemory).  Our memory-map converter
    // reports that region as `Available`, so the loop above just marked the
    // bootstrap-stack pages FREE.  Under heavy allocation pressure the PMM then
    // hands one of those physical frames to a user/heap allocation whose owner
    // overwrites it — while TID 0's saved `switch_context` frame still lives on
    // that very stack.  The next resume of TID 0 restores a torn frame
    // (garbage RSP/RIP) and faults.  By design TID 0 never migrates off this
    // stack (see `proc::init` / `main`), so the frames must be reserved.
    //
    // We are executing on the bootstrap stack right now, so the live RSP names
    // a page inside it.  Reserve a generous window: a few pages above the
    // current frame (the firmware's own callers, already unwound but still part
    // of the allocation) and the full kernel-stack span below it — every later
    // boot phase (`syscall::init`, `vfs::init`, the scheduler bring-up, …) grows
    // the stack *below* this point, and all of those frames belong to TID 0's
    // permanent stack and must stay reserved.  The window is bounded and one-
    // shot; over-reserving a handful of conventional pages is harmless.
    //
    // Only meaningful when the live stack is identity-mapped (RSP < the
    // higher-half base): in `test-mode` the harness may already be on a
    // higher-half kernel stack, in which case there is no firmware stack to
    // reserve and we skip — the reservation is purely additive and SMP-count
    // independent, so it is a behaviour-preserving no-op there and on SMP=1.
    {
        let rsp: u64;
        // SAFETY: reading the stack pointer has no side effects.
        unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)); }
        if rsp != 0 && rsp < astryx_shared::KERNEL_VIRT_BASE {
            // Pages above the current frame (firmware callers) + a generous
            // span below it.  The BSP never leaves this stack, and every later
            // boot phase (`syscall::init`, `vfs::init`, the GUI/X11 bring-up
            // with on-stack page buffers, …) descends *below* this frame, so
            // the downward reservation must comfortably exceed the deepest
            // `kernel_main` frame.  128 pages (512 KiB) is twice the kernel's
            // own per-thread kernel-stack budget (`proc::KERNEL_STACK_PAGES`
            // = 64 pages / 256 KiB), which already bounds the deepest call
            // chain any single thread is allowed to reach — so a frame below
            // this floor would be a stack-overflow bug in its own right.
            // `bootstrap_stack_contains_rsp` provides a loud runtime backstop
            // at the deepest init point so any shortfall is a bugcheck, never
            // a silent recycle.  4 pages above covers the firmware's residual
            // (already-unwound) frames.
            const ABOVE_PAGES: u64 = 4;
            const BELOW_PAGES: u64 = 128;
            let cur_page = rsp / PAGE_SIZE as u64;
            let first = cur_page.saturating_sub(BELOW_PAGES);
            let last = cur_page.saturating_add(ABOVE_PAGES);
            let mut reserved = 0u64;
            for page in first..=last {
                let p = page as usize;
                if p == 0 || p >= MAX_PAGES {
                    continue;
                }
                // SAFETY: lock held, index bounds-checked above.
                unsafe {
                    if !is_page_used_locked(p) {
                        mark_page_used(p);
                        reserved += 1;
                        boot_reserved += 1;
                    }
                }
            }
            BOOTSTRAP_STACK_PHYS_FIRST.store(first * PAGE_SIZE as u64, Ordering::Relaxed);
            BOOTSTRAP_STACK_PHYS_LAST.store(last * PAGE_SIZE as u64, Ordering::Relaxed);
            crate::serial_println!(
                "[PMM] Bootstrap stack reserved: rsp={:#x} phys=[{:#x}..={:#x}] newly_reserved={} (torn-frame fix)",
                rsp,
                first * PAGE_SIZE as u64,
                last * PAGE_SIZE as u64,
                reserved,
            );
        }
    }

    // Publish the counters together, and only now — every reservation above
    // has already run, so `USED_PAGES` starts life agreeing with the bitmap
    // instead of being zeroed on top of frames that are already withdrawn.
    // (Zeroing it here is what previously made the counters report the
    // boot reservations — most of it the static kernel heap — as free.)
    TOTAL_PAGES.store(total_available, Ordering::Relaxed);
    USED_PAGES.store(boot_reserved, Ordering::Relaxed);
    RESERVED_PAGES.store(boot_reserved, Ordering::Relaxed);

    crate::serial_println!(
        "[PMM] Initialized: {} MiB usable RAM ({} pages), {} MiB reserved at boot \
         ({} pages), {} MiB allocatable",
        total_available * 4 / 1024,
        total_available,
        boot_reserved * 4 / 1024,
        boot_reserved,
        total_available.saturating_sub(boot_reserved) * 4 / 1024,
    );
}

/// Inner bitmap search for a single free page.
/// Caller must hold PMM_LOCK.
///
/// # Safety
/// Caller must hold PMM_LOCK.  The bitmap is accessed without bounds checking
/// on the page index, but `byte_idx * 8 + bit` is always < MAX_PAGES because
/// `byte_idx < BITMAP_SIZE` and `bit < 8`.
unsafe fn alloc_page_locked() -> Option<u64> {
    let start_byte = NEXT_FIT_BYTE.load(Ordering::Relaxed) as usize;

    // Two-pass search: start from cursor, wrap around if needed.
    for pass in 0..2 {
        let begin = if pass == 0 { start_byte } else { 0 };
        let end   = if pass == 0 { BITMAP_SIZE } else { start_byte };
        for byte_idx in begin..end {
            if BITMAP[byte_idx] != 0xFF {
                for bit in 0..8u64 {
                    if BITMAP[byte_idx] & (1 << bit) == 0 {
                        let page = byte_idx * 8 + bit as usize;
                        mark_page_used(page);
                        USED_PAGES.fetch_add(1, Ordering::Relaxed);
                        // Advance cursor past this byte for next call.
                        let next = (byte_idx + 1) % BITMAP_SIZE;
                        NEXT_FIT_BYTE.store(next as u64, Ordering::Relaxed);
                        let phys = (page * PAGE_SIZE) as u64;
                        // W215 diagnostic Arm-1: record the ALLOC event.
                        #[cfg(feature = "firefox-test-core")]
                        crate::mm::w215_diag::prov_record(
                            phys, crate::mm::w215_diag::KIND_ALLOC, 0,
                        );
                        // Track K (2026-05-20): record the alloc in the
                        // direct-addressed ALLOC_SHADOW alongside the hashed
                        // ring above.  Symmetric to `free_shadow_record`
                        // (Phase D); together they reconstruct the
                        // FREE→ALLOC chain for a specific phys (per Intel
                        // SDM Vol. 3A §4.10.5 the most-recent alloc is the
                        // upstream of any use-after-recycle observable at
                        // the current rip_phys).
                        #[cfg(feature = "firefox-test-core")]
                        {
                            let rip = caller_rip();
                            crate::mm::w215_diag::alloc_shadow_record(phys, rip);
                        }
                        // H1 diagnostic: check whether this frame still
                        // carries a live refcount — a mismatch between the
                        // PMM bitmap (free) and the refcount table (in-use).
                        // Gated on firefox-test to keep production builds
                        // identical.
                        #[cfg(feature = "firefox-test-core")]
                        {
                            let rc = crate::mm::refcount::page_ref_count(phys);
                            if rc != 0 {
                                let total = PMM_ALLOC_NONZERO_RC
                                    .fetch_add(1, Ordering::Relaxed) + 1;
                                // Log first 8, then every 1000th occurrence.
                                if total <= 8 || total % 1000 == 0 {
                                    crate::serial_println!(
                                        "[PMM/ALLOC-NONZERO-RC] pfn={} phys={:#x} rc_at_alloc={} count_total={}",
                                        page, phys, rc, total,
                                    );
                                }
                            }
                        }
                        // H2 diagnostic: check if this frame was freed very
                        // recently (within RECENT_FREE_WINDOW_TICKS).  Uses
                        // `try_lock` to avoid holding two spinlocks; a missed
                        // check under contention is acceptable for a diagnostic.
                        #[cfg(feature = "firefox-test-core")]
                        if let Some(mut ring) = RECENT_FREE_RING.try_lock() {
                            let now = crate::arch::x86_64::irq::TICK_COUNT
                                .load(Ordering::Relaxed);
                            if let Some(freed_tick) =
                                ring.find(phys, now, RECENT_FREE_WINDOW_TICKS)
                            {
                                let total = PMM_ALLOC_RECENT_FREE
                                    .fetch_add(1, Ordering::Relaxed) + 1;
                                let delta_ticks = now.saturating_sub(freed_tick);
                                // 1 tick ≈ 10 ms at TICK_HZ=100; express
                                // delta in µs for readability (approximate).
                                let delta_us = delta_ticks.saturating_mul(10_000);
                                crate::serial_println!(
                                    "[PMM/ALLOC-RECENT-FREE] phys={:#x} \
                                     freed_at_tick={} now_tick={} \
                                     delta_us\u{2248}={} count_total={}",
                                    phys, freed_tick, now, delta_us, total
                                );
                                // Clear the matched entry so it doesn't
                                // double-count on the next allocation of the
                                // same frame.
                                for e in ring.entries.iter_mut() {
                                    if e.phys == phys { e.phys = 0; break; }
                                }
                            }
                        }
                        return Some(phys);
                    }
                }
            }
        }
    }

    None
}

/// Allocate a single physical page frame.
/// Returns the physical address, or None if out of memory.
///
/// Uses a next-fit cursor so repeated allocations don't scan from address 0
/// each time.  This is critical for performance when the low physical frames
/// are permanently occupied (kernel, page cache).
///
/// On first failure the OOM killer is invoked and the allocation is retried
/// once after giving the scheduler a brief window to reap the killed process.
/// If the retry also fails, None is returned (or the caller may panic — that
/// is preserved from whatever the caller was already doing).
///
/// Side effect: every call also drives [`crate::mm::dma_pin`]'s opportunistic
/// deferred-free sweep (`dma_pin::drain_deferred_if_due`), tick-throttled to
/// at most once per ~1 s system-wide. This is unrelated to the requested
/// allocation itself — see that function's doc for why it lives here — and
/// is cheap (a single relaxed load-and-compare) on every call where the
/// interval isn't due.
pub fn alloc_page() -> Option<u64> {
    // Opportunistic, tick-throttled sweep of the DMA-pin deferred-free ring
    // (~once/second) — closes the "device went idle right after an
    // ISR-context reclaim" gap without a block-layer-specific idle hook. See
    // `dma_pin::drain_deferred_if_due` for why this lives on the allocator's
    // hot path: it is cheap when not due, and fires independent of disk I/O.
    crate::mm::dma_pin::drain_deferred_if_due();

    // Fast path: try the normal allocation first.
    {
        let _lock = PMM_LOCK.lock();
        // SAFETY: We hold the PMM lock.
        if let Some(addr) = unsafe { alloc_page_locked() } {
            return Some(addr);
        }
    } // release lock before calling OOM killer

    // Slow path: bitmap is full.  Announce it BEFORE calling the OOM killer:
    // every diagnostic downstream of this point (the `[OOM]` lines) is emitted
    // by code that has to acquire a lock first, so a kernel that exhausts
    // memory while that lock is contended produces no evidence at all that it
    // ran out.  This line is the one signal that cannot be swallowed.
    // Rate-limited (first 8, then every 1024th) so a sustained-pressure
    // workload does not turn COM1 into the bottleneck.
    {
        let total = PMM_EXHAUSTED_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if total <= 8 || total % 1024 == 0 {
            crate::serial_println!(
                "[PMM/EXHAUSTED] alloc_page found no free frame — invoking OOM killer; \
                 count_total={}",
                total,
            );
        }
    }

    // Invoke the OOM killer, yield briefly so the scheduler can run SIGKILL
    // handling, then retry once.
    if crate::mm::oom::invoke_oom_killer(1).is_some() {
        // Spin a moment to let the killed process's exit path run.  We cannot
        // call schedule() here because alloc_page() may be called from paths
        // that hold other locks.  A short spin is acceptable: SIGKILL takes
        // effect on the next scheduler tick, which fires within ~10 ms.
        for _ in 0..100_000u32 {
            core::hint::spin_loop();
        }

        // Retry once after the OOM event.
        let _lock = PMM_LOCK.lock();
        // SAFETY: We hold the PMM lock.
        return unsafe { alloc_page_locked() };
    }

    None
}

/// Best-effort caller-RIP capture used by the residual-PTE-reference
/// diagnostic.  Walks one frame up using `rbp`; if the prologue did not
/// save RBP (LTO / `-fomit-frame-pointer`) this returns 0 — the
/// `[PMM/PTE-REFS]` line is still useful from the phys + residual count
/// alone.  Diagnostic-only.
///
/// Defensive range check: kernel stacks live in the higher-half
/// direct-map at `[KERNEL_VIRT_OFFSET, KERNEL_VIRT_OFFSET + 4 GiB)`
/// (see `kernel/src/proc/mod.rs::alloc_kernel_stack` and
/// `mm/pmm.rs::MAX_PAGES`).  A bare "higher-half" check accepts any
/// VA ≥ 0xFFFF_8000_0000_0000 — including unmapped holes between the
/// direct map, the kernel heap, and per-CPU regions.  If bookkeeping
/// corruption ever placed RBP into one of those holes, the
/// `read_volatile` below would page-fault in kernel mode (likely
/// fatal during a diagnostic that exists to AID triage of a separate
/// fault).  Restricting RBP to the direct-map range keeps the read
/// safe: every address in `[KERNEL_VIRT_OFFSET, +4 GiB)` is mapped by
/// the higher-half PML4 entries set up at boot.
#[inline(never)]
fn caller_rip() -> u64 {
    let rbp: u64;
    // SAFETY: reading the frame pointer is always safe; the subsequent
    // dereference is guarded by alignment + range checks below.
    unsafe {
        core::arch::asm!(
            "mov {}, rbp",
            out(reg) rbp,
            options(nomem, nostack, preserves_flags),
        );
    }
    // Direct-map bounds: 4 GiB of physical RAM identity-mapped into
    // the higher half (MAX_PAGES * PAGE_SIZE = 4 GiB).
    const DIRECT_MAP_BASE: u64 = crate::proc::KERNEL_VIRT_OFFSET;
    const DIRECT_MAP_END:  u64 = DIRECT_MAP_BASE + (MAX_PAGES * PAGE_SIZE) as u64;
    if rbp == 0
        || (rbp & 7) != 0
        || rbp < DIRECT_MAP_BASE
        || rbp.saturating_add(8) >= DIRECT_MAP_END
    {
        return 0;
    }
    // [rbp+8] = saved return address into `free_page`'s caller.
    // SAFETY: rbp + 8 has passed the direct-map range + alignment
    // guard above; the entire direct-map window is mapped via the
    // higher-half PML4 entries.
    unsafe { core::ptr::read_volatile((rbp + 8) as *const u64) }
}

/// Free a physical page frame.
///
/// ## W215 PTE-share-count free-time invariant
///
/// A physical frame must not return to the PMM free list while any user
/// PTE still references it (see [`crate::mm::refcount::pte_share_count`]
/// for the full invariant statement).  If the residual PTE-reference
/// count is non-zero at the moment of free, the frame is **quarantined**
/// — not returned to the allocator — for the remainder of the boot.
/// This is the conservative choice: a stale PTE on some sibling CPU may
/// still map a user VA to `phys`, so returning the frame to the allocator
/// would let it be repurposed under that live PTE.  The frame is
/// effectively leaked, but the alternative (use-after-recycle) is the
/// W215 fault class itself.
///
/// Per Intel SDM Vol. 3A §4.10.5 (paging-structure changes must be
/// propagated to all processors before the physical frame is repurposed)
/// and POSIX mmap(2) (user-visible page contents must remain valid for
/// the lifetime of the mapping), the only safe outcome under residual
/// references is to keep the frame out of circulation.
///
/// Every `[PMM/PTE-REFS]` line emitted here identifies a real upstream
/// bug: a caller cleared a PTE without the matching `page_ref_dec`, or
/// dropped a `page_ref_inc` somewhere along the install path.  The
/// caller-RIP captured in the line is the locus of the upstream fix.
pub fn free_page(phys_addr: u64) {
    let page = (phys_addr / PAGE_SIZE as u64) as usize;
    if page >= MAX_PAGES {
        return;
    }

    // Kernel-static-frame free refusal — checked FIRST, before the bitmap is
    // touched, because every present-PTE-based teardown path funnels through
    // this one function to actually recycle a frame: process exit's VMA
    // walk (`proc::free_process_memory`/`free_vm_space`, which DOES consult
    // VMA backing type), but also `sys_munmap`'s raw-PTE
    // `vmm::unmap_and_free_range_in` — which runs AFTER the VMA record has
    // already been dropped (`VmSpace::remove_range`) and so has no backing
    // type left to consult — plus `mremap` and `madvise(MADV_DONTNEED/FREE)`,
    // which take the same backing-agnostic raw-PTE path. A kernel-static
    // frame (e.g. `KUSER_SHARED_DATA`, mapped read-only into every Win32
    // process at a fixed VA — see `proc::usermode::create_win32_process`)
    // is present in a user PTE without ever being `page_ref_inc`'d, so its
    // refcount reads 0 from the moment it is first mapped: to every one of
    // those raw-PTE paths, "refcount hit zero" is indistinguishable from
    // "genuinely last reference dropped". Tagging the owning VMA
    // `VmBacking::Device` (as `sysv_shm` and `kuser_shared`'s installer do)
    // fixes the VMA-aware paths, but a single enum tag cannot reach a path
    // that no longer has the VMA to read. This range check is the actual
    // authority: it refuses the free regardless of which path — existing or
    // future — reached here, closing the class in one place rather than at
    // each call site individually. Pure comparison against two relaxed
    // atomic loads (`is_kernel_static_phys`): no lock is taken and no
    // freelist state is touched before the refusal, so it cannot introduce
    // a new interaction with the PMM's free-list/bitmap race surface.
    if is_kernel_static_phys(phys_addr) {
        let total = PMM_FREE_KERNEL_STATIC_REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
        if total <= 16 || total % 1000 == 0 {
            let (base, end) = kernel_image_phys_range();
            crate::serial_println!(
                "[PMM/KERNEL-STATIC] refusing free of phys={:#x} — inside kernel image \
                 [{:#x}, {:#x}); refused_total={}",
                phys_addr, base, end, total,
            );
        }
        return;
    }

    // W215 PTE-share-count free-time invariant — see function-level doc.
    // The check is performed BEFORE the bitmap is cleared so that a
    // refused free leaves no PMM-side state change.  An out-of-range
    // page (caught above) and a phys backed by a refcount slot whose
    // bookkeeping has never been touched (kernel-static, page-table
    // levels, sysv_shm Device frames) both load 0 — the assertion is
    // a no-op for them.
    let residual = crate::mm::refcount::pte_share_count(phys_addr);
    if residual > 0 {
        let total = PMM_FREE_RESIDUAL_REFS.fetch_add(1, Ordering::Relaxed) + 1;
        let rip = caller_rip();
        // Log first 16 fires, then every 1000th, to bound serial bandwidth
        // under a sustained-fault workload while keeping the smoking-gun
        // line visible during normal triage.
        if total <= 16 || total % 1000 == 0 {
            crate::serial_println!(
                "[PMM/PTE-REFS] refusing free of phys={:#x} — residual \
                 pte_share_count={} caller_rip={:#x} refused_total={}",
                phys_addr, residual, rip, total,
            );
        }
        // Quarantine the frame for the remainder of the boot: do NOT
        // clear the bitmap bit, do NOT decrement USED_PAGES.  The frame
        // stays out of the allocator's free pool — leaked, but safe.
        return;
    }

    // DMA-in-flight deferred-free invariant.  A block driver that exposed this
    // frame to a device (its physical address is programmed into a live
    // descriptor) holds a DMA pin on it until the device retires the request.
    // Per VIRTIO 1.2 §2.7.13.3 the device may read or write the buffer at any
    // time until it returns the chain via the used ring (§2.7.14), so returning
    // the frame to the allocator now would let it be repurposed under an
    // in-flight device transfer — a DMA-buffer use-after-free.  Atomically
    // record the free request against the pin; if the frame is pinned the free
    // is DEFERRED (the last unpin returns it to the PMM) and we return here
    // without touching the bitmap.  The check-and-mark is a single CAS so it
    // cannot race the last unpin (see `dma_pin::mark_free_pending_if_pinned`).
    if crate::mm::dma_pin::mark_free_pending_if_pinned(phys_addr) {
        return;
    }

    // Phase D (2026-05-20) — record the upstream unmap path in the per-phys
    // event ring AND the dedicated direct-addressed free-shadow BEFORE the
    // bitmap clear so that a concurrent fault-site dump always observes the
    // FREE event before the frame is reachable from the next
    // `alloc_page_locked` cursor advance.  Reading RBP via `caller_rip()` is
    // safe outside any lock — it touches only the current kernel stack,
    // which is the calling thread's own.  Per Intel SDM Vol. 3A §4.10.5,
    // the most-recent free of a physical frame is the most-likely upstream
    // of a W215-class use-after-recycle, so this record is the key evidence
    // for localising anonymous-VMA recurrences (where the cache-key
    // bucket-A path cannot fire because the VMA has `VmBacking::Anonymous`).
    //
    // The 256-bucket × 16-slot `PROV_TABLE` ring is too small to retain a
    // FREE event for the duration of a typical Firefox-musl boot's
    // ~1000-syscall window: Phase D's first trial confirmed an EMPTY ring
    // for the fault's `rip_phys` (the original FREE / REFINC / ALLOC
    // events had been rotated out by ~16 unrelated phys in the same hash
    // bucket).  The dedicated `FREE_SHADOW` (`free_shadow_record`) uses
    // direct `pfn % 64K` addressing — no hash-bucket eviction — so any
    // per-pfn collision is recorded as a displacement counter increment
    // rather than silent data loss.  At 64 Ki slots × 24 bytes = 1.5 MiB
    // BSS, the cost is material only in `firefox-test` builds.
    #[cfg(feature = "firefox-test-core")]
    {
        let rip = caller_rip();
        crate::mm::w215_diag::prov_record_free(phys_addr, rip);
        crate::mm::w215_diag::free_shadow_record(phys_addr, rip);
    }

    // Double-free refusal.  `mark_page_free` is an AND-NOT and is therefore
    // idempotent; the `USED_PAGES` decrement below is not.  Freeing a frame
    // whose bit is already clear would leave the bitmap unchanged while
    // raising the counter-derived free count by one — the counter-vs-bitmap
    // drift the accounting invariant on `USED_PAGES` forbids, reintroduced a
    // page at a time and undetectably (the boot-time check ran long ago).
    // None of the refusals above can stand in for this one: they test frame
    // *identity* (`page >= MAX_PAGES`, kernel-static, residual PTE refs,
    // DMA-pinned), never the frame's current bitmap state.
    //
    // The test-and-clear and the counter update happen inside the one
    // `PMM_LOCK` hold, so `accounting_snapshot_locked` — which reads counters
    // and bitmap under that same lock — can never observe a half-applied free.
    let _lock = PMM_LOCK.lock();
    // SAFETY: PMM_LOCK is held and `page < MAX_PAGES` was checked on entry.
    let already_free = unsafe {
        if is_page_used_locked(page) {
            mark_page_free(page);
            USED_PAGES.fetch_sub(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    };
    if already_free {
        // Release before reporting: the serial path takes its own lock, and
        // nothing below this point applies to a refused free anyway.  The
        // success path keeps the hold to the end of the function exactly as
        // before, so the recent-free ring is still published before a
        // concurrent `alloc_page` can acquire the lock and hand the frame out.
        drop(_lock);
        let total = PMM_FREE_ALREADY_FREE.fetch_add(1, Ordering::Relaxed) + 1;
        if total <= 16 || total % 1000 == 0 {
            crate::serial_println!(
                "[PMM/DOUBLE-FREE] refusing free of phys={:#x} — bitmap bit already \
                 clear; caller_rip={:#x} refused_total={}",
                phys_addr, caller_rip(), total,
            );
        }
        return;
    }

    // H2 diagnostic: record this free in the recent-free ring so that
    // a rapid re-allocation of the same frame triggers PMM_ALLOC_RECENT_FREE.
    #[cfg(feature = "firefox-test-core")]
    if let Some(mut ring) = RECENT_FREE_RING.try_lock() {
        let tick = crate::arch::x86_64::irq::TICK_COUNT
            .load(Ordering::Relaxed);
        ring.push(phys_addr, tick);
    }
}

/// Allocate `count` contiguous physical pages.
/// Returns the physical address of the first page.
pub fn alloc_pages(count: usize) -> Option<u64> {
    if count == 0 {
        return None;
    }

    let _lock = PMM_LOCK.lock();

    // SAFETY: We hold the PMM lock. Linear search for contiguous free pages.
    unsafe {
        let mut start = 0;
        let mut found = 0;

        for page in 0..MAX_PAGES {
            let byte_idx = page / 8;
            let bit = page % 8;

            if BITMAP[byte_idx] & (1 << bit) == 0 {
                if found == 0 {
                    start = page;
                }
                found += 1;
                if found == count {
                    // Mark all pages as used
                    for p in start..start + count {
                        mark_page_used(p);
                    }
                    USED_PAGES.fetch_add(count as u64, Ordering::Relaxed);
                    return Some((start * PAGE_SIZE) as u64);
                }
            } else {
                found = 0;
            }
        }
    }

    None
}

/// Reserve a physical address range so `alloc_page` will never hand it out.
///
/// Used to protect memory that is implicitly mapped by the bootloader's
/// 2 MiB huge pages (e.g., the kernel heap's backing physical range).
///
/// End-exclusive, idempotent, and **accounted**: every frame whose bit this
/// call newly sets is added to both `USED_PAGES` and `RESERVED_PAGES`, so the
/// counters keep agreeing with the bitmap (see the invariant on
/// [`USED_PAGES`]).  Re-reserving an already-reserved frame counts nothing.
///
/// The dominant caller is `mm::vmm::init`, which reserves the static kernel
/// heap — hundreds of MiB on a heavy-render build.  Before this was counted,
/// `stats()` and everything derived from it (`/proc/meminfo`, `kdb
/// heap-stats`) reported that entire span as free memory the allocator could
/// hand out, which it never could.
pub fn reserve_range(start: u64, end: u64) {
    let _lock = PMM_LOCK.lock();
    let start_page = (start / PAGE_SIZE as u64) as usize;
    let end_page = ((end + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;
    let mut newly_reserved = 0u64;
    for page in start_page..end_page {
        if page < MAX_PAGES {
            // SAFETY: We hold the PMM lock and page is in bounds.
            unsafe {
                if !is_page_used_locked(page) {
                    mark_page_used(page);
                    newly_reserved += 1;
                }
            }
        }
    }
    if newly_reserved > 0 {
        USED_PAGES.fetch_add(newly_reserved, Ordering::Relaxed);
        RESERVED_PAGES.fetch_add(newly_reserved, Ordering::Relaxed);
    }
}

/// Get memory statistics: `(total_pages, used_pages)`.
///
/// `total_pages` is all firmware-usable RAM; `used_pages` counts allocated
/// **and** boot-reserved frames.  `total - used` is therefore exactly what
/// `alloc_page` can still hand out — see the invariant on [`USED_PAGES`].
/// Callers that want proc(5) `MemTotal` semantics (usable RAM minus the
/// kernel's own permanent reservations) subtract [`reserved_page_count`].
pub fn stats() -> (u64, u64) {
    (
        TOTAL_PAGES.load(Ordering::Relaxed),
        USED_PAGES.load(Ordering::Relaxed),
    )
}

/// Frames permanently reserved at boot — the kernel image, BootInfo, the low
/// 1 MiB, the bootstrap stack, and every [`reserve_range`] span (chiefly the
/// static kernel heap).  A subset of the `used` figure from [`stats`].
///
/// The subset relation is what makes `total - reserved >= total - used`, i.e.
/// what keeps every consumer's `MemTotal >= MemFree`.  Nothing in the running
/// kernel maintains it: `RESERVED_PAGES` is monotone (only ever stored once
/// and `fetch_add`ed) while `USED_PAGES` falls on every `free_page`, so a
/// stray free of a reserved frame would invert it.  The consumers that
/// *derive* from the relation (`/proc/meminfo`, `sysinfo(2)`) clamp at the
/// point of computation; the figure returned here stays raw, so a standalone
/// `Rsvd:` readout keeps reporting the reservation as recorded rather than
/// silently mirroring `Used:` under exactly the fault an operator would be
/// inspecting.  Test 752 asserts the subset relation directly against
/// [`Accounting`] and catches the inversion at its source.
pub fn reserved_page_count() -> u64 {
    RESERVED_PAGES.load(Ordering::Relaxed)
}

/// A consistent snapshot of the frame allocator's counters *and* of the
/// bitmap they are supposed to describe.
#[derive(Clone, Copy, Debug)]
pub struct Accounting {
    /// All firmware-usable RAM, in frames ([`TOTAL_PAGES`]).
    pub total: u64,
    /// Frames whose bitmap bit is set — allocated + reserved ([`USED_PAGES`]).
    pub used: u64,
    /// The permanently-reserved subset of `used` ([`RESERVED_PAGES`]).
    pub reserved: u64,
    /// `total - used` — what the counters claim is allocatable.
    pub counter_free: u64,
    /// Clear bits in the bitmap — what `alloc_page` can actually hand out.
    pub bitmap_free: u64,
}

impl Accounting {
    /// `counter_free - bitmap_free`.  Must be zero; a positive value is the
    /// allocator promising memory it cannot produce.
    pub fn drift(&self) -> i64 {
        self.counter_free as i64 - self.bitmap_free as i64
    }
}

/// Read the counters and scan the bitmap under a single `PMM_LOCK`
/// acquisition, so the two cannot drift apart *because of the sampling*.
///
/// Every mutator (`alloc_page_locked`, `alloc_pages`, `free_page`,
/// `reserve_range`, `init`) updates the bitmap and its counter inside the same
/// lock hold, so a snapshot taken here observes both or neither.  That makes
/// `drift() != 0` a real defect rather than a sampling artefact.
///
/// The scan reads the 128 KiB bitmap eight bytes at a time, so the lock hold
/// is tens of microseconds rather than hundreds — but it is still far too long
/// for an allocation path.  This is for tests and boot-time verification;
/// sampling callers that must not stall the allocator use
/// [`accounting_snapshot_nonblocking`].
pub fn accounting_snapshot() -> Accounting {
    let _lock = PMM_LOCK.lock();
    // SAFETY: PMM_LOCK held for the whole read.
    unsafe { accounting_snapshot_locked() }
}

/// [`accounting_snapshot`] that gives up rather than waiting for `PMM_LOCK`.
///
/// Returns `None` on contention so a sampling caller (`kdb`) can report "no
/// data this sample" instead of blocking every allocation on the machine for
/// the duration of a bitmap scan.
pub fn accounting_snapshot_nonblocking() -> Option<Accounting> {
    // SAFETY: the snapshot runs only on the `Some` arm, i.e. with the lock
    // held for its whole duration.
    PMM_LOCK.try_lock().map(|_g| unsafe { accounting_snapshot_locked() })
}

/// Body of [`accounting_snapshot`].
///
/// # Safety
/// Caller must hold `PMM_LOCK` for the whole call.
unsafe fn accounting_snapshot_locked() -> Accounting {
    let total = TOTAL_PAGES.load(Ordering::Relaxed);
    let used = USED_PAGES.load(Ordering::Relaxed);
    let reserved = RESERVED_PAGES.load(Ordering::Relaxed);
    let mut bitmap_free = 0u64;
    // `BITMAP_SIZE` is a power of two ≥ 8, so `chunks_exact(8)` covers it
    // exactly and leaves no remainder to handle.
    //
    // `chunks_exact` is a slice method, so naming `BITMAP` directly would
    // create a shared reference to a mutable static — `static_mut_refs`, a
    // warning under edition 2021 and a hard error after the edition 2024
    // migration.  SAFETY: the caller holds `PMM_LOCK` for the whole call (see
    // the fn contract), so no concurrent mutation of `BITMAP` is possible and
    // the borrow this raw pointer is promoted to is uniquely ours.
    let bitmap = unsafe { &*core::ptr::addr_of!(BITMAP) };
    for chunk in bitmap.chunks_exact(8) {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3],
            chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        bitmap_free += word.count_zeros() as u64;
    }
    Accounting {
        total,
        used,
        reserved,
        counter_free: total.saturating_sub(used),
        bitmap_free,
    }
}

/// H2 diagnostic: return the cumulative count of physical frames that were
/// re-allocated within `RECENT_FREE_WINDOW_TICKS` ticks of their most recent
/// free.  Returns 0 in non-firefox-test builds.
pub fn pmm_alloc_recent_free_count() -> u64 {
    #[cfg(feature = "firefox-test-core")]
    {
        PMM_ALLOC_RECENT_FREE.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "firefox-test-core"))]
    {
        0
    }
}

/// Returns the number of free (unallocated) physical pages.
pub fn free_page_count() -> u64 {
    let total = TOTAL_PAGES.load(Ordering::Relaxed);
    let used = USED_PAGES.load(Ordering::Relaxed);
    total.saturating_sub(used)
}

/// Read the cumulative `PMM_ALLOC_NONZERO_RC` counter.
///
/// Returns the number of times an `alloc_page` call returned a frame whose
/// refcount was already non-zero.  Always 0 on non-firefox-test builds.
pub fn pmm_alloc_nonzero_rc_count() -> u64 {
    #[cfg(feature = "firefox-test-core")]
    { PMM_ALLOC_NONZERO_RC.load(Ordering::Relaxed) }
    #[cfg(not(feature = "firefox-test-core"))]
    { 0 }
}

/// Read the cumulative `PMM_FREE_RESIDUAL_REFS` counter.
///
/// Returns the number of times [`free_page`] was refused because the
/// frame still had a non-zero `pte_share_count` at the moment of free.
/// Each refusal corresponds to one quarantined (leaked) frame and one
/// upstream PTE-decref bug that needs investigation.
pub fn pmm_free_residual_refs_count() -> u64 {
    PMM_FREE_RESIDUAL_REFS.load(Ordering::Relaxed)
}

/// Read the cumulative `PMM_FREE_KERNEL_STATIC_REFUSED` counter.
///
/// Returns the number of times [`free_page`] refused to free a frame
/// because it lies inside the running kernel's own image. Each refusal
/// corresponds to a caller (any unmap/teardown path) that reached the free
/// chokepoint for a kernel-static frame — the frame is never actually
/// freed, so a nonzero count is a diagnostic signal, not damage.
pub fn pmm_free_kernel_static_refused_count() -> u64 {
    PMM_FREE_KERNEL_STATIC_REFUSED.load(Ordering::Relaxed)
}

/// Read the cumulative `PMM_FREE_ALREADY_FREE` counter.
///
/// Returns the number of times [`free_page`] was refused because the frame's
/// bitmap bit was already clear. Each increment is one double free (or one
/// free of a never-allocated frame) that would otherwise have overstated the
/// machine's free memory by a page for the rest of the boot.
pub fn pmm_free_already_free_count() -> u64 {
    PMM_FREE_ALREADY_FREE.load(Ordering::Relaxed)
}

/// Mark a page as used in the bitmap.
///
/// # Safety
/// Caller must hold PMM_LOCK and ensure page is in bounds.
unsafe fn mark_page_used(page: usize) {
    BITMAP[page / 8] |= 1 << (page % 8);
}

/// Mark a page as free in the bitmap.
///
/// # Safety
/// Caller must hold PMM_LOCK and ensure page is in bounds.
unsafe fn mark_page_free(page: usize) {
    BITMAP[page / 8] &= !(1 << (page % 8));
}

/// Check whether a page is currently marked used in the bitmap.
///
/// Used by `init` to avoid double-counting `total_available` when an
/// adjacent reservation block (kernel image + slack, first-MiB BIOS
/// reserve, BootInfo span) overlaps a page that another block already
/// claimed.
///
/// # Safety
/// Caller must hold PMM_LOCK and ensure page is in bounds.
unsafe fn is_page_used_locked(page: usize) -> bool {
    BITMAP[page / 8] & (1 << (page % 8)) != 0
}
