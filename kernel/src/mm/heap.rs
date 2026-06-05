//! Kernel Heap Allocator
//!
//! Linked-list free-list allocator for the kernel heap.
//! Supports proper allocation and deallocation with coalescing of adjacent free blocks.
//!
//! ## Heap base placement
//!
//! The heap virtual base is computed at runtime in `init()` from the
//! `__kernel_end` linker symbol so the heap always sits above whatever the
//! linker actually placed BSS at.  Default builds (where BSS fits under
//! 8 MiB) keep the historical layout — `HEAP_START_MIN_VA = 0xFFFF_8000_0080_0000`
//! — for byte-identical behaviour.  Heavy diagnostic feature combinations
//! (`firefox-test,w215-diag,f3-watch,file-buf-witness`) grow BSS past
//! 8 MiB; in those builds the heap follows BSS rather than overlapping it,
//! avoiding the silent free-list corruption that first surfaced in Phase 2
//! QA on 2026-05-21.
//!
//! `vmm::init()` calls `compute_heap_layout()` to reserve the backing
//! frames in the PMM before any `pmm::alloc_page()` runs; `init()` here
//! latches the same layout and wires the global allocator.  Both call
//! sites get identical answers because `__kernel_end` is a link-time
//! constant.  See Intel SDM Vol. 3A §4.3 (IA-32e 2 MiB paging) for the
//! 2 MiB-aligned base rationale.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

/// Kernel heap size: 128 MiB (sufficient for 1920×1080 GUI with multiple window surfaces).
pub const HEAP_SIZE: usize = 128 * 1024 * 1024;

/// Minimum heap base virtual address — phys 8 MiB in the higher-half map.
///
/// Preserves the historical layout for small kernel builds.  When BSS fits
/// below 8 MiB (default `firefox-test`) the computed layout pins the heap
/// here and the build is byte-identical to pre-dynamic-heap kernels.
const HEAP_START_MIN_VA: usize = 0xFFFF_8000_0080_0000;

/// One 2 MiB huge page.  Heap base is rounded up to this alignment so it
/// always falls on a 2 MiB boundary matching the bootloader's higher-half
/// huge-page map.  See Intel SDM Vol. 3A §4.3.
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Physical-to-virtual offset for the kernel's higher-half map (PML4[256-511]).
/// Matches `shared::KERNEL_VIRT_BASE` and `vmm::PHYS_OFF`.
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

extern "C" {
    /// 4 KiB-aligned symbol emitted by `kernel/linker.ld` immediately after
    /// `.bss` (see `__kernel_end = .;`).  Used to position the heap above
    /// whatever the linker actually placed BSS at, so feature-gated
    /// diagnostic statics that inflate BSS (e.g. `w215_diag` shadow tables
    /// at ~1.65 MiB) do not silently overlap the heap.
    static __kernel_end: u8;
}

/// Runtime-latched heap virtual base, computed in `heap::init()` from the
/// `__kernel_end` linker symbol.  `0` until `heap::init()` runs.  All
/// external callers (idt page-fault guard, test_runner) must read through
/// `heap_start()` / `heap_guard_*_va()` so the "not yet initialised"
/// sentinel is honoured.
static HEAP_START_VA: AtomicUsize = AtomicUsize::new(0);

/// Returns the kernel heap base virtual address, or `0` if `heap::init()`
/// has not yet executed.
#[inline]
pub fn heap_start() -> usize {
    HEAP_START_VA.load(Ordering::Relaxed)
}

/// Returns the not-present guard page VA immediately below the heap base,
/// or `0` if `heap::init()` has not yet executed.
#[inline]
pub fn heap_guard_below_va() -> u64 {
    let base = HEAP_START_VA.load(Ordering::Relaxed);
    if base == 0 { 0 } else { base as u64 - 0x1000 }
}

/// Returns the not-present guard page VA immediately above the heap, or
/// `0` if `heap::init()` has not yet executed.
#[inline]
pub fn heap_guard_above_va() -> u64 {
    let base = HEAP_START_VA.load(Ordering::Relaxed);
    if base == 0 { 0 } else { (base + HEAP_SIZE) as u64 }
}

/// Compute the kernel heap layout — virtual base, physical base, physical
/// end-exclusive — by aligning past the linker's `__kernel_end` symbol.
///
/// Called twice during early boot: once from `vmm::init()` to reserve the
/// backing frames in the PMM before any `pmm::alloc_page()` can hand them
/// out, and once from `heap::init()` to wire the allocator.  Both calls
/// agree because `__kernel_end` is a link-time constant.
///
/// Returns `(va_start, phys_start, phys_end_exclusive)`.
pub fn compute_heap_layout() -> (usize, u64, u64) {
    // SAFETY: `__kernel_end` is a linker-defined symbol; taking its
    // address is always safe.  Its higher-half VA translates back to a
    // physical address via `va - PHYS_OFF`.
    let kernel_end_va: u64 = unsafe { &__kernel_end as *const u8 as u64 };
    let kernel_end_phys: u64 = kernel_end_va.saturating_sub(PHYS_OFF);

    // Round up past kernel_end by ≥1 page (so there is always a strictly
    // non-present byte between BSS and the below-guard PTE), then to the
    // next 2 MiB huge-page boundary so the heap base aligns with the
    // bootloader's higher-half huge-page map.
    let candidate_phys = (kernel_end_phys + 0x1000 + HUGE_PAGE_SIZE as u64 - 1)
        & !(HUGE_PAGE_SIZE as u64 - 1);

    // Honour the historical lower bound (HEAP_START_MIN_VA, phys 0x80_0000)
    // so default builds with BSS < 8 MiB get byte-identical layout.
    let min_phys = (HEAP_START_MIN_VA as u64).saturating_sub(PHYS_OFF);
    let phys_start = core::cmp::max(candidate_phys, min_phys);
    let phys_end = phys_start + HEAP_SIZE as u64;
    let va_start = (phys_start + PHYS_OFF) as usize;

    (va_start, phys_start, phys_end)
}

/// Compute the physical frames of the two heap guard pages directly from
/// `compute_heap_layout()`, **without** depending on `heap::init()` having
/// latched `HEAP_START_VA`.
///
/// `vmm::init()` runs before `heap::init()` and allocates page-table pages
/// (PD copies in `separate_higher_half_pds`, the 1..4 GiB PDs in
/// `extend_higher_half_to_4gib`, and any later 2 MiB-split for MMIO with
/// stronger cache attributes).  Those allocations draw from the PMM, whose
/// next free frame immediately above the just-reserved heap-backing range is
/// exactly the above-guard frame (`heap_phys_end`).  If that frame is handed
/// out as a page-table page and `heap::init_guard_pages()` then marks its
/// higher-half VA not-present, a later write to that page table — e.g. a PD
/// entry split during MMIO mapping (Intel SDM Vol. 3A §4.10.5: paging-structure
/// frames must stay reserved against recycling) or the LAPIC MMIO PD entry
/// during `apic::init` (§10.4.4) — faults on the guard page.  Reserving both
/// guard frames here — before any `pmm::alloc_page()` — closes that window.
///
/// Returns `(below_guard_phys, above_guard_phys)`, each a 4 KiB frame.
pub fn compute_guard_phys() -> (u64, u64) {
    let (_va, phys_start, phys_end) = compute_heap_layout();
    // Below-guard sits one page under the heap base; above-guard is the first
    // page past the heap (== phys_end-exclusive).
    (phys_start.saturating_sub(0x1000), phys_end)
}

/// Physical frame backing the below-guard VA, for PMM reservation.
#[inline]
fn heap_guard_below_phys() -> u64 {
    heap_guard_below_va().saturating_sub(PHYS_OFF)
}

/// Physical frame backing the above-guard VA, for PMM reservation.
#[inline]
fn heap_guard_above_phys() -> u64 {
    heap_guard_above_va().saturating_sub(PHYS_OFF)
}

/// Minimum block size — must be large enough to hold a FreeBlock header.
const MIN_BLOCK_SIZE: usize = core::mem::size_of::<FreeBlock>();

// ─────────────────────────────────────────────────────────────────────────
// Free-list corruption detection
//
// The kernel heap is a single-linked free list walked under a `spin::Mutex`.
// A stray out-of-bounds write that lands on a free block's `next` pointer
// turns the O(n) first-fit walk into an unbounded chase of garbage pointers:
// the holder of the heap lock spins forever and every other CPU that needs
// the heap blocks behind it — a silent whole-machine freeze.
//
// To convert that silent freeze into a LOUD, LOCATED panic we validate every
// `next`-pointer traversal against three cheap invariants (alignment, heap
// range, and a bounded walk) and we fence each live allocation with magic
// canary words.  A corrupted canary at free-time names the victim block — far
// closer to the offending write than the eventual free-list-walk freeze.
//
// References: Rust `core::alloc::{GlobalAlloc, Layout}`; the general
// allocator red-zone / guard-byte technique (fencing each object with a known
// magic and validating it on free); System V AMD64 ABI §3.1.2 (natural
// alignment of fundamental types — the minimum block alignment enforced here).
// ─────────────────────────────────────────────────────────────────────────

/// Minimum alignment every `FreeBlock` start is guaranteed to satisfy.
///
/// `FreeBlock` is two pointer-sized words, so its natural alignment is 8 on
/// x86_64 (System V AMD64 ABI §3.1.2).  The heap base is 2 MiB-aligned and the
/// allocator only ever advances block starts by whole `AllocHeader`-plus-data
/// spans, all of which are multiples of `align_of::<FreeBlock>()`; therefore a
/// `next` pointer that is not 8-aligned is proof of corruption.  We derive the
/// bound from the type so it self-corrects if the header ever grows.
const BLOCK_ALIGN: usize = core::mem::align_of::<FreeBlock>();

/// Generous upper bound on the number of distinct free blocks the walk may
/// visit before we declare the list corrupt (cycle / runaway chase).  The heap
/// is 128 MiB and the minimum block is `MIN_BLOCK_SIZE` (16 B); the true block
/// count can never exceed `HEAP_SIZE / MIN_BLOCK_SIZE`.  We add headroom and
/// cap at a fixed constant so the bound is independent of fragmentation.
const MAX_WALK_ITERS: usize = (HEAP_SIZE / MIN_BLOCK_SIZE) + 16;

/// Magic word written into the front canary slot of every live allocation
/// (only when the `heap-canary` feature is enabled).  A distinct, non-zero,
/// non-pointer-looking constant so a clobber is obvious in a hex dump.
#[cfg(feature = "heap-canary")]
const CANARY_FRONT: u64 = 0xA5A5_5A5A_C0DE_F00D;

/// Magic word written into the rear canary slot immediately after the user
/// region of every live allocation (only when `heap-canary` is enabled).
#[cfg(feature = "heap-canary")]
const CANARY_REAR: u64 = 0x5A5A_A5A5_DEAD_BEEF;

/// Size of one canary word.
#[cfg(feature = "heap-canary")]
const CANARY_SIZE: usize = core::mem::size_of::<u64>();

/// Extra bytes reserved at the tail of every allocation for the rear canary
/// word.  Zero unless the `heap-canary` feature is enabled, so default builds
/// reserve nothing and keep the historical block sizing.
#[inline(always)]
const fn canary_tail_bytes() -> usize {
    #[cfg(feature = "heap-canary")]
    { CANARY_SIZE }
    #[cfg(not(feature = "heap-canary"))]
    { 0 }
}

/// Validate a free-list `next` pointer.  Returns `Ok(())` if the pointer is a
/// plausible `FreeBlock` (null is the legitimate list terminator and is
/// accepted), or `Err(reason)` naming the first invariant it violates.
///
/// Checks (cheap — a handful of compares per block):
/// * `BLOCK_ALIGN`-aligned (every real block start is 8-aligned, see
///   [`BLOCK_ALIGN`]);
/// * within the live heap range `[heap_start, heap_start + HEAP_SIZE)` with
///   room for at least a `FreeBlock` header before the end.
#[inline]
fn validate_block_ptr(p: *mut FreeBlock) -> Result<(), &'static str> {
    if p.is_null() {
        return Ok(());
    }
    let addr = p as usize;
    if addr & (BLOCK_ALIGN - 1) != 0 {
        return Err("next pointer is not 8-aligned");
    }
    let base = heap_start();
    if base == 0 {
        // Heap not yet initialised: any non-null pointer is bogus.
        return Err("next pointer non-null before heap init");
    }
    let end = base + HEAP_SIZE;
    if addr < base || addr > end.saturating_sub(MIN_BLOCK_SIZE) {
        return Err("next pointer outside heap range");
    }
    Ok(())
}

/// Loudly abort with rich, greppable context when free-list corruption is
/// detected.  Tagged `[HEAP CORRUPT]` so the harness can `wait`/`grep` for it.
///
/// This runs while the heap `spin::Mutex` is held, so it must not allocate.
/// `panic!` routes through the serial sink (no heap traffic) and the panic
/// handler halts every CPU, so the held lock is moot.
#[inline(never)]
#[cold]
fn heap_corrupt(
    reason: &str,
    block: usize,
    bad_next: usize,
    layout: Layout,
    head: usize,
) -> ! {
    // `_caller` is the return address of `alloc`/`dealloc`'s caller — a cheap
    // "where" hint to narrow the next phase (finding the OOB writer).
    let caller = caller_return_address();
    panic!(
        "[HEAP CORRUPT] {reason}: block={block:#x} bad_next={bad_next:#x} \
         req_size={req_size} req_align={req_align} head={head:#x} \
         heap=[{lo:#x}..{hi:#x}) caller_ret={caller:#x}",
        reason = reason,
        block = block,
        bad_next = bad_next,
        req_size = layout.size(),
        req_align = layout.align(),
        head = head,
        lo = heap_start(),
        hi = heap_start() + HEAP_SIZE,
        caller = caller,
    );
}

/// Loudly abort when an allocation's red-zone (canary) is found clobbered at
/// free-time.  Names the victim block, the corrupted value, what it should
/// have been, and which edge overflowed.  Tagged `[HEAP CORRUPT]`.
#[cfg(feature = "heap-canary")]
#[inline(never)]
#[cold]
fn heap_corrupt_canary(
    reason: &str,
    block_start: usize,
    data_ptr: usize,
    found: u64,
    expected: u64,
    user_size: usize,
) -> ! {
    let caller = caller_return_address();
    panic!(
        "[HEAP CORRUPT] {reason}: block={block:#x} data={data:#x} \
         user_size={user_size} found={found:#018x} expected={expected:#018x} \
         heap=[{lo:#x}..{hi:#x}) caller_ret={caller:#x}",
        reason = reason,
        block = block_start,
        data = data_ptr,
        user_size = user_size,
        found = found,
        expected = expected,
        lo = heap_start(),
        hi = heap_start() + HEAP_SIZE,
        caller = caller,
    );
}

/// Best-effort return address of the current frame's caller, for the
/// `caller_ret=` field in a corruption panic.  Reads the saved return slot
/// `[rbp + 8]` per the System V AMD64 ABI §3.4.1 frame-pointer convention.
///
/// This is a *hint* only — the kernel is built with `-fomit-frame-pointer` in
/// some translation units, so the value may not be a true return address.  We
/// only ever format it (never dereference it), so a garbage read is harmless,
/// and on the common path (`heap_corrupt` keeps a frame pointer) it points at
/// the alloc/dealloc call site that tripped the corruption check.
#[inline(always)]
fn caller_return_address() -> usize {
    let ra: usize;
    // SAFETY: read-only load through RBP; the value is only formatted into the
    // panic string, never used as a pointer.  No memory is written.
    unsafe {
        core::arch::asm!(
            "mov {ra}, [rbp + 8]",
            ra = out(reg) ra,
            options(nostack, readonly, preserves_flags),
        );
    }
    ra
}

/// Global kernel allocator.
#[global_allocator]
static ALLOCATOR: LockedHeapAllocator = LockedHeapAllocator(Mutex::new(LinkedListAllocator {
    head: ptr::null_mut(),
    initialized: false,
    total_bytes: 0,
    allocated_bytes: 0,
}));

/// Header for a free block in the free list.
#[repr(C)]
struct FreeBlock {
    /// Size of this free block (including the header).
    size: usize,
    /// Pointer to the next free block, or null.
    next: *mut FreeBlock,
}

/// Header stored just before every returned allocation.
/// Stores the original block start address and total block size.
///
/// When the `heap-canary` feature is enabled the header additionally carries
/// the user-requested size and a front-canary magic word.  `#[repr(C)]` lays
/// the fields out in declaration order, so `front_canary` is declared *last*
/// and therefore sits in the bytes immediately below `data_start`: an
/// underflowing write to this allocation (a store just before the returned
/// pointer) lands on the front canary first.  `block_start`/`block_size` keep
/// their position at the top of the header and are accessed by name, so
/// reordering is transparent to the recovery logic.  Without `heap-canary`
/// the header is the historical `{block_start, block_size}` pair, byte-for-byte.
#[repr(C)]
struct AllocHeader {
    /// Start address of the entire block (including any alignment padding before this header).
    block_start: usize,
    /// Total size of the entire block.
    block_size: usize,
    /// User-requested allocation size, so the rear canary at
    /// `data_start + user_size` can be located on free.
    #[cfg(feature = "heap-canary")]
    user_size: usize,
    /// Front-canary magic word — sits immediately below `data_start`; a write
    /// that underflows this allocation clobbers it.  Validated on free.
    #[cfg(feature = "heap-canary")]
    front_canary: u64,
}

const ALLOC_HEADER_SIZE: usize = core::mem::size_of::<AllocHeader>();

/// Linked-list free-list heap allocator with first-fit strategy and coalescing.
struct LinkedListAllocator {
    /// Head of the free list.
    head: *mut FreeBlock,
    /// Whether the allocator has been initialized.
    initialized: bool,
    /// Total bytes under management.
    total_bytes: usize,
    /// Currently allocated bytes (approximate, includes overhead).
    allocated_bytes: usize,
}

// SAFETY: We protect all access behind a spin::Mutex.
unsafe impl Send for LinkedListAllocator {}

impl LinkedListAllocator {
    /// Initialize the heap with a single large free block.
    fn init(&mut self, heap_start: usize, heap_size: usize) {
        let block = heap_start as *mut FreeBlock;
        unsafe {
            (*block).size = heap_size;
            (*block).next = ptr::null_mut();
        }
        self.head = block;
        self.total_bytes = heap_size;
        self.allocated_bytes = 0;
        self.initialized = true;
    }

    /// Allocate memory with the given layout.
    fn alloc(&mut self, layout: Layout) -> *mut u8 {
        if !self.initialized {
            return ptr::null_mut();
        }

        let align = layout.align().max(core::mem::align_of::<AllocHeader>());

        // Validate the head before the walk: a corrupt head is the first
        // thing a stray write clobbers and the most common freeze signature.
        if let Err(reason) = validate_block_ptr(self.head) {
            heap_corrupt(reason, self.head as usize, self.head as usize, layout, self.head as usize);
        }

        // Walk the free list looking for first fit.
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = self.head;
        let head_snapshot = self.head as usize;
        let mut iters: usize = 0;

        while !current.is_null() {
            // Bounded walk: a runaway chase (cycle or garbage tail) is proof
            // of corruption — abort loudly instead of spinning forever holding
            // the heap lock.
            iters += 1;
            if iters > MAX_WALK_ITERS {
                heap_corrupt(
                    "alloc free-list walk exceeded max iterations (cycle?)",
                    current as usize, current as usize, layout, head_snapshot,
                );
            }

            let block_addr = current as usize;
            // Canary-validate the FreeBlock so a clobbered header is caught at
            // walk-time, not just at free-time (cheap; only under heap-canary).
            self.check_freeblock_canary(current, layout, head_snapshot);
            let block_size = unsafe { (*current).size };

            // The user data must be aligned, and we need an AllocHeader just before it.
            let data_start = align_up(block_addr + ALLOC_HEADER_SIZE, align);
            // Round the consumed span up to BLOCK_ALIGN so the *next* free block
            // start (block_addr + total_needed) stays BLOCK_ALIGN-aligned.  This
            // keeps every FreeBlock header naturally aligned (no unaligned
            // pointer stores) and lets `validate_block_ptr` treat a misaligned
            // `next` as definitive corruption.  See System V AMD64 ABI §3.1.2.
            let raw_needed = (data_start + layout.size() + canary_tail_bytes()) - block_addr;
            let total_needed = align_up(raw_needed, BLOCK_ALIGN);

            if block_size >= total_needed {
                let remainder = block_size - total_needed;
                let next_block = unsafe { (*current).next };
                // Validate the successor we're about to splice around.
                if let Err(reason) = validate_block_ptr(next_block) {
                    heap_corrupt(reason, block_addr, next_block as usize, layout, head_snapshot);
                }

                let header_block_size;
                if remainder >= MIN_BLOCK_SIZE + 16 {
                    // Split: create a new free block after the allocation.
                    let new_free_addr = block_addr + total_needed;
                    let new_free = new_free_addr as *mut FreeBlock;
                    unsafe {
                        (*new_free).size = remainder;
                        (*new_free).next = next_block;
                    }

                    if prev.is_null() {
                        self.head = new_free;
                    } else {
                        unsafe { (*prev).next = new_free; }
                    }

                    header_block_size = total_needed;
                    self.allocated_bytes += total_needed;
                } else {
                    // Use the entire block (don't split tiny remainders).
                    if prev.is_null() {
                        self.head = next_block;
                    } else {
                        unsafe { (*prev).next = next_block; }
                    }

                    header_block_size = block_size;
                    self.allocated_bytes += block_size;
                }

                // Write the allocation header just before user data, then fence
                // the user region with front/rear canaries (under heap-canary).
                let header_ptr = (data_start - ALLOC_HEADER_SIZE) as *mut AllocHeader;
                unsafe {
                    (*header_ptr).block_start = block_addr;
                    (*header_ptr).block_size = header_block_size;
                }
                self.write_alloc_canaries(header_ptr, data_start, layout.size());

                return data_start as *mut u8;
            }

            prev = current;
            let next = unsafe { (*current).next };
            if let Err(reason) = validate_block_ptr(next) {
                heap_corrupt(reason, current as usize, next as usize, layout, head_snapshot);
            }
            current = next;
        }

        // Out of memory.
        ptr::null_mut()
    }

    /// Deallocate memory and coalesce adjacent free blocks.
    fn dealloc(&mut self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() || !self.initialized {
            return;
        }

        // Read the allocation header to find the original block.
        let header_ptr = (ptr as usize - ALLOC_HEADER_SIZE) as *const AllocHeader;
        let block_start = unsafe { (*header_ptr).block_start };
        let block_size = unsafe { (*header_ptr).block_size };

        // Validate the canaries that fence this allocation BEFORE we trust
        // `block_start`/`block_size`.  A corrupted canary names the victim of
        // an out-of-bounds write right here at free-time — the closest point
        // to the offending store we can cheaply reach (no-op without
        // `heap-canary`).
        self.check_alloc_canaries(header_ptr, ptr);

        // The recovered block start is what we will hand back to the free
        // list; if the header was clobbered it would corrupt the list, so
        // validate it as a block pointer before insertion.
        if let Err(reason) = validate_block_ptr(block_start as *mut FreeBlock) {
            heap_corrupt(
                reason, block_start, block_start,
                Layout::from_size_align(block_size, BLOCK_ALIGN)
                    .unwrap_or(Layout::new::<u8>()),
                self.head as usize,
            );
        }

        self.allocated_bytes = self.allocated_bytes.saturating_sub(block_size);
        self.insert_free_block(block_start, block_size);
    }

    /// Insert a free block in address-sorted order, coalescing with neighbors.
    fn insert_free_block(&mut self, addr: usize, size: usize) {
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = self.head;
        let head_snapshot = self.head as usize;
        let ins_layout = Layout::from_size_align(size, BLOCK_ALIGN)
            .unwrap_or(Layout::new::<u8>());

        // A clobbered head here would otherwise be silently re-linked.
        if let Err(reason) = validate_block_ptr(self.head) {
            heap_corrupt(reason, addr, self.head as usize, ins_layout, head_snapshot);
        }

        // Find insertion point (sorted by address).
        let mut iters: usize = 0;
        while !current.is_null() && (current as usize) < addr {
            iters += 1;
            if iters > MAX_WALK_ITERS {
                heap_corrupt(
                    "insert_free_block walk exceeded max iterations (cycle?)",
                    current as usize, current as usize, ins_layout, head_snapshot,
                );
            }
            prev = current;
            let next = unsafe { (*current).next };
            if let Err(reason) = validate_block_ptr(next) {
                heap_corrupt(reason, current as usize, next as usize, ins_layout, head_snapshot);
            }
            current = next;
        }

        // Write the new free block.
        let new_block = addr as *mut FreeBlock;
        unsafe {
            (*new_block).size = size;
            (*new_block).next = current;
        }

        // Link it into the list.
        if prev.is_null() {
            self.head = new_block;
        } else {
            unsafe { (*prev).next = new_block; }
        }

        // Try to merge with next block.
        if !current.is_null() && addr + size == current as usize {
            unsafe {
                (*new_block).size += (*current).size;
                (*new_block).next = (*current).next;
            }
        }

        // Try to merge with previous block.
        if !prev.is_null() {
            let prev_end = prev as usize + unsafe { (*prev).size };
            if prev_end == addr {
                unsafe {
                    (*prev).size += (*new_block).size;
                    (*prev).next = (*new_block).next;
                }
            }
        }
    }

    // ── Allocation red-zone (canary) helpers ─────────────────────────────
    //
    // These fence each live allocation with two magic words — a front canary
    // stored in the `AllocHeader` (immediately below the user region) and a
    // rear canary placed immediately after `data_start + user_size`.  An
    // out-of-bounds write that overruns either edge clobbers a canary; the
    // corruption is then caught the next time the block is freed (or, for the
    // FreeBlock canary, walked), naming the victim block far closer to the
    // offending store than the eventual free-list-walk freeze.
    //
    // All four helpers compile to nothing without the `heap-canary` feature,
    // keeping the default fast path untouched.

    /// Stamp the front + rear canaries onto a freshly carved allocation.
    #[inline(always)]
    #[cfg_attr(not(feature = "heap-canary"), allow(unused_variables))]
    fn write_alloc_canaries(&self, header_ptr: *mut AllocHeader, data_start: usize, user_size: usize) {
        #[cfg(feature = "heap-canary")]
        unsafe {
            (*header_ptr).front_canary = CANARY_FRONT;
            (*header_ptr).user_size = user_size;
            // Rear canary immediately after the user region.  `total_needed`
            // in `alloc` reserved `CANARY_SIZE` extra bytes for exactly this.
            let rear = (data_start + user_size) as *mut u64;
            core::ptr::write_unaligned(rear, CANARY_REAR);
        }
    }

    /// Validate the front + rear canaries of a live allocation at free-time.
    /// Panics with `[HEAP CORRUPT]` naming the victim and which edge overflowed.
    #[inline(always)]
    #[cfg_attr(not(feature = "heap-canary"), allow(unused_variables))]
    fn check_alloc_canaries(&self, header_ptr: *const AllocHeader, data_ptr: *mut u8) {
        #[cfg(feature = "heap-canary")]
        unsafe {
            let front = (*header_ptr).front_canary;
            let user_size = (*header_ptr).user_size;
            let block_start = (*header_ptr).block_start;
            if front != CANARY_FRONT {
                heap_corrupt_canary(
                    "front canary clobbered (underflow into this block's header)",
                    block_start, data_ptr as usize, front, CANARY_FRONT, user_size,
                );
            }
            let rear_ptr = (data_ptr as usize + user_size) as *const u64;
            let rear = core::ptr::read_unaligned(rear_ptr);
            if rear != CANARY_REAR {
                heap_corrupt_canary(
                    "rear canary clobbered (overflow past end of this allocation)",
                    block_start, data_ptr as usize, rear, CANARY_REAR, user_size,
                );
            }
        }
    }

    /// Cheap FreeBlock sanity at walk-time.  Currently a no-op placeholder for
    /// the always-validated pointer checks; reserved for a future free-block
    /// poison word.  Kept as a hook so the walk has a single canary call site.
    #[inline(always)]
    #[cfg_attr(not(feature = "heap-canary"), allow(unused_variables))]
    fn check_freeblock_canary(&self, _block: *mut FreeBlock, _layout: Layout, _head: usize) {
        // The structural invariants (alignment, range, bounded walk) are
        // already enforced on every `next` traversal by `validate_block_ptr`;
        // a dedicated free-block poison word would duplicate the in-band
        // `size`/`next` validation, so this is intentionally empty for now.
    }
}

/// RAII bracket that clears IF for the duration of a heap critical section,
/// restoring the caller's prior interrupt state on drop.
///
/// ## Why the heap lock must run with interrupts masked
///
/// The kernel heap is guarded by a single non-reentrant `spin::Mutex`
/// (`LockedHeapAllocator.0`).  A plain `spin::Mutex` does **not** mask
/// interrupts while held: the free-list walk in `alloc`/`dealloc` runs with
/// `IF` left at whatever the caller had.  Almost every allocation happens in
/// ordinary kernel code with interrupts enabled, so the LAPIC timer ISR can
/// fire *while this core holds the heap lock*.
///
/// The timer ISR's periodic metrics dump
/// (`crate::proc::proc_metrics::maybe_emit_periodic`) itself allocates
/// (`Vec`/`String`/`format!`).  When the ISR lands on a core that is mid-walk
/// inside the heap lock, the ISR re-enters `alloc`, takes the same
/// `spin::Mutex`, and busy-spins forever waiting for a lock the *interrupted*
/// frame on the very same core can never release — a re-entrant self-deadlock
/// that strands the core in a non-preemptible Ring-0 spin (the timer ISR
/// skips kernel-mode preemption), freezing the whole machine.
///
/// Masking interrupts for the (tiny, bounded) free-list critical section
/// makes a heap allocation atomic with respect to ISRs on the local core, so
/// no interrupt handler can ever observe the lock held and re-enter the
/// allocator.  This mirrors the same discipline `_serial_print` already uses
/// around the `SERIAL` mutex, and follows the standard "spinlock that may be
/// taken from interrupt context must be IRQ-safe" rule (an irqsave spinlock).
/// Cross-core safety is unchanged: the `spin::Mutex` still serialises CPUs;
/// masking only prevents *same-core* ISR re-entry.
struct HeapIrqGuard {
    /// True if IF was set on entry and must be restored to set on drop.
    reenable: bool,
}

impl HeapIrqGuard {
    #[inline(always)]
    fn new() -> Self {
        // Read RFLAGS, then mask interrupts.  `pushfq` reflects IF before the
        // following `cli`, so we capture the caller's true prior state even
        // when nested inside another IRQ-masked region (then `reenable` is
        // false and drop is a no-op — correct).
        let rflags: u64;
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {rflags}",
                "cli",
                rflags = out(reg) rflags,
                options(nomem, preserves_flags),
            );
        }
        HeapIrqGuard { reenable: rflags & (1 << 9) != 0 }
    }
}

impl Drop for HeapIrqGuard {
    #[inline(always)]
    fn drop(&mut self) {
        if self.reenable {
            // SAFETY: restoring IF to exactly the value the caller had on
            // entry.  If the caller already had interrupts masked we leave
            // them masked.
            unsafe {
                core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
            }
        }
    }
}

/// Thread-safe wrapper around the heap allocator.
struct LockedHeapAllocator(Mutex<LinkedListAllocator>);

unsafe impl GlobalAlloc for LockedHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Mask interrupts across the lock-held critical section so the timer
        // ISR (which itself allocates via the periodic metrics dump) cannot
        // fire on this core while the heap lock is held and re-enter the
        // allocator into a same-core spin deadlock.  See `HeapIrqGuard`.
        let _irq = HeapIrqGuard::new();
        let ptr = self.0.lock().alloc(layout);
        if !ptr.is_null() {
            crate::perf::record_heap_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::perf::record_heap_free(layout.size());
        let _irq = HeapIrqGuard::new();
        self.0.lock().dealloc(ptr, layout)
    }
}

/// Get heap statistics: (total_bytes, allocated_bytes, free_bytes).
pub fn stats() -> (usize, usize, usize) {
    let alloc = ALLOCATOR.0.lock();
    let free = alloc.total_bytes.saturating_sub(alloc.allocated_bytes);
    (alloc.total_bytes, alloc.allocated_bytes, free)
}

/// Initialize the kernel heap.
///
/// Computes the heap base from the linker's `__kernel_end` symbol so the
/// heap follows BSS dynamically (see module docs).  Panics if the heap
/// would extend past 1 GiB phys (outside the bootloader's huge-page map)
/// — this is a build-misconfiguration assertion that catches kernels
/// grown so large they would extend the heap into MMIO territory.
pub fn init() {
    let (va_start, phys_start, phys_end) = compute_heap_layout();

    // Sanity: the bootloader maps phys 0..1 GiB into PML4[256] via 2 MiB
    // huge pages; `vmm::extend_higher_half_to_4gib` later covers 1..4 GiB
    // but that path is for MMIO, not RAM-backed heap.  A heap extending
    // past 1 GiB phys means the kernel image+BSS is multiple-hundred-MiB
    // — investigate before papering over.
    assert!(
        phys_end <= 0x4000_0000,
        "[HEAP] heap layout phys_end={:#x} exceeds 1 GiB — kernel image too large?",
        phys_end,
    );

    HEAP_START_VA.store(va_start, Ordering::Relaxed);
    ALLOCATOR.0.lock().init(va_start, HEAP_SIZE);

    crate::serial_println!(
        "[HEAP] Initialized at {:#x}-{:#x} (phys {:#x}-{:#x}, {} KiB) — linked-list allocator",
        va_start,
        va_start + HEAP_SIZE,
        phys_start,
        phys_end,
        HEAP_SIZE / 1024
    );
}

/// Install 4 KiB guard pages immediately below and above the heap region.
///
/// # Guard layout
/// ```
/// heap_guard_below_va()         (not-present PTE)  ← underflow trap
/// heap_start()                  (heap, 128 MiB)
/// heap_start() + HEAP_SIZE  (= heap_guard_above_va(), not-present PTE) ← overflow trap
/// ```
///
/// # Physical-alias prevention
/// The bootloader maps all physical RAM at both the identity map (PML4[0]) and the
/// higher-half (PML4[256]) using 2 MiB huge pages.  The physical frames that
/// correspond to the guard VAs (`guard_va - PHYS_OFF`) are inside UEFI CONVENTIONAL
/// memory and could normally be handed out by the PMM, which would mean another
/// caller could access them via `PHYS_OFF + phys` even though the guard PTE is
/// not-present — defeating the guard silently.
///
/// To prevent this we call `pmm::reserve_range` on those frames *before* writing
/// the not-present PTEs, so the PMM bitmap marks them as permanently used.  The
/// guard PTEs themselves have no physical backing (PTE value = 0); the reservation
/// merely prevents the direct-map alias.
pub fn init_guard_pages() {
    use crate::mm::{pmm, vmm};

    let below_va    = heap_guard_below_va();
    let above_va    = heap_guard_above_va();
    let below_phys  = heap_guard_below_phys();
    let above_phys  = heap_guard_above_phys();
    let base        = heap_start() as u64;

    debug_assert!(base != 0, "init_guard_pages called before heap::init");

    // Reserve the physical frames for both guard pages.
    // This must happen before installing PTEs so that no racing allocation can
    // grab those frames in the window between the PMM free-mark and the PTE write.
    pmm::reserve_range(below_phys, below_phys + 0x1000);
    pmm::reserve_range(above_phys, above_phys + 0x1000);

    // Install not-present PTEs (creates PT hierarchy, writes PTE = 0).
    if !vmm::install_not_present_guard(below_va) {
        crate::serial_println!("[HEAP GUARD] WARN: failed to install below-guard at {:#x}", below_va);
    }
    if !vmm::install_not_present_guard(above_va) {
        crate::serial_println!("[HEAP GUARD] WARN: failed to install above-guard at {:#x}", above_va);
    }

    crate::serial_println!(
        "[HEAP GUARD] Guard pages installed: below={:#x} above={:#x} (heap {:#x}..{:#x})",
        below_va,
        above_va,
        base,
        base + HEAP_SIZE as u64,
    );
}

/// Align a value up to the given alignment.
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}