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

#[cfg(feature = "firefox-test")]
const RECENT_FREE_CAP: usize = 64;

#[cfg(feature = "firefox-test")]
const RECENT_FREE_WINDOW_TICKS: u64 = 2;

#[cfg(feature = "firefox-test")]
#[derive(Copy, Clone)]
struct RecentFreeEntry { phys: u64, freed_tick: u64 }

#[cfg(feature = "firefox-test")]
struct RecentFreeRing {
    entries: [RecentFreeEntry; RECENT_FREE_CAP],
    next: usize,
}

#[cfg(feature = "firefox-test")]
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

#[cfg(feature = "firefox-test")]
static RECENT_FREE_RING: Mutex<RecentFreeRing> = Mutex::new(RecentFreeRing::new());

/// H2 diagnostic counter: physical frames re-allocated within
/// `RECENT_FREE_WINDOW_TICKS` ticks of their most recent free.  A non-zero
/// value indicates that the PMM is recycling frames faster than the
/// quarantine grace-period guarantees — the time-axis condition for H2.
#[cfg(feature = "firefox-test")]
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

/// Lock for bitmap operations.
static PMM_LOCK: Mutex<()> = Mutex::new(());

/// Total available pages.
static TOTAL_PAGES: AtomicU64 = AtomicU64::new(0);
/// Used pages.
static USED_PAGES: AtomicU64 = AtomicU64::new(0);

/// Next-fit cursor: byte index into BITMAP to start the next search.
/// Avoids O(N) scans from 0 when low physical frames are all in use.
static NEXT_FIT_BYTE: AtomicU64 = AtomicU64::new(0);

/// Diagnostic counter (firefox-test only): number of times `alloc_page`
/// returned a frame whose refcount was already non-zero at the moment of
/// allocation.  A non-zero count is a direct indicator of H1 (cache-vs-PMM
/// bitmap drift): the PMM believes a frame is free (bitmap bit clear) but
/// the refcount table still holds a live reference — indicating the previous
/// owner never called `page_ref_dec` before the frame was recycled.
#[cfg(feature = "firefox-test")]
static PMM_ALLOC_NONZERO_RC: AtomicU64 = AtomicU64::new(0);

/// Initialize the PMM from the UEFI memory map.
pub fn init(boot_info: &BootInfo) {
    let _lock = PMM_LOCK.lock();
    let mut total_available = 0u64;

    for i in 0..boot_info.memory_map.entry_count as usize {
        let entry = &boot_info.memory_map.entries[i];

        if entry.memory_type == MemoryType::Available {
            let start_page = (entry.physical_start / PAGE_SIZE as u64) as usize;
            let page_count = entry.page_count as usize;

            for page in start_page..start_page + page_count {
                if page < MAX_PAGES {
                    unsafe {
                        mark_page_free(page);
                    }
                    total_available += 1;
                }
            }
        }
    }

    // Mark kernel region as used (1 MiB + kernel size)
    let kernel_start = (boot_info.kernel_phys_base / PAGE_SIZE as u64) as usize;
    let kernel_pages = ((boot_info.kernel_size + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;
    for page in kernel_start..kernel_start + kernel_pages + 256 {
        // +256 pages for boot info and early structures
        if page < MAX_PAGES {
            // SAFETY: We hold the PMM lock and page is in bounds.
            unsafe {
                mark_page_used(page);
            }
            if total_available > 0 {
                total_available -= 1;
            }
        }
    }

    // Mark first 1 MiB as reserved (BIOS, VGA, etc.)
    for page in 0..256 {
        // SAFETY: We hold the PMM lock and page is in bounds.
        unsafe {
            mark_page_used(page);
        }
    }

    TOTAL_PAGES.store(total_available, Ordering::Relaxed);
    USED_PAGES.store(0, Ordering::Relaxed);

    crate::serial_println!(
        "[PMM] Initialized: {} MiB available ({} pages)",
        total_available * 4 / 1024,
        total_available
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
                        #[cfg(feature = "firefox-test")]
                        crate::mm::w215_diag::prov_record(
                            phys, crate::mm::w215_diag::KIND_ALLOC, 0,
                        );
                        // H1 diagnostic: check whether this frame still
                        // carries a live refcount — a mismatch between the
                        // PMM bitmap (free) and the refcount table (in-use).
                        // Gated on firefox-test to keep production builds
                        // identical.
                        #[cfg(feature = "firefox-test")]
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
                        #[cfg(feature = "firefox-test")]
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
pub fn alloc_page() -> Option<u64> {
    // Fast path: try the normal allocation first.
    {
        let _lock = PMM_LOCK.lock();
        // SAFETY: We hold the PMM lock.
        if let Some(addr) = unsafe { alloc_page_locked() } {
            return Some(addr);
        }
    } // release lock before calling OOM killer

    // Slow path: bitmap is full.  Invoke the OOM killer, yield briefly so the
    // scheduler can run SIGKILL handling, then retry once.
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

/// Free a physical page frame.
pub fn free_page(phys_addr: u64) {
    let page = (phys_addr / PAGE_SIZE as u64) as usize;
    if page >= MAX_PAGES {
        return;
    }

    let _lock = PMM_LOCK.lock();
    // SAFETY: We hold the PMM lock and page is in bounds.
    unsafe {
        mark_page_free(page);
    }
    USED_PAGES.fetch_sub(1, Ordering::Relaxed);

    // H2 diagnostic: record this free in the recent-free ring so that
    // a rapid re-allocation of the same frame triggers PMM_ALLOC_RECENT_FREE.
    #[cfg(feature = "firefox-test")]
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
pub fn reserve_range(start: u64, end: u64) {
    let _lock = PMM_LOCK.lock();
    let start_page = (start / PAGE_SIZE as u64) as usize;
    let end_page = ((end + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;
    for page in start_page..end_page {
        if page < MAX_PAGES {
            // SAFETY: We hold the PMM lock and page is in bounds.
            unsafe { mark_page_used(page); }
        }
    }
}

/// Get memory statistics.
pub fn stats() -> (u64, u64) {
    (
        TOTAL_PAGES.load(Ordering::Relaxed),
        USED_PAGES.load(Ordering::Relaxed),
    )
}

/// H2 diagnostic: return the cumulative count of physical frames that were
/// re-allocated within `RECENT_FREE_WINDOW_TICKS` ticks of their most recent
/// free.  Returns 0 in non-firefox-test builds.
pub fn pmm_alloc_recent_free_count() -> u64 {
    #[cfg(feature = "firefox-test")]
    {
        PMM_ALLOC_RECENT_FREE.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "firefox-test"))]
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
    #[cfg(feature = "firefox-test")]
    { PMM_ALLOC_NONZERO_RC.load(Ordering::Relaxed) }
    #[cfg(not(feature = "firefox-test"))]
    { 0 }
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
