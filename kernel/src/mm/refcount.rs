//! Physical Page Reference Counting
//!
//! Tracks how many page tables reference each physical page frame.
//! Required for Copy-on-Write (CoW) fork: when a page has refcount > 1,
//! a write fault triggers a copy instead of modifying in place.
//!
//! Uses a heap-allocated array indexed by page frame number (PFN).
//! Supports up to 4 GiB of physical memory (1M pages).
//!
//! The array is allocated on the heap during `init()` to avoid inflating
//! the kernel's BSS section (which would overlap the BootInfo area).

extern crate alloc;

use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use spin::Once;

/// Diagnostic counter (firefox-test only): number of times `page_ref_set` was
/// called with `val < existing_rc` on a frame that already had a non-zero
/// refcount.  A decreasing set-over-nonzero is the H1 signature for a caller
/// that resets a live frame's refcount without going through `page_ref_dec`,
/// bypassing the zero-check that would trigger `pmm::free_page`.
#[cfg(feature = "firefox-test")]
static REFCOUNT_SET_OVER_NONZERO: AtomicU64 = AtomicU64::new(0);

/// Maximum physical pages we track (same as PMM: 4 GiB / 4 KiB = 1M pages).
const MAX_PAGES: usize = 1024 * 1024;

/// Heap-allocated reference-count array, initialized once by `init()`.
static REFCOUNTS: Once<&'static [AtomicU16]> = Once::new();

/// Initialize the refcount table (call after the heap allocator is ready).
pub fn init() {
    REFCOUNTS.call_once(|| {
        let mut v = alloc::vec::Vec::with_capacity(MAX_PAGES);
        for _ in 0..MAX_PAGES {
            v.push(AtomicU16::new(0));
        }
        // Leak into a &'static slice so we never deallocate it.
        let boxed_slice = v.into_boxed_slice();
        let ptr = alloc::boxed::Box::leak(boxed_slice);
        &*ptr
    });
}

/// Get the refcount array, panicking if not yet initialised.
#[inline]
fn refcounts() -> &'static [AtomicU16] {
    REFCOUNTS.get().expect("refcount::init() not called")
}

/// Page frame number from a physical address.
fn pfn(phys_addr: u64) -> usize {
    (phys_addr / 4096) as usize
}

/// Increment the reference count for a physical page.
/// Called when a new page table references this page (e.g., CoW fork).
pub fn page_ref_inc(phys_addr: u64) {
    let idx = pfn(phys_addr);
    let rc = refcounts();
    if idx < rc.len() {
        rc[idx].fetch_add(1, Ordering::Relaxed);
    }
}

/// Decrement the reference count for a physical page.
///
/// Returns the **new** count after the decrement.  Callers MUST check the
/// return value: when it is zero the frame has no remaining references and
/// must be freed via `pmm::free_page` only AFTER a completed TLB shootdown
/// on every CPU that may hold a cached translation to this frame
/// (see Intel SDM Vol. 3A §4.10.5).
#[must_use = "dropping the return value of page_ref_dec silently loses the \
              information needed to decide when to free the frame; check \
              whether the count reached zero and schedule a shootdown+free"]
pub fn page_ref_dec(phys_addr: u64) -> u16 {
    let idx = pfn(phys_addr);
    let rc = refcounts();
    if idx < rc.len() {
        let prev = rc[idx].fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            // Underflow protection — shouldn't happen but be safe
            rc[idx].store(0, Ordering::Relaxed);
            return 0;
        }
        prev - 1
    } else {
        0
    }
}

/// Get the current reference count for a physical page.
pub fn page_ref_count(phys_addr: u64) -> u16 {
    let idx = pfn(phys_addr);
    let rc = refcounts();
    if idx < rc.len() {
        rc[idx].load(Ordering::Relaxed)
    } else {
        0
    }
}

/// Set the reference count for a physical page (used during initialization).
///
/// Under the `firefox-test` feature gate, this function observes any case
/// where `count` is less than the existing non-zero refcount.  Such a
/// decreasing set-over-nonzero bypasses the zero-transition that would
/// normally trigger `pmm::free_page`, which is a potential H1 aliasing path:
/// the frame is not freed, but its refcount is silently lowered, possibly
/// below the number of live PTEs that still reference it.
pub fn page_ref_set(phys_addr: u64, count: u16) {
    let idx = pfn(phys_addr);
    let rc = refcounts();
    if idx < rc.len() {
        // H1 diagnostic: observe decreasing set-over-nonzero transitions.
        #[cfg(feature = "firefox-test")]
        {
            let existing = rc[idx].load(Ordering::Relaxed);
            if existing > 0 && count != existing && count < existing {
                let total = REFCOUNT_SET_OVER_NONZERO
                    .fetch_add(1, Ordering::Relaxed) + 1;
                if total <= 8 || total % 1000 == 0 {
                    crate::serial_println!(
                        "[REFCOUNT/SET-OVER-NONZERO] phys={:#x} existing_rc={} new_rc={} count_total={}",
                        phys_addr, existing, count, total,
                    );
                }
            }
        }
        rc[idx].store(count, Ordering::Relaxed);
    }
}

/// Read the cumulative `REFCOUNT_SET_OVER_NONZERO` counter.
///
/// Returns the number of times `page_ref_set` decreased a non-zero refcount.
/// Always 0 on non-firefox-test builds.
pub fn refcount_set_over_nonzero_count() -> u64 {
    #[cfg(feature = "firefox-test")]
    { REFCOUNT_SET_OVER_NONZERO.load(Ordering::Relaxed) }
    #[cfg(not(feature = "firefox-test"))]
    { 0 }
}
