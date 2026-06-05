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
#[cfg(feature = "firefox-test-core")]
static REFCOUNT_SET_OVER_NONZERO: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of `page_ref_dec` calls that found the refcount already
/// at zero.  Every increment names a real upstream bug: a caller either
/// paired a `page_ref_inc` with two `page_ref_dec` calls, or decremented a
/// frame whose refcount was never bumped.  Pre-fix the function silently
/// wrapped through `0xFFFF` and then raced its recovery store against any
/// concurrent `page_ref_inc`, which could lose increments and re-corrupt
/// the table.  See `page_ref_dec` for the CAS-loop discipline that replaces
/// the racy recovery.  Always 0 outside `firefox-test` builds.
#[cfg(feature = "firefox-test-core")]
static PAGE_REF_DEC_UNDERFLOW: AtomicU64 = AtomicU64::new(0);

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
///
/// Internal helper for callers that must only run post-`init()`.
#[inline]
fn refcounts() -> &'static [AtomicU16] {
    REFCOUNTS.get().expect("refcount::init() not called")
}

/// Get the refcount array if already initialised, or `None` during early boot.
///
/// Used by read-only / diagnostic paths (e.g. `page_ref_count`) that can be
/// reached before `refcount::init()` via the early-boot allocator chain:
/// `vmm::init() → separate_higher_half_pds() → pmm::alloc_page() →
/// alloc_page_locked() → [firefox-test diagnostic] → page_ref_count()`.
/// At that point the heap is not yet set up, so REFCOUNTS is `None`.
/// Returning `None` here lets the caller return a safe sentinel (0) instead
/// of panicking with "refcount::init() not called".
#[inline]
fn refcounts_opt() -> Option<&'static [AtomicU16]> {
    // REFCOUNTS stores a &'static [AtomicU16]; Once::get() returns
    // Option<&&'static [AtomicU16]>, so one deref is needed to get the
    // inner &'static slice back.
    REFCOUNTS.get().copied()
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
    // W215 diagnostic Arm-1: record the REFINC event.
    #[cfg(feature = "firefox-test-core")]
    crate::mm::w215_diag::prov_record(
        phys_addr, crate::mm::w215_diag::KIND_REFINC, 0,
    );
}

/// Decrement the reference count for a physical page.
///
/// Returns the **new** count after the decrement.  Callers MUST check the
/// return value: when it is zero the frame has no remaining references and
/// must be freed via `pmm::free_page` only AFTER a completed TLB shootdown
/// on every CPU that may hold a cached translation to this frame
/// (see Intel SDM Vol. 3A §4.10.5).
///
/// # Underflow safety
///
/// Earlier versions of this function used `fetch_sub(1, Relaxed)` and then,
/// on observing a pre-decrement value of 0, performed a `store(0, Relaxed)`
/// recovery.  That recovery was racy against a concurrent `page_ref_inc`:
/// `fetch_sub(1)` on a `0u16` wraps the slot to `0xFFFF`, and if a peer
/// CPU's `fetch_add(1, Relaxed)` interleaved between the wrap and the
/// recovery store, the increment was silently lost — observable as a
/// later W215-class use-after-recycle once `pmm::free_page` was reached
/// on a frame that still had a live PTE referencing it.
///
/// The CAS loop below maintains the invariant "the slot never holds a
/// negative count" without using a recovery store: if the current value
/// is already 0, the decrement is rejected and `PAGE_REF_DEC_UNDERFLOW`
/// is bumped (every increment names a real upstream paired-call bug that
/// the maintainer should chase).  If the slot has decreased to 0 since
/// our last read but a concurrent `page_ref_inc` then bumped it, the CAS
/// reloads and retries with the new value — no increment can be lost.
///
/// Per the x86-64 memory model (Intel SDM Vol. 3A §8.2.2), `LOCK CMPXCHG`
/// is fully ordered and is the natural primitive for this pattern.  We use
/// `Ordering::Relaxed` for the success ordering because the refcount table
/// participates only in its own logical ordering (no cross-data invariant
/// relies on a stronger fence here); the consumer that decides to free the
/// frame must already serialise through the TLB-shootdown protocol, which
/// supplies the cross-CPU acquire fence.
#[must_use = "dropping the return value of page_ref_dec silently loses the \
              information needed to decide when to free the frame; check \
              whether the count reached zero and schedule a shootdown+free"]
pub fn page_ref_dec(phys_addr: u64) -> u16 {
    // W215 diagnostic Arm-1: record the REFDEC event.
    #[cfg(feature = "firefox-test-core")]
    crate::mm::w215_diag::prov_record(
        phys_addr, crate::mm::w215_diag::KIND_REFDEC, 0,
    );
    let idx = pfn(phys_addr);
    let rc = refcounts();
    if idx >= rc.len() {
        return 0;
    }
    let slot = &rc[idx];
    let mut cur = slot.load(Ordering::Relaxed);
    loop {
        if cur == 0 {
            // Refuse the underflow: leave the slot at 0 and return 0 so
            // the caller's "did we reach zero?" check still fires (it would
            // already have fired on the legitimate decrement that took the
            // count to zero; this second call is the bug).
            #[cfg(feature = "firefox-test-core")]
            {
                let total = PAGE_REF_DEC_UNDERFLOW
                    .fetch_add(1, Ordering::Relaxed) + 1;
                if total <= 8 || total % 1000 == 0 {
                    crate::serial_println!(
                        "[REFCOUNT/DEC-UNDERFLOW] phys={:#x} count_total={}",
                        phys_addr, total,
                    );
                }
            }
            return 0;
        }
        // Try to install `cur - 1`.  On CAS failure (some peer CPU
        // updated the slot between our load and CAS), reload `cur` from
        // the failure result and retry.
        match slot.compare_exchange_weak(
            cur,
            cur - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return cur - 1,
            Err(observed) => cur = observed,
        }
    }
}

/// Read the cumulative `PAGE_REF_DEC_UNDERFLOW` counter.
///
/// Returns the number of times [`page_ref_dec`] was called on a refcount
/// slot that was already zero.  Each non-zero observation names one
/// upstream paired-call bug (a caller decremented a frame twice, or
/// decremented one whose `page_ref_inc` was missed).  Always 0 on
/// non-`firefox-test` builds.
pub fn page_ref_dec_underflow_count() -> u64 {
    #[cfg(feature = "firefox-test-core")]
    { PAGE_REF_DEC_UNDERFLOW.load(Ordering::Relaxed) }
    #[cfg(not(feature = "firefox-test-core"))]
    { 0 }
}

/// Number of user-PTE references the kernel believes are alive on `phys`.
///
/// This is a thin alias for [`page_ref_count`] that documents the W215
/// `pte_share_count` invariant: every user-PTE install path
/// (page-fault handler, ELF loader, fork CoW, MAP_FIXED) MUST pair its
/// `map_page_in` with a matching `page_ref_inc`, and every PTE-clearing
/// path (unmap, mremap, mprotect→PROT_NONE, process exit) MUST pair its
/// PTE-clear with a matching `page_ref_dec`.  When the invariant holds,
/// the value returned here is the count of live user PTEs that reference
/// `phys`.  When [`crate::mm::pmm::free_page`] is about to return a frame
/// to the PMM free list, this value MUST be zero — otherwise the frame
/// would be repurposed while a stale PTE still maps a user VA to it,
/// producing the W215 fault class (post-evict execution from a recycled
/// physical frame).
///
/// Per Intel SDM Vol. 3A §4.10.5, paging-structure changes must be
/// propagated to every processor before a physical frame is repurposed.
/// Per POSIX mmap(2), the page contents observable through a mapping
/// must remain valid for the lifetime of the mapping.
#[inline]
pub fn pte_share_count(phys_addr: u64) -> u16 {
    page_ref_count(phys_addr)
}

/// Get the current reference count for a physical page.
///
/// Returns 0 if the refcount table has not yet been initialised (early-boot
/// allocator calls arrive before `refcount::init()` — returning 0 is correct
/// because no PTE references have been recorded yet).
pub fn page_ref_count(phys_addr: u64) -> u16 {
    let rc = match refcounts_opt() {
        Some(r) => r,
        None => return 0, // pre-init: no refs tracked yet
    };
    let idx = pfn(phys_addr);
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
    let rc = match refcounts_opt() {
        Some(r) => r,
        None => return, // pre-init: table does not exist yet, silently no-op
    };
    let idx = pfn(phys_addr);
    if idx < rc.len() {
        // H1 diagnostic: observe decreasing set-over-nonzero transitions.
        #[cfg(feature = "firefox-test-core")]
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
    #[cfg(feature = "firefox-test-core")]
    { REFCOUNT_SET_OVER_NONZERO.load(Ordering::Relaxed) }
    #[cfg(not(feature = "firefox-test-core"))]
    { 0 }
}
