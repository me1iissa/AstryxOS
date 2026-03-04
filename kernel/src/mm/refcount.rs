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

use core::sync::atomic::{AtomicU16, Ordering};
use spin::Once;

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
/// Returns the new count. If it reaches 0, the page can be freed.
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
pub fn page_ref_set(phys_addr: u64, count: u16) {
    let idx = pfn(phys_addr);
    let rc = refcounts();
    if idx < rc.len() {
        rc[idx].store(count, Ordering::Relaxed);
    }
}
