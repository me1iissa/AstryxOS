//! DMA frame pinning for in-flight device transfers.
//!
//! # Why this exists
//!
//! A block driver may hand a device the raw physical address of a caller's
//! data frame (the virtio-blk request path programs a descriptor whose `addr`
//! field is the DMA-target frame's physical address).  Per the VIRTIO 1.2
//! specification §2.7.13.3, once a buffer descriptor is exposed in the
//! available ring the device MAY read or write that buffer at any time until
//! it returns the chain via the used ring (§2.7.14).  The frame is therefore
//! *device-owned* for the whole request lifetime.
//!
//! If the request stalls and the submitter abandons it on a no-progress
//! deadline, the caller's error path may `pmm::free_page` the DMA-target frame
//! while the device still owns the descriptor that points at it.  The PMM then
//! reallocates the frame for an unrelated purpose, and a late device
//! completion writes stale transfer bytes into that frame — a classic
//! DMA-buffer use-after-free that corrupts whatever now owns the frame.
//!
//! # The pin contract
//!
//! A driver that exposes a caller frame to a device takes a **DMA pin** on
//! every frame the device may touch, for the request lifetime:
//!
//!   * [`pin_range`] at submit time (before the descriptor is exposed).
//!   * [`unpin_range`] only when the device truly retires the request
//!     (used-ring reclaim, or a device reset that abandons all in-flight
//!     chains — never merely on the submitter's timeout).
//!
//! While a frame is pinned, [`crate::mm::pmm::free_page`] does not return it to
//! the allocator.  Instead the free is **deferred**: the free request is
//! remembered, and the frame is returned to the PMM only when the last pin is
//! released.  A caller's `free_page` on the error path therefore becomes a
//! decrement-and-defer instead of handing a device-owned frame back to the
//! pool.  This is the physical-memory analogue of a POSIX
//! `get_user_pages()`-style page pin held across an in-flight I/O.
//!
//! # Deferred-free contract
//!
//! Correctness requires the deferred frame to be *actually* freed once the
//! device retires — no permanent leak.  Two release contexts exist:
//!
//!   * **Thread context** (a waiter reclaiming its own slot): the last unpin
//!     frees the frame directly via `pmm::free_page`.
//!   * **Hard-IRQ context** (a completion ISR reclaiming a quarantined slot):
//!     `pmm::free_page` takes a spinlock that a preempted thread on the same
//!     CPU may already hold, so the ISR MUST NOT free inline.  The last unpin
//!     instead posts the frame to a lock-free deferred ring which the next
//!     thread-context unpin (or the device-reset path) drains.  If the device
//!     never completes, the frame stays safely out of circulation until the
//!     reset-recovery path releases every pin — a bounded leak, never a
//!     use-after-free.
//!
//! Per Intel SDM Vol. 3A §4.10.5, paging-structure and frame-repurposing
//! changes must be serialised against every agent that can still reference the
//! frame; a DMA-capable device is such an agent, and this ledger is how the
//! block layer holds a frame out of reuse until the device is done with it.

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::Once;

/// Maximum physical pages tracked — same window as the PMM / refcount table
/// (4 GiB / 4 KiB = 1M pages).
const MAX_PAGES: usize = 1024 * 1024;

const PAGE_SIZE: u64 = 4096;

/// Low bits of a pin slot hold the pin count; the top bit records a deferred
/// free request against the frame.  Keeping both in one `AtomicU32` lets the
/// "drop to zero AND a free is pending" test be a single compare-exchange, so
/// the frame is freed exactly once with no torn count/flag window.
const COUNT_MASK: u32 = 0x7FFF_FFFF;
const FREE_PENDING: u32 = 0x8000_0000;

/// Per-PFN pin ledger, heap-allocated once by [`init`] (like the refcount
/// table, this avoids a multi-MiB BSS region that would collide with the
/// BootInfo area).
static PINS: Once<&'static [AtomicU32]> = Once::new();

/// Capacity of the lock-free deferred-free ring.  Only frames whose last pin
/// is dropped from hard-IRQ context land here, which is rare (the common
/// reclaim happens in the waiter's thread context).  On overflow the frame is
/// left pinned-and-leaked rather than freed unsafely — safe, and bounded by
/// the device-reset recovery path.
const DEFERRED_CAP: usize = 256;

/// Lock-free deferred-free slots.  A zero entry is empty; a non-zero entry is a
/// physical frame awaiting a thread-context `pmm::free_page`.
static DEFERRED: [AtomicU64; DEFERRED_CAP] =
    [const { AtomicU64::new(0) }; DEFERRED_CAP];

/// Number of frames dropped because the deferred ring was full (leaked, safe).
static DEFERRED_OVERFLOW: AtomicU64 = AtomicU64::new(0);

/// Cumulative deferred frees actually executed (diagnostic).
static DEFERRED_FREED: AtomicU64 = AtomicU64::new(0);

/// Cumulative frees deferred by [`mark_free_pending_if_pinned`] (diagnostic).
static FREES_DEFERRED: AtomicU64 = AtomicU64::new(0);

/// Cursor for round-robin scanning of the deferred ring on push (reduces
/// linear-scan contention when several frames are posted in a burst).
static DEFERRED_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// Initialise the pin ledger.  Call once, after the heap allocator is ready
/// (paired with `refcount::init`).  Idempotent via `Once`.
pub fn init() {
    PINS.call_once(|| {
        let mut v = alloc::vec::Vec::with_capacity(MAX_PAGES);
        for _ in 0..MAX_PAGES {
            v.push(AtomicU32::new(0));
        }
        let boxed = v.into_boxed_slice();
        &*alloc::boxed::Box::leak(boxed)
    });
}

#[inline]
fn pins_opt() -> Option<&'static [AtomicU32]> {
    PINS.get().copied()
}

#[inline]
fn pfn(phys: u64) -> usize {
    (phys / PAGE_SIZE) as usize
}

/// First PFN and frame count spanned by the byte range `[phys, phys + len)`.
#[inline]
fn page_span(phys: u64, len: usize) -> (usize, usize) {
    if len == 0 {
        return (pfn(phys), 0);
    }
    let first = pfn(phys);
    let last = pfn(phys + (len as u64) - 1);
    (first, last - first + 1)
}

/// Increment the pin count for the frame containing `phys`.
#[inline]
pub fn pin(phys: u64) {
    let pins = match pins_opt() {
        Some(p) => p,
        None => return, // pre-init: no device DMA can be in flight yet
    };
    let idx = pfn(phys);
    if idx < pins.len() {
        // The count occupies the low 31 bits and never approaches 2^31 in
        // practice (bounded by MAX_INFLIGHT * pages-per-request), so a plain
        // increment cannot carry into the FREE_PENDING bit.
        pins[idx].fetch_add(1, Ordering::AcqRel);
    }
}

/// Pin every frame the byte range `[phys, phys + len)` touches.
#[inline]
pub fn pin_range(phys: u64, len: usize) {
    let (first, count) = page_span(phys, len);
    for i in 0..count {
        pin(((first + i) as u64) * PAGE_SIZE);
    }
}

/// Is the frame containing `phys` currently pinned by at least one in-flight
/// transfer?
#[inline]
pub fn is_pinned(phys: u64) -> bool {
    pin_count(phys) > 0
}

/// Current pin count for the frame containing `phys` (0 if unpinned or the
/// ledger is not yet initialised).
#[inline]
pub fn pin_count(phys: u64) -> u32 {
    let pins = match pins_opt() {
        Some(p) => p,
        None => return 0,
    };
    let idx = pfn(phys);
    if idx < pins.len() {
        pins[idx].load(Ordering::Acquire) & COUNT_MASK
    } else {
        0
    }
}

/// Atomically record a deferred free against `phys` **iff** the frame is
/// pinned.  Returns `true` when the frame is pinned and the free was deferred
/// (the caller MUST NOT free the frame now — the last [`unpin`] will), or
/// `false` when the frame is not pinned (the caller should free normally).
///
/// This is the single point that resolves the free-vs-last-unpin race: setting
/// the FREE_PENDING bit and dropping the count to zero are both compare-exchange
/// against the same word, so exactly one of "defer then unpin frees" or
/// "unpin already emptied, free normally" happens — never both, never neither.
#[inline]
pub fn mark_free_pending_if_pinned(phys: u64) -> bool {
    let pins = match pins_opt() {
        Some(p) => p,
        None => return false,
    };
    let idx = pfn(phys);
    if idx >= pins.len() {
        return false;
    }
    let slot = &pins[idx];
    let mut cur = slot.load(Ordering::Acquire);
    loop {
        if (cur & COUNT_MASK) == 0 {
            // Not pinned (or the last unpin won the race) — caller frees now.
            return false;
        }
        if (cur & FREE_PENDING) != 0 {
            // Already deferred by a prior free request.
            return true;
        }
        match slot.compare_exchange_weak(
            cur,
            cur | FREE_PENDING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                FREES_DEFERRED.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            Err(observed) => cur = observed,
        }
    }
}

/// Result of a single [`unpin_ledger`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnpinResult {
    /// Count decremented; frame still pinned or no deferred free was pending.
    NoFree,
    /// The last pin was released and a free had been deferred — the frame is
    /// now due to be returned to the PMM.
    FreeDue,
    /// Unpin was called on an already-zero count (a paired-call bug).
    Underflow,
}

/// Decrement the pin count for the frame containing `phys`.  When this drops
/// the count to zero **and** a free was deferred while pinned, clears both and
/// returns [`UnpinResult::FreeDue`] — the caller is then responsible for the
/// actual free (see [`unpin`] for the context-aware wrapper).
fn unpin_ledger(phys: u64) -> UnpinResult {
    let pins = match pins_opt() {
        Some(p) => p,
        None => return UnpinResult::NoFree,
    };
    let idx = pfn(phys);
    if idx >= pins.len() {
        return UnpinResult::NoFree;
    }
    let slot = &pins[idx];
    let mut cur = slot.load(Ordering::Acquire);
    loop {
        let count = cur & COUNT_MASK;
        if count == 0 {
            return UnpinResult::Underflow;
        }
        let pending = cur & FREE_PENDING;
        let new_count = count - 1;
        // On the last release, clear the pending bit together with the count so
        // a subsequent re-pin of the same (freed-and-reallocated) frame starts
        // from a clean slate.
        let new_val = if new_count == 0 { 0 } else { pending | new_count };
        match slot.compare_exchange_weak(
            cur,
            new_val,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                if new_count == 0 && pending != 0 {
                    return UnpinResult::FreeDue;
                }
                return UnpinResult::NoFree;
            }
            Err(observed) => cur = observed,
        }
    }
}

/// Release one pin on the frame containing `phys`.
///
/// `can_free_now` MUST be `true` only when the caller runs in a context where
/// taking the PMM spinlock is safe (ordinary thread context), and `false` from
/// hard-IRQ context (a completion ISR).  When the last pin is released and a
/// free was deferred:
///   * `can_free_now == true`  → free this frame directly.
///   * `can_free_now == false` → post this frame to the lock-free deferred ring
///     for a later thread-context drain.
///
/// This does NOT sweep the IRQ-deferred ring — callers that release a whole
/// buffer should call [`drain_deferred`] once at the range level (see
/// `unpin_range`) rather than paying an O(ring) scan per page.
#[inline]
pub fn unpin(phys: u64, can_free_now: bool) {
    match unpin_ledger(phys) {
        UnpinResult::FreeDue => {
            if can_free_now {
                DEFERRED_FREED.fetch_add(1, Ordering::Relaxed);
                crate::mm::pmm::free_page(phys);
            } else {
                push_deferred(phys);
            }
        }
        UnpinResult::Underflow => {
            crate::serial_println!(
                "[DMA-PIN] unpin underflow phys={:#x} (paired-call bug)", phys,
            );
        }
        UnpinResult::NoFree => {}
    }
}

/// Unpin every frame the byte range `[phys, phys + len)` touches.  When
/// `can_free_now` is set (thread context), also sweep the IRQ-deferred ring
/// once for the whole range so any frame a prior completion ISR could not free
/// inline is returned to the PMM here.
#[inline]
pub fn unpin_range(phys: u64, len: usize, can_free_now: bool) {
    let (first, count) = page_span(phys, len);
    if can_free_now {
        // Sweep prior IRQ-deferred frees once, in this lock-safe context.
        drain_deferred();
    }
    for i in 0..count {
        unpin(((first + i) as u64) * PAGE_SIZE, can_free_now);
    }
}

/// Post `phys` to the lock-free deferred-free ring (IRQ-safe: no spinlock).
fn push_deferred(phys: u64) {
    if phys == 0 {
        return;
    }
    let start = DEFERRED_CURSOR.fetch_add(1, Ordering::Relaxed);
    for i in 0..DEFERRED_CAP {
        let slot = &DEFERRED[(start.wrapping_add(i)) % DEFERRED_CAP];
        if slot
            .compare_exchange(0, phys, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
    // Ring full — leave the frame pinned-and-leaked rather than free it from an
    // unsafe context.  Bounded and safe; the reset path recovers it.
    let n = DEFERRED_OVERFLOW.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 || n % 1000 == 0 {
        crate::serial_println!(
            "[DMA-PIN] deferred-free ring full; leaking phys={:#x} total={}",
            phys, n,
        );
    }
}

/// Drain the deferred-free ring, returning each queued frame to the PMM.  Safe
/// to call only from thread context (it takes the PMM lock).  Idempotent and
/// cheap when the ring is empty.
pub fn drain_deferred() {
    for slot in DEFERRED.iter() {
        // Fast path: skip empty slots without a RMW.
        if slot.load(Ordering::Acquire) == 0 {
            continue;
        }
        let phys = slot.swap(0, Ordering::AcqRel);
        if phys != 0 {
            DEFERRED_FREED.fetch_add(1, Ordering::Relaxed);
            crate::mm::pmm::free_page(phys);
        }
    }
}

/// Diagnostic totals: (frees deferred, deferred frees executed, ring overflows).
pub fn stats() -> (u64, u64, u64) {
    (
        FREES_DEFERRED.load(Ordering::Relaxed),
        DEFERRED_FREED.load(Ordering::Relaxed),
        DEFERRED_OVERFLOW.load(Ordering::Relaxed),
    )
}

/// Self-check of the pin ledger's accounting invariants.  Operates only on the
/// ledger word for a high, page-aligned test PFN — it never hands that frame to
/// the PMM (the `FreeDue` transitions are inspected via `unpin_ledger`
/// directly, not `pmm::free_page`), so it is safe to run on a live system.
/// Returns `Err(&str)` naming the first violated invariant.
#[cfg(any(test, feature = "test-mode", feature = "firefox-test-core"))]
pub fn test_ledger() -> Result<(), &'static str> {
    // A high, page-aligned test PFN inside the tracked window.  We only ever
    // touch the ledger word for this PFN, never PMM state for it.
    let p: u64 = ((MAX_PAGES as u64) - 3) * PAGE_SIZE;

    if is_pinned(p) {
        return Err("test frame unexpectedly pinned on entry");
    }

    // (1) A pinned frame reports FreeDue on the final unpin once a free is
    //     deferred against it.
    pin(p);
    if pin_count(p) != 1 {
        return Err("pin did not raise count to 1");
    }
    if !mark_free_pending_if_pinned(p) {
        return Err("mark_free_pending_if_pinned returned false on a pinned frame");
    }
    if unpin_ledger(p) != UnpinResult::FreeDue {
        return Err("last unpin of a free-pending frame did not report FreeDue");
    }
    if is_pinned(p) {
        return Err("frame still pinned after final unpin");
    }

    // (2) not-pinned frame: mark_free_pending_if_pinned returns false.
    if mark_free_pending_if_pinned(p) {
        return Err("mark_free_pending_if_pinned true on an unpinned frame");
    }

    // (3) multi-pin (the 8x-retry-same-phys shape): free deferred once, only the
    //     LAST unpin reports FreeDue.
    pin(p);
    pin(p);
    pin(p);
    if pin_count(p) != 3 {
        return Err("triple pin did not reach count 3");
    }
    if !mark_free_pending_if_pinned(p) {
        return Err("multi-pin free not deferred");
    }
    if unpin_ledger(p) != UnpinResult::NoFree {
        return Err("1st of 3 unpins reported a free");
    }
    if unpin_ledger(p) != UnpinResult::NoFree {
        return Err("2nd of 3 unpins reported a free");
    }
    if unpin_ledger(p) != UnpinResult::FreeDue {
        return Err("3rd (last) of 3 unpins did not report FreeDue");
    }

    // (4) unpin underflow guard.
    if unpin_ledger(p) != UnpinResult::Underflow {
        return Err("unpin on a zero count did not report Underflow");
    }
    if pin_count(p) != 0 {
        return Err("count corrupted after underflow guard");
    }

    // (5) race resolution: unpin-to-zero BEFORE the free request → free normally.
    pin(p);
    if unpin_ledger(p) != UnpinResult::NoFree {
        return Err("plain unpin (no pending) reported a free");
    }
    if mark_free_pending_if_pinned(p) {
        return Err("free after count already zero was wrongly deferred");
    }

    Ok(())
}
