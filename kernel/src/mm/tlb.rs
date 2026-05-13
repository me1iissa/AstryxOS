//! Cross-CPU TLB shootdown.
//!
//! When a PTE is *cleared*, *write-protected*, or otherwise has its
//! permissions tightened in one process address space, every CPU that
//! currently has that CR3 loaded — *or* might be about to load it — must
//! invalidate its TLB entries for the affected range.  Without that the
//! other CPUs continue to use a cached translation that points to a page
//! the kernel has just freed, write-protected, or remapped, producing
//! silent memory corruption or, when the physical frame is recycled, a
//! use-after-free that can manifest as an arbitrary GPF in the running
//! user code.
//!
//! This module implements the AstryxOS TLB shootdown protocol:
//!
//! 1. Every process address space tracks, in [`crate::proc::Process`], the
//!    set of CPUs that have its CR3 currently loaded (one bit per CPU in
//!    an `AtomicU64`).  The scheduler updates that bit on every CR3 load
//!    and unload (see [`note_cr3_load`] / [`note_cr3_unload`]).
//!
//! 2. The PTE-mutating site calls [`shootdown_range`] with `(cr3, start,
//!    end)`.  We snapshot the active-CPU mask for `cr3`, exclude the
//!    calling CPU, and for every remaining bit write a per-CPU shootdown
//!    payload slot, send an IPI on the reserved vector
//!    [`TLB_SHOOTDOWN_VECTOR`], and spin on the per-target `ack` flag
//!    with a microsecond-scale deadline.
//!
//! 3. The IPI handler [`handle_shootdown_ipi`] reads its own slot,
//!    invalidates every page in `[start, end)` if the slot's CR3 matches
//!    the currently active CR3 on that CPU, then bumps `ack`.
//!
//! The reserved LAPIC vector `0xF0` is below the LAPIC spurious-interrupt
//! cutoff (0xFF) and above every hardware-IRQ vector AstryxOS uses
//! (0x20..0x2F).  No other AstryxOS handler installs at 0xF0.  Per Intel
//! SDM Vol 3A §10.5.1 and §10.6.1, fixed-mode IPIs may target any
//! interrupt vector ≥ 16; vector 0xF0 satisfies that and matches the
//! convention used by other x86_64 kernels for cross-CPU TLB flushes.
//!
//! # Feature gating
//!
//! The full shootdown protocol is enabled by default but can be turned
//! off with `--features tlb-shootdown-off` for bisect/baseline use.
//! With the protocol disabled the API is reduced to a local-only
//! `invlpg` so single-CPU correctness is preserved.
//!
//! # Lock order
//!
//! `CR3_ACTIVE_CPUS` is a leaf lock; it must not be acquired while
//! holding any other kernel lock that another thread might acquire
//! across a syscall.  All operations on it are either bare atomic
//! ops on the per-CR3 mask or short critical sections that take the
//! map mutex and immediately drop it after returning a snapshot.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;

use crate::arch::x86_64::apic;

/// Reserved LAPIC vector for the cross-CPU TLB shootdown IPI.
///
/// Chosen so it sits above every hardware IRQ vector (0x20..0x2F)
/// AstryxOS routes through the IO-APIC, below the LAPIC spurious-
/// interrupt cutoff (0xFF), and clear of the syscall gates (0x2E,
/// 0x80).  See Intel SDM Vol 3A §10.6.1 (Interrupt Command Register).
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xF0;

/// Threshold (in pages) at and above which a range invalidation falls back
/// to a full TLB reload (write CR3) instead of per-page `invlpg`.  Any range
/// covering **more than** `FULL_FLUSH_PAGES_THRESHOLD` pages takes the
/// full-flush path; up to and including the threshold it remains a per-page
/// `invlpg` loop.  Mirrors the policy used by other x86_64 kernels;
/// `invlpg` per page costs ~100 cycles each so above this threshold a CR3
/// reload is cheaper than the loop.
const FULL_FLUSH_PAGES_THRESHOLD: usize = 32;

/// Per-CPU shootdown payload slot.
///
/// The IPI sender writes `cr3 / va_lo / va_hi`, then publishes the slot
/// to the target by setting `pending` to 1 and sending the IPI.  The
/// target reads the slot, performs the invalidation, and clears
/// `pending` to 0 — which the sender spins on.
struct ShootdownSlot {
    /// CR3 the shootdown is targeted at.  Stale TLB entries on a CPU
    /// that has since switched away from this CR3 will be evicted
    /// naturally on the next CR3 reload, so we only invalidate if the
    /// running CR3 still matches.
    cr3: AtomicU64,
    /// Inclusive lower bound of the virtual range, page-aligned.
    va_lo: AtomicU64,
    /// Exclusive upper bound of the virtual range, page-aligned.
    va_hi: AtomicU64,
    /// 1 while the slot holds an unacknowledged request, 0 otherwise.
    /// Sender writes 1 before signalling the IPI; handler clears to 0
    /// after performing the invalidation.
    pending: AtomicU8,
}

impl ShootdownSlot {
    const fn new() -> Self {
        Self {
            cr3: AtomicU64::new(0),
            va_lo: AtomicU64::new(0),
            va_hi: AtomicU64::new(0),
            pending: AtomicU8::new(0),
        }
    }
}

/// Per-CPU shootdown slots, indexed by `cpu_index()` (0..MAX_CPUS).
static SHOOTDOWN_SLOTS: [ShootdownSlot; apic::MAX_CPUS] =
    [const { ShootdownSlot::new() }; apic::MAX_CPUS];

/// Active-CPU mask keyed by CR3.  Each bit `i` is set when CPU `i` has
/// the indexed CR3 currently loaded.  Updated by [`note_cr3_load`] and
/// [`note_cr3_unload`] from the scheduler context-switch path.
///
/// The map is a leaf lock — never held across other kernel locks.
static CR3_ACTIVE_CPUS: Mutex<BTreeMap<u64, AtomicU64>> = Mutex::new(BTreeMap::new());

/// Statistic: number of shootdowns issued (sender side).
static STAT_SHOOTDOWNS_SENT: AtomicU64 = AtomicU64::new(0);

/// Statistic: number of IPIs delivered (sender side, target CPUs poked).
static STAT_IPIS_SENT: AtomicU64 = AtomicU64::new(0);

/// Statistic: number of IPIs that timed out waiting for ack.  A non-zero
/// value indicates a wedged CPU.
static STAT_ACK_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// Statistic: number of shootdowns handled (receiver side).
static STAT_SHOOTDOWNS_HANDLED: AtomicU64 = AtomicU64::new(0);

/// Lightweight running-on-AP guard for the early-boot window.  Set to
/// true once the scheduler has begun migrating threads onto APs; before
/// that, only the BSP exists and a local `invlpg` is sufficient.
static SMP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Mark the system as having ≥2 active CPUs.  Called from [`apic::start_aps`]
/// after all APs are online as a belt-and-braces backstop.  In practice each
/// AP flips the flag itself via [`mark_self_smp_online`] before it enables
/// interrupts, so by the time `start_aps` returns the flag is already set.
/// Before this is set, [`shootdown_range`] short-circuits to a local-only
/// `invlpg` since no other CPU can be touching the TLB.
pub fn mark_smp_active() {
    SMP_ACTIVE.store(true, Ordering::Release);
}

/// Called from each AP on its own entry path immediately before it enables
/// interrupts and joins the scheduler.  Flips the global SMP_ACTIVE flag
/// so that subsequent [`shootdown_range`] calls — including ones issued
/// from the BSP while later APs are still booting — emit IPIs to this CPU
/// instead of short-circuiting to a local-only `invlpg`.
///
/// The previous design only set `SMP_ACTIVE` once `start_aps` had finished
/// bringing up every AP.  That left a per-AP window between
/// "AP records its CR3 via `note_cr3_load`" and "BSP flips the global
/// flag" during which a shootdown from the BSP for an address space this
/// AP had loaded would silently miss this CPU.  Having each AP set the
/// flag itself, after its CR3 bookkeeping and IDT are live, closes that
/// window without changing the BSP-side call.  Multiple concurrent flips
/// are harmless (idempotent monotonic store).
pub fn mark_self_smp_online() {
    SMP_ACTIVE.store(true, Ordering::Release);
}

/// Record that this CPU has just loaded `cr3`.  Called from the
/// scheduler immediately AFTER the `mov cr3` instruction completes —
/// the bit must only be set when the CR3 is actually live, so that a
/// shootdown sent in the window between "set bit" and "load CR3" cannot
/// race past us.
pub fn note_cr3_load(cr3: u64) {
    if cr3 == 0 {
        return;
    }
    let cpu = apic::cpu_index();
    if cpu >= apic::MAX_CPUS {
        return;
    }
    let mask = 1u64 << (cpu as u64);
    let mut map = CR3_ACTIVE_CPUS.lock();
    let entry = map
        .entry(cr3)
        .or_insert_with(|| AtomicU64::new(0));
    entry.fetch_or(mask, Ordering::AcqRel);
}

/// Record that this CPU has just left `cr3` (i.e. is about to switch
/// to a different one).  Called from the scheduler immediately BEFORE
/// the `mov cr3` that loads the new value — the bit must be cleared
/// while the CR3 is still live, so that a concurrent shootdown finds
/// the old CR3's mask consistent with the TLB state.
pub fn note_cr3_unload(cr3: u64) {
    if cr3 == 0 {
        return;
    }
    let cpu = apic::cpu_index();
    if cpu >= apic::MAX_CPUS {
        return;
    }
    let mask = !(1u64 << (cpu as u64));
    let map = CR3_ACTIVE_CPUS.lock();
    if let Some(entry) = map.get(&cr3) {
        entry.fetch_and(mask, Ordering::AcqRel);
    }
}

/// Remove all tracking state for `cr3`.  Called from
/// [`crate::proc::free_user_page_tables`] once the address space has
/// been torn down: no CPU can have it loaded any longer, so the
/// associated bitmask is no longer meaningful.
///
/// In debug builds this asserts that the active-CPU mask is zero —
/// i.e. that every CPU which ever ran on `cr3` has since called
/// `note_cr3_unload(cr3)`.  A non-zero mask at forget time indicates a
/// missing `note_cr3_unload` somewhere in the scheduler path, which
/// would leave a stale bit pointing at this freed CR3 and could cause
/// a later `shootdown_range` to target a CPU that has long since
/// switched away — pessimal but not catastrophic, since the IPI
/// handler's running-CR3 check rejects the stale invalidation.  We
/// still want this caught in tests rather than allowed to drift.
pub fn forget_cr3(cr3: u64) {
    if cr3 == 0 {
        return;
    }
    debug_assert_eq!(
        snapshot_active_mask(cr3),
        0,
        "forget_cr3({:#x}) called with non-zero active-CPU mask — a CPU \
         is still bookkept as running on this CR3 (missing note_cr3_unload)",
        cr3,
    );
    let mut map = CR3_ACTIVE_CPUS.lock();
    map.remove(&cr3);
}

/// Snapshot the active-CPU mask for `cr3`.  Returns 0 if `cr3` is not
/// tracked (e.g. kernel CR3, or an address space that has never been
/// scheduled).
fn snapshot_active_mask(cr3: u64) -> u64 {
    if cr3 == 0 {
        return 0;
    }
    let map = CR3_ACTIVE_CPUS.lock();
    map.get(&cr3)
        .map(|m| m.load(Ordering::Acquire))
        .unwrap_or(0)
}

/// Local `invlpg` over `[va_lo, va_hi)`.  Used by both the sender and
/// the IPI handler.
#[inline]
fn local_invlpg_range(va_lo: u64, va_hi: u64) {
    let lo = va_lo & !0xFFFu64;
    let hi = (va_hi + 0xFFF) & !0xFFFu64;
    let pages = ((hi.saturating_sub(lo)) >> 12) as usize;
    if pages > FULL_FLUSH_PAGES_THRESHOLD {
        // Large range — full TLB flush via CR3 reload is cheaper than
        // hundreds of invlpg.  Intel SDM Vol 3A §4.10.4.1: MOV to CR3
        // invalidates all TLB entries for the current process (but
        // preserves PCID-tagged entries — AstryxOS doesn't use PCID, so
        // this is a full TLB drop).
        crate::mm::vmm::flush_tlb();
        return;
    }
    let mut p = lo;
    while p < hi {
        crate::mm::vmm::invlpg(p);
        p += 0x1000;
    }
}

/// Shoot down TLB entries for `[va_lo, va_hi)` in the address space
/// identified by `cr3` on every CPU that currently has that CR3 loaded
/// (other than the calling CPU).  Always performs a local invalidation
/// on the calling CPU.
///
/// Returns once every targeted CPU has acknowledged the request, or
/// after a microsecond-scale deadline expires (in which case
/// `STAT_ACK_TIMEOUTS` is incremented and the wedged CPUs are skipped
/// — the kernel cannot make forward progress otherwise).
///
/// # When to call
///
/// Call this whenever a PTE is *cleared*, has its permissions *tightened*
/// (e.g. RW → RO during CoW write-protect), or is otherwise rewritten in
/// a way that demands the old translation be invalidated on every CPU
/// that might still hold it.  Installing a new mapping over a not-present
/// PTE does *not* require shootdown — there is no stale entry to evict —
/// and is left as a plain local `invlpg`.
pub fn shootdown_range(cr3: u64, va_lo: u64, va_hi: u64) {
    // Always do the local invalidation first.  This handles the common
    // single-CPU case at the cost of one extra invlpg on a 2+ CPU system,
    // which is negligible compared to the IPI cost.
    local_invlpg_range(va_lo, va_hi);

    // If SMP is not yet active, no other CPU can hold the TLB.
    if !SMP_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    // The protocol-off feature flag lets a bisect/baseline keep the
    // local invlpg but skip the cross-CPU work.
    #[cfg(feature = "tlb-shootdown-off")]
    {
        return;
    }

    #[cfg(not(feature = "tlb-shootdown-off"))]
    {
        let self_cpu = apic::cpu_index();
        if self_cpu >= apic::MAX_CPUS {
            return;
        }
        let self_mask = 1u64 << (self_cpu as u64);

        let mut targets = snapshot_active_mask(cr3) & !self_mask;
        if targets == 0 {
            return;
        }

        STAT_SHOOTDOWNS_SENT.fetch_add(1, Ordering::Relaxed);

        // Order the caller's PTE writes (write-back cacheable memory)
        // against the upcoming payload Release-store and the LAPIC IPI
        // MMIO write.  Per Intel SDM Vol 3A §4.10.4.2 (TLB shootdown
        // protocol) and §8.2.5 (memory-ordering instructions), MFENCE
        // serializes all prior loads and stores (including WB writes
        // to the page-table memory the caller has just mutated) with
        // respect to all later loads and stores from this processor.
        // Without it, the architectural memory-order rules allow the
        // PTE store to be globally visible after the slot Release-store
        // — so a target CPU could observe `pending = 1`, acquire the
        // payload, run `invlpg`, and STILL walk a stale PTE if the
        // PTE update has not yet drained.  The slot's own Release fence
        // orders the slot fields against `pending = 1`, but Release
        // does NOT order earlier WB stores against the IPI MMIO write.
        // MFENCE here, before the payload publish, plugs that gap for
        // every target CPU in one shot.
        core::sync::atomic::fence(Ordering::SeqCst);

        // Per Intel SDM Vol 3A §10.6.1, a fixed-mode IPI's delivery
        // status is reflected in ICR_LO bit 12.  send_ipi() already
        // waits for that bit to clear before returning, so we know the
        // IPI has been accepted by the target's LAPIC by the time we
        // begin spinning on ack.  See apic.rs::send_ipi.

        // Publish payloads to every target slot BEFORE any IPI is sent.
        // Each slot is single-writer (only this sender for the duration
        // of the protocol) and single-reader (only the target CPU).
        let mut t = targets;
        while t != 0 {
            let bit = t.trailing_zeros() as usize;
            t &= t - 1;
            if bit >= apic::MAX_CPUS {
                continue;
            }
            let slot = &SHOOTDOWN_SLOTS[bit];
            slot.cr3.store(cr3, Ordering::Relaxed);
            slot.va_lo.store(va_lo, Ordering::Relaxed);
            slot.va_hi.store(va_hi, Ordering::Relaxed);
            // pending=1 must be the LAST write so the handler sees a
            // fully-published payload.  Release pairs with Acquire in
            // the handler.
            slot.pending.store(1, Ordering::Release);
        }

        // Now signal every target.  Doing this AFTER the payload writes
        // guarantees that when the handler observes pending=1 it can
        // also see the corresponding cr3/va_lo/va_hi.
        let mut t = targets;
        while t != 0 {
            let bit = t.trailing_zeros() as usize;
            t &= t - 1;
            if bit >= apic::MAX_CPUS {
                continue;
            }
            apic::send_ipi(bit as u8, TLB_SHOOTDOWN_VECTOR);
            STAT_IPIS_SENT.fetch_add(1, Ordering::Relaxed);
        }

        // Spin on ack from each target.  Bounded so a wedged CPU does
        // not deadlock the whole kernel — about 1 ms at 1 GHz, which is
        // ~10000× the expected shootdown latency.
        const ACK_BOUND: u32 = 1_000_000;
        let mut remaining = targets;
        let mut iters: u32 = 0;
        while remaining != 0 && iters < ACK_BOUND {
            let mut still = 0u64;
            let mut r = remaining;
            while r != 0 {
                let bit = r.trailing_zeros() as usize;
                r &= r - 1;
                if bit >= apic::MAX_CPUS {
                    continue;
                }
                if SHOOTDOWN_SLOTS[bit].pending.load(Ordering::Acquire) != 0 {
                    still |= 1u64 << (bit as u64);
                }
            }
            remaining = still;
            if remaining == 0 {
                break;
            }
            core::hint::spin_loop();
            iters += 1;
        }

        if remaining != 0 {
            // One or more targets did not ack in time.  Drop the
            // unacknowledged slots (clear pending so they don't trip
            // a later shootdown), log, and continue — the alternative
            // is wedging the entire system on a single uncooperative
            // CPU, which is strictly worse.
            STAT_ACK_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            let mut r = remaining;
            while r != 0 {
                let bit = r.trailing_zeros() as usize;
                r &= r - 1;
                if bit >= apic::MAX_CPUS {
                    continue;
                }
                SHOOTDOWN_SLOTS[bit].pending.store(0, Ordering::Release);
            }
            crate::serial_println!(
                "[TLB] WARN shootdown timeout cr3={:#x} va=[{:#x}..{:#x}) targets_unacked={:#x}",
                cr3, va_lo, va_hi, remaining,
            );
        }
    }
}

/// Single-page convenience wrapper around [`shootdown_range`].
#[inline]
pub fn shootdown_page(cr3: u64, va: u64) {
    let lo = va & !0xFFFu64;
    shootdown_range(cr3, lo, lo + 0x1000);
}

/// Convenience wrapper for the "all of the user half" shootdown that
/// process-teardown sites need.  Covers the canonical lower-half VA
/// range `[0, 0x0000_8000_0000_0000)`.  Page-count above the
/// `FULL_FLUSH_PAGES_THRESHOLD` so it always takes the CR3-reload
/// (full TLB flush) fast path on every receiving CPU.
#[inline]
pub fn shootdown_full_user(cr3: u64) {
    shootdown_range(cr3, 0, 0x0000_8000_0000_0000);
}

/// IPI handler.  Invoked from [`crate::arch::x86_64::idt`] when the LAPIC
/// delivers a [`TLB_SHOOTDOWN_VECTOR`] interrupt to this CPU.
///
/// Reads the per-CPU shootdown slot, performs the invalidation if the
/// target CR3 matches the running one, and clears `pending`.  Always
/// EOIs the LAPIC at the end.
pub extern "C" fn handle_shootdown_ipi() {
    let cpu = apic::cpu_index();
    if cpu < apic::MAX_CPUS {
        let slot = &SHOOTDOWN_SLOTS[cpu];
        // Atomically claim the slot.  The single-writer rule on
        // `pending` (one sender publishes 1, one handler invocation
        // clears to 0) is enforced architecturally by the per-CPU
        // shootdown protocol: only one IPI per target is in flight at
        // a time because the sender spins on this slot's ack before
        // re-using it.  We use a compare-exchange anyway so a spurious
        // IPI delivery (vector 0xF0 arriving at a CPU whose slot is
        // already drained, e.g. after a previously-timed-out sender
        // cleared it) is observably handled exactly once.  AcqRel on
        // success pairs with the sender's Release-store of `pending=1`
        // and the matching Release-store of the ack-clear below, so we
        // see the published cr3/va_lo/va_hi before the invalidation.
        if slot
            .pending
            .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let target_cr3 = slot.cr3.load(Ordering::Relaxed);
            let va_lo = slot.va_lo.load(Ordering::Relaxed);
            let va_hi = slot.va_hi.load(Ordering::Relaxed);

            let cur_cr3 = crate::mm::vmm::get_cr3();
            if cur_cr3 == target_cr3 {
                local_invlpg_range(va_lo, va_hi);
            }
            // Even if the CR3 has since changed, ack — the bit in the
            // active-CPU mask is gone (the scheduler cleared it after
            // the new mov cr3) so the sender will not target this CPU
            // again with the same payload.  The ack-clear is implicit
            // in the compare_exchange above; no second store needed.

            STAT_SHOOTDOWNS_HANDLED.fetch_add(1, Ordering::Relaxed);
        }
    }

    apic::lapic_eoi();
}

/// Diagnostic snapshot for kdb / introspection.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    pub shootdowns_sent: u64,
    pub ipis_sent: u64,
    pub ack_timeouts: u64,
    pub shootdowns_handled: u64,
}

/// Return a snapshot of the running shootdown statistics.
pub fn stats() -> Stats {
    Stats {
        shootdowns_sent: STAT_SHOOTDOWNS_SENT.load(Ordering::Relaxed),
        ipis_sent: STAT_IPIS_SENT.load(Ordering::Relaxed),
        ack_timeouts: STAT_ACK_TIMEOUTS.load(Ordering::Relaxed),
        shootdowns_handled: STAT_SHOOTDOWNS_HANDLED.load(Ordering::Relaxed),
    }
}
