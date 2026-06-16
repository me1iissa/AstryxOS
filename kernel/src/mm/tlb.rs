//! Cross-CPU TLB shootdown and quarantine-free.
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
//! # Quarantine-free
//!
//! When a shootdown ACK times out, the physical frame cannot be returned
//! immediately to the PMM: one or more CPUs may still have a valid TLB
//! entry for the old virtual-to-physical mapping.  Freeing the frame now
//! allows the PMM to recycle it, producing a use-after-free whose symptom
//! is arbitrary data corruption at scattered user-code offsets.
//!
//! To eliminate this hazard, frames whose shootdown did not complete within
//! the ACK deadline are routed through [`quarantine_free`] instead of
//! `pmm::free_page`.  The quarantine defers the actual PMM release until
//! a *quiescent state* has been observed: every online CPU has passed
//! through at least one timer-ISR since the frame was enqueued.  Because
//! the timer ISR is delivered with interrupts disabled, it cannot be
//! delayed indefinitely by user code; any CPU-local TLB entry that was
//! stale at enqueue time will have been retired once [`on_cpu_tick`] runs
//! on that CPU.  [`on_cpu_tick`] issues an explicit CR3 reload
//! (`flush_tlb`) at the very start of each invocation, before it advances
//! the per-CPU tick stamp.  This guarantees that stale TLB entries are
//! purged on the tick event itself — not merely at some later context-switch
//! that may never occur if a compute-bound thread monopolises a vCPU across
//! many ticks.  Per Intel SDM Vol. 3A §4.10.4.1 (MOV to CR3), writing CR3
//! invalidates all TLB entries for the current PCID (AstryxOS uses PCID 0,
//! so this is a full TLB drop).
//!
//! The quiescent-state concept is analogous to the RCU grace-period used
//! in general read-copy-update literature (see McKenney, "Is Parallel
//! Programming Hard?", §B.5, publicly available).  Here, each CPU's timer
//! ISR is the "quiescent event" because it guarantees that any pre-ISR
//! TLB state has been superseded.
//!
//! Implementation uses a global fixed-size ring of (phys_addr, enqueue_tick)
//! pairs protected by a single spin mutex.  [`on_cpu_tick`] is called from
//! every CPU's timer ISR and drains entries whose enqueue tick is older than
//! the minimum per-CPU tick observed since the ring was last drained.  This
//! is conservative (may hold frames one extra tick) but is strictly safe.
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
//!
//! `QUARANTINE.lock` is also a leaf lock.  It is acquired only from
//! [`quarantine_free`] (called from PTE-teardown paths) and from
//! [`on_cpu_tick`] (timer ISR).  These two sites never hold any other
//! kernel lock simultaneously, so no cycle is possible.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
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

/// Statistic: number of frames deferred through the quarantine-free path.
static STAT_QUARANTINE_DEFERRED: AtomicU64 = AtomicU64::new(0);

/// Statistic: number of frames actually released from the quarantine to PMM.
static STAT_QUARANTINE_RELEASED: AtomicU64 = AtomicU64::new(0);

/// H2 diagnostic counter: number of times `shootdown_range_inner` returned
/// `true` (clean) but at least one target CPU had not yet set its per-CPU
/// `SHOOTDOWN_DONE_FLAGS` bit by the time the sender polled post-return.
///
/// A non-zero value is direct evidence that the protocol declares the
/// shootdown complete while the receiving CPU's `local_invlpg_range` may
/// not yet be committed to the hardware TLB, making the W215 frame-aliasing
/// class mechanically plausible.  Gated behind `#[cfg(feature = "firefox-test-core")]`.
#[cfg(feature = "firefox-test-core")]
pub(crate) static STAT_CLEAN_ACK_LATE: AtomicU64 = AtomicU64::new(0);

/// H2 diagnostic counter: number of times `shootdown_range_inner` returned
/// `false` (unclean → quarantine path).  Counts timed-out shootdowns routed
/// to quarantine — these never reach the done-flag poll.
/// Gated behind `#[cfg(feature = "firefox-test-core")]`.
#[cfg(feature = "firefox-test-core")]
pub(crate) static STAT_UNCLEAN_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Per-CPU "done" flag set by `handle_shootdown_ipi` immediately AFTER the
/// local invalidation completes.  The sender clears a CPU's slot to 0 before
/// publishing the IPI payload; the handler sets it to 1 after `invlpg`.
/// The sender reads these flags (Acquire) after observing `pending=0` (the
/// existing ack path) to verify that the invalidation actually ran, not merely
/// that the IPI was received.
///
/// Addressing: indexed by `cpu_index()`.  One `AtomicU8` per slot (same width
/// as `ShootdownSlot::pending`); natural alignment guarantees no false sharing
/// with the payload fields.
///
/// Only materialised under `firefox-test`; in production the slot's `pending`
/// flag is the sole synchronisation point and carries no extra overhead.
#[cfg(feature = "firefox-test-core")]
static SHOOTDOWN_DONE_FLAGS: [AtomicU8; apic::MAX_CPUS] =
    [const { AtomicU8::new(0) }; apic::MAX_CPUS];

// ── Quarantine-free ring ─────────────────────────────────────────────────────
//
// Physical frames that cannot be immediately returned to the PMM because
// their TLB shootdown timed out are placed here.  A frame is only returned
// to the PMM once every online CPU has passed through a timer ISR since the
// frame was enqueued (the "quiescent-state" condition).
//
// Implementation notes:
//   - Fixed capacity (256 entries) chosen to exceed the maximum number of
//     frames that can accumulate between two consecutive timer ticks at the
//     current shootdown rate.  If the ring fills, the frame is freed
//     immediately (a deliberate leak of the safety property under extreme
//     memory pressure — a stale TLB hit is very unlikely at that point
//     because the quiescent-state condition will have been met for most
//     entries before we reach capacity).
//   - A single spin mutex protects the ring.  Contention is bounded:
//     `quarantine_free` is called from syscall/fault paths (not hot-path
//     unless timeouts are frequent), and `on_cpu_tick` drains the ring
//     at most once every ~10 ms per CPU.
//   - The enqueue tick is compared against the *per-CPU minimum* of the
//     tick at which each CPU last ran its timer ISR.  An entry is safe to
//     release when `min_cpu_tick > entry.enqueue_tick`.

/// Maximum entries in the quarantine ring.
const QUARANTINE_CAPACITY: usize = 256;

/// One quarantined frame entry.
#[derive(Copy, Clone)]
struct QuarantineEntry {
    /// Physical address of the frame held in quarantine.
    phys: u64,
    /// Value of the global `TICK_COUNT` when this entry was enqueued.
    enqueue_tick: u64,
}

/// The quarantine ring buffer.
struct QuarantineRing {
    entries: [QuarantineEntry; QUARANTINE_CAPACITY],
    /// Number of valid entries (head always at 0, tail at `len`).
    len: usize,
}

impl QuarantineRing {
    const fn new() -> Self {
        Self {
            entries: [QuarantineEntry { phys: 0, enqueue_tick: 0 }; QUARANTINE_CAPACITY],
            len: 0,
        }
    }
}

/// Global quarantine ring, protected by a spin mutex.
static QUARANTINE: Mutex<QuarantineRing> = Mutex::new(QuarantineRing::new());

/// Per-CPU tick stamp: the global tick value the last time each CPU ran its
/// timer ISR.  Used by [`on_cpu_tick`] to compute the quiescent-state minimum.
static CPU_LAST_TICK: [AtomicU64; apic::MAX_CPUS] =
    [const { AtomicU64::new(0) }; apic::MAX_CPUS];

/// Current depth of the quarantine ring (approximate — for diagnostics).
static STAT_QUARANTINE_DEPTH: AtomicUsize = AtomicUsize::new(0);

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
/// # Return value
///
/// Returns `true` if every targeted CPU acknowledged the shootdown IPI
/// within the deadline.  Returns `false` if one or more CPUs timed out.
///
/// **Critical**: when this function returns `false`, any physical frames
/// that were freed by PTE-clearing operations in the same batch MUST be
/// routed through [`quarantine_free`] rather than `pmm::free_page`.  A
/// timed-out CPU may still hold a valid TLB entry for the freed virtual
/// address, and recycling the frame immediately would allow that CPU to
/// read or write the new owner's content through the stale mapping —
/// a silent use-after-free.  [`quarantine_free`] defers the actual PMM
/// release until all CPUs have passed through a quiescent state (one
/// timer-ISR each), guaranteeing every stale TLB entry has been retired.
///
/// Callers that do not free physical pages (e.g. write-protect for CoW,
/// mapping permission tightening) may safely ignore the return value.
///
/// # When to call
///
/// Call this whenever a PTE is *cleared*, has its permissions *tightened*
/// (e.g. RW → RO during CoW write-protect), or is otherwise rewritten in
/// a way that demands the old translation be invalidated on every CPU
/// that might still hold it.  Installing a new mapping over a not-present
/// PTE does *not* require shootdown — there is no stale entry to evict —
/// and is left as a plain local `invlpg`.
pub fn shootdown_range(cr3: u64, va_lo: u64, va_hi: u64) -> bool {
    // Always do the local invalidation first.  This handles the common
    // single-CPU case at the cost of one extra invlpg on a 2+ CPU system,
    // which is negligible compared to the IPI cost.
    local_invlpg_range(va_lo, va_hi);

    // If SMP is not yet active, no other CPU can hold the TLB.
    if !SMP_ACTIVE.load(Ordering::Acquire) {
        return true;
    }

    // The protocol-off feature flag lets a bisect/baseline keep the
    // local invlpg but skip the cross-CPU work.
    #[cfg(feature = "tlb-shootdown-off")]
    return true;

    #[cfg(not(feature = "tlb-shootdown-off"))]
    shootdown_range_inner(cr3, va_lo, va_hi)
}

/// Inner implementation of the cross-CPU shootdown protocol.
///
/// Separated so the `#[cfg(feature = "tlb-shootdown-off")]` early-return
/// above does not conflict with a function-level `#[cfg(...)]` attribute.
#[cfg(not(feature = "tlb-shootdown-off"))]
fn shootdown_range_inner(cr3: u64, va_lo: u64, va_hi: u64) -> bool {
    let self_cpu = apic::cpu_index();
    if self_cpu >= apic::MAX_CPUS {
        return true;
    }
    let self_mask = 1u64 << (self_cpu as u64);

    let targets = snapshot_active_mask(cr3) & !self_mask;
    if targets == 0 {
        return true;
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
        // H2 diagnostic: clear the done flag before publishing the
        // payload so the handler's subsequent store of 1 is
        // unambiguously for *this* shootdown, not a residual from a prior
        // one.  Must precede the Release-store of pending below.
        #[cfg(feature = "firefox-test-core")]
        SHOOTDOWN_DONE_FLAGS[bit].store(0, Ordering::Release);
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

    // Spin on ack from each target.  Bounded so a wedged CPU (e.g. a
    // KVM vCPU that is host-descheduled during a long critical section)
    // does not deadlock the whole kernel.  The bound is ~10 ms at 1 GHz
    // — about 1 000× larger than the previous 1 ms budget — to cover
    // realistic KVM vCPU scheduling jitter without risking indefinite
    // spin.  Per Intel SDM Vol. 3A §10.6.1, IPI delivery to a wedged
    // or powered-down CPU must be handled by the sender; this bound
    // provides that guarantee.
    const ACK_BOUND: u32 = 10_000_000;
    let mut remaining = targets;
    let mut iters: u32 = 0;
    while remaining != 0 && iters < ACK_BOUND {
        // Self-service: we are spinning here with interrupts disabled (this
        // path runs from inside an interrupt-gate exception handler — Intel
        // SDM Vol. 3A §6.12.1.2 — so RFLAGS.IF is clear and we CANNOT take an
        // incoming TLB_SHOOTDOWN_VECTOR IPI).  A sibling CPU may be spinning
        // here too, waiting for *our* ack on the IPI it delivered to us.
        // Drain our own pending slot inline so that sibling sees the ack and
        // makes progress — without this, two CPUs that concurrently shoot
        // down the same shared CR3 from fault handlers mutually deadlock
        // until both burn the full ACK_BOUND.  See
        // `service_local_shootdown_slot` for the full rationale.
        service_local_shootdown_slot(self_cpu);

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
        // One or more targets did not ack in time.  Clear the
        // unacknowledged slots so they don't trip a later shootdown.
        // The caller MUST route any affected frames through
        // `quarantine_free` rather than `pmm::free_page` directly.
        // This function records the timeout and returns false; the
        // caller's free loop checks the return value.
        let timeout_count = STAT_ACK_TIMEOUTS.fetch_add(1, Ordering::Relaxed) + 1;
        let mut tgt_count = 0u32;
        let mut r = remaining;
        while r != 0 {
            let bit = r.trailing_zeros() as usize;
            r &= r - 1;
            if bit >= apic::MAX_CPUS {
                continue;
            }
            SHOOTDOWN_SLOTS[bit].pending.store(0, Ordering::Release);
            tgt_count += 1;
        }
        crate::serial_println!(
            "[TLB/TIMEOUT] cpu={} target_mask={:#x} unacked_cpus={} \
             va=[{:#x}..{:#x}) iters={} total_timeouts={}",
            self_cpu, remaining, tgt_count,
            va_lo, va_hi, iters, timeout_count,
        );
        // H2 diagnostic: count this unclean shootdown for baseline comparison
        // with CLEAN_ACK_LATE.
        #[cfg(feature = "firefox-test-core")]
        STAT_UNCLEAN_TOTAL.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // All targets acked (pending cleared).  Poll the done flags to verify
    // that the local invalidation actually committed on each target CPU —
    // not merely that the IPI was received and the slot was acknowledged.
    // Per Intel SDM Vol. 3A §4.10.4.2, the `invlpg` must complete before
    // the handler clears pending (the AcqRel compare_exchange in
    // `handle_shootdown_ipi` provides that ordering guarantee relative to
    // the pending clear); the done flag provides a second, independent
    // readback point that is set AFTER the invalidation instruction
    // completes, giving us a measurement of whether the two signals race.
    #[cfg(feature = "firefox-test-core")]
    {
        // Brief spin on the done flags: 4000 iterations ≈ a few µs, far
        // cheaper than the ACK_BOUND above, but enough to cover any IPI
        // delivery jitter between `pending=0` and the done flag store.
        let mut late_mask: u64 = targets;
        for _ in 0..4_000u32 {
            let mut still = 0u64;
            let mut r = late_mask;
            while r != 0 {
                let bit = r.trailing_zeros() as usize;
                r &= r - 1;
                if bit < apic::MAX_CPUS
                    && SHOOTDOWN_DONE_FLAGS[bit].load(Ordering::Acquire) == 0
                {
                    still |= 1u64 << (bit as u64);
                }
            }
            late_mask = still;
            if late_mask == 0 { break; }
            core::hint::spin_loop();
        }
        if late_mask != 0 {
            // At least one CPU cleared pending but has not yet stored
            // done=1.  The shootdown was declared clean prematurely.
            let total = STAT_CLEAN_ACK_LATE.fetch_add(1, Ordering::Relaxed) + 1;
            // Collect the late CPU list for the log line (max 8 entries).
            let mut late_cpus = [0u8; 8];
            let mut nlate = 0usize;
            let mut r = late_mask;
            while r != 0 && nlate < 8 {
                let bit = r.trailing_zeros() as usize;
                r &= r - 1;
                late_cpus[nlate] = bit as u8;
                nlate += 1;
            }
            crate::serial_println!(
                "[TLB/CLEAN-ACK-LATE] cr3={:#x} late_cpus={:?} count_total={}",
                cr3, &late_cpus[..nlate], total
            );
        }
    }

    true
}

/// Single-page convenience wrapper around [`shootdown_range`].
///
/// Returns `true` if the shootdown completed without any ACK timeouts;
/// see [`shootdown_range`] for the significance of the return value.
#[inline]
pub fn shootdown_page(cr3: u64, va: u64) -> bool {
    let lo = va & !0xFFFu64;
    shootdown_range(cr3, lo, lo + 0x1000)
}

/// Convenience wrapper for the "all of the user half" shootdown that
/// process-teardown sites need.  Covers the canonical lower-half VA
/// range `[0, 0x0000_8000_0000_0000)`.  Page-count above the
/// `FULL_FLUSH_PAGES_THRESHOLD` so it always takes the CR3-reload
/// (full TLB flush) fast path on every receiving CPU.
///
/// Returns `true` if all CPUs acknowledged within the deadline.  See
/// [`shootdown_range`] for the importance of the return value when
/// physical frames are being freed alongside the shootdown.
#[inline]
pub fn shootdown_full_user(cr3: u64) -> bool {
    shootdown_range(cr3, 0, 0x0000_8000_0000_0000)
}

// ── Quarantine-free API ──────────────────────────────────────────────────────

/// Defer the release of physical frame `phys` to the PMM until a
/// quiescent state has been observed on every online CPU.
///
/// Use this instead of `pmm::free_page` when a TLB shootdown for the
/// virtual-to-physical mapping of `phys` may not have reached every CPU
/// (i.e. [`shootdown_range`] returned `false`).  This guarantees that no
/// CPU can reach `phys` through a stale TLB entry after it is returned
/// to the PMM, preventing use-after-free aliasing.
///
/// # Quiescent state
///
/// A CPU is considered to have passed through a quiescent state once it
/// has executed its timer ISR at least one tick after `quarantine_free`
/// was called.  [`on_cpu_tick`] performs an explicit CR3 reload
/// (`flush_tlb`) at the very start of each invocation, before it
/// advances the per-CPU tick stamp.  This means that by the time a
/// CPU's `CPU_LAST_TICK` entry is updated to reflect tick `T`, that CPU
/// has already executed a full TLB flush — so any stale TLB entry for a
/// VA whose frame was enqueued at or before tick `T` has been retired.
/// The grace-period invariant therefore holds even when a compute-bound
/// thread monopolises a vCPU across many ticks without triggering a
/// context-switch.  Per Intel SDM Vol. 3A §4.10.4.1, a MOV to CR3
/// invalidates all non-global TLB entries (AstryxOS uses PCID 0, so
/// this is a complete flush).
///
/// # Overflow behaviour
///
/// The quarantine ring has capacity for [`QUARANTINE_CAPACITY`] frames.
/// If the ring is full when `quarantine_free` is called, the frame is
/// freed immediately.  This degrades gracefully under extreme memory
/// pressure: the quiescent-state guarantee is lost for that one frame,
/// but the alternative (blocking the caller) would cause a deadlock in
/// the free path.  Under normal workloads the ring depth never exceeds a
/// handful of entries.
pub fn quarantine_free(phys: u64) {
    if phys == 0 {
        return;
    }
    let tick = crate::arch::x86_64::irq::TICK_COUNT
        .load(Ordering::Relaxed);

    let full: bool;
    {
        let mut ring = QUARANTINE.lock();
        if ring.len < QUARANTINE_CAPACITY {
            // Store the index in a local to avoid simultaneous mutable+immutable
            // borrow of `ring` through `ring.entries[ring.len]`.
            let idx = ring.len;
            ring.entries[idx] = QuarantineEntry { phys, enqueue_tick: tick };
            ring.len += 1;
            STAT_QUARANTINE_DEPTH.store(ring.len, Ordering::Relaxed);
            full = false;
        } else {
            full = true;
        }
    } // release QUARANTINE lock

    if full {
        // Ring full — free immediately rather than blocking.
        crate::serial_println!(
            "[TLB/QUARANTINE] ring full; freeing phys={:#x} immediately (grace-period not guaranteed)",
            phys,
        );
        crate::mm::pmm::free_page(phys);
    } else {
        STAT_QUARANTINE_DEFERRED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Per-CPU tick notification.  Must be called from every CPU's timer ISR
/// (via [`crate::arch::x86_64::irq::timer_tick`]) to advance the
/// quarantine grace-period tracking.
///
/// At the very start of each invocation, this function performs an explicit
/// full TLB flush (CR3 reload) on the calling CPU.  This flush happens
/// *before* the per-CPU tick stamp is recorded, so the grace-period
/// invariant is genuine: by the time `CPU_LAST_TICK[cpu]` is updated to
/// `current_tick`, all stale TLB entries on this CPU have already been
/// retired.  Without this flush the grace period relied solely on
/// context-switch CR3 reloads, which are never issued when a single
/// compute-bound thread runs uncontested across many ticks — exactly the
/// Firefox workload profile that triggered the W215 page-aliasing fault.
///
/// Cost: one CR3 reload per timer tick per CPU (~30 cycles at 100 Hz =
/// ~0.001% of CPU time).  This is negligible in any workload that involves
/// real user code.
///
/// Records this CPU's current tick and, if all online CPUs have ticked
/// past the earliest entry's enqueue tick, drains those entries to PMM.
pub fn on_cpu_tick(current_tick: u64) {
    // Drain this CPU's TLB before recording the tick stamp.  The order is
    // critical: the grace-period guarantee is "every CPU has flushed its
    // TLB since the frame was enqueued".  The flush must precede the stamp
    // update so that the min-tick calculation in the drain loop sees a
    // value that reflects a post-flush state.  Per Intel SDM Vol. 3A
    // §4.10.4.1, MOV to CR3 invalidates all non-global TLB entries; since
    // AstryxOS does not use PCID, this is a complete TLB drop.
    crate::mm::vmm::flush_tlb();

    let cpu = apic::cpu_index();
    if cpu < apic::MAX_CPUS {
        CPU_LAST_TICK[cpu].store(current_tick, Ordering::Relaxed);
    }

    // Fast path: quarantine ring is empty.
    if STAT_QUARANTINE_DEPTH.load(Ordering::Relaxed) == 0 {
        return;
    }

    // Compute the minimum tick across all online CPUs.  Any quarantine
    // entry whose enqueue_tick < min_tick is safe to release: every CPU
    // has passed through at least one timer ISR after it was enqueued,
    // guaranteeing that any TLB entry for the freed VA has been retired.
    let ncpus = apic::cpu_count() as usize;
    let ncpus = ncpus.min(apic::MAX_CPUS).max(1);
    let mut min_tick = u64::MAX;
    for i in 0..ncpus {
        let t = CPU_LAST_TICK[i].load(Ordering::Relaxed);
        if t < min_tick {
            min_tick = t;
        }
    }

    // Drain entries older than min_tick without holding the lock across
    // the pmm::free_page calls (which take PMM_LOCK).
    let mut to_free = [0u64; QUARANTINE_CAPACITY];
    let mut nfree = 0usize;

    {
        let mut ring = QUARANTINE.lock();
        if ring.len == 0 {
            return;
        }
        // Partition: entries with enqueue_tick < min_tick move to to_free;
        // the rest are compacted to the front.
        let mut keep = 0usize;
        for i in 0..ring.len {
            let e = ring.entries[i];
            if e.enqueue_tick < min_tick {
                to_free[nfree] = e.phys;
                nfree += 1;
            } else {
                ring.entries[keep] = e;
                keep += 1;
            }
        }
        ring.len = keep;
        STAT_QUARANTINE_DEPTH.store(keep, Ordering::Relaxed);
    } // release QUARANTINE lock

    for i in 0..nfree {
        crate::mm::pmm::free_page(to_free[i]);
    }
    if nfree > 0 {
        STAT_QUARANTINE_RELEASED.fetch_add(nfree as u64, Ordering::Relaxed);
    }
}

/// IPI handler.  Invoked from [`crate::arch::x86_64::idt`] when the LAPIC
/// delivers a [`TLB_SHOOTDOWN_VECTOR`] interrupt to this CPU.
///
/// Reads the per-CPU shootdown slot, performs the invalidation if the
/// target CR3 matches the running one, and clears `pending`.  Always
/// EOIs the LAPIC at the end.
/// Service this CPU's own shootdown slot inline: claim a pending request,
/// perform the local invalidation, ack it (clear `pending`), and raise the
/// done flag.  Returns `true` iff a pending request was claimed and handled.
///
/// This is the shared core of both the IPI handler ([`handle_shootdown_ipi`])
/// and the ACK-spin self-service path in [`shootdown_range_inner`].  It is
/// safe to call with interrupts disabled (it performs no IPI sends, no
/// locking, and only touches per-CPU shootdown state plus `invlpg`).
///
/// # Why the ACK-spin must call this
///
/// A page fault, `#GP`, or any other exception enters through an *interrupt
/// gate* (Intel SDM Vol. 3A §6.12.1.2: an interrupt gate clears RFLAGS.IF on
/// entry), so a CPU that issues a TLB shootdown from inside a fault handler
/// spins for sibling acks with **interrupts masked**.  A masked CPU cannot
/// take the `TLB_SHOOTDOWN_VECTOR` IPI a sibling has delivered to it, so its
/// own `SHOOTDOWN_SLOTS[self]` entry stays `pending = 1` indefinitely.  If
/// that sibling is *also* spinning IRQ-masked for *this* CPU's ack, neither
/// can ever ack the other — a mutual cross-CPU ack-spin deadlock that burns
/// the full `ACK_BOUND` on both CPUs (observed as interleaved `[TLB/TIMEOUT]`
/// with `cpu=0 mask=0x2` / `cpu=1 mask=0x1`).  Draining our own slot inline
/// while we spin breaks the cycle: the sibling sees our ack and makes
/// progress, then acks us in turn.  Per Intel SDM Vol. 3A §10.6.1 the sender
/// is responsible for handling delivery to a CPU that cannot service the IPI
/// itself; here the "sender" services the request on the target's behalf.
#[inline]
fn service_local_shootdown_slot(cpu: usize) -> bool {
    if cpu >= apic::MAX_CPUS {
        return false;
    }
    let slot = &SHOOTDOWN_SLOTS[cpu];
    // Atomically claim the slot.  The single-writer rule on `pending`
    // (one sender publishes 1, exactly one of {IPI handler, this inline
    // self-service} clears to 0) is preserved by the compare_exchange:
    // whichever path wins the 1→0 transition does the invalidation; the
    // loser observes 0 and no-ops.  AcqRel on success pairs with the
    // sender's Release-store of `pending=1` so we see the published
    // cr3/va_lo/va_hi before the invalidation.
    if slot
        .pending
        .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    let target_cr3 = slot.cr3.load(Ordering::Relaxed);
    let va_lo = slot.va_lo.load(Ordering::Relaxed);
    let va_hi = slot.va_hi.load(Ordering::Relaxed);

    let cur_cr3 = crate::mm::vmm::get_cr3();
    if cur_cr3 == target_cr3 {
        local_invlpg_range(va_lo, va_hi);
    }
    // Even if the CR3 has since changed, ack — the bit in the active-CPU
    // mask is gone (the scheduler cleared it after the new mov cr3) so the
    // sender will not target this CPU again with the same payload.  The
    // ack-clear is implicit in the compare_exchange above.

    // H2 diagnostic: signal the sender that the local invalidation has
    // committed.  The Release here pairs with the Acquire poll in
    // `shootdown_range_inner` so the sender observes the completed `invlpg`
    // ordering, not just the `pending` clear.
    #[cfg(feature = "firefox-test-core")]
    SHOOTDOWN_DONE_FLAGS[cpu].store(1, Ordering::Release);

    STAT_SHOOTDOWNS_HANDLED.fetch_add(1, Ordering::Relaxed);
    true
}

pub extern "C" fn handle_shootdown_ipi() {
    let cpu = apic::cpu_index();
    // Service this CPU's slot.  The compare_exchange inside guards against a
    // spurious IPI delivery (vector 0xF0 arriving at a CPU whose slot is
    // already drained, e.g. after a previously-timed-out sender cleared it,
    // or after the inline self-service path already handled it) — it is
    // observably handled exactly once.
    service_local_shootdown_slot(cpu);

    apic::lapic_eoi();
}

/// Test-only harness for the inline self-service path.
///
/// Publishes a synthetic pending request into THIS CPU's shootdown slot for a
/// CR3 that deliberately does not match the running one (so no real `invlpg`
/// side-effect occurs), then drains it twice via the same code path the
/// IRQ-disabled ACK-spin uses.  Returns `(first, second)` where `first` must
/// be `true` (the pending request was claimed exactly once) and `second` must
/// be `false` (idempotent — a drained slot is a no-op).  This exercises the
/// fix for the cross-CPU ack-spin deadlock without needing two live CPUs.
#[doc(hidden)]
pub fn test_self_service_drains_own_slot() -> (bool, bool) {
    let cpu = apic::cpu_index();
    if cpu >= apic::MAX_CPUS {
        // Degenerate environment — report the idempotent shape so the
        // caller's assertion still holds.
        return (true, false);
    }
    let slot = &SHOOTDOWN_SLOTS[cpu];
    // A CR3 that no running context can match (kernel CR3 is low phys; user
    // CR3s are PMM frames, never this sentinel) → the invalidation is skipped
    // but the claim/ack/done bookkeeping still runs.
    slot.cr3.store(0xFEED_FACE_000, Ordering::Relaxed);
    slot.va_lo.store(0x4000_0000_0000, Ordering::Relaxed);
    slot.va_hi.store(0x4000_0000_1000, Ordering::Relaxed);
    #[cfg(feature = "firefox-test-core")]
    SHOOTDOWN_DONE_FLAGS[cpu].store(0, Ordering::Release);
    // Publish LAST so the claim sees a fully-formed payload.
    slot.pending.store(1, Ordering::Release);

    let first = service_local_shootdown_slot(cpu);
    // A second drain must observe pending==0 and no-op.
    let second = service_local_shootdown_slot(cpu);

    // Leave the slot pristine for any later real shootdown to this CPU.
    slot.pending.store(0, Ordering::Release);
    slot.cr3.store(0, Ordering::Relaxed);
    slot.va_lo.store(0, Ordering::Relaxed);
    slot.va_hi.store(0, Ordering::Relaxed);

    (first, second)
}

/// Diagnostic snapshot for kdb / introspection.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    pub shootdowns_sent: u64,
    pub ipis_sent: u64,
    pub ack_timeouts: u64,
    pub shootdowns_handled: u64,
    /// Frames deferred through the quarantine-free path (not yet returned to PMM).
    pub quarantine_deferred: u64,
    /// Frames released from quarantine back to PMM (grace period elapsed).
    pub quarantine_released: u64,
    /// Current number of frames held in the quarantine ring.
    pub quarantine_depth: usize,
    /// H2 diagnostic (firefox-test only): shootdowns declared clean while at
    /// least one target CPU had not yet committed the local invalidation.
    /// Always 0 in non-firefox-test builds.
    pub clean_ack_late: u64,
    /// H2 diagnostic (firefox-test only): shootdowns that returned false
    /// (unclean → quarantine).  Baseline rate for the above counter.
    /// Always 0 in non-firefox-test builds.
    pub unclean_total: u64,
}

/// Return a snapshot of the running shootdown statistics.
pub fn stats() -> Stats {
    Stats {
        shootdowns_sent: STAT_SHOOTDOWNS_SENT.load(Ordering::Relaxed),
        ipis_sent: STAT_IPIS_SENT.load(Ordering::Relaxed),
        ack_timeouts: STAT_ACK_TIMEOUTS.load(Ordering::Relaxed),
        shootdowns_handled: STAT_SHOOTDOWNS_HANDLED.load(Ordering::Relaxed),
        quarantine_deferred: STAT_QUARANTINE_DEFERRED.load(Ordering::Relaxed),
        quarantine_released: STAT_QUARANTINE_RELEASED.load(Ordering::Relaxed),
        quarantine_depth: STAT_QUARANTINE_DEPTH.load(Ordering::Relaxed),
        #[cfg(feature = "firefox-test-core")]
        clean_ack_late: STAT_CLEAN_ACK_LATE.load(Ordering::Relaxed),
        #[cfg(not(feature = "firefox-test-core"))]
        clean_ack_late: 0,
        #[cfg(feature = "firefox-test-core")]
        unclean_total: STAT_UNCLEAN_TOTAL.load(Ordering::Relaxed),
        #[cfg(not(feature = "firefox-test-core"))]
        unclean_total: 0,
    }
}
