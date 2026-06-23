//! Per-CPU / per-priority runqueue scaffold (Perf P2, phase 1).
//!
//! # What this is
//!
//! This module introduces the *data structure* for a per-CPU, per-priority
//! runqueue without yet changing any scheduling decision.  The authoritative
//! picker still lives in [`super::schedule`] and still selects the next thread
//! by scanning `THREAD_TABLE`.  This scaffold runs *alongside* it as a passive
//! mirror so that the structure, its O(1) pick, its priority bitmap and its
//! `nr_running` accounting are populated and continuously self-verified against
//! the authoritative ready-set on every scheduling pass — but the mirror is
//! never consulted to make a decision.
//!
//! The phased rework (per-CPU pick → per-CPU enqueue + wakeup target + a
//! reschedule IPI → load balancing → SMP=2 default) builds on this structure.
//! Keeping phase 1 strictly behaviour-preserving means SMP=1 stays bit-for-bit
//! identical and the anti-starvation aging/force-deadline fairness already in
//! `schedule()` is untouched.
//!
//! # Design
//!
//! Each logical CPU owns a [`PerCpuRq`] guarded by its own leaf lock (below
//! `THREAD_TABLE` in the lock order — see [`RQS`]).  Inside the runqueue the
//! runnable threads are bucketed by base priority into one FIFO per priority
//! level (`lists[prio]`), a `bitmap` records which priority levels are
//! non-empty so the highest runnable priority is found in O(1) via a single
//! count-trailing/leading-zeros, and `nr_running` is the cached count of queued
//! threads.  The queues store thread IDs; the `Thread` records themselves stay
//! in `THREAD_TABLE`, which remains the system's thread *record* store (it is
//! simply no longer the *run queue* once the later phases switch the picker
//! over).
//!
//! # Priority model
//!
//! AstryxOS uses a small discrete priority range (`proc::PRIORITY_IDLE = 0` ..=
//! `proc::PRIORITY_MAX = 31`), so a fixed array of `NPRIO = 32` FIFOs plus a
//! 32-bit bitmap is exact and cheap — this is the classic multilevel run-queue
//! shape (one ready list per priority level, a bitmap for O(1) "highest
//! non-empty level") used by priority-array schedulers.  It fits AstryxOS's
//! existing discrete-priority + wait-age model directly, without a virtual-time
//! ordered structure.

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use alloc::collections::VecDeque;
use crate::arch::x86_64::apic::MAX_CPUS;
use crate::proc::{self, Tid, ThreadState};

/// Number of priority levels: `PRIORITY_IDLE (0)` ..= `PRIORITY_MAX (31)`,
/// inclusive, so 32 FIFO buckets and a 32-bit non-empty bitmap.  A
/// compile-time assertion below pins this to `PRIORITY_MAX` so a future
/// priority-range change cannot silently desynchronise the bucket array from
/// the bitmap width.
pub const NPRIO: usize = 32;

// If `PRIORITY_MAX` ever grows past the 32-bit bitmap, this fails to compile.
const _: () = assert!((proc::PRIORITY_MAX as usize) < NPRIO);

/// A per-CPU, per-priority runqueue.
///
/// Scaffold semantics (phase 1): this is populated and verified as a mirror of
/// the authoritative `THREAD_TABLE` ready-set for the owning CPU; it does not
/// yet drive any scheduling decision.  All mutation happens through the
/// [`enqueue`](PerCpuRq::enqueue) / [`dequeue`](PerCpuRq::dequeue) methods so
/// the bitmap and `nr_running` invariants are maintained in exactly one place
/// (the later phases reuse these same primitives to drive real scheduling).
pub struct PerCpuRq {
    /// One FIFO of runnable thread IDs per priority level.  `lists[p]` holds
    /// the threads whose base priority maps to level `p`; the head is the
    /// next-to-run within that level (round-robin among equals).
    lists: [VecDeque<Tid>; NPRIO],
    /// Bit `p` is set iff `lists[p]` is non-empty.  Lets the picker find the
    /// highest non-empty priority level in O(1) (`31 - leading_zeros`).
    bitmap: u32,
    /// Cached count of queued thread IDs across all levels — the sum of
    /// `lists[p].len()`.  Maintained incrementally by enqueue/dequeue.
    nr_running: u32,
}

impl PerCpuRq {
    /// Construct an empty runqueue.
    const fn new() -> Self {
        // `VecDeque::new()` is const and allocation-free until first push, so
        // the static array of empty queues costs nothing at boot.
        const EMPTY: VecDeque<Tid> = VecDeque::new();
        PerCpuRq {
            lists: [EMPTY; NPRIO],
            bitmap: 0,
            nr_running: 0,
        }
    }

    /// Public constructor for the test suite, which exercises the runqueue API
    /// directly (deterministic, no thread spinning).  Identical to the internal
    /// `new()` — exposed only so `test_runner` can build a standalone instance
    /// without reaching into the static `RQS`.
    pub fn new_for_test() -> Self {
        Self::new()
    }

    /// Number of runnable threads currently queued on this CPU.
    #[inline]
    pub fn nr_running(&self) -> u32 {
        self.nr_running
    }

    /// The priority-non-empty bitmap (bit `p` set ⇔ `lists[p]` non-empty).
    #[inline]
    pub fn bitmap(&self) -> u32 {
        self.bitmap
    }

    /// Reset to empty.  Used by the phase-1 mirror rebuild before it re-derives
    /// the queue from the authoritative table; also the natural "clear" for
    /// tests.
    pub fn clear(&mut self) {
        for l in self.lists.iter_mut() {
            l.clear();
        }
        self.bitmap = 0;
        self.nr_running = 0;
    }

    /// Enqueue `tid` at priority level `prio` (FIFO tail — round-robin among
    /// equals).  Maintains the bitmap and `nr_running`.  `prio` is clamped to a
    /// valid level defensively; a caller should always pass a real base
    /// priority (`0..=PRIORITY_MAX`).
    pub fn enqueue(&mut self, tid: Tid, prio: u8) {
        let p = (prio as usize).min(NPRIO - 1);
        self.lists[p].push_back(tid);
        self.bitmap |= 1u32 << p;
        self.nr_running += 1;
    }

    /// Remove the first occurrence of `tid` from priority level `prio`.
    /// Returns `true` if it was present.  Clears the bitmap bit when the level
    /// becomes empty and decrements `nr_running`.
    pub fn dequeue(&mut self, tid: Tid, prio: u8) -> bool {
        let p = (prio as usize).min(NPRIO - 1);
        if let Some(pos) = self.lists[p].iter().position(|&t| t == tid) {
            self.lists[p].remove(pos);
            if self.lists[p].is_empty() {
                self.bitmap &= !(1u32 << p);
            }
            self.nr_running -= 1;
            true
        } else {
            false
        }
    }

    /// O(1) peek at the next thread to run: the head of the highest non-empty
    /// priority level.  Returns `None` when the runqueue is empty.  This is the
    /// pick primitive the later phases adopt; in phase 1 it is exercised only by
    /// the self-verification and the unit tests.
    #[inline]
    pub fn highest(&self) -> Option<Tid> {
        if self.bitmap == 0 {
            return None;
        }
        // Highest set bit = highest priority level present.
        let top = 31 - self.bitmap.leading_zeros() as usize;
        self.lists[top].front().copied()
    }

    /// Self-check the structural invariants of this runqueue:
    ///   * `bitmap` bit `p` is set iff `lists[p]` is non-empty, and
    ///   * `nr_running` equals the total number of queued IDs.
    /// Returns `true` when consistent.  Used by the phase-1 mirror's
    /// post-rebuild assertion and by the unit tests; cheap (one pass over 32
    /// short queues).
    pub fn invariants_hold(&self) -> bool {
        let mut count = 0u32;
        for p in 0..NPRIO {
            let non_empty = !self.lists[p].is_empty();
            let bit_set = (self.bitmap & (1u32 << p)) != 0;
            if non_empty != bit_set {
                return false;
            }
            count += self.lists[p].len() as u32;
        }
        count == self.nr_running
    }
}

/// One [`PerCpuRq`] per logical CPU, each behind its own leaf lock.
///
/// # Lock order
///
/// `THREAD_TABLE` → `RQS[cpu]` (the runqueue lock is a leaf).  The phase-1
/// mirror only ever takes a runqueue lock *while already holding*
/// `THREAD_TABLE` (it derives the mirror from the locked table), which respects
/// this order.  Phase 3+ migration takes two runqueue locks in ascending CPU
/// index order to stay deadlock-free; no path takes `THREAD_TABLE` while
/// holding a runqueue lock.
pub static RQS: [spin::Mutex<PerCpuRq>; MAX_CPUS] =
    [const { spin::Mutex::new(PerCpuRq::new()) }; MAX_CPUS];

/// Cumulative count of phase-1 mirror rebuilds that detected a structural
/// invariant break (bitmap/`nr_running` desynchronised from the lists).  This
/// must stay at zero; a non-zero value is a scaffold bug, surfaced to the test
/// suite via [`mirror_invariant_failures`].  Monotone since boot.
pub static MIRROR_INVARIANT_FAILURES: AtomicU32 = AtomicU32::new(0);

/// Cumulative count of phase-1 mirror rebuilds where the per-CPU runqueue's
/// ready membership disagreed with the authoritative `THREAD_TABLE` ready-set
/// for that CPU.  Must stay zero in phase 1 (the mirror is *built from* the
/// table, so it can only diverge on a real scaffold bug).  Monotone since boot.
pub static MIRROR_MEMBERSHIP_FAILURES: AtomicU32 = AtomicU32::new(0);

/// Snapshot of [`MIRROR_INVARIANT_FAILURES`].
pub fn mirror_invariant_failures() -> u32 {
    MIRROR_INVARIANT_FAILURES.load(Ordering::Relaxed)
}

/// Snapshot of [`MIRROR_MEMBERSHIP_FAILURES`].
pub fn mirror_membership_failures() -> u32 {
    MIRROR_MEMBERSHIP_FAILURES.load(Ordering::Relaxed)
}

/// O(1) read of a CPU's mirrored runnable count without scanning the table.
/// Phase-1 diagnostic only (the authoritative depth metric is still
/// `super::ready_depth()`); later phases promote this to the live count.
pub fn rq_nr_running(cpu: usize) -> u32 {
    if cpu >= MAX_CPUS {
        return 0;
    }
    RQS[cpu].lock().nr_running()
}

/// Decide which CPU's runqueue a Ready thread is mirrored onto.
///
/// Phase-1 placement policy (mirror only): a thread is mirrored onto the CPU it
/// would run on under the *current* picker's affinity preference — its
/// `cpu_affinity` pin if set, else the CPU it last ran on (`last_cpu`).  This
/// keeps the mirror's membership aligned with where the authoritative picker
/// would place the thread, so the membership cross-check is meaningful.  The
/// real wakeup-target selection (`select_task_rq`-equivalent, with
/// least-loaded fallback) arrives in phase 3.
#[inline]
fn target_cpu_for(affinity: Option<u8>, last_cpu: u8) -> usize {
    let c = match affinity {
        Some(a) => a as usize,
        None => last_cpu as usize,
    };
    if c < MAX_CPUS { c } else { 0 }
}

/// True iff `t` belongs to the mirrored non-idle runnable pool: a `Ready`
/// thread that is NOT an idle-class thread.
///
/// "Idle class" matches the authoritative picker EXACTLY: `is_idle_thread =
/// t.tid >= 0x1000` (super::schedule, the AP idle threads).  TID 0 — the BSP
/// poll reactor — is DELIBERATELY a non-idle `PRIORITY_IDLE` peer, NOT idle, in
/// both the picker (which warns that classifying TID 0 as idle would starve the
/// net/x11/compositor polls) and here, so the mirror tracks the picker's
/// non-idle pool faithfully.  Phase 2 switches the pick to read this pool;
/// excluding TID 0 here would silently drop the latency-critical reactor from
/// the runnable set, so this predicate is load-bearing.
#[inline]
fn is_mirrored_runnable(t: &proc::Thread) -> bool {
    t.state == ThreadState::Ready && t.tid < 0x1000
}

/// Phase-1 mirror rebuild + self-verify, called from the authoritative picker
/// while `THREAD_TABLE` is held.
///
/// Rebuilds every CPU's runqueue from the locked thread table so the structure,
/// bitmap and `nr_running` reflect the current non-idle Ready set, then
/// verifies two properties and records any break in the monotone failure
/// counters:
///
///   1. **Structural invariants** — for each rebuilt runqueue, the bitmap and
///      `nr_running` agree with the lists ([`PerCpuRq::invariants_hold`]).
///   2. **Membership** — the number of thread IDs mirrored across all CPUs
///      equals the authoritative non-idle Ready count ([`is_mirrored_runnable`],
///      the same `tid < 0x1000` non-idle pool the picker's `ready_peers`
///      counts).  This `expected` count is derived in an INDEPENDENT pass over
///      the table (not folded into the enqueue loop), so a bug that drops a
///      thread during enqueue/target-selection/clamp is actually caught rather
///      than silently agreeing with itself.
///
/// This is the heart of "behaviour-preserving scaffold": it touches no thread
/// state and changes no decision; it only proves the new structure tracks the
/// authoritative ready-set, on every scheduling pass, so phases 2+ can switch
/// the picker over to it with confidence.
///
/// `threads` is the already-locked thread table (the caller in
/// `super::schedule` holds `THREAD_TABLE`).  Cheap relative to the picker's own
/// table walk it piggybacks on: one independent count pass, one rebuild pass,
/// one short verify pass per CPU.
pub fn mirror_rebuild_and_verify(threads: &[proc::Thread]) {
    // Independent expected count FIRST, before any enqueue — this is the
    // authoritative non-idle Ready population the mirror must reproduce.
    // Deriving it separately (rather than incrementing alongside the enqueue)
    // makes the membership check a genuine cross-check: if the rebuild loop
    // drops a thread (lost clamp, missing guard, target bug), the two counts
    // diverge and the failure is recorded.
    let expected_runnable = threads.iter().filter(|t| is_mirrored_runnable(t)).count() as u32;

    // Take all runqueue locks for the duration of the rebuild.  Lock order is
    // honoured (we already hold THREAD_TABLE; RQS is the leaf), and the locks
    // are acquired in ascending CPU index order — the same order phase-3
    // migration uses — so no two callers can deadlock on them.
    //
    // We hold them across the whole rebuild+verify so a concurrent reader on
    // another CPU never observes a half-rebuilt mirror.
    let mut guards: [Option<spin::MutexGuard<'_, PerCpuRq>>; MAX_CPUS] =
        [const { None }; MAX_CPUS];
    for cpu in 0..MAX_CPUS {
        let mut g = RQS[cpu].lock();
        g.clear();
        guards[cpu] = Some(g);
    }

    // Rebuild: place every non-idle Ready thread onto its target CPU's queue.
    // The idle class (AP idle threads, TID ≥ 0x1000) is excluded exactly as the
    // authoritative picker excludes it; TID 0 (the BSP poll reactor) is a
    // non-idle peer and IS mirrored — see `is_mirrored_runnable`.
    for t in threads.iter() {
        if !is_mirrored_runnable(t) {
            continue;
        }
        let cpu = target_cpu_for(t.cpu_affinity, t.last_cpu);
        if let Some(g) = guards[cpu].as_mut() {
            g.enqueue(t.tid, t.priority);
        }
    }

    // Verify (1): structural invariants per CPU, and tally the mirrored total.
    let mut mirrored_total = 0u32;
    let mut invariant_ok = true;
    for cpu in 0..MAX_CPUS {
        if let Some(g) = guards[cpu].as_ref() {
            if !g.invariants_hold() {
                invariant_ok = false;
            }
            mirrored_total += g.nr_running();
        }
    }
    if !invariant_ok {
        MIRROR_INVARIANT_FAILURES.fetch_add(1, Ordering::Relaxed);
    }

    // Verify (2): the mirrored total matches the INDEPENDENTLY-derived
    // authoritative non-idle Ready count.  A mismatch means the rebuild dropped
    // or duplicated a thread relative to the table — a genuine scaffold bug.
    if mirrored_total != expected_runnable {
        MIRROR_MEMBERSHIP_FAILURES.fetch_add(1, Ordering::Relaxed);
    }

    // Guards drop here in declaration order, releasing every runqueue lock.
}
