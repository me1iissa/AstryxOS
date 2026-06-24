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
    /// The earliest absolute anti-starvation force-deadline among the non-idle
    /// Ready threads on this runqueue, in 100 Hz ticks, or `u64::MAX` when none.
    ///
    /// For each queued non-idle thread the absolute deadline is
    /// `ready_since_tick + (TID 0 ? STARVE_FORCE_TICKS_BSP : STARVE_FORCE_TICKS)`;
    /// `min_deadline` is the minimum over the runqueue.  It is the O(1)
    /// force-gate: `min_deadline <= now` is true **iff at least one thread on
    /// this runqueue is at or past its force deadline** (i.e. iff the picker's
    /// per-candidate `max(wait_age - deadline) >= 0`).  See
    /// [`overdue`](PerCpuRq::overdue).  The picker still scans the candidates to
    /// NAME the most-overdue thread (that scan is already part of its scoring
    /// pass); this scalar lets a caller cheaply answer "is anyone overdue?"
    /// without re-deriving per-candidate margins.  Recomputed each maintenance
    /// pass by [`set_min_deadline`](PerCpuRq::set_min_deadline) (it depends on
    /// `now`-relative wait clocks, which advance even when membership does not).
    ///
    /// # Staging
    ///
    /// As of Phase 3a this scalar is maintained and PROVEN equivalent to the
    /// picker's per-candidate force gate (Test 649) but has no production
    /// consumer yet — the live force DECISION still flows through
    /// `select_next_core`'s per-candidate margin scan (which also NAMES the
    /// most-overdue thread, something a single scalar cannot do).  `overdue` is
    /// the O(1) "is anyone on this rq past their deadline?" primitive the
    /// Phase 3d load balancer will use to decide, without a full scan, whether a
    /// remote runqueue holds a steal-worthy overdue task; it does not (and in
    /// 3a must not) change any scheduling decision.
    min_deadline: u64,
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
            min_deadline: u64::MAX,
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

    /// Set the cached earliest force-deadline for this runqueue (the minimum,
    /// over its non-idle Ready threads, of `ready_since_tick + deadline`), or
    /// `u64::MAX` when there is no non-idle Ready thread.  Called once per
    /// maintenance pass by the caller that holds the table (it has the
    /// per-thread wait clocks and per-TID deadlines needed to compute it).
    #[inline]
    pub fn set_min_deadline(&mut self, d: u64) {
        self.min_deadline = d;
    }

    /// The cached earliest force-deadline (see [`min_deadline`](Self::min_deadline)).
    #[inline]
    pub fn min_deadline(&self) -> u64 {
        self.min_deadline
    }

    /// O(1) anti-starvation force-gate: is any non-idle Ready thread on this
    /// runqueue at or past its force deadline as of tick `now`?
    ///
    /// Equivalent to the picker's per-candidate test
    /// `max over candidates of (wait_age - deadline) >= 0`, because
    /// `min_deadline = min(ready_since + deadline)` and
    /// `wait_age - deadline = now - (ready_since + deadline)`, so the maximum
    /// margin is non-negative exactly when the minimum absolute deadline has
    /// been reached: `min_deadline <= now`.  Test 649 proves this equivalence.
    #[inline]
    pub fn overdue(&self, now: u64) -> bool {
        self.min_deadline <= now
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
        self.min_deadline = u64::MAX;
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

    /// Strict structural equality against another runqueue: identical `bitmap`,
    /// `nr_running`, and identical per-level FIFO contents (same tids in the
    /// SAME order at every priority level).  Used by the unit test (Test 647)
    /// where the intra-level order is deterministic and must be checked exactly.
    pub fn equals(&self, other: &PerCpuRq) -> bool {
        if self.bitmap != other.bitmap || self.nr_running != other.nr_running {
            return false;
        }
        for p in 0..NPRIO {
            if self.lists[p] != other.lists[p] {
                return false;
            }
        }
        true
    }

    /// Order-insensitive membership equality against another runqueue: identical
    /// `bitmap`, `nr_running`, and the same SET of tids at every priority level,
    /// regardless of intra-level order.  Used by the phase-2a maintainer's
    /// audit.
    ///
    /// The audit compares the incrementally-maintained runqueue against a
    /// from-scratch table-rebuild image.  Both contain exactly the same threads
    /// in exactly the same (cpu, level) buckets, but they can legitimately differ
    /// in the *order within a level*: the rebuild appends in table-iteration
    /// order, while the incremental path appends a thread at the moment it
    /// transitions into the level (its join order).  Phase 2a does not yet define
    /// a canonical intra-level order — the legacy picker's round-robin is
    /// rotation-over-the-table, not a persistent per-level FIFO — so the audit's
    /// correctness property is *membership + placement*, not order.  (Phase 3,
    /// which makes the runqueue the authoritative round-robin source, will pin
    /// the intra-level order and tighten this back to ordered equality.)
    pub fn same_membership(&self, other: &PerCpuRq) -> bool {
        if self.bitmap != other.bitmap || self.nr_running != other.nr_running {
            return false;
        }
        for p in 0..NPRIO {
            if self.lists[p].len() != other.lists[p].len() {
                return false;
            }
            // Same length and small queues — O(k²) set check is cheap and
            // allocation-free.  Every tid in self's level must appear (with
            // multiplicity 1 — tids are unique) in other's level.
            for &tid in self.lists[p].iter() {
                if !other.lists[p].iter().any(|&o| o == tid) {
                    return false;
                }
            }
        }
        true
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

/// Drop a thread from the per-CPU runqueues given its recorded mirror slot.
///
/// Called at the points that REMOVE a thread from `THREAD_TABLE` (reap, waitpid,
/// orphan-zombie auto-reap), BEFORE the removal, so a thread that is still
/// mirrored when its record disappears does not strand its tid (and a leaked
/// `nr_running` / bitmap bit) in a runqueue the maintainer can never revisit.
/// Without this, a thread reaped before a `mirror_maintain` pass observes it as
/// non-runnable would dangle until the next gated audit notices the divergence.
///
/// `slot` is the thread's `Thread::mirror_slot` (read just before removal); a
/// `None` slot is a no-op.  The caller MUST hold `THREAD_TABLE` (so the slot it
/// read is the current one); this takes the single relevant `RQS[cpu]` leaf lock
/// in the documented order.
pub fn mirror_forget(slot: MirrorSlot, tid: Tid) {
    if let Some((cpu, prio)) = slot {
        if (cpu as usize) < MAX_CPUS {
            RQS[cpu as usize].lock().dequeue(tid, prio);
        }
    }
}

/// Test-facing exact replica of the maintainer's two reconciliation algorithms,
/// operating on caller-owned structures so the live static `RQS` (shared with
/// the running scheduler) is never disturbed.
///
/// `slots` is the per-thread recorded mirror slot (the `Thread::mirror_slot`
/// shadow), `desired` is each thread's [`desired_slot`] for the current pass,
/// and `tids` are the thread IDs (parallel arrays, one entry per thread).  This
/// applies the SAME O(Δ) delta `mirror_maintain` applies — dequeue from the old
/// recorded bucket, enqueue into the new desired bucket, update the recorded
/// slot — to the caller's `rqs`, and updates `slots` in place.  Used by the
/// equivalence test (Test 647) to drive a sequence of transitions through the
/// incremental path and compare the result, pass by pass, against a
/// from-scratch full rebuild ([`test_full_rebuild`]).
#[doc(hidden)]
pub fn test_apply_incremental(
    rqs: &mut [PerCpuRq],
    slots: &mut [MirrorSlot],
    tids: &[Tid],
    desired: &[MirrorSlot],
) {
    for i in 0..tids.len() {
        let have = slots[i];
        let want = desired[i];
        if have == want {
            continue;
        }
        if let Some((ocpu, oprio)) = have {
            if (ocpu as usize) < rqs.len() {
                rqs[ocpu as usize].dequeue(tids[i], oprio);
            }
        }
        if let Some((ncpu, nprio)) = want {
            if (ncpu as usize) < rqs.len() {
                rqs[ncpu as usize].enqueue(tids[i], nprio);
            }
        }
        slots[i] = want;
    }
}

/// Test-facing exact replica of the maintainer's full table-derived rebuild
/// (the gated audit's reference image): clear every runqueue, then enqueue each
/// thread that has a `desired` slot, in array order (the same order the audit
/// walks the table in).  Used by Test 647 as the from-scratch oracle the
/// incremental path must match.
#[doc(hidden)]
pub fn test_full_rebuild(rqs: &mut [PerCpuRq], tids: &[Tid], desired: &[MirrorSlot]) {
    for rq in rqs.iter_mut() {
        rq.clear();
    }
    for i in 0..tids.len() {
        if let Some((cpu, prio)) = desired[i] {
            if (cpu as usize) < rqs.len() {
                rqs[cpu as usize].enqueue(tids[i], prio);
            }
        }
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

/// Cumulative count of audit passes that found a structural invariant break
/// (bitmap/`nr_running` desynchronised from the lists) in an
/// incrementally-maintained runqueue.  This must stay at zero; a non-zero value
/// is a maintainer bug, surfaced to the test suite via
/// [`mirror_invariant_failures`].  Bumped only by the gated audit in
/// [`mirror_maintain`].  Monotone since boot.
pub static MIRROR_INVARIANT_FAILURES: AtomicU32 = AtomicU32::new(0);

/// Cumulative count of audit passes where an incrementally-maintained per-CPU
/// runqueue disagreed (membership, placement or FIFO order) with the
/// authoritative `THREAD_TABLE`-derived image.  Must stay zero: the maintainer
/// tracks the table, so it can only diverge on a real maintenance bug (a dropped
/// delta, an unreflected off-path transition).  Bumped only by the gated audit
/// in [`mirror_maintain`].  Monotone since boot.
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

/// Decide which CPU's runqueue a Ready thread is mirrored onto — the
/// DETERMINISTIC placement read from the thread's stored fields.
///
/// A pinned thread (`cpu_affinity = Some(a)`) is always placed on its pinned
/// CPU; an unpinned thread is placed on the CPU it last ran on (`last_cpu`).
/// This is a pure function of stored state, so the per-CPU runqueue placement is
/// stable across maintenance passes (it does NOT recompute a load-aware target
/// each pass, which would thrash a thread between runqueues as load fluctuates).
///
/// The LOAD-AWARE wakeup-target choice (`select_task_rq`-equivalent) is made
/// once, at the moment a thread enters the runnable set (its wake edge), by
/// [`select_wake_target`]; the result is baked into `last_cpu` so that this
/// deterministic placement then follows it.  See [`mirror_maintain`].
#[inline]
fn target_cpu_for(affinity: Option<u8>, last_cpu: u8) -> usize {
    let c = match affinity {
        Some(a) => a as usize,
        None => last_cpu as usize,
    };
    if c < MAX_CPUS { c } else { 0 }
}

/// A runqueue at or above this `nr_running` is considered "overloaded" for the
/// purpose of the cache-warm wakeup heuristic: a waking thread prefers its
/// cache-warm `last_cpu`, but only while that CPU is not already this deep, in
/// which case it falls back to the least-loaded runqueue.  One in-flight task
/// plus one waking task is fine (depth 1 is not overloaded); the threshold
/// trips when the cache-warm CPU already has a backlog the waker would queue
/// behind.
const RQ_OVERLOAD_THRESHOLD: u32 = 2;

/// Pure wakeup-target decision (`select_task_rq`-equivalent), parameterised by a
/// runqueue-load reader so it can run either over the live `RQS` locks (external
/// callers) or over guards already held (the `mirror_maintain` wake edge,
/// which must not re-lock the leaf spinlock).  `ncpus` is the number of online
/// CPUs.  Decision order:
///
///   1. **Hard affinity pin** — if `affinity = Some(a)` the thread MUST run on
///      CPU `a` (a pin is a correctness constraint, not a hint); return it.
///   2. **Cache-warm `last_cpu`** — if that CPU's runqueue is not overloaded
///      (`load < RQ_OVERLOAD_THRESHOLD`), keep the thread there to reuse its
///      warm cache footprint.
///   3. **Least-loaded runqueue** — otherwise spread the load: the CPU with the
///      smallest load, ties broken toward the warm CPU (then the lowest index)
///      so a tie never forces a gratuitous migration.
///
/// On a uniprocessor (`ncpus <= 1`) every candidate resolves to CPU 0.
#[inline]
fn wake_target_with_loads(
    affinity: Option<u8>,
    last_cpu: u8,
    ncpus: usize,
    load: impl Fn(usize) -> u32,
) -> u8 {
    // 1. Hard pin wins unconditionally.
    if let Some(a) = affinity {
        return if (a as usize) < MAX_CPUS { a } else { 0 };
    }
    if ncpus <= 1 {
        return 0; // uniprocessor: only CPU 0 exists
    }
    let warm = (last_cpu as usize).min(ncpus - 1);
    // 2. Cache-warm CPU if not overloaded.
    let warm_load = load(warm);
    if warm_load < RQ_OVERLOAD_THRESHOLD {
        return warm as u8;
    }
    // 3. Least-loaded runqueue (prefer the warm CPU on a tie → no needless move).
    let mut best_cpu = warm;
    let mut best_load = warm_load;
    for cpu in 0..ncpus {
        let l = load(cpu);
        if l < best_load {
            best_load = l;
            best_cpu = cpu;
        }
    }
    best_cpu as u8
}

/// Choose the CPU a waking thread should be enqueued on
/// (`select_task_rq`-equivalent) by reading the LIVE runqueue loads.
///
/// O(MAX_CPUS) and allocation-free; it briefly takes each runqueue's leaf lock
/// to read `nr_running` (ascending index order, the documented order — and the
/// caller must therefore NOT already hold any `RQS` lock).  On a uniprocessor
/// (`cpu_count() == 1`) this returns 0, so the wakeup target is a no-op and
/// SMP=1 is unchanged.  See [`wake_target_with_loads`] for the decision logic.
pub fn select_wake_target(affinity: Option<u8>, last_cpu: u8) -> u8 {
    let ncpus = crate::arch::x86_64::apic::cpu_count().min(MAX_CPUS as u32) as usize;
    wake_target_with_loads(affinity, last_cpu, ncpus, |cpu| RQS[cpu].lock().nr_running())
}

/// Test-facing replica of the wakeup-target decision over caller-supplied loads
/// (Test 650), so the >1-CPU routing can be proven without spinning real
/// threads or touching the live `RQS`.  Identical logic to the live paths.
#[doc(hidden)]
pub fn test_wake_target(affinity: Option<u8>, last_cpu: u8, loads: &[u32]) -> u8 {
    wake_target_with_loads(affinity, last_cpu, loads.len(), |cpu| {
        loads.get(cpu).copied().unwrap_or(0)
    })
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

/// The per-thread mirror slot that the incremental maintainer records on the
/// `Thread` record so a later pass can locate (and dequeue) the thread in O(1)
/// without re-deriving its priority/target from scratch.
///
/// `None` ⇒ the thread is NOT currently in any per-CPU runqueue.  `Some((cpu,
/// prio))` ⇒ the thread is enqueued on `RQS[cpu]` at priority level `prio`.
/// Storing the level the thread was enqueued AT (rather than re-reading its
/// live `priority`) is what makes dequeue exact even if the thread's priority
/// changed since it was enqueued: we always remove from the bucket it actually
/// occupies.
pub type MirrorSlot = Option<(u8, u8)>;

/// Periodic full-rebuild audit cadence, in scheduling passes (picker
/// iterations).  Every `AUDIT_EVERY_PASSES`-th pass the maintainer does the
/// original O(N) clear-rebuild-from-table + independent cross-check; the other
/// passes only apply the O(Δ) membership delta.  64 keeps the audit's amortized
/// cost negligible (one full rebuild per ~64 picks) while still catching, within
/// well under a second of wall-clock, any drift between the incrementally
/// maintained runqueues and the authoritative table.
const AUDIT_EVERY_PASSES: u64 = 64;

/// Monotone counter of scheduling passes seen by [`mirror_maintain`]; drives the
/// `AUDIT_EVERY_PASSES` audit cadence.  Picker passes always run with the owning
/// CPU holding `THREAD_TABLE`, so a `Relaxed` non-atomic-RMW would suffice on
/// SMP=1; it is an atomic so the cadence is well-defined if two CPUs ever drive
/// the maintainer concurrently in a later phase.
static MAINTAIN_PASSES: AtomicU32 = AtomicU32::new(0);

/// Cumulative count of audit passes whose full table-derived rebuild disagreed
/// with the incrementally-maintained runqueues (membership or per-CPU
/// placement).  Must stay zero: a non-zero value means the incremental
/// enqueue/dequeue maintenance dropped, duplicated or mis-placed a thread
/// relative to the authoritative table.  Monotone since boot; surfaced to the
/// test suite via [`mirror_audit_failures`].
pub static MIRROR_AUDIT_FAILURES: AtomicU32 = AtomicU32::new(0);

/// Snapshot of [`MIRROR_AUDIT_FAILURES`].
pub fn mirror_audit_failures() -> u32 {
    MIRROR_AUDIT_FAILURES.load(Ordering::Relaxed)
}

/// Cumulative count of live scheduling passes (debug builds only) where the
/// phase-2b per-CPU runqueue pick selected a DIFFERENT thread than the
/// authoritative legacy table-scan pick.  Must stay zero on SMP=1: a non-zero
/// value means the per-CPU candidate derivation or the `select_next`
/// equivalence diverged from the legacy picker for some live ready-set the
/// Test-648 constructed cases did not cover.  This is the live half of the
/// pick-equivalence proof; the legacy result remains authoritative, so a
/// divergence is observed, logged and counted but never acted on.  Monotone
/// since boot; surfaced via [`pick_divergences`].
pub static PICK_DIVERGENCES: AtomicU32 = AtomicU32::new(0);

/// Record one live per-CPU-vs-legacy pick divergence (phase-2b cross-check).
#[inline]
pub fn note_pick_divergence() {
    PICK_DIVERGENCES.fetch_add(1, Ordering::Relaxed);
}

/// Sample gate for the live pick cross-check: returns `true` once every
/// `PICK_XCHECK_SAMPLE` scheduling passes, so the cross-check's per-sample heap
/// allocation and O(n) candidate rebuild never dominate the pick hot path.  The
/// cross-check still catches a divergence within `PICK_XCHECK_SAMPLE` passes of
/// it first arising, which is ample for a live equivalence soak.
#[cfg(feature = "sched-pick-xcheck")]
pub fn pick_xcheck_sample_due() -> bool {
    /// Sample one pick in this many passes.  Power of two so the modulo is a
    /// mask; large enough that the cross-check is a negligible amortized cost.
    const PICK_XCHECK_SAMPLE: u32 = 256;
    static PASS: AtomicU32 = AtomicU32::new(0);
    let n = PASS.fetch_add(1, Ordering::Relaxed);
    n % PICK_XCHECK_SAMPLE == 0
}

/// Snapshot of [`PICK_DIVERGENCES`].
pub fn pick_divergences() -> u32 {
    PICK_DIVERGENCES.load(Ordering::Relaxed)
}

/// The runqueue membership a thread SHOULD have right now: `None` if it is not a
/// mirrored-runnable thread, else `Some((target_cpu, priority))`.  This is the
/// single definition of "where the mirror wants this thread", shared by the
/// incremental delta and the audit so they cannot drift in interpretation.
#[inline]
fn desired_slot(t: &proc::Thread) -> MirrorSlot {
    if is_mirrored_runnable(t) {
        let cpu = target_cpu_for(t.cpu_affinity, t.last_cpu) as u8;
        Some((cpu, t.priority))
    } else {
        None
    }
}

/// Incremental per-CPU runqueue maintenance + gated audit (Perf P2 phase 2a),
/// called from the authoritative picker while `THREAD_TABLE` is held.  Replaces
/// the phase-1 passive mirror (a full O(N) clear-and-rebuild on
/// EVERY pass) with O(Δ) maintenance on the hot path plus an amortized O(N)
/// audit.
///
/// On every pass it walks the table once and, for each thread, compares its
/// recorded `mirror_slot` (where it is currently enqueued) against its
/// [`desired_slot`] (where it should be).  Only a thread whose membership
/// actually changed since the previous pass costs an enqueue and/or dequeue — a
/// quiescent ready-set costs zero queue mutations.  This is the behaviour the
/// later phases need: the runqueue tracks the live ready-set continuously and
/// cheaply, with no per-pass rebuild.
///
/// Every [`AUDIT_EVERY_PASSES`]-th pass it ADDITIONALLY rebuilds a throwaway
/// view from the table and cross-checks it against the incrementally-maintained
/// runqueues; any divergence (membership, placement, or a broken
/// bitmap/`nr_running` invariant) bumps [`MIRROR_AUDIT_FAILURES`].  This is the
/// safety net that catches an off-path state transition the incremental delta
/// failed to reflect (a future wake site that never runs through the picker
/// before the pick reads the mirror).
///
/// Still behaviour-preserving: it touches no scheduling DECISION (the legacy
/// picker remains authoritative this PR) and only the new `mirror_slot` shadow
/// field of `Thread`; SMP=1 selection stays bit-for-bit identical.
///
/// `threads` is the already-locked thread table.  Lock order is honoured
/// (THREAD_TABLE held; the RQS locks are leaves taken in ascending CPU order
/// inside this function).
pub fn mirror_maintain(threads: &mut [proc::Thread]) {
    let pass = MAINTAIN_PASSES.fetch_add(1, Ordering::Relaxed);
    let audit_due = pass % (AUDIT_EVERY_PASSES as u32) == 0;

    // Take all runqueue locks for the whole pass, in ascending CPU index order
    // (the order phase-3 migration uses), so a concurrent reader on another CPU
    // never observes a half-updated mirror and no path can deadlock on them.
    let mut guards: [Option<spin::MutexGuard<'_, PerCpuRq>>; MAX_CPUS] =
        [const { None }; MAX_CPUS];
    for cpu in 0..MAX_CPUS {
        guards[cpu] = Some(RQS[cpu].lock());
    }

    // Number of online CPUs, computed once for this pass (drives the wakeup
    // target spread below).  `cpu_count()==1` ⇒ every target is CPU 0.
    let ncpus = crate::arch::x86_64::apic::cpu_count().min(MAX_CPUS as u32) as usize;

    // ── O(Δ) incremental delta + wakeup-target selection ─────────────────────
    // For each thread, reconcile its recorded slot with its desired slot.  A
    // thread whose membership is unchanged (same cpu+prio, or still absent)
    // performs no queue mutation.
    //
    // WAKEUP TARGET (Perf P2 phase 3b): the moment a thread ENTERS the
    // mirrored-runnable set — its `mirror_slot` was `None` and it is now a Ready
    // non-idle thread — is the wake edge as the scheduler observes it (covering
    // every Blocked/New→Ready wake site without instrumenting each one
    // individually, the same centralisation `ready_since_tick` stamping uses).
    // At that edge, for an UNPINNED thread, choose the load-aware target CPU
    // (`select_task_rq`-equivalent) and bake it into `last_cpu` so the
    // deterministic `desired_slot` placement then follows it.  A pinned thread's
    // target is its pin, handled by `desired_slot`/`target_cpu_for` directly.
    // The load read uses the guards already held (re-locking `RQS` here would
    // deadlock the leaf spinlock), so the spread sees this pass's live counts.
    // Bitmask of CPUs that gained a freshly-enqueued thread on a REMOTE
    // runqueue this pass and should be poked with a reschedule IPI (Perf P2
    // phase 3c).  Collected under the locks but the IPIs are fired AFTER the
    // guards drop, so no IPI is sent from inside the locked window.  `here` is
    // this CPU; a bit is set only for a CPU != here, so on SMP=1 the mask stays
    // empty (the wake edge requires `ncpus > 1` to even reassign a target, and
    // the only enqueue CPU is 0 == here).
    let here = crate::arch::x86_64::apic::cpu_index();
    let mut resched_mask: u32 = 0;

    for t in threads.iter_mut() {
        // Wake-edge target assignment (before computing `want`, which reads
        // `last_cpu`).  Only on the None→runnable transition, only for unpinned
        // threads, and only when there is more than one CPU to spread across.
        if ncpus > 1
            && t.mirror_slot.is_none()
            && t.cpu_affinity.is_none()
            && is_mirrored_runnable(t)
        {
            // Read loads from the guards already held (re-locking RQS here would
            // deadlock the leaf spinlock); shares the decision with the live and
            // test paths via `wake_target_with_loads`.
            let target = wake_target_with_loads(
                t.cpu_affinity, t.last_cpu, ncpus,
                |cpu| guards[cpu].as_ref().map_or(0, |g| g.nr_running()),
            );
            t.last_cpu = target;
        }

        let have = t.mirror_slot;
        let want = desired_slot(t);
        if have == want {
            continue;
        }
        // A None→Some transition that lands on a REMOTE CPU is a cross-CPU
        // wakeup: flag that CPU for a reschedule poke.  (have==None means the
        // thread was not previously enqueued — i.e. it just woke; a Some→Some
        // re-placement is a migration handled elsewhere, not a wake.)
        if have.is_none() {
            if let Some((ncpu, _)) = want {
                if (ncpu as usize) != here && (ncpu as usize) < 32 {
                    resched_mask |= 1u32 << (ncpu as u32);
                }
            }
        }
        // Remove from the old bucket (if any) — using the level it was enqueued
        // AT, not its (possibly changed) live priority.
        if let Some((ocpu, oprio)) = have {
            if let Some(g) = guards[ocpu as usize].as_mut() {
                g.dequeue(t.tid, oprio);
            }
        }
        // Insert into the new bucket (if it should be present).
        if let Some((ncpu, nprio)) = want {
            if let Some(g) = guards[ncpu as usize].as_mut() {
                g.enqueue(t.tid, nprio);
            }
        }
        t.mirror_slot = want;
    }

    // ── Per-rq earliest force-deadline (O(1) starvation gate) ────────────────
    // Recompute each pass: a thread's absolute deadline (`ready_since + per-TID
    // deadline`) is fixed once it becomes Ready, but membership and wait clocks
    // change between passes, so the per-rq minimum is re-derived from the live
    // ready-set here (one extra walk, same lock window).  `min_deadline = MAX`
    // means "no non-idle Ready thread" → `overdue(now)` is always false.  This
    // mirrors `desired_slot`'s placement so the scalar and the queued set agree.
    let mut mins: [u64; MAX_CPUS] = [u64::MAX; MAX_CPUS];
    for t in threads.iter() {
        if let Some((cpu, _prio)) = desired_slot(t) {
            let deadline = super::force_deadline_for_tid(t.tid);
            let abs = t.ready_since_tick.saturating_add(deadline);
            let c = cpu as usize;
            if abs < mins[c] {
                mins[c] = abs;
            }
        }
    }
    for cpu in 0..MAX_CPUS {
        if let Some(g) = guards[cpu].as_mut() {
            g.set_min_deadline(mins[cpu]);
        }
    }

    // ── Gated audit ──────────────────────────────────────────────────────────
    // Rebuild a throwaway image of every CPU's runqueue directly from the table
    // and compare it, bucket-for-bucket, against the incrementally-maintained
    // runqueues.  An independent derivation (not folded into the delta above) is
    // what makes this a genuine cross-check rather than a self-confirming tally.
    if audit_due {
        let mut audit: [PerCpuRq; MAX_CPUS] = core::array::from_fn(|_| PerCpuRq::new());
        for t in threads.iter() {
            if let Some((cpu, prio)) = desired_slot(t) {
                audit[cpu as usize].enqueue(t.tid, prio);
            }
        }
        let mut invariant_ok = true;
        let mut membership_ok = true;
        for cpu in 0..MAX_CPUS {
            if let Some(g) = guards[cpu].as_ref() {
                // Structural invariant of the live (incrementally-maintained)
                // runqueue: bitmap/nr_running agree with its own lists.
                if !g.invariants_hold() {
                    invariant_ok = false;
                }
                // Membership + placement match the table-derived image.
                // Intra-level ORDER is intentionally not required here (see
                // `same_membership`): phase 2a does not yet define a canonical
                // per-level order, so requiring it would false-positive whenever
                // a thread's join order differs from table-iteration order.
                if !g.same_membership(&audit[cpu]) {
                    membership_ok = false;
                }
            }
        }
        // Feed BOTH the long-standing phase-1 counters (so Test 645's
        // zero-failure assertions remain a live signal under the new
        // maintainer) AND the dedicated audit counter.
        if !invariant_ok {
            MIRROR_INVARIANT_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        if !membership_ok {
            MIRROR_MEMBERSHIP_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        if !invariant_ok || !membership_ok {
            MIRROR_AUDIT_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Release every runqueue lock BEFORE issuing any reschedule IPI, so no IPI
    // is sent from inside the locked window (the handler is lock-free, but
    // keeping the send out of the critical section bounds the lock-hold time).
    drop(guards);

    // ── Reschedule IPIs for cross-CPU wakeups (Perf P2 phase 3c) ─────────────
    // Poke each remote CPU that gained a freshly-enqueued thread this pass so it
    // reschedules at its next return-to-context check instead of waiting out a
    // timer tick.  `resched_cpu` sets the target's NEED_RESCHEDULE flag and
    // sends the fire-and-forget 0xF2 IPI; it takes no lock.  On SMP=1 the mask
    // is always empty, so this loop is a no-op and behaviour is unchanged.
    let mut m = resched_mask;
    while m != 0 {
        let cpu = m.trailing_zeros() as usize;
        super::resched_cpu(cpu);
        m &= m - 1;
    }
}
