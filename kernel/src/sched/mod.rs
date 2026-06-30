//! CoreSched — The AstryxOS Scheduler
//!
//! Implements a round-robin cooperative/preemptive scheduler.
//! The timer interrupt calls `timer_tick_schedule()` which triggers
//! context switches at the end of each time quantum.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::proc::{self, ThreadState, THREAD_TABLE};
use crate::arch::x86_64::apic::MAX_CPUS;

/// Per-CPU / per-priority runqueue scaffold (Perf P2, phase 1).
///
/// Behaviour-preserving in phase 1: the structure is populated and continuously
/// self-verified as a passive mirror of the authoritative `THREAD_TABLE`
/// ready-set, but the authoritative picker below still makes every scheduling
/// decision.  See [`percpu`] for the design and the phased plan.
pub mod percpu;

/// Whether the scheduler is active.
static SCHEDULER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Time slice in ticks before preemption.
const TIME_SLICE: u64 = 5; // ~50 ms at 100 Hz

/// Per-CPU ticks remaining for current time slice.
static TICKS_REMAINING: [AtomicU64; MAX_CPUS] =
    [const { AtomicU64::new(TIME_SLICE) }; MAX_CPUS];


/// Per-CPU reschedule flag: set by timer ISR, checked after interrupt return.
static NEED_RESCHEDULE: [AtomicBool; MAX_CPUS] =
    [const { AtomicBool::new(false) }; MAX_CPUS];

/// #582 diagnostic: per-CPU resumed-switch counter used to SAMPLE the
/// RFLAGS-slot write-watch arm site 1-in-N (see the arm block in
/// `schedule()`).  Diagnostic-only; carried unconditionally (a single
/// AtomicU64 array) so the arm block stays simple, but only read under
/// `#[cfg(feature = "582-diag")]`.
#[cfg(feature = "582-diag")]
static D582_SAMPLE_CTR: [AtomicU64; MAX_CPUS] =
    [const { AtomicU64::new(0) }; MAX_CPUS];

/// Per-CPU context-switch generation counter.
///
/// Incremented by `note_switch_completed()` every time a CPU finishes a
/// `switch_context_asm` and is running on the *incoming* thread's kernel
/// stack — i.e. once per completed context switch, for both resumed-kernel
/// threads (post-`switch_context` resume point in `schedule()`) and
/// first-run threads (top of `proc::usermode::user_mode_bootstrap`).
///
/// This is the SMP-correct quiescence signal for kernel-stack recycling.
/// `ctx_rsp_valid` proves the *dying* thread's CPU executed `mov [rdi],rsp;
/// mov byte[rdx],1` (it saved the dead frame), but at that instant the CPU
/// is still at `mov rsp,rsi; popfq; pop …; ret` — the restore epilogue,
/// physically *on the dead stack's VA* until `mov rsp,rsi` retires, and a
/// device/timer interrupt can still push an interrupt frame onto that VA via
/// `TSS.RSP[0]` during a ring transition (Intel SDM Vol. 3A §6.14 "Interrupt
/// and Exception Handling": the stack switch on interrupt delivery uses the
/// TSS RSP for the target privilege level).  Re-issuing the stack to a new
/// thread in that window lets the old CPU's epilogue/interrupt-frame writes
/// tear the new thread's freshly-initialised `switch_context_asm` frame —
/// observed as a torn saved-RFLAGS slot (TF=1 garbage) that `popfq` loads,
/// single-stepping the next instruction into a kernel-mode `#DB` →
/// `UNEXPECTED_KERNEL_MODE_TRAP` (0x7f) bugcheck.
///
/// A dead stack records `CPU_SWITCH_GEN[last_cpu]` at reap time; the cache
/// withholds the entry from re-issue until that CPU's generation has
/// advanced (proving `last_cpu` completed at least one *further* switch and
/// is therefore no longer executing on, nor delivering interrupts to, the
/// recycled stack VA).  This is the kernel-side realisation of the
/// POSIX clone(2) "no CPU references the thread" lifecycle contract — the
/// same invariant a reference monolithic kernel enforces by deferring the
/// dead task's stack release into the *successor* task's post-switch
/// cleanup (which by construction runs on a different stack).
static CPU_SWITCH_GEN: [AtomicU64; MAX_CPUS] =
    [const { AtomicU64::new(0) }; MAX_CPUS];

/// Record that the calling CPU has completed a context switch and is now
/// executing on the incoming thread's kernel stack.  Called from the two
/// post-`switch_context` resume points (resumed-kernel in `schedule()` and
/// first-run in `user_mode_bootstrap`).  Lock-free; safe with interrupts
/// disabled.  See `CPU_SWITCH_GEN` for the full rationale.
#[inline]
pub fn note_switch_completed() {
    let cpu = cpu_index();
    if cpu < MAX_CPUS {
        // Release: pair with the Acquire load in `entry_is_quiesced` so a
        // reaper on another CPU that observes the advanced generation also
        // observes all of this CPU's prior stack writes as retired.
        CPU_SWITCH_GEN[cpu].fetch_add(1, Ordering::Release);
    }
    // Publish the thread now physically on this CPU's kernel stack.  This runs
    // AFTER `switch_context_asm` has flipped the stack, so the now-current TID is
    // provably the one executing here and the predecessor it replaces is provably
    // off its stack.  The reaper and the kstack alloc-alias guard survey
    // `is_tid_on_stack_any_cpu` to gate stack reclaim on this signal, closing the
    // switch-OUT half of the window in which a Dead-but-still-on-stack thread's
    // live kernel stack could be recycled into a new thread (a two-CPU-one-stack
    // kstack double-use crash class).  See `proc::PER_CPU_ONSTACK_TID`.
    crate::proc::set_onstack_tid(crate::proc::current_tid());
}

/// On-CPU dispatch-interlock counter: number of times a candidate was DEFERRED
/// from dispatch/work-steal because it was still live (current or on-stack) on
/// another CPU.  A non-zero value proves the #655 double-dispatch race was
/// occurring and is now being caught.  Read via [`double_dispatch_defers`].
static DOUBLE_DISPATCH_DEFERS: AtomicU64 = AtomicU64::new(0);

/// Read the on-CPU dispatch-interlock defer counter (see
/// [`DOUBLE_DISPATCH_DEFERS`]).
#[inline]
pub fn double_dispatch_defers() -> u64 {
    DOUBLE_DISPATCH_DEFERS.load(Ordering::Relaxed)
}

/// The on-CPU dispatch interlock, applied at every dispatch/resume/work-steal
/// site: returns `true` (and counts, rate-limited-logs) when `tid` must NOT be
/// dispatched on `self_cpu` because it is still live on another CPU.
///
/// A deferred thread is NOT lost — it remains Ready/enqueued and is selected
/// normally on a later pass once the other CPU has switched off it (both the
/// current- and on-stack signals clear).  This is the skip-and-defer form of the
/// SMP wakeup/migration interlock (a task is never re-placed on a runqueue while
/// still on-CPU elsewhere); for a cooperative picker, deferring the *selection*
/// is equivalent to — and cheaper than — spin-waiting on the marker.  Closes the
/// #655 window in which one live thread was dispatched onto two CPUs and the two
/// executions tore its single kernel stack's saved switch frame in place.
#[inline]
pub(crate) fn defer_if_live_on_other_cpu(tid: proc::Tid, self_cpu: usize) -> bool {
    if proc::is_tid_live_on_other_cpu(tid, self_cpu) {
        let n = DOUBLE_DISPATCH_DEFERS.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 16 || n % 4096 == 0 {
            crate::serial_println!(
                "[SCHED/INTERLOCK] deferred dispatch of tid={} on cpu={} \
                 (still live on another CPU) total_defers={}",
                tid, self_cpu, n,
            );
        }
        true
    } else {
        false
    }
}

/// Read the current switch generation for `cpu` (Acquire).  Used both to
/// snapshot at reap time and to test eligibility at pop time.
#[inline]
fn cpu_switch_gen(cpu: usize) -> u64 {
    if cpu < MAX_CPUS {
        CPU_SWITCH_GEN[cpu].load(Ordering::Acquire)
    } else {
        // Unknown CPU: return a value that can never be "advanced past",
        // forcing the conservative wall-clock-tick fallback to govern.
        0
    }
}

/// Global "a timer due-wake scan was deferred" flag.
///
/// The 100 Hz timer ISR (`wake_sleeping_threads`) is the driver that re-Readies
/// a `Sleeping`/`Blocked`-with-deadline thread once its `wake_tick` has passed.
/// It acquires `THREAD_TABLE` with `try_lock` to avoid a same-CPU re-entrant
/// deadlock against an interrupted code path that already holds the lock.  When
/// that `try_lock` fails the ISR CANNOT do the scan on this tick — but it MUST
/// NOT silently lose the due-wake: if contention persists across a sleeper's
/// deadline window, the sleeper would never be re-Readied and the run queue
/// wedges (`[SCHED/STARVE]` → `SCHEDULER_DEADLOCK`).
///
/// Instead the ISR records the deferral here.  The scan is then honoured at the
/// next opportunity by ANY context that holds `THREAD_TABLE` unconditionally —
/// principally the picker's `'pick:` loop, which already walks the table every
/// iteration and re-acquires the lock fresh after each `sti; hlt; cli`, and the
/// next uncontended timer tick.  This mirrors the deferred-timer-softirq shape:
/// the hard IRQ records that timer work is due and a context that can safely
/// take the relevant lock drains it.  Wake latency is therefore bounded to "the
/// next picker iteration or the next uncontended tick" — never "permanently
/// lost".
static RESCAN_PENDING: AtomicBool = AtomicBool::new(false);

/// Diagnostic: cumulative count of timer due-wake scans that were deferred
/// because the ISR could not acquire `THREAD_TABLE`.  Monotone; its delta over
/// a workload tells tooling how often the contended-tick path was taken.  A
/// non-zero delta is EXPECTED under contention and is NOT itself a bug — the
/// deferred scan is honoured elsewhere — but a large delta with no matching
/// `RESCAN_HONORED_TOTAL` progress would indicate the drain path is not running.
pub static RESCAN_DEFERRED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Diagnostic: cumulative count of deferred due-wake scans actually drained
/// (the flag was observed set and a scan ran).  Pairs with
/// `RESCAN_DEFERRED_TOTAL` for test-side assertions that no deferral is lost.
pub static RESCAN_HONORED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the cumulative deferred-scan count (see [`RESCAN_DEFERRED_TOTAL`]).
pub fn rescan_deferred_count() -> u64 {
    RESCAN_DEFERRED_TOTAL.load(Ordering::Relaxed)
}

/// Snapshot of the cumulative honored-scan count (see [`RESCAN_HONORED_TOTAL`]).
pub fn rescan_honored_count() -> u64 {
    RESCAN_HONORED_TOTAL.load(Ordering::Relaxed)
}

/// Cumulative count of `'pick:` retry iterations that wrapped through
/// the `sti; hlt; cli; continue 'pick` wait path because no Ready peer
/// was selectable for the current thread.
///
/// One increment per HLT wakeup: in a healthy system this counts the
/// idle-cycle taken when the CPU literally has no work and is waiting on
/// the next timer ISR or other wake source.  In a wedge — e.g. every
/// runnable thread is sleeping on the same condition that nobody is
/// firing — this counter advances rapidly and unbounded.  Together with
/// `STARVATION_BURST` it lets diagnostics report "the picker has been
/// in a sti/hlt/cli loop for N consecutive iterations on CPU X for thread
/// T".  The counter never resets except on boot, so its rate-of-change
/// is what diagnostics watch.
pub static SCHED_PICK_HLT_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Diagnostic threshold above which `schedule()` emits a `[SCHED/STARVE]`
/// line.  At TICK_HZ=100 a single `sti; hlt; cli` runs until the next
/// timer ISR (~10 ms), so 200 consecutive HLTs on one thread without a
/// successful pick corresponds to ~2 s of inability to make forward
/// progress.  The threshold is intentionally generous: short HLT runs
/// during legitimate idle (every other tick under low load) must not
/// trigger the diagnostic.
///
/// NOTE: this threshold is tuned for KVM (the default in
/// `scripts/qemu-harness.py` when `/dev/kvm` is available).  TCG runs
/// have a syscall throughput roughly an order of magnitude lower and
/// will spend proportionally more time in HLT during quiet phases —
/// expect occasional extra `[SCHED/STARVE]` lines on TCG-only hosts and
/// CI lanes that opt out of KVM with `--no-kvm`.  The line itself is
/// diagnostic only; it does not change scheduler behaviour.
const STARVATION_BURST_THRESHOLD: u32 = 200;

/// Re-emit factor for sustained-wedge heartbeats.  After the first
/// threshold crossing, [`note_picker_hlt`] returns `true` again every
/// `RESTARVE_PERIOD * STARVATION_BURST_THRESHOLD` HLT cycles so a
/// multi-minute wedge leaves a trail in the serial log rather than a
/// single line followed by silence.  At TICK_HZ=100 the default
/// (10×200 = 2000 HLTs) corresponds to a heartbeat every ~20 s of
/// sustained wedge time.
const RESTARVE_PERIOD: u64 = 10;

/// Per-CPU counter of consecutive `sti; hlt; cli; continue 'pick` cycles
/// on the same `current_tid` without a Ready peer being found.  Reset to
/// zero whenever the picker succeeds (peer found and context-switch happens)
/// or `current_tid` changes between iterations.
static STARVATION_BURST: [AtomicU64; MAX_CPUS] =
    [const { AtomicU64::new(0) }; MAX_CPUS];

/// Per-CPU `current_tid` snapshot at the most recent HLT decision.  Used to
/// detect "the burst is for THIS thread" — if the picker context-switches
/// away, the burst counter is naturally reset because subsequent waits are
/// for a different thread.
static STARVATION_LAST_TID: [AtomicU64; MAX_CPUS] =
    [const { AtomicU64::new(u64::MAX) }; MAX_CPUS];

/// Total number of times the starvation threshold has been crossed since
/// boot.  Each increment names one diagnostic emission; the counter is
/// monotone so downstream tooling can compute "did the scheduler starve
/// during the last test run?" by snapshotting before/after.
pub static SCHED_STARVATION_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the cumulative HLT count.  Useful for test-side checks that
/// the scheduler did not enter an HLT storm during a workload.
pub fn pick_hlt_count() -> u64 {
    SCHED_PICK_HLT_TOTAL.load(Ordering::Relaxed)
}

/// Most-recently-observed run-queue depth: the count of `Ready` non-idle
/// threads the picker considered on its last pass.  Published lock-free from
/// inside `schedule()` (which already iterates `THREAD_TABLE` and tests each
/// thread's state), so any caller can read an O(1) estimate of how many
/// runnable peers a yielding thread is competing against WITHOUT taking the
/// table lock itself.  This is the metric the virtio-blk wait-amplification
/// histogram correlates against (see `drivers::virtio_blk`): it is the size
/// of the field a spin-then-yield disk waiter must be re-selected out of.
///
/// "Estimate" because it is a snapshot of the last picker pass, not a fresh
/// count — but the picker runs on every quantum and every yield, so under the
/// disk-I/O workload it is at most a few ticks stale, which is exactly the
/// resolution the histogram needs.
static READY_DEPTH: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the last-observed run-queue depth (non-idle `Ready` peers).
/// O(1), lock-free.  See [`READY_DEPTH`].
pub fn ready_depth() -> u64 {
    READY_DEPTH.load(Ordering::Relaxed)
}

/// Snapshot of the cumulative starvation events.  An increment indicates
/// the picker held the same thread for `STARVATION_BURST_THRESHOLD`
/// consecutive HLT cycles without a successful pick.
pub fn starvation_count() -> u64 {
    SCHED_STARVATION_TOTAL.load(Ordering::Relaxed)
}

// ── Anti-starvation aging (run-queue wait fairness) ─────────────────────────
//
// The base picker scores a Ready peer as `priority*4 + affinity_bonus(0..2)`
// and selects the strict maximum.  With no wait-time term, a Ready thread that
// is continuously out-scored — e.g. a `PRIORITY_NORMAL` peer competing against
// a population that is repeatedly wake-boosted to `PRIORITY_NORMAL +
// PRIORITY_BOOST_WAIT` on every event-loop wakeup — can be passed over on every
// tick forever.  That is an indefinite run-queue starvation: it violates the
// POSIX `sched(7)` SCHED_OTHER expectation that every runnable thread
// eventually gets the CPU, and the practical "longest-waiting runnable task
// eventually runs" guarantee that real general-purpose schedulers provide.
//
// The fix gives each Ready thread a wait-age that the picker folds into its
// score, plus a hard force-select ceiling:
//
//   * `ready_since_tick` (per-thread) is stamped lazily by the picker the
//     first time it observes a Ready thread without a stamp, and cleared the
//     moment the thread is selected to Run.  The picker walks the whole table
//     each iteration under `THREAD_TABLE`, so a freshly-Readied thread is
//     stamped within ~1 tick of becoming runnable.
//
//   * Once a thread's wait-age reaches `STARVE_AGE_TICKS` it earns an
//     escalating score bonus — one point per `STARVE_AGE_QUANTUM` ticks beyond
//     the threshold, saturating at `STARVE_AGE_BONUS_MAX`.  The cap is sized to
//     exceed the FULL base-priority span (`PRIORITY_MAX * 4`), not merely a
//     same-base-priority wake-boost differential.  This is the central fairness
//     property: wait-time MONOTONICALLY raises selection priority until a
//     sufficiently-aged thread out-scores ANY runnable peer regardless of base
//     priority — the published "wait-time → eligibility" guarantee of a fair
//     run-queue scheduler (POSIX sched(7) SCHED_OTHER; the proportional-share /
//     virtual-deadline family of fair schedulers).  A starved thread therefore
//     climbs past a heavy higher-priority population WELL BEFORE the hard
//     force-ceiling, so the force backstop fires only in genuinely pathological
//     edge cases rather than as the routine rescue path.
//
//   * The BSP main thread (TID 0) is the kernel's latency-critical poll reactor
//     (net::poll / x11::poll / compositor::compose).  Like an interactive task
//     in a virtual-deadline scheduler it consumes very little CPU and yields
//     early every iteration, so it is owed an EARLIER deadline than the
//     compute-bound workers it competes with.  It is granted a much tighter
//     per-thread force-deadline (`STARVE_FORCE_TICKS_BSP`) so the reactor runs
//     at a healthy cadence (tens of Hz) even when the run-queue is saturated by
//     a 50+-thread userspace workload, instead of being rescued only at the
//     coarse ~1 s global ceiling.  This mirrors the latency-deadline treatment a
//     virtual-deadline fair scheduler gives an early-yielding interactive task.
//
//   * As an absolute backstop, a thread whose wait-age reaches
//     `STARVE_FORCE_TICKS` is force-selected this tick regardless of score
//     (the oldest such thread wins, mirroring an NT balance-set-manager
//     force-boost / a fair-scheduler eligibility deadline).  This bounds
//     worst-case run-queue latency even against a pathological mix of
//     priorities.  With the widened monotone aging above it is now a true
//     last-resort safety net, not the routine rescue mechanism.
//
// All terms are inert in the common case: a thread that runs within
// `STARVE_AGE_TICKS` of becoming Ready never accrues any bonus, so quiet or
// lightly-loaded systems keep their existing priority ordering exactly.

/// Run-queue wait-age (in 100 Hz ticks) at which a Ready thread begins to earn
/// an anti-starvation score bonus.  20 ticks ≈ 200 ms — long enough that a
/// thread scheduled in the normal course of events never accrues a bonus, short
/// enough that a genuinely out-scored thread starts climbing well before a user
/// would perceive a stall.
const STARVE_AGE_TICKS: u64 = 20;

/// Ticks of additional wait per +1 of escalating wait-age bonus once past
/// `STARVE_AGE_TICKS`.  At 2 ticks (≈20 ms) per point the bonus climbs one step
/// every ~20 ms of continued starvation.  This slope is deliberately steep: a
/// run-queue-starved thread must climb the FULL base-priority span (see
/// `STARVE_AGE_BONUS_MAX`) and overtake a heavy higher-priority population
/// *before* the hard force-ceiling, so the score-based aging — not the backstop
/// — is what rescues it.  A worker out-scored by a wake-boosted peer (needing
/// ~11 bonus points) wins at age ≈ 40 ticks — well before the ~100-tick global
/// ceiling.  (The `PRIORITY_IDLE` BSP reactor's deficit is far larger, so it
/// climbs the full span only after ~100 ticks; that is why the reactor is
/// primarily rescued by its tighter per-thread deadline, not by this score
/// path — see `STARVE_FORCE_TICKS_BSP`.)
const STARVE_AGE_QUANTUM: u64 = 2;

/// Maximum wait-age score bonus.  Sized to exceed the FULL base-priority span,
/// not merely a same-base-priority wake-boost differential: `PRIORITY_MAX * 4 =
/// 124` is the largest possible base score gap between two threads, and `+4`
/// covers the affinity-bonus headroom (a competitor's +2 plus our own deficit).
/// At 128 a fully-aged Ready thread is guaranteed to out-score ANY runnable peer
/// regardless of base priority — the monotone "wait-time → eligibility"
/// guarantee.  This bounds every thread's worst-case score-path latency even a
/// `PRIORITY_IDLE` thread (TID 0, base score ≈ 0..2) eventually out-scores a
/// saturated `PRIORITY_NORMAL`+ population rather than relying solely on the
/// force backstop — though for the BSP reactor specifically the tighter
/// `STARVE_FORCE_TICKS_BSP` deadline rescues it first (its full-span climb takes
/// ~100 ticks).  Cf. POSIX sched(7) (SCHED_OTHER: every runnable thread
/// eventually runs).
const STARVE_AGE_BONUS_MAX: u16 = 128;

/// Hard ceiling: a Ready thread that has waited this many ticks (≈1 s) is
/// force-selected on the current CPU regardless of score, bypassing the normal
/// strict-max comparison.  This is the absolute anti-starvation guarantee that
/// bounds worst-case run-queue latency independent of any priority arithmetic.
/// With the widened monotone aging above, the score-based path almost always
/// rescues a starved thread first, so this backstop is now a true last-resort
/// safety net rather than the routine rescue mechanism.
const STARVE_FORCE_TICKS: u64 = 100;

/// Tighter force-deadline for the BSP main thread (TID 0) only — the kernel's
/// latency-critical poll reactor (net::poll / x11::poll / compositor::compose).
/// Like an interactive task in a virtual-deadline fair scheduler, TID 0 spends
/// almost no CPU and yields early every iteration, so it is owed a much earlier
/// deadline than the compute-bound workers it competes with.  At TICK_HZ = 100,
/// 1 tick (≈10 ms) bounds the reactor's worst-case run-queue latency at the
/// finest granularity the periodic timer can resolve — every scheduler tick the
/// reactor is at or past deadline, so it is force-selected at the next
/// preemption point regardless of how many userspace threads are runnable.
///
/// Why 1 and not 2 (single-core Firefox-load measurement, 2026-06-30): under a
/// ~100-thread windowed-Firefox load the reactor's measured service rate was
/// only ~20-30 Hz, not the 50 Hz a 2-tick deadline nominally allows — roughly
/// half of each re-selection period is dead time (the reactor's post-yield idle
/// `hlt` waits out the remainder of a tick, and ~10 userspace threads are
/// continuously Ready and out-score the `PRIORITY_IDLE` reactor on every normal
/// pick, so it advances only via this force backstop).  A 1-tick deadline lifts
/// the force ceiling to the 100 Hz periodic-timer limit, roughly doubling the
/// reactor's worst-case wakeup rate so it drains net::poll / services the
/// in-kernel X server / pumps the event loop about twice as often, which is the
/// single-core analogue of the dedicated execution context a second CPU gives
/// the reactor.  The reactor early-yields every iteration and the compositor
/// self-throttles at `COMPOSE_MIN_INTERVAL_TICKS = 2` (≈50 Hz), so the extra
/// (odd-tick) forced runs that find no owed frame are cheap skips (see
/// `compose_if_due` / `COMPOSE_SKIPPED`): the higher cadence buys more net/X
/// service WITHOUT handing TID 0 a larger share of the vCPU and WITHOUT raising
/// the present rate above the compositor's own ceiling.  The score-based aging
/// usually selects TID 0 even sooner; this deadline bounds the reactor's
/// worst-case latency well below the coarse `STARVE_FORCE_TICKS` global ceiling.
/// (Cite POSIX sched(7): every runnable thread eventually runs; an early-yielding
/// latency-sensitive task is owed an earlier virtual deadline than compute-bound
/// peers — the proportional-share / virtual-deadline fair-scheduler family.)
const STARVE_FORCE_TICKS_BSP: u64 = 1;

/// Throttle factor for the `[SCHED/STARVE] force-select` diagnostic: the line
/// is emitted on the first force and then once per this many force-selects.
/// The monotone `SCHED_STARVE_FORCE_TOTAL` counter is unaffected and remains
/// the authoritative rate source.  64 keeps a steady-but-quiet trail under a
/// ~1 Hz re-starve without flooding a multi-minute soak log.
const STARVE_FORCE_LOG_EVERY: u64 = 64;

/// Cumulative count of force-selects performed by the anti-starvation backstop
/// (`STARVE_FORCE_TICKS` reached).  A non-zero value means at least one Ready
/// thread was rescued from indefinite starvation; the test suite snapshots this
/// to assert the backstop fired.  Monotone since boot.
pub static SCHED_STARVE_FORCE_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Snapshot of [`SCHED_STARVE_FORCE_TOTAL`].
pub fn starve_force_count() -> u64 {
    SCHED_STARVE_FORCE_TOTAL.load(Ordering::Relaxed)
}

/// The BSP poll-reactor (TID 0) force-deadline in 100 Hz ticks.  Exposed for
/// the scheduler regression test to assert the latency guarantee without
/// reaching into the private constant.
pub fn bsp_force_deadline_ticks() -> u64 {
    STARVE_FORCE_TICKS_BSP
}

/// The global last-resort force-deadline in 100 Hz ticks (applies to
/// compute-bound worker threads).  Exposed for the scheduler regression test.
pub fn global_force_deadline_ticks() -> u64 {
    STARVE_FORCE_TICKS
}

/// The anti-starvation force-deadline (in 100 Hz ticks) for a thread with the
/// given TID: the tighter `STARVE_FORCE_TICKS_BSP` for the BSP poll reactor
/// (TID 0), the coarse `STARVE_FORCE_TICKS` for every other thread.  Single
/// source of truth for the per-TID deadline so the picker's per-candidate force
/// scan and the per-runqueue `min_deadline` gate (`sched::percpu`) cannot drift.
#[inline]
pub(crate) fn force_deadline_for_tid(tid: proc::Tid) -> u64 {
    if tid == 0 { STARVE_FORCE_TICKS_BSP } else { STARVE_FORCE_TICKS }
}

/// Pure helper: the anti-starvation score bonus for a Ready thread that has
/// been waiting `age` ticks (`age = now - ready_since_tick`, saturating).
///
/// Returns 0 below `STARVE_AGE_TICKS`; thereafter one point per
/// `STARVE_AGE_QUANTUM` ticks of further wait, saturating at
/// `STARVE_AGE_BONUS_MAX`.  Extracted as a free function so the scheduler
/// regression test can assert the escalation/cap curve without spinning real
/// threads.
#[inline]
pub fn wait_age_bonus(age: u64) -> u16 {
    if age < STARVE_AGE_TICKS {
        return 0;
    }
    let steps = (age - STARVE_AGE_TICKS) / STARVE_AGE_QUANTUM + 1;
    (steps.min(STARVE_AGE_BONUS_MAX as u64)) as u16
}

/// Internal: record one HLT decision for the given `current_tid` on this
/// CPU.  Returns `true` if the per-thread burst has just crossed the
/// starvation threshold (or a subsequent re-emit boundary — see
/// [`RESTARVE_PERIOD`]) so the caller should emit the diagnostic;
/// `false` otherwise.  Always bumps the cumulative `SCHED_PICK_HLT_TOTAL`.
///
/// A sustained wedge produces a heartbeat trail: the first crossing at
/// `STARVATION_BURST_THRESHOLD`, then one re-emit every
/// `RESTARVE_PERIOD * STARVATION_BURST_THRESHOLD` HLT cycles thereafter.
/// `SCHED_STARVATION_TOTAL` is bumped on every emit, so downstream
/// tooling can compute "the scheduler was wedged for N×period HLT cycles"
/// from the delta alone.
#[inline]
fn note_picker_hlt(current_tid: u64) -> bool {
    SCHED_PICK_HLT_TOTAL.fetch_add(1, Ordering::Relaxed);
    let cpu = cpu_index();
    if cpu >= MAX_CPUS {
        return false;
    }
    let prev_tid = STARVATION_LAST_TID[cpu].load(Ordering::Relaxed);
    if prev_tid != current_tid {
        STARVATION_LAST_TID[cpu].store(current_tid, Ordering::Relaxed);
        STARVATION_BURST[cpu].store(1, Ordering::Relaxed);
        return false;
    }
    let new_burst = STARVATION_BURST[cpu].fetch_add(1, Ordering::Relaxed) + 1;
    let threshold = STARVATION_BURST_THRESHOLD as u64;
    // Initial crossing: new_burst == threshold.
    // Subsequent heartbeats: new_burst == threshold * (1 + k*RESTARVE_PERIOD)
    //                       for k = 1, 2, 3, ...
    //   ↳ equivalent to:  new_burst > threshold
    //                  && (new_burst - threshold) % (threshold * RESTARVE_PERIOD) == 0
    let crossed_initial = new_burst == threshold;
    let crossed_heartbeat = new_burst > threshold
        && (new_burst - threshold) % (threshold * RESTARVE_PERIOD) == 0;
    if crossed_initial || crossed_heartbeat {
        SCHED_STARVATION_TOTAL.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

/// Internal: clear the per-CPU starvation burst (called when the picker
/// succeeds, so legitimate idle on a quiet system does not leave stale
/// burst state that conflates with a later wedge).
#[inline]
fn clear_picker_burst() {
    let cpu = cpu_index();
    if cpu < MAX_CPUS {
        STARVATION_BURST[cpu].store(0, Ordering::Relaxed);
        STARVATION_LAST_TID[cpu].store(u64::MAX, Ordering::Relaxed);
    }
}

use crate::arch::x86_64::apic::cpu_index;

/// Initialize CoreSched.
pub fn init() {
    SCHEDULER_ACTIVE.store(false, Ordering::Relaxed);
    for i in 0..MAX_CPUS {
        TICKS_REMAINING[i].store(TIME_SLICE, Ordering::Relaxed);
        NEED_RESCHEDULE[i].store(false, Ordering::Relaxed);
    }
    crate::serial_println!("[CoreSched] Scheduler initialized (per-CPU round-robin, quantum={} ticks)", TIME_SLICE);
}

/// Enable the scheduler.
pub fn enable() {
    SCHEDULER_ACTIVE.store(true, Ordering::Relaxed);
    crate::serial_println!("[CoreSched] Scheduler enabled");
}

/// Disable the scheduler.
pub fn disable() {
    SCHEDULER_ACTIVE.store(false, Ordering::Relaxed);
}

/// Check if the scheduler is active.
pub fn is_active() -> bool {
    SCHEDULER_ACTIVE.load(Ordering::Relaxed)
}

/// Called from the timer interrupt handler.
/// Decrements the time slice counter and sets the reschedule flag when expired.
/// Also decays boosted thread priorities towards their base values.
pub fn timer_tick_schedule() {
    if !is_active() {
        return;
    }

    // Wake sleeping threads and handle blocked timeouts.
    // Use try_lock to avoid deadlock: if THREAD_TABLE is held by
    // the interrupted code path, skip this tick.
    wake_sleeping_threads();

    // NOTE: Dead-thread reaping (freeing kernel stacks via pmm::free_page)
    // is intentionally NOT done here.  pmm::free_page acquires PMM_LOCK.
    // If the interrupted code already holds PMM_LOCK (e.g. free_process_memory),
    // the ISR would spin on PMM_LOCK forever — a same-CPU re-entrant deadlock.
    // Reaping is instead done at the start of schedule() where interrupts are
    // already disabled and no ISR can fire to cause this race.

    let cpu = cpu_index();
    let remaining = TICKS_REMAINING[cpu].load(Ordering::Relaxed);
    if remaining <= 1 {
        NEED_RESCHEDULE[cpu].store(true, Ordering::Relaxed);
        TICKS_REMAINING[cpu].store(TIME_SLICE, Ordering::Relaxed);
    } else {
        TICKS_REMAINING[cpu].store(remaining - 1, Ordering::Relaxed);
    }
}

/// Perform one due-wake pass over an already-locked thread table.
///
/// Re-Readies every `Sleeping` thread whose `wake_tick` deadline has passed and
/// every `Blocked`-with-deadline thread whose timeout has expired.  This is the
/// pure, lock-in-hand core shared by both the timer-ISR path
/// (`wake_sleeping_threads`) and the deferred drain (`drain_due_wakes_if_pending`):
/// keeping it in one place guarantees the two callers can never diverge on which
/// states/deadlines count as "due".
///
/// The caller MUST already hold `THREAD_TABLE`.  `now` is the current
/// `TICK_COUNT` (monotone); pass the value read by the caller so a single tick
/// snapshot drives the whole pass.  Returns the number of threads flipped to
/// `Ready` (diagnostic only).
#[inline]
fn due_wake_scan(threads: &mut alloc::vec::Vec<proc::Thread>, now: u64) -> u32 {
    let mut woken = 0u32;
    for t in threads.iter_mut() {
        if t.state == ThreadState::Sleeping && now >= t.wake_tick {
            t.state = ThreadState::Ready;
            woken += 1;
        }
        // Wake blocked threads whose timeout has expired.
        // The thread will resume in wait_for_single_object / wait_for_multiple_objects,
        // discover that its WaitBlock was NOT satisfied, and return Timeout.
        if t.state == ThreadState::Blocked && t.wake_tick != u64::MAX && now >= t.wake_tick {
            t.state = ThreadState::Ready;
            woken += 1;
        }
    }
    woken
}

/// Wake any threads whose sleep time has elapsed (timer-ISR path).
/// Also wakes blocked threads whose wait timeout has expired.
///
/// Uses `try_lock` because this runs in the timer ISR: if the interrupted code
/// path on THIS CPU already holds `THREAD_TABLE`, blocking here would be a
/// same-CPU re-entrant deadlock.  The original code returned silently on a
/// `try_lock` miss — which PERMANENTLY DROPPED the due-wake for that tick.  If
/// contention persisted across a sleeper's deadline window the sleeper was
/// never re-Readied and the run queue wedged (`[SCHED/STARVE]` →
/// `SCHEDULER_DEADLOCK`).
///
/// The fix: a `try_lock` miss now records the deferral in [`RESCAN_PENDING`]
/// instead of dropping it.  The deferred scan is honoured at the next
/// opportunity by [`drain_due_wakes_if_pending`] (called from the picker's
/// lock-held window and from the next uncontended tick), so no due-wake is ever
/// permanently lost — the bound is the next picker iteration or the next
/// uncontended tick, not "never".  We never block in the ISR, preserving the
/// original deadlock-avoidance property.
fn wake_sleeping_threads() {
    let now = crate::arch::x86_64::irq::get_ticks();
    let mut threads = match THREAD_TABLE.try_lock() {
        Some(guard) => guard,
        None => {
            // Lock held by interrupted code — cannot scan now.  Record the
            // deferral so a context that CAN take the lock drains it; do NOT
            // silently drop the due-wake.
            RESCAN_PENDING.store(true, Ordering::SeqCst);
            RESCAN_DEFERRED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    // We hold the lock: this tick's scan is authoritative.  Clear any pending
    // deferral first so a deferral set on a PRIOR contended tick is also
    // satisfied by this pass (this scan sees the same or newer `now`, so it
    // covers every deadline the deferred scan would have).
    if RESCAN_PENDING.swap(false, Ordering::SeqCst) {
        RESCAN_HONORED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    due_wake_scan(&mut threads, now);
}

/// Drain a deferred due-wake scan if one is pending, with the caller already
/// holding `THREAD_TABLE`.
///
/// This is the deferred-softirq drain side of the [`RESCAN_PENDING`] protocol.
/// It is called from contexts that hold `THREAD_TABLE` UNCONDITIONALLY (not via
/// `try_lock`) and can therefore safely complete a scan the timer ISR had to
/// defer — principally the picker's `'pick:` loop, which re-acquires the lock
/// fresh on every iteration after each `sti; hlt; cli`.  Because the picker is
/// exactly the code path that runs while a thread is wedged waiting to be
/// re-Readied, folding the drain in here makes the wedged path SELF-HEAL: the
/// sleeper whose deadline passed during the contention window is re-Readied by
/// the very picker iteration that is looking for a Ready peer, even if the timer
/// ISR keeps missing its `try_lock`.
///
/// Cheap fast path: a single relaxed load when no deferral is pending (the
/// common case), so this adds negligible cost to the picker hot loop.  The
/// `swap` only runs on the rare tick where a deferral was actually recorded.
///
/// SAFETY / SMP: the caller holds `THREAD_TABLE`, so the table mutation is
/// serialised exactly as the ISR's own scan would be.  Clearing the flag with a
/// `swap` is race-free against a concurrent ISR set on another CPU: if the ISR
/// sets the flag AFTER our `swap` reads `true`, that set survives and the next
/// drain (or uncontended tick) honours it — the worst case is one extra
/// redundant scan, never a lost wake.
#[inline]
fn drain_due_wakes_if_pending(threads: &mut alloc::vec::Vec<proc::Thread>) {
    if !RESCAN_PENDING.load(Ordering::Relaxed) {
        return;
    }
    if RESCAN_PENDING.swap(false, Ordering::SeqCst) {
        RESCAN_HONORED_TOTAL.fetch_add(1, Ordering::Relaxed);
        let now = crate::arch::x86_64::irq::get_ticks();
        due_wake_scan(threads, now);
    }
}


/// Request that the calling CPU reschedule at its next preemption point.
///
/// Sets the per-CPU `NEED_RESCHEDULE` flag so that the deferred-preemption
/// check at syscall return (`check_reschedule`) — and the post-IRQ check —
/// will invoke `schedule()` and re-select the highest-priority Ready thread.
///
/// This is the AstryxOS analogue of `resched_curr()`: a wakeup path that has
/// just made a higher-priority thread runnable uses it to let that thread
/// preempt the current (lower-priority) thread, rather than waiting out the
/// running thread's whole time slice. Cheap and lock-free; the actual switch
/// happens later at a safe point where no syscall lock is held.
#[inline]
pub fn request_reschedule() {
    if !is_active() {
        return;
    }
    let cpu = cpu_index();
    if cpu < MAX_CPUS {
        NEED_RESCHEDULE[cpu].store(true, Ordering::Relaxed);
    }
}

/// Non-consuming peek at this CPU's pending-preemption flag.
///
/// The timer ISR sets `NEED_RESCHEDULE` at each quantum boundary
/// (`timer_tick_schedule`), but a long-running Ring-0 path is never preempted
/// — the timer stub calls `check_reschedule()` only when it interrupted user
/// mode (see the kernel-mode skip in the timer ISR).  A cooperative kernel loop
/// that wants to be a good scheduling citizen can poll this and voluntarily
/// `schedule()` when it returns `true`, the AstryxOS analogue of Linux's
/// `cond_resched()` / `need_resched()` (kernel/sched/core.c): yield the CPU at a
/// safe point when the scheduler has decided this thread's quantum is up, rather
/// than monopolising the core across the whole operation.  Unlike
/// `check_reschedule`, this does NOT clear the flag (the eventual `schedule()`
/// clears it) and does NOT itself switch — it is a cheap relaxed read.
#[inline]
pub fn reschedule_pending() -> bool {
    if !is_active() {
        return false;
    }
    let cpu = cpu_index();
    cpu < MAX_CPUS && NEED_RESCHEDULE[cpu].load(Ordering::Relaxed)
}

/// Check if a reschedule is pending (called after returning from interrupt).
///
/// Returns immediately if the scheduler is not yet active — this avoids
/// calling `cpu_index()` (which reads `IA32_TSC_AUX` via `rdmsr`) before
/// `syscall::init()` has initialised that MSR on the BSP.
pub fn check_reschedule() {
    if !is_active() {
        return;
    }
    let cpu = cpu_index();
    if NEED_RESCHEDULE[cpu].swap(false, Ordering::Relaxed) {
        schedule();
    }
}

/// True if some thread in `threads` (other than `excluding_tid`) has a saved
/// kernel RSP (`context.rsp`) that falls within `[base, base + size)`.
///
/// This is the saved-RSP analogue of `proc::is_tid_current_on_any_cpu` (the
/// #653 per-CPU running-TID survey): it answers "does a live thread's *saved*
/// switch-context frame still live in this kstack span?", which is the
/// invariant a kstack frame must satisfy as FALSE before the frame may be
/// freed or recycled.  A parked thread's `context.rsp` points at its saved
/// `switch_context_asm` frame (the `pushfq` slot at `context.rsp + 0`); if a
/// freed/recycled frame aliases that span, a zero-fill or a re-issue tears the
/// parked thread's saved RFLAGS slot, and its later `popfq` faults
/// (kernel-mode `#DB`, `UNEXPECTED_KERNEL_MODE_TRAP` 0x7f).  Folded into the
/// reaper's existing THREAD_TABLE scan, so it adds no asymptotic cost.
///
/// `excluding_tid` is the owner being reaped — its own saved RSP necessarily
/// lies in its own kstack and must not self-defer the free.
fn saved_rsp_aliases_live_frame(
    threads: &[crate::proc::Thread],
    base: u64,
    size: u64,
    excluding_tid: crate::proc::Tid,
) -> bool {
    let end = base.wrapping_add(size);
    threads.iter().any(|t| {
        t.tid != excluding_tid
            && t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire)
            && {
                let rsp = t.context.rsp;
                rsp >= base && rsp < end
            }
    })
}

/// Reap dead threads and free their kernel stacks.
///
/// Observability counter: number of Dead threads whose kstack reclaim the
/// reaper DEFERRED specifically because they were still physically on a CPU's
/// kernel stack (the switch-OUT window the on-stack half of the union gate
/// closes — a deferral the current-CPU gate alone would not have made).  A
/// non-zero value confirms the deferral path fired.  Read via
/// [`kstack_reclaim_deferred`].
static KSTACK_RECLAIM_DEFERRED: AtomicU64 = AtomicU64::new(0);

/// Read the kstack-reclaim defer counter (see [`KSTACK_RECLAIM_DEFERRED`]).
pub fn kstack_reclaim_deferred() -> u64 {
    KSTACK_RECLAIM_DEFERRED.load(Ordering::Relaxed)
}

/// MUST be called with interrupts already disabled so that pmm::free_page()
/// cannot deadlock with a concurrent timer ISR that also acquires PMM_LOCK.
/// Called at the start of schedule() which guarantees IF=0 via disable_interrupts().
fn reap_dead_threads_sched() {
    use crate::proc::KERNEL_VIRT_OFFSET;

    // First, drain any previously-quarantined emergency-tier frees whose
    // quiescence + saved-RSP gates have since cleared.  Doing this at the top
    // of every reaper pass bounds the quarantine and reclaims memory promptly
    // once a frame is provably no longer referenced.  Safe under the reaper's
    // IF=0 contract (takes its own short THREAD_TABLE + quarantine locks,
    // releases before PMM ops).
    //
    // Throttled to at most once per `TICK_COUNT` advance: the survey is
    // O(entries × live-threads) and its eligibility gates are wall-clock based
    // (minimum 2 ticks, see `entry_is_quiesced`), so re-running it within a
    // single tick reclaims nothing while still paying the full scan on every
    // schedule.  Gating it to per-tick bounds the reaper cost and prevents the
    // near-full-quarantine survey from starving cooperative kernel threads,
    // without changing which frames are freed or when.  See
    // `LAST_KSTACK_DRAIN_TICK`.
    {
        let now = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
        if kstack_drain_due(&LAST_KSTACK_DRAIN_TICK, now) {
            drain_pending_kstack_free();
        }
    }

    // IMPORTANT: Never reap the CURRENT thread. The caller is still running on
    // its kernel stack — freeing the stack while executing on it is a UAF.
    // The current thread will be reaped the next time a DIFFERENT thread calls
    // schedule() and runs this function (with a different current_tid).
    let current_tid = crate::proc::current_tid();

    // Collect (stack_base, stack_pages, last_cpu, aliased) for each reapable
    // thread, removing them from THREAD_TABLE in the same pass.  `last_cpu`
    // feeds the per-CPU switch-generation quiescence gate (see
    // `CPU_SWITCH_GEN`); `aliased` is the saved-RSP survey result (computed
    // after all removals, against the survivors) — see
    // `saved_rsp_aliases_live_frame`.
    let stacks = {
        let mut threads = THREAD_TABLE.lock();
        // A Dead thread is safe to reap only when ctx_rsp_valid == true, which
        // switch_context_asm sets AFTER saving the thread's RSP (meaning the CPU
        // has left or is about to leave the thread's kernel stack).  Exit paths
        // (exit_thread/exit_group) set ctx_rsp_valid=false before calling schedule(),
        // preventing the AP from freeing the stack while the BSP is still on it.
        //
        // CROSS-CPU GUARD (SMP=2 exit_group race): `current_tid` only names the
        // thread running on THIS CPU.  `exit_group_inner` marks every sibling of
        // the dying group Dead out-of-band (proc/mod.rs) while a sibling may be
        // mid-syscall and physically executing on ANOTHER CPU.  Such a sibling
        // still has ctx_rsp_valid == true (it was set true when the sibling was
        // switched IN, not when it switched out), so the ctx_rsp_valid gate alone
        // does NOT exclude it.  Reaping it would push its kernel stack to the
        // dead-stack cache (which zero-fills the stack) or free it to the PMM
        // while that stack is live on the other CPU.
        //
        // A thread's kernel stack must not be reclaimed until the thread is
        // provably off it on EVERY CPU.  Two surveys are required because the
        // scheduler's two publish points straddle the actual stack switch:
        //   * `is_tid_current_on_any_cpu` reads `PER_CPU_CURRENT_TID`, which the
        //     scheduler sets to the INCOMING thread BEFORE `switch_context_asm`.
        //     It covers the switch-IN window: a thread just made Running/current
        //     on another CPU, then marked Dead in-flight by a sibling's
        //     exit_group BEFORE its successor runs and BEFORE it starts executing
        //     — still about to run on its stack.
        //   * `is_tid_on_stack_any_cpu` reads `PER_CPU_ONSTACK_TID`, which the
        //     SUCCESSOR publishes AFTER `switch_context_asm` has flipped the
        //     stack.  It covers the switch-OUT window: a Dead outgoing thread no
        //     longer named current, with `ctx_rsp_valid` already set by
        //     `switch_context_asm` (set BEFORE the `mov rsp` that leaves the old
        //     stack), still physically on its stack.
        // Gating on EITHER predicate alone leaves the OTHER window open — reaping
        // a still-on-stack thread lets `push_dead_stack` zero-fill a live frame
        // while a CPU's `switch_context_asm` is restoring it, so its `ret`/`iretq`
        // loads a torn/zeroed slot (KERNEL_PAGE_FAULT).  Gate on the UNION: reap a
        // Dead thread only when it is NEITHER current NOR on-stack on any CPU —
        // i.e. no CPU is executing on (or about to execute on) it, the POSIX
        // clone(2) "no CPU references the thread" lifecycle contract.  Strictly
        // more conservative and leak-free: a genuinely off-stack Dead thread has
        // current=false AND on_stack=false, so it is still reaped promptly.
        let dead_indices: alloc::vec::Vec<usize> = threads.iter().enumerate()
            .filter(|(_, t)| {
                t.is_reapable()
                    && t.tid != current_tid
                    && !crate::proc::is_tid_current_on_any_cpu(t.tid)
                    && !crate::proc::is_tid_on_stack_any_cpu(t.tid)
                    && t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire)
            })
            .map(|(i, _)| i)
            .collect();
        // Observability: count Dead threads this pass that satisfy the
        // current-CPU gate (`!is_tid_current_on_any_cpu`) but that the on-stack
        // half of the union DEFERS because they are still physically on a CPU's
        // kernel stack (the switch-OUT window this hardening newly closes).  A
        // non-zero count means the deferral fired.  Cheap (only walks threads the
        // current-CPU gate would have admitted); does not change which threads
        // are reaped.
        {
            let deferred = threads.iter().filter(|t| {
                t.is_reapable()
                    && t.tid != current_tid
                    && !crate::proc::is_tid_current_on_any_cpu(t.tid)
                    && t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire)
                    && crate::proc::is_tid_on_stack_any_cpu(t.tid)
            }).count() as u64;
            if deferred > 0 {
                let n = KSTACK_RECLAIM_DEFERRED.fetch_add(deferred, Ordering::Relaxed)
                    + deferred;
                if n <= 16 || n % 256 < deferred {
                    crate::serial_println!(
                        "[KSTACK/RECLAIM] reaper deferred {} Dead-but-on-stack thread(s) \
                         (still on a CPU's kstack) total_deferred={}",
                        deferred, n,
                    );
                }
            }
        }
        if dead_indices.is_empty() {
            return;
        }
        // Pass 1: remove the reapable threads, capturing each frame's
        // (base, size, last_cpu, tid).  We must remove ALL of them BEFORE the
        // saved-RSP survey so a sibling reaped in the same batch does not count
        // itself (or another batch member) as a "live aliaser".
        let mut removed: alloc::vec::Vec<(u64, u64, usize, crate::proc::Tid)> =
            alloc::vec::Vec::with_capacity(dead_indices.len());
        for &idx in dead_indices.iter().rev() {
            let t = &threads[idx];
            let base = t.kernel_stack_base;
            let size = if t.kernel_stack_size > 0 { t.kernel_stack_size } else { 0 };
            let last_cpu = t.last_cpu as usize;
            let reaped_tid = t.tid;
            // #582 diagnostic: disarm the RFLAGS-slot write-watch if it
            // currently belongs to the thread being reaped.  The watch was
            // previously disarmed only on RESUME (the owner becoming
            // `next_tid`); a thread that dies while parked never resumes, so
            // its watch would persist with a now-dead owner_tid — turning a
            // recycle of that frame into a misleading "foreign" catch.  After
            // this, a [582/CATCH] can only fire on a still-resumable owner =
            // a real tear.  `d582_disarm_if_tid` is lock-free (no IPI; lazy
            // cross-CPU gen-sync) and safe under THREAD_TABLE with IF=0.
            #[cfg(feature = "582-diag")]
            crate::arch::x86_64::debug_reg::d582_disarm_if_tid(reaped_tid as u64);
            // Drop any still-mirrored entry from the per-CPU runqueues before
            // the record disappears (Perf P2 phase 2a — see
            // `percpu::mirror_forget`).  This reaper runs at the top of
            // schedule(), BEFORE mirror_maintain in the same pass, so without
            // this a thread mirrored on a prior pass would strand its tid.
            percpu::mirror_forget(t.mirror_slot, t.tid);
            threads.swap_remove(idx);
            if base > 0 && size > 0 {
                removed.push((base, size, last_cpu, reaped_tid));
            }
        }
        // Pass 2: survey the survivors for each removed frame.  `aliased=true`
        // means some still-live thread's saved RSP points into this frame's
        // span — it MUST NOT be cached/freed yet (the #582 tear root); route it
        // to the gated quarantine instead.  `excluding_tid` is the frame's own
        // (now-removed) owner, which is harmless to pass (it is gone from the
        // table) but keeps intent explicit.
        let mut out: alloc::vec::Vec<(u64, usize, usize, bool)> =
            alloc::vec::Vec::with_capacity(removed.len());
        for (base, size, last_cpu, reaped_tid) in removed {
            let aliased = saved_rsp_aliases_live_frame(&threads, base, size, reaped_tid);
            let pages = ((size + 4095) / 4096) as usize;
            out.push((base, pages, last_cpu, aliased));
        }
        out
    }; // THREAD_TABLE released before any PMM operations

    // Return kernel stacks to the dead-stack cache for reuse (NT pattern:
    // MmDeadStackSListHead).  Only cache stacks of the standard size —
    // shorter emergency-tier fallbacks (16 KiB / 8 KiB / 4 KiB; see
    // `proc::alloc_kernel_stack::SMALL_KSTACK_TIERS`) go straight back
    // to PMM so the cache never has to bound a partial zero-fill into
    // unrelated higher-half mappings.
    //
    // The push carries the honest byte-extent of the dead Thread's
    // kernel stack (`stack_pages * 0x1000`) so that
    // `push_dead_stack`'s bulk zero-fill is strictly bounded to the
    // entry's allocation — see `CachedDeadStack` and
    // `push_dead_stack`'s doc-comments for the PR #399
    // STACK_CANARY_CORRUPT closure rationale.  Overflow (cache full,
    // or push rejected by the defensive size check) falls through to
    // per-page PMM free as before.
    for (stack_base, stack_pages, last_cpu, aliased) in stacks {
        let stack_size_bytes = (stack_pages as u64) * 0x1000;
        // Standard-size frame with no live saved-RSP aliasing it → dead-stack
        // cache (its own quiescence gate governs re-issue).  An ALIASED frame
        // — even a standard-size one — must NOT enter the cache: a live
        // thread's saved switch_context frame still lives in this span, and
        // `push_dead_stack` would zero-fill it (the #582 tear).  Route any
        // aliased frame to the gated quarantine instead.
        if !aliased && stack_pages == crate::proc::KERNEL_STACK_PAGES_PUB {
            if push_dead_stack(stack_base, stack_size_bytes, last_cpu) {
                #[cfg(feature = "test-mode")]
                {
                    let len = DEAD_STACK_CACHE.lock().len();
                    crate::serial_println!(
                        "[KSTACK/REAP] pushed base={:#x} to cache (len={})",
                        stack_base, len);
                }
                continue; // cached for reuse
            }
        }
        // Emergency-tier (sub-256 KiB), cache-overflow, OR aliased frame:
        // quarantine for a GATED PMM free instead of freeing immediately.
        // This closes the #582 root — an emergency-tier frame freed straight
        // to the PMM while a parked thread's saved switch_context frame still
        // lives in its span (its own in-flight switch epilogue, or a PMM
        // double-alloc aliasing a live frame) gets re-allocated + zero-filled,
        // tearing the parked owner's saved RFLAGS slot → its `popfq` faults.
        if quarantine_kstack_free(stack_base, stack_size_bytes, last_cpu) {
            #[cfg(feature = "test-mode")]
            crate::serial_println!(
                "[KSTACK/REAP] quarantined base={:#x} size={} aliased={} (gated PMM free)",
                stack_base, stack_size_bytes, aliased as u8);
            continue;
        }
        // Quarantine full (pathological) — fall back to an immediate PMM free.
        // This is the pre-fix behaviour and re-opens the residual race only in
        // the rare full-quarantine case; preferred over leaking the frame.
        #[cfg(feature = "test-mode")]
        crate::serial_println!(
            "[KSTACK/REAP] quarantine FULL — immediate PMM free base={:#x} size={}",
            stack_base, stack_size_bytes);
        let phys_base = if stack_base >= KERNEL_VIRT_OFFSET {
            stack_base - KERNEL_VIRT_OFFSET
        } else {
            stack_base
        };
        for p in 0..stack_pages {
            crate::mm::pmm::free_page(phys_base + (p as u64) * 0x1000);
        }
    }
}

// ── Dead Stack Cache (NT-inspired MmDeadStackSListHead) ──────────────────────
//
// Reaped kernel stacks are kept in a small pool instead of being freed to the
// PMM.  New threads pull from this pool first, avoiding page allocator overhead
// and TLB shootdowns.  The cache stores higher-half virtual base addresses.

/// Maximum cached dead stacks. Increased for Firefox (many threads + PMM fragmentation).
const MAX_DEAD_STACKS: usize = 64;

/// Quiescence margin: a cached kstack is eligible for re-issue only after
/// the global `TICK_COUNT` has advanced by at least this many ticks since
/// the push.  N=2 gives a 20 ms wall-clock window at TICK_HZ=100 — longer
/// than any in-flight `switch_context_asm` call (x86-64 context switches
/// take microseconds, not milliseconds) but negligible against thread-
/// creation cost.
///
/// `TICK_COUNT` is TSC-derived and advances at wall-clock rate regardless
/// of which CPU fires the timer ISR (any CPU that wins the CAS publishes
/// the new value).  This replaces a previous per-CPU
/// `TIMER_ISR_PER_CPU[i]` scheme that could deadlock if a single CPU's
/// LAPIC timer stopped delivering interrupts — causing its per-CPU counter
/// to freeze and all cache entries to remain permanently unquiesced.
const DEAD_STACK_QUIESCE_TICKS: u64 = 2;

// ── #582 cache-push provenance shadow ────────────────────────────────────────
//
// Records, per dead-stack-cache push, the (push_tick, pusher_tid) for the
// pushed frame, keyed by physical frame number.  Lets the alloc-side alias
// guard answer "who put this frame into the cache?" when a cache-pop returns a
// base that aliases a LIVE thread — distinguishing a cache-admitted-live-frame
// disease from a PMM-returned-live-frame disease.  Diagnostic-only; gated on
// `582-diag`.  Direct pfn-addressed (mod size) so a collision overwrites the
// oldest record rather than evicting a hash bucket.
#[cfg(feature = "582-diag")]
mod d582_push_prov {
    use core::sync::atomic::{AtomicU64, Ordering};
    const SIZE: usize = 4096; // covers a wide span of kstack pfns; pow2 for mask
    struct Slot {
        pfn: AtomicU64,
        tick: AtomicU64,
        pusher_tid: AtomicU64,
    }
    impl Slot {
        const fn new() -> Self {
            Self {
                pfn: AtomicU64::new(u64::MAX),
                tick: AtomicU64::new(0),
                pusher_tid: AtomicU64::new(u64::MAX),
            }
        }
    }
    struct Shadow {
        slots: [Slot; SIZE],
    }
    impl Shadow {
        const fn new() -> Self {
            const S: Slot = Slot::new();
            Self { slots: [S; SIZE] }
        }
    }
    static SHADOW: Shadow = Shadow::new();

    #[inline]
    fn slot(phys: u64) -> &'static Slot {
        let pfn = (phys >> 12) as usize;
        &SHADOW.slots[pfn & (SIZE - 1)]
    }

    /// Record a dead-stack-cache push for the page-aligned `base` (higher-half
    /// VA).  `pusher_tid` is the reaper's current thread (the pusher).
    pub fn record(base_virt: u64, pusher_tid: u64) {
        let phys = base_virt.wrapping_sub(crate::proc::KERNEL_VIRT_OFFSET);
        let pfn = (phys >> 12) as u64;
        let s = slot(phys);
        s.pfn.store(pfn, Ordering::Relaxed);
        s.tick
            .store(crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed), Ordering::Relaxed);
        s.pusher_tid.store(pusher_tid, Ordering::Relaxed);
    }

    /// Look up the last cache-push for the page containing `base_virt`.
    /// Returns `(push_tick, pusher_tid)` if the slot's pfn matches.
    pub fn lookup(base_virt: u64) -> Option<(u64, u64)> {
        let phys = base_virt.wrapping_sub(crate::proc::KERNEL_VIRT_OFFSET);
        let pfn = (phys >> 12) as u64;
        let s = slot(phys);
        if s.pfn.load(Ordering::Relaxed) != pfn {
            return None;
        }
        Some((
            s.tick.load(Ordering::Relaxed),
            s.pusher_tid.load(Ordering::Relaxed),
        ))
    }
}

/// One cached dead stack: the higher-half kernel-stack base, the honest
/// byte-extent of the underlying kernel-stack allocation, plus the per-CPU
/// timer-ISR tick counter snapshot taken at push time.
///
/// `size` is the honest byte-extent reported by the reaper from
/// `Thread::kernel_stack_size` (see `proc::alloc_kernel_stack` for why
/// callers stamp the real span, not the compile-time
/// `KERNEL_STACK_SIZE`).  It is load-bearing: `push_dead_stack`
/// zero-fills exactly `size` bytes starting at `base`, never more.
/// Without this, a buggy or future loosened call site that admits a
/// shorter stack to the cache would scribble through the cached
/// entry's true extent and into whichever physical pages happen to lie
/// at the higher-half VAs immediately above it — corrupting an
/// unrelated thread's kernel stack and tripping the STACK_CANARY_CORRUPT
/// bugcheck (PR #399 D20 DR-watchpoint dispositive evidence).  See the
/// `push_dead_stack` doc-comment for the closure narrative.
///
/// Generation snapshot: `push_tick` is the value of the global
/// `TICK_COUNT` (TSC-derived wall-clock, see `arch::x86_64::irq`) at
/// push time.  At pop time we require `TICK_COUNT >= push_tick +
/// DEAD_STACK_QUIESCE_TICKS`.
///
/// Why this works: `TICK_COUNT` is monotone and advances at the real
/// wall-clock rate regardless of which CPU fires the timer ISR (any CPU
/// that wins the CAS publishes the new value).  Waiting two ticks (20 ms
/// at TICK_HZ=100) is sufficient for any in-flight `switch_context_asm`
/// to complete — x86-64 context switches take microseconds, never
/// tens of milliseconds.
///
/// Previous design used per-CPU `TIMER_ISR_PER_CPU[i]` counters.  That
/// scheme fails when a CPU's LAPIC timer delivers interrupts to a
/// different MSR slot (e.g. if `IA32_TSC_AUX` is transiently wrong),
/// causing one CPU's counter to freeze while the others advance.
/// `TICK_COUNT` sidesteps this: it is a single global value advanced by
/// the first CPU to win the CAS each tick period — immune to per-CPU
/// timer delivery skew.
///
/// Why this matters: when a thread exits, its saved context (the
/// `switch_context_asm` frame stored in `Thread::context.rsp`) still
/// points into the kstack VA range we're caching.  Another CPU mid-way
/// through `schedule()` may have already loaded that thread's `rsp` into
/// a register and be about to execute the post-`ret` epilogue.  If we
/// re-issue the kstack to a new thread before the other CPU completes
/// at least one full quiescent state (Intel SDM Vol. 3A §11.10 cache-
/// coherence implies the CPU has retired the in-flight stack reads/writes
/// only after it has serialised against the timer ISR returning), the
/// new thread's first `ret` from `switch_context_asm` pops zero bytes
/// (we bulk-zeroed at push) and lands at RIP=0 — the deterministic
/// low-RIP kernel #GP cluster.
///
/// POSIX clone(2) thread lifecycle: a thread is reaped only after the
/// scheduler has fully removed it from THREAD_TABLE and no CPU
/// references it.  This gen-tick gate is the kernel-side mechanism that
/// guarantees the "no CPU references it" half of that contract under SMP.
#[derive(Clone, Copy)]
struct CachedDeadStack {
    /// Higher-half kernel-stack base virtual address.
    base: u64,
    /// Honest byte-extent of this cached stack — exactly the same value
    /// the reaper read from `Thread::kernel_stack_size` (which itself is
    /// `stack_top - stack_base`, set at allocation time in
    /// `proc::alloc_kernel_stack`).  Used to bound the bulk zero-fill in
    /// `push_dead_stack` and to compute `stack_top` at
    /// `pop_dead_stack` time.
    size: u64,
    /// Global `TICK_COUNT` snapshot at push time.  `entry_is_quiesced`
    /// requires `TICK_COUNT >= push_tick + DEAD_STACK_QUIESCE_TICKS`
    /// before re-issuing this entry.  Replaces the previous per-CPU
    /// `TIMER_ISR_PER_CPU` snapshot — see the struct-level doc comment
    /// for the rationale.
    push_tick: u64,

    /// The CPU that last ran the dead thread (`Thread::last_cpu`) and the
    /// value of `CPU_SWITCH_GEN[last_cpu]` at reap time.  The cache
    /// withholds this entry until that CPU's switch generation has advanced
    /// past `last_cpu_gen` — proving `last_cpu` completed at least one
    /// further `switch_context_asm` since the thread died and is therefore
    /// no longer executing on (or delivering interrupts to) this stack VA.
    /// This closes the torn-`switch_context_asm`-frame `#DB` race that a
    /// pure wall-clock-tick gate can miss when a context switch and a
    /// recycle land inside the same tick under a clone-thread spawn burst.
    /// See `CPU_SWITCH_GEN`.
    last_cpu: usize,
    last_cpu_gen: u64,
}

static DEAD_STACK_CACHE: spin::Mutex<alloc::vec::Vec<CachedDeadStack>> =
    spin::Mutex::new(alloc::vec::Vec::new());

/// Read the current global tick count for use as a quiescence snapshot.
///
/// Uses `TICK_COUNT` rather than per-CPU `TIMER_ISR_PER_CPU` — see the
/// `CachedDeadStack` struct doc for the rationale.
#[inline]
fn current_tick_for_quiesce() -> u64 {
    crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed)
}

/// Decide whether a cached entry has quiesced — the global `TICK_COUNT`
/// must have advanced by at least `DEAD_STACK_QUIESCE_TICKS` since push.
///
/// This replaces the previous per-CPU `TIMER_ISR_PER_CPU` check.  See
/// `CachedDeadStack` struct doc for the full rationale.
#[inline]
fn entry_is_quiesced(entry: &CachedDeadStack) -> bool {
    // Gate 1 (per-CPU switch generation — the primary, race-tight signal):
    // the CPU that last ran the dead thread must have completed at least one
    // further context switch since the thread died, proving it is no longer
    // executing `switch_context_asm`'s restore epilogue on this stack VA and
    // can no longer land an interrupt frame on it via TSS.RSP[0].  See
    // `CPU_SWITCH_GEN`.  A snapshot of `u64::MAX` (set when `last_cpu` was
    // unknown at reap) makes this gate vacuously pass so the tick gate
    // governs alone — never under-waits, only the tick fallback applies.
    let gen_ok = entry.last_cpu_gen == u64::MAX
        || cpu_switch_gen(entry.last_cpu) > entry.last_cpu_gen;

    // Gate 2 (wall-clock tick — defence-in-depth): bounds the re-issue
    // against any in-flight switch the generation counter cannot attribute
    // to a specific CPU.  The minimum wait is `DEAD_STACK_QUIESCE_TICKS`.
    let now = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let tick_ok = now >= entry.push_tick.saturating_add(DEAD_STACK_QUIESCE_TICKS);

    // Liveness escape valve: if `last_cpu` goes idle (parks in `sti;hlt;cli`
    // with no Ready work) it stops bumping its switch generation, so a pure
    // `gen_ok && tick_ok` rule would withhold the entry until that CPU next
    // schedules — a *leak* (never a UAF) under a quiet system.  After a much
    // larger margin (`DEAD_STACK_QUIESCE_TICKS * GEN_ESCAPE_MULT` ≈ 160 ms at
    // TICK_HZ=100) the in-flight `switch_context_asm` epilogue (microseconds)
    // has unquestionably retired on any non-wedged CPU, so the entry is safe
    // to re-issue on the tick gate alone.  This bounds the cache occupancy
    // without re-opening the race the gen gate closes for the common
    // (busy-CPU) case.  Cite Intel SDM Vol. 3A §6.14: an interrupt's TSS-RSP
    // stack switch and the switch epilogue both complete in bounded time.
    const GEN_ESCAPE_MULT: u64 = 8;
    let escape_ok = now
        >= entry.push_tick
            .saturating_add(DEAD_STACK_QUIESCE_TICKS.saturating_mul(GEN_ESCAPE_MULT));

    (gen_ok && tick_ok) || escape_ok
}

/// Try to push a dead stack to the cache. Returns true if cached, false if full.
///
/// `stack_size_bytes` is the honest byte-extent of the kernel-stack
/// allocation backing `stack_base_virt` — i.e. the same
/// `kernel_stack_size` the reaper read from the dead Thread, which itself
/// is `stack_top - stack_base` at allocation time.  The zero-fill below
/// is strictly bounded to `stack_size_bytes`; it MUST NOT write past the
/// end of the cached allocation.
///
/// Why this bound matters (closure of STACK_CANARY_CORRUPT, PR #399
/// D20 DR-watchpoint disposition): the prior implementation zeroed a
/// fixed `KERNEL_STACK_PAGES_PUB * 0x1000` = 256 KiB irrespective of
/// the cached entry's true extent.  In the saga's bugcheck signature,
/// the writer RIP captured by the D20 hardware watchpoint resolved to
/// `compiler_builtins::memset` called from this site, with the
/// destination range extending past the cached allocation's true
/// end and into the higher-half mapping of an adjacent thread's
/// kernel stack canary.  Bounding the zero-fill to the cached entry's
/// honest size eliminates that out-of-bounds write at its source.
/// The call site in `reap_dead_threads_sched` separately refuses to
/// push entries whose `kernel_stack_size` is not the full
/// `KERNEL_STACK_SIZE`, so today `stack_size_bytes` is always
/// `KERNEL_STACK_PAGES_PUB * 0x1000`; the bound is the defence-in-depth
/// invariant that survives future gate changes.
///
/// Zeroing rationale: a recycled stack must not carry the previous
/// thread's saved register state, syscall arguments, or kernel
/// pointers across the lifetime boundary into the new thread that
/// pops it.  Without zeroing, `pop_dead_stack` returns a base whose
/// top frame still contains the prior occupant's RIP / RBP / scratch
/// values; any kernel code that subsequently reads from the stack —
/// speculatively or architecturally — observes another thread's
/// secret state.  CWE-244 (Improper Clean Up on Thrown Exception in
/// the broader "improper resource shutdown" class — recycled-resource
/// leak of residual data).
///
/// Cost: one `write_bytes(.., 0, stack_size_bytes)` per reaped thread.
/// At 64 pages = 256 KiB this is ~12 µs on a modern core, paid once
/// per thread death — comparable to the page-zeroing cost paid on the
/// non-cached path (`pmm::free_page` → `pmm::alloc_page` zero on the
/// allocation side).  The cache exists to skip TLB shootdowns and the
/// PMM round-trip, not to skip zeroing.
///
/// Quiescence gate: the global `TICK_COUNT` is recorded alongside the
/// kstack base so `pop_dead_stack` can withhold the entry from re-issue
/// until `TICK_COUNT` has advanced by at least `DEAD_STACK_QUIESCE_TICKS`
/// (wall-clock: 20 ms at TICK_HZ=100).  See `CachedDeadStack` for the
/// rationale.
fn push_dead_stack(
    stack_base_virt: u64,
    stack_size_bytes: u64,
    last_cpu: usize,
) -> bool {
    // Defensive: refuse zero-sized or absurdly-large entries.  Both shapes
    // are programmer errors at the call site — the cache must never
    // hand back a base whose true extent we cannot honour.  Treat as
    // "cache full" so the caller falls through to `pmm::free_page` for
    // each of the kstack's pages (see `reap_dead_threads_sched`).
    if stack_size_bytes == 0
        || stack_size_bytes > (crate::proc::KERNEL_STACK_PAGES_PUB as u64) * 0x1000
    {
        return false;
    }

    // Bulk-zero the kernel stack via the higher-half virtual base BEFORE
    // taking the cache lock — keeps the lock window tight (a few CPU
    // cycles to push the entry; the ~12 µs zero runs outside the lock).
    // The cached entry is not observable to any reader until we acquire
    // the lock below, so the zero is guaranteed to be visible to the
    // first `pop_dead_stack` caller that recycles this base.
    //
    // The zero length is `stack_size_bytes`, which is the honest extent
    // of this entry's underlying allocation (see doc-comment).  Writing
    // past that would step into another allocation's higher-half
    // mapping and corrupt unrelated kernel state.
    // SAFETY: `stack_base_virt` is a kernel higher-half virtual address
    // that was previously allocated as a kernel stack for a thread that
    // is now Dead and removed from THREAD_TABLE (see
    // `reap_dead_threads_sched`).  The caller runs with interrupts
    // disabled; no other CPU can be executing on this stack — Dead
    // state is set by the thread's last `schedule()` call, after which
    // the per-CPU `current_tid` moves away from this thread.  The
    // mapping is in the kernel half (above KERNEL_VIRT_BASE) so a
    // user-mode access cannot reach it.  The length `stack_size_bytes`
    // is bounded above by `KERNEL_STACK_PAGES_PUB * 0x1000` (checked
    // immediately above), so the write stays within the kstack
    // allocation's physical extent.
    unsafe {
        core::ptr::write_bytes(
            stack_base_virt as *mut u8,
            0u8,
            stack_size_bytes as usize,
        );
    }

    let push_tick = current_tick_for_quiesce();

    // Snapshot the switch generation of the CPU that last ran the dead
    // thread.  Re-issue is withheld until that CPU's generation advances
    // (it completes another switch onto a different stack).  A `last_cpu`
    // outside the valid range (e.g. a never-scheduled thread) records a
    // `u64::MAX` sentinel so `entry_is_quiesced`'s gen gate passes
    // vacuously and the wall-clock-tick gate governs alone — conservative,
    // never under-waits.  See `CPU_SWITCH_GEN`.
    let (last_cpu_norm, last_cpu_gen) = if last_cpu < MAX_CPUS {
        (last_cpu, cpu_switch_gen(last_cpu))
    } else {
        (0usize, u64::MAX)
    };

    let mut cache = DEAD_STACK_CACHE.lock();
    if cache.len() >= MAX_DEAD_STACKS {
        return false;
    }
    cache.push(CachedDeadStack {
        base: stack_base_virt,
        size: stack_size_bytes,
        push_tick,
        last_cpu: last_cpu_norm,
        last_cpu_gen,
    });
    // #582 provenance: record who pushed this frame to the cache, so the
    // alloc-side alias guard can name a cache-admitted-live-frame disease.
    #[cfg(feature = "582-diag")]
    d582_push_prov::record(stack_base_virt, crate::proc::current_tid() as u64);
    true
}

/// Try to pop a cached stack for reuse.
///
/// Returns `(stack_base_virt, stack_size_bytes)` of the oldest cached
/// entry that has quiesced — i.e. the global `TICK_COUNT` has advanced
/// by at least `DEAD_STACK_QUIESCE_TICKS` since push.  Non-quiesced
/// entries are left in place; the next pop attempt re-checks them.
///
/// `stack_size_bytes` is the honest extent stamped at push time (the
/// reaper's view of `Thread::kernel_stack_size`).  Callers use it to
/// build a `stack_top` without falling back to the compile-time
/// `KERNEL_STACK_SIZE` constant — see `proc::alloc_kernel_stack`.
/// Today every cached entry is `KERNEL_STACK_PAGES_PUB * 0x1000`
/// (the call-site gate in `reap_dead_threads_sched` refuses anything
/// shorter), so this is effectively a constant in production; we still
/// return it explicitly to keep the cache's external contract honest
/// against future gate changes.
///
/// PMM allocator fallback: returning `None` here is the normal path that
/// causes `proc::alloc_kernel_stack` to fall through to
/// `pmm::alloc_pages(KERNEL_STACK_PAGES)` — see `proc/mod.rs`.  No caller
/// of `pop_dead_stack` treats `None` as fatal, so withholding a
/// non-quiesced entry is always safe; it costs a fresh PMM allocation in
/// exchange for closing the kstack-reuse-while-RSP-still-live race
/// (Intel SDM Vol. 3A §6.14 "Interrupt and Exception Handling").  See
/// `CachedDeadStack` for the full quiescence rationale.
pub fn pop_dead_stack() -> Option<(u64, u64)> {
    let mut cache = DEAD_STACK_CACHE.lock();
    // Scan from the oldest end (index 0) — older entries have had more
    // time to quiesce, so this preserves rough-FIFO recycle order even
    // though pushes append to the end.
    let mut idx_found: Option<usize> = None;
    for (i, entry) in cache.iter().enumerate() {
        if entry_is_quiesced(entry) {
            idx_found = Some(i);
            break;
        }
    }
    #[cfg(feature = "test-mode")]
    if idx_found.is_none() && !cache.is_empty() {
        let e = &cache[0];
        let now = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
        let cur_gen = cpu_switch_gen(e.last_cpu);
        crate::serial_println!(
            "[KSTACK/QUIESCE] push_tick={} now={} need={} tick_ok={} \
             last_cpu={} snap_gen={} cur_gen={} gen_ok={}",
            e.push_tick, now, e.push_tick.saturating_add(DEAD_STACK_QUIESCE_TICKS),
            now >= e.push_tick.saturating_add(DEAD_STACK_QUIESCE_TICKS),
            e.last_cpu, e.last_cpu_gen, cur_gen,
            e.last_cpu_gen == u64::MAX || cur_gen > e.last_cpu_gen);
    }
    let i = idx_found?;
    // `remove` is O(n) but n ≤ MAX_DEAD_STACKS = 64 and the call site
    // (alloc_kernel_stack) is off the hot scheduler path — already
    // amortised against PMM allocation cost.
    let entry = cache.remove(i);
    Some((entry.base, entry.size))
}

// ── Emergency-tier kstack free quarantine ────────────────────────────────────
//
// Standard 256 KiB kstacks go to the dead-stack cache, which already withholds
// re-issue until the frame is quiesced (CPU_SWITCH_GEN + tick — see
// `entry_is_quiesced`).  Sub-256 KiB *emergency-tier* frames (16K/8K/4K, taken
// when the PMM is fragmented) historically went STRAIGHT to `pmm::free_page` in
// the reaper, with NO quiescence gate.  The DR0 write-watch named the resulting
// bug: a reaper frees an emergency-tier frame to the PMM while a *parked*
// thread's saved `switch_context_asm` frame still lives in that span (its own
// in-flight switch epilogue, or — case B — a PMM double-allocation aliasing a
// live frame); the next `alloc_kernel_stack` zero-fills it (proc/mod.rs:725) or
// the new owner's `pushfq`/a stale-TSS.RSP0 interrupt frame tears the parked
// owner's saved RFLAGS slot → its `popfq` faults (`#DB`,
// `UNEXPECTED_KERNEL_MODE_TRAP` 0x7f).
//
// Fix: route emergency-tier frees through this quarantine, which applies BOTH
// gates the standard cache gets:
//   (a) quiescence — `entry_is_quiesced` (CPU_SWITCH_GEN + tick), so the frame
//       cannot reach the PMM free list until its last user's switch epilogue
//       has retired;
//   (b) saved-RSP survey — `saved_rsp_aliases_live_frame`, so the frame is also
//       withheld while ANY live thread's `context.rsp` still falls in its span
//       (covers the aliasing / case-B variants the gen gate alone cannot see).
// A quarantined frame is re-checked on every later reaper pass and freed to the
// PMM only once BOTH gates clear — no leak (the entry is retried, not dropped),
// no UAF (the frame never reaches the PMM while still referenced).  Cite Intel
// SDM Vol. 3A §6.14 (TSS-RSP interrupt stack switch) + Vol. 3B §17.3.1.1 (TF).
#[derive(Clone, Copy)]
struct PendingKstackFree {
    /// Higher-half kernel-stack base virtual address.
    base: u64,
    /// Honest byte-extent of the underlying allocation (emergency tier:
    /// 16K/8K/4K; or any non-standard size that overflowed the cache).
    size: u64,
    /// Global `TICK_COUNT` at quarantine time (drives `entry_is_quiesced`).
    push_tick: u64,
    /// CPU that last ran the dead thread + its `CPU_SWITCH_GEN` snapshot —
    /// same gen-quiescence signal the dead-stack cache uses.
    last_cpu: usize,
    last_cpu_gen: u64,
}

/// Quarantine of emergency-tier (and cache-overflow) kstack frames awaiting a
/// PMM free, gated on quiescence + saved-RSP survey.  Bounded by the live
/// thread count (each reaped thread contributes at most one entry, and entries
/// drain as soon as their gates clear); a generous cap prevents unbounded
/// growth if a frame's gate somehow never clears (it would surface as a
/// diagnostic, never a silent leak of all of RAM).
const MAX_PENDING_KSTACK_FREES: usize = 256;
static PENDING_KSTACK_FREE: spin::Mutex<alloc::vec::Vec<PendingKstackFree>> =
    spin::Mutex::new(alloc::vec::Vec::new());

/// `TICK_COUNT` at the last `drain_pending_kstack_free` survey, plus the
/// reaper's per-tick throttle gate.
///
/// The quarantine survey is O(entries × live-threads): for each pending frame
/// it walks the whole `THREAD_TABLE` (`saved_rsp_aliases_live_frame`).  The
/// reaper runs at the top of every `schedule()`, so calling the survey on every
/// schedule made the cost scale with both the quarantine depth (which climbs to
/// `MAX_PENDING_KSTACK_FREES` whenever a frame's VA is recycled to a live
/// thread and the alias gate therefore *correctly, permanently* withholds it)
/// and the live-thread count.  Under a thread-churning workload that pinned a
/// near-full quarantine, the survey dominated the single CPU and starved the
/// cooperative kernel service threads (net poll / display / compositor).
///
/// The survey gates are purely wall-clock / generation based: the earliest an
/// entry can clear is `DEAD_STACK_QUIESCE_TICKS` (2 ticks) and the slowest is
/// the escape valve at `DEAD_STACK_QUIESCE_TICKS * 8` (16 ticks).  Re-running it
/// more than once per `TICK_COUNT` advance therefore reclaims nothing — no entry
/// can become eligible within a single tick that was not eligible at the start
/// of it.  Gating the survey to at most once per tick bounds the reaper's cost
/// to O(entries × threads) per tick (≈ once per 10 ms at TICK_HZ=100) instead of
/// per schedule, with zero change to *which* entries are freed or *when* they
/// become eligible (the quiescence + alias correctness gates are untouched).
static LAST_KSTACK_DRAIN_TICK: AtomicU64 = AtomicU64::new(u64::MAX);

/// Per-tick throttle gate for the quarantine survey.  Returns `true` at most
/// once per distinct `now` value across all callers: the atomic swap publishes
/// `now` and the prior occupant of `slot` decides.  The first caller to observe
/// a new tick swaps in `now`, reads back the *previous* tick (`!= now`) and
/// drains; every later caller in the same tick reads back `now` (`== now`) and
/// skips.  Under SMP this admits exactly one drain per tick — the swap is a
/// single atomic RMW, so concurrent callers cannot both read back a value other
/// than `now` (Intel SDM Vol. 3A §8.1.2.2: locked read-modify-write operations
/// are atomic).  `Relaxed` ordering suffices: the gate carries no data, and the
/// drain it guards takes its own `THREAD_TABLE` / quarantine / PMM locks which
/// provide the ordering for the actual reclamation.  Initialising `slot` to
/// `u64::MAX` guarantees the first-ever call drains (no real `TICK_COUNT` value
/// equals `u64::MAX`).
#[inline]
fn kstack_drain_due(slot: &AtomicU64, now: u64) -> bool {
    slot.swap(now, Ordering::Relaxed) != now
}

/// Test-only: exercise the per-tick drain-throttle gate against a caller-owned
/// `slot`, so the suite can assert the once-per-tick invariant without
/// perturbing the production `LAST_KSTACK_DRAIN_TICK` (which a sibling CPU's
/// reaper may be reading concurrently).  Identical code path to the production
/// call site in `reap_dead_threads_sched`.
#[cfg(feature = "test-mode")]
pub fn test_kstack_drain_due(slot: &AtomicU64, now: u64) -> bool {
    kstack_drain_due(slot, now)
}

/// Quarantine an emergency-tier / cache-overflow kstack frame for a gated PMM
/// free.  Stamps the quiescence snapshot exactly like `push_dead_stack`.
/// Returns `true` if quarantined; `false` if the quarantine is full (caller
/// then falls back to an immediate PMM free, accepting the residual race — far
/// rarer than the steady-state emergency-tier path this closes).
fn quarantine_kstack_free(base: u64, size: u64, last_cpu: usize) -> bool {
    let (last_cpu_norm, last_cpu_gen) = if last_cpu < MAX_CPUS {
        (last_cpu, cpu_switch_gen(last_cpu))
    } else {
        (0usize, u64::MAX)
    };
    let push_tick = current_tick_for_quiesce();
    let mut q = PENDING_KSTACK_FREE.lock();
    if q.len() >= MAX_PENDING_KSTACK_FREES {
        return false;
    }
    q.push(PendingKstackFree {
        base,
        size,
        push_tick,
        last_cpu: last_cpu_norm,
        last_cpu_gen,
    });
    true
}

/// Public entry for the alloc-side alias guard to deposit a REJECTED candidate
/// frame (one whose span aliased a live thread's kstack) into the gated
/// quarantine instead of returning it or re-freeing it to the PMM.  The
/// quarantine's quiescence + saved-RSP gates ensure the frame is freed to the
/// PMM only once it is genuinely no longer referenced — never re-issued as a
/// kstack while still live, never double-freed, never leaked.  `last_cpu` is
/// unknown at the alloc site, so the `u64::MAX` gen sentinel is recorded and
/// the wall-clock tick + survey gates govern.  Returns `false` if the
/// quarantine is full (caller must then leak-with-diagnostic rather than risk
/// returning the aliasing frame).
pub fn quarantine_rejected_alloc_frame(base: u64, size: u64) -> bool {
    quarantine_kstack_free(base, size, usize::MAX)
}

/// #582 provenance lookup: who pushed the page at `base_virt` to the dead-stack
/// cache?  Returns `(push_tick, pusher_tid)`.  Diagnostic-only.
#[cfg(feature = "582-diag")]
pub fn d582_cache_push_prov(base_virt: u64) -> Option<(u64, u64)> {
    d582_push_prov::lookup(base_virt)
}

/// Drain the emergency-tier free quarantine: free to the PMM every entry that
/// has BOTH quiesced (`entry_is_quiesced`) AND cleared the saved-RSP survey
/// (no live thread's `context.rsp` aliases its span).  Entries failing either
/// gate are retried on the next reaper pass.
///
/// MUST be called with interrupts disabled (reaper contract — `pmm::free_page`
/// shares `PMM_LOCK` with the timer ISR).  Takes a fresh `THREAD_TABLE` lock to
/// run the survey, then releases it before any PMM op (the established pattern
/// in `reap_dead_threads_sched`).
fn drain_pending_kstack_free() {
    use crate::proc::KERNEL_VIRT_OFFSET;
    // Phase 1: under THREAD_TABLE, partition the quarantine into "free now"
    // (both gates clear) vs "retain" (still gated).  We build the free-list
    // while holding both locks briefly, then release before PMM ops.
    let to_free: alloc::vec::Vec<(u64, u64)> = {
        let threads = THREAD_TABLE.lock();
        let mut q = PENDING_KSTACK_FREE.lock();
        if q.is_empty() {
            return;
        }
        let mut freeable = alloc::vec::Vec::new();
        q.retain(|e| {
            // Reuse the dead-stack cache's quiescence decision verbatim (it
            // reads `entry_is_quiesced`'s gen + tick + escape-valve logic).
            let quiesced = {
                let probe = CachedDeadStack {
                    base: e.base,
                    size: e.size,
                    push_tick: e.push_tick,
                    last_cpu: e.last_cpu,
                    last_cpu_gen: e.last_cpu_gen,
                };
                entry_is_quiesced(&probe)
            };
            // Survey: the owner has already been removed from THREAD_TABLE by
            // the reaper, so any saved-RSP hit here is a DIFFERENT live thread
            // aliasing this span — withhold.  `excluding_tid = 0` is safe: tid
            // 0 (BSP idle) runs on the identity-mapped bootstrap stack, never
            // an emergency-tier higher-half kstack, so it can never legitimately
            // alias a quarantined frame.
            let aliased = saved_rsp_aliases_live_frame(&threads, e.base, e.size, 0);
            if quiesced && !aliased {
                freeable.push((e.base, e.size));
                false // remove from quarantine
            } else {
                true // retain, retry next pass
            }
        });
        freeable
    }; // both locks released

    // Phase 2: free the cleared frames to the PMM (no lock held except PMM's).
    for (base, size) in to_free {
        let phys_base = if base >= KERNEL_VIRT_OFFSET {
            base - KERNEL_VIRT_OFFSET
        } else {
            base
        };
        let pages = ((size + 4095) / 4096) as u64;
        for p in 0..pages {
            crate::mm::pmm::free_page(phys_base + p * 0x1000);
        }
    }
}

/// Test-only: current quarantine depth.
#[cfg(any(feature = "test-mode", feature = "582-diag"))]
pub fn pending_kstack_free_len() -> usize {
    PENDING_KSTACK_FREE.lock().len()
}

/// Public interface to pre-populate the dead stack cache (called from main.rs).
///
/// Pre-allocated stacks are always full-sized (`KERNEL_STACK_PAGES_PUB *
/// 0x1000`) — see `main.rs::pre_alloc_stacks` — so this shim stamps
/// that size unconditionally.  No other production call site uses the
/// `_pub` shim; all reaper-driven pushes go through the internal
/// `push_dead_stack` with the honest `kernel_stack_size`.
pub fn push_dead_stack_pub(stack_base_virt: u64) -> bool {
    let stack_size = (crate::proc::KERNEL_STACK_PAGES_PUB as u64) * 0x1000;
    // Pre-allocated stacks never ran a thread, so there is no `last_cpu` that
    // could still be switching off them.  Pass an out-of-range CPU index so
    // `push_dead_stack` records the `u64::MAX` gen sentinel and only the
    // wall-clock-tick gate governs eligibility.
    push_dead_stack(stack_base_virt, stack_size, usize::MAX)
}

/// Test-only pop that bypasses the `DEAD_STACK_QUIESCE_TICKS` gate so a
/// freshly-pushed entry can be popped in the same tick.  Behaves like
/// `pop_dead_stack` but disregards `entry_is_quiesced`.
///
/// This exists for `test_runner::test_236_dead_stack_zeroing`, which pushes
/// and pops in the same call frame to verify the zeroing contract — the
/// quiescence gate would otherwise withhold the entry for ~20 ms and the
/// test would deterministically fail under `--features test-mode`.
///
/// Return the number of entries currently in the dead-stack cache.
///
/// Diagnostic helper: only compiled for test-mode to avoid polluting the
/// production binary.  Use to verify kstack recycling in PMM-leak tests.
#[cfg(feature = "test-mode")]
pub fn dead_stack_cache_len() -> usize {
    DEAD_STACK_CACHE.lock().len()
}

/// Wait (yield-based) until the global `TICK_COUNT` has advanced by
/// `DEAD_STACK_QUIESCE_TICKS + 1` ticks from the current instant.
///
/// After this returns, any dead-stack cache entry pushed BEFORE the call
/// will satisfy `entry_is_quiesced` — `TICK_COUNT` is the same counter
/// that `entry_is_quiesced` now reads (see `CachedDeadStack.push_tick`).
///
/// Test-mode only: used by the PMM-leak test to ensure the child's kstack
/// is recycled on the next iteration rather than forcing a fresh PMM alloc.
#[cfg(feature = "test-mode")]
pub fn wait_dead_stacks_quiesced() {
    const NEEDED: u64 = DEAD_STACK_QUIESCE_TICKS + 1;
    let baseline = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    loop {
        crate::hal::enable_interrupts();
        yield_cpu();
        let now = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
        if now >= baseline.saturating_add(NEEDED) { break; }
        for _ in 0..200 { core::hint::spin_loop(); }
    }
}

/// Production callers MUST use `pop_dead_stack`; the gate is load-bearing
/// for closing the kstack-reuse-while-RSP-still-live race (PR #348).
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
pub fn pop_dead_stack_force() -> Option<(u64, u64)> {
    let mut cache = DEAD_STACK_CACHE.lock();
    if cache.is_empty() { return None; }
    let entry = cache.remove(0);
    Some((entry.base, entry.size))
}

/// Test-only: evaluate the `entry_is_quiesced` decision for a synthetic
/// cache entry with the supplied `(push_tick, last_cpu, last_cpu_gen)`.
///
/// Lets the kernel test suite verify the per-CPU switch-generation gate
/// (`CPU_SWITCH_GEN`) in isolation without spawning real threads:
///   * gen not advanced + tick gate met            → withheld (false)
///   * gen advanced     + tick gate met            → eligible (true)
///   * `last_cpu_gen == u64::MAX` (unknown CPU)     → gen gate vacuous
///   * tick margin ≥ escape valve                   → eligible regardless
#[cfg(any(feature = "test-mode", feature = "firefox-test-core"))]
pub fn test_entry_quiesced(push_tick: u64, last_cpu: usize, last_cpu_gen: u64) -> bool {
    entry_is_quiesced(&CachedDeadStack {
        base: 0,
        size: 0,
        push_tick,
        last_cpu,
        last_cpu_gen,
    })
}

/// Test-only: read the live switch generation of `cpu`.
#[cfg(any(feature = "test-mode", feature = "firefox-test-core"))]
pub fn test_cpu_switch_gen(cpu: usize) -> u64 {
    cpu_switch_gen(cpu)
}

/// Test-only: run the saved-RSP survey against a caller-supplied thread slice.
///
/// Lets the kernel test suite verify the #582 saved-RSP-survey gate
/// (`saved_rsp_aliases_live_frame`) in isolation: a kstack frame must report
/// `aliased=true` while a live thread's saved `context.rsp` falls in its span,
/// `false` once it does not — and the frame's own (excluded) owner must never
/// self-alias.  Mirrors `test_entry_quiesced`'s isolation shape.
#[cfg(any(feature = "test-mode", feature = "firefox-test-core"))]
pub fn test_saved_rsp_aliases(
    threads: &[crate::proc::Thread],
    base: u64,
    size: u64,
    excluding_tid: crate::proc::Tid,
) -> bool {
    saved_rsp_aliases_live_frame(threads, base, size, excluding_tid)
}

/// Pure selection core: the scoring loop + two-pass split + force-backstop
/// resolution, with NO side effects (no `READY_DEPTH` publish, no
/// `SCHED_STARVE_FORCE_TOTAL` bump, no diagnostic).  Returns the selected table
/// index, the run-queue depth observed, and — when the force backstop chose the
/// pick — the forced thread's `(index, raw_wait_age)` so the caller can apply
/// the side effects exactly once.  Extracted verbatim from the legacy in-line
/// picker (Perf P2 phase 2b): same `score = priority*4 + aff_bonus(0..2) +
/// wait_age_bonus(age)`, same strict-max first-in-candidate-order tie-break,
/// same two-pass non-idle-then-idle split, same per-thread force deadline
/// (`STARVE_FORCE_TICKS_BSP` for TID 0 else `STARVE_FORCE_TICKS`).  Candidates
/// must be supplied **in the picker's rotation order** so the tie-break matches.
fn select_next_core(
    threads: &[proc::Thread],
    cpu: u8,
    candidate_indices: impl Iterator<Item = usize>,
    now: u64,
) -> (Option<usize>, u64, Option<(usize, u64)>) {
    let mut best_idx: Option<usize> = None;
    let mut best_score: u16 = 0;
    let mut idle_best_idx: Option<usize> = None;
    let mut idle_best_score: u16 = 0;
    let mut force_idx: Option<usize> = None;
    let mut force_age: u64 = 0;
    let mut force_margin: i64 = i64::MIN;
    let mut ready_peers: u64 = 0;

    for idx in candidate_indices {
        let t = &threads[idx];
        if t.state != ThreadState::Ready {
            continue;
        }
        if t.tid < 0x1000 {
            ready_peers += 1;
        }
        if !t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire) {
            continue;
        }
        if let Some(aff) = t.cpu_affinity {
            if aff != cpu {
                continue;
            }
        }

        let wait_age = now.saturating_sub(t.ready_since_tick);
        let is_idle_thread = t.tid >= 0x1000;

        let mut score = (t.priority as u16) * 4;
        if t.cpu_affinity == Some(cpu) {
            score += 2;
        } else if t.last_cpu == cpu {
            score += 1;
        }
        if !is_idle_thread {
            score += wait_age_bonus(wait_age);
            let deadline: u64 = force_deadline_for_tid(t.tid);
            let margin = wait_age as i64 - deadline as i64;
            if margin > force_margin {
                force_margin = margin;
                force_age = wait_age;
                force_idx = Some(idx);
            }
        }

        if is_idle_thread {
            if score > idle_best_score || idle_best_idx.is_none() {
                idle_best_idx = Some(idx);
                idle_best_score = score;
            }
        } else if score > best_score || best_idx.is_none() {
            best_idx = Some(idx);
            best_score = score;
        }
    }

    if best_idx.is_none() {
        best_idx = idle_best_idx;
    }

    let mut forced: Option<(usize, u64)> = None;
    if force_margin >= 0 {
        if let Some(fidx) = force_idx {
            if best_idx != Some(fidx) {
                best_idx = Some(fidx);
                forced = Some((fidx, force_age));
            }
        }
    }
    (best_idx, ready_peers, forced)
}

/// The authoritative per-CPU selection (Perf P2 phase 2b), with the original
/// inline-picker side effects: publishes `READY_DEPTH`, bumps
/// `SCHED_STARVE_FORCE_TOTAL` and emits the throttled `[SCHED/STARVE]
/// force-select` diagnostic on a force.  Returns `(selected_index, ready_peers)`.
/// The legacy path calls this with the full rotated `1..len` candidate sequence
/// — proving the extraction is byte-identical to the old inline loop.
fn select_next(
    threads: &[proc::Thread],
    cpu: u8,
    candidate_indices: impl Iterator<Item = usize>,
    now: u64,
) -> (Option<usize>, u64) {
    let (best_idx, ready_peers, forced) =
        select_next_core(threads, cpu, candidate_indices, now);

    READY_DEPTH.store(ready_peers, Ordering::Relaxed);

    if let Some((fidx, force_age)) = forced {
        let n = SCHED_STARVE_FORCE_TOTAL.fetch_add(1, Ordering::Relaxed);
        let deadline: u64 = force_deadline_for_tid(threads[fidx].tid);
        if n == 0 || n % STARVE_FORCE_LOG_EVERY == 0 {
            crate::serial_println!(
                "[SCHED/STARVE] force-select tid={} (waited {} ticks >= {}) on cpu={} \
                 total={} — anti-starvation backstop",
                threads[fidx].tid, force_age, deadline, cpu, n + 1,
            );
        }
    }
    (best_idx, ready_peers)
}

/// Side-effect-free selection used by the phase-2b equivalence cross-check: the
/// pure [`select_next_core`], returning only the selected table index.  Must not
/// drive the authoritative path (it skips the READY_DEPTH/force-counter side
/// effects, which would then never fire).
#[cfg(feature = "sched-pick-xcheck")]
fn select_next_no_side_effects(
    threads: &[proc::Thread],
    cpu: u8,
    candidate_indices: impl Iterator<Item = usize>,
    now: u64,
) -> Option<usize> {
    select_next_core(threads, cpu, candidate_indices, now).0
}

/// Test entry point (Perf P2 phase 2b pick-equivalence proof, Test 648).
///
/// Runs the selection core over a caller-built synthetic thread table for a
/// given running CPU, current index and tick, with TWO candidate orderings:
///
///   * `legacy` — the full rotated `(current_idx + i) % len` walk, and
///   * `percpu` — the candidate set the per-CPU path would derive (built here by
///     [`test_percpu_candidates`] over the supplied `runnable_tids`, applying
///     the same rotation-distance ordering the live per-CPU pick re-imposes on
///     its runqueue membership, so the test need not touch the live `RQS`).
///
/// Returns the selected TID for each ordering so the test can assert they are
/// identical.  Uses the side-effect-free [`select_next_core`], so it perturbs no
/// live scheduler counters.
pub fn test_pick_equivalence(
    threads: &[proc::Thread],
    cpu: u8,
    current_idx: usize,
    now: u64,
    runnable_tids: &[proc::Tid],
) -> (Option<proc::Tid>, Option<proc::Tid>) {
    let len = threads.len();
    let percpu = test_percpu_candidates(threads, current_idx, runnable_tids);

    let legacy_idx =
        select_next_core(threads, cpu, (1..len).map(|i| (current_idx + i) % len), now).0;
    let percpu_idx = select_next_core(threads, cpu, percpu.iter().copied(), now).0;
    (
        legacy_idx.map(|i| threads[i].tid),
        percpu_idx.map(|i| threads[i].tid),
    )
}

/// Build the per-CPU candidate index ordering for [`test_pick_equivalence`] from
/// an explicit list of runnable Tids (modelling `RQS[cpu]`'s membership),
/// applying the SAME rotation-distance ordering the live authoritative pick
/// re-imposes on its per-CPU runqueue membership (the rotated `(current_idx +
/// i) % len` walk filtered to this CPU's `mirror_slot` members, in `schedule`).
fn test_percpu_candidates(
    threads: &[proc::Thread],
    current_idx: usize,
    runnable_tids: &[proc::Tid],
) -> alloc::vec::Vec<usize> {
    let len = threads.len();
    let mut out: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
    for &tid in runnable_tids {
        if let Some(idx) = threads.iter().position(|t| t.tid == tid) {
            // Exclude the current thread's own index: the legacy rotation walk
            // is `i in 1..len` (it never re-considers `current_idx`), so the
            // per-CPU candidate set must drop it too for an exact match.
            if idx != current_idx % len {
                out.push(idx);
            }
        }
    }
    out.sort_by_key(|&idx| (idx + len - (current_idx % len)) % len);
    out
}

/// Schedule the next thread to run.
///
/// This is the core scheduling function. It:
/// 1. Finds the highest-priority Ready thread (round-robin among equals).
/// 2. Saves context of the current thread.
/// 3. Switches to the new thread via switch_context.
pub fn schedule() {
    if !is_active() {
        return;
    }

    // Clear the reschedule flag for this CPU (it was set by timer_tick_schedule).
    let cpu_idx = cpu_index();
    NEED_RESCHEDULE[cpu_idx].store(false, Ordering::Relaxed);

    // ── Disable interrupts to prevent deadlock ──────────────────────
    // timer_tick_schedule() runs in the timer ISR and acquires THREAD_TABLE.
    // If we hold THREAD_TABLE when a timer interrupt fires on this CPU,
    // the ISR spins on the same lock → deadlock.  CLI prevents that.
    // Interrupts are re-enabled at each early-return and after the context
    // switch completes.
    crate::hal::disable_interrupts();

    // Reap dead threads here (interrupts disabled → PMM_LOCK safe, no ISR deadlock).
    reap_dead_threads_sched();

    let current_tid = proc::current_tid();
    let cpu = cpu_index() as u8;

    // ── Stack canary check for the outgoing thread ───────────────────
    // Detect kernel stack overflow before it causes silent corruption.
    //
    // When the canary is corrupt we emit a structured diagnostic line
    // BEFORE entering `ke_bugcheck`.  The bugcheck path is fault-immune
    // but extremely terse; the diagnostic carries the context the
    // STACK_CANARY_CORRUPT investigation actually needs:
    //   - live RSP and depth from the recorded top
    //   - observed bytes at the canary slot (canary, +8, +16, +24)
    //   - flag for "ran on the 4 KiB emergency fallback" (see
    //     `proc::record_emergency_kstack` / `was_emergency_kstack`).
    // The pre-bugcheck print uses ordinary serial_println so any side
    // fault inside the formatter just leads to the bugcheck banner,
    // which is the same outcome we get today.
    {
        // The `(pid, kernel_stack_base, kernel_stack_size)` tuple is read
        // out of the THREAD_TABLE here, BEFORE we drop the lock — and the
        // `stack_size` captured into the diagnostic emit below reflects the
        // value at canary-fail observation time.  This is intentional: the
        // diagnostic must describe what was true when the overflow
        // happened, not whatever the Thread record may be patched to look
        // like by the time the bugcheck banner prints.
        let canary_info = {
            let threads = THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == current_tid)
                .filter(|t| t.kernel_stack_base > 0)
                .map(|t| (t.pid, t.kernel_stack_base, t.kernel_stack_size))
        };
        if let Some((pid, stack_base, stack_size)) = canary_info {
            if !proc::check_stack_canary(stack_base) {
                let rsp_live = proc::current_kernel_rsp_live();
                let kstack_top = stack_base.wrapping_add(stack_size);
                let depth_used = kstack_top.wrapping_sub(rsp_live);
                let observed_canary = proc::read_stack_canary(stack_base);
                let observed_p8     = proc::read_stack_word_at(stack_base, 8);
                let observed_p16    = proc::read_stack_word_at(stack_base, 16);
                let observed_p24    = proc::read_stack_word_at(stack_base, 24);
                let was_emergency   = proc::was_emergency_kstack(stack_base);
                crate::serial_println!(
                    "[KSTACK/CANARY-FAIL] tid={} pid={} base={:#x} size={:#x} top={:#x} \
rsp_live={:#x} depth={:#x} expect_magic={:#x} got={:#x} +8={:#x} +16={:#x} +24={:#x} \
was_emergency_4k={}",
                    current_tid, pid, stack_base, stack_size, kstack_top,
                    rsp_live, depth_used, proc::STACK_END_MAGIC,
                    observed_canary, observed_p8, observed_p16, observed_p24,
                    was_emergency,
                );
                crate::ke::bugcheck::ke_bugcheck(
                    crate::ke::bugcheck::BUGCHECK_CANARY_CORRUPT,
                    current_tid,   // P1: thread ID
                    pid as u64,    // P2: process ID
                    stack_base,    // P3: kernel stack base
                    0,
                );
            }
        }
    }

    // Find the next ready thread — highest priority wins, round-robin among equals.
    // Prefer threads with matching cpu_affinity, then threads whose last_cpu
    // matches the current CPU (cache locality), then any Ready thread.
    //
    // The whole picker is wrapped in a `'pick:` loop so the "no Ready peer
    // and the current thread is Sleeping/Blocked/Dead" path can wait for an
    // interrupt and retry WITHOUT recursing into schedule().  Recursion was
    // unbounded under TCG (both CPUs Dead/idle never converged) and burned
    // a kernel-stack frame per iteration; an iterative `'pick:` retry is
    // O(1) stack with the same observable behaviour.  Each iteration runs
    // with IF=0 to keep the THREAD_TABLE acquisition safe against the
    // timer ISR (which also acquires it).  The wait paths use `sti; hlt;
    // cli`: the dying/sleeping vCPU halts so the OTHER vCPU is not
    // starved competing for host CPU time under TCG, and the timer ISR
    // wakes us on the next tick.
    let (next_tid, next_rsp, next_pid, next_kstack_top, _next_first_run) = 'pick: loop {
        // Re-establish IF=0 at the top of every iteration.  The wait
        // paths below execute `sti; hlt; cli` which leaves IF=0 on
        // return — this disable_interrupts() call is defence in depth
        // against a future edit that switches to a wait primitive that
        // does not re-disable interrupts.
        crate::hal::disable_interrupts();
        let mut threads = THREAD_TABLE.lock();
        // Deferred timer due-wake drain (lock-held window).
        //
        // The timer ISR re-Readies sleeping/blocked-with-deadline threads, but
        // it uses `try_lock` and must defer the scan when the lock is contended
        // (see `wake_sleeping_threads` / `RESCAN_PENDING`).  The picker is the
        // code path that runs WHILE a thread is wedged waiting to be re-Readied,
        // and it holds `THREAD_TABLE` unconditionally here — so it is the right
        // place to honour any deferred scan.  Doing it before the Ready-peer
        // search means a sleeper whose deadline passed during the ISR's
        // contention window becomes selectable on THIS iteration, closing the
        // lost-wakeup window deterministically (cheap relaxed probe in the
        // common no-deferral case).
        drain_due_wakes_if_pending(&mut threads);
        let len = threads.len();
        if len <= 1 {
            // Only this thread (idle) exists.  Decide based on its state.
            //   Running             — caller wanted to yield/preempt but
            //                         there's nothing else; reset watchdog
            //                         and return so the caller's spin loop
            //                         retries naturally.
            //   Sleeping / Blocked  — `sti; hlt; cli` so the vCPU sleeps
            //                         until the timer ISR (or any other
            //                         wake source) flips us back to Ready;
            //                         then `continue 'pick` to retry.
            //   Dead                — terminal halt; no wake source can
            //                         ever produce another runnable
            //                         thread on this kernel.  Returning
            //                         would sysretq into dead user code.
            let current_state = threads
                .iter()
                .find(|t| t.tid == current_tid)
                .map(|t| t.state);
            drop(threads);
            match current_state {
                // Running, or freshly re-Readied (e.g. by the due-wake drain
                // above): the single thread is runnable — return to the caller
                // so it resumes rather than being mistaken for a terminal wedge.
                // A `Ready` single thread reaching the picker means its wake
                // deadline elapsed and the drain flipped it; sysret-ing back to
                // it is exactly the intended self-resume.  Clear the burst so a
                // brief wedge that just self-resolved does not leave stale state.
                Some(ThreadState::Running) | Some(ThreadState::Ready) => {
                    clear_picker_burst();
                    crate::arch::x86_64::irq::reset_watchdog_counter();
                    crate::hal::enable_interrupts();
                    return;
                }
                Some(ThreadState::Sleeping) | Some(ThreadState::Blocked) => {
                    crate::arch::x86_64::irq::reset_watchdog_counter();
                    crate::perf::record_idle_tick();
                    if note_picker_hlt(current_tid) {
                        crate::serial_println!(
                            "[SCHED/STARVE] tid={} state=Sleeping/Blocked (len=1) burst={} \
                             (>2 s without ready peer; check waitlist / futex bookkeeping)",
                            current_tid, STARVATION_BURST_THRESHOLD,
                        );
                    }
                    // sti; hlt; cli — the STI shadow guarantees the next
                    // instruction (hlt) is executed before any pending
                    // interrupt fires, so this sequence is race-free.
                    crate::arch::x86_64::irq::sched_wait_quantum();
                    // Re-check SCHEDULER_ACTIVE after waking from hlt.
                    // If another CPU called sched::disable() while we were
                    // halted, timer_tick_schedule() now short-circuits and
                    // will never flip a peer to Ready or set NEED_RESCHEDULE
                    // — `continue 'pick` would loop forever in sti;hlt;cli.
                    // Treat disable as "drop out of the picker"; the caller's
                    // schedule() prologue already returns when is_active() is
                    // false, so unwinding to it preserves existing semantics.
                    if !is_active() {
                        crate::hal::enable_interrupts();
                        return;
                    }
                    continue 'pick;
                }
                _ => {
                    // Dead, or thread already reaped.  Halt until the timer
                    // ISR (or another wake source) flips a peer to Ready,
                    // then `continue 'pick` so the picker can find it.
                    // We do NOT loop here without re-entering the picker —
                    // a peer thread with affinity to THIS CPU can become
                    // Ready while we're halted (e.g. an idle TID 0
                    // preempted by mmap_test that has now exited), and
                    // only the picker is allowed to context-switch back
                    // to it.  Looping forever in `sti;hlt;cli` without
                    // retrying the picker leaves the affinity-pinned peer
                    // stranded and deadlocks the test_runner.
                    crate::arch::x86_64::irq::reset_watchdog_counter();
                    crate::perf::record_idle_tick();
                    if note_picker_hlt(current_tid) {
                        crate::serial_println!(
                            "[SCHED/STARVE] tid={} state=Dead/reaped (len=1) burst={} \
                             (terminal wedge — no other thread can ever become ready)",
                            current_tid, STARVATION_BURST_THRESHOLD,
                        );
                    }
                    crate::arch::x86_64::irq::sched_wait_quantum();
                    // See is_active() recheck rationale above.
                    if !is_active() {
                        crate::hal::enable_interrupts();
                        return;
                    }
                    continue 'pick;
                }
            }
        }

        // Find current thread's index.
        let current_idx = threads.iter()
            .position(|t| t.tid == current_tid)
            .unwrap_or(0);

        // ── Anti-starvation: lazy run-queue wait stamping ───────────────────
        // Stamp every Ready thread that is not yet stamped with `now` so its
        // run-queue wait clock starts ticking.  This is the single place a
        // thread's `ready_since_tick` is set: doing it here (rather than at the
        // ~18 scattered Blocked→Ready / Running→Ready wake sites) keeps the
        // bookkeeping in one auditable spot and cannot be forgotten by a new
        // wake path.  The picker runs at least once per quantum and on every
        // yield/wake, so a freshly-Readied thread is stamped within ~1 tick of
        // becoming runnable — far finer than the ~200 ms `STARVE_AGE_TICKS`
        // threshold.  `now.max(1)` keeps 0 reserved as the "unstamped"
        // sentinel even on the (boot-only) tick 0.
        let now = crate::arch::x86_64::irq::get_ticks();
        let stamp = now.max(1);
        for t in threads.iter_mut() {
            if t.state == ThreadState::Ready {
                if t.ready_since_tick == 0 {
                    t.ready_since_tick = stamp;
                }
            } else if t.ready_since_tick != 0 {
                // Left the Ready state by some other path (e.g. re-Blocked
                // before ever running); drop the stale stamp so a future
                // Ready episode starts its wait clock fresh.
                t.ready_since_tick = 0;
            }
        }

        // ── Per-CPU runqueue mirror (Perf P2 phase 2a, behaviour-preserving) ──
        // Incrementally reconcile the per-CPU/per-priority runqueue structures
        // with this locked snapshot of the ready-set: a thread whose runqueue
        // membership is unchanged since the previous pass costs no queue
        // mutation (O(Δ) on the hot path), and a full table-derived audit runs
        // only once per `AUDIT_EVERY_PASSES` passes (amortized O(N)).  This
        // populates and continuously validates the new structure WITHOUT
        // influencing the pick below — the authoritative picker still selects
        // the next thread by scoring the table.  Lock order is respected
        // (THREAD_TABLE held here; the runqueue locks are leaves taken inside
        // `mirror_maintain`).  See `sched::percpu`.
        percpu::mirror_maintain(&mut threads);

        // ── Pick the next thread (Perf P2 phase 3a: AUTHORITATIVE per-CPU pick) ─
        // The selection is computed by `select_next` (the verbatim extraction of
        // the legacy in-line scoring/force picker) driven over THIS CPU's
        // runqueue membership instead of the whole table.
        //
        // The candidate sequence is the rotated `(current_idx + i) % len` walk —
        // the SAME rotation order the legacy picker used, so the strict-max
        // first-in-order tie-break is unchanged — but each index is admitted only
        // if the thread is enqueued on THIS CPU's runqueue, i.e. its
        // `mirror_slot` (stamped by `mirror_maintain` just above, in this same
        // locked pass) is `Some((cpu, _))`.  This restricts scoring to the
        // per-CPU Ready-eligible set while staying ALLOCATION-FREE on the pick
        // hot path: the candidate iterator is a lazy `filter` over the rotation
        // walk (no `Vec`, no runqueue-lock re-entry — the slot is read straight
        // off the locked thread record), which matters because `schedule()` runs
        // with interrupts disabled and the kernel heap lock is non-reentrant.
        //
        // Why this is the SAME decision as the legacy whole-table scan on SMP=1
        // (Perf P2 phase 2b, Test 648, proven for nine cases incl. score-aging
        // crossover, the TID-0 reactor and the rotation sweep): the runqueue's
        // non-idle pool (`mirror_slot == Some((cpu, _))`) is exactly the legacy
        // eligible non-idle Ready set on this CPU, and the idle pool the legacy
        // two-pass fallback would consider holds only AP-pinned idle threads
        // (TID >= 0x1000) that are never affinity-eligible on the BSP — so the
        // legacy idle fallback selects nothing the per-CPU path misses.  `now`,
        // `wait_age_bonus` and the per-thread force deadline are applied
        // identically by the shared `select_next`/`select_next_core`.
        //
        // `select_next` publishes READY_DEPTH and drives the force backstop
        // exactly as the inline picker did.  The candidate `filter` reads
        // `mirror_slot` (a plain field on the locked `Thread`), so the per-CPU
        // restriction costs one comparison per rotation step and no allocation.
        let percpu_cpu = cpu;
        let (best_idx, _ready_peers) = select_next(
            &threads,
            cpu,
            (1..len)
                .map(|i| (current_idx + i) % len)
                .filter(|&idx| matches!(threads[idx].mirror_slot, Some((c, _)) if c == percpu_cpu))
                // ── #655 on-CPU dispatch interlock (the dispatch chokepoint) ──
                // Skip-and-defer any candidate still live (current or on-stack)
                // on another CPU, so one thread is never dispatched onto two CPUs
                // at once (which would tear its single kernel stack's saved
                // switch frame in place).  Inert on SMP=1 (no other CPU) ⇒
                // bit-for-bit unchanged.  See `defer_if_live_on_other_cpu`.
                .filter(|&idx| !defer_if_live_on_other_cpu(threads[idx].tid, cpu as usize)),
            now,
        );

        // ── Cross-check: legacy whole-table scan agrees (debug feature only) ──
        // The legacy global scan is no longer the decider; it is retained ONLY
        // behind `sched-pick-xcheck` as an adversarial cross-check that the
        // authoritative per-CPU pick still selects the thread the old O(N)
        // table scan would have.  Gated on SMP=1 (where the two are provably
        // equivalent) and SAMPLED (every Nth pass) so the legacy O(N) re-scan
        // and its allocation never dominate the hot path.  A divergence is
        // recorded (`percpu::PICK_DIVERGENCES`) and logged but, the per-CPU
        // result being authoritative, never acted on — it is the live evidence
        // that the promotion is behaviour-preserving.
        #[cfg(feature = "sched-pick-xcheck")]
        if crate::arch::x86_64::apic::cpu_count() == 1
            && percpu::pick_xcheck_sample_due()
        {
            let legacy_idx = select_next_no_side_effects(
                &threads, cpu, (1..len).map(|i| (current_idx + i) % len), now);
            let legacy_tid = legacy_idx.map(|i| threads[i].tid);
            let percpu_tid = best_idx.map(|i| threads[i].tid);
            if legacy_tid != percpu_tid {
                percpu::note_pick_divergence();
                crate::serial_println!(
                    "[SCHED/P2] PICK DIVERGENCE cpu={} legacy_tid={:?} percpu_tid={:?} \
                     now={} current_tid={:?}",
                    cpu, legacy_tid, percpu_tid, now,
                    threads.get(current_idx).map(|t| t.tid),
                );
            }
        }

        match best_idx {
            Some(idx) => {
                // Mark current thread as Ready (unless it's Dead/Blocked/Sleeping).
                // IMPORTANT: Clear ctx_rsp_valid BEFORE marking Ready.  This prevents
                // other CPUs from picking up the thread with a stale kernel RSP (SMP
                // context-switch race guard).  switch_context_asm will set it back to
                // true atomically right after saving the new RSP.
                if let Some(cur) = threads.iter_mut().find(|t| t.tid == current_tid) {
                    if cur.state == ThreadState::Running {
                        cur.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
                        cur.state = ThreadState::Ready;
                    } else {
                        // Outgoing thread is NOT Running — it Blocked/Slept, or was
                        // marked Dead out-of-band by a sibling's `exit_group` while
                        // executing here.  We are still on its kernel stack until
                        // `switch_context_asm` below saves RSP, but `set_current_tid`
                        // (a few lines down) will stop publishing this tid as current.
                        // Clear ctx_rsp_valid so the cross-CPU reaper's gate
                        // (`Dead && !current_on_any_cpu && ctx_rsp_valid`) cannot free
                        // this still-in-use stack during the publish→switch window.
                        // `switch_context_asm` re-sets it true after saving RSP.
                        cur.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
                    }
                    // Decay priority boost here (outgoing thread, lock already held)
                    // rather than in the timer ISR to avoid 100 Hz try_lock overhead.
                    if cur.priority > cur.base_priority {
                        cur.priority -= 1;
                    }
                }

                // Mark next thread as Running and record which CPU it's on.
                threads[idx].state = ThreadState::Running;
                threads[idx].last_cpu = cpu;
                // This thread got the CPU — its run-queue wait is over.  Clear
                // the stamp so any escalating anti-starvation bonus resets and
                // its NEXT Ready episode times a fresh wait from zero.
                threads[idx].ready_since_tick = 0;
                let tid = threads[idx].tid;
                let rsp = threads[idx].context.rsp;
                let pid = threads[idx].pid;
                let kstack_top = if threads[idx].kernel_stack_base > 0 {
                    threads[idx].kernel_stack_base + threads[idx].kernel_stack_size
                } else { 0 };
                // Catch corrupted kernel_stack_base: kstack_top must be either 0
                // (idle/kernel thread) or a higher-half address.  A non-higher-half
                // value would set TSS.RSP[0] to user-space, causing a double fault
                // on the next Ring-3 exception.
                if kstack_top != 0 && kstack_top < 0xFFFF_8000_0000_0000 {
                    crate::serial_println!(
                        "[SCHED] PANIC: tid={} pid={} kernel_stack_base={:#x} size={:#x} kstack_top={:#x}",
                        threads[idx].tid, threads[idx].pid,
                        threads[idx].kernel_stack_base, threads[idx].kernel_stack_size, kstack_top
                    );
                    panic!("schedule(): non-higher-half kstack_top");
                }
                let first_run = threads[idx].first_run;
                break 'pick (tid, rsp, pid, kstack_top, first_run);
            }
            None => {
                // ── Leg 1: idle-path work-steal (Perf P2 phase 3d) ───────────
                // Nothing is Ready on THIS CPU's own mirror set.  Before halting
                // this CPU, try to PULL one runnable thread from a peer CPU's
                // runqueue and re-home it here, so a thread the wake path
                // enqueued on a stalled/dead-timer peer (whose own picker cannot
                // drain it) does not strand.  `try_steal_to` re-homes the
                // thread's `mirror_slot`/`last_cpu` to this CPU under the
                // THREAD_TABLE lock we already hold; on success we drop the lock
                // and retry the pick — the stolen thread is now on our mirror set
                // and the normal `select_next` path selects it.  Gated on
                // `cpu_count() > 1` so SMP=1 is bit-for-bit unchanged (no peer to
                // steal from).  Cheap to gate: only attempt the (worst-case O(N))
                // scan when more than one CPU exists and there is peer work — the
                // scan stops at the first eligible thread.
                if crate::arch::x86_64::apic::cpu_count() > 1 {
                    let ncpus = (crate::arch::x86_64::apic::cpu_count() as usize)
                        .min(crate::arch::x86_64::apic::MAX_CPUS);
                    // Only scan if SOME peer runqueue is non-empty (cheap O(ncpus)
                    // probe of the already-maintained nr_running counters), so the
                    // steal scan never runs on a genuinely-idle system.
                    let peer_work = (0..ncpus).any(|c| {
                        c != cpu as usize && percpu::rq_nr_running(c) > 0
                    });
                    if peer_work {
                        if percpu::try_steal_to(&mut threads, cpu, ncpus).is_some() {
                            drop(threads);
                            // A peer thread is now mirrored on this CPU; retry the
                            // pick so the normal path selects and switches to it.
                            continue 'pick;
                        }
                    }
                }
                // No Ready peer on this CPU right now.  Three cases for the
                // current thread:
                //
                //   Running             — return to caller.  The caller wanted
                //                         to yield/preempt but there's nothing
                //                         better to run on this CPU; reset the
                //                         watchdog and let the caller's spin
                //                         loop retry on the next tick.
                //
                //   Sleeping / Blocked  — drop the lock, `sti; hlt; cli`,
                //                         then `continue 'pick`.  The vCPU
                //                         halts so it does not starve peer
                //                         vCPUs of host CPU time under TCG;
                //                         the timer ISR (or any other wake
                //                         source — futex_wake, signal
                //                         delivery) flips our state to
                //                         Ready, and the next iteration's
                //                         picker selects us cleanly via the
                //                         normal context-switch path.  We
                //                         deliberately do NOT auto-self-
                //                         resume — only the wake source is
                //                         entitled to flip our state to
                //                         Ready, preserving the picker's
                //                         invariant (only Ready→Running
                //                         transitions happen under
                //                         THREAD_TABLE).
                //
                //   Dead                — drop the lock, `sti; hlt; cli` and
                //                         loop.  At least one peer thread
                //                         exists (len > 1) but none are
                //                         Ready right now; wait for the
                //                         timer ISR (or signal delivery
                //                         from another CPU) to flip a peer
                //                         to Ready, then continue 'pick.
                //                         Returning would sysretq into
                //                         dead user code.
                let current_state = threads
                    .iter()
                    .find(|t| t.tid == current_tid)
                    .map(|t| t.state);
                drop(threads);
                match current_state {
                    // Running, or freshly re-Readied by the due-wake drain at
                    // the top of this iteration: no OTHER peer is Ready, so the
                    // current thread is the one to run — return to the caller
                    // rather than HLT-ing it as a wedge.  This is the in-place
                    // self-resume of a thread whose own sleep/timeout deadline
                    // just elapsed.  A self-resume is a successful pick, so clear
                    // the per-CPU starvation burst (matches the `break 'pick`
                    // success path) — otherwise a thread that wedged briefly and
                    // then self-resumed would carry a stale burst into the next
                    // transient idle.
                    Some(ThreadState::Running) | Some(ThreadState::Ready) => {
                        clear_picker_burst();
                        crate::perf::record_idle_tick();
                        crate::arch::x86_64::irq::reset_watchdog_counter();
                        crate::hal::enable_interrupts();
                        return;
                    }
                    Some(ThreadState::Sleeping) | Some(ThreadState::Blocked) => {
                        crate::arch::x86_64::irq::reset_watchdog_counter();
                        crate::perf::record_idle_tick();
                        if note_picker_hlt(current_tid) {
                            crate::serial_println!(
                                "[SCHED/STARVE] tid={} state=Sleeping/Blocked (peers exist but none ready) \
                                 burst={} — runqueue stuck for >2 s; check peer wake hooks",
                                current_tid, STARVATION_BURST_THRESHOLD,
                            );
                        }
                        crate::arch::x86_64::irq::sched_wait_quantum();
                        // Re-check SCHEDULER_ACTIVE after waking from hlt.
                        // sched::disable() on another CPU silently disarms
                        // timer_tick_schedule()'s wake hooks, so without
                        // this guard the loop would spin sti;hlt;cli forever.
                        if !is_active() {
                            crate::hal::enable_interrupts();
                            return;
                        }
                        continue 'pick;
                    }
                    _ => {
                        // Dead, or already reaped.  Halt until a peer
                        // becomes Ready.
                        crate::arch::x86_64::irq::reset_watchdog_counter();
                        crate::perf::record_idle_tick();
                        if note_picker_hlt(current_tid) {
                            crate::serial_println!(
                                "[SCHED/STARVE] tid={} state=Dead/reaped (peers exist but none ready) \
                                 burst={} — runqueue wedged; no peer wake source firing",
                                current_tid, STARVATION_BURST_THRESHOLD,
                            );
                        }
                        crate::arch::x86_64::irq::sched_wait_quantum();
                        // See is_active() recheck rationale above.
                        if !is_active() {
                            crate::hal::enable_interrupts();
                            return;
                        }
                        continue 'pick;
                    }
                }
            }
        }
    };

    // ── Picker succeeded: reset the per-CPU starvation burst ─────────────
    // Reaching here means a Ready peer was selected; clear the per-CPU
    // burst counter so subsequent legitimate idle on a quiet system does
    // not inherit a stale burst from an earlier transient wedge.
    clear_picker_burst();

    if next_tid == current_tid {
        crate::arch::x86_64::irq::reset_watchdog_counter();
        crate::hal::enable_interrupts();
        return; // No switch needed.
    }

    // Record performance metric
    crate::perf::record_context_switch();

    // Perform context switch.  Update both the per-CPU TID and PID atomics
    // together so the page-fault handler's lockless current_pid_lockless()
    // sees a consistent (tid, pid) pair across the switch.
    proc::set_current_tid(next_tid);
    proc::set_current_pid(next_pid);

    TICKS_REMAINING[cpu as usize].store(TIME_SLICE, Ordering::Relaxed);

    // Update TSS.rsp[0] and SYSCALL_KERNEL_RSP for the next thread.
    // This ensures that interrupts and SYSCALL from Ring 3 land on the
    // correct kernel stack for the newly-scheduled thread.
    // next_kstack_top was extracted from the main scheduling lock above.
    unsafe {
        if next_kstack_top > 0 {
            crate::arch::x86_64::gdt::update_tss_rsp0(next_kstack_top);
            crate::syscall::set_kernel_rsp(next_kstack_top);
        } else {
            // Switching to idle/kernel thread with no dedicated stack.
            // Invalidate kernel_rsp so recover_current_tid() slow-path
            // does not misidentify this thread as the previous user thread.
            crate::syscall::set_kernel_rsp(0);
        }
    }

    // ── Per-process address space switch (DEFERRED) ─────────────────
    //
    // The CR3 switch is done AFTER switch_context, not before.
    //
    // Reason: The outgoing thread may be TID 0 (BSP idle) which runs on the
    // UEFI bootstrap stack at a physical address in PML4[0] (identity-mapped).
    // If we switch CR3 to a user page table here (before switch_context), the
    // identity map in PML4[0] is replaced by user mappings and the bootstrap
    // stack becomes unmapped — the next stack access causes a double fault.
    //
    // By deferring the CR3 switch to after switch_context, we're already on
    // the incoming thread's kernel stack (higher-half, PML4[256-511], shared
    // across all page tables) so the switch is safe.
    //
    // EXCEPTION: first-run threads skip the CR3 switch entirely here.
    // user_mode_bootstrap() handles it after the initial context switch.

    // Get raw pointers to the current thread's RSP and ctx_rsp_valid fields,
    // and save FPU state, all in a single lock acquisition.  The lock must be
    // released before switch_context (which won't return until rescheduled).
    // If the current thread has already been removed from the table (e.g. it
    // called exit_group and was reaped before schedule() ran), use a throwaway
    // stack location for the RSP save — we will never return to this thread.
    let mut _dead_rsp: u64 = 0;
    static DEAD_VALID: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    let (old_rsp_ptr, ctx_valid_ptr) = {
        let mut threads = THREAD_TABLE.lock();
        if let Some(cur) = threads.iter_mut().find(|t| t.tid == current_tid) {
            // ── FPU/SSE state save for outgoing thread ─────────────────────
            if cur.fpu_state.is_none() {
                cur.fpu_state = Some(alloc::boxed::Box::new(proc::FpuState::new_zeroed()));
            }
            if let Some(ref mut fpu) = cur.fpu_state {
                unsafe {
                    core::arch::asm!(
                        "fxsave [{}]",
                        in(reg) fpu.data.as_mut_ptr(),
                        options(nostack, preserves_flags),
                    );
                }
            }
            (
                &mut cur.context.rsp as *mut u64,
                cur.ctx_rsp_valid.as_ptr() as *mut u8,
            )
        } else {
            // Thread already cleaned up — use throwaway storage.
            (&mut _dead_rsp as *mut u64, DEAD_VALID.as_ptr())
        }
    };

    // SAFETY: old_rsp_ptr and new_rsp are valid. switch_context saves/restores
    // all callee-saved registers and switches stacks.
    // Note: interrupts are disabled (CLI). The switched-to thread will either:
    //   - IRETQ to Ring 3 with IF=1 (new user thread)
    //   - Return here and re-enable below (resumed kernel thread)
    // ctx_valid_ptr: switch_context_asm sets *ctx_valid_ptr = 1 after saving
    // old_rsp, preventing other CPUs from using a stale RSP (SMP race guard).
    // Debug: warn if we're loading a non-higher-half RSP (indicates corruption).
    //
    // Exception: the BSP idle thread (tid=0) and the AP idle threads
    // (tid >= 0x1000) intentionally execute on identity-mapped low addresses —
    // tid=0 keeps the UEFI bootstrap stack (PML4[0] identity map) and AP idle
    // threads have context.rsp=0 until their first switch.  Both are safe by
    // construction; emitting a WARN every time the BSP idle is scheduled-back
    // is just noise and floods the serial log on TCG runners where tests
    // round-trip through the idle thread frequently.
    let next_is_idle = next_tid == 0 || next_tid >= 0x1000;
    if !next_is_idle && next_rsp != 0 && next_rsp < 0xFFFF_8000_0000_0000 {
        crate::serial_println!(
            "[SCHED] WARN cpu={} cur_tid={} → next_tid={} next_rsp={:#x} (NOT higher-half!)",
            cpu, current_tid, next_tid, next_rsp
        );
    }

    // ── Pre-switch: ensure kernel CR3 for switch_context ────────────
    // All kernel stacks are in the higher-half (PML4[256-511]), which is
    // shared across all page tables.  However, the UEFI bootstrap stack
    // (TID 0) is identity-mapped and requires the kernel CR3 to be active.
    // Switch to kernel CR3 unconditionally before switch_context.
    {
        let kernel_cr3 = crate::mm::vmm::get_kernel_cr3();
        let current_cr3 = crate::mm::vmm::get_cr3();
        if kernel_cr3 != 0 && current_cr3 != kernel_cr3 {
            // See note in the unconditional CR3-load block below.
            // Order: set NEW bit → switch hardware CR3 → clear OLD bit.
            crate::mm::tlb::note_cr3_load(kernel_cr3);
            unsafe { crate::mm::vmm::switch_cr3(kernel_cr3); }
            crate::mm::tlb::note_cr3_unload(current_cr3);
        }
    }

    // ── #582 diagnostic: disarm the RFLAGS-slot watch if it belongs to the
    //    thread we are about to resume ────────────────────────────────────
    // On resume, `next_tid`'s saved-RFLAGS slot becomes live stack within
    // its running frame; leaving the watch armed across the resume turns
    // every ordinary store to that reclaimed slot into a false-positive
    // `#DB`.  Disarm here (we know `next_tid`), so the watch only ever fires
    // while the watched victim is genuinely parked.  See `db582`.
    #[cfg(feature = "582-diag")]
    {
        crate::arch::x86_64::debug_reg::d582_disarm_if_tid(next_tid as u64);
    }

    unsafe {
        proc::thread::switch_context(old_rsp_ptr, next_rsp, ctx_valid_ptr);
    }

    // ── Resumed after being rescheduled back onto this thread ───────
    // Interrupts are still disabled (CLI was set by whoever rescheduled us).

    // This CPU has just completed a context switch and is now executing on
    // the incoming thread's kernel stack.  Bump the per-CPU switch
    // generation so any dead stack whose `last_cpu` is this CPU (and which
    // was reaped before this switch) becomes eligible for recycle — it is
    // now proven that this CPU is no longer on the recycled stack VA.  See
    // `CPU_SWITCH_GEN` / `note_switch_completed`.  (First-run threads jump
    // to `user_mode_bootstrap` and never reach this line; they bump there.)
    note_switch_completed();

    // ── #582 diagnostic: arm a DR0 write-watch on the DEPARTED victim's
    //    saved-RFLAGS slot ────────────────────────────────────────────────
    //
    // We have just switched AWAY from `current_tid` and are now running as
    // `next_tid`.  `current_tid`'s `switch_context_asm` frame is therefore
    // fully saved: `Thread::context.rsp` points at the qword the `pushfq`
    // last stored (the saved-RFLAGS slot, `context.rsp + 0`).  If that slot
    // currently reads the healthy `0x202`, arm an 8-byte data-write watch on
    // it (DR0).  Any subsequent 8-byte store to that slot — while the victim
    // sits Ready/Blocked — raises `#DB` on the writing CPU; the fire path
    // (`db582::record_fire`) classifies the writer as the legitimate
    // `switch_context_asm` re-save (benign) versus an out-of-band RIP (the
    // #582 catch).  Re-armable: the watch rotates onto a fresh victim each
    // time it is not currently watching one of equal address.  Gated on
    // `582-diag`; zero cost in production builds.  See `arch::x86_64::db582`.
    #[cfg(feature = "582-diag")]
    {
        // SAMPLED rotation: re-arm only once every `D582_SAMPLE_PERIOD`
        // resumed switches on this CPU.  Each armed slot fires a `#DB` per
        // store to it, so arming on EVERY switch traps at the switch rate
        // and slows the system into the `[SCHED/STARVE]` wedge before the
        // (timing-sensitive) #582 race can fire — and risks perturbing the
        // race away.  Sampling 1-in-N keeps the trap overhead ~N× lower
        // while still rotating across the diverse thread population over a
        // run.  The counter is per-CPU and Relaxed (diagnostic only).
        const D582_SAMPLE_PERIOD: u64 = 32;
        let do_sample = {
            let c = D582_SAMPLE_CTR[cpu as usize]
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            c % D582_SAMPLE_PERIOD == 0
        };
        // Read the slot value AND gate on healthy WHILE STILL HOLDING the
        // table lock, so the saved-RSP VA cannot be reaped/recycled between
        // the lookup and the read (no TOCTOU on a dereference of a possibly-
        // freed kstack).  The slot is a higher-half kernel-stack VA mapped
        // in every CR3 (PML4[256-511]); the read is well-defined under the
        // kernel CR3 active at this resume point.
        let victim_rflags_slot = {
            let threads = THREAD_TABLE.lock();
            threads
                .iter()
                .find(|t| t.tid == current_tid)
                .filter(|t| {
                    // Only watch a victim that actually saved a frame (its
                    // ctx_rsp_valid is set by switch_context_asm) and whose
                    // saved RSP is a higher-half kernel-stack VA.
                    t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire)
                        && t.context.rsp >= 0xFFFF_8000_0000_0000
                })
                .and_then(|t| {
                    let slot_va = t.context.rsp;
                    // Gate on the slot reading *structurally healthy* before
                    // arming so we never start a watch on an already-torn slot
                    // (which would mis-attribute the tear to the next benign
                    // writer).  A live thread's saved `pushfq` carries
                    // condition-code flags (ZF/SF/PF/CF/OF) in addition to
                    // IF, so an exact `0x202` match would reject almost every
                    // real frame; the #582 signature is specifically TF (bit
                    // 8) SET, so "healthy" = reserved-bit-1 set, IF set, TF
                    // clear (Intel SDM Vol. 1 §3.4.3).
                    let val = unsafe { core::ptr::read_volatile(slot_va as *const u64) };
                    if crate::arch::x86_64::db582::rflags_is_healthy(val) {
                        Some(slot_va)
                    } else {
                        None
                    }
                })
        };
        if let (true, Some(slot_va)) = (do_sample, victim_rflags_slot) {
            // Rotation policy: on a sampled switch, re-arm on the
            // JUST-DEPARTED victim (replacing any prior watch).  The freshest
            // departed victim is the one whose CPU may still be in the
            // `switch_context_asm` restore epilogue / whose TSS.RSP0 may be
            // stale, i.e. the one most exposed to the #582 tear.  False
            // positives from the owner's own-stack reuse are filtered
            // downstream (`db582::record_fire` writer-vs-owner check) and on
            // resume (`d582_disarm_if_tid`).  Avoid a redundant re-arm when
            // DR0 already watches this exact slot.  Record `current_tid` as
            // owner so the resume-disarm + foreign-writer test can match.
            if crate::arch::x86_64::debug_reg::d582_armed_addr() != slot_va {
                crate::arch::x86_64::debug_reg::arm_d582_rflags_watchpoint_for(
                    slot_va, current_tid as u64,
                );
            }
        }
    }

    // ── FPU/SSE state restore for incoming thread ───────────────────
    {
        let current_tid_now = proc::current_tid();
        let threads = THREAD_TABLE.lock();
        if let Some(cur) = threads.iter().find(|t| t.tid == current_tid_now) {
            if let Some(ref fpu) = cur.fpu_state {
                unsafe {
                    core::arch::asm!(
                        "fxrstor [{}]",
                        in(reg) fpu.data.as_ptr(),
                        options(nostack, preserves_flags),
                    );
                }
            }
        }
    }

    // ── TLS: restore FS base for incoming thread ────────────────────
    proc::restore_tls_for_current();

    // ── Unconditional CR3 load (NT SwapContext model) ────────────────
    // After switch_context, we're on the incoming thread's kernel stack.
    // ALWAYS load the correct CR3 for this thread's process.  This is
    // the NT approach (SwapContext unconditionally loads DirectoryTableBase)
    // rather than Linux's lazy TLB.  Eliminates all CR3 race conditions.
    //
    // For first-run threads: switch_context jumped to user_mode_bootstrap
    // which handles its own CR3 switch — this code is never reached.
    //
    // For idle/kernel threads (process cr3 == 0): fall back to kernel_cr3.
    // For user threads: load the process's user CR3.
    {
        let current_pid_now = proc::current_pid();
        let target_cr3 = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == current_pid_now)
                .map(|p| p.cr3).unwrap_or(0)
        };
        let effective_cr3 = if target_cr3 != 0 {
            target_cr3
        } else {
            crate::mm::vmm::get_kernel_cr3()
        };
        let current_cr3 = crate::mm::vmm::get_cr3();
        if effective_cr3 != current_cr3 {
            // Update the per-CR3 active-CPU mask in tandem with the
            // hardware CR3 load.  Order: set the bit for the NEW CR3
            // BEFORE the hardware write, then write CR3, then clear
            // the bit for the OLD CR3.  This guarantees that at every
            // intermediate state at least one of the two masks names
            // this CPU; a concurrent shootdown for either CR3 will
            // still target us, and the IPI handler's running-CR3
            // equality check prevents it from invalidating the wrong
            // TLB.  The earlier order (unload → switch → load) left a
            // window in which neither bit was set and a shootdown for
            // the new CR3 could miss this CPU.  See mm/tlb.rs.
            crate::mm::tlb::note_cr3_load(effective_cr3);
            unsafe { crate::mm::vmm::switch_cr3(effective_cr3); }
            crate::mm::tlb::note_cr3_unload(current_cr3);
        }

        // Idle thread invariant: PID 0 must always have kernel CR3.
        if current_pid_now == 0 {
            let kcr3 = crate::mm::vmm::get_kernel_cr3();
            if effective_cr3 != kcr3 {
                crate::ke::bugcheck::ke_bugcheck(
                    crate::ke::bugcheck::BUGCHECK_BAD_KERNEL_RSP,
                    effective_cr3, kcr3, current_pid_now as u64, 0,
                );
            }
        }
    }

    // ── Reset watchdog counter: this CPU just completed a context switch ──
    crate::arch::x86_64::irq::reset_watchdog_counter();

    // Re-enable interrupts now that all locks are released.
    crate::hal::enable_interrupts();
}

/// Yield the current thread's time slice voluntarily.
pub fn yield_cpu() {
    schedule();
}

/// Get scheduler statistics.
pub fn stats() -> (u64, u64) {
    let threads = THREAD_TABLE.lock();
    let ready = threads.iter().filter(|t| t.state == ThreadState::Ready).count() as u64;
    let total = threads.len() as u64;
    (ready, total)
}

/// Get the total number of timer ticks since boot.
pub fn total_ticks() -> u64 {
    crate::arch::x86_64::irq::get_ticks()
}
