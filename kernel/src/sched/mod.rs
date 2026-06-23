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
/// deadline than the compute-bound workers it competes with.  8 ticks (≈80 ms,
/// at TICK_HZ = 100) keeps the reactor running at ~10+ Hz even when a 50+-thread
/// userspace workload saturates the run-queue, so the network/compositor pump
/// keeps draining and a page load can actually complete and composite.  The
/// score-based aging usually selects TID 0 even sooner; this deadline bounds the
/// reactor's worst-case latency well below the coarse `STARVE_FORCE_TICKS`
/// global ceiling.
const STARVE_FORCE_TICKS_BSP: u64 = 8;

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

/// Reap dead threads and free their kernel stacks.
///
/// MUST be called with interrupts already disabled so that pmm::free_page()
/// cannot deadlock with a concurrent timer ISR that also acquires PMM_LOCK.
/// Called at the start of schedule() which guarantees IF=0 via disable_interrupts().
fn reap_dead_threads_sched() {
    use crate::proc::KERNEL_VIRT_OFFSET;

    // IMPORTANT: Never reap the CURRENT thread. The caller is still running on
    // its kernel stack — freeing the stack while executing on it is a UAF.
    // The current thread will be reaped the next time a DIFFERENT thread calls
    // schedule() and runs this function (with a different current_tid).
    let current_tid = crate::proc::current_tid();

    // Collect (stack_base, stack_pages, last_cpu) for each reapable thread,
    // removing them from THREAD_TABLE in the same pass.  `last_cpu` feeds the
    // per-CPU switch-generation quiescence gate (see `CPU_SWITCH_GEN`).
    let stacks: alloc::vec::Vec<(u64, usize, usize)> = {
        let mut threads = THREAD_TABLE.lock();
        // A Dead thread is safe to reap only when ctx_rsp_valid == true, which
        // switch_context_asm sets AFTER saving the thread's RSP (meaning the CPU
        // has left or is about to leave the thread's kernel stack).  Exit paths
        // (exit_thread/exit_group) set ctx_rsp_valid=false before calling schedule(),
        // preventing the AP from freeing the stack while the BSP is still on it.
        let dead_indices: alloc::vec::Vec<usize> = threads.iter().enumerate()
            .filter(|(_, t)| {
                t.is_reapable()
                    && t.tid != current_tid
                    && t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire)
            })
            .map(|(i, _)| i)
            .collect();
        if dead_indices.is_empty() {
            return;
        }
        let mut out = alloc::vec::Vec::with_capacity(dead_indices.len());
        for &idx in dead_indices.iter().rev() {
            let t = &threads[idx];
            let base = t.kernel_stack_base;
            let pages = if t.kernel_stack_size > 0 {
                (t.kernel_stack_size as usize + 4095) / 4096
            } else { 0 };
            let last_cpu = t.last_cpu as usize;
            threads.swap_remove(idx);
            if base > 0 && pages > 0 {
                out.push((base, pages, last_cpu));
            }
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
    for (stack_base, stack_pages, last_cpu) in stacks {
        if stack_pages == crate::proc::KERNEL_STACK_PAGES_PUB {
            let stack_size_bytes = (stack_pages as u64) * 0x1000;
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
        // Cache full or non-standard size — free to PMM.
        #[cfg(feature = "test-mode")]
        crate::serial_println!(
            "[KSTACK/REAP] cache full or non-std size={} — freed to PMM base={:#x}",
            stack_pages, stack_base);
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
                    unsafe {
                        core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
                    }
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
                    unsafe {
                        core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
                    }
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

        // ── Per-CPU runqueue mirror (Perf P2 phase 1, behaviour-preserving) ──
        // Rebuild the per-CPU/per-priority runqueue structures from this locked
        // snapshot of the ready-set and self-verify their bitmap/nr_running
        // invariants and membership against the authoritative table.  This
        // populates and continuously validates the new structure WITHOUT
        // influencing the pick below — the authoritative picker still selects
        // the next thread by scoring the table.  Lock order is respected
        // (THREAD_TABLE held here; the runqueue locks are leaves taken inside
        // `mirror_rebuild_and_verify`).  See `sched::percpu`.
        percpu::mirror_rebuild_and_verify(&threads);

        // Find the highest-priority Ready thread with affinity awareness.
        // Scoring: priority * 4 + affinity_bonus (0-2)
        //   - affinity match (pinned to this cpu): +2
        //   - last_cpu match (cache-warm): +1
        //   - no match: +0
        //
        // INVARIANT (POSIX SCHED_OTHER hardening): a CPU MUST NEVER pick an idle thread
        // while a non-idle Ready peer exists.  POSIX SCHED_OTHER and sched(7)
        // both require that the per-CPU idle thread is the "schedule of last
        // resort" — it runs ONLY when no runnable user/kernel work is
        // available on this CPU.  The picker enforces this by doing TWO
        // passes: pass 1 considers only NON-IDLE Ready peers; pass 2 (run
        // only when pass 1 finds nothing) considers idle peers.  Without the
        // two-pass split, a per-CPU idle thread with `cpu_affinity=Some(cpu)`
        // (+2 affinity bonus) could in principle tie or beat a worker that
        // has never run on this CPU (+0) at sufficiently low worker priority,
        // even though SCHED_OTHER says workers must always win.  The two-pass
        // structure also reads as a clear invariant in the source, making
        // future picker edits less likely to regress.
        let mut best_idx: Option<usize> = None;
        let mut best_score: u16 = 0;
        let mut idle_best_idx: Option<usize> = None;
        let mut idle_best_score: u16 = 0;
        // Anti-starvation backstop: the schedulable-on-this-CPU Ready peer that
        // is the most OVERDUE relative to its own force-deadline.  Each thread
        // has a per-thread deadline — `STARVE_FORCE_TICKS_BSP` for the BSP poll
        // reactor (TID 0), `STARVE_FORCE_TICKS` for everyone else — so the
        // latency-critical reactor becomes force-eligible far sooner than a
        // compute-bound worker.  We track the candidate with the largest
        // `wait_age - deadline` (its overdue margin); a non-overdue thread has a
        // negative margin and is never the force pick.  `force_age` records that
        // winner's raw wait age for the diagnostic.  Idle threads (TID >=
        // 0x1000) are deliberately excluded — they are the schedule-of-last-
        // resort and must never pre-empt real work via the backstop.
        let mut force_idx: Option<usize> = None;
        let mut force_age: u64 = 0;
        // Most-overdue margin seen so far (`wait_age - deadline`), as a signed
        // value.  `i64::MIN` means "no overdue candidate yet".
        let mut force_margin: i64 = i64::MIN;
        // Run-queue depth: count of non-idle Ready peers considered this pass.
        // Published lock-free into READY_DEPTH after the scan so disk-I/O
        // waiters (and the wait-amplification histogram) can read, without the
        // table lock, how many runnable peers a yield competes against.
        let mut ready_peers: u64 = 0;

        for i in 1..len {
            let idx = (current_idx + i) % len;
            let t = &threads[idx];
            if t.state != ThreadState::Ready {
                continue;
            }
            if t.tid < 0x1000 {
                // Non-idle Ready peer (idle threads are TID >= 0x1000); count it
                // toward the run-queue depth before any affinity/validity skips
                // so the metric reflects total runnable work, not just
                // this-CPU-eligible work.
                ready_peers += 1;
            }
            // Skip threads whose kernel RSP is not yet valid — another CPU is
            // mid-way through switching them out and hasn't saved the new RSP
            // yet.  Picking up such a thread would resume it from a stale RSP.
            if !t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire) {
                continue;
            }
            // Skip threads pinned to a different CPU.
            if let Some(aff) = t.cpu_affinity {
                if aff != cpu {
                    continue;
                }
            }

            // Run-queue wait age (ticks) for the anti-starvation terms.  The
            // lazy-stamp pass above guarantees `ready_since_tick != 0` for any
            // Ready thread by the time we get here; `saturating_sub` keeps the
            // arithmetic safe against a non-monotone read in the unlikely event
            // a stamp landed a tick ahead of `now`.
            let wait_age = now.saturating_sub(t.ready_since_tick);
            let is_idle_thread = t.tid >= 0x1000;

            let mut score = (t.priority as u16) * 4;
            if t.cpu_affinity == Some(cpu) {
                score += 2; // Pinned to us — strong preference.
            } else if t.last_cpu == cpu {
                score += 1; // Ran here last — cache-warm preference.
            }
            // Anti-starvation aging: a Ready thread that has been passed over
            // long enough earns an escalating, capped score bonus so it cannot
            // be out-competed forever by continuously wake-boosted peers.  Only
            // real (non-idle) work ages — idle threads must stay the schedule
            // of last resort.  See `wait_age_bonus` / `STARVE_*`.
            if !is_idle_thread {
                score += wait_age_bonus(wait_age);
                // Track the most-overdue real Ready peer for the hard backstop,
                // each measured against its OWN force-deadline.  The BSP poll
                // reactor (TID 0) gets the tighter `STARVE_FORCE_TICKS_BSP`
                // deadline so it becomes force-eligible (and wins the most-
                // overdue comparison) well before any worker on the coarse
                // global ceiling.  `margin = wait_age - deadline`; positive ⇒
                // overdue.  Comparing margins (not raw ages) means a worker that
                // has waited longer in absolute terms does not steal the force
                // pick from a reactor that is further past its own deadline.
                let deadline: u64 = if t.tid == 0 {
                    STARVE_FORCE_TICKS_BSP
                } else {
                    STARVE_FORCE_TICKS
                };
                let margin = wait_age as i64 - deadline as i64;
                if margin > force_margin {
                    force_margin = margin;
                    force_age = wait_age;
                    force_idx = Some(idx);
                }
            }

            // AP idle threads (TID >= 0x1000 + apic_id, see
            // arch/x86_64/apic.rs) are constructed at PRIORITY_IDLE with
            // a per-CPU affinity pin and exist purely to give the AP a
            // Ready thread to context-switch through when no other work
            // is available.  Route them to the idle pool so non-idle
            // peers always win pass 1.
            //
            // NB: the BSP idle thread (TID 0) is intentionally NOT in
            // the idle pool.  TID 0 doubles as the BSP main thread that
            // drives the kernel's polling loops (net::poll, x11::poll,
            // gui::compositor::compose, the firefox-test heartbeat,
            // etc.) — work that must keep advancing under load.
            // Classifying TID 0 as idle would starve those polls when
            // user threads saturate CPU 0, hanging the network stack and
            // the framebuffer compositor.  Treat TID 0 as an ordinary
            // PRIORITY_IDLE peer that loses to higher-priority workers
            // on score alone but never falls into the schedule-of-last-
            // resort bucket.  (`is_idle_thread` is computed once above, before
            // the anti-starvation aging block.)
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

        // Publish the run-queue depth observed this pass (lock-free, relaxed —
        // a diagnostic estimate, not a synchronisation point).
        READY_DEPTH.store(ready_peers, Ordering::Relaxed);

        // Pass 2 fallback: if no non-idle Ready peer is available on this
        // CPU, fall through to the idle thread.  This preserves the
        // existing "no work → HLT" behaviour for genuinely idle systems
        // while honouring the invariant above when work IS available.
        if best_idx.is_none() {
            best_idx = idle_best_idx;
            best_score = idle_best_score;
        }

        // Anti-starvation backstop (hard guarantee): if the most-overdue real
        // Ready peer on this CPU is at or past its OWN force-deadline
        // (`force_margin >= 0` ⇔ `wait_age >= deadline`), force-select it this
        // tick regardless of score.
        //
        // For ordinary same-base-priority contention the widened, escalating
        // `wait_age_bonus` (cap = full base-priority span) wins the score
        // comparison first, so a starved worker is rescued by score-aging well
        // before this backstop — the backstop is then a true last resort.
        //
        // For the `PRIORITY_IDLE` BSP poll reactor (TID 0) the split is
        // deliberate: its score-bonus can only overtake a continuously
        // wake-boosted `PRIORITY_NORMAL` storm after ~100 ticks of aging, so the
        // reactor is intentionally rescued by its TIGHT per-thread deadline
        // (`STARVE_FORCE_TICKS_BSP`, ~80 ms) — the score path is its backstop's
        // backstop, not its primary rescue.  The tight deadline is exactly the
        // virtual-deadline treatment a fair scheduler gives an early-yielding
        // latency-sensitive task, bounding the net/x11/compositor pump's
        // run-queue latency at ~80 ms instead of the ~1 s global ceiling that
        // applies to compute-bound workers.
        //
        // This mirrors the balance-set-manager force-boost of starved Ready
        // threads and the virtual-deadline guarantee that the longest-overdue
        // runnable task eventually runs.  Only fires when the forced thread is
        // not already the best pick (avoids a redundant override) and is
        // non-idle (tracked that way in `force_idx`).
        if force_margin >= 0 {
            if let Some(fidx) = force_idx {
                if best_idx != Some(fidx) {
                    let n = SCHED_STARVE_FORCE_TOTAL.fetch_add(1, Ordering::Relaxed);
                    let deadline: u64 = if threads[fidx].tid == 0 {
                        STARVE_FORCE_TICKS_BSP
                    } else {
                        STARVE_FORCE_TICKS
                    };
                    // Throttle the diagnostic: emit the first force-select and
                    // then one per `STARVE_FORCE_LOG_EVERY` thereafter.  Under
                    // sustained contention (e.g. a busy poll thread that
                    // re-starves ~1 Hz) an unthrottled line per event would
                    // flood the serial log; the monotone counter
                    // (`starve_force_count()`) stays the authoritative rate
                    // source for tooling.
                    if n == 0 || n % STARVE_FORCE_LOG_EVERY == 0 {
                        crate::serial_println!(
                            "[SCHED/STARVE] force-select tid={} (waited {} ticks >= {}) on cpu={} \
                             total={} — anti-starvation backstop",
                            threads[fidx].tid, force_age, deadline, cpu, n + 1,
                        );
                    }
                    best_idx = Some(fidx);
                    best_score = (threads[fidx].priority as u16) * 4;
                }
            }
        }
        let _ = best_score; // suppress "unused" if later edits drop the read

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
                        unsafe {
                            core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
                        }
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
                        unsafe {
                            core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
                        }
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
