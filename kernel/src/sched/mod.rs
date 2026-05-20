//! CoreSched — The AstryxOS Scheduler
//!
//! Implements a round-robin cooperative/preemptive scheduler.
//! The timer interrupt calls `timer_tick_schedule()` which triggers
//! context switches at the end of each time quantum.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::proc::{self, ThreadState, THREAD_TABLE};
use crate::arch::x86_64::apic::MAX_CPUS;

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

/// Snapshot of the cumulative starvation events.  An increment indicates
/// the picker held the same thread for `STARVATION_BURST_THRESHOLD`
/// consecutive HLT cycles without a successful pick.
pub fn starvation_count() -> u64 {
    SCHED_STARVATION_TOTAL.load(Ordering::Relaxed)
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

/// Wake any threads whose sleep time has elapsed.
/// Also wakes blocked threads whose wait timeout has expired.
/// Uses try_lock since this is called from interrupt context —
/// if THREAD_TABLE is already held, skip this tick (wakeups will
/// be caught on the next timer tick).
fn wake_sleeping_threads() {
    let now = crate::arch::x86_64::irq::get_ticks();
    let mut threads = match THREAD_TABLE.try_lock() {
        Some(guard) => guard,
        None => return, // Lock held — skip this tick.
    };
    for t in threads.iter_mut() {
        if t.state == ThreadState::Sleeping && now >= t.wake_tick {
            t.state = ThreadState::Ready;
        }
        // Wake blocked threads whose timeout has expired.
        // The thread will resume in wait_for_single_object / wait_for_multiple_objects,
        // discover that its WaitBlock was NOT satisfied, and return Timeout.
        if t.state == ThreadState::Blocked && t.wake_tick != u64::MAX && now >= t.wake_tick {
            t.state = ThreadState::Ready;
        }
    }
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

    // Collect (stack_base, stack_pages) for each reapable thread, removing
    // them from THREAD_TABLE in the same pass.
    let stacks: alloc::vec::Vec<(u64, usize)> = {
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
            threads.swap_remove(idx);
            if base > 0 && pages > 0 {
                out.push((base, pages));
            }
        }
        out
    }; // THREAD_TABLE released before any PMM operations

    // Return kernel stacks to the dead-stack cache for reuse (NT pattern:
    // MmDeadStackSListHead).  Only cache stacks of the standard size.
    // Overflow goes to PMM free as before.
    for (stack_base, stack_pages) in stacks {
        if stack_pages == crate::proc::KERNEL_STACK_PAGES_PUB {
            if push_dead_stack(stack_base) {
                continue; // cached for reuse
            }
        }
        // Cache full or non-standard size — free to PMM.
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
/// every CPU that was actively counting timer ticks at push time has
/// advanced its per-CPU timer-ISR counter by at least this many ticks since
/// the push.  N=2 gives one full timer period of slack beyond the minimum
/// "the CPU has fired its ISR once since push", protecting against the
/// degenerate case where a CPU was already inside the timer ISR (between
/// the `TIMER_ISR_PER_CPU.fetch_add` and the eventual `iretq`) at the
/// instant push() snapshotted its counter — that single increment is then
/// not in fact a quiescent state for the rest of the ISR body.
///
/// At TICK_HZ=100 (see `arch::x86_64::irq::TICK_HZ`) this is a worst-case
/// 20 ms reuse delay per cached kstack — negligible against the multi-
/// millisecond cost of falling back to `pmm::alloc_pages(KERNEL_STACK_PAGES)`
/// under PMM fragmentation, and orders of magnitude smaller than thread
/// creation latency.
const DEAD_STACK_QUIESCE_TICKS: u64 = 2;

/// One cached dead stack: the higher-half kernel-stack base plus the
/// per-CPU timer-ISR tick counter snapshot taken at push time.
///
/// Generation snapshot: `push_gen[i]` is the value of
/// `arch::x86_64::irq::TIMER_ISR_PER_CPU[i]` observed by the pushing CPU
/// at push time.  At pop time we require, for every CPU `i` where
/// `push_gen[i] != 0` (i.e. CPU i was actively counting ticks at push),
/// that `TIMER_ISR_PER_CPU[i] >= push_gen[i] + DEAD_STACK_QUIESCE_TICKS`.
/// Only when every such CPU has independently advanced through that many
/// timer interrupts since the push do we hand the stack back out.
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
    /// Per-CPU timer-ISR tick counter snapshot at push time.
    /// `push_gen[i] == 0` means CPU i was not counting ticks at push
    /// (offline / never ticked) — that CPU does not gate quiescence.
    push_gen: [u64; MAX_CPUS],
}

static DEAD_STACK_CACHE: spin::Mutex<alloc::vec::Vec<CachedDeadStack>> =
    spin::Mutex::new(alloc::vec::Vec::new());

/// Snapshot the per-CPU timer-ISR tick counters into a `push_gen` array.
///
/// Reads `arch::x86_64::irq::TIMER_ISR_PER_CPU` with `Relaxed` ordering;
/// these counters are monotone-increasing and any race producing a stale
/// (lower) read only delays quiescence by at most one tick — the
/// `DEAD_STACK_QUIESCE_TICKS` margin absorbs that without changing the
/// safety property.
#[inline]
fn snapshot_per_cpu_ticks() -> [u64; MAX_CPUS] {
    let mut out = [0u64; MAX_CPUS];
    for i in 0..MAX_CPUS {
        out[i] = crate::arch::x86_64::irq::TIMER_ISR_PER_CPU[i]
            .load(Ordering::Relaxed);
    }
    out
}

/// Decide whether a cached entry has quiesced — every CPU that was
/// counting ticks at push time must have advanced its per-CPU counter by
/// at least `DEAD_STACK_QUIESCE_TICKS` since.  CPUs whose `push_gen[i]`
/// is zero (offline at push) are not required to advance.
#[inline]
fn entry_is_quiesced(entry: &CachedDeadStack) -> bool {
    for i in 0..MAX_CPUS {
        let pg = entry.push_gen[i];
        if pg == 0 {
            // CPU i was not ticking at push time → not a quiescence gate.
            continue;
        }
        let now = crate::arch::x86_64::irq::TIMER_ISR_PER_CPU[i]
            .load(Ordering::Relaxed);
        if now < pg.saturating_add(DEAD_STACK_QUIESCE_TICKS) {
            return false;
        }
    }
    true
}

/// Try to push a dead stack to the cache. Returns true if cached, false if full.
///
/// Zeroes the full stack region before caching so a recycled stack does not
/// carry the previous thread's saved register state, syscall arguments, or
/// kernel pointers across the lifetime boundary into the new thread that
/// pops it.  Without this, `pop_dead_stack` returns a base whose top frame
/// still contains the prior occupant's RIP / RBP / scratch values; any
/// kernel code that subsequently reads from the stack — speculatively or
/// architecturally — observes another thread's secret state.  CWE-244
/// (Improper Clean Up on Thrown Exception in the broader "improper resource
/// shutdown" class — recycled-resource leak of residual data).
///
/// Cost: one `write_bytes(..,0,KERNEL_STACK_SIZE)` per reaped thread.  At
/// 64 pages = 256 KiB this is ~12 µs on a modern core, paid once per
/// thread death — comparable to the page-zeroing cost paid on the
/// non-cached path (`pmm::free_page` → `pmm::alloc_page` zero on the
/// allocation side).  The cache exists to skip TLB shootdowns and the
/// PMM round-trip, not to skip zeroing.
///
/// Quiescence gate: a per-CPU tick snapshot is recorded alongside the
/// kstack base so `pop_dead_stack` can withhold the entry from re-issue
/// until every CPU that was ticking at push time has advanced through
/// `DEAD_STACK_QUIESCE_TICKS` timer interrupts (one full ISR round-trip
/// plus margin).  See `CachedDeadStack` for the rationale.
fn push_dead_stack(stack_base_virt: u64) -> bool {
    // Bulk-zero the kernel stack via the higher-half virtual base BEFORE
    // taking the cache lock — keeps the lock window tight (a few CPU
    // cycles to push the entry; the ~12 µs zero runs outside the lock).
    // The cached entry is not observable to any reader until we acquire
    // the lock below, so the zero is guaranteed to be visible to the
    // first `pop_dead_stack` caller that recycles this base.
    //
    // The caller (sched reaper) only caches stacks of
    // `KERNEL_STACK_PAGES_PUB` pages (verified at the call site in
    // `reap_dead_threads_sched`), so the zero length is fixed and known.
    let stack_size = crate::proc::KERNEL_STACK_PAGES_PUB * 0x1000;
    // SAFETY: `stack_base_virt` is a kernel higher-half virtual address
    // that was previously allocated as a kernel stack for a thread that
    // is now Dead and removed from THREAD_TABLE (see
    // `reap_dead_threads_sched`).  The caller runs with interrupts
    // disabled; no other CPU can be executing on this stack — Dead
    // state is set by the thread's last `schedule()` call, after which
    // the per-CPU `current_tid` moves away from this thread.  The
    // mapping is in the kernel half (above KERNEL_VIRT_BASE) so a
    // user-mode access cannot reach it.
    unsafe {
        core::ptr::write_bytes(stack_base_virt as *mut u8, 0u8, stack_size);
    }

    let push_gen = snapshot_per_cpu_ticks();

    let mut cache = DEAD_STACK_CACHE.lock();
    if cache.len() >= MAX_DEAD_STACKS {
        return false;
    }
    cache.push(CachedDeadStack { base: stack_base_virt, push_gen });
    true
}

/// Try to pop a cached stack for reuse.
///
/// Returns the higher-half base of the oldest cached entry that has
/// quiesced — i.e. every CPU active at push time has advanced its per-CPU
/// timer-ISR counter by at least `DEAD_STACK_QUIESCE_TICKS` since.
/// Non-quiesced entries are left in place; the next pop attempt re-checks
/// them.
///
/// PMM allocator fallback: returning `None` here is the normal path that
/// causes `proc::alloc_kernel_stack` to fall through to
/// `pmm::alloc_pages(KERNEL_STACK_PAGES)` — see `proc/mod.rs`.  No caller
/// of `pop_dead_stack` treats `None` as fatal, so withholding a
/// non-quiesced entry is always safe; it costs a fresh PMM allocation in
/// exchange for closing the kstack-reuse-while-RSP-still-live race
/// (Intel SDM Vol. 3A §6.14 "Interrupt and Exception Handling" — a CPU's
/// in-flight stack access against a saved kernel RSP is only retired
/// once that CPU has executed at least one further `iretq` cycle, which
/// the per-CPU timer ISR counter directly measures).
pub fn pop_dead_stack() -> Option<u64> {
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
    let i = idx_found?;
    // `remove` is O(n) but n ≤ MAX_DEAD_STACKS = 64 and the call site
    // (alloc_kernel_stack) is off the hot scheduler path — already
    // amortised against PMM allocation cost.
    Some(cache.remove(i).base)
}

/// Public interface to pre-populate the dead stack cache (called from main.rs).
pub fn push_dead_stack_pub(stack_base_virt: u64) -> bool {
    push_dead_stack(stack_base_virt)
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
    {
        let canary_info = {
            let threads = THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == current_tid)
                .filter(|t| t.kernel_stack_base > 0)
                .map(|t| (t.pid, t.kernel_stack_base))
        };
        if let Some((pid, stack_base)) = canary_info {
            if !proc::check_stack_canary(stack_base) {
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
                Some(ThreadState::Running) => {
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

        for i in 1..len {
            let idx = (current_idx + i) % len;
            let t = &threads[idx];
            if t.state != ThreadState::Ready {
                continue;
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

            let mut score = (t.priority as u16) * 4;
            if t.cpu_affinity == Some(cpu) {
                score += 2; // Pinned to us — strong preference.
            } else if t.last_cpu == cpu {
                score += 1; // Ran here last — cache-warm preference.
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
            // resort bucket.
            let is_idle_thread = t.tid >= 0x1000;
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

        // Pass 2 fallback: if no non-idle Ready peer is available on this
        // CPU, fall through to the idle thread.  This preserves the
        // existing "no work → HLT" behaviour for genuinely idle systems
        // while honouring the invariant above when work IS available.
        if best_idx.is_none() {
            best_idx = idle_best_idx;
            best_score = idle_best_score;
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
                    Some(ThreadState::Running) => {
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
