//! Per-fd wait list primitive for pipe / eventfd / poll wake hooks.
//!
//! A `WaitList` is a list of TIDs that have parked themselves on a single
//! condition (e.g. "this pipe has data" or "this eventfd's counter is
//! non-zero").  Wake-ups walk the list and flip every parked thread back
//! from `ThreadState::Blocked` to `ThreadState::Ready` so the scheduler
//! picks them up on the next tick.
//!
//! The shape mirrors the futex wait queue (`crate::syscall::FUTEX_WAITERS`)
//! and the same lost-wakeup discipline applies: any condition that depends
//! on a "is there data?" check followed by a "park if not" decision MUST
//! perform both steps under the same `WaitList` lock.  See
//! `wait_check_and_enqueue` for the canonical pattern.
//!
//! Per `man 7 pipe`, `man 2 eventfd`, and `man 2 poll`: a reader that finds
//! a pipe / eventfd unready must block (when the fd is in blocking mode)
//! until either data arrives, the peer closes the write end, or a signal
//! is delivered.  Pre-fix, both subsystems returned "no data" without
//! parking, leaving callers to busy-spin via the syscall layer.

extern crate alloc;

use alloc::vec::Vec;

/// A list of thread IDs parked on a single wake condition.
///
/// `WaitList` is meant to live inside an outer `Mutex<...>` (typically the
/// `Mutex<BTreeMap<key, WaitList>>` keyed by pipe id, eventfd id, etc).
/// All operations therefore assume exclusive access via the outer lock and
/// do not synchronise internally.
pub struct WaitList {
    tids: Vec<u64>,
}

impl WaitList {
    /// Construct an empty wait list.  `const fn` so it can be used in
    /// `static` initialisers (e.g. inside a `Mutex<BTreeMap<u64, WaitList>>`
    /// allocated lazily on first use).
    pub const fn new() -> Self {
        Self { tids: Vec::new() }
    }

    /// True if no threads are parked on this list.  Used by wake helpers
    /// to short-circuit work when there is nothing to do.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tids.is_empty()
    }

    /// Number of TIDs currently parked.  Diagnostic-only — wake paths use
    /// `drain` / `drain_all` which return the TID list directly.
    #[inline]
    pub fn len(&self) -> usize {
        self.tids.len()
    }

    /// Enqueue `tid` on the wait list, then mark the matching thread
    /// `Blocked` with the supplied `wake_tick` deadline (use `u64::MAX`
    /// for an indefinite block).  The caller MUST hold the outer wait-list
    /// lock for the duration of this call; this function additionally
    /// acquires `proc::THREAD_TABLE` while still holding it (lock order:
    /// `WaitList parent` -> `THREAD_TABLE`, identical to the futex
    /// `FUTEX_WAITERS -> THREAD_TABLE` order documented in
    /// `crate::syscall::futex_wait_check_and_enqueue`).
    ///
    /// The caller invokes `crate::sched::schedule()` after the outer lock
    /// has been dropped.
    pub fn enqueue_self_blocked(&mut self, tid: u64, wake_tick: u64) {
        self.tids.push(tid);
        let mut threads = crate::proc::THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            // Mirror the SMP context-switch invariant from `sleep_ticks`:
            // release-store ctx_rsp_valid=false BEFORE transitioning out
            // of `Running`, so a peer CPU that sees the wake (via the
            // scheduler tick or an explicit `wake_all`) cannot load a
            // stale RSP between the state write and our schedule().
            t.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
            t.state = crate::proc::ThreadState::Blocked;
            t.wake_tick = wake_tick;
        }
    }

    /// Drain up to `max` parked TIDs and return them to the caller, who is
    /// expected to call `wake_tids` *after* dropping the outer wait-list
    /// lock.  Splitting drain-from-list and flip-thread-state into two
    /// phases keeps the wait-list lock and `THREAD_TABLE` from being
    /// nested in the wake path (the matching pattern used by FUTEX_WAKE).
    pub fn drain(&mut self, max: usize) -> Vec<u64> {
        if self.tids.is_empty() || max == 0 {
            return Vec::new();
        }
        let n = self.tids.len().min(max);
        self.tids.drain(..n).collect()
    }

    /// Drain every parked TID — used by close-end wakes (EOF) where every
    /// blocked reader must be released.
    pub fn drain_all(&mut self) -> Vec<u64> {
        if self.tids.is_empty() {
            return Vec::new();
        }
        let n = self.tids.len();
        self.tids.drain(..n).collect()
    }

    /// Remove `tid` from the list if present.  Returns `true` if the TID
    /// was found.  Used by post-wake cleanup paths to detect whether a
    /// timed-out / signalled waiter raced with a wake (still on the list
    /// -> we own the dequeue and treat as timeout; no longer on the list
    /// -> a wake removed us already, treat as success).
    pub fn remove_tid(&mut self, tid: u64) -> bool {
        let before = self.tids.len();
        self.tids.retain(|&t| t != tid);
        self.tids.len() < before
    }
}

/// Flip a batch of TIDs from `Blocked` to `Ready` under a single
/// `THREAD_TABLE` acquisition.  Matches the FUTEX_WAKE post-drain pattern
/// (see `subsys/linux/syscall.rs` op == 1 / 10): drain TIDs from the
/// keyed wait list, drop that lock, then take `THREAD_TABLE` once and
/// flip every drained TID.  Threads that have already transitioned out
/// of `Blocked` (e.g. timed out via the scheduler tick at
/// `sched/mod.rs:104`) are left alone.
pub fn wake_tids(tids: &[u64]) {
    if tids.is_empty() {
        return;
    }
    let mut threads = crate::proc::THREAD_TABLE.lock();
    for &t in tids {
        if let Some(th) = threads.iter_mut().find(|th| th.tid == t) {
            if th.state == crate::proc::ThreadState::Blocked {
                th.state = crate::proc::ThreadState::Ready;
                th.wake_tick = 0;
            }
        }
    }
}

// ── Global poll/select/epoll wake-bell ────────────────────────────────────────
//
// `poll(2)`, `select(2)`, and `epoll_wait(2)` block on a set of fds.
// Maintaining per-(fd, poller) registration lists is the optimal
// solution but requires invasive cleanup on every wake, signal, or
// timeout path.  As a tractable middle ground we expose a global
// "poll bell" — a single wait list that every IPC state-change writer
// rings via `ring_poll_bell()`.  Any thread blocked in
// `wait_poll_event` is woken; it then re-evaluates its fd set and
// either returns ready or re-parks.
//
// Per `man 2 select`: "If the call is interrupted by a signal handler
// or a fd becomes ready, select() returns".  The bell is correct so
// long as every state change that could affect fd readiness rings it;
// false wakeups (writer rings the bell for an fd we are not watching)
// are harmless — the poller re-checks and re-parks.
//
// The bell uses the same `Blocked + wake_tick` discipline as the
// per-fd wait lists: parking is `Blocked`, the scheduler tick auto-
// wakes on `wake_tick` (poll timeout), and `ring_poll_bell` flips us
// back to `Ready` immediately when a writer fires.

static POLL_BELL: spin::Mutex<WaitList> = spin::Mutex::new(WaitList::new());

/// Park the caller on the global poll bell.  Returns once any IPC
/// writer has rung the bell, the bounded resync interval elapses, or
/// the caller is woken for another reason (e.g. signal injection
/// flips us to Ready).  Callers MUST treat the wake as advisory — re-
/// evaluate fd readiness before returning to userspace.
///
/// `caller_deadline` is the absolute scheduler tick at which the
/// caller's own timeout expires (`u64::MAX` for infinite waits, per
/// `poll(2)` `timeout=-1` and `epoll_wait(2)` `timeout=-1`).  The
/// helper deliberately parks for at most `RESYNC_INTERVAL_TICKS`
/// before falling back through so the caller's outer rescan loop
/// observes any fd state that did not ring the bell — TCP socket
/// data, X11 reply bytes, signal injection mid-park, and any future
/// readiness source not yet wired into `ring_poll_bell` are all
/// covered by the next periodic recheck.  Without this floor an
/// `epoll_wait(timeout=-1)` watching only TCP fds would park
/// indefinitely (the bell only fires on pipe / eventfd / unix-socket
/// writes), reproducing the pre-fix busy-poll wedge in inverse.
pub fn wait_poll_event(caller_deadline: u64) {
    /// Maximum ticks to park before the outer loop rescans.  10 ticks
    /// = 100 ms at TICK_HZ=100 — coarse enough to be a low-CPU floor
    /// for genuinely-quiescent fd sets, fine enough that polling
    /// interactive workloads (X11, etc.) stay responsive.  The bell
    /// path returns much sooner in the common case.
    const RESYNC_INTERVAL_TICKS: u64 = 10;
    let tid = crate::proc::current_tid();
    let now = crate::arch::x86_64::irq::get_ticks();
    let resync_tick = now.saturating_add(RESYNC_INTERVAL_TICKS);
    // Honor whichever deadline arrives first — the caller's, or our
    // periodic resync.  Saturating arithmetic on u64::MAX yields the
    // resync floor (correct: the caller wants infinity, we want to
    // floor at resync).
    let wake_tick = caller_deadline.min(resync_tick);

    let mut bell = POLL_BELL.lock();
    bell.enqueue_self_blocked(tid, wake_tick);
    drop(bell);
    crate::sched::schedule();
    // Drop any stale entry — we may have woken via the scheduler tick
    // (deadline elapsed) rather than via `ring_poll_bell`, in which
    // case our TID is still on the list.
    POLL_BELL.lock().remove_tid(tid);
}

/// Ring the poll bell — wake every thread parked in `wait_poll_event`.
/// Called by IPC writers (pipe write, eventfd post, unix socket write,
/// X11 server reply, etc.) after the data side has been updated.
pub fn ring_poll_bell() {
    let drained = POLL_BELL.lock().drain_all();
    wake_tids(&drained);
}

/// Diagnostic hook — number of threads currently parked on the global
/// poll bell.  Used by the test runner to assert wake-up correctness.
pub fn poll_bell_waiter_count() -> usize {
    POLL_BELL.lock().len()
}
