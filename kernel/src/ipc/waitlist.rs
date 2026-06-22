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
use core::sync::atomic::{AtomicU64, Ordering};

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

    /// Test-only: push a raw `tid` onto the list without touching
    /// `THREAD_TABLE`.  Lets the in-kernel test runner simulate a parked
    /// waiter (for asserting wake/drain invariants) without a live Blocked
    /// thread or a second CPU.
    #[cfg(any(feature = "test-mode", feature = "firefox-test-core"))]
    pub fn push_tid_raw(&mut self, tid: u64) {
        self.tids.push(tid);
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

/// Identifies the IPC subsystem that rang the poll bell.  Used to
/// attribute each ring to a counter so kdb / test instrumentation can
/// see which readiness sources are firing.  Add a new variant when a
/// new readiness source learns to ring the bell; the `BELL_RINGS_BY_SOURCE`
/// table grows automatically because `N_BELL_SOURCES` is derived from
/// the variant count.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum PollBellSource {
    /// `crate::ipc::pipe::wake_*_all` — pipe data / EOF arrival.
    Pipe         = 0,
    /// `crate::ipc::eventfd::wake_readers_all` — eventfd post.
    Eventfd      = 1,
    /// `crate::net::unix::write` — AF_UNIX data arrival.
    UnixWrite    = 2,
    /// `crate::net::unix::shutdown` / `connect` / `accept` —
    /// AF_UNIX peer half-close or connection completion.
    UnixShutdown = 3,
    /// `crate::ipc::timerfd::*` — timer-fd expiration becomes readable.
    Timerfd      = 4,
    /// `crate::ipc::signalfd::*` — signal pending against a watched
    /// signalfd's mask (rung from the signal-injection path that also
    /// updates `signal_state.pending`).
    Signalfd     = 5,
    /// `crate::ipc::inotify::notify_event` — first event enqueued on
    /// an inotify instance's empty queue.
    Inotify      = 6,
    /// `crate::signal::kill` and other signal-injection sites — wakes
    /// `epoll_pwait*` callers whose temporary sigmask just admitted a
    /// pending signal, and any signalfd/self-pipe loop the process
    /// uses for signal-driven IPC.
    SignalInject = 7,
    /// `crate::net::udp::handle_udp` / `crate::net::tcp::handle_tcp` —
    /// AF_INET datagram or stream segment arrival on a bound port.
    /// Without this, a userspace `poll()` parked on a UDP/TCP socket
    /// would only re-evaluate on the 1 s resync floor, defeating the
    /// short timeouts DNS resolvers expect (RFC 1035 §4.2.1).
    InetRx       = 8,
    /// `crate::net::unix::read_msg` recv-drain — a reader consuming bytes
    /// frees room in the recv ring, which makes the *peer's* write side
    /// newly `POLLOUT`-ready.  Rung so a peer parked in `poll`/`epoll_wait`
    /// waiting for the socket to become writable re-checks immediately,
    /// rather than only on the resync floor (`man 7 unix`, the recv-side
    /// write-space wake).  Distinct from `UnixWrite` (data-arrival, which
    /// makes the reader `POLLIN`-ready) so kdb attribution stays honest.
    UnixRead     = 9,
    /// `crate::net::tcp::tcp_timer_tick` send-buffer drain — bytes leaving
    /// the TCP send buffer (as ACKs open the congestion/peer window per
    /// RFC 9293 §3.7) free room below the `sndbuf` high-water mark, which
    /// makes a connected TCP socket newly `POLLOUT`-ready.  Rung on the
    /// *rising* write-space edge (the buffer was at/over `sndbuf` — POLLOUT
    /// was de-asserted by the NDE-24 backpressure gate — and is now below
    /// it) so a producer parked in `poll(POLLOUT)` / `epoll_wait(EPOLLOUT)`
    /// / `select(writefds)` on a previously-full send buffer re-checks
    /// immediately rather than only on the ~1 s resync floor (IEEE Std
    /// 1003.1-2017 §poll: a socket whose `send(2)` would no longer block
    /// must report writable).  Distinct from `InetRx` (the rx data-arrival
    /// edge that makes a socket `POLLIN`-ready) so kdb attribution stays
    /// honest — exactly the rationale that split `UnixRead` from
    /// `UnixWrite`.
    InetTx       = 10,
    /// Catch-all for ad-hoc readiness sources that have not yet been
    /// given their own variant (kept last for ABI tail-stability).
    Other        = 11,
}

/// Number of `PollBellSource` variants — keep in sync with the enum.
pub const N_BELL_SOURCES: usize = 12;

/// Stable string label for each `PollBellSource`, used by kdb to
/// render the per-source counters.  Indexed by the enum's discriminant.
pub const BELL_SOURCE_NAMES: [&str; N_BELL_SOURCES] = [
    "pipe", "eventfd", "unix_write", "unix_shutdown",
    "timerfd", "signalfd", "inotify", "signal_inject", "inet_rx",
    "unix_read", "inet_tx", "other",
];

/// Per-source ring counters.  Bumped (Relaxed) at every successful
/// `ring_poll_bell_for(_)` call regardless of how many waiters were
/// drained — counts the *firing*, not the *wake*, so a quiet system
/// still shows attribution for sources that fire on internal events.
pub static BELL_RINGS_BY_SOURCE: [AtomicU64; N_BELL_SOURCES] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

/// Cumulative number of `wait_poll_event` calls that woke via a bell
/// drain (i.e. somebody called `ring_poll_bell*` while we were parked
/// and the wake flipped us back to Ready before the resync tick fired).
/// Together with `POLL_BELL_RESYNC_WAKES` this lets the harness verify
/// the demo-gate exit criterion: "epoll_wait returns on bell-ring not
/// resync ≥ 90% of the time on the firefox-test boot".
pub static POLL_BELL_BELL_WAKES: AtomicU64 = AtomicU64::new(0);

/// Cumulative number of `wait_poll_event` calls that returned because
/// the resync-floor timer expired (i.e. nobody rang the bell within
/// `RESYNC_INTERVAL_TICKS`).  A high ratio here means a readiness
/// source is not wired into the bell yet — see `bell_stats()`.
pub static POLL_BELL_RESYNC_WAKES: AtomicU64 = AtomicU64::new(0);

/// Park the caller on the global poll bell.  Returns once any IPC
/// writer has rung the bell, the bounded resync interval elapses, or
/// the caller is woken for another reason (e.g. signal injection
/// flips us to Ready).  Callers MUST treat the wake as advisory — re-
/// evaluate fd readiness before returning to userspace.
///
/// `caller_deadline` is the absolute scheduler tick at which the
/// caller's own timeout expires (`u64::MAX` for infinite waits, per
/// `poll(2)` `timeout=-1` and `epoll_wait(2)` `timeout=-1`).  The
/// helper parks for at most `RESYNC_INTERVAL_TICKS` before falling
/// back through.  With every readiness source now wiring through
/// `ring_poll_bell_for`, the resync floor is purely a safety net for
/// future sources (or third-party fds) that have not yet been added
/// to the bell — it is sized accordingly (1 s, was 100 ms pre-wiring).
///
/// ## Lost-wakeup correctness (prepare-to-wait / recheck-under-lock)
///
/// The caller's fd-readiness scan (`poll_revents` / `epoll_poll_events`)
/// runs in a *different* lock domain (`PROCESS_TABLE` + the per-fd
/// pipe/socket/eventfd state locks) from the bell.  A naive
/// `scan → if not-ready park` has a lost-wakeup window: between the
/// scan reading "not ready" and this function taking `POLL_BELL`, a
/// writer can run `ring_poll_bell_for → drain_all()`, find the waiter
/// list empty, and consume the readiness edge — the parker then sleeps
/// with the wakeup already gone, only recovering at the
/// `RESYNC_INTERVAL_TICKS` (≈1 s) floor.  This is the classic
/// prepare-to-wait / lost-wakeup hazard (cf. `poll(2)`, `epoll(7)`,
/// `man 7 futex` "futex word recheck"): the condition must be
/// re-tested *after* committing to the wait queue but *before*
/// sleeping, atomically with respect to the waker.
///
/// `ready_now` is the caller's readiness re-scan.  This function holds
/// `POLL_BELL` and calls `ready_now()`; if it reports readiness, the
/// caller is NOT enqueued and NOT scheduled away — `true` is returned
/// so the caller drops straight back into its evaluate-and-return path.
/// Otherwise the caller is enqueued *under the same `POLL_BELL` hold*
/// that gated the recheck, so any `ring_poll_bell_for` that races
/// between the recheck and `schedule()` is serialized behind the bell
/// lock and therefore observes the now-enqueued waiter — no edge can
/// be lost.  Returns `false` if it actually parked.
///
/// ### Lock order (no inversion)
///
/// While holding `POLL_BELL` this function acquires, *sequentially and
/// non-nested*, first whatever locks `ready_now()` needs
/// (`PROCESS_TABLE` + per-fd state, all released before it returns),
/// then `THREAD_TABLE` via `enqueue_self_blocked`.  The new edge is
/// `POLL_BELL → PROCESS_TABLE`.  No bell *writer* ever rings the bell
/// while holding `PROCESS_TABLE` (every `ring_poll_bell_for` site drops
/// the process/state lock first — see `signal::kill`, the alarm
/// dispatcher, and the pipe/eventfd/unix wake paths), so the reverse
/// edge `PROCESS_TABLE → POLL_BELL` does not exist and the addition is
/// inversion-free.  `POLL_BELL` is never held across `schedule()`.
pub fn wait_poll_event(caller_deadline: u64, mut ready_now: impl FnMut() -> bool) -> bool {
    /// Maximum ticks to park before the outer loop rescans.  100 ticks
    /// = 1 s at `TICK_HZ=100`.  Pre-wiring this was 100 ms because the
    /// bell missed timerfd / signalfd / inotify / unix-shutdown /
    /// signal-injection readiness; with those sources now wired, the
    /// floor exists only as a backstop for future readiness sources
    /// that have not yet been ring-bell-wired, and a 1 s rescan keeps
    /// CPU overhead in the long-quiet case ~10× lower.  It is retained
    /// as belt-and-braces even though the recheck-under-lock above
    /// closes the structural lost-wakeup window for every wired source.
    const RESYNC_INTERVAL_TICKS: u64 = 100;
    let tid = crate::proc::current_tid();
    let now = crate::arch::x86_64::irq::get_ticks();
    let resync_tick = now.saturating_add(RESYNC_INTERVAL_TICKS);
    // Honor whichever deadline arrives first — the caller's, or our
    // periodic resync.  Saturating arithmetic on u64::MAX yields the
    // resync floor (correct: the caller wants infinity, we want to
    // floor at resync).
    let wake_tick = caller_deadline.min(resync_tick);

    let mut bell = POLL_BELL.lock();
    // Recheck readiness WHILE HOLDING the bell lock.  If a watched fd
    // became ready in the window between the caller's last scan and
    // now, bail without parking: returning `true` tells the caller to
    // re-evaluate and return ready, and because we never enqueued there
    // is nothing to clean up.  A writer racing here is serialized on
    // `POLL_BELL` — it either ran before us (we observe ready) or after
    // us (we are enqueued and it drains us).
    if ready_now() {
        drop(bell);
        return true;
    }
    bell.enqueue_self_blocked(tid, wake_tick);
    // Drop the bell AFTER enqueue but BEFORE schedule(): a wake that
    // arrives between here and schedule() finds us already on the list
    // and flips us Blocked→Ready, so the schedule() (or the scheduler
    // tick) returns us promptly rather than losing the wake.
    drop(bell);
    crate::sched::schedule();
    // Classify the wake: if we are still on the bell list, the
    // scheduler tick (resync or caller deadline) woke us; if not, a
    // bell ring drained us.  `remove_tid` returns true when the entry
    // was present, so we attribute the wake based on its return.
    let still_parked = POLL_BELL.lock().remove_tid(tid);
    if still_parked {
        POLL_BELL_RESYNC_WAKES.fetch_add(1, Ordering::Relaxed);
    } else {
        POLL_BELL_BELL_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    false
}

/// Ring the poll bell — wake every thread parked in `wait_poll_event`.
/// Called by IPC writers (pipe write, eventfd post, unix socket write,
/// X11 server reply, etc.) after the data side has been updated.
///
/// Equivalent to `ring_poll_bell_for(PollBellSource::Other)` — kept as
/// a stable shim for callers that have not been migrated to the tagged
/// variant.  Prefer `ring_poll_bell_for` in new code so the per-source
/// counter attributes the ring correctly.
pub fn ring_poll_bell() {
    ring_poll_bell_for(PollBellSource::Other);
}

/// Ring the poll bell and increment the per-source counter for
/// `source`.  The counter is bumped exactly once per call regardless
/// of how many waiters were drained — kdb sees "this source fired N
/// times", not "this source woke M waiters".
pub fn ring_poll_bell_for(source: PollBellSource) {
    BELL_RINGS_BY_SOURCE[source as usize].fetch_add(1, Ordering::Relaxed);
    let drained = POLL_BELL.lock().drain_all();
    wake_tids(&drained);
}

/// Diagnostic hook — number of threads currently parked on the global
/// poll bell.  Used by the test runner to assert wake-up correctness.
pub fn poll_bell_waiter_count() -> usize {
    POLL_BELL.lock().len()
}

/// Snapshot the per-source bell counters and wake-classification
/// totals into a fixed-size array.  Returned tuple is
/// `(per_source_counts, bell_wakes, resync_wakes)`.  Used by the kdb
/// `bell-stats` op to render an attribution table.
pub fn bell_stats() -> ([u64; N_BELL_SOURCES], u64, u64) {
    let mut counts = [0u64; N_BELL_SOURCES];
    for (i, c) in BELL_RINGS_BY_SOURCE.iter().enumerate() {
        counts[i] = c.load(Ordering::Relaxed);
    }
    (
        counts,
        POLL_BELL_BELL_WAKES.load(Ordering::Relaxed),
        POLL_BELL_RESYNC_WAKES.load(Ordering::Relaxed),
    )
}
