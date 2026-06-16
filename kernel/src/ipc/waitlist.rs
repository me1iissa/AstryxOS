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
    tids: Vec<BellWaiter>,
}

/// A concrete (source-class, object) the parker is watching — the exact-match
/// key for per-object targeted wakeup.  `source_bit` is a single
/// `1 << (PollBellSource as u32)` bit; `object_id` is that source's own object
/// identity (pipe_id / unix socket id / eventfd slot / inet socket_id), which is
/// what the parker's fd resolves to via the syscall-layer `get_*_id(pid, fd)`
/// helpers and what the ring site passes to `ring_poll_bell_for_obj`.  The id
/// namespaces are per-source (a pipe_id and a socket id may collide as raw
/// `u64`), so a match REQUIRES both `source_bit` and `object_id` to agree.
#[derive(Clone, Copy, PartialEq, Eq)]
struct WatchKey {
    source_bit: u32,
    object_id: u64,
}

/// A single per-object watch key supplied by callers of the object-targeted
/// park/enqueue API.  `source` is the readiness class; `object_id` is the
/// concrete object the parker's fd resolves to (pipe_id / unix socket id /
/// eventfd slot / inet socket_id), built by the syscall-layer mask builder from
/// each watched fd.  Public counterpart to the private [`WatchKey`].
#[derive(Clone, Copy)]
pub struct ObjWatch {
    pub source: PollBellSource,
    pub object_id: u64,
}

/// Test-only constructor for an [`ObjWatch`] from a raw `source_bit` and id —
/// lets `test_runner` build watch keys without the syscall-layer fd plumbing.
/// `source_bit` must be a single `1 << (PollBellSource as u32)` bit.
#[doc(hidden)]
pub fn watch_key_for_test(source_bit: u32, object_id: u64) -> ObjWatch {
    // Recover the source variant from its bit position.  Only used by tests.
    let idx = source_bit.trailing_zeros() as usize;
    let source = match idx {
        0 => PollBellSource::Pipe,
        1 => PollBellSource::Eventfd,
        2 => PollBellSource::UnixWrite,
        3 => PollBellSource::UnixShutdown,
        4 => PollBellSource::Timerfd,
        5 => PollBellSource::Signalfd,
        6 => PollBellSource::Inotify,
        7 => PollBellSource::SignalInject,
        8 => PollBellSource::InetRx,
        9 => PollBellSource::UnixRead,
        _ => PollBellSource::Other,
    };
    ObjWatch { source, object_id }
}

/// A single parker on a `WaitList`.
///
/// Wakeup interest is recorded at two granularities, both honoured by
/// [`WaitList::matches`]:
///
/// * `mask` — the coarse source-CLASS bitset (`bit(s) = 1 << (s as u32)`).  A bit
///   set here means "wake me on ANY edge of this source class," used for (a) the
///   cross-cutting always-wake classes (`Other`, `SignalInject`), (b) any fd the
///   parker watches whose object id could not be pinned (unknown/raced/regular-
///   file/nested-epoll fd → its source bit lands here as a conservative
///   wake-on-class), and (c) the whole-list `BELL_MASK_ALL` sentinel for callers
///   that do not classify at all.
/// * `objects` — the per-OBJECT pins.  When the parker watches a concrete,
///   resolvable pipe/socket/eventfd, the exact `(source_bit, object_id)` is
///   recorded here and the source bit is NOT set in `mask`.  A targeted ring for
///   `(S, id)` then wakes this parker iff `(S, id) ∈ objects` — so a write to one
///   AF_UNIX socket no longer re-schedules every AF_UNIX poller, only the
///   poller(s) actually watching that socket.  This is the intra-class herd
///   collapse (the Linux per-`wait_queue_head` model: a writer wakes only the
///   waiters registered on that object's queue, not a global scan).
///
/// CRITICAL (no under-wake): `mask` and `objects` are a SUPERSET of true
/// interest.  A class-only ring (`ring_poll_bell_for`, object unknown) wakes
/// every parker that has the source bit in `mask` OR any object of that source
/// in `objects` — because "an edge of source S I cannot attribute" must reach
/// all S-watchers.  Under-waking is a hang; over-waking is a redundant re-scan.
struct BellWaiter {
    tid: u64,
    mask: u32,
    objects: Vec<WatchKey>,
}

/// Sentinel `object_id` meaning "this ring is class-only — no specific object
/// known" (e.g. timerfd fired from an ISR with no id in scope, or a legacy
/// `ring_poll_bell()` caller).  A class-only drain wakes every parker interested
/// in the source class (mask bit set OR any pinned object of that source),
/// preserving the pre-per-object behaviour exactly for unconverted ring sites.
pub const OBJECT_ID_NONE: u64 = u64::MAX;

impl BellWaiter {
    /// True if this parker must be woken by a readiness edge `(source_bit,
    /// object_id)`.  See [`WaitList::drain_matching`] for the full predicate
    /// rationale.  The three disjuncts are, in cheapest-first order:
    ///   1. wake-on-CLASS: `mask` has the source bit (BELL_MASK_ALL, the
    ///      cross-cutting classes, or an unpinnable fd of this source);
    ///   2. targeted ring with an exact object pin: `(source_bit, object_id)`
    ///      is in `objects`;
    ///   3. class-only ring (`OBJECT_ID_NONE`) with any object pin of this
    ///      source — the unattributable-edge safety net (never under-wake).
    #[inline]
    fn matches(&self, source_bit: u32, object_id: u64) -> bool {
        if self.mask & source_bit != 0 {
            return true;
        }
        if self.objects.is_empty() {
            return false;
        }
        if object_id == OBJECT_ID_NONE {
            // Class-only edge: wake if we pin ANY object of this source.
            self.objects.iter().any(|k| k.source_bit == source_bit)
        } else {
            // Targeted edge: wake only on the exact object.
            self.objects
                .iter()
                .any(|k| k.source_bit == source_bit && k.object_id == object_id)
        }
    }
}

/// Conservative "this waiter is interested in every readiness source" sentinel.
/// Equal to all `N_BELL_SOURCES` low bits set; any per-source `drain_matching`
/// bit intersects it, so a `BELL_MASK_ALL` waiter is woken by every ring — the
/// exact semantics of the historical `drain_all`-only path.  Under-waking is a
/// hang and strictly worse than over-waking, so any unclassifiable interest
/// MUST fall back to this value (see `wait_poll_event` and the syscall-layer
/// `bell_mask_for_fd`).
pub const BELL_MASK_ALL: u32 = (1u32 << N_BELL_SOURCES) - 1;

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
        // Shim: a caller that does not (yet) classify its interest is woken by
        // every readiness source — identical to the historical drain_all-only
        // behaviour.  Preserves every non-poll-bell caller (gui/terminal.rs,
        // udp/tcp internal waiters) unchanged.
        self.enqueue_self_blocked_full(tid, wake_tick, BELL_MASK_ALL, &[]);
    }

    /// Like [`enqueue_self_blocked`] but records the parker's readiness-source
    /// interest `mask` so a later `drain_matching` can wake it selectively.
    ///
    /// CRITICAL (lost-wakeup discipline): `mask` is written to the wait list
    /// under the SAME outer (`POLL_BELL`) lock hold as the `Running -> Blocked`
    /// transition below — exactly as this function takes `THREAD_TABLE` while
    /// the caller still holds the outer lock.  A `drain_matching` racing in
    /// that window is serialized on the outer lock and therefore observes the
    /// fully-formed `BellWaiter { tid, mask }`; no readiness edge can slip
    /// between the mask write and the state transition.  The caller MUST pass a
    /// SUPERSET of its true interest (`BELL_MASK_ALL` when unsure) — a too-narrow
    /// mask is a missed wake.
    pub fn enqueue_self_blocked_masked(&mut self, tid: u64, wake_tick: u64, mask: u32) {
        self.enqueue_self_blocked_full(tid, wake_tick, mask, &[]);
    }

    /// Like [`enqueue_self_blocked_masked`] but additionally records the parker's
    /// concrete per-object watch keys (`objects`) for intra-class targeted
    /// wakeup.  `mask` carries the wake-on-CLASS sources (cross-cutting classes,
    /// unpinnable fds, or `BELL_MASK_ALL`); `objects` carries the pinned
    /// `(source, object_id)` keys.  A given source should appear in EITHER
    /// `mask` (wake-on-any-edge) OR `objects` (wake-on-this-object), never both —
    /// the syscall-layer mask builder enforces that.  Both are written under the
    /// SAME outer (`POLL_BELL`) lock hold as the `Running -> Blocked` transition
    /// below, so a `drain_matching` racing in that window is serialized on the
    /// outer lock and observes the fully-formed waiter — no edge can be lost.
    pub fn enqueue_self_blocked_full(
        &mut self,
        tid: u64,
        wake_tick: u64,
        mask: u32,
        objects: &[ObjWatch],
    ) {
        let keys: Vec<WatchKey> = objects
            .iter()
            .map(|o| WatchKey {
                source_bit: 1u32 << (o.source as u32),
                object_id: o.object_id,
            })
            .collect();
        self.tids.push(BellWaiter { tid, mask, objects: keys });
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

    /// Drain every parker that matches the readiness edge `(source_bit,
    /// object_id)`, returning their TIDs and RETAINING the non-matching waiters
    /// in place.
    ///
    /// `source_bit` is a single `1 << (PollBellSource as u32)` bit.  `object_id`
    /// is the concrete object that became ready, or [`OBJECT_ID_NONE`] for a
    /// class-only ring (no specific object known).  A waiter matches iff:
    ///
    /// * its `mask` has `source_bit` set (wake-on-CLASS: a `BELL_MASK_ALL`
    ///   waiter, the cross-cutting `Other`/`SignalInject` classes, or a source
    ///   whose fd the parker could not pin to an object); OR
    /// * the ring is targeted (`object_id != OBJECT_ID_NONE`) and the parker has
    ///   the exact `(source_bit, object_id)` pinned in `objects`; OR
    /// * the ring is class-only (`object_id == OBJECT_ID_NONE`) and the parker
    ///   has ANY object of `source_bit` pinned — an unattributable edge of source
    ///   S must reach every S-watcher (never under-wake).
    ///
    /// This is the intra-class targeted counterpart to `drain_all` (which is kept
    /// for unconditional EOF/close/shutdown wakes where every parker must be
    /// released regardless of interest).
    pub fn drain_matching(&mut self, source_bit: u32, object_id: u64) -> Vec<u64> {
        let out: Vec<u64> = self
            .tids
            .iter()
            .filter(|w| w.matches(source_bit, object_id))
            .map(|w| w.tid)
            .collect();
        if !out.is_empty() {
            // Diagnostic: count parkers LEFT BEHIND by this filter (the herd the
            // class+object filter spared from a needless re-scan).  A non-zero
            // value proves the filter is shrinking the wake set; see
            // `POLL_BELL_MASK_FILTERED` and kdb `sched-stats`.
            POLL_BELL_MASK_FILTERED
                .fetch_add((self.tids.len() - out.len()) as u64, Ordering::Relaxed);
            self.tids.retain(|w| !w.matches(source_bit, object_id));
        }
        out
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
        self.tids.drain(..n).map(|w| w.tid).collect()
    }

    /// Drain every parked TID — used by close-end wakes (EOF) where every
    /// blocked reader must be released regardless of interest mask.
    /// Semantically `drain_matching(BELL_MASK_ALL)` (every waiter's mask
    /// intersects the all-ones sentinel), kept as a distinct, intent-revealing
    /// entry point for the unconditional EOF/close/shutdown wakes.
    pub fn drain_all(&mut self) -> Vec<u64> {
        if self.tids.is_empty() {
            return Vec::new();
        }
        let n = self.tids.len();
        self.tids.drain(..n).map(|w| w.tid).collect()
    }

    /// Remove `tid` from the list if present.  Returns `true` if the TID
    /// was found.  Used by post-wake cleanup paths to detect whether a
    /// timed-out / signalled waiter raced with a wake (still on the list
    /// -> we own the dequeue and treat as timeout; no longer on the list
    /// -> a wake removed us already, treat as success).
    pub fn remove_tid(&mut self, tid: u64) -> bool {
        let before = self.tids.len();
        self.tids.retain(|w| w.tid != tid);
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
    // Event wake: boost-and-ready each parked waiter, tracking the highest
    // effective priority so the wakeup-preemption kick below can ask any
    // CPU running lower-priority work to reschedule promptly instead of
    // letting the woken thread wait out a full quantum (see
    // `sched::kick_preempt_for_wake`).
    let mut max_prio: u8 = 0;
    let mut any_woken = false;
    for &t in tids {
        if let Some(th) = threads.iter_mut().find(|th| th.tid == t) {
            if th.state == crate::proc::ThreadState::Blocked {
                crate::proc::wake_ready_event(th);
                if th.priority > max_prio {
                    max_prio = th.priority;
                }
                any_woken = true;
            }
        }
    }
    if any_woken {
        crate::sched::kick_preempt_for_wake(&threads, max_prio);
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
    /// Catch-all for ad-hoc readiness sources that have not yet been
    /// given their own variant (kept last for ABI tail-stability).
    Other        = 10,
}

/// Number of `PollBellSource` variants — keep in sync with the enum.
pub const N_BELL_SOURCES: usize = 11;

/// Stable string label for each `PollBellSource`, used by kdb to
/// render the per-source counters.  Indexed by the enum's discriminant.
pub const BELL_SOURCE_NAMES: [&str; N_BELL_SOURCES] = [
    "pipe", "eventfd", "unix_write", "unix_shutdown",
    "timerfd", "signalfd", "inotify", "signal_inject", "inet_rx",
    "unix_read", "other",
];

/// Per-source ring counters.  Bumped (Relaxed) at every successful
/// `ring_poll_bell_for(_)` call regardless of how many waiters were
/// drained — counts the *firing*, not the *wake*, so a quiet system
/// still shows attribution for sources that fire on internal events.
pub static BELL_RINGS_BY_SOURCE: [AtomicU64; N_BELL_SOURCES] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0),
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

/// Cumulative number of parkers LEFT BEHIND by `drain_matching` (i.e. a
/// per-source readiness ring fired and the class filter spared a parker whose
/// interest mask did not include that source).  This is the direct measure of
/// the thundering-herd collapse Stage C buys: a large value means each
/// readiness edge wakes only the relevant class instead of every poll/epoll
/// parker.  Surfaced via kdb `sched-stats`.  Pairs with
/// `POLL_BELL_RESYNC_WAKES` as a correctness check: if filtering ever caused a
/// *missed* wake the resync-wake count would rise (the waiter would only
/// recover at the 1 s resync floor), so a stable resync ratio alongside a
/// growing filtered count confirms the masks are a correct superset.
pub static POLL_BELL_MASK_FILTERED: AtomicU64 = AtomicU64::new(0);

/// PROFILING (intra-class herd diagnostic): cumulative number of *bell* wakes
/// (a `ring_poll_bell_for` drained this parker, not a resync/timeout) after
/// which the parker's own readiness re-scan reported NOT-ready — i.e. the
/// parker was woken by a readiness edge on some OTHER object in the same source
/// class and has nothing to do but re-park.  This is the direct measure of the
/// intra-class thundering herd that per-object targeting eliminates: with a
/// global source-class drain, a single AF_UNIX write wakes every AF_UNIX poller
/// even though only one socket got data, so every poller but one lands here.
/// A `bell_wakes`-to-`wasted_bell_wakes` ratio near 1:1 means almost every wake
/// is wasted herd churn.  Surfaced via kdb `sched-stats` / `bell-stats`.
pub static POLL_BELL_WASTED_BELL_WAKES: AtomicU64 = AtomicU64::new(0);

/// PROFILING companion: cumulative parkers DRAINED by `drain_matching` across
/// all rings (the raw wake-fanout numerator).  `bell_wakes` already counts the
/// woken-parker side from `wait_poll_event`'s perspective, but this counts it at
/// the *ring* site so the harness can compute mean fanout = drained / rings
/// without per-parker attribution.  A mean fanout ≫ 1 with a high wasted ratio
/// is the smoking gun for the intra-class herd.
pub static POLL_BELL_DRAINED_TOTAL: AtomicU64 = AtomicU64::new(0);

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
pub fn wait_poll_event(caller_deadline: u64, ready_now: impl FnMut() -> bool) -> bool {
    // Shim for callers that do not classify their interest (gui/terminal.rs,
    // udp/tcp internal waiters): park interested in every readiness source,
    // identical to the historical drain_all-only behaviour.
    wait_poll_event_masked(caller_deadline, BELL_MASK_ALL, ready_now)
}

/// Class-filtered variant of [`wait_poll_event`].  `mask` is the set of
/// `PollBellSource` classes (`bit(s) = 1 << (s as u32)`) the caller's watched
/// fds can actually be made ready by; a per-source `ring_poll_bell_for(S)`
/// wakes this parker iff `mask & (1 << S) != 0`.  Pass a SUPERSET of true
/// interest (`BELL_MASK_ALL` for any unclassifiable fd) — under-waking is a
/// lost wakeup / hang, over-waking is merely a redundant re-scan.  The mask is
/// recorded under the same `POLL_BELL` hold as the park (see
/// `enqueue_self_blocked_masked`), so no racing ring can lose the edge.
pub fn wait_poll_event_masked(
    caller_deadline: u64,
    mask: u32,
    ready_now: impl FnMut() -> bool,
) -> bool {
    wait_poll_event_obj(caller_deadline, mask, &[], ready_now)
}

/// Object-targeted variant of [`wait_poll_event_masked`].  `class_mask` carries
/// the wake-on-CLASS sources (cross-cutting classes, unpinnable fds, or
/// `BELL_MASK_ALL`); `objects` carries the concrete `(source, object_id)` pins
/// for fds that resolved to an object.  A targeted `ring_poll_bell_for_obj(S,
/// id)` wakes this parker only if `(S, id)` is in `objects`; a class-only ring
/// or a `class_mask` source wakes it as before.  Pass a SUPERSET of true
/// interest — under-waking is a hang; the mask builder defaults any unpinnable
/// fd to the class mask, so doubt always resolves to wake-on-class.  The objects
/// are recorded under the same `POLL_BELL` hold as the park (see
/// `enqueue_self_blocked_full`), so no racing ring can lose the edge.
pub fn wait_poll_event_obj(
    caller_deadline: u64,
    class_mask: u32,
    objects: &[ObjWatch],
    mut ready_now: impl FnMut() -> bool,
) -> bool {
    let mask = class_mask;
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
    bell.enqueue_self_blocked_full(tid, wake_tick, mask, objects);
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
        // PROFILING (intra-class herd): a bell drained us.  Re-run the
        // readiness probe once; if our own watched fds are STILL not ready, the
        // wake was an unrelated same-class edge (another socket/pipe got data)
        // and is pure herd churn.  `ready_now` is side-effect-light (it only
        // recomputes idempotent revents bits); the caller re-checks anyway, so
        // this adds one extra probe per bell wake — acceptable for a diagnostic.
        if !ready_now() {
            POLL_BELL_WASTED_BELL_WAKES.fetch_add(1, Ordering::Relaxed);
        }
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
    ring_poll_bell_for_obj(source, OBJECT_ID_NONE);
}

/// Ring the poll bell for a SPECIFIC object of `source` — the intra-class
/// targeted wakeup.  `object_id` is the concrete pipe/socket/eventfd id whose
/// readiness changed (resolve via the same `get_*_id` namespace the parker's fd
/// resolves through); only parkers that pinned that exact `(source, object_id)`
/// — plus every wake-on-class parker of `source` — are woken.  Pass
/// [`OBJECT_ID_NONE`] (or use [`ring_poll_bell_for`]) when the ring site has no
/// object id in scope (e.g. an ISR-driven timerfd edge): that degrades to the
/// class-only behaviour and wakes every parker of the class.
///
/// This collapses the intra-class poll-bell thundering herd: a write to ONE
/// AF_UNIX socket no longer re-schedules every AF_UNIX poller (only the one
/// watching that socket), mirroring the per-`wait_queue_head` wakeup model where
/// a writer walks only the waiters registered on that object's queue.
/// EOF/close/shutdown paths still call `drain_all` to release everyone.
pub fn ring_poll_bell_for_obj(source: PollBellSource, object_id: u64) {
    BELL_RINGS_BY_SOURCE[source as usize].fetch_add(1, Ordering::Relaxed);
    let bit = 1u32 << (source as u32);
    let drained = POLL_BELL.lock().drain_matching(bit, object_id);
    // PROFILING: raw wake-fanout numerator (drained parkers per ring).
    if !drained.is_empty() {
        POLL_BELL_DRAINED_TOTAL.fetch_add(drained.len() as u64, Ordering::Relaxed);
    }
    wake_tids(&drained);
}

/// Diagnostic hook — number of threads currently parked on the global
/// poll bell.  Used by the test runner to assert wake-up correctness.
pub fn poll_bell_waiter_count() -> usize {
    POLL_BELL.lock().len()
}

/// Snapshot the per-source bell counters and wake-classification
/// totals into a fixed-size array.  Returned tuple is
/// `(per_source_counts, bell_wakes, resync_wakes, mask_filtered)`.  Used by the
/// kdb `bell-stats` / `sched-stats` ops to render an attribution table and to
/// prove the Stage-C class filter is shrinking the wake set
/// (`mask_filtered` > 0) without raising the resync ratio.
pub fn bell_stats() -> ([u64; N_BELL_SOURCES], u64, u64, u64) {
    let mut counts = [0u64; N_BELL_SOURCES];
    for (i, c) in BELL_RINGS_BY_SOURCE.iter().enumerate() {
        counts[i] = c.load(Ordering::Relaxed);
    }
    (
        counts,
        POLL_BELL_BELL_WAKES.load(Ordering::Relaxed),
        POLL_BELL_RESYNC_WAKES.load(Ordering::Relaxed),
        POLL_BELL_MASK_FILTERED.load(Ordering::Relaxed),
    )
}
