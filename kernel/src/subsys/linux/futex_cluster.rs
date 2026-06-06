//! Bounded broadcast-within-cluster compensation for FUTEX_WAKE.
//!
//! Background
//! ----------
//! Per POSIX `pthread_cond_signal(3p)`: "If any threads are blocked on the
//! condition variable, at least one of these threads shall be unblocked."
//! POSIX places the obligation to wake on the signaller; the kernel's
//! `futex(2)` `FUTEX_WAKE` is the transport.  When a userspace condvar
//! implementation issues `FUTEX_WAKE(uaddr=A, n)` but the waiter is parked
//! on `uaddr=B` where B is adjacent to A inside the same `pthread_cond_t`
//! (or inside a small composite locking object), the wake misses and the
//! waiter never unblocks — observable as the worker thread stalling
//! indefinitely.
//!
//! This is a known pattern in older NPTL implementations; see the public
//! glibc bug at <https://sourceware.org/bugzilla/show_bug.cgi?id=25847>
//! ("pthread_cond_signal failed to wake up pthread_cond_wait due to a
//! data race").  Userspace implementations after the fix avoid the race
//! by re-checking after a missed wake, but older binaries — which we run
//! unmodified per the Linux personality subsystem invariant — cannot be
//! patched.
//!
//! Compensation
//! ------------
//! When `FUTEX_WAKE(uaddr, n)` finds zero waiters at the exact uaddr,
//! AstryxOS scans a 256-byte window centred on `uaddr`
//! (`[uaddr − 0x80, uaddr + 0x80)`, aligned to 4-byte futex boundaries)
//! and considers waking siblings that pass the safety harness below.
//!
//! Safety harness (a candidate at `addr` may be woken only if):
//!   1. `addr` was the target of a prior `FUTEX_WAKE` from the SAME TID
//!      within the per-CPU wake-history ring (last `WAKE_HISTORY_DEPTH`
//!      wakes), OR
//!   2. `addr` was the target of a `FUTEX_WAIT` from the SAME TGID
//!      within the per-CPU wait-history ring (last `WAIT_HISTORY_DEPTH`
//!      waits), OR
//!   3. `addr` sits at one of the canonical glibc `pthread_cond_t`
//!      slot offsets relative to `uaddr` — `±0x04` (same cond_t's
//!      `__g_signals[0]` ↔ `__g_signals[1]` per the layout in glibc's
//!      `bits/thread-shared-types.h` — `pthread_cond_t` is 48 bytes,
//!      `__g_signals` at offset 40), `±0x30` (one cond_t apart),
//!      `±0x08` (same cond_t's `__g1_start` half-word) — in which case
//!      the structural shape alone is dispositive without history.
//!
//! Wake budget honours the original `nr_wake` parameter.  Selection order
//! is: canonical-offset matches first, then by ascending |distance|, then
//! by recency in the history rings.
//!
//! This is a recovery path — not generic "wake everyone in 256 bytes".
//! Without history or canonical-offset evidence, neighbouring waiters
//! are left alone, so the cost of being wrong is bounded.
//!
//! The compensation is gated by a runtime toggle (`ENABLED`) and a
//! compile-time feature.  The default is ON when `firefox-test` is
//! enabled (the workload that exposes the pattern) and OFF in production
//! builds, so a fleet kernel never executes the path unless an operator
//! explicitly enables it via `kdb futex-set-cluster-wake`.

#![cfg(any(feature = "firefox-test-core", feature = "test-mode"))]

extern crate alloc;

use crate::arch::x86_64::apic::{cpu_index, MAX_CPUS};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

// ── Tunables (see module docstring for rationale) ──────────────────────────

/// 256-byte cluster window centred on the wake target.  Covers an entire
/// 48-byte `pthread_cond_t` plus several composite-object neighbours with
/// margin, while staying narrow enough that unrelated futexes in the same
/// page are not pulled in.
pub const CLUSTER_WINDOW_BYTES: u64 = 256;

/// Half-window; the search range is `[uaddr − HALF, uaddr + HALF)`.
pub const CLUSTER_HALF_WINDOW: u64 = CLUSTER_WINDOW_BYTES / 2;

/// Depth of the per-CPU FUTEX_WAKE history ring.  64 entries is enough to
/// span ~1 ms of glibc condvar churn on the firefox-test workload; smaller
/// rings under-cover the pattern (the recent wake may have rolled out),
/// larger rings waste cache.
const WAKE_HISTORY_DEPTH: usize = 64;

/// Depth of the per-CPU FUTEX_WAIT history ring.  Same sizing rationale
/// as `WAKE_HISTORY_DEPTH`.
const WAIT_HISTORY_DEPTH: usize = 64;

/// Canonical glibc `pthread_cond_t` futex-slot offsets relative to the
/// wake target.  These match the layout published in glibc's
/// `bits/thread-shared-types.h` (`__pthread_cond_s`):
///
/// ```text
///   offset   field
///   0        __wseq            (8 B)
///   8        __g1_start        (8 B)
///   16       __g_refs[0..1]    (8 B)
///   24       __g_size[0..1]    (8 B)
///   32       __g1_orig_size    (4 B)
///   36       __wrefs           (4 B)
///   40       __g_signals[0]    (4 B)   ← futex word for group 0
///   44       __g_signals[1]    (4 B)   ← futex word for group 1
/// ```
///
/// The signal/wait races BZ 25847 describes occur between `__g_signals[0]`
/// and `__g_signals[1]` (distance 4 bytes) — the within-cond_t shape.
/// Composite locking objects (Mozilla `Monitor`, GLib `GMutex`, …) place
/// pthread_cond_t structs back-to-back; the between-cond_t shape clusters
/// at multiples of 48.  We include `±0x04`, `±0x08` (same-cond intra-slot
/// neighbour), `±0x30` (one cond_t apart) — chosen narrowly so unrelated
/// futexes inside the cluster do not match.
pub const CANONICAL_COND_OFFSETS: &[i32] = &[
    -0x30, -0x08, -0x04, 0x04, 0x08, 0x30,
];

// ── Counters (kdb-exposed) ────────────────────────────────────────────────

/// Number of times the cluster-wake path fired and woke ≥ 1 candidate.
pub static CLUSTER_WAKE_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// Cluster-wake path entered but no candidate matched the safety harness.
pub static CLUSTER_WAKE_MISSES: AtomicU64 = AtomicU64::new(0);

/// Cluster-wake path entered with no waiters anywhere in the window.
pub static CLUSTER_WAKE_NO_CANDIDATES: AtomicU64 = AtomicU64::new(0);

/// Total cluster-wake-path entries — entered = recoveries + misses + no_candidates.
pub static CLUSTER_WAKE_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

/// Per-emit diagnostic-line counter; serial output is rate-limited to 1 in
/// `DIAG_RATE_DIVISOR` to stay out of the firefox-test serial budget.  The
/// kdb counters above accumulate unconditionally.
const DIAG_RATE_DIVISOR: u64 = 1024;

/// Emit the first `DIAG_FIRST_N` recoveries verbatim so the path is
/// visibly exercised on any run that fires it — operators reading the
/// serial log can see the compensation engaging without having to query
/// kdb.  Beyond that, `DIAG_RATE_DIVISOR` takes over to bound serial
/// volume on long soaks.
const DIAG_FIRST_N: u64 = 4;

/// Runtime gate.  Default ON when `firefox-test` is the active feature
/// (the workload the compensation was designed for); OFF otherwise so a
/// stock build never executes the path.  Operator can flip at runtime via
/// `kdb futex-set-cluster-wake {on|off}`.
pub static ENABLED: AtomicBool = AtomicBool::new(cfg!(feature = "firefox-test-core"));

#[inline]
pub fn is_enabled() -> bool { ENABLED.load(Ordering::Relaxed) }

#[inline]
pub fn set_enabled(v: bool) { ENABLED.store(v, Ordering::Relaxed); }

// ── Per-CPU history rings ──────────────────────────────────────────────────

/// One entry in the wake history ring.  `tid == 0` and `uaddr == 0` is
/// the sentinel "unused slot".
#[derive(Copy, Clone, Default)]
struct WakeEntry {
    tid:   u64,
    uaddr: u64,
}

/// One entry in the wait history ring.  Keyed by `pid` (TGID) — the safety
/// harness reasons about "this process recently parked someone here".
#[derive(Copy, Clone, Default)]
struct WaitEntry {
    pid:   u64,
    uaddr: u64,
}

struct WakeRing {
    head: usize,
    buf:  [WakeEntry; WAKE_HISTORY_DEPTH],
}

struct WaitRing {
    head: usize,
    buf:  [WaitEntry; WAIT_HISTORY_DEPTH],
}

impl WakeRing {
    const fn new() -> Self {
        Self { head: 0, buf: [WakeEntry { tid: 0, uaddr: 0 }; WAKE_HISTORY_DEPTH] }
    }
    fn push(&mut self, e: WakeEntry) {
        self.buf[self.head] = e;
        self.head = (self.head + 1) % WAKE_HISTORY_DEPTH;
    }
    fn contains(&self, tid: u64, uaddr: u64) -> bool {
        self.buf.iter().any(|x| x.tid == tid && x.uaddr == uaddr)
    }
    fn contains_uaddr(&self, uaddr: u64) -> bool {
        self.buf.iter().any(|x| x.uaddr == uaddr)
    }
}

impl WaitRing {
    const fn new() -> Self {
        Self { head: 0, buf: [WaitEntry { pid: 0, uaddr: 0 }; WAIT_HISTORY_DEPTH] }
    }
    fn push(&mut self, e: WaitEntry) {
        self.buf[self.head] = e;
        self.head = (self.head + 1) % WAIT_HISTORY_DEPTH;
    }
    fn contains(&self, pid: u64, uaddr: u64) -> bool {
        self.buf.iter().any(|x| x.pid == pid && x.uaddr == uaddr)
    }
}

/// Per-CPU rings.  Wrapped in `spin::Mutex` so push/contains are atomic.
/// A `Mutex` (not RwLock) is correct because the ring is touched by
/// foreground syscalls only — never from interrupt context — and the
/// critical section is O(WAKE_HISTORY_DEPTH) =  64 reads, in the
/// few-microsecond range.
static WAKE_HISTORY: [Mutex<WakeRing>; MAX_CPUS] =
    [const { Mutex::new(WakeRing::new()) }; MAX_CPUS];

static WAIT_HISTORY: [Mutex<WaitRing>; MAX_CPUS] =
    [const { Mutex::new(WaitRing::new()) }; MAX_CPUS];

/// Record an outgoing `FUTEX_WAKE(uaddr)` from `tid`.  Called from the
/// FUTEX_WAKE arm of `sys_futex_linux` REGARDLESS of `woken`.
pub fn record_wake(tid: u64, uaddr: u64) {
    if !is_enabled() { return; }
    let mut ring = WAKE_HISTORY[cpu_index()].lock();
    ring.push(WakeEntry { tid, uaddr });
}

/// Record an incoming `FUTEX_WAIT(uaddr)` from process `pid`.  Called
/// from the FUTEX_WAIT arm of `sys_futex_linux` once the waiter is
/// successfully enqueued (so spurious EAGAIN/EFAULT paths don't pollute
/// history).
pub fn record_wait(pid: u64, uaddr: u64) {
    if !is_enabled() { return; }
    let mut ring = WAIT_HISTORY[cpu_index()].lock();
    ring.push(WaitEntry { pid, uaddr });
}

/// Read-only accessor: every recent `FUTEX_WAKE` target within `half` bytes
/// of `uaddr`, across all per-CPU wake-history rings.
///
/// Returns `(tid, entry_uaddr, signed_delta)` triples where
/// `signed_delta = entry_uaddr − uaddr` (so a wake one cond-slot above the
/// query reads `+0x04`).  De-duplicated by `(tid, entry_uaddr)` and capped at
/// 64 entries so the response stays bounded.  Returns an empty vector when the
/// cluster-wake feature is disabled on this build (mirroring `record_wake`'s
/// `is_enabled()` gate), so a stock kernel produces nothing.
///
/// This is the one primitive the `cond-autopsy` kdb op needs that is not
/// derivable host-side: the per-CPU wake rings are private to this module.
/// No behaviour change — pure read of the existing rings.
pub fn recent_wakes_near(uaddr: u64, half: u64) -> alloc::vec::Vec<(u64, u64, i64)> {
    let mut out: alloc::vec::Vec<(u64, u64, i64)> = alloc::vec::Vec::new();
    if !is_enabled() { return out; }
    let lo = uaddr.saturating_sub(half);
    let hi = uaddr.saturating_add(half);
    for ring in WAKE_HISTORY.iter() {
        // Brief try_lock: never block the kdb pump thread on a ring a
        // concurrent FUTEX_WAKE happens to hold.  A missed ring is benign —
        // the autopsy is a snapshot, not a ledger.
        let Some(g) = ring.try_lock() else { continue };
        for e in g.buf.iter() {
            if e.tid == 0 && e.uaddr == 0 { continue; } // sentinel / unused
            if e.uaddr < lo || e.uaddr > hi { continue; }
            let delta = e.uaddr as i64 - uaddr as i64;
            if out.iter().any(|&(t, u, _)| t == e.tid && u == e.uaddr) { continue; }
            out.push((e.tid, e.uaddr, delta));
            if out.len() >= 64 { return out; }
        }
    }
    out
}

// ── Candidate selection ───────────────────────────────────────────────────

/// Per-candidate annotation: why we admitted it through the safety harness.
#[derive(Copy, Clone, PartialEq, Eq)]
enum CandidateReason {
    /// Canonical glibc cond_var slot offset (±0x04 / ±0x08 / ±0x30 …).
    CondSlot,
    /// Same TID recently issued `FUTEX_WAKE` at this addr.
    WakeHistory,
    /// Same TGID recently parked on this addr (FUTEX_WAIT history).
    WaitHistory,
}

struct Candidate {
    uaddr:   u64,
    distance: u64,   // |uaddr − wake_target|
    reason:  CandidateReason,
    first_tid: u64,
    waiter_count: usize,
}

/// Scan the 256-byte cluster centred on `wake_uaddr` and rank candidates.
///
/// Visits `FUTEX_WAITERS` once under its lock, copies candidate metadata
/// out, then releases the lock before logging or returning.  This keeps
/// the critical section bounded by the cluster size (≤ 64 distinct
/// 4-byte slots per pid).
///
/// Returns at most `nr_wake` candidates, ordered:
///   1. `CondSlot` matches by ascending |distance|
///   2. `WakeHistory`/`WaitHistory` matches by ascending |distance|, then
///      by recency (the ring iteration order is "most recent last", so
///      this is implicit in the scan order).
fn select_candidates(
    pid: u64,
    wake_tid: u64,
    wake_uaddr: u64,
    nr_wake: u64,
) -> alloc::vec::Vec<Candidate> {
    let lo = wake_uaddr.saturating_sub(CLUSTER_HALF_WINDOW) & !3u64;
    let hi = wake_uaddr
        .saturating_add(CLUSTER_HALF_WINDOW)
        .saturating_add(3) & !3u64;
    let hi = hi.max(lo + 4); // ensure half-open range is non-empty

    let wake_ring = WAKE_HISTORY[cpu_index()].lock();
    let wait_ring = WAIT_HISTORY[cpu_index()].lock();

    let mut out: alloc::vec::Vec<Candidate> = alloc::vec::Vec::new();
    {
        use crate::syscall::FutexKey;
        let waiters = crate::syscall::FUTEX_WAITERS.lock();
        // The cluster-wake compensation operates on the same-process
        // (PRIVATE-key) virtual-address cluster: sibling pthread_cond_t fields
        // within one process's enclosing object.  A process-SHARED futex is
        // keyed by backing-object identity (no contiguous virtual range), so it
        // is excluded — `Private(pid, _)` keys form a contiguous, ascending
        // slice in the FutexKey ordering.
        for (k, tids) in waiters.range(FutexKey::Private(pid, lo)..FutexKey::Private(pid, hi)) {
            let (wpid, wuaddr) = match k {
                FutexKey::Private(p, u) => (*p, *u),
                FutexKey::Shared { .. } => continue,
            };
            if wpid != pid { continue; }
            if wuaddr == wake_uaddr { continue; } // exact match handled by main wake
            if tids.is_empty() { continue; }
            // tids[0] is the longest-parked waiter on this uaddr — that's
            // the one we hand to the wake list when this candidate fires.
            let first_tid = tids[0];
            let waiter_count = tids.len();

            let signed_off: i64 = wuaddr as i64 - wake_uaddr as i64;
            let distance: u64 = signed_off.unsigned_abs();

            // Reason classification ─────────────────────────────────────
            //
            // Canonical-offset preference: if the candidate is exactly at
            // one of the pthread_cond_t slot offsets, admit it on
            // structural shape alone.  This is the dispositive pattern
            // and doesn't require history.
            let cond_slot = CANONICAL_COND_OFFSETS
                .iter()
                .any(|&o| signed_off == o as i64);

            let reason = if cond_slot {
                Some(CandidateReason::CondSlot)
            } else if wake_ring.contains_uaddr(wuaddr)
                   || wake_ring.contains(wake_tid, wuaddr)
            {
                Some(CandidateReason::WakeHistory)
            } else if wait_ring.contains(pid, wuaddr) {
                Some(CandidateReason::WaitHistory)
            } else {
                None
            };
            if let Some(reason) = reason {
                out.push(Candidate {
                    uaddr: wuaddr,
                    distance,
                    reason,
                    first_tid,
                    waiter_count,
                });
            }
        }
    }
    drop(wake_ring);
    drop(wait_ring);

    // Order: CondSlot before others, then by ascending distance.
    out.sort_by(|a, b| {
        let cs_a = a.reason == CandidateReason::CondSlot;
        let cs_b = b.reason == CandidateReason::CondSlot;
        match (cs_a, cs_b) {
            (true, false) => core::cmp::Ordering::Less,
            (false, true) => core::cmp::Ordering::Greater,
            _ => a.distance.cmp(&b.distance),
        }
    });
    out.truncate(nr_wake.min(u32::MAX as u64) as usize);
    out
}

// ── Wake candidates ───────────────────────────────────────────────────────

/// Remove the longest-parked waiter on `cand.uaddr` from `FUTEX_WAITERS`
/// (mirroring the main FUTEX_WAKE arm), then transition it to `Ready`.
///
/// Returns the TID actually woken, or `None` if the candidate was racey-
/// drained (e.g. another CPU's FUTEX_WAKE on `cand.uaddr` ran between
/// `select_candidates` and here).  A racey drain is benign — the waiter
/// was already woken; our compensation simply didn't wake an additional
/// one.
fn wake_one_candidate(pid: u64, cand: &Candidate) -> Option<u64> {
    use crate::syscall::FutexKey;
    // Candidates are selected only from the PRIVATE-key cluster, so the
    // bucket to drain is the private key for `(pid, cand.uaddr)`.
    let cand_key = FutexKey::Private(pid, cand.uaddr);
    let tid = {
        let mut waiters = crate::syscall::FUTEX_WAITERS.lock();
        let list = waiters.get_mut(&cand_key)?;
        if list.is_empty() { return None; }
        let t = list.remove(0);
        if list.is_empty() {
            waiters.remove(&cand_key);
        }
        t
    };

    let mut threads = crate::proc::THREAD_TABLE.lock();
    if let Some(th) = threads.iter_mut().find(|th| th.tid == tid) {
        if th.state == crate::proc::ThreadState::Blocked {
            th.state    = crate::proc::ThreadState::Ready;
            th.wake_tick = 0;
        }
    }
    Some(tid)
}

// ── Main entry point ──────────────────────────────────────────────────────

/// Bounded broadcast-within-cluster compensation.
///
/// Invoked by the FUTEX_WAKE arm of `sys_futex_linux` ONLY when the
/// initial wake produced `woken == 0` and the op is `FUTEX_WAKE` (1) or
/// `FUTEX_WAKE_BITSET` (10).  Walks the 256-byte cluster, selects
/// candidates through the safety harness, and wakes up to `nr_wake` of
/// them.  Returns the additional wake count (≥ 0).
///
/// Per `pthread_cond_signal(3p)` POSIX:2017 §2.9.5 — at least one of any
/// blocked threads MUST be unblocked.  Older glibc condvar implementations
/// race in the unmodified-binary case; this path closes the window
/// without changing userspace.
pub fn compensate(pid: u64, wake_tid: u64, wake_uaddr: u64, nr_wake: u64) -> u64 {
    if !is_enabled() { return 0; }
    if nr_wake == 0  { return 0; }

    CLUSTER_WAKE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);

    let cands = select_candidates(pid, wake_tid, wake_uaddr, nr_wake);
    if cands.is_empty() {
        // Was the cluster empty entirely, or did it have neighbours but
        // none passed the safety harness?  Re-scan briefly to distinguish.
        let lo = wake_uaddr.saturating_sub(CLUSTER_HALF_WINDOW) & !3u64;
        let hi = wake_uaddr
            .saturating_add(CLUSTER_HALF_WINDOW)
            .saturating_add(3) & !3u64;
        let any_neighbour = {
            use crate::syscall::FutexKey;
            let waiters = crate::syscall::FUTEX_WAITERS.lock();
            waiters.range(FutexKey::Private(pid, lo)..FutexKey::Private(pid, hi))
                .any(|(k, tids)| matches!(k, FutexKey::Private(p, u) if *p == pid && *u != wake_uaddr) && !tids.is_empty())
        };
        if any_neighbour {
            CLUSTER_WAKE_MISSES.fetch_add(1, Ordering::Relaxed);
        } else {
            CLUSTER_WAKE_NO_CANDIDATES.fetch_add(1, Ordering::Relaxed);
        }
        return 0;
    }

    let mut woken_extra = 0u64;
    for cand in cands.iter() {
        if wake_one_candidate(pid, cand).is_some() {
            woken_extra += 1;
            // Rate-limited diagnostic line.  Always emit the first
            // `DIAG_FIRST_N` recoveries (so the path is visibly
            // exercised on any run that fires it), then 1 in
            // `DIAG_RATE_DIVISOR` thereafter (so a long firefox-test
            // soak doesn't flood the serial budget).
            let attempt    = CLUSTER_WAKE_ATTEMPTS.load(Ordering::Relaxed);
            let recoveries = CLUSTER_WAKE_RECOVERIES.load(Ordering::Relaxed);
            let should_emit = recoveries < DIAG_FIRST_N
                              || attempt % DIAG_RATE_DIVISOR == 1;
            if should_emit {
                let reason_s = match cand.reason {
                    CandidateReason::CondSlot    => "cond_slot",
                    CandidateReason::WakeHistory => "wake_history",
                    CandidateReason::WaitHistory => "wait_history",
                };
                let signed_off: i64 = cand.uaddr as i64 - wake_uaddr as i64;
                crate::serial_fast_println!(
                    "[FUTEX_CLUSTER_WAKE] tid={} tgid={} wake_uaddr={:#x} \
                     target_uaddr={:#x} offset={} reason={} \
                     waiter_count={} woken_tid={} attempt_no={}",
                    wake_tid, pid, wake_uaddr,
                    cand.uaddr, signed_off, reason_s,
                    cand.waiter_count, cand.first_tid, attempt
                );
            }
        }
    }

    if woken_extra > 0 {
        CLUSTER_WAKE_RECOVERIES.fetch_add(1, Ordering::Relaxed);
    } else {
        CLUSTER_WAKE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
    woken_extra
}

// ── kdb-exposed snapshot ─────────────────────────────────────────────────

/// Snapshot of the futex cluster-wake counters.  Returned by
/// `kdb futex-stats` and consumed by the qemu-harness front-end.
#[derive(Default, Copy, Clone)]
pub struct ClusterWakeStats {
    pub attempts:      u64,
    pub recoveries:    u64,
    pub misses:        u64,
    pub no_candidates: u64,
    pub enabled:       bool,
}

pub fn stats() -> ClusterWakeStats {
    ClusterWakeStats {
        attempts:      CLUSTER_WAKE_ATTEMPTS.load(Ordering::Relaxed),
        recoveries:    CLUSTER_WAKE_RECOVERIES.load(Ordering::Relaxed),
        misses:        CLUSTER_WAKE_MISSES.load(Ordering::Relaxed),
        no_candidates: CLUSTER_WAKE_NO_CANDIDATES.load(Ordering::Relaxed),
        enabled:       is_enabled(),
    }
}

// ── Test surface ─────────────────────────────────────────────────────────

/// Test-only direct entry for the in-kernel test harness.  Performs no
/// syscall, no user-pointer validation; the harness controls the
/// `FUTEX_WAITERS` content and history rings directly.
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
pub fn _test_compensate(pid: u64, wake_tid: u64, wake_uaddr: u64, nr_wake: u64) -> u64 {
    compensate(pid, wake_tid, wake_uaddr, nr_wake)
}

#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
pub fn _test_record_wake(tid: u64, uaddr: u64) { record_wake(tid, uaddr); }

#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
pub fn _test_record_wait(pid: u64, uaddr: u64) { record_wait(pid, uaddr); }
