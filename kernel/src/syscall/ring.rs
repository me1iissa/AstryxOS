//! Per-process syscall ring buffer (firefox-test feature only).
//!
//! Records a bounded (RING_CAP-entry) chronological history of syscalls for
//! each tracked process.  On `exit_group(code)` with `code != 0` the ring is
//! dumped to the serial console framed by `[SC-RING-BEGIN]` / `[SC-RING-END]`
//! lines; each entry is printed on a single `[SC-RING]` line.
//!
//! The ring is a purely diagnostic aid: the information it captures (syscall
//! number, six argument registers, return value, user RIP, a TSC-derived
//! monotonic-ns timestamp, the calling thread id, how any blocking wait
//! concluded, and optional resolved path / first read bytes) is a superset of
//! what a userspace strace would observe.  For Firefox debugging this is the
//! cheapest way to answer "what was the process looking at — and what woke it
//! — immediately before it acted?"
//!
//! The `optrace` submodule adds a kdb-armable gap-end freeze trigger so a
//! single Wikipedia-load wake-chain transition can be captured and
//! reconstructed offline (W101 op-trace, Phase 0).
//!
//! Feature-gated: compiled under `firefox-test-core` (the Firefox bring-up
//! profile) and `test-mode` (so the in-kernel test suite can exercise the
//! plumbing).  Nothing is ever auto-tracked under bare `test-mode`, so the
//! general syscall path stays untouched for production builds.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

use crate::arch::x86_64::apic::{cpu_index, MAX_CPUS};

/// Default ring capacity per process (last N syscalls).
///
/// The gap-end freeze trigger (see `optrace` below) stops recording once the
/// captured transition tail has settled, so the *live* requirement on this
/// number is only "deep enough to span the gap-ending send through the grace
/// window at storm rate".  The historical value was 256 (≈2 ms of storm) —
/// far too shallow for a W101 op-trace capture where the post-gap burst runs
/// at ~10^5 syscalls/s.  The default is bumped modestly (holds ~24 ms of
/// storm) and the per-pid depth is raised to a capture depth via the kdb
/// `optrace-depth` op right before arming, which bounds heap cost to just the
/// two focus PIDs rather than every tracked process.  Each slot is a fixed
/// ~104 B header plus (empty) `String`/`Vec` handles — see the PR notes for
/// the memory model.
pub const RING_CAP: usize = 4096;

/// Runtime default capacity for newly-created rings.  Seeded from `RING_CAP`;
/// raised via `set_default_capacity` (kdb `optrace-depth` with no pid).
static RING_CAP_RUNTIME: AtomicUsize = AtomicUsize::new(RING_CAP);

/// Max bytes of `open()`'d path stored per entry.
pub const PATH_BYTES: usize = 128;

/// Max bytes of `read()` content captured per entry.
pub const READ_BYTES: usize = 256;

/// How a blocking wait concluded, captured at syscall exit so an offline
/// chain reconstruction can tell "woken by data/readiness" apart from "gave
/// up on a timeout" — the one discrimination a userspace strace cannot make.
///
/// `NeverBlocked` is the default for every entry; a wait path overwrites the
/// per-CPU slot (see [`note_wake_reason`]) *after* its final `schedule()`
/// returns, and [`end`] folds the slot into the entry.  Values are stable
/// (append-only) so the harness/JSON mapping never shifts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum WakeReason {
    /// Syscall did not park (or is not a wait syscall) — data was immediate.
    NeverBlocked = 0,
    /// A poll-bell ring (an IPC/readiness writer) drained the waiter.
    Bell         = 1,
    /// The bounded resync-floor scheduler tick woke us (no bell fired).
    Resync       = 2,
    /// The caller's own absolute deadline expired (poll/epoll timeout).
    Timeout      = 3,
    /// A signal delivery flipped us Ready (EINTR-shaped wake).
    Signal       = 4,
    /// A matching FUTEX_WAKE removed us from the waiter list.
    FutexWake    = 5,
    /// FUTEX_WAIT deadline expired (ETIMEDOUT).
    FutexTimeout = 6,
    /// Blocked, but the wait path could not cheaply attribute the wake.
    Unknown      = 7,
}

impl WakeReason {
    #[inline]
    fn from_u8(v: u8) -> WakeReason {
        match v {
            1 => WakeReason::Bell,
            2 => WakeReason::Resync,
            3 => WakeReason::Timeout,
            4 => WakeReason::Signal,
            5 => WakeReason::FutexWake,
            6 => WakeReason::FutexTimeout,
            7 => WakeReason::Unknown,
            _ => WakeReason::NeverBlocked,
        }
    }
    /// Stable string label used by the serial dumper and the scrings JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            WakeReason::NeverBlocked => "never_blocked",
            WakeReason::Bell         => "bell",
            WakeReason::Resync       => "resync",
            WakeReason::Timeout      => "timeout",
            WakeReason::Signal       => "signal",
            WakeReason::FutexWake    => "futex_wake",
            WakeReason::FutexTimeout => "futex_timeout",
            WakeReason::Unknown      => "unknown",
        }
    }
}

/// One entry in the ring.
#[derive(Clone)]
pub struct Entry {
    pub nr: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub ret: i64,
    pub rip: u64,
    /// Return-address at `[user_rsp]` captured at syscall entry.  For calls
    /// going through the libc `syscall()` wrapper (which issues the HW
    /// `syscall` instruction directly and does not push a return address),
    /// this is the caller of the wrapper — typically a function in the
    /// application binary (libxul/firefox-bin).  Zero if the stack read
    /// failed.
    pub caller_rip: u64,
    /// Resolved path (open/openat); empty otherwise.
    pub path: String,
    /// First PATH_BYTES of read content, if this entry is a read() that we
    /// captured.  Hex-escaped by the dumper; kept as raw bytes here.
    pub read_bytes: Vec<u8>,
    /// Tick counter (10 ms `get_ticks`) when the entry was committed — lets
    /// the dumper show the approximate rate and interleaving.
    pub tick: u64,
    /// TSC-derived monotonic nanoseconds at syscall entry.  Unlike `tick`
    /// (10 ms granularity, and frozen on a dead LAPIC timer under KVM — see
    /// PR #692), this reads the vDSO calibration directly, so cross-process
    /// op ordering at a gap transition is unambiguous even inside one tick.
    pub ns: u64,
    /// Calling thread id (per-CPU `current_tid`).  The ring is per-PID; this
    /// records which thread issued the call so a chain reconstruction knows
    /// which-thread-did-what across the process's threads.
    pub tid: u64,
    /// How the wait concluded, if this entry blocked.  `NeverBlocked` for the
    /// common (non-parking) case.  See [`WakeReason`].
    pub wake: WakeReason,
}

impl Entry {
    const fn zero() -> Self {
        Entry {
            nr: 0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0, a6: 0,
            ret: 0, rip: 0, caller_rip: 0,
            path: String::new(),
            read_bytes: Vec::new(),
            tick: 0,
            ns: 0,
            tid: 0,
            wake: WakeReason::NeverBlocked,
        }
    }
}

/// Per-process ring state.
///
/// `buf` is a runtime-sized boxed slice (was a const-generic array) so a
/// focus PID's depth can be raised for a capture without recompiling — see
/// [`optrace`] and the kdb `optrace-depth` op.  `cap()` is always `buf.len()`.
pub struct Ring {
    pub buf: Box<[Entry]>,
    pub head: usize,   // index where the NEXT entry will be written
    pub len:  usize,   // number of valid entries (<= cap())
    /// Pending entry: we record at syscall-entry (nr/args/rip) and patch the
    /// return value at syscall-exit.  None when no entry is in-flight for
    /// this process on the current CPU.
    pub pending_idx: Option<usize>,
}

impl Ring {
    fn with_capacity(cap: usize) -> Self {
        let cap = cap.max(1);
        // Box the slice directly to avoid stack-allocating a large array.
        let mut v: Vec<Entry> = Vec::with_capacity(cap);
        for _ in 0..cap { v.push(Entry::zero()); }
        Ring { buf: v.into_boxed_slice(), head: 0, len: 0, pending_idx: None }
    }

    fn new() -> Self {
        Ring::with_capacity(RING_CAP_RUNTIME.load(Ordering::Relaxed))
    }

    #[inline]
    fn cap(&self) -> usize { self.buf.len() }

    /// Re-allocate the ring to `cap` entries, discarding history.  Called
    /// only from the kdb `optrace-depth` op before a capture, so clearing is
    /// intentional (the capture happens after the resize).
    fn resize(&mut self, cap: usize) {
        *self = Ring::with_capacity(cap);
    }

    fn push_begin(&mut self, mut e: Entry) -> usize {
        let cap = self.cap();
        let idx = self.head;
        // Drop old content at this slot to free its String/Vec allocations
        // before overwriting (avoids unbounded memory retention).
        self.buf[idx] = core::mem::replace(&mut e, Entry::zero());
        self.head = (self.head + 1) % cap;
        if self.len < cap { self.len += 1; }
        self.pending_idx = Some(idx);
        idx
    }

    fn iter_chronological(&self) -> impl Iterator<Item = &Entry> {
        let cap = self.cap();
        let start = if self.len < cap { 0 } else { self.head };
        let len = self.len;
        (0..len).map(move |i| &self.buf[(start + i) % cap])
    }
}

// ── Global state: PID → Ring ───────────────────────────────────────────────

static RINGS: Mutex<BTreeMap<u64, Ring>> = Mutex::new(BTreeMap::new());

/// Set of PIDs that are tracked.  When a PID is enabled and not yet present
/// in `RINGS`, the first `begin()` call creates the ring lazily.
static TRACKED: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// Enable ring-buffer tracking for `pid`.  Idempotent.
pub fn enable_for(pid: u64) {
    if pid == 0 { return; }
    let mut t = TRACKED.lock();
    if !t.contains(&pid) { t.push(pid); }
}

/// Return true if `pid` is tracked.
pub fn is_tracked(pid: u64) -> bool {
    let t = TRACKED.lock();
    t.contains(&pid)
}

// ── Per-CPU wake-reason slot ────────────────────────────────────────────────
//
// A blocking wait path (poll/epoll/select via `wait_poll_event`, or the
// FUTEX_WAIT arm) records how it concluded here, AFTER its final `schedule()`
// returns.  `begin()` resets the slot at syscall entry; `end()` folds it into
// the entry.  Because no `schedule()` runs between a wait path's post-wake
// note and `end()`, the calling thread stays on the same CPU across that
// window, so a lock-free per-CPU slot is race-free for the reader.  Writes
// from other threads while this thread is parked land on whichever CPU they
// run on and are overwritten by this thread's own post-wake note on resume.

static WAKE_REASON: [AtomicU8; MAX_CPUS] =
    [const { AtomicU8::new(0) }; MAX_CPUS];

/// Record how the current syscall's blocking wait concluded.  Called by the
/// wait paths (feature-gated at the call site) right after the wake.
#[inline]
pub fn note_wake_reason(r: WakeReason) {
    WAKE_REASON[cpu_index()].store(r as u8, Ordering::Relaxed);
}

/// Reset this CPU's wake-reason slot to `NeverBlocked` (syscall entry).
#[inline]
fn clear_wake_reason() {
    WAKE_REASON[cpu_index()].store(WakeReason::NeverBlocked as u8, Ordering::Relaxed);
}

/// Read (and reset) this CPU's wake-reason slot (syscall exit).
#[inline]
fn take_wake_reason() -> WakeReason {
    let v = WAKE_REASON[cpu_index()]
        .swap(WakeReason::NeverBlocked as u8, Ordering::Relaxed);
    WakeReason::from_u8(v)
}

// ── Gap-end freeze trigger (W101 op-trace capture) ──────────────────────────
//
// Arm from kdb; then the FIRST TCP send from a tracked FF pid after a
// configurable quiet interval sets a freeze deadline `now + grace`.  Once the
// deadline passes, `begin()` becomes a no-op, so the gap-ending send AND its
// immediate consequent chain are captured, then the post-gap storm cannot
// overwrite them.  A single serial marker is emitted when the trigger fires
// (one line per gap-end — not a hot path) so the harness can `wait` on it.
//
// All state is plain atomics; the only hot-path reader is `is_frozen_at`
// (one relaxed load) from `begin()`.
pub mod optrace {
    use super::*;

    /// Master arm flag.  When false, `note_tcp_send` is a single atomic load.
    static ARMED: AtomicBool = AtomicBool::new(false);
    /// Quiet threshold (ns) a TCP-send stream must be silent for before the
    /// next send counts as a gap end.  Default 2000 ms.
    static QUIET_NS: AtomicU64 = AtomicU64::new(2_000_000_000);
    /// Grace window (ns) recorded after the trigger fires before the ring
    /// freezes.  Default 500 ms.
    static GRACE_NS: AtomicU64 = AtomicU64::new(500_000_000);
    /// Monotonic ns of the last observed tracked-pid TCP send (0 = none yet).
    static LAST_TCP_SEND_NS: AtomicU64 = AtomicU64::new(0);
    /// Absolute monotonic ns at which the ring freezes (0 = not frozen /
    /// not triggered).  Set once by the trigger or by a manual freeze.
    static FREEZE_AT_NS: AtomicU64 = AtomicU64::new(0);

    /// Arm the trigger with the given quiet/grace thresholds (ms).  Resets
    /// the last-send timestamp and any prior freeze deadline so a fresh gap
    /// is captured.
    pub fn arm(quiet_ms: u64, grace_ms: u64) {
        QUIET_NS.store(quiet_ms.saturating_mul(1_000_000), Ordering::Relaxed);
        GRACE_NS.store(grace_ms.saturating_mul(1_000_000), Ordering::Relaxed);
        LAST_TCP_SEND_NS.store(0, Ordering::Relaxed);
        FREEZE_AT_NS.store(0, Ordering::Relaxed);
        ARMED.store(true, Ordering::Relaxed);
    }

    /// Disarm the trigger.  Leaves any existing freeze deadline untouched
    /// (use `unfreeze` to resume recording).
    pub fn disarm() { ARMED.store(false, Ordering::Relaxed); }

    /// Manually freeze the ring right now (`freeze_at = now`).
    pub fn freeze_now() {
        let now = crate::proc::vdso::monotonic_ns();
        // A monotonic_ns() of 0 (pre-calibration) would never freeze; clamp
        // to 1 so the gate (`now >= freeze_at`) engages immediately.
        FREEZE_AT_NS.store(now.max(1), Ordering::Relaxed);
    }

    /// Clear any freeze deadline and resume recording.
    pub fn unfreeze() { FREEZE_AT_NS.store(0, Ordering::Relaxed); }

    /// Hot-path gate for `begin()`: has the freeze deadline passed?
    #[inline]
    pub fn is_frozen_at(now_ns: u64) -> bool {
        let f = FREEZE_AT_NS.load(Ordering::Relaxed);
        f != 0 && now_ns >= f
    }

    /// Snapshot: `(armed, quiet_ns, grace_ns, last_send_ns, freeze_at_ns,
    /// frozen_now)`.  Used by the kdb `optrace-status` op.
    pub fn status() -> (bool, u64, u64, u64, u64, bool) {
        let now = crate::proc::vdso::monotonic_ns();
        (
            ARMED.load(Ordering::Relaxed),
            QUIET_NS.load(Ordering::Relaxed),
            GRACE_NS.load(Ordering::Relaxed),
            LAST_TCP_SEND_NS.load(Ordering::Relaxed),
            FREEZE_AT_NS.load(Ordering::Relaxed),
            is_frozen_at(now),
        )
    }

    /// Core trigger logic, parameterised on `now` for deterministic testing.
    /// Returns `true` when this call fired the trigger.
    pub fn tcp_send_at(pid: u64, now_ns: u64) -> bool {
        if !ARMED.load(Ordering::Relaxed) { return false; }
        if !is_tracked(pid) { return false; }
        let last = LAST_TCP_SEND_NS.swap(now_ns, Ordering::Relaxed);
        // Already triggered → don't re-fire (keeps the first gap end).
        if FREEZE_AT_NS.load(Ordering::Relaxed) != 0 { return false; }
        let quiet = QUIET_NS.load(Ordering::Relaxed);
        if last == 0 || now_ns.saturating_sub(last) < quiet {
            return false;
        }
        let grace = GRACE_NS.load(Ordering::Relaxed);
        let freeze_at = now_ns.saturating_add(grace).max(1);
        // CAS 0 → freeze_at so exactly one send wins the trigger.
        if FREEZE_AT_NS
            .compare_exchange(0, freeze_at, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            crate::serial_println!(
                "[OPTRACE] gap-end trigger fired pid={} quiet_ms={} grace_ms={} \
                 last_ns={} now_ns={} freeze_at_ns={}",
                pid, quiet / 1_000_000, grace / 1_000_000, last, now_ns, freeze_at
            );
            true
        } else {
            false
        }
    }

    /// Hook from the socket TCP-send path (feature-gated at the call site).
    pub fn note_tcp_send(pid: u64) {
        // Fast bail before reading the clock when disarmed.
        if !ARMED.load(Ordering::Relaxed) { return; }
        let now = crate::proc::vdso::monotonic_ns();
        let _ = tcp_send_at(pid, now);
    }
}

// ── Ring depth control (kdb `optrace-depth`) ────────────────────────────────

/// Set the default capacity used for rings created from now on.  Does NOT
/// resize existing rings (use `resize_ring` for a specific focus pid).
pub fn set_default_capacity(cap: usize) {
    RING_CAP_RUNTIME.store(cap.max(1), Ordering::Relaxed);
}

/// Read the current default capacity for new rings.
pub fn default_capacity() -> usize {
    RING_CAP_RUNTIME.load(Ordering::Relaxed)
}

/// Resize (and clear) the ring for `pid` to `cap` entries, creating it if the
/// pid is tracked but has no ring yet.  Returns the resulting capacity, or 0
/// if `pid` is not tracked.  Called from kdb before a capture, so discarding
/// history is intentional.
pub fn resize_ring(pid: u64, cap: usize) -> usize {
    if !is_tracked(pid) { return 0; }
    let cap = cap.max(1);
    let mut rings = RINGS.lock();
    let ring = rings.entry(pid).or_insert_with(|| Ring::with_capacity(cap));
    ring.resize(cap);
    ring.cap()
}

/// Current capacity of `pid`'s ring (0 if none).  Used by `optrace-status`.
pub fn ring_capacity(pid: u64) -> usize {
    RINGS.lock().get(&pid).map(|r| r.cap()).unwrap_or(0)
}

/// Snapshot of tracked pids and their ring depth/occupancy, for kdb status.
pub fn tracked_rings() -> Vec<(u64, usize, usize)> {
    let rings = RINGS.lock();
    let t = TRACKED.lock();
    t.iter()
        .map(|&pid| {
            let (cap, len) = rings.get(&pid).map(|r| (r.cap(), r.len)).unwrap_or((0, 0));
            (pid, cap, len)
        })
        .collect()
}

/// Record syscall entry — stores (nr, args, rip, caller_rip) in a new ring
/// slot and returns its index.  Caller passes the index back to `end()`
/// together with the syscall's return value.
///
/// `caller_rip` is the value at `[user_rsp]` at syscall entry; for libc
/// `syscall()`-wrapper calls this is the return address to the caller of
/// the wrapper (typically a libxul / firefox-bin function).
pub fn begin(
    pid: u64, nr: u64,
    a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64,
    rip: u64, caller_rip: u64,
) -> Option<usize> {
    if !is_tracked(pid) { return None; }
    // TSC-derived monotonic ns; also drives the gap-end freeze gate so we
    // read the clock exactly once per entry.
    let ns = crate::proc::vdso::monotonic_ns();
    // Gap-end freeze: once the trigger has fired and the grace window has
    // elapsed, stop recording so the captured transition tail is not
    // overwritten by the post-gap storm.  Pure instrumentation — no syscall
    // behaviour changes, the call still runs; only the trace slot is skipped.
    if optrace::is_frozen_at(ns) { return None; }
    // Reset the per-CPU wake-reason slot for this syscall.  A blocking wait
    // path overwrites it after its final schedule(); end() folds it in.
    clear_wake_reason();
    let tick = crate::arch::x86_64::irq::get_ticks();
    let tid = crate::proc::current_tid();
    let mut rings = RINGS.lock();
    let ring = rings.entry(pid).or_insert_with(Ring::new);
    let entry = Entry {
        nr, a1, a2, a3, a4, a5, a6,
        ret: 0, rip, caller_rip,
        path: String::new(),
        read_bytes: Vec::new(),
        tick,
        ns,
        tid,
        wake: WakeReason::NeverBlocked,
    };
    Some(ring.push_begin(entry))
}

/// Attach a resolved path string to the current (or most-recent) entry for
/// `pid` — used by open/openat to record the path they resolved.  No-op if
/// the PID has no ring or no pending entry.
pub fn set_path(pid: u64, idx: Option<usize>, path: &str) {
    let Some(idx) = idx else { return; };
    let mut rings = RINGS.lock();
    if let Some(ring) = rings.get_mut(&pid) {
        if let Some(slot) = ring.buf.get_mut(idx) {
            let end = path.len().min(PATH_BYTES);
            slot.path = path[..end].into();
        }
    }
}

/// Attach first bytes returned from a read() to the current entry.  `data`
/// is truncated to READ_BYTES.
pub fn set_read_bytes(pid: u64, idx: Option<usize>, data: &[u8]) {
    let Some(idx) = idx else { return; };
    let mut rings = RINGS.lock();
    if let Some(ring) = rings.get_mut(&pid) {
        if let Some(slot) = ring.buf.get_mut(idx) {
            let end = data.len().min(READ_BYTES);
            slot.read_bytes.clear();
            slot.read_bytes.extend_from_slice(&data[..end]);
        }
    }
}

/// Patch the return value (and the wake reason recorded by any blocking wait
/// this syscall performed) onto the entry previously created by `begin()`.
pub fn end(pid: u64, idx: Option<usize>, ret: i64) {
    let Some(idx) = idx else { return; };
    // Read the per-CPU wake-reason slot BEFORE taking RINGS.  No schedule()
    // runs between a wait path's post-wake note and here, so this CPU's slot
    // still reflects THIS thread's wait outcome.
    let wake = take_wake_reason();
    let mut rings = RINGS.lock();
    if let Some(ring) = rings.get_mut(&pid) {
        if let Some(slot) = ring.buf.get_mut(idx) {
            slot.ret = ret;
            slot.wake = wake;
        }
        ring.pending_idx = None;
    }
}

/// Pretty-name table for the most common Linux x86_64 syscalls.  Only used
/// by the dumper — unknown numbers are printed as "nr=<N>".
fn nr_name(nr: u64) -> &'static str {
    match nr {
        0   => "read",
        1   => "write",
        2   => "open",
        3   => "close",
        4   => "stat",
        5   => "fstat",
        6   => "lstat",
        7   => "poll",
        8   => "lseek",
        9   => "mmap",
        10  => "mprotect",
        11  => "munmap",
        12  => "brk",
        13  => "rt_sigaction",
        14  => "rt_sigprocmask",
        15  => "rt_sigreturn",
        16  => "ioctl",
        17  => "pread64",
        18  => "pwrite64",
        19  => "readv",
        20  => "writev",
        21  => "access",
        22  => "pipe",
        23  => "select",
        24  => "sched_yield",
        25  => "mremap",
        28  => "madvise",
        32  => "dup",
        33  => "dup2",
        35  => "nanosleep",
        39  => "getpid",
        56  => "clone",
        57  => "fork",
        59  => "execve",
        60  => "exit",
        61  => "wait4",
        62  => "kill",
        63  => "uname",
        72  => "fcntl",
        78  => "getdents",
        79  => "getcwd",
        87  => "unlink",
        89  => "readlink",
        96  => "gettimeofday",
        97  => "getrlimit",
        99  => "sysinfo",
        102 => "getuid",
        104 => "getgid",
        107 => "geteuid",
        108 => "getegid",
        110 => "getppid",
        125 => "capget",
        158 => "arch_prctl",
        160 => "setrlimit",
        186 => "gettid",
        202 => "futex",
        217 => "getdents64",
        218 => "set_tid_address",
        228 => "clock_gettime",
        231 => "exit_group",
        234 => "tgkill",
        257 => "openat",
        262 => "newfstatat",
        302 => "prlimit64",
        318 => "getrandom",
        332 => "statx",
        435 => "clone3",
        _   => "",
    }
}

/// Emit the entries of `ring` framed by `[SC-RING-BEGIN]`/`[SC-RING-END]`.
///
/// The BEGIN line carries the legacy `pid`/`exit_code`/`entries` fields the
/// harness regex anchors on, plus additive `kind=` (exit|frozen) and
/// `ns_now=` tail fields (ignored by the anchored regex).  Each `[SC-RING]`
/// line gains additive `ns=`/`tid=`/`wake=` fields, appended after `ret=` so
/// older parsers keep matching.
fn emit_ring(pid: u64, ring: &Ring, exit_code: i64, kind: &str) {
    let ns_now = crate::proc::vdso::monotonic_ns();
    crate::serial_println!(
        "[SC-RING-BEGIN] pid={} exit_code={} entries={} kind={} ns_now={}",
        pid, exit_code, ring.len, kind, ns_now
    );

    for (i, e) in ring.iter_chronological().enumerate() {
        let name = nr_name(e.nr);
        let name_field = if name.is_empty() {
            alloc::format!("nr={}", e.nr)
        } else {
            alloc::format!("{}/{}", name, e.nr)
        };
        // Print one header line per entry.  `caller_rip` is the return
        // address at `[user_rsp]` captured at syscall entry: typically the
        // caller of libc's `syscall()` wrapper, which resolves directly to
        // a libxul / firefox-bin function name when the offset-from-base is
        // looked up in the Breakpad .sym symbol files.
        crate::serial_println!(
            "[SC-RING] i={:03} t={} {} rip={:#x} cr={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x} a6={:#x} ret={} ns={} tid={} wake={}",
            i, e.tick, name_field,
            e.rip, e.caller_rip,
            e.a1, e.a2, e.a3, e.a4, e.a5, e.a6, e.ret,
            e.ns, e.tid, e.wake.as_str()
        );
        if !e.path.is_empty() {
            crate::serial_println!("[SC-RING-PATH] i={:03} path={:?}", i, &e.path);
        }
        if !e.read_bytes.is_empty() {
            // Hex-encode the bytes.  Keep everything on a single line — the
            // harness parses this by regex so line boundaries matter.
            let mut hex = alloc::string::String::with_capacity(e.read_bytes.len() * 2);
            for b in &e.read_bytes {
                let hi = b >> 4;
                let lo = b & 0xF;
                hex.push(HEX[hi as usize] as char);
                hex.push(HEX[lo as usize] as char);
            }
            crate::serial_println!(
                "[SC-RING-BYTES] i={:03} len={} hex={}", i, e.read_bytes.len(), hex
            );
        }
    }

    crate::serial_println!("[SC-RING-END] pid={}", pid);
}

/// Dump the ring for `pid` to the serial console, framed by
/// `[SC-RING-BEGIN]` / `[SC-RING-END]`.  Called from `exit_group` when the
/// exit code is non-zero.  Clears the ring afterwards so a crashed process
/// doesn't leak its entries into a re-used PID.
pub fn dump_for_exit(pid: u64, exit_code: i64) {
    let mut rings = RINGS.lock();
    let Some(ring) = rings.remove(&pid) else {
        // No ring — nothing to dump.  Still emit the frame so the harness
        // can record that a non-zero exit happened but produced no trace.
        crate::serial_println!(
            "[SC-RING-BEGIN] pid={} exit_code={} entries=0 kind=exit ns_now=0", pid, exit_code);
        crate::serial_println!("[SC-RING-END] pid={}", pid);
        return;
    };
    emit_ring(pid, &ring, exit_code, "exit");
}

/// Non-destructively dump the (typically frozen) ring for `pid` on demand —
/// called from the kdb `scrings-dump` op during a live W101 capture, where
/// the process is still running.  Reuses the `[SC-RING-BEGIN]`/`[SC-RING-END]`
/// framing so the existing `scrings` parser handles it unchanged; `kind=frozen`
/// distinguishes it from an exit dump.  The ring is left in place so it can be
/// re-dumped.
pub fn dump_for_pid(pid: u64) {
    let rings = RINGS.lock();
    let Some(ring) = rings.get(&pid) else {
        crate::serial_println!(
            "[SC-RING-BEGIN] pid={} exit_code=0 entries=0 kind=frozen ns_now=0", pid);
        crate::serial_println!("[SC-RING-END] pid={}", pid);
        return;
    };
    emit_ring(pid, ring, 0, "frozen");
}

/// Dump every tracked pid's ring on demand (frozen capture convenience).
pub fn dump_all_tracked() {
    let pids: Vec<u64> = TRACKED.lock().clone();
    for pid in pids {
        dump_for_pid(pid);
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Drop the ring for a pid that exited cleanly (zero exit code).  Prevents
/// unbounded growth when processes come and go in normal operation.
///
/// Lock order: TRACKED → RINGS, matching `begin()`.  An earlier version
/// took RINGS first and would have invited an ABBA against any concurrent
/// `begin()` that arrived between the two acquisitions.  In single-process
/// firefox-test runs this never fires in practice, but the order is fixed
/// here to keep `begin()` and `drop_ring()` on the same lock-acquisition
/// graph.
pub fn drop_ring(pid: u64) {
    let mut t = TRACKED.lock();
    t.retain(|p| *p != pid);
    let mut rings = RINGS.lock();
    rings.remove(&pid);
}

/// Emit a `[FF/read-bytes]` line for synthetic-filesystem reads — used by
/// Part 2 of the diagnostic instrumentation.  Called from sys_read_linux()
/// after a successful read, with the resolved path, returned byte count,
/// and the first-up-to-64 bytes of content.
pub fn log_synthetic_read(fd: u64, path: &str, ret: i64, data: &[u8]) {
    let n = data.len().min(64);
    let mut hex = alloc::string::String::with_capacity(n * 2);
    for b in &data[..n] {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0xF) as usize] as char);
    }
    crate::serial_println!(
        "[FF/read-bytes] fd={} path={:?} ret={} bytes={}",
        fd, path, ret, hex
    );
}

/// Return true if `path` is on a synthetic filesystem we want to peek at.
/// Keeps the log short by excluding `/disk/opt/firefox/**` and similar
/// high-volume regular-disk paths.
pub fn is_synthetic_path(path: &str) -> bool {
    path.starts_with("/proc")
        || path.starts_with("/sys")
        || path == "/etc/nsswitch.conf"
        || path == "/etc/ld.so.cache"
        || path == "/etc/resolv.conf"
        || path == "/etc/host.conf"
        || path == "/etc/hosts"
        || path == "/etc/gai.conf"
        || path == "/etc/localtime"
        || path == "/etc/passwd"
        || path == "/etc/group"
}

// ── User-mode stack snapshot (exit-time diagnostic) ──────────────────────────
//
// On non-zero exit, capture the caller's user RSP / RBP, dump the first 128
// bytes of the user stack, then walk the frame-pointer chain up to 8 frames
// deep.  Gives us the caller's return-address chain so a log analyzer can
// resolve each RIP back to a function via the ELF symbols of the mapped
// libraries.
//
// Page-table reads are routed through `virt_to_phys_in(cr3, va)` which returns
// `None` for any unmapped page — so we can never fault while walking.  Reads
// go through the PHYS_OFF identity map (0xFFFF_8000_0000_0000), matching the
// pattern used by PE loader helpers.
//
// Output format (consumed by `qemu-harness.py stack`):
//
//   [SC-RING-STACK] pid=<N> rsp=<rsp> rbp=<rbp>
//   [SC-RING-STACK] stack_top=<256-hex-chars>
//   [SC-RING-STACK] frame[0] rbp=<saved_rbp> rip=<saved_rip>
//   ...
//   [SC-RING-STACK-END]

const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Page-fault-safe read of a u64 from user virtual address `va` under page
/// table `cr3`.  Returns `None` if the page is not mapped or the address
/// crosses into the kernel half.
fn read_user_u64_safe(cr3: u64, va: u64) -> Option<u64> {
    // Reject kernel-half addresses (anything >= KERNEL_VIRT_BASE) and
    // addresses that cross a page boundary in a way we can't handle.  The
    // 8-byte read straddling a page is fine here because `virt_to_phys_in`
    // returns the physical address for the starting page; we re-check the
    // second page if the address is misaligned.
    if va >= astryx_shared::KERNEL_VIRT_BASE { return None; }
    let end = va.checked_add(8)?;
    if end > astryx_shared::KERNEL_VIRT_BASE { return None; }

    // Resolve starting byte (phys0 already includes the in-page offset).
    let phys0 = crate::mm::vmm::virt_to_phys_in(cr3, va)?;
    let page_off = va & 0xFFF;
    if page_off + 8 > 0x1000 {
        // The 8-byte read straddles a page boundary.  Resolve the SECOND
        // page ONCE (rather than per byte) and read the two halves through
        // PHYS_OFF.  Re-walking the page tables for each of the 8 bytes
        // costs 8x VMM_LOCK acquisitions on every cross-page user-stack
        // probe — measurable on the SC-RING-STACK dump path that walks up
        // to 16 KiB of user stack.
        let va_next = (va & !0xFFF).wrapping_add(0x1000);
        let phys_next_base = crate::mm::vmm::virt_to_phys_in(cr3, va_next)?;
        let first_len = (0x1000 - page_off) as usize; // 1..=7 bytes from phys0
        let mut bytes = [0u8; 8];
        unsafe {
            // First half: bytes from the starting page, contiguous from phys0.
            for i in 0..first_len {
                bytes[i] = core::ptr::read_volatile(
                    (PHYS_OFF + phys0 + i as u64) as *const u8
                );
            }
            // Second half: bytes from the next page, starting at its base.
            for i in first_len..8 {
                bytes[i] = core::ptr::read_volatile(
                    (PHYS_OFF + phys_next_base + (i - first_len) as u64) as *const u8
                );
            }
        }
        return Some(u64::from_le_bytes(bytes));
    }
    // Single-page read — straight unaligned read through PHYS_OFF.
    // phys0 already accounts for the in-page offset of `va`.
    unsafe {
        Some(core::ptr::read_unaligned((PHYS_OFF + phys0) as *const u64))
    }
}

/// Page-fault-safe read of up to `N` bytes from user VA `va` under `cr3`.
/// Any unmapped byte in the range truncates the returned slice length.
fn read_user_bytes_safe(cr3: u64, va: u64, out: &mut [u8]) -> usize {
    if va >= astryx_shared::KERNEL_VIRT_BASE { return 0; }
    let mut n = 0;
    for i in 0..out.len() {
        let b_va = va.wrapping_add(i as u64);
        if b_va >= astryx_shared::KERNEL_VIRT_BASE { break; }
        match crate::mm::vmm::virt_to_phys_in(cr3, b_va) {
            Some(phys) => unsafe {
                out[i] = core::ptr::read_volatile((PHYS_OFF + phys) as *const u8);
            },
            None => break,
        }
        n += 1;
    }
    n
}

/// Dump a user-mode stack snapshot to the serial console.  Called from
/// `exit_group` when the exit code is non-zero.  `rsp` and `rbp` are the
/// user values captured at syscall entry.  `cr3` is the caller's page
/// table (must still be live — call before process teardown).
pub fn dump_exit_stack(pid: u64, cr3: u64, rsp: u64, rbp: u64) {
    crate::serial_println!(
        "[SC-RING-STACK] pid={} rsp={:#x} rbp={:#x}", pid, rsp, rbp
    );

    // 128 bytes at [rsp, rsp+128) — the top of the user stack.
    let mut stack_top = [0u8; 128];
    let got = read_user_bytes_safe(cr3, rsp, &mut stack_top);
    let mut hex = alloc::string::String::with_capacity(got * 2);
    for b in &stack_top[..got] {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0xF) as usize] as char);
    }
    crate::serial_println!("[SC-RING-STACK] stack_top={}", hex);

    // Extended window: up to 16 KiB at [rsp, rsp+16K), emitted as chunked
    // hex lines (1 KiB per line = 2048 hex chars).  Consumed by an offline
    // post-processor that scans for u64 values within [lib_base, lib_base +
    // code_size) as candidate return addresses — recovers the libxul and
    // firefox-bin frames that the RBP chain walker cannot cross because
    // those libraries are built with `-fomit-frame-pointer`.
    //
    // The dump stops early on the first unmapped page: stacks typically live
    // near the top of user VA and may have guard pages below; truncation is
    // expected and signalled by a shorter final chunk.
    const EXT_CHUNK: usize = 1024;      // bytes per line
    const EXT_CHUNKS: usize = 16;       // 16 KiB total
    let mut chunk_buf = [0u8; EXT_CHUNK];
    for ci in 0..EXT_CHUNKS {
        let chunk_va = rsp.wrapping_add((ci * EXT_CHUNK) as u64);
        let n = read_user_bytes_safe(cr3, chunk_va, &mut chunk_buf);
        if n == 0 { break; }
        let mut line = alloc::string::String::with_capacity(n * 2);
        for b in &chunk_buf[..n] {
            line.push(HEX[(b >> 4) as usize] as char);
            line.push(HEX[(b & 0xF) as usize] as char);
        }
        crate::serial_println!(
            "[SC-RING-STACK] stack_ext i={} va={:#x} len={} hex={}",
            ci, chunk_va, n, line
        );
        if n < EXT_CHUNK { break; }
    }

    // Walk the frame-pointer chain up to 8 frames deep.
    //
    // Convention (System V x86-64, -fno-omit-frame-pointer):
    //   [rbp + 0] = saved RBP of caller
    //   [rbp + 8] = return RIP to caller
    //
    // Stop early on: unmapped page, null/tiny RBP, non-user RBP, or RBP
    // not strictly greater than previous (guards against cycles).
    let mut cur_rbp = rbp;
    let mut prev_rbp: u64 = 0;
    for i in 0..8u32 {
        if cur_rbp == 0 || cur_rbp < 0x1000 { break; }
        if cur_rbp >= astryx_shared::KERNEL_VIRT_BASE { break; }
        // Frame pointer should be 8-byte aligned in well-behaved code.
        // Don't require it strictly — glibc has some frames that are not —
        // but bail if it's wildly unaligned.
        if cur_rbp & 0x7 != 0 { break; }
        let saved_rbp = match read_user_u64_safe(cr3, cur_rbp) {
            Some(v) => v,
            None => break,
        };
        let saved_rip = match read_user_u64_safe(cr3, cur_rbp.wrapping_add(8)) {
            Some(v) => v,
            None => break,
        };
        crate::serial_println!(
            "[SC-RING-STACK] frame[{}] rbp={:#x} rip={:#x}", i, saved_rbp, saved_rip
        );
        // Cycle / descent guard: frame pointers walk UP the stack, so each
        // saved RBP must be strictly greater than the current one.
        if saved_rbp <= cur_rbp {
            // Accept the final frame but don't continue — avoids infinite loops
            // on corrupted stacks or leaf frames where the caller did not set RBP.
            break;
        }
        // Plausibility: rbp chain should stay within ~2 MiB of itself (same stack).
        if saved_rbp.wrapping_sub(cur_rbp) > 0x20_0000 { break; }
        prev_rbp = cur_rbp;
        cur_rbp = saved_rbp;
        let _ = prev_rbp;
    }
    crate::serial_println!("[SC-RING-STACK-END]");
}

/// Compact RBP-chain walk for futex_wait registration sites.
///
/// Walks up to `MAX_FRAMES` frames and emits a single tagged line:
///
///     [FUTEX_WAIT_STACK] tid=<N> pid=<N> uaddr=<hex> leaf=<rip> \
///         f1=<rip> f2=<rip> ... f7=<rip>
///
/// Combined with the [FFTEST/mmap-so] table the harness can resolve each
/// frame to <library>+<offset> and (with --symbolise) <symbol>+<delta>.
/// This is the minimum information needed to identify which Mozilla
/// CondVar / Semaphore wait-site a parked worker is blocked on, without
/// needing a kdb round-trip or a host-side GDB attach (both of which are
/// fragile under SLIRP+e1000 hostfwd).
///
/// SAFETY-of-fault-recovery: every memory read uses `read_user_u64_safe`
/// which walks the page table via `virt_to_phys_in` and returns `None` on
/// any unmapped step.  No PF can fire from this path.  The caller must
/// supply `cr3` of the *current* thread's address space (i.e. read by
/// `crate::mm::vmm::get_cr3()` while still on the calling thread's CR3).
/// Emit a single line of up to N hex u64 words from a user stack so the
/// harness can do a stack-scan symbolisation pass (catches return addresses
/// of frames whose callee was built with -fomit-frame-pointer, where the
/// rbp-chain walker dies after one or two frames).
///
/// Output: `[FUTEX_WAIT_SCAN] tid=<N> pid=<N> rsp=<hex> w0=<hex> w1=<hex> ...`
///
/// Words are read with `read_user_u64_safe`; an unmapped page truncates
/// the suffix.  The default depth (32 words = 256 bytes of stack) is small
/// enough to keep the line under the serial driver's 1024-byte budget but
/// deep enough to capture two or three frames' worth of return-address
/// candidates above the futex syscall's argument-pass region.
fn dump_futex_wait_scan(tid: u64, pid: u64, cr3: u64, rsp: u64) {
    // 128 words = 1 KiB of stack — enough to walk past pthread_cond_wait's
    // local-variable region and capture the libxul/libnspr return address
    // of whatever user code called pthread_cond_wait or sem_wait.  Emitted
    // as a single line to stay below the serial driver's 4 KiB budget
    // (128 × ~22 bytes per " w<idx>=<hex>" tag ≈ 2.8 KiB).
    const WORDS: u64 = 128;
    let mut suffix = alloc::string::String::with_capacity(WORDS as usize * 22);
    for i in 0..WORDS {
        let va = rsp.wrapping_add(i.wrapping_mul(8));
        if va >= astryx_shared::KERNEL_VIRT_BASE { break; }
        match read_user_u64_safe(cr3, va) {
            Some(w) => {
                let _ = core::fmt::Write::write_fmt(
                    &mut suffix,
                    format_args!(" w{}={:#x}", i, w),
                );
            }
            None => break,
        }
    }
    crate::serial_println!(
        "[FUTEX_WAIT_SCAN] tid={} pid={} rsp={:#x}{}",
        tid, pid, rsp, suffix
    );
}

pub fn dump_futex_wait_stack(tid: u64, pid: u64, uaddr: u64, cr3: u64,
                             leaf_rip: u64, rsp: u64, rbp: u64) {
    // Stack-scan pass first — catches return addresses where the rbp chain
    // is unreliable (libxul / libnspr are -fomit-frame-pointer in release
    // builds, so the rbp-chain walk often dies after f1-f2 inside libc).
    #[cfg(feature = "futex-wait-scan")]
    dump_futex_wait_scan(tid, pid, cr3, rsp);
    const MAX_FRAMES: u32 = 7;
    // Build the suffix incrementally so we emit a single line.  An empty
    // chain still prints the leaf — useful when libc's sem_wait clobbers
    // RBP before parking and the chain dies at frame 0.
    let mut suffix = alloc::string::String::with_capacity(8 * 24);
    let mut cur_rbp = rbp;
    let mut prev_rbp: u64 = 0;
    for i in 0..MAX_FRAMES {
        if cur_rbp == 0 || cur_rbp < 0x1000 { break; }
        if cur_rbp >= astryx_shared::KERNEL_VIRT_BASE { break; }
        if cur_rbp & 0x7 != 0 { break; }
        let saved_rbp = match read_user_u64_safe(cr3, cur_rbp) {
            Some(v) => v, None => break,
        };
        let saved_rip = match read_user_u64_safe(cr3, cur_rbp.wrapping_add(8)) {
            Some(v) => v, None => break,
        };
        // Reject obviously bogus RIPs (zero, kernel half).  Keeps the
        // emitted line tight and the post-processor simple.
        if saved_rip == 0 || saved_rip >= astryx_shared::KERNEL_VIRT_BASE {
            break;
        }
        // i is 0..MAX_FRAMES; format the ordinal one-based for parity with
        // [SC-RING-STACK] frame[i] semantics.
        let _ = core::fmt::Write::write_fmt(
            &mut suffix,
            format_args!(" f{}={:#x}", i + 1, saved_rip),
        );
        let _ = saved_rbp;
        // Cycle / descent guard: each saved_rbp must be strictly higher
        // than the current one and within a reasonable stack window.
        if saved_rbp <= cur_rbp { break; }
        if saved_rbp.wrapping_sub(cur_rbp) > 0x20_0000 { break; }
        prev_rbp = cur_rbp;
        cur_rbp = saved_rbp;
        let _ = prev_rbp;
    }
    crate::serial_println!(
        "[FUTEX_WAIT_STACK] tid={} pid={} uaddr={:#x} leaf={:#x}{}",
        tid, pid, uaddr, leaf_rip, suffix
    );
}

// ── Test accessors ──────────────────────────────────────────────────────────
//
// Read-only snapshots of ring internals for the in-kernel test suite
// (`test_runner.rs`).  Compiled in every build the module is (so
// `firefox-test-core` and `test-mode`); they take the same locks as the live
// paths and never mutate state.

/// Snapshot the most-recently committed entry for `pid`:
/// `(nr, tid, ns, wake, ret)`.  `None` if the pid has no ring / no entries.
pub fn snapshot_last(pid: u64) -> Option<(u64, u64, u64, WakeReason, i64)> {
    let rings = RINGS.lock();
    let ring = rings.get(&pid)?;
    if ring.len == 0 { return None; }
    let cap = ring.cap();
    // head points at the NEXT write slot; the last written is one behind it.
    let idx = (ring.head + cap - 1) % cap;
    let e = &ring.buf[idx];
    Some((e.nr, e.tid, e.ns, e.wake, e.ret))
}

/// Number of valid entries currently held for `pid` (0 if none).
pub fn entry_count(pid: u64) -> usize {
    RINGS.lock().get(&pid).map(|r| r.len).unwrap_or(0)
}
