//! Per-process activity metrics.
//!
//! Counters are accumulated in a fixed-size, pre-allocated, lockless slot
//! table keyed by PID.  The table lives outside `Process` so increments from
//! interrupt context (page-fault handler, block-IO completion ISR, network
//! receive paths) can use a single `fetch_add(Relaxed)` per event without
//! ever touching `PROCESS_TABLE.lock()` — that lock is held for tens of
//! microseconds during long mmap / fork edits and would serialise the hot
//! syscall path otherwise.
//!
//! The exposed metrics mirror the field set documented for Linux's
//! /proc/[pid]/stat (see `proc(5)`) plus a per-syscall-category breakdown
//! patterned on POSIX wait/IO/IPC verbs.  Cross-reference: POSIX.1-2017
//! §2.3 "Error Numbers" for the syscall surface; Intel SDM Vol. 3A §17 for
//! the use of TSC-derived ticks as the wall-clock anchor for stuck-syscall
//! detection.
//!
//! ## Per-PID slot table
//!
//! `METRICS[pid]` is `None` until `register(pid)` is called from the
//! `Process::new` paths (`create_kernel_process_inner`, `fork_process`,
//! `fork_process_share_vm`, `vfork_process`).  `unregister(pid)` is called
//! by the reaper when a process is removed from `PROCESS_TABLE` so that
//! PIDs can be re-issued without collision.  Out-of-range or unregistered
//! PIDs no-op the increment helpers — the only cost is one bounds-check
//! plus one `Acquire` load of the registration `AtomicBool`.
//!
//! The table size matches `SIGNAL_HINT_TABLE_SIZE` (256) which is the same
//! bound used for the signal-pending hint table.  Bump together if PIDs
//! ever exceed that count.
//!
//! ## Hot-path discipline
//!
//! Every public `bump_*` function is one branch + one `fetch_add(Relaxed)`.
//! No locks, no allocations, no formatting.  The periodic dump in
//! [`emit_periodic`] takes a `try_lock` on `PROCESS_TABLE` for the name
//! resolution and silently skips emission when the lock is contended.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use crate::proc::Pid;

/// Upper bound on PIDs covered by the metrics table.
///
/// Matches `SIGNAL_HINT_TABLE_SIZE` for symmetry — both tables index by
/// PID without hashing.  Out-of-range PIDs silently no-op.
pub const METRICS_TABLE_SIZE: usize = 256;

/// One per-process activity record.  All fields are `AtomicU64` so any CPU
/// can update them with a single `fetch_add(Relaxed)` in hot paths.
///
/// Categories mirror the bucketing in [`syscall_category`].  The set was
/// chosen to answer the common operator question "what is PID X doing right
/// now?" — file I/O, network I/O, memory operations, blocking waits,
/// process lifecycle, signals — without per-syscall granularity.
#[repr(C)]
pub struct ProcessMetrics {
    pub sc_vm:     AtomicU64,
    pub sc_file:   AtomicU64,
    pub sc_net:    AtomicU64,
    pub sc_sync:   AtomicU64,
    pub sc_proc:   AtomicU64,
    pub sc_signal: AtomicU64,
    pub sc_other:  AtomicU64,

    pub pf_count: AtomicU64,

    pub disk_r_bytes: AtomicU64,
    pub disk_w_bytes: AtomicU64,

    /// Count of distinct block-device read *requests* (one per `do_io` call).
    /// Together with `disk_r_bytes` this exposes the read-batching efficiency:
    /// for a fixed byte total, fewer requests means larger coalesced transfers
    /// and fewer device round-trips — the metric that moves when the
    /// demand-fault readahead coalesces contiguous blocks.
    pub disk_r_reqs: AtomicU64,

    pub net_r_bytes: AtomicU64,
    pub net_w_bytes: AtomicU64,

    /// Last syscall number observed for this PID (any thread).
    /// Updated at dispatch entry; cleared to `-1` at dispatch exit.
    /// `i32` (signed) so the "no current syscall" sentinel can be a
    /// negative value, distinguishing it from legitimate syscall 0 (read).
    pub last_sc_nr: AtomicI32,
    /// Tick value captured at the last syscall entry.  Together with
    /// `last_sc_nr` this lets the periodic dump compute
    /// `(now - last_sc_tick)` to flag threads stuck in the kernel.
    pub last_sc_tick: AtomicU64,
}

impl ProcessMetrics {
    const fn new() -> Self {
        Self {
            sc_vm:        AtomicU64::new(0),
            sc_file:      AtomicU64::new(0),
            sc_net:       AtomicU64::new(0),
            sc_sync:      AtomicU64::new(0),
            sc_proc:      AtomicU64::new(0),
            sc_signal:    AtomicU64::new(0),
            sc_other:     AtomicU64::new(0),
            pf_count:     AtomicU64::new(0),
            disk_r_bytes: AtomicU64::new(0),
            disk_w_bytes: AtomicU64::new(0),
            disk_r_reqs:  AtomicU64::new(0),
            net_r_bytes:  AtomicU64::new(0),
            net_w_bytes:  AtomicU64::new(0),
            last_sc_nr:   AtomicI32::new(-1),
            last_sc_tick: AtomicU64::new(0),
        }
    }

    fn reset(&self) {
        self.sc_vm.store(0, Ordering::Relaxed);
        self.sc_file.store(0, Ordering::Relaxed);
        self.sc_net.store(0, Ordering::Relaxed);
        self.sc_sync.store(0, Ordering::Relaxed);
        self.sc_proc.store(0, Ordering::Relaxed);
        self.sc_signal.store(0, Ordering::Relaxed);
        self.sc_other.store(0, Ordering::Relaxed);
        self.pf_count.store(0, Ordering::Relaxed);
        self.disk_r_bytes.store(0, Ordering::Relaxed);
        self.disk_w_bytes.store(0, Ordering::Relaxed);
        self.disk_r_reqs.store(0, Ordering::Relaxed);
        self.net_r_bytes.store(0, Ordering::Relaxed);
        self.net_w_bytes.store(0, Ordering::Relaxed);
        self.last_sc_nr.store(-1, Ordering::Relaxed);
        self.last_sc_tick.store(0, Ordering::Relaxed);
    }

    /// Sum of all syscall category counters.
    pub fn sc_total(&self) -> u64 {
        self.sc_vm.load(Ordering::Relaxed)
            + self.sc_file.load(Ordering::Relaxed)
            + self.sc_net.load(Ordering::Relaxed)
            + self.sc_sync.load(Ordering::Relaxed)
            + self.sc_proc.load(Ordering::Relaxed)
            + self.sc_signal.load(Ordering::Relaxed)
            + self.sc_other.load(Ordering::Relaxed)
    }
}

/// Per-PID slot table.  Slot `i` is live iff `REGISTERED[i].load(Acquire)`
/// is `true`.  The two atomics are independent — readers must always check
/// `REGISTERED` first; the lookup helpers below encapsulate the pattern.
static METRICS: [ProcessMetrics; METRICS_TABLE_SIZE] =
    [const { ProcessMetrics::new() }; METRICS_TABLE_SIZE];

static REGISTERED: [AtomicBool; METRICS_TABLE_SIZE] =
    [const { AtomicBool::new(false) }; METRICS_TABLE_SIZE];

/// Mark `pid` live and zero its counters.  Idempotent.
pub fn register(pid: Pid) {
    let idx = pid as usize;
    if idx >= METRICS_TABLE_SIZE { return; }
    METRICS[idx].reset();
    REGISTERED[idx].store(true, Ordering::Release);
}

/// Mark `pid` dead.  Subsequent increments for the same slot no-op until
/// it is registered again.  Called by the reaper.
pub fn unregister(pid: Pid) {
    let idx = pid as usize;
    if idx >= METRICS_TABLE_SIZE { return; }
    REGISTERED[idx].store(false, Ordering::Release);
}

/// Look up the metrics slot for `pid`, returning `None` if the slot is
/// out of range or not registered.  Hot-path callers wrap this in their
/// own one-line `if let Some(m) = …` and bump the relevant counter.
#[inline]
fn lookup(pid: Pid) -> Option<&'static ProcessMetrics> {
    let idx = pid as usize;
    if idx >= METRICS_TABLE_SIZE { return None; }
    if !REGISTERED[idx].load(Ordering::Acquire) { return None; }
    Some(&METRICS[idx])
}

// ── Syscall category bucketing ────────────────────────────────────────────

/// One of seven mutually exclusive activity classes.  See
/// [`syscall_category`] for the Linux x86_64 number-to-class mapping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyscallCategory { Vm, File, Net, Sync, Proc, Signal, Other }

/// Classify a Linux x86_64 syscall number into the category whose counter
/// should be bumped.  Numbers come from `arch/x86_64/include/uapi/asm/unistd_64.h`
/// in the upstream kernel headers, available as `unistd_64.h(3)` in any glibc
/// development package.  Where a syscall straddles two categories (e.g.
/// 257 openat is file + path-walk) the dominant operation wins — for openat,
/// the path-walk inode lookup dominates so it stays in `File`.
#[inline]
pub fn syscall_category(nr: u64) -> SyscallCategory {
    use SyscallCategory::*;
    match nr {
        // Vm: mmap-family, mprotect, munmap, brk, madvise
        9 | 10 | 11 | 12 | 25 | 26 | 28 => Vm,

        // File: read/write/open/close/stat-family, readv/writev, fcntl,
        // pread64/pwrite64, dup, lseek, access, pipe, getdents,
        // openat/mkdirat/unlinkat/readlinkat/statx/getdents64
        0 | 1 | 2 | 3 | 4 | 5 | 6 | 8 | 16 | 17 | 18 | 19 | 20 | 21 |
        22 | 32 | 33 | 72 | 79 | 81 | 83 | 84 | 85 | 86 | 87 | 88 | 89 |
        217 | 257 | 258 | 263 | 267 | 269 | 285 | 291 | 332 => File,

        // Net: socket-family
        41 | 42 | 43 | 44 | 45 | 46 | 47 | 48 | 49 | 50 | 51 | 52 |
        53 | 54 | 55 | 288 => Net,

        // Sync: poll/select/epoll/futex (blocking waits)
        7 | 23 | 202 | 213 | 232 | 233 | 270 | 271 | 281 | 449 => Sync,

        // Proc: clone/fork/execve/wait/exit, tgkill, kill, getpid family,
        // exit_group, execveat, clone3
        56 | 57 | 58 | 59 | 60 | 61 | 62 | 39 | 110 | 111 | 186 | 200 |
        231 | 322 | 435 => Proc,

        // Signal: rt_sigaction/rt_sigprocmask/rt_sigreturn/sigaltstack/sigsuspend
        13 | 14 | 15 | 130 | 131 | 132 | 134 => Signal,

        _ => Other,
    }
}

// ── Hot-path bump helpers ────────────────────────────────────────────────

/// Mark `pid` as currently executing syscall `nr` at tick `tick`, and bump
/// the appropriate category counter.  Single bounds-check, single atomic
/// load, three relaxed stores in the live-slot path.  Called from the
/// Linux syscall dispatcher's entry hook.
#[inline]
pub fn enter_syscall(pid: Pid, nr: u64, tick: u64) {
    let Some(m) = lookup(pid) else { return };
    m.last_sc_nr.store(nr as i32, Ordering::Relaxed);
    m.last_sc_tick.store(tick, Ordering::Relaxed);
    let counter = match syscall_category(nr) {
        SyscallCategory::Vm     => &m.sc_vm,
        SyscallCategory::File   => &m.sc_file,
        SyscallCategory::Net    => &m.sc_net,
        SyscallCategory::Sync   => &m.sc_sync,
        SyscallCategory::Proc   => &m.sc_proc,
        SyscallCategory::Signal => &m.sc_signal,
        SyscallCategory::Other  => &m.sc_other,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Mark the syscall as complete for `pid`.  Clears `last_sc_nr` to `-1`
/// so the periodic dump's stuck-syscall detector does not flag a thread
/// that legitimately returned to user-mode.
#[inline]
pub fn leave_syscall(pid: Pid) {
    if let Some(m) = lookup(pid) {
        m.last_sc_nr.store(-1, Ordering::Relaxed);
    }
}

/// Bump page-fault counter.  Called from the #PF handler.
#[inline]
pub fn bump_page_fault(pid: Pid) {
    if let Some(m) = lookup(pid) {
        m.pf_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bump disk-read byte counter and the per-request counter (one call per
/// logical block-device read request, i.e. one `do_io`).
#[inline]
pub fn bump_disk_read(pid: Pid, bytes: u64) {
    if let Some(m) = lookup(pid) {
        m.disk_r_bytes.fetch_add(bytes, Ordering::Relaxed);
        m.disk_r_reqs.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bump disk-write byte counter.
#[inline]
pub fn bump_disk_write(pid: Pid, bytes: u64) {
    if let Some(m) = lookup(pid) {
        m.disk_w_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// Bump network-receive byte counter.
#[inline]
pub fn bump_net_read(pid: Pid, bytes: u64) {
    if let Some(m) = lookup(pid) {
        m.net_r_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// Bump network-send byte counter.
#[inline]
pub fn bump_net_write(pid: Pid, bytes: u64) {
    if let Some(m) = lookup(pid) {
        m.net_w_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

// ── Snapshot for kdb + periodic dump ─────────────────────────────────────

/// Public read-only snapshot of one PID's metrics.  Returned by [`snapshot`]
/// for the kdb `proc-metrics` op.  All values are loaded under `Relaxed`
/// ordering — a torn read between fields is possible but cosmetically
/// uninteresting at the rates these counters move.
#[derive(Clone, Copy, Debug)]
pub struct MetricsSnap {
    pub pid: Pid,
    pub sc_total: u64,
    pub sc_vm:    u64,
    pub sc_file:  u64,
    pub sc_net:   u64,
    pub sc_sync:  u64,
    pub sc_proc:  u64,
    pub sc_signal: u64,
    pub sc_other: u64,
    pub pf_count: u64,
    pub disk_r_bytes: u64,
    pub disk_w_bytes: u64,
    pub disk_r_reqs:  u64,
    pub net_r_bytes:  u64,
    pub net_w_bytes:  u64,
    pub last_sc_nr:   i32,
    pub last_sc_tick: u64,
}

/// Take a non-blocking snapshot of one PID's counters.  Returns `None` if
/// the slot is out of range or unregistered.
pub fn snapshot(pid: Pid) -> Option<MetricsSnap> {
    let m = lookup(pid)?;
    Some(MetricsSnap {
        pid,
        sc_total: m.sc_total(),
        sc_vm:    m.sc_vm.load(Ordering::Relaxed),
        sc_file:  m.sc_file.load(Ordering::Relaxed),
        sc_net:   m.sc_net.load(Ordering::Relaxed),
        sc_sync:  m.sc_sync.load(Ordering::Relaxed),
        sc_proc:  m.sc_proc.load(Ordering::Relaxed),
        sc_signal: m.sc_signal.load(Ordering::Relaxed),
        sc_other: m.sc_other.load(Ordering::Relaxed),
        pf_count: m.pf_count.load(Ordering::Relaxed),
        disk_r_bytes: m.disk_r_bytes.load(Ordering::Relaxed),
        disk_w_bytes: m.disk_w_bytes.load(Ordering::Relaxed),
        disk_r_reqs:  m.disk_r_reqs.load(Ordering::Relaxed),
        net_r_bytes:  m.net_r_bytes.load(Ordering::Relaxed),
        net_w_bytes:  m.net_w_bytes.load(Ordering::Relaxed),
        last_sc_nr:   m.last_sc_nr.load(Ordering::Relaxed),
        last_sc_tick: m.last_sc_tick.load(Ordering::Relaxed),
    })
}

/// Enumerate all currently-registered PIDs.  The caller filters by
/// liveness via [`snapshot`].
pub fn live_pids() -> alloc::vec::Vec<Pid> {
    let mut v = alloc::vec::Vec::new();
    for idx in 0..METRICS_TABLE_SIZE {
        if REGISTERED[idx].load(Ordering::Acquire) {
            v.push(idx as Pid);
        }
    }
    v
}

// ── Periodic emission ────────────────────────────────────────────────────

/// Emission cadence in ticks.  At `TICK_HZ = 100` this is ~5 s wall clock —
/// rare enough to keep serial overhead negligible, fast enough to let an
/// operator catch a 30 s plateau before the trial times out.
pub const EMIT_INTERVAL_TICKS: u64 = 500;

/// Threshold for the "stuck in syscall" tag.  At `TICK_HZ = 100` this
/// corresponds to ~3 s — well past any legitimate latency for non-blocking
/// syscalls, and shorter than any reasonable poll/futex timeout in
/// Mozilla / NSS code.
const STUCK_TICKS: u64 = 300;

/// Last tick at which [`emit_periodic`] published a snapshot block.  Used
/// to gate the timer-ISR call so emission happens at most once per
/// `EMIT_INTERVAL_TICKS` regardless of how many CPUs deliver the tick.
static LAST_EMIT_TICK: AtomicU64 = AtomicU64::new(0);

/// If `tick` is past the next emission boundary, publish one
/// `[PROC-METRICS]` block.  Safe to call from any context (timer ISR or
/// scheduler tail).  Wait-free in the common case (one atomic load); takes
/// no locks on the fast path.  When the boundary is crossed it CAS-claims
/// the publish slot so only one CPU emits per interval.
pub fn maybe_emit_periodic(tick: u64) {
    let last = LAST_EMIT_TICK.load(Ordering::Relaxed);
    if tick.saturating_sub(last) < EMIT_INTERVAL_TICKS { return; }
    // Try to claim this interval.  If another CPU beat us, bail.
    if LAST_EMIT_TICK.compare_exchange(
        last, tick, Ordering::AcqRel, Ordering::Relaxed
    ).is_err() {
        return;
    }
    emit_periodic(tick);
}

/// Emit one `[PROC-METRICS]` block to the serial console.  Skipped if
/// `PROCESS_TABLE` is contended — the next interval will retry.
fn emit_periodic(tick: u64) {
    use alloc::format;
    // Resolve process names without blocking; if PROCESS_TABLE is held by
    // a long syscall (mmap/fork), the next 5 s window will re-attempt and
    // we lose only one sample.  Cosmetic.
    let names: alloc::vec::Vec<(Pid, alloc::string::String)> =
        match crate::proc::PROCESS_TABLE.try_lock() {
            Some(g) => g.iter().map(|p| {
                let end = p.name.iter().position(|&b| b == 0)
                    .unwrap_or(p.name.len());
                let name = alloc::string::String::from_utf8_lossy(
                    &p.name[..end]).into_owned();
                (p.pid, name)
            }).collect(),
            None => alloc::vec::Vec::new(),
        };

    for pid in live_pids() {
        let Some(s) = snapshot(pid) else { continue };
        // Skip PID 0 (idle) and pids that have no recorded activity at all —
        // they pollute the dump with empty lines.
        if pid == 0 { continue; }
        if s.sc_total == 0 && s.pf_count == 0 && s.disk_r_bytes == 0
            && s.disk_w_bytes == 0 && s.net_r_bytes == 0 && s.net_w_bytes == 0
        { continue; }

        let name = names.iter().find(|(p, _)| *p == pid)
            .map(|(_, n)| n.as_str()).unwrap_or("?");

        // Stuck-syscall tag.  Only meaningful when last_sc_nr is non-negative
        // (i.e. the process is currently inside the kernel).
        let stuck = if s.last_sc_nr >= 0 {
            let delta = tick.saturating_sub(s.last_sc_tick);
            if delta >= STUCK_TICKS {
                format!(" STUCK_IN_NR={}@{}t", s.last_sc_nr, delta)
            } else {
                format!(" cur_nr={}@{}t", s.last_sc_nr, delta)
            }
        } else {
            alloc::string::String::new()
        };

        crate::serial_println!(
            "[PROC-METRICS] tick={} pid={} name={} sc={} (vm={} file={} net={} sync={} proc={} sig={} other={}) pf={} disk=R{}/W{} rreq={} net=R{}/W{}{}",
            tick, pid, name, s.sc_total,
            s.sc_vm, s.sc_file, s.sc_net, s.sc_sync, s.sc_proc,
            s.sc_signal, s.sc_other,
            s.pf_count,
            s.disk_r_bytes, s.disk_w_bytes,
            s.disk_r_reqs,
            s.net_r_bytes, s.net_w_bytes,
            stuck
        );
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(feature = "test-mode")]
pub fn run_self_test() -> bool {
    // Pick a PID well above the boot bringup range and below table size.
    let pid: Pid = 200;
    register(pid);

    // Category bucketing
    enter_syscall(pid, 0, 1);   // read -> File
    enter_syscall(pid, 9, 1);   // mmap -> Vm
    enter_syscall(pid, 41, 1);  // socket -> Net
    enter_syscall(pid, 202, 1); // futex -> Sync
    enter_syscall(pid, 56, 1);  // clone -> Proc
    enter_syscall(pid, 13, 1);  // rt_sigaction -> Signal
    enter_syscall(pid, 99999, 1); // unknown -> Other

    bump_page_fault(pid);
    bump_disk_read(pid, 4096);
    bump_disk_write(pid, 8192);
    bump_net_read(pid, 100);
    bump_net_write(pid, 200);

    let s = snapshot(pid).expect("snapshot present");
    let ok = s.sc_file == 1 && s.sc_vm == 1 && s.sc_net == 1
        && s.sc_sync == 1 && s.sc_proc == 1 && s.sc_signal == 1
        && s.sc_other == 1 && s.sc_total == 7
        && s.pf_count == 1
        && s.disk_r_bytes == 4096 && s.disk_w_bytes == 8192
        && s.net_r_bytes == 100 && s.net_w_bytes == 200;

    // leave_syscall clears the sentinel
    leave_syscall(pid);
    let s2 = snapshot(pid).expect("snapshot present");
    let ok2 = s2.last_sc_nr == -1;

    // unregister hides the slot
    unregister(pid);
    let ok3 = snapshot(pid).is_none();

    // Out-of-range PID is a silent no-op
    bump_page_fault(METRICS_TABLE_SIZE as Pid + 100);
    let ok4 = snapshot(METRICS_TABLE_SIZE as Pid + 100).is_none();

    ok && ok2 && ok3 && ok4
}
