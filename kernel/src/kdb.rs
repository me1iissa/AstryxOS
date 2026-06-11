//! Tier 1 kdb — read-only kernel JSON introspection server on TCP/9999.
//! One JSON request per connection, one response, close.  Driven by
//! `scripts/qemu-harness.py kdb`.  Gated behind `#[cfg(feature = "kdb")]`.

#![cfg(feature = "kdb")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::net::tcp::{self, TcpState};

// ── Wire constants ────────────────────────────────────────────────────────────

/// TCP port the kdb server listens on.  Matches the hostfwd rule
/// synthesised by `qemu-harness.py start --features kdb`.
pub const KDB_PORT: u16 = 9999;

/// Maximum request line size.  Safeguards against a misbehaving client.
const MAX_REQ_BYTES:  usize = 16 * 1024;
/// Maximum response size written back in one segment.
const MAX_RESP_BYTES: usize = 32 * 1024;

// ── Dmesg ring buffer ────────────────────────────────────────────────────────
//
// 64 KiB byte ring.  Intended to mirror COM1 output; currently populated
// only by explicit `dmesg_write_str()` callers.  Wiring a mirror hook
// into `drivers::serial::_serial_print` is a follow-up.

const DMESG_CAP: usize = 64 * 1024;

struct DmesgRing { buf: [u8; DMESG_CAP], head: usize, filled: bool }

impl DmesgRing {
    const fn new() -> Self { Self { buf: [0u8; DMESG_CAP], head: 0, filled: false } }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.buf[self.head] = b;
            self.head += 1;
            if self.head == DMESG_CAP { self.head = 0; self.filled = true; }
        }
    }
    fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(if self.filled { DMESG_CAP } else { self.head });
        if self.filled {
            out.extend_from_slice(&self.buf[self.head..]);
            out.extend_from_slice(&self.buf[..self.head]);
        } else {
            out.extend_from_slice(&self.buf[..self.head]);
        }
        out
    }
}

pub(crate) static DMESG: Mutex<DmesgRing> = Mutex::new(DmesgRing::new());

/// Feed bytes into the in-kernel log ring.  Tiny / no alloc.
/// Currently only callable from within this crate; kept public so a
/// future serial-mirror hook can forward into it without refactoring.
#[allow(dead_code)]
pub fn dmesg_write_str(s: &str) {
    if let Some(mut r) = DMESG.try_lock() { r.write(s.as_bytes()); }
}

// ── Listener state machine ───────────────────────────────────────────────────

#[derive(Clone)]
struct PendingSession {
    remote_ip:   [u8; 4],
    remote_port: u16,
    local_port:  u16,
    buf:         Vec<u8>,
    responded:   bool,
}

static KDB_SESSIONS: Mutex<Vec<PendingSession>> = Mutex::new(Vec::new());
static INITED: AtomicBool = AtomicBool::new(false);
static PUMP_THREAD_STARTED: AtomicBool = AtomicBool::new(false);

/// Initialise the kdb listener.  Safe to call multiple times.
///
/// Also spawns a dedicated PRIORITY_HIGH kernel thread (`kdb_pump`) that
/// services the TCP/9999 socket independently of the BSP main loop.  The
/// BSP runs as the idle thread and is starved under heavy userland load
/// (e.g. ~40 libxul threads at PRIORITY_NORMAL); without this pump thread
/// the in-kernel debugger appears wedged to the host even though the
/// kernel itself is healthy and continues to make forward progress.
pub fn init() {
    if INITED.swap(true, Ordering::SeqCst) { return; }
    match tcp::listen(KDB_PORT) {
        Ok(()) => {
            crate::serial_println!("[KDB] listening on 0.0.0.0:{}", KDB_PORT);
            start_pump_thread();
        }
        Err(e) => {
            crate::serial_println!("[KDB] listen({}) failed: {}", KDB_PORT, e);
            INITED.store(false, Ordering::SeqCst);
        }
    }
}

/// Dedicated kdb-pump kernel thread entry point.
///
/// Runs at PRIORITY_HIGH so it stays scheduled even when ~40 userland threads
/// (e.g. libxul + content processes) are saturating CPU at PRIORITY_NORMAL.
/// The BSP main loop also calls `net::poll()`, but the BSP runs as the idle
/// thread (PRIORITY_IDLE = 0) and is starved by any Ready peer — so under
/// heavy load it can go minutes without polling, and the in-kernel TCP/9999
/// debugger appears wedged to the host even though the kernel is healthy.
///
/// Sleeping 1 timer tick (~10 ms) between iterations keeps overhead bounded
/// to one schedule + one `net::poll` per ~10 ms.  `net::poll()` itself is
/// already designed for periodic 10 ms cadence (see its docstring), so this
/// thread effectively replaces the BSP's polling on the kdb hot path while
/// letting the BSP keep doing X11/compositor work between its (rarer) slices.
fn pump_thread_entry() {
    crate::serial_println!("[KDB] pump thread started (TID {})",
                           crate::proc::current_tid());
    loop {
        // Service NIC RX + TCP timers + kdb pump.  Locks are taken inside
        // each callee; concurrent calls from the BSP main loop are
        // serialised by those locks (TCP_CONNECTIONS, KDB_SESSIONS).
        crate::net::poll();
        // Yield for 1 tick.  At the firefox-test BSP cadence of ~100 Hz
        // this gives ~100 kdb-pump opportunities per second, well above
        // the ~5 cycles a single kdb exchange (handshake + req + resp +
        // close) needs to complete.
        crate::proc::sleep_ticks(1);
    }
}

/// Spawn the dedicated kdb-pump kernel thread.  Idempotent: returns
/// immediately if already started.  Must be called AFTER `init()` (so the
/// TCP listener exists) and AFTER `proc::init()` (so `create_thread` can
/// allocate a kernel stack).
///
/// Spawned in PID 0 (idle process) — the thread shares the kernel CR3 so
/// it can call `net::poll()` safely regardless of which user CR3 the BSP
/// happens to be on when the thread is scheduled in.
pub fn start_pump_thread() {
    if !INITED.load(Ordering::Acquire) { return; }
    if PUMP_THREAD_STARTED.swap(true, Ordering::SeqCst) { return; }
    match crate::proc::create_thread(
        0,                                          // PID 0 (idle/kernel)
        "kdb_pump",
        pump_thread_entry as *const () as u64,
    ) {
        Some(tid) => {
            // Bump to PRIORITY_HIGH so we beat userland (PRIORITY_NORMAL).
            // Without this bump the new thread also runs at PRIORITY_NORMAL
            // and gets starved 1:N alongside libxul's many threads.
            let _ = crate::proc::set_thread_priority(
                tid, crate::proc::PRIORITY_HIGH);
            crate::serial_println!("[KDB] pump thread spawned as TID {} (PRIORITY_HIGH)", tid);
        }
        None => {
            PUMP_THREAD_STARTED.store(false, Ordering::SeqCst);
            crate::serial_println!("[KDB] WARNING: failed to spawn pump thread; kdb will rely on BSP polling");
        }
    }
}

/// Drive the kdb state machine.  Called from `net::poll()`.
pub fn pump() {
    if !INITED.load(Ordering::Relaxed) { return; }

    // Find Established child connections on KDB_PORT.
    let new_peers: Vec<([u8; 4], u16)> = tcp::snapshot_connections().iter()
        .filter(|c| c.local_port == KDB_PORT
                 && c.state == TcpState::Established
                 && c.remote_port != 0)
        .map(|c| (c.remote_ip, c.remote_port))
        .collect();

    // Make sure each has a session entry.
    {
        let mut ss = KDB_SESSIONS.lock();
        for (rip, rp) in &new_peers {
            if !ss.iter().any(|s| s.remote_ip == *rip && s.remote_port == *rp) {
                ss.push(PendingSession {
                    remote_ip: *rip, remote_port: *rp, local_port: KDB_PORT,
                    buf: Vec::new(), responded: false,
                });
            }
        }
    }

    // Drain each connected child TCB by full 4-tuple so two concurrent
    // clients can't have their request bytes mis-attributed to each other.
    // `tcp::read(port)` returns bytes from whichever Established TCB on
    // KDB_PORT matches first — that's a real cross-session leak when more
    // than one harness shell is talking to kdb at the same time.  See
    // tcp::read_from for the per-connection variant.
    for (rip, rp) in &new_peers {
        let bytes = tcp::read_from(KDB_PORT, *rip, *rp);
        if bytes.is_empty() { continue; }
        let mut ss = KDB_SESSIONS.lock();
        if let Some(s) = ss.iter_mut()
            .find(|s| !s.responded && s.remote_ip == *rip && s.remote_port == *rp)
        {
            if s.buf.len() + bytes.len() <= MAX_REQ_BYTES {
                s.buf.extend_from_slice(&bytes);
            } else {
                s.buf.clear();
                s.buf.extend_from_slice(b"__oversize__\n");
            }
        }
    }

    // Dispatch any session with a full line.  Identify the responded
    // connection by its full 4-tuple — closing by `local_port` alone would
    // FIN whichever TCB on KDB_PORT matches first (typically the listener
    // itself), permanently disabling kdb after the very first response.
    {
        let mut ss = KDB_SESSIONS.lock();
        for s in ss.iter_mut() {
            if s.responded { continue; }
            if let Some(nl) = s.buf.iter().position(|&b| b == b'\n') {
                let line = s.buf[..nl].to_vec();
                let resp = handle_request(&line);
                let _ = tcp::send_data_to(
                    s.local_port, s.remote_ip, s.remote_port, resp.as_bytes(),
                );
                s.responded = true;
            }
        }
    }

    // Close only sessions whose response has fully drained out of the
    // TCP send_buffer and retransmit queue.  `send_data_to` may have
    // buffered the tail of a large response when cwnd was small (one
    // MSS at start-of-connection); calling `close_connection` while
    // anything is still pending would advance send_next past that
    // unsent data and the peer would never see it.  We defer the FIN
    // to a later pump tick once `tcp::tcp_timer_tick` has drained the
    // buffer naturally.
    let mut to_close: Vec<([u8; 4], u16, u16)> = Vec::new();
    {
        let ss = KDB_SESSIONS.lock();
        for s in ss.iter() {
            if !s.responded { continue; }
            let pending = tcp::outbound_pending(s.local_port, s.remote_ip, s.remote_port);
            if pending == 0 {
                to_close.push((s.remote_ip, s.remote_port, s.local_port));
            }
        }
    }
    for (rip, rp, lp) in to_close {
        let _ = tcp::close_connection(lp, rip, rp);
    }

    // Reap sessions whose TCP side has fully closed.
    {
        let alive: Vec<([u8; 4], u16)> = tcp::snapshot_connections().iter()
            .filter(|c| c.local_port == KDB_PORT
                     && c.remote_port != 0
                     && c.state != TcpState::Closed
                     && c.state != TcpState::TimeWait)
            .map(|c| (c.remote_ip, c.remote_port))
            .collect();
        let mut ss = KDB_SESSIONS.lock();
        ss.retain(|s| alive.iter().any(|(ip, p)|
                  *ip == s.remote_ip && *p == s.remote_port));
    }
}

/// Process one request line and return the JSON response with trailing '\n'.
fn handle_request(line: &[u8]) -> String {
    let mut out = String::with_capacity(256);
    match core::str::from_utf8(line) {
        Ok(s) => dispatch(s, &mut out),
        Err(_) => { out.push_str(r#"{"error":"request not valid UTF-8"}"#); }
    }
    out.push('\n');
    if out.len() > MAX_RESP_BYTES {
        out.truncate(MAX_RESP_BYTES);
        out.push('\n');
    }
    out
}

// ── Small JSON helpers used by ops::* ─────────────────────────────────────────

/// Append a JSON-escaped string (including surrounding quotes) to `out`.
pub(crate) fn j_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append `"key":value,` (value is written verbatim).
pub(crate) fn j_kv(out: &mut String, key: &str, value: &str) {
    j_str(out, key); out.push(':'); out.push_str(value); out.push(',');
}

/// Append `"key":"str",`.
pub(crate) fn j_kv_str(out: &mut String, key: &str, value: &str) {
    j_str(out, key); out.push(':'); j_str(out, value); out.push(',');
}

/// Drop the trailing ',' left by the `j_kv*` helpers.
pub(crate) fn j_trim_comma(out: &mut String) {
    if out.ends_with(',') { out.pop(); }
}

/// Format a u64 as 0x-prefixed hex string literal into `out`.
pub(crate) fn j_hex(out: &mut String, v: u64) {
    use core::fmt::Write;
    let _ = write!(out, "\"{:#x}\"", v);
}

// ═══════════════════════════════════════════════════════════════════════
// Operation dispatch — one handler per op.
// ═══════════════════════════════════════════════════════════════════════

use crate::proc::{PROCESS_TABLE, THREAD_TABLE};

pub fn dispatch(req: &str, out: &mut String) {
    let op = match extract_field(req, "op") {
        Some(v) => v,
        None => { out.push_str(r#"{"error":"missing 'op' field"}"#); return; }
    };
    match op.as_str() {
        "ping"           => op_ping(out),
        "proc-list"      => op_proc_list(out),
        "proc"           => op_proc(req, out),
        "proc-tree"      => op_proc_tree(req, out),
        "fd-table"       => op_fd_table(req, out),
        "fd-map"         => op_fd_map(req, out),
        "unix-diag"      => op_unix_diag(req, out),
        "pipe-diag"      => op_pipe_diag(req, out),
        "epoll-watch"    => op_epoll_watch(req, out),
        "syscall-trend"  => op_syscall_trend(req, out),
        "vfs-mounts"     => op_vfs_mounts(out),
        "dmesg"          => op_dmesg(req, out),
        "syms"           => op_syms(req, out),
        "mem"            => op_mem(req, out),
        "read-file"      => op_read_file(req, out),
        "trace-status"   => op_trace_status(out),
        // blk-trace: dump the virtio-blk LBA trace ring as JSON (out-of-band
        // drain replacing the old per-op COM1 write). `blk-trace-flush` re-emits
        // the classic `[BLK]` serial lines for the legacy heatmap ingestion.
        "blk-trace"      => op_blk_trace(out),
        "blk-trace-flush" => op_blk_trace_flush(out),
        "log-ring"        => op_log_ring(out),
        "log-ring-flush"  => op_log_ring_flush(out),
        "log-ring-enable" => op_log_ring_enable(req, out),
        // virtio-blk wait-amplification telemetry + runtime A/B controls.
        "virtio-wait-hist"  => op_virtio_wait_hist(out),
        "virtio-wait-mode"  => op_virtio_wait_mode(req, out),
        "virtio-wait-spin"  => op_virtio_wait_spin(req, out),
        "virtio-wait-reset" => op_virtio_wait_reset(out),
        "bell-stats"       => op_bell_stats(out),
        "cache-audit"      => op_cache_audit(out),
        "cache-aliasing"   => op_cache_aliasing(out),
        "fault-cache-keys" => op_fault_cache_keys(out),
        "w215-cache-residency" => op_w215_cache_residency(out),
        "tlb-stats"        => op_tlb_stats(out),
        "heap-stats"       => op_heap_stats(out),
        "w215-diag"        => op_w215_diag(out),
        "w215-cow-witness" => op_w215_cow_witness(req, out),
        "arm-phys"         => op_arm_phys(req, out),
        "coverage-flush" => op_coverage_flush(out),
        "proc-metrics"   => op_proc_metrics(out),
        "poll-revents"   => op_poll_revents(req, out),
        "thread-park-audit" => op_thread_park_audit(req, out),
        "rip-trace"      => op_rip_trace(req, out),
        "procmaps"       => op_procmaps(req, out),
        #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
        "futex-stats"           => op_futex_stats(out),
        #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
        "futex-set-cluster-wake" => op_futex_set_cluster_wake(req, out),
        "futex-ghost-hist" => op_futex_ghost_hist(req, out),
        // cond-autopsy: one-shot musl pthread_cond/mutex wake-target-vs-
        // wait-addr report.  Composes the live struct dump + parked waiters +
        // recent wake targets + inferred lock holder into a single verdict.
        "cond-autopsy"   => op_cond_autopsy(req, out),
        // Deliver a signal to a guest process (default SIGKILL) — the
        // induced-verdict primitive: terminate a parked process and observe
        // what its supervisor/peer reports.
        "proc-kill"      => op_proc_kill(req, out),
        // INFRA-3 record/replay introspection.  Off-path when the
        // `record-replay` feature is OFF — the ops return a fixed
        // "feature off" JSON object so the KDB protocol surface is
        // stable across builds.
        "record-status" => op_record_status(out),
        "replay-dump"   => op_replay_dump(req, out),
        // net-ipver: read or toggle the runtime IPv4/IPv6 address-family
        // enable flags (net::ipver).  One-shot, structured JSON output.
        "net-ipver"     => op_net_ipver(req, out),
        // net-rxstats: receive-path health — per-connection recv_next/seq
        // cursors + e1000 RX-ring MPC/byte counts.  Used to confirm TCP/NIC
        // packet loss (a stalled recv_next or a non-zero MPC).
        "net-rxstats"   => op_net_rxstats(req, out),
        _ => {
            out.push_str(r#"{"error":"unknown op: "#);
            for c in op.chars().take(64) {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' { out.push(c); }
            }
            out.push_str(r#""}"#);
        }
    }
}

// ── Minimal scalar-field extraction ───────────────────────────────────────────

fn extract_field(req: &str, key: &str) -> Option<String> {
    let needle = {
        let mut s = String::with_capacity(key.len() + 4);
        s.push('"'); s.push_str(key); s.push('"'); s
    };
    let idx = req.find(needle.as_str())?;
    let rest = req[idx + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    parse_scalar(rest)
}

fn parse_scalar(s: &str) -> Option<String> {
    if let Some(inner) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Some(out),
                '\\' => if let Some(esc) = chars.next() {
                    out.push(match esc { 'n'=>'\n','r'=>'\r','t'=>'\t','"'=>'"','\\'=>'\\',c=>c });
                },
                c => out.push(c),
            }
        }
        None
    } else {
        let end = s.find(|c: char| c == ',' || c == '}' || c.is_whitespace())
                   .unwrap_or(s.len());
        if end == 0 { None } else { Some(s[..end].into()) }
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else { s.parse::<u64>().ok() }
}

// ── ping ──────────────────────────────────────────────────────────────────────

fn op_ping(out: &mut String) {
    use core::fmt::Write;
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let _ = write!(out, r#"{{"pong":true,"uptime_ticks":{}}}"#, ticks);
}

// ── proc-list ─────────────────────────────────────────────────────────────────

fn proc_name_string(bytes: &[u8; 64]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn proc_state_str(s: crate::proc::ProcessState) -> &'static str {
    match s {
        crate::proc::ProcessState::Active  => "active",
        crate::proc::ProcessState::Waiting => "waiting",
        crate::proc::ProcessState::Zombie  => "zombie",
    }
}

fn thread_state_str(s: crate::proc::ThreadState) -> &'static str {
    match s {
        crate::proc::ThreadState::Ready    => "ready",
        crate::proc::ThreadState::Running  => "running",
        crate::proc::ThreadState::Blocked  => "blocked",
        crate::proc::ThreadState::Sleeping => "sleeping",
        crate::proc::ThreadState::Dead     => "dead",
    }
}

/// Brief bounded try_lock — returns None if the lock is held by another CPU
/// for the entire spin window.  Used by kdb so introspection commands don't
/// block forever when a syscall holds PROCESS_TABLE during a long mmap /
/// munmap edit.  Each iteration spins ~the cost of a `pause`; total wall
/// budget is well under a millisecond, far shorter than the 5 s the host
/// kdb client allows before its own timeout.
fn try_lock_brief<'a, T>(m: &'a Mutex<T>) -> Option<spin::MutexGuard<'a, T>> {
    for _ in 0..2048 {
        if let Some(g) = m.try_lock() {
            return Some(g);
        }
        core::hint::spin_loop();
    }
    None
}

fn op_proc_list(out: &mut String) {
    struct Row {
        pid: u64, parent: u64, state: &'static str,
        name: String, thread0: Option<u64>, num_threads: usize,
    }
    let rows: Vec<Row> = match try_lock_brief(&PROCESS_TABLE) {
        Some(guard) => guard.iter().map(|p| Row {
            pid: p.pid, parent: p.parent_pid,
            state: proc_state_str(p.state),
            name: proc_name_string(&p.name),
            thread0: p.threads.first().copied(),
            num_threads: p.threads.len(),
        }).collect(),
        None => {
            // PROCESS_TABLE held — emit a `busy` envelope rather than block
            // the kdb listener thread (which serves every other op too).
            out.push_str(r#"{"busy":"PROCESS_TABLE held","procs":[]}"#);
            return;
        }
    };

    // tmap: per-PID (thread0_tid, entry_rip) so we can also resolve the
    // *current* sampled user RIP for thread0 below.  The "rip" key in the
    // response now reports the live user RIP from proc::sample (data source
    // for diagnosing userspace plateaux — see PSE memory on post-#287/#288/
    // #289 JIT plateau, which misread the frozen entry_rip as "current"),
    // while "entry_rip" preserves the historical value for callers that
    // want the immutable trampoline entry.
    let mut tmap: alloc::collections::BTreeMap<u64, (u64, u64)> =
        alloc::collections::BTreeMap::new();
    let thread_table_busy = match try_lock_brief(&THREAD_TABLE) {
        Some(tt) => {
            for r in &rows {
                if let Some(tid) = r.thread0 {
                    if let Some(t) = tt.iter().find(|t| t.tid == tid) {
                        tmap.insert(r.pid, (tid, t.user_entry_rip));
                    }
                }
            }
            false
        }
        None => true, // best-effort: omit per-thread RIPs from the response.
    };

    let sc_total = crate::syscall::syscall_count();
    // Emit `syscall_count_total` once at the response root rather than on
    // every row — it is a global counter, not per-process, and repeating it
    // on each row was actively misleading.  Per-process syscall counters
    // would need separate plumbing through dispatch and are out of scope.
    if thread_table_busy {
        out.push_str(r#"{"busy":"THREAD_TABLE held",""#);
    } else {
        out.push_str(r#"{""#);
    }
    out.push_str("syscall_count_total\":");
    use core::fmt::Write;
    let _ = write!(out, "{}", sc_total);
    out.push_str(",\"procs\":[");

    for (i, r) in rows.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_kv(out, "pid", &alloc::format!("{}", r.pid));
        j_kv(out, "ppid", &alloc::format!("{}", r.parent));
        j_kv_str(out, "state", r.state);
        j_kv_str(out, "name", &r.name);
        j_kv(out, "threads", &alloc::format!("{}", r.num_threads));
        let (thread0_tid, entry_rip) = tmap.get(&r.pid).copied().unwrap_or((0, 0));
        // `rip` reports the live user RIP from the per-tick sampler when
        // available, falling back to entry_rip so the key is never absent
        // for callers that already parse it.  `entry_rip` and `tid0` are
        // additive companions so old behaviour can be reconstructed.
        let live_rip = crate::proc::sample::read_user_rip(thread0_tid)
            .map(|(rip, _, _)| rip)
            .filter(|r| *r != 0)
            .unwrap_or(entry_rip);
        j_str(out, "rip"); out.push(':'); j_hex(out, live_rip); out.push(',');
        j_str(out, "entry_rip"); out.push(':'); j_hex(out, entry_rip); out.push(',');
        j_kv(out, "tid0", &alloc::format!("{}", thread0_tid));
        j_kv(out, "pf_count", "0");
        j_trim_comma(out);
        out.push('}');
    }
    out.push_str("]}");
}

// ── proc ──────────────────────────────────────────────────────────────────────

fn op_proc(req: &str, out: &mut String) {
    let pid = match extract_field(req, "pid").and_then(|s| parse_u64(&s)) {
        Some(p) => p,
        None => { out.push_str(r#"{"error":"missing or bad 'pid'"}"#); return; }
    };

    // Stage 1: copy scalar process fields.
    struct Snap {
        pid: u64, parent: u64, state: &'static str,
        name: String, threads: Vec<u64>, cwd: String, uid: u32, gid: u32,
        vmas: Vec<(u64, u64, u32, &'static str)>,
        fds: Vec<(usize, String)>, exe: Option<String>,
    }
    let pt = match try_lock_brief(&PROCESS_TABLE) {
        Some(g) => g,
        None => {
            out.push_str(r#"{"busy":"PROCESS_TABLE held"}"#);
            return;
        }
    };
    let snap: Option<Snap> = pt.iter().find(|p| p.pid == pid).map(|p| {
        let vmas = match &p.vm_space {
            Some(vs) => vs.areas.iter().map(|a| (a.base, a.end(), a.prot, a.name)).collect(),
            None => Vec::new(),
        };
        let fds = p.file_descriptors.iter().enumerate()
            .filter_map(|(i, fd)| fd.as_ref().map(|fd| {
                let label = if fd.is_console {
                    match i { 0 => "<stdin>", 1 => "<stdout>", 2 => "<stderr>", _ => "<console>" }.into()
                } else if !fd.open_path.is_empty() { fd.open_path.clone() }
                else { alloc::format!("inode={} mount={}", fd.inode, fd.mount_idx) };
                (i, label)
            })).collect();
        Snap {
            pid: p.pid, parent: p.parent_pid, state: proc_state_str(p.state),
            name: proc_name_string(&p.name), threads: p.threads.clone(),
            cwd: p.cwd.clone(), uid: p.uid, gid: p.gid,
            vmas, fds, exe: p.exe_path.clone(),
        }
    });
    drop(pt);
    let snap = match snap {
        Some(s) => s,
        None => {
            use core::fmt::Write;
            let _ = write!(out, r#"{{"error":"pid {} not found"}}"#, pid);
            return;
        }
    };

    // Stage 2: per-thread data under a different lock.  `entry_rip` is
    // the immutable trampoline entry RIP from thread creation; the live
    // `rip` field below is populated post-lock from proc::sample so a
    // long-running thread reports where it is actually parked in
    // userspace right now (cf. PSE memory on JIT-plateau misread).
    struct TR { tid: u64, state: &'static str, entry_rip: u64, rsp: u64 }
    let trs: Vec<TR> = match try_lock_brief(&THREAD_TABLE) {
        Some(tt) => snap.threads.iter()
            .filter_map(|tid| tt.iter().find(|t| t.tid == *tid).map(|t| TR {
                tid: t.tid, state: thread_state_str(t.state),
                entry_rip: t.user_entry_rip, rsp: t.context.rsp,
            })).collect(),
        None => Vec::new(), // Lock contended — emit threads array empty.
    };

    out.push('{');
    j_kv(out, "pid", &alloc::format!("{}", snap.pid));
    j_kv(out, "ppid", &alloc::format!("{}", snap.parent));
    j_kv_str(out, "state", snap.state);
    j_kv_str(out, "name", &snap.name);
    j_kv_str(out, "cwd", &snap.cwd);
    j_kv(out, "uid", &alloc::format!("{}", snap.uid));
    j_kv(out, "gid", &alloc::format!("{}", snap.gid));
    if let Some(e) = snap.exe.as_deref() { j_kv_str(out, "exe", e); }

    j_str(out, "threads"); out.push(':'); out.push('[');
    for (i, t) in trs.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_kv(out, "tid", &alloc::format!("{}", t.tid));
        j_kv_str(out, "state", t.state);
        // Live user RIP/RBP if the sampler has observed this TID in
        // Ring 3; falls back to entry_rip so `rip` is never null.
        let (live_rip, live_rbp) = crate::proc::sample::read_user_rip(t.tid)
            .map(|(r, b, _)| (if r != 0 { r } else { t.entry_rip }, b))
            .unwrap_or((t.entry_rip, 0));
        j_str(out, "rip"); out.push(':'); j_hex(out, live_rip); out.push(',');
        j_str(out, "entry_rip"); out.push(':'); j_hex(out, t.entry_rip); out.push(',');
        j_str(out, "rbp"); out.push(':'); j_hex(out, live_rbp); out.push(',');
        j_str(out, "rsp"); out.push(':'); j_hex(out, t.rsp);
        out.push('}');
    }
    out.push_str("],");

    j_str(out, "vmas"); out.push(':'); out.push('[');
    for (i, (base, end, prot, name)) in snap.vmas.iter().take(256).enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_str(out, "start"); out.push(':'); j_hex(out, *base); out.push(',');
        j_str(out, "end");   out.push(':'); j_hex(out, *end);  out.push(',');
        let mut fb = [b'-'; 3];
        if *prot & crate::mm::vma::PROT_READ  != 0 { fb[0] = b'r'; }
        if *prot & crate::mm::vma::PROT_WRITE != 0 { fb[1] = b'w'; }
        if *prot & crate::mm::vma::PROT_EXEC  != 0 { fb[2] = b'x'; }
        j_kv_str(out, "flags", core::str::from_utf8(&fb).unwrap_or("---"));
        j_kv_str(out, "name", name);
        j_trim_comma(out);
        out.push('}');
    }
    out.push_str("],");

    j_str(out, "open_fds"); out.push(':'); out.push('{');
    for (i, (fd, label)) in snap.fds.iter().take(64).enumerate() {
        if i > 0 { out.push(','); }
        j_str(out, &alloc::format!("{}", fd)); out.push(':'); j_str(out, label);
    }
    out.push('}');
    out.push('}');
}

// ── vfs-mounts ────────────────────────────────────────────────────────────────

fn op_vfs_mounts(out: &mut String) {
    // Mirror the try_lock_brief discipline used by op_proc_list / op_proc:
    // a blocking MOUNTS.lock() would freeze the kdb listener thread when a
    // concurrent mount/unmount is in flight, since pump() handles every op
    // (including unrelated ones) on the same poll tick.  Emit a `busy`
    // envelope on contention so the host harness can distinguish "no
    // mounts" (`mounts:[]` with no `busy` key) from "couldn't read".
    let mounts = match try_lock_brief(&crate::vfs::MOUNTS) {
        Some(g) => g,
        None => {
            out.push_str(r#"{"busy":"MOUNTS held","mounts":[]}"#);
            return;
        }
    };
    out.push_str(r#"{"mounts":["#);
    for (i, m) in mounts.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_kv_str(out, "mountpoint", &m.path);
        j_kv_str(out, "fstype", m.fs.name());
        j_kv(out, "root_inode", &alloc::format!("{}", m.root_inode));
        j_trim_comma(out);
        out.push('}');
    }
    out.push_str("]}");
}

// ── dmesg ─────────────────────────────────────────────────────────────────────

fn op_dmesg(req: &str, out: &mut String) {
    let tail = extract_field(req, "tail").and_then(|s| parse_u64(&s)).unwrap_or(100) as usize;
    let snap = DMESG.lock().snapshot();
    let text = core::str::from_utf8(&snap).unwrap_or("");
    let lines: Vec<&str> = text.split('\n').collect();
    let start = lines.len().saturating_sub(tail + 1);
    out.push_str(r#"{"lines":["#);
    let mut first = true;
    let mut budget = 32 * 1024;
    for line in &lines[start..] {
        if line.is_empty() { continue; }
        if !first { out.push(','); }
        first = false;
        let before = out.len();
        j_str(out, line);
        let grew = out.len() - before;
        if grew >= budget { out.truncate(before); j_trim_comma(out); break; }
        budget -= grew;
    }
    out.push_str("]}");
}

// ── syms ──────────────────────────────────────────────────────────────────────
//
// The kernel keeps no embedded symbol table; this op answers only for a
// hand-maintained list of well-known entry points.  Full ELF resolution
// stays host-side via `qemu-harness.py sym`.

struct KSym { name: &'static str, addr: u64 }

#[allow(clippy::fn_to_numeric_cast_any)]
fn known_symbols() -> Vec<KSym> {
    fn fp(f: fn()) -> u64 { f as *const () as usize as u64 }
    alloc::vec![
        KSym { name: "kdb_init",    addr: fp(crate::kdb::init) },
        KSym { name: "kdb_pump",    addr: fp(crate::kdb::pump) },
        KSym { name: "serial_init", addr: fp(crate::drivers::serial::init) },
        KSym { name: "net_poll",    addr: fp(crate::net::poll) },
    ]
}

fn op_syms(req: &str, out: &mut String) {
    let table = known_symbols();
    if let Some(name) = extract_field(req, "name") {
        for s in &table {
            if s.name == name {
                use core::fmt::Write;
                out.push('{');
                j_kv_str(out, "name", s.name);
                j_str(out, "addr"); out.push(':'); j_hex(out, s.addr);
                let _ = write!(out, r#","source":"in-kernel"}}"#);
                return;
            }
        }
        out.push_str(r#"{"error":"symbol not in kernel-resident table — use 'qemu-harness.py sym' for full ELF lookup"}"#);
        return;
    }
    if let Some(addr) = extract_field(req, "addr").and_then(|s| parse_u64(&s)) {
        let mut best: Option<&KSym> = None;
        for s in &table {
            if s.addr <= addr {
                best = match best { None => Some(s), Some(b) => if s.addr > b.addr { Some(s) } else { Some(b) } };
            }
        }
        if let Some(s) = best {
            out.push('{');
            j_kv_str(out, "name", s.name);
            j_str(out, "addr"); out.push(':'); j_hex(out, s.addr); out.push(',');
            j_str(out, "offset"); out.push(':'); j_hex(out, addr - s.addr);
            out.push('}');
            return;
        }
        out.push_str(r#"{"error":"no symbol at or below given address"}"#);
        return;
    }
    out.push_str(r#"{"error":"syms requires 'name' or 'addr'"}"#);
}

// ── mem ───────────────────────────────────────────────────────────────────────

const MEM_MAX: u64 = 4096;

fn is_kernel_address(addr: u64) -> bool {
    // Higher-half canonical: addresses ≥ 0xFFFF_8000_0000_0000 are mapped
    // into every process via PML4[256-511], so the read is well-defined
    // regardless of the current CR3.
    addr >= 0xFFFF_8000_0000_0000
}

fn op_mem(req: &str, out: &mut String) {
    let addr = match extract_field(req, "addr").and_then(|s| parse_u64(&s)) {
        Some(a) => a,
        None => { out.push_str(r#"{"error":"missing 'addr'"}"#); return; }
    };
    let len = match extract_field(req, "len").and_then(|s| parse_u64(&s)) {
        Some(l) if l > 0 && l <= MEM_MAX => l,
        Some(_) => { out.push_str(r#"{"error":"len out of range (1..=4096)"}"#); return; }
        None    => { out.push_str(r#"{"error":"missing 'len'"}"#); return; }
    };
    if !is_kernel_address(addr) {
        out.push_str(r#"{"error":"address must be kernel higher-half (>= 0xFFFF_8000_0000_0000)"}"#);
        return;
    }
    let Some(end) = addr.checked_add(len) else {
        out.push_str(r#"{"error":"addr+len overflow"}"#); return;
    };
    if end < addr || !is_kernel_address(end - 1) {
        out.push_str(r#"{"error":"range escapes kernel half"}"#); return;
    }

    // Walk every 4 KiB page and refuse if any is unmapped — catches the
    // fault cleanly without triggering #PF in kernel mode.
    let first_page = addr & !0xFFF;
    let last_page  = (end - 1) & !0xFFF;
    let mut p = first_page;
    while p <= last_page {
        if crate::mm::vmm::virt_to_phys(p).is_none() {
            use core::fmt::Write;
            let _ = write!(out, r#"{{"error":"unmapped page at "#);
            j_hex(out, p);
            out.push_str(r#"}"#);
            return;
        }
        p += 0x1000;
    }

    // SAFETY: every page verified mapped; this is a kernel read.  Volatile
    // so the compiler can't elide or reorder.
    let mut hex = String::with_capacity((len as usize) * 2);
    for i in 0..len {
        let b = unsafe { core::ptr::read_volatile((addr + i) as *const u8) };
        use core::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    out.push('{');
    j_str(out, "addr"); out.push(':'); j_hex(out, addr); out.push(',');
    j_kv(out, "len", &alloc::format!("{}", len));
    j_kv_str(out, "hex", &hex);
    j_trim_comma(out);
    out.push('}');
}

// ── read-file ───────────────────────────────────────────────────────────────
//
// Read a slice of a VFS file and return it base64-encoded (RFC 4648 §4).  This
// is the robust, FFTEST-loop-independent extraction primitive: it works against
// any live kdb-attached session regardless of process / scheduler state, so a
// guest-written artefact (e.g. Firefox's /tmp/out.png screenshot) can be pulled
// to the host even when the boot's own detect-and-emit path is blocked.
//
// Request : {"op":"read-file","path":"/tmp/out.png","offset":0,"len":16384}
// Response: {"path":..,"file_size":N,"offset":O,"n":K,"eof":bool,
//            "sig_png":bool,"b64":"<K bytes base64>"}
//
// `len` is capped at READ_FILE_CHUNK so the base64 payload stays under the kdb
// MAX_RESP_BYTES truncation threshold; the host loops offset+=n until eof to
// reassemble the whole file byte-exactly.  `sig_png` reports whether the file
// begins with the 8-byte PNG signature (W3C PNG §5.2 / ISO 15948) — a cheap
// "is this a real PNG?" check the host can read off the first chunk.

/// Max raw bytes per read-file chunk.  16384 raw -> ceil(16384/3)*4 = 21848
/// base64 chars, comfortably under the 32 KiB MAX_RESP_BYTES kdb response cap.
const READ_FILE_CHUNK: u64 = 16384;

fn b64_append(out: &mut String, src: &[u8]) {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0usize;
    while i + 2 < src.len() {
        let (b0, b1, b2) = (src[i] as usize, src[i + 1] as usize, src[i + 2] as usize);
        out.push(ALPHABET[b0 >> 2] as char);
        out.push(ALPHABET[((b0 & 0x3) << 4) | (b1 >> 4)] as char);
        out.push(ALPHABET[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        out.push(ALPHABET[b2 & 0x3f] as char);
        i += 3;
    }
    if i < src.len() {
        let b0 = src[i] as usize;
        let b1 = if i + 1 < src.len() { src[i + 1] as usize } else { 0 };
        out.push(ALPHABET[b0 >> 2] as char);
        out.push(ALPHABET[((b0 & 0x3) << 4) | (b1 >> 4)] as char);
        out.push(if i + 1 < src.len() {
            ALPHABET[(b1 & 0xf) << 2] as char
        } else {
            '='
        });
        out.push('=');
    }
}

fn op_read_file(req: &str, out: &mut String) {
    let path = match extract_field(req, "path") {
        Some(p) => p,
        None => { out.push_str(r#"{"error":"missing 'path'"}"#); return; }
    };
    let offset = extract_field(req, "offset").and_then(|s| parse_u64(&s)).unwrap_or(0);
    let len = extract_field(req, "len")
        .and_then(|s| parse_u64(&s))
        .unwrap_or(READ_FILE_CHUNK)
        .min(READ_FILE_CHUNK);

    // Read the whole file once (ramfs/cache-backed; cheap for the small
    // artefacts this op targets), then slice — keeps the VFS surface minimal.
    let bytes = match crate::vfs::read_file(&path) {
        Ok(b) => b,
        Err(e) => {
            use core::fmt::Write;
            out.push('{');
            j_kv_str(out, "path", &path);
            let _ = write!(out, r#""error":"read failed: {:?}","#, e);
            j_trim_comma(out);
            out.push('}');
            return;
        }
    };

    let file_size = bytes.len() as u64;
    let start = offset.min(file_size) as usize;
    let end = (offset + len).min(file_size) as usize;
    let slice = &bytes[start..end];
    let n = slice.len() as u64;
    let eof = (offset + n) >= file_size;
    let sig_png = bytes.len() >= 8
        && bytes[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    out.push('{');
    j_kv_str(out, "path", &path);
    j_kv(out, "file_size", &alloc::format!("{}", file_size));
    j_kv(out, "offset", &alloc::format!("{}", offset));
    j_kv(out, "n", &alloc::format!("{}", n));
    j_kv(out, "eof", if eof { "true" } else { "false" });
    j_kv(out, "sig_png", if sig_png { "true" } else { "false" });
    j_str(out, "b64"); out.push(':'); out.push('"');
    b64_append(out, slice);
    out.push('"');
    out.push('}');
}

// ── trace-status ──────────────────────────────────────────────────────────────

fn op_trace_status(out: &mut String) {
    use core::fmt::Write;
    let _ = write!(out, r#"{{"syscall_trace":{},"pf_trace":{},"build":"kdb"}}"#,
                   cfg!(feature = "syscall-trace"), cfg!(feature = "pf-trace"));
}

// ── blk-trace ────────────────────────────────────────────────────────────────
//
// Drain the virtio-blk LBA trace ring (drivers/blk_trace) as JSON. This is the
// out-of-band replacement for the old per-op `[BLK]` COM1 write — the kernel
// now records each request into a lock-free ring (no VM-exit storm), and this
// op serialises the most-recent window on demand. When the `blk-trace` feature
// is off the ring is absent and the op reports `feature: off`.

fn op_blk_trace(out: &mut String) {
    crate::drivers::blk_trace::dump_json(out);
}

// blk-trace-flush: re-emit the classic `[BLK] op/lba/len/pid` serial lines in a
// single controlled burst so the legacy data.img-heatmap serial-log ingestion
// keeps working. Unlike the old design these lines are emitted on demand, not
// once per disk op in the hot path. Returns the emitted line count as JSON.
fn op_blk_trace_flush(out: &mut String) {
    use core::fmt::Write;
    let emitted = crate::drivers::blk_trace::flush_to_serial();
    let _ = write!(out, r#"{{"ok":true,"emitted":{},"feature":"{}"}}"#,
                   emitted, if cfg!(feature = "blk-trace") { "on" } else { "off" });
}

// ── log-ring ─────────────────────────────────────────────────────────────────
//
// Out-of-band drain of the near-zero-overhead guest-RAM log ring
// (drivers::log_ring) — the cheap high-volume log transport that replaces the
// per-byte COM1 16550 PIO firehose.  `log-ring` serialises the live ring as
// JSON over this kdb channel (zero UART cost); `log-ring-flush` re-emits the
// buffered lines to COM1 in one burst for serial-log consumers; the
// `log-ring-enable` toggle forces the slow COM1 path on/off for an A/B
// measurement.

fn op_log_ring(out: &mut String) {
    crate::drivers::log_ring::dump_json(out);
}

fn op_log_ring_flush(out: &mut String) {
    use core::fmt::Write;
    let emitted = crate::drivers::log_ring::flush_to_serial();
    let _ = write!(out, r#"{{"ok":true,"emitted":{}}}"#, emitted);
}

fn op_log_ring_enable(req: &str, out: &mut String) {
    use core::fmt::Write;
    // Optional JSON field `"on": "on"|"off"|"true"|"false"|"1"|"0"`.  Absent →
    // report current state without changing it (query-only).  Mirrors the
    // `futex-set-cluster-wake` request shape so the kdb protocol is consistent.
    let arg = extract_field(req, "on").unwrap_or_default();
    let prev = crate::drivers::log_ring::stats().enabled;
    let now = match arg.as_str() {
        "on" | "1" | "true" => {
            crate::drivers::log_ring::set_enabled(true);
            true
        }
        "off" | "0" | "false" => {
            crate::drivers::log_ring::set_enabled(false);
            false
        }
        _ => prev, // query-only (field absent or unrecognised)
    };
    let _ = write!(
        out,
        r#"{{"ok":true,"prev":{},"enabled":{}}}"#,
        prev, now
    );
}

// ── virtio-blk wait-amplification telemetry ──────────────────────────────────
//
// `virtio-wait-hist` drains the per-round-trip wait-sample ring as a JSON
// histogram (log-scale µs buckets × mean run-queue depth, plus median/p99).
// `virtio-wait-mode block|yield` flips the wait strategy at runtime so a single
// build measures BOTH the BEFORE (spin-then-yield) and AFTER (IRQ-driven block)
// distributions with no build-to-build confound.  `virtio-wait-spin <n>` tunes
// the adaptive-spin budget.  `virtio-wait-reset` zeroes the ring for a clean
// A/B window.

fn op_virtio_wait_hist(out: &mut String) {
    use core::fmt::Write;
    // Prefix the current strategy so the histogram is self-describing.
    let mode = if crate::drivers::virtio_blk::wait_adaptive_enabled() { "adaptive" } else { "legacy" };
    let _ = write!(out, r#"{{"mode":"{}","hist":"#, mode);
    crate::drivers::virtio_blk::wait_hist_json(out);
    out.push('}');
}

fn op_virtio_wait_mode(req: &str, out: &mut String) {
    use core::fmt::Write;
    let arg = extract_field(req, "mode").unwrap_or_default();
    let prev = crate::drivers::virtio_blk::wait_adaptive_enabled();
    let now = match arg.as_str() {
        "adaptive" | "1" | "true" => {
            crate::drivers::virtio_blk::set_wait_adaptive(true);
            true
        }
        "legacy" | "0" | "false" => {
            crate::drivers::virtio_blk::set_wait_adaptive(false);
            false
        }
        _ => prev, // query-only
    };
    let _ = write!(
        out,
        r#"{{"ok":true,"prev_mode":"{}","mode":"{}"}}"#,
        if prev { "adaptive" } else { "legacy" },
        if now { "adaptive" } else { "legacy" }
    );
}

fn op_virtio_wait_spin(req: &str, out: &mut String) {
    use core::fmt::Write;
    match extract_field(req, "n").and_then(|s| s.parse::<u32>().ok()) {
        Some(n) => {
            let prev = crate::drivers::virtio_blk::set_spin_budget(n);
            let _ = write!(out, r#"{{"ok":true,"prev_spin":{},"spin":{}}}"#, prev, n.max(1));
        }
        None => {
            out.push_str(r#"{"error":"virtio-wait-spin needs integer field 'n'"}"#);
        }
    }
}

fn op_virtio_wait_reset(out: &mut String) {
    crate::drivers::virtio_blk::wait_hist_reset();
    out.push_str(r#"{"ok":true,"reset":true}"#);
}

// ── bell-stats ───────────────────────────────────────────────────────────────
//
// Dump the per-source `POLL_BELL` ring counters plus the
// bell-vs-resync wake classification.  Used by the firefox-test
// post-fix verification step (the demo-gate exit criterion is that
// `epoll_wait` returns on bell-ring rather than resync ≥ 90% of the
// time).  The output is one JSON object with:
//   sources: {<name>: <count>, ...}    one entry per PollBellSource
//   bell_wakes:    cumulative wakes attributed to a bell ring
//   resync_wakes:  cumulative wakes attributed to the resync floor
//   bell_ratio:    bell_wakes / (bell_wakes + resync_wakes) × 1000
//                  (integer per-mille so the JSON stays integer-only)

fn op_bell_stats(out: &mut String) {
    use core::fmt::Write;
    let (counts, bell_wakes, resync_wakes) = crate::ipc::waitlist::bell_stats();
    let total_wakes = bell_wakes.saturating_add(resync_wakes);
    let bell_ratio_permille = if total_wakes == 0 {
        0u64
    } else {
        // Integer per-mille — caller divides by 10 for percent.
        bell_wakes.saturating_mul(1000) / total_wakes
    };

    out.push_str(r#"{"sources":{"#);
    for (i, (name, count)) in crate::ipc::waitlist::BELL_SOURCE_NAMES
        .iter()
        .zip(counts.iter())
        .enumerate()
    {
        if i > 0 { out.push(','); }
        let _ = write!(out, r#""{}":{}"#, name, count);
    }
    let _ = write!(
        out,
        r#"}},"bell_wakes":{},"resync_wakes":{},"bell_ratio_permille":{}}}"#,
        bell_wakes, resync_wakes, bell_ratio_permille
    );
}
// ── cache-aliasing ────────────────────────────────────────────────────────────
//
// W215 H3a diagnostic: dump the two new counters that instrument the
// "writer into cache frame" axis.
//
// Output (firefox-test builds):
//   {
//     "pfh_writable_alias_cache":      N,   -- writable installs aliasing a cache frame
//     "sys_mmap_shared_write_filebacked": M, -- MAP_SHARED|PROT_WRITE filebacked mmaps
//   }
//
// Disambiguation per W215_H3_CACHE_HIT_COW_2026-05-16.md §188-196:
//   sys_mmap_shared_write_filebacked > 0 AND inode matches libxul  → H3a confirmed (mmap path)
//   pfh_writable_alias_cache > 0 AND key mismatch with installer   → H3a confirmed (PFH path)
//   both == 0 AND W215 still fires                                  → H3a dead; escalate to H3b
//   pfh_writable_alias_cache > 0 but key matches installer          → NULL; re-frame

fn op_cache_aliasing(out: &mut String) {
    #[cfg(feature = "firefox-test-core")]
    {
        use core::fmt::Write;
        let pfh_alias = crate::arch::x86_64::idt::pfh_writable_alias_cache_count();
        let mmap_sw   = crate::syscall::sys_mmap_shared_write_filebacked_count();
        out.push('{');
        let _ = write!(out, r#""pfh_writable_alias_cache":{},"sys_mmap_shared_write_filebacked":{}"#,
            pfh_alias, mmap_sw);
        out.push('}');
    }
    #[cfg(not(feature = "firefox-test-core"))]
    {
        out.push_str(r#"{"error":"cache-aliasing requires firefox-test feature"}"#);
    }
}

// ── fault-cache-keys ──────────────────────────────────────────────────────────
//
// W215 action-(C) diagnostic: dump the three FAULT/CACHE-KEY bucket counters
// that classify each FAULT/PHYS event by the corrupted frame's cache state.
//
// Bucket A — same-key in-place corruption: frame still in cache under the
//   correct (mount,inode,page_offset) key; content corrupted by a writer with
//   direct physmap or MAP_SHARED+RW access.  Next dispatch: kernel physmap /
//   same-inode SHARED+RW user-PTE audit.
//
// Bucket B — cross-key aliased: frame in cache under a *different* key; a
//   second cache::insert raced the PFH install and evicted + reused the frame.
//   Next dispatch: cache::insert / cache::lookup_and_acquire phys-collision audit.
//
// Bucket C — not in cache (post-evict stale PTE): cache evicted the frame
//   but the PTE was not shot down; PMM may have recycled the frame.  Next
//   dispatch: VMA-shootdown-on-evict audit.
//
// Requires: --features firefox-test,kdb.
// Returns zero for all buckets before any W215-cluster fault fires (idle state).

fn op_fault_cache_keys(out: &mut String) {
    #[cfg(feature = "firefox-test-core")]
    {
        use core::fmt::Write;
        let (a, b, c) = crate::signal::fault_cache_key_bucket_counts();
        out.push('{');
        let _ = write!(out,
            r#""bucket_a_same_key_inplace":{a},"bucket_b_cross_key_aliased":{b},"bucket_c_post_evict_stale_pte":{c}"#,
        );
        out.push('}');
    }
    #[cfg(not(feature = "firefox-test-core"))]
    {
        out.push_str(r#"{"error":"fault-cache-keys requires firefox-test feature"}"#);
    }
}

// ── w215-cache-residency ────────────────────────────────────────────────────
//
// W215 axis-B per-writer cache-residency probe readout.  Each counter
// represents one instrumented kernel writer; the value is the number of
// times that writer attempted to write into a user buffer whose backing
// physical frame was at that moment resident in the page cache (i.e. a
// W215 bucket-A in-place corruption opportunity, per Intel SDM Vol. 3A
// §4.10.5 page-content coherence semantics).
//
// Decision matrix:
//   - exactly one counter > 0  → that writer is the W215 trigger
//   - multiple counters > 0    → multi-writer class; need copy_to_user
//   - all counters = 0         → axis B is wrong; pivot to PHYS_OFF
//                                kernel-internal writers
//
// The first hit per writer also emits a `[H_W/<name>]` serial line with
// pid/vaddr/phys/key for provenance.  Requires --features firefox-test.

fn op_w215_cache_residency(out: &mut String) {
    #[cfg(feature = "firefox-test-core")]
    {
        use core::fmt::Write;
        out.push('{');
        let counts = crate::mm::w215_diag::counts();
        for (i, (name, val)) in counts.iter().enumerate() {
            if i > 0 { out.push(','); }
            let _ = write!(out, r#""{name}":{val}"#);
        }
        out.push('}');
    }
    #[cfg(not(feature = "firefox-test-core"))]
    {
        out.push_str(r#"{"error":"w215-cache-residency requires firefox-test feature"}"#);
    }
}

// ── tlb-stats ────────────────────────────────────────────────────────────────
//
// Unified TLB shootdown + PMM recent-free diagnostic readout.
//
// Exposes the six counters used by the W215 H1 and H2 investigations:
//
//   H1 counters (always-present paths — not currently in tlb.rs but kept here
//   as zero placeholders for unified harness output):
//     cache_audit_orphan        [cache::audit_invariant: orphaned rc=0 cache entry]
//     pmm_alloc_nonzero_rc      [pmm::alloc_page: frame handed out at rc>0]
//     refcount_set_over_nonzero [page_ref_set called on frame already live]
//
//   H2 counters (firefox-test gated):
//     shootdown_clean_ack_late  [shootdown declared clean, handler not yet done]
//     shootdown_unclean_total   [shootdown returned false → quarantine]
//     pmm_alloc_recent_free     [frame re-allocated within RECENT_FREE_WINDOW]
//
//   Plus existing TLB transport stats:
//     shootdowns_sent, ipis_sent, ack_timeouts, shootdowns_handled,
//     quarantine_deferred, quarantine_released, quarantine_depth.
//
// Output: single flat JSON object; all fields present in every build (H2 fields
// read as 0 when the feature is absent so the harness needs no per-build logic).

// ── w215-diag ────────────────────────────────────────────────────────────────
//
// W215 two-arm diagnostic readout.  Returns:
//   { window_race, install_race, prov_ring_overflow,
//     top_traced: [[phys, count], ...] }
//
// window_race > 0   → PREINS Arm-2 axis A confirmed at the cache-op layer.
// install_race > 0  → PREINS Arm-2 axis A confirmed at the PFH install layer.
// prov_ring_overflow > 0 (small) → some buckets are hotter than 16 entries;
//                                  acceptable.  Large → bucket sizing wrong.
//
// Requires: --features firefox-test.

fn op_w215_diag(out: &mut String) {
    #[cfg(feature = "firefox-test-core")]
    {
        use core::fmt::Write;
        let window_race = crate::mm::w215_diag::window_race_count();
        let install_race = crate::mm::w215_diag::install_race_count();
        let overflow = crate::mm::w215_diag::prov_ring_overflow_count();
        let mut top: [(u64, u32); 5] = [(0, 0); 5];
        let n = crate::mm::w215_diag::top_traced_physes(&mut top);
        out.push('{');
        let _ = write!(out,
            r#""window_race":{window_race},"install_race":{install_race},"prov_ring_overflow":{overflow}"#,
        );
        let _ = write!(out, r#","top_traced":["#);
        for i in 0..n {
            if i != 0 { out.push(','); }
            let _ = write!(out, r#"[{},{}]"#, top[i].0, top[i].1);
        }
        out.push(']');
        out.push('}');
    }
    #[cfg(not(feature = "firefox-test-core"))]
    {
        out.push_str(r#"{"error":"w215-diag requires firefox-test feature"}"#);
    }
}

// ── w215-cow-witness ───────────────────────────────────────────────────────
//
// Dump the CoW double-install witness table.  Each entry is a dispositive
// A-vs-B pair captured at the page-fault CoW install site: a sibling thread on
// the same shared CR3 already installed its OWN frame (existing_phys = frame B)
// at the faulting VA while this CPU was about to install a DIFFERENT frame
// (incoming_phys = frame A) — one VA resolving to two physical frames, the
// W215 shared-CR3 double-install (Intel SDM Vol. 3A §4.10.4).
//
// Request:  {"op":"w215-cow-witness"}            dump all slots + total
//           {"op":"w215-cow-witness","va":"0x7eff19c7a534"}  filter to one VA
// Response: {"total":N,"hits":M}  (the per-entry detail is emitted to serial
//           as [W215/COW-WITNESS] lines for grep capture)
//
// Requires: --features firefox-test.
fn op_w215_cow_witness(req: &str, out: &mut String) {
    #[cfg(feature = "firefox-test")]
    {
        use core::fmt::Write;
        let va = extract_field(req, "va").and_then(|s| parse_u64(&s)).unwrap_or(0);
        let total = crate::mm::w215_diag::cow_double_install_total();
        let hits = crate::mm::w215_diag::dump_cow_witness_for_va(va);
        let _ = write!(out, r#"{{"total":{},"hits":{},"va":"{:#x}"}}"#, total, hits, va);
    }
    #[cfg(not(feature = "firefox-test"))]
    {
        let _ = req;
        out.push_str(r#"{"error":"w215-cow-witness requires firefox-test feature"}"#);
    }
}

// ── arm-phys ─────────────────────────────────────────────────────────────────
//
// Manually arm a write-only hardware watchpoint on a specific physical
// address, bypassing the cache::insert pre-arm key filter.  Used when the
// CRC walker has identified a corrupted phys (W215 saga) and the caller
// wants to catch the next write to it irrespective of cache-key heuristics.
//
// Request:   {"op":"arm-phys","phys":"0x29d91000"}   (hex or decimal)
// Response:  {"armed":true,"slot":N}                       on success
//            {"armed":false,"error":"<reason>"}            otherwise
//
// Reasons: "not_aligned" (phys not 4 KiB-aligned),
//          "out_of_range" (phys >= installed RAM top),
//          "pool_exhausted" (all four DR slots busy),
//          "missing_phys" (no phys field in request),
//          "bad_phys" (phys field not parseable as u64),
//          "requires_w215_diag" (kernel built without --features w215-diag).
//
// Requires: --features w215-diag.

fn op_arm_phys(req: &str, out: &mut String) {
    #[cfg(feature = "w215-diag")]
    {
        use core::fmt::Write;
        let phys_str = match extract_field(req, "phys") {
            Some(v) => v,
            None => {
                out.push_str(r#"{"armed":false,"error":"missing_phys"}"#);
                return;
            }
        };
        let phys = match parse_u64(&phys_str) {
            Some(v) => v,
            None => {
                out.push_str(r#"{"armed":false,"error":"bad_phys"}"#);
                return;
            }
        };
        use crate::arch::x86_64::debug_reg::{arm_phys_watchpoint, ArmPhysResult};
        match arm_phys_watchpoint(phys) {
            ArmPhysResult::Armed(slot) => {
                let _ = write!(
                    out,
                    r#"{{"armed":true,"slot":{},"phys":"{:#x}"}}"#,
                    slot, phys,
                );
            }
            ArmPhysResult::NotAligned => {
                out.push_str(r#"{"armed":false,"error":"not_aligned"}"#);
            }
            ArmPhysResult::OutOfRange => {
                out.push_str(r#"{"armed":false,"error":"out_of_range"}"#);
            }
            ArmPhysResult::PoolExhausted => {
                out.push_str(r#"{"armed":false,"error":"pool_exhausted"}"#);
            }
        }
    }
    #[cfg(not(feature = "w215-diag"))]
    {
        let _ = req;
        out.push_str(r#"{"armed":false,"error":"requires_w215_diag"}"#);
    }
}

fn op_tlb_stats(out: &mut String) {
    use core::fmt::Write;

    let s = crate::mm::tlb::stats();
    let pmm_recent = crate::mm::pmm::pmm_alloc_recent_free_count();

    out.push('{');
    // ── TLB transport counters ─────────────────────────────────────────────
    let _ = write!(out, r#""shootdowns_sent":{},"#,    s.shootdowns_sent);
    let _ = write!(out, r#""ipis_sent":{},"#,           s.ipis_sent);
    let _ = write!(out, r#""ack_timeouts":{},"#,        s.ack_timeouts);
    let _ = write!(out, r#""shootdowns_handled":{},"#,  s.shootdowns_handled);
    let _ = write!(out, r#""quarantine_deferred":{},"#, s.quarantine_deferred);
    let _ = write!(out, r#""quarantine_released":{},"#, s.quarantine_released);
    let _ = write!(out, r#""quarantine_depth":{},"#,   s.quarantine_depth);
    // ── H2 diagnostic counters ─────────────────────────────────────────────
    let _ = write!(out, r#""shootdown_clean_ack_late":{},"#, s.clean_ack_late);
    let _ = write!(out, r#""shootdown_unclean_total":{},"#,  s.unclean_total);
    let _ = write!(out, r#""pmm_alloc_recent_free":{}"#,     pmm_recent);
    out.push('}');
}

// ── heap-stats ────────────────────────────────────────────────────────────────
//
// Snapshots the kernel-heap allocator plus the few growable collections
// that have been observed to leak over a long firefox-test soak.  The
// 6-minute heap-guard panic at `HEAP_START + 128 MiB` (idt.rs page-fault
// handler) is, by definition, a slow-leak class — this op makes the
// rate visible so a sampling caller can identify which collection is
// climbing linearly with wall-clock.
//
// Output shape (JSON):
//   {
//     "heap": { "current_bytes":N, "peak_bytes":N, "alloc_count":N,
//               "free_count":N, "alloc_bytes":N, "free_bytes":N,
//               "total_bytes":N, "allocator_used":N, "allocator_free":N },
//     "collections": {
//       "process_table": N | -1,
//       "thread_table":  N | -1,
//       "page_cache":    N,
//       "page_cache_dirty": N,
//       "tlb_quarantine":   N,
//       "tcp_connections":  N | -1
//     },
//     "uptime_ticks": N
//   }
//
// Collection probes that cannot acquire their lock within the brief
// try-lock window emit `-1` so the caller distinguishes "no data this
// sample" from a genuine zero.  Every probe uses a budget of ~few
// microseconds so this op never blocks the kdb pump thread.
//
// Public spec citations:
//   - POSIX 1003.1-2024 process model — process / thread table sizing.
//   - Intel SDM Vol. 3A §4.10.4 — TLB quarantine semantics this op
//     surfaces depth for.
fn op_heap_stats(out: &mut String) {
    use core::fmt::Write;

    // ── Allocator-level totals ─────────────────────────────────────────────
    let (h_total, h_alloc, h_free) = crate::mm::heap::stats();
    let (h_allocs, h_frees, h_alloc_b, h_free_b, h_cur, h_peak) =
        crate::perf::heap_alloc_stats();

    out.push('{');
    out.push_str(r#""heap":{"#);
    let _ = write!(out, r#""current_bytes":{},"#, h_cur);
    let _ = write!(out, r#""peak_bytes":{},"#, h_peak);
    let _ = write!(out, r#""alloc_count":{},"#, h_allocs);
    let _ = write!(out, r#""free_count":{},"#, h_frees);
    let _ = write!(out, r#""alloc_bytes":{},"#, h_alloc_b);
    let _ = write!(out, r#""free_bytes":{},"#, h_free_b);
    let _ = write!(out, r#""total_bytes":{},"#, h_total);
    let _ = write!(out, r#""allocator_used":{},"#, h_alloc);
    let _ = write!(out, r#""allocator_free":{}"#, h_free);
    out.push('}');

    // ── Per-collection sizes ───────────────────────────────────────────────
    out.push_str(r#","collections":{"#);

    let proc_n = match try_lock_brief(&PROCESS_TABLE) {
        Some(g) => g.len() as i64, None => -1,
    };
    let thr_n  = match try_lock_brief(&crate::proc::THREAD_TABLE) {
        Some(g) => g.len() as i64, None => -1,
    };
    let _ = write!(out, r#""process_table":{},"#, proc_n);
    let _ = write!(out, r#""thread_table":{},"#, thr_n);

    let (pc_total, pc_dirty) = crate::mm::cache::stats();
    let _ = write!(out, r#""page_cache":{},"#, pc_total);
    let _ = write!(out, r#""page_cache_dirty":{},"#, pc_dirty);
    let _ = write!(out, r#""tlb_quarantine":{},"#,
        crate::mm::tlb::stats().quarantine_depth);

    let tcp_n = match crate::net::tcp::connection_count() {
        Some(n) => n as i64, None => -1,
    };
    let _ = write!(out, r#""tcp_connections":{}"#, tcp_n);

    out.push('}');

    // Uptime for caller-side rate computation.
    let _ = write!(out, r#","uptime_ticks":{}}}"#,
        crate::arch::x86_64::irq::get_ticks());
}

// ── proc-tree ────────────────────────────────────────────────────────────────
//
// Render a depth-first parent/child tree rooted at a chosen PID (default 1).
// Each node emits {pid, ppid, name, state, threads, exit_code, children:[]}.
// Cycles are guarded against by capping recursion depth and bounding the
// total number of emitted nodes; in a healthy system parent_pid forms a
// forest, but a corrupt table or a transient race during reparenting could
// otherwise loop forever.

const PROC_TREE_MAX_DEPTH: u32 = 64;
const PROC_TREE_MAX_NODES: usize = 4096;

fn op_proc_tree(req: &str, out: &mut String) {
    let root = extract_field(req, "pid").and_then(|s| parse_u64(&s)).unwrap_or(1);

    struct Node {
        pid: u64,
        ppid: u64,
        name: String,
        state: &'static str,
        threads: usize,
        exit_code: i32,
    }

    let nodes: Vec<Node> = match try_lock_brief(&PROCESS_TABLE) {
        Some(g) => g.iter().map(|p| Node {
            pid: p.pid,
            ppid: p.parent_pid,
            name: proc_name_string(&p.name),
            state: proc_state_str(p.state),
            threads: p.threads.len(),
            exit_code: p.exit_code,
        }).collect(),
        None => {
            out.push_str(r#"{"busy":"PROCESS_TABLE held","tree":null}"#);
            return;
        }
    };

    if !nodes.iter().any(|n| n.pid == root) {
        use core::fmt::Write;
        let _ = write!(out, r#"{{"error":"root pid {} not found","tree":null}}"#, root);
        return;
    }

    // Build pid → children index up front so render is O(1) per node
    // rather than O(N²) over the table.
    let mut children: alloc::collections::BTreeMap<u64, Vec<u64>> =
        alloc::collections::BTreeMap::new();
    for n in &nodes {
        if n.pid != n.ppid {  // self-parent (PID 0 / kernel) doesn't recurse
            children.entry(n.ppid).or_default().push(n.pid);
        }
    }

    let by_pid: alloc::collections::BTreeMap<u64, &Node> =
        nodes.iter().map(|n| (n.pid, n)).collect();

    // Per-call rendering counters so an enormous table can't blow the
    // response or recurse arbitrarily deep.
    struct Ctx<'a> {
        out: &'a mut String,
        nodes_emitted: usize,
        truncated: bool,
        by_pid: &'a alloc::collections::BTreeMap<u64, &'a Node>,
        children: &'a alloc::collections::BTreeMap<u64, Vec<u64>>,
    }

    fn render(ctx: &mut Ctx, pid: u64, depth: u32) {
        if ctx.truncated { return; }
        if ctx.nodes_emitted >= PROC_TREE_MAX_NODES {
            ctx.truncated = true;
            return;
        }
        let Some(n) = ctx.by_pid.get(&pid) else { return; };
        ctx.nodes_emitted += 1;

        ctx.out.push('{');
        j_kv(ctx.out, "pid",         &alloc::format!("{}", n.pid));
        j_kv(ctx.out, "ppid",        &alloc::format!("{}", n.ppid));
        j_kv_str(ctx.out, "name",    &n.name);
        j_kv_str(ctx.out, "state",   n.state);
        j_kv(ctx.out, "threads",     &alloc::format!("{}", n.threads));
        if n.state == "zombie" {
            j_kv(ctx.out, "exit_code", &alloc::format!("{}", n.exit_code));
        }
        j_str(ctx.out, "children");
        ctx.out.push(':');
        ctx.out.push('[');
        if depth + 1 < PROC_TREE_MAX_DEPTH {
            if let Some(kids) = ctx.children.get(&pid) {
                for (i, child_pid) in kids.iter().enumerate() {
                    if i > 0 { ctx.out.push(','); }
                    render(ctx, *child_pid, depth + 1);
                    if ctx.truncated { break; }
                }
            }
        }
        ctx.out.push(']');
        ctx.out.push('}');
    }

    out.push_str(r#"{"root":"#);
    use core::fmt::Write;
    let _ = write!(out, "{}", root);
    out.push_str(r#","tree":"#);

    let mut ctx = Ctx {
        out, nodes_emitted: 0, truncated: false,
        by_pid: &by_pid, children: &children,
    };
    render(&mut ctx, root, 0);
    let truncated = ctx.truncated;
    let emitted = ctx.nodes_emitted;

    out.push_str(r#","nodes_emitted":"#);
    let _ = write!(out, "{}", emitted);
    if truncated {
        out.push_str(r#","truncated":true"#);
    }
    out.push('}');
}

// ── fd-table ─────────────────────────────────────────────────────────────────
//
// Per-process file descriptor dump.  Emits {pid, count, fds:[…]} where each
// fd entry carries fd number, kind (regular/dir/pipe/socket/timerfd/…),
// flags (numeric + symbolic access mode), inode, mount_idx, offset, cloexec,
// and a best-effort label (open_path for path-backed fds, or a synthesised
// "<console>" / "pipe[id]" / "timerfd[slot]" tag for kernel-sentinel fds).
//
// FileDescriptor in the VFS does not currently track a host-side refcount —
// pipe / socket / timerfd backings refcount internally — so refcount is
// omitted rather than reported as an unreliable value.  open_path doubles
// as the "backing path/peer" identifier.

fn ftype_str(ft: crate::vfs::FileType) -> &'static str {
    use crate::vfs::FileType::*;
    match ft {
        RegularFile => "regular",
        Directory   => "directory",
        SymLink     => "symlink",
        CharDevice  => "char",
        BlockDevice => "block",
        Pipe        => "pipe",
        EventFd     => "eventfd",
        Socket      => "socket",
        TimerFd     => "timerfd",
        SignalFd    => "signalfd",
        InotifyFd   => "inotifyfd",
        PtyMaster   => "pty-master",
        PtySlave    => "pty-slave",
    }
}

fn fd_access_mode_str(flags: u32) -> &'static str {
    use crate::vfs::flags::{O_RDONLY, O_WRONLY, O_RDWR};
    // Linux ABI keeps the access mode in the low 2 bits.
    match flags & 0x3 {
        m if m == O_RDONLY => "r",
        m if m == O_WRONLY => "w",
        m if m == O_RDWR   => "rw",
        _                  => "?",
    }
}

fn op_fd_table(req: &str, out: &mut String) {
    let pid = match extract_field(req, "pid").and_then(|s| parse_u64(&s)) {
        Some(p) => p,
        None => { out.push_str(r#"{"error":"missing or bad 'pid'"}"#); return; }
    };

    struct Row {
        fd: usize,
        kind: &'static str,
        access: &'static str,
        flags: u32,
        cloexec: bool,
        is_console: bool,
        inode: u64,
        mount_idx: usize,
        offset: u64,
        label: String,
    }

    let rows: Option<Vec<Row>> = match try_lock_brief(&PROCESS_TABLE) {
        Some(g) => g.iter().find(|p| p.pid == pid).map(|p| {
            p.file_descriptors.iter().enumerate()
                .filter_map(|(i, fd)| fd.as_ref().map(|fd| {
                    let label = if fd.is_console {
                        match i {
                            0 => "<stdin>".into(),
                            1 => "<stdout>".into(),
                            2 => "<stderr>".into(),
                            _ => "<console>".into(),
                        }
                    } else if !fd.open_path.is_empty() {
                        fd.open_path.clone()
                    } else {
                        // Synthesise a tag for kernel-sentinel fds without a path.
                        match fd.file_type {
                            crate::vfs::FileType::Pipe =>
                                alloc::format!("pipe[{}]", fd.inode),
                            crate::vfs::FileType::TimerFd =>
                                alloc::format!("timerfd[{}]", fd.inode),
                            crate::vfs::FileType::SignalFd =>
                                alloc::format!("signalfd[{}]", fd.inode),
                            crate::vfs::FileType::InotifyFd =>
                                alloc::format!("inotifyfd[{}]", fd.inode),
                            crate::vfs::FileType::EventFd =>
                                alloc::format!("eventfd[{}]", fd.inode),
                            crate::vfs::FileType::Socket =>
                                alloc::format!("socket[{}]", fd.inode),
                            crate::vfs::FileType::PtyMaster =>
                                alloc::format!("ptmx[{}]", fd.inode),
                            crate::vfs::FileType::PtySlave =>
                                alloc::format!("pts[{}]", fd.inode),
                            _ =>
                                alloc::format!("inode={} mount={}", fd.inode, fd.mount_idx),
                        }
                    };
                    Row {
                        fd: i,
                        kind: ftype_str(fd.file_type),
                        access: fd_access_mode_str(fd.flags),
                        flags: fd.flags,
                        cloexec: fd.cloexec,
                        is_console: fd.is_console,
                        inode: fd.inode,
                        mount_idx: fd.mount_idx,
                        offset: fd.offset,
                        label,
                    }
                })).collect()
        }),
        None => {
            out.push_str(r#"{"busy":"PROCESS_TABLE held","fds":[]}"#);
            return;
        }
    };

    let rows = match rows {
        Some(r) => r,
        None => {
            use core::fmt::Write;
            let _ = write!(out, r#"{{"error":"pid {} not found"}}"#, pid);
            return;
        }
    };

    out.push('{');
    j_kv(out, "pid",   &alloc::format!("{}", pid));
    j_kv(out, "count", &alloc::format!("{}", rows.len()));
    j_str(out, "fds"); out.push(':'); out.push('[');
    for (i, r) in rows.iter().take(256).enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_kv(out, "fd",        &alloc::format!("{}", r.fd));
        j_kv_str(out, "kind",  r.kind);
        j_kv_str(out, "access", r.access);
        j_str(out, "flags"); out.push(':'); j_hex(out, r.flags as u64); out.push(',');
        j_kv(out, "cloexec",   if r.cloexec    { "true" } else { "false" });
        j_kv(out, "is_console", if r.is_console { "true" } else { "false" });
        j_kv(out, "inode",     &alloc::format!("{}", r.inode));
        j_kv(out, "mount_idx", &alloc::format!("{}", r.mount_idx as u64));
        j_kv(out, "offset",    &alloc::format!("{}", r.offset));
        j_kv_str(out, "label", &r.label);
        j_trim_comma(out);
        out.push('}');
    }
    out.push(']');
    if rows.len() > 256 {
        out.push_str(r#","truncated":true"#);
    }
    out.push('}');
}

// ── fd-map ───────────────────────────────────────────────────────────────────
//
// Cross-process FD map: for every open FD in the requested process(es),
// emit the FD number, kind, and — critically for socketpair/pipe diagnosis —
// the resolved (peer_pid, peer_fd) for socket and pipe endpoints.
//
// This answers Hypothesis A vs B in the T1 IPC-handshake forensic:
//   A (routing bug):  PID-1 fd=70 peer resolves to a DIFFERENT (pid,fd) than
//                     the one PID-4 TID-78 writes fd=27 to.
//   B (wake bug):     PID-1 fd=70 peer == (PID-4, fd=27) but poll never fires.
//
// The resolution algorithm:
//   sockets: snapshot the unix TABLE once; for a socket FD with id=X,
//            peer_id = TABLE[X].peer_id.  Scan all processes to find which
//            (pid, fd_n) has file_type=Socket and inode==peer_id.
//   pipes:   two FDs sharing the same inode (pipe_id) are a pair.
//            The one with flags bit-0 set is the write-end; the other is read.
//
// Output: { "pid": N | "all", "entries": [ { pid, fd, kind, socket_id,
//   peer_socket_id, peer_pid, peer_fd, pipe_id, pipe_end, path } ] }

fn op_fd_map(req: &str, out: &mut String) {
    use core::fmt::Write;

    // Optional pid filter — 0 means "all".
    let pid_filter: u64 = extract_field(req, "pid")
        .and_then(|s| parse_u64(&s))
        .unwrap_or(0);

    // ── Stage 1: snapshot the process table ───────────────────────────────
    //
    // Collect (pid, fd_index, file_type, inode, flags, open_path) for
    // every open FD across all processes (or just the filtered one).
    // We release PROCESS_TABLE before touching the unix TABLE.

    struct FdSnap {
        pid:       u64,
        fd:        usize,
        file_type: crate::vfs::FileType,
        inode:     u64,   // socket_id or pipe_id depending on kind
        flags:     u32,
        path:      alloc::string::String,
    }

    let fd_snaps: alloc::vec::Vec<FdSnap> = match try_lock_brief(&PROCESS_TABLE) {
        Some(g) => {
            let mut v = alloc::vec::Vec::new();
            for p in g.iter() {
                if pid_filter != 0 && p.pid != pid_filter { continue; }
                for (i, slot) in p.file_descriptors.iter().enumerate() {
                    let fd = match slot { Some(f) => f, None => continue };
                    if fd.is_console { continue; }
                    use crate::vfs::FileType::*;
                    match fd.file_type {
                        Socket | Pipe => {}
                        _ => continue, // only emit types with meaningful peers
                    }
                    v.push(FdSnap {
                        pid:       p.pid,
                        fd:        i,
                        file_type: fd.file_type,
                        inode:     fd.inode,
                        flags:     fd.flags,
                        path:      fd.open_path.clone(),
                    });
                }
            }
            v
        }
        None => {
            out.push_str(r#"{"busy":"PROCESS_TABLE held","entries":[]}"#);
            return;
        }
    };

    if fd_snaps.is_empty() {
        // No socket/pipe FDs for the requested filter.
        if pid_filter != 0 {
            let _ = write!(out, r#"{{"pid":{},"entries":[]}}"#, pid_filter);
        } else {
            out.push_str(r#"{"pid":"all","entries":[]}"#);
        }
        return;
    }

    // ── Stage 2: snapshot the unix socket TABLE ────────────────────────────
    //
    // Build a map from socket_id → peer_socket_id from one lock
    // acquisition rather than calling get_peer() per FD.

    let sock_snaps = crate::net::unix::snapshot_all();

    // ── Stage 3: resolve peer (pid, fd) for each socket FD ────────────────
    //
    // For socket FD with inode=S: peer_socket_id = sock_snaps[S].peer_id.
    // Then find the FdSnap whose inode == peer_socket_id.

    // Helper: find (pid, fd_n) for a given socket_id.
    let find_socket_owner = |target_socket_id: u64| -> Option<(u64, usize)> {
        fd_snaps.iter()
            .find(|s| {
                matches!(s.file_type, crate::vfs::FileType::Socket)
                    && s.inode == target_socket_id
            })
            .map(|s| (s.pid, s.fd))
    };

    // ── Stage 4: emit JSON ─────────────────────────────────────────────────

    if pid_filter != 0 {
        let _ = write!(out, r#"{{"pid":{},"entries":["#, pid_filter);
    } else {
        out.push_str(r#"{"pid":"all","entries":["#);
    }

    let mut first = true;
    for snap in &fd_snaps {
        if !first { out.push(','); }
        first = false;
        out.push('{');
        j_kv(out, "pid", &alloc::format!("{}", snap.pid));
        j_kv(out, "fd",  &alloc::format!("{}", snap.fd));

        match snap.file_type {
            crate::vfs::FileType::Socket => {
                j_kv_str(out, "kind", "socket");
                j_kv(out, "socket_id", &alloc::format!("{}", snap.inode));

                // Resolve peer socket id from the snapshot.
                let peer_socket_id = sock_snaps.iter()
                    .find(|s| s.id == snap.inode)
                    .map(|s| s.peer_id)
                    .unwrap_or(u64::MAX);

                if peer_socket_id == u64::MAX {
                    j_kv_str(out, "peer_socket_id", "none");
                    j_kv_str(out, "peer_pid", "none");
                    j_kv_str(out, "peer_fd",  "none");
                } else {
                    j_kv(out, "peer_socket_id", &alloc::format!("{}", peer_socket_id));
                    match find_socket_owner(peer_socket_id) {
                        Some((ppid, pfd)) => {
                            j_kv(out, "peer_pid", &alloc::format!("{}", ppid));
                            j_kv(out, "peer_fd",  &alloc::format!("{}", pfd));
                        }
                        None => {
                            // Peer socket exists in TABLE but no process owns it yet
                            // (e.g. created but not yet dup'd/installed in any FD table).
                            j_kv_str(out, "peer_pid", "unowned");
                            j_kv_str(out, "peer_fd",  "unowned");
                        }
                    }
                }
            }
            crate::vfs::FileType::Pipe => {
                j_kv_str(out, "kind", "pipe");
                j_kv(out, "pipe_id", &alloc::format!("{}", snap.inode));
                // Bit 0 of flags: 1 = write end (see FileDescriptor::pipe_write_end)
                let is_write = snap.flags & 1 == 1;
                j_kv_str(out, "pipe_end", if is_write { "write" } else { "read" });

                // Find the complementary end (same pipe_id, opposite direction).
                let peer = fd_snaps.iter().find(|s| {
                    matches!(s.file_type, crate::vfs::FileType::Pipe)
                        && s.inode == snap.inode
                        && (s.flags & 1 == 1) != is_write // opposite end
                });
                match peer {
                    Some(p) => {
                        j_kv(out, "peer_pid", &alloc::format!("{}", p.pid));
                        j_kv(out, "peer_fd",  &alloc::format!("{}", p.fd));
                    }
                    None => {
                        j_kv_str(out, "peer_pid", "none");
                        j_kv_str(out, "peer_fd",  "none");
                    }
                }
            }
            _ => { j_kv_str(out, "kind", "other"); }
        }

        if !snap.path.is_empty() { j_kv_str(out, "path", &snap.path); }
        j_trim_comma(out);
        out.push('}');
    }

    out.push_str("]}");
}

// ── unix-diag ────────────────────────────────────────────────────────────────
//
// Decisive recv-side readiness probe for one AF_UNIX socket inode.  Answers, at
// a live wedge, the gate-4 question: does the content proc's IPDL channel have
// ── pipe-diag ─────────────────────────────────────────────────────────────────
//
// One-pipe diagnostic for blocking-write triage: ring occupancy, free space,
// endpoint refcounts, and how many threads are parked on each waitlist.
// Discriminates "pipe full + writers parked" (reader not draining) from
// "pipe empty + writers parked" (drain ran but the wake was lost) from
// "no waiters" (writer blocked elsewhere).
//
// Request: {"op":"pipe-diag","id":N}.
// Reply:   {"id":N,"buffered":B,"space":S,"readers":R,"writers":W,
//           "read_waiters":RW,"write_waiters":WW}
fn op_pipe_diag(req: &str, out: &mut String) {
    use core::fmt::Write;
    let id: u64 = match extract_field(req, "id").and_then(|s| parse_u64(&s)) {
        Some(v) => v,
        None => { out.push_str(r#"{"error":"missing 'id' field"}"#); return; }
    };
    match crate::ipc::pipe::pipe_diag_for(id) {
        Some((buffered, space, readers, writers)) => {
            let rw = crate::ipc::pipe::debug_reader_waiter_count(id);
            let ww = crate::ipc::pipe::debug_writer_waiter_count(id);
            let _ = write!(
                out,
                r#"{{"id":{},"buffered":{},"space":{},"readers":{},"writers":{},"read_waiters":{},"write_waiters":{}}}"#,
                id, buffered, space, readers, writers, rw, ww
            );
        }
        None => {
            let _ = write!(out, r#"{{"id":{},"error":"no such pipe"}}"#, id);
        }
    }
}

// UNREAD data in its recv ring (recv_avail>0) that epoll fails to report (=> P1
// epoll readiness drop), an undelivered SCM batch sitting ahead of the reader
// (=> P2 recvmsg SCM drop), or an EMPTY ring with no pending SCM (=> the parent
// never wrote to this inode => P3 routing / P4 navigation-never-sent)?
//
// Request: {"op":"unix-diag","inode":N}.  Reports for socket N AND its peer:
//   recv_avail (unread bytes in ring), recv_pushed/recv_popped (stream pos),
//   read/write shutdown, plus the pending SCM batches bound to N
//   (byte_offset, fd_count, deliverable=consumed>=offset).
fn op_unix_diag(req: &str, out: &mut String) {
    use core::fmt::Write;

    let inode: u64 = match extract_field(req, "inode").and_then(|s| parse_u64(&s)) {
        Some(v) => v,
        None => { out.push_str(r#"{"error":"missing 'inode' field"}"#); return; }
    };

    let emit_sock = |out: &mut String, id: u64| {
        match crate::net::unix::diag_for(id) {
            Some(d) => {
                let consumed = d.recv_popped;
                let scm = crate::syscall::scm_diag_for(id, consumed);
                let has_scm_deliv = scm.iter().any(|(_, _, deliv)| *deliv);
                out.push('{');
                let _ = write!(out, r#""id":{},"#, d.id);
                j_kv_str(out, "state", match d.state {
                    crate::net::unix::UnixState::Free => "free",
                    crate::net::unix::UnixState::Unbound => "unbound",
                    crate::net::unix::UnixState::Bound => "bound",
                    crate::net::unix::UnixState::Listening => "listening",
                    crate::net::unix::UnixState::Connected => "connected",
                });
                let _ = write!(out, r#""peer_id":{},"#, d.peer_id as i64);
                let _ = write!(out, r#""recv_avail":{},"#, d.recv_avail);
                let _ = write!(out, r#""recv_pushed":{},"#, d.recv_pushed);
                let _ = write!(out, r#""recv_popped":{},"#, d.recv_popped);
                let _ = write!(out, r#""read_shutdown":{},"#, d.read_shutdown);
                let _ = write!(out, r#""write_shutdown":{},"#, d.write_shutdown);
                let _ = write!(out, r#""rx_eof":{},"#, d.rx_eof);
                let _ = write!(out, r#""peer_closed":{},"#, d.peer_closed);
                let _ = write!(out, r#""has_data":{},"#, d.recv_avail > 0);
                let _ = write!(out, r#""scm_deliverable":{},"#, has_scm_deliv);
                out.push_str(r#""scm_batches":["#);
                let mut first = true;
                for (off, nfds, deliv) in &scm {
                    if !first { out.push(','); }
                    first = false;
                    let _ = write!(out,
                        r#"{{"byte_offset":{},"fd_count":{},"deliverable":{}}}"#,
                        off, nfds, deliv);
                }
                out.push_str("]}");
            }
            None => {
                let _ = write!(out, r#"{{"id":{},"state":"free-or-oob"}}"#, id);
            }
        }
    };

    out.push('{');
    let _ = write!(out, r#""inode":{},"#, inode);
    out.push_str(r#""socket":"#);
    emit_sock(out, inode);
    // Peer end (where the parent's writes land BEFORE they reach this end's
    // recv ring is the OTHER direction — but report the peer for context).
    let peer = crate::net::unix::get_peer(inode);
    out.push(',');
    out.push_str(r#""peer":"#);
    if peer != u64::MAX {
        emit_sock(out, peer);
    } else {
        out.push_str(r#"{"state":"no-peer"}"#);
    }
    out.push('}');
}

// ── epoll-watch ──────────────────────────────────────────────────────────────
//
// Decisive reactor-liveness probe.  Given a pid and one of its epoll fds, dump
// the epoll INTEREST SET and each watched fd's LIVE readiness, computed via the
// exact same path `epoll_wait(2)` uses internally.  Pairs with `unix-diag`: at
// a wedge where a content-reply AF_UNIX channel shows parent-end
// `recv_avail>0, recv_popped=0` frozen, this answers WHY the reactor never
// drains it:
//
//   * the fd IS in the interest set and `delivered` carries EPOLLIN (ready)
//     yet the reactor never recvmsg's  → the reactor THREAD is not running
//     epoll_wait (parked / scheduled-out / busy elsewhere) = a starvation /
//     userspace-reactor problem, NOT a kernel readiness drop.
//   * the fd is ABSENT from the interest set, OR `revents` reports no EPOLLIN
//     despite unread data  → a kernel epoll readiness/registration divergence
//     (epoll(7): a level-triggered fd with unread data MUST report EPOLLIN).
//
// Request: {"op":"epoll-watch","pid":P,"epfd":E}.
// Output:  {pid, epfd, epoll_id, watches:[{fd, subscribed, subscribed_flags,
//          revents, revents_flags, delivered, delivered_flags, ready}…]}.
// `subscribed`/`revents`/`delivered` are the raw EPOLL* bitmasks; the
// `_flags` siblings decode them to a human-readable string; `ready` is
// `delivered != 0`.

/// Decode an EPOLL* bitmask into a compact `|`-joined flag string for JSON.
fn epoll_flags_str(m: u32) -> alloc::string::String {
    use crate::ipc::epoll::{
        EPOLLIN, EPOLLPRI, EPOLLOUT, EPOLLERR, EPOLLHUP, EPOLLRDHUP,
    };
    let mut s = alloc::string::String::new();
    let mut push = |name: &str| {
        if !s.is_empty() { s.push('|'); }
        s.push_str(name);
    };
    if m & EPOLLIN    != 0 { push("EPOLLIN"); }
    if m & EPOLLOUT   != 0 { push("EPOLLOUT"); }
    if m & EPOLLPRI   != 0 { push("EPOLLPRI"); }
    if m & EPOLLRDHUP != 0 { push("EPOLLRDHUP"); }
    if m & EPOLLHUP   != 0 { push("EPOLLHUP"); }
    if m & EPOLLERR   != 0 { push("EPOLLERR"); }
    if s.is_empty() { s.push('0'); }
    s
}

fn op_epoll_watch(req: &str, out: &mut String) {
    use core::fmt::Write;

    let pid: u64 = match extract_field(req, "pid").and_then(|s| parse_u64(&s)) {
        Some(v) => v,
        None => { out.push_str(r#"{"error":"missing 'pid' field"}"#); return; }
    };
    let epfd: usize = match extract_field(req, "epfd").and_then(|s| parse_u64(&s)) {
        Some(v) => v as usize,
        None => { out.push_str(r#"{"error":"missing 'epfd' field"}"#); return; }
    };

    use crate::subsys::linux::syscall::{epoll_watch_diag, EpollWatchResult};
    out.push('{');
    let _ = write!(out, r#""pid":{},"epfd":{},"#, pid, epfd);
    match epoll_watch_diag(pid, epfd) {
        EpollWatchResult::NoProc =>
            out.push_str(r#""error":"no-such-pid","watches":[]}"#),
        EpollWatchResult::NotEpoll =>
            out.push_str(r#""error":"fd-not-epoll","watches":[]}"#),
        EpollWatchResult::NoInstance =>
            out.push_str(r#""error":"no-epoll-instance","watches":[]}"#),
        EpollWatchResult::Ok { epoll_id, watches } => {
            let _ = write!(out, r#""epoll_id":{},"watch_count":{},"#,
                epoll_id, watches.len());
            out.push_str(r#""watches":["#);
            let mut first = true;
            for w in &watches {
                if !first { out.push(','); }
                first = false;
                out.push('{');
                let _ = write!(out, r#""fd":{},"#, w.fd);
                let _ = write!(out, r#""subscribed":{},"#, w.subscribed);
                let _ = write!(out, r#""subscribed_flags":"{}","#,
                    epoll_flags_str(w.subscribed));
                let _ = write!(out, r#""revents":{},"#, w.revents);
                let _ = write!(out, r#""revents_flags":"{}","#,
                    epoll_flags_str(w.revents));
                let _ = write!(out, r#""delivered":{},"#, w.delivered);
                let _ = write!(out, r#""delivered_flags":"{}","#,
                    epoll_flags_str(w.delivered));
                let _ = write!(out, r#""ready":{}"#, w.delivered != 0);
                out.push('}');
            }
            out.push_str("]}");
        }
    }
}

// ── syscall-trend ────────────────────────────────────────────────────────────
//
// Histogram of recent syscall events from the perf::syscall_ring.  Optionally
// filter to one PID and bound the lookback to N seconds (default 5).  The
// window is capped at 600 s — matches the test-mode kdb runtime watchdog at
// 100 Hz, so the ceiling is the longest realistic introspection window.
// Note: the ring holds 16384 entries; under heavy syscall traffic (~10k/sec
// from a Firefox-class process) the oldest entries scroll out long before
// the requested window — `samples` reports what actually survived.
//
// Output: {window_seconds, pid_filter, samples, top:[{nr,name,count}…]}.
// Sorted descending by count; capped at 32 entries to keep responses bounded.

const SYSCALL_TREND_TOP_N: usize = 32;
const SYSCALL_TREND_MAX_SECONDS: u64 = 600;

fn op_syscall_trend(req: &str, out: &mut String) {
    use core::fmt::Write;

    let seconds = extract_field(req, "seconds")
        .and_then(|s| parse_u64(&s))
        .unwrap_or(5)
        .min(SYSCALL_TREND_MAX_SECONDS)
        .max(1);
    let pid_filter = extract_field(req, "pid")
        .and_then(|s| parse_u64(&s))
        .unwrap_or(0);

    // PIT runs at 100 Hz — see arch::x86_64::irq.  The ring stores ticks in
    // 32 bits; the trend window is computed in u64 with saturation.
    let now_ticks = crate::arch::x86_64::irq::get_ticks();
    let lookback_ticks = seconds.saturating_mul(100);
    let since_tick = now_ticks.saturating_sub(lookback_ticks);

    // BTreeMap → deterministic iteration; small (≤ ring distinct nrs).
    let mut hist: alloc::collections::BTreeMap<u16, u64> =
        alloc::collections::BTreeMap::new();
    let mut samples: u64 = 0;
    crate::perf::syscall_ring_walk(since_tick, pid_filter, |ev| {
        *hist.entry(ev.nr).or_insert(0) += 1;
        samples += 1;
    });

    // Rank by count descending, then nr ascending to break ties stably.
    let mut ranked: Vec<(u16, u64)> = hist.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    out.push('{');
    j_kv(out, "window_seconds", &alloc::format!("{}", seconds));
    j_kv(out, "pid_filter",     &alloc::format!("{}", pid_filter));
    j_kv(out, "now_tick",       &alloc::format!("{}", now_ticks));
    j_kv(out, "since_tick",     &alloc::format!("{}", since_tick));
    j_kv(out, "samples",        &alloc::format!("{}", samples));
    j_str(out, "top"); out.push(':'); out.push('[');
    for (i, (nr, count)) in ranked.iter().take(SYSCALL_TREND_TOP_N).enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        let _ = write!(out, r#""nr":{},"#, nr);
        j_kv_str(out, "name", crate::perf::linux_syscall_name(*nr as u64));
        let _ = write!(out, r#""count":{}"#, count);
        out.push('}');
    }
    out.push(']');
    if ranked.len() > SYSCALL_TREND_TOP_N {
        out.push_str(r#","more":true"#);
    }
    out.push('}');
}

// ── cache-audit ───────────────────────────────────────────────────────────────
//
// Run `cache::audit_invariant()` (firefox-test only) and return structured
// JSON.  Also reads the PMM and refcount diagnostic counters accumulated since
// boot.
//
// Output (firefox-test builds):
//   {
//     "total_entries": N,
//     "orphan_count":  M,
//     "pmm_alloc_nonzero_rc": P,
//     "refcount_set_over_nonzero": Q,
//     "orphans": [ {"key":"(m,i,0xoff)", "phys":"0x...", "rc":0}, ... ]
//   }
//
// On non-firefox-test builds the op returns a capabilities note instead.

fn op_cache_audit(out: &mut String) {
    #[cfg(feature = "firefox-test-core")]
    {
        use core::fmt::Write;

        // Run the audit — also emits serial lines for grep.
        let (total, orphan_count) = crate::mm::cache::audit_invariant();

        // Read the PMM and refcount counters.
        let pmm_nonzero = crate::mm::pmm::pmm_alloc_nonzero_rc_count();
        let rc_set_over = crate::mm::refcount::refcount_set_over_nonzero_count();
        let pmm_residual = crate::mm::pmm::pmm_free_residual_refs_count();

        // We already logged individual orphans via serial in audit_invariant.
        // The JSON response carries the aggregate numbers plus a note that
        // full orphan detail is in the serial log.
        out.push('{');
        let _ = write!(out, r#""total_entries":{},"orphan_count":{},"pmm_alloc_nonzero_rc":{},"refcount_set_over_nonzero":{},"pmm_free_residual_refs":{}"#,
            total, orphan_count, pmm_nonzero, rc_set_over, pmm_residual,
        );
        // Indicate where to find per-orphan detail.
        out.push_str(r#","note":"per-orphan detail in serial log [CACHE/AUDIT/ORPHAN] lines""#);
        out.push('}');
    }
    #[cfg(not(feature = "firefox-test-core"))]
    {
        out.push_str(r#"{"error":"cache-audit requires firefox-test feature"}"#);
    }
}

// ── coverage-flush ────────────────────────────────────────────────────────────
//
// Triggers the in-kernel LLVM source-based coverage dump (see
// `crate::coverage::dump_profile`).  Walks `__llvm_prf_cnts` /
// `__llvm_prf_data` / `__llvm_prf_names` plus the static `__llvm_covmap` /
// `__llvm_covfun` regions and emits hex `[COV-CHUNK]` lines plus a
// `[COV-SUMMARY]` JSON line on the serial port.  Returns the region-level
// summary as a JSON envelope so the harness can confirm flush completion
// without re-grepping the serial log.
//
// Resets the once-per-boot idempotency latch first so an interactive
// caller can re-flush after additional work has executed.  Requires the
// `coverage` feature (which in turn implies the `-C instrument-coverage`
// rustflag, set by the harness).

fn op_coverage_flush(out: &mut String) {
    #[cfg(feature = "coverage")]
    {
        use core::fmt::Write;
        crate::coverage::reset();
        let (covered, total, bytes) = crate::coverage::dump_profile();
        let pct_x100 = if total == 0 { 0 } else { (covered as u64 * 10_000) / total as u64 };
        let pct_whole = pct_x100 / 100;
        let pct_frac = pct_x100 % 100;
        out.push('{');
        let _ = write!(out,
            r#""regions_covered":{},"regions_total":{},"pct":"{}.{}{}","bytes_dumped":{}"#,
            covered, total, pct_whole,
            if pct_frac < 10 { "0" } else { "" }, pct_frac, bytes,
        );
        out.push_str(r#","note":"raw chunks in serial log [COV-CHUNK] lines""#);
        out.push('}');
    }
    #[cfg(not(feature = "coverage"))]
    {
        out.push_str(r#"{"error":"coverage-flush requires coverage feature"}"#);
    }
}

// ── poll-revents ─────────────────────────────────────────────────────────────
//
// Request: {"op":"poll-revents","pid":N[,"fd":F]}.
//
// Evaluates the kernel's poll(2) readiness verdict for one PID's descriptors
// via the same `crate::syscall::poll_revents()` path the poll/select/epoll
// syscalls use, asking for POLLIN|POLLOUT (0x0005).  With a "fd" field, reports
// just that descriptor; without it, scans every open fd and lists those the
// kernel currently considers readable (revents & POLLIN).  This is the decisive
// discriminator for a "data is queued on the socket but the poller never wakes"
// stall: it answers "does the kernel itself report this fd as POLLIN-ready?"
// independent of whether the userspace poll() set actually includes the fd.
//   revents bits (poll(2)): POLLIN=0x1, POLLOUT=0x4, POLLERR=0x8,
//   POLLHUP=0x10, POLLRDHUP=0x2000 (Linux ABI).
fn op_poll_revents(req: &str, out: &mut String) {
    use core::fmt::Write;

    let pid: u64 = match extract_field(req, "pid").and_then(|s| parse_u64(&s)) {
        Some(v) => v,
        None => { out.push_str(r#"{"error":"missing or bad 'pid'"}"#); return; }
    };
    let one_fd: Option<usize> =
        extract_field(req, "fd").and_then(|s| parse_u64(&s)).map(|v| v as usize);

    // POLLIN | POLLOUT — ask for the read+write readiness the IPC poll loops use.
    const REQ_EVENTS: u16 = 0x0001 | 0x0004;

    // Snapshot the set of open fd indices first (brief PROCESS_TABLE hold), then
    // evaluate readiness OUTSIDE the table lock — `poll_revents` re-locks
    // PROCESS_TABLE internally, so holding it here would deadlock.
    let fds: Option<Vec<usize>> = match try_lock_brief(&PROCESS_TABLE) {
        Some(g) => g.iter().find(|p| p.pid == pid).map(|p| {
            match one_fd {
                Some(f) => if p.file_descriptors.get(f).map_or(false, |e| e.is_some()) {
                    alloc::vec![f]
                } else {
                    Vec::new()
                },
                None => p.file_descriptors.iter().enumerate()
                    .filter_map(|(i, e)| e.as_ref().map(|_| i))
                    .collect(),
            }
        }),
        None => { out.push_str(r#"{"error":"PROCESS_TABLE busy"}"#); return; }
    };
    let fds = match fds {
        Some(v) => v,
        None => { let _ = write!(out, r#"{{"error":"no pid {}"}}"#, pid); return; }
    };

    out.push('{');
    let _ = write!(out, r#""pid":{},"#, pid);
    out.push_str(r#""fds":["#);
    let mut first = true;
    for fd in fds {
        let revents = crate::syscall::poll_revents(pid, fd, REQ_EVENTS);
        if !first { out.push(','); }
        first = false;
        let _ = write!(out,
            r#"{{"fd":{},"revents":{},"pollin":{},"pollout":{},"pollhup":{}}}"#,
            fd, revents,
            revents & 0x0001 != 0,
            revents & 0x0004 != 0,
            revents & 0x0010 != 0);
    }
    out.push_str("]}");
}

// ── proc-metrics ─────────────────────────────────────────────────────────────
//
// One-shot snapshot of the per-process activity counters maintained in
// `crate::proc::proc_metrics`.  Emits one JSON object per live PID, each
// with its syscall-category breakdown, page-fault count, disk and network
// byte totals, and a "currently inside syscall N for D ticks" flag for
// stuck-thread diagnosis.  No locks held during emission beyond a brief
// try_lock on PROCESS_TABLE for name resolution; contended PROCESS_TABLE
// causes the names to be reported as "?".

fn op_proc_metrics(out: &mut String) {
    use core::fmt::Write;
    let tick_now = crate::arch::x86_64::irq::get_ticks();

    // Best-effort name lookup.  Mirror try_lock_brief discipline used by
    // op_proc_list — never block the kdb listener thread.
    let names: Vec<(u64, String)> = match try_lock_brief(&PROCESS_TABLE) {
        Some(g) => g.iter().map(|p| (p.pid, proc_name_string(&p.name))).collect(),
        None => Vec::new(),
    };

    out.push('{');
    let _ = write!(out, r#""tick":{},"procs":["#, tick_now);
    let mut first = true;
    for pid in crate::proc::proc_metrics::live_pids() {
        let Some(s) = crate::proc::proc_metrics::snapshot(pid) else { continue };
        if !first { out.push(','); }
        first = false;
        let name = names.iter().find(|(p, _)| *p == pid)
            .map(|(_, n)| n.as_str()).unwrap_or("?");
        out.push('{');
        j_kv(out, "pid", &alloc::format!("{}", pid));
        j_kv_str(out, "name", name);
        j_kv(out, "sc_total", &alloc::format!("{}", s.sc_total));
        j_kv(out, "sc_vm",    &alloc::format!("{}", s.sc_vm));
        j_kv(out, "sc_file",  &alloc::format!("{}", s.sc_file));
        j_kv(out, "sc_net",   &alloc::format!("{}", s.sc_net));
        j_kv(out, "sc_sync",  &alloc::format!("{}", s.sc_sync));
        j_kv(out, "sc_proc",  &alloc::format!("{}", s.sc_proc));
        j_kv(out, "sc_signal",&alloc::format!("{}", s.sc_signal));
        j_kv(out, "sc_other", &alloc::format!("{}", s.sc_other));
        j_kv(out, "pf_count", &alloc::format!("{}", s.pf_count));
        j_kv(out, "disk_r_bytes", &alloc::format!("{}", s.disk_r_bytes));
        j_kv(out, "disk_w_bytes", &alloc::format!("{}", s.disk_w_bytes));
        j_kv(out, "net_r_bytes",  &alloc::format!("{}", s.net_r_bytes));
        j_kv(out, "net_w_bytes",  &alloc::format!("{}", s.net_w_bytes));
        // Currently-running syscall: -1 means none.  Compute the
        // tick-delta so the caller can decide what counts as "stuck"
        // without rounding decisions baked into the kernel.
        j_kv(out, "last_sc_nr", &alloc::format!("{}", s.last_sc_nr));
        let delta = if s.last_sc_nr >= 0 {
            tick_now.saturating_sub(s.last_sc_tick)
        } else { 0 };
        j_kv(out, "in_sc_ticks", &alloc::format!("{}", delta));
        j_trim_comma(out);
        out.push('}');
    }
    out.push(']');
    out.push('}');
}

// ── thread-park-audit ────────────────────────────────────────────────────────
//
// PNG-1 plateau characterisation (post-W215-closure).  For every thread
// currently in the THREAD_TABLE that is not Dead, emit:
//
//   { tid, pid, name, state, rip, rsp, wake_tick,
//     syscall: { nr, name, arg0 } | null,
//     blocked_for_ticks,                 // tick_now - last_syscall_tick
//     wait: { kind, ... }                // classification (best effort)
//   }
//
// `kind` is one of:
//   "futex"          → uaddr resolved from FUTEX_WAITERS reverse lookup
//   "poll-bell"      → last syscall was poll/ppoll/epoll_wait/select; the
//                      thread is parked on the global POLL_BELL.  arg0 is
//                      the fd-array pointer (poll) or epfd (epoll_wait).
//   "vfork-complete" → vfork_parent_tid is set; child waits for execve/exit
//   "sleep"          → sleeping with finite wake_tick (nanosleep/clock_nanosleep)
//   "fd-blocked"     → last syscall is a blocking fd op (read/recvmsg/sendmsg/
//                      pread/preadv/accept) and the thread is Blocked.  arg0
//                      is the fd; we resolve the FD via the process table and
//                      walk the unix-socket snapshot to find the peer.
//   "unknown"        → no classifier matched.
//
// Per-thread `last_syscall_*` comes from `proc::sample::read_sample(tid)`
// (firefox-test only; populated on every syscall dispatch entry).  For
// non-firefox-test builds the syscall field is `null` and `wait.kind` is
// always "unknown" — the op stays usable but degraded.
//
// Optional pid filter: `{"op":"thread-park-audit","pid":N}`.  pid=0 (or
// omitted) means all PIDs.
//
// References:
//   - POSIX `poll(2)` and `epoll_wait(2)` for wait semantics
//   - `man 2 futex` for FUTEX_WAIT registration
//   - Intel SDM Vol 3A §8.2.3 (total store order for in-cache writes)
//     justifies the read-back order in `sample::read_sample`.

// Linux syscall numbers we classify (x86_64).  Kept inline rather than
// imported from subsys/linux/syscall.rs to avoid a kdb→subsys dependency
// for what is, fundamentally, a diagnostic-side lookup table.
const NR_READ:        u64 = 0;
const NR_POLL:        u64 = 7;
const NR_PREAD64:     u64 = 17;
const NR_PREADV:      u64 = 295;
const NR_NANOSLEEP:   u64 = 35;
const NR_CLOCK_NANOSLEEP: u64 = 230;
const NR_RECVMSG:     u64 = 47;
const NR_SENDMSG:     u64 = 46;
const NR_RECVFROM:    u64 = 45;
const NR_ACCEPT:      u64 = 43;
const NR_ACCEPT4:     u64 = 288;
const NR_SELECT:      u64 = 23;
const NR_PSELECT6:    u64 = 270;
const NR_PPOLL:       u64 = 271;
const NR_EPOLL_WAIT:  u64 = 232;
const NR_EPOLL_PWAIT: u64 = 281;
const NR_FUTEX:       u64 = 202;

fn is_poll_family(nr: u64) -> bool {
    matches!(nr, NR_POLL | NR_PPOLL | NR_SELECT | NR_PSELECT6
                | NR_EPOLL_WAIT | NR_EPOLL_PWAIT)
}
fn is_fd_blocking(nr: u64) -> bool {
    matches!(nr, NR_READ | NR_PREAD64 | NR_PREADV | NR_RECVMSG
                | NR_RECVFROM | NR_ACCEPT | NR_ACCEPT4 | NR_SENDMSG)
}

fn op_thread_park_audit(req: &str, out: &mut String) {
    use core::fmt::Write;

    let pid_filter: u64 = extract_field(req, "pid")
        .and_then(|s| parse_u64(&s))
        .unwrap_or(0);

    let tick_now = crate::arch::x86_64::irq::get_ticks();
    let sc_total = crate::syscall::syscall_count();

    // ── Stage 1: snapshot all live threads of interest ─────────────────
    struct ThreadSnap {
        tid: u64, pid: u64, name: String,
        state: &'static str, entry_rip: u64, rsp: u64,
        wake_tick: u64, clear_child_tid: u64,
        vfork_parent_tid: Option<u64>,
    }
    let thread_snaps: Vec<ThreadSnap> = match try_lock_brief(&THREAD_TABLE) {
        Some(tt) => tt.iter()
            .filter(|t| t.state != crate::proc::ThreadState::Dead)
            .filter(|t| pid_filter == 0 || t.pid == pid_filter)
            .map(|t| ThreadSnap {
                tid: t.tid, pid: t.pid,
                name: {
                    let end = t.name.iter().position(|&b| b == 0).unwrap_or(t.name.len());
                    String::from_utf8_lossy(&t.name[..end]).into_owned()
                },
                state: thread_state_str(t.state),
                entry_rip: t.user_entry_rip, rsp: t.context.rsp,
                wake_tick: t.wake_tick,
                clear_child_tid: t.clear_child_tid,
                vfork_parent_tid: t.vfork_parent_tid,
            }).collect(),
        None => {
            out.push_str(r#"{"busy":"THREAD_TABLE held","threads":[]}"#);
            return;
        }
    };

    // ── Stage 2: snapshot the per-PID process names + FD tables ────────
    // Only fetch what we need for "fd-blocked" peer resolution.  Note we
    // intentionally do NOT honour `pid_filter` here — when one thread is
    // blocked on a socket, its peer process can be ANY pid, and the FD
    // tables of those peer pids are needed to render the (peer_pid, peer_fd)
    // tuple even when the caller filtered the thread view to one pid.
    // Tuple shape: (pid, proc_name, fds[(fd, file_type, inode, flags, path)]).
    let proc_snaps: Vec<ProcFdRow> = match try_lock_brief(&PROCESS_TABLE) {
        Some(pt) => pt.iter()
            .map(|p| (
                p.pid,
                proc_name_string(&p.name),
                p.file_descriptors.iter().enumerate()
                    .filter_map(|(i, fd)| fd.as_ref().map(|fd|
                        (i, fd.file_type, fd.inode, fd.flags, fd.open_path.clone())))
                    .collect::<Vec<_>>(),
            )).collect(),
        None => Vec::new(), // best-effort: emit per-thread state without FD resolution
    };

    // ── Stage 3: snapshot FUTEX waiters (for futex reverse-lookup) ─────
    // Map tid → (pid, uaddr) so the per-thread emit can answer "this TID
    // is waiting on which futex".  Best-effort: a long-held FUTEX_WAITERS
    // (e.g. mid-FUTEX_WAKE across a busy contentproc) is common under
    // Firefox load; rather than block the kdb listener thread we fall
    // back to the empty map so "wait.kind":"futex" classification is
    // skipped on contention but every other field still surfaces.  The
    // try_lock_brief discipline matches op_proc_list / op_fd_map.
    let mut tid_to_futex: alloc::collections::BTreeMap<u64, (u64, u64)> =
        alloc::collections::BTreeMap::new();
    let futex_busy = match try_lock_brief(&crate::syscall::FUTEX_WAITERS) {
        Some(waiters) => {
            use crate::syscall::FutexKey;
            for (k, tids) in waiters.iter() {
                // Map the key to the diagnostic `(pid, uaddr)` pair the JSON
                // shape expects.  A process-SHARED futex has no single owning
                // pid; surface it as `(u64::MAX, byte_off)` so the reverse
                // lookup still records the waiter without inventing a pid.
                let (pid_k, uaddr) = match k {
                    FutexKey::Private(p, u) => (*p, *u),
                    FutexKey::Shared { byte_off, .. } => (u64::MAX, *byte_off),
                };
                for tid in tids {
                    tid_to_futex.insert(*tid, (pid_k, uaddr));
                }
            }
            false
        }
        None => true,
    };

    // ── Stage 4: snapshot unix sockets (for fd-blocked peer lookup) ────
    let sock_snaps = crate::net::unix::snapshot_all();

    // ── Stage 5: emit JSON ─────────────────────────────────────────────
    out.push('{');
    let _ = write!(out, r#""tick":{},"sc_total":{},"pid_filter":{},"#,
                   tick_now, sc_total, pid_filter);
    if futex_busy {
        out.push_str(r#""futex_waiters_busy":true,"#);
    }
    out.push_str(r#""threads":["#);

    // Emission budget: each thread renders ~250-450 B of JSON; cap at
    // 24 KB so the full envelope (including overhead) clears the 32 KB
    // kernel-side MAX_RESP_BYTES truncation threshold.  If we hit the cap
    // we emit `truncated_at_thread:N` and stop — the caller can re-issue
    // with `--pid N` for a narrower view.
    //
    // Additionally, every per-thread record is mirrored to the serial log
    // as `[THREAD-PARK]` so the harness can recover from a TCP send-buffer
    // stall (rare but observed: the in-kernel TCP stack drains the
    // response over multiple pump ticks via tcp_timer_tick, and a kdb
    // response > 1 MSS may not fully arrive before the host's recv
    // deadline expires).  Serial is unconditionally drained on each
    // emission, so the lines reach the harness even if the JSON envelope
    // is truncated mid-flight.  The serial format mirrors the JSON shape
    // 1:1 so the harness can synthesise the response from serial alone.
    const EMIT_BUDGET_BYTES: usize = 24 * 1024;
    let mut first = true;
    let mut emitted = 0usize;
    let mut truncated_at: Option<u64> = None;
    let audit_id = tick_now;  // marker so harness can scope its parse
    crate::serial_println!("[THREAD-PARK] BEGIN audit_id={} tick={} sc_total={} pid_filter={} threads={}",
                            audit_id, tick_now, sc_total, pid_filter, thread_snaps.len());
    for ts in &thread_snaps {
        if out.len() > EMIT_BUDGET_BYTES {
            truncated_at = Some(ts.tid);
            // Still emit the remaining threads to serial for harness recovery.
            // (we just skip pushing into `out`).
        }
        let in_budget = out.len() <= EMIT_BUDGET_BYTES;
        if in_budget {
            if !first { out.push(','); }
            first = false;
            emitted += 1;
        }

        // Per-thread sample lookup.  Returns `None` when the writer (gated
        // behind `firefox-test`) has never fired; the downstream
        // classifier is correct under either case.
        let sample = crate::proc::sample::read_sample(ts.tid);

        // Resolve owning process name (lookup in proc_snaps).
        let proc_name = proc_snaps.iter().find(|(p, _, _)| *p == ts.pid)
            .map(|(_, n, _)| n.as_str()).unwrap_or("?");

        let (nr_opt, arg0_opt, blocked_for) = match &sample {
            Some(s) => (Some(s.last_syscall_nr), Some(s.last_syscall_arg0),
                        tick_now.saturating_sub(s.last_syscall_tick)),
            None => (None, None, 0u64),
        };

        // Live user RIP/RBP from per-tick sampler.  Falls back to
        // entry_rip so the `rip` key is never null for callers that
        // already parse it.
        let (live_rip, live_rbp) = match &sample {
            Some(s) if s.last_user_rip != 0 => (s.last_user_rip, s.last_user_rbp),
            _ => (ts.entry_rip, 0u64),
        };

        // ── JSON emission (budget-gated) ─────────────────────────────
        if in_budget {
            out.push('{');
            j_kv(out, "tid", &alloc::format!("{}", ts.tid));
            j_kv(out, "pid", &alloc::format!("{}", ts.pid));
            j_kv_str(out, "proc_name", proc_name);
            j_kv_str(out, "thread_name", &ts.name);
            j_kv_str(out, "state", ts.state);
            j_str(out, "rip"); out.push(':'); j_hex(out, live_rip); out.push(',');
            j_str(out, "entry_rip"); out.push(':'); j_hex(out, ts.entry_rip); out.push(',');
            j_str(out, "rbp"); out.push(':'); j_hex(out, live_rbp); out.push(',');
            j_str(out, "rsp"); out.push(':'); j_hex(out, ts.rsp); out.push(',');
            let _ = write!(out, r#""wake_tick":{},"#, ts.wake_tick);
            let _ = write!(out, r#""blocked_for_ticks":{},"#, blocked_for);
            match (nr_opt, arg0_opt) {
                (Some(nr), Some(arg0)) => {
                    out.push_str(r#""syscall":{"#);
                    let _ = write!(out, r#""nr":{},"#, nr);
                    j_kv_str(out, "name", crate::perf::linux_syscall_name(nr));
                    j_str(out, "arg0"); out.push(':'); j_hex(out, arg0);
                    out.push_str("},");
                }
                _ => {
                    out.push_str(r#""syscall":null,"#);
                }
            }
            out.push_str(r#""wait":"#);
            emit_wait_classification(
                out,
                ts.tid, ts.pid, ts.wake_tick,
                ts.clear_child_tid, ts.vfork_parent_tid,
                sample.as_ref(),
                &tid_to_futex, &proc_snaps, &sock_snaps,
            );
            out.push('}');
        }

        // ── Serial-log mirror (always emitted; harness fallback) ────
        // Single line per thread.  Keys are stable so the harness regex
        // is also stable.  Wait classification is rendered as a compact
        // `wait=KIND[,kv]*` suffix; the harness parses it into the same
        // shape it would synthesise from the JSON path.
        let (sn, sa0): (i64, u64) = match (nr_opt, arg0_opt) {
            (Some(n), Some(a)) => (n as i64, a),
            _                  => (-1, 0),
        };
        let mut wait_buf = String::with_capacity(96);
        render_wait_compact(&mut wait_buf,
                            ts.tid, ts.pid, ts.wake_tick,
                            ts.clear_child_tid, ts.vfork_parent_tid,
                            sample.as_ref(),
                            &tid_to_futex, &proc_snaps, &sock_snaps);
        crate::serial_println!(
            "[THREAD-PARK] id={} tid={} pid={} pname={} tname={} state={} \
             rip={:#x} entry_rip={:#x} rsp={:#x} wake_tick={} blocked_for={} \
             sc_nr={} sc_arg0={:#x} {}",
            audit_id, ts.tid, ts.pid, proc_name, ts.name, ts.state,
            live_rip, ts.entry_rip, ts.rsp, ts.wake_tick, blocked_for, sn, sa0, wait_buf,
        );
    }
    crate::serial_println!("[THREAD-PARK] END audit_id={} emitted_json={} threads_total={}",
                            audit_id, emitted, thread_snaps.len());
    out.push(']');
    let _ = write!(out, r#","emitted":{}"#, emitted);
    if let Some(tid) = truncated_at {
        let _ = write!(out, r#","truncated_at_tid":{}"#, tid);
    }
    out.push('}');
}

// Concrete shape mirrored from op_thread_park_audit's local `ProcFdSnap`.
// Kept module-private; the op_thread_park_audit function builds a Vec of
// these and passes it by reference to emit_wait_classification.
type ProcFdRow = (u64, String, Vec<(usize, crate::vfs::FileType, u64, u32, String)>);


/// Emit the `"wait":{...}` object for one thread.  Best-effort classifier;
/// see the op_thread_park_audit doc-comment for the kind taxonomy.
///
/// `proc_snaps` is a parallel slice of `(pid, name, fds)` per Stage 2 of
/// op_thread_park_audit.  Passed as primitive references rather than via
/// a trait so the function-local snapshot structs can stay encapsulated.
#[allow(clippy::too_many_arguments)]
fn emit_wait_classification(
    out: &mut String,
    tid: u64,
    pid: u64,
    wake_tick: u64,
    clear_child_tid: u64,
    vfork_parent_tid: Option<u64>,
    sample: Option<&crate::proc::sample::TidSyscallSample>,
    tid_to_futex: &alloc::collections::BTreeMap<u64, (u64, u64)>,
    proc_snaps: &[ProcFdRow],
    sock_snaps: &[crate::net::unix::SocketSnap],
) {
    use core::fmt::Write;

    // 1. Futex: highest-confidence — direct reverse lookup from the
    //    kernel's wait queue.
    if let Some((futex_pid, uaddr)) = tid_to_futex.get(&tid).copied() {
        out.push('{');
        j_kv_str(out, "kind", "futex");
        let _ = write!(out, r#""pid":{},"#, futex_pid);
        j_str(out, "uaddr"); out.push(':'); j_hex(out, uaddr);
        out.push('}');
        return;
    }

    // 2. vfork-complete: child blocked until execve/exit wakes parent.
    if let Some(parent_tid) = vfork_parent_tid {
        out.push('{');
        j_kv_str(out, "kind", "vfork-complete");
        let _ = write!(out, r#""parent_tid":{}"#, parent_tid);
        out.push('}');
        return;
    }

    // 3/4/5. Sample-driven classifications (require firefox-test).
    if let Some(s) = sample {
        let nr = s.last_syscall_nr;
        let arg0 = s.last_syscall_arg0;
        if matches!(nr, NR_NANOSLEEP | NR_CLOCK_NANOSLEEP)
            && wake_tick != u64::MAX && wake_tick != 0 {
            out.push('{');
            j_kv_str(out, "kind", "sleep");
            let _ = write!(out, r#""wake_tick":{}"#, wake_tick);
            out.push('}');
            return;
        }
        if is_poll_family(nr) {
            out.push('{');
            j_kv_str(out, "kind", "poll-bell");
            let _ = write!(out, r#""nr":{},"#, nr);
            j_str(out, "arg0"); out.push(':'); j_hex(out, arg0);
            out.push('}');
            return;
        }
        if is_fd_blocking(nr) {
            // arg0 is the fd; resolve it via the process FD table.
            let fd = arg0 as usize;
            let resolved = proc_snaps.iter().find(|(p, _, _)| *p == pid)
                .and_then(|(_, _, fds)| fds.iter()
                    .find(|(i, _, _, _, _)| *i == fd));
            out.push('{');
            j_kv_str(out, "kind", "fd-blocked");
            let _ = write!(out, r#""nr":{},"#, nr);
            let _ = write!(out, r#""fd":{},"#, fd);
            match resolved {
                Some((_, ft, inode, flags, path)) => {
                    let ft_str = file_type_str(*ft);
                    j_kv_str(out, "fd_kind", ft_str);
                    let _ = write!(out, r#""inode":{},"#, inode);
                    // For sockets: resolve peer via sock_snaps.
                    if matches!(ft, crate::vfs::FileType::Socket) {
                        let peer_socket_id = sock_snaps.iter()
                            .find(|s| s.id == *inode)
                            .map(|s| s.peer_id)
                            .unwrap_or(u64::MAX);
                        if peer_socket_id == u64::MAX {
                            j_kv_str(out, "peer_pid", "none");
                            j_kv_str(out, "peer_fd",  "none");
                        } else {
                            // Find which (pid, fd) owns peer_socket_id.
                            let owner = proc_snaps.iter().find_map(|(ppid, _, fds)|
                                fds.iter().find(|(_, ft2, inode2, _, _)|
                                    matches!(ft2, crate::vfs::FileType::Socket)
                                    && *inode2 == peer_socket_id)
                                .map(|(fd2, _, _, _, _)| (*ppid, *fd2)));
                            match owner {
                                Some((ppid, pfd)) => {
                                    let _ = write!(out, r#""peer_pid":{},"peer_fd":{},"#, ppid, pfd);
                                }
                                None => {
                                    j_kv_str(out, "peer_pid", "unowned");
                                    j_kv_str(out, "peer_fd",  "unowned");
                                }
                            }
                        }
                    }
                    // For pipes: find the opposite end.
                    if matches!(ft, crate::vfs::FileType::Pipe) {
                        let is_write = flags & 1 == 1;
                        let peer = proc_snaps.iter().find_map(|(ppid, _, fds)|
                            fds.iter().find(|(_, ft2, inode2, fl, _)|
                                matches!(ft2, crate::vfs::FileType::Pipe)
                                && *inode2 == *inode
                                && (fl & 1 == 1) != is_write)
                            .map(|(fd2, _, _, _, _)| (*ppid, *fd2)));
                        match peer {
                            Some((ppid, pfd)) => {
                                let _ = write!(out, r#""peer_pid":{},"peer_fd":{},"#, ppid, pfd);
                            }
                            None => {
                                j_kv_str(out, "peer_pid", "none");
                                j_kv_str(out, "peer_fd",  "none");
                            }
                        }
                    }
                    if !path.is_empty() { j_kv_str(out, "path", path); }
                }
                None => {
                    j_kv_str(out, "fd_kind", "unresolved");
                }
            }
            j_trim_comma(out);
            out.push('}');
            return;
        }
        if nr == NR_FUTEX {
            // FUTEX waiter without a queue entry — likely either FUTEX_WAKE
            // beat us out of the wait queue (and we just haven't returned
            // yet) or a non-WAIT futex op.  Surface arg0 (uaddr) so the
            // caller can still cross-reference.
            out.push('{');
            j_kv_str(out, "kind", "futex-other");
            j_str(out, "uaddr"); out.push(':'); j_hex(out, arg0);
            out.push('}');
            return;
        }
    }

    // 6. Catch-all: state may still be informative even without a syscall.
    out.push('{');
    j_kv_str(out, "kind", "unknown");
    if clear_child_tid != 0 {
        // Newly-spawned thread or one that's about to exit cleanly.
        j_str(out, "clear_child_tid"); out.push(':'); j_hex(out, clear_child_tid);
        out.push(',');
    }
    j_trim_comma(out);
    out.push('}');
}

/// Render a one-line `wait=KIND[,kv]*` description for the serial mirror.
/// Mirrors `emit_wait_classification`'s taxonomy but in a flat suffix shape
/// the harness can `wait=(.*)$` capture.  Same classifier inputs.
#[allow(clippy::too_many_arguments)]
fn render_wait_compact(
    out: &mut String,
    tid: u64,
    pid: u64,
    wake_tick: u64,
    clear_child_tid: u64,
    vfork_parent_tid: Option<u64>,
    sample: Option<&crate::proc::sample::TidSyscallSample>,
    tid_to_futex: &alloc::collections::BTreeMap<u64, (u64, u64)>,
    proc_snaps: &[ProcFdRow],
    sock_snaps: &[crate::net::unix::SocketSnap],
) {
    use core::fmt::Write;
    if let Some((fp, uaddr)) = tid_to_futex.get(&tid).copied() {
        let _ = write!(out, "wait=futex,fpid={},uaddr={:#x}", fp, uaddr);
        return;
    }
    if let Some(parent_tid) = vfork_parent_tid {
        let _ = write!(out, "wait=vfork-complete,parent_tid={}", parent_tid);
        return;
    }
    if let Some(s) = sample {
        let nr = s.last_syscall_nr;
        let arg0 = s.last_syscall_arg0;
        if matches!(nr, NR_NANOSLEEP | NR_CLOCK_NANOSLEEP)
            && wake_tick != u64::MAX && wake_tick != 0 {
            let _ = write!(out, "wait=sleep,wake_tick={}", wake_tick);
            return;
        }
        if is_poll_family(nr) {
            let _ = write!(out, "wait=poll-bell,nr={},arg0={:#x}", nr, arg0);
            return;
        }
        if is_fd_blocking(nr) {
            let fd = arg0 as usize;
            let resolved = proc_snaps.iter().find(|(p, _, _)| *p == pid)
                .and_then(|(_, _, fds)| fds.iter()
                    .find(|(i, _, _, _, _)| *i == fd));
            let _ = write!(out, "wait=fd-blocked,nr={},fd={}", nr, fd);
            match resolved {
                Some((_, ft, inode, flags, _path)) => {
                    let _ = write!(out, ",fd_kind={},inode={}", file_type_str(*ft), inode);
                    if matches!(ft, crate::vfs::FileType::Socket) {
                        let peer_socket_id = sock_snaps.iter()
                            .find(|s| s.id == *inode)
                            .map(|s| s.peer_id).unwrap_or(u64::MAX);
                        if peer_socket_id == u64::MAX {
                            out.push_str(",peer=none");
                        } else {
                            let owner = proc_snaps.iter().find_map(|(ppid, _, fds)|
                                fds.iter().find(|(_, ft2, inode2, _, _)|
                                    matches!(ft2, crate::vfs::FileType::Socket)
                                    && *inode2 == peer_socket_id)
                                .map(|(fd2, _, _, _, _)| (*ppid, *fd2)));
                            match owner {
                                Some((pp, pf)) => { let _ = write!(out, ",peer_pid={},peer_fd={}", pp, pf); }
                                None => out.push_str(",peer=unowned"),
                            }
                        }
                    } else if matches!(ft, crate::vfs::FileType::Pipe) {
                        let is_write = flags & 1 == 1;
                        let peer = proc_snaps.iter().find_map(|(ppid, _, fds)|
                            fds.iter().find(|(_, ft2, inode2, fl, _)|
                                matches!(ft2, crate::vfs::FileType::Pipe)
                                && *inode2 == *inode
                                && (fl & 1 == 1) != is_write)
                            .map(|(fd2, _, _, _, _)| (*ppid, *fd2)));
                        match peer {
                            Some((pp, pf)) => { let _ = write!(out, ",peer_pid={},peer_fd={}", pp, pf); }
                            None => out.push_str(",peer=none"),
                        }
                    }
                }
                None => out.push_str(",fd_kind=unresolved"),
            }
            return;
        }
        if nr == NR_FUTEX {
            let _ = write!(out, "wait=futex-other,uaddr={:#x}", arg0);
            return;
        }
    }
    out.push_str("wait=unknown");
    if clear_child_tid != 0 {
        let _ = write!(out, ",clear_child_tid={:#x}", clear_child_tid);
    }
}

// ── rip-trace ────────────────────────────────────────────────────────────────
//
// Userspace RIP sampler for one TID over a fixed time window.  Polls the
// per-TID `proc::sample` slot every kernel tick (~10 ms at the 100 Hz
// scheduler cadence) for the requested wall-clock window, walks the
// user-mode frame-pointer chain on each fresh sample, and returns a
// top-N histogram of RIPs and unique RBP-chain prefixes.
//
// Motivation: kdb `proc-list` / `proc` / `thread-park-audit` emit the
// frozen `user_entry_rip` (set once at thread creation), which is
// misleading for diagnosing userspace plateaux — a long-running thread
// looks parked at ld.so's trampoline forever even when it is actively
// looping inside libxul.  This op samples the *current* user RIP across
// the window so the host can decide which library / function is
// responsible without an external profiler.
//
// Request shape:
//   { "op": "rip-trace", "tid": N, "ms": N }
//
// Response shape:
//   { "tid": N, "pid": N, "ms_requested": N, "samples": N,
//     "errors": { "rbp_fault": N, "no_sample": N, "torn_read": N,
//                 "rsp_scan_faults": N },
//     "top_rips": [ { "rip": "0x...", "count": N, "page": "0x..." }, ... ],
//     "top_rbp_chains":
//        [ { "chain": ["0x..", "0x..", "0x.."], "count": N }, ... ],
//     "top_rsp_scan":
//        [ { "addr": "0x..", "count": N, "page": "0x..." }, ... ] }
//
// `top_rsp_scan` lists user-stack words above RSP that look like
// canonical user-code return addresses, ranked by frequency across the
// sampling window.  This is the fallback for `-fomit-frame-pointer`
// binaries (firefox-bin/libxul) where the RBP chain terminates at depth
// 1 because RBP is used as a general-purpose register; addresses that
// occur in N out of N samples are almost certainly real saved-RIPs from
// frames that the RBP walker could not reach.
//
// The op MUST NOT pause or freeze the target TID — it is purely
// observational.  It is also bounded in cost: the histogram tables are
// fixed-capacity and trimmed before emit, and the sample loop yields
// one tick per iteration via `proc::sleep_ticks(1)` (the same cadence
// the kdb pump thread itself uses between TCP polls).
//
// Page-table walks of foreign user memory use the target process's
// CR3 (loaded once at op entry) via the same software-walk path as
// `proc::sample::maybe_sample` — see Intel SDM Vol 3A §4.5 for the
// 4-level paging walk and §8.2.3 for the same-cache-line TSO guarantee
// that lets us read RIP/RBP/seq from the slot without locking.
const RIP_TRACE_MAX_MS: u64 = 5_000;
const RIP_TRACE_TOP_N: usize = 10;
const RIP_TRACE_RBP_MAX_FRAMES: usize = 10;
/// Words above RSP to scan for return-address candidates.  The 96-word
/// (768 B) window picks up the typical 10-15 frames of an active call
/// stack without inflating cost — each word is one software page-walk
/// look-up via `proc::sample::read_user_u64_at`.
const RIP_TRACE_RSP_SCAN_WORDS: u64 = 96;

fn op_rip_trace(req: &str, out: &mut String) {
    use core::fmt::Write;

    let tid = match extract_field(req, "tid").and_then(|s| parse_u64(&s)) {
        Some(t) if t != 0 => t,
        _ => { out.push_str(r#"{"error":"missing or invalid 'tid'"}"#); return; }
    };
    let ms = extract_field(req, "ms")
        .and_then(|s| parse_u64(&s))
        .unwrap_or(1000);
    let ms = ms.clamp(1, RIP_TRACE_MAX_MS);

    // Resolve the owning PID and its CR3 up front.  If the thread is
    // gone by the time we ask, return a deterministic error rather
    // than silently producing an empty histogram.
    let pid = {
        let threads = match try_lock_brief(&THREAD_TABLE) {
            Some(g) => g,
            None => { out.push_str(r#"{"busy":"THREAD_TABLE held"}"#); return; }
        };
        match threads.iter().find(|t| t.tid == tid) {
            Some(t) => t.pid,
            None => {
                let _ = write!(out,
                    r#"{{"error":"tid {} not found"}}"#, tid);
                return;
            }
        }
    };
    let cr3 = match crate::proc::get_process_cr3(pid) {
        Some(c) => c,
        None => {
            let _ = write!(out, r#"{{"error":"pid {} has no cr3"}}"#, pid);
            return;
        }
    };

    // ── Sampling loop ───────────────────────────────────────────────
    //
    // Each iteration: sleep 1 tick, then read the slot's (rip, rbp,
    // seq) triple.  Only count a sample if `seq` advanced since the
    // previous observation — otherwise the kernel hasn't produced a
    // new Ring-3 tick for this TID (either the thread was off-CPU or
    // in kernel mode the whole interval) and we'd otherwise inflate
    // the histogram by repeating the same RIP.
    let ticks_to_run = (ms.saturating_add(9) / 10).max(1);  // 10 ms/tick
    let mut last_seq: u64 = 0;
    let mut samples: u64 = 0;
    let mut errors_no_sample: u64 = 0;
    let mut errors_rbp_fault: u64 = 0;
    // `errors_torn_read` is reserved for future extension when the
    // sampler exposes a "writer was mid-update" channel; today
    // `read_user_rip` collapses that case to None and we count it as
    // a no_sample tick.  Emitted as 0 to keep the JSON schema stable
    // for future-proofed callers.
    let errors_torn_read: u64 = 0;

    // Small bounded histograms.  RIP buckets keyed by full RIP (we
    // don't bucket by page here because the response includes the
    // page for the caller anyway).  RBP chain keyed by tuple-encoded
    // string (cheap; max RIP_TRACE_RBP_MAX_FRAMES frames).
    let mut rip_hist: alloc::collections::BTreeMap<u64, u64> =
        alloc::collections::BTreeMap::new();
    let mut chain_hist:
        alloc::collections::BTreeMap<alloc::vec::Vec<u64>, u64> =
        alloc::collections::BTreeMap::new();
    // RSP-scan histogram: words found above the user RSP that look like
    // canonical user-code return addresses (canonical low-half, low bit
    // clear, > 0x10000).  Mozilla's firefox-bin/libxul build with
    // `-fomit-frame-pointer` so the RBP chain frequently terminates at
    // depth 1.  Stack-word inspection is the standard fallback in any
    // sampling profiler that lacks DWARF unwind info.
    let mut rsp_scan_hist: alloc::collections::BTreeMap<u64, u64> =
        alloc::collections::BTreeMap::new();
    let mut rsp_scan_faults: u64 = 0;

    for _ in 0..ticks_to_run {
        crate::proc::sleep_ticks(1);
        match crate::proc::sample::read_user_rip_rsp(tid) {
            None => { errors_no_sample += 1; }
            Some((_, _, _, seq)) if seq == last_seq => {
                // Same observation as last iteration — TID didn't run
                // in Ring 3 during this tick (kernel-bound, off-CPU,
                // or terminated).  Don't double-count.
                errors_no_sample += 1;
            }
            Some((rip, rbp, rsp, seq)) => {
                if rip == 0 {
                    // Slot owned by `tid` but the sampler has never
                    // observed a non-zero Ring-3 RIP — treat as a
                    // no-sample tick.
                    errors_no_sample += 1;
                    last_seq = seq;
                    continue;
                }
                last_seq = seq;
                samples += 1;
                *rip_hist.entry(rip).or_insert(0) += 1;

                // Walk the user RBP chain via the foreign CR3.  All
                // reads are software page-table walks under
                // `proc::sample::read_user_u64_at` — they cannot
                // fault.  Stop on the first unmapped slot, on a non-
                // ascending RBP (cycle / descent guard), on kernel-
                // half pointers, or on the depth cap.  Record at
                // least the head RIP even if the chain immediately
                // terminates so the caller can still see the
                // sampling distribution.
                let mut chain: alloc::vec::Vec<u64> =
                    alloc::vec::Vec::with_capacity(RIP_TRACE_RBP_MAX_FRAMES);
                chain.push(rip);
                let mut cur = rbp;
                let mut chain_faulted = false;
                for _ in 1..RIP_TRACE_RBP_MAX_FRAMES {
                    if cur == 0 || cur < 0x1000 { break; }
                    if cur >= astryx_shared::KERNEL_VIRT_BASE { break; }
                    if cur & 0x7 != 0 { break; }
                    let saved_rbp = match
                        crate::proc::sample::read_user_u64_at(cr3, cur)
                    {
                        Some(v) => v,
                        None => { chain_faulted = true; break; }
                    };
                    let saved_rip = match
                        crate::proc::sample::read_user_u64_at(cr3, cur.wrapping_add(8))
                    {
                        Some(v) => v,
                        None => { chain_faulted = true; break; }
                    };
                    chain.push(saved_rip);
                    if saved_rbp <= cur { break; }
                    cur = saved_rbp;
                }
                if chain_faulted { errors_rbp_fault += 1; }
                *chain_hist.entry(chain).or_insert(0) += 1;

                // RSP-scan fallback.  Scan up to RIP_TRACE_RSP_SCAN_WORDS
                // qwords above RSP.  Filter:
                //   - canonical user-half (< KERNEL_VIRT_BASE) and not in
                //     the kernel canonical hole
                //   - non-trivial (> 0x10000 i.e. above the unmapped first
                //     64 KiB)
                //   - even-byte alignment (return addresses are byte-
                //     aligned after `call`; we only require LSB clear
                //     because most call-site successor instructions are
                //     2-byte+ aligned in practice, but allow any byte)
                //   - the candidate's PAGE must be mapped under cr3 (we
                //     don't validate executability here — the caller's
                //     symbol-table lookup will tell us if it's code)
                //
                // A real return address may share its page with data, so
                // we cannot demand X-bit visibility from a software page
                // walk (we don't know which library's text-section pages
                // are R-X without an aux table).  This is a heuristic
                // filter, not a proof.  False positives are tolerable —
                // the caller groups by histogram count and only the most-
                // frequent candidates are meaningful.
                if rsp != 0 && rsp >= 0x1000 && rsp < astryx_shared::KERNEL_VIRT_BASE {
                    for i in 0..RIP_TRACE_RSP_SCAN_WORDS {
                        let va = rsp.wrapping_add(i * 8);
                        if va >= astryx_shared::KERNEL_VIRT_BASE { break; }
                        let w = match
                            crate::proc::sample::read_user_u64_at(cr3, va)
                        {
                            Some(v) => v,
                            None => { rsp_scan_faults += 1; break; }
                        };
                        // Canonical low-half user address?
                        if w < 0x10000 { continue; }
                        if w >= astryx_shared::KERNEL_VIRT_BASE { continue; }
                        // Bucket by full address.  Caller resolves to
                        // library/symbol via the FFTEST/mmap-so table.
                        *rsp_scan_hist.entry(w).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    // ── Rank top-N RIPs and chains ───────────────────────────────────
    let mut rip_vec: alloc::vec::Vec<(u64, u64)> =
        rip_hist.into_iter().map(|(k, v)| (k, v)).collect();
    rip_vec.sort_by(|a, b| b.1.cmp(&a.1));
    rip_vec.truncate(RIP_TRACE_TOP_N);

    let mut chain_vec: alloc::vec::Vec<(alloc::vec::Vec<u64>, u64)> =
        chain_hist.into_iter().collect();
    chain_vec.sort_by(|a, b| b.1.cmp(&a.1));
    chain_vec.truncate(RIP_TRACE_TOP_N);

    let mut rsp_scan_vec: alloc::vec::Vec<(u64, u64)> =
        rsp_scan_hist.into_iter().collect();
    rsp_scan_vec.sort_by(|a, b| b.1.cmp(&a.1));
    rsp_scan_vec.truncate(RIP_TRACE_TOP_N * 2);  // wider window — caller filters by lib

    // ── Emit response JSON ───────────────────────────────────────────
    out.push('{');
    let _ = write!(out, r#""tid":{},"pid":{},"ms_requested":{},"#, tid, pid, ms);
    let _ = write!(out, r#""ticks_polled":{},"samples":{},"#, ticks_to_run, samples);
    out.push_str(r#""errors":{"#);
    let _ = write!(out, r#""rbp_fault":{},"no_sample":{},"torn_read":{},"rsp_scan_faults":{}"#,
                   errors_rbp_fault, errors_no_sample, errors_torn_read,
                   rsp_scan_faults);
    out.push_str("},");
    out.push_str(r#""top_rips":["#);
    for (i, (rip, count)) in rip_vec.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_str(out, "rip"); out.push(':'); j_hex(out, *rip); out.push(',');
        let _ = write!(out, r#""count":{},"#, count);
        j_str(out, "page"); out.push(':'); j_hex(out, *rip & !0xFFFu64);
        out.push('}');
    }
    out.push_str("],");
    out.push_str(r#""top_rbp_chains":["#);
    for (i, (chain, count)) in chain_vec.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        out.push_str(r#""chain":["#);
        for (j, addr) in chain.iter().enumerate() {
            if j > 0 { out.push(','); }
            j_hex(out, *addr);
        }
        out.push_str("],");
        let _ = write!(out, r#""count":{}"#, count);
        out.push('}');
    }
    out.push_str("],");
    out.push_str(r#""top_rsp_scan":["#);
    for (i, (addr, count)) in rsp_scan_vec.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_str(out, "addr"); out.push(':'); j_hex(out, *addr); out.push(',');
        let _ = write!(out, r#""count":{},"#, count);
        j_str(out, "page"); out.push(':'); j_hex(out, *addr & !0xFFFu64);
        out.push('}');
    }
    out.push_str("]}");

    // Mirror a one-line summary to serial so the harness has a
    // fallback path even if the JSON arm is truncated.
    crate::serial_println!(
        "[RIP-TRACE] tid={} pid={} cr3={:#x} ms={} samples={} no_sample={} \
         rbp_fault={} top_rip={:#x} top_rip_count={}",
        tid, pid, cr3, ms, samples,
        errors_no_sample, errors_rbp_fault,
        rip_vec.first().map(|(r, _)| *r).unwrap_or(0),
        rip_vec.first().map(|(_, c)| *c).unwrap_or(0),
    );
}

// ── futex-ghost-hist ─────────────────────────────────────────────────────────
//
// History-based FUTEX_WAKE_GHOST diagnostic snapshot.  Returns the
// running counters (total_wakes, woken_zero, hist_hits, waits_recorded)
// and the full per-offset histogram, then emits a `[GHOST_HIST_SUMMARY]`
// block to serial so the harness can pick it up either way.
//
// Request shape:
//   { "op": "futex-ghost-hist" }
//   { "op": "futex-ghost-hist", "enable": true }    // turn on tracking
//   { "op": "futex-ghost-hist", "enable": false }   // turn off
//   { "op": "futex-ghost-hist", "reset": true }     // reset counters + ring
//
// Response shape:
//   { "enabled": bool, "total_wakes": N, "woken_zero": N, "hist_hits": N,
//     "waits_recorded": N,
//     "offsets": [ { "off": N, "count": N }, ... ],   // non-zero buckets
//     "other": N }
//
// The diagnostic state lives in `subsys::linux::syscall::ghost_hist`;
// this op is the only structured way to read it back without scraping
// the serial transcript.  The synchronous summary emission is
// idempotent — calling it multiple times just refreshes the line.
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
fn op_futex_ghost_hist(req: &str, out: &mut String) {
    use core::fmt::Write;
    use core::sync::atomic::Ordering;
    use crate::subsys::linux::syscall::ghost_hist;

    // Process imperative flags first (enable/reset).  Each is independently
    // optional; both can be present in one call.
    if let Some(en) = extract_field(req, "enable") {
        let on = matches!(en.as_str(), "true" | "1" | "on" | "yes");
        ghost_hist::set_enabled(on);
    }
    if let Some(rs) = extract_field(req, "reset") {
        if matches!(rs.as_str(), "true" | "1" | "on" | "yes") {
            ghost_hist::reset_for_test();
        }
    }

    // Snapshot the current counters.  Reads are independent atomics so
    // we can race against a concurrent FUTEX_WAKE — the harness is
    // tolerant of small inconsistencies between fields when called mid-trial.
    let enabled = ghost_hist::is_enabled();
    let total_wakes = ghost_hist::GHOST_HIST_TOTAL_WAKES.load(Ordering::Relaxed);
    let woken_zero  = ghost_hist::GHOST_HIST_WOKEN_ZERO.load(Ordering::Relaxed);
    let hist_hits   = ghost_hist::GHOST_HIST_HITS.load(Ordering::Relaxed);
    let waits       = ghost_hist::GHOST_HIST_WAITS.load(Ordering::Relaxed);

    out.push('{');
    j_kv(out, "enabled", if enabled { "true" } else { "false" });
    j_kv(out, "total_wakes", &alloc::format!("{}", total_wakes));
    j_kv(out, "woken_zero",  &alloc::format!("{}", woken_zero));
    j_kv(out, "hist_hits",   &alloc::format!("{}", hist_hits));
    j_kv(out, "waits_recorded", &alloc::format!("{}", waits));
    j_kv(out, "window_ticks", &alloc::format!("{}", ghost_hist::HIST_WINDOW_TICKS));
    j_kv(out, "cluster_half_bytes",
         &alloc::format!("{}", ghost_hist::HIST_CLUSTER_HALF));

    // Per-offset histogram — emit ALL buckets with count > 0 so the
    // caller sees the full distribution.  Each entry is
    // {"off":N,"count":N}.  The "other" bucket (unaligned / out of
    // half-window) is emitted separately as `other`.
    out.push_str("\"offsets\":[");
    let mut first = true;
    for (i, slot) in ghost_hist::GHOST_HIST_OFFSET_COUNTS.iter().enumerate() {
        if i == ghost_hist::OTHER_BUCKET { continue; }
        let c = slot.load(Ordering::Relaxed);
        if c == 0 { continue; }
        if !first { out.push(','); }
        first = false;
        let off = ghost_hist::bucket_to_offset(i);
        let _ = write!(out, "{{\"off\":{},\"count\":{}}}", off, c);
    }
    out.push_str("],");
    j_kv(out, "other",
         &alloc::format!("{}",
                ghost_hist::GHOST_HIST_OFFSET_COUNTS[
                    ghost_hist::OTHER_BUCKET].load(Ordering::Relaxed)));
    j_trim_comma(out);
    out.push('}');

    // Mirror the human-readable summary block to serial so a harness
    // that called this op via the network has a parallel serial
    // record (kdb responses can race the serial pump under load; the
    // [GHOST_HIST_SUMMARY] line is the reliable side channel).
    ghost_hist::dump_summary();
}

#[cfg(not(any(feature = "firefox-test-core", feature = "test-mode")))]
fn op_futex_ghost_hist(_req: &str, out: &mut String) {
    out.push_str(r#"{"error":"futex-ghost-hist requires firefox-test or test-mode feature"}"#);
}

// ── cond-autopsy ────────────────────────────────────────────────────────────
//
// One-shot wake-target-vs-wait-addr report for a musl pthread_cond_t / mutex.
//
// The decisive recurring question at a condvar/mutex livelock is: "the waiter
// parks on uaddr X, but the wake targets uaddr Y — what is the delta, who
// holds the lock, and does the holder ever run?".  This op composes the
// already-tracked pieces into ONE structured object so the answer is a single
// argv call rather than five.
//
// Request: {"op":"cond-autopsy","pid":N,"addr":"0x..","half":N}  (half def 128)
//
// Response fields:
//   pid, addr, half
//   cr3                  — guest CR3 the user reads were resolved under
//   struct.hex           — `STRUCT_WORDS` u64 words read live from `addr`
//                          (LE-byte hex string), unmapped slots filled "..".
//   struct.mutex/.cond   — labelled musl field decode (both sets emitted;
//                          the caller picks the one matching the object).
//   waiters[]            — every FUTEX_WAITERS entry in [addr-half, addr+half]
//                          for `pid`: {tid, uaddr, delta, state, nr, rip}
//   recent_wakes[]       — recent FUTEX_WAKE targets in the same window
//                          (firefox-test/test-mode only): {tid, uaddr, delta}
//   holder               — inferred lock owner {owner_tid, owner_state,
//                          owner_runs, source}
//   verdict_hint         — wake-address-mismatch | held-lock-deadlock |
//                          owner-starved | true-lost-wakeup | benign-empty
//   summary              — one-line human gloss of the verdict
//
// Public references: pthread_cond_signal(3p), pthread_mutex_lock(3p),
// futex(2).  The musl struct field offsets used below match the public
// `pthread_cond_t` / `pthread_mutex_t` layout (musl exposes `__u.__vi[]` and
// the `_c_*` / `_m_*` accessor macros in its public headers).
//
// Bounded: ≤ 64 waiters, ≤ 64 wakes, 12 struct words → response < 4 KB.

/// Number of 64-bit words dumped from the cond/mutex object (96 bytes —
/// covers a full musl pthread_cond_t plus the head of an adjacent object).
const COND_STRUCT_WORDS: u64 = 12;

/// Decode the low-30-bit owner-tid field from a musl mutex `_m_lock` word.
/// musl stores the owning kernel TID in the low bits of `_m_lock`
/// (`__u.__vi[1]`, offset +4); the high bits carry FUTEX_WAITERS (0x8000_0000)
/// and the robust/owner-dead markers.
#[inline]
fn musl_mutex_owner_tid(m_lock_word: u32) -> u32 { m_lock_word & 0x3FFF_FFFF }

// Deliver a signal to a process — controlled fault-injection for live
// debugging (e.g. SIGKILL a parked content process and observe which awaited
// link its supervisor reports in the rejection).  POSIX kill(2) semantics via
// signal::kill.  Request: {"op":"proc-kill","pid":N,"sig":M} (sig default 9).
fn op_proc_kill(req: &str, out: &mut String) {
    use core::fmt::Write;
    let pid = match extract_field(req, "pid").and_then(|s| parse_u64(&s)) {
        Some(p) => p,
        None => { out.push_str(r#"{"error":"missing or bad 'pid'"}"#); return; }
    };
    let sig = extract_field(req, "sig").and_then(|s| parse_u64(&s)).unwrap_or(9).min(64) as u8;
    let ret = crate::signal::kill(pid, sig);
    let _ = write!(out, r#"{{"op":"proc-kill","pid":{},"sig":{},"ret":{}}}"#, pid, sig, ret);
}

fn op_cond_autopsy(req: &str, out: &mut String) {
    use core::fmt::Write;

    let pid = match extract_field(req, "pid").and_then(|s| parse_u64(&s)) {
        Some(p) => p,
        None => { out.push_str(r#"{"error":"missing or bad 'pid'"}"#); return; }
    };
    let addr = match extract_field(req, "addr").and_then(|s| parse_u64(&s)) {
        Some(a) => a,
        None => { out.push_str(r#"{"error":"missing or bad 'addr'"}"#); return; }
    };
    if addr >= astryx_shared::KERNEL_VIRT_BASE {
        out.push_str(r#"{"error":"addr must be a user (canonical low-half) VA"}"#);
        return;
    }
    // `half` window for waiter / wake scan.  Default 128 B (covers a full
    // pthread_cond_t with margin); clamp to a sane bound so the scan stays
    // cheap and the response stays < 4 KB.
    let half = extract_field(req, "half")
        .and_then(|s| parse_u64(&s))
        .unwrap_or(128)
        .clamp(4, 0x400);

    let cr3 = match crate::proc::get_process_cr3(pid) {
        Some(c) => c,
        None => { let _ = write!(out, r#"{{"error":"pid {} has no cr3"}}"#, pid); return; }
    };

    // ── Stage 1: live struct dump ──────────────────────────────────────
    // Read COND_STRUCT_WORDS u64s via the foreign-CR3 software walk (cannot
    // fault).  None for an unmapped slot → "..".  We keep both the raw word
    // array (for the decode below) and the hex string (for the caller).
    let mut words: [Option<u64>; COND_STRUCT_WORDS as usize] =
        [None; COND_STRUCT_WORDS as usize];
    let mut struct_hex = String::with_capacity(COND_STRUCT_WORDS as usize * 16);
    let mut any_mapped = false;
    for i in 0..COND_STRUCT_WORDS {
        let va = addr.wrapping_add(i * 8);
        match crate::proc::sample::read_user_u64_at(cr3, va) {
            Some(w) => {
                words[i as usize] = Some(w);
                any_mapped = true;
                // Little-endian byte order so the hex reads as memory bytes.
                for b in 0..8 { let _ = write!(struct_hex, "{:02x}", (w >> (b * 8)) & 0xff); }
            }
            None => { struct_hex.push_str(".."); for _ in 0..14 { struct_hex.push('.'); } }
        }
    }

    // Helper: extract a 32-bit field at byte offset `off` from the dumped
    // words (assumes `off` is 4-byte aligned and within the dump).
    let u32_at = |off: u64| -> Option<u32> {
        let wi = (off / 8) as usize;
        if wi >= words.len() { return None; }
        words[wi].map(|w| if off % 8 == 0 { w as u32 } else { (w >> 32) as u32 })
    };

    // ── Stage 2: parked waiters in the window ──────────────────────────
    struct WaiterRow { tid: u64, uaddr: u64, delta: i64 }
    let lo = addr.saturating_sub(half);
    let hi = addr.saturating_add(half);
    let mut waiters_busy = false;
    let mut waiter_rows: Vec<WaiterRow> = Vec::new();
    match try_lock_brief(&crate::syscall::FUTEX_WAITERS) {
        Some(w) => {
            use crate::syscall::FutexKey;
            // Scan the same-process PRIVATE-key cluster around `addr`.  A
            // process-SHARED futex is keyed by backing-object identity, not by
            // `(pid, uaddr)`, so it does not appear in this virtual-address
            // window.
            for (k, tids) in w.range(FutexKey::Private(pid, lo)..=FutexKey::Private(pid, hi)) {
                let (wpid, wuaddr) = match k {
                    FutexKey::Private(p, u) => (*p, *u),
                    FutexKey::Shared { .. } => continue,
                };
                if wpid != pid { continue; }
                if tids.is_empty() { continue; }
                for &tid in tids.iter() {
                    waiter_rows.push(WaiterRow {
                        tid, uaddr: wuaddr,
                        delta: wuaddr as i64 - addr as i64,
                    });
                    if waiter_rows.len() >= 64 { break; }
                }
                if waiter_rows.len() >= 64 { break; }
            }
        }
        None => waiters_busy = true,
    }

    // ── Stage 3: thread states (for waiter + holder state lookup) ──────
    // Snapshot tid → (state, runnable) so the emit phase needs no lock.
    let mut tid_state: alloc::collections::BTreeMap<u64, (&'static str, bool)> =
        alloc::collections::BTreeMap::new();
    if let Some(tt) = try_lock_brief(&THREAD_TABLE) {
        for t in tt.iter() {
            let runnable = matches!(t.state,
                crate::proc::ThreadState::Ready | crate::proc::ThreadState::Running);
            tid_state.insert(t.tid, (thread_state_str(t.state), runnable));
        }
    }

    // ── Stage 4: recent wake targets in the window ─────────────────────
    // firefox-test/test-mode only — the per-CPU wake rings live in the
    // feature-gated futex_cluster module.  Empty otherwise.
    #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
    let recent_wakes: alloc::vec::Vec<(u64, u64, i64)> =
        crate::subsys::linux::futex_cluster::recent_wakes_near(addr, half);
    #[cfg(not(any(feature = "firefox-test-core", feature = "test-mode")))]
    let recent_wakes: alloc::vec::Vec<(u64, u64, i64)> = alloc::vec::Vec::new();

    // ── Stage 5: holder inference ──────────────────────────────────────
    // For a mutex the owner is the low-30 bits of `_m_lock` (offset +4).
    // For a cond the "holder" is whichever thread most recently woke a
    // NON-zero-delta target (the signaller advancing a paired mutex); we
    // surface the mutex decode as primary and the cond signaller as a hint.
    let m_lock = u32_at(4);
    let m_owner_tid = m_lock.map(musl_mutex_owner_tid).filter(|&t| t != 0);
    // Cond signaller hint: nearest non-zero-delta recent wake.
    let cond_signaller: Option<u64> = recent_wakes.iter()
        .filter(|&&(_, _, d)| d != 0)
        .min_by_key(|&&(_, _, d)| d.unsigned_abs())
        .map(|&(tid, _, _)| tid);
    let (owner_tid, owner_source): (Option<u64>, &'static str) = match m_owner_tid {
        Some(t) => (Some(t as u64), "m_lock"),
        None => (cond_signaller, if cond_signaller.is_some() { "cond_signaller" } else { "none" }),
    };
    let owner_state_run = owner_tid.and_then(|t| tid_state.get(&t).copied());

    // ── Stage 6: verdict ───────────────────────────────────────────────
    // Decision logic (matches the 4-case audit shape):
    //   benign-empty        : no waiter anywhere in the window
    //   true-lost-wakeup     : a waiter parks EXACTLY at `addr` (delta 0) but
    //                          the object shows no live owner & a wake fired
    //   wake-address-mismatch: a waiter parks at a NON-zero delta and a
    //                          recent wake targets a DIFFERENT slot in-window
    //   held-lock-deadlock   : an owner is named and is NOT runnable
    //   owner-starved        : an owner is named, IS runnable, yet a waiter
    //                          is still parked (owner hasn't been scheduled)
    let waiter_at_exact = waiter_rows.iter().any(|w| w.delta == 0);
    let waiter_at_offset = waiter_rows.iter().any(|w| w.delta != 0);
    let wake_offset_mismatch = recent_wakes.iter().any(|&(_, _, d)| d != 0)
        && waiter_rows.iter().any(|w| !recent_wakes.iter().any(|&(_, u, _)| u == w.uaddr));
    let (verdict, reason): (&'static str, &'static str) = if waiter_rows.is_empty() {
        ("benign-empty", "no parked waiter in the cluster window")
    } else if let Some((_, runnable)) = owner_state_run {
        if !runnable {
            ("held-lock-deadlock", "named lock owner is not runnable")
        } else if waiter_at_offset || waiter_at_exact {
            ("owner-starved", "owner is runnable but a waiter is still parked")
        } else {
            ("benign-empty", "owner runnable, no blocked waiter")
        }
    } else if wake_offset_mismatch || (waiter_at_offset && !waiter_at_exact) {
        ("wake-address-mismatch", "waiter parked at a delta the wake never targeted")
    } else if waiter_at_exact {
        ("true-lost-wakeup", "waiter parked exactly at addr; no owner, wake missed")
    } else {
        ("benign-empty", "waiters present but classification inconclusive")
    };

    // ── Stage 7: emit JSON ─────────────────────────────────────────────
    out.push('{');
    j_kv(out, "pid", &alloc::format!("{}", pid));
    j_str(out, "addr"); out.push(':'); j_hex(out, addr); out.push(',');
    j_str(out, "cr3");  out.push(':'); j_hex(out, cr3);  out.push(',');
    j_kv(out, "half", &alloc::format!("{}", half));

    // struct
    out.push_str("\"struct\":{");
    j_kv_str(out, "hex", &struct_hex);
    j_kv(out, "any_mapped", if any_mapped { "true" } else { "false" });
    // mutex decode
    out.push_str("\"mutex\":{");
    if let Some(l) = m_lock {
        j_str(out, "m_lock"); out.push(':'); j_hex(out, l as u64); out.push(',');
        j_kv(out, "owner_tid", &alloc::format!("{}", musl_mutex_owner_tid(l)));
        j_kv(out, "waiters_bit", if l & 0x8000_0000 != 0 { "true" } else { "false" });
    }
    if let Some(w) = u32_at(8) { j_str(out, "m_waiters"); out.push(':'); j_hex(out, w as u64); out.push(','); }
    j_trim_comma(out); out.push_str("},");
    // cond decode
    out.push_str("\"cond\":{");
    if let Some(s) = u32_at(8)  { j_str(out, "c_seq");      out.push(':'); j_hex(out, s as u64); out.push(','); }
    if let Some(s) = u32_at(12) { j_str(out, "c_waiters");  out.push(':'); j_hex(out, s as u64); out.push(','); }
    if let Some(s) = u32_at(0)  { j_str(out, "c_lock");     out.push(':'); j_hex(out, s as u64); out.push(','); }
    j_trim_comma(out); out.push('}');   // close "cond"
    out.push('}');                       // close "struct"
    out.push(',');

    // waiters
    if waiters_busy { out.push_str("\"waiters_busy\":true,"); }
    out.push_str("\"waiters\":[");
    for (i, w) in waiter_rows.iter().enumerate() {
        if i > 0 { out.push(','); }
        let (st, _) = tid_state.get(&w.tid).copied().unwrap_or(("?", false));
        let (nr, rip) = match crate::proc::sample::read_sample(w.tid) {
            Some(s) => (s.last_syscall_nr, s.last_user_rip),
            None => (u64::MAX, 0),
        };
        out.push('{');
        j_kv(out, "tid", &alloc::format!("{}", w.tid));
        j_str(out, "uaddr"); out.push(':'); j_hex(out, w.uaddr); out.push(',');
        j_kv(out, "delta", &alloc::format!("{}", w.delta));
        j_kv_str(out, "state", st);
        if nr != u64::MAX { j_kv(out, "nr", &alloc::format!("{}", nr)); }
        j_str(out, "rip"); out.push(':'); j_hex(out, rip); out.push(',');
        j_trim_comma(out);
        out.push('}');
    }
    out.push_str("],");

    // recent_wakes
    out.push_str("\"recent_wakes\":[");
    for (i, &(tid, u, d)) in recent_wakes.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_kv(out, "tid", &alloc::format!("{}", tid));
        j_str(out, "uaddr"); out.push(':'); j_hex(out, u); out.push(',');
        j_kv(out, "delta", &alloc::format!("{}", d));
        j_trim_comma(out);
        out.push('}');
    }
    out.push_str("],");

    // holder
    out.push_str("\"holder\":{");
    match owner_tid {
        Some(t) => {
            j_kv(out, "owner_tid", &alloc::format!("{}", t));
            let (st, runs) = owner_state_run.unwrap_or(("unknown", false));
            j_kv_str(out, "owner_state", st);
            j_kv(out, "owner_runs", if runs { "true" } else { "false" });
        }
        None => { j_kv(out, "owner_tid", "0"); j_kv_str(out, "owner_state", "none"); j_kv(out, "owner_runs", "false"); }
    }
    j_kv_str(out, "source", owner_source);
    j_trim_comma(out); out.push_str("},");

    j_kv_str(out, "verdict_hint", verdict);
    j_kv_str(out, "reason", reason);
    j_trim_comma(out);
    out.push('}');

    // Serial mirror for TCP-drain recovery (mirrors op_thread_park_audit's
    // [THREAD-PARK] side channel).  One compact line; the harness can
    // reconstruct the verdict from serial even if the JSON envelope is
    // truncated mid-flight under load.
    crate::serial_println!(
        "[COND-AUTOPSY] pid={} addr={:#x} verdict={} waiters={} recent_wakes={} \
         owner_tid={} owner_runs={} reason={}",
        pid, addr, verdict, waiter_rows.len(), recent_wakes.len(),
        owner_tid.unwrap_or(0),
        owner_state_run.map(|(_, r)| r).unwrap_or(false),
        reason
    );
}

fn file_type_str(ft: crate::vfs::FileType) -> &'static str {
    use crate::vfs::FileType::*;
    match ft {
        Socket => "socket",
        Pipe => "pipe",
        RegularFile => "regular",
        Directory => "directory",
        SymLink => "symlink",
        CharDevice => "char-device",
        BlockDevice => "block-device",
        EventFd => "eventfd",
        TimerFd => "timerfd",
        SignalFd => "signalfd",
        InotifyFd => "inotifyfd",
        PtyMaster => "pty-master",
        PtySlave => "pty-slave",
    }
}

// ── futex-stats ──────────────────────────────────────────────────────────────
//
// Surfaces the counters from `subsys::linux::futex_cluster` plus the existing
// `FUTEX_WAKE_GHOST` counter from `subsys::linux::syscall`.  The qemu-harness
// front-end uses this to verify the cluster-wake compensation is firing
// during firefox-test runs.  Per POSIX `pthread_cond_signal(3p)` the wake
// recovery upholds the at-least-one-unblocked guarantee when older glibc
// loses the race documented at the public bug
// <https://sourceware.org/bugzilla/show_bug.cgi?id=25847>.
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
fn op_futex_stats(out: &mut String) {
    use core::fmt::Write;
    let s = crate::subsys::linux::futex_cluster::stats();
    let ghost = crate::subsys::linux::syscall::FUTEX_WAKE_GHOST_COUNT
        .load(core::sync::atomic::Ordering::Relaxed);
    out.push('{');
    let _ = write!(
        out,
        r#""cluster_wake_enabled":{},"#,
        if s.enabled { "true" } else { "false" }
    );
    let _ = write!(out, r#""cluster_wake_attempts":{},"#,      s.attempts);
    let _ = write!(out, r#""cluster_wake_recoveries":{},"#,    s.recoveries);
    let _ = write!(out, r#""cluster_wake_misses":{},"#,        s.misses);
    let _ = write!(out, r#""cluster_wake_no_candidates":{},"#, s.no_candidates);
    let _ = write!(out, r#""futex_wake_ghost":{}"#,            ghost);
    out.push('}');
}

// ── futex-set-cluster-wake ───────────────────────────────────────────────────
//
// Runtime toggle for the bounded broadcast-within-cluster wake compensation.
// Request:
//   {"op":"futex-set-cluster-wake","on":true}   or "false"
// Default is ON when the kernel was built with `firefox-test`, OFF otherwise.
// Production safety: operator must explicitly opt-in via this kdb command
// on a stock build.
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
fn op_futex_set_cluster_wake(req: &str, out: &mut String) {
    use core::fmt::Write;
    let on_field = extract_field(req, "on").map(|v| v.to_ascii_lowercase());
    let new_state = match on_field.as_deref() {
        Some("true") | Some("1") | Some("on")  => Some(true),
        Some("false") | Some("0") | Some("off") => Some(false),
        _ => None,
    };
    match new_state {
        Some(v) => {
            crate::subsys::linux::futex_cluster::set_enabled(v);
            let _ = write!(
                out,
                r#"{{"cluster_wake_enabled":{}}}"#,
                if v { "true" } else { "false" }
            );
        }
        None => {
            let current = crate::subsys::linux::futex_cluster::is_enabled();
            let _ = write!(
                out,
                r#"{{"error":"missing or unrecognised 'on' field","cluster_wake_enabled":{}}}"#,
                if current { "true" } else { "false" }
            );
        }
    }
}

// ── net-ipver ─────────────────────────────────────────────────────────────────
//
// Read or toggle the runtime IPv4/IPv6 address-family enable flags
// (net::ipver).  One-shot, structured JSON.
//
//   {"op":"net-ipver"}                          → report current state
//   {"op":"net-ipver","family":"6","state":"off"}  → disable IPv6, then report
//   {"op":"net-ipver","family":"4","state":"on"}   → enable IPv4, then report
//
// Always emits the full {ipv4_enabled, ipv6_enabled} state so a caller never
// needs a second round-trip to read back the effect of a toggle.
fn op_net_ipver(req: &str, out: &mut String) {
    use core::fmt::Write;
    let family = extract_field(req, "family");
    let state  = extract_field(req, "state").map(|v| v.to_ascii_lowercase());

    // Apply a toggle only when BOTH family and a recognised state are present.
    let mut applied: Option<&'static str> = None;
    let mut bad: Option<&'static str> = None;
    if let Some(fam) = family.as_deref() {
        let on = match state.as_deref() {
            Some("on") | Some("1") | Some("true")  | Some("enable")  => Some(true),
            Some("off") | Some("0") | Some("false") | Some("disable") => Some(false),
            _ => None,
        };
        match (fam, on) {
            ("4", Some(v)) => { crate::net::ipver::set_ipv4_enabled(v); applied = Some("ipv4"); }
            ("6", Some(v)) => { crate::net::ipver::set_ipv6_enabled(v); applied = Some("ipv6"); }
            (_, None)      => { bad = Some("missing or unrecognised 'state' (expected on|off)"); }
            _              => { bad = Some("unrecognised 'family' (expected 4 or 6)"); }
        }
    }

    let v4 = crate::net::ipver::ipv4_enabled();
    let v6 = crate::net::ipver::ipv6_enabled();
    out.push('{');
    if let Some(a) = applied { let _ = write!(out, r#""applied":"{}","#, a); }
    if let Some(e) = bad     { let _ = write!(out, r#""error":"{}","#, e); }
    let _ = write!(
        out,
        r#""ipv4_enabled":{},"ipv6_enabled":{}}}"#,
        if v4 { "true" } else { "false" },
        if v6 { "true" } else { "false" },
    );
}

// ── net-rxstats ───────────────────────────────────────────────────────────────
//
// One-shot receive-path health snapshot for confirming TCP/NIC packet loss.
// Emits, for every connection in the TCP table, the 4-tuple + state + the
// sequence cursors (recv_next / send_next / send_unack), the application
// receive-queue depth, the peer window, and the retransmit-queue depth.  A
// recv_next that stalls while the peer keeps retransmitting (retransmit_len
// stays > 0 on the peer's side, observable as a non-advancing recv_next on
// repeated polls) localizes a receive-side gap — the in-order-only accept
// path refusing an out-of-order segment (RFC 9293 §3.10.7.4).
//
// Also emits the e1000 RX statistics: cumulative software frame/byte counts
// delivered to the stack, plus the hardware Missed-Packets-Count (MPC) and
// Receive-No-Buffers-Count (RNBC) deltas.  A non-zero MPC confirms the NIC
// dropped inbound frames because the descriptor ring was full (ring overrun).
//
// Read repeatedly (e.g. once a second) to watch recv_next advance or stall.
fn op_net_rxstats(_req: &str, out: &mut String) {
    use core::fmt::Write;
    out.push('{');

    // e1000 RX statistics first.
    let (rx_frames, rx_bytes, mpc, rnbc, ring) = crate::net::e1000::rx_stats();
    let _ = write!(
        out,
        r#""e1000":{{"rx_frames":{},"rx_bytes":{},"mpc_delta":{},"rnbc_delta":{},"num_rx_desc":{}}},"#,
        rx_frames, rx_bytes, mpc, rnbc, ring,
    );

    out.push_str(r#""conns":["#);
    let snap = tcp::snapshot_connections();
    let mut first = true;
    for c in snap.iter() {
        if !first { out.push(','); }
        first = false;
        let st = match c.state {
            TcpState::Closed      => "Closed",
            TcpState::Listen      => "Listen",
            TcpState::SynSent     => "SynSent",
            TcpState::SynReceived => "SynReceived",
            TcpState::Established  => "Established",
            TcpState::FinWait1    => "FinWait1",
            TcpState::FinWait2    => "FinWait2",
            TcpState::CloseWait   => "CloseWait",
            TcpState::LastAck     => "LastAck",
            TcpState::TimeWait    => "TimeWait",
        };
        let _ = write!(
            out,
            r#"{{"local_port":{},"remote_ip":"{}.{}.{}.{}","remote_port":{},"state":"{}","recv_next":{},"send_next":{},"send_unack":{},"recv_buf_len":{},"peer_window":{},"retransmit_len":{}}}"#,
            c.local_port,
            c.remote_ip[0], c.remote_ip[1], c.remote_ip[2], c.remote_ip[3],
            c.remote_port, st,
            c.recv_next, c.send_next, c.send_unack,
            c.recv_buf_len, c.peer_window, c.retransmit_len,
        );
    }
    out.push_str("]}");
}

// ── procmaps ──────────────────────────────────────────────────────────────────
//
// Terse file-backed VMA map for one process.  Modeled on the Linux
// /proc/<pid>/maps format documented in proc(5) (Linux man-pages 6.7,
// §"/proc/[pid]/maps") but emitted as JSON for harness consumption.
//
// For each file-backed VMA we emit:
//   base, end, prot, name, first_page_phys
// `first_page_phys` is the physical address of the page mapping the first
// byte of the VMA, derived by walking the process's PML4.  This anchors
// the ASLR base for any ELF image (libxul, ld-musl, etc.) so a harness
// caller can run `addr2line` on the kernel's symbol-bearing copy of the
// binary.
fn op_procmaps(req: &str, out: &mut String) {
    use core::fmt::Write;
    let pid = match extract_field(req, "pid").and_then(|s| parse_u64(&s)) {
        Some(p) => p,
        None => { out.push_str(r#"{"error":"missing or bad 'pid'"}"#); return; }
    };

    struct VmaRow {
        base: u64, end: u64, prot: u32, name: alloc::string::String, phys: Option<u64>,
    }

    let pt = match try_lock_brief(&PROCESS_TABLE) {
        Some(g) => g,
        None => {
            out.push_str(r#"{"busy":"PROCESS_TABLE held"}"#);
            return;
        }
    };
    let snap: Option<(u64, alloc::vec::Vec<VmaRow>)> = pt.iter().find(|p| p.pid == pid).map(|p| {
        let rows: alloc::vec::Vec<VmaRow> = match &p.vm_space {
            Some(vs) => vs.areas.iter().map(|a| {
                let phys = crate::mm::vmm::virt_to_phys_in(p.cr3, a.base);
                VmaRow {
                    base: a.base, end: a.end(), prot: a.prot,
                    name: alloc::string::String::from(a.name),
                    phys,
                }
            }).collect(),
            None => alloc::vec::Vec::new(),
        };
        (p.cr3, rows)
    });
    drop(pt);

    let (cr3, rows) = match snap {
        Some(s) => s,
        None => {
            let _ = write!(out, r#"{{"error":"pid {} not found"}}"#, pid);
            return;
        }
    };

    out.push('{');
    let _ = write!(out, r#""pid":{},"cr3":"{:#x}","vmas":["#, pid, cr3);
    for (i, r) in rows.iter().take(512).enumerate() {
        if i > 0 { out.push(','); }
        out.push('{');
        j_str(out, "base"); out.push(':'); j_hex(out, r.base); out.push(',');
        j_str(out, "end");  out.push(':'); j_hex(out, r.end);  out.push(',');
        let mut fb = [b'-'; 3];
        if r.prot & crate::mm::vma::PROT_READ  != 0 { fb[0] = b'r'; }
        if r.prot & crate::mm::vma::PROT_WRITE != 0 { fb[1] = b'w'; }
        if r.prot & crate::mm::vma::PROT_EXEC  != 0 { fb[2] = b'x'; }
        j_kv_str(out, "prot", core::str::from_utf8(&fb).unwrap_or("---"));
        j_kv_str(out, "name", &r.name);
        match r.phys {
            Some(p) => { j_str(out, "first_page_phys"); out.push(':'); j_hex(out, p); }
            None    => { out.push_str(r#""first_page_phys":null"#); }
        }
        out.push('}');
    }
    out.push_str("]}");
}

// ── record-status ────────────────────────────────────────────────────────────
//
// Returns the current INFRA-3 record/replay state: PRNG seed loaded at
// boot, current virtual-tick value, and current syscall-record
// ordinal.  When the `record-replay` feature is OFF, returns a stable
// "feature off" JSON so the KDB protocol surface does not change
// across builds.

#[cfg(feature = "record-replay")]
fn op_record_status(out: &mut String) {
    use core::fmt::Write;
    let seed = crate::record_replay::seed_at_boot();
    let vt   = crate::record_replay::current_virtual_ticks();
    let ord  = crate::record_replay::current_ordinal();
    let _ = write!(
        out,
        r#"{{"enabled":true,"seed":"{:#018x}","virtual_ticks":{},"ordinal":{}}}"#,
        seed, vt, ord,
    );
}

#[cfg(not(feature = "record-replay"))]
fn op_record_status(out: &mut String) {
    out.push_str(r#"{"enabled":false}"#);
}

// ── replay-dump ──────────────────────────────────────────────────────────────
//
// Writes the in-RAM `[SC-REC]` record log to a VFS path.  Request
// field: `"path":"<absolute path>"`.  Response: `{"ok":true,"records":N,"path":"..."}`
// on success, `{"ok":false,"error":"..."}` on failure.
//
// When the `record-replay` feature is OFF, returns a stable
// "feature off" JSON so the protocol surface is stable.

#[cfg(feature = "record-replay")]
fn op_replay_dump(req: &str, out: &mut String) {
    use core::fmt::Write;
    let path = match extract_field(req, "path") {
        Some(p) => p,
        None    => { out.push_str(r#"{"ok":false,"error":"missing 'path' field"}"#); return; }
    };
    match crate::record_replay::dump_records_to(&path) {
        Ok(n) => {
            let _ = write!(out, r#"{{"ok":true,"records":{},"path":""#, n);
            for c in path.chars().take(256) {
                if c == '"' || c == '\\' { out.push('\\'); }
                out.push(c);
            }
            out.push_str(r#""}"#);
        }
        Err(e) => {
            let _ = write!(out, r#"{{"ok":false,"error":""#);
            for c in e.chars().take(128) {
                if c == '"' || c == '\\' { out.push('\\'); }
                out.push(c);
            }
            out.push_str(r#""}"#);
        }
    }
}

#[cfg(not(feature = "record-replay"))]
fn op_replay_dump(_req: &str, out: &mut String) {
    out.push_str(r#"{"ok":false,"error":"record-replay feature off"}"#);
}
