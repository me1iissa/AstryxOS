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

/// Initialise the kdb listener.  Safe to call multiple times.
pub fn init() {
    if INITED.swap(true, Ordering::SeqCst) { return; }
    match tcp::listen(KDB_PORT) {
        Ok(()) => crate::serial_println!("[KDB] listening on 0.0.0.0:{}", KDB_PORT),
        Err(e) => {
            crate::serial_println!("[KDB] listen({}) failed: {}", KDB_PORT, e);
            INITED.store(false, Ordering::SeqCst);
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
    let mut to_close: Vec<([u8; 4], u16, u16)> = Vec::new();
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
        "syscall-trend"  => op_syscall_trend(req, out),
        "vfs-mounts"     => op_vfs_mounts(out),
        "dmesg"          => op_dmesg(req, out),
        "syms"           => op_syms(req, out),
        "mem"            => op_mem(req, out),
        "trace-status"   => op_trace_status(out),
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

    let mut tmap: alloc::collections::BTreeMap<u64, u64> = alloc::collections::BTreeMap::new();
    let thread_table_busy = match try_lock_brief(&THREAD_TABLE) {
        Some(tt) => {
            for r in &rows {
                if let Some(tid) = r.thread0 {
                    if let Some(t) = tt.iter().find(|t| t.tid == tid) {
                        tmap.insert(r.pid, t.user_entry_rip);
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
        let rip = tmap.get(&r.pid).copied().unwrap_or(0);
        j_str(out, "rip"); out.push(':'); j_hex(out, rip); out.push(',');
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

    // Stage 2: per-thread data under a different lock.
    struct TR { tid: u64, state: &'static str, rip: u64, rsp: u64 }
    let trs: Vec<TR> = match try_lock_brief(&THREAD_TABLE) {
        Some(tt) => snap.threads.iter()
            .filter_map(|tid| tt.iter().find(|t| t.tid == *tid).map(|t| TR {
                tid: t.tid, state: thread_state_str(t.state),
                rip: t.user_entry_rip, rsp: t.context.rsp,
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
        j_str(out, "rip"); out.push(':'); j_hex(out, t.rip); out.push(',');
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

// ── trace-status ──────────────────────────────────────────────────────────────

fn op_trace_status(out: &mut String) {
    use core::fmt::Write;
    let _ = write!(out, r#"{{"syscall_trace":{},"pf_trace":{},"build":"kdb"}}"#,
                   cfg!(feature = "syscall-trace"), cfg!(feature = "pf-trace"));
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
