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
        "ping"         => op_ping(out),
        "proc-list"    => op_proc_list(out),
        "proc"         => op_proc(req, out),
        "vfs-mounts"   => op_vfs_mounts(out),
        "dmesg"        => op_dmesg(req, out),
        "syms"         => op_syms(req, out),
        "mem"          => op_mem(req, out),
        "trace-status" => op_trace_status(out),
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
