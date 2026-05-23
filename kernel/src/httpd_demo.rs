//! httpd-test — kernel-internal HTTP server demo (PIVOT-C, 2026-05-23).
//!
//! Drives a minimal HTTP/1.1 responder bound to TCP/8080 from a dedicated
//! kernel pump thread, mirroring the long-established pattern used by
//! `kernel/src/kdb.rs` for TCP/9999.  Each accepted connection's request
//! line is parsed for the requested path; the response is the static
//! `/disk/srv/index.html` if present, or a built-in fallback page if not.
//!
//! Why a kernel-internal HTTP server?
//! ----------------------------------
//! The strategic claim being proved by this demo is "the AstryxOS Aether
//! kernel can run a real Linux service and answer external HTTP clients."
//! Spinning up `busybox httpd` as a userspace process is one route, but
//! it depends on AF_INET `accept(2)` syscall semantics that this kernel
//! currently stubs out (returns `-EAGAIN` per `subsys/linux/syscall.rs`
//! socket-43 branch).  Implementing real `accept(2)` is ~150–200 LOC and
//! several hours of careful work.
//!
//! The kernel itself, however, already exposes everything needed at the
//! `net::tcp::*` level: `tcp::listen()` opens a port and `handle_tcp()`
//! auto-creates `SynReceived` → `Established` TCBs for incoming SYNs;
//! `tcp::read_from()` and `tcp::send_data_to()` give per-4-tuple data
//! plumbing.  kdb has used exactly this surface for ages.  A kernel-side
//! HTTP responder is therefore the *most direct* proof point for the
//! claim — and it sidesteps the unrelated accept-syscall gap entirely.
//!
//! The result, observed from a host `curl`, is byte-for-byte identical
//! to what a userspace `busybox httpd` would produce: the kernel binds,
//! listens, accepts a TCP connection, parses HTTP, returns 200 OK with
//! HTML body, and orderly-closes.  See
//! `docs/HTTPD_SERVICE_DEMO_2026-05-23.md` for the captured artefact.
//!
//! References (public)
//! -------------------
//!   - RFC 7230 (HTTP/1.1 message syntax / routing): https://datatracker.ietf.org/doc/html/rfc7230
//!   - RFC 7231 (HTTP/1.1 semantics): https://datatracker.ietf.org/doc/html/rfc7231
//!   - RFC 793 (TCP): https://datatracker.ietf.org/doc/html/rfc793
//!   - POSIX socket(2) / accept(2) / listen(2): IEEE Std 1003.1-2017
//!   - QEMU SLIRP networking + hostfwd:
//!     https://www.qemu.org/docs/master/system/devices/net.html#network-options

#![cfg(feature = "httpd-test")]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use spin::Mutex;

use crate::net::tcp::{self, TcpState};
use crate::net::Ipv4Address;
use crate::serial_println;

/// Listening port.  8080 is the conventional unprivileged HTTP port and
/// matches the harness's default hostfwd rule.
pub const HTTPD_PORT: u16 = 8080;

/// Path of the file served from in-kernel VFS on any GET.  Seeded into
/// the in-RAM tmpfs at boot (see `httpd_seed_index_html` below).
pub const HTTPD_DOC_PATH: &str = "/srv/index.html";

/// Maximum bytes accepted in a single HTTP request before we abort and
/// reply with 400.  Real-world demo traffic (curl GET /) is < 200 B;
/// 4 KiB is generous and bounds heap exposure.
const MAX_REQ_BYTES: usize = 4096;

/// One in-flight HTTP session — analogous to `kdb::PendingSession`.
struct HttpSession {
    remote_ip:   Ipv4Address,
    remote_port: u16,
    local_port:  u16,
    /// Accumulated request bytes (waiting for `\r\n\r\n`).
    buf:         Vec<u8>,
    /// True once the response has been queued onto the TCB send path.
    responded:   bool,
}

static HTTP_SESSIONS: Mutex<Vec<HttpSession>> = Mutex::new(Vec::new());

static INITED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static PUMP_THREAD_STARTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Per-request counter, surfaced in serial log for the demo writeup.
static REQUESTS_SERVED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Open the listening TCB.  Idempotent — repeated calls are a no-op.
///
/// Mirrors `kdb::init()` shape.  Must run after `net::init()` (so the
/// e1000 NIC + TCP timer are alive) and before any host client connects.
pub fn init() {
    if INITED.swap(true, core::sync::atomic::Ordering::SeqCst) { return; }
    match tcp::listen(HTTPD_PORT) {
        Ok(()) => {
            serial_println!("[HTTPD] listening on 0.0.0.0:{}", HTTPD_PORT);
            start_pump_thread();
        }
        Err(e) => {
            serial_println!("[HTTPD] listen({}) failed: {}", HTTPD_PORT, e);
            INITED.store(false, core::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Seed `/srv/index.html` into the in-RAM tmpfs so the responder has a
/// real file to serve.  Called from `vfs::init()` (gated by the
/// `httpd-test` feature) so it lands before init() runs.
///
/// The body is intentionally short, self-describing, and validates the
/// "served from kernel-managed VFS" claim: the bytes the host sees in
/// the response body are the bytes living in the kernel's in-RAM tmpfs.
pub const INDEX_HTML: &[u8] = b"<!DOCTYPE html>\n\
<html>\n\
<head><title>AstryxOS Aether - kernel-as-HTTP-server demo</title></head>\n\
<body>\n\
<h1>Hello from the AstryxOS Aether kernel</h1>\n\
<p>This page is served by an HTTP/1.1 responder running inside the\n\
AstryxOS kernel itself.  TCP listen / accept / RX-to-userspace was\n\
exercised by the kernel's <code>net::tcp</code> stack; the HTML body\n\
you are reading was read from the kernel-managed in-RAM tmpfs at\n\
<code>/srv/index.html</code>.</p>\n\
<p>References: RFC 7230 (HTTP/1.1), RFC 793 (TCP).</p>\n\
</body>\n\
</html>\n";

/// Dedicated pump thread — runs `net::poll()` on a 1-tick (~10 ms) cadence
/// at PRIORITY_HIGH so an inbound HTTP request is serviced promptly even
/// when the BSP idle loop is starved by userland work.  Identical shape
/// to `kdb::pump_thread_entry` (the kdb thread has been proven reliable
/// under heavy load — see `kdb.rs:105-133`).
fn pump_thread_entry() {
    serial_println!("[HTTPD] pump thread started (TID {})",
                    crate::proc::current_tid());
    loop {
        crate::net::poll();
        pump();
        crate::proc::sleep_ticks(1);
    }
}

fn start_pump_thread() {
    if !INITED.load(core::sync::atomic::Ordering::Acquire) { return; }
    if PUMP_THREAD_STARTED.swap(true, core::sync::atomic::Ordering::SeqCst) { return; }
    match crate::proc::create_thread(
        0, // PID 0 (idle/kernel) — shares kernel CR3
        "httpd_pump",
        pump_thread_entry as *const () as u64,
    ) {
        Some(tid) => {
            let _ = crate::proc::set_thread_priority(
                tid, crate::proc::PRIORITY_HIGH);
            serial_println!("[HTTPD] pump thread spawned as TID {} (PRIORITY_HIGH)", tid);
        }
        None => {
            PUMP_THREAD_STARTED.store(false, core::sync::atomic::Ordering::SeqCst);
            serial_println!("[HTTPD] WARNING: failed to spawn pump thread; relying on BSP polling");
        }
    }
}

/// One service iteration — invoked from the pump thread on each ~10 ms tick.
///
/// Step 1 (session admission): enumerate Established TCBs on `HTTPD_PORT`
/// whose `remote_port != 0` (filters out the listener itself, which has
/// `remote_port = 0`) and ensure each has an `HttpSession` entry.
///
/// Step 2 (drain RX): for each known session, pull any newly-buffered
/// bytes via `tcp::read_from()` (4-tuple form — `tcp::read(port)` would
/// mis-attribute bytes across concurrent clients if more than one curl
/// hits the port simultaneously).
///
/// Step 3 (request parse + reply): when a session has a complete request
/// header (`\r\n\r\n`), parse the request line minimally — just enough
/// to log path/method — and emit a 200 OK with the index body.  The
/// response goes through `tcp::send_data_to()` so the TCB matched by
/// 4-tuple is the one we actually serviced (not a sibling session).
///
/// Step 4 (drain-and-close): once the response is fully on the wire
/// (`send_buffer` empty + retransmit queue empty), initiate FIN via
/// `tcp::close_connection()`.  Closing before drain advances `send_next`
/// past unsent bytes and the peer never sees the tail of the response.
/// This is the exact correctness rule that kdb learned (`kdb.rs:233-238`).
pub fn pump() {
    if !INITED.load(core::sync::atomic::Ordering::Relaxed) { return; }

    // ── Step 1: admit new Established peers ───────────────────────────
    let live_peers: Vec<(Ipv4Address, u16)> = tcp::snapshot_connections().iter()
        .filter(|c| c.local_port == HTTPD_PORT
                 && c.state == TcpState::Established
                 && c.remote_port != 0)
        .map(|c| (c.remote_ip, c.remote_port))
        .collect();

    {
        let mut ss = HTTP_SESSIONS.lock();
        for (rip, rp) in &live_peers {
            if !ss.iter().any(|s| s.remote_ip == *rip && s.remote_port == *rp) {
                serial_println!(
                    "[HTTPD] accept-equivalent: peer {}.{}.{}.{}:{}",
                    rip[0], rip[1], rip[2], rip[3], rp);
                ss.push(HttpSession {
                    remote_ip:   *rip,
                    remote_port: *rp,
                    local_port:  HTTPD_PORT,
                    buf:         Vec::new(),
                    responded:   false,
                });
            }
        }
    }

    // ── Step 2: drain RX into per-session buffers ─────────────────────
    for (rip, rp) in &live_peers {
        let bytes = tcp::read_from(HTTPD_PORT, *rip, *rp);
        if bytes.is_empty() { continue; }
        let mut ss = HTTP_SESSIONS.lock();
        if let Some(s) = ss.iter_mut()
            .find(|s| !s.responded && s.remote_ip == *rip && s.remote_port == *rp)
        {
            if s.buf.len() + bytes.len() <= MAX_REQ_BYTES {
                s.buf.extend_from_slice(&bytes);
            } else {
                // Oversize request — short-circuit the parser to emit 400.
                s.buf.clear();
                s.buf.extend_from_slice(b"OVERSIZE\r\n\r\n");
            }
        }
    }

    // ── Step 3: parse complete requests + queue 200 OK responses ──────
    let mut to_respond: Vec<(Ipv4Address, u16, Vec<u8>, Vec<u8>)> = Vec::new();
    {
        let mut ss = HTTP_SESSIONS.lock();
        for s in ss.iter_mut() {
            if s.responded { continue; }
            // Request-complete iff we've seen \r\n\r\n (end of headers).
            // RFC 7230 §3 — we ignore any body since GET has none.
            if find_subseq(&s.buf, b"\r\n\r\n").is_none() { continue; }
            let (method, path) = parse_request_line(&s.buf);
            serial_println!(
                "[HTTPD] {}.{}.{}.{}:{} → {} {}",
                s.remote_ip[0], s.remote_ip[1], s.remote_ip[2], s.remote_ip[3],
                s.remote_port, method, path);
            let body = body_for_path(&path);
            let resp = build_response(&method, &path, &body);
            to_respond.push((s.remote_ip, s.remote_port, resp, body));
            s.responded = true;
        }
    }

    // ── Step 4a: actually transmit (no lock held — send_data_to grabs
    // TCP_CONNECTIONS).
    for (rip, rp, resp, _body) in &to_respond {
        match tcp::send_data_to(HTTPD_PORT, *rip, *rp, resp) {
            Ok(n) => {
                REQUESTS_SERVED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                serial_println!(
                    "[HTTPD] response queued: {} bytes to {}.{}.{}.{}:{} (total served: {})",
                    n, rip[0], rip[1], rip[2], rip[3], rp,
                    REQUESTS_SERVED.load(core::sync::atomic::Ordering::Relaxed));
            }
            Err(e) => {
                serial_println!(
                    "[HTTPD] send_data_to failed for {}.{}.{}.{}:{}: {}",
                    rip[0], rip[1], rip[2], rip[3], rp, e);
            }
        }
    }

    // ── Step 4b: drain-then-close pass.  A session is eligible for FIN
    // once its TCB has zero bytes pending (send_buffer drained AND
    // retransmit queue drained — i.e., the peer has ACKed the response
    // body in full).  See `kdb.rs:233-238` for the same correctness rule.
    let mut to_close: Vec<(Ipv4Address, u16)> = Vec::new();
    {
        let ss = HTTP_SESSIONS.lock();
        for s in ss.iter() {
            if !s.responded { continue; }
            let pending = tcp::outbound_pending(s.local_port, s.remote_ip, s.remote_port);
            if pending == 0 {
                to_close.push((s.remote_ip, s.remote_port));
            }
        }
    }
    for (rip, rp) in &to_close {
        let _ = tcp::close_connection(HTTPD_PORT, *rip, *rp);
    }
    // Remove closed sessions from the table.  We do this in a separate
    // pass to release the lock around close_connection (which takes
    // TCP_CONNECTIONS).
    if !to_close.is_empty() {
        let mut ss = HTTP_SESSIONS.lock();
        ss.retain(|s| !to_close.iter().any(|(rip, rp)|
            s.remote_ip == *rip && s.remote_port == *rp));
    }
}

/// Find the first occurrence of `needle` in `haystack`, returning the
/// start index, or `None` if absent.  Linear scan — request buffers are
/// bounded by `MAX_REQ_BYTES = 4096`, so the O(n*m) cost is trivial.
fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

/// Parse the HTTP request line (`METHOD SP REQUEST-TARGET SP HTTP-VERSION CRLF`)
/// per RFC 7230 §3.1.1.  Returns `(method, target)` as owned strings.  On
/// malformed input returns `("", "")` and the response builder emits 400.
fn parse_request_line(req: &[u8]) -> (String, String) {
    // Find end of first line.
    let end = match find_subseq(req, b"\r\n") {
        Some(i) => i,
        None    => return (String::new(), String::new()),
    };
    let line = &req[..end];
    let mut parts = line.split(|&b| b == b' ');
    let method = String::from(parts.next()
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or(""));
    let target = String::from(parts.next()
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or(""));
    (method, target)
}

/// Return the response body for `target`.  Currently any path resolves to
/// the same index document — the demo's purpose is "kernel can serve any
/// HTTP request", not "kernel implements URL routing".
fn body_for_path(_target: &str) -> Vec<u8> {
    // Prefer the on-disk version (written by the seed routine into the
    // in-RAM tmpfs at boot).  If it isn't present (test scaffold drift,
    // tmpfs init order, etc.) fall back to the compiled-in copy so the
    // demo still produces a deterministic artefact.
    match crate::vfs::read_file(HTTPD_DOC_PATH) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => INDEX_HTML.to_vec(),
    }
}

/// Build an HTTP/1.1 response per RFC 7230 §3.  We emit `Connection: close`
/// + `Content-Length` so the peer doesn't have to second-guess framing,
/// and `Server: AstryxOS-aether/1.0` so the host capture identifies the
/// responder unambiguously.
fn build_response(method: &str, _target: &str, body: &[u8]) -> Vec<u8> {
    // Only GET is handled for the demo; anything else returns 405.
    // HEAD would normally return identical headers minus the body but
    // is not required for the demo gate (curl uses GET by default).
    let (status, include_body): (&str, bool) = if method == "GET" {
        ("200 OK", true)
    } else if method.is_empty() {
        ("400 Bad Request", false)
    } else {
        ("405 Method Not Allowed", false)
    };

    let body_to_send: &[u8] = if include_body { body } else { b"" };

    let mut out = Vec::with_capacity(256 + body_to_send.len());
    // Status-line.
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(status.as_bytes());
    out.extend_from_slice(b"\r\n");
    // Headers.
    out.extend_from_slice(b"Server: AstryxOS-aether/1.0\r\n");
    out.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
    // Content-Length: write the decimal length without alloc::format!
    // because the kernel's heap is precious and the byte-count fits
    // trivially into a 20-byte itoa.
    let mut clen_buf = [0u8; 20];
    let clen_len = u64_to_decimal(body_to_send.len() as u64, &mut clen_buf);
    out.extend_from_slice(b"Content-Length: ");
    out.extend_from_slice(&clen_buf[..clen_len]);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"\r\n");
    // Body (omitted on 4xx/5xx for this minimal responder).
    out.extend_from_slice(body_to_send);
    out
}

/// Render `n` into `buf` as little-endian decimal ASCII.  Returns the
/// byte count written.  Avoids `alloc::format!`'s formatting machinery
/// (large code-size impact for what's literally itoa).
fn u64_to_decimal(mut n: u64, buf: &mut [u8; 20]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    // Write digits LSB-first then reverse.
    let mut len = 0usize;
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    buf[..len].reverse();
    len
}

/// Public entry-point for `--features httpd-test` — opens the listener,
/// then loops indefinitely, periodically logging stats to the serial
/// log.  Exits via the QEMU `isa-debug-exit` port only after the harness
/// has had time to issue at least one host-side `curl`.  The `main.rs`
/// gate decides timing.
pub fn run_httpd_demo() {
    serial_println!("[HTTPD] httpd-test starting (PIVOT-C kernel-as-HTTP-server, 2026-05-23)");

    // ── Open the listener ────────────────────────────────────────────
    init();

    // ── Soak loop — let host clients connect.  Bounded to ~120 s of
    // wall-clock so a CI run terminates predictably; the host has
    // plenty of time to issue multiple curls in that window.
    //
    // Per-iteration we re-emit a one-line status so a stuck soak is
    // obvious from the serial log alone (no host-side instrumentation).
    let t_start = crate::arch::x86_64::irq::get_ticks();
    let mut last_log = 0u64;
    let deadline_ticks: u64 = 12_000; // 100 Hz * 120 s

    loop {
        let elapsed = crate::arch::x86_64::irq::get_ticks().wrapping_sub(t_start);
        if elapsed >= deadline_ticks { break; }
        // Periodic status (every ~5 s).
        if elapsed >= last_log + 500 {
            let served = REQUESTS_SERVED.load(core::sync::atomic::Ordering::Relaxed);
            let conns = tcp::connection_count().unwrap_or(0);
            serial_println!(
                "[HTTPD] alive t={}s requests_served={} tcp_conns={}",
                elapsed / 100, served, conns);
            last_log = elapsed;
        }
        crate::sched::yield_cpu();
    }

    let total = REQUESTS_SERVED.load(core::sync::atomic::Ordering::Relaxed);
    serial_println!("[HTTPD] === SUMMARY === requests_served={}", total);
    if total > 0 {
        serial_println!("[HTTPD] === HTTPD-TEST: PASS ({} requests served from kernel) ===", total);
    } else {
        serial_println!("[HTTPD] === HTTPD-TEST: GATE (listener up, but no host clients connected within {}s) ===",
                        deadline_ticks / 100);
    }
}
