//! webxo: userspace HTTP-server demo runner (web/httpd-bringup).
//!
//! Launches the WebXO HTTP/1.1 server (a small musl-linked C++ static-page
//! server, ~470 KB) as a userspace process listening on guest TCP port 8080.
//! Used as the proof point that the AstryxOS kernel personality stack can
//! host a real Linux web service end-to-end, on the SAME live instance that
//! serves SSH: socket(2), setsockopt(2) SO_REUSEADDR, bind(2), listen(2),
//! accept(2) (from a pool of worker threads all blocked on the shared listen
//! fd), recv(2)/send(2), plus a std::thread worker pool (clone(2) + futex(2))
//! and ifstream-based static-file reads (openat/read/close).
//!
//! Shape
//! -----
//! Mirrors sshd_demo's launcher: build a small argv/envp, fork+exec via
//! `create_user_process_with_args_blocked`, attach a stdout-capture pipe,
//! unblock, and (for the standalone webxo-test feature) run a bounded soak
//! while echoing the server's log lines to serial.
//!
//! WebXO is a long-lived daemon: its main thread binds + listens, then the
//! worker threads loop on accept(2) forever.  `spawn_webxo` is the reusable
//! half — it loads the ELF, spawns it, attaches a capture pipe, and returns
//! the pid + pipe id so a caller (the persistent SSH/web instance) can pump
//! its log alongside other daemons.  `run_webxo_demo` is the standalone
//! soak used by the `webxo-test` cargo feature for isolated bring-up.
//!
//! References (public):
//!   - HTTP/1.1 semantics:  RFC 9110, RFC 7230
//!   - POSIX sockets:       socket(2), setsockopt(2) (SO_REUSEADDR),
//!                          bind(2), listen(2), accept(2), recv(2), send(2)
//!   - QEMU SLIRP hostfwd:
//!     https://www.qemu.org/docs/master/system/devices/net.html#network-options

extern crate alloc;
use alloc::vec::Vec;

use crate::serial_println;

/// Absolute path of the staged WebXO binary on the data disk.  Matches
/// scripts/install-webxo.sh which copies to /usr/bin/webxo; create-data-
/// disk.sh propagates the file into the data image at the same path.
pub const WEBXO_PATH: &str = "/disk/usr/bin/webxo";

/// Document root the server serves from.  Staged by install-webxo.sh at
/// /var/www/ASTRYX (→ /disk/var/www/ASTRYX on the data disk).
pub const WEBXO_DOCROOT: &str = "/disk/var/www/ASTRYX";

/// Guest TCP port WebXO binds.  Forwarded to a host port by the harness
/// `--http-host-port` / auto-default hostfwd rule (guest :8080).
pub const WEBXO_PORT: &str = "8080";

/// Envp for WebXO.  Kept small + deterministic.
///   - HOME=/root            — consistent with the SSH instance.
///   - PATH=/bin:/usr/bin:/usr/sbin
///   - LD_LIBRARY_PATH       — the server's shared libs (libstdc++, libgcc_s,
///                              libz, musl) are staged under /disk/lib and
///                              /disk/usr/lib; point the loader there.  The
///                              musl loader also honours /etc/ld-musl-*.path,
///                              but an explicit LD_LIBRARY_PATH is belt-and-
///                              braces on the guest.
///   - LANG=C / LC_ALL=C     — byte-deterministic logs.
fn default_envp() -> &'static [&'static str] {
    &[
        "HOME=/root",
        "PATH=/bin:/usr/bin:/usr/sbin",
        "LD_LIBRARY_PATH=/disk/lib:/disk/usr/lib:/lib:/usr/lib",
        "TERM=dumb",
        "LANG=C",
        "LC_ALL=C",
    ]
}

/// Load + spawn WebXO blocked, attach a stdout-capture pipe, and unblock it.
/// Returns `(pid, pipe_id)` on success.  This is the reusable half so the
/// persistent SSH/web instance can launch the web server and then pump its
/// log alongside dropbear's.
pub fn spawn_webxo() -> Option<(u64, u64)> {
    let elf = match crate::vfs::read_file(WEBXO_PATH) {
        Ok(d) => d,
        Err(e) => {
            serial_println!(
                "[WEBXO] FATAL: cannot read {}: {:?} (run scripts/create-data-disk.sh then install-webxo.sh)",
                WEBXO_PATH, e
            );
            return None;
        }
    };
    serial_println!("[WEBXO] Loaded {} ({} bytes)", WEBXO_PATH, elf.len());

    if !crate::proc::elf::is_elf(&elf) {
        serial_println!("[WEBXO] FATAL: {} is not an ELF binary", WEBXO_PATH);
        return None;
    }

    // WebXO command-line (see its pMain ParseCLIOptions):
    //   --basepath=DIR  document root served for GET/HEAD.
    //   --port=N        TCP port to bind (INADDR_ANY ⇒ 0.0.0.0).
    //   --nthreads=N    worker-thread pool size; each worker blocks on
    //                   accept(2) on the shared listen fd.
    //
    // We launch with a SINGLE worker thread.  WebXO's worker pool shares one
    // HTTP/Directory object across all workers with no internal locking, so a
    // multi-worker pool races on that shared object once threads are reused —
    // the directory scan intermittently reads empty and the request 500s.  A
    // single worker serialises every request through the shared object and is
    // fully reliable.  (The kernel's directory-read path is concurrency-safe;
    // the race is WebXO-internal, so this is the correct app-level config — a
    // single-threaded static server is more than adequate for this docroot.)
    let basepath_arg = alloc::format!("--basepath={}", WEBXO_DOCROOT);
    let port_arg = alloc::format!("--port={}", WEBXO_PORT);
    let argv: &[&str] = &["webxo", &basepath_arg, &port_arg, "--nthreads=1"];
    let envp = default_envp();

    serial_println!("[WEBXO] Spawning webxo with argv={:?}", argv);

    let pid = match crate::proc::usermode::create_user_process_with_args_blocked(
        "webxo", &elf, argv, envp,
    ) {
        Ok(pid) => pid,
        Err(e) => {
            serial_println!(
                "[WEBXO] FATAL: spawn failed: create_user_process_with_args_blocked={:?}",
                e
            );
            return None;
        }
    };
    serial_println!("[WEBXO] webxo spawned: pid={}", pid);

    let pipe_id = crate::ipc::pipe::create_pipe();
    crate::proc::attach_stdout_pipe(pid, pipe_id);
    crate::proc::unblock_process(pid);

    Some((pid, pipe_id))
}

/// Drain a daemon's stdout-capture pipe, echoing each line to serial with a
/// `[WEBXO] webxo |` prefix and accumulating into `captured` (capped).
/// Returns the number of bytes appended.  Shared by both the standalone soak
/// and the persistent-instance pump.
pub fn pump_webxo_log(pipe_id: u64, captured: &mut Vec<u8>) -> usize {
    let mut buf = [0u8; 512];
    let mut total = 0;
    while let Some(n) = crate::ipc::pipe::pipe_read_wake(pipe_id, &mut buf) {
        if n == 0 {
            break;
        }
        if captured.len() < 16_384 {
            let take = core::cmp::min(n, 16_384 - captured.len());
            captured.extend_from_slice(&buf[..take]);
            let text = core::str::from_utf8(&buf[..take]).unwrap_or("<non-utf8>");
            for line in text.lines() {
                serial_println!("[WEBXO] webxo | {}", line);
            }
        }
        total += n;
        if n < buf.len() {
            break;
        }
    }
    total
}

/// Standalone soak for the `webxo-test` cargo feature: spawn WebXO, run it
/// for a bounded window while echoing its log, and emit a verdict.  Used for
/// isolated syscall-gap bring-up of the web server (the combined SSH+web
/// instance launches it via `spawn_webxo` instead).
#[cfg(feature = "webxo-test")]
pub fn run_webxo_demo() {
    serial_println!("[WEBXO] webxo-test starting (web/httpd-bringup)");

    let (pid, pipe_id) = match spawn_webxo() {
        Some(v) => v,
        None => return,
    };

    if !crate::sched::is_active() {
        crate::sched::enable();
    }
    crate::hal::enable_interrupts();

    let t_start = crate::arch::x86_64::irq::get_ticks();
    let mut captured: Vec<u8> = Vec::with_capacity(4096);
    let mut last_marker_tick: u64 = 0;
    // 60 s soak @ TICK_HZ=100 — enough for a host-side curl to drive a few
    // requests and for the worker accept-loop to be observed live.
    const WEBXO_SOAK_TICKS: u64 = 6_000;

    loop {
        crate::sched::yield_cpu();
        pump_webxo_log(pipe_id, &mut captured);

        let (state, exit_code) = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter().find(|p| p.pid == pid) {
                Some(p) => (p.state, p.exit_code),
                None => (crate::proc::ProcessState::Zombie, 0),
            }
        };
        if state == crate::proc::ProcessState::Zombie {
            serial_println!(
                "[WEBXO] webxo EXITED unexpectedly: pid={} exit={} (state=Zombie)",
                pid, exit_code
            );
            break;
        }

        let elapsed = crate::arch::x86_64::irq::get_ticks().wrapping_sub(t_start);
        if elapsed >= WEBXO_SOAK_TICKS {
            serial_println!(
                "[WEBXO] Soak budget reached ({} ticks); webxo still RUNNING (pid={})",
                WEBXO_SOAK_TICKS, pid
            );
            break;
        }
        if elapsed.wrapping_sub(last_marker_tick) >= 1_000 {
            last_marker_tick = elapsed;
            serial_println!(
                "[WEBXO] LIVENESS pid={} state={:?} elapsed_ticks={} captured_bytes={}",
                pid, state, elapsed, captured.len()
            );
        }
        for _ in 0..1_000u32 {
            core::hint::spin_loop();
        }
    }

    let text = core::str::from_utf8(&captured).unwrap_or("<non-utf8>");
    let saw_listen = text.contains("Bound the Socket") || text.contains("istening for Clients");
    let saw_serve = text.contains("servering a client") || text.contains("Connected to Client");
    let final_state = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid).map(|p| p.state)
            .unwrap_or(crate::proc::ProcessState::Zombie)
    };
    let still_running = final_state != crate::proc::ProcessState::Zombie;

    serial_println!(
        "[WEBXO] === SUMMARY === bound_listen={} served_client={} final_state={:?} captured_bytes={}",
        saw_listen as u8, saw_serve as u8, final_state, captured.len()
    );
    if still_running && saw_listen {
        serial_println!(
            "[WEBXO] === WEBXO-TEST: LISTENING (bind+listen markers + process Active at soak end) ==="
        );
    } else if saw_listen {
        serial_println!(
            "[WEBXO] === WEBXO-TEST: PARTIAL (bind/listen seen but webxo exited) ==="
        );
    } else {
        serial_println!(
            "[WEBXO] === WEBXO-TEST: PRE-LISTEN-EXIT (no bind/listen marker; check ELF loader / musl / socket path) ==="
        );
    }
}
