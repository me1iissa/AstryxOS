//! oracle-test — Oracle endpoint agent first-boot demo (PIVOT-I2, 2026-05-23).
//!
//! Launches a production GLIBC-linked endpoint-agent binary (caller-supplied
//! at staging time via `scripts/install-oracle.sh`, ~5 MiB) with
//! `--mode console --once` so it runs a single observation cycle and exits.
//! Captures stdout to serial and characterises whichever syscall/file gate
//! fires first.  This is a first-boot VALIDATION pass — the goal is to
//! reach the first non-recoverable failure and name it, not to make oracle
//! fully functional.
//!
//! Why GLIBC, not musl?
//! --------------------
//! Unlike dropbear/openssl which are Alpine musl binaries, oracle ships as a
//! glibc binary (DT_NEEDED libc.so.6, libssl.so.3, libcrypto.so.3,
//! interp = /lib64/ld-linux-x86-64.so.2; max GLIBC_2.39).  The data-disk
//! staging therefore relies on the install-glibc.sh tree at
//! /lib64/ + /lib/x86_64-linux-gnu/ plus the host's glibc-linked libssl3
//! (staged by install-oracle.sh — install-tls-stack.sh's musl libssl is
//! incompatible).  No new kernel-side surface — the existing glibc-track
//! firefox-test pipeline already proves the dynamic linker.
//!
//! Predicted first-gate candidates ((internal scratch audit))
//! ---------------------------------------------------------
//!   - `/sys/class/net/` ENOENT — oracle's NetworkCollector walks this dir
//!     looking for interfaces.  AstryxOS exposes only `/sys/devices/system/cpu/`
//!     today; the audit names this as a P0 gap (~150 LOC for the shim).
//!   - `sd_notify` socket failure — the binary statically links the
//!     `sd_notify` crate (READY=1 / WATCHDOG=1 / STOPPING=1 emitter).
//!     `--mode console` should bypass this code path; if it doesn't,
//!     NOTIFY_SOCKET env-var absence makes the sd_notify call a no-op per
//!     systemd docs.
//!   - Some new ENOSYS in the tokio runtime — not predicted by the audit
//!     because PR #437 (I1b) just landed pidfd_open/signalfd-legacy/
//!     epoll_pwait2/prctl(PR_GET_NAME); this demo proves that closure.
//!   - libssl init failure — host glibc-linked OpenSSL 3.5.5 should load
//!     against the staged libssl3.  If init fails the binary crashes before
//!     main() runs.
//!
//! Verdict semantics
//! -----------------
//!   - PASS         — oracle exits 0 with at least one observation cycle line
//!                    on stdout (e.g. "Polling network adapters..." with
//!                    actual data).  Means the agent is hosting end-to-end.
//!   - PASS-INIT    — oracle reaches `Oracle agent starting in console mode`
//!                    banner + Cli::parse succeeded but exits non-zero with
//!                    a named, recoverable error (ENOENT on /sys/class/net,
//!                    etc.).  Means dynamic linker + glibc + tokio init
//!                    + clap parse all worked; one bounded gap to fix.
//!   - PRE-MAIN     — process exits before any stdout.  Means the dynamic
//!                    linker / glibc / static-init / sd_notify-init failed
//!                    BEFORE main() ran.  Worst-case diagnostic; needs
//!                    deeper investigation.
//!   - TIMEOUT      — process still running after soak budget.  Likely a
//!                    futex/IO hang; capture is whatever stdout produced.
//!
//! References (public)
//! -------------------
//!   - tokio runtime:        https://tokio.rs/
//!   - sd_notify(3):         https://www.freedesktop.org/software/systemd/man/sd_notify.html
//!   - systemd.service(5):   https://www.freedesktop.org/software/systemd/man/systemd.service.html
//!   - POSIX execve(2), exit_group(2)
//!   - clap CLI parser:      https://docs.rs/clap/

#![cfg(any(feature = "oracle-test", feature = "oracle-daemon-test"))]

extern crate alloc;
use alloc::vec::Vec;

use crate::serial_println;

/// Absolute path of the staged oracle binary on the data disk.  Matches
/// scripts/install-oracle.sh which copies to /usr/bin/oracle; create-data-
/// disk.sh's --oracle flag propagates the file into the FAT32 image.
const ORACLE_PATH: &str = "/disk/usr/bin/oracle";

/// Soak budget in TICK_HZ=100 ticks.  oracle --once runs a single observation
/// cycle and exits; on a working substrate it should complete in well under
/// 10 s.  Budget 30 s so a slow CI host plus the glibc dynamic-linker walk
/// (oracle has ~50 DT_NEEDED transitive deps) doesn't trip a false timeout.
const ORACLE_SOAK_TICKS: u64 = 3_000;

/// Envp for oracle.  Notable entries:
///   - `INFRASVC_LOG_LEVEL=debug` — surfaces every collector init line.
///     The agent prefers this over the config file's logging.level when set.
///   - `RUST_BACKTRACE=1` — if oracle panics, we get the backtrace on
///     stderr (which routes to the same pipe as stdout).
///   - `NOTIFY_SOCKET` is INTENTIONALLY UNSET — the sd_notify crate
///     treats absence as "not under systemd" and skips the notify
///     socket connect entirely, so we don't need an AF_UNIX SOCK_DGRAM
///     listener to prevent ENOTCONN.
///   - `SSL_CERT_FILE` / `SSL_CERT_DIR` — defensive; oracle uses these
///     for native-tls CA discovery but with sync.enabled=false in
///     config.toml the TLS code path is unreached on first boot.
///   - `LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/lib64:/usr/lib/x86_64-linux-gnu`
///     — defensive; the dynamic linker should find libssl/libcrypto via
///     ld.so.conf or the standard system search path, but a stale data.img
///     may have an empty ld.so.cache.
fn default_envp() -> &'static [&'static str] {
    &[
        "HOME=/root",
        "PATH=/bin:/usr/bin:/usr/sbin",
        "TMPDIR=/tmp",
        "TERM=dumb",
        "LANG=C",
        "LC_ALL=C",
        "INFRASVC_LOG_LEVEL=debug",
        "RUST_BACKTRACE=1",
        "SSL_CERT_FILE=/etc/ssl/cert.pem",
        "SSL_CERT_DIR=/etc/ssl/certs",
        "LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/lib64:/usr/lib/x86_64-linux-gnu",
    ]
}

/// Public entry point for `--features oracle-test`.  Loads
/// /disk/usr/bin/oracle, launches it with `--mode console --once`, captures
/// stdout, and reports the first-boot verdict.
#[cfg(feature = "oracle-test")]
pub fn run_oracle_demo() {
    serial_println!("[ORACLE] oracle-test starting (PIVOT-I2, 2026-05-23)");

    let elf = match crate::vfs::read_file(ORACLE_PATH) {
        Ok(d) => d,
        Err(e) => {
            serial_println!(
                "[ORACLE] FATAL: cannot read {}: {:?} (run scripts/create-data-disk.sh --oracle --force)",
                ORACLE_PATH, e
            );
            serial_println!("[ORACLE] === ORACLE-TEST: FAIL (staging) ===");
            return;
        }
    };
    serial_println!("[ORACLE] Loaded {} ({} bytes)", ORACLE_PATH, elf.len());

    if !crate::proc::elf::is_elf(&elf) {
        serial_println!("[ORACLE] FATAL: {} is not an ELF binary", ORACLE_PATH);
        serial_println!("[ORACLE] === ORACLE-TEST: FAIL (staging) ===");
        return;
    }

    // CLI flags chosen for minimum-surface first-boot validation:
    //   --mode console — interactive mode (vs `service` which would try to
    //                    register with systemd's SCM-equivalent).
    //   --once         — run one observation cycle and exit.  Without
    //                    --once the agent loops on polling.interval_secs
    //                    forever, blocking the demo until the soak
    //                    deadline fires.
    //   --log-level debug — overrides config.toml; surfaces every
    //                    collector-init line on stdout for diagnostic
    //                    visibility.
    //   --config /etc/oracle/config.toml — explicit; the binary's default
    //                    is the same path on Linux but we set it
    //                    defensively in case env-var-based override is
    //                    surprising.
    let argv: &[&str] = &[
        "oracle",
        "--mode", "console",
        "--once",
        "--log-level", "debug",
        "--config", "/etc/oracle/config.toml",
    ];
    let envp = default_envp();

    serial_println!("[ORACLE] Spawning oracle with argv={:?}", argv);

    let pid = match crate::proc::usermode::create_user_process_with_args_blocked(
        "oracle",
        &elf,
        argv,
        envp,
    ) {
        Ok(pid) => pid,
        Err(e) => {
            serial_println!(
                "[ORACLE] FATAL: spawn failed: create_user_process_with_args_blocked={:?}",
                e
            );
            serial_println!("[ORACLE] === ORACLE-TEST: FAIL (spawn) ===");
            return;
        }
    };
    serial_println!("[ORACLE] oracle spawned: pid={}", pid);

    let pipe_id = crate::ipc::pipe::create_pipe();
    crate::proc::attach_stdout_pipe(pid, pipe_id);
    crate::proc::unblock_process(pid);

    if !crate::sched::is_active() {
        crate::sched::enable();
    }
    crate::hal::enable_interrupts();

    let t_start = crate::arch::x86_64::irq::get_ticks();
    // oracle is verbose at log-level=debug — bump capture cap to 32 KiB so
    // we don't truncate the collector-init transcript.
    let cap = 32_768usize;
    let mut captured: Vec<u8> = Vec::with_capacity(4096);
    let mut buf = [0u8; 512];
    let mut last_marker_tick: u64 = 0;
    let mut timed_out = true;

    loop {
        crate::sched::yield_cpu();

        if let Some(n) = crate::ipc::pipe::pipe_read(pipe_id, &mut buf) {
            if n > 0 && captured.len() < cap {
                let take = core::cmp::min(n, cap - captured.len());
                captured.extend_from_slice(&buf[..take]);

                // Echo each line so the harness wait/grep can correlate
                // collector events with kernel-side syscall markers.
                let text = core::str::from_utf8(&buf[..take]).unwrap_or("<non-utf8>");
                for line in text.lines() {
                    serial_println!("[ORACLE] oracle | {}", line);
                }
            }
        }

        let done = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter().find(|p| p.pid == pid) {
                Some(p) => p.state == crate::proc::ProcessState::Zombie,
                None => true,
            }
        };
        if done {
            timed_out = false;
            break;
        }

        let elapsed = crate::arch::x86_64::irq::get_ticks().wrapping_sub(t_start);
        if elapsed >= ORACLE_SOAK_TICKS {
            break;
        }

        // Periodic liveness marker every ~10 s so a stuck oracle is
        // distinguishable from a slow one in serial logs.
        if elapsed.wrapping_sub(last_marker_tick) >= 1_000 {
            last_marker_tick = elapsed;
            serial_println!(
                "[ORACLE] LIVENESS pid={} elapsed_ticks={} captured_bytes={}",
                pid, elapsed, captured.len()
            );
        }

        for _ in 0..1_000u32 {
            core::hint::spin_loop();
        }
    }

    // Drain any tail bytes the child wrote after we noticed it exited.
    {
        let mut tail = [0u8; 4096];
        while let Some(n) = crate::ipc::pipe::pipe_read(pipe_id, &mut tail) {
            if n == 0 {
                break;
            }
            if captured.len() < cap {
                let take = core::cmp::min(n, cap - captured.len());
                captured.extend_from_slice(&tail[..take]);
            }
        }
    }

    let (final_state, exit_code) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        match procs.iter().find(|p| p.pid == pid) {
            Some(p) => (p.state, p.exit_code),
            None => (crate::proc::ProcessState::Zombie, 0),
        }
    };

    crate::ipc::pipe::pipe_close_reader(pipe_id);
    let _ = crate::proc::waitpid(0, pid as i64);

    let text = core::str::from_utf8(&captured).unwrap_or("<non-utf8>");
    // Marker hunt: each predicted gate has a stable substring.  Listed in
    // approximate "how far did oracle get" order — match the latest one
    // hit and emit it in the SUMMARY.
    let saw_banner          = text.contains("Oracle endpoint agent") ||
                              text.contains("Oracle agent starting");
    let saw_collector_init  = text.contains("Polling") ||
                              text.contains("collector") ||
                              text.contains("Network") ||
                              text.contains("System");
    let saw_observation     = text.contains("adapter") ||
                              text.contains("interface") ||
                              text.contains("operstate") ||
                              text.contains("address:");
    let saw_sys_class_net   = text.contains("/sys/class/net");
    let saw_panic           = text.contains("panic") || text.contains("PANIC");
    let saw_enosys          = text.contains("ENOSYS") || text.contains("unsupported syscall");
    let saw_libssl_fail     = text.contains("libssl") || text.contains("undefined symbol");

    serial_println!(
        "[ORACLE] === SUMMARY === banner={} collector_init={} observation={} sys_class_net={} panic={} enosys={} libssl_fail={} exit={} state={:?} captured_bytes={} timed_out={}",
        saw_banner as u8,
        saw_collector_init as u8,
        saw_observation as u8,
        saw_sys_class_net as u8,
        saw_panic as u8,
        saw_enosys as u8,
        saw_libssl_fail as u8,
        exit_code,
        final_state,
        captured.len(),
        timed_out as u8,
    );

    // Verdict logic — pick the most informative bucket the data supports.
    if timed_out {
        serial_println!(
            "[ORACLE] === ORACLE-TEST: TIMEOUT (process still running after {} ticks; captured {} bytes) ===",
            ORACLE_SOAK_TICKS, captured.len()
        );
    } else if exit_code == 0 && saw_observation {
        serial_println!(
            "[ORACLE] === ORACLE-TEST: PASS (oracle completed observation cycle exit=0) ==="
        );
    } else if saw_banner || saw_collector_init {
        serial_println!(
            "[ORACLE] === ORACLE-TEST: PASS-INIT (reached banner/collector init; exit={} — name the gate above) ===",
            exit_code
        );
    } else if captured.is_empty() {
        serial_println!(
            "[ORACLE] === ORACLE-TEST: PRE-MAIN (no stdout; dynamic linker / glibc / static-init failure; exit={}) ===",
            exit_code
        );
    } else {
        serial_println!(
            "[ORACLE] === ORACLE-TEST: PARTIAL (some stdout but no banner; exit={}; first bytes may name the loader gate) ===",
            exit_code
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Daemon-mode bring-up (PIVOT-I2 Phase D, 2026-05-23)
// ─────────────────────────────────────────────────────────────────────────────
//
// `--features oracle-daemon-test` stretches the first-boot --once flow into a
// real long-running agent against a host-side stub Conflux endpoint.  Reaches
// (and exercises) the parts of the agent the --once path does NOT:
//
//   - tokio multi-thread runtime worker bring-up (clone3 + tokio's
//     blocking-pool ramp).
//   - the polling loop's heartbeat task — the timer-driven
//     periodic publish path.
//   - HTTP sync backend — reqwest + hyper + tokio-net TCP outbound
//     against `http://10.0.2.2:<port>/heartbeat` (the QEMU SLIRP gateway
//     alias for the host stub).
//
// Sync is enabled via *env-vars*, NOT by mutating /etc/oracle/config.toml.
// Oracle reads INFRASVC_SYNC_ENABLED and INFRASVC_SYNC_URL (per its
// CONFIG_ENV mapping; the env-var names are statically interned in the
// shipped binary — confirmed by `strings(1)`).  This keeps the existing
// first-boot config staged by `install-oracle.sh` (which sets
// `sync.enabled=false`) intact: the daemon demo overrides at run-time,
// the first-boot --once flow keeps its sync-disabled posture.
//
// Soak budget is configurable but defaults to 90 s wall-clock.  At
// `INFRASVC_POLL_INTERVAL=10` (we override the default 60 s to keep test
// turnaround tight) the heartbeat emitter publishes roughly every 10 s,
// so 90 s gives 5–8 heartbeats — comfortably above the "at least one
// reached the host" success threshold while leaving slack for tokio's
// own bring-up latency (worker-thread spawn + dynamic-linker walk).
//
// Why plain HTTP, not HTTPS?
// --------------------------
// Per audit §7, this defers the I1 (ca-certificates + libssl soak) work.
// The reqwest client this oracle release was built with accepts both
// `http://` and `https://`; we just point at the plain-HTTP URL and the
// hyper-tls layer no-ops out of the connect path (per the strings dump
// `hyper-util/.../connect/http.rs:481` plain-HTTP path is the
// non-conditional branch when scheme==http).  No upstream-side code
// change required.

/// Soak budget for the daemon mode.  TICK_HZ=100, so 18_000 = 180 s
/// (3 minutes).  Initially 90 s; bumped to 180 s after empirical
/// observation that the first heartbeat send routinely arrives in the
/// ~80-100 s window once the host-side stub Conflux is reachable, but
/// the heartbeat-send log line + post-send pipe drain can lag by an
/// extra ~30 s on a heavily-spinning tokio worker (verified
/// PIVOT-I2 Phase D, 2026-05-23).  180 s comfortably brackets that
/// without making CI runs balloon.
#[cfg(feature = "oracle-daemon-test")]
const ORACLE_DAEMON_SOAK_TICKS: u64 = 18_000;

/// Heartbeat cadence we coerce oracle into via env-var override
/// (INFRASVC_POLL_INTERVAL).  10 s gives 5–8 heartbeats in a 90 s soak
/// — fast enough to demo, slow enough to not look like a flood.
#[cfg(feature = "oracle-daemon-test")]
const ORACLE_DAEMON_INTERVAL_SECS: &str = "10";

/// Default Conflux stub endpoint URL — BASE only.  Oracle's
/// `the HTTP sync send_heartbeat path` appends the canonical
/// Conflux v1 path `/v1/hosts/<hostname>/heartbeat` itself, so this
/// constant must NOT carry a trailing `/heartbeat` (or any path) — see
/// `scripts/oracle-stub-conflux.py::do_POST` for the matching server
/// routes.  Viewed through the QEMU SLIRP NAT gateway alias 10.0.2.2
/// (host loopback as seen from the guest — same alias used by
/// busybox-test and tls-test).
#[cfg(feature = "oracle-daemon-test")]
const ORACLE_DAEMON_SYNC_URL: &str = "http://10.0.2.2:8088";

/// Envp for daemon-mode oracle.  Extends `default_envp()` with the
/// sync-override entries.  We hand-roll the slice rather than calling
/// `default_envp()` + push because the kernel-side process spawner takes
/// `&[&str]` and we want to avoid heap allocation for the envp before
/// the address space is built.
#[cfg(feature = "oracle-daemon-test")]
fn daemon_envp() -> &'static [&'static str] {
    &[
        "HOME=/root",
        "PATH=/bin:/usr/bin:/usr/sbin",
        "TMPDIR=/tmp",
        "TERM=dumb",
        "LANG=C",
        "LC_ALL=C",
        "INFRASVC_LOG_LEVEL=info",
        "RUST_BACKTRACE=1",
        "SSL_CERT_FILE=/etc/ssl/cert.pem",
        "SSL_CERT_DIR=/etc/ssl/certs",
        "LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/lib64:/usr/lib/x86_64-linux-gnu",
        // ── PIVOT-I2 Phase D overrides ──────────────────────────────────
        // These three env-vars steer the agent into "sync enabled, plain
        // HTTP, fast heartbeat" without touching /etc/oracle/config.toml.
        // The shipped binary reads them at startup (confirmed via
        // strings dump: INFRASVC_SYNC_ENABLED, INFRASVC_SYNC_URL,
        // INFRASVC_POLL_INTERVAL).
        "INFRASVC_SYNC_ENABLED=true",
        // BASE URL only — oracle appends `/v1/hosts/<hostname>/heartbeat`.
        // See ORACLE_DAEMON_SYNC_URL above for rationale.
        "INFRASVC_SYNC_URL=http://10.0.2.2:8088",
        "INFRASVC_POLL_INTERVAL=10",
    ]
}

/// Public entry point for `--features oracle-daemon-test`.  Loads
/// /disk/usr/bin/oracle, launches it with `--mode console` (no --once),
/// captures stdout, and looks for the "Heartbeat sent for" /
/// "Conflux rejected heartbeat" log lines that mark a successful
/// reqwest POST to the host stub.  Reports a daemon-specific verdict
/// surface (HEARTBEAT-OK / HEARTBEAT-FAIL / NO-HEARTBEAT / PRE-MAIN).
#[cfg(feature = "oracle-daemon-test")]
pub fn run_oracle_daemon() {
    serial_println!("[ORACLED] oracle-daemon-test starting (PIVOT-I2 Phase D, 2026-05-23)");
    serial_println!(
        "[ORACLED] target sync URL: {} (host stub: scripts/oracle-stub-conflux.py --port 8088)",
        ORACLE_DAEMON_SYNC_URL
    );

    let elf = match crate::vfs::read_file(ORACLE_PATH) {
        Ok(d) => d,
        Err(e) => {
            serial_println!(
                "[ORACLED] FATAL: cannot read {}: {:?} (run scripts/create-data-disk.sh --oracle --force)",
                ORACLE_PATH, e
            );
            serial_println!("[ORACLED] === ORACLE-DAEMON: FAIL (staging) ===");
            return;
        }
    };
    serial_println!("[ORACLED] Loaded {} ({} bytes)", ORACLE_PATH, elf.len());

    if !crate::proc::elf::is_elf(&elf) {
        serial_println!("[ORACLED] FATAL: {} is not an ELF binary", ORACLE_PATH);
        serial_println!("[ORACLED] === ORACLE-DAEMON: FAIL (staging) ===");
        return;
    }

    // Daemon-mode CLI: drop --once and point at the daemon-specific
    // /etc/oracle/daemon.toml (staged by install-oracle.sh — has
    // `[sync] enabled = true` + `server_url = "http://10.0.2.2:8088/heartbeat"`
    // + `interval_secs = 10`).  Using a separate config file keeps the
    // first-boot --once flow's offline-only config.toml untouched, which
    // matters because PR #439 PINS sync.enabled=false there as the
    // first-boot contract.
    //
    // Why not env-vars?  The shipped oracle binary interns
    // INFRASVC_SYNC_ENABLED / INFRASVC_SYNC_URL in the strings table but
    // empirically does NOT honour them once a config-file is supplied
    // (verified 2026-05-23: even with sync env vars set, no "failed to
    // build HttpSync" or heartbeat lines fire).  The two-config-file
    // approach is robust to that env-var-precedence ambiguity.
    let argv: &[&str] = &[
        "oracle",
        "--mode", "console",
        "--log-level", "info",
        "--interval", ORACLE_DAEMON_INTERVAL_SECS,
        "--config", "/etc/oracle/daemon.toml",
    ];
    let envp = daemon_envp();

    serial_println!("[ORACLED] Spawning oracle (daemon) with argv={:?}", argv);

    let pid = match crate::proc::usermode::create_user_process_with_args_blocked(
        "oracle-daemon",
        &elf,
        argv,
        envp,
    ) {
        Ok(pid) => pid,
        Err(e) => {
            serial_println!(
                "[ORACLED] FATAL: spawn failed: create_user_process_with_args_blocked={:?}",
                e
            );
            serial_println!("[ORACLED] === ORACLE-DAEMON: FAIL (spawn) ===");
            return;
        }
    };
    serial_println!("[ORACLED] oracle (daemon) spawned: pid={}", pid);

    let pipe_id = crate::ipc::pipe::create_pipe();
    crate::proc::attach_stdout_pipe(pid, pipe_id);
    crate::proc::unblock_process(pid);

    if !crate::sched::is_active() {
        crate::sched::enable();
    }
    crate::hal::enable_interrupts();

    let t_start = crate::arch::x86_64::irq::get_ticks();
    // Daemon mode is verbose — bump capture cap to 64 KiB (vs 32 KiB for
    // the --once path) so a chatty tokio runtime + multiple heartbeats
    // worth of poll-cycle log don't truncate.
    let cap = 65_536usize;
    let mut captured: Vec<u8> = Vec::with_capacity(8_192);
    let mut buf = [0u8; 512];
    let mut last_marker_tick: u64 = 0;
    let mut heartbeats_emitted: u32 = 0;
    let mut heartbeats_rejected: u32 = 0;
    let mut last_heartbeat_text_len: usize = 0;
    let mut connect_errors: u32 = 0;

    loop {
        crate::sched::yield_cpu();

        // Drive the NIC RX ring and TCP timers from the BSP main loop.
        // The Oracle daemon is a tokio binary that calls epoll_wait(2) on
        // its worker threads; those calls pump net::poll() on each wakeup
        // (NDE-5 fix).  This additional call from the BSP loop ensures that
        // net::poll() advances even when ALL tokio workers happen to be
        // running (not blocked in epoll_wait) — e.g. during the HTTP POST
        // body serialisation phase.  Without it, the BSP spins in yield_cpu
        // + pipe_read while the NIC ring accumulates unprocessed ACKs, and
        // tcp_timer_tick() has no caller to drain the send_buffer.
        crate::net::poll();

        if let Some(n) = crate::ipc::pipe::pipe_read(pipe_id, &mut buf) {
            if n > 0 && captured.len() < cap {
                let take = core::cmp::min(n, cap - captured.len());
                captured.extend_from_slice(&buf[..take]);

                // Echo each line so the harness wait/grep can correlate
                // collector events with kernel-side syscall markers.
                let text = core::str::from_utf8(&buf[..take]).unwrap_or("<non-utf8>");
                for line in text.lines() {
                    serial_println!("[ORACLED] oracle | {}", line);
                }
            }
        }

        // Incremental marker accounting — scan only the new portion of
        // captured since the last marker tick, so we count each heartbeat
        // exactly once regardless of how the pipe chunks the bytes.
        if captured.len() > last_heartbeat_text_len {
            let slice = &captured[last_heartbeat_text_len..];
            let text = core::str::from_utf8(slice).unwrap_or("");
            // Count occurrences of each marker substring.  Each
            // `windows(n).filter(...)` walk is O(N*M) but N is small here
            // (one tick's worth of fresh bytes).
            for line in text.lines() {
                if line.contains("Heartbeat sent for") {
                    heartbeats_emitted += 1;
                }
                if line.contains("Conflux rejected heartbeat") {
                    heartbeats_rejected += 1;
                }
                if line.contains("error sending request")
                    || line.contains("Connection refused")
                    || line.contains("tcp connect error")
                {
                    connect_errors += 1;
                }
            }
            last_heartbeat_text_len = captured.len();
        }

        let done = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter().find(|p| p.pid == pid) {
                Some(p) => p.state == crate::proc::ProcessState::Zombie,
                None => true,
            }
        };
        if done {
            serial_println!("[ORACLED] oracle exited unexpectedly during soak");
            break;
        }

        let elapsed = crate::arch::x86_64::irq::get_ticks().wrapping_sub(t_start);
        if elapsed >= ORACLE_DAEMON_SOAK_TICKS {
            serial_println!(
                "[ORACLED] soak budget reached ({} ticks ~= {} s); winding down",
                ORACLE_DAEMON_SOAK_TICKS, ORACLE_DAEMON_SOAK_TICKS / 100
            );
            // Best-effort kill: SIGKILL via the existing signal::kill
            // path.  SIGKILL (vs SIGTERM) so we don't depend on oracle
            // installing a graceful-shutdown signal handler — the soak
            // is done either way and we just want to release the pipe
            // reader and reap the zombie.
            //
            // POSIX kill(2): https://pubs.opengroup.org/onlinepubs/9699919799/functions/kill.html
            let _ = crate::signal::kill(pid as u64, crate::signal::SIGKILL);
            break;
        }

        // Periodic liveness marker every ~10 s.  Differs from --once mode:
        // we surface the in-flight heartbeat count so a stalled oracle
        // (TCP timeout, tokio worker wedge) is visible before the soak
        // budget expires.
        if elapsed.wrapping_sub(last_marker_tick) >= 1_000 {
            last_marker_tick = elapsed;
            serial_println!(
                "[ORACLED] LIVENESS pid={} elapsed_s={} heartbeats_ok={} heartbeats_rej={} conn_err={} captured_bytes={}",
                pid,
                elapsed / 100,
                heartbeats_emitted,
                heartbeats_rejected,
                connect_errors,
                captured.len()
            );
        }

        for _ in 0..1_000u32 {
            core::hint::spin_loop();
        }
    }

    // Drain any tail bytes the child wrote after the soak deadline.
    {
        let mut tail = [0u8; 4096];
        while let Some(n) = crate::ipc::pipe::pipe_read(pipe_id, &mut tail) {
            if n == 0 {
                break;
            }
            if captured.len() < cap {
                let take = core::cmp::min(n, cap - captured.len());
                captured.extend_from_slice(&tail[..take]);
            }
        }
    }

    // One more marker sweep over the drained tail for accuracy.
    if captured.len() > last_heartbeat_text_len {
        let slice = &captured[last_heartbeat_text_len..];
        let text = core::str::from_utf8(slice).unwrap_or("");
        for line in text.lines() {
            if line.contains("Heartbeat sent for") {
                heartbeats_emitted += 1;
            }
            if line.contains("Conflux rejected heartbeat") {
                heartbeats_rejected += 1;
            }
            if line.contains("error sending request")
                || line.contains("Connection refused")
                || line.contains("tcp connect error")
            {
                connect_errors += 1;
            }
        }
    }

    let (final_state, exit_code) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        match procs.iter().find(|p| p.pid == pid) {
            Some(p) => (p.state, p.exit_code),
            None => (crate::proc::ProcessState::Zombie, 0),
        }
    };

    crate::ipc::pipe::pipe_close_reader(pipe_id);
    let _ = crate::proc::waitpid(0, pid as i64);

    let text = core::str::from_utf8(&captured).unwrap_or("<non-utf8>");
    let saw_banner          = text.contains("Oracle endpoint agent") ||
                              text.contains("Oracle agent starting");
    let saw_runtime_ready   = text.contains("tokio") ||
                              text.contains("worker") ||
                              text.contains("Polling");
    let saw_panic           = text.contains("panic") || text.contains("PANIC");

    serial_println!(
        "[ORACLED] === SUMMARY === banner={} runtime_ready={} heartbeats_ok={} heartbeats_rej={} conn_err={} panic={} exit={} state={:?} captured_bytes={}",
        saw_banner as u8,
        saw_runtime_ready as u8,
        heartbeats_emitted,
        heartbeats_rejected,
        connect_errors,
        saw_panic as u8,
        exit_code,
        final_state,
        captured.len(),
    );

    // Verdict tree — pick the most informative bucket the data supports.
    // The major-win threshold per dispatch is "1+ heartbeat received"; the
    // stub Conflux logs the host-side view independently in /tmp/oracle-stub.jsonl.
    if heartbeats_emitted > 0 {
        serial_println!(
            "[ORACLED] === ORACLE-DAEMON: HEARTBEAT-OK ({} heartbeats emitted to host stub; substrate proven end-to-end) ===",
            heartbeats_emitted
        );
    } else if heartbeats_rejected > 0 {
        serial_println!(
            "[ORACLED] === ORACLE-DAEMON: HEARTBEAT-REJECTED (reqwest reached host but Conflux rejected; check stub status code) ==="
        );
    } else if connect_errors > 0 {
        serial_println!(
            "[ORACLED] === ORACLE-DAEMON: CONNECT-FAIL ({} TCP-connect failures; host stub probably not listening on 10.0.2.2:8088 — start with `python3 scripts/oracle-stub-conflux.py --port 8088`) ===",
            connect_errors
        );
    } else if saw_runtime_ready {
        serial_println!(
            "[ORACLED] === ORACLE-DAEMON: RUNTIME-OK-NO-EMIT (tokio runtime up, collectors polling, but no heartbeat publish line in stdout — check INFRASVC_SYNC_ENABLED honoring) ==="
        );
    } else if saw_banner {
        serial_println!(
            "[ORACLED] === ORACLE-DAEMON: BANNER-ONLY (oracle banner printed but no runtime line; tokio bring-up wedge — check syscall trace for clone3/eventfd/epoll faults) ==="
        );
    } else if captured.is_empty() {
        serial_println!(
            "[ORACLED] === ORACLE-DAEMON: PRE-MAIN (no stdout; dynamic linker / glibc / static-init failure; exit={}) ===",
            exit_code
        );
    } else {
        serial_println!(
            "[ORACLED] === ORACLE-DAEMON: PARTIAL (some stdout but no banner; exit={}) ===",
            exit_code
        );
    }
}
