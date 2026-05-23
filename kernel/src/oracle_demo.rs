//! oracle-test — Oracle endpoint agent first-boot demo (PIVOT-I2, 2026-05-23).
//!
//! Launches the production GLIBC-linked `oracle` binary from the user's
//! infrastructure-services/infrasvc project (release 7b03aa65, ~5 MiB) with
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
//! Predicted first-gate candidates (from the infrasvc audit)
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

#![cfg(feature = "oracle-test")]

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
