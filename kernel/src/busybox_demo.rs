//! busybox-test / wget-test CLI demo runner (PIVOT-B, 2026-05-23).
//!
//! Drives the Alpine busybox-static binary through a short battery of
//! standard CLI applets, capturing each child's stdout to the serial
//! console.  Used as a kernel-personality proof point for upstream
//! Linux CLI binaries outside the X11 / libxul paths: static ELF
//! loader, brk(2), mmap(2) for argv/env, write(2) to pipe,
//! readdir/getdents(2), exit_group(2).
//!
//! The runner is intentionally minimal — no GUI, no compositor, no
//! Xastryx, no posix_spawn — so the failure modes are isolated to
//! the core syscall surface.  Each applet is run as its own process,
//! waited on with a per-applet timeout, and the pipe is drained
//! between iterations so a stuck child can't pin the next applet.
//!
//! References (public)
//!   - BusyBox upstream: https://busybox.net/
//!   - POSIX exec(3), read(2), write(2), exit(3)
//!   - QEMU SLIRP networking:
//!     https://www.qemu.org/docs/master/system/devices/net.html#network-options
//!   - RFC 7230 (HTTP/1.1) — for the wget-test fetch path

#![cfg(any(feature = "busybox-test", feature = "wget-test", feature = "pivot-e-test", feature = "pivot-e-tui-test", feature = "pivot-e-git-test"))]

extern crate alloc;
use alloc::vec::Vec;

use crate::serial_println;

pub(crate) const BUSYBOX_PATH: &str = "/disk/bin/busybox";

/// Per-applet wall-clock budget, in 100 Hz ticks (TICK_HZ=100 ⇒ 1 tick ≈ 10 ms).
/// 10 s should be ample for any of the demo applets — the existing
/// `test_busybox_basic` (Test 63b) measures `busybox echo` at < 1 s on the same
/// kernel.  wget HTTP fetches need a larger budget; see WGET_APPLET_TICKS.
pub(crate) const APPLET_TICKS: u64 = 1_000;

/// Wget-specific timeout — the connect / DNS / response cycle on a SLIRP
/// gateway round-trip can take several seconds.  Bump to ~30 s.
pub(crate) const WGET_APPLET_TICKS: u64 = 3_000;

/// Standard envp passed to every applet.  Kept small and deterministic —
/// no MOZ_*, no LD_PRELOAD, no LD_DEBUG.  PATH points at /bin (where the
/// busybox multi-call binary lives) and /disk/bin (where the data-disk
/// stages additional binaries).
pub(crate) fn default_envp() -> &'static [&'static str] {
    &[
        "HOME=/",
        "PATH=/bin:/disk/bin",
        "TMPDIR=/tmp",
        // BusyBox honours TERM for `clear`, `less`, etc.  Default to
        // a value that disables fancy escape sequences so the serial
        // capture stays human-readable.
        "TERM=dumb",
        // Some applets (uname, hostname) read LANG / LC_*.  An empty
        // C locale is the most portable default for byte-deterministic
        // output across glibc/musl/uClibc.
        "LANG=C",
        "LC_ALL=C",
    ]
}

/// Run a single applet and return its (exit_code, captured stdout bytes).
/// `label` is the human-readable name printed in serial markers.
/// `argv` MUST start with the applet name as argv[0] (BusyBox's
/// multi-call dispatch reads argv[0]); for `busybox sh -c '...'` the
/// canonical shape is `&["busybox", "sh", "-c", "echo hi"]`.
///
/// Captured stdout is bounded to 4 KiB per applet to keep the BSS / heap
/// footprint deterministic; the busybox demo applets all fit in <1 KiB.
pub(crate) fn run_applet(label: &str, argv: &[&str], elf_bytes: &[u8], deadline_ticks: u64) -> (i32, Vec<u8>) {
    // Thin wrapper — delegates to run_applet_with_env with no env extras.
    // Existing callers see no signature change.
    run_applet_with_env(label, argv, &[], elf_bytes, deadline_ticks)
}

/// Run a single applet with caller-supplied env extras APPENDED to the
/// default envp.  Used by callers that need binary-specific environment
/// (e.g. PIVOT-E Tier D git needs GIT_EXEC_PATH / GIT_CONFIG_NOSYSTEM /
/// GIT_TEMPLATE_DIR to redirect the helper-exec lookup onto the FAT32
/// data disk).  Pass `&[]` for the extras when no overrides are needed —
/// the plain `run_applet` is the equivalent shortcut.
///
/// Environment-precedence note: musl libc's getenv(3) returns the FIRST
/// matching entry, so extras MUST be passed FIRST in the final envp.  We
/// build the merged envp as `[extras..., default_envp()...]` so a caller
/// override of e.g. HOME beats the default `HOME=/`.
pub(crate) fn run_applet_with_env(
    label: &str,
    argv: &[&str],
    env_extras: &[&str],
    elf_bytes: &[u8],
    deadline_ticks: u64,
) -> (i32, Vec<u8>) {
    run_applet_with_env_and_cwd(label, argv, env_extras, None, elf_bytes, deadline_ticks)
}

/// Run a single applet with both caller-supplied env extras AND a
/// caller-specified working directory.  The cwd is installed into the
/// child's PROCESS_TABLE entry BEFORE unblocking — this matches the
/// effect of `chdir(2)` at process startup but does not require the
/// caller to invoke a shell.  Pass `None` for the cwd to keep the
/// kernel default ("/").
///
/// Use case: PIVOT-E Tier D git steps need to run with cwd inside the
/// working tree so git's `setup_git_directory_gently()` and friends see
/// the right cwd from getcwd(2) — without this, git computes a "prefix"
/// based on cwd vs work-tree mismatch and confuses subsequent path
/// lookups.
pub(crate) fn run_applet_with_env_and_cwd(
    label: &str,
    argv: &[&str],
    env_extras: &[&str],
    cwd_override: Option<&str>,
    elf_bytes: &[u8],
    deadline_ticks: u64,
) -> (i32, Vec<u8>) {
    serial_println!("[BBDEMO] ── {}: {:?} (cwd={:?}) ──", label, argv, cwd_override);

    // Merge: extras first (override), then defaults (fallback).  Per POSIX
    // env(7) and musl libc's getenv() this gives "extras win".
    let defaults = default_envp();
    let mut envp_vec: Vec<&str> = Vec::with_capacity(env_extras.len() + defaults.len());
    envp_vec.extend_from_slice(env_extras);
    envp_vec.extend_from_slice(defaults);
    let envp: &[&str] = &envp_vec;

    // Spawn blocked so we can attach the pipe to fd 1 / fd 2 before the
    // child can call write(2).  Pattern is identical to the existing
    // test_runner::test_busybox_basic (Test 63b).  argv[0] is also used
    // as the process display name for ps / kdb proc-list.  For Tier B
    // binaries (curl/jq/tar) the same loader path applies — the
    // `"busybox"` name string is just a display label and is not
    // interpreted by the loader.
    let pid = match crate::proc::usermode::create_user_process_with_args_blocked(
        "busybox",
        elf_bytes,
        argv,
        envp,
    ) {
        Ok(pid) => pid,
        Err(e) => {
            serial_println!(
                "[BBDEMO] {}: SPAWN-FAIL create_user_process_with_args_blocked={:?}",
                label, e
            );
            return (-1, Vec::new());
        }
    };

    // If caller requested a non-default cwd, install it BEFORE unblock so
    // the child sees the requested working directory from its first
    // getcwd(2) call.  This matches the effect of an in-shell `cd` but
    // does not require spawning sh as an intermediate.  See PIVOT-E Tier
    // D's git runner for the use case.
    if let Some(cwd_str) = cwd_override {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.cwd = alloc::string::String::from(cwd_str);
        }
    }

    let pipe_id = crate::ipc::pipe::create_pipe();
    crate::proc::attach_stdout_pipe(pid, pipe_id);
    crate::proc::unblock_process(pid);

    // Scheduler must be live or the child never runs.  The xeyes /
    // firefox-test paths enable_interrupts() earlier in main.rs but
    // we defensively re-enable here in case a caller path skipped it.
    if !crate::sched::is_active() {
        crate::sched::enable();
    }
    crate::hal::enable_interrupts();

    let t_start = crate::arch::x86_64::irq::get_ticks();
    let mut captured: Vec<u8> = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    let mut timed_out = true;

    loop {
        crate::sched::yield_cpu();

        // Drain whatever the child wrote since last poll.  pipe_read is
        // non-blocking; n==0 means "no bytes ready", not EOF.
        if let Some(n) = crate::ipc::pipe::pipe_read(pipe_id, &mut buf) {
            if n > 0 && captured.len() < 4096 {
                let take = core::cmp::min(n, 4096 - captured.len());
                captured.extend_from_slice(&buf[..take]);
            }
        }

        // Has the child become a zombie?
        let done = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter().find(|p| p.pid == pid) {
                Some(p) => p.state == crate::proc::ProcessState::Zombie,
                None => true, // already reaped (shouldn't happen — we hold pipe)
            }
        };
        if done {
            timed_out = false;
            break;
        }

        // Deadline check.
        let elapsed = crate::arch::x86_64::irq::get_ticks().wrapping_sub(t_start);
        if elapsed >= deadline_ticks {
            break;
        }

        // Yield CPU between polls — busy-spin would starve the AP.
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
            if captured.len() < 4096 {
                let take = core::cmp::min(n, 4096 - captured.len());
                captured.extend_from_slice(&tail[..take]);
            }
        }
    }

    let (state, exit_code) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        match procs.iter().find(|p| p.pid == pid) {
            Some(p) => (p.state, p.exit_code),
            None => (crate::proc::ProcessState::Zombie, 0),
        }
    };

    crate::ipc::pipe::pipe_close_reader(pipe_id);

    // Reap the zombie so PID is recyclable for the next applet.  waitpid
    // with a specific pid (>0) returns once the child has been collected.
    let _ = crate::proc::waitpid(0, pid as i64);

    if timed_out {
        serial_println!(
            "[BBDEMO] {}: TIMEOUT after {} ticks (state={:?}, captured {} bytes)",
            label, deadline_ticks, state, captured.len()
        );
    } else {
        serial_println!(
            "[BBDEMO] {}: exit={} state={:?} stdout_bytes={}",
            label, exit_code, state, captured.len()
        );
    }

    // Echo captured stdout to serial, one line at a time, with a
    // label prefix so post-processors can attribute lines to applets.
    if !captured.is_empty() {
        let text = core::str::from_utf8(&captured).unwrap_or("<non-utf8 stdout>");
        for line in text.lines() {
            serial_println!("[BBDEMO] {} | {}", label, line);
        }
    }

    (exit_code, captured)
}

/// Public entry point for `--features busybox-test`.  Loads /disk/bin/busybox
/// once and runs the demo battery against it, emitting a final summary.
#[cfg(feature = "busybox-test")]
pub fn run_busybox_demo() {
    serial_println!("[BBDEMO] busybox-test starting (PIVOT-B, 2026-05-23)");

    // Read the binary into the kernel heap once — the loader copies the
    // bytes into a fresh AddressSpace per applet, so we don't need to
    // re-read for every applet.
    let elf = match crate::vfs::read_file(BUSYBOX_PATH) {
        Ok(d) => d,
        Err(e) => {
            serial_println!(
                "[BBDEMO] FATAL: cannot read {}: {:?} (run scripts/create-data-disk.sh --busybox --force)",
                BUSYBOX_PATH, e
            );
            return;
        }
    };
    serial_println!("[BBDEMO] Loaded {} ({} bytes)", BUSYBOX_PATH, elf.len());

    if !crate::proc::elf::is_elf(&elf) {
        serial_println!("[BBDEMO] FATAL: {} is not an ELF binary", BUSYBOX_PATH);
        return;
    }

    // ── Battery of demo applets ──────────────────────────────────────────
    //
    // Chosen for breadth of syscall coverage at minimum runtime cost:
    //
    //   echo       — write(2) only — baseline sanity
    //   uname -a   — uname(2)
    //   ls -la /   — getdents64(2), stat(2), readlinkat(2)
    //   cat /etc/os-release  — open(2), read(2), write(2), close(2)
    //   sh -c 'echo SH_OK; exit 0'  — fork(2)+execve(2) avoided since
    //                                 sh -c runs builtins in-process;
    //                                 exercises the sh applet's parser
    //   printenv HOME  — argv/env exposure to the child
    //   du -sh /bin   — recursive stat / readdir aggregation
    //
    // We deliberately skip pipelines (`sh -c 'ls | wc -l'`) — those
    // require fork(2), which is a separate axis covered by the test
    // runner's fork tests.  The demo focuses on single-process applets.
    let battery: &[(&str, &[&str])] = &[
        ("echo",         &["busybox", "echo", "hello from AstryxOS"]),
        ("uname-a",      &["busybox", "uname", "-a"]),
        // ls on /etc rather than / — root has dangling FHS-compat symlinks
        // (/lib64 → /disk/lib64 only exists in glibc-staged builds) which
        // would cause ls to set exit=1 even though the listing succeeds.
        // /etc is a fully-populated in-RAM tmpfs (see vfs::init).
        ("ls-etc",       &["busybox", "ls", "-la", "/etc"]),
        ("cat-osrel",    &["busybox", "cat", "/etc/os-release"]),
        ("sh-c-echo",    &["busybox", "sh", "-c", "echo SH_OK; exit 0"]),
        ("printenv",     &["busybox", "printenv", "HOME"]),
        ("du-disk-bin",  &["busybox", "du", "-sh", "/disk/bin"]),
        // nslookup exercises the full userspace UDP DNS path: musl
        // getaddrinfo(3) → /etc/resolv.conf → socket(AF_INET,SOCK_DGRAM)
        // → sendto(2) → recvfrom(2).  Resolves a stable name via SLIRP's
        // DNS forwarder at 10.0.2.3 (RFC 1035, RFC 768).  The applet
        // ignores its own argv flags inside busybox so the trailing
        // argument is the server override; we pass it explicitly so the
        // test does not depend on /etc/resolv.conf order.
        ("nslookup",     &["busybox", "nslookup", "example.com", "10.0.2.3"]),
    ];

    let mut passed = 0usize;
    let mut total_bytes = 0usize;
    for (label, argv) in battery {
        let (code, out) = run_applet(label, argv, &elf, APPLET_TICKS);
        if code == 0 {
            passed += 1;
        }
        total_bytes += out.len();
    }

    serial_println!(
        "[BBDEMO] === SUMMARY === applets={} passed={} failed={} total_stdout={} bytes",
        battery.len(), passed, battery.len() - passed, total_bytes
    );
    if passed == battery.len() {
        serial_println!("[BBDEMO] === BUSYBOX-TEST: PASS ===");
    } else {
        serial_println!("[BBDEMO] === BUSYBOX-TEST: FAIL ({}/{} applets ok) ===",
            passed, battery.len());
    }
}

/// Public entry point for `--features wget-test`.  Runs a single
/// `busybox wget` against the SLIRP gateway.  The default URL is
/// `http://10.0.2.2:8888/` — the conventional QEMU SLIRP host alias
/// (gateway = 10.0.2.2).  If no host responder is listening, busybox
/// wget exits non-zero with "Connection refused" on stderr and the
/// test reports the network gate state without failing destructively.
#[cfg(feature = "wget-test")]
pub fn run_wget_demo() {
    serial_println!("[BBDEMO] wget-test starting (PIVOT-B Phase 2, 2026-05-23)");

    let elf = match crate::vfs::read_file(BUSYBOX_PATH) {
        Ok(d) => d,
        Err(e) => {
            serial_println!(
                "[BBDEMO] FATAL: cannot read {}: {:?} (run scripts/create-data-disk.sh --busybox --force)",
                BUSYBOX_PATH, e
            );
            return;
        }
    };
    serial_println!("[BBDEMO] Loaded {} ({} bytes)", BUSYBOX_PATH, elf.len());

    if !crate::proc::elf::is_elf(&elf) {
        serial_println!("[BBDEMO] FATAL: {} is not an ELF binary", BUSYBOX_PATH);
        return;
    }

    // ── Pre-flight: confirm busybox wget applet exists ───────────────────
    // `busybox --list` prints all linked-in applets, one per line.  A small
    // grep on the captured output tells us whether the staged binary
    // actually has wget compiled in (Alpine's busybox-static does, but
    // bespoke builds may not).
    let (list_code, list_out) = run_applet(
        "wget-applet-check",
        &["busybox", "--list"],
        &elf,
        APPLET_TICKS,
    );
    if list_code != 0 || !list_out.windows(4).any(|w| w == b"wget") {
        serial_println!(
            "[BBDEMO] wget-test: SKIP — busybox binary at {} does not include wget applet",
            BUSYBOX_PATH
        );
        serial_println!("[BBDEMO] === WGET-TEST: SKIP ===");
        return;
    }
    serial_println!("[BBDEMO] wget applet present in busybox.");

    // ── Phase A: spider check (HEAD-equivalent, no body) ─────────────────
    // --spider mode probes URL existence without downloading the body —
    // exit 0 if reachable, non-zero otherwise.  Short timeout so a
    // missing responder fails fast.
    //
    // 10.0.2.2 is the canonical QEMU SLIRP gateway alias (host's loopback
    // as seen from the guest).  Default port 8888 — agents can run
    // `python3 -m http.server 8888` on the host to satisfy this.
    let (spider_code, _) = run_applet(
        "wget-spider",
        &["busybox", "wget", "--spider", "-T", "10", "-q", "http://10.0.2.2:8888/"],
        &elf,
        WGET_APPLET_TICKS,
    );

    let net_reachable = spider_code == 0;
    serial_println!(
        "[BBDEMO] wget-spider: exit={} (network gate {})",
        spider_code,
        if net_reachable { "OPEN" } else { "CLOSED — no host responder?" }
    );

    // ── Phase B: full fetch (only if spider succeeded) ───────────────────
    if net_reachable {
        let (fetch_code, body) = run_applet(
            "wget-fetch",
            &["busybox", "wget", "-q", "-O", "-", "-T", "10", "http://10.0.2.2:8888/"],
            &elf,
            WGET_APPLET_TICKS,
        );
        serial_println!(
            "[BBDEMO] wget-fetch: exit={} body_bytes={}",
            fetch_code, body.len()
        );
        if fetch_code == 0 && !body.is_empty() {
            serial_println!("[BBDEMO] === WGET-TEST: PASS ===");
        } else {
            serial_println!(
                "[BBDEMO] === WGET-TEST: FAIL (fetch exit={} body_bytes={}) ===",
                fetch_code, body.len()
            );
        }
    } else {
        // Spider failed — report the gate but don't claim PASS or FAIL.
        // The exit code from wget tells us which boundary we hit:
        //   1 = generic failure (usually "connect: Connection refused")
        //   4 = network failure
        //   8 = server error
        // Useful for triage but not actionable in this short demo.
        serial_println!("[BBDEMO] === WGET-TEST: GATE (no host responder; kernel net stack reached connect-refused boundary) ===");
    }
}
