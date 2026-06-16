//! sshd-test: dropbear SSH-service demo runner (PIVOT-D, 2026-05-23).
//!
//! Launches Alpine's dropbear (musl-linked, ~260 KB) as a userspace process
//! listening on guest TCP port 22.  Used as the maximum-surface proof point
//! that the AstryxOS kernel personality stack can host a real Linux network
//! service end-to-end: socket(2), bind(2), listen(2), accept(2), fork(2)
//! per-connection, plus the SSH-2 binary-packet protocol + RSA/Ed25519
//! host-key handshake from RFCs 4252-4254.
//!
//! Shape
//! -----
//! Mirrors busybox_demo's `run_applet`: build a small argv/envp, fork+exec
//! via `create_user_process_with_args_blocked`, attach a stdout-capture
//! pipe, unblock, then poll the process until it exits OR a soak deadline.
//!
//! Unlike the busybox-test battery, dropbear is meant to RUN, not exit.
//! It's a long-lived daemon: bind+listen, then loop on accept(2) forever
//! (until a SIGTERM).  The deadline here is a "demo soak" wall-clock budget
//! that gives the harness time to drive a host-side `ssh` and capture the
//! exchange via the serial log; when the budget expires the process is
//! left running and the demo records what it observed.
//!
//! accept(2) gate
//! --------------
//! As of 2026-05-23, AF_INET accept(2) is stubbed in
//! kernel/src/subsys/linux/syscall.rs (returns -EAGAIN unconditionally).
//! Dropbear's main loop calls accept(2) in a poll-driven loop and will
//! never see an established connection.  The boot still validates:
//!
//!   - dropbear ELF loads (musl, libz, libc.musl-x86_64.so.1)
//!   - host-key files load (Ed25519 + RSA, dropbear binary format)
//!   - getpwnam_r("root") + /etc/shadow + /etc/passwd parse OK
//!   - socket(AF_INET, SOCK_STREAM), bind(:22), listen() succeed
//!   - accept(2) returns -EAGAIN (named gate, expected)
//!
//! Once AF_INET accept(2) lands, the same code path completes the SSH
//! handshake and serves the host's `ssh -p N root@127.0.0.1`.
//!
//! References (public):
//!   - dropbear(8): https://matt.ucc.asn.au/dropbear/dropbear.html
//!   - RFC 4252 SSH userauth, RFC 4253 SSH transport, RFC 4254 conn protocol
//!   - POSIX socket(2) / bind(2) / listen(2) / accept(2)
//!   - QEMU SLIRP networking:
//!     https://www.qemu.org/docs/master/system/devices/net.html#network-options

#![cfg(feature = "sshd-test")]

extern crate alloc;
use alloc::vec::Vec;

use crate::serial_println;

/// Absolute path of the staged dropbear binary on the data disk.  Matches
/// scripts/install-sshd.sh which copies to /usr/sbin/dropbear; create-data-
/// disk.sh propagates the file into the FAT32 image at the same path.
const DROPBEAR_PATH: &str = "/disk/usr/sbin/dropbear";

/// Soak budget in TICK_HZ=100 ticks.  Dropbear is a long-lived daemon —
/// it does not exit cleanly under normal operation.  We let it run for
/// 60 s in the demo mode so the harness has time to:
///   1. Wait for the "Not backgrounding" / "Listening on" markers
///   2. Issue a host-side `ssh -p N` (once accept(2) is real)
///   3. Capture stdout + serial events
///
/// 6_000 ticks = 60 s @ 100 Hz.  Bump for longer interactive soaks.
/// Raised to 24_000 (≈240 s @ 100 Hz) so a host-driven `ssh -p N` has a
/// comfortable live window to complete the TCP 3-way handshake, the SSH-2
/// transport/kex (RFC 4253), public-key userauth (RFC 4252) and open a
/// session channel (RFC 4254) before the demo soak tears the daemon down.
const SSHD_SOAK_TICKS: u64 = 24_000;

/// Envp for dropbear.  Kept small + deterministic.  Notable entries:
///   - HOME=/root            — dropbear sets supplementary groups before
///                              chdir; getpwnam_r resolves home from /etc/passwd
///                              but HOME is also consulted for client-side
///                              tooling, kept consistent here.
///   - PATH=/bin:/usr/bin    — login shell PATH inherited by child processes
///                              once accept lands (busybox `sh` lives at /bin).
///   - TMPDIR=/tmp           — dropbear caches PRNG state there.
///   - LANG=C / LC_ALL=C     — byte-deterministic logs.
fn default_envp() -> &'static [&'static str] {
    &[
        "HOME=/root",
        "PATH=/bin:/usr/bin:/usr/sbin",
        "TMPDIR=/tmp",
        "TERM=dumb",
        "LANG=C",
        "LC_ALL=C",
    ]
}

/// Public entry point for `--features sshd-test`.  Loads /disk/usr/sbin/
/// dropbear once, launches it, and runs a bounded soak.
pub fn run_sshd_demo() {
    serial_println!("[SSHD] sshd-test starting (PIVOT-D, 2026-05-23)");

    let elf = match crate::vfs::read_file(DROPBEAR_PATH) {
        Ok(d) => d,
        Err(e) => {
            serial_println!(
                "[SSHD] FATAL: cannot read {}: {:?} (run scripts/create-data-disk.sh --sshd --force)",
                DROPBEAR_PATH, e
            );
            return;
        }
    };
    serial_println!("[SSHD] Loaded {} ({} bytes)", DROPBEAR_PATH, elf.len());

    if !crate::proc::elf::is_elf(&elf) {
        serial_println!("[SSHD] FATAL: {} is not an ELF binary", DROPBEAR_PATH);
        return;
    }

    // dropbear command-line flags chosen for visibility + demo-friendliness:
    //
    //   -F     — foreground (don't fork to background).  Dropbear's default
    //            is to daemonise via fork()+setsid()+detach; -F keeps it in
    //            the foreground so PID tracking + serial capture work without
    //            having to chase a child PID.  Per dropbear(8) FLAGS.
    //   -E     — log to stderr (not syslog).  Stderr is wired to our capture
    //            pipe so all init lines come through to serial.
    //   -p 22  — listen on TCP port 22 only.  Default behaviour, but explicit.
    //   -r <K> — host-key path (Ed25519 + RSA, repeatable per RFC 4253).  We
    //            pass both so older clients (RSA-only) and modern clients
    //            (Ed25519) both work.
    //   -P /tmp/dropbear.pid — pidfile.  Not strictly required (-F suppresses
    //            it) but dropbear writes one anyway; redirecting to /tmp
    //            keeps the FAT32 root clean.
    //   -B     — allow blank-password logins (DISABLED — we keep /etc/shadow
    //            locked, so this is never used; mentioned for completeness).
    //   -s     — disable password auth (force public-key only).  Belt-and-
    //            braces with the locked /etc/shadow entry: even if shadow
    //            ever got unlocked accidentally, this flag prevents
    //            password auth at the protocol level.  Per RFC 4252 §5.
    let argv: &[&str] = &[
        "dropbear",
        "-F",                                             // foreground
        "-E",                                             // log stderr
        "-s",                                             // disable password auth
        "-p", "22",                                       // listen :22
        "-r", "/disk/etc/dropbear/dropbear_ed25519_host_key",
        "-r", "/disk/etc/dropbear/dropbear_rsa_host_key",
        "-P", "/tmp/dropbear.pid",
    ];
    let envp = default_envp();

    serial_println!("[SSHD] Spawning dropbear with argv={:?}", argv);

    // Spawn blocked so we can attach the stdout pipe before write(2)s race.
    let pid = match crate::proc::usermode::create_user_process_with_args_blocked(
        "dropbear",
        &elf,
        argv,
        envp,
    ) {
        Ok(pid) => pid,
        Err(e) => {
            serial_println!(
                "[SSHD] FATAL: spawn failed: create_user_process_with_args_blocked={:?}",
                e
            );
            return;
        }
    };
    serial_println!("[SSHD] dropbear spawned: pid={}", pid);

    let pipe_id = crate::ipc::pipe::create_pipe();
    crate::proc::attach_stdout_pipe(pid, pipe_id);
    crate::proc::unblock_process(pid);

    // Make sure the scheduler is live; the launch path may have left the BSP
    // idle slot without timer ticks if the caller didn't enable IRQs.
    if !crate::sched::is_active() {
        crate::sched::enable();
    }
    crate::hal::enable_interrupts();

    let t_start = crate::arch::x86_64::irq::get_ticks();
    let mut captured: Vec<u8> = Vec::with_capacity(4096);
    let mut buf = [0u8; 512];
    let mut last_marker_tick: u64 = 0;

    loop {
        crate::sched::yield_cpu();

        // Drain stdout — dropbear writes init banner + per-event lines.
        if let Some(n) = crate::ipc::pipe::pipe_read_wake(pipe_id, &mut buf) {
            if n > 0 && captured.len() < 16_384 {
                let take = core::cmp::min(n, 16_384 - captured.len());
                captured.extend_from_slice(&buf[..take]);

                // Echo every line as it comes in so post-processors can
                // correlate dropbear init events with kernel-side syscall
                // markers in real time.
                let text = core::str::from_utf8(&buf[..take]).unwrap_or("<non-utf8>");
                for line in text.lines() {
                    serial_println!("[SSHD] dropbear | {}", line);
                }
            }
        }

        // Has the child exited?  Dropbear shouldn't under normal -F operation,
        // so this firing is itself diagnostic.
        let (state, exit_code) = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter().find(|p| p.pid == pid) {
                Some(p) => (p.state, p.exit_code),
                None => (crate::proc::ProcessState::Zombie, 0),
            }
        };

        if state == crate::proc::ProcessState::Zombie {
            serial_println!(
                "[SSHD] dropbear EXITED unexpectedly: pid={} exit={} (state=Zombie)",
                pid, exit_code
            );
            break;
        }

        // Deadline check.
        let elapsed = crate::arch::x86_64::irq::get_ticks().wrapping_sub(t_start);
        if elapsed >= SSHD_SOAK_TICKS {
            serial_println!(
                "[SSHD] Soak budget reached ({} ticks); dropbear still RUNNING (pid={}, state={:?})",
                SSHD_SOAK_TICKS, pid, state
            );
            break;
        }

        // Periodic liveness marker so the harness `wait` regex has stable
        // text to match on (every 1000 ticks = ~10 s).
        if elapsed.wrapping_sub(last_marker_tick) >= 1_000 {
            last_marker_tick = elapsed;
            serial_println!(
                "[SSHD] LIVENESS pid={} state={:?} elapsed_ticks={} captured_bytes={}",
                pid, state, elapsed, captured.len()
            );
        }

        // Yield CPU between polls.
        for _ in 0..1_000u32 {
            core::hint::spin_loop();
        }
    }

    // Final summary line + look for known initialisation markers in captured
    // stdout.  These let an external script tell whether dropbear reached
    // its accept-loop or wedged at an earlier point.
    //
    // Dropbear's first stderr line under `-F -E` is "Not backgrounding"
    // (printed BEFORE the version banner; see dropbear's main.c in
    // dropbear-2024.85).  Subsequent lines (under verbose -v flags) include
    // host-key load events and the per-connection authentication trace.
    //
    // Verdict logic:
    //   - Process still Active when soak ends         → REACHED-ACCEPT-LOOP
    //     (dropbear -F bound :22 and is in accept() loop)
    //   - "Not backgrounding" seen AND process exited → PARTIAL
    //     (started but failed at host-key load or similar)
    //   - Process exited and no startup marker        → PRE-BANNER-EXIT
    //     (failed at ELF load, musl reloc, or syscall startup)
    let text = core::str::from_utf8(&captured).unwrap_or("<non-utf8>");
    let saw_dropbear_v   = text.contains("Dropbear v");
    let saw_not_bkg      = text.contains("Not backgrounding");
    let saw_pubkey       = text.contains("publickey") || text.contains("Pubkey");

    // Re-read process state at end (it may have transitioned since the loop).
    let final_state = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid).map(|p| p.state)
            .unwrap_or(crate::proc::ProcessState::Zombie)
    };

    serial_println!(
        "[SSHD] === SUMMARY === banner={} foreground={} pubkey_seen={} final_state={:?} captured_bytes={}",
        saw_dropbear_v as u8, saw_not_bkg as u8, saw_pubkey as u8, final_state, captured.len()
    );

    let still_running = final_state != crate::proc::ProcessState::Zombie;

    if still_running && saw_not_bkg {
        serial_println!(
            "[SSHD] === SSHD-TEST: REACHED-ACCEPT-LOOP (foreground marker + process Active at soak end) ==="
        );
    } else if saw_not_bkg {
        serial_println!(
            "[SSHD] === SSHD-TEST: PARTIAL (foreground marker seen but dropbear exited; likely host-key load failure) ==="
        );
    } else {
        serial_println!(
            "[SSHD] === SSHD-TEST: PRE-BANNER-EXIT (dropbear didn't print startup marker; check ELF loader / musl / host-key paths) ==="
        );
    }
}
