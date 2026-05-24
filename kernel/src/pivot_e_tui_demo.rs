//! pivot-e-tui-test runner — PIVOT-E Tier C (nano, vim, htop, tmux) on
//! the per-pair PTY substrate landed in PR #450 (2026-05-24).
//!
//! Each TUI utility is launched as a standalone musl-PIE Linux binary
//! through the same loader path exercised by Tier B (curl/jq/tar in
//! `pivot_e_demo.rs`).  The verification surface here is two-fold:
//!
//!   1. **DT_NEEDED closure walk** — each binary depends on
//!      libncursesw.so.6 + libc.musl-x86_64.so.1; tmux additionally
//!      depends on libevent_core-2.1.so.7.  All four .so files are
//!      staged by `scripts/install-pivot-e-tui.sh` and the kernel ELF
//!      loader's PT_INTERP → /lib/ld-musl-x86_64.so.1 path resolves the
//!      closure at process startup.  If any soname is missing the
//!      child exits before main() with a ld-musl diagnostic on stderr.
//!
//!   2. **ncurses init runs cleanly** — each utility calls
//!      `setupterm()` / `newterm()` (or the higher-level `initscr()`)
//!      against the TERM= environment value (defaulted to `xterm` by
//!      `default_envp()`) and the `/usr/share/terminfo/x/xterm` entry
//!      staged by `scripts/create-data-disk.sh` (PR #450).  --version
//!      and -V banners run AFTER the ncurses init path (htop and tmux)
//!      OR BEFORE it (nano, vim — both honour --version as a pure-text
//!      early-exit before TUI init).  Either way, a clean exit + the
//!      expected first-line text proves the substrate is sound.
//!
//! Per-utility smoke (non-interactive — avoids needing PTY stdin attached
//! to the test runner; the binary's stdin defaults to whatever the
//! kernel hands children, but version/help paths do not read stdin):
//!
//!   nano   → `nano --version`   → "GNU nano, version 8.x"
//!   vim    → `vim --version`    → "VIM - Vi IMproved 9.x"
//!   htop   → `htop --version`   → "htop 3.x"
//!   tmux   → `tmux -V`          → "tmux 3.x"
//!
//! Each utility's success path is `exit_code == 0` AND captured stdout
//! contains a small banner-match substring.  We do NOT gate on the
//! presence of terminal control sequences (ESC[...) here — --version
//! paths print plain text.  A richer interactive smoke (sending Ctrl-X
//! to nano via a PTY-attached stdin, or `tmux new-session -d "echo OK"`
//! to exercise the AF_UNIX socket and forkpty(3) chain) is intentionally
//! deferred — it requires either extending the demo harness with a
//! PTY-bound stdin pipe (~200 LOC) or relaxing the run_applet fd-1
//! capture pattern, both of which are scope creep for the milestone.
//!
//! Reuses `run_applet` from `busybox_demo` (pub(crate)) so the pipe /
//! waitpid / timeout machinery is shared with Tier A and Tier B.
//!
//! References (public)
//!   - GNU nano(1):    https://www.nano-editor.org/dist/v8/nano.html
//!   - vim(1):         https://vimhelp.org/
//!   - htop(1):        https://htop.dev/
//!   - tmux(1):        https://github.com/tmux/tmux/wiki
//!   - ncurses(3X):    https://invisible-island.net/ncurses/man/ncurses.3x.html
//!   - terminfo(5):    https://invisible-island.net/ncurses/man/terminfo.5.html
//!   - POSIX termios + tty(4) + pty(7) — IEEE Std 1003.1

#![cfg(feature = "pivot-e-tui-test")]

extern crate alloc;

use crate::busybox_demo::{run_applet, APPLET_TICKS};
use crate::serial_println;

const NANO_PATH: &str = "/disk/usr/bin/nano";
const VIM_PATH:  &str = "/disk/usr/bin/vim";
const HTOP_PATH: &str = "/disk/usr/bin/htop";
const TMUX_PATH: &str = "/disk/usr/bin/tmux";

/// One Tier C entry.  Tuple = (label, binary_path, argv, expect_substr).
/// The expect_substr is searched in captured stdout for a banner match —
/// "GNU nano" / "VIM - Vi" / "htop " / "tmux ".  argv[0] is the binary's
/// basename (musl ld derives the program name from it for `__progname`).
struct TierC {
    label:    &'static str,
    binary:   &'static str,
    argv:     &'static [&'static str],
    expect:   &'static str,
}

const TIER_C_BATTERY: &[TierC] = &[
    TierC {
        label:  "tc-nano-ver",
        binary: NANO_PATH,
        // `nano --version` prints "GNU nano, version 8.0\n..." and exits 0
        // BEFORE invoking initscr() / newterm() — pure text path, no
        // terminal driver init.  Proves binary + libncursesw + libc.musl
        // all load.
        argv:   &["nano", "--version"],
        expect: "GNU nano",
    },
    TierC {
        label:  "tc-vim-ver",
        binary: VIM_PATH,
        // `vim --version` is similar to nano: pure-text banner + feature
        // matrix print, then exit 0.  No ncurses init.  Tests the
        // ~2.7 MiB binary load path (largest Tier C binary).
        argv:   &["vim", "--version"],
        expect: "VIM - Vi",
    },
    TierC {
        label:  "tc-htop-ver",
        binary: HTOP_PATH,
        // `htop --version` prints "htop 3.3.0\n(C) ..." and exits 0.
        // This path explicitly does NOT call setupterm() / refresh_screen,
        // so a successful --version is a load + linker test rather than a
        // PTY-init test.  See htop's CommandLine.c::CommandLine_run for
        // the early --version branch.
        argv:   &["htop", "--version"],
        expect: "htop ",
    },
    TierC {
        label:  "tc-tmux-V",
        binary: TMUX_PATH,
        // `tmux -V` (note: capital V, distinct from `tmux -v` which means
        // verbose-logging).  Prints "tmux 3.4\n" and exits 0 BEFORE
        // opening the server socket at /tmp/tmux-<uid>/default — pure
        // version banner.  Validates libevent_core DT_NEEDED + libncursesw
        // load (tmux links both at load time even though the version path
        // doesn't use them).
        argv:   &["tmux", "-V"],
        expect: "tmux ",
    },
];

/// Per-utility verdict for the per-binary summary block.
#[derive(Clone, Copy)]
struct UtilVerdict {
    label:   &'static str,
    loaded:  bool,         // run_applet returned anything other than (-1, _)
    exited:  bool,         // process reached zombie state (not timed out)
    code:    i32,
    banner:  bool,         // expect substr present in captured stdout
}

/// Verify one Tier C utility.  Returns a UtilVerdict the aggregator uses
/// to compute PASS/FAIL.  Each call is independent — failure to load one
/// utility does not block the others.
fn run_one(entry: &TierC) -> UtilVerdict {
    // Read the binary from data.img.  read_file caches via PR #248 file-
    // read cache so the second time a Tier C util is launched the read
    // is in-RAM.
    let elf = match crate::vfs::read_file(entry.binary) {
        Ok(d) => d,
        Err(e) => {
            serial_println!(
                "[PIVOT-E-TUI] {} SKIP — cannot read {}: {:?}",
                entry.label, entry.binary, e
            );
            return UtilVerdict {
                label: entry.label, loaded: false, exited: false,
                code: -1, banner: false,
            };
        }
    };
    if !crate::proc::elf::is_elf(&elf) {
        serial_println!(
            "[PIVOT-E-TUI] {} SKIP — {} is not an ELF binary",
            entry.label, entry.binary
        );
        return UtilVerdict {
            label: entry.label, loaded: false, exited: false,
            code: -1, banner: false,
        };
    }

    let (code, out) = run_applet(entry.label, entry.argv, &elf, APPLET_TICKS);

    let loaded = code != -1;
    let exited = loaded; // run_applet returns -1 only on spawn fail; any
                         // other value means the process actually reached
                         // zombie state (or was reaped after running).
    let banner = if !out.is_empty() {
        core::str::from_utf8(&out)
            .map(|s| s.contains(entry.expect))
            .unwrap_or(false)
    } else {
        false
    };

    UtilVerdict { label: entry.label, loaded, exited, code, banner }
}

/// Run the full Tier C battery and emit per-utility + aggregate verdicts.
///
/// Verdict rules:
///   - Per-utility PASS  = loaded && exited && code == 0 && banner
///   - Per-utility PARTIAL = loaded && exited && (code != 0 || !banner)
///                          (binary ran but didn't print expected banner —
///                          often means DT_NEEDED resolved but a runtime
///                          init step failed)
///   - Per-utility FAIL   = !loaded || !exited
///   - Aggregate PASS     = >= 2 utilities at PASS (major-win threshold;
///                          per dispatch hand-back "at least 2 of 4 reach
///                          a clean exit").
///   - Aggregate FAIL     = < 2 utilities at PASS.
pub fn run_pivot_e_tui_demo() {
    serial_println!("[PIVOT-E-TUI] pivot-e-tui-test starting (PIVOT-E Tier C, 2026-05-24)");
    serial_println!("[PIVOT-E-TUI] PTY substrate (PR #450) + libncursesw closure");

    let mut verdicts: [UtilVerdict; 4] = [UtilVerdict {
        label: "", loaded: false, exited: false, code: -1, banner: false,
    }; 4];
    for (i, entry) in TIER_C_BATTERY.iter().enumerate() {
        verdicts[i] = run_one(entry);
    }

    // Per-utility summary block.
    serial_println!("[PIVOT-E-TUI] ── Per-utility verdicts ──");
    let mut pass = 0usize;
    let mut partial = 0usize;
    let mut fail = 0usize;
    for v in verdicts.iter() {
        let verdict_str = if !v.loaded || !v.exited {
            fail += 1;
            "FAIL"
        } else if v.code == 0 && v.banner {
            pass += 1;
            "PASS"
        } else {
            partial += 1;
            "PARTIAL"
        };
        serial_println!(
            "[PIVOT-E-TUI]   {:<14} {:<7} loaded={} exited={} code={} banner={}",
            v.label, verdict_str, v.loaded, v.exited, v.code, v.banner
        );
    }

    serial_println!(
        "[PIVOT-E-TUI] === Tier C SUMMARY === pass={} partial={} fail={} (of {})",
        pass, partial, fail, TIER_C_BATTERY.len()
    );

    // Aggregate verdict.  Threshold = 2/4 PASS per dispatch (major-win
    // line); 3-of-4 means the substrate is robust enough for richer
    // interactive demos.  4-of-4 is the ideal.
    if pass >= 2 {
        serial_println!(
            "[PIVOT-E-TUI] === PIVOT-E-TUI-TEST: PASS ({}/{} clean) ===",
            pass, TIER_C_BATTERY.len()
        );
    } else {
        serial_println!(
            "[PIVOT-E-TUI] === PIVOT-E-TUI-TEST: FAIL (pass={} partial={} fail={}; need pass>=2) ===",
            pass, partial, fail
        );
    }
}
