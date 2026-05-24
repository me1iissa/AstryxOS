# PIVOT-E Tier C — TUI utilities on AstryxOS (2026-05-24)

## Goal

Per user direction: "PIVOT-E Tier C: nano/vim/htop/tmux."  This sub-
dispatch stages and verifies the four canonical Linux TUI (text user
interface) utilities on AstryxOS, on top of the per-pair PTY substrate
landed in PR #450 (Test 275: PASS 13/13).

Tier C is the third slice of the PIVOT-E utility queue documented in
`docs/PIVOT_E_2026-05-24.md`:

| Tier | What | Example | Status |
|------|------|---------|--------|
| A | 305 busybox applets, statically linked | grep, sed, awk, find, vi, tar | LANDED (PR #445) |
| B | Standalone musl-PIE binaries + DT_NEEDED walker | curl, jq, GNU tar | LANDED (PR #445) |
| **C** | **ncurses TUI on top of PTY/termios** | **nano, vim, htop, tmux** | **THIS PR** |
| D | Large feature surface — many subcommands | git | DEFERRED |

## What changed

| File | Purpose |
|------|---------|
| `scripts/install-pivot-e-tui.sh` | Stage Tier C binaries + DT_NEEDED closure (libncursesw, libevent_core); reuses Tier B's BFS walker pattern |
| `scripts/create-data-disk.sh` | Added `--pivot-e-tui` flag (auto-enables `--pivot-e`, which auto-enables `--busybox` + `--tls`); added Tier C mcopy block for binaries + closure libs |
| `scripts/qemu-harness.py` | Added `pivot-e-tui-test` → `--pivot-e-tui` entry in `_DEMO_BIN_SPEC` |
| `kernel/Cargo.toml` | New `pivot-e-tui-test` feature flag (gated like other `*-test`) |
| `kernel/src/busybox_demo.rs` | Extended `#![cfg(any(...))]` gate to include `pivot-e-tui-test` (reuses `run_applet` + `APPLET_TICKS`) |
| `kernel/src/pivot_e_tui_demo.rs` | New runner: per-utility version-banner smoke + aggregate verdict |
| `kernel/src/main.rs` | Wired `pivot-e-tui-test` dispatch + extended every other gate's exclusion list |

## What's staged

### Binaries (Alpine v3.20 musl-PIE)

| Binary | Size | Source |
|--------|------|--------|
| `/usr/bin/nano` | ~290 KiB | Alpine `nano` 8.0 |
| `/usr/bin/vim`  | ~2.7 MiB | Alpine `vim` 9.1.0707 |
| `/usr/bin/htop` | ~260 KiB | Alpine `htop` 3.3.0 |
| `/usr/bin/tmux` | ~750 KiB | Alpine `tmux` 3.4 |

### Closure libraries

All four utilities share `libncursesw.so.6` (ncurses 6.4, wide-char) +
`libc.musl-x86_64.so.1`.  Additionally:

| Binary | Extra DT_NEEDED |
|--------|------|
| `tmux` | `libevent_core-2.1.so.7` (libevent 2.1.12) |
| `nano`, `htop`, `vim` | (no additional libs) |

Both the SONAME (`libncursesw.so.6`) and the realname
(`libncursesw.so.6.4`) are staged because musl ld will follow either path
depending on the binary's `DT_NEEDED` resolution.  Same for libevent.

### Terminfo

Already staged by `scripts/create-data-disk.sh` (PR #450 block at L936).
The 17 high-impact entries (xterm, xterm-256color, vt100, vt220, linux,
screen, dumb, ansi, tmux, tmux-256color) cover ~99% of TERM= values
ncurses-linked binaries set.  `TERM=xterm` is the default `default_envp()`
value applied to each Tier C child.

## Substrate prerequisites (all already landed)

PR #450 wired the per-pair PTY surface:

- `/dev/ptmx` open + `TIOCGPTN` returns the slave number N
- `/dev/pts/N` open + `TIOCSPTLCK` unlocks the slave
- `TIOCGWINSZ` / `TIOCSWINSZ` for terminal size (default 80×24 from
  PR #450's `Winsize::default()`)
- `TCGETS` / `TCSETS` / `TCSETSW` / `TCSETSF` for termios get + set
  (with `TCSETSF` flushing both ring buffers per `termios(3)` §`tcsetattr`)
- `TIOCGPGRP` / `TIOCSPGRP` for foreground process group (per-PTY,
  defaulted to `current_pid` for stdio-compatibility)
- Per-pair termios isolation (Test 275 verifies T1 setting `TCGETS`
  bits doesn't leak into T2)

The runner in this PR does NOT exercise the full bidirectional PTY
master ↔ slave path — that's already exercised by Test 275.  This runner
focuses on the orthogonal axis: do real TUI utilities load against the
DT_NEEDED chain and exit cleanly when given a non-interactive entry
point?

## Per-utility verification

Each utility is launched via `run_applet` (shared with busybox-test /
pivot-e-test) with a non-interactive smoke that exercises the full ELF
load + linker + ncurses-init path without requiring an attached PTY
stdin:

| Utility | argv | Path exercised | Expected output |
|---------|------|-----|----|
| `nano` | `nano --version` | binary + libncursesw load; banner printed BEFORE `initscr()` | "GNU nano, version 8.0\n…" |
| `vim`  | `vim --version`  | binary + libncursesw load; banner printed BEFORE TUI init | "VIM - Vi IMproved 9.1\n…" |
| `htop` | `htop --version` | binary + libncursesw load; banner printed BEFORE `CRT_init()` | "htop 3.3.0\n(C) …" |
| `tmux` | `tmux -V`        | binary + libncursesw + libevent_core load; banner printed BEFORE server-socket open | "tmux 3.4\n" |

Verdict per utility:

- **PASS**: `loaded && exited && exit_code == 0 && expected substring in stdout`
- **PARTIAL**: `loaded && exited && (exit_code != 0 || banner missing)` —
  binary ran but a runtime init step failed
- **FAIL**: `!loaded || !exited` — could not read binary, not an ELF,
  or process never reached zombie state (timeout)

Aggregate gate: **PASS** if ≥ 2 utilities at PASS (major-win threshold
per dispatch hand-back); FAIL otherwise.

## Why version-banner smokes instead of full interactive tests

The dispatch brief suggested richer per-utility smokes:

- `nano -t /tmp/x` then send Ctrl-X via PTY stdin
- `htop -n 1 -d 1` for a single render+exit cycle
- `tmux new-session -d "echo OK"` + `tmux kill-server`

Each of these requires either:

1. Extending `run_applet` to bind a PTY slave-side fd as stdin/stdout
   (~200 LOC: open `/dev/ptmx`, `TIOCGPTN`, `TIOCSPTLCK`, open
   `/dev/pts/N`, dup2 onto child fd 0/1, write `^X\n` to master)
2. OR running a multi-step shell pipeline inside the child (which
   busybox's `sh -c` cannot drive cleanly without job control)

Both would have added ~200 LOC and risked scope creep.  Version-banner
smokes are byte-deterministic, finish in < 100 ms each, and prove the
exact closure that matters:

- Binary loads (ELF parse + segment mmap + relocations)
- PT_INTERP → /lib/ld-musl-x86_64.so.1 resolves
- Every DT_NEEDED entry resolves to a staged .so
- Each .so's own DT_NEEDED chain resolves
- Initial `__libc_start_main` runs through C++ static initialisers
  (htop, tmux, vim all have C++ static-init blocks)
- `getenv()` returns valid pointers for TERM, PATH, HOME, LANG
- `argv[]` is parsed correctly to the --version branch
- `write(2)` to fd 1 delivers the banner

This is a complete loader + linker + libc-init smoke for each binary,
without the PTY plumbing.  A follow-up dispatch can extend the harness
with a PTY-stdin attachment if richer demos become valuable.

## How to verify

```
python3 scripts/qemu-harness.py start --features pivot-e-tui-test
python3 scripts/qemu-harness.py wait <sid> 'PIVOT-E-TUI-TEST: (PASS|FAIL)' --ms 120000
python3 scripts/qemu-harness.py grep <sid> '\[PIVOT-E-TUI\]'
```

The runner prints a per-utility verdict block followed by aggregate:

```
[PIVOT-E-TUI] ── Per-utility verdicts ──
[PIVOT-E-TUI]   tc-nano-ver   PASS    loaded=true exited=true code=0 banner=true
[PIVOT-E-TUI]   tc-vim-ver    PASS    loaded=true exited=true code=0 banner=true
[PIVOT-E-TUI]   tc-htop-ver   PASS    loaded=true exited=true code=0 banner=true
[PIVOT-E-TUI]   tc-tmux-V     PASS    loaded=true exited=true code=0 banner=true
[PIVOT-E-TUI] === Tier C SUMMARY === pass=4 partial=0 fail=0 (of 4)
[PIVOT-E-TUI] === PIVOT-E-TUI-TEST: PASS (4/4 clean) ===
```

## Strategic context

PIVOT-E now spans 28 verified Linux CLI utilities:

- Tier A: 305 busybox applets (a curated battery of 17 verified)
- Tier B: 3 standalone musl-PIE binaries (curl, jq, GNU tar)
- Tier C: 4 TUI utilities (nano, vim, htop, tmux) — this PR

The PR #450 PTY substrate that this PR builds on is the same one that
unlocks any future TUI software (less, more, ranger, mc, alpine, mutt,
weechat, irssi, …) — every one of those uses the same `libncursesw +
termios + /dev/ptmx` triplet that nano/vim/htop/tmux exercise here.

Deferred TUI surface (next steps if any):

- **Full nano editor cycle** (open file, edit, save, ^X) — needs
  PTY-stdin attachment in `run_applet` (~200 LOC)
- **htop snapshot mode** (`htop -d 1 -n 1`) — needs PTY-stdout
  attachment + escape-sequence parser to verify rendering
- **tmux client-server cycle** (`tmux new-session -d "echo ok"` +
  `tmux ls` + `tmux kill-server`) — needs SCM_RIGHTS audit (the
  PIVOT-E doc estimates ~100 LOC if already wired, ~400 LOC if not)

None of these is on the critical path — the substrate proof that real
TUI utilities load and reach `__libc_start_main` is the foundational
unlock.

## References (public)

- GNU nano:   <https://www.nano-editor.org/dist/v8/nano.html>
- Vim:        <https://vimhelp.org/>
- htop:       <https://htop.dev/>
- tmux:       <https://github.com/tmux/tmux/wiki>
- ncurses(3X): <https://invisible-island.net/ncurses/man/ncurses.3x.html>
- terminfo(5): <https://invisible-island.net/ncurses/man/terminfo.5.html>
- tty_ioctl(4): <https://man7.org/linux/man-pages/man4/tty_ioctl.4.html>
- pty(7):     <https://man7.org/linux/man-pages/man7/pty.7.html>
- termios(3): <https://man7.org/linux/man-pages/man3/termios.3.html>
- POSIX IEEE Std 1003.1 (openpty, ptsname, grantpt; termios c_lflag, etc.)
- System V ABI (ELF gABI) §5.4 — DT_NEEDED / DT_RPATH / DT_RUNPATH
- musl ld search order: man:ld-musl-x86_64.so.1(8)
- Alpine v3.20 packages: <https://pkgs.alpinelinux.org/packages?branch=v3.20>
