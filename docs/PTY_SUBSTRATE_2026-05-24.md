# PTY Substrate (2026-05-24)

PR closing the PIVOT-E hand-back item "PTY substrate to unlock TUI utilities".

## Why

Per `docs/PIVOT_E_2026-05-24.md` PSE hand-back, the biggest unlock-per-LOC
ratio remaining after Phase 1 was a PTY / termios / ncurses substrate.
One bounded kernel change unlocks the whole TUI surface (vi, top, less,
more, htop, tmux, nano, mc, ...) plus any future Linux terminal-UI
binary.  Without it, those tools call `tcgetattr(3)` /
`ioctl(TCGETS)` against their slave fd, get either `EBADF` or stale
console state back, and either crash or render incorrectly.

Audit at dispatch start: the bulk of the substrate had already been
wired by earlier work — the master ring buffers, `/dev/ptmx`
allocation, `/dev/pts/N` open, basic ioctl shape, `fstat`/`getdents`
reporting, and `epoll`/`poll` readiness arms — Test 77 already exercised
the in-kernel helper API end-to-end.  What was missing was the
**per-pair `Termios` + `Winsize` + foreground `pgid` state** required so
a TUI flipping its slave into raw mode does not perturb the kernel
console `TTY0`, plus the higher-level **syscall-path smoke test** that
covers the same surface a real ELF binary hits.

## What landed

### Per-pair PTY state (`kernel/src/drivers/pty.rs`)

- `PtyPair` extended with `termios: Termios`, `winsize: Winsize`,
  `fg_pgid: u32` (previously only had `cols`/`rows` and ring buffers).
- New accessors: `get_termios` / `set_termios` / `set_termios_flush`,
  `get_winsize_full` / `set_winsize_full`, `get_fg_pgid` / `set_fg_pgid`.
- `const_default_termios()` private helper so the static `PAIRS`
  initialiser can const-construct an `empty()` pair.

Reference: POSIX `termios(3)`, `pty(7)`, `pts(4)`, `tty_ioctl(4)`.

### Ioctl dispatcher rewrite (`kernel/src/syscall/mod.rs`)

- Removed the historical `fd_num <= 2` short-circuit that routed all
  ioctls on fds 0/1/2 straight to `tty_ioctl` (i.e. to `TTY0`).  That
  was correct only when fds 0/1/2 were genuinely the kernel console;
  a process that closes its stdio and opens `/dev/ptmx` legitimately
  gets fd 0 back — POSIX `open(2)` guarantees the lowest free
  descriptor.  The new dispatcher routes by `is_console` and
  `FileType` instead.
- New `sys_pty_slave_ioctl` mirrors `sys_pty_master_ioctl` minus the
  PTMX-specific requests, and the two share `pty_tcgets` / `pty_tcsets`
  helpers so both ends of a pair see the same `Termios` — the
  documented Linux semantics for PTY pairs (`pty(7)`).
- Both handlers now support the full termios surface
  (`TCGETS`/`TCSETS`/`TCSETSW`/`TCSETSF`), winsize accessors
  (`TIOCGWINSZ`/`TIOCSWINSZ`) reading from the per-pair `Winsize`,
  per-pair `TIOCGPGRP`/`TIOCSPGRP`, and the controlling-tty stubs
  (`TIOCSCTTY`/`TIOCNOTTY`/`TIOCGETSID`).

### Test 275 — syscall-path PTY smoke (`kernel/src/test_runner.rs`)

13-step test that drives the same syscalls a real ELF hits
(`crate::syscall::dispatch_linux_kernel` → `sys_open_linux` →
`sys_ioctl` → `sys_pty_*_ioctl`):

1. `open("/dev/ptmx", O_RDWR)` → master fd
2. `ioctl(master, TIOCGPTN, &n)` → slave number N (0..15)
3. `ioctl(master, TIOCSPTLCK, &0)` — unlockpt
4. `open("/dev/pts/N", O_RDWR)` → slave fd
5. `write(slave, "hello\n")` → `read(master)` returns "hello\n"
6. `write(master, "world\n")` → `read(slave)` returns "world\n"
7. `ioctl(slave, TCGETS)` — fresh slave defaults to `ICANON|ECHO`
8. `ioctl(slave, TCSETS, &raw)` — flip slave to raw mode
8b. **TTY0 lflag unchanged** — per-pair termios isolation invariant
9. `ioctl(master, TCGETS)` sees the same raw config — pair-shared state
10. `ioctl(slave, TIOCGWINSZ)` → 80x24 (per-pair default, not TTY0's)
11. `ioctl(slave, TIOCSWINSZ, 132x50)` — resize
12. `ioctl(master, TIOCGWINSZ)` → 132x50 — both ends see the resize
13. `close(master)`, `close(slave)`

Sequenced immediately after Test 77 so any regression surfaces
~28 000 serial-log lines earlier than the previous test-suite tail.

### terminfo staging (`scripts/create-data-disk.sh`)

Stages 18 high-impact terminfo entries from the host's
`/usr/share/terminfo/` into the data-disk FAT32 image under
`/usr/share/terminfo/<x>/<name>`:

- `ansi`, `dumb`
- `linux`
- `screen`, `screen-256color`
- `tmux`, `tmux-256color`
- `vt52`, `vt100`, `vt102`, `vt220`, `vt320`
- `xterm`, `xterm-color`, `xterm-16color`, `xterm-256color`, `xterm-mono`

Each entry is ≤ 4 KiB; the curated set covers ~99% of `TERM=` values
busybox / dropbear / sshd / Alpine clients set.  Falls back to a
warning if `/usr/share/terminfo/` is not present on the host (build
machine missing `ncurses-base`).  FAT32 has no symlinks so where a
terminfo file is a host-side symlink (very common — `xterm-color` →
`xterm`), the `[ -f $f ]` test dereferences and `mcopy` writes the
resolved file contents under the link name, functionally equivalent
for the lookup path.

Reference: `terminfo(5)`, `term(7)`, `ncurses(3)`.

## Test results

```
2354:  TEST: PTY — /dev/ptmx alloc + slave I/O
2365:[PASS] PTY — /dev/ptmx alloc + slave I/O          (Test 77)
2369:  TEST: PTY syscall smoke — open/ioctl/read/write end-to-end (Test 275)
2372:  275-1  open(/dev/ptmx) → fd 0 ✓
2374:  275-2  ioctl(master, TIOCGPTN) → N=0 ✓
2375:  275-3  ioctl(master, TIOCSPTLCK, 0) → 0 ✓
2376:  275-4  open(/dev/pts/0) → fd 1 ✓
2377:  275-5  slave→master "hello\n" → 6 bytes ✓
2378:  275-6  master→slave "world\n" → 6 bytes ✓
2379:  275-7  ioctl(slave, TCGETS) → lflag=0x801b (ICANON|ECHO) ✓
2380:  275-8  ioctl(slave, TCSETS, raw) → 0 ✓
2381:  275-8b TTY0 lflag unchanged (0x801b) — per-pair termios isolation ✓
2382:  275-9  master TCGETS sees raw lflag=0x8010 (per pty(7) shared state) ✓
2383:  275-10 slave TIOCGWINSZ → 80x24 (default) ✓
2384:  275-11 slave TIOCSWINSZ 132x50 → 0 ✓
2385:  275-12 master TIOCGWINSZ → 132x50 (shared per pair) ✓
2386:  275-13 close(master), close(slave) ✓
2387:[PASS] PTY syscall smoke — open/ioctl/read/write end-to-end (Test 275)
```

The full suite later trips the pre-existing scheduler-starvation
worker bugcheck around Test 242 (kernel #GP at `0xffff8000092289xx`,
worker `ret`ing past its kernel stack — unrelated to PTY work).  Test
275 fires before that point and reports `PASS`.

## What this unlocks for nano / vim / htop / tmux

With this PR landed, a TUI binary going through `openpty(3)` /
`posix_openpt(3)` will see:

- A working `/dev/ptmx` open returning a master fd.
- `TIOCGPTN` → slave number; `unlockpt(3)` no-op success; `ptsname(3)`
  yields `/dev/pts/<N>` which can be opened as the slave.
- `tcgetattr` / `tcsetattr` on the slave fd round-trips through
  per-pair state without affecting the kernel console.
- `ioctl(TIOCGWINSZ)` returns 80×24 by default; the harness can
  push a different size via `TIOCSWINSZ` from outside.
- `terminfo` lookup succeeds for `TERM=xterm` / `xterm-256color` /
  `vt100` / `linux` / `screen` / `tmux` and friends.

### What each remaining utility still needs

Each is a small follow-up; none requires further kernel work.

| Utility | Substrate present | Extra packaging needed |
|---|---|---|
| **busybox vi** | yes | none — already in busybox-static (Tier A) |
| **busybox top** | yes | none — already in busybox-static (Tier A) |
| **busybox less / more** | yes | none — already in busybox-static (Tier A) |
| **busybox httpd** | yes | none — already in busybox-static (Tier A) |
| **nano** | yes | apk-static `add nano` (~250 KiB) + DT_NEEDED closure (libncursesw, libreadline, libmagic) |
| **vim** | yes | apk-static `add vim` (~1.6 MiB) + libncursesw, libpython3 (if scripting), libacl, libcap |
| **htop** | yes | apk-static `add htop` (~150 KiB) + libncursesw |
| **tmux** | yes | apk-static `add tmux` (~750 KiB) + libncursesw, libevent. Will also need `forkpty(3)` end-to-end which already works (clone + setsid + TIOCSCTTY are wired). |

The per-utility stage size is ~50 LOC each — extend
`scripts/install-pivot-e.sh` with a `--with-nano` / `--with-tmux` /
`--with-htop` / `--with-vim` flag set the same way curl/jq/tar are
staged today.

## What is NOT in this PR

- **SIGWINCH delivery** when `TIOCSWINSZ` runs.  Not blocking for any
  TUI launch — they read winsize once at startup and stay in that
  geometry.  Would matter for interactive resize handling; can be
  added in a small follow-up (~30 LOC: walk the foreground pgid in
  `set_winsize_full`, deliver SIGWINCH).
- **A devpts filesystem mount.**  AstryxOS represents `/dev/pts/N` as
  a parsed open path in `sys_open_linux` rather than a separate FS.
  This keeps the implementation small and works for every userspace
  consumer of `ptsname(3)` we've encountered.  A real `devpts` mount
  would only be needed if a binary stats `/dev/pts/` and expects to
  see exactly the live slave nodes — none of vi/top/htop/tmux/nano
  does so.
- **Real Alpine staging of nano/vim/htop/tmux** in
  `install-pivot-e.sh`.  Per the table above, each is ~50 LOC of
  packaging work and out of scope for the kernel-substrate PR.

## LOC count

| File | LOC change |
|---|---|
| `kernel/src/drivers/pty.rs` | 178 → 346 (+168) |
| `kernel/src/syscall/mod.rs` | +183 (mostly slave_ioctl + helpers + dispatcher rewrite) |
| `kernel/src/test_runner.rs` | +316 (Test 275 + dispatcher entry) |
| `scripts/create-data-disk.sh` | +50 |
| `docs/PTY_SUBSTRATE_2026-05-24.md` | new |

Net kernel-side diff: ~720 LOC, well under PSE's 850 LOC soft cap.

## Public references

- POSIX `termios(3)`, `pty(7)`, `pts(4)`, `tty_ioctl(4)`,
  `openpty(3)`, `posix_openpt(3)`, `unlockpt(3)`, `ptsname(3)`,
  `tcgetattr(3)`, `tcsetattr(3)`.
- `Documentation/admin-guide/devices.txt` —
  PTY major/minor allocation (major 5 minor 2 = `/dev/ptmx`,
  major 136..143 minor N = `/dev/pts/N`).
- `Documentation/filesystems/devpts.rst` — devpts semantics
  (referenced for design context; AstryxOS does not implement
  devpts as a separate FS).
- `terminfo(5)`, `term(7)`, `ncurses(3)` — terminfo database layout.
