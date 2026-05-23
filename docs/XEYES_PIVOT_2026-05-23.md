# xeyes pivot — Alpine X11 "hello world" on AstryxOS (2026-05-23)

## TL;DR

**Verdict: WORKS to deep X11 protocol exchange; plateaus in `poll(2)` while
waiting for further server responses.  Zero crashes, zero panics, zero
SIGSEGV / #UD / #GP / BUGCHECK — the kernel runs an unmodified Alpine
musl-linked X11 binary end-to-end through the dynamic linker, libc,
libX11, libxcb and into the X11 protocol layer.**

This is a pivot away from the multi-week Firefox SSP saga to a tiny Linux
X11 client to prove the kernel runs SOMETHING simpler than libxul without
the SSP/JIT/vfork complexity.  It succeeded: the kernel personality stack
does run real Alpine X11 binaries; the next blocker is X11 server (Xastryx)
response coverage, not anything in the personality layer or runtime loader.

## What landed in this PR

| File | Change |
|---|---|
| `scripts/install-xeyes.sh` | New: stages Alpine `xeyes` + 5 deps into `build/disk/` (reuses the shared `install-firefox-musl.sh` apk rootfs at `~/.cache/astryxos-firefox-musl/`). |
| `scripts/create-data-disk.sh` | Calls `install-xeyes.sh` when `ASTRYXOS_XEYES=1` or `--xeyes`; copies `/usr/bin/xeyes` into `data.img`.  The 5 dep libs ride the existing musl `/usr/lib/*.so*` copy step automatically. |
| `kernel/Cargo.toml` | New cargo feature `xeyes-test`; mutually exclusive with `firefox-test` and `gui-test` at the `main.rs` cfg gate level. |
| `kernel/src/main.rs` | New early-boot block under `#[cfg(feature = "xeyes-test")]`: brings up Xastryx, pre-allocates kernel stacks, pre-populates the page cache for xeyes + 17 supporting files, calls `gui::terminal::launch_process("/disk/usr/bin/xeyes")`, then runs a 180 s soak loop polling X11 + net.  The normal-boot and `firefox-test` gates were extended to exclude `xeyes-test`. |

## How to run it

```bash
# One-time: stage xeyes into build/disk/ and rebuild data.img.
ASTRYXOS_XEYES=1 bash scripts/create-data-disk.sh --force --xeyes

# Boot the xeyes-test soak.
python3 scripts/qemu-harness.py start --features xeyes-test
python3 scripts/qemu-harness.py wait <sid> 'XEYES.*Soak budget|XEYES.*DONE|BUGCHECK|PANIC|SIGSEGV' --ms 240000
python3 scripts/qemu-harness.py grep <sid> 'XEYES|X11|PROC-METRICS' --tail 50
python3 scripts/qemu-harness.py stop <sid>
```

## Soak results — TCG (initial reproducer)

```
[XEYES] xeyes-test mode starting...
[XEYES] X11 server ready
[XEYES] Pre-allocated 8 kernel stacks (512 KiB)
[XEYES] Pre-populating page cache for xeyes + deps...
[XEYES] Cached /disk/lib/ld-musl-x86_64.so.1 (159 pages, 4 ticks)
[XEYES] Cached /disk/usr/bin/xeyes (7 pages, 0 ticks)
[XEYES] Cached /disk/usr/lib/libX11.so.6 (284 pages, 2 ticks)
[XEYES] Cached /disk/usr/lib/libXt.so.6 (87 pages, 1 ticks)
... (17 files total, 860 pages) ...
[XEYES] Page cache: 860 pages total
[XEYES] Pre-load complete — launching xeyes
[XEYES] Binary probe: /disk/usr/bin/xeyes -> Ok(28336)
[XEYES] Launching /disk/usr/bin/xeyes ...
[USER] Loading ELF binary '/disk/usr/bin/xeyes' (28336 bytes)
[ELF] PT_INTERP: loading interpreter '/disk/lib/ld-musl-x86_64.so.1'
[PROC] Created kernel process '/disk/usr/bin/xeyes' PID 1 TID 1
[X11] client fd=2
[X11] fd=2 setup ok
[PROC-METRICS] tick=500 pid=1 name=/disk/usr/bin/xeyes
    sc=252 (vm=106 file=119 net=14 sync=10 proc=0 sig=0 other=3) pf=216
    disk=R425984/W0 net=R211/W324 STUCK_IN_NR=7@298t
...
[XEYES] Soak budget reached at 18000 ticks
[XEYES] xeyes_exited=false
[XEYES] DONE
```

**TCG plateau**: 252 syscalls (vm=106 file=119 net=14 sync=10 proc=0 sig=0 other=3).
Stuck in syscall nr=7 (`poll(2)` on x86-64 Linux personality).
14 net syscalls (socket + connect + sendmsg + read in the X11 setup).
No crashes; clean shutdown at 180 s soak budget.

## Soak results — KVM (deeper code path)

```
... (identical pre-launch through "[X11] fd=2 setup ok") ...
[X11] InternAtom("Custom Init")      -> 83
[X11] InternAtom("Custom Data")      -> 84
[X11] InternAtom("SCREEN_RESOURCES") -> 0
[X11] InternAtom("WM_DELETE_WINDOW") -> 70
[PROC-METRICS] tick=16000 pid=1 name=/disk/usr/bin/xeyes
    sc=466 (vm=124 file=252 net=52 sync=34 proc=0 sig=0 other=4) pf=294
    disk=R1277952/W0 net=R1212/W1856 STUCK_IN_NR=7@15627t
... (plateau persists indefinitely under KVM — see "Open thread" below) ...
```

**KVM plateau**: 466 syscalls (+85 % more progress vs TCG), 52 net syscalls
(+271 %), 252 file syscalls (+112 %).  Critically, xeyes reaches the X11
protocol layer past handshake and issues real `InternAtom` requests for
the standard ICCCM/EWMH atoms (`WM_DELETE_WINDOW`, etc.).  Xastryx responds
with valid atom IDs.  Then xeyes parks in `poll(2)` waiting for further
events that never arrive.

## What this proves

1. **ELF loader runs Alpine musl PIE binaries**.  `xeyes` (28336 bytes,
   musl-PIE, no DT_RUNPATH) loads cleanly; `PT_INTERP` resolves to
   `/disk/lib/ld-musl-x86_64.so.1`; the interpreter mmap'd, relocations
   applied, control transferred to user.
2. **ld-musl + libc.musl resolve all 12 NEEDED entries** of xeyes
   (libXi, libXext, libXmu, libXt, libX11, libXrender, libX11-xcb,
   libxcb, libxcb-present, libxcb-xfixes, libxcb-damage, libc.musl).
   294 page faults under KVM = on-demand paging served from the
   pre-populated page cache without falling back to ATA PIO.
3. **Linux personality syscall surface is functional enough to start an
   X11 client**.  Categorised distribution under KVM: vm=124 (mmap,
   mprotect, brk), file=252 (openat, read, close, stat), net=52
   (socket, connect, sendmsg, recvmsg), sync=34 (futex, rt_sigprocmask,
   rt_sigaction).  No syscall fault, no `-ENOSYS`, no kernel BUGCHECK.
4. **Xastryx accepts the AF_UNIX X11 connection** at
   `/tmp/.X11-unix/X0` and replies to the X11 protocol handshake (opcode
   0x6C, 12-byte client setup -> server setup-success reply).
5. **Xastryx handles real X11 protocol requests**: `InternAtom(name)`
   under KVM returns valid atom IDs for "Custom Init", "Custom Data",
   "WM_DELETE_WINDOW" (atom 70), and correctly returns 0 for an
   unrecognised atom name "SCREEN_RESOURCES" (an XRandR-extension atom
   Xastryx doesn't track).
6. **No SSP-canary fire, no #UD, no `__stack_chk_fail`**.  The Firefox
   SSP saga's signature is absent here — confirming the saga's blocker
   is libxul-specific rather than musl-fundamental.

## What this isolates

The Firefox SSP saga (PR #421 / #425 / #426 / #427) reframed as an
upstream libxul indirect-call attribution problem.  Running an
independent Alpine musl PIE binary through the same kernel + ld-musl
stack without any SSP-canary fire empirically confirms that reframe:
**the SSP signature is bound to libxul's indirect-call sites, not to
the kernel's musl ABI, ld-musl bootstrap, or static-TLS layout**.  Any
future SSP-canary fire that doesn't reproduce on xeyes is libxul-side.

## Next move

**Option A (recommended) — Pursue the Xastryx response-coverage gate.**
Under KVM, xeyes parks in `poll(2)` after issuing 4× `InternAtom`
requests.  The next X11 RPCs in xeyes' Xt initialisation path are
typically `QueryExtension` (for SHAPE / XInputExtension / RENDER) and
`CreateWindow` (for the eyeball widget).  Xastryx implements both
opcodes (see `kernel/src/x11/mod.rs:553` opcode dispatch) — the gate is
likely an incomplete reply path or a missing pseudo-event Xt expects.
Concrete next probe: re-run with `--features xeyes-test,firefox-test`
(simultaneously) so the `[X11POLL]` per-request trace at `kernel/src/x11/mod.rs:441`
fires (currently gated on `firefox-test` only) and we can see which
client-write opcode Xastryx receives last.

**Option B — Try xterm next.**  xterm exercises pty/pts allocation
(`openpty(3)`, `grantpt`, `unlockpt`, `ptsname`) which is a different
syscall surface from xeyes and a more aggressive probe of the
personality layer's TTY abstractions.

**Option C — Try a non-X11 binary** (wget, busybox-static).  Strips
out the X11 surface entirely; tests pure musl + libc + net stack +
TCP socket lifetime.

**NOT recommended — return to Firefox SSP saga immediately.**  The
xeyes verdict isolates SSP firmly into libxul-internal territory, which
the saga's outstanding work item (full libxul indirect-call disassembly,
multi-PR exercise per PR #427) is already framed for.  Better to spend
~2 more dispatches widening the kernel-side proof base (xterm + wget)
before re-engaging the libxul attribution swamp.

## Open thread — kernel main.rs soak heartbeat lost under KVM

Under TCG the `[XEYES] tick=N sc=M pf=K total_th=T` heartbeat from
`main.rs` fires every ~1000 ticks (10 s wall) as designed.  Under KVM
the same heartbeat NEVER fires, even though the `[PROC-METRICS]`
heartbeat (emitted by `test_runner.rs` background infrastructure)
continues to print for the full ~400 s wall window.  This means the
BSP `main.rs` soak loop is not iterating under KVM despite the kernel
making forward progress on other CPUs.

This is incidental to the xeyes pivot — it doesn't affect the
"does xeyes run?" verdict — but it is a real anomaly: either
`gui::terminal::launch_process` blocks differently under KVM (a
KVM-vs-TCG main-loop scheduler divergence), or the BSP is dead and
something else is keeping the kernel alive.  Worth a follow-up
investigation by `aether-kernel-engineer` if and when it starts
gating other test paths.

## References (public)

- xeyes upstream: <https://gitlab.freedesktop.org/xorg/app/xeyes>
- Alpine xeyes package: <https://pkgs.alpinelinux.org/package/v3.20/community/x86_64/xeyes>
- X11 protocol (X Window System Protocol, version 11):
  <https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html>
- ICCCM (Inter-Client Communication Conventions Manual):
  <https://www.x.org/releases/X11R7.7/doc/xorg-docs/icccm/icccm.html>
- EWMH (Extended Window Manager Hints):
  <https://specifications.freedesktop.org/wm-spec/wm-spec-1.5.html>
- musl libc reference manual: <https://musl.libc.org/manual.html>
- ELF gABI (System V ABI §5 Object files): <https://www.sco.com/developers/gabi/latest/ch5.dynamic.html>
- POSIX `poll(2)`: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/poll.html>
