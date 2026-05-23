# Linux RBP ground-truth walk at libxul `__stack_chk_fail` (Wave 15, R-B)

**Date**: 2026-05-23
**Author**: principal-systems-engineer
**Saga**: user-SSP canary mismatch (sc=1171 / F3 / R-A→R-B)
**Status**: Reference data — no code changes, doc-only

## TL;DR

Linux preserves the parent's user-mode RBP **bit-for-bit** across the
`vfork()` syscall window. Across four `vfork()` rounds in an
SSP-instrumented musl test program (Ubuntu 24.04 / kernel
`6.8.0-117-generic`), `RBP = 0x7fffffffeb30` was stable at PROLOGUE,
PRE-VFORK, POST-VFORK, and SSP-EPILOGUE sites; `[rbp-8]` canary stable
at `0x24351f8c974a0006`; `__stack_chk_fail` did not fire. PR #410
already proved AstryxOS slot-11 RBP bit-stable at `0x7ffffffec738`
3/3 KVM trials. **Both sides preserve RBP. RBP-chain identity (R-A
and R-B-as-posed) is closed.** The SSP mismatch must be either an
out-of-band write to the parent's `[rbp-8]` memory while parked, or a
guard-side rewrite at `fs:0x28`.

## Methodology

Re-used PR #394 infrastructure: QEMU 10.2.1 + KVM, Ubuntu 24.04 noble
cloud image, 9p `/shared` mount. Copied the AstryxOS-shipped
`ld-musl-x86_64.so.1` (sha256
`19738ba9b967e61ea87c6530f428f811eb16af0b111e83bfc348e26886324b66`)
plus `libc.musl-x86_64.so.1`, `libstdc++.so.6.0.32`, `libgcc_s.so.1`,
`libscudo.so` from AstryxOS `build/disk/` into the guest. Confirmed
`__stack_chk_fail` lives at offset `0x1c7f9` (`f4 c3` HLT;RET, musl
1.2.5 abort convention) — same offset as AstryxOS.

Test program `vfork-rbp-probe.c` (`musl-gcc -O0 -g -fno-pie -no-pie
-fno-omit-frame-pointer -fstack-protector-strong`): SSP-guarded
`do_vfork_dance()` calls `vfork@plt @ 0x401201`, waits for child,
runs SSP epilogue at `0x401254-0x401261` (`mov rdx, [rbp-8] ; sub
rdx, fs:0x28 ; je .ok ; call __stack_chk_fail@plt`). Structurally
identical to the libxul vfork-caller frame that trips AstryxOS BUGCHECK
0xdead0001 (System V AMD64 ABI §3.4.5.2 frame-pointer convention,
System V x86_64 psABI §6.4 TLS variant II `__stack_chk_guard` at
`fs:0x28`).

Probes per vfork round: PROLOGUE-STORE (`0x4011e1`), PRE-VFORK
(`0x401201`), POST-VFORK (`0x401206`), SSP-EPILOGUE (`0x401254`),
SSP-CMP-JE (`0x401261`). Permanent breakpoint on `__stack_chk_fail`.

## Linux capture

4 vfork rounds, one round shown — all 4 identical:

```
PROLOGUE-STORE  rip=0x4011e1 rbp=0x7fffffffeb30 [rbp-8]=0x24351f8c974a0006  rax(canary)=0x24351f8c974a0006
PRE-VFORK       rip=0x401201 rbp=0x7fffffffeb30 [rbp-8]=0x24351f8c974a0006
POST-VFORK      rip=0x401206 rbp=0x7fffffffeb30 [rbp-8]=0x24351f8c974a0006  rax(vfork-ret)=2606
SSP-EPILOGUE    rip=0x401254 rbp=0x7fffffffeb30 [rbp-8]=0x24351f8c974a0006
SSP-CMP-JE      rip=0x401261 rbp=0x7fffffffeb30 rdx(canary-fsguard)=0x0  (canary OK)
```

Saved-RBP at `[rbp+0]` = `0x7fffffffeb60`; saved-RIP at `[rbp+8]` =
`0x4012ba`; both bit-stable across all 4 rounds.

FS-BASE / guard-stability pass:
```
PROLOGUE  rbp=0x7fffffffeb30 fs_base=0x7ffff7ffdb08 *(fs_base+0x28)=0xc4fe67537d0c0010
POST-VFK  rbp=0x7fffffffeb30 fs_base=0x7ffff7ffdb08 *(fs_base+0x28)=0xc4fe67537d0c0010
SSP-CMP   rbp=0x7fffffffeb30 fs_base=0x7ffff7ffdb08 *(fs_base+0x28)=0xc4fe67537d0c0010  rdx=0
```

FS_BASE bit-stable; `__stack_chk_guard` bit-stable; RBP bit-stable;
`[rbp-8]` bit-stable; SSP check succeeds. (Canary differs from the
RBP-walk run because musl re-seeds from `AT_RANDOM` per process start
— per-process, intra-run stability is what matters and is total.)

## AstryxOS comparison

From PR #410 (`88a9c23b`, landed 2026-05-23 04:17Z):

| Property | Linux (this) | AstryxOS (PR #410) |
|---|---|---|
| RBP at PRE-VFORK (= what kernel saves slot-11) | `0x7fffffffeb30` | (proxy via slot-11) `0x7ffffffec738` bit-stable 3/3 |
| RBP at POST-VFORK (= what SYSRET restored) | `0x7fffffffeb30` (= pre, no drift) | (= slot-11 by IRETQ semantics, PR #407 proved slot-14 RSP bit-stable analogously) |
| RBP at SSP-epilogue | `0x7fffffffeb30` (= pre, no drift) | (downstream of vfork-return; same frame, no intermediate FPO) |
| `[rbp-8]` through window | bit-stable `0x24351f8c974a0006` | **corrupted (saga symptom)** |
| `fs:0x28` through window | bit-stable `0xc4fe67537d0c0010` | not yet captured |
| `__stack_chk_fail` fires | NO (0/4) | YES (BUGCHECK 0xdead0001) |

## Named (non-)divergence

**R-A (RBP-identity across `schedule()`) is closed.** Both kernels
preserve RBP byte-for-byte. The slot-11 value at AstryxOS
`kstack_top - 32` IS the userland RBP at resume — PR #410 verified the
kernel save/restore, this walk verifies the userland frame stays put.

**R-B-as-posed (FPO calling-convention skew) is also not the answer.**
The chain is intact on both sides; musl's `vfork` wrapper does
`pop %rdx ; syscall ; push %rdx` and does not touch RBP — so the
kernel's slot-11 RBP IS the immediate libxul caller's RBP, which is
the SSP-instrumented frame.

**Un-falsified axes (R-B reframed)**:

1. **Out-of-band write to `[rbp-8]` while parent is parked.** Some
   kernel-side path writes into the parent's user-stack VA between
   pre-block and post-wake.
2. **`fs:0x28` rewrite.** PT_TLS .tbss bzero landing on
   `__stack_chk_guard`, or any `arch_prctl(SET_FS)` re-issue across
   the window. (Intersects sc=1171 PT_TLS axis from
   [[project_session_handoff_2026_05_22]].)

## Recommended fix shape (kernel-side; never edit upstream binaries)

Pick one bounded probe; do (a) first (cheaper):

(a) **`fs:0x28` stability** — extend `[VFORK/CANARY]` to read
`*(fs_base_parent + 0x28)` at the existing pre/post emit sites,
report `same` / `drift=...`. ~30 LOC. If `drift`, saga reframes onto
PT_TLS init. If `same`, run (b).

(b) **Canary-slot writer hunt** — add a DR-watchpoint over the 8-qword
window centred on captured `rbp - 8` for the parent thread between
`pre_block.clone[3]` and `post_wake.clone[3]`. Any write prints
`[CANARY-WRITER]` with writing-thread TID, RIP, CR3. ~80 LOC,
additive to existing diagnostic, uses the DR-watchpoint infra from
PR #407 generation.

## Public-spec citations

- System V AMD64 ABI 1.0 §3.4.5.2 (RBP preservation across calls)
- System V x86_64 psABI §6.4 (`__stack_chk_guard` at `fs:0x28`)
- Intel SDM Vol. 3A §6 (IRETQ / SYSRET restore semantics)
- Linux man-pages 6.7: `vfork(2)`, `arch_prctl(2)`
- musl.libc.org (`vfork` wrapper preserves RBP)
- GCC manual §3.20 (`-fstack-protector-strong`)

## Raw data files (not committed)

`/home/ubuntu/linuxgt/shared/`:
- `vfork-rbp-probe.c` (~50 LOC)
- `vfork-rbp-probe-musl` (20 KiB ELF, debug)
- `walk-deep.gdb`, `walk-fs.gdb`
- `walk-final.log` (~5 KiB)
