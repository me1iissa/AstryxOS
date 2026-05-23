# sc=1171 autopsy result — CRASH-NAMED at musl `__stack_chk_fail+0x0`

**Date**: 2026-05-23
**Dispatch**: post-INFRA-4 deterministic-replay autopsy against the sc=1171
plateau (re-named with current evidence after Wave 14 falsification of
PR #419 kstack-canary closure)
**Infrastructure used**: INFRA-2 `qemu-harness.py autopsy` (cherry-picked
into this worktree from `4ea3e7f`) + INFRA-3 record/replay primitives
(cherry-picked from `dfec2ab`); kernel features
`firefox-test,record-replay,kdb` + cmdline `astryx.rng_seed=0xCAFEF00DCAFEF00D`
**Trials**: 2, both KVM, both reproduced byte-identical (record-replay
deterministic substrate validated end-to-end)

---

## Verdict

**CRASH-NAMED.** The sc=1171 gate is a **userspace SSP failure** in
PID 1 (`/disk/usr/lib/firefox-esr/firefox-bin`), TID 2 (parent), with
trap-RIP at musl `__stack_chk_fail+0x0`. The kernel is not the proximate
faulter; the kernel sees the user-mode `hlt` instruction (`0xf4`) execute
at CPL=3 and synthesises the resulting `#GP` into `exit_group(-13)` per
musl `crt_arch.h` SSP convention.

The autopsy at the trap site itself could not be planted via the INFRA-2
software-breakpoint mechanism (GDB `Z0` write into the user-VA page
returns `armed: false` — the stub cannot place an INT3 in a user-mapped
page when the running CR3 at arm time is not the target process; this is
the documented "GDB literally cannot reach" exception class in the
autopsy-first rule). Crash naming is therefore via post-mortem
serial-log evidence captured by the existing `[FAULT/PHYS/RAW16]` and
`[FAULT/RIP-CONTENT]` rings; their bytes were cross-walked against the
on-disk `/disk/lib/libc.musl-x86_64.so.1` (BuildID
`cc77a6e278a161964ce8abdbe0751ad333aff469`) to symbolise.

## Dispositive evidence (both trials)

### Trap site and instruction stream

```
[FAULT/PHYS] pid=1 tid=2 rip=0x7f41a4b567f9 rip_phys=0x12911000 vma_offset=0x87f9
[FAULT/PHYS/RAW16] rip=0x7f41a4b567f9 bytes=f4 c3 48 8b 05 9e 27 08 00 53 48 8b 18 48 c7 00
```

Disassembly via `objdump -d` of musl libc at file offset `0x1c7f9`
(load-base-adjusted from RIP — load base = `0x7f41a4b3a000`):

```
000000000001c7f9 <__stack_chk_fail>:
   1c7f9:       f4                      hlt
   1c7fa:       c3                      ret
000000000001c7fb <clearenv>:
   1c7fb:       48 8b 05 9e 27 08 00    mov    0x8279e(%rip),%rax
```

This is musl's published two-byte abort sequence (sysV AMD64 ABI
§3.4.1 — `hlt` at CPL=3 raises `#GP` which the kernel routes to
`SIGSEGV`, then `exit_group(-13)`; cross-walk per public musl source
convention). The next 14 bytes captured by the RAW16 ring exactly match
the next symbol `<clearenv>` — i.e. there is no off-by-N RIP framing
error; the kernel is faulting on the exact first byte of
`__stack_chk_fail`.

### vfork canary window (the F3 axis is hot)

Both trials emit identical `[VFORK/CANARY]` pre/post pairs:

```
pre_block.clone  fs_base=0x7f41a4bdbb28 fs_28=0x37b9354151870065
                 user_rsp=0x7ffffffec708 rsp_slot14=0x7ffffffec708
                 rbp_slot11=0x7ffffffec738 rbp_diff=pre
                 s_1d58=0x7ffffffee4c0 s_1d60=0x7eff8b1ad5f5

post_wake.clone  fs_base=0x7f41a4bdbb28 fs_28=0x37b9354151870065
                 user_rsp=0x7ffffffec708 rsp_slot14=0x7ffffffec708
                 rbp_slot11=0x7ffffffec738 rbp_diff=same
                 s_1d58=0x7ffffffee4c0 s_1d60=0x7eff8b1ad5f5
```

Key observations:

1. **`fs_28` (musl per-thread SSP guard, loaded via `mov %fs:0x28,…` per
   sysV AMD64 ABI §11.4 TLS Variant II) is invariant across the
   vfork window.** The TLS guard at fs:0x28 did **not** rotate / drift.
2. **`rbp_slot11` is identical pre and post (`rbp_diff=same`).** The
   RBP-derived stack-frame identity at the vfork return site appears
   unchanged.
3. **`s_1d58=0x7ffffffee4c0`** — the F3-axis canary VA, identical to the
   address captured in Waves 12–14 D21/D22 diagnostics
   ([[project_d22_wave13_falsification_2026_05_23]]).
4. **`s_1d8=0` and `s_1e0=0`** in the slot-14/slot-15 window — those
   slots are zero, NOT containing a canary signature byte. Whatever
   `__stack_chk_fail` is comparing against, it lives at a slot the
   `[VFORK/CANARY]` snapshot does not directly capture (the snapshot
   dumps slot-11, slot-14, slot-d58, slot-1d58, slot-1d60 — the actual
   prologue-stamped canary in the failing function lives elsewhere).

### Syscall ordinal stream up to fault

The deterministic-replay `[SC-REC]` stream identifies the last 6
syscalls before TID 2 traps. The vfork→child→parent-resume sequence is
the immediate predecessor:

```
ord=1212  sc=293 (vfork)           pid=1 tid=2 rip=0x7f41a4b9c3a8
ord=1213  sc=56  (clone, flags=0x4111)
                                   pid=1 tid=2 rip=0x7f41a4b988a6
ord=1214  sc=14  (rt_sigprocmask)  pid=1 tid=4  ← child runs
ord=1215  sc=157 (prctl)           pid=1 tid=4
ord=1216..1224 — child loops sched_yield+SIGACTION until ord=1226 futex_wake
                                   pid=1 tid=4 → wakes parent
ord=1225+ — pid=2 tid=5 (cloned-process) runs sigaction init
                                   pid=2 tid=5
[VFORK-STACK] cleanup parent_pid=1 base=0x7f362cdfb000 length=0x10000
                                                       unmapped_pages=1
[VFORK/CANARY] post_wake.clone … (canary window snapshot ALL invariant)
[FAULT/PHYS] pid=1 tid=2 rip=0x7f41a4b567f9   ← parent resumes, immediately traps
```

The crash fires in the **very next instruction** after the parent
resumes from the vfork wake. There is no intervening parent syscall
between `post_wake` and the trap — meaning the failing function ran
its **epilogue** (canary check) immediately upon return-to-userspace
and detected mismatch.

### Deterministic-replay validation (INFRA-3)

Both trials at seed `0xCAFEF00DCAFEF00D` produced byte-identical
values for: trap RIP `0x7f41a4b567f9`, trap phys `0x12911000`,
`fs_28=0x37b9354151870065` pre/post, `s_1d58=0x7ffffffee4c0`,
last-syscall ordinal 1226 (futex_wake from child wakes parent), and
post-fault phys totals (recorded=15 displaced=0). The deterministic
substrate is sound and is the canonical reproducer for this gate.

## What the autopsy did NOT establish

1. **Caller RIP / callsite.** `__stack_chk_fail` is `f4 c3 ret`; the
   return address pushed by the caller's `call` sits at `[rsp]` at
   trap time. The autopsy preset `ssp-fail-snapshot` captures
   `mem_via_reg rsp 0` — but only when the breakpoint plants. With
   `Z0` rejected we do not have the `[rsp]` qword. The caller is the
   `call __stack_chk_fail` site in the libxul or musl function whose
   epilogue ran immediately upon vfork-wake.
2. **Failing canary slot identity.** The `[VFORK/CANARY]` snapshot dumps
   five named slots (`s_1d8`, `s_1e0`, `s_d58`, `s_1d58`, `s_1d60`) but
   none of them are the actual `[rbp-8]` slot of the failing function
   itself — the prior INFRA-4 SSP-shape audit
   ([[a29cf97e]] commit) established the failing function is FPO
   with the canary at `[rsp+0x1e0]` of its own frame, NOT at the
   D21/D22 arm-site formula `caller_rsp+0x1d50`.
3. **Which slot was written by whom.** This requires arming D21
   (linear-VA DR0 on the prologue-stamped canary VA) OR D22 (PHYS_OFF
   shadow channel) which are gated behind the
   `firefox-test,ssp-canary-diag,d22-user-canary-phys` feature set; the
   build under autopsy here did NOT include those flags.

## Cross-walk with prior investigations

| Wave | Verdict | Relation to this autopsy |
|---|---|---|
| W12 D21 stack-frame canary watch | Parent-stack collision (PR #404) | Same failing canary VA `0x7ffffffee4c0` |
| W13 D22 PHYS_OFF channel | `phys_at_arm==phys_at_write` — NOT phys-aliasing (#408) | Confirms backing frame is consistent; failure is user-VA-mismatch |
| W14 user-RBP-identity reframe | RBP at vfork-wake matches; `0x68` delta is inter-frame | Confirmed here: `rbp_diff=same` |
| W15 INFRA-4 reframe | Caller function is FPO; canary at `[rsp+0x1e0]` not `caller_rsp+0x1d50` | Need code-DR on `__stack_chk_fail@plt` (~40 LOC) per [[a29cf97e]] |
| Kstack canary axis (PR #419) | Kernel-tier canary closed; new gate exposed | This autopsy IS that new-gate plateau |

The verdict is **consistent** with the Wave 15 INFRA-4 reframe: the
sc=1171 gate is the **userspace** SSP class (musl `__stack_chk_fail`
called by an FPO libxul function whose `[rbp-8]` got clobbered during
the vfork window), distinct from the kernel-tier kstack canary class
closed by PR #419.

## Verdict statement

**Gate sc=1171 (re-named): musl `__stack_chk_fail+0x0` SSP-abort in
PID 1 / TID 2 immediately after vfork-wake.** The `fs:0x28` per-thread
guard is invariant across the vfork window (NOT FSBASE drift). The
failing canary slot is on the parent's user stack at an offset within
the FPO caller's frame; some store during the vfork-substitution window
(child running on parent's stack, then VFORK-STACK cleanup unmapping
the child-stack range) clobbered it. The verdict is a **CRASH**, not
a HANG, and the proximate writer remains unnamed because the writer is
no longer at the write site by trap time (fire-and-forget corruption
class — the legitimate exception under the autopsy-first rule).

## Recommended next dispatch

**One bounded fix-it dispatch, ~40 LoC, `aether-kernel-engineer`:**
add a code-DR (instruction-fetch hardware breakpoint via DR0–DR3 in
exec mode per Intel SDM Vol. 3B §17.2.4) on the user-VA
`0x7f41a4b567f9` (musl `__stack_chk_fail+0x0`), armed at the same
gating point as the existing D21 user-canary watch (first PID 1 TID 2
syscall after the F3 `[VFORK/CANARY]` post_wake snapshot has captured
`s_1d58=0x7ffffffee4c0`). On `#DB` fire, dump:

- full GPR + segment regs (the existing `handle_db_exception` shape)
- `[rsp]..[rsp+0x40]` (the caller's return address + saved GPRs)
- `[rbp-0x10]..[rbp+0x10]` (the caller's frame around `[rbp-8]`)
- the `KERNEL_VIRTUAL_TICKS` ordinal (INFRA-3 substrate)

This single fire names the caller (= the libxul or musl function whose
SSP check failed) and gives the `[rbp-8]` value at the moment of the
check, which when cross-walked against `fs:0x28` answers whether the
canary was overwritten (stack-overflow class) or whether the comparand
load was misframed (FPO-skew class — the W15 INFRA-4 framing).

Estimated diff: 35–45 LOC across
`kernel/src/subsys/linux/{f3_watch.rs, mod.rs}` reusing existing
`debug_reg::arm_linear_watchpoint` plumbing; depends on
`firefox-test,ssp-canary-diag` feature set already present in the tree.
PR title shape: `kernel/subsys/linux: code-DR on musl __stack_chk_fail
entry (Wave 16 caller-RIP name)`. Cite Intel SDM Vol. 3B §17.2.4 and
sysV AMD64 ABI §3.4.1, §11.4.

If that fire's `[rsp]` resolves to a libxul RIP, the next dispatch is
to `abi-compatibility-engineer` for an objdump+CFI walkthrough of the
caller function. If it resolves to a musl RIP, the next dispatch is to
`userspace-engineer` for the libc compatibility lens.

## Artefacts

- `docs/SC1171_AUTOPSY_RESULT_2026-05-23_artifacts/autopsy.json` —
  the autopsy attempt JSON (`armed: false`, zero hits — confirming
  the documented "GDB cannot reach" Z0 exception)
- Session serial logs: `~/.astryx-harness/{fd7c6ce7b1b7,1f8d37bc3b36}.serial.log`

## References (public specs only)

- Intel SDM Vol. 1 §6.5 (`HLT` at CPL>0 → `#GP`); Vol. 3A §3.4.4
  (FSBASE/GSBASE MSRs); Vol. 3B §17.2.4 (DR0–DR3, DR7 — hardware
  breakpoints incl. code-execute mode)
- sysV AMD64 ABI §3.2 (stack frame, `[rbp-8]` canary); §3.4.1
  (process termination); §11.4 (TLS Variant II, `fs:0x28` guard)
- GDB Remote Serial Protocol — `gnu.org/software/gdb/documentation/`
  (Z0 packet semantics)
- QEMU `docs/specs/fw_cfg.txt` (the `opt/astryx/cmdline` channel)
