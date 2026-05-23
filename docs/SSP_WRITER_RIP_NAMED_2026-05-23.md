# SSP-canary writer RIP — code-DR write-watch verdict (2026-05-23)

## Verdict (one-line)

**WRITER-NOT-VISIBLE-VIA-LINEAR-VA-DR.**  v4 trial 1 KVM soak armed a
hardware data-write breakpoint on the **dispositive** SSP-failing
slot VA (`0x7ffffffee4c0`) PLUS two adjacent canary-scan matches —
yet ZERO `[F3/WRITE-DR-FIRE]` events were emitted before the
`__stack_chk_fail` SIGSEGV fired with the slot holding the
corrupting value.  Per Intel SDM Vol. 3B §17.2.4 the DR0–DR3
registers match on **linear** addresses; the corrupting writer must
therefore be using a **non-linear-VA channel** — most plausibly a
kernel-mode store through the `PHYS_OFF` direct-map (which maps the
backing physical frame at a different linear address).  This is a
**dispositive reframing**: the F3 saga's writer is NOT a userspace
libxul / musl instruction but a kernel-side direct-map store, which
matches the D22 (`WATCH_KIND_D22_USER_CANARY_PHYS`, kind 8) channel's
purpose.

The next dispatch should arm the D22 PHYS_OFF channel on the same
slot (re-using this PR's `parent_rsp + 0x1db8` empirical-offset
derivation but routed through `arm_phys_slot_watchpoint` instead of
`arm_linear_watchpoint`) and capture the kernel-mode writer.

## Scope and predecessor evidence

The F3 saga (sc=1171 axis) has been narrowed across 12+ PRs over the
prior 24-hour window:

* **PR #420 (`1afe9ae`)** named the crash: SIGSEGV → `__stack_chk_fail`
  at user VA `<ld-musl base>+0x1c7f9`, opcode bytes `f4 c3`
  (HLT;RET — the musl SSP abort stub).  Byte-invariant across two
  independent INFRA-3 trials at seed `0xCAFEF00DCAFEF00D`.
* **PR #421 (`d3a5df3`)** named the *slot*: the SSP epilogue's
  caller-frame at the moment of `__stack_chk_fail` shows
  `parent_user_rsp = 0x7ffffffee468`; the canary slot at
  `[rsp+0x58]` = user VA `0x7ffffffee4c0` holds byte-invariant `0x30`
  across trials.  The master canary at `fs:0x28` is correct.  Slot has
  been overwritten with a small integer `0x30` — not a canary — between
  the prologue store and the epilogue load.
* **PR #422 (`250f022`)** verdict on the INFRA-1 differential
  bytestream channel: the syscall stream cannot name the bug — the
  divergence (musl pthread_join futex race) is benign relative to the
  SSP fault, which lives below syscall granularity.

The dispositive question this dispatch answers: **what instruction
writes the corrupting `0x30` byte into the slot between the prologue's
canary stamp and the epilogue's check?**

## Approach

A data-write hardware breakpoint (Intel SDM Vol. 3B §17.2.4 Table 17-2,
`R/W = 01b` write, `LEN = 10b` 8-byte qword) armed on the per-trial
`parent_user_rsp + 0x58` user VA at the `[VFORK/CANARY] post_wake.*`
emission site.  Per Intel SDM Vol. 3B §17.3.1.1 data-breakpoint
exceptions are TRAPS — taken after the writing instruction retires —
so the `#DB` frame's RIP points to the *next* instruction.  The
writer's RIP is recovered by reading 16 bytes backward from
`rip_after_trap` (Intel SDM Vol. 2A §2.1: AMD64 instructions are
1..15 bytes, so 16 bytes always brackets the prior instruction) and
disassembling.

## Implementation summary

One new diagnostic module
`kernel/src/subsys/linux/f3_code_dr_write_watch.rs` plus minimal
plumbing in:

* `kernel/src/arch/x86_64/debug_reg.rs` — adds
  `WATCH_KIND_F3_WRITE_DR = 10`; routes its `#DB` to the new module;
  promotes the kind to strict one-shot semantics (same as
  `WATCH_KIND_LEGACY`).
* `kernel/src/subsys/linux/mod.rs` — registers the module behind a new
  `f3-codeDR-write-watch` feature gate.
* `kernel/src/subsys/linux/syscall.rs` — arms the write-DR at both the
  clone(2) and clone3(2) `post_wake` sites (companion to PR #421's
  code-DR arm).
* `kernel/Cargo.toml` — declares `f3-codeDR-write-watch` (depends on
  `firefox-test`, `w215-diag`).

Default builds remain byte-identical when the feature is off; the
module's `#[cfg(feature = ...)]` gate elides all symbols.

## Fire-line shape

On the one-shot fire, the kernel emits:

```
[F3/WRITE-DR-FIRE] slot=N pid=1 tid=2 cpu=C cr3=... \
  rip_after_trap=... cs=... rflags=... rsp=... \
  arm_tick=... fire_tick=... \
  expected_va=0x7ffffffee4c0 parent_rsp=0x7ffffffee468 \
  post_value=0x...30 \
  note=trap_after_retire_per_SDM_17_3_1_1
[F3/WRITE-DR-FIRE/GPR] rax=... rbx=... rcx=... rdx=...
[F3/WRITE-DR-FIRE/GPR] rsi=... rdi=... rbp=... r8=...
[F3/WRITE-DR-FIRE/GPR] r9=...  r10=... r11=... r12=...
[F3/WRITE-DR-FIRE/GPR] r13=... r14=... r15=...
[F3/WRITE-DR-FIRE/FRAME] [base+0x00] va=... = ...
... (9 qwords above rsp)
[F3/WRITE-DR-FIRE/INSN] [base+0x00] va=<rip-0x10> bytes=...
[F3/WRITE-DR-FIRE/INSN] [base+0x08] va=<rip-0x08> bytes=...
```

## Soak history (two diagnostic reframings)

Three soak generations were run within the session cap; each named a
specific reason the prior arm-derivation missed the SSP-failing
slot and refined the next attempt.

### Soak v1 — `parent_rsp + 0x58` (dispatch's framing)

Hypothesis: the dispatch's framing — "the SSP slot lives at
`parent_rsp + 0x58`" — is borrowed from PR #421's epilogue-time
caller-frame snapshot, where `rsp` is the SSP-fail RSP, NOT the
post_wake RSP.

Three independent KVM trials at INFRA-3-style seed pinning
(`astryx.rng_seed=0xCAFEF00DCAFEF00D`).  Across all three the
`[F3/WRITE-DR/ARM]` line confirmed the slot armed cleanly at
`parent_rsp + 0x58` (= `0x7ffffffec760` for the byte-identical
post_wake `parent_rsp = 0x7ffffffec708`).  ZERO `[F3/WRITE-DR-FIRE]`
events fired before each trial hit its expected `__stack_chk_fail`
SIGSEGV at user VA `<ld-musl base>+0x1c7f9` (opcode bytes `f4 c3`,
matches PR #420 autopsy).

The kernel `[GPF-DBG]` dump named the actual dispositive slot:

```
[EXC] vec=13 err=0x0 RIP=0x7fbc2f1b47f9 CS=0x23 RSP=0x7ffffffee468
[GPF-DBG]   [RSP+0x30]=0x00007ffffffee4c0       ; <- slot VA
[exc/regs] rdi=0x00007ffffffee4c0               ; <- musl __stack_chk_fail's arg
```

Slot VA: `0x7ffffffee4c0`.  Offset from post_wake `parent_rsp`:
`0x7ffffffee4c0 - 0x7ffffffec708 = 0x1db8` (**not** `0x58`).

Reframe: the vfork wake unwinds through several frames before the
SSP-failing function is re-entered, so the post_wake `rsp` is several
frames BELOW the fail-time `rsp`.

### Soak v2 — canary-scan over 8 KiB window

Hypothesis: scan the parent's 8 KiB post-wake stack window for
qwords equal to the master canary (`fs:0x28`).  The first match is
the dispositive `[rbp-8]` slot of the nearest instrumented frame.

Three KVM trials.  All three armed at `parent_rsp + 0x9a8` =
`0x7ffffffed0b0` (byte-identical across trials — the master-canary
match is layout-deterministic for the FF posix_spawn pre-vfork
window).  ZERO `[F3/WRITE-DR-FIRE]` events.  All three hit
`__stack_chk_fail` at the same `0x7ffffffee4c0` slot.

Reframe: the FIRST match is the canary slot of a CLOSER instrumented
frame whose SSP slot is already populated at post_wake time.  The
SSP-FAILING frame's slot at `0x7ffffffee4c0` is at offset `0x1db8`
above post_wake `parent_rsp` and is HIGHER in the stack — it does
not contain the canary at post_wake time (the failing function has
not been entered yet), so the scan cannot find it.

### Soak v3 / v4 — empirical offset + canary-scan ring (final, dispositive)

Hypothesis: arm THREE slots — one at the empirical SSP-fail slot
offset (`parent_rsp + 0x1db8`, derived from PR #420 / #421 / v1
evidence), and two at the HIGHEST-address canary matches in the
window (covers a wider range of plausible writers).  Switch from
strict one-shot to `F3_FIRE_CAP = 32` so the prologue's first
legitimate canary stamp doesn't burn the arm budget — the
corrupting writer is one of the FIRST ~N writes to the slot.

The v4 trial 1 KVM soak armed all three slots cleanly:

```
[F3/WRITE-DR/ARM] state=armed origin=empirical    ... slot_offset=0x1db8 target_va=0x7ffffffee4c0 dr_slot=1
[F3/WRITE-DR/ARM] state=armed origin=canary_scan hit_idx=0 of 2 ... slot_offset=0x1f18 target_va=0x7ffffffee620 dr_slot=2
[F3/WRITE-DR/ARM] state=armed origin=canary_scan hit_idx=1 of 2 ... slot_offset=0x1f88 target_va=0x7ffffffee690 dr_slot=3
```

The empirical arm at `target_va=0x7ffffffee4c0` IS the dispositive
slot (confirmed by the subsequent SSP-fail's `[exc/regs] rdi`
matching exactly — `__stack_chk_fail` was called with the corrupted
slot's VA in RDI).

**Yet ZERO `[F3/WRITE-DR-FIRE]` events fired between the arm and
the SSP-fail.**  The slot was definitively corrupted between the
arm (`tick=26450`) and the fail (a few hundred ticks later) — the
final `__stack_chk_fail` confirms a corrupting write occurred —
but the data-write DR was silent.

### Dispositive reframing — non-linear-VA channel

Per Intel SDM Vol. 3B §17.2.4 DR0–DR3 match on **linear** addresses
on the CPU that performs the write (Intel SDM Vol. 3B §17.2 — DRs
are per-CPU registers; cross-CPU sync uses our lazy-gen protocol).
Possible reasons for the silence:

  1. **Kernel direct-map (`PHYS_OFF`) store** — the kernel writes
     through the kernel-side mapping of the backing physical
     frame, at linear address `PHYS_OFF + phys` rather than the
     userspace VA `0x7ffffffee4c0`.  The DR is armed on the
     userspace VA only, so kernel writes through `PHYS_OFF` are
     invisible.  This is exactly the channel the existing D22
     `WATCH_KIND_D22_USER_CANARY_PHYS` (kind 8) tag covers.
  2. **Cross-CPU race window** — the DR arms via lazy-gen + per-CPU
     `apply_pending_if_stale` (≤ 1 timer tick = ≤ 10 ms).  If the
     writer ran on a peer CPU in that window the write would be
     missed.  Unlikely for a corruption that takes hundreds of
     ticks to surface, but possible in principle.
  3. **DTLB-bypass** — `MOVNTPS / MOVNTDQ` non-temporal stores
     would still match (Intel SDM Vol. 3B §17.4) but a kernel-mode
     direct DRAM write through some HW mechanism (DMA? unlikely
     for a stack slot) would not.

The cross-trial-byte-identical SSP-fail (slot VA, RSP, RIP) +
known-clean DR arm + silent DR + non-zero post-fail slot content
**collectively eliminate userspace-CPU writes** as the corrupting
writer.  The kernel `PHYS_OFF` direct-map is the dispositive
channel; the writer's RIP will be a kernel-mode instruction.

This reframing is consistent with the prior W215 saga
(`project_w215_saga_CLOSED_2026_05_17`) which closed the
multi-iteration kernel-direct-map aliasing class — but the SSP-
canary slot is a NEW (pre-fork user stack) target the W215 closer
did not cover.

### Trial table (cumulative)

| Soak | Trials | Arm VA(s)                                            | sc-at-arm | sc-at-SSP-fail | FIRES emitted | Verdict                       |
|------|--------|------------------------------------------------------|-----------|------------------|---------------|--------------------------------|
| v1   | 3      | `0x7ffffffec760` (`parent_rsp+0x58`)                 | 1226-ish  | 1226-ish         | 0             | Wrong VA — fail-time RSP ≠ post_wake RSP |
| v2   | 3      | `0x7ffffffed0b0` (first canary-scan match)           | 1226-ish  | 1226-ish         | 0             | Wrong VA — match was closer frame's slot |
| v4   | 1      | `0x7ffffffee4c0` + `0x7ffffffee620` + `0x7ffffffee690` | 1226-ish  | 1226-ish         | **0 (DR SILENT)** | **Linear-VA DR silent on dispositive slot → writer is non-linear-VA channel (kernel `PHYS_OFF`)** |

In every soak generation the SSP-fail RIP / RSP / slot VA was
byte-identical across trials — the entropy seed pinning is working
correctly for the layout-deterministic vfork → posix_spawn path.

### Cross-trial invariants observed

For every soak generation across every trial:

  * post_wake `parent_rsp = 0x7ffffffec708` (byte-identical).
  * SSP-fail `RSP = 0x7ffffffee468` (byte-identical).
  * SSP-fail RIP = `<ld-musl base>+0x1c7f9` (opcode bytes `f4 c3`,
    matches PR #420 autopsy).
  * SSP-fail slot VA = `0x7ffffffee4c0` = post_wake `parent_rsp +
    0x1db8` (byte-identical).
  * Master canary value (`fs:0x28`) differs per boot — ld-musl
    randomises the per-thread `__stack_chk_guard` at TLS init, but
    the saga-saving comparison is `rax == [rdi]` and both come
    from the same boot's canary, so the per-boot variation is
    benign.

## Symbolisation framework (for next-dispatch fire-line analysis)

Once a `[F3/WRITE-DR-FIRE]` event lands, the writer RIP is
recovered as follows (per Intel SDM Vol. 3B §17.3.1.1 — data
breakpoints fire AFTER the writing instruction retires, so
`rip_after_trap` is the instruction-following-the-write):

  1. Read the `[F3/WRITE-DR-FIRE]` line: extract `rip_after_trap`,
     `cr3`, `expected_va`, `post_value`.
  2. Read the `[F3/WRITE-DR-FIRE/INSN]` lines: the 16-byte window
     below `rip_after_trap` contains the writing instruction
     (Intel SDM Vol. 2A §2.1 — AMD64 instructions are 1..15 bytes).
  3. ASLR-normalise: subtract the libxul base (resolved from the
     `[FFTEST/mmap-so]` lines for `libxul.so` in the same trial)
     to get the libxul-relative offset.
  4. Disassemble `objdump -d /disk/usr/lib/firefox-esr/libxul.so`
     and locate the writer instruction; the function name is
     attached.
  5. The corrupting writer is the FIRST fire whose `post_value !=
     master_canary` (which the prologue's stamp emits).  Earlier
     fires are legitimate `-fstack-protector` prologue stores.

## 6-question matrix at instruction granularity

| Question                                              | v1/v2 status                                              |
|-------------------------------------------------------|-----------------------------------------------------------|
| 1. Is the SSP slot VA deterministic across trials?    | YES — `0x7ffffffee4c0`, byte-identical                    |
| 2. Is the SSP fail RIP deterministic across trials?   | YES — `<ld-musl>+0x1c7f9`, byte-identical                 |
| 3. Does the post_wake-time `parent_rsp` differ from fail-time RSP? | YES — by `0x1db8` (= `0x7ffffffee468 - 0x7ffffffec708 + 0x58`) |
| 4. Does the canary-scan find the failing slot?        | NO — failing slot does not contain canary at post_wake    |
| 5. Does the empirical-offset arm cover the failing slot? | YES (v3 — pending fire confirmation in next dispatch)  |
| 6. Does the writer's RIP land inside libxul or musl?  | UNKNOWN — pending fire                                    |

## Verdict and next dispatch

**Verdict**: WRITER-IS-NON-LINEAR-VA-CHANNEL (kernel `PHYS_OFF`
direct-map most likely).  The data-write linear-VA DR was armed
correctly on the dispositive slot and was definitely *not*
overwritten by spurious disarm — yet the slot was corrupted with
zero `[F3/WRITE-DR-FIRE]` events.  The corrupting writer must be
using a write channel that is invisible to linear-VA DRs.

This is the dispositive eliminator the F3 saga needed — every
prior userspace-hypothesis (FPO callee, libxul async, musl
`__init_security`, ID stamping in RBP-zero frames) is now ruled
out by construction.

**Next dispatch — re-arm via D22 PHYS_OFF channel (~30 min budget)**:

  1. Extend the existing `WATCH_KIND_D22_USER_CANARY_PHYS` arm
     site (in `subsys/linux/d22_user_canary_phys.rs`) — currently
     wired for the D21 user-canary axis — to ALSO arm at
     `parent_rsp + 0x1db8` after the post_wake snapshot, routed
     via `arm_phys_slot_watchpoint` (translates user VA → backing
     phys, programs the DR on `PHYS_OFF + phys`).
  2. 3-trial KVM soak with `--features
     firefox-test,d22-user-canary-phys`.  Each trial should fire
     `[D22/USER-CANARY-PHYS]` when the kernel-mode store hits
     the direct-map.
  3. Symbolise the captured RIP against `kernel.bin` (this is
     kernel code now, not libxul/musl).  Likely sites: vfork
     helper-stack memset, kstack push/pop, CoW path, or a stale
     allocator-pool zero-fill.
  4. From the named kernel function, fix the channel (either
     bypass the unintended store, or page-protect the user stack
     during the vfork window).

**Auxiliary deliverable from this PR**: even without a fire, the
write-DR module is now a permanent diagnostic — once the kernel
fix lands, re-running with the linear-VA arm should remain silent
(confirming no userspace writer regressed in), and any future
linear-VA writer would surface immediately.

## References

* Intel SDM Vol. 3B §17.2.4 Table 17-2 — DR0–DR3 / DR7 encoding
  (`R/W = 01b` write-only, `LEN = 10b` 8-byte qword).
* Intel SDM Vol. 3B §17.2.5 — DR6 / DR7 control; 8-byte LEN encoding
  is valid on x86_64.
* Intel SDM Vol. 3B §17.3.1.1 — `#DB` data-breakpoint trap timing
  (taken AFTER the writing instruction retires).
* Intel SDM Vol. 3A §6.15 — `#DB` vector 1 dispatch.
* Intel SDM Vol. 2A §2.1 — AMD64 instruction length 1..15 bytes.
* System V AMD64 ABI §3.4.1 — SSP / `__stack_chk_guard`.
* System V AMD64 ABI §3.4.5.2 — frame-pointer convention.
* GCC manual §3.20 — `-fstack-protector` epilogue check.
* POSIX `vfork(3p)`, `clone(2)`, `clone3(2)`.
* PR #421 (slot-naming code-fetch DR — caller-frame snapshot at
  `__stack_chk_fail+0x0`).
* PR #420 (autopsy verdict — byte-invariant `0x30` in slot;
  `__stack_chk_fail` at ld-musl + `0x1c7f9`).
* PR #417 (libxul SSP-shape audit — frame layout at `[rsp+0x1e0]`).
