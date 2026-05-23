# D22 falsification cross-walk — user-RBP-identity hypothesis

**Date**: 2026-05-23
**Author**: tech-lead (doc-only)
**Inputs**: PR #408 (D22 phys, FALSIFIES Mechanism D), PR #407 (Wave 12
vfork-return RSP audit), PR #406 (D21 B1/B2 reject), PR #405 (D21 cross-walk),
PR #404 (D21 DR-watch), PR #394 (Linux ground-truth)

## 1. TL;DR

**Picked dispatch: `aether-kernel-engineer` audit of parent user-RBP identity
across the vfork wake window.** D22 ruled out phys-aliasing
(`phys_at_write == phys_at_arm` byte-for-byte, 3/3 KVM). The "two phys"
shape was two *distinct linear VAs* — write_va `0x7ffffffee458` vs read_va
`0x7ffffffee4c0`, 0x68 apart in the same frame. Remaining hypothesis: **RBP
at the SSP epilogue ≠ RBP at the SSP prologue across `vfork(2)`**, so the
prologue's `[rsp+n]` store and the epilogue's `[rbp-8]` load land on
different qwords. Wave 12 verified slot 14 (user RSP) bit-stable but did
NOT audit slot 11 (user RBP). That's the next bounded probe.

## 2. D22 evidence recap

D22 armed a phys-walk channel at `pre_block.clone` (complementing D21's
linear-VA arm, mirroring D16/PR #248 `[FAULT/PHYS/PFH]` lens). 3 KVM trials:
`phys_at_arm == phys_at_write` exact; `phys_at_read` walks deterministically
to the same physical frame. The earlier "phys != phys" was an artifact of
read_va ≠ write_va, not aliasing.

Per SysV AMD64 ABI 1.0 §3.4.5.2, an SSP frame's prologue stores via
`[rsp+k]` and its epilogue loads via `[rbp-8]`. Those resolve to the same
qword only when RBP at epilogue equals RBP at prologue. If RBP drifts
across the wake, the canary "fails" with zero corruption.

## 3. RBP-identity audit in AstryxOS

Probe structurally identical to Wave 12, on slot 11 (`rbp`) instead of
slot 14 (`user_rsp`). Per `kernel/src/syscall/mod.rs:422` frame layout:
`[rdi, rsi, rdx, r8, r9, r10, r15, r14, r13, r12, rbx, rbp, r11, rcx, user_rsp]`.

| Step | File:line | Audit question |
|---|---|---|
| Push RBP at entry | `syscall/mod.rs:861` | pushed == user RBP at SYSCALL? |
| Context switch | `proc/thread.rs:55-110,118` | push/pop symmetric (Wave 12 ✓); slot 11 undisturbed? |
| Wake | `syscall/mod.rs:1626-1647` (`wake_vfork_parent`) | does wake write parent slot 11? |
| Signal-intercept | `signal.rs:944` | touches slot 15 only — confirm slot 11 never re-stamped |
| Pop at exit | `syscall/mod.rs:957` | popped == pushed? |

Two failure modes worth naming:

- **R-A — slot-11 stomp across `schedule()`.** Some path between
  `pre_block.clone` and `post_wake.clone` writes slot 11. Probe:
  snapshot `[kstack_top - 8 - 11*8]` before/after `schedule()`.
- **R-B — FPO calling-convention skew.** libxul's vfork-calling function
  compiled `-fomit-frame-pointer`, or AstryxOS's syscall wrapper leaves a
  value in RBP at SYSRET that Linux would zero / set to syscall return.
  Userspace ABI shape; kernel-side fix is preservation, not patching.

## 4. Linux ground-truth — not first, not parallel

**Only on R-A falsification.** PR #394 covers brk/vfork; per
`man7.org/linux/man-pages/man2/syscall.2.html` Linux preserves
`rbx,rbp,r12-r15` across `syscall(2)`. If R-A fires, divergence is
mechanical and re-walk adds nothing. If R-A is clean and only R-B remains,
a Linux gdb walk (pre-block vs post-wake RBP) becomes useful to confirm
userspace frame identity holds. Until R-A is falsified, re-walk is
premature.

## 5. Anti-patterns explicitly fenced

- **Do NOT re-open phys-aliasing.** D22 closed it 3/3.
- **Do NOT widen the vfork substitution gate.** PR #406 confirmed
  `new_stack != 0` and `alloc_vfork_child_stack` returned `Some`; R-A is
  upstream of the substitution decision.
- **Do NOT patch musl or libxul.** No-upstream-binary-edits invariant.
- **Do NOT 5-lens fan-out yet.** Hypothesis is narrow (one register, two
  modes). Per `[[feedback_saga_exhaustion_pattern_2026_05_22]]` this is the
  bounded disassembly-first probe the discipline calls for.
- **Do NOT widen a substitution gate "as a hedge."** Per
  `[[project_w215_saga_antipattern_2026_05_16]]` (right theory, wrong
  write site) — act only on a named writer.

## 6. Recommended next dispatch

**Agent**: `aether-kernel-engineer`. Native-kernel callee-saved
preservation across vfork wake is a kernel primitive; relevant code is
`kernel/src/syscall/mod.rs:822-960` and `kernel/src/proc/thread.rs:55-118`.

**Scope**: add a slot-11 user-RBP snapshot to the existing
`[VFORK/CANARY]` `pre_block.clone` / `post_wake.clone` lines using the
same `kstack_top - 8 - 11*8` access pattern Wave 12 used for slot 14, run
a fresh KVM trial, report whether slot 11 is bit-stable across
`schedule()`.

**Exit criteria**: doc states "N≥3 KVM trials, parent user-RBP at
`pre_block.clone` = `0x…`, at `post_wake.clone` = `0x…`; equal [yes/no]."
If unequal: name the writer via `[FAULT/PHYS/PFH]` armed on slot 11. If
equal: R-A closes; next dispatch is the Linux RBP walk per §4.

**Soft cap**: 60 min (burst to 90 if writer-naming probe needed).

**Parallelism**: can run alongside a `principal-systems-engineer` sample-
RIP correlation for `<ld-musl base>+0x15630`, `+0x1efb7`, `+0x1c7f9`. Both
read-only against the canary slot; no file conflict.

## References

- SysV AMD64 ABI 1.0 §3.2.1 (callee-saved), §3.2.2 (frame & alignment),
  §3.4.5.2 (SSP canary)
- POSIX.1-2017 `vfork(2)`, `clone(2)`
- Intel SDM Vol. 2B `SYSCALL`/`SYSRETQ`; Vol. 3B §17.2.4 (DR0–DR3)
- `man7.org/linux/man-pages/man2/syscall.2.html` — preserved registers
- musl.libc.org `__stack_chk_fail` (`hlt; ret`)
- PRs #404, #405, #406, #407, #408, #394, #248, #368
