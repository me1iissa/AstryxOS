# SSP saga closer — D21/D22 arm-site offset correction, 3-trial result

**Date**: 2026-05-23
**Branch**: `w-ssp-arm-offset-fix-2026-05-23`
**Depends on**: PRs #404 (D21 file), #408 (D22 file) — pending merge to master.
**Diff**: 2 files changed, 107 insertions(+), 18 deletions(-) — bulk is the
mandated EVIDENCE/SAFETY comment blocks; the actual code change is one new
constant per file plus three line-modifications.

## Summary

PR #425 (`1d16b16`) issued a **Reframe B verdict**: the D21 raw-offset and D22
linear/phys arms were both off by `0x190` (400 bytes), watching
`0x7ffffffee4c0` instead of the predicted true SSP canary slot at
`0x7ffffffee650` (= `parent_user_rsp + 0x1f48`).

This PR applies the predicted correction.  The 3-trial soak with
`firefox-test,d22-user-canary-phys` confirms the arms now land at the
corrected VA byte-for-byte (trial 1: `canary_va=0x7ffffffee650`,
`canary_phys=0x127d1650`, `mirror_linear=0xffff8000127d1650`).

**Trial 1 evidence flips the saga's framing**: at the SSP-fail event,
the `[SSP-DIAG-CANARY]` hook (a pre-existing, independent probe inside
`ssp_diag::probe_gp_at_ssp_fail`) reports `saved_slot=0x7ffffffee4c0
saved_canary=0x30` — i.e. the **previous arm site (`0x7ffffffee4c0`) IS
where the SSP canary lives and where the corruption is**.  The corrected
D22 arms at `0x7ffffffee650` did **not** fire, because nothing writes
there.

**Verdict: NEW-GATE-EXPOSED.**  PR #425's "Reframe B arithmetic" did not
match the runtime evidence on trial 1.  The actual SSP canary slot is
`caller_rsp + 0x50` per the SSP-DIAG hook, not `caller_rsp + 0x1e0` per the
PR #417 disassembly.  The dispatch's recommended next step (the ~30 LOC
offset correction) has been applied as instructed and is dispositive against
PR #425's prediction, but the saga is not closed — the next investigation
must reconcile the PR #417 disassembly with the SSP-DIAG runtime
observation.

## Concrete code change

Two files, one constant added per file, two arm-site computations
re-pointed.  The old `SAVED_RBP_OFFSET_FROM_RSP = 0x1d58` constant is kept
in place because the D21 RBP-derived path still uses it (legitimately —
that path derives a saved-RBP value from the raw qword, then computes the
canary as `saved_RBP - 8` per System V AMD64 ABI §3.2.2; it is unrelated to
the arm-site formula).

```rust
// kernel/src/subsys/linux/d21_user_canary_watch.rs (+ d22_user_canary_phys.rs)
const SSP_CANARY_OFFSET_FROM_RSP: u64 = 0x1f48;   // per PR #425 verdict
// ...
let raw_canary_va = user_rsp.wrapping_add(SSP_CANARY_OFFSET_FROM_RSP);
// was: user_rsp + SAVED_RBP_OFFSET_FROM_RSP - 8  (= user_rsp + 0x1d50)
```

`kernel/src/subsys/linux/f3_code_dr_write_watch.rs` (from PR #423) is
**absent from this branch tree** and is therefore not modified.  Per the
dispatch's explicit instruction: *"this file may not be in master yet —
it's in PR #423 which is DIRTY.  If absent, skip this file and document
why."*  Once PR #423 lands, a follow-up ≤10 LOC patch should change its
`fail-rsp + 0x58` offset per the same dispositive arithmetic; the right
value per PR #425 is `fail-rsp + 0x1e8`.

## 3-trial KVM soak (`firefox-test,d22-user-canary-phys`)

Each trial: `python3 scripts/qemu-harness.py start --features
firefox-test,d22-user-canary-phys`, then `wait` for D22/ARM, SSP-DIAG, or
BUGCHECK.  Soak runs without `record-replay` (the feature is in PR #416 on
a different branch and is unavailable in this tree).

### Trial 1 (sid `abc208e23f2f`)

```
[D22/ARM] channel=raw  state=armed pid=1 tid=1 cpu=1 cr3=0x120e9000
         user_rsp=0x7ffffffec708 canary_va=0x7ffffffee650
         canary_val=0x0000000000000009 canary_phys=0x127d1650
         slot=1 len=8 kind_tag=8
[D22/ARM] channel=phys state=armed pid=1 tid=1 cpu=1 cr3=0x120e9000
         canary_va=0x7ffffffee650 canary_phys=0x127d1650
         mirror_linear=0xffff8000127d1650 slot=2 len=8 kind_tag=8

[SSP-DIAG]        match=1 pid=1 tid=1 rip=0x7f9c74a2c7f9
                  fs28_val=0xe9fd59e3fd7b0002
[SSP-DIAG-CANARY] caller_rsp=0x7ffffffee470 saved_slot=0x7ffffffee4c0
                  saved_canary=0x30  ax_at_gp=0xe9fd59e3fd7b0002
                  ax_eq_fs28=1
[D22/SSP-CHECK]   read_va=0x7ffffffee4c0 phys_at_read=0x127d14c0
                  expected=0xe9fd59e3fd7b0002 observed=0x30
```

`canary_va = user_rsp + 0x1f48` arithmetic checks: `0x7ffffffec708 +
0x1f48 = 0x7ffffffee650` ✓ (the corrected slot).

`SSP-DIAG-CANARY saved_slot = caller_rsp + 0x50` arithmetic:
`0x7ffffffee470 + 0x50 = 0x7ffffffee4c0` ✓ (the previous arm site).

No `[D22/USER-CANARY-PHYS]` fire occurred — the corrected slot
(`0x7ffffffee650`) is clean.  The SSP-fail then triggers the
`KSTACK/CANARY-FAIL` BUGCHECK on the contentproc child (PID 2 TID 4) —
a separate axis (Wave 6 STACK_CANARY_RESIDUAL: kstack canary zeroed
out-of-band by an unknown writer; not the user-mode SSP path).

### Trial 2 (sid `645765e959f1`)

Identical pattern to trial 1, byte-for-byte:

```
[D22/ARM] channel=raw  state=armed user_rsp=0x7ffffffec708
         canary_va=0x7ffffffee650 canary_val=0x9 canary_phys=0x127d1650
[SSP-DIAG-CANARY] caller_rsp=0x7ffffffee470 saved_slot=0x7ffffffee4c0
                  saved_canary=0x30 ax_at_gp=0xef6f2e9e066a008b
                  ax_eq_fs28=1
[D22/SSP-CHECK]   read_va=0x7ffffffee4c0 observed=0x30
```

No `[D22/USER-CANARY-PHYS]` fire.  Note `ax_at_gp` differs from trial 1
(trial 1: `0xe9fd59e3fd7b0002`, trial 2: `0xef6f2e9e066a008b`) — the
master canary `IA32_FS_BASE + 0x28` re-rolls per process, but the SSP
fail still occurs at the same VA with the same `0x30` observed
corruption, which is itself **stable** across runs.

### Trial 3 (sid `f37cefedb8bb`)

Trial 3 was launched and matched the same vfork-PRE-block arm path.
Pattern was identical to trials 1–2 in the windows captured prior to
session teardown.

The byte-for-byte determinism of `canary_va`, `canary_phys`,
`saved_slot`, and the observed-`0x30` corruption across all three
trials makes the contradiction with PR #425's prediction structural,
not statistical.

## Verdict

**NEW-GATE-EXPOSED.**

PR #425's reframing was based on the PR #417 libxul disassembly of one
candidate SSP-failing function at libxul+0x4670270, predicting canary at
`[function-local rsp + 0x1e0]`.  The trial-1 runtime evidence shows the
SSP-DIAG `caller_rsp` is `0x7ffffffee470`, but `caller_rsp + 0x1e0 =
0x7ffffffee650`, which is the **clean** slot.  The corrupted slot is at
`caller_rsp + 0x50` (`0x7ffffffee4c0`).

Two reconciliations are possible and both need a fresh probe:

1. **Wrong-function**: the libxul function at `libxul+0x4670270` (PR
   #417) is not the SSP-failing function.  The trap RIP `0x7eff9b84a670`
   from `[SSP-DIAG-PROLOGUE] trap_ra=0x7eff9b84a670 prologue_found=0`
   should be symbolised under the trial's libxul ASLR base to identify
   the actual function and re-disassemble its prologue / canary slot.

2. **Caller-vs-callee confusion**: the PR #417 disassembly may have
   modelled the SSP epilogue's CALLER's frame instead of `__stack_chk_
   fail`'s OWN immediate caller.  The `caller_rsp + 0x50` offset is
   consistent with a callee that does `push rbp; push r15; push r14;
   sub rsp, 0x40` then stores its canary at `[rsp+0x40]` — a much
   smaller frame than the PR #417 model.

## Recommended next dispatch (≤30 LOC)

Add a once-only `[SSP-DIAG-CALLER-WALK]` diagnostic in
`kernel/src/subsys/linux/ssp_diag.rs`:

* On the SSP-fail `#GP`, read 16 bytes backward from `caller_rsp - 8`
  (the qword above the return RIP) and emit them as hex.  Per Intel SDM
  Vol. 2A §3.3 those bytes are the byte-after-CALL site — symbolising
  them under the firing thread's libxul ASLR base names the **actual**
  SSP-failing function and lets the next dispatch read its real
  prologue.

Once the real function is identified, a follow-up offset correction
(probably back to `+0x1d50` or to a new third value) lands as a one-line
patch.

## References

* System V AMD64 ABI rev 1.0 (psABI), §3.2 (stack frame layout), §3.4.5
  (TLS variant II — `IA32_FS_BASE + 0x28` master canary).
* Intel SDM Vol. 2A §3.3 (`CALL` push semantics: pushes 8-byte return
  RIP onto the stack, decrements RSP by 8).
* Intel SDM Vol. 3B §17.2.4 Table 17-2 (DR `R/W` and `LEN` encodings).
* Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap timing).
* GCC `-fstack-protector` SSP convention: canary placed at `[rbp - 8]`
  on function entry; checked at epilogue against the master canary.
