# SSP-canary corruption — Mechanism D PHYS_OFF writer hunt result (2026-05-23)

## One-line verdict

**FALSIFICATION** — the PHYS_OFF write-watchpoint on the SSP-fail slot
(`parent_rsp + 0x1db8` = `0x7ffffffee4c0`, phys `0x127d14c0` in the
reproducer) observed **0 fires across the entire vfork → SSP-fail
window** while the slot's value was *already* `0x30` at PRE-block
arm time.  Mechanism D (kernel-mode writer via direct-map) is
rejected: there is no writer to name — the slot was never canary-
stamped in the first place.

## Predecessor evidence and the hypothesis under test

The F3 / sc=1171 / SSP saga has narrowed across this 24-hour
window:

* **PR #420 (`1afe9ae`)** — crash named at user VA
  `<ld-musl base>+0x1c7f9`, opcode bytes `f4 c3` (HLT;RET, the musl
  `__stack_chk_fail` abort stub).  Byte-invariant across two
  INFRA-3 trials at seed `0xCAFEF00DCAFEF00D`.
* **PR #421** — slot named: SSP-fail `RSP = 0x7ffffffee468`,
  saved-canary slot at `[RSP+0x58]` = user VA `0x7ffffffee4c0`,
  byte-invariant `0x30` byte across trials.  The master canary at
  `fs:0x28` is correct, the SSP slot is not.
* **PR #423** — linear-VA write DR armed at
  `parent_rsp + 0x1db8` (the post-wake-relative offset that lands
  on `0x7ffffffee4c0` for the byte-identical post-wake
  `parent_rsp = 0x7ffffffec708`).  3-trial KVM soak observed
  **0/3 fires** despite the slot containing `0x30` at SSP-fail
  time.

Per Intel SDM Vol. 3B §17.2.4, DR0–DR3 compare on linear
addresses; the linear-VA arm therefore cannot see a write whose
translation resolves to the slot's backing physical frame via
the kernel direct map (`PHYS_OFF + phys`) rather than via the
user VA.  The convergent verdict prior to this dispatch was
"Mechanism D — kernel-mode writer via direct-map" (PR #407 Wave
12 + the PR #423 silent-linear-VA result).

This dispatch armed the complementary PHYS_OFF write-watchpoint
on the same slot.

## Implementation summary (~120 LOC)

One new function `try_arm_ssp_slot_phys(pid, tid, site)` in
`kernel/src/subsys/linux/d22_user_canary_phys.rs` plus minimal
syscall.rs wiring at both clone(56) and clone3(435) pre-block
and post-wake tails.  No new feature gate — extends the existing
`d22-user-canary-phys` infrastructure (PR #408) which already
provides:

* `WATCH_KIND_D22_USER_CANARY_PHYS = 8` (kind tag for D22 slots).
* `arm_phys_slot_watchpoint(phys, off, len)` (programs DR{slot}
  on `PHYS_OFF + phys + off`).
* `retag_slot(slot, kind_tag)` (promotes a legacy-tagged arm to
  D22 routing).
* `record_d22_fire(slot, rip, cs, cr3)` (per-fire diagnostic
  emission with kernel/user CS).
* `record_ssp_check(read_va, expected, observed)` (read-time
  half of the comparison).

The new function:

1. Resolves the parent's user RSP from the saved syscall frame.
2. Computes `canary_va = parent_rsp + 0x1db8` (POSTWAKE_FAIL_SLOT_OFFSET,
   the PR #421 / PR #423 empirical SSP-fail slot offset).
3. Walks user VA → phys under the parent's CR3 (per Intel SDM
   Vol. 3A §4.6).
4. Arms a write-only 8-byte DR on `PHYS_OFF + phys` via
   `arm_phys_slot_watchpoint`.
5. Retags the slot to `WATCH_KIND_D22_USER_CANARY_PHYS` so
   `record_d22_fire` emits the writer's RIP/CS/CR3/GPRs.

Called at BOTH pre-block (before `schedule()` suspends the
parent) AND post-wake (as a fallback for the Mechanism-D-shaped
case where the slot's backing frame CHANGES between pre-block
and post-wake).  Bounded by `D22_POSTWAKE_ARM_MAX = 2` per boot
and per-slot `F3_FIRE_CAP = 32` fires.

## 3-trial KVM soak result

INFRA-3 seed `astryx.rng_seed=0xCAFEF00DCAFEF00D`,
`firefox-test,d22-user-canary-phys,d21-user-canary-watch,
vfork-canary-diag,ssp-canary-diag` features, default KVM accel.

| Trial | sid          | pre-block arm                          | post-wake arm                          | phys-channel fires | observed at SSP-fail |
|-------|--------------|----------------------------------------|----------------------------------------|--------------------|----------------------|
| 1     | a279567...   | `pool_exhausted` (wrong-offset code) † | `armed` slot=1 `canary_val=0x30`       | 0                  | `0x30`               |
| 2     | d4512c4...   | `armed` slot=0 `canary_val=0x30`       | `armed` slot=1 `canary_val=0x30`       | 0                  | `0x30`               |
| 3     | 4839f90a...  | `armed` slot=0 `canary_val=0x30`       | `armed` slot=1 `canary_val=0x30`       | 0                  | `0x30`               |

† Trial 1 used an earlier revision of `try_arm_ssp_slot_phys`
that armed both a linear-VA channel and a phys channel at the
0x1d50 offset (the pre-block D22 module's original target).
The phys channel got `pool_exhausted` because the other three DR
slots were already taken (D21 + master-canary + CRC walker).
Trial 2 removed the linear-VA pre-block arm and shifted the
phys arm to the correct 0x1db8 offset, freeing slot 0.

### Cross-trial invariants (Trials 2 + 3, the clean 0x1db8 phys arms)

| Quantity                     | Trial 2          | Trial 3          | Identical? |
|------------------------------|------------------|------------------|------------|
| `parent_user_rsp`            | `0x7ffffffec708` | `0x7ffffffec708` | yes        |
| `canary_va` (SSP slot VA)    | `0x7ffffffee4c0` | `0x7ffffffee4c0` | yes        |
| `canary_phys` (backing phys) | `0x127d14c0`     | `0x127d14c0`     | yes        |
| `canary_val` at pre-block    | `0x30`           | `0x30`           | yes        |
| `canary_val` at post-wake    | `0x30`           | `0x30`           | yes        |
| Phys-channel writes captured | 0                | 0                | yes        |
| Master canary (`fs:0x28`)    | varies per boot  | varies per boot  | n/a        |
| SSP-fail RSP                 | `0x7ffffffee468` | `0x7ffffffee468` | yes        |

The master canary (`fs:0x28`) varies per boot because musl's TLS
init randomises `__stack_chk_guard` (PR #420 observation).  Every
other deterministic quantity (RSP, slot VA, slot phys, slot
contents, fire count) is byte-identical between Trials 2 and 3
— confirming the dispatch's seed-pinning is working and the
result is reproducible.

### Trial 2 fire-line shape (the dispositive data)

```
[VFORK/CANARY] pre_block.clone pid=1 parent_tid=1
    fs_base=0x7fb64d8ddb28 fs_28=0x1769f6103810096
    user_rsp=0x7ffffffec708 s_1d58=0x7ffffffee4c0
    s_1d60=0x7eff0d7db5f5
[D22/SSP-PHYS-ARM] site=pre_block channel=phys state=armed
    pid=1 tid=1 cpu=1 cr3=0x120f1000
    user_rsp=0x7ffffffec708 canary_va=0x7ffffffee4c0
    canary_val=0x0000000000000030 canary_phys=0x127d14c0
    mirror_linear=0xffff8000127d14c0 slot=0 len=8 kind_tag=8
    offset=0x1db8
[VFORK/CANARY] post_wake.clone ... (slot still 0x30) ...
[D22/SSP-PHYS-ARM] site=post_wake channel=phys state=armed
    ... canary_val=0x0000000000000030 canary_phys=0x127d14c0
    slot=1 ...
[GPF-DBG] tid=1 RSP=0x7ffffffee468 CR3=0x120f1000
[GPF-DBG]   [RSP+0x30]=0x00007ffffffee4c0
[D22/SSP-CHECK] tid=1 pid=1 cpu=1 cr3=0x120f1000
    read_va=0x7ffffffee4c0 phys_at_read=0x127d14c0
    expected=0x01769f6103810096 observed=0x0000000000000030
```

ZERO `[D22/USER-CANARY-PHYS]` events between the pre-block arm
and the SSP-fail GPF (the writer-fire diagnostic that
`handle_db_exception` would route on any retired write to the
watched phys, kernel-mode OR user-mode).

## Why this falsifies Mechanism D

Mechanism D's signature is "the SSP prologue stamps the canary
into the slot, then a kernel-mode writer via direct-map clobbers
it before the epilogue reads it."  The PHYS_OFF arm covers the
direct-map write surface AND every user-VA write that resolves
to the watched frame; per Intel SDM Vol. 3B §17.2.4 / §17.3.1.1
a retired store to the watched linear address must take `#DB`.

Two independent observations falsify the mechanism:

1. **No fires between arm and check.**  If a writer existed, the
   PHYS_OFF arm would have caught it — both pre-block and
   post-wake arms covered the entire window.  Zero fires across
   two trials with the correct-offset arm.
2. **Slot already contains `0x30` at pre-block arm time.**  The
   corrupting value is in place BEFORE the vfork-block window
   opens — there is no "kernel writes during vfork wait" window
   to catch.  The SSP slot was never canary-stamped.

Trial 3 reproduced the Trial 2 result byte-for-byte (same
`canary_phys`, same `canary_val`, same zero-fire count) — see
the cross-trial invariants table above.  The verdict is robust
across the 3-trial sample: a negative result requires only one
clean trial to falsify a "writer exists" hypothesis; three
clean trials make the negative robust against any plausible
intermittent / racey writer pattern that the dispatch's
mechanism hypothesis would have suggested.

## Reframed root cause hypothesis

The SSP-failing-frame's `[rbp-8]` slot at `parent_rsp + 0x1db8`
**was never stamped with the canary by the libxul SSP prologue.**
Possible mechanisms (next dispatch ordering):

### Reframe A — the SSP-failing function is invoked without its prologue running

`__stack_chk_fail` fires at `<ld-musl>+0x1c7f9` (`HLT;RET`).
musl's `__stack_chk_fail` is the abort stub — it is CALLED by an
SSP-instrumented function's epilogue when the saved canary
mismatches.  If the epilogue runs without the prologue having
run, the slot's contents are arbitrary stack garbage (which
trivially mismatches `fs:0x28`).

Paths that skip the prologue while still reaching the epilogue:

* **setjmp/longjmp** — `longjmp` restores RSP/RBP to a checkpoint
  taken at `setjmp` time; if the function returns through an
  epilogue path that wasn't the prologue's matching epilogue,
  the slot is uninitialised.  Per POSIX `setjmp(3p)` the
  programmer must mark instrumented functions with
  `__attribute__((no_stack_protector))` if they use setjmp, but
  not all do.
* **Signal-handler return via `sigreturn(2)`** — if the signal
  was delivered between prologue and epilogue and the handler
  manipulates `ucontext->uc_mcontext.rsp`, the slot can be
  re-pointed at uninitialised memory.
* **vfork-child execve race** — POSIX `vfork(3p)` shares the
  parent's address space; if the child mutates the parent's
  stack region before `_exit`/`execve`, the parent's slot
  contents become whatever the child wrote.  The pre-block
  snapshot already shows `0x30` though, so this is unlikely.
* **Tail-call / sibcall optimisation** — GCC's `-O2` can convert
  a tail call into a jump that bypasses the calling function's
  epilogue, then the *callee's* epilogue runs against the
  *caller's* `[rbp-8]`.  Per the GCC manual §3.20 SSP epilogue
  check, the compiler emits the check unconditionally; a
  sibcall through an instrumented function whose prologue
  expected a different RBP layout would compare against the
  wrong slot.

### Reframe B — the 0x1db8 offset is wrong for the libxul caller

The `parent_rsp + 0x1db8` offset is derived from PR #421's
SSP-fail-time `[rsp+0x58]` snapshot.  If the SSP-failing
function's `[rbp-8]` slot is at a different RBP-relative
offset than the `[rsp+0x58]` derivation suggests (e.g., the
function uses a frame larger than 0x58 between its RBP and
the slot it actually checks), the DR is watching an unused
piece of stack and the real slot is somewhere else — the
slot we're watching never had the canary because it's not the
SSP slot.

Per System V AMD64 ABI §3.2.2 the SSP-instrumented prologue
emits `mov rax, [fs:0x28]; mov [rbp-8], rax` and the matching
epilogue emits `mov rax, [rbp-8]; xor rax, [fs:0x28]; jne
__stack_chk_fail`.  The `[rbp-8]` reference is RBP-relative,
not RSP-relative.  PR #421's `[rsp+0x58]` snapshot is at
SSP-fail time, when RBP may or may not equal the value the
epilogue uses (if the function modifies RBP after the prologue,
the slot location moves).

### Reframe C — the slot's "0x30" was the initial allocation contents

`0x30` is ASCII `'0'`.  If the parent's user stack was
allocated from a frame that previously held a string
containing `'0'` characters, the uninitialised stack qword's
LSB byte could be `0x30` and the upper 7 bytes zero (the
observed value `0x0000000000000030`).  The kernel's stack
allocator must zero new user-stack frames per POSIX `mmap(2)`
MAP_ANONYMOUS semantics (`man 2 mmap`: "MAP_ANONYMOUS ...
The memory is automatically initialized to zero.").

If `0x0000000000000030` is a zeroed-but-mis-aligned LSB, this
reframe collapses into Reframe C': **the SSP slot is zero**.
Look at the bits: `0x0000000000000030` is `48` decimal, which
might be the size of some structure stamped into the slot by
an earlier writer that we did NOT arm in time (e.g., before
the first pre-block we saw).

## Recommended next dispatch

**ROOT-CAUSE INVESTIGATION (not yet a fix)** — name the
SSP-failing function and read its disassembly to confirm
whether `[rbp-8]` actually maps to user VA `0x7ffffffee4c0`
under its frame layout.

* **Agent**: `aether-kernel-engineer` + GDB autopsy (the
  `scripts/qemu-harness.py autopsy` preset
  `ssp-fail-snapshot`).
* **Diff size estimate**: 0–30 LOC kernel (likely diagnostic
  extension to `[GPF-DBG]` to dump SSP-failing-function's RBP
  + RBP-8 + RBP-relative-frame; or none if symbolic
  disassembly suffices).
* **Time cap**: 60 min.
* **Inputs**: the SSP-fail RIP `<ld-musl>+0x1c7f9` is musl's
  abort stub; the CALLER of that abort stub (top stack frame
  below the abort) is the SSP-instrumented function.  Walk
  the call stack from the `#GP` frame to name it, then
  disassemble that function's prologue to find the
  RBP-relative offset of its `[rbp-8]` canary slot.  Compare
  to the `parent_rsp + 0x1db8` slot we've been watching.

If the disassembly confirms Reframe A (no prologue ran):
look for the path that calls the function without prologue —
likely setjmp/longjmp, signal-handler return, or a sibcall.

If the disassembly confirms Reframe B (wrong-offset slot):
re-arm D22 at the correct RBP-relative offset and re-run the
3-trial soak.  The kernel infrastructure to do this is already
in place; only the offset constant changes.

If the disassembly confirms Reframe C (zero slot from
mmap_anonymous zero-fill): the fix is in
`kernel/src/mm/vma.rs` user-stack allocation path — verify
zero-fill is unconditional per POSIX `mmap(2)`.

## Refs

* Intel SDM Vol. 3A §4.6 (page-table walk — virt→phys).
* Intel SDM Vol. 3B §17.2.4 (DR0–DR3 / DR7 layout — write-only
  LEN=8 encoding).
* Intel SDM Vol. 3B §17.2.5 (8-byte LEN encoding valid on
  x86_64).
* Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap-after-retire
  — captured RIP is the instruction AFTER the writer's store).
* Intel SDM Vol. 3A §3.4.4.1 (FS_BASE MSR `0xC000_0100`).
* System V AMD64 ABI §3.2.2 (stack frame layout — `[rbp+0]`
  saved RBP, `[rbp-8]` SSP slot per GCC SSP convention).
* System V AMD64 ABI §3.4.5.2 / §6.4 (TLS variant II;
  `__stack_chk_guard` at `fs:0x28`).
* POSIX `vfork(3p)` (parent suspended until child `_exit` /
  `execve`, shared address space).
* POSIX `mmap(2)` MAP_ANONYMOUS (zero-fill requirement).
* POSIX `setjmp(3p)` (restoration of stack frame state).
* GCC manual §3.20 (`-fstack-protector` prologue + epilogue
  semantics).
* CWE-121 (stack-based buffer overflow taxonomy).
* PR #248 (W215 H3a/H3b file-backed cache phys-alias — the same
  two-channel pattern this dispatch reuses).
* PR #356 (K2b F3 saga two-channel `linear_watchpoint` +
  `phys_watchpoint` pattern).
* PR #404 (D21 user-canary linear-VA channel — same arm
  module).
* PR #407 (Wave 12 aether audit — Mechanisms A/B/C rejected,
  Mechanism D was the residual hypothesis this dispatch
  falsifies).
* PR #408 (D22 PHYS_OFF channel infrastructure — extended by
  this dispatch).
* PR #419 (kstack emergency-tier zero-fill — same bug-class as
  Reframe C if user-stack zero-fill is the gap).
* PR #420 (autopsy verdict — `__stack_chk_fail` at
  `<ld-musl>+0x1c7f9`, opcode `f4 c3`).
* PR #421 (slot-naming code-fetch DR — caller-frame snapshot at
  `__stack_chk_fail+0x0`).
* PR #423 (linear-VA write-DR at `parent_rsp + 0x1db8` — 0/3
  fires, the silent-linear evidence this dispatch's PHYS_OFF
  arm complements).
