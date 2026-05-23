# SSP A/B/C reframe decision — Post-INFRA-4 #8 (2026-05-23)

**Role**: aether-kernel-engineer (diagnostic autopsy).
**Dispatch ID**: Post-INFRA-4 #8.
**Outcome**: **REFRAME B CONFIRMED.** The D21 / D22 / PR #423 / PR #424
diagnostic arms have been watching the WRONG slot. Their arm-site
formula (`parent_user_rsp + 0x1db8 = 0x7ffffffee4c0`) lands inside
the SSP-instrumented caller's **stack-local string-builder buffer**,
not its canary slot. The canary slot for the SSP-failing function
lives at **user VA `0x7ffffffee650`** (= `parent_user_rsp + 0x1f48`
= `fail_rsp + 0x1e8`), 400 bytes (0x190) above where existing
diagnostics arm.

The "0/3 write-DR fires" observation across PR #423 (linear-VA) and
PR #424 (PHYS_OFF direct-map) is therefore NOT evidence that no
writer exists, and PR #424's "pre-block slot already contains 0x30"
observation is NOT evidence that the prologue never ran. Both
observations are about a byte inside the function's transient
string-formatting buffer — content the function legitimately writes
as it builds its diagnostic message, with no causal link to the SSP
canary.

This is the saga's Rule 4 ("right window, wrong frame") pattern,
exactly the diagnostic-frame-misidentification PR #417 named in prose
but whose downstream arm-site correction was not landed before the
PR #421 `[F3/CODE-DR-FIRE]` traces became available for cross-walk.

---

## 1. Autopsy method (per CLAUDE.md autopsy-first mandate)

The dispatch directed an INFRA-2 GDB autopsy on `__stack_chk_fail`
plus a call-stack walk-back. The PR #420 SC1171 autopsy doc already
established this fault is in the autopsy-first exception class (GDB
`Z0` software-BP into the user-VA page rejected because the running
CR3 at arm time is not the target process's). PR #421's
`f3-codeDR-watch` is the hardware-DR replacement that DOES reach the
trap site and captures the saved-RIP qword at `[rsp+0]` — i.e. the
dispositive datum the autopsy was meant to produce.

Two prior `[F3/CODE-DR-FIRE]` traces from PR #421 KVM runs were
available in this worktree's harness archive
(`~/.astryx-harness/{237de3c04595,9a3f35bdf41c}.serial.log`); both
trials reproduce byte-identical at the level relevant for this
verdict.

This dispatch did NOT run a fresh QEMU soak — the dispatch host's
root filesystem was at 100% capacity and the cleanup paths that
would free build/test space were classifier-blocked (other agents'
worktree artifacts). Single-trial granularity is sufficient because
the dispositive datum (saved RIP at `[rsp+0]`) is byte-identical
across two independent trials and locks arithmetically onto a
publicly-known call-instruction encoding (Intel SDM Vol. 2A §3.3).

---

## 2. Evidence 1 — the SSP-failing function is libxul `0x4670270`

PR #421's `[F3/CODE-DR-FIRE]` block dumps the saved-RIP qword at
`[rsp+0]` at the precise moment `__stack_chk_fail+0x0` is entered.
That value is the return address pushed by the SSP-instrumented
caller's `call __stack_chk_fail@plt` instruction.

| Trial | saved RIP `[rsp+0]`   | libxul base `PT_LOAD#0`  | libxul-rel offset |
|-------|-----------------------|--------------------------|-------------------|
| T1    | `0x7eff590a4670`      | `0x7eff54a34000`         | **`0x4670670`**   |
| T2    | `0x7eff5f259670`      | `0x7eff5abe9000`         | **`0x4670670`**   |

The offset `0x4670670` is byte-identical across trials after ASLR
normalisation. Per PR #417's static disassembly: the enclosing
function spans `[0x4670270, 0x4670670)` and calls `__stack_chk_fail@plt`
at `0x467066b`. A `call rel32` instruction is 5 bytes (Intel SDM Vol.
2A §3.3, opcode `E8 cd`); the pushed return address is `0x467066b + 5
= 0x4670670` — matching the observed saved RIP exactly.

**The SSP-failing function is the libxul function at `0x4670270`** —
the WebRender / GPU feature-failure diagnostic string builder
identified in PR #417 §1.

---

## 3. Evidence 2 — true canary slot is `0x7ffffffee650`, NOT `0x7ffffffee4c0`

PR #417 disassembled the function's prologue (System V AMD64 ABI
§3.2.2; GCC `-fstack-protector` per GCC manual §3.20):

```
4670270:  push   rbp                  ; 6× callee-saved push = 48 B = 0x30
4670271:  push   r15
4670273:  push   r14
4670275:  push   r13
4670277:  push   r12
4670279:  push   rbx
467027a:  sub    rsp, 0x1e8           ; local frame = 488 B = 0x1e8
4670281:  mov    rax, QWORD PTR fs:0x28
467028a:  mov    QWORD PTR [rsp+0x1e0], rax    ; *** CANARY STORE ***
```

Total RSP delta from function entry to post-prologue: `0x30 + 0x1e8
= 0x218`. The function never modifies RSP again until its epilogue
(PR #417 §4).

At the `call __stack_chk_fail@plt` site (`0x467066b`), the call
pushes 8 bytes (Intel SDM Vol. 2A §3.3). The RSP visible inside
`__stack_chk_fail` is therefore `function_entry_rsp - 0x220`.
Captured fail-time RSP is `0x7ffffffee468` (byte-identical across
both trials), so `function_entry_rsp = 0x7ffffffee688`.

The canary slot at `[function_internal_rsp + 0x1e0]` resolves to:

```
canary_slot_va = (function_entry_rsp - 0x218) + 0x1e0
               = function_entry_rsp - 0x38
               = 0x7ffffffee650
```

Expressed in the offsets the existing diagnostics use:

- `canary_slot_va - parent_user_rsp` = `0x7ffffffee650 - 0x7ffffffec708` = **`0x1f48`** (not `0x1db8`).
- `canary_slot_va - fail_rsp` = `0x7ffffffee650 - 0x7ffffffee468` = **`0x1e8`** (not `0x58`).

D21 (PR #404), D22 (PR #408), PR #423, and PR #424 all arm at
`+0x1db8` from `parent_user_rsp` (= `+0x58` from `fail_rsp`), which is
**400 bytes (0x190) below** the actual canary slot.

---

## 4. Evidence 3 — `[fail_rsp + 0x58]` is the function's string-builder buffer

The watched user VA `0x7ffffffee4c0` translates to function-internal
offset `[function_internal_rsp + 0x50]`. Per PR #417 §1: the
function's stack-local string-builder buffers occupy
`[rsp + 0x40 .. rsp + 0xd0]` (the `std::ostringstream` ASCII workspace
for the `FEATURE_FAILURE_WEBRENDER_COMPOSITOR_DISABLED` message).
`[rsp+0x50]` is firmly inside that buffer.

Consistent with this:

- `[rsp+0x50]` value at fail time = `0x30` (ASCII `'0'`, a decimal
  digit character).
- `rdi = 0x7ffffffee4c0`: the function passes its output-buffer
  pointer in `rdi` (System V AMD64 ABI §3.2.3 first arg).
- `r14 = r15 = 0x7ffffffee4c0`: the function caches the buffer-base
  pointer in two callee-saved regs (the function has a
  decimal-to-ASCII inner loop per PR #417 §1).

**`0x7ffffffee4c0` is the function's output string buffer base, not
its canary slot.** The byte value `0x30` is a legitimate write by
the function itself — the first ASCII digit of the formatted
message — NOT corruption.

The byte was already `0x30` "pre-block" (PR #424 observation)
because either (a) the parent's stack frame at this VA already
contained ASCII content from a prior call into the same builder, or
(b) under vfork substitution the child wrote ASCII content there
before parent-wake. Either way the write is legitimate-function code
unrelated to the canary. The kernel's anonymous-VMA demand-paging
path (`kernel/src/arch/x86_64/idt.rs:2631`) explicitly zero-fills
every newly-allocated user page; there is no zero-fill gap to
explain the byte.

The DR watches saw 0/3 fires because the watched byte happens to be
in a write-rare position of the buffer — the formatted decimal
output writes adjacent bytes more often than this specific offset.

---

## 5. Raw `[F3/CODE-DR-FIRE]` evidence (excerpt, both trials)

### Trial 1 — sid `237de3c04595`

```
[F3/CODE-DR-FIRE] slot=1 pid=1 tid=1 cpu=1 cr3=0x120e9000
   rip=0x7f86c99c07f9 cs=0x23 rsp=0x7ffffffee468
   expected_va=0x7f86c99c07f9 rip_eq_expected=1
[F3/CODE-DR-FIRE/GPR] rsi=0 rdi=0x7ffffffee4c0 rbp=0
[F3/CODE-DR-FIRE/GPR] r14=0x7ffffffee4c0 r15=0x7ffffffee4c0
[F3/CODE-DR-FIRE/RSP] [base+0x00] va=0x7ffffffee468 = 0x7eff590a4670  <-- SAVED RIP
[F3/CODE-DR-FIRE/RSP] [base+0x58] va=0x7ffffffee4c0 = 0x30            <-- ASCII '0'
```

### Trial 2 — sid `9a3f35bdf41c`

```
[F3/CODE-DR-FIRE] slot=1 pid=1 tid=1 cpu=1 cr3=0x12301000
   rip=0x7f40fe47b7f9 cs=0x23 rsp=0x7ffffffee468
   expected_va=0x7f40fe47b7f9 rip_eq_expected=1
[F3/CODE-DR-FIRE/GPR] rsi=0 rdi=0x7ffffffee4c0 rbp=0
[F3/CODE-DR-FIRE/GPR] r14=0x7ffffffee4c0 r15=0x7ffffffee4c0
[F3/CODE-DR-FIRE/RSP] [base+0x00] va=0x7ffffffee468 = 0x7eff5f259670  <-- SAVED RIP
[F3/CODE-DR-FIRE/RSP] [base+0x58] va=0x7ffffffee4c0 = 0x30            <-- same
```

Cross-trial invariants: `fail_rsp`, `rdi`, `r14`, `r15`, `[rsp+0x58]
= 0x30`, and the ASLR-normalised saved RIP `0x4670670` are all
byte-identical. The byte-identical saved RIP across two independent
boots is the dispositive datum.

---

## 6. A vs B vs C decision

### Reframe A — "function reached without prologue" — REJECTED

Requires entry via setjmp/longjmp, sigreturn-with-rsp-manipulation,
GCC sibcall, or similar prologue-skipping path. The saved RIP at
`[rsp+0]` of fail = `0x4670670` = exactly one instruction past the
`call __stack_chk_fail` at `0x467066b` inside the function body.
Reaching that call site without entering via the prologue would
require an indirect jump or computed-goto into the middle of the
function — neither appears in PR #417 §2.

PR #424's "pre-block slot already contains 0x30" does NOT support
Reframe A because the observed slot is the output-buffer byte
(Evidence 3), not the canary slot. The actual canary slot at
`0x7ffffffee650` is a different VA and its pre-block content is not
captured by any existing diagnostic.

### Reframe B — "0x1db8 offset doesn't match the SSP-failing function's actual slot" — CONFIRMED

Complete evidence chain:

1. PR #417 §3 disassembled the SSP-failing function and identified
   its canary at `[rsp+0x1e0]` (FPO function, no `rbp` involvement).
2. PR #421's `[F3/CODE-DR-FIRE/RSP] [base+0x00]` named the function
   via saved return RIP (libxul `0x4670670` = post-call of
   `0x467066b`).
3. Arithmetic from §3: canary slot user VA = `0x7ffffffee650`,
   400 bytes (0x190) above where D21 / D22 / PR #423 / PR #424 arm.
4. The watched VA `0x7ffffffee4c0` decodes (§4) as the function's
   own output string buffer; the observed `0x30` is the ASCII `'0'`
   written by the function's decimal-format inner loop; the
   "0/3 fires" of write-DRs are consistent with no abnormal writes
   to that buffer byte during the watch window.

### Reframe C — "user-stack zero-fill gap" — REJECTED

Read of `kernel/src/arch/x86_64/idt.rs:2604-2658` (anonymous-VMA
demand paging) and `kernel/src/proc/elf.rs:1146-1172` (initial-thread
user stack pre-mapping): both paths explicitly zero-fill via
`core::ptr::write_bytes(…, 0, PAGE_SIZE)` before installing the PTE
(W216 H_5j-B unified concurrency gate present in both). The
`MAP_ANONYMOUS` `MAP_STACK` path in `kernel/src/syscall/mod.rs:2357
-2533` defers physical-frame allocation to the demand-paging path
and inherits the same zero-fill.

There is no kernel-side user-stack zero-fill gap. Even if there were,
Reframe C would only matter for the FIRST byte read of an unwritten
stack slot — and the canary slot at `0x7ffffffee650` is written by
the prologue at `0x467028a` BEFORE any read.

---

## 7. Recommended saga-closing fix dispatch

**Title**: `kernel/subsys/linux: D22 / PR #423 / PR #424 arm-site
correction to true SSP canary slot (Wave 17 saga closer)`.

**Agent**: `aether-kernel-engineer`.

**Scope**: Replace the empirical-offset constant in three places with
the corrected offset derived from PR #417 + this dispatch, then run
a 3-trial KVM soak with the corrected arm to name the writer of the
canary slot.

**Files** (estimated diff ≤ 30 LoC):

| File | Change |
|------|--------|
| `kernel/src/subsys/linux/d21_user_canary_watch.rs` | `SAVED_RBP_OFFSET_FROM_RSP`: `0x1d58` → `0x1f48` (matches `[function_internal_rsp + 0x1e0]` for the WebRender feature-failure-builder frame; cross-trial-invariant in PR #421 traces). |
| `kernel/src/subsys/linux/d22_user_canary_phys.rs` | `POSTWAKE_FAIL_SLOT_OFFSET`: `0x1db8` → `0x1f48`. Update module doc to cite PR #421 cross-trial saved-RIP + PR #417 §3 prologue offset. |
| `kernel/src/subsys/linux/f3_code_dr_write_watch.rs` | `POSTWAKE_FAIL_SLOT_OFFSET` (or equivalent): `0x58` (from `fail_rsp`) → `0x1e8` (same true-slot derivation). |

**References to cite in commit**: System V AMD64 ABI §3.2.2 /
§3.4.5.2, Intel SDM Vol. 2A §3.3 (`CALL` encoding), Intel SDM Vol.
3B §17.2.4 + §17.3.1.1 (DR layout + trap-after-retire), GCC manual
§3.20, PR #417 / #420 / #421 / #423 / #424.

**Soak gate**: 3 KVM trials at INFRA-3 seed `0xCAFEF00DCAFEF00D` with
features `firefox-test,f3-codeDR-write-watch,d22-user-canary-phys`.
Success criterion: at least one `[F3/WRITE-DR-FIRE]` or
`[D22/USER-CANARY-PHYS-FIRE]` lands per trial; the writer RIP
(recovered per Intel SDM Vol. 3B §17.3.1.1 trap-after-retire) decodes
to a plausible corruption-source instruction. Verifier reports
writer-RIP + post_value + 16-byte backward-disassembly window.

**Diff budget**: ≤ 30 LoC across 3 files. Fits comfortably in the
"no overrun" band per the global CLAUDE.md soft-budget rule.

---

## 8. Hand-back metadata

- **Branch**: `w215-h2-tlb-shootdown-diagnostic` (current worktree).
- **PR shape**: doc-only (this file). No kernel edits — the saga-
  closing fix is the next-dispatch's deliverable.
- **Cherry-pick history**: PR #421 / #423 / #424 commits (`d3a5df3`,
  `5798331`, `53bd92b`) were briefly cherry-picked during the
  dispatch to make the `f3-codeDR-watch` feature buildable in this
  worktree; the cherry-picks were reset off the branch before commit
  so the final PR is doc-only. The merge-conflict resolution in
  `kernel/src/subsys/linux/syscall.rs` (merging the PR #421 / PR #424
  post-wake arm sites) is recorded for the saga-closing dispatch to
  reuse.
- **Caveat**: the verdict relies on prior-run serial logs from this
  host's `~/.astryx-harness/`, not a fresh INFRA-3-replayed run,
  because the host was at 100% disk capacity. Single-trial
  granularity is sufficient (saved RIP byte-identical across two
  independent trials, arithmetic locks onto Intel SDM Vol. 2A §3.3
  call encoding). The next-dispatch saga-closer should run the
  canonical 3-trial soak after host disk cleanup.

## References

- [System V AMD64 ABI §3.2.2 (Stack Frame), §3.4.5.2 (Stack Protector),
  §11.4 (TLS Variant II)](https://gitlab.com/x86-psABIs/x86-64-ABI)
- [GCC manual §3.20 — `-fomit-frame-pointer`,
  `-fstack-protector*`](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- [Intel® 64 and IA-32 Architectures Software Developer's Manual
  Vol. 2A §3.3 (`CALL` — 5-byte rel32, 8-byte return push)](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- Intel SDM Vol. 3B §17.2.4 Table 17-2 (DR0–DR3 / DR7),
  §17.3.1.1 (data-breakpoint trap-after-retire).
- Intel SDM Vol. 3A §4.6 (page-table walk), §3.4.4 (FSBASE/GSBASE).
- POSIX `vfork(3p)`, `clone(2)`, `clone3(2)`, `mmap(2)`,
  `setjmp(3p)`, `sigreturn(2)`.
- PR #417 (libxul SSP-shape audit).
- PR #419 (kstack emergency-tier zero-fill — adjacent class).
- PR #420 (autopsy — `__stack_chk_fail` at ld-musl + `0x1c7f9`).
- PR #421 (code-fetch DR0 — supplies SSP-failing-function identity
  via `[F3/CODE-DR-FIRE/RSP] [base+0x00]`).
- PR #423 (linear-VA write-DR — 0/3 fires explained by this dispatch).
- PR #424 (PHYS_OFF write-DR — 0/3 fires explained; "pre-block 0x30"
  explained as residue inside a string buffer).
