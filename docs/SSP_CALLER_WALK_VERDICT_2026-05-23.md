# SSP-DIAG-CALLER-WALK Verdict — 2026-05-23

Deciding probe for the PR #421 (`0c91263b`) vs PR #425 (`1d16b16`) /
PR #426 (`3d23398`) canary-slot offset contradiction, per the
post-INFRA-4 cycle.

## TL;DR

**Verdict: NEITHER OF THE STATED OUTCOMES — third-axis failure exposed.**

PR #417's named function at libxul file offset `0x4670270` IS a real
SSP-instrumented function with frame size `0x1e8` storing its canary at
`[rsp + 0x1e0]`. PR #425's arithmetic (`frame_rsp + 0x1e8` = canary slot)
is correct for that function. **However**, the trap-time `[frame_rsp]`
qword (`0x466f670` in three independent KVM trials) is **not a real return
address**: file offset `0x466f670` is the `inc %rbx` instruction inside a
loop body, not a byte-after-a-call-site. There is no `call __stack_chk_fail`
whose return RIP would be `0x466f670`. The trap was reached via a control
path that did NOT involve a normal `call __stack_chk_fail@plt` — pre-existing
`[SSP-DIAG-PROLOGUE] prologue_found=0` and `[SSP-DIAG-RBP] rbp0=0x0
chain_break=0 reason=non_canonical` corroborate.

**Recommendation: pivot to simpler Linux apps (xeyes/xterm/wget).** The SSP
gate is reached by a non-standard control flow that neither PR #421's nor
PR #425's offset formula correctly models. Further offset adjustment is
unlikely to close the saga.

## Patch shape

One file, 41 effective code lines (within the 60 LOC hard cap):

- `kernel/src/subsys/linux/ssp_diag.rs`: new `lookup_vma_file_info()`
  helper for file-backed VMAs + new `[SSP-DIAG-CALLER-WALK]` emission
  after `[SSP-DIAG-RBP]`, before `[SSP-DIAG-SIGNALS]`. Reads
  `return_rip = [frame_rsp]`, computes `pre_call_rip = return_rip - 5`
  (CALL rel32, Intel SDM Vol. 2A §3.3), resolves the covering VMA,
  emits the byte-offset-in-file and the link-time `vaddr_in_elf` per
  ELF-64 §3, and dumps PR #425's "Reframe B" slot at
  `caller_rsp + 0x1e0` (= `frame_rsp + 0x1e8`).

Feature gate `ssp-canary-diag` (already gated; master builds
byte-identical). Shares the existing `SSP_DIAG_MAX = 8` per-boot budget.

## Captured output — three KVM trials (determinism observed without
INFRA-3 seed)

All trials emit byte-identical values except for per-boot ASLR base.

### Trial 1 — sid `a7fd0235bbb5`

```
[SSP-DIAG] match=1 pid=1 tid=1 cpu=1 rip=0x7fbf27fb97f9 ld_musl_base=0x7fbf27fb1000 vma_offset=0x87f9 fs_base=0x7fbf2803eb28 fs28_addr=0x7fbf2803eb50 fs28_val=0x1c3c3949294b00fa fs28_phys=0x12bd1b50
[SSP-DIAG-CANARY] pid=1 tid=1 caller_rsp=0x7ffffffee470 saved_slot=0x7ffffffee4c0 saved_canary=0x0000000000000030 saved_canary_phys=0x126a14c0 ax_at_gp=0x1c3c3949294b00fa ax_eq_fs28=1
[SSP-DIAG-WINDOW] pid=1 tid=1 caller_rsp=0x7ffffffee470 +0x40=0x00007ffffffee4c0 +0x48=0x0000000000000001 +0x50=0x0000000000000030 +0x58=0x00007effc016dcb0 +0x60=0x0000000000000007
[SSP-DIAG-PROV] pid=1 tid=1 saved_slot=0x7ffffffee4c0 saved_slot_phys=0x126a1000
[SSP-DIAG-RA] pid=1 tid=1 ra_slot=0x7ffffffee470 ra=0x0000000000000001 ra_vma_start=? ra_vma_end=? ra_vma_perms=?
[SSP-DIAG-PROLOGUE] pid=1 tid=1 trap_ra=0x7effc530d670 prologue_found=0 prologue_rip=? mov_fs28=0 mov_save=0 bytes=?
[SSP-DIAG-RBP] pid=1 tid=1 rbp0=0x0  rbp_chain_break=0 reason=non_canonical
[SSP-DIAG-CALLER-WALK] pid=1 tid=1 return_rip=0x7effc530d670 pre_call_rip=0x7effc530d66b caller_vma_name=[mmap-file] caller_vma_base=0x7effc26c2000 caller_vma_end=0x7effc83ec000 return_rip_offset_in_file=0x466f670 return_rip_vaddr_in_elf=0x7effc530d670 caller_vma_mount=4 caller_vma_inode=0x1d7 slot_pr421=0x7ffffffee4c0 slot_pr421_val=0x0000000000000030 slot_pr425=0x7ffffffee650 slot_pr425_val=0x0000000000000009
[SSP-DIAG-SIGNALS] pid=1 tid=1 signals_delivered=?
```

(Trials 1-3 captured with a larger emission variant that also dumped
`slot_pr421` inline; the compressed final variant drops it — already
shown by `[SSP-DIAG-CANARY]` — but is otherwise identical. See Trial 4.)

### Trial 2 — sid `ea077ab428cc`

```
[SSP-DIAG-CALLER-WALK] pid=1 tid=1 return_rip=0x7efefcf69670 pre_call_rip=0x7efefcf6966b caller_vma_name=[mmap-file] caller_vma_base=0x7efefa31e000 caller_vma_end=0x7eff00048000 return_rip_offset_in_file=0x466f670 return_rip_vaddr_in_elf=0x7efefcf69670 caller_vma_mount=4 caller_vma_inode=0x1d7 slot_pr421=0x7ffffffee4c0 slot_pr421_val=0x0000000000000030 slot_pr425=0x7ffffffee650 slot_pr425_val=0x0000000000000009
```

### Trial 3 — sid `890c2fce02a2`

```
[SSP-DIAG-CALLER-WALK] pid=1 tid=1 return_rip=0x7eff49d44670 pre_call_rip=0x7eff49d4466b caller_vma_name=[mmap-file] caller_vma_base=0x7eff470f9000 caller_vma_end=0x7eff4ce23000 return_rip_offset_in_file=0x466f670 return_rip_vaddr_in_elf=0x7eff49d44670 caller_vma_mount=4 caller_vma_inode=0x1d7 slot_pr421=0x7ffffffee4c0 slot_pr421_val=0x0000000000000030 slot_pr425=0x7ffffffee650 slot_pr425_val=0x0000000000000009
```

### Trial 4 — sid `de1b10d8bf90` (compressed-emission verification)

```
[SSP-DIAG-CALLER-WALK] pid=1 tid=1 return_rip=0x7eff4f390670 pre_call_rip=0x7eff4f39066b caller_vma_name=[mmap-file] caller_vma_base=0x7eff4c745000 caller_vma_end=0x7eff5246f000 return_rip_offset_in_file=0x466f670 return_rip_vaddr_in_elf=0x7eff4f390670 caller_vma_mount=4 caller_vma_inode=471 slot_pr425=0x7ffffffee650 slot_pr425_val=0x0000000000000009
```

(Inode renders as decimal `471` in the compressed variant — same value as
`0x1d7` above; no semantic change.)

## Cross-walk against staged libxul

Staged libxul: `build/disk/usr/lib/firefox-esr/libxul.so` — BuildID
`a5376fe04c6356fa322d30858e9e36a468f9a897`, stripped. The companion
`build/disk/usr/lib/debug/usr/lib/firefox/libxul.so.debug` has a DIFFERENT
BuildID (`0bec43280031c8118416bf812fcb5057fe753406`) — NOT a valid
symbol companion. `addr2line` against it returns inapplicable symbols and
must be discarded. `objdump` against the stripped staged binary is
authoritative:

### Disassembly at `return_rip` (file offset `0x466f670`)

```
466f660:  0f 84 49 01 00 00  je     466f7af
466f666:  41 be 08 00 00 00  mov    $0x8, %r14d
466f66c:  31 db              xor    %ebx, %ebx
466f66e:  eb 10              jmp    466f680
466f670:  48 ff c3           inc    %rbx          <-- "return_rip"
466f673:  49 83 c6 10        add    $0x10, %r14
466f677:  49 39 dc           cmp    %rbx, %r12
466f67a:  0f 84 76 fa ff ff  je     466f0f6
```

There is **no `call` whose return address could be `0x466f670`**. The five
bytes immediately preceding (`pre_call_rip = 0x466f66b`) are
`00 00 00 31 db` — the trailing bytes of `mov $0x8,%r14d` followed by
`xor %ebx,%ebx`. Not a CALL.

### Disassembly at PR #417's named function (file offset `0x4670270`)

PR #417 is **correct about the function shape**:

```
4670270:  55                  push   %rbp
4670271:  41 57               push   %r15
4670273:  41 56               push   %r14
4670275:  41 55               push   %r13
4670277:  41 54               push   %r12
4670279:  53                  push   %rbx
467027a:  48 81 ec e8 01 00   sub    $0x1e8, %rsp
4670281:  64 48 8b 04 25 28 00 00 00   mov    %fs:0x28, %rax
467028a:  48 89 84 24 e0 01 00 00      mov    %rax, 0x1e0(%rsp)
```

Frame allocation: 6 callee-saved pushes (48 B) + `sub $0x1e8` (488 B) =
536 B. Canary stored at `[rsp + 0x1e0]` after the prologue runs. When this
function executes its `call __stack_chk_fail`, the CALL pushes the return
RIP advancing RSP by 8, so inside `__stack_chk_fail`'s `hlt` body the
canary lives at `[rsp + 0x1e8]`. **PR #425's "Reframe B" arithmetic
matches this function's geometry.**

The instruction immediately preceding `0x4670270` is:

```
4670246:  e8 c5 dd 0d 03      call   774e010 <__stack_chk_fail@plt>
467024b:  48 8d 05 bf 28 ba fb  lea    -0x445d741(%rip), %rax
```

If this function's SSP-fail branch were the one trapping, the trap-time
`return_rip` would be `0x467024b` — NOT `0x466f670`.

The symbol covering both `0x466f670` and `0x4670270` is
`_ZNSt8_Rb_treeIjSt4pairIKjP17_GdkEventSequenceESt10_Select1stIS4_ESt4lessIjESaIS4_EE29_M_get_insert_hint_unique_pos<...>+0x{d060,dcd0}` — these are
two distinct compiler-generated bodies (likely an outer iterator
function and an inner exception-cleanup or inlined-copy variant) sharing
the same nearest-preceding export symbol after stripping.

## Verdict matrix

| Outcome (per dispatch) | Met? | Evidence |
|---|---|---|
| **MATCH PR #417** — `return_rip` in `[0x4670270, 0x4670670)` | NO | `return_rip` file offset is `0x466f670`, lies 0xc00 (3 KiB) *before* PR #417's range. |
| **DIFFERENT FUNCTION** — symbolisation names a different SSP-instrumented function | INCONCLUSIVE | `return_rip` is inside the *same compiler-output symbol cluster* as PR #417's function, but the byte at `return_rip` is `inc %rbx` (loop body), not a byte-after-a-call. So PR #417's function STILL appears to be the SSP-instrumented one whose canary at `[rsp+0x1e0]` was clobbered — but the trap was reached by an abnormal control transfer, NOT by `call __stack_chk_fail` from that function. |
| **UNRESOLVED** — function symbolisation fails OR no SSP prologue near the trap | YES | `[SSP-DIAG-PROLOGUE] prologue_found=0` (existing diagnostic, pre-this-PR); `[SSP-DIAG-RBP] rbp0=0x0 chain_break=0 reason=non_canonical`; pre_call site is not a CALL. The trap arrived via **non-standard control flow** — escalates to "Reframe A revival" per the dispatch. Plausible mechanisms: setjmp/longjmp into a stack constructed to look like an SSP fail; sigreturn frame manipulation; corrupted-indirect-call landing on `__stack_chk_fail` after the unrelated qword `0x466f670` was already on the stack. |

## Observed slot values (both candidate offsets corrupted)

Both PR #421's slot (`caller_rsp + 0x50` = `0x7ffffffee4c0`) and PR #425's
slot (`caller_rsp + 0x1e0` = `0x7ffffffee650`) show non-canary values
byte-identically across all four trials:

| Slot | Value | Expected canary (from `[FS:0x28]`) |
|---|---|---|
| `0x7ffffffee4c0` (PR #421) | `0x30` | high-entropy 64-bit |
| `0x7ffffffee650` (PR #425) | `0x09` | high-entropy 64-bit |

Trial 1's `[SSP-DIAG] fs28_val=0x1c3c3949294b00fa` is the live master
canary. Neither slot holds anything resembling a canary; both hold
small-integer "looks like a count" values. This is consistent with the
slots being **bystander stack memory**, not actual SSP-canary save sites,
which in turn is consistent with the "abnormal control transfer"
interpretation.

## Why PR #426 saw 0/3 D22 fires at `+0x1f48`

PR #426 armed D22 PHYS_OFF watch at `parent_rsp + 0x1f48` = PR #425's
"Reframe B" slot. The watch did not fire because — under the
abnormal-control-flow interpretation — no write to that slot occurs
between vfork-wake and the SSP trap. The slot contains stale stack
memory (`0x09`) inherited from whatever shared its frame. `[SSP-DIAG-
CANARY]` reports `0x30` at `+0x1d58` for the same reason. **The two
diagnostics agree on a single fact** — neither slot is a legitimate
canary save site in this trap's control-flow path.

## Recommended next step

**Pivot to simpler Linux apps (xeyes/xterm/wget)**, per the user's
prior authorisation. The SSP saga has now produced four sequential
"right-window-wrong-frame" outcomes (PR #421 / #425 / #426 / this
probe), and the trap's call chain demonstrably does not match either
candidate function's SSP-fail branch. Further per-offset adjustment is
unlikely to converge.

Residual axis ("Reframe A revival": find the non-standard control transfer
that lands the CPU on `__stack_chk_fail`'s `hlt` with `[rsp] = 0x466f670`
deterministically) requires disassembling outwards from libxul's
indirect-call surface — not a single-PR exercise; park unless the
simpler-app pivot reveals a related primitive.

## References

- Intel SDM Vol. 2A §3.3 — `CALL` instruction encoding (`CALL rel32` =
  `E8 cd`, 5 bytes).
- Intel SDM Vol. 3A §3.4.4.1 — `IA32_FS_BASE` MSR (`0xC000_0100`).
- System V AMD64 ABI §3.4.5 — calling convention; §3.2.2 — frame layout.
- GCC manual §3.20 — `-fstack-protector-strong`.
- ELF-64 Object File Format §3 — Program Loading
  (`vaddr_in_elf = file_offset + elf_load_delta`).
- POSIX.1-2017 — `sigaction(2)`, `setjmp(3)`, `longjmp(3)`.
- PR #417 — libxul SSP frame-shape audit.
- PR #421 — F3 code-fetch DR0 watchpoint on musl `__stack_chk_fail+0x0`.
- PR #425 — Reframe B (arm-site offset) confirmed.
- PR #426 — D22 PHYS_OFF watch re-armed at corrected offset (0/3 fires).
