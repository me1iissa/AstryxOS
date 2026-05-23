# vfork → SSP-canary structural walkthrough (Wave 14, INFRA-4)

**Date**: 2026-05-23
**Author**: principal-systems-engineer
**Saga**: user-SSP canary mismatch (sc=1171 / F3 / Wave 12+13 reframes)
**Status**: Reference data — no code changes, doc-only. Inputs: PR #248
(W215 H3a/H3b channel), PR #408 (D22 phys dispositive), PR #410 (slot-11
RBP bit-stable), PR #411 (Linux RBP ground-truth).

## TL;DR

After 6 weeks of writer-hunt diagnostics, every kernel-side mechanism that
could mutate the parent's saved SSP canary has been falsified:

- **RBP-identity** across `schedule()`: closed. PR #410 — slot-11 bit-stable
  `0x7ffffffec738` 3/3 KVM. Mirrored on Linux at `0x7fffffffeb30`.
- **Phys-aliasing**: closed. PR #408 — `phys_at_arm == phys_at_write`
  byte-for-byte across 6 D22 fires. Same backing frame both ends.
- **Kstack writer**: closed. Wave 12 audit + PR #410 — no signal/exec/
  scheduler path mutates parent's syscall-frame slot 11 (RBP).
- **Register-restore ordering**: convergent. Both AstryxOS and Linux pop
  `..., r12, rbp, rbx, r11, rcx, rsp, sysretq`. RBP popped before RSP.
- **Stack-cleanup ordering**: convergent. Both kernels run the child's
  resource teardown BEFORE waking the parent.

The Wave 13 finding `write_va=0x..458 vs read_va=0x..4c0` (delta `0x68`) with
RBP stable and phys stable means the failing function's **prologue store and
epilogue load are reading different canary slots in the same RBP-anchored
frame**. This collapses the saga onto two unfalsified axes:

1. **`fs:0x28` value drift during the vfork window** — never directly
   measured on AstryxOS at the pre-block / post-wake snapshot points (only
   measured on Linux in PR #411). Cheapest dispositive probe.
2. **SSP frame-shape skew in libxul** — prologue store offset and epilogue
   load offset disagree about what `[rbp-?]` means. Userspace-binary axis
   requiring `objdump -d libxul.so` around the failing RIP.

Recommended next dispatch: **`[VFORK/GUARD]` pre/post fs:0x28 snapshot**,
~30 LOC in `kernel/src/subsys/linux/syscall.rs`, dispositive on axis 1.
If `fs:0x28` is bit-stable, escalate to objdump audit (axis 2) — that path
exits the kernel and lands with `abi-compatibility-engineer`.

## Methodology change vs dispatch brief

The INFRA-4 brief expected a 5-reader fan-out via the Agent tool. The Agent
/ Task / spawn tool was not granted in this dispatch's tool surface
(verified via `ToolSearch` for "select:Agent", "select:Task", "+Task",
"subagent dispatch"). Executed as a single principal-systems-engineer walk
following the brief's 10-step decomposition. Notes written to the shared
scratch cache at `/home/ubuntu/.astryx-research-cache/walkthrough-vfork-ssp/`
for future re-runs.

## 10-step gap matrix

| # | Step | Linux structure | AstryxOS structure | Verdict | Gap category | Suggested probe |
|---|---|---|---|---|---|---|
| 1 | process-load | ELF mmap + AT_RANDOM in AUXV; initial RSP at stack-top; FS_BASE=0 | ELF mmap + AUXV; AT_RANDOM presence unverified; entry_rsp = result.user_stack_ptr; FS_BASE set later | EQUIVALENT (modulo AT_RANDOM) | possible: AT_RANDOM omission | grep ELF loader for AT_RANDOM, decode AUXV at first emit |
| 2 | ldmusl-init | musl `__libc_start_main` reads AT_RANDOM, writes `pthread->canary` (= fs:0x28) | runs upstream binary; same code path executes in user-mode | BIT-IDENTICAL by construction (upstream binary) | precondition risk if AT_RANDOM absent | covered by step-1 probe |
| 3 | tls-bootstrap | `__init_tls` allocates TCB via mmap or builtin, calls `arch_prctl(SET_FS)` | userspace `arch_prctl(SET_FS, addr)` → kernel `sys_arch_prctl` (subsys/linux/syscall.rs:3153) → `proc::write_fs_base(addr)` | EQUIVALENT (different code but same MSR semantics) | none observed | n/a |
| 4 | libxul-init-array | dl_init → ctor chain | identical (upstream binary runs) | BIT-IDENTICAL by construction | n/a | n/a |
| 5 | mozilla-spawn | musl `posix_spawn` → `__clone(child, &args, CLONE_VM\|CLONE_VFORK\|SIGCHLD)` with `stack[1024+PATH_MAX]` on parent's stack | identical (upstream binary runs) → AstryxOS sees sc=56 with CLONE_VM\|CLONE_VFORK | BIT-IDENTICAL on entry; AstryxOS substitutes child stack (justified — see step 6) | none observed | n/a |
| 6 | kernel-clone-vm-vfork | `kernel_clone` → `copy_process` (kstack, fds, mm if !CLONE_VM) → `wake_up_new_task` → `wait_for_vfork_done` (parent blocks on completion on its own kstack) | `fork_process_share_vm` (share CR3) → `alloc_vfork_child_stack` (substitute 64 KiB VMA) → `unblock_process(child)` → parent sets Blocked → `schedule()` | EQUIVALENT (different shape, same semantics) | none observed | n/a |
| 7 | parent-block-wake | child's `mm_release` calls `complete(vfork)` from exit/exec path | child's `sys_exec` or `exit_thread` calls `wake_vfork_parent` which only writes `p.state = Ready` | EQUIVALENT — no writer to kstack/userstack from wake-side | none observed | n/a |
| 8 | parent-saved-state | `PUSH_REGS` macro lays out pt_regs on kstack; rbp at fixed offset; signal/ptrace can rewrite via pt_regs* | syscall_entry pushes manually, frame slots: 0..14 with rbp@11, rsp@14, RFLAGS@12, RIP@13; signal_check_on_syscall_return can write slot 14 for signal-handler delivery | EQUIVALENT (different layout but functionally equivalent) | none observed | n/a |
| 9 | parent-return-userland | POP_REGS r15→r14→...→rbp→rbx→r11→rcx→rsp→sysretq; FS_BASE restored at sched-in (via `__switch_to_xtra`), not at SYSRET | identical pop order; FS_BASE restored via `proc::write_fs_base` at thread-switch | EQUIVALENT (audit needed for exact AstryxOS sched-in FS_BASE site for vfork-wake) | needs-verify ordering | grep `proc::sched::switch_to` for write_fs_base call site |
| 10 | ssp-epilogue | gcc `-fstack-protector-strong`: prologue `mov rax, fs:0x28; mov [rbp-8], rax`. Epilogue `mov rdx, [rbp-8]; sub rdx, fs:0x28; jne <call __stack_chk_fail>` | identical (upstream binary runs) | BIT-IDENTICAL by construction (upstream binary) | precondition: `fs:0x28` must be stable AND prologue/epilogue must address the same canary slot | (A) two-snapshot `fs:0x28` probe; (B) objdump audit of failing libxul fn |

## Answers to the 6 critical questions

**Q1 — Does AstryxOS write `__stack_chk_guard` to the SAME `fs:0x28` slot as
Linux at the SAME step?**
**Confidence: HIGH.** musl's `__libc_start_main` → `__init_security` does the
write on both kernels — same upstream binary, same code path, runs in user
mode. The precondition is that AstryxOS's execve places `AT_RANDOM` in
AUXV. The boot-time success of musl on AstryxOS in countless prior PRs
(reaching libxul init) implies AT_RANDOM is present; otherwise musl would
abort earlier.

**Q2 — Does AstryxOS's vfork child see the EXACT SAME stack layout as
Linux's?**
**Confidence: MEDIUM.** No. AstryxOS substitutes a fresh 64 KiB VMA for the
child (`alloc_vfork_child_stack`); Linux runs the child on `stack+sizeof
stack` of the parent's posix_spawn-local buffer. This is a deliberate
divergence to avoid CWE-787-class overflow; it does NOT affect the
parent's SSP slot. The parent's RBP-anchored frame is on the parent's
RSP page, which is untouched on both sides.

**Q3 — Does AstryxOS restore RSP, RBP, AND FS_BASE in the SAME ORDER as
Linux?**
**Confidence: HIGH for RBP/RSP, MEDIUM for FS_BASE.** RBP and RSP pop order
is byte-identical to Linux's POP_REGS macro (verified against
`arch/x86/entry/calling.h` `POP_REGS`). FS_BASE is NOT touched on the
SYSRET path on either kernel; both restore at sched-in via WRMSR. The
AstryxOS sched-in path needs one direct audit (covered in gap 9) to
confirm FS_BASE is restored BEFORE any user code that touches `%fs:0x28`
can run. With both kernels following the same architecture this is
essentially given, but explicit verification is cheap and would close the
gap to HIGH.

**Q4 — Are there any concurrent writes to the parent's stack between
blocking and unblocking?**
**Confidence: HIGH (no).** Audited:
- `switch_context_asm`: pushes 7 qwords (rbp, rbx, r12-r15, RFLAGS) on the
  parent's KERNEL stack, not user stack. Symmetric push/pop on resume.
- `wake_vfork_parent`: ONLY writes `p.state = Ready` in THREAD_TABLE. No
  user-VA access.
- `vfork_isolated_stack_cleanup` and `vfork_isolated_tls_cleanup`:
  manipulate disjoint VMAs allocated via `find_free_stack_range` —
  separate stack-ASLR window. They DO bump `vm_space.generation`, but
  the parent isn't faulting during the window, so generation-aborts are
  not consequential.
- `sys_exec` case-C path: switches CR3 to child's NEW cr3 (parent's CR3
  still mapped and live). No write through PHYS_OFF direct map to any
  frame backing the parent's stack VA — PR #408 verified.
- The kstack-cache reuse / freelist scribble / page-zero paths: all
  audited in Wave 12. None fire for an in-flight parent thread.

**Q5 — Does ld-musl's vfork wrapper actually touch RBP?**
**Confidence: HIGH (no).** Confirmed against musl
`src/process/x86_64/vfork.s`:
```
vfork:
    pop  %rdx          ; pop return addr to rdx
    mov  $58, %eax
    syscall
    push %rdx          ; push return addr back
    mov  %rax, %rdi
    jmp  __syscall_ret
```
No `push %rbp` / `mov %rbp, ...` / `lea %rbp, ...`. PR #411 already
verified by running this exact wrapper on Linux with GDB. **However**:
Mozilla's libxul uses `posix_spawn(3)`, NOT raw `vfork(2)`. posix_spawn
issues sc=56 (clone) via `__clone`, not sc=58. The SSP-instrumented
frame is libxul's posix_spawn-caller, separated from the `__clone`
wrapper by at least posix_spawn() itself.

**Q6 — Does anything in the AstryxOS kstack/free path write to the
PARENT'S USERSPACE STACK PAGE while the parent is parked?**
**Confidence: HIGH (no — verified by PR #408 phys-stability).** PR #408
proved that the physical frame backing the parent's `[rbp-8]` VA at
prologue-arm time is IDENTICAL to the phys at epilogue-write time (D22
PHYS_OFF channel, 6/6 byte-identical). If any kernel writer were
mutating that frame via `PHYS_OFF + phys`, the D22 channel would have
fired. It did not. Combined with PR #410's slot-11 RBP bit-stability,
the kernel CANNOT be the writer to `[rbp-8]` during the window.

## Prioritised dispatch list (top 5)

| # | Dispatch | Why | LOC | Agent type |
|---|---|---|---|---|
| 1 | **`[VFORK/GUARD]` fs:0x28 two-snapshot probe** at `pre_block.clone` and `post_wake.clone` | Closes axis 1 (FS-BASE-or-guard drift). Cheapest dispositive in the saga's history. Wave 12 assumed `fs:0x28` was stable; never measured on AstryxOS. | ~30 (`kernel/src/subsys/linux/syscall.rs:2553` + `:2636`; vfork_canary_snapshot helper) | astryx-kernel-engineer |
| 2 | **libxul SSP-shape `objdump` audit** at the failing function | Closes axis 2 (frame-shape skew). The Wave 13 `0x68` delta between write_va and read_va is the smoking gun for prologue-vs-epilogue offset disagreement. Userspace-binary axis. | ~60 (script + doc) | abi-compatibility-engineer |
| 3 | **AT_RANDOM AUXV verification** | Defensive: if AT_RANDOM is absent or zeroed, musl's `__init_security` writes canary=0 and the SSP compare always fails on functions whose prologue stored a non-zero `fs:0x28` snapshot taken before the canary write. | ~20 (kernel/src/proc/elf.rs + diagnostic) | aether-kernel-engineer |
| 4 | **FS_BASE-on-sched-in audit for vfork-wake path** | Confirms gap-9. Direct grep of `proc::sched::switch_to` + ordering with `switch_context_asm` and `proc::write_fs_base`. Doc-only or small assert. | ~20 (audit + `debug_assert!`) | aether-kernel-engineer |
| 5 | **Multi-frame SSP walker on D21 fire** | Dumps the parent's user RBP-chain when the watchpoint fires. Disambiguates "same function, different slot" from "two different functions sharing similar layout". | ~60 (kernel/src/subsys/linux/d21_user_canary_watch.rs additive) | aether-kernel-engineer |

## Single most-likely candidate

**SSP frame-shape skew in the failing libxul function** (axis 2, dispatch
#2 above). Reasoning:

The Wave 13 `write_va=0x..458 vs read_va=0x..4c0` (delta `0x68`) with
RBP bit-stable AND phys bit-stable AND no kstack writer found is
*structurally impossible* unless:

- The prologue and epilogue address different qwords through different
  base-displacement modes, OR
- The "prologue" and "epilogue" are in different functions, OR
- The canary value at `fs:0x28` changed mid-window.

The third is testable cheaply (dispatch #1, `[VFORK/GUARD]`). The first
two are tested by `objdump -d libxul.so` around `__stack_chk_fail@plt`
call sites (dispatch #2). If the prologue store and epilogue load
genuinely target the same `[rbp-8]` slot, the saga collapses onto a
TRUE userspace writer (libxul or its callees writing through some other
path into `[rbp-8]` between prologue and epilogue — the most exotic
possibility) or onto AT_RANDOM (dispatch #3).

Probability ranking based on saga falsifications:
- 40% SSP frame-shape skew (axis 2)
- 30% `fs:0x28` drift during window (axis 1)
- 15% AT_RANDOM absent / zeroed (axis 3)
- 10% FS_BASE sched-in ordering on vfork-wake (axis 4)
- 5% userspace writer inside libxul (long tail)

## Public-spec citations

- System V AMD64 ABI 1.0 §3.2.2, §3.4.5.2, §3.4.2 (RBP preservation, frame
  pointer convention, TLS variant II)
- System V x86_64 psABI §6.4 (`__stack_chk_guard` at `fs:0x28`)
- Intel SDM Vol. 2B (`SYSCALL`, `SYSRETQ` — register restore semantics)
- Intel SDM Vol. 3A §3.4.4.1 (`IA32_FS_BASE` MSR 0xC000_0100)
- Intel SDM Vol. 3A §4.10.4-5 (TLB shootdown coherence)
- Intel SDM Vol. 3B §17.2.4 (`DR0`-`DR3`, `DR7` linear-VA watchpoints)
- POSIX.1-2017 `vfork(2)`, `clone(2)`, `posix_spawn(3)`, `execve(2)`,
  `arch_prctl(2)`
- ELF gABI §3.5 (`PT_TLS`)
- GCC manual §3.20 (`-fstack-protector-strong`)
- musl libc public docs (`vfork`, `posix_spawn`, `__init_tls`)
- kernel.org public docs (`AT_RANDOM`, CLONE_VM semantics)

## Raw walk substrate (not committed; for future dispatches)

Shared cache: `/home/ubuntu/.astryx-research-cache/walkthrough-vfork-ssp/`

- `_meta/README.md` — decomposition + note schema
- `_meta/SOLO_ORCHESTRATOR_NOTE.md` — methodology change record
- `astryxos/06-kernel-clone-vm-vfork.md`
- `astryxos/07-parent-block-wake.md`
- `astryxos/08-parent-saved-state.md`
- `astryxos/09-parent-return-userland.md`
- `musl/02-ldmusl-init.md`
- `musl/05-mozilla-spawn.md`
- `musl/10-ssp-epilogue.md`
- `linux/07-parent-block-wake.md`
- `gaps/07-block-wake.md`
- `gaps/09-fs-base-restore.md`
- `gaps/10-ssp-shape.md`

A future re-dispatch with the Agent tool can use these as starting points
for the 5-reader fan-out per the INFRA-4 brief.
