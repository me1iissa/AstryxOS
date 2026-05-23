# PID 1 `exit_group(-13)` — root cause investigation

**Date**: 2026-05-23
**Author**: principal-systems-engineer
**Status**: Investigation complete — divergence named — NO code fix in this PR

## TL;DR

The dispatch task ("PID 1 EACCES'ing in trial 3, must be a syscall returning
EACCES that Linux returns 0") is **founded on a misreading of `exit_group(-13)`**.

PID 1 is **not** EACCES'ing from a syscall.  It is taking a **#GP (vector 13)
General Protection Fault** at user RIP `<ld-musl base>+0x1c7f9`.  That offset
in ld-musl-x86_64.so.1 is **`__stack_chk_fail`**, which is implemented in
musl as a single `hlt` instruction (`f4 c3`).  Executing `hlt` from
CPL=3 raises `#GP(0)` per Intel SDM Vol. 2A — that is the documented and
correct CPU behaviour.

AstryxOS encodes an unhandled user-mode #GP as `exit_group(-(vector as i64))`,
which is `exit_group(-13)` in this case.  The `-13` here has nothing to do
with `EACCES`; it is the integer encoding of vector 13.

The real divergence vs Linux is therefore not "Linux's access(2) returns 0,
ours returns EACCES".  It is "Linux's identical firefox-bin run does **not**
trip musl's SSP canary check during vfork-return cleanup; ours **does**".
That is a kernel-ABI stack-corruption gap, identical in shape to the
in-flight `sc=1171` family of investigations but firing on **PID 1
(launcher)** rather than the previously-observed **PID 2 (content process)**.

This document quantifies the divergence and recommends the next dispatch
shape.

## Citations used in this document

- Intel SDM Vol. 2A — `HLT` instruction reference: "If CPL is greater than
  0, a general protection exception (#GP) is generated."
- Linux man-pages 6.7 — `exit_group(2)`, `signal(7)` (SSP/SIGABRT semantics).
- POSIX.1-2017 §A.3.4 (process termination from synchronous fatal CPU
  exceptions).
- musl public docs `musl.libc.org/about.html` — SSP support is
  unconditional; `__stack_chk_fail` is `noreturn`.
- ELF gABI 5.2 (PT_INTERP base-address semantics).
- POSIX `vfork(3p)` — parent suspended until child `_exit` or `execve`;
  shared address space until then.

## Reproduction

```
python3 scripts/qemu-harness.py start --features "firefox-test,kdb,syscall-trace"
# Wait until [SC] pid=1 ... clone/56 ret=2 fires (vfork+execve PID 2 = glxtest)
# Within ~50 ticks of that, see the [EXC] vec=13 ... CS=0x23 line.
```

Two fresh-master sids reproduce 100% identical pattern:

| sid | RIP at #GP | ld-musl base | offset in ld-musl | exit_code emitted |
|---|---|---|---|---|
| `8ff0efde94ce` | `0x7fa8e3d417f9` | `0x7fa8e3d25000` | `0x1c7f9` | `-13` |
| `8543b82d338d` | `0x7f65740357f9` | `0x7f6574019000` | `0x1c7f9` | `-13` |

Both runs land at the **identical ld-musl offset `0x1c7f9`**.  `objdump -d
build/disk/lib/ld-musl-x86_64.so.1` shows the symbol at that offset:

```
000000000001c7f9 <__stack_chk_fail>:
   1c7f9:   f4                      hlt
   1c7fa:   c3                      ret
```

The RIP-content dump emitted by the IDT handler agrees byte-for-byte:

```
[FAULT/PHYS/RAW16] rip=0x7f65740357f9 phys=0x128f9000 bytes=f4 c3 48 8b 05 9e 27 08 00 53 48 8b 18 48 c7 00
```

`f4` is HLT; `c3` is RET; `48 8b 05 9e 27 08 00` is `mov rax, [rip+0x8279e]`
(the start of the next function in ld-musl, presumably `__stack_chk_guard`
load or similar).

## The actual return path in AstryxOS

1. User code calls some function in libxul/firefox-bin whose prologue saves
   the SSP canary from `FS:0x28` to a slot in its stack frame.
2. The function returns; its epilogue compares the saved canary against
   `FS:0x28`.  Mismatch → it calls `__stack_chk_fail` (tail-call, RIP
   stored to the called function's own stack as the return address).
3. Inside `__stack_chk_fail` (ld-musl `+0x1c7f9`), the first instruction is
   `hlt`.  CPL=3 (CS=0x23) → CPU raises `#GP(0)`.
4. AstryxOS `kernel/src/arch/x86_64/idt.rs:1183` translates the unhandled
   user-mode #GP into `crate::proc::exit_group(-(vector as i64))` =
   `exit_group(-13)`.
5. `kernel/src/subsys/linux/syscall.rs:3125` is the userspace `exit_group`
   path; this is internal and doesn't run for the IDT-side call, but the
   diagnostic `[PROC] PID 1 exit_group(-13) caller_tid=2` is emitted from
   `kernel/src/proc/mod.rs::exit_group`.

The `[VFORK/CANARY]` probe (already in tree) confirms that the *TCB-side*
canary at `FS:0x28` is **stable** across the vfork — the value
`0x8ce3ae1ad2ee0005` is identical in both `pre_block.clone` and
`post_wake.clone`.  Therefore the corruption is on the **stack frame**, not
in the TCB.  This matches the F3-saga shape: a saved-canary slot in a
function's stack frame is mutated between the function prologue and epilogue
across a vfork-return boundary.

## The Linux side

Per `docs/LINUX_GROUND_TRUTH_FF_2026-05-22.md` and a fresh manual review:
the same musl-linked firefox-bin running under Linux 6.8 completes the
identical syscall sequence (vfork+execve glxtest, parent reads child status
pipe, closes fds, returns from launcher to `XRE_main`) without ever
entering `__stack_chk_fail`.  The TCB canary is the same shape; the stack
frames are the same shape; the function calls are the same.  Linux's
*kernel* simply does not introduce the perturbation that causes the saved
canary slot on PID 1's user stack to drift.

man `signal(7)`: SSP failure on Linux normally synthesises `SIGABRT` (via
`abort(3)`), but musl's `__stack_chk_fail` short-circuits with `hlt` and
relies on the kernel to deliver the resulting SIGSEGV/SIGBUS.  On AstryxOS
we don't synthesise a signal — we terminate the process directly via
`exit_group(-vector)`.  That is a separable, smaller divergence (see
recommendation #3 below).

## The misreading

The dispatch task assumed `exit_group(-13)` meant "PID 1 called exit_group
with the EACCES errno value", as if `firefox-bin` had read an `errno == 13`
from a failing syscall and propagated it.  Two things falsify that reading:

1. The syscall ring captured immediately before exit (256 entries) contains
   **zero syscalls** returning `-13` / `EACCES`.  Every negative return in
   the ring is `-2` (ENOENT) for the standard library-path probe sequence
   `[/lib/x86_64-linux-gnu, /usr/lib, /etc/ld-musl-x86_64.path]` — all
   benign and expected.
2. The `[EXC] vec=13 err=0x0 RIP=…` line is emitted by the IDT path
   (`kernel/src/arch/x86_64/idt.rs`), not by any syscall dispatcher.  No
   syscall returned `-13` to userspace; the kernel synthesised the exit
   code from the vector number.

The misreading is easy to make because (a) errno EACCES happens to equal
13, and (b) `exit_group(-13)` looks like a userspace literal.  Future qa
reports should not infer EACCES from `exit_group(-13)` without checking
the preceding `[EXC] vec=…` line.

## Divergence — named

AstryxOS perturbs PID 1's user stack in a way that mutates the saved-canary
slot in some libxul/firefox-bin frame across the vfork-return boundary,
between the function's prologue (which stores `FS:0x28` into the slot) and
its epilogue (which compares the slot to `FS:0x28`).  Linux does not.

Suspected perturbation candidates (each falsifiable with a small probe):

1. **vfork stack handling.**  AstryxOS's vfork shares the parent's VM,
   then the child execve cleans up its inherited stack pages.  See
   `[VFORK-STACK] cleanup parent_pid=1 cr3=0x12111000 base=0x7f13ba2c9000
   length=0x10000 unmapped_pages=1` in the trace.  If this cleanup walks a
   range that overlaps the parent's live stack (e.g. due to a stale
   `stack_start` from before vfork), it would mutate exactly this kind of
   saved-canary slot.  Falsifier: snapshot the saved-canary slot phys-page
   before and after `[VFORK-STACK] cleanup` and dump any mismatching word.
2. **Signal-frame restore vs syscall return path on the parent.**  After
   futex/SIGCHLD wakeup, the parent's saved RSP/RIP come from the per-CPU
   syscall save area; if any spilled register or red-zone byte is written
   on the kernel side between SAVE and RESTORE, a 16-byte-aligned canary
   slot could be clobbered.  Falsifier: DR-watchpoint on the canary slot
   for PID 1 TID 2 from the moment of vfork wake through the next 32
   syscalls.
3. **Stack-frame identity loss across vfork's `clone` codegen.**  In the
   musl source the `clone` wrapper saves a frame pointer; if our `clone`
   syscall return path skips restoring an alignment-sensitive register,
   the saved canary may be read from one slot and written to another.
   Falsifier: dump the user RSP+0..0x80 bytewise at `pre_block.clone` and
   at the syscall-return that immediately precedes `__stack_chk_fail`,
   diff.

This is the **same shape** as the in-flight `sc=1171` family; the only
difference is the surface — PID 1 here, PID 2 in the previously-observed
saga.

## Recommendation

**Do NOT include a fix in this PR.**  The divergence is the same class as
sc=1171 / F3, which is an active multi-iteration saga.  Adding a partial
fix here while another agent is investigating the same class would
duplicate work and introduce churn.

Three small, separable items that can be picked up cleanly:

1. **(Documentation only — this PR)** This document, so the next qa /
   investigator dispatch doesn't re-derive "exit_group(-13) means EACCES".
   The qa report
   `/home/ubuntu/.claude/projects/-home-ubuntu-AstryxOS/1d60ef12-e992-48c8-8800-0ac84ba49171/subagents/agent-a5932b26508ff3d3d.jsonl`
   already half-acknowledges this in its closing paragraph; this doc
   makes it explicit.

2. **(~30 LOC, separate PR — `aether-kernel-engineer` scope)** Improve
   the IDT exit-code encoding so PID 1 emits a *labelled* termination line:

   ```
   [PROC] PID 1 terminated by #GP (vector 13) at RIP=… → exit_code=-13
   ```

   instead of bare `exit_group(-13) caller_tid=2`.  This is purely a
   logging-clarity change; it does not change behaviour.  Location:
   `kernel/src/arch/x86_64/idt.rs:1183` and
   `kernel/src/proc/mod.rs::exit_group`.

3. **(~50 LOC, separate PR — `aether-kernel-engineer` + sc=1171 owner
   coordination)** Wire a DR-watchpoint on the PID-1 PT_TLS / saved-canary
   stack slot from the moment of `[VFORK/CANARY] pre_block.clone`,
   following the same shape as the existing D7/D8/D15/D16/D17/D18
   diagnostics in `kernel/src/arch+subsys/linux`.  This produces phys-
   anchored "name the writer" data identical in form to the PID-2 work.

The PR for this dispatch contains item (1) only.

## Artefacts

- `/home/ubuntu/.astryx-harness/8ff0efde94ce.serial.log` (T1 — qa
  dispatch a5932b26)
- `/home/ubuntu/.astryx-harness/43a3ba4357ad.serial.log` (T2)
- `/home/ubuntu/.astryx-harness/557ffbdba186.serial.log` (T3)
- `/home/ubuntu/.astryx-harness/8543b82d338d.serial.log` (this dispatch's
  fresh reproduction)
- `objdump -d build/disk/lib/ld-musl-x86_64.so.1 | grep -B1 '1c7f9:'` for
  the ld-musl symbol confirmation.
