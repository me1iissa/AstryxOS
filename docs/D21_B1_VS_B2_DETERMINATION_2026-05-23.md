# D21 B1-vs-B2 determination — vfork stack-substitution gate sub-shape identification

**Date**: 2026-05-23
**Author**: abi-compatibility-engineer
**Inputs**: PR #404 (D21 DR-watchpoint, merged), PR #405 (tech-lead cross-walk doc, open), PR #398 (PID 1 `exit_group(-13)` is `__stack_chk_fail` #GP, merged), fresh KVM trial `5457f20092bf`, prior dispositive trial `14173782be43`
**Status**: framing call — verdict is neither B1 nor B2 as originally posed; reframes the question

## 1. TL;DR

**Neither B1 nor B2 is the active sub-shape.** The vfork substitution gate at
`kernel/src/subsys/linux/syscall.rs:2341` ran successfully:

| Marker | Captured | Implication |
|---|---|---|
| `[VFORK] new_stack=0x7ffffffedd28` | non-zero | B1 (`new_stack == 0` gate miss) is **rejected** — the gate condition `if new_stack != 0` was true |
| `[VFORK-STACK] alloc base=0x7f0d0be0f000 top=0x7f0d0be1f000 new_rsp=0x7f0d0be1eff8` | allocator returned `Some(child_rsp)` inside `[STACK_ASLR_MIN, STACK_ASLR_MAX) = [0x7F00_…, 0x7F40_…)` | B2 (`alloc_vfork_child_stack` returned `None` → WARN path) is **rejected** — no `[VFORK] WARN: failed to allocate isolated stack` line was ever emitted |
| `[VFORK/CHILD-STACK] note=runtime_rsp_substituted_by_caller` | recorded | substitution applied to the child thread's `user_entry_rsp` |
| `[VFORK-STACK] cleanup parent_pid=1 base=0x7f0d0be0f000 unmapped_pages=1` | recorded | VMA torn down on the child's `execve` — full lifecycle observed |

The DR-watchpoint writes at user-VA `0x7ffffffee458` (`ld-musl+0x15630` push %rbx
and `ld-musl+0x1efb7` syscall handler) happen **AFTER `[VFORK/CANARY]
post_wake.clone`** — i.e. after the child has already `execve`'d, the substituted
stack VMA has already been torn down, and the **parent PID 1 TID 2 has resumed
execution**.  Those musl writes are normal post-`vfork(2)` parent execution
(continuing the libxul/musl helper chain that called vfork in the first place);
they are pushes into the parent's `[stack]` band by definition.

The corruption that fires `__stack_chk_fail` (`RIP = <ld-musl base>+0x1c7f9`)
is **not the writes the D21 watchpoint captured**.  D21 was watching the
canary slot at `[user_rsp + 0x1d50]` (rbp-derived candidate 1) and
`[user_rsp + 0x1d58]` (raw-offset candidate 2) on the PARENT'S stack frame
that called `vfork(2)`.  Those values are equal across `pre_block.clone` and
`post_wake.clone` (`s_1d58 = 0x7ffffffee4c0` in both snapshots).  The
post-vfork DR fires are the **musl epilogue/syscall-return prologue pushing
into the slot the canary already occupied** — a *legitimate write to a
restored stack frame*, not a corruption of the canary itself.

The real divergence vs Linux is therefore not the substitution gate.  The
real divergence is that **the parent's stack frame state at `vfork(2)` return
is different from what musl's SSP prologue saved before the call**.  The
gate-related substitution is doing exactly what it was designed to do; the
SSP fault has a different origin.

## 2. Captured serial-log evidence

Fresh KVM trial `5457f20092bf`, features
`firefox-test,kdb,syscall-trace,d21-user-canary-watch`, `--firefox-variant musl`,
host CR3=`0x12429000`, started 2026-05-23 02:59:30Z:

```
[VFORK] pid=1 flags=0x4111 vfork=true parent_tid=2 new_stack=0x7ffffffedd28 tls=0x7eff9dbfeb80
[VFORK/CHILD-STACK] pid=2 parent_pid=1 parent_frame_rsp_at_clone=0x7ffffffec708
                    child_uses_parent_frame_at_clone=true
                    note=runtime_rsp_substituted_by_caller
                    parent_tls_base=0x7f6649dddb28 child_tls_base=0
[VFORK] child PID 2 TID 5 created (shared VM)
[VFORK-STACK] alloc base=0x7f11784ae000 top=0x7f11784be000 new_rsp=0x7f11784bdff8
              arg=0x7ffffffec730 (parent_rsp=0x7ffffffedd28)
[VFORK/TLS] pid=1 child_tid=5 child_tls_base=0x7f6649dddb28 via=parent
[VFORK/CANARY] pre_block.clone pid=1 parent_tid=2
               fs_base=0x7f6649dddb28 fs_28=0x9705bb7d37470085
               tcb_self=0x7f6649dddb28 user_rsp=0x7ffffffec708
               s_1d8=0x0 s_1e0=0x0 s_d58=0x80520001
               s_1d58=0x7ffffffee4c0 s_1d60=0x7effa2d8e5f5
               win_bytes=8192 win_crc=0x35b37ed6
[D21/ARM] pid=1 tid=2 state=caller_rbp_bad
          wrap_rbp=0x7ffffffec738 caller_rbp=0xfffffffc7ff7fdff
[VFORK-STACK] cleanup parent_pid=1 cr3=0x12429000 base=0x7f11784ae000
              length=0x10000 unmapped_pages=1
[VFORK] child tid=5 waking parent tid=2
[VFORK/CANARY] post_wake.clone pid=1 parent_tid=2
               fs_base=0x7f6649dddb28 fs_28=0x9705bb7d37470085
               tcb_self=0x7f6649dddb28 user_rsp=0x7ffffffec708
               s_1d8=0x0 s_1e0=0x0 s_d58=0x80520001
               s_1d58=0x7ffffffee4c0 s_1d60=0x7effa2d8e5f5
               win_bytes=8192 win_crc=0x35b37ed6
[EXC] vec=13 err=0x0 RIP=0x7f6649d587f9 CS=0x23 RSP=0x7ffffffee468
[PROC] PID 1 exit_group(-13) caller_tid=2
```

In the prior dispositive trial `14173782be43` (kernel build with the
RBP-derived + raw-offset arming branches both reaching `state=armed`):

```
[VFORK] pid=1 flags=0x4111 vfork=true parent_tid=2 new_stack=0x7ffffffedd28
[VFORK-STACK] alloc base=0x7f0d0be0f000 top=0x7f0d0be1f000 new_rsp=0x7f0d0be1eff8
[D21/ARM] channel=rbp_derived state=armed pid=1 tid=2 cpu=1 cr3=0x12431000
          probe_va=0x7ffffffee460 saved_rbp=0x7ffffffee4c0 canary_va=0x7ffffffee4b8
          canary_val=0x1 slot=1 kind_tag=7
[D21/ARM] channel=raw_offset state=armed pid=1 tid=2 cpu=1 cr3=0x12431000
          canary_va=0x7ffffffee458 canary_val=0x7ffffffee4c0 slot=2 kind_tag=7
[VFORK-STACK] cleanup parent_pid=1 cr3=0x12431000 base=0x7f0d0be0f000 unmapped_pages=1
[VFORK/CANARY] post_wake.clone … s_1d58=0x7ffffffee4c0 …      ← unchanged across window
[W215/DR-WATCH-FIRE] slot=2 fire_idx=0 cpu=1 rip=0x7fbe5a7dd630 cs=0x23 cr3=0x12431000
                     linear=0x7ffffffee458 kind_tag=7
[W215/DR-WATCH-FIRE/STACK] slot=2 cpu=1 rip=0x7fbe5a7dd630 rsp=0x7ffffffee458
[W215/DR-WATCH-FIRE] slot=2 fire_idx=1 cpu=1 rip=0x7fbe5a7e6fb7 cs=0x23 cr3=0x12431000
                     linear=0x7ffffffee458 kind_tag=7
[W215/DR-WATCH-FIRE/STACK] slot=2 cpu=1 rip=0x7fbe5a7e6fb7 rsp=0x7ffffffee458
[PROC] PID 1 exit_group(-13) caller_tid=2
```

Both DR fires happen **after** `post_wake.clone` (line 4995) and **before**
the `exit_group(-13)` (line 5354).  CR3 = `0x12431000` is PID 1's address
space; CS = `0x23` is CPL=3 user mode.  RSP = `0x7ffffffee458` = the watched
canary VA itself.  The values stored at `[user_rsp + 0x1d58]` are *identical*
across `pre_block.clone` and `post_wake.clone` — the canary slot is not
modified by the vfork child or by the kernel during the window.

## 3. Source-code analysis

### `kernel/src/subsys/linux/syscall.rs:2341` (the gate)

```rust
if new_stack != 0 {
    match crate::proc::alloc_vfork_child_stack(pid, new_stack) {
        Some(child_rsp) => { /* record child_rsp on thread.user_entry_rsp */ }
        None => { /* WARN line, fall back to caller-supplied new_stack */ }
    }
}
```

The captured `new_stack=0x7ffffffedd28` ≠ 0 → the gate enters the `match`.
The captured `[VFORK-STACK] alloc … new_rsp=0x7f11784bdff8` proves
`alloc_vfork_child_stack` returned `Some(0x7f11784bdff8)`.  Neither failure
mode of the gate was reached.

### `kernel/src/proc/mod.rs:3192` (`alloc_vfork_child_stack`)

`Phase 0` validates `parent_new_stack` (validate_user_ptr + 8-byte
alignment) — both pass for `0x7ffffffedd28`.  `Phase 1` reads the
helper-arg word (`arg=0x7ffffffec730` in the captured `[VFORK-STACK]
alloc` line).  `Phase 2` calls `space.find_free_stack_range(0x10000)` —
returned `0x7f11784ae000` (inside `[STACK_ASLR_MIN=0x7F00_…,
STACK_ASLR_MAX=0x7F40_…)`).  `Phase 3` allocates and zeroes a frame, writes
the arg word at `top - 8`, installs PTE — the `[VFORK-STACK] alloc` line
prints unconditionally on success, and we see it.  Allocator path: clean.

### `kernel/src/mm/vma.rs:1082` (`find_free_stack_range`)

Returns `None` only when:

1. Requested size > 256 GiB (the window).  64 KiB is far smaller — N/A.
2. All 16 jittered placements collide with existing VMAs AND the fallback
   `find_free_range` also fails.  In the captured trial, the first
   placement succeeded (no retries logged).

### `kernel/src/subsys/linux/syscall.rs:2365` (the WARN path)

`crate::serial_println!("[VFORK] WARN: failed to allocate isolated stack; …")`
— this string is **never** emitted in the captured trial (verified via
`grep 'VFORK.*WARN' /home/ubuntu/.astryx-harness/5457f20092bf.serial.log`
returns empty).  B2 is mechanically excluded.

### Why D21 still observed writes at the parent's canary VA

The substitution gate places the **child** on an isolated stack.  It does
nothing to the **parent's** stack, which is correct: per POSIX `vfork(2)`
the parent is suspended until the child `_exit`s or `execve`s, and on
wakeup the parent resumes from the syscall instruction with its own
`user_entry_rsp` intact.  The `[VFORK/CANARY] pre_block.clone` and
`post_wake.clone` lines confirm `user_rsp=0x7ffffffec708` is identical
before and after, and the contents at `[user_rsp + 0x1d58]` are bit-equal
(`s_1d58=0x7ffffffee4c0` in both).

So the canary slot was **not corrupted during the vfork window**.  The
D21 DR fires at `linear=0x7ffffffee458` happen *after* the parent has
resumed and is unwinding its own SSP-instrumented frames — those writes
are legitimate pops/pushes on the parent's own stack at addresses the
parent's own prologue saved values to.  D21's invariant ("any user-VA
write at the watched address is a corruption") is too strict for a
post-vfork return path: the parent's normal epilogue *does* write into
the saved-canary slot as part of restoring the frame.

The actual divergence vs Linux is downstream: the `mov %fs:0x28, %rdx`
load that musl's SSP epilogue performs at `<ld-musl base>+0x1c7e8`
returns a value that does not match the canary slot the prologue saved.
That can be:

- (a) `%fs:0x28` (the TCB SSP master canary) was changed across the
  vfork window — captured `[VFORK/CANARY]` lines show
  `fs_28=0x9705bb7d37470085` in both `pre_block.clone` and
  `post_wake.clone`, so this is **rejected**;
- (b) the slot the prologue saved to was *different* from the slot the
  epilogue reads from (frame-identity mismatch — same shape as the F3
  saga close v2 in `[[project_f3_saga_CLOSED_v2_2026_05_21]]`);
- (c) the parent's `[user_rsp]` itself is wrong on return — i.e. the
  syscall return path restored a stale RSP, causing the epilogue to
  read the canary from a different slot than the prologue wrote it
  to.  This is the most consistent shape with the evidence: the
  `[VFORK/CANARY]` `user_rsp=0x7ffffffec708` is the value at *kernel-stack
  TF save*, not the value the user code actually returns to; if the kernel's
  `iretq` frame for vfork-return has a different RSP, the parent would
  resume on a "shifted" frame and its epilogue would consult the wrong
  slot.

## 4. Recommended fix shape

**The gate at `syscall.rs:2341` is correct as written.** Do not widen it
to `new_stack == 0` callers (which would be unnecessary — B1 is rejected),
and do not rework `find_free_stack_range` (B2 is rejected — the allocator
succeeded).

The actual fix-shape recommendation is **a dispatch one level higher**:

> Investigate the parent's vfork-return RSP/RBP identity.  Compare the
> `[VFORK/CANARY] pre_block.clone user_rsp=…` value to the actual
> `[iretq]` frame the kernel pushes for vfork-return.  If they differ,
> the parent resumes on a stack frame whose offsets do not align with
> what its SSP prologue saved.  Candidate locations:
>
> - `kernel/src/subsys/linux/syscall.rs` — the vfork wake path: confirm
>   `parent.user_entry_rsp` and the iretq RSP are derived from the same
>   `read_fork_user_regs()` snapshot captured BEFORE the child ran.
> - `kernel/src/proc/mod.rs` — `wake_vfork_parent()`: confirm it does
>   not overwrite or relocate the parent's saved-syscall-frame on the
>   kernel stack.
> - `kernel/src/proc/usermode.rs` — the syscall-return path that
>   restores user state from the saved frame: confirm RSP is restored
>   from the SAME slot it was saved into.

The right dispatch agent is **`aether-kernel-engineer`** (the parent's
return-from-syscall path is a native kernel primitive, not an ABI
translation), with `principal-systems-engineer` as a cross-walk reviewer
because the symptom spans subsystems (`syscall.rs` ↔ `usermode.rs` ↔ the
SSP runtime in musl, which we cannot patch per the
*never edit upstream binaries* invariant).

If the parent-return RSP audit comes back clean, the fallback hypothesis
is shape (b) — frame-identity mismatch in the SSP-instrumented caller of
vfork itself.  That maps to the F3 saga close v2 pattern (per
`[[project_f3_saga_CLOSED_v2_2026_05_21]]`) and would re-open the F3
axis at a deeper layer.

## 5. Cross-process safety

Since the recommended fix shape **does not touch the substitution gate
or the allocator**, the question of cross-process safety for non-vfork
`CLONE_VM` callers (e.g. pthread create at `syscall.rs:2239`) does not
arise.  Specifically:

- `pthread_create` clones take the `CLONE_THREAD | CLONE_VM` arm
  (`syscall.rs:2239`), not the vfork arm; `alloc_vfork_child_stack` is
  not on that path.
- The vfork arm itself remains unchanged, so all `CLONE_VM` without
  `CLONE_THREAD` callers (the genuine vfork/posix_spawn shape) continue
  to receive the isolated stack VMA exactly as today.
- The DR-watchpoint diagnostic remains a debug feature gated behind
  `--features d21-user-canary-watch` and does not affect production
  control flow.

The vfork-return-RSP audit dispatched per §4 will, by construction, only
touch the parent's wake path, which is invoked exclusively from the
vfork code path.  pthread, posix_spawn, glibc fork, and clone3() siblings
do not pass through `wake_vfork_parent()`.

## 6. References

- POSIX.1-2017 `clone(2)`, `vfork(2)`, `vfork(3p)` — child & parent
  stack/VM sharing semantics, parent-suspend contract.
- SysV AMD64 ABI 1.0 §3.2.2 — stack alignment, SSP frame layout.
- Intel SDM Vol. 2A — `HLT` from CPL > 0 raises `#GP(0)`.
- Intel SDM Vol. 3B §17.2.4 — DR0–DR3 linear-address watchpoint
  semantics; firing CPU matches CR3 of the resolving translation.
- musl.libc.org — `__stack_chk_fail` is `noreturn`, implemented as
  `hlt; ret`.
- ELF gABI §6 — SSP canary placement.
- `kernel/src/subsys/linux/syscall.rs:2295–2376` — `CLONE_VM` arm +
  substitution gate.
- `kernel/src/proc/mod.rs:3192–3328` — `alloc_vfork_child_stack`.
- `kernel/src/mm/vma.rs:1082–1118` — `find_free_stack_range`.
- `kernel/src/mm/vma.rs:393–394` — `STACK_ASLR_MIN`, `STACK_ASLR_MAX`.
- PR #404 (D21 DR-watchpoint, merged d71a3b1).
- PR #405 (tech-lead cross-walk, open).
- PR #398 (PID 1 exit_group(-13) = `__stack_chk_fail` #GP).
- `docs/PID1_EXIT_GROUP_NEG13_INVESTIGATION_2026-05-23.md` — orthogonal
  evidence of the same musl SSP fault.
