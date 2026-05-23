# Parent vfork-return RSP/RBP identity audit (Wave 12)

**Date:** 2026-05-23. **Read-only.** Inputs: PR #404 (D21 DR-watch), PR
#405 (tech-lead cross-walk), PR #406 (abi-compat B1/B2 rejection +
refined hypothesis).

## TL;DR

**None of A/B/C in literal form fires; the actual mechanism is _D — SSP
frame-identity mismatch via phys-aliasing on the parent's post-vfork
stack expansion_.** The kernel's parent vfork-return RSP path is
single-store / single-read and bit-stable: PR #406 already confirmed
`s_1d58=0x7ffffffee4c0` is bit-equal across `pre_block.clone`/
`post_wake.clone`, and the D21 fires at `0x7ffffffee458` (`-0x68` from
`s_1d58`) occur in **a different libxul frame** established **after**
the parent resumes from `vfork(2)`. With `fs:0x28` `__stack_chk_guard`
stable across the window, the only way for the epilogue compare against
`[rbp-8]` to fail is if the prologue store and epilogue load resolve
to **different physical pages** for the same linear VA — phys-aliasing,
same axis as PR #248's W215 H3a/H3b channel.

## AstryxOS source path (parent: vfork-syscall → SYSRET)

| Step | File:line | What it does |
|---|---|---|
| Save user-RSP | `kernel/src/syscall/mod.rs:846,852` | `mov gs:[8], rsp` then `push qword ptr gs:[8]` — frame slot 14 (the only authoritative copy SYSRETQ reads). |
| Frame snapshot | `kernel/src/syscall/mod.rs:897` | `mov gs:[24], rsp` records `frame_rsp` (diagnostic). |
| PRE snapshot | `kernel/src/subsys/linux/syscall.rs:2439` | `vfork_canary_snapshot("pre_block.clone", …)` reads frame slot 14 via `vfork_diag::get_parent_user_rsp_rbp` (`vfork_diag.rs:357`, `kstack_top - 8`). |
| Block | `kernel/src/subsys/linux/syscall.rs:2432,2485` | parent → `Blocked`, then `crate::sched::schedule()`. |
| Context switch | `kernel/src/proc/thread.rs:55-110` | `switch_context_asm` push/pop is `rbp,rbx,r12-r15,RFLAGS` (7 qwords) **below** current RSP. Syscall-frame slots untouched. |
| Wake | `kernel/src/syscall/mod.rs:1626-1647` | `wake_vfork_parent` only writes `p.state = Ready` (line 1643). No touch to `t.user_entry_rsp`, no touch to parent kstack. |
| POST snapshot | `kernel/src/subsys/linux/syscall.rs:2508` | `post_wake.clone` reads same slot 14. |
| Signal check | `kernel/src/signal.rs:944` | `*frame.add(15) = new_rsp` — IS a write to slot 14, but only when a non-default handler is being delivered (would route into handler, not back to caller). |
| Restore + SYSRETQ | `kernel/src/syscall/mod.rs:960` | `pop rsp` reads slot 14. |

`user_mode_bootstrap` (`kernel/src/proc/usermode.rs:313`) reads
`t.user_entry_rsp` only on **first-run** trampoline; the parent of a
vfork returns through `syscall_entry`, never through bootstrap.
`t.user_entry_rsp` is irrelevant to the parent's vfork-wake SYSRET.

`sys_exec` (`kernel/src/syscall/mod.rs:1603-1613`) rewrites
`kstack_top - 8` of the **child's** stack, never the parent's.

## Mechanism analysis

**A — frame-restore misalignment:** rejected. Both push/pop pairs in
`switch_context_asm` (`proc/thread.rs:55-110`) and `syscall_entry`
(`syscall/mod.rs:846-960`) are byte-symmetric.

**B — two stores diverge:** rejected. `wake_vfork_parent`
(`syscall/mod.rs:1628`) mutates only `state`. The Thread-struct
`user_entry_rsp` field (`proc/mod.rs:186`) is read by first-run paths
only — never by the vfork-wake return path.

**C — signal-frame return modifies RSP:** rejected for this axis. PR
#398's `#GP(0)` is at `ld-musl+0x1c7f9` on the **parent's own** code,
not inside any handler; if `signal.rs:944` had fired, the parent would
resume at `handler_addr` instead.

**D — SSP frame-identity mismatch (the actual divergence):** the failing
`mov rax, fs:0x28 ; cmp [rbp-8], rax` (SysV AMD64 ABI §3.4.5.2) is in
**a frame established AFTER `schedule()` returns** — the libxul
`posix_spawn` epilogue's caller. D21's user-VA DR caught that fresh
frame's _prologue store_ (a legitimate write per
`d21_user_canary_watch.rs:91-98`). With both `fs:0x28` and the snapshot
slot stable, the failing epilogue must be reading from a **different
phys page** than the prologue wrote — phys-aliasing on the linear VA.

**Candidate AstryxOS surfaces that could host the aliasing:**

- `kernel/src/mm/vmm.rs` page-fault-on-demand-paging for the parent's
  post-vfork stack expansion (`[rbp-8]` straddling a page boundary
  where page 2 is demand-faulted between prologue and epilogue).
- `kernel/src/proc/mod.rs:1399-1495` (`vfork_isolated_stack_cleanup` /
  `vfork_isolated_tls_cleanup`) — child-VMA teardown. If the freed
  phys frames are re-handed by the PMM to the parent's stack-expansion
  fault during the same window, the parent's prologue and epilogue see
  different phys for the same VA. Same class as PR #248's H3a/H3b.
- `kernel/src/mm/tlb.rs` — TLB stale entry on the prologue's writable
  cache-alias path (W215 catalog, PR #248).

## Recommended fix shape

**No fix yet.** Next dispatch should add a **PHYS_OFF channel** to D21
(complementary to the linear-VA arm, mirroring D16's two-channel shape
per `d16_canary_watch.rs`). Arm it at `pre_block.clone` against the
phys frame backing the candidate canary slot; emit on any phys writer
through the `[FAULT/PHYS/PFH]` channel introduced by PR #248. If the
prologue and epilogue resolve to distinct phys, the next dispatch has
a writer-named root cause and a ~30-80 LOC fix in `mm/vmm.rs` PFH for
the parent's stack-expansion arm.

**Defensive sideline (~10 LOC, optional):** `debug_assert!` in
`signal_check_on_syscall_return` (`signal.rs:944`) that frame[15]
matches the snapshot for vfork-window resumers — catches Mechanism C
if it ever re-emerges.

## Refs

SysV AMD64 ABI 1.0 §3.2.2, §3.4.5.2, §6.4; POSIX.1-2017 `vfork(2)`,
`clone(2)`; Intel SDM Vol. 2B `SYSCALL`/`SYSRETQ`; Intel SDM Vol. 2A
`HLT`; Intel SDM Vol. 3A §3.4.4.1, §6; Intel SDM Vol. 3B §17.2.4,
§17.3.1.1; ELF gABI §6; musl.libc.org `__stack_chk_fail`
(`hlt;ret`). Cross-refs: PR #404, #405, #406, #248, #398.
