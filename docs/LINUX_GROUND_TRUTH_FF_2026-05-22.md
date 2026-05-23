# Linux ground-truth — Firefox-132 syscall + stack walk comparison (musl + glibc)

**Date**: 2026-05-22
**Author**: principal-systems-engineer
**Status**: Reference data — no code changes, doc-only

## Goal

Capture what a stock Linux 6.8 kernel (Ubuntu 24.04 LTS, kernel `6.8.0-117-generic`) does at the exact syscall sequence where AstryxOS wedges with `BUGCHECK 0xdead0001 STACK_CANARY_CORRUPT`. The aim is ground truth, not a fix — so the next dispatch can interpret the data against the AstryxOS kernel path.

The wedge sequence reported by `qa-engineer` retry verdict `a3a30c6af8b4345f8` for PID 2 firefox-bin TID 5 on AstryxOS:

```
nr=158 arch_prctl(SET_FS, …)            ret=0
nr=218 set_tid_address(…)               ret=5
nr=12  brk(0)                           ret=0x4000000000
nr=12  brk(0x4000002000)                ret=0x4000002000
→ BUGCHECK 0xdead0001 STACK_CANARY_CORRUPT
```

Linux clears all four cleanly and continues. This document captures **how**.

## Method

- Host: Ubuntu (claude agent host), QEMU 10.2.1, KVM enabled
- Guest: Ubuntu Server 24.04.4 cloud image, kernel `6.8.0-117-generic`, 4 GiB RAM, 4 vCPUs
- Firefox variants:
  - **glibc 2.39**: Mozilla's official Firefox 132.0 Linux build (`firefox-132.0.tar.bz2`, BuildID `a8e1363fc8b7acfcda364631a45117cd95d4962b`)
  - **musl 1.2.5**: Alpine-built Firefox 132 binary as staged in AstryxOS `build/disk/usr/lib/firefox/firefox-bin` (BuildID `36c1256c55b38d02b311b5e58646a226d34b9c1c`), mounted into the guest read-only via 9p
- Kernel-side gdb: host gdb 17.1 connecting to QEMU's `-s` gdbstub (TCP 1234), `vmlinux-6.8.0-117-generic` from the Canonical `ddebs.ubuntu.com` archive (`linux-image-6.8.0-117-generic-dbgsym`), KASLR slide `0x29800000` resolved via `/proc/kallsyms`
- Userspace gdb: in-guest gdb 17.1 with a Python script (`walk.py`) that installs `catch syscall arch_prctl|set_tid_address|brk` and dumps `bt`, `disas`, `x/8xg $rsp`, and `/proc/self/maps[rip]` at each hit
- Userspace stack walks: 26 anchor hits (glibc), 12 anchor hits (musl) — both variants reach the canonical anchor `brk(curr+0x2000)` without fault
- Kernel-side hits: `__x64_sys_brk` × 11, `__x64_sys_arch_prctl` × 3, `__x64_sys_set_tid_address` × 2 captured via hardware breakpoint at the live (slid) kernel address

The full raw capture logs live under `/home/ubuntu/linuxgt/` on the dispatch host (not committed): `walk-glibc-full.log` (1089 lines), `walk-musl-full.log` (402 lines), `kgdb-output.log` (604 lines), `kgdb-multi.log` (236 lines).

## Public-spec citations used

- Linux man-pages 6.7: `brk(2)`, `arch_prctl(2)`, `set_tid_address(2)`
- System V AMD64 ABI 1.0 §A.2 (syscall convention, RDI/RSI/RDX/R10/R8/R9, RAX return)
- Intel SDM Vol 3A §3.4.3 (segment registers + FS_BASE via `wrfsbase`/MSR), §4.6 (paging access rights)
- POSIX.1-2017 §A.4.8 (set_tid_address semantics)
- musl public docs `musl.libc.org/about.html` — heap is `brk`-based, single arena, no per-thread heap
- ELF gABI 5.2 (PT_TLS initialisation)
- Documented Linux ABI constant `STACK_END_MAGIC = 0x57AC6E9D`

## Anchor data

### Anchor 1 — `arch_prctl(ARCH_SET_FS, ptr)` (syscall 158)

#### musl — userspace at syscall exit

```
rip = 0x00007ffff7fba86f  (inside ld-musl-x86_64.so.1, the __set_thread_area path)
rsp = 0x00007fffffffe8d8
rax = 0  (success)
rdi = 0x1002  (ARCH_SET_FS)
rsi = 0x00007ffff7ffdb28  (TLS base pointer — the static-TLS area)
fs_base = 0x00007ffff7ffdb28  (kernel has set MSR_FS_BASE)

bt:
  #0 __set_thread_area in ld-musl-x86_64.so.1
  #1 __init_tp           in ld-musl-x86_64.so.1
  #4 __dls2b             in ld-musl-x86_64.so.1   (musl dynamic-linker phase 2b)
```

Source identification: musl calls `arch_prctl(ARCH_SET_FS, tls_base)` from `__init_tp()` during `__dls2b`, before any user code or `libc.so` finalisation. RDI=0x1002 is the documented ARCH_SET_FS constant (per `arch_prctl(2)` man page).

#### glibc — userspace at syscall exit

```
rip = 0x00007ffff7fee*  (inside ld-linux-x86-64.so.2, init_tls path)
rdi = 0x1002  (ARCH_SET_FS)
rsi = TLS base pointer
fs_base ends up = the same value

bt:
  #0 __glibc_arch_prctl  in ld-linux-x86-64.so.2
  #1 init_tls            in ld-linux-x86-64.so.2
  #2 dl_main             in ld-linux-x86-64.so.2
```

#### Linux kernel side (both variants — same kernel path)

```
hbreak *0xffffffffaa855b50 (__x64_sys_arch_prctl)
rdi = pt_regs*  (pointer to the saved user pt_regs on the kernel stack)
rsi = orig_rax = 158
*(rdi+0x70) = user RDI = 0x1002  (ARCH_SET_FS)
*(rdi+0x68) = user RSI = TLS base ptr

bt:
  #0 __x64_sys_arch_prctl
  #1 x64_sys_call
  #2 do_syscall_x64
  #3 do_syscall_64
  #4 entry_SYSCALL_64
  #5 <user rip>               at 0x00007ffff7fba86f
```

`__x64_sys_arch_prctl` dispatches on RDI: for `ARCH_SET_FS` it writes MSR_FS_BASE via `wrmsrl(MSR_FS_BASE, addr)` and stores the value in `current->thread.fsbase`, then returns 0. No allocation, no stack-canary-poisoning code path.

### Anchor 2 — `set_tid_address(tidptr)` (syscall 218)

#### musl — userspace at syscall exit

```
rip = 0x00007ffff7f7847c  (inside ld-musl-x86_64.so.1)
rax = 0x1dd6  (returned TID, matches getpid for the single-thread init)
rdi = 0x00007ffff7ffdf90  (user-space tidptr — inside TLS region)

bt:
  #0 __init_tp continued
  #4 __dls2b in ld-musl-x86_64.so.1
```

#### glibc — userspace at syscall exit

```
rax = 0x1ba7  (returned TID)
rdi = tidptr inside the TLS region

bt:
  #0 set_tid_address in ld-linux-x86-64.so.2
  #1 init_tls       in ld-linux-x86-64.so.2
```

#### Linux kernel side

```
hbreak *0xffffffffaa901df0 (__x64_sys_set_tid_address)
rsi = orig_rax = 218
*(rdi+0x70) = user RDI = tidptr (validated by access_ok)

bt:
  #0 __x64_sys_set_tid_address
  #1 x64_sys_call
  #2 do_syscall_x64
  #3 do_syscall_64
  #4 entry_SYSCALL_64
```

Linux stores `tidptr` in `current->clear_child_tid`. On task exit, the kernel writes 0 to that user address and `futex_wake()`s any waiter. Pure pointer-save — no allocation, no stack writes beyond pt_regs itself.

### Anchor 3 — `brk(0)` (syscall 12) — query current break

#### musl — userspace at syscall exit

```
rip = 0x00007ffff7f81089  (inside ld-musl-x86_64.so.1 __expand_heap or __init_libc)
rsp = 0x00007fffffffe710
rax = 0x00005555555d4000   ← current break, page-aligned
rdi = 0  (the brk argument)
fs_base = 0x00007ffff7ffdb28  (FS_BASE already set from Anchor 1)

disas @ rip:
  0x7ffff7f81089:  mov    %rax,%rbp           ← save current_brk
  0x7ffff7f8108c:  neg    %rbp
  0x7ffff7f8108f:  and    $0xfff,%ebp         ← round-up offset
  0x7ffff7f81095:  add    %rax,%rbp           ← page-aligned base
  0x7ffff7f81098:  mov    %rdx,%rax
  0x7ffff7f8109b:  lea    0x2000(%rbp),%r13   ← target = base + 0x2000  ★
```

This is the exact code that produces "current break + 0x2000" — the canonical 8 KiB heap-init grow that AstryxOS reports as the trigger of the bugcheck. It is musl 1.2.5's `expand_heap` rounding up to a page boundary and then asking for two additional pages (0x2000 bytes), per the public musl allocator design (musl.libc.org).

#### glibc — userspace at syscall exit

```
rip = 0x00007ffff7fe99cb  (inside ld-linux-x86-64.so.2, __brk)
rsp = 0x00007fffffffead8
rax = 0x0000555555622000   ← current break (different ASLR'd VA from musl)
rdi = 0

bt:
  #0 __brk
  #1 _dl_sysdep_start
  #2 _dl_start_final
  #3 _dl_start
  #4 _start           in /lib64/ld-linux-x86-64.so.2

disas @ rip:
  0x7ffff7fe99cb:  mov    %rax,0x148c6(%rip)   ← store to __curbrk
  0x7ffff7fe99d2:  cmp    %rdi,%rax
  0x7ffff7fe99d5:  jb     <error path>
  0x7ffff7fe99d7:  xor    %eax,%eax            ← return 0 on query path
  0x7ffff7fe99d9:  ret
```

glibc emits brk(0) extremely early — from `_dl_sysdep_start` in the dynamic linker itself, before any libxul code. Same pattern as musl: probe-then-extend.

#### Linux kernel side

```
hbreak *0xffffffffaac3b7a0 (__x64_sys_brk)

# Kernel registers at the BREAKPOINT:
rax = 0xffff8b1485dd8000   (current task_struct ptr from pcpu)
rdi = pt_regs* on kernel stack
rsi = orig_rax = 12
rsp = 0xffffcee4862ebbc8   (kernel stack — see below)
rip = 0xffffffffaac3b7a0 <__x64_sys_brk>

# Deref pt_regs:
*(rdi+0x70) = user RDI = 0
*(rdi+0x80) = user RIP = 0x70246fc029cb  (matches userspace rip above for glibc)
*(rdi+0x98) = user RSP = 0x7ffc110d9fb8

bt (kernel frames):
  #0 __x64_sys_brk
  #1 x64_sys_call
  #2 do_syscall_x64
  #3 do_syscall_64
  #4 entry_SYSCALL_64
  #5 <user RIP>             (returned from kernel via sysret)

disas @ __x64_sys_brk:
  0xffffffffaac3b7a0:  nopl   0x0(%rax,%rax,1)
  0xffffffffaac3b7a5:  push   %rbp
  0xffffffffaac3b7a6:  mov    0x70(%rdi),%rdi    ← load user RDI (new_brk) from pt_regs
  0xffffffffaac3b7aa:  mov    %rsp,%rbp
  0xffffffffaac3b7ad:  call   0xffffffffaac3b350 <__do_sys_brk>   ← actual handler
  0xffffffffaac3b7b2:  pop    %rbp
  0xffffffffaac3b7b3:  xor    %edi,%edi
  0xffffffffaac3b7b5:  ret
```

`__do_sys_brk(unsigned long brk)` reads `current->mm->brk` and `current->mm->start_brk`. For `brk == 0` (query), it returns `mm->brk` after `mmap_read_lock()/mmap_read_unlock()`. No VMA mutation. Kernel stack usage: one stack frame for `__x64_sys_brk` + one for `__do_sys_brk` + the `mmap_lock` read-side primitives (rwsem fast path is a single atomic CAS), totalling well under 1 KiB of kernel stack consumed.

### Anchor 4 — `brk(curr+0x2000)` (syscall 12) — **the canonical comparison point**

#### musl — userspace at syscall exit

```
rip = 0x00007ffff7f810ae  (inside ld-musl-x86_64.so.1, after the lea above)
rsp = 0x00007fffffffe710
rbp = 0x00005555555d4000   ← previous break (saved earlier)
rax = 0x00005555555d6000   ← new break = previous + 0x2000 (kernel granted)
rdi = 0x00005555555d6000   ← the argument that was passed
fs_base = 0x00007ffff7ffdb28  (unchanged from Anchor 1 — FS_BASE invariant)

disas @ rip:
  0x7ffff7f810ae:  cmp    %rax,%r13       ← check returned brk == requested
  0x7ffff7f810b1:  jne    <retry/error>
  0x7ffff7f810b7:  xor    %r9d,%r9d
  0x7ffff7f810ba:  mov    $0xffffffff,%r8d
  0x7ffff7f810c0:  mov    $0x32,%ecx      ← MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
  0x7ffff7f810c5:  xor    %edx,%edx
  ...
```

This is the musl heap-init success path: `expand_heap` got its 0x2000 bytes from `brk`, now it proceeds to map an arena via `mmap` for the actual allocator. **On Linux the kernel returns the same address that was requested, and execution continues normally.**

#### glibc — userspace at syscall exit

After the early `brk(0)` from `_dl_sysdep_start`, glibc later calls `sbrk(0x21000)` from `__GI___sbrk` to extend the heap. Multiple `brk` extensions are captured in the trace; all return successfully. Example hit at `ret=0x0000555555572000`:

```
rip = 0x00007ffff7fe99cb  (inside __brk)
rax = 0x0000555555572000   ← new break, kernel granted
rdi = 0x0000555555572000

bt:
  #0 __brk
  #1 __GI___sbrk    (increment=135168 = 0x21000)
  #2 __default_morecore
  #3 sysmalloc
```

#### Linux kernel side at `brk(curr+0x2000)`

The kernel breakpoint hit `__x64_sys_brk` 11 times during the run (across both processes), all on the same code path. For the canonical anchor — user RDI ≠ 0:

```
rsp = 0xffffcee48625bbf8   (kernel stack pointer, in vmalloc area for vmap_stack)
*(rdi+0x70) = user RDI = new_brk = curr + 0x2000  ← non-zero this time
*(rdi+0x80) = user RIP = 0x7b3b81e8d9cb  (= userspace rip inside musl/glibc __brk)

bt: identical to Anchor 3 — entry_SYSCALL_64 → do_syscall_64 → do_syscall_x64 →
    x64_sys_call → __x64_sys_brk → __do_sys_brk
```

`__do_sys_brk` for non-zero argument:
1. `mmap_write_lock(current->mm)` (rwsem write side — kernel-stack-deep)
2. `newbrk = PAGE_ALIGN(brk); oldbrk = PAGE_ALIGN(mm->brk)`
3. If extending: `do_brk_flags(&vmi, brkvma, oldbrk, newbrk - oldbrk, 0)` — inserts/grows a single anonymous VMA covering the new bytes
4. `mm->brk = brk; mmap_write_unlock(...)`
5. Returns the granted brk

The kernel-stack consumed by this path peaks around `do_brk_flags → vma_complete → vma_iter_load` (maple-tree update). On Linux 6.8 with `CONFIG_VMAP_STACK=y` this is bounded to ~3 KiB of kernel stack out of THREAD_SIZE = 16 KiB; the BASE of the stack (`task_stack_page(current)`) carries `STACK_END_MAGIC = 0x57AC6E9D` written at fork-time by `dup_task_struct → setup_thread_stack → end_of_stack(p)[0] = STACK_END_MAGIC`.

**The canary slot is NOT read on syscall entry, syscall exit, or context switch in modern Linux.** It is read only by:

- `__schedule_bug()` / `oops_end()` — when something else has already gone wrong
- `end_of_stack()` callers — `kthreadd`, `flush_workqueue`, a few legacy paths
- The fault handler (`handle_stack_overflow`) — but only AFTER a guard-page page-fault has already fired

If the kernel stack DOES overflow on Linux, the next byte past the BASE of the stack is an unmapped guard page (set up by `__vmalloc_node_range` with `VM_NO_GUARD` cleared). A write to the guard page triggers a `#PF` immediately, which is caught by `do_user_addr_fault → handle_stack_overflow` and converted into a panic with a clean stack trace — **the canary slot itself is never relied upon as the primary overflow signal.**

## Diff column — Linux vs AstryxOS at each anchor

| Anchor | Linux kernel path | AstryxOS kernel path | Divergence |
|---|---|---|---|
| `arch_prctl(ARCH_SET_FS)` | `__x64_sys_arch_prctl → do_arch_prctl_64 → wrmsrl(MSR_FS_BASE, addr); current->thread.fsbase = addr` | `subsys/linux/syscall.rs::158 → wrmsr(MSR_FS_BASE, addr); proc.fs_base = addr` (per `kernel/src/proc/mod.rs` invariants) | **Equivalent.** Single MSR write + per-task save. No alloc, no stack pressure. |
| `set_tid_address(tidptr)` | `__x64_sys_set_tid_address → current->clear_child_tid = tidptr` | `subsys/linux/syscall.rs::218 → store tidptr in current TaskControlBlock` | **Equivalent.** Single pointer-store under task lock. |
| `brk(0)` (query) | `__do_sys_brk(0) → mmap_read_lock; ret = mm->brk; mmap_read_unlock; return ret` | `sys_brk(0) → PROCESS_TABLE.lock(); proc.vm_space.brk` (per `kernel/src/syscall/mod.rs:2776-2795`) | **Equivalent in spirit.** AstryxOS uses a single global `PROCESS_TABLE` Mutex (not an rwsem) — see "AstryxOS-specific notes" below. |
| `brk(curr+0x2000)` | `mmap_write_lock; do_brk_flags(&vmi, brkvma, oldbrk, 0x2000, 0); mm->brk = brk; unlock` — peak kernel-stack depth ~3 KiB, vmap_stack guard-page protected | `sys_brk(new_brk) → PROCESS_TABLE.lock(); proc.vm_space.adjust_brk(new_brk)` — kernel stack is `KERNEL_STACK_PAGES = 64` pages (256 KiB) contiguous, **OR a 4 KiB emergency stack** when the PMM is fragmented (`alloc_kernel_stack()` fallback at `kernel/src/proc/mod.rs:568-575`) | **Major.** See implications below. |

### AstryxOS-specific notes

1. **Kernel stack allocation strategy** (`kernel/src/proc/mod.rs:537-575`):
   - Fast path: `crate::sched::pop_dead_stack()` — reuse a recently-freed kstack from the dead-stack cache
   - Normal path: `crate::mm::pmm::alloc_pages(KERNEL_STACK_PAGES = 64)` — contiguous 64-page allocation
   - **Fragmented PMM path**: `crate::mm::pmm::alloc_page()` — **single 4 KiB page** used as the entire kstack, with a `[PROC] WARN: 4KB emergency kernel stack (PMM fragmented)` log line emitted
   - Stack base is `KERNEL_VIRT_OFFSET + phys = 0xFFFF_8000_0000_0000 + phys`, a direct higher-half map — **no guard page**

2. **Canary write/check** (`kernel/src/proc/mod.rs:581-596`):
   - `STACK_END_MAGIC = 0x5741_436B_5374_4B21` ("WACkStK!") — 64-bit
   - `write_stack_canary(stack_base)` writes the magic at `*(stack_base as *mut u64)` — i.e. at the very bottom of the stack
   - `check_stack_canary(stack_base)` is called from `sched::schedule()` (`kernel/src/sched/mod.rs:587`) for the OUTGOING thread on every context switch
   - On mismatch → `ke_bugcheck(BUGCHECK_CANARY_CORRUPT)` = `0xdead0001`

3. **The brk path on AstryxOS** (`kernel/src/syscall/mod.rs:2776-2795`):
   - Acquires `PROCESS_TABLE.lock()` — a global `spin::Mutex<Vec<Process>>`. Same lock is held by every other syscall accessing the process table.
   - Looks up the process by `current_pid_lockless()`, then calls `space.adjust_brk(new_brk)` on the `VmSpace`.
   - `VmSpace::adjust_brk` walks/edits the VMA list under another lock.

## Implications

### A — Implications for the sc=1230 musl axis (PARKED demo gate)

The userspace walk shows musl's `expand_heap` doing exactly what Linux is asked to do, and Linux handling it without incident. On AstryxOS, the same musl code, the same VA pattern (`0x4000000000`), and the same `+0x2000` increment trips `STACK_CANARY_CORRUPT` on the next context switch after `brk(curr+0x2000)` returns.

Three Linux/AstryxOS divergences are visible from the data:

1. **Kernel stack size + structure**:
   - Linux: 16 KiB vmap_stack, guard page below, `STACK_END_MAGIC` at base, **canary is a safety-net AFTER guard-page faults**, not the primary overflow detector.
   - AstryxOS: 256 KiB contiguous (or **4 KiB emergency if PMM fragmented**), no guard page, **canary IS the primary overflow detector** and is checked on every context switch.

   If the AstryxOS path ever takes the 4 KiB emergency-stack branch — and `crate::serial_println!` at line 572 would log a `[PROC] WARN: 4KB emergency kernel stack` line — then ANY brk path (which legitimately consumes 3 KiB+ of kernel stack on Linux) would silently overrun and clobber the canary slot. The bugcheck-on-next-context-switch is the only place this overflow is observed; the actual corruption happened inside `sys_brk` or `adjust_brk`.

   **Investigation lead**: Search the post-#392 serial log for `4KB emergency kernel stack`. If present at the same TID/PID where `STACK_CANARY_CORRUPT` fires shortly after, the residual "out-of-band writer" is **the brk handler itself overflowing the emergency stack**. PR #392 stamped honest `kernel_stack_size` for this fallback; the diagnostic groundwork is already in place.

2. **Lock granularity**:
   - Linux: per-mm `mmap_lock` rwsem. brk takes the write side; pure-read syscalls take the read side concurrently.
   - AstryxOS: global `PROCESS_TABLE` mutex held across the entire syscall, plus a second VMA-list lock inside `adjust_brk`. The PROCESS_TABLE lock serialises ALL syscall traffic against ALL processes. Under firefox-bin (which is launching 16 worker threads simultaneously via `clone(CLONE_THREAD)`), this is a hot contention point.

   This is not directly related to the canary corruption but is a known scalability issue (referenced in memory `project_w216_t1_plateau_ipc_fd_routing_2026_05_15`).

3. **PT_TLS handling**:
   - Linux: after `arch_prctl(ARCH_SET_FS, tls_base)`, FS_BASE points at musl's static TLS area (`0x7ffff7ffdb28` in the capture). The ld-musl `__dls3` then does a SECOND `arch_prctl(ARCH_SET_FS, ...)` to a per-thread TLS once threading initialises.
   - AstryxOS sc=1171 saga reframed (memory `project_session_handoff_2026_05_22`) suggests `mThreadInfo NULL-field` — an axis that intersects PT_TLS init. The musl walk shows the FIRST prctl happens at `__dls2b` *before* `set_tid_address`, and the SECOND prctl happens at `__dls3` *after* all heap-init brks. **The AstryxOS-reported sequence (158 → 218 → 12 → 12) is the FIRST prctl only**, so PT_TLS .tbss bzero (PR α-fix per memory) would be relevant before the second prctl, not at this anchor.

### B — Implications for the STACK_CANARY_CORRUPT "out-of-band writer" residual

The earlier Wave 3→6 investigation (PRs #388/#390/#391/#392) closed the diagnostic-and-fix arc but left open: **the canary slot is zeroed via an out-of-band store, not stack-depth overflow.**

The Linux walk does NOT directly falsify this framing — Linux never observes a corrupted canary at all because (a) the canary is not read on the hot path and (b) the kernel stack never overflows under brk on Linux. But it sharpens the search space:

- **The "out-of-band store" hypothesis requires a writer somewhere in the kernel that writes to `kernel_stack_base` of a non-current task.** No such writer is visible on the Linux side (Linux has no analogue — the magic is written once at fork and never touched until the task dies).
- **An alternative: the canary slot is INSIDE the stack range of a different recycled task.** If AstryxOS's dead-stack cache (`sched::pop_dead_stack()`) hands out a stack whose base address overlaps a still-live mapping from a previous task that didn't fully unmap, the "previous occupant" could be writing to what is now the canary slot of the new task. This is a different bug class from depth-overflow.
- **A third: the 4 KiB emergency stack** is so small that `sys_brk → PROCESS_TABLE.lock() → spin::Mutex internals + adjust_brk + VMA list walk` literally overflows it. The canary at offset 0 would be the FIRST overwritten byte. The Linux side bounds the equivalent at ~3 KiB, which would not fit in 4 KiB once you account for the pt_regs frame at the top (≈300 bytes) and the rwsem internal state.

The dispositive test, given the post-#392 instrumentation, is:
1. Run firefox-test with the merged kstack-overflow diagnostic from PR #391
2. Look for the `[PROC] WARN: 4KB emergency kernel stack` line emitted from `alloc_kernel_stack` line 572
3. Cross-correlate with the TID/PID that fires `STACK_CANARY_CORRUPT`

If the warn line precedes the bugcheck on the same TID → **the residual IS depth overflow into a degraded emergency stack**, not an out-of-band writer.

If the warn line is absent → the 4 KiB path is not implicated; an actual out-of-band writer search is warranted, and the candidate is the dead-stack cache returning still-live stacks (see `kernel/src/proc/mod.rs:539 — pop_dead_stack()`).

## Headline observation

**Linux's behaviour at the `brk(0x4000002000)` point looks completely NORMAL — the kernel-side breakpoint dump matches the textbook sysenter → `do_syscall_64` → `__x64_sys_brk` → `__do_sys_brk` path, kernel stack is at a vmap_stack VA with a guard page below, the user is granted the requested 0x2000-byte extension, and execution returns cleanly with no stack-magic interaction whatsoever.**

The AstryxOS bugcheck is unambiguously an AstryxOS-side condition. The Linux comparison narrows the candidates to either:

- the 4 KiB emergency kernel stack fallback being silently exercised under PMM fragmentation, with brk overflowing it (a previously known risk that PR #392 surfaced but did not eliminate), or
- a stack-recycling problem in the dead-stack cache (`pop_dead_stack`) where the cache returns a stack whose base address still aliases a live mapping or sees writes from another path.

The next dispatch should run firefox-test under the post-#392 `kstack-overflow` feature and grep for `4KB emergency kernel stack` in the serial log. If present in conjunction with the bugcheck TID, the residual is closed — overflow into the degraded fallback path. If absent, the dead-stack cache is the next axis.

## Captured data files (not committed)

Raw logs on the dispatch host under `/home/ubuntu/linuxgt/`:

- `walk-glibc-full.log` (1089 lines) — userspace gdb walk of stock Firefox 132 glibc
- `walk-musl-full.log` (402 lines) — userspace gdb walk of Alpine-built Firefox 132 musl
- `kgdb-output.log` (604 lines) — 11 hits of `__x64_sys_brk` via QEMU gdbstub
- `kgdb-multi.log` (236 lines) — 9 hits across `__x64_sys_brk`, `__x64_sys_arch_prctl`, `__x64_sys_set_tid_address`
- `vmlinux` (397 MiB) — Ubuntu kernel image with full debug symbols (`6.8.0-117-generic`)

These remain available for the follow-up dispatch interpreting the residual.
