# PID 2 page-fault loop investigation (2026-05-17)

## TL;DR

**Verdict: H1 confirmed with a precise diagnosis.**  The "PID 2 in a heavy
page-fault loop at the sc=1423 plateau" symptom is a kernel-side SMAP fault
that the page-fault handler silently "resolves" by tweaking the PTE — but
the actual cause is EFLAGS.AC=0 inside a function-scope `UserGuard`, so on
IRET the same instruction re-faults, producing ~400 M page faults/sec until
the scheduler watchdog bugchecks (`BUGCHECK_SCHEDULER_DEADLOCK 0xDEAD_0004`).

**Root cause: `switch_context_asm` does not save/restore RFLAGS.**  A kernel
thread that holds a `UserGuard` (STAC issued → AC=1) and blocks on disk I/O
gets context-switched out via `schedule()`.  When it resumes — typically
seconds later, after another thread ran with AC=0 — its EFLAGS.AC is whatever
the previously-saved sibling had at its own suspend point (almost always 0).
The thread continues executing inside its original `UserGuard` scope, hits
the next user-pointer dereference, and faults.  The page-fault handler's CoW
arm "resolves" the fault by setting PTE.W (no-op — the bit was already set)
and shooting down TLB; IRET retries the same instruction with AC still 0;
fault loop.

**Fix shape (≤ 50 LOC):** add `pushfq` / `popfq` around the callee-save
window in `switch_context_asm`.  Also reserve one stack slot in the two
synthetic kernel-stack initialisers (`init_thread_stack`,
`init_fork_child_stack`) so freshly-scheduled threads pop a sane 0x202
prelude rather than uninitialised memory.

A defensive SMAP-fault detector in `idt::handle_page_fault` surfaces any
remaining unbracketed user dereference as a fast bugcheck instead of a
silent 400 M-fault retry storm — included in the fix commit because it
turned this 6-month-old W209 "Branch-A plateau" symptom into a 2-trial
RCA.

## Reproduction

Master tip `3d7389a` (PR #285), features `firefox-test,kdb,w215-diag`,
`scripts/qemu-harness.py start`, KVM (default).

Trial 1 (pre-fix, sid=`a641a1d77bf0`):

```
[PROC-METRICS] tick=11500 pid=2 name=/disk/opt/firefox/firefox-bin.vm \
    sc=13 (vm=2 file=6 net=0 sync=0 proc=3 sig=2 other=0) \
    pf=849187 disk=R40960/W0 net=R0/W0 cur_nr=0@165t
[PROC-METRICS] tick=12000 pid=2 … pf=4269615 … STUCK_IN_NR=0@665t
[PROC-METRICS] tick=12500 pid=2 … pf=7811388 … STUCK_IN_NR=0@1165t
…
[HB] tick=71500 cpu=1 pf=411425724 sc=1452
*** AETHER KERNEL BUGCHECK ***
  Code:   0xdead0004 (SCHEDULER_DEADLOCK)
  CPU:    1   TID: 5   PID: 2
  CR2:    0x00007ffffffedfe8
```

PID 2 made it through ~7 syscalls into glxtest startup, then `clone`-VM child
TID 5 began faulting at CR2=0x7FFF_FFFF_EDFE8 (high user stack, top of
`USER_STACK_TOP = 0x7FFF_FFFF_0000`).

`[PF/stat]` revealed the fault was a same-CR2 retry storm:

```
[PF/stat] total= 1000000 write= 998569 notpresent=1432 err_sample=0x3 cr2=0x7ffffffedfe8
[PF/stat] total= 2000000 write=1998569 notpresent=1432 err_sample=0x3 cr2=0x7ffffffedfe8
…
[PF/stat] total=21000000 write=20998569 notpresent=1432 err_sample=0x3 cr2=0x7ffffffedfe8
```

Bit-decode of `err_sample=0x3`:

| Bit | Meaning  | Value | Reading                                |
|----:|----------|-------|----------------------------------------|
| 0   | PRESENT  | 1     | PTE was present — not a demand fault   |
| 1   | WRITE    | 1     | Write access (not read, not ifetch)    |
| 2   | USER     | **0** | **Supervisor mode** (kernel was writing)|
| 4   | IFETCH   | 0     | Data access                            |

Supervisor write to a present user page is the SMAP signature (Intel SDM
Vol. 3A §4.6).

## RIP capture

Defensive detector inserted at the top of `handle_page_fault` (idt.rs)
isolated the fault before the CoW arm ran:

```
[SMAP/FAULT] supervisor access to user page cr2=0x7ffffffedfe8 \
    rip=0xffff800000226c53 code=0x3 pte=0x8000000026549067 cr3=0x26461000 \
    rflags=0x10202 cpu=1 pid=2 tid=5
[SMAP/FAULT/regs] rax=0x7ffffffedfe8 rcx=0x68 rdx=0x340 rsi=0xffff800000b1d360
[SMAP/FAULT/regs] rdi=0x7ffffffedfe8 r8=0 r9=0xff r10=0xc00
[SMAP/FAULT/regs] r11=0xff rbx=0xffff800009062c28 rbp=0x340 r12=0xffff800000b1d360
[SMAP/FAULT/regs] r13=2 r14=0xffff800000a0c5f8 r15=0x340 rsp=0xffff800009062af8
[SMAP/FAULT/stk] +0x00 0xffff800009062af8 = 0xffff8000001e34ad   ← memcpy ret addr
```

PTE decode `0x8000000026549067`:

| Bits   | Value             | Meaning                                      |
|--------|-------------------|----------------------------------------------|
| 63     | 1                 | NX (no-execute)                              |
| 12-51  | 0x26549           | physical frame address                       |
| 6 (D)  | 1                 | dirty                                        |
| 5 (A)  | 1                 | accessed                                     |
| 2 (U)  | 1                 | **user page** (SMAP-relevant)                |
| 1 (W)  | 1                 | writable                                     |
| 0 (P)  | 1                 | present                                      |

RFLAGS `0x10202`: bit 1 reserved (always 1), bit 9 (IF) = 1, **bit 18 (AC) = 0**.
Definitive SMAP fault.

Faulting RIP `0xffff800000226c53` lives inside `memcpy` (the compiler-builtins
`rep movsq` loop).  The return address on the kernel stack
(`0xffff8000001e34ad`) resolved to
`kernel::vfs::fat32::Fat32Fs::FileSystemOps::read`.

## Call chain

```
sys_read_linux(fd=N, buf=0x7ffffffedfe8, count=?)
└── vfs::fd_read(pid=2, fd_num=N, buf=0x7ffffffedfe8, count=?)
    ├── let _smap_g = UserGuard::new();   ← STAC issued (AC=1)
    ├── PROCESS_TABLE.lock() → drops
    ├── fs.read(inode, offset, &mut buffer)
    │   └── Fat32Fs::read(...)
    │       ├── inner.lock() → drops
    │       ├── device.read_sectors(...)  ← BLOCKING — schedule() may fire
    │       │   ↳ context-switched out, sibling runs with AC=0
    │       │   ↳ resumed; RFLAGS now has AC=0 (sibling's saved value)
    │       └── buf[written..].copy_from_slice(&run_buf[..]);  ← memcpy
    │           └── rep movsq  ← FAULT here (SMAP supervisor → user page)
    └── _smap_g drops → CLAC
```

The UserGuard outer scope is correct in principle (one bracket per syscall),
but the call-tree includes a guaranteed blocking point (disk read), and
EFLAGS.AC is per-CPU not per-thread.  The context switcher never preserved
it.

## Why the fault loop is invisible to existing handlers

`handle_page_fault`'s present+write arm (idt.rs:1000-1088) sees:

* `is_present=true, is_write=true` → enters CoW arm.
* `find_vma` returns the user-stack VMA (prot=RW).
* `read_pte` returns the present+writable PTE.
* `page_ref_count == 1` (the stack page is single-owner) → single-owner sub-arm.
* Single-owner sub-arm: `write_pte(cr3, page_addr, pte | PAGE_WRITABLE)` —
  no-op on this PTE — and `tlb::shootdown_page`.
* Returns `true` ("fault resolved").

The handler "fixes" the PTE that was already correct, IRETs back to the
`rep movsq` instruction, the CPU re-executes it with the same AC=0, the
fault re-fires.  RIP, CR2, and error_code are identical on every retry.

The scheduler watchdog (irq.rs:471) caps this at `WATCHDOG_LIMIT` ticks
on a single CPU without `schedule()` calls; once exceeded, the watchdog
fires `BUGCHECK_SCHEDULER_DEADLOCK 0xDEAD_0004` — which is the actual
"plateau wedge" reported by the PR #283 fix-it agent.

## Discrimination of the dispatched hypotheses

| Hyp | Verdict   | Evidence                                                   |
|----:|-----------|------------------------------------------------------------|
| H1  | **YES**   | err_code=0x3 (no USER bit) + AC=0 in RFLAGS + PTE.U=1 + same CR2 across 21 M faults |
| H2  | NO        | Page IS PRESENT in PTE; CoW arm runs and returns true; not a demand-paging miss |
| H3  | NO        | Real #PF firing 700 K/sec; not a userspace cpuid/TSC spin (RIP is in kernel-half) |
| H4  | NO        | PID 1's state is irrelevant; the SMAP fault is purely between kernel CPU1 and PID 2's user stack |

## Fix

Three coupled changes (PR `investigate/pid2-pf-loop`):

1. **`proc/thread.rs` — `switch_context_asm`** adds `pushfq` before the
   callee-save window and `popfq` after the RSP swap.  Cite Intel SDM
   Vol. 3A §4.6 (SMAP — STAC/CLAC are the only way to toggle AC; AC is
   in RFLAGS and must be saved/restored explicitly on any context switch
   that may span a STAC/CLAC bracket).

2. **`proc/thread.rs` — `init_thread_stack` / `init_fork_child_stack`**
   reserve one extra slot at the bottom of the synthetic switch frame and
   pre-fill it with `0x202` (IF=1, AC=0) so freshly-scheduled threads pop
   a sane RFLAGS prelude.  Without this, the first switch-into a new
   thread would `popfq` whatever garbage was on the freshly-allocated
   stack (typically zero, clearing IF and wedging the thread on the next
   CLI).

3. **`arch/x86_64/idt.rs` — SMAP-fault triage in `handle_page_fault`**.
   Before invoking the CoW / demand-paging arms, detect "supervisor
   access to user page with AC=0" and bugcheck with the faulting RIP +
   GPR dump + RBP-chain backtrace + kernel-stack head dump.  This
   converts any future occurrence of the same class of bug (forgotten
   `UserGuard` bracket, RFLAGS not preserved across a new sched
   boundary) into a single-fault, single-line diagnosis instead of a
   400 M-fault retry storm.

Also bumps `BOOT_INFO_PHYS_BASE` 7 MiB → 16 MiB in `shared/src/lib.rs`
because the current `firefox-test,kdb,w215-diag` build's `.bss` size
(0x28F7E0) ends at virt `0x70B7E0` — past the 7 MiB anchor — which
previously caused `_start`'s BSS zero-fill to clobber the bootloader's
handoff page and trigger "Invalid BootInfo magic" panic before the kernel
could reach init.  The new anchor leaves ~8 MiB of headroom for future
BSS-adding diagnostic features.

## Diff inventory

```
shared/src/lib.rs                         (+13 -5)  BOOT_INFO_PHYS_BASE 7 MiB → 16 MiB
kernel/src/mm/w215_crc.rs                 (+ 2 -1)  doc-comment de-references 0x700000
kernel/src/subsys/linux/syscall.rs        (+ 3 -2)  doc-comment de-references 0x700000
kernel/src/proc/thread.rs                 (+30 -11) pushfq/popfq + init_thread_stack +
                                                    init_fork_child_stack RFLAGS slot
kernel/src/arch/x86_64/idt.rs             (+90 -1)  SMAP-fault detector + GPR/bt dump
```

Total: ~135 LOC across 5 files; within budget for an investigation PR
that includes the fix.

## Verification gates

* `[Aether] BootInfo magic validated OK` — boot reaches `phase 9` (was
  panicking at line 94 with the 7 MiB anchor for any w215-diag build).
* No `[SMAP/FAULT]` lines during a firefox-test soak (the detector is
  one-shot per fault and bugchecks on hit; absence over a multi-minute
  run = no remaining unbracketed user dereference in a swept code path).
* `[HB]` heartbeat sc count continues to climb past the historical 1423
  plateau (the wedge was the SMAP retry storm; with RFLAGS preserved
  across schedule, fd_read inside the original UserGuard scope completes
  and PID 2 progresses).

## Notes for follow-up

* The SMAP-fault detector intentionally bugchecks rather than returning
  `false` (which would deliver SIGSEGV to the faulting thread).  A
  kernel-side missing `UserGuard` is a kernel bug, not a user fault —
  killing the user process would mask the actual defect.
* The `init_*_stack` helpers now publish a 0x202 RFLAGS prelude.  Any
  future kernel-stack synthesiser must do the same; the docstrings on
  both functions call this out.
* Long-term, the systemic fix is to scope `UserGuard` to the
  smallest-possible leaf copy (Linux's `__copy_to_user` /
  `__copy_from_user` pattern) so AC=1 windows never span a `schedule()`
  call.  That refactor is much larger than ~135 LOC and is left for a
  follow-up dispatch.
