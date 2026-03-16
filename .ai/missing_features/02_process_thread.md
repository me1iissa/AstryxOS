# Process & Thread Management Gaps

> Reference: Windows XP `base/ntos/ps/` (28 C files), Linux `kernel/fork.c`, `kernel/exit.c`,
>             `kernel/sched/` (33 C files), ReactOS `ntoskrnl/ps/`
> AstryxOS: `proc/mod.rs`, `proc/thread.rs`, `sched/mod.rs`

---

## What We Have

- Per-process PCB: PID, PPID, name, state (Active/Waiting/Zombie/Dead), CR3, VmSpace
- Per-thread TCB: TID, kernel stack, CPU context (RIP/RSP/RFLAGS/GPRs), priority 0-31
- Thread states: Ready, Running, Blocked, Sleeping, Dead
- SIGCHLD delivery on child exit (parent_pid != 0 guard)
- Process memory cleanup: `free_process_memory()` → VMA walk → refcount → page table walk
- TLS base field + PT_TLS ELF segment loading
- CPU affinity: `Option<u8>` per thread
- Round-robin scheduler with TIME_SLICE=5 ticks
- SMP-safe: ctx_rsp_valid AtomicBool, kernel CR3 for AP idle threads
- `create_user_process_with_args_blocked` + `unblock_process` (no race)

---

## Missing (Critical)

### Process Groups & Session Management
**What**: POSIX requires every process to belong to a process group (PGID) and a session (SID).
`setsid()` creates a new session; `setpgid()` moves a process between groups.
Job control (Ctrl+C, Ctrl+Z, fg, bg) depends entirely on this.

**Impacts**:
- `kill(-pgid, sig)` (send to group) is wired but has no real PGID table
- Shell job control (bash, dash) won't work
- TTY foreground process group (TIOCSPGRP/TIOCGPGRP) is unimplemented

**Reference**: `linux/kernel/sys.c` (`sys_setsid`, `sys_setpgid`);
`XP/base/ntos/ps/job.c`; `reactos/ntoskrnl/ps/job.c`

---

### Process Resource Limits (`rlimit`)
**What**: Every process has per-resource soft/hard limits: RLIMIT_NOFILE (max open FDs),
RLIMIT_DATA (max heap size), RLIMIT_STACK (max stack), RLIMIT_NPROC (max child processes),
RLIMIT_CPU (CPU time), RLIMIT_AS (address space), RLIMIT_FSIZE (max file size).

**Impacts**:
- Runaway processes can consume all RAM / FDs with no enforcement
- musl `getrlimit(RLIMIT_NOFILE)` returns ENOSYS → defaults to 0 → apps refuse to open files
- Firefox will crash trying to open many sockets

**Reference**: `linux/include/uapi/linux/resource.h`; `linux/kernel/sys.c` (`do_getrlimit`);
`XP/base/ntos/ps/quota.c`

---

### Zombie Reaping & Orphan Adoption
**What**: When a parent dies before waiting for its children, those children become orphans and
must be re-parented to PID 1 (init). Without PID 1 adoption, orphaned zombies accumulate and
consume PID space.

**Reference**: `linux/kernel/exit.c` (`forget_original_parent`, `exit_ptrace`);
`XP/base/ntos/ps/kill.c`

---

## Missing (High)

### Realtime Scheduling (SCHED_FIFO / SCHED_RR)
**What**: RT threads must preempt normal threads immediately. SCHED_FIFO runs until it blocks;
SCHED_RR gives equal timeslices among same-priority RT threads.

**Reference**: `linux/kernel/sched/rt.c`; `XP/base/ntos/ke/thredsup.c` (priority boost)

---

### `rusage` / Process Timing Accounting
**What**: Track per-process CPU time (user/sys), page faults, context switches, I/O bytes.
`getrusage()` returns this. `wait4()` with rusage argument too.

**Reference**: `linux/kernel/sys.c` (`getrusage`); `linux/include/linux/sched.h` (task_struct fields)

---

### Detached Thread State
**What**: `pthread_detach()` means the thread's resources are freed automatically on exit with no
need for `pthread_join()`. Currently all threads require explicit cleanup via `exit_thread`.

**Reference**: `linux/kernel/exit.c` (`do_exit`, `release_task`); `linux/kernel/thread.c`

---

### `prctl()` Full Implementation
**What**: Most `prctl()` codes are stubs. Missing critical ones:
- `PR_SET_NAME` — set thread name (shows in `ps`, crash dumps)
- `PR_SET_DUMPABLE` — control core dump generation
- `PR_SET_PDEATHSIG` — signal parent when child dies
- `PR_GET_CHILD_SUBREAPER` — used by init systems
- `PR_SET_NO_NEW_PRIVS` — security hardening (used by Chrome sandbox)
- `PR_SET_SECCOMP` — install BPF filter (Chrome, Firefox use this)

**Reference**: `linux/kernel/sys.c` (`sys_prctl`); `linux/include/uapi/linux/prctl.h`

---

### `clone()` Full Flag Support
**What**: Current clone() only handles basic thread creation. Missing flags:
- `CLONE_PARENT_SETTID` / `CLONE_CHILD_SETTID` / `CLONE_CHILD_CLEARTID` — TID communication
- `CLONE_DETACHED` — auto-reap
- `CLONE_SYSVSEM` — share SysV semaphore undo state
- `CLONE_NEWUSER` / `CLONE_NEWPID` / `CLONE_NEWNS` — namespace creation (containers)
- `CLONE_IO` — share I/O context

**Reference**: `linux/kernel/fork.c` (`copy_process`); `clone(2)` man page

---

## Missing (Medium)

| Feature | Description | Reference |
|---------|-------------|-----------|
| `ptrace()` | Process debugging / tracing | `linux/kernel/ptrace.c` |
| Thread pause/resume from debugger | PTRACE_SEIZE semantics | `linux/kernel/signal.c` |
| Core dump generation | Write crash state to file on SIGSEGV | `linux/fs/coredump.c` |
| Thread-local destructors | TLS cleanup on exit_thread | `linux/kernel/exit.c` |
| CPU quota (RLIMIT_CPU + SIGXCPU) | Kill processes exceeding CPU budget | `linux/kernel/timer.c` |

---

## Missing (Low)

| Feature | Description |
|---------|-------------|
| Kernel threads naming | `/proc/N/comm` display for kernel workers |
| Kernel stack unwinding | Structured crash dumps with symbol names |
| Namespace isolation (pid_ns) | PID 1 inside container, isolated PID space |
| Per-CPU idle thread power management | Deep C-state entry from idle |
| `execve()` cred propagation | setuid binary execution, capability drops |

---

## Implementation Order

1. **Sessions/PGID** — add `pgid: u32`, `sid: u32` to PCB; implement `setsid()`/`setpgid()`/`getpgrp()`
2. **rlimit table** — `rlimits: [RLimit; RLIM_NLIMITS]` in PCB; enforce NOFILE on fd alloc, AS on mmap
3. **Orphan adoption** — in `exit_group()` walk all processes with `ppid == dying_pid`, set `ppid = 1`
4. **prctl PR_SET_NAME / PR_SET_NO_NEW_PRIVS / PR_SET_SECCOMP** — syscall 157 dispatch expansion
5. **rusage** — add `utime_ticks`, `stime_ticks`, `page_faults` to PCB; update at context switch
