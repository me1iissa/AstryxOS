# Syscall Surface Completeness

> Reference: Linux x86_64 syscall table `arch/x86/entry/syscalls/syscall_64.tbl` (350+ entries)
> AstryxOS: `syscall/mod.rs` (6,124 lines)

---

## What We Have (NT-style + Linux compat)

**NT dispatch (SYS_* constants)**:
Exit, Write, Read, Open, Close, GetPid, Yield, Fork, Exec, Waitpid,
Mmap, Munmap, Brk, Getppid, Getcwd, Chdir, Mkdir, Rmdir, Stat, Fstat,
Lseek, Dup, Dup2, Pipe, Uname, Nanosleep, Getuid/Gid/Euid/Egid, Umask,
Unlink, Getrandom, Kill, Sigaction, Sigprocmask, Sigreturn, Ioctl,
Chmod, Chown, Socket, Bind, Connect, Sendto, Recvfrom, Listen, Accept,
Clone (basic), Futex, Sync

**Linux x86_64 dispatch (raw numbers)**:
0(read), 1(write), 2(open), 3(close), 4(stat), 5(fstat), 6(lstat), 8(lseek),
9(mmap), 10(mprotect), 11(munmap), 12(brk), 13(rt_sigaction), 14(rt_sigprocmask),
15(rt_sigreturn), 20(writev), 21(access), 22(pipe), 29-32(sysv_shm), 34(pause),
39(getpid), 41(socket), 42(connect), 43(accept), 44(sendto), 45(recvfrom),
46(sendmsg), 47(recvmsg), 49(bind), 50(listen), 51(getsockname), 52(getpeername),
53(socketpair), 55(setsockopt), 56(clone), 59(execve), 60(exit), 77(getrusage),
82(rename), 88(symlink), 89(readlink), 98(getitimer), 99(setitimer),
100(getrlimit), 118(setresuid), 120(getresuid), 121(getresgid), 122(setresgid),
127(rt_sigpending), 130(madvise), 157(prctl), 162(nanosleep), 204(sched_setaffinity),
229(clock_nanosleep), 231(exit_group), 247(waitid), 253(inotify_init1),
254(inotify_add_watch), 266(clock_gettime), 267(clock_getres), 271(clock_settime),
283(timerfd_create), 287(timerfd_settime), 288(timerfd_gettime), 289(signalfd4),
290(eventfd2), 294(inotify_rm_watch), 295(openat2), 302(prlimit64), 309(getcpu),
316(renameat2), 332(statx), 355(pidfd_open), 435(clone3)

---

## Missing (Critical — Will ENOSYS on Real Apps)

### Multiplexed I/O: `poll` (7) / `select` (23) / `ppoll` (271) / `pselect6` (270)

Current `epoll` works. But hundreds of apps use `poll()`/`select()` and will fail with ENOSYS.

```
poll(fds, nfds, timeout_ms)  →  syscall 7
select(nfds, readfds, writefds, exceptfds, timeout)  →  syscall 23
ppoll(fds, nfds, tspec, sigmask, sigsetsize)  →  syscall 271
pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)  →  syscall 270
```

**Implementation**: Convert to epoll internally, or build a unified `do_poll_wait()`.
`linux/fs/select.c` implements both using `poll_wait()` on file operations.

---

### `pread64` (17) / `pwrite64` (18)
Read/write at offset without changing fd position. Used extensively by database code (SQLite,
IndexedDB in Firefox). Without this, thread-safe file access is impossible.

---

### `readv` (19) / `writev` (20) — `readv` is missing (`writev` done)
Scatter-gather read into multiple buffers. musl `writev` is done; `readv` is ENOSYS.

---

### `setsockopt` (55) / `getsockopt` (54) — full implementation needed
Both are stubs returning 0 without setting anything. `TCP_NODELAY`, `SO_REUSEADDR`,
`SO_RCVBUF`, `SO_SNDBUF`, `IPV6_V6ONLY` must actually change socket behavior.

---

### `sendmsg` (46) / `recvmsg` (47) — ancillary data
Currently ignores `msg_control` (ancillary data). SCM_RIGHTS fd passing is required for
D-Bus, Wayland, XDG portals.

---

### `setuid` (105) / `setgid` (106) / `setreuid` (113) / `setregid` (114)
Privilege drop — setuid executables (sudo, passwd) and sandboxing (dropping root).
Currently only getuid/getgid return 0; setuid/setgid are unimplemented.

---

### `getrlimit` (97) / `setrlimit` (160) — return real values
Currently returns ENOSYS or 0. musl calls `getrlimit(RLIMIT_NOFILE)` at startup and
uses the result to size internal fd tables. Returning 0 means "max 0 file descriptors."

---

### `sysinfo` (99)
Returns system statistics (uptime, loads, total RAM, free RAM, processes).
Firefox reads total RAM to decide cache sizes. Returns ENOSYS → Firefox may crash or
use default 1 MB cache.

---

### `times` (100)
Process CPU time accounting. Returns ticks for user/system/children. Used by shells
and `time` command.

---

### `ptrace` (101)
Process tracing / debugger interface. Required for: gdb, strace, crash reporters.
Firefox's crash handler uses ptrace to capture stack traces.

---

### `fcntl` (72) — full F_GETFL / F_SETFL / F_GETFD / F_SETFD
Currently handles F_GETFL/F_SETFL as stubs. Missing:
- `F_GETFD` / `F_SETFD` — FD_CLOEXEC flag (close on exec)
- `F_SETLK` / `F_SETLKW` / `F_GETLK` — file locking
- `F_DUPFD_CLOEXEC` — dup with cloexec

FD_CLOEXEC is critical — without it, fds leak across exec boundaries.

---

### `openat` (257) — most opens in musl use openat
`openat(AT_FDCWD, path, flags, mode)` with `dirfd=AT_FDCWD` should behave like `open()`.
Currently wired to openat2 but `openat` (257) itself may be missing.

---

## Missing (High)

| Syscall | Number | Description |
|---------|--------|-------------|
| `dup3` | 292 | dup2 + O_CLOEXEC flag |
| `pipe2` | 293 | pipe + O_CLOEXEC / O_NONBLOCK |
| `accept4` | 288 | accept + SOCK_CLOEXEC / SOCK_NONBLOCK |
| `epoll_pwait` | 281 | epoll_wait + signal mask |
| `signalfd` | 282 | signalfd (old, non-4 version) |
| `recvmmsg` | 299 | Batch receive of multiple messages |
| `sendmmsg` | 307 | Batch send of multiple messages |
| `memfd_create` | 319 | Anonymous in-memory file (used by Firefox for JIT) |
| `mmap2` | — | 32-bit compat mmap (pgoffset in pages) |
| `capget` | 125 | Get process capabilities |
| `capset` | 126 | Set process capabilities |
| `personality` | 135 | Linux personality / ABI selection |
| `getitimer` | 36 | Get interval timer |
| `setitimer` | 38 | Set interval timer (SIGALRM) |
| `fchmod` | 91 | chmod by fd |
| `fchown` | 93 | chown by fd |
| `lchown` | 94 | chown, no symlink follow |
| `chmod` | 90 | chmod by path (vs fchmod) |
| `ftruncate` | 77 | truncate by fd |
| `truncate` | 76 | truncate by path |
| `chroot` | 161 | Change root directory |
| `getgroups` | 115 | Get supplementary GIDs |
| `setgroups` | 116 | Set supplementary GIDs |
| `fsync` | 74 | Flush fd to storage |
| `fdatasync` | 75 | Flush fd data (no metadata) |
| `msync` | 26 | Flush mmap to file |
| `fallocate` | 285 | Preallocate disk space |
| `fadvise64` | 221 | I/O readahead hint |

---

## Missing (Medium)

| Syscall | Number | Description |
|---------|--------|-------------|
| `sched_setscheduler` | 144 | Set RT scheduling policy |
| `sched_getscheduler` | 145 | Get scheduling policy |
| `sched_setparam` | 142 | Set RT priority |
| `sched_getparam` | 143 | Get RT priority |
| `sched_get_priority_max` | 146 | Max RT priority |
| `sched_get_priority_min` | 147 | Min RT priority |
| `sched_rr_get_interval` | 148 | Get RR timeslice |
| `mlock2` | 325 | Lock memory (with flags) |
| `munlock` | 151 | Unlock memory |
| `mlockall` | 152 | Lock entire address space |
| `munlockall` | 153 | Unlock all |
| `mincore` | 27 | Query page residency |
| `mremap` | 25 | Resize/move mapping |
| `userfaultfd` | 323 | User-space page fault handler |
| `pidfd_open` | 434 | Open PID as fd (already wired?) |
| `pidfd_send_signal` | 424 | Signal via pidfd |
| `pidfd_getfd` | 438 | Get fd from another process via pidfd |

---

## Missing (Low — Advanced)

| Syscall | Number | Description |
|---------|--------|-------------|
| `seccomp` | 317 | Syscall filter with BPF |
| `bpf` | 321 | Load/run eBPF programs |
| `perf_event_open` | 298 | Performance monitoring |
| `io_uring_setup` | 425 | Async I/O ring setup |
| `io_uring_enter` | 426 | Submit/wait on io_uring |
| `io_uring_register` | 427 | Register buffers for io_uring |
| `landlock_create_ruleset` | 444 | Filesystem sandboxing |
| `landlock_add_rule` | 445 | Add landlock rule |
| `landlock_restrict_self` | 446 | Apply landlock rules |

---

## Syscall Audit Checklist (Priority Order)

**This week** (required for musl/libc compat):
- [ ] `poll` (7) + `select` (23)
- [ ] `pread64` (17) + `pwrite64` (18)
- [ ] `readv` (19)
- [ ] `getrlimit` (97) — return real values from PCB rlimits
- [ ] `sysinfo` (99)
- [ ] `fcntl` F_GETFD/F_SETFD/F_SETLK

**Next sprint** (required for sockets/networking):
- [ ] `setsockopt` (55) + `getsockopt` (54) — actually set flags
- [ ] `sendmsg` (46) full — ancillary data
- [ ] `recvmsg` (47) full — ancillary data
- [ ] `getsockname` (51) + `getpeername` (52)

**Following sprint** (required for privilege/security):
- [ ] `setuid` (105) + `setgid` (106)
- [ ] `capget` (125) + `capset` (126)
- [ ] `fchmod` (91) + `fchown` (93)

**Later** (process control):
- [ ] `ptrace` (101) — at least PTRACE_GETREGS/SETREGS for gdb
- [ ] `sched_setscheduler` (144) + `sched_getscheduler` (145)
- [ ] `getitimer` (36) + `setitimer` (38)
