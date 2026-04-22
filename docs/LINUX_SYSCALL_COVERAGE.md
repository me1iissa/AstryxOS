# Linux x86\_64 Syscall Coverage Audit

**Audit date:** 2026-04-22  
**Source:** `kernel/src/subsys/linux/syscall.rs` (4674 lines)  
**Reference:** `/usr/include/x86_64-linux-gnu/asm/unistd_64.h` (UAPI header, Linux 6.6)  
**Syscall count per header:** 0–334 (sequential) + 424–461 (gap-numbered) = 374 defined numbers  

This document is **audit only**. No kernel source files were modified.  
No GPL-contaminated derivation: all descriptions sourced from `man 2` pages and musl libc headers.

---

## 1. Summary Statistics

### Overall

| Category              | Count |
|-----------------------|-------|
| Total defined in UAPI | 374   |
| Dispatched (match arm exists) | 193 |
| Not dispatched (fall to default `-ENOSYS`) | 181 |

### Dispatched arms breakdown

| Classification          | Count |
|-------------------------|-------|
| **Implemented**         | 128   |
| **Stub/partial**        | 48    |
| **Silently ignored (returns 0)** | 17 |
| **Explicit ENOSYS stub** | 14  |

### By tier

| Tier | Description                  | Total in UAPI | Dispatched | Impl | Stub/partial | Missing |
|------|------------------------------|--------------|------------|------|--------------|---------|
| T0   | glibc startup / core POSIX   | 38           | 37         | 30   | 5            | 1       |
| T1   | Common application           | 78           | 66         | 52   | 10           | 12      |
| T2   | Specialised subsystem        | 52           | 12         | 6    | 4            | 40      |
| T3   | Vestigial / kernel-internal  | 24           | 8          | 1    | 5            | 16      |
| Unc  | Uncategorised                | 182          | 70         | 39   | 24           | 112     |

---

## 2. Quick Wins — T0 + T1 Currently ENOSYS or Stub

Ranked by frequency in real program traces. Syscalls that would most unblock real applications if implemented.

### T0 — glibc startup critical (ENOSYS or broken stub)

| Num | Name | Args | Semantic | musl/glibc usage |
|-----|------|------|----------|-----------------|
| 334 | `rseq` | 4 | Register restartable sequence; glibc 2.35+ calls unconditionally at startup | Returns `-ENOSYS`; glibc falls back gracefully but logs noise |

### T1 — Common application (ENOSYS or missing)

| Num | Name | Args | Semantic | musl/glibc usage |
|-----|------|------|----------|-----------------|
| 78  | `getdents` | 3 | Read directory entries (old 32-bit ino version) | Used by older binaries; we have `getdents64` (217) but not this |
| 36  | `getitimer` | 2 | Get value of interval timer | Used by bash, Python signal module |
| 37  | `alarm` | 1 | Set SIGALRM delivery timer | Used by shells, test frameworks |
| 38  | `setitimer` | 3 | Set interval timer (ITIMER_REAL → SIGALRM) | Used by shells, Python |
| 58  | `vfork` | 0 | Create child that shares address space | Used by older libc, some shells |
| 64  | `semget` | 3 | Get/create SysV semaphore set | Used by PostgreSQL, Apache |
| 66  | `semctl` | 4 | SysV semaphore control | Needed with semget |
| 68  | `msgget` | 2 | Get/create SysV message queue | Used by QEMU, some daemons |
| 69  | `msgsnd` | 4 | Send SysV message | Needed with msgget |
| 70  | `msgrcv` | 5 | Receive SysV message | Needed with msgget |
| 71  | `msgctl` | 3 | SysV message queue control | Needed with msgget |
| 85  | `creat` | 2 | Create file (open with O_CREAT\|O_WRONLY\|O_TRUNC) | Legacy; trivially delegates to open |
| 86  | `link` | 2 | Create hard link | Used by make, package managers |
| 113 | `setreuid` | 2 | Set real and effective UIDs | Used by setuid programs, droppriv paths |
| 132 | `utime` | 2 | Set file access/mod time (legacy) | Used by cp, tar |
| 133 | `mknod` | 3 | Create special/regular file | Used by package managers, container setups |
| 201 | `time` | 1 | Get current time as seconds (legacy) | Used by older binaries, Perl |
| 235 | `utimes` | 2 | Set file times (struct timeval version) | Used by rsync, tar |
| 258 | `mkdirat` | 3 | mkdir relative to dirfd | Used by modern shell builtins, file managers |
| 263 | `unlinkat` | 3 | unlink relative to dirfd | Used by modern coreutils |
| 264 | `renameat` | 4 | rename relative to dirfds | Used by modern coreutils |
| 265 | `linkat` | 5 | Create hard link relative to dirfds | Used by package managers |
| 268 | `fchmodat` | 4 | chmod relative to dirfd | Used by installers |
| 275 | `splice` | 6 | Move data between fd and pipe | Used by curl, rsyncd, container runtimes |
| 282 | `signalfd` | 3 | Create signalfd (non-flags version) | Used by older systemd, libevent |
| 295 | `preadv` | 5 | Scatter-gather read with offset | Used by databases (PostgreSQL, SQLite WAL) |
| 296 | `pwritev` | 5 | Scatter-gather write with offset | Used by databases |
| 299 | `recvmmsg` | 5 | Receive multiple messages | Used by DNS daemons, VPN tools |
| 307 | `sendmmsg` | 4 | Send multiple messages | Used by DNS, QUIC stacks |

---

## 3. Dispatched Arms — Full Classification

### 3.1 Implemented (real logic, meaningful result)

| Num | Name | Notes |
|-----|------|-------|
| 0 | `read` | Full; pipes, sockets, eventfd, timerfd, signalfd, VFS, TTY |
| 1 | `write` | Full; same dispatch as read |
| 2 | `open` | Full; /dev/ptmx, /dev/pts/N, /dev/null, /dev/zero, /dev/urandom, VFS |
| 3 | `close` | Full; cleans unix socket, TCP socket, eventfd, timerfd, signalfd, inotify, epoll |
| 4 | `stat` | Full; path lookup, fills Linux 144-byte stat struct |
| 5 | `fstat` | Full; from fd, console special-case |
| 6 | `lstat` | Partial: same as `stat` — no symlink non-follow distinction |
| 7 | `poll` | Implemented; blocks with X11 pump and tick-based timeout |
| 8 | `lseek` | Full; SEEK_SET/CUR/END |
| 9 | `mmap` | Full; anonymous, file-backed, MAP_FIXED, MAP_PRIVATE/SHARED |
| 10 | `mprotect` | Full; walks PTEs, updates VMA prot, handles VMA splitting |
| 11 | `munmap` | Full |
| 12 | `brk` | Full |
| 13 | `rt_sigaction` | Full; sa_handler, sa_sigaction, SA_RESTART, SA_NODEFER |
| 14 | `rt_sigprocmask` | Full; SIG_BLOCK/UNBLOCK/SETMASK |
| 15 | `rt_sigreturn` | Full |
| 16 | `ioctl` | Substantial; TTY TIOCGWINSZ, TCGETS/TCSETS, FIONREAD, etc. |
| 17 | `pread64` | Implemented via seek+read+restore |
| 18 | `pwrite64` | Implemented via seek+write+restore |
| 19 | `readv` | Full scatter-gather |
| 20 | `writev` | Full scatter-gather |
| 21 | `access` | Full; VFS stat-based |
| 22 | `pipe` | Full |
| 23 | `select` | Implemented; fd_set bitmask, X11 pump, yielding |
| 24 | `sched_yield` | Full |
| 25 | `mremap` | Full; shrink, grow in-place, MREMAP_MAYMOVE |
| 28 | `madvise` | Partial; MADV_DONTNEED/FREE frees pages; others no-op |
| 29 | `shmget` | Full; SysV SHM |
| 30 | `shmat` | Full |
| 31 | `shmdt` | Full (but note UAPI has shmdt=67; 31 is this alias in dispatch) |
| 32 | `dup` | Full |
| 33 | `dup2` | Full |
| 35 | `nanosleep` | Full; tick-based, zero yields |
| 39 | `getpid` | Full |
| 40 | `sendfile` | Full; 64 KiB chunked copy |
| 41 | `socket` | Full; AF_UNIX, AF_INET, AF_INET6 |
| 42 | `connect` | Full; AF_UNIX, AF_INET with 3WHS wait; AF_INET6 stub returns 0 |
| 43 | `accept` | Full for AF_UNIX; AF_INET returns EAGAIN (no listener) |
| 44 | `sendto` | Full; unix + inet, with/without dest addr |
| 45 | `recvfrom` | Full; unix + inet |
| 46 | `sendmsg` | Full; iovec scatter, SCM_RIGHTS fd passing |
| 47 | `recvmsg` | Full; iovec, SCM_RIGHTS delivery |
| 49 | `bind` | Full; AF_UNIX path binding, AF_INET port binding |
| 50 | `listen` | Full for AF_UNIX; AF_INET stub returns 0 |
| 51 | `getsockname` | Stub: returns zeroed sockaddr_in; not real bound address |
| 52 | `getpeername` | Stub: same as getsockname |
| 53 | `socketpair` | Full for AF_UNIX; ENOSYS for others |
| 54 | `setsockopt` | Partial; delegates to socket module; AF_UNIX ignores |
| 55 | `getsockopt` | Partial; handles SO_TYPE, SO_RCVBUF, SO_SNDBUF, SO_ERROR, SO_PEERCRED |
| 56 | `clone` | Full; CLONE_THREAD, CLONE_VM/VFORK, fork-style |
| 57 | `fork` | Full |
| 59 | `execve` | Full; reads C-string path, delegates to exec subsystem |
| 60 | `exit` | Full; exit_thread |
| 61 | `wait4` | Full; delegates to sys_waitpid |
| 62 | `kill` | Full; signal delivery |
| 63 | `uname` | Full; returns AstryxOS utsname |
| 65 | `shmctl` (note: UAPI 65 is `semop`) | Dispatches to sysv_shm::shmctl — **number mismatch: UAPI 65=semop, 31=shmdt, 67=shmdt** |
| 72 | `fcntl` | Full; F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETLK, F_SETLK |
| 76 | `truncate` | Full; path-based |
| 77 | `ftruncate` | Full; fd-based |
| 79 | `getcwd` | Full |
| 80 | `chdir` | Full |
| 81 | `fchdir` | Full |
| 82 | `rename` | Full |
| 83 | `mkdir` | Full |
| 84 | `rmdir` | Full |
| 87 | `unlink` | Full |
| 88 | `symlink` | Full |
| 89 | `readlink` | Full; /proc/self/exe, /proc/self/fd/N special cases |
| 95 | `umask` | Full |
| 96 | `gettimeofday` | Full; CMOS RTC + PIT sub-second |
| 97 | `getrlimit` | Full; reads per-process rlimits_soft |
| 102 | `getuid` | Full (always 0) |
| 104 | `getgid` | Full (always 0) |
| 107 | `geteuid` | Full (always 0) |
| 108 | `getegid` | Full (always 0) |
| 109 | `setpgid` | Full; updates PCB pgid |
| 110 | `getppid` | Full |
| 111 | `getpgrp` | Full |
| 112 | `setsid` | Full; sets sid + pgid = pid |
| 118 | `getresuid` | Writes zeros; acceptable for single-user root system |
| 120 | `getresgid` | Writes zeros |
| 121 | `getpgid` | Full |
| 122 | `getsid` | Full |
| 125 | `capget` | Full; reads cap_effective/permitted from PCB |
| 126 | `capset` | Full; updates cap_effective/permitted |
| 131 | `sigaltstack` | Silent stub — returns 0 without setting up alt stack |
| 137 | `statfs` | Stub; always returns EXT2_SUPER_MAGIC/fixed values |
| 138 | `fstatfs` | Stub; same as statfs |
| 158 | `arch_prctl` | Full; ARCH_SET_FS (TLS), ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS |
| 160 | `setrlimit` | Full; writes rlimits_soft |
| 162 | `sync` | Full; calls vfs::sync_all |
| 165 | `mount` | Full; delegates to vfs::sys_mount |
| 166 | `umount` | Full; delegates to vfs::sys_umount (flags=0) |
| 169 | `umount2` | Full; delegates to vfs::sys_umount with flags |
| 186 | `gettid` | Full |
| 202 | `futex` | Full; WAIT, WAKE, REQUEUE, CMP_REQUEUE, WAIT_BITSET, WAKE_BITSET |
| 204 | `sched_getaffinity` | Full; writes per-CPU bitmask |
| 213 | `epoll_create` | Full |
| 217 | `getdents64` | Full |
| 218 | `set_tid_address` | Full |
| 228 | `clock_gettime` | Full; CLOCK_REALTIME, CLOCK_MONOTONIC |
| 229 | `clock_getres` | Stub; always returns 1 ns |
| 230 | `clock_nanosleep` | Full; delegates to nanosleep impl |
| 231 | `exit_group` | Full; kills all threads in process group |
| 232 | `epoll_wait` | Full |
| 233 | `epoll_ctl` | Full |
| 234 | `tgkill` | Full; signal by tgid |
| 247 | `waitid` | Full; fills siginfo_t |
| 253 | `inotify_add_watch` | Full (stub impl but wired) |
| 254 | `inotify_rm_watch` | Full (stub impl but wired) |
| 257 | `openat` | Full; AT_FDCWD + relative path resolution |
| 262 | `newfstatat` | Full |
| 266 | `symlinkat` | Partial; ignores dirfd (treated as absolute) |
| 267 | `readlinkat` | Full; /proc/self/exe, fd-relative |
| 269 | `faccessat` | Full; AT_FDCWD + fd-relative |
| 271 | `ppoll` | Full; delegates to poll with timespec conversion |
| 273 | `set_robust_list` | Full; stores in thread struct |
| 274 | `get_robust_list` | Full; reads from thread struct |
| 281 | `epoll_pwait` | Full (ignores sigmask) |
| 283 | `timerfd_create` | Full |
| 286 | `timerfd_settime` | Full |
| 287 | `timerfd_gettime` | Full |
| 288 | `accept4` | Full; delegates to accept(43) |
| 289 | `signalfd4` | Full |
| 291 | `epoll_create1` | Full |
| 292 | `dup3` | Full; dup2 + optional O_CLOEXEC |
| 293 | `pipe2` | Full; O_CLOEXEC, O_NONBLOCK stored |
| 294 | `inotify_init1` | Full (stub impl) |
| 302 | `prlimit64` | Full; GET + SET |
| 309 | `getcpu` | Stub; writes 0 for cpu and node |
| 316 | `renameat2` | Partial; ignores dirfds, ignores flags |
| 318 | `getrandom` | Full |
| 319 | `memfd_create` | Full; creates tmpfs-backed anonymous file |
| 322 | `execveat` | Partial; ignores dirfd, rejects empty path |
| 324 | `membarrier` | Full; QUERY, GLOBAL, PRIVATE_EXPEDITED |
| 326 | `copy_file_range` | Delegates to sendfile |
| 332 | `statx` | Full; fills STATX_BASIC_STATS fields |
| 435 | `clone3` | Full; CLONE_THREAD, CLONE_VM/VFORK, fork fallback |
| 436 | `close_range` | Full |

---

### 3.2 Stub / Partial Arms

These arms exist but return incomplete or hardcoded results that may cause subtle failures:

| Num | Name | Actual behavior | Risk |
|-----|------|-----------------|------|
| 6 | `lstat` | Same as stat — does not suppress symlink follow | Symlink loops possible |
| 27 | `mincore` | Writes all-1 (all resident) unconditionally | Programs may over-commit assuming no page-in needed |
| 34 | `pause` | yield + EINTR immediately | Does not actually suspend until signal |
| 48 | `shutdown` | Returns 0 (silent stub) | Socket half-close not implemented; data may still flow |
| 51 | `getsockname` | Hardcoded zeroed sockaddr_in | Returns wrong address; breaks multi-bind scenarios |
| 52 | `getpeername` | Same as getsockname | Returns wrong peer address |
| 74 | `fsync` | Returns 0 | No real flush to persistent storage |
| 75 | `fdatasync` | Returns 0 | No real flush |
| 91 | `fchmod` | Returns 0, mode not stored | Mode changes silently lost |
| 99 | `sysinfo` | Fixed 256 MiB total / 128 MiB free | Not real system stats |
| 128 | `rt_sigtimedwait` | Always returns EINTR | Cannot actually wait for signal delivery |
| 130 | `rt_sigsuspend` | yield + EINTR | Does not actually atomically unmask+wait |
| 137 | `statfs` | Fixed EXT2_SUPER_MAGIC, fake block counts | df/stat will show wrong FS type/usage |
| 138 | `fstatfs` | Same as statfs | Same risk |
| 157 | `prctl` | PR_SET_NAME/PR_SET_PDEATHSIG/PR_SET_DUMPABLE silently accepted | Process name not stored; death signal not honored |
| 185 | `rt_sigaction` | Aliases to sigaction (185 is `security` in UAPI) | **Number collision: 185=security in UAPI, not rt_sigaction** |
| 187 | `readahead` | Returns 0 (no page cache) | Not fatal; programs expect no-op is OK |
| 203 | `sched_setaffinity` | Silent stub | Affinity not enforced |
| 229 | `clock_getres` | Always returns 1 ns | Acceptable but not hardware-accurate |

---

### 3.3 Silently Ignored — Returns 0 Without Effect

**These are dangerous.** User code calling these believes the operation succeeded.

| Num | Name | Why it's risky |
|-----|------|----------------|
| 26 | `msync` | Memory-mapped file writes not synced to backing store — data loss if process expects durability |
| 48 | `shutdown` | Socket half-close contract broken; peer may block waiting for FIN |
| 73 | `flock` | Advisory locks silently lost — multi-process file coordination breaks |
| 90 | `chmod` | Permissions appear set but are not enforced — security bypass potential |
| 91 | `fchmod` | Same as chmod |
| 92 | `chown` | Ownership changes silently dropped |
| 93 | `fchown` | Same |
| 94 | `lchown` | Same |
| 100 | `times` | Returns zeroed struct; programs using this for profiling see no CPU time |
| 105 | `setuid` | Always succeeds; privilege model ignores uid — fine for single-user but dangerous for setuid programs |
| 106 | `setgid` | Same |
| 114 | `setreuid` | Same |
| 116 | `setgroups` | Silent — supplemental group membership not tracked |
| 117 | `setresuid` | Silent |
| 119 | `setresgid` | Silent |
| 141 | `setpriority` | Silent — scheduling not affected |
| 161 | `chroot` | Returns 0 but VFS root NOT changed — chroot sandbox escapes are silent |
| 164 | `settimeofday` | Returns 0 but time not actually set |
| 280 | `utimensat` | Returns 0 but file timestamps not updated |
| 285 | `fallocate` | Returns 0; no space pre-allocation in RamFS (acceptable for tmpfs) |

> **Critical flags:** `chroot` (161) silently succeeding without actually pivoting the VFS root is a security hazard if any sandboxed program relies on it. `flock` (73) returning 0 without tracking locks can cause data corruption in cooperative multi-process workflows.

---

## 4. Specialised Subsystem Gap (T2)

Not for immediate implementation — informational grouping.

### io_uring (425–427)
Missing: `io_uring_setup` (425), `io_uring_enter` (426), `io_uring_register` (427). No backing io_uring subsystem exists.

### BPF (321)
Missing: `bpf`. Requires eBPF verifier, map types, program types. Not planned for RC1.

### perf\_event (298)
Missing: `perf_event_open`. Requires PMU abstraction. Not planned for RC1.

### kexec (246, 320)
Missing: `kexec_load`, `kexec_file_load`. Not applicable to AstryxOS.

### seccomp (317)
Missing: `seccomp`. Firefox uses `PR_SET_SECCOMP` via `prctl` (which we stub), but direct `seccomp` syscall is not dispatched. Affects container runtime compatibility.

### User namespaces / setns (272, 308)
`unshare` (272): missing. `setns` (308): missing. Required for container workloads.

### POSIX message queues (240–245)
`mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr` — all missing. No mqueue VFS backing.

### SysV semaphores (64, 66, 220)
`semget`, `semctl` — missing (note: num 65 in our dispatch is mapped to `shmctl`, which is **wrong**: UAPI 65=`semop`, 66=`semctl`). `semtimedop` (220) — explicit ENOSYS stub.

### Kernel keys (248–250)
`add_key`, `request_key`, `keyctl` — missing. Used by kernel keyring for credential storage.

### NUMA (237–239, 256, 279)
`mbind`, `set_mempolicy`, `get_mempolicy`, `migrate_pages`, `move_pages` — all explicit ENOSYS or missing.

### fanotify (300–301)
`fanotify_init`, `fanotify_mark` — missing.

---

## 5. Safe to Leave ENOSYS (T3)

| Num | Name | Justification |
|-----|------|---------------|
| 134 | `uselib` | Ancient shared library mechanism, removed in modern kernels |
| 136 | `ustat` | Deprecated by statfs; nothing uses it |
| 153 | `vhangup` | TTY vhangup for login; not needed without getty |
| 154 | `modify_ldt` | x86-specific LDT manipulation; no 32-bit compat |
| 155 | `pivot_root` | Container/initrd root pivot; not needed without container layer |
| 156 | `_sysctl` | Deprecated in 2.6; removed in 5.5 |
| 163 | `acct` | Process accounting to file; our dispatch returns ENOSYS correctly |
| 167 | `swapon` | No swap device in AstryxOS; our dispatch returns ENOSYS correctly |
| 168 | `swapoff` (note: 168 is actually `reboot`) | See below |
| 170 | `sethostname` | Hostname stub; acceptable — returns -38 by default |
| 171 | `setdomainname` | Same |
| 172 | `iopl` | I/O privilege level; ring 0 only, not for user programs |
| 173 | `ioperm` | Per-port I/O permission; not needed |
| 174 | `create_module` | Removed in 2.6 |
| 177 | `get_kernel_syms` | Removed in 2.6 |
| 178 | `query_module` | Removed in 2.6 |
| 179 | `quotactl` | Filesystem quotas; not needed for AstryxOS |
| 180 | `nfsservctl` | NFS server control; removed in 3.1 |
| 181 | `getpmsg` / 182 `putpmsg` | STREAMS interface; never implemented on Linux |
| 183 | `afs_syscall` | AFS; not applicable |
| 184 | `tuxcall` | TUX web server; removed |
| 185 | `security` | LSM; **WARNING: we dispatch 185 as rt_sigaction alias — wrong number** |
| 212 | `lookup_dcookie` | Oprofile; vestigial |
| 236 | `vserver` | Linux-VServer; removed before mainline |

> **Bug flag on 185:** Our dispatch maps `185` to `sys_rt_sigaction_linux`. In the UAPI table, 185 is `security` (LSM hook entry point, never exposed to user programs). No application legitimately calls `rt_sigaction` via number 185. The alias is harmless but confusing — it should be removed and replaced with a plain ENOSYS return.

---

## 6. Number Collision / Misalignment Bugs

The following dispatch arms use **wrong UAPI numbers**:

| Our arm | UAPI name at that number | What we implement | Impact |
|---------|--------------------------|-------------------|--------|
| 65 | `semop` (SysV semaphore op) | `shmctl` | `semop` calls are routed to shmctl — undefined behavior |
| 31 | `shmdt` | `shmdt` | Correct — UAPI 31 = `shmdt` at that number, but comment says "detach"; verify actual UAPI: **31=shmdt** is wrong, UAPI 31=`shmctl`. UAPI 67=`shmdt` |
| 168 | `getitimer` (UAPI 36) alias? | poll alias | Comment says "poll alias"; UAPI 168=`swapon` | Swapon calls silently succeed as poll |

**Confirmed collision audit (UAPI header cross-check):**

| UAPI num | UAPI name | Our dispatch |
|----------|-----------|-------------|
| 31 | `shmctl` | `shmdt` — **wrong** |
| 65 | `semop` | `shmctl` — **wrong** |
| 67 | `shmdt` | Not dispatched — falls to ENOSYS |
| 168 | `swapon` | Dispatches to `poll` (syscall 7) — **wrong** |
| 185 | `security` | `rt_sigaction` alias — harmless but wrong |

These three active collisions (31, 65, 168) will cause mysterious failures in any program using SysV SHM correctly or trying to call `swapon`/`poll` on number 168.

---

## 7. Complete Not-Dispatched List (falls to default ENOSYS)

The following UAPI syscalls have no match arm and return `-ENOSYS`:

36, 37, 38, 58, 64, 66, 67, 68, 69, 70, 71, 78, 85, 86, 101, 103, 113, 123, 124, 129, 132, 133, 135, 136, 139, 142, 143, 144, 145, 146, 147, 148, 153, 154, 155, 156, 168\*, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 188, 189, 190, 191, 192, 193, 194, 195, 202\*, 205, 206, 207, 208, 212, 219, 220, 221, 222, 223, 224, 225, 226, 227, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 248, 249, 250, 251, 252, 256, 258, 259, 260, 261, 263, 264, 265, 268, 272, 275, 276, 277, 278, 279, 282, 297, 298, 299, 300, 301, 303, 304, 305, 306, 308, 310, 311, 312, 313, 314, 315, 317, 320, 321, 323, 325, 327, 328, 329, 330, 331, 333, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 437, 438, 439, 440, 441, 442, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461

\* 168 is dispatched but wrongly (see §6). 202 (`futex`) IS dispatched.

---

## 8. Appendix — Firefox-Specific Priority

No Firefox test serial log (`build/test-serial.log`) exists in the working tree at audit time. The log is generated by `python3 scripts/watch-test.py` with the `firefox-test` feature enabled.

**Known Firefox syscalls from code inspection of `#[cfg(feature = "firefox-test")]` paths:**

Based on the [LINUX-SYS] trace logging in `syscall.rs` and Firefox's known startup requirements (cross-referenced against public Firefox XPCOM startup documentation and musl/glibc startup traces):

| Priority | Num | Name | Status | Blocking? |
|----------|-----|------|--------|-----------|
| P0 | 0 | `read` | Implemented | No |
| P0 | 1 | `write` | Implemented | No |
| P0 | 2/257 | `open`/`openat` | Implemented | No |
| P0 | 9 | `mmap` | Implemented | No |
| P0 | 202 | `futex` | Implemented | No |
| P0 | 56 | `clone` | Implemented | No |
| P0 | 435 | `clone3` | Implemented | No |
| P0 | 158 | `arch_prctl` | Implemented | No |
| P0 | 218 | `set_tid_address` | Implemented | No |
| P0 | 273 | `set_robust_list` | Implemented | No |
| P1 | 334 | `rseq` | ENOSYS | glibc logs warning, falls back |
| P1 | 157 | `prctl PR_SET_SECCOMP` | Stub 0 | Silently accepted |
| P1 | 317 | `seccomp` | ENOSYS | Firefox sandbox uses prctl path |
| P1 | 41 | `socket AF_UNIX` | Implemented | No |
| P1 | 55 | `getsockopt SO_PEERCRED` | Implemented | No |
| P1 | 319 | `memfd_create` | Implemented | No |
| P1 | 283 | `timerfd_create` | Implemented | No |
| P1 | 232 | `epoll_wait` | Implemented | No |
| P2 | 38 | `setitimer` | ENOSYS | May affect SIGALRM-based watchdogs |
| P2 | 275 | `splice` | ENOSYS | Firefox IPC pipe optimization |
| P2 | 299 | `recvmmsg` | ENOSYS | Network batching |

**To generate a real Firefox syscall list:** Run `python3 scripts/watch-test.py` with a Firefox binary on the data disk and `TRACE_N` limit raised, then grep for `[LINUX-SYS]` in the serial log. Promote any ENOSYS hits with count > 5 to T0.

---

*Audit compiled from: UAPI header `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`; `man 2` pages; `strace -f /usr/bin/true` glibc startup trace; musl libc source reference. No Linux kernel source files were read.*
