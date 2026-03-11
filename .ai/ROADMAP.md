# AstryxOS — Feature Roadmap to POSIX + GUI

> Generated 2026-02-27 — Targets musl libc compatibility, SMP, AHCI, hand-rolled TCP,
> and a custom framebuffer compositor.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| POSIX scope | **Full** (musl libc target) | Run real ELF binaries: bash, coreutils, GCC |
| GUI model | **Custom compositor** | Framebuffer + mouse, draw rects/bitmaps, no protocol standard |
| SMP | **Yes** | APIC, per-CPU structures, proper locking |
| Disk driver | **AHCI** | q35 machine, future-proof |
| TCP | **Hand-rolled** | Full retransmit, window management, congestion |
| Phase order | **Memory first** | mmap → CR3 → signals → syscalls → SMP → AHCI → GUI |

---

## Current State (70/70 tests, Session 29 — SMP stable)

**Have**: UEFI boot, GDT/IDT/PIC, PMM (bitmap), VMM (4-level), heap (linked-list),
process/thread model (shared CR3), round-robin scheduler, context switch (global_asm),
syscalls (int 0x80 + SYSCALL/SYSRET), VFS + RamFS + ProcFS + FAT32 (in-memory),
E1000 NIC, ARP/IPv4/ICMP/UDP/DNS/DHCP, pipes (kernel-only), PS/2 keyboard, serial,
framebuffer console, ELF64 loader, fork (vfork-like)/exec/waitpid, NtStatus error model,
Orbit shell (50+ commands).

**Don't have**: Per-process address spaces, mmap, signals, FPU save/restore, mouse,
AHCI, SMP, full TCP, most POSIX syscalls, user-mode libc, GUI.

---

## Phase 6 — Memory Subsystem (Foundation)

Everything else depends on proper virtual memory. This is the highest priority.

### 6.1 — Virtual Memory Areas (VMA)
- [ ] `VmArea` struct: base, length, flags (R/W/X/Shared/Private), backing (anon/file/device)
- [ ] Per-process `VmSpace`: sorted `Vec<VmArea>`, owns a CR3
- [ ] VMA find / split / merge operations
- [ ] Track all user-mapped regions for cleanup on process exit

### 6.2 — Per-Process Page Tables
- [ ] `PageTable::new()` — allocate fresh PML4, clone kernel half (entries 256–511)
- [ ] `PageTable::clone_for_fork()` — CoW: mark all user pages read-only, increment refcount
- [ ] Page frame reference counting (`Arc`-like counter per physical frame)
- [ ] CR3 switch on context switch (scheduler stores/restores CR3 per-thread)
- [ ] Free page tables + user frames on process exit
- [ ] Update `fork_process()` to use real CoW instead of sharing CR3

### 6.3 — Page Fault Handler (Demand Paging + CoW)
- [ ] Handle CoW faults: if write to shared page, allocate new frame, copy, remap, decrement refcount
- [ ] Handle demand-paging: lazy allocation of anonymous mmap'd regions
- [ ] Handle stack growth: auto-extend stack VMA on guard page fault
- [ ] Distinguish kernel vs user faults (check error code bit 2)
- [ ] Kill process on invalid access (deliver SIGSEGV when signals exist)

### 6.4 — mmap / munmap / mprotect / brk
- [ ] `SYS_MMAP(addr, len, prot, flags, fd, offset)` — anonymous + file-backed
  - `MAP_ANONYMOUS | MAP_PRIVATE` — lazy-allocate zero pages
  - `MAP_ANONYMOUS | MAP_SHARED` — shared memory between processes
  - `MAP_PRIVATE` + fd — file-backed private mapping (for ELF loading)
  - `MAP_FIXED` — map at exact address
- [ ] `SYS_MUNMAP(addr, len)` — unmap region, flush TLB, free frames if refcount → 0
- [ ] `SYS_MPROTECT(addr, len, prot)` — change page permissions on existing mapping
- [ ] `SYS_BRK(addr)` — adjust process heap break (program break for malloc)
- [ ] Wire mmap into ELF loader (replace direct `map_page` calls)
- [ ] Tests: anonymous mmap, munmap, CoW fork, brk

### 6.5 — FPU / SSE / AVX Context
- [ ] `fxsave` / `fxrstor` (SSE) or `xsave` / `xrstor` (AVX) on context switch
- [ ] Detect CPU features via CPUID (SSE, SSE2, AVX, AVX-512)
- [ ] Lazy FPU switching: set CR0.TS, handle #NM (Device Not Available) to save/restore only when needed
- [ ] 512-byte (fxsave) or XSAVE area per thread, 16-byte aligned
- [ ] Initialize FPU state for new threads (FNINIT + LDMXCSR)

**Milestone**: Real fork with CoW, mmap works, user processes have isolated address spaces.

---

## Phase 7 — Signals

Signals are required by POSIX and needed for Ctrl+C, child notification, and process cleanup.

### 7.1 — Signal Infrastructure
- [ ] Signal number definitions (1–31 standard signals): SIGHUP, SIGINT, SIGQUIT, SIGILL,
      SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGKILL, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE,
      SIGALRM, SIGTERM, SIGCHLD, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU
- [ ] Per-process signal state: pending mask (bitset), blocked mask, handler table
- [ ] `SignalAction`: Default, Ignore, or handler function pointer (+ SA_SIGINFO, SA_RESTART flags)
- [ ] Default actions per signal: Terminate, CoreDump, Stop, Continue, Ignore

### 7.2 — Signal Delivery
- [ ] `send_signal(pid, sig)` — queue signal to target process
- [ ] Check pending signals on return-to-userspace (after syscall or interrupt)
- [ ] Build signal trampoline frame on user stack (save registers, push `siginfo_t`, call handler)
- [ ] `SYS_SIGRETURN` — restore original user context after handler returns
- [ ] Kernel-generated signals: SIGSEGV (page fault), SIGFPE (div-by-zero), SIGPIPE (broken pipe),
      SIGCHLD (child exit)
- [ ] SIGKILL / SIGSTOP cannot be caught or blocked

### 7.3 — Signal Syscalls
- [ ] `SYS_KILL(pid, sig)` — send signal to process
- [ ] `SYS_SIGACTION(sig, act, oldact)` — register signal handler
- [ ] `SYS_SIGPROCMASK(how, set, oldset)` — block/unblock signals
- [ ] `SYS_SIGPENDING(set)` — query pending signals
- [ ] `SYS_SIGSUSPEND(mask)` — atomically wait for signal
- [ ] `SYS_SIGTIMEDWAIT` — wait with timeout

### 7.4 — Process Groups & Sessions
- [ ] PGID (process group ID) and SID (session ID) fields in PCB
- [ ] `SYS_SETPGID`, `SYS_GETPGID`, `SYS_SETSID`, `SYS_GETSID`
- [ ] Terminal control: foreground process group
- [ ] `SYS_KILL` with negative PID → send to process group

**Milestone**: Ctrl+C kills foreground process, SIGCHLD notifies parent, SIGSEGV terminates bad processes.

---

## Phase 8 — POSIX Syscall Surface

The full set of syscalls needed for musl libc. Grouped by subsystem.

### 8.1 — File Operations
- [ ] `SYS_LSEEK(fd, offset, whence)` — SEEK_SET, SEEK_CUR, SEEK_END
- [ ] `SYS_STAT(path, buf)` / `SYS_FSTAT(fd, buf)` / `SYS_LSTAT(path, buf)`
- [ ] `SYS_ACCESS(path, mode)` — check file accessibility (F_OK, R_OK, W_OK, X_OK)
- [ ] `SYS_DUP(oldfd)` / `SYS_DUP2(oldfd, newfd)`
- [ ] `SYS_FCNTL(fd, cmd, arg)` — F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL
- [ ] `SYS_IOCTL(fd, request, arg)` — dispatch to device-specific handlers
- [ ] `SYS_READV(fd, iov, iovcnt)` / `SYS_WRITEV(fd, iov, iovcnt)` — scatter/gather I/O
- [ ] `SYS_PREAD64(fd, buf, count, offset)` / `SYS_PWRITE64`
- [ ] `SYS_TRUNCATE(path, length)` / `SYS_FTRUNCATE(fd, length)`
- [ ] `SYS_UMASK(mask)`

### 8.2 — Directory & Path Operations
- [ ] `SYS_MKDIR(path, mode)` / `SYS_RMDIR(path)`
- [ ] `SYS_UNLINK(path)` / `SYS_RENAME(oldpath, newpath)`
- [ ] `SYS_LINK(oldpath, newpath)` / `SYS_SYMLINK(target, linkpath)`
- [ ] `SYS_READLINK(path, buf, bufsiz)`
- [ ] `SYS_CHDIR(path)` / `SYS_GETCWD(buf, size)`
- [ ] `SYS_GETDENTS64(fd, buf, count)` — read directory entries
- [ ] `SYS_CHROOT(path)` — (optional, for containers)

### 8.3 — Process Operations
- [ ] Fix exec to **replace** current process image (not create new process)
- [ ] `SYS_EXECVE(path, argv, envp)` — pass arguments and environment
- [ ] `SYS_GETPPID` — parent PID
- [ ] `SYS_WAIT4(pid, status, options, rusage)` — wait with WNOHANG, WUNTRACED
- [ ] `SYS_CLONE(flags, stack, ...)` — flexible process/thread creation (musl uses this)
- [ ] `SYS_SET_TID_ADDRESS` — thread-local storage support
- [ ] `SYS_EXIT_GROUP(status)` — terminate all threads in process
- [ ] `SYS_ARCH_PRCTL(code, addr)` — set FS/GS base for TLS
- [ ] argv/envp/auxv placed on user stack per ELF ABI spec

### 8.4 — Pipe & IPC
- [ ] `SYS_PIPE(fds[2])` / `SYS_PIPE2(fds[2], flags)` — create connected fd pair via VFS
- [ ] Wire existing kernel pipe into VFS fd_read/fd_write
- [ ] `SYS_SOCKETPAIR` — (for Unix domain sockets, later)
- [ ] `SYS_EVENTFD` / `SYS_EVENTFD2` — lightweight notification

### 8.5 — Time
- [ ] `SYS_CLOCK_GETTIME(clk_id, tp)` — CLOCK_REALTIME, CLOCK_MONOTONIC
- [ ] `SYS_GETTIMEOFDAY(tv, tz)` — (legacy, wraps clock_gettime)
- [ ] `SYS_NANOSLEEP(req, rem)` — high-resolution sleep
- [ ] `SYS_CLOCK_GETRES` — clock resolution query
- [ ] RTC driver (CMOS or HPET) for wall-clock time
- [ ] Monotonic tick → nanosecond conversion using TSC or PIT calibration

### 8.6 — User & Permission Model
- [ ] UID / GID / EUID / EGID fields in PCB (default: root / 0)
- [ ] `SYS_GETUID` / `SYS_GETGID` / `SYS_GETEUID` / `SYS_GETEGID`
- [ ] `SYS_SETUID` / `SYS_SETGID` / `SYS_SETREUID` / `SYS_SETREGID`
- [ ] `SYS_CHMOD(path, mode)` / `SYS_FCHMOD(fd, mode)`
- [ ] `SYS_CHOWN(path, uid, gid)` / `SYS_FCHOWN(fd, uid, gid)`
- [ ] Permission checking in VFS open/read/write/exec (rwx bits vs uid/gid)

### 8.7 — Miscellaneous Musl Requirements
- [ ] `SYS_UNAME(buf)` — system name, release, version, machine
- [ ] `SYS_SYSINFO(info)` — uptime, loads, total/free RAM
- [ ] `SYS_GETRLIMIT` / `SYS_SETRLIMIT` / `SYS_PRLIMIT64`
- [ ] `SYS_GETRANDOM(buf, len, flags)` — entropy source (RDRAND or /dev/urandom)
- [ ] `SYS_FUTEX(addr, op, val, ...)` — fast userspace mutex (critical for musl threading)
- [ ] `SYS_SET_ROBUST_LIST` / `SYS_GET_ROBUST_LIST`
- [ ] `SYS_RT_SIGACTION` / `SYS_RT_SIGPROCMASK` (rt_sig variants for 64-bit masks)

**Milestone**: musl libc `hello world` (static) runs. Basic coreutils compile and execute.

---

## Phase 9 — Storage: AHCI Driver & Persistent Filesystem

### 9.1 — PCI Improvements
- [ ] Full PCI enumeration (bus/device/function scan, or ECAM for PCIe)
- [ ] BAR decoding (MMIO vs I/O, 32-bit vs 64-bit)
- [ ] PCI capability list walking (MSI/MSI-X)
- [ ] Device driver matching by vendor/device ID

### 9.2 — AHCI / SATA Driver
- [ ] AHCI HBA discovery via PCI (class 01h, subclass 06h, prog-if 01h)
- [ ] AHCI port enumeration and device detection (check PxSSTS.DET)
- [ ] Port initialization: allocate command list, FIS receive area, command tables
- [ ] IDENTIFY DEVICE command (ATA IDENTIFY via AHCI)
- [ ] Read/write sectors via AHCI command engine (DMA)
- [ ] Interrupt-driven completion (or polling fallback)
- [ ] `BlockDevice` trait implementation for AHCI ports
- [ ] Test: detect data.img in QEMU q35, read sectors, mount FAT32

### 9.3 — Persistent Filesystem
- [ ] Mount real AHCI disk at `/disk` or `/mnt`
- [ ] FAT32 write support (allocate clusters, update FAT, directory entries)
- [ ] ext2 read support (superblock, block groups, inodes, directories)
- [ ] ext2 write support (stretch goal)
- [ ] Buffer cache (LRU page cache for disk blocks)
- [ ] `SYS_SYNC` / `SYS_FSYNC` — flush dirty pages

**Milestone**: Real disk I/O via AHCI. Persistent files survive reboot.

---

## Phase 10 — SMP (Multi-Core)

### 10.1 — APIC & Timer
- [ ] Detect Local APIC via CPUID + ACPI MADT table parsing
- [ ] Initialize Local APIC (spurious interrupt vector, TPR, enable)
- [ ] APIC timer calibration (using PIT or TSC as reference)
- [ ] Replace PIC timer with APIC timer for scheduler ticks
- [ ] I/O APIC initialization and interrupt routing (MADT entries)
- [ ] MSI/MSI-X support for PCI devices (E1000, AHCI)

### 10.2 — AP Startup
- [ ] Parse ACPI MADT for processor entries (LAPIC IDs)
- [ ] AP boot trampoline (real mode → protected → long mode)
- [ ] Per-CPU GDT, IDT pointer, TSS
- [ ] Per-CPU kernel stack
- [ ] INIT-SIPI-SIPI sequence to wake Application Processors
- [ ] Barrier: BSP waits for all APs to reach a known state

### 10.3 — SMP Kernel Infrastructure
- [ ] Per-CPU variables (current_tid, current_cpu_id)
- [ ] Replace `spin::Mutex` with ticket locks or MCS locks (fairness)
- [ ] Interrupt-disabling spinlocks for data touched by ISRs
- [ ] Per-CPU run queues in scheduler (work stealing or global queue with per-CPU dispatch)
- [ ] Atomic operations audit (all global state uses correct Ordering)
- [ ] IPI (Inter-Processor Interrupt) for: TLB shootdown, scheduler kick, stop-the-world
- [ ] TLB shootdown on munmap / mprotect (send IPI to all cores)

### 10.4 — SMP Scheduler
- [ ] CPU affinity (optional)
- [ ] Load balancing / migration between per-CPU queues
- [ ] `SYS_SCHED_SETAFFINITY` / `SYS_SCHED_GETAFFINITY`

**Milestone**: Kernel runs on multiple cores. Scheduler distributes threads across CPUs.

---

## Phase 11 — TCP/IP Stack (Full)

### 11.1 — TCP Core
- [ ] 3-way handshake (SYN → SYN-ACK → ACK), proper ISN generation
- [ ] Sliding window (send window, receive window, window scaling option)
- [ ] Retransmission timer (Karn's algorithm, exponential backoff)
- [ ] Fast retransmit (3 duplicate ACKs)
- [ ] Congestion control (slow start, congestion avoidance, Reno or Cubic)
- [ ] PUSH flag handling, Nagle's algorithm (TCP_NODELAY)
- [ ] FIN exchange for graceful close (FIN-WAIT-1/2, TIME-WAIT, CLOSE-WAIT, LAST-ACK)
- [ ] RST handling for abortive close
- [ ] Out-of-order segment reassembly (reorder buffer)
- [ ] Keep-alive (SO_KEEPALIVE)
- [ ] TCP options: MSS, Window Scale, SACK, Timestamps
- [ ] MSS clamping based on MTU

### 11.2 — Socket Layer
- [ ] `SYS_SOCKET(domain, type, protocol)` — AF_INET + SOCK_STREAM/SOCK_DGRAM
- [ ] `SYS_BIND(sockfd, addr, addrlen)`
- [ ] `SYS_LISTEN(sockfd, backlog)` — accept queue
- [ ] `SYS_ACCEPT(sockfd, addr, addrlen)` / `SYS_ACCEPT4` — dequeue connection
- [ ] `SYS_CONNECT(sockfd, addr, addrlen)` — initiate 3-way handshake
- [ ] `SYS_SEND` / `SYS_RECV` / `SYS_SENDTO` / `SYS_RECVFROM`
- [ ] `SYS_SENDMSG` / `SYS_RECVMSG` (scatter/gather + ancillary data)
- [ ] `SYS_SETSOCKOPT` / `SYS_GETSOCKOPT` (SO_REUSEADDR, TCP_NODELAY, etc.)
- [ ] `SYS_SHUTDOWN(sockfd, how)` — half-close
- [ ] `SYS_GETPEERNAME` / `SYS_GETSOCKNAME`
- [ ] Socket fds integrated into VFS (read/write/close work on socket fds)
- [ ] Loopback interface (127.0.0.1)

### 11.3 — I/O Multiplexing
- [ ] `SYS_SELECT(nfds, readfds, writefds, exceptfds, timeout)`
- [ ] `SYS_POLL(fds, nfds, timeout)`
- [ ] `SYS_EPOLL_CREATE` / `SYS_EPOLL_CTL` / `SYS_EPOLL_WAIT`
- [ ] Blocking I/O with wait queues (thread sleeps until fd is ready)
- [ ] Non-blocking I/O (O_NONBLOCK flag, EAGAIN return)

### 11.4 — Unix Domain Sockets
- [ ] AF_UNIX / SOCK_STREAM and SOCK_DGRAM
- [ ] Filesystem-path based binding (`/var/run/compositor.sock`)
- [ ] `SCM_RIGHTS` fd passing (needed for compositor↔client)

**Milestone**: HTTP GET works. `curl` or `wget` (static musl build) can fetch a page.

---

## Phase 12 — GUI: Windowing & Compositor

### 12.1 — Mouse Driver
- [ ] PS/2 mouse initialization (enable IRQ 12, unmask PIC2 line 4)
- [ ] PS/2 mouse packet parsing (3-byte: buttons + delta X/Y; 4-byte with scroll)
- [ ] Mouse state: absolute position (clamped to screen), button state
- [ ] `/dev/input/mouse0` device node with read() interface

### 12.2 — Input Event Subsystem
- [ ] Unified `InputEvent` struct: { timestamp, type (key/mouse/scroll), code, value }
- [ ] Kernel event ring buffer (per-device or global)
- [ ] `/dev/input/event0` (keyboard), `/dev/input/event1` (mouse)
- [ ] `read()` on event device returns events; blocks if empty
- [ ] `poll()` / `select()` support on event fds

### 12.3 — Framebuffer Device
- [ ] `/dev/fb0` character device node
- [ ] `ioctl(FBIOGET_VSCREENINFO)` — get resolution, bpp, stride
- [ ] `ioctl(FBIOPUT_VSCREENINFO)` — set mode (if HW supports)
- [ ] `mmap()` on `/dev/fb0` → map framebuffer physical memory into user process
- [ ] Double-buffering support (front/back buffer swap)

### 12.4 — Compositor (User-Mode Process)
- [ ] Window server daemon (`/sbin/compositor`)
- [ ] Shared memory protocol: clients allocate window buffer via `mmap(MAP_SHARED)`
- [ ] Window table: id, title, x, y, w, h, z-order, buffer_shm_fd, owning_pid
- [ ] Client API (`libastryxui`):
  - `create_window(title, w, h)` → window handle
  - `draw_rect(win, x, y, w, h, color)`
  - `draw_bitmap(win, x, y, w, h, pixels)`
  - `draw_text(win, x, y, text, color)`
  - `present(win)` — notify compositor that buffer is ready
- [ ] Compositor main loop:
  1. `poll()` on mouse + keyboard event devices
  2. Update cursor position from mouse deltas
  3. Dispatch keyboard/mouse events to focused window's client
  4. Composite: for each window (back-to-front), blit shared buffer to framebuffer
  5. Draw cursor sprite on top
  6. Swap to front buffer
- [ ] Window decorations: title bar, close/minimize buttons
- [ ] Window dragging by title bar
- [ ] Window focus: click-to-focus or follows-mouse
- [ ] Keyboard focus → route key events to focused window's client
- [ ] Desktop background (solid color or BMP)

### 12.5 — Terminal Emulator (GUI App)
- [ ] `astryxterm` — first GUI application
- [ ] PTY (pseudo-terminal): `/dev/ptmx` master + `/dev/pts/N` slave
- [ ] VT100/ANSI escape code parsing (reuse existing console parsing)
- [ ] Font rendering in window buffer (reuse 8x16 bitmap font)
- [ ] Spawn `/bin/sh` (or Orbit shell) connected to PTY
- [ ] Scrollback buffer
- [ ] Copy/paste (stretch)

**Milestone**: Draggable terminal windows on screen with mouse cursor. Multiple terminal instances.

---

## Phase 13 — Userspace & Toolchain

### 13.1 — C Toolchain & musl Port
- [x] **TinyCC 0.9.27** — static musl binary deployed to `/disk/bin/tcc`; compiles and runs C programs inside AstryxOS (Test 63 ✅, 2026-03-06)
  - Bug fix applied: `fill_local_got_entries` null-guard for `-nostdlib` builds
  - Runtime: `/disk/lib/tcc/libtcc1.a` + `/disk/lib/tcc/include/`
- [ ] Cross-compile musl libc targeting `x86_64-astryx-linux-musl` (or custom triple)
- [ ] Implement all syscalls musl requires (see Phase 8)
- [ ] `crt0.S` / `crt1.o` — C runtime startup (calls `__libc_start_main`)
- [ ] Static linking works (`musl-gcc -static hello.c`)
- [ ] Dynamic linking (stretch — `ld-musl.so`, `dlopen`/`dlsym`)

### 13.2 — Core Userspace
- [ ] `/sbin/init` (Ascension) — PID 1, reads config, starts services
- [ ] `/bin/sh` — port existing Orbit shell to user-mode, or port `dash`
- [ ] Coreutils subset: `ls`, `cat`, `echo`, `cp`, `mv`, `rm`, `mkdir`, `chmod`, `ps`, `kill`, `grep`, `wc`
- [ ] `/bin/login` — user authentication (optional, can default to auto-login)

### 13.3 — Package Format (stretch)
- [ ] Simple tar-based package format
- [ ] Package manager (`apkg`) to install/remove packages

---

## Dependency Graph (Critical Path)

```
Phase 6 (Memory)
  ├── 6.1 VMA
  ├── 6.2 Per-Process Page Tables
  │     └── 6.3 Page Fault Handler (CoW + demand paging)
  │           └── 6.4 mmap/munmap/brk
  └── 6.5 FPU Context
        │
        ▼
Phase 7 (Signals)
  └── 7.1-7.4
        │
        ▼
Phase 8 (Syscalls)  ◄──── Phase 9 (AHCI + Persistent FS)
  └── 8.1-8.7             └── 9.1-9.3
        │
        ▼
Phase 10 (SMP)
  └── 10.1-10.4
        │
        ▼
Phase 11 (TCP)
  └── 11.1-11.4
        │
        ▼
Phase 12 (GUI)  ◄──── depends on mmap, signals, poll, mouse
  └── 12.1-12.5
        │
        ▼
Phase 13 (Userspace + Toolchain)
```

**Notes**:
- Phase 9 (AHCI) can be done in parallel with Phases 7/8
- Phase 10 (SMP) can start as soon as Phase 6 is done (needs proper locking)
- Phase 12 (GUI) needs: mmap (6.4), signals (7), poll (11.3), mouse driver (12.1)
- Phase 11 (TCP) is mostly independent, can start any time after Phase 8

---

## Estimated Effort

| Phase | Scope | Relative Size |
|-------|-------|---------------|
| 6 — Memory | VMAs, per-process CR3, CoW, mmap, FPU | **XL** — most complex phase |
| 7 — Signals | Infrastructure, delivery, syscalls | **L** |
| 8 — Syscalls | ~50 new syscalls | **XL** |
| 9 — AHCI | PCI, AHCI driver, persistent FS | **L** |
| 10 — SMP | APIC, AP startup, locking, scheduler | **XL** |
| 11 — TCP | Full TCP, socket syscalls, poll/epoll | **XL** |
| 12 — GUI | Mouse, events, compositor, PTY | **L** |
| 13 — Userspace | musl port, init, shell, coreutils | **L** |

---

## Quick Win Targets (can do NOW without major infra)

These smaller items don't depend on the big phases and can be knocked out any time:

1. **`SYS_UNAME`** — trivial, musl calls it immediately
2. **`SYS_GETPPID`** — one-liner
3. **`SYS_GETCWD` / `SYS_CHDIR`** — uses existing PCB.cwd field
4. **`SYS_MKDIR` / `SYS_RMDIR`** — wire existing VFS calls to syscalls
5. **`SYS_STAT` / `SYS_FSTAT`** — wire existing VFS stat()
6. **`SYS_DUP` / `SYS_DUP2`** — fd table copy
7. **`SYS_PIPE`** — connect existing pipe to fd table
8. **`SYS_LSEEK`** — fd offset manipulation
9. **`SYS_GETRANDOM`** — read RDRAND instruction
10. **`SYS_NANOSLEEP`** — convert ns to ticks, call sleep_ticks()
