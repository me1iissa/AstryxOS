# Subsystem Implementation Plan — Phased Milestones

> Last updated: 2026-03-09 (Session 22)

## Phase 0 — Restructure ✅ COMPLETE

**Goal**: Clean up the current code to establish proper subsystem boundaries.

### 0.1 — Create `kernel/src/subsys/` module tree ✅
```
kernel/src/subsys/
├── mod.rs       — SubsystemManager, detect_elf_subsystem(), subsystem_name()
├── aether/
│   └── mod.rs   — pub dispatch() → crate::syscall::dispatch_aether()  [wired ✓]
├── linux/
│   └── mod.rs   — pub dispatch() → crate::syscall::dispatch_linux()   [wired ✓]
└── win32/
    └── mod.rs   — Win32 architecture stub
```
Physical code migration (dispatch bodies → subsys/) deferred to Phase 0.5.

### 0.2 — Unify SubsystemType ✅
- `SubsystemType::Posix` → `SubsystemType::Aether` (renamed)
- `SubsystemType::Linux` added as 4th variant
- `Process.linux_abi: bool` kept for compat; `is_linux_abi()` checks both
- All exec/fork/shell/signal/test sites updated to set `.subsystem`

### 0.3 — Update syscall entry point ✅
- `syscall::dispatch()` is now a thin router:
  - `is_linux_abi()` → `dispatch_linux()`  (routes to `subsys::linux` path)
  - else → `dispatch_aether()`             (routes to `subsys::aether` path)
- `dispatch_aether()` extracted as `pub fn` in `syscall/mod.rs`
- Dep direction: `subsys::*` → `syscall` (one-way, no circular dep)

### 0.4 — ELF subsystem auto-detection ✅
- `subsys::detect_elf_subsystem(elf_bytes)` reads OS/ABI byte + PT_INTERP
- Returns `SubsystemType::Linux` or `SubsystemType::Aether`
- Used by exec path and ELF loader

### 0.5 — Physical code migration (deferred)
Move implementation bodies out of `syscall/mod.rs`:
- `dispatch_aether()` + Aether helpers → `subsys/aether/syscall.rs`
- `dispatch_linux()` + Linux helpers → `subsys/linux/syscall.rs`
- Shared helpers (sys_mmap, sys_brk, sys_lseek…) → `syscall/shared.rs`

**Deliverable**: All 56 tests pass with restructured routing. ✅ Verified.

---

## Phase 1 — Linux Subsystem Hardening (🔧 in progress)

**Goal**: Enough Linux syscall coverage to run `bash` and basic coreutils.

### 1.1 — Complete stub syscalls (partial ✅)
- `nanosleep` ✅ — Real `struct timespec` parsing, `proc::sleep_ticks()`
- `ftruncate` ✅ — VFS `fd_truncate()` (was stub)
- `setsockopt` / `getsockopt` — still stubs (return 0)
- `sigaltstack` — still stub (return 0)

## Phase 1 — Linux Subsystem Hardening (🔧 in progress)

**Goal**: Enough Linux syscall coverage to run `bash` and basic coreutils.

### 1.1 — Complete stub syscalls (partial ✅)
- `nanosleep` ✅ — Real `struct timespec` parsing, `proc::sleep_ticks()`
- `ftruncate` ✅ — VFS `fd_truncate()` (was stub)
- `setsockopt` / `getsockopt` — still stubs (return 0)
- `sigaltstack` — still stub (return 0)

### 1.2 — Add missing critical syscalls (batch 1 ✅  batch 2 ✅)
- `select` (23) ✅ — fd_set bitmask poll
- `mremap` (25) ✅ — grow/shrink/move anonymous mappings
- `pipe` (22) ✅ — real pipe pair allocation; write `[u64; 2]` fds
- `msync` (26) ✅ — stub 0 (no writeback needed for RAM-backed pages)
- `mincore` (27) ✅ — fills all-resident vec
- `truncate` (76) ✅ — path-based VFS truncate
- `chmod` (90) ✅ — delegates to vfs::chmod()
- `fchmod/chown/fchown/lchown` (91-94) ✅ — stubs (return 0)
- `umask` (95) ✅ — per-process mask get/set
- `getrlimit` (97) ✅ — returns POSIX defaults; prlimit64 GET wired
- `times` (100) ✅ — zeroed struct tms
- `setuid/setgid` (105/106) ✅ — stubs 0
- `setreuid` (114) ✅ — stub 0
- `getgroups/setgroups` (115/116) ✅ — 0/stub
- `setresuid/getresuid/setresgid/getresgid` (117-120) ✅ — stubs/zero-fill
- `setpgid/getpgrp/setsid/getpgid/getsid` (109/111/112/121/122) ✅ — stubs
- `rt_sigpending/rt_sigtimedwait/rt_sigsuspend` (127/128/130) ✅ — 0/EINTR
- `chroot` (161) ✅ — stub 0
- `sync` (162) ✅ — calls vfs::sync_all()
- `uname` (63) ✅ — delegates to sys_uname()
- `clock_nanosleep` (230) ✅ — delegates to nanosleep
- `pselect6` (270) ✅ — delegates to sys_select_linux()
- `renameat2` (316) ✅ — delegates to vfs::rename()
- `close_range` (355) ✅ — closes fds in [lo,hi] range
- `dup3` (292) ✅ — delegates to sys_dup2
- `epoll_create1/ctl/wait` (213/232/233/281/291) ✅ — Real impl: sys_epoll_create1/ctl/wait; EpollInstance per-process; pipe read/write-end aware polling; fd cleanup on close

### 1.3 — Linux `/proc` filesystem enhancements
- `/proc/self/exe` ✅ — readlink returns exe_path
- `/proc/self/maps` ✅ — Virtual memory layout (done earlier)
- `/proc/self/status` ✅ — `refresh_proc_status(pid)` generates live content on open
- `/proc/self/fd/N` ✅ — readlink(89) returns `fd.open_path` or `/dev/fd/N` fallback
- `/proc/self/fd/` getdents64 ✅ — `getdents64_proc_fd()` synthesises `.`, `..`, numeric entries
- `/proc/cpuinfo`, `/proc/meminfo` ✅ — static stubs (written in vfs::init)

### 1.4 — Linux errno mapping ✅
- `subsys/linux/errno.rs` — 133 named constants (EPERM…EHWPOISON), `neg()`, `vfs_err()`, `ntstatus_to_errno()`
- `vfs_err(VfsError)` used throughout `syscall/mod.rs` (replaced 25 `-(e as i64)` forms)
- `pub mod errno` + common re-exports added to `subsys/linux/mod.rs`
- VfsError discriminants already match Linux errno values ✅

### 1.5 — bash/coreutils compatibility baseline ✅
- **Job-control TTY ioctls** (`kernel/src/drivers/tty.rs`) added:
  - `TIOCGPGRP` (0x540f) — returns current PID as foreground pgrp
  - `TIOCSPGRP` (0x5410) — silently accepts new pgrp
  - `TIOCSCTTY` (0x540e) — stub: make controlling terminal (always OK)
  - `TIOCNOTTY` (0x5422) — stub: release controlling terminal (always OK)
  - `TIOCSWINSZ` (0x5414) — stub: accept new window size quietly
  - `TIOCGETSID` (0x5429) — returns current PID as session leader PID
- **`/etc` stubs** added to `vfs::init()` (`kernel/src/vfs/mod.rs`):
  - `/etc/passwd`  — `root:x:0:0:root:/root:/bin/sh` + nobody line
  - `/etc/shadow`  — minimal stub (suppresses hard errors in libc)
  - `/etc/group`   — `root:x:0:` + nogroup line
  - `/etc/shells`  — `/bin/sh`, `/bin/bash`
  - `/etc/nsswitch.conf` — `passwd:files group:files hosts:files`
  - `/etc/profile` — PATH/HOME/TERM exports
  - `/root` home directory created
  - `/etc/localtime` — empty stub (glibc falls back to UTC)
- **`waitid` (247)** implemented in `syscall/mod.rs`:
  - Supports P_ALL/P_PID/P_PGID idtype
  - WEXITED required; WNOHANG respected
  - Fills minimal `siginfo_t` (si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid)
  - Delegates to existing `sys_waitpid`
- **`prctl` (157) extended**:
  - `PR_SET_CHILD_SUBREAPER` (36) + `PR_GET_CHILD_SUBREAPER` (37) — stub
  - `PR_SET_NO_NEW_PRIVS` (38) + `PR_GET_NO_NEW_PRIVS` (39) — accept
  - `PR_SET_SECCOMP` (22) + `PR_GET_SECCOMP` (21) — accept / MODE_DISABLED
  - `PR_SET/GET_KEEPCAPS` (8/7), `PR_CAP_AMBIENT` (47) — stub 0
- **Test 60** `test_bash_compat()` — 12 sub-checks:
  - TIOCGPGRP on fd 0 returns 0 with valid pgrp
  - TIOCSPGRP on fd 0 returns 0
  - TIOCSCTTY on fd 0 returns 0
  - TIOCGETSID on fd 0 returns 0 with valid sid
  - prctl(PR_SET_CHILD_SUBREAPER), prctl(PR_SET_NO_NEW_PRIVS), prctl(PR_SET_SECCOMP) → 0
  - /etc/passwd, /etc/group, /etc/shells, /etc/nsswitch.conf all open and have expected content
  - waitid(WNOHANG, no-child) → 0 or -ECHILD (non-fatal)
- **60/60 tests passing** ✅

**Deliverable**: Static musl `ls`, `cat`, `echo` run successfully.

---

## Phase 2 — Win32 Subsystem Foundation

**Goal**: Load and execute a minimal Win32 PE console application.

### 2.1 — PE loader ✅ (Session 22, 2026-03-06)
- [x] Parse DOS/PE headers, COFF, optional header
- [x] Map sections with correct page protections
- [x] Apply base relocations
- [x] Build import address table (IAT)

### 2.2 — ntdll.dll stub ✅ (Session 22, kernel-side stubs)
- [x] `NtTerminateProcess` / `NtTerminateThread`
- [x] `NtWriteFile` / `NtReadFile` / `NtClose`
- [x] `NtAllocateVirtualMemory` / `NtFreeVirtualMemory`
- [x] Embedded as kernel-side stubs in `crate::nt`

### 2.3 — NT syscall dispatch ✅ (Session 22, 2026-03-06)
- [x] INT 0x2E handler in IDT (`isr_syscall_int2e`)
- [x] SSDT table (43 NT service numbers, 60+ stub entries)
- [x] NT calling convention → C calling convention translation
- [x] `dispatch_nt()` routing to all service stubs

### 2.4 — kernel32.dll stub ✅ (Session 23, 2026-03-06)
- [x] `ExitProcess` forwarded to NtTerminateProcess
- [x] `ReadFile` / `WriteFile` kernel stubs
- [x] `WriteConsoleA` / `WriteConsoleW` (UTF-16 → ASCII passthrough)
- [x] `GetStdHandle` (pseudo-handles → fd 0/1/2)
- [x] `GetCommandLineA` / `GetCommandLineW` (static "hello.exe" strings)
- [x] `GetProcessHeap` / `HeapAlloc` / `HeapFree` / `HeapReAlloc` / `HeapSize`
- [x] `VirtualAlloc` / `VirtualFree` / `VirtualQuery`
- [x] `GetLastError` / `SetLastError` / `IsDebuggerPresent`
- [x] `GetCurrentProcessId` / `GetCurrentThreadId` / `GetCurrentProcess` / `GetCurrentThread`
- [x] `OutputDebugStringA` / `OutputDebugStringW` (serial console)
- [x] `GetSystemInfo` (SYSTEM_INFO: AMD64, 4K pages, 1 CPU)
- [x] `QueryPerformanceCounter` / `QueryPerformanceFrequency`
- [x] `Sleep` (Linux nanosleep)
- [x] `SetConsoleCtrlHandler` / `GetConsoleMode` / `SetConsoleMode`
- [x] Bug fix: `nt_prot_to_posix` PAGE_READWRITE now correctly gives PROT_READ|PROT_WRITE

**Deliverable**: Win32 PE console infrastructure complete — a static Win32 console binary importing kernel32.dll would have all IAT entries resolved and a working execution path. Hello World deliverable is complete at the stub layer (Test 62 confirms all stubs callable and functional).

---

## Phase 3 — Compiler Toolchain (Linux subsystem)

**Goal**: Cross-compile a C program inside AstryxOS and execute it.

### 3.1 — Port musl libc
- Cross-compile musl for x86_64-astryx target
- Verify `libc.a` links and produces working static binaries

### 3.2 — Port TinyCC (tcc)
- Smallest self-contained C compiler
- Needs: open, read, write, close, mmap, exec, fork, waitpid
- Single binary, no external dependencies

### 3.3 — Port GCC (stretch)
- Needs full POSIX: pipe, dup2, fork, exec, wait4, signal
- Needs `/tmp` filesystem
- Needs working dynamic linker (ld-musl)

**Deliverable**: `tcc -o hello hello.c && ./hello` works inside AstryxOS.

---

## Phase 4 — Framebuffer + X11 Compatibility

**Goal**: Run existing X11 applications on AstryxOS.

### 4.1 — Framebuffer improvements ✅ (Session 22)
- Dirty rectangle tracking (avoid 8MB full-frame blits)
- Double buffering with page-flip
- Hardware cursor (✅ implemented)

### 4.2 — X11 protocol server (Xastryx) ✅ (Session 22)
- [x] Minimal X11 server running in kernel (`kernel/src/x11/`)
- [x] Communicates with clients via Unix domain sockets
- [x] Maps X11 drawing requests to GDI/compositor operations
- [x] Connection setup handshake (Test 64)
- [x] InternAtom RPC (Test 65)
- [x] CreateWindow + MapWindow + Draw cycle (Test 66)
- [x] Key event injection + delivery (part of Test 66)

**Higher-half kernel bug fix** (critical, also Session 22):
- Root cause: kernel VMA=LMA=physical (0x100000+) caused kernel statics at
  0x400000–0x472700 to be aliased by user ELF page tables (TCC loaded 131 pages there)
- Fix: `kernel/linker.ld` uses `KERNEL_VIRT_BASE + KERNEL_PHYS_BASE` as VMA with
  `AT(VMA - KERNEL_VIRT_BASE)` for LMA; bootloader jumps to higher-half entry
- All statics now at 0xFFFF800000... accessible via PML4[256]

### 4.3 — X11 shared memory extension (MIT-SHM)
- `shm_open` / `mmap` for shared pixmaps
- Zero-copy blit from client to server

### 4.4 — xterm / simple X11 app
- Port xterm or st (simple terminal)
- Verify keyboard/mouse input pipeline works through X11

**Deliverable**: `xterm` window appears on screen with working shell inside.

---

## Phase 5 — Ascension Init System

**Goal**: Proper system initialization, service management, multi-user.

### 5.1 — Ascension core
- PID 1 init process (already exists as ELF)
- Parse `/etc/ascension.conf` configuration
- Mount filesystems from fstab
- Set hostname, timezone

### 5.2 — Service management
- Service definitions (name, binary, dependencies, restart policy)
- Dependency-ordered startup
- `ascctl start|stop|restart|status <service>`

### 5.3 — Login / multi-user
- `login` program (authenticate, setuid, spawn shell)
- `/etc/passwd`, `/etc/shadow` (basic)
- Console allocation per virtual terminal

**Deliverable**: System boots → Ascension → mounts FS → starts services → login prompt.

---

## Priority Summary

| Phase | Priority | Estimated Effort | Depends On |
|-------|----------|-----------------|------------|
| Phase 0 (Restructure) | **P0 — Now** | 1 session | Nothing |
| Phase 1 (Linux hardening) | **P0 — Next** | 2-3 sessions | Phase 0 |
| Phase 2 (Win32 foundation) | P1 | 3-4 sessions | Phase 0 |
| Phase 3 (Compiler) | P1 | 2-3 sessions | Phase 1 |
| Phase 4 (X11) | P2 | 4-5 sessions | Phase 1, Phase 4.1 |
| Phase 5 (Ascension) | P2 | 2-3 sessions | Phase 1 |
