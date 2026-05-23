# Firefox Critical-Path Coverage Gap Matrix

**Date:** 2026-05-23
**Audience:** AstryxOS coordinators / specialists
**Scope:** What Firefox on Linux *actually exercises* end-to-end, cross-referenced against
AstryxOS subsystems. Companion to `LINUX_SYSCALL_COVERAGE.md` (per-syscall audit) — this
doc frames coverage by *FF stage*, not by syscall number.

This is a survey, not an implementation plan. It exists so the next bounded
investigation chooses the right axis instead of grinding on syscalls Firefox
never touches.

## Sources

Public specs and Mozilla documentation only:

- Mozilla seccomp-bpf whitelist source: `security/sandbox/linux/SandboxFilter.cpp`
  (mozilla-central, raw view via `raw.githubusercontent.com/mozilla/gecko-dev`)
- Firefox system requirements: `firefox.com/en-US/firefox/system-requirements/`
  (glibc 2.17+, GTK+ 3.14+, libglib 2.42+, libstdc++ 4.8.1+, X.Org 1.0+)
- Mozilla wiki, `Security/Sandbox/Seccomp` (sandbox model overview)
- Mozilla IPC docs: `firefox-source-docs.mozilla.org/ipc/ipdl.html`
- Linux man pages (man7.org): `vdso(7)`, `clone(2)`, `futex(2)`, `mmap(2)`,
  `prctl(2)`, `seccomp(2)`, `set_robust_list(2)`, `getauxval(3)`
- kernel.org Documentation: `cgroup-v2`, `robust-futexes`, `vDSO`
- POSIX.1-2017 (pubs.opengroup.org)
- ELF gABI §5 (TLS, dynamic linking)
- Intel SDM Vol. 3A §2.5 (CR4 control bits)

Reviewed Mozilla bugzillas (public): #1198550 (/proc/self/maps), #1303813 +
#1406304 (MADV_FREE seccomp + jemalloc), #1273852 + #942698 (seccomp violations),
#1571290 (clock_gettime64 in 32-bit profile), #1129492 (X11 connection in
content process), #1480755 + #1640053 (glxtest / EGL).

## Executive summary

Firefox on Linux exercises ~120 distinct syscalls in steady state (per Mozilla's
allow-list policy), plus ~25 X11 opcodes (core + RENDER + MIT-SHM + extensions),
plus the vDSO (4 symbols on x86_64), plus the auxv (~14 entries consumed by
glibc/musl + IFUNC resolvers).

Against this:

- **Syscalls** — 206 dispatched arms exist in `kernel/src/subsys/linux/syscall.rs`;
  superset of Mozilla's whitelist with two important *behavioural* gaps
  (`set_robust_list` and `futex_waitv`, both ENOSYS by default arm).
- **vDSO** — 4/4 x86_64 symbols implemented (`__vdso_clock_gettime`,
  `__vdso_gettimeofday`, `__vdso_time`, `__vdso_getcpu`), TSC-derived,
  matches syscall path (vDSO audit clean, 2026-05-18).
- **Auxv** — 12 of the ~14 entries glibc/musl actually consume on x86_64 are
  emitted (`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_BASE`, `AT_ENTRY`, `AT_PAGESZ`,
  `AT_HWCAP`, `AT_HWCAP2`, `AT_CLKTCK`, `AT_RANDOM`, `AT_UID/EUID/GID/EGID`,
  `AT_SYSINFO_EHDR`). **Gaps:** `AT_EXECFN`, `AT_PLATFORM`, `AT_SECURE` —
  the first is consulted by musl's `__progname`, the third gates SUID hardening
  (we never run SUID so 0 is correct, but the entry should be present).
- **X11** — 11 extensions advertised and dispatched (MIT-SHM, BIG-REQUESTS,
  XKEYBOARD, SHAPE, RENDER, XFIXES, DAMAGE, SYNC, COMPOSITE, XInputExtension,
  XTEST). **Gaps:** GLX, DRI3, RandR (RANDR string is advertised in
  `query_extension` list but not dispatched), Present extension. For a
  *headless* PNG screenshot via llvmpipe/softpipe, none of these are mandatory
  (Mesa software rasterisers route through XCB/RENDER without DRI3).
- **AF_UNIX** — STREAM + SEQPACKET, `SCM_RIGHTS` fd-passing via sendmsg/recvmsg,
  `SO_PEERCRED`. **Gap:** `SOCK_DGRAM` AF_UNIX (less commonly used by FF; D-Bus
  prefers it).
- **CPU security** — SMEP + SMAP + UMIP enabled at boot (CR4 bits 20/21/11)
  per Intel SDM Vol. 3A §2.5; NX always on.

**Top-5 likely "missing integral" items**, in order of how often they could
gate Firefox:

1. **`set_robust_list(2)` and the kernel-side robust-futex unlock path** —
   ENOSYS. glibc 2.34+ NPTL calls this once per thread; without it, robust
   mutexes leak on thread death. Per `robust-futexes.txt`: "if a thread fails to
   unlock a futex before terminating ... another thread that is waiting on that
   futex is notified that the former owner of the futex has died." Firefox uses
   robust mutexes in mozjemalloc and several IPC primitives. Symptom: silent
   deadlock when a thread is killed mid-critical-section.
2. **`futex_waitv(2)`** — ENOSYS. Linux 5.16+ vectored multi-futex wait. Firefox
    115+ (Rust std with futex-based parking) opportunistically uses it; on
   ENOSYS, Rust std falls back to `futex(FUTEX_WAIT)` so this is currently
   tolerated, but the fallback path is a *fewer-wake-paths* path that
   contributes to the W101 plateau character.
3. **`AT_EXECFN` auxv entry** — Absent. musl's `__progname_full` falls back to
   `argv[0]` when absent (correct per `getauxval(3)`), so binaries run; but
   sandbox probes (and `/proc/self/exe` consistency checks) may diverge from
   reality. Cheap to add (~3 lines in `proc/elf.rs` auxv build).
4. **`/proc/self/mountinfo` residual deficiencies** — Canonical 11-column
   emitter is PRESENT (`vfs/procfs.rs:876-950`); the refuse-all-cascade risk
   from an earlier-draft "empty stub" characterisation is already mitigated.
   Residual: bind-mount support, optional_fields column, octal-escape of
   path control bytes. Smaller scope (~30-50 LOC) than initially framed.
   Cite: Mozilla bz #1198550.
5. **MAP_HUGETLB / 2 MiB huge mapping support** — Absent. jemalloc tries
   `mmap(... MAP_HUGETLB)` opportunistically; we silently return EINVAL via
   the default-flag check. jemalloc handles this gracefully (falls back to 4 K)
   so this is *latent*, but explains some of the elevated PMM pressure under
   Firefox-test runs.

The four prominent items that we have been investigating but the gap matrix
shows are **NOT** on the Firefox critical path (potential time-savers):

- **`io_uring`** — Mozilla seccomp whitelist contains no `io_uring_*` syscalls;
  Firefox does not use it.
- **`landlock_*` (syscalls 443–445)** — ENOSYS-fine; not used by Firefox.
- **`pidfd_*` (syscalls 424/434)** — ENOSYS-fine; Firefox uses regular
  `clone(2)` + `wait4(2)` for content-process lifecycle.
- **`fanotify_*` (300/301)** — ENOSYS-fine, Firefox probes presence and falls
  back per Mozilla source comments. Confirmed by AstryxOS source comment
  (`kernel/src/subsys/linux/syscall.rs:4365`).

## Stage-by-stage matrix

Columns: **FF-dep** = mandatory / soft (FF probes and falls back) / optional;
**Status** = present (P) / partial (p) / absent (—); **AstryxOS ref** =
authoritative source location; **Spec** = public spec citation.

### Stage 1 — Process bringup (ELF loader / dynamic linker / auxv / vDSO)

| Feature | FF-dep | Status | AstryxOS ref | Spec |
|---|---|---|---|---|
| ELF64 magic + PT_LOAD | mandatory | P | `kernel/src/proc/elf.rs` | ELF gABI §5.1 |
| PT_INTERP (musl ld-musl-x86_64.so.1 / glibc ld-linux-x86-64.so.2) | mandatory | P | `proc/elf.rs:54` (INTERP cache) | ELF gABI §5.4 |
| PT_DYNAMIC parsing | mandatory | P | `proc/elf.rs:496` | ELF gABI §5.5 |
| PT_TLS (memsz > filesz BSS zero-fill) | mandatory | P | `proc/elf.rs` + `subsys/linux/d7_bss_watch.rs` | ELF gABI §5.2 |
| PT_GNU_RELRO (read-only relocations) | mandatory | p | parsed but RELRO not enforced (mprotect after relocations not applied by loader) | ELF gABI §5; binutils ld manual |
| PT_GNU_STACK (NX-stack hint) | mandatory | P (always NX) | x86_64 NX always enforced | ELF gABI §5; Intel SDM Vol. 3A §4.6 |
| DT_RELR / DT_RELRSZ / DT_RELRENT | mandatory (modern musl/glibc) | P | `proc/elf.rs:386-565` | RELR proposal (Wladimir van der Laan, 2018) |
| DT_GNU_HASH | mandatory | P (parsed) | `proc/elf.rs:564-566` | gnu-hash spec (Roland McGrath 2006) |
| R_X86_64_TPOFF64 / R_X86_64_DTPOFF / R_X86_64_DTPMOD (TLS relocations) | mandatory | P (applied at load) | `proc/elf.rs` + ABI tests in `test_runner` | System V AMD64 ABI §4.4 |
| AT_PHDR / AT_PHENT / AT_PHNUM | mandatory | P | `proc/elf.rs:1305-1307` | ELF gABI §6 |
| AT_BASE | mandatory (PIE) | P | `proc/elf.rs:1309` | ELF gABI §6 |
| AT_ENTRY | mandatory | P | `proc/elf.rs:2035` | ELF gABI §6 |
| AT_PAGESZ | mandatory | P | `proc/elf.rs:2035` | getauxval(3) |
| AT_RANDOM (SSP seed) | mandatory | P | `proc/elf.rs:1899,2038` | getauxval(3); musl `__init_ssp` |
| AT_HWCAP / AT_HWCAP2 (CPUID-derived) | mandatory (IFUNC resolvers) | P | `proc/elf.rs:1352-1353,2035-2036` | getauxval(3); System V AMD64 ABI §3.4.3 |
| AT_CLKTCK | mandatory | P | `proc/elf.rs:1957` | getauxval(3) |
| AT_UID/EUID/GID/EGID | mandatory | P | `proc/elf.rs:1957` | getauxval(3) |
| AT_SYSINFO_EHDR (vDSO base) | mandatory | P | `proc/vdso.rs:105,237` | vdso(7) |
| AT_EXECFN | soft (musl `__progname_full` fallback to argv[0]) | — | absent in build | getauxval(3) |
| AT_PLATFORM | optional | — | absent | getauxval(3) |
| AT_SECURE | mandatory (SUID hardening gate; 0 correct for us) | — | absent | getauxval(3) |
| __vdso_clock_gettime | mandatory (perf-critical) | P | `proc/vdso.rs` (PR #128 syscall-vDSO formula match) | vdso(7) |
| __vdso_gettimeofday | mandatory | P | `proc/vdso.rs` | vdso(7) |
| __vdso_time | soft | P | `proc/vdso.rs` | vdso(7) |
| __vdso_getcpu | soft (sched\_getcpu fallback exists) | P | `proc/vdso.rs` | vdso(7) |

### Stage 2 — Threading + IPC (clone, futex, signals, fd-passing)

| Feature | FF-dep | Status | AstryxOS ref | Spec |
|---|---|---|---|---|
| `clone(2)` CLONE_VM / CLONE_THREAD / CLONE_FS / CLONE_FILES / CLONE_SIGHAND / CLONE_SETTLS | mandatory | P | `subsys/linux/syscall.rs:1014-2484` | clone(2) man page |
| `clone(2)` CLONE_CHILD_CLEARTID / CLONE_PARENT_SETTID / CLONE_CHILD_SETTID | mandatory | P | `subsys/linux/syscall.rs:2256-2270` | clone(2) man page |
| `clone(2)` CLONE_VFORK semantics (parent blocks until execve/exit) | mandatory | P | `subsys/linux/syscall.rs:2404+` | clone(2) man page |
| `clone3(2)` (nr=435) | soft (glibc 2.34+ prefers, falls back to clone) | P | `subsys/linux/syscall.rs:3265-3360` | clone3(2) man page |
| `set_tid_address(2)` (nr=218) | mandatory | P | `subsys/linux/syscall.rs:5829` | set_tid_address(2) man page |
| `set_robust_list(2)` (nr=273) + robust-futex wake-on-death | mandatory (NPTL) | p | nr=273 dispatch PRESENT (`syscall.rs:2815`), stores `(head, len)`; **wake-on-death walker MISSING** (`proc/mod.rs:2420-2425` self-documents the omission) | set_robust_list(2); kernel.org `robust-futexes.txt` |
| `get_robust_list(2)` (nr=274) | optional (debugger only) | y | nr=274 dispatch PRESENT (`syscall.rs:2837`) — round-trips stored head/len | get_robust_list(2) man page |
| `futex(2)` FUTEX_WAIT / FUTEX_WAKE / FUTEX_PRIVATE_FLAG | mandatory | P | `subsys/linux/syscall.rs:7486+` | futex(2) man page |
| `futex(2)` FUTEX_REQUEUE / FUTEX_CMP_REQUEUE | mandatory (pthread_cond) | P | `subsys/linux/syscall.rs:7466-7468` | futex(2) man page |
| `futex(2)` FUTEX_WAIT_BITSET / FUTEX_WAKE_BITSET | mandatory (priority-inherit) | p (bitset accepted but treated as MATCH_ANY) | `subsys/linux/syscall.rs:7470-7471` | futex(2) man page |
| `futex(2)` FUTEX_CLOCK_REALTIME | mandatory (absolute timeouts) | P | `subsys/linux/syscall.rs:7475` | futex(2) man page |
| `futex(2)` FUTEX_WAKE_OP | optional | — | ENOSYS | futex(2) man page |
| `futex_waitv(2)` (nr=449) | soft (Rust std opportunistic) | — | ENOSYS via default arm | futex_waitv(2) man page (Linux 5.16+) |
| `rt_sigaction(2)` SA_SIGINFO + 3-arg handler + ucontext_t | mandatory | P | `subsys/linux/syscall.rs:6898` + `signal.rs` | rt_sigaction(2) man page |
| `rt_sigprocmask(2)` | mandatory | P | `subsys/linux/syscall.rs:7032` | rt_sigprocmask(2) man page |
| `sigaltstack(2)` | mandatory (SIGSEGV on user stack) | P | `signal.rs` | sigaltstack(2) man page |
| `rt_sigreturn(2)` (syscall 15) | mandatory | P | dispatched | rt_sigreturn(2) man page |
| `tgkill(2)` / `tkill(2)` | mandatory | P | dispatched | tgkill(2) man page |
| `pipe2(2)` (nr=293) | mandatory | P | `subsys/linux/syscall.rs:8116` | pipe2(2) man page |
| `eventfd2(2)` (nr=290) | mandatory | P | `subsys/linux/syscall.rs:8060` | eventfd(2) man page |
| `signalfd4(2)` (nr=289) | soft | P | `subsys/linux/syscall.rs:8890` | signalfd(2) man page |
| `epoll_create1(2)` / `epoll_ctl(2)` / `epoll_pwait(2)` | mandatory | P | `subsys/linux/syscall.rs:8617-8780` | epoll_pwait(2) man page |
| `epoll_pwait2(2)` | soft (timespec timeout) | — | ENOSYS | epoll_pwait2(2) man page |
| `socketpair(2)` (nr=53) | mandatory (Mojo) | P | `subsys/linux/syscall.rs:2041` | socketpair(2) man page |
| AF_UNIX SOCK_STREAM | mandatory | P | `net/unix.rs:42` | unix(7) |
| AF_UNIX SOCK_SEQPACKET | mandatory (Mojo channel framing) | P | `net/unix.rs:44` | unix(7) |
| AF_UNIX SOCK_DGRAM | soft (D-Bus prefers) | — | not in `SocketType` enum | unix(7) |
| `sendmsg(2)` + `SCM_RIGHTS` (fd-passing) | mandatory (Mojo handles) | P | `subsys/linux/syscall.rs:1590-1730` | unix(7); cmsg(3) |
| `recvmsg(2)` + `SCM_RIGHTS` + `MSG_TRUNC` | mandatory | P | `subsys/linux/syscall.rs:1727-1840` | recvmsg(2); cmsg(3) |
| `SO_PEERCRED` (getsockopt) | mandatory (D-Bus, sandbox identity) | P | `net/unix.rs:213,707` | unix(7) |

### Stage 3 — Memory + I/O (mmap, mprotect, madvise, procfs)

| Feature | FF-dep | Status | AstryxOS ref | Spec |
|---|---|---|---|---|
| `mmap(2)` MAP_PRIVATE / MAP_ANONYMOUS / MAP_FIXED | mandatory | P | `subsys/linux/syscall.rs` (nr=9) | mmap(2) man page |
| `mmap(2)` MAP_STACK | mandatory (pthread stacks) | p (accepted but treated as anonymous) | dispatched | mmap(2) man page |
| `mmap(2)` MAP_NORESERVE | mandatory (jemalloc large arenas) | p | dispatched | mmap(2) man page |
| `mmap(2)` MAP_POPULATE | soft | P | dispatched | mmap(2) man page |
| `mmap(2)` MAP_HUGETLB / 2 MiB | soft (jemalloc opportunistic) | — | EINVAL on flag | mmap(2) man page; `memfd_create(2)` MFD_HUGETLB |
| `mprotect(2)` | mandatory | P | `subsys/linux/syscall.rs:5925` | mprotect(2) man page |
| `mremap(2)` | mandatory (jemalloc resize, Mozilla bz #1286119) | P | `subsys/linux/syscall.rs:4863` | mremap(2) man page |
| `madvise(2)` MADV_DONTNEED | mandatory | P | dispatched | madvise(2) man page |
| `madvise(2)` MADV_FREE | mandatory (mozjemalloc with new headers — Mozilla bz #1406304) | P | dispatched | madvise(2) man page |
| `madvise(2)` MADV_HUGEPAGE | soft | P (ignored) | dispatched | madvise(2) man page |
| `brk(2)` (nr=12) | mandatory (glibc malloc fallback) | P | dispatched | brk(2) man page |
| `prctl(2)` PR_SET_NAME / PR_GET_NAME | mandatory (thread name) | P | `subsys/linux/syscall.rs:2619` | prctl(2) man page |
| `prctl(2)` PR_SET_DUMPABLE | mandatory | P | `subsys/linux/syscall.rs:2629` | prctl(2) man page |
| `prctl(2)` PR_SET_PDEATHSIG | mandatory | P | `subsys/linux/syscall.rs:2636` | prctl(2) man page |
| `prctl(2)` PR_SET_NO_NEW_PRIVS | mandatory (precondition for seccomp) | P (accepts, no enforcement) | `subsys/linux/syscall.rs:2723` | kernel.org `no_new_privs.txt` |
| `prctl(2)` PR_SET_SECCOMP | mandatory (FF sandbox) | P (accepts MODE_FILTER, no enforcement) | `subsys/linux/syscall.rs:2740` | seccomp(2) man page; `seccomp_filter.txt` |
| `prctl(2)` PR_CAPBSET_READ / PR_CAPBSET_DROP | soft | P | `subsys/linux/syscall.rs:2680-2692` | prctl(2); capabilities(7) |
| `arch_prctl(2)` ARCH_SET_FS / ARCH_GET_FS | mandatory (TLS) | P | `subsys/linux/syscall.rs:5751` | arch_prctl(2) man page; Intel SDM Vol. 3A §3.4.4 |
| `seccomp(2)` SECCOMP_SET_MODE_FILTER | mandatory (FF sandbox) | p (PR_SET_SECCOMP path accepts; nr=317 seccomp not separately dispatched but same handler) | linked via prctl path | seccomp(2) man page |
| `getrandom(2)` (nr=318) | mandatory | P | `subsys/linux/syscall.rs:3180` | getrandom(2) man page |
| `prlimit64(2)` (nr=302) | mandatory | P | `subsys/linux/syscall.rs:3158` | prlimit(2) man page |
| `getrlimit(2)` (nr=97) / `setrlimit(2)` | mandatory | P | `subsys/linux/syscall.rs:3924` | getrlimit(2) man page |
| `/proc/self/maps` | mandatory (Mozilla bz #1198550 — Profiler reads to find loaded objects) | P | `vfs/procfs.rs:179` | proc(5) man page |
| `/proc/self/auxv` | mandatory | P | `vfs/procfs.rs` (via auxv_snap) | proc(5) man page |
| `/proc/self/cmdline` | mandatory | P | `vfs/procfs.rs` | proc(5) man page |
| `/proc/self/exe` (symlink) | mandatory | P | `vfs/procfs.rs:486` | proc(5) man page |
| `/proc/self/fd/<N>` (symlinks) | mandatory (Mojo handle passing) | P | `vfs/procfs.rs:155,295,486` | proc(5) man page |
| `/proc/self/status` | mandatory (Mozilla sandbox parsers) | P | `vfs/procfs.rs` (46-key per 2026-05-18 expansion) | proc(5) man page |
| `/proc/self/mountinfo` | mandatory (sandbox policy enumerates fs) | y | `vfs/procfs.rs:876-950` (`generate_mountinfo`) — residual gaps: bind-mounts, optional_fields, octal-escape | proc(5) man page |
| `/proc/self/cgroup` | mandatory (cgroup-aware code reads `0::/\n`) | P | `vfs/procfs.rs:273` | cgroup-v2 docs |
| `/proc/self/oom_score_adj` | soft (Mozilla writes here, see source comment) | P | `vfs/procfs.rs:197,276` | proc(5) man page |
| `/proc/self/loginuid` | soft (audit) | P (returns -1) | `vfs/procfs.rs:200,279` | audit(7) |
| `/proc/self/task/<tid>/stat` | mandatory (glibc start_thread per source comment) | P | `vfs/procfs.rs:77,82,286` | proc(5) man page |
| `/proc/cpuinfo` | mandatory (libstdc++ stdlib detect) | P | `vfs/procfs.rs:514` (CPUID-derived) | proc(5) man page |
| `/proc/meminfo` | mandatory (sysconf) | P | `vfs/procfs.rs` | proc(5) man page |
| `/proc/stat` | soft | P | `vfs/procfs.rs` | proc(5) man page |
| `/proc/sys/kernel/random/uuid` | soft | — | not implemented | proc(5) man page |
| `/sys/devices/system/cpu/{present,possible,online}` | mandatory (sysconf _SC_NPROCESSORS_ONLN) | P | `vfs/sysfs.rs:42-44` | sysfs(5) man page |
| `/sys/devices/system/cpu/cpuX/cache/index*/size` | soft | P (4 K L1 / 4 MiB L2 stub) | `vfs/sysfs.rs:179-180` | sysfs(5) man page |

### Stage 4 — Display + sandbox (X11, seccomp, namespaces)

| Feature | FF-dep | Status | AstryxOS ref | Spec |
|---|---|---|---|---|
| X11 core opcodes 1–127 | mandatory | P | `kernel/src/x11/proto.rs` (~60 core ops) | X11 protocol spec (X Consortium) |
| BIG-REQUESTS | mandatory (libxul, libxcb) | P | `kernel/src/x11/proto.rs:310` | X11R6 BIG-REQUESTS spec |
| MIT-SHM | mandatory (Firefox content compositor) | P (advertised + dispatched) | `kernel/src/x11/proto.rs:273` + `kernel/src/x11/mod.rs:1899` | MIT-SHM extension spec |
| RENDER (Composite, glyphs, FillRectangles) | mandatory (XRender path) | P | `kernel/src/x11/proto.rs:229` + `kernel/src/x11/mod.rs:599` | XRender Extension spec (Keith Packard) |
| SHAPE | soft (window decorations) | P | `kernel/src/x11/proto.rs:263` | SHAPE extension spec |
| XKEYBOARD | mandatory (keyboard input on display) | P | `kernel/src/x11/proto.rs:266` | XKB spec |
| XInputExtension (XI2) | mandatory (pointer / multitouch) | P | `kernel/src/x11/proto.rs:272` | XI2 spec (Peter Hutterer) |
| XFIXES | mandatory (transparent windows) | P | `kernel/src/x11/proto.rs:268` | XFixes spec |
| DAMAGE | mandatory (compositor dirty rect) | P | `kernel/src/x11/proto.rs:269` | DAMAGE extension spec |
| COMPOSITE | soft | P | `kernel/src/x11/proto.rs:270` | COMPOSITE extension spec |
| SYNC | soft | P | `kernel/src/x11/proto.rs:265` | XSYNC spec |
| RANDR | soft (display info) | p (advertised in QueryExtension list but no minor-opcode dispatch) | `kernel/src/x11/mod.rs:1925` | XRandR 1.5 spec |
| GLX | optional (glxtest probe — falls back gracefully per Mozilla bz #1480755) | — | not present | GLX 1.4 spec |
| DRI3 | optional (hardware-accelerated buffer sharing) | — | not present | DRI3 spec |
| Present extension | optional | — | not present | Present extension proposal |
| MIT-MAGIC-COOKIE-1 authentication | mandatory (connection handshake) | P | `kernel/src/x11/mod.rs` (cookie accepted) | X11 protocol auth spec |
| `seccomp-bpf` enforcement | mandatory for full sandbox; soft for screenshot demo | p (accepted, BPF not executed) | `subsys/linux/syscall.rs:2740` (stub) | seccomp(2) man page |
| `clone(CLONE_NEWNS / CLONE_NEWUSER / CLONE_NEWPID …)` namespaces | optional (some FF sandbox configs) | — | flags accepted but no namespace impl | namespaces(7) man page |

### Stage 5 — Time + signals

| Feature | FF-dep | Status | AstryxOS ref | Spec |
|---|---|---|---|---|
| `clock_gettime(CLOCK_MONOTONIC)` | mandatory | P | `subsys/linux/syscall.rs:5867` + vDSO | clock_gettime(2) man page |
| `clock_gettime(CLOCK_REALTIME)` | mandatory | P | syscall + vDSO formulas agree (PR #128) | clock_gettime(2) man page |
| `clock_gettime(CLOCK_BOOTTIME)` | soft | p (treated as MONOTONIC) | dispatched | clock_gettime(2) man page |
| `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` | soft | p | dispatched | clock_gettime(2) man page |
| `clock_gettime64(2)` (32-bit time64 — Mozilla bz #1571290) | mandatory on 32-bit | n/a (64-bit only) | n/a | clock_gettime(2) man page |
| `nanosleep(2)` / `clock_nanosleep(2)` | mandatory | P | `subsys/linux/syscall.rs:4411,3964` | nanosleep(2) man page |
| `timer_create(2)` / `timer_settime(2)` | soft | — | absent | timer_create(2) man page |
| `timerfd_create(2)` / `timerfd_settime(2)` / `timerfd_gettime(2)` | mandatory (GMainLoop) | P | `subsys/linux/syscall.rs:8789-8870` | timerfd_create(2) man page |
| `membarrier(2)` (nr=324) | soft (Rust std::sync; falls back on ENOSYS) | P (treated as full barrier) | `subsys/linux/syscall.rs:3181` | membarrier(2) man page |
| `rseq(2)` (nr=334) | soft (glibc 2.34 init; treats ENOSYS as fatal in some paths) | P (returns success, no slot) | `subsys/linux/syscall.rs:3221-3236` | rseq(2) man page |

### Stage 6 — Audio / input / GPU / aux IO (mostly gated)

Headless screenshot does not require any of these.

| Feature | FF-dep | Status | Notes |
|---|---|---|---|
| ALSA / `/dev/snd` | optional (`--headless` disables) | — | not on demo critical path |
| PulseAudio / `/run/user/<uid>/pulse/native` | optional | — | not on demo critical path |
| PipeWire | optional | — | not on demo critical path |
| `/dev/input/event*` | optional (`--headless`) | — | not on demo critical path |
| `/dev/dri/card*` (DRM/GBM) | optional (Mesa software falls back) | — | confirmed Mesa swrast handles missing /dev/dri |
| `/dev/video*` (V4L2) | optional | — | not on demo critical path |
| `/dev/tty` (pty) | soft (stderr) | P (serial console exposed) | OK |

## Top-5 gaps — fix shape and recommended investigation

### Gap 1 — Robust-futex wake-on-thread-death walker MISSING (set_robust_list dispatch is PRESENT)

**Current state on master (corrected after /review):** `set_robust_list` (nr=273)
and `get_robust_list` (nr=274) dispatch arms are present at
`kernel/src/subsys/linux/syscall.rs:2810-2845`; `(head, len)` is stored in
`Thread.robust_list_head/_len` (`kernel/src/proc/mod.rs:244-247`) with
CWE-822 user-pointer validation. The wake-on-thread-death walker is
intentionally absent — `kernel/src/proc/mod.rs:2420-2425` explicitly
documents: "Robust-list teardown is intentionally **not** performed here …
the slot is round-tripped for `get_robust_list(2)` only."

**FF behaviour:** NPTL is happy — its `set_robust_list` succeeds and the
head is stored. But when a thread holding a robust mutex is killed
(SIGKILL, SIGSEGV, exit_group), waiters **never receive `EOWNERDEAD`** —
they block forever instead of taking the lock with the owner-died bit
set. Mozilla IPC and mozjemalloc use robust mutexes in several paths.

**AstryxOS fix shape:** ~60 LOC (walker + test only — dispatch arms already
exist).

1. On task exit (`subsys/linux/syscall.rs` `sys_exit` / clone-path teardown /
   `proc/mod.rs:2420-2425` exit path), walk the stored `robust_list_head`;
   for each user-space lock node, atomically set the `FUTEX_OWNER_DIED` bit
   (`0x40000000`) and wake one waiter on that `uaddr`. Enforce the 1M-entry
   silent-stop cap per `Documentation/robust-futex-ABI.txt`.
2. Add `kernel/src/test_runner.rs` test: spawn a thread holding robust mutex,
   kill it, observe `EOWNERDEAD` returned to the waiter.

**Recommended dispatch:** `aether-kernel-engineer` for the exit walker;
`qa-engineer` for the test case.

### Gap 2 — `futex_waitv(2)` ENOSYS (nr=449)

**FF behaviour:** Rust std's parking primitives opportunistically issue
`futex_waitv` on Linux 5.16+, fall back to `futex(FUTEX_WAIT)` on ENOSYS. Build
runs but pays the slow path: every wait is one futex per call rather than a
batched wait on a vector. Likely a non-trivial fraction of the W101 plateau
character is the Rust event-loop sitting on these single-target waits when
the vectored form would have collapsed to one syscall.

**AstryxOS fix shape:** ~120 LOC.

1. Add nr=449 dispatch reading the `struct futex_waitv[]` (count up to 128 per
   `futex_waitv(2)`). Current state on master: nr=449 appears only as
   metadata in `kernel/src/subsys/linux/syscall.rs:811,838` ("202 | 449 |
   ... // futex, futex_waitv") with no executable arm — falls through to
   the default ENOSYS arm.
2. For each element, validate (uaddr aligned, val matches, flags valid).
3. Park the calling thread on multiple uaddrs in
   `FUTEX_WAITERS` (single-blocker semantics — first wake returns the index).
4. On timeout, return `-ETIMEDOUT`; otherwise the matching index.

Cite: `futex_waitv(2)` man page (Linux 5.16+).

**Recommended dispatch:** `aether-kernel-engineer`. Tests in `test_runner.rs`
covering 1-entry (degenerates to FUTEX_WAIT), 4-entry, all-already-mismatching,
timeout.

### Gap 3 — `AT_EXECFN` (and `AT_PLATFORM`, `AT_SECURE`) auxv entries

**FF behaviour:** musl's `__progname_full` (used by sandbox debug logging and
crash reports) falls back to `argv[0]` when `AT_EXECFN` is absent, which is
correct per `getauxval(3)`. `AT_SECURE` absence means glibc defaults to 0
(non-SUID), which is also correct for our environment. So *behaviour* matches,
but the auxv is a Linux ABI surface — any future tool that requires these to
exist (rather than be zero) will surprise us.

**AstryxOS fix shape:** ~10 LOC in `kernel/src/proc/elf.rs` auxv build.

```rust
// AT_EXECFN — pointer to NUL-terminated executable name (POSIX execve(2)).
// Place a copy near AT_RANDOM in the user-stack scratch area.
extra_auxv.push((AT_EXECFN, execfn_va));
// AT_PLATFORM — "x86_64\0" or similar; near AT_RANDOM.
extra_auxv.push((AT_PLATFORM, platform_va));
// AT_SECURE — 0 (we never run SUID; cite getauxval(3)).
extra_auxv.push((AT_SECURE, 0));
```

**Recommended dispatch:** any kernel engineer; trivially small.

### Gap 4 — `/proc/self/mountinfo` residual deficiencies (canonical emitter is PRESENT)

**Current state on master (corrected after /review):** `generate_mountinfo()`
exists at `kernel/src/vfs/procfs.rs:876-950`, walks `MOUNTS`, and emits
the canonical 11-column `proc(5)` mountinfo format with synthetic
major:minor, mount opts, and fstype-derived source names. The "empty stub"
characterisation in earlier drafts of this doc was wrong — the comment at
line 897-899 explicitly notes the past-tense "ENOENT used to make it fall
back to a refuse-all policy". The primary refuse-all-cascade risk is
already mitigated.

**Residual deficiencies (still real, smaller scope):**

1. **Bind-mount support** — no current mount-table primitive for bind mounts;
   Firefox sandbox bind-mounts `/proc/self/cwd` and similar. Per
   `mount(2)` `MS_BIND`.
2. **`optional_fields` column** — column 7 in `proc(5)` mountinfo is
   `optional_fields` (e.g. `shared:N`, `master:N`); currently emitted
   empty (`-`). Some sandbox enumerators parse it; verify Mozilla's
   broker tolerates an empty value.
3. **Octal escape of mount-point spaces / control bytes** — `proc(5)`
   requires `\040` etc. for any whitespace in the path. Verify
   our emitter handles this (currently the bringup paths are all
   plain-ASCII so this hasn't been exercised).

**AstryxOS fix shape:** ~30-50 LOC of incremental hardening, not the
80 LOC of a fresh emitter.

Cite: `proc(5)` man page, Mozilla bz #1198550 (sandbox reads
`/proc/self/maps`; the broker-policy / mountinfo enumeration is implied
but the bz primarily covers `/proc/self/maps`).

**Recommended dispatch:** `filesystem-engineer` for bind-mount support
*only if* a downstream investigation surfaces a bind-mount-dependent
Mozilla path. Bumped down priority versus initial draft because the
"empty stub" framing was wrong.

### Gap 5 — `MAP_HUGETLB` / 2 MiB mapping

**FF behaviour:** mozjemalloc tries `mmap(MAP_HUGETLB)` opportunistically for
large arenas; on EINVAL falls back to 4 K. Latent — but every 2 MiB allocation
takes 512 ptes plus 512 PMM operations instead of 1+1. Under firefox-test soaks
this is a measurable fraction of PMM thrash.

**AstryxOS fix shape:** ~200 LOC, mostly in PMM.

1. Add 2 MiB page allocator (PMM tier) — most BIOSes give us enough contiguous
   2 MiB ranges that a simple bitmap-per-2MiB-region works.
2. Add `mmap(MAP_HUGETLB)` and `mmap(MAP_HUGETLB | MAP_HUGE_2MB)` paths that
   request from this tier and install PSE bits (PDE bit 7) per Intel SDM Vol.
   3A §4.5.4.
3. TLB shootdown already covers PSE.

Cite: Intel SDM Vol. 3A §4.5; mmap(2) `MAP_HUGETLB`; `kernel.org`
`Documentation/admin-guide/mm/hugetlbpage.rst`.

**Recommended dispatch:** `aether-kernel-engineer`. Lower priority than gaps
1–4 because it is *latent* — FF runs without it, just slower.

## What's surprising — investigations we may be over-weighting

Cross-referencing the gap matrix against the recent saga memory, three
patterns stand out:

1. **`io_uring` need** — sometimes raised as a candidate for I/O speedups, but
   Firefox's seccomp whitelist has no `io_uring_*` syscalls at all. Investing
   in `io_uring` would not move Firefox metrics.
2. **Aggressive seccomp enforcement** — accepting `PR_SET_SECCOMP` as a no-op
   is the *right* posture for the screenshot demo. Mozilla bz #1259273 +
   #1285827 + #942698 cumulatively show that *enforcing* seccomp closes ~80%
   of FF's typical content-process syscall surface (paths, networking) — that
   would gate the demo, not enable it. The `PR_SET_NO_NEW_PRIVS` precondition
   we already accept is the only behaviour Firefox checks.
3. **Per-syscall ABI drift hunts** — `LINUX_SYSCALL_COVERAGE.md` shows 193/206
   dispatched syscalls. The matrix above suggests the highest-leverage remaining
   gaps are *structural* (robust-list wake-path, mountinfo content) not
   per-syscall. A single audit pass on mountinfo could close more FF behaviour
   than 10 individual syscall arms.

## Calibration against recent memory

Aligns with:

- 2026-05-20 FF gap matrix (strace-ref differential) findings of 70% memory
  hygiene + 30% ABI — this matrix sees both axes but reframes the 30% as
  "structural ABI gaps that look small per-syscall but affect whole behaviour
  classes (robust-list wake path, mountinfo)".
- 2026-05-22 sc=1171 Phase 1 fan-out — none of the five Phase 2 axes
  (heap-alloc / ctor codegen / TLS-store ordering / caller-identity /
  heap-reuse) is *directly* on the FF demand-critical path per the seccomp
  whitelist; sc=1171 is a deeper Mozilla-internal axis, not a missing-syscall
  axis. This matrix recommends not derailing that investigation onto syscall
  gaps unless one of the five Phase 2 axes lands "blocked by ENOSYS".

## Conclusion

The Firefox critical path on AstryxOS is structurally complete:

- vDSO: 4/4 symbols.
- Auxv: 12/15 entries.
- Syscalls (Mozilla whitelist intersection): ~118/120.
- X11 (headless RENDER path): 11/11 required extensions.
- AF_UNIX SCM_RIGHTS: complete.

The five named gaps (robust-list, futex_waitv, AT_EXECFN/PLATFORM/SECURE,
mountinfo, MAP_HUGETLB) total roughly 470 LOC of new kernel code, ~3 dispatches
of ~150 LOC each. None of them is blocking the *current* PNG demo (W101 and
sc=1171 dominate), but Gaps 1 and 4 are the cheapest paths to closing classes
of Mozilla-bz-confirmed sandbox surface.
