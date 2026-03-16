# Linux C Runtime: musl vs glibc

> This covers the Linux ELF personality
> Reference: `SupportingResources/linux/` (kernel syscall ABI)
> Already working: static musl (confirmed Session 23)

---

## Current State

Static musl ELF binaries already run on AstryxOS:
- `arch_prctl(158)` → FS.base set for TLS ✅
- `set_tid_address(218)` → TID stored ✅
- `exit_group(231)` → process terminates ✅
- TCC (TinyCC) compiles and runs C programs ✅

The Linux personality dispatch path is live and correctly wired.

---

## musl vs glibc: The Right Choice for AstryxOS

### musl libc

```
Size:          ~450 KB (static), ~600 KB (shared)
License:       MIT
Syscall model: Direct SYSCALL — no intermediate vDSO required
TLS:           Single PT_TLS segment, simple static model
Dependencies:  None — pure C, no external library requirements
Startup:       crt1.o → __libc_start_main → main()
Thread model:  pthread built-in (no separate libpthread)
Complexity:    ~80K LOC total
```

**Why musl is right for AstryxOS**:
1. **Already proven** — static musl runs on AstryxOS today
2. **Simple syscall model** — every libc function calls SYSCALL directly, no vDSO
3. **No glibc-isms** — doesn't use non-standard kernel interfaces
4. **Clean TLS** — single PT_TLS segment, no NPTL complexity
5. **Predictable** — no lazy binding, no hidden kernel assumptions
6. **Buildable** — `scripts/build-musl.sh` already exists in AstryxOS

**musl syscall convention** (x86_64):
```asm
; musl syscall macro expansion
mov rax, SYS_write    ; syscall number (1)
mov rdi, fd           ; arg1
mov rsi, buf          ; arg2
mov rdx, len          ; arg3
syscall
; return value in rax (negative = error, -errno)
```

### glibc

```
Size:          ~2.5 MB (shared), ~8 MB all components
License:       LGPL
Syscall model: vDSO for gettimeofday/clock_gettime (requires kernel vDSO page)
TLS:           Complex NPTL model with __thread, __tls_get_addr indirection
Dependencies:  Kernel version checks, specific /proc paths, /etc/ld.so.cache
Startup:       complex — involves IFUNC resolvers, PLT lazy binding
Thread model:  Separate libpthread.so.0 (NPTL)
Complexity:    ~400K LOC
```

**Why glibc is hard for AstryxOS**:
1. **vDSO required** — glibc maps `AT_SYSINFO_EHDR` from aux vector to find `__vdso_gettimeofday`.
   Without a vDSO page, glibc falls back but it's complex to get right.
2. **IFUNC resolvers** — CPU feature detection at load time (AVX2 vs SSE2 fast paths)
3. **NPTL** — complex TLS model; `__tls_get_addr` requires precise allocation
4. **Kernel version checks** — glibc checks `uname()` return and gates features on kernel version
5. **`/etc/ld.so.preload`**, **`/etc/ld.so.cache`** — dynamic linker reads these at startup
6. **Lots of `/proc` usage** — glibc reads `/proc/self/maps`, `/proc/cpuinfo`, `/proc/sys/`

**Recommendation**: Focus on musl. glibc is doable but adds 3-5 sessions of compatibility work
before the first app runs.

---

## musl Static Linking (Already Working)

Static musl embeds all of libc into the binary. No .so loading needed.

```
Compile:   musl-gcc -static hello.c -o hello
Result:    single ELF binary, ~100 KB, no PT_INTERP

Load path in AstryxOS:
  kernel loads ELF → no PT_INTERP → jump to e_entry (_start)
  _start (crt/crt1.c):
    xor rbp, rbp           ; clear frame pointer
    mov rdi, [rsp]         ; argc
    lea rsi, [rsp+8]       ; argv
    lea rdx, [rsi+8*rdi+8] ; envp
    call __libc_start_main(main, argc, argv, envp, ...)
  __libc_start_main:
    init TLS
    call __init_array (C++ static constructors)
    int ret = main(argc, argv, envp)
    exit(ret)
  exit():
    call __fini_array (C++ static destructors)
    call _exit()
  _exit():
    syscall SYS_exit_group(status)
```

Everything above the final syscall is already in the binary. The kernel just sets up the
stack correctly (argc, argv, envp, aux vector) and jumps to `_start`.

### Stack layout at process entry (ELF ABI)

```
[rsp]         argc                    ← number of arguments
[rsp+8]       argv[0]                 ← pointer to program name string
[rsp+16]      argv[1]                 ← first argument
...
[rsp+8*(argc+1)] NULL                 ← end of argv
[rsp+8*(argc+2)] envp[0]              ← first environment variable
...
[some address] NULL                   ← end of envp
               AT_NULL (0)            ← end of aux vector
               AT_ENTRY (9)           ← ELF entry point
               AT_PHDR  (3)           ← program header address
               AT_PHNUM (4)           ← number of program headers
               AT_PHENT (5)           ← size of each program header
               AT_PAGESZ(6)           ← 4096
               AT_BASE  (7)           ← interpreter base (0 for static)
               AT_UID   (11)          ← real UID
               AT_EUID  (12)          ← effective UID
               AT_GID   (13)          ← real GID
               AT_EGID  (14)          ← effective GID
               AT_CLKTCK(17)          ← clock ticks per second (100)
               AT_RANDOM(25)          ← pointer to 16 random bytes
               AT_EXECFN(31)          ← pointer to executable path string
```

AstryxOS ELF loader (`proc/elf.rs`) already populates this. Verify AT_RANDOM is set — musl
uses it to seed its PRNG.

---

## musl Dynamic Linking (Not Yet Working)

Dynamic musl uses `ld-musl-x86_64.so.1` as the runtime dynamic linker (PT_INTERP).

```
Compile:   musl-gcc hello.c -o hello   (no -static)
PT_INTERP: /lib/ld-musl-x86_64.so.1

Load path:
  kernel sees PT_INTERP = /lib/ld-musl-x86_64.so.1
  kernel loads interpreter ELF at 0x7F00_0000_0000
  kernel patches aux vector: AT_BASE = interpreter base, AT_ENTRY = app entry
  CPU jumps to ld-musl entry point (_start in ld.so)
  ld-musl:
    mmap() each DT_NEEDED shared library (.so.N) from /lib/ or /usr/lib/
    Apply relocations: RELATIVE, GLOB_DAT, JUMP_SLOT
    Call DT_INIT sections
    Jump to AT_ENTRY (original application entry)
```

### What's needed in AstryxOS for dynamic musl

1. **`/lib/ld-musl-x86_64.so.1` on disk** — `scripts/build-musl.sh` builds this
2. **VFS `read()` of .so files** — already works via FAT32 driver
3. **`mmap(MAP_PRIVATE, fd, offset)` on files** — file-backed mmap not yet implemented
4. **`mprotect()` with hardware PTE update** — needed to mark code RX after load
5. **`AT_BASE` in aux vector** — ELF loader must pass interpreter load address
6. **Enough syscalls** — `mmap`, `mprotect`, `open`, `read`, `close`, `fstat` at minimum

The biggest gap is **file-backed mmap** (see `missing_features/01_memory.md`). Without it,
`ld.so` can't map the shared library's ELF segments into memory.

---

## glibc Compatibility (Future / Optional)

If glibc support is ever needed (for pre-built binaries):

### Additional requirements beyond musl

| Requirement | Effort | Why |
|-------------|--------|-----|
| vDSO page | M | glibc clock_gettime/gettimeofday use vDSO |
| IFUNC support in ELF loader | M | CPU feature dispatch via indirect functions |
| `__tls_get_addr` ABI | M | NPTL thread-local storage dynamic model |
| `/etc/ld.so.cache` | S | glibc dynamic linker reads library cache |
| Kernel version ≥ 4.x in uname | S | glibc checks kernel version number |
| `/proc/self/maps` (already done) | ✅ | glibc reads this |
| NPTL `set_robust_list` | S | glibc sets up robust futex list |
| `AT_HWCAP` in aux vector | S | hardware capability bits (SSE/AVX flags) |

**Estimate**: 3-4 sessions to get glibc "hello world" running; 8-10 sessions for reliable
glibc app support.

### The vDSO

The vDSO (virtual Dynamic Shared Object) is a tiny kernel-mapped ELF that provides
`gettimeofday`, `clock_gettime`, `getcpu`, and `time` without crossing the kernel boundary.

```
Kernel maps a read-only page containing a small ELF
Sets AT_SYSINFO_EHDR = address of that page in aux vector
glibc linker reads AT_SYSINFO_EHDR at startup
glibc clock_gettime() resolves to __vdso_clock_gettime (in the kernel page)
__vdso_clock_gettime reads a timekeeping struct the kernel updates in place
```

For musl: musl falls back to SYSCALL if vDSO is missing. For glibc: required.

**Implementation**: ~300 LOC — a tiny ELF with 4 functions, mapped at a fixed high address.

---

## C++ on Linux: libstdc++ and libc++

For C++ apps on the Linux personality:

**libstdc++ (GCC)**:
- Bundled with GCC toolchain
- Links against glibc or musl
- If building with `musl-gcc`, libstdc++ is statically available as `-lstdc++`
- Size: ~4 MB shared / ~1.5 MB relevant static subset

**libc++ (LLVM/Clang)**:
- Bundled with LLVM
- Works with musl via clang's `-stdlib=libc++`
- Cleaner design, easier to port to new targets
- Size: ~1.5 MB shared

For AstryxOS, **static libstdc++ or libc++** will work as soon as musl static works.
The C++ binary is fully self-contained. Dynamic C++ requires the same .so infrastructure as dynamic musl.

---

## Syscall Gaps That Block musl Applications

From `missing_features/05_syscalls.md`, the most critical missing calls for musl apps:

| Syscall | musl use | Priority |
|---------|---------|---------|
| `poll(7)` | stdio buffering, select-based apps | Critical |
| `pread64(17)` | Many file operations | Critical |
| `getrlimit(97)` | musl startup — determines FD table size | Critical |
| `fcntl F_SETFD` | FD_CLOEXEC on exec | High |
| `fchown/fchmod` | File permissions | Medium |
| `setuid/setgid` | Privilege drop | Medium |

All of these are in Phase A of the Action Plan in `missing_features/ACTION_PLAN.md`.

---

## Summary: musl Roadmap

```
Now:    Static musl ELF works ✅
         ↓ requires: more syscalls (Phase A)
Next:   Full static musl app suite (bash, coreutils, Python)
         ↓ requires: file-backed mmap, mprotect PTE update
Then:   Dynamic musl linking (ld.so)
         ↓ requires: file-backed mmap, complete AT_BASE handling
Future: glibc compatibility (vDSO, IFUNC, NPTL)
```
