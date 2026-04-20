# C Runtime Action Plan

> Ordered roadmap for adding Win32 CRT (MSVCRT+STL) and Linux CRT (glibc/musl) to AstryxOS.
> Prerequisite reading: `01_architecture.md`, `02_win32_crt.md`, `03_linux_crt.md`

---

## Decision Matrix

Before picking a path, understand the trade-offs:

| Goal | Effort | Value | Recommendation |
|------|--------|-------|----------------|
| More musl static syscalls | S | High — real apps now | **Do first** |
| musl dynamic linking | L | High — shared libs | After syscalls |
| glibc compat | XL | Medium — pre-built bins | Defer |
| ntdll.dll (userspace) | L | High — Win32 apps | Phase W1 |
| kernel32.dll | M | High — Win32 apps | Phase W2 |
| msvcrt.dll | L | High — C apps on Win32 | Phase W3 |
| STL / C++ runtime | L | Medium — C++ apps | Phase W4 |
| libaether | M | Medium — native apps | Phase A |

**Short answer**:
- **Linux path**: Focus on musl. More syscalls now, dynamic linking later. glibc someday.
- **Win32 path**: Move ntdll stubs to userspace, then build kernel32 + msvcrt.
- **Native path**: Build libaether as the Orbit shell migration prep.

---

## Track 1: Linux / musl — Completing the Runtime

### L1. Syscall completeness pass (2-3 sessions)
*Prerequisite for any real musl app to work.*

```
Session L1a — I/O syscalls:
  [ ] poll(7), select(23), pselect6(270), ppoll(271)
  [ ] pread64(17), pwrite64(18)
  [ ] readv(19) — writev already done
  [ ] fcntl F_GETFD/F_SETFD (FD_CLOEXEC), F_SETLK/F_SETLKW (file locks)
  [ ] dup3(292) — dup with O_CLOEXEC
  [ ] pipe2(293) — pipe with O_NONBLOCK/O_CLOEXEC
  [ ] fsync(74), fdatasync(75)
  [ ] ftruncate(77), truncate(76)
  [ ] fchmod(91), fchown(93)

Session L1b — process/user syscalls:
  [ ] getrlimit(97) — return real values from PCB rlimit table
  [ ] setrlimit(160), prlimit64(302) — enforce limits
  [ ] sysinfo(99) — totalram/freeram for Firefox cache sizing
  [ ] times(100) — process CPU time
  [ ] setuid(105)/setgid(106)/setreuid(113)/setregid(114)
  [ ] capget(125)/capset(126) — capability bitmask
  [ ] prctl PR_SET_NAME, PR_SET_NO_NEW_PRIVS

Session L1c — socket/network syscalls:
  [ ] setsockopt(55)/getsockopt(54) — actually set flags
  [ ] sendmsg(46) full — ancillary data (SCM_RIGHTS)
  [ ] recvmsg(47) full — ancillary data
  [ ] getsockname(51), getpeername(52)
  [ ] socketpair(53)
  [ ] accept4(288) — with SOCK_CLOEXEC flag
```

After L1: bash, Python, curl (static musl), basic coreutils all work.

---

### L2. musl dynamic linking (3-4 sessions)
*Enables shared library support and dynamic C++ runtimes.*

```
Session L2a — File-backed mmap:
  [ ] mmap(MAP_PRIVATE, fd, offset) — map file contents to VA
      In mm/vmm.rs: on page fault, read from file inode at offset
      Track file+offset in VmaInfo::File { inode_id, file_offset }
  [ ] mmap(MAP_SHARED, fd, offset) — shared file mapping (backed by page cache)
  [ ] mprotect() hardware PTE update (not just VMA flags)

Session L2b — Kernel ld.so support:
  [ ] AT_BASE in aux vector = interpreter load base (currently may be 0)
  [ ] AT_ENTRY in aux vector = original app entry (proc/elf.rs already may set this)
  [ ] AT_RANDOM = 16 random bytes on stack (from RDRAND)
  [ ] AT_HWCAP = CPUID feature bits (SSE/AVX flags)
  [ ] AT_CLKTCK = 100 (ticks per second)
  [ ] Interpreter loaded at 0x7F00_0000_0000 correctly (check proc/elf.rs load_elf_dyn)

Session L2c — VFS .so loading:
  [ ] /lib/ and /usr/lib/ directory structure on data disk
  [ ] /lib/ld-musl-x86_64.so.1 deployed to disk (scripts/build-musl.sh output)
  [ ] /lib/libc.so (or musl libc.so → /lib/libc.musl-x86_64.so.1)
  [ ] VFS fstat() returns correct file size for shared libs
  [ ] MAP_PRIVATE mmap on /lib/libfoo.so works end-to-end

Session L2d — Test and validation:
  [ ] Compile hello_dynamic.c with -lpthread (or no -static)
  [ ] Run it on AstryxOS — verify ld-musl resolves and calls main()
  [ ] Dynamic libcurl or libssl linked app (stretch goal)
```

After L2: `./hello_dynamic` works; shared library ecosystem is viable.

---

### L3. glibc compatibility (optional, 5-8 sessions)
*For running pre-built Linux x86_64 binaries.*

```
Prerequisites (all from L1-L2):
  [ ] All ~90 current Linux syscalls working correctly
  [ ] File-backed mmap, mprotect PTE update
  [ ] Dynamic linker infrastructure (AT_BASE, interpreter loading)

Additional glibc-specific:
  [ ] uname() returns "Linux" with version "6.1.0" or similar
  [ ] vDSO page (200-300 LOC mini ELF with __vdso_clock_gettime)
  [ ] AT_SYSINFO_EHDR in aux vector pointing to vDSO
  [ ] IFUNC resolver support in ELF loader
  [ ] /etc/ld.so.cache or stub that returns empty
  [ ] /etc/ld.so.conf stub
  [ ] NPTL: set_robust_list(310), get_robust_list(311)
  [ ] __tls_get_addr ABI (dynamic TLS access)

Glibc startup quirks:
  [ ] Reads /proc/self/maps at startup (already working)
  [ ] Reads /proc/cpuinfo for CPU features
  [ ] Reads /proc/sys/kernel/overcommit_memory (return "0")
  [ ] __libc_init_first() may need specific signals wired
```

---

## Track 2: Win32 — Building the NT Runtime Stack

### W0. Pre-work: kernel NT syscall handlers (1 session)
*The SSDT stubs in nt/mod.rs currently return 0. Make them call real kernel functions.*

```
Map each NT service number to the equivalent kernel function:

NT_CLOSE (0x00) → proc::close_handle(handle)
NT_CREATE_FILE (0x01) → vfs::create_or_open(path, access, disposition, ...)
NT_READ_FILE (0x06) → vfs::read_fd(handle, buffer, length) [with offset from OVERLAPPED]
NT_WRITE_FILE (0x07) → vfs::write_fd(handle, buffer, length)
NT_DEVICE_IO_CONTROL (0x07) → ioctl dispatch
NT_ALLOCATE_VIRTUAL_MEMORY (0x15) → mm::mmap(addr, size, type, prot)
NT_FREE_VIRTUAL_MEMORY (0x1A) → mm::munmap(addr, size)
NT_PROTECT_VIRTUAL_MEMORY (0x4D) → mm::mprotect(addr, size, prot)
NT_CREATE_THREAD (0x1B) → proc::create_thread(entry, stack)
NT_TERMINATE_THREAD (0x53) → proc::exit_thread(status)
NT_TERMINATE_PROCESS (0x2C) → proc::exit_group(status)
NT_WAIT_FOR_SINGLE_OBJECT (0x04) → ke::wait_for_single_object(handle, timeout)
NT_WAIT_FOR_MULTIPLE_OBJECTS (0x05) → ke::wait_for_multiple_objects(...)
NT_CREATE_SECTION (0x4A) → mm::create_section(file, size, prot)
NT_MAP_VIEW_OF_SECTION (0x28) → mm::map_view(section, addr, offset, size, prot)
NT_UNMAP_VIEW_OF_SECTION (0x2A) → mm::unmap_view(addr)
NT_QUERY_VIRTUAL_MEMORY (0x23) → mm::query_vma(addr, info_class, buffer)
NT_QUERY_INFORMATION_PROCESS (0x16) → proc::query_process_info(pid, info_class, buffer)
NT_SET_INFORMATION_THREAD (0x0D) → proc::set_thread_info(...)

INT 2E handler must route: RAX=service number → SSDT[RAX](RCX, RDX, R8, R9, ...)
```

---

### W1. ntdll.dll — NT Foundation Library (3-4 sessions)
*The most critical Win32 component. Build as a PE DLL in C (or Rust with C ABI).*

```
Session W1a — Syscall stubs + basic RTL:
  ntdll.dll source file: ntdll/syscalls.asm (or syscalls.rs)
    One stub per NT service (43 total):
      NtClose: mov eax, 0; syscall; ret   (INT 2E variant: int 0x2e; ret)
    Build as PE DLL with .def export list

  ntdll.dll RTL primitives:
    RtlCopyMemory, RtlZeroMemory, RtlCompareMemory
    RtlInitUnicodeString, RtlFreeUnicodeString
    RtlUnicodeStringToAnsiString, RtlAnsiStringToUnicodeString

Session W1b — Heap manager (RtlHeap):
  RtlCreateHeap(flags, base, reserve, commit, lock, params)
    → NtAllocateVirtualMemory for initial commit
    → Buddy allocator or NT-style heap (see reactos/sdk/lib/rtl/heap.c)
  RtlAllocateHeap(heap, flags, size) → allocate from heap
  RtlFreeHeap(heap, flags, ptr) → free block
  RtlReAllocateHeap(heap, flags, ptr, size) → resize block

  Reference: reactos/dll/ntdll/rtl/heap.c (900 LOC, cleanest version)

Session W1c — LDR (PE dynamic linker):
  LdrLoadDll(search_path, dll_name, &handle)
    → NtCreateFile to find .dll on disk (search DLL directories)
    → NtCreateSection + NtMapViewOfSection to map it
    → Apply base relocations (IMAGE_REL_BASED_DIR64)
    → Walk import table: call LdrLoadDll recursively for each dependency
    → Patch IAT: NtQueryVirtualMemory + patch slots with exported function addresses
    → Call DllMain(DLL_PROCESS_ATTACH)
    → Add to PEB.Ldr list (InLoadOrderModuleList)
  LdrUnloadDll(handle)
    → Call DllMain(DLL_PROCESS_DETACH)
    → NtUnmapViewOfSection
  LdrGetProcedureAddress(module, name, ordinal, &address)
    → Walk PE export directory by name or ordinal

  Reference: reactos/dll/ntdll/ldr/ldrpe.c + ldrapi.c + ldrinit.c

Session W1d — Exception dispatcher + CritSec:
  RtlRaiseException(record) → dispatch to VEH/SEH handlers
  RtlUnwind / RtlUnwindEx (x64 DWARF-style unwind)
  RtlLookupFunctionEntry(pc) → find RUNTIME_FUNCTION in .pdata section
  RtlVirtualUnwind(type, base, pc, func_entry, context, ...)
  RtlInitializeCriticalSection / RtlEnterCriticalSection / RtlLeaveCriticalSection

Session W1e — LdrInitializeThunk (process startup):
  LdrInitializeThunk(context, params):
    InitializeHeap()             → RtlCreateHeap for ProcessHeap
    InitTls()                    → allocate TLS slots
    LdrpInitializeProcess():
      Load ntdll, kernel32 into PEB.Ldr
      Walk EXE import table, load all DLLs (DLL_PROCESS_ATTACH)
      Call EXE entry point

  Reference: reactos/dll/ntdll/ldr/ldrinit.c lines 1-500
```

**Key decision**: ntdll.dll should be written in **C** (not Rust) for maximum compatibility
with reference source (XP crts + ReactOS). The C code can be compiled with clang targeting
`x86_64-pc-windows-gnu` or `x86_64-unknown-none`.

---

### W2. kernel32.dll (2-3 sessions)
*Win32 API shim over ntdll.*

```
Session W2a — File + Console I/O:
  CreateFileA/W → NtCreateFile
  ReadFile / WriteFile → NtReadFile / NtWriteFile
  CloseHandle → NtClose
  GetStdHandle → return pre-set handles from PEB.ProcessParameters
  WriteConsoleA/W → WriteFile(stdout)
  GetConsoleMode / SetConsoleMode → ioctl on console handle
  FindFirstFile / FindNextFile / FindClose → NtQueryDirectoryFile

Session W2b — Process + Thread:
  CreateProcess → NtCreateProcess + NtCreateThread + LdrLoadDll("ntdll")
  ExitProcess → NtTerminateProcess
  CreateThread → NtCreateThread
  ExitThread → NtTerminateThread
  WaitForSingleObject → NtWaitForSingleObject
  GetCurrentProcessId / GetCurrentThreadId → from TEB.ClientId

Session W2c — Memory + Error:
  VirtualAlloc → NtAllocateVirtualMemory
  VirtualFree → NtFreeVirtualMemory
  VirtualProtect → NtProtectVirtualMemory
  GetProcessHeap → PEB.ProcessHeap
  HeapAlloc/Free/ReAlloc → RtlAllocateHeap/RtlFreeHeap/RtlReAllocateHeap
  GetLastError → TEB.LastErrorValue
  SetLastError → TEB.LastErrorValue = x
  FormatMessage → basic string lookup from error code table

Reference: reactos/dll/win32/kernel32/ (full reimplementation)
```

---

### W3. msvcrt.dll — C Runtime (2-3 sessions)
*malloc, printf, stdio — all the C standard library.*

```
Session W3a — Heap + startup:
  malloc() → HeapAlloc(GetProcessHeap(), 0, size)
  free() → HeapFree(GetProcessHeap(), 0, ptr)
  realloc() → HeapReAlloc(...)
  operator new / delete → malloc / free
  mainCRTStartup():
    _cinit(): init errno, init FPU, run .CRT$XI* constructors
    argc/argv: GetCommandLineA() → CommandLineToArgvA()
    main(argc, argv, envp)
    exit(ret)

Session W3b — stdio:
  FILE struct: { handle, buf[4096], buf_pos, buf_len, mode, flags }
  fopen → CreateFile; returns FILE*
  fread/fwrite → ReadFile/WriteFile via internal buffer
  fclose → FlushFileBuffers + CloseHandle
  printf/fprintf → format to buffer → WriteFile
  scanf/fscanf → ReadFile → parse
  stdin/stdout/stderr → pre-initialized FILE* for handles 0/1/2

Session W3c — String + Math:
  memcpy/memset/memmove (compiler intrinsics if possible, else hand-written)
  strlen/strcpy/strcat/strcmp/strncmp/strstr/strtok
  sprintf/vsprintf/sscanf
  strtol/strtod/atoi/atof
  sin/cos/sqrt → delegate to x87 FPU instructions
  time/localtime/gmtime → GetSystemTime → convert

Reference: reactos/dll/win32/msvcrt/ (complete implementation in C)
XP: base/crts/crtw32/startup/crt0.c, base/crts/crtw32/stdio/, base/crts/crtw32/heap/
```

---

### W4. STL / C++ Runtime (1-2 sessions)
*Only needed for C++ apps. Build on top of W3.*

```
Option 1 (recommended): Port LLVM libc++ to AstryxOS Win32 target
  Download libc++ source (LLVM)
  Define __AstryxOS__ target in libcxx
  Configure: -target x86_64-pc-astryx -stdlib=libc++ -nostdinc++
  Needs: operator new/delete from msvcrt, malloc, pthread_mutex (from kernel32/ntdll)

Option 2: Minimal STL stub for common containers
  std::string: small-string-opt buffer + heap alloc, operator=, +, find, substr
  std::vector: grow-by-2 dynamic array with iterator pair
  std::map: red-black tree (from Rust HashMap as reference)
  std::unordered_map: open-addressing hash table
  std::shared_ptr / std::unique_ptr: reference-counted wrapper
  ~1000 LOC total for just these 6

C++ exception ABI (required for any C++ app):
  __cxa_throw, __cxa_begin_catch, __cxa_end_catch
  __cxa_allocate_exception (malloc wrapper)
  _Unwind_RaiseException (DWARF unwind) or SEH integration
  Reference: Itanium C++ ABI spec + libcxxabi, or SEH via reactos/sdk/lib/rtl/
```

---

## Track 3: Aether Native (libaether)

### A1. libaether crate (1 session)
```
Create: userspace/libaether/  (separate crate outside kernel)
  Cargo.toml: crate-type=["staticlib"], no_std + alloc feature
  src/syscall.rs: raw syscall(n, ..) macro with inline asm
  src/io.rs: read/write/open/close/lseek
  src/mem.rs: malloc/free (mmap-backed)
  src/string.rs: memcpy/strlen/strcmp
  src/stdio.rs: printf/putchar
  src/process.rs: fork/exec/exit/wait
  src/start.s: _start → __aether_start_main → main → exit
Build: cargo build --target x86_64-unknown-none → libaether.a
Test: compile a C file with clang -nostdlib -L. -laether → run on AstryxOS
```

---

## Recommended Build Order

```
Week 1-2: Track 1 — Linux syscall completeness (L1a, L1b, L1c)
           → Unlocks: bash, Python, curl, real POSIX apps

Week 3: Track 3 — libaether skeleton (A1)
         → Unlocks: Orbit shell in user-mode, native AstryxOS apps

Week 4-5: Track 2 — Win32 W0 + W1a/W1b (kernel SSDT handlers + ntdll stubs + heap)
           → Unlocks: simple Win32 console apps

Week 6-7: Track 2 — W1c/W1d (LDR + exceptions)
           → Unlocks: Win32 apps with DLL dependencies

Week 8: Track 2 — W2 (kernel32.dll)
         → Unlocks: CreateFile/ReadFile/WriteFile Win32 apps

Week 9-10: Track 2 — W3 (msvcrt.dll)
            → Unlocks: printf/scanf C runtime for Win32

Week 11: Track 1 — L2 (dynamic musl)
          → Unlocks: shared library ecosystem, ./configure-based apps

Week 12-13: Track 2 — W4 (STL)
             → Unlocks: C++ Win32 apps

Future: Track 1 — L3 (glibc), when pre-built binary compat is needed
```

---

## Reference Source Usage Guide

| What you need | Best reference | Why |
|---------------|---------------|-----|
| ntdll LDR (PE loader) | `reactos/dll/ntdll/ldr/` | Clean C, same logic as XP, shorter |
| ntdll RTL (heap, strings) | `reactos/dll/ntdll/rtl/` | Clean C reimplementation |
| ntdll syscall stubs | `reactos/dll/ntdll/dispatch/` | ntdll stub format for AMD64 |
| msvcrt | `reactos/dll/win32/msvcrt/` | Complete, buildable, MIT-ish license |
| CRT startup (crt0) | `reactos/dll/win32/msvcrt/startup/crt0_c.c` | CRT startup |
| CRT heap | `reactos/sdk/lib/rtl/heap.c` | NT-style heap allocator |
| CRT exception handling | `reactos/sdk/lib/rtl/amd64/unwind.c` | SEH unwinder |
| PEB/TEB structures | `reactos/sdk/include/ndk/peb_teb.h` | NT PEB/TEB structure defs |
| ELF aux vector | `linux/fs/binfmt_elf.c` | Canonical aux vector population |
| musl startup | musl source (`crt/crt1.c`) | Direct _start → main path |
| Linux syscall ABI | `linux/arch/x86/entry/syscalls/syscall_64.tbl` | Canonical x86_64 syscall numbers |

---

## Critical Path: What Blocks What

```
Win32 apps working:
  W0 (SSDT real handlers) → W1a (ntdll stubs) → W1b (heap) → W1c (LDR)
    → W2 (kernel32) → W3 (msvcrt) → W4 (STL)

musl dynamic apps:
  L1a (I/O syscalls) → L2a (file-backed mmap) → L2b (aux vector)
    → L2c (VFS .so loading) → dynamic ELF works

C++ on Linux:
  static libstdc++ or libc++ links automatically once L1 done
  dynamic libc++ requires L2 first

Native AstryxOS apps:
  A1 (libaether) → any time after basic kernel I/O works (already done)
```
