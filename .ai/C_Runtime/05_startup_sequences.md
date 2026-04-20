# Process Startup Sequences

> Every personality has a different startup sequence.
> This document traces exactly what happens from "kernel creates process" to "main() is called".

---

## Personality 1: Win32 (PE binary)

### Full startup trace

```
1. KERNEL: Kernel creates new process from PE binary
   ─────────────────────────────────────────────────────────────────────
   proc/pe.rs: load_pe_binary(path)
     → Parse DOS header → PE signature → COFF/Optional headers
     → Map sections to virtual addresses (apply base relocations)
     → Read Import Directory: find "ntdll.dll" and "kernel32.dll"
     → Call nt::lookup_stub(dll_name, fn_name) per IAT entry
     → Patch IAT with stub addresses
     → Detect ELF subsystem = Win32
     → Set process entry point to PE.AddressOfEntryPoint

   CURRENTLY: nt::lookup_stub() returns in-kernel function addresses (WRONG)
   SHOULD BE: ntdll.dll is loaded into user address space; IAT points to ntdll exports

2. KERNEL: Allocate and populate PEB + TEB in user address space
   ─────────────────────────────────────────────────────────────────────
   Allocate PEB at a well-known high address (e.g., 0x7FFDF000)
   Allocate TEB for main thread
   Fill PEB:
     .ImageBaseAddress = EXE load address
     .ProcessHeap = 0   (ntdll will create it)
     .Ldr = pointer to PEB_LDR_DATA struct (list of loaded modules)
     .ProcessParameters → RTL_USER_PROCESS_PARAMETERS {
         CommandLine, ImagePathName, Environment, etc.
     }
   Fill TEB:
     .NtTib.StackBase = user stack top
     .NtTib.StackLimit = user stack bottom
     .ProcessEnvironmentBlock = PEB address
     .ClientId.UniqueProcess = PID
     .ClientId.UniqueThread = TID
   Set GS base to TEB address (arch_prctl ARCH_SET_GS)

3. KERNEL: Transfer control to ntdll entry point
   ─────────────────────────────────────────────────────────────────────
   Jump to ntdll!LdrInitializeThunk(context, process_param)
   (ntdll is mapped at a fixed address, e.g., 0x77F00000)

4. NTDLL: LdrInitializeThunk
   ─────────────────────────────────────────────────────────────────────
   ntdll!LdrInitializeThunk(context, param):
     RtlInitializeHeap()          → call NtAllocateVirtualMemory for initial heap
     _init_tls()                  → allocate TLS index 0 for CRT
     LdrpInitializeProcess():
       Map ntdll into PEB.Ldr list
       Walk EXE import table:
         For each imported DLL:
           LdrpLoadDll(dll_name):
             Search %PATH% / System32 / SxS
             NtCreateSection(file) + NtMapViewOfSection(process)
             Apply base relocations
             Walk DLL's import table recursively
             Call DllMain(DLL_PROCESS_ATTACH)
       Patch EXE IAT with final function addresses from loaded DLLs

5. NTDLL → KERNEL32: Transfer to CRT startup
   ─────────────────────────────────────────────────────────────────────
   After all DLLs loaded, ntdll calls EXE entry point:
   Call EXE.AddressOfEntryPoint

6. KERNEL32 / MSVCRT: mainCRTStartup
   ─────────────────────────────────────────────────────────────────────
   msvcrt!mainCRTStartup() (or kernel32!BaseProcessStartThunk → msvcrt):
     _cinit():
       Initialize FPU control word
       Initialize errno = 0
       Run .CRT$XIA → .CRT$XIZ (C initializers)
       Run .CRT$XCA → .CRT$XCZ (C++ static constructors)
     GetCommandLineA() → parse into argc/argv
     GetEnvironmentStrings() → build envp
     main(argc, argv, envp)         ← USER CODE STARTS HERE
     exit(return_value):
       _cexit():
         Run atexit() callbacks
         Run .CRT$XPA → .CRT$XPZ (C++ destructors)
         Flush stdio buffers
       ExitProcess(return_value)
       → NtTerminateProcess(current_process, return_value)
```

**Reference**:
- `reactos/dll/ntdll/ldr/ldrinit.c` — steps 3-4 (LdrInitializeThunk, LdrpInitializeProcess)
- `reactos/dll/win32/msvcrt/main.c` — step 6 (mainCRTStartup)

---

## Personality 2: Linux ELF — Static musl (Already Working)

```
1. KERNEL: Load ELF binary
   ─────────────────────────────────────────────────────────────────────
   proc/elf.rs: load_elf_binary(path)
     → Read ELF header, validate magic (0x7F 'E' 'L' 'F')
     → Parse program headers (PT_LOAD, PT_TLS, PT_INTERP)
     → No PT_INTERP: static binary
     → Map PT_LOAD segments to specified virtual addresses
     → Setup user stack at 0x0000_7FFF_FFFF_0000
     → Push argv/envp/auxv to stack (per ELF ABI)
     → Set TLS base from PT_TLS (arch_prctl ARCH_SET_FS)
     → Jump to ELF e_entry (_start)

2. MUSL: _start (crt/crt1.c compiled into binary)
   ─────────────────────────────────────────────────────────────────────
   _start:
     xor rbp, rbp                    ; clear frame pointer
     mov rdi, [rsp]                  ; argc
     lea rsi, [rsp+8]               ; argv
     lea rdx, [rsi+rdi*8+8]         ; envp
     and rsp, ~15                   ; 16-byte align stack
     call __libc_start_main

3. MUSL: __libc_start_main
   ─────────────────────────────────────────────────────────────────────
   __libc_start_main(main, argc, argv):
     __init_tp()                     ; setup TLS pointer
     __init_libc(envp, argv[0])      ; parse environ, init stdio
     __libc_start_init()             ; run .init_array
     int ret = main(argc, argv, envp)  ← USER CODE STARTS HERE
     exit(ret)

4. MUSL: exit()
   ─────────────────────────────────────────────────────────────────────
   exit(code):
     Call all atexit() callbacks
     Call all __cxa_atexit() callbacks (C++ static destructors)
     __libc_exit_fini()              ; run .fini_array
     _exit(code)                     ; syscall SYS_exit_group

5. KERNEL: exit_group(code)
   ─────────────────────────────────────────────────────────────────────
   syscall/mod.rs dispatch_linux(231, code):
     proc::exit_group(pid, code)
```

**This already works** for static musl. Confirmed: arch_prctl(158) → set_tid_address(218) → exit_group(231).

---

## Personality 2: Linux ELF — Dynamic musl (Future)

```
1. KERNEL: Load ELF binary
   ─────────────────────────────────────────────────────────────────────
   proc/elf.rs detects PT_INTERP = /lib/ld-musl-x86_64.so.1
   Load interpreter ELF at 0x7F00_0000_0000 (proc/elf.rs load_elf_dyn)
   Set AT_INTERP_BASE = interpreter load address
   Set AT_ENTRY = original ELF entry point (for ld.so to call later)
   Jump to interpreter _start (not original ELF _start)

2. MUSL ld.so: runtime dynamic linker
   ─────────────────────────────────────────────────────────────────────
   _dlstart_c(raw_sp, got):
     Find own load address (from AT_BASE in aux vector)
     Self-relocate (apply own RELATIVE relocations)
     __dls2(base, sp):
       Parse aux vector (AT_PHDR, AT_ENTRY, AT_BASE, AT_RANDOM, etc.)
       Map each DT_NEEDED .so:
         mmap(MAP_PRIVATE, file, offset) each PT_LOAD segment
         Apply RELATIVE, GLOB_DAT, JUMP_SLOT relocations
         Call DT_INIT
       Jump to AT_ENTRY (original application entry _start)

3. Application _start → __libc_start_main → main()
   (same as static, steps 2-5 above)
```

**Blockers for dynamic musl**:
- File-backed `mmap(MAP_PRIVATE, fd, offset)` — ld.so maps .so files this way
- `mprotect()` updating hardware PTEs — mark code pages RX after relocation
- Enough /lib/ directory structure on disk

---

## Personality 3: Aether Native ELF

```
1. KERNEL: Load ELF binary
   ─────────────────────────────────────────────────────────────────────
   proc/elf.rs detects OS/ABI = 0xFF (AstryxOS)
   Dispatch subsystem = Aether
   Load PT_LOAD segments normally
   No PT_INTERP → static binary
   Jump to e_entry (_start from libaether)

2. LIBAETHER: _start (libaether/src/start.s)
   ─────────────────────────────────────────────────────────────────────
   _start:
     xor rbp, rbp
     mov rdi, [rsp]      ; argc
     lea rsi, [rsp+8]    ; argv
     call __aether_start_main

3. LIBAETHER: __aether_start_main
   ─────────────────────────────────────────────────────────────────────
   __aether_start_main(argc, argv):
     __aether_init_tls()       ; arch_prctl ARCH_SET_FS
     __aether_init_heap()      ; mmap first heap region
     __aether_run_ctors()      ; .init_array
     int ret = main(argc, argv)  ← USER CODE STARTS HERE
     __aether_run_dtors()      ; .fini_array
     aether_exit(ret)          ; SYS_EXIT_GROUP
```

---

## Kernel Responsibilities Summary

What the kernel must provide *before* any CRT code runs:

| Personality | Kernel sets up | Entry point |
|-------------|---------------|-------------|
| Win32 | PEB+TEB at known addresses; GS → TEB; ntdll mapped | ntdll!LdrInitializeThunk |
| Linux (static) | Stack with argc/argv/envp/auxv; FS → TLS block | ELF e_entry (_start) |
| Linux (dynamic) | Same + AT_BASE=interp_base, AT_ENTRY=app_entry | Interpreter _start |
| Aether native | Stack with argc/argv/envp/auxv; optionally FS → TLS | ELF e_entry (_start) |

---

## The PEB / TEB: What AstryxOS Must Build for Win32

This is the most AstryxOS-specific piece of Win32 startup. The kernel must allocate and
fill these structures in the process's user address space:

```
+--- User address space -----------------------------------------------+
| 0x7FFDF000  PEB (Process Environment Block, 488 bytes on XP x64)     |
|   .ImageBaseAddress = 0x400000 (where EXE was loaded)                 |
|   .ProcessHeap = NULL (ntdll will fill this in LdrInitializeThunk)    |
|   .Ldr → PEB_LDR_DATA (ntdll fills in)                                |
|   .ProcessParameters → RTL_USER_PROCESS_PARAMETERS                    |
|     .CommandLine.Buffer = pointer to wchar_t argv[0] argv[1]...        |
|     .ImagePathName.Buffer = pointer to wchar_t path                   |
|     .Environment = pointer to environment block                        |
|     .StandardInput = handle 0 (stdin)                                 |
|     .StandardOutput = handle 1 (stdout)                               |
|     .StandardError = handle 2 (stderr)                                |
|                                                                       |
| 0x7FFDE000  TEB (Thread Environment Block, 4 KiB)                     |
|   .NtTib.ExceptionList = -1 (end of SEH chain)                        |
|   .NtTib.StackBase = stack top                                         |
|   .NtTib.StackLimit = stack bottom                                     |
|   .NtTib.Self = TEB address (TEB points to itself for quick access)   |
|   .ProcessEnvironmentBlock = 0x7FFDF000 (PEB address)                 |
|   .ClientId.UniqueProcess = PID                                        |
|   .ClientId.UniqueThread = TID                                         |
|   .LastErrorValue = 0 (GetLastError reads this)                        |
|   .TlsSlots[64] (TLS slot array — index 0 reserved for CRT)           |
+-----------------------------------------------------------------------+
```

**Reference**:
- `reactos/dll/ntdll/include/ntdll.h` — ReactOS PEB/TEB definitions
- `reactos/dll/ntdll/ldr/ldrinit.c` — reading from PEB in LdrInitializeThunk
- Public NT Internals documentation (Russinovich/Solomon) — PEB/TEB structure layouts
