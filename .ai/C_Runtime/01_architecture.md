# C Runtime Architecture

---

## The Fundamental Model: Personalities

AstryxOS supports three execution **personalities** — distinct ABIs with different syscall
conventions, error models, and runtime expectations. Each personality has its own C runtime stack.

```
╔══════════════════════════════════════════════════════════════════════╗
║                     APPLICATION LAYER                                ║
║  Win32 .exe      │  Linux .elf (ELF/musl)  │  Aether .elf (native)  ║
╠══════════════════╪═════════════════════════╪════════════════════════╣
║  MSVCRT / STL    │  musl libc / glibc      │  libaether             ║
║  (C runtime)     │  (POSIX + C runtime)    │  (minimal C runtime)   ║
╠══════════════════╪═════════════════════════╪════════════════════════╣
║  kernel32.dll    │  (libc does this)       │  (libaether does this) ║
║  (Win32 API)     │                         │                        ║
╠══════════════════╪═════════════════════════╪════════════════════════╣
║  ntdll.dll       │  ld-musl.so.1           │  (static link)         ║
║  (NT layer + LDR)│  (dynamic linker)       │                        ║
╠══════════════════╪═════════════════════════╪════════════════════════╣
║  INT 2E / SYSCALL│  SYSCALL                │  SYSCALL / INT 0x80    ║
╠══════════════════╪═════════════════════════╪════════════════════════╣
║         A E T H E R   K E R N E L   E X E C U T I V E              ║
║  dispatch_win32() (SSDT)  │  dispatch_linux()  │  dispatch_aether() ║
╚══════════════════════════════════════════════════════════════════════╝
```

Each layer is **userspace except the bottom row**. The kernel only sees syscall numbers and
arguments — it doesn't know or care about malloc, printf, or STL.

---

## NT Personality: The Win32 Stack in Detail

This is the architecture Windows has used since NT 3.1. Every component is a userspace DLL.

```
application.exe
    │
    │ imports  ──────────────────────────────────────────────────────┐
    ▼                                                                │
msvcrt.dll / ucrtbase.dll                                           │
  malloc(), free(), printf(), scanf(), fopen(), fclose()            │
  _beginthread(), _endthread()                                      │
  C++ new/delete, std::exception, std::string, STL containers       │
    │                                                                │
    │ imports                                                        │
    ▼                                                                │
kernel32.dll (+ kernelbase.dll in Vista+)                           │
  CreateFile(), ReadFile(), WriteFile(), CloseHandle()              │
  CreateProcess(), CreateThread(), ExitProcess()                    │
  VirtualAlloc(), VirtualFree(), VirtualProtect()                   │
  GetStdHandle(), WriteConsoleA(), ReadConsoleA()                   │
  GetLastError(), SetLastError()                                    │
    │                                                                │
    │ imports                                                        │
    ▼                                                                │
ntdll.dll   ◄───────────────────── ALL DLLS link to ntdll ──────────┘
  NtCreateFile(), NtReadFile(), NtWriteFile(), NtClose()
  NtAllocateVirtualMemory(), NtFreeVirtualMemory()
  NtProtectVirtualMemory(), NtQueryVirtualMemory()
  NtCreateProcess(), NtTerminateProcess(), NtCreateThread()
  LdrLoadDll(), LdrUnloadDll(), LdrGetProcedureAddress()
  RtlAllocateHeap(), RtlFreeHeap(), RtlReAllocateHeap()
  RtlCreateHeap(), RtlDestroyHeap()
  RtlCopyMemory(), RtlZeroMemory(), RtlCompareMemory()
  RtlInitUnicodeString(), RtlUnicodeStringToAnsiString()
  RtlRaiseException(), RtlUnwind() (SEH)
  KeUserModeCallback() (kernel → user callbacks)
    │
    │ INT 2E or SYSCALL (syscall number in RAX, args in RCX/RDX/R8/R9)
    ▼
Aether Kernel — NT Executive (SSDT)
  NtCreateFile handler, NtReadFile handler, NtAllocateVirtualMemory handler...
  (kernel/src/syscall/mod.rs → dispatch_win32 path)
```

**Key NT design rules**:
1. Only ntdll.dll talks directly to the kernel. ALL other DLLs call ntdll.
2. ntdll is loaded by the kernel into every process before any other code runs.
3. The IAT (Import Address Table) in the PE binary is pre-patched with ntdll exports.
4. kernel32.dll is NOT a kernel DLL — despite the name, it's a userspace Win32 compatibility shim.

---

## Linux Personality: The ELF Stack in Detail

```
application.elf
    │
    │ dynamic: PT_INTERP = /lib/ld-musl-x86_64.so.1
    ▼
ld-musl-x86_64.so.1  (dynamic linker / loader)
  mmap() the libc
  Resolve PLT/GOT relocations
  Call DT_INIT sections
  Jump to _start
    │
    │ links to
    ▼
musl libc.so  (or glibc libc.so.6)
  malloc(), free(), printf(), scanf(), fopen(), fclose()
  pthread_create(), pthread_mutex_lock()
  All POSIX: stat(), open(), read(), write(), fork(), exec()
  C++ (via libstdc++ / libc++ layered on top)
    │
    │ SYSCALL instruction (syscall number in RAX, args in RDI/RSI/RDX/R10/R8/R9)
    ▼
Aether Kernel — Linux compat (dispatch_linux)
  sys_read, sys_write, sys_openat, sys_mmap, sys_clone, sys_exit...
  (kernel/src/syscall/mod.rs → dispatch_linux path)
```

**Key Linux design rules**:
1. Everything in libc calls SYSCALL directly — no intermediate DLL layer.
2. Dynamic linking is handled by ld.so (the runtime dynamic linker).
3. Static linking embeds libc.a directly in the binary (no .so at all).
4. musl and glibc are ABI-compatible at the syscall level but differ in symbols.

---

## Aether Native Personality

AstryxOS's own native ABI — for OS utilities, the kernel loader, and native apps.

```
native_app.elf (OS/ABI byte = 0xFF = AstryxOS)
    │
    │ static link
    ▼
libaether.a (future: libaether.so)
  Minimal C runtime: malloc, printf, string ops
  Aether syscall wrappers: sys_open(), sys_write(), sys_fork()
  AstryxOS extensions: window_create(), ipc_connect()
    │
    │ SYSCALL / INT 0x80 (Aether ABI: syscall number in RAX)
    ▼
Aether Kernel — Native (dispatch_aether)
  (kernel/src/syscall/mod.rs → dispatch_aether path)
```

---

## Critical Architectural Decision: ntdll is NOT in the Kernel

**Current wrong state** (`kernel/src/nt/mod.rs`):
```
Kernel space:
  extern "C" fn nt_fn_close()    { /* stub */ }
  extern "C" fn nt_fn_read_file() { /* stub */ }
  ... 73 functions ...
  fn lookup_stub(dll, name) → VA in kernel space
PE loader patches IAT with addresses inside kernel text
```

**Why this is wrong**: When a PE application calls `CloseHandle()`, it calls kernel32 → ntdll →
the function pointer that was patched into the IAT. If that pointer points into kernel space,
the CPU is executing ring-3 code at a kernel address. This is a GPF on a real system and
conceptually wrong — ntdll must live in user address space.

**Correct architecture**:
```
Kernel SSDT:
  SSDT[NT_CLOSE] = kernel's handler for NtClose
  SSDT[NT_READ_FILE] = kernel's handler for NtReadFile
  (these are legitimate kernel-space functions)

Userspace ntdll.dll:
  NtClose:
    mov rax, NT_CLOSE   ; service number
    syscall             ; INT 2E or SYSCALL
    ret

PE loader patches IAT with addresses in ntdll.dll (user space)
```

The **stubs in nt/mod.rs** should be migrated to a userspace `ntdll.dll` binary. The SSDT
in the kernel should only contain the actual handlers (which `dispatch_win32` already wires).

---

## Comparison: How Each Source Does It

| Aspect | Windows XP | ReactOS | Linux | AstryxOS (target) |
|--------|-----------|---------|-------|-------------------|
| Kernel syscall entry | INT 2E / SYSCALL | INT 2E / SYSCALL | SYSCALL | INT 2E + SYSCALL (both working) |
| NT layer | ntdll.dll (user) | ntdll.dll (user) | n/a | ntdll.dll (user, to build) |
| C runtime | msvcrt.dll (user) | msvcrt.dll (user) | libc.so.6 / musl | msvcrt.dll (user, to build) |
| C++ STL | msvcp*.dll (user) | msvcp*.dll (user) | libstdc++ / libc++ | to build |
| Dynamic linker | ntdll LDR | ntdll LDR | ld.so | ntdll LDR (Win32) / ld-musl (Linux) |
| Source reference | ReactOS / NT Internals docs | `reactos/dll/ntdll/` + `reactos/dll/win32/msvcrt/` | linux kernel syscall table | — |

---

## What the Kernel Actually Needs to Provide

For each personality, the kernel just needs to correctly handle these syscall gates:

**Win32 (INT 2E, RAX = service number)**:
```
RAX = 0x00 → NtClose(Handle)
RAX = 0x01 → NtCreateFile(...)
RAX = 0x15 → NtAllocateVirtualMemory(...)
RAX = 0x1B → NtCreateThread(...)
... (43 services defined in kernel/src/nt/mod.rs, need real handlers)
```

**Linux (SYSCALL, RAX = Linux syscall number)**:
```
RAX = 0  → read()
RAX = 1  → write()
RAX = 9  → mmap()
RAX = 60 → exit()
... (~90 wired, many more needed)
```

**Aether (SYSCALL / INT 0x80, RAX = Aether syscall number)**:
```
RAX = SYS_OPEN → open()
RAX = SYS_READ → read()
... (NT-style constants currently)
```

Everything above the syscall boundary is **userspace** and is what we must build.
