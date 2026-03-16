# Win32 C Runtime (MSVCRT + STL)

> This covers the Win32 personality: ntdll.dll → kernel32.dll → msvcrt.dll → STL/msvcp
> Reference: `SupportingResources/Microsoft-Windows-XP-Source-Kit/base/crts/`
>             `SupportingResources/Microsoft-Windows-XP-Source-Kit/base/ntdll/`
>             `SupportingResources/reactos/dll/ntdll/`
>             `SupportingResources/reactos/dll/win32/msvcrt/`

---

## Layer 1: ntdll.dll — The NT Foundation

ntdll.dll is the most critical userspace component in the NT architecture. It is:
- The **only** DLL that makes kernel syscalls (INT 2E / SYSCALL)
- The **process loader** (LDR subsystem — loads and links all other DLLs)
- The **NT heap manager** (RtlCreateHeap, RtlAllocateHeap, RtlFreeHeap)
- The **exception dispatcher** (RtlRaiseException, RtlUnwind, SEH unwinder)
- The **string/memory runtime** (RtlCopyMemory, RtlCompareMemory, etc.)
- The **NT API surface** (Nt* and Zw* function families)

### What ntdll must export

```
Category           Functions
─────────────────  ────────────────────────────────────────────────────────
NT system calls    NtClose, NtCreateFile, NtReadFile, NtWriteFile, NtOpenFile
                   NtAllocateVirtualMemory, NtFreeVirtualMemory
                   NtProtectVirtualMemory, NtQueryVirtualMemory
                   NtCreateProcess, NtTerminateProcess, NtCreateThread
                   NtTerminateThread, NtQueryInformationProcess
                   NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection
                   NtCreateEvent, NtSetEvent, NtResetEvent, NtWaitForSingleObject
                   NtWaitForMultipleObjects, NtCreateMutant, NtReleaseMutant
                   NtCreateSemaphore, NtReleaseSemaphore
                   NtSetSystemTime, NtQuerySystemTime
                   NtQuerySystemInformation, NtQueryPerformanceCounter

Zw* aliases        ZwClose = NtClose (same function, different kernel path on NT)
                   ZwCreateFile, ZwReadFile, ZwWriteFile, etc.

Heap manager       RtlCreateHeap, RtlDestroyHeap
                   RtlAllocateHeap, RtlFreeHeap, RtlReAllocateHeap
                   RtlSizeHeap, RtlValidateHeap
                   RtlGetProcessHeaps, NtCurrentPeb() → ProcessHeap

Process loader     LdrLoadDll, LdrUnloadDll
                   LdrGetProcedureAddress
                   LdrFindEntryForAddress
                   LdrInitializeThunk (called by kernel at process start)

Exception (SEH)    RtlRaiseException, RtlUnwind, RtlUnwindEx
                   RtlCaptureContext, RtlRestoreContext
                   RtlLookupFunctionEntry (x64 RUNTIME_FUNCTION table)
                   RtlVirtualUnwind

Strings / memory   RtlCopyMemory, RtlMoveMemory, RtlZeroMemory
                   RtlFillMemory, RtlEqualMemory, RtlCompareMemory
                   RtlInitUnicodeString, RtlUnicodeStringToAnsiString
                   RtlAnsiStringToUnicodeString, RtlFreeUnicodeString
                   RtlCompareString, RtlUpperString

Critical sections  RtlInitializeCriticalSection, RtlDeleteCriticalSection
                   RtlEnterCriticalSection, RtlLeaveCriticalSection
                   RtlTryEnterCriticalSection

TLS                RtlAllocateThreadActivationContextStack
                   TlsAlloc, TlsFree, TlsSetValue, TlsGetValue (via PEB/TEB)

Debugging          DbgPrint, DbgBreakPoint, RtlAssert
                   OutputDebugStringA/W
```

### ntdll internal structure

The NT LDR (Loader) subsystem within ntdll is responsible for:

```
LdrpInitializeProcess()  (called from LdrInitializeThunk, which kernel calls at process start)
  │
  ├── Parse PEB.Ldr (populated by kernel before process starts)
  ├── Load kernel32.dll (if not already mapped)
  ├── Load each DLL in the EXE's import table (recursively)
  │     LdrpLoadDll()
  │       → find DLL on disk (search PATH, System32, etc.)
  │       → NtCreateSection / NtMapViewOfSection
  │       → apply base relocations (LdrpRelocateImage)
  │       → patch Import Address Table (LdrpSnapThunk)
  │       → call DLL entry point with DLL_PROCESS_ATTACH
  │
  └── Call EXE entry point (kernel32!mainCRTStartup or WinMainCRTStartup)
```

**Reference files**:
- `XP/base/ntdll/ldrinit.c` — `LdrpInitializeProcess` (2,000 LOC)
- `XP/base/ntdll/ldrapi.c` — `LdrLoadDll`, `LdrGetProcedureAddress`
- `XP/base/ntdll/ldrsnap.c` — IAT snapping / thunk patching
- `XP/base/ntdll/ldrutil.c` — helper routines
- `reactos/dll/ntdll/ldr/ldrpe.c` — PE loading (cleaner, same logic)
- `reactos/dll/ntdll/ldr/ldrinit.c` — initialization

### ntdll syscall stubs (the key piece)

Each NT function is just a tiny stub that invokes the kernel:

```asm
; x86_64 NT syscall stub pattern (Windows 8+)
NtReadFile:
    mov r10, rcx        ; syscall convention: R10 = RCX (first arg)
    mov eax, 0x06       ; NT_READ_FILE service number
    syscall             ; kernel entry via SYSCALL MSR
    ret

; INT 2E variant (Windows XP / older):
NtReadFile_int2e:
    mov eax, 0x06       ; NT_READ_FILE service number
    lea edx, [esp+4]    ; pointer to argument block
    int 0x2E            ; kernel entry via IDT
    ret
```

For AstryxOS, the service numbers are defined in `kernel/src/nt/mod.rs`:
```
NT_CLOSE=0x00, NT_CREATE_FILE=0x01, NT_READ_FILE=0x06, NT_WRITE_FILE=0x07...
```

**ntdll.dll should have one such stub per SSDT entry.** The 43 SSDT entries in
`kernel/src/nt/mod.rs` = 43 stubs in ntdll.dll.

---

## Layer 2: kernel32.dll — Win32 API

kernel32.dll is a thin translation layer between the Win32 API (Unicode/ANSI, Win32 handles,
Win32 errors) and the NT API (Unicode-native, NT handles, NTSTATUS).

```
CreateFileA(path_ansi, ...) {
    wchar path_wide = AnsiToUnicode(path_ansi);   // via RtlAnsiStringToUnicodeString
    return CreateFileW(path_wide, ...);
}

CreateFileW(path_wide, access, share, sa, disposition, flags, template) {
    OBJECT_ATTRIBUTES oa = make_oa(path_wide, OBJ_CASE_INSENSITIVE);
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = NtCreateFile(&handle, access, &oa, &iosb, ...);
    if (!NT_SUCCESS(status)) {
        SetLastError(RtlNtStatusToDosError(status));  // translate error code
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}
```

### kernel32.dll export list (minimum viable)

```
File I/O         CreateFileA/W, ReadFile, WriteFile, CloseHandle
                 GetFileSize, SetFilePointer, FlushFileBuffers
                 CreateDirectory, RemoveDirectory, DeleteFile, MoveFile
                 FindFirstFile, FindNextFile, FindClose
                 GetFullPathName, GetCurrentDirectory, SetCurrentDirectory

Console          GetStdHandle, WriteConsoleA/W, ReadConsoleA/W
                 AllocConsole, FreeConsole, SetConsoleTitle
                 GetConsoleMode, SetConsoleMode, SetConsoleCtrlHandler

Process/Thread   CreateProcess, CreateThread, ExitProcess, ExitThread
                 GetCurrentProcess, GetCurrentProcessId
                 GetCurrentThread, GetCurrentThreadId
                 WaitForSingleObject, WaitForMultipleObjects
                 OpenProcess, TerminateProcess, TerminateThread
                 GetExitCodeProcess, GetExitCodeThread

Memory           VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery
                 GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc, HeapSize
                 LocalAlloc, LocalFree, GlobalAlloc, GlobalFree

Sync             CreateEvent, SetEvent, ResetEvent, PulseEvent, OpenEvent
                 CreateMutex, ReleaseMutex, OpenMutex
                 CreateSemaphore, ReleaseSemaphore, OpenSemaphore
                 InitializeCriticalSection, EnterCriticalSection, LeaveCriticalSection

System info      GetSystemInfo, GlobalMemoryStatus, GetSystemTime, GetLocalTime
                 QueryPerformanceCounter, QueryPerformanceFrequency
                 GetTickCount, GetTickCount64
                 Sleep, SleepEx
                 GetComputerName, GetUserName, GetWindowsDirectory

Error            GetLastError, SetLastError, FormatMessageA/W

Library          LoadLibraryA/W, FreeLibrary, GetProcAddress
                 GetModuleHandle, GetModuleFileName

Misc             IsDebuggerPresent, DebugBreak, OutputDebugStringA/W
                 GetCommandLineA/W, GetEnvironmentVariable, SetEnvironmentVariable
                 SetConsoleCtrlHandler
```

**Reference files**:
- `reactos/dll/win32/kernel32/` — complete kernel32 reimplementation
- `XP/base/ntos/io/` — NT I/O primitives that kernel32 wraps

---

## Layer 3: msvcrt.dll — C Runtime

msvcrt.dll provides the full C standard library. It calls kernel32/ntdll for OS operations.

### Organization by subsystem

```
Startup / init
  crt0.c         mainCRTStartup() → initialize CRT → call main() → exit()
  dllcrt0.c      DllMain() entry point for DLLs
  tlssup.c       TLS callbacks (for C++ static constructors in DLLs)
  crt0init.c     .CRT$XI* initializers (C++ static ctors / atexit table)

Heap (malloc)
  malloc.c       malloc() → HeapAlloc(ProcessHeap, 0, size)
  free.c         free() → HeapFree(ProcessHeap, 0, ptr)
  realloc.c      realloc()
  new.cpp        operator new → malloc()
  delete.cpp     operator delete → free()
  sbheap.c       small block heap (separate pool for < 1024 byte allocs)

Standard I/O (stdio)
  fopen.c        fopen → CreateFile
  fread.c        fread → ReadFile
  fwrite.c       fwrite → WriteFile
  fclose.c       fclose → CloseHandle
  printf.c       printf → fwrite(stdout)
  scanf.c        scanf → fread(stdin)
  _open.c        open() → CreateFile (POSIX lowio)
  _read.c        read() → ReadFile
  _write.c       write() → WriteFile (lowio layer)

Strings
  strcpy, strcat, strlen, strcmp, strncmp, strstr, strtok
  wcscpy, wcscat, wcslen, wcscmp (wide char)
  sprintf, vsprintf, sscanf (formatted)
  strtol, strtod, atoi, atof

Math
  sin, cos, tan, sqrt, pow, log, exp (call FPU or x87)
  floor, ceil, round, fabs

Time
  time(), localtime(), gmtime(), mktime()
  clock() → QueryPerformanceCounter / GetTickCount
  difftime()

Process
  exit() → ExitProcess()
  abort() → terminate()
  system() → CreateProcess("cmd.exe /c ...")
  getenv() → GetEnvironmentVariable()
  putenv() → SetEnvironmentVariable()
  _beginthread / _endthread → CreateThread / ExitThread

C++ exception handling (SEH integration)
  eh/frame.cpp      __CxxFrameHandler (SEH-based C++ exception dispatch)
  eh/throw.cpp      _CxxThrowException
  eh/rtti.cpp       dynamic_cast, typeid

Locale
  setlocale(), localeconv()
  Multi-byte character support (mbstowcs, wcstombs)
```

**Reference files**:
- `XP/base/crts/crtw32/startup/crt0.c` — mainCRTStartup
- `XP/base/crts/crtw32/heap/malloc.c` — malloc
- `XP/base/crts/crtw32/stdio/` — stdio implementation
- `XP/base/crts/crtw32/eh/frame.cpp` — C++ exception handling
- `reactos/dll/win32/msvcrt/` — complete msvcrt reimplementation (easiest reference)
  - `reactos/dll/win32/msvcrt/heap.c` — heap ops
  - `reactos/dll/win32/msvcrt/main.c` — mainCRTStartup
  - `reactos/dll/win32/msvcrt/except.c` — exception handling

---

## Layer 4: STL — C++ Standard Template Library

The STL (msvcp140.dll, libstdc++, or libc++) lives on top of the CRT.
It requires only:
- `operator new` / `operator delete` (from msvcrt)
- `malloc` / `free`
- Basic I/O streams

### Components needed

```
Containers      std::vector, std::list, std::deque, std::map, std::unordered_map
                std::set, std::unordered_set, std::queue, std::stack
Algorithms      std::sort, std::find, std::copy, std::transform, std::for_each
Strings         std::string, std::wstring, std::string_view
Streams         std::cin, std::cout, std::cerr, std::stringstream, std::fstream
Utilities       std::shared_ptr, std::unique_ptr, std::optional, std::variant
                std::tuple, std::pair, std::function, std::any
Exceptions      std::exception, std::runtime_error, std::logic_error, std::bad_alloc
Threading       std::thread, std::mutex, std::condition_variable (needs OS primitives)
                std::atomic<T> (uses CPU atomic instructions, no OS needed)
```

### Options for AstryxOS

**Option A: Port LLVM libc++ to AstryxOS**
- libc++ is the cleanest modern STL implementation
- Available from LLVM source; works with clang
- Needs: `operator new/delete`, `malloc/free`, `pthread_mutex` or `std::mutex` backend
- Size: ~2 MB compiled

**Option B: Use libstdc++ (GCC's STL)**
- Larger, more complex, but extremely well-tested
- Available in the GCC source; used by most Linux software
- Needs: glibc or musl for POSIX threading primitives

**Option C: Minimal STL for Win32 personality only**
- Implement only what Win32 apps need (most don't use STL directly)
- Just `std::string`, `std::vector`, `std::map` (200 LOC each)
- Suitable for the initial Win32 compat layer

**Recommendation**: Start with Option C (minimal) for Win32 compat. For the Linux
personality, libstdc++/libc++ will come as part of the GCC/clang toolchain targeting musl.

---

## Error Handling Model: NTSTATUS vs Win32 Error vs C errno

Win32 uses three parallel error systems that must all be properly threaded:

```
Kernel returns:   NTSTATUS (0xC0000005 = ACCESS_VIOLATION, 0x00000000 = SUCCESS)
                           │
                           │ ntdll: RtlNtStatusToDosError()
                           ▼
kernel32 stores:  Win32 Error (GetLastError → DWORD 5 = ERROR_ACCESS_DENIED)
                           │
                           │ msvcrt: errno_from_win32error()
                           ▼
msvcrt stores:    errno (EACCES = 13)
```

The mapping chain is already partially present in `subsys/linux/errno.rs`.
A parallel `nt/ntstatus_to_win32.rs` + `nt/win32_to_errno.rs` table needs to be built.

---

## Minimum Viable Win32 Runtime (MVP)

To get a simple Win32 console app (`Hello, World!`) running:

```
1. ntdll.dll:
   - NtWriteFile() syscall stub → kernel INT 2E
   - NtAllocateVirtualMemory() syscall stub
   - NtTerminateProcess() syscall stub
   - RtlAllocateHeap() / RtlFreeHeap() (small allocator)
   - LdrInitializeThunk() entry point

2. kernel32.dll:
   - WriteConsoleA() → NtWriteFile(stdout_handle, ...)
   - GetStdHandle(STD_OUTPUT_HANDLE) → return pre-assigned console handle
   - ExitProcess() → NtTerminateProcess()
   - HeapAlloc/HeapFree → RtlAllocateHeap/RtlFreeHeap

3. msvcrt.dll:
   - mainCRTStartup() → get argc/argv from PEB → call main() → call ExitProcess(ret)
   - printf() → WriteConsoleA()
   - malloc() / free() → HeapAlloc/HeapFree

4. Kernel SSDT (must be real handlers, not stubs):
   - NT_WRITE_FILE handler: dispatch to VFS write()
   - NT_TERMINATE_PROCESS handler: dispatch to proc::exit_group()
   - NT_ALLOCATE_VIRTUAL_MEMORY handler: dispatch to mm::mmap()
```

This is the minimum to run: `int main() { printf("Hello\n"); return 0; }`

---

## Process Environment Block (PEB) and Thread Environment Block (TEB)

The PEB and TEB are NT structures that the kernel populates before transferring control
to ntdll. They form the primary communication channel between kernel and userspace.

```c
typedef struct _PEB {
    UCHAR       InheritedAddressSpace;      // 0x000
    UCHAR       ReadImageFileExecOptions;   // 0x001
    UCHAR       BeingDebugged;              // 0x002
    UCHAR       BitField;                   // 0x003
    PVOID       Mutant;                     // 0x008
    PVOID       ImageBaseAddress;           // 0x010  ← EXE base
    PVOID       Ldr;                        // 0x018  ← PEB_LDR_DATA (DLL list)
    PVOID       ProcessParameters;          // 0x020  ← RTL_USER_PROCESS_PARAMETERS
    PVOID       SubSystemData;              // 0x028
    PVOID       ProcessHeap;               // 0x030  ← default heap handle
    // ... many more fields
} PEB;

typedef struct _TEB {
    NT_TIB      NtTib;                      // 0x000  ← ExceptionList, StackBase, StackLimit
    PVOID       EnvironmentPointer;         // 0x038
    CLIENT_ID   ClientId;                   // 0x040  ← UniqueProcess, UniqueThread
    PVOID       ActiveRpcHandle;            // 0x050
    PVOID       ThreadLocalStoragePointer;  // 0x058  ← TLS array
    PVOID       ProcessEnvironmentBlock;    // 0x060  ← points to PEB
    ULONG       LastErrorValue;             // 0x068  ← GetLastError() reads this
    // ... many more fields
} TEB;
```

The TEB is accessed via `GS:0` on x86_64 (set via `arch_prctl(ARCH_SET_GS, teb_addr)`).
`GetLastError()` reads `GS:[0x68]`. `NtCurrentTeb()` reads `GS:0`.

**AstryxOS kernel must populate PEB + TEB before jumping to ntdll entrypoint.**

This is the most complex part of Win32 startup. See:
- `XP/base/ntdll/ldrinit.c` — `LdrpInitializeProcess()` builds these structures
- `reactos/dll/ntdll/ldr/ldrinit.c` — ReactOS equivalent
