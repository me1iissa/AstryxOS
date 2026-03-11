# Win32/WoW Subsystem — Design Document

> Last updated: 2026-03-05

## 1. Purpose

The Win32/WoW subsystem provides **Windows application compatibility** for AstryxOS.
This enables running PE32+ (64-bit) and eventually PE32 (32-bit via WoW64) Windows
executables. The implementation is inspired by:

- **Windows NT** executive architecture (`SupportingResources/NT4.0/private/`)
- **ReactOS** Win32 subsystem (`SupportingResources/reactos/win32ss/`)
- **Wine** NT syscall thunking and PE loading

## 2. Architecture

```
  Win32 PE executable (.exe)
         │
         │  loaded by PE loader → ntdll.dll thunks → INT 0x2E / SYSCALL
         ▼
  ┌──────────────────────┐
  │  win32::dispatch      │  ← translates Nt* numbers → Aether calls
  │  (subsys/win32/)      │
  └──────────┬───────────┘
             │
       ┌─────┴──────────────────────┐
       │                            │
       ▼                            ▼
  ┌──────────┐            ┌─────────────────┐
  │ NT Compat │            │ Win32k (GDI/USER)│
  │ (NtCreate │            │ Window manager   │
  │  File etc) │            │ integration      │
  └─────┬─────┘            └────────┬────────┘
        │                           │
        └───────────┬───────────────┘
                    ▼
            ┌───────────────┐
            │ Aether Kernel  │
            │ Primitives     │
            └───────────────┘
```

## 3. Current State

### What exists

| Component | Status | Location |
|-----------|--------|----------|
| `SubsystemType` enum | ✅ Defined | `kernel/src/win32/mod.rs` |
| `SubsystemContext` | ✅ Defined | `kernel/src/win32/mod.rs` |
| `Win32Environment` (per-process) | ✅ Skeleton | `kernel/src/win32/mod.rs` |
| Window Station / Desktop in OB | ✅ Created | `win32::init()` → OB namespace |
| CSRSS ALPC port | ✅ Created | `\ALPC\CsrApiPort` |
| `CsrApiNumber` enum | ✅ Defined | `kernel/src/win32/mod.rs` |
| Subsystem registry | ✅ Working | 3 subsystems registered (Native, Posix, Win32) |
| GDI primitives | ✅ Skeleton | `kernel/src/gdi/` (DC, BitBlt, surfaces, regions) |
| Object Manager (NT namespace) | ✅ Working | `kernel/src/ob/` |
| Handle Table | ✅ Working | `kernel/src/ob/handle.rs` |
| Access Tokens + ACLs | ✅ Working | `kernel/src/security/` |
| ALPC messaging | ✅ Working | `kernel/src/lpc/mod.rs` |
| IRP / Driver model | ✅ Working | `kernel/src/io/mod.rs` |

### What needs to be built

| Component | Priority | Description |
|-----------|----------|-------------|
| PE loader | P0 | Parse PE32+/PE32 headers, load sections, relocations |
| ntdll.dll stub | P0 | Minimal NT API thunks (NtCreateFile, NtClose, etc.) |
| NT syscall dispatch | P0 | Map Nt* call numbers to Aether primitives |
| INT 0x2E handler | P0 | IDT entry for NT system service calls |
| SSDT (System Service Descriptor Table) | P1 | NT-style syscall table |
| kernel32.dll stub | P1 | Win32 API → NT API translation |
| user32.dll stub | P2 | Window management, messaging |
| gdi32.dll stub | P2 | Graphics Device Interface |
| WoW64 layer | P3 | 32-bit PE32 → 64-bit thunking |

## 4. NT Syscall ABI

NT system calls use a different number space from Linux/Aether:

| Register | Purpose |
|----------|---------|
| RAX | NT system service number (SSDT index) |
| RCX | arg1 (NT calling convention: `__stdcall`) |
| RDX | arg2 |
| R8  | arg3 |
| R9  | arg4 |
| Stack | arg5+ (pushed right-to-left) |
| RAX (return) | NTSTATUS code |

Entry: `INT 0x2E` → `nt_syscall_handler` → index into SSDT.
(Modern NT also uses `SYSCALL` via ntdll thunks, but INT 0x2E is the classic path.)

## 5. NT System Service Table (SSDT) — Phase 1

```
SSDT#  Name                    → Aether Equivalent
────── ─────────────────────── ───────────────────────
0x00   NtAcceptConnectPort     → lpc::accept_connection
0x01   NtAccessCheck           → security::check_access
0x06   NtClose                 → vfs::close / ob::close_handle
0x0C   NtCreateEvent           → ke::create_event
0x0F   NtCreateFile            → vfs::open (with NT open options)
0x15   NtCreateSection         → mm::create_section
0x17   NtCreateThread          → proc::clone
0x1E   NtDuplicateObject       → ob::duplicate_handle
0x25   NtFreeVirtualMemory     → mm::munmap
0x2B   NtMapViewOfSection      → mm::mmap
0x31   NtOpenFile              → vfs::open
0x34   NtOpenProcess           → proc (handle-based)
0x39   NtProtectVirtualMemory  → mm::mprotect
0x44   NtQueryInformationFile  → vfs::fstat
0x4F   NtReadFile              → vfs::read
0x54   NtReadVirtualMemory     → mm::read_process_memory
0x60   NtSetInformationFile    → vfs::ioctl
0x67   NtTerminateProcess      → proc::exit
0x68   NtTerminateThread       → proc::exit_thread
0x6F   NtUnmapViewOfSection    → mm::munmap
0x73   NtWaitForSingleObject   → ke::wait_for_single_object
0x74   NtWaitForMultipleObjects → ke::wait_for_multiple_objects
0x78   NtWriteFile             → vfs::write
0x7A   NtWriteVirtualMemory    → mm::write_process_memory
```

## 6. PE Loader Design

```rust
// kernel/src/subsys/win32/pe_loader.rs

pub struct PeImage {
    pub base_address: u64,
    pub entry_point: u64,
    pub size_of_image: u64,
    pub sections: Vec<PeSection>,
    pub imports: Vec<ImportEntry>,
    pub relocations: Vec<Relocation>,
}

pub fn load_pe(data: &[u8], preferred_base: u64) -> Result<PeImage, PeError> {
    // 1. Parse DOS header (MZ)
    // 2. Parse PE signature at e_lfanew
    // 3. Parse COFF header + Optional header
    // 4. Map sections (RVA → virtual addresses)
    // 5. Apply base relocations if loaded at non-preferred address
    // 6. Resolve imports (IAT patching)
    // 7. Return PeImage with entry point
}
```

### Reference: ReactOS PE loader
- `SupportingResources/reactos/ntoskrnl/mm/section.c` — `MmLoadSystemImage`
- `SupportingResources/reactos/dll/ntdll/ldr/` — User-mode PE loader

## 7. CSRSS Communication

Win32 processes communicate with the CSRSS server via ALPC:

```
Win32 Process                    CSRSS Server (kernel-mode)
     │                                  │
     │──── ALPC Request ──────────────►│
     │     (CsrApiNumber::CreateProcess)│
     │                                  │── create window station entry
     │◄──── ALPC Reply ────────────────│
     │     (success + console handle)   │
```

The existing ALPC infrastructure (`kernel/src/lpc/mod.rs`) already supports this pattern.

## 8. Module Structure (Target)

```
kernel/src/subsys/win32/
├── mod.rs           — init, SubsystemType, Win32Environment
├── dispatch.rs      — NT syscall dispatch (SSDT)
├── pe_loader.rs     — PE32+/PE32 parser and loader
├── ntdll.rs         — ntdll.dll function stubs
├── kernel32.rs      — kernel32.dll thunks (→ ntdll)
├── csrss.rs         — CSRSS server logic (ALPC handler)
├── user32.rs        — USER subsystem (windows, messages)
├── gdi32.rs         — GDI subsystem (DCs, drawing)
└── wow64.rs         — WoW64 thunking (32→64 bit, future)
```

## 9. Integration with Existing Components

| AstryxOS Component | Win32 Usage |
|---------------------|-------------|
| `ob/` (Object Manager) | NT object namespace (`\Device\`, `\BaseNamedObjects\`) |
| `ob/handle.rs` (Handle Table) | NT-style handles for all kernel objects |
| `security/` (Tokens, ACLs) | Process tokens, access checks on open |
| `lpc/` (ALPC) | CSRSS communication, LPC port objects |
| `ke/` (Dispatcher objects) | Events, mutants, semaphores, timers |
| `ex/` (Executive resources) | Kernel worker threads, locks |
| `io/` (I/O Manager, IRPs) | NtCreateFile → IRP dispatch to drivers |
| `gdi/` (GDI primitives) | Device contexts, BitBlt, text rendering |
| `wm/` (Window Manager) | wm::window for HWND-based operations |
| `mm/` (Memory Manager) | VirtualAlloc/Free → mmap/munmap, sections |

## 10. Testing Strategy

- **Unit test**: PE header parsing (test with minimal PE binaries)
- **Integration test**: Load a simple PE .exe, verify sections mapped correctly
- **Syscall test**: NT syscall dispatch for NtWriteFile, NtClose, NtTerminateProcess
- **End-to-end**: Simple Win32 console app (printf via WriteConsoleA) runs to completion

## 11. Reference Material

- NT4.0 source: `SupportingResources/NT4.0/private/` (csr/, windows/, sm/)
- ReactOS: `SupportingResources/reactos/` (subsystems/csr/, win32ss/, ntoskrnl/)
- OpenNT: `SupportingResources/OpenNT/`
- Wine: PE loading, DLL stubbing (external reference)
