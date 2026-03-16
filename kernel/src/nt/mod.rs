//! NT Subsystem — kernel-mode stubs for Windows NT syscalls.
//!
//! # Architecture
//! This module provides the NT system service dispatch table (SSDT) for
//! AstryxOS.  Each NT function number maps to a thin kernel wrapper that
//! translates the NT argument convention and delegates to the existing
//! Aether/Linux kernel primitives already implemented in `crate::syscall`.
//!
//! # INT 0x2E Support
//! Windows NT originally used `INT 0x2E` for system calls.  AstryxOS supports
//! this gate for Win32 compatibility.  The IDT handler calls
//! `dispatch_nt_int2e`, which extracts the NT-ABI registers and routes to
//! `dispatch_nt`.
//!
//! # NT Syscall ABI  (INT 0x2E / SYSCALL variant)
//! - RAX = service number
//! - RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
//! - Stack: arg5, arg6, ... at [RSP+0x28], [RSP+0x30], ...
//!
//! # IAT Stub Lookup
//! When the PE loader resolves imports, it calls `lookup_stub(dll, name)` to
//! get a kernel-function pointer to install into the IAT.  This pointer is a
//! direct kernel-space VA of a stub function that bridges NT callers to the
//! AstryxOS kernel.

extern crate alloc;

// ═══════════════════════════════════════════════════════════════════════════════
// NT Service Numbers — AstryxOS custom SSDT
// ═══════════════════════════════════════════════════════════════════════════════

pub const NT_CLOSE:                     u64 = 0x00;
pub const NT_CREATE_FILE:               u64 = 0x01;
pub const NT_OPEN_FILE:                 u64 = 0x02;
pub const NT_READ_FILE:                 u64 = 0x03;
pub const NT_WRITE_FILE:                u64 = 0x04;
pub const NT_QUERY_INFO_FILE:           u64 = 0x05;
pub const NT_SET_INFO_FILE:             u64 = 0x06;
pub const NT_TERMINATE_PROCESS:         u64 = 0x07;
pub const NT_TERMINATE_THREAD:          u64 = 0x08;
pub const NT_ALLOC_VIRTUAL_MEMORY:      u64 = 0x09;
pub const NT_FREE_VIRTUAL_MEMORY:       u64 = 0x0A;
pub const NT_PROTECT_VIRTUAL_MEMORY:    u64 = 0x0B;
pub const NT_QUERY_VIRTUAL_MEMORY:      u64 = 0x0C;
pub const NT_CREATE_SECTION:            u64 = 0x0D;
pub const NT_MAP_VIEW_OF_SECTION:       u64 = 0x0E;
pub const NT_UNMAP_VIEW_OF_SECTION:     u64 = 0x0F;
pub const NT_CREATE_THREAD:             u64 = 0x10;
pub const NT_CREATE_PROCESS:            u64 = 0x11;
pub const NT_QUERY_SYSTEM_INFORMATION:  u64 = 0x12;
pub const NT_QUERY_INFO_PROCESS:        u64 = 0x13;
pub const NT_WAIT_FOR_SINGLE_OBJECT:    u64 = 0x14;
pub const NT_WAIT_FOR_MULTIPLE_OBJECTS: u64 = 0x15;
pub const NT_DUPLICATE_OBJECT:          u64 = 0x16;
pub const NT_SET_INFO_PROCESS:          u64 = 0x17;
pub const NT_CREATE_EVENT:              u64 = 0x18;
pub const NT_OPEN_EVENT:                u64 = 0x19;
pub const NT_SET_EVENT:                 u64 = 0x1A;
pub const NT_RESET_EVENT:               u64 = 0x1B;
pub const NT_CREATE_MUTANT:             u64 = 0x1C;
pub const NT_RELEASE_MUTANT:            u64 = 0x1D;
pub const NT_QUERY_SYSTEM_TIME:         u64 = 0x1E;
pub const NT_FLUSH_BUFFERS_FILE:        u64 = 0x1F;
pub const NT_SET_SYSTEM_TIME:           u64 = 0x20;
pub const NT_DEVICE_IO_CONTROL_FILE:    u64 = 0x21;
pub const NT_FS_CONTROL_FILE:           u64 = 0x22;
pub const NT_QUERY_DIRECTORY_FILE:      u64 = 0x23;
pub const NT_CREATE_KEY:                u64 = 0x24;
pub const NT_OPEN_KEY:                  u64 = 0x25;
pub const NT_QUERY_VALUE_KEY:           u64 = 0x26;
pub const NT_SET_VALUE_KEY:             u64 = 0x27;
pub const NT_DELETE_VALUE_KEY:          u64 = 0x28;
pub const NT_ENUMERATE_KEY:             u64 = 0x29;
pub const NT_DELETE_KEY:                u64 = 0x2A;

// ═══════════════════════════════════════════════════════════════════════════════
// NTSTATUS codes
// ═══════════════════════════════════════════════════════════════════════════════

pub const STATUS_SUCCESS:               i64 = 0x0000_0000;
pub const STATUS_NOT_IMPLEMENTED:       i64 = 0xC000_0002_u32 as i32 as i64;
pub const STATUS_INVALID_HANDLE:        i64 = 0xC000_0008_u32 as i32 as i64;
pub const STATUS_INVALID_PARAMETER:     i64 = 0xC000_000D_u32 as i32 as i64;
pub const STATUS_ACCESS_DENIED:         i64 = 0xC000_0022_u32 as i32 as i64;
pub const STATUS_OBJECT_NAME_NOT_FOUND: i64 = 0xC000_0034_u32 as i32 as i64;
pub const STATUS_OBJECT_PATH_NOT_FOUND: i64 = 0xC000_003A_u32 as i32 as i64;
pub const STATUS_NO_MEMORY:             i64 = 0xC000_0017_u32 as i32 as i64;
pub const STATUS_END_OF_FILE:           i64 = 0xC000_0011_u32 as i32 as i64;
pub const STATUS_PENDING:               i64 = 0x0000_0103;
pub const STATUS_WAIT_0:                i64 = 0x0000_0000;
pub const STATUS_TIMEOUT:               i64 = 0x0000_0102;

// ═══════════════════════════════════════════════════════════════════════════════
// kernel32.dll AstryxOS service numbers (0x100-0x11F range)
// These are dispatched via INT 0x2E just like NT services.
// ═══════════════════════════════════════════════════════════════════════════════

pub const K32_EXIT_PROCESS:          u64 = 0x100;
pub const K32_READ_FILE:             u64 = 0x101;
pub const K32_WRITE_FILE:            u64 = 0x102;
pub const K32_GET_STD_HANDLE:        u64 = 0x103;
pub const K32_WRITE_CONSOLE_A:       u64 = 0x104;
pub const K32_WRITE_CONSOLE_W:       u64 = 0x105;
pub const K32_GET_CMDLINE_A:         u64 = 0x106;
pub const K32_GET_CMDLINE_W:         u64 = 0x107;
pub const K32_GET_PROCESS_HEAP:      u64 = 0x108;
pub const K32_HEAP_ALLOC:            u64 = 0x109;
pub const K32_HEAP_FREE:             u64 = 0x10A;
pub const K32_HEAP_REALLOC:          u64 = 0x10B;
pub const K32_HEAP_SIZE:             u64 = 0x10C;
pub const K32_VIRTUAL_ALLOC:         u64 = 0x10D;
pub const K32_VIRTUAL_FREE:          u64 = 0x10E;
pub const K32_VIRTUAL_QUERY:         u64 = 0x10F;
pub const K32_GET_LAST_ERROR:        u64 = 0x110;
pub const K32_SET_LAST_ERROR:        u64 = 0x111;
pub const K32_OUTPUT_DEBUG_A:        u64 = 0x112;
pub const K32_OUTPUT_DEBUG_W:        u64 = 0x113;
pub const K32_IS_DEBUGGER_PRESENT:   u64 = 0x114;
pub const K32_GET_PID:               u64 = 0x115;
pub const K32_GET_TID:               u64 = 0x116;
pub const K32_GET_PROCESS_HANDLE:    u64 = 0x117;
pub const K32_GET_THREAD_HANDLE:     u64 = 0x118;
pub const K32_GET_SYSTEM_INFO:       u64 = 0x119;
pub const K32_QPC:                   u64 = 0x11A;
pub const K32_QPF:                   u64 = 0x11B;
pub const K32_SLEEP:                 u64 = 0x11C;
pub const K32_SET_CONSOLE_CTRL:      u64 = 0x11D;
pub const K32_GET_CONSOLE_MODE:      u64 = 0x11E;
pub const K32_SET_CONSOLE_MODE:      u64 = 0x11F;

// ═══════════════════════════════════════════════════════════════════════════════
// NT Stub Table — keyed by (DLL name, export name)
// ═══════════════════════════════════════════════════════════════════════════════

/// User-space address for the per-process NT syscall trampoline page.
/// Each slot (16 bytes): `mov rax, service_num (10 bytes); int 0x2e (2); ret (1); nop*3`.
/// Mapped in every Win32 process so IAT entries can call NT services from Ring 3.
pub const NT_STUB_PAGE_VA: u64 = 0x7FFF_0000;
pub const NT_STUB_SLOT_BYTES: usize = 16;

/// Stub function signature: same as `extern "C" fn(a1..a5) -> i64`.
type NtStubFn = extern "C" fn(u64, u64, u64, u64, u64) -> i64;

/// Static NT stub entry: (dll_name, export_name, service_num, stub_fn).
struct NtStub {
    dll:         &'static str,
    name:        &'static str,
    service_num: u64,
    func:        NtStubFn,
}

/// Macro to declare a stub entry.
macro_rules! stub_entry {
    ($dll:literal, $name:literal, $svc:expr, $fn:expr) => {
        NtStub { dll: $dll, name: $name, service_num: $svc, func: $fn }
    };
}

/// The static NT stub table.  All stubs must be `extern "C"` functions
/// with an `NT_fn_...` prefix to avoid name conflicts.
/// `service_num` is used by `build_stub_trampoline_page` to generate
/// the per-process user-space `mov rax, N; int 0x2e; ret` stubs.
static NT_STUB_TABLE: &[NtStub] = &[
    // ── ntdll.dll NT services ────────────────────────────────────────────────
    stub_entry!("ntdll.dll", "NtClose",                  NT_CLOSE,                    nt_fn_close),
    stub_entry!("ntdll.dll", "ZwClose",                  NT_CLOSE,                    nt_fn_close),
    stub_entry!("ntdll.dll", "NtReadFile",               NT_READ_FILE,                nt_fn_read_file),
    stub_entry!("ntdll.dll", "ZwReadFile",               NT_READ_FILE,                nt_fn_read_file),
    stub_entry!("ntdll.dll", "NtWriteFile",              NT_WRITE_FILE,               nt_fn_write_file),
    stub_entry!("ntdll.dll", "ZwWriteFile",              NT_WRITE_FILE,               nt_fn_write_file),
    stub_entry!("ntdll.dll", "NtTerminateProcess",       NT_TERMINATE_PROCESS,        nt_fn_terminate_process),
    stub_entry!("ntdll.dll", "ZwTerminateProcess",       NT_TERMINATE_PROCESS,        nt_fn_terminate_process),
    stub_entry!("ntdll.dll", "NtTerminateThread",        NT_TERMINATE_THREAD,         nt_fn_terminate_thread),
    stub_entry!("ntdll.dll", "ZwTerminateThread",        NT_TERMINATE_THREAD,         nt_fn_terminate_thread),
    stub_entry!("ntdll.dll", "NtAllocateVirtualMemory",  NT_ALLOC_VIRTUAL_MEMORY,     nt_fn_alloc_virtual_memory),
    stub_entry!("ntdll.dll", "ZwAllocateVirtualMemory",  NT_ALLOC_VIRTUAL_MEMORY,     nt_fn_alloc_virtual_memory),
    stub_entry!("ntdll.dll", "NtFreeVirtualMemory",      NT_FREE_VIRTUAL_MEMORY,      nt_fn_free_virtual_memory),
    stub_entry!("ntdll.dll", "ZwFreeVirtualMemory",      NT_FREE_VIRTUAL_MEMORY,      nt_fn_free_virtual_memory),
    stub_entry!("ntdll.dll", "NtProtectVirtualMemory",   NT_PROTECT_VIRTUAL_MEMORY,   nt_fn_protect_virtual_memory),
    stub_entry!("ntdll.dll", "ZwProtectVirtualMemory",   NT_PROTECT_VIRTUAL_MEMORY,   nt_fn_protect_virtual_memory),
    stub_entry!("ntdll.dll", "NtQueryVirtualMemory",     NT_QUERY_VIRTUAL_MEMORY,     nt_fn_query_virtual_memory),
    stub_entry!("ntdll.dll", "NtCreateFile",             NT_CREATE_FILE,              nt_fn_create_file),
    stub_entry!("ntdll.dll", "ZwCreateFile",             NT_CREATE_FILE,              nt_fn_create_file),
    stub_entry!("ntdll.dll", "NtOpenFile",               NT_OPEN_FILE,                nt_fn_open_file),
    stub_entry!("ntdll.dll", "ZwOpenFile",               NT_OPEN_FILE,                nt_fn_open_file),
    stub_entry!("ntdll.dll", "NtQueryInformationFile",   NT_QUERY_INFO_FILE,          nt_fn_query_info_file),
    stub_entry!("ntdll.dll", "NtSetInformationFile",     NT_SET_INFO_FILE,            nt_fn_set_info_file),
    stub_entry!("ntdll.dll", "NtQuerySystemInformation", NT_QUERY_SYSTEM_INFORMATION, nt_fn_query_system_info),
    stub_entry!("ntdll.dll", "ZwQuerySystemInformation", NT_QUERY_SYSTEM_INFORMATION, nt_fn_query_system_info),
    stub_entry!("ntdll.dll", "NtQueryInformationProcess",NT_QUERY_INFO_PROCESS,       nt_fn_query_info_process),
    stub_entry!("ntdll.dll", "ZwQueryInformationProcess",NT_QUERY_INFO_PROCESS,       nt_fn_query_info_process),
    stub_entry!("ntdll.dll", "NtWaitForSingleObject",    NT_WAIT_FOR_SINGLE_OBJECT,   nt_fn_wait_for_single_object),
    stub_entry!("ntdll.dll", "ZwWaitForSingleObject",    NT_WAIT_FOR_SINGLE_OBJECT,   nt_fn_wait_for_single_object),
    stub_entry!("ntdll.dll", "NtWaitForMultipleObjects", NT_WAIT_FOR_MULTIPLE_OBJECTS,nt_fn_wait_for_multiple_objects),
    stub_entry!("ntdll.dll", "NtDuplicateObject",        NT_DUPLICATE_OBJECT,         nt_fn_duplicate_object),
    stub_entry!("ntdll.dll", "NtCreateEvent",            NT_CREATE_EVENT,             nt_fn_create_event),
    stub_entry!("ntdll.dll", "ZwCreateEvent",            NT_CREATE_EVENT,             nt_fn_create_event),
    stub_entry!("ntdll.dll", "NtSetEvent",               NT_SET_EVENT,                nt_fn_set_event),
    stub_entry!("ntdll.dll", "NtResetEvent",             NT_RESET_EVENT,              nt_fn_reset_event),
    stub_entry!("ntdll.dll", "NtCreateMutant",           NT_CREATE_MUTANT,            nt_fn_create_mutant),
    stub_entry!("ntdll.dll", "ZwCreateMutant",           NT_CREATE_MUTANT,            nt_fn_create_mutant),
    stub_entry!("ntdll.dll", "NtReleaseMutant",          NT_RELEASE_MUTANT,           nt_fn_release_mutant),
    stub_entry!("ntdll.dll", "NtQuerySystemTime",        NT_QUERY_SYSTEM_TIME,        nt_fn_query_system_time),
    stub_entry!("ntdll.dll", "ZwQuerySystemTime",        NT_QUERY_SYSTEM_TIME,        nt_fn_query_system_time),
    stub_entry!("ntdll.dll", "NtFlushBuffersFile",       NT_FLUSH_BUFFERS_FILE,       nt_fn_flush_buffers_file),
    stub_entry!("ntdll.dll", "NtDeviceIoControlFile",    NT_DEVICE_IO_CONTROL_FILE,   nt_fn_device_io_control_file),
    stub_entry!("ntdll.dll", "NtFsControlFile",          NT_FS_CONTROL_FILE,          nt_fn_fs_control_file),
    stub_entry!("ntdll.dll", "NtQueryDirectoryFile",     NT_QUERY_DIRECTORY_FILE,     nt_fn_query_directory_file),
    stub_entry!("ntdll.dll", "NtCreateKey",              NT_CREATE_KEY,               nt_fn_create_key),
    stub_entry!("ntdll.dll", "ZwCreateKey",              NT_CREATE_KEY,               nt_fn_create_key),
    stub_entry!("ntdll.dll", "NtOpenKey",                NT_OPEN_KEY,                 nt_fn_open_key),
    stub_entry!("ntdll.dll", "ZwOpenKey",                NT_OPEN_KEY,                 nt_fn_open_key),
    stub_entry!("ntdll.dll", "NtQueryValueKey",          NT_QUERY_VALUE_KEY,          nt_fn_query_value_key),
    stub_entry!("ntdll.dll", "NtSetValueKey",            NT_SET_VALUE_KEY,            nt_fn_set_value_key),
    stub_entry!("ntdll.dll", "NtDeleteValueKey",         NT_DELETE_VALUE_KEY,         nt_fn_delete_value_key),
    stub_entry!("ntdll.dll", "NtEnumerateKey",           NT_ENUMERATE_KEY,            nt_fn_enumerate_key),
    stub_entry!("ntdll.dll", "NtDeleteKey",              NT_DELETE_KEY,               nt_fn_delete_key),
    stub_entry!("ntdll.dll", "NtCreateSection",          NT_CREATE_SECTION,           nt_fn_create_section),
    stub_entry!("ntdll.dll", "ZwCreateSection",          NT_CREATE_SECTION,           nt_fn_create_section),
    stub_entry!("ntdll.dll", "NtMapViewOfSection",       NT_MAP_VIEW_OF_SECTION,      nt_fn_map_view_of_section),
    stub_entry!("ntdll.dll", "ZwMapViewOfSection",       NT_MAP_VIEW_OF_SECTION,      nt_fn_map_view_of_section),
    stub_entry!("ntdll.dll", "NtUnmapViewOfSection",     NT_UNMAP_VIEW_OF_SECTION,    nt_fn_unmap_view_of_section),
    stub_entry!("ntdll.dll", "ZwUnmapViewOfSection",     NT_UNMAP_VIEW_OF_SECTION,    nt_fn_unmap_view_of_section),
    stub_entry!("ntdll.dll", "NtCreateThread",           NT_CREATE_THREAD,            nt_fn_create_thread),
    stub_entry!("ntdll.dll", "NtCreateProcess",          NT_CREATE_PROCESS,           nt_fn_create_process),
    stub_entry!("ntdll.dll", "NtSetInformationProcess",  NT_SET_INFO_PROCESS,         nt_fn_set_info_process),
    // ── kernel32.dll stubs — use K32_* service numbers ───────────────────────
    stub_entry!("kernel32.dll", "ExitProcess",               K32_EXIT_PROCESS,        nt_fn_terminate_process),
    stub_entry!("kernel32.dll", "ReadFile",                  K32_READ_FILE,           nt_fn_k32_read_file),
    stub_entry!("kernel32.dll", "WriteFile",                 K32_WRITE_FILE,          nt_fn_k32_write_file),
    stub_entry!("kernel32.dll", "CloseHandle",               NT_CLOSE,                nt_fn_close),
    stub_entry!("kernel32.dll", "GetStdHandle",              K32_GET_STD_HANDLE,      nt_fn_get_std_handle),
    stub_entry!("kernel32.dll", "WriteConsoleA",             K32_WRITE_CONSOLE_A,     nt_fn_write_console_a),
    stub_entry!("kernel32.dll", "WriteConsoleW",             K32_WRITE_CONSOLE_W,     nt_fn_write_console_w),
    stub_entry!("kernel32.dll", "GetCommandLineA",           K32_GET_CMDLINE_A,       nt_fn_get_cmdline_a),
    stub_entry!("kernel32.dll", "GetCommandLineW",           K32_GET_CMDLINE_W,       nt_fn_get_cmdline_w),
    stub_entry!("kernel32.dll", "GetProcessHeap",            K32_GET_PROCESS_HEAP,    nt_fn_get_process_heap),
    stub_entry!("kernel32.dll", "HeapAlloc",                 K32_HEAP_ALLOC,          nt_fn_heap_alloc),
    stub_entry!("kernel32.dll", "HeapFree",                  K32_HEAP_FREE,           nt_fn_heap_free),
    stub_entry!("kernel32.dll", "HeapReAlloc",               K32_HEAP_REALLOC,        nt_fn_heap_realloc),
    stub_entry!("kernel32.dll", "HeapSize",                  K32_HEAP_SIZE,           nt_fn_heap_size),
    stub_entry!("kernel32.dll", "VirtualAlloc",              K32_VIRTUAL_ALLOC,       nt_fn_virtual_alloc),
    stub_entry!("kernel32.dll", "VirtualFree",               K32_VIRTUAL_FREE,        nt_fn_virtual_free),
    stub_entry!("kernel32.dll", "VirtualQuery",              K32_VIRTUAL_QUERY,       nt_fn_virtual_query),
    stub_entry!("kernel32.dll", "GetLastError",              K32_GET_LAST_ERROR,      nt_fn_get_last_error),
    stub_entry!("kernel32.dll", "SetLastError",              K32_SET_LAST_ERROR,      nt_fn_set_last_error),
    stub_entry!("kernel32.dll", "OutputDebugStringA",        K32_OUTPUT_DEBUG_A,      nt_fn_output_debug_string_a),
    stub_entry!("kernel32.dll", "OutputDebugStringW",        K32_OUTPUT_DEBUG_W,      nt_fn_output_debug_string_w),
    stub_entry!("kernel32.dll", "IsDebuggerPresent",         K32_IS_DEBUGGER_PRESENT, nt_fn_is_debugger_present),
    stub_entry!("kernel32.dll", "GetCurrentProcessId",       K32_GET_PID,             nt_fn_get_current_process_id),
    stub_entry!("kernel32.dll", "GetCurrentThreadId",        K32_GET_TID,             nt_fn_get_current_thread_id),
    stub_entry!("kernel32.dll", "GetCurrentProcess",         K32_GET_PROCESS_HANDLE,  nt_fn_get_current_process),
    stub_entry!("kernel32.dll", "GetCurrentThread",          K32_GET_THREAD_HANDLE,   nt_fn_get_current_thread),
    stub_entry!("kernel32.dll", "GetSystemInfo",             K32_GET_SYSTEM_INFO,     nt_fn_get_system_info),
    stub_entry!("kernel32.dll", "QueryPerformanceCounter",   K32_QPC,                 nt_fn_query_perf_counter),
    stub_entry!("kernel32.dll", "QueryPerformanceFrequency", K32_QPF,                 nt_fn_query_perf_freq),
    stub_entry!("kernel32.dll", "Sleep",                     K32_SLEEP,               nt_fn_sleep),
    stub_entry!("kernel32.dll", "FlushFileBuffers",          NT_FLUSH_BUFFERS_FILE,   nt_fn_flush_buffers_file),
    stub_entry!("kernel32.dll", "SetConsoleCtrlHandler",     K32_SET_CONSOLE_CTRL,    nt_fn_set_console_ctrl_handler),
    stub_entry!("kernel32.dll", "GetConsoleMode",            K32_GET_CONSOLE_MODE,    nt_fn_get_console_mode),
    stub_entry!("kernel32.dll", "SetConsoleMode",            K32_SET_CONSOLE_MODE,    nt_fn_set_console_mode),
];

// ─── Ordinal table (for imports resolved by ordinal) ────────────────────────

struct NtOrdinalStub {
    dll:     &'static str,
    ordinal: u16,
    func:    NtStubFn,
}

/// Sparse ordinal table — only entries required by Phase 2 test images.
static NT_ORDINAL_TABLE: &[NtOrdinalStub] = &[
    // ntdll exports #0 for NtTerminateProcess on some Windows versions
    NtOrdinalStub { dll: "ntdll.dll", ordinal: 0, func: nt_fn_terminate_process },
];

// ═══════════════════════════════════════════════════════════════════════════════
// Public interface
// ═══════════════════════════════════════════════════════════════════════════════

/// Look up a kernel stub VA for a named export.
///
/// Called by the PE loader during IAT resolution.  Returns the kernel VA of
/// the appropriate NT stub function, or 0 if the symbol is not found.
pub fn lookup_stub(dll: &str, name: &str) -> u64 {
    // Case-insensitive DLL name match, case-sensitive function name match
    // (NT export names are case-sensitive in practice).
    for entry in NT_STUB_TABLE {
        if dll.eq_ignore_ascii_case(entry.dll) && entry.name == name {
            return entry.func as u64;
        }
    }
    crate::serial_println!("[NT] lookup_stub: unresolved {}!{}", dll, name);
    0
}

/// Return the slot index for (dll, name) in NT_STUB_TABLE, or None.
///
/// Used by `resolve_imports` when building user-space IAT entries that point
/// into the per-process trampoline page instead of kernel VAs.
pub fn lookup_stub_slot_index(dll: &str, name: &str) -> Option<usize> {
    NT_STUB_TABLE.iter().position(|e| {
        dll.eq_ignore_ascii_case(e.dll) && e.name == name
    })
}

/// Write per-process NT syscall trampoline stubs into `page_ptr`.
///
/// The page must be at least `NT_STUB_TABLE.len() * NT_STUB_SLOT_BYTES` bytes
/// and must already be mapped into the process address space at `NT_STUB_PAGE_VA`.
///
/// Each 16-byte slot:
///   48 B8 <svc u64 LE>   — MOV RAX, service_num  (10 bytes)
///   CD 2E                 — INT 0x2E              ( 2 bytes)
///   C3                    — RET                   ( 1 byte )
///   90 90 90              — NOP padding           ( 3 bytes)
///
/// # Safety
/// `page_ptr` must be valid for `NT_STUB_TABLE.len() * 16` bytes of write.
pub unsafe fn build_stub_trampoline_page(page_ptr: *mut u8) {
    for (i, entry) in NT_STUB_TABLE.iter().enumerate() {
        let slot = page_ptr.add(i * NT_STUB_SLOT_BYTES);
        let svc  = entry.service_num;
        // MOV RAX, imm64 — opcode 48 B8 followed by 8-byte little-endian immediate
        slot.write(0x48);
        slot.add(1).write(0xB8);
        slot.add(2).write((svc      ) as u8);
        slot.add(3).write((svc >>  8) as u8);
        slot.add(4).write((svc >> 16) as u8);
        slot.add(5).write((svc >> 24) as u8);
        slot.add(6).write((svc >> 32) as u8);
        slot.add(7).write((svc >> 40) as u8);
        slot.add(8).write((svc >> 48) as u8);
        slot.add(9).write((svc >> 56) as u8);
        // INT 0x2E
        slot.add(10).write(0xCD);
        slot.add(11).write(0x2E);
        // RET
        slot.add(12).write(0xC3);
        // NOP padding
        slot.add(13).write(0x90);
        slot.add(14).write(0x90);
        slot.add(15).write(0x90);
    }
}

/// Look up a kernel stub VA by ordinal.
pub fn lookup_stub_ordinal(dll: &str, ordinal: u16) -> Option<u64> {
    for entry in NT_ORDINAL_TABLE {
        if dll.eq_ignore_ascii_case(entry.dll) && entry.ordinal == ordinal {
            return Some(entry.func as u64);
        }
    }
    crate::serial_println!("[NT] lookup_stub_ordinal: unresolved {}#{}", dll, ordinal);
    None
}

/// NT system service dispatch — INT 0x2E C-thunk entry point.
///
/// Called from `isr_syscall_int2e` with the NT ABI register mapping already
/// translated to the standard 6-arg Rust calling convention.
/// (`num`=RAX, `a1`=RCX, `a2`=RDX, `a3`=R8, `a4`=R9).
#[no_mangle]
pub extern "C" fn dispatch_nt_int2e(
    num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
) -> i64 {
    dispatch_nt(num, a1, a2, a3, a4, a5)
}

/// Core NT SSDT dispatch.  Routes service number to the appropriate stub.
pub fn dispatch_nt(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    crate::perf::record_syscall(num | 0x8000_0000_0000_0000); // tag NT syscalls
    match num {
        NT_CLOSE                     => nt_fn_close(a1, a2, a3, a4, a5),
        NT_CREATE_FILE               => nt_fn_create_file(a1, a2, a3, a4, a5),
        NT_OPEN_FILE                 => nt_fn_open_file(a1, a2, a3, a4, a5),
        NT_READ_FILE                 => nt_fn_read_file(a1, a2, a3, a4, a5),
        NT_WRITE_FILE                => nt_fn_write_file(a1, a2, a3, a4, a5),
        NT_QUERY_INFO_FILE           => nt_fn_query_info_file(a1, a2, a3, a4, a5),
        NT_SET_INFO_FILE             => nt_fn_set_info_file(a1, a2, a3, a4, a5),
        NT_TERMINATE_PROCESS         => nt_fn_terminate_process(a1, a2, a3, a4, a5),
        NT_TERMINATE_THREAD          => nt_fn_terminate_thread(a1, a2, a3, a4, a5),
        NT_ALLOC_VIRTUAL_MEMORY      => nt_fn_alloc_virtual_memory(a1, a2, a3, a4, a5),
        NT_FREE_VIRTUAL_MEMORY       => nt_fn_free_virtual_memory(a1, a2, a3, a4, a5),
        NT_PROTECT_VIRTUAL_MEMORY    => nt_fn_protect_virtual_memory(a1, a2, a3, a4, a5),
        NT_QUERY_VIRTUAL_MEMORY      => nt_fn_query_virtual_memory(a1, a2, a3, a4, a5),
        NT_CREATE_SECTION            => nt_fn_create_section(a1, a2, a3, a4, a5),
        NT_MAP_VIEW_OF_SECTION       => nt_fn_map_view_of_section(a1, a2, a3, a4, a5),
        NT_UNMAP_VIEW_OF_SECTION     => nt_fn_unmap_view_of_section(a1, a2, a3, a4, a5),
        NT_CREATE_THREAD             => nt_fn_create_thread(a1, a2, a3, a4, a5),
        NT_CREATE_PROCESS            => nt_fn_create_process(a1, a2, a3, a4, a5),
        NT_QUERY_SYSTEM_INFORMATION  => nt_fn_query_system_info(a1, a2, a3, a4, a5),
        NT_QUERY_INFO_PROCESS        => nt_fn_query_info_process(a1, a2, a3, a4, a5),
        NT_WAIT_FOR_SINGLE_OBJECT    => nt_fn_wait_for_single_object(a1, a2, a3, a4, a5),
        NT_WAIT_FOR_MULTIPLE_OBJECTS => nt_fn_wait_for_multiple_objects(a1, a2, a3, a4, a5),
        NT_DUPLICATE_OBJECT          => nt_fn_duplicate_object(a1, a2, a3, a4, a5),
        NT_SET_INFO_PROCESS          => nt_fn_set_info_process(a1, a2, a3, a4, a5),
        NT_CREATE_EVENT              => nt_fn_create_event(a1, a2, a3, a4, a5),
        NT_OPEN_EVENT                => nt_fn_open_event(a1, a2, a3, a4, a5),
        NT_SET_EVENT                 => nt_fn_set_event(a1, a2, a3, a4, a5),
        NT_RESET_EVENT               => nt_fn_reset_event(a1, a2, a3, a4, a5),
        NT_CREATE_MUTANT             => nt_fn_create_mutant(a1, a2, a3, a4, a5),
        NT_RELEASE_MUTANT            => nt_fn_release_mutant(a1, a2, a3, a4, a5),
        NT_QUERY_SYSTEM_TIME         => nt_fn_query_system_time(a1, a2, a3, a4, a5),
        NT_FLUSH_BUFFERS_FILE        => nt_fn_flush_buffers_file(a1, a2, a3, a4, a5),
        NT_DEVICE_IO_CONTROL_FILE    => nt_fn_device_io_control_file(a1, a2, a3, a4, a5),
        NT_FS_CONTROL_FILE           => nt_fn_fs_control_file(a1, a2, a3, a4, a5),
        NT_QUERY_DIRECTORY_FILE      => nt_fn_query_directory_file(a1, a2, a3, a4, a5),
        NT_CREATE_KEY                => nt_fn_create_key(a1, a2, a3, a4, a5),
        NT_OPEN_KEY                  => nt_fn_open_key(a1, a2, a3, a4, a5),
        NT_QUERY_VALUE_KEY           => nt_fn_query_value_key(a1, a2, a3, a4, a5),
        NT_SET_VALUE_KEY             => nt_fn_set_value_key(a1, a2, a3, a4, a5),
        NT_DELETE_VALUE_KEY          => nt_fn_delete_value_key(a1, a2, a3, a4, a5),
        NT_ENUMERATE_KEY             => nt_fn_enumerate_key(a1, a2, a3, a4, a5),
        NT_DELETE_KEY                => nt_fn_delete_key(a1, a2, a3, a4, a5),
        NT_SET_SYSTEM_TIME           => STATUS_NOT_IMPLEMENTED,
        // ── kernel32.dll services (0x100–0x11F) ─────────────────────────────
        K32_EXIT_PROCESS        => { crate::proc::exit_thread(a1 as i64); 0 }
        K32_READ_FILE           => nt_fn_k32_read_file(a1, a2, a3, a4, a5),
        K32_WRITE_FILE          => nt_fn_k32_write_file(a1, a2, a3, a4, a5),
        K32_GET_STD_HANDLE      => nt_fn_get_std_handle(a1, a2, a3, a4, a5),
        K32_WRITE_CONSOLE_A     => nt_fn_write_console_a(a1, a2, a3, a4, a5),
        K32_WRITE_CONSOLE_W     => nt_fn_write_console_w(a1, a2, a3, a4, a5),
        K32_GET_CMDLINE_A       => nt_fn_get_cmdline_a(a1, a2, a3, a4, a5),
        K32_GET_CMDLINE_W       => nt_fn_get_cmdline_w(a1, a2, a3, a4, a5),
        K32_GET_PROCESS_HEAP    => nt_fn_get_process_heap(a1, a2, a3, a4, a5),
        K32_HEAP_ALLOC          => nt_fn_heap_alloc(a1, a2, a3, a4, a5),
        K32_HEAP_FREE           => nt_fn_heap_free(a1, a2, a3, a4, a5),
        K32_HEAP_REALLOC        => nt_fn_heap_realloc(a1, a2, a3, a4, a5),
        K32_HEAP_SIZE           => nt_fn_heap_size(a1, a2, a3, a4, a5),
        K32_VIRTUAL_ALLOC       => nt_fn_virtual_alloc(a1, a2, a3, a4, a5),
        K32_VIRTUAL_FREE        => nt_fn_virtual_free(a1, a2, a3, a4, a5),
        K32_VIRTUAL_QUERY       => nt_fn_virtual_query(a1, a2, a3, a4, a5),
        K32_GET_LAST_ERROR      => nt_fn_get_last_error(a1, a2, a3, a4, a5),
        K32_SET_LAST_ERROR      => nt_fn_set_last_error(a1, a2, a3, a4, a5),
        K32_OUTPUT_DEBUG_A      => nt_fn_output_debug_string_a(a1, a2, a3, a4, a5),
        K32_OUTPUT_DEBUG_W      => nt_fn_output_debug_string_w(a1, a2, a3, a4, a5),
        K32_IS_DEBUGGER_PRESENT => nt_fn_is_debugger_present(a1, a2, a3, a4, a5),
        K32_GET_PID             => nt_fn_get_current_process_id(a1, a2, a3, a4, a5),
        K32_GET_TID             => nt_fn_get_current_thread_id(a1, a2, a3, a4, a5),
        K32_GET_PROCESS_HANDLE  => nt_fn_get_current_process(a1, a2, a3, a4, a5),
        K32_GET_THREAD_HANDLE   => nt_fn_get_current_thread(a1, a2, a3, a4, a5),
        K32_GET_SYSTEM_INFO     => nt_fn_get_system_info(a1, a2, a3, a4, a5),
        K32_QPC                 => nt_fn_query_perf_counter(a1, a2, a3, a4, a5),
        K32_QPF                 => nt_fn_query_perf_freq(a1, a2, a3, a4, a5),
        K32_SLEEP               => nt_fn_sleep(a1, a2, a3, a4, a5),
        K32_SET_CONSOLE_CTRL    => nt_fn_set_console_ctrl_handler(a1, a2, a3, a4, a5),
        K32_GET_CONSOLE_MODE    => nt_fn_get_console_mode(a1, a2, a3, a4, a5),
        K32_SET_CONSOLE_MODE    => nt_fn_set_console_mode(a1, a2, a3, a4, a5),
        _ => {
            crate::serial_println!("[NT] unknown service 0x{:X}", num);
            STATUS_NOT_IMPLEMENTED
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NT Stub Implementations
//
// Each stub takes (a1..a5: u64) with NT ABI args already mapped.
// Stubs delegate to existing AstryxOS kernel primitives.
// ═══════════════════════════════════════════════════════════════════════════════

/// NtClose(Handle) — close any kernel handle.
extern "C" fn nt_fn_close(handle: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    let r = crate::syscall::dispatch_linux(3, handle, 0, 0, 0, 0, 0); // Linux close(2)
    if r < 0 { map_errno(r) } else { STATUS_SUCCESS }
}

/// NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
///            Buffer, Length, ByteOffset, Key)
extern "C" fn nt_fn_read_file(handle: u64, _a2: u64, _a3: u64, _a4: u64, a5: u64) -> i64 {
    // a5 holds `Buffer` in our simplified 5-arg call (see test path).
    // Full NT ReadFile: handle=a1, iosb=5th stack arg, buf=6th, len=7th.
    // For Phase 2, map to: read(handle, a5, 0x1000)
    let r = crate::syscall::dispatch_linux(0, handle, a5, 0x1000, 0, 0, 0);
    if r < 0 { map_errno(r) } else { STATUS_SUCCESS }
}

/// NtWriteFile(FileHandle, Event, ..., Buffer, Length, ByteOffset, Key)
extern "C" fn nt_fn_write_file(handle: u64, _a2: u64, _a3: u64, buf: u64, len: u64) -> i64 {
    let r = crate::syscall::dispatch_linux(1, handle, buf, len, 0, 0, 0);
    if r < 0 { map_errno(r) } else { STATUS_SUCCESS }
}

/// NtTerminateProcess(ProcessHandle, ExitStatus)
extern "C" fn nt_fn_terminate_process(_handle: u64, exit_status: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    crate::proc::exit_thread(exit_status as i64);
    STATUS_SUCCESS // unreachable
}

/// NtTerminateThread(ThreadHandle, ExitStatus)
extern "C" fn nt_fn_terminate_thread(_handle: u64, exit_status: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    crate::proc::exit_thread(exit_status as i64);
    STATUS_SUCCESS // unreachable
}

/// NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, ZeroBits,
///                          RegionSize*, AllocationType, Protect)
/// For now: map to mmap_anon(addr_hint, *size, prot)
extern "C" fn nt_fn_alloc_virtual_memory(_handle: u64, base_addr_ptr: u64, _zero_bits: u64, size_ptr: u64, _alloc_type: u64) -> i64 {
    let size = if size_ptr != 0 {
        unsafe { core::ptr::read_volatile(size_ptr as *const u64) }
    } else {
        0x1000
    };
    let addr_hint = if base_addr_ptr != 0 {
        unsafe { core::ptr::read_volatile(base_addr_ptr as *const u64) }
    } else {
        0
    };
    // Linux mmap(addr, size, PROT_READ|WRITE, MAP_PRIVATE|ANON, -1, 0)
    let r = crate::syscall::dispatch_linux(9, addr_hint, size, 3, 0x22, u64::MAX, 0);
    if r < 0 { map_errno(r) } else {
        // Write allocated address back through BaseAddress pointer
        if base_addr_ptr != 0 {
            unsafe { core::ptr::write_volatile(base_addr_ptr as *mut u64, r as u64); }
        }
        STATUS_SUCCESS
    }
}

/// NtFreeVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*, FreeType)
extern "C" fn nt_fn_free_virtual_memory(_handle: u64, base_addr_ptr: u64, size_ptr: u64, _free_type: u64, _a5: u64) -> i64 {
    let addr = if base_addr_ptr != 0 {
        unsafe { core::ptr::read_volatile(base_addr_ptr as *const u64) }
    } else { return STATUS_INVALID_PARAMETER; };
    let size = if size_ptr != 0 {
        unsafe { core::ptr::read_volatile(size_ptr as *const u64) }
    } else { 0 };
    let r = crate::syscall::dispatch_linux(11, addr, size, 0, 0, 0, 0); // munmap
    if r < 0 { map_errno(r) } else { STATUS_SUCCESS }
}

/// NtProtectVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*, NewProtect, OldProtect*)
extern "C" fn nt_fn_protect_virtual_memory(_handle: u64, base_ptr: u64, size_ptr: u64, prot: u64, _old_prot: u64) -> i64 {
    let addr = if base_ptr != 0 { unsafe { core::ptr::read_volatile(base_ptr as *const u64) } } else { return STATUS_INVALID_PARAMETER; };
    let size = if size_ptr != 0 { unsafe { core::ptr::read_volatile(size_ptr as *const u64) } } else { 0x1000 };
    let linux_prot = nt_prot_to_posix(prot as u32);
    let r = crate::syscall::dispatch_linux(10, addr, size, linux_prot, 0, 0, 0); // mprotect
    if r < 0 { map_errno(r) } else { STATUS_SUCCESS }
}

/// NtQueryVirtualMemory — stub (returns STATUS_NOT_IMPLEMENTED for now).
extern "C" fn nt_fn_query_virtual_memory(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateFile — simplified: open (or create) a path-string file.
extern "C" fn nt_fn_create_file(handle_out: u64, _access: u64, obj_attrs: u64, _io_status: u64, _a5: u64) -> i64 {
    // ObjectAttributes->ObjectName is a UNICODE_STRING at offset 8.
    // For Phase 2 we skip proper UNICODE_STRING parsing and return stub.
    let _ = (handle_out, obj_attrs);
    STATUS_NOT_IMPLEMENTED
}

/// NtOpenFile — stub.
extern "C" fn nt_fn_open_file(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtQueryInformationFile — stub.
extern "C" fn nt_fn_query_info_file(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtSetInformationFile — stub.
extern "C" fn nt_fn_set_info_file(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtFlushBuffersFile — accepts any handle, returns SUCCESS.
extern "C" fn nt_fn_flush_buffers_file(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_SUCCESS
}

/// NtQuerySystemInformation(SystemInformationClass, Buffer, Length, ResultLen*)
extern "C" fn nt_fn_query_system_info(info_class: u64, buf: u64, buf_len: u64, _result_len: u64, _a5: u64) -> i64 {
    match info_class {
        // SystemBasicInformation (0)
        0 => {
            if buf != 0 && buf_len >= 8 {
                // Write number of CPUs at offset 0
                unsafe { core::ptr::write_volatile(buf as *mut u32, 1); }
            }
            STATUS_SUCCESS
        }
        // SystemPerformanceInformation (2) — stub
        2 => STATUS_NOT_IMPLEMENTED,
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

/// NtQueryInformationProcess — stub.
extern "C" fn nt_fn_query_info_process(_handle: u64, _class: u64, _buf: u64, _len: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtSetInformationProcess — stub.
extern "C" fn nt_fn_set_info_process(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtWaitForSingleObject(Handle, Alertable, Timeout*)
extern "C" fn nt_fn_wait_for_single_object(handle: u64, _alertable: u64, timeout_ptr: u64, _a4: u64, _a5: u64) -> i64 {
    let timeout_ms: u64 = if timeout_ptr == 0 {
        u64::MAX // infinite
    } else {
        // NT timeout is in 100ns units, negative = relative
        let nt_ticks = unsafe { core::ptr::read_volatile(timeout_ptr as *const i64) };
        if nt_ticks == i64::MIN { u64::MAX }
        else if nt_ticks < 0 { ((-nt_ticks) / 10_000) as u64 } // relative
        else { 0 } // absolute — simplify to no-wait
    };
    let r = crate::syscall::dispatch_linux(7, handle, 0, timeout_ms, 0, 0, 0); // poll
    if r < 0 { map_errno(r) } else { STATUS_WAIT_0 }
}

/// NtWaitForMultipleObjects — stub.
extern "C" fn nt_fn_wait_for_multiple_objects(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtDuplicateObject — stub.
extern "C" fn nt_fn_duplicate_object(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateEvent — stub.
extern "C" fn nt_fn_create_event(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtOpenEvent — stub.
extern "C" fn nt_fn_open_event(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtSetEvent — stub.
extern "C" fn nt_fn_set_event(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtResetEvent — stub.
extern "C" fn nt_fn_reset_event(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateMutant — stub.
extern "C" fn nt_fn_create_mutant(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtReleaseMutant — stub.
extern "C" fn nt_fn_release_mutant(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtQuerySystemTime(SystemTime: *mut i64)
extern "C" fn nt_fn_query_system_time(time_ptr: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    if time_ptr != 0 {
        // Return current time as NT FILETIME (100ns ticks since 1601-01-01).
        // Stub: return a plausible constant.
        // 132000000000000000 = 2019-01-01 in NT time
        let nt_time: i64 = 132_000_000_000_000_000i64;
        unsafe { core::ptr::write_volatile(time_ptr as *mut i64, nt_time); }
    }
    STATUS_SUCCESS
}

/// NtDeviceIoControlFile — stub.
extern "C" fn nt_fn_device_io_control_file(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtFsControlFile — stub.
extern "C" fn nt_fn_fs_control_file(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtQueryDirectoryFile — stub.
extern "C" fn nt_fn_query_directory_file(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateSection — stub.
extern "C" fn nt_fn_create_section(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtMapViewOfSection — stub.
extern "C" fn nt_fn_map_view_of_section(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtUnmapViewOfSection — stub.
extern "C" fn nt_fn_unmap_view_of_section(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateThread — stub.
extern "C" fn nt_fn_create_thread(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateProcess — stub.
extern "C" fn nt_fn_create_process(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    STATUS_NOT_IMPLEMENTED
}

/// Registry stubs.
extern "C" fn nt_fn_create_key(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 { STATUS_NOT_IMPLEMENTED }
extern "C" fn nt_fn_open_key(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 { STATUS_NOT_IMPLEMENTED }
extern "C" fn nt_fn_query_value_key(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 { STATUS_NOT_IMPLEMENTED }
extern "C" fn nt_fn_set_value_key(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 { STATUS_NOT_IMPLEMENTED }
extern "C" fn nt_fn_delete_value_key(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 { STATUS_NOT_IMPLEMENTED }
extern "C" fn nt_fn_enumerate_key(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 { STATUS_NOT_IMPLEMENTED }
extern "C" fn nt_fn_delete_key(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 { STATUS_NOT_IMPLEMENTED }

// ─── kernel32.dll kernel-mode stubs ─────────────────────────────────────────

/// kernel32!ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped)
extern "C" fn nt_fn_k32_read_file(handle: u64, buf: u64, count: u64, bytes_read: u64, _overlapped: u64) -> i64 {
    let r = crate::syscall::dispatch_linux(0, handle, buf, count, 0, 0, 0);
    if r < 0 {
        // Indicate failure via BOOL return
        0
    } else {
        if bytes_read != 0 {
            unsafe { core::ptr::write_volatile(bytes_read as *mut u32, r as u32); }
        }
        1 // TRUE
    }
}

/// kernel32!WriteFile(hFile, lpBuffer, nBytesToWrite, lpBytesWritten, lpOverlapped)
extern "C" fn nt_fn_k32_write_file(handle: u64, buf: u64, count: u64, bytes_written: u64, _overlapped: u64) -> i64 {
    let r = crate::syscall::dispatch_linux(1, handle, buf, count, 0, 0, 0);
    if r < 0 {
        0  // FALSE
    } else {
        if bytes_written != 0 {
            unsafe { core::ptr::write_volatile(bytes_written as *mut u32, r as u32); }
        }
        1 // TRUE
    }
}

// ─── kernel32.dll console, heap, and environment stubs ─────────────────────

/// kernel32!GetStdHandle(nStdHandle: DWORD) -> HANDLE
/// STD_INPUT_HANDLE  = 0xFFFF_FFF6 (-10)
/// STD_OUTPUT_HANDLE = 0xFFFF_FFF5 (-11)
/// STD_ERROR_HANDLE  = 0xFFFF_FFF4 (-12)
extern "C" fn nt_fn_get_std_handle(n: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    match n as u32 {
        0xFFFF_FFF6 => 0, // STD_INPUT  → fd 0
        0xFFFF_FFF5 => 1, // STD_OUTPUT → fd 1
        0xFFFF_FFF4 => 2, // STD_ERROR  → fd 2
        _ => -1,          // INVALID_HANDLE_VALUE
    }
}

/// kernel32!WriteConsoleA(hConsole, lpBuffer, nChars, lpCharsWritten, lpReserved)
extern "C" fn nt_fn_write_console_a(handle: u64, buf: u64, count: u64, chars_written: u64, _reserved: u64) -> i64 {
    let r = crate::syscall::dispatch_linux(1, handle, buf, count, 0, 0, 0);
    if r < 0 {
        0 // FALSE
    } else {
        if chars_written != 0 {
            unsafe { core::ptr::write_volatile(chars_written as *mut u32, r as u32); }
        }
        1 // TRUE
    }
}

/// kernel32!WriteConsoleW(hConsole, lpBuffer, nChars, lpCharsWritten, lpReserved)
/// lpBuffer is UTF-16LE; nChars is number of WCHARs.
/// We extract the low byte of each code unit for a simple ASCII passthrough.
extern "C" fn nt_fn_write_console_w(handle: u64, buf: u64, count: u64, chars_written: u64, _reserved: u64) -> i64 {
    // Safety: caller guarantees buf is valid for count u16 values.
    let n = (count as usize).min(512);
    let mut ascii_buf = [0u8; 512];
    for i in 0..n {
        let wc: u16 = unsafe { core::ptr::read_unaligned((buf as *const u16).add(i)) };
        ascii_buf[i] = wc as u8;
    }
    let r = crate::syscall::dispatch_linux(1, handle, ascii_buf.as_ptr() as u64, n as u64, 0, 0, 0);
    if r < 0 {
        0
    } else {
        if chars_written != 0 {
            unsafe { core::ptr::write_volatile(chars_written as *mut u32, r as u32); }
        }
        1
    }
}

/// kernel32!GetCommandLineA() -> LPSTR
/// Returns a pointer to a static NUL-terminated ASCII command line.
extern "C" fn nt_fn_get_cmdline_a(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    static CMDLINE_A: &[u8] = b"hello.exe\0";
    CMDLINE_A.as_ptr() as i64
}

/// kernel32!GetCommandLineW() -> LPWSTR
/// Returns a pointer to a static NUL-terminated UTF-16LE command line.
extern "C" fn nt_fn_get_cmdline_w(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    // "hello.exe\0" as UTF-16LE
    static CMDLINE_W: &[u16] = &[
        b'h' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16,
        b'.' as u16, b'e' as u16, b'x' as u16, b'e' as u16, 0u16,
    ];
    CMDLINE_W.as_ptr() as i64
}

/// kernel32!GetProcessHeap() -> HANDLE  — returns a fake heap sentinel.
extern "C" fn nt_fn_get_process_heap(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    0x0000_DEAD_0001_0000_i64 // non-zero sentinel so callers see a "valid" handle
}

/// kernel32!HeapAlloc(hHeap, dwFlags, dwBytes) -> LPVOID
extern "C" fn nt_fn_heap_alloc(_heap: u64, _flags: u64, size: u64, _a4: u64, _a5: u64) -> i64 {
    // MAP_PRIVATE|MAP_ANONYMOUS=0x22, PROT_READ|PROT_WRITE=3, fd=-1
    crate::syscall::dispatch_linux(9, 0, size, 3, 0x22, u64::MAX, 0)
}

/// kernel32!HeapFree(hHeap, dwFlags, lpMem) -> BOOL
extern "C" fn nt_fn_heap_free(_heap: u64, _flags: u64, ptr: u64, _a4: u64, _a5: u64) -> i64 {
    if ptr == 0 { return 1; } // HeapFree(NULL) is a no-op on Windows
    // Unmap one page — rough approximation for kernel-test use
    let r = crate::syscall::dispatch_linux(11, ptr, 0x1000, 0, 0, 0, 0);
    if r < 0 { 0 } else { 1 }
}

/// kernel32!HeapReAlloc — stub (return NULL; callers must handle gracefully).
extern "C" fn nt_fn_heap_realloc(_heap: u64, _flags: u64, _ptr: u64, _a4: u64, _a5: u64) -> i64 {
    0 // NULL
}

/// kernel32!HeapSize — stub.
extern "C" fn nt_fn_heap_size(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    0xFFFF_FFFF_u64 as i64 // SIZE_T_MAX — "large enough"
}

/// kernel32!VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) -> LPVOID
extern "C" fn nt_fn_virtual_alloc(addr: u64, size: u64, _alloc_type: u64, protect: u64, _a5: u64) -> i64 {
    let prot = nt_prot_to_posix(protect as u32);
    crate::syscall::dispatch_linux(9, addr, size, prot, 0x22, u64::MAX, 0)
}

/// kernel32!VirtualFree(lpAddress, dwSize, dwFreeType) -> BOOL
extern "C" fn nt_fn_virtual_free(ptr: u64, size: u64, _free_type: u64, _a4: u64, _a5: u64) -> i64 {
    let r = crate::syscall::dispatch_linux(11, ptr, if size == 0 { 0x1000 } else { size }, 0, 0, 0, 0);
    if r < 0 { 0 } else { 1 }
}

/// kernel32!VirtualQuery — stub (returns 0 bytes written).
extern "C" fn nt_fn_virtual_query(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    0
}

/// kernel32!GetLastError() -> DWORD — always returns 0 (ERROR_SUCCESS)
extern "C" fn nt_fn_get_last_error(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    0
}

/// kernel32!SetLastError(dwErrCode) — silently ignored.
extern "C" fn nt_fn_set_last_error(_code: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    0
}

/// kernel32!OutputDebugStringA(lpOutputString) — emit to serial console.
extern "C" fn nt_fn_output_debug_string_a(ptr: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    if ptr == 0 { return 0; }
    // Read up to 256 bytes as a C string and emit to serial.
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, 256) };
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(256);
    let s = core::str::from_utf8(&bytes[..len]).unwrap_or("<invalid utf8>");
    crate::serial_println!("[ODS] {}", s);
    0
}

/// kernel32!OutputDebugStringW(lpOutputString) — emit low-byte of UTF-16 to serial.
extern "C" fn nt_fn_output_debug_string_w(ptr: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    if ptr == 0 { return 0; }
    let wchars = unsafe { core::slice::from_raw_parts(ptr as *const u16, 256) };
    let n = wchars.iter().position(|&c| c == 0).unwrap_or(256);
    let mut buf = [0u8; 256];
    for (i, &wc) in wchars[..n].iter().enumerate() { buf[i] = wc as u8; }
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("<invalid utf8>");
    crate::serial_println!("[ODS] {}", s);
    0
}

/// kernel32!IsDebuggerPresent() -> BOOL — always returns FALSE.
extern "C" fn nt_fn_is_debugger_present(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    0
}

/// kernel32!GetCurrentProcessId() -> DWORD
extern "C" fn nt_fn_get_current_process_id(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    crate::proc::current_pid() as i64
}

/// kernel32!GetCurrentThreadId() -> DWORD  (same as pid in our flat model)
extern "C" fn nt_fn_get_current_thread_id(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    crate::proc::current_pid() as i64
}

/// kernel32!GetCurrentProcess() -> HANDLE  — pseudo-handle -1 (0xFFFF...)
extern "C" fn nt_fn_get_current_process(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    -1
}

/// kernel32!GetCurrentThread() -> HANDLE  — pseudo-handle -2
extern "C" fn nt_fn_get_current_thread(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    -2
}

/// kernel32!GetSystemInfo(lpSystemInfo*) — writes a minimal SYSTEM_INFO struct.
/// SYSTEM_INFO layout (simplified, 48 bytes):
///   WORD  wProcessorArchitecture (offset 0)  = 9 (PROCESSOR_ARCHITECTURE_AMD64)
///   WORD  wReserved (2) = 0
///   DWORD dwPageSize (4) = 0x1000
///   LPVOID lpMinimumApplicationAddress (8) = 0x10000
///   LPVOID lpMaximumApplicationAddress (16) = 0x0000_7FFF_FFFF_0000
///   DWORD_PTR dwActiveProcessorMask (24) = 1
///   DWORD dwNumberOfProcessors (32) = 1
///   DWORD dwProcessorType (36) = 8664 (x64)
///   DWORD dwAllocationGranularity (40) = 0x10000
///   WORD  wProcessorLevel (44) = 6
///   WORD  wProcessorRevision (46) = 0
extern "C" fn nt_fn_get_system_info(buf: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    if buf == 0 { return 0; }
    let p = buf as *mut u8;
    unsafe {
        core::ptr::write_bytes(p, 0, 48);                           // zero struct
        core::ptr::write_unaligned(p.add(0) as *mut u16, 9u16);     // AMD64
        core::ptr::write_unaligned(p.add(4) as *mut u32, 0x1000);   // page size
        core::ptr::write_unaligned(p.add(8) as *mut u64, 0x10000u64); // min addr
        core::ptr::write_unaligned(p.add(16) as *mut u64, 0x0000_7FFF_FFFF_0000u64); // max addr
        core::ptr::write_unaligned(p.add(24) as *mut u64, 1u64);    // proc mask
        core::ptr::write_unaligned(p.add(32) as *mut u32, 1u32);    // num procs
        core::ptr::write_unaligned(p.add(36) as *mut u32, 8664u32); // proc type
        core::ptr::write_unaligned(p.add(40) as *mut u32, 0x10000); // granularity
        core::ptr::write_unaligned(p.add(44) as *mut u16, 6u16);    // proc level
    }
    0
}

/// kernel32!QueryPerformanceCounter(lpPerformanceCount*) -> BOOL
extern "C" fn nt_fn_query_perf_counter(ptr: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    if ptr != 0 {
        // Return a plausible monotonic counter (use NT time as base)
        let t: i64 = 132_000_000_000_000_000i64;
        unsafe { core::ptr::write_volatile(ptr as *mut i64, t); }
    }
    1 // TRUE
}

/// kernel32!QueryPerformanceFrequency(lpFrequency*) -> BOOL
extern "C" fn nt_fn_query_perf_freq(ptr: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    if ptr != 0 {
        // 10_000_000 = NT FILETIME units per second (100ns ticks)
        let f: i64 = 10_000_000i64;
        unsafe { core::ptr::write_volatile(ptr as *mut i64, f); }
    }
    1 // TRUE
}

/// kernel32!Sleep(dwMilliseconds) — real sleep via nanosleep syscall.
extern "C" fn nt_fn_sleep(ms: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    // Linux nanosleep(35): struct timespec { tv_sec, tv_nsec }
    let mut ts = [ms / 1000, (ms % 1000) * 1_000_000];
    crate::syscall::dispatch_linux(35, ts.as_mut_ptr() as u64, 0, 0, 0, 0, 0);
    0
}

/// kernel32!SetConsoleCtrlHandler — stub (accept any handler silently).
extern "C" fn nt_fn_set_console_ctrl_handler(_handler: u64, _add: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    1 // TRUE
}

/// kernel32!GetConsoleMode(hConsole, lpMode*) -> BOOL
extern "C" fn nt_fn_get_console_mode(_handle: u64, mode_ptr: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    if mode_ptr != 0 {
        // ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT
        unsafe { core::ptr::write_volatile(mode_ptr as *mut u32, 0x0003); }
    }
    1 // TRUE
}

/// kernel32!SetConsoleMode(hConsole, dwMode) -> BOOL  — accept silently.
extern "C" fn nt_fn_set_console_mode(_handle: u64, _mode: u64, _a3: u64, _a4: u64, _a5: u64) -> i64 {
    1 // TRUE
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Convert a negative Linux errno to the nearest NTSTATUS.
fn map_errno(errno: i64) -> i64 {
    match (-errno) as u64 {
        1  => STATUS_ACCESS_DENIED,           // EPERM
        2  => STATUS_OBJECT_NAME_NOT_FOUND,   // ENOENT
        9  => STATUS_INVALID_HANDLE,          // EBADF
        13 => STATUS_ACCESS_DENIED,           // EACCES
        14 => STATUS_INVALID_PARAMETER,       // EFAULT
        22 => STATUS_INVALID_PARAMETER,       // EINVAL
        12 => STATUS_NO_MEMORY,               // ENOMEM
        _  => STATUS_NOT_IMPLEMENTED,
    }
}

/// Map NT page protection flags to POSIX mmap/mprotect flags.
fn nt_prot_to_posix(prot: u32) -> u64 {
    // Linux: PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
    match prot {
        0x01 => 0, // PAGE_NOACCESS           → PROT_NONE
        0x02 => 1, // PAGE_READONLY           → PROT_READ
        0x04 => 3, // PAGE_READWRITE          → PROT_READ|PROT_WRITE
        0x08 => 3, // PAGE_WRITECOPY          → PROT_READ|PROT_WRITE
        0x10 => 4, // PAGE_EXECUTE            → PROT_EXEC
        0x20 => 5, // PAGE_EXECUTE_READ       → PROT_READ|PROT_EXEC
        0x40 => 7, // PAGE_EXECUTE_READWRITE  → PROT_READ|PROT_WRITE|PROT_EXEC
        0x80 => 7, // PAGE_EXECUTE_WRITECOPY  → PROT_READ|PROT_WRITE|PROT_EXEC
        _    => 3, // fallback: PROT_READ|PROT_WRITE
    }
}
