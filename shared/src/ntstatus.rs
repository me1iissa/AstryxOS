//! NT-Style Status Codes for AstryxOS
//!
//! Inspired by the Windows NT / ReactOS `NTSTATUS` model. Provides a unified
//! status code type used throughout the kernel and exposed to userspace via
//! the syscall ABI.
//!
//! # Bit Layout (32-bit signed integer)
//!
//! ```text
//!  3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//!  1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//! ┌───┬─┬─────────────┬───────────────────────────────────────────────┐
//! │Sev│C│   Facility   │                    Code                      │
//! └───┴─┴─────────────┴───────────────────────────────────────────────┘
//! ```
//!
//! | Field      | Bits  | Description                                     |
//! |------------|-------|-------------------------------------------------|
//! | Severity   | 31–30 | 0=Success, 1=Info, 2=Warning, 3=Error           |
//! | Customer   | 29    | 0=System-defined, 1=Custom/driver-defined        |
//! | Reserved   | 28    | Must be 0                                        |
//! | Facility   | 27–16 | Subsystem that generated the status              |
//! | Code       | 15–0  | Specific status code within that facility        |
//!
//! # Severity
//!
//! - **Success (0)**: Operation completed; `is_success()` returns `true`.
//! - **Informational (1)**: Success with additional info; `is_success()` true.
//! - **Warning (2)**: Partial failure; `is_success()` returns `false`.
//! - **Error (3)**: Operation failed; `is_success()` returns `false`.
//!
//! Key insight: `is_success()` checks `value >= 0` (signed), so both severity
//! 0 and 1 (bit 31 clear) are considered success.

/// NT-style status code — a signed 32-bit integer.
///
/// Follows the ReactOS/Windows NTSTATUS convention:
/// - `>= 0` → success (severity 0 or 1)
/// - `< 0`  → failure (severity 2 or 3)
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(pub i32);

// ═══════════════════════════════════════════════════════════════════════
//  Severity Constants
// ═══════════════════════════════════════════════════════════════════════

/// Severity value for success (bits 31–30 = 00).
pub const SEVERITY_SUCCESS: u32 = 0;
/// Severity value for informational (bits 31–30 = 01).
pub const SEVERITY_INFORMATIONAL: u32 = 1;
/// Severity value for warning (bits 31–30 = 10).
pub const SEVERITY_WARNING: u32 = 2;
/// Severity value for error (bits 31–30 = 11).
pub const SEVERITY_ERROR: u32 = 3;

/// Severity mask shifted into position.
pub const ERROR_SEVERITY_SUCCESS: u32       = 0x0000_0000;
pub const ERROR_SEVERITY_INFORMATIONAL: u32 = 0x4000_0000;
pub const ERROR_SEVERITY_WARNING: u32       = 0x8000_0000;
pub const ERROR_SEVERITY_ERROR: u32         = 0xC000_0000;

// ═══════════════════════════════════════════════════════════════════════
//  Facility Codes
// ═══════════════════════════════════════════════════════════════════════

/// Default facility — most core kernel status codes use this.
pub const FACILITY_NONE: u32 = 0x000;
/// I/O subsystem (block devices, VFS operations).
pub const FACILITY_IO: u32 = 0x004;
/// Process/thread management.
pub const FACILITY_PROCESS: u32 = 0x005;
/// Memory management.
pub const FACILITY_MEMORY: u32 = 0x006;
/// Network stack.
pub const FACILITY_NETWORK: u32 = 0x007;
/// Security / access control.
pub const FACILITY_SECURITY: u32 = 0x008;
/// Filesystem (VFS, FAT32, etc.).
pub const FACILITY_FILESYSTEM: u32 = 0x009;
/// Device drivers.
pub const FACILITY_DRIVER: u32 = 0x00A;
/// Inter-process communication (LPC, pipes).
pub const FACILITY_IPC: u32 = 0x00B;
/// Configuration / Registry.
pub const FACILITY_CONFIG: u32 = 0x00C;
/// Object Manager.
pub const FACILITY_OBJECT: u32 = 0x00D;
/// ELF loader / executable image.
pub const FACILITY_IMAGE: u32 = 0x00E;
/// Syscall interface.
pub const FACILITY_SYSCALL: u32 = 0x00F;
/// Scheduler.
pub const FACILITY_SCHEDULER: u32 = 0x010;
/// ACPI / hardware abstraction.
pub const FACILITY_HAL: u32 = 0x011;
/// Graphics / framebuffer / window manager.
pub const FACILITY_GRAPHICS: u32 = 0x01E;
/// Maximum facility value.
pub const FACILITY_MAXIMUM: u32 = 0x0F0;

// ═══════════════════════════════════════════════════════════════════════
//  Helper: Construct an NTSTATUS from parts
// ═══════════════════════════════════════════════════════════════════════

/// Construct an `NtStatus` from severity, facility, and code.
///
/// ```text
/// value = (severity << 30) | (facility << 16) | code
/// ```
pub const fn make_ntstatus(severity: u32, facility: u32, code: u32) -> NtStatus {
    NtStatus(((severity & 0x3) << 30 | (facility & 0xFFF) << 16 | (code & 0xFFFF)) as i32)
}

// ═══════════════════════════════════════════════════════════════════════
//  Status Code Definitions
// ═══════════════════════════════════════════════════════════════════════

// ── Success (Severity 0) ────────────────────────────────────────────

/// Operation completed successfully.
pub const STATUS_SUCCESS: NtStatus           = NtStatus(0x0000_0000u32 as i32);
/// Operation is pending (async).
pub const STATUS_PENDING: NtStatus           = NtStatus(0x0000_0103u32 as i32);
/// More data is available for enumeration.
pub const STATUS_MORE_ENTRIES: NtStatus      = NtStatus(0x0000_0105u32 as i32);
/// Wait completed due to timeout (success variant).
pub const STATUS_TIMEOUT: NtStatus           = NtStatus(0x0000_0102u32 as i32);
/// Reparse point encountered.
pub const STATUS_REPARSE: NtStatus           = NtStatus(0x0000_0104u32 as i32);
/// Some data was written/read, but not all.
pub const STATUS_PARTIAL_COPY: NtStatus      = NtStatus(0x0000_012Bu32 as i32);

// ── Informational (Severity 1) ──────────────────────────────────────

/// Object created, but name already existed.
pub const STATUS_OBJECT_NAME_EXISTS: NtStatus   = NtStatus(0x4000_0000u32 as i32);
/// Thread was already suspended.
pub const STATUS_THREAD_WAS_SUSPENDED: NtStatus = NtStatus(0x4000_0001u32 as i32);
/// Image loaded at different base address.
pub const STATUS_IMAGE_NOT_AT_BASE: NtStatus    = NtStatus(0x4000_0003u32 as i32);

// ── Warning (Severity 2) ────────────────────────────────────────────

/// Guard page was accessed.
pub const STATUS_GUARD_PAGE_VIOLATION: NtStatus = NtStatus(0x8000_0001u32 as i32);
/// Unaligned data access.
pub const STATUS_DATATYPE_MISALIGNMENT: NtStatus = NtStatus(0x8000_0002u32 as i32);
/// Breakpoint hit.
pub const STATUS_BREAKPOINT: NtStatus           = NtStatus(0x8000_0003u32 as i32);
/// Buffer too small for full data; partial result returned.
pub const STATUS_BUFFER_OVERFLOW: NtStatus      = NtStatus(0x8000_0005u32 as i32);
/// No more files in directory enumeration.
pub const STATUS_NO_MORE_FILES: NtStatus        = NtStatus(0x8000_0006u32 as i32);
/// No more entries in enumeration.
pub const STATUS_NO_MORE_ENTRIES: NtStatus      = NtStatus(0x8000_001Au32 as i32);

// ── Error (Severity 3) ──────────────────────────────────────────────

// Generic errors (Facility 0x000)
/// Generic failure.
pub const STATUS_UNSUCCESSFUL: NtStatus          = NtStatus(0xC000_0001u32 as i32);
/// Function not implemented.
pub const STATUS_NOT_IMPLEMENTED: NtStatus       = NtStatus(0xC000_0002u32 as i32);
/// Invalid information class.
pub const STATUS_INVALID_INFO_CLASS: NtStatus    = NtStatus(0xC000_0003u32 as i32);
/// Buffer length mismatch.
pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus  = NtStatus(0xC000_0004u32 as i32);
/// Invalid memory access.
pub const STATUS_ACCESS_VIOLATION: NtStatus      = NtStatus(0xC000_0005u32 as i32);
/// Page fault I/O error.
pub const STATUS_IN_PAGE_ERROR: NtStatus         = NtStatus(0xC000_0006u32 as i32);
/// Invalid handle.
pub const STATUS_INVALID_HANDLE: NtStatus        = NtStatus(0xC000_0008u32 as i32);
/// Invalid parameter.
pub const STATUS_INVALID_PARAMETER: NtStatus     = NtStatus(0xC000_000Du32 as i32);
/// Device not found.
pub const STATUS_NO_SUCH_DEVICE: NtStatus        = NtStatus(0xC000_000Eu32 as i32);
/// File not found.
pub const STATUS_NO_SUCH_FILE: NtStatus          = NtStatus(0xC000_000Fu32 as i32);
/// Invalid I/O request for device.
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = NtStatus(0xC000_0010u32 as i32);
/// End of file reached.
pub const STATUS_END_OF_FILE: NtStatus           = NtStatus(0xC000_0011u32 as i32);
/// Insufficient virtual memory / out of memory.
pub const STATUS_NO_MEMORY: NtStatus             = NtStatus(0xC000_0017u32 as i32);
/// Illegal CPU instruction.
pub const STATUS_ILLEGAL_INSTRUCTION: NtStatus   = NtStatus(0xC000_001Du32 as i32);
/// Access denied / insufficient privileges.
pub const STATUS_ACCESS_DENIED: NtStatus         = NtStatus(0xC000_0022u32 as i32);
/// Buffer too small (error variant — no partial data).
pub const STATUS_BUFFER_TOO_SMALL: NtStatus      = NtStatus(0xC000_0023u32 as i32);
/// Object name contains invalid characters.
pub const STATUS_OBJECT_NAME_INVALID: NtStatus   = NtStatus(0xC000_0033u32 as i32);
/// Named object not found.
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xC000_0034u32 as i32);
/// Object name collision (already exists).
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = NtStatus(0xC000_0035u32 as i32);
/// Path component not found.
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = NtStatus(0xC000_003Au32 as i32);
/// File sharing violation.
pub const STATUS_SHARING_VIOLATION: NtStatus     = NtStatus(0xC000_0043u32 as i32);
/// Disk is full.
pub const STATUS_DISK_FULL: NtStatus             = NtStatus(0xC000_007Fu32 as i32);
/// Division by zero.
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: NtStatus = NtStatus(0xC000_0094u32 as i32);
/// Insufficient system resources.
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = NtStatus(0xC000_009Au32 as i32);
/// Operation not supported.
pub const STATUS_NOT_SUPPORTED: NtStatus         = NtStatus(0xC000_00BBu32 as i32);
/// Internal error.
pub const STATUS_INTERNAL_ERROR: NtStatus        = NtStatus(0xC000_00E5u32 as i32);
/// Stack overflow.
pub const STATUS_STACK_OVERFLOW: NtStatus        = NtStatus(0xC000_00FDu32 as i32);
/// Directory not empty.
pub const STATUS_DIRECTORY_NOT_EMPTY: NtStatus   = NtStatus(0xC000_0101u32 as i32);
/// Expected directory, got file.
pub const STATUS_NOT_A_DIRECTORY: NtStatus       = NtStatus(0xC000_0103u32 as i32);
/// Expected file, got directory.
pub const STATUS_FILE_IS_A_DIRECTORY: NtStatus   = NtStatus(0xC000_0104u32 as i32);

// I/O errors (Facility FACILITY_IO = 0x004)
/// Device I/O error.
pub const STATUS_IO_DEVICE_ERROR: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IO, 0x0001);
/// Read past end of device.
pub const STATUS_DEVICE_OUT_OF_RANGE: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IO, 0x0002);
/// Buffer too small for I/O operation.
pub const STATUS_IO_BUFFER_TOO_SMALL: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IO, 0x0003);

// Process/thread errors (Facility FACILITY_PROCESS = 0x005)
/// No child processes to wait for.
pub const STATUS_NO_CHILD_PROCESS: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_PROCESS, 0x0001);
/// Process creation failed.
pub const STATUS_PROCESS_CREATION_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_PROCESS, 0x0002);
/// Thread creation failed.
pub const STATUS_THREAD_CREATION_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_PROCESS, 0x0003);
/// Process not found by PID.
pub const STATUS_PROCESS_NOT_FOUND: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_PROCESS, 0x0004);
/// Thread not found by TID.
pub const STATUS_THREAD_NOT_FOUND: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_PROCESS, 0x0005);

// Memory errors (Facility FACILITY_MEMORY = 0x006)
/// Page allocation failed.
pub const STATUS_PAGE_ALLOCATION_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_MEMORY, 0x0001);
/// Virtual memory mapping failed.
pub const STATUS_MAPPING_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_MEMORY, 0x0002);

// Network errors (Facility FACILITY_NETWORK = 0x007)
/// Socket bind failed.
pub const STATUS_NET_BIND_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0001);
/// Socket send failed.
pub const STATUS_NET_SEND_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0002);
/// Socket receive failed (no data).
pub const STATUS_NET_RECV_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0003);
/// Socket not found / invalid.
pub const STATUS_NET_INVALID_SOCKET: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0004);
/// DNS resolution failed.
pub const STATUS_NET_DNS_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0005);
/// Connection refused.
pub const STATUS_NET_CONNECTION_REFUSED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0006);
/// Network timeout.
pub const STATUS_NET_TIMEOUT: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0007);
/// Network interface not initialized.
pub const STATUS_NET_NOT_INITIALIZED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0008);
/// Port already in use.
pub const STATUS_NET_PORT_IN_USE: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_NETWORK, 0x0009);

// Filesystem errors (Facility FACILITY_FILESYSTEM = 0x009)
/// File not found.
pub const STATUS_FS_NOT_FOUND: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_FILESYSTEM, 0x0001);
/// File already exists.
pub const STATUS_FS_FILE_EXISTS: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_FILESYSTEM, 0x0002);
/// Too many open file descriptors.
pub const STATUS_FS_TOO_MANY_OPEN: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_FILESYSTEM, 0x0003);
/// Bad file descriptor.
pub const STATUS_FS_BAD_FD: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_FILESYSTEM, 0x0004);
/// Filesystem full / no space.
pub const STATUS_FS_NO_SPACE: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_FILESYSTEM, 0x0005);
/// FAT32-specific parse error.
pub const STATUS_FS_CORRUPT: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_FILESYSTEM, 0x0006);
/// Read-only filesystem.
pub const STATUS_FS_READ_ONLY: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_FILESYSTEM, 0x0007);

// Image/ELF errors (Facility FACILITY_IMAGE = 0x00E)
/// Not a valid ELF binary (bad magic).
pub const STATUS_INVALID_IMAGE_FORMAT: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IMAGE, 0x0001);
/// Wrong ELF class (not 64-bit).
pub const STATUS_INVALID_IMAGE_CLASS: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IMAGE, 0x0002);
/// Wrong byte order (not little-endian).
pub const STATUS_INVALID_IMAGE_ENDIAN: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IMAGE, 0x0003);
/// Not an executable image.
pub const STATUS_INVALID_IMAGE_TYPE: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IMAGE, 0x0004);
/// Wrong CPU architecture.
pub const STATUS_INVALID_IMAGE_MACHINE: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IMAGE, 0x0005);
/// No loadable segments in image.
pub const STATUS_INVALID_IMAGE_NO_LOAD: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IMAGE, 0x0006);
/// Image too small to be valid.
pub const STATUS_INVALID_IMAGE_TOO_SMALL: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IMAGE, 0x0007);
/// Segment maps into kernel address space.
pub const STATUS_INVALID_IMAGE_KERNEL_ADDR: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IMAGE, 0x0008);

// IPC errors (Facility FACILITY_IPC = 0x00B)
/// Pipe is full / broken.
pub const STATUS_PIPE_BROKEN: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IPC, 0x0001);
/// LPC port not found.
pub const STATUS_PORT_NOT_FOUND: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IPC, 0x0002);
/// LPC message delivery failed.
pub const STATUS_PORT_MESSAGE_FAILED: NtStatus = make_ntstatus(SEVERITY_ERROR, FACILITY_IPC, 0x0003);

// ═══════════════════════════════════════════════════════════════════════
//  NtStatus Methods
// ═══════════════════════════════════════════════════════════════════════

impl NtStatus {
    /// Create an `NtStatus` from a raw i32 value.
    #[inline]
    pub const fn from_raw(value: i32) -> Self {
        NtStatus(value)
    }

    /// Get the raw i32 value.
    #[inline]
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// Check if this is a success status (severity 0 or 1).
    ///
    /// Equivalent to NT's `NT_SUCCESS()` macro: `value >= 0`.
    #[inline]
    pub const fn is_success(self) -> bool {
        self.0 >= 0
    }

    /// Check if this is an informational status (severity 1).
    #[inline]
    pub const fn is_info(self) -> bool {
        self.severity() == SEVERITY_INFORMATIONAL
    }

    /// Check if this is a warning status (severity 2).
    #[inline]
    pub const fn is_warning(self) -> bool {
        self.severity() == SEVERITY_WARNING
    }

    /// Check if this is an error status (severity 3).
    #[inline]
    pub const fn is_error(self) -> bool {
        self.severity() == SEVERITY_ERROR
    }

    /// Extract the severity field (bits 31–30).
    #[inline]
    pub const fn severity(self) -> u32 {
        ((self.0 as u32) >> 30) & 0x3
    }

    /// Extract the facility field (bits 27–16).
    #[inline]
    pub const fn facility(self) -> u32 {
        ((self.0 as u32) >> 16) & 0xFFF
    }

    /// Extract the code field (bits 15–0).
    #[inline]
    pub const fn code(self) -> u32 {
        (self.0 as u32) & 0xFFFF
    }

    /// Check if this is a customer-defined status (bit 29).
    #[inline]
    pub const fn is_customer(self) -> bool {
        ((self.0 as u32) >> 29) & 1 != 0
    }

    /// Convert to a Result: Ok(()) for success, Err(self) for failure.
    #[inline]
    pub fn to_result(self) -> Result<(), NtStatus> {
        if self.is_success() {
            Ok(())
        } else {
            Err(self)
        }
    }

    /// Returns the status name as a static string, or "STATUS_UNKNOWN" if
    /// not recognized.
    pub const fn name(self) -> &'static str {
        match self.0 as u32 {
            // Success
            0x0000_0000 => "STATUS_SUCCESS",
            0x0000_0102 => "STATUS_TIMEOUT",
            0x0000_0103 => "STATUS_PENDING",
            0x0000_0104 => "STATUS_REPARSE",
            0x0000_0105 => "STATUS_MORE_ENTRIES",
            0x0000_012B => "STATUS_PARTIAL_COPY",

            // Informational
            0x4000_0000 => "STATUS_OBJECT_NAME_EXISTS",
            0x4000_0001 => "STATUS_THREAD_WAS_SUSPENDED",
            0x4000_0003 => "STATUS_IMAGE_NOT_AT_BASE",

            // Warning
            0x8000_0001 => "STATUS_GUARD_PAGE_VIOLATION",
            0x8000_0002 => "STATUS_DATATYPE_MISALIGNMENT",
            0x8000_0003 => "STATUS_BREAKPOINT",
            0x8000_0005 => "STATUS_BUFFER_OVERFLOW",
            0x8000_0006 => "STATUS_NO_MORE_FILES",
            0x8000_001A => "STATUS_NO_MORE_ENTRIES",

            // Error — generic
            0xC000_0001 => "STATUS_UNSUCCESSFUL",
            0xC000_0002 => "STATUS_NOT_IMPLEMENTED",
            0xC000_0003 => "STATUS_INVALID_INFO_CLASS",
            0xC000_0004 => "STATUS_INFO_LENGTH_MISMATCH",
            0xC000_0005 => "STATUS_ACCESS_VIOLATION",
            0xC000_0006 => "STATUS_IN_PAGE_ERROR",
            0xC000_0008 => "STATUS_INVALID_HANDLE",
            0xC000_000D => "STATUS_INVALID_PARAMETER",
            0xC000_000E => "STATUS_NO_SUCH_DEVICE",
            0xC000_000F => "STATUS_NO_SUCH_FILE",
            0xC000_0010 => "STATUS_INVALID_DEVICE_REQUEST",
            0xC000_0011 => "STATUS_END_OF_FILE",
            0xC000_0017 => "STATUS_NO_MEMORY",
            0xC000_001D => "STATUS_ILLEGAL_INSTRUCTION",
            0xC000_0022 => "STATUS_ACCESS_DENIED",
            0xC000_0023 => "STATUS_BUFFER_TOO_SMALL",
            0xC000_0033 => "STATUS_OBJECT_NAME_INVALID",
            0xC000_0034 => "STATUS_OBJECT_NAME_NOT_FOUND",
            0xC000_0035 => "STATUS_OBJECT_NAME_COLLISION",
            0xC000_003A => "STATUS_OBJECT_PATH_NOT_FOUND",
            0xC000_0043 => "STATUS_SHARING_VIOLATION",
            0xC000_007F => "STATUS_DISK_FULL",
            0xC000_0094 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
            0xC000_009A => "STATUS_INSUFFICIENT_RESOURCES",
            0xC000_00BB => "STATUS_NOT_SUPPORTED",
            0xC000_00E5 => "STATUS_INTERNAL_ERROR",
            0xC000_00FD => "STATUS_STACK_OVERFLOW",
            0xC000_0101 => "STATUS_DIRECTORY_NOT_EMPTY",
            0xC000_0103 => "STATUS_NOT_A_DIRECTORY",
            0xC000_0104 => "STATUS_FILE_IS_A_DIRECTORY",

            // I/O facility (0x004)
            0xC004_0001 => "STATUS_IO_DEVICE_ERROR",
            0xC004_0002 => "STATUS_DEVICE_OUT_OF_RANGE",
            0xC004_0003 => "STATUS_IO_BUFFER_TOO_SMALL",

            // Process facility (0x005)
            0xC005_0001 => "STATUS_NO_CHILD_PROCESS",
            0xC005_0002 => "STATUS_PROCESS_CREATION_FAILED",
            0xC005_0003 => "STATUS_THREAD_CREATION_FAILED",
            0xC005_0004 => "STATUS_PROCESS_NOT_FOUND",
            0xC005_0005 => "STATUS_THREAD_NOT_FOUND",

            // Memory facility (0x006)
            0xC006_0001 => "STATUS_PAGE_ALLOCATION_FAILED",
            0xC006_0002 => "STATUS_MAPPING_FAILED",

            // Network facility (0x007)
            0xC007_0001 => "STATUS_NET_BIND_FAILED",
            0xC007_0002 => "STATUS_NET_SEND_FAILED",
            0xC007_0003 => "STATUS_NET_RECV_FAILED",
            0xC007_0004 => "STATUS_NET_INVALID_SOCKET",
            0xC007_0005 => "STATUS_NET_DNS_FAILED",
            0xC007_0006 => "STATUS_NET_CONNECTION_REFUSED",
            0xC007_0007 => "STATUS_NET_TIMEOUT",
            0xC007_0008 => "STATUS_NET_NOT_INITIALIZED",
            0xC007_0009 => "STATUS_NET_PORT_IN_USE",

            // Filesystem facility (0x009)
            0xC009_0001 => "STATUS_FS_NOT_FOUND",
            0xC009_0002 => "STATUS_FS_FILE_EXISTS",
            0xC009_0003 => "STATUS_FS_TOO_MANY_OPEN",
            0xC009_0004 => "STATUS_FS_BAD_FD",
            0xC009_0005 => "STATUS_FS_NO_SPACE",
            0xC009_0006 => "STATUS_FS_CORRUPT",
            0xC009_0007 => "STATUS_FS_READ_ONLY",

            // IPC facility (0x00B)
            0xC00B_0001 => "STATUS_PIPE_BROKEN",
            0xC00B_0002 => "STATUS_PORT_NOT_FOUND",

            // Image/ELF facility (0x00E)
            0xC00E_0001 => "STATUS_INVALID_IMAGE_FORMAT",
            0xC00E_0002 => "STATUS_INVALID_IMAGE_CLASS",
            0xC00E_0003 => "STATUS_INVALID_IMAGE_ENDIAN",
            0xC00E_0004 => "STATUS_INVALID_IMAGE_TYPE",
            0xC00E_0005 => "STATUS_INVALID_IMAGE_MACHINE",
            0xC00E_0006 => "STATUS_INVALID_IMAGE_NO_LOAD",
            0xC00E_0007 => "STATUS_INVALID_IMAGE_TOO_SMALL",
            0xC00E_0008 => "STATUS_INVALID_IMAGE_KERNEL_ADDR",

            _ => "STATUS_UNKNOWN",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Trait Implementations
// ═══════════════════════════════════════════════════════════════════════

impl core::fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NtStatus({:#010X} = {})", self.0 as u32, self.name())
    }
}

impl core::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = self.name();
        if name == "STATUS_UNKNOWN" {
            write!(f, "NtStatus({:#010X})", self.0 as u32)
        } else {
            write!(f, "{}", name)
        }
    }
}

impl From<NtStatus> for i32 {
    #[inline]
    fn from(s: NtStatus) -> i32 {
        s.0
    }
}

impl From<i32> for NtStatus {
    #[inline]
    fn from(v: i32) -> Self {
        NtStatus(v)
    }
}

impl From<NtStatus> for i64 {
    #[inline]
    fn from(s: NtStatus) -> i64 {
        s.0 as i64
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  NtResult type alias
// ═══════════════════════════════════════════════════════════════════════

/// Convenience alias: `Result<T, NtStatus>`.
///
/// Used throughout the kernel where functions return data on success
/// or an NT status code on failure.
pub type NtResult<T> = Result<T, NtStatus>;
