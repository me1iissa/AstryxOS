//! Linux errno constants and conversion helpers for the Linux compatibility
//! subsystem.
//!
//! Errno codes are positive here (matching the Linux convention).
//! Syscalls return `-ENOENT`, `-EINVAL`, etc.  Use the `neg()` helper or
//! just write `-ENOENT` directly.
//!
//! # Usage
//! ```ignore
//! use crate::subsys::linux::errno::*;
//! return -EINVAL;            // → -22
//! return vfs_err(e);         // converts VfsError → negative i64
//! ```
//!
//! # Sources
//! Values match `include/uapi/asm-generic/errno-base.h` and
//! `include/uapi/asm-generic/errno.h` from the Linux kernel source.

// ─── Base errno (1–34) ───────────────────────────────────────────────────────
/// Operation not permitted
pub const EPERM:            i64 = 1;
/// No such file or directory
pub const ENOENT:           i64 = 2;
/// No such process
pub const ESRCH:            i64 = 3;
/// Interrupted system call
pub const EINTR:            i64 = 4;
/// I/O error
pub const EIO:              i64 = 5;
/// No such device or address
pub const ENXIO:            i64 = 6;
/// Argument list too long
pub const E2BIG:            i64 = 7;
/// Exec format error
pub const ENOEXEC:          i64 = 8;
/// Bad file number
pub const EBADF:            i64 = 9;
/// No child processes
pub const ECHILD:           i64 = 10;
/// Try again (same as EWOULDBLOCK)
pub const EAGAIN:           i64 = 11;
/// Out of memory
pub const ENOMEM:           i64 = 12;
/// Permission denied
pub const EACCES:           i64 = 13;
/// Bad address
pub const EFAULT:           i64 = 14;
/// Block device required
pub const ENOTBLK:          i64 = 15;
/// Device or resource busy
pub const EBUSY:            i64 = 16;
/// File exists
pub const EEXIST:           i64 = 17;
/// Cross-device link
pub const EXDEV:            i64 = 18;
/// No such device
pub const ENODEV:           i64 = 19;
/// Not a directory
pub const ENOTDIR:          i64 = 20;
/// Is a directory
pub const EISDIR:           i64 = 21;
/// Invalid argument
pub const EINVAL:           i64 = 22;
/// File table overflow
pub const ENFILE:           i64 = 23;
/// Too many open files
pub const EMFILE:           i64 = 24;
/// Not a typewriter / inappropriate ioctl
pub const ENOTTY:           i64 = 25;
/// Text file busy
pub const ETXTBSY:          i64 = 26;
/// File too large
pub const EFBIG:            i64 = 27;
/// No space left on device
pub const ENOSPC:           i64 = 28;
/// Illegal seek
pub const ESPIPE:           i64 = 29;
/// Read-only file system
pub const EROFS:            i64 = 30;
/// Too many links
pub const EMLINK:           i64 = 31;
/// Broken pipe
pub const EPIPE:            i64 = 32;
/// Math argument out of domain
pub const EDOM:             i64 = 33;
/// Math result not representable
pub const ERANGE:           i64 = 34;

// ─── Extended errno (35–133) ─────────────────────────────────────────────────
/// Resource deadlock would occur
pub const EDEADLK:          i64 = 35;
/// File name too long
pub const ENAMETOOLONG:     i64 = 36;
/// No record locks available
pub const ENOLCK:           i64 = 37;
/// Invalid system call number
pub const ENOSYS:           i64 = 38;
/// Directory not empty
pub const ENOTEMPTY:        i64 = 39;
/// Too many symbolic links
pub const ELOOP:            i64 = 40;
/// Operation would block (alias of EAGAIN)
pub const EWOULDBLOCK:      i64 = EAGAIN;
/// No message of desired type
pub const ENOMSG:           i64 = 42;
/// Identifier removed
pub const EIDRM:            i64 = 43;
/// Invalid exchange
pub const EBADE:            i64 = 52;
/// No data available
pub const ENODATA:          i64 = 61;
/// Timer expired
pub const ETIME:            i64 = 62;
/// Out of streams resources
pub const ENOSR:            i64 = 63;
/// Link has been severed
pub const ENOLINK:          i64 = 67;
/// Protocol error
pub const EPROTO:           i64 = 71;
/// Multihop attempted
pub const EMULTIHOP:        i64 = 72;
/// Not a data message
pub const EBADMSG:          i64 = 74;
/// Value too large for defined data type
pub const EOVERFLOW:        i64 = 75;
/// Illegal byte sequence
pub const EILSEQ:           i64 = 84;
/// Too many users
pub const EUSERS:           i64 = 87;
/// Socket operation on non-socket
pub const ENOTSOCK:         i64 = 88;
/// Destination address required
pub const EDESTADDRREQ:     i64 = 89;
/// Message too long
pub const EMSGSIZE:         i64 = 90;
/// Protocol wrong type for socket
pub const EPROTOTYPE:       i64 = 91;
/// Protocol not available
pub const ENOPROTOOPT:      i64 = 92;
/// Protocol not supported
pub const EPROTONOSUPPORT:  i64 = 93;
/// Socket type not supported
pub const ESOCKTNOSUPPORT:  i64 = 94;
/// Operation not supported on transport endpoint
pub const EOPNOTSUPP:       i64 = 95;
/// Protocol family not supported
pub const EPFNOSUPPORT:     i64 = 96;
/// Address family not supported by protocol
pub const EAFNOSUPPORT:     i64 = 97;
/// Address already in use
pub const EADDRINUSE:       i64 = 98;
/// Cannot assign requested address
pub const EADDRNOTAVAIL:    i64 = 99;
/// Network is down
pub const ENETDOWN:         i64 = 100;
/// Network is unreachable
pub const ENETUNREACH:      i64 = 101;
/// Network dropped connection because of reset
pub const ENETRESET:        i64 = 102;
/// Software caused connection abort
pub const ECONNABORTED:     i64 = 103;
/// Connection reset by peer
pub const ECONNRESET:       i64 = 104;
/// No buffer space available
pub const ENOBUFS:          i64 = 105;
/// Transport endpoint is already connected
pub const EISCONN:          i64 = 106;
/// Transport endpoint is not connected
pub const ENOTCONN:         i64 = 107;
/// Cannot send after transport endpoint shutdown
pub const ESHUTDOWN:        i64 = 108;
/// Connection timed out
pub const ETIMEDOUT:        i64 = 110;
/// Connection refused
pub const ECONNREFUSED:     i64 = 111;
/// Host is down
pub const EHOSTDOWN:        i64 = 112;
/// No route to host
pub const EHOSTUNREACH:     i64 = 113;
/// Operation already in progress
pub const EALREADY:         i64 = 114;
/// Operation now in progress
pub const EINPROGRESS:      i64 = 115;
/// Stale file handle
pub const ESTALE:           i64 = 116;
/// Quota exceeded
pub const EDQUOT:           i64 = 122;
/// Operation Canceled
pub const ECANCELED:        i64 = 125;
/// Owner died
pub const EOWNERDEAD:       i64 = 130;
/// State not recoverable
pub const ENOTRECOVERABLE:  i64 = 131;

// ─── Convenience helpers ──────────────────────────────────────────────────────

/// Convert a positive errno constant to the negative value returned by a
/// syscall, e.g. `neg(EINVAL)` → `-22i64`.
#[inline(always)]
pub const fn neg(errno: i64) -> i64 { -errno }

/// Convert a [`crate::vfs::VfsError`] into a negative Linux errno value
/// suitable for returning from a Linux syscall handler.
///
/// `VfsError` discriminants already equal their Linux errno counterparts, so
/// this is just a sign-flip.
#[inline]
pub fn vfs_err(e: crate::vfs::VfsError) -> i64 {
    -(e as i64)
}

/// Convert an NtStatus value into a Linux errno.
///
/// Only the most common NT status codes that arise from AstryxOS internals are
/// mapped here.  Unmapped codes fall back to `-EIO`.
pub fn ntstatus_to_errno(status: astryx_shared::NtStatus) -> i64 {
    use astryx_shared::ntstatus::*;
    // NtStatus is an i32 wrapper; match on raw value for clarity.
    let raw = status.0;
    match raw as u32 {
        // Success range → 0
        0x0000_0000 => 0, // STATUS_SUCCESS

        // Common error codes
        0xC000_0001 => -EIO,              // STATUS_UNSUCCESSFUL
        0xC000_0002 => -ENOSYS,           // STATUS_NOT_IMPLEMENTED
        0xC000_0003 => -EIO,              // STATUS_INVALID_INFO_CLASS
        0xC000_0004 => -EINVAL,           // STATUS_INFO_LENGTH_MISMATCH
        0xC000_0005 => -EFAULT,           // STATUS_ACCESS_VIOLATION
        0xC000_0008 => -EBADF,            // STATUS_INVALID_HANDLE
        0xC000_000D => -EINVAL,           // STATUS_INVALID_PARAMETER
        0xC000_0022 => -EACCES,           // STATUS_ACCESS_DENIED
        0xC000_0033 => -ENOENT,           // STATUS_OBJECT_NAME_NOT_FOUND (NO_SUCH_FILE alt)
        0xC000_0034 => -ENOENT,           // STATUS_OBJECT_NAME_INVALID
        0xC000_0035 => -EEXIST,           // STATUS_OBJECT_NAME_COLLISION
        0xC000_003A => -ENOENT,           // STATUS_OBJECT_PATH_NOT_FOUND
        0xC000_004B => -EBUSY,            // STATUS_PIPE_BUSY
        0xC000_0103 => -ENOTEMPTY,        // STATUS_DIRECTORY_NOT_EMPTY
        0xC000_010B => -ENOTDIR,          // STATUS_NOT_A_DIRECTORY
        0xC000_010C => -EISDIR,           // STATUS_FILE_IS_A_DIRECTORY
        0xC000_0120 => -ECANCELED,        // STATUS_CANCELLED
        0xC000_012F => -EIO,              // STATUS_IO_DEVICE_ERROR
        0xC000_0184 => -ENODEV,           // STATUS_DEVICE_NOT_READY
        0xC000_00CF => -EROFS,            // STATUS_MEDIA_WRITE_PROTECTED
        0xC000_0275 => -EOPNOTSUPP,       // STATUS_NOT_SUPPORTED
        0x8000_0005 => -EAGAIN,           // STATUS_BUFFER_OVERFLOW (partial)
        _ if (raw as u32) < 0x4000_0000 => 0,   // informational/success
        _ if (raw as u32) < 0x8000_0000 => 0,   // informational
        _           => -EIO,             // everything else
    }
}
