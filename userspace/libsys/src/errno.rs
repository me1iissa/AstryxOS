//! POSIX errno constants and result translation for libsys wrappers.
//!
//! # Background
//!
//! On AstryxOS (and Linux), the `syscall` instruction returns a single
//! `u64`/`i64` in `rax`.  The kernel encodes errors as **small negative
//! values**: a return of `-1..-4095` is an errno code (so e.g. `-2` →
//! `ENOENT`, `-22` → `EINVAL`); anything outside that range is a
//! successful return value.  This is the same convention every Linux
//! syscall obeys (see `intro(2)` and the System V ABI x86_64 supplement
//! §A.2.1).
//!
//! POSIX-shape wrappers, by contrast, return `-1` on failure and set the
//! thread-local `errno` to the corresponding error code.  See
//! `errno(3)` and the relevant function man pages (e.g. `read(2)`,
//! `clock_gettime(2)`).  This module bridges the two conventions.
//!
//! # Usage
//!
//! Wrappers that want POSIX semantics call [`from_kernel_ret`] on the
//! raw syscall return, then either return the success value or surface
//! the error via [`SysResult`].  Wrappers that want raw kernel semantics
//! continue to return `u64`/`i64` directly — both styles coexist.
//!
//! # Why no `errno` global yet
//!
//! AstryxOS-native binaries do not yet have a TLS-backed `errno`
//! global; that requires libsys to take over `_start`, set up the TCB,
//! and provide `__errno_location()`.  Until that lands, callers use
//! `SysResult` directly and inspect the error from the `Err` arm —
//! which is in fact the AS-safe pattern that signal-safe code wants
//! anyway (errno is per-thread state that a signal handler can
//! clobber if not saved/restored).

#![allow(dead_code)]

/// POSIX errno values shared between the kernel and userland.
///
/// These match the Linux x86_64 UAPI numbering so that AstryxOS-native
/// code and the Linux subsystem agree on the wire format.  Sources:
/// `errno(3)`, POSIX issue 7, and `intro(2)`.  Only the codes the
/// kernel currently emits are enumerated here; add more as wrappers
/// surface them.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    /// Operation not permitted.
    EPerm = 1,
    /// No such file or directory.
    ENoEnt = 2,
    /// No such process.
    ESrch = 3,
    /// Interrupted system call.
    EIntr = 4,
    /// I/O error.
    EIo = 5,
    /// No such device or address.
    ENxIo = 6,
    /// Argument list too long.
    E2Big = 7,
    /// Exec format error.
    ENoExec = 8,
    /// Bad file descriptor.
    EBadF = 9,
    /// No child processes.
    EChild = 10,
    /// Resource temporarily unavailable / Try again.
    EAgain = 11,
    /// Out of memory.
    ENoMem = 12,
    /// Permission denied.
    EAcces = 13,
    /// Bad address.
    EFault = 14,
    /// Device or resource busy.
    EBusy = 16,
    /// File exists.
    EExist = 17,
    /// No such device.
    ENoDev = 19,
    /// Not a directory.
    ENotDir = 20,
    /// Is a directory.
    EIsDir = 21,
    /// Invalid argument.
    EInval = 22,
    /// Too many open files in system.
    ENFile = 23,
    /// Too many open files.
    EMFile = 24,
    /// File too large.
    EFBig = 27,
    /// No space left on device.
    ENoSpc = 28,
    /// Illegal seek.
    ESpipe = 29,
    /// Read-only file system.
    ERoFs = 30,
    /// Broken pipe.
    EPipe = 32,
    /// Function not implemented.
    ENoSys = 38,
    /// Not supported.
    ENotSup = 95,
    /// Operation timed out.
    ETimedOut = 110,
    /// An unknown errno value reported by the kernel.
    EUnknown = i32::MAX,
}

impl SysError {
    /// Numeric errno code as POSIX expects.
    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Wrap a raw kernel errno value (positive, i.e. already negated).
    /// Unknown codes round-trip through [`SysError::EUnknown`] — the
    /// raw value is lost, callers needing it should inspect the raw
    /// kernel return before calling this.
    #[inline]
    pub fn from_code(code: i32) -> SysError {
        match code {
            1 => SysError::EPerm,
            2 => SysError::ENoEnt,
            3 => SysError::ESrch,
            4 => SysError::EIntr,
            5 => SysError::EIo,
            6 => SysError::ENxIo,
            7 => SysError::E2Big,
            8 => SysError::ENoExec,
            9 => SysError::EBadF,
            10 => SysError::EChild,
            11 => SysError::EAgain,
            12 => SysError::ENoMem,
            13 => SysError::EAcces,
            14 => SysError::EFault,
            16 => SysError::EBusy,
            17 => SysError::EExist,
            19 => SysError::ENoDev,
            20 => SysError::ENotDir,
            21 => SysError::EIsDir,
            22 => SysError::EInval,
            23 => SysError::ENFile,
            24 => SysError::EMFile,
            27 => SysError::EFBig,
            28 => SysError::ENoSpc,
            29 => SysError::ESpipe,
            30 => SysError::ERoFs,
            32 => SysError::EPipe,
            38 => SysError::ENoSys,
            95 => SysError::ENotSup,
            110 => SysError::ETimedOut,
            _ => SysError::EUnknown,
        }
    }
}

/// Result type for POSIX-shape libsys wrappers.
///
/// `Ok(value)` is the unsigned success return (e.g. byte count for
/// `read`, fd for `open`).  `Err(SysError)` is the POSIX errno code
/// that the wrapper *would* have set on `errno` had a TLS-backed global
/// been available.
pub type SysResult<T> = Result<T, SysError>;

/// The maximum errno code the kernel may encode in a syscall return.
///
/// Per the System V ABI x86_64 supplement §A.2.1 and Linux's
/// `intro(2)`, kernel syscall returns in `-1..=-4095` are errno codes;
/// anything more-negative is a successful pointer/length.  4095 is the
/// canonical MAX_ERRNO; codes beyond it would collide with legitimate
/// high-address pointer returns from `mmap(2)` etc.
pub const MAX_ERRNO: i64 = 4095;

/// Translate a raw kernel syscall return into a [`SysResult`].
///
/// * Returns `Ok(ret as u64)` when `ret >= 0` (success) or when `ret`
///   is more-negative than `-MAX_ERRNO` (a high-address pointer cast
///   to `i64`, as `mmap` returns).
/// * Returns `Err(SysError::from_code(-ret))` when `ret` is in
///   `[-MAX_ERRNO, -1]`.
///
/// This is the single bridge function between the kernel's "negative
/// errno in `rax`" convention and POSIX's "-1 + errno" convention.
#[inline]
pub fn from_kernel_ret(ret: i64) -> SysResult<u64> {
    if ret >= 0 {
        Ok(ret as u64)
    } else if ret >= -MAX_ERRNO {
        // ret is in [-4095, -1] → kernel errno.
        Err(SysError::from_code(-ret as i32))
    } else {
        // Very-negative value: a high-address pointer that the kernel
        // returned as u64 and we widened to i64.  Surface as success.
        Ok(ret as u64)
    }
}

/// Translate a raw kernel return treating it as a *signed* value (for
/// syscalls like `lseek(2)` whose successful return is a signed offset
/// and whose errors fit in `-MAX_ERRNO..-1`).
#[inline]
pub fn from_kernel_ret_signed(ret: i64) -> SysResult<i64> {
    if ret < 0 && ret >= -MAX_ERRNO {
        Err(SysError::from_code(-ret as i32))
    } else {
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_round_trips() {
        for code in [1, 2, 9, 11, 13, 14, 17, 22, 38, 110] {
            let e = SysError::from_code(code);
            assert_eq!(e.as_i32(), code);
        }
    }

    #[test]
    fn unknown_code_falls_back() {
        let e = SysError::from_code(999);
        assert_eq!(e, SysError::EUnknown);
    }

    #[test]
    fn kernel_success_passthrough() {
        assert_eq!(from_kernel_ret(0), Ok(0));
        assert_eq!(from_kernel_ret(42), Ok(42));
        assert_eq!(from_kernel_ret(0x7fff_ffff_ffff), Ok(0x7fff_ffff_ffff));
    }

    #[test]
    fn kernel_error_mapped() {
        assert_eq!(from_kernel_ret(-2), Err(SysError::ENoEnt));
        assert_eq!(from_kernel_ret(-22), Err(SysError::EInval));
        assert_eq!(from_kernel_ret(-4095), Err(SysError::EUnknown));
    }

    #[test]
    fn high_address_pointer_is_success() {
        // mmap commonly returns 0x7eff_xxxx_xxxx as u64; cast to i64 is
        // very-negative (< -MAX_ERRNO) and must surface as Ok.
        let ptr_u64: u64 = 0x7eff_0000_0000;
        assert_eq!(from_kernel_ret(ptr_u64 as i64), Ok(ptr_u64));
        // Even higher: 0xffff_xxxx_xxxx (kernel-half address) → Ok.
        let kptr: u64 = 0xffff_8000_0000_1000;
        assert_eq!(from_kernel_ret(kptr as i64), Ok(kptr));
    }

    #[test]
    fn signed_lseek_error_path() {
        assert_eq!(from_kernel_ret_signed(0), Ok(0));
        assert_eq!(from_kernel_ret_signed(1_000_000), Ok(1_000_000));
        assert_eq!(from_kernel_ret_signed(-29), Err(SysError::ESpipe));
        // A genuinely-large offset on a 64-bit file remains a success:
        assert_eq!(from_kernel_ret_signed(i64::MAX), Ok(i64::MAX));
    }
}
