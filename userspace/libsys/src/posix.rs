//! POSIX-shape syscall wrappers on top of the raw `syscall*` helpers.
//!
//! Each wrapper here returns a [`SysResult`] (`Ok` on success, `Err`
//! with the errno on failure) instead of the raw kernel return value.
//! This mirrors the convention POSIX function manuals use (`-1` +
//! `errno`), without requiring a TLS-backed `errno` global yet.
//!
//! These wrappers complement (do NOT replace) the raw helpers in
//! `lib.rs`.  Both styles coexist so existing code keeps working while
//! new code can opt into the typed errors.
//!
//! Numbering follows the AstryxOS Linux personality (`linux::SYS_*`),
//! because that is what the kernel's Linux syscall dispatcher accepts.
//! Native programs that have not opted into the Linux ABI must use
//! the raw helpers in `lib.rs`; that interaction is documented per-
//! wrapper below.
//!
//! Sources:
//! * `clock_gettime(2)`, `gettimeofday(2)`, `nanosleep(2)`,
//!   `mprotect(2)`, `tgkill(2)`, `set_tid_address(2)` — Linux man-pages.
//! * POSIX issue 7, `errno(3)` — error convention.
//! * Linux x86_64 UAPI `arch/x86/entry/syscalls/syscall_64.tbl` —
//!   syscall numbers.

#![allow(dead_code)]

use crate::errno::{from_kernel_ret, from_kernel_ret_signed, SysResult};
use crate::linux;
use crate::{syscall0, syscall1, syscall2, syscall3};

// ── Time ────────────────────────────────────────────────────────────

/// `struct timespec` matching the Linux UAPI layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `struct timeval` matching the Linux UAPI layout (microseconds).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// `clockid_t` values per `clock_gettime(2)`.
#[allow(non_camel_case_types)]
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockId {
    Realtime = 0,
    Monotonic = 1,
    ProcessCpuTimeId = 2,
    ThreadCpuTimeId = 3,
    MonotonicRaw = 4,
    RealtimeCoarse = 5,
    MonotonicCoarse = 6,
    Boottime = 7,
}

/// `clock_gettime(clk_id, &mut ts)`.
///
/// On AstryxOS this always goes through the syscall; for the vDSO
/// fast path see [`clock_gettime_vdso`].  Per `clock_gettime(2)`:
/// returns `Ok(())` on success, `Err(EInval)` for an unsupported
/// `clk_id`, `Err(EFault)` if the timespec pointer is outside the
/// process address space.
pub fn clock_gettime(clk_id: ClockId, ts: &mut Timespec) -> SysResult<()> {
    let ret = unsafe {
        syscall2(
            linux::SYS_CLOCK_GETTIME,
            clk_id as u64,
            ts as *mut Timespec as u64,
        ) as i64
    };
    from_kernel_ret(ret).map(|_| ())
}

/// `gettimeofday(&mut tv, NULL)`.
///
/// Per `gettimeofday(2)`: the `tz` argument is obsolete on Linux; we
/// always pass NULL.  Returns `Ok(())` on success.
pub fn gettimeofday(tv: &mut Timeval) -> SysResult<()> {
    let ret = unsafe {
        syscall2(
            linux::SYS_GETTIMEOFDAY,
            tv as *mut Timeval as u64,
            0,
        ) as i64
    };
    from_kernel_ret(ret).map(|_| ())
}

/// `nanosleep(&req, NULL)` — POSIX-shape sleep with `Timespec`.
///
/// Per `nanosleep(2)`: returns `Ok(())` on success, `Err(EIntr)` if a
/// signal interrupted the sleep, `Err(EInval)` if `tv_nsec` is out of
/// range or `tv_sec` is negative.
pub fn nanosleep_ts(req: &Timespec) -> SysResult<()> {
    // Linux `nanosleep(2)` is syscall 35; this calls it directly rather
    // than the AstryxOS-native millisecond variant in `lib.rs::nanosleep`.
    const SYS_NANOSLEEP_LINUX: u64 = 35;
    let ret = unsafe {
        syscall2(
            SYS_NANOSLEEP_LINUX,
            req as *const Timespec as u64,
            0, // rem: NULL — we don't surface remainder
        ) as i64
    };
    from_kernel_ret(ret).map(|_| ())
}

/// vDSO fast-path `clock_gettime`.
///
/// `vdso_fn` is the function pointer obtained from
/// [`crate::auxv::vdso_lookup`] resolving `"__vdso_clock_gettime"`
/// against the vDSO base address from `AT_SYSINFO_EHDR`.  If `vdso_fn`
/// is `None`, falls back to [`clock_gettime`].
///
/// Per `vdso(7)`: the vDSO version returns `0` on success and a
/// negative errno on failure — the same convention as a raw syscall —
/// so the translation step uses [`from_kernel_ret`] just like the
/// syscall path.
pub fn clock_gettime_vdso(
    vdso_fn: Option<unsafe extern "C" fn(i32, *mut Timespec) -> i32>,
    clk_id: ClockId,
    ts: &mut Timespec,
) -> SysResult<()> {
    if let Some(f) = vdso_fn {
        let r = unsafe { f(clk_id as i32, ts as *mut Timespec) };
        from_kernel_ret(r as i64).map(|_| ())
    } else {
        clock_gettime(clk_id, ts)
    }
}

// ── Memory protection ──────────────────────────────────────────────

/// `prot` bits for [`mprotect`] per `mprotect(2)`.
pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

/// `mprotect(addr, len, prot)`.
///
/// Per `mprotect(2)`: changes the protection of pages in
/// `[addr, addr + len)`.  Returns `Ok(())` on success, `Err(EInval)`
/// for an unaligned address or an out-of-range protection bitmask,
/// `Err(EAcces)` if the mapping does not permit the requested
/// protection (e.g. write on a read-only file mapping with
/// `MAP_PRIVATE`).
pub fn mprotect(addr: *mut u8, len: usize, prot: u32) -> SysResult<()> {
    let ret = unsafe {
        syscall3(linux::SYS_MPROTECT, addr as u64, len as u64, prot as u64) as i64
    };
    from_kernel_ret(ret).map(|_| ())
}

// ── Signals ────────────────────────────────────────────────────────

/// `tgkill(tgid, tid, sig)` — POSIX-extension signal delivery to a
/// specific thread of a specific process.
///
/// Per `tgkill(2)`: returns `Ok(())` on success, `Err(ESrch)` if no
/// such tgid/tid combination exists, `Err(EInval)` for an invalid
/// signal number, `Err(EPerm)` if the caller lacks permission.
pub fn tgkill(tgid: i32, tid: i32, sig: i32) -> SysResult<()> {
    let ret = unsafe {
        syscall3(linux::SYS_TGKILL, tgid as u64, tid as u64, sig as u64) as i64
    };
    from_kernel_ret(ret).map(|_| ())
}

// ── Thread / TID housekeeping ──────────────────────────────────────

/// `set_tid_address(tidptr)` — register a TID-clear address with the
/// kernel.
///
/// Per `set_tid_address(2)`: stores `tidptr` in the calling thread's
/// `clear_child_tid` field; the kernel zeroes `*tidptr` and wakes one
/// futex waiter on it when the thread exits.  Returns the caller's
/// TID; the syscall does not fail (Linux documents no error returns).
///
/// libc startup (musl, glibc) calls this very early to wire up
/// `pthread_join` / `pthread_detach` wakeup semantics.
pub fn set_tid_address(tidptr: *mut i32) -> SysResult<u64> {
    let ret = unsafe { syscall1(linux::SYS_SET_TID_ADDRESS, tidptr as u64) as i64 };
    from_kernel_ret(ret)
}

// ── Misc ───────────────────────────────────────────────────────────

/// `sched_yield()` (Linux #24) — voluntarily relinquish the CPU.
pub fn sched_yield() -> SysResult<()> {
    let ret = unsafe { syscall0(linux::SYS_SCHED_YIELD) as i64 };
    from_kernel_ret(ret).map(|_| ())
}

/// `getrandom(buf, flags=0)` — fill `buf` with kernel-supplied
/// randomness.
///
/// Per `getrandom(2)`: returns the number of bytes written.
pub fn getrandom_buf(buf: &mut [u8]) -> SysResult<usize> {
    let ret = unsafe {
        syscall3(
            linux::SYS_GETRANDOM,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
        ) as i64
    };
    from_kernel_ret_signed(ret).map(|n| n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::SysError;

    #[test]
    fn timespec_layout() {
        // 16 bytes — kernel UAPI expects exactly this for clock_gettime.
        assert_eq!(core::mem::size_of::<Timespec>(), 16);
        assert_eq!(core::mem::align_of::<Timespec>(), 8);
    }

    #[test]
    fn timeval_layout() {
        assert_eq!(core::mem::size_of::<Timeval>(), 16);
    }

    #[test]
    fn clock_id_values_match_uapi() {
        // <linux/time.h> CLOCK_MONOTONIC = 1, CLOCK_REALTIME = 0, etc.
        assert_eq!(ClockId::Realtime as i32, 0);
        assert_eq!(ClockId::Monotonic as i32, 1);
        assert_eq!(ClockId::Boottime as i32, 7);
    }

    #[test]
    fn prot_bits_match_uapi() {
        // <sys/mman.h> bit assignments.
        assert_eq!(PROT_NONE, 0);
        assert_eq!(PROT_READ, 1);
        assert_eq!(PROT_WRITE, 2);
        assert_eq!(PROT_EXEC, 4);
    }

    #[test]
    fn from_kernel_ret_classifies_eintr() {
        // A nanosleep(2) error path: kernel returns -EINTR (-4).
        let err = from_kernel_ret(-4);
        assert_eq!(err, Err(SysError::EIntr));
    }
}
