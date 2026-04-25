//! Linux Compatibility Subsystem
//!
//! Translates Linux x86_64 syscalls to their Aether equivalents.
//! Processes with `SubsystemType::Linux` use this personality.
//!
//! # Translation Model
//! Linux binaries (musl, glibc) issue `SYSCALL` with Linux-number in RAX.
//! The kernel's `dispatch()` detects `SubsystemType::Linux` and routes here.
//! Each syscall is translated: Linux number → Aether handler or stub.
//! No Linux kernel code is re-implemented; we only translate the interface.
//!
//! # Current State
//! ~90 Linux syscall numbers mapped in `kernel/src/syscall/mod.rs::dispatch_linux()`.
//! Full coverage target: ~385 Linux x86_64 native syscalls.
//!
//! # Phase 0.2 Plan
//! Extract `dispatch_linux()` from `syscall/mod.rs` into `linux/syscall.rs` here.
//! Then add helper modules: translate.rs, errno.rs, signal.rs, elf.rs.
//!
//! # Implementation Phases
//! - Phase 1: ~90 syscalls → static musl hello, ls, cat (done)
//! - Phase 2: ~150 syscalls → coreutils, bash
//! - Phase 3: ~250 syscalls → GCC + dynamic linking (in progress)
//! - Phase 4: ~350 syscalls → X11 client protocol
//!
//! See `.ai/subsystem/LINUX.md` for full design and syscall translation table.

// ─── Submodules ──────────────────────────────────────────────────────────────

/// Linux errno constants and VfsError / NtStatus conversion helpers.
pub mod errno;

/// Linux x86_64 syscall dispatch and Linux-specific helpers.
/// Extracted from `kernel/src/syscall/mod.rs` in Phase 0.2.
pub mod syscall;

/// Firefox-test diagnostic ring helpers — tiny shim that holds the "current
/// syscall's ring-entry index" so sys_read_linux / sys_open_linux can attach
/// path / read-content context without threading it through every signature.
#[cfg(feature = "firefox-test")]
pub mod syscall_ring {
    use core::sync::atomic::{AtomicI64, Ordering};
    use crate::arch::x86_64::apic::MAX_CPUS;

    /// Per-CPU "current syscall ring entry".  -1 means "no entry".
    /// A u64 would wrap harmlessly; i64 lets us store -1 as a sentinel.
    static CUR: [AtomicI64; MAX_CPUS] = [const { AtomicI64::new(-1) }; MAX_CPUS];

    #[inline]
    fn cpu() -> usize { crate::arch::x86_64::apic::cpu_index() }

    #[inline]
    pub fn set_current_entry(idx: Option<usize>) {
        CUR[cpu()].store(idx.map(|v| v as i64).unwrap_or(-1), Ordering::Relaxed);
    }

    #[inline]
    pub fn clear_current_entry() {
        CUR[cpu()].store(-1, Ordering::Relaxed);
    }

    #[inline]
    pub fn current_entry() -> Option<usize> {
        let v = CUR[cpu()].load(Ordering::Relaxed);
        if v < 0 { None } else { Some(v as usize) }
    }
}

// Re-export the two most-used helpers at the subsystem level so submodules
// can write `use crate::subsys::linux::{vfs_err, EINVAL};`.
pub use errno::{vfs_err, EINVAL, ENOENT, EBADF, ENOMEM, EFAULT, ENOSYS,
                EAGAIN, ENFILE, EMFILE, EINTR, EACCES, EPERM, EEXIST, ENOTDIR,
                EISDIR, ENOTEMPTY, ENOSPC, EROFS, EPIPE, ESPIPE, EBUSY,
                ENODEV, ENOTTY, E2BIG, ENOEXEC, ELOOP, ECHILD, EIO};

// ============================================================================
// Subsystem dispatch entry point
// ============================================================================
//
// `dispatch_linux()` lives in `kernel/src/syscall/mod.rs` during Phase 0.
// It will migrate to `linux/syscall.rs` in Phase 0.2.  This wrapper provides
// the stable public API surface now.
//   crate::subsys::linux → crate::syscall  (one-way, no circular dep)

/// Linux compatibility syscall entry point.
///
/// Delegates directly to `self::syscall::dispatch`.  External code should use
/// this rather than calling `syscall::dispatch_linux` directly.
#[inline]
pub fn dispatch(
    num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, arg6: u64,
) -> i64 {
    self::syscall::dispatch(num, arg1, arg2, arg3, arg4, arg5, arg6)
}
