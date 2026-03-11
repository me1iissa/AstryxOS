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
/// Forwards to `crate::syscall::dispatch_linux()`.  External code should use
/// this rather than calling `syscall::dispatch_linux` directly, as this will
/// remain the stable API surface once the implementation migrates here.
#[inline]
pub fn dispatch(
    num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, arg6: u64,
) -> i64 {
    crate::syscall::dispatch_linux(num, arg1, arg2, arg3, arg4, arg5, arg6)
}
