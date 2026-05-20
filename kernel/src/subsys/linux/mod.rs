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

/// Vfork canary snapshot-pair + sibling-syscall tagger diagnostic.  See
/// the module docstring (`vfork_diag.rs`) for the three channels and the
/// reference set (POSIX vfork(2) / clone(2), Intel SDM Vol. 3A §6.8,
/// System V AMD64 ABI §3.4.5.2).  Gated entirely behind `vfork-canary-diag`
/// so master builds are byte-identical.
#[cfg(feature = "vfork-canary-diag")]
pub mod vfork_diag;

/// ELF write-trace diagnostic for the W215-aliasing axis-N investigation:
/// arms a hardware write-only watchpoint on the ld-musl `.data.rel.ro`
/// slot at `0x7F00_0003_7e18` for the duration of the `CLONE_VM|CLONE_VFORK`
/// parent-block window and snapshots the page content before/after.
/// Per Intel SDM Vol. 3B §17.2.4 / §17.2.5.  Gated behind `elf-write-trace`
/// (which also pulls in `w215-diag` for the DR0–DR3 plumbing) so master
/// builds are byte-identical without it.
#[cfg(feature = "elf-write-trace")]
pub mod elf_write_trace;

/// Live `__clone` pthread-args smoking-gun diagnostic — W215 axis-N
/// continuation per tech-lead cross-walk verdict 2026-05-20.  Captures the
/// pthread-args struct's `start_routine` and `arg` fields at successful
/// clone(2)/clone3(2) syscall exit into a 16-entry ring keyed by (pid,
/// tid); on a later CPL-3 `#GP` looks up the trapping child and emits
/// `[CLONE-CHECK]` (framing-falsifier, fires for every matched trap) and
/// `[CLONE-SMOKING-GUN]` (fires when captured `start_routine == rip`).
/// Disambiguates F1 (pre-clone corruption) from F2 (mid-flight kernel
/// aliasing — W215 axis-N) via phys-frame variance.  See POSIX
/// pthread_create(3) / clone(2) / clone3(2), AMD64 SysV ABI §3.4, Intel
/// SDM Vol. 3A §6.15 (`#GP`).  Gated behind `clone-args-diag` so master
/// builds remain byte-identical.
#[cfg(feature = "clone-args-diag")]
pub mod clone_args_diag;

/// SSP-canary divergence diagnostic.  Fires once per `#GP` taken from CPL 3
/// at the publicly-exported musl `__stack_chk_fail` two-byte `hlt;ret` stub
/// (ld-musl-x86_64.so.1 + 0x1c7f9, per the musl ldso `.dynsym`).  The hook
/// emits the live `IA32_FS_BASE` MSR, the master canary at `*(fs_base+0x28)`,
/// and the saved-canary qword the SSP epilogue was about to read.  Mode A
/// (saved-canary mutated) and Mode B (FS_BASE shifted mid-function) are
/// distinguishable from the emitted lines.  Bounded to a small number of
/// events per boot.  See POSIX sigaction(2), Intel SDM Vol. 3A §3.4.4.1
/// (IA32_FS_BASE), §6.15 (#GP), System V AMD64 ABI §6.4.  Gated behind
/// `ssp-canary-diag` so master builds remain byte-identical.
#[cfg(feature = "ssp-canary-diag")]
pub mod ssp_diag;

/// Bounded broadcast-within-cluster compensation for FUTEX_WAKE.  Mitigates
/// the older-glibc `pthread_cond_signal` race
/// (<https://sourceware.org/bugzilla/show_bug.cgi?id=25847>) by
/// optionally waking nearby waiters when a `FUTEX_WAKE(uaddr, n)` would
/// otherwise leave a recently-parked sibling stranded.  See
/// `futex_cluster.rs` for the safety harness.
#[cfg(any(feature = "firefox-test", feature = "test-mode"))]
pub mod futex_cluster;

/// Futex-key resolution diagnostic for `FUTEX_WAKE woken=0`.
///
/// Emits `[FUTEX-WAKE-EMPTY]` lines describing the bucket landscape when
/// a wake returns zero, so the harness can decide whether the kernel
/// key-resolution is correct (waiter on different uaddr → userspace
/// POSIX defence) or wrong (waiter and waker hash to different keys for
/// the same logical futex).  Per `futex(2)`
/// (<https://man7.org/linux/man-pages/man2/futex.2.html>) the
/// `FUTEX_PRIVATE_FLAG` key is `(mm, uaddr)`; AstryxOS uses `(pid, uaddr)`
/// equivalent.  See `futex_key_diag.rs` for the audit framing.
#[cfg(feature = "firefox-test")]
pub mod futex_key_diag;

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
