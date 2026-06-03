//! `aether-sys` — Astryx Native SDK, Phase 0 system-call layer.
//!
//! This is the thin, `no_std` foundation that native AstryxOS programs link
//! against to talk to the **Aether** kernel ABI directly — no Linux
//! personality, no libc.  A binary built on `aether-sys` and stamped with the
//! AstryxOS `EI_OSABI` marker (`0xFF`, see [`EI_OSABI`]/[`ELFOSABI_ASTRYX`])
//! is routed by the kernel exec path to the native `dispatch_aether`
//! handler, where syscalls use the small AstryxOS numbering
//! (`SYS_EXIT = 0 .. SYS_SYNC = 49`).
//!
//! # Single-sourced syscall numbers
//!
//! The syscall numbers are **not** re-declared here.  They are re-exported
//! verbatim from [`astryx_shared::syscall`] — the exact same constants the
//! kernel's native dispatch reads — so the userspace and kernel sides of the
//! ABI cannot drift.  Use them via [`nr`], e.g. `aether_sys::nr::SYS_WRITE`.
//!
//! # Calling convention
//!
//! AstryxOS uses the System V AMD64 syscall register convention (the same
//! register assignment the `syscall` instruction expects on x86_64):
//!
//! ```text
//!   rax = syscall number
//!   rdi = arg1   rsi = arg2   rdx = arg3
//!   r10 = arg4   r8  = arg5   r9  = arg6
//!   → result in rax; rcx and r11 are clobbered by `syscall`
//! ```
//!
//! See the System V AMD64 ABI and the AMD64 Architecture Programmer's Manual
//! Vol. 3 (`SYSCALL`/`SYSRET`) for the register-clobber contract.
//!
//! # Status (Phase 0)
//!
//! Phase 0 provides the raw `syscall0..syscall6` primitives (including the
//! previously-missing 6-argument form) and thin wrappers for the calls a
//! "hello world" native program needs (`write`, `exit`, `read`, `getpid`,
//! `yield_cpu`).  Later phases grow the typed wrapper surface and layer the
//! per-call personality selection (Linux / Win32 / BSD) on top.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::arch::asm;

/// Aether native syscall numbers, re-exported from the shared ABI crate.
///
/// This is the **single source of truth** for the native syscall table —
/// the very same `astryx_shared::syscall` module the kernel dispatch reads.
/// Importing through `aether_sys::nr::*` guarantees a native program and the
/// kernel agree on every number.
pub mod nr {
    pub use astryx_shared::syscall::*;
}

// ── EI_OSABI native marker (re-exported for tooling) ───────────────────────

/// `e_ident[EI_OSABI]` index into the ELF identification array (ELF gABI).
pub const EI_OSABI: usize = 7;

/// The `EI_OSABI` byte that marks an ELF as a native AstryxOS (Aether)
/// binary.  Sits in the ELF gABI's architecture/OS-specific `EI_OSABI` range
/// (`0x40..=0xFF`), so it cannot collide with `ELFOSABI_NONE` (0) or
/// `ELFOSABI_GNU` (3).  A build tool stamps `e_ident[7] = 0xFF` on a native
/// program's ELF so the kernel exec path routes it to `dispatch_aether`.
pub const ELFOSABI_ASTRYX: u8 = 0xFF;

// ── Raw syscall primitives ─────────────────────────────────────────────────

/// Perform a raw syscall with 0 arguments.
///
/// # Safety
/// The caller must ensure `nr` is a valid syscall number and that any
/// pointer arguments passed by higher-arity variants are valid.
#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Perform a raw syscall with 1 argument.
///
/// # Safety
/// See [`syscall0`].
#[inline(always)]
pub unsafe fn syscall1(nr: u64, arg1: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Perform a raw syscall with 2 arguments.
///
/// # Safety
/// See [`syscall0`].
#[inline(always)]
pub unsafe fn syscall2(nr: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Perform a raw syscall with 3 arguments.
///
/// # Safety
/// See [`syscall0`].
#[inline(always)]
pub unsafe fn syscall3(nr: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Perform a raw syscall with 4 arguments.
///
/// # Safety
/// See [`syscall0`].
#[inline(always)]
pub unsafe fn syscall4(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Perform a raw syscall with 5 arguments.
///
/// # Safety
/// See [`syscall0`].
#[inline(always)]
pub unsafe fn syscall5(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Perform a raw syscall with 6 arguments.
///
/// The sixth argument is passed in `r9`, completing the System V AMD64
/// syscall register set (`rdi, rsi, rdx, r10, r8, r9`).  This fills the gap
/// that `libsys` left at five arguments — native calls such as a future
/// 6-arg `mmap`/`futex` need it.
///
/// # Safety
/// See [`syscall0`].
#[inline(always)]
pub unsafe fn syscall6(
    nr: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            in("r9") arg6,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

// ── Thin high-level wrappers (Aether numbering) ────────────────────────────

/// `write(fd, buf, count)` — write `count` bytes from `buf` to `fd`.
///
/// Reaches the native [`nr::SYS_WRITE`] (= 1) handler.  Returns the number of
/// bytes written, or a negative errno encoded in the unsigned return.
#[inline]
pub fn write(fd: u64, buf: *const u8, count: u64) -> u64 {
    unsafe { syscall3(nr::SYS_WRITE, fd, buf as u64, count) }
}

/// `read(fd, buf, count)` — read up to `count` bytes from `fd` into `buf`.
///
/// Reaches the native [`nr::SYS_READ`] (= 2) handler.
#[inline]
pub fn read(fd: u64, buf: *mut u8, count: u64) -> u64 {
    unsafe { syscall3(nr::SYS_READ, fd, buf as u64, count) }
}

/// `exit(code)` — terminate the current process with `code`.
///
/// Reaches the native [`nr::SYS_EXIT`] (= 0) handler and never returns.  The
/// trailing `hlt` loop is a defensive fallback in case the kernel ever
/// returns (it does not).
#[inline]
pub fn exit(code: u64) -> ! {
    unsafe {
        syscall1(nr::SYS_EXIT, code);
    }
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

/// `getpid()` — return the calling process's PID.  Native [`nr::SYS_GETPID`].
#[inline]
pub fn getpid() -> u64 {
    unsafe { syscall0(nr::SYS_GETPID) }
}

/// `yield_cpu()` — voluntarily yield the CPU.  Native [`nr::SYS_YIELD`].
#[inline]
pub fn yield_cpu() {
    unsafe {
        syscall0(nr::SYS_YIELD);
    }
}

/// Convenience: write a byte slice to a file descriptor.
///
/// Thin sugar over [`write`] that takes a `&[u8]` instead of a raw pointer +
/// length — the common case for a native "hello world".
#[inline]
pub fn write_all(fd: u64, bytes: &[u8]) -> u64 {
    write(fd, bytes.as_ptr(), bytes.len() as u64)
}
