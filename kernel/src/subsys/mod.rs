//! Environment Subsystem Dispatch Layer
//!
//! AstryxOS supports three environment subsystems, each providing a distinct
//! API personality over the Aether kernel executive:
//!
//! - **Aether** (native): The primary AstryxOS subsystem. Uses a custom
//!   ptr+len syscall ABI with 50 native calls and NtStatus error returns.
//!
//! - **Linux** (compat): Translates Linux x86_64 syscall numbers and ABI
//!   conventions to their Aether equivalents. Enables running static and
//!   dynamically-linked Linux ELF binaries.
//!
//! - **Win32/WoW** (compat): Maps NT/Win32 syscalls (INT 0x2E / SYSCALL)
//!   to Aether primitives. Enables running PE32+ console applications.
//!
//! # Module Layout
//!
//! ```text
//! subsys/
//!   mod.rs        — This file: SubsystemManager, detection, helpers
//!   aether/       — Aether native syscall dispatch (Phase 0.1)
//!   linux/        — Linux compat syscall dispatch (Phase 0.2)
//!   win32/        — Win32/WoW dispatch + PE loader (Phase 0.3)
//! ```
//!
//! # Current Status
//! Phase 0.1+0.2 wiring complete:
//! - `syscall::dispatch()` is now a thin router → calls `dispatch_aether()` or
//!   `dispatch_linux()` based on process `SubsystemType`.
//! - `crate::subsys::aether::dispatch()` forwards to `syscall::dispatch_aether()`.
//! - `crate::subsys::linux::dispatch()` forwards to `syscall::dispatch_linux()`.
//! - Implementation bodies still live in `syscall/mod.rs`; physical migration
//!   to `subsys/aether/` and `subsys/linux/` is tracked in Phase 1.
//!
//! See `.ai/subsystem/` for the full architecture design documents.

pub mod aether;
pub mod linux;
pub mod win32;

use crate::win32::SubsystemType;

// ============================================================================
// Subsystem Detection
// ============================================================================

/// `e_ident[EI_OSABI]` index into the ELF identification array.
///
/// Per the ELF gABI, `e_ident[7]` (`EI_OSABI`) identifies the OS/ABI for
/// which the object is prepared.  `0` is `ELFOSABI_NONE` (System V / no
/// extensions), `3` is `ELFOSABI_GNU` (GNU/Linux).  Values `0x40..=0xFF`
/// are reserved for architecture/OS-specific semantics; AstryxOS claims
/// `0xFF` as its private native-ABI marker.
pub const EI_OSABI: usize = 7;

/// The `EI_OSABI` byte that marks an ELF as a native AstryxOS (Aether)
/// binary — i.e. one built against the Aether syscall numbering
/// (`astryx_shared::syscall`, `SYS_EXIT=0 .. SYS_SYNC=49`) rather than the
/// Linux personality.
///
/// `0xFF` sits in the ELF gABI's architecture/OS-specific `EI_OSABI` range
/// (`0x40..=0xFF`), so claiming it cannot collide with the standardised
/// values used by upstream toolchains (`ELFOSABI_NONE=0`, `ELFOSABI_GNU=3`).
pub const ELFOSABI_ASTRYX: u8 = 0xFF;

/// Returns `true` iff `elf_bytes` carries the unambiguous AstryxOS native
/// marker `EI_OSABI == 0xFF`.
///
/// This is the **contract** for native-ABI routing: only an ELF that an
/// AstryxOS toolchain explicitly stamped with `0xFF` is treated as Aether.
/// Everything else — including a bare static System-V ELF (`EI_OSABI=0`,
/// no `PT_INTERP`) — is *not* native and must keep using the Linux
/// personality.  This is the load-bearing invariant that lets AstryxOS run
/// upstream Linux binaries (glibc, musl, libxul) unmodified: those carry
/// `EI_OSABI` of `0` (System V) or `3` (GNU) and must never be mis-routed.
#[inline]
pub fn elf_is_aether_native(elf_bytes: &[u8]) -> bool {
    elf_bytes.len() > EI_OSABI && elf_bytes[EI_OSABI] == ELFOSABI_ASTRYX
}

/// Detect the correct subsystem for an ELF binary.
///
/// Keys off the ELF `EI_OSABI` byte (`e_ident[7]`):
/// - AstryxOS native ABI (`0xFF`)            → `Aether`
/// - everything else (System-V `0`, GNU `3`,
///   any unknown value, or a bare static ELF) → `Linux`
///
/// The default is deliberately `Linux`: AstryxOS's prime directive is to
/// run upstream Linux binaries unmodified, and the overwhelming majority of
/// disk-loaded ELFs (static musl, GCC/Clang output, prebuilt distro
/// binaries) carry `EI_OSABI` of `0` or `3` with no native marker.  A
/// process is routed to `Aether` *only* on the unambiguous `0xFF` marker —
/// see [`elf_is_aether_native`].
///
/// This is called by the exec/ELF-load path before spawning a process so
/// the process's `subsystem` / `linux_abi` fields are set from the start.
pub fn detect_elf_subsystem(elf_bytes: &[u8]) -> SubsystemType {
    if elf_is_aether_native(elf_bytes) {
        SubsystemType::Aether
    } else {
        // System-V (0), GNU/Linux (3), any unknown EI_OSABI, a too-short
        // buffer, or a bare static ELF all stay on the Linux personality —
        // the safe choice for a kernel that must run upstream Linux binaries.
        SubsystemType::Linux
    }
}

// ============================================================================
// Active Subsystem Helper
// ============================================================================

/// Returns a display name for a subsystem type.
pub fn subsystem_name(subsystem: SubsystemType) -> &'static str {
    match subsystem {
        SubsystemType::Native => "Native",
        SubsystemType::Aether => "Aether",
        SubsystemType::Linux  => "Linux",
        SubsystemType::Win32  => "Win32",
    }
}
