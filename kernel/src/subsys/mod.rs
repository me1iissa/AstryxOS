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

/// Detect the correct subsystem for an ELF binary.
///
/// Checks ELF OS/ABI byte and PT_INTERP presence:
/// - GNU/Linux ABI (0x03) or PT_INTERP present → `Linux`
/// - AstryxOS ABI (0xFF) or bare static ELF → `Aether`
///
/// This is called by the ELF loader before spawning the process so
/// the process's `subsystem` field is set correctly from the start.
pub fn detect_elf_subsystem(elf_bytes: &[u8]) -> SubsystemType {
    if elf_bytes.len() < 20 {
        return SubsystemType::Aether;
    }

    // ELF identity: byte 7 = OS/ABI
    let os_abi = elf_bytes[7];
    match os_abi {
        0x00 => {
            // System V ABI — could be Linux or Aether; check PT_INTERP
            if has_pt_interp(elf_bytes) {
                SubsystemType::Linux
            } else {
                // Could be either; default to Linux for disk-loaded ELFs
                // (static musl, GCC output, etc.)
                SubsystemType::Linux
            }
        }
        0x03 => SubsystemType::Linux,  // GNU/Linux
        0xFF => SubsystemType::Aether, // AstryxOS native (future)
        _    => SubsystemType::Linux,  // Unknown → assume Linux compat
    }
}

/// Returns true if the ELF has a PT_INTERP segment (dynamic binary).
fn has_pt_interp(elf_bytes: &[u8]) -> bool {
    if elf_bytes.len() < 64 {
        return false;
    }
    // ELF64: e_phoff at offset 32 (8 bytes), e_phentsize at 54 (2 bytes), e_phnum at 56 (2 bytes)
    let e_phoff = u64::from_le_bytes([
        elf_bytes[32], elf_bytes[33], elf_bytes[34], elf_bytes[35],
        elf_bytes[36], elf_bytes[37], elf_bytes[38], elf_bytes[39],
    ]) as usize;
    let e_phentsize = u16::from_le_bytes([elf_bytes[54], elf_bytes[55]]) as usize;
    let e_phnum = u16::from_le_bytes([elf_bytes[56], elf_bytes[57]]) as usize;

    if e_phoff == 0 || e_phentsize < 56 || e_phnum == 0 {
        return false;
    }

    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + 4 > elf_bytes.len() {
            break;
        }
        let p_type = u32::from_le_bytes([
            elf_bytes[off], elf_bytes[off + 1], elf_bytes[off + 2], elf_bytes[off + 3],
        ]);
        if p_type == 3 {
            // PT_INTERP
            return true;
        }
    }
    false
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
