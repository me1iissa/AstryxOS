//! Aether Native Subsystem
//!
//! The primary AstryxOS subsystem. Processes with `SubsystemType::Aether`
//! use this personality.
//!
//! # Syscall ABI
//! - Numbers: `SYS_EXIT=0` .. `SYS_SYNC=49` (defined in `astryx_shared::syscall`)
//! - Strings: passed as `(ptr: u64, len: u64)` pairs (not null-terminated)
//! - Errors: negative NtStatus values on failure
//! - Entry: `SYSCALL` instruction (MSR-based, same x86_64 path as Linux)
//!
//! # Phase 0.1 Plan
//! Move `dispatch()` body from `kernel/src/syscall/mod.rs` into this module
//! once the Linux extraction is done (avoids disturbing both at once).
//!
//! See `.ai/subsystem/AETHER.md` for full design.

// ============================================================================
// Subsystem dispatch entry point
// ============================================================================
//
// The actual syscall implementations live in `kernel/src/syscall/mod.rs` as
// `dispatch_aether()` during Phase 0.  They will migrate here in Phase 1.
// This wrapper establishes the correct public API without a circular dep:
//   crate::subsys::aether → crate::syscall  (one-way)

/// Aether native syscall entry point.
///
/// Forwards to `crate::syscall::dispatch_aether()`.  External code should use
/// this rather than calling `syscall::dispatch_aether` directly, as this will
/// remain the stable API surface once the implementation migrates here.
#[inline]
pub fn dispatch(
    num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, arg6: u64,
) -> i64 {
    crate::syscall::dispatch_aether(num, arg1, arg2, arg3, arg4, arg5, arg6)
}
