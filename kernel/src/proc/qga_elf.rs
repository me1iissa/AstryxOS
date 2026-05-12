//! Embedded "QGA" guest-agent daemon ELF64 binary for Ring 3 — Phase QGA-2.
//!
//! Unlike the hand-crafted `ascension_elf` / `orbit_elf` placeholders, this
//! binary is the result of compiling `userspace/qga/` with the Rust
//! `x86_64-unknown-none` freestanding target (see `kernel/build.rs`).  The
//! daemon links against `userspace/libsys/` for raw `syscall` wrappers and
//! runs as a native AstryxOS userspace process — no Linux personality, no
//! glibc.
//!
//! The kernel embeds the ELF via `include_bytes!` from Cargo's `OUT_DIR`,
//! then loads it through the existing `proc::usermode::create_user_process`
//! path whenever the `qga` feature is enabled.  See the spawn call sites in
//! `kernel/src/main.rs` for the launch points (early in firefox-test and
//! the default-boot userland-startup blocks).
//!
//! References:
//! * QGA protocol: <https://www.qemu.org/docs/master/interop/qemu-ga-ref.html>
//! * Base64 alphabet used by `guest-file-read`: RFC 4648 §4.

/// The complete QGA daemon ELF64 binary.
///
/// Produced by `cargo build --release --target x86_64-unknown-none` against
/// the `userspace/qga` crate; size is whatever Rust + lld settles on (a few
/// kilobytes — the daemon is small and has no allocator).
pub static QGA_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/qga.elf"));
