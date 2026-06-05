//! Embedded `native_hello` ELF64 — Astryx Native SDK Phase 0 sample.
//!
//! This is the result of compiling `userspace/sdk/native_hello/` with the
//! Rust `x86_64-unknown-none` freestanding target (see `kernel/build.rs`),
//! then stamping the ELF `EI_OSABI` byte (`e_ident[7]`) to the AstryxOS
//! native marker `0xFF`.  The sample links only against
//! `userspace/sdk/aether-sys/` — no libc, no Linux personality.
//!
//! Because the binary carries `EI_OSABI = 0xFF`, the kernel exec path
//! (`crate::syscall::apply_exec_subsystem`) routes it to the native
//! `dispatch_aether` handler, where its `SYS_WRITE`/`SYS_EXIT` (Aether
//! numbers 1 / 0) run.  This artefact lets the test suite prove that routing
//! end-to-end without an ext2 disk repack.
//!
//! References:
//! * ELF gABI — `e_ident[EI_OSABI]` field, architecture/OS-specific range.
//! * System V AMD64 ABI — `SYSCALL` register convention.

/// The complete `native_hello` ELF64 binary, EI_OSABI-stamped `0xFF`.
pub static NATIVE_HELLO_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/native_hello.elf"));
