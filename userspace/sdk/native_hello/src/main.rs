//! `native_hello` — Astryx Native SDK Phase 0 sample program.
//!
//! A minimal native AstryxOS program: it links only against `aether-sys`
//! (no libc, no Linux personality) and issues two **Aether-numbered**
//! syscalls — `SYS_WRITE` (= 1) and `SYS_EXIT` (= 0) — through the native
//! `syscall` ABI.
//!
//! When this binary's ELF is stamped with the AstryxOS `EI_OSABI` marker
//! (`e_ident[7] = 0xFF`), the kernel exec path routes it to the native
//! `dispatch_aether` handler.  The line it writes to stdout is therefore
//! proof — visible on the serial console — that a native binary reached the
//! Aether dispatch arm, which is the whole point of Phase 0.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

extern crate aether_sys as sys;

/// Distinctive serial-visible marker.  The native `SYS_WRITE` path on fd 1
/// forwards to TTY0, which prints to the serial console, so a harness `grep`
/// for this exact string confirms the program ran under `dispatch_aether`.
const GREETING: &[u8] = b"native_hello: aether dispatch reached (SYS_WRITE/SYS_EXIT)\n";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // fd 1 = stdout.  Aether SYS_WRITE.
    let _ = sys::write_all(1, GREETING);
    // Aether SYS_EXIT with status 0 — never returns.
    sys::exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // No unwinding in a freestanding native binary; exit non-zero.
    sys::exit(101)
}
