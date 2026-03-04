//! Orbit — AstryxOS User-Mode Shell
//!
//! This is the source code for the Orbit shell process. It cannot currently
//! be built with `cargo build` because it requires a custom freestanding target.
//! The executable is instead hand-assembled as an ELF binary embedded in the
//! kernel at `kernel/src/proc/orbit_elf.rs`.
//!
//! # Behavior (Phase 13 — minimal)
//! 1. Prints a banner to stdout
//! 2. Enters an infinite yield loop (placeholder for interactive REPL)
//!
//! # Future
//! In later phases, Orbit will:
//! - Print a "orbit> " prompt
//! - Read user input from stdin (fd 0) character by character
//! - Echo characters back to stdout
//! - Parse and execute built-in commands (help, ps, ls, cat, etc.)
//! - Fork + exec external programs from the filesystem
//! - Support command history and line editing

#![no_std]
#![no_main]

// This source is for documentation only. The actual binary is hand-crafted.
// When a userspace toolchain is available, uncomment the code below.

/*
extern crate astryx_libsys as sys;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Print banner
    let banner = b"Orbit: AstryxOS user shell\n";
    sys::write(1, banner.as_ptr(), banner.len() as u64);

    // Main loop (placeholder — will be interactive REPL in future phases)
    loop {
        sys::yield_cpu();

        // Future: print prompt, read input, parse, execute
        // let prompt = b"orbit> ";
        // sys::write(1, prompt.as_ptr(), prompt.len() as u64);
        //
        // let mut buf = [0u8; 1];
        // let n = sys::read(0, buf.as_mut_ptr(), 1);
        // if n == 1 {
        //     sys::write(1, buf.as_ptr(), 1); // echo
        //     if buf[0] == b'\n' {
        //         // parse and execute command
        //     }
        // }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    sys::exit(1);
}
*/
