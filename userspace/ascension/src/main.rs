//! Ascension — AstryxOS Init Process (PID 1)
//!
//! This is the source code for the Ascension init process. It cannot currently
//! be built with `cargo build` because it requires a custom freestanding target.
//! The executable is instead hand-assembled as an ELF binary embedded in the
//! kernel at `kernel/src/proc/ascension_elf.rs`.
//!
//! # Behavior
//! 1. Prints a greeting to stdout
//! 2. Queries its own PID (should be 1)
//! 3. Enters an infinite loop: yields CPU, then reaps any zombie children
//!
//! # Future
//! In later phases, Ascension will:
//! - Fork and exec Orbit (the user shell)
//! - Spawn system services (daemons)
//! - Handle SIGCHLD and reap orphaned processes
//! - Perform orderly shutdown on SYS_EXIT from PID 0

#![no_std]
#![no_main]

// This source is for documentation only. The actual binary is hand-crafted.
// When a userspace toolchain is available, uncomment the code below.

/*
extern crate astryx_libsys as sys;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Greet
    let msg = b"Ascension: AstryxOS init started\n";
    sys::write(1, msg.as_ptr(), msg.len() as u64);

    // Confirm our PID
    let pid = sys::getpid();
    // pid should be 1

    // Main loop: yield + reap children
    loop {
        sys::yield_cpu();
        // Reap any zombie children (non-blocking)
        sys::waitpid(-1, core::ptr::null_mut(), 1); // WNOHANG = 1
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    sys::exit(1);
}
*/
