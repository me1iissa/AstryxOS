//! Inter-Process Communication (IPC) Subsystem
//!
//! Provides pipes, message passing, and signaling mechanisms.

pub mod pipe;

/// Initialize the IPC subsystem.
pub fn init() {
    crate::serial_println!("[IPC] IPC subsystem initialized (pipes)");
}
