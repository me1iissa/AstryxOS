//! Inter-Process Communication (IPC) Subsystem
//!
//! Provides pipes, message passing, and signaling mechanisms.

pub mod pipe;
pub mod eventfd;

/// Initialize the IPC subsystem.
pub fn init() {
    crate::serial_println!("[IPC] IPC subsystem initialized (pipes + eventfd)");
}
