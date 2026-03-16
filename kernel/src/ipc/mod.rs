//! Inter-Process Communication (IPC) Subsystem
//!
//! Provides pipes, message passing, and signaling mechanisms.

pub mod pipe;
pub mod eventfd;
pub mod epoll;
pub mod timerfd;
pub mod signalfd;
pub mod inotify;
pub mod sysv_shm;

/// Initialize the IPC subsystem.
pub fn init() {
    crate::serial_println!("[IPC] IPC subsystem initialized (pipes + eventfd + epoll + timerfd + signalfd + inotify + sysv_shm)");
}
