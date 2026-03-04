//! Po — Power Management Subsystem
//!
//! Provides power state management, shutdown, reboot, and power callbacks.

pub mod acpi;
pub mod power;
pub mod shutdown;

pub use power::{PowerAction, PowerState, get_power_state, request_power_action};
pub use shutdown::{emergency_shutdown, initiate_reboot, initiate_shutdown};

/// Initialize the power management subsystem.
pub fn init() {
    power::init();
    shutdown::init_shutdown();
    crate::serial_println!("[Po] Power management initialized");
}
