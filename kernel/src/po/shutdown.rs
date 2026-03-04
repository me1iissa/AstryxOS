//! Shutdown / Reboot Coordination
//!
//! Implements the orderly shutdown and reboot sequences: notifying callbacks,
//! flushing caches, stopping drivers, and finally powering off or rebooting.

use spin::Mutex;

/// Phases of a shutdown sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    NotStarted,
    NotifyingCallbacks,
    FlushingCaches,
    StoppingDrivers,
    PoweringOff,
    Complete,
}

/// Current shutdown phase.
static SHUTDOWN_PHASE: Mutex<ShutdownPhase> = Mutex::new(ShutdownPhase::NotStarted);

/// Initialize shutdown state.
pub fn init_shutdown() {
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::NotStarted;
}

/// Get the current shutdown phase.
pub fn get_shutdown_phase() -> ShutdownPhase {
    *SHUTDOWN_PHASE.lock()
}

/// Perform a clean shutdown sequence.
pub fn initiate_shutdown() {
    crate::serial_println!("[Po] Initiating system shutdown...");

    // Phase 1: Notify power callbacks
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::NotifyingCallbacks;
    super::power::notify_power_callbacks(super::PowerAction::Shutdown);

    // Phase 2: Flush caches
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::FlushingCaches;
    flush_all_caches();

    // Phase 3: Stop drivers
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::StoppingDrivers;
    stop_all_drivers();

    // Phase 4: Power off
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::PoweringOff;
    super::acpi::acpi_shutdown();

    // If we somehow get here, mark complete
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::Complete;
}

/// Perform a clean reboot sequence.
pub fn initiate_reboot() {
    crate::serial_println!("[Po] Initiating system reboot...");

    // Phase 1: Notify power callbacks
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::NotifyingCallbacks;
    super::power::notify_power_callbacks(super::PowerAction::Reboot);

    // Phase 2: Flush caches
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::FlushingCaches;
    flush_all_caches();

    // Phase 3: Stop drivers
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::StoppingDrivers;
    stop_all_drivers();

    // Phase 4: Reboot
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::PoweringOff;
    super::acpi::system_reboot();

    // If we somehow get here, mark complete
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::Complete;
}

/// Emergency shutdown — skip all cleanup, immediately power off.
pub fn emergency_shutdown() {
    crate::serial_println!("[Po] EMERGENCY SHUTDOWN — skipping cleanup!");
    super::acpi::acpi_shutdown();
}

/// Sync all mounted filesystems and flush the page cache.
pub fn flush_all_caches() {
    crate::serial_println!("[Po] Flushing all caches...");
    crate::vfs::sync_all();
    crate::serial_println!("[Po] All caches flushed");
}

/// Placeholder for driver shutdown — log and return.
pub fn stop_all_drivers() {
    crate::serial_println!("[Po] Stopping all drivers...");
    // TODO: iterate over registered drivers and call their stop routines
    crate::serial_println!("[Po] All drivers stopped (placeholder)");
}
