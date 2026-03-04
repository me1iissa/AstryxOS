//! Power State Model
//!
//! Tracks the current power state, manages power callbacks, and coordinates
//! power transitions across the kernel.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

/// System power states (ACPI S-states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// S0 — Full operation.
    S0Working,
    /// S1 — CPU stopped, RAM refreshed (future).
    S1Standby,
    /// S3 — Suspend to RAM (future).
    S3Suspend,
    /// S4 — Suspend to disk (future).
    S4Hibernate,
    /// S5 — Soft off.
    S5Shutdown,
}

/// Power actions that can be requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    None,
    Shutdown,
    Reboot,
    /// Future: suspend to RAM.
    Sleep,
    /// Future: suspend to disk.
    Hibernate,
}

/// Power callback — registered subsystems/drivers get notified of power transitions.
pub type PowerCallback = fn(action: PowerAction);

/// Entry in the power callback registry.
pub struct PowerCallbackEntry {
    pub id: u64,
    pub name: &'static str,
    pub callback: PowerCallback,
    /// Lower priority values are called first.
    pub priority: u32,
}

/// Current power state.
static CURRENT_STATE: Mutex<PowerState> = Mutex::new(PowerState::S0Working);

/// Registered power callbacks.
static POWER_CALLBACKS: Mutex<Vec<PowerCallbackEntry>> = Mutex::new(Vec::new());

/// Next callback ID.
static NEXT_CALLBACK_ID: AtomicU64 = AtomicU64::new(1);

/// Whether a shutdown has been requested.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Whether a reboot has been requested.
static REBOOT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Initialize the power state model.
pub fn init() {
    let mut state = CURRENT_STATE.lock();
    *state = PowerState::S0Working;
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    REBOOT_REQUESTED.store(false, Ordering::SeqCst);
}

/// Get the current power state.
pub fn get_power_state() -> PowerState {
    *CURRENT_STATE.lock()
}

/// Set the current power state.
pub fn set_power_state(state: PowerState) {
    *CURRENT_STATE.lock() = state;
}

/// Initiate a power transition. This sets the appropriate flags and, for
/// Shutdown/Reboot, delegates to the shutdown subsystem.
pub fn request_power_action(action: PowerAction) {
    match action {
        PowerAction::None => {}
        PowerAction::Shutdown => {
            SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
            super::shutdown::initiate_shutdown();
        }
        PowerAction::Reboot => {
            REBOOT_REQUESTED.store(true, Ordering::SeqCst);
            super::shutdown::initiate_reboot();
        }
        PowerAction::Sleep | PowerAction::Hibernate => {
            crate::serial_println!("[Po] Sleep/Hibernate not yet implemented");
        }
    }
}

/// Register a power callback. Returns a unique ID that can be used to
/// unregister the callback later.
pub fn register_power_callback(
    name: &'static str,
    callback: PowerCallback,
    priority: u32,
) -> u64 {
    let id = NEXT_CALLBACK_ID.fetch_add(1, Ordering::SeqCst);
    let entry = PowerCallbackEntry {
        id,
        name,
        callback,
        priority,
    };
    POWER_CALLBACKS.lock().push(entry);
    id
}

/// Unregister a power callback by its ID.
pub fn unregister_power_callback(id: u64) {
    POWER_CALLBACKS.lock().retain(|e| e.id != id);
}

/// Returns `true` if a shutdown is in progress.
pub fn is_shutdown_in_progress() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Returns `true` if a reboot is in progress.
pub fn is_reboot_in_progress() -> bool {
    REBOOT_REQUESTED.load(Ordering::SeqCst)
}

/// Notify all registered power callbacks of a power action.
/// Callbacks are called in priority order (lowest priority value first).
pub fn notify_power_callbacks(action: PowerAction) {
    let callbacks = POWER_CALLBACKS.lock();
    // Build a sorted list of indices by priority.
    let mut indices: Vec<usize> = (0..callbacks.len()).collect();
    indices.sort_by_key(|&i| callbacks[i].priority);
    for &i in &indices {
        crate::serial_println!(
            "[Po] Notifying power callback '{}' (priority {})",
            callbacks[i].name,
            callbacks[i].priority
        );
        (callbacks[i].callback)(action);
    }
}
