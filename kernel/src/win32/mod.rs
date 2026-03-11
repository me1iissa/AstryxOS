//! Win32 Environment Subsystem — NT Executive Personality Layer
//!
//! Inspired by the Windows NT Win32 subsystem (csrss.exe / win32k.sys).
//! In AstryxOS this is a kernel-mode subsystem that provides the framework
//! for a Win32 environment personality.
//!
//! # Architecture
//! - `SubsystemType` — Tags each process with its environment personality.
//! - `Win32Environment` — Per-process Win32 state (desktop, window station, etc.).
//! - CSRSS-like initialization creates well-known OB objects and an ALPC port.
//! - `CsrApiNumber` — Defines the Win32 CSRSS API message types.
//!
//! In a full implementation, user-mode processes marked as Win32 would
//! communicate with this subsystem via ALPC to perform console and window
//! operations. Here we provide the executive framework.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

// ============================================================================
// Subsystem Type — shared by all processes
// ============================================================================

/// Environment subsystem type for a process.
///
/// Each process is associated with exactly one subsystem personality.
/// The subsystem type determines which APIs are available and how
/// certain syscalls are dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsystemType {
    /// NT native — no environment subsystem; uses raw NT APIs.
    Native,
    /// Aether personality — primary native AstryxOS subsystem.
    Aether,
    /// Linux compatibility personality — translates Linux ABI to Aether.
    Linux,
    /// Win32 personality — Windows-compatible API surface.
    Win32,
}

impl Default for SubsystemType {
    fn default() -> Self {
        SubsystemType::Aether
    }
}

// ============================================================================
// Subsystem Context — per-process subsystem metadata
// ============================================================================

/// Subsystem-specific context attached to a process.
pub struct SubsystemContext {
    /// Which subsystem this process belongs to.
    pub subsystem_type: SubsystemType,
    /// ALPC channel ID to the CSRSS-like server (Win32 only).
    pub csrss_channel: Option<u32>,
    /// Win32-specific flags (reserved for future use).
    pub win32_flags: u32,
}

impl SubsystemContext {
    /// Create a default (Aether) subsystem context.
    pub fn aether() -> Self {
        Self {
            subsystem_type: SubsystemType::Aether,
            csrss_channel: None,
            win32_flags: 0,
        }
    }

    /// Create a Linux compatibility subsystem context.
    pub fn linux() -> Self {
        Self {
            subsystem_type: SubsystemType::Linux,
            csrss_channel: None,
            win32_flags: 0,
        }
    }

    /// Create a Win32 subsystem context.
    pub fn win32(csrss_channel: Option<u32>) -> Self {
        Self {
            subsystem_type: SubsystemType::Win32,
            csrss_channel,
            win32_flags: 0,
        }
    }

    /// Create a native (no subsystem) context.
    pub fn native() -> Self {
        Self {
            subsystem_type: SubsystemType::Native,
            csrss_channel: None,
            win32_flags: 0,
        }
    }
}

// ============================================================================
// Win32 Environment — per-process Win32 state
// ============================================================================

/// Win32 process environment block.
///
/// Stores the Win32-specific state for a process running under the
/// Win32 environment subsystem.
pub struct Win32Environment {
    /// Desktop name (e.g., "WinSta0\\Default").
    pub desktop: String,
    /// Window station name (e.g., "WinSta0").
    pub window_station: String,
    /// Handle to the console object (0 = no console).
    pub console_handle: u32,
    /// Win32 process heap virtual address.
    pub process_heap: u64,
}

impl Win32Environment {
    /// Create a default Win32 environment.
    pub fn default_env() -> Self {
        Self {
            desktop: String::from("WinSta0\\Default"),
            window_station: String::from("WinSta0"),
            console_handle: 0,
            process_heap: 0,
        }
    }
}

// ============================================================================
// CSRSS API Numbers — Win32 subsystem message types
// ============================================================================

/// CSRSS API function numbers for Win32 subsystem ALPC communication.
///
/// In a full implementation, Win32 processes send these as ALPC requests
/// to the CSRSS port, and the subsystem dispatches accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CsrApiNumber {
    /// Create a new Win32 process.
    CreateProcess = 0,
    /// Terminate a Win32 process.
    TerminateProcess = 1,
    /// Create a new Win32 thread.
    CreateThread = 2,
    /// Terminate a Win32 thread.
    TerminateThread = 3,
    /// Get the console handle for the calling process.
    GetConsole = 4,
    /// Allocate a new console for the calling process.
    AllocConsole = 5,
    /// Free the console for the calling process.
    FreeConsole = 6,
}

// ============================================================================
// Subsystem Registry — tracks registered subsystems
// ============================================================================

/// Registered subsystem entry.
struct SubsystemEntry {
    subsystem_type: SubsystemType,
    name: String,
    /// ALPC port name for this subsystem's API port.
    api_port: String,
    /// Whether this subsystem is initialized and active.
    active: bool,
}

/// Global subsystem registry.
static SUBSYSTEM_REGISTRY: Mutex<Vec<SubsystemEntry>> = Mutex::new(Vec::new());

/// Win32 process environments, keyed by PID.
static WIN32_ENVIRONMENTS: Mutex<Vec<(u64, Win32Environment)>> = Mutex::new(Vec::new());

/// Window station counter for handle generation.
static NEXT_STATION_HANDLE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

/// Desktop counter for handle generation.
static NEXT_DESKTOP_HANDLE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

// ============================================================================
// Public API
// ============================================================================

/// Create a window station object in the OB namespace.
///
/// Returns a handle value for the window station.
pub fn create_window_station(name: &str) -> u32 {
    let path = alloc::format!("\\Windows\\WindowStations\\{}", name);
    crate::ob::insert_object(&path, crate::ob::ObjectType::Directory);
    let handle = NEXT_STATION_HANDLE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    crate::serial_println!("[WIN32] Created window station '{}' (handle={})", name, handle);
    handle
}

/// Create a desktop object under a window station in the OB namespace.
///
/// Returns a handle value for the desktop.
pub fn create_desktop(station: &str, name: &str) -> u32 {
    let path = alloc::format!("\\Windows\\Desktops\\{}\\{}", station, name);
    crate::ob::insert_object(&path, crate::ob::ObjectType::Directory);
    let handle = NEXT_DESKTOP_HANDLE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    crate::serial_println!("[WIN32] Created desktop '{}\\{}' (handle={})", station, name, handle);
    handle
}

/// Get the Win32 environment for a process, if it has one.
pub fn get_process_environment(pid: u64) -> Option<usize> {
    let envs = WIN32_ENVIRONMENTS.lock();
    envs.iter().position(|(p, _)| *p == pid)
}

/// Register a Win32 environment for a process.
pub fn register_process_environment(pid: u64, env: Win32Environment) {
    WIN32_ENVIRONMENTS.lock().push((pid, env));
}

/// Remove a Win32 environment when a process exits.
pub fn unregister_process_environment(pid: u64) {
    WIN32_ENVIRONMENTS.lock().retain(|(p, _)| *p != pid);
}

/// Query the subsystem registry for a given type.
pub fn is_subsystem_active(subsystem: SubsystemType) -> bool {
    let registry = SUBSYSTEM_REGISTRY.lock();
    registry.iter().any(|e| e.subsystem_type == subsystem && e.active)
}

/// Get the API port name for a subsystem.
pub fn get_subsystem_port(subsystem: SubsystemType) -> Option<String> {
    let registry = SUBSYSTEM_REGISTRY.lock();
    registry.iter()
        .find(|e| e.subsystem_type == subsystem && e.active)
        .map(|e| e.api_port.clone())
}

/// Get the number of registered subsystems.
pub fn subsystem_count() -> usize {
    SUBSYSTEM_REGISTRY.lock().len()
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the Win32 environment subsystem.
///
/// This performs CSRSS-like initialization:
/// 1. Creates window station and desktop objects in OB.
/// 2. Creates the CsrApiPort ALPC connection port.
/// 3. Registers the Win32 subsystem in the subsystem registry.
pub fn init() {
    // Create the default window station: WinSta0
    // (intermediate directories \Windows\WindowStations are auto-created by OB)
    create_window_station("WinSta0");

    // Create the default desktop: WinSta0\Default
    // (intermediate directories \Windows\Desktops\WinSta0 are auto-created by OB)
    create_desktop("WinSta0", "Default");

    // Create the CSRSS API port via ALPC
    let _csrss_port_id = crate::lpc::create_port("\\ALPC\\CsrApiPort");

    // Register the Win32 subsystem
    {
        let mut registry = SUBSYSTEM_REGISTRY.lock();
        registry.push(SubsystemEntry {
            subsystem_type: SubsystemType::Win32,
            name: String::from("Win32"),
            api_port: String::from("\\ALPC\\CsrApiPort"),
            active: true,
        });
    }

    // Also register the Native and Posix subsystems as always-active
    {
        let mut registry = SUBSYSTEM_REGISTRY.lock();
        registry.push(SubsystemEntry {
            subsystem_type: SubsystemType::Native,
            name: String::from("Native"),
            api_port: String::new(),
            active: true,
        });
        registry.push(SubsystemEntry {
            subsystem_type: SubsystemType::Aether,
            name: String::from("Aether"),
            api_port: String::new(),
            active: true,
        });
        registry.push(SubsystemEntry {
            subsystem_type: SubsystemType::Linux,
            name: String::from("Linux"),
            api_port: String::new(),
            active: true,
        });
    }

    crate::serial_println!("[WIN32] Win32 environment subsystem initialized (CSRSS, WinSta0, Default desktop)");
}
