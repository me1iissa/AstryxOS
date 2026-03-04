//! Desktop & Window Station management
//!
//! A `WinStation` contains one or more `Desktop` instances.  Each desktop
//! holds the set of top-level windows and tracks the active/capture window.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use super::window::WindowHandle;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A desktop contains windows and manages a screen.
pub struct Desktop {
    pub name: String,
    pub width: u32,
    pub height: u32,
    /// Background colour (ARGB).
    pub bg_color: u32,
    /// Top-level window handles in z-order (back-to-front: last element = topmost).
    pub windows: Vec<WindowHandle>,
    /// The currently active (foreground) window.
    pub active_window: Option<WindowHandle>,
    /// The window that has captured the mouse, if any.
    pub capture_window: Option<WindowHandle>,
}

impl Desktop {
    /// Create a new desktop with the given name and screen dimensions.
    pub fn new(name: &str, width: u32, height: u32) -> Self {
        Self {
            name: String::from(name),
            width,
            height,
            bg_color: 0xFF000000,
            windows: Vec::new(),
            active_window: None,
            capture_window: None,
        }
    }
}

/// A window station contains desktops.
pub struct WinStation {
    pub name: String,
    pub desktops: Vec<Desktop>,
    pub active_desktop: usize,
}

impl WinStation {
    /// Create a new window station with a single default desktop.
    pub fn new(name: &str, desktop: Desktop) -> Self {
        Self {
            name: String::from(name),
            desktops: alloc::vec![desktop],
            active_desktop: 0,
        }
    }

    /// Return a reference to the active desktop.
    pub fn active_desktop(&self) -> &Desktop {
        &self.desktops[self.active_desktop]
    }

    /// Return a mutable reference to the active desktop.
    pub fn active_desktop_mut(&mut self) -> &mut Desktop {
        &mut self.desktops[self.active_desktop]
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static WIN_STATION: Mutex<Option<WinStation>> = Mutex::new(None);

/// Initialize the default window station ("WinSta0") and desktop ("Default").
pub fn init_desktop(width: u32, height: u32) {
    let desktop = Desktop::new("Default", width, height);
    let station = WinStation::new("WinSta0", desktop);
    let mut ws = WIN_STATION.lock();
    *ws = Some(station);
    crate::serial_println!("[WM] Created WinSta0/Default desktop ({}x{})", width, height);
}

/// Run a closure with an immutable reference to the active desktop.
pub fn with_desktop<F, R>(f: F) -> R
where
    F: FnOnce(&Desktop) -> R,
{
    let ws = WIN_STATION.lock();
    let station = ws.as_ref().expect("[WM] Window station not initialized");
    f(station.active_desktop())
}

/// Run a closure with a mutable reference to the active desktop.
pub fn with_desktop_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut Desktop) -> R,
{
    let mut ws = WIN_STATION.lock();
    let station = ws.as_mut().expect("[WM] Window station not initialized");
    f(station.active_desktop_mut())
}

/// Set the active (foreground) window on the current desktop.
pub fn set_active_window(handle: WindowHandle) {
    with_desktop_mut(|desk| {
        desk.active_window = Some(handle);
    });
}

/// Set or clear the mouse-capture window.
pub fn set_capture(handle: Option<WindowHandle>) {
    with_desktop_mut(|desk| {
        desk.capture_window = handle;
    });
}

/// Get the screen dimensions of the active desktop.
pub fn screen_size() -> (u32, u32) {
    with_desktop(|desk| (desk.width, desk.height))
}
