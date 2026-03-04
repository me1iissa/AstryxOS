//! WM — Window Manager
//!
//! NT-inspired window management subsystem:
//! - Window classes and registration
//! - Window creation, destruction, hierarchy
//! - Desktop and window station management
//! - Z-order stacking
//! - Hit testing for mouse interaction
//! - Modern flat window decorations

extern crate alloc;

pub mod window;
pub mod class;
pub mod desktop;
pub mod zorder;
pub mod hittest;
pub mod decorator;

// Re-export key types
pub use window::{WindowHandle, Window, WindowStyle, WindowState};
pub use class::{WindowClass, CursorType};
pub use hittest::HitTestResult;
pub use decorator::{TITLE_BAR_HEIGHT, BORDER_WIDTH};

// Re-export public API
pub use window::{
    create_window, destroy_window, show_window, move_window, resize_window,
    set_window_title, get_window_rect, get_client_rect, find_window,
    get_active_window, set_active_window, get_window_count,
};

/// Initialize the window manager subsystem.
///
/// Creates the default window station, desktop, and registers built-in
/// window classes (Button, Static, Edit, Desktop).
pub fn init(screen_width: u32, screen_height: u32) {
    class::init_default_classes();
    desktop::init_desktop(screen_width, screen_height);
    crate::serial_println!("[WM] Window Manager initialized ({}x{})", screen_width, screen_height);
}
