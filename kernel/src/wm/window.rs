//! Window — Core window structure, styles, and global window registry
//!
//! Each window has a unique `WindowHandle` (u64), a class, title, position,
//! dimensions, style flags, and parent/child relationships.  The global
//! `WINDOW_REGISTRY` BTreeMap stores all live windows.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::decorator;
use super::desktop;

// ---------------------------------------------------------------------------
// Handle generation
// ---------------------------------------------------------------------------

/// Opaque handle identifying a window.
pub type WindowHandle = u64;

/// Monotonically increasing handle counter.  Handle 0 is reserved (invalid).
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn alloc_handle() -> WindowHandle {
    NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Window style flags
// ---------------------------------------------------------------------------

/// Per-window style flags controlling decoration and behavior.
#[derive(Debug, Clone, Copy)]
pub struct WindowStyle {
    pub has_title_bar: bool,
    pub has_border: bool,
    pub has_close_button: bool,
    pub has_minimize_button: bool,
    pub has_maximize_button: bool,
    pub resizable: bool,
    pub visible: bool,
    pub topmost: bool,
    pub child: bool,
    pub popup: bool,
}

impl WindowStyle {
    /// Standard overlapped window: title bar, border, all buttons, resizable.
    pub fn overlapped() -> Self {
        Self {
            has_title_bar: true,
            has_border: true,
            has_close_button: true,
            has_minimize_button: true,
            has_maximize_button: true,
            resizable: true,
            visible: true,
            topmost: false,
            child: false,
            popup: false,
        }
    }

    /// Popup window: no decorations, visible.
    pub fn popup() -> Self {
        Self {
            has_title_bar: false,
            has_border: false,
            has_close_button: false,
            has_minimize_button: false,
            has_maximize_button: false,
            resizable: false,
            visible: true,
            topmost: false,
            child: false,
            popup: true,
        }
    }

    /// Child window: no title bar by default, visible.
    pub fn child() -> Self {
        Self {
            has_title_bar: false,
            has_border: true,
            has_close_button: false,
            has_minimize_button: false,
            has_maximize_button: false,
            resizable: false,
            visible: true,
            topmost: false,
            child: true,
            popup: false,
        }
    }

    /// Borderless window: no border, no title — for desktop background, etc.
    pub fn borderless() -> Self {
        Self {
            has_title_bar: false,
            has_border: false,
            has_close_button: false,
            has_minimize_button: false,
            has_maximize_button: false,
            resizable: false,
            visible: true,
            topmost: false,
            child: false,
            popup: false,
        }
    }

    /// Compute the title-bar height for this style.
    pub fn title_bar_height(&self) -> u32 {
        if self.has_title_bar { decorator::TITLE_BAR_HEIGHT } else { 0 }
    }

    /// Compute the border width for this style.
    pub fn border_width(&self) -> u32 {
        if self.has_border { decorator::BORDER_WIDTH } else { 0 }
    }
}

// ---------------------------------------------------------------------------
// Window state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    Normal,
    Minimized,
    Maximized,
}

// ---------------------------------------------------------------------------
// Window struct
// ---------------------------------------------------------------------------

/// A window managed by the window manager.
pub struct Window {
    pub handle: WindowHandle,
    pub class_name: String,
    pub title: String,
    /// Position of the window's outer top-left corner in screen coords.
    pub x: i32,
    pub y: i32,
    /// Full window dimensions including decorations.
    pub width: u32,
    pub height: u32,
    /// Client-area offset from window origin.
    pub client_x: i32,
    pub client_y: i32,
    /// Client-area dimensions.
    pub client_width: u32,
    pub client_height: u32,
    pub style: WindowStyle,
    pub state: WindowState,
    pub parent: Option<WindowHandle>,
    pub children: Vec<WindowHandle>,
    pub focused: bool,
    pub needs_repaint: bool,
    /// Background colour in ARGB format.
    pub bg_color: u32,
    /// Per-window pixel surface (client area): `client_width × client_height` ARGB pixels.
    pub surface: Vec<u32>,
    /// Application-defined data.
    pub user_data: u64,
}

impl Window {
    /// Create a new window, computing client area from style constants.
    pub fn new(
        handle: WindowHandle,
        class_name: &str,
        title: &str,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        style: WindowStyle,
        parent: Option<WindowHandle>,
    ) -> Self {
        let border = style.border_width();
        let title_h = style.title_bar_height();

        let client_x = border as i32;
        let client_y = (title_h + border) as i32;
        let client_width = width.saturating_sub(2 * border);
        let client_height = height.saturating_sub(title_h + 2 * border);

        let surface_size = (client_width as usize) * (client_height as usize);

        Self {
            handle,
            class_name: String::from(class_name),
            title: String::from(title),
            x,
            y,
            width,
            height,
            client_x,
            client_y,
            client_width,
            client_height,
            style,
            state: WindowState::Normal,
            parent,
            children: Vec::new(),
            focused: false,
            needs_repaint: true,
            bg_color: 0xFF1E1E1E, // dark background default
            surface: vec![0xFF1E1E1E; surface_size],
            user_data: 0,
        }
    }

    /// Client rectangle relative to the window origin: (x, y, width, height).
    pub fn client_rect(&self) -> (i32, i32, u32, u32) {
        (self.client_x, self.client_y, self.client_width, self.client_height)
    }

    /// Full window rectangle in screen coordinates: (x, y, width, height).
    pub fn window_rect(&self) -> (i32, i32, u32, u32) {
        (self.x, self.y, self.width, self.height)
    }

    /// Convert screen coordinates to client coordinates.
    pub fn screen_to_client(&self, sx: i32, sy: i32) -> (i32, i32) {
        (sx - self.x - self.client_x, sy - self.y - self.client_y)
    }

    /// Convert client coordinates to screen coordinates.
    pub fn client_to_screen(&self, cx: i32, cy: i32) -> (i32, i32) {
        (cx + self.x + self.client_x, cy + self.y + self.client_y)
    }

    /// Mark the window as needing a repaint.
    pub fn invalidate(&mut self) {
        self.needs_repaint = true;
    }

    /// Returns `true` if the given screen point is inside the window rectangle.
    pub fn contains_point(&self, px: i32, py: i32) -> bool {
        px >= self.x
            && py >= self.y
            && px < self.x + self.width as i32
            && py < self.y + self.height as i32
    }

    /// Recompute client area dimensions (e.g. after resize or style change).
    pub fn recompute_client_area(&mut self) {
        let border = self.style.border_width();
        let title_h = self.style.title_bar_height();
        self.client_x = border as i32;
        self.client_y = (title_h + border) as i32;
        self.client_width = self.width.saturating_sub(2 * border);
        self.client_height = self.height.saturating_sub(title_h + 2 * border);
        // Fully re-allocate the surface so it matches the new stride.
        // Vec::resize would keep old pixel data that is now misaligned.
        self.init_surface();
    }

    /// Re-initialise the surface buffer, filling with `bg_color`.
    pub fn init_surface(&mut self) {
        let size = (self.client_width as usize) * (self.client_height as usize);
        self.surface = vec![self.bg_color; size];
    }
}

// ---------------------------------------------------------------------------
// Global window registry
// ---------------------------------------------------------------------------

static WINDOW_REGISTRY: Mutex<BTreeMap<WindowHandle, Window>> = Mutex::new(BTreeMap::new());

/// Helper: run a closure with an immutable reference to a window.
pub fn with_window<F, R>(handle: WindowHandle, f: F) -> Option<R>
where
    F: FnOnce(&Window) -> R,
{
    let registry = WINDOW_REGISTRY.lock();
    registry.get(&handle).map(f)
}

/// Helper: run a closure with a mutable reference to a window.
pub fn with_window_mut<F, R>(handle: WindowHandle, f: F) -> Option<R>
where
    F: FnOnce(&mut Window) -> R,
{
    let mut registry = WINDOW_REGISTRY.lock();
    registry.get_mut(&handle).map(f)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new window, register it, and add it to the active desktop.
pub fn create_window(
    class_name: &str,
    title: &str,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    style: WindowStyle,
    parent: Option<WindowHandle>,
) -> WindowHandle {
    let handle = alloc_handle();

    // Look up class background colour (if registered)
    let bg = super::class::with_class(class_name, |cls| cls.bg_color).unwrap_or(0xFF1E1E1E);

    let mut win = Window::new(handle, class_name, title, x, y, width, height, style, parent);
    win.bg_color = bg;
    win.init_surface();

    // If this is a child, register with the parent.
    if let Some(parent_h) = parent {
        with_window_mut(parent_h, |p| {
            p.children.push(handle);
        });
    }

    {
        let mut registry = WINDOW_REGISTRY.lock();
        registry.insert(handle, win);
    }

    // Add to desktop z-order if it is a top-level window.
    if parent.is_none() && !style.child {
        desktop::with_desktop_mut(|desk| {
            desk.windows.push(handle);
        });
    }

    crate::serial_println!(
        "[WM] Created window #{} \"{}\" class=\"{}\" ({}x{} at {},{})",
        handle, title, class_name, width, height, x, y
    );

    handle
}

/// Destroy a window and remove it from all registries.
pub fn destroy_window(handle: WindowHandle) {
    // Collect children first so we can destroy them recursively.
    let children: Vec<WindowHandle> = with_window(handle, |w| w.children.clone()).unwrap_or_default();

    for child in children {
        destroy_window(child);
    }

    // Remove from parent's child list.
    if let Some(parent_h) = with_window(handle, |w| w.parent).flatten() {
        with_window_mut(parent_h, |p| {
            p.children.retain(|&h| h != handle);
        });
    }

    // Remove from desktop z-order.
    desktop::with_desktop_mut(|desk| {
        desk.windows.retain(|&h| h != handle);
        if desk.active_window == Some(handle) {
            desk.active_window = None;
        }
        if desk.capture_window == Some(handle) {
            desk.capture_window = None;
        }
    });

    {
        let mut registry = WINDOW_REGISTRY.lock();
        registry.remove(&handle);
    }

    crate::serial_println!("[WM] Destroyed window #{}", handle);
}

/// Show or hide a window.
pub fn show_window(handle: WindowHandle, visible: bool) {
    with_window_mut(handle, |w| {
        w.style.visible = visible;
        w.needs_repaint = true;
    });
}

/// Move a window to new screen coordinates.
pub fn move_window(handle: WindowHandle, x: i32, y: i32) {
    with_window_mut(handle, |w| {
        w.x = x;
        w.y = y;
        w.needs_repaint = true;
    });
}

/// Resize a window and recompute its client area.
///
/// Posts `WM_SIZE` to the window's message queue so apps can re-render.
pub fn resize_window(handle: WindowHandle, width: u32, height: u32) {
    let changed = with_window_mut(handle, |w| {
        let old_w = w.width;
        let old_h = w.height;
        w.width = width;
        w.height = height;
        w.recompute_client_area();
        w.needs_repaint = true;
        old_w != width || old_h != height
    });
    // Notify the window so apps can re-render their content.
    if changed == Some(true) {
        crate::msg::queue::post_message(
            handle,
            crate::msg::message::WM_SIZE,
            0,
            ((width as u64) & 0xFFFF) | (((height as u64) & 0xFFFF) << 16),
        );
    }
}

/// Set the title text of a window.
pub fn set_window_title(handle: WindowHandle, title: &str) {
    with_window_mut(handle, |w| {
        w.title = String::from(title);
        w.needs_repaint = true;
    });
}

/// Get the full window rectangle: (x, y, width, height).
pub fn get_window_rect(handle: WindowHandle) -> Option<(i32, i32, u32, u32)> {
    with_window(handle, |w| w.window_rect())
}

/// Get the client rectangle: (x, y, width, height) relative to window origin.
pub fn get_client_rect(handle: WindowHandle) -> Option<(i32, i32, u32, u32)> {
    with_window(handle, |w| w.client_rect())
}

/// Find the first window with the given title.
pub fn find_window(title: &str) -> Option<WindowHandle> {
    let registry = WINDOW_REGISTRY.lock();
    for (handle, win) in registry.iter() {
        if win.title == title {
            return Some(*handle);
        }
    }
    None
}

/// Get the currently active (focused) window on the default desktop.
pub fn get_active_window() -> Option<WindowHandle> {
    desktop::with_desktop(|desk| desk.active_window)
}

/// Set the active window on the default desktop and update focus flags.
pub fn set_active_window(handle: WindowHandle) {
    // Unfocus the previously active window.
    if let Some(prev) = get_active_window() {
        with_window_mut(prev, |w| {
            w.focused = false;
            w.needs_repaint = true;
        });
    }

    // Focus the new window.
    with_window_mut(handle, |w| {
        w.focused = true;
        w.needs_repaint = true;
    });

    desktop::with_desktop_mut(|desk| {
        desk.active_window = Some(handle);
    });
}

/// Return the total number of live windows.
pub fn get_window_count() -> usize {
    let registry = WINDOW_REGISTRY.lock();
    registry.len()
}
