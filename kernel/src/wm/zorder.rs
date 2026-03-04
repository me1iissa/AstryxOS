//! Z-Order Manager — Window stacking management
//!
//! The desktop's `windows` vec is kept in back-to-front order: the last
//! element is the topmost (foreground) window.

extern crate alloc;

use alloc::vec::Vec;

use super::desktop;
use super::window::{self, WindowHandle};

/// Bring a window to the front (top of z-order).
pub fn bring_to_front(handle: WindowHandle) {
    desktop::with_desktop_mut(|desk| {
        if let Some(pos) = desk.windows.iter().position(|&h| h == handle) {
            desk.windows.remove(pos);
            desk.windows.push(handle);
        }
    });
}

/// Send a window to the back (bottom of z-order).
pub fn send_to_back(handle: WindowHandle) {
    desktop::with_desktop_mut(|desk| {
        if let Some(pos) = desk.windows.iter().position(|&h| h == handle) {
            desk.windows.remove(pos);
            desk.windows.insert(0, handle);
        }
    });
}

/// Insert a window immediately after `after` in z-order.
/// If `after` is not found, the window is placed at the front.
pub fn insert_after(handle: WindowHandle, after: WindowHandle) {
    desktop::with_desktop_mut(|desk| {
        // Remove handle from its current position, if present.
        desk.windows.retain(|&h| h != handle);

        if let Some(pos) = desk.windows.iter().position(|&h| h == after) {
            desk.windows.insert(pos + 1, handle);
        } else {
            // Fallback: push to front.
            desk.windows.push(handle);
        }
    });
}

/// Return window handles in z-order (back-to-front).
pub fn get_z_order() -> Vec<WindowHandle> {
    desktop::with_desktop(|desk| desk.windows.clone())
}

/// Return the topmost visible window whose rectangle contains the given
/// screen point, or `None` if the point is on the desktop background.
///
/// Iterates from front (last) to back (first) so the first hit wins.
pub fn window_from_point(x: i32, y: i32) -> Option<WindowHandle> {
    let order = get_z_order();
    // Iterate front→back.
    for &handle in order.iter().rev() {
        let hit = window::with_window(handle, |w| {
            w.style.visible && w.contains_point(x, y)
        });
        if hit == Some(true) {
            return Some(handle);
        }
    }
    None
}
