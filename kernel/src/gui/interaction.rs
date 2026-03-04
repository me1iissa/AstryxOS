//! Window Interaction — dragging, resizing, and caption button operations
//!
//! Handles move-by-title-bar, resize-by-border, and close / minimize /
//! maximize button clicks in the non-client area.

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::Mutex;

use crate::wm::desktop;
use crate::wm::hittest::HitTestResult;
use crate::wm::window::{self, WindowHandle, WindowState};
use crate::msg::message::WM_CLOSE;
use crate::msg::queue::post_message;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum window width during interactive resize.
const MIN_WIDTH: u32 = 150;
/// Minimum window height during interactive resize.
const MIN_HEIGHT: u32 = 80;

// ---------------------------------------------------------------------------
// Drag state
// ---------------------------------------------------------------------------

/// Describes the current interactive operation in progress.
#[derive(Debug)]
enum DragOperation {
    /// No interactive operation.
    None,
    /// The user is moving a window by its title bar.
    Moving {
        handle: WindowHandle,
        offset_x: i32,
        offset_y: i32,
    },
    /// The user is resizing a window by one of its border edges/corners.
    Resizing {
        handle: WindowHandle,
        edge: HitTestResult,
        start_x: i32,
        start_y: i32,
        orig_x: i32,
        orig_y: i32,
        orig_w: u32,
        orig_h: u32,
    },
}

/// Global drag/resize operation state.
static DRAG_STATE: Mutex<DragOperation> = Mutex::new(DragOperation::None);

/// Saved rectangles for maximize-then-restore.  Maps window handle →
/// (x, y, width, height) of the window before it was maximized.
static SAVED_RECTS: Mutex<BTreeMap<WindowHandle, (i32, i32, u32, u32)>> =
    Mutex::new(BTreeMap::new());

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Returns `true` if a drag or resize operation is currently in progress.
pub fn is_dragging() -> bool {
    !matches!(*DRAG_STATE.lock(), DragOperation::None)
}

// ---------------------------------------------------------------------------
// Begin / update / end drag
// ---------------------------------------------------------------------------

/// Begin a title-bar move operation.
///
/// Called when `WM_NCLBUTTONDOWN` fires on `HitTestResult::TitleBar`.
pub fn begin_drag(handle: WindowHandle, mouse_x: i32, mouse_y: i32) {
    if let Some((wx, wy, _, _)) = window::with_window(handle, |w| (w.x, w.y, w.width, w.height)) {
        let offset_x = mouse_x - wx;
        let offset_y = mouse_y - wy;

        *DRAG_STATE.lock() = DragOperation::Moving {
            handle,
            offset_x,
            offset_y,
        };

        desktop::set_capture(Some(handle));
    }
}

/// Begin a border-resize operation.
///
/// Called when `WM_NCLBUTTONDOWN` fires on one of the border hit-test regions.
pub fn begin_resize(handle: WindowHandle, edge: HitTestResult, mouse_x: i32, mouse_y: i32) {
    if let Some((x, y, w, h)) = window::with_window(handle, |w| (w.x, w.y, w.width, w.height)) {
        *DRAG_STATE.lock() = DragOperation::Resizing {
            handle,
            edge,
            start_x: mouse_x,
            start_y: mouse_y,
            orig_x: x,
            orig_y: y,
            orig_w: w,
            orig_h: h,
        };

        desktop::set_capture(Some(handle));
    }
}

/// Update the current drag/resize operation based on new mouse position.
///
/// Called on every `WM_MOUSEMOVE` while a capture is active.
pub fn update_drag(mouse_x: i32, mouse_y: i32) {
    let state = DRAG_STATE.lock();

    match *state {
        DragOperation::None => {}

        DragOperation::Moving {
            handle,
            offset_x,
            offset_y,
        } => {
            let new_x = mouse_x - offset_x;
            let new_y = mouse_y - offset_y;
            // Drop lock before calling into WM to avoid potential deadlocks.
            drop(state);
            window::move_window(handle, new_x, new_y);
        }

        DragOperation::Resizing {
            handle,
            edge,
            start_x,
            start_y,
            orig_x,
            orig_y,
            orig_w,
            orig_h,
        } => {
            // Drop lock early.
            drop(state);

            let dx = mouse_x - start_x;
            let dy = mouse_y - start_y;

            let (mut new_x, mut new_y, mut new_w, mut new_h) = (orig_x, orig_y, orig_w, orig_h);

            // Horizontal component
            match edge {
                HitTestResult::BorderRight
                | HitTestResult::BorderTopRight
                | HitTestResult::BorderBottomRight => {
                    new_w = clamp_u32(orig_w as i32 + dx, MIN_WIDTH);
                }
                HitTestResult::BorderLeft
                | HitTestResult::BorderTopLeft
                | HitTestResult::BorderBottomLeft => {
                    let proposed_w = orig_w as i32 - dx;
                    if proposed_w >= MIN_WIDTH as i32 {
                        new_w = proposed_w as u32;
                        new_x = orig_x + dx;
                    } else {
                        new_w = MIN_WIDTH;
                        new_x = orig_x + (orig_w as i32 - MIN_WIDTH as i32);
                    }
                }
                _ => {}
            }

            // Vertical component
            match edge {
                HitTestResult::BorderBottom
                | HitTestResult::BorderBottomLeft
                | HitTestResult::BorderBottomRight => {
                    new_h = clamp_u32(orig_h as i32 + dy, MIN_HEIGHT);
                }
                HitTestResult::BorderTop
                | HitTestResult::BorderTopLeft
                | HitTestResult::BorderTopRight => {
                    let proposed_h = orig_h as i32 - dy;
                    if proposed_h >= MIN_HEIGHT as i32 {
                        new_h = proposed_h as u32;
                        new_y = orig_y + dy;
                    } else {
                        new_h = MIN_HEIGHT;
                        new_y = orig_y + (orig_h as i32 - MIN_HEIGHT as i32);
                    }
                }
                _ => {}
            }

            window::move_window(handle, new_x, new_y);
            window::resize_window(handle, new_w, new_h);
        }
    }
}

/// End any in-progress drag/resize operation and release the mouse capture.
pub fn end_drag() {
    *DRAG_STATE.lock() = DragOperation::None;
    desktop::set_capture(None);
}

// ---------------------------------------------------------------------------
// Non-client click dispatch
// ---------------------------------------------------------------------------

/// Dispatch a non-client left-button-down event based on the hit-test result.
///
/// Called by the WM message loop when `WM_NCLBUTTONDOWN` is received.
pub fn handle_nonclient_click(
    handle: WindowHandle,
    hit: HitTestResult,
    mouse_x: i32,
    mouse_y: i32,
) {
    match hit {
        // --- Title bar: start moving ---
        HitTestResult::TitleBar => {
            begin_drag(handle, mouse_x, mouse_y);
        }

        // --- Close button ---
        HitTestResult::CloseButton => {
            post_message(handle, WM_CLOSE, 0, 0);
            window::destroy_window(handle);
        }

        // --- Minimize button ---
        HitTestResult::MinimizeButton => {
            window::with_window_mut(handle, |w| {
                w.state = WindowState::Minimized;
            });
            window::show_window(handle, false);
        }

        // --- Maximize / restore toggle ---
        HitTestResult::MaximizeButton => {
            toggle_maximize(handle);
        }

        // --- Border edges and corners: start resizing ---
        HitTestResult::BorderLeft
        | HitTestResult::BorderRight
        | HitTestResult::BorderTop
        | HitTestResult::BorderBottom
        | HitTestResult::BorderTopLeft
        | HitTestResult::BorderTopRight
        | HitTestResult::BorderBottomLeft
        | HitTestResult::BorderBottomRight => {
            begin_resize(handle, hit, mouse_x, mouse_y);
        }

        // Client / Nowhere — nothing to do here.
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Maximize / restore
// ---------------------------------------------------------------------------

/// Toggle between maximized and normal states.
fn toggle_maximize(handle: WindowHandle) {
    let current_state = window::with_window(handle, |w| w.state);

    match current_state {
        Some(WindowState::Maximized) => {
            // Restore to the saved rectangle.
            let saved = {
                let mut rects = SAVED_RECTS.lock();
                rects.remove(&handle)
            };

            if let Some((sx, sy, sw, sh)) = saved {
                window::move_window(handle, sx, sy);
                window::resize_window(handle, sw, sh);
            }

            window::with_window_mut(handle, |w| {
                w.state = WindowState::Normal;
            });
        }

        Some(WindowState::Normal) | Some(WindowState::Minimized) | None => {
            // Save the current rect, then maximize.
            if let Some((x, y, w, h)) =
                window::with_window(handle, |w| (w.x, w.y, w.width, w.height))
            {
                SAVED_RECTS.lock().insert(handle, (x, y, w, h));
            }

            let (screen_w, screen_h) = desktop::screen_size();

            // Maximized windows fill the screen minus the taskbar area.
            let taskbar_h = crate::gui::desktop::TASKBAR_HEIGHT;
            let max_h = screen_h.saturating_sub(taskbar_h);

            window::move_window(handle, 0, 0);
            window::resize_window(handle, screen_w, max_h);

            window::with_window_mut(handle, |w| {
                w.state = WindowState::Maximized;
            });

            // Make sure the window is visible (covers restore-from-minimized).
            window::show_window(handle, true);
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Clamp a signed value to at least `min`, returning as `u32`.
#[inline]
fn clamp_u32(value: i32, min: u32) -> u32 {
    if value < min as i32 {
        min
    } else {
        value as u32
    }
}
