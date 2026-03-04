//! Hit Testing — Determine what part of a window the cursor is over
//!
//! Uses the modern flat-style dimensions from `decorator` to classify a
//! screen-space point into one of the `HitTestResult` variants.

use super::decorator;
use super::window::Window;

// ---------------------------------------------------------------------------
// Result enum
// ---------------------------------------------------------------------------

/// Classification of a point relative to a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitTestResult {
    /// Outside all windows.
    Nowhere,
    /// Inside the client area.
    Client,
    /// On the title bar (drag handle).
    TitleBar,
    /// On the close button.
    CloseButton,
    /// On the minimize button.
    MinimizeButton,
    /// On the maximize button.
    MaximizeButton,
    /// Resize border regions.
    BorderLeft,
    BorderRight,
    BorderTop,
    BorderBottom,
    BorderTopLeft,
    BorderTopRight,
    BorderBottomLeft,
    BorderBottomRight,
}

// ---------------------------------------------------------------------------
// Hit test implementation
// ---------------------------------------------------------------------------

/// Test a screen-space point `(x, y)` against `window` and return the region.
///
/// Returns `HitTestResult::Nowhere` if the point is outside the window rect.
pub fn hit_test(window: &Window, x: i32, y: i32) -> HitTestResult {
    if !window.contains_point(x, y) {
        return HitTestResult::Nowhere;
    }

    // Local coordinates relative to window origin.
    let lx = x - window.x;
    let ly = y - window.y;
    let w = window.width as i32;
    let h = window.height as i32;

    let grip = decorator::RESIZE_GRIP as i32;
    let corner = (grip * 2) as i32; // corner regions are 8×8

    // --- Resize borders (only if resizable + has_border) ---
    if window.style.resizable && window.style.has_border {
        let on_left   = lx < grip;
        let on_right  = lx >= w - grip;
        let on_top    = ly < grip;
        let on_bottom = ly >= h - grip;

        // Corners first (they overlap edges).
        if on_top && on_left && lx < corner && ly < corner {
            return HitTestResult::BorderTopLeft;
        }
        if on_top && on_right && lx >= w - corner && ly < corner {
            return HitTestResult::BorderTopRight;
        }
        if on_bottom && on_left && lx < corner && ly >= h - corner {
            return HitTestResult::BorderBottomLeft;
        }
        if on_bottom && on_right && lx >= w - corner && ly >= h - corner {
            return HitTestResult::BorderBottomRight;
        }

        // Edges.
        if on_left   { return HitTestResult::BorderLeft; }
        if on_right  { return HitTestResult::BorderRight; }
        if on_top    { return HitTestResult::BorderTop; }
        if on_bottom { return HitTestResult::BorderBottom; }
    }

    // --- Title bar region ---
    if window.style.has_title_bar {
        let tb_height = decorator::TITLE_BAR_HEIGHT as i32;
        let border = if window.style.has_border { decorator::BORDER_WIDTH as i32 } else { 0 };

        if ly >= border && ly < border + tb_height {
            // Check caption buttons (right-aligned in the title bar).
            let btn_w = decorator::BUTTON_WIDTH as i32;

            // Close button: rightmost.
            if window.style.has_close_button {
                let close_x = w - border - btn_w;
                if lx >= close_x && lx < close_x + btn_w {
                    return HitTestResult::CloseButton;
                }
            }

            // Maximize button: next to close.
            if window.style.has_maximize_button {
                let offset = if window.style.has_close_button { btn_w } else { 0 };
                let max_x = w - border - offset - btn_w;
                if lx >= max_x && lx < max_x + btn_w {
                    return HitTestResult::MaximizeButton;
                }
            }

            // Minimize button: next to maximize.
            if window.style.has_minimize_button {
                let offset = {
                    let mut o = 0i32;
                    if window.style.has_close_button { o += btn_w; }
                    if window.style.has_maximize_button { o += btn_w; }
                    o
                };
                let min_x = w - border - offset - btn_w;
                if lx >= min_x && lx < min_x + btn_w {
                    return HitTestResult::MinimizeButton;
                }
            }

            // Rest of the title bar → drag handle.
            return HitTestResult::TitleBar;
        }
    }

    // --- Client area (everything else inside the window) ---
    HitTestResult::Client
}
