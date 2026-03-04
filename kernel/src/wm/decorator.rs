//! Window Decorator — Draws modern flat window decorations
//!
//! All drawing is done directly to pixel slices (`&mut [u32]` ARGB buffers)
//! to avoid circular dependencies on the GDI engine.

use super::window::Window;

// ---------------------------------------------------------------------------
// Geometry constants (modern flat style)
// ---------------------------------------------------------------------------

/// Height of the title bar in pixels.
pub const TITLE_BAR_HEIGHT: u32 = 32;
/// Width of the thin window border.
pub const BORDER_WIDTH: u32 = 1;
/// Width of each caption button.
pub const BUTTON_WIDTH: u32 = 46;
/// Invisible resize grip width on each edge.
pub const RESIZE_GRIP: u32 = 4;

// ---------------------------------------------------------------------------
// Colour palette — active windows
// ---------------------------------------------------------------------------

/// Title bar background for the active window.
pub const COLOR_TITLE_BAR_ACTIVE: u32 = 0xFF1B1B1B;
/// Title text for the active window.
pub const COLOR_TITLE_TEXT_ACTIVE: u32 = 0xFFFFFFFF;
/// Thin border for the active window.
pub const COLOR_BORDER_ACTIVE: u32 = 0xFF404040;
/// Close button hover background.
pub const COLOR_CLOSE_HOVER: u32 = 0xFFE81123;
/// Other button hover background.
pub const COLOR_BUTTON_HOVER: u32 = 0xFF333333;

// ---------------------------------------------------------------------------
// Colour palette — inactive windows
// ---------------------------------------------------------------------------

/// Title bar background for an inactive window.
pub const COLOR_TITLE_BAR_INACTIVE: u32 = 0xFF2D2D2D;
/// Title text for an inactive window.
pub const COLOR_TITLE_TEXT_INACTIVE: u32 = 0xFF999999;
/// Thin border for an inactive window.
pub const COLOR_BORDER_INACTIVE: u32 = 0xFF333333;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Set a pixel in an ARGB slice, with bounds checking.
#[inline]
fn put_pixel(pixels: &mut [u32], stride: u32, x: i32, y: i32, color: u32) {
    if x >= 0 && y >= 0 {
        let idx = y as usize * stride as usize + x as usize;
        if idx < pixels.len() {
            pixels[idx] = color;
        }
    }
}

/// Fill a rectangle `(rx, ry, rw, rh)` on the surface.
fn fill_rect(
    pixels: &mut [u32],
    stride: u32,
    rx: i32,
    ry: i32,
    rw: u32,
    rh: u32,
    color: u32,
) {
    for row in 0..rh as i32 {
        for col in 0..rw as i32 {
            put_pixel(pixels, stride, rx + col, ry + row, color);
        }
    }
}

/// Draw a horizontal line.
fn hline(pixels: &mut [u32], stride: u32, x: i32, y: i32, len: u32, color: u32) {
    for i in 0..len as i32 {
        put_pixel(pixels, stride, x + i, y, color);
    }
}

/// Draw a vertical line.
fn vline(pixels: &mut [u32], stride: u32, x: i32, y: i32, len: u32, color: u32) {
    for i in 0..len as i32 {
        put_pixel(pixels, stride, x, y + i, color);
    }
}

// ---------------------------------------------------------------------------
// Public decoration drawing functions
// ---------------------------------------------------------------------------

/// Draw the full title bar for a window.
///
/// `surface_pixels` is the ARGB framebuffer, `surface_width` is the stride.
/// The title bar is drawn at the window's position `(window.x, window.y)`.
pub fn draw_title_bar(
    surface_pixels: &mut [u32],
    surface_width: u32,
    window: &Window,
    _title: &str,
) {
    if !window.style.has_title_bar {
        return;
    }

    let active = window.focused;
    let bg = if active { COLOR_TITLE_BAR_ACTIVE } else { COLOR_TITLE_BAR_INACTIVE };
    let _text_color = if active { COLOR_TITLE_TEXT_ACTIVE } else { COLOR_TITLE_TEXT_INACTIVE };

    let border = if window.style.has_border { BORDER_WIDTH as i32 } else { 0 };
    let bar_x = window.x + border;
    let bar_y = window.y + border;
    let bar_w = (window.width as i32 - 2 * border) as u32;

    // Fill title bar background.
    fill_rect(surface_pixels, surface_width, bar_x, bar_y, bar_w, TITLE_BAR_HEIGHT, bg);

    // TODO: render title text with GDI font
    // For now, draw a small colored rectangle as a placeholder indicating
    // where the title text would appear (12px high, starting 10px from left).
    let text_placeholder_color = if active { COLOR_TITLE_TEXT_ACTIVE } else { COLOR_TITLE_TEXT_INACTIVE };
    if !_title.is_empty() {
        // Placeholder: small rectangle (width proportional to title length, max 200px)
        let tw = core::cmp::min(_title.len() as u32 * 7, 200);
        let th: u32 = 12;
        let tx = bar_x + 10;
        let ty = bar_y + (TITLE_BAR_HEIGHT as i32 - th as i32) / 2;
        fill_rect(surface_pixels, surface_width, tx, ty, tw, th, text_placeholder_color);
    }

    // Draw caption buttons.
    let mut btn_x = window.x + window.width as i32 - border - BUTTON_WIDTH as i32;

    if window.style.has_close_button {
        draw_close_button(surface_pixels, surface_width, btn_x as u32, bar_y as u32, false);
        btn_x -= BUTTON_WIDTH as i32;
    }
    if window.style.has_maximize_button {
        draw_maximize_button(
            surface_pixels,
            surface_width,
            TITLE_BAR_HEIGHT,
            btn_x as u32,
            bar_y as u32,
            false,
            window.state == super::window::WindowState::Maximized,
        );
        btn_x -= BUTTON_WIDTH as i32;
    }
    if window.style.has_minimize_button {
        draw_minimize_button(surface_pixels, surface_width, btn_x as u32, bar_y as u32, false);
    }
}

/// Draw the thin border around a window.
pub fn draw_border(
    surface_pixels: &mut [u32],
    surface_width: u32,
    window: &Window,
    active: bool,
) {
    if !window.style.has_border {
        return;
    }

    let color = if active { COLOR_BORDER_ACTIVE } else { COLOR_BORDER_INACTIVE };
    let x = window.x;
    let y = window.y;
    let w = window.width;
    let h = window.height;

    // Top edge.
    hline(surface_pixels, surface_width, x, y, w, color);
    // Bottom edge.
    hline(surface_pixels, surface_width, x, y + h as i32 - 1, w, color);
    // Left edge.
    vline(surface_pixels, surface_width, x, y, h, color);
    // Right edge.
    vline(surface_pixels, surface_width, x + w as i32 - 1, y, h, color);
}

/// Draw the close button glyph (×).
///
/// The button occupies `BUTTON_WIDTH × TITLE_BAR_HEIGHT` pixels at `(x, y)`.
pub fn draw_close_button(
    surface_pixels: &mut [u32],
    surface_width: u32,
    x: u32,
    y: u32,
    hovered: bool,
) {
    let bg = if hovered { COLOR_CLOSE_HOVER } else { COLOR_TITLE_BAR_ACTIVE };
    fill_rect(surface_pixels, surface_width, x as i32, y as i32, BUTTON_WIDTH, TITLE_BAR_HEIGHT, bg);

    // Draw × glyph (two diagonal lines, roughly 10×10, centered in the button).
    let glyph_size: i32 = 10;
    let cx = x as i32 + (BUTTON_WIDTH as i32 - glyph_size) / 2;
    let cy = y as i32 + (TITLE_BAR_HEIGHT as i32 - glyph_size) / 2;
    let glyph_color: u32 = 0xFFFFFFFF;

    for i in 0..glyph_size {
        // Top-left → bottom-right diagonal.
        put_pixel(surface_pixels, surface_width, cx + i, cy + i, glyph_color);
        // Top-right → bottom-left diagonal.
        put_pixel(surface_pixels, surface_width, cx + glyph_size - 1 - i, cy + i, glyph_color);
    }
}

/// Draw the minimize button glyph (horizontal dash).
pub fn draw_minimize_button(
    surface_pixels: &mut [u32],
    surface_width: u32,
    x: u32,
    y: u32,
    hovered: bool,
) {
    let bg = if hovered { COLOR_BUTTON_HOVER } else { COLOR_TITLE_BAR_ACTIVE };
    fill_rect(surface_pixels, surface_width, x as i32, y as i32, BUTTON_WIDTH, TITLE_BAR_HEIGHT, bg);

    // Draw dash glyph (horizontal line, 10px wide, centered).
    let glyph_w: u32 = 10;
    let gx = x as i32 + (BUTTON_WIDTH as i32 - glyph_w as i32) / 2;
    let gy = y as i32 + TITLE_BAR_HEIGHT as i32 / 2;
    hline(surface_pixels, surface_width, gx, gy, glyph_w, 0xFFFFFFFF);
}

/// Draw the maximize / restore button glyph.
///
/// When `maximized` is false, draws a single rectangle outline.
/// When `maximized` is true, draws two overlapping rectangles (restore icon).
pub fn draw_maximize_button(
    surface_pixels: &mut [u32],
    surface_width: u32,
    _surface_height: u32,
    x: u32,
    y: u32,
    hovered: bool,
    maximized: bool,
) {
    let bg = if hovered { COLOR_BUTTON_HOVER } else { COLOR_TITLE_BAR_ACTIVE };
    fill_rect(surface_pixels, surface_width, x as i32, y as i32, BUTTON_WIDTH, TITLE_BAR_HEIGHT, bg);

    let glyph_color: u32 = 0xFFFFFFFF;
    let size: i32 = 10;

    if !maximized {
        // Single rectangle outline, centered.
        let gx = x as i32 + (BUTTON_WIDTH as i32 - size) / 2;
        let gy = y as i32 + (TITLE_BAR_HEIGHT as i32 - size) / 2;
        hline(surface_pixels, surface_width, gx, gy, size as u32, glyph_color);
        hline(surface_pixels, surface_width, gx, gy + size - 1, size as u32, glyph_color);
        vline(surface_pixels, surface_width, gx, gy, size as u32, glyph_color);
        vline(surface_pixels, surface_width, gx + size - 1, gy, size as u32, glyph_color);
    } else {
        // Two overlapping rectangles (restore icon).
        let small = size - 2;
        // Back rectangle (offset +2,+0).
        let bx = x as i32 + (BUTTON_WIDTH as i32 - size) / 2 + 2;
        let by = y as i32 + (TITLE_BAR_HEIGHT as i32 - size) / 2;
        hline(surface_pixels, surface_width, bx, by, small as u32, glyph_color);
        hline(surface_pixels, surface_width, bx, by + small - 1, small as u32, glyph_color);
        vline(surface_pixels, surface_width, bx, by, small as u32, glyph_color);
        vline(surface_pixels, surface_width, bx + small - 1, by, small as u32, glyph_color);
        // Front rectangle (offset +0,+2).
        let fx = x as i32 + (BUTTON_WIDTH as i32 - size) / 2;
        let fy = y as i32 + (TITLE_BAR_HEIGHT as i32 - size) / 2 + 2;
        // Fill front rect background first so it occludes the back rect.
        fill_rect(surface_pixels, surface_width, fx, fy, small as u32, small as u32, bg);
        hline(surface_pixels, surface_width, fx, fy, small as u32, glyph_color);
        hline(surface_pixels, surface_width, fx, fy + small - 1, small as u32, glyph_color);
        vline(surface_pixels, surface_width, fx, fy, small as u32, glyph_color);
        vline(surface_pixels, surface_width, fx + small - 1, fy, small as u32, glyph_color);
    }
}

/// Draw all decorations for a window (border + title bar + buttons).
///
/// Convenience wrapper that calls `draw_border`, `draw_title_bar`.
pub fn draw_decorations(
    surface_pixels: &mut [u32],
    surface_width: u32,
    window: &Window,
) {
    draw_border(surface_pixels, surface_width, window, window.focused);
    draw_title_bar(surface_pixels, surface_width, window, &window.title.clone());
}
