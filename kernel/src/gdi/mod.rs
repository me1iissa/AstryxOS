//! GDI — Graphics Device Interface
//!
//! NT-inspired graphics rendering engine providing:
//! - Surface (pixel buffer abstraction)
//! - Device Contexts (drawing state)
//! - Drawing primitives (rectangles, lines, ellipses, gradients)
//! - Text rendering (8x16 bitmap font)
//! - BitBlt operations (copy, blend, stretch)
//! - Clipping regions

extern crate alloc;

pub mod surface;
pub mod dc;
pub mod primitives;
pub mod text;
pub mod bitblt;
pub mod region;

pub use surface::Surface;
pub use dc::{DeviceContext, Pen, Brush, PenStyle, BrushStyle, Rop2, BgMode, Rect};
pub use dc::{create_dc, delete_dc, with_dc, with_dc_mut};
pub use bitblt::RasterOp;
pub use region::Region;

/// Common colors (ARGB format: 0xAARRGGBB)
pub const COLOR_TRANSPARENT: u32 = 0x00000000;
pub const COLOR_BLACK: u32 = 0xFF000000;
pub const COLOR_WHITE: u32 = 0xFFFFFFFF;
pub const COLOR_RED: u32 = 0xFFFF0000;
pub const COLOR_GREEN: u32 = 0xFF00FF00;
pub const COLOR_BLUE: u32 = 0xFF0000FF;
pub const COLOR_GRAY: u32 = 0xFFC0C0C0;
pub const COLOR_DARK_GRAY: u32 = 0xFF808080;
pub const COLOR_LIGHT_GRAY: u32 = 0xFFE0E0E0;

/// Initialize the GDI subsystem
pub fn init() {
    crate::serial_println!("[GDI] Graphics Device Interface initialized");
}

// ── X11 screen-space drawing — wired to the compositor backbuffer ─────────────
// Called from the Xastryx X11 server (PolyFillRectangle, PutImage, ImageText8).
// Delegates to gui::compositor which holds the per-frame backbuffer and tracks
// dirty rectangles for efficient hardware blit.

/// Fill a solid rectangle at screen coordinates. `color` is 0x00RRGGBB.
pub fn fill_rect_screen(x: i32, y: i32, w: i32, h: i32, color: u32) {
    crate::gui::compositor::screen_fill_rect(x, y, w, h, color);
}

/// Blit a 32-bpp BGRA/XRGB pixel buffer at screen coordinates.
pub fn blit_pixels_screen(x: i32, y: i32, w: u32, h: u32, pixels: &[u8]) {
    crate::gui::compositor::screen_blit_pixels(x, y, w, h, pixels);
}

/// Draw a UTF-8 string at screen coordinates using the 8×16 VGA font.
/// `fg`/`bg` are 0x00RRGGBB.
pub fn draw_text_screen(x: i32, y: i32, text: &str, fg: u32, bg: u32) {
    crate::gui::compositor::screen_draw_text(x, y, text, fg, bg);
}
