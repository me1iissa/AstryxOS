//! Unified Compositor — Reads from the WM subsystem and composites to the
//! hardware framebuffer (VMware SVGA II, 1920×1080×32bpp default).
//!
//! Replaces the old legacy compositor in `gui/mod.rs`.  All drawing is
//! performed into a backbuffer and then blitted to the hardware FB in one
//! pass per frame.

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// True when the desktop compositor owns the framebuffer.
/// When active, the TTY console should NOT write directly to the FB.
static COMPOSITOR_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Check if the compositor is active (desktop mode).
pub fn is_active() -> bool {
    COMPOSITOR_ACTIVE.load(Ordering::Relaxed)
}

use crate::wm::decorator;
use crate::wm::window::{WindowHandle, WindowState, WindowStyle};

// ---------------------------------------------------------------------------
// Geometry / colour constants
// ---------------------------------------------------------------------------

const TITLE_BAR_HEIGHT: u32 = decorator::TITLE_BAR_HEIGHT;
const BORDER_WIDTH: u32 = decorator::BORDER_WIDTH;
const BUTTON_WIDTH: u32 = decorator::BUTTON_WIDTH;

const COLOR_TITLE_BAR_ACTIVE: u32 = decorator::COLOR_TITLE_BAR_ACTIVE;
const COLOR_TITLE_BAR_INACTIVE: u32 = decorator::COLOR_TITLE_BAR_INACTIVE;
const COLOR_TITLE_TEXT_ACTIVE: u32 = decorator::COLOR_TITLE_TEXT_ACTIVE;
const COLOR_TITLE_TEXT_INACTIVE: u32 = decorator::COLOR_TITLE_TEXT_INACTIVE;
const COLOR_BORDER_ACTIVE: u32 = decorator::COLOR_BORDER_ACTIVE;
const COLOR_BORDER_INACTIVE: u32 = decorator::COLOR_BORDER_INACTIVE;
const COLOR_CLOSE_HOVER: u32 = decorator::COLOR_CLOSE_HOVER;

const COLOR_CURSOR: u32 = 0xFFFFFFFF;
const COLOR_CURSOR_BORDER: u32 = 0xFF000000;

/// Font glyph width in pixels.
const FONT_WIDTH: u32 = 8;
/// Font glyph height in pixels.
const FONT_HEIGHT: u32 = 16;

// ---------------------------------------------------------------------------
// Embedded 8×16 VGA bitmap font (printable ASCII 0x20–0x7E, 95 glyphs)
// ---------------------------------------------------------------------------

#[rustfmt::skip]
pub static VGA_FONT_8X16: [u8; 95 * 16] = [
    // 0x20  ' '
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x21  '!'
    0x00, 0x00, 0x18, 0x3C, 0x3C, 0x3C, 0x18, 0x18,
    0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00,
    // 0x22  '"'
    0x00, 0x66, 0x66, 0x66, 0x24, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x23  '#'
    0x00, 0x00, 0x00, 0x6C, 0x6C, 0xFE, 0x6C, 0x6C,
    0x6C, 0xFE, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00,
    // 0x24  '$'
    0x18, 0x18, 0x7C, 0xC6, 0xC2, 0xC0, 0x7C, 0x06,
    0x06, 0x86, 0xC6, 0x7C, 0x18, 0x18, 0x00, 0x00,
    // 0x25  '%'
    0x00, 0x00, 0x00, 0x00, 0xC2, 0xC6, 0x0C, 0x18,
    0x30, 0x60, 0xC6, 0x86, 0x00, 0x00, 0x00, 0x00,
    // 0x26  '&'
    0x00, 0x00, 0x38, 0x6C, 0x6C, 0x38, 0x76, 0xDC,
    0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00,
    // 0x27  "'"
    0x00, 0x30, 0x30, 0x30, 0x60, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x28  '('
    0x00, 0x00, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00,
    // 0x29  ')'
    0x00, 0x00, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00,
    // 0x2A  '*'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x3C, 0xFF,
    0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x2B  '+'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x7E,
    0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x2C  ','
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x18, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00,
    // 0x2D  '-'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x2E  '.'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00,
    // 0x2F  '/'
    0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x0C, 0x18,
    0x30, 0x60, 0xC0, 0x80, 0x00, 0x00, 0x00, 0x00,
    // 0x30  '0'
    0x00, 0x00, 0x38, 0x6C, 0xC6, 0xC6, 0xD6, 0xD6,
    0xC6, 0xC6, 0x6C, 0x38, 0x00, 0x00, 0x00, 0x00,
    // 0x31  '1'
    0x00, 0x00, 0x18, 0x38, 0x78, 0x18, 0x18, 0x18,
    0x18, 0x18, 0x18, 0x7E, 0x00, 0x00, 0x00, 0x00,
    // 0x32  '2'
    0x00, 0x00, 0x7C, 0xC6, 0x06, 0x0C, 0x18, 0x30,
    0x60, 0xC0, 0xC6, 0xFE, 0x00, 0x00, 0x00, 0x00,
    // 0x33  '3'
    0x00, 0x00, 0x7C, 0xC6, 0x06, 0x06, 0x3C, 0x06,
    0x06, 0x06, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x34  '4'
    0x00, 0x00, 0x0C, 0x1C, 0x3C, 0x6C, 0xCC, 0xFE,
    0x0C, 0x0C, 0x0C, 0x1E, 0x00, 0x00, 0x00, 0x00,
    // 0x35  '5'
    0x00, 0x00, 0xFE, 0xC0, 0xC0, 0xC0, 0xFC, 0x06,
    0x06, 0x06, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x36  '6'
    0x00, 0x00, 0x38, 0x60, 0xC0, 0xC0, 0xFC, 0xC6,
    0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x37  '7'
    0x00, 0x00, 0xFE, 0xC6, 0x06, 0x06, 0x0C, 0x18,
    0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00,
    // 0x38  '8'
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7C, 0xC6,
    0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x39  '9'
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7E, 0x06,
    0x06, 0x06, 0x0C, 0x78, 0x00, 0x00, 0x00, 0x00,
    // 0x3A  ':'
    0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00,
    0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x3B  ';'
    0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00,
    0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00,
    // 0x3C  '<'
    0x00, 0x00, 0x00, 0x06, 0x0C, 0x18, 0x30, 0x60,
    0x30, 0x18, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00,
    // 0x3D  '='
    0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00,
    0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x3E  '>'
    0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x0C, 0x06,
    0x0C, 0x18, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00,
    // 0x3F  '?'
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0x0C, 0x18, 0x18,
    0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00,
    // 0x40  '@'
    0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xDE, 0xDE,
    0xDE, 0xDC, 0xC0, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x41  'A'
    0x00, 0x00, 0x10, 0x38, 0x6C, 0xC6, 0xC6, 0xFE,
    0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00,
    // 0x42  'B'
    0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x66,
    0x66, 0x66, 0x66, 0xFC, 0x00, 0x00, 0x00, 0x00,
    // 0x43  'C'
    0x00, 0x00, 0x3C, 0x66, 0xC2, 0xC0, 0xC0, 0xC0,
    0xC0, 0xC2, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00,
    // 0x44  'D'
    0x00, 0x00, 0xF8, 0x6C, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x6C, 0xF8, 0x00, 0x00, 0x00, 0x00,
    // 0x45  'E'
    0x00, 0x00, 0xFE, 0x66, 0x62, 0x68, 0x78, 0x68,
    0x60, 0x62, 0x66, 0xFE, 0x00, 0x00, 0x00, 0x00,
    // 0x46  'F'
    0x00, 0x00, 0xFE, 0x66, 0x62, 0x68, 0x78, 0x68,
    0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00, 0x00,
    // 0x47  'G'
    0x00, 0x00, 0x3C, 0x66, 0xC2, 0xC0, 0xC0, 0xDE,
    0xC6, 0xC6, 0x66, 0x3A, 0x00, 0x00, 0x00, 0x00,
    // 0x48  'H'
    0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xFE, 0xC6,
    0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00,
    // 0x49  'I'
    0x00, 0x00, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18,
    0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00,
    // 0x4A  'J'
    0x00, 0x00, 0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0xCC, 0xCC, 0xCC, 0x78, 0x00, 0x00, 0x00, 0x00,
    // 0x4B  'K'
    0x00, 0x00, 0xE6, 0x66, 0x6C, 0x6C, 0x78, 0x78,
    0x6C, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00, 0x00,
    // 0x4C  'L'
    0x00, 0x00, 0xF0, 0x60, 0x60, 0x60, 0x60, 0x60,
    0x60, 0x62, 0x66, 0xFE, 0x00, 0x00, 0x00, 0x00,
    // 0x4D  'M'
    0x00, 0x00, 0xC6, 0xEE, 0xFE, 0xFE, 0xD6, 0xC6,
    0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00,
    // 0x4E  'N'
    0x00, 0x00, 0xC6, 0xE6, 0xF6, 0xFE, 0xDE, 0xCE,
    0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00,
    // 0x4F  'O'
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6,
    0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x50  'P'
    0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x60,
    0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00, 0x00,
    // 0x51  'Q'
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6,
    0xC6, 0xD6, 0xDE, 0x7C, 0x0C, 0x0E, 0x00, 0x00,
    // 0x52  'R'
    0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x6C,
    0x66, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00, 0x00,
    // 0x53  'S'
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0x60, 0x38, 0x0C,
    0x06, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x54  'T'
    0x00, 0x00, 0xFF, 0xDB, 0x99, 0x18, 0x18, 0x18,
    0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00,
    // 0x55  'U'
    0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6,
    0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x56  'V'
    0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6,
    0xC6, 0x6C, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00,
    // 0x57  'W'
    0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xD6,
    0xD6, 0xFE, 0xEE, 0x6C, 0x00, 0x00, 0x00, 0x00,
    // 0x58  'X'
    0x00, 0x00, 0xC6, 0xC6, 0x6C, 0x7C, 0x38, 0x38,
    0x7C, 0x6C, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00,
    // 0x59  'Y'
    0x00, 0x00, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x18,
    0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00,
    // 0x5A  'Z'
    0x00, 0x00, 0xFE, 0xC6, 0x86, 0x0C, 0x18, 0x30,
    0x60, 0xC2, 0xC6, 0xFE, 0x00, 0x00, 0x00, 0x00,
    // 0x5B  '['
    0x00, 0x00, 0x3C, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x3C, 0x00, 0x00, 0x00, 0x00,
    // 0x5C  '\'
    0x00, 0x00, 0x00, 0x80, 0xC0, 0xE0, 0x70, 0x38,
    0x1C, 0x0E, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00,
    // 0x5D  ']'
    0x00, 0x00, 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x3C, 0x00, 0x00, 0x00, 0x00,
    // 0x5E  '^'
    0x10, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x5F  '_'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00,
    // 0x60  '`'
    0x30, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x61  'a'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x0C, 0x7C,
    0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00,
    // 0x62  'b'
    0x00, 0x00, 0xE0, 0x60, 0x60, 0x78, 0x6C, 0x66,
    0x66, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x63  'c'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC0,
    0xC0, 0xC0, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x64  'd'
    0x00, 0x00, 0x1C, 0x0C, 0x0C, 0x3C, 0x6C, 0xCC,
    0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00,
    // 0x65  'e'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xFE,
    0xC0, 0xC0, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x66  'f'
    0x00, 0x00, 0x1C, 0x36, 0x32, 0x30, 0x78, 0x30,
    0x30, 0x30, 0x30, 0x78, 0x00, 0x00, 0x00, 0x00,
    // 0x67  'g'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xCC, 0xCC,
    0xCC, 0xCC, 0x7C, 0x0C, 0xCC, 0x78, 0x00, 0x00,
    // 0x68  'h'
    0x00, 0x00, 0xE0, 0x60, 0x60, 0x6C, 0x76, 0x66,
    0x66, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00, 0x00,
    // 0x69  'i'
    0x00, 0x00, 0x18, 0x18, 0x00, 0x38, 0x18, 0x18,
    0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00,
    // 0x6A  'j'
    0x00, 0x00, 0x06, 0x06, 0x00, 0x0E, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00,
    // 0x6B  'k'
    0x00, 0x00, 0xE0, 0x60, 0x60, 0x66, 0x6C, 0x78,
    0x78, 0x6C, 0x66, 0xE6, 0x00, 0x00, 0x00, 0x00,
    // 0x6C  'l'
    0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18,
    0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00,
    // 0x6D  'm'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0xFE, 0xD6,
    0xD6, 0xD6, 0xD6, 0xC6, 0x00, 0x00, 0x00, 0x00,
    // 0x6E  'n'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00,
    // 0x6F  'o'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC6,
    0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x70  'p'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x66, 0x66,
    0x66, 0x66, 0x7C, 0x60, 0x60, 0xF0, 0x00, 0x00,
    // 0x71  'q'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xCC, 0xCC,
    0xCC, 0xCC, 0x7C, 0x0C, 0x0C, 0x1E, 0x00, 0x00,
    // 0x72  'r'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x76, 0x66,
    0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00, 0x00,
    // 0x73  's'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0x60,
    0x38, 0x0C, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    // 0x74  't'
    0x00, 0x00, 0x10, 0x30, 0x30, 0xFC, 0x30, 0x30,
    0x30, 0x30, 0x36, 0x1C, 0x00, 0x00, 0x00, 0x00,
    // 0x75  'u'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00,
    // 0x76  'v'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xC6,
    0xC6, 0x6C, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00,
    // 0x77  'w'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xD6,
    0xD6, 0xD6, 0xFE, 0x6C, 0x00, 0x00, 0x00, 0x00,
    // 0x78  'x'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x6C, 0x38,
    0x38, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00,
    // 0x79  'y'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xC6,
    0xC6, 0xC6, 0x7E, 0x06, 0x0C, 0xF8, 0x00, 0x00,
    // 0x7A  'z'
    0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0xCC, 0x18,
    0x30, 0x60, 0xC6, 0xFE, 0x00, 0x00, 0x00, 0x00,
    // 0x7B  '{'
    0x00, 0x00, 0x0E, 0x18, 0x18, 0x18, 0x70, 0x18,
    0x18, 0x18, 0x18, 0x0E, 0x00, 0x00, 0x00, 0x00,
    // 0x7C  '|'
    0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18,
    0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00,
    // 0x7D  '}'
    0x00, 0x00, 0x70, 0x18, 0x18, 0x18, 0x0E, 0x18,
    0x18, 0x18, 0x18, 0x70, 0x00, 0x00, 0x00, 0x00,
    // 0x7E  '~'
    0x00, 0x00, 0x76, 0xDC, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ---------------------------------------------------------------------------
// 12×12 arrow cursor bitmap (same as legacy compositor)
// ---------------------------------------------------------------------------

/// 12×12 cursor bitmap: 0 = transparent, 1 = border, 2 = fill.
#[rustfmt::skip]
static CURSOR_BITMAP: [[u8; 12]; 12] = [
    [1,0,0,0,0,0,0,0,0,0,0,0],
    [1,1,0,0,0,0,0,0,0,0,0,0],
    [1,2,1,0,0,0,0,0,0,0,0,0],
    [1,2,2,1,0,0,0,0,0,0,0,0],
    [1,2,2,2,1,0,0,0,0,0,0,0],
    [1,2,2,2,2,1,0,0,0,0,0,0],
    [1,2,2,2,2,2,1,0,0,0,0,0],
    [1,2,2,2,2,2,2,1,0,0,0,0],
    [1,2,2,2,2,1,1,1,1,0,0,0],
    [1,2,2,1,2,1,0,0,0,0,0,0],
    [1,2,1,0,1,2,1,0,0,0,0,0],
    [1,1,0,0,0,1,1,0,0,0,0,0],
];

// ---------------------------------------------------------------------------
// Hardware cursor support
// ---------------------------------------------------------------------------

/// Set to `true` once the VMware SVGA hardware cursor shape has been uploaded.
/// When `true`, `compose()` uses [`vmware_svga::move_cursor`] to position the
/// hardware-composited cursor overlay instead of drawing pixels into the
/// backbuffer (which would require a full 8 MB MMIO blit to take effect).
static HARDWARE_CURSOR_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Upload the 12×12 arrow cursor shape to the VMware SVGA hardware.
///
/// Converts `CURSOR_BITMAP` into:
/// - a 1-bpp AND mask  (1 = transparent/pass-through,  0 = use XOR colour)
/// - a 32-bpp XOR mask (the actual ARGB pixels for opaque pixels)
///
/// Sets `HARDWARE_CURSOR_ACTIVE` to `true` on success so that `compose()`
/// switches to the hardware cursor path.
fn define_hardware_cursor() {
    if !crate::drivers::vmware_svga::has_cursor_support() {
        crate::serial_println!("[GUI] VMware SVGA cursor capability absent — using software cursor");
        return;
    }

    const CW: usize = 12;
    const CH: usize = 12;

    // AND mask — 1 bpp, one u32 per row, MSB = leftmost pixel.
    //   AND bit = 0: pixel is opaque (use XOR colour)
    //   AND bit = 1: pixel is transparent (show framebuffer behind)
    let mut and_mask = [0u32; CH];
    for (row_idx, row) in CURSOR_BITMAP.iter().enumerate() {
        let mut word: u32 = 0;
        for col in 0..CW {
            if row[col] == 0 {
                // transparent pixel → AND bit = 1
                word |= 1u32 << (31 - col);
            }
            // opaque pixel (1 or 2) → AND bit stays 0
        }
        and_mask[row_idx] = word;
    }

    // XOR mask — 32 bpp, one u32 per pixel (row-major).
    //   CURSOR_BITMAP 1 → black border (0x00000000)
    //   CURSOR_BITMAP 2 → white fill   (0x00FFFFFF)
    //   CURSOR_BITMAP 0 → irrelevant   (AND=1 makes it transparent)
    let mut xor_mask = [0u32; CW * CH];
    for row in 0..CH {
        for col in 0..CW {
            xor_mask[row * CW + col] = match CURSOR_BITMAP[row][col] {
                1 => 0x00000000, // black border
                2 => 0x00FFFFFF, // white fill
                _ => 0x00000000, // transparent (irrelevant)
            };
        }
    }

    crate::drivers::vmware_svga::define_cursor(
        0, 0,             // hotspot at the tip of the arrow
        CW as u16, CH as u16,
        &and_mask,
        &xor_mask,
    );

    // Hardware cursor intentionally disabled — QEMU VMware SVGA emulation does
    // not render the cursor overlay visibly. Use software cursor (draw_cursor)
    // in compose() instead, which blits the arrow directly into the backbuffer.
    // HARDWARE_CURSOR_ACTIVE remains false.
    crate::serial_println!("[GUI] VMware SVGA hardware cursor disabled — using software cursor");
}

// ---------------------------------------------------------------------------
// Window snapshot — captures all data we need without holding the WM lock
// ---------------------------------------------------------------------------

/// A snapshot of a window's state captured while the `WINDOW_REGISTRY` lock is
/// held.  Once copied out we can draw without contending on the lock.
struct WindowSnapshot {
    handle: WindowHandle,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    client_x: i32,
    client_y: i32,
    client_width: u32,
    client_height: u32,
    title: String,
    focused: bool,
    bg_color: u32,
    style: WindowStyle,
    state: WindowState,
}

// ---------------------------------------------------------------------------
// Compositor state
// ---------------------------------------------------------------------------

/// Global compositor state.
pub struct CompositorState {
    pub screen_width: u32,
    pub screen_height: u32,
    pub fb_base: u64,
    pub fb_stride: u32,
    pub backbuffer: Vec<u32>,
    pub frame_count: u64,
    /// Bounding box of dirty region this frame: (x, y, w, h).
    /// `None` means nothing dirty yet; `Some((0,0,sw,sh))` = full screen.
    pub dirty_rect: Option<(u32, u32, u32, u32)>,
}

static COMPOSITOR: Mutex<Option<CompositorState>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Pixel-level helpers (operate on raw `&mut [u32]` buffers)
// ---------------------------------------------------------------------------

/// Set a single pixel with bounds checking.
#[inline]
fn put_pixel(buf: &mut [u32], stride: u32, x: i32, y: i32, color: u32) {
    if x >= 0 && y >= 0 {
        let idx = y as usize * stride as usize + x as usize;
        if idx < buf.len() {
            buf[idx] = color;
        }
    }
}

/// Fill a rectangle on the buffer.
fn fill_rect(buf: &mut [u32], stride: u32, rx: i32, ry: i32, rw: u32, rh: u32, color: u32) {
    for row in 0..rh as i32 {
        for col in 0..rw as i32 {
            put_pixel(buf, stride, rx + col, ry + row, color);
        }
    }
}

/// Draw a horizontal line.
fn hline(buf: &mut [u32], stride: u32, x: i32, y: i32, len: u32, color: u32) {
    for i in 0..len as i32 {
        put_pixel(buf, stride, x + i, y, color);
    }
}

/// Draw a vertical line.
fn vline(buf: &mut [u32], stride: u32, x: i32, y: i32, len: u32, color: u32) {
    for i in 0..len as i32 {
        put_pixel(buf, stride, x, y + i, color);
    }
}

/// Blit a per-window surface (`src_w × src_h` pixels, tightly packed) onto
/// the compositor backbuffer at screen position `(dst_x, dst_y)`.
fn blit_surface(
    buf: &mut [u32],
    buf_stride: u32,
    dst_x: i32,
    dst_y: i32,
    src_w: u32,
    src_h: u32,
    surface: &[u32],
) {
    let expected = (src_w as usize) * (src_h as usize);
    if surface.len() < expected {
        // Surface not yet sized — skip.
        return;
    }
    for row in 0..src_h as i32 {
        let py = dst_y + row;
        if py < 0 || py >= buf.len() as i32 / buf_stride as i32 {
            continue;
        }
        for col in 0..src_w as i32 {
            let px = dst_x + col;
            if px < 0 || px >= buf_stride as i32 {
                continue;
            }
            let src_idx = row as usize * src_w as usize + col as usize;
            let dst_idx = py as usize * buf_stride as usize + px as usize;
            if dst_idx < buf.len() {
                buf[dst_idx] = surface[src_idx];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Text rendering on raw buffer
// ---------------------------------------------------------------------------

/// Draw a single 8×16 glyph onto a raw pixel buffer.
fn draw_char_on_buffer(buf: &mut [u32], stride: u32, x: i32, y: i32, ch: char, color: u32) {
    let c = ch as u32;
    if c < 0x20 || c > 0x7E {
        return;
    }
    let glyph_offset = ((c - 0x20) as usize) * 16;

    for row in 0..16i32 {
        let py = y + row;
        if py < 0 {
            continue;
        }
        let byte = VGA_FONT_8X16[glyph_offset + row as usize];
        for col in 0..8i32 {
            let px = x + col;
            if px < 0 {
                continue;
            }
            if (byte >> (7 - col)) & 1 != 0 {
                put_pixel(buf, stride, px, py, color);
            }
        }
    }
}

/// Draw a text string onto a raw pixel buffer using the embedded 8×16 font.
/// Only foreground pixels are written (transparent background).
pub fn draw_text_on_backbuffer(
    buf: &mut [u32],
    stride: u32,
    x: i32,
    y: i32,
    text: &str,
    color: u32,
) {
    let mut cx = x;
    for ch in text.chars() {
        if ch == '\n' {
            continue;
        }
        draw_char_on_buffer(buf, stride, cx, y, ch, color);
        cx += FONT_WIDTH as i32;
    }
}

// ---------------------------------------------------------------------------
// Decoration drawing (inline, avoids holding WM lock)
// ---------------------------------------------------------------------------

/// Draw the thin 1px border around a window.
fn draw_border(buf: &mut [u32], stride: u32, snap: &WindowSnapshot) {
    if !snap.style.has_border {
        return;
    }
    let color = if snap.focused { COLOR_BORDER_ACTIVE } else { COLOR_BORDER_INACTIVE };
    let x = snap.x;
    let y = snap.y;
    let w = snap.width;
    let h = snap.height;

    hline(buf, stride, x, y, w, color);
    hline(buf, stride, x, y + h as i32 - 1, w, color);
    vline(buf, stride, x, y, h, color);
    vline(buf, stride, x + w as i32 - 1, y, h, color);
}

/// Draw the close button glyph (×).
fn draw_close_button(buf: &mut [u32], stride: u32, x: i32, y: i32, _hovered: bool) {
    let bg = if _hovered { COLOR_CLOSE_HOVER } else { COLOR_TITLE_BAR_ACTIVE };
    fill_rect(buf, stride, x, y, BUTTON_WIDTH, TITLE_BAR_HEIGHT, bg);

    let glyph_size: i32 = 10;
    let cx = x + (BUTTON_WIDTH as i32 - glyph_size) / 2;
    let cy = y + (TITLE_BAR_HEIGHT as i32 - glyph_size) / 2;
    let glyph_color: u32 = 0xFFFFFFFF;

    for i in 0..glyph_size {
        put_pixel(buf, stride, cx + i, cy + i, glyph_color);
        put_pixel(buf, stride, cx + glyph_size - 1 - i, cy + i, glyph_color);
    }
}

/// Draw the minimize button glyph (horizontal dash).
fn draw_minimize_button(buf: &mut [u32], stride: u32, x: i32, y: i32, _hovered: bool) {
    let bg = if _hovered { decorator::COLOR_BUTTON_HOVER } else { COLOR_TITLE_BAR_ACTIVE };
    fill_rect(buf, stride, x, y, BUTTON_WIDTH, TITLE_BAR_HEIGHT, bg);

    let glyph_w: u32 = 10;
    let gx = x + (BUTTON_WIDTH as i32 - glyph_w as i32) / 2;
    let gy = y + TITLE_BAR_HEIGHT as i32 / 2;
    hline(buf, stride, gx, gy, glyph_w, 0xFFFFFFFF);
}

/// Draw the maximize / restore button glyph.
fn draw_maximize_button(
    buf: &mut [u32],
    stride: u32,
    x: i32,
    y: i32,
    _hovered: bool,
    maximized: bool,
) {
    let bg = if _hovered { decorator::COLOR_BUTTON_HOVER } else { COLOR_TITLE_BAR_ACTIVE };
    fill_rect(buf, stride, x, y, BUTTON_WIDTH, TITLE_BAR_HEIGHT, bg);

    let glyph_color: u32 = 0xFFFFFFFF;
    let size: i32 = 10;

    if !maximized {
        let gx = x + (BUTTON_WIDTH as i32 - size) / 2;
        let gy = y + (TITLE_BAR_HEIGHT as i32 - size) / 2;
        hline(buf, stride, gx, gy, size as u32, glyph_color);
        hline(buf, stride, gx, gy + size - 1, size as u32, glyph_color);
        vline(buf, stride, gx, gy, size as u32, glyph_color);
        vline(buf, stride, gx + size - 1, gy, size as u32, glyph_color);
    } else {
        let small = size - 2;
        let bx = x + (BUTTON_WIDTH as i32 - size) / 2 + 2;
        let by = y + (TITLE_BAR_HEIGHT as i32 - size) / 2;
        hline(buf, stride, bx, by, small as u32, glyph_color);
        hline(buf, stride, bx, by + small - 1, small as u32, glyph_color);
        vline(buf, stride, bx, by, small as u32, glyph_color);
        vline(buf, stride, bx + small - 1, by, small as u32, glyph_color);
        let fx = x + (BUTTON_WIDTH as i32 - size) / 2;
        let fy = y + (TITLE_BAR_HEIGHT as i32 - size) / 2 + 2;
        fill_rect(buf, stride, fx, fy, small as u32, small as u32, bg);
        hline(buf, stride, fx, fy, small as u32, glyph_color);
        hline(buf, stride, fx, fy + small - 1, small as u32, glyph_color);
        vline(buf, stride, fx, fy, small as u32, glyph_color);
        vline(buf, stride, fx + small - 1, fy, small as u32, glyph_color);
    }
}

/// Draw the title bar (background + caption buttons + title text).
fn draw_title_bar(buf: &mut [u32], stride: u32, snap: &WindowSnapshot) {
    if !snap.style.has_title_bar {
        return;
    }

    let active = snap.focused;
    let bg = if active { COLOR_TITLE_BAR_ACTIVE } else { COLOR_TITLE_BAR_INACTIVE };
    let text_color = if active { COLOR_TITLE_TEXT_ACTIVE } else { COLOR_TITLE_TEXT_INACTIVE };

    let border = if snap.style.has_border { BORDER_WIDTH as i32 } else { 0 };
    let bar_x = snap.x + border;
    let bar_y = snap.y + border;
    let bar_w = (snap.width as i32 - 2 * border) as u32;

    // Fill title bar background.
    fill_rect(buf, stride, bar_x, bar_y, bar_w, TITLE_BAR_HEIGHT, bg);

    // Draw title text (vertically centred in the title bar).
    if !snap.title.is_empty() {
        let text_x = bar_x + 10;
        let text_y = bar_y + (TITLE_BAR_HEIGHT as i32 - FONT_HEIGHT as i32) / 2;
        // Clamp text to avoid overwriting caption buttons.
        let max_text_pixels = bar_w as i32 - 10 - (BUTTON_WIDTH as i32 * 3) - 4;
        let max_chars = if max_text_pixels > 0 {
            (max_text_pixels / FONT_WIDTH as i32) as usize
        } else {
            0
        };
        let display: &str = if snap.title.len() <= max_chars {
            &snap.title
        } else if max_chars > 3 {
            // Truncation happens at byte level; safe for ASCII titles.
            // For non-ASCII we just draw whatever fits.
            &snap.title[..max_chars]
        } else {
            ""
        };
        draw_text_on_backbuffer(buf, stride, text_x, text_y, display, text_color);
    }

    // Caption buttons (right-aligned).
    let mut btn_x = snap.x + snap.width as i32 - border - BUTTON_WIDTH as i32;

    if snap.style.has_close_button {
        draw_close_button(buf, stride, btn_x, bar_y, false);
        btn_x -= BUTTON_WIDTH as i32;
    }
    if snap.style.has_maximize_button {
        draw_maximize_button(
            buf,
            stride,
            btn_x,
            bar_y,
            false,
            snap.state == WindowState::Maximized,
        );
        btn_x -= BUTTON_WIDTH as i32;
    }
    if snap.style.has_minimize_button {
        draw_minimize_button(buf, stride, btn_x, bar_y, false);
    }
}

/// Draw a complete window (border + title bar + surface blit) onto the
/// backbuffer.
fn draw_window(buf: &mut [u32], stride: u32, snap: &WindowSnapshot) {
    // 1. Border
    draw_border(buf, stride, snap);

    // 2. Title bar (background, buttons, text)
    draw_title_bar(buf, stride, snap);

    // 3. Client area — blit the per-window surface, or fill with bg_color
    let cx = snap.x + snap.client_x;
    let cy = snap.y + snap.client_y;

    // Read the window's surface directly from the registry (brief lock).
    let blitted = crate::wm::window::with_window(snap.handle, |w| {
        if !w.surface.is_empty() {
            let sw = w.client_width;
            let sh = w.client_height;
            blit_surface(buf, stride, cx, cy, sw, sh, &w.surface);
            true
        } else {
            false
        }
    }).unwrap_or(false);

    // Fallback: solid fill if no surface.
    if !blitted {
        fill_rect(buf, stride, cx, cy, snap.client_width, snap.client_height, snap.bg_color);
    }
}

// ---------------------------------------------------------------------------
// Mouse cursor
// ---------------------------------------------------------------------------

/// Draw the 12×12 arrow cursor at `(mx, my)`.
fn draw_cursor(buf: &mut [u32], stride: u32, screen_w: u32, screen_h: u32, mx: i32, my: i32) {
    for dy in 0..12i32 {
        for dx in 0..12i32 {
            let px = mx + dx;
            let py = my + dy;
            if px >= 0 && px < screen_w as i32 && py >= 0 && py < screen_h as i32 {
                let c = CURSOR_BITMAP[dy as usize][dx as usize];
                if c == 1 {
                    put_pixel(buf, stride, px, py, COLOR_CURSOR_BORDER);
                } else if c == 2 {
                    put_pixel(buf, stride, px, py, COLOR_CURSOR);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialise the compositor.
///
/// `fb_base` is the physical address of the hardware framebuffer mapped into
/// the kernel's address space.  `stride` is the number of **pixels** per
/// scanline (may be wider than `width` due to hardware alignment).
pub fn init(fb_base: u64, width: u32, height: u32, stride: u32) {
    let buf_size = (width as usize) * (height as usize);
    let state = CompositorState {
        screen_width: width,
        screen_height: height,
        fb_base,
        fb_stride: stride,
        backbuffer: vec![0u32; buf_size],
        frame_count: 0,
        dirty_rect: Some((0, 0, width, height)), // initial frame: full dirty
    };
    *COMPOSITOR.lock() = Some(state);
    crate::serial_println!(
        "[GUI] Compositor initialized ({}x{}, stride={}, fb=0x{:X})",
        width,
        height,
        stride,
        fb_base,
    );

    // Upload the hardware cursor shape to the SVGA device so the cursor can
    // be moved via FIFO bypass registers instead of re-blitting the whole screen.
    define_hardware_cursor();
}

/// Main compositing entry point — call once per frame.
///
/// 1. Fills the backbuffer with the desktop background colour.
/// 2. Iterates over windows in z-order (back → front), collecting a snapshot
///    of each visible, non-minimized window and drawing it.
/// 3. Draws the mouse cursor.
/// 4. Blits the backbuffer to the hardware framebuffer.
pub fn compose() {
    // Mark compositor as active — disables TTY console framebuffer writes.
    COMPOSITOR_ACTIVE.store(true, Ordering::Relaxed);

    let mut guard = COMPOSITOR.lock();
    let comp = match guard.as_mut() {
        Some(c) => c,
        None => return,
    };

    let sw = comp.screen_width;
    let sh = comp.screen_height;
    let stride = sw; // backbuffer is tightly packed

    // --- 1. Desktop background (subtle gradient) ---
    // Top: deep navy (0xFF0A0A20) → Bottom: dark teal (0xFF0D1B2A)
    let top_r: u32 = 0x0A; let top_g: u32 = 0x0A; let top_b: u32 = 0x20;
    let bot_r: u32 = 0x0D; let bot_g: u32 = 0x1B; let bot_b: u32 = 0x2A;
    for y in 0..sh {
        let r = top_r + (bot_r.wrapping_sub(top_r)) * y / sh.max(1);
        let g = top_g + (bot_g.wrapping_sub(top_g)) * y / sh.max(1);
        let b = top_b + (bot_b.wrapping_sub(top_b)) * y / sh.max(1);
        let color = 0xFF000000 | (r << 16) | (g << 8) | b;
        let row_start = (y * stride) as usize;
        let row_end = row_start + sw as usize;
        if row_end <= comp.backbuffer.len() {
            comp.backbuffer[row_start..row_end].fill(color);
        }
    }
    // Full screen is dirty (background covers entire frame).
    expand_dirty(comp, 0, 0, sw, sh);

    // --- 2. Windows (back-to-front) ---
    let z_order: Vec<WindowHandle> = crate::wm::zorder::get_z_order();

    for &handle in z_order.iter() {
        // Snapshot the window data (briefly locks WINDOW_REGISTRY, then releases).
        let snap = crate::wm::window::with_window(handle, |w| WindowSnapshot {
            handle: w.handle,
            x: w.x,
            y: w.y,
            width: w.width,
            height: w.height,
            client_x: w.client_x,
            client_y: w.client_y,
            client_width: w.client_width,
            client_height: w.client_height,
            title: w.title.clone(),
            focused: w.focused,
            bg_color: w.bg_color,
            style: w.style,
            state: w.state,
        });

        let snap = match snap {
            Some(s) => s,
            None => continue,
        };

        // Skip invisible or minimized windows.
        if !snap.style.visible || snap.state == WindowState::Minimized {
            continue;
        }

        // Trivial off-screen rejection.
        if snap.x + (snap.width as i32) <= 0
            || snap.y + (snap.height as i32) <= 0
            || snap.x >= sw as i32
            || snap.y >= sh as i32
        {
            continue;
        }

        draw_window(&mut comp.backbuffer, stride, &snap);
        // Mark the window's bounding box dirty.
        let wx = snap.x.max(0) as u32;
        let wy = snap.y.max(0) as u32;
        let wx2 = ((snap.x + snap.width as i32).max(0) as u32).min(sw);
        let wy2 = ((snap.y + snap.height as i32).max(0) as u32).min(sh);
        if wx2 > wx && wy2 > wy {
            expand_dirty(comp, wx, wy, wx2 - wx, wy2 - wy);
        }
    }

    // --- 2b. X11 client windows (on top of Win32 windows) ---
    // Render mapped X11 windows to the backbuffer. These are from Firefox,
    // xterm, or any other X11 client connected to our Xastryx server.
    {
        let x11_windows = crate::x11::get_mapped_windows();
        for xwin in &x11_windows {
            let wx = xwin.x as i32;
            let wy = xwin.y as i32;
            let ww = xwin.width as u32;
            let wh = xwin.height as u32;
            // Clip to screen
            let x0 = wx.max(0) as u32;
            let y0 = wy.max(0) as u32;
            let x1 = ((wx + ww as i32) as u32).min(sw);
            let y1 = ((wy + wh as i32) as u32).min(sh);
            if x1 <= x0 || y1 <= y0 { continue; }
            // Blit BGRA pixels to backbuffer
            for py in y0..y1 {
                let src_y = (py as i32 - wy) as u32;
                let dst_off = (py * stride + x0) as usize;
                let src_off = (src_y * ww + (x0 as i32 - wx) as u32) as usize;
                for px in 0..(x1 - x0) as usize {
                    let si = (src_off + px) * 4;
                    if si + 3 >= xwin.pixels.len() { break; }
                    let b = xwin.pixels[si] as u32;
                    let g = xwin.pixels[si + 1] as u32;
                    let r = xwin.pixels[si + 2] as u32;
                    comp.backbuffer[dst_off + px] = 0xFF000000 | (r << 16) | (g << 8) | b;
                }
            }
            expand_dirty(comp, x0, y0, x1 - x0, y1 - y0);
        }
    }

    // --- 3. Start menu overlay (on top of all windows) ---
    if crate::gui::content::is_start_menu_open() {
        crate::gui::content::render_start_menu_to_backbuffer(
            &mut comp.backbuffer,
            sw,
            sh,
        );
    }

    // --- 4. Mouse cursor ---
    let (mx, my) = crate::drivers::mouse::position();
    if HARDWARE_CURSOR_ACTIVE.load(Ordering::Relaxed) {
        // Hardware cursor: tell the SVGA device where to composite the cursor
        // overlay.  This writes 3 u32s directly into FIFO bypass registers —
        // no backbuffer modification, no MMIO blit required.
        crate::drivers::vmware_svga::move_cursor(mx as u32, my as u32);
    } else {
        // Software fallback: paint the cursor into the backbuffer.  The
        // upcoming blit will copy it to VRAM along with everything else.
        draw_cursor(&mut comp.backbuffer, stride, sw, sh, mx, my);
    }

    // --- 5. Blit to screen ---
    blit_to_screen(comp);

    // --- 6. Frame counter ---
    comp.frame_count += 1;
}

/// Expand the dirty bounding box to include the given rectangle.
#[inline]
fn expand_dirty(comp: &mut CompositorState, x: u32, y: u32, w: u32, h: u32) {
    let x2 = (x + w).min(comp.screen_width);
    let y2 = (y + h).min(comp.screen_height);
    let x = x.min(comp.screen_width);
    let y = y.min(comp.screen_height);
    if x2 <= x || y2 <= y { return; }
    comp.dirty_rect = Some(match comp.dirty_rect {
        None => (x, y, x2 - x, y2 - y),
        Some((dx, dy, dw, dh)) => {
            let nx = x.min(dx);
            let ny = y.min(dy);
            let nx2 = x2.max(dx + dw);
            let ny2 = y2.max(dy + dh);
            (nx, ny, nx2 - nx, ny2 - ny)
        }
    });
}

/// Copy the backbuffer to the hardware framebuffer.
/// Only blits the dirty region (or the full screen if dirty_rect covers it),
/// then issues a targeted SVGA_CMD_UPDATE for that rectangle.
fn blit_to_screen(comp: &mut CompositorState) {
    let (dx, dy, dw, dh) = match comp.dirty_rect.take() {
        Some(r) => r,
        None => return, // nothing changed
    };

    let fb = comp.fb_base as *mut u32;
    let hw_stride = comp.fb_stride;
    let w = comp.screen_width;

    // Blit only the dirty rows.
    for row_idx in dy..(dy + dh) {
        let src_row_start = (row_idx * w + dx) as usize;
        let dst_row_start = (row_idx * hw_stride + dx) as usize;
        let pixels = dw as usize;
        let src = &comp.backbuffer[src_row_start..src_row_start + pixels];
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), fb.add(dst_row_start), pixels);
        }
    }

    crate::drivers::vmware_svga::update_rect(dx, dy, dw, dh);
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

/// Mark a screen rectangle as dirty so it will be re-blitted this frame.
///
/// Called by external code (e.g. the X11 server) when window pixel data
/// has changed and the hardware framebuffer needs to be refreshed.
pub fn mark_dirty(x: u32, y: u32, w: u32, h: u32) {
    let mut guard = COMPOSITOR.lock();
    if let Some(comp) = guard.as_mut() {
        expand_dirty(comp, x, y, w, h);
    }
}

/// Fill a solid rectangle in the backbuffer. `color` is 0x00RRGGBB.
/// Clipped to the screen bounds. Marks the region dirty.
/// Called from gdi::fill_rect_screen (X11 PolyFillRectangle path).
pub fn screen_fill_rect(x: i32, y: i32, w: i32, h: i32, color: u32) {
    let mut guard = COMPOSITOR.lock();
    let comp = match guard.as_mut() { Some(c) => c, None => return };
    let sw = comp.screen_width as i32;
    let sh = comp.screen_height as i32;
    let x0 = x.max(0); let y0 = y.max(0);
    let x1 = (x + w).min(sw); let y1 = (y + h).min(sh);
    if x0 >= x1 || y0 >= y1 { return; }
    let stride = comp.screen_width as usize;
    for ry in y0..y1 {
        for rx in x0..x1 {
            comp.backbuffer[ry as usize * stride + rx as usize] = color;
        }
    }
    expand_dirty(comp, x0 as u32, y0 as u32, (x1 - x0) as u32, (y1 - y0) as u32);
}

/// Blit a 32-bpp BGRA/XRGB pixel buffer into the backbuffer.
/// `pixels` layout: B G R X (4 bytes per pixel, left-to-right, top-to-bottom).
/// Clipped to screen bounds. Marks the region dirty.
/// Called from gdi::blit_pixels_screen (X11 PutImage path).
pub fn screen_blit_pixels(x: i32, y: i32, w: u32, h: u32, pixels: &[u8]) {
    let mut guard = COMPOSITOR.lock();
    let comp = match guard.as_mut() { Some(c) => c, None => return };
    let sw = comp.screen_width as i32;
    let sh = comp.screen_height as i32;
    let stride = comp.screen_width as usize;
    for row in 0..h {
        let dy = y + row as i32;
        if dy < 0 || dy >= sh { continue; }
        for col in 0..w {
            let dx = x + col as i32;
            if dx < 0 || dx >= sw { continue; }
            let src = ((row * w + col) * 4) as usize;
            if src + 3 >= pixels.len() { break; }
            let b = pixels[src] as u32;
            let g = pixels[src + 1] as u32;
            let r = pixels[src + 2] as u32;
            comp.backbuffer[dy as usize * stride + dx as usize] =
                (r << 16) | (g << 8) | b;
        }
    }
    let x0 = x.max(0) as u32;
    let y0 = y.max(0) as u32;
    expand_dirty(comp, x0, y0, w, h);
}

/// Draw ASCII text using the embedded 8×16 VGA bitmap font.
/// `fg`/`bg` are 0x00RRGGBB. Clipped to screen bounds. Marks region dirty.
/// Called from gdi::draw_text_screen (X11 ImageText8 path).
pub fn screen_draw_text(x: i32, y: i32, text: &str, fg: u32, bg: u32) {
    let mut guard = COMPOSITOR.lock();
    let comp = match guard.as_mut() { Some(c) => c, None => return };
    if text.is_empty() { return; }
    let sw = comp.screen_width as i32;
    let sh = comp.screen_height as i32;
    let stride = comp.screen_width as usize;
    let mut cx = x;
    for ch in text.chars() {
        let idx = (ch as usize).saturating_sub(0x20);
        let glyph_idx = if idx < 95 { idx } else { cx += 8; continue };
        for row in 0..16i32 {
            let py = y + row;
            if py < 0 || py >= sh { continue; }
            let bits = VGA_FONT_8X16[glyph_idx * 16 + row as usize];
            for col in 0..8i32 {
                let px = cx + col;
                if px < 0 || px >= sw { continue; }
                let color = if bits & (0x80 >> col as u8) != 0 { fg } else { bg };
                comp.backbuffer[py as usize * stride + px as usize] = color;
            }
        }
        cx += 8;
    }
    let tw = (text.len() as i32 * 8).max(0) as u32;
    expand_dirty(comp, x.max(0) as u32, y.max(0) as u32, tw, 16);
}

/// Returns `true` if the compositor has been initialised.
pub fn is_initialized() -> bool {
    COMPOSITOR.lock().is_some()
}

/// Returns the number of frames composed so far, or 0 if not initialised.
pub fn frame_count() -> u64 {
    COMPOSITOR.lock().as_ref().map_or(0, |c| c.frame_count)
}

/// Run a closure with a reference to the compositor state.
pub fn with_compositor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&CompositorState) -> R,
{
    let guard = COMPOSITOR.lock();
    guard.as_ref().map(f)
}

/// Run a closure with a mutable reference to the compositor state.
pub fn with_compositor_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut CompositorState) -> R,
{
    let mut guard = COMPOSITOR.lock();
    guard.as_mut().map(f)
}

// ---------------------------------------------------------------------------
// GUI Automated Test — pixel telemetry
// ---------------------------------------------------------------------------

/// Sample key pixels from the backbuffer and emit them to the serial port.
///
/// Each pixel line has the form:
///   `[GUITEST] pixel X Y NAME #RRGGBB`
///
/// A summary line follows:
///   `[GUITEST] width=W height=H frames=N`
///
/// Called in `gui-test` mode after the bounded desktop loop completes.
/// The Python analyser (`scripts/analyze-gui.py`) parses these lines and
/// validates them against expected colour ranges.
///
/// **Sampling strategy** (1920×1080 layout):
/// | NAME            | Coordinates   | Expected colour        | Why                        |
/// |-----------------|---------------|------------------------|----------------------------|
/// | `desktop_center`| (960, 540)    | gradient ~#0B1225      | open desktop area (mid-y)  |
/// | `desktop_top`   | (10, 10)      | top gradient #0A0A20   | top-left desktop corner    |
/// | `taskbar`       | (960, 1060)   | TASKBAR_COLOR #1A1A2E  | inside taskbar strip       |
/// | `term_title`    | (550, 215)    | active titlebar #1B1B1B| terminal window (focused)  |
/// | `expl_title`    | (400, 115)    | inactive tbar #2D2D2D  | explorer (not focused)     |
/// | `term_client`   | (550, 380)    | window interior        | terminal client area       |
#[cfg(feature = "gui-test")]
pub fn emit_pixel_telemetry() {
    let guard = COMPOSITOR.lock();
    let comp = match guard.as_ref() {
        Some(c) => c,
        None => {
            crate::serial_println!("[GUITEST] ERROR compositor not initialized");
            return;
        }
    };

    let sw = comp.screen_width;
    let sh = comp.screen_height;

    // Fixed sample points — computed once the screen dimensions are known.
    // Using concrete coordinates calibrated for the default 1920×1080 layout.
    let samples: &[(u32, u32, &str)] = &[
        (sw / 2,  sh / 2,       "desktop_center"),
        (10,      10,            "desktop_top"),
        (sw / 2,  sh - 20,      "taskbar"),
        (550,     215,           "term_title"),
        (400,     115,           "expl_title"),
        (550,     380,           "term_client"),
    ];

    for &(x, y, name) in samples {
        let idx = y as usize * sw as usize + x as usize;
        if idx < comp.backbuffer.len() {
            let pixel = comp.backbuffer[idx];
            let r = (pixel >> 16) & 0xFF;
            let g = (pixel >>  8) & 0xFF;
            let b =  pixel        & 0xFF;
            crate::serial_println!(
                "[GUITEST] pixel {} {} {} #{:02X}{:02X}{:02X}",
                x, y, name, r, g, b
            );
        }
    }

    crate::serial_println!(
        "[GUITEST] width={} height={} frames={}",
        sw, sh, comp.frame_count
    );
}
