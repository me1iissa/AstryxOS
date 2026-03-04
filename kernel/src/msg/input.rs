//! Input event translation — raw hardware events to WM_* messages.
//!
//! Translates PS/2 Set 1 scancodes into WM_KEYDOWN / WM_KEYUP messages and
//! mouse state deltas into WM_MOUSEMOVE / WM_*BUTTON* messages.

extern crate alloc;
use alloc::vec::Vec;

use crate::msg::message::*;

// ── Keyboard translation ───────────────────────────────────────────────────

/// Map a PS/2 Set 1 scancode to the corresponding virtual key code.
/// Returns 0 for unmapped scancodes.
fn scancode_to_vk(scancode: u8) -> u64 {
    match scancode & 0x7F {
        0x01 => VK_ESCAPE,
        0x0E => VK_BACK,
        0x0F => VK_TAB,
        0x1C => VK_RETURN,
        0x2A | 0x36 => VK_SHIFT,
        0x1D => VK_CONTROL,
        0x38 => VK_ALT,
        0x39 => VK_SPACE,
        0x48 => VK_UP,
        0x4B => VK_LEFT,
        0x4D => VK_RIGHT,
        0x50 => VK_DOWN,
        0x47 => VK_HOME,
        0x4F => VK_END,
        0x49 => VK_PAGEUP,
        0x51 => VK_PAGEDOWN,
        0x53 => VK_DELETE,
        // Function keys F1–F10
        0x3B..=0x44 => VK_F1 + (scancode & 0x7F) as u64 - 0x3B,
        0x57 => VK_F11,
        0x58 => VK_F12,
        // Number row: 0x02 = '1' … 0x0B = '0'
        0x02..=0x0B => {
            let n = scancode & 0x7F;
            if n == 0x0B {
                0x30 // '0'
            } else {
                0x30 + n as u64 - 1 // '1'–'9'
            }
        }
        // QWERTY letter keys → ASCII uppercase VK codes
        0x10 => 0x51, // Q
        0x11 => 0x57, // W
        0x12 => 0x45, // E
        0x13 => 0x52, // R
        0x14 => 0x54, // T
        0x15 => 0x59, // Y
        0x16 => 0x55, // U
        0x17 => 0x49, // I
        0x18 => 0x4F, // O
        0x19 => 0x50, // P
        0x1E => 0x41, // A
        0x1F => 0x53, // S
        0x20 => 0x44, // D
        0x21 => 0x46, // F
        0x22 => 0x47, // G
        0x23 => 0x48, // H
        0x24 => 0x4A, // J
        0x25 => 0x4B, // K
        0x26 => 0x4C, // L
        0x2C => 0x5A, // Z
        0x2D => 0x58, // X
        0x2E => 0x43, // C
        0x2F => 0x56, // V
        0x30 => 0x42, // B
        0x31 => 0x4E, // N
        0x32 => 0x4D, // M
        // Punctuation / symbol keys
        0x27 => VK_OEM_1,      // ;:
        0x0D => VK_OEM_PLUS,   // =+
        0x33 => VK_OEM_COMMA,  // ,<
        0x0C => VK_OEM_MINUS,  // -_
        0x34 => VK_OEM_PERIOD, // .>
        0x35 => VK_OEM_2,      // /?
        0x29 => VK_OEM_3,      // `~
        0x1A => VK_OEM_4,      // [{
        0x2B => VK_OEM_5,      // \|
        0x1B => VK_OEM_6,      // ]}
        0x28 => VK_OEM_7,      // '"
        _ => 0,
    }
}

/// Translate a raw PS/2 scancode into a `WM_KEYDOWN` or `WM_KEYUP` message.
///
/// `pressed` should be `true` for a make code, `false` for a break code.
/// Returns `None` for scancodes that do not map to a virtual key.
pub fn translate_scancode(scancode: u8, pressed: bool) -> Option<Message> {
    let vk = scancode_to_vk(scancode);
    if vk == 0 {
        return None;
    }

    let msg_type = if pressed { WM_KEYDOWN } else { WM_KEYUP };
    // wparam = virtual key code
    // lparam = raw scancode (extended info can be packed later)
    Some(Message::new(0, msg_type, vk, scancode as u64))
}

// ── Mouse translation ──────────────────────────────────────────────────────

/// Translate a mouse state snapshot into zero or more window messages.
///
/// * `x`, `y`           — current cursor position.
/// * `buttons`          — current button state (bit 0 = left, 1 = right, 2 = middle).
/// * `prev_buttons`     — button state from the previous snapshot.
///
/// Always emits `WM_MOUSEMOVE`; additionally emits button-down / button-up
/// messages for every button whose state has changed.
pub fn translate_mouse(x: i32, y: i32, buttons: u8, prev_buttons: u8) -> Vec<Message> {
    let mut messages = Vec::new();
    let lparam = make_lparam(x, y);

    // Build wparam flags from current button state.
    let mut wparam: u64 = 0;
    if buttons & 0x01 != 0 {
        wparam |= MK_LBUTTON;
    }
    if buttons & 0x02 != 0 {
        wparam |= MK_RBUTTON;
    }
    if buttons & 0x04 != 0 {
        wparam |= MK_MBUTTON;
    }

    // Always emit a move.
    messages.push(Message::new(0, WM_MOUSEMOVE, wparam, lparam));

    // Left button transitions.
    if buttons & 0x01 != 0 && prev_buttons & 0x01 == 0 {
        messages.push(Message::new(0, WM_LBUTTONDOWN, wparam, lparam));
    }
    if buttons & 0x01 == 0 && prev_buttons & 0x01 != 0 {
        messages.push(Message::new(0, WM_LBUTTONUP, wparam, lparam));
    }

    // Right button transitions.
    if buttons & 0x02 != 0 && prev_buttons & 0x02 == 0 {
        messages.push(Message::new(0, WM_RBUTTONDOWN, wparam, lparam));
    }
    if buttons & 0x02 == 0 && prev_buttons & 0x02 != 0 {
        messages.push(Message::new(0, WM_RBUTTONUP, wparam, lparam));
    }

    // Middle button transitions.
    if buttons & 0x04 != 0 && prev_buttons & 0x04 == 0 {
        messages.push(Message::new(0, WM_MBUTTONDOWN, wparam, lparam));
    }
    if buttons & 0x04 == 0 && prev_buttons & 0x04 != 0 {
        messages.push(Message::new(0, WM_MBUTTONUP, wparam, lparam));
    }

    messages
}

// ── Character translation ──────────────────────────────────────────────────

/// Convert a virtual key code to a basic ASCII character.
///
/// `shift` indicates whether a Shift key is held. Only a minimal ASCII
/// subset is handled; returns `None` for non-printable / unmapped keys.
pub fn vk_to_char(vk: u64, shift: bool) -> Option<char> {
    match vk {
        // Digit row: unshifted → digits, shifted → symbols
        0x30 if shift => Some(')'),
        0x31 if shift => Some('!'),
        0x32 if shift => Some('@'),
        0x33 if shift => Some('#'),
        0x34 if shift => Some('$'),
        0x35 if shift => Some('%'),
        0x36 if shift => Some('^'),
        0x37 if shift => Some('&'),
        0x38 if shift => Some('*'),
        0x39 if shift => Some('('),
        0x30..=0x39 => Some((vk as u8) as char), // '0'–'9'
        // Letters
        0x41..=0x5A => {
            let ch = if shift { vk as u8 } else { vk as u8 + 32 };
            Some(ch as char)
        }
        // Punctuation / OEM keys
        VK_OEM_1      => Some(if shift { ':' } else { ';' }),
        VK_OEM_PLUS   => Some(if shift { '+' } else { '=' }),
        VK_OEM_COMMA  => Some(if shift { '<' } else { ',' }),
        VK_OEM_MINUS  => Some(if shift { '_' } else { '-' }),
        VK_OEM_PERIOD => Some(if shift { '>' } else { '.' }),
        VK_OEM_2      => Some(if shift { '?' } else { '/' }),
        VK_OEM_3      => Some(if shift { '~' } else { '`' }),
        VK_OEM_4      => Some(if shift { '{' } else { '[' }),
        VK_OEM_5      => Some(if shift { '|' } else { '\\' }),
        VK_OEM_6      => Some(if shift { '}' } else { ']' }),
        VK_OEM_7      => Some(if shift { '"' } else { '\'' }),
        // Whitespace / control
        VK_SPACE  => Some(' '),
        VK_RETURN => Some('\n'),
        VK_TAB    => Some('\t'),
        VK_BACK   => Some('\x08'),
        _ => None,
    }
}
