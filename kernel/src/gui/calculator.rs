//! AstryxOS Calculator — A basic GUI calculator app.
//!
//! Supports:
//! - Digits 0-9, decimal point
//! - Operations: + - * /
//! - Clear (C), backspace, equals (=)
//! - Mouse-click on buttons or keyboard input
//! - Display of current expression and result

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::wm::window::{self, WindowHandle};
use crate::msg::message::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FONT_W: u32 = 8;
const FONT_H: u32 = 16;

// Button grid: 4 columns × 5 rows
const BTN_COLS: u32 = 4;
const BTN_ROWS: u32 = 5;
const BTN_W: u32 = 60;
const BTN_H: u32 = 40;
const BTN_GAP: u32 = 4;

const DISPLAY_H: u32 = 60;

// Colours
const COLOR_BG: u32 = 0xFF1A1A2E;
const COLOR_DISPLAY_BG: u32 = 0xFF0D0D1A;
const COLOR_DISPLAY_TEXT: u32 = 0xFF50C878;
const COLOR_DISPLAY_EXPR: u32 = 0xFF808080;
const COLOR_BTN_NUM: u32 = 0xFF2A2A3E;
const COLOR_BTN_OP: u32 = 0xFF3D5A80;
const COLOR_BTN_EQ: u32 = 0xFF50C878;
const COLOR_BTN_CLR: u32 = 0xFFCC4444;
const COLOR_BTN_TEXT: u32 = 0xFFE0E0E0;
const COLOR_BTN_HOVER: u32 = 0xFF3A3A50;

// ---------------------------------------------------------------------------
// Calculator state
// ---------------------------------------------------------------------------

struct CalcState {
    handle: WindowHandle,
    /// Current display value (what user is typing).
    display: String,
    /// Expression shown above display.
    expression: String,
    /// Accumulator from previous operations.
    accumulator: f64,
    /// Pending operator (+, -, *, /).
    pending_op: Option<char>,
    /// Whether the display shows a result (next digit replaces it).
    show_result: bool,
}

static CALC_STATE: spin::Mutex<Option<CalcState>> = spin::Mutex::new(None);

/// Button labels in row-major order (top to bottom, left to right).
const BUTTON_LABELS: [&str; 20] = [
    "C",  "(", ")", "/",
    "7",  "8", "9", "*",
    "4",  "5", "6", "-",
    "1",  "2", "3", "+",
    "0",  ".", "←", "=",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the calculator in the given window.
pub fn init(handle: WindowHandle) {
    let state = CalcState {
        handle,
        display: String::from("0"),
        expression: String::new(),
        accumulator: 0.0,
        pending_op: None,
        show_result: false,
    };
    *CALC_STATE.lock() = Some(state);
    render(handle);
}

/// Handle a keyboard event for the calculator.
pub fn handle_key(msg_type: u32, wparam: u64, _lparam: u64) {
    if msg_type != WM_KEYDOWN { return; }

    let key = wparam as u8 as char;
    process_input(key);
}

/// Handle a mouse click on the calculator at client coordinates.
pub fn handle_click(cx: i32, cy: i32) {
    // Check if click is in the button grid area.
    let grid_y_start = DISPLAY_H as i32 + 8;
    let grid_x_start = 8i32;

    if cy < grid_y_start || cx < grid_x_start { return; }

    let rel_x = (cx - grid_x_start) as u32;
    let rel_y = (cy - grid_y_start) as u32;

    let cell_w = BTN_W + BTN_GAP;
    let cell_h = BTN_H + BTN_GAP;

    let col = rel_x / cell_w;
    let row = rel_y / cell_h;

    if col >= BTN_COLS || row >= BTN_ROWS { return; }

    // Check we're actually inside the button (not the gap)
    if rel_x % cell_w >= BTN_W || rel_y % cell_h >= BTN_H { return; }

    let idx = (row * BTN_COLS + col) as usize;
    if idx >= BUTTON_LABELS.len() { return; }

    let label = BUTTON_LABELS[idx];
    let ch = match label {
        "C" => 'C',
        "←" => '\x08', // backspace
        "=" => '=',
        "+" => '+',
        "-" => '-',
        "*" => '*',
        "/" => '/',
        "(" => '(',
        ")" => ')',
        "." => '.',
        _ => label.chars().next().unwrap_or('0'),
    };

    process_input(ch);
}

/// Return the calculator handle if initialized.
pub fn calc_handle() -> Option<WindowHandle> {
    CALC_STATE.lock().as_ref().map(|s| s.handle)
}

/// Re-render the calculator surface (called after WM_SIZE / maximize).
pub fn re_render() {
    let handle = match CALC_STATE.lock().as_ref().map(|s| s.handle) {
        Some(h) => h,
        None => return,
    };
    render(handle);
}

// ---------------------------------------------------------------------------
// Input processing
// ---------------------------------------------------------------------------

fn process_input(ch: char) {
    let mut state_guard = CALC_STATE.lock();
    let state = match state_guard.as_mut() {
        Some(s) => s,
        None => return,
    };
    let handle = state.handle;

    match ch {
        '0'..='9' => {
            if state.show_result {
                state.display.clear();
                state.show_result = false;
            }
            if state.display == "0" {
                state.display.clear();
            }
            state.display.push(ch);
        }
        '.' => {
            if state.show_result {
                state.display = String::from("0");
                state.show_result = false;
            }
            if !state.display.contains('.') {
                if state.display.is_empty() {
                    state.display.push('0');
                }
                state.display.push('.');
            }
        }
        '+' | '-' | '*' | '/' => {
            // Apply pending operation first.
            apply_pending(state);
            state.pending_op = Some(ch);
            let val_str = format_display(&state.display);
            state.expression = alloc::format!("{} {} ", val_str, ch);
            state.show_result = true;
        }
        '=' => {
            apply_pending(state);
            state.expression.clear();
            state.pending_op = None;
            state.show_result = true;
        }
        'C' | 'c' => {
            state.display = String::from("0");
            state.expression.clear();
            state.accumulator = 0.0;
            state.pending_op = None;
            state.show_result = false;
        }
        '\x08' => {
            // Backspace
            if !state.show_result && !state.display.is_empty() {
                state.display.pop();
                if state.display.is_empty() {
                    state.display.push('0');
                }
            }
        }
        _ => {}
    }

    drop(state_guard);
    render(handle);
}

fn apply_pending(state: &mut CalcState) {
    let current: f64 = parse_display(&state.display);

    if let Some(op) = state.pending_op {
        state.accumulator = match op {
            '+' => state.accumulator + current,
            '-' => state.accumulator - current,
            '*' => state.accumulator * current,
            '/' => {
                if current != 0.0 { state.accumulator / current }
                else { f64::INFINITY }
            }
            _ => current,
        };
    } else {
        state.accumulator = current;
    }

    state.display = format_display_f64(state.accumulator);
}

fn parse_display(s: &str) -> f64 {
    // Simple manual float parser (no std)
    if s.is_empty() || s == "-" { return 0.0; }

    let negative = s.starts_with('-');
    let s = if negative { &s[1..] } else { s };

    let mut integer_part: f64 = 0.0;
    let mut frac_part: f64 = 0.0;
    let mut frac_div: f64 = 1.0;
    let mut in_frac = false;

    for ch in s.chars() {
        if ch == '.' {
            in_frac = true;
            continue;
        }
        if let Some(d) = ch.to_digit(10) {
            if in_frac {
                frac_div *= 10.0;
                frac_part += d as f64 / frac_div;
            } else {
                integer_part = integer_part * 10.0 + d as f64;
            }
        }
    }

    let result = integer_part + frac_part;
    if negative { -result } else { result }
}

fn format_display(s: &str) -> String {
    if s.is_empty() { String::from("0") } else { String::from(s) }
}

fn format_display_f64(val: f64) -> String {
    if val == f64::INFINITY { return String::from("Inf"); }
    if val == f64::NEG_INFINITY { return String::from("-Inf"); }
    if val != val { return String::from("NaN"); } // NaN check

    // Format with up to 8 decimal places, strip trailing zeros.
    let negative = val < 0.0;
    let abs_val = if negative { -val } else { val };

    let integer = abs_val as u64;
    let frac = abs_val - integer as f64;

    let mut result = if negative {
        alloc::format!("-{}", integer)
    } else {
        alloc::format!("{}", integer)
    };

    if frac > 0.000000001 {
        result.push('.');
        let mut f = frac;
        for _ in 0..8 {
            f *= 10.0;
            let d = f as u64 % 10;
            result.push((b'0' + d as u8) as char);
            if (f - (f as u64 as f64)) < 0.000000001 { break; }
        }
        // Strip trailing zeros after decimal point
        while result.ends_with('0') {
            result.pop();
        }
        if result.ends_with('.') {
            result.pop();
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render(handle: WindowHandle) {
    let (cw, ch) = match window::with_window(handle, |w| (w.client_width, w.client_height)) {
        Some(d) => d,
        None => return,
    };

    let stride = cw;
    let mut surface = vec![COLOR_BG; (cw * ch) as usize];

    let state_guard = CALC_STATE.lock();
    let state = match state_guard.as_ref() {
        Some(s) => s,
        None => return,
    };

    // Display area
    draw_filled_rect(&mut surface, stride, 4, 4, cw - 8, DISPLAY_H - 8, COLOR_DISPLAY_BG);

    // Expression (small, gray)
    if !state.expression.is_empty() {
        draw_text(&mut surface, stride, 12, 8, &state.expression, COLOR_DISPLAY_EXPR, 30);
    }

    // Current value (large — 2x scale simulated by drawing twice)
    let display_y = (DISPLAY_H as i32 - FONT_H as i32) / 2 + 6;
    let display_str = &state.display;
    // Right-align: calculate offset
    let text_px_w = display_str.len() as i32 * FONT_W as i32;
    let display_x = (cw as i32 - 12).max(0) - text_px_w;
    draw_text(&mut surface, stride, display_x, display_y, display_str, COLOR_DISPLAY_TEXT, 30);

    // Button grid
    let grid_x = 8i32;
    let grid_y = DISPLAY_H as i32 + 8;

    for row in 0..BTN_ROWS {
        for col in 0..BTN_COLS {
            let idx = (row * BTN_COLS + col) as usize;
            if idx >= BUTTON_LABELS.len() { continue; }

            let label = BUTTON_LABELS[idx];
            let bx = grid_x + (col * (BTN_W + BTN_GAP)) as i32;
            let by = grid_y + (row * (BTN_H + BTN_GAP)) as i32;

            let btn_color = match label {
                "C" => COLOR_BTN_CLR,
                "=" => COLOR_BTN_EQ,
                "+" | "-" | "*" | "/" | "(" | ")" => COLOR_BTN_OP,
                _ => COLOR_BTN_NUM,
            };

            // Button background with rounded feel (just a rect for simplicity)
            draw_filled_rect(&mut surface, stride, bx, by, BTN_W, BTN_H, btn_color);

            // Button label centered
            let label_px_w = label.len() as i32 * FONT_W as i32;
            let lx = bx + (BTN_W as i32 - label_px_w) / 2;
            let ly = by + (BTN_H as i32 - FONT_H as i32) / 2;
            draw_text(&mut surface, stride, lx, ly, label, COLOR_BTN_TEXT, 4);
        }
    }

    drop(state_guard);

    window::with_window_mut(handle, |w| {
        w.surface = surface;
    });
}

// ---------------------------------------------------------------------------
// Drawing helpers
// ---------------------------------------------------------------------------

fn draw_text(buf: &mut [u32], stride: u32, x: i32, y: i32, text: &str, color: u32, max_chars: usize) {
    let mut cx = x;
    for (i, ch) in text.chars().enumerate() {
        if i >= max_chars { break; }
        if ch == '\n' || ch == '\r' { continue; }
        draw_char(buf, stride, cx, y, ch, color);
        cx += FONT_W as i32;
    }
}

fn draw_char(buf: &mut [u32], stride: u32, x: i32, y: i32, ch: char, color: u32) {
    let c = ch as u32;
    if c < 0x20 || c > 0x7E { return; }
    let glyph_offset = ((c - 0x20) as usize) * 16;
    let font = &crate::gui::compositor::VGA_FONT_8X16;

    for row in 0..16i32 {
        let py = y + row;
        if py < 0 { continue; }
        let byte = font[glyph_offset + row as usize];
        for col in 0..8i32 {
            let px = x + col;
            if px < 0 || px >= stride as i32 { continue; }
            if (byte >> (7 - col)) & 1 != 0 {
                let idx = py as usize * stride as usize + px as usize;
                if idx < buf.len() {
                    buf[idx] = color;
                }
            }
        }
    }
}

fn draw_filled_rect(buf: &mut [u32], stride: u32, x: i32, y: i32, w: u32, h: u32, color: u32) {
    for row in 0..h as i32 {
        let py = y + row;
        if py < 0 { continue; }
        for col in 0..w as i32 {
            let px = x + col;
            if px < 0 || px >= stride as i32 { continue; }
            let idx = py as usize * stride as usize + px as usize;
            if idx < buf.len() {
                buf[idx] = color;
            }
        }
    }
}
