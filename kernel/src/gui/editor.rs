//! AstryxOS Text Editor — A minimal notepad-style text editor GUI app.
//!
//! Supports:
//! - Typing text with word wrap
//! - Backspace / Delete
//! - Enter for newlines
//! - Arrow key navigation (up/down/left/right)
//! - Visual cursor

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

const COLOR_BG: u32 = 0xFF1E1E2E;
const COLOR_TEXT: u32 = 0xFFD4D4D4;
const COLOR_CURSOR: u32 = 0xFFFFFFFF;
const COLOR_LINE_NUM_BG: u32 = 0xFF252535;
const COLOR_LINE_NUM: u32 = 0xFF606060;
const COLOR_STATUS_BG: u32 = 0xFF2D2D44;
const COLOR_STATUS_TEXT: u32 = 0xFFAABBCC;
const COLOR_TITLE_BG: u32 = 0xFF2A2A3E;
const COLOR_TITLE_TEXT: u32 = 0xFF50C878;

/// Width of the line-number gutter (4 columns).
const GUTTER_W: i32 = 4 * FONT_W as i32 + 4;

// ---------------------------------------------------------------------------
// Editor state
// ---------------------------------------------------------------------------

struct EditorState {
    /// All lines of text.
    lines: Vec<String>,
    /// Cursor line (0-based).
    cursor_row: usize,
    /// Cursor column (0-based, byte position within line).
    cursor_col: usize,
    /// Scroll offset (first visible line).
    scroll: usize,
    /// Window handle.
    handle: WindowHandle,
    /// Whether content has been modified.
    dirty: bool,
    /// Filename (if any).
    filename: String,
    /// Whether the Ctrl key is currently held.
    ctrl_held: bool,
    /// Whether the Shift key is currently held.
    shift_held: bool,
}

static EDITOR_STATE: spin::Mutex<Option<EditorState>> = spin::Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the text editor in the given window.
pub fn init(handle: WindowHandle) {
    let state = EditorState {
        lines: vec![String::new()],
        cursor_row: 0,
        cursor_col: 0,
        scroll: 0,
        handle,
        dirty: false,
        filename: String::from("untitled.txt"),
        ctrl_held: false,
        shift_held: false,
    };
    *EDITOR_STATE.lock() = Some(state);
    render(handle);
}

/// Handle a keyboard event for the editor.
pub fn handle_key(msg_type: u32, wparam: u64, _lparam: u64) {
    // VK_CONTROL
    const VK_CONTROL: u8 = 0x11;
    const VK_SHIFT: u8 = 0x10;
    const VK_S: u8 = 0x53;
    const VK_O: u8 = 0x4F;

    // Track Shift key state on both key-down and key-up
    if wparam as u8 == VK_SHIFT {
        let mut state_guard = EDITOR_STATE.lock();
        if let Some(ref mut state) = *state_guard {
            state.shift_held = msg_type == WM_KEYDOWN;
        }
        return;
    }

    // Track Ctrl key state on both key-down and key-up
    if wparam as u8 == VK_CONTROL {
        let mut state_guard = EDITOR_STATE.lock();
        if let Some(ref mut state) = *state_guard {
            state.ctrl_held = msg_type == WM_KEYDOWN;
        }
        return;
    }

    if msg_type != WM_KEYDOWN { return; }

    let mut state_guard = EDITOR_STATE.lock();
    let state = match state_guard.as_mut() {
        Some(s) => s,
        None => return,
    };
    let handle = state.handle;

    let key = wparam as u8;

    // Ctrl+S — Save file
    if state.ctrl_held && key == VK_S {
        let mut content = String::new();
        for (i, line) in state.lines.iter().enumerate() {
            if i > 0 { content.push('\n'); }
            content.push_str(line);
        }
        let path = if state.filename.is_empty() || state.filename == "untitled.txt" {
            String::from("/untitled.txt")
        } else {
            if state.filename.starts_with('/') {
                state.filename.clone()
            } else {
                let mut p = String::from("/");
                p.push_str(&state.filename);
                p
            }
        };
        // Ensure file exists, then write
        let _ = crate::vfs::create_file(&path);
        let _ = crate::vfs::write_file(&path, content.as_bytes());
        state.dirty = false;
        if state.filename == "untitled.txt" || state.filename.is_empty() {
            state.filename = path.clone();
        }
        // Update window title
        let mut title = String::from("Text Editor - ");
        title.push_str(&state.filename);
        drop(state_guard);
        window::set_window_title(handle, &title);
        render(handle);
        return;
    }

    // Ctrl+O — Open file
    if state.ctrl_held && key == VK_O {
        // Open the default file /untitled.txt or the current filename
        let path = if state.filename.starts_with('/') {
            state.filename.clone()
        } else {
            String::from("/untitled.txt")
        };
        if let Ok(data) = crate::vfs::read_file(&path) {
            // Parse file contents into lines
            state.lines.clear();
            let text = core::str::from_utf8(&data).unwrap_or("");
            if text.is_empty() {
                state.lines.push(String::new());
            } else {
                for line in text.split('\n') {
                    state.lines.push(String::from(line));
                }
            }
            state.cursor_row = 0;
            state.cursor_col = 0;
            state.scroll = 0;
            state.dirty = false;
            state.filename = path.clone();
            let mut title = String::from("Text Editor - ");
            title.push_str(&state.filename);
            drop(state_guard);
            window::set_window_title(handle, &title);
            render(handle);
        }
        return;
    }

    match key {
        // Backspace
        0x08 => {
            if state.cursor_col > 0 {
                state.cursor_col -= 1;
                state.lines[state.cursor_row].remove(state.cursor_col);
                state.dirty = true;
            } else if state.cursor_row > 0 {
                // Merge with previous line
                let current_line = state.lines.remove(state.cursor_row);
                state.cursor_row -= 1;
                state.cursor_col = state.lines[state.cursor_row].len();
                state.lines[state.cursor_row].push_str(&current_line);
                state.dirty = true;
            }
        }
        // Enter
        0x0A | 0x0D => {
            let rest = state.lines[state.cursor_row].split_off(state.cursor_col);
            state.cursor_row += 1;
            state.cursor_col = 0;
            state.lines.insert(state.cursor_row, rest);
            state.dirty = true;
        }
        // Tab → 4 spaces
        0x09 => {
            for _ in 0..4 {
                state.lines[state.cursor_row].insert(state.cursor_col, ' ');
                state.cursor_col += 1;
            }
            state.dirty = true;
        }
        // Arrow keys: Up=0x80, Down=0x81, Left=0x82, Right=0x83
        0x80 => {
            // Up
            if state.cursor_row > 0 {
                state.cursor_row -= 1;
                let line_len = state.lines[state.cursor_row].len();
                if state.cursor_col > line_len {
                    state.cursor_col = line_len;
                }
            }
        }
        0x81 => {
            // Down
            if state.cursor_row + 1 < state.lines.len() {
                state.cursor_row += 1;
                let line_len = state.lines[state.cursor_row].len();
                if state.cursor_col > line_len {
                    state.cursor_col = line_len;
                }
            }
        }
        0x82 => {
            // Left
            if state.cursor_col > 0 {
                state.cursor_col -= 1;
            } else if state.cursor_row > 0 {
                state.cursor_row -= 1;
                state.cursor_col = state.lines[state.cursor_row].len();
            }
        }
        0x83 => {
            // Right
            let line_len = state.lines[state.cursor_row].len();
            if state.cursor_col < line_len {
                state.cursor_col += 1;
            } else if state.cursor_row + 1 < state.lines.len() {
                state.cursor_row += 1;
                state.cursor_col = 0;
            }
        }
        // Delete
        0x7F => {
            let line_len = state.lines[state.cursor_row].len();
            if state.cursor_col < line_len {
                state.lines[state.cursor_row].remove(state.cursor_col);
                state.dirty = true;
            } else if state.cursor_row + 1 < state.lines.len() {
                let next_line = state.lines.remove(state.cursor_row + 1);
                state.lines[state.cursor_row].push_str(&next_line);
                state.dirty = true;
            }
        }
        // Home
        0x84 => {
            state.cursor_col = 0;
        }
        // End
        0x85 => {
            state.cursor_col = state.lines[state.cursor_row].len();
        }
        // Printable characters — translate VK code through vk_to_char
        _ => {
            if let Some(ch) = crate::msg::input::vk_to_char(key as u64, state.shift_held) {
                if ch as u32 >= 0x20 && ch as u32 <= 0x7E {
                    state.lines[state.cursor_row].insert(state.cursor_col, ch);
                    state.cursor_col += 1;
                    state.dirty = true;
                }
            }
        }
    }

    // Auto-scroll to keep cursor visible
    let (_, ch) = window::with_window(handle, |w| (w.client_width, w.client_height))
        .unwrap_or((400, 300));
    let status_h: u32 = FONT_H + 4;
    let title_h: u32 = FONT_H + 4;
    let visible_lines = ((ch - status_h - title_h) / FONT_H) as usize;

    if state.cursor_row < state.scroll {
        state.scroll = state.cursor_row;
    } else if state.cursor_row >= state.scroll + visible_lines {
        state.scroll = state.cursor_row - visible_lines + 1;
    }

    drop(state_guard);
    render(handle);
}

/// Return the editor handle if initialized.
pub fn editor_handle() -> Option<WindowHandle> {
    EDITOR_STATE.lock().as_ref().map(|s| s.handle)
}

/// Re-render the editor surface (called after WM_SIZE / maximize).
pub fn re_render() {
    let handle = match EDITOR_STATE.lock().as_ref().map(|s| s.handle) {
        Some(h) => h,
        None => return,
    };
    render(handle);
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

    let state_guard = EDITOR_STATE.lock();
    let state = match state_guard.as_ref() {
        Some(s) => s,
        None => return,
    };

    // Title bar area
    let title_h: u32 = FONT_H + 4;
    draw_filled_rect(&mut surface, stride, 0, 0, cw, title_h, COLOR_TITLE_BG);
    let title = if state.dirty {
        alloc::format!("\u{00B7} {} — Text Editor", state.filename)
    } else {
        alloc::format!("{} — Text Editor", state.filename)
    };
    draw_text(&mut surface, stride, 8, 2, &title, COLOR_TITLE_TEXT, 60);

    // Line number gutter
    let text_y_start = title_h as i32;
    let status_h: u32 = FONT_H + 4;
    let text_area_h = ch.saturating_sub(title_h + status_h);
    let visible_lines = (text_area_h / FONT_H) as usize;

    draw_filled_rect(&mut surface, stride, 0, text_y_start, GUTTER_W as u32, text_area_h, COLOR_LINE_NUM_BG);

    // Draw lines
    for vi in 0..visible_lines {
        let line_idx = state.scroll + vi;
        if line_idx >= state.lines.len() { break; }

        let y = text_y_start + (vi as u32 * FONT_H) as i32;

        // Line number
        let num_str = alloc::format!("{:>3}", line_idx + 1);
        draw_text(&mut surface, stride, 2, y, &num_str, COLOR_LINE_NUM, 4);

        // Line text
        let line = &state.lines[line_idx];
        let x = GUTTER_W + 4;
        draw_text(&mut surface, stride, x, y, line, COLOR_TEXT, 200);

        // Cursor
        if line_idx == state.cursor_row {
            let cx = GUTTER_W + 4 + (state.cursor_col as u32 * FONT_W) as i32;
            draw_filled_rect(&mut surface, stride, cx, y, 2, FONT_H, COLOR_CURSOR);
        }
    }

    // Status bar
    let status_y = (ch - status_h) as i32;
    draw_filled_rect(&mut surface, stride, 0, status_y, cw, status_h, COLOR_STATUS_BG);
    let status = alloc::format!(
        " Ln {}, Col {} | {} lines | {}",
        state.cursor_row + 1,
        state.cursor_col + 1,
        state.lines.len(),
        if state.dirty { "Modified" } else { "Saved" }
    );
    draw_text(&mut surface, stride, 4, status_y + 2, &status, COLOR_STATUS_TEXT, 80);

    drop(state_guard);

    window::with_window_mut(handle, |w| {
        w.surface = surface;
    });
}

// ---------------------------------------------------------------------------
// Drawing helpers (same interface as content.rs)
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
