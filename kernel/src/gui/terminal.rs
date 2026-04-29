//! GUI Terminal Emulator — runs Orbit shell inside a desktop window.
//!
//! This module provides a terminal emulator widget that:
//! - Renders a character grid with scrollback into a window surface
//! - Captures keyboard input and builds command lines
//! - Executes commands through the real Orbit shell (shell::GuiShellState)
//! - Captures shell output and displays it with ANSI color support

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// Set when a child exec is running so `poll_output()` skips the TERMINAL
/// mutex acquisition in the common idle case.
static EXEC_RUNNING: AtomicBool = AtomicBool::new(false);

use crate::wm::window::{self, WindowHandle};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FONT_W: u32 = 8;
const FONT_H: u32 = 16;

/// Terminal foreground/background defaults
const DEFAULT_FG: u32 = 0xFFCCCCCC;
const DEFAULT_BG: u32 = 0xFF0C0C0C;

/// ANSI 16-color palette (standard + bright), ARGB
const ANSI_COLORS: [u32; 16] = [
    0xFF000000, // 0  black
    0xFFCC0000, // 1  red
    0xFF00CC00, // 2  green
    0xFFCCCC00, // 3  yellow
    0xFF5555FF, // 4  blue
    0xFFCC00CC, // 5  magenta
    0xFF00CCCC, // 6  cyan
    0xFFCCCCCC, // 7  white
    0xFF555555, // 8  bright black (gray)
    0xFFFF5555, // 9  bright red
    0xFF55FF55, // 10 bright green
    0xFFFFFF55, // 11 bright yellow
    0xFF5555FF, // 12 bright blue
    0xFFFF55FF, // 13 bright magenta
    0xFF55FFFF, // 14 bright cyan
    0xFFFFFFFF, // 15 bright white
];

// ---------------------------------------------------------------------------
// Colored character cell
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Cell {
    ch: char,
    fg: u32,
    bg: u32,
}

impl Cell {
    fn blank() -> Self {
        Self { ch: ' ', fg: DEFAULT_FG, bg: DEFAULT_BG }
    }
}

// ---------------------------------------------------------------------------
// Terminal state
// ---------------------------------------------------------------------------

struct TerminalState {
    /// The window handle this terminal renders into.
    handle: WindowHandle,
    /// Character grid: rows of cells (scrollback + visible).
    lines: Vec<Vec<Cell>>,
    /// Number of columns that fit in the window.
    cols: usize,
    /// Number of rows that fit in the window.
    rows: usize,
    /// Current cursor row (index into `lines`).
    cursor_row: usize,
    /// Current cursor column.
    cursor_col: usize,
    /// Current text attributes for new characters.
    cur_fg: u32,
    cur_bg: u32,
    cur_bold: bool,
    /// Scroll offset (0 = bottom of scrollback visible).
    scroll_offset: usize,
    /// Input line buffer (what the user is typing).
    input: String,
    /// Cursor position within the input line.
    input_cursor: usize,
    /// Whether Shift is currently held.
    shift_held: bool,
    /// Whether Ctrl is currently held.
    ctrl_held: bool,
    /// The Orbit shell state (cwd, history, etc.).
    shell: crate::shell::GuiShellState,
    /// ANSI escape sequence parser state.
    esc_state: EscState,
    esc_buf: [u8; 32],
    esc_len: usize,
    /// Running async child process (pid, pipe read-end id).
    /// Set when `exec` is dispatched asynchronously; cleared on child exit.
    running_exec: Option<(u64, u64)>,
}

#[derive(Clone, Copy, PartialEq)]
enum EscState {
    Normal,
    Escape,     // just saw \x1b
    Csi,        // saw \x1b[
}

static TERMINAL: Mutex<Option<TerminalState>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the terminal emulator for the given window.
pub fn init(handle: WindowHandle) {
    let (cw, ch) = match window::with_window(handle, |w| (w.client_width, w.client_height)) {
        Some(d) => d,
        None => return,
    };

    let cols = (cw / FONT_W) as usize;
    let rows = (ch / FONT_H) as usize;
    if cols == 0 || rows == 0 { return; }

    let mut state = TerminalState {
        handle,
        lines: vec![vec![Cell::blank(); cols]],
        cols,
        rows,
        cursor_row: 0,
        cursor_col: 0,
        cur_fg: DEFAULT_FG,
        cur_bg: DEFAULT_BG,
        cur_bold: false,
        scroll_offset: 0,
        input: String::new(),
        input_cursor: 0,
        shift_held: false,
        ctrl_held: false,
        shell: crate::shell::GuiShellState::new(),
        esc_state: EscState::Normal,
        esc_buf: [0u8; 32],
        esc_len: 0,
        running_exec: None,
    };

    // Write welcome banner
    state.write_str_colored("Orbit Shell v0.2", ANSI_COLORS[14]); // bright cyan
    state.write_str_colored(" — AstryxOS\n", DEFAULT_FG);
    state.write_str_colored("Type 'help' for available commands.\n\n", ANSI_COLORS[6]);

    // Draw initial prompt
    state.draw_prompt();

    // Render to surface
    state.render_to_surface();

    *TERMINAL.lock() = Some(state);
}

/// Get the window handle of the terminal (if initialized).
pub fn terminal_handle() -> Option<WindowHandle> {
    TERMINAL.lock().as_ref().map(|s| s.handle)
}

/// Re-render the terminal surface (called after WM_SIZE / maximize).
pub fn re_render() {
    let mut guard = TERMINAL.lock();
    if let Some(ref mut state) = *guard {
        // Recalculate grid dimensions from the (possibly resized) window.
        let (cw, ch) = match window::with_window(state.handle, |w| {
            (w.client_width, w.client_height)
        }) {
            Some(d) => d,
            None => return,
        };

        let new_cols = (cw / FONT_W) as usize;
        let new_rows = (ch / FONT_H) as usize;
        if new_cols == 0 || new_rows == 0 { return; }

        // If grid dimensions changed, resize existing lines & update state.
        if new_cols != state.cols {
            for line in state.lines.iter_mut() {
                line.resize(new_cols, Cell::blank());
            }
        }
        state.cols = new_cols;
        state.rows = new_rows;

        state.render_to_surface();
    }
}

/// Handle a keyboard message routed from the desktop loop.
pub fn handle_key(msg: u32, wparam: u64, _lparam: u64) {
    use crate::msg::message::{WM_KEYDOWN, WM_KEYUP};

    let mut guard = TERMINAL.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => return,
    };

    if msg == WM_KEYUP {
        // Track shift/ctrl release
        if wparam == 0x10 { state.shift_held = false; }
        if wparam == 0x11 { state.ctrl_held = false; }
        return;
    }

    // WM_KEYDOWN
    if wparam == 0x10 {
        state.shift_held = true;
        return;
    }
    if wparam == 0x11 {
        state.ctrl_held = true;
        return;
    }

    // Ctrl+C — cancel current input, print ^C and new prompt
    if state.ctrl_held && wparam == 0x43 {
        if !state.input.is_empty() {
            state.write_str_colored("^C", ANSI_COLORS[1]); // red
            state.put_char('\n');
            state.input.clear();
            state.input_cursor = 0;
            state.draw_prompt();
            state.scroll_offset = 0;
            state.render_to_surface();
        }
        return;
    }

    // Ctrl+L — clear screen, redraw prompt + current input
    if state.ctrl_held && wparam == 0x4C {
        state.lines.clear();
        state.lines.push(vec![Cell::blank(); state.cols]);
        state.cursor_row = 0;
        state.cursor_col = 0;
        state.scroll_offset = 0;
        state.draw_prompt();
        let input_copy = state.input.clone();
        for ch in input_copy.chars() {
            state.put_char(ch);
        }
        state.render_to_surface();
        return;
    }

    match wparam {
        // Enter
        0x0D => {
            let cmd = state.input.clone();
            // Echo the newline
            state.put_char('\n');
            state.input.clear();
            state.input_cursor = 0;

            if !cmd.trim().is_empty() {
                let trimmed = cmd.trim();
                if trimmed == "clear" || trimmed == "cls" {
                    state.lines.clear();
                    state.lines.push(vec![Cell::blank(); state.cols]);
                    state.cursor_row = 0;
                    state.cursor_col = 0;
                } else if state.running_exec.is_some() {
                    // Ignore input while a child is running.
                    state.write_str_colored("[busy — process running]\n", ANSI_COLORS[3]);
                } else if is_exec_command(trimmed) {
                    // Async path: spawn child with stdout → pipe.
                    match spawn_async(trimmed) {
                        Ok((pid, pipe_id)) => {
                            state.running_exec = Some((pid, pipe_id));
                            EXEC_RUNNING.store(true, Ordering::Release);
                            // Don't draw prompt yet — poll_output() will do it on exit.
                        }
                        Err(msg) => {
                            state.write_str_colored(&msg, ANSI_COLORS[9]);
                            state.write_str_colored("\n", DEFAULT_FG);
                        }
                    }
                    // Skip draw_prompt below.
                    state.scroll_offset = 0;
                    state.render_to_surface();
                    return;
                } else {
                    // Synchronous shell commands (built-ins, ls, cat, etc.)
                    let output = state.shell.execute_capture(&cmd);
                    state.write_ansi_str(&output);
                }
            }

            // Draw fresh prompt
            state.draw_prompt();
            state.scroll_offset = 0;
            state.render_to_surface();
        }

        // Backspace
        0x08 => {
            if state.input_cursor > 0 {
                state.input_cursor -= 1;
                state.input.remove(state.input_cursor);
                state.redraw_input_line();
            }
        }

        // Delete
        0x2E => {
            if state.input_cursor < state.input.len() {
                state.input.remove(state.input_cursor);
                state.redraw_input_line();
            }
        }

        // Left arrow
        0x25 => {
            if state.input_cursor > 0 {
                state.input_cursor -= 1;
                state.redraw_input_line();
            }
        }

        // Right arrow
        0x27 => {
            if state.input_cursor < state.input.len() {
                state.input_cursor += 1;
                state.redraw_input_line();
            }
        }

        // Up arrow — history previous
        0x26 => {
            let hist = state.shell.history();
            if !hist.is_empty() {
                // Simple: just cycle through history
                // We store the current history index in a hacky way using scroll
                let hist_len = hist.len();
                // Try to find a previous entry
                let current = state.input.clone();
                let mut idx = hist_len;
                for (i, h) in hist.iter().enumerate().rev() {
                    if h != &current {
                        idx = i;
                        break;
                    }
                }
                if idx < hist_len {
                    state.input = hist[idx].clone();
                    state.input_cursor = state.input.len();
                    state.redraw_input_line();
                }
            }
        }

        // Down arrow — restore empty or next history
        0x28 => {
            state.input.clear();
            state.input_cursor = 0;
            state.redraw_input_line();
        }

        // Home
        0x24 => {
            state.input_cursor = 0;
            state.redraw_input_line();
        }

        // End
        0x23 => {
            state.input_cursor = state.input.len();
            state.redraw_input_line();
        }

        // Escape
        0x1B => {
            state.input.clear();
            state.input_cursor = 0;
            state.redraw_input_line();
        }

        // Page Up
        0x21 => {
            let max_scroll = state.lines.len().saturating_sub(state.rows);
            state.scroll_offset = (state.scroll_offset + state.rows / 2).min(max_scroll);
            state.render_to_surface();
        }

        // Page Down
        0x22 => {
            if state.scroll_offset > 0 {
                state.scroll_offset = state.scroll_offset.saturating_sub(state.rows / 2);
                state.render_to_surface();
            }
        }

        // Tab — attempt tab completion
        0x09 => {
            let completions = state.shell.complete(&state.input);
            if completions.len() == 1 {
                state.input = alloc::format!("{} ", completions[0]);
                state.input_cursor = state.input.len();
                state.redraw_input_line();
            } else if completions.len() > 1 {
                // Display completions as output
                state.put_char('\n');
                for c in &completions {
                    state.write_str_colored(c, ANSI_COLORS[6]);
                    state.write_str_colored("  ", DEFAULT_FG);
                }
                state.put_char('\n');
                state.draw_prompt();
                // Re-type current input
                let input_copy = state.input.clone();
                for ch in input_copy.chars() {
                    state.put_char(ch);
                }
                state.render_to_surface();
            }
        }

        // Printable characters: use vk_to_char
        vk => {
            if let Some(ch) = crate::msg::input::vk_to_char(vk, state.shift_held) {
                if ch as u32 >= 0x20 {
                    state.input.insert(state.input_cursor, ch);
                    state.input_cursor += 1;
                    state.redraw_input_line();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TerminalState implementation
// ---------------------------------------------------------------------------

impl TerminalState {
    /// Ensure there are enough lines for the cursor position.
    fn ensure_row(&mut self, row: usize) {
        while self.lines.len() <= row {
            self.lines.push(vec![Cell::blank(); self.cols]);
        }
    }

    /// Write a single character to the grid at cursor, advancing cursor.
    fn put_char(&mut self, ch: char) {
        match ch {
            '\n' => {
                self.cursor_col = 0;
                self.cursor_row += 1;
                self.ensure_row(self.cursor_row);
            }
            '\r' => {
                self.cursor_col = 0;
            }
            '\t' => {
                let next = (self.cursor_col + 8) & !7;
                while self.cursor_col < next && self.cursor_col < self.cols {
                    self.put_visible_char(' ');
                }
            }
            c if (c as u32) >= 0x20 => {
                self.put_visible_char(c);
            }
            _ => {} // ignore other control chars
        }
    }

    fn put_visible_char(&mut self, ch: char) {
        self.ensure_row(self.cursor_row);
        if self.cursor_col >= self.cols {
            // Wrap to next line
            self.cursor_col = 0;
            self.cursor_row += 1;
            self.ensure_row(self.cursor_row);
        }
        let cell = Cell {
            ch,
            fg: if self.cur_bold { brighten(self.cur_fg) } else { self.cur_fg },
            bg: self.cur_bg,
        };
        self.lines[self.cursor_row][self.cursor_col] = cell;
        self.cursor_col += 1;
    }

    /// Write a plain string with a specific color (no ANSI parsing).
    fn write_str_colored(&mut self, s: &str, color: u32) {
        let saved_fg = self.cur_fg;
        self.cur_fg = color;
        for ch in s.chars() {
            self.put_char(ch);
        }
        self.cur_fg = saved_fg;
    }

    /// Write a string that may contain ANSI escape sequences.
    fn write_ansi_str(&mut self, s: &str) {
        for byte in s.bytes() {
            match self.esc_state {
                EscState::Normal => {
                    if byte == 0x1b {
                        self.esc_state = EscState::Escape;
                        self.esc_len = 0;
                    } else {
                        self.put_char(byte as char);
                    }
                }
                EscState::Escape => {
                    if byte == b'[' {
                        self.esc_state = EscState::Csi;
                        self.esc_len = 0;
                    } else {
                        // Not a CSI sequence, emit ESC as-is and re-process byte
                        self.esc_state = EscState::Normal;
                        self.put_char(byte as char);
                    }
                }
                EscState::Csi => {
                    if byte >= b'@' && byte <= b'~' {
                        // Final byte of CSI sequence
                        self.esc_state = EscState::Normal;
                        if byte == b'm' {
                            self.process_sgr();
                        }
                        // Other CSI sequences (cursor movement, etc.) are ignored
                        // since we're just capturing text output
                    } else if self.esc_len < 31 {
                        self.esc_buf[self.esc_len] = byte;
                        self.esc_len += 1;
                    } else {
                        // Buffer overflow, abandon sequence
                        self.esc_state = EscState::Normal;
                    }
                }
            }
        }
    }

    /// Process SGR (Select Graphic Rendition) — ANSI color codes.
    fn process_sgr(&mut self) {
        let params_str = core::str::from_utf8(&self.esc_buf[..self.esc_len]).unwrap_or("");
        if params_str.is_empty() {
            // ESC[m = reset
            self.cur_fg = DEFAULT_FG;
            self.cur_bg = DEFAULT_BG;
            self.cur_bold = false;
            return;
        }

        for param in params_str.split(';') {
            let n: u32 = param.parse().unwrap_or(0);
            match n {
                0 => {
                    self.cur_fg = DEFAULT_FG;
                    self.cur_bg = DEFAULT_BG;
                    self.cur_bold = false;
                }
                1 => { self.cur_bold = true; }
                22 => { self.cur_bold = false; }
                // Standard foreground colors 30-37
                30..=37 => { self.cur_fg = ANSI_COLORS[(n - 30) as usize]; }
                39 => { self.cur_fg = DEFAULT_FG; }
                // Standard background colors 40-47
                40..=47 => { self.cur_bg = ANSI_COLORS[(n - 40) as usize]; }
                49 => { self.cur_bg = DEFAULT_BG; }
                // Bright foreground 90-97
                90..=97 => { self.cur_fg = ANSI_COLORS[(n - 90 + 8) as usize]; }
                // Bright background 100-107
                100..=107 => { self.cur_bg = ANSI_COLORS[(n - 100 + 8) as usize]; }
                _ => {}
            }
        }
    }

    /// Draw the shell prompt at the current cursor position.
    fn draw_prompt(&mut self) {
        let cwd = String::from(self.shell.cwd());
        self.write_str_colored("astryx", ANSI_COLORS[10]); // bright green
        self.write_str_colored(&cwd, ANSI_COLORS[4]);      // blue
        self.write_str_colored("> ", DEFAULT_FG);
    }

    /// Redraw the current input line (after editing).
    /// Erases the old input from the grid and redraws it.
    fn redraw_input_line(&mut self) {
        // Find the prompt row — it's the row where the prompt was drawn.
        // We need to figure out where the prompt ends and input starts.
        // The prompt is "astryx<cwd>> " which has a known length.
        let prompt_len = 6 + self.shell.cwd().len() + 2; // "astryx" + cwd + "> "
        
        // Calculate the row where the prompt started
        // Walk backward from cursor to find prompt start  
        let total_chars = prompt_len + self.input.len();
        let _start_row = if total_chars > 0 {
            self.cursor_row.saturating_sub((self.cursor_col + self.input.len()) / self.cols)
        } else {
            self.cursor_row
        };
        
        // Find the prompt row: back up from cursor_row
        // Actually, simplest approach: clear from prompt position and redraw
        let prompt_row = self.lines.len().saturating_sub(1);
        // Find where the prompt starts on this line
        let _pr = prompt_row;
        // Walk back to find a row that starts with prompt (heuristic: look for 'a' of 'astryx')
        // Simpler: just track the prompt start position
        
        // Clear from the prompt output row to EOL
        // We know the prompt was the last thing written before input. 
        // The grid's last line(s) contain: prompt + old input
        // We need to erase the old input and write the new one.
        
        // Strategy: erase the entire last line(s) that contain prompt+input, redraw prompt+input
        // Calculate how many rows the prompt+old_input spans. Actually we don't know old input len.
        // Safest: find the line that has the prompt, clear it + subsequent lines, redraw.
        
        // Simplest correct approach: remember the row where prompt starts.
        // For now, overwrite: clear the last few rows and redraw prompt + input.
        let clear_rows = (total_chars / self.cols) + 2;
        let clear_start = self.lines.len().saturating_sub(clear_rows);
        
        // Truncate lines to the prompt start row
        self.lines.truncate(clear_start.max(1));
        self.cursor_row = self.lines.len().saturating_sub(1);
        // Make sure we end on a fresh line
        if self.cursor_col != 0 || self.lines.is_empty() {
            self.lines.push(vec![Cell::blank(); self.cols]);
            self.cursor_row = self.lines.len() - 1;
        }
        self.cursor_col = 0;
        
        // Redraw prompt + input
        self.draw_prompt();
        let input_copy = self.input.clone();
        for ch in input_copy.chars() {
            self.put_char(ch);
        }
        
        self.scroll_offset = 0;
        self.render_to_surface();
    }

    /// Render the character grid to the window's pixel surface.
    fn render_to_surface(&self) {
        let (cw, ch) = match window::with_window(self.handle, |w| (w.client_width, w.client_height)) {
            Some(d) => d,
            None => return,
        };
        if cw == 0 || ch == 0 { return; }

        let size = (cw as usize) * (ch as usize);
        let mut surface = vec![DEFAULT_BG; size];
        let stride = cw as usize;

        // Calculate which lines to display
        let total_lines = self.lines.len();
        let visible_rows = self.rows;
        let scroll = self.scroll_offset;

        // The "bottom" of the view is total_lines - scroll
        let view_end = total_lines.saturating_sub(scroll);
        let view_start = view_end.saturating_sub(visible_rows);

        for (screen_row, line_idx) in (view_start..view_end).enumerate() {
            if line_idx >= self.lines.len() { break; }
            let line = &self.lines[line_idx];

            for (col, cell) in line.iter().enumerate() {
                if col >= self.cols { break; }

                let px = col * FONT_W as usize;
                let py = screen_row * FONT_H as usize;

                // Draw background if not default
                if cell.bg != DEFAULT_BG {
                    for row in 0..FONT_H as usize {
                        let y = py + row;
                        if y >= ch as usize { break; }
                        for c in 0..FONT_W as usize {
                            let x = px + c;
                            if x >= cw as usize { continue; }
                            surface[y * stride + x] = cell.bg;
                        }
                    }
                }

                // Draw character
                if cell.ch != ' ' {
                    draw_char_to_surface(&mut surface, stride, px as i32, py as i32, cell.ch, cell.fg);
                }
            }
        }

        // Draw cursor (blinking block at input position)
        // The cursor is at the end of prompt + input text
        let cursor_line = self.cursor_row;
        let cursor_col = self.cursor_col;
        if cursor_line >= view_start && cursor_line < view_end {
            let screen_row = cursor_line - view_start;
            let px = cursor_col * FONT_W as usize;
            let py = screen_row * FONT_H as usize;
            // Draw a block cursor
            for row in 0..FONT_H as usize {
                let y = py + row;
                if y >= ch as usize { break; }
                for c in 0..FONT_W as usize {
                    let x = px + c;
                    if x >= cw as usize { continue; }
                    let idx = y * stride + x;
                    if idx < surface.len() {
                        // Invert colors for cursor
                        surface[idx] = 0xFFCCCCCC;
                    }
                }
            }
        }

        // Write surface to window
        window::with_window_mut(self.handle, |w| {
            w.surface = surface;
        });
    }
}

// ---------------------------------------------------------------------------
// Drawing helpers
// ---------------------------------------------------------------------------

fn draw_char_to_surface(buf: &mut [u32], stride: usize, x: i32, y: i32, ch: char, color: u32) {
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

/// Make a color brighter (for bold text).
fn brighten(color: u32) -> u32 {
    let a = color & 0xFF000000;
    let r = ((color >> 16) & 0xFF).min(200) + 55;
    let g = ((color >> 8) & 0xFF).min(200) + 55;
    let b = (color & 0xFF).min(200) + 55;
    a | (r << 16) | (g << 8) | b
}

// ---------------------------------------------------------------------------
// Async exec helpers
// ---------------------------------------------------------------------------

/// Returns true if the command should be run as an async child process
/// (i.e. it's `exec <path>` or a bare absolute/relative path).
fn is_exec_command(cmd: &str) -> bool {
    let first = cmd.split_whitespace().next().unwrap_or("");
    first == "exec" || first.starts_with('/') || first.starts_with("./")
}

/// Spawn a child process asynchronously, wiring its stdout/stderr to a new
/// pipe.  Returns `(child_pid, pipe_read_id)` on success.
fn spawn_async(cmd: &str) -> Result<(u64, u64), alloc::string::String> {
    let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
    if parts.is_empty() {
        return Err(alloc::string::String::from("empty command"));
    }

    // Strip leading "exec" keyword if present.
    let args = if parts[0] == "exec" { &parts[1..] } else { &parts[..] };
    if args.is_empty() {
        return Err(alloc::string::String::from("exec: missing path"));
    }

    let raw_path = args[0];
    let name_buf;
    let name: &str = if raw_path.starts_with('/') {
        raw_path
    } else {
        name_buf = alloc::format!("/{}", raw_path);
        &name_buf
    };

    // Load ELF bytes; capture any orbit_println! output during this phase.
    crate::drivers::console::begin_capture();
    let data = match crate::vfs::read_file(name) {
        Ok(d) => d,
        Err(e) => {
            let _ = crate::drivers::console::end_capture();
            return Err(alloc::format!("exec: {}: {:?}", name, e));
        }
    };
    let _setup_log = crate::drivers::console::end_capture();

    if !crate::proc::elf::is_elf(&data) {
        return Err(alloc::format!("exec: '{}' is not an ELF binary", name));
    }

    // Enable scheduler so the child can run.
    if !crate::sched::is_active() {
        crate::sched::enable();
    }

    let envp: &[&str] = &[
        "HOME=/home/user",
        "PATH=/bin:/disk/bin",
        "TCCDIR=/disk/lib/tcc",
        "TMPDIR=/tmp",
        "DISPLAY=:0",
        "GDK_BACKEND=x11",
        // Tell Firefox to run headless even when DISPLAY is set.  libxul
        // checks gfxPlatform::IsHeadless() / nsAppRunner XRE_main and skips
        // gdk_display_open() / XOpenDisplay() entirely on this branch.  Our
        // libX11 / libgdk stubs return NULL from those calls, which would
        // otherwise produce "Error: cannot open display: :0\n" on stderr
        // followed by exit_group(1).  Mozilla documents `MOZ_HEADLESS=1`
        // (and the equivalent `--headless` argv flag) as the canonical
        // headless-mode trigger.
        // See: https://firefox-source-docs.mozilla.org/widget/headless.html
        "MOZ_HEADLESS=1",
        "MOZ_DISABLE_CONTENT_SANDBOX=1",
        "MOZ_DISABLE_NONLOCAL_CONNECTIONS=1",
        "MOZ_DISABLE_AUTO_SAFE_MODE=1",
        // Short-circuit SetExceptionHandler() before it touches the
        // Crash Reports directory tree.  Release builds of Firefox check
        // `MOZ_CRASHREPORTER_DISABLE` early and return NS_OK without any
        // filesystem setup, sidestepping /home/user/.mozilla/firefox/Crash
        // Reports/ creation and the subsequent fatal-on-error writes that
        // bubble up through CrashReporter::SetupExtraData().
        "MOZ_CRASHREPORTER_DISABLE=1",
        // Force single-process mode — no content process fork.
        "MOZ_FORCE_DISABLE_E10S=1",
        // Skip GPU/glxtest process — we don't support fork+exec yet.
        // Tell Firefox to use software rendering without probing.
        "MOZ_GFX_TESTING_NO_CHILD_PROCESS=1",
        "MOZ_X11_EGL=0",
        "MOZ_ACCELERATED=0",
        "LIBGL_ALWAYS_SOFTWARE=1",
        "LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/disk/lib/firefox",
        "XDG_RUNTIME_DIR=/tmp",
        "XDG_CONFIG_HOME=/tmp/.config",
        "FONTCONFIG_PATH=/disk/lib/firefox/fonts",
        // Pre-set D-Bus address so Firefox does not try to exec dbus-launch.
        // Without this, Firefox forks a child that execs dbus-launch, fails
        // (not on disk), and both parent and child exit with code 1.
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus.sock",
        // Route NSPR/XPCOM module logging to stderr (fd 2) so the kernel
        // write-trace picks it up.  Level 5 = debug.  Deliberately omit
        // NSPR_LOG_FILE — we want output on the parent-visible fd, not
        // squirreled away in a file we'd have to tail separately.
        // See https://firefox-source-docs.mozilla.org/xpcom/logging.html
        "MOZ_LOG=all:5,nsresult:5,xpcom:5",
        "NSPR_LOG_MODULES=all:5",
    ];

    // Spawn blocked so we can attach the pipe before the child can run.
    // linux_abi / subsystem are set inside create_user_process_with_args_blocked.
    let pid = crate::proc::usermode::create_user_process_with_args_blocked(name, &data, args, envp)
        .map_err(|e| alloc::format!("exec: ELF load failed: {:?}", e))?;

    // Attach pipe to stdout/stderr while the child is still blocked.
    let pipe_id = crate::ipc::pipe::create_pipe();
    crate::proc::attach_stdout_pipe(pid, pipe_id);

    // Now allow the scheduler to run the child.
    crate::proc::unblock_process(pid);

    Ok((pid, pipe_id))
}

// ---------------------------------------------------------------------------
// Public launch helper — called from start menu / desktop
// ---------------------------------------------------------------------------

/// Launch an external ELF process asynchronously, wiring its stdout to the
/// terminal widget.  Prints any error to the terminal on failure.
/// Safe to call even when another exec is running (will show busy message).
pub fn launch_process(path: &str) {
    // Show a "launching..." message in the terminal first.
    {
        let mut guard = TERMINAL.lock();
        if let Some(ref mut state) = *guard {
            let msg = alloc::format!("Launching {}...\n", path);
            state.write_str_colored(&msg, ANSI_COLORS[2]); // green
        }
    }

    match spawn_async(path) {
        Ok((pid, pipe_id)) => {
            let mut guard = TERMINAL.lock();
            if let Some(ref mut state) = *guard {
                state.running_exec = Some((pid, pipe_id));
                EXEC_RUNNING.store(true, core::sync::atomic::Ordering::Release);
            }
        }
        Err(msg) => {
            let mut guard = TERMINAL.lock();
            if let Some(ref mut state) = *guard {
                let err = alloc::format!("Error: {}\n", msg);
                state.write_str_colored(&err, ANSI_COLORS[1]); // red
            }
        }
    }
}

/// Returns true if a child process launched via `launch_process` is currently
/// running.  Used by the `firefox-test` feature to detect Firefox exit.
pub fn is_firefox_running() -> bool {
    EXEC_RUNNING.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Public per-tick poll — called from the desktop loop
// ---------------------------------------------------------------------------

/// Drain any pending stdout bytes from a running child process into the
/// terminal display, and reap the child if it has exited.
///
/// Called every desktop tick so the GUI stays responsive while TCC (or any
/// other child) is running.  Must NOT hold the TERMINAL lock while calling
/// into the process or pipe tables (ABBA deadlock risk).
pub fn poll_output() {
    // Fast path: no exec is running — skip acquiring the TERMINAL mutex.
    if !EXEC_RUNNING.load(Ordering::Acquire) { return; }

    // Snapshot the running-exec handle without holding TERMINAL across
    // the waitpid / pipe_read calls below.
    let running = {
        let guard = TERMINAL.lock();
        guard.as_ref().and_then(|s| s.running_exec)
    };

    let (pid, pipe_id) = match running {
        Some(r) => r,
        None => return,
    };

    // Drain ALL available pipe bytes in a loop (non-blocking).
    // Larger buffer (4096) + loop drains the entire pipe in one poll_output() call,
    // then renders ONCE — eliminates the per-512-byte render overhead that made
    // terminal text appear much slower than serial output.
    let mut raw = [0u8; 4096];
    let mut any_data = false;

    // First pass: read all available data before locking TERMINAL
    let mut chunks: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    loop {
        let n = crate::ipc::pipe::pipe_read(pipe_id, &mut raw).unwrap_or(0);
        if n == 0 { break; }
        chunks.push(raw[..n].to_vec());
        any_data = true;
    }

    // Non-blocking waitpid: did the child become a zombie?
    let exit_status = crate::proc::waitpid(0, pid as i64);

    // Now re-lock TERMINAL to push output + update state.
    let mut guard = TERMINAL.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => return,
    };

    // Append ALL stdout bytes to the terminal grid, then render ONCE.
    for chunk in &chunks {
        let text = core::str::from_utf8(chunk).unwrap_or("\u{FFFD}");
        state.write_ansi_str(text);
    }
    if any_data {
        state.render_to_surface();
    }

    if let Some((_reaped, code)) = exit_status {
        // Drain any final bytes the child wrote before exiting.
        drop(guard); // release TERMINAL before pipe_read
        let mut tail = [0u8; 4096];
        let tn = crate::ipc::pipe::pipe_read(pipe_id, &mut tail).unwrap_or(0);
        crate::ipc::pipe::pipe_close_reader(pipe_id);

        let mut guard2 = TERMINAL.lock();
        let state2 = match guard2.as_mut() { Some(s) => s, None => return };

        if tn > 0 {
            let text = core::str::from_utf8(&tail[..tn]).unwrap_or("\u{FFFD}");
            state2.write_ansi_str(text);
        }
        if code != 0 {
            state2.write_str_colored(
                &alloc::format!("\r\n[exited: code {}]\r\n", code),
                ANSI_COLORS[9],
            );
        } else {
            state2.write_str_colored("\r\n", DEFAULT_FG);
        }
        state2.running_exec = None;
        EXEC_RUNNING.store(false, Ordering::Release);
        state2.draw_prompt();
        state2.scroll_offset = 0;
        state2.render_to_surface();
    }
}
