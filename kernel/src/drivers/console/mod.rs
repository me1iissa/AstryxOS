//! Framebuffer Console Driver
//!
//! Renders text to the UEFI framebuffer using a built-in bitmap font.
//! Supports ANSI/VT100 escape sequences, cursor rendering, and 16 colors.
//! Also provides the kernel debug shell for Phase 0-3.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use astryx_shared::{BootInfo, FramebufferInfo, PixelFormat};
use core::fmt;
use spin::Mutex;

/// Console state.
pub static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// GUI output capture — when active, _kprint appends text here instead of
// (in addition to) the hardware console.
// ---------------------------------------------------------------------------

/// When `Some`, _kprint appends all text here (captured for the GUI terminal).
static GUI_CAPTURE: Mutex<Option<String>> = Mutex::new(None);

/// Begin capturing console output. All subsequent `_kprint` calls will
/// append their text to an internal buffer instead of the framebuffer console.
pub fn begin_capture() {
    *GUI_CAPTURE.lock() = Some(String::new());
}

/// End capturing and return the collected output.
pub fn end_capture() -> String {
    GUI_CAPTURE.lock().take().unwrap_or_default()
}

/// ANSI 16-color palette (standard + bright).
const ANSI_COLORS: [u32; 16] = [
    0x0000_0000, // 0: Black
    0x00AA_0000, // 1: Red
    0x0000_AA00, // 2: Green
    0x00AA_5500, // 3: Yellow/Brown
    0x0000_00AA, // 4: Blue
    0x00AA_00AA, // 5: Magenta
    0x0000_AAAA, // 6: Cyan
    0x00AA_AAAA, // 7: White (light gray)
    0x0055_5555, // 8: Bright black (dark gray)
    0x00FF_5555, // 9: Bright red
    0x0055_FF55, // 10: Bright green
    0x00FF_FF55, // 11: Bright yellow
    0x0055_55FF, // 12: Bright blue
    0x00FF_55FF, // 13: Bright magenta
    0x0055_FFFF, // 14: Bright cyan
    0x00FF_FFFF, // 15: Bright white
];

/// ANSI escape sequence parser state.
#[derive(Debug, Clone, Copy, PartialEq)]
enum AnsiState {
    Normal,
    /// Received ESC (0x1B)
    Escape,
    /// Received ESC [
    Csi,
}

/// Console text rendering state.
pub struct Console {
    fb: FramebufferInfo,
    col: usize,
    row: usize,
    max_cols: usize,
    max_rows: usize,
    fg_color: u32,
    bg_color: u32,
    /// Default colors (for reset).
    default_fg: u32,
    default_bg: u32,
    /// Whether text is bold (bright colors).
    bold: bool,
    /// ANSI escape sequence parser.
    ansi_state: AnsiState,
    /// CSI parameter buffer.
    ansi_params: [u8; 16],
    ansi_param_len: usize,
    /// Cursor visibility & blink state.
    cursor_visible: bool,
    cursor_shown: bool,
    /// Last cursor blink toggle tick.
    cursor_last_toggle: u64,
    /// Saved cursor position (ESC 7 / CSI s).
    saved_row: usize,
    saved_col: usize,
    /// Scroll region (top and bottom row, 0-indexed, inclusive).
    scroll_top: usize,
    scroll_bottom: usize,
    /// CSI private mode flag ('?' prefix).
    csi_private: bool,
}

mod font8x16;

/// Basic 8x16 bitmap font (ASCII 32-126).
const FONT_WIDTH: usize = 8;
const FONT_HEIGHT: usize = 16;
/// Cursor blink interval in ticks (100 Hz → 50 ticks = 500ms).
const CURSOR_BLINK_TICKS: u64 = 50;

impl Console {
    /// Create a new console from framebuffer info.
    fn new(mut fb: FramebufferInfo) -> Self {
        // The bootloader stores the framebuffer physical address in base_address.
        // Physical addresses above 1 GiB are not in the bootloader's higher-half
        // RAM map, but vmm::extend_higher_half_to_4gib() maps them at PHYS_OFF+phys
        // so the kernel can access them regardless of which CR3 is active.
        // Convert to the kernel virtual address here so all accesses use PHYS_OFF.
        const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
        if fb.base_address < PHYS_OFF {
            // base_address is still a physical address — convert to virtual.
            fb.base_address += PHYS_OFF;
        }
        let max_cols = fb.width as usize / FONT_WIDTH;
        let max_rows = fb.height as usize / FONT_HEIGHT;
        let default_fg = 0x0055_FFFF; // Bright cyan (AstryxOS brand)
        let default_bg = 0x0000_0000; // Black

        Console {
            fb,
            col: 0,
            row: 0,
            max_cols,
            max_rows,
            fg_color: default_fg,
            bg_color: default_bg,
            default_fg,
            default_bg,
            bold: false,
            ansi_state: AnsiState::Normal,
            ansi_params: [0; 16],
            ansi_param_len: 0,
            cursor_visible: true,
            cursor_shown: false,
            cursor_last_toggle: 0,
            saved_row: 0,
            saved_col: 0,
            scroll_top: 0,
            scroll_bottom: max_rows.saturating_sub(1),
            csi_private: false,
        }
    }

    /// Get cursor position (col, row).
    pub fn cursor_pos(&self) -> (usize, usize) {
        (self.col, self.row)
    }

    /// Set cursor position.
    pub fn set_cursor_pos(&mut self, col: usize, row: usize) {
        self.hide_cursor();
        self.col = col.min(self.max_cols.saturating_sub(1));
        self.row = row.min(self.max_rows.saturating_sub(1));
    }

    /// Get terminal dimensions (cols, rows).
    pub fn dimensions(&self) -> (usize, usize) {
        (self.max_cols, self.max_rows)
    }

    /// Set foreground color directly (32-bit RGB).
    pub fn set_fg_color(&mut self, color: u32) {
        self.fg_color = color;
    }

    /// Set background color directly (32-bit RGB).
    pub fn set_bg_color(&mut self, color: u32) {
        self.bg_color = color;
    }

    /// Reset to default colors.
    pub fn reset_colors(&mut self) {
        self.fg_color = self.default_fg;
        self.bg_color = self.default_bg;
        self.bold = false;
    }

    /// Clear the screen.
    pub fn clear(&mut self) {
        self.hide_cursor();
        let total_pixels = self.fb.stride as usize * self.fb.height as usize;
        let fb_ptr = self.fb.base_address as *mut u32;

        unsafe {
            for i in 0..total_pixels {
                *fb_ptr.add(i) = self.bg_color;
            }
        }
        self.col = 0;
        self.row = 0;
    }

    /// Clear from cursor to end of screen.
    fn clear_to_end(&mut self) {
        // Clear rest of current line
        self.clear_line_from_cursor();
        // Clear all subsequent lines
        let start_row = self.row + 1;
        for r in start_row..self.max_rows {
            let y_start = r * FONT_HEIGHT;
            for y in y_start..(y_start + FONT_HEIGHT) {
                for x in 0..self.fb.width as usize {
                    self.put_pixel(x, y, self.bg_color);
                }
            }
        }
    }

    /// Clear from cursor to end of line.
    pub fn clear_line_from_cursor(&mut self) {
        let y_start = self.row * FONT_HEIGHT;
        for c in self.col..self.max_cols {
            let x_start = c * FONT_WIDTH;
            for y in 0..FONT_HEIGHT {
                for x in 0..FONT_WIDTH {
                    self.put_pixel(x_start + x, y_start + y, self.bg_color);
                }
            }
        }
    }

    /// Clear entire current line.
    fn clear_entire_line(&mut self) {
        let y_start = self.row * FONT_HEIGHT;
        for y in 0..FONT_HEIGHT {
            for x in 0..self.fb.width as usize {
                self.put_pixel(x, y_start + y, self.bg_color);
            }
        }
    }

    /// Put a single pixel.
    fn put_pixel(&self, x: usize, y: usize, color: u32) {
        if x >= self.fb.width as usize || y >= self.fb.height as usize {
            return;
        }
        let offset = y * self.fb.stride as usize + x;
        let fb_ptr = self.fb.base_address as *mut u32;
        unsafe {
            *fb_ptr.add(offset) = color;
        }
    }

    /// Draw a character at a specific (col, row) with given colors.
    pub fn draw_char_at(&self, ch: char, col: usize, row: usize, fg: u32, bg: u32) {
        if (ch as u32) < 32 || (ch as u32) > 126 { return; }
        let font_idx = (ch as u8 - 32) as usize * FONT_HEIGHT;
        let x_start = col * FONT_WIDTH;
        let y_start = row * FONT_HEIGHT;

        for r in 0..FONT_HEIGHT {
            let row_data = font8x16::VGA_FONT_8X16[font_idx + r];
            for bit in 0..FONT_WIDTH {
                let color = if row_data & (0x80 >> bit) != 0 { fg } else { bg };
                self.put_pixel(x_start + bit, y_start + r, color);
            }
        }
    }

    /// Erase a character cell at (col, row).
    pub fn erase_cell(&self, col: usize, row: usize) {
        let x_start = col * FONT_WIDTH;
        let y_start = row * FONT_HEIGHT;
        for r in 0..FONT_HEIGHT {
            for bit in 0..FONT_WIDTH {
                self.put_pixel(x_start + bit, y_start + r, self.bg_color);
            }
        }
    }

    /// Show the cursor (block cursor) at current position.
    pub fn show_cursor(&mut self) {
        if !self.cursor_visible || self.cursor_shown { return; }
        self.cursor_shown = true;
        let x_start = self.col * FONT_WIDTH;
        let y_start = self.row * FONT_HEIGHT;
        // Draw an underline cursor (last 2 rows of the cell)
        for y in (FONT_HEIGHT - 2)..FONT_HEIGHT {
            for x in 0..FONT_WIDTH {
                self.put_pixel(x_start + x, y_start + y, self.fg_color);
            }
        }
    }

    /// Hide the cursor at current position.
    pub fn hide_cursor(&mut self) {
        if !self.cursor_shown { return; }
        self.cursor_shown = false;
        let x_start = self.col * FONT_WIDTH;
        let y_start = self.row * FONT_HEIGHT;
        // Erase the underline cursor
        for y in (FONT_HEIGHT - 2)..FONT_HEIGHT {
            for x in 0..FONT_WIDTH {
                self.put_pixel(x_start + x, y_start + y, self.bg_color);
            }
        }
    }

    /// Toggle cursor blink based on tick count. Call from the main loop.
    /// Returns `true` if the cursor was actually toggled (screen needs refresh).
    pub fn blink_cursor(&mut self, ticks: u64) -> bool {
        if !self.cursor_visible { return false; }
        if ticks.wrapping_sub(self.cursor_last_toggle) >= CURSOR_BLINK_TICKS {
            self.cursor_last_toggle = ticks;
            if self.cursor_shown {
                self.hide_cursor();
            } else {
                self.show_cursor();
            }
            true
        } else {
            false
        }
    }

    /// Draw a character at the current cursor position and advance.
    pub fn put_char(&mut self, ch: char) {
        // Feed through ANSI escape parser first
        match self.ansi_state {
            AnsiState::Escape => {
                match ch {
                    '[' => {
                        self.ansi_state = AnsiState::Csi;
                        self.ansi_param_len = 0;
                        self.ansi_params = [0; 16];
                        self.csi_private = false;
                        return;
                    }
                    _ => {
                        // Unknown escape sequence, ignore
                        self.ansi_state = AnsiState::Normal;
                        return;
                    }
                }
            }
            AnsiState::Csi => {
                if ch == '?' {
                    // Private mode prefix (e.g. CSI ? 25 h)
                    self.csi_private = true;
                    return;
                }
                if ch.is_ascii_digit() || ch == ';' {
                    // Accumulate parameter bytes
                    if self.ansi_param_len < 16 {
                        self.ansi_params[self.ansi_param_len] = ch as u8;
                        self.ansi_param_len += 1;
                    }
                    return;
                } else {
                    // Final character — execute CSI command
                    self.execute_csi(ch);
                    self.ansi_state = AnsiState::Normal;
                    self.csi_private = false;
                    return;
                }
            }
            AnsiState::Normal => {}
        }

        // Check for ESC character
        if ch == '\x1b' {
            self.ansi_state = AnsiState::Escape;
            return;
        }

        self.hide_cursor();

        match ch {
            '\n' => {
                self.col = 0;
                self.row += 1;
                if self.row >= self.max_rows {
                    self.scroll();
                }
            }
            '\r' => {
                self.col = 0;
            }
            '\t' => {
                self.col = (self.col + 8) & !7;
                if self.col >= self.max_cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.max_rows {
                        self.scroll();
                    }
                }
            }
            ch if (ch as u32) >= 32 && (ch as u32) <= 126 => {
                self.draw_char_at(ch, self.col, self.row, self.fg_color, self.bg_color);

                self.col += 1;
                if self.col >= self.max_cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.max_rows {
                        self.scroll();
                    }
                }
            }
            _ => {}
        }
    }

    /// Execute a CSI (Control Sequence Introducer) command.
    fn execute_csi(&mut self, cmd: char) {
        let params = self.parse_csi_params();

        match cmd {
            // Cursor movement
            'A' => { // Cursor Up
                let n = params.first().copied().unwrap_or(1).max(1) as usize;
                self.hide_cursor();
                self.row = self.row.saturating_sub(n);
            }
            'B' => { // Cursor Down
                let n = params.first().copied().unwrap_or(1).max(1) as usize;
                self.hide_cursor();
                self.row = (self.row + n).min(self.max_rows - 1);
            }
            'C' => { // Cursor Forward
                let n = params.first().copied().unwrap_or(1).max(1) as usize;
                self.hide_cursor();
                self.col = (self.col + n).min(self.max_cols - 1);
            }
            'D' => { // Cursor Back
                let n = params.first().copied().unwrap_or(1).max(1) as usize;
                self.hide_cursor();
                self.col = self.col.saturating_sub(n);
            }
            'H' | 'f' => { // Cursor Position
                let row = params.first().copied().unwrap_or(1).max(1) as usize - 1;
                let col = params.get(1).copied().unwrap_or(1).max(1) as usize - 1;
                self.hide_cursor();
                self.row = row.min(self.max_rows - 1);
                self.col = col.min(self.max_cols - 1);
            }
            'J' => { // Erase in Display
                let n = params.first().copied().unwrap_or(0);
                match n {
                    0 => self.clear_to_end(),
                    2 => self.clear(),
                    _ => {}
                }
            }
            'K' => { // Erase in Line
                let n = params.first().copied().unwrap_or(0);
                match n {
                    0 => self.clear_line_from_cursor(),
                    2 => self.clear_entire_line(),
                    _ => {}
                }
            }
            'm' => { // SGR (Select Graphic Rendition)
                if params.is_empty() {
                    self.reset_colors();
                } else {
                    for &p in &params {
                        self.apply_sgr(p);
                    }
                }
            }
            'P' => { // Delete n characters at cursor (shift rest left)
                let n = params.first().copied().unwrap_or(1).max(1) as usize;
                self.hide_cursor();
                self.delete_chars(n);
            }
            '@' => { // Insert n blank characters at cursor (shift rest right)
                let n = params.first().copied().unwrap_or(1).max(1) as usize;
                self.hide_cursor();
                self.insert_chars(n);
            }
            'L' => { // Insert n blank lines (scroll region down)
                let n = params.first().copied().unwrap_or(1).max(1) as usize;
                self.hide_cursor();
                self.insert_lines(n);
            }
            'M' => { // Delete n lines (scroll region up)
                let n = params.first().copied().unwrap_or(1).max(1) as usize;
                self.hide_cursor();
                self.delete_lines(n);
            }
            's' => { // Save cursor position
                self.saved_row = self.row;
                self.saved_col = self.col;
            }
            'u' => { // Restore cursor position
                self.hide_cursor();
                self.row = self.saved_row.min(self.max_rows.saturating_sub(1));
                self.col = self.saved_col.min(self.max_cols.saturating_sub(1));
            }
            'h' => { // Set mode
                if self.csi_private {
                    let mode = params.first().copied().unwrap_or(0);
                    if mode == 25 {
                        self.cursor_visible = true; // Show cursor
                    }
                }
            }
            'l' => { // Reset mode
                if self.csi_private {
                    let mode = params.first().copied().unwrap_or(0);
                    if mode == 25 {
                        self.hide_cursor();
                        self.cursor_visible = false; // Hide cursor
                    }
                }
            }
            'r' => { // Set scroll region (top;bottom)
                let top = params.first().copied().unwrap_or(1).max(1) as usize - 1;
                let bottom = params.get(1).copied().unwrap_or(self.max_rows as u32).max(1) as usize - 1;
                self.scroll_top = top.min(self.max_rows.saturating_sub(1));
                self.scroll_bottom = bottom.min(self.max_rows.saturating_sub(1));
                if self.scroll_top > self.scroll_bottom {
                    self.scroll_top = 0;
                    self.scroll_bottom = self.max_rows.saturating_sub(1);
                }
                // Reset cursor to top-left
                self.hide_cursor();
                self.row = 0;
                self.col = 0;
            }
            _ => {} // Unknown CSI command
        }
    }

    /// Parse CSI parameters from the buffer (semicolon-separated numbers).
    fn parse_csi_params(&self) -> alloc::vec::Vec<u32> {
        let mut result = alloc::vec::Vec::new();
        let mut current: u32 = 0;
        let mut has_digit = false;

        for i in 0..self.ansi_param_len {
            let b = self.ansi_params[i];
            if b == b';' {
                result.push(if has_digit { current } else { 0 });
                current = 0;
                has_digit = false;
            } else if b.is_ascii_digit() {
                current = current * 10 + (b - b'0') as u32;
                has_digit = true;
            }
        }
        if has_digit || result.is_empty() {
            result.push(current);
        }
        result
    }

    /// Apply an SGR (Select Graphic Rendition) parameter.
    fn apply_sgr(&mut self, code: u32) {
        match code {
            0 => self.reset_colors(),
            1 => self.bold = true,
            22 => self.bold = false,
            // Foreground colors 30-37
            30..=37 => {
                let idx = (code - 30) as usize + if self.bold { 8 } else { 0 };
                self.fg_color = ANSI_COLORS[idx];
            }
            // Default foreground
            39 => self.fg_color = self.default_fg,
            // Background colors 40-47
            40..=47 => {
                let idx = (code - 40) as usize;
                self.bg_color = ANSI_COLORS[idx];
            }
            // Default background
            49 => self.bg_color = self.default_bg,
            // Bright foreground 90-97
            90..=97 => {
                let idx = (code - 90) as usize + 8;
                self.fg_color = ANSI_COLORS[idx];
            }
            // Bright background 100-107
            100..=107 => {
                let idx = (code - 100) as usize + 8;
                self.bg_color = ANSI_COLORS[idx];
            }
            _ => {} // Unrecognized SGR
        }
    }

    /// Scroll the screen up by one line.
    fn scroll(&mut self) {
        // Use scroll region if set
        self.scroll_region_up(self.scroll_top, self.scroll_bottom);
        self.row = self.scroll_bottom;
    }

    /// Scroll a region of the screen up by one text row.
    fn scroll_region_up(&self, top: usize, bottom: usize) {
        let fb_ptr = self.fb.base_address as *mut u32;
        let stride = self.fb.stride as usize;
        let line_height = FONT_HEIGHT;

        let y_top = top * line_height;
        let y_bottom = (bottom + 1) * line_height;
        let region_height = y_bottom - y_top;

        if region_height <= line_height {
            return;
        }

        unsafe {
            for y in 0..(region_height - line_height) {
                let src_offset = (y_top + y + line_height) * stride;
                let dst_offset = (y_top + y) * stride;
                core::ptr::copy(
                    fb_ptr.add(src_offset),
                    fb_ptr.add(dst_offset),
                    stride,
                );
            }
            // Clear the last line in the region
            let last_line_y = y_bottom - line_height;
            for y in 0..line_height {
                for x in 0..stride {
                    *fb_ptr.add((last_line_y + y) * stride + x) = self.bg_color;
                }
            }
        }
    }

    /// Scroll a region of the screen down by one text row.
    fn scroll_region_down(&self, top: usize, bottom: usize) {
        let fb_ptr = self.fb.base_address as *mut u32;
        let stride = self.fb.stride as usize;
        let line_height = FONT_HEIGHT;

        let y_top = top * line_height;
        let y_bottom = (bottom + 1) * line_height;
        let region_height = y_bottom - y_top;

        if region_height <= line_height {
            return;
        }

        unsafe {
            // Copy from bottom to top (reverse order to avoid overwriting)
            for y in (0..(region_height - line_height)).rev() {
                let src_offset = (y_top + y) * stride;
                let dst_offset = (y_top + y + line_height) * stride;
                core::ptr::copy(
                    fb_ptr.add(src_offset),
                    fb_ptr.add(dst_offset),
                    stride,
                );
            }
            // Clear the first line in the region
            for y in 0..line_height {
                for x in 0..stride {
                    *fb_ptr.add((y_top + y) * stride + x) = self.bg_color;
                }
            }
        }
    }

    /// Delete n characters at cursor position, shifting the rest left.
    fn delete_chars(&mut self, n: usize) {
        let fb_ptr = self.fb.base_address as *mut u32;
        let stride = self.fb.stride as usize;

        let shift = n.min(self.max_cols - self.col);
        let remaining = self.max_cols - self.col - shift;

        // Shift remaining characters left
        for c in 0..remaining {
            let src_col = self.col + shift + c;
            let dst_col = self.col + c;
            let src_x = src_col * FONT_WIDTH;
            let dst_x = dst_col * FONT_WIDTH;
            let y_start = self.row * FONT_HEIGHT;
            unsafe {
                for y in 0..FONT_HEIGHT {
                    let src_off = (y_start + y) * stride + src_x;
                    let dst_off = (y_start + y) * stride + dst_x;
                    core::ptr::copy(
                        fb_ptr.add(src_off),
                        fb_ptr.add(dst_off),
                        FONT_WIDTH,
                    );
                }
            }
        }

        // Clear vacated cells at the end
        for c in 0..shift {
            self.erase_cell(self.max_cols - 1 - c, self.row);
        }
    }

    /// Insert n blank characters at cursor position, shifting the rest right.
    fn insert_chars(&mut self, n: usize) {
        let fb_ptr = self.fb.base_address as *mut u32;
        let stride = self.fb.stride as usize;

        let shift = n.min(self.max_cols - self.col);
        let remaining = self.max_cols - self.col - shift;

        // Shift characters right (from end to avoid overwriting)
        for c in (0..remaining).rev() {
            let src_col = self.col + c;
            let dst_col = self.col + c + shift;
            let src_x = src_col * FONT_WIDTH;
            let dst_x = dst_col * FONT_WIDTH;
            let y_start = self.row * FONT_HEIGHT;
            unsafe {
                for y in 0..FONT_HEIGHT {
                    let src_off = (y_start + y) * stride + src_x;
                    let dst_off = (y_start + y) * stride + dst_x;
                    core::ptr::copy(
                        fb_ptr.add(src_off),
                        fb_ptr.add(dst_off),
                        FONT_WIDTH,
                    );
                }
            }
        }

        // Clear inserted cells
        for c in 0..shift {
            self.erase_cell(self.col + c, self.row);
        }
    }

    /// Insert n blank lines at the current row (scroll region down).
    fn insert_lines(&mut self, n: usize) {
        let bottom = self.scroll_bottom;
        for _ in 0..n {
            if self.row <= bottom {
                self.scroll_region_down(self.row, bottom);
            }
        }
    }

    /// Delete n lines at the current row (scroll region up).
    fn delete_lines(&mut self, n: usize) {
        let bottom = self.scroll_bottom;
        for _ in 0..n {
            if self.row <= bottom {
                self.scroll_region_up(self.row, bottom);
            }
        }
    }

    /// Backspace: erase last character.
    pub fn backspace(&mut self) {
        if self.col > 0 {
            self.hide_cursor();
            self.col -= 1;
            self.erase_cell(self.col, self.row);
        }
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            self.put_char(ch);
        }
        Ok(())
    }
}

/// Initialize the console driver.
pub fn init(boot_info: &BootInfo) {
    let mut console = Console::new(boot_info.framebuffer);
    console.clear();

    // Draw boot logo
    let logo = r"
    ___         __                  ____  _____
   /   |  _____/ /________  ___  __/ __ \/ ___/
  / /| | / ___/ __/ ___/ / / / |/_/ / / /\__ \
 / ___ |(__  ) /_/ /  / /_/ />  </ /_/ /___/ /
/_/  |_/____/\__/_/   \__, /_/|_|\____//____/
                      /____/

        Aether Kernel v0.1
";
    use fmt::Write;
    let _ = console.write_str(logo);
    let _ = console.write_str("\n");

    *CONSOLE.lock() = Some(console);
    crate::serial_println!("[CONSOLE] Framebuffer console initialized");
}

/// Reconfigure the console to use a new framebuffer (e.g. after SVGA init).
///
/// Updates base address, dimensions, stride; recomputes text grid; redraws logo.
pub fn reconfigure_framebuffer(base: u64, width: u32, height: u32, stride: u32) {
    use fmt::Write;
    // Convert physical framebuffer address to kernel virtual (PHYS_OFF + phys).
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let virt_base = if base < PHYS_OFF { base + PHYS_OFF } else { base };
    let mut guard = CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.fb.base_address = virt_base;
        console.fb.width = width;
        console.fb.height = height;
        console.fb.stride = stride;
        console.max_cols = width as usize / FONT_WIDTH;
        console.max_rows = height as usize / FONT_HEIGHT;
        console.scroll_bottom = console.max_rows.saturating_sub(1);
        // Reset cursor position and clear
        console.col = 0;
        console.row = 0;
        console.clear();
        let _ = console.write_str("[CONSOLE] Framebuffer reconfigured\n");
    }
    // Flush the display so the clear + text is visible immediately.
    crate::drivers::vmware_svga::update_screen();
    crate::serial_println!(
        "[CONSOLE] Reconfigured framebuffer: {}x{} @ 0x{:x} stride={}",
        width, height, base, stride
    );
}

/// Quiesce the framebuffer console on shutdown.
///
/// Clears cursor blink state, hides the cursor, and issues a final
/// framebuffer flush so the last console output is committed to VRAM before
/// the power-off path executes.  Safe to call with or without VMware SVGA.
pub fn stop() {
    crate::serial_println!("[CONSOLE] stop: finalizing framebuffer");
    if let Some(ref mut c) = *CONSOLE.lock() {
        c.cursor_visible = false;
        c.cursor_shown   = false;
    }
    crate::drivers::vmware_svga::update_screen();
}

/// Print to the framebuffer console (used by kprint! macro).
#[doc(hidden)]
pub fn _kprint(args: fmt::Arguments) {
    use fmt::Write;

    // If GUI capture is active, redirect output to the capture buffer.
    {
        let mut cap = GUI_CAPTURE.lock();
        if let Some(ref mut buf) = *cap {
            let _ = buf.write_fmt(args);
            return;
        }
    }

    if let Some(ref mut console) = *CONSOLE.lock() {
        let _ = console.write_fmt(args);
    }
    // Kick the SVGA device asynchronously so the display refreshes without
    // spin-waiting.  This keeps kprint latency minimal for interactive use.
    crate::drivers::vmware_svga::display_notify();
}

/// Kernel debug shell — simple command loop for Phase 0-3.
///
/// This will be replaced by Ascension (init) + Orbit (shell) in later phases.
pub fn kernel_shell() -> ! {
    use crate::arch::x86_64::irq;
    use fmt::Write;

    // Enable interrupts for keyboard input
    crate::hal::enable_interrupts();

    let mut cmd_buf = [0u8; 256];
    let mut cmd_len = 0usize;

    // Print prompt
    if let Some(ref mut console) = *CONSOLE.lock() {
        let _ = console.write_str("astryx> ");
    }

    loop {
        // Poll for keyboard input
        if let Some(scancode) = irq::read_scancode() {
            // Convert scancode to ASCII (simple US keyboard layout)
            if let Some(ch) = crate::drivers::keyboard::scancode_to_ascii(scancode) {
                match ch {
                    '\n' => {
                        // Execute command
                        if let Some(ref mut console) = *CONSOLE.lock() {
                            let _ = console.write_str("\n");
                        }

                        if cmd_len > 0 {
                            let cmd =
                                core::str::from_utf8(&cmd_buf[..cmd_len]).unwrap_or("");
                            execute_command(cmd);
                        }

                        cmd_len = 0;
                        if let Some(ref mut console) = *CONSOLE.lock() {
                            let _ = console.write_str("astryx> ");
                        }
                    }
                    '\x08' => {
                        // Backspace
                        if cmd_len > 0 {
                            cmd_len -= 1;
                            if let Some(ref mut console) = *CONSOLE.lock() {
                                console.backspace();
                            }
                        }
                    }
                    ch if ch.is_ascii() && !ch.is_ascii_control() => {
                        if cmd_len < 255 {
                            cmd_buf[cmd_len] = ch as u8;
                            cmd_len += 1;
                            if let Some(ref mut console) = *CONSOLE.lock() {
                                console.put_char(ch);
                            }
                        }
                    }
                    _ => {}
                }
            }
        } else {
            // No input — halt until next interrupt
            crate::hal::halt();
        }
    }
}

/// Execute a kernel shell command.
fn execute_command(cmd: &str) {
    let parts: alloc::vec::Vec<&str> = cmd.trim().split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    match parts[0] {
        "help" => {
            kprintln!("AstryxOS Kernel Shell (Aether v0.1)");
            kprintln!("Available commands:");
            kprintln!("  help       — Show this help message");
            kprintln!("  info       — Show system information");
            kprintln!("  mem        — Show memory statistics");
            kprintln!("  heap       — Show heap statistics");
            kprintln!("  ticks      — Show timer tick count");
            kprintln!("  clear      — Clear the screen");
            kprintln!("  echo       — Echo text");
            kprintln!("  ls [path]  — List directory contents");
            kprintln!("  cat <path> — Display file contents");
            kprintln!("  mkdir <p>  — Create a directory");
            kprintln!("  touch <p>  — Create an empty file");
            kprintln!("  rm <path>  — Remove a file/directory");
            kprintln!("  write <path> <text> — Write text to file");
            kprintln!("  stat <p>   — Show file/dir information");
            kprintln!("  ps         — List processes");
            kprintln!("  threads    — List threads");
            kprintln!("  sched      — Scheduler statistics");
            kprintln!("  ifconfig   — Network interface info");
            kprintln!("  ping <ip>  — Send ICMP echo request");
            kprintln!("  netstats   — Network statistics");
            kprintln!("  beep       — Play a beep tone");
            kprintln!("  audio      — Audio device status");
            kprintln!("  panic      — Trigger a kernel panic (test)");
            kprintln!("  reboot     — Reboot the system");
        }
        "info" => {
            kprintln!("AstryxOS — Aether Kernel v0.1");
            kprintln!("Architecture: x86_64 (UEFI)");
            kprintln!("Scheduler: CoreSched (round-robin, preemptive)");
            let pc = crate::proc::process_count();
            let tc = crate::proc::thread_count();
            kprintln!("Processes: {}   Threads: {}", pc, tc);
        }
        "mem" => {
            let (total, used) = crate::mm::pmm::stats();
            kprintln!("Physical Memory:");
            kprintln!("  Total: {} pages ({} MiB)", total, total * 4 / 1024);
            kprintln!("  Used:  {} pages ({} MiB)", used, used * 4 / 1024);
            kprintln!("  Free:  {} pages ({} MiB)", total - used, (total - used) * 4 / 1024);
        }
        "heap" => {
            let (total, alloc, free) = crate::mm::heap::stats();
            kprintln!("Kernel Heap:");
            kprintln!("  Total:     {} bytes ({} KiB)", total, total / 1024);
            kprintln!("  Allocated: {} bytes ({} KiB)", alloc, alloc / 1024);
            kprintln!("  Free:      {} bytes ({} KiB)", free, free / 1024);
        }
        "ticks" => {
            let ticks = crate::arch::x86_64::irq::get_ticks();
            kprintln!("Timer ticks: {} (~{} seconds)", ticks, ticks / 100);
        }
        "clear" => {
            if let Some(ref mut console) = *CONSOLE.lock() {
                console.clear();
            }
        }
        "echo" => {
            let text = if parts.len() > 1 {
                &cmd[5..] // Skip "echo "
            } else {
                ""
            };
            kprintln!("{}", text);
        }
        "ls" => {
            let path = if parts.len() > 1 { parts[1] } else { "/" };
            match crate::vfs::readdir(path) {
                Ok(entries) => {
                    for (name, ftype) in entries {
                        let type_char = match ftype {
                            crate::vfs::FileType::Directory => "d",
                            crate::vfs::FileType::RegularFile => "-",
                            crate::vfs::FileType::Pipe => "p",
                            _ => "?",
                        };
                        kprintln!("  {} {}", type_char, name);
                    }
                }
                Err(e) => kprintln!("ls: {}: {:?}", path, e),
            }
        }
        "cat" => {
            if parts.len() < 2 {
                kprintln!("Usage: cat <path>");
                return;
            }
            match crate::vfs::read_file(parts[1]) {
                Ok(data) => {
                    if let Ok(text) = core::str::from_utf8(&data) {
                        kprintln!("{}", text);
                    } else {
                        kprintln!("(binary data, {} bytes)", data.len());
                    }
                }
                Err(e) => kprintln!("cat: {}: {:?}", parts[1], e),
            }
        }
        "mkdir" => {
            if parts.len() < 2 {
                kprintln!("Usage: mkdir <path>");
                return;
            }
            match crate::vfs::mkdir(parts[1]) {
                Ok(()) => kprintln!("Created directory: {}", parts[1]),
                Err(e) => kprintln!("mkdir: {}: {:?}", parts[1], e),
            }
        }
        "touch" => {
            if parts.len() < 2 {
                kprintln!("Usage: touch <path>");
                return;
            }
            match crate::vfs::create_file(parts[1]) {
                Ok(()) => {}
                Err(e) => kprintln!("touch: {}: {:?}", parts[1], e),
            }
        }
        "rm" => {
            if parts.len() < 2 {
                kprintln!("Usage: rm <path>");
                return;
            }
            match crate::vfs::remove(parts[1]) {
                Ok(()) => kprintln!("Removed: {}", parts[1]),
                Err(e) => kprintln!("rm: {}: {:?}", parts[1], e),
            }
        }
        "write" => {
            if parts.len() < 3 {
                kprintln!("Usage: write <path> <text>");
                return;
            }
            let text_start = cmd.find(parts[2]).unwrap_or(0);
            let text = &cmd[text_start..];
            match crate::vfs::write_file(parts[1], text.as_bytes()) {
                Ok(n) => kprintln!("Wrote {} bytes to {}", n, parts[1]),
                Err(e) => kprintln!("write: {}: {:?}", parts[1], e),
            }
        }
        "stat" => {
            if parts.len() < 2 {
                kprintln!("Usage: stat <path>");
                return;
            }
            match crate::vfs::stat(parts[1]) {
                Ok(st) => {
                    kprintln!("  Inode: {}", st.inode);
                    kprintln!("  Type:  {:?}", st.file_type);
                    kprintln!("  Size:  {} bytes", st.size);
                }
                Err(e) => kprintln!("stat: {}: {:?}", parts[1], e),
            }
        }
        "ps" => {
            kprintln!("  PID  Name");
            kprintln!("  ---  ----");
            let count = crate::proc::process_count();
            for pid in 0..count as u64 + 1 {
                if let Some(name) = crate::proc::process_name(pid) {
                    kprintln!("  {:>3}  {}", pid, name);
                }
            }
        }
        "threads" => {
            kprintln!("  TID  State        Name");
            kprintln!("  ---  -----        ----");
            let count = crate::proc::thread_count();
            kprintln!("  ({} thread(s) total)", count);
            kprintln!("  Current TID: {}", crate::proc::current_tid());
        }
        "sched" => {
            let (total_switches, idle_switches) = crate::sched::stats();
            kprintln!("Scheduler Statistics:");
            kprintln!("  Context switches: {}", total_switches);
            kprintln!("  Idle switches:    {}", idle_switches);
        }
        "ifconfig" => {
            let mac = crate::net::our_mac();
            let ip = crate::net::our_ip();
            let gw = crate::net::gateway_ip();
            let mask = crate::net::subnet_mask();
            kprintln!("eth0:");
            kprintln!("  MAC:     {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            kprintln!("  IPv4:    {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            kprintln!("  Gateway: {}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
            kprintln!("  Netmask: {}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]);
        }
        "ping" => {
            if parts.len() < 2 {
                kprintln!("Usage: ping <ip>");
                return;
            }
            let octets: alloc::vec::Vec<&str> = parts[1].split('.').collect();
            if octets.len() != 4 {
                kprintln!("Invalid IP address format");
                return;
            }
            let ip: [u8; 4] = [
                octets[0].parse().unwrap_or(0),
                octets[1].parse().unwrap_or(0),
                octets[2].parse().unwrap_or(0),
                octets[3].parse().unwrap_or(0),
            ];
            kprintln!("PING {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            crate::net::icmp::send_ping(ip, 1, 1);
            kprintln!("Echo request sent (check serial for reply)");
        }
        "netstats" => {
            let (rx_pkts, tx_pkts, rx_bytes, tx_bytes) = crate::net::stats();
            kprintln!("Network Statistics:");
            kprintln!("  RX: {} packets, {} bytes", rx_pkts, rx_bytes);
            kprintln!("  TX: {} packets, {} bytes", tx_pkts, tx_bytes);
        }
        "beep" => {
            if crate::drivers::ac97::is_available() {
                kprintln!("♪ Beep!");
                crate::drivers::ac97::beep();
            } else {
                kprintln!("No audio device available");
            }
        }
        "audio" => {
            if crate::drivers::ac97::is_available() {
                let rate = crate::drivers::ac97::sample_rate();
                let (l, r) = crate::drivers::ac97::get_volume();
                kprintln!("AC97 Audio: {} Hz, volume L={} R={}", rate, l, r);
            } else {
                kprintln!("No audio device available");
            }
        }
        "panic" => {
            panic!("User-triggered kernel panic");
        }
        "reboot" => {
            kprintln!("Rebooting...");
            // SAFETY: Writing to keyboard controller reset port.
            unsafe {
                crate::hal::outb(0x64, 0xFE);
            }
        }
        _ => {
            kprintln!("Unknown command: '{}'. Type 'help' for available commands.", parts[0]);
        }
    }
}

use crate::{kprint, kprintln};
