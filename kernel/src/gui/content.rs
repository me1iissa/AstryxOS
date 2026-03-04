//! Content Renderers — Draw window content into per-window pixel surfaces.
//!
//! Each window type (File Explorer, Settings, Taskbar) has a renderer that
//! draws text and simple graphics into the window's surface buffer.
//! The File Explorer maintains browsing state (current directory) and supports
//! click-to-navigate. The Taskbar shows a clock and start menu area.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::wm::window::{self, WindowHandle};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FONT_W: u32 = 8;
const FONT_H: u32 = 16;

// Colours
const COLOR_TEXT: u32 = 0xFFCCCCCC;
const COLOR_HEADER: u32 = 0xFF00BFFF;
const COLOR_DIR: u32 = 0xFF5DADE2;
const COLOR_FILE: u32 = 0xFFCCCCCC;
const COLOR_MUTED: u32 = 0xFF808080;
const COLOR_ACCENT: u32 = 0xFF50C878;
const COLOR_TASKBAR_BG: u32 = 0xFF1A1A2E;
const COLOR_TASKBAR_TEXT: u32 = 0xFFCCCCCC;
const COLOR_TASKBAR_ACTIVE: u32 = 0xFF2D5AA0;
const COLOR_TASKBAR_BUTTON: u32 = 0xFF252540;
const COLOR_SEPARATOR: u32 = 0xFF404040;

/// Row height for file entries (FONT_H + gap).
const FILE_ROW_H: u32 = FONT_H + 2;
/// Y-offset where file listing begins (after header + column headers).
const FILE_LIST_Y: i32 = (FONT_H as i32 + 12) + (FONT_H as i32 + 4) + 4;

// ---------------------------------------------------------------------------
// Start menu state
// ---------------------------------------------------------------------------

static START_MENU_OPEN: spin::Mutex<bool> = spin::Mutex::new(false);

/// Handle a click on the start menu popup overlay at screen coordinates.
/// Returns true if the click was consumed by a menu item.
/// Call this BEFORE dispatching the click to regular windows.
pub fn handle_start_menu_click(screen_x: i32, screen_y: i32) -> bool {
    if !is_start_menu_open() { return false; }

    // Get screen dimensions
    let (_sw, sh) = crate::gui::compositor::with_compositor(|c| {
        (c.screen_width, c.screen_height)
    }).unwrap_or((1024, 768));

    let popup_w: i32 = 200;
    let popup_h: i32 = 280;
    let popup_x: i32 = 4;
    let popup_y: i32 = sh as i32 - crate::gui::desktop::TASKBAR_HEIGHT as i32 - popup_h - 2;

    // Check if click is inside the popup
    if screen_x < popup_x || screen_x >= popup_x + popup_w
        || screen_y < popup_y || screen_y >= popup_y + popup_h
    {
        // Click outside menu → close it
        close_start_menu();
        return false;
    }

    // Determine which menu item was clicked.
    // Must match the layout in render_start_menu_to_backbuffer exactly.
    let item_heights: [(i32, &str); 12] = [
        (20, "AstryxOS"),     // header — not clickable
        (8,  ""),             // separator
        (20, "File Explorer"),
        (20, "Terminal"),
        (20, "Settings"),
        (8,  ""),             // separator
        (20, "Text Editor"),
        (20, "Calculator"),
        (8,  ""),             // separator
        (20, "System Info"),
        (8,  ""),             // separator
        (20, "Shutdown"),
    ];

    let mut item_y = popup_y + 8;
    for (item_h, label) in &item_heights {
        if screen_y >= item_y && screen_y < item_y + item_h {
            close_start_menu();
            match *label {
                "File Explorer" => {
                    crate::gui::desktop::focus_app("explorer");
                    return true;
                }
                "Terminal" => {
                    crate::gui::desktop::focus_app("terminal");
                    return true;
                }
                "Settings" => {
                    crate::gui::desktop::focus_app("settings");
                    return true;
                }
                "Text Editor" => {
                    crate::gui::desktop::focus_app("editor");
                    return true;
                }
                "Calculator" => {
                    crate::gui::desktop::focus_app("calculator");
                    return true;
                }
                "System Info" => {
                    crate::gui::desktop::focus_app("settings");
                    return true;
                }
                _ => return true, // header/separator — consume but do nothing
            }
        }
        item_y += item_h;
    }

    true // consumed (inside popup)
}

/// Toggle the start menu open/closed.
pub fn toggle_start_menu() {
    let mut open = START_MENU_OPEN.lock();
    *open = !*open;
}

/// Returns true if the start menu popup is currently open.
pub fn is_start_menu_open() -> bool {
    *START_MENU_OPEN.lock()
}

/// Close the start menu if it is open.
pub fn close_start_menu() {
    *START_MENU_OPEN.lock() = false;
}

/// Render the start menu popup overlay directly to the hardware framebuffer.
/// Call this AFTER compose() when the start menu is open.
pub fn render_start_menu_overlay(taskbar_handle: WindowHandle) {
    if !is_start_menu_open() { return; }

    let (_, th) = match window::with_window(taskbar_handle, |w| (w.client_width, w.client_height)) {
        Some(d) => d,
        None => return,
    };

    // Get compositor info (fb_base, screen dimensions)
    let info = crate::gui::compositor::with_compositor(|c| {
        (c.fb_base, c.screen_width, c.screen_height, c.fb_stride)
    });
    let (fb_base, sw, sh, fb_stride) = match info {
        Some(i) => i,
        None => return,
    };

    let fb = fb_base as *mut u32;

    let popup_w: u32 = 200;
    let popup_h: u32 = 280;
    let popup_bg: u32 = 0xFF1E1E2E;
    let popup_border: u32 = 0xFF444466;

    let popup_x: i32 = 4;
    let popup_y: i32 = sh as i32 - th as i32 - popup_h as i32 - 2;

    // Draw popup background
    for row in 0..popup_h as i32 {
        for col in 0..popup_w as i32 {
            let px = popup_x + col;
            let py = popup_y + row;
            if px >= 0 && px < sw as i32 && py >= 0 && py < sh as i32 {
                let idx = py as usize * fb_stride as usize + px as usize;
                unsafe { *fb.add(idx) = popup_bg; }
            }
        }
    }

    // Draw border
    for col in 0..popup_w as i32 {
        for &row in &[0i32, popup_h as i32 - 1] {
            let px = popup_x + col;
            let py = popup_y + row;
            if px >= 0 && px < sw as i32 && py >= 0 && py < sh as i32 {
                let idx = py as usize * fb_stride as usize + px as usize;
                unsafe { *fb.add(idx) = popup_border; }
            }
        }
    }
    for row in 0..popup_h as i32 {
        for &col in &[0i32, popup_w as i32 - 1] {
            let px = popup_x + col;
            let py = popup_y + row;
            if px >= 0 && px < sw as i32 && py >= 0 && py < sh as i32 {
                let idx = py as usize * fb_stride as usize + px as usize;
                unsafe { *fb.add(idx) = popup_border; }
            }
        }
    }

    // Draw menu items directly to framebuffer
    let items: [(&str, u32); 12] = [
        ("\x0F AstryxOS", 0xFF50C878),
        ("", 0),
        ("  File Explorer", 0xFFCCCCCC),
        ("  Terminal", 0xFFCCCCCC),
        ("  Settings", 0xFFCCCCCC),
        ("", 0),
        ("  Text Editor", 0xFFCCCCCC),
        ("  Calculator", 0xFFCCCCCC),
        ("", 0),
        ("  System Info", 0xFF808080),
        ("", 0),
        ("  Shutdown", 0xFFFF6666),
    ];

    let mut iy = popup_y + 8;
    let font = &crate::gui::compositor::VGA_FONT_8X16;
    for (text, color) in &items {
        if text.is_empty() {
            iy += 8;
            continue;
        }
        let mut cx = popup_x + 12;
        for ch_c in text.chars() {
            if ch_c < ' ' || ch_c > '~' { cx += FONT_W as i32; continue; }
            let c = ch_c as u32;
            let glyph_offset = ((c - 0x20) as usize) * 16;
            for row in 0..16i32 {
                let py = iy + row;
                if py < 0 || py >= sh as i32 { continue; }
                let byte = font[glyph_offset + row as usize];
                for col in 0..8i32 {
                    let px = cx + col;
                    if px < 0 || px >= sw as i32 { continue; }
                    if (byte >> (7 - col)) & 1 != 0 {
                        let idx = py as usize * fb_stride as usize + px as usize;
                        unsafe { *fb.add(idx) = *color; }
                    }
                }
            }
            cx += FONT_W as i32;
        }
        iy += FONT_H as i32 + 4;
    }
}

/// Draw the start menu popup into the compositor backbuffer (no flicker).
pub fn render_start_menu_to_backbuffer(buf: &mut [u32], sw: u32, sh: u32) {
    let popup_w: u32 = 200;
    let popup_h: u32 = 280;
    let popup_bg: u32 = 0xFF1E1E2E;
    let popup_border: u32 = 0xFF444466;

    let popup_x: i32 = 4;
    let popup_y: i32 = sh as i32 - crate::gui::desktop::TASKBAR_HEIGHT as i32 - popup_h as i32 - 2;

    let stride = sw as usize;

    // Draw popup background
    for row in 0..popup_h as i32 {
        for col in 0..popup_w as i32 {
            let px = popup_x + col;
            let py = popup_y + row;
            if px >= 0 && px < sw as i32 && py >= 0 && py < sh as i32 {
                let idx = py as usize * stride + px as usize;
                if idx < buf.len() { buf[idx] = popup_bg; }
            }
        }
    }

    // Border
    for col in 0..popup_w as i32 {
        for &row in &[0i32, popup_h as i32 - 1] {
            let px = popup_x + col;
            let py = popup_y + row;
            if px >= 0 && px < sw as i32 && py >= 0 && py < sh as i32 {
                let idx = py as usize * stride + px as usize;
                if idx < buf.len() { buf[idx] = popup_border; }
            }
        }
    }
    for row in 0..popup_h as i32 {
        for &col in &[0i32, popup_w as i32 - 1] {
            let px = popup_x + col;
            let py = popup_y + row;
            if px >= 0 && px < sw as i32 && py >= 0 && py < sh as i32 {
                let idx = py as usize * stride + px as usize;
                if idx < buf.len() { buf[idx] = popup_border; }
            }
        }
    }

    // Menu items
    let items: [(&str, u32); 12] = [
        ("\x0F AstryxOS", 0xFF50C878),
        ("", 0),
        ("  File Explorer", 0xFFCCCCCC),
        ("  Terminal", 0xFFCCCCCC),
        ("  Settings", 0xFFCCCCCC),
        ("", 0),
        ("  Text Editor", 0xFFCCCCCC),
        ("  Calculator", 0xFFCCCCCC),
        ("", 0),
        ("  System Info", 0xFF808080),
        ("", 0),
        ("  Shutdown", 0xFFFF6666),
    ];

    let mut iy = popup_y + 8;
    let font = &crate::gui::compositor::VGA_FONT_8X16;
    for (text, color) in &items {
        if text.is_empty() {
            iy += 8;
            continue;
        }
        let mut cx = popup_x + 12;
        for ch_c in text.chars() {
            if ch_c < ' ' || ch_c > '~' { cx += FONT_W as i32; continue; }
            let c = ch_c as u32;
            let glyph_offset = ((c - 0x20) as usize) * 16;
            for glyph_row in 0..16i32 {
                let py = iy + glyph_row;
                if py < 0 || py >= sh as i32 { continue; }
                let byte = font[glyph_offset + glyph_row as usize];
                for glyph_col in 0..8i32 {
                    let px = cx + glyph_col;
                    if px < 0 || px >= sw as i32 { continue; }
                    if (byte >> (7 - glyph_col)) & 1 != 0 {
                        let idx = py as usize * stride + px as usize;
                        if idx < buf.len() { buf[idx] = *color; }
                    }
                }
            }
            cx += FONT_W as i32;
        }
        iy += FONT_H as i32 + 4;
    }
}

/// Handle a click on the taskbar at client coordinates (cx, cy).
/// Returns true if the click was consumed (e.g., start button toggled).
pub fn handle_taskbar_click(cx: i32, _cy: i32) -> bool {
    // Start button area: x 4..84
    if cx >= 4 && cx < 84 {
        toggle_start_menu();
        return true;
    }
    // Click somewhere else on the taskbar → close start menu
    close_start_menu();
    false
}

// ---------------------------------------------------------------------------
// File Explorer state
// ---------------------------------------------------------------------------

/// Persistent state for the File Explorer window.
struct ExplorerState {
    handle: WindowHandle,
    cwd: String,
    /// Cached directory entries (name, FileType, size).
    entries: Vec<(String, crate::vfs::FileType, u64)>,
    /// Currently selected entry index.
    selected: Option<usize>,
    /// Scroll offset (entry index of first visible row).
    scroll: usize,
}

static EXPLORER: spin::Mutex<Option<ExplorerState>> = spin::Mutex::new(None);

/// Initialize the file explorer state and render it.
pub fn init_file_explorer(handle: WindowHandle) {
    let mut state = ExplorerState {
        handle,
        cwd: String::from("/"),
        entries: Vec::new(),
        selected: None,
        scroll: 0,
    };
    state.refresh_entries();
    render_explorer_surface(&state);
    *EXPLORER.lock() = Some(state);
}

/// Navigate the file explorer to a new directory.
pub fn explorer_navigate(path: &str) {
    let mut guard = EXPLORER.lock();
    if let Some(ref mut st) = *guard {
        st.cwd = String::from(path);
        st.selected = None;
        st.scroll = 0;
        st.refresh_entries();
        render_explorer_surface(st);
    }
}

/// Handle a click at the given client-area coordinates inside the file explorer.
pub fn explorer_click(_cx: i32, cy: i32) {
    let mut guard = EXPLORER.lock();
    let st = match guard.as_mut() {
        Some(s) => s,
        None => return,
    };

    // Check if click is in the file list area
    if cy < FILE_LIST_Y { return; }

    let row_offset = ((cy - FILE_LIST_Y) as u32) / FILE_ROW_H;
    let entry_idx = st.scroll + row_offset as usize;

    if entry_idx >= st.entries.len() { return; }

    // Double-click logic: if already selected, navigate into directory
    if st.selected == Some(entry_idx) {
        let (ref name, ref ftype, _) = st.entries[entry_idx];
        if *ftype == crate::vfs::FileType::Directory {
            // Navigate into it
            let new_path = if st.cwd == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", st.cwd, name)
            };
            st.cwd = new_path;
            st.selected = None;
            st.scroll = 0;
            st.refresh_entries();
        }
    } else {
        st.selected = Some(entry_idx);
    }
    render_explorer_surface(st);
}

/// Navigate the file explorer up one directory level.
pub fn explorer_go_up() {
    let mut guard = EXPLORER.lock();
    let st = match guard.as_mut() {
        Some(s) => s,
        None => return,
    };
    if st.cwd != "/" {
        if let Some(pos) = st.cwd.rfind('/') {
            let parent = if pos == 0 { String::from("/") } else { String::from(&st.cwd[..pos]) };
            st.cwd = parent;
            st.selected = None;
            st.scroll = 0;
            st.refresh_entries();
            render_explorer_surface(st);
        }
    }
}

/// Re-render the file explorer from its current state (e.g., after window resize).
pub fn render_file_explorer(handle: WindowHandle) {
    let guard = EXPLORER.lock();
    if let Some(ref st) = *guard {
        if st.handle == handle {
            render_explorer_surface(st);
            return;
        }
    }
    drop(guard);
    // Not initialized yet, initialize it
    init_file_explorer(handle);
}

impl ExplorerState {
    fn refresh_entries(&mut self) {
        self.entries.clear();
        // Add ".." for non-root directories
        if self.cwd != "/" {
            self.entries.push((String::from(".."), crate::vfs::FileType::Directory, 0));
        }
        if let Ok(entries) = crate::vfs::readdir(&self.cwd) {
            for (name, ftype) in entries {
                let full_path = if self.cwd == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", self.cwd, name)
                };
                let size = crate::vfs::stat(&full_path).map(|s| s.size).unwrap_or(0);
                self.entries.push((name, ftype, size));
            }
        }
    }
}

/// Render the explorer's current state into its window surface.
fn render_explorer_surface(st: &ExplorerState) {
    let (cw, ch) = match window::with_window(st.handle, |w| (w.client_width, w.client_height)) {
        Some(d) => d,
        None => return,
    };
    if cw == 0 || ch == 0 { return; }

    let bg: u32 = 0xFF1E1E1E;
    let size = (cw as usize) * (ch as usize);
    let mut surface = vec![bg; size];
    let stride = cw;
    let cols = (cw / FONT_W) as usize;

    let x: i32 = 8;
    let mut y: i32 = 6;

    // Header bar with current path
    draw_filled_rect(&mut surface, stride, 0, 0, cw, FONT_H + 10, 0xFF252530);
    let path_display = format!("  {}  ({})", st.cwd, if st.cwd == "/" { "root" } else { "dir" });
    draw_text(&mut surface, stride, x, 5, &path_display, COLOR_HEADER, cols);
    // Draw back button if not at root
    if st.cwd != "/" {
        let back_text = " [..] ";
        let back_x = cw as i32 - (back_text.len() as i32 + 1) * FONT_W as i32;
        draw_text(&mut surface, stride, back_x, 5, back_text, COLOR_ACCENT, 8);
    }
    y += FONT_H as i32 + 12;

    // Separator
    draw_hline(&mut surface, stride, 0, y - 2, cw, COLOR_SEPARATOR);

    // Column headers
    draw_text(&mut surface, stride, x, y, "Name", COLOR_MUTED, cols);
    draw_text(&mut surface, stride, x + 200, y, "Type", COLOR_MUTED, cols);
    draw_text(&mut surface, stride, x + 320, y, "Size", COLOR_MUTED, cols);
    y += FONT_H as i32 + 4;
    draw_hline(&mut surface, stride, x, y - 2, cw - 16, 0xFF333333);

    // File listing
    let status_y = ch as i32 - FONT_H as i32 - 6;
    let max_visible = ((status_y - y) as u32 / FILE_ROW_H) as usize;

    let visible_end = (st.scroll + max_visible).min(st.entries.len());
    for i in st.scroll..visible_end {
        let (ref name, ref ftype, fsize) = st.entries[i];

        // Highlight selected row
        if st.selected == Some(i) {
            draw_filled_rect(&mut surface, stride, 0, y - 1, cw, FILE_ROW_H, 0xFF2A2A4A);
        }

        let (icon, color, type_str) = match ftype {
            crate::vfs::FileType::Directory => ("DIR", COLOR_DIR, "Directory"),
            crate::vfs::FileType::RegularFile => ("   ", COLOR_FILE, "File"),
            crate::vfs::FileType::SymLink => ("LNK", COLOR_ACCENT, "Symlink"),
            _ => ("   ", COLOR_FILE, "Special"),
        };
        let entry_text = format!("{} {}", icon, name);
        draw_text(&mut surface, stride, x, y, &entry_text, color, cols);
        draw_text(&mut surface, stride, x + 200, y, type_str, COLOR_MUTED, cols);
        if *ftype != crate::vfs::FileType::Directory {
            let size_str = format_size(fsize);
            draw_text(&mut surface, stride, x + 320, y, &size_str, COLOR_MUTED, cols);
        }
        y += FILE_ROW_H as i32;
    }

    // Status bar
    if status_y > y - FILE_ROW_H as i32 {
        draw_filled_rect(&mut surface, stride, 0, status_y - 4, cw, FONT_H + 10, 0xFF252530);
        draw_hline(&mut surface, stride, 0, status_y - 4, cw, COLOR_SEPARATOR);
        let status_text = format!("{} items — AstryxOS File Explorer", st.entries.len());
        draw_text(&mut surface, stride, x, status_y, &status_text, COLOR_MUTED, cols);
    }

    window::with_window_mut(st.handle, |w| {
        w.surface = surface;
    });
}

/// Format a byte count as a human-readable size.
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} MB", bytes / (1024 * 1024))
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Render the Settings window content (system information).
pub fn render_settings(handle: WindowHandle) {
    let (cw, ch) = match window::with_window(handle, |w| (w.client_width, w.client_height)) {
        Some(d) => d,
        None => return,
    };
    if cw == 0 || ch == 0 { return; }

    let bg: u32 = 0xFF1E1E1E;
    let size = (cw as usize) * (ch as usize);
    let mut surface = vec![bg; size];
    let stride = cw;
    let cols = (cw / FONT_W) as usize;

    let x: i32 = 12;
    let mut y: i32 = 8;

    // Header
    draw_filled_rect(&mut surface, stride, 0, 0, cw, FONT_H + 10, 0xFF252530);
    draw_text(&mut surface, stride, x, 5, "System Settings", COLOR_HEADER, cols);
    y += FONT_H as i32 + 14;
    draw_hline(&mut surface, stride, 0, y - 4, cw, COLOR_SEPARATOR);

    // System section
    draw_text(&mut surface, stride, x, y, "System Information", COLOR_ACCENT, cols);
    y += FONT_H as i32 + 8;

    let info_lines: Vec<(&str, String)> = {
        let (total, used, free) = crate::mm::heap::stats();
        let snap = crate::perf::snapshot();
        let screen = crate::wm::desktop::screen_size();
        let cpu_count = crate::arch::x86_64::apic::cpu_count();

        alloc::vec![
            ("OS:",        String::from("AstryxOS")),
            ("Kernel:",    String::from("Aether v0.1")),
            ("Arch:",      String::from("x86_64 (UEFI)")),
            ("CPUs:",      format!("{}", cpu_count)),
            ("Display:",   format!("{}x{}", screen.0, screen.1)),
            ("Uptime:",    format!("{} seconds", snap.uptime_seconds)),
            ("Heap Total:", format!("{} KB", total / 1024)),
            ("Heap Used:", format!("{} KB", used / 1024)),
            ("Heap Free:", format!("{} KB", free / 1024)),
            ("Windows:",   format!("{}", crate::wm::get_window_count())),
        ]
    };

    for (label, value) in &info_lines {
        if y + FONT_H as i32 > ch as i32 - 20 {
            break;
        }
        draw_text(&mut surface, stride, x + 4, y, label, COLOR_MUTED, cols);
        draw_text(&mut surface, stride, x + 120, y, value, COLOR_TEXT, cols);
        y += FONT_H as i32 + 4;
    }

    // Separator
    y += 8;
    if y + 20 < ch as i32 {
        draw_hline(&mut surface, stride, x, y, cw - 24, 0xFF333333);
        y += 12;
        draw_text(&mut surface, stride, x, y, "Kernel Subsystems", COLOR_ACCENT, cols);
        y += FONT_H as i32 + 6;
        let subsystems = ["HAL", "MM", "VFS", "Proc", "WM", "GDI", "MSG", "GUI", "Net", "SMP"];
        for ss in &subsystems {
            if y + FONT_H as i32 > ch as i32 {
                break;
            }
            let line = format!("  [OK]  {}", ss);
            draw_text(&mut surface, stride, x, y, &line, COLOR_ACCENT, cols);
            y += FONT_H as i32 + 2;
        }
    }

    window::with_window_mut(handle, |w| {
        w.surface = surface;
    });
}

// ---------------------------------------------------------------------------
// Taskbar
// ---------------------------------------------------------------------------

/// Render the taskbar window content (logo + window buttons).
pub fn render_taskbar(handle: WindowHandle) {
    let (cw, ch) = match window::with_window(handle, |w| (w.client_width, w.client_height)) {
        Some(d) => d,
        None => return,
    };
    if cw == 0 || ch == 0 { return; }

    let size = (cw as usize) * (ch as usize);
    let mut surface = vec![COLOR_TASKBAR_BG; size];
    let stride = cw;

    // Top separator line
    draw_hline(&mut surface, stride, 0, 0, cw, 0xFF333355);

    // "Start" button area
    let start_w: u32 = 80;
    draw_filled_rect(&mut surface, stride, 4, 4, start_w, ch - 8, COLOR_TASKBAR_BUTTON);
    draw_text(&mut surface, stride, 14, (ch as i32 - FONT_H as i32) / 2, "AstryxOS", 0xFF50C878, 10);

    // Window buttons (from z-order, skip taskbar itself)
    let z_order = crate::wm::zorder::get_z_order();
    let mut btn_x: i32 = start_w as i32 + 16;
    let btn_h = ch - 8;

    for &wh in z_order.iter() {
        let info = window::with_window(wh, |w| {
            (w.title.clone(), w.focused, w.style.has_title_bar, w.handle)
        });
        let (title, focused, has_tb, _h) = match info {
            Some(i) => i,
            None => continue,
        };
        // Skip the taskbar itself and windows without title bars.
        if !has_tb {
            continue;
        }

        let btn_w: u32 = 120;
        if btn_x + btn_w as i32 + 8 > cw as i32 - 80 {
            break;
        }

        let btn_bg = if focused { COLOR_TASKBAR_ACTIVE } else { COLOR_TASKBAR_BUTTON };
        draw_filled_rect(&mut surface, stride, btn_x, 4, btn_w, btn_h, btn_bg);

        // Title text (clamp to button width)
        let max_chars = ((btn_w - 10) / FONT_W) as usize;
        let display: &str = if title.len() <= max_chars {
            &title
        } else if max_chars > 3 {
            &title[..max_chars]
        } else {
            ""
        };
        let ty = (ch as i32 - FONT_H as i32) / 2;
        draw_text(&mut surface, stride, btn_x + 6, ty, display, COLOR_TASKBAR_TEXT, max_chars + 1);

        btn_x += btn_w as i32 + 4;
    }

    // Clock area on the right — show HH:MM:SS from uptime
    let snap = crate::perf::snapshot();
    let secs = snap.uptime_seconds;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let clock_text = format!("{:02}:{:02}:{:02}", h, m, s);
    let clock_x = cw as i32 - (clock_text.len() as i32 + 2) * FONT_W as i32;
    let clock_y = (ch as i32 - FONT_H as i32) / 2;
    draw_text(&mut surface, stride, clock_x, clock_y, &clock_text, 0xFFDDDDDD, 12);

    window::with_window_mut(handle, |w| {
        w.surface = surface;
    });
}

// ---------------------------------------------------------------------------
// Drawing helpers (operate on surface Vec<u32>)
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

fn draw_hline(buf: &mut [u32], stride: u32, x: i32, y: i32, len: u32, color: u32) {
    if y < 0 { return; }
    for i in 0..len as i32 {
        let px = x + i;
        if px < 0 || px >= stride as i32 { continue; }
        let idx = y as usize * stride as usize + px as usize;
        if idx < buf.len() {
            buf[idx] = color;
        }
    }
}
