//! AstryxOS Demo Desktop Environment
//!
//! Creates a demonstration desktop layout with a taskbar and several
//! demo windows, then runs the main GUI event loop.

extern crate alloc;

use crate::wm::window::{WindowHandle, WindowStyle};
use crate::msg::message::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Height of the taskbar in pixels.
pub const TASKBAR_HEIGHT: u32 = 40;

/// Colour of the taskbar background (dark blue-gray, ARGB).
pub const TASKBAR_COLOR: u32 = 0xFF1A1A2E;

// ---------------------------------------------------------------------------
// Window handles for the demo windows (stored so we can reference them)
// ---------------------------------------------------------------------------

static TASKBAR_HANDLE: spin::Mutex<Option<WindowHandle>> = spin::Mutex::new(None);
static EXPLORER_HANDLE: spin::Mutex<Option<WindowHandle>> = spin::Mutex::new(None);
static TERMINAL_HANDLE: spin::Mutex<Option<WindowHandle>> = spin::Mutex::new(None);
static SETTINGS_HANDLE: spin::Mutex<Option<WindowHandle>> = spin::Mutex::new(None);
static EDITOR_HANDLE: spin::Mutex<Option<WindowHandle>> = spin::Mutex::new(None);
static CALCULATOR_HANDLE: spin::Mutex<Option<WindowHandle>> = spin::Mutex::new(None);

// ---------------------------------------------------------------------------
// launch_desktop — create the demo desktop layout
// ---------------------------------------------------------------------------

/// Focus an app window by name. Called from start menu click handler.
pub fn focus_app(name: &str) {
    let handle = match name {
        "explorer" => *EXPLORER_HANDLE.lock(),
        "terminal" => *TERMINAL_HANDLE.lock(),
        "settings" => *SETTINGS_HANDLE.lock(),
        "editor" => *EDITOR_HANDLE.lock(),
        "calculator" => *CALCULATOR_HANDLE.lock(),
        _ => None,
    };
    if let Some(h) = handle {
        // Unminimize if needed
        crate::wm::window::with_window_mut(h, |w| {
            if w.state == crate::wm::window::WindowState::Minimized {
                w.state = crate::wm::window::WindowState::Normal;
            }
        });
        crate::wm::set_active_window(h);
        crate::wm::zorder::bring_to_front(h);
    }
}

/// Creates the demo desktop layout: a taskbar pinned to the bottom of the
/// screen and three overlapped demo windows (File Explorer, Terminal, Settings).
pub fn launch_desktop() {
    // (a) Get screen dimensions from the active desktop.
    let (screen_width, screen_height) =
        crate::wm::desktop::with_desktop(|desk| (desk.width, desk.height));

    // (b) Taskbar — borderless, pinned to the bottom of the screen.
    let taskbar: WindowHandle = crate::wm::create_window(
        "Static",
        "Taskbar",
        0,
        (screen_height - TASKBAR_HEIGHT) as i32,
        screen_width,
        TASKBAR_HEIGHT,
        WindowStyle::borderless(),
        None,
    );
    crate::msg::queue::create_queue(taskbar);
    *TASKBAR_HANDLE.lock() = Some(taskbar);

    // (c) Demo Window 1 — File Explorer
    let file_explorer: WindowHandle = crate::wm::create_window(
        "Static",
        "File Explorer",
        100,
        100,
        600,
        400,
        WindowStyle::overlapped(),
        None,
    );
    crate::msg::queue::create_queue(file_explorer);
    *EXPLORER_HANDLE.lock() = Some(file_explorer);

    // (d) Demo Window 2 — Terminal
    let terminal: WindowHandle = crate::wm::create_window(
        "Edit",
        "Terminal",
        300,
        200,
        500,
        350,
        WindowStyle::overlapped(),
        None,
    );
    crate::msg::queue::create_queue(terminal);
    *TERMINAL_HANDLE.lock() = Some(terminal);

    // (e) Demo Window 3 — Settings
    let settings: WindowHandle = crate::wm::create_window(
        "Static",
        "Settings",
        500,
        150,
        450,
        300,
        WindowStyle::overlapped(),
        None,
    );
    crate::msg::queue::create_queue(settings);
    *SETTINGS_HANDLE.lock() = Some(settings);

    // (f) Demo Window 4 — Text Editor
    let editor: WindowHandle = crate::wm::create_window(
        "Edit",
        "Text Editor",
        150,
        120,
        520,
        380,
        WindowStyle::overlapped(),
        None,
    );
    crate::msg::queue::create_queue(editor);
    *EDITOR_HANDLE.lock() = Some(editor);

    // (g) Demo Window 5 — Calculator
    let calculator: WindowHandle = crate::wm::create_window(
        "Static",
        "Calculator",
        700,
        180,
        272,
        310,
        WindowStyle::overlapped(),
        None,
    );
    crate::msg::queue::create_queue(calculator);
    *CALCULATOR_HANDLE.lock() = Some(calculator);

    // (h) Set focus order (last created = front)
    crate::wm::set_active_window(file_explorer);
    crate::wm::zorder::bring_to_front(file_explorer);
    crate::wm::set_active_window(editor);
    crate::wm::zorder::bring_to_front(editor);
    crate::wm::set_active_window(calculator);
    crate::wm::zorder::bring_to_front(calculator);
    crate::wm::set_active_window(terminal);
    crate::wm::zorder::bring_to_front(terminal);
    crate::wm::set_active_window(settings);
    crate::wm::zorder::bring_to_front(settings);

    // (i) Render initial content into window surfaces.
    crate::gui::content::init_file_explorer(file_explorer);
    crate::gui::content::render_settings(settings);
    crate::gui::content::render_taskbar(taskbar);
    crate::gui::terminal::init(terminal);
    crate::gui::editor::init(editor);
    crate::gui::calculator::init(calculator);

    // (j) Log creation to serial.
    crate::serial_println!(
        "[GUI/Desktop] Demo desktop created ({}x{}) — taskbar={}, explorer={}, terminal={}, settings={}, editor={}, calculator={}",
        screen_width,
        screen_height,
        taskbar,
        file_explorer,
        terminal,
        settings,
        editor,
        calculator,
    );
}

// ---------------------------------------------------------------------------
// process_desktop_messages — drain and dispatch window messages
// ---------------------------------------------------------------------------

/// Process all pending window messages, routing them to the appropriate
/// handlers (interaction module for NC messages, terminal for keyboard, etc.).
fn process_desktop_messages() {
    let handles = crate::msg::queue::all_handles();

    for hwnd in handles {
        // Process up to N messages per window per tick to avoid starvation.
        for _ in 0..32 {
            let msg = match crate::msg::queue::get_message(hwnd) {
                Some(m) => m,
                None => break,
            };

            dispatch_desktop_message(hwnd, &msg);
        }
    }

    // Also drain system queue.
    for _ in 0..16 {
        match crate::msg::queue::get_system_message() {
            Some(msg) => {
                crate::msg::dispatch::dispatch_message(&msg);
            }
            None => break,
        }
    }
}

/// Route a single message to the appropriate handler.
fn dispatch_desktop_message(hwnd: WindowHandle, msg: &Message) {
    match msg.msg {
        // ── Non-client left button down: start drag / resize / button click ──
        WM_NCLBUTTONDOWN => {
            let ht = wparam_to_hittest(msg.wparam);
            let mx = get_x_lparam(msg.lparam);
            let my = get_y_lparam(msg.lparam);
            crate::gui::interaction::handle_nonclient_click(hwnd, ht, mx, my);
        }

        // ── Non-client left button up: end drag / resize ──
        WM_NCLBUTTONUP => {
            if crate::gui::interaction::is_dragging() {
                crate::gui::interaction::end_drag();
            }
        }

        // ── Mouse move (client): update drag if in progress ──
        WM_MOUSEMOVE => {
            if crate::gui::interaction::is_dragging() {
                // Convert client coords back to screen coords for drag.
                let (sx, sy) = crate::wm::window::with_window(hwnd, |w| {
                    w.client_to_screen(
                        get_x_lparam(msg.lparam),
                        get_y_lparam(msg.lparam),
                    )
                }).unwrap_or((get_x_lparam(msg.lparam), get_y_lparam(msg.lparam)));
                crate::gui::interaction::update_drag(sx, sy);
            }
        }

        // ── Non-client mouse move: update drag if in progress ──
        WM_NCMOUSEMOVE => {
            if crate::gui::interaction::is_dragging() {
                let mx = get_x_lparam(msg.lparam);
                let my = get_y_lparam(msg.lparam);
                crate::gui::interaction::update_drag(mx, my);
            }
        }

        // ── Client left button down: route to explorer / taskbar ──
        WM_LBUTTONDOWN => {
            let cx = get_x_lparam(msg.lparam);
            let cy = get_y_lparam(msg.lparam);

            let explorer_hwnd = *EXPLORER_HANDLE.lock();
            let taskbar_hwnd = *TASKBAR_HANDLE.lock();
            let calc_hwnd = *CALCULATOR_HANDLE.lock();

            if explorer_hwnd == Some(hwnd) {
                crate::gui::content::explorer_click(cx, cy);
            } else if taskbar_hwnd == Some(hwnd) {
                crate::gui::content::handle_taskbar_click(cx, cy);
            } else if calc_hwnd == Some(hwnd) {
                crate::gui::calculator::handle_click(cx, cy);
            } else {
                // Click on other windows → close start menu if open
                crate::gui::content::close_start_menu();
            }
        }

        // ── Client left button up: end drag if in progress ──
        WM_LBUTTONUP => {
            if crate::gui::interaction::is_dragging() {
                crate::gui::interaction::end_drag();
            }
        }

        // ── Keyboard: route to terminal, editor, or calculator ──
        WM_KEYDOWN | WM_KEYUP => {
            let term_hwnd = crate::gui::terminal::terminal_handle();
            let editor_hwnd = crate::gui::editor::editor_handle();
            let calc_hwnd = crate::gui::calculator::calc_handle();
            if term_hwnd == Some(hwnd) {
                crate::gui::terminal::handle_key(msg.msg, msg.wparam, msg.lparam);
            } else if editor_hwnd == Some(hwnd) {
                crate::gui::editor::handle_key(msg.msg, msg.wparam, msg.lparam);
            } else if calc_hwnd == Some(hwnd) {
                crate::gui::calculator::handle_key(msg.msg, msg.wparam, msg.lparam);
            }
        }

        // ── WM_SIZE: re-render app content after resize / maximize ──
        WM_SIZE => {
            let term_hwnd = crate::gui::terminal::terminal_handle();
            let editor_hwnd = crate::gui::editor::editor_handle();
            let calc_hwnd = crate::gui::calculator::calc_handle();
            let explorer_hwnd = *EXPLORER_HANDLE.lock();
            let settings_hwnd = *SETTINGS_HANDLE.lock();

            if term_hwnd == Some(hwnd) {
                crate::gui::terminal::re_render();
            } else if editor_hwnd == Some(hwnd) {
                crate::gui::editor::re_render();
            } else if calc_hwnd == Some(hwnd) {
                crate::gui::calculator::re_render();
            } else if explorer_hwnd == Some(hwnd) {
                crate::gui::content::render_file_explorer(hwnd);
            } else if settings_hwnd == Some(hwnd) {
                crate::gui::content::render_settings(hwnd);
            }
        }

        // ── WM_CLOSE: destroy the window ──
        WM_CLOSE => {
            crate::wm::destroy_window(hwnd);
        }

        // ── WM_DESTROY: clean up queue ──
        WM_DESTROY => {
            crate::msg::queue::destroy_queue(hwnd);
        }

        // ── Default: delegate to the registered WndProc or DefWindowProc ──
        _ => {
            crate::msg::dispatch::dispatch_message(msg);
        }
    }
}

/// Convert a wparam HT* value back to a `HitTestResult`.
fn wparam_to_hittest(wp: u64) -> crate::wm::hittest::HitTestResult {
    use crate::wm::hittest::HitTestResult;
    match wp {
        0  => HitTestResult::Nowhere,
        1  => HitTestResult::Client,
        2  => HitTestResult::TitleBar,
        8  => HitTestResult::MinimizeButton,
        9  => HitTestResult::MaximizeButton,
        10 => HitTestResult::BorderLeft,
        11 => HitTestResult::BorderRight,
        12 => HitTestResult::BorderTop,
        13 => HitTestResult::BorderTopLeft,
        14 => HitTestResult::BorderTopRight,
        15 => HitTestResult::BorderBottom,
        16 => HitTestResult::BorderBottomLeft,
        17 => HitTestResult::BorderBottomRight,
        20 => HitTestResult::CloseButton,
        _  => HitTestResult::Nowhere,
    }
}

// ---------------------------------------------------------------------------
// run_desktop_loop — main GUI event loop (never returns)
// ---------------------------------------------------------------------------

/// The main desktop event loop.
///
/// Enables hardware interrupts and then loops forever: pumping input events,
/// processing window messages, re-rendering dynamic content, compositing the
/// scene, and yielding to the next interrupt via `hlt`.
pub fn run_desktop_loop() -> ! {
    crate::hal::enable_interrupts();

    // ── SLIRP warmup ──
    // QEMU's SLIRP user-mode network backend may need a few seconds after
    // boot before it starts responding to ARP.  Now that interrupts are on
    // and we are late in the boot sequence, actively pre-resolve the
    // gateway so the first user command works immediately.
    {
        let gateway = crate::net::gateway_ip();
        crate::net::arp::send_request(gateway);
        let start = crate::arch::x86_64::irq::get_ticks();
        let max_wait = start + 300; // up to 3 seconds
        let mut last_probe = start;
        loop {
            crate::net::poll();
            if crate::net::arp::lookup(gateway).is_some() {
                crate::serial_println!("[NET] Gateway ARP resolved — network ready");
                break;
            }
            let now = crate::arch::x86_64::irq::get_ticks();
            if now >= max_wait {
                crate::serial_println!("[NET] SLIRP warmup timed out — network may be unavailable");
                break;
            }
            if now - last_probe >= 50 {
                crate::net::arp::send_request(gateway);
                last_probe = now;
            }
            for _ in 0..10_000 { unsafe { core::arch::asm!("pause"); } }
        }
    }

    let mut tick: u64 = 0;

    loop {
        // 1. Process mouse / keyboard events → post to window queues.
        crate::gui::input::pump_input();

        // 2. Drain and dispatch window messages (drag, resize, keys, etc.)
        process_desktop_messages();

        // 3. Poll the network stack so incoming packets (ARP, DNS, ICMP,
        //    TCP, etc.) are processed promptly even while idle.
        crate::net::poll();

        // 4. Re-render dynamic content periodically (taskbar every 30 ticks).
        if tick % 30 == 0 {
            if let Some(tb) = *TASKBAR_HANDLE.lock() {
                crate::gui::content::render_taskbar(tb);
            }
        }

        // 5. Composite and display all windows.
        crate::gui::compositor::compose();

        tick = tick.wrapping_add(1);

        // 6. Yield until the next interrupt.
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

// ---------------------------------------------------------------------------
// launch_desktop_with_timeout — for test mode
// ---------------------------------------------------------------------------

/// Creates the demo desktop layout and runs the event loop for exactly `ticks`
/// iterations, then returns the number of frames that were composed.
///
/// This is intended for automated / integration tests where the loop must
/// terminate.
pub fn launch_desktop_with_timeout(ticks: u64) -> u64 {
    // Build the same desktop layout.
    launch_desktop();

    crate::hal::enable_interrupts();

    let mut frames: u64 = 0;

    for _ in 0..ticks {
        crate::gui::input::pump_input();
        process_desktop_messages();
        crate::gui::compositor::compose();
        frames += 1;

        unsafe {
            core::arch::asm!("hlt");
        }
    }

    frames
}
