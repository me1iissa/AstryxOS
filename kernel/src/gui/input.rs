//! Input Event Pump — translates raw hardware mouse/keyboard state into
//! window messages and routes them to the correct windows.
//!
//! Called once per compositor tick via [`pump_input`].  Reads the PS/2
//! keyboard scancode ring-buffer and current mouse state, performs hit
//! testing, and posts the appropriate `WM_*` / `WM_NC*` messages.

extern crate alloc;

use spin::Mutex;

use crate::arch::x86_64::irq;
use crate::drivers::mouse;
use crate::msg::message::*;
use crate::msg::queue;
use crate::msg::input as msg_input;
use crate::wm::desktop;
use crate::wm::hittest::{self, HitTestResult};
use crate::wm::window::{self, WindowHandle};
use crate::wm::zorder;

// ── Win32 HT* constants ────────────────────────────────────────────────────

/// Map a [`HitTestResult`] to its numeric Win32 `HT*` constant for wparam.
const fn ht_to_wparam(ht: HitTestResult) -> u64 {
    match ht {
        HitTestResult::Nowhere        => 0,   // HTNOWHERE
        HitTestResult::Client         => 1,   // HTCLIENT
        HitTestResult::TitleBar       => 2,   // HTCAPTION
        HitTestResult::MinimizeButton => 8,   // HTMINBUTTON
        HitTestResult::MaximizeButton => 9,   // HTMAXBUTTON
        HitTestResult::BorderLeft     => 10,  // HTLEFT
        HitTestResult::BorderRight    => 11,  // HTRIGHT
        HitTestResult::BorderTop      => 12,  // HTTOP
        HitTestResult::BorderTopLeft  => 13,  // HTTOPLEFT
        HitTestResult::BorderTopRight => 14,  // HTTOPRIGHT
        HitTestResult::BorderBottom   => 15,  // HTBOTTOM
        HitTestResult::BorderBottomLeft  => 16, // HTBOTTOMLEFT
        HitTestResult::BorderBottomRight => 17, // HTBOTTOMRIGHT
        HitTestResult::CloseButton    => 20,  // HTCLOSE
    }
}

// ── Scancode constants for modifier tracking ───────────────────────────────

const SC_LSHIFT: u8   = 0x2A;
const SC_RSHIFT: u8   = 0x36;
const SC_LCTRL: u8    = 0x1D;
const SC_LALT: u8     = 0x38;
// Break-code flag
const SC_RELEASE: u8  = 0x80;

// ── Input state ────────────────────────────────────────────────────────────

/// Tracks previous-frame state so we can detect deltas.
pub struct InputState {
    pub prev_buttons: u8,
    pub prev_mouse_x: i32,
    pub prev_mouse_y: i32,
    pub shift_held: bool,
    pub ctrl_held: bool,
    pub alt_held: bool,
}

impl InputState {
    const fn new() -> Self {
        Self {
            prev_buttons: 0,
            prev_mouse_x: 0,
            prev_mouse_y: 0,
            shift_held: false,
            ctrl_held: false,
            alt_held: false,
        }
    }
}

/// Global input state, protected by a spin-lock.
static INPUT_STATE: Mutex<InputState> = Mutex::new(InputState::new());

// ── Public API ─────────────────────────────────────────────────────────────

/// Initialise (or reset) the input state to match the current hardware.
pub fn init() {
    let mut state = INPUT_STATE.lock();
    let (mx, my) = mouse::position();
    state.prev_mouse_x = mx;
    state.prev_mouse_y = my;
    state.prev_buttons = mouse::buttons();
    state.shift_held = false;
    state.ctrl_held = false;
    state.alt_held = false;
}

/// Main per-tick input pump.
///
/// 1. Reads mouse hardware state and posts mouse / non-client messages.
/// 2. Drains the keyboard scancode ring-buffer and posts key messages.
pub fn pump_input() {
    let mut state = INPUT_STATE.lock();

    // ── Mouse ──────────────────────────────────────────────────────────
    let (mx, my) = mouse::position();
    let buttons = mouse::buttons();

    let mouse_moved = mx != state.prev_mouse_x || my != state.prev_mouse_y;
    let buttons_changed = buttons != state.prev_buttons;

    if mouse_moved || buttons_changed {
        process_mouse(&state, mx, my, buttons);
    }

    // Update previous mouse state *after* processing.
    state.prev_mouse_x = mx;
    state.prev_mouse_y = my;
    state.prev_buttons = buttons;

    // ── Keyboard ───────────────────────────────────────────────────────
    process_keyboard(&mut state);
}

// ── Mouse processing (internal) ────────────────────────────────────────────

/// Build the `MK_*` wparam flags from raw button bits and modifier state.
fn mouse_wparam(buttons: u8, state: &InputState) -> u64 {
    let mut wp: u64 = 0;
    if buttons & 0x01 != 0 { wp |= MK_LBUTTON; }
    if buttons & 0x02 != 0 { wp |= MK_RBUTTON; }
    if buttons & 0x04 != 0 { wp |= MK_MBUTTON; }
    if state.shift_held     { wp |= MK_SHIFT; }
    if state.ctrl_held      { wp |= MK_CONTROL; }
    wp
}

/// Determine the target window and post the correct mouse messages.
fn process_mouse(state: &InputState, mx: i32, my: i32, buttons: u8) {
    let prev_buttons = state.prev_buttons;
    let left_down_early = buttons & 0x01 != 0 && prev_buttons & 0x01 == 0;

    // Intercept clicks on the start menu overlay (drawn on top of windows).
    if left_down_early && crate::gui::content::handle_start_menu_click(mx, my) {
        return; // Click consumed by start menu.
    }

    // Determine target window: capture overrides hit-test.
    let target: Option<WindowHandle> = desktop::with_desktop(|desk| desk.capture_window)
        .or_else(|| zorder::window_from_point(mx, my));

    let handle = match target {
        Some(h) => h,
        None => return, // click on desktop background, no window
    };

    // Hit-test against the target window.
    let ht = window::with_window(handle, |w| hittest::hit_test(w, mx, my))
        .unwrap_or(HitTestResult::Nowhere);

    let lparam = make_lparam(mx, my);
    let mk_wparam = mouse_wparam(buttons, state);

    let left_down  = buttons & 0x01 != 0 && prev_buttons & 0x01 == 0;
    let left_up    = buttons & 0x01 == 0 && prev_buttons & 0x01 != 0;
    let right_down = buttons & 0x02 != 0 && prev_buttons & 0x02 == 0;
    let right_up   = buttons & 0x02 == 0 && prev_buttons & 0x02 != 0;
    let mid_down   = buttons & 0x04 != 0 && prev_buttons & 0x04 == 0;
    let mid_up     = buttons & 0x04 == 0 && prev_buttons & 0x04 != 0;

    // ── Focus management on left-button press ──────────────────────────
    if left_down {
        handle_focus_change(handle);
    }

    match ht {
        HitTestResult::Client => {
            // Convert screen coords → client coords for client-area msgs.
            let (cx, cy) = window::with_window(handle, |w| w.screen_to_client(mx, my))
                .unwrap_or((mx, my));
            let client_lp = make_lparam(cx, cy);

            queue::post_message(handle, WM_MOUSEMOVE, mk_wparam, client_lp);

            if left_down  { queue::post_message(handle, WM_LBUTTONDOWN, mk_wparam, client_lp); }
            if left_up    { queue::post_message(handle, WM_LBUTTONUP,   mk_wparam, client_lp); }
            if right_down { queue::post_message(handle, WM_RBUTTONDOWN, mk_wparam, client_lp); }
            if right_up   { queue::post_message(handle, WM_RBUTTONUP,   mk_wparam, client_lp); }
            if mid_down   { queue::post_message(handle, WM_MBUTTONDOWN, mk_wparam, client_lp); }
            if mid_up     { queue::post_message(handle, WM_MBUTTONUP,   mk_wparam, client_lp); }
        }
        HitTestResult::Nowhere => {
            // Point outside window — nothing to post.
        }
        _ => {
            // Non-client area (title bar, borders, buttons, etc.)
            let ht_wp = ht_to_wparam(ht);

            queue::post_message(handle, WM_NCMOUSEMOVE, ht_wp, lparam);

            if left_down { queue::post_message(handle, WM_NCLBUTTONDOWN, ht_wp, lparam); }
            if left_up   { queue::post_message(handle, WM_NCLBUTTONUP,   ht_wp, lparam); }
            // Right/middle non-client messages could be added here if needed.
        }
    }
}

/// Handle focus / z-order changes when the user clicks a window.
fn handle_focus_change(new_handle: WindowHandle) {
    let current_active = window::get_active_window();

    let already_active = match current_active {
        Some(cur) => cur == new_handle,
        None => false,
    };

    if already_active {
        return;
    }

    // Kill focus on old window.
    if let Some(old) = current_active {
        queue::post_message(old, WM_KILLFOCUS, new_handle, 0);
    }

    // Set focus on new window.
    queue::post_message(new_handle, WM_SETFOCUS, current_active.unwrap_or(0), 0);
    window::set_active_window(new_handle);
    zorder::bring_to_front(new_handle);
}

// ── Keyboard processing (internal) ─────────────────────────────────────────

/// Drain the scancode ring-buffer and post keyboard messages to the focused
/// window.  Also tracks modifier (shift / ctrl / alt) state in `InputState`.
fn process_keyboard(state: &mut InputState) {
    // Max scancodes to drain per tick to avoid starvation.
    const MAX_PER_TICK: usize = 64;

    let active_hwnd = window::get_active_window().unwrap_or(0);

    for _ in 0..MAX_PER_TICK {
        let scancode = match irq::read_scancode() {
            Some(sc) => sc,
            None => break,
        };

        // Track modifier keys locally.
        update_modifiers(state, scancode);

        // Determine press / release.
        let pressed = scancode & SC_RELEASE == 0;
        let base_sc = scancode & 0x7F;

        // Translate to a WM_KEYDOWN / WM_KEYUP message.
        if let Some(mut msg) = msg_input::translate_scancode(base_sc, pressed) {
            // Route to the active (focused) window.
            msg.hwnd = active_hwnd;
            queue::post_message(msg.hwnd, msg.msg, msg.wparam, msg.lparam);
        }
    }
}

/// Update the modifier tracking bits in `InputState`.
fn update_modifiers(state: &mut InputState, scancode: u8) {
    let pressed = scancode & SC_RELEASE == 0;
    let base = scancode & 0x7F;

    match base {
        SC_LSHIFT | SC_RSHIFT => state.shift_held = pressed,
        SC_LCTRL              => state.ctrl_held  = pressed,
        SC_LALT               => state.alt_held   = pressed,
        _ => {}
    }
}
