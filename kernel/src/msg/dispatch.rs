//! Message dispatch — GetMessage / DispatchMessage / SendMessage loop.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use crate::msg::message::{Message, WM_CLOSE, WM_DESTROY, WM_ERASEBKGND, WM_PAINT, WM_QUIT};
use crate::msg::queue;

// ── Window procedure type ──────────────────────────────────────────────────

/// Signature for a window procedure.
pub type WndProc = fn(hwnd: u64, msg: u32, wparam: u64, lparam: u64) -> u64;

// ── Window procedure registry ──────────────────────────────────────────────

static WNDPROCS: Mutex<Option<BTreeMap<u64, WndProc>>> = Mutex::new(None);

/// Initialise the dispatch subsystem. Must be called once at startup.
pub fn init() {
    *WNDPROCS.lock() = Some(BTreeMap::new());
    crate::serial_println!("[MSG/DISPATCH] Dispatch subsystem initialized");
}

/// Register (or replace) the window procedure for a window.
pub fn set_window_proc(hwnd: u64, proc_fn: WndProc) {
    if let Some(ref mut map) = *WNDPROCS.lock() {
        map.insert(hwnd, proc_fn);
    }
}

/// Look up the window procedure for a window.
pub fn get_window_proc(hwnd: u64) -> Option<WndProc> {
    if let Some(ref map) = *WNDPROCS.lock() {
        map.get(&hwnd).copied()
    } else {
        None
    }
}

// ── Default window procedure ───────────────────────────────────────────────

/// Default window procedure — provides default behaviour for unhandled
/// messages, analogous to `DefWindowProc` in Win32.
pub fn def_window_proc(hwnd: u64, msg: u32, _wparam: u64, _lparam: u64) -> u64 {
    match msg {
        WM_CLOSE => {
            // Default: post WM_DESTROY to begin teardown.
            queue::post_message(hwnd, WM_DESTROY, 0, 0);
            0
        }
        WM_DESTROY => 0,
        WM_ERASEBKGND => {
            // Return 1 = background erased (handled).
            1
        }
        WM_PAINT => {
            // Default: validate the window (nothing to draw).
            0
        }
        _ => 0,
    }
}

// ── Dispatch helpers ───────────────────────────────────────────────────────

/// Dispatch a message to its window's registered procedure.  Falls back to
/// `def_window_proc` when no procedure has been registered.
pub fn dispatch_message(msg: &Message) -> u64 {
    if let Some(proc_fn) = get_window_proc(msg.hwnd) {
        proc_fn(msg.hwnd, msg.msg, msg.wparam, msg.lparam)
    } else {
        def_window_proc(msg.hwnd, msg.msg, msg.wparam, msg.lparam)
    }
}

/// Send a message synchronously — calls the window procedure directly
/// without enqueuing.
pub fn send_message(hwnd: u64, msg: u32, wparam: u64, lparam: u64) -> u64 {
    dispatch_message(&Message::new(hwnd, msg, wparam, lparam))
}

/// Drain all pending messages for every registered window and the system
/// queue, dispatching each one.  Returns the total number of messages
/// processed.
pub fn process_messages() -> u32 {
    let mut count = 0u32;

    let handles: Vec<u64> = queue::all_handles();

    for hwnd in handles {
        while let Some(msg) = queue::get_message(hwnd) {
            dispatch_message(&msg);
            count += 1;
        }
    }

    // Drain the system queue as well.
    while let Some(msg) = queue::get_system_message() {
        dispatch_message(&msg);
        count += 1;
    }

    count
}

/// Convenience: post `WM_QUIT` to the system queue with the given exit code.
pub fn post_quit_message(exit_code: i32) {
    let msg = Message::new(0, WM_QUIT, exit_code as u64, 0);
    queue::post_system_message(msg);
}
