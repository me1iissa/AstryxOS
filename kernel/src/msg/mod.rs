//! Msg — Window Message System
//!
//! NT-inspired window messaging:
//! - Message types (WM_PAINT, WM_KEY*, WM_MOUSE*, etc.)
//! - Per-window message queues
//! - GetMessage / PeekMessage / DispatchMessage
//! - Input translation (scancode → VK, mouse → WM_MOUSE*)

extern crate alloc;

pub mod message;
pub mod queue;
pub mod dispatch;
pub mod input;

pub use message::*;
pub use queue::{
    broadcast_message, create_queue, destroy_queue, get_message, has_messages, peek_message,
    post_message, total_queued_messages,
};
pub use dispatch::{
    def_window_proc, dispatch_message, post_quit_message, process_messages, send_message,
    set_window_proc, WndProc,
};
pub use input::{translate_mouse, translate_scancode, vk_to_char};

/// Initialise the entire message subsystem.
pub fn init() {
    queue::init();
    dispatch::init();
    crate::serial_println!("[MSG] Window message system initialized");
}
