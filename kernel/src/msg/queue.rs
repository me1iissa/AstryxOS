//! Per-window message queues and a global queue registry.

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

use crate::msg::message::{Message, WM_PAINT, WM_TIMER};

/// Maximum number of messages a single queue will hold before dropping.
const MAX_QUEUE_SIZE: usize = 256;

// ── Per-window message queue ───────────────────────────────────────────────

/// A bounded message queue associated with a single window handle.
pub struct MessageQueue {
    /// Normal posted messages.
    pub messages: VecDeque<Message>,
    /// Coalesced WM_PAINT flag — generated only when the queue is otherwise empty.
    pub pending_paint: bool,
    /// Coalesced WM_TIMER flag — generated only when the queue is otherwise empty.
    pub pending_timer: bool,
}

impl MessageQueue {
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            pending_paint: false,
            pending_timer: false,
        }
    }

    /// Push a message. Returns `false` if the queue is full and the message
    /// was dropped.  WM_PAINT and WM_TIMER are coalesced into flags instead
    /// of being enqueued directly.
    pub fn push(&mut self, msg: Message) -> bool {
        match msg.msg {
            WM_PAINT => {
                self.pending_paint = true;
                true
            }
            WM_TIMER => {
                self.pending_timer = true;
                true
            }
            _ => {
                if self.messages.len() >= MAX_QUEUE_SIZE {
                    false
                } else {
                    self.messages.push_back(msg);
                    true
                }
            }
        }
    }

    /// Pop the next message.  Normal messages are returned first; once the
    /// queue is empty, a synthetic WM_PAINT or WM_TIMER is generated if the
    /// corresponding flag is set (matching NT behaviour where low-priority
    /// messages are only generated when nothing else is pending).
    pub fn pop(&mut self) -> Option<Message> {
        if let Some(msg) = self.messages.pop_front() {
            return Some(msg);
        }
        // Generate low-priority synthetic messages.
        if self.pending_paint {
            self.pending_paint = false;
            return Some(Message::new(0, WM_PAINT, 0, 0));
        }
        if self.pending_timer {
            self.pending_timer = false;
            return Some(Message::new(0, WM_TIMER, 0, 0));
        }
        None
    }

    /// Peek at the next message without removing it.
    pub fn peek(&self) -> Option<&Message> {
        self.messages.front()
    }

    /// Returns `true` when there are no queued messages and no pending
    /// synthetic messages.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty() && !self.pending_paint && !self.pending_timer
    }

    /// Number of normal (non-synthetic) messages currently queued.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Discard all messages and clear pending flags.
    pub fn clear(&mut self) {
        self.messages.clear();
        self.pending_paint = false;
        self.pending_timer = false;
    }
}

// ── Global queue registry ──────────────────────────────────────────────────

static QUEUES: Mutex<Option<BTreeMap<u64, MessageQueue>>> = Mutex::new(None);

/// System-wide message queue (hwnd == 0 / thread-level messages).
static SYSTEM_QUEUE: Mutex<Option<MessageQueue>> = Mutex::new(None);

/// Initialise the queue subsystem. Must be called once at startup.
pub fn init() {
    *QUEUES.lock() = Some(BTreeMap::new());
    *SYSTEM_QUEUE.lock() = Some(MessageQueue::new());
    crate::serial_println!("[MSG/QUEUE] Queue subsystem initialized");
}

/// Create a message queue for the given window handle.
pub fn create_queue(hwnd: u64) {
    if let Some(ref mut map) = *QUEUES.lock() {
        map.insert(hwnd, MessageQueue::new());
    }
}

/// Destroy the message queue associated with the given window handle.
pub fn destroy_queue(hwnd: u64) {
    if let Some(ref mut map) = *QUEUES.lock() {
        map.remove(&hwnd);
    }
}

/// Post a message to a window's queue (non-blocking enqueue).
/// Returns `false` when the queue is full or the window has no queue.
pub fn post_message(hwnd: u64, msg: u32, wparam: u64, lparam: u64) -> bool {
    if let Some(ref mut map) = *QUEUES.lock() {
        if let Some(queue) = map.get_mut(&hwnd) {
            return queue.push(Message::new(hwnd, msg, wparam, lparam));
        }
    }
    false
}

/// Broadcast a message to every window that has a queue.
pub fn broadcast_message(msg: u32, wparam: u64, lparam: u64) {
    if let Some(ref mut map) = *QUEUES.lock() {
        let hwnds: Vec<u64> = map.keys().cloned().collect();
        for hwnd in hwnds {
            if let Some(queue) = map.get_mut(&hwnd) {
                let _ = queue.push(Message::new(hwnd, msg, wparam, lparam));
            }
        }
    }
}

/// Peek at the next message for a window (non-blocking, does not remove).
pub fn peek_message(hwnd: u64) -> Option<Message> {
    if let Some(ref map) = *QUEUES.lock() {
        if let Some(queue) = map.get(&hwnd) {
            return queue.peek().copied();
        }
    }
    None
}

/// Retrieve and remove the next message for a window.
/// WM_PAINT / WM_TIMER are synthesised when the normal queue is empty and
/// their pending flag is set.
pub fn get_message(hwnd: u64) -> Option<Message> {
    if let Some(ref mut map) = *QUEUES.lock() {
        if let Some(queue) = map.get_mut(&hwnd) {
            return queue.pop();
        }
    }
    None
}

/// Returns `true` if the queue for `hwnd` has any pending messages.
pub fn has_messages(hwnd: u64) -> bool {
    if let Some(ref map) = *QUEUES.lock() {
        if let Some(queue) = map.get(&hwnd) {
            return !queue.is_empty();
        }
    }
    false
}

/// Total number of queued messages across all window queues.
pub fn total_queued_messages() -> usize {
    if let Some(ref map) = *QUEUES.lock() {
        map.values().map(|q| q.len()).sum()
    } else {
        0
    }
}

/// Return a snapshot of all registered window handles.
pub fn all_handles() -> Vec<u64> {
    if let Some(ref map) = *QUEUES.lock() {
        map.keys().cloned().collect()
    } else {
        Vec::new()
    }
}

// ── System queue ───────────────────────────────────────────────────────────

/// Post a message to the system (thread-level) queue.
pub fn post_system_message(msg: Message) {
    if let Some(ref mut q) = *SYSTEM_QUEUE.lock() {
        let _ = q.push(msg);
    }
}

/// Retrieve the next system message, if any.
pub fn get_system_message() -> Option<Message> {
    if let Some(ref mut q) = *SYSTEM_QUEUE.lock() {
        q.pop()
    } else {
        None
    }
}
