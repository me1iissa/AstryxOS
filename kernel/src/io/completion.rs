//! I/O Completion Ports — NT-Inspired Async Completion Queue
//!
//! An I/O Completion Port (IOCP) is a queue of completion packets that worker
//! threads can dequeue from.  This is the NT async I/O completion mechanism.
//!
//! # Architecture
//! - **IoCompletionPort** — The port object itself (packet queue + metadata).
//! - **IoCompletionPacket** — A single queued completion result.
//! - **AssociatedHandle** — Binding between a file/device handle and a key.
//! - Global registry of all ports keyed by auto-incrementing ID.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// ============================================================================
// IoStatus
// ============================================================================

/// Status code for an I/O completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoStatus {
    Success,
    Pending,
    Error(i32),
    Cancelled,
    EndOfFile,
    BufferOverflow,
    Timeout,
}

// ============================================================================
// IoCompletionPacket
// ============================================================================

/// A single completion packet queued to an IOCP.
#[derive(Debug, Clone)]
pub struct IoCompletionPacket {
    /// Completion key associated with the file handle.
    pub key: u64,
    /// Operation result status.
    pub status: IoStatus,
    /// Bytes transferred or other information.
    pub information: u64,
    /// User-provided overlapped pointer / context.
    pub overlapped: u64,
}

// ============================================================================
// AssociatedHandle
// ============================================================================

/// Association between a file/device handle and a completion key.
#[derive(Debug, Clone)]
pub struct AssociatedHandle {
    /// File or device handle value.
    pub handle: u64,
    /// User-defined key returned with completions.
    pub completion_key: u64,
}

// ============================================================================
// IoCompletionPort
// ============================================================================

/// An I/O completion port — a FIFO queue of completion packets.
pub struct IoCompletionPort {
    /// Unique port identifier.
    pub id: u64,
    /// Pending completion packets (FIFO).
    pub queue: VecDeque<IoCompletionPacket>,
    /// Concurrency hint — maximum threads processing simultaneously.
    pub max_concurrent_threads: u32,
    /// Number of threads currently processing a packet.
    pub active_threads: u32,
    /// Number of threads blocked in `dequeue_completion`.
    pub waiter_count: u32,
    /// File handles bound to this port.
    pub associated_handles: Vec<AssociatedHandle>,
    /// Lifetime statistics — total packets ever enqueued.
    pub total_packets_queued: u64,
    /// Lifetime statistics — total packets ever dequeued.
    pub total_packets_dequeued: u64,
}

// ============================================================================
// Global Registry
// ============================================================================

static COMPLETION_PORTS: Mutex<Option<BTreeMap<u64, IoCompletionPort>>> = Mutex::new(None);
static NEXT_PORT_ID: AtomicU64 = AtomicU64::new(1);

/// Initialize the completion port subsystem.  Must be called once at boot.
pub fn init() {
    *COMPLETION_PORTS.lock() = Some(BTreeMap::new());
    crate::serial_println!("[IO/IOCP] Completion port subsystem initialized");
}

// ============================================================================
// Public API
// ============================================================================

/// Create a new I/O completion port and return its unique ID.
pub fn create_completion_port(max_concurrent: u32) -> u64 {
    let id = NEXT_PORT_ID.fetch_add(1, Ordering::Relaxed);
    let port = IoCompletionPort {
        id,
        queue: VecDeque::new(),
        max_concurrent_threads: max_concurrent,
        active_threads: 0,
        waiter_count: 0,
        associated_handles: Vec::new(),
        total_packets_queued: 0,
        total_packets_dequeued: 0,
    };

    let mut ports = COMPLETION_PORTS.lock();
    if let Some(ref mut map) = *ports {
        map.insert(id, port);
    }
    id
}

/// Destroy an I/O completion port. Returns `true` if the port existed.
pub fn close_completion_port(port_id: u64) -> bool {
    let mut ports = COMPLETION_PORTS.lock();
    if let Some(ref mut map) = *ports {
        map.remove(&port_id).is_some()
    } else {
        false
    }
}

/// Associate a file/device handle with a completion port and key.
/// Returns `true` on success, `false` if the port does not exist.
pub fn associate_handle(port_id: u64, handle: u64, completion_key: u64) -> bool {
    let mut ports = COMPLETION_PORTS.lock();
    if let Some(ref mut map) = *ports {
        if let Some(port) = map.get_mut(&port_id) {
            port.associated_handles.push(AssociatedHandle {
                handle,
                completion_key,
            });
            return true;
        }
    }
    false
}

/// Remove the association for a handle from a completion port.
/// Returns `true` if the handle was found and removed.
pub fn disassociate_handle(port_id: u64, handle: u64) -> bool {
    let mut ports = COMPLETION_PORTS.lock();
    if let Some(ref mut map) = *ports {
        if let Some(port) = map.get_mut(&port_id) {
            let before = port.associated_handles.len();
            port.associated_handles.retain(|a| a.handle != handle);
            return port.associated_handles.len() < before;
        }
    }
    false
}

/// Post a completion packet to the port's queue.
/// Returns `true` on success, `false` if the port does not exist.
pub fn post_completion(port_id: u64, packet: IoCompletionPacket) -> bool {
    let mut ports = COMPLETION_PORTS.lock();
    if let Some(ref mut map) = *ports {
        if let Some(port) = map.get_mut(&port_id) {
            port.queue.push_back(packet);
            port.total_packets_queued += 1;
            return true;
        }
    }
    false
}

/// Dequeue a completion packet from the port.
///
/// If the queue is empty the call spin-yields up to `timeout_ticks` ticks
/// (similar to the ke wait infrastructure).  `None` timeout means infinite
/// wait; `Some(0)` is a poll.
pub fn dequeue_completion(
    port_id: u64,
    timeout_ticks: Option<u64>,
) -> Option<IoCompletionPacket> {
    let start = crate::arch::x86_64::irq::get_ticks();

    // Increment waiter count
    {
        let mut ports = COMPLETION_PORTS.lock();
        if let Some(ref mut map) = *ports {
            if let Some(port) = map.get_mut(&port_id) {
                port.waiter_count += 1;
            }
        }
    }

    loop {
        // Try to grab a packet
        {
            let mut ports = COMPLETION_PORTS.lock();
            if let Some(ref mut map) = *ports {
                if let Some(port) = map.get_mut(&port_id) {
                    if let Some(packet) = port.queue.pop_front() {
                        port.total_packets_dequeued += 1;
                        port.active_threads += 1;
                        port.waiter_count = port.waiter_count.saturating_sub(1);
                        return Some(packet);
                    }
                } else {
                    // Port does not exist — bail out
                    return None;
                }
            } else {
                return None;
            }
        }

        // Check timeout
        match timeout_ticks {
            Some(0) => {
                // Poll mode — decrement waiter and return
                let mut ports = COMPLETION_PORTS.lock();
                if let Some(ref mut map) = *ports {
                    if let Some(port) = map.get_mut(&port_id) {
                        port.waiter_count = port.waiter_count.saturating_sub(1);
                    }
                }
                return None;
            }
            Some(n) => {
                let now = crate::arch::x86_64::irq::get_ticks();
                if now.wrapping_sub(start) >= n {
                    let mut ports = COMPLETION_PORTS.lock();
                    if let Some(ref mut map) = *ports {
                        if let Some(port) = map.get_mut(&port_id) {
                            port.waiter_count = port.waiter_count.saturating_sub(1);
                        }
                    }
                    return None;
                }
            }
            None => {} // infinite — keep spinning
        }

        // Yield CPU and retry
        crate::sched::yield_cpu();
    }
}

/// Mark a thread as done processing (decrement active_threads).
pub fn release_thread(port_id: u64) {
    let mut ports = COMPLETION_PORTS.lock();
    if let Some(ref mut map) = *ports {
        if let Some(port) = map.get_mut(&port_id) {
            port.active_threads = port.active_threads.saturating_sub(1);
        }
    }
}

/// Return the number of pending (queued) packets on a port.
pub fn get_queued_count(port_id: u64) -> usize {
    let ports = COMPLETION_PORTS.lock();
    if let Some(ref map) = *ports {
        if let Some(port) = map.get(&port_id) {
            return port.queue.len();
        }
    }
    0
}

/// Return lifetime statistics `(total_queued, total_dequeued)` for a port.
pub fn port_stats(port_id: u64) -> Option<(u64, u64)> {
    let ports = COMPLETION_PORTS.lock();
    if let Some(ref map) = *ports {
        if let Some(port) = map.get(&port_id) {
            return Some((port.total_packets_queued, port.total_packets_dequeued));
        }
    }
    None
}
