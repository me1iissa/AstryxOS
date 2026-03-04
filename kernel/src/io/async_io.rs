//! Async I/O Request Infrastructure
//!
//! Tracks pending asynchronous I/O operations and integrates with the
//! I/O Completion Port subsystem so that completed requests are
//! automatically posted to their associated IOCP.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::completion::{self, IoCompletionPacket, IoStatus};

// ============================================================================
// AsyncIoOperation
// ============================================================================

/// The kind of asynchronous I/O operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncIoOperation {
    Read,
    Write,
    DeviceControl(u32), // IOCTL code
    Flush,
}

// ============================================================================
// AsyncIoRequest
// ============================================================================

/// An in-flight asynchronous I/O request.
#[derive(Debug, Clone)]
pub struct AsyncIoRequest {
    /// Unique request identifier.
    pub id: u64,
    /// Target file/device handle.
    pub file_handle: u64,
    /// Kind of operation.
    pub operation: AsyncIoOperation,
    /// User buffer virtual address.
    pub buffer_addr: u64,
    /// User buffer length.
    pub buffer_len: usize,
    /// File offset.
    pub offset: u64,
    /// Associated I/O completion port (if any).
    pub completion_port_id: Option<u64>,
    /// Completion key for the IOCP packet.
    pub completion_key: u64,
    /// Current status.
    pub status: IoStatus,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Tick at which the request was submitted.
    pub submitted_tick: u64,
}

// ============================================================================
// Global Request Tracker
// ============================================================================

static ASYNC_REQUESTS: Mutex<Option<BTreeMap<u64, AsyncIoRequest>>> = Mutex::new(None);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Initialize the async I/O subsystem.  Must be called once at boot.
pub fn init_async_io() {
    *ASYNC_REQUESTS.lock() = Some(BTreeMap::new());
    crate::serial_println!("[IO/Async] Async I/O subsystem initialized");
}

// ============================================================================
// Public API
// ============================================================================

/// Submit an asynchronous I/O request.  Returns the unique request ID.
///
/// The caller should pre-fill all fields *except* `id` (which will be
/// overwritten with the generated value).
pub fn submit_async_io(mut request: AsyncIoRequest) -> u64 {
    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    request.id = id;
    request.status = IoStatus::Pending;
    request.submitted_tick = crate::arch::x86_64::irq::get_ticks();

    let mut reqs = ASYNC_REQUESTS.lock();
    if let Some(ref mut map) = *reqs {
        map.insert(id, request);
    }
    id
}

/// Mark an async request as complete and, if an IOCP is associated, post
/// the completion packet automatically.
pub fn complete_async_io(request_id: u64, status: IoStatus, bytes_transferred: u64) {
    let mut reqs = ASYNC_REQUESTS.lock();
    if let Some(ref mut map) = *reqs {
        if let Some(req) = map.get_mut(&request_id) {
            req.status = status;
            req.bytes_transferred = bytes_transferred;

            // Post to IOCP if associated
            if let Some(port_id) = req.completion_port_id {
                let packet = IoCompletionPacket {
                    key: req.completion_key,
                    status,
                    information: bytes_transferred,
                    overlapped: req.id, // use request id as overlapped context
                };
                completion::post_completion(port_id, packet);
            }

            // Remove from pending set (it is now complete)
            let _ = map.remove(&request_id);
        }
    }
}

/// Cancel a pending async request.  Returns `true` if the request existed
/// and was successfully cancelled.
pub fn cancel_async_io(request_id: u64) -> bool {
    let mut reqs = ASYNC_REQUESTS.lock();
    if let Some(ref mut map) = *reqs {
        if let Some(req) = map.get_mut(&request_id) {
            req.status = IoStatus::Cancelled;

            // Post cancellation to IOCP if associated
            if let Some(port_id) = req.completion_port_id {
                let packet = IoCompletionPacket {
                    key: req.completion_key,
                    status: IoStatus::Cancelled,
                    information: 0,
                    overlapped: req.id,
                };
                completion::post_completion(port_id, packet);
            }

            map.remove(&request_id);
            return true;
        }
    }
    false
}

/// Query the current status of an async request.
pub fn get_async_status(request_id: u64) -> Option<IoStatus> {
    let reqs = ASYNC_REQUESTS.lock();
    if let Some(ref map) = *reqs {
        return map.get(&request_id).map(|r| r.status);
    }
    None
}

/// Return the number of currently pending async requests.
pub fn pending_async_count() -> usize {
    let reqs = ASYNC_REQUESTS.lock();
    if let Some(ref map) = *reqs {
        return map.len();
    }
    0
}
