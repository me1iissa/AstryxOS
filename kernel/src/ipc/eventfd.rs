//! eventfd — Simple counter-based signaling file descriptor.
//!
//! An eventfd holds a u64 counter.  Writing adds to the counter; reading
//! returns the current value (or decrements by 1 in `EFD_SEMAPHORE` mode)
//! and clears it (or decrements it).  Per `man 2 eventfd`:
//!
//! > If the eventfd counter is zero at the time of the call, then the call
//! > either blocks until the counter becomes nonzero (at which time, the
//! > read(2) proceeds as described above) or fails with the error EAGAIN if
//! > the file descriptor has been made nonblocking.
//!
//! The blocking decision is made at the syscall layer (which knows the
//! per-fd O_NONBLOCK status).  This module provides a non-blocking
//! `try_read` primitive plus a helper to inspect the EFD_NONBLOCK creation
//! flag so the caller can decide.
//!
//! This implementation stores counters in a fixed-size global table.

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Maximum number of concurrent eventfds.
const MAX_EVENTFDS: usize = 64;

/// eventfd flags.
pub const EFD_NONBLOCK: u32  = 0x0800;
pub const EFD_CLOEXEC: u32   = 0x0008_0000;
pub const EFD_SEMAPHORE: u32 = 0x0000_0001;

/// Next eventfd slot ID.
static NEXT_EFD_ID: AtomicU64 = AtomicU64::new(1);

/// An eventfd entry.
#[derive(Clone, Copy)]
struct EventFdEntry {
    counter: u64,
    flags:   u32,
    in_use:  bool,
}

impl EventFdEntry {
    const fn empty() -> Self {
        Self { counter: 0, flags: 0, in_use: false }
    }
}

static TABLE: Mutex<[EventFdEntry; MAX_EVENTFDS]> =
    Mutex::new([EventFdEntry::empty(); MAX_EVENTFDS]);

/// Allocate a new eventfd slot.  Returns the slot index (as the `inode`
/// value stored in the FileDescriptor) or `u64::MAX` on failure.
pub fn create(initval: u64, flags: u32) -> u64 {
    let mut table = TABLE.lock();
    for (i, slot) in table.iter_mut().enumerate() {
        if !slot.in_use {
            slot.in_use  = true;
            slot.counter = initval;
            slot.flags   = flags;
            return i as u64;
        }
    }
    u64::MAX // No free slot
}

/// Non-blocking read from eventfd.  Returns the current counter as a u64
/// (caller serializes to 8 LE bytes), then resets the counter to 0 (or
/// decrements by 1 in `EFD_SEMAPHORE` mode).  Returns `Err(-11)` (EAGAIN)
/// if counter is 0.
///
/// The blocking-vs-non-blocking decision lives at the syscall layer; this
/// primitive never blocks.  See `is_efd_nonblock` to query the
/// EFD_NONBLOCK creation flag.
pub fn try_read(id: u64) -> Result<u64, i64> {
    let mut table = TABLE.lock();
    let slot = match table.get_mut(id as usize) {
        Some(s) if s.in_use => s,
        _ => return Err(-9), // EBADF
    };
    if slot.counter == 0 {
        return Err(-11); // EAGAIN
    }
    let val = if slot.flags & EFD_SEMAPHORE != 0 {
        let v = slot.counter;
        slot.counter -= 1;
        v
    } else {
        let v = slot.counter;
        slot.counter = 0;
        v
    };
    Ok(val)
}

/// Backwards-compatible alias of [`try_read`].  Older call sites that did
/// not implement blocking semantics relied on the unconditional EAGAIN
/// behaviour; new callers should prefer `try_read` for clarity.
pub fn read(id: u64) -> Result<u64, i64> {
    try_read(id)
}

/// Was this eventfd created with `EFD_NONBLOCK`?  Per `man 2 eventfd`,
/// EFD_NONBLOCK is shorthand for setting `O_NONBLOCK` on the resulting fd.
/// The syscall layer combines this with the per-fd O_NONBLOCK status
/// (which may be toggled later via `fcntl(F_SETFL)`).
pub fn is_efd_nonblock(id: u64) -> bool {
    let table = TABLE.lock();
    table.get(id as usize)
        .map(|s| s.in_use && (s.flags & EFD_NONBLOCK) != 0)
        .unwrap_or(false)
}

/// Write to eventfd — add `val` to the counter.  Returns 0 on success or
/// `Err(-27)` (EFBIG) if the counter would overflow u64::MAX - 1.
pub fn write(id: u64, val: u64) -> Result<(), i64> {
    let mut table = TABLE.lock();
    let slot = match table.get_mut(id as usize) {
        Some(s) if s.in_use => s,
        _ => return Err(-9), // EBADF
    };
    // Guard against overflow (u64::MAX is special in eventfd protocol).
    if val > u64::MAX - 1 - slot.counter {
        return Err(-27); // EFBIG
    }
    slot.counter += val;
    Ok(())
}

/// Free an eventfd slot.
pub fn close(id: u64) {
    let mut table = TABLE.lock();
    if let Some(slot) = table.get_mut(id as usize) {
        *slot = EventFdEntry::empty();
    }
}

/// Check if counter > 0 (used by `poll` / `select`).
pub fn is_readable(id: u64) -> bool {
    let table = TABLE.lock();
    table.get(id as usize).map(|s| s.in_use && s.counter > 0).unwrap_or(false)
}
