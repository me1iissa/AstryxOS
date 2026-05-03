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
//! `try_read` primitive plus the wait/wake hooks the syscall layer uses
//! to park a caller atomically without busy-spinning.
//!
//! ## Wake hooks
//!
//! `wait_readable(efd_id, wake_tick)` performs an atomic check-then-park
//! against the per-eventfd wait list (`EVENTFD_READ_WAITERS`).  The
//! `write` helper drains the wait list after bumping the counter so a
//! peer parked in `wait_readable` (or `poll`/`epoll_wait` registered
//! against this fd) is woken on the same code path.
//!
//! Lock order:
//!     `EVENTFD_READ_WAITERS` -> `TABLE` (waiter side)
//!     `TABLE` -> drop -> `EVENTFD_READ_WAITERS` (writer side)
//! Same shape as the pipe wake hooks; matches the futex
//! `FUTEX_WAITERS` -> `THREAD_TABLE` ordering.
//!
//! This implementation stores counters in a fixed-size global table.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::ipc::waitlist::{ring_poll_bell, wake_tids, WaitList};

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

/// Per-eventfd reader wait queue, keyed by slot id.  Entries are removed
/// when the last waiter is drained.
static EVENTFD_READ_WAITERS: Mutex<BTreeMap<u64, WaitList>> = Mutex::new(BTreeMap::new());

/// Outcome of `wait_readable`.
#[derive(Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Counter was non-zero at the recheck — caller may retry the read.
    Ready,
    /// Caller is now parked; the calling site MUST invoke
    /// `crate::sched::schedule()` after this returns.
    Enqueued,
    /// `efd_id` does not refer to a live slot; treat as EBADF.
    Gone,
}

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
/// EFD_NONBLOCK creation flag and `wait_readable` for the parking helper.
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
///
/// On success the caller should invoke `wake_readers(id)` after dropping
/// any unrelated locks so a peer parked in `wait_readable` (or registered
/// on this fd via poll/epoll) is woken promptly.  The wake is NOT issued
/// from inside this helper because callers in the syscall layer keep
/// `TABLE` and `EVENTFD_READ_WAITERS` strictly disjoint.
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

/// Free an eventfd slot.  Wakes every reader parked on the slot so they
/// observe EBADF on the next try_read call rather than blocking
/// indefinitely against a counter that nobody can ever post to.
pub fn close(id: u64) {
    {
        let mut table = TABLE.lock();
        if let Some(slot) = table.get_mut(id as usize) {
            *slot = EventFdEntry::empty();
        }
    }
    wake_readers_all(id);
}

/// Check if counter > 0 (used by `poll` / `select`).
pub fn is_readable(id: u64) -> bool {
    let table = TABLE.lock();
    table.get(id as usize).map(|s| s.in_use && s.counter > 0).unwrap_or(false)
}

// ── Wait / wake hooks ─────────────────────────────────────────────────────────

/// Atomic check-then-park for a reader on `efd_id`.
///
/// Holds `EVENTFD_READ_WAITERS` across a brief `TABLE` re-check so the
/// "counter still zero?" decision and the "enqueue self" step are one
/// critical section.  See `crate::ipc::pipe::wait_readable` for the
/// wider rationale; the futex check-then-queue helper documents the
/// lost-wakeup race this discipline closes.
///
/// `wake_tick` is the absolute tick at which the kernel timer auto-wakes
/// a Blocked thread; pass `u64::MAX` for an indefinite block.
pub fn wait_readable(efd_id: u64, wake_tick: u64) -> WaitOutcome {
    let tid = crate::proc::current_tid();
    let mut waiters = EVENTFD_READ_WAITERS.lock();

    // Brief re-check under the wait-list lock.  Lock order is
    // EVENTFD_READ_WAITERS -> TABLE on the waiter side; the writer side
    // drops TABLE before taking the wait-list, so the orders agree.
    let outcome = {
        let table = TABLE.lock();
        match table.get(efd_id as usize) {
            None => WaitOutcome::Gone,
            Some(slot) if !slot.in_use => WaitOutcome::Gone,
            Some(slot) if slot.counter > 0 => WaitOutcome::Ready,
            Some(_) => WaitOutcome::Enqueued,
        }
    };
    if matches!(outcome, WaitOutcome::Ready | WaitOutcome::Gone) {
        return outcome;
    }

    let entry = waiters.entry(efd_id).or_insert_with(WaitList::new);
    entry.enqueue_self_blocked(tid, wake_tick);
    drop(waiters);
    WaitOutcome::Enqueued
}

/// Wake every reader parked on `efd_id`.  Idempotent — a no-op when no
/// waiters are registered.  For semaphore-mode eventfds (EFD_SEMAPHORE)
/// only one reader will successfully decrement on the first try_read;
/// any extras simply re-park on the next pass.  Waking all matches
/// pipe-EOF semantics and avoids a thundering-herd-vs-stranded-waiter
/// trade-off in the common single-waiter case.
pub fn wake_readers_all(efd_id: u64) {
    let drained = {
        let mut waiters = EVENTFD_READ_WAITERS.lock();
        match waiters.get_mut(&efd_id) {
            Some(list) => {
                let v = list.drain_all();
                if list.is_empty() { waiters.remove(&efd_id); }
                v
            }
            None => Vec::new(),
        }
    };
    wake_tids(&drained);
    // Also kick the global poll bell so a poll/epoll/select caller
    // watching this eventfd re-evaluates immediately.
    ring_poll_bell();
}

/// Best-effort cleanup: remove `tid` from this eventfd's wait list.
/// Called by callers that returned from `schedule()` having timed out or
/// been interrupted, so they do not leak a stale entry.
pub fn waiter_cleanup(efd_id: u64, tid: u64) {
    let mut waiters = EVENTFD_READ_WAITERS.lock();
    if let Some(list) = waiters.get_mut(&efd_id) {
        list.remove_tid(tid);
        if list.is_empty() {
            waiters.remove(&efd_id);
        }
    }
}

/// Test-only diagnostic: returns the number of reader TIDs currently
/// parked on `efd_id`.
pub fn debug_reader_waiter_count(efd_id: u64) -> usize {
    let waiters = EVENTFD_READ_WAITERS.lock();
    waiters.get(&efd_id).map(|l| l.len()).unwrap_or(0)
}
