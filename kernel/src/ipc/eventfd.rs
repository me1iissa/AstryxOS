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

use crate::ipc::waitlist::{ring_poll_bell_for, wake_tids, PollBellSource, WaitList};

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
    /// Open-file-description reference count.  One reference per
    /// `FileDescriptor` (in any process's fd table) that names this slot,
    /// plus one per in-flight SCM_RIGHTS copy.  Per POSIX.1-2017 §2.14,
    /// `fork(2)`, and `dup(2)`: duplicated descriptors refer to the SAME
    /// open file description, and per `close(2)` the underlying object is
    /// released only when the LAST descriptor referring to it is closed.
    /// `create()` starts this at 1; `inc_ref()` bumps it on fork/dup/
    /// SCM-enqueue; `close()` decrements and frees the slot only at zero.
    refs:    u32,
    /// Monotonic readiness-rise generation.  Bumped on every counter
    /// `0 → non-zero` transition (a fresh not-ready→ready edge per
    /// `eventfd(2)` + `epoll(7)`), and never on a write that only grows an
    /// already-non-zero counter.  An edge-triggered (`EPOLLET`) epoll watch
    /// records the generation it last delivered; `sys_epoll_wait` re-arms the
    /// EPOLLIN edge whenever the live generation differs from the recorded
    /// one, even when the asserted *level* looks continuously high.  This
    /// records the 0-crossing at the moment readiness rises (the canonical
    /// epoll ready-list / wakeup-callback contract) rather than only when an
    /// `epoll_wait` happens to observe the drained state — closing the
    /// drain-then-rise-between-two-waits edge-suppression gap.
    rise_seq: u64,
}

impl EventFdEntry {
    const fn empty() -> Self {
        Self { counter: 0, flags: 0, in_use: false, refs: 0, rise_seq: 0 }
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
            slot.refs    = 1; // the creating fd's open-file-description ref
            return i as u64;
        }
    }
    u64::MAX // No free slot
}

/// Add one open-file-description reference to a live slot.
///
/// Call sites mirror the unix-socket / pipe refcount discipline:
/// `fork(2)`/`clone(2)`-without-CLONE_FILES fd-table duplication,
/// `dup(2)`/`dup2(2)`/`fcntl(F_DUPFD)`, and SCM_RIGHTS enqueue.  Per
/// POSIX.1-2017 §2.14 the duplicate descriptor refers to the same open
/// file description; without this bump the FIRST `close(2)` from either
/// holder would free the shared counter slot, leaving the survivor with
/// a dangling id that fails EBADF — or worse, lands on a recycled slot.
pub fn inc_ref(id: u64) {
    let mut table = TABLE.lock();
    if let Some(slot) = table.get_mut(id as usize) {
        if slot.in_use {
            slot.refs = slot.refs.saturating_add(1);
        }
    }
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

/// Read the live counter value for an eventfd slot without mutating it.
///
/// Diagnostic-only (kdb introspection): returns `Some(counter)` for a live
/// slot, `None` for a free/invalid id.  Unlike `try_read` this never resets
/// the counter, so it is safe to call from a debugger snapshot path that must
/// not perturb the protocol state of a live workload.
pub fn peek_counter(id: u64) -> Option<u64> {
    let table = TABLE.lock();
    table.get(id as usize)
        .filter(|s| s.in_use)
        .map(|s| s.counter)
}

/// Read the live readiness-rise generation for an eventfd slot (see
/// `EventFdEntry.rise_seq`).  Returns `Some(seq)` for a live slot, `None` for
/// a free/invalid id.  `sys_epoll_wait` consults this to re-arm an EPOLLET
/// EPOLLIN edge across a drain-then-rise that no `epoll_wait` observed at
/// level 0.  Non-mutating; safe to call from any context.
pub fn rise_seq(id: u64) -> Option<u64> {
    let table = TABLE.lock();
    table.get(id as usize)
        .filter(|s| s.in_use)
        .map(|s| s.rise_seq)
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
    // A write that takes the counter from 0 to non-zero is a fresh
    // not-ready→ready edge: bump the rise generation so an edge-triggered
    // epoll watch that already delivered the previous rise (and was drained to
    // 0 since) re-arms.  A write that only grows an already-non-zero counter
    // is NOT a new edge (the fd was continuously ready), so the generation is
    // left untouched — matching `EPOLLET` "deliver only on changes" semantics.
    let was_zero = slot.counter == 0;
    slot.counter += val;
    if was_zero && val > 0 {
        // `wrapping_add` is intentional and benign: only inequality with the
        // watch's recorded `et_rise` is consulted, never an ordering, and a u64
        // wrap requires ~2^64 rise events (centuries of edges) — a wrap would
        // at worst alias one generation and miss a single edge, never panic.
        slot.rise_seq = slot.rise_seq.wrapping_add(1);
    }
    Ok(())
}

/// Drop one open-file-description reference; free the slot only when the
/// LAST reference is released.  Per POSIX `close(2)`: "If fildes is the
/// last file descriptor referring to the open file description, the
/// resources associated with the open file description shall be
/// released."  An eventfd inherited across `fork(2)` (or duplicated via
/// `dup(2)`/SCM_RIGHTS) is one shared object with multiple references —
/// a child's close (e.g. a pre-`execve(2)` close-on-exec scrub) must NOT
/// destroy the counter the parent is still writing to.
///
/// On the final free, wakes every reader parked on the slot so they
/// observe EBADF on the next try_read call rather than blocking
/// indefinitely against a counter that nobody can ever post to.
pub fn close(id: u64) {
    let freed = {
        let mut table = TABLE.lock();
        match table.get_mut(id as usize) {
            Some(slot) if slot.in_use => {
                if slot.refs > 1 {
                    slot.refs -= 1;
                    false
                } else {
                    *slot = EventFdEntry::empty();
                    true
                }
            }
            // Not in use: double-close or stale id — nothing to drop.
            _ => false,
        }
    };
    if freed {
        wake_readers_all(id);
    }
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
    ring_poll_bell_for(PollBellSource::Eventfd);
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

/// Test-only diagnostic: returns the open-file-description reference
/// count for `efd_id` (0 when the slot is free).
pub fn debug_ref_count(efd_id: u64) -> u32 {
    let table = TABLE.lock();
    table.get(efd_id as usize)
        .map(|s| if s.in_use { s.refs } else { 0 })
        .unwrap_or(0)
}
