//! Pipes — Inter-Process Communication
//!
//! Provides an in-kernel pipe mechanism for data transfer between threads/processes.
//! Used for shell pipelines and general IPC.
//!
//! ## Wake hooks (per `man 7 pipe`, `man 2 read`, `man 2 write`)
//!
//! When a reader finds an empty blocking pipe, it must park itself until
//! either data arrives or the write end is closed (EOF -> `read` returns 0).
//! Symmetrically, a writer that finds a full pipe parks until space is
//! available or the read end is closed (in which case `write` raises
//! `SIGPIPE` / returns `EPIPE`).
//!
//! Wait lists live OUTSIDE `PIPE_TABLE` so `PIPE_TABLE` is never held
//! across `schedule()`.  Lock order:
//!     `PIPE_*_WAITERS` -> `PIPE_TABLE` (waiter side)
//!     `PIPE_TABLE` -> drop -> `PIPE_*_WAITERS` (writer/closer side)
//! Both orders agree because no path holds both locks at once.  Identical
//! pattern to `crate::syscall::FUTEX_WAITERS` -> `THREAD_TABLE`.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::ipc::waitlist::{ring_poll_bell, wake_tids, WaitList};

/// Pipe buffer size (4 KiB).
const PIPE_BUF_SIZE: usize = 4096;

/// Next pipe ID.
static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(1);

/// A kernel pipe — a bounded ring buffer.
pub struct Pipe {
    pub id: u64,
    buffer: [u8; PIPE_BUF_SIZE],
    read_pos: usize,
    write_pos: usize,
    count: usize,
    /// Number of open write ends. When 0, reads past end return EOF.
    writers: u32,
    /// Number of open read ends.
    readers: u32,
    closed: bool,
}

impl Pipe {
    fn new(id: u64) -> Self {
        Self {
            id,
            buffer: [0; PIPE_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            writers: 1,
            readers: 1,
            closed: false,
        }
    }

    /// Read up to `buf.len()` bytes from the pipe. Returns bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.count);
        for i in 0..to_read {
            buf[i] = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUF_SIZE;
        }
        self.count -= to_read;
        to_read
    }

    /// Write up to `data.len()` bytes into the pipe. Returns bytes written.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let space = PIPE_BUF_SIZE - self.count;
        let to_write = data.len().min(space);
        for i in 0..to_write {
            self.buffer[self.write_pos] = data[i];
            self.write_pos = (self.write_pos + 1) % PIPE_BUF_SIZE;
        }
        self.count += to_write;
        to_write
    }

    /// Check if the pipe has data available to read.
    pub fn has_data(&self) -> bool {
        self.count > 0
    }

    /// Check if write end is closed (EOF for readers).
    pub fn is_eof(&self) -> bool {
        self.writers == 0 && self.count == 0
    }

    /// Check if write end is closed (regardless of buffered data).  Used
    /// by the wait helper to short-circuit a parked reader when there is
    /// no possibility of more data ever arriving.
    pub fn writer_closed(&self) -> bool {
        self.writers == 0
    }

    /// Available bytes (count of unread data).
    pub fn available(&self) -> usize {
        self.count
    }

    /// Free space remaining in the ring buffer.
    pub fn space(&self) -> usize {
        PIPE_BUF_SIZE - self.count
    }
}

/// Global pipe table.
static PIPE_TABLE: Mutex<Vec<Pipe>> = Mutex::new(Vec::new());

/// Per-pipe reader wait queue.  Keyed by pipe id; the entry is dropped
/// when the last waiter departs to keep the map small in the steady state.
static PIPE_READ_WAITERS: Mutex<BTreeMap<u64, WaitList>> = Mutex::new(BTreeMap::new());

/// Per-pipe writer wait queue (used when `write()` would block on a full
/// buffer).  Same shape as `PIPE_READ_WAITERS`.
static PIPE_WRITE_WAITERS: Mutex<BTreeMap<u64, WaitList>> = Mutex::new(BTreeMap::new());

/// Outcome of a check-then-park call.
#[derive(Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Condition was already satisfied — caller may proceed without parking.
    Ready,
    /// Caller is now parked; the calling site MUST invoke `schedule()`.
    Enqueued,
    /// Pipe id no longer exists (e.g. both ends closed).  Treat as EBADF.
    Gone,
}

/// Create a new pipe. Returns the pipe ID.
pub fn create_pipe() -> u64 {
    let id = NEXT_PIPE_ID.fetch_add(1, Ordering::Relaxed);
    PIPE_TABLE.lock().push(Pipe::new(id));
    id
}

/// Read from a pipe by ID.
pub fn pipe_read(pipe_id: u64, buf: &mut [u8]) -> Option<usize> {
    let mut pipes = PIPE_TABLE.lock();
    let pipe = pipes.iter_mut().find(|p| p.id == pipe_id)?;
    Some(pipe.read(buf))
}

/// Write to a pipe by ID.
///
/// On a successful write of one or more bytes the caller should invoke
/// `wake_readers(pipe_id)` after dropping any unrelated locks, so a peer
/// thread blocked in `pipe_read` (or `poll`/`epoll_wait`) is woken
/// promptly.  The wake is NOT issued from inside the write helper itself
/// because callers in the syscall layer already separate "advance pipe
/// state" from "notify waiters" to keep `PIPE_TABLE` strictly disjoint
/// from `PIPE_*_WAITERS`.
pub fn pipe_write(pipe_id: u64, data: &[u8]) -> Option<usize> {
    let mut pipes = PIPE_TABLE.lock();
    let pipe = pipes.iter_mut().find(|p| p.id == pipe_id)?;
    Some(pipe.write(data))
}

/// Increment the writer count (e.g. when a second fd aliases the write-end).
pub fn pipe_add_writer(pipe_id: u64) {
    let mut pipes = PIPE_TABLE.lock();
    if let Some(pipe) = pipes.iter_mut().find(|p| p.id == pipe_id) {
        pipe.writers = pipe.writers.saturating_add(1);
    }
}

/// Close the write end of a pipe.  When the writer count reaches zero,
/// every reader parked on `PIPE_READ_WAITERS` for this pipe id is woken
/// so it observes EOF (per `man 7 pipe`: "If all file descriptors
/// referring to the write end of a pipe have been closed, then an attempt
/// to read(2) from the pipe will see end-of-file (read(2) will return 0)").
pub fn pipe_close_writer(pipe_id: u64) {
    let became_eof = {
        let mut pipes = PIPE_TABLE.lock();
        match pipes.iter_mut().find(|p| p.id == pipe_id) {
            Some(pipe) => {
                pipe.writers = pipe.writers.saturating_sub(1);
                pipe.writers == 0
            }
            None => false,
        }
    };
    if became_eof {
        // Wake every reader waiting on this pipe — they must see EOF.
        wake_readers_all(pipe_id);
        // Also wake any writers parked for buffer space; without a peer
        // reader they would otherwise stall forever (in practice a SIGPIPE
        // path, but the wake still has to fire so the syscall returns).
        wake_writers_all(pipe_id);
    }
}

/// Close the read end of a pipe.  When the reader count reaches zero,
/// any writer parked waiting for buffer space must be woken so it can
/// observe `EPIPE` rather than block forever.
pub fn pipe_close_reader(pipe_id: u64) {
    let no_readers = {
        let mut pipes = PIPE_TABLE.lock();
        let result = if let Some(pipe) = pipes.iter_mut().find(|p| p.id == pipe_id) {
            pipe.readers = pipe.readers.saturating_sub(1);
            pipe.readers == 0
        } else {
            false
        };
        // Clean up pipes with no readers and no writers.
        pipes.retain(|p| p.readers > 0 || p.writers > 0);
        result
    };
    if no_readers {
        wake_writers_all(pipe_id);
        // Drop any reader waitlist that lingered (the pipe may have been
        // dropped by `retain` above).
        wake_readers_all(pipe_id);
    }
}

/// Check if a pipe has data.
pub fn pipe_has_data(pipe_id: u64) -> bool {
    let pipes = PIPE_TABLE.lock();
    pipes.iter().find(|p| p.id == pipe_id)
        .map(|p| p.has_data())
        .unwrap_or(false)
}

/// Check if a pipe's write end is closed.
pub fn pipe_is_eof(pipe_id: u64) -> bool {
    let pipes = PIPE_TABLE.lock();
    pipes.iter().find(|p| p.id == pipe_id)
        .map(|p| p.is_eof())
        .unwrap_or(true)
}

// ── Wait / wake hooks ─────────────────────────────────────────────────────────

/// Atomic check-then-park for a reader on `pipe_id`.
///
/// Holds `PIPE_READ_WAITERS` across a brief `PIPE_TABLE` re-check so the
/// "pipe still empty?" decision and the "enqueue self as a waiter" step
/// happen under one critical section, mirroring the futex
/// `check-then-queue` pattern documented at
/// `crate::syscall::futex_wait_check_and_enqueue`.  Without that
/// discipline, a writer that fires its `wake_readers` between our check
/// and our enqueue would slip past us and we would park with no wake on
/// the way.
///
/// `wake_tick` is the absolute scheduler tick at which the kernel timer
/// auto-wakes a Blocked thread; pass `u64::MAX` for an indefinite block,
/// or a finite tick to honor a `poll` / `select` timeout.
///
/// Returns:
///   * `Ready`    — pipe already has data (or EOF).  Caller may retry the
///                  read without parking.
///   * `Enqueued` — caller is now in `Blocked`; caller MUST call
///                  `crate::sched::schedule()` after this returns.
///   * `Gone`     — pipe id no longer exists (caller treats as EBADF).
pub fn wait_readable(pipe_id: u64, wake_tick: u64) -> WaitOutcome {
    let tid = crate::proc::current_tid();
    let mut waiters = PIPE_READ_WAITERS.lock();

    // Brief re-check under the wait-list lock — see the doc-comment for
    // why this MUST be inside the critical section.  We take and drop
    // PIPE_TABLE while still holding PIPE_READ_WAITERS.  Lock order:
    // PIPE_READ_WAITERS -> PIPE_TABLE.  No path goes the other direction
    // (the writer/closer drop PIPE_TABLE before taking the wait-list).
    let outcome = {
        let pipes = PIPE_TABLE.lock();
        match pipes.iter().find(|p| p.id == pipe_id) {
            None => WaitOutcome::Gone,
            // Either data is buffered or the writer has closed and we
            // would observe EOF — in both cases the caller can return
            // immediately without parking.
            Some(p) if p.has_data() || p.writer_closed() => WaitOutcome::Ready,
            Some(_) => WaitOutcome::Enqueued,
        }
    };
    if matches!(outcome, WaitOutcome::Ready | WaitOutcome::Gone) {
        return outcome;
    }

    // Park the caller while still holding PIPE_READ_WAITERS.
    let entry = waiters.entry(pipe_id).or_insert_with(WaitList::new);
    entry.enqueue_self_blocked(tid, wake_tick);
    drop(waiters);
    WaitOutcome::Enqueued
}

/// Atomic check-then-park for a writer on `pipe_id`.  Symmetric with
/// `wait_readable`; a writer parks when the pipe is full unless the
/// reader has gone away (in which case the caller will return EPIPE).
pub fn wait_writable(pipe_id: u64, wake_tick: u64) -> WaitOutcome {
    let tid = crate::proc::current_tid();
    let mut waiters = PIPE_WRITE_WAITERS.lock();

    let outcome = {
        let pipes = PIPE_TABLE.lock();
        match pipes.iter().find(|p| p.id == pipe_id) {
            None => WaitOutcome::Gone,
            Some(p) if p.space() > 0 || p.readers == 0 => WaitOutcome::Ready,
            Some(_) => WaitOutcome::Enqueued,
        }
    };
    if matches!(outcome, WaitOutcome::Ready | WaitOutcome::Gone) {
        return outcome;
    }

    let entry = waiters.entry(pipe_id).or_insert_with(WaitList::new);
    entry.enqueue_self_blocked(tid, wake_tick);
    drop(waiters);
    WaitOutcome::Enqueued
}

/// Wake every reader parked on `pipe_id`.  Idempotent — a no-op when no
/// waiters are registered.  The split between draining TIDs (under
/// `PIPE_READ_WAITERS`) and flipping thread state (under `THREAD_TABLE`)
/// avoids holding two locks simultaneously, identical to FUTEX_WAKE.
///
/// Bounded variant `wake_readers(pipe_id, n)` is intentionally not
/// exposed: pipe data is universally consumable so waking one reader vs.
/// many makes no spec-visible difference and the all-wake path matches
/// `wake_up_interruptible_all` in mainline pipe-EOF semantics.
pub fn wake_readers_all(pipe_id: u64) {
    let drained = {
        let mut waiters = PIPE_READ_WAITERS.lock();
        match waiters.get_mut(&pipe_id) {
            Some(list) => {
                let v = list.drain_all();
                if list.is_empty() { waiters.remove(&pipe_id); }
                v
            }
            None => Vec::new(),
        }
    };
    wake_tids(&drained);
    // Also kick the global poll bell so any poll/epoll/select caller
    // watching this pipe re-evaluates immediately rather than waiting
    // for its 10 ms tick.
    ring_poll_bell();
}

/// Wake every writer parked on `pipe_id`.
pub fn wake_writers_all(pipe_id: u64) {
    let drained = {
        let mut waiters = PIPE_WRITE_WAITERS.lock();
        match waiters.get_mut(&pipe_id) {
            Some(list) => {
                let v = list.drain_all();
                if list.is_empty() { waiters.remove(&pipe_id); }
                v
            }
            None => Vec::new(),
        }
    };
    wake_tids(&drained);
    ring_poll_bell();
}

/// Best-effort cleanup: remove `tid` from this pipe's reader wait list.
/// Called by callers that returned from `schedule()` having timed out or
/// been interrupted, to ensure they do not leak a stale entry.
pub fn waiter_cleanup_reader(pipe_id: u64, tid: u64) {
    let mut waiters = PIPE_READ_WAITERS.lock();
    if let Some(list) = waiters.get_mut(&pipe_id) {
        list.remove_tid(tid);
        if list.is_empty() {
            waiters.remove(&pipe_id);
        }
    }
}

/// Best-effort cleanup for a writer that was parked on `pipe_id`.
pub fn waiter_cleanup_writer(pipe_id: u64, tid: u64) {
    let mut waiters = PIPE_WRITE_WAITERS.lock();
    if let Some(list) = waiters.get_mut(&pipe_id) {
        list.remove_tid(tid);
        if list.is_empty() {
            waiters.remove(&pipe_id);
        }
    }
}

/// Test-only diagnostic: returns the number of reader TIDs currently
/// parked on `pipe_id`.  Exposed to the in-kernel test runner so wake-up
/// invariants ("0 waiters after wake_readers_all") can be asserted.
pub fn debug_reader_waiter_count(pipe_id: u64) -> usize {
    let waiters = PIPE_READ_WAITERS.lock();
    waiters.get(&pipe_id).map(|l| l.len()).unwrap_or(0)
}

/// Test-only diagnostic: returns the number of writer TIDs currently
/// parked on `pipe_id`.
pub fn debug_writer_waiter_count(pipe_id: u64) -> usize {
    let waiters = PIPE_WRITE_WAITERS.lock();
    waiters.get(&pipe_id).map(|l| l.len()).unwrap_or(0)
}
