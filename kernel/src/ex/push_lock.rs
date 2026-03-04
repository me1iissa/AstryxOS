//! Push Lock — Slim reader-writer lock
//!
//! Inspired by NT push locks: a very lightweight reader-writer primitive that
//! packs its state into a single word.  Lighter weight than EResource — no
//! per-thread ownership tracking or contention stats.

/// State of the push lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushLockState {
    /// Not held by anyone.
    Free,
    /// Held in shared (read) mode by `count` readers.
    SharedRead(u32),
    /// Held in exclusive (write) mode.
    Exclusive,
}

/// A slim reader-writer lock.
pub struct PushLock {
    /// Current lock state.
    pub state: PushLockState,
}

impl PushLock {
    /// Create a new, free PushLock.
    pub fn new() -> Self {
        Self {
            state: PushLockState::Free,
        }
    }
}

/// Acquire `lock` in shared (read) mode.
///
/// Multiple shared readers are allowed simultaneously.  If the lock is
/// exclusively held, this function spin-yields until it becomes free.
pub fn acquire_push_lock_shared(lock: &mut PushLock) {
    loop {
        match lock.state {
            PushLockState::Free => {
                lock.state = PushLockState::SharedRead(1);
                return;
            }
            PushLockState::SharedRead(n) => {
                lock.state = PushLockState::SharedRead(n + 1);
                return;
            }
            PushLockState::Exclusive => {
                // Block briefly until the exclusive holder releases.
                crate::proc::sleep_ticks(1);
            }
        }
    }
}

/// Acquire `lock` in exclusive (write) mode.
///
/// Only one exclusive holder at a time; no shared readers either.
/// Spin-yields until the lock is completely free.
pub fn acquire_push_lock_exclusive(lock: &mut PushLock) {
    loop {
        match lock.state {
            PushLockState::Free => {
                lock.state = PushLockState::Exclusive;
                return;
            }
            _ => {
                // Block briefly until the lock is free.
                crate::proc::sleep_ticks(1);
            }
        }
    }
}

/// Release shared (read) access to `lock`.
pub fn release_push_lock_shared(lock: &mut PushLock) {
    match lock.state {
        PushLockState::SharedRead(n) if n > 1 => {
            lock.state = PushLockState::SharedRead(n - 1);
        }
        PushLockState::SharedRead(1) => {
            lock.state = PushLockState::Free;
        }
        _ => {
            // Not held in shared mode — programming error, but don't panic
            // in kernel context; just ignore.
        }
    }
}

/// Release exclusive (write) access to `lock`.
pub fn release_push_lock_exclusive(lock: &mut PushLock) {
    if lock.state == PushLockState::Exclusive {
        lock.state = PushLockState::Free;
    }
}
