//! KeSemaphore — Counting Semaphore
//!
//! A classic counting semaphore with a configurable maximum limit.

use super::dispatcher::{DispatcherHeader, DispatcherObjectType};

/// A kernel semaphore object.
pub struct KeSemaphore {
    pub header: DispatcherHeader,
    pub limit: i32,
}

impl KeSemaphore {
    /// Create a new semaphore with the given initial count and maximum limit.
    pub fn new(initial_count: i32, limit: i32) -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherObjectType::Semaphore, initial_count),
            limit,
        }
    }
}

/// Release (increment) the semaphore by `adjustment`.
///
/// Returns the previous count on success, or `-1` if the release would
/// exceed the semaphore's limit.
pub fn release_semaphore(sem: &mut KeSemaphore, adjustment: i32) -> i32 {
    let prev = sem.header.signal_state;
    let new_count = prev + adjustment;
    if new_count > sem.limit {
        return -1; // would exceed limit
    }
    sem.header.signal_state = new_count;

    // Wake up to new_count waiting threads; each woken thread "consumes" one count.
    if new_count > 0 {
        let mut woken = 0;
        for wb in sem.header.wait_list.iter_mut() {
            if !wb.satisfied && woken < sem.header.signal_state {
                wb.satisfied = true;
                woken += 1;
            }
        }
        // Decrement the count for each woken waiter.
        sem.header.signal_state -= woken;
    }

    // Unblock the woken threads.
    super::dispatcher::wake_blocked_waiters(&mut sem.header);
    prev
}
