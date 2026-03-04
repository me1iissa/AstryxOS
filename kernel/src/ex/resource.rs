//! EResource — NT Executive reader-writer lock
//!
//! Allows shared (read) or exclusive (write) access to a protected resource.
//! Multiple threads may hold shared access simultaneously; exclusive access
//! requires no other holders.

use core::sync::atomic::{AtomicU64, Ordering};

/// Monotonically increasing ID generator for EResource instances.
static NEXT_RESOURCE_ID: AtomicU64 = AtomicU64::new(1);

/// NT Executive reader-writer lock.
pub struct EResource {
    /// Unique identifier for this resource.
    pub id: u64,
    /// Number of current shared (read) holders.
    pub shared_count: u32,
    /// Thread ID of the exclusive holder, if any.
    pub exclusive_owner: Option<u64>,
    /// Recursive exclusive acquisition count.
    pub exclusive_recursion: u32,
    /// Number of threads waiting for exclusive access.
    pub exclusive_waiters: u32,
    /// Number of threads waiting for shared access.
    pub shared_waiters: u32,
    /// Contention statistics — number of times a caller had to wait.
    pub contention_count: u64,
}

impl EResource {
    /// Create a new EResource in the free state.
    pub fn new() -> Self {
        Self {
            id: NEXT_RESOURCE_ID.fetch_add(1, Ordering::Relaxed),
            shared_count: 0,
            exclusive_owner: None,
            exclusive_recursion: 0,
            exclusive_waiters: 0,
            shared_waiters: 0,
            contention_count: 0,
        }
    }
}

/// Acquire `res` for shared (read) access.
///
/// If the resource is exclusively held by another thread, behavior depends on
/// `wait`:
/// - `true`  — spin-yield until available, then acquire.
/// - `false` — return `false` immediately if not available.
///
/// Multiple shared readers are allowed simultaneously.
pub fn acquire_shared(res: &mut EResource, wait: bool) -> bool {
    let tid = crate::proc::current_tid();

    loop {
        // Allow shared access if: no exclusive holder, OR we ourselves are
        // the exclusive holder (a thread that holds exclusive may also take
        // shared access — NT semantics).
        let can_acquire = match res.exclusive_owner {
            None => true,
            Some(owner) => owner == tid,
        };

        if can_acquire {
            res.shared_count += 1;
            return true;
        }

        if !wait {
            return false;
        }

        // Must wait — track contention.
        res.shared_waiters += 1;
        res.contention_count += 1;
        // Block briefly instead of spinning to save CPU cycles on SMP.
        crate::proc::sleep_ticks(1);
        res.shared_waiters -= 1;
    }
}

/// Acquire `res` for exclusive (write) access.
///
/// If the resource is held (shared or exclusive by another thread), behavior
/// depends on `wait`:
/// - `true`  — spin-yield until available, then acquire.
/// - `false` — return `false` immediately if not available.
///
/// The same thread may acquire exclusive access recursively; the recursion
/// count is incremented.
pub fn acquire_exclusive(res: &mut EResource, wait: bool) -> bool {
    let tid = crate::proc::current_tid();

    loop {
        // Recursive acquisition by the same thread.
        if let Some(owner) = res.exclusive_owner {
            if owner == tid {
                res.exclusive_recursion += 1;
                return true;
            }
        }

        // Can acquire if nobody holds it (no shared readers, no exclusive).
        let free = res.shared_count == 0 && res.exclusive_owner.is_none();

        if free {
            res.exclusive_owner = Some(tid);
            res.exclusive_recursion = 1;
            return true;
        }

        if !wait {
            return false;
        }

        // Must wait.
        res.exclusive_waiters += 1;
        res.contention_count += 1;
        // Block briefly instead of spinning to save CPU cycles on SMP.
        crate::proc::sleep_ticks(1);
        res.exclusive_waiters -= 1;
    }
}

/// Release shared access to `res`.
pub fn release_shared(res: &mut EResource) {
    if res.shared_count > 0 {
        res.shared_count -= 1;
    }
}

/// Release exclusive access to `res`.
///
/// Decrements the recursion count; the resource is fully released only when
/// the recursion count reaches zero.
pub fn release_exclusive(res: &mut EResource) {
    if res.exclusive_recursion > 0 {
        res.exclusive_recursion -= 1;
        if res.exclusive_recursion == 0 {
            res.exclusive_owner = None;
        }
    }
}

/// Returns `true` if the resource is currently held in shared mode.
pub fn is_acquired_shared(res: &EResource) -> bool {
    res.shared_count > 0
}

/// Returns `true` if the resource is currently held in exclusive mode.
pub fn is_acquired_exclusive(res: &EResource) -> bool {
    res.exclusive_owner.is_some()
}

/// Returns the contention count (number of times a caller had to wait).
pub fn get_contention_count(res: &EResource) -> u64 {
    res.contention_count
}
