//! Fast Mutex — Lightweight non-recursive mutex
//!
//! Raises IRQL to APC level while held, preventing APC delivery and ensuring
//! the holder won't be preempted by APCs.  Not re-entrant: attempting to
//! acquire recursively is undefined behavior in NT; here it will spin forever.

use core::sync::atomic::{AtomicU64, Ordering};
use crate::ke::irql::{self, Irql};

/// Monotonically increasing ID generator for FastMutex instances.
static NEXT_FAST_MUTEX_ID: AtomicU64 = AtomicU64::new(1);

/// A lightweight, non-recursive executive mutex.
pub struct FastMutex {
    /// Unique identifier.
    pub id: u64,
    /// Whether the mutex is currently held.
    pub locked: bool,
    /// Thread ID of the current owner, if any.
    pub owner: Option<u64>,
    /// Number of times a caller had to wait (contention statistic).
    pub contention_count: u64,
    /// Saved IRQL from before acquisition (restored on release).
    pub old_irql: u8,
}

impl FastMutex {
    /// Create a new, unlocked FastMutex.
    pub fn new() -> Self {
        Self {
            id: NEXT_FAST_MUTEX_ID.fetch_add(1, Ordering::Relaxed),
            locked: false,
            owner: None,
            contention_count: 0,
            old_irql: Irql::Passive as u8,
        }
    }
}

/// Acquire `mutex`, raising IRQL to APC level.
///
/// Spins (with yield) until the mutex is free, then acquires it.  Returns
/// `true` on success (always succeeds, but the return value is kept for
/// API consistency).
pub fn acquire_fast_mutex(mutex: &mut FastMutex) -> bool {
    // Raise IRQL to APC first.
    let old = irql::raise_irql(Irql::Apc);
    mutex.old_irql = old as u8;

    let tid = crate::proc::current_tid();

    // Block until free (short sleeps instead of spin-yield for SMP efficiency).
    while mutex.locked {
        mutex.contention_count += 1;
        // Lower IRQL briefly to allow scheduling, sleep, then re-raise.
        irql::lower_irql(old);
        crate::proc::sleep_ticks(1);
        let _ = irql::raise_irql(Irql::Apc);
    }

    mutex.locked = true;
    mutex.owner = Some(tid);
    true
}

/// Release `mutex` and restore the previous IRQL.
pub fn release_fast_mutex(mutex: &mut FastMutex) {
    let old = Irql::from_u8(mutex.old_irql).unwrap_or(Irql::Passive);
    mutex.locked = false;
    mutex.owner = None;
    irql::lower_irql(old);
}

/// Try to acquire `mutex` without waiting.
///
/// Returns `true` if acquired, `false` if already held.
pub fn try_acquire_fast_mutex(mutex: &mut FastMutex) -> bool {
    if mutex.locked {
        return false;
    }

    let old = irql::raise_irql(Irql::Apc);
    mutex.old_irql = old as u8;

    // Re-check after IRQL raise (window of opportunity).
    if mutex.locked {
        irql::lower_irql(old);
        return false;
    }

    let tid = crate::proc::current_tid();
    mutex.locked = true;
    mutex.owner = Some(tid);
    true
}
