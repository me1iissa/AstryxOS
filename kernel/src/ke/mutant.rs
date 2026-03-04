//! KeMutant — NT Kernel Mutexes (Mutants)
//!
//! Recursive, ownable kernel mutexes. Called "mutants" in NT tradition.

use super::dispatcher::{DispatcherHeader, DispatcherObjectType};

/// A kernel mutant (mutex) object.
pub struct KeMutant {
    pub header: DispatcherHeader,
    pub owner_thread: Option<u64>,
    pub recursion_count: u32,
    pub abandoned: bool,
}

impl KeMutant {
    /// Create a new mutant — starts signaled (acquirable).
    pub fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherObjectType::Mutant, 1),
            owner_thread: None,
            recursion_count: 0,
            abandoned: false,
        }
    }
}

/// Try to acquire the mutant for the given thread.
///
/// - If the mutant is signaled (unowned), take ownership and return `true`.
/// - If already owned by the same thread, increment recursion count and return `true`.
/// - If owned by another thread, return `false`.
pub fn acquire_mutant(mutant: &mut KeMutant, thread_id: u64) -> bool {
    match mutant.owner_thread {
        None => {
            // Signaled → acquire
            mutant.owner_thread = Some(thread_id);
            mutant.recursion_count = 1;
            mutant.header.signal_state = 0; // now non-signaled (owned)
            true
        }
        Some(owner) if owner == thread_id => {
            // Recursive acquisition
            mutant.recursion_count += 1;
            true
        }
        Some(_) => {
            // Owned by another thread
            false
        }
    }
}

/// Release the mutant. Decrements recursion count; signals when count reaches 0.
///
/// Returns `true` on success, `false` if the caller is not the owner.
pub fn release_mutant(mutant: &mut KeMutant, thread_id: u64) -> bool {
    match mutant.owner_thread {
        Some(owner) if owner == thread_id => {
            mutant.recursion_count -= 1;
            if mutant.recursion_count == 0 {
                mutant.owner_thread = None;
                mutant.header.signal_state = 1; // signaled (available)

                // Transfer ownership directly to the first waiter (if any).
                if let Some(wb) = mutant.header.wait_list.iter_mut().find(|wb| !wb.satisfied) {
                    wb.satisfied = true;
                    mutant.owner_thread = Some(wb.thread_id);
                    mutant.recursion_count = 1;
                    mutant.header.signal_state = 0; // owned again
                }

                // Unblock the woken thread.
                super::dispatcher::wake_blocked_waiters(&mut mutant.header);
            }
            true
        }
        _ => false,
    }
}
