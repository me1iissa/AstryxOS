//! Wait Infrastructure — Core wait mechanism for dispatcher objects
//!
//! Provides `wait_for_single_object` and `wait_for_multiple_objects`.
//! Uses true thread blocking: waiting threads are set to `Blocked` state
//! and removed from the scheduler's run queue until the target object is
//! signaled or the timeout expires.

use super::dispatcher::{
    DispatcherObjectType, DispatcherEntry, WaitType, DISPATCHER_REGISTRY,
    dispatcher_header_mut, WaitBlock,
};
use super::event::{self, EventType};
use super::mutant;
use super::semaphore;

/// Result of a wait operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStatus {
    /// Wait satisfied; u32 = index for WaitAny (0 for single object)
    Satisfied(u32),
    /// Wait timed out
    Timeout,
    /// Mutant was abandoned
    Abandoned,
    /// Wait failed (invalid object, etc.)
    Failed,
}

/// Wait for a single dispatcher object to become signaled.
///
/// - `object_id`: the dispatcher registry ID
/// - `timeout_ticks`: `None` = infinite, `Some(0)` = poll, `Some(n)` = wait up to n ticks
///
/// The thread is truly blocked (removed from the run queue) until the object
/// is signaled or the timeout expires.  The scheduler will not run this thread
/// while it is blocked.
pub fn wait_for_single_object(
    object_id: u64,
    timeout_ticks: Option<u64>,
) -> WaitStatus {
    let tid = crate::proc::current_tid();

    // ── Phase 1: Try immediate satisfaction (poll) ──────────────────
    {
        let result = try_satisfy_single(object_id);
        if let Some(status) = result {
            return status;
        }
    }

    // Poll mode — we already tried.
    if timeout_ticks == Some(0) {
        return WaitStatus::Timeout;
    }

    // ── Phase 2: Set up true blocking wait ──────────────────────────
    let deadline = timeout_ticks.map(|t| {
        crate::arch::x86_64::irq::get_ticks().wrapping_add(t)
    });

    // Add a WaitBlock to the object's wait_list.
    {
        let mut reg = DISPATCHER_REGISTRY.lock();
        if let Some(map) = reg.as_mut() {
            if let Some(entry) = map.get_mut(&object_id) {
                let header = dispatcher_header_mut(entry);
                header.wait_list.push(WaitBlock {
                    thread_id: tid,
                    wait_type: WaitType::WaitAny,
                    wait_key: 0,
                    satisfied: false,
                });
            } else {
                return WaitStatus::Failed;
            }
        } else {
            return WaitStatus::Failed;
        }
    }

    // Set the thread to Blocked with a timeout deadline.
    // The scheduler will skip this thread until it is set back to Ready
    // (either by a signal operation or by the timeout path in the scheduler tick).
    {
        let mut threads = crate::proc::THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.state = crate::proc::ThreadState::Blocked;
            t.wake_tick = deadline.unwrap_or(u64::MAX);
        }
    }

    // Yield to the scheduler.  This call will not return until this thread
    // is set back to Ready (by the signal operation or by timeout).
    crate::sched::schedule();

    // ── Phase 3: Woken up — determine the result ────────────────────
    let was_satisfied = {
        let mut reg = DISPATCHER_REGISTRY.lock();
        let mut satisfied = false;
        if let Some(map) = reg.as_mut() {
            if let Some(entry) = map.get_mut(&object_id) {
                let header = dispatcher_header_mut(entry);
                if let Some(pos) = header.wait_list.iter().position(|wb| wb.thread_id == tid) {
                    satisfied = header.wait_list[pos].satisfied;
                    header.wait_list.remove(pos);
                }
            }
        }
        satisfied
    };

    if was_satisfied {
        WaitStatus::Satisfied(0)
    } else {
        WaitStatus::Timeout
    }
}

/// Wait for multiple dispatcher objects.
///
/// - `object_ids`: slice of dispatcher registry IDs
/// - `wait_type`: `WaitAll` or `WaitAny`
/// - `timeout_ticks`: `None` = infinite, `Some(0)` = poll, `Some(n)` = wait up to n ticks
///
/// For `WaitAny`: uses true blocking — the thread sleeps until any object is
/// signaled.  For `WaitAll`: uses a blocking-yield hybrid (blocks the thread
/// but re-checks periodically via timeout wakeups) because atomically waiting
/// on multiple objects requires cross-object coordination.
pub fn wait_for_multiple_objects(
    object_ids: &[u64],
    wait_type: WaitType,
    timeout_ticks: Option<u64>,
) -> WaitStatus {
    let tid = crate::proc::current_tid();
    let start = crate::arch::x86_64::irq::get_ticks();

    // ── Phase 1: Try immediate satisfaction ──────────────────────────
    {
        let result = try_satisfy_multiple(object_ids, wait_type);
        if let Some(status) = result {
            return status;
        }
    }

    if timeout_ticks == Some(0) {
        return WaitStatus::Timeout;
    }

    match wait_type {
        WaitType::WaitAny => {
            // True blocking for WaitAny: add WaitBlocks to all objects.
            let deadline = timeout_ticks.map(|t| start.wrapping_add(t));

            {
                let mut reg = DISPATCHER_REGISTRY.lock();
                if let Some(map) = reg.as_mut() {
                    for (idx, &id) in object_ids.iter().enumerate() {
                        if let Some(entry) = map.get_mut(&id) {
                            let header = dispatcher_header_mut(entry);
                            header.wait_list.push(WaitBlock {
                                thread_id: tid,
                                wait_type: WaitType::WaitAny,
                                wait_key: idx as u32,
                                satisfied: false,
                            });
                        } else {
                            // Clean up any WaitBlocks we already inserted.
                            for &prev_id in &object_ids[..idx] {
                                if let Some(prev_entry) = map.get_mut(&prev_id) {
                                    let h = dispatcher_header_mut(prev_entry);
                                    h.wait_list.retain(|wb| wb.thread_id != tid);
                                }
                            }
                            return WaitStatus::Failed;
                        }
                    }
                } else {
                    return WaitStatus::Failed;
                }
            }

            // Block the thread.
            {
                let mut threads = crate::proc::THREAD_TABLE.lock();
                if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                    t.state = crate::proc::ThreadState::Blocked;
                    t.wake_tick = deadline.unwrap_or(u64::MAX);
                }
            }

            crate::sched::schedule();

            // Find which object was satisfied and clean up all WaitBlocks.
            let result = {
                let mut reg = DISPATCHER_REGISTRY.lock();
                let mut result = WaitStatus::Timeout;
                if let Some(map) = reg.as_mut() {
                    for &id in object_ids {
                        if let Some(entry) = map.get_mut(&id) {
                            let header = dispatcher_header_mut(entry);
                            if let Some(pos) = header.wait_list.iter().position(|wb| wb.thread_id == tid) {
                                let wb = &header.wait_list[pos];
                                if wb.satisfied && result == WaitStatus::Timeout {
                                    result = WaitStatus::Satisfied(wb.wait_key);
                                }
                                header.wait_list.remove(pos);
                            }
                        }
                    }
                }
                result
            };

            result
        }
        WaitType::WaitAll => {
            // WaitAll: use blocking with periodic re-check.
            // We block with a short timeout cut and re-check on each wake.
            let deadline = timeout_ticks.map(|t| start.wrapping_add(t));

            loop {
                let result = try_satisfy_multiple(object_ids, WaitType::WaitAll);
                if let Some(status) = result {
                    return status;
                }

                // Check deadline.
                if let Some(dl) = deadline {
                    let now = crate::arch::x86_64::irq::get_ticks();
                    if now >= dl {
                        return WaitStatus::Timeout;
                    }
                }

                // Block briefly (10 ticks = ~100ms) then re-check.
                let short_deadline = {
                    let now = crate::arch::x86_64::irq::get_ticks();
                    let short = now.wrapping_add(10);
                    match deadline {
                        Some(dl) if dl < short => dl,
                        _ => short,
                    }
                };

                {
                    let mut threads = crate::proc::THREAD_TABLE.lock();
                    if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                        t.state = crate::proc::ThreadState::Blocked;
                        t.wake_tick = short_deadline;
                    }
                }

                crate::sched::schedule();
            }
        }
    }
}

/// Try to satisfy a wait on a single object.
/// Returns `Some(status)` if satisfied, `None` if not yet signaled.
fn try_satisfy_single(object_id: u64) -> Option<WaitStatus> {
    let mut reg = DISPATCHER_REGISTRY.lock();
    let map = match reg.as_mut() {
        Some(m) => m,
        None => return Some(WaitStatus::Failed),
    };

    let entry = match map.get_mut(&object_id) {
        Some(e) => e,
        None => return Some(WaitStatus::Failed),
    };

    match entry {
        DispatcherEntry::Event(ev) => {
            if ev.header.signal_state > 0 {
                // For SynchronizationEvent, auto-reset on satisfy
                if ev.event_type == EventType::SynchronizationEvent {
                    ev.header.signal_state = 0;
                }
                Some(WaitStatus::Satisfied(0))
            } else {
                None
            }
        }
        DispatcherEntry::Mutant(m) => {
            if m.abandoned {
                return Some(WaitStatus::Abandoned);
            }
            let tid = crate::proc::current_tid();
            if m.header.signal_state > 0 {
                // Acquire for the calling thread.
                m.owner_thread = Some(tid);
                m.recursion_count = 1;
                m.header.signal_state = 0;
                Some(WaitStatus::Satisfied(0))
            } else if m.owner_thread == Some(tid) {
                // Recursive acquisition by the same thread.
                m.recursion_count += 1;
                Some(WaitStatus::Satisfied(0))
            } else {
                None
            }
        }
        DispatcherEntry::Semaphore(s) => {
            if s.header.signal_state > 0 {
                s.header.signal_state -= 1;
                Some(WaitStatus::Satisfied(0))
            } else {
                None
            }
        }
        DispatcherEntry::Timer(t) => {
            if t.header.signal_state > 0 {
                Some(WaitStatus::Satisfied(0))
            } else {
                None
            }
        }
    }
}

/// Try to satisfy a multi-object wait.
fn try_satisfy_multiple(object_ids: &[u64], wait_type: WaitType) -> Option<WaitStatus> {
    let mut reg = DISPATCHER_REGISTRY.lock();
    let map = match reg.as_mut() {
        Some(m) => m,
        None => return Some(WaitStatus::Failed),
    };

    match wait_type {
        WaitType::WaitAll => {
            // Check if ALL objects are signaled
            for &id in object_ids {
                match map.get(&id) {
                    None => return Some(WaitStatus::Failed),
                    Some(entry) => {
                        let signaled = match entry {
                            DispatcherEntry::Event(e) => e.header.signal_state > 0,
                            DispatcherEntry::Mutant(m) => m.header.signal_state > 0,
                            DispatcherEntry::Semaphore(s) => s.header.signal_state > 0,
                            DispatcherEntry::Timer(t) => t.header.signal_state > 0,
                        };
                        if !signaled {
                            return None; // not all signaled yet
                        }
                    }
                }
            }
            // All signaled — consume (auto-reset events, decrement semaphores, etc.)
            for &id in object_ids {
                consume_signal(map.get_mut(&id).unwrap());
            }
            Some(WaitStatus::Satisfied(0))
        }
        WaitType::WaitAny => {
            // Check if ANY object is signaled
            for (idx, &id) in object_ids.iter().enumerate() {
                match map.get_mut(&id) {
                    None => return Some(WaitStatus::Failed),
                    Some(entry) => {
                        let signaled = match entry {
                            DispatcherEntry::Event(e) => e.header.signal_state > 0,
                            DispatcherEntry::Mutant(m) => m.header.signal_state > 0,
                            DispatcherEntry::Semaphore(s) => s.header.signal_state > 0,
                            DispatcherEntry::Timer(t) => t.header.signal_state > 0,
                        };
                        if signaled {
                            consume_signal(entry);
                            return Some(WaitStatus::Satisfied(idx as u32));
                        }
                    }
                }
            }
            None // none signaled yet
        }
    }
}

/// Consume the signal on a dispatcher entry (auto-reset events, decrement semaphores).
fn consume_signal(entry: &mut DispatcherEntry) {
    match entry {
        DispatcherEntry::Event(e) => {
            if e.event_type == EventType::SynchronizationEvent {
                e.header.signal_state = 0;
            }
        }
        DispatcherEntry::Mutant(m) => {
            let tid = crate::proc::current_tid();
            m.owner_thread = Some(tid);
            m.recursion_count = 1;
            m.header.signal_state = 0;
        }
        DispatcherEntry::Semaphore(s) => {
            s.header.signal_state -= 1;
        }
        DispatcherEntry::Timer(_) => {
            // Timers stay signaled until cancelled or reset
        }
    }
}
