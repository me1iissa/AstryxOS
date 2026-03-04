//! KeEvent — NT Kernel Events
//!
//! Synchronization events: notification (manual-reset) and
//! synchronization (auto-reset) event types.

use super::dispatcher::{DispatcherHeader, DispatcherObjectType};

/// Event type: notification = manual-reset, synchronization = auto-reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Stays signaled until explicit reset; wakes all waiters.
    NotificationEvent,
    /// Auto-resets after releasing one waiter.
    SynchronizationEvent,
}

/// A kernel event object.
pub struct KeEvent {
    pub header: DispatcherHeader,
    pub event_type: EventType,
}

impl KeEvent {
    /// Create a new event (initially non-signaled).
    pub fn new(event_type: EventType) -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherObjectType::Event, 0),
            event_type,
        }
    }
}

/// Signal the event, return previous signal state.
pub fn set_event(event: &mut KeEvent) -> i32 {
    let prev = event.header.signal_state;
    event.header.signal_state = 1;

    match event.event_type {
        EventType::NotificationEvent => {
            // Wake ALL waiters (manual-reset event stays signaled).
            for wb in event.header.wait_list.iter_mut() {
                wb.satisfied = true;
            }
        }
        EventType::SynchronizationEvent => {
            // Wake ONE waiter, then auto-reset.
            if let Some(wb) = event.header.wait_list.iter_mut().find(|wb| !wb.satisfied) {
                wb.satisfied = true;
                event.header.signal_state = 0;
            }
        }
    }

    // Unblock the woken threads so the scheduler can run them.
    super::dispatcher::wake_blocked_waiters(&mut event.header);
    prev
}

/// Reset (clear) the event, return previous signal state.
pub fn reset_event(event: &mut KeEvent) -> i32 {
    let prev = event.header.signal_state;
    event.header.signal_state = 0;
    prev
}

/// Pulse the event: signal it, wake all current waiters, then immediately reset.
/// Returns previous signal state.
pub fn pulse_event(event: &mut KeEvent) -> i32 {
    let prev = event.header.signal_state;
    // Momentarily signal — wake all current waiters
    for wb in event.header.wait_list.iter_mut() {
        wb.satisfied = true;
    }
    // Reset immediately
    event.header.signal_state = 0;

    // Unblock the woken threads.
    super::dispatcher::wake_blocked_waiters(&mut event.header);
    prev
}

/// Read the current signal state of the event.
pub fn read_state_event(event: &KeEvent) -> i32 {
    event.header.signal_state
}
