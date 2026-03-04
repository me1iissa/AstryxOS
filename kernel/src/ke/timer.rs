//! KeTimer — Waitable Kernel Timers
//!
//! One-shot or periodic timers that become signaled when they fire,
//! optionally queuing a DPC.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};

use super::dispatcher::{DispatcherHeader, DispatcherObjectType};
use super::dpc::{Dpc, DpcImportance, DpcRoutine};

/// A kernel timer object.
pub struct KeTimer {
    pub header: DispatcherHeader,
    pub timer_id: u64,  // references TimerEntry in registry
    pub active: bool,
}

impl KeTimer {
    /// Create a new timer (initially inactive, non-signaled).
    pub fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherObjectType::Timer, 0),
            timer_id: 0,
            active: false,
        }
    }
}

/// An entry in the global timer registry.
struct TimerEntry {
    id: u64,
    due_time: u64,
    period: u64,
    signaled: bool,
    active: bool,
    dpc_routine: Option<DpcRoutine>,
    dpc_context: u64,
}

/// Next timer registry ID.
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

/// Global timer registry.
static TIMER_REGISTRY: Mutex<Option<Vec<TimerEntry>>> = Mutex::new(None);

/// Initialize the timer subsystem.
pub fn init() {
    let mut reg = TIMER_REGISTRY.lock();
    *reg = Some(Vec::new());
    crate::serial_println!("[Ke/Timer] Initialized");
}

/// Arm a timer. The timer will fire at `due_ticks` (absolute tick count).
/// If `period > 0`, it becomes a periodic timer.
/// If a `dpc` is provided, its routine+context are captured for later queuing.
pub fn set_timer(timer: &mut KeTimer, due_ticks: u64, period: u64, dpc: Option<Dpc>) {
    let tid = NEXT_TIMER_ID.fetch_add(1, Ordering::SeqCst);
    timer.timer_id = tid;
    timer.active = true;
    timer.header.signal_state = 0; // not yet signaled

    let (dpc_routine, dpc_context) = match dpc {
        Some(d) => (Some(d.routine), d.context),
        None => (None, 0),
    };

    let entry = TimerEntry {
        id: tid,
        due_time: due_ticks,
        period,
        signaled: false,
        active: true,
        dpc_routine,
        dpc_context,
    };

    let mut reg = TIMER_REGISTRY.lock();
    if let Some(list) = reg.as_mut() {
        list.push(entry);
    }
}

/// Cancel a timer. Returns `true` if it was active.
pub fn cancel_timer(timer: &mut KeTimer) -> bool {
    let was_active = timer.active;
    timer.active = false;

    let mut reg = TIMER_REGISTRY.lock();
    if let Some(list) = reg.as_mut() {
        list.retain(|e| e.id != timer.timer_id);
    }

    was_active
}

/// Check all active timers against the current tick count.
/// Fire expired ones: signal them and queue their DPC if set.
///
/// This should be called from the scheduler timer tick or manually in tests.
pub fn check_timers() {
    let current_ticks = crate::arch::x86_64::irq::get_ticks();

    let mut to_fire: Vec<(u64, Option<DpcRoutine>, u64)> = Vec::new();

    {
        let mut reg = TIMER_REGISTRY.lock();
        if let Some(list) = reg.as_mut() {
            let mut i = 0;
            while i < list.len() {
                if list[i].active && current_ticks >= list[i].due_time {
                    list[i].signaled = true;
                    let routine = list[i].dpc_routine;
                    let ctx = list[i].dpc_context;
                    let timer_id = list[i].id;

                    if list[i].period > 0 {
                        // Periodic: reschedule
                        list[i].due_time = current_ticks + list[i].period;
                        list[i].signaled = false;
                    } else {
                        // One-shot: deactivate
                        list[i].active = false;
                    }

                    to_fire.push((timer_id, routine, ctx));
                }
                i += 1;
            }
        }
    }

    // Now signal the dispatcher objects and queue DPCs outside the lock
    for (timer_id, dpc_routine, dpc_context) in to_fire {
        // Signal the KeTimer in the dispatcher registry
        signal_timer_in_registry(timer_id);

        // Queue DPC if set
        if let Some(routine) = dpc_routine {
            super::dpc::queue_dpc(Dpc {
                routine,
                context: dpc_context,
                importance: DpcImportance::Medium,
                enqueued: false,
            });
        }
    }
}

/// Check if a specific timer has fired (by its timer_id in the timer registry).
pub fn is_timer_signaled(timer_id: u64) -> bool {
    let reg = TIMER_REGISTRY.lock();
    if let Some(list) = reg.as_ref() {
        for entry in list.iter() {
            if entry.id == timer_id {
                return entry.signaled;
            }
        }
    }
    false
}

/// Signal the timer with the given timer_id in the dispatcher registry.
fn signal_timer_in_registry(timer_id: u64) {
    // Look through the dispatcher registry to find the timer with this timer_id
    use super::dispatcher::{DISPATCHER_REGISTRY, DispatcherEntry};
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        for (_id, entry) in map.iter_mut() {
            if let DispatcherEntry::Timer(ref mut t) = entry {
                if t.timer_id == timer_id {
                    t.header.signal_state = 1;
                    for wb in t.header.wait_list.iter_mut() {
                        wb.satisfied = true;
                    }
                    // Unblock threads waiting on this timer.
                    super::dispatcher::wake_blocked_waiters(&mut t.header);
                    break;
                }
            }
        }
    }
}
