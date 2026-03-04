//! DPC — Deferred Procedure Calls
//!
//! Mechanism for deferring work from ISR context to a lower (but still
//! elevated) IRQL.  DPCs run at IRQL::Dispatch and must not block.

extern crate alloc;

use alloc::collections::VecDeque;
use spin::Mutex;
use super::irql::{self, Irql};

/// DPC callback signature.
pub type DpcRoutine = fn(dpc: &Dpc);

/// Importance level of a DPC (affects queue position).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpcImportance {
    Low,
    Medium, // default
    High,
}

/// A Deferred Procedure Call object.
pub struct Dpc {
    pub routine: DpcRoutine,
    pub context: u64,
    pub importance: DpcImportance,
    pub enqueued: bool,
}

/// Global DPC queue.
static DPC_QUEUE: Mutex<VecDeque<Dpc>> = Mutex::new(VecDeque::new());

/// Initialize the DPC subsystem.
pub fn init() {
    // Queue is already empty via const init; nothing else needed.
    crate::serial_println!("[Ke/DPC] Initialized");
}

/// Initialize a DPC object with the given routine.
pub fn init_dpc(dpc: &mut Dpc, routine: DpcRoutine) {
    dpc.routine = routine;
    dpc.importance = DpcImportance::Medium;
    dpc.context = 0;
    dpc.enqueued = false;
}

/// Enqueue a DPC.  High-importance DPCs go to the front of the queue;
/// Medium and Low go to the back.
pub fn queue_dpc(mut dpc: Dpc) {
    dpc.enqueued = true;
    let mut q = DPC_QUEUE.lock();
    if dpc.importance == DpcImportance::High {
        q.push_front(dpc);
    } else {
        q.push_back(dpc);
    }
}

/// Enqueue a DPC with an explicit context value.
pub fn queue_dpc_with_context(mut dpc: Dpc, context: u64) {
    dpc.context = context;
    queue_dpc(dpc);
}

/// Drain and execute all pending DPCs.
///
/// Called automatically when IRQL drops below Dispatch (via `lower_irql`).
/// Can also be called explicitly.  Temporarily raises IRQL to Dispatch while
/// executing DPC routines.
pub fn drain_dpc_queue() {
    // Take all pending DPCs out of the queue in one shot.
    let mut batch: VecDeque<Dpc> = {
        let mut q = DPC_QUEUE.lock();
        core::mem::replace(&mut *q, VecDeque::new())
    };

    if batch.is_empty() {
        return;
    }

    // Execute each DPC at IRQL::Dispatch.
    let prev = irql::raise_irql(Irql::Dispatch);
    while let Some(dpc) = batch.pop_front() {
        (dpc.routine)(&dpc);
    }
    irql::lower_irql_raw(prev);
}

/// Return the number of DPCs currently queued.
pub fn dpc_queue_length() -> usize {
    DPC_QUEUE.lock().len()
}
