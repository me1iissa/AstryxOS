//! System Worker Threads — Executive work item queues
//!
//! Provides a deferred work-item mechanism at the executive level.  Work items
//! are enqueued and later processed by `process_work_items()`, which services
//! the three priority queues in order: HyperCritical → Critical → Delayed.

extern crate alloc;

use alloc::collections::VecDeque;
use spin::Mutex;

/// Signature for a work-item callback.
pub type WorkItemRoutine = fn(context: u64);

/// Priority class of a work queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkQueueType {
    /// Normal priority.
    DelayedWorkQueue,
    /// High priority.
    CriticalWorkQueue,
    /// Highest priority — processed first.
    HyperCriticalWorkQueue,
}

/// A single work item to be executed asynchronously.
pub struct WorkItem {
    pub routine: WorkItemRoutine,
    pub context: u64,
    pub queue_type: WorkQueueType,
}

/// Internal queue state for one priority level.
struct WorkQueue {
    items: VecDeque<WorkItem>,
    pending_count: u64,
    processed_count: u64,
}

impl WorkQueue {
    const fn new() -> Self {
        Self {
            items: VecDeque::new(),
            pending_count: 0,
            processed_count: 0,
        }
    }
}

// ── Global work queues (one per priority level) ────────────────────────────

static DELAYED_QUEUE: Mutex<WorkQueue> = Mutex::new(WorkQueue::new());
static CRITICAL_QUEUE: Mutex<WorkQueue> = Mutex::new(WorkQueue::new());
static HYPER_CRITICAL_QUEUE: Mutex<WorkQueue> = Mutex::new(WorkQueue::new());

/// Initialize the work-queue subsystem.
pub fn init_work_queues() {
    // Queues are already initialized via const constructors; this is a
    // placeholder for any future setup (e.g., spawning actual worker threads).
    crate::serial_println!("[Ex/WorkQueue] Work queues initialized (Delayed+Critical+HyperCritical)");
}

/// Enqueue a work item into the appropriate priority queue.
pub fn queue_work_item(item: WorkItem) {
    match item.queue_type {
        WorkQueueType::DelayedWorkQueue => {
            let mut q = DELAYED_QUEUE.lock();
            q.items.push_back(item);
            q.pending_count += 1;
        }
        WorkQueueType::CriticalWorkQueue => {
            let mut q = CRITICAL_QUEUE.lock();
            q.items.push_back(item);
            q.pending_count += 1;
        }
        WorkQueueType::HyperCriticalWorkQueue => {
            let mut q = HYPER_CRITICAL_QUEUE.lock();
            q.items.push_back(item);
            q.pending_count += 1;
        }
    }
}

/// Convenience wrapper — build a `WorkItem` and enqueue it.
pub fn ex_queue_work_item(
    routine: WorkItemRoutine,
    context: u64,
    queue_type: WorkQueueType,
) {
    queue_work_item(WorkItem {
        routine,
        context,
        queue_type,
    });
}

/// Process all pending work items across all queues.
///
/// Priority order: **HyperCritical** → **Critical** → **Delayed**.
/// Each item's routine is called inline; after completion the item is
/// counted as processed.
pub fn process_work_items() {
    drain_single_queue(&HYPER_CRITICAL_QUEUE);
    drain_single_queue(&CRITICAL_QUEUE);
    drain_single_queue(&DELAYED_QUEUE);
}

/// Drain and execute all items in a specific queue type.
pub fn drain_work_queue(queue_type: WorkQueueType) {
    let q = match queue_type {
        WorkQueueType::DelayedWorkQueue => &DELAYED_QUEUE,
        WorkQueueType::CriticalWorkQueue => &CRITICAL_QUEUE,
        WorkQueueType::HyperCriticalWorkQueue => &HYPER_CRITICAL_QUEUE,
    };
    drain_single_queue(q);
}

/// Returns `(delayed_pending, critical_pending, hyper_critical_pending)`.
pub fn work_queue_stats() -> (u64, u64, u64) {
    let d = DELAYED_QUEUE.lock().items.len() as u64;
    let c = CRITICAL_QUEUE.lock().items.len() as u64;
    let h = HYPER_CRITICAL_QUEUE.lock().items.len() as u64;
    (d, c, h)
}

/// Total number of items processed across all queue types (lifetime count).
pub fn total_processed() -> u64 {
    let d = DELAYED_QUEUE.lock().processed_count;
    let c = CRITICAL_QUEUE.lock().processed_count;
    let h = HYPER_CRITICAL_QUEUE.lock().processed_count;
    d + c + h
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Drain a single `Mutex<WorkQueue>`, executing each item's routine.
fn drain_single_queue(queue: &Mutex<WorkQueue>) {
    // Take all items out under the lock, then execute outside the lock to
    // avoid holding it while running arbitrary callbacks.
    let batch: VecDeque<WorkItem> = {
        let mut q = queue.lock();
        core::mem::replace(&mut q.items, VecDeque::new())
    };

    let count = batch.len() as u64;
    for item in batch {
        (item.routine)(item.context);
    }

    if count > 0 {
        let mut q = queue.lock();
        q.processed_count += count;
        // pending_count tracks enqueued; subtract what we just processed.
        q.pending_count = q.pending_count.saturating_sub(count);
    }
}
