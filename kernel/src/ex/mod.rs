//! Ex — Executive Services
//!
//! Provides executive-level synchronization and work management:
//! - EResource (reader-writer lock)
//! - Fast Mutex (lightweight non-recursive mutex)
//! - Push Lock (slim reader-writer)
//! - System Worker Threads (deferred work items)

pub mod resource;
pub mod fast_mutex;
pub mod push_lock;
pub mod work_queue;

pub use resource::EResource;
pub use fast_mutex::FastMutex;
pub use push_lock::{PushLock, PushLockState};
pub use work_queue::{WorkItem, WorkQueueType, WorkItemRoutine};

/// Initialize executive services.
pub fn init() {
    work_queue::init_work_queues();
    crate::serial_println!("[Ex] Executive services initialized (EResource+FastMutex+PushLock+WorkQueues)");
}
