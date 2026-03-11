//! inotify — filesystem event notification (stub implementation).
//!
//! Accepts all inotify syscalls so applications that use file-watching
//! don't crash.  No events are ever delivered — `read()` always returns
//! EAGAIN and `poll()` never signals POLLIN.  Applications must handle
//! this gracefully (most do, falling back to polling).

use spin::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};

/// Max concurrent inotify instances.
const MAX_INOTIFYFDS: usize = 16;

/// Global watch descriptor counter (each add_watch gets a unique >0 value).
static NEXT_WD: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy)]
pub struct InotifyFdEntry {
    pub in_use: bool,
}

impl InotifyFdEntry {
    const fn empty() -> Self { Self { in_use: false } }
}

static TABLE: Mutex<[InotifyFdEntry; MAX_INOTIFYFDS]> =
    Mutex::new([InotifyFdEntry::empty(); MAX_INOTIFYFDS]);

/// Allocate a new inotify fd. Returns slot index or u64::MAX.
pub fn create() -> u64 {
    let mut table = TABLE.lock();
    for (i, slot) in table.iter_mut().enumerate() {
        if !slot.in_use {
            slot.in_use = true;
            return i as u64;
        }
    }
    u64::MAX
}

/// `inotify_add_watch` — register a watch for a path.
/// Returns a positive watch descriptor on success, -1 on error.
pub fn add_watch(_id: u64, _path: &str, _mask: u32) -> i32 {
    NEXT_WD.fetch_add(1, Ordering::Relaxed) as i32
}

/// `inotify_rm_watch` — remove a watch descriptor (stub).
pub fn rm_watch(_id: u64, _wd: i32) -> bool { true }

/// read — no events available (EAGAIN).
pub fn read(_id: u64) -> Result<usize, i64> { Err(-11) }

/// poll — never readable (no events queued).
pub fn is_readable(_id: u64) -> bool { false }

/// Free an inotify slot.
pub fn close(id: u64) {
    let mut table = TABLE.lock();
    if let Some(slot) = table.get_mut(id as usize) {
        *slot = InotifyFdEntry::empty();
    }
}
