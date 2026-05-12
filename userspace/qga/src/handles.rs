//! Daemon-internal handle table — maps QGA handle integers onto libsys file
//! descriptors.
//!
//! Handles are issued from a monotonic counter starting at 1; an entry is
//! reused only after `guest-file-close` releases it.  The cap of 64 is far
//! larger than any sensible QGA session — the host extracts a screenshot
//! file at a time.

const TABLE_LEN: usize = 64;

#[derive(Clone, Copy)]
struct Slot {
    handle: i64, // 0 means free
    fd: u64,
}

pub struct HandleTable {
    slots: [Slot; TABLE_LEN],
    next_id: i64,
}

impl HandleTable {
    pub const fn new() -> Self {
        Self {
            slots: [Slot { handle: 0, fd: 0 }; TABLE_LEN],
            next_id: 1,
        }
    }

    /// Allocate a new handle for `fd`.  Returns `None` if all slots are
    /// occupied or the monotonic counter would wrap.
    pub fn insert(&mut self, fd: u64) -> Option<i64> {
        let slot = self.slots.iter().position(|s| s.handle == 0)?;
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1)?;
        self.slots[slot] = Slot { handle: id, fd };
        Some(id)
    }

    /// Look up the libsys fd associated with `handle`, returning `None` if
    /// the handle is unknown or already closed.
    pub fn lookup(&self, handle: i64) -> Option<u64> {
        if handle <= 0 {
            return None;
        }
        self.slots
            .iter()
            .find(|s| s.handle == handle)
            .map(|s| s.fd)
    }

    /// Remove the entry for `handle`, returning the underlying fd so the
    /// caller can `close()` it.  Returns `None` if the handle is unknown.
    pub fn remove(&mut self, handle: i64) -> Option<u64> {
        if handle <= 0 {
            return None;
        }
        for s in self.slots.iter_mut() {
            if s.handle == handle {
                let fd = s.fd;
                s.handle = 0;
                s.fd = 0;
                return Some(fd);
            }
        }
        None
    }
}
