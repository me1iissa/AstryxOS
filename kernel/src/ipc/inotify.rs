//! inotify — real filesystem event notification.
//!
//! Each `inotify_init1()` call allocates an `InotifyInstance` that holds:
//!   - a list of watch descriptors (wd → path + mask)
//!   - a bounded ring-buffer of `inotify_event` records
//!
//! Events are injected via `notify_event(path, filename, mask, cookie)` which
//! is called from the VFS hot paths (open, close, write, create, remove, rename).
//!
//! Linux semantics preserved:
//!   - Duplicate add_watch on the same path merges the mask and returns the
//!     existing wd.
//!   - Max 16 384 queued events per instance; overflow sets IN_Q_OVERFLOW on
//!     a synthetic event with wd = -1.
//!   - `read()` drains events into `struct inotify_event` ABI records.
//!   - `is_readable()` returns true when at least one event is queued.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};

// ── inotify mask constants (Linux ABI) ────────────────────────────────────────

pub const IN_ACCESS:        u32 = 0x0000_0001;
pub const IN_MODIFY:        u32 = 0x0000_0002;
pub const IN_ATTRIB:        u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE:   u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_OPEN:          u32 = 0x0000_0020;
pub const IN_MOVED_FROM:    u32 = 0x0000_0040;
pub const IN_MOVED_TO:      u32 = 0x0000_0080;
pub const IN_CREATE:        u32 = 0x0000_0100;
pub const IN_DELETE:        u32 = 0x0000_0200;
pub const IN_DELETE_SELF:   u32 = 0x0000_0400;
pub const IN_MOVE_SELF:     u32 = 0x0000_0800;
pub const IN_Q_OVERFLOW:    u32 = 0x0000_4000;
pub const IN_ISDIR:         u32 = 0x4000_0000;

/// Maximum events in the queue before we drop with IN_Q_OVERFLOW.
const MAX_EVENTS: usize = 16384;

/// Maximum concurrent inotify instances.
const MAX_INOTIFYFDS: usize = 64;

/// Maximum filename length stored inline in an event (including NUL).
const MAX_NAME_LEN: usize = 256;

/// Global watch descriptor counter — each add_watch gets a unique positive value.
static NEXT_WD: AtomicU32 = AtomicU32::new(1);

// ── Event record ─────────────────────────────────────────────────────────────

/// Queued event (internal representation).
#[derive(Clone)]
struct QueuedEvent {
    /// Watch descriptor (-1 for IN_Q_OVERFLOW).
    wd:     i32,
    /// Event mask bits.
    mask:   u32,
    /// Rename cookie (paired IN_MOVED_FROM / IN_MOVED_TO).
    cookie: u32,
    /// Optional filename bytes (with NUL terminator), zero-padded.
    name:   [u8; MAX_NAME_LEN],
    /// Length of padded name field to emit in the ABI struct (0 if no name).
    padded_name_len: u32,
}

impl QueuedEvent {
    fn new(wd: i32, mask: u32, cookie: u32, name: &str) -> Self {
        let mut arr = [0u8; MAX_NAME_LEN];
        let raw = name.as_bytes();
        let copy_len = raw.len().min(MAX_NAME_LEN - 1);
        arr[..copy_len].copy_from_slice(&raw[..copy_len]);
        // NUL terminator is already zero from array init.
        let padded_name_len = if name.is_empty() {
            0u32
        } else {
            // Round up copy_len+1 (including NUL) to next u32 boundary.
            (((copy_len + 1) + 3) / 4 * 4) as u32
        };
        QueuedEvent { wd, mask, cookie, name: arr, padded_name_len }
    }

    /// Total size of this event's ABI record.
    fn abi_size(&self) -> usize {
        16 + self.padded_name_len as usize
    }

    /// Write this event as `struct inotify_event` into `dst`.
    /// Returns bytes written (= abi_size()), or 0 if dst is too small.
    fn write_abi(&self, dst: &mut [u8]) -> usize {
        let sz = self.abi_size();
        if dst.len() < sz { return 0; }
        dst[0..4].copy_from_slice(&self.wd.to_le_bytes());
        dst[4..8].copy_from_slice(&self.mask.to_le_bytes());
        dst[8..12].copy_from_slice(&self.cookie.to_le_bytes());
        dst[12..16].copy_from_slice(&self.padded_name_len.to_le_bytes());
        if self.padded_name_len > 0 {
            let end = 16 + self.padded_name_len as usize;
            for b in dst[16..end].iter_mut() { *b = 0; }
            dst[16..16 + self.padded_name_len as usize]
                .copy_from_slice(&self.name[..self.padded_name_len as usize]);
        }
        sz
    }
}

// ── Watch entry ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct WatchEntry {
    wd:   i32,
    /// Absolute path being watched (directory or file).
    path: String,
    mask: u32,
}

// ── InotifyInstance ───────────────────────────────────────────────────────────

struct InotifyInstance {
    watches: Vec<WatchEntry>,
    queue:   Vec<QueuedEvent>,
    /// True when an overflow event is already queued (avoid duplicates).
    overflow_queued: bool,
}

impl InotifyInstance {
    fn new() -> Self {
        InotifyInstance {
            watches: Vec::new(),
            queue:   Vec::new(),
            overflow_queued: false,
        }
    }

    /// Push an event, enforcing the max-queue limit.
    fn push_event(&mut self, ev: QueuedEvent) {
        if self.queue.len() >= MAX_EVENTS {
            if !self.overflow_queued {
                self.overflow_queued = true;
                // Push an IN_Q_OVERFLOW synthetic event with wd = -1.
                self.queue.push(QueuedEvent::new(-1, IN_Q_OVERFLOW, 0, ""));
            }
            return;
        }
        // If we had previously set overflow_queued but now have space, clear it.
        // (This can happen if something else drained the queue before us.)
        self.overflow_queued = false;
        self.queue.push(ev);
    }
}

// ── Global instance table ─────────────────────────────────────────────────────
//
// We use Option<Box<InotifyInstance>> so we can have heap-allocated instances
// in a fixed-size Mutex-protected array without needing a const Vec::new().

static TABLE: Mutex<[Option<alloc::boxed::Box<InotifyInstance>>; MAX_INOTIFYFDS]> =
    Mutex::new([
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
    ]);

// ── Public API ───────────────────────────────────────────────────────────────

/// Allocate a new inotify instance.  Returns slot index or u64::MAX.
pub fn create() -> u64 {
    let mut table = TABLE.lock();
    for (i, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(alloc::boxed::Box::new(InotifyInstance::new()));
            return i as u64;
        }
    }
    u64::MAX
}

/// `inotify_add_watch` — register (or update) a watch for `path` with `mask`.
///
/// If the path is already watched by this instance the mask is merged and the
/// existing wd is returned (Linux semantics).
/// Returns a positive watch descriptor on success, -1 on error.
pub fn add_watch(id: u64, path: &str, mask: u32) -> i32 {
    let mut table = TABLE.lock();
    let inst = match table.get_mut(id as usize).and_then(|s| s.as_deref_mut()) {
        Some(i) => i,
        None => return -1,
    };

    // Merge mask if path already watched.
    if let Some(w) = inst.watches.iter_mut().find(|w| w.path == path) {
        w.mask |= mask;
        return w.wd;
    }

    let wd = NEXT_WD.fetch_add(1, Ordering::Relaxed) as i32;
    inst.watches.push(WatchEntry { wd, path: String::from(path), mask });
    wd
}

/// `inotify_rm_watch` — remove watch `wd` from instance `id`.
pub fn rm_watch(id: u64, wd: i32) -> bool {
    let mut table = TABLE.lock();
    let inst = match table.get_mut(id as usize).and_then(|s| s.as_deref_mut()) {
        Some(i) => i,
        None => return false,
    };
    let before = inst.watches.len();
    inst.watches.retain(|w| w.wd != wd);
    inst.watches.len() < before
}

/// `read()` — drain queued events into caller-supplied buffer.
///
/// Returns `Ok(bytes)` or:
///   `Err(-9)`  (EBADF)  — unknown instance id
///   `Err(-11)` (EAGAIN) — no events pending
///   `Err(-22)` (EINVAL) — buffer smaller than first event
pub fn read(id: u64, buf: *mut u8, count: usize) -> Result<usize, i64> {
    let mut table = TABLE.lock();
    let inst = match table.get_mut(id as usize).and_then(|s| s.as_deref_mut()) {
        Some(i) => i,
        None => return Err(-9),
    };

    if inst.queue.is_empty() {
        return Err(-11); // EAGAIN
    }

    // The buffer must accommodate at least the first event.
    let first_sz = inst.queue[0].abi_size();
    if count < first_sz {
        return Err(-22); // EINVAL
    }

    let mut written = 0usize;
    while !inst.queue.is_empty() {
        let ev_sz = inst.queue[0].abi_size();
        if written + ev_sz > count { break; }
        let ev = inst.queue.remove(0);
        // SAFETY: buf is caller-provided and we verified count >= first_sz.
        let dst = unsafe { core::slice::from_raw_parts_mut(buf.add(written), ev_sz) };
        ev.write_abi(dst);
        written += ev_sz;
    }

    if written == 0 { Err(-11) } else { Ok(written) }
}

/// Returns true when at least one event is pending (used by poll/epoll/select).
pub fn is_readable(id: u64) -> bool {
    let table = TABLE.lock();
    match table.get(id as usize).and_then(|s| s.as_deref()) {
        Some(inst) => !inst.queue.is_empty(),
        None => false,
    }
}

/// Free an inotify instance and all its watches.
pub fn close(id: u64) {
    let mut table = TABLE.lock();
    if let Some(slot) = table.get_mut(id as usize) {
        *slot = None;
    }
}

// ── VFS notification entry point ─────────────────────────────────────────────

/// Fire an inotify event on behalf of the VFS.
///
/// `dir_path`  — absolute path of the parent directory (e.g. "/tmp").
/// `filename`  — name of the entry that changed (e.g. "foo").  Pass "" when
///               the event concerns the directory itself.
/// `mask`      — one of the IN_* bits.
/// `cookie`    — non-zero for paired IN_MOVED_FROM / IN_MOVED_TO events.
///
/// Called from VFS with NO kernel locks held (MOUNTS has already been
/// released), so acquiring TABLE here is safe.
pub fn notify_event(dir_path: &str, filename: &str, mask: u32, cookie: u32) {
    // Build the full path of the target file for file-self watch matching.
    let full_path: String = if filename.is_empty() {
        String::from(dir_path)
    } else if dir_path.ends_with('/') {
        alloc::format!("{}{}", dir_path, filename)
    } else {
        alloc::format!("{}/{}", dir_path, filename)
    };

    let mut table = TABLE.lock();
    for slot in table.iter_mut().flatten() {
        // Collect matching (wd, effective_mask, emit_name) tuples first so we
        // don't hold an immutable borrow while calling push_event (mutable).
        let mut hits: Vec<(i32, u32, bool)> = Vec::new(); // (wd, eff_mask, is_dir_watch)

        for w in &slot.watches {
            if w.mask & mask == 0 { continue; }
            // Directory watch: path matches the parent directory.
            let dir_match = w.path == dir_path;
            // Self watch: path matches the full path of the changed file.
            let self_match = !filename.is_empty() && w.path == full_path;
            if dir_match {
                hits.push((w.wd, w.mask & mask, true));
            } else if self_match {
                hits.push((w.wd, w.mask & mask, false));
            }
        }

        for (wd, eff_mask, is_dir_watch) in hits {
            let name = if is_dir_watch { filename } else { "" };
            slot.push_event(QueuedEvent::new(wd, eff_mask, cookie, name));
        }
    }
}
