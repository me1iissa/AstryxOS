//! Kernel log ring buffer (`dmesg`).
//!
//! A fixed-capacity byte ring that mirrors the kernel's serial log output so
//! that userspace `syslog(2)`/`klogctl` (and `/proc/kmsg`) can read the boot
//! log without a serial console.  This is the canonical, always-compiled home
//! of the ring; `kdb` and the `syslog(2)` handler both read from it.
//!
//! The ring is fed by a tee in the serial print path
//! (`drivers::serial::_serial_print`) so every line that reaches COM1 also
//! lands here.  Writes are best-effort: a `try_lock` that loses the race (a
//! concurrent reader, or a cross-CPU writer) simply drops the chunk rather
//! than block.  Log fidelity is therefore "almost always complete"; this is
//! the standard trade-off for an in-kernel log ring and matches how a
//! best-effort console buffer behaves.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

/// Ring capacity in bytes.  64 KiB holds the full boot log for a typical run
/// with room to spare; once full, the oldest bytes are overwritten (the most
/// recent 64 KiB are always retained — the bytes `dmesg` cares about).
pub const DMESG_CAP: usize = 64 * 1024;

/// A simple overwrite-on-wrap byte ring.
///
/// `head` is the next write position; `filled` becomes true once the ring has
/// wrapped at least once (i.e. `buf` is fully populated and the logical start
/// of the log is at `head`, not 0).
pub struct DmesgRing {
    buf: [u8; DMESG_CAP],
    head: usize,
    filled: bool,
    /// Read cursor for `SYSLOG_ACTION_READ` (consuming reads).  Counts bytes
    /// already consumed since the last clear; the number of unread bytes is
    /// `len() - read_consumed`.  Reset to 0 on clear.
    read_consumed: usize,
}

impl DmesgRing {
    pub const fn new() -> Self {
        Self { buf: [0u8; DMESG_CAP], head: 0, filled: false, read_consumed: 0 }
    }

    /// Append bytes, overwriting the oldest on wrap.
    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.buf[self.head] = b;
            self.head += 1;
            if self.head == DMESG_CAP {
                self.head = 0;
                self.filled = true;
            }
        }
        // New bytes are "unread"; never let the consume cursor run past the
        // logical length.  (It can only shrink here when the ring wraps and
        // the cursor's record falls off the back; clamp defensively.)
        let total = self.logical_len();
        if self.read_consumed > total {
            self.read_consumed = total;
        }
    }

    /// Number of bytes logically present in the ring (≤ `DMESG_CAP`).
    fn logical_len(&self) -> usize {
        if self.filled { DMESG_CAP } else { self.head }
    }

    /// Copy the entire ring (oldest → newest) into a fresh `Vec`.
    /// Backs `SYSLOG_ACTION_READ_ALL` and `/proc/kmsg`.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.logical_len());
        if self.filled {
            out.extend_from_slice(&self.buf[self.head..]);
            out.extend_from_slice(&self.buf[..self.head]);
        } else {
            out.extend_from_slice(&self.buf[..self.head]);
        }
        out
    }

    /// Bytes available to a consuming `SYSLOG_ACTION_READ` (unread tail).
    /// Backs `SYSLOG_ACTION_SIZE_UNREAD`.
    pub fn unread_len(&self) -> usize {
        self.logical_len().saturating_sub(self.read_consumed)
    }

    /// Consume up to `max` unread bytes (oldest unread first), advancing the
    /// read cursor.  Returns the consumed bytes.  Backs the consuming
    /// `SYSLOG_ACTION_READ`.
    pub fn read_consume(&mut self, max: usize) -> Vec<u8> {
        let snap = self.snapshot();
        let start = self.read_consumed.min(snap.len());
        let end = (start + max).min(snap.len());
        let out = snap[start..end].to_vec();
        self.read_consumed = end;
        out
    }

    /// Drop all content and reset cursors.  Backs `SYSLOG_ACTION_CLEAR`.
    pub fn clear(&mut self) {
        self.head = 0;
        self.filled = false;
        self.read_consumed = 0;
    }
}

/// The global kernel log ring.
pub static DMESG: Mutex<DmesgRing> = Mutex::new(DmesgRing::new());

/// Tee a string into the log ring.  Allocation-free; best-effort under
/// contention (a failed `try_lock` drops the chunk rather than blocking, which
/// is safe to call from the IRQ-disabled serial critical section).
#[inline]
pub fn write_str(s: &str) {
    if let Some(mut r) = DMESG.try_lock() {
        r.write(s.as_bytes());
    }
}

/// Snapshot the whole ring (oldest → newest).  Used by `/proc/kmsg` and kdb.
pub fn snapshot() -> Vec<u8> {
    DMESG.lock().snapshot()
}
