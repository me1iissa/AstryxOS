//! Pseudo-Terminal (PTY) driver — /dev/ptmx + /dev/pts/N
//!
//! Provides up to 16 PTY pairs.  Opening `/dev/ptmx` allocates a pair and
//! returns the master fd; `ioctl(TIOCGPTN)` returns the slave number N;
//! opening `/dev/pts/N` gives the slave fd.
//!
//! Data written to the master appears on the slave's read buffer and vice
//! versa.  TIOCGWINSZ / TIOCSWINSZ pass through silently (80×24 default).
//! `unlockpt` and `grantpt` are no-ops (always succeed).

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

/// Maximum simultaneous PTY pairs.
const MAX_PTYS: usize = 16;
/// Ring buffer capacity per direction.
const BUF_CAP: usize = 4096;

pub struct PtyPair {
    pub in_use:         bool,
    pub slave_locked:   bool,
    /// master→slave (written by master, read by slave)
    pub m2s: Vec<u8>,
    /// slave→master (written by slave, read by master)
    pub s2m: Vec<u8>,
    /// Window size: cols × rows
    pub cols: u16,
    pub rows: u16,
}

impl PtyPair {
    const fn empty() -> Self {
        Self {
            in_use:       false,
            slave_locked: true,
            m2s: Vec::new(),
            s2m: Vec::new(),
            cols: 80,
            rows: 24,
        }
    }
}

// Static table — can't use Vec<PtyPair> in a static, so use Option array.
static PAIRS: Mutex<[Option<PtyPair>; MAX_PTYS]> =
    Mutex::new([const { None }; MAX_PTYS]);

// ── Lifecycle ─────────────────────────────────────────────────────────────────

/// Allocate a new PTY pair.  Returns the PTY index (= slave number N) or
/// `None` if all pairs are in use.
pub fn alloc() -> Option<u8> {
    let mut pairs = PAIRS.lock();
    for (i, slot) in pairs.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(PtyPair {
                in_use:       true,
                slave_locked: true,
                m2s: Vec::new(),
                s2m: Vec::new(),
                cols: 80,
                rows: 24,
            });
            crate::serial_println!("[PTY] Allocated pair {}", i);
            return Some(i as u8);
        }
    }
    None
}

/// Unlock the slave side (called by `unlockpt`).
pub fn unlock_slave(n: u8) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.slave_locked = false;
    }
}

/// Free a PTY pair (called when both ends are closed).
pub fn free(n: u8) {
    let mut pairs = PAIRS.lock();
    if let Some(slot) = pairs.get_mut(n as usize) {
        *slot = None;
        crate::serial_println!("[PTY] Freed pair {}", n);
    }
}

// ── I/O ───────────────────────────────────────────────────────────────────────

/// Write to the master side (data appears on slave's read buffer).
pub fn master_write(n: u8, data: &[u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let space = BUF_CAP.saturating_sub(p.m2s.len());
        let to_copy = data.len().min(space);
        p.m2s.extend_from_slice(&data[..to_copy]);
        to_copy
    } else {
        0
    }
}

/// Read from the master side (data written by slave).
pub fn master_read(n: u8, buf: &mut [u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let to_copy = buf.len().min(p.s2m.len());
        buf[..to_copy].copy_from_slice(&p.s2m[..to_copy]);
        p.s2m.drain(..to_copy);
        to_copy
    } else {
        0
    }
}

/// Returns true if the master read buffer (slave→master) has data.
pub fn master_readable(n: u8) -> bool {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| !p.s2m.is_empty())
        .unwrap_or(false)
}

/// Write to the slave side (data appears on master's read buffer).
pub fn slave_write(n: u8, data: &[u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let space = BUF_CAP.saturating_sub(p.s2m.len());
        let to_copy = data.len().min(space);
        p.s2m.extend_from_slice(&data[..to_copy]);
        to_copy
    } else {
        0
    }
}

/// Read from the slave side (data written by master).
pub fn slave_read(n: u8, buf: &mut [u8]) -> usize {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        let to_copy = buf.len().min(p.m2s.len());
        buf[..to_copy].copy_from_slice(&p.m2s[..to_copy]);
        p.m2s.drain(..to_copy);
        to_copy
    } else {
        0
    }
}

/// Returns true if the slave read buffer (master→slave) has data.
pub fn slave_readable(n: u8) -> bool {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| !p.m2s.is_empty())
        .unwrap_or(false)
}

// ── Window size ───────────────────────────────────────────────────────────────

pub fn get_winsz(n: u8) -> (u16, u16) {
    let pairs = PAIRS.lock();
    pairs.get(n as usize)
        .and_then(|s| s.as_ref())
        .map(|p| (p.cols, p.rows))
        .unwrap_or((80, 24))
}

pub fn set_winsz(n: u8, cols: u16, rows: u16) {
    let mut pairs = PAIRS.lock();
    if let Some(Some(p)) = pairs.get_mut(n as usize) {
        p.cols = cols;
        p.rows = rows;
    }
}
