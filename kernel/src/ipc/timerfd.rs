//! timerfd — POSIX-style timer notification file descriptors.
//!
//! `timerfd_create(clockid, flags)` allocates a timer fd.
//! `timerfd_settime(fd, flags, new_value, old_value)` arms/disarms it.
//! `timerfd_gettime(fd, curr_value)` reads the current setting.
//! `read(fd, buf, 8)` returns the number of expirations as a LE-u64.
//! `poll/epoll` reports POLLIN when one or more expirations are pending.
//!
//! Timing uses the PIT TICK_COUNT (~100 Hz = 10 ms resolution).

extern crate alloc;

use spin::Mutex;

/// Max concurrent timerfds.
const MAX_TIMERFDS: usize = 64;

/// Nanoseconds per PIT tick (100 Hz → 10 ms).
const NS_PER_TICK: u64 = 10_000_000;

/// timerfd clockid constants (from <time.h>).
pub const CLOCK_REALTIME:  u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;

/// TFD_TIMER_ABSTIME: interpret expiry as absolute time (we map to relative).
pub const TFD_TIMER_ABSTIME: u32 = 1;
/// TFD_TIMER_CANCEL_ON_SET: cancel on clock change (stub).
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 2;

#[derive(Clone, Copy)]
pub struct TimerFdEntry {
    pub in_use:          bool,
    pub clockid:         u32,
    /// Tick count at which the next expiration fires (0 = not armed).
    pub next_expiry:     u64,
    /// Interval between repeating expirations in ticks (0 = one-shot).
    pub interval_ticks:  u64,
    /// Number of expirations not yet consumed by read().
    pub expirations:     u64,
}

impl TimerFdEntry {
    const fn empty() -> Self {
        Self { in_use: false, clockid: 0, next_expiry: 0, interval_ticks: 0, expirations: 0 }
    }
}

static TABLE: Mutex<[TimerFdEntry; MAX_TIMERFDS]> =
    Mutex::new([TimerFdEntry::empty(); MAX_TIMERFDS]);

/// Allocate a new timerfd. Returns the slot index (used as inode) or u64::MAX.
pub fn create(clockid: u32) -> u64 {
    let mut table = TABLE.lock();
    for (i, slot) in table.iter_mut().enumerate() {
        if !slot.in_use {
            *slot = TimerFdEntry { in_use: true, clockid, ..TimerFdEntry::empty() };
            return i as u64;
        }
    }
    u64::MAX
}

/// `timerfd_settime` — arm or disarm the timer.
///
/// `value_ns` is the initial expiry delay in nanoseconds (0 = disarm).
/// `interval_ns` is the repeat interval in nanoseconds (0 = one-shot).
/// Returns the previous (interval_ns, value_ns) on success.
pub fn settime(id: u64, flags: u32, value_ns: u64, interval_ns: u64) -> Option<(u64, u64)> {
    let mut table = TABLE.lock();
    let slot = table.get_mut(id as usize)?;
    if !slot.in_use { return None; }

    // Snapshot current settings before overwriting.
    let now = crate::arch::x86_64::irq::get_ticks();
    let old_interval = slot.interval_ticks * NS_PER_TICK;
    let old_value = if slot.next_expiry == 0 {
        0
    } else {
        slot.next_expiry.saturating_sub(now) * NS_PER_TICK
    };

    if value_ns == 0 {
        // Disarm.
        slot.next_expiry    = 0;
        slot.interval_ticks = 0;
        slot.expirations    = 0;
    } else {
        let value_ticks = (value_ns / NS_PER_TICK).max(1);
        slot.interval_ticks = interval_ns / NS_PER_TICK;
        slot.expirations    = 0;

        if flags & TFD_TIMER_ABSTIME != 0 {
            // Absolute time: clamp to at least now+1.
            let abs_ticks = value_ns / NS_PER_TICK;
            slot.next_expiry = abs_ticks.max(now + 1);
        } else {
            slot.next_expiry = now + value_ticks;
        }
    }

    Some((old_interval, old_value))
}

/// `timerfd_gettime` — return (it_interval_ns, it_value_remaining_ns).
pub fn gettime(id: u64) -> (u64, u64) {
    let mut table = TABLE.lock();
    let slot = match table.get_mut(id as usize) {
        Some(s) if s.in_use => s,
        _ => return (0, 0),
    };
    let now = crate::arch::x86_64::irq::get_ticks();
    // Flush pending expirations so remaining value is accurate.
    update_expirations(slot, now);
    let interval_ns = slot.interval_ticks * NS_PER_TICK;
    let value_ns = if slot.next_expiry == 0 {
        0
    } else {
        slot.next_expiry.saturating_sub(now) * NS_PER_TICK
    };
    (interval_ns, value_ns)
}

/// Advance expiration counter for elapsed ticks (called before read/poll).
fn update_expirations(slot: &mut TimerFdEntry, now: u64) {
    if slot.next_expiry == 0 || now < slot.next_expiry {
        return;
    }
    if slot.interval_ticks > 0 {
        // Repeating: count how many intervals have elapsed.
        let elapsed = now - slot.next_expiry + 1;
        let count   = elapsed / slot.interval_ticks + 1;
        slot.expirations  += count;
        slot.next_expiry  += count * slot.interval_ticks;
    } else {
        // One-shot.
        slot.expirations += 1;
        slot.next_expiry  = 0;
    }
}

/// read() — return expiration count as LE u64, reset counter.
/// Returns Err(-11) (EAGAIN) if no expirations are pending.
pub fn read(id: u64) -> Result<u64, i64> {
    let mut table = TABLE.lock();
    let slot = match table.get_mut(id as usize) {
        Some(s) if s.in_use => s,
        _ => return Err(-9), // EBADF
    };
    let now = crate::arch::x86_64::irq::get_ticks();
    update_expirations(slot, now);
    if slot.expirations == 0 {
        return Err(-11); // EAGAIN
    }
    let val = slot.expirations;
    slot.expirations = 0;
    Ok(val)
}

/// poll — returns true if one or more expirations are pending (POLLIN ready).
pub fn is_readable(id: u64) -> bool {
    let mut table = TABLE.lock();
    let slot = match table.get_mut(id as usize) {
        Some(s) if s.in_use => s,
        _ => return false,
    };
    let now = crate::arch::x86_64::irq::get_ticks();
    update_expirations(slot, now);
    slot.expirations > 0
}

/// Free a timerfd slot.
pub fn close(id: u64) {
    let mut table = TABLE.lock();
    if let Some(slot) = table.get_mut(id as usize) {
        *slot = TimerFdEntry::empty();
    }
}
