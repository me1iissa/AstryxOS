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

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Max concurrent timerfds.
const MAX_TIMERFDS: usize = 64;

/// Lockless hint: earliest `next_expiry` (in scheduler ticks) across
/// all armed timerfds, or `u64::MAX` if no timerfd is armed.  Read by
/// the timer ISR every tick to decide whether to ring the poll bell
/// without ever taking `TABLE` from interrupt context — `TABLE` is
/// also held by syscall paths (`read`, `is_readable`, `settime`) and
/// taking it from the ISR would deadlock the same CPU if a syscall
/// holds it mid-edit.
///
/// Written by `settime` (the only path that arms or disarms a timer),
/// and reset by `maybe_ring_from_tick` after a bell fire so the bell
/// does not re-ring every tick until the next `settime`.  Reset by
/// `update_expirations` is intentionally avoided — the
/// `update_expirations` path holds `TABLE` and racing the timer ISR
/// against the slot edit would be uncomfortable.
static EARLIEST_TIMERFD_EXPIRY: AtomicU64 = AtomicU64::new(u64::MAX);

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

    // Recompute the lockless earliest-expiry hint so the timer ISR can
    // ring the bell at expiry without taking TABLE.  Walk the slot
    // array once — bounded by MAX_TIMERFDS (=64) so the cost is fixed.
    let mut earliest = u64::MAX;
    for s in table.iter() {
        if s.in_use && s.next_expiry != 0 && s.next_expiry < earliest {
            earliest = s.next_expiry;
        }
    }
    EARLIEST_TIMERFD_EXPIRY.store(earliest, Ordering::Release);

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
///
/// On a repeating timer this advances `next_expiry` to the first
/// future tick; the bell-fire hint is then refreshed via
/// `recompute_hint_min` so the timer ISR rings the bell again at the
/// next period without the caller needing to re-arm via `settime`.
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
        // Periodic-timer hint update: propagate the freshly-advanced
        // next_expiry into the lockless hint so the ISR sees it.
        let prev = EARLIEST_TIMERFD_EXPIRY.load(Ordering::Acquire);
        if slot.next_expiry < prev {
            EARLIEST_TIMERFD_EXPIRY.store(slot.next_expiry, Ordering::Release);
        }
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
    // Recompute the earliest-expiry hint after disarming this slot.
    let mut earliest = u64::MAX;
    for s in table.iter() {
        if s.in_use && s.next_expiry != 0 && s.next_expiry < earliest {
            earliest = s.next_expiry;
        }
    }
    EARLIEST_TIMERFD_EXPIRY.store(earliest, Ordering::Release);
}

/// Called from the timer ISR each tick.  Lockless: reads the
/// earliest-expiry hint and rings the poll bell only when at least
/// one armed timer has reached or passed its scheduled tick.  On a
/// fire, the hint is bumped to `u64::MAX` so the bell does not re-ring
/// every tick — `settime` (the only path that arms a new timer) will
/// re-populate the hint on its next call.  Periodic timers are kept
/// firing because each `read` advances `next_expiry` and the next
/// `settime` (or the syscall path itself, via `update_expirations` →
/// `settime` not being called) is not invoked; instead, the lazy
/// rescan on the wake-up satisfies any periodic timerfd because the
/// poller calls `is_readable` which updates `expirations`.
///
/// Safe to call from interrupt context: it never blocks, only takes
/// a single atomic Acquire load and (on fire) two Acquire/Release
/// CAS-equivalent stores plus the bell-ring path's brief
/// `POLL_BELL` lock.  `POLL_BELL` is never acquired by ISR-only code
/// other than this hook, so no nested-ISR deadlock is possible.
#[inline]
pub fn maybe_ring_from_tick(now_tick: u64) {
    let earliest = EARLIEST_TIMERFD_EXPIRY.load(Ordering::Acquire);
    if earliest == u64::MAX || now_tick < earliest {
        return;
    }
    // Race-tolerant CAS to claim the ring: if another CPU already
    // bumped the hint to u64::MAX, leave them to it — the bell will
    // only fire once per arm cycle.
    if EARLIEST_TIMERFD_EXPIRY
        .compare_exchange(earliest, u64::MAX, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        crate::ipc::waitlist::ring_poll_bell_for(
            crate::ipc::waitlist::PollBellSource::Timerfd);
    }
}
