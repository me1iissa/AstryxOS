//! signalfd — signal delivery via file descriptor.
//!
//! `signalfd4(fd, mask, sizemask, flags)` creates (or updates) a signalfd.
//! The fd becomes readable (POLLIN) whenever a signal matching the sigmask
//! is pending for the calling process.  `read()` returns one or more
//! `signalfd_siginfo` records (128 bytes each), dequeuing each signal.

extern crate alloc;

use spin::Mutex;

/// Max concurrent signalfd instances.
const MAX_SIGNALFDS: usize = 32;

/// signalfd_siginfo layout (128 bytes, Linux ABI).
/// Only the fields most commonly checked by libc/libraries are populated.
#[repr(C)]
pub struct SfdSiginfo {
    pub ssi_signo:   u32,   // +0
    pub ssi_errno:   i32,   // +4
    pub ssi_code:    i32,   // +8
    pub ssi_pid:     u32,   // +12
    pub ssi_uid:     u32,   // +16
    pub ssi_fd:      i32,   // +20
    pub ssi_tid:     u32,   // +24
    pub ssi_band:    u32,   // +28
    pub ssi_overrun: u32,   // +32
    pub ssi_trapno:  u32,   // +36
    pub ssi_status:  i32,   // +40
    pub ssi_int:     i32,   // +44
    pub ssi_ptr:     u64,   // +48
    pub ssi_utime:   u64,   // +56
    pub ssi_stime:   u64,   // +64
    pub ssi_addr:    u64,   // +72
    pub ssi_addr_lsb: u16,  // +80
    _pad: [u8; 46],         // +82..128
}

impl SfdSiginfo {
    fn zeroed() -> Self {
        SfdSiginfo {
            ssi_signo: 0, ssi_errno: 0, ssi_code: 0, ssi_pid: 0, ssi_uid: 0,
            ssi_fd: 0, ssi_tid: 0, ssi_band: 0, ssi_overrun: 0, ssi_trapno: 0,
            ssi_status: 0, ssi_int: 0, ssi_ptr: 0, ssi_utime: 0, ssi_stime: 0,
            ssi_addr: 0, ssi_addr_lsb: 0, _pad: [0; 46],
        }
    }
}

/// SI_KERNEL: signal sent by the kernel.
const SI_KERNEL: i32 = 0x80;

#[derive(Clone, Copy)]
pub struct SignalFdEntry {
    pub in_use:  bool,
    /// PID of the process that created this signalfd.
    pub pid:     u64,
    /// Bitmask of signals this fd monitors (signal N = bit N-1).
    pub sigmask: u64,
}

impl SignalFdEntry {
    const fn empty() -> Self {
        Self { in_use: false, pid: 0, sigmask: 0 }
    }
}

static TABLE: Mutex<[SignalFdEntry; MAX_SIGNALFDS]> =
    Mutex::new([SignalFdEntry::empty(); MAX_SIGNALFDS]);

/// Create a new signalfd. Returns slot index or u64::MAX.
pub fn create(pid: u64, sigmask: u64) -> u64 {
    let mut table = TABLE.lock();
    for (i, slot) in table.iter_mut().enumerate() {
        if !slot.in_use {
            *slot = SignalFdEntry { in_use: true, pid, sigmask };
            return i as u64;
        }
    }
    u64::MAX
}

/// Update the sigmask of an existing signalfd (re-use fd case).
pub fn update_mask(id: u64, sigmask: u64) {
    let mut table = TABLE.lock();
    if let Some(slot) = table.get_mut(id as usize) {
        if slot.in_use { slot.sigmask = sigmask; }
    }
}

/// Return true if any signal matching the mask is pending for the process.
pub fn is_readable(id: u64) -> bool {
    let entry = {
        let table = TABLE.lock();
        match table.get(id as usize) {
            Some(s) if s.in_use => *s,
            _ => return false,
        }
    };
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter()
        .find(|p| p.pid == entry.pid)
        .map(|p| p.signal_state.as_ref().map_or(false, |ss| ss.pending & entry.sigmask != 0))
        .unwrap_or(false)
}

/// Read up to `count / 128` signalfd_siginfo records.
/// Dequeues matching pending signals from the process.
/// Returns bytes written or Err(-11) (EAGAIN) if no signals pending.
pub fn read(id: u64, buf: *mut u8, count: usize) -> Result<usize, i64> {
    if count < 128 { return Err(-22); } // EINVAL

    let entry = {
        let table = TABLE.lock();
        match table.get(id as usize) {
            Some(s) if s.in_use => *s,
            _ => return Err(-9), // EBADF
        }
    };

    // Dequeue at most count/128 signals.
    let max_records = count / 128;
    let mut written  = 0usize;

    for _ in 0..max_records {
        // Find and dequeue one pending signal matching the mask.
        let signum = {
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter_mut().find(|p| p.pid == entry.pid) {
                None => break,
                Some(p) => {
                    let ss = match p.signal_state.as_mut() {
                        Some(s) => s, None => break,
                    };
                    let masked = ss.pending & entry.sigmask;
                    if masked == 0 { break; }
                    let bit = masked.trailing_zeros(); // lowest matching signal
                    ss.pending &= !(1u64 << bit);
                    (bit + 1) as u32 // convert to signal number (1-based)
                }
            }
        };

        // Fill signalfd_siginfo at buf + written.
        let mut info = SfdSiginfo::zeroed();
        info.ssi_signo = signum;
        info.ssi_code  = SI_KERNEL;

        let dst = unsafe {
            core::slice::from_raw_parts_mut(buf.add(written), 128)
        };
        // SAFETY: SfdSiginfo is repr(C), 128 bytes, no padding ambiguity.
        let src = unsafe {
            core::slice::from_raw_parts(
                &info as *const SfdSiginfo as *const u8,
                128,
            )
        };
        dst.copy_from_slice(src);
        written += 128;
    }

    if written == 0 { Err(-11) } else { Ok(written) }
}

/// Free a signalfd slot.
pub fn close(id: u64) {
    let mut table = TABLE.lock();
    if let Some(slot) = table.get_mut(id as usize) {
        *slot = SignalFdEntry::empty();
    }
}
