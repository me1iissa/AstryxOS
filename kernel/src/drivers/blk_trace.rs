//! Block-I/O LBA trace ring (feature `blk-trace`, default-OFF).
//!
//! # Why a ring instead of `serial_println!`
//!
//! The previous `blk-trace` design emitted one `[BLK] op/lba/len/pid` line to
//! COM1 **synchronously inside the virtio-blk submit hot path**, once per
//! request. Under KVM this is pathological:
//!
//!   * Each byte written to the 16550A THR is an `outb` to port 0x3F8, and
//!     every port-I/O instruction traps to the hypervisor as a VM-exit
//!     (Intel SDM Vol. 3C §25.1.3, "I/O instructions"). A ~28-byte `[BLK]`
//!     line is ~28 VM-exits.
//!   * The serial driver polls `LSR.THRE` per 16-byte FIFO chunk with a
//!     bounded spin (NS16550A datasheet §8.3). At 115200 baud a full 16-byte
//!     FIFO takes ~1.4 ms to physically shift out, so a 2-chunk line spins
//!     the submitting CPU for **milliseconds** waiting on the UART.
//!   * All of this runs under the single global `SERIAL` `spin::Mutex`, so on
//!     SMP both cores funnel their disk-trace output through one lock.
//!
//! Measured cost (deterministic 50,000 single-sector reads, KVM, smp=2):
//! ~4.2 s without the trace vs ~165 s with it — a ~39× slowdown, dominated by
//! per-op UART drain. A real Firefox boot emits ~66,589 `[BLK]` lines, i.e.
//! ~minutes of added boot time spent in the serial driver.
//!
//! # This design
//!
//! `record()` writes a fixed-size packed [`BlkEvent`] into a static ring with a
//! single relaxed `fetch_add` to claim a slot — no lock, no UART, no VM-exit.
//! Cost per call is a handful of cycles. The ring is drained **out of band**:
//!
//!   * [`dump_json`] serialises the live ring as JSON — exposed via the kdb
//!     `blk-trace` op and the `qemu-harness.py blk-trace drain` wrapper.
//!   * [`flush_to_serial`] emits the classic `[BLK] op/lba/len/pid` lines in a
//!     single controlled burst, so the existing serial-log heatmap ingestion
//!     keeps working — but as an explicit drain, never per-op.
//!
//! When the `blk-trace` feature is OFF, [`record`] compiles to an empty inline
//! no-op (zero overhead, byte-identical default builds) and the drains report
//! the feature is disabled.

extern crate alloc;

use alloc::string::String;

/// One traced block request. 24 bytes; `op` is `b'R'` or `b'W'`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BlkEvent {
    pub seq: u64,
    pub lba: u64,
    pub len: u32,
    pub pid: u32,
    pub op: u8,
}

impl BlkEvent {
    const EMPTY: BlkEvent = BlkEvent { seq: 0, lba: 0, len: 0, pid: 0, op: 0 };
}

#[cfg(feature = "blk-trace")]
mod imp {
    use super::{BlkEvent, String};
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Ring capacity (power of two so wrap is a mask). 65,536 events covers a
    /// full Firefox boot's ~66k requests without wrap; on overflow the oldest
    /// events are overwritten, which is fine for a recency-weighted heatmap.
    pub const CAP: usize = 1 << 16;
    const MASK: u64 = (CAP as u64) - 1;

    /// Monotonic write cursor. The low `log2(CAP)` bits index the ring; the
    /// full value is the total events ever recorded (used to detect wrap and
    /// to report drop counts on drain).
    static CURSOR: AtomicU64 = AtomicU64::new(0);

    /// The ring. Plain `static mut` guarded by the per-slot publication
    /// protocol below — no `Mutex`, so `record()` never blocks a submitter.
    static mut RING: [BlkEvent; CAP] = [BlkEvent::EMPTY; CAP];

    /// Record one block request. Lock-free and SMP-safe: each caller claims a
    /// unique monotonic slot via a single `fetch_add`, then writes its event
    /// into `slot & MASK`. A concurrent writer that wins a later slot writes a
    /// different cell; a wrap that collides with a slow reader can tear a
    /// single event, which a heatmap tolerates (no pointer/length is derived
    /// from ring contents). The stored `seq` lets the drain order events and
    /// spot a wrap.
    #[inline]
    pub fn record(op: u8, lba: u64, len: u32, pid: u32) {
        let seq = CURSOR.fetch_add(1, Ordering::Relaxed);
        let idx = (seq & MASK) as usize;
        // SAFETY: `idx < CAP`. Writes to distinct slots do not alias; a wrap
        // collision only tears trace data, never kernel state. RING is only
        // read by the drains, which run on the kdb/test thread, not in IRQ.
        unsafe {
            let ev = &mut *core::ptr::addr_of_mut!(RING[idx]);
            ev.seq = seq;
            ev.lba = lba;
            ev.len = len;
            ev.pid = pid;
            ev.op = op;
        }
    }

    /// Snapshot of valid events, oldest-first, into `dst`. Returns
    /// `(total_recorded, dropped_to_wrap)`.
    fn snapshot(dst: &mut [BlkEvent]) -> (u64, u64) {
        let total = CURSOR.load(Ordering::Acquire);
        let have = core::cmp::min(total, CAP as u64);
        let dropped = total.saturating_sub(have);
        let start = total.saturating_sub(have); // first still-resident seq
        let mut n = 0usize;
        let mut s = start;
        while s < total && n < dst.len() {
            let idx = (s & MASK) as usize;
            // SAFETY: idx < CAP; read-only snapshot of POD.
            dst[n] = unsafe { *core::ptr::addr_of!(RING[idx]) };
            n += 1;
            s += 1;
        }
        (total, dropped)
    }

    /// Serialise the live ring as JSON for the kdb `blk-trace` op.
    ///
    /// To bound the output (the kdb response is a heap `String`), only the most
    /// recent `MAX_EMIT` events are emitted; `total`/`dropped`/`emitted` make
    /// the truncation explicit. The data.img heatmap aggregates into a fixed
    /// bucket grid, so the most-recent window is sufficient for the display.
    pub fn dump_json(out: &mut String) {
        use core::fmt::Write;
        const MAX_EMIT: usize = 8192;
        let total = CURSOR.load(Ordering::Acquire);
        let resident = core::cmp::min(total, CAP as u64);
        let emit = core::cmp::min(resident, MAX_EMIT as u64);
        let first = total.saturating_sub(emit);
        let dropped = total.saturating_sub(resident);
        let _ = write!(
            out,
            r#"{{"feature":"on","total":{},"resident":{},"dropped":{},"emitted":{},"cap":{},"events":["#,
            total, resident, dropped, emit, CAP
        );
        let mut s = first;
        let mut firstcomma = true;
        while s < total {
            let idx = (s & MASK) as usize;
            // SAFETY: idx < CAP; read-only POD access.
            let ev = unsafe { *core::ptr::addr_of!(RING[idx]) };
            if !firstcomma { out.push(','); }
            firstcomma = false;
            let _ = write!(
                out,
                r#"{{"op":"{}","lba":{},"len":{},"pid":{}}}"#,
                if ev.op == b'R' { 'R' } else { 'W' },
                ev.lba, ev.len, ev.pid
            );
            s += 1;
        }
        out.push_str("]}");
    }

    /// Emit the classic `[BLK] op=.. lba=.. len=.. pid=..` lines to the serial
    /// log in one controlled burst. Back-compat for the data.img heatmap
    /// ingestion that scans the serial log — same on-wire format as the old
    /// per-op path, but drained on demand instead of in the hot path. Returns
    /// the number of lines emitted.
    pub fn flush_to_serial() -> u64 {
        let mut buf = [BlkEvent::EMPTY; CAP];
        let (total, dropped) = snapshot(&mut buf);
        let resident = core::cmp::min(total, CAP as u64);
        crate::serial_println!(
            "[BLK-FLUSH] begin total={} resident={} dropped={}",
            total, resident, dropped
        );
        let mut emitted = 0u64;
        for i in 0..(resident as usize) {
            let ev = buf[i];
            crate::serial_println!(
                "[BLK] op={} lba={} len={} pid={}",
                if ev.op == b'R' { 'R' } else { 'W' },
                ev.lba, ev.len, ev.pid
            );
            emitted += 1;
        }
        crate::serial_println!("[BLK-FLUSH] end emitted={}", emitted);
        emitted
    }
}

// ── Public surface ───────────────────────────────────────────────────────────
//
// `record` is always defined so the virtio-blk hot path calls it
// unconditionally; when the feature is off it is an empty `#[inline]` no-op the
// optimiser elides. The drains report the feature state so the kdb protocol
// surface is stable across builds.

/// Record one block request into the trace ring (no-op unless `blk-trace`).
#[inline(always)]
pub fn record(_op: u8, _lba: u64, _len: u32, _pid: u32) {
    #[cfg(feature = "blk-trace")]
    imp::record(_op, _lba, _len, _pid);
}

/// Serialise the trace ring as JSON (kdb `blk-trace` op / harness drain).
pub fn dump_json(out: &mut String) {
    #[cfg(feature = "blk-trace")]
    {
        imp::dump_json(out);
        return;
    }
    #[cfg(not(feature = "blk-trace"))]
    out.push_str(r#"{"feature":"off","note":"build with --features blk-trace to record [BLK] events"}"#);
}

/// Drain the ring to the serial log as classic `[BLK]` lines (heatmap compat).
/// Returns the number of `[BLK]` lines emitted (0 when the feature is off).
pub fn flush_to_serial() -> u64 {
    #[cfg(feature = "blk-trace")]
    { return imp::flush_to_serial(); }
    #[cfg(not(feature = "blk-trace"))]
    { 0 }
}
