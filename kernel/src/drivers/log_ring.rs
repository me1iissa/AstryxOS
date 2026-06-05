//! Lock-free guest-RAM log ring — the near-zero-overhead high-volume log sink.
//!
//! # Why a ring instead of `serial_println!`
//!
//! The kernel console is the legacy NS16550A UART at COM1 (port 0x3F8). Each
//! byte written to the THR is an `outb`, and under KVM every port-I/O
//! instruction traps to the hypervisor as a VM-exit (Intel SDM Vol. 3C
//! §25.1.3, "I/O instructions cause VM exits"). The driver also polls
//! `LSR.THRE` (`inb` — another exit) per 16-byte FIFO chunk, all under the
//! global `SERIAL` `spin::Mutex`. A ~150-byte syscall-trace line is therefore
//! ~150 VM-exits plus lock contention; a Firefox boot emits tens of millions
//! of such lines, so the firehose alone can add tens of minutes of wall time.
//!
//! The 16550A has no DMA and no batch interface — it is PIO by design (NS16550A
//! datasheet §8), so there is no cheaper way to push the firehose through it.
//!
//! # This design (the cheap transport)
//!
//! [`record`] copies a fully-formatted log line into a large byte ring in guest
//! RAM, claiming space with a single relaxed `fetch_add` — no lock, no `outb`,
//! no VM-exit. Cost per call is a bounded `memcpy` plus one atomic. The ring is
//! drained **out of band**, exactly like the block-trace ring it generalises
//! (`drivers/blk_trace.rs`): the host harness asks the kernel to serialise the
//! live ring over the kdb channel (`log-ring drain`), or to re-emit the
//! buffered lines to COM1 in one controlled burst at shutdown
//! (`log-ring flush`). Either way the same log content still lands in a file a
//! human or agent can read; the per-byte UART cost is paid once, in a burst, or
//! never (when drained via kdb).
//!
//! # Backing store
//!
//! The ring is **PMM-allocated at [`init`] time** (one contiguous run of pages,
//! addressed through the higher-half map), not a giant `static` array. A
//! multi-megabyte `static [u8; N]` would inflate the kernel image's BSS and
//! push `__kernel_end` past the historical 8 MiB heap-base floor, perturbing
//! the runtime heap layout (`mm::heap::compute_heap_layout`). Allocating from
//! the PMM — the same mechanism the virtio drivers use for their virtqueues —
//! decouples the ring size from the kernel image and heap entirely.
//!
//! Until [`init`] runs, [`record`] is a safe no-op (the base pointer is null),
//! so the early-boot path simply keeps using COM1 directly.
//!
//! # Record framing
//!
//! Records are length-prefixed and stored in a power-of-two byte ring so wrap
//! is a mask. Each record is:
//!
//! ```text
//!   u32 magic = REC_MAGIC      (frame sync; lets the drain re-find boundaries
//!                               after the oldest records are overwritten)
//!   u32 len                    (payload byte count, <= MAX_RECORD payload)
//!   u8  payload[len]           (the formatted line, '\n'-terminated by caller)
//! ```
//!
//! A reservation claims `header + len` contiguous bytes via one `fetch_add` on
//! a monotonic cursor. The low `log2(CAP)` bits index the ring; the full cursor
//! value is the total bytes ever written, used to detect wrap and report drop
//! counts. Writers to disjoint reservations never alias; a wrap that collides
//! with a slow drain can tear one record, which the drain detects by the magic
//! and resyncs forward — no kernel state is ever derived from ring contents.
//!
//! # What goes here vs. COM1
//!
//! This ring is for the **firehose** — high-frequency trace families
//! (`[SC]` syscall trace, etc.). COM1 16550 PIO stays the lifeline for:
//!   * early boot, before this ring or the harness drain exist;
//!   * `panic` / `ke::bugcheck` (which already bypass the `SERIAL` mutex via
//!     `util::no_alloc_fmt`);
//!   * low-volume, must-always-appear lines.
//!
//! Routing is decided by [`crate::drivers::serial::log_fast`] / the
//! `serial_fast_println!` macro — see `drivers/serial.rs`.

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Ring capacity in bytes (power of two so wrap is a mask). 4 MiB holds tens of
/// thousands of ~150-byte trace lines before wrap; the drain reports total and
/// dropped byte counts so truncation is always explicit.
pub const CAP: usize = 4 * 1024 * 1024;
const MASK: u64 = (CAP as u64) - 1;

/// Per-record frame header: `u32 magic` + `u32 len`.
const HEADER_LEN: usize = 8;
/// Frame-sync magic prefixing every record. Chosen to be unlikely in formatted
/// log text so the drain can resynchronise after wrap-overwrite.
const REC_MAGIC: u32 = 0x676F_4C52; // "RLog" little-endian-ish sentinel

/// Largest payload a single [`record`] call may store. Longer lines are
/// truncated with no trailing marker so one oversized line cannot desync the
/// ring. 1 KiB comfortably covers the `[SC]` trace line and stack snapshots.
pub const MAX_RECORD: usize = 1024;

/// Virtual base address of the PMM-allocated ring buffer, or 0 until [`init`]
/// runs. The hot path loads this once with a relaxed atomic; a null base makes
/// [`record`] a no-op (early-boot callers fall back to COM1).
static RING_BASE: AtomicU64 = AtomicU64::new(0);

/// Monotonic byte write cursor. The low `log2(CAP)` bits index the ring; the
/// full value is the total bytes ever reserved (used to detect wrap and report
/// drops on drain).
static CURSOR: AtomicU64 = AtomicU64::new(0);

/// Count of records dropped because they exceeded `MAX_RECORD` after the
/// truncation cap (should stay 0; diagnostic only).
static OVERSIZE_DROPS: AtomicU64 = AtomicU64::new(0);

/// Total records successfully reserved. Diagnostic; the drain cross-checks it
/// against the frames it recovers.
static RECORDS: AtomicU64 = AtomicU64::new(0);

/// Whether the ring is the active sink for fast-path logging. Defaults to
/// `true`: the ring is cheap and the routing helper falls back to COM1 while
/// the ring is uninitialised, so high-volume logging prefers it the moment the
/// ring exists. The panic path uses COM1 directly regardless.
static RING_ENABLED: AtomicBool = AtomicBool::new(true);

/// Allocate the ring's backing store from the PMM. Idempotent — a second call
/// is a no-op once `RING_BASE` is set. Called once during driver init, after
/// the PMM is up. Returns `true` if the ring is now available.
pub fn init() -> bool {
    if RING_BASE.load(Ordering::Acquire) != 0 {
        return true;
    }
    const PAGE: usize = 4096;
    let pages = CAP / PAGE; // CAP is a power-of-two multiple of the page size.
    let phys = match crate::mm::pmm::alloc_pages(pages) {
        Some(p) => p,
        None => {
            crate::serial_println!(
                "[LOG-RING] PMM alloc of {} pages ({} bytes) failed — fast log path stays on COM1",
                pages, CAP
            );
            return false;
        }
    };
    let virt = astryx_shared::KERNEL_VIRT_BASE + phys;
    // SAFETY: `virt..virt+CAP` is the higher-half mapping of the freshly
    // allocated, exclusively-owned physical run. Zero it so a drain before any
    // record sees clean (non-magic) bytes.
    unsafe {
        core::ptr::write_bytes(virt as *mut u8, 0, CAP);
    }
    RING_BASE.store(virt, Ordering::Release);
    crate::serial_println!(
        "[LOG-RING] backing buffer ready: {} bytes at phys={:#x} virt={:#x} (cheap log transport)",
        CAP, phys, virt
    );
    true
}

/// Whether the fast-path ring sink is enabled AND initialised.
#[inline(always)]
pub fn enabled() -> bool {
    RING_ENABLED.load(Ordering::Relaxed) && RING_BASE.load(Ordering::Relaxed) != 0
}

/// Enable/disable the ring as the fast-path sink at runtime (kdb-driven, e.g.
/// to force the slow COM1 path for an A/B measurement). Returns the prior
/// state. Has no effect on whether the ring is *initialised*.
pub fn set_enabled(on: bool) -> bool {
    RING_ENABLED.swap(on, Ordering::Relaxed)
}

/// Record one already-formatted log line into the ring.
///
/// Lock-free and SMP/IRQ-safe: a single `fetch_add` reserves `HEADER_LEN + len`
/// contiguous monotonic bytes; the caller then writes its header and payload
/// into `reservation & MASK`, wrapping at the ring end. Two concurrent callers
/// reserve disjoint spans and never write the same byte. A wrap that overruns a
/// still-unread record corrupts only trace data (the drain resyncs on
/// `REC_MAGIC`), never kernel state.
///
/// A safe no-op until [`init`] has allocated the backing store. Lines longer
/// than [`MAX_RECORD`] are truncated to `MAX_RECORD` bytes.
#[inline]
pub fn record(line: &[u8]) {
    let base = RING_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return; // not initialised — caller falls back to COM1
    }
    let mut len = line.len();
    if len > MAX_RECORD {
        len = MAX_RECORD;
        OVERSIZE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
    let total = HEADER_LEN + len;

    // Reserve a contiguous monotonic span. Relaxed is sufficient: the only
    // reader is the out-of-band drain, which is ordered after the writers it
    // observes via the Acquire load of CURSOR in the drain.
    let reservation = CURSOR.fetch_add(total as u64, Ordering::Relaxed);

    // SAFETY: each reserved span is disjoint from every other live reservation,
    // so distinct callers write distinct bytes. `idx` is reduced mod CAP on
    // every store, so all writes stay within `base..base+CAP`. The ring is POD
    // and only read by the (non-IRQ) drain path. A wrap-collision tears trace
    // bytes only.
    unsafe {
        let ring = base as *mut u8;
        let mut pos = reservation;
        let mut put = |byte: u8, pos: &mut u64| {
            let idx = (*pos & MASK) as usize;
            ring.add(idx).write(byte);
            *pos = pos.wrapping_add(1);
        };
        // Header: magic (LE) then len (LE).
        for b in REC_MAGIC.to_le_bytes() {
            put(b, &mut pos);
        }
        for b in (len as u32).to_le_bytes() {
            put(b, &mut pos);
        }
        // Payload.
        let mut i = 0usize;
        while i < len {
            put(*line.get_unchecked(i), &mut pos);
            i += 1;
        }
    }

    RECORDS.fetch_add(1, Ordering::Relaxed);
}

/// Recover well-framed records from the ring, oldest-resident first, invoking
/// `emit(&[u8])` per record payload. Returns `(records_emitted, bytes_dropped)`
/// where `bytes_dropped` is the count of byte-reservations overwritten before
/// the drain (i.e. lost to wrap).
///
/// The walk starts at the oldest still-resident byte and scans forward for the
/// `REC_MAGIC` frame sync, so a torn or partially-overwritten leading record is
/// skipped rather than mis-parsed. Each subsequent record is validated by its
/// magic before its payload is trusted. A no-op (returns `(0, 0)`) until the
/// ring is initialised.
fn drain_records<F: FnMut(&[u8])>(mut emit: F) -> (u64, u64) {
    let base = RING_BASE.load(Ordering::Acquire);
    if base == 0 {
        return (0, 0);
    }
    let total = CURSOR.load(Ordering::Acquire);
    let resident = core::cmp::min(total, CAP as u64);
    let dropped = total.saturating_sub(resident);
    let mut pos = total - resident; // first still-resident byte
    let end = total;
    let mut emitted = 0u64;

    // SAFETY: read-only access to POD ring bytes; `idx < CAP` always.
    let ring = base as *const u8;
    let read_at = |p: u64| -> u8 {
        let idx = (p & MASK) as usize;
        unsafe { *ring.add(idx) }
    };
    let read_u32 = |p: u64| -> u32 {
        let mut v = [0u8; 4];
        for (k, slot) in v.iter_mut().enumerate() {
            *slot = read_at(p + k as u64);
        }
        u32::from_le_bytes(v)
    };

    // Scratch for a single record payload (bounded by MAX_RECORD).
    let mut scratch = [0u8; MAX_RECORD];

    while pos + HEADER_LEN as u64 <= end {
        if read_u32(pos) != REC_MAGIC {
            // Not a frame boundary (torn leading record / overwritten). Scan
            // forward one byte at a time until the next magic.
            pos += 1;
            continue;
        }
        let len = read_u32(pos + 4) as usize;
        if len > MAX_RECORD || pos + HEADER_LEN as u64 + len as u64 > end {
            // Bad/truncated frame — skip past this magic and resync.
            pos += 1;
            continue;
        }
        let payload_start = pos + HEADER_LEN as u64;
        for (k, slot) in scratch.iter_mut().enumerate().take(len) {
            *slot = read_at(payload_start + k as u64);
        }
        emit(&scratch[..len]);
        emitted += 1;
        pos = payload_start + len as u64;
    }
    (emitted, dropped)
}

/// Serialise the live ring as JSON for the kdb `log-ring` op / the
/// `qemu-harness.py log-ring drain` wrapper. The payloads are emitted as a
/// single concatenated blob (`text`) with each record already `\n`-terminated
/// by its producer, plus the framing counters so truncation is explicit.
///
/// `text` is JSON-escaped minimally (`"`, `\\`, control bytes) so the harness
/// can `json.loads` it and write the bytes straight to a log file.
pub fn dump_json(out: &mut String) {
    use core::fmt::Write;
    let total = CURSOR.load(Ordering::Acquire);
    let resident = core::cmp::min(total, CAP as u64);
    let dropped = total.saturating_sub(resident);
    let records = RECORDS.load(Ordering::Relaxed);
    let oversize = OVERSIZE_DROPS.load(Ordering::Relaxed);
    let ready = RING_BASE.load(Ordering::Acquire) != 0;

    let _ = write!(
        out,
        r#"{{"feature":"{}","cap":{},"total_bytes":{},"resident_bytes":{},"dropped_bytes":{},"records":{},"oversize_drops":{},"text":""#,
        if ready { "on" } else { "uninitialised" },
        CAP, total, resident, dropped, records, oversize
    );

    let (emitted, _) = drain_records(|payload| {
        for &b in payload {
            match b {
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                0x00..=0x1F => {
                    let _ = write!(out, "\\u{:04x}", b);
                }
                _ => out.push(b as char),
            }
        }
    });

    let _ = write!(out, r#"","emitted_records":{}}}"#, emitted);
}

/// Re-emit every buffered record to COM1 in one controlled burst, so a host
/// that scans the serial log still sees the firehose content. Unlike per-line
/// emission this pays the UART cost once, at drain time, never in the hot path.
/// Returns the number of records emitted.
///
/// This is the bridge for the existing serial-log consumers
/// (`serial-web.py`, grep-based gates): the bytes land in the same
/// `<sid>.serial.log` file, just batched.
pub fn flush_to_serial() -> u64 {
    let (records, dropped) = {
        let total = CURSOR.load(Ordering::Acquire);
        let resident = core::cmp::min(total, CAP as u64);
        (RECORDS.load(Ordering::Relaxed), total.saturating_sub(resident))
    };
    crate::serial_println!(
        "[LOG-RING-FLUSH] begin records={} dropped_bytes={} cap={}",
        records, dropped, CAP
    );
    let mut n = 0u64;
    drain_records(|payload| {
        // Each payload is already a full line (newline-terminated by the
        // producer); push it through the classic COM1 path as raw bytes.
        crate::drivers::serial::write_bytes_com1(payload);
        n += 1;
    });
    crate::serial_println!("[LOG-RING-FLUSH] end emitted={}", n);
    n
}

/// Snapshot of ring counters for kdb / tests.
pub struct Stats {
    pub cap: usize,
    pub total_bytes: u64,
    pub resident_bytes: u64,
    pub dropped_bytes: u64,
    pub records: u64,
    pub oversize_drops: u64,
    pub enabled: bool,
    pub initialised: bool,
}

pub fn stats() -> Stats {
    let total = CURSOR.load(Ordering::Acquire);
    let resident = core::cmp::min(total, CAP as u64);
    Stats {
        cap: CAP,
        total_bytes: total,
        resident_bytes: resident,
        dropped_bytes: total.saturating_sub(resident),
        records: RECORDS.load(Ordering::Relaxed),
        oversize_drops: OVERSIZE_DROPS.load(Ordering::Relaxed),
        enabled: RING_ENABLED.load(Ordering::Relaxed),
        initialised: RING_BASE.load(Ordering::Relaxed) != 0,
    }
}

// ── Self-test hooks (test-mode) ──────────────────────────────────────────────

/// Reset the ring's cursors. Test-only: lets a unit test measure a clean
/// before/after without prior boot traffic. Not exposed outside test builds —
/// resetting CURSOR mid-flight on a live system would desync a concurrent
/// drain.
#[cfg(feature = "test-mode")]
pub fn _test_reset() {
    CURSOR.store(0, Ordering::SeqCst);
    RECORDS.store(0, Ordering::SeqCst);
    OVERSIZE_DROPS.store(0, Ordering::SeqCst);
}

/// Drain every record into a caller-supplied closure for assertion in tests.
/// Returns `(records, dropped_bytes)`.
#[cfg(feature = "test-mode")]
pub fn _test_drain<F: FnMut(&[u8])>(emit: F) -> (u64, u64) {
    drain_records(emit)
}

/// Whether the backing store has been allocated (test-mode visibility).
#[cfg(feature = "test-mode")]
pub fn _test_initialised() -> bool {
    RING_BASE.load(Ordering::Acquire) != 0
}
