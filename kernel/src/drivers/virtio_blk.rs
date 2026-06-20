//! Virtio-blk PCI Block Device Driver (Legacy Interface)
//!
//! Implements a virtio block device using the legacy (transitional) PCI
//! interface.  This replaces the extremely slow ATA PIO path (~100us per
//! `inb` on WSL2/KVM) with virtio's virtqueue-based I/O, providing
//! 50-100x faster disk reads.
//!
//! # Protocol
//!
//! Uses a single request virtqueue (queue 0).  Each I/O request is a
//! 3-descriptor chain: header (type + sector) -> data buffer -> status byte.
//!
//! # Completion Model
//!
//! Two paths coexist:
//!
//! * **Poll fallback** — used during early boot before the IO-APIC and the
//!   scheduler are ready (mount of root FS happens in this window).  The
//!   submitter spins on its slot's status byte after writing the doorbell.
//!
//! * **IRQ-driven** — armed once the APIC is up via [`arm_irq`].  Each
//!   submission allocates one of [`MAX_INFLIGHT`] completion slots, publishes
//!   its TID into that slot, drops the device mutex, and waits.  The
//!   virtio-blk ISR walks the used ring, looks each completed descriptor
//!   chain head up to its owning slot, copies the status byte, and wakes
//!   the waiter that registered against that slot.
//!
//! Per-slot state means concurrent submitters (e.g. two threads issuing
//! reads while a third's request is parked in `wait_completion`) do not
//! clobber each other's done-flag, status, or waiter TID.  See the
//! W160 investigation for the symptoms before this restructure.
//!
//! # References
//! - Virtio 1.0 spec, Section 5.2 (Block Device)
//! - Virtio 1.0 spec, Section 2.4 (Virtqueue Interrupt Suppression),
//!   §2.4.8 (used ring `id` is the head descriptor index)
//! - Virtio 1.0 spec, Section 4.1.4 (PCI legacy device init)
//! - Legacy interface: <https://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html>

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::block::{BlockDevice, BlockError, SECTOR_SIZE};
use crate::hal;
use crate::mm::pmm;

// ── Virtio PCI Constants ────────────────────────────────────────────────────

/// Red Hat / Virtio vendor ID.
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Legacy virtio-blk device ID (transitional).
const VIRTIO_BLK_DEVICE_LEGACY: u16 = 0x1001;
/// Virtio subsystem ID for block devices.
const VIRTIO_SUBSYS_BLK: u16 = 2;

// ── Legacy Virtio Register Offsets (from BAR0 I/O base) ─────────────────────

const VIRTIO_REG_DEVICE_FEATURES: u16 = 0x00; // u32 RO
const VIRTIO_REG_GUEST_FEATURES:  u16 = 0x04; // u32 RW
const VIRTIO_REG_QUEUE_ADDRESS:   u16 = 0x08; // u32 RW  (PFN = phys >> 12)
const VIRTIO_REG_QUEUE_SIZE:      u16 = 0x0C; // u16 RO
const VIRTIO_REG_QUEUE_SELECT:    u16 = 0x0E; // u16 RW
const VIRTIO_REG_QUEUE_NOTIFY:    u16 = 0x10; // u16 WO
const VIRTIO_REG_DEVICE_STATUS:   u16 = 0x12; // u8  RW
/// ISR status (read-to-clear).  Bit 0 = used-ring update; bit 1 = config change.
/// Per virtio 1.0 §4.1.4.5, reading this register clears all bits and
/// de-asserts the legacy INTx line.
const VIRTIO_REG_ISR_STATUS:      u16 = 0x13; // u8  RO (read-to-clear)
// Device-specific config starts at +0x14 for legacy.
const VIRTIO_REG_BLK_CAPACITY_LO: u16 = 0x14; // u32 RO (low 32 bits)
const VIRTIO_REG_BLK_CAPACITY_HI: u16 = 0x18; // u32 RO (high 32 bits)

// ── Device Status Bits ──────────────────────────────────────────────────────

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER:      u8 = 2;
const VIRTIO_STATUS_DRIVER_OK:   u8 = 4;

// ── Virtqueue Descriptor Flags ──────────────────────────────────────────────

const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

// ── Virtio Block Request Types ──────────────────────────────────────────────

const VIRTIO_BLK_T_IN:    u32 = 0; // Read
const VIRTIO_BLK_T_OUT:   u32 = 1; // Write
/// Cache flush command (legacy feature bit `VIRTIO_BLK_F_FLUSH` = 9).
/// A flush request has no data descriptor — just the request header and
/// the status byte.  See virtio 1.2 §5.2.6 (Device Operation).
const VIRTIO_BLK_T_FLUSH: u32 = 4;

// ── Virtio Block Feature Bits ───────────────────────────────────────────────
//
// Bit numbers per virtio 1.2 §5.2.3 (Feature bits).  Only the legacy
// transport bits relevant to this driver are listed; modern-only bits
// (VIRTIO_F_VERSION_1 etc.) are out of scope for the legacy I/O register
// interface.

/// Disk is read-only.  Writes will fail with status VIRTIO_BLK_S_IOERR;
/// we reject them locally with `BlockError::IoError` before submitting.
const VIRTIO_BLK_F_RO:       u32 = 5;
/// Block size of disk is available in `virtio_blk_config.blk_size`
/// (offset 0x20 from the device-specific config base).
const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
/// FLUSH command is supported; the device honours `VIRTIO_BLK_T_FLUSH`.
/// Without this bit the device does not buffer writes and a flush is a
/// no-op at the virtio layer.
const VIRTIO_BLK_F_FLUSH:    u32 = 9;

// ── Virtio Block Status Codes ───────────────────────────────────────────────
// Returned in the status byte at the end of each request chain.  Defined
// in virtio 1.2 §5.2.6.

#[allow(dead_code)] const VIRTIO_BLK_S_OK:     u8 = 0;
#[allow(dead_code)] const VIRTIO_BLK_S_IOERR:  u8 = 1;
#[allow(dead_code)] const VIRTIO_BLK_S_UNSUPP: u8 = 2;

// ── Block Device Config Offsets (Legacy) ────────────────────────────────────
//
// Device-specific config starts at +0x14 for legacy virtio-blk.  Offsets
// here are relative to the start of the device-specific config block
// (`io_base + 0x14`).  See virtio 1.2 §5.2.4 (Device configuration layout).

/// `virtio_blk_config.blk_size` (u32) — logical block size in bytes.
/// Valid only when `VIRTIO_BLK_F_BLK_SIZE` was negotiated.
const VIRTIO_REG_BLK_BLK_SIZE: u16 = 0x14 + 0x14;

// ── Higher-Half Mapping ─────────────────────────────────────────────────────

const PHYS_OFFSET: u64 = astryx_shared::KERNEL_VIRT_BASE;

/// Convert a physical address to a virtual pointer in the kernel higher-half.
#[inline]
fn phys_to_virt<T>(phys: u64) -> *mut T {
    (PHYS_OFFSET + phys) as *mut T
}

// ── Virtqueue Layout Helpers ────────────────────────────────────────────────

/// Calculate the byte offset of the available ring within the virtqueue.
/// The descriptor table occupies 16 * queue_size bytes, immediately followed
/// by the available ring.
#[inline]
fn avail_ring_offset(queue_size: u16) -> usize {
    (queue_size as usize) * 16
}

/// Calculate the byte offset of the used ring within the virtqueue.
/// Per the legacy spec, the used ring starts at the first page-aligned
/// address after the available ring.
#[inline]
fn used_ring_offset(queue_size: u16) -> usize {
    let avail_end = avail_ring_offset(queue_size) + 4 + (queue_size as usize) * 2;
    // Align up to 4096.
    (avail_end + 4095) & !4095
}

/// Calculate the byte offset of the per-slot request-header array within
/// the virtqueue page.  Headers are 16 bytes each, MAX_INFLIGHT total,
/// placed immediately after the used ring (16-byte aligned per the
/// device's natural alignment for `VirtioBlkReqHeader`).
#[inline]
fn header_array_offset(queue_size: u16) -> usize {
    let used_end = used_ring_offset(queue_size) + 4 + (queue_size as usize) * 8;
    (used_end + 15) & !15
}

/// Calculate the byte offset of the per-slot status-byte array within
/// the virtqueue page.  One byte per slot, placed immediately after the
/// header array (no further alignment required — devices write bytes
/// independently).
#[inline]
fn status_array_offset(queue_size: u16) -> usize {
    header_array_offset(queue_size) + MAX_INFLIGHT * 16
}

/// Calculate the total bytes needed for a virtqueue with the given size.
/// Includes the per-slot header + status scratch arrays so the entire
/// driver-private region fits in the same physically-contiguous allocation.
#[inline]
fn virtqueue_total_bytes(queue_size: u16) -> usize {
    let scratch_end = status_array_offset(queue_size) + MAX_INFLIGHT;
    // Align up to page boundary.
    (scratch_end + 4095) & !4095
}

// ── Request Header ──────────────────────────────────────────────────────────

/// Virtio block request header (16 bytes).
#[repr(C)]
struct VirtioBlkReqHeader {
    type_: u32,
    reserved: u32,
    sector: u64,
}

// ── Driver State ────────────────────────────────────────────────────────────

/// Virtio-blk device state.
struct VirtioBlkDevice {
    /// BAR0 I/O port base.
    io_base: u16,
    /// Disk capacity in sectors.
    capacity: u64,
    /// Virtqueue size (number of descriptors).
    queue_size: u16,
    /// Physical base of the virtqueue memory.
    vq_phys: u64,
    /// Last seen used ring index.  Kept in step with the device's view so we
    /// can detect newly-completed requests in both the poll and IRQ paths.
    last_used_idx: u16,
    /// PCI bus/device/function (cached for IRQ ack diagnostics + `restart_device`).
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    /// PCI legacy interrupt line as programmed by firmware (read from PCI
    /// config offset 0x3C).  Used as the IO-APIC GSI for level-triggered
    /// PCI INTx routing.
    pci_irq_line: u8,
    /// Subset of device features we acknowledged at init time.  Reading
    /// this back lets the I/O paths check whether `VIRTIO_BLK_T_FLUSH` is
    /// usable (FLUSH bit set) or whether to short-circuit writes (RO bit
    /// set).  See virtio 1.2 §5.2.3.
    negotiated_features: u32,
    /// Logical block size in bytes — `virtio_blk_config.blk_size` when
    /// `VIRTIO_BLK_F_BLK_SIZE` was negotiated, otherwise 512 (the legacy
    /// default per virtio 1.2 §5.2.6, "every request is a multiple of 512
    /// bytes").
    blk_size: u32,
}

/// Global virtio-blk device (if found).
static VIRTIO_BLK: Mutex<Option<VirtioBlkDevice>> = Mutex::new(None);
/// Fast check without acquiring the mutex on every block I/O call.
static VIRTIO_BLK_AVAILABLE: AtomicBool = AtomicBool::new(false);
/// Lock-free `VIRTIO_BLK_F_FLUSH` flag.  Set at init time if the device
/// advertised the FLUSH feature bit AND we acknowledged it.  Consulted by
/// the `flush()` path so a no-flush device returns Ok without entering
/// the submit machinery (the host backend is effectively write-through).
static VIRTIO_BLK_FLUSH_SUPPORTED: AtomicBool = AtomicBool::new(false);
/// Lock-free `VIRTIO_BLK_F_RO` flag.  Set at init time if the device
/// advertised the RO feature bit.  Reads are still allowed; writes are
/// rejected with `BlockError::IoError` before any device submission.
static VIRTIO_BLK_READONLY: AtomicBool = AtomicBool::new(false);
/// Lock-free cached logical-block size (bytes).  Initialised to 512 and
/// updated to `blk_size` if `VIRTIO_BLK_F_BLK_SIZE` was negotiated.
static VIRTIO_BLK_LOGICAL_BLOCK_SIZE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(SECTOR_SIZE as u32);

// ── IRQ-Driven Completion State ─────────────────────────────────────────────
//
// Each request occupies one of [`MAX_INFLIGHT`] completion slots.  A slot
// owns a private 3-descriptor chain (heads `3*N`, `3*N+1`, `3*N+2`), a
// 16-byte request header, and a 1-byte status byte — all carved out of
// the virtqueue page in [`init`] / [`restart_device`].  The submitter:
//
//   1. Allocates a free slot (CAS on `Completion::in_use`) — done while
//      the device mutex is held so descriptor builds don't race.
//   2. Builds descriptors, writes the header, sets the status sentinel,
//      and pre-arms the slot's `done` / `waiter_tid` / `status`.
//   3. Drops the device mutex and waits on its slot's `done` flag.
//
// The ISR walks the used ring; for each newly-completed entry it computes
// `slot_idx = used.ring[i].id / 3` and (a) copies the slot's status byte
// from the virtqueue scratch area into the slot, (b) sets `done`, (c)
// wakes the registered TID.
//
// `IRQS_ARMED` gates the entire path: until `arm_irq()` has registered the
// IO-APIC route the driver falls back to spin-polling on the slot's
// virtqueue status byte.  This keeps the early-boot mount sequence
// (which runs before APIC init) working.

/// Set to `true` by [`arm_irq`] once the IO-APIC route is live; the submit
/// path then prefers blocking over polling.
static IRQS_ARMED: AtomicBool = AtomicBool::new(false);

/// Maximum concurrent in-flight virtio-blk requests.  Each slot consumes
/// 3 descriptor table entries (header + data + status), so this bounds
/// the descriptor-table footprint at `MAX_INFLIGHT * 3`.  QEMU's
/// virtio-blk-pci legacy device exposes 128-deep queues, so 32 slots
/// (96 descriptors) leaves headroom for non-paged callers and aligns
/// the per-slot scratch onto cache lines.
pub const MAX_INFLIGHT: usize = 32;

/// Sentinel meaning "no thread is currently registered to be woken on
/// this slot's completion".  Zero is a valid TID (BSP idle / kernel-init
/// thread issues disk reads during Firefox bring-up), so we use `u64::MAX`.
const NO_WAITER: u64 = u64::MAX;

/// Per-slot completion record.  Cache-line aligned to keep ISR / waiter
/// updates from creating false sharing across the slot array.
#[repr(align(64))]
struct Completion {
    /// Slot allocation flag.  `acquire_slot` CAS-set to `true`; the
    /// waiter clears it after consuming `done` + `status`.
    in_use: AtomicBool,
    /// Set by ISR (or the polled fallback in `wait_completion`) once the
    /// device has retired this slot's descriptor chain.
    done: AtomicBool,
    /// Last-seen virtio-blk request status byte for this slot
    /// (0 = OK, non-zero = device error).
    status: AtomicU8,
    /// TID of the thread blocked on this slot, or [`NO_WAITER`].
    waiter_tid: AtomicU64,
    /// Monotonic-clock nanoseconds at submission (doorbell write).  Used only
    /// by the wait-amplification histogram to compute per-round-trip latency;
    /// not load-bearing for completion detection.  0 before the first arm.
    submit_ns: AtomicU64,
    /// Quarantine flag.  Set when a waiter abandons this slot on a timeout while
    /// the request is still owned by the device (published to the avail ring but
    /// not yet retired in the used ring).  Per VIRTIO 1.2 §2.7.13.3 the device
    /// MAY access the descriptor chain — and the data buffer it points at — at
    /// any time until it returns the chain via the used ring (§2.7.14); recycling
    /// the slot's descriptors or its data buffer before then is a use-after-free
    /// from the device's perspective and corrupts the virtqueue (the device sees
    /// a chain it never expected to be re-published and stops the queue).  A
    /// quarantined slot stays `in_use` — so `acquire_slot` skips it and never
    /// overwrites its descriptors — until [`drain_used_ring`] observes its
    /// used-ring entry and reclaims it.  See the completion-stall autopsy:
    /// abandoning device-owned chains is what let in-flight escape `MAX_INFLIGHT`
    /// and wedged the device.
    quarantined: AtomicBool,
}

impl Completion {
    const fn new() -> Self {
        Self {
            in_use: AtomicBool::new(false),
            done: AtomicBool::new(false),
            status: AtomicU8::new(0),
            waiter_tid: AtomicU64::new(NO_WAITER),
            submit_ns: AtomicU64::new(0),
            quarantined: AtomicBool::new(false),
        }
    }
}

static COMPLETIONS: [Completion; MAX_INFLIGHT] =
    [const { Completion::new() }; MAX_INFLIGHT];

/// Spurious-IRQ counter (ISR fired but no used-ring progress).  Useful for
/// detecting shared-IRQ wiring mistakes; surfaced via [`spurious_count`].
static SPURIOUS_IRQS: AtomicU64 = AtomicU64::new(0);

/// Total IRQ entries (productive + spurious).  Diagnostic only.
static TOTAL_IRQS: AtomicU64 = AtomicU64::new(0);

/// Completions discovered via the poll-fallback in `wait_completion`.
/// Non-zero values indicate the IRQ wiring is unreliable on the host —
/// the wait loop's status-byte read picked up the completion before the
/// ISR did.  Zero in steady state means IRQ delivery is working as
/// designed and the schedule() yield happens once per request.
static POLLED_COMPLETIONS: AtomicU64 = AtomicU64::new(0);

/// Total `VIRTIO_BLK_T_FLUSH` requests submitted (diagnostic).  Bumped
/// once per `do_flush` call, regardless of completion path.
static FLUSH_SUBMITTED: AtomicU64 = AtomicU64::new(0);

/// Number of slots quarantined on a wait timeout (request abandoned by its
/// waiter while still owned by the device).  Diagnostic: a non-zero value
/// means the device is taking longer than the no-progress deadline to retire
/// some requests; a steadily-climbing value alongside forward progress is
/// benign back-pressure, whereas a value that climbs while `used.idx` is
/// frozen indicates a genuinely wedged device.
static QUARANTINED_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// Number of quarantined slots later reclaimed by `drain_used_ring` once the
/// device retired their chains.  In steady state this tracks
/// `QUARANTINED_TIMEOUTS` (every quarantine is eventually reclaimed); a gap
/// (`QUARANTINED_TIMEOUTS - RECLAIMED_QUARANTINES`) is the count of slots the
/// device still owes — bounded by `MAX_INFLIGHT`.
static RECLAIMED_QUARANTINES: AtomicU64 = AtomicU64::new(0);

// ── Wait-amplification sample ring (diagnostic) ──────────────────────────────
//
// Per-round-trip telemetry for the I/O-wait amplification investigation.  Each
// completed `wait_completion` records ONE fixed-width sample into a lock-free
// ring: the wait duration (submit→complete, microseconds, sub-tick resolution
// from the TSC-derived monotonic clock), the run-queue depth observed at the
// point the waiter gave up the CPU (how many Ready peers it had to be
// re-selected out of), how many times it yielded, and whether the completion
// was seen by the IRQ (`done` set under the micro-spin / by direct wake) or by
// the waiter's own poll fallback.
//
// Why a ring and not `serial_println!`: a Firefox boot issues ~15 k disk
// round-trips; one COM1 line per round-trip is ~15 k×~150 PIO `outb` VM-exits
// (Intel SDM Vol. 3C §25.1.3 — I/O instructions cause VM exits), which would
// inject exactly the per-exit cost the time-source campaign removed and
// destroy the timing it is meant to measure.  The ring claims a fixed-width
// slot with one relaxed `fetch_add` — no lock, no `outb`, no VM-exit — and is
// drained out of band over kdb (`virtio-wait-hist`), the same pattern as
// `drivers::log_ring` / `drivers::blk_trace`.
//
// The ring is a `static` array (small: 4096 × 16 B = 64 KiB) rather than a PMM
// allocation because it must work from the very first disk read (before the
// PMM-backed log ring is initialised) and 64 KiB of BSS is negligible.

/// Number of samples the ring holds before wrap.  Power of two so the wrap is
/// a mask.  4096 covers the steady-state disk-I/O burst; older samples are
/// overwritten and the drain reports the dropped count, so truncation is
/// explicit.  The histogram bucketises on drain, so a wrapped ring still
/// yields a faithful distribution of the most recent N round-trips.
const WAIT_SAMPLES: usize = 4096;
const WAIT_SAMPLE_MASK: u64 = (WAIT_SAMPLES as u64) - 1;

/// One round-trip wait sample.  16 bytes, cache-line agnostic (the ring is
/// drained out of band, never in the hot path, so false sharing on a partially
/// written slot only tears diagnostic data — never kernel state).
#[repr(C)]
struct WaitSample {
    /// Wait duration submit→complete in microseconds (saturating at u32::MAX
    /// ≈ 71 min, far beyond the 1 s device deadline).  `u32::MAX` sentinel for
    /// a not-yet-written slot is impossible to confuse with a real sample
    /// because the drain gates on the monotonic `seq` below.
    wait_us: AtomicU32,
    /// Run-queue depth (non-idle Ready peers) observed at the yield, clamped to
    /// u16.  0 when the waiter never yielded (completion caught by micro-spin).
    runq_depth: AtomicU16,
    /// Number of `schedule()` yields this round-trip took before completion.
    yields: AtomicU16,
    /// Reservation sequence number (monotone).  The drain reads this to decide
    /// which slots are live and in what order; a slot whose `seq` is 0 was
    /// never written.  Stored LAST (Release) so a drain that observes a fresh
    /// `seq` also observes the fully-written payload.
    seq: AtomicU64,
}

impl WaitSample {
    const fn new() -> Self {
        Self {
            wait_us: AtomicU32::new(0),
            runq_depth: AtomicU16::new(0),
            yields: AtomicU16::new(0),
            seq: AtomicU64::new(0),
        }
    }
}

static WAIT_RING: [WaitSample; WAIT_SAMPLES] =
    [const { WaitSample::new() }; WAIT_SAMPLES];

/// Monotone reservation cursor.  The low `log2(WAIT_SAMPLES)` bits index the
/// ring; the full value is the total samples ever recorded (lets the drain
/// report wrap/drop counts and is itself the per-slot `seq`).
static WAIT_CURSOR: AtomicU64 = AtomicU64::new(0);

/// Record one round-trip wait sample.  Lock-free and IRQ/SMP-safe: a single
/// `fetch_add` reserves a slot; the payload is written, then `seq` is stored
/// with Release ordering so the out-of-band drain never reads a torn sample.
#[inline]
fn record_wait_sample(wait_us: u32, runq_depth: u16, yields: u16) {
    let resv = WAIT_CURSOR.fetch_add(1, Ordering::Relaxed);
    let slot = &WAIT_RING[(resv & WAIT_SAMPLE_MASK) as usize];
    slot.wait_us.store(wait_us, Ordering::Relaxed);
    slot.runq_depth.store(runq_depth, Ordering::Relaxed);
    slot.yields.store(yields, Ordering::Relaxed);
    // `resv + 1` keeps 0 reserved as the "never written" sentinel and makes
    // `seq` strictly increasing.  Release so the payload above is visible to
    // any drain that observes this `seq`.
    slot.seq.store(resv + 1, Ordering::Release);
}

/// Serialise the wait-sample ring as a JSON histogram for the kdb
/// `virtio-wait-hist` op.  Emits log-scale wait-duration buckets, the
/// per-bucket mean run-queue depth, total/yield/poll-fallback counts, and the
/// median + p99 wait in microseconds.  Drains a stable snapshot (bounded by the
/// cursor at entry) so a concurrent recorder cannot make the walk run long.
pub fn wait_hist_json(out: &mut alloc::string::String) {
    use core::fmt::Write;
    let total = WAIT_CURSOR.load(Ordering::Acquire);
    let resident = core::cmp::min(total, WAIT_SAMPLES as u64);
    let dropped = total.saturating_sub(resident);

    // Log-scale buckets (microseconds), open-ended last bucket.  Chosen so
    // device-latency (~tens-hundreds of µs on KVM) and scheduler-sweep
    // amplification (single-to-tens of ms) land in distinct buckets.
    const EDGES_US: [u32; 12] =
        [0, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000];
    let nb = EDGES_US.len(); // buckets: [edge[i], edge[i+1]) + final open bucket
    let mut counts = [0u64; 13];
    let mut depth_sum = [0u64; 13];
    let mut total_wait_us: u64 = 0;
    let mut any_yield: u64 = 0;
    let mut max_us: u32 = 0;

    // First pass: bucketise + accumulate.  Also collect samples for the
    // percentile pass into a small scratch (bounded by resident).
    let mut sampled: u64 = 0;
    // For the median/p99 we use a coarse fixed-resolution histogram (1 µs
    // granularity up to 100 ms) accumulated alongside — avoids needing a sort
    // or a large scratch buffer in kernel space.
    for i in 0..resident {
        let slot = &WAIT_RING[(i & WAIT_SAMPLE_MASK) as usize];
        let seq = slot.seq.load(Ordering::Acquire);
        if seq == 0 {
            continue; // never written
        }
        let us = slot.wait_us.load(Ordering::Relaxed);
        let d = slot.runq_depth.load(Ordering::Relaxed) as u64;
        let y = slot.yields.load(Ordering::Relaxed);
        // Find bucket.
        let mut b = nb; // default to final open bucket
        for e in 0..nb {
            if us < EDGES_US[e] {
                b = e; // us falls in [EDGES[e-1], EDGES[e]); record as e-1
                break;
            }
        }
        let bi = if b == 0 { 0 } else { b - 1 };
        counts[bi] += 1;
        depth_sum[bi] += d;
        total_wait_us += us as u64;
        if y > 0 { any_yield += 1; }
        if us > max_us { max_us = us; }
        sampled += 1;
    }

    // Percentile pass: a second walk computing the value at the median and p99
    // ranks by counting how many samples are <= a probe value.  Cheap because
    // `resident` <= 4096 and we only probe via the bucket edges + a linear
    // interpolation; for a precise-enough p99 we report the bucket lower edge
    // the rank lands in.  (Exact percentiles would need a sort; the bucketed
    // estimate is sufficient to show the before/after collapse.)
    let median_rank = sampled / 2;
    let p99_rank = (sampled * 99) / 100;
    let mut acc: u64 = 0;
    let mut median_us: u32 = 0;
    let mut p99_us: u32 = 0;
    let mut got_median = false;
    let mut got_p99 = false;
    for bi in 0..=nb {
        acc += counts[bi];
        let edge = if bi < nb { EDGES_US[bi] } else { 100_000 };
        if !got_median && acc > median_rank {
            median_us = edge;
            got_median = true;
        }
        if !got_p99 && acc > p99_rank {
            p99_us = edge;
            got_p99 = true;
        }
    }
    let mean_us = if sampled > 0 { total_wait_us / sampled } else { 0 };

    let _ = write!(
        out,
        r#"{{"feature":"on","total_roundtrips":{},"resident":{},"dropped":{},"sampled":{},"yielded":{},"mean_us":{},"median_us":{},"p99_us":{},"max_us":{},"buckets":["#,
        total, resident, dropped, sampled, any_yield, mean_us, median_us, p99_us, max_us
    );
    let mut first = true;
    for bi in 0..=nb {
        if counts[bi] == 0 {
            continue;
        }
        let lo = if bi == 0 { 0 } else { EDGES_US[bi - 1] };
        let hi = if bi < nb { EDGES_US[bi] } else { 0 /* open */ };
        let mean_depth = depth_sum[bi] / counts[bi];
        if !first { out.push(','); }
        first = false;
        let _ = write!(
            out,
            r#"{{"lo_us":{},"hi_us":{},"count":{},"mean_runq_depth":{}}}"#,
            lo, hi, counts[bi], mean_depth
        );
    }
    out.push_str("]}");
}

/// Reset the wait-sample ring (test/kdb only).  Lets an A/B measurement start
/// from a clean cursor.  Not load-bearing — resetting mid-flight only loses
/// diagnostic samples.
pub fn wait_hist_reset() {
    WAIT_CURSOR.store(0, Ordering::SeqCst);
    for s in WAIT_RING.iter() {
        s.seq.store(0, Ordering::SeqCst);
    }
}

/// Acquire a free slot via CAS scan; returns `Some(slot_idx)` on success.
/// Caller must hold the device mutex while submitting against this slot
/// (so descriptor and header writes are serialised), but the wait runs
/// without the mutex held.  Returns `None` if every slot is busy — the
/// caller spins (with `core::hint::spin_loop`) and retries.
///
/// A quarantined slot ([`quarantine_slot`]) has `in_use == true`, so its
/// CAS fails here and it is skipped automatically — its descriptor chain is
/// never reused while the device may still own it.
fn acquire_slot() -> Option<usize> {
    for i in 0..MAX_INFLIGHT {
        if COMPLETIONS[i]
            .in_use
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Reset slot state for new request.  `quarantined` is cleared on
            // reclaim in `drain_used_ring`, but clear it here too so a slot
            // can never be acquired while still flagged.
            COMPLETIONS[i].done.store(false, Ordering::Release);
            COMPLETIONS[i].status.store(0xFF, Ordering::Relaxed);
            COMPLETIONS[i].waiter_tid.store(NO_WAITER, Ordering::Release);
            COMPLETIONS[i].quarantined.store(false, Ordering::Release);
            return Some(i);
        }
    }
    None
}

/// Count how many of the `MAX_INFLIGHT` slots are currently quarantined
/// (timed-out, device-owned, awaiting reclaim).  Used by `do_io`'s
/// acquire-slot deadline path to distinguish a self-inflicted slot-exhaustion
/// wedge (every slot pinned by a leaked quarantine) from a genuinely
/// busy-but-healthy 32-deep queue: in the former the device's used ring has
/// nothing left to retire, so its `used.idx` legitimately freezes and the
/// quarantined slots can NEVER be reclaimed by `drain_used_ring` — a permanent
/// wedge that only a device reset can recover (VIRTIO 1.2 §2.7).
fn quarantined_count() -> usize {
    let mut n = 0;
    for i in 0..MAX_INFLIGHT {
        if COMPLETIONS[i].quarantined.load(Ordering::Acquire) {
            n += 1;
        }
    }
    n
}

/// Release a slot for reuse.  Must be called by the same waiter that
/// acquired it, after the wait has consumed `done` + `status` — i.e. only
/// once the device has retired this slot's descriptor chain (or the request
/// was never published to the device).  Releasing a slot whose request is
/// still in flight in the device is a use-after-free of the descriptor chain
/// — use [`quarantine_slot`] for that case instead.
fn release_slot(slot_idx: usize) {
    COMPLETIONS[slot_idx].waiter_tid.store(NO_WAITER, Ordering::Release);
    COMPLETIONS[slot_idx].quarantined.store(false, Ordering::Release);
    COMPLETIONS[slot_idx].in_use.store(false, Ordering::Release);
}

/// Mark a slot quarantined: the waiter is giving up (timeout) but the request
/// is still owned by the device — it was published to the avail ring and has
/// not yet been retired in the used ring.  Per VIRTIO 1.2 §2.7.13.3 / §2.7.14
/// the device may read or write the descriptor chain and its data buffer until
/// it returns the chain via the used ring, so the slot must NOT be released for
/// reuse (which would let a new request overwrite the device-owned descriptors
/// and re-publish the same chain head, corrupting the queue).
///
/// The slot keeps `in_use == true` so `acquire_slot` skips it; `waiter_tid` is
/// cleared so no stale wake targets a thread that has moved on.  The slot is
/// reclaimed (its `in_use` cleared) by [`drain_used_ring`] when the device
/// finally retires the chain.  Until then it counts against `MAX_INFLIGHT`,
/// which is exactly the back-pressure that keeps in-flight bounded.
fn quarantine_slot(slot_idx: usize) {
    QUARANTINED_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    COMPLETIONS[slot_idx].waiter_tid.store(NO_WAITER, Ordering::Release);
    COMPLETIONS[slot_idx].quarantined.store(true, Ordering::Release);
    // `in_use` is left set — the slot stays reserved until the device retires
    // its chain and `drain_used_ring` reclaims it.
}

/// Test-only exercise of the slot-quarantine lifecycle invariant (the
/// completion-stall fix).  Operates purely on the in-memory `COMPLETIONS`
/// slot-allocation state — it issues NO device I/O — so it is safe to call on
/// a live system: it acquires only currently-free slots and restores them to
/// `free` before returning.  Returns `Ok(())` if every invariant held, or
/// `Err(&str)` naming the first violation.
///
/// Invariants checked:
///   1. A quarantined slot stays `in_use` (counts against MAX_INFLIGHT) and is
///      NOT handed out by `acquire_slot` — i.e. its device-owned descriptor
///      chain can never be reused.
///   2. Clearing the quarantine (the reclaim `drain_used_ring` performs once
///      the device retires the chain) makes the slot acquirable again.
///   3. `acquire_slot` never hands out the same slot twice (no double-use), and
///      the number of simultaneously-held slots never exceeds MAX_INFLIGHT.
#[cfg(any(test, feature = "test-mode", feature = "firefox-test-core"))]
pub fn test_quarantine_lifecycle() -> Result<(), &'static str> {
    // Snapshot which slots were free on entry so we can restore exactly those.
    // We only ever touch slots we successfully acquire here.
    let s0 = acquire_slot().ok_or("acquire_slot returned None with free slots expected")?;

    // Invariant 1: quarantine the slot, then prove acquire_slot never returns it.
    quarantine_slot(s0);
    if !COMPLETIONS[s0].in_use.load(Ordering::Acquire) {
        // Restore and fail.
        release_slot(s0);
        return Err("quarantined slot cleared in_use (should stay reserved)");
    }
    if !COMPLETIONS[s0].quarantined.load(Ordering::Acquire) {
        release_slot(s0);
        return Err("quarantine flag not set");
    }
    // Drain every other free slot; none of them may be s0 (it is quarantined).
    let mut held: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
    while let Some(s) = acquire_slot() {
        if s == s0 {
            // Catastrophic: the quarantined slot was handed out.
            for h in &held { release_slot(*h); }
            release_slot(s0);
            return Err("acquire_slot handed out a quarantined slot");
        }
        if held.contains(&s) {
            for h in &held { release_slot(*h); }
            release_slot(s0);
            return Err("acquire_slot handed out the same slot twice");
        }
        held.push(s);
        if held.len() >= MAX_INFLIGHT {
            // Defensive: must terminate before exceeding the slot count.
            break;
        }
    }
    // Invariant 3: with s0 quarantined, at most MAX_INFLIGHT-1 others are free.
    if held.len() > MAX_INFLIGHT - 1 {
        for h in &held { release_slot(*h); }
        release_slot(s0);
        return Err("acquired more slots than MAX_INFLIGHT-1 while one quarantined");
    }

    // Invariant 2: clear the quarantine (the reclaim path) and prove s0 is
    // acquirable again.  Release everything else first.
    for h in &held { release_slot(*h); }
    // Simulate `drain_used_ring`'s reclaim of a quarantined slot.
    COMPLETIONS[s0].quarantined.store(false, Ordering::Release);
    COMPLETIONS[s0].in_use.store(false, Ordering::Release);
    match acquire_slot() {
        Some(s) => {
            // It should be reusable now (may or may not be s0 depending on scan
            // order, but acquisition must succeed and the slot must be clean).
            if COMPLETIONS[s].quarantined.load(Ordering::Acquire) {
                release_slot(s);
                return Err("reclaimed slot still flagged quarantined after acquire");
            }
            release_slot(s);
        }
        None => return Err("no slot acquirable after reclaim"),
    }
    Ok(())
}

// ── Lock-Free Snapshot for the ISR ──────────────────────────────────────────
//
// The submit path holds `VIRTIO_BLK.lock()` only during descriptor build +
// doorbell write; it drops the mutex before waiting.  The ISR therefore
// must not touch that mutex (it might be held by an in-flight submitter
// on another CPU) — `try_lock` would fail unpredictably and lose IRQs.
//
// These atomics hold the post-init values that never change for the lifetime
// of the device (or change only inside `restart_device`, which runs with
// IRQs effectively quiet).  Populated by [`publish_irq_snapshot`].
static IRQ_VQ_VIRT: AtomicU64 = AtomicU64::new(0);
static IRQ_QUEUE_SIZE: AtomicU16 = AtomicU16::new(0);
static IRQ_IO_BASE: AtomicU16 = AtomicU16::new(0);

/// Last-used-ring index observed by the ISR.  The submit path reads it via
/// [`Ordering::Acquire`] after waking to confirm a completion happened, and
/// the ISR uses it to detect newly-completed requests across IRQ events.
/// At init time this is 0, matching the device's reset state.
static IRQ_LAST_USED_IDX: AtomicU16 = AtomicU16::new(0);

/// IRQ vector assigned to virtio-blk in the IDT.  Vectors 32-44 are taken by
/// the timer (32), keyboard (33), e1000 (43) and mouse (44) — pick the next
/// free slot.
pub const VIRTIO_BLK_IRQ_VECTOR: u8 = 45;

// ── Initialization ──────────────────────────────────────────────────────────

/// Initialize the virtio-blk driver.  Scans PCI for a virtio block device,
/// performs device setup, and allocates the virtqueue.
/// Returns true if a device was found and initialized successfully.
pub fn init() -> bool {
    let pci_dev = match find_virtio_blk_pci() {
        Some(d) => d,
        None => {
            crate::serial_println!("[VIRTIO-BLK] No virtio-blk PCI device found");
            return false;
        }
    };

    crate::serial_println!(
        "[VIRTIO-BLK] Found device at PCI {:02x}:{:02x}.{} (vendor={:04x} device={:04x})",
        pci_dev.bus, pci_dev.device, pci_dev.function,
        pci_dev.vendor_id, pci_dev.device_id
    );

    // BAR0 must be an I/O port BAR (bit 0 = 1).
    let bar0 = pci_dev.bar[0];
    if bar0 & 1 == 0 {
        crate::serial_println!("[VIRTIO-BLK] BAR0 is not I/O space, aborting");
        return false;
    }
    let io_base = (bar0 & 0xFFFF_FFFC) as u16;

    crate::serial_println!("[VIRTIO-BLK] I/O base = {:#06x}", io_base);

    // Enable bus mastering + I/O space access.
    super::pci::enable_bus_master(pci_dev.bus, pci_dev.device, pci_dev.function);
    // Also ensure I/O space is enabled (bit 0 of PCI command register).
    let cmd = super::pci::pci_config_read32(pci_dev.bus, pci_dev.device, pci_dev.function, 0x04);
    super::pci::pci_config_write32(pci_dev.bus, pci_dev.device, pci_dev.function, 0x04, cmd | 0x01);

    // ── Device Reset + Init Sequence (Legacy) ───────────────────────────

    // SAFETY: Writing to I/O ports of the discovered virtio PCI device.
    // The io_base was read from a valid BAR0 of a known virtio device.
    unsafe {
        // 1. Reset device.
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);

        // 2. Acknowledge.
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. Driver.
        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );

        // 4. Negotiate features.  Virtio 1.2 §3.1.1 spells out the legacy
        //    handshake: read DEVICE_FEATURES, write back the subset we
        //    understand into GUEST_FEATURES.  We accept three bits today:
        //
        //      VIRTIO_BLK_F_FLUSH    — VIRTIO_BLK_T_FLUSH command is honoured
        //                              (virtio 1.2 §5.2.3, legacy bit 9).
        //      VIRTIO_BLK_F_RO       — disk is read-only (bit 5); writes will
        //                              never succeed regardless of permission.
        //      VIRTIO_BLK_F_BLK_SIZE — `virtio_blk_config.blk_size` is valid
        //                              (bit 6); used as the logical block
        //                              size hint for filesystems.
        //
        //    Other useful bits (SIZE_MAX, SEG_MAX, GEOMETRY, TOPOLOGY, MQ,
        //    DISCARD, WRITE_ZEROES, CONFIG_WCE) are deferred — they are
        //    optional and not load-bearing for the current single-queue,
        //    fixed-segment-size pipeline.
        let device_features = hal::inl(io_base + VIRTIO_REG_DEVICE_FEATURES);
        let want: u32 = (1u32 << VIRTIO_BLK_F_FLUSH)
            | (1u32 << VIRTIO_BLK_F_RO)
            | (1u32 << VIRTIO_BLK_F_BLK_SIZE);
        let negotiated = device_features & want;
        hal::outl(io_base + VIRTIO_REG_GUEST_FEATURES, negotiated);

        let flush_ok    = (negotiated & (1u32 << VIRTIO_BLK_F_FLUSH))    != 0;
        let readonly    = (negotiated & (1u32 << VIRTIO_BLK_F_RO))       != 0;
        let blk_size_ok = (negotiated & (1u32 << VIRTIO_BLK_F_BLK_SIZE)) != 0;
        crate::serial_println!(
            "[VIRTIO-BLK] Features: dev={:#010x} want={:#010x} got={:#010x} (flush={} ro={} blk_size={})",
            device_features, want, negotiated, flush_ok, readonly, blk_size_ok
        );

        // 5. Read device capacity (sectors).
        let cap_lo = hal::inl(io_base + VIRTIO_REG_BLK_CAPACITY_LO) as u64;
        let cap_hi = hal::inl(io_base + VIRTIO_REG_BLK_CAPACITY_HI) as u64;
        let capacity = (cap_hi << 32) | cap_lo;
        crate::serial_println!("[VIRTIO-BLK] Capacity: {} sectors ({} MiB)", capacity, capacity * 512 / (1024 * 1024));

        // 5b. Read the device's logical block size when supported.  Falls
        //     back to 512 (the implicit legacy default — every request is a
        //     multiple of 512 bytes per virtio 1.2 §5.2.6) so the rest of
        //     the driver and partition-table code keeps working unchanged.
        let blk_size = if blk_size_ok {
            let raw = hal::inl(io_base + VIRTIO_REG_BLK_BLK_SIZE);
            // Sanity-check: must be a power of two, multiple of 512, and
            // <= 4096 (page-aligned device buffers).  An obviously bogus
            // value falls back to 512 with a WARN.
            if raw != 0 && raw <= 4096 && (raw & (raw - 1)) == 0 && (raw % (SECTOR_SIZE as u32)) == 0 {
                raw
            } else {
                crate::serial_println!(
                    "[VIRTIO-BLK] Ignoring out-of-range blk_size={}; falling back to {}",
                    raw, SECTOR_SIZE
                );
                SECTOR_SIZE as u32
            }
        } else {
            SECTOR_SIZE as u32
        };

        // 6. Set up virtqueue 0.
        hal::outw(io_base + VIRTIO_REG_QUEUE_SELECT, 0);
        let queue_size = hal::inw(io_base + VIRTIO_REG_QUEUE_SIZE);
        if queue_size == 0 {
            crate::serial_println!("[VIRTIO-BLK] Queue 0 not available");
            hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0); // reset
            return false;
        }
        // The per-slot descriptor layout consumes `MAX_INFLIGHT * 3`
        // descriptor table entries.  Refuse to run on a queue that can't
        // hold them — virtio §2.4 leaves the queue size to the device,
        // but the legacy QEMU virtio-blk-pci default is 128, well above
        // our 96-entry need.
        if (queue_size as usize) < MAX_INFLIGHT * 3 {
            crate::serial_println!(
                "[VIRTIO-BLK] Queue size {} < required {} (MAX_INFLIGHT={} * 3)",
                queue_size, MAX_INFLIGHT * 3, MAX_INFLIGHT
            );
            hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
            return false;
        }
        crate::serial_println!("[VIRTIO-BLK] Queue 0 size: {}", queue_size);

        // Allocate physically contiguous pages for the virtqueue.
        let total_bytes = virtqueue_total_bytes(queue_size);
        let pages_needed = (total_bytes + 4095) / 4096;
        let vq_phys = match pmm::alloc_pages(pages_needed) {
            Some(p) => p,
            None => {
                crate::serial_println!("[VIRTIO-BLK] Failed to allocate {} pages for virtqueue", pages_needed);
                hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
                return false;
            }
        };

        // Zero the entire virtqueue region.
        let vq_virt = phys_to_virt::<u8>(vq_phys);
        core::ptr::write_bytes(vq_virt, 0, total_bytes);

        // Tell the device the page frame number of the virtqueue.
        let pfn = (vq_phys >> 12) as u32;
        hal::outl(io_base + VIRTIO_REG_QUEUE_ADDRESS, pfn);

        // 7. Mark driver ready.
        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
        );

        crate::serial_println!(
            "[VIRTIO-BLK] Initialized: io={:#06x}, capacity={} sectors, queue_size={}, vq_phys={:#x}",
            io_base, capacity, queue_size, vq_phys
        );

        *VIRTIO_BLK.lock() = Some(VirtioBlkDevice {
            io_base,
            capacity,
            queue_size,
            vq_phys,
            last_used_idx: 0,
            pci_bus: pci_dev.bus,
            pci_dev: pci_dev.device,
            pci_func: pci_dev.function,
            pci_irq_line: pci_dev.interrupt_line,
            negotiated_features: negotiated,
            blk_size,
        });
        publish_irq_snapshot(io_base, queue_size, vq_phys);
        VIRTIO_BLK_FLUSH_SUPPORTED.store(flush_ok, Ordering::Release);
        VIRTIO_BLK_READONLY.store(readonly, Ordering::Release);
        VIRTIO_BLK_LOGICAL_BLOCK_SIZE.store(blk_size, Ordering::Release);
        VIRTIO_BLK_AVAILABLE.store(true, Ordering::Release);
    }

    true
}

/// Publish the device's invariant fields into the ISR-visible snapshot.
/// Called from [`init`] and [`restart_device`].  Resets `IRQ_LAST_USED_IDX`
/// to 0 because the device's used.idx is also 0 after a reset.
fn publish_irq_snapshot(io_base: u16, queue_size: u16, vq_phys: u64) {
    IRQ_VQ_VIRT.store(PHYS_OFFSET + vq_phys, Ordering::Release);
    IRQ_QUEUE_SIZE.store(queue_size, Ordering::Release);
    IRQ_IO_BASE.store(io_base, Ordering::Release);
    IRQ_LAST_USED_IDX.store(0, Ordering::Release);
}

// ── IRQ Wiring ──────────────────────────────────────────────────────────────

/// Route the virtio-blk legacy INTx line through the IO-APIC and flip
/// [`IRQS_ARMED`] so subsequent submissions block instead of spinning.
///
/// MUST be called after `apic::init()` (the IO-APIC must be live) and after
/// `sched::init()` (the blocking path needs the scheduler).  Safe to call
/// even if no virtio-blk device was discovered — it becomes a no-op.
///
/// Per virtio 1.0 §4.1.4.5 a driver enables interrupts simply by leaving
/// the device's interrupt line unmasked at the IO-APIC; nothing in the
/// virtio-blk register file needs to change.  The device already raises
/// the line whenever it advances `used.idx`, regardless of whether anyone
/// is listening.  We acknowledge each IRQ by reading `ISR_STATUS`
/// (read-to-clear, §4.1.4.5).
pub fn arm_irq() {
    if !VIRTIO_BLK_AVAILABLE.load(Ordering::Acquire) {
        return;
    }
    let (irq_line, b, d, f) = {
        let guard = VIRTIO_BLK.lock();
        match guard.as_ref() {
            Some(dev) => (dev.pci_irq_line, dev.pci_bus, dev.pci_dev, dev.pci_func),
            None => return,
        }
    };
    if irq_line == 0 || irq_line == 0xFF {
        crate::serial_println!(
            "[VIRTIO-BLK] No PCI interrupt line programmed (line={:#x}); staying on poll path",
            irq_line
        );
        return;
    }

    // Clear PCI command-register bit 10 (Interrupt Disable) so the device
    // can assert legacy INTx.  Default after PCI reset is bit 10 = 0
    // (INTx enabled), but firmware may have set it expecting an MSI/MSI-X
    // path; we explicitly enable INTx for the legacy IO-APIC route below.
    // PCI Local Bus Specification 3.0, §6.2.2.
    let cmd = super::pci::pci_config_read32(b, d, f, 0x04);
    super::pci::pci_config_write32(b, d, f, 0x04, cmd & !(1u32 << 10));

    // Walk the PCI capability list and disable MSI-X if present.  When
    // MSI-X enable=1 the device routes interrupts via MSI-X messages and
    // ignores its INTx pin entirely (PCI 3.0 §6.8.2.3 — MSI-X Message
    // Control register, Bit 15 "MSI-X Enable").  QEMU's virtio-blk-pci
    // exposes MSI-X by default; UEFI may have left it enabled with
    // entries still in their "function masked" reset state, which makes
    // the device silently swallow our completions.  Forcing it off on
    // arm restores the legacy INTx path that this driver uses.
    disable_msix(b, d, f);

    // Route the GSI through the IO-APIC.  PCI INTx is level-triggered,
    // active-low — use the level helper.
    let bsp_id = crate::arch::x86_64::apic::bsp_apic_id();
    crate::arch::x86_64::apic::ioapic_route_irq_level(irq_line, VIRTIO_BLK_IRQ_VECTOR, bsp_id);

    // Drain any stale ISR bit so the first real completion isn't masked
    // behind a left-over assertion from QEMU's device init.
    // SAFETY: Reading the device's ISR status is read-to-clear; no side
    // effects beyond clearing the latched bits and de-asserting INTx.
    let io_base_snap = IRQ_IO_BASE.load(Ordering::Acquire);
    if io_base_snap != 0 {
        unsafe {
            let _ = crate::hal::inb(io_base_snap + VIRTIO_REG_ISR_STATUS);
        }
    }

    // `IRQ_LAST_USED_IDX` is kept current by the poll-fallback path in
    // `submit_request`, which advances it on every completion.  By the
    // time `arm_irq` runs it already matches the device's `used.idx`,
    // so the ISR's first walk starts from the correct cursor.

    IRQS_ARMED.store(true, Ordering::Release);
    crate::serial_println!(
        "[VIRTIO-BLK] IRQ armed: PCI {:02x}:{:02x}.{} line={} -> vector {} (BSP APIC {})",
        b, d, f, irq_line, VIRTIO_BLK_IRQ_VECTOR, bsp_id
    );
}

/// Walk a device's PCI capability list and disable any MSI-X capability we
/// find.  PCI 3.0 §6.7 (Capability Pointers): caps list starts at config
/// offset 0x34 if Status register bit 4 is set; each cap header is two
/// bytes — `cap_id` at +0, `next_ptr` at +1.  MSI-X cap_id = 0x11.
/// The MSI-X Message Control register lives at cap_offset+2; bit 15 of
/// that 16-bit field is "MSI-X Enable" — clear it to fall back to INTx.
fn disable_msix(bus: u8, device: u8, function: u8) {
    // Status reg is at +0x06 (high half of dword at +0x04).
    let status_reg = super::pci::pci_config_read32(bus, device, function, 0x04);
    let status = (status_reg >> 16) as u16;
    if status & (1 << 4) == 0 {
        return; // Capabilities List bit not set — no caps.
    }
    // Cap pointer at +0x34, low byte.
    let cap_ptr = super::pci::pci_config_read32(bus, device, function, 0x34) & 0xFF;
    let mut off = (cap_ptr as u8) & 0xFC; // dword-aligned
    let mut hops = 0u8;
    while off != 0 && hops < 48 {
        let dw = super::pci::pci_config_read32(bus, device, function, off);
        let cap_id = (dw & 0xFF) as u8;
        let next = ((dw >> 8) & 0xFF) as u8;
        if cap_id == 0x11 {
            // MSI-X.  Message Control is bits 16..31 of the same dword
            // (cap_offset+2 = high half).
            let msg_ctl = ((dw >> 16) & 0xFFFF) as u16;
            if msg_ctl & (1 << 15) != 0 {
                let new_ctl = (msg_ctl & !(1u16 << 15)) as u32;
                let new_dw = (dw & 0x0000_FFFF) | (new_ctl << 16);
                super::pci::pci_config_write32(bus, device, function, off, new_dw);
                crate::serial_println!(
                    "[VIRTIO-BLK] Disabled MSI-X (was enabled, cap@{:#x})", off
                );
            }
            return;
        }
        off = next & 0xFC;
        hops += 1;
    }
}

/// Number of IRQs we received that did not advance the used ring.
/// Exposed for diagnostics; spurious counts > a handful at boot indicate
/// a routing or shared-IRQ misconfiguration.
pub fn spurious_count() -> u64 {
    SPURIOUS_IRQS.load(Ordering::Relaxed)
}

/// Diagnostics for the slot-quarantine path (completion-stall fix).  Returns
/// `(quarantined, reclaimed)`:
///   * `quarantined` — slots abandoned by a waiter on a no-progress timeout
///     while still owned by the device.
///   * `reclaimed`   — quarantined slots later retired by the device and
///     reclaimed by `drain_used_ring`.
/// In a healthy device these track each other; an outstanding gap
/// (`quarantined - reclaimed`) is bounded by `MAX_INFLIGHT` and represents
/// requests the device still owes.  A `quarantined` count that climbs while
/// `reclaimed` stays flat is the signature of a genuinely wedged device.
pub fn quarantine_counts() -> (u64, u64) {
    (
        QUARANTINED_TIMEOUTS.load(Ordering::Relaxed),
        RECLAIMED_QUARANTINES.load(Ordering::Relaxed),
    )
}

// ── ISR ─────────────────────────────────────────────────────────────────────

/// Virtio-blk interrupt handler.  Called from the IDT stub with interrupts
/// disabled.  Acknowledges the device, walks the used ring, and (if a
/// completion is observed) wakes the blocked submitter.
///
/// The handler must:
///   1. Read `ISR_STATUS` to clear the device's INTx assertion (virtio 1.0
///      §4.1.4.5 — read-to-clear).
///   2. Walk used.ring from `IRQ_LAST_USED_IDX` to the device's current
///      `used.idx`, demultiplexing each completed chain to its owning slot
///      (slot N's head descriptor is index `3*N`, virtio 1.0 §2.4.8).
///   3. Copy each completed slot's status byte from the per-slot virtqueue
///      scratch into `COMPLETIONS[slot].status`.
///   4. Signal `COMPLETIONS[slot].done` and try to flip the registered
///      waiter thread to `Ready`.
///   5. Send LAPIC EOI.
///
/// Lock discipline: the ISR NEVER takes [`VIRTIO_BLK`] (the submit path
/// only holds it briefly during descriptor build) and uses `try_lock`
/// only for [`THREAD_TABLE`].  All device state needed by the ISR is
/// read from the lock-free atomics populated by [`publish_irq_snapshot`]
/// plus the per-slot `COMPLETIONS` array.  If `THREAD_TABLE` is contended,
/// the wake is deferred — the slot's `done` flag is already set, so the
/// waiter's polled fallback in [`wait_completion`] picks the completion
/// up on its next iteration.
pub(crate) fn handle_irq() {
    TOTAL_IRQS.fetch_add(1, Ordering::Relaxed);
    let io_base = IRQ_IO_BASE.load(Ordering::Acquire);
    let qs = IRQ_QUEUE_SIZE.load(Ordering::Acquire);
    let vq_virt = IRQ_VQ_VIRT.load(Ordering::Acquire);

    // 1. Acknowledge device — read ISR status (read-to-clear).  Required
    //    even on spurious entries to keep the level-triggered PCI line from
    //    re-asserting immediately after EOI.
    let isr_bits = if io_base != 0 {
        // SAFETY: ISR status is a read-to-clear u8 register at +0x13.
        unsafe { crate::hal::inb(io_base + VIRTIO_REG_ISR_STATUS) }
    } else { 0 };

    // 2. Walk the used ring and wake every completed slot's waiter.
    let completed_any = if qs != 0 && vq_virt != 0 {
        drain_used_ring(qs, vq_virt) > 0
    } else {
        false
    };

    if !completed_any && isr_bits & 1 != 0 {
        // Device asserted "used ring update" but we couldn't see any new
        // entries — probably already serviced by a previous IRQ or by
        // the polled fallback in `wait_completion`.
        SPURIOUS_IRQS.fetch_add(1, Ordering::Relaxed);
    }

    // 3. EOI.
    if crate::arch::x86_64::apic::is_enabled() {
        crate::arch::x86_64::apic::lapic_eoi();
    }
}

/// Walk the used ring from `IRQ_LAST_USED_IDX` to the device's current
/// `used.idx`, marking every completed slot's `COMPLETIONS[slot].done`
/// and waking its registered TID.  Returns the number of entries
/// processed.
///
/// Used by both [`handle_irq`] and the polled fallback inside
/// [`wait_completion`] to keep the ISR's view of the ring consistent
/// with the polled view.  Per virtio 1.0 §2.4.8 each used-ring entry's
/// `id` is the head descriptor index — slot N's head is descriptor `3*N`.
///
/// Concurrent walks (ISR vs polled fallback on another CPU) are
/// serialised by a CAS on the cursor: each entry index is processed
/// by exactly one caller.  This avoids the race where a stale read of
/// a long-since-recycled ring slot would incorrectly flip a freshly-
/// reused completion slot's `done` flag.
fn drain_used_ring(qs: u16, vq_virt: u64) -> u32 {
    // SAFETY: `vq_virt` is the kernel higher-half mapping of the
    // virtqueue PFN we passed to QUEUE_ADDRESS; valid until
    // `restart_device` republishes it (in which case IRQS_ARMED gating
    // prevents new requests from racing with the republish).
    let used_ring_base = unsafe { (vq_virt as *const u8).add(used_ring_offset(qs)) };
    let cur_used = unsafe {
        let used_idx_ptr = used_ring_base.add(2) as *const u16;
        used_idx_ptr.read_volatile()
    };
    let mut count: u32 = 0;
    loop {
        // Take a single ring index for this iteration.  CAS guarantees
        // that exactly one caller observes each index value, even when
        // the ISR runs while a polled-fallback walk is in progress on
        // a different CPU.
        let last_seen = IRQ_LAST_USED_IDX.load(Ordering::Acquire);
        if last_seen == cur_used {
            break;
        }
        let next = last_seen.wrapping_add(1);
        if IRQ_LAST_USED_IDX
            .compare_exchange(last_seen, next, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Another walker advanced the cursor — retry from the new
            // baseline.  This is rare in practice (one IRQ + at most
            // one polled walker per CPU).
            continue;
        }

        // used.ring is at +4 from used_ring_base; each entry is 8 bytes
        // (`u32 id`, `u32 len`).  See virtio 1.0 §2.4.8.
        let slot_in_ring = (last_seen as usize) % (qs as usize);
        let entry_off = 4 + slot_in_ring * 8;
        let head_id = unsafe {
            let p = used_ring_base.add(entry_off) as *const u32;
            p.read_volatile()
        };
        // Recover slot index from head descriptor index.  Slot N's head
        // is descriptor 3N (see `submit_request`); any other id value
        // means the device returned a chain we did not submit (spec
        // violation), skip rather than indexing out of range.
        let slot_idx = (head_id / 3) as usize;
        if (head_id % 3) == 0 && slot_idx < MAX_INFLIGHT {
            let status_off = status_array_offset(qs) + slot_idx;
            // SAFETY: Device writes the status byte into the slot's
            // scratch before it advances used.idx (virtio 1.0 §2.4.7.2).
            //
            // QEMU's virtio-blk-pci-legacy backend can advance used.idx
            // before the status-byte write has propagated to guest-visible
            // memory.  Spin briefly on the 0xFF sentinel until the real
            // status arrives so the wake doesn't carry a phantom value.
            // In practice the window is < 1000 spin iterations on KVM.
            let status_byte = unsafe {
                let p = (vq_virt as *const u8).add(status_off);
                let mut s = p.read_volatile();
                let mut spins = 0u32;
                while s == 0xFF && spins < 100_000 {
                    core::hint::spin_loop();
                    s = p.read_volatile();
                    spins += 1;
                }
                s
            };
            COMPLETIONS[slot_idx].status.store(status_byte, Ordering::Relaxed);
            COMPLETIONS[slot_idx].done.store(true, Ordering::Release);

            // If this slot was quarantined (its waiter timed out while the
            // request was still owned by the device — see `quarantine_slot`),
            // the device has now retired the chain, so the descriptors and the
            // data buffer are no longer device-owned: reclaim the slot for
            // reuse.  There is no waiter to wake.  The reclaim must happen
            // AFTER the status read above so the device's status byte is fully
            // consumed first.  Release ordering pairs with `acquire_slot`'s
            // AcqRel CAS so the next acquirer observes the cleared state.
            if COMPLETIONS[slot_idx].quarantined.load(Ordering::Acquire) {
                COMPLETIONS[slot_idx].quarantined.store(false, Ordering::Release);
                COMPLETIONS[slot_idx].in_use.store(false, Ordering::Release);
                RECLAIMED_QUARANTINES.fetch_add(1, Ordering::Relaxed);
                count += 1;
                continue;
            }

            // Wake the registered waiter, if any.  `try_lock` only — if
            // THREAD_TABLE is contended, the slot's `done` flag is
            // already set, so the waiter's polled fallback inside
            // `wait_completion` picks the completion up next iteration.
            let waker = COMPLETIONS[slot_idx].waiter_tid.load(Ordering::Acquire);
            if waker != NO_WAITER {
                if let Some(mut threads) = crate::proc::THREAD_TABLE.try_lock() {
                    if let Some(t) = threads.iter_mut().find(|t| t.tid == waker) {
                        if t.state == crate::proc::ThreadState::Blocked {
                            t.state = crate::proc::ThreadState::Ready;
                            t.wake_tick = 0;
                        }
                    }
                }
            }
            count += 1;
        }
    }
    count
}

// ── PCI Discovery ───────────────────────────────────────────────────────────

/// Find a virtio-blk PCI device.
fn find_virtio_blk_pci() -> Option<super::pci::PciDevice> {
    let devices = super::pci::devices();
    for dev in &devices {
        if dev.vendor_id == VIRTIO_VENDOR {
            // Legacy device ID 0x1001 is virtio-blk.
            if dev.device_id == VIRTIO_BLK_DEVICE_LEGACY {
                return Some(*dev);
            }
            // Also check subsystem ID for generic virtio devices.
            let subsys = super::pci::pci_config_read32(
                dev.bus, dev.device, dev.function, 0x2C,
            );
            let subsys_id = (subsys >> 16) as u16;
            if subsys_id == VIRTIO_SUBSYS_BLK {
                return Some(*dev);
            }
        }
    }
    None
}

// ── I/O Operations ──────────────────────────────────────────────────────────

/// Outcome of [`submit_request`].
enum SubmitOutcome {
    /// Request completed inline via the early-boot poll fallback.  No
    /// further wait is required and the slot has already been released.
    PollDone,
    /// Request was submitted on the IRQ path; caller must drop the device
    /// mutex and call [`wait_completion`] with the returned slot index.
    IrqWait { slot: usize },
}

/// Submit a virtio-blk request against an already-acquired completion slot.
///
/// `req_type` is VIRTIO_BLK_T_IN (read) or VIRTIO_BLK_T_OUT (write).
/// `sector` is the starting LBA.
/// `data` points to the data buffer (count * 512 bytes).
/// `data_len` is the buffer length in bytes.
/// `slot` is a slot index returned by [`acquire_slot`]; the submitter
/// owns it for the duration of the request.
///
/// Per-slot descriptor layout: slot N owns descriptor heads `3*N`,
/// `3*N+1`, `3*N+2` in the shared descriptor table.  Per-slot scratch
/// (header + status byte) lives at fixed offsets in the virtqueue page
/// so concurrent submitters do not stomp each other's request data.
fn submit_request(
    dev: &mut VirtioBlkDevice,
    req_type: u32,
    sector: u64,
    data: *mut u8,
    data_len: usize,
    slot: usize,
) -> Result<SubmitOutcome, BlockError> {
    debug_assert!(slot < MAX_INFLIGHT);
    let io_base = dev.io_base;
    let qs = dev.queue_size;
    let vq_base = phys_to_virt::<u8>(dev.vq_phys);

    // Per-slot descriptor head index: slot N → descriptors 3N, 3N+1, 3N+2.
    let desc0_idx: u16 = (slot as u16) * 3;
    let desc1_idx: u16 = desc0_idx + 1;
    let desc2_idx: u16 = desc0_idx + 2;
    let desc_base = vq_base; // descriptor table at offset 0
    let avail_base = unsafe { vq_base.add(avail_ring_offset(qs)) };

    // Per-slot scratch: header at `header_array_offset + slot*16`,
    // status at `status_array_offset + slot`.
    let header_offset = header_array_offset(qs) + slot * 16;
    let status_offset = status_array_offset(qs) + slot;

    let header_virt = unsafe { vq_base.add(header_offset) } as *mut VirtioBlkReqHeader;
    let status_virt = unsafe { vq_base.add(status_offset) } as *mut u8;

    let header_phys = dev.vq_phys + header_offset as u64;
    let status_phys = dev.vq_phys + status_offset as u64;

    // SAFETY: Slot allocation gives this submitter exclusive access to its
    // header + status scratch, and the device mutex serialises descriptor
    // writes for the lifetime of submit_request.
    unsafe {
        (*header_virt).type_ = req_type;
        (*header_virt).reserved = 0;
        (*header_virt).sector = sector;
        core::ptr::write_volatile(status_virt, 0xFFu8); // sentinel
    }

    // Convert data pointer to physical address.
    // Kernel buffers may be in either:
    //   - Identity-mapped low memory (boot stack, below PHYS_OFFSET): phys = virt
    //   - Higher-half mapped memory (kernel heap/thread stacks): phys = virt - PHYS_OFFSET
    let data_virt = data as u64;
    let data_phys = if data_virt >= PHYS_OFFSET {
        data_virt - PHYS_OFFSET
    } else {
        data_virt
    };

    // ── Fill Descriptor Table ───────────────────────────────────────
    // Descriptor offsets are 16 bytes each, indexed by the slot's
    // per-slot head/middle/tail indices computed above.

    // Descriptor 3*slot (head): request header (device reads).
    let desc0 = unsafe { desc_base.add((desc0_idx as usize) * 16) };
    // SAFETY: Writing to the descriptor table within our allocated virtqueue memory.
    unsafe {
        let d0 = desc0 as *mut u64;
        d0.write_volatile(header_phys);
        let d0_meta = desc0.add(8) as *mut u32;
        d0_meta.write_volatile(16); // len = 16 bytes
        let d0_flags = desc0.add(12) as *mut u16;
        d0_flags.write_volatile(VRING_DESC_F_NEXT);
        let d0_next = desc0.add(14) as *mut u16;
        d0_next.write_volatile(desc1_idx);
    }

    // Descriptor 3*slot + 1: data buffer.
    let desc1 = unsafe { desc_base.add((desc1_idx as usize) * 16) };
    let data_flags = if req_type == VIRTIO_BLK_T_IN {
        VRING_DESC_F_NEXT | VRING_DESC_F_WRITE // device writes to buffer (read request)
    } else {
        VRING_DESC_F_NEXT // device reads from buffer (write request)
    };
    // SAFETY: Writing within our allocated virtqueue memory.
    unsafe {
        let d1_addr = desc1 as *mut u64;
        d1_addr.write_volatile(data_phys);
        let d1_len = desc1.add(8) as *mut u32;
        d1_len.write_volatile(data_len as u32);
        let d1_flags = desc1.add(12) as *mut u16;
        d1_flags.write_volatile(data_flags);
        let d1_next = desc1.add(14) as *mut u16;
        d1_next.write_volatile(desc2_idx);
    }

    // Descriptor 3*slot + 2: status byte (device writes).
    let desc2 = unsafe { desc_base.add((desc2_idx as usize) * 16) };
    // SAFETY: Writing within our allocated virtqueue memory.
    unsafe {
        let d2_addr = desc2 as *mut u64;
        d2_addr.write_volatile(status_phys);
        let d2_len = desc2.add(8) as *mut u32;
        d2_len.write_volatile(1);
        let d2_flags = desc2.add(12) as *mut u16;
        d2_flags.write_volatile(VRING_DESC_F_WRITE);
        let d2_next = desc2.add(14) as *mut u16;
        d2_next.write_volatile(0);
    }

    // ── Pre-arm completion state BEFORE doorbell ────────────────────
    //
    // Once the device sees the bumped avail.idx it can complete and IRQ
    // at any time; the ISR must be able to find a valid waker TID and
    // cleared done flag in this slot.  The slot was already initialised
    // by `acquire_slot`, but we set `waiter_tid` here (the caller's TID)
    // and ensure `done` is still false.  Done so before the doorbell
    // even on the poll-fallback path so a concurrent IRQ entry never
    // races with the slot's state.
    let irq_path = IRQS_ARMED.load(Ordering::Acquire) && crate::sched::is_active();
    COMPLETIONS[slot].done.store(false, Ordering::Release);
    COMPLETIONS[slot].status.store(0xFF, Ordering::Relaxed);
    if irq_path {
        COMPLETIONS[slot]
            .waiter_tid
            .store(crate::proc::current_tid(), Ordering::Release);
        COMPLETIONS[slot]
            .submit_ns
            .store(crate::proc::vdso::monotonic_ns(), Ordering::Relaxed);
    }

    // ── Submit to Available Ring ────────────────────────────────────

    // avail ring layout: flags(u16), idx(u16), ring[qs](u16 each)
    // SAFETY: Writing to the available ring within our allocated virtqueue memory.
    unsafe {
        let avail_idx_ptr = avail_base.add(2) as *mut u16;
        let idx = avail_idx_ptr.read_volatile();

        // Write descriptor chain head at ring[idx % qs].
        let ring_entry = avail_base.add(4 + ((idx % qs) as usize) * 2) as *mut u16;
        ring_entry.write_volatile(desc0_idx);

        // Memory barrier — ensure descriptor writes are visible before we
        // advance the index.
        core::sync::atomic::fence(Ordering::SeqCst);

        // Increment avail idx.
        avail_idx_ptr.write_volatile(idx.wrapping_add(1));
    }

    // Track total submissions for diagnostic last_used_idx (still useful
    // for spurious-IRQ accounting; no longer load-bearing for completion
    // detection now that we read the per-slot status byte).
    dev.last_used_idx = dev.last_used_idx.wrapping_add(1);

    // ── Notify Device ──────────────────────────────────────────────

    // SAFETY: Writing to the notify register of our discovered virtio device.
    unsafe {
        hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, 0);
    }

    if irq_path {
        // Caller will drop the device mutex and call `wait_completion(slot)`.
        return Ok(SubmitOutcome::IrqWait { slot });
    }

    // ── Poll Fallback ──────────────────────────────────────────────
    //
    // Used whenever the IRQ path is unavailable: during early boot
    // before `arm_irq` (FAT32 mount at Phase 7), and between `arm_irq`
    // and `sched::enable` (the FFTEST `prepopulate_file` path runs
    // hundreds of disk reads here on the BSP idle thread).  We poll
    // the slot's status byte directly: the device writes the real
    // status (0 = OK, non-zero = err) before advancing used.idx, so
    // any value other than the 0xFF sentinel means the request retired.
    //
    // We also keep `IRQ_LAST_USED_IDX` in step with the device's
    // `used.idx` on every completion so the first post-poll IRQ-path
    // request does not start from a stale cursor and find hundreds of
    // phantom completed entries from this poll-fallback era.
    let mut timeout = 10_000_000u32;
    let used_idx_ptr = unsafe {
        (vq_base as *const u8).add(used_ring_offset(qs) + 2) as *const u16
    };
    loop {
        // SAFETY: Reading the per-slot status byte from our virtqueue memory.
        let s = unsafe { status_virt.read_volatile() };
        if s != 0xFF {
            // SAFETY: Reading the device's used.idx from owned VQ memory.
            let cur_used = unsafe { used_idx_ptr.read_volatile() };
            IRQ_LAST_USED_IDX.store(cur_used, Ordering::Release);
            // Release the slot now since the caller won't enter wait_completion.
            // Safe: the device retired this chain (`s != 0xFF`), so it no longer
            // owns the descriptors or the data buffer.
            release_slot(slot);
            if s != 0 {
                crate::serial_println!("[VIRTIO-BLK] Request failed: status={}", s);
                return Err(BlockError::IoError);
            }
            return Ok(SubmitOutcome::PollDone);
        }
        // Timed out before the device retired the chain — it is still device-owned
        // (published to the avail ring, no used-ring entry yet).  Quarantine, not
        // release, so the descriptors and data buffer are not recycled under the
        // device (VIRTIO 1.2 §2.7.13.3).  `drain_used_ring` reclaims the slot when
        // the device finally retires it.
        timeout = timeout.checked_sub(1).ok_or_else(|| {
            quarantine_slot(slot);
            BlockError::IoError
        })?;
        core::hint::spin_loop();
    }
}

/// Submit a `VIRTIO_BLK_T_FLUSH` request and ring the device doorbell.
///
/// FLUSH has a degenerate two-descriptor chain — header → status, no data
/// buffer — per virtio 1.2 §5.2.6.2.  We still own three descriptors per
/// slot, but the middle one (`3*slot + 1`) is unused for flush; we link
/// the header (`3*slot`) directly to the status (`3*slot + 2`).
///
/// The completion path is identical to a read/write: the ISR demuxes by
/// head descriptor index (`head_id / 3`), the status byte lands in the
/// same per-slot scratch, and `wait_completion` (or the poll fallback)
/// observes `status != 0xFF` to detect retirement.
///
/// Caller must hold `VIRTIO_BLK.lock()` and have already acquired `slot`.
fn submit_flush_request(
    dev: &mut VirtioBlkDevice,
    slot: usize,
) -> Result<SubmitOutcome, BlockError> {
    debug_assert!(slot < MAX_INFLIGHT);
    let io_base = dev.io_base;
    let qs = dev.queue_size;
    let vq_base = phys_to_virt::<u8>(dev.vq_phys);

    // Slot N owns descriptors 3N (header), 3N+1 (unused for flush), 3N+2 (status).
    let desc0_idx: u16 = (slot as u16) * 3;
    let desc2_idx: u16 = desc0_idx + 2;
    let desc_base = vq_base; // descriptor table at offset 0
    let avail_base = unsafe { vq_base.add(avail_ring_offset(qs)) };

    let header_offset = header_array_offset(qs) + slot * 16;
    let status_offset = status_array_offset(qs) + slot;
    let header_virt = unsafe { vq_base.add(header_offset) } as *mut VirtioBlkReqHeader;
    let status_virt = unsafe { vq_base.add(status_offset) } as *mut u8;
    let header_phys = dev.vq_phys + header_offset as u64;
    let status_phys = dev.vq_phys + status_offset as u64;

    // SAFETY: slot allocation gives us exclusive access; the device mutex
    // serialises descriptor table writes for the duration of submit.
    unsafe {
        // VIRTIO_BLK_T_FLUSH request: sector field is reserved (and was
        // historically the LBA before which to flush; modern devices
        // ignore it and flush everything).  We zero it both for spec
        // hygiene and to avoid leaking previous-request data.
        (*header_virt).type_ = VIRTIO_BLK_T_FLUSH;
        (*header_virt).reserved = 0;
        (*header_virt).sector = 0;
        core::ptr::write_volatile(status_virt, 0xFFu8); // sentinel
    }

    // Descriptor 3*slot (head): request header (device reads).  Chain
    // straight to the status descriptor; no intermediate data buffer.
    let desc0 = unsafe { desc_base.add((desc0_idx as usize) * 16) };
    // SAFETY: writing within our owned virtqueue page.
    unsafe {
        let d0_addr = desc0 as *mut u64;
        d0_addr.write_volatile(header_phys);
        let d0_len = desc0.add(8) as *mut u32;
        d0_len.write_volatile(16); // sizeof(virtio_blk_outhdr) per §5.2.6
        let d0_flags = desc0.add(12) as *mut u16;
        d0_flags.write_volatile(VRING_DESC_F_NEXT);
        let d0_next = desc0.add(14) as *mut u16;
        d0_next.write_volatile(desc2_idx); // skip 3N+1
    }

    // Descriptor 3*slot + 2: status byte (device writes).
    let desc2 = unsafe { desc_base.add((desc2_idx as usize) * 16) };
    // SAFETY: writing within our owned virtqueue page.
    unsafe {
        let d2_addr = desc2 as *mut u64;
        d2_addr.write_volatile(status_phys);
        let d2_len = desc2.add(8) as *mut u32;
        d2_len.write_volatile(1);
        let d2_flags = desc2.add(12) as *mut u16;
        d2_flags.write_volatile(VRING_DESC_F_WRITE);
        let d2_next = desc2.add(14) as *mut u16;
        d2_next.write_volatile(0);
    }

    // Pre-arm slot completion state (matches submit_request).
    let irq_path = IRQS_ARMED.load(Ordering::Acquire) && crate::sched::is_active();
    COMPLETIONS[slot].done.store(false, Ordering::Release);
    COMPLETIONS[slot].status.store(0xFF, Ordering::Relaxed);
    if irq_path {
        COMPLETIONS[slot]
            .waiter_tid
            .store(crate::proc::current_tid(), Ordering::Release);
        COMPLETIONS[slot]
            .submit_ns
            .store(crate::proc::vdso::monotonic_ns(), Ordering::Relaxed);
    }

    // Publish into the available ring.
    // SAFETY: writing within our owned virtqueue page.
    unsafe {
        let avail_idx_ptr = avail_base.add(2) as *mut u16;
        let idx = avail_idx_ptr.read_volatile();
        let ring_entry = avail_base.add(4 + ((idx % qs) as usize) * 2) as *mut u16;
        ring_entry.write_volatile(desc0_idx);
        // Make descriptor + ring writes visible before the avail.idx bump.
        core::sync::atomic::fence(Ordering::SeqCst);
        avail_idx_ptr.write_volatile(idx.wrapping_add(1));
    }

    dev.last_used_idx = dev.last_used_idx.wrapping_add(1);

    // Ring the doorbell.
    // SAFETY: writing the notify register of the discovered virtio-blk PCI
    // device — same handling as the read/write submit path.
    unsafe {
        hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, 0);
    }

    if irq_path {
        return Ok(SubmitOutcome::IrqWait { slot });
    }

    // Poll fallback — same shape as submit_request's poll loop.  Flushes
    // can take longer than reads (the host must commit cached writes), so
    // we use a wider budget than the data-path's 10M-iter loop.
    let mut timeout = 50_000_000u32;
    let used_idx_ptr = unsafe {
        (vq_base as *const u8).add(used_ring_offset(qs) + 2) as *const u16
    };
    loop {
        // SAFETY: reading the per-slot status byte in owned VQ memory.
        let s = unsafe { status_virt.read_volatile() };
        if s != 0xFF {
            // SAFETY: reading the device's used.idx in owned VQ memory.
            let cur_used = unsafe { used_idx_ptr.read_volatile() };
            IRQ_LAST_USED_IDX.store(cur_used, Ordering::Release);
            // Safe: the device retired this chain, so it no longer owns it.
            release_slot(slot);
            if s != 0 {
                crate::serial_println!("[VIRTIO-BLK] Flush failed: status={}", s);
                return Err(BlockError::IoError);
            }
            return Ok(SubmitOutcome::PollDone);
        }
        // Still device-owned on timeout — quarantine, not release (see the read
        // path's poll fallback; VIRTIO 1.2 §2.7.13.3).
        timeout = timeout.checked_sub(1).ok_or_else(|| {
            quarantine_slot(slot);
            BlockError::IoError
        })?;
        core::hint::spin_loop();
    }
}

/// Diagnostic: number of times we entered wait_completion (one per IRQ-path
/// request).  Cheap counter for figuring out which step in the IRQ pipeline
/// is silent during early bring-up.
static WAIT_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Adaptive spin budget, in iterations, polled per round-trip before the waiter
/// considers yielding.  A KVM virtio-blk completion is typically retired within
/// ~50–100 µs of the doorbell — the host backend services it on the QEMU I/O
/// thread and advances `used.idx` — so spinning across that window catches the
/// common case with NO context switch and NO timer-tick stall, the cheapest
/// possible wait when the completion is imminent.  Measured device latency from
/// the wait-amplification histogram is ~50–100 µs at the 90th percentile; the
/// budget is sized to comfortably cover that.  Tunable at runtime via kdb
/// (`virtio-wait-spin <n>`).
///
/// NOTE (this host): the virtio-blk completion interrupt does NOT deliver on the
/// QEMU/KVM legacy-INTx configuration AstryxOS boots — `TOTAL_IRQS` stays 0
/// across thousands of round-trips while `POLLED_COMPLETIONS` climbs 1:1 with
/// `WAIT_ENTRIES`.  Every completion is therefore discovered by the waiter
/// polling the used ring itself (per virtio 1.2 §2.7.13, the device advances
/// `used.idx` whether or not anyone is listening on the interrupt line).  The
/// wait strategy is built around poll-discovery, not IRQ wakeup.
///
/// Sized to span the measured device latency (~50–100 µs ⇒ ~16 k `done`-probe
/// iterations on this host): the host I/O thread retires the request and
/// advances `used.idx` within this window in the overwhelming majority of
/// round-trips, so the waiter catches the completion by polling WITHOUT ever
/// giving up the CPU.  This is the load-bearing tuning: when the spin is too
/// short and the completion is missed, the waiter must yield — and on a deep
/// run queue (Firefox spawns ~200 threads) being re-selected to poll again
/// costs ~45 ms (a full set of peer quanta), measured directly in the
/// wait-amplification histogram (mean ~46 ms, yielded ~95 %).  Spinning ~100 µs
/// to avoid a ~45 ms re-selection stall is the right trade: the histogram
/// collapses to mean ~0.6 ms / p99 ~0.5 ms / max ~3 ms with this budget and
/// zero yields.  Tunable at runtime via kdb (`virtio-wait-spin <n>`).
static SPIN_BUDGET: AtomicU32 = AtomicU32::new(16384);

/// Runtime switch between the two wait strategies, so a single kernel build can
/// produce BOTH the BEFORE and AFTER wait-amplification histograms with no
/// build-to-build confound — the discipline this timing-sensitive investigation
/// needs.
///
///   `true`  (default) — ADAPTIVE: poll the slot + used ring at microsecond
///                       granularity, and yield (`schedule()`) ONLY when a real
///                       Ready peer exists to receive the CPU.  When the run
///                       queue is otherwise empty the waiter keeps polling
///                       instead of `schedule()`-ing into a `sti;hlt;cli` that
///                       would stall the (imminent) completion until the next
///                       100 Hz timer tick.
///   `false`           — LEGACY: poll the used ring, then unconditionally
///                       `schedule()` each round.  When no peer is Ready this
///                       hlts the CPU until the next timer tick, quantising a
///                       ~100 µs device wait up to a ~10–50 ms stall — the
///                       amplification this fix removes.
///
/// kdb: `virtio-wait-mode adaptive|legacy` flips it; `virtio-wait-hist` reports
/// it.
static WAIT_ADAPTIVE_ENABLED: AtomicBool = AtomicBool::new(true);

/// Set the wait strategy at runtime.  Returns the prior value.
pub fn set_wait_adaptive(on: bool) -> bool {
    WAIT_ADAPTIVE_ENABLED.swap(on, Ordering::Relaxed)
}

/// Current wait strategy (`true` = adaptive poll, `false` = legacy spin-yield).
pub fn wait_adaptive_enabled() -> bool {
    WAIT_ADAPTIVE_ENABLED.load(Ordering::Relaxed)
}

/// Set the adaptive-spin budget (iterations).  Returns the prior value.  0 is
/// clamped to 1 to keep at least one `done` probe per poll window.
pub fn set_spin_budget(n: u32) -> u32 {
    SPIN_BUDGET.swap(n.max(1), Ordering::Relaxed)
}

/// Wait for the in-flight virtio-blk request on `slot` to complete.
///
/// MUST be called with the [`VIRTIO_BLK`] mutex *not* held — the ISR runs
/// lock-free (it reads device state from `IRQ_*` atomics), but holding
/// the device mutex across `schedule()` would block any other thread
/// that tries to issue disk I/O.
///
/// Wait strategy (selected at runtime by [`WAIT_ADAPTIVE_ENABLED`]):
///
///   1. Bounded adaptive micro-spin on `COMPLETIONS[slot].done`, sized to the
///      ~50–100 µs device latency.  This catches the vast majority of
///      completions with NO context switch and NO timer-tick stall.
///   2a. ADAPTIVE (default): if still pending, walk the used ring ourselves
///       (the completion IRQ does not deliver on this host — see `SPIN_BUDGET`),
///       and yield via `schedule()` ONLY when a real Ready peer exists to take
///       the CPU.  When the run queue is otherwise empty, keep polling at
///       microsecond granularity instead of `schedule()`-ing into a
///       `sti;hlt;cli` that would stall the (imminent) completion until the
///       next 100 Hz tick.  This removes the 10–50 ms amplification cliff.
///   2b. LEGACY: unconditionally `schedule()` each poll round (the old path,
///       retained for the BEFORE/AFTER A/B on a single build).
///   3.  No-forward-progress deadline (`NO_PROGRESS_DEADLINE_TICKS`, re-armed
///       on device-side `used.idx` advance) — a genuinely wedged device
///       fails-fast rather than hanging the kernel, while a merely-slow device
///       or a descheduled waiter never trips it.
///
/// The calling thread is never marked `Blocked`: it remains Ready and either
/// spins or cooperatively yields, so it cannot be lost behind an interrupt that
/// never arrives.  On success the slot is released; on a deadline timeout the
/// slot is QUARANTINED (not released) by `wait_adaptive`/`wait_legacy_yield`,
/// because the request may still be owned by the device — `drain_used_ring`
/// reclaims it when the device finally retires the chain.
fn wait_completion(slot: usize) -> Result<(), BlockError> {
    debug_assert!(slot < MAX_INFLIGHT);
    let _ = WAIT_ENTRIES.fetch_add(1, Ordering::Relaxed);

    // Stage 1: adaptive micro-spin.  Device completions retire within ~50–100 µs
    // of the doorbell, so a spin across that window catches them with no context
    // switch — the cheapest wait when the completion is imminent.
    let budget = SPIN_BUDGET.load(Ordering::Relaxed);
    let mut spin = budget;
    while spin > 0 && !COMPLETIONS[slot].done.load(Ordering::Acquire) {
        core::hint::spin_loop();
        spin -= 1;
    }

    let mut yields: u16 = 0;
    if !COMPLETIONS[slot].done.load(Ordering::Acquire) {
        yields = if WAIT_ADAPTIVE_ENABLED.load(Ordering::Relaxed) {
            wait_adaptive(slot)?
        } else {
            wait_legacy_yield(slot)?
        };
    }

    // Record one wait-amplification sample (out-of-band ring, no VM-exit).
    record_completion_sample(slot, yields);

    let status = COMPLETIONS[slot].status.load(Ordering::Relaxed);
    release_slot(slot);
    if status != 0 {
        crate::serial_println!("[VIRTIO-BLK] Request failed: status={}", status);
        return Err(BlockError::IoError);
    }
    Ok(())
}

/// Compute and record the per-round-trip wait sample for `slot`.  Reads the
/// submit timestamp stamped at the doorbell and the current run-queue depth.
#[inline]
fn record_completion_sample(slot: usize, yields: u16) {
    let submit_ns = COMPLETIONS[slot].submit_ns.load(Ordering::Relaxed);
    if submit_ns == 0 {
        return; // poll-only / pre-IRQ submission — not part of the histogram
    }
    let now_ns = crate::proc::vdso::monotonic_ns();
    let wait_us = now_ns.saturating_sub(submit_ns) / 1000;
    let wait_us = if wait_us > u32::MAX as u64 { u32::MAX } else { wait_us as u32 };
    let depth = crate::sched::ready_depth();
    let depth = if depth > u16::MAX as u64 { u16::MAX } else { depth as u16 };
    record_wait_sample(wait_us, depth, yields);
}

/// Inner adaptive-spin chunk size, in `done`-probe iterations, between used-ring
/// walks.  Small enough that the loop re-walks the ring at microsecond
/// granularity, large enough that the `get_ticks()` read is amortised across
/// many cheap `done` probes.
const ADAPTIVE_CHUNK: u32 = 4096;

/// AFTER path: adaptive poll for the slow-completion tail.
///
/// Reached only when Stage 1's ~device-latency spin (`SPIN_BUDGET`) did not
/// catch the completion — i.e. this request is slower than the ~50–100 µs
/// common case.  The policy here is dictated by a measured asymmetry on this
/// host:
///
///   * The completion IRQ never delivers, so the waiter retires its own slot by
///     walking the used ring (per virtio 1.2 §2.7.13 the device advances
///     `used.idx` regardless of the interrupt line).
///   * Cooperatively `schedule()`-yielding is EXPENSIVE: with no IRQ wake, the
///     yielding waiter rejoins a ~200-thread run queue and is not re-selected to
///     poll again until it wins the picker — measured at ~45 ms (a full sweep of
///     peer quanta) in the wait-amplification histogram (legacy mean ~46 ms,
///     yielded ~95 %).  Yielding a ~hundred-µs wait turns it into a ~45 ms stall.
///
/// Therefore the waiter KEEPS POLLING through the early-slow window rather than
/// paying the re-selection stall, and only yields once the wait has clearly
/// crossed into "genuinely slow I/O" territory (`YIELD_AFTER_TICKS`), where the
/// device itself will take longer than the ~45 ms re-selection cost and giving
/// peers the core is the fair, throughput-preserving choice.  Even then it
/// yields only when `sched::ready_depth() > 0`, so it never `schedule()`s into
/// the empty-run-queue `sti;hlt;cli` that would stall the completion until the
/// next 100 Hz timer tick.
///
/// Correctness:
///   * No lost wakeups: the thread never sleeps `Blocked`, so there is no wake
///     to lose; completion is always discovered by the next ring walk.
///   * SMP (smp=2): `drain_used_ring` serialises the used-ring walk between this
///     waiter and any peer/ISR walker via the `IRQ_LAST_USED_IDX` CAS cursor, so
///     each used-ring entry is consumed exactly once.
///   * Liveness: a hard ~1 s deadline fails-fast a genuinely wedged device.
///
/// Returns the number of cooperative yields performed (0 when the completion was
/// caught purely by polling) for the wait-amplification telemetry.
fn wait_adaptive(slot: usize) -> Result<u16, BlockError> {
    let qs = IRQ_QUEUE_SIZE.load(Ordering::Acquire);
    let vq_virt = IRQ_VQ_VIRT.load(Ordering::Acquire);
    let start_tick = crate::arch::x86_64::irq::get_ticks();
    // Progress-based deadline: re-armed whenever the device retires ANY request
    // (its `used.idx` advances), so it measures time-since-the-device-last-made-
    // progress, never absolute wall-clock.  A descheduled waiter on a deep run
    // queue no longer spuriously trips the deadline while the device is healthy —
    // the previous absolute `start_tick + 100` fired on deschedule alone, abandoning
    // an in-flight request (the completion-stall root cause).  The deadline now
    // fires only when the device itself stops retiring requests for the whole
    // window, which is a genuine wedge.  See VIRTIO 1.2 §2.7.14.
    const NO_PROGRESS_TICKS: u64 = NO_PROGRESS_DEADLINE_TICKS;
    let mut deadline = start_tick.saturating_add(NO_PROGRESS_TICKS);
    let mut last_used = device_used_idx(qs, vq_virt);
    // Poll (don't yield) until the wait has lasted this many ticks; beyond it the
    // request is genuinely slow I/O and yielding to peers is worth the
    // re-selection cost.  5 ticks (~50 ms) comfortably exceeds the ~45 ms
    // re-selection stall, so we only ever yield when the device wait dominates.
    const YIELD_AFTER_TICKS: u64 = 5;
    let yield_after = start_tick.saturating_add(YIELD_AFTER_TICKS);
    let mut yields: u16 = 0;

    loop {
        // Walk the used ring ourselves — the completion IRQ does not deliver on
        // this host, so the waiter is the one that retires its own slot.
        if qs != 0 && vq_virt != 0 {
            drain_used_ring(qs, vq_virt);
        }
        if COMPLETIONS[slot].done.load(Ordering::Acquire) {
            POLLED_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
            return Ok(yields);
        }

        let now = crate::arch::x86_64::irq::get_ticks();
        // Re-arm the deadline on any device-side forward progress.  The device's
        // `used.idx` advances when it retires ANY queued request (not necessarily
        // ours), which proves the device is alive and draining the queue — so our
        // request is merely behind, not lost.  Only sustained zero progress means
        // a wedge.
        let cur_used = device_used_idx(qs, vq_virt);
        if cur_used != last_used {
            last_used = cur_used;
            deadline = now.saturating_add(NO_PROGRESS_TICKS);
        }
        if now >= deadline {
            // FINAL-DRAIN re-check before quarantining (closes the spurious-
            // quarantine TOCTOU that leaks slots under load).  Between the last
            // `drain_used_ring` at the top of this loop and the deadline test,
            // the device may have retired THIS slot's chain — advancing its own
            // `used.idx` for our entry — but the global `used.idx` re-arm above
            // only sees aggregate progress, so our slot's completion can be
            // missed and the slot needlessly quarantined.  A quarantined slot is
            // reclaimed ONLY when a future used-ring entry appears for it; once
            // the device's queue empties (every other slot is also pinned) that
            // entry never comes and the slot leaks, exhausting MAX_INFLIGHT and
            // wedging all further I/O.  This is the GUI fork-storm cascade: the
            // device retires requests in <2 ms (per the wait-amplification
            // histogram) yet slots accumulate as quarantined-and-leaked.  So
            // before giving up, walk the ring one last time and re-test `done`:
            // if our completion has in fact landed, release the slot normally
            // instead of leaking it via quarantine.  Per VIRTIO 1.2 §2.7.13 the
            // device retires a chain by appending it to the used ring; this
            // re-drain consumes exactly that.
            if qs != 0 && vq_virt != 0 {
                drain_used_ring(qs, vq_virt);
            }
            if COMPLETIONS[slot].done.load(Ordering::Acquire) {
                POLLED_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                return Ok(yields);
            }
            crate::serial_println!("[VIRTIO-BLK] wait_completion timeout (slot={})", slot);
            // The request really is still owned by the device (it is in the avail
            // ring but the device has not retired it).  Quarantine — do NOT
            // release — so its descriptor chain and data buffer are not recycled
            // under the device.  Releasing here is the bug that let in-flight
            // escape MAX_INFLIGHT and wedged the device (VIRTIO 1.2 §2.7.13.3).
            quarantine_slot(slot);
            return Err(BlockError::IoError);
        }

        // Only yield for genuinely slow I/O (wait already > YIELD_AFTER_TICKS),
        // and only when a real peer can take the core — never `schedule()` into
        // the empty-run-queue hlt that would tick-stall the completion.  In the
        // common early-slow window we keep polling, because yielding would cost
        // a ~45 ms run-queue re-selection (see the doc comment) — far more than
        // the few extra microseconds of polling.
        if now >= yield_after && crate::sched::ready_depth() > 0 {
            crate::sched::schedule();
            yields = yields.saturating_add(1);
        } else {
            // Spin a short chunk re-polling `done` before the next ring walk.
            let mut c = ADAPTIVE_CHUNK;
            while c > 0 && !COMPLETIONS[slot].done.load(Ordering::Acquire) {
                core::hint::spin_loop();
                c -= 1;
            }
        }
    }
}

/// BEFORE path: legacy spin-then-yield wait, retained behind the runtime
/// `WAIT_ADAPTIVE_ENABLED=false` switch so the BEFORE histogram can be measured
/// on the SAME build as the AFTER one.  Functionally identical to the
/// pre-change `wait_completion` Stage 2: it unconditionally `schedule()`s each
/// round, which hlts the CPU until the next timer tick when no peer is Ready —
/// the amplification this fix removes.  Returns the yield count.
fn wait_legacy_yield(slot: usize) -> Result<u16, BlockError> {
    let qs = IRQ_QUEUE_SIZE.load(Ordering::Acquire);
    let vq_virt = IRQ_VQ_VIRT.load(Ordering::Acquire);
    let start_tick = crate::arch::x86_64::irq::get_ticks();
    // Progress-based deadline (see `wait_adaptive`): re-armed on device-side
    // forward progress so a descheduled waiter never trips it while the device
    // is healthy.
    let mut deadline = start_tick.saturating_add(NO_PROGRESS_DEADLINE_TICKS);
    let mut last_used = device_used_idx(qs, vq_virt);
    let mut yields: u16 = 0;

    loop {
        if COMPLETIONS[slot].done.load(Ordering::Acquire) {
            return Ok(yields);
        }
        if qs != 0 && vq_virt != 0 {
            drain_used_ring(qs, vq_virt);
        }
        if COMPLETIONS[slot].done.load(Ordering::Acquire) {
            POLLED_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
            return Ok(yields);
        }
        let now = crate::arch::x86_64::irq::get_ticks();
        let cur_used = device_used_idx(qs, vq_virt);
        if cur_used != last_used {
            last_used = cur_used;
            deadline = now.saturating_add(NO_PROGRESS_DEADLINE_TICKS);
        }
        if now >= deadline {
            // FINAL-DRAIN re-check before quarantining — see the matching
            // comment in `wait_adaptive`.  The device may have retired our chain
            // since the last ring walk; re-draining and re-testing `done` here
            // avoids needlessly quarantining (and leaking) a slot whose
            // completion has already landed.  VIRTIO 1.2 §2.7.13.
            if qs != 0 && vq_virt != 0 {
                drain_used_ring(qs, vq_virt);
            }
            if COMPLETIONS[slot].done.load(Ordering::Acquire) {
                POLLED_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                return Ok(yields);
            }
            crate::serial_println!("[VIRTIO-BLK] wait_completion timeout (slot={})", slot);
            // Quarantine, not release — the request really is still device-owned.
            quarantine_slot(slot);
            return Err(BlockError::IoError);
        }
        crate::sched::schedule();
        yields = yields.saturating_add(1);
    }
}

/// No-forward-progress deadline for a device-side stall, in 100 Hz timer ticks.
/// The deadline is re-armed every time the device retires ANY request, so this
/// bounds *time since the device last made progress*, not absolute wall-clock.
/// 200 ticks ≈ 2 s of total device silence — generous enough that a merely-slow
/// host backend or a descheduled waiter never trips it, tight enough that a
/// genuinely wedged device still fails fast.  (The previous absolute 100-tick /
/// 1 s wall-clock deadline tripped on deschedule alone — the completion-stall
/// root cause; this is the same re-arm-on-progress correction the VFS
/// path-resolution deadline received.)
const NO_PROGRESS_DEADLINE_TICKS: u64 = 200;

/// Read the device's current `used.idx` (the count of requests it has retired)
/// from the virtqueue's used ring.  Used by the wait loops to re-arm the
/// no-progress deadline on device-side forward progress.  Returns 0 when the
/// ISR snapshot is not yet published (early boot), which simply means the
/// deadline is not re-armed until the device starts retiring requests.
#[inline]
fn device_used_idx(qs: u16, vq_virt: u64) -> u16 {
    if qs == 0 || vq_virt == 0 {
        return 0;
    }
    // used.idx is a u16 at `used_ring_base + 2` (flags u16, idx u16, ring...).
    // See VIRTIO 1.0 §2.4.8 (used ring layout).
    // SAFETY: `vq_virt` is the kernel higher-half mapping of the virtqueue page,
    // valid for the device's lifetime; the read is a single aligned volatile u16.
    unsafe {
        let p = (vq_virt as *const u8).add(used_ring_offset(qs) + 2) as *const u16;
        p.read_volatile()
    }
}

// ── BlockDevice Implementation ──────────────────────────────────────────────

/// A virtio-blk block device that implements the BlockDevice trait.
///
/// This is a zero-size wrapper — all state lives in the global VIRTIO_BLK.
/// Multiple callers can safely use it because submit_request holds the mutex.
pub struct VirtioBlkBlockDevice;

impl BlockDevice for VirtioBlkBlockDevice {
    fn sector_count(&self) -> u64 {
        VIRTIO_BLK.lock().as_ref().map_or(0, |d| d.capacity)
    }

    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        let needed = (count as usize) * SECTOR_SIZE;
        if buf.len() < needed {
            return Err(BlockError::BufferTooSmall);
        }
        if count == 0 {
            return Ok(());
        }
        do_io(VIRTIO_BLK_T_IN, lba, count, buf.as_mut_ptr())
    }

    fn write_sectors(&self, lba: u64, count: u32, data: &[u8]) -> Result<(), BlockError> {
        let needed = (count as usize) * SECTOR_SIZE;
        if data.len() < needed {
            return Err(BlockError::BufferTooSmall);
        }
        if count == 0 {
            return Ok(());
        }
        // Fail fast on a read-only device.  Per virtio 1.2 §5.2.3 the
        // device WILL reject the request, but checking locally avoids the
        // virtqueue round-trip and surfaces the policy uniformly to
        // every caller — `mkfs` / log writers / FAT32 dirty-flush all see
        // `IoError` instead of a transport-level success-then-failure.
        if VIRTIO_BLK_READONLY.load(Ordering::Acquire) {
            return Err(BlockError::IoError);
        }
        // SAFETY: We pass a *mut for the submit_request interface but the
        // device only reads from this buffer for T_OUT.
        do_io(VIRTIO_BLK_T_OUT, lba, count, data.as_ptr() as *mut u8)
    }

    fn flush(&self) -> Result<(), BlockError> {
        do_flush()
    }

    fn is_readonly(&self) -> bool {
        VIRTIO_BLK_READONLY.load(Ordering::Acquire)
    }

    fn logical_block_size(&self) -> u32 {
        VIRTIO_BLK_LOGICAL_BLOCK_SIZE.load(Ordering::Acquire)
    }
}

/// Issue a virtio-blk request and await its completion.  Splits the work into
/// up-to-MAX_SECTORS-sized batches; each batch acquires the device mutex,
/// builds descriptors, rings the doorbell, **drops the mutex**, then either
/// blocks on the IRQ-completion path (post-`arm_irq`) or polls inline (early
/// boot).  Dropping the mutex around the wait is essential — the ISR is
/// lock-free, but holding the mutex across `schedule()` would block any
/// other thread that tries to issue disk I/O.
///
/// Virtio block devices accept arbitrarily large data descriptors (the
/// descriptor's `len` field is u32, so up to 4 GiB per request); the
/// per-request size is constrained only by the device's segment limits and
/// the contiguity of the caller's buffer.  Kernel-heap buffers in AstryxOS
/// are always physically contiguous (the heap occupies one contiguous
/// physical range), so a single descriptor suffices.
///
/// 2048 sectors = 1 MiB per request.  Larger values further amortise the
/// per-request overhead (one KVM/MMIO round trip, one doorbell write, one
/// IRQ delivery) but require the caller's buffer to be physically
/// contiguous over the same span.  1 MiB stays well within the 128 MiB
/// kernel heap.
fn do_io(req_type: u32, lba: u64, count: u32, buf: *mut u8) -> Result<(), BlockError> {
    if !VIRTIO_BLK_AVAILABLE.load(Ordering::Acquire) {
        return Err(BlockError::IoError);
    }

    // Per-process disk-byte counter.  Attributed to the currently-running
    // PID — either the user task that issued the syscall (read/write/mmap
    // page-cache miss) or PID 0 for kernel-internal IO (mount, page-cache
    // readahead from a kernel worker).  Counted at submission time so the
    // sample reflects what the process actually requested, regardless of
    // whether the IO subsequently succeeds.  Bumped exactly once per do_io
    // call (i.e. per logical caller request) rather than per MAX_SECTORS
    // batch.
    {
        let _io_pid = crate::proc::current_pid_lockless();
        let bytes = (count as u64) * (SECTOR_SIZE as u64);
        if req_type == VIRTIO_BLK_T_IN {
            crate::proc::proc_metrics::bump_disk_read(_io_pid, bytes);
        } else if req_type == VIRTIO_BLK_T_OUT {
            crate::proc::proc_metrics::bump_disk_write(_io_pid, bytes);
        }
    }

    const MAX_SECTORS: u32 = 2048;
    let mut sector_idx = 0u32;

    while sector_idx < count {
        let batch = core::cmp::min(count - sector_idx, MAX_SECTORS);
        let offset = (sector_idx as usize) * SECTOR_SIZE;
        let batch_len = (batch as usize) * SECTOR_SIZE;
        // SAFETY: caller has already validated `buf` covers `count` sectors.
        let data_ptr = unsafe { buf.add(offset) };

        // ── Per-request LBA trace (feature `blk-trace`; default builds no-op).
        // One record per submitted virtio request — i.e. per batched descriptor
        // chain — so the LBA/len reflect the actual on-disk request granularity
        // (bounded by MAX_SECTORS) rather than the logical caller range. Drives
        // the data.img block-map heatmap. This records into a lock-free ring
        // (drivers/blk_trace) instead of a synchronous COM1 write, so it does
        // NOT inject a per-op PIO VM-exit storm into the disk hot path under
        // KVM. Drain out of band: kdb `blk-trace` op / harness `blk-trace
        // drain` / serial flush. The cfg guard keeps default builds
        // byte-identical: when the feature is off NONE of the argument
        // expressions (incl. the pid read) are evaluated, so the disk hot path
        // is exactly as before.
        #[cfg(feature = "blk-trace")]
        crate::drivers::blk_trace::record(
            if req_type == VIRTIO_BLK_T_IN { b'R' } else { b'W' },
            lba + sector_idx as u64,
            batch,
            crate::proc::current_pid_lockless() as u32,
        );

        // ── Acquire a completion slot (lock-free spin) ─────────────────
        //
        // Slot acquisition is independent of the device mutex — it just
        // claims an entry in COMPLETIONS[].  If every slot is busy
        // (MAX_INFLIGHT concurrent requests, unlikely in practice), we
        // yield and retry.  Sched availability is checked because early
        // boot has no scheduler to yield to; in that window the slot is
        // almost always free anyway (single-threaded mount path).
        // Acquire a slot.  If every slot is busy we yield and retry.  With the
        // quarantine fix a genuinely wedged device eventually pins all
        // MAX_INFLIGHT slots (each waiter quarantines on the no-progress
        // deadline), so bound the retry on device-side forward progress: if the
        // device's used.idx has not advanced for a full no-progress window while
        // we cannot get a slot, the device is dead — fail the I/O rather than
        // spinning forever.  A device that IS retiring requests reclaims
        // quarantined slots via drain_used_ring, so a slot frees up promptly and
        // this bound never trips in the healthy case.
        let acq_qs = IRQ_QUEUE_SIZE.load(Ordering::Acquire);
        let acq_vq = IRQ_VQ_VIRT.load(Ordering::Acquire);
        let mut acq_last_used = device_used_idx(acq_qs, acq_vq);
        let mut acq_deadline = crate::arch::x86_64::irq::get_ticks()
            .saturating_add(NO_PROGRESS_DEADLINE_TICKS);
        // One-shot device-reset recovery for self-inflicted slot exhaustion.
        // Under a heavy fork/teardown storm (the GTK/X11 GUI-launch path) the
        // per-request no-progress deadline can fire on a burst of in-flight
        // requests, quarantining their slots.  A quarantined slot is reclaimed
        // ONLY when the device produces a used-ring entry for it; once EVERY
        // slot is quarantined the device's queue is empty, its `used.idx`
        // freezes for lack of anything to retire, and the quarantined slots can
        // never be reclaimed — a permanent wedge that starves all further I/O
        // and, downstream, fails the demand-fault read of a shared-library code
        // page (delivering a fatal SIGSEGV to the faulting process).  The
        // device itself is healthy (it retired thousands of prior requests); the
        // queue is wedged purely by our own leaked quarantines.  When the
        // acquire deadline fires on this signature, a single device reset drops
        // all (now-meaningless) in-flight chains and releases every slot — the
        // spec-sanctioned way to abandon device-owned buffers (VIRTIO 1.2 §2.7)
        // — converting the permanent wedge into a transient hiccup.  Gated to
        // fire at most once per `do_io` call and only on the exhaustion
        // signature, so a genuinely-busy 32-deep queue (no quarantines) never
        // triggers it and a truly dead device still fails after the reset.
        let mut reset_recovered = false;
        let slot = loop {
            if let Some(s) = acquire_slot() {
                break s;
            }
            // Walk the used ring so quarantined slots get reclaimed promptly even
            // if no other waiter is currently draining it.
            if acq_qs != 0 && acq_vq != 0 {
                drain_used_ring(acq_qs, acq_vq);
            }
            let now = crate::arch::x86_64::irq::get_ticks();
            let cur_used = device_used_idx(acq_qs, acq_vq);
            if cur_used != acq_last_used {
                acq_last_used = cur_used;
                acq_deadline = now.saturating_add(NO_PROGRESS_DEADLINE_TICKS);
            } else if crate::sched::is_active() && now >= acq_deadline {
                // No slot freed and no device progress for the whole window.
                // Distinguish self-inflicted slot exhaustion (every slot pinned
                // by a leaked quarantine) from a genuinely dead device.  A high
                // quarantine count with zero free slots is the exhaustion
                // signature: reset the device once to recover the queue, then
                // give the acquire one more full window.
                if !reset_recovered
                    && quarantined_count() >= MAX_INFLIGHT / 2
                {
                    crate::serial_println!(
                        "[VIRTIO-BLK] slot exhaustion ({}/{} quarantined) — \
                         resetting device to recover the queue",
                        quarantined_count(), MAX_INFLIGHT);
                    // `restart_device` takes VIRTIO_BLK.lock() (not held here)
                    // and releases ALL slots after the reset.  Re-snapshot the
                    // ISR virtqueue handles afterwards: the reset zeroes the
                    // used ring and resets `used.idx`, so our cached cursor must
                    // restart too.
                    if restart_device() {
                        reset_recovered = true;
                        acq_last_used = device_used_idx(acq_qs, acq_vq);
                        acq_deadline =
                            now.saturating_add(NO_PROGRESS_DEADLINE_TICKS);
                        continue;
                    }
                }
                // Reset already attempted (or refused) and still no slot — the
                // device is genuinely wedged.  Fail-fast (matches the
                // wait-completion deadline contract) instead of hanging forever.
                return Err(BlockError::IoError);
            }
            if crate::sched::is_active() {
                crate::sched::schedule();
            } else {
                core::hint::spin_loop();
            }
        };

        // ── Submit + doorbell (lock held only across submission) ──────
        let outcome = {
            let mut guard = VIRTIO_BLK.lock();
            let dev = match guard.as_mut() {
                Some(d) => d,
                None => {
                    release_slot(slot);
                    return Err(BlockError::IoError);
                }
            };
            if lba + count as u64 > dev.capacity {
                drop(guard);
                release_slot(slot);
                return Err(BlockError::OutOfRange);
            }
            match submit_request(
                dev,
                req_type,
                lba + sector_idx as u64,
                data_ptr,
                batch_len,
                slot,
            ) {
                Ok(o) => o,
                Err(e) => {
                    // submit_request owns slot disposition on ALL of its error
                    // paths: the poll fallback already either released the slot
                    // (device-retired-with-error) or quarantined it (timeout,
                    // request still device-owned).  The IRQ path returns Err
                    // only BEFORE the doorbell, in which case it has likewise
                    // not left the slot armed.  Releasing the slot here would
                    // double-dispose — and worse, un-quarantine a device-owned
                    // chain (the completion-stall bug).  Leave the slot alone.
                    drop(guard);
                    return Err(e);
                }
            }
        };

        // ── Wait (lock dropped) ────────────────────────────────────────
        match outcome {
            SubmitOutcome::IrqWait { slot } => {
                // wait_completion releases the slot in both Ok and Err.
                wait_completion(slot)?;
            }
            SubmitOutcome::PollDone => {
                // Slot already released inside submit_request.
            }
        }

        sector_idx += batch;
    }

    Ok(())
}

/// Issue a single `VIRTIO_BLK_T_FLUSH` request and await its completion.
///
/// Mirrors the structure of [`do_io`]: acquire a slot, build descriptors
/// under the device mutex, drop the mutex before waiting.  If the device
/// did not negotiate `VIRTIO_BLK_F_FLUSH`, returns `Ok(())` immediately —
/// the host backend is write-through and there is nothing to flush.
///
/// Per virtio 1.2 §5.2.6.4: the device may complete the FLUSH request
/// before all in-flight writes have been retired; durable ordering is
/// guaranteed only with respect to writes the driver has already received
/// successful completions for.  Callers should therefore drain their own
/// outstanding writes before invoking flush(), which is the contract the
/// BlockDevice trait implies (writes are acknowledged before this method
/// is called).
fn do_flush() -> Result<(), BlockError> {
    if !VIRTIO_BLK_AVAILABLE.load(Ordering::Acquire) {
        return Err(BlockError::IoError);
    }
    if !VIRTIO_BLK_FLUSH_SUPPORTED.load(Ordering::Acquire) {
        // No-op: device has no write-back cache to drain.  Returning Ok
        // matches POSIX `fsync` on a tmpfs / write-through volume.
        return Ok(());
    }
    FLUSH_SUBMITTED.fetch_add(1, Ordering::Relaxed);

    // Slot acquisition mirrors do_io — yield to the scheduler if every
    // slot is currently in flight rather than busy-spinning the CPU.
    let slot = loop {
        if let Some(s) = acquire_slot() {
            break s;
        }
        if crate::sched::is_active() {
            crate::sched::schedule();
        } else {
            core::hint::spin_loop();
        }
    };

    let outcome = {
        let mut guard = VIRTIO_BLK.lock();
        let dev = match guard.as_mut() {
            Some(d) => d,
            None => {
                release_slot(slot);
                return Err(BlockError::IoError);
            }
        };
        match submit_flush_request(dev, slot) {
            Ok(o) => o,
            Err(e) => {
                // submit_flush_request owns slot disposition on all its error
                // paths (release on retired-error, quarantine on timeout) — do
                // not double-dispose here (see do_io).
                drop(guard);
                return Err(e);
            }
        }
    };

    match outcome {
        SubmitOutcome::IrqWait { slot } => wait_completion(slot),
        SubmitOutcome::PollDone => Ok(()),
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Quiesce the virtio-blk device on shutdown.
///
/// Writes 0 to the VIRTIO_DEVICE_STATUS register to reset the device,
/// which tells the hypervisor that this driver is done.  The virtio spec
/// (§4.1.4.1) says writing 0 performs a device reset, and is the correct
/// way to cleanly hand back the device on teardown.
pub fn stop() {
    crate::serial_println!("[VIRTIO-BLK] stop: resetting device");
    if !VIRTIO_BLK_AVAILABLE.load(Ordering::Acquire) {
        crate::serial_println!("[VIRTIO-BLK] stop: not initialized, skipping");
        return;
    }
    let guard = VIRTIO_BLK.lock();
    if let Some(ref dev) = *guard {
        // SAFETY: Writing device-status 0 is the spec-defined reset path for
        // a legacy virtio device; this is safe to do at any time per §4.1.4.1.
        unsafe {
            crate::hal::outb(dev.io_base + VIRTIO_REG_DEVICE_STATUS, 0);
        }
    }
    VIRTIO_BLK_AVAILABLE.store(false, Ordering::Release);
    // Per virtio 1.2 §4.1.4.1 a reset clears the device's negotiated
    // feature set.  Mirror that locally so a caller racing in between
    // `stop()` and `restart_device()` doesn't see stale FLUSH/RO bits.
    // `restart_device` republishes the cached values from `dev`.
    VIRTIO_BLK_FLUSH_SUPPORTED.store(false, Ordering::Release);
    crate::serial_println!("[VIRTIO-BLK] stop: done");
}

/// Re-initialize a previously-stopped virtio-blk device in place.
///
/// Used by the Po dry-run shutdown test, which calls `stop()` on every
/// registered driver but still needs disk I/O for the rest of the test
/// suite.  Reuses the already-allocated virtqueue memory and the cached
/// I/O base / queue size so no PCI re-discovery is required.
///
/// After a device reset (status=0), virtio §4.1.4.1 requires the driver
/// to re-run the ACKNOWLEDGE → DRIVER → FEATURES → QUEUE_ADDRESS →
/// DRIVER_OK sequence.  We also zero the virtqueue and reset our cached
/// `last_used_idx` so the used-ring poll matches the device's post-reset
/// state (device starts at used_idx=0 again).
///
/// Returns true if the device was successfully restarted.  Returns false
/// if no device was ever initialized, or if the queue configuration has
/// diverged (spec violation — device should report the same queue size).
pub fn restart_device() -> bool {
    let mut guard = VIRTIO_BLK.lock();
    let dev = match guard.as_mut() {
        Some(d) => d,
        None => {
            crate::serial_println!("[VIRTIO-BLK] restart_device: no device to restart");
            return false;
        }
    };

    // Zero the virtqueue region — stale descriptor/used-ring bytes from
    // before the reset would confuse the device after re-enable.
    let vq_virt = phys_to_virt::<u8>(dev.vq_phys);
    let total_bytes = virtqueue_total_bytes(dev.queue_size);
    // SAFETY: vq_phys + total_bytes is the owned virtqueue region we
    // allocated in init(); still reserved because we hold VIRTIO_BLK.
    unsafe {
        core::ptr::write_bytes(vq_virt, 0, total_bytes);
    }

    // SAFETY: Writing I/O ports of the discovered virtio-blk device.
    unsafe {
        // Re-run the device-init handshake (§4.1.4.1 after status=0 reset).
        hal::outb(dev.io_base + VIRTIO_REG_DEVICE_STATUS, 0);
        hal::outb(dev.io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        hal::outb(
            dev.io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );
        // Re-acknowledge the same feature subset we negotiated at init.
        // A reset clears the device's negotiated state, but per virtio
        // 1.2 §3.1.1 the driver must re-write GUEST_FEATURES before
        // DRIVER_OK; using the cached value keeps `VIRTIO_BLK_T_FLUSH`
        // available across the Po dry-run shutdown sweep.
        let _features = hal::inl(dev.io_base + VIRTIO_REG_DEVICE_FEATURES);
        hal::outl(dev.io_base + VIRTIO_REG_GUEST_FEATURES, dev.negotiated_features);

        // Select queue 0 and reconfirm queue size matches.
        hal::outw(dev.io_base + VIRTIO_REG_QUEUE_SELECT, 0);
        let queue_size = hal::inw(dev.io_base + VIRTIO_REG_QUEUE_SIZE);
        if queue_size != dev.queue_size {
            crate::serial_println!(
                "[VIRTIO-BLK] restart_device: queue size changed ({} → {}), aborting",
                dev.queue_size, queue_size
            );
            hal::outb(dev.io_base + VIRTIO_REG_DEVICE_STATUS, 0);
            return false;
        }

        // Re-publish the virtqueue PFN (the device forgets it across reset).
        let pfn = (dev.vq_phys >> 12) as u32;
        hal::outl(dev.io_base + VIRTIO_REG_QUEUE_ADDRESS, pfn);

        // DRIVER_OK — device is live again.
        hal::outb(
            dev.io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
        );
    }

    // Reset our cached used-ring index — the device's used idx is 0 again
    // after reset, and we just zeroed the used ring.
    dev.last_used_idx = 0;

    // A hard reset drops every in-flight request: the device no longer owns
    // any descriptor chain, so any quarantined slots (abandoned on a wait
    // timeout, awaiting their used-ring entry) will NEVER be reclaimed by
    // `drain_used_ring` — the used ring restarts from 0.  Fully release all
    // slots here so they are reusable; doing this now (with no in-flight
    // requests after the reset) is safe.
    for i in 0..MAX_INFLIGHT {
        COMPLETIONS[i].waiter_tid.store(NO_WAITER, Ordering::Release);
        COMPLETIONS[i].done.store(false, Ordering::Release);
        COMPLETIONS[i].status.store(0xFF, Ordering::Relaxed);
        COMPLETIONS[i].quarantined.store(false, Ordering::Release);
        COMPLETIONS[i].in_use.store(false, Ordering::Release);
    }

    let io_base_snap = dev.io_base;
    let qs_snap = dev.queue_size;
    let vq_phys_snap = dev.vq_phys;

    let flush_supported_snap =
        (dev.negotiated_features & (1u32 << VIRTIO_BLK_F_FLUSH)) != 0;
    let readonly_snap =
        (dev.negotiated_features & (1u32 << VIRTIO_BLK_F_RO)) != 0;
    let blk_size_snap = dev.blk_size;

    drop(guard);
    // Refresh the lock-free ISR snapshot — the device fields have not
    // changed but `IRQ_LAST_USED_IDX` must be reset to 0 to match the
    // post-reset device state.
    publish_irq_snapshot(io_base_snap, qs_snap, vq_phys_snap);
    VIRTIO_BLK_FLUSH_SUPPORTED.store(flush_supported_snap, Ordering::Release);
    VIRTIO_BLK_READONLY.store(readonly_snap, Ordering::Release);
    VIRTIO_BLK_LOGICAL_BLOCK_SIZE.store(blk_size_snap, Ordering::Release);
    VIRTIO_BLK_AVAILABLE.store(true, Ordering::Release);
    crate::serial_println!("[VIRTIO-BLK] restart_device: device re-initialized");
    true
}

/// Check if a virtio-blk device is available.
pub fn is_available() -> bool {
    VIRTIO_BLK_AVAILABLE.load(Ordering::Acquire)
}

/// Get the disk capacity in sectors (0 if no device).
pub fn capacity() -> u64 {
    VIRTIO_BLK.lock().as_ref().map_or(0, |d| d.capacity)
}

/// Returns `true` if `VIRTIO_BLK_F_FLUSH` was negotiated and the device
/// honours `VIRTIO_BLK_T_FLUSH`.  When `false`, [`do_flush`] returns
/// `Ok(())` without entering the submit machinery.
pub fn flush_supported() -> bool {
    VIRTIO_BLK_FLUSH_SUPPORTED.load(Ordering::Acquire)
}

/// Returns `true` if the device advertised `VIRTIO_BLK_F_RO`.  The
/// `BlockDevice::write_sectors` impl rejects writes locally when this
/// is set, before ringing the doorbell.
pub fn is_readonly() -> bool {
    VIRTIO_BLK_READONLY.load(Ordering::Acquire)
}

/// Logical block size in bytes — `virtio_blk_config.blk_size` if the
/// `VIRTIO_BLK_F_BLK_SIZE` feature was negotiated, otherwise 512.
pub fn logical_block_size() -> u32 {
    VIRTIO_BLK_LOGICAL_BLOCK_SIZE.load(Ordering::Acquire)
}

/// Diagnostic: total number of `VIRTIO_BLK_T_FLUSH` requests submitted
/// since boot.  Useful for confirming an `fsync(2)` or `FlushFileBuffers`
/// call actually reached the device.
pub fn flush_submitted() -> u64 {
    FLUSH_SUBMITTED.load(Ordering::Relaxed)
}

/// Diagnostic: total per-round-trip wait samples recorded into the
/// wait-amplification ring since boot (monotone; the ring wraps but this count
/// does not).  Used by the test harness to confirm the histogram is recording.
pub fn wait_samples_recorded() -> u64 {
    WAIT_CURSOR.load(Ordering::Relaxed)
}

/// Trigger a device flush from outside the BlockDevice trait — used by
/// the test harness and the kernel-side `sync()` path.  Wraps [`do_flush`]
/// so callers do not need a `VirtioBlkBlockDevice` handle.
pub fn flush() -> Result<(), BlockError> {
    do_flush()
}
