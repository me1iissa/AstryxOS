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

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};
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

const VIRTIO_BLK_T_IN:  u32 = 0; // Read
const VIRTIO_BLK_T_OUT: u32 = 1; // Write

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
}

/// Global virtio-blk device (if found).
static VIRTIO_BLK: Mutex<Option<VirtioBlkDevice>> = Mutex::new(None);
/// Fast check without acquiring the mutex on every block I/O call.
static VIRTIO_BLK_AVAILABLE: AtomicBool = AtomicBool::new(false);

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
}

impl Completion {
    const fn new() -> Self {
        Self {
            in_use: AtomicBool::new(false),
            done: AtomicBool::new(false),
            status: AtomicU8::new(0),
            waiter_tid: AtomicU64::new(NO_WAITER),
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

/// Acquire a free slot via CAS scan; returns `Some(slot_idx)` on success.
/// Caller must hold the device mutex while submitting against this slot
/// (so descriptor and header writes are serialised), but the wait runs
/// without the mutex held.  Returns `None` if every slot is busy — the
/// caller spins (with `core::hint::spin_loop`) and retries.
fn acquire_slot() -> Option<usize> {
    for i in 0..MAX_INFLIGHT {
        if COMPLETIONS[i]
            .in_use
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Reset slot state for new request.
            COMPLETIONS[i].done.store(false, Ordering::Release);
            COMPLETIONS[i].status.store(0xFF, Ordering::Relaxed);
            COMPLETIONS[i].waiter_tid.store(NO_WAITER, Ordering::Release);
            return Some(i);
        }
    }
    None
}

/// Release a slot for reuse.  Must be called by the same waiter that
/// acquired it, after the wait has consumed `done` + `status`.
fn release_slot(slot_idx: usize) {
    COMPLETIONS[slot_idx].waiter_tid.store(NO_WAITER, Ordering::Release);
    COMPLETIONS[slot_idx].in_use.store(false, Ordering::Release);
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

        // 4. Read device features, write guest features (accept none for basic I/O).
        let _features = hal::inl(io_base + VIRTIO_REG_DEVICE_FEATURES);
        hal::outl(io_base + VIRTIO_REG_GUEST_FEATURES, 0);

        // 5. Read device capacity (sectors).
        let cap_lo = hal::inl(io_base + VIRTIO_REG_BLK_CAPACITY_LO) as u64;
        let cap_hi = hal::inl(io_base + VIRTIO_REG_BLK_CAPACITY_HI) as u64;
        let capacity = (cap_hi << 32) | cap_lo;
        crate::serial_println!("[VIRTIO-BLK] Capacity: {} sectors ({} MiB)", capacity, capacity * 512 / (1024 * 1024));

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
        });
        publish_irq_snapshot(io_base, queue_size, vq_phys);
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
            release_slot(slot);
            if s != 0 {
                crate::serial_println!("[VIRTIO-BLK] Request failed: status={}", s);
                return Err(BlockError::IoError);
            }
            return Ok(SubmitOutcome::PollDone);
        }
        timeout = timeout.checked_sub(1).ok_or_else(|| {
            release_slot(slot);
            BlockError::IoError
        })?;
        core::hint::spin_loop();
    }
}

/// Diagnostic: number of times we entered wait_completion (one per IRQ-path
/// request).  Cheap counter for figuring out which step in the IRQ pipeline
/// is silent during early bring-up.
static WAIT_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Wait for the in-flight virtio-blk request on `slot` to complete.
///
/// MUST be called with the [`VIRTIO_BLK`] mutex *not* held — the ISR runs
/// lock-free (it reads device state from `IRQ_*` atomics), but holding
/// the device mutex across `schedule()` would block any other thread
/// that tries to issue disk I/O.
///
/// Three-stage wait:
///   1. Bounded micro-spin on `COMPLETIONS[slot].done` (most KVM
///      completions land here because the ISR runs immediately).
///   2. Polled per-slot status-byte read + scheduler yield: if the IRQ
///      hasn't fired promptly, we read the slot's status byte directly
///      and yield via `schedule()` to let other threads run.  This is
///      the load-bearing path for hosts where the IO-APIC route doesn't
///      actually deliver to vector 45 (UEFI quirk, shared-IRQ corner
///      case, etc.).
///   3. Hard deadline at 1s wall-clock — a wedged device fails-fast
///      rather than hanging the kernel.
///
/// Even in stage 2, the calling thread is *not* marked Blocked: when no
/// other thread is Ready on this CPU, `schedule()` returns immediately
/// (no work to do) and we re-poll.  When other threads ARE Ready, the
/// scheduler dispatches them while our request is in flight — which is
/// the SMP-fairness win this driver is after.
///
/// Always releases `slot` before returning (Ok or Err).
fn wait_completion(slot: usize) -> Result<(), BlockError> {
    debug_assert!(slot < MAX_INFLIGHT);
    let _ = WAIT_ENTRIES.fetch_add(1, Ordering::Relaxed);

    // Stage 1: cheap micro-spin.
    let mut spin_budget = 1024u32;
    while spin_budget > 0 && !COMPLETIONS[slot].done.load(Ordering::Acquire) {
        core::hint::spin_loop();
        spin_budget -= 1;
    }

    if !COMPLETIONS[slot].done.load(Ordering::Acquire) {
        let qs = IRQ_QUEUE_SIZE.load(Ordering::Acquire);
        let vq_virt = IRQ_VQ_VIRT.load(Ordering::Acquire);

        let start_tick = crate::arch::x86_64::irq::get_ticks();
        let deadline = start_tick.saturating_add(100); // ~1s @ 100Hz

        loop {
            if COMPLETIONS[slot].done.load(Ordering::Acquire) {
                break;
            }

            // Walk the used ring ourselves.  The ISR may have missed
            // entries (e.g. the IO-APIC route silently drops vector 45
            // on some UEFI configurations), or the IRQ may not have
            // fired yet.  We mirror the ISR's demultiplex logic so each
            // newly-completed slot's `done` flag is set and the global
            // cursor advances past every completed entry — keeping the
            // ISR's view consistent with ours.
            if qs != 0 && vq_virt != 0 {
                drain_used_ring(qs, vq_virt);
            }

            if COMPLETIONS[slot].done.load(Ordering::Acquire) {
                POLLED_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                break;
            }

            if crate::arch::x86_64::irq::get_ticks() >= deadline {
                crate::serial_println!(
                    "[VIRTIO-BLK] wait_completion timeout (slot={})",
                    slot
                );
                release_slot(slot);
                return Err(BlockError::IoError);
            }

            // Yield to the scheduler.  If another thread is Ready on this
            // CPU, schedule() picks it; we resume on the next round.  If
            // not, schedule() is essentially a no-op and we go straight
            // back to the polled status check.
            crate::sched::schedule();
        }
    }

    let status = COMPLETIONS[slot].status.load(Ordering::Relaxed);
    release_slot(slot);
    if status != 0 {
        crate::serial_println!("[VIRTIO-BLK] Request failed: status={}", status);
        return Err(BlockError::IoError);
    }
    Ok(())
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
        // SAFETY: We pass a *mut for the submit_request interface but the
        // device only reads from this buffer for T_OUT.
        do_io(VIRTIO_BLK_T_OUT, lba, count, data.as_ptr() as *mut u8)
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

    const MAX_SECTORS: u32 = 2048;
    let mut sector_idx = 0u32;

    while sector_idx < count {
        let batch = core::cmp::min(count - sector_idx, MAX_SECTORS);
        let offset = (sector_idx as usize) * SECTOR_SIZE;
        let batch_len = (batch as usize) * SECTOR_SIZE;
        // SAFETY: caller has already validated `buf` covers `count` sectors.
        let data_ptr = unsafe { buf.add(offset) };

        // ── Acquire a completion slot (lock-free spin) ─────────────────
        //
        // Slot acquisition is independent of the device mutex — it just
        // claims an entry in COMPLETIONS[].  If every slot is busy
        // (MAX_INFLIGHT concurrent requests, unlikely in practice), we
        // yield and retry.  Sched availability is checked because early
        // boot has no scheduler to yield to; in that window the slot is
        // almost always free anyway (single-threaded mount path).
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
                    // submit_request releases the slot on its poll-fallback
                    // error path, but the IRQ-path error path here means
                    // we never armed the slot — release it ourselves.
                    drop(guard);
                    release_slot(slot);
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
        let _features = hal::inl(dev.io_base + VIRTIO_REG_DEVICE_FEATURES);
        hal::outl(dev.io_base + VIRTIO_REG_GUEST_FEATURES, 0);

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
    let io_base_snap = dev.io_base;
    let qs_snap = dev.queue_size;
    let vq_phys_snap = dev.vq_phys;

    drop(guard);
    // Refresh the lock-free ISR snapshot — the device fields have not
    // changed but `IRQ_LAST_USED_IDX` must be reset to 0 to match the
    // post-reset device state.
    publish_irq_snapshot(io_base_snap, qs_snap, vq_phys_snap);
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
