//! Virtio-serial PCI Driver (Legacy Interface) — Multiport + IRQ-driven RX
//!
//! Exposes a single byte-stream character device at `/dev/vport0p0` backed by
//! a virtio-serial (virtio-console) port.  This is the kernel half of the
//! QEMU Guest Agent (QGA) transport: a userspace daemon (`userspace/qga/`)
//! opens the device node and runs the QGA JSON-RPC loop against the host.
//!
//! # Multiport (PORT_OPEN handshake)
//!
//! QEMU's `-device virtserialport,nr=1,name=org.qemu.guest_agent.0` wires
//! the QGA chardev to **port 1**, not port 0.  Port 0 is permanently
//! reserved for the legacy console pair (vq0/vq1).  To route data through
//! port 1 we must negotiate `VIRTIO_CONSOLE_F_MULTIPORT` and perform the
//! control-queue handshake from virtio 1.2 §5.3.6: send `DEVICE_READY(1)`
//! and `PORT_OPEN(port=1, value=1)` on the control TX queue, then receive
//! and ack the host's `PORT_ADD` / `PORT_NAME` / `PORT_OPEN` events on the
//! control RX queue.  Without this, QEMU keeps `host_connected = false`
//! for port 1 and silently swallows incoming chardev bytes — the wedge
//! that PR #158's QGA-3 harness surfaced.
//!
//! # Virtqueue layout (per §5.3.2)
//!
//! * vq0 — port 0 receiveq      (allocated for DRIVER_OK; never used).
//! * vq1 — port 0 transmitq     (same).
//! * vq2 — control receiveq     (host → guest control events).
//! * vq3 — control transmitq    (guest → host control events).
//! * vq4 — port 1 (QGA) rx      (the data RX queue).
//! * vq5 — port 1 (QGA) tx      (the data TX queue).
//!
//! # RX path (poll + IRQ)
//!
//! Two delivery paths cooperate:
//!
//! 1. **Polling** — `read()` always walks the rx used ring directly.  This
//!    is the only path active before `arm_irq()` registers the IO-APIC
//!    route (early-boot test runner, QGA-1 smoke).
//! 2. **IRQ-driven** — after `arm_irq()` flips `IRQS_ARMED`, the device's
//!    `virtio_notify` on used.idx advance fires the IO-APIC line through
//!    vector `VIRTIO_SERIAL_IRQ_VECTOR`.  `handle_irq` drains the used
//!    ring into `rx_ring`, re-publishes the rx descriptor, and wakes any
//!    thread parked in `read_blocking` via the global `WaitList`.
//!
//! `read_blocking` is the VFS entry point for blocking reads (default for
//! `/dev/vport0p0` opens without `O_NONBLOCK`).  It loop-yields when IRQs
//! have never fired (test-mode synthetic injection bypasses the host) and
//! parks on the WaitList once a real IRQ has been observed.
//!
//! # References
//!
//! * Virtio 1.2 spec, §5.3 (Console Device).
//! * Virtio 1.0 legacy PCI device init: §4.1.4.
//! * Virtio 1.0 ISR-status read-to-clear: §4.1.4.5.
//! * Virtqueue split-ring layout: §2.6.

extern crate alloc;

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use spin::Mutex;

use crate::hal;
use crate::ipc::waitlist::{ring_poll_bell, wake_tids, WaitList};
use crate::mm::pmm;

// ── Virtio PCI Constants ────────────────────────────────────────────────────

/// Red Hat / Virtio vendor ID.
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Legacy (transitional) virtio-console / virtio-serial device ID.
const VIRTIO_SERIAL_DEVICE_LEGACY: u16 = 0x1003;
/// Virtio subsystem ID for console devices (§5.3.1).
const VIRTIO_SUBSYS_CONSOLE: u16 = 3;

// ── Legacy Virtio Register Offsets (from BAR0 I/O base) ─────────────────────

const VIRTIO_REG_DEVICE_FEATURES: u16 = 0x00; // u32 RO
const VIRTIO_REG_GUEST_FEATURES:  u16 = 0x04; // u32 RW
const VIRTIO_REG_QUEUE_ADDRESS:   u16 = 0x08; // u32 RW  (PFN = phys >> 12)
const VIRTIO_REG_QUEUE_SIZE:      u16 = 0x0C; // u16 RO
const VIRTIO_REG_QUEUE_SELECT:    u16 = 0x0E; // u16 RW
const VIRTIO_REG_QUEUE_NOTIFY:    u16 = 0x10; // u16 WO
const VIRTIO_REG_DEVICE_STATUS:   u16 = 0x12; // u8  RW
#[allow(dead_code)]
const VIRTIO_REG_ISR_STATUS:      u16 = 0x13; // u8  RO (read-to-clear; QGA-1b)

// ── Device Status Bits ──────────────────────────────────────────────────────

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER:      u8 = 2;
const VIRTIO_STATUS_DRIVER_OK:   u8 = 4;

// ── Virtio-Console Feature Bits ─────────────────────────────────────────────
//
// Per virtio 1.2 §5.3.3:
//   VIRTIO_CONSOLE_F_SIZE      (bit 0) — host carries console window-size info.
//   VIRTIO_CONSOLE_F_MULTIPORT (bit 1) — device supports multiple ports.
//
// QEMU's virtio-serial-pci offers MULTIPORT unconditionally.  We must
// accept it: the QGA chardev is wired to port 1 (port 0 is reserved for
// the legacy console pair), and QEMU only routes data to port 1 when
// the driver has acknowledged MULTIPORT, processed the control-queue
// PORT_ADD handshake, and sent PORT_OPEN.  Without this, QEMU keeps
// `host_connected = false` for port 1 and silently swallows host writes
// to the chardev socket (the QGA-3 wedge surfaced by PR #158).
const VIRTIO_CONSOLE_F_MULTIPORT: u32 = 1 << 1;

// ── Control-Queue Message Layout & Events ───────────────────────────────────
//
// Per virtio 1.2 §5.3.6.7.  Every control message is a 4-byte header:
//   u32 id     — target port id (0xFFFFFFFF / "bad id" for device-wide messages)
//   u16 event  — event code, table below
//   u16 value  — event payload (boolean flag for OPEN/READY/etc.)
//
// We send DEVICE_READY + PORT_OPEN; we consume PORT_ADD, PORT_NAME, and
// PORT_OPEN (host-initiated) from the device.  Other event types are
// processed by replenishing the rx buffer and silently dropping the
// payload.
const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
#[allow(dead_code)]
const VIRTIO_CONSOLE_DEVICE_ADD:   u16 = 1;
#[allow(dead_code)]
const VIRTIO_CONSOLE_DEVICE_REMOVE:u16 = 2;
const VIRTIO_CONSOLE_PORT_READY:   u16 = 3;
#[allow(dead_code)]
const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
#[allow(dead_code)]
const VIRTIO_CONSOLE_RESIZE:       u16 = 5;
const VIRTIO_CONSOLE_PORT_OPEN:    u16 = 6;
#[allow(dead_code)]
const VIRTIO_CONSOLE_PORT_NAME:    u16 = 7;

/// Port id of the QGA chardev, derived from the `-device virtserialport,nr=1`
/// QEMU CLI.  Port 0 is reserved for the console pair (vq0 / vq1) so the
/// first user-visible port is always 1, regardless of multiport count.
const QGA_PORT_ID: u32 = 1;

/// "Bad" port id used for device-wide control messages (DEVICE_READY,
/// DEVICE_ADD/REMOVE).
const CTRL_BAD_PORT_ID: u32 = 0xFFFF_FFFF;

/// Number of control-rx buffers we keep parked.  The host issues one
/// control event per port at init (PORT_ADD, PORT_NAME, PORT_OPEN — three
/// events for our single QGA port) plus an indefinite trickle of
/// connect/disconnect notifications; a small ring is enough.
const CTRL_RX_BUFS: u16 = 8;

/// Size of one control-rx scratch slot.  Control messages are at most a
/// 4-byte header + a small payload (port name string for PORT_NAME), all
/// well under 256 B.  Round to one cache line for hygiene.
const CTRL_BUF_LEN: usize = 64;

// ── Virtqueue Descriptor Flags ──────────────────────────────────────────────

#[allow(dead_code)]
const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

// ── Higher-Half Mapping ─────────────────────────────────────────────────────

const PHYS_OFFSET: u64 = astryx_shared::KERNEL_VIRT_BASE;

#[inline]
fn phys_to_virt<T>(phys: u64) -> *mut T {
    (PHYS_OFFSET + phys) as *mut T
}

// ── Virtqueue Layout Helpers ────────────────────────────────────────────────
//
// Split-ring layout per virtio 1.2 §2.6:
//
//   offset 0                       descriptor table   (16 * qs bytes)
//   offset 16 * qs                 available ring     (4 + 2 * qs bytes)
//   offset ≈ above, page-aligned   used ring          (4 + 8 * qs bytes)
//
// A second 4 KiB page after the used ring holds the per-port rx/tx scratch
// buffer (one per queue).  Keeping it inside the virtqueue allocation keeps
// the whole driver in one contiguous PMM region.

#[inline]
fn avail_ring_offset(queue_size: u16) -> usize {
    (queue_size as usize) * 16
}

#[inline]
fn used_ring_offset(queue_size: u16) -> usize {
    let avail_end = avail_ring_offset(queue_size) + 4 + (queue_size as usize) * 2;
    (avail_end + 4095) & !4095
}

#[inline]
fn used_ring_end(queue_size: u16) -> usize {
    used_ring_offset(queue_size) + 4 + (queue_size as usize) * 8
}

/// Total bytes for a virtqueue plus its co-located scratch page.
#[inline]
fn virtqueue_total_bytes(queue_size: u16) -> usize {
    let with_scratch = ((used_ring_end(queue_size) + 4095) & !4095) + 4096;
    (with_scratch + 4095) & !4095
}

#[inline]
fn scratch_buf_offset(queue_size: u16) -> usize {
    (used_ring_end(queue_size) + 4095) & !4095
}

/// Size of one rx/tx scratch buffer.  4 KiB matches a typical virtio-console
/// descriptor and is the largest QGA chunk size the daemon will produce.
const SCRATCH_BUF_LEN: usize = 4096;

// ── Driver State ────────────────────────────────────────────────────────────

struct VirtQueue {
    queue_size: u16,
    phys: u64,
    last_used: u16,
    next_avail: u16,
}

impl VirtQueue {
    #[inline]
    fn desc(&self) -> *mut u8 {
        phys_to_virt::<u8>(self.phys)
    }

    #[inline]
    fn avail(&self) -> *mut u8 {
        unsafe { self.desc().add(avail_ring_offset(self.queue_size)) }
    }

    #[inline]
    fn used(&self) -> *mut u8 {
        unsafe { self.desc().add(used_ring_offset(self.queue_size)) }
    }

    #[inline]
    fn scratch_phys(&self) -> u64 {
        self.phys + scratch_buf_offset(self.queue_size) as u64
    }

    #[inline]
    fn scratch_virt(&self) -> *mut u8 {
        unsafe { self.desc().add(scratch_buf_offset(self.queue_size)) }
    }

    /// Write descriptor 0 with `(addr, len, flags)` — no next link.
    /// SAFETY: caller must hold the device mutex.
    unsafe fn fill_desc0(&self, addr: u64, len: u32, flags: u16) {
        self.fill_desc(0, addr, len, flags);
    }

    /// Write descriptor `idx` with `(addr, len, flags)` — no next link.
    /// `idx` must be < `queue_size`.  Used for control-queue rings where we
    /// want multiple parked buffers, one per descriptor index.
    /// SAFETY: caller must hold the device mutex.
    unsafe fn fill_desc(&self, idx: u16, addr: u64, len: u32, flags: u16) {
        let d = self.desc().add((idx as usize) * 16);
        (d as *mut u64).write_volatile(addr);
        (d.add(8) as *mut u32).write_volatile(len);
        (d.add(12) as *mut u16).write_volatile(flags & !VRING_DESC_F_NEXT);
        (d.add(14) as *mut u16).write_volatile(0);
    }

    /// Publish descriptor 0 into the available ring.
    /// SAFETY: caller must hold the device mutex.
    unsafe fn publish_desc0(&mut self) {
        self.publish_desc(0);
    }

    /// Publish descriptor `idx` into the available ring.  Bumps
    /// `next_avail` and writes the new value into `avail.idx` per virtio
    /// 1.2 §2.6.6.
    /// SAFETY: caller must hold the device mutex.
    unsafe fn publish_desc(&mut self, idx: u16) {
        let avail = self.avail();
        let slot = avail.add(4 + ((self.next_avail % self.queue_size) as usize) * 2) as *mut u16;
        slot.write_volatile(idx);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.next_avail = self.next_avail.wrapping_add(1);
        let avail_idx = avail.add(2) as *mut u16;
        avail_idx.write_volatile(self.next_avail);
    }

    /// Read the descriptor id of the entry at `used.ring[(used_idx-1) % qs].id`.
    /// Counterpart to `used_len`.  Needed for control-queue replenish so we
    /// can re-publish the slot the device just returned.
    /// SAFETY: caller must hold the device mutex.
    unsafe fn used_id(&self, used_idx: u16) -> u32 {
        let slot = self.used().add(4 + ((used_idx.wrapping_sub(1) % self.queue_size) as usize) * 8);
        (slot as *const u32).read_volatile()
    }

    /// SAFETY: caller must hold the device mutex (or be the ISR).
    unsafe fn used_idx(&self) -> u16 {
        let p = self.used().add(2) as *const u16;
        p.read_volatile()
    }

    /// Read the byte count from used.ring[(used_idx - 1) % qs].len.
    /// SAFETY: caller must hold the device mutex.
    unsafe fn used_len(&self, used_idx: u16) -> u32 {
        let slot = self.used().add(4 + ((used_idx.wrapping_sub(1) % self.queue_size) as usize) * 8);
        (slot.add(4) as *const u32).read_volatile()
    }
}

struct VirtioSerialDevice {
    io_base: u16,
    /// Port 1 (QGA) data RX queue — virtqueue index 4.
    rxq: VirtQueue,
    /// Port 1 (QGA) data TX queue — virtqueue index 5.
    txq: VirtQueue,
    /// Control RX queue (host → guest control messages) — virtqueue index 2.
    /// Populated with `CTRL_RX_BUFS` slots in `init()`; replenished by the
    /// ISR each time the host pushes a control event.
    cq_rx: VirtQueue,
    /// Control TX queue (guest → host control messages) — virtqueue index 3.
    /// Used to send DEVICE_READY, PORT_READY, and PORT_OPEN.
    cq_tx: VirtQueue,
    /// Bytes already consumed from the currently active rx descriptor.
    rx_consumed: u32,
    /// Total bytes available in the currently active rx descriptor.
    rx_avail: u32,
    /// PCI bus/device/function and INTx line, cached for `arm_irq()`.
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    pci_irq_line: u8,
    /// Bytes copied out of the rx virtqueue by the ISR but not yet drained
    /// by a userspace `read()`.  The ring is short-lived in steady state —
    /// host writes one QGA frame, daemon `read()`s it within a tick.  The
    /// 16 KiB cap matches the maximum-burst case (four 4 KiB descriptors
    /// landing back-to-back before the daemon catches up).
    rx_ring: VecDeque<u8>,
    /// True once we have replied PORT_OPEN(1) for the QGA port, which
    /// flips QEMU's `host_connected` flag for the chardev backend and
    /// authorises data delivery.  Diagnostic — also surfaces in `stats()`.
    port_opened: bool,
}

/// Maximum bytes held in `rx_ring` before the ISR starts dropping data.
/// The QGA frame upper bound is ~5.5 KiB (base64 of a 4 KiB file read);
/// 16 KiB gives ~3 frames of headroom which is enough for any burst the
/// host can produce between two scheduler ticks.
const RX_RING_CAP: usize = 16 * 1024;

static VIRTIO_SERIAL: Mutex<Option<VirtioSerialDevice>> = Mutex::new(None);
static VIRTIO_SERIAL_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Whether `arm_irq()` has registered the IO-APIC route.  Until this flips
/// true the driver uses pure polling (the boot path runs before APIC init
/// on the BSP, so the polling fallback covers early callers).
static IRQS_ARMED: AtomicBool = AtomicBool::new(false);

/// Wait list of threads parked in `read_blocking()` waiting for the ISR
/// to deposit bytes into `rx_ring`.  Woken via `wake_tids` from the IRQ
/// path; the global poll bell is also rung so any `poll`/`epoll_wait`
/// caller watching the vport re-evaluates.
static RX_WAITERS: Mutex<WaitList> = Mutex::new(WaitList::new());

/// Lock-free snapshot of the device's I/O base for the ISR.  The ISR
/// reads `ISR_STATUS` (read-to-clear) without taking [`VIRTIO_SERIAL`] —
/// a `read_blocking()` caller may have just parked while still holding
/// the device mutex's spinlock briefly, and we want the IRQ to be
/// serviceable immediately regardless.
static IRQ_IO_BASE: AtomicU16 = AtomicU16::new(0);
/// Total ISR entries.  Diagnostic counter.
static TOTAL_IRQS: AtomicU64 = AtomicU64::new(0);
/// ISR entries that found no new used-ring progress.  Non-zero in steady
/// state indicates shared-IRQ routing or a stale ack.
static SPURIOUS_IRQS: AtomicU64 = AtomicU64::new(0);
/// Bytes the ISR had to drop because `rx_ring` was full.  Should stay 0
/// for QGA workloads; rising values mean the daemon is not draining fast
/// enough or the ring cap is too small.
static RX_DROPPED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Mutex-free snapshot of the virtqueue physical/runtime addresses used by
/// the loopback test helpers (`test_inject_rx` / `test_drain_tx`).  These are
/// set exactly once during `init()` and never change afterwards, so we can
/// reach into the queues without contending against the device-mutex spin
/// inside `write()`.  Without this, a daemon parked spinning on tx
/// completion would block the test runner from ever advancing used.idx.
#[cfg(feature = "qga")]
#[derive(Clone, Copy)]
struct LoopbackHandles {
    rxq_phys: u64,
    rxq_size: u16,
    txq_phys: u64,
    txq_size: u16,
}
#[cfg(feature = "qga")]
static LOOPBACK: Mutex<Option<LoopbackHandles>> = Mutex::new(None);

// VIRTIO_SERIAL_IRQ_VECTOR is defined further down inside the IRQ wiring
// block, alongside `arm_irq()` and `handle_irq()`.  Vectors 32-45 are
// taken by timer, keyboard, e1000, mouse, virtio-blk; we use 46.

// ── PCI Discovery ───────────────────────────────────────────────────────────

fn find_virtio_serial_pci() -> Option<super::pci::PciDevice> {
    let devs = super::pci::devices();
    for d in &devs {
        if d.vendor_id != VIRTIO_VENDOR {
            continue;
        }
        if d.device_id == VIRTIO_SERIAL_DEVICE_LEGACY {
            return Some(*d);
        }
        // Modern virtio devices: disambiguate by subsystem ID at PCI 0x2C.
        let subsys = super::pci::pci_config_read32(d.bus, d.device, d.function, 0x2C);
        let subsys_id = (subsys >> 16) as u16;
        if subsys_id == VIRTIO_SUBSYS_CONSOLE {
            return Some(*d);
        }
    }
    None
}

// ── Queue Setup ─────────────────────────────────────────────────────────────

unsafe fn setup_queue(io_base: u16, idx: u16) -> Option<VirtQueue> {
    hal::outw(io_base + VIRTIO_REG_QUEUE_SELECT, idx);
    let qs = hal::inw(io_base + VIRTIO_REG_QUEUE_SIZE);
    if qs == 0 {
        crate::serial_println!("[VIRTIO-SERIAL] queue {} unavailable (qs=0)", idx);
        return None;
    }
    let total = virtqueue_total_bytes(qs);
    let pages = (total + 4095) / 4096;
    let phys = pmm::alloc_pages(pages)?;
    let virt = phys_to_virt::<u8>(phys);
    core::ptr::write_bytes(virt, 0, total);
    let pfn = (phys >> 12) as u32;
    hal::outl(io_base + VIRTIO_REG_QUEUE_ADDRESS, pfn);
    Some(VirtQueue {
        queue_size: qs,
        phys,
        last_used: 0,
        next_avail: 0,
    })
}

/// Hand the rx queue a buffer so the device can write incoming bytes into it.
unsafe fn replenish_rx(rxq: &mut VirtQueue) {
    rxq.fill_desc0(rxq.scratch_phys(), SCRATCH_BUF_LEN as u32, VRING_DESC_F_WRITE);
    rxq.publish_desc0();
}

// ── Initialization ──────────────────────────────────────────────────────────

/// Probe PCI for a virtio-serial device and bring it up.  Returns `true` on
/// success, `false` when no device was found or init failed.  Safe to call
/// multiple times — the global state will only be populated once.
///
/// # MULTIPORT init sequence
///
/// QEMU's `-device virtserialport,nr=1,name=org.qemu.guest_agent.0` exposes
/// the QGA chardev on **port 1**, not port 0.  Port 0 is permanently
/// reserved for the legacy console pair (vq0/vq1).  Routing data through
/// port 1 requires `VIRTIO_CONSOLE_F_MULTIPORT` and the control-queue
/// handshake from virtio 1.2 §5.3.6.  Without MULTIPORT the host treats
/// port 1 as `host_connected = false` and silently swallows incoming
/// chardev bytes — the wedge that PR #158's QGA-3 harness surfaced.
///
/// Steps performed here:
///   1. PCI probe + reset → ACK → DRIVER.
///   2. Negotiate features: accept `VIRTIO_CONSOLE_F_MULTIPORT`, refuse
///      every other offered bit.
///   3. Set up six virtqueues:
///         vq0 — port 0 receiveq      (allocated but unused; QEMU still
///                                     enumerates port 0 in non-console
///                                     mode and rejects DRIVER_OK if the
///                                     queue PFNs are zero).
///         vq1 — port 0 transmitq     (same — allocated, never published to).
///         vq2 — control receiveq     (filled with `CTRL_RX_BUFS` buffers).
///         vq3 — control transmitq    (used for DEVICE_READY / PORT_OPEN).
///         vq4 — port 1 (QGA) rx      (the only RX queue we actually consume).
///         vq5 — port 1 (QGA) tx      (the only TX queue we ever write to).
///   4. Mark DRIVER_OK.
///   5. Replenish the QGA rx queue with one scratch buffer.
///   6. Send `VIRTIO_CONSOLE_DEVICE_READY(value=1)` via vq3.  The host
///      responds with a stream of control events on vq2 (PORT_ADD,
///      PORT_NAME, PORT_OPEN) which we consume + reply to in the IRQ
///      handler.
///   7. Send `VIRTIO_CONSOLE_PORT_OPEN(port=1, value=1)` via vq3.  This
///      flips `host_connected = true` on the QEMU side and unblocks
///      `virtio_serial_write()` so chardev data starts flowing to vq4.
pub fn init() -> bool {
    if VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) {
        return true;
    }

    let pci_dev = match find_virtio_serial_pci() {
        Some(d) => d,
        None => {
            crate::serial_println!("[VIRTIO-SERIAL] No virtio-serial PCI device found");
            return false;
        }
    };

    crate::serial_println!(
        "[VIRTIO-SERIAL] Found device at PCI {:02x}:{:02x}.{} (vendor={:04x} device={:04x})",
        pci_dev.bus, pci_dev.device, pci_dev.function,
        pci_dev.vendor_id, pci_dev.device_id
    );

    let bar0 = pci_dev.bar[0];
    if bar0 & 1 == 0 {
        crate::serial_println!("[VIRTIO-SERIAL] BAR0 is not I/O space, aborting");
        return false;
    }
    let io_base = (bar0 & 0xFFFF_FFFC) as u16;
    crate::serial_println!("[VIRTIO-SERIAL] I/O base = {:#06x}", io_base);

    super::pci::enable_bus_master(pci_dev.bus, pci_dev.device, pci_dev.function);
    let cmd = super::pci::pci_config_read32(pci_dev.bus, pci_dev.device, pci_dev.function, 0x04);
    super::pci::pci_config_write32(pci_dev.bus, pci_dev.device, pci_dev.function, 0x04, cmd | 0x01);

    // SAFETY: writing to the discovered virtio device's own I/O ports.
    let (port0_rx, port0_tx, cq_rx, cq_tx, rxq, txq) = unsafe {
        // Reset → ACK → DRIVER per §4.1.4.1.
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );

        // Negotiate features.  Accept MULTIPORT; refuse the rest — we do
        // not implement F_SIZE (console-mode window-size), and the
        // device's advanced layout bits (event_idx, packed, etc.) are
        // unconditionally legacy-off for a vendor 0x1003 device.
        let offered = hal::inl(io_base + VIRTIO_REG_DEVICE_FEATURES);
        let guest_feats = offered & VIRTIO_CONSOLE_F_MULTIPORT;
        hal::outl(io_base + VIRTIO_REG_GUEST_FEATURES, guest_feats);
        crate::serial_println!(
            "[VIRTIO-SERIAL] features: offered={:#x} accepted={:#x} (multiport={})",
            offered, guest_feats,
            if guest_feats & VIRTIO_CONSOLE_F_MULTIPORT != 0 { "yes" } else { "NO" }
        );
        if guest_feats & VIRTIO_CONSOLE_F_MULTIPORT == 0 {
            crate::serial_println!(
                "[VIRTIO-SERIAL] host refused MULTIPORT — port 1 (QGA) cannot be reached, aborting"
            );
            hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
            return false;
        }

        // Per §5.3.2, multiport layout is vq0..vq5:
        //   0/1 = port 0 (console pair),  2/3 = control rx/tx,
        //   4/5 = port 1 (QGA) rx/tx.
        // We allocate all six even though port 0 stays idle, because
        // QEMU's `virtio-serial-bus.c::set_status` refuses DRIVER_OK
        // unless every advertised queue has been programmed with a PFN.
        let port0_rx = match setup_queue(io_base, 0) {
            Some(q) => q,
            None => { hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0); return false; }
        };
        let port0_tx = match setup_queue(io_base, 1) {
            Some(q) => q,
            None => { hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0); return false; }
        };
        let cq_rx = match setup_queue(io_base, 2) {
            Some(q) => q,
            None => { hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0); return false; }
        };
        let cq_tx = match setup_queue(io_base, 3) {
            Some(q) => q,
            None => { hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0); return false; }
        };
        let rxq = match setup_queue(io_base, 4) {
            Some(q) => q,
            None => { hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0); return false; }
        };
        let txq = match setup_queue(io_base, 5) {
            Some(q) => q,
            None => { hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0); return false; }
        };

        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
        );
        (port0_rx, port0_tx, cq_rx, cq_tx, rxq, txq)
    };

    crate::serial_println!(
        "[VIRTIO-SERIAL] queues: p0_rx={:#x} p0_tx={:#x} cq_rx={:#x} cq_tx={:#x} p1_rx={:#x} p1_tx={:#x}",
        port0_rx.phys, port0_tx.phys, cq_rx.phys, cq_tx.phys, rxq.phys, txq.phys
    );

    let mut dev = VirtioSerialDevice {
        io_base,
        rxq,
        txq,
        cq_rx,
        cq_tx,
        rx_consumed: 0,
        rx_avail: 0,
        pci_bus:  pci_dev.bus,
        pci_dev:  pci_dev.device,
        pci_func: pci_dev.function,
        pci_irq_line: pci_dev.interrupt_line,
        rx_ring: VecDeque::with_capacity(RX_RING_CAP),
        port_opened: false,
    };
    // Port 0's queues are bound to the device but never carry data on our
    // QGA wiring; drop them on the floor.  Holding them in `dev` would
    // confuse the loopback test which keys off (rxq, txq) addresses.
    drop(port0_rx);
    drop(port0_tx);

    // SAFETY: dev is locally owned at this point.
    unsafe {
        // Replenish the QGA rx queue with one scratch buffer.  Notify
        // after publishing so the host wakes up immediately.
        replenish_rx(&mut dev.rxq);
        hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, 4);

        // Replenish the control rx queue with CTRL_RX_BUFS small slots,
        // each living at scratch_phys + i*CTRL_BUF_LEN.  The slots fit
        // inside the queue's 4 KiB scratch page (8 * 64 = 512 bytes).
        let cq_rx_scratch = dev.cq_rx.scratch_phys();
        for i in 0..CTRL_RX_BUFS {
            let addr = cq_rx_scratch + (i as u64) * (CTRL_BUF_LEN as u64);
            dev.cq_rx.fill_desc(i, addr, CTRL_BUF_LEN as u32, VRING_DESC_F_WRITE);
            dev.cq_rx.publish_desc(i);
        }
        hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, 2);

        // Step 6 — send DEVICE_READY(1) on the control TX queue.  Host
        // responds with PORT_ADD / PORT_NAME control events for every
        // configured port.  We don't have to wait for them in init;
        // they will arrive on the cq_rx and be consumed by the ISR
        // (or by `pump_control_rx` called from the polling path).
        send_control_msg(&mut dev, CTRL_BAD_PORT_ID, VIRTIO_CONSOLE_DEVICE_READY, 1);

        // Step 7 — send PORT_READY(1) + PORT_OPEN(1) for the QGA port.
        // PORT_READY signals "I'm ready to receive PORT_ADD's friends
        // (PORT_NAME, etc.)"; PORT_OPEN flips the host's
        // `host_connected` flag for the chardev backend and authorises
        // data delivery into vq4.
        //
        // Spec deviation: virtio-console §5.3.6 has the guest first consume
        // the host's PORT_ADD on cq_rx before announcing PORT_READY/PORT_OPEN.
        // QEMU tolerates the inversion (PORT_READY/OPEN sent ahead of seeing
        // PORT_ADD on the rx side) and the alternative — block init waiting
        // for cq_rx — would force IRQ-driven completion or an arbitrary spin,
        // both of which complicate boot ordering for no functional gain.
        send_control_msg(&mut dev, QGA_PORT_ID, VIRTIO_CONSOLE_PORT_READY, 1);
        send_control_msg(&mut dev, QGA_PORT_ID, VIRTIO_CONSOLE_PORT_OPEN,  1);
    }

    // Stash the queue physical addresses + sizes for mutex-free loopback
    // access from the test helpers (Phase QGA-2 only).
    #[cfg(feature = "qga")]
    {
        *LOOPBACK.lock() = Some(LoopbackHandles {
            rxq_phys:  dev.rxq.phys,
            rxq_size:  dev.rxq.queue_size,
            txq_phys:  dev.txq.phys,
            txq_size:  dev.txq.queue_size,
        });
    }

    crate::serial_println!(
        "[VIRTIO-SERIAL] Initialized: io={:#06x}, rxq_size={}, txq_size={}, rxq_phys={:#x}, txq_phys={:#x}",
        io_base, dev.rxq.queue_size, dev.txq.queue_size, dev.rxq.phys, dev.txq.phys
    );

    *VIRTIO_SERIAL.lock() = Some(dev);
    IRQ_IO_BASE.store(io_base, Ordering::Release);
    VIRTIO_SERIAL_AVAILABLE.store(true, Ordering::Release);
    true
}

/// Send one virtio-console control message via the control TX queue
/// (`cq_tx`).  The message is the canonical 8-byte header:
///   u32 id, u16 event, u16 value
/// per virtio 1.2 §5.3.6.7.  We reuse the queue's scratch buffer (each
/// VirtQueue has one); the call is synchronous — descriptor 0 carries
/// the message, we publish, notify, and spin briefly on the used ring.
///
/// SAFETY: caller must hold the device mutex (or be in `init()` which
/// owns the device).  Bounded by a 1 M iteration budget so a wedged
/// hypervisor cannot hang init.
unsafe fn send_control_msg(dev: &mut VirtioSerialDevice, id: u32, event: u16, value: u16) {
    let scratch = dev.cq_tx.scratch_virt();
    (scratch as *mut u32).write_volatile(id);
    (scratch.add(4) as *mut u16).write_volatile(event);
    (scratch.add(6) as *mut u16).write_volatile(value);

    let msg_len: u32 = 8;
    dev.cq_tx.fill_desc0(dev.cq_tx.scratch_phys(), msg_len, 0); // device reads
    dev.cq_tx.publish_desc0();
    hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 3);

    // Spin briefly on used.idx — the host retires the control message
    // synchronously, so the wait is bounded.  At ~1 M iterations on
    // typical KVM hardware this is well under a millisecond.
    let mut budget: u32 = 1_000_000;
    let expected = dev.cq_tx.next_avail;
    loop {
        let cur = dev.cq_tx.used_idx();
        if cur == expected {
            dev.cq_tx.last_used = cur;
            break;
        }
        budget = match budget.checked_sub(1) {
            Some(b) => b,
            None => {
                crate::serial_println!(
                    "[VIRTIO-SERIAL] ctrl-tx wedged sending id={} event={} value={}",
                    id, event, value
                );
                return;
            }
        };
        core::hint::spin_loop();
    }
    // ctrl-tx happens exactly three times at init (DEVICE_READY,
    // PORT_READY, PORT_OPEN) so we leave the trace in to make the
    // multiport handshake observable; suppressing it would hide a
    // regression where one of the three never goes out.
    let ev_name = match event {
        VIRTIO_CONSOLE_DEVICE_READY => "DEVICE_READY",
        VIRTIO_CONSOLE_PORT_READY   => "PORT_READY",
        VIRTIO_CONSOLE_PORT_OPEN    => "PORT_OPEN",
        _ => "?",
    };
    crate::serial_println!(
        "[VIRTIO-SERIAL] ctrl-tx {} value={} id={}",
        ev_name, value, id as i32
    );
}

/// Drain pending control RX messages from `cq_rx`, take any actions
/// they imply (PORT_OPEN → flip `port_opened`), and re-publish the
/// consumed descriptor.  Idempotent — returns the number of events
/// drained.  Called both from the ISR and from the polling `read()`
/// path so the handshake completes even before `arm_irq()` runs.
///
/// SAFETY: caller must hold the device mutex.
unsafe fn pump_control_rx(dev: &mut VirtioSerialDevice) -> u32 {
    let mut drained: u32 = 0;
    loop {
        let cur_used = dev.cq_rx.used_idx();
        if cur_used == dev.cq_rx.last_used {
            return drained;
        }
        let new_used = dev.cq_rx.last_used.wrapping_add(1);
        let len = dev.cq_rx.used_len(new_used) as usize;
        let id_desc = dev.cq_rx.used_id(new_used) as u16;
        dev.cq_rx.last_used = new_used;

        if len >= 8 {
            let slot = dev.cq_rx.scratch_virt().add((id_desc as usize) * CTRL_BUF_LEN);
            let port_id = (slot as *const u32).read_volatile();
            let event   = (slot.add(4) as *const u16).read_volatile();
            let value   = (slot.add(6) as *const u16).read_volatile();
            // Only log PORT_OPEN transitions — every other event (PORT_ADD,
            // PORT_NAME) fires exactly twice at init and is noise after that.
            if event == VIRTIO_CONSOLE_PORT_OPEN {
                crate::serial_println!(
                    "[VIRTIO-SERIAL] port {} {}", port_id,
                    if value != 0 { "opened (host connected)" } else { "closed (host disconnected)" }
                );
                if port_id == QGA_PORT_ID && value != 0 {
                    dev.port_opened = true;
                }
            }
        }

        // Re-publish the descriptor for the next host control message.
        let addr = dev.cq_rx.scratch_phys() + (id_desc as u64) * (CTRL_BUF_LEN as u64);
        dev.cq_rx.fill_desc(id_desc, addr, CTRL_BUF_LEN as u32, VRING_DESC_F_WRITE);
        dev.cq_rx.publish_desc(id_desc);
        hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 2);
        drained += 1;
    }
}

// ── IRQ Wiring ──────────────────────────────────────────────────────────────

/// IRQ vector reserved for virtio-serial in the IDT.  Allocated alongside
/// the other PCI INTx vectors at the top of `irq.rs`; kept in sync with
/// the `IDT[46].set_handler(...)` call in `arch/x86_64/idt.rs`.
pub const VIRTIO_SERIAL_IRQ_VECTOR: u8 = 46;

/// Route the virtio-serial legacy INTx line through the IO-APIC, disable
/// any MSI-X capability the firmware may have left armed, and flip
/// `IRQS_ARMED` so `read_blocking()` parks instead of busy-polling.
///
/// MUST be called after `apic::init()` has brought the IO-APIC up.  Safe
/// to call when no device was discovered or when invoked twice — both
/// become no-ops.  Mirrors `virtio_blk::arm_irq()` exactly so the two
/// drivers share the same legacy-INTx contract.
///
/// Per virtio 1.0 §4.1.4.5 the driver enables interrupts simply by
/// leaving the device's line unmasked at the IO-APIC; no register write
/// to the device itself is required.  The device raises the line
/// whenever it advances `used.idx`; we ack each entry by reading
/// `ISR_STATUS` (read-to-clear) inside the ISR.
pub fn arm_irq() {
    if !VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) {
        return;
    }
    if IRQS_ARMED.load(Ordering::Acquire) {
        return;
    }
    let (irq_line, b, d, f) = {
        let guard = VIRTIO_SERIAL.lock();
        match guard.as_ref() {
            Some(dev) => (dev.pci_irq_line, dev.pci_bus, dev.pci_dev, dev.pci_func),
            None => return,
        }
    };
    if irq_line == 0 || irq_line == 0xFF {
        crate::serial_println!(
            "[VIRTIO-SERIAL] No PCI interrupt line programmed (line={:#x}); staying on poll path",
            irq_line
        );
        return;
    }

    // Clear PCI command-register bit 10 (Interrupt Disable) so the device
    // can assert legacy INTx.  Some firmware leaves it set expecting an
    // MSI/MSI-X path; we explicitly enable INTx for the legacy IO-APIC
    // route below.  PCI Local Bus Specification 3.0, §6.2.2.
    let cmd = super::pci::pci_config_read32(b, d, f, 0x04);
    super::pci::pci_config_write32(b, d, f, 0x04, cmd & !(1u32 << 10));

    // Walk the PCI capability list and disable MSI-X if present — when
    // MSI-X enable=1 the device routes interrupts via MSI-X messages and
    // ignores its INTx pin entirely (PCI 3.0 §6.8.2.3).  QEMU's
    // `virtio-serial-pci` exposes MSI-X by default; forcing it off
    // restores the legacy INTx path that this driver uses.
    disable_msix(b, d, f);

    // Route the GSI through the IO-APIC.  PCI INTx is level-triggered,
    // active-low — use the level helper.
    let bsp_id = crate::arch::x86_64::apic::bsp_apic_id();
    crate::arch::x86_64::apic::ioapic_route_irq_level(irq_line, VIRTIO_SERIAL_IRQ_VECTOR, bsp_id);

    // Drain any stale ISR bit so the first real completion isn't masked
    // behind a left-over assertion from QEMU's device init.
    let io_base_snap = IRQ_IO_BASE.load(Ordering::Acquire);
    if io_base_snap != 0 {
        // SAFETY: ISR status is read-to-clear; no side effects beyond
        // clearing latched bits and de-asserting the level line.
        unsafe {
            let _ = crate::hal::inb(io_base_snap + VIRTIO_REG_ISR_STATUS);
        }
    }

    IRQS_ARMED.store(true, Ordering::Release);
    crate::serial_println!(
        "[VIRTIO-SERIAL] IRQ armed: PCI {:02x}:{:02x}.{} line={} -> vector {} (BSP APIC {})",
        b, d, f, irq_line, VIRTIO_SERIAL_IRQ_VECTOR, bsp_id
    );

    // Kick the QGA rx queue (vq4) once now that interrupts are live.
    // QEMU's `handle_input` callback uses the kick to call
    // `qemu_chr_fe_accept_input`, which is the only path that primes
    // the chardev for the first read after a `host_connected` flip.
    // Without this, host writes that arrive after init silently sit in
    // the socket's kernel buffer until the next guest kick — the
    // exact symptom observed on PR #158's QGA-3 wedge.  See virtio 1.2
    // §5.3.7.3 for the rx-side delivery model.
    if io_base_snap != 0 {
        unsafe { crate::hal::outw(io_base_snap + VIRTIO_REG_QUEUE_NOTIFY, 4); }
    }
}

/// Walk a device's PCI capability list and disable any MSI-X capability
/// we find.  PCI 3.0 §6.7 (Capability Pointers): caps list starts at
/// config offset 0x34 if Status register bit 4 is set; each cap header is
/// two bytes — `cap_id` at +0, `next_ptr` at +1.  MSI-X cap_id = 0x11.
/// The MSI-X Message Control register lives at cap_offset+2; bit 15 of
/// that 16-bit field is "MSI-X Enable" — clear it to fall back to INTx.
fn disable_msix(bus: u8, device: u8, function: u8) {
    let status_reg = super::pci::pci_config_read32(bus, device, function, 0x04);
    let status = (status_reg >> 16) as u16;
    if status & (1 << 4) == 0 {
        return;
    }
    let cap_ptr = super::pci::pci_config_read32(bus, device, function, 0x34) & 0xFF;
    let mut off = (cap_ptr as u8) & 0xFC;
    let mut hops = 0u8;
    while off != 0 && hops < 48 {
        let dw = super::pci::pci_config_read32(bus, device, function, off);
        let cap_id = (dw & 0xFF) as u8;
        let next = ((dw >> 8) & 0xFF) as u8;
        if cap_id == 0x11 {
            let msg_ctl = ((dw >> 16) & 0xFFFF) as u16;
            if msg_ctl & (1 << 15) != 0 {
                let new_ctl = (msg_ctl & !(1u16 << 15)) as u32;
                let new_dw = (dw & 0x0000_FFFF) | (new_ctl << 16);
                super::pci::pci_config_write32(bus, device, function, off, new_dw);
                crate::serial_println!(
                    "[VIRTIO-SERIAL] Disabled MSI-X (was enabled, cap@{:#x})", off
                );
            }
            return;
        }
        off = next & 0xFC;
        hops += 1;
    }
}

/// Virtio-serial ISR.  Called from the IDT stub with interrupts disabled.
///
/// Per virtio 1.0 §4.1.4.5 the driver:
///   1. Reads `ISR_STATUS` (read-to-clear) to ack the device's INTx
///      assertion — required even on spurious entries to keep the level
///      line from re-asserting after EOI.
///   2. Drains every newly-completed rx descriptor into `rx_ring`,
///      re-priming the descriptor and notifying the device so the next
///      host write has somewhere to land.
///   3. Wakes any thread parked in `read_blocking()`.
///   4. Issues LAPIC EOI.
///
/// Lock discipline: tries `VIRTIO_SERIAL.try_lock()` — if the device
/// mutex is held by a concurrent `read()` / `write()` on another CPU,
/// the latched ISR_STATUS read still completes (so the line de-asserts)
/// and the wake is deferred to the next ISR entry.  The bounded
/// re-arm interval is one timer tick because `read_blocking()`'s wake
/// fires whenever new bytes land — a single missed wake is harmless
/// (the next host write or replenish kick re-fires the IRQ).
pub(crate) fn handle_irq() {
    TOTAL_IRQS.fetch_add(1, Ordering::Relaxed);
    let io_base = IRQ_IO_BASE.load(Ordering::Acquire);

    // 1. Acknowledge device — read ISR status (read-to-clear).
    let isr_bits = if io_base != 0 {
        // SAFETY: ISR status is a read-to-clear u8 register at +0x13.
        unsafe { crate::hal::inb(io_base + VIRTIO_REG_ISR_STATUS) }
    } else { 0 };

    // 2. Drain newly-completed rx descriptors AND control-rx events.
    let mut woke_any = false;
    if let Some(guard) = VIRTIO_SERIAL.try_lock() {
        let mut g = guard;
        if let Some(dev) = g.as_mut() {
            // Drain control-queue events first — PORT_OPEN handshake
            // completion may flip `port_opened` which the data path
            // queries.
            // SAFETY: we hold the device mutex.
            unsafe { pump_control_rx(dev); }
            // SAFETY: walking our owned virtqueue memory.
            loop {
                let cur_used = unsafe { dev.rxq.used_idx() };
                if cur_used == dev.rxq.last_used {
                    break;
                }
                let new_used = dev.rxq.last_used.wrapping_add(1);
                // SAFETY: device wrote this many bytes into our scratch.
                let len = unsafe { dev.rxq.used_len(new_used) } as usize;
                let len = len.min(SCRATCH_BUF_LEN);
                // Copy into the ring; drop overflow (counted).
                let room = RX_RING_CAP.saturating_sub(dev.rx_ring.len());
                let take = len.min(room);
                if take < len {
                    RX_DROPPED_BYTES.fetch_add((len - take) as u64, Ordering::Relaxed);
                }
                // SAFETY: scratch_virt..+take is within our owned buffer.
                unsafe {
                    let src = dev.rxq.scratch_virt();
                    for i in 0..take {
                        dev.rx_ring.push_back(src.add(i).read_volatile());
                    }
                }
                dev.rxq.last_used = new_used;
                woke_any = true;
                // Re-publish the descriptor for the next host write.
                // SAFETY: we hold the device mutex.
                unsafe {
                    replenish_rx(&mut dev.rxq);
                    crate::hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 4);
                }
            }
        }
    } else if isr_bits != 0 {
        // Mutex contended — count and ack only.  The next read()/timer
        // tick will catch the missed descriptor.
        SPURIOUS_IRQS.fetch_add(1, Ordering::Relaxed);
    }

    // 3. Wake parked readers if we deposited bytes.
    if woke_any {
        let drained = RX_WAITERS.lock().drain_all();
        wake_tids(&drained);
        ring_poll_bell();
    }

    // 4. EOI.
    if crate::arch::x86_64::apic::is_enabled() {
        crate::arch::x86_64::apic::lapic_eoi();
    } else {
        // SAFETY: PIC fallback path; we never see this on KVM but keep
        // parity with the virtio-blk handler so a PIC-only smoke test
        // doesn't surprise us.
        unsafe {
            crate::arch::x86_64::irq::send_eoi(
                VIRTIO_SERIAL_IRQ_VECTOR.saturating_sub(32),
            );
        }
    }
}

// ── Read / Write API ────────────────────────────────────────────────────────

/// Read up to `out.len()` bytes from the rx queue.  Non-blocking — returns
/// zero immediately when no data is available.
///
/// In steady state (post-`arm_irq()`) bytes are deposited into `rx_ring`
/// by the ISR and this call drains the ring under the device mutex.
/// During early boot — before `arm_irq()` has registered the IO-APIC
/// route — the call falls back to walking the virtqueue itself; that
/// path matches the pre-IRQ behaviour required by the QGA-2 loopback
/// test (`test_inject_rx` → `read`).
///
/// **Wedge fix (PR following #158)**: when the call would otherwise
/// return 0, it issues a single `QUEUE_NOTIFY` to re-arm QEMU's chardev
/// poll.  Per virtio-serial-bus semantics, QEMU only re-primes
/// `qemu_chr_fe_accept_input` on a guest kick of vq0; host-side
/// connections that arrive after init therefore stay invisible to the
/// device until the first such kick.  Issuing the notify on every empty
/// read is cheap (one I/O port write) and self-throttling — the daemon
/// only polls when no data is in flight.
pub fn read(out: &mut [u8]) -> usize {
    if !VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) || out.is_empty() {
        return 0;
    }
    let mut guard = VIRTIO_SERIAL.lock();
    let dev = match guard.as_mut() {
        Some(d) => d,
        None => return 0,
    };

    // Drain any pending control-queue events first.  In test-mode boots
    // `arm_irq()` is never called, so the ISR-driven pump never fires —
    // doing it here on every read keeps the multiport handshake live
    // for both the loopback test and the early-boot real-host path.
    // SAFETY: we hold the device mutex.
    unsafe { pump_control_rx(dev); }

    // Fast path — ISR has already deposited bytes into the ring.
    if !dev.rx_ring.is_empty() {
        let n = drain_rx_ring(dev, out);
        if n > 0 { return n; }
    }

    // Polling fallback — also taken in steady state if IRQs are armed.
    // The ISR may have missed deposits if the device mutex was contended,
    // and bytes that landed via the device's `virtio_notify` between two
    // ISR entries are still recoverable by walking the used ring here.
    // SAFETY: reading our owned virtqueue memory.
    if dev.rx_avail == 0 {
        // SAFETY: reading our owned virtqueue memory.
        let cur_used = unsafe { dev.rxq.used_idx() };
        if cur_used == dev.rxq.last_used {
            // Same wedge fix on the polling path — many test boots run
            // long before `arm_irq()` fires (test runner reads before
            // APIC init); we want host writes to flush in either case.
            // SAFETY: doorbell write to our device.
            unsafe { hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 4); }
            return 0;
        }
        let new_used = dev.rxq.last_used.wrapping_add(1);
        // SAFETY: device has written this many bytes into our scratch buffer.
        let len = unsafe { dev.rxq.used_len(new_used) };
        dev.rxq.last_used = new_used;
        dev.rx_avail = core::cmp::min(len, SCRATCH_BUF_LEN as u32);
        dev.rx_consumed = 0;
    }

    let remaining = (dev.rx_avail - dev.rx_consumed) as usize;
    let n = core::cmp::min(remaining, out.len());
    // SAFETY: scratch_virt + rx_consumed .. + n is within our owned buffer.
    unsafe {
        let src = dev.rxq.scratch_virt().add(dev.rx_consumed as usize);
        core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), n);
    }
    dev.rx_consumed += n as u32;

    if dev.rx_consumed >= dev.rx_avail {
        dev.rx_avail = 0;
        dev.rx_consumed = 0;
        // SAFETY: replenish + notify; we hold the device mutex.
        unsafe {
            replenish_rx(&mut dev.rxq);
            hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 4);
        }
    }

    n
}

/// Drain bytes from the ISR-filled ring into `out`.  Assumes the caller
/// holds the device mutex.  Returns the number of bytes copied.
fn drain_rx_ring(dev: &mut VirtioSerialDevice, out: &mut [u8]) -> usize {
    let mut n = 0;
    while n < out.len() {
        match dev.rx_ring.pop_front() {
            Some(b) => { out[n] = b; n += 1; }
            None => break,
        }
    }
    n
}

/// Blocking variant of [`read`].  Parks the caller on `RX_WAITERS` until
/// the ISR deposits bytes, then returns the same way as `read`.  Used by
/// the VFS layer for `/dev/vport0p0` opens that are NOT `O_NONBLOCK`.
///
/// Returns 0 only when the device is unavailable; otherwise blocks until
/// at least one byte is delivered.  This is the semantics POSIX
/// `read(2)` on a blocking fd specifies — no partial-success path is
/// needed because the caller already framed the request.
pub fn read_blocking(out: &mut [u8]) -> usize {
    if !VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) || out.is_empty() {
        return 0;
    }
    loop {
        let n = read(out);
        if n > 0 {
            return n;
        }
        // Before parking, kick the QGA rx queue (vq4) once more so that
        // any data that landed while we held the mutex during the prior
        // read attempt is observed by the ISR before we go to sleep.
        // This closes the lost-wakeup window between the ring-empty
        // check and the enqueue; symmetric with the futex
        // `check-then-enqueue-under-lock` pattern in
        // `subsys/linux/syscall.rs::futex_wait_check_and_enqueue`.
        {
            let guard = VIRTIO_SERIAL.lock();
            if let Some(dev) = guard.as_ref() {
                // SAFETY: doorbell write to our device's notify port.
                unsafe { hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 4); }
            }
        }
        // Re-check after the kick; QEMU may have delivered bytes by the
        // time we get the device mutex below.
        let n = read(out);
        if n > 0 {
            return n;
        }
        // Decide whether to park or just yield-poll.  We park (block via
        // WaitList) only when there is concrete evidence the ISR path is
        // delivering wake-ups — i.e. `TOTAL_IRQS > 0`.  In test-mode
        // boots `test_inject_rx` bumps `used.idx` synthetically without
        // firing the IRQ, so a parked thread would never be woken until
        // the 10-tick safety floor expires (which doesn't advance under
        // a tight `yield_cpu` loop — yields don't tick the clock).  The
        // yield path keeps the QGA-2 loopback test working without
        // hurting the real-boot path: once a real IRQ has fired we
        // commit to the WaitList wake source.
        let irqs_seen = TOTAL_IRQS.load(Ordering::Relaxed);
        if !IRQS_ARMED.load(Ordering::Acquire) || irqs_seen == 0 {
            // Cooperative yield — gives the producer (host write,
            // test_inject_rx caller) a quantum to make progress; we
            // recheck on next loop iteration.
            crate::sched::yield_cpu();
            continue;
        }
        // Park ourselves on the wait list.  Wake source is the ISR's
        // `wake_tids` call after it deposits into `rx_ring`; a 10-tick
        // ceiling matches the global poll-bell resync interval so a
        // hypothetical missed wake recovers within 100 ms.
        let tid = crate::proc::current_tid();
        let now = crate::arch::x86_64::irq::get_ticks();
        let wake_tick = now.saturating_add(10);
        {
            let mut wl = RX_WAITERS.lock();
            wl.enqueue_self_blocked(tid, wake_tick);
        }
        crate::sched::schedule();
        // Drop any stale entry — we may have been woken via the
        // scheduler tick rather than via the ISR's `wake_tids`.
        RX_WAITERS.lock().remove_tid(tid);
    }
}


/// Send up to `data.len()` bytes through the tx queue.  Returns the number
/// of bytes accepted by the device; capped at the scratch buffer length
/// for larger writes.  Spins on the used ring for completion.
pub fn write(data: &[u8]) -> usize {
    if !VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) || data.is_empty() {
        return 0;
    }
    let mut guard = VIRTIO_SERIAL.lock();
    let dev = match guard.as_mut() {
        Some(d) => d,
        None => return 0,
    };

    let n = core::cmp::min(data.len(), SCRATCH_BUF_LEN);

    // SAFETY: scratch buffer is owned by us; we hold the device mutex.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), dev.txq.scratch_virt(), n);
        dev.txq.fill_desc0(dev.txq.scratch_phys(), n as u32, 0); // device reads
        dev.txq.publish_desc0();
        // Notify vq5 — port 1's TX queue under MULTIPORT layout.
        hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 5);
    }

    // Spin until the device retires our descriptor.  Bounded so a wedged
    // hypervisor doesn't hang the kernel — at QGA cadence the loop
    // typically exits in a few thousand iterations.
    let mut budget: u32 = 10_000_000;
    let expected = dev.txq.next_avail;
    loop {
        // SAFETY: read our virtqueue memory.
        let cur = unsafe { dev.txq.used_idx() };
        if cur == expected {
            dev.txq.last_used = cur;
            break;
        }
        budget = match budget.checked_sub(1) {
            Some(b) => b,
            None => {
                crate::serial_println!("[VIRTIO-SERIAL] write: device wedged, giving up");
                return 0;
            }
        };
        core::hint::spin_loop();
    }
    n
}

/// Whether the rx queue has data ready to be consumed without blocking.
pub fn has_data() -> bool {
    if !VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) {
        return false;
    }
    let guard = VIRTIO_SERIAL.lock();
    let dev = match guard.as_ref() {
        Some(d) => d,
        None => return false,
    };
    if !dev.rx_ring.is_empty() {
        return true;
    }
    if dev.rx_avail > dev.rx_consumed {
        return true;
    }
    // SAFETY: reading the device-published used.idx of our owned queue.
    let cur = unsafe { dev.rxq.used_idx() };
    cur != dev.rxq.last_used
}

/// Whether `init` discovered and brought up a virtio-serial device.
pub fn is_available() -> bool {
    VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire)
}

// ── Diagnostics ─────────────────────────────────────────────────────────────

/// Snapshot of internal counters for tests / kdb.
pub struct Stats {
    pub rx_last_used: u16,
    pub tx_last_used: u16,
    pub rx_next_avail: u16,
    pub tx_next_avail: u16,
    /// Bytes the ISR has deposited into `rx_ring` but the daemon has not
    /// yet drained.  Steady-state hover around 0; spikes indicate the
    /// userspace reader is throughput-bound.
    pub rx_ring_pending: usize,
    /// Total IRQ entries since boot.  Zero post-boot means the IO-APIC
    /// route never bound (likely an MSI-X residue) — `arm_irq()`
    /// disables MSI-X but a misbehaving firmware may re-enable it.
    pub total_irqs: u64,
    /// Bytes the ISR dropped because `rx_ring` was full.
    pub rx_dropped_bytes: u64,
    /// True once the host has signalled `VIRTIO_CONSOLE_PORT_OPEN(1)` on
    /// the QGA port via the control queue.  Indicates the chardev socket
    /// has a peer connected and the data path is authorised.
    pub port_opened: bool,
}

pub fn stats() -> Option<Stats> {
    let guard = VIRTIO_SERIAL.lock();
    guard.as_ref().map(|d| Stats {
        rx_last_used: d.rxq.last_used,
        tx_last_used: d.txq.last_used,
        rx_next_avail: d.rxq.next_avail,
        tx_next_avail: d.txq.next_avail,
        rx_ring_pending: d.rx_ring.len(),
        total_irqs: TOTAL_IRQS.load(Ordering::Relaxed),
        rx_dropped_bytes: RX_DROPPED_BYTES.load(Ordering::Relaxed),
        port_opened: d.port_opened,
    })
}

/// Diagnostic counter — number of times the ISR raced the device mutex
/// and had to ack-only.  Surfaced to `kdb` for the QGA wiring tests.
pub fn spurious_irq_count() -> u64 {
    SPURIOUS_IRQS.load(Ordering::Relaxed)
}

// ── Loopback test helpers (Phase QGA-2) ─────────────────────────────────────
//
// In a normal boot the host drives both ends of the virtio-serial pair: it
// sends QGA frames into the rx queue (which becomes guest-visible) and
// consumes the daemon's replies from the tx queue.  In `test-mode` boots no
// host is present, so the test runner needs a way to forge a host into the
// loop: push bytes into rx so the daemon's `read()` returns them, and pull
// bytes from tx so the daemon's `write()` completes.
//
// These helpers manipulate the same virtqueue memory the device would
// touch.  They run only from kernel test code (no syscall surface) and
// only when the `qga` feature is on.  The split-ring layout we operate on
// matches §2.6 of the virtio 1.2 spec.

/// Inject `bytes` into the rx queue as if the host had written them.
///
/// Returns `false` if the device is not initialised or `bytes` is larger
/// than a single descriptor's scratch buffer (4 KiB).  Otherwise copies the
/// bytes into the rx scratch slot, bumps the used-ring length, and advances
/// `used.idx` so a subsequent `read()` consumes the data.
///
/// This helper does NOT take the device mutex — it operates on the
/// LOOPBACK snapshot of the queue's physical addresses.  That is essential
/// for the QGA-2 test: the daemon spins inside `virtio_serial::write`
/// holding the device mutex, and a peer that needs to advance used.idx
/// would otherwise deadlock waiting on the lock.
#[cfg(feature = "qga")]
pub fn test_inject_rx(bytes: &[u8]) -> bool {
    if !VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) {
        return false;
    }
    if bytes.len() > SCRATCH_BUF_LEN {
        return false;
    }
    let h = match *LOOPBACK.lock() {
        Some(h) => h,
        None => return false,
    };
    // SAFETY: the queue physical pages were allocated in init() and never
    // freed; we have a stable virtual mapping via phys_to_virt.  The bytes
    // we write here will be observed by the driver's subsequent `read()`
    // via the same memory.
    unsafe {
        let desc_virt = phys_to_virt::<u8>(h.rxq_phys);
        let scratch_virt = desc_virt.add(scratch_buf_offset(h.rxq_size));
        let avail_virt = desc_virt.add(avail_ring_offset(h.rxq_size));
        let used_virt = desc_virt.add(used_ring_offset(h.rxq_size));

        core::ptr::copy_nonoverlapping(bytes.as_ptr(), scratch_virt, bytes.len());

        let cur_used = (used_virt.add(2) as *const u16).read_volatile();
        let next_used = cur_used.wrapping_add(1);
        let slot_idx = (cur_used % h.rxq_size) as usize;
        let slot = used_virt.add(4 + slot_idx * 8);
        (slot as *mut u32).write_volatile(0); // descriptor id 0
        (slot.add(4) as *mut u32).write_volatile(bytes.len() as u32);
        core::sync::atomic::fence(Ordering::SeqCst);
        (used_virt.add(2) as *mut u16).write_volatile(next_used);
        let _ = avail_virt; // referenced for completeness; rx avail is driver-driven
    }
    LoopbackHandles::touch(); // suppress dead_code on the helper-only path
    true
}

/// Drain bytes from the tx queue's scratch buffer, capturing whatever the
/// daemon most recently wrote to `/dev/vport0p0`.  Returns `Some(n)` with
/// the number of bytes copied when there is a new descriptor since the
/// caller's `last_avail` watermark; `None` otherwise.  Also returns the
/// new watermark so the caller can poll without observing the same
/// descriptor twice.
///
/// Unlike a normal host-side virtio consumer, this helper does NOT bump
/// `used.idx` — that is done by QEMU's emulated device whenever bytes
/// pass through the chardev to the host socket.  In test mode the host
/// socket may have a peer (real harness) or no peer at all; either way
/// the scratch buffer holds the most recently published payload.
///
/// Like `test_inject_rx`, this helper deliberately bypasses the device
/// mutex (see that function's doc comment for the rationale).
#[cfg(feature = "qga")]
pub fn test_drain_tx(out: &mut [u8], last_avail: u16) -> (usize, u16) {
    if !VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) || out.is_empty() {
        return (0, last_avail);
    }
    let h = match *LOOPBACK.lock() {
        Some(h) => h,
        None => return (0, last_avail),
    };
    // SAFETY: see `test_inject_rx`.  We observe the daemon's tx state
    // through volatile reads of the queue memory.
    unsafe {
        let desc_virt = phys_to_virt::<u8>(h.txq_phys);
        let scratch_virt = desc_virt.add(scratch_buf_offset(h.txq_size));
        let avail_virt = desc_virt.add(avail_ring_offset(h.txq_size));

        let avail_idx = (avail_virt.add(2) as *const u16).read_volatile();
        if avail_idx == last_avail {
            return (0, last_avail);
        }
        // Descriptor 0 carries (addr, len, flags) for the daemon's write.
        let len = (desc_virt.add(8) as *const u32).read_volatile() as usize;
        let n = core::cmp::min(len, out.len());
        core::ptr::copy_nonoverlapping(scratch_virt, out.as_mut_ptr(), n);
        (n, avail_idx)
    }
}

#[cfg(feature = "qga")]
impl LoopbackHandles {
    #[inline(always)]
    fn touch() {}
}
