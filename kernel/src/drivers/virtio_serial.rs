//! Virtio-serial PCI Driver (Legacy Interface) — Phase QGA-1
//!
//! Exposes a single byte-stream character device at `/dev/vport0p0` backed by
//! a virtio-serial (virtio-console) port.  This is the kernel half of the
//! QEMU Guest Agent (QGA) transport: a userspace daemon (Phase QGA-2) will
//! open the device node and run the QGA JSON-RPC loop against the host.
//!
//! # Scope (QGA-1 only)
//!
//! * Legacy PCI virtio (vendor `0x1AF4`, device `0x1003`, subsystem id `3`).
//! * Two virtqueues:
//!   - vq0 (port 0 receive — host → guest writes data here).
//!   - vq1 (port 0 transmit — guest → host).
//! * Feature negotiation accepts **no** features.  In particular we do NOT
//!   negotiate `VIRTIO_CONSOLE_F_MULTIPORT`, so the device skips the control
//!   queue handshake entirely and port 0 is the only port that ever carries
//!   data.  QEMU still routes a single `virtserialport,name=org.qemu.guest_agent.0`
//!   to that port regardless of the name string — naming only matters once
//!   multiport is on.
//! * Polling-mode I/O.  The byte path is exercised by a userspace daemon at
//!   human timescales (QGA frames arrive at request/response cadence, not at
//!   block-I/O throughput), so the spin cost is acceptable until Phase QGA-4
//!   promotes the rx path to interrupt-driven completion.
//!
//! # References
//!
//! * Virtio 1.2 spec, §5.3 (Console Device).
//! * Virtio 1.0 legacy PCI device init: §4.1.4.
//! * Virtqueue split-ring layout: §2.6.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Mutex;

use crate::hal;
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
        let d = self.desc();
        (d as *mut u64).write_volatile(addr);
        (d.add(8) as *mut u32).write_volatile(len);
        (d.add(12) as *mut u16).write_volatile(flags & !VRING_DESC_F_NEXT);
        (d.add(14) as *mut u16).write_volatile(0);
    }

    /// Publish descriptor 0 into the available ring.
    /// SAFETY: caller must hold the device mutex.
    unsafe fn publish_desc0(&mut self) {
        let avail = self.avail();
        let entry = avail.add(4 + ((self.next_avail % self.queue_size) as usize) * 2) as *mut u16;
        entry.write_volatile(0);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.next_avail = self.next_avail.wrapping_add(1);
        let avail_idx = avail.add(2) as *mut u16;
        avail_idx.write_volatile(self.next_avail);
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
    rxq: VirtQueue,
    txq: VirtQueue,
    /// Bytes already consumed from the currently active rx descriptor.
    rx_consumed: u32,
    /// Total bytes available in the currently active rx descriptor.
    rx_avail: u32,
}

static VIRTIO_SERIAL: Mutex<Option<VirtioSerialDevice>> = Mutex::new(None);
static VIRTIO_SERIAL_AVAILABLE: AtomicBool = AtomicBool::new(false);

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

/// IRQ vector reserved for Phase QGA-1b.  Vectors 32-45 are taken by timer,
/// keyboard, e1000, mouse, virtio-blk; pick the next free slot.
#[allow(dead_code)]
pub const VIRTIO_SERIAL_IRQ_VECTOR: u8 = 46;

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
    let (rxq, txq) = unsafe {
        // Reset → ACK → DRIVER per §4.1.4.1.
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );

        // Read offered features, accept none.  We deliberately do NOT
        // negotiate VIRTIO_CONSOLE_F_MULTIPORT (bit 1) — without it the
        // device exposes only vq0 (port 0 rx) and vq1 (port 0 tx) and
        // skips the control queue handshake entirely (§5.3.6).
        let _offered = hal::inl(io_base + VIRTIO_REG_DEVICE_FEATURES);
        hal::outl(io_base + VIRTIO_REG_GUEST_FEATURES, 0);

        let rxq = match setup_queue(io_base, 0) {
            Some(q) => q,
            None => {
                hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
                return false;
            }
        };
        let txq = match setup_queue(io_base, 1) {
            Some(q) => q,
            None => {
                hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
                return false;
            }
        };

        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
        );
        (rxq, txq)
    };

    crate::serial_println!(
        "[VIRTIO-SERIAL] Initialized: io={:#06x}, rxq_size={}, txq_size={}, rxq_phys={:#x}, txq_phys={:#x}",
        io_base, rxq.queue_size, txq.queue_size, rxq.phys, txq.phys
    );

    let mut dev = VirtioSerialDevice {
        io_base,
        rxq,
        txq,
        rx_consumed: 0,
        rx_avail: 0,
    };

    // Prime the rx ring with one empty buffer so the device has somewhere
    // to write the first host-originated bytes.  Notify after publishing.
    // SAFETY: dev is locally owned at this point.
    unsafe {
        replenish_rx(&mut dev.rxq);
        hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, 0);
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

    *VIRTIO_SERIAL.lock() = Some(dev);
    VIRTIO_SERIAL_AVAILABLE.store(true, Ordering::Release);
    true
}

// ── Read / Write API ────────────────────────────────────────────────────────

/// Read up to `out.len()` bytes from the rx queue.  Returns the number of
/// bytes copied.  Zero on no data available (non-blocking semantics).
///
/// Bytes from a single device-written descriptor are streamed out across
/// multiple `read()` calls — the driver remembers how many bytes have been
/// consumed from the active rx descriptor and replenishes only once it is
/// fully drained.
pub fn read(out: &mut [u8]) -> usize {
    if !VIRTIO_SERIAL_AVAILABLE.load(Ordering::Acquire) || out.is_empty() {
        return 0;
    }
    let mut guard = VIRTIO_SERIAL.lock();
    let dev = match guard.as_mut() {
        Some(d) => d,
        None => return 0,
    };

    if dev.rx_avail == 0 {
        // SAFETY: reading our owned virtqueue memory.
        let cur_used = unsafe { dev.rxq.used_idx() };
        if cur_used == dev.rxq.last_used {
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
            hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 0);
        }
    }

    n
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
        hal::outw(dev.io_base + VIRTIO_REG_QUEUE_NOTIFY, 1);
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
}

pub fn stats() -> Option<Stats> {
    let guard = VIRTIO_SERIAL.lock();
    guard.as_ref().map(|d| Stats {
        rx_last_used: d.rxq.last_used,
        tx_last_used: d.txq.last_used,
        rx_next_avail: d.rxq.next_avail,
        tx_next_avail: d.txq.next_avail,
    })
}

// Anchor for the QGA-1b IRQ path so a follow-up PR can land its atomics
// import without rewriting the use block.
#[allow(dead_code)]
fn _atomic_u16_anchor() -> AtomicU16 { AtomicU16::new(0) }

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
