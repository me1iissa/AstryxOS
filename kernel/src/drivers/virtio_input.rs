//! Virtio-input PCI Driver (Modern / virtio-1.0 transport) — absolute pointer
//!
//! Brings up a **virtio-input** device (QEMU `-device virtio-tablet-pci`,
//! `virtio-mouse-pci`, …) and feeds its pointer events into the kernel mouse
//! state so the in-kernel X11 server / GUI compositor cursor tracks an
//! absolute pointing device.  This is what a VNC client needs: VNC delivers
//! *absolute* pointer coordinates, and a virtio-tablet exposes exactly that
//! (`EV_ABS`/`ABS_X`/`ABS_Y`), unlike the relative-only PS/2 mouse.
//!
//! # Why a new transport
//!
//! virtio-input has no legacy/transitional PCI device id — it is a
//! **modern-only** device (PCI device id 0x1052 = 0x1040 + VIRTIO_ID_INPUT(18)).
//! The existing `virtio_blk` / `virtio_serial` / `virtio_net` drivers all use
//! the legacy BAR0 port-I/O register window, which a modern-only device does
//! not provide.  This driver therefore implements the small slice of the
//! **virtio 1.x modern PCI transport** that an input device needs:
//!
//!   * Walk the PCI capability list for the vendor-specific virtio caps
//!     (`VIRTIO_PCI_CAP_COMMON_CFG`/`NOTIFY_CFG`/`ISR_CFG`/`DEVICE_CFG`),
//!     each of which names a BAR + offset + length (virtio 1.2 §4.1.4).
//!   * Map those MMIO windows uncached (mirrors `apic::init`'s LAPIC map).
//!   * Drive the common-config register block (device/driver feature select,
//!     status, per-queue desc/avail/used addresses) (virtio 1.2 §4.1.4.3).
//!   * Set up one split virtqueue — the **event queue** (queue 0) — filled
//!     with device-writable 8-byte `virtio_input_event` buffers
//!     (virtio 1.2 §5.8: Input Device).
//!
//! # Event flow (polled)
//!
//! The device writes Linux-evdev `input_event` records (type/code/value, all
//! little-endian) into the event queue as the host pointer moves.  We drain
//! the used ring from [`poll`], which the GUI input pump calls once per tick
//! (`gui::input::pump_input`).  Polling at the compositor cadence (~50 Hz) is
//! ample for a cursor and keeps the driver free of IRQ-vector wiring for this
//! first cut; the device's INTx line is simply left unused.
//!
//! Accumulated `EV_ABS` (ABS_X/ABS_Y) and `EV_KEY` (BTN_LEFT/RIGHT/MIDDLE)
//! state is committed to [`crate::drivers::mouse`] on each `EV_SYN`/SYN_REPORT,
//! scaling the device's absolute axis range onto the framebuffer.
//!
//! # References
//!
//! * Virtio 1.2 spec §4.1.4 (Modern PCI device layout & capabilities),
//!   §4.1.5 (device initialization), §2.7 (split virtqueues), §5.8 (Input
//!   Device): config selects `VIRTIO_INPUT_CFG_*`, `virtio_input_event`,
//!   `virtio_input_absinfo`.
//! * Linux evdev event codes (`EV_ABS`, `ABS_X`/`ABS_Y`, `EV_KEY`,
//!   `BTN_LEFT`/`BTN_RIGHT`/`BTN_MIDDLE`, `EV_SYN`/`SYN_REPORT`) —
//!   `input-event-codes.h` UAPI (public, BSD-licensed).

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::mm::pmm;

// ── PCI identity ────────────────────────────────────────────────────────────

/// Red Hat / Virtio vendor id.
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Modern virtio-input PCI device id (0x1040 + VIRTIO_ID_INPUT(18)).  There is
/// no legacy/transitional id for input devices.
const VIRTIO_INPUT_DEVICE_ID: u16 = 0x1052;

// ── Modern PCI virtio capability (virtio 1.2 §4.1.4) ────────────────────────
//
// Vendor-specific capability (PCI cap id 0x09).  Byte layout from cap start:
//   +0 cap_vndr (0x09)  +1 cap_next  +2 cap_len  +3 cfg_type
//   +4 bar              +5 id        +6..7 pad
//   +8 offset (le32)    +12 length (le32)
//   +16 notify_off_multiplier (le32, NOTIFY_CFG only)

const PCI_CAP_ID_VNDR: u8 = 0x09;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
#[allow(dead_code)]
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

// ── Common-config register offsets (virtio 1.2 §4.1.4.3) ────────────────────

const CFG_DEVICE_FEATURE_SELECT: usize = 0x00; // u32
const CFG_DEVICE_FEATURE: usize = 0x04; // u32 (RO)
const CFG_DRIVER_FEATURE_SELECT: usize = 0x08; // u32
const CFG_DRIVER_FEATURE: usize = 0x0C; // u32
const CFG_DEVICE_STATUS: usize = 0x14; // u8
const CFG_QUEUE_SELECT: usize = 0x16; // u16
const CFG_QUEUE_SIZE: usize = 0x18; // u16
const CFG_QUEUE_ENABLE: usize = 0x1C; // u16
const CFG_QUEUE_NOTIFY_OFF: usize = 0x1E; // u16
const CFG_QUEUE_DESC_LO: usize = 0x20; // u32
const CFG_QUEUE_DESC_HI: usize = 0x24;
const CFG_QUEUE_AVAIL_LO: usize = 0x28;
const CFG_QUEUE_AVAIL_HI: usize = 0x2C;
const CFG_QUEUE_USED_LO: usize = 0x30;
const CFG_QUEUE_USED_HI: usize = 0x34;

// ── Device status bits (virtio 1.2 §2.1) ────────────────────────────────────

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 0x80;

/// VIRTIO_F_VERSION_1 (feature bit 32 → select word 1, bit 0).
const VIRTIO_F_VERSION_1_BIT: u32 = 0; // bit 0 of feature word 1

// ── virtio-input config selects (virtio 1.2 §5.8.5) ─────────────────────────

const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;

// ── Linux evdev event types/codes (input-event-codes.h, public UAPI) ────────

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;

const SYN_REPORT: u16 = 0x00;

const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;

const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;

// ── Split-virtqueue descriptor flags (virtio 1.2 §2.7.5) ────────────────────

const VRING_DESC_F_WRITE: u16 = 2;

/// Avail-ring flag: ask the device not to interrupt on used-buffer
/// notification (virtio 1.2 §2.7.6).  We poll the event queue, so we never
/// want the device to assert its INTx line.
const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;

// ── Higher-half mapping ─────────────────────────────────────────────────────

const PHYS_OFFSET: u64 = astryx_shared::KERNEL_VIRT_BASE;

#[inline]
fn phys_to_virt<T>(phys: u64) -> *mut T {
    (PHYS_OFFSET + phys) as *mut T
}

/// Map an MMIO physical range uncached into the higher-half and return a
/// pointer to its base.  Mirrors `apic::init`'s LAPIC mapping: MMIO pages are
/// PRESENT|WRITABLE|NO_CACHE|WRITE_THROUGH|GLOBAL and must NOT set NX.
fn map_mmio(phys: u64, len: u32) -> *mut u8 {
    use crate::mm::vmm::{
        PAGE_GLOBAL, PAGE_NO_CACHE, PAGE_PRESENT, PAGE_WRITABLE, PAGE_WRITE_THROUGH,
    };
    let flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_CACHE | PAGE_WRITE_THROUGH | PAGE_GLOBAL;
    let start = phys & !0xFFF;
    let end = (phys + len as u64 + 0xFFF) & !0xFFF;
    let mut p = start;
    while p < end {
        crate::mm::vmm::map_page(PHYS_OFFSET + p, p, flags);
        p += 0x1000;
    }
    (PHYS_OFFSET + phys) as *mut u8
}

// ── Volatile MMIO accessors ─────────────────────────────────────────────────

#[inline]
unsafe fn r8(base: *mut u8, off: usize) -> u8 {
    base.add(off).read_volatile()
}
#[inline]
unsafe fn r16(base: *mut u8, off: usize) -> u16 {
    (base.add(off) as *mut u16).read_volatile()
}
#[inline]
unsafe fn r32(base: *mut u8, off: usize) -> u32 {
    (base.add(off) as *mut u32).read_volatile()
}
#[inline]
unsafe fn w8(base: *mut u8, off: usize, v: u8) {
    base.add(off).write_volatile(v);
}
#[inline]
unsafe fn w16(base: *mut u8, off: usize, v: u16) {
    (base.add(off) as *mut u16).write_volatile(v);
}
#[inline]
unsafe fn w32(base: *mut u8, off: usize, v: u32) {
    (base.add(off) as *mut u32).write_volatile(v);
}

// ── Virtqueue layout (split ring, virtio 1.2 §2.7) ──────────────────────────
//
// Single contiguous allocation:
//   desc  @ 0                       16 * qs
//   avail @ desc_end (2-aligned)    6 + 2*qs
//   used  @ next page boundary      6 + 8*qs
//   evbuf @ next page boundary      qs * 8  (one virtio_input_event each)

#[inline]
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

struct EventQueue {
    qs: u16,
    base_phys: u64,
    desc_off: usize,
    avail_off: usize,
    used_off: usize,
    evbuf_off: usize,
    /// Last used-ring index we have consumed.
    last_used: u16,
    /// Running available-ring index.
    next_avail: u16,
}

impl EventQueue {
    fn desc_phys(&self) -> u64 {
        self.base_phys + self.desc_off as u64
    }
    fn avail_phys(&self) -> u64 {
        self.base_phys + self.avail_off as u64
    }
    fn used_phys(&self) -> u64 {
        self.base_phys + self.used_off as u64
    }
    fn desc(&self) -> *mut u8 {
        phys_to_virt::<u8>(self.desc_phys())
    }
    fn avail(&self) -> *mut u8 {
        phys_to_virt::<u8>(self.avail_phys())
    }
    fn used(&self) -> *mut u8 {
        phys_to_virt::<u8>(self.used_phys())
    }
    fn evbuf_phys(&self, idx: u16) -> u64 {
        self.base_phys + self.evbuf_off as u64 + (idx as u64) * 8
    }
    fn evbuf(&self, idx: u16) -> *mut u8 {
        phys_to_virt::<u8>(self.evbuf_phys(idx))
    }

    /// Program descriptor `idx` to point at its event buffer (device-writable).
    /// SAFETY: caller owns the queue memory.
    unsafe fn fill_desc(&self, idx: u16) {
        let d = self.desc().add((idx as usize) * 16);
        (d as *mut u64).write_volatile(self.evbuf_phys(idx)); // addr
        (d.add(8) as *mut u32).write_volatile(8); // len
        (d.add(12) as *mut u16).write_volatile(VRING_DESC_F_WRITE); // flags
        (d.add(14) as *mut u16).write_volatile(0); // next
    }

    /// Publish descriptor `idx` into the available ring (bump avail.idx).
    /// SAFETY: caller owns the queue memory.
    unsafe fn publish(&mut self, idx: u16) {
        let avail = self.avail();
        // ring[] starts at +4 (flags u16, idx u16).
        let slot = avail.add(4 + ((self.next_avail % self.qs) as usize) * 2) as *mut u16;
        slot.write_volatile(idx);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.next_avail = self.next_avail.wrapping_add(1);
        (avail.add(2) as *mut u16).write_volatile(self.next_avail); // avail.idx
    }

    /// Current device-published used-ring index.
    /// SAFETY: caller owns the queue memory.
    unsafe fn used_idx(&self) -> u16 {
        (self.used().add(2) as *const u16).read_volatile()
    }

    /// Descriptor id of used-ring entry `(used_idx-1)`.
    /// SAFETY: caller owns the queue memory.
    unsafe fn used_id(&self, used_idx: u16) -> u32 {
        let slot = self
            .used()
            .add(4 + ((used_idx.wrapping_sub(1) % self.qs) as usize) * 8);
        (slot as *const u32).read_volatile()
    }
}

// ── MMIO cap windows + device state ─────────────────────────────────────────

struct VirtioInput {
    /// Common-config window — retained for future reset / status / IRQ work.
    #[allow(dead_code)]
    common: *mut u8,
    notify_base: *mut u8,
    notify_mult: u32,
    /// Device-config window — retained for future config-generation re-reads.
    #[allow(dead_code)]
    device_cfg: *mut u8,
    io_notify_off: u16,
    evq: EventQueue,
    /// Absolute axis maxima (device units).  0 → device is relative-only.
    abs_max_x: u32,
    abs_max_y: u32,
    is_abs: bool,
    // Pending (uncommitted) pointer state, accumulated until SYN_REPORT.
    pend_abs_x: u32,
    pend_abs_y: u32,
    pend_rel_x: i32,
    pend_rel_y: i32,
    buttons: u8,
}

// SAFETY: the pointers reference device MMIO / DMA memory that is only ever
// touched while holding [`VIRTIO_INPUT`]'s mutex; the device is single-instance.
unsafe impl Send for VirtioInput {}

static VIRTIO_INPUT: Mutex<Option<VirtioInput>> = Mutex::new(None);
static AVAILABLE: AtomicBool = AtomicBool::new(false);

// ── PCI capability walk ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct VirtioCap {
    bar: u8,
    offset: u32,
    length: u32,
    notify_mult: u32,
}

/// Read all four virtio modern caps from the device's PCI capability list.
/// Returns `(common, notify, device)` if the required ones are present.
fn read_virtio_caps(
    bus: u8,
    dev: u8,
    func: u8,
) -> Option<(VirtioCap, VirtioCap, VirtioCap)> {
    use super::pci::pci_config_read32;
    // Capabilities present? PCI status register (0x06) bit 4.
    let status = (pci_config_read32(bus, dev, func, 0x04) >> 16) as u16;
    if status & (1 << 4) == 0 {
        return None;
    }
    let mut common: Option<VirtioCap> = None;
    let mut notify: Option<VirtioCap> = None;
    let mut device: Option<VirtioCap> = None;

    let mut off = ((pci_config_read32(bus, dev, func, 0x34) & 0xFF) as u8) & 0xFC;
    let mut hops = 0u8;
    while off != 0 && hops < 48 {
        let dw0 = pci_config_read32(bus, dev, func, off);
        let cap_id = (dw0 & 0xFF) as u8;
        let next = ((dw0 >> 8) & 0xFF) as u8;
        if cap_id == PCI_CAP_ID_VNDR {
            let cfg_type = ((dw0 >> 24) & 0xFF) as u8;
            let bar = (pci_config_read32(bus, dev, func, off + 4) & 0xFF) as u8;
            let offset = pci_config_read32(bus, dev, func, off + 8);
            let length = pci_config_read32(bus, dev, func, off + 12);
            let mut cap = VirtioCap {
                bar,
                offset,
                length,
                notify_mult: 0,
            };
            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => common = Some(cap),
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    cap.notify_mult = pci_config_read32(bus, dev, func, off + 16);
                    notify = Some(cap);
                }
                VIRTIO_PCI_CAP_DEVICE_CFG => device = Some(cap),
                _ => {}
            }
        }
        off = next & 0xFC;
        hops += 1;
    }
    match (common, notify, device) {
        (Some(c), Some(n), Some(d)) => Some((c, n, d)),
        _ => None,
    }
}

/// Resolve a BAR index to its 64-bit-aware physical base address.
fn bar_base(d: &super::pci::PciDevice, bar: u8) -> u64 {
    let i = bar as usize;
    let lo = d.bar[i];
    // Memory BAR: bit0=0; bits[2:1]=10b → 64-bit.
    if lo & 0x1 == 0 && (lo & 0x6) == 0x4 && i + 1 < 6 {
        ((d.bar[i + 1] as u64) << 32) | ((lo & 0xFFFF_FFF0) as u64)
    } else {
        (lo & 0xFFFF_FFF0) as u64
    }
}

// ── virtio-input device-config queries (virtio 1.2 §5.8.5) ──────────────────
//
// struct virtio_input_config { u8 select; u8 subsel; u8 size; u8 rsvd[5];
//                              union {..} u; }  — union starts at +8.

/// Select a config (select, subsel) and return the reported payload size.
/// SAFETY: `cfg` must point at the mapped device-config window.
unsafe fn cfg_select(cfg: *mut u8, select: u8, subsel: u8) -> u8 {
    w8(cfg, 0, select);
    w8(cfg, 1, subsel);
    r8(cfg, 2)
}

// ── Initialization ──────────────────────────────────────────────────────────

/// Probe PCI for a virtio-input pointing device and bring it up via the modern
/// transport.  Returns `true` if a pointer (tablet or mouse) was claimed.
pub fn init() -> bool {
    if AVAILABLE.load(Ordering::Acquire) {
        return true;
    }

    let devices = super::pci::devices();
    for pci in devices.iter() {
        if pci.vendor_id != VIRTIO_VENDOR || pci.device_id != VIRTIO_INPUT_DEVICE_ID {
            continue;
        }
        crate::serial_println!(
            "[VIRTIO-INPUT] candidate at PCI {:02x}:{:02x}.{} (device={:04x})",
            pci.bus,
            pci.device,
            pci.function,
            pci.device_id
        );
        if let Some(dev) = bringup(pci) {
            let kind = if dev.is_abs { "absolute (tablet)" } else { "relative (mouse)" };
            crate::serial_println!(
                "[VIRTIO-INPUT] claimed {} pointer: abs_max=({},{}) qs={}",
                kind,
                dev.abs_max_x,
                dev.abs_max_y,
                dev.evq.qs
            );
            *VIRTIO_INPUT.lock() = Some(dev);
            AVAILABLE.store(true, Ordering::Release);
            return true;
        }
    }
    false
}

/// Bring one virtio-input PCI function up to DRIVER_OK with the event queue
/// armed.  Returns the device on success, or `None` (after FAILED-status reset)
/// if it is not a pointing device or init fails.
fn bringup(pci: &super::pci::PciDevice) -> Option<VirtioInput> {
    let (common_cap, notify_cap, device_cap) = match read_virtio_caps(pci.bus, pci.device, pci.function) {
        Some(c) => c,
        None => {
            crate::serial_println!("[VIRTIO-INPUT] no modern virtio caps; skipping");
            return None;
        }
    };

    super::pci::enable_bus_master(pci.bus, pci.device, pci.function);
    // We poll the event queue; mask the device's legacy INTx by setting the PCI
    // command-register Interrupt Disable bit (bit 10).  PCI Local Bus Spec 3.0
    // §6.2.2.  Combined with VRING_AVAIL_F_NO_INTERRUPT this keeps the line
    // quiescent so no unrouted GSI is ever asserted.
    {
        let cmd = super::pci::pci_config_read32(pci.bus, pci.device, pci.function, 0x04);
        super::pci::pci_config_write32(
            pci.bus,
            pci.device,
            pci.function,
            0x04,
            cmd | (1 << 10),
        );
    }

    let common = map_mmio(
        bar_base(pci, common_cap.bar) + common_cap.offset as u64,
        common_cap.length.max(64),
    );
    let notify_base = map_mmio(
        bar_base(pci, notify_cap.bar) + notify_cap.offset as u64,
        notify_cap.length.max(4),
    );
    let device_cfg = map_mmio(
        bar_base(pci, device_cap.bar) + device_cap.offset as u64,
        device_cap.length.max(136),
    );

    unsafe {
        // 1. Reset, then ACK + DRIVER (virtio 1.2 §3.1.1).
        w8(common, CFG_DEVICE_STATUS, 0);
        // Spin until the device acknowledges the reset (status reads back 0).
        let mut budget = 100_000u32;
        while r8(common, CFG_DEVICE_STATUS) != 0 && budget > 0 {
            budget -= 1;
            core::hint::spin_loop();
        }
        w8(common, CFG_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        w8(common, CFG_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // 2. Negotiate features: we only require VIRTIO_F_VERSION_1 (bit 32).
        //    Refuse every device-specific bit — virtio-input needs none.
        w32(common, CFG_DEVICE_FEATURE_SELECT, 1);
        let feat_hi = r32(common, CFG_DEVICE_FEATURE);
        if feat_hi & (1 << VIRTIO_F_VERSION_1_BIT) == 0 {
            crate::serial_println!("[VIRTIO-INPUT] device lacks VERSION_1; aborting");
            w8(common, CFG_DEVICE_STATUS, STATUS_FAILED);
            return None;
        }
        w32(common, CFG_DRIVER_FEATURE_SELECT, 0);
        w32(common, CFG_DRIVER_FEATURE, 0);
        w32(common, CFG_DRIVER_FEATURE_SELECT, 1);
        w32(common, CFG_DRIVER_FEATURE, 1 << VIRTIO_F_VERSION_1_BIT);

        // 3. FEATURES_OK, then confirm the device kept it (virtio 1.2 §3.1.1).
        w8(common, CFG_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        if r8(common, CFG_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
            crate::serial_println!("[VIRTIO-INPUT] FEATURES_OK rejected; aborting");
            w8(common, CFG_DEVICE_STATUS, STATUS_FAILED);
            return None;
        }

        // 4. Identify the device: query EV_BITS for EV_ABS / EV_REL.  We only
        //    claim pointing devices; a keyboard (EV_KEY only) is skipped so a
        //    multi-device guest still binds the tablet here.
        let abs_bytes = cfg_select(device_cfg, VIRTIO_INPUT_CFG_EV_BITS, EV_ABS as u8);
        let rel_bytes = cfg_select(device_cfg, VIRTIO_INPUT_CFG_EV_BITS, EV_REL as u8);
        let is_abs = abs_bytes > 0;
        let is_rel = rel_bytes > 0;
        if !is_abs && !is_rel {
            crate::serial_println!("[VIRTIO-INPUT] not a pointer (no EV_ABS/EV_REL); skipping");
            w8(common, CFG_DEVICE_STATUS, STATUS_FAILED);
            return None;
        }

        // Query absolute axis maxima for coordinate scaling (virtio_input_absinfo
        // union: min@+8, max@+12).
        let mut abs_max_x = 0u32;
        let mut abs_max_y = 0u32;
        if is_abs {
            if cfg_select(device_cfg, VIRTIO_INPUT_CFG_ABS_INFO, ABS_X as u8) > 0 {
                abs_max_x = r32(device_cfg, 8 + 4);
            }
            if cfg_select(device_cfg, VIRTIO_INPUT_CFG_ABS_INFO, ABS_Y as u8) > 0 {
                abs_max_y = r32(device_cfg, 8 + 4);
            }
        }

        // 5. Set up the event queue (queue 0).
        w16(common, CFG_QUEUE_SELECT, 0);
        let qs = r16(common, CFG_QUEUE_SIZE);
        if qs == 0 {
            crate::serial_println!("[VIRTIO-INPUT] event queue size 0; aborting");
            w8(common, CFG_DEVICE_STATUS, STATUS_FAILED);
            return None;
        }
        // Cap the buffer count we manage; the device's qs is the upper bound.
        let qs = qs.min(64);
        let io_notify_off = r16(common, CFG_QUEUE_NOTIFY_OFF);

        // Allocate one contiguous region for desc/avail/used + event buffers.
        let desc_off = 0usize;
        let desc_len = (qs as usize) * 16;
        let avail_off = align_up(desc_off + desc_len, 2);
        let avail_len = 6 + (qs as usize) * 2;
        let used_off = align_up(avail_off + avail_len, 4096);
        let used_len = 6 + (qs as usize) * 8;
        let evbuf_off = align_up(used_off + used_len, 4096);
        let evbuf_len = (qs as usize) * 8;
        let total = evbuf_off + evbuf_len;
        let pages = (total + 4095) / 4096;
        let base_phys = match pmm::alloc_pages(pages) {
            Some(p) => p,
            None => {
                crate::serial_println!("[VIRTIO-INPUT] PMM alloc failed; aborting");
                w8(common, CFG_DEVICE_STATUS, STATUS_FAILED);
                return None;
            }
        };
        core::ptr::write_bytes(phys_to_virt::<u8>(base_phys), 0, total);

        let mut evq = EventQueue {
            qs,
            base_phys,
            desc_off,
            avail_off,
            used_off,
            evbuf_off,
            last_used: 0,
            next_avail: 0,
        };

        // Program queue addresses + enable (virtio 1.2 §4.1.4.3.2).  Shrink the
        // queue to our managed size (queue_size is a RW u16 — a 32-bit write
        // would clobber the adjacent queue_msix_vector field).
        w16(common, CFG_QUEUE_SIZE, qs);
        let dp = evq.desc_phys();
        let ap = evq.avail_phys();
        let up = evq.used_phys();
        w32(common, CFG_QUEUE_DESC_LO, dp as u32);
        w32(common, CFG_QUEUE_DESC_HI, (dp >> 32) as u32);
        w32(common, CFG_QUEUE_AVAIL_LO, ap as u32);
        w32(common, CFG_QUEUE_AVAIL_HI, (ap >> 32) as u32);
        w32(common, CFG_QUEUE_USED_LO, up as u32);
        w32(common, CFG_QUEUE_USED_HI, (up >> 32) as u32);
        w16(common, CFG_QUEUE_ENABLE, 1);

        // We poll the queue: tell the device not to raise interrupts.
        (evq.avail() as *mut u16).write_volatile(VRING_AVAIL_F_NO_INTERRUPT);

        // Fill the event queue with device-writable buffers.
        for i in 0..qs {
            evq.fill_desc(i);
            evq.publish(i);
        }

        // 6. DRIVER_OK, then kick the event queue so the device starts
        //    delivering (notify address = notify_base + notify_off * mult).
        w8(
            common,
            CFG_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
        let notify_addr = (io_notify_off as usize) * (notify_cap.notify_mult as usize);
        (notify_base.add(notify_addr) as *mut u16).write_volatile(0);

        Some(VirtioInput {
            common,
            notify_base,
            notify_mult: notify_cap.notify_mult,
            device_cfg,
            io_notify_off,
            evq,
            abs_max_x,
            abs_max_y,
            is_abs,
            pend_abs_x: 0,
            pend_abs_y: 0,
            pend_rel_x: 0,
            pend_rel_y: 0,
            buttons: 0,
        })
    }
}

// ── Poll path ───────────────────────────────────────────────────────────────

/// Drain the event queue and commit pointer state to [`crate::drivers::mouse`].
/// Called once per tick from the GUI input pump; a no-op until a device is
/// claimed.  Returns the number of `input_event` records processed.
pub fn poll() -> usize {
    if !AVAILABLE.load(Ordering::Acquire) {
        return 0;
    }
    let mut guard = VIRTIO_INPUT.lock();
    let dev = match guard.as_mut() {
        Some(d) => d,
        None => return 0,
    };

    let mut processed = 0usize;
    let mut committed = false;

    // SAFETY: we own all queue memory while holding the mutex.
    unsafe {
        loop {
            let cur = dev.evq.used_idx();
            if cur == dev.evq.last_used {
                break;
            }
            let new_used = dev.evq.last_used.wrapping_add(1);
            let id = dev.evq.used_id(new_used) as u16;
            dev.evq.last_used = new_used;

            // Decode the 8-byte virtio_input_event (type, code, value), LE.
            let buf = dev.evq.evbuf(id);
            let etype = (buf as *const u16).read_volatile();
            let code = (buf.add(2) as *const u16).read_volatile();
            let value = (buf.add(4) as *const u32).read_volatile();
            processed += 1;

            match etype {
                EV_ABS => match code {
                    ABS_X => dev.pend_abs_x = value,
                    ABS_Y => dev.pend_abs_y = value,
                    _ => {}
                },
                EV_REL => match code {
                    REL_X => dev.pend_rel_x += value as i32,
                    REL_Y => dev.pend_rel_y += value as i32,
                    _ => {}
                },
                EV_KEY => {
                    let mask = match code {
                        BTN_LEFT => 0x01,
                        BTN_RIGHT => 0x02,
                        BTN_MIDDLE => 0x04,
                        _ => 0,
                    };
                    if mask != 0 {
                        if value != 0 {
                            dev.buttons |= mask;
                        } else {
                            dev.buttons &= !mask;
                        }
                    }
                }
                EV_SYN if code == SYN_REPORT => {
                    commit(dev);
                    committed = true;
                }
                _ => {}
            }

            // Return the buffer to the device.
            dev.evq.fill_desc(id);
            dev.evq.publish(id);
        }

        if processed > 0 {
            // Kick the device so it knows fresh buffers are available.
            let notify_addr = (dev.io_notify_off as usize) * (dev.notify_mult as usize);
            (dev.notify_base.add(notify_addr) as *mut u16).write_volatile(0);
        }
    }

    // Some hosts (and QMP `input-send-event`) emit ABS/KEY without a trailing
    // SYN in every batch; commit any residual movement once the ring drains.
    if processed > 0 && !committed {
        commit(dev);
    }

    processed
}

/// Translate accumulated device-space pointer state to screen coordinates and
/// push it into the mouse state.
fn commit(dev: &mut VirtioInput) {
    let (sw, sh) = crate::drivers::mouse::screen_bounds();
    if dev.is_abs {
        // Scale device absolute axis [0, abs_max] onto [0, screen-1].
        let x = if dev.abs_max_x > 0 {
            ((dev.pend_abs_x as u64 * (sw.max(1) as u64 - 1)) / dev.abs_max_x as u64) as i32
        } else {
            dev.pend_abs_x as i32
        };
        let y = if dev.abs_max_y > 0 {
            ((dev.pend_abs_y as u64 * (sh.max(1) as u64 - 1)) / dev.abs_max_y as u64) as i32
        } else {
            dev.pend_abs_y as i32
        };
        crate::drivers::mouse::set_state(x, y, dev.buttons);
    } else {
        // Relative device: integrate deltas onto the current position.
        let (cx, cy) = crate::drivers::mouse::position();
        let nx = cx + dev.pend_rel_x;
        let ny = cy + dev.pend_rel_y;
        dev.pend_rel_x = 0;
        dev.pend_rel_y = 0;
        crate::drivers::mouse::set_state(nx, ny, dev.buttons);
    }
}

/// Whether a virtio-input pointer was claimed.
pub fn is_available() -> bool {
    AVAILABLE.load(Ordering::Acquire)
}
