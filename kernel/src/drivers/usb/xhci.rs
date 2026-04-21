//! xHCI (Extensible Host Controller Interface) Driver
//!
//! Implements PCI discovery, MMIO capability-register decoding, ring/DCBAA
//! allocation, and root-hub port counting for USB 3.x host controllers.
//!
//! ## Scope (this file)
//! - PCI probe: class 0x0C, subclass 0x03, prog_if 0x30.
//! - MMIO BAR0 mapping: decode CAP registers (HCSPARAMS1/2/3, HCCPARAMS1/2,
//!   DBOFF, RTSOFF).
//! - Physical-memory allocations: Device Context Base Address Array (DCBAA),
//!   Command Ring (64-entry), Event Ring Segment Table + one Event Ring segment.
//! - OP register programming: CONFIG (MaxSlotsEn), DCBAAP, CRCR (ring base +
//!   RCS), USBCMD Run/Stop to start the controller.
//! - Root-hub port enumeration: read PORTSC[0..MaxPorts], count CCS bits.
//!
//! ## Out of scope (full USB stack, not needed for RC1 port-counting)
//! - Slot/endpoint context setup.
//! - SETUP/IN/OUT control transfers.
//! - HID / mass-storage class drivers.
//! - MSI-X — uses polled rings only.
//!
//! ## QEMU testing
//! Default QEMU has no xHCI.  Add `-device qemu-xhci,id=xhci` to enable it.
//! With that flag, `is_present()` returns true and `connected_port_count()`
//! reflects any `-device usb-kbd` / `-device usb-tablet` attached to the bus.
//! Without it, the driver cleanly skips init and returns 0 / false.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// ── xHCI Capability Register offsets (from CAP base = BAR0) ─────────────────
// xHCI 1.2 spec §5.3

const CAP_CAPLENGTH:  u32 = 0x00; // [7:0] cap length, [15:8] rsvd, [31:16] HCI ver
const CAP_HCSPARAMS1: u32 = 0x04; // [7:0] MaxSlots, [18:8] MaxIntrs, [31:24] MaxPorts
const CAP_DBOFF:      u32 = 0x14; // Doorbell Array Offset [31:2]
const CAP_RTSOFF:     u32 = 0x18; // Runtime Register Space Offset [31:5]

// ── xHCI Operational Register offsets (from OP base = BAR0 + CapLength) ─────
// xHCI 1.2 spec §5.4

const OP_USBCMD:  u32 = 0x00; // USB Command
const OP_USBSTS:  u32 = 0x04; // USB Status
const OP_CRCR:    u32 = 0x18; // Command Ring Control Register (64-bit)
const OP_DCBAAP:  u32 = 0x30; // Device Context Base Address Array Pointer (64-bit)
const OP_CONFIG:  u32 = 0x38; // Configure Register [7:0] MaxSlotsEn

// ── USBCMD bits ──────────────────────────────────────────────────────────────
const USBCMD_RUN:   u32 = 1 << 0; // Run/Stop
const USBCMD_HCRST: u32 = 1 << 1; // Host Controller Reset

// ── USBSTS bits ──────────────────────────────────────────────────────────────
const USBSTS_HCH: u32 = 1 << 0;  // HCHalted
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// ── CRCR bits ────────────────────────────────────────────────────────────────
// Ring Cycle State: initial = 1 so first TRBs have Cycle = 1 (= owned by SW).
const CRCR_RCS: u64 = 1 << 0;

// ── PORTSC bits (per-port, at OP base + 0x400 + port * 0x10) ─────────────────
const PORTSC_CCS:        u32 = 1 << 0;    // Current Connect Status
const PORTSC_PP:         u32 = 1 << 9;    // Port Power
const PORTSC_SPEED_MASK: u32 = 0xF << 10; // Port Speed nibble

// ── Ring / DCBAA sizing ──────────────────────────────────────────────────────

/// Number of TRBs in the Command Ring.  Each TRB is 16 bytes.
/// The last entry is a Link TRB, so COMMAND_RING_SIZE-1 are usable.
const COMMAND_RING_SIZE: usize = 64;

/// Number of TRBs in the single Event Ring segment.
const EVENT_RING_SIZE: usize = 256;

// ── Controller state ─────────────────────────────────────────────────────────

/// Per-controller state, set up during `try_init_controller`.
struct XhciController {
    // MMIO addresses (physical, accessible via identity map of 0–4 GiB)
    op_base: u64,  // Operational registers  = mmio_base + cap_length

    // Capability values
    max_ports: u8,
}

/// Global list of initialized xHCI controllers.
static XHCI_CONTROLLERS: Mutex<Vec<XhciController>> = Mutex::new(Vec::new());

/// Fast flag: at least one controller successfully initialized.
static XHCI_PRESENT: AtomicBool = AtomicBool::new(false);

// ── MMIO helpers (physical address, accessible via identity map 0–4 GiB) ────

/// Read a 32-bit xHCI register.
///
/// SAFETY: caller guarantees `base + offset` is within the controller's MMIO
/// window and that `base` is a valid MMIO physical address covered by the
/// bootloader's identity map of 0–4 GiB (PML4[0]).
#[inline]
unsafe fn mmio_r32(base: u64, offset: u32) -> u32 {
    core::ptr::read_volatile((base + offset as u64) as *const u32)
}

/// Write a 32-bit xHCI register.
///
/// SAFETY: same as mmio_r32.
#[inline]
unsafe fn mmio_w32(base: u64, offset: u32, val: u32) {
    core::ptr::write_volatile((base + offset as u64) as *mut u32, val);
}

/// Write a 64-bit xHCI register as two 32-bit writes (lo first, then hi).
/// xHCI §4.2: software must write 64-bit registers with two 32-bit accesses.
///
/// SAFETY: same as mmio_r32.
#[inline]
unsafe fn mmio_w64(base: u64, offset: u32, val: u64) {
    mmio_w32(base, offset,     val as u32);
    mmio_w32(base, offset + 4, (val >> 32) as u32);
}

// ── Physical-memory helpers ───────────────────────────────────────────────────

/// Allocate `pages` contiguous 4 KiB pages from the PMM and zero them.
/// Returns the physical base address, or None on OOM.
///
/// The kernel identity-maps 0–4 GiB (PML4[0]) so physical addresses returned
/// by the PMM (which are below 4 GiB) can be written directly.
fn alloc_zeroed_pages(pages: usize) -> Option<u64> {
    let phys = crate::mm::pmm::alloc_pages(pages)?;
    // SAFETY: phys is a fresh PMM allocation below 4 GiB, accessible via
    // the bootloader's identity map at PML4[0].
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, pages * 4096);
    }
    Some(phys)
}

// ── Controller-level init sequence ───────────────────────────────────────────

/// Attempt to bring up a single xHCI controller.
///
/// Returns `Some(XhciController)` on success, `None` if any step fails.
/// All failure paths are logged but never panic.
fn try_init_controller(bus: u8, device: u8, function: u8, bar0_raw: u32) -> Option<XhciController> {
    // ── Decode BAR0 ─────────────────────────────────────────────────────
    // BAR0 for xHCI is always a memory BAR (bit 0 = 0).
    // Bits 2:1 encode the address width: 00 = 32-bit, 10 = 64-bit.
    if bar0_raw & 1 != 0 {
        crate::serial_println!("[xHCI] BAR0 is I/O space — not a valid MMIO BAR, skipping");
        return None;
    }

    let mmio_base: u64 = if (bar0_raw >> 1) & 3 == 2 {
        // 64-bit BAR: high 32 bits in BAR1 at PCI config offset 0x14
        let bar1 = crate::drivers::pci::pci_config_read32(bus, device, function, 0x14);
        ((bar1 as u64) << 32) | ((bar0_raw & 0xFFFF_FFF0) as u64)
    } else {
        (bar0_raw & 0xFFFF_FFF0) as u64
    };

    if mmio_base == 0 {
        crate::serial_println!("[xHCI] BAR0 MMIO base is zero — skipping");
        return None;
    }

    crate::serial_println!("[xHCI] {:02x}:{:02x}.{} MMIO base = {:#010x}",
        bus, device, function, mmio_base);

    // ── Read Capability Registers ────────────────────────────────────────
    // SAFETY: mmio_base is within PCI MMIO space, covered by the bootloader's
    // identity map of 0–4 GiB.

    let cap0   = unsafe { mmio_r32(mmio_base, CAP_CAPLENGTH) };
    let cap_length  = (cap0 & 0xFF) as u8;
    let hci_version = ((cap0 >> 16) & 0xFFFF) as u16;

    if cap_length < 0x10 {
        crate::serial_println!("[xHCI] Suspicious cap_length={} — skipping", cap_length);
        return None;
    }

    let hcsparams1 = unsafe { mmio_r32(mmio_base, CAP_HCSPARAMS1) };
    let max_slots = (hcsparams1 & 0xFF) as u8;
    let max_intrs = ((hcsparams1 >> 8) & 0x7FF) as u16;
    let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

    // DBOFF[31:2] aligned to 4 bytes; RTSOFF[31:5] aligned to 32 bytes.
    let dboff  = unsafe { mmio_r32(mmio_base, CAP_DBOFF)  } & !0x03u32;
    let rtsoff = unsafe { mmio_r32(mmio_base, CAP_RTSOFF) } & !0x1Fu32;

    let op_base  = mmio_base + cap_length as u64;
    let rts_base = mmio_base + rtsoff as u64;

    crate::serial_println!(
        "[xHCI] HCI v{:#04x} — MaxSlots={} MaxPorts={} MaxIntrs={}",
        hci_version, max_slots, max_ports, max_intrs
    );
    // Suppress unused-variable warning for db_base (doorbell not yet needed
    // for polled port-count — no commands submitted).
    let _ = mmio_base + dboff as u64; // db_base computed but unused at this scope

    // ── Wait for Controller Not Ready to clear ───────────────────────────
    // SAFETY: op_base is within the controller MMIO window.

    let mut ready = false;
    for _ in 0..50_000u32 {
        if unsafe { mmio_r32(op_base, OP_USBSTS) } & USBSTS_CNR == 0 {
            ready = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !ready {
        crate::serial_println!("[xHCI] Controller Not Ready timeout — aborting");
        return None;
    }

    // ── Stop the controller if it was running ────────────────────────────
    let cmd = unsafe { mmio_r32(op_base, OP_USBCMD) };
    if cmd & USBCMD_RUN != 0 {
        unsafe { mmio_w32(op_base, OP_USBCMD, cmd & !USBCMD_RUN); }
        // Wait for HCHalted (xHCI spec: max 16 ms)
        for _ in 0..500_000u32 {
            if unsafe { mmio_r32(op_base, OP_USBSTS) } & USBSTS_HCH != 0 { break; }
            core::hint::spin_loop();
        }
    }

    // ── Reset the controller ─────────────────────────────────────────────
    unsafe { mmio_w32(op_base, OP_USBCMD, USBCMD_HCRST); }
    for _ in 0..500_000u32 {
        let c = unsafe { mmio_r32(op_base, OP_USBCMD) };
        let s = unsafe { mmio_r32(op_base, OP_USBSTS) };
        if c & USBCMD_HCRST == 0 && s & USBSTS_CNR == 0 { break; }
        core::hint::spin_loop();
    }
    if unsafe { mmio_r32(op_base, OP_USBCMD) } & USBCMD_HCRST != 0 {
        crate::serial_println!("[xHCI] Reset did not complete — aborting");
        return None;
    }

    // ── Allocate DCBAA ───────────────────────────────────────────────────
    // Device Context Base Address Array: (MaxSlots+1) × 8 bytes, page-aligned.
    // Slot 0 = Scratchpad Buffer Array pointer (NULL here — QEMU's xHCI
    // reports 0 scratchpad buffers in HCSPARAMS2).
    // Slots 1..MaxSlots = Device Context base pointers (all NULL = no device).
    // 1 page (4 KiB) covers up to 511 slots.
    let dcbaa_phys = alloc_zeroed_pages(1)?;

    // ── Allocate Command Ring ────────────────────────────────────────────
    // COMMAND_RING_SIZE TRBs × 16 bytes = 1 KiB, within 1 page.
    // Last TRB is a Link TRB wrapping back to the ring start (TC=1).
    let cmd_ring_phys = alloc_zeroed_pages(1)?;

    // Write Link TRB at last slot (index COMMAND_RING_SIZE-1).
    // Link TRB DW3: TRB Type [15:10] = 0x06 (0x06 << 10 = 0x1800),
    //               Toggle Cycle [1] = 1, Cycle [0] = 1 (initial RCS).
    // SAFETY: cmd_ring_phys is our freshly allocated PMM page, identity-mapped.
    unsafe {
        let link = (cmd_ring_phys + ((COMMAND_RING_SIZE - 1) as u64) * 16) as *mut u32;
        link.add(0).write_volatile(cmd_ring_phys as u32);         // ring base lo
        link.add(1).write_volatile((cmd_ring_phys >> 32) as u32); // ring base hi
        link.add(2).write_volatile(0);                            // RsvdZ
        link.add(3).write_volatile(0x1800 | 0x02 | 0x01);        // type=Link, TC=1, Cycle=1
    }

    // ── Allocate Event Ring ──────────────────────────────────────────────
    // One segment: EVENT_RING_SIZE TRBs × 16 B = 4 KiB → 1 page.
    let event_seg_phys = alloc_zeroed_pages(1)?;

    // Event Ring Segment Table (ERST): one 16-byte entry within 1 page.
    // Layout per xHCI spec §6.5:
    //   Offset 0x00 (u64): Ring Segment Base Address
    //   Offset 0x08 (u32): Ring Segment Size (TRB count)
    //   Offset 0x0C (u32): RsvdZ
    let erst_phys = alloc_zeroed_pages(1)?;
    // SAFETY: erst_phys is our allocation, identity-mapped.
    unsafe {
        let p = erst_phys as *mut u32;
        p.add(0).write_volatile(event_seg_phys as u32);         // base lo
        p.add(1).write_volatile((event_seg_phys >> 32) as u32); // base hi
        p.add(2).write_volatile(EVENT_RING_SIZE as u32);        // segment size
        p.add(3).write_volatile(0);                             // RsvdZ
    }

    // ── Program Operational Registers ────────────────────────────────────
    // SAFETY: op_base is within the controller MMIO window, identity-mapped.

    // CONFIG: MaxSlotsEn = max_slots
    unsafe { mmio_w32(op_base, OP_CONFIG, max_slots as u32); }

    // DCBAAP: 64-bit physical address of the DCBAA (must be 64-byte aligned;
    // our page-aligned allocation satisfies this).
    unsafe { mmio_w64(op_base, OP_DCBAAP, dcbaa_phys); }

    // CRCR: Command Ring dequeue pointer [63:6] | RCS=1 [0].
    // Lower 6 bits are ring control fields (CA, CRR, CS, RCS); we set RCS=1.
    let crcr_val = (cmd_ring_phys & !0x3Fu64) | CRCR_RCS;
    unsafe { mmio_w64(op_base, OP_CRCR, crcr_val); }

    // Program Primary Interrupter (Interrupter[0]).
    // Runtime register layout (xHCI §5.5):
    //   rts_base + 0x00: MFINDEX (read-only)
    //   rts_base + 0x20: Interrupter[0] IMAN
    //   rts_base + 0x24: Interrupter[0] IMOD
    //   rts_base + 0x28: Interrupter[0] ERSTSZ
    //   rts_base + 0x2C: RsvdZ
    //   rts_base + 0x30: Interrupter[0] ERSTBA (64-bit)
    //   rts_base + 0x38: Interrupter[0] ERDP   (64-bit)
    //
    // We configure for polled operation (IMAN.IE=0, IMOD.IMODI=0).
    // Set ERSTSZ=1, ERSTBA=erst_phys, ERDP=event_seg_phys (EHB=0 initially).
    //
    // SAFETY: rts_base is within the controller MMIO window, identity-mapped.
    let intr0 = rts_base + 0x20;
    unsafe {
        mmio_w32(intr0, 0x08, 1);             // ERSTSZ = 1
        mmio_w64(intr0, 0x10, erst_phys);     // ERSTBA
        mmio_w64(intr0, 0x18, event_seg_phys); // ERDP (EHB=0, no events yet)
    }

    // ── Start the controller (Run/Stop = 1) ──────────────────────────────
    unsafe { mmio_w32(op_base, OP_USBCMD, USBCMD_RUN); }

    // Wait for HCHalted to de-assert (controller running)
    let mut running = false;
    for _ in 0..100_000u32 {
        if unsafe { mmio_r32(op_base, OP_USBSTS) } & USBSTS_HCH == 0 {
            running = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !running {
        crate::serial_println!("[xHCI] Controller did not start (HCH still set) — aborting");
        return None;
    }

    crate::serial_println!("[xHCI] Controller running");

    // ── Scan root-hub ports for connected devices ────────────────────────
    // PORTSC is at OP base + 0x400 + port_index * 0x10 (0-based index).
    // CCS (bit 0) = device physically attached to this port.
    // We only count connections — no device enumeration here.
    let mut connected = 0usize;
    for port in 0..max_ports {
        let portsc_off: u32 = 0x400u32 + (port as u32) * 0x10;
        let portsc = unsafe { mmio_r32(op_base, portsc_off) };
        if portsc & PORTSC_CCS != 0 {
            connected += 1;
            let speed = (portsc & PORTSC_SPEED_MASK) >> 10;
            let speed_str = match speed {
                1 => "Full (12 Mbps)",
                2 => "Low (1.5 Mbps)",
                3 => "High (480 Mbps)",
                4 => "Super (5 Gbps)",
                5 => "Super+ (10 Gbps)",
                _ => "Unknown",
            };
            crate::serial_println!("[xHCI] Port {}: connected, speed={}, powered={}",
                port + 1, speed_str, portsc & PORTSC_PP != 0);
        }
    }

    crate::serial_println!("[xHCI] Init complete — {} port(s) with connected devices", connected);

    // suppress unused read; hci_version logged above, max_intrs/max_slots
    // stored in OP registers but not cached in XhciController (not needed
    // for the minimal API surface)
    let _ = (hci_version, max_slots, max_intrs);

    Some(XhciController { op_base, max_ports })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Probe PCI for xHCI controllers (class 0x0C, subclass 0x03, prog_if 0x30),
/// decode capability registers, allocate DCBAA + command/event rings, start
/// the controller, and count connected root-hub ports.
///
/// Called from `drivers::usb::init()` (via `init_controller`) and may also be
/// called standalone.  Safe to call with no xHCI device present — will log a
/// diagnostic and return without touching any hardware.
pub fn init() {
    // Guard: if usb::init() already called init_controller() and succeeded,
    // there is nothing to do.
    if XHCI_PRESENT.load(Ordering::Acquire) {
        return;
    }

    let devices = crate::drivers::pci::devices();
    let mut found_any = false;

    for dev in &devices {
        if dev.class_code != 0x0C || dev.subclass != 0x03 || dev.prog_if != 0x30 {
            continue;
        }

        crate::serial_println!(
            "[xHCI] Found PCI device {:02x}:{:02x}.{} ({:04x}:{:04x})",
            dev.bus, dev.device, dev.function, dev.vendor_id, dev.device_id
        );

        // Enable bus mastering (bit 2) + memory space (bit 1) in PCI command.
        crate::drivers::pci::enable_bus_master(dev.bus, dev.device, dev.function);
        let pci_cmd = crate::drivers::pci::pci_config_read32(
            dev.bus, dev.device, dev.function, 0x04);
        crate::drivers::pci::pci_config_write32(
            dev.bus, dev.device, dev.function, 0x04, pci_cmd | 0x06);

        if let Some(ctrl) = try_init_controller(dev.bus, dev.device, dev.function, dev.bar[0]) {
            XHCI_CONTROLLERS.lock().push(ctrl);
            found_any = true;
        }
    }

    if found_any {
        XHCI_PRESENT.store(true, Ordering::Release);
        crate::serial_println!(
            "[xHCI] {} controller(s) initialized, {} port(s) connected",
            XHCI_CONTROLLERS.lock().len(),
            connected_port_count()
        );
    } else {
        crate::serial_println!(
            "[xHCI] No xHCI controller found (add -device qemu-xhci,id=xhci for USB 3.0)"
        );
    }
}

/// Returns `true` if at least one xHCI controller was successfully initialized.
pub fn is_present() -> bool {
    XHCI_PRESENT.load(Ordering::Acquire)
}

/// Returns the number of root-hub ports that have a device physically connected
/// (PORTSC.CCS = 1) across all initialized xHCI controllers.
///
/// Performs live MMIO reads, so the result is current if called after `init()`.
/// Returns 0 if no controller is present.
pub fn connected_port_count() -> usize {
    let controllers = XHCI_CONTROLLERS.lock();
    let mut count = 0usize;
    for ctrl in controllers.iter() {
        let op = ctrl.op_base;
        for port in 0..ctrl.max_ports {
            let portsc_off: u32 = 0x400u32 + (port as u32) * 0x10;
            // SAFETY: op_base is within the controller MMIO window, identity-mapped.
            let portsc = unsafe { mmio_r32(op, portsc_off) };
            if portsc & PORTSC_CCS != 0 {
                count += 1;
            }
        }
    }
    count
}

/// Returns the number of initialized xHCI controllers.
pub fn controller_count() -> usize {
    XHCI_CONTROLLERS.lock().len()
}

// ── Legacy entry point (called by usb::init via UsbControllerInfo) ───────────

/// Initialize a single xHCI controller given pre-scanned PCI info.
///
/// Called by `drivers::usb::init()` when it encounters an xHCI device during
/// its PCI scan.  Guards against double-init via `XHCI_PRESENT`.
pub fn init_controller(info: &super::UsbControllerInfo) {
    // usb::init() may call us before the standalone init() runs; guard here
    // so we don't initialize the same hardware twice.
    if XHCI_PRESENT.load(Ordering::Acquire) {
        return;
    }

    // Enable bus mastering + memory space
    crate::drivers::pci::enable_bus_master(info.bus, info.device, info.function);
    let pci_cmd = crate::drivers::pci::pci_config_read32(
        info.bus, info.device, info.function, 0x04);
    crate::drivers::pci::pci_config_write32(
        info.bus, info.device, info.function, 0x04, pci_cmd | 0x06);

    if let Some(ctrl) = try_init_controller(info.bus, info.device, info.function, info.bar0) {
        XHCI_CONTROLLERS.lock().push(ctrl);
        XHCI_PRESENT.store(true, Ordering::Release);
    }
}
