//! xHCI (Extensible Host Controller Interface) Driver
//!
//! USB 3.x host controller driver. Implements basic controller initialization,
//! capability register reading, and device slot management.
//!
//! xHCI uses MMIO registers mapped via PCI BAR0, with three register spaces:
//!   - Capability Registers (read-only, at BAR0)
//!   - Operational Registers (at BAR0 + cap_length)
//!   - Runtime Registers (at BAR0 + rts_offset)
//!
//! Data flow uses Transfer Request Blocks (TRBs) organized into rings.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

// ── xHCI Capability Register offsets ────────────────────────────────────────

const CAP_CAPLENGTH: u32 = 0x00;    // Capability Register Length (1 byte)
const CAP_HCIVERSION: u32 = 0x02;   // HCI Version (2 bytes, at offset 0x02)
const CAP_HCSPARAMS1: u32 = 0x04;   // Structural params 1
const CAP_HCSPARAMS2: u32 = 0x08;   // Structural params 2
const CAP_HCSPARAMS3: u32 = 0x0C;   // Structural params 3
const CAP_HCCPARAMS1: u32 = 0x10;   // Capability params 1
const CAP_DBOFF: u32 = 0x14;        // Doorbell offset
const CAP_RTSOFF: u32 = 0x18;       // Runtime register space offset

// ── xHCI Operational Register offsets (from op_base) ────────────────────────

const OP_USBCMD: u32 = 0x00;        // USB Command
const OP_USBSTS: u32 = 0x04;        // USB Status
const OP_PAGESIZE: u32 = 0x08;      // Page Size
const OP_DNCTRL: u32 = 0x14;        // Device Notification Control
const OP_CRCR: u32 = 0x18;          // Command Ring Control
const OP_DCBAAP: u32 = 0x30;        // Device Context Base Address Array Pointer
const OP_CONFIG: u32 = 0x38;        // Configure

// ── USBCMD bits ─────────────────────────────────────────────────────────────

const USBCMD_RUN: u32 = 1 << 0;     // Run/Stop
const USBCMD_HCRST: u32 = 1 << 1;   // Host Controller Reset
const USBCMD_INTE: u32 = 1 << 2;    // Interrupter Enable

// ── USBSTS bits ─────────────────────────────────────────────────────────────

const USBSTS_HCH: u32 = 1 << 0;     // HCHalted
const USBSTS_CNR: u32 = 1 << 11;    // Controller Not Ready

// ── Port Status and Control (per port, at op_base + 0x400 + port*0x10) ──────

const PORTSC_CCS: u32 = 1 << 0;     // Current Connect Status
const PORTSC_PED: u32 = 1 << 1;     // Port Enabled/Disabled
const PORTSC_PR: u32 = 1 << 4;      // Port Reset
const PORTSC_PLS_MASK: u32 = 0xF << 5; // Port Link State
const PORTSC_PP: u32 = 1 << 9;      // Port Power
const PORTSC_SPEED_MASK: u32 = 0xF << 10; // Port Speed

// ── Controller state ────────────────────────────────────────────────────────

struct XhciController {
    /// MMIO base address
    mmio_base: u64,
    /// Capability register length
    cap_length: u8,
    /// Operational register base = mmio_base + cap_length
    op_base: u64,
    /// Runtime register base
    rts_base: u64,
    /// Doorbell register base
    db_base: u64,
    /// Maximum device slots
    max_slots: u8,
    /// Maximum ports
    max_ports: u8,
    /// Maximum interrupters
    max_intrs: u16,
    /// HCI version (e.g., 0x0100 = 1.0)
    hci_version: u16,
    /// Page size in bytes
    page_size: u32,
    /// Whether the controller has been initialized
    initialized: bool,
}

static XHCI_CONTROLLERS: Mutex<Vec<XhciController>> = Mutex::new(Vec::new());

// ── MMIO helpers ────────────────────────────────────────────────────────────

unsafe fn mmio_read32(base: u64, offset: u32) -> u32 {
    let ptr = (base + offset as u64) as *const u32;
    core::ptr::read_volatile(ptr)
}

unsafe fn mmio_write32(base: u64, offset: u32, val: u32) {
    let ptr = (base + offset as u64) as *mut u32;
    core::ptr::write_volatile(ptr, val);
}

unsafe fn mmio_read64(base: u64, offset: u32) -> u64 {
    let lo = mmio_read32(base, offset) as u64;
    let hi = mmio_read32(base, offset + 4) as u64;
    (hi << 32) | lo
}

unsafe fn mmio_write64(base: u64, offset: u32, val: u64) {
    mmio_write32(base, offset, val as u32);
    mmio_write32(base, offset + 4, (val >> 32) as u32);
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Initialize a single xHCI controller.
pub fn init_controller(info: &super::UsbControllerInfo) {
    let bar0 = info.bar0;

    // Determine MMIO base from BAR0 (memory-mapped)
    let mmio_base = if bar0 & 0x04 != 0 {
        // 64-bit BAR: read BAR1 for high bits
        let bar1 = crate::drivers::pci::pci_config_read32(info.bus, info.device, info.function, 0x14);
        ((bar1 as u64) << 32) | ((bar0 & 0xFFFF_FFF0) as u64)
    } else {
        (bar0 & 0xFFFF_FFF0) as u64
    };

    crate::serial_println!("[xHCI] MMIO base: {:#X}", mmio_base);

    // Read capability registers
    let cap_reg = unsafe { mmio_read32(mmio_base, CAP_CAPLENGTH) };
    let cap_length = (cap_reg & 0xFF) as u8;
    let hci_version = ((cap_reg >> 16) & 0xFFFF) as u16;

    let hcsparams1 = unsafe { mmio_read32(mmio_base, CAP_HCSPARAMS1) };
    let max_slots = (hcsparams1 & 0xFF) as u8;
    let max_intrs = ((hcsparams1 >> 8) & 0x7FF) as u16;
    let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

    let dboff = unsafe { mmio_read32(mmio_base, CAP_DBOFF) } & !0x03;
    let rtsoff = unsafe { mmio_read32(mmio_base, CAP_RTSOFF) } & !0x1F;

    let op_base = mmio_base + cap_length as u64;
    let rts_base = mmio_base + rtsoff as u64;
    let db_base = mmio_base + dboff as u64;

    crate::serial_println!("[xHCI] Version: {}.{}.{}, Slots: {}, Ports: {}, Intrs: {}",
        (hci_version >> 8) & 0xF, (hci_version >> 4) & 0xF, hci_version & 0xF,
        max_slots, max_ports, max_intrs);

    // Read page size
    let page_size_reg = unsafe { mmio_read32(op_base, OP_PAGESIZE) };
    let page_size = (page_size_reg & 0xFFFF) << 12; // Bit N means (1 << (N+12)) bytes

    // Wait for Controller Not Ready to clear
    let mut ready = false;
    for _ in 0..1000 {
        let sts = unsafe { mmio_read32(op_base, OP_USBSTS) };
        if sts & USBSTS_CNR == 0 {
            ready = true;
            break;
        }
        for _ in 0..10_000 { unsafe { core::arch::asm!("pause"); } }
    }

    if !ready {
        crate::serial_println!("[xHCI] Controller not ready, skipping");
        return;
    }

    // Stop the controller if running
    let cmd = unsafe { mmio_read32(op_base, OP_USBCMD) };
    if cmd & USBCMD_RUN != 0 {
        unsafe { mmio_write32(op_base, OP_USBCMD, cmd & !USBCMD_RUN); }
        // Wait for HCHalted
        for _ in 0..1000 {
            let sts = unsafe { mmio_read32(op_base, OP_USBSTS) };
            if sts & USBSTS_HCH != 0 { break; }
            for _ in 0..10_000 { unsafe { core::arch::asm!("pause"); } }
        }
    }

    // Reset controller
    unsafe { mmio_write32(op_base, OP_USBCMD, USBCMD_HCRST); }

    // Wait for reset to complete
    for _ in 0..1000 {
        let cmd = unsafe { mmio_read32(op_base, OP_USBCMD) };
        let sts = unsafe { mmio_read32(op_base, OP_USBSTS) };
        if cmd & USBCMD_HCRST == 0 && sts & USBSTS_CNR == 0 {
            break;
        }
        for _ in 0..10_000 { unsafe { core::arch::asm!("pause"); } }
    }

    // Configure max device slots
    unsafe { mmio_write32(op_base, OP_CONFIG, max_slots as u32); }

    // Scan ports for connected devices
    let mut connected_ports = 0u8;
    for port in 0..max_ports {
        let portsc_offset = 0x400 + (port as u32) * 0x10;
        let portsc = unsafe { mmio_read32(op_base, portsc_offset) };
        let connected = portsc & PORTSC_CCS != 0;
        let enabled = portsc & PORTSC_PED != 0;
        let powered = portsc & PORTSC_PP != 0;
        let speed = (portsc & PORTSC_SPEED_MASK) >> 10;

        if connected {
            connected_ports += 1;
            let speed_str = match speed {
                1 => "Full (12 Mbps)",
                2 => "Low (1.5 Mbps)",
                3 => "High (480 Mbps)",
                4 => "Super (5 Gbps)",
                5 => "Super+ (10 Gbps)",
                _ => "Unknown",
            };
            crate::serial_println!("[xHCI] Port {}: connected, speed={}, enabled={}, powered={}",
                port, speed_str, enabled, powered);
        }
    }

    crate::serial_println!("[xHCI] {} port(s) with connected devices", connected_ports);

    let controller = XhciController {
        mmio_base,
        cap_length,
        op_base,
        rts_base,
        db_base,
        max_slots,
        max_ports,
        max_intrs,
        hci_version,
        page_size,
        initialized: true,
    };

    XHCI_CONTROLLERS.lock().push(controller);
    crate::serial_println!("[xHCI] Controller initialized");
}

/// Return information about connected ports on all xHCI controllers.
pub fn connected_port_count() -> usize {
    let controllers = XHCI_CONTROLLERS.lock();
    let mut count = 0;
    for ctrl in controllers.iter() {
        if !ctrl.initialized { continue; }
        for port in 0..ctrl.max_ports {
            let portsc_offset = 0x400 + (port as u32) * 0x10;
            let portsc = unsafe { mmio_read32(ctrl.op_base, portsc_offset) };
            if portsc & PORTSC_CCS != 0 {
                count += 1;
            }
        }
    }
    count
}

/// Return the number of initialized xHCI controllers.
pub fn controller_count() -> usize {
    XHCI_CONTROLLERS.lock().iter().filter(|c| c.initialized).count()
}
