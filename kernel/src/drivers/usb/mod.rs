//! USB Subsystem
//!
//! Provides USB host controller detection and enumeration.
//! Supports xHCI, EHCI, OHCI, and UHCI controllers via PCI discovery.
//!
//! Sub-modules:
//!   - `xhci` — Extensible Host Controller Interface (USB 3.x)
//!   - `hid`  — Human Interface Device class driver (keyboards, mice)
//!   - `mass_storage` — Mass Storage class driver (USB sticks)

pub mod xhci;

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

// ── USB Controller Types ────────────────────────────────────────────────────

/// USB host controller type, identified by PCI prog_if.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UsbControllerType {
    Uhci,  // prog_if = 0x00 (Universal HCI, USB 1.x)
    Ohci,  // prog_if = 0x10 (Open HCI, USB 1.x)
    Ehci,  // prog_if = 0x20 (Enhanced HCI, USB 2.0)
    Xhci,  // prog_if = 0x30 (Extensible HCI, USB 3.x)
    Unknown(u8),
}

impl core::fmt::Display for UsbControllerType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UsbControllerType::Uhci => write!(f, "UHCI"),
            UsbControllerType::Ohci => write!(f, "OHCI"),
            UsbControllerType::Ehci => write!(f, "EHCI"),
            UsbControllerType::Xhci => write!(f, "xHCI"),
            UsbControllerType::Unknown(pi) => write!(f, "Unknown(0x{:02X})", pi),
        }
    }
}

/// Information about a detected USB controller.
#[derive(Clone)]
pub struct UsbControllerInfo {
    pub name: String,
    pub controller_type: UsbControllerType,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub irq: u8,
    pub bar0: u32,
}

impl core::fmt::Display for UsbControllerInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({:04x}:{:04x} @ {:02x}:{:02x}.{} irq={})",
            self.controller_type, self.vendor_id, self.device_id,
            self.bus, self.device, self.function, self.irq)
    }
}

// ── USB Device Descriptor (standard) ────────────────────────────────────────

/// Standard USB device descriptor (18 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub bcd_usb: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub manufacturer_idx: u8,
    pub product_idx: u8,
    pub serial_number_idx: u8,
    pub num_configurations: u8,
}

/// USB class codes.
pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_CLASS_MASS_STORAGE: u8 = 0x08;
pub const USB_CLASS_HUB: u8 = 0x09;
pub const USB_CLASS_AUDIO: u8 = 0x01;
pub const USB_CLASS_VIDEO: u8 = 0x0E;

// ── Global State ────────────────────────────────────────────────────────────

static CONTROLLERS: Mutex<Vec<UsbControllerInfo>> = Mutex::new(Vec::new());

// ── Initialization ──────────────────────────────────────────────────────────

/// Scan PCI bus for USB host controllers and initialize them.
pub fn init() {
    crate::serial_println!("[USB] Scanning for USB controllers...");

    let mut controllers = Vec::new();

    // USB controllers: PCI class 0x0C, subclass 0x03
    // Scan all PCI bus/device/function combinations
    for bus in 0u8..=255 {
        for device in 0u8..32 {
            let vendor_id = crate::drivers::pci::pci_config_read32(bus, device, 0, 0x00) as u16;
            if vendor_id == 0xFFFF || vendor_id == 0 { continue; }

            let max_funcs = {
                let ht = (crate::drivers::pci::pci_config_read32(bus, device, 0, 0x0C) >> 16) & 0xFF;
                if ht & 0x80 != 0 { 8 } else { 1 }
            };

            for func in 0..max_funcs {
                let reg0 = crate::drivers::pci::pci_config_read32(bus, device, func, 0x00);
                let vid = reg0 as u16;
                let did = (reg0 >> 16) as u16;
                if vid == 0xFFFF || vid == 0 { continue; }

                let reg2 = crate::drivers::pci::pci_config_read32(bus, device, func, 0x08);
                let class = ((reg2 >> 24) & 0xFF) as u8;
                let subclass = ((reg2 >> 16) & 0xFF) as u8;
                let prog_if = ((reg2 >> 8) & 0xFF) as u8;

                // USB: class 0x0C, subclass 0x03
                if class != 0x0C || subclass != 0x03 { continue; }

                let ctrl_type = match prog_if {
                    0x00 => UsbControllerType::Uhci,
                    0x10 => UsbControllerType::Ohci,
                    0x20 => UsbControllerType::Ehci,
                    0x30 => UsbControllerType::Xhci,
                    pi => UsbControllerType::Unknown(pi),
                };

                let bar0 = crate::drivers::pci::pci_config_read32(bus, device, func, 0x10);
                let irq_reg = crate::drivers::pci::pci_config_read32(bus, device, func, 0x3C);
                let irq = (irq_reg & 0xFF) as u8;

                let name = alloc::format!("USB {} Controller", ctrl_type);

                crate::serial_println!("[USB] Found {} at {:02x}:{:02x}.{} (vid={:04x} did={:04x} irq={})",
                    ctrl_type, bus, device, func, vid, did, irq);

                // Enable PCI bus mastering
                crate::drivers::pci::enable_bus_master(bus, device, func);

                let info = UsbControllerInfo {
                    name,
                    controller_type: ctrl_type,
                    bus,
                    device,
                    function: func,
                    vendor_id: vid,
                    device_id: did,
                    irq,
                    bar0,
                };

                // Initialize xHCI if found
                if ctrl_type == UsbControllerType::Xhci {
                    xhci::init_controller(&info);
                }

                controllers.push(info);
            }
        }
        // Early exit if we've scanned bus 0 and no bridges found (most QEMU setups)
        if bus == 0 { break; }
    }

    let count = controllers.len();
    *CONTROLLERS.lock() = controllers;
    crate::serial_println!("[USB] Found {} USB controller(s)", count);
}

/// Return the number of USB controllers detected.
pub fn controller_count() -> usize {
    CONTROLLERS.lock().len()
}

/// Return a list of all detected USB controllers.
pub fn list_controllers() -> Vec<UsbControllerInfo> {
    CONTROLLERS.lock().clone()
}

/// Check if any USB controller is available.
pub fn is_available() -> bool {
    !CONTROLLERS.lock().is_empty()
}
