//! PCI Bus Enumeration
//!
//! Scans the PCI bus using configuration space I/O ports (0xCF8/0xCFC).
//! Discovers devices and provides device lookup by class/vendor.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

/// PCI configuration address port.
const PCI_CONFIG_ADDR: u16 = 0xCF8;
/// PCI configuration data port.
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// A discovered PCI device.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub interrupt_line: u8,
    pub bar: [u32; 6],
}

/// Global PCI device list.
static PCI_DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());

/// Read a 32-bit value from PCI configuration space.
pub fn pci_config_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let addr: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        crate::hal::outl(PCI_CONFIG_ADDR, addr);
        crate::hal::inl(PCI_CONFIG_DATA)
    }
}

/// Write a 32-bit value to PCI configuration space.
pub fn pci_config_write32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let addr: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        crate::hal::outl(PCI_CONFIG_ADDR, addr);
        crate::hal::outl(PCI_CONFIG_DATA, value);
    }
}

/// Scan a single PCI function.
fn scan_function(bus: u8, device: u8, function: u8) -> Option<PciDevice> {
    let id = pci_config_read32(bus, device, function, 0x00);
    let vendor_id = (id & 0xFFFF) as u16;
    let device_id = ((id >> 16) & 0xFFFF) as u16;

    if vendor_id == 0xFFFF {
        return None;
    }

    let class_rev = pci_config_read32(bus, device, function, 0x08);
    let class_code = ((class_rev >> 24) & 0xFF) as u8;
    let subclass = ((class_rev >> 16) & 0xFF) as u8;
    let prog_if = ((class_rev >> 8) & 0xFF) as u8;

    let header_info = pci_config_read32(bus, device, function, 0x0C);
    let header_type = ((header_info >> 16) & 0xFF) as u8;

    let irq = pci_config_read32(bus, device, function, 0x3C);
    let interrupt_line = (irq & 0xFF) as u8;

    let mut bar = [0u32; 6];
    for i in 0..6 {
        bar[i] = pci_config_read32(bus, device, function, 0x10 + (i as u8) * 4);
    }

    Some(PciDevice {
        bus, device, function,
        vendor_id, device_id,
        class_code, subclass, prog_if,
        header_type, interrupt_line,
        bar,
    })
}

/// Enumerate all PCI devices.
pub fn init() {
    let mut devices = PCI_DEVICES.lock();
    devices.clear();

    for bus in 0..=255u16 {
        for device in 0..32u8 {
            let id = pci_config_read32(bus as u8, device, 0, 0x00);
            if (id & 0xFFFF) == 0xFFFF {
                continue;
            }

            if let Some(dev) = scan_function(bus as u8, device, 0) {
                crate::serial_println!(
                    "[PCI] {:02x}:{:02x}.{} {:04x}:{:04x} class={:02x}.{:02x}",
                    bus, device, 0, dev.vendor_id, dev.device_id,
                    dev.class_code, dev.subclass
                );
                let is_multi = dev.header_type & 0x80 != 0;
                devices.push(dev);

                if is_multi {
                    for func in 1..8u8 {
                        if let Some(dev) = scan_function(bus as u8, device, func) {
                            crate::serial_println!(
                                "[PCI] {:02x}:{:02x}.{} {:04x}:{:04x} class={:02x}.{:02x}",
                                bus as u8, device, func, dev.vendor_id, dev.device_id,
                                dev.class_code, dev.subclass
                            );
                            devices.push(dev);
                        }
                    }
                }
            }
        }
    }

    crate::serial_println!("[PCI] Enumeration complete: {} devices found", devices.len());
}

/// Find a PCI device by class and subclass.
pub fn find_by_class(class: u8, subclass: u8) -> Option<PciDevice> {
    PCI_DEVICES.lock().iter().find(|d| d.class_code == class && d.subclass == subclass).copied()
}

/// Find a PCI device by vendor and device ID.
pub fn find_by_id(vendor: u16, device: u16) -> Option<PciDevice> {
    PCI_DEVICES.lock().iter().find(|d| d.vendor_id == vendor && d.device_id == device).copied()
}

/// Enable bus mastering for a PCI device.
pub fn enable_bus_master(bus: u8, device: u8, function: u8) {
    let cmd = pci_config_read32(bus, device, function, 0x04);
    pci_config_write32(bus, device, function, 0x04, cmd | 0x06); // Bus Master + Memory Space
}

/// Get all discovered PCI devices.
pub fn devices() -> Vec<PciDevice> {
    PCI_DEVICES.lock().clone()
}
