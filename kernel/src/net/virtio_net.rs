//! Virtio-net device driver (PCI, legacy interface)
//!
//! QEMU provides a virtio-net PCI device. This driver discovers it via PCI
//! configuration space and sets up virtqueues for packet TX/RX.
//!
//! For now this is a stub that provides the interface.
//! Full implementation requires PCI bus enumeration and virtqueue setup.

extern crate alloc;

use spin::Mutex;

static NET_AVAILABLE: Mutex<bool> = Mutex::new(false);

/// Initialize the virtio-net device.
/// Returns true if a device was found and initialized.
pub fn init() -> bool {
    // Scan PCI bus for virtio-net device (vendor=0x1AF4, device=0x1000).
    // For now, we do a basic PCI config space scan.
    
    if let Some(_base_addr) = scan_pci_for_virtio_net() {
        *NET_AVAILABLE.lock() = true;
        true
    } else {
        false
    }
}

/// Scan PCI bus for virtio-net device.
fn scan_pci_for_virtio_net() -> Option<u32> {
    // PCI configuration space access via I/O ports 0xCF8/0xCFC.
    for bus in 0u8..=255 {
        for device in 0u8..32 {
            let id = pci_read_config(bus, device, 0, 0x00);
            if id == 0xFFFF_FFFF { continue; }
            
            let vendor = (id & 0xFFFF) as u16;
            let dev_id = (id >> 16) as u16;
            
            // virtio-net: vendor=0x1AF4, device ID 0x1000 (legacy) or 0x1041 (modern)
            if vendor == 0x1AF4 && (dev_id == 0x1000 || dev_id == 0x1041) {
                crate::serial_println!("[VIRTIO-NET] Found device at PCI {}:{}.0", bus, device);
                
                // Read subsystem ID to confirm it's network
                let subsys = pci_read_config(bus, device, 0, 0x2C);
                let subsys_id = (subsys >> 16) as u16;
                
                if subsys_id == 1 || dev_id == 0x1041 {
                    // Read BAR0 for I/O base address
                    let bar0 = pci_read_config(bus, device, 0, 0x10);
                    
                    // Read MAC address from device config space
                    if bar0 & 1 != 0 {
                        let io_base = (bar0 & 0xFFFF_FFFC) as u16;
                        read_mac_from_device(io_base);
                    }
                    
                    return Some(bar0);
                }
            }
        }
    }
    None
}

/// Read PCI configuration space.
fn pci_read_config(bus: u8, device: u8, func: u8, offset: u8) -> u32 {
    let address: u32 = 0x8000_0000
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    
    unsafe {
        crate::hal::outl(0xCF8, address);
        crate::hal::inl(0xCFC)
    }
}

/// Read MAC address from the virtio device I/O space.
fn read_mac_from_device(io_base: u16) {
    // In virtio legacy, the MAC is at device-specific config offset 0x14.
    // Device config starts after the common virtio header (20 bytes for legacy).
    let mac_offset = io_base + 0x14;
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = unsafe { crate::hal::inb(mac_offset + i as u16) };
    }
    
    // Only use it if it's not all zeros.
    if mac.iter().any(|&b| b != 0) {
        super::set_our_mac(mac);
    }
}

/// Send a packet via virtio-net.
pub fn send_packet(data: &[u8]) {
    if !*NET_AVAILABLE.lock() { return; }
    // TODO: Virtqueue TX submission
    let _ = data;
}

/// Check for received packets.
pub fn poll_rx() {
    if !*NET_AVAILABLE.lock() { return; }
    // TODO: Virtqueue RX polling
}

/// Check if network is available.
pub fn is_available() -> bool {
    *NET_AVAILABLE.lock()
}
