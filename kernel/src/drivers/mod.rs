//! Device Drivers
//!
//! Provides the driver subsystem with serial, framebuffer console, keyboard,
//! block device abstraction, and ATA PIO disk drivers.

pub mod ac97;
pub mod ahci;
pub mod ata;
pub mod block;
pub mod console;
pub mod keyboard;
pub mod mouse;
pub mod partition;
pub mod pci;
pub mod serial;
pub mod tty;
pub mod usb;
pub mod vmware_svga;

use astryx_shared::BootInfo;

/// Initialize all drivers.
pub fn init(boot_info: &BootInfo) {
    serial::init();
    console::init(boot_info);
    keyboard::init();
    mouse::init(boot_info.framebuffer.width, boot_info.framebuffer.height);
    tty::init();
    ata::init();
    pci::init();
    if ahci::init() {
        crate::serial_println!("[DRIVERS] AHCI/SATA initialized");
    }
    if ac97::init() {
        crate::serial_println!("[DRIVERS] AC97 audio initialized");
    }
    usb::init();
    // Note: vmware_svga::init() is called later in Phase 10b (after PCI init)
    crate::serial_println!("[DRIVERS] All drivers initialized");
}
