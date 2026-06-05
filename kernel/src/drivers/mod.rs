//! Device Drivers
//!
//! Provides the driver subsystem with serial, framebuffer console, keyboard,
//! block device abstraction, and ATA PIO disk drivers.

pub mod ac97;
pub mod ahci;
pub mod rtc;
pub mod ata;
pub mod block;
pub mod blk_trace;
pub mod log_ring;
pub mod console;
pub mod keyboard;
pub mod mouse;
pub mod partition;
pub mod pci;
pub mod serial;
pub mod pty;
pub mod tty;
pub mod usb;
pub mod virtio_blk;
#[cfg(feature = "qga")]
pub mod virtio_serial;
pub mod vmware_svga;

use astryx_shared::BootInfo;

/// Initialize all drivers.
pub fn init(boot_info: &BootInfo) {
    serial::init();
    // Bring up the near-zero-overhead log ring early (right after COM1) so the
    // high-volume fast-log path has its PMM-backed buffer before the firehose
    // trace families start emitting.  Until this runs, `serial_fast_println!`
    // transparently falls back to COM1.  The PMM is already initialised by the
    // time drivers::init runs (see virtio_blk below, which also alloc_pages).
    if log_ring::init() {
        crate::serial_println!("[DRIVERS] Log ring initialized (cheap high-volume log transport)");
    }
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
    if virtio_blk::init() {
        crate::serial_println!("[DRIVERS] Virtio-blk initialized");
    }
    #[cfg(feature = "qga")]
    {
        if virtio_serial::init() {
            crate::serial_println!("[DRIVERS] Virtio-serial initialized (/dev/vport0p0)");
        }
    }
    // Note: vmware_svga::init() is called later in Phase 10b (after PCI init)
    crate::serial_println!("[DRIVERS] All drivers initialized");
}
