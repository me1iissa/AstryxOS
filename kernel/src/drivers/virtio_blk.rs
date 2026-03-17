//! Virtio-blk PCI Block Device Driver (Legacy Interface)
//!
//! Implements a virtio block device using the legacy (transitional) PCI
//! interface.  This replaces the extremely slow ATA PIO path (~100us per
//! `inb` on WSL2/KVM) with virtio's virtqueue-based I/O, providing
//! 50-100x faster disk reads.
//!
//! # Protocol
//!
//! Uses a single request virtqueue (queue 0).  Each I/O request is a
//! 3-descriptor chain: header (type + sector) -> data buffer -> status byte.
//! The driver polls the used ring for completion (no interrupt handler needed).
//!
//! # References
//! - Virtio 1.0 spec, Section 5.2 (Block Device)
//! - Legacy interface: <https://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html>

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::block::{BlockDevice, BlockError, SECTOR_SIZE};
use crate::hal;
use crate::mm::pmm;

// ── Virtio PCI Constants ────────────────────────────────────────────────────

/// Red Hat / Virtio vendor ID.
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Legacy virtio-blk device ID (transitional).
const VIRTIO_BLK_DEVICE_LEGACY: u16 = 0x1001;
/// Virtio subsystem ID for block devices.
const VIRTIO_SUBSYS_BLK: u16 = 2;

// ── Legacy Virtio Register Offsets (from BAR0 I/O base) ─────────────────────

const VIRTIO_REG_DEVICE_FEATURES: u16 = 0x00; // u32 RO
const VIRTIO_REG_GUEST_FEATURES:  u16 = 0x04; // u32 RW
const VIRTIO_REG_QUEUE_ADDRESS:   u16 = 0x08; // u32 RW  (PFN = phys >> 12)
const VIRTIO_REG_QUEUE_SIZE:      u16 = 0x0C; // u16 RO
const VIRTIO_REG_QUEUE_SELECT:    u16 = 0x0E; // u16 RW
const VIRTIO_REG_QUEUE_NOTIFY:    u16 = 0x10; // u16 WO
const VIRTIO_REG_DEVICE_STATUS:   u16 = 0x12; // u8  RW
const _VIRTIO_REG_ISR_STATUS:     u16 = 0x13; // u8  RO
// Device-specific config starts at +0x14 for legacy.
const VIRTIO_REG_BLK_CAPACITY_LO: u16 = 0x14; // u32 RO (low 32 bits)
const VIRTIO_REG_BLK_CAPACITY_HI: u16 = 0x18; // u32 RO (high 32 bits)

// ── Device Status Bits ──────────────────────────────────────────────────────

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER:      u8 = 2;
const VIRTIO_STATUS_DRIVER_OK:   u8 = 4;

// ── Virtqueue Descriptor Flags ──────────────────────────────────────────────

const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

// ── Virtio Block Request Types ──────────────────────────────────────────────

const VIRTIO_BLK_T_IN:  u32 = 0; // Read
const VIRTIO_BLK_T_OUT: u32 = 1; // Write

// ── Higher-Half Mapping ─────────────────────────────────────────────────────

const PHYS_OFFSET: u64 = astryx_shared::KERNEL_VIRT_BASE;

/// Convert a physical address to a virtual pointer in the kernel higher-half.
#[inline]
fn phys_to_virt<T>(phys: u64) -> *mut T {
    (PHYS_OFFSET + phys) as *mut T
}

// ── Virtqueue Layout Helpers ────────────────────────────────────────────────

/// Calculate the byte offset of the available ring within the virtqueue.
/// The descriptor table occupies 16 * queue_size bytes, immediately followed
/// by the available ring.
#[inline]
fn avail_ring_offset(queue_size: u16) -> usize {
    (queue_size as usize) * 16
}

/// Calculate the byte offset of the used ring within the virtqueue.
/// Per the legacy spec, the used ring starts at the first page-aligned
/// address after the available ring.
#[inline]
fn used_ring_offset(queue_size: u16) -> usize {
    let avail_end = avail_ring_offset(queue_size) + 4 + (queue_size as usize) * 2;
    // Align up to 4096.
    (avail_end + 4095) & !4095
}

/// Calculate the total bytes needed for a virtqueue with the given size.
#[inline]
fn virtqueue_total_bytes(queue_size: u16) -> usize {
    let used_off = used_ring_offset(queue_size);
    let used_end = used_off + 4 + (queue_size as usize) * 8;
    // Align up to page boundary.
    (used_end + 4095) & !4095
}

// ── Request Header ──────────────────────────────────────────────────────────

/// Virtio block request header (16 bytes).
#[repr(C)]
struct VirtioBlkReqHeader {
    type_: u32,
    reserved: u32,
    sector: u64,
}

// ── Driver State ────────────────────────────────────────────────────────────

/// Virtio-blk device state.
struct VirtioBlkDevice {
    /// BAR0 I/O port base.
    io_base: u16,
    /// Disk capacity in sectors.
    capacity: u64,
    /// Virtqueue size (number of descriptors).
    queue_size: u16,
    /// Physical base of the virtqueue memory.
    vq_phys: u64,
    /// Last seen used ring index (for polling).
    last_used_idx: u16,
}

/// Global virtio-blk device (if found).
static VIRTIO_BLK: Mutex<Option<VirtioBlkDevice>> = Mutex::new(None);
/// Fast check without acquiring the mutex on every block I/O call.
static VIRTIO_BLK_AVAILABLE: AtomicBool = AtomicBool::new(false);

// ── Initialization ──────────────────────────────────────────────────────────

/// Initialize the virtio-blk driver.  Scans PCI for a virtio block device,
/// performs device setup, and allocates the virtqueue.
/// Returns true if a device was found and initialized successfully.
pub fn init() -> bool {
    let pci_dev = match find_virtio_blk_pci() {
        Some(d) => d,
        None => {
            crate::serial_println!("[VIRTIO-BLK] No virtio-blk PCI device found");
            return false;
        }
    };

    crate::serial_println!(
        "[VIRTIO-BLK] Found device at PCI {:02x}:{:02x}.{} (vendor={:04x} device={:04x})",
        pci_dev.bus, pci_dev.device, pci_dev.function,
        pci_dev.vendor_id, pci_dev.device_id
    );

    // BAR0 must be an I/O port BAR (bit 0 = 1).
    let bar0 = pci_dev.bar[0];
    if bar0 & 1 == 0 {
        crate::serial_println!("[VIRTIO-BLK] BAR0 is not I/O space, aborting");
        return false;
    }
    let io_base = (bar0 & 0xFFFF_FFFC) as u16;

    crate::serial_println!("[VIRTIO-BLK] I/O base = {:#06x}", io_base);

    // Enable bus mastering + I/O space access.
    super::pci::enable_bus_master(pci_dev.bus, pci_dev.device, pci_dev.function);
    // Also ensure I/O space is enabled (bit 0 of PCI command register).
    let cmd = super::pci::pci_config_read32(pci_dev.bus, pci_dev.device, pci_dev.function, 0x04);
    super::pci::pci_config_write32(pci_dev.bus, pci_dev.device, pci_dev.function, 0x04, cmd | 0x01);

    // ── Device Reset + Init Sequence (Legacy) ───────────────────────────

    // SAFETY: Writing to I/O ports of the discovered virtio PCI device.
    // The io_base was read from a valid BAR0 of a known virtio device.
    unsafe {
        // 1. Reset device.
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);

        // 2. Acknowledge.
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. Driver.
        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );

        // 4. Read device features, write guest features (accept none for basic I/O).
        let _features = hal::inl(io_base + VIRTIO_REG_DEVICE_FEATURES);
        hal::outl(io_base + VIRTIO_REG_GUEST_FEATURES, 0);

        // 5. Read device capacity (sectors).
        let cap_lo = hal::inl(io_base + VIRTIO_REG_BLK_CAPACITY_LO) as u64;
        let cap_hi = hal::inl(io_base + VIRTIO_REG_BLK_CAPACITY_HI) as u64;
        let capacity = (cap_hi << 32) | cap_lo;
        crate::serial_println!("[VIRTIO-BLK] Capacity: {} sectors ({} MiB)", capacity, capacity * 512 / (1024 * 1024));

        // 6. Set up virtqueue 0.
        hal::outw(io_base + VIRTIO_REG_QUEUE_SELECT, 0);
        let queue_size = hal::inw(io_base + VIRTIO_REG_QUEUE_SIZE);
        if queue_size == 0 {
            crate::serial_println!("[VIRTIO-BLK] Queue 0 not available");
            hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0); // reset
            return false;
        }
        crate::serial_println!("[VIRTIO-BLK] Queue 0 size: {}", queue_size);

        // Allocate physically contiguous pages for the virtqueue.
        let total_bytes = virtqueue_total_bytes(queue_size);
        let pages_needed = (total_bytes + 4095) / 4096;
        let vq_phys = match pmm::alloc_pages(pages_needed) {
            Some(p) => p,
            None => {
                crate::serial_println!("[VIRTIO-BLK] Failed to allocate {} pages for virtqueue", pages_needed);
                hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
                return false;
            }
        };

        // Zero the entire virtqueue region.
        let vq_virt = phys_to_virt::<u8>(vq_phys);
        core::ptr::write_bytes(vq_virt, 0, total_bytes);

        // Tell the device the page frame number of the virtqueue.
        let pfn = (vq_phys >> 12) as u32;
        hal::outl(io_base + VIRTIO_REG_QUEUE_ADDRESS, pfn);

        // 7. Mark driver ready.
        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
        );

        crate::serial_println!(
            "[VIRTIO-BLK] Initialized: io={:#06x}, capacity={} sectors, queue_size={}, vq_phys={:#x}",
            io_base, capacity, queue_size, vq_phys
        );

        *VIRTIO_BLK.lock() = Some(VirtioBlkDevice {
            io_base,
            capacity,
            queue_size,
            vq_phys,
            last_used_idx: 0,
        });
        VIRTIO_BLK_AVAILABLE.store(true, Ordering::Release);
    }

    true
}

// ── PCI Discovery ───────────────────────────────────────────────────────────

/// Find a virtio-blk PCI device.
fn find_virtio_blk_pci() -> Option<super::pci::PciDevice> {
    let devices = super::pci::devices();
    for dev in &devices {
        if dev.vendor_id == VIRTIO_VENDOR {
            // Legacy device ID 0x1001 is virtio-blk.
            if dev.device_id == VIRTIO_BLK_DEVICE_LEGACY {
                return Some(*dev);
            }
            // Also check subsystem ID for generic virtio devices.
            let subsys = super::pci::pci_config_read32(
                dev.bus, dev.device, dev.function, 0x2C,
            );
            let subsys_id = (subsys >> 16) as u16;
            if subsys_id == VIRTIO_SUBSYS_BLK {
                return Some(*dev);
            }
        }
    }
    None
}

// ── I/O Operations ──────────────────────────────────────────────────────────

/// Submit a virtio-blk request and poll for completion.
///
/// `req_type` is VIRTIO_BLK_T_IN (read) or VIRTIO_BLK_T_OUT (write).
/// `sector` is the starting LBA.
/// `data` points to the data buffer (count * 512 bytes).
/// `count` is the number of sectors.
///
/// Returns Ok(()) on success, Err(BlockError) on failure.
fn submit_request(
    dev: &mut VirtioBlkDevice,
    req_type: u32,
    sector: u64,
    data: *mut u8,
    data_len: usize,
) -> Result<(), BlockError> {
    let io_base = dev.io_base;
    let qs = dev.queue_size;
    let vq_base = phys_to_virt::<u8>(dev.vq_phys);

    // We use 3 descriptors per request.  Pick descriptors 0, 1, 2.
    // Since we hold the mutex, only one request is in flight at a time,
    // so we can always reuse the same descriptor indices.
    let desc_base = vq_base; // descriptor table at offset 0
    let avail_base = unsafe { vq_base.add(avail_ring_offset(qs)) };
    let used_base = unsafe { vq_base.add(used_ring_offset(qs)) };

    // ── Build Request Header (on the virtqueue page itself) ─────────

    // We need the header in a physically contiguous location.  Use a small
    // region right after the used ring for the header + status byte.
    // The used ring ends at: used_ring_offset + 4 + qs*8.
    // We place:
    //   - req header (16 bytes) at used_ring_end
    //   - status byte (1 byte) at used_ring_end + 16
    let used_ring_end = used_ring_offset(qs) + 4 + (qs as usize) * 8;
    let header_offset = (used_ring_end + 15) & !15; // align to 16
    let status_offset = header_offset + 16;

    let header_virt = unsafe { vq_base.add(header_offset) } as *mut VirtioBlkReqHeader;
    let status_virt = unsafe { vq_base.add(status_offset) } as *mut u8;

    let header_phys = dev.vq_phys + header_offset as u64;
    let status_phys = dev.vq_phys + status_offset as u64;

    // SAFETY: We exclusively own this memory region while holding the mutex.
    // The header and status are within the allocated virtqueue pages.
    unsafe {
        (*header_virt).type_ = req_type;
        (*header_virt).reserved = 0;
        (*header_virt).sector = sector;
        *status_virt = 0xFF; // sentinel — device will overwrite with 0 on success
    }

    // Convert data pointer to physical address.
    // Kernel buffers may be in either:
    //   - Identity-mapped low memory (boot stack, below PHYS_OFFSET): phys = virt
    //   - Higher-half mapped memory (kernel heap/thread stacks): phys = virt - PHYS_OFFSET
    let data_virt = data as u64;
    let data_phys = if data_virt >= PHYS_OFFSET {
        data_virt - PHYS_OFFSET
    } else {
        data_virt
    };

    // ── Fill Descriptor Table ───────────────────────────────────────

    // Descriptor 0: request header (device reads).
    // SAFETY: Writing to the descriptor table within our allocated virtqueue memory.
    unsafe {
        let d0 = desc_base as *mut u64;
        // addr
        d0.write_volatile(header_phys);
        // len (u32) + flags (u16) + next (u16) packed into second u64
        let d0_meta = desc_base.add(8) as *mut u32;
        d0_meta.write_volatile(16); // len = 16 bytes
        let d0_flags = desc_base.add(12) as *mut u16;
        d0_flags.write_volatile(VRING_DESC_F_NEXT); // has next
        let d0_next = desc_base.add(14) as *mut u16;
        d0_next.write_volatile(1); // next = descriptor 1
    }

    // Descriptor 1: data buffer.
    let desc1 = unsafe { desc_base.add(16) };
    let data_flags = if req_type == VIRTIO_BLK_T_IN {
        VRING_DESC_F_NEXT | VRING_DESC_F_WRITE // device writes to buffer (read request)
    } else {
        VRING_DESC_F_NEXT // device reads from buffer (write request)
    };
    // SAFETY: Writing to descriptor 1 within our allocated virtqueue memory.
    unsafe {
        let d1_addr = desc1 as *mut u64;
        d1_addr.write_volatile(data_phys);
        let d1_len = desc1.add(8) as *mut u32;
        d1_len.write_volatile(data_len as u32);
        let d1_flags = desc1.add(12) as *mut u16;
        d1_flags.write_volatile(data_flags);
        let d1_next = desc1.add(14) as *mut u16;
        d1_next.write_volatile(2); // next = descriptor 2
    }

    // Descriptor 2: status byte (device writes).
    let desc2 = unsafe { desc_base.add(32) };
    // SAFETY: Writing to descriptor 2 within our allocated virtqueue memory.
    unsafe {
        let d2_addr = desc2 as *mut u64;
        d2_addr.write_volatile(status_phys);
        let d2_len = desc2.add(8) as *mut u32;
        d2_len.write_volatile(1);
        let d2_flags = desc2.add(12) as *mut u16;
        d2_flags.write_volatile(VRING_DESC_F_WRITE); // device writes status
        let d2_next = desc2.add(14) as *mut u16;
        d2_next.write_volatile(0); // no next
    }

    // ── Submit to Available Ring ────────────────────────────────────

    // avail ring layout: flags(u16), idx(u16), ring[qs](u16 each)
    // SAFETY: Writing to the available ring within our allocated virtqueue memory.
    let avail_idx = unsafe {
        let avail_idx_ptr = avail_base.add(2) as *mut u16;
        let idx = avail_idx_ptr.read_volatile();

        // Write descriptor chain head (0) at ring[idx % qs].
        let ring_entry = avail_base.add(4 + ((idx % qs) as usize) * 2) as *mut u16;
        ring_entry.write_volatile(0); // head descriptor index

        // Memory barrier — ensure descriptor writes are visible before we
        // advance the index.
        core::sync::atomic::fence(Ordering::SeqCst);

        // Increment avail idx.
        avail_idx_ptr.write_volatile(idx.wrapping_add(1));

        idx.wrapping_add(1)
    };
    let _ = avail_idx;

    // ── Notify Device ──────────────────────────────────────────────

    // SAFETY: Writing to the notify register of our discovered virtio device.
    unsafe {
        hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, 0);
    }

    // ── Poll Used Ring for Completion ──────────────────────────────

    let used_idx_ptr = unsafe { used_base.add(2) as *const u16 };
    let expected_used = dev.last_used_idx.wrapping_add(1);

    let mut timeout = 10_000_000u32;
    loop {
        // SAFETY: Reading the used ring index from our virtqueue memory.
        let current_used = unsafe { used_idx_ptr.read_volatile() };
        if current_used == expected_used {
            break;
        }
        timeout = timeout.checked_sub(1).ok_or(BlockError::IoError)?;
        core::hint::spin_loop();
    }

    dev.last_used_idx = expected_used;

    // ── Check Status Byte ──────────────────────────────────────────

    // SAFETY: The device has written the status byte; we read it back.
    let status = unsafe { status_virt.read_volatile() };

    if status != 0 {
        crate::serial_println!("[VIRTIO-BLK] Request failed: status={}", status);
        return Err(BlockError::IoError);
    }

    Ok(())
}

// ── BlockDevice Implementation ──────────────────────────────────────────────

/// A virtio-blk block device that implements the BlockDevice trait.
///
/// This is a zero-size wrapper — all state lives in the global VIRTIO_BLK.
/// Multiple callers can safely use it because submit_request holds the mutex.
pub struct VirtioBlkBlockDevice;

impl BlockDevice for VirtioBlkBlockDevice {
    fn sector_count(&self) -> u64 {
        VIRTIO_BLK.lock().as_ref().map_or(0, |d| d.capacity)
    }

    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        let needed = (count as usize) * SECTOR_SIZE;
        if buf.len() < needed {
            return Err(BlockError::BufferTooSmall);
        }
        if count == 0 {
            return Ok(());
        }

        let mut dev = VIRTIO_BLK.lock();
        let dev = dev.as_mut().ok_or(BlockError::IoError)?;

        if lba + count as u64 > dev.capacity {
            return Err(BlockError::OutOfRange);
        }

        // Submit one request for the entire read.  Virtio can handle
        // multi-sector requests natively — no need to loop sector by sector.
        // However, very large requests may exceed descriptor data size limits,
        // so batch in chunks of 128 sectors (64 KiB) to be safe.
        const MAX_SECTORS: u32 = 128;
        let mut sector_idx = 0u32;

        while sector_idx < count {
            let batch = core::cmp::min(count - sector_idx, MAX_SECTORS);
            let offset = (sector_idx as usize) * SECTOR_SIZE;
            let batch_len = (batch as usize) * SECTOR_SIZE;
            let data_ptr = unsafe { buf.as_mut_ptr().add(offset) };

            submit_request(
                dev,
                VIRTIO_BLK_T_IN,
                lba + sector_idx as u64,
                data_ptr,
                batch_len,
            )?;

            sector_idx += batch;
        }

        Ok(())
    }

    fn write_sectors(&self, lba: u64, count: u32, data: &[u8]) -> Result<(), BlockError> {
        let needed = (count as usize) * SECTOR_SIZE;
        if data.len() < needed {
            return Err(BlockError::BufferTooSmall);
        }
        if count == 0 {
            return Ok(());
        }

        let mut dev = VIRTIO_BLK.lock();
        let dev = dev.as_mut().ok_or(BlockError::IoError)?;

        if lba + count as u64 > dev.capacity {
            return Err(BlockError::OutOfRange);
        }

        const MAX_SECTORS: u32 = 128;
        let mut sector_idx = 0u32;

        while sector_idx < count {
            let batch = core::cmp::min(count - sector_idx, MAX_SECTORS);
            let offset = (sector_idx as usize) * SECTOR_SIZE;
            let batch_len = (batch as usize) * SECTOR_SIZE;
            // SAFETY: We need a *mut u8 for the submit_request interface but
            // we won't actually write to it for VIRTIO_BLK_T_OUT — the device
            // reads from this buffer.
            let data_ptr = unsafe { data.as_ptr().add(offset) as *mut u8 };

            submit_request(
                dev,
                VIRTIO_BLK_T_OUT,
                lba + sector_idx as u64,
                data_ptr,
                batch_len,
            )?;

            sector_idx += batch;
        }

        Ok(())
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Check if a virtio-blk device is available.
pub fn is_available() -> bool {
    VIRTIO_BLK_AVAILABLE.load(Ordering::Acquire)
}

/// Get the disk capacity in sectors (0 if no device).
pub fn capacity() -> u64 {
    VIRTIO_BLK.lock().as_ref().map_or(0, |d| d.capacity)
}
