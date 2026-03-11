//! ATA PIO Block Device Driver
//!
//! Provides sector-level read/write access to IDE/ATA hard drives using
//! Programmed I/O (PIO) mode. This is the simplest (non-DMA) method of
//! talking to IDE drives — suitable for an educational OS.
//!
//! # Hardware
//! - Primary bus:   I/O ports 0x1F0–0x1F7, control 0x3F6
//! - Secondary bus: I/O ports 0x170–0x177, control 0x376
//!
//! We use 28-bit LBA addressing (supports up to 128 GiB).
//!
//! # References
//! - OSDev Wiki: <https://wiki.osdev.org/ATA_PIO_Mode>
//! - ATA-6 specification

use super::block::{BlockDevice, BlockError, SECTOR_SIZE};
use crate::hal;

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

/// Global device list cached after probing.
static ATA_DEVICES: Mutex<Vec<AtaPioDevice>> = Mutex::new(Vec::new());

// ── I/O Port Offsets ────────────────────────────────────────────────────────

/// Data register (16-bit read/write).
const ATA_REG_DATA: u16 = 0;
/// Error register (read) / Features (write).
const ATA_REG_ERROR: u16 = 1;
/// Sector count.
const ATA_REG_SECTOR_COUNT: u16 = 2;
/// LBA low byte (bits 0-7).
const ATA_REG_LBA_LO: u16 = 3;
/// LBA mid byte (bits 8-15).
const ATA_REG_LBA_MID: u16 = 4;
/// LBA high byte (bits 16-23).
const ATA_REG_LBA_HI: u16 = 5;
/// Drive/Head register (bits 24-27 of LBA + drive select).
const ATA_REG_DRIVE_HEAD: u16 = 6;
/// Status register (read) / Command register (write).
const ATA_REG_STATUS_CMD: u16 = 7;

// ── Status Register Bits ────────────────────────────────────────────────────

const ATA_SR_BSY: u8 = 0x80;  // Busy
const ATA_SR_DRDY: u8 = 0x40; // Drive ready
const ATA_SR_DRQ: u8 = 0x08;  // Data request
const ATA_SR_ERR: u8 = 0x01;  // Error

// ── Commands ────────────────────────────────────────────────────────────────

const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
const ATA_CMD_IDENTIFY: u8 = 0xEC;

// ── Bus Definitions ─────────────────────────────────────────────────────────

/// ATA bus base I/O ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaBus {
    Primary   = 0x1F0,
    Secondary = 0x170,
}

/// Drive on a bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaDrive {
    Master = 0,
    Slave  = 1,
}

// ── ATA PIO Device ──────────────────────────────────────────────────────────

/// An ATA PIO block device (IDE hard drive).
pub struct AtaPioDevice {
    /// Base I/O port for this bus.
    base: u16,
    /// Master or slave drive selection.
    drive: AtaDrive,
    /// Total sector count (from IDENTIFY).
    sectors: u64,
    /// Model string (from IDENTIFY, trimmed).
    #[allow(dead_code)]
    model: [u8; 40],
}

impl AtaPioDevice {
    /// Probe for an ATA drive on the given bus and drive slot.
    ///
    /// Returns `Some(device)` if a drive is present and responds to IDENTIFY.
    pub fn probe(bus: AtaBus, drive: AtaDrive) -> Option<Self> {
        let base = bus as u16;

        // Select drive.
        let drive_sel = match drive {
            AtaDrive::Master => 0xA0,
            AtaDrive::Slave  => 0xB0,
        };
        unsafe { hal::outb(base + ATA_REG_DRIVE_HEAD, drive_sel); }

        // Small delay — read status port 4 times (400ns on a real PC).
        for _ in 0..4 {
            unsafe { hal::inb(base + ATA_REG_STATUS_CMD); }
        }

        // Clear sector count and LBA registers.
        unsafe {
            hal::outb(base + ATA_REG_SECTOR_COUNT, 0);
            hal::outb(base + ATA_REG_LBA_LO, 0);
            hal::outb(base + ATA_REG_LBA_MID, 0);
            hal::outb(base + ATA_REG_LBA_HI, 0);
        }

        // Send IDENTIFY command.
        unsafe { hal::outb(base + ATA_REG_STATUS_CMD, ATA_CMD_IDENTIFY); }

        // Read status — if 0, no drive.
        let status = unsafe { hal::inb(base + ATA_REG_STATUS_CMD) };
        if status == 0 {
            return None;
        }

        // Wait for BSY to clear.
        let mut timeout = 100_000u32;
        loop {
            let s = unsafe { hal::inb(base + ATA_REG_STATUS_CMD) };
            if s & ATA_SR_BSY == 0 { break; }
            timeout = timeout.checked_sub(1)?;
        }

        // Check this is really ATA (not ATAPI): LBA_MID and LBA_HI should be 0.
        let lba_mid = unsafe { hal::inb(base + ATA_REG_LBA_MID) };
        let lba_hi  = unsafe { hal::inb(base + ATA_REG_LBA_HI) };
        if lba_mid != 0 || lba_hi != 0 {
            // Not a standard ATA device (could be ATAPI CD-ROM).
            return None;
        }

        // Wait for DRQ or ERR.
        timeout = 100_000;
        loop {
            let s = unsafe { hal::inb(base + ATA_REG_STATUS_CMD) };
            if s & ATA_SR_ERR != 0 { return None; }
            if s & ATA_SR_DRQ != 0 { break; }
            timeout = timeout.checked_sub(1)?;
        }

        // Read 256 words (512 bytes) of IDENTIFY data.
        let mut identify = [0u16; 256];
        for word in identify.iter_mut() {
            *word = unsafe { hal::inw(base + ATA_REG_DATA) };
        }

        // Extract total sectors (28-bit LBA: words 60-61).
        let sectors_28 = (identify[61] as u64) << 16 | (identify[60] as u64);

        // Try 48-bit LBA (words 100-103) if supported (bit 10 of word 83).
        let sectors = if identify[83] & (1 << 10) != 0 {
            let lba48 = (identify[103] as u64) << 48
                | (identify[102] as u64) << 32
                | (identify[101] as u64) << 16
                | (identify[100] as u64);
            if lba48 > 0 { lba48 } else { sectors_28 }
        } else {
            sectors_28
        };

        if sectors == 0 {
            return None;
        }

        // Extract model string (words 27-46, big-endian byte order per word).
        let mut model = [0u8; 40];
        for i in 0..20 {
            let w = identify[27 + i];
            model[i * 2] = (w >> 8) as u8;
            model[i * 2 + 1] = (w & 0xFF) as u8;
        }
        // Trim trailing spaces.
        let model_len = model.iter().rposition(|&b| b != b' ' && b != 0)
            .map(|i| i + 1).unwrap_or(0);

        let model_str = core::str::from_utf8(&model[..model_len]).unwrap_or("Unknown");

        crate::serial_println!(
            "[ATA] Found {:?} {:?}: {} sectors ({} MiB), model: {}",
            bus, drive, sectors,
            sectors * SECTOR_SIZE as u64 / (1024 * 1024),
            model_str
        );

        Some(Self { base, drive, sectors, model })
    }

    /// Wait for the drive to be not-busy and optionally wait for DRQ.
    fn wait_ready(&self, need_drq: bool) -> Result<(), BlockError> {
        let mut timeout = 1_000_000u32;
        loop {
            let status = unsafe { hal::inb(self.base + ATA_REG_STATUS_CMD) };
            if status & ATA_SR_ERR != 0 {
                return Err(BlockError::IoError);
            }
            if status & ATA_SR_BSY == 0 {
                if !need_drq || (status & ATA_SR_DRQ != 0) {
                    return Ok(());
                }
            }
            timeout = timeout.checked_sub(1).ok_or(BlockError::IoError)?;
        }
    }

    /// Select the drive and set up LBA addressing for a 28-bit LBA read/write.
    fn select_sector(&self, lba: u64, count: u8) -> Result<(), BlockError> {
        if lba + count as u64 > self.sectors {
            return Err(BlockError::OutOfRange);
        }

        // We use 28-bit LBA mode: bits 24-27 go into the drive/head register.
        let drive_bits: u8 = match self.drive {
            AtaDrive::Master => 0xE0,
            AtaDrive::Slave  => 0xF0,
        };

        self.wait_ready(false)?;

        unsafe {
            hal::outb(self.base + ATA_REG_DRIVE_HEAD, drive_bits | ((lba >> 24) as u8 & 0x0F));
            hal::outb(self.base + ATA_REG_SECTOR_COUNT, count);
            hal::outb(self.base + ATA_REG_LBA_LO, (lba & 0xFF) as u8);
            hal::outb(self.base + ATA_REG_LBA_MID, ((lba >> 8) & 0xFF) as u8);
            hal::outb(self.base + ATA_REG_LBA_HI, ((lba >> 16) & 0xFF) as u8);
        }

        Ok(())
    }

    /// Write sectors to the drive (PIO).
    #[allow(dead_code)]
    pub fn write_sectors_pio(&self, lba: u64, count: u32, data: &[u8]) -> Result<(), BlockError> {
        if data.len() < (count as usize) * SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }
        if count == 0 || count > 256 {
            return Err(BlockError::OutOfRange);
        }

        // Issue commands one sector at a time for reliability.
        for i in 0..count {
            self.select_sector(lba + i as u64, 1)?;
            unsafe { hal::outb(self.base + ATA_REG_STATUS_CMD, ATA_CMD_WRITE_SECTORS); }

            self.wait_ready(true)?;

            let offset = (i as usize) * SECTOR_SIZE;
            let sector_data = &data[offset..offset + SECTOR_SIZE];

            // Write 256 words (512 bytes) using rep outsw — single VM exit in KVM.
            unsafe {
                core::arch::asm!(
                    "rep outsw",
                    in("dx") self.base + ATA_REG_DATA,
                    inout("ecx") 256u32 => _,
                    in("rsi") sector_data.as_ptr(),
                    options(nostack, preserves_flags)
                );
            }

            // Flush — read status to ensure write is committed.
            self.wait_ready(false)?;
        }

        Ok(())
    }
}

impl BlockDevice for AtaPioDevice {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        if buf.len() < (count as usize) * SECTOR_SIZE {
            return Err(BlockError::BufferTooSmall);
        }
        if count == 0 || count > 256 {
            return Err(BlockError::OutOfRange);
        }

        // Read one sector at a time for reliability on PIO.
        for i in 0..count {
            self.select_sector(lba + i as u64, 1)?;
            unsafe { hal::outb(self.base + ATA_REG_STATUS_CMD, ATA_CMD_READ_SECTORS); }

            self.wait_ready(true)?;

            let offset = (i as usize) * SECTOR_SIZE;

            // Read 256 words (512 bytes) using rep insw — single VM exit in KVM,
            // avoiding 256 separate port-read VM exits in QEMU/nested environments.
            unsafe {
                core::arch::asm!(
                    "rep insw",
                    in("dx") self.base + ATA_REG_DATA,
                    inout("ecx") 256u32 => _,
                    in("rdi") buf.as_mut_ptr().add(offset),
                    options(nostack, preserves_flags)
                );
            }
        }

        Ok(())
    }

    fn write_sectors(&self, lba: u64, count: u32, data: &[u8]) -> Result<(), BlockError> {
        self.write_sectors_pio(lba, count, data)
    }
}

// ── Disk Discovery ──────────────────────────────────────────────────────────

/// Probe all ATA buses and return discovered devices.
///
/// Checks primary master/slave and secondary master/slave.
pub fn probe_all() -> Vec<AtaPioDevice> {
    let mut devices = Vec::new();

    let buses = [
        (AtaBus::Primary, "Primary"),
        (AtaBus::Secondary, "Secondary"),
    ];
    let drives = [
        (AtaDrive::Master, "Master"),
        (AtaDrive::Slave, "Slave"),
    ];

    for &(bus, bus_name) in &buses {
        for &(drive, drive_name) in &drives {
            crate::serial_println!("[ATA] Probing {} {}...", bus_name, drive_name);
            if let Some(dev) = AtaPioDevice::probe(bus, drive) {
                devices.push(dev);
            }
        }
    }

    if devices.is_empty() {
        crate::serial_println!("[ATA] No ATA drives found");
    } else {
        crate::serial_println!("[ATA] Found {} ATA drive(s)", devices.len());
    }

    devices
}

/// Initialize ATA subsystem: probe all buses and cache discovered devices.
pub fn init() {
    let devices = probe_all();
    *ATA_DEVICES.lock() = devices;
}

/// Read sectors from ATA drive `drive` (0-based index) using cached devices.
pub fn read_sectors(drive: u8, lba: u32, count: u8, buf: &mut [u8]) -> Result<(), &'static str> {
    let devices = ATA_DEVICES.lock();
    let dev = devices.get(drive as usize).ok_or("ATA drive not found")?;
    dev.read_sectors(lba as u64, count as u32, buf).map_err(|_| "ATA read error")
}

/// Write sectors to ATA drive `drive` (0-based index) using cached devices.
pub fn write_sectors(drive: u8, lba: u32, count: u8, data: &[u8]) -> Result<(), &'static str> {
    let devices = ATA_DEVICES.lock();
    let dev = devices.get(drive as usize).ok_or("ATA drive not found")?;
    dev.write_sectors_pio(lba as u64, count as u32, data).map_err(|_| "ATA write error")
}
