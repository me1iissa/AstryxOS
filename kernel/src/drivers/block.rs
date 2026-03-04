//! Block Device Abstraction
//!
//! Provides a trait for reading sectors from block devices. Implementations
//! include MemoryBlockDevice (for in-memory images) and can be extended with
//! ATA PIO, AHCI, or virtio-blk drivers.

extern crate alloc;

/// Sector size in bytes (standard for ATA/IDE/SATA).
pub const SECTOR_SIZE: usize = 512;

/// Error type for block device operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// Attempted to read beyond the device's capacity.
    OutOfRange,
    /// Hardware or I/O error during the read.
    IoError,
    /// The buffer is too small for the requested read.
    BufferTooSmall,
}

impl From<BlockError> for astryx_shared::NtStatus {
    fn from(e: BlockError) -> Self {
        use astryx_shared::ntstatus::*;
        match e {
            BlockError::OutOfRange => STATUS_DEVICE_OUT_OF_RANGE,
            BlockError::IoError => STATUS_IO_DEVICE_ERROR,
            BlockError::BufferTooSmall => STATUS_IO_BUFFER_TOO_SMALL,
        }
    }
}

/// Block device trait — sector-based access.
pub trait BlockDevice: Send + Sync {
    /// Return the total number of sectors on the device.
    fn sector_count(&self) -> u64;

    /// Read `count` sectors starting at `lba` into `buf`.
    ///
    /// `buf` must be at least `count * SECTOR_SIZE` bytes.
    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError>;

    /// Read a single sector at `lba` into `buf` (convenience method).
    fn read_sector(&self, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), BlockError> {
        self.read_sectors(lba, 1, buf)
    }

    /// Write `count` sectors starting at `lba` from `data`.
    ///
    /// `data` must be at least `count * SECTOR_SIZE` bytes.
    fn write_sectors(&self, lba: u64, count: u32, data: &[u8]) -> Result<(), BlockError>;

    /// Write a single sector at `lba` from `data` (convenience method).
    fn write_sector(&self, lba: u64, data: &[u8; SECTOR_SIZE]) -> Result<(), BlockError> {
        self.write_sectors(lba, 1, data)
    }
}

/// A block device backed by an in-memory byte slice.
///
/// Used for testing (e.g., parsing an in-memory FAT32 image) and for
/// images loaded by the bootloader.
pub struct MemoryBlockDevice {
    data: &'static [u8],
}

impl MemoryBlockDevice {
    /// Create a new MemoryBlockDevice wrapping a static byte slice.
    pub const fn new(data: &'static [u8]) -> Self {
        Self { data }
    }

    /// Get the raw underlying data.
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl BlockDevice for MemoryBlockDevice {
    fn sector_count(&self) -> u64 {
        (self.data.len() / SECTOR_SIZE) as u64
    }

    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        let start = (lba as usize) * SECTOR_SIZE;
        let len = (count as usize) * SECTOR_SIZE;

        if buf.len() < len {
            return Err(BlockError::BufferTooSmall);
        }
        if start + len > self.data.len() {
            return Err(BlockError::OutOfRange);
        }

        buf[..len].copy_from_slice(&self.data[start..start + len]);
        Ok(())
    }

    fn write_sectors(&self, _lba: u64, _count: u32, _data: &[u8]) -> Result<(), BlockError> {
        // In-memory block device backed by &'static [u8] is read-only.
        Err(BlockError::IoError)
    }
}

// ── AHCI Block Device ──────────────────────────────────────────────────────

/// A block device backed by an AHCI SATA port.
pub struct AhciBlockDevice {
    port: u8,
}

impl AhciBlockDevice {
    /// Create a new AHCI block device for the given SATA port.
    pub fn new(port: u8) -> Self {
        Self { port }
    }
}

impl BlockDevice for AhciBlockDevice {
    fn sector_count(&self) -> u64 {
        // AHCI IDENTIFY would give us exact count; use a large default.
        // For a 64 MiB disk: 64 * 1024 * 1024 / 512 = 131072 sectors.
        // We'll return a generous upper bound and let I/O errors handle OOB.
        131072
    }

    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        let len = (count as usize) * SECTOR_SIZE;
        if buf.len() < len {
            return Err(BlockError::BufferTooSmall);
        }
        super::ahci::read_sectors(self.port, lba, count as u16, buf)
            .map_err(|_| BlockError::IoError)
    }

    fn write_sectors(&self, lba: u64, count: u32, data: &[u8]) -> Result<(), BlockError> {
        let len = (count as usize) * SECTOR_SIZE;
        if data.len() < len {
            return Err(BlockError::BufferTooSmall);
        }
        super::ahci::write_sectors(self.port, lba, count as u16, data)
            .map_err(|_| BlockError::IoError)
    }
}
