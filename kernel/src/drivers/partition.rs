//! MBR and GPT Partition Table Parser
//!
//! Scans a block device for an MBR or GPT partition table and returns
//! a list of discovered partitions.  Also provides `PartitionBlockDevice`
//! which wraps an inner `BlockDevice` to expose a single partition as
//! its own block device.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::block::{BlockDevice, BlockError, SECTOR_SIZE};

// ── Constants ───────────────────────────────────────────────────────────────

/// MBR boot signature at offset 510.
const MBR_SIGNATURE: u16 = 0xAA55;

/// Offset of the partition table inside the MBR.
const MBR_PARTITION_TABLE_OFFSET: usize = 446;

/// Size of one MBR partition entry.
const MBR_ENTRY_SIZE: usize = 16;

/// Number of primary partition entries in an MBR.
const MBR_MAX_ENTRIES: usize = 4;

/// GPT header signature.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

// ── Known GPT Type GUIDs (stored in mixed-endian on-disk order) ─────────

/// Microsoft Basic Data (FAT32, NTFS, exFAT)
/// EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
const GPT_TYPE_MICROSOFT_BASIC_DATA: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, // first 4 bytes LE
    0xE5, 0xB9,             // next 2 bytes LE
    0x33, 0x44,             // next 2 bytes LE
    0x87, 0xC0,             // big-endian from here
    0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

/// Linux Filesystem
/// 0FC63DAF-8483-4772-8E79-3D69D8477DE4
const GPT_TYPE_LINUX_FILESYSTEM: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F,
    0x83, 0x84,
    0x72, 0x47,
    0x8E, 0x79,
    0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

/// EFI System Partition
/// C12A7328-F81F-11D2-BA4B-00A0C93EC93B
const GPT_TYPE_EFI_SYSTEM: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1,
    0x1F, 0xF8,
    0xD2, 0x11,
    0xBA, 0x4B,
    0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

/// All-zero GUID means unused entry.
const GPT_TYPE_UNUSED: [u8; 16] = [0u8; 16];

// ── Public types ────────────────────────────────────────────────────────────

/// The detected type of a partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionType {
    Fat32,
    Ntfs,
    LinuxExt,
    EfiSystem,
    /// MBR partition with an unrecognised type byte.
    Unknown(u8),
    /// GPT partition with an unrecognised type GUID.
    UnknownGpt([u8; 16]),
}

/// Information about a single partition discovered on a block device.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    /// Zero-based index of this partition in the table.
    pub index: u8,
    /// Partition type.
    pub partition_type: PartitionType,
    /// First absolute LBA on the underlying device.
    pub start_lba: u64,
    /// Number of sectors the partition spans.
    pub sector_count: u64,
    /// Whether the partition is marked as bootable/active (MBR only).
    pub bootable: bool,
    /// Human-readable name (from GPT entry, or empty for MBR).
    pub name: String,
}

// ── MBR parsing ─────────────────────────────────────────────────────────────

/// Classify an MBR type byte into a `PartitionType`.
fn mbr_type_from_byte(b: u8) -> PartitionType {
    match b {
        0x07 => PartitionType::Ntfs, // NTFS / exFAT
        0x0B | 0x0C => PartitionType::Fat32,
        0x83 => PartitionType::LinuxExt,
        _ => PartitionType::Unknown(b),
    }
}

/// Read little-endian u32 from a byte slice at the given offset.
#[inline]
fn read_u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Read little-endian u64 from a byte slice at the given offset.
#[inline]
fn read_u64_le(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}

/// Parse the four MBR partition entries from a 512-byte sector buffer.
/// Returns `(partitions, has_gpt_protective)`.
fn parse_mbr_entries(sector: &[u8; SECTOR_SIZE]) -> (Vec<PartitionInfo>, bool) {
    let sig = u16::from_le_bytes([sector[510], sector[511]]);
    if sig != MBR_SIGNATURE {
        return (Vec::new(), false);
    }

    let mut partitions = Vec::new();
    let mut has_gpt = false;

    for i in 0..MBR_MAX_ENTRIES {
        let base = MBR_PARTITION_TABLE_OFFSET + i * MBR_ENTRY_SIZE;
        let boot_indicator = sector[base];
        let type_byte = sector[base + 4];
        let lba_start = read_u32_le(sector, base + 8) as u64;
        let sectors = read_u32_le(sector, base + 12) as u64;

        // Skip empty entries.
        if type_byte == 0x00 || sectors == 0 {
            continue;
        }

        if type_byte == 0xEE {
            has_gpt = true;
            continue; // don't expose the protective MBR entry itself
        }

        let bootable = boot_indicator == 0x80;
        let partition_type = mbr_type_from_byte(type_byte);

        crate::serial_println!(
            "[PARTITION] Found MBR partition: type=0x{:02X}, LBA={}, sectors={}",
            type_byte,
            lba_start,
            sectors
        );

        partitions.push(PartitionInfo {
            index: i as u8,
            partition_type,
            start_lba: lba_start,
            sector_count: sectors,
            bootable,
            name: String::new(),
        });
    }

    (partitions, has_gpt)
}

// ── GPT parsing ─────────────────────────────────────────────────────────────

/// Classify a GPT type GUID into a `PartitionType`.
fn gpt_type_from_guid(guid: &[u8; 16]) -> PartitionType {
    if *guid == GPT_TYPE_MICROSOFT_BASIC_DATA {
        // Could be FAT32 or NTFS — without reading the filesystem header
        // we report it generically as NTFS (Microsoft Basic Data).
        PartitionType::Ntfs
    } else if *guid == GPT_TYPE_LINUX_FILESYSTEM {
        PartitionType::LinuxExt
    } else if *guid == GPT_TYPE_EFI_SYSTEM {
        PartitionType::EfiSystem
    } else {
        PartitionType::UnknownGpt(*guid)
    }
}

/// Decode a UTF-16LE name from a GPT entry (up to 36 code units).
fn decode_gpt_name(data: &[u8], off: usize, max_chars: usize) -> String {
    let mut chars: Vec<u16> = Vec::with_capacity(max_chars);
    for i in 0..max_chars {
        let lo = data[off + i * 2] as u16;
        let hi = data[off + i * 2 + 1] as u16;
        let c = lo | (hi << 8);
        if c == 0 {
            break;
        }
        chars.push(c);
    }
    String::from_utf16_lossy(&chars)
}

/// Parse the GPT header + entries from the device.
fn parse_gpt(device: &dyn BlockDevice) -> Vec<PartitionInfo> {
    let mut header_buf = [0u8; SECTOR_SIZE];
    // GPT header is at LBA 1.
    if device.read_sector(1, &mut header_buf).is_err() {
        crate::serial_println!("[PARTITION] Failed to read GPT header at LBA 1");
        return Vec::new();
    }

    // Verify signature.
    if &header_buf[0..8] != GPT_SIGNATURE {
        crate::serial_println!("[PARTITION] GPT signature mismatch");
        return Vec::new();
    }

    let entries_start_lba = read_u64_le(&header_buf, 72);
    let num_entries = read_u32_le(&header_buf, 80);
    let entry_size = read_u32_le(&header_buf, 84) as usize;

    crate::serial_println!(
        "[PARTITION] GPT: entries_start_lba={}, num_entries={}, entry_size={}",
        entries_start_lba,
        num_entries,
        entry_size
    );

    if entry_size == 0 || entry_size > 512 {
        crate::serial_println!("[PARTITION] GPT entry size out of range: {}", entry_size);
        return Vec::new();
    }

    // How many entries fit in one sector?
    let entries_per_sector = SECTOR_SIZE / entry_size;
    // How many sectors do we need to read?
    let sectors_needed = (num_entries as usize + entries_per_sector - 1) / entries_per_sector;

    // Read all entry sectors in one go if possible.
    let total_bytes = sectors_needed * SECTOR_SIZE;
    let mut entry_buf = vec![0u8; total_bytes];
    if device
        .read_sectors(
            entries_start_lba,
            sectors_needed as u32,
            &mut entry_buf,
        )
        .is_err()
    {
        crate::serial_println!("[PARTITION] Failed to read GPT partition entries");
        return Vec::new();
    }

    let mut partitions = Vec::new();

    for i in 0..num_entries as usize {
        let off = i * entry_size;
        if off + entry_size > entry_buf.len() {
            break;
        }

        // Read the type GUID.
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&entry_buf[off..off + 16]);

        if type_guid == GPT_TYPE_UNUSED {
            continue;
        }

        let first_lba = read_u64_le(&entry_buf, off + 32);
        let last_lba = read_u64_le(&entry_buf, off + 40);
        let sector_count = last_lba.saturating_sub(first_lba) + 1;

        // Name is at offset 56, up to 36 UTF-16LE code units.
        let max_name_chars = (entry_size.saturating_sub(56)) / 2;
        let max_name_chars = max_name_chars.min(36);
        let name = decode_gpt_name(&entry_buf, off + 56, max_name_chars);

        let partition_type = gpt_type_from_guid(&type_guid);

        crate::serial_println!(
            "[PARTITION] Found GPT partition {}: type={:?}, LBA={}..{}, name=\"{}\"",
            i,
            partition_type,
            first_lba,
            last_lba,
            name
        );

        partitions.push(PartitionInfo {
            index: i as u8,
            partition_type,
            start_lba: first_lba,
            sector_count,
            bootable: false,
            name,
        });
    }

    partitions
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Scan a block device for partitions.
///
/// Tries MBR first; if a GPT protective entry (type 0xEE) is found, falls
/// through to GPT parsing.  Returns an empty `Vec` if no valid partition
/// table is found.
pub fn scan_partitions(device: &dyn BlockDevice) -> Vec<PartitionInfo> {
    let mut mbr_buf = [0u8; SECTOR_SIZE];
    if device.read_sector(0, &mut mbr_buf).is_err() {
        crate::serial_println!("[PARTITION] Failed to read MBR (LBA 0)");
        return Vec::new();
    }

    let (mbr_parts, has_gpt) = parse_mbr_entries(&mbr_buf);

    if has_gpt {
        crate::serial_println!("[PARTITION] GPT protective MBR detected — parsing GPT");
        return parse_gpt(device);
    }

    mbr_parts
}

// ── PartitionBlockDevice ────────────────────────────────────────────────────

/// A `BlockDevice` that represents a single partition on an underlying device.
///
/// All LBA values are transparently offset by `start_lba`, and accesses are
/// bounds-checked against `sector_count`.
pub struct PartitionBlockDevice {
    inner: Box<dyn BlockDevice>,
    start_lba: u64,
    sector_count: u64,
}

impl PartitionBlockDevice {
    /// The partition's start LBA on the underlying device.
    pub fn start_lba(&self) -> u64 {
        self.start_lba
    }

    /// Number of sectors in this partition.
    pub fn partition_sector_count(&self) -> u64 {
        self.sector_count
    }
}

impl BlockDevice for PartitionBlockDevice {
    fn sector_count(&self) -> u64 {
        self.sector_count
    }

    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        if lba.checked_add(count as u64).map_or(true, |end| end > self.sector_count) {
            return Err(BlockError::OutOfRange);
        }
        self.inner.read_sectors(self.start_lba + lba, count, buf)
    }

    fn write_sectors(&self, lba: u64, count: u32, data: &[u8]) -> Result<(), BlockError> {
        if lba.checked_add(count as u64).map_or(true, |end| end > self.sector_count) {
            return Err(BlockError::OutOfRange);
        }
        self.inner.write_sectors(self.start_lba + lba, count, data)
    }
}

/// Create a `PartitionBlockDevice` wrapping an inner device at the given LBA
/// offset and sector count.
pub fn create_partition_device(
    inner: Box<dyn BlockDevice>,
    start_lba: u64,
    sector_count: u64,
) -> PartitionBlockDevice {
    PartitionBlockDevice {
        inner,
        start_lba,
        sector_count,
    }
}
