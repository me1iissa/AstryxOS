//! NTFS Filesystem — Read-Only Implementation
//!
//! Implements a read-only NTFS filesystem driver for AstryxOS, inspired by
//! the ReactOS NTFS driver design. Supports:
//! - NTFS boot sector parsing (OEM ID, BPB, MFT location)
//! - MFT record parsing with update sequence array fixup
//! - Attribute parsing: $STANDARD_INFORMATION, $FILE_NAME, $DATA,
//!   $INDEX_ROOT, $INDEX_ALLOCATION, $BITMAP
//! - Resident and non-resident data attribute reading
//! - Data run decoding for non-resident attributes
//! - B+ tree index traversal for directory lookup and enumeration
//! - VFS integration via `FileSystemOps` trait
//!
//! All write operations return `VfsError::PermissionDenied` (read-only driver).
//!
//! Reference: NTFS Documentation (Wikipedia, Linux-NTFS project, ReactOS sources)

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::block::{BlockDevice, SECTOR_SIZE};
use super::{FileSystemOps, FileStat, FileType, VfsError, VfsResult};

// ── NTFS Constants ──────────────────────────────────────────────────────────

/// NTFS OEM identifier at offset 3 in the boot sector.
const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

/// MFT record magic signature: "FILE"
const MFT_RECORD_MAGIC: u32 = 0x454C_4946; // "FILE" in little-endian

/// Well-known MFT record numbers.
const MFT_RECORD_MFT: u64 = 0;
const MFT_RECORD_ROOT: u64 = 5;

/// Attribute type codes.
const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_BITMAP: u32 = 0xB0;
const ATTR_END: u32 = 0xFFFF_FFFF;

/// MFT record flags.
const MFT_RECORD_IN_USE: u16 = 0x0001;
const MFT_RECORD_IS_DIRECTORY: u16 = 0x0002;

/// Index entry flags.
const INDEX_ENTRY_SUBNODE: u16 = 0x0001;
const INDEX_ENTRY_LAST: u16 = 0x0002;

/// File name namespace values.
const FILE_NAME_POSIX: u8 = 0;
const FILE_NAME_WIN32: u8 = 1;
const FILE_NAME_DOS: u8 = 2;
const FILE_NAME_WIN32_AND_DOS: u8 = 3;

/// NTFS FILETIME epoch offset: seconds between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_DIFF: u64 = 11_644_473_600;

/// Index record magic: "INDX"
const INDX_RECORD_MAGIC: u32 = 0x5844_4E49; // "INDX" in little-endian

// ── Helper: Read Little-Endian Values ───────────────────────────────────────

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

fn read_i64_le(buf: &[u8], off: usize) -> i64 {
    i64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Read a signed value of `size` bytes (1..=8) in little-endian.
fn read_signed_le(buf: &[u8], off: usize, size: usize) -> i64 {
    if size == 0 || size > 8 {
        return 0;
    }
    let mut val: i64 = 0;
    for i in 0..size {
        val |= (buf[off + i] as i64) << (i * 8);
    }
    // Sign-extend if top bit is set.
    if buf[off + size - 1] & 0x80 != 0 {
        for i in size..8 {
            val |= 0xFFi64 << (i * 8);
        }
    }
    val
}

/// Read an unsigned value of `size` bytes (1..=8) in little-endian.
fn read_unsigned_le(buf: &[u8], off: usize, size: usize) -> u64 {
    if size == 0 || size > 8 {
        return 0;
    }
    let mut val: u64 = 0;
    for i in 0..size {
        val |= (buf[off + i] as u64) << (i * 8);
    }
    val
}

/// Convert NTFS FILETIME (100ns intervals from 1601-01-01) to Unix epoch seconds.
fn filetime_to_unix(filetime: u64) -> u64 {
    if filetime == 0 {
        return 0;
    }
    let secs = filetime / 10_000_000;
    if secs >= FILETIME_UNIX_DIFF {
        secs - FILETIME_UNIX_DIFF
    } else {
        0
    }
}

/// Decode a UTF-16LE name into a UTF-8 String.
fn decode_utf16le(buf: &[u8], char_count: usize) -> String {
    let mut chars = Vec::with_capacity(char_count);
    for i in 0..char_count {
        let off = i * 2;
        if off + 1 >= buf.len() {
            break;
        }
        let code = u16::from_le_bytes([buf[off], buf[off + 1]]);
        chars.push(code);
    }
    String::from_utf16_lossy(&chars)
}

// ── Parsed Boot Sector ──────────────────────────────────────────────────────

/// Parsed NTFS BPB and boot sector parameters.
#[derive(Debug, Clone)]
struct NtfsBpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    mft_start_lcn: u64,
    mft_mirror_start_lcn: u64,
    mft_record_size: u32,
    index_record_size: u32,
    total_sectors: u64,
    cluster_size: u32,
}

impl NtfsBpb {
    /// Parse from a 512-byte boot sector buffer.
    fn parse(buf: &[u8]) -> Option<Self> {
        // Verify OEM ID at offset 3.
        if &buf[3..11] != NTFS_OEM_ID {
            return None;
        }

        let bytes_per_sector = read_u16_le(buf, 0x0B);
        let sectors_per_cluster = buf[0x0D];
        let total_sectors = read_u64_le(buf, 0x28);
        let mft_start_lcn = read_u64_le(buf, 0x30);
        let mft_mirror_start_lcn = read_u64_le(buf, 0x38);

        // Clusters per MFT record: if negative, record size = 2^|value|.
        let clusters_per_mft_raw = buf[0x40] as i8;
        let mft_record_size = if clusters_per_mft_raw < 0 {
            1u32 << ((-clusters_per_mft_raw) as u32)
        } else {
            (clusters_per_mft_raw as u32)
                * (sectors_per_cluster as u32)
                * (bytes_per_sector as u32)
        };

        // Clusters per index record: same encoding.
        let clusters_per_index_raw = buf[0x44] as i8;
        let index_record_size = if clusters_per_index_raw < 0 {
            1u32 << ((-clusters_per_index_raw) as u32)
        } else {
            (clusters_per_index_raw as u32)
                * (sectors_per_cluster as u32)
                * (bytes_per_sector as u32)
        };

        let cluster_size = (sectors_per_cluster as u32) * (bytes_per_sector as u32);

        // Sanity checks.
        if bytes_per_sector == 0
            || sectors_per_cluster == 0
            || cluster_size == 0
            || mft_record_size == 0
            || mft_start_lcn == 0
        {
            return None;
        }

        Some(NtfsBpb {
            bytes_per_sector,
            sectors_per_cluster,
            mft_start_lcn,
            mft_mirror_start_lcn,
            mft_record_size,
            index_record_size,
            total_sectors,
            cluster_size,
        })
    }
}

// ── Data Run Decoding ───────────────────────────────────────────────────────

/// A decoded data run: (VCN start, LCN start, cluster count).
#[derive(Debug, Clone)]
struct DataRun {
    lcn: u64,
    length: u64, // in clusters
}

/// Decode data runs from an attribute's run list bytes.
/// Returns a list of DataRun entries.
fn decode_data_runs(run_data: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut offset = 0usize;
    let mut prev_lcn: i64 = 0;

    while offset < run_data.len() {
        let header = run_data[offset];
        if header == 0 {
            break;
        }
        offset += 1;

        let length_size = (header & 0x0F) as usize;
        let offset_size = ((header >> 4) & 0x0F) as usize;

        if length_size == 0 || offset + length_size + offset_size > run_data.len() {
            break;
        }

        let run_length = read_unsigned_le(run_data, offset, length_size);
        offset += length_size;

        if offset_size == 0 {
            // Sparse run — no LCN.
            runs.push(DataRun {
                lcn: 0,
                length: run_length,
            });
        } else {
            let run_offset = read_signed_le(run_data, offset, offset_size);
            offset += offset_size;

            prev_lcn += run_offset;
            if prev_lcn < 0 {
                break; // Invalid
            }
            runs.push(DataRun {
                lcn: prev_lcn as u64,
                length: run_length,
            });
        }
    }

    runs
}

// ── Attribute Parsing ───────────────────────────────────────────────────────

/// Parsed attribute header.
#[derive(Debug, Clone)]
struct NtfsAttribute {
    attr_type: u32,
    /// Total length of this attribute (header + value).
    length: u32,
    /// Whether the attribute data is non-resident.
    non_resident: bool,
    /// Name length (in UTF-16 chars).
    name_length: u16,
    /// For resident attributes: the raw data bytes.
    resident_data: Option<Vec<u8>>,
    /// For non-resident attributes: decoded data runs.
    data_runs: Option<Vec<DataRun>>,
    /// For non-resident: real size of the data.
    data_size: u64,
    /// For non-resident: initialized size.
    initialized_size: u64,
    /// Attribute name (if named), e.g. "$I30" for index attributes.
    name: Option<String>,
}

/// Parse all attributes from an MFT record (after fixup).
fn parse_attributes(record: &[u8], first_attr_offset: u16) -> Vec<NtfsAttribute> {
    let mut attrs = Vec::new();
    let mut off = first_attr_offset as usize;

    loop {
        if off + 4 > record.len() {
            break;
        }

        let attr_type = read_u32_le(record, off);
        if attr_type == ATTR_END || attr_type == 0 {
            break;
        }

        if off + 16 > record.len() {
            break;
        }

        let attr_length = read_u32_le(record, off + 4);
        if attr_length < 16 || (off + attr_length as usize) > record.len() {
            break;
        }

        let non_resident = record[off + 8] != 0;
        let name_length = record[off + 9] as u16;
        let name_offset = read_u16_le(record, off + 10) as usize;

        // Parse attribute name if present.
        let name = if name_length > 0 && name_offset + (name_length as usize * 2) <= attr_length as usize {
            Some(decode_utf16le(
                &record[off + name_offset..],
                name_length as usize,
            ))
        } else {
            None
        };

        let attr = if non_resident {
            // Non-resident attribute header.
            if off + 64 > record.len() {
                off += attr_length as usize;
                continue;
            }

            let run_offset = read_u16_le(record, off + 32) as usize;
            let _alloc_size = read_u64_le(record, off + 40);
            let data_size = read_u64_le(record, off + 48);
            let initialized_size = read_u64_le(record, off + 56);

            let run_start = off + run_offset;
            let run_end = off + attr_length as usize;
            let runs = if run_start < run_end && run_start < record.len() {
                let end = core::cmp::min(run_end, record.len());
                decode_data_runs(&record[run_start..end])
            } else {
                Vec::new()
            };

            NtfsAttribute {
                attr_type,
                length: attr_length,
                non_resident: true,
                name_length,
                resident_data: None,
                data_runs: Some(runs),
                data_size,
                initialized_size,
                name,
            }
        } else {
            // Resident attribute header.
            if off + 24 > record.len() {
                off += attr_length as usize;
                continue;
            }

            let value_length = read_u32_le(record, off + 16) as usize;
            let value_offset = read_u16_le(record, off + 20) as usize;

            let data_start = off + value_offset;
            let data_end = data_start + value_length;
            let data = if data_start < record.len() && data_end <= record.len() {
                Some(record[data_start..data_end].to_vec())
            } else {
                Some(Vec::new())
            };

            NtfsAttribute {
                attr_type,
                length: attr_length,
                non_resident: false,
                name_length,
                resident_data: data,
                data_runs: None,
                data_size: value_length as u64,
                initialized_size: value_length as u64,
                name,
            }
        };

        attrs.push(attr);
        off += attr_length as usize;
    }

    attrs
}

// ── $STANDARD_INFORMATION ───────────────────────────────────────────────────

/// Timestamps from $STANDARD_INFORMATION attribute.
#[derive(Debug, Clone, Default)]
struct StdInfo {
    created: u64,   // Unix epoch seconds
    modified: u64,
    accessed: u64,
    mft_modified: u64,
    flags: u32,
}

fn parse_standard_information(data: &[u8]) -> StdInfo {
    if data.len() < 48 {
        return StdInfo::default();
    }
    let created = filetime_to_unix(read_u64_le(data, 0));
    let modified = filetime_to_unix(read_u64_le(data, 8));
    let mft_modified = filetime_to_unix(read_u64_le(data, 16));
    let accessed = filetime_to_unix(read_u64_le(data, 24));
    let flags = read_u32_le(data, 32);
    StdInfo {
        created,
        modified,
        accessed,
        mft_modified,
        flags,
    }
}

// ── $FILE_NAME ──────────────────────────────────────────────────────────────

/// Parsed $FILE_NAME attribute.
#[derive(Debug, Clone)]
struct FileName {
    parent_mft_ref: u64,    // Lower 48 bits = MFT record number
    name: String,
    namespace: u8,
    flags: u32,             // Directory / Hidden / etc.
    data_size: u64,         // Allocated from $FILE_NAME (may be stale)
}

fn parse_file_name(data: &[u8]) -> Option<FileName> {
    if data.len() < 66 {
        return None;
    }
    let parent_ref = read_u64_le(data, 0) & 0x0000_FFFF_FFFF_FFFF;
    let flags = read_u32_le(data, 56);
    let data_size = read_u64_le(data, 48); // real size from file name attr
    let name_length = data[64] as usize;
    let namespace = data[65];

    if data.len() < 66 + name_length * 2 {
        return None;
    }
    let name = decode_utf16le(&data[66..], name_length);

    Some(FileName {
        parent_mft_ref: parent_ref,
        name,
        namespace,
        flags,
        data_size,
    })
}

/// Extract MFT record number from a 48-bit MFT reference (lower 6 bytes).
fn mft_ref_to_record(reference: u64) -> u64 {
    reference & 0x0000_FFFF_FFFF_FFFF
}

// ── Index Entry Parsing ─────────────────────────────────────────────────────

/// A parsed index entry from an $INDEX_ROOT or $INDEX_ALLOCATION node.
#[derive(Debug, Clone)]
struct IndexEntry {
    mft_reference: u64,
    file_name: Option<FileName>,
    sub_node_vcn: Option<u64>,
    is_last: bool,
}

/// Parse index entries from a buffer starting at `offset`.
/// `entries_offset` is the offset to the first entry within the index node header.
/// `entries_size` is the total size of all entries.
fn parse_index_entries(buf: &[u8], start: usize, total_size: usize) -> Vec<IndexEntry> {
    let mut entries = Vec::new();
    let mut off = start;
    let end = start + total_size;

    loop {
        if off + 16 > buf.len() || off >= end {
            break;
        }

        let mft_ref = read_u64_le(buf, off);
        let entry_length = read_u16_le(buf, off + 8) as usize;
        let content_length = read_u16_le(buf, off + 10) as usize;
        let entry_flags = read_u16_le(buf, off + 12); // Using read_u16_le for the flags at +12

        if entry_length < 16 || off + entry_length > buf.len() {
            break;
        }

        let is_last = entry_flags & INDEX_ENTRY_LAST != 0;
        let has_sub_node = entry_flags & INDEX_ENTRY_SUBNODE != 0;

        let file_name = if content_length >= 66 && off + 16 + content_length <= buf.len() {
            parse_file_name(&buf[off + 16..off + 16 + content_length])
        } else {
            None
        };

        let sub_node_vcn = if has_sub_node && entry_length >= 8 {
            Some(read_u64_le(buf, off + entry_length - 8))
        } else {
            None
        };

        entries.push(IndexEntry {
            mft_reference: mft_ref_to_record(mft_ref),
            file_name,
            sub_node_vcn,
            is_last,
        });

        if is_last {
            break;
        }

        off += entry_length;
    }

    entries
}

// ── NtfsFs ──────────────────────────────────────────────────────────────────

/// Read-only NTFS filesystem driver.
pub struct NtfsFs {
    device: Box<dyn BlockDevice>,
    bpb: NtfsBpb,
    /// Cache of loaded MFT records: record_number → raw bytes (after fixup).
    mft_cache: Mutex<BTreeMap<u64, Vec<u8>>>,
}

// SAFETY: NtfsFs is protected by the internal Mutex on mft_cache.
// The device is already Send + Sync.
unsafe impl Send for NtfsFs {}
unsafe impl Sync for NtfsFs {}

impl NtfsFs {
    /// Read clusters from the block device.
    fn read_clusters(&self, lcn: u64, count: u64) -> VfsResult<Vec<u8>> {
        let cluster_size = self.bpb.cluster_size as u64;
        let total_bytes = count * cluster_size;
        let mut buf = vec![0u8; total_bytes as usize];

        let sectors_per_cluster = self.bpb.sectors_per_cluster as u64;
        let start_sector = lcn * sectors_per_cluster;
        let total_sectors = count * sectors_per_cluster;

        // Read in chunks since read_sectors takes u32 count.
        let mut sector = start_sector;
        let mut buf_off = 0usize;
        let mut remaining = total_sectors;
        while remaining > 0 {
            let chunk = core::cmp::min(remaining, 256) as u32;
            let chunk_bytes = chunk as usize * SECTOR_SIZE;
            self.device
                .read_sectors(sector, chunk, &mut buf[buf_off..buf_off + chunk_bytes])
                .map_err(|_| VfsError::Io)?;
            sector += chunk as u64;
            buf_off += chunk_bytes;
            remaining -= chunk as u64;
        }

        Ok(buf)
    }

    /// Read bytes at an absolute byte offset from the device.
    fn read_bytes(&self, byte_offset: u64, length: usize) -> VfsResult<Vec<u8>> {
        let start_sector = byte_offset / SECTOR_SIZE as u64;
        let end_byte = byte_offset + length as u64;
        let end_sector = (end_byte + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64;
        let sector_count = end_sector - start_sector;

        let mut sector_buf = vec![0u8; sector_count as usize * SECTOR_SIZE];

        let mut remaining = sector_count;
        let mut sector = start_sector;
        let mut buf_off = 0;
        while remaining > 0 {
            let chunk = core::cmp::min(remaining, 256) as u32;
            let chunk_bytes = chunk as usize * SECTOR_SIZE;
            self.device
                .read_sectors(sector, chunk, &mut sector_buf[buf_off..buf_off + chunk_bytes])
                .map_err(|_| VfsError::Io)?;
            sector += chunk as u64;
            buf_off += chunk_bytes;
            remaining -= chunk as u64;
        }

        let start_off = (byte_offset % SECTOR_SIZE as u64) as usize;
        Ok(sector_buf[start_off..start_off + length].to_vec())
    }

    /// Apply the update sequence array fixup to an MFT record buffer.
    fn apply_fixup(record: &mut [u8], record_size: u32) -> VfsResult<()> {
        if record.len() < 48 {
            return Err(VfsError::Io);
        }

        let usa_offset = read_u16_le(record, 4) as usize;
        let usa_count = read_u16_le(record, 6) as usize;

        if usa_count == 0 || usa_offset + usa_count * 2 > record.len() {
            return Err(VfsError::Io);
        }

        // USA: first u16 is the fixup value, followed by (usa_count - 1) replacement values.
        let fixup_value = read_u16_le(record, usa_offset);

        for i in 1..usa_count {
            let entry_offset = usa_offset + i * 2;
            let sector_end = i * SECTOR_SIZE;

            // The last two bytes of each sector should match the fixup value.
            if sector_end < 2 || sector_end > record_size as usize {
                break;
            }
            let pos = sector_end - 2;
            if pos + 1 >= record.len() || entry_offset + 1 >= record.len() {
                break;
            }

            // Verify fixup value matches.
            let stored = read_u16_le(record, pos);
            if stored != fixup_value {
                crate::serial_println!("[NTFS] Fixup mismatch at sector boundary {}: expected 0x{:04X}, got 0x{:04X}", i, fixup_value, stored);
                return Err(VfsError::Io);
            }

            // Replace with the original bytes from the USA.
            record[pos] = record[entry_offset];
            record[pos + 1] = record[entry_offset + 1];
        }

        Ok(())
    }

    /// Apply fixup for an index record (INDX).
    fn apply_indx_fixup(record: &mut [u8]) -> VfsResult<()> {
        if record.len() < 28 {
            return Err(VfsError::Io);
        }

        let usa_offset = read_u16_le(record, 4) as usize;
        let usa_count = read_u16_le(record, 6) as usize;

        if usa_count == 0 || usa_offset + usa_count * 2 > record.len() {
            return Err(VfsError::Io);
        }

        let fixup_value = read_u16_le(record, usa_offset);

        for i in 1..usa_count {
            let entry_offset = usa_offset + i * 2;
            let pos = i * SECTOR_SIZE - 2;

            if pos + 1 >= record.len() || entry_offset + 1 >= record.len() {
                break;
            }

            let stored = read_u16_le(record, pos);
            if stored != fixup_value {
                crate::serial_println!("[NTFS] INDX fixup mismatch at {}", i);
                return Err(VfsError::Io);
            }

            record[pos] = record[entry_offset];
            record[pos + 1] = record[entry_offset + 1];
        }

        Ok(())
    }

    /// Load and cache an MFT record by record number.
    fn load_mft_record(&self, record_number: u64) -> VfsResult<Vec<u8>> {
        // Check cache first.
        {
            let cache = self.mft_cache.lock();
            if let Some(cached) = cache.get(&record_number) {
                return Ok(cached.clone());
            }
        }

        let record_size = self.bpb.mft_record_size;
        let byte_offset = self.bpb.mft_start_lcn
            * self.bpb.cluster_size as u64
            + record_number * record_size as u64;

        let mut record = self.read_bytes(byte_offset, record_size as usize)?;

        // Verify magic.
        let magic = read_u32_le(&record, 0);
        if magic != MFT_RECORD_MAGIC {
            crate::serial_println!(
                "[NTFS] MFT record {} has bad magic: 0x{:08X}",
                record_number,
                magic
            );
            return Err(VfsError::Io);
        }

        // Apply update sequence array fixup.
        Self::apply_fixup(&mut record, record_size)?;

        // Cache it.
        {
            let mut cache = self.mft_cache.lock();
            cache.insert(record_number, record.clone());
        }

        Ok(record)
    }

    /// Parse all attributes from an MFT record.
    fn get_attributes(&self, record_number: u64) -> VfsResult<Vec<NtfsAttribute>> {
        let record = self.load_mft_record(record_number)?;

        if record.len() < 22 {
            return Err(VfsError::Io);
        }

        let first_attr_offset = read_u16_le(&record, 20);
        Ok(parse_attributes(&record, first_attr_offset))
    }

    /// Find the first attribute of a given type in an MFT record.
    fn find_attribute(
        &self,
        record_number: u64,
        attr_type: u32,
    ) -> VfsResult<Option<NtfsAttribute>> {
        let attrs = self.get_attributes(record_number)?;
        Ok(attrs.into_iter().find(|a| a.attr_type == attr_type))
    }

    /// Find a named attribute (e.g., $I30 data stream).
    fn find_named_attribute(
        &self,
        record_number: u64,
        attr_type: u32,
        name: &str,
    ) -> VfsResult<Option<NtfsAttribute>> {
        let attrs = self.get_attributes(record_number)?;
        Ok(attrs.into_iter().find(|a| {
            a.attr_type == attr_type
                && a.name.as_deref() == Some(name)
        }))
    }

    /// Read the full contents of an attribute (resident or non-resident).
    fn read_attribute_data(&self, attr: &NtfsAttribute) -> VfsResult<Vec<u8>> {
        if !attr.non_resident {
            return Ok(attr.resident_data.clone().unwrap_or_default());
        }

        let runs = attr.data_runs.as_ref().ok_or(VfsError::Io)?;
        let data_size = attr.data_size as usize;
        let mut result = Vec::with_capacity(data_size);

        for run in runs {
            if run.lcn == 0 {
                // Sparse run: fill with zeros.
                let bytes = run.length as usize * self.bpb.cluster_size as usize;
                result.extend(core::iter::repeat(0u8).take(bytes));
            } else {
                let cluster_data = self.read_clusters(run.lcn, run.length)?;
                result.extend_from_slice(&cluster_data);
            }
        }

        // Trim to actual data size.
        result.truncate(data_size);
        Ok(result)
    }

    /// Read a range of bytes from an attribute.
    fn read_attribute_range(
        &self,
        attr: &NtfsAttribute,
        offset: u64,
        buf: &mut [u8],
    ) -> VfsResult<usize> {
        let data_size = attr.data_size;

        if offset >= data_size {
            return Ok(0);
        }

        let available = data_size - offset;
        let to_read = core::cmp::min(buf.len() as u64, available) as usize;

        if !attr.non_resident {
            let data = attr.resident_data.as_ref().ok_or(VfsError::Io)?;
            let start = offset as usize;
            let end = start + to_read;
            if end <= data.len() {
                buf[..to_read].copy_from_slice(&data[start..end]);
            } else {
                let avail = if start < data.len() {
                    data.len() - start
                } else {
                    0
                };
                buf[..avail].copy_from_slice(&data[start..start + avail]);
                return Ok(avail);
            }
            return Ok(to_read);
        }

        // Non-resident: walk data runs.
        let runs = attr.data_runs.as_ref().ok_or(VfsError::Io)?;
        let cluster_size = self.bpb.cluster_size as u64;
        let mut buf_pos = 0usize;
        let mut remaining = to_read;
        let mut vcn_offset: u64 = 0;

        for run in runs {
            let run_bytes = run.length * cluster_size;

            if offset + buf_pos as u64 >= vcn_offset + run_bytes {
                vcn_offset += run_bytes;
                continue;
            }

            let run_start = if vcn_offset < offset + buf_pos as u64 {
                offset + buf_pos as u64 - vcn_offset
            } else {
                0
            };

            let run_avail = (run_bytes - run_start) as usize;
            let chunk_size = core::cmp::min(remaining, run_avail);

            if run.lcn == 0 {
                // Sparse: fill with zeros.
                for i in 0..chunk_size {
                    buf[buf_pos + i] = 0;
                }
            } else {
                // Calculate the byte offset within this run.
                let byte_off = run.lcn * cluster_size + run_start;

                // Read only the needed portion.
                let chunk_data = self.read_bytes(byte_off, chunk_size)?;
                buf[buf_pos..buf_pos + chunk_size].copy_from_slice(&chunk_data);
            }

            buf_pos += chunk_size;
            remaining -= chunk_size;

            if remaining == 0 {
                break;
            }

            vcn_offset += run_bytes;
        }

        Ok(buf_pos)
    }

    /// Check if an MFT record is a directory.
    fn is_directory(&self, record_number: u64) -> VfsResult<bool> {
        let record = self.load_mft_record(record_number)?;
        if record.len() < 24 {
            return Err(VfsError::Io);
        }
        let flags = read_u16_le(&record, 22);
        Ok(flags & MFT_RECORD_IS_DIRECTORY != 0)
    }

    /// Check if an MFT record is in use.
    fn is_in_use(&self, record_number: u64) -> VfsResult<bool> {
        let record = self.load_mft_record(record_number)?;
        if record.len() < 24 {
            return Err(VfsError::Io);
        }
        let flags = read_u16_le(&record, 22);
        Ok(flags & MFT_RECORD_IN_USE != 0)
    }

    /// Get the best file name from an MFT record.
    /// Prefers Win32 or Win32+DOS namespace over DOS-only.
    fn get_file_name(&self, record_number: u64) -> VfsResult<Option<FileName>> {
        let attrs = self.get_attributes(record_number)?;
        let mut best: Option<FileName> = None;

        for attr in &attrs {
            if attr.attr_type == ATTR_FILE_NAME {
                if let Some(data) = &attr.resident_data {
                    if let Some(fn_attr) = parse_file_name(data) {
                        match fn_attr.namespace {
                            FILE_NAME_WIN32 | FILE_NAME_WIN32_AND_DOS | FILE_NAME_POSIX => {
                                // Prefer Win32 or POSIX name over what we have.
                                if best
                                    .as_ref()
                                    .map_or(true, |b| b.namespace == FILE_NAME_DOS)
                                {
                                    best = Some(fn_attr);
                                }
                            }
                            FILE_NAME_DOS => {
                                if best.is_none() {
                                    best = Some(fn_attr);
                                }
                            }
                            _ => {
                                if best.is_none() {
                                    best = Some(fn_attr);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(best)
    }

    /// Get the $DATA attribute data size for a file.
    fn get_data_size(&self, record_number: u64) -> VfsResult<u64> {
        let attr = self.find_attribute(record_number, ATTR_DATA)?;
        Ok(attr.map_or(0, |a| a.data_size))
    }

    /// Collect all index entries from a directory's $INDEX_ROOT and
    /// $INDEX_ALLOCATION (if any).
    fn collect_index_entries(&self, dir_record: u64) -> VfsResult<Vec<IndexEntry>> {
        let mut all_entries = Vec::new();

        // 1. Parse $INDEX_ROOT (always resident).
        let root_attr = self
            .find_attribute(dir_record, ATTR_INDEX_ROOT)?
            .ok_or(VfsError::NotADirectory)?;
        let root_data = root_attr.resident_data.as_ref().ok_or(VfsError::Io)?;

        if root_data.len() < 32 {
            return Err(VfsError::Io);
        }

        // Index Root header:
        //  0: Attribute type (u32) — should be $FILE_NAME (0x30)
        //  4: Collation rule (u32)
        //  8: Index allocation entry size (u32)
        // 12: Clusters per index record (u8)
        // 16: Index node header starts here
        //   16+0: Entries offset (relative to start of node header)
        //   16+4: Total size of entries
        //   16+8: Allocated size
        //   16+12: Flags (0x01 = has sub-nodes)

        let entries_offset = read_u32_le(root_data, 16) as usize;
        let entries_total_size = read_u32_le(root_data, 20) as usize;

        let entries_start = 16 + entries_offset; // relative to root_data start

        if entries_start < root_data.len() {
            let entries_size = core::cmp::min(entries_total_size, root_data.len() - entries_start);
            let root_entries = parse_index_entries(root_data, entries_start, entries_size);

            // Collect sub-node VCNs for traversal.
            let mut sub_vcns: Vec<u64> = Vec::new();
            for entry in &root_entries {
                if !entry.is_last && entry.file_name.is_some() {
                    all_entries.push(entry.clone());
                }
                if let Some(vcn) = entry.sub_node_vcn {
                    sub_vcns.push(vcn);
                }
            }

            // 2. If there are sub-nodes, read $INDEX_ALLOCATION.
            if !sub_vcns.is_empty() {
                if let Ok(Some(alloc_attr)) =
                    self.find_attribute(dir_record, ATTR_INDEX_ALLOCATION)
                {
                    let alloc_data = self.read_attribute_data(&alloc_attr)?;
                    let index_record_size = self.bpb.index_record_size as usize;

                    self.traverse_index_allocation(
                        &alloc_data,
                        index_record_size,
                        &sub_vcns,
                        &mut all_entries,
                    )?;
                }
            }
        }

        Ok(all_entries)
    }

    /// Traverse index allocation records for the given VCNs, recursively
    /// collecting index entries.
    fn traverse_index_allocation(
        &self,
        alloc_data: &[u8],
        index_record_size: usize,
        vcns: &[u64],
        entries: &mut Vec<IndexEntry>,
    ) -> VfsResult<()> {
        let cluster_size = self.bpb.cluster_size as usize;

        for &vcn in vcns {
            // The VCN tells us the offset within the $INDEX_ALLOCATION data.
            // Each VCN unit is typically one cluster.
            let record_offset = vcn as usize * cluster_size;

            if record_offset + index_record_size > alloc_data.len() {
                continue;
            }

            let mut indx_record =
                alloc_data[record_offset..record_offset + index_record_size].to_vec();

            // Verify INDX magic.
            if indx_record.len() < 28 {
                continue;
            }
            let magic = read_u32_le(&indx_record, 0);
            if magic != INDX_RECORD_MAGIC {
                continue;
            }

            // Apply fixup.
            if Self::apply_indx_fixup(&mut indx_record).is_err() {
                continue;
            }

            // Index node header starts at offset 24 within the INDX record.
            let node_header_offset = 24usize;
            if node_header_offset + 16 > indx_record.len() {
                continue;
            }

            let ie_offset = read_u32_le(&indx_record, node_header_offset) as usize;
            let ie_total_size = read_u32_le(&indx_record, node_header_offset + 4) as usize;

            let start = node_header_offset + ie_offset;
            if start >= indx_record.len() {
                continue;
            }
            let size = core::cmp::min(ie_total_size, indx_record.len() - start);

            let node_entries = parse_index_entries(&indx_record, start, size);

            let mut sub_vcns: Vec<u64> = Vec::new();
            for entry in &node_entries {
                if !entry.is_last && entry.file_name.is_some() {
                    entries.push(entry.clone());
                }
                if let Some(child_vcn) = entry.sub_node_vcn {
                    sub_vcns.push(child_vcn);
                }
            }

            // Recurse into child nodes.
            if !sub_vcns.is_empty() {
                self.traverse_index_allocation(
                    alloc_data,
                    index_record_size,
                    &sub_vcns,
                    entries,
                )?;
            }
        }

        Ok(())
    }

    /// Look up a name in a directory's index, returning the MFT record number.
    fn lookup_in_directory(&self, dir_record: u64, name: &str) -> VfsResult<u64> {
        let entries = self.collect_index_entries(dir_record)?;

        let name_lower = name.to_lowercase();

        for entry in &entries {
            if let Some(ref fn_attr) = entry.file_name {
                // Skip DOS-only names if a Win32 name is also present.
                if fn_attr.namespace == FILE_NAME_DOS {
                    continue;
                }
                if fn_attr.name.to_lowercase() == name_lower {
                    return Ok(entry.mft_reference);
                }
            }
        }

        // Also try DOS names as a fallback.
        for entry in &entries {
            if let Some(ref fn_attr) = entry.file_name {
                if fn_attr.name.to_lowercase() == name_lower {
                    return Ok(entry.mft_reference);
                }
            }
        }

        Err(VfsError::NotFound)
    }

    /// Get the root directory MFT record number.
    pub fn root_inode(&self) -> u64 {
        MFT_RECORD_ROOT
    }
}

// ── FileSystemOps Implementation ────────────────────────────────────────────

impl FileSystemOps for NtfsFs {
    fn name(&self) -> &str {
        "ntfs"
    }

    fn create_file(&self, _parent_inode: u64, _name: &str) -> VfsResult<u64> {
        Err(VfsError::PermissionDenied) // Read-only
    }

    fn create_dir(&self, _parent_inode: u64, _name: &str) -> VfsResult<u64> {
        Err(VfsError::PermissionDenied) // Read-only
    }

    fn remove(&self, _parent_inode: u64, _name: &str) -> VfsResult<()> {
        Err(VfsError::PermissionDenied) // Read-only
    }

    fn lookup(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        // Special: "." returns itself, ".." returns parent.
        if name == "." {
            return Ok(parent_inode);
        }
        if name == ".." {
            // Get the parent from $FILE_NAME attribute.
            if let Ok(Some(fn_attr)) = self.get_file_name(parent_inode) {
                return Ok(fn_attr.parent_mft_ref);
            }
            // Root directory's parent is itself.
            return Ok(MFT_RECORD_ROOT);
        }

        self.lookup_in_directory(parent_inode, name)
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // Verify it's a file, not a directory.
        if self.is_directory(inode)? {
            return Err(VfsError::IsADirectory);
        }

        let data_attr = self
            .find_attribute(inode, ATTR_DATA)?
            .ok_or(VfsError::NotFound)?;

        self.read_attribute_range(&data_attr, offset, buf)
    }

    fn write(&self, _inode: u64, _offset: u64, _data: &[u8]) -> VfsResult<usize> {
        Err(VfsError::PermissionDenied) // Read-only
    }

    fn stat(&self, inode: u64) -> VfsResult<FileStat> {
        // Check in-use.
        if !self.is_in_use(inode)? {
            return Err(VfsError::NotFound);
        }

        let is_dir = self.is_directory(inode)?;
        let file_type = if is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

        // Get data size (for files).
        let size = if is_dir {
            0
        } else {
            self.get_data_size(inode)?
        };

        // Get permissions and timestamps from $STANDARD_INFORMATION.
        let (permissions, created, modified, accessed) = if let Ok(Some(attr)) =
            self.find_attribute(inode, ATTR_STANDARD_INFORMATION)
        {
            if let Some(data) = &attr.resident_data {
                let std_info = parse_standard_information(data);
                let perms = if std_info.flags & 0x0001 != 0 { 0o444 } else { 0o555 };
                (perms, std_info.created, std_info.modified, std_info.accessed)
            } else {
                (0o555, 0, 0, 0)
            }
        } else {
            (0o555, 0, 0, 0)
        };

        Ok(FileStat {
            inode,
            file_type,
            size,
            permissions,
            created,
            modified,
            accessed,
        })
    }

    fn readdir(&self, inode: u64) -> VfsResult<Vec<(String, u64, FileType)>> {
        if !self.is_directory(inode)? {
            return Err(VfsError::NotADirectory);
        }

        let entries = self.collect_index_entries(inode)?;
        let mut result = Vec::new();
        let mut seen = BTreeMap::new();

        for entry in entries {
            if let Some(ref fn_attr) = entry.file_name {
                // Skip DOS-only names when a Win32 name is available.
                if fn_attr.namespace == FILE_NAME_DOS {
                    if seen.contains_key(&entry.mft_reference) {
                        continue;
                    }
                }

                // Skip system metafiles (MFT records 0..=11 and 24).
                // These are internal NTFS files and shouldn't be visible.
                if entry.mft_reference < 12 || entry.mft_reference == 24 {
                    // Allow root dir reference to appear (e.g., in "." entries)
                    // but don't show metafiles as directory entries.
                    if entry.mft_reference != MFT_RECORD_ROOT {
                        continue;
                    }
                }

                // Skip entries named "." or ".." (self and parent refs).
                if fn_attr.name == "." || fn_attr.name == ".." {
                    continue;
                }

                // De-duplicate: prefer Win32 names.
                if let Some(existing_ns) = seen.get(&entry.mft_reference) {
                    if fn_attr.namespace == FILE_NAME_DOS
                        && (*existing_ns == FILE_NAME_WIN32
                            || *existing_ns == FILE_NAME_WIN32_AND_DOS
                            || *existing_ns == FILE_NAME_POSIX)
                    {
                        continue;
                    }
                }

                // Determine file type from MFT record flags.
                let ft = if fn_attr.flags & 0x10000000 != 0 {
                    // FILE_ATTR_DIRECTORY flag in $FILE_NAME
                    FileType::Directory
                } else {
                    // Try loading the record to check its flags.
                    match self.is_directory(entry.mft_reference) {
                        Ok(true) => FileType::Directory,
                        _ => FileType::RegularFile,
                    }
                };

                seen.insert(entry.mft_reference, fn_attr.namespace);
                result.push((fn_attr.name.clone(), entry.mft_reference, ft));
            }
        }

        Ok(result)
    }

    fn truncate(&self, _inode: u64, _size: u64) -> VfsResult<()> {
        Err(VfsError::PermissionDenied) // Read-only
    }

    fn sync(&self) -> VfsResult<()> {
        Ok(()) // Nothing to flush — read-only
    }
}

// ── Public Mount Function ───────────────────────────────────────────────────

/// Probe a block device for an NTFS signature and return a mounted `NtfsFs`.
///
/// Reads sector 0 and checks for the "NTFS    " OEM identifier. If valid,
/// parses the boot sector parameters and returns the filesystem driver.
///
/// Returns `None` if the device does not contain an NTFS volume.
pub fn try_mount_ntfs(device: Box<dyn BlockDevice>) -> Option<NtfsFs> {
    let mut boot_sector = [0u8; SECTOR_SIZE];
    if device.read_sectors(0, 1, &mut boot_sector).is_err() {
        crate::serial_println!("[NTFS] Failed to read boot sector");
        return None;
    }

    let bpb = match NtfsBpb::parse(&boot_sector) {
        Some(bpb) => bpb,
        None => {
            return None;
        }
    };

    crate::serial_println!(
        "[NTFS] Detected NTFS volume: {} bytes/sector, {} sectors/cluster, \
         MFT at LCN {}, record size {} bytes",
        bpb.bytes_per_sector,
        bpb.sectors_per_cluster,
        bpb.mft_start_lcn,
        bpb.mft_record_size
    );

    let fs = NtfsFs {
        device,
        bpb,
        mft_cache: Mutex::new(BTreeMap::new()),
    };

    // Validate by loading the root directory MFT record.
    match fs.load_mft_record(MFT_RECORD_ROOT) {
        Ok(record) => {
            let flags = read_u16_le(&record, 22);
            if flags & MFT_RECORD_IN_USE == 0 {
                crate::serial_println!("[NTFS] Root directory MFT record not in use");
                return None;
            }
            if flags & MFT_RECORD_IS_DIRECTORY == 0 {
                crate::serial_println!("[NTFS] MFT record 5 is not a directory");
                return None;
            }
            crate::serial_println!("[NTFS] Root directory validated (MFT record 5)");
        }
        Err(_) => {
            crate::serial_println!("[NTFS] Failed to load root directory MFT record");
            return None;
        }
    }

    Some(fs)
}

// ── String Case Conversion Helper ───────────────────────────────────────────

/// Simple lowercase conversion for ASCII characters (NTFS names are mostly ASCII).
trait ToLowercase {
    fn to_lowercase(&self) -> String;
}

impl ToLowercase for str {
    fn to_lowercase(&self) -> String {
        let mut s = String::with_capacity(self.len());
        for c in self.chars() {
            if c.is_ascii_uppercase() {
                s.push((c as u8 + 32) as char);
            } else {
                s.push(c);
            }
        }
        s
    }
}

impl ToLowercase for String {
    fn to_lowercase(&self) -> String {
        self.as_str().to_lowercase()
    }
}
