//! FAT32 Filesystem — Read/Write Implementation
//!
//! Implements the FAT32 filesystem specification for reading and writing files
//! and directories on a block device. Supports:
//! - BPB (BIOS Parameter Block) parsing
//! - FAT chain following (cluster chains)
//! - Directory entry parsing (8.3 names + long filename entries)
//! - VFS integration via `FileSystemOps` trait
//! - File creation, writing, deletion, truncation
//! - Directory creation and removal
//! - Dirty sector tracking and sync-to-disk
//!
//! Reference: Microsoft FAT32 File System Specification (fatgen103.doc)

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::block::{BlockDevice, SECTOR_SIZE};
use super::{FileSystemOps, FileStat, FileType, VfsError, VfsResult, alloc_inode_number};

// ── FAT32 Constants ─────────────────────────────────────────────────────────

/// FAT32 end-of-chain marker range.
const FAT_EOC_MIN: u32 = 0x0FFFFFF8;

/// FAT entry mask (lower 28 bits).
const FAT_ENTRY_MASK: u32 = 0x0FFFFFFF;

/// Directory entry size in bytes.
const DIR_ENTRY_SIZE: usize = 32;

/// Attribute flags for directory entries.
mod attr {
    pub const READ_ONLY: u8 = 0x01;
    pub const HIDDEN: u8    = 0x02;
    pub const SYSTEM: u8    = 0x04;
    pub const VOLUME_ID: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;
    #[allow(dead_code)]
    pub const ARCHIVE: u8   = 0x20;
    pub const LONG_NAME: u8 = 0x0F;
}

// ── BPB (BIOS Parameter Block) ──────────────────────────────────────────────

/// Parsed FAT32 BPB + derived geometry values.
#[derive(Debug, Clone)]
struct Fat32Bpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    total_sectors: u32,
    fat_size: u32,          // sectors per FAT
    root_cluster: u32,
    /// FSInfo sector number from BPB offset 48 (0 or 0xFFFF → no FSInfo).
    /// When present, `do_sync` updates its free-cluster count and next-free
    /// hint on every flush (FAT32-6).
    fsinfo_sector: u16,
    // Derived values
    fat_start_sector: u32,
    data_start_sector: u32,
    cluster_size: u32,      // bytes per cluster
}

impl Fat32Bpb {
    /// Parse a BPB from a 512-byte boot sector.
    fn parse(sector: &[u8; SECTOR_SIZE]) -> Result<Self, VfsError> {
        // Validate boot signature.
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(VfsError::Io);
        }

        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        let sectors_per_cluster = sector[13];
        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
        let num_fats = sector[16];

        // root_entry_count (offset 17) must be 0 for FAT32.
        let root_entry_count = u16::from_le_bytes([sector[17], sector[18]]);
        if root_entry_count != 0 {
            return Err(VfsError::Io); // Probably FAT12/16, not FAT32
        }

        // Total sectors — FAT32 uses the 32-bit field at offset 32.
        let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
        let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16 as u32
        } else {
            total_sectors_32
        };

        // FAT size — FAT32 uses the 32-bit field at offset 36.
        let fat_size_16 = u16::from_le_bytes([sector[22], sector[23]]);
        let fat_size_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        let fat_size = if fat_size_16 != 0 {
            fat_size_16 as u32
        } else {
            fat_size_32
        };

        let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
        // FAT32-6: FSInfo sector number lives at offset 48 (2 bytes LE).
        // 0x0000 and 0xFFFF are both defined as "no FSInfo" per the MS spec.
        let fsinfo_sector = u16::from_le_bytes([sector[48], sector[49]]);

        // Validate basic sanity.
        if bytes_per_sector == 0 || sectors_per_cluster == 0 || num_fats == 0 || fat_size == 0 {
            return Err(VfsError::Io);
        }

        let fat_start_sector = reserved_sectors as u32;
        let data_start_sector = fat_start_sector + (num_fats as u32) * fat_size;
        let cluster_size = (sectors_per_cluster as u32) * (bytes_per_sector as u32);

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            total_sectors,
            fat_size,
            root_cluster,
            fsinfo_sector,
            fat_start_sector,
            data_start_sector,
            cluster_size,
        })
    }

    /// Convert a cluster number to its first sector (LBA).
    fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.data_start_sector + (cluster - 2) * (self.sectors_per_cluster as u32)
    }
}

// ── Directory Entry ─────────────────────────────────────────────────────────

/// A parsed FAT32 directory entry.
#[derive(Debug, Clone)]
struct Fat32DirEntry {
    name: String,
    attr: u8,
    first_cluster: u32,
    file_size: u32,
    /// NT-case preservation byte (offset 12 in on-disk entry). FAT32-8.
    nt_res: u8,
    /// Absolute byte offset of this 32-byte entry in the volume.
    dir_entry_offset: usize,
    /// First cluster of the containing directory.
    dir_entry_cluster: u32,
}

impl Fat32DirEntry {
    fn is_directory(&self) -> bool {
        self.attr & attr::DIRECTORY != 0
    }

    fn file_type(&self) -> FileType {
        if self.is_directory() {
            FileType::Directory
        } else {
            FileType::RegularFile
        }
    }
}

/// NT-case preservation bits in directory-entry byte 12 (`NTRes`).
/// Windows NT sets these for 8.3 names that would otherwise need a redundant
/// LFN entry. Without honouring them, every short name from Windows appears
/// lowercased here (FAT32-8).
const NT_RES_LOWERCASE_BASE: u8 = 0x08;
const NT_RES_LOWERCASE_EXT:  u8 = 0x10;

/// Parse an 8.3 short filename from a directory entry, honouring NTRes
/// (byte 12) per MS FAT spec. The caller passes the full 32-byte entry
/// so we can read the NTRes byte; the raw 8.3 name is stored on disk in
/// uppercase and per-segment case is reconstructed via NTRes bits.
///
/// Exposed `pub(crate)` so regression tests can exercise it without
/// constructing a full disk image (FAT32-8).
pub(crate) fn parse_short_name_test(entry: &[u8]) -> String {
    parse_short_name(entry)
}

fn parse_short_name(entry: &[u8]) -> String {
    let nt_res = if entry.len() > 12 { entry[12] } else { 0 };
    let lower_base = nt_res & NT_RES_LOWERCASE_BASE != 0;
    let lower_ext  = nt_res & NT_RES_LOWERCASE_EXT  != 0;

    // First 8 bytes: name (space-padded). Preserve as-on-disk, then
    // apply lowercase per-segment only if NTRes requests it.
    let name_part: String = entry[0..8]
        .iter()
        .take_while(|&&b| b != b' ')
        .map(|&b| {
            let c = b as char;
            if lower_base { c.to_ascii_lowercase() } else { c }
        })
        .collect();

    // Next 3 bytes: extension (space-padded).
    let ext_part: String = entry[8..11]
        .iter()
        .take_while(|&&b| b != b' ')
        .map(|&b| {
            let c = b as char;
            if lower_ext { c.to_ascii_lowercase() } else { c }
        })
        .collect();

    if ext_part.is_empty() {
        name_part
    } else {
        let mut result = name_part;
        result.push('.');
        result.push_str(&ext_part);
        result
    }
}

/// Parse a single 32-byte directory entry.
fn parse_dir_entry(raw: &[u8]) -> Option<Fat32DirEntry> {
    if raw.len() < DIR_ENTRY_SIZE {
        return None;
    }

    let first_byte = raw[0];

    // 0x00 = end of directory
    if first_byte == 0x00 {
        return None;
    }

    // 0xE5 = deleted entry — skip
    if first_byte == 0xE5 {
        return Some(Fat32DirEntry {
            name: String::new(), // sentinel for "skip"
            attr: 0,
            first_cluster: 0,
            file_size: 0,
            nt_res: 0,
            dir_entry_offset: 0,
            dir_entry_cluster: 0,
        });
    }

    let attributes = raw[11];

    // Skip long filename entries (handled separately) and volume ID.
    if attributes == attr::LONG_NAME || attributes & attr::VOLUME_ID != 0 {
        return Some(Fat32DirEntry {
            name: String::new(),
            attr: attributes,
            first_cluster: 0,
            file_size: 0,
            nt_res: 0,
            dir_entry_offset: 0,
            dir_entry_cluster: 0,
        });
    }

    let name = parse_short_name(raw);
    let nt_res = raw[12];

    let cluster_hi = u16::from_le_bytes([raw[20], raw[21]]) as u32;
    let cluster_lo = u16::from_le_bytes([raw[26], raw[27]]) as u32;
    let first_cluster = (cluster_hi << 16) | cluster_lo;

    let file_size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);

    Some(Fat32DirEntry {
        name,
        attr: attributes,
        first_cluster,
        file_size,
        nt_res,
        dir_entry_offset: 0,  // filled in by caller
        dir_entry_cluster: 0, // filled in by caller
    })
}

// ── Long Filename (LFN) Support ─────────────────────────────────────────────

/// Extract UCS-2 characters from a long filename directory entry.
fn lfn_chars(raw: &[u8]) -> Vec<u16> {
    let mut chars = Vec::with_capacity(13);
    // Characters are at fixed offsets in the LFN entry:
    // Offset 1-10 (5 chars), 14-25 (6 chars), 28-31 (2 chars)
    let offsets: &[usize] = &[1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for &off in offsets {
        if off + 1 < raw.len() {
            let ch = u16::from_le_bytes([raw[off], raw[off + 1]]);
            if ch == 0x0000 || ch == 0xFFFF {
                break;
            }
            chars.push(ch);
        }
    }
    chars
}

/// Decode a sequence of UCS-2 code units to a String.
fn ucs2_to_string(chars: &[u16]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &ch in chars {
        if let Some(c) = char::from_u32(ch as u32) {
            s.push(c);
        }
    }
    s
}

/// Return the absolute byte offset of the 32-byte directory slot that
/// immediately precedes `cur_off` in the directory whose cluster chain is
/// `chain`. Handles cluster-boundary wrap-around: when `cur_off` is at the
/// first slot of a cluster, steps back into the last slot of the previous
/// cluster in the chain. Returns `None` at the very first slot of the chain.
///
/// Used by `remove()` (FAT32-5) to mark preceding LFN entries as 0xE5.
fn prev_dir_slot(
    cur_off: usize,
    chain: &[u32],
    bpb: &Fat32Bpb,
    cluster_size: usize,
) -> Option<usize> {
    if chain.is_empty() {
        return None;
    }
    // Find which cluster in the chain contains cur_off.
    // Each cluster covers [cluster_to_sector(c)*SECTOR_SIZE,
    //                      cluster_to_sector(c)*SECTOR_SIZE + cluster_size).
    let mut cluster_idx_opt: Option<usize> = None;
    for (i, &c) in chain.iter().enumerate() {
        let base = (bpb.cluster_to_sector(c) as usize) * SECTOR_SIZE;
        if cur_off >= base && cur_off < base + cluster_size {
            cluster_idx_opt = Some(i);
            break;
        }
    }
    let cluster_idx = cluster_idx_opt?;
    let base = (bpb.cluster_to_sector(chain[cluster_idx]) as usize) * SECTOR_SIZE;
    let within = cur_off - base;
    if within >= DIR_ENTRY_SIZE {
        // Simple case: stay in the same cluster.
        Some(cur_off - DIR_ENTRY_SIZE)
    } else if cluster_idx > 0 {
        // Wrap to the last slot of the previous cluster in the chain.
        let prev_base = (bpb.cluster_to_sector(chain[cluster_idx - 1]) as usize) * SECTOR_SIZE;
        Some(prev_base + cluster_size - DIR_ENTRY_SIZE)
    } else {
        None
    }
}

// ── FAT32 VFS Node ──────────────────────────────────────────────────────────

/// Internal node stored for each discovered file/directory.
#[derive(Clone)]
struct Fat32Node {
    inode: u64,
    name: String,
    file_type: FileType,
    first_cluster: u32,
    size: u64,
    /// Cluster of the parent directory (0 for root).
    parent_cluster: u32,
    /// Byte offset of this entry's 32-byte directory record within the
    /// parent directory's cluster data (absolute byte offset in volume).
    dir_entry_offset: usize,
    /// First cluster of the directory that contains this entry.
    dir_entry_cluster: u32,
    /// True only for the filesystem's root node. Used by `flush_dir_entry`
    /// to short-circuit updates for the root (which has no parent directory
    /// entry to update). Previously `flush_dir_entry` relied on
    /// `dir_entry_offset == 0 && parent_cluster == 0`, which can legitimately
    /// be true for a file at the very first slot of the root directory on
    /// corrupted/edge BPBs where `root_cluster == 0` (FAT32-7).
    is_root: bool,
    /// NT-case preservation flags (byte 12 of the directory entry, `NTRes`).
    /// Bit 0x08 = basename is lowercase for display, 0x10 = extension is
    /// lowercase (FAT32-8). New files created by this driver always have
    /// NTRes=0 (MS-DOS semantics); existing files from Windows retain their
    /// original NTRes on read. Only used by `flush_dir_entry` to preserve
    /// the byte on round-trip updates.
    nt_res: u8,
    /// Cached cluster chain for fast random-access reads.
    /// Built lazily on first read.  chain[i] = cluster number for logical
    /// cluster i of this file.  Eliminates O(n) FAT walk per page fault
    /// (critical for 194MB libxul.so with ~47000 clusters).
    cluster_chain: alloc::vec::Vec<u32>,
}

// ── FAT32 Filesystem ────────────────────────────────────────────────────────

/// FAT32 filesystem instance.
pub struct Fat32Fs {
    device: Box<dyn BlockDevice>,
    bpb: Fat32Bpb,
    inner: Mutex<Fat32Inner>,
}

struct Fat32Inner {
    /// All discovered nodes (inodes).
    nodes: Vec<Fat32Node>,
    /// Cached FAT table (all entries). Modified in place for writes.
    fat: Vec<u32>,
    /// Sparse sector cache: maps LBA → 512-byte sector data.
    /// Sectors are loaded on demand from the block device.
    sector_cache: BTreeMap<u64, [u8; SECTOR_SIZE]>,
    /// Set of dirty sector LBAs that need to be written back.
    dirty: BTreeSet<u64>,
    /// Set of parent cluster numbers whose directory contents have been fully
    /// read from disk. Used by `ensure_children_loaded` to distinguish
    /// "already scanned from disk" from "has in-memory children" — the latter
    /// is no longer a valid proxy (FAT32-3) once `create_file` can inject
    /// nodes before a scan.
    scanned_clusters: BTreeSet<u32>,
}

impl Fat32Fs {
    /// Create a new FAT32 filesystem from a block device.
    pub fn new(device: Box<dyn BlockDevice>) -> Result<Self, VfsError> {
        // Read boot sector.
        let mut boot_sector = [0u8; SECTOR_SIZE];
        device.read_sector(0, &mut boot_sector).map_err(|_| VfsError::Io)?;

        let bpb = Fat32Bpb::parse(&boot_sector)?;

        crate::serial_println!(
            "[FAT32] BPB: {} bytes/sector, {} sectors/cluster, {} reserved, \
             {} FATs, fat_size={}, root_cluster={}, total_sectors={}",
            bpb.bytes_per_sector,
            bpb.sectors_per_cluster,
            bpb.reserved_sectors,
            bpb.num_fats,
            bpb.fat_size,
            bpb.root_cluster,
            bpb.total_sectors
        );

        // Build a sparse sector cache — pre-load only the FAT sectors.
        let mut sector_cache: BTreeMap<u64, [u8; SECTOR_SIZE]> = BTreeMap::new();

        // Cache the boot sector we already have.
        sector_cache.insert(0, boot_sector);

        // Read FAT #1 sectors into cache.
        let fat_start = bpb.fat_start_sector as u64;
        let fat_sectors = bpb.fat_size as u64;
        for lba in fat_start..fat_start + fat_sectors {
            let mut buf = [0u8; SECTOR_SIZE];
            device.read_sector(lba, &mut buf).map_err(|_| VfsError::Io)?;
            sector_cache.insert(lba, buf);
        }

        // Read FAT #2 sectors into cache (if present).
        if bpb.num_fats >= 2 {
            let fat2_start = fat_start + fat_sectors;
            for lba in fat2_start..fat2_start + fat_sectors {
                let mut buf = [0u8; SECTOR_SIZE];
                device.read_sector(lba, &mut buf).map_err(|_| VfsError::Io)?;
                sector_cache.insert(lba, buf);
            }
        }

        // Parse FAT entries from cached FAT sectors.
        let fat_byte_size = (bpb.fat_size as usize) * SECTOR_SIZE;
        let fat_entry_count = fat_byte_size / 4;
        let mut fat = Vec::with_capacity(fat_entry_count);
        for i in 0..fat_entry_count {
            let abs_byte = (bpb.fat_start_sector as usize) * SECTOR_SIZE + i * 4;
            let sector_lba = (abs_byte / SECTOR_SIZE) as u64;
            let offset_in_sector = abs_byte % SECTOR_SIZE;
            if let Some(sector_data) = sector_cache.get(&sector_lba) {
                let entry = u32::from_le_bytes([
                    sector_data[offset_in_sector],
                    sector_data[offset_in_sector + 1],
                    sector_data[offset_in_sector + 2],
                    sector_data[offset_in_sector + 3],
                ]) & FAT_ENTRY_MASK;
                fat.push(entry);
            } else {
                fat.push(0);
            }
        }

        crate::serial_println!(
            "[FAT32] Read {} FAT entries, cached {} sectors",
            fat.len(),
            sector_cache.len()
        );

        // Create root node.
        let root_inode = alloc_inode_number();
        let root_node = Fat32Node {
            inode: root_inode,
            name: String::from("/"),
            file_type: FileType::Directory,
            first_cluster: bpb.root_cluster,
            size: 0,
            parent_cluster: 0,
            dir_entry_offset: 0,
            dir_entry_cluster: 0,
            is_root: true,
            nt_res: 0,
            cluster_chain: alloc::vec::Vec::new(),
        };

        let mut scanned_clusters = BTreeSet::new();
        // Mount pre-scans the root directory below, so record that here so
        // a later `create_file` can't cause `ensure_children_loaded` to skip
        // re-scanning (FAT32-3).
        scanned_clusters.insert(bpb.root_cluster);

        let inner = Fat32Inner {
            nodes: vec![root_node],
            fat,
            sector_cache,
            dirty: BTreeSet::new(),
            scanned_clusters,
        };

        let root_cluster = bpb.root_cluster;
        let fs = Self {
            device,
            bpb,
            inner: Mutex::new(inner),
        };

        // Pre-scan root directory to populate initial nodes.
        let entries = fs.read_directory_raw(root_cluster)?;
        {
            let mut inner = fs.inner.lock();
            for entry in &entries {
                if entry.name.is_empty() || entry.name == "." || entry.name == ".." {
                    continue;
                }
                let inode = alloc_inode_number();
                inner.nodes.push(Fat32Node {
                    inode,
                    name: entry.name.clone(),
                    file_type: entry.file_type(),
                    first_cluster: entry.first_cluster,
                    size: entry.file_size as u64,
                    parent_cluster: root_cluster,
                    dir_entry_offset: entry.dir_entry_offset,
                    dir_entry_cluster: entry.dir_entry_cluster,
                    is_root: false,
                    nt_res: entry.nt_res,
                    cluster_chain: alloc::vec::Vec::new(),
                });
            }
        }

        let node_count = fs.inner.lock().nodes.len();
        crate::serial_println!("[FAT32] Mounted: {} nodes discovered in root", node_count - 1);

        Ok(fs)
    }

    /// Get the root inode number.
    pub fn root_inode(&self) -> u64 {
        self.inner.lock().nodes[0].inode
    }

    /// Count the number of free clusters in FAT1.
    /// A cluster is free when its FAT entry is 0.
    /// Clusters 0 and 1 are reserved; usable data clusters start at 2.
    pub fn count_free_clusters(&self) -> usize {
        let inner = self.inner.lock();
        inner.fat.iter().skip(2).filter(|&&v| v == 0).count()
    }

    /// Read the currently-cached FSInfo sector as the driver sees it.
    /// Used by FAT32-6 tests to verify that `do_sync` updates the free-count
    /// and next-free-hint fields. Returns `None` if the BPB specified no
    /// FSInfo sector (0 or 0xFFFF).
    pub fn cached_fsinfo(&self) -> Option<[u8; SECTOR_SIZE]> {
        let lba = self.bpb.fsinfo_sector;
        if lba == 0 || lba == 0xFFFF {
            return None;
        }
        let inner = self.inner.lock();
        inner.sector_cache.get(&(lba as u64)).copied()
    }

    /// Test-only: read the raw sector at `lba` from the cache.
    /// Returns `None` if not cached.
    pub fn cached_sector(&self, lba: u64) -> Option<[u8; SECTOR_SIZE]> {
        self.inner.lock().sector_cache.get(&lba).copied()
    }

    /// Test-only: write `data` to sector `lba` in the cache and mark dirty.
    /// Used by FAT32-5 regression test to plant a synthetic LFN run.
    pub fn test_poke_sector(&self, lba: u64, data: &[u8; SECTOR_SIZE]) {
        let mut inner = self.inner.lock();
        inner.sector_cache.insert(lba, *data);
        inner.dirty.insert(lba);
    }

    /// Test-only: expose data-region start sector (first data cluster is 2).
    pub fn data_start_sector(&self) -> u32 {
        self.bpb.data_start_sector
    }

    // ── Cache helpers ───────────────────────────────────────────────────

    /// Ensure a sector is in the sparse cache, loading from device if needed.
    fn ensure_sector(inner: &mut Fat32Inner, device: &dyn BlockDevice, lba: u64) -> Result<(), VfsError> {
        if !inner.sector_cache.contains_key(&lba) {
            // Evict old sectors if cache is too large (prevents OOM for large file reads).
            // 8K sectors × 512 bytes = 4MB maximum sector cache footprint.
            const MAX_SECTOR_CACHE: usize = 8192;
            if inner.sector_cache.len() >= MAX_SECTOR_CACHE {
                // Evict the first half (lowest LBAs — likely already consumed).
                // CRITICAL (FAT32-2): dirty sectors must be flushed before
                // eviction. FAT sectors live at the lowest LBAs and are the
                // most likely victims; dropping a dirty FAT sector silently
                // loses the cluster-allocation update.
                let to_remove: alloc::vec::Vec<u64> = inner.sector_cache.keys()
                    .take(MAX_SECTOR_CACHE / 2).copied().collect();
                for k in to_remove {
                    if inner.dirty.contains(&k) {
                        if let Some(sector) = inner.sector_cache.get(&k) {
                            let data = *sector;
                            if device.write_sectors(k, 1, &data).is_ok() {
                                inner.dirty.remove(&k);
                                crate::serial_println!(
                                    "[FAT32] flushed dirty sector {} during eviction", k);
                            } else {
                                // Write failed — keep the sector cached so
                                // a later `do_sync` can retry. Skip eviction
                                // of this entry.
                                crate::serial_println!(
                                    "[FAT32] WARN: failed to flush dirty sector {} during eviction; \
                                     keeping in cache", k);
                                continue;
                            }
                        }
                    }
                    inner.sector_cache.remove(&k);
                }
            }

            // Batch prefetch: read 8 consecutive sectors (4KB = one cluster) at once.
            const BATCH: u32 = 8;
            let batch_start = lba & !(BATCH as u64 - 1);
            let mut multi_buf = [0u8; SECTOR_SIZE * BATCH as usize];
            if device.read_sectors(batch_start, BATCH, &mut multi_buf).is_ok() {
                for i in 0..BATCH {
                    let sector_lba = batch_start + i as u64;
                    if !inner.sector_cache.contains_key(&sector_lba) {
                        let mut sector = [0u8; SECTOR_SIZE];
                        let off = i as usize * SECTOR_SIZE;
                        sector.copy_from_slice(&multi_buf[off..off + SECTOR_SIZE]);
                        inner.sector_cache.insert(sector_lba, sector);
                    }
                }
            } else {
                let mut buf = [0u8; SECTOR_SIZE];
                device.read_sector(lba, &mut buf).map_err(|_| VfsError::Io)?;
                inner.sector_cache.insert(lba, buf);
            }
        }
        Ok(())
    }

    /// Read bytes from the sparse sector cache at a given absolute byte offset.
    /// Loads sectors on demand from the block device.
    fn cache_read(&self, offset: usize, len: usize) -> Result<Vec<u8>, VfsError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let first_sector = (offset / SECTOR_SIZE) as u64;
        let last_sector = ((offset + len - 1) / SECTOR_SIZE) as u64;

        let mut inner = self.inner.lock();
        for lba in first_sector..=last_sector {
            Self::ensure_sector(&mut inner, &*self.device, lba)?;
        }

        let mut result = Vec::with_capacity(len);
        let mut pos = offset;
        let mut remaining = len;
        while remaining > 0 {
            let sector_lba = (pos / SECTOR_SIZE) as u64;
            let sector_off = pos % SECTOR_SIZE;
            let avail = SECTOR_SIZE - sector_off;
            let to_copy = core::cmp::min(avail, remaining);

            let sector_data = inner.sector_cache.get(&sector_lba).ok_or(VfsError::Io)?;
            result.extend_from_slice(&sector_data[sector_off..sector_off + to_copy]);

            pos += to_copy;
            remaining -= to_copy;
        }
        Ok(result)
    }

    /// Write bytes into the sparse sector cache and mark sectors dirty.
    /// Loads sectors on demand so partial-sector writes are correct.
    fn cache_write(&self, offset: usize, data: &[u8]) -> Result<(), VfsError> {
        if data.is_empty() {
            return Ok(());
        }
        let first_sector = (offset / SECTOR_SIZE) as u64;
        let last_sector = ((offset + data.len() - 1) / SECTOR_SIZE) as u64;

        let mut inner = self.inner.lock();
        for lba in first_sector..=last_sector {
            Self::ensure_sector(&mut inner, &*self.device, lba)?;
        }

        let mut written = 0usize;
        let mut pos = offset;
        while written < data.len() {
            let sector_lba = (pos / SECTOR_SIZE) as u64;
            let sector_off = pos % SECTOR_SIZE;
            let avail = SECTOR_SIZE - sector_off;
            let to_copy = core::cmp::min(avail, data.len() - written);

            let sector_data = inner.sector_cache.get_mut(&sector_lba).ok_or(VfsError::Io)?;
            sector_data[sector_off..sector_off + to_copy]
                .copy_from_slice(&data[written..written + to_copy]);
            inner.dirty.insert(sector_lba);

            pos += to_copy;
            written += to_copy;
        }
        Ok(())
    }

    // ── FAT manipulation helpers ────────────────────────────────────────

    /// Read a FAT entry for a given cluster.
    fn fat_read(&self, cluster: u32) -> u32 {
        let inner = self.inner.lock();
        if (cluster as usize) < inner.fat.len() {
            inner.fat[cluster as usize]
        } else {
            0
        }
    }

    /// Write a FAT entry and update both the in-memory FAT vec and the
    /// sector cache bytes (for both FAT copies).
    fn fat_write(&self, cluster: u32, value: u32) {
        let mut inner = self.inner.lock();
        let idx = cluster as usize;
        if idx >= inner.fat.len() {
            return;
        }
        let masked = value & FAT_ENTRY_MASK;

        // Compute the absolute byte offset of this FAT entry.
        let fat_byte_offset = (self.bpb.fat_start_sector as usize) * SECTOR_SIZE + idx * 4;
        let sector_lba = (fat_byte_offset / SECTOR_SIZE) as u64;
        let sector_off = fat_byte_offset % SECTOR_SIZE;

        // Ensure sector is cached.
        let _ = Self::ensure_sector(&mut inner, &*self.device, sector_lba);

        // Read old value to preserve upper 4 bits.
        let old_val = if let Some(s) = inner.sector_cache.get(&sector_lba) {
            u32::from_le_bytes([s[sector_off], s[sector_off+1], s[sector_off+2], s[sector_off+3]])
        } else {
            0
        };
        let new_val = (old_val & 0xF0000000) | masked;
        let new_bytes = new_val.to_le_bytes();

        inner.fat[idx] = masked;

        // Update FAT #1 in sector cache.
        if let Some(s) = inner.sector_cache.get_mut(&sector_lba) {
            s[sector_off..sector_off + 4].copy_from_slice(&new_bytes);
        }
        inner.dirty.insert(sector_lba);

        // Update FAT #2 (if present).
        if self.bpb.num_fats >= 2 {
            let fat2_byte_offset = fat_byte_offset + (self.bpb.fat_size as usize) * SECTOR_SIZE;
            let sector2_lba = (fat2_byte_offset / SECTOR_SIZE) as u64;
            let sector2_off = fat2_byte_offset % SECTOR_SIZE;
            let _ = Self::ensure_sector(&mut inner, &*self.device, sector2_lba);
            if let Some(s) = inner.sector_cache.get_mut(&sector2_lba) {
                s[sector2_off..sector2_off + 4].copy_from_slice(&new_bytes);
            }
            inner.dirty.insert(sector2_lba);
        }
    }

    /// Allocate a free cluster. Scans the FAT for a 0 entry starting after
    /// cluster 2. Returns the cluster number, already marked as EOC.
    fn alloc_cluster(&self) -> Result<u32, VfsError> {
        let free_cluster = {
            let inner = self.inner.lock();
            let mut found = None;
            for i in 2..inner.fat.len() {
                if inner.fat[i] == 0 {
                    found = Some(i as u32);
                    break;
                }
            }
            found
        };
        match free_cluster {
            Some(c) => {
                self.fat_write(c, 0x0FFFFFFF); // EOC
                // Zero out the cluster data in sector cache.
                let cluster_start_sector = self.bpb.cluster_to_sector(c) as u64;
                let spc = self.bpb.sectors_per_cluster as u64;
                {
                    let mut inner = self.inner.lock();
                    for s in 0..spc {
                        let lba = cluster_start_sector + s;
                        inner.sector_cache.insert(lba, [0u8; SECTOR_SIZE]);
                        inner.dirty.insert(lba);
                    }
                }
                Ok(c)
            }
            None => Err(VfsError::NoSpace),
        }
    }

    /// Extend a cluster chain: allocate a new cluster and link it to the end
    /// of the chain that ends at `last_cluster`.
    fn extend_chain(&self, last_cluster: u32) -> Result<u32, VfsError> {
        let new = self.alloc_cluster()?;
        self.fat_write(last_cluster, new);
        Ok(new)
    }

    /// Free an entire cluster chain starting at `start`.
    fn free_chain(&self, start: u32) {
        let chain = self.follow_chain(start);
        for c in chain {
            self.fat_write(c, 0);
        }
    }

    // ── Cluster chain helpers ───────────────────────────────────────────

    /// Follow a cluster chain, returning all clusters in order.
    fn follow_chain(&self, start_cluster: u32) -> Vec<u32> {
        let inner = self.inner.lock();
        let mut chain = Vec::new();
        let mut current = start_cluster;

        let max_clusters = inner.fat.len();
        for _ in 0..max_clusters {
            if current < 2 || current as usize >= inner.fat.len() {
                break;
            }
            chain.push(current);
            let next = inner.fat[current as usize];
            if next >= FAT_EOC_MIN {
                break;
            }
            if next < 2 {
                break;
            }
            current = next;
        }
        chain
    }

    /// Read all data from a cluster chain, loading sectors on demand.
    fn read_chain(&self, start_cluster: u32, max_bytes: usize) -> Result<Vec<u8>, VfsError> {
        let chain = self.follow_chain(start_cluster);
        let cluster_size = self.bpb.cluster_size as usize;
        let spc = self.bpb.sectors_per_cluster as u64;
        let mut data = Vec::with_capacity(core::cmp::min(
            chain.len() * cluster_size,
            max_bytes,
        ));

        let mut inner = self.inner.lock();
        for &cluster in &chain {
            if data.len() >= max_bytes {
                break;
            }
            let first_sector = self.bpb.cluster_to_sector(cluster) as u64;
            // Ensure all sectors of this cluster are cached.
            for s in 0..spc {
                Self::ensure_sector(&mut inner, &*self.device, first_sector + s)?;
            }

            let remaining = max_bytes - data.len();
            let copy_len = core::cmp::min(cluster_size, remaining);

            // Copy from cached sectors.
            let mut copied = 0;
            for s in 0..spc {
                if copied >= copy_len {
                    break;
                }
                let lba = first_sector + s;
                let sector_data = inner.sector_cache.get(&lba).ok_or(VfsError::Io)?;
                let to_copy = core::cmp::min(SECTOR_SIZE, copy_len - copied);
                data.extend_from_slice(&sector_data[..to_copy]);
                copied += to_copy;
            }
        }

        data.truncate(max_bytes);
        Ok(data)
    }

    // ── Directory parsing ───────────────────────────────────────────────

    /// Read raw directory entries from a directory cluster chain.
    /// Populates dir_entry_offset and dir_entry_cluster on each returned entry.
    fn read_directory_raw(&self, dir_cluster: u32) -> Result<Vec<Fat32DirEntry>, VfsError> {
        let chain = self.follow_chain(dir_cluster);
        let cluster_size = self.bpb.cluster_size as usize;
        let spc = self.bpb.sectors_per_cluster as u64;

        // Collect all directory data, ensuring sectors are cached on demand.
        let mut dir_data = Vec::new();
        {
            let mut inner = self.inner.lock();
            for &cluster in &chain {
                let first_sector = self.bpb.cluster_to_sector(cluster) as u64;
                for s in 0..spc {
                    let lba = first_sector + s;
                    Self::ensure_sector(&mut inner, &*self.device, lba)?;
                    if let Some(sector_data) = inner.sector_cache.get(&lba) {
                        dir_data.extend_from_slice(sector_data);
                    }
                }
            }
        }

        // Build a map: byte-offset-in-dir-data → absolute byte offset in volume.
        // dir_data[i] came from: chain[i / cluster_size] at local offset (i % cluster_size).
        let abs_offset = |local: usize| -> usize {
            let cluster_idx = local / cluster_size;
            let within = local % cluster_size;
            if cluster_idx < chain.len() {
                (self.bpb.cluster_to_sector(chain[cluster_idx]) as usize) * SECTOR_SIZE + within
            } else {
                0
            }
        };

        let mut entries = Vec::new();
        let mut lfn_buffer: Vec<u16> = Vec::new();

        let mut i = 0;
        while i + DIR_ENTRY_SIZE <= dir_data.len() {
            let raw = &dir_data[i..i + DIR_ENTRY_SIZE];
            let entry_abs_offset = abs_offset(i);

            if raw[0] == 0x00 {
                break;
            }

            i += DIR_ENTRY_SIZE;

            if raw[0] == 0xE5 {
                lfn_buffer.clear();
                continue;
            }

            let attributes = raw[11];

            if attributes == attr::LONG_NAME {
                let is_last = raw[0] & 0x40 != 0;
                if is_last {
                    lfn_buffer.clear();
                }
                let chars = lfn_chars(raw);
                let mut new_buf = chars;
                new_buf.extend_from_slice(&lfn_buffer);
                lfn_buffer = new_buf;
                continue;
            }

            if attributes & attr::VOLUME_ID != 0 {
                lfn_buffer.clear();
                continue;
            }

            if let Some(mut entry) = parse_dir_entry(raw) {
                if !entry.name.is_empty() {
                    if !lfn_buffer.is_empty() {
                        entry.name = ucs2_to_string(&lfn_buffer);
                    }
                    entry.dir_entry_offset = entry_abs_offset;
                    entry.dir_entry_cluster = dir_cluster;
                    entries.push(entry);
                }
            }

            lfn_buffer.clear();
        }

        Ok(entries)
    }

    /// Find or create inode nodes for a directory's children.
    ///
    /// Uses `scanned_clusters` to track which directory clusters have been
    /// read from disk. The previous "any in-memory child" heuristic was
    /// incorrect (FAT32-3): once `create_file` injects a single node, it
    /// short-circuits the disk scan for the whole directory and any
    /// pre-existing on-disk files remain invisible.
    fn ensure_children_loaded(&self, parent_cluster: u32) -> Result<(), VfsError> {
        {
            let inner = self.inner.lock();
            if inner.scanned_clusters.contains(&parent_cluster) {
                return Ok(());
            }
        }

        let entries = self.read_directory_raw(parent_cluster)?;

        let mut inner = self.inner.lock();
        for entry in &entries {
            if entry.name.is_empty() || entry.name == "." || entry.name == ".." {
                continue;
            }
            let exists = inner.nodes.iter().any(|n| {
                n.parent_cluster == parent_cluster && n.name == entry.name
            });
            if !exists {
                let inode = alloc_inode_number();
                inner.nodes.push(Fat32Node {
                    inode,
                    name: entry.name.clone(),
                    file_type: entry.file_type(),
                    first_cluster: entry.first_cluster,
                    size: entry.file_size as u64,
                    parent_cluster,
                    dir_entry_offset: entry.dir_entry_offset,
                    dir_entry_cluster: entry.dir_entry_cluster,
                    is_root: false,
                    nt_res: entry.nt_res,
                    cluster_chain: alloc::vec::Vec::new(),
                });
            }
        }
        inner.scanned_clusters.insert(parent_cluster);

        Ok(())
    }

    /// Find a node by inode number.
    fn find_node(&self, inode: u64) -> Option<Fat32Node> {
        self.inner.lock().nodes.iter().find(|n| n.inode == inode).cloned()
    }

    // ── Directory entry write helpers ───────────────────────────────────

    /// Update the file size and first cluster of a node's directory entry
    /// in the cache.
    fn flush_dir_entry(&self, node: &Fat32Node) -> Result<(), VfsError> {
        // The old guard `dir_entry_offset == 0 && parent_cluster == 0` can
        // false-positive on corrupted/edge BPBs where `root_cluster == 0`
        // (which would make a real child of root satisfy both conditions)
        // — FAT32-7. Use the explicit root flag instead.
        if node.is_root {
            return Ok(());
        }
        let off = node.dir_entry_offset;
        let sector_lba = (off / SECTOR_SIZE) as u64;
        let sector_off = off % SECTOR_SIZE;

        let mut inner = self.inner.lock();
        Self::ensure_sector(&mut inner, &*self.device, sector_lba)?;

        let sector_data = inner.sector_cache.get_mut(&sector_lba).ok_or(VfsError::Io)?;
        // Update first cluster high (bytes 20-21).
        let cluster_hi = ((node.first_cluster >> 16) & 0xFFFF) as u16;
        sector_data[sector_off + 20..sector_off + 22].copy_from_slice(&cluster_hi.to_le_bytes());
        // Update first cluster low (bytes 26-27).
        let cluster_lo = (node.first_cluster & 0xFFFF) as u16;
        sector_data[sector_off + 26..sector_off + 28].copy_from_slice(&cluster_lo.to_le_bytes());
        // Update file size (bytes 28-31).
        let size = node.size as u32;
        sector_data[sector_off + 28..sector_off + 32].copy_from_slice(&size.to_le_bytes());

        inner.dirty.insert(sector_lba);
        Ok(())
    }

    /// Make an 8.3 short name from a user-supplied filename.
    /// Returns (name8, ext3, full_lower) — the 8-byte name, 3-byte extension,
    /// and the lowercased display name.
    fn make_short_name(name: &str) -> ([u8; 8], [u8; 3], String) {
        let upper = name.to_ascii_uppercase();
        let display = name.to_ascii_lowercase();

        let (base, ext) = if let Some(dot_pos) = upper.rfind('.') {
            (&upper[..dot_pos], &upper[dot_pos + 1..])
        } else {
            (upper.as_str(), "")
        };

        let mut name8 = [b' '; 8];
        for (i, &b) in base.as_bytes().iter().take(8).enumerate() {
            name8[i] = b;
        }

        let mut ext3 = [b' '; 3];
        for (i, &b) in ext.as_bytes().iter().take(3).enumerate() {
            ext3[i] = b;
        }

        (name8, ext3, display)
    }

    /// Find a free 32-byte slot in a directory's cluster chain.
    /// Returns the absolute byte offset of the free slot, allocating a new
    /// cluster if necessary.
    fn find_free_dir_slot(&self, dir_cluster: u32) -> Result<usize, VfsError> {
        let chain = self.follow_chain(dir_cluster);
        let cluster_size = self.bpb.cluster_size as usize;
        let spc = self.bpb.sectors_per_cluster as u64;

        // Scan existing clusters for a free or end-of-directory slot.
        {
            let mut inner = self.inner.lock();
            for &cluster in &chain {
                let first_sector = self.bpb.cluster_to_sector(cluster) as u64;
                for s in 0..spc {
                    let lba = first_sector + s;
                    Self::ensure_sector(&mut inner, &*self.device, lba)?;
                }

                let base = (first_sector as usize) * SECTOR_SIZE;
                let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
                for e in 0..entries_per_cluster {
                    let off = base + e * DIR_ENTRY_SIZE;
                    let entry_sector = (off / SECTOR_SIZE) as u64;
                    let entry_offset = off % SECTOR_SIZE;
                    if let Some(sector_data) = inner.sector_cache.get(&entry_sector) {
                        let first = sector_data[entry_offset];
                        if first == 0x00 || first == 0xE5 {
                            return Ok(off);
                        }
                    }
                }
            }
        }

        // No free slot — extend the directory with a new cluster.
        let last = *chain.last().ok_or(VfsError::Io)?;
        let new_cluster = self.extend_chain(last)?;
        let new_offset = (self.bpb.cluster_to_sector(new_cluster) as usize) * SECTOR_SIZE;
        Ok(new_offset)
    }

    /// Write a 32-byte directory entry at the given absolute cache offset.
    fn write_dir_entry_at(
        &self,
        offset: usize,
        name8: &[u8; 8],
        ext3: &[u8; 3],
        attr: u8,
        first_cluster: u32,
        file_size: u32,
    ) -> Result<(), VfsError> {
        let mut entry = [0u8; DIR_ENTRY_SIZE];
        entry[0..8].copy_from_slice(name8);
        entry[8..11].copy_from_slice(ext3);
        entry[11] = attr;
        // bytes 12-19: reserved/time/date — leave as 0.
        let cluster_hi = ((first_cluster >> 16) & 0xFFFF) as u16;
        entry[20..22].copy_from_slice(&cluster_hi.to_le_bytes());
        let cluster_lo = (first_cluster & 0xFFFF) as u16;
        entry[26..28].copy_from_slice(&cluster_lo.to_le_bytes());
        entry[28..32].copy_from_slice(&file_size.to_le_bytes());

        self.cache_write(offset, &entry)
    }

    // ── Sync to disk ────────────────────────────────────────────────────

    /// Refresh the FSInfo sector (FAT32-6). Computes the free-cluster count
    /// from the in-memory FAT and writes it (plus a next-free hint) into the
    /// cached FSInfo sector, after validating the three FAT32 FSInfo
    /// signatures. If signatures don't match we leave the sector alone rather
    /// than corrupt an unrelated reserved sector.
    ///
    /// Assumes the caller does not hold `inner`.
    fn refresh_fsinfo(&self) -> Result<(), VfsError> {
        let fsinfo_lba = self.bpb.fsinfo_sector;
        if fsinfo_lba == 0 || fsinfo_lba == 0xFFFF {
            return Ok(());
        }
        let lba = fsinfo_lba as u64;

        // Compute free-cluster count and lowest free cluster.
        // Clusters 0 and 1 are reserved; data clusters start at 2.
        let (free_count, next_free_hint) = {
            let inner = self.inner.lock();
            let mut count: u32 = 0;
            let mut lowest: Option<u32> = None;
            for (i, &v) in inner.fat.iter().enumerate().skip(2) {
                if v == 0 {
                    count = count.saturating_add(1);
                    if lowest.is_none() {
                        lowest = Some(i as u32);
                    }
                }
            }
            (count, lowest.unwrap_or(0xFFFFFFFF))
        };

        let mut inner = self.inner.lock();
        Self::ensure_sector(&mut inner, &*self.device, lba)?;
        let sector = match inner.sector_cache.get_mut(&lba) {
            Some(s) => s,
            None => return Ok(()),
        };

        // Validate FSInfo signatures. Misplaced/wrong FSInfo pointer is a
        // real-world BPB bug — don't stomp on a non-FSInfo sector.
        let sig1 = u32::from_le_bytes([sector[0], sector[1], sector[2], sector[3]]);
        let sig2 = u32::from_le_bytes([sector[484], sector[485], sector[486], sector[487]]);
        let sig3 = u32::from_le_bytes([sector[508], sector[509], sector[510], sector[511]]);
        if sig1 != 0x41615252 || sig2 != 0x61417272 || sig3 != 0xAA550000 {
            crate::serial_println!(
                "[FAT32] FSInfo sector {} signatures invalid ({:#x}/{:#x}/{:#x}); \
                 skipping update", lba, sig1, sig2, sig3);
            return Ok(());
        }

        // Free-cluster count at offset 488 (4 bytes LE).
        sector[488..492].copy_from_slice(&free_count.to_le_bytes());
        // Next-free-cluster hint at offset 492 (4 bytes LE).
        sector[492..496].copy_from_slice(&next_free_hint.to_le_bytes());
        inner.dirty.insert(lba);
        Ok(())
    }

    /// Flush all dirty sectors from cache to the underlying block device.
    fn do_sync(&self) -> Result<(), VfsError> {
        // Refresh FSInfo free count/hint BEFORE collecting the dirty set so
        // the FSInfo sector itself is included in this flush (FAT32-6).
        let _ = self.refresh_fsinfo();

        let dirty: Vec<u64> = {
            let inner = self.inner.lock();
            inner.dirty.iter().copied().collect()
        };

        if dirty.is_empty() {
            return Ok(());
        }

        crate::serial_println!("[FAT32] Syncing {} dirty sectors", dirty.len());

        for &lba in &dirty {
            let data = {
                let inner = self.inner.lock();
                match inner.sector_cache.get(&lba) {
                    Some(sector) => *sector,
                    None => {
                        // After FAT32-2's eviction fix, a dirty LBA should
                        // always be present in the cache (eviction flushes
                        // and clears `dirty` atomically under the lock).
                        // If we see this, it indicates a bug somewhere.
                        crate::serial_println!(
                            "[FAT32] WARN: dirty sector {} not in cache at sync!", lba);
                        continue;
                    }
                }
            };
            self.device.write_sectors(lba, 1, &data).map_err(|_| VfsError::Io)?;
        }

        self.inner.lock().dirty.clear();
        Ok(())
    }
}

// ── FileSystemOps Implementation ────────────────────────────────────────────

impl FileSystemOps for Fat32Fs {
    fn name(&self) -> &str {
        "fat32"
    }

    fn create_file(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        let parent = self.find_node(parent_inode).ok_or(VfsError::NotFound)?;
        if parent.file_type != FileType::Directory {
            return Err(VfsError::NotADirectory);
        }

        // Check for duplicates.
        self.ensure_children_loaded(parent.first_cluster)?;
        {
            let inner = self.inner.lock();
            let name_lower = name.to_ascii_lowercase();
            if inner.nodes.iter().any(|n| {
                n.parent_cluster == parent.first_cluster
                    && n.name.to_ascii_lowercase() == name_lower
            }) {
                return Err(VfsError::FileExists);
            }
        }

        let (name8, ext3, display) = Self::make_short_name(name);

        // Find a free slot in the parent directory.
        let slot_offset = self.find_free_dir_slot(parent.first_cluster)?;

        // Write the directory entry (size=0, no cluster yet).
        self.write_dir_entry_at(slot_offset, &name8, &ext3, 0x20, 0, 0)?;

        // Create the in-memory node.
        let inode = alloc_inode_number();
        let node = Fat32Node {
            inode,
            name: display,
            file_type: FileType::RegularFile,
            first_cluster: 0,
            size: 0,
            parent_cluster: parent.first_cluster,
            dir_entry_offset: slot_offset,
            dir_entry_cluster: parent.first_cluster,
            is_root: false,
            nt_res: 0, // new files written by us follow MS-DOS semantics
            cluster_chain: alloc::vec::Vec::new(),
        };
        self.inner.lock().nodes.push(node);

        // Auto-sync to disk.
        let _ = self.do_sync();

        Ok(inode)
    }

    fn create_dir(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        let parent = self.find_node(parent_inode).ok_or(VfsError::NotFound)?;
        if parent.file_type != FileType::Directory {
            return Err(VfsError::NotADirectory);
        }

        // Check for duplicates.
        self.ensure_children_loaded(parent.first_cluster)?;
        {
            let inner = self.inner.lock();
            let name_lower = name.to_ascii_lowercase();
            if inner.nodes.iter().any(|n| {
                n.parent_cluster == parent.first_cluster
                    && n.name.to_ascii_lowercase() == name_lower
            }) {
                return Err(VfsError::FileExists);
            }
        }

        let (name8, ext3, display) = Self::make_short_name(name);

        // Allocate a cluster for the new directory.
        let new_cluster = self.alloc_cluster()?;

        // Write . and .. entries in the new cluster.
        let cluster_offset = (self.bpb.cluster_to_sector(new_cluster) as usize) * SECTOR_SIZE;
        // . entry
        self.write_dir_entry_at(
            cluster_offset,
            b".       ", b"   ",
            attr::DIRECTORY, new_cluster, 0,
        )?;
        // .. entry
        self.write_dir_entry_at(
            cluster_offset + DIR_ENTRY_SIZE,
            b"..      ", b"   ",
            attr::DIRECTORY, parent.first_cluster, 0,
        )?;

        // Find a free slot in the parent directory.
        let slot_offset = self.find_free_dir_slot(parent.first_cluster)?;

        // Write the directory entry in the parent.
        self.write_dir_entry_at(slot_offset, &name8, &ext3, attr::DIRECTORY, new_cluster, 0)?;

        // Create the in-memory node.
        let inode = alloc_inode_number();
        let node = Fat32Node {
            inode,
            name: display,
            file_type: FileType::Directory,
            first_cluster: new_cluster,
            size: 0,
            parent_cluster: parent.first_cluster,
            dir_entry_offset: slot_offset,
            dir_entry_cluster: parent.first_cluster,
            is_root: false,
            nt_res: 0,
            cluster_chain: alloc::vec::Vec::new(),
        };
        self.inner.lock().nodes.push(node);

        let _ = self.do_sync();
        Ok(inode)
    }

    fn remove(&self, parent_inode: u64, name: &str) -> VfsResult<()> {
        let parent = self.find_node(parent_inode).ok_or(VfsError::NotFound)?;
        if parent.file_type != FileType::Directory {
            return Err(VfsError::NotADirectory);
        }

        self.ensure_children_loaded(parent.first_cluster)?;

        let name_lower = name.to_ascii_lowercase();
        let node = {
            let inner = self.inner.lock();
            inner.nodes.iter().find(|n| {
                n.parent_cluster == parent.first_cluster
                    && n.name.to_ascii_lowercase() == name_lower
            }).cloned()
        }.ok_or(VfsError::NotFound)?;

        // If it's a directory, verify it's empty.
        if node.file_type == FileType::Directory {
            self.ensure_children_loaded(node.first_cluster)?;
            let inner = self.inner.lock();
            let has_children = inner.nodes.iter().any(|n| {
                n.parent_cluster == node.first_cluster && n.name != "/"
            });
            if has_children {
                return Err(VfsError::NotEmpty);
            }
        }

        // Free the cluster chain.
        if node.first_cluster >= 2 {
            self.free_chain(node.first_cluster);
        }

        // Walk the parent directory's cluster chain to translate absolute
        // byte offsets into (cluster-index-in-chain, within-cluster) pairs.
        // Needed for FAT32-5 so that scanning backwards across cluster
        // boundaries in a multi-cluster directory works correctly.
        let dir_chain = self.follow_chain(node.dir_entry_cluster);
        let cluster_size = self.bpb.cluster_size as usize;

        // Mark directory entry as deleted (0xE5) and also mark any preceding
        // LFN entries (attr byte 11 == 0x0F) as deleted. Otherwise orphaned
        // LFN entries re-associate with the next short-name entry on the next
        // scan, producing ghost filenames (FAT32-5).
        {
            let mut inner = self.inner.lock();
            let off = node.dir_entry_offset;
            let sector_lba = (off / SECTOR_SIZE) as u64;
            let sector_off = off % SECTOR_SIZE;
            let _ = Self::ensure_sector(&mut inner, &*self.device, sector_lba);
            if let Some(sector_data) = inner.sector_cache.get_mut(&sector_lba) {
                sector_data[sector_off] = 0xE5;
                inner.dirty.insert(sector_lba);
            }

            // FAT32-5: scan backwards 32 bytes at a time, crossing cluster
            // boundaries along the parent directory's chain. Stop at the
            // first non-LFN entry or when we run out of chain.
            let mut cur_off = off;
            loop {
                // Step back 32 bytes, handling cluster-boundary wrap-around.
                let new_off_opt = prev_dir_slot(cur_off, &dir_chain, &self.bpb, cluster_size);
                let prev_off = match new_off_opt {
                    Some(v) => v,
                    None => break, // at the very start of the directory chain
                };
                let prev_lba = (prev_off / SECTOR_SIZE) as u64;
                let prev_in  = prev_off % SECTOR_SIZE;
                if Self::ensure_sector(&mut inner, &*self.device, prev_lba).is_err() {
                    break;
                }
                let is_lfn = if let Some(s) = inner.sector_cache.get(&prev_lba) {
                    // Don't reap already-deleted (0xE5) entries as LFN —
                    // they belonged to a prior short-name entry's LFN run.
                    s[prev_in] != 0xE5 && s[prev_in + 11] == attr::LONG_NAME
                } else {
                    false
                };
                if !is_lfn {
                    break;
                }
                if let Some(s) = inner.sector_cache.get_mut(&prev_lba) {
                    s[prev_in] = 0xE5;
                    inner.dirty.insert(prev_lba);
                }
                cur_off = prev_off;
            }

            // Remove node from in-memory list.
            inner.nodes.retain(|n| n.inode != node.inode);

            // If we just removed a directory, its cluster is freed and may
            // later be reallocated to a different directory. Drop the
            // "already scanned" mark so a future lookup re-scans (FAT32-3).
            if node.file_type == FileType::Directory && node.first_cluster >= 2 {
                inner.scanned_clusters.remove(&node.first_cluster);
            }
        }

        let _ = self.do_sync();
        Ok(())
    }

    fn lookup(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        let parent = self.find_node(parent_inode).ok_or(VfsError::NotFound)?;
        if parent.file_type != FileType::Directory {
            return Err(VfsError::NotADirectory);
        }

        self.ensure_children_loaded(parent.first_cluster)?;

        let inner = self.inner.lock();
        let name_lower = name.to_ascii_lowercase();
        for node in &inner.nodes {
            if node.parent_cluster == parent.first_cluster
                && node.name.to_ascii_lowercase() == name_lower
            {
                return Ok(node.inode);
            }
        }

        Err(VfsError::NotFound)
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let node = self.find_node(inode).ok_or(VfsError::NotFound)?;

        if node.file_type != FileType::RegularFile {
            return Err(VfsError::IsADirectory);
        }

        if offset >= node.size {
            return Ok(0);
        }

        let cluster_size = self.bpb.cluster_size as usize;
        let spc = self.bpb.sectors_per_cluster as u64;

        // How many bytes remain in the file from `offset`.
        let file_remaining = (node.size - offset) as usize;
        let to_read = core::cmp::min(buf.len(), file_remaining);

        let start_cluster_idx = (offset as usize) / cluster_size;
        let offset_in_cluster = (offset as usize) % cluster_size;

        // Build cluster chain cache on first access (lazy).
        // This converts O(n) per-read FAT walks to O(1) indexed lookups.
        {
            let mut inner = self.inner.lock();
            // Check if chain needs building by looking at the node
            let needs_build = inner.nodes.iter()
                .find(|n| n.inode == inode)
                .map(|n| n.cluster_chain.is_empty() && n.first_cluster >= 2)
                .unwrap_or(false);
            if needs_build {
                let first_cluster = inner.nodes.iter()
                    .find(|n| n.inode == inode).unwrap().first_cluster;
                // Build chain by walking FAT (once, then cached)
                let mut chain = alloc::vec::Vec::new();
                let mut c = first_cluster;
                loop {
                    chain.push(c);
                    if c < 2 || c as usize >= inner.fat.len() { break; }
                    let next = inner.fat[c as usize];
                    if next >= FAT_EOC_MIN || next < 2 { break; }
                    c = next;
                }
                // Store in node
                if let Some(n) = inner.nodes.iter_mut().find(|n| n.inode == inode) {
                    n.cluster_chain = chain;
                }
            }
        }

        // Look up the starting cluster via the cached chain (O(1)).
        let mut current = {
            let inner = self.inner.lock();
            if let Some(n) = inner.nodes.iter().find(|n| n.inode == inode) {
                if start_cluster_idx < n.cluster_chain.len() {
                    n.cluster_chain[start_cluster_idx]
                } else {
                    return Ok(0); // offset beyond end of chain
                }
            } else {
                return Err(VfsError::NotFound);
            }
        };

        // Legacy fallback removed — cluster chain cache handles all cases.
        let _ = start_cluster_idx; // used above in chain lookup

        // Read the required bytes cluster by cluster.
        let mut written = 0usize;
        let mut cluster_skip = offset_in_cluster; // byte offset within first cluster
        let mut inner = self.inner.lock();

        while written < to_read {
            if current < 2 || current as usize >= inner.fat.len() {
                break;
            }

            let first_sector = self.bpb.cluster_to_sector(current) as u64;
            for s in 0..spc {
                Self::ensure_sector(&mut inner, &*self.device, first_sector + s)?;
            }

            // How many bytes to take from this cluster.
            let cluster_avail = cluster_size - cluster_skip;
            let this_copy = core::cmp::min(cluster_avail, to_read - written);

            // Copy sector-by-sector from the cache.
            let mut copied = 0;
            let mut byte_off = cluster_skip; // byte offset within cluster
            while copied < this_copy {
                let s = (byte_off / SECTOR_SIZE) as u64;
                let lba = first_sector + s;
                let in_sector = byte_off % SECTOR_SIZE;
                let sector_data = inner.sector_cache.get(&lba).ok_or(VfsError::Io)?;
                let avail = SECTOR_SIZE - in_sector;
                let n = core::cmp::min(avail, this_copy - copied);
                buf[written + copied..written + copied + n]
                    .copy_from_slice(&sector_data[in_sector..in_sector + n]);
                copied += n;
                byte_off += n;
            }

            written += this_copy;
            cluster_skip = 0; // subsequent clusters start at byte 0

            let next = inner.fat[current as usize];
            if next >= FAT_EOC_MIN || next < 2 {
                break;
            }
            current = next;
        }

        Ok(written)
    }

    fn write(&self, inode: u64, offset: u64, data: &[u8]) -> VfsResult<usize> {
        let mut node = self.find_node(inode).ok_or(VfsError::NotFound)?;

        if node.file_type != FileType::RegularFile {
            return Err(VfsError::IsADirectory);
        }

        if data.is_empty() {
            return Ok(0);
        }

        let cluster_size = self.bpb.cluster_size as usize;
        let end_offset = offset as usize + data.len();

        // Calculate how many clusters are needed for the file after this write.
        let needed_bytes = core::cmp::max(node.size as usize, end_offset);
        let needed_clusters = if needed_bytes == 0 { 0 } else { (needed_bytes + cluster_size - 1) / cluster_size };

        // Get current cluster chain.
        let mut chain = if node.first_cluster >= 2 {
            self.follow_chain(node.first_cluster)
        } else {
            Vec::new()
        };

        // Allocate the first cluster if the file has none.
        if chain.is_empty() && needed_clusters > 0 {
            let c = self.alloc_cluster()?;
            node.first_cluster = c;
            chain.push(c);
        }

        // Extend the chain if necessary.
        while chain.len() < needed_clusters {
            let last = *chain.last().unwrap();
            let new = self.extend_chain(last)?;
            chain.push(new);
        }

        // Write data into the appropriate cluster(s).
        let mut written = 0usize;
        let mut file_pos = offset as usize;

        while written < data.len() {
            let cluster_idx = file_pos / cluster_size;
            let within_cluster = file_pos % cluster_size;

            if cluster_idx >= chain.len() {
                break;
            }

            let cluster = chain[cluster_idx];
            let cluster_offset = (self.bpb.cluster_to_sector(cluster) as usize) * SECTOR_SIZE;
            let bytes_left_in_cluster = cluster_size - within_cluster;
            let to_write = core::cmp::min(bytes_left_in_cluster, data.len() - written);

            let abs_offset = cluster_offset + within_cluster;
            self.cache_write(abs_offset, &data[written..written + to_write])?;

            written += to_write;
            file_pos += to_write;
        }

        // Update file size.
        let new_size = core::cmp::max(node.size as usize, end_offset) as u64;
        node.size = new_size;

        // Update the directory entry on disk.
        self.flush_dir_entry(&node)?;

        // Update in-memory node.
        {
            let mut inner = self.inner.lock();
            if let Some(n) = inner.nodes.iter_mut().find(|n| n.inode == inode) {
                n.size = new_size;
                n.first_cluster = node.first_cluster;
                // Writes that extended the file may have allocated new
                // clusters beyond the cached chain. Clearing forces the
                // next read to rebuild the chain from the updated FAT
                // (FAT32-1). Without this, reads past the original EOF
                // silently return Ok(0).
                n.cluster_chain.clear();
            }
        }

        let _ = self.do_sync();
        Ok(written)
    }

    fn stat(&self, inode: u64) -> VfsResult<FileStat> {
        let node = self.find_node(inode).ok_or(VfsError::NotFound)?;

        Ok(FileStat {
            inode: node.inode,
            file_type: node.file_type,
            size: node.size,
            permissions: if node.file_type == FileType::Directory {
                0o755
            } else {
                0o644
            },
            created: 0,
            modified: 0,
            accessed: 0,
        })
    }

    fn readdir(&self, inode: u64) -> VfsResult<Vec<(String, u64, FileType)>> {
        let node = self.find_node(inode).ok_or(VfsError::NotFound)?;

        if node.file_type != FileType::Directory {
            return Err(VfsError::NotADirectory);
        }

        self.ensure_children_loaded(node.first_cluster)?;

        let inner = self.inner.lock();
        let entries: Vec<(String, u64, FileType)> = inner
            .nodes
            .iter()
            .filter(|n| n.parent_cluster == node.first_cluster && n.inode != node.inode)
            .map(|n| (n.name.clone(), n.inode, n.file_type))
            .collect();

        Ok(entries)
    }

    fn truncate(&self, inode: u64, size: u64) -> VfsResult<()> {
        let mut node = self.find_node(inode).ok_or(VfsError::NotFound)?;

        if node.file_type != FileType::RegularFile {
            return Err(VfsError::IsADirectory);
        }

        let cluster_size = self.bpb.cluster_size as usize;
        let new_size = size as usize;
        let needed_clusters = if new_size == 0 { 0 } else { (new_size + cluster_size - 1) / cluster_size };

        let mut chain = if node.first_cluster >= 2 {
            self.follow_chain(node.first_cluster)
        } else {
            Vec::new()
        };

        if new_size == 0 {
            // Free all clusters.
            if node.first_cluster >= 2 {
                self.free_chain(node.first_cluster);
            }
            node.first_cluster = 0;
            chain.clear();
        } else if chain.len() > needed_clusters {
            // Shrink: free excess clusters.
            let keep = needed_clusters;
            // Mark last kept cluster as EOC.
            if keep > 0 {
                self.fat_write(chain[keep - 1], 0x0FFFFFFF);
            }
            // Free the rest.
            for i in keep..chain.len() {
                self.fat_write(chain[i], 0);
            }
            chain.truncate(keep);
        } else {
            // Extend if needed.
            if chain.is_empty() && needed_clusters > 0 {
                let c = self.alloc_cluster()?;
                node.first_cluster = c;
                chain.push(c);
            }
            while chain.len() < needed_clusters {
                let last = *chain.last().unwrap();
                let new = self.extend_chain(last)?;
                chain.push(new);
            }
        }

        // Zero out any bytes between old EOF and new size if extending.
        if new_size > node.size as usize && !chain.is_empty() {
            let old_end = node.size as usize;
            let zero_start_cluster_idx = old_end / cluster_size;
            let zero_start_within = old_end % cluster_size;
            // Only iterate clusters up to and including the one that
            // contains `new_size`. Without the saturating_sub below, the
            // `new_size - idx * cluster_size` expression would wrap in
            // usize when idx * cluster_size > new_size, and `min` would
            // happily return `cluster_size`, zeroing an entire partial
            // tail cluster (FAT32-4).
            let last_cluster_idx = if new_size == 0 { 0 } else { (new_size - 1) / cluster_size };
            let end_cluster_idx = core::cmp::min(chain.len(), last_cluster_idx + 1);

            for idx in zero_start_cluster_idx..end_cluster_idx {
                let cluster = chain[idx];
                let cluster_offset = (self.bpb.cluster_to_sector(cluster) as usize) * SECTOR_SIZE;
                let start = if idx == zero_start_cluster_idx { zero_start_within } else { 0 };
                let end = core::cmp::min(
                    cluster_size,
                    new_size.saturating_sub(idx * cluster_size),
                );
                if start < end {
                    let zeros = vec![0u8; end - start];
                    self.cache_write(cluster_offset + start, &zeros)?;
                }
            }
        }

        node.size = size;
        self.flush_dir_entry(&node)?;

        // Update in-memory node.
        {
            let mut inner = self.inner.lock();
            if let Some(n) = inner.nodes.iter_mut().find(|n| n.inode == inode) {
                n.size = size;
                n.first_cluster = node.first_cluster;
                // Truncate may have freed or extended the cluster chain.
                // Invalidate the cache so next read rebuilds it from the
                // updated FAT (FAT32-1).
                n.cluster_chain.clear();
            }
        }

        let _ = self.do_sync();
        Ok(())
    }

    fn sync(&self) -> VfsResult<()> {
        self.do_sync()
    }
}

// ── Test Image Generator ────────────────────────────────────────────────────

/// Create a minimal FAT32 filesystem image in memory for testing.
///
/// The image contains:
/// - `/hello.txt`  — "Hello from FAT32!\n" (18 bytes)
/// - `/readme.txt` — "AstryxOS FAT32 test image.\n" (27 bytes)
/// - `/docs/`      — subdirectory
/// - `/docs/notes.txt` — "Notes file in subdirectory.\n" (28 bytes)
///
/// Image layout (512 bytes/sector, 1 sector/cluster):
/// - Sector 0:    Boot sector (BPB)
/// - Sector 1:    FSInfo sector
/// - Sectors 2-3: FAT #1 (2 sectors = 256 entries max)
/// - Sectors 4-5: FAT #2 (copy)
/// - Sector 6:    Cluster 2 = Root directory
/// - Sector 7:    Cluster 3 = hello.txt data
/// - Sector 8:    Cluster 4 = readme.txt data
/// - Sector 9:    Cluster 5 = docs/ directory
/// - Sector 10:   Cluster 6 = notes.txt data
pub fn create_test_image() -> Vec<u8> {
    // Image parameters.
    const BYTES_PER_SECTOR: u16 = 512;
    const SECTORS_PER_CLUSTER: u8 = 1;
    const RESERVED_SECTORS: u16 = 2;    // boot + fsinfo
    const NUM_FATS: u8 = 2;
    const FAT_SIZE_SECTORS: u32 = 2;    // 2 sectors per FAT = 256 entries
    const TOTAL_SECTORS: u32 = 32;      // small image

    const FAT1_START: u32 = RESERVED_SECTORS as u32;   // sector 2
    const FAT2_START: u32 = FAT1_START + FAT_SIZE_SECTORS;  // sector 4
    const DATA_START: u32 = FAT2_START + FAT_SIZE_SECTORS;  // sector 6

    const ROOT_CLUSTER: u32 = 2;

    let image_size = (TOTAL_SECTORS as usize) * (BYTES_PER_SECTOR as usize);
    let mut img = vec![0u8; image_size];

    // ── Boot Sector (sector 0) ──────────────────────────────────────────
    {
        let s = &mut img[0..512];

        // Jump instruction (EB 58 90).
        s[0] = 0xEB; s[1] = 0x58; s[2] = 0x90;

        // OEM name.
        s[3..11].copy_from_slice(b"ASTRYX  ");

        // BPB fields.
        s[11..13].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
        s[13] = SECTORS_PER_CLUSTER;
        s[14..16].copy_from_slice(&RESERVED_SECTORS.to_le_bytes());
        s[16] = NUM_FATS;
        // root_entry_count = 0 (FAT32)
        s[17] = 0; s[18] = 0;
        // total_sectors_16 = 0 (use 32-bit field)
        s[19] = 0; s[20] = 0;
        // media type
        s[21] = 0xF8;
        // fat_size_16 = 0 (use 32-bit field)
        s[22] = 0; s[23] = 0;
        // sectors per track
        s[24..26].copy_from_slice(&63u16.to_le_bytes());
        // heads
        s[26..28].copy_from_slice(&255u16.to_le_bytes());
        // hidden sectors
        s[28..32].copy_from_slice(&0u32.to_le_bytes());
        // total sectors 32
        s[32..36].copy_from_slice(&TOTAL_SECTORS.to_le_bytes());

        // FAT32-specific BPB fields (offset 36+).
        s[36..40].copy_from_slice(&FAT_SIZE_SECTORS.to_le_bytes());
        // ext_flags = 0 (active FAT mirrored)
        s[40..42].copy_from_slice(&0u16.to_le_bytes());
        // fs_version = 0.0
        s[42..44].copy_from_slice(&0u16.to_le_bytes());
        // root_cluster
        s[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
        // fsinfo sector = 1
        s[48..50].copy_from_slice(&1u16.to_le_bytes());
        // backup boot sector = 0 (none)
        s[50..52].copy_from_slice(&0u16.to_le_bytes());

        // Drive number
        s[64] = 0x80;
        // Boot signature
        s[66] = 0x29;
        // Volume serial
        s[67..71].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        // Volume label
        s[71..82].copy_from_slice(b"ASTRYXTEST ");
        // FS type
        s[82..90].copy_from_slice(b"FAT32   ");

        // Boot signature.
        s[510] = 0x55;
        s[511] = 0xAA;
    }

    // ── FSInfo Sector (sector 1) ────────────────────────────────────────
    {
        let s = &mut img[512..1024];
        // Lead signature.
        s[0..4].copy_from_slice(&0x41615252u32.to_le_bytes());
        // Struct signature.
        s[484..488].copy_from_slice(&0x61417272u32.to_le_bytes());
        // Free cluster count (unknown).
        s[488..492].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Next free cluster hint.
        s[492..496].copy_from_slice(&7u32.to_le_bytes());
        // Trail signature.
        s[508..512].copy_from_slice(&0xAA550000u32.to_le_bytes());
    }

    // ── FAT #1 (sectors 2-3) ───────────────────────────────────────────
    // FAT entries: cluster → next_cluster  (0x0FFFFFFF = end of chain)
    let fat1_offset = (FAT1_START as usize) * 512;
    {
        let fat = &mut img[fat1_offset..fat1_offset + (FAT_SIZE_SECTORS as usize) * 512];

        // Entry 0: media type (0x0FFFFFF8)
        fat[0..4].copy_from_slice(&0x0FFFFFF8u32.to_le_bytes());
        // Entry 1: end of chain marker
        fat[4..8].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
        // Entry 2: root directory — end of chain (1 cluster)
        fat[8..12].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
        // Entry 3: hello.txt — end of chain (1 cluster)
        fat[12..16].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
        // Entry 4: readme.txt — end of chain (1 cluster)
        fat[16..20].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
        // Entry 5: docs/ directory — end of chain (1 cluster)
        fat[20..24].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
        // Entry 6: notes.txt — end of chain (1 cluster)
        fat[24..28].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
    }

    // ── FAT #2 (sectors 4-5) — copy of FAT #1 ─────────────────────────
    let fat2_offset = (FAT2_START as usize) * 512;
    let fat_byte_size = (FAT_SIZE_SECTORS as usize) * 512;
    img.copy_within(fat1_offset..fat1_offset + fat_byte_size, fat2_offset);

    // ── Root Directory (cluster 2 = sector 6) ──────────────────────────
    let root_offset = (DATA_START as usize) * 512;
    {
        let dir = &mut img[root_offset..root_offset + 512];

        // Entry 0: HELLO.TXT  (cluster 3, 18 bytes)
        write_dir_entry(&mut dir[0..32], b"HELLO   ", b"TXT", 0x20, 3, 18);

        // Entry 1: README.TXT  (cluster 4, 27 bytes)
        write_dir_entry(&mut dir[32..64], b"README  ", b"TXT", 0x20, 4, 27);

        // Entry 2: DOCS  (cluster 5, directory)
        write_dir_entry(&mut dir[64..96], b"DOCS    ", b"   ", attr::DIRECTORY, 5, 0);
    }

    // ── hello.txt data (cluster 3 = sector 7) ─────────────────────────
    {
        let data = b"Hello from FAT32!\n";
        let offset = ((DATA_START + 1) as usize) * 512;
        img[offset..offset + data.len()].copy_from_slice(data);
    }

    // ── readme.txt data (cluster 4 = sector 8) ────────────────────────
    {
        let data = b"AstryxOS FAT32 test image.\n";
        let offset = ((DATA_START + 2) as usize) * 512;
        img[offset..offset + data.len()].copy_from_slice(data);
    }

    // ── docs/ directory (cluster 5 = sector 9) ────────────────────────
    {
        let offset = ((DATA_START + 3) as usize) * 512;
        let dir = &mut img[offset..offset + 512];

        // .  entry (self)
        write_dir_entry(&mut dir[0..32], b".       ", b"   ", attr::DIRECTORY, 5, 0);

        // .. entry (parent = root)
        write_dir_entry(&mut dir[32..64], b"..      ", b"   ", attr::DIRECTORY, ROOT_CLUSTER, 0);

        // notes.txt  (cluster 6, 28 bytes)
        write_dir_entry(&mut dir[64..96], b"NOTES   ", b"TXT", 0x20, 6, 28);
    }

    // ── notes.txt data (cluster 6 = sector 10) ────────────────────────
    {
        let data = b"Notes file in subdirectory.\n";
        let offset = ((DATA_START + 4) as usize) * 512;
        img[offset..offset + data.len()].copy_from_slice(data);
    }

    img
}

/// Create a larger FAT32 test image suitable for read-write tests.
///
/// 256 sectors × 512 bytes = 128 KiB image.  Layout:
/// - Sector 0:      Boot sector (BPB)
/// - Sector 1:      FSInfo sector
/// - Sectors 2-3:   FAT #1 (2 sectors = 256 entries)
/// - Sectors 4-5:   FAT #2 (copy)
/// - Sector 6+:     Data clusters (cluster 2 = root directory, rest free)
///
/// Provides ~250 free clusters (×512 bytes = ~125 KiB free) for write tests.
pub fn create_rw_test_image() -> Vec<u8> {
    const BYTES_PER_SECTOR: u16 = 512;
    const SECTORS_PER_CLUSTER: u8 = 1;
    const RESERVED_SECTORS: u16 = 2;
    const NUM_FATS: u8 = 2;
    const FAT_SIZE_SECTORS: u32 = 2;
    const TOTAL_SECTORS: u32 = 256;

    const FAT1_START: u32 = RESERVED_SECTORS as u32;
    const FAT2_START: u32 = FAT1_START + FAT_SIZE_SECTORS;
    const DATA_START: u32 = FAT2_START + FAT_SIZE_SECTORS;
    const ROOT_CLUSTER: u32 = 2;

    let image_size = (TOTAL_SECTORS as usize) * (BYTES_PER_SECTOR as usize);
    let mut img = vec![0u8; image_size];

    // Boot sector.
    {
        let s = &mut img[0..512];
        s[0] = 0xEB; s[1] = 0x58; s[2] = 0x90;
        s[3..11].copy_from_slice(b"ASTRYX  ");
        s[11..13].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
        s[13] = SECTORS_PER_CLUSTER;
        s[14..16].copy_from_slice(&RESERVED_SECTORS.to_le_bytes());
        s[16] = NUM_FATS;
        // root_entry_count = 0 (FAT32)
        s[17] = 0; s[18] = 0;
        // total_sectors_16 = 0
        s[19] = 0; s[20] = 0;
        s[21] = 0xF8; // media type
        s[22] = 0; s[23] = 0; // fat_size_16 = 0
        s[24..26].copy_from_slice(&63u16.to_le_bytes());
        s[26..28].copy_from_slice(&255u16.to_le_bytes());
        s[28..32].copy_from_slice(&0u32.to_le_bytes());
        s[32..36].copy_from_slice(&TOTAL_SECTORS.to_le_bytes());
        s[36..40].copy_from_slice(&FAT_SIZE_SECTORS.to_le_bytes());
        s[40..42].copy_from_slice(&0u16.to_le_bytes());
        s[42..44].copy_from_slice(&0u16.to_le_bytes());
        s[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
        s[48..50].copy_from_slice(&1u16.to_le_bytes());
        s[50..52].copy_from_slice(&0u16.to_le_bytes());
        s[64] = 0x80;
        s[66] = 0x29;
        s[67..71].copy_from_slice(&0xCAFEBABEu32.to_le_bytes());
        s[71..82].copy_from_slice(b"ASTRYXRWIMG");
        s[82..90].copy_from_slice(b"FAT32   ");
        s[510] = 0x55;
        s[511] = 0xAA;
    }

    // FSInfo sector.
    {
        let s = &mut img[512..1024];
        s[0..4].copy_from_slice(&0x41615252u32.to_le_bytes());
        s[484..488].copy_from_slice(&0x61417272u32.to_le_bytes());
        s[488..492].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        s[492..496].copy_from_slice(&3u32.to_le_bytes());
        s[508..512].copy_from_slice(&0xAA550000u32.to_le_bytes());
    }

    // FAT #1: entries 0-1 reserved; entry 2 (root) = EOC; rest = 0 (free).
    let fat1_offset = (FAT1_START as usize) * 512;
    {
        let fat = &mut img[fat1_offset..fat1_offset + (FAT_SIZE_SECTORS as usize) * 512];
        fat[0..4].copy_from_slice(&0x0FFFFFF8u32.to_le_bytes());
        fat[4..8].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
        fat[8..12].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // root dir EOC
        // All other entries remain 0 (free).
    }

    // FAT #2 = copy of FAT #1.
    let fat2_offset = (FAT2_START as usize) * 512;
    let fat_byte_size = (FAT_SIZE_SECTORS as usize) * 512;
    img.copy_within(fat1_offset..fat1_offset + fat_byte_size, fat2_offset);

    // Root directory cluster (cluster 2 = sector DATA_START) — empty.
    // All 512 bytes are already zero, which is correct (no entries).
    let _ = DATA_START;

    img
}

/// Write a single 32-byte directory entry.
fn write_dir_entry(
    buf: &mut [u8],
    name: &[u8; 8],
    ext: &[u8; 3],
    attr: u8,
    first_cluster: u32,
    file_size: u32,
) {
    buf[0..8].copy_from_slice(name);
    buf[8..11].copy_from_slice(ext);
    buf[11] = attr;
    // Reserved + create time/date + access date + write time/date = zeros.

    // First cluster high (bytes 20-21).
    let cluster_hi = ((first_cluster >> 16) & 0xFFFF) as u16;
    buf[20..22].copy_from_slice(&cluster_hi.to_le_bytes());

    // First cluster low (bytes 26-27).
    let cluster_lo = (first_cluster & 0xFFFF) as u16;
    buf[26..28].copy_from_slice(&cluster_lo.to_le_bytes());

    // File size.
    buf[28..32].copy_from_slice(&file_size.to_le_bytes());
}
