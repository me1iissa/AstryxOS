//! ext2 Filesystem Driver (read-only)
//!
//! Provides read-only access to ext2-formatted disk partitions.
//! Supports reading the superblock, block group descriptors, inodes,
//! directory entries, file data, and symbolic-link targets (both
//! "fast" inline and "slow" block-backed forms).
//!
//! # Block-device binding
//!
//! `Ext2Fs` can be constructed against either a [`BlockDevice`] trait
//! object (the production path used by [`init_disks`]) or against a
//! caller-supplied `fn(sector, count, &mut [u8]) -> Result<(), _>`
//! reader (the test path used by `test_runner`).  Both shapes funnel
//! through the same in-driver `read_sectors_inner` helper, so on-disk
//! parsing logic only needs to be written once.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::drivers::block::BlockDevice;

/// ext2 magic number.
const EXT2_MAGIC: u16 = 0xEF53;

/// ext2 superblock (subset of fields we need).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub r_blocks_count: u32,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub log_frag_size: u32,
    pub blocks_per_group: u32,
    pub frags_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub mnt_count: u16,
    pub max_mnt_count: u16,
    pub magic: u16,
    pub state: u16,
    pub errors: u16,
    pub minor_rev_level: u16,
    pub lastcheck: u32,
    pub checkinterval: u32,
    pub creator_os: u32,
    pub rev_level: u32,
    pub def_resuid: u16,
    pub def_resgid: u16,
    // Rev 1 fields
    pub first_ino: u32,
    pub inode_size: u16,
}

/// ext2 block group descriptor.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockGroupDesc {
    pub block_bitmap: u32,
    pub inode_bitmap: u32,
    pub inode_table: u32,
    pub free_blocks_count: u16,
    pub free_inodes_count: u16,
    pub used_dirs_count: u16,
    pub pad: u16,
    pub reserved: [u32; 3],
}

/// ext2 inode (128 or 256 bytes, we only need first 128).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext2Inode {
    pub mode: u16,
    pub uid: u16,
    pub size: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks: u32,
    pub flags: u32,
    pub osd1: u32,
    pub block: [u32; 15],
    pub generation: u32,
    pub file_acl: u32,
    pub dir_acl: u32,
    pub faddr: u32,
    pub osd2: [u8; 12],
}

/// Inode type constants from mode field.
const S_IFMT: u16 = 0xF000;
#[allow(dead_code)]
const S_IFREG: u16 = 0x8000;
const S_IFDIR: u16 = 0x4000;
const S_IFLNK: u16 = 0xA000;

/// Fast-symlink size threshold per ext2 spec §6 "Symbolic links":
/// `i_size` ≤ 60 AND `i_blocks` == 0 ⇒ target stored inline in the
/// 15-entry `i_block[]` array (60 bytes total).  Slow symlinks use
/// the regular file-data path.
const EXT2_FAST_SYMLINK_MAX: u64 = 60;

/// Underlying reader for sector I/O.  Production callers pass a
/// `Box<dyn BlockDevice>`; tests pass a plain function pointer to
/// avoid having to mock the BlockDevice trait surface.  Both shapes
/// are reachable through [`Ext2Fs::read_sectors_inner`].
enum BlockReader {
    /// Production path — a real or partition-wrapped block device.
    Device(Box<dyn BlockDevice>),
    /// Test path — a fn pointer used by `test_runner`.
    Fn(fn(u64, u16, &mut [u8]) -> Result<(), &'static str>),
}

/// ext2 filesystem instance.
pub struct Ext2Fs {
    /// Underlying reader (block-device trait object or test fn pointer).
    reader: BlockReader,
    /// Cached superblock.
    superblock: Superblock,
    /// Block size in bytes.
    block_size: usize,
    /// Inode size in bytes.
    inode_size: usize,
}

impl Ext2Fs {
    /// Try to mount an ext2 filesystem from the given block device.
    ///
    /// Validates the superblock against the constraints in the
    /// second-extended-filesystem specification
    /// (<https://www.nongnu.org/ext2-doc/ext2.html#superblock>) before
    /// returning the mounted instance.  A malformed superblock — block size
    /// out of range, `inodes_per_group == 0`, `inode_size` not a power of
    /// two, etc. — must be rejected up front: every other method on
    /// `Ext2Fs` trusts these fields and would otherwise panic in debug or
    /// produce arbitrary memory reads in release.
    pub fn new(device: Box<dyn BlockDevice>) -> Option<Self> {
        Self::new_with_reader(BlockReader::Device(device))
    }

    /// Test-only constructor accepting a function-pointer reader.
    ///
    /// Lets `test_runner` exercise the validation rules without having to
    /// implement the [`BlockDevice`] trait.  Production callers must use
    /// [`Ext2Fs::new`].
    #[doc(hidden)]
    pub fn new_with_fn(
        read_fn: fn(u64, u16, &mut [u8]) -> Result<(), &'static str>,
    ) -> Option<Self> {
        Self::new_with_reader(BlockReader::Fn(read_fn))
    }

    fn new_with_reader(reader: BlockReader) -> Option<Self> {
        // Read superblock (at byte offset 1024, sector 2)
        let mut sb_buf = [0u8; 512];
        if Self::read_sectors_via(&reader, 2, 1, &mut sb_buf).is_err() {
            crate::serial_println!("[EXT2] Failed to read superblock");
            return None;
        }

        let sb: Superblock = unsafe { core::ptr::read_unaligned(sb_buf.as_ptr() as *const Superblock) };

        if sb.magic != EXT2_MAGIC {
            // Magic mismatch is the common case for "this partition is not ext2".
            // Demote to a single debug-level line to keep the boot log readable
            // when the probe also tries FAT32 and NTFS on the same partition.
            return None;
        }

        // ── Superblock validation (ext2 spec §2 "Superblock") ──────────────
        // log_block_size of N means block_size = 1024 << N.  The ext2
        // specification caps block size at 4096; mkfs.ext2 in practice
        // accepts up to 65536 (log = 6).  Reject anything larger so the
        // left-shift below cannot overflow a usize / produce a runaway
        // block size that crashes the read path.
        if sb.log_block_size > 6 {
            crate::serial_println!(
                "[EXT2] Invalid log_block_size={} (max 6 → 64 KiB)",
                sb.log_block_size,
            );
            return None;
        }
        // The ext2 spec also requires log_frag_size == log_block_size on
        // modern filesystems (fragments unused, fragment size == block
        // size).  A divergence indicates either pre-spec ext2fs or a
        // mangled superblock; reject either way.
        if sb.log_frag_size != sb.log_block_size {
            crate::serial_println!(
                "[EXT2] log_frag_size={} != log_block_size={}",
                sb.log_frag_size, sb.log_block_size,
            );
            return None;
        }
        let block_size = 1024usize << sb.log_block_size;

        // inodes_per_group / blocks_per_group are used as divisors by
        // `read_inode`; zero would panic in debug and wrap in release.
        if sb.inodes_per_group == 0 {
            crate::serial_println!("[EXT2] inodes_per_group must be non-zero");
            return None;
        }
        if sb.blocks_per_group == 0 {
            crate::serial_println!("[EXT2] blocks_per_group must be non-zero");
            return None;
        }

        // Determine inode size per the revision-level rules in the spec.
        // Rev 0 has a fixed 128-byte inode; rev 1+ stores the size in the
        // superblock and requires it to be a power of two, at least 128,
        // and no larger than the block size.
        let inode_size = if sb.rev_level >= 1 {
            let isz = sb.inode_size as usize;
            if isz < 128 || !isz.is_power_of_two() || isz > block_size {
                crate::serial_println!(
                    "[EXT2] Invalid inode_size={} (must be power of two in [128, {}])",
                    isz, block_size,
                );
                return None;
            }
            isz
        } else {
            128
        };

        // blocks_per_group bounded by `block_size * 8` bits in the block
        // bitmap (one bit per data block).  This is the canonical sanity
        // check in the ext2 mount path.
        if sb.blocks_per_group > (block_size as u32) * 8 {
            crate::serial_println!(
                "[EXT2] blocks_per_group={} exceeds bitmap capacity ({} bits)",
                sb.blocks_per_group, block_size * 8,
            );
            return None;
        }

        crate::serial_println!("[EXT2] Superblock valid: {} inodes, {} blocks, block_size={}",
            sb.inodes_count, sb.blocks_count, block_size);

        Some(Ext2Fs {
            reader,
            superblock: sb,
            block_size,
            inode_size,
        })
    }

    /// Test-only constructor that bypasses the disk read and uses an
    /// in-memory `Superblock` for direct validation testing.  The
    /// `read_fn` is unused; callers pass a no-op stub.
    ///
    /// Mirrors the validation in [`Ext2Fs::new`].  Returns `None` on the
    /// same set of spec violations.
    #[doc(hidden)]
    pub fn try_from_superblock_for_test(
        sb: Superblock,
        read_fn: fn(u64, u16, &mut [u8]) -> Result<(), &'static str>,
    ) -> Option<Self> {
        if sb.magic != EXT2_MAGIC { return None; }
        if sb.log_block_size > 6 { return None; }
        if sb.log_frag_size != sb.log_block_size { return None; }
        let block_size = 1024usize << sb.log_block_size;
        if sb.inodes_per_group == 0 || sb.blocks_per_group == 0 { return None; }
        let inode_size = if sb.rev_level >= 1 {
            let isz = sb.inode_size as usize;
            if isz < 128 || !isz.is_power_of_two() || isz > block_size { return None; }
            isz
        } else { 128 };
        if sb.blocks_per_group > (block_size as u32) * 8 { return None; }
        Some(Ext2Fs {
            reader: BlockReader::Fn(read_fn),
            superblock: sb,
            block_size,
            inode_size,
        })
    }

    /// Dispatch a sector-level read through whichever reader the FS holds.
    fn read_sectors_inner(&self, sector: u64, count: u16, buf: &mut [u8])
        -> Result<(), &'static str>
    {
        Self::read_sectors_via(&self.reader, sector, count, buf)
    }

    fn read_sectors_via(reader: &BlockReader, sector: u64, count: u16, buf: &mut [u8])
        -> Result<(), &'static str>
    {
        match reader {
            BlockReader::Device(dev) => {
                dev.read_sectors(sector, count as u32, buf)
                    .map_err(|_| "ext2: block device read error")
            }
            BlockReader::Fn(f) => f(sector, count, buf),
        }
    }

    /// Read a block from the filesystem.
    fn read_block(&self, block_num: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        let sectors_per_block = (self.block_size / 512) as u16;
        let start_sector = block_num as u64 * sectors_per_block as u64;
        self.read_sectors_inner(start_sector, sectors_per_block, buf)
    }

    /// Read an inode by number (1-based).
    fn read_inode(&self, inode_num: u64) -> Option<Ext2Inode> {
        if inode_num == 0 { return None; }
        let inode_idx = (inode_num - 1) as u32;
        let group = inode_idx / self.superblock.inodes_per_group;
        let idx_in_group = inode_idx % self.superblock.inodes_per_group;

        // Read block group descriptor
        let bgd_block = if self.block_size == 1024 { 2 } else { 1 };
        let bgd_offset = group as usize * 32; // sizeof(BlockGroupDesc) = 32
        let bgd_sector = bgd_block as u64 * (self.block_size as u64 / 512) + (bgd_offset as u64 / 512);

        let mut sector_buf = [0u8; 512];
        if self.read_sectors_inner(bgd_sector, 1, &mut sector_buf).is_err() {
            return None;
        }

        let bgd_off_in_sector = bgd_offset % 512;
        let bgd: BlockGroupDesc = unsafe {
            core::ptr::read_unaligned(sector_buf[bgd_off_in_sector..].as_ptr() as *const BlockGroupDesc)
        };

        // Calculate inode location
        let inode_table_byte = bgd.inode_table as u64 * self.block_size as u64;
        let inode_byte = inode_table_byte + idx_in_group as u64 * self.inode_size as u64;
        let inode_sector = inode_byte / 512;
        let inode_off = (inode_byte % 512) as usize;

        let mut buf = [0u8; 512];
        if self.read_sectors_inner(inode_sector, 1, &mut buf).is_err() {
            return None;
        }

        if inode_off + 128 <= 512 {
            Some(unsafe { core::ptr::read_unaligned(buf[inode_off..].as_ptr() as *const Ext2Inode) })
        } else {
            // Inode spans sector boundary — read two sectors
            let mut buf2 = [0u8; 1024];
            if self.read_sectors_inner(inode_sector, 2, &mut buf2).is_err() {
                return None;
            }
            Some(unsafe { core::ptr::read_unaligned(buf2[inode_off..].as_ptr() as *const Ext2Inode) })
        }
    }

    /// Read file data from an inode.
    fn read_inode_data(&self, inode: &Ext2Inode, offset: u64, buf: &mut [u8]) -> usize {
        let file_size = inode.size as u64;
        if offset >= file_size { return 0; }

        let to_read = buf.len().min((file_size - offset) as usize);
        let mut read_total = 0;
        let mut block_buf = alloc::vec![0u8; self.block_size];

        while read_total < to_read {
            let pos = offset + read_total as u64;
            let block_idx = (pos / self.block_size as u64) as usize;
            let off_in_block = (pos % self.block_size as u64) as usize;

            let block_num = self.resolve_block(inode, block_idx);
            if block_num == 0 {
                // Sparse block — fill with zeros
                let n = (self.block_size - off_in_block).min(to_read - read_total);
                buf[read_total..read_total + n].fill(0);
                read_total += n;
                continue;
            }

            if self.read_block(block_num, &mut block_buf).is_err() {
                break;
            }

            let n = (self.block_size - off_in_block).min(to_read - read_total);
            buf[read_total..read_total + n].copy_from_slice(&block_buf[off_in_block..off_in_block + n]);
            read_total += n;
        }

        read_total
    }

    /// Resolve a logical block index to a physical block number.
    /// Handles direct, indirect, double-indirect, and triple-indirect blocks.
    fn resolve_block(&self, inode: &Ext2Inode, block_idx: usize) -> u32 {
        let ptrs_per_block = self.block_size / 4;

        if block_idx < 12 {
            // Direct blocks
            return inode.block[block_idx];
        }

        let block_idx = block_idx - 12;
        if block_idx < ptrs_per_block {
            // Single indirect
            return self.read_indirect(inode.block[12], block_idx);
        }

        let block_idx = block_idx - ptrs_per_block;
        if block_idx < ptrs_per_block * ptrs_per_block {
            // Double indirect
            let i = block_idx / ptrs_per_block;
            let j = block_idx % ptrs_per_block;
            let indirect = self.read_indirect(inode.block[13], i);
            if indirect == 0 { return 0; }
            return self.read_indirect(indirect, j);
        }

        let block_idx = block_idx - ptrs_per_block * ptrs_per_block;
        // Triple indirect
        let i = block_idx / (ptrs_per_block * ptrs_per_block);
        let rem = block_idx % (ptrs_per_block * ptrs_per_block);
        let j = rem / ptrs_per_block;
        let k = rem % ptrs_per_block;
        let ind1 = self.read_indirect(inode.block[14], i);
        if ind1 == 0 { return 0; }
        let ind2 = self.read_indirect(ind1, j);
        if ind2 == 0 { return 0; }
        self.read_indirect(ind2, k)
    }

    /// Read one pointer from an indirect block.
    fn read_indirect(&self, block_num: u32, index: usize) -> u32 {
        if block_num == 0 { return 0; }
        let mut buf = alloc::vec![0u8; self.block_size];
        if self.read_block(block_num, &mut buf).is_err() { return 0; }
        let ptrs = unsafe {
            core::slice::from_raw_parts(buf.as_ptr() as *const u32, self.block_size / 4)
        };
        if index < ptrs.len() { u32::from_le(ptrs[index]) } else { 0 }
    }

    /// Read directory entries from an inode.
    ///
    /// Parses on-disk `ext2_dir_entry_2` records and enforces the integrity
    /// constraints from the second-extended-filesystem specification.  See
    /// <https://www.nongnu.org/ext2-doc/ext2.html#linked-directories>:
    ///
    /// * `rec_len` is at least `EXT2_DIR_REC_LEN(1) = 12` (the directory
    ///   entry header (8 bytes) + at least one name byte, rounded up to a
    ///   4-byte boundary).
    /// * `rec_len` is a multiple of 4 (4-byte alignment).
    /// * `rec_len` is large enough to hold the declared `name_len`
    ///   (`rec_len >= 8 + name_len`).
    /// * The entry does not span past the directory's logical size.
    /// * `inode` field does not exceed the filesystem's inode count.
    ///
    /// On a corruption violation we stop parsing the current directory but
    /// return whatever was parsed before — matching the conservative
    /// behaviour mandated by POSIX `readdir(3)` (no entries lost from
    /// before the bad slot).  The total iterations are also bounded by
    /// `size / 8 + 1` so a self-referencing `rec_len` cannot livelock the
    /// read loop.
    fn read_dir_entries(&self, inode: &Ext2Inode) -> Vec<(u32, String, u8)> {
        const EXT2_DIR_HDR: usize = 8;
        const EXT2_DIR_MIN_REC_LEN: usize = 12;
        let mut entries = Vec::new();
        let size = inode.size as usize;
        if size < EXT2_DIR_HDR {
            return entries;
        }
        let mut data = alloc::vec![0u8; size];
        self.read_inode_data(inode, 0, &mut data);

        let max_inumber = self.superblock.inodes_count;
        // Defensive iteration bound: each iteration must consume at least
        // `EXT2_DIR_HDR = 8` bytes — if `rec_len` ever underflows we still
        // stop after at most `size / 8 + 1` iterations.
        let max_iter = size / EXT2_DIR_HDR + 1;
        let mut iter = 0usize;
        let mut offset = 0usize;
        while offset + EXT2_DIR_HDR <= size {
            iter += 1;
            if iter > max_iter {
                crate::serial_println!(
                    "[EXT2] dir parse: iteration cap reached at offset={} size={}",
                    offset, size,
                );
                break;
            }
            let entry_inode = u32::from_le_bytes(
                [data[offset], data[offset+1], data[offset+2], data[offset+3]]);
            let rec_len = u16::from_le_bytes([data[offset+4], data[offset+5]]) as usize;
            let name_len = data[offset+6] as usize;
            let file_type = data[offset+7];

            // ── Corruption guards (ext2 spec §3 "Linked directory entries") ──
            // rec_len of zero or less than the spec minimum signals corruption.
            if rec_len < EXT2_DIR_MIN_REC_LEN {
                crate::serial_println!(
                    "[EXT2] dir parse: short rec_len={} at offset={}",
                    rec_len, offset,
                );
                break;
            }
            // rec_len must be a multiple of 4 (directory entries are aligned).
            if rec_len & 3 != 0 {
                crate::serial_println!(
                    "[EXT2] dir parse: misaligned rec_len={} at offset={}",
                    rec_len, offset,
                );
                break;
            }
            // rec_len must hold the declared name.
            if rec_len < EXT2_DIR_HDR + name_len {
                crate::serial_println!(
                    "[EXT2] dir parse: rec_len={} too small for name_len={} at offset={}",
                    rec_len, name_len, offset,
                );
                break;
            }
            // Entry must not extend past the directory's logical size.
            if offset.checked_add(rec_len).map_or(true, |end| end > size) {
                crate::serial_println!(
                    "[EXT2] dir parse: entry overruns dir size offset={} rec_len={} size={}",
                    offset, rec_len, size,
                );
                break;
            }
            // Inode field must fit in the filesystem's inode count (0 means
            // "unused entry" — that's legal, only "out-of-bounds positive"
            // is a corruption signal).
            if entry_inode != 0 && entry_inode > max_inumber {
                crate::serial_println!(
                    "[EXT2] dir parse: inode={} > max_inumber={} at offset={}",
                    entry_inode, max_inumber, offset,
                );
                break;
            }

            if entry_inode != 0 && name_len > 0 {
                let name = core::str::from_utf8(&data[offset+EXT2_DIR_HDR..offset+EXT2_DIR_HDR+name_len])
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    entries.push((entry_inode, name, file_type));
                }
            }

            offset += rec_len;
        }

        entries
    }

    /// Decode the target of a symbolic-link inode.
    ///
    /// The ext2 specification (Stephen Tweedie, *Design and Implementation
    /// of the Second Extended Filesystem*, Annual Linux Expo 1998 — see
    /// <https://www.nongnu.org/ext2-doc/ext2.html#symbolic-links>) defines
    /// two on-disk encodings for a symlink target:
    ///
    /// * **Fast symlink** — `i_size ≤ 60` AND `i_blocks == 0`.  The target
    ///   string is stored inline in the 15-entry `i_block[]` array (60
    ///   bytes total).  No block I/O is required.
    /// * **Slow symlink** — target stored in regular file data blocks.
    ///   Read via the same path as a regular file's contents.
    ///
    /// Returns the decoded target as a `String`, with any trailing NUL
    /// bytes stripped (mkfs.ext2 and Linux do not require a terminator,
    /// but some implementations zero-pad to a 4-byte boundary).
    ///
    /// Returns `None` if the inode is not a symlink, if the inline bytes
    /// are not valid UTF-8, or if a slow-symlink read fails.
    fn read_symlink_target(&self, inode: &Ext2Inode) -> Option<String> {
        if (inode.mode & S_IFMT) != S_IFLNK {
            return None;
        }
        let size = inode.size as u64;
        if size == 0 {
            return Some(String::new());
        }
        // Fast-symlink discriminator (ext2 spec §6 "Symbolic links"):
        // i_blocks reports allocated 512-byte sectors; a value of zero
        // signals that no data block was allocated, in which case the
        // target lives inside i_block[].  The 60-byte cap is a hard
        // ceiling — i_block[] is exactly 15 × 4 = 60 bytes.
        if inode.blocks == 0 && size <= EXT2_FAST_SYMLINK_MAX {
            // Reinterpret i_block[] as a 60-byte little-endian-agnostic
            // byte array — the values stored here are raw bytes, not
            // u32 pointers, when the inode is a fast symlink.
            let mut buf = [0u8; 60];
            for (i, word) in inode.block.iter().enumerate() {
                let bytes = word.to_le_bytes();
                buf[i * 4..i * 4 + 4].copy_from_slice(&bytes);
            }
            let len = (size as usize).min(60);
            // Strip any trailing NULs from the declared length.
            let mut effective = len;
            while effective > 0 && buf[effective - 1] == 0 {
                effective -= 1;
            }
            return core::str::from_utf8(&buf[..effective])
                .ok()
                .map(|s| s.to_string());
        }
        // Slow symlink — read the target out of file-data blocks.
        let mut data = alloc::vec![0u8; size as usize];
        let got = self.read_inode_data(inode, 0, &mut data);
        if got == 0 {
            return None;
        }
        // Trim trailing NULs and decode.
        let mut effective = got;
        while effective > 0 && data[effective - 1] == 0 {
            effective -= 1;
        }
        core::str::from_utf8(&data[..effective])
            .ok()
            .map(|s| s.to_string())
    }

    /// Test-only wrapper exposing the symlink-target decoder against a
    /// caller-supplied `Ext2Inode`.  Lets `test_runner` validate the fast
    /// / slow discrimination logic without instantiating a full mock
    /// block device.
    #[doc(hidden)]
    pub fn decode_symlink_for_test(&self, inode: &Ext2Inode) -> Option<String> {
        self.read_symlink_target(inode)
    }

    /// Test-only helper exercising the directory-entry validator against a
    /// caller-supplied buffer.  Used by the corruption-resilience tests in
    /// `test_runner.rs`.  Returns the parsed `(inode, name, file_type)`
    /// tuples just like `read_dir_entries`.
    #[doc(hidden)]
    pub fn parse_dir_buf_for_test(&self, data: &[u8]) -> Vec<(u32, String, u8)> {
        const EXT2_DIR_HDR: usize = 8;
        const EXT2_DIR_MIN_REC_LEN: usize = 12;
        let size = data.len();
        let mut entries = Vec::new();
        if size < EXT2_DIR_HDR {
            return entries;
        }
        let max_inumber = self.superblock.inodes_count;
        let max_iter = size / EXT2_DIR_HDR + 1;
        let mut iter = 0usize;
        let mut offset = 0usize;
        while offset + EXT2_DIR_HDR <= size {
            iter += 1;
            if iter > max_iter { break; }
            let entry_inode = u32::from_le_bytes(
                [data[offset], data[offset+1], data[offset+2], data[offset+3]]);
            let rec_len = u16::from_le_bytes([data[offset+4], data[offset+5]]) as usize;
            let name_len = data[offset+6] as usize;
            let file_type = data[offset+7];
            if rec_len < EXT2_DIR_MIN_REC_LEN { break; }
            if rec_len & 3 != 0 { break; }
            if rec_len < EXT2_DIR_HDR + name_len { break; }
            if offset.checked_add(rec_len).map_or(true, |end| end > size) { break; }
            if entry_inode != 0 && entry_inode > max_inumber { break; }
            if entry_inode != 0 && name_len > 0 {
                let name = core::str::from_utf8(&data[offset+EXT2_DIR_HDR..offset+EXT2_DIR_HDR+name_len])
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    entries.push((entry_inode, name, file_type));
                }
            }
            offset += rec_len;
        }
        entries
    }
}

// Implement FileSystemOps trait
use crate::vfs::{FileSystemOps, FileStat, FileType, VfsResult, VfsError};

// Need Send + Sync. read_fn is a function pointer (Send+Sync), rest is plain data.
unsafe impl Send for Ext2Fs {}
unsafe impl Sync for Ext2Fs {}

impl FileSystemOps for Ext2Fs {
    fn name(&self) -> &str {
        "ext2"
    }

    fn stat(&self, inode: u64) -> VfsResult<FileStat> {
        let ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        let file_type = match ino.mode & S_IFMT {
            S_IFDIR => FileType::Directory,
            S_IFLNK => FileType::SymLink,
            _ => FileType::RegularFile,
        };
        Ok(FileStat {
            inode,
            file_type,
            size: ino.size as u64,
            permissions: (ino.mode & 0o7777) as u32,
            created: ino.ctime as u64,
            modified: ino.mtime as u64,
            accessed: ino.atime as u64,
        })
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        Ok(self.read_inode_data(&ino, offset, buf))
    }

    fn write(&self, _inode: u64, _offset: u64, _data: &[u8]) -> VfsResult<usize> {
        Err(VfsError::PermissionDenied) // Read-only
    }

    fn lookup(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        let ino = self.read_inode(parent_inode).ok_or(VfsError::NotFound)?;
        let entries = self.read_dir_entries(&ino);
        for (entry_ino, entry_name, _) in entries {
            if entry_name == name {
                return Ok(entry_ino as u64);
            }
        }
        Err(VfsError::NotFound)
    }

    fn readdir(&self, inode: u64) -> VfsResult<Vec<(String, u64, FileType)>> {
        let ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        let entries = self.read_dir_entries(&ino);
        let mut result = Vec::new();
        for (entry_ino, name, ft) in entries {
            if name == "." || name == ".." { continue; }
            let file_type = match ft {
                2 => FileType::Directory,
                7 => FileType::SymLink,
                _ => FileType::RegularFile,
            };
            result.push((name, entry_ino as u64, file_type));
        }
        Ok(result)
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

    fn truncate(&self, _inode: u64, _size: u64) -> VfsResult<()> {
        Err(VfsError::PermissionDenied) // Read-only
    }

    fn readlink(&self, inode: u64) -> VfsResult<String> {
        let ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        if (ino.mode & S_IFMT) != S_IFLNK {
            return Err(VfsError::InvalidArg); // POSIX readlink(2): EINVAL on non-symlink
        }
        self.read_symlink_target(&ino).ok_or(VfsError::Io)
    }
}

/// Try to construct an `Ext2Fs` over the given block device.
///
/// Returns `Some(fs)` if the device's superblock parses cleanly, `None`
/// otherwise (wrong filesystem, corrupt superblock, I/O error).  This is
/// the production entry point used by [`crate::vfs::init_disks`] when a
/// partition probe wants to try ext2 alongside (or in fallback from)
/// FAT32 / NTFS.
pub fn try_mount_ext2(device: Box<dyn BlockDevice>) -> Option<Ext2Fs> {
    Ext2Fs::new(device)
}

/// ext2 root inode number per the spec (always 2; inode 1 reserves the
/// "bad blocks" list, inode 0 is invalid).
pub const EXT2_ROOT_INODE: u64 = 2;
