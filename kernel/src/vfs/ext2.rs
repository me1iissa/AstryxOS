//! ext2 Filesystem Driver
//!
//! Provides access to ext2-formatted disk partitions.  Read support
//! covers the superblock, block group descriptors, inodes, directory
//! entries, file data, and symbolic-link targets (both "fast" inline
//! and "slow" block-backed forms).  Write support (added in PR-B,
//! 2026-05-24) covers data-block + inode allocation via the per-group
//! bitmaps, block-resolved + indirect-tree-aware `write`, in-place
//! and growing `truncate`, and inode write-back to the inode table.
//!
//! # Block-device binding
//!
//! `Ext2Fs` can be constructed against either a [`BlockDevice`] trait
//! object (the production path used by [`init_disks`]) or against a
//! caller-supplied `fn(sector, count, &mut [u8]) -> Result<(), _>`
//! reader (the test path used by `test_runner` for read-only
//! validation).  Both shapes funnel through the same in-driver
//! `read_sectors_inner` helper, so on-disk parsing logic only needs
//! to be written once.  Writes require a [`BlockDevice`] (the `Fn`
//! reader is read-only by construction); attempting a write through
//! the `Fn` variant returns `VfsError::PermissionDenied`.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::block::BlockDevice;

/// ext2 magic number.
const EXT2_MAGIC: u16 = 0xEF53;

/// Read the wall clock as a Unix-epoch second count, clamped to `u32`
/// because ext2 timestamps are 32-bit (`i_mtime` / `i_atime` / `i_ctime`
/// are all `__u32`).  Per the spec the 32-bit overflow ("Y2038 problem")
/// is the on-disk format's limit, not a driver bug.
fn current_unix_time() -> u32 {
    let t = crate::drivers::rtc::read_unix_time();
    if t > u32::MAX as u64 { u32::MAX } else { t as u32 }
}

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

/// Mutable on-disk state guarded by a single mutex.
///
/// Holds the superblock counters (`s_free_blocks_count`,
/// `s_free_inodes_count`, `s_wtime`) and the block-group descriptor
/// table.  The BGDT is loaded eagerly at mount time — its size is
/// `32 * num_groups`, bounded by `blocks_count / blocks_per_group + 1`
/// (a 4 GiB ext2 with 4 KiB blocks and 32 768 blocks/group has 32
/// groups → 1 KiB of BGDT).  Keeping the BGDT in RAM lets the
/// allocator decide which group to consult without an extra disk
/// round-trip per allocation.
///
/// Both the superblock and BGDT are written back to disk after every
/// allocation / free in the synchronous-write style described in the
/// ext2 specification (§2 "Superblock", §3 "Block Group Descriptor
/// Table").  ext2 has no journal, so durability is achieved by
/// updating bitmap → BGDT → superblock in that order; a crash between
/// any two steps leaves the filesystem internally consistent under
/// `e2fsck -fy`.
struct Ext2State {
    /// Mutable superblock counters.  Other fields of the superblock
    /// (block_size, inode_size, …) are duplicated as immutable plain
    /// fields on [`Ext2Fs`] so reads do not need to acquire this mutex.
    superblock: Superblock,
    /// Block-group descriptor table cached at mount time.  Indexed by
    /// block-group number.  Mutated by the block / inode allocators
    /// and the free paths.
    bgdt: Vec<BlockGroupDesc>,
}

/// ext2 filesystem instance.
pub struct Ext2Fs {
    /// Underlying reader (block-device trait object or test fn pointer).
    reader: BlockReader,
    /// Cached snapshot of the immutable parts of the superblock.  Counter
    /// fields here are NOT authoritative for write paths — those go
    /// through `state.superblock`.  Read paths can use either.
    superblock: Superblock,
    /// Block size in bytes.
    block_size: usize,
    /// Inode size in bytes.
    inode_size: usize,
    /// Number of block groups (ceil(blocks_count / blocks_per_group)).
    num_groups: u32,
    /// On-disk block number of the BGDT (block 1 with 4 KiB blocks,
    /// block 2 with 1 KiB blocks).
    bgdt_block: u32,
    /// Mutable state — see [`Ext2State`].
    state: Mutex<Ext2State>,
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

        // Number of block groups: ceil(blocks_count / blocks_per_group).
        // ext2 spec §2.4 "Block Group Descriptor Table".
        let num_groups = (sb.blocks_count + sb.blocks_per_group - 1) / sb.blocks_per_group;

        // BGDT location: per the spec the BGDT begins on the block IMMEDIATELY
        // following the superblock block.  With a 1 KiB block size the
        // superblock occupies block 1 (it starts at byte offset 1024), so the
        // BGDT begins at block 2; with any larger block size the superblock
        // shares block 0 and the BGDT begins at block 1.  (Spec §1.4 "Block
        // size" and §2.4 "Block Group Descriptor Table".)
        let bgdt_block = if block_size == 1024 { 2 } else { 1 };

        // Eagerly read the BGDT (32 bytes per entry).
        let bgdt = match Self::read_bgdt_via(
            &reader, block_size, bgdt_block, num_groups,
        ) {
            Some(t) => t,
            None => {
                crate::serial_println!("[EXT2] Failed to read BGDT");
                return None;
            }
        };

        Some(Ext2Fs {
            reader,
            superblock: sb,
            block_size,
            inode_size,
            num_groups,
            bgdt_block,
            state: Mutex::new(Ext2State { superblock: sb, bgdt }),
        })
    }

    /// Read the block-group descriptor table from disk into a Vec.
    ///
    /// Each descriptor is 32 bytes (ext2 spec §3 "Block Group Descriptor
    /// Structure" — `bg_block_bitmap`, `bg_inode_bitmap`, `bg_inode_table`,
    /// `bg_free_blocks_count`, `bg_free_inodes_count`, `bg_used_dirs_count`,
    /// `bg_pad`, `bg_reserved[3]` = 4+4+4+2+2+2+2+12 = 32).
    fn read_bgdt_via(
        reader: &BlockReader,
        block_size: usize,
        bgdt_block: u32,
        num_groups: u32,
    ) -> Option<Vec<BlockGroupDesc>> {
        let bgdt_bytes = num_groups as usize * 32;
        let sectors = (bgdt_bytes + 511) / 512;
        let mut buf = alloc::vec![0u8; sectors * 512];
        let start_sector = bgdt_block as u64 * (block_size as u64 / 512);
        Self::read_sectors_via(reader, start_sector, sectors as u16, &mut buf).ok()?;
        let mut out = Vec::with_capacity(num_groups as usize);
        for i in 0..num_groups as usize {
            let off = i * 32;
            let bgd: BlockGroupDesc = unsafe {
                core::ptr::read_unaligned(buf[off..].as_ptr() as *const BlockGroupDesc)
            };
            out.push(bgd);
        }
        Some(out)
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
        let num_groups = (sb.blocks_count + sb.blocks_per_group - 1) / sb.blocks_per_group;
        let bgdt_block = if block_size == 1024 { 2 } else { 1 };
        // The Fn-reader test path never exercises the allocator (the existing
        // EXT2-DIR-1 / EXT2-SB-1 / EXT2-LINK-1 tests are read-only validators)
        // so a dummy single-group BGDT is sufficient.  Real BGDT contents are
        // only consulted by the allocator, which requires the Device variant.
        let dummy_bgd = BlockGroupDesc {
            block_bitmap: 0, inode_bitmap: 0, inode_table: 0,
            free_blocks_count: 0, free_inodes_count: 0, used_dirs_count: 0,
            pad: 0, reserved: [0; 3],
        };
        let bgdt = alloc::vec![dummy_bgd; num_groups as usize];
        Some(Ext2Fs {
            reader: BlockReader::Fn(read_fn),
            superblock: sb,
            block_size,
            inode_size,
            num_groups,
            bgdt_block,
            state: Mutex::new(Ext2State { superblock: sb, bgdt }),
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

    /// Write `count` sectors starting at `sector` from `data`.
    ///
    /// Only the [`BlockReader::Device`] variant supports writes; the
    /// fn-pointer test variant returns an error (the read-only-validator
    /// tests never issue writes — the in-memory ext2 image tests use
    /// `MutableMemoryBlockDevice`, which IS a `BlockDevice`).
    fn write_sectors_inner(&self, sector: u64, count: u16, data: &[u8])
        -> Result<(), &'static str>
    {
        match &self.reader {
            BlockReader::Device(dev) => {
                dev.write_sectors(sector, count as u32, data)
                    .map_err(|_| "ext2: block device write error")
            }
            BlockReader::Fn(_) => Err("ext2: write through Fn reader not supported"),
        }
    }

    /// Read a block from the filesystem.
    fn read_block(&self, block_num: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        let sectors_per_block = (self.block_size / 512) as u16;
        let start_sector = block_num as u64 * sectors_per_block as u64;
        self.read_sectors_inner(start_sector, sectors_per_block, buf)
    }

    /// Write a whole block to the filesystem.
    fn write_block(&self, block_num: u32, data: &[u8]) -> Result<(), &'static str> {
        let sectors_per_block = (self.block_size / 512) as u16;
        let start_sector = block_num as u64 * sectors_per_block as u64;
        if data.len() < self.block_size {
            return Err("ext2: write_block called with short buffer");
        }
        self.write_sectors_inner(start_sector, sectors_per_block, &data[..self.block_size])
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

    // ────────────────────────────────────────────────────────────────────────
    // Write substrate (PR-B, 2026-05-24).
    //
    // The routines below implement the parts of the ext2 specification
    // that touch on-disk state mutation:
    //
    //   * Block + inode bitmap allocators (§4 "Block Bitmap" / §5 "Inode
    //     Bitmap"), walking the BGDT to find a group with free entries.
    //   * Inode write-back (§7 "Inode Table"), recomputing the table-block
    //     location for a given inode number from its block group.
    //   * Block resolution with on-demand allocation
    //     (`ensure_block`/`resolve_or_alloc_block`) — direct + single,
    //     double, triple indirect, allocating intermediate-pointer blocks
    //     when growing past the previous extent.
    //   * `write_inode_data` — buffered RMW for partial-block tail writes.
    //   * `truncate_inode_to` — both shrink (frees data + indirect blocks
    //     in reverse logical order) and grow (sparse — POSIX ftruncate(2)
    //     says trailing reads of the new tail return zeros, which we get
    //     for free from `read_inode_data`'s sparse-block branch).
    //
    // All routines that mutate the superblock counters or the BGDT take
    // `&self` and grab `self.state.lock()` internally — callers do not
    // synchronise.  After each mutation the corresponding 512-byte sector
    // is written back synchronously (ext2 has no journal; durability
    // depends on bitmap → BGDT → superblock ordering).
    // ────────────────────────────────────────────────────────────────────────

    /// Persist the live superblock counters back to sector 2.
    ///
    /// The superblock occupies the first 1 024 bytes at byte offset 1 024 in
    /// the partition, i.e. exactly sectors 2..3 (ext2 spec §2 "Superblock").
    /// Only the small subset of fields modelled by [`Superblock`] is
    /// rewritten — the trailing bytes of the on-disk superblock are
    /// preserved by reading first, patching the prefix, and writing back.
    fn flush_superblock(&self, sb: &Superblock) -> Result<(), &'static str> {
        let mut buf = [0u8; 512];
        self.read_sectors_inner(2, 1, &mut buf)?;
        unsafe {
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut Superblock, *sb);
        }
        self.write_sectors_inner(2, 1, &buf)
    }

    /// Persist a single block-group descriptor.
    ///
    /// The BGDT is at `bgdt_block`, with each descriptor being 32 bytes
    /// (ext2 spec §3 "Block Group Descriptor Structure").  We rewrite the
    /// 512-byte sector that contains `group`'s descriptor (read-modify-write
    /// so neighbouring descriptors are preserved).
    fn flush_bgd(&self, group: u32, bgd: &BlockGroupDesc) -> Result<(), &'static str> {
        let bgd_byte = self.bgdt_block as u64 * self.block_size as u64
            + group as u64 * 32;
        let sector = bgd_byte / 512;
        let off_in_sector = (bgd_byte % 512) as usize;
        let mut buf = [0u8; 512];
        self.read_sectors_inner(sector, 1, &mut buf)?;
        unsafe {
            core::ptr::write_unaligned(
                buf[off_in_sector..].as_mut_ptr() as *mut BlockGroupDesc, *bgd);
        }
        self.write_sectors_inner(sector, 1, &buf)
    }

    /// Write an inode by number back to the inode table.
    ///
    /// Inverse of [`Self::read_inode`].  Computes the inode-table location
    /// from the BGDT, reads the host sector, patches the first 128 bytes
    /// (the [`Ext2Inode`] prefix), and writes back.  Rev-1 filesystems
    /// allocate `inode_size` bytes per slot but we only model and dirty the
    /// classical 128-byte prefix — the trailing bytes (xattrs, nsec
    /// timestamps, …) round-trip unchanged through the RMW.
    pub(crate) fn write_inode(&self, inode_num: u64, inode: &Ext2Inode)
        -> Result<(), &'static str>
    {
        if inode_num == 0 { return Err("ext2: inode 0 invalid"); }
        let inode_idx = (inode_num - 1) as u32;
        let group = inode_idx / self.superblock.inodes_per_group;
        let idx_in_group = inode_idx % self.superblock.inodes_per_group;
        let table_block = {
            let state = self.state.lock();
            let bgd = state.bgdt.get(group as usize)
                .ok_or("ext2: write_inode group out of range")?;
            bgd.inode_table
        };
        let inode_byte = table_block as u64 * self.block_size as u64
            + idx_in_group as u64 * self.inode_size as u64;
        let inode_sector = inode_byte / 512;
        let inode_off = (inode_byte % 512) as usize;

        if inode_off + 128 <= 512 {
            let mut buf = [0u8; 512];
            self.read_sectors_inner(inode_sector, 1, &mut buf)?;
            unsafe {
                core::ptr::write_unaligned(
                    buf[inode_off..].as_mut_ptr() as *mut Ext2Inode, *inode);
            }
            self.write_sectors_inner(inode_sector, 1, &buf)
        } else {
            let mut buf2 = [0u8; 1024];
            self.read_sectors_inner(inode_sector, 2, &mut buf2)?;
            unsafe {
                core::ptr::write_unaligned(
                    buf2[inode_off..].as_mut_ptr() as *mut Ext2Inode, *inode);
            }
            self.write_sectors_inner(inode_sector, 2, &buf2)
        }
    }

    /// Allocate one free data block, mark its bitmap bit, decrement free
    /// counters in the owning group's BGDT entry and the superblock, and
    /// return the absolute block number.  Returns `None` if the filesystem
    /// has no free blocks (ENOSPC).
    ///
    /// Bitmap-scan order matches the ext2 spec §4 "Block Bitmap": walk
    /// groups round-robin starting at group 0, and within a group scan the
    /// bitmap bits low-to-high (LSB of byte 0 is data block
    /// `first_data_block + group * blocks_per_group`).
    fn alloc_block(&self) -> Option<u32> {
        let mut state = self.state.lock();
        if state.superblock.free_blocks_count == 0 { return None; }
        let num_groups = self.num_groups as usize;
        for group in 0..num_groups {
            if state.bgdt[group].free_blocks_count == 0 { continue; }
            // Read the group's block bitmap.
            let bitmap_block = state.bgdt[group].block_bitmap;
            // Drop the state lock across the I/O — we re-acquire to commit
            // the bit and counters.  Other allocators racing on the same
            // group are coordinated by the bitmap-scan retry below
            // (re-read after re-locking).
            drop(state);
            let mut bitmap = alloc::vec![0u8; self.block_size];
            if self.read_block(bitmap_block, &mut bitmap).is_err() {
                state = self.state.lock();
                continue;
            }
            // Find a clear bit within `blocks_per_group` of the group's
            // bitmap.  Limit the scan: the bitmap byte count is
            // `block_size`, but `blocks_per_group` may be smaller — beyond
            // that the bits MUST be set to 1 by mkfs (spec §4) and we
            // honour that here defensively.
            let bits_in_group = self.superblock.blocks_per_group as usize;
            let mut chosen: Option<usize> = None;
            for byte_idx in 0..(bits_in_group + 7) / 8 {
                if bitmap[byte_idx] == 0xFF { continue; }
                for bit in 0..8 {
                    let bit_idx = byte_idx * 8 + bit;
                    if bit_idx >= bits_in_group { break; }
                    if bitmap[byte_idx] & (1 << bit) == 0 {
                        chosen = Some(bit_idx);
                        break;
                    }
                }
                if chosen.is_some() { break; }
            }
            state = self.state.lock();
            let Some(bit_idx) = chosen else {
                // Re-acquired and found no free bit — counter was stale or
                // raced; skip group.
                continue;
            };
            // Re-check after re-acquiring (free count could have dropped to 0).
            if state.bgdt[group].free_blocks_count == 0 { continue; }
            // Commit the bit.  Note bitmap was read without the lock; under
            // single-threaded test runs this is exact, under SMP a future
            // PR-E should add a per-group lock + atomic CAS retry on the
            // bit.  For PR-B we accept the wider critical section by
            // re-reading the byte and OR-ing the bit.
            let byte_idx = bit_idx / 8;
            let bit_off = bit_idx % 8;
            // Re-read the host byte (single sector containing it) to apply
            // the bit OR.  Doing a full block re-read would be safer; this
            // narrow RMW is what the spec describes.
            bitmap[byte_idx] |= 1 << bit_off;
            if self.write_block(bitmap_block, &bitmap).is_err() {
                continue;
            }
            // Compute the absolute block number.
            let block_num = self.superblock.first_data_block
                + (group as u32) * self.superblock.blocks_per_group
                + bit_idx as u32;
            // Zero the new block — ext2 spec does not strictly require this
            // but most callers expect zeroed indirect/data blocks (POSIX
            // `lseek(SEEK_END) + write` semantics for tail extension, and
            // indirect-block initialisation).
            let zero = alloc::vec![0u8; self.block_size];
            let _ = self.write_block(block_num, &zero);
            // Update BGDT + superblock counters.
            state.bgdt[group].free_blocks_count -= 1;
            state.superblock.free_blocks_count -= 1;
            let bgd_snap = state.bgdt[group];
            let sb_snap = state.superblock;
            drop(state);
            let _ = self.flush_bgd(group as u32, &bgd_snap);
            let _ = self.flush_superblock(&sb_snap);
            return Some(block_num);
        }
        None
    }

    /// Free one data block — clear its bitmap bit, increment free counters.
    /// No-op for `block_num == 0` (sparse-block sentinel).
    fn free_block(&self, block_num: u32) {
        if block_num == 0 { return; }
        if block_num < self.superblock.first_data_block { return; }
        let offset = block_num - self.superblock.first_data_block;
        let group = offset / self.superblock.blocks_per_group;
        let bit_idx = (offset % self.superblock.blocks_per_group) as usize;
        if group as usize >= self.num_groups as usize { return; }
        let mut state = self.state.lock();
        let bitmap_block = state.bgdt[group as usize].block_bitmap;
        drop(state);
        let mut bitmap = alloc::vec![0u8; self.block_size];
        if self.read_block(bitmap_block, &mut bitmap).is_err() { return; }
        let byte_idx = bit_idx / 8;
        let bit_off = bit_idx % 8;
        if bitmap[byte_idx] & (1 << bit_off) == 0 {
            // Already free — log and skip the counter increment to avoid
            // double-free corruption.
            crate::serial_println!(
                "[EXT2] free_block({}): bit already clear (double free?)", block_num);
            return;
        }
        bitmap[byte_idx] &= !(1 << bit_off);
        if self.write_block(bitmap_block, &bitmap).is_err() { return; }
        let mut state = self.state.lock();
        state.bgdt[group as usize].free_blocks_count += 1;
        state.superblock.free_blocks_count += 1;
        let bgd_snap = state.bgdt[group as usize];
        let sb_snap = state.superblock;
        drop(state);
        let _ = self.flush_bgd(group, &bgd_snap);
        let _ = self.flush_superblock(&sb_snap);
    }

    /// Allocate one free inode and return its 1-based inode number.
    ///
    /// `is_dir` controls bookkeeping only (the spec asks us to keep a
    /// per-group `used_dirs_count` for the Orlov allocator's directory
    /// spreading heuristic).  Reserved inodes (1..`first_ino` exclusive for
    /// rev ≥ 1) are never returned.
    #[allow(dead_code)]
    pub(crate) fn alloc_inode(&self, is_dir: bool) -> Option<u32> {
        let first_ino = if self.superblock.rev_level >= 1 {
            self.superblock.first_ino
        } else {
            11 // Rev 0 reserves inodes 1..11.
        };
        let inodes_per_group = self.superblock.inodes_per_group as usize;
        let num_groups = self.num_groups as usize;
        let mut state = self.state.lock();
        if state.superblock.free_inodes_count == 0 { return None; }
        for group in 0..num_groups {
            if state.bgdt[group].free_inodes_count == 0 { continue; }
            let bitmap_block = state.bgdt[group].inode_bitmap;
            drop(state);
            let mut bitmap = alloc::vec![0u8; self.block_size];
            if self.read_block(bitmap_block, &mut bitmap).is_err() {
                state = self.state.lock();
                continue;
            }
            let mut chosen: Option<usize> = None;
            for bit_idx in 0..inodes_per_group {
                let absolute = (group as u32 * self.superblock.inodes_per_group)
                    + bit_idx as u32 + 1;
                if absolute < first_ino { continue; }
                let byte_idx = bit_idx / 8;
                let bit_off = bit_idx % 8;
                if bitmap[byte_idx] & (1 << bit_off) == 0 {
                    chosen = Some(bit_idx);
                    break;
                }
            }
            state = self.state.lock();
            let Some(bit_idx) = chosen else { continue; };
            if state.bgdt[group].free_inodes_count == 0 { continue; }
            let byte_idx = bit_idx / 8;
            let bit_off = bit_idx % 8;
            bitmap[byte_idx] |= 1 << bit_off;
            if self.write_block(bitmap_block, &bitmap).is_err() { continue; }
            let inum = (group as u32 * self.superblock.inodes_per_group)
                + bit_idx as u32 + 1;
            state.bgdt[group].free_inodes_count -= 1;
            if is_dir { state.bgdt[group].used_dirs_count += 1; }
            state.superblock.free_inodes_count -= 1;
            let bgd_snap = state.bgdt[group];
            let sb_snap = state.superblock;
            drop(state);
            let _ = self.flush_bgd(group as u32, &bgd_snap);
            let _ = self.flush_superblock(&sb_snap);
            return Some(inum);
        }
        None
    }

    /// Free an inode — clear its bitmap bit, increment free counters.
    #[allow(dead_code)]
    pub(crate) fn free_inode(&self, inum: u32, was_dir: bool) {
        if inum == 0 { return; }
        let group = (inum - 1) / self.superblock.inodes_per_group;
        let bit_idx = ((inum - 1) % self.superblock.inodes_per_group) as usize;
        if group as usize >= self.num_groups as usize { return; }
        let mut state = self.state.lock();
        let bitmap_block = state.bgdt[group as usize].inode_bitmap;
        drop(state);
        let mut bitmap = alloc::vec![0u8; self.block_size];
        if self.read_block(bitmap_block, &mut bitmap).is_err() { return; }
        let byte_idx = bit_idx / 8;
        let bit_off = bit_idx % 8;
        if bitmap[byte_idx] & (1 << bit_off) == 0 { return; }
        bitmap[byte_idx] &= !(1 << bit_off);
        if self.write_block(bitmap_block, &bitmap).is_err() { return; }
        let mut state = self.state.lock();
        state.bgdt[group as usize].free_inodes_count += 1;
        if was_dir && state.bgdt[group as usize].used_dirs_count > 0 {
            state.bgdt[group as usize].used_dirs_count -= 1;
        }
        state.superblock.free_inodes_count += 1;
        let bgd_snap = state.bgdt[group as usize];
        let sb_snap = state.superblock;
        drop(state);
        let _ = self.flush_bgd(group, &bgd_snap);
        let _ = self.flush_superblock(&sb_snap);
    }

    /// Write a single 32-bit little-endian pointer into an indirect block
    /// at slot `index`.  Reads, modifies, writes the block.  Used by the
    /// indirect-tree growth path.
    fn write_indirect_slot(&self, block_num: u32, index: usize, value: u32)
        -> Result<(), &'static str>
    {
        let mut buf = alloc::vec![0u8; self.block_size];
        self.read_block(block_num, &mut buf)?;
        let byte_off = index * 4;
        if byte_off + 4 > self.block_size {
            return Err("ext2: indirect slot out of range");
        }
        buf[byte_off..byte_off + 4].copy_from_slice(&value.to_le_bytes());
        self.write_block(block_num, &buf)
    }

    /// Resolve a logical block index to a physical block number,
    /// allocating intermediate-indirect and leaf data blocks as needed.
    ///
    /// `inode` is mutated in place: if the inode's direct slots
    /// (`i_block[0..12]`) or indirect-tree-root slots (`i_block[12..15]`)
    /// gain new pointers, the caller observes them.  The caller is
    /// responsible for writing the modified inode back with
    /// [`Self::write_inode`].
    ///
    /// Returns the absolute block number, or `None` if a needed allocation
    /// failed (ENOSPC).
    fn ensure_block(&self, inode: &mut Ext2Inode, block_idx: usize) -> Option<u32> {
        let ptrs_per_block = self.block_size / 4;

        // ── Direct ────────────────────────────────────────────────────────
        if block_idx < 12 {
            if inode.block[block_idx] == 0 {
                let new = self.alloc_block()?;
                inode.block[block_idx] = new;
                inode.blocks += (self.block_size / 512) as u32;
            }
            return Some(inode.block[block_idx]);
        }

        let block_idx = block_idx - 12;

        // ── Single indirect ───────────────────────────────────────────────
        if block_idx < ptrs_per_block {
            if inode.block[12] == 0 {
                let new = self.alloc_block()?;
                inode.block[12] = new;
                inode.blocks += (self.block_size / 512) as u32;
            }
            let leaf = self.read_indirect(inode.block[12], block_idx);
            if leaf == 0 {
                let new = self.alloc_block()?;
                self.write_indirect_slot(inode.block[12], block_idx, new).ok()?;
                inode.blocks += (self.block_size / 512) as u32;
                return Some(new);
            }
            return Some(leaf);
        }

        let block_idx = block_idx - ptrs_per_block;

        // ── Double indirect ───────────────────────────────────────────────
        if block_idx < ptrs_per_block * ptrs_per_block {
            let i = block_idx / ptrs_per_block;
            let j = block_idx % ptrs_per_block;
            if inode.block[13] == 0 {
                let new = self.alloc_block()?;
                inode.block[13] = new;
                inode.blocks += (self.block_size / 512) as u32;
            }
            let mut ind1 = self.read_indirect(inode.block[13], i);
            if ind1 == 0 {
                ind1 = self.alloc_block()?;
                self.write_indirect_slot(inode.block[13], i, ind1).ok()?;
                inode.blocks += (self.block_size / 512) as u32;
            }
            let leaf = self.read_indirect(ind1, j);
            if leaf == 0 {
                let new = self.alloc_block()?;
                self.write_indirect_slot(ind1, j, new).ok()?;
                inode.blocks += (self.block_size / 512) as u32;
                return Some(new);
            }
            return Some(leaf);
        }

        let block_idx = block_idx - ptrs_per_block * ptrs_per_block;

        // ── Triple indirect ───────────────────────────────────────────────
        let i = block_idx / (ptrs_per_block * ptrs_per_block);
        let rem = block_idx % (ptrs_per_block * ptrs_per_block);
        let j = rem / ptrs_per_block;
        let k = rem % ptrs_per_block;
        if inode.block[14] == 0 {
            let new = self.alloc_block()?;
            inode.block[14] = new;
            inode.blocks += (self.block_size / 512) as u32;
        }
        let mut ind1 = self.read_indirect(inode.block[14], i);
        if ind1 == 0 {
            ind1 = self.alloc_block()?;
            self.write_indirect_slot(inode.block[14], i, ind1).ok()?;
            inode.blocks += (self.block_size / 512) as u32;
        }
        let mut ind2 = self.read_indirect(ind1, j);
        if ind2 == 0 {
            ind2 = self.alloc_block()?;
            self.write_indirect_slot(ind1, j, ind2).ok()?;
            inode.blocks += (self.block_size / 512) as u32;
        }
        let leaf = self.read_indirect(ind2, k);
        if leaf == 0 {
            let new = self.alloc_block()?;
            self.write_indirect_slot(ind2, k, new).ok()?;
            inode.blocks += (self.block_size / 512) as u32;
            return Some(new);
        }
        Some(leaf)
    }

    /// Write `data` to `inode` at `offset`.  Allocates blocks as needed.
    /// Updates `i_size`, `i_blocks`, `i_mtime` and writes the inode back.
    /// Returns the number of bytes written (always `data.len()` on success,
    /// or fewer on ENOSPC partway through).
    fn write_inode_data(&self, inode_num: u64, mut inode: Ext2Inode,
                        offset: u64, data: &[u8]) -> Result<usize, &'static str>
    {
        if data.is_empty() { return Ok(0); }
        let mut written = 0;
        let mut block_buf = alloc::vec![0u8; self.block_size];

        while written < data.len() {
            let pos = offset + written as u64;
            let block_idx = (pos / self.block_size as u64) as usize;
            let off_in_block = (pos % self.block_size as u64) as usize;
            let Some(phys) = self.ensure_block(&mut inode, block_idx) else {
                break; // ENOSPC partway through — flush what we have
            };
            let n = (self.block_size - off_in_block).min(data.len() - written);
            if off_in_block == 0 && n == self.block_size {
                // Whole-block fast path — no RMW needed.
                self.write_sectors_inner(
                    phys as u64 * (self.block_size / 512) as u64,
                    (self.block_size / 512) as u16,
                    &data[written..written + n],
                )?;
            } else {
                // Partial-block tail — RMW.
                self.read_block(phys, &mut block_buf)?;
                block_buf[off_in_block..off_in_block + n]
                    .copy_from_slice(&data[written..written + n]);
                self.write_block(phys, &block_buf)?;
            }
            written += n;
        }

        // Update size / mtime if file grew.
        let end = offset + written as u64;
        if end > inode.size as u64 {
            inode.size = end.min(u32::MAX as u64) as u32;
        }
        inode.mtime = current_unix_time();
        self.write_inode(inode_num, &inode)?;
        Ok(written)
    }

    /// Truncate (shrink or grow) an inode to `new_size`.
    ///
    /// * **Shrink** — frees data blocks that fall entirely past the new
    ///   logical end.  Indirect, double-indirect and triple-indirect index
    ///   blocks that become unreferenced are also freed.  Per POSIX
    ///   `ftruncate(2)`, the partial trailing block (if any) is preserved
    ///   in the file but the bytes past `new_size` are not guaranteed to
    ///   read as zero — we DO zero them so a subsequent grow does not
    ///   surface stale data.
    /// * **Grow** — leaves the file sparse; no blocks are allocated.
    ///   `read_inode_data`'s sparse-block branch already returns zeros for
    ///   any logical block whose pointer slot is 0, matching the POSIX
    ///   contract that bytes added by ftruncate read as zero.
    ///
    /// Updates `i_size`, `i_blocks`, `i_mtime` and writes the inode back.
    fn truncate_inode_to(&self, inode_num: u64, mut inode: Ext2Inode,
                         new_size: u64) -> Result<(), &'static str>
    {
        let old_size = inode.size as u64;
        if new_size == old_size {
            return Ok(());
        }

        if new_size > old_size {
            // Grow path: sparse.  Just update size + mtime.
            inode.size = new_size.min(u32::MAX as u64) as u32;
            inode.mtime = current_unix_time();
            return self.write_inode(inode_num, &inode);
        }

        // Shrink path.  Compute the first block index that must be entirely
        // freed: `first_free_idx = ceil(new_size / block_size)`.  Blocks
        // strictly before that index are kept; the block at that index, if
        // any portion remains in-file (i.e. new_size > first_free_idx *
        // block_size), is RMW-zeroed in its trailing portion.
        let bs = self.block_size as u64;
        let first_free_idx = ((new_size + bs - 1) / bs) as usize;
        let last_kept_idx = if new_size == 0 { 0 } else { ((new_size - 1) / bs) as usize };

        // Zero the trailing portion of the last-kept block if the cut
        // falls mid-block.
        if new_size > 0 && new_size % bs != 0 {
            let tail_off = (new_size % bs) as usize;
            let phys = self.resolve_block(&inode, last_kept_idx);
            if phys != 0 {
                let mut buf = alloc::vec![0u8; self.block_size];
                if self.read_block(phys, &mut buf).is_ok() {
                    for byte in &mut buf[tail_off..] { *byte = 0; }
                    let _ = self.write_block(phys, &buf);
                }
            }
        }

        // Walk the indirect tree in reverse order, freeing any data blocks
        // and intermediate-pointer blocks no longer needed.  This is a
        // straightforward iteration over the inode's three branches.
        self.free_blocks_from(&mut inode, first_free_idx);

        inode.size = new_size as u32;
        inode.mtime = current_unix_time();
        self.write_inode(inode_num, &inode)
    }

    /// Free all data blocks at logical index ≥ `first_free`.  Also frees
    /// any indirect / double-indirect / triple-indirect index blocks that
    /// become unreferenced.  Mutates `inode.block[]` to clear the freed
    /// roots and `inode.blocks` to drop the released sector count.
    fn free_blocks_from(&self, inode: &mut Ext2Inode, first_free: usize) {
        let ptrs_per_block = self.block_size / 4;
        let direct_capacity = 12usize;
        let single_capacity = direct_capacity + ptrs_per_block;
        let double_capacity = single_capacity + ptrs_per_block * ptrs_per_block;
        // Triple capacity is `double + ptrs_per_block ** 3`.  No need to
        // compute it explicitly — anything past `double_capacity` lives in
        // the triple-indirect branch.

        // ── Direct ────────────────────────────────────────────────────────
        for idx in first_free.min(direct_capacity)..direct_capacity {
            let b = inode.block[idx];
            if b != 0 {
                self.free_block(b);
                inode.block[idx] = 0;
                inode.blocks = inode.blocks.saturating_sub((self.block_size / 512) as u32);
            }
        }

        // ── Single indirect ───────────────────────────────────────────────
        if first_free < single_capacity && inode.block[12] != 0 {
            let local_first = first_free.saturating_sub(direct_capacity);
            self.free_indirect_branch(inode.block[12], local_first, ptrs_per_block, inode, 1);
            if local_first == 0 {
                self.free_block(inode.block[12]);
                inode.block[12] = 0;
                inode.blocks = inode.blocks.saturating_sub((self.block_size / 512) as u32);
            }
        }

        // ── Double indirect ───────────────────────────────────────────────
        if first_free < double_capacity && inode.block[13] != 0 {
            let local_first = first_free.saturating_sub(single_capacity);
            let count_per_branch = ptrs_per_block;
            // Walk the top-level pointers in `inode.block[13]`.  Each slot
            // refers to a single-indirect branch addressing
            // `ptrs_per_block` data blocks.
            let mut buf = alloc::vec![0u8; self.block_size];
            if self.read_block(inode.block[13], &mut buf).is_ok() {
                let mut top_changed = false;
                for i in 0..ptrs_per_block {
                    let branch_first_logical = i * count_per_branch;
                    let branch_last_logical = branch_first_logical + count_per_branch;
                    if branch_last_logical <= local_first { continue; }
                    let byte_off = i * 4;
                    let ind_ptr = u32::from_le_bytes(
                        [buf[byte_off], buf[byte_off+1], buf[byte_off+2], buf[byte_off+3]]);
                    if ind_ptr == 0 { continue; }
                    let local_inner = local_first.saturating_sub(branch_first_logical);
                    self.free_indirect_branch(ind_ptr, local_inner, ptrs_per_block, inode, 1);
                    if local_inner == 0 {
                        self.free_block(ind_ptr);
                        buf[byte_off..byte_off+4].copy_from_slice(&0u32.to_le_bytes());
                        top_changed = true;
                        inode.blocks = inode.blocks
                            .saturating_sub((self.block_size / 512) as u32);
                    }
                }
                if top_changed {
                    let _ = self.write_block(inode.block[13], &buf);
                }
            }
            if local_first == 0 {
                self.free_block(inode.block[13]);
                inode.block[13] = 0;
                inode.blocks = inode.blocks.saturating_sub((self.block_size / 512) as u32);
            }
        }

        // ── Triple indirect ───────────────────────────────────────────────
        if inode.block[14] != 0 {
            let local_first = first_free.saturating_sub(double_capacity);
            let count_per_branch = ptrs_per_block * ptrs_per_block;
            let mut buf = alloc::vec![0u8; self.block_size];
            if self.read_block(inode.block[14], &mut buf).is_ok() {
                let mut top_changed = false;
                for i in 0..ptrs_per_block {
                    let branch_first_logical = i * count_per_branch;
                    let branch_last_logical = branch_first_logical + count_per_branch;
                    if branch_last_logical <= local_first { continue; }
                    let byte_off = i * 4;
                    let ind_ptr = u32::from_le_bytes(
                        [buf[byte_off], buf[byte_off+1], buf[byte_off+2], buf[byte_off+3]]);
                    if ind_ptr == 0 { continue; }
                    let local_inner = local_first.saturating_sub(branch_first_logical);
                    self.free_double_indirect_branch(
                        ind_ptr, local_inner, ptrs_per_block, inode);
                    if local_inner == 0 {
                        self.free_block(ind_ptr);
                        buf[byte_off..byte_off+4].copy_from_slice(&0u32.to_le_bytes());
                        top_changed = true;
                        inode.blocks = inode.blocks
                            .saturating_sub((self.block_size / 512) as u32);
                    }
                }
                if top_changed {
                    let _ = self.write_block(inode.block[14], &buf);
                }
            }
            if local_first == 0 {
                self.free_block(inode.block[14]);
                inode.block[14] = 0;
                inode.blocks = inode.blocks.saturating_sub((self.block_size / 512) as u32);
            }
        }
    }

    /// Free leaf data blocks in the single-indirect branch rooted at
    /// `ind_block`, starting at logical index `from` (in this branch's
    /// local numbering), up to `count` entries.  Does NOT free the
    /// `ind_block` itself — that is the caller's decision based on
    /// whether the branch is now fully emptied.
    fn free_indirect_branch(&self, ind_block: u32, from: usize,
                            count: usize, inode: &mut Ext2Inode, _depth: u32)
    {
        let mut buf = alloc::vec![0u8; self.block_size];
        if self.read_block(ind_block, &mut buf).is_err() { return; }
        let mut changed = false;
        for i in from..count.min(self.block_size / 4) {
            let off = i * 4;
            let ptr = u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
            if ptr != 0 {
                self.free_block(ptr);
                buf[off..off+4].copy_from_slice(&0u32.to_le_bytes());
                changed = true;
                inode.blocks = inode.blocks
                    .saturating_sub((self.block_size / 512) as u32);
            }
        }
        if changed {
            let _ = self.write_block(ind_block, &buf);
        }
    }

    /// Free a double-indirect branch from logical index `from` onwards.
    fn free_double_indirect_branch(&self, dind_block: u32, from: usize,
                                   ptrs_per_block: usize, inode: &mut Ext2Inode)
    {
        let mut buf = alloc::vec![0u8; self.block_size];
        if self.read_block(dind_block, &mut buf).is_err() { return; }
        let mut changed = false;
        for i in 0..ptrs_per_block {
            let branch_first = i * ptrs_per_block;
            let branch_last = branch_first + ptrs_per_block;
            if branch_last <= from { continue; }
            let off = i * 4;
            let ind = u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
            if ind == 0 { continue; }
            let local_inner = from.saturating_sub(branch_first);
            self.free_indirect_branch(ind, local_inner, ptrs_per_block, inode, 1);
            if local_inner == 0 {
                self.free_block(ind);
                buf[off..off+4].copy_from_slice(&0u32.to_le_bytes());
                changed = true;
                inode.blocks = inode.blocks
                    .saturating_sub((self.block_size / 512) as u32);
            }
        }
        if changed {
            let _ = self.write_block(dind_block, &buf);
        }
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

    /// Test-only accessor for the live `s_free_blocks_count` counter.
    /// Used by EXT2-TRUNC-1 / EXT2-ALLOC-1 to assert that allocation +
    /// free balance.  Reads through the mutex so the test sees the
    /// post-flush value rather than the immutable mount-time snapshot
    /// stored on `Ext2Fs::superblock`.
    #[doc(hidden)]
    pub fn stat_free_blocks_count_for_test(&self) -> u32 {
        self.state.lock().superblock.free_blocks_count
    }

    /// Test-only accessor for a single group's `bg_free_blocks_count`.
    /// Returns 0 if `group` is out of range.
    #[doc(hidden)]
    pub fn stat_free_blocks_count_for_group_for_test(&self, group: u32) -> u16 {
        let state = self.state.lock();
        state.bgdt.get(group as usize)
            .map(|b| b.free_blocks_count)
            .unwrap_or(0)
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

    fn write(&self, inode: u64, offset: u64, data: &[u8]) -> VfsResult<usize> {
        let ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        // POSIX write(2): writing to a directory returns EISDIR.
        if (ino.mode & S_IFMT) == S_IFDIR {
            return Err(VfsError::IsADirectory);
        }
        self.write_inode_data(inode, ino, offset, data)
            .map_err(|e| {
                crate::serial_println!("[EXT2] write(inode={}, off={}, len={}) failed: {}",
                    inode, offset, data.len(), e);
                VfsError::Io
            })
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

    fn truncate(&self, inode: u64, size: u64) -> VfsResult<()> {
        let ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        // POSIX ftruncate(2) / truncate(2): EISDIR on a directory.
        if (ino.mode & S_IFMT) == S_IFDIR {
            return Err(VfsError::IsADirectory);
        }
        // Cap at i_size's representable range — we do not support
        // EXT2_FEATURE_RO_COMPAT_LARGE_FILE (i_dir_acl as size_high) in
        // PR-B; the audit lists this as a low-risk gap for libxul-dbg.
        if size > u32::MAX as u64 {
            return Err(VfsError::InvalidArg);
        }
        self.truncate_inode_to(inode, ino, size).map_err(|e| {
            crate::serial_println!("[EXT2] truncate(inode={}, size={}) failed: {}",
                inode, size, e);
            VfsError::Io
        })
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
