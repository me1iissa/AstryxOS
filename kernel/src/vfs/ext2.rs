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
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::drivers::block::BlockDevice;
use crate::vfs::VfsError;

/// Maximum number of entries kept in the per-directory dentry cache.
///
/// When this limit is reached the oldest entry (FIFO order) is evicted.
/// 1024 entries cover the entire `/usr/lib` directory of a typical Alpine
/// Linux installation (≈600–900 shared libraries) with some headroom.
const DENTRY_CACHE_CAP: usize = 1024;

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
const S_IFREG: u16 = 0x8000;
const S_IFDIR: u16 = 0x4000;
const S_IFLNK: u16 = 0xA000;

/// Directory entry `file_type` byte values for revision-1 ext2 images
/// (`EXT2_FEATURE_INCOMPAT_FILETYPE`).  See the second-extended-filesystem
/// specification §3 "Linked directory entries"
/// (<https://www.nongnu.org/ext2-doc/ext2.html#linked-directory-entries>).
/// Rev-0 images always set this byte to 0; that case is handled implicitly
/// by [`Ext2Fs::readdir`] which already maps unknown values to
/// `FileType::RegularFile`.
const EXT2_FT_REG_FILE: u8 = 1;
const EXT2_FT_DIR: u8 = 2;
#[allow(dead_code)]
const EXT2_FT_SYMLINK: u8 = 7;

/// Directory-entry on-disk header size (`inode` + `rec_len` + `name_len`
/// + `file_type` = 4+2+1+1 = 8 bytes), per the specification §3 "Linked
/// directory entries".
const EXT2_DIR_HDR: usize = 8;

/// Compute the on-disk record length needed to store an entry with the
/// given `name_len`, rounded up to a 4-byte boundary
/// (`EXT2_DIR_REC_LEN(name_len) = ((name_len + 8 + 3) & ~3)`).  This is
/// the canonical macro from the ext2 specification; every entry that
/// goes on disk must be aligned to a 4-byte multiple so the next entry's
/// `inode` field is naturally aligned.
#[inline]
const fn ext2_dir_rec_len(name_len: usize) -> usize {
    (name_len + EXT2_DIR_HDR + 3) & !3
}

/// Map an inode `mode` to the dir-entry `file_type` byte.
fn ext2_ft_from_mode(mode: u16) -> u8 {
    match mode & S_IFMT {
        S_IFDIR => EXT2_FT_DIR,
        S_IFLNK => EXT2_FT_SYMLINK,
        _ => EXT2_FT_REG_FILE,
    }
}

/// Serialise a single directory-entry record at byte offset `off` in
/// `buf`.  Writes the 8-byte header (`inode`, `rec_len`, `name_len`,
/// `file_type`) followed by `name`, then zero-pads any trailing slack
/// inside `rec_len` so a later read does not see stale bytes.  Caller
/// guarantees `off + rec_len ≤ buf.len()`.
fn write_dir_entry(buf: &mut [u8], off: usize, inode: u32,
                   rec_len: usize, name: &[u8], file_type: u8) {
    debug_assert!(rec_len >= ext2_dir_rec_len(name.len()));
    debug_assert!(off + rec_len <= buf.len());
    buf[off..off+4].copy_from_slice(&inode.to_le_bytes());
    buf[off+4..off+6].copy_from_slice(&(rec_len as u16).to_le_bytes());
    buf[off+6] = name.len() as u8;
    buf[off+7] = file_type;
    buf[off+EXT2_DIR_HDR..off+EXT2_DIR_HDR+name.len()].copy_from_slice(name);
    // Zero the trailing slack so stale bytes from a previous entry don't
    // leak (some tools sanity-check zero padding).
    for byte in &mut buf[off+EXT2_DIR_HDR+name.len()..off+rec_len] {
        *byte = 0;
    }
}

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
///
/// Also holds the two hot-path caches added in PR-E:
///
/// * **Dentry cache** — a bounded `BTreeMap` mapping
///   `(parent_inode, name)` to the child inode number.  Populated on
///   every successful `lookup`, evicted on `unlink`, `rename`,
///   `create_file`, `create_dir`, and `symlink`.  FIFO eviction via a
///   companion `VecDeque` of keys.  Cap: [`DENTRY_CACHE_CAP`] entries.
///
/// * **Indirect-block cache** — a single-entry cache holding the most
///   recently read indirect block.  Avoids re-reading the same indirect
///   block on every pointer lookup when reading a large file
///   sequentially (e.g. libxul.so mmap demand-fault storms).
struct Ext2State {
    /// Mutable superblock counters.  Other fields of the superblock
    /// (block_size, inode_size, …) are duplicated as immutable plain
    /// fields on [`Ext2Fs`] so reads do not need to acquire this mutex.
    superblock: Superblock,
    /// Block-group descriptor table cached at mount time.  Indexed by
    /// block-group number.  Mutated by the block / inode allocators
    /// and the free paths.
    bgdt: Vec<BlockGroupDesc>,
    /// Per-directory dentry cache: (parent_inode, name) → child_inode.
    /// Protected by this mutex because dentry inserts/evictions race
    /// with concurrent lookups in the same mutex epoch.
    dentry_map: BTreeMap<(u64, String), u64>,
    /// FIFO eviction queue — keys are (parent_inode, name) in insertion
    /// order.  When `dentry_map.len() == DENTRY_CACHE_CAP` we pop the
    /// front and remove the corresponding entry from `dentry_map`.
    dentry_fifo: VecDeque<(u64, String)>,
    /// Single-entry indirect-block cache.  `None` if empty.
    /// Tuple is `(block_num, block_data)`.  Invalidated whenever
    /// [`Ext2Fs::write_indirect_slot`] modifies an indirect block.
    indirect_cache: Option<(u32, Vec<u8>)>,
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
    /// Per-group allocation lock (PR-E SMP fix).
    ///
    /// Serialises concurrent block/inode allocations within the same
    /// block group.  A CPU that wins the per-group lock reads the bitmap,
    /// finds a free bit, sets it, and writes the bitmap back — all while
    /// holding this lock.  A racing CPU queues behind the lock and then
    /// re-reads the bitmap after acquiring it, so it sees the updated
    /// state and cannot pick the same bit.
    ///
    /// Different block groups can allocate in parallel (different indices
    /// in this vec), eliminating the bottleneck of a single global lock.
    ///
    /// Allocated lazily (empty `Vec` when num_groups is not yet known)
    /// and then populated in [`Ext2Fs::new_with_reader`].
    per_group_alloc: Vec<Mutex<()>>,
    /// Count of dentry-cache hits since mount.  Incremented atomically
    /// so it is visible to test assertions without taking the state lock.
    pub dentry_cache_hits: AtomicUsize,
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

        // Build per-group alloc locks.
        let mut per_group_alloc = Vec::with_capacity(num_groups as usize);
        for _ in 0..num_groups {
            per_group_alloc.push(Mutex::new(()));
        }

        Some(Ext2Fs {
            reader,
            superblock: sb,
            block_size,
            inode_size,
            num_groups,
            bgdt_block,
            state: Mutex::new(Ext2State {
                superblock: sb,
                bgdt,
                dentry_map: BTreeMap::new(),
                dentry_fifo: VecDeque::new(),
                indirect_cache: None,
            }),
            per_group_alloc,
            dentry_cache_hits: AtomicUsize::new(0),
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
        // Build per-group alloc locks (test path — same as production).
        let mut per_group_alloc = Vec::with_capacity(num_groups as usize);
        for _ in 0..num_groups {
            per_group_alloc.push(Mutex::new(()));
        }
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
            state: Mutex::new(Ext2State {
                superblock: sb,
                bgdt,
                dentry_map: BTreeMap::new(),
                dentry_fifo: VecDeque::new(),
                indirect_cache: None,
            }),
            per_group_alloc,
            dentry_cache_hits: AtomicUsize::new(0),
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
    ///
    /// Physically-contiguous logical blocks are coalesced into a single
    /// multi-sector block-device transfer.  This is the dominant latency cost
    /// on the demand-fault / shared-library load path: a sequential read of an
    /// N-page run (e.g. the dynamic loader walking a shared object's
    /// PROT_READ|PROT_EXEC segment during relocation) that previously issued
    /// one block-device request per filesystem block now issues one request per
    /// physically-contiguous extent.  For a well-laid-out file the whole run is
    /// a single extent, collapsing N round-trips into one — see mmap(2) /
    /// madvise(2) MADV_SEQUENTIAL for the conceptual access pattern this
    /// optimises.
    ///
    /// Behaviour is byte-for-byte identical to the per-block loop it replaces:
    /// sparse blocks still read as zero, the result is still clamped to EOF
    /// (`i_size`), and a block-device error still yields a short read.
    fn read_inode_data(&self, inode: &Ext2Inode, offset: u64, buf: &mut [u8]) -> usize {
        let file_size = inode.size as u64;
        if offset >= file_size { return 0; }

        let bs = self.block_size as u64;
        let to_read = buf.len().min((file_size - offset) as usize);
        let mut read_total = 0usize;
        // Bounce buffer for the unaligned head/tail of a transfer (a partial
        // block at either edge that cannot be read straight into `buf`).
        let mut block_buf = alloc::vec![0u8; self.block_size];

        while read_total < to_read {
            let pos = offset + read_total as u64;
            let block_idx = (pos / bs) as usize;
            let off_in_block = (pos % bs) as usize;

            let block_num = self.resolve_block(inode, block_idx);

            // Sparse block (hole) — fill with zeros, no device I/O.
            if block_num == 0 {
                let n = (self.block_size - off_in_block).min(to_read - read_total);
                buf[read_total..read_total + n].fill(0);
                read_total += n;
                continue;
            }

            // Fast path: a block-aligned position with at least one whole block
            // left to read.  Greedily extend the run across physically
            // contiguous blocks and issue ONE multi-sector device read straight
            // into the caller's buffer (no bounce copy).  The run breaks at the
            // first hole, the first non-contiguous block, or end-of-request.
            if off_in_block == 0 && (to_read - read_total) >= self.block_size {
                // Cap the coalesced run so the sector count fits the device
                // request ABI (u16 sectors) with margin: 512 sectors = 256 KiB
                // at 1 KiB blocks, comfortably larger than the 128 KiB
                // demand-fault readahead window while staying well inside u16.
                const MAX_RUN_SECTORS: usize = 512;
                let sectors_per_block_usz = (self.block_size / 512).max(1);
                let max_run_by_sectors = MAX_RUN_SECTORS / sectors_per_block_usz;
                let max_whole_blocks =
                    ((to_read - read_total) / self.block_size).min(max_run_by_sectors.max(1));
                let mut run_blocks = 1usize;
                while run_blocks < max_whole_blocks {
                    let next = self.resolve_block(inode, block_idx + run_blocks);
                    // Stop at a hole or a discontinuity; both are serviced by a
                    // fresh iteration of the outer loop.
                    if next == 0 || next != block_num + run_blocks as u32 {
                        break;
                    }
                    run_blocks += 1;
                }
                let run_bytes = run_blocks * self.block_size;
                let sectors_per_block = (self.block_size / 512) as u64;
                let start_sector = block_num as u64 * sectors_per_block;
                let sector_count = (run_blocks as u64 * sectors_per_block) as u16;
                let dst = &mut buf[read_total..read_total + run_bytes];
                if self.read_sectors_inner(start_sector, sector_count, dst).is_err() {
                    break;
                }
                read_total += run_bytes;
                continue;
            }

            // Slow path: unaligned head/tail — read one block through the
            // bounce buffer and copy the overlapping window.
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
    ///
    /// Uses the single-entry indirect-block cache in `Ext2State` (PR-E).
    /// When the same indirect block is read repeatedly — the common case for
    /// a sequential read of a file > 48 KiB — each pointer lookup hits the
    /// cache rather than issuing a fresh disk read, eliminating the ~256×
    /// redundant I/O noted in the audit §6 "Indirect block re-reading".
    fn read_indirect(&self, block_num: u32, index: usize) -> u32 {
        if block_num == 0 { return 0; }
        // Fast path: hit the per-FS indirect-block cache.
        {
            let state = self.state.lock();
            if let Some((cached_block, ref cached_data)) = state.indirect_cache {
                if cached_block == block_num {
                    let off = index * 4;
                    if off + 4 <= cached_data.len() {
                        return u32::from_le_bytes([
                            cached_data[off], cached_data[off+1],
                            cached_data[off+2], cached_data[off+3],
                        ]);
                    }
                }
            }
        }
        // Miss: read the block and populate the cache.
        let mut buf = alloc::vec![0u8; self.block_size];
        if self.read_block(block_num, &mut buf).is_err() { return 0; }
        let result = {
            let off = index * 4;
            if off + 4 <= buf.len() {
                u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
            } else { 0 }
        };
        // Store in cache.
        {
            let mut state = self.state.lock();
            state.indirect_cache = Some((block_num, buf));
        }
        result
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
    ///
    /// # SMP correctness (PR-E)
    ///
    /// PR-B allocated with a drop-lock-across-I/O pattern that left a
    /// window where two CPUs could independently read the same bitmap byte,
    /// find the same free bit, and allocate the same block number.
    ///
    /// PR-E fixes this by holding the per-group lock (`self.per_group_alloc[group]`)
    /// across the entire read–set–write sequence for the bitmap.  The global
    /// state lock is still used for the BGDT free-count checks and updates;
    /// it is dropped across the I/O to avoid holding it during disk access.
    /// The protocol is:
    ///
    /// 1. Hold state lock: check global + group free count.  Release.
    /// 2. Acquire per-group alloc lock.
    /// 3. (Re)read the bitmap while holding the per-group lock.
    /// 4. Find and set a free bit while holding the per-group lock.
    /// 5. Write the bitmap back while holding the per-group lock.
    /// 6. Release per-group lock.
    /// 7. Acquire state lock: update BGDT + superblock counters.  Release.
    /// 8. Flush BGDT + superblock to disk.
    ///
    /// Steps 3–5 are serialised per-group; different groups can run in
    /// parallel.  The re-read in step 3 means a CPU that queued behind
    /// another on the same group always sees the post-commit bitmap.
    fn alloc_block(&self) -> Option<u32> {
        // Quick global check before taking any per-group lock.
        {
            let state = self.state.lock();
            if state.superblock.free_blocks_count == 0 { return None; }
        }
        let num_groups = self.num_groups as usize;
        for group in 0..num_groups {
            // Fast per-group free-count check (no I/O yet).
            let bitmap_block = {
                let state = self.state.lock();
                if state.bgdt[group].free_blocks_count == 0 { continue; }
                state.bgdt[group].block_bitmap
            };

            // Acquire the per-group alloc lock.  This serialises the
            // read-find-set-write bitmap sequence within this group.
            let _group_guard = self.per_group_alloc[group].lock();

            // Re-read the bitmap under the per-group lock so we see any
            // writes committed by a racing allocator that held this lock
            // before us.
            let mut bitmap = alloc::vec![0u8; self.block_size];
            if self.read_block(bitmap_block, &mut bitmap).is_err() {
                continue;
            }

            // Scan for a free bit within blocks_per_group.
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
            let Some(bit_idx) = chosen else { continue; };

            // Set the bit and write the bitmap back — still under the
            // per-group lock, so no other CPU can pick this bit.
            let byte_idx = bit_idx / 8;
            let bit_off = bit_idx % 8;
            bitmap[byte_idx] |= 1 << bit_off;
            if self.write_block(bitmap_block, &bitmap).is_err() {
                continue;
            }
            // Per-group lock can be released here; the bit is on disk.
            drop(_group_guard);

            // Compute the absolute block number.
            let block_num = self.superblock.first_data_block
                + (group as u32) * self.superblock.blocks_per_group
                + bit_idx as u32;

            // Zero the new block — POSIX ftruncate / lseek+write semantics
            // require that newly-allocated tail bytes read as zero.
            let zero = alloc::vec![0u8; self.block_size];
            let _ = self.write_block(block_num, &zero);

            // Update BGDT + superblock counters (state lock).
            let (bgd_snap, sb_snap) = {
                let mut state = self.state.lock();
                // Re-check after the I/O: another CPU may have exhausted
                // this group while we were writing.  Accept if it was > 0
                // when we committed the bitmap.
                state.bgdt[group].free_blocks_count =
                    state.bgdt[group].free_blocks_count.saturating_sub(1);
                state.superblock.free_blocks_count =
                    state.superblock.free_blocks_count.saturating_sub(1);
                (state.bgdt[group], state.superblock)
            };
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
    ///
    /// Uses the same per-group lock protocol as [`Self::alloc_block`]
    /// (PR-E SMP fix): reads, finds, and sets the bitmap bit while holding
    /// the per-group alloc lock, eliminating the concurrent-allocation race
    /// window that existed in PR-B.
    #[allow(dead_code)]
    pub(crate) fn alloc_inode(&self, is_dir: bool) -> Option<u32> {
        let first_ino = if self.superblock.rev_level >= 1 {
            self.superblock.first_ino
        } else {
            11 // Rev 0 reserves inodes 1..11.
        };
        let inodes_per_group = self.superblock.inodes_per_group as usize;
        let num_groups = self.num_groups as usize;
        {
            let state = self.state.lock();
            if state.superblock.free_inodes_count == 0 { return None; }
        }
        for group in 0..num_groups {
            let bitmap_block = {
                let state = self.state.lock();
                if state.bgdt[group].free_inodes_count == 0 { continue; }
                state.bgdt[group].inode_bitmap
            };

            // Per-group lock: serialises inode bitmap R-M-W within this group.
            let _group_guard = self.per_group_alloc[group].lock();

            let mut bitmap = alloc::vec![0u8; self.block_size];
            if self.read_block(bitmap_block, &mut bitmap).is_err() { continue; }

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
            let Some(bit_idx) = chosen else { continue; };

            let byte_idx = bit_idx / 8;
            let bit_off = bit_idx % 8;
            bitmap[byte_idx] |= 1 << bit_off;
            if self.write_block(bitmap_block, &bitmap).is_err() { continue; }
            let inum = (group as u32 * self.superblock.inodes_per_group)
                + bit_idx as u32 + 1;
            drop(_group_guard);

            let (bgd_snap, sb_snap) = {
                let mut state = self.state.lock();
                state.bgdt[group].free_inodes_count =
                    state.bgdt[group].free_inodes_count.saturating_sub(1);
                if is_dir { state.bgdt[group].used_dirs_count += 1; }
                state.superblock.free_inodes_count =
                    state.superblock.free_inodes_count.saturating_sub(1);
                (state.bgdt[group], state.superblock)
            };
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
    ///
    /// Also invalidates the single-entry indirect-block cache (PR-E) so a
    /// subsequent `read_indirect` on the same block sees the updated value
    /// rather than a stale cache entry.
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
        self.write_block(block_num, &buf)?;
        // Invalidate: either evict or update the cache entry for this block.
        {
            let mut state = self.state.lock();
            match &mut state.indirect_cache {
                Some((cached_block, _)) if *cached_block == block_num => {
                    state.indirect_cache = None;
                }
                _ => {}
            }
        }
        Ok(())
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

    // ────────────────────────────────────────────────────────────────────────
    // Directory mutation (PR-C, 2026-05-24).
    //
    // Directory-block layout follows ext2 spec §3 "Linked directory entries".
    // Each directory block is a logically independent linked list of
    // variable-length entries.  The final entry's `rec_len` extends to the
    // end of the block; insertion either splits the final entry's slack (if
    // it can accommodate a new entry plus the existing entry's true size) or
    // re-uses an existing inode==0 entry whose `rec_len` is large enough.
    // Removal merges the dead entry's space into the preceding entry's
    // `rec_len` (or, for the first entry in a block, marks `inode = 0` and
    // keeps `rec_len` unchanged so the linked-list walk can step past it).
    //
    // All routines below mutate the parent directory's data blocks via the
    // existing `ensure_block` / `read_block` / `write_block` substrate from
    // PR-B and keep `i_size` aligned with the directory's allocated block
    // count (each directory block is fully owned by the directory; spec §3).
    // ────────────────────────────────────────────────────────────────────────

    /// Initialise a fresh directory block containing `.` and `..` entries.
    ///
    /// Per the spec a newly-empty directory has exactly two records:
    /// `(inode=self_ino, name=".", rec_len = REC_LEN(1))` followed by
    /// `(inode=parent_ino, name="..", rec_len = block_size - REC_LEN(1))`.
    /// The second entry's `rec_len` extends to the end of the block so the
    /// linked-list walk reaches block-end correctly.
    fn init_dir_block(&self, buf: &mut [u8], self_ino: u32, parent_ino: u32) {
        debug_assert_eq!(buf.len(), self.block_size);
        for byte in buf.iter_mut() { *byte = 0; }
        let dot_reclen = ext2_dir_rec_len(1);
        let dotdot_reclen = self.block_size - dot_reclen;

        // `.` entry
        buf[0..4].copy_from_slice(&self_ino.to_le_bytes());
        buf[4..6].copy_from_slice(&(dot_reclen as u16).to_le_bytes());
        buf[6] = 1; // name_len
        buf[7] = EXT2_FT_DIR;
        buf[8] = b'.';
        // bytes 9..dot_reclen are zero-padded (already memset above).

        // `..` entry
        let off = dot_reclen;
        buf[off..off + 4].copy_from_slice(&parent_ino.to_le_bytes());
        buf[off + 4..off + 6].copy_from_slice(&(dotdot_reclen as u16).to_le_bytes());
        buf[off + 6] = 2; // name_len
        buf[off + 7] = EXT2_FT_DIR;
        buf[off + 8] = b'.';
        buf[off + 9] = b'.';
        // bytes [off+10..] zero-padded.
    }

    /// Insert a new entry `(child_ino, name, file_type)` into the parent
    /// directory.  Walks the parent's data blocks looking for a slot:
    ///
    /// 1. **Empty slot reuse** — an existing `inode == 0` entry whose
    ///    `rec_len ≥ needed` is repurposed wholesale.
    /// 2. **Slack split** — an entry whose `rec_len - REC_LEN(name_len)`
    ///    is at least `needed` gives up its trailing slack to the new
    ///    entry.  The old entry's `rec_len` shrinks to its minimum
    ///    (`REC_LEN(name_len)`); the new entry's `rec_len` consumes the
    ///    rest of what the old entry held.
    /// 3. **New block** — if no slot in any existing block fits, allocate
    ///    a fresh data block via [`Self::ensure_block`], place the new
    ///    entry at offset 0 with `rec_len = block_size`, and grow
    ///    `i_size` by `block_size`.
    ///
    /// Mutates `parent_inode` in place (the caller observes any `i_size`
    /// or `i_block[]` changes from path 3).  Persistence of `parent_inode`
    /// is the caller's responsibility (call [`Self::write_inode`]).
    ///
    /// Returns `Err` on I/O failure or duplicate-name (`EEXIST`).
    fn insert_dir_entry(&self, parent_inode: &mut Ext2Inode, parent_ino_num: u64,
                        name: &str, child_ino: u32, child_file_type: u8)
        -> Result<(), VfsError>
    {
        if name.is_empty() || name.len() > 255 || name.contains('/') || name == "." || name == ".." {
            return Err(VfsError::InvalidArg);
        }
        let name_bytes = name.as_bytes();
        let needed = ext2_dir_rec_len(name_bytes.len());
        if needed > self.block_size {
            return Err(VfsError::InvalidArg);
        }

        let bs = self.block_size;
        let dir_size = parent_inode.size as usize;
        let num_blocks = dir_size / bs; // directory blocks are full-block records
        let mut block_buf = alloc::vec![0u8; bs];

        // Pass 1 — walk existing blocks for a slot, and check for duplicate.
        for blk_idx in 0..num_blocks {
            let phys = self.resolve_block(parent_inode, blk_idx);
            if phys == 0 { continue; } // sparse — skip for insertion search
            if self.read_block(phys, &mut block_buf).is_err() {
                return Err(VfsError::Io);
            }

            // Walk entries in this block. We need both "is duplicate" and
            // "where to insert" knowledge, so collect candidate slot info
            // as we go.  Slot priority is: dead entry first, then a split.
            let mut offset = 0usize;
            let mut slot: Option<(usize, bool, usize)> = None; // (offset, is_dead, fitted_split_size)
            while offset + EXT2_DIR_HDR <= bs {
                let entry_inode = u32::from_le_bytes([
                    block_buf[offset], block_buf[offset+1],
                    block_buf[offset+2], block_buf[offset+3]]);
                let rec_len = u16::from_le_bytes(
                    [block_buf[offset+4], block_buf[offset+5]]) as usize;
                let nm_len = block_buf[offset+6] as usize;
                if rec_len < EXT2_DIR_HDR || rec_len & 3 != 0
                    || offset + rec_len > bs
                {
                    // Treat malformed dir as fatal — corruption.
                    crate::serial_println!(
                        "[EXT2] insert_dir_entry: malformed entry blk_idx={} off={} rec_len={}",
                        blk_idx, offset, rec_len);
                    return Err(VfsError::Io);
                }
                // Duplicate-name check (POSIX EEXIST).
                if entry_inode != 0 && nm_len == name_bytes.len() {
                    let on_disk = &block_buf[offset + EXT2_DIR_HDR
                        ..offset + EXT2_DIR_HDR + nm_len];
                    if on_disk == name_bytes {
                        return Err(VfsError::FileExists);
                    }
                }
                // Slot candidates.
                if slot.is_none() {
                    if entry_inode == 0 && rec_len >= needed {
                        slot = Some((offset, true, rec_len));
                    } else if entry_inode != 0 {
                        let used = ext2_dir_rec_len(nm_len);
                        if rec_len >= used + needed {
                            slot = Some((offset, false, used));
                        }
                    }
                }
                offset += rec_len;
            }

            if let Some((slot_off, is_dead, fitted)) = slot {
                // Apply placement.
                if is_dead {
                    // Reuse: keep rec_len, overwrite header + name.
                    let kept_reclen = u16::from_le_bytes(
                        [block_buf[slot_off+4], block_buf[slot_off+5]]) as usize;
                    write_dir_entry(&mut block_buf, slot_off,
                        child_ino, kept_reclen,
                        name_bytes, child_file_type);
                } else {
                    // Split: shrink existing entry's rec_len to its minimum,
                    // place new entry in the released tail.
                    let old_reclen = u16::from_le_bytes(
                        [block_buf[slot_off+4], block_buf[slot_off+5]]) as usize;
                    let new_off = slot_off + fitted;
                    let new_reclen = old_reclen - fitted;
                    // Patch the predecessor's rec_len.
                    block_buf[slot_off+4..slot_off+6]
                        .copy_from_slice(&(fitted as u16).to_le_bytes());
                    write_dir_entry(&mut block_buf, new_off,
                        child_ino, new_reclen,
                        name_bytes, child_file_type);
                }
                if self.write_block(phys, &block_buf).is_err() {
                    return Err(VfsError::Io);
                }
                return Ok(());
            }
        }

        // Pass 2 — no existing block had room.  Allocate one new block,
        // initialise it with a single entry spanning the whole block, and
        // extend `i_size` accordingly.
        let new_block_idx = num_blocks;
        let phys = self.ensure_block(parent_inode, new_block_idx)
            .ok_or(VfsError::Io)?;
        for byte in block_buf.iter_mut() { *byte = 0; }
        write_dir_entry(&mut block_buf, 0, child_ino, bs,
            name_bytes, child_file_type);
        if self.write_block(phys, &block_buf).is_err() {
            return Err(VfsError::Io);
        }
        // Grow i_size by one block.  Directory size is always a multiple
        // of the FS block size (spec §3.1).
        let new_size = (dir_size + bs) as u64;
        if new_size > u32::MAX as u64 {
            return Err(VfsError::Io);
        }
        parent_inode.size = new_size as u32;
        parent_inode.mtime = current_unix_time();
        // Persist parent inode now — the cooperating caller's write_inode
        // is also safe but doing it here keeps `i_blocks` / `i_size` in
        // sync after the ensure_block above.
        self.write_inode(parent_ino_num, parent_inode)
            .map_err(|_| VfsError::Io)?;
        Ok(())
    }

    /// Remove the directory entry named `name` from the parent directory.
    /// Returns the inode number that the dead entry pointed at, so the
    /// caller can decrement that inode's `i_links_count`.
    ///
    /// Coalescing strategy per ext2 spec §3 "Linked directory entries":
    ///
    /// * If the entry is preceded by another entry in the same block, the
    ///   predecessor's `rec_len` absorbs the removed entry's `rec_len`
    ///   (the linked-list walk skips over the gap).
    /// * If the entry is the FIRST entry in its block (no predecessor in
    ///   the same block), the entry's `inode` field is set to 0 and its
    ///   `rec_len` is left unchanged — the walk steps past the dead slot.
    ///
    /// Directories never shrink (we do not free the trailing block even
    /// if every entry in it has been removed) — matches Linux's ext2
    /// implementation and keeps the indirect tree stable.
    fn remove_dir_entry(&self, parent_inode: &Ext2Inode, name: &str)
        -> Result<u32, VfsError>
    {
        if name.is_empty() || name == "." || name == ".." {
            return Err(VfsError::InvalidArg);
        }
        let name_bytes = name.as_bytes();
        let bs = self.block_size;
        let dir_size = parent_inode.size as usize;
        let num_blocks = dir_size / bs;
        let mut block_buf = alloc::vec![0u8; bs];

        for blk_idx in 0..num_blocks {
            let phys = self.resolve_block(parent_inode, blk_idx);
            if phys == 0 { continue; }
            if self.read_block(phys, &mut block_buf).is_err() {
                return Err(VfsError::Io);
            }
            let mut offset = 0usize;
            let mut prev_offset: Option<usize> = None;
            while offset + EXT2_DIR_HDR <= bs {
                let entry_inode = u32::from_le_bytes([
                    block_buf[offset], block_buf[offset+1],
                    block_buf[offset+2], block_buf[offset+3]]);
                let rec_len = u16::from_le_bytes(
                    [block_buf[offset+4], block_buf[offset+5]]) as usize;
                let nm_len = block_buf[offset+6] as usize;
                if rec_len < EXT2_DIR_HDR || rec_len & 3 != 0
                    || offset + rec_len > bs
                {
                    return Err(VfsError::Io);
                }
                if entry_inode != 0 && nm_len == name_bytes.len() {
                    let on_disk = &block_buf[offset + EXT2_DIR_HDR
                        ..offset + EXT2_DIR_HDR + nm_len];
                    if on_disk == name_bytes {
                        // Found.
                        let dead_ino = entry_inode;
                        if let Some(po) = prev_offset {
                            // Coalesce into predecessor.
                            let prev_reclen = u16::from_le_bytes(
                                [block_buf[po+4], block_buf[po+5]]) as usize;
                            let new_prev = prev_reclen + rec_len;
                            block_buf[po+4..po+6]
                                .copy_from_slice(&(new_prev as u16).to_le_bytes());
                        } else {
                            // First entry: mark inode=0, keep rec_len.
                            block_buf[offset..offset+4].fill(0);
                            // Clear name_len so a stale-name scan can't match.
                            block_buf[offset+6] = 0;
                            block_buf[offset+7] = 0;
                        }
                        if self.write_block(phys, &block_buf).is_err() {
                            return Err(VfsError::Io);
                        }
                        return Ok(dead_ino);
                    }
                }
                prev_offset = Some(offset);
                offset += rec_len;
            }
        }
        Err(VfsError::NotFound)
    }

    /// Check whether the directory inode has any entries other than `.`
    /// and `..`.  Used to enforce POSIX `rmdir(2)` ENOTEMPTY.
    fn dir_is_empty(&self, inode: &Ext2Inode) -> bool {
        let entries = self.read_dir_entries(inode);
        for (_, name, _) in entries {
            if name != "." && name != ".." {
                return false;
            }
        }
        true
    }

    /// Tear down an inode after its last directory link is gone.  Frees
    /// all allocated data + indirect blocks, sets `i_dtime`, and clears
    /// the inode bitmap bit (releasing the inode number for reuse).
    ///
    /// Used by [`FileSystemOps::remove_inode`] when `i_links_count` drops
    /// to 0 and no fds reference the inode.
    fn destroy_inode(&self, inode_num: u64, mut inode: Ext2Inode)
        -> Result<(), &'static str>
    {
        let was_dir = (inode.mode & S_IFMT) == S_IFDIR;
        // Free all data blocks first.  For regular files this walks the
        // direct + indirect tree; for symlinks we may have a slow-link
        // tail (fast symlinks have inode.blocks == 0 and the loop is a
        // no-op).  For directories we free every block they own.
        self.free_blocks_from(&mut inode, 0);
        // Mark dtime + clear mode so e2fsck recognises the slot as free.
        inode.dtime = current_unix_time();
        inode.size = 0;
        inode.links_count = 0;
        self.write_inode(inode_num, &inode)?;
        // Finally release the inode-bitmap bit.
        self.free_inode(inode_num as u32, was_dir);
        Ok(())
    }

    /// Internal helper for create_file / create_dir: build a freshly-
    /// initialised inode with the given mode bits.  Timestamps are set
    /// from the live RTC; uid / gid default to 0 (root) — PR-C does not
    /// thread per-process credentials through the create path.
    fn make_new_inode(&self, mode: u16, links_count: u16) -> Ext2Inode {
        let t = current_unix_time();
        Ext2Inode {
            mode,
            uid: 0,
            size: 0,
            atime: t,
            ctime: t,
            mtime: t,
            dtime: 0,
            gid: 0,
            links_count,
            blocks: 0,
            flags: 0,
            osd1: 0,
            block: [0; 15],
            generation: 0,
            file_acl: 0,
            dir_acl: 0,
            faddr: 0,
            osd2: [0; 12],
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

    // ────────────────────────────────────────────────────────────────────────
    // Per-directory dentry cache (PR-E).
    //
    // The hot path in Firefox boot is a dlopen cascade: the dynamic linker
    // calls lookup() once per entry in the DT_NEEDED closure (~100 names)
    // against the same parent directory (/usr/lib or /usr/lib/firefox).
    // Without a cache, each call runs read_dir_entries() from scratch —
    // allocating a full-directory Vec<u8> and scanning every dir-entry.
    //
    // The cache maps (parent_inode, name) → child_inode and is bounded at
    // DENTRY_CACHE_CAP entries with FIFO eviction.  The cache is stored in
    // Ext2State (protected by the state mutex) to avoid a second lock and
    // the associated deadlock risk; the mutex is held for the duration of
    // the cache lookup, which is just a BTreeMap::get — a few hundred
    // nanoseconds, well below any preemption threshold.
    // ────────────────────────────────────────────────────────────────────────

    /// Insert a (parent, name) → child mapping into the dentry cache.
    /// If the cache is at capacity, the oldest entry is evicted (FIFO).
    fn dentry_cache_insert(&self, parent: u64, name: &str, child: u64) {
        let mut state = self.state.lock();
        // Evict if at capacity.
        if state.dentry_map.len() >= DENTRY_CACHE_CAP {
            if let Some(oldest) = state.dentry_fifo.pop_front() {
                state.dentry_map.remove(&oldest);
            }
        }
        let key = (parent, name.to_string());
        // Only insert if not already present (avoid duplicate FIFO entries).
        if state.dentry_map.insert(key.clone(), child).is_none() {
            state.dentry_fifo.push_back(key);
        }
    }

    /// Look up a name in the dentry cache.  Returns `Some(inode)` on hit.
    fn dentry_cache_lookup(&self, parent: u64, name: &str) -> Option<u64> {
        let state = self.state.lock();
        let result = state.dentry_map.get(&(parent, name.to_string())).copied();
        drop(state);
        if result.is_some() {
            self.dentry_cache_hits.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Evict all dentry-cache entries whose parent inode matches `parent`.
    /// Called after any mutation to the directory (create, unlink, rename)
    /// so the cache cannot serve stale positive entries.
    fn dentry_cache_evict_parent(&self, parent: u64) {
        let mut state = self.state.lock();
        let old_len = state.dentry_map.len();
        if old_len == 0 { return; }
        // Collect keys to remove (can't mutate while iterating).
        let to_remove: Vec<_> = state.dentry_map.keys()
            .filter(|(p, _)| *p == parent)
            .cloned()
            .collect();
        for k in &to_remove {
            state.dentry_map.remove(k);
        }
        // Rebuild FIFO to remove the evicted entries.  This is O(n) where
        // n = FIFO length (bounded by DENTRY_CACHE_CAP = 1024), so it is
        // fine on the infrequent mutation path.
        if !to_remove.is_empty() {
            let remove_set: BTreeMap<_, ()> =
                to_remove.iter().map(|k| (k.clone(), ())).collect();
            state.dentry_fifo.retain(|k| !remove_set.contains_key(k));
        }
    }

    /// Test-only accessor: current dentry-cache hit counter.
    #[doc(hidden)]
    pub fn dentry_cache_hits_for_test(&self) -> usize {
        self.dentry_cache_hits.load(Ordering::Relaxed)
    }

    /// Test-only accessor: current dentry-cache size.
    #[doc(hidden)]
    pub fn dentry_cache_size_for_test(&self) -> usize {
        self.state.lock().dentry_map.len()
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
use crate::vfs::{FileSystemOps, FileStat, FileType, VfsResult};

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
        // Hot path: dentry cache hit avoids a full directory scan (PR-E).
        if let Some(child) = self.dentry_cache_lookup(parent_inode, name) {
            return Ok(child);
        }
        // Cache miss: fall through to linear scan.
        let ino = self.read_inode(parent_inode).ok_or(VfsError::NotFound)?;
        let entries = self.read_dir_entries(&ino);
        for (entry_ino, entry_name, _) in entries {
            if entry_name == name {
                let child = entry_ino as u64;
                // Populate cache on successful lookup.
                self.dentry_cache_insert(parent_inode, name, child);
                return Ok(child);
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

    fn create_file(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        // POSIX open(2) O_CREAT semantics: parent must be a directory; the
        // resulting inode is a regular file with i_mode = S_IFREG | 0o644
        // (the kernel applies umask at the syscall layer — we hand back
        // raw 0644 here and let the personality layer mask later).
        let mut parent = self.read_inode(parent_inode).ok_or(VfsError::NotFound)?;
        if (parent.mode & S_IFMT) != S_IFDIR {
            return Err(VfsError::NotADirectory);
        }
        let new_ino = self.alloc_inode(false).ok_or(VfsError::NoSpace)?;
        let inode = self.make_new_inode(S_IFREG | 0o644, 1);
        self.write_inode(new_ino as u64, &inode)
            .map_err(|_| VfsError::Io)?;
        // Insert the dir-entry.  On failure we must roll back the inode
        // allocation so we don't leak the bitmap bit.
        match self.insert_dir_entry(&mut parent, parent_inode, name,
            new_ino, EXT2_FT_REG_FILE)
        {
            Ok(()) => {
                // insert_dir_entry persists `parent` only when it had to
                // grow into a new block; for the in-place split / reuse
                // paths we still need to bump parent's mtime/ctime.  Do
                // a single defensive write — duplicate writes are
                // idempotent (RMW touches the same 512-byte sector).
                let t = current_unix_time();
                parent.mtime = t;
                parent.ctime = t;
                let _ = self.write_inode(parent_inode, &parent);
                // Evict stale dentry-cache entries for this parent (PR-E).
                self.dentry_cache_evict_parent(parent_inode);
                Ok(new_ino as u64)
            }
            Err(e) => {
                self.free_inode(new_ino, false);
                Err(e)
            }
        }
    }

    fn create_dir(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        // POSIX mkdir(2): allocate inode, allocate one data block for the
        // initial `.`/`..` entries, link into parent.  i_links_count starts
        // at 2 (the `.` self-link plus the parent's name→inode link) per
        // spec §3.1 "Linked directory entries".
        let mut parent = self.read_inode(parent_inode).ok_or(VfsError::NotFound)?;
        if (parent.mode & S_IFMT) != S_IFDIR {
            return Err(VfsError::NotADirectory);
        }
        let new_ino = self.alloc_inode(true).ok_or(VfsError::NoSpace)?;
        let mut inode = self.make_new_inode(S_IFDIR | 0o755, 2);
        // Allocate the directory's first data block via ensure_block.
        // This populates inode.block[0] and i_blocks; size is updated by
        // hand to one full block.
        let bs = self.block_size;
        let first_block = match self.ensure_block(&mut inode, 0) {
            Some(b) => b,
            None => {
                self.free_inode(new_ino, true);
                return Err(VfsError::NoSpace);
            }
        };
        inode.size = bs as u32;
        // Write `.`/`..` into the new block.
        let mut block_buf = alloc::vec![0u8; bs];
        self.init_dir_block(&mut block_buf, new_ino, parent_inode as u32);
        if self.write_block(first_block, &block_buf).is_err() {
            // Best-effort rollback: free the block and the inode.
            self.free_block(first_block);
            self.free_inode(new_ino, true);
            return Err(VfsError::Io);
        }
        if self.write_inode(new_ino as u64, &inode).is_err() {
            self.free_block(first_block);
            self.free_inode(new_ino, true);
            return Err(VfsError::Io);
        }
        // Link into parent.
        match self.insert_dir_entry(&mut parent, parent_inode, name,
            new_ino, EXT2_FT_DIR)
        {
            Ok(()) => {
                // Bump parent's links_count by 1 for the new child's `..`
                // back-reference, plus mtime/ctime.
                let t = current_unix_time();
                parent.links_count = parent.links_count.saturating_add(1);
                parent.mtime = t;
                parent.ctime = t;
                let _ = self.write_inode(parent_inode, &parent);
                // Evict stale dentry-cache entries for this parent (PR-E).
                self.dentry_cache_evict_parent(parent_inode);
                Ok(new_ino as u64)
            }
            Err(e) => {
                // Roll back the child inode + block.
                let inode_copy = inode;
                let _ = self.destroy_inode(new_ino as u64, inode_copy);
                Err(e)
            }
        }
    }

    fn remove(&self, parent_inode: u64, name: &str) -> VfsResult<()> {
        // POSIX-style combined unlink: look up the target so we can decide
        // between rmdir(2) (ENOTEMPTY check + parent links_count decrement)
        // and unlink(2) (regular-file or symlink path).  Then run the
        // unlink_entry / remove_inode pair atomically.
        let parent = self.read_inode(parent_inode).ok_or(VfsError::NotFound)?;
        if (parent.mode & S_IFMT) != S_IFDIR {
            return Err(VfsError::NotADirectory);
        }
        // Find target.
        let target_ino = {
            let entries = self.read_dir_entries(&parent);
            entries.into_iter()
                .find(|(_, n, _)| n == name)
                .map(|(i, _, _)| i as u64)
                .ok_or(VfsError::NotFound)?
        };
        let target = self.read_inode(target_ino).ok_or(VfsError::NotFound)?;
        let is_dir = (target.mode & S_IFMT) == S_IFDIR;
        if is_dir && !self.dir_is_empty(&target) {
            return Err(VfsError::NotEmpty);
        }
        // 1) Remove dir-entry.
        self.unlink_entry(parent_inode, name)?;
        // 2) Free inode if no more refs (PR-C does not maintain an
        // in-memory open-fd ref-count; we conservatively free immediately,
        // matching the inline-unlink behaviour POSIX requires when no fd
        // is open on the target.  Open-fd retention is a VFS-layer concern
        // outside this FS driver.)
        self.remove_inode(target_ino)
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

    fn unlink_entry(&self, parent_inode: u64, name: &str) -> VfsResult<()> {
        // POSIX unlink(2) split form: remove the name→inode binding from
        // the parent directory but leave the target inode in place; the
        // VFS layer calls `remove_inode` once all open fds are closed.
        // Decrements the target's `i_links_count`.  For directories the
        // parent's `i_links_count` is also decremented (the child's `..`
        // back-link is going away).
        let parent = self.read_inode(parent_inode).ok_or(VfsError::NotFound)?;
        if (parent.mode & S_IFMT) != S_IFDIR {
            return Err(VfsError::NotADirectory);
        }
        let dead_ino = self.remove_dir_entry(&parent, name)?;
        // Evict dentry-cache entries for this parent (PR-E).
        self.dentry_cache_evict_parent(parent_inode);
        // Decrement target's links_count.
        if let Some(mut target) = self.read_inode(dead_ino as u64) {
            target.links_count = target.links_count.saturating_sub(1);
            target.ctime = current_unix_time();
            let _ = self.write_inode(dead_ino as u64, &target);
            // Directory case: parent loses one ref from the child's `..`.
            if (target.mode & S_IFMT) == S_IFDIR {
                if let Some(mut p) = self.read_inode(parent_inode) {
                    p.links_count = p.links_count.saturating_sub(1);
                    p.mtime = current_unix_time();
                    p.ctime = p.mtime;
                    let _ = self.write_inode(parent_inode, &p);
                }
            } else {
                if let Some(mut p) = self.read_inode(parent_inode) {
                    p.mtime = current_unix_time();
                    p.ctime = p.mtime;
                    let _ = self.write_inode(parent_inode, &p);
                }
            }
        }
        Ok(())
    }

    fn remove_inode(&self, inode: u64) -> VfsResult<()> {
        // Final teardown — called after the last open fd is closed.  If
        // `i_links_count` is still > 0 the inode is reachable from some
        // surviving directory entry and we must NOT free it (e.g. a hard-
        // linked file unlinked from one path but still bound to another).
        let ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        if ino.links_count > 0 {
            return Ok(());
        }
        self.destroy_inode(inode, ino).map_err(|e| {
            crate::serial_println!("[EXT2] remove_inode({}) failed: {}", inode, e);
            VfsError::Io
        })
    }

    /// Create a symbolic link in `parent_inode` with name `name` pointing to
    /// `target`.
    ///
    /// The ext2 specification (Stephen Tweedie, *Design and Implementation of
    /// the Second Extended Filesystem*, Annual Linux Expo 1998 — see
    /// <https://www.nongnu.org/ext2-doc/ext2.html#symbolic-links>) defines two
    /// storage encodings:
    ///
    /// * **Fast symlink** (`target.len() ≤ 60`): the target string is stored
    ///   inline in the 15 × 4 = 60-byte `i_block[]` array.  `i_blocks` remains
    ///   0 (no data block allocated); `i_size` is the byte length of the target.
    /// * **Slow symlink** (`target.len() > 60`): a single data block is
    ///   allocated and the target is written there, exactly as a regular file.
    ///
    /// Per POSIX `symlink(2)`, the parent must be a directory and the name
    /// must not already exist.
    fn symlink(&self, parent_inode: u64, name: &str, target: &str) -> VfsResult<u64> {
        let mut parent = self.read_inode(parent_inode).ok_or(VfsError::NotFound)?;
        if (parent.mode & S_IFMT) != S_IFDIR {
            return Err(VfsError::NotADirectory);
        }
        let target_bytes = target.as_bytes();
        if target_bytes.is_empty() || target_bytes.len() > 4095 {
            return Err(VfsError::InvalidArg);
        }
        let new_ino = self.alloc_inode(false).ok_or(VfsError::NoSpace)?;
        let mut inode = self.make_new_inode(S_IFLNK | 0o777, 1);
        inode.size = target_bytes.len() as u32;

        if target_bytes.len() as u64 <= EXT2_FAST_SYMLINK_MAX {
            // Fast symlink: store target inline in i_block[], i_blocks stays 0.
            // i_block[] is treated as a 60-byte raw byte array (not as block
            // pointers) for fast symlinks — see spec §6 "Symbolic links".
            let mut inline_buf = [0u8; 60];
            inline_buf[..target_bytes.len()].copy_from_slice(target_bytes);
            for (i, word) in inode.block.iter_mut().enumerate() {
                let off = i * 4;
                *word = u32::from_le_bytes([
                    inline_buf[off],
                    inline_buf[off + 1],
                    inline_buf[off + 2],
                    inline_buf[off + 3],
                ]);
            }
            // i_blocks is already 0 from make_new_inode.
        } else {
            // Slow symlink: allocate a data block and write the target there.
            let phys = self.ensure_block(&mut inode, 0).ok_or(VfsError::NoSpace)?;
            let mut block_buf = alloc::vec![0u8; self.block_size];
            block_buf[..target_bytes.len()].copy_from_slice(target_bytes);
            self.write_block(phys, &block_buf).map_err(|_| VfsError::Io)?;
        }

        self.write_inode(new_ino as u64, &inode).map_err(|_| VfsError::Io)?;

        match self.insert_dir_entry(&mut parent, parent_inode, name,
            new_ino, EXT2_FT_SYMLINK)
        {
            Ok(()) => {
                let t = current_unix_time();
                parent.mtime = t;
                parent.ctime = t;
                let _ = self.write_inode(parent_inode, &parent);
                // Evict stale dentry-cache entries for this parent (PR-E).
                self.dentry_cache_evict_parent(parent_inode);
                Ok(new_ino as u64)
            }
            Err(e) => {
                self.free_inode(new_ino, false);
                Err(e)
            }
        }
    }

    /// Create a hard link.  Inserts `name` in `parent_inode` pointing at the
    /// same inode as `target_inode`, then increments `i_links_count` on that
    /// inode and updates `i_ctime`.
    ///
    /// Per POSIX `link(2)`: the target must not be a directory (EPERM), and
    /// `name` must not already exist in `parent_inode` (EEXIST from
    /// `insert_dir_entry`).  Incrementing `i_links_count` before inserting
    /// the dir-entry ensures the inode is not freed if a concurrent unlink on
    /// the old name fires between the two steps.
    fn link(&self, target_inode: u64, parent_inode: u64, name: &str) -> VfsResult<()> {
        let mut target = self.read_inode(target_inode).ok_or(VfsError::NotFound)?;
        // POSIX link(2): hard-linking a directory returns EPERM (privilege
        // required, not granted at the FS layer).
        if (target.mode & S_IFMT) == S_IFDIR {
            return Err(VfsError::PermissionDenied);
        }
        let mut parent = self.read_inode(parent_inode).ok_or(VfsError::NotFound)?;
        if (parent.mode & S_IFMT) != S_IFDIR {
            return Err(VfsError::NotADirectory);
        }
        // Bump links_count before inserting the dir-entry so the inode is
        // kept alive even if a concurrent remove fires between the two steps.
        target.links_count = target.links_count.saturating_add(1);
        target.ctime = current_unix_time();
        self.write_inode(target_inode, &target).map_err(|_| VfsError::Io)?;

        let ft = ext2_ft_from_mode(target.mode);
        match self.insert_dir_entry(&mut parent, parent_inode, name,
            target_inode as u32, ft)
        {
            Ok(()) => {
                let t = current_unix_time();
                parent.mtime = t;
                parent.ctime = t;
                let _ = self.write_inode(parent_inode, &parent);
                // Evict stale dentry-cache entries for this parent (PR-E).
                self.dentry_cache_evict_parent(parent_inode);
                Ok(())
            }
            Err(e) => {
                // Roll back the links_count increment.
                if let Some(mut t2) = self.read_inode(target_inode) {
                    t2.links_count = t2.links_count.saturating_sub(1);
                    t2.ctime = current_unix_time();
                    let _ = self.write_inode(target_inode, &t2);
                }
                Err(e)
            }
        }
    }

    /// Rename / move a directory entry.
    ///
    /// The POSIX `rename(2)` contract (POSIX.1-2017 §3 "The rename function"):
    ///
    /// * If `new_name` already exists in `new_parent`, unlink it first
    ///   (for regular files / symlinks: decrement `i_links_count`; for dirs:
    ///   only if empty — ENOTEMPTY otherwise).
    /// * Insert a new dir-entry `new_name → old_inode` in `new_parent`.
    /// * Remove the old dir-entry `old_name` from `old_parent`.
    ///
    /// Cross-directory rename: both parent inodes are mutated.  If the
    /// renamed entry is a directory, its `..` entry's inode number is updated
    /// to reflect the new parent, `old_parent.i_links_count` is decremented,
    /// and `new_parent.i_links_count` is incremented.
    ///
    /// This implementation is not atomic across a power failure (ext2 has no
    /// journal), but the sequence — unlink new, insert new, remove old — is
    /// crash-consistent under `e2fsck -fy` because each step is a single
    /// idempotent directory block write.
    fn rename(&self, old_parent: u64, old_name: &str,
              new_parent: u64, new_name: &str) -> VfsResult<()> {
        // Locate the inode being moved.
        let old_p_inode = self.read_inode(old_parent).ok_or(VfsError::NotFound)?;
        if (old_p_inode.mode & S_IFMT) != S_IFDIR {
            return Err(VfsError::NotADirectory);
        }
        let victim_ino = {
            let entries = self.read_dir_entries(&old_p_inode);
            entries.into_iter()
                .find(|(_, n, _)| n == old_name)
                .map(|(i, _, _)| i as u64)
                .ok_or(VfsError::NotFound)?
        };
        let victim = self.read_inode(victim_ino).ok_or(VfsError::NotFound)?;
        let victim_is_dir = (victim.mode & S_IFMT) == S_IFDIR;

        // Validate new_parent is a directory.
        let mut new_p_inode = self.read_inode(new_parent).ok_or(VfsError::NotFound)?;
        if (new_p_inode.mode & S_IFMT) != S_IFDIR {
            return Err(VfsError::NotADirectory);
        }

        // If new_name already exists, unlink it (POSIX rename(2) §ERRORS).
        // For a directory target, require it to be empty (ENOTEMPTY).
        {
            let entries = self.read_dir_entries(&new_p_inode);
            if let Some((existing_ino, _, _)) = entries.into_iter()
                .find(|(_, n, _)| n == new_name)
            {
                let existing = self.read_inode(existing_ino as u64)
                    .ok_or(VfsError::NotFound)?;
                if (existing.mode & S_IFMT) == S_IFDIR
                    && !self.dir_is_empty(&existing)
                {
                    return Err(VfsError::NotEmpty);
                }
                // Unlink the existing entry; if it was a dir, remove_inode
                // will free it once links_count drops to 0.
                self.unlink_entry(new_parent, new_name)?;
                self.remove_inode(existing_ino as u64)?;
            }
        }

        // Re-read new_parent (unlink_entry may have mutated it).
        new_p_inode = self.read_inode(new_parent).ok_or(VfsError::NotFound)?;

        // Insert the new dir-entry in new_parent.
        let ft = ext2_ft_from_mode(victim.mode);
        self.insert_dir_entry(&mut new_p_inode, new_parent, new_name,
            victim_ino as u32, ft)?;

        // Remove the old dir-entry.  We call remove_dir_entry directly to
        // avoid decrementing links_count a second time (the entry is being
        // moved, not removed).
        let old_p_inode2 = self.read_inode(old_parent).ok_or(VfsError::NotFound)?;
        self.remove_dir_entry(&old_p_inode2, old_name)
            .map_err(|_| VfsError::Io)?;

        // Cross-directory: fix the `..` back-pointer in the moved subtree
        // and adjust parent link-counts.
        if victim_is_dir && old_parent != new_parent {
            // Update `..` entry inside the moved directory to point at
            // new_parent.  The `..` entry is always the second record in
            // block 0 (immediately after `.`), per the ext2 spec §3
            // "Linked directory entries".
            let mut dir_block = alloc::vec![0u8; self.block_size];
            let phys = self.resolve_block(&victim, 0);
            if phys != 0 && self.read_block(phys, &mut dir_block).is_ok() {
                // Walk past the `.` entry to reach `..`.
                let dot_rec_len = u16::from_le_bytes(
                    [dir_block[4], dir_block[5]]) as usize;
                if dot_rec_len + 4 <= self.block_size {
                    dir_block[dot_rec_len..dot_rec_len + 4]
                        .copy_from_slice(&(new_parent as u32).to_le_bytes());
                    let _ = self.write_block(phys, &dir_block);
                }
            }
            // old_parent loses one i_links_count (the `..` back-ref leaving).
            if let Some(mut op) = self.read_inode(old_parent) {
                op.links_count = op.links_count.saturating_sub(1);
                op.mtime = current_unix_time();
                op.ctime = op.mtime;
                let _ = self.write_inode(old_parent, &op);
            }
            // new_parent gains one i_links_count (the `..` back-ref arriving).
            if let Some(mut np) = self.read_inode(new_parent) {
                np.links_count = np.links_count.saturating_add(1);
                np.mtime = current_unix_time();
                np.ctime = np.mtime;
                let _ = self.write_inode(new_parent, &np);
            }
        } else {
            // Intra-directory rename or non-dir: just bump mtimes.
            let t = current_unix_time();
            if let Some(mut op) = self.read_inode(old_parent) {
                op.mtime = t; op.ctime = t;
                let _ = self.write_inode(old_parent, &op);
            }
            if old_parent != new_parent {
                if let Some(mut np) = self.read_inode(new_parent) {
                    np.mtime = t; np.ctime = t;
                    let _ = self.write_inode(new_parent, &np);
                }
            }
        }

        // Evict dentry-cache entries for both parents (PR-E): the old
        // name is gone from old_parent; new_parent may have a new entry
        // (or a replaced one) under new_name.
        self.dentry_cache_evict_parent(old_parent);
        if new_parent != old_parent {
            self.dentry_cache_evict_parent(new_parent);
        }

        Ok(())
    }

    /// Change permission bits.
    ///
    /// Updates `i_mode` preserving the file-type high bits (S_IFMT mask),
    /// updates `i_ctime` to the current wall-clock time, and writes the
    /// inode back.  Per POSIX `chmod(2)`, only the low 12 bits of `mode`
    /// (permissions + setuid/setgid/sticky) are stored; the file-type bits
    /// are always preserved from the existing inode.
    fn chmod(&self, inode: u64, mode: u32) -> VfsResult<()> {
        let mut ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        // Preserve file-type bits; replace permission bits only.
        ino.mode = (ino.mode & S_IFMT) | ((mode as u16) & 0o7777);
        ino.ctime = current_unix_time();
        self.write_inode(inode, &ino).map_err(|_| VfsError::Io)
    }

    /// Update access and modification timestamps.
    ///
    /// Per POSIX `utimes(2)`: if `atime` or `mtime` is `Some`, the
    /// corresponding field is updated; `None` leaves the field unchanged.
    /// `i_ctime` is always updated to the current wall-clock time when any
    /// timestamp changes, per POSIX.1-2017 §2 "file times update rules".
    fn utimes(&self, inode: u64, atime: Option<u64>, mtime: Option<u64>) -> VfsResult<()> {
        let mut ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        if atime.is_none() && mtime.is_none() {
            return Ok(());
        }
        if let Some(a) = atime {
            ino.atime = a.min(u32::MAX as u64) as u32;
        }
        if let Some(m) = mtime {
            ino.mtime = m.min(u32::MAX as u64) as u32;
        }
        ino.ctime = current_unix_time();
        self.write_inode(inode, &ino).map_err(|_| VfsError::Io)
    }

    /// Change owner and group.
    ///
    /// Updates `i_uid` / `i_gid` and `i_ctime`, then writes the inode back.
    /// Per POSIX `chown(2)`, privilege enforcement (only root may change uid
    /// to an arbitrary value) is the personality layer's responsibility; the
    /// FS driver simply applies the values it is given.
    fn chown(&self, inode: u64, uid: u32, gid: u32) -> VfsResult<()> {
        let mut ino = self.read_inode(inode).ok_or(VfsError::NotFound)?;
        ino.uid = (uid & 0xFFFF) as u16;
        ino.gid = (gid & 0xFFFF) as u16;
        ino.ctime = current_unix_time();
        self.write_inode(inode, &ino).map_err(|_| VfsError::Io)
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
