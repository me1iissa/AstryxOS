//! ext2 Filesystem Driver (read-only)
//!
//! Provides read-only access to ext2-formatted disk partitions.
//! Supports reading the superblock, block group descriptors, inodes,
//! directory entries, and file data.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

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
const S_IFREG: u16 = 0x8000;
const S_IFDIR: u16 = 0x4000;
const S_IFLNK: u16 = 0xA000;

/// ext2 filesystem instance.
pub struct Ext2Fs {
    /// Function to read raw sectors from the underlying block device.
    /// (sector: u64, count: u16, buf: &mut [u8])
    read_fn: fn(u64, u16, &mut [u8]) -> Result<(), &'static str>,
    /// Cached superblock.
    superblock: Superblock,
    /// Block size in bytes.
    block_size: usize,
    /// Inode size in bytes.
    inode_size: usize,
}

impl Ext2Fs {
    /// Try to mount an ext2 filesystem from the given block device reader.
    pub fn new(read_fn: fn(u64, u16, &mut [u8]) -> Result<(), &'static str>) -> Option<Self> {
        // Read superblock (at byte offset 1024, sector 2)
        let mut sb_buf = [0u8; 512];
        if read_fn(2, 1, &mut sb_buf).is_err() {
            crate::serial_println!("[EXT2] Failed to read superblock");
            return None;
        }

        let sb: Superblock = unsafe { core::ptr::read_unaligned(sb_buf.as_ptr() as *const Superblock) };

        if sb.magic != EXT2_MAGIC {
            crate::serial_println!("[EXT2] Invalid magic: {:#06x} (expected {:#06x})", sb.magic, EXT2_MAGIC);
            return None;
        }

        let block_size = 1024usize << sb.log_block_size;
        let inode_size = if sb.rev_level >= 1 { sb.inode_size as usize } else { 128 };

        crate::serial_println!("[EXT2] Superblock valid: {} inodes, {} blocks, block_size={}",
            sb.inodes_count, sb.blocks_count, block_size);

        Some(Ext2Fs {
            read_fn,
            superblock: sb,
            block_size,
            inode_size,
        })
    }

    /// Read a block from the filesystem.
    fn read_block(&self, block_num: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        let sectors_per_block = (self.block_size / 512) as u16;
        let start_sector = block_num as u64 * sectors_per_block as u64;
        (self.read_fn)(start_sector, sectors_per_block, buf)
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
        if (self.read_fn)(bgd_sector, 1, &mut sector_buf).is_err() {
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
        if (self.read_fn)(inode_sector, 1, &mut buf).is_err() {
            return None;
        }

        if inode_off + 128 <= 512 {
            Some(unsafe { core::ptr::read_unaligned(buf[inode_off..].as_ptr() as *const Ext2Inode) })
        } else {
            // Inode spans sector boundary — read two sectors
            let mut buf2 = [0u8; 1024];
            if (self.read_fn)(inode_sector, 2, &mut buf2).is_err() {
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
    fn read_dir_entries(&self, inode: &Ext2Inode) -> Vec<(u32, String, u8)> {
        let mut entries = Vec::new();
        let size = inode.size as usize;
        let mut data = alloc::vec![0u8; size];
        self.read_inode_data(inode, 0, &mut data);

        let mut offset = 0;
        while offset + 8 <= size {
            let entry_inode = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
            let rec_len = u16::from_le_bytes([data[offset+4], data[offset+5]]) as usize;
            let name_len = data[offset+6] as usize;
            let file_type = data[offset+7];

            if rec_len == 0 { break; }

            if entry_inode != 0 && name_len > 0 && offset + 8 + name_len <= size {
                let name = core::str::from_utf8(&data[offset+8..offset+8+name_len])
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
}

/// Try to mount an ext2 filesystem from ATA disk 0.
pub fn try_mount() {
    fn ata_read(sector: u64, count: u16, buf: &mut [u8]) -> Result<(), &'static str> {
        crate::drivers::ata::read_sectors(0, sector as u32, count as u8, buf)
    }

    match Ext2Fs::new(ata_read) {
        Some(fs) => {
            crate::serial_println!("[EXT2] Mounting ext2 filesystem at /ext2");
            crate::vfs::mount("/ext2", alloc::boxed::Box::new(fs), 2); // ext2 root inode = 2
        }
        None => {
            crate::serial_println!("[EXT2] No ext2 filesystem found on disk 0");
        }
    }
}
