//! RAM Filesystem (ramfs)
//!
//! A simple in-memory filesystem for AstryxOS. All data is stored in the
//! kernel heap. Files and directories are backed by `Vec<u8>`.
//! This serves as the root filesystem and /tmp.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use super::{FileSystemOps, FileStat, FileType, VfsError, VfsResult, alloc_inode_number};

/// Get current uptime in seconds (used as a pseudo-timestamp).
fn now_secs() -> u64 {
    crate::arch::x86_64::irq::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed) / 100
}

/// Entry type within a directory.
#[derive(Clone)]
struct DirEntry {
    name: String,
    inode: u64,
}

/// An inode in the ramfs — either a file or a directory.
enum RamInode {
    File {
        inode: u64,
        data: Vec<u8>,
        permissions: u32,
        created: u64,
        modified: u64,
        accessed: u64,
    },
    Dir {
        inode: u64,
        entries: Vec<DirEntry>,
        permissions: u32,
        created: u64,
        modified: u64,
        accessed: u64,
    },
    SymLink {
        inode: u64,
        target: String,
        permissions: u32,
        created: u64,
        modified: u64,
        accessed: u64,
    },
}

impl RamInode {
    fn inode_number(&self) -> u64 {
        match self {
            RamInode::File { inode, .. } => *inode,
            RamInode::Dir { inode, .. } => *inode,
            RamInode::SymLink { inode, .. } => *inode,
        }
    }

    fn file_type(&self) -> FileType {
        match self {
            RamInode::File { .. } => FileType::RegularFile,
            RamInode::Dir { .. } => FileType::Directory,
            RamInode::SymLink { .. } => FileType::SymLink,
        }
    }
}

/// RAM filesystem instance.
pub struct RamFs {
    inodes: Mutex<Vec<RamInode>>,
    root_inode: u64,
}

impl RamFs {
    /// Create a new ramfs with an empty root directory.
    pub fn new() -> Self {
        let root_ino = 1u64; // root is always inode 1
        let now = now_secs();
        let root = RamInode::Dir {
            inode: root_ino,
            entries: Vec::new(),
            permissions: 0o755,
            created: now,
            modified: now,
            accessed: now,
        };

        Self {
            inodes: Mutex::new(alloc::vec![root]),
            root_inode: root_ino,
        }
    }

    pub fn root_inode(&self) -> u64 {
        self.root_inode
    }

    fn find_inode_idx(inodes: &[RamInode], inode: u64) -> Option<usize> {
        inodes.iter().position(|n| n.inode_number() == inode)
    }
}

impl FileSystemOps for RamFs {
    fn name(&self) -> &str {
        "ramfs"
    }

    fn create_file(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        let mut inodes = self.inodes.lock();

        // Find parent directory.
        let parent_idx = Self::find_inode_idx(&inodes, parent_inode)
            .ok_or(VfsError::NotFound)?;

        // Ensure parent is a directory.
        match &inodes[parent_idx] {
            RamInode::Dir { entries, .. } => {
                // Check if name already exists.
                if entries.iter().any(|e| e.name == name) {
                    return Err(VfsError::FileExists);
                }
            }
            _ => return Err(VfsError::NotADirectory),
        }

        let new_ino = alloc_inode_number();
        let now = now_secs();
        let new_file = RamInode::File {
            inode: new_ino,
            data: Vec::new(),
            permissions: 0o644,
            created: now,
            modified: now,
            accessed: now,
        };
        inodes.push(new_file);

        // Add entry to parent.
        if let RamInode::Dir { entries, .. } = &mut inodes[parent_idx] {
            entries.push(DirEntry {
                name: String::from(name),
                inode: new_ino,
            });
        }

        Ok(new_ino)
    }

    fn create_dir(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        let mut inodes = self.inodes.lock();

        let parent_idx = Self::find_inode_idx(&inodes, parent_inode)
            .ok_or(VfsError::NotFound)?;

        match &inodes[parent_idx] {
            RamInode::Dir { entries, .. } => {
                if entries.iter().any(|e| e.name == name) {
                    return Err(VfsError::FileExists);
                }
            }
            _ => return Err(VfsError::NotADirectory),
        }

        let new_ino = alloc_inode_number();
        let now = now_secs();
        let new_dir = RamInode::Dir {
            inode: new_ino,
            entries: Vec::new(),
            permissions: 0o755,
            created: now,
            modified: now,
            accessed: now,
        };
        inodes.push(new_dir);

        if let RamInode::Dir { entries, .. } = &mut inodes[parent_idx] {
            entries.push(DirEntry {
                name: String::from(name),
                inode: new_ino,
            });
        }

        Ok(new_ino)
    }

    fn remove(&self, parent_inode: u64, name: &str) -> VfsResult<()> {
        let mut inodes = self.inodes.lock();

        let parent_idx = Self::find_inode_idx(&inodes, parent_inode)
            .ok_or(VfsError::NotFound)?;

        let target_inode = match &inodes[parent_idx] {
            RamInode::Dir { entries, .. } => {
                entries.iter().find(|e| e.name == name)
                    .map(|e| e.inode)
                    .ok_or(VfsError::NotFound)?
            }
            _ => return Err(VfsError::NotADirectory),
        };

        // Check if target is a non-empty directory.
        let target_idx = Self::find_inode_idx(&inodes, target_inode)
            .ok_or(VfsError::NotFound)?;
        if let RamInode::Dir { entries, .. } = &inodes[target_idx] {
            if !entries.is_empty() {
                return Err(VfsError::NotEmpty);
            }
        }

        // Remove from parent.
        if let RamInode::Dir { entries, .. } = &mut inodes[parent_idx] {
            entries.retain(|e| e.name != name);
        }

        // Remove the inode.
        inodes.retain(|n| n.inode_number() != target_inode);

        Ok(())
    }

    fn lookup(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        let inodes = self.inodes.lock();

        let parent_idx = Self::find_inode_idx(&inodes, parent_inode)
            .ok_or(VfsError::NotFound)?;

        match &inodes[parent_idx] {
            RamInode::Dir { entries, .. } => {
                entries.iter().find(|e| e.name == name)
                    .map(|e| e.inode)
                    .ok_or(VfsError::NotFound)
            }
            _ => Err(VfsError::NotADirectory),
        }
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let inodes = self.inodes.lock();
        let idx = Self::find_inode_idx(&inodes, inode).ok_or(VfsError::NotFound)?;

        match &inodes[idx] {
            RamInode::File { data, .. } => {
                let off = offset as usize;
                if off >= data.len() {
                    return Ok(0);
                }
                let available = data.len() - off;
                let to_read = available.min(buf.len());
                buf[..to_read].copy_from_slice(&data[off..off + to_read]);
                Ok(to_read)
            }
            RamInode::Dir { .. } => Err(VfsError::IsADirectory),
            RamInode::SymLink { target, .. } => {
                let bytes = target.as_bytes();
                let off = offset as usize;
                if off >= bytes.len() {
                    return Ok(0);
                }
                let available = bytes.len() - off;
                let to_read = available.min(buf.len());
                buf[..to_read].copy_from_slice(&bytes[off..off + to_read]);
                Ok(to_read)
            }
        }
    }

    fn write(&self, inode: u64, offset: u64, data_in: &[u8]) -> VfsResult<usize> {
        let mut inodes = self.inodes.lock();
        let idx = Self::find_inode_idx(&inodes, inode).ok_or(VfsError::NotFound)?;

        match &mut inodes[idx] {
            RamInode::File { data, modified, .. } => {
                let off = offset as usize;
                let end = off + data_in.len();

                // Grow file if necessary.
                if end > data.len() {
                    data.resize(end, 0);
                }

                data[off..end].copy_from_slice(data_in);
                *modified = now_secs();
                Ok(data_in.len())
            }
            RamInode::Dir { .. } => Err(VfsError::IsADirectory),
            RamInode::SymLink { .. } => Err(VfsError::InvalidArg),
        }
    }

    fn stat(&self, inode: u64) -> VfsResult<FileStat> {
        let inodes = self.inodes.lock();
        let idx = Self::find_inode_idx(&inodes, inode).ok_or(VfsError::NotFound)?;

        match &inodes[idx] {
            RamInode::File { inode, data, permissions, created, modified, accessed } => Ok(FileStat {
                inode: *inode,
                file_type: FileType::RegularFile,
                size: data.len() as u64,
                permissions: *permissions,
                created: *created,
                modified: *modified,
                accessed: *accessed,
            }),
            RamInode::Dir { inode, entries, permissions, created, modified, accessed } => Ok(FileStat {
                inode: *inode,
                file_type: FileType::Directory,
                size: entries.len() as u64,
                permissions: *permissions,
                created: *created,
                modified: *modified,
                accessed: *accessed,
            }),
            RamInode::SymLink { inode, target, permissions, created, modified, accessed } => Ok(FileStat {
                inode: *inode,
                file_type: FileType::SymLink,
                size: target.len() as u64,
                permissions: *permissions,
                created: *created,
                modified: *modified,
                accessed: *accessed,
            }),
        }
    }

    fn readdir(&self, inode: u64) -> VfsResult<Vec<(String, u64, FileType)>> {
        let inodes = self.inodes.lock();
        let idx = Self::find_inode_idx(&inodes, inode).ok_or(VfsError::NotFound)?;

        match &inodes[idx] {
            RamInode::Dir { entries, .. } => {
                let mut result = Vec::new();
                for entry in entries {
                    let ft = if let Some(eidx) = Self::find_inode_idx(&inodes, entry.inode) {
                        inodes[eidx].file_type()
                    } else {
                        FileType::RegularFile
                    };
                    result.push((entry.name.clone(), entry.inode, ft));
                }
                Ok(result)
            }
            _ => Err(VfsError::NotADirectory),
        }
    }

    fn truncate(&self, inode: u64, size: u64) -> VfsResult<()> {
        let mut inodes = self.inodes.lock();
        let idx = Self::find_inode_idx(&inodes, inode).ok_or(VfsError::NotFound)?;

        match &mut inodes[idx] {
            RamInode::File { data, modified, .. } => {
                data.resize(size as usize, 0);
                *modified = now_secs();
                Ok(())
            }
            _ => Err(VfsError::IsADirectory),
        }
    }

    fn rename(&self, old_parent: u64, old_name: &str, new_parent: u64, new_name: &str) -> VfsResult<()> {
        let mut inodes = self.inodes.lock();

        // Find old entry inode.
        let old_parent_idx = Self::find_inode_idx(&inodes, old_parent).ok_or(VfsError::NotFound)?;
        let target_inode = match &inodes[old_parent_idx] {
            RamInode::Dir { entries, .. } => {
                entries.iter().find(|e| e.name == old_name)
                    .map(|e| e.inode)
                    .ok_or(VfsError::NotFound)?
            }
            _ => return Err(VfsError::NotADirectory),
        };

        // Remove from old parent.
        let old_parent_idx = Self::find_inode_idx(&inodes, old_parent).ok_or(VfsError::NotFound)?;
        if let RamInode::Dir { entries, modified, .. } = &mut inodes[old_parent_idx] {
            entries.retain(|e| e.name != old_name);
            *modified = now_secs();
        }

        // Remove any existing entry with the new name in the new parent (overwrite).
        let new_parent_idx = Self::find_inode_idx(&inodes, new_parent).ok_or(VfsError::NotFound)?;
        if let RamInode::Dir { entries, .. } = &inodes[new_parent_idx] {
            if let Some(existing) = entries.iter().find(|e| e.name == new_name).map(|e| e.inode) {
                // Remove the overwritten inode.
                let new_parent_idx2 = Self::find_inode_idx(&inodes, new_parent).ok_or(VfsError::NotFound)?;
                if let RamInode::Dir { entries, .. } = &mut inodes[new_parent_idx2] {
                    entries.retain(|e| e.name != new_name);
                }
                inodes.retain(|n| n.inode_number() != existing);
            }
        }

        // Add to new parent.
        let new_parent_idx = Self::find_inode_idx(&inodes, new_parent).ok_or(VfsError::NotFound)?;
        if let RamInode::Dir { entries, modified, .. } = &mut inodes[new_parent_idx] {
            entries.push(DirEntry {
                name: String::from(new_name),
                inode: target_inode,
            });
            *modified = now_secs();
        }

        Ok(())
    }

    fn symlink(&self, parent_inode: u64, name: &str, target: &str) -> VfsResult<u64> {
        let mut inodes = self.inodes.lock();

        let parent_idx = Self::find_inode_idx(&inodes, parent_inode).ok_or(VfsError::NotFound)?;
        match &inodes[parent_idx] {
            RamInode::Dir { entries, .. } => {
                if entries.iter().any(|e| e.name == name) {
                    return Err(VfsError::FileExists);
                }
            }
            _ => return Err(VfsError::NotADirectory),
        }

        let new_ino = alloc_inode_number();
        let now = now_secs();
        let link = RamInode::SymLink {
            inode: new_ino,
            target: String::from(target),
            permissions: 0o777,
            created: now,
            modified: now,
            accessed: now,
        };
        inodes.push(link);

        let parent_idx = Self::find_inode_idx(&inodes, parent_inode).ok_or(VfsError::NotFound)?;
        if let RamInode::Dir { entries, modified, .. } = &mut inodes[parent_idx] {
            entries.push(DirEntry {
                name: String::from(name),
                inode: new_ino,
            });
            *modified = now_secs();
        }

        Ok(new_ino)
    }

    fn readlink(&self, inode: u64) -> VfsResult<String> {
        let inodes = self.inodes.lock();
        let idx = Self::find_inode_idx(&inodes, inode).ok_or(VfsError::NotFound)?;

        match &inodes[idx] {
            RamInode::SymLink { target, .. } => Ok(target.clone()),
            _ => Err(VfsError::InvalidArg),
        }
    }

    fn chmod(&self, inode: u64, mode: u32) -> VfsResult<()> {
        let mut inodes = self.inodes.lock();
        let idx = Self::find_inode_idx(&inodes, inode).ok_or(VfsError::NotFound)?;

        match &mut inodes[idx] {
            RamInode::File { permissions, .. } => { *permissions = mode; Ok(()) }
            RamInode::Dir { permissions, .. } => { *permissions = mode; Ok(()) }
            RamInode::SymLink { permissions, .. } => { *permissions = mode; Ok(()) }
        }
    }
}
