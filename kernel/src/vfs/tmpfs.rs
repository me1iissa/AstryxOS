//! Tmpfs — a mountable anonymous in-memory filesystem.
//!
//! Each call to `TmpFs::new()` produces an independent filesystem instance
//! backed by its own `RamFs`.  Unlike the root ramfs (which is seeded once at
//! boot), tmpfs instances are created on demand by `sys_mount` and destroyed
//! when `sys_umount` removes the mount entry.
//!
//! This means that:
//!   mount("tmpfs", "/tmp",     "tmpfs", 0)
//!   mount("tmpfs", "/var/run", "tmpfs", 0)
//!
//! …produce two *completely independent* directory trees.  Writing `/tmp/x`
//! has no effect on `/var/run/x`.
//!
//! # Read-only support
//! When created with `TmpFs::new_rdonly()` all write operations return
//! `VfsError::PermissionDenied`.  This honours the MS_RDONLY flag (bit 0).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::{FileSystemOps, FileStat, FileType, VfsError, VfsResult};
use super::ramfs::RamFs;

/// Mount flag: read-only mount.
pub const MS_RDONLY: u64 = 1;

/// An independent tmpfs instance.  All state lives in the embedded `RamFs`.
pub struct TmpFs {
    inner: RamFs,
    rdonly: bool,
}

impl TmpFs {
    /// Create a new, empty, writable tmpfs.
    pub fn new() -> Self {
        Self { inner: RamFs::new(), rdonly: false }
    }

    /// Create a new, empty, read-only tmpfs (MS_RDONLY).
    pub fn new_rdonly() -> Self {
        Self { inner: RamFs::new(), rdonly: true }
    }

    /// Return the inode number of the root directory.
    pub fn root_inode(&self) -> u64 {
        self.inner.root_inode()
    }

    #[inline]
    fn check_writable(&self) -> VfsResult<()> {
        if self.rdonly { Err(VfsError::PermissionDenied) } else { Ok(()) }
    }
}

impl FileSystemOps for TmpFs {
    fn name(&self) -> &str {
        "tmpfs"
    }

    fn create_file(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        self.check_writable()?;
        self.inner.create_file(parent_inode, name)
    }

    fn create_dir(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        self.check_writable()?;
        self.inner.create_dir(parent_inode, name)
    }

    fn remove(&self, parent_inode: u64, name: &str) -> VfsResult<()> {
        self.check_writable()?;
        self.inner.remove(parent_inode, name)
    }

    fn lookup(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        self.inner.lookup(parent_inode, name)
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        self.inner.read(inode, offset, buf)
    }

    fn write(&self, inode: u64, offset: u64, data: &[u8]) -> VfsResult<usize> {
        self.check_writable()?;
        self.inner.write(inode, offset, data)
    }

    fn stat(&self, inode: u64) -> VfsResult<FileStat> {
        self.inner.stat(inode)
    }

    fn readdir(&self, inode: u64) -> VfsResult<Vec<(String, u64, FileType)>> {
        self.inner.readdir(inode)
    }

    fn truncate(&self, inode: u64, size: u64) -> VfsResult<()> {
        self.check_writable()?;
        self.inner.truncate(inode, size)
    }

    fn rename(&self, old_parent: u64, old_name: &str, new_parent: u64, new_name: &str) -> VfsResult<()> {
        self.check_writable()?;
        self.inner.rename(old_parent, old_name, new_parent, new_name)
    }

    fn symlink(&self, parent_inode: u64, name: &str, target: &str) -> VfsResult<u64> {
        self.check_writable()?;
        self.inner.symlink(parent_inode, name, target)
    }

    fn readlink(&self, inode: u64) -> VfsResult<String> {
        self.inner.readlink(inode)
    }

    fn chmod(&self, inode: u64, mode: u32) -> VfsResult<()> {
        self.check_writable()?;
        self.inner.chmod(inode, mode)
    }

    fn unlink_entry(&self, parent_inode: u64, name: &str) -> VfsResult<()> {
        self.check_writable()?;
        self.inner.unlink_entry(parent_inode, name)
    }

    fn remove_inode(&self, inode: u64) -> VfsResult<()> {
        self.inner.remove_inode(inode)
    }
}
