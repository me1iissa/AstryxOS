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
        /// Hard-link count (POSIX `st_nlink`).  Created with 1; incremented
        /// by `link(2)` (a second directory entry naming this inode) and
        /// decremented by `unlink(2)`.  The inode's storage is freed only
        /// when this count reaches 0, so a file kept alive solely by a
        /// second link (e.g. fontconfig's `link(TMP, LCK)` lockfile pattern,
        /// per `link(2)`) survives removal of its original name.
        nlink: u32,
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

    /// ramfs opts in to the VFS path cache (positive + negative dentries):
    /// names are case-sensitive byte strings, every directory mutation flows
    /// through the VFS helpers (which invalidate), and the namespace is not
    /// externally synthesized.  See `FileSystemOps::lookup_cacheable`.
    fn lookup_cacheable(&self) -> bool {
        true
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
            nlink: 1,
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

        // Per POSIX `unlink(2)`: "When the file's link count reaches 0 and no
        // process has the file open, the space occupied by the file shall be
        // freed."  A regular file may have multiple hard links (see `link`);
        // decrement its link count and only free the inode storage once the
        // last name is gone.  Directories and symlinks have exactly one link
        // in ramfs, so they are freed unconditionally.
        let drop_inode = match &mut inodes[target_idx] {
            RamInode::File { nlink, .. } => {
                *nlink = nlink.saturating_sub(1);
                *nlink == 0
            }
            _ => true,
        };
        if drop_inode {
            inodes.retain(|n| n.inode_number() != target_inode);
        }

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
        let mut inodes = self.inodes.lock();
        let idx = Self::find_inode_idx(&inodes, inode).ok_or(VfsError::NotFound)?;

        match &mut inodes[idx] {
            RamInode::File { data, accessed, .. } => {
                let off = offset as usize;
                if off >= data.len() {
                    return Ok(0);
                }
                let available = data.len() - off;
                let to_read = available.min(buf.len());
                buf[..to_read].copy_from_slice(&data[off..off + to_read]);
                *accessed = now_secs(); // C2: update atime on read
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
            RamInode::File { inode, data, permissions, created, modified, accessed, .. } => Ok(FileStat {
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

    /// POSIX-compliant rename per `rename(2)`.
    ///
    /// References:
    /// - POSIX.1-2017 rename(2) <https://pubs.opengroup.org/onlinepubs/9699919799/functions/rename.html>
    /// - Linux rename(2) man page <https://man7.org/linux/man-pages/man2/rename.2.html>
    ///
    /// Error semantics enforced here (otherwise userspace tools relying on
    /// `rename` for atomicity — config-file replace, mailbox spool, etc. —
    /// see surprising results):
    ///
    /// * `old_name` / `new_name` of `.` or `..` → `EINVAL`.
    /// * Source does not exist → `ENOENT`.
    /// * Rename to self (same parent + same name) → success, no-op.
    /// * Overwriting a non-empty directory → `ENOTEMPTY`.
    /// * Mismatched types on overwrite:
    ///   - non-dir over dir → `EISDIR`
    ///   - dir over non-dir → `ENOTDIR`
    /// * Renaming a directory into its own descendant → `EINVAL` (POSIX:
    ///   "The new pathname contained a path prefix of the old.")
    fn rename(&self, old_parent: u64, old_name: &str, new_parent: u64, new_name: &str) -> VfsResult<()> {
        // POSIX rename(2): "If either the old or new argument names `.` or
        // `..`, rename() shall fail." (EINVAL).
        if old_name == "." || old_name == ".." || new_name == "." || new_name == ".." {
            return Err(VfsError::InvalidArg);
        }
        // Empty names are nonsensical at this layer; callers (`resolve_parent`)
        // already reject them, but defend-in-depth here.
        if old_name.is_empty() || new_name.is_empty() {
            return Err(VfsError::InvalidArg);
        }

        let mut inodes = self.inodes.lock();

        // Locate source.  Both parents must exist and be directories.
        let old_parent_idx = Self::find_inode_idx(&inodes, old_parent).ok_or(VfsError::NotFound)?;
        let target_inode = match &inodes[old_parent_idx] {
            RamInode::Dir { entries, .. } => {
                entries.iter().find(|e| e.name == old_name)
                    .map(|e| e.inode)
                    .ok_or(VfsError::NotFound)?
            }
            _ => return Err(VfsError::NotADirectory),
        };

        let new_parent_idx = Self::find_inode_idx(&inodes, new_parent).ok_or(VfsError::NotFound)?;
        match &inodes[new_parent_idx] {
            RamInode::Dir { .. } => {}
            _ => return Err(VfsError::NotADirectory),
        }

        // POSIX: "If the old argument and the new argument resolve to either
        // the same existing directory entry or different directory entries
        // for the same existing file, rename() shall return successfully and
        // perform no other action."  Same-parent + same-name is the trivial
        // case; the cross-link case is not representable in ramfs (no hard
        // links), so this check is sufficient here.
        if old_parent == new_parent && old_name == new_name {
            return Ok(());
        }

        // Determine source type — needed for type-mismatch checks below and
        // for the descendant-loop check.
        let target_idx = Self::find_inode_idx(&inodes, target_inode).ok_or(VfsError::NotFound)?;
        let target_is_dir = matches!(&inodes[target_idx], RamInode::Dir { .. });

        // POSIX EINVAL: "The link named by `new` is a directory that contains
        // any entries that name an ancestor of the source."  Practically:
        // forbid `rename("/a", "/a/b/c")` because that would orphan the
        // sub-tree under "a" once we re-link it.
        //
        // Walk up from `new_parent` via entries scanning until we either find
        // `target_inode` (loop!) or run out of parents.  Implemented as a
        // bounded BFS over the entry graph because ramfs has no back-pointer.
        if target_is_dir {
            // Quick reject: if new_parent IS the target itself, that's a
            // direct loop attempt.
            if new_parent == target_inode {
                return Err(VfsError::InvalidArg);
            }
            // Walk descendants of target_inode and check for new_parent.
            // Bounded by the total number of inodes (cannot exceed the
            // current FS size).
            let mut stack: Vec<u64> = alloc::vec![target_inode];
            let mut visited = 0usize;
            let cap = inodes.len() + 1;
            while let Some(cur) = stack.pop() {
                visited += 1;
                if visited > cap {
                    // Defensive: cycle in directory graph (shouldn't happen
                    // in ramfs, but corrupt state must not livelock the rename).
                    break;
                }
                if cur == new_parent {
                    return Err(VfsError::InvalidArg);
                }
                if let Some(ci) = Self::find_inode_idx(&inodes, cur) {
                    if let RamInode::Dir { entries, .. } = &inodes[ci] {
                        for e in entries {
                            // Only recurse into dir children to keep the
                            // traversal bounded; non-dirs cannot contain
                            // new_parent.
                            if let Some(ei) = Self::find_inode_idx(&inodes, e.inode) {
                                if matches!(&inodes[ei], RamInode::Dir { .. }) {
                                    stack.push(e.inode);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Handle overwrite: if `new_name` already exists in `new_parent`,
        // POSIX requires atomic replace with type-compatibility rules.
        let existing_target_inode: Option<u64> = {
            if let RamInode::Dir { entries, .. } = &inodes[new_parent_idx] {
                entries.iter().find(|e| e.name == new_name).map(|e| e.inode)
            } else {
                None
            }
        };

        if let Some(existing) = existing_target_inode {
            let existing_idx = Self::find_inode_idx(&inodes, existing).ok_or(VfsError::NotFound)?;
            let existing_is_dir = matches!(&inodes[existing_idx], RamInode::Dir { .. });

            // Type-compatibility (POSIX rename(2)):
            //   * If `old` names a directory, `new` must either not exist
            //     or be an empty directory.
            //   * If `old` is not a directory, `new` must not be a directory.
            if target_is_dir && !existing_is_dir {
                return Err(VfsError::NotADirectory);
            }
            if !target_is_dir && existing_is_dir {
                return Err(VfsError::IsADirectory);
            }
            if existing_is_dir {
                // Must be empty.
                if let RamInode::Dir { entries, .. } = &inodes[existing_idx] {
                    if !entries.is_empty() {
                        return Err(VfsError::NotEmpty);
                    }
                }
            }

            // Remove the displaced entry from new_parent and the displaced
            // inode itself.
            if let RamInode::Dir { entries, .. } = &mut inodes[new_parent_idx] {
                entries.retain(|e| e.name != new_name);
            }
            inodes.retain(|n| n.inode_number() != existing);
        }

        // All checks passed — perform the rename atomically (single lock,
        // single inodes vector mutation sequence).  Re-resolve indices
        // because removals above may have shifted positions.
        let old_parent_idx = Self::find_inode_idx(&inodes, old_parent).ok_or(VfsError::NotFound)?;
        if let RamInode::Dir { entries, modified, .. } = &mut inodes[old_parent_idx] {
            entries.retain(|e| e.name != old_name);
            *modified = now_secs();
        }

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

    /// Create a hard link: insert `name` in `parent_inode` referencing the
    /// existing `target_inode`, bumping its link count.
    ///
    /// Per POSIX `link(2)`:
    ///   * "If the path named by `path2` exists, `link()` shall fail" — EEXIST.
    ///   * Hard-linking a directory is not permitted — EPERM.
    /// Symlinks are likewise not hard-linkable here (ramfs tracks a link
    /// count only on regular files).  This implements exactly the lockfile
    /// idiom `link(TMP, LCK)` that fontconfig (`FcDirCacheLock`) and many
    /// other tools use for atomic, NFS-safe locking.
    fn link(&self, target_inode: u64, parent_inode: u64, name: &str) -> VfsResult<()> {
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

        // The target must exist and be a regular file (no dir/symlink links).
        let target_idx = Self::find_inode_idx(&inodes, target_inode).ok_or(VfsError::NotFound)?;
        match &mut inodes[target_idx] {
            RamInode::File { nlink, .. } => {
                *nlink = nlink.saturating_add(1);
            }
            RamInode::Dir { .. } => return Err(VfsError::PermissionDenied), // EPERM
            RamInode::SymLink { .. } => return Err(VfsError::Unsupported),
        }

        if let RamInode::Dir { entries, modified, .. } = &mut inodes[parent_idx] {
            entries.push(DirEntry {
                name: String::from(name),
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

    fn unlink_entry(&self, parent_inode: u64, name: &str) -> VfsResult<()> {
        let mut inodes = self.inodes.lock();
        let parent_idx = Self::find_inode_idx(&inodes, parent_inode)
            .ok_or(VfsError::NotFound)?;
        // Resolve the target inode of the name being removed so we can drop its
        // link count.  `unlink_entry` removes only the directory entry (the
        // deferred-delete path keeps the inode storage alive until the last fd
        // closes), but the *link* count must still fall — otherwise a file with
        // a second hard link would over-count and never be freed.
        let target_inode = match &inodes[parent_idx] {
            RamInode::Dir { entries, .. } =>
                entries.iter().find(|e| e.name == name).map(|e| e.inode),
            _ => return Err(VfsError::NotADirectory),
        };
        match &mut inodes[parent_idx] {
            RamInode::Dir { entries, modified, .. } => {
                let before = entries.len();
                entries.retain(|e| e.name != name);
                if entries.len() == before {
                    return Err(VfsError::NotFound);
                }
                *modified = now_secs();
            }
            _ => return Err(VfsError::NotADirectory),
        }
        if let Some(ti) = target_inode {
            if let Some(tidx) = Self::find_inode_idx(&inodes, ti) {
                if let RamInode::File { nlink, .. } = &mut inodes[tidx] {
                    *nlink = nlink.saturating_sub(1);
                }
            }
        }
        Ok(())
    }

    fn remove_inode(&self, inode: u64) -> VfsResult<()> {
        let mut inodes = self.inodes.lock();
        // Honour the hard-link count: the deferred-delete machinery calls this
        // on last-close of an unlinked file, but if another hard link still
        // names the inode (nlink > 0) its storage must survive (POSIX
        // `unlink(2)` link-count semantics).  Only regular files carry a link
        // count; directories/symlinks are single-linked here.
        if let Some(idx) = Self::find_inode_idx(&inodes, inode) {
            if let RamInode::File { nlink, .. } = &inodes[idx] {
                if *nlink > 0 {
                    return Ok(()); // still referenced by another name — keep it
                }
            }
        }
        inodes.retain(|n| n.inode_number() != inode);
        Ok(())
    }
}
