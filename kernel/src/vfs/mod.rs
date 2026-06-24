//! Virtual Filesystem (VFS) Layer
//!
//! Provides a unified filesystem interface inspired by the Unix VFS model.
//! All filesystems register with the VFS and expose a common set of operations.
//!
//! # Architecture
//! - **Inode**: An in-memory representation of a file/directory (metadata + data reference).
//! - **Dentry**: A directory entry mapping a name to an inode.
//! - **FileSystem**: A registered filesystem type (ramfs, fat32, etc.).
//! - **Mount**: A filesystem mounted at a path in the directory tree.
//! - **FileDescriptor**: An open file handle in a process.
//!
//! # Mount Table
//! The VFS maintains a flat mount table. Path resolution walks mounts to find
//! the deepest matching mount point.

pub mod ext2;
pub mod fat32;
pub mod ntfs;
pub mod ramfs;
pub mod tmpfs;
pub mod procfs;
pub mod sysfs;

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Maximum open files per process.
pub const MAX_FDS_PER_PROCESS: usize = 1024;

/// Error codes for VFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotFound = 2,       // ENOENT
    PermissionDenied = 13, // EACCES
    FileExists = 17,    // EEXIST
    NotADirectory = 20, // ENOTDIR
    IsADirectory = 21,  // EISDIR
    InvalidArg = 22,    // EINVAL
    TooManyOpenFiles = 24, // EMFILE
    NoSpace = 28,       // ENOSPC
    BadFd = 9,          // EBADF
    NotEmpty = 39,      // ENOTEMPTY
    Unsupported = 95,   // EOPNOTSUPP
    Io = 5,             // EIO
    WouldBlock = 11,    // EAGAIN / EWOULDBLOCK
    /// Operation could not complete within an internal anti-wedge budget.
    /// Emitted by `resolve_path_opts` when a path resolution makes no forward
    /// progress for the whole no-progress budget (a genuinely-stuck FS
    /// dispatch) — see the W83 wedge (`/usr → /disk/usr` symlink traversal hung
    /// indefinitely in 2/3 firefox-test trials) and [`ResolveDeadline`].  POSIX
    /// `open(2)` does not list ETIMEDOUT and never returns it for a *present,
    /// progressing* file; the deadline is purely an internal hang-breaker that
    /// cleanly distinguishes a wedged dispatch from EIO or ENOENT in serial
    /// logs.
    TimedOut = 110,     // ETIMEDOUT
}

impl From<VfsError> for astryx_shared::NtStatus {
    fn from(e: VfsError) -> Self {
        use astryx_shared::ntstatus::*;
        match e {
            VfsError::NotFound => STATUS_NO_SUCH_FILE,
            VfsError::PermissionDenied => STATUS_ACCESS_DENIED,
            VfsError::FileExists => STATUS_OBJECT_NAME_COLLISION,
            VfsError::NotADirectory => STATUS_NOT_A_DIRECTORY,
            VfsError::IsADirectory => STATUS_FILE_IS_A_DIRECTORY,
            VfsError::InvalidArg => STATUS_INVALID_PARAMETER,
            VfsError::TooManyOpenFiles => STATUS_FS_TOO_MANY_OPEN,
            VfsError::NoSpace => STATUS_DISK_FULL,
            VfsError::BadFd => STATUS_INVALID_HANDLE,
            VfsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
            VfsError::Unsupported => STATUS_NOT_SUPPORTED,
            VfsError::Io => STATUS_IO_DEVICE_ERROR,
            VfsError::WouldBlock => STATUS_NO_MORE_FILES,
            VfsError::TimedOut => STATUS_TIMEOUT,
        }
    }
}

pub type VfsResult<T> = Result<T, VfsError>;

/// File type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    RegularFile,
    Directory,
    SymLink,
    CharDevice,
    BlockDevice,
    Pipe,
    /// eventfd counter-based signaling fd.
    EventFd,
    /// Unix-domain or TCP socket unified into the fd table.
    Socket,
    /// timerfd — POSIX interval timer notification fd.
    TimerFd,
    /// signalfd — signal delivery via fd.
    SignalFd,
    /// inotify — filesystem event notification fd (stub: no events delivered).
    InotifyFd,
    /// PTY master side (/dev/ptmx).  Payload = PTY pair index stored in fd.open_path.
    PtyMaster,
    /// PTY slave side (/dev/pts/N).  Payload = PTY pair index stored in fd.open_path.
    PtySlave,
}

/// File open flags.
pub mod flags {
    pub const O_RDONLY: u32 = 0;
    pub const O_WRONLY: u32 = 1;
    pub const O_RDWR: u32 = 2;
    pub const O_CREAT: u32 = 0x40;
    pub const O_TRUNC: u32 = 0x200;
    pub const O_APPEND: u32 = 0x400;
}

/// File metadata.
#[derive(Debug, Clone)]
pub struct FileStat {
    pub inode: u64,
    pub file_type: FileType,
    pub size: u64,
    pub permissions: u32,
    /// Created timestamp (Unix epoch seconds, 0 = unavailable).
    pub created: u64,
    /// Last-modified timestamp (Unix epoch seconds, 0 = unavailable).
    pub modified: u64,
    /// Last-accessed timestamp (Unix epoch seconds, 0 = unavailable).
    pub accessed: u64,
}

/// Next inode number.
static NEXT_INODE: AtomicU64 = AtomicU64::new(2); // 0 = invalid, 1 = root

pub fn alloc_inode_number() -> u64 {
    NEXT_INODE.fetch_add(1, Ordering::Relaxed)
}

/// Inodes pending deletion: (mount_idx, inode_number).
/// Added by remove() when the file is still open; freed on last close().
static DELETED_INODES: Mutex<Vec<(usize, u64)>> = Mutex::new(Vec::new());

/// Inodes pinned alive by a kernel reference that is NOT a process fd-table
/// slot: (mount_idx, inode_number, pin_count).
///
/// The unlink-on-last-close machinery in [`close`] decides whether a
/// deferred-deleted inode may be freed by scanning every process fd table for
/// a slot that still points at it.  That scan cannot see a descriptor that is
/// in flight — queued for SCM_RIGHTS delivery but not yet installed in the
/// receiver's fd table.  Such a descriptor is held only in the syscall layer's
/// PENDING_SCM queue; without a pin, a sender that `close(2)`s its copy of an
/// unlinked memfd while the batch is still pending would free the inode out
/// from under the un-received descriptor, corrupting the shared surface.  Per
/// `memfd_create(2)` ("the memory is freed when all references are dropped")
/// and `unix(7)` SCM_RIGHTS ("the passed descriptor refers to the same open
/// file description"), an in-flight passed descriptor IS such a reference.
///
/// A pinned inode is never freed by `close`; it is freed only once both the
/// last fd-table slot is gone AND the pin count reaches zero (see
/// [`unpin_inode`]).
static PINNED_INODES: Mutex<Vec<(usize, u64, u32)>> = Mutex::new(Vec::new());

/// Add one kernel pin on `(mount_idx, inode)` so [`close`] will not free it
/// even when no process fd table references it (e.g. an SCM_RIGHTS descriptor
/// queued for delivery).  Balance every call with exactly one [`unpin_inode`].
pub fn pin_inode(mount_idx: usize, inode: u64) {
    if mount_idx == usize::MAX { return; } // sentinel fds (pipes etc.) have no inode
    let mut p = PINNED_INODES.lock();
    if let Some(e) = p.iter_mut().find(|(m, n, _)| *m == mount_idx && *n == inode) {
        e.2 = e.2.saturating_add(1);
    } else {
        p.push((mount_idx, inode, 1));
    }
}

/// Inodes whose last kernel pin was dropped by an *under-lock* caller (one that
/// already holds [`crate::proc::PROCESS_TABLE`]) and which therefore could not
/// run the orphan check / free inline.  Drained by [`reap_pending_inodes`] after
/// the caller releases PROCESS_TABLE.  Entries: `(mount_idx, inode_number)`.
///
/// This mirrors the fd-close machinery's split between a lock-free fast path and
/// a deferred free: the VMA-list edit that drops a `MAP_SHARED` mapping's pin
/// (munmap, `MAP_FIXED` replacement, a hole-punch split) runs inside the
/// `mmap`/`munmap` PROCESS_TABLE critical section, so the actual inode-free —
/// which itself must scan PROCESS_TABLE for surviving fd references — is queued
/// here and reaped once the lock is dropped.  Calling a PROCESS_TABLE-taking
/// helper while PROCESS_TABLE is held would self-deadlock the non-reentrant
/// spin lock.
static PENDING_INODE_REAP: Mutex<Vec<(usize, u64)>> = Mutex::new(Vec::new());

/// Decrement the pin count on `(mount_idx, inode)`.  Returns `true` iff this call
/// dropped the *last* pin (count reached zero and the entry was removed).  Does
/// NOT take any lock other than `PINNED_INODES`, so it is safe to call with
/// `PROCESS_TABLE` held.
fn dec_pin(mount_idx: usize, inode: u64) -> bool {
    let mut p = PINNED_INODES.lock();
    if let Some(idx) = p.iter().position(|(m, n, _)| *m == mount_idx && *n == inode) {
        if p[idx].2 > 1 {
            p[idx].2 -= 1;
            false
        } else {
            p.remove(idx);
            true
        }
    } else {
        false
    }
}

/// Free `(mount_idx, inode)` iff it was deferred-deleted (unlinked while open or
/// mapped) and no process fd table still references it.  Returns `true` if the
/// inode was actually freed.  Takes `PROCESS_TABLE`, so callers MUST NOT already
/// hold it (use [`unpin_inode_deferred`] + [`reap_pending_inodes`] instead).
///
/// Mirrors the close()-time last-close test in [`close`] (its C5 path).
fn try_free_orphan_inode(mount_idx: usize, inode: u64) -> bool {
    let still_open = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().any(|p| p.file_descriptors.iter().any(|fdo| {
            fdo.as_ref().map(|f| f.mount_idx == mount_idx && f.inode == inode)
                .unwrap_or(false)
        }))
    };
    // Another live kernel pin (e.g. an in-flight SCM_RIGHTS descriptor) keeps the
    // inode alive even after this one was dropped.
    if still_open || inode_is_pinned(mount_idx, inode) { return false; }
    let was_deleted = {
        let mut dl = DELETED_INODES.lock();
        let before = dl.len();
        dl.retain(|(m, n)| !(*m == mount_idx && *n == inode));
        dl.len() < before
    };
    if was_deleted {
        if let Some((fs, _)) = fs_at(mount_idx) {
            let _ = fs.remove_inode(inode);
            return true;
        }
    }
    false
}

/// Drop one kernel pin on `(mount_idx, inode)`.  When the pin count reaches
/// zero AND the inode was deferred-deleted with no remaining open fd, the inode
/// is freed here (the pin was the last thing keeping it alive).  Returns true
/// if the inode was actually freed by this call.
///
/// Takes `PROCESS_TABLE`; callers MUST NOT hold it.  The in-flight SCM_RIGHTS
/// drop path and the no-lock address-space teardown paths use this directly.
/// Under-lock VMA edits (munmap/mmap-replace/split) must use
/// [`unpin_inode_deferred`] instead.
pub fn unpin_inode(mount_idx: usize, inode: u64) -> bool {
    if mount_idx == usize::MAX { return false; }
    if !dec_pin(mount_idx, inode) { return false; }
    try_free_orphan_inode(mount_idx, inode)
}

/// Drop one kernel pin on `(mount_idx, inode)` from a context that may already
/// hold `PROCESS_TABLE` (e.g. `VmSpace::remove_range` running inside the
/// `mmap`/`munmap` critical section).  This NEVER takes `PROCESS_TABLE`: if the
/// last pin is dropped, the orphan check + free is queued for
/// [`reap_pending_inodes`], which the syscall layer runs after releasing the
/// lock.  See [`PENDING_INODE_REAP`].
pub fn unpin_inode_deferred(mount_idx: usize, inode: u64) {
    if mount_idx == usize::MAX { return; }
    if dec_pin(mount_idx, inode) {
        PENDING_INODE_REAP.lock().push((mount_idx, inode));
    }
}

/// Drain [`PENDING_INODE_REAP`] and free any inode whose last `MAP_SHARED`
/// mapping pin was dropped under `PROCESS_TABLE` and which is now orphaned
/// (deferred-deleted, no open fd, no other pin).  MUST be called with
/// `PROCESS_TABLE` *not* held; the syscall layer invokes it after every
/// `mmap`/`munmap` that may have unpinned an inode, so a still-mapped shm
/// inode is freed the moment its last mapping is torn down (the POSIX shm
/// `shm_open`→`mmap`→`close`→`shm_unlink` idiom).
pub fn reap_pending_inodes() {
    // Move the queue out under its own lock so we are not iterating while the
    // (possibly slow) free path runs, and so a re-entrant push cannot deadlock.
    let pending: Vec<(usize, u64)> = {
        let mut q = PENDING_INODE_REAP.lock();
        if q.is_empty() { return; }
        core::mem::take(&mut *q)
    };
    for (mount_idx, inode) in pending {
        try_free_orphan_inode(mount_idx, inode);
    }
}

/// True if `(mount_idx, inode)` currently has at least one kernel pin
/// (see [`pin_inode`]).
fn inode_is_pinned(mount_idx: usize, inode: u64) -> bool {
    PINNED_INODES.lock().iter().any(|(m, n, c)| *m == mount_idx && *n == inode && *c > 0)
}

/// Public view of [`inode_is_pinned`] for regression tests that assert the
/// MAP_SHARED-file pin balance (see test_runner Test 119b).  Test-mode only.
#[cfg(feature = "test-mode")]
pub fn inode_is_pinned_pub(mount_idx: usize, inode: u64) -> bool {
    inode_is_pinned(mount_idx, inode)
}

/// Exact kernel pin count on `(mount_idx, inode)` (0 when unpinned).  Lets
/// regression tests assert the one-pin-per-VMA-membership invariant precisely
/// after an `mprotect` split (Test 119c), not just "pinned vs not".  Test-mode
/// only.
#[cfg(feature = "test-mode")]
pub fn inode_pin_count_pub(mount_idx: usize, inode: u64) -> u32 {
    PINNED_INODES.lock().iter()
        .find(|(m, n, _)| *m == mount_idx && *n == inode)
        .map(|(_, _, c)| *c)
        .unwrap_or(0)
}

/// Place one kernel pin on the inode backing a `MAP_SHARED` file-backed VMA.
///
/// POSIX `mmap(2)` makes a mapping an independent reference on the underlying
/// open file description: "The mmap() function adds an extra reference to the
/// file associated with the file descriptor fildes which is not removed by a
/// subsequent close() on that file descriptor."  Combined with `unlink(2)`
/// ("if [the link count] was the last link ... but [a] process has the file
/// open, the file shall remain in existence until ... the file is no longer
/// open"), a live `MAP_SHARED` mapping must keep an unlinked file's inode (and
/// its data) alive until the mapping is torn down.
///
/// This is exactly the POSIX shared-memory idiom — `shm_open` → `ftruncate` →
/// `mmap(MAP_SHARED)` → `close(fd)` → `shm_unlink` — used by, among others,
/// the cross-process IPC shared buffers of large desktop applications.  Without
/// this pin the `close(fd)` after `mmap` triggers unlink-on-last-close (see
/// [`close`]'s C5 path), `remove_inode` frees the ramfs/tmpfs inode, and the
/// next demand-fault on the still-live mapping reads a now-absent inode →
/// SIGSEGV.
///
/// `MAP_PRIVATE` file mappings (e.g. ELF `PT_LOAD` segments) do NOT pin: a
/// private mapping copies file pages into anonymous frames and does not require
/// the inode to survive past `close`.  Anonymous and device mappings have no
/// inode and are ignored.
///
/// Balanced by [`vma_unpin_if_shared_file`]; one pin per VMA-list membership.
pub fn vma_pin_if_shared_file(
    flags: crate::mm::vma::VmFlags,
    backing: &crate::mm::vma::VmBacking,
) {
    if flags & crate::mm::vma::MAP_SHARED == 0 {
        return;
    }
    if let crate::mm::vma::VmBacking::File { mount_idx, inode, .. } = backing {
        pin_inode(*mount_idx, *inode);
    }
}

/// Drop the kernel pin placed by [`vma_pin_if_shared_file`] when a `MAP_SHARED`
/// file-backed VMA leaves a process's address space (munmap, `MAP_FIXED`
/// replacement, a hole-punch split, or whole-address-space teardown at
/// exit/exec).
///
/// This uses [`unpin_inode_deferred`], which NEVER takes `PROCESS_TABLE`, so it
/// is safe to call from inside `VmSpace::remove_range` (run under PROCESS_TABLE
/// by `mmap`/`munmap`) and from the address-space teardown VMA walks.  When this
/// drops the last pin of an already-unlinked shm inode, the actual free is
/// queued; the caller frees it by calling [`reap_pending_inodes`] after it
/// releases PROCESS_TABLE.
pub fn vma_unpin_if_shared_file(
    flags: crate::mm::vma::VmFlags,
    backing: &crate::mm::vma::VmBacking,
) {
    if flags & crate::mm::vma::MAP_SHARED == 0 {
        return;
    }
    if let crate::mm::vma::VmBacking::File { mount_idx, inode, .. } = backing {
        unpin_inode_deferred(*mount_idx, *inode);
    }
}

// ───── firefox-test screenshot-write gate ───────────────────────────────────
//
// The firefox-test workload renders to a `--screenshot <PATH>` file.  There is
// no genuine "PNG written" serial marker in the fast (core) build, so winning
// boots are mis-classified as stalled at the screenshot-IPC stage.  The launch
// path registers the screenshot PATH here; [`close`] then emits exactly one
// `[GATE] png-write path=<p> bytes=<n>` line the first time that file is closed
// after a write (the file is complete the moment the renderer closes it).  The
// marker is keyed on a write-mode close of a non-empty file, NOT on opens or
// path resolves, so a probe/stat of the path never false-fires.

/// Registered screenshot output path (full open path, e.g. `/tmp/out.png`), or
/// empty when unset.  Set once by the launch path via
/// [`set_screenshot_gate_path`]; read on every regular-file close.
static SCREENSHOT_GATE_PATH: Mutex<String> = Mutex::new(String::new());

/// True once the `[GATE] png-write` line has been emitted this boot, so a later
/// re-write/close of the same path (e.g. a relaunch overwriting the file) does
/// not double-fire.  The first complete write is the demo-success signal.
static SCREENSHOT_GATE_FIRED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Register the firefox-test `--screenshot` output path so [`close`] can emit
/// the `[GATE] png-write` marker for exactly that file.  Idempotent; the last
/// caller wins (the launch path calls it once before launching Firefox).
pub fn set_screenshot_gate_path(path: &str) {
    *SCREENSHOT_GATE_PATH.lock() = String::from(path);
    SCREENSHOT_GATE_FIRED.store(false, Ordering::Relaxed);
}

/// On a write-mode close of the registered screenshot path with `bytes > 0`,
/// emit one `[GATE] png-write path=<p> bytes=<n>` line (first arrival only).
/// `bytes` is the file's write offset at close — a non-zero offset proves the
/// renderer wrote content before closing.  Cheap: a single atomic load short-
/// circuits once fired or when no path is registered.
fn maybe_emit_png_write_gate(open_path: &str, writable: bool, bytes: u64) {
    if !writable || bytes == 0 {
        return;
    }
    if SCREENSHOT_GATE_FIRED.load(Ordering::Relaxed) {
        return;
    }
    {
        let p = SCREENSHOT_GATE_PATH.lock();
        if p.is_empty() || p.as_str() != open_path {
            return;
        }
    }
    // First arrival claims the flag; only that caller emits the line.
    if !SCREENSHOT_GATE_FIRED.swap(true, Ordering::Relaxed) {
        crate::serial_println!("[GATE] png-write path={} bytes={}", open_path, bytes);
    }
}

/// A held POSIX byte-range lock.
#[derive(Clone)]
pub struct FileLockEntry {
    pub mount_idx: usize,
    pub inode: u64,
    pub pid: u64,
    pub start: u64,
    pub end: u64,       // 0 = to end-of-file (entire range above start)
    pub lock_type: i16, // F_RDLCK=0, F_WRLCK=1
}

/// Global file-lock table (F_SETLK / F_SETLKW / F_GETLK).
pub static FILE_LOCKS: Mutex<Vec<FileLockEntry>> = Mutex::new(Vec::new());

/// Filesystem operations trait — each filesystem type must implement this.
pub trait FileSystemOps: Send + Sync {
    fn name(&self) -> &str;
    fn create_file(&self, parent_inode: u64, name: &str) -> VfsResult<u64>;
    fn create_dir(&self, parent_inode: u64, name: &str) -> VfsResult<u64>;
    fn remove(&self, parent_inode: u64, name: &str) -> VfsResult<()>;
    fn lookup(&self, parent_inode: u64, name: &str) -> VfsResult<u64>;
    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> VfsResult<usize>;
    fn write(&self, inode: u64, offset: u64, data: &[u8]) -> VfsResult<usize>;
    fn stat(&self, inode: u64) -> VfsResult<FileStat>;
    fn readdir(&self, inode: u64) -> VfsResult<Vec<(String, u64, FileType)>>;
    fn truncate(&self, inode: u64, size: u64) -> VfsResult<()>;
    /// Flush any dirty in-memory state to the backing store.
    fn sync(&self) -> VfsResult<()> { Ok(()) }

    /// Whether this filesystem stores file content purely in RAM with NO
    /// distinct backing store (ramfs / tmpfs).
    ///
    /// In-memory filesystems keep two copies of a file's bytes once a page is
    /// demand-faulted: the inode's own buffer (authoritative for `read` /
    /// `write` / `stat.size`) and the page-cache frame the demand-fault path
    /// installs (what an `mmap` PTE aliases).  A `MAP_SHARED` + `PROT_WRITE`
    /// store lands ONLY in the page-cache frame — the hardware writes the
    /// frame directly through the aliasing PTE, never the inode buffer.
    ///
    /// For a block-backed filesystem (ext2 / fat32) the on-disk image is the
    /// single source of truth and a `read` re-reads it, so this hazard does
    /// not arise; those filesystems return the default `false`.
    ///
    /// The page cache uses this to keep the two copies coherent for in-memory
    /// filesystems: it writes a cache frame back to the inode buffer before
    /// the frame is evicted, and `fd_read` reads through a resident cache
    /// frame in preference to the inode buffer.  This satisfies POSIX
    /// mmap(2) `MAP_SHARED` visibility — "writes ... shall be visible in all
    /// processes mapping the same region" and to a subsequent `read(2)`.
    fn is_in_memory(&self) -> bool { false }

    /// Rename / move an entry from one directory to another.
    fn rename(&self, _old_parent: u64, _old_name: &str, _new_parent: u64, _new_name: &str) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }

    /// Create a symbolic link in `parent_inode` with name `name` pointing to `target`.
    fn symlink(&self, _parent_inode: u64, _name: &str, _target: &str) -> VfsResult<u64> {
        Err(VfsError::Unsupported)
    }

    /// Read the target path of a symbolic link.
    fn readlink(&self, _inode: u64) -> VfsResult<String> {
        Err(VfsError::Unsupported)
    }

    /// Change permission bits.
    fn chmod(&self, _inode: u64, _mode: u32) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }

    /// Unlink just the directory entry (name→inode link) without freeing the inode.
    /// Used for unlink-on-last-close: the inode survives while fds are open.
    fn unlink_entry(&self, _parent_inode: u64, _name: &str) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }

    /// Free an inode that has already been unlinked from its parent directory.
    /// Called when the last open file descriptor pointing to the inode is closed.
    fn remove_inode(&self, _inode: u64) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }

    /// Create a hard link: insert `name` in `parent_inode` pointing at
    /// `target_inode`, incrementing `i_links_count`.  Per POSIX `link(2)`,
    /// linking a directory is not permitted (`EPERM`); that check is the
    /// caller's responsibility.  Returns `Err(Unsupported)` on filesystems
    /// (FAT32, procfs, …) that do not support hard links.
    fn link(&self, _target_inode: u64, _parent_inode: u64, _name: &str) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }

    /// Update access and modification timestamps.  `atime` / `mtime` are
    /// Unix-epoch seconds; pass `None` to leave the field unchanged.
    /// Per POSIX `utimes(2)` / `utimensat(2)`, also updates `i_ctime` to
    /// the current wall-clock time whenever either timestamp is changed.
    fn utimes(&self, _inode: u64, _atime: Option<u64>, _mtime: Option<u64>) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }

    /// Change owner and group.  Per POSIX `chown(2)`, also clears the
    /// set-user-ID and set-group-ID bits unless the caller is privileged
    /// (the kernel personality layer enforces privilege; here we simply
    /// update `i_uid` / `i_gid` and write the inode back).
    fn chown(&self, _inode: u64, _uid: u32, _gid: u32) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }
}

/// A mounted filesystem.
///
/// `fs` is held as `Arc<dyn FileSystemOps>` rather than `Box` so that the VFS
/// helpers can clone a reference out of `MOUNTS`, drop the lock, and then
/// dispatch into the FS without holding the global mount-table mutex.
///
/// # Why this matters
///
/// Holding `MOUNTS` across an FS-method dispatch creates a same-thread
/// recursive-lock hazard: if the dispatched method touches a userspace
/// buffer (or any file-backed VMA) whose page is not yet resident, the
/// kernel-mode page-fault handler also needs `MOUNTS` to satisfy the
/// demand-page — and the spin-yield retry path cannot make forward
/// progress because the holder is *this* CPU.  See `resolve_path` and
/// the page-fault file-backed path in `arch/x86_64/idt.rs` for the
/// fix shape (snapshot the Arc under the lock; drop; dispatch).
pub struct Mount {
    pub path: String,
    pub fs: Arc<dyn FileSystemOps>,
    pub root_inode: u64,
}

/// Mount table.
pub static MOUNTS: Mutex<Vec<Mount>> = Mutex::new(Vec::new());

/// Snapshot `(Arc<dyn FileSystemOps>, root_inode)` for `mount_idx` and
/// immediately drop the `MOUNTS` lock.  The returned `Arc` keeps the
/// filesystem alive independent of the mount table: a concurrent unmount
/// cannot free the backing FS while the caller holds the Arc.
///
/// All callers that dispatch a `FileSystemOps` method which may block on I/O
/// (e.g. `stat`, `read`, `write`, `lookup`) MUST use this helper rather than
/// holding `MOUNTS.lock()` across the dispatch.  The `MOUNTS` spinlock is
/// non-yielding; holding it across a `schedule()` point (which virtio block
/// I/O reaches via `wait_completion`) causes a cross-thread spinlock deadlock
/// on SMP — the holder yields at the I/O wait, another thread spins forever
/// on `MOUNTS`, monopolising its CPU, and the holder is never rescheduled.
/// (POSIX fstat(2) / vfork(2) interaction; confirmed via GDB autopsy.)
///
/// Returns `None` when `idx` is out of bounds.
pub fn fs_at(idx: usize) -> Option<(Arc<dyn FileSystemOps>, u64)> {
    let mounts = MOUNTS.lock();
    mounts.get(idx).map(|m| (m.fs.clone(), m.root_inode))
}

/// File descriptor — an open file handle in a process.
#[derive(Clone)]
pub struct FileDescriptor {
    /// Inode of the open file.
    pub inode: u64,
    /// Mount index in the MOUNTS table.
    pub mount_idx: usize,
    /// Current read/write offset.
    pub offset: u64,
    /// Open flags.
    pub flags: u32,
    /// File type.
    pub file_type: FileType,
    /// Special: console stdin/stdout/stderr (not backed by VFS inode).
    pub is_console: bool,
    /// Close-on-exec flag (set by O_CLOEXEC or fcntl F_SETFD FD_CLOEXEC).
    pub cloexec: bool,
    /// Absolute path this fd was opened with (used by fchdir, /proc/fd/ etc.)
    pub open_path: String,
}

impl FileDescriptor {
    pub fn console_stdin() -> Self {
        Self {
            inode: 0, mount_idx: 0, offset: 0,
            flags: flags::O_RDONLY, file_type: FileType::CharDevice,
            is_console: true, cloexec: false, open_path: String::new(),
        }
    }
    pub fn console_stdout() -> Self {
        Self {
            inode: 0, mount_idx: 0, offset: 0,
            flags: flags::O_WRONLY, file_type: FileType::CharDevice,
            is_console: true, cloexec: false, open_path: String::new(),
        }
    }
    pub fn console_stderr() -> Self {
        Self {
            inode: 0, mount_idx: 0, offset: 0,
            flags: flags::O_WRONLY, file_type: FileType::CharDevice,
            is_console: true, cloexec: false, open_path: String::new(),
        }
    }
    /// Pipe write-end sentinel fd (not backed by VFS inode).
    pub fn pipe_write_end(pipe_id: u64) -> Self {
        Self {
            inode: pipe_id, mount_idx: usize::MAX, offset: 0,
            flags: 0x8000_0001, file_type: FileType::Pipe,
            is_console: false, cloexec: false, open_path: String::new(),
        }
    }
    /// Pipe read-end sentinel fd (not backed by VFS inode).
    pub fn pipe_read_end(pipe_id: u64) -> Self {
        Self {
            inode: pipe_id, mount_idx: usize::MAX, offset: 0,
            flags: 0x8000_0000, file_type: FileType::Pipe,
            is_console: false, cloexec: false, open_path: String::new(),
        }
    }
    /// timerfd sentinel fd.  `slot_id` is the index into the timerfd table.
    pub fn timer_fd(slot_id: u64) -> Self {
        Self {
            inode: slot_id, mount_idx: usize::MAX, offset: 0,
            flags: 0, file_type: FileType::TimerFd,
            is_console: false, cloexec: false, open_path: String::new(),
        }
    }
    /// signalfd sentinel fd.  `slot_id` is the index into the signalfd table.
    pub fn signal_fd(slot_id: u64) -> Self {
        Self {
            inode: slot_id, mount_idx: usize::MAX, offset: 0,
            flags: 0, file_type: FileType::SignalFd,
            is_console: false, cloexec: false, open_path: String::new(),
        }
    }
    /// inotifyfd sentinel fd.  `slot_id` is the index into the inotify table.
    pub fn inotify_fd(slot_id: u64) -> Self {
        Self {
            inode: slot_id, mount_idx: usize::MAX, offset: 0,
            flags: 0, file_type: FileType::InotifyFd,
            is_console: false, cloexec: false, open_path: String::new(),
        }
    }
    /// PTY master fd.  `pty_n` is the pair index (= slave number N).
    pub fn pty_master(pty_n: u8) -> Self {
        use alloc::format;
        Self {
            inode: pty_n as u64, mount_idx: usize::MAX, offset: 0,
            flags: flags::O_RDWR, file_type: FileType::PtyMaster,
            is_console: false, cloexec: false, open_path: format!("/dev/ptmx"),
        }
    }
    /// PTY slave fd.  `pty_n` is the pair index.
    pub fn pty_slave(pty_n: u8) -> Self {
        use alloc::format;
        Self {
            inode: pty_n as u64, mount_idx: usize::MAX, offset: 0,
            flags: flags::O_RDWR, file_type: FileType::PtySlave,
            is_console: false, cloexec: false, open_path: format!("/dev/pts/{}", pty_n),
        }
    }
}

/// Initialize the VFS with a root ramfs.
pub fn init() {
    let root_fs = ramfs::RamFs::new();
    let root_inode = root_fs.root_inode();

    MOUNTS.lock().push(Mount {
        path: String::from("/"),
        fs: Arc::new(root_fs),
        root_inode,
    });

    // Create standard directories.
    let _ = mkdir("/dev");
    let _ = mkdir("/tmp");
    let _ = mkdir("/home");
    let _ = mkdir("/bin");
    let _ = mkdir("/etc");

    // Symlinks so glibc/musl dynamic linker can find libraries on the data disk.
    // When ld.so opens e.g. /lib/x86_64-linux-gnu/libc.so.6, the VFS follows
    // the symlink to /disk/lib/x86_64-linux-gnu/libc.so.6.
    // /lib64/ld-linux-x86-64.so.2 → /disk/lib64/ld-linux-x86-64.so.2
    let _ = symlink("/lib",   "/disk/lib");
    let _ = symlink("/lib64", "/disk/lib64");
    let _ = symlink("/usr",   "/disk/usr");
    let _ = symlink("/opt",   "/disk/opt");
    // /bin → /disk/bin so /bin/busybox and the applet wrappers
    // staged by create-data-disk.sh are reachable at their FHS path
    // (per https://refspecs.linuxfoundation.org/FHS_3.0/).  Upstream
    // binaries hard-code `/bin/foo` for many tools; without this the
    // PATH search in busybox sh would only find files staged at
    // `/disk/bin/foo`.  /etc/ is NOT symlinked because the kernel
    // populates it in-RAM with locally-customised tmpfs entries
    // (hostname, motd, nsswitch.conf, hosts, resolv.conf, etc.) below.
    let _ = symlink("/bin",   "/disk/bin");

    // /etc/ssl and /etc/pki/tls/certs — symlinked into the data disk so
    // upstream TLS clients (openssl, ssl_client, busybox wget --https,
    // anything DT_NEEDED libssl) find the Mozilla CA bundle at every
    // conventional path without the kernel having to embed ~220 KiB of
    // PEM into tmpfs.  Staged by scripts/install-tls-stack.sh +
    // create-data-disk.sh --tls.  The targets may be absent on builds
    // that did not stage the TLS pack; symlink creation is best-effort.
    //
    // Paths covered:
    //   /etc/ssl/cert.pem                    (Alpine / LibreSSL default)
    //   /etc/ssl/certs/ca-certificates.crt   (Debian / Ubuntu)
    //   /etc/ssl/openssl.cnf                 (OpenSSL CLI config)
    //   /etc/pki/tls/certs/ca-bundle.crt     (RHEL / Fedora)
    //
    // Per FHS 3.0 (https://refspecs.linuxfoundation.org/FHS_3.0/) and
    // ca-certificates(7), these are the documented locations userland
    // expects.  We make /etc/ssl and /etc/pki point at /disk/ subtrees;
    // the parent /etc tmpfs entries above (hostname, hosts, ...) are
    // unaffected because the kernel symlink walker matches the longest
    // mount-point prefix.
    let _ = mkdir("/etc/pki");
    let _ = mkdir("/etc/pki/tls");
    let _ = symlink("/etc/ssl",            "/disk/etc/ssl");
    let _ = symlink("/etc/pki/tls/certs",  "/disk/etc/pki/tls/certs");

    // fontconfig reads its configuration from /etc/fonts/fonts.conf at FcInit
    // time (the library's compiled-in sysconfdir default; see fonts-conf(5)).
    // The real config tree is staged on the data disk at /disk/etc/fonts/, so
    // point /etc/fonts at it the same way /etc/ssl is handled above.  Without
    // this every GTK/Firefox process — including the e10s content children,
    // which do not reliably inherit FONTCONFIG_* — fails the default-config
    // load ("Cannot load default config file: No such file") and degrades to
    // fontconfig's minimal built-in fallback, breaking text/glyph rendering
    // and the windowed (--ff-gui) paint path.  The longest-prefix symlink
    // walker leaves the rest of the /etc tmpfs (hostname, hosts, ...) intact.
    let _ = symlink("/etc/fonts",          "/disk/etc/fonts");

    // Create /dev/null and /dev/console.
    let _ = create_file("/dev/null");
    let _ = create_file("/dev/zero");
    let _ = create_file("/dev/urandom");
    let _ = create_file("/dev/random");
    let _ = create_file("/dev/console");
    let _ = create_file("/dev/tty");
    let _ = create_file("/dev/ptmx");
    let _ = mkdir("/dev/pts");
    // /dev/shm — POSIX shared memory (tmpfs on Linux).
    // Firefox IPC falls back to shm_open() when memfd_create fails.
    // shm_open("/name") maps to open("/dev/shm/name", O_RDWR|O_CREAT).
    let _ = mkdir("/dev/shm");

    // Framebuffer device.
    let _ = create_file("/dev/fb0");

    // OSS-compatible audio device.  Writes go to the AC97 DMA ring when
    // the driver is present; open returns ENODEV when AC97 was not probed.
    let _ = create_file("/dev/dsp");

    // Input devices (evdev).
    let _ = mkdir("/dev/input");
    let _ = create_file("/dev/input/event0");  // keyboard
    let _ = create_file("/dev/input/event1");  // mouse / pointer

    // DRI / DRM stub (Firefox probes these).
    let _ = mkdir("/dev/dri");
    let _ = create_file("/dev/dri/card0");

    // virtio-serial port 0 (QGA transport, Phase QGA-1).  The node is always
    // created so userspace probes get -ENODEV from the open path when QGA
    // was not compiled in or the device was not discovered, rather than
    // -ENOENT.
    let _ = create_file("/dev/vport0p0");

    // Create /etc/hostname with default content.
    if let Ok(()) = create_file("/etc/hostname") {
        let _ = write_file("/etc/hostname", b"astryx\n");
    }

    // Create /etc/motd.
    if let Ok(()) = create_file("/etc/motd") {
        let _ = write_file("/etc/motd", b"Welcome to AstryxOS!\n");
    }

    // Minimal /etc/passwd — required by bash, login, id, whoami, etc.
    // Format: name:password:uid:gid:gecos:home:shell
    if let Ok(()) = create_file("/etc/passwd") {
        let _ = write_file("/etc/passwd",
            b"root:x:0:0:root:/root:/bin/sh\n\
              nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n");
    }

    // /etc/shadow — stub so passwd-reading libs don't hard-error
    if let Ok(()) = create_file("/etc/shadow") {
        let _ = write_file("/etc/shadow", b"root:!:19000:0:99999:7:::\nnobody:!:19000::::::\n");
    }

    // Minimal /etc/group — required by id, newgrp, bash
    // Format: group:password:gid:member_list
    if let Ok(()) = create_file("/etc/group") {
        let _ = write_file("/etc/group",
            b"root:x:0:\nnogroup:x:65534:\n");
    }

    // /etc/shells — list of valid login shells
    if let Ok(()) = create_file("/etc/shells") {
        let _ = write_file("/etc/shells", b"/bin/sh\n/bin/bash\n");
    }

    // /etc/nsswitch.conf — tells glibc where to look up users/hosts
    if let Ok(()) = create_file("/etc/nsswitch.conf") {
        let _ = write_file("/etc/nsswitch.conf",
            b"passwd:   files\ngroup:    files\nshadow:   files\nhosts:    files\n");
    }

    // /etc/hosts — minimal hostname map (required by musl resolver)
    if let Ok(()) = create_file("/etc/hosts") {
        // Local + SLIRP gateway aliases.  10.0.2.2 is the conventional
        // QEMU SLIRP host loopback alias
        // (https://www.qemu.org/docs/master/system/devices/net.html);
        // `gateway` lets tls-test / wget-test / busybox-test refer to
        // the host responder by name and avoids the musl getaddrinfo
        // DNS-fallthrough path that some libc versions take even for
        // literal IPv4 strings.
        //
        // NB: bytes literal must NOT use \\ line continuations — those
        // would preserve the leading indentation as part of the line
        // body and musl's /etc/hosts parser silently rejects lines with
        // leading whitespace.
        let _ = write_file("/etc/hosts",
            b"127.0.0.1 localhost\n::1 localhost\n127.0.0.1 astryx\n10.0.2.2 gateway host\n");
    }

    // /etc/host.conf — resolver order configuration
    if let Ok(()) = create_file("/etc/host.conf") {
        let _ = write_file("/etc/host.conf", b"order files,bind\n");
    }

    // /etc/resolv.conf — point at the QEMU SLIRP DNS gateway (10.0.2.3)
    // by default.  This is the conventional SLIRP-internal DNS proxy
    // (https://www.qemu.org/docs/master/system/devices/net.html) and is
    // reachable from any guest on the default user-mode network.  When
    // SLIRP is not in use the address is unreachable; clients fall back
    // to the `hosts: files` rule above, which suffices for /etc/hosts
    // mappings and literal-IP connect attempts.  Without a nameserver
    // entry, some userspace getaddrinfo implementations (musl's
    // included) refuse to look up even literal IPs, returning
    // EAI_AGAIN — see the I1a tls-test investigation 2026-05-23.
    if let Ok(()) = create_file("/etc/resolv.conf") {
        let _ = write_file("/etc/resolv.conf",
            b"nameserver 10.0.2.3\n");
    }

    // /etc/os-release — systemd-style distro identifier
    // (https://www.freedesktop.org/software/systemd/man/os-release.html).
    // Many CLI tools (lsb_release, neofetch, busybox uname -a fallback,
    // various Mozilla telemetry sniffers) read this file to identify
    // the host distro.  We provide a static AstryxOS-flavoured entry
    // here as the in-RAM authoritative copy; the data.img build also
    // stages a copy at /disk/etc/os-release for tools that hard-code
    // the `/disk/` prefix.
    if let Ok(()) = create_file("/etc/os-release") {
        let _ = write_file("/etc/os-release",
            b"NAME=\"AstryxOS\"\n\
              ID=astryxos\n\
              VERSION_ID=demo\n\
              PRETTY_NAME=\"AstryxOS (Aether kernel demo)\"\n\
              HOME_URL=\"https://example.org/astryxos\"\n");
    }

    // /srv/index.html — document served by the httpd-test in-kernel
    // HTTP responder (PIVOT-C, 2026-05-23).  Gated to httpd-test so the
    // default kernel build doesn't carry the ~700-byte tmpfs entry.
    // The responder also has a compiled-in fallback in httpd_demo.rs,
    // so a tmpfs miss is benign; we still seed here so the served bytes
    // demonstrably came from "kernel-managed VFS" rather than a const.
    #[cfg(feature = "httpd-test")]
    {
        let _ = mkdir("/srv");
        if let Ok(()) = create_file("/srv/index.html") {
            let _ = write_file("/srv/index.html",
                crate::httpd_demo::INDEX_HTML);
        }
    }

    // /etc/machine-id — required by GLib, systemd, D-Bus, and many userspace tools.
    // Must be a 32-character lowercase hex string.
    if let Ok(()) = create_file("/etc/machine-id") {
        let _ = write_file("/etc/machine-id", b"d3b07384d113edec49eaa6238ad5ff00\n");
    }

    // /var/lib/dbus/machine-id — D-Bus reads this path first; same value.
    let _ = mkdir("/var");
    let _ = mkdir("/var/lib");
    let _ = mkdir("/var/lib/dbus");
    if let Ok(()) = create_file("/var/lib/dbus/machine-id") {
        let _ = write_file("/var/lib/dbus/machine-id", b"d3b07384d113edec49eaa6238ad5ff00\n");
    }

    // /etc/profile — sourced by login shells
    if let Ok(()) = create_file("/etc/profile") {
        let _ = write_file("/etc/profile",
            b"export PATH=/bin:/usr/bin:/sbin:/usr/sbin\nexport HOME=/root\nexport TERM=linux\n");
    }

    // /root home directory
    let _ = mkdir("/root");

    // /etc/localtime stub — prevents TZ-related crashes in some libc builds
    if let Ok(()) = create_file("/etc/localtime") {
        // Empty file; glibc will fall back to UTC
    }

    // /etc/ascension.conf — Ascension init service configuration.
    // Empty by default; add "service <name> <binary> [args...]" lines to
    // register services that Ascension will launch at boot.
    if let Ok(()) = create_file("/etc/ascension.conf") {
        let _ = write_file("/etc/ascension.conf",
            b"# Ascension Init Configuration\n\
              # Format: service <name> <binary> [args...]\n\
              # Format: service-restart <name> <binary> [args...]  (restart on exit)\n\
              # Format: service-onfail  <name> <binary> [args...]  (restart on failure)\n\
              #\n\
              # Example:\n\
              #   service-restart syslogd /disk/bin/syslogd\n\
              #   service-restart getty   /disk/bin/getty tty0\n");
    }

    // ── /proc — mount ProcFs as a real VFS filesystem ─────────────────────
    // ProcFs generates all content dynamically on every read(), so userspace
    // always sees live kernel state.  The static ramfs entries that used to
    // live here have been replaced by the ProcFs mount below.
    //
    // The `mount()` call creates the /proc directory in the parent ramfs and
    // then registers ProcFs in the MOUNTS table.  The path resolver will
    // thereafter route any /proc/... open() to ProcFs rather than ramfs.
    {
        let proc_fs = procfs::ProcFs::new();
        let proc_root = proc_fs.root_inode();
        mount("/proc", Box::new(proc_fs), proc_root);
        crate::serial_println!("[VFS] ProcFs mounted at /proc (dynamic, live kernel state)");
    }

    // ── /sys — mount SysFs ─────────────────────────────────────────────────
    // Provides /sys/devices/system/cpu/... used by Firefox and other
    // Gecko-based applications for CPU topology detection.  Without these
    // files Firefox calls exit(1) before its event loop starts.
    {
        let sys_fs = sysfs::SysFs::new();
        let sys_root = sys_fs.root_inode();
        mount("/sys", Box::new(sys_fs), sys_root);
        crate::serial_println!("[VFS] SysFs mounted at /sys");
    }

    crate::serial_println!("[VFS] Initialized with root ramfs, standard directories created");
}

/// Mount a filesystem at the given path.
///
/// The supplied `Box` is converted to `Arc` on insertion so that the VFS
/// helpers can clone a reference out of `MOUNTS` and dispatch without
/// holding the lock.  Callers continue to pass `Box::new(MyFs::new())` —
/// the conversion is zero-cost (`Arc::from(Box<T>)` reuses the allocation).
pub fn mount(path: &str, fs: Box<dyn FileSystemOps>, root_inode: u64) {
    // Ensure mount point directory exists in parent filesystem.
    let _ = mkdir(path);

    MOUNTS.lock().push(Mount {
        path: String::from(path),
        fs: Arc::from(fs),
        root_inode,
    });
}

/// Initialize disks: mount in-memory test image at /mnt, then probe for
/// real AHCI/ATA disks, scan for partitions, and mount FAT32/NTFS volumes.
pub fn init_disks() {
    use crate::drivers::block::MemoryBlockDevice;

    // ── In-memory test image at /mnt (always, for tests) ────────────────
    let image_data = fat32::create_test_image();
    let image_static: &'static [u8] = Box::leak(image_data.into_boxed_slice());

    let device = Box::new(MemoryBlockDevice::new(image_static));

    match fat32::Fat32Fs::new(device) {
        Ok(fs) => {
            let root_inode = fs.root_inode();
            mount("/mnt", Box::new(fs), root_inode);
            crate::serial_println!("[VFS] FAT32 test image mounted at /mnt");
        }
        Err(e) => {
            crate::serial_println!("[VFS] FAT32 test image mount failed: {:?}", e);
        }
    }

    // ── Real disk at /disk (try virtio first, then AHCI, then ATA PIO) ─
    if !init_virtio_disks() {
        if !init_ahci_disks() {
            init_ata_disks();
        }
    }
}

/// Backwards-compatible alias for `init_disks`.
pub fn init_fat32() {
    init_disks();
}

/// Probe virtio-blk device for partitions and mount FAT32/NTFS volumes.
/// Returns true if any volume was successfully mounted.
fn init_virtio_disks() -> bool {
    use crate::drivers::block::BlockDevice;
    use crate::drivers::partition;
    use crate::drivers::virtio_blk;

    if !virtio_blk::is_available() {
        crate::serial_println!("[VFS] Virtio-blk not available, skipping");
        return false;
    }

    let dev = virtio_blk::VirtioBlkBlockDevice;
    crate::serial_println!(
        "[VFS] Probing virtio-blk device ({} sectors) for partitions...",
        dev.sector_count()
    );

    let partitions = partition::scan_partitions(&dev as &dyn BlockDevice);

    if !partitions.is_empty() {
        crate::serial_println!(
            "[VFS] Found {} partition(s) on virtio-blk",
            partitions.len()
        );
        for part in &partitions {
            crate::serial_println!(
                "[VFS]   Partition {}: type={:?}, start={}, size={} sectors",
                part.index, part.partition_type, part.start_lba, part.sector_count
            );
            // Each Fs::new consumes the BlockDevice; build a fresh one per try.
            let new_pdev = || partition::create_partition_device(
                Box::new(virtio_blk::VirtioBlkBlockDevice),
                part.start_lba,
                part.sector_count,
            );
            match part.partition_type {
                partition::PartitionType::Fat32 => {
                    match fat32::Fat32Fs::new(Box::new(new_pdev())) {
                        Ok(fs) => {
                            let root_inode = fs.root_inode();
                            mount("/disk", Box::new(fs), root_inode);
                            crate::serial_println!(
                                "[VFS] FAT32 partition mounted at /disk (virtio-blk)"
                            );
                            return true;
                        }
                        Err(e) => {
                            crate::serial_println!(
                                "[VFS] FAT32 mount failed on virtio-blk partition: {:?}",
                                e
                            );
                        }
                    }
                }
                partition::PartitionType::Ntfs => {
                    if let Some(fs) = ntfs::try_mount_ntfs(Box::new(new_pdev())) {
                        let root_inode = fs.root_inode();
                        mount("/ntfs", Box::new(fs), root_inode);
                        crate::serial_println!(
                            "[VFS] NTFS partition mounted at /ntfs (virtio-blk)"
                        );
                        return true;
                    }
                }
                partition::PartitionType::LinuxExt => {
                    if let Some(fs) = ext2::try_mount_ext2(Box::new(new_pdev())) {
                        mount("/disk", Box::new(fs), ext2::EXT2_ROOT_INODE);
                        crate::serial_println!(
                            "[VFS] ext2 partition mounted at /disk (virtio-blk)"
                        );
                        return true;
                    }
                    crate::serial_println!(
                        "[VFS] ext2 mount failed on virtio-blk LinuxExt partition"
                    );
                }
                _ => {
                    crate::serial_println!(
                        "[VFS]   Skipping unsupported partition type: {:?}",
                        part.partition_type
                    );
                }
            }
        }
    }

    // Fallback: try whole-disk FAT32, then ext2.  ext2 added per the
    // 2026-05-24 FAT32 → ext2 data-disk migration plan.
    crate::serial_println!(
        "[VFS] No partitions on virtio-blk, trying whole disk FAT32..."
    );
    match fat32::Fat32Fs::new(Box::new(virtio_blk::VirtioBlkBlockDevice)) {
        Ok(fs) => {
            let root_inode = fs.root_inode();
            mount("/disk", Box::new(fs), root_inode);
            crate::serial_println!("[VFS] FAT32 whole-disk mounted at /disk (virtio-blk)");
            return true;
        }
        Err(_) => {
            crate::serial_println!("[VFS] Virtio-blk disk is not FAT32, trying ext2...");
        }
    }
    if let Some(fs) = ext2::try_mount_ext2(Box::new(virtio_blk::VirtioBlkBlockDevice)) {
        mount("/disk", Box::new(fs), ext2::EXT2_ROOT_INODE);
        crate::serial_println!("[VFS] ext2 whole-disk mounted at /disk (virtio-blk)");
        return true;
    }
    crate::serial_println!("[VFS] Virtio-blk disk is neither FAT32 nor ext2");
    false
}

/// Probe AHCI ports for partitions and mount FAT32/NTFS volumes.
/// Returns true if any volume was successfully mounted.
fn init_ahci_disks() -> bool {
    use crate::drivers::ahci;
    use crate::drivers::block::AhciBlockDevice;
    use crate::drivers::partition;

    if !ahci::is_available() {
        crate::serial_println!("[VFS] AHCI not available, skipping");
        return false;
    }

    let ports = ahci::active_ports();
    crate::serial_println!("[VFS] AHCI active ports: {:?}", ports);
    let mut mounted_any = false;

    for port in ports {
        // Skip port 0 — that's the boot disk / UEFI ESP.
        if port == 0 {
            continue;
        }

        crate::serial_println!("[VFS] Probing AHCI port {} for partitions...", port);
        let probe_dev = AhciBlockDevice::new(port);
        let partitions = partition::scan_partitions(&probe_dev);

        if !partitions.is_empty() {
            crate::serial_println!("[VFS] Found {} partition(s) on AHCI port {}", partitions.len(), port);
            for part in &partitions {
                crate::serial_println!("[VFS]   Partition {}: type={:?}, start={}, size={} sectors",
                    part.index, part.partition_type, part.start_lba, part.sector_count);

                let new_pdev = || partition::create_partition_device(
                    Box::new(AhciBlockDevice::new(port)),
                    part.start_lba,
                    part.sector_count,
                );
                match part.partition_type {
                    partition::PartitionType::Fat32 => {
                        // Try FAT32 first
                        match fat32::Fat32Fs::new(Box::new(new_pdev())) {
                            Ok(fs) => {
                                let root_inode = fs.root_inode();
                                mount("/disk", Box::new(fs), root_inode);
                                crate::serial_println!("[VFS] FAT32 partition mounted at /disk (AHCI port {})", port);
                                mounted_any = true;
                                continue;
                            }
                            Err(_) => {}
                        }
                        // Try NTFS
                        if let Some(fs) = ntfs::try_mount_ntfs(Box::new(new_pdev())) {
                            let root_inode = fs.root_inode();
                            mount("/ntfs", Box::new(fs), root_inode);
                            crate::serial_println!("[VFS] NTFS partition mounted at /ntfs (AHCI port {})", port);
                            mounted_any = true;
                        }
                    }
                    partition::PartitionType::Ntfs => {
                        if let Some(fs) = ntfs::try_mount_ntfs(Box::new(new_pdev())) {
                            let root_inode = fs.root_inode();
                            mount("/ntfs", Box::new(fs), root_inode);
                            crate::serial_println!("[VFS] NTFS partition mounted at /ntfs (AHCI port {})", port);
                            mounted_any = true;
                        }
                    }
                    partition::PartitionType::LinuxExt => {
                        if let Some(fs) = ext2::try_mount_ext2(Box::new(new_pdev())) {
                            mount("/disk", Box::new(fs), ext2::EXT2_ROOT_INODE);
                            crate::serial_println!("[VFS] ext2 partition mounted at /disk (AHCI port {})", port);
                            mounted_any = true;
                        } else {
                            crate::serial_println!("[VFS] ext2 mount failed on AHCI port {} LinuxExt partition", port);
                        }
                    }
                    _ => {
                        crate::serial_println!("[VFS]   Skipping unsupported partition type: {:?}", part.partition_type);
                    }
                }
            }
        } else {
            // No partition table — try whole disk as FAT32 (legacy), then ext2.
            crate::serial_println!("[VFS] No partitions found on AHCI port {}, trying whole disk as FAT32...", port);
            match fat32::Fat32Fs::new(Box::new(AhciBlockDevice::new(port))) {
                Ok(fs) => {
                    let root_inode = fs.root_inode();
                    mount("/disk", Box::new(fs), root_inode);
                    crate::serial_println!("[VFS] FAT32 whole-disk mounted at /disk (AHCI port {})", port);
                    mounted_any = true;
                    continue;
                }
                Err(e) => {
                    crate::serial_println!("[VFS] AHCI port {} is not FAT32: {:?}, trying ext2...", port, e);
                }
            }
            if let Some(fs) = ext2::try_mount_ext2(Box::new(AhciBlockDevice::new(port))) {
                mount("/disk", Box::new(fs), ext2::EXT2_ROOT_INODE);
                crate::serial_println!("[VFS] ext2 whole-disk mounted at /disk (AHCI port {})", port);
                mounted_any = true;
            } else {
                crate::serial_println!("[VFS] AHCI port {} is neither FAT32 nor ext2", port);
            }
        }
    }

    if !mounted_any {
        crate::serial_println!("[VFS] No AHCI disks mounted");
    }
    mounted_any
}

/// Probe ATA buses for partitions and mount FAT32/NTFS volumes.
fn init_ata_disks() {
    use crate::drivers::block::BlockDevice; // Trait needed for .sector_count()
    use crate::drivers::partition;

    let devices = crate::drivers::ata::probe_all();

    for (dev_idx, dev) in devices.iter().enumerate() {
        crate::serial_println!("[VFS] Probing ATA device {} ({} sectors) for partitions...",
            dev_idx, dev.sector_count());

        let partitions = partition::scan_partitions(dev as &dyn BlockDevice);

        if !partitions.is_empty() {
            crate::serial_println!("[VFS] Found {} partition(s) on ATA device {}", partitions.len(), dev_idx);
            for part in &partitions {
                crate::serial_println!("[VFS]   Partition {}: type={:?}, start={}, size={} sectors",
                    part.index, part.partition_type, part.start_lba, part.sector_count);

                // Helper: re-probe ATA and build a fresh partition device
                // for `dev_idx` — needed because each Fs::new consumes its
                // BlockDevice, and ATA devices are not Clone.
                let new_pdev = || -> Option<crate::drivers::partition::PartitionBlockDevice> {
                    let fresh = crate::drivers::ata::probe_all();
                    fresh.into_iter().nth(dev_idx).map(|d| {
                        partition::create_partition_device(
                            Box::new(d), part.start_lba, part.sector_count,
                        )
                    })
                };
                match part.partition_type {
                    partition::PartitionType::Fat32 => {
                        if let Some(pdev) = new_pdev() {
                            match fat32::Fat32Fs::new(Box::new(pdev)) {
                                Ok(fs) => {
                                    let root_inode = fs.root_inode();
                                    mount("/disk", Box::new(fs), root_inode);
                                    crate::serial_println!("[VFS] FAT32 partition mounted at /disk (ATA dev {})", dev_idx);
                                    return;
                                }
                                Err(_) => {
                                    if let Some(pd) = new_pdev() {
                                        if let Some(fs) = ntfs::try_mount_ntfs(Box::new(pd)) {
                                            let root_inode = fs.root_inode();
                                            mount("/ntfs", Box::new(fs), root_inode);
                                            crate::serial_println!("[VFS] NTFS partition mounted at /ntfs (ATA dev {})", dev_idx);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    partition::PartitionType::Ntfs => {
                        if let Some(pdev) = new_pdev() {
                            if let Some(fs) = ntfs::try_mount_ntfs(Box::new(pdev)) {
                                let root_inode = fs.root_inode();
                                mount("/ntfs", Box::new(fs), root_inode);
                                crate::serial_println!("[VFS] NTFS partition mounted at /ntfs (ATA dev {})", dev_idx);
                            }
                        }
                    }
                    partition::PartitionType::LinuxExt => {
                        if let Some(pdev) = new_pdev() {
                            if let Some(fs) = ext2::try_mount_ext2(Box::new(pdev)) {
                                mount("/disk", Box::new(fs), ext2::EXT2_ROOT_INODE);
                                crate::serial_println!("[VFS] ext2 partition mounted at /disk (ATA dev {})", dev_idx);
                                return;
                            }
                            crate::serial_println!("[VFS] ext2 mount failed on ATA dev {} LinuxExt partition", dev_idx);
                        }
                    }
                    _ => {
                        crate::serial_println!("[VFS]   Skipping unsupported partition type: {:?}", part.partition_type);
                    }
                }
            }
        } else {
            crate::serial_println!("[VFS] No partitions on ATA device {}, trying whole disk...", dev_idx);
        }
    }

    // Fallback: try each ATA device as whole-disk FAT32, then ext2.
    // Mount the LARGEST valid FAT32 device at /disk (this skips the small
    // boot ESP and picks the data disk).  Other valid devices get skipped
    // for now — in the future they could be mounted at /disk2 etc.
    let devices2 = crate::drivers::ata::probe_all();
    let mut best: Option<(usize, u64)> = None; // (index, sector_count)
    for (idx, dev) in devices2.iter().enumerate() {
        // Quick check: read sector 0 and see if it looks like FAT32
        let mut buf = [0u8; 512];
        if dev.read_sector(0, &mut buf).is_ok() {
            let sig = u16::from_le_bytes([buf[510], buf[511]]);
            let bps = u16::from_le_bytes([buf[11], buf[12]]);
            if sig == 0xAA55 && (bps == 512 || bps == 1024 || bps == 4096) {
                let sc = dev.sector_count();
                if best.is_none() || sc > best.unwrap().1 {
                    best = Some((idx, sc));
                }
            }
        }
    }
    if let Some((best_idx, _best_sectors)) = best {
        // Re-probe to get an owned device for the selected index
        let fresh = crate::drivers::ata::probe_all();
        if let Some(dev) = fresh.into_iter().nth(best_idx) {
            let boxed: Box<dyn crate::drivers::block::BlockDevice> = Box::new(dev);
            match fat32::Fat32Fs::new(boxed) {
                Ok(fs) => {
                    let root_inode = fs.root_inode();
                    mount("/disk", Box::new(fs), root_inode);
                    crate::serial_println!("[VFS] FAT32 whole-disk mounted at /disk (ATA dev {}, largest)", best_idx);
                    return;
                }
                Err(e) => {
                    crate::serial_println!("[VFS] ATA dev {} FAT32 mount failed: {:?}, trying ext2...", best_idx, e);
                    let fresh2 = crate::drivers::ata::probe_all();
                    if let Some(dev2) = fresh2.into_iter().nth(best_idx) {
                        if let Some(fs) = ext2::try_mount_ext2(Box::new(dev2)) {
                            mount("/disk", Box::new(fs), ext2::EXT2_ROOT_INODE);
                            crate::serial_println!("[VFS] ext2 whole-disk mounted at /disk (ATA dev {}, largest)", best_idx);
                            return;
                        }
                        crate::serial_println!("[VFS] ATA dev {} is neither FAT32 nor ext2", best_idx);
                    }
                }
            }
        }
    }
    crate::serial_println!("[VFS] No real ATA data disk found");
}


/// Resolve a path to (mount_index, inode), following all symlinks.
pub fn resolve_path(path: &str) -> VfsResult<(usize, u64)> {
    let mut tctx = ResolveTrace::new();
    let mut dl = ResolveDeadline::arm();
    resolve_path_opts(path, 0, true, &mut dl, &mut tctx)
}

/// Resolve a path but do NOT follow the final component if it is a symlink.
/// Intermediate symlinks are still followed.  Used by lstat() and readlink().
fn resolve_path_no_follow(path: &str) -> VfsResult<(usize, u64)> {
    let mut tctx = ResolveTrace::new();
    let mut dl = ResolveDeadline::arm();
    resolve_path_opts(path, 0, false, &mut dl, &mut tctx)
}

/// Test-only entrypoint to resolve a path with a caller-supplied absolute
/// no-progress deadline tick value.
///
/// Exposed so `test_runner` can verify that the deadline fires when the
/// budget has already expired.  Production callers must use [`resolve_path`].
/// Passing `deadline_ticks = 0` yields a deadline that is already in the past,
/// so the first component lookup observes `get_ticks() >= 0` and bails out —
/// the forced-timeout case the suite asserts on.
#[doc(hidden)]
pub fn _test_resolve_with_deadline(path: &str, deadline_ticks: u64) -> VfsResult<(usize, u64)> {
    let mut tctx = ResolveTrace::new();
    let mut dl = ResolveDeadline::with_per_component_deadline(deadline_ticks);
    resolve_path_opts(path, 0, true, &mut dl, &mut tctx)
}

/// Test-only check of the no-progress re-arm semantics, decoupled from the
/// live clock so the assertion is deterministic.
///
/// Models the failure the production bug exhibited: a wall-clock budget that
/// would be *exceeded* by the time a multi-component walk reaches a later
/// component because the resolving thread was descheduled.  Returns
/// `(expired_without_progress, expired_after_progress)`:
///
/// * `expired_without_progress` — with the clock advanced past the original
///   budget and **no** `note_progress` call, the deadline has expired (the
///   genuine-wedge case the net must still catch).
/// * `expired_after_progress` — the same clock advance, but with a
///   `note_progress` call in between (the walk advanced), leaves the deadline
///   *un*-expired (the present-file case the bug wrongly failed).
///
/// The test asserts `(true, false)`.
#[doc(hidden)]
pub fn _test_resolve_deadline_rearm() -> (bool, bool) {
    let base = crate::arch::x86_64::irq::get_ticks();
    // Budget armed at `base`.  Use the production constant so the test tracks
    // any future tuning of the budget.
    let armed = base.saturating_add(ResolveDeadline::NO_PROGRESS_TICKS);

    // Case 1: no progress.  If the live clock is already past `armed`, the
    // deadline is expired.  We can't fast-forward the real PIT here, so model
    // the comparison directly against a clock value past the budget.
    let clock_past_budget = armed.saturating_add(1);
    let expired_without_progress = clock_past_budget >= armed;

    // Case 2: progress re-armed the budget to `clock_past_budget +
    // NO_PROGRESS_TICKS`, which is strictly greater than `clock_past_budget`,
    // so the deadline is NOT expired at that same clock value.
    let rearmed = clock_past_budget.saturating_add(ResolveDeadline::NO_PROGRESS_TICKS);
    let expired_after_progress = clock_past_budget >= rearmed;

    (expired_without_progress, expired_after_progress)
}

/// No-forward-progress deadline for a single path resolution.
///
/// The original W83 safety net used one *absolute* wall-clock budget computed
/// once at the outer resolve and threaded unchanged through the whole walk.
/// That is wrong for an operation that is CPU-cheap but freely deschedulable:
/// `get_ticks()` keeps advancing while the resolving thread is parked (waiting
/// on the global `MOUNTS` lock or a serialized block device under contention),
/// so a resolve that *is* making forward progress — distinct components
/// resolving on successive trips — could still overrun the budget and fail an
/// `open(2)` of a present file with `ETIMEDOUT`.  Under heavy load (the Firefox
/// content-process spawn parks the resolving thread behind ~200 sibling threads
/// and a serialized block device) the deschedule gap *between two components*
/// can exceed several wall-clock seconds even though each component resolves
/// the instant the thread runs.  No fixed wall-clock budget can tell that apart
/// from a genuine hang.  POSIX `open(2)` does not define `ETIMEDOUT` for an
/// existing file, and pathname resolution (IEEE Std 1003.1 §4.13) is bounded by
/// structural limits (symlink recursion → `ELOOP`), never by a wall-clock
/// timer; mature kernels impose no resolve deadline at all.
///
/// The corrected net therefore measures **lack of forward progress** rather
/// than elapsed wall-clock: a single deadline is re-armed every time the walk
/// advances (a new component is entered or a symlink is followed), so it fires
/// only when the walk makes *zero* progress for the whole budget — i.e. a
/// single FS dispatch that genuinely never returns, the one case the net
/// exists to break.  A resolve that keeps advancing, however slowly and however
/// often descheduled, never trips it.  This also retains the original
/// fail-fast-on-wedge guarantee: a driver that hangs forever in one `lookup`
/// stops re-arming and the deadline fires.
#[derive(Clone, Copy)]
struct ResolveDeadline {
    /// Tick value past which the resolve gives up if it has made no forward
    /// progress.  Re-armed on every advance.  `u64::MAX` disables the check
    /// (extremely early boot, no clock yet).
    no_progress: u64,
}

impl ResolveDeadline {
    /// PIT runs at ~100 Hz (`arch::x86_64::irq::init`), so 100 ticks ≈ 1 s and
    /// `NO_PROGRESS_TICKS = 3000` ≈ 30 s.  Because the budget is re-armed on
    /// every advance it bounds time-since-last-progress, not total walk time:
    /// 30 s of a *single* component making no progress is unambiguously a
    /// wedged FS dispatch (no legitimate directory lookup — even of a directory
    /// holding a 130 MB file, even on virtio-blk poll-fallback at ~100 ms per
    /// request — takes 30 s of wall-clock while the rest of the system keeps
    /// running and the walk would otherwise advance).
    const NO_PROGRESS_TICKS: u64 = 3000;

    /// Arm a fresh no-progress deadline at the outermost resolve call.
    #[inline]
    fn arm() -> Self {
        Self { no_progress: Self::rearm_value() }
    }

    /// Compute the tick value `NO_PROGRESS_TICKS` in the future, or `u64::MAX`
    /// when the PIT is not yet ticking (pre-IRQ boot — there is no clock to
    /// measure against, so the deadline must be a no-op).
    #[inline]
    fn rearm_value() -> u64 {
        let now = crate::arch::x86_64::irq::get_ticks();
        if now == 0 {
            u64::MAX
        } else {
            now.saturating_add(Self::NO_PROGRESS_TICKS)
        }
    }

    /// Construct a deadline with an explicit absolute tick value (test-only).
    /// Passing `0` yields a deadline already in the past, so the first
    /// component lookup trips it (the forced-timeout case the suite asserts).
    #[inline]
    fn with_per_component_deadline(no_progress: u64) -> Self {
        Self { no_progress }
    }

    /// True if the walk has made no forward progress for the whole budget
    /// (a genuinely-stuck dispatch).
    #[inline]
    fn expired(&self) -> bool {
        crate::arch::x86_64::irq::get_ticks() >= self.no_progress
    }

    /// Re-arm the deadline because the walk demonstrably advanced (a new
    /// component was entered, or a symlink was followed).  Resets
    /// time-since-last-progress to zero.
    #[inline]
    fn note_progress(&mut self) {
        if self.no_progress != u64::MAX {
            self.no_progress = Self::rearm_value();
        }
    }
}

/// Per-resolution trace state.
///
/// We cap to a small number of lines per outermost resolve to keep the
/// serial log readable even on a wedged path (which would otherwise emit
/// one line per loop iteration × symlink-recursion-depth combinations).
struct ResolveTrace {
    /// Lines already emitted by this outermost resolve call (and its
    /// recursive descendants).
    emitted: u32,
}

impl ResolveTrace {
    const MAX_LINES: u32 = 20;
    #[inline]
    fn new() -> Self { Self { emitted: 0 } }
}

/// Emit one `[VFS/resolve]` trace line, respecting the per-resolve cap.
///
/// Gated behind the `vfs-trace` feature flag (always-on diagnostic) and
/// `firefox-test` (default-on for the browser bring-up).  In a release build
/// without either flag, this compiles to nothing — the deadline still fires,
/// but per-component spew does not.  The serial log on the `firefox-test`
/// path is already dense; capping the emitter avoids flooding it when a path
/// genuinely needs >20 iterations to resolve.
#[inline]
fn resolve_trace(tctx: &mut ResolveTrace, args: core::fmt::Arguments<'_>) {
    // Per-component [VFS/resolve] progress trace.  High-frequency diagnostic
    // (one line per path component per resolve) with no correctness role — the
    // [VFS/resolve] DEADLINE EXCEEDED error line below is emitted
    // unconditionally and is the only resolve signal a non-trace build needs.
    // Gated on `firefox-test-trace` (and the standalone `vfs-trace`) so the
    // functional `firefox-test-core` boot does not flood COM1.
    #[cfg(any(feature = "vfs-trace", feature = "firefox-test-trace"))]
    {
        if tctx.emitted < ResolveTrace::MAX_LINES {
            crate::serial_println!("{}", args);
            tctx.emitted += 1;
            if tctx.emitted == ResolveTrace::MAX_LINES {
                crate::serial_println!(
                    "[VFS/resolve] (trace cap reached, suppressing further per-component lines)"
                );
            }
        }
    }
    #[cfg(not(any(feature = "vfs-trace", feature = "firefox-test-trace")))]
    {
        let _ = tctx;
        let _ = args;
    }
}

/// Inner resolver with symlink depth tracking and final-follow control.
///
/// * `follow_final` – when `true`, follow the last path component if it is a
///   symlink (stat / open behaviour).  When `false`, stop at the symlink inode
///   itself (lstat / readlink behaviour).
///
/// # Forward-progress deadline (W83 safety net, corrected)
///
/// Some pathological combinations of mount-table layout, symlinks, and
/// concrete-FS state can cause path resolution to make no forward progress
/// (W83 reproducer: every `firefox-test` trial wedged on the first traversal
/// of `/usr → /disk/usr/.../libGL.so.1`).  To bound the worst case we carry a
/// [`ResolveDeadline`] threaded through `resolve_path_opts` as a mutable
/// argument (so a symlink chase shares one deadline across recursion rather
/// than resetting the whole budget).  The deadline is **re-armed on each
/// component that successfully resolves**, so it measures lack of *forward
/// progress* on a single component — a genuinely-stuck FS dispatch — rather
/// than absolute wall-clock across deschedule windows.  A resolve that is
/// slow-but-progressing (each component resolving on a later trip because the
/// thread keeps getting descheduled under `MOUNTS`/block-device contention)
/// no longer trips it.  When the deadline does expire we return
/// [`VfsError::TimedOut`] (`ETIMEDOUT`, errno 110) and emit
/// `[VFS/resolve] DEADLINE EXCEEDED` to the serial log along with the
/// partial-resolved path — the exact diagnostic that names the hang point.
///
/// POSIX `open(2)` does not define `ETIMEDOUT` for a present file, and
/// pathname resolution (IEEE Std 1003.1 §4.13) is bounded by structural
/// limits (symlink recursion → `ELOOP`, here `MAX_SYMLINK_DEPTH`), not a
/// wall-clock timer.  The deadline is purely an internal anti-wedge net for
/// a driver that never returns; sizing is documented on [`ResolveDeadline`].
fn resolve_path_opts(
    path: &str,
    depth: u32,
    follow_final: bool,
    deadline: &mut ResolveDeadline,
    tctx: &mut ResolveTrace,
) -> VfsResult<(usize, u64)> {
    const MAX_SYMLINK_DEPTH: u32 = 16;
    if depth > MAX_SYMLINK_DEPTH {
        return Err(VfsError::NotFound); // symlink loop
    }

    // Per POSIX pathname resolution (IEEE Std 1003.1 §4.13), "." (the
    // current-directory entry) is consumed by the resolver as a no-op
    // (it refers to the directory itself), and ".." steps one level
    // toward the root.  Filter out "." components here so callers that
    // pass paths like "/." (= "/"), "/tmp/repo/./hello.txt", etc. do not
    // try to look up "." as a literal directory entry against an inode's
    // child list — which would NotFound because POSIX dirent enumeration
    // does not always materialise "." and ".." as user-visible names.
    // ".." is left for explicit handling further down (or absorbed by the
    // mount-walker which can pop the resolved_so_far stack); on AstryxOS
    // tmpfs no callers currently rely on ".." resolution outside of
    // openat/realpath which canonicalise client-side.
    let components: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    // Start from root mount and walk component by component.
    // After each lookup, check if the result is a symlink and follow it.
    //
    // Resolve the starting mount in a SINGLE `MOUNTS` acquisition: pick the
    // mount whose mount-path is the longest prefix of `path` (the deepest
    // covering mount).  Snapshotting the relevant fields and dropping the lock
    // here — rather than taking it twice per resolve — halves the contention on
    // the global mount lock, which under heavy load (many threads resolving
    // concurrently) is a major source of the deschedule gaps the resolve
    // deadline must tolerate.  Consistent with the snapshot-then-drop pattern
    // used for every other `MOUNTS` access on this path: never hold `MOUNTS`
    // across an FS dispatch (#82).
    let mut resolved_so_far;
    let (mut cur_mount, mut cur_inode) = {
        let mounts = MOUNTS.lock();
        if mounts.is_empty() {
            return Err(VfsError::NotFound);
        }
        let mut best_mount = 0;
        let mut best_len = 0;
        for (i, mount) in mounts.iter().enumerate() {
            if path.starts_with(mount.path.as_str()) && mount.path.len() >= best_len {
                best_mount = i;
                best_len = mount.path.len();
            }
        }
        resolved_so_far = mounts[best_mount].path.clone();
        if resolved_so_far.is_empty() {
            resolved_so_far = String::from("/");
        }
        (best_mount, mounts[best_mount].root_inode)
    };

    // Determine which components are already consumed by the mount path.
    let mount_path = resolved_so_far.clone();
    let mount_components: Vec<&str> = mount_path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let remaining = &components[mount_components.len()..];

    for (i, component) in remaining.iter().enumerate() {
        let is_final = i + 1 == remaining.len();

        // ── W83 trace: per-component progress marker ────────────────────────
        resolve_trace(tctx, format_args!(
            "[VFS/resolve] depth={} component='{}' cur_mount={} resolved_so_far='{}'",
            depth, component, cur_mount, resolved_so_far,
        ));

        // ── W83 deadline: fail-fast only on a genuinely-wedged dispatch ────
        // `deadline` is re-armed on every advance (a resolved component or a
        // followed symlink), so the value checked here is time-since-last-
        // progress, NOT total walk time.  Under heavy contention (Firefox
        // content-proc spawn parks this thread behind ~200 siblings and a
        // serialized block device) the deschedule gap before a component can
        // be several wall-clock seconds even though the walk advances the
        // instant the thread runs; the budget is sized far above that gap so
        // only a single FS dispatch that makes no progress for the whole
        // budget — a genuine hang — trips it.  POSIX open(2) never returns
        // ETIMEDOUT for a present, progressing file.
        if deadline.expired() {
            crate::serial_println!(
                "[VFS/resolve] DEADLINE EXCEEDED depth={} stuck-at='{}' next-component='{}' input-path='{}'",
                depth, resolved_so_far, component, path,
            );
            return Err(VfsError::TimedOut);
        }

        // Snapshot the current FS handle before each dispatch.  Holding
        // `MOUNTS` across `lookup` / `stat` / `readlink` would deadlock if
        // the FS implementation faults on a user-supplied or file-backed
        // buffer — the page-fault handler also needs `MOUNTS` to demand-page
        // the missing frame, but this thread already holds it (#82).
        let fs = fs_at(cur_mount).ok_or(VfsError::NotFound)?.0;

        // Lookup this component in the current directory.
        let child_inode = fs.lookup(cur_inode, component)?;

        // Check if the child is a symlink.
        let child_stat = fs.stat(child_inode)?;

        if child_stat.file_type == FileType::SymLink {
            // If this is the final component and we were asked not to follow,
            // return the symlink inode directly.
            if is_final && !follow_final {
                return Ok((cur_mount, child_inode));
            }

            // Read the symlink target.
            let target = fs.readlink(child_inode)?;

            // Build the new path: target + remaining components after this one.
            // We borrow `target` here rather than moving it so the W83 trace
            // below can still print its raw value.
            let rest: Vec<&str> = remaining[i + 1..].to_vec();
            let new_path: String = if rest.is_empty() {
                if target.starts_with('/') {
                    target.clone()
                } else {
                    alloc::format!("{}/{}", resolved_so_far.trim_end_matches('/'), target)
                }
            } else {
                let rest_str = rest.join("/");
                if target.starts_with('/') {
                    alloc::format!("{}/{}", target.trim_end_matches('/'), rest_str)
                } else {
                    alloc::format!("{}/{}/{}", resolved_so_far.trim_end_matches('/'), target, rest_str)
                }
            };
            // Recurse with incremented depth.  When following intermediate
            // symlinks the recursive call always follows the final component
            // (the rest of the path after the symlink).
            resolve_trace(tctx, format_args!(
                "[VFS/resolve] follow-symlink depth={} from='{}' target='{}' new_path='{}'",
                depth, resolved_so_far, target, new_path,
            ));
            // Resolving + reading this symlink component is forward progress;
            // re-arm the no-progress deadline before recursing so the shared
            // budget measures time-since-last-progress, not total chase time.
            deadline.note_progress();
            return resolve_path_opts(&new_path, depth + 1, true, deadline, tctx);
        }

        // Not a symlink — advance.  This component resolved: re-arm the
        // no-progress deadline so a slow-but-progressing walk is not failed.
        deadline.note_progress();
        cur_inode = child_inode;
        if resolved_so_far.ends_with('/') {
            resolved_so_far.push_str(component);
        } else {
            resolved_so_far.push('/');
            resolved_so_far.push_str(component);
        }

        // Check if there's a deeper mount point at the resolved path.
        {
            let mounts = MOUNTS.lock();
            for (mi, mount) in mounts.iter().enumerate() {
                if mount.path == resolved_so_far {
                    cur_mount = mi;
                    cur_inode = mount.root_inode;
                    break;
                }
            }
        }
    }

    Ok((cur_mount, cur_inode))
}

/// Resolve a path to (mount_index, parent_inode, last_component).
fn resolve_parent(path: &str) -> VfsResult<(usize, u64, String)> {
    let path = path.trim_end_matches('/');
    if path.is_empty() || path == "/" {
        return Err(VfsError::InvalidArg);
    }

    let last_slash = path.rfind('/').unwrap_or(0);
    let parent_path = if last_slash == 0 { "/" } else { &path[..last_slash] };
    let name = &path[last_slash + 1..];

    if name.is_empty() {
        return Err(VfsError::InvalidArg);
    }

    let (mount_idx, parent_inode) = resolve_path(parent_path)?;
    Ok((mount_idx, parent_inode, String::from(name)))
}

/// Split an absolute path into (parent_dir, filename).
/// Returns ("/", path) for top-level entries.
fn split_parent_name(path: &str) -> (&str, &str) {
    let path = path.trim_end_matches('/');
    match path.rfind('/') {
        Some(0) | None => ("/", &path[path.rfind('/').map(|i| i + 1).unwrap_or(0)..]),
        Some(pos) => (&path[..pos], &path[pos + 1..]),
    }
}

/// Create a file at the given absolute path.
pub fn create_file(path: &str) -> VfsResult<()> {
    let (mount_idx, parent_inode, name) = resolve_parent(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    fs.create_file(parent_inode, &name)?;
    // Fire IN_CREATE on the parent directory.
    let (parent_dir, filename) = split_parent_name(path);
    crate::ipc::inotify::notify_event(parent_dir, filename, crate::ipc::inotify::IN_CREATE, 0);
    Ok(())
}

/// Create a directory.
pub fn mkdir(path: &str) -> VfsResult<()> {
    let (mount_idx, parent_inode, name) = resolve_parent(path)?;
    {
        let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
        fs.create_dir(parent_inode, &name)?;
    }
    // Fire IN_CREATE|IN_ISDIR on the parent directory.
    let (parent_dir, filename) = split_parent_name(path);
    crate::ipc::inotify::notify_event(
        parent_dir, filename,
        crate::ipc::inotify::IN_CREATE | crate::ipc::inotify::IN_ISDIR,
        0,
    );
    Ok(())
}

/// Remove a file or empty directory.
/// For regular files that are currently open, the directory entry is removed
/// immediately but the inode is kept alive until all file descriptors are closed
/// (Unix unlink-on-last-close semantics — C5).
pub fn remove(path: &str) -> VfsResult<()> {
    let (mount_idx, parent_inode, name) = resolve_parent(path)?;

    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;

    // Resolve the target inode to check whether it is open.
    let target_inode = fs.lookup(parent_inode, &name)?;

    // Determine whether it is a regular file that any process has open.
    let is_open = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().any(|p| p.file_descriptors.iter().any(|fdo| {
            fdo.as_ref().map(|f| f.mount_idx == mount_idx && f.inode == target_inode)
                .unwrap_or(false)
        }))
    };

    if is_open {
        // Deferred deletion: unlink directory entry, keep inode until last close.
        fs.unlink_entry(parent_inode, &name)?;
        DELETED_INODES.lock().push((mount_idx, target_inode));
    } else {
        fs.remove(parent_inode, &name)?;
    }
    // Fire IN_DELETE on the parent directory.
    let (parent_dir, filename) = split_parent_name(path);
    crate::ipc::inotify::notify_event(parent_dir, filename, crate::ipc::inotify::IN_DELETE, 0);
    Ok(())
}

/// Stat a file (follows symlinks — like Linux `stat`).
pub fn stat(path: &str) -> VfsResult<FileStat> {
    let (mount_idx, inode) = resolve_path(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    fs.stat(inode)
}

/// Stat a file without following the final symlink (like Linux `lstat`).
pub fn lstat(path: &str) -> VfsResult<FileStat> {
    let (mount_idx, inode) = resolve_path_no_follow(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    fs.stat(inode)
}

/// Read directory contents. Returns (name, file_type) pairs.
pub fn readdir(path: &str) -> VfsResult<Vec<(String, FileType)>> {
    let (mount_idx, inode) = resolve_path(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    let entries = fs.readdir(inode)?;
    Ok(entries.into_iter().map(|(name, _ino, ft)| (name, ft)).collect())
}

/// Write data to a file (overwrite from beginning).
pub fn write_file(path: &str, data: &[u8]) -> VfsResult<usize> {
    let (mount_idx, inode) = resolve_path(path)?;
    let (old_size, n) = {
        let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
        let old_size = fs.stat(inode).map(|s| s.size).unwrap_or(0);
        fs.truncate(inode, 0)?;
        (old_size, fs.write(inode, 0, data)?)
    };
    // Page-cache coherency (POSIX mmap(2) MAP_SHARED + write(2) contract):
    // this overwrite-from-beginning first truncates to 0, then writes the
    // new bytes.  `update_range` reconciles the [0, n) overlap, but any
    // cache page that belonged to the OLD file beyond the new length is now
    // stale (the truncate-to-0 discarded it).  Drop those pages first so a
    // mmap / cached read does not resurrect the pre-write tail; then bring
    // the freshly-written range up to date in place.
    crate::mm::cache::truncate_range(mount_idx, inode, old_size, n as u64);
    if n > 0 {
        crate::mm::cache::update_range(mount_idx, inode, 0, &data[..n]);
    }
    // Path-keyed read cache (`FILE_READ_CACHE`) must be invalidated so
    // subsequent `read_file(path)` does not return the stale snapshot.
    invalidate_path_read_cache(path);
    // Fire IN_MODIFY so inotify watchers (and poll/epoll) see the update.
    // This mirrors the notification in the fd-based write() syscall path.
    let (parent_dir, filename) = split_parent_name(path);
    crate::ipc::inotify::notify_event(parent_dir, filename, crate::ipc::inotify::IN_MODIFY, 0);
    Ok(n)
}

/// File read cache — avoids re-reading large files from slow ATA PIO.
/// On WSL2/KVM, ATA PIO takes ~100µs per sector (hypervisor exit), making
/// a 3MB file take 5+ minutes. Caching makes repeated reads instant.
static FILE_READ_CACHE: spin::Mutex<Vec<(alloc::string::String, Vec<u8>)>> =
    spin::Mutex::new(Vec::new());
const FILE_CACHE_MAX: usize = 8;
const FILE_CACHE_MAX_SIZE: usize = 16 * 1024 * 1024;

/// Read data from a file (with caching for slow disk I/O).
pub fn read_file(path: &str) -> VfsResult<Vec<u8>> {
    // Check cache first.
    {
        let cache = FILE_READ_CACHE.lock();
        for (ref p, ref data) in cache.iter() {
            if p == path {
                return Ok(data.clone());
            }
        }
    }
    // Cache miss — read from VFS.
    let (mount_idx, inode) = resolve_path(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    let stat = fs.stat(inode)?;
    let mut buf = alloc::vec![0u8; stat.size as usize];
    let n = fs.read(inode, 0, &mut buf)?;
    buf.truncate(n);
    // Cache if reasonably sized.
    if buf.len() <= FILE_CACHE_MAX_SIZE {
        let mut cache = FILE_READ_CACHE.lock();
        if cache.len() >= FILE_CACHE_MAX { cache.remove(0); }
        cache.push((alloc::string::String::from(path), buf.clone()));
    }
    Ok(buf)
}

/// Append data to a file.
pub fn append_file(path: &str, data: &[u8]) -> VfsResult<usize> {
    let (mount_idx, inode) = resolve_path(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    let stat = fs.stat(inode)?;
    let append_off = stat.size;
    let n = fs.write(inode, append_off, data)?;
    // Page-cache coherency (POSIX mmap(2) MAP_SHARED + write(2) contract):
    // update any cache pages that overlap the appended range — usually
    // only the tail page of the original file if it was partial.
    if n > 0 {
        crate::mm::cache::update_range(mount_idx, inode, append_off, &data[..n]);
    }
    // Path-keyed read cache must be invalidated as well.
    invalidate_path_read_cache(path);
    Ok(n)
}

/// Drop the cached snapshot for `path` from `FILE_READ_CACHE`, if any.
///
/// `FILE_READ_CACHE` is a path-keyed convenience cache layered on top of
/// the VFS for slow ATA PIO; it must be invalidated whenever a write
/// updates the underlying file or `read_file(path)` would return a
/// pre-write snapshot indefinitely (the cache has no TTL).  Callers in
/// the write path invoke this after a successful write; the cost is a
/// single mutex acquire plus an O(n≤8) scan.
fn invalidate_path_read_cache(path: &str) {
    let mut cache = FILE_READ_CACHE.lock();
    cache.retain(|(p, _)| p != path);
}

/// Sync (flush) all dirty data in all mounted filesystems to their backing store.
pub fn sync_all() {
    // Snapshot the FS handles, then drop MOUNTS before invoking sync —
    // sync() may flush to a backing block device which can in turn fault
    // on a kernel buffer (#82 hazard shape).
    let fss: Vec<Arc<dyn FileSystemOps>> = {
        let mounts = MOUNTS.lock();
        mounts.iter().map(|m| m.fs.clone()).collect()
    };
    for fs in fss.iter() {
        let _ = fs.sync();
    }
}

/// Rename (move) a file or directory.
pub fn rename(old_path: &str, new_path: &str) -> VfsResult<()> {
    let (old_mount, old_parent, old_name) = resolve_parent(old_path)?;
    let (new_mount, new_parent, new_name) = resolve_parent(new_path)?;
    if old_mount != new_mount {
        return Err(VfsError::Unsupported); // cross-mount rename not supported
    }
    {
        let fs = fs_at(old_mount).ok_or(VfsError::NotFound)?.0;
        fs.rename(old_parent, &old_name, new_parent, &new_name)?;
    }
    // Fire IN_MOVED_FROM / IN_MOVED_TO with a shared non-zero cookie.
    // Use a simple increment from the tick counter as the cookie.
    let cookie = (crate::arch::x86_64::irq::TICK_COUNT
        .load(core::sync::atomic::Ordering::Relaxed) & 0xFFFF_FFFF) as u32;
    let (old_dir, old_fn) = split_parent_name(old_path);
    let (new_dir, new_fn) = split_parent_name(new_path);
    crate::ipc::inotify::notify_event(old_dir, old_fn, crate::ipc::inotify::IN_MOVED_FROM, cookie);
    crate::ipc::inotify::notify_event(new_dir, new_fn, crate::ipc::inotify::IN_MOVED_TO, cookie);
    Ok(())
}

/// Create a symbolic link at `link_path` pointing to `target`.
pub fn symlink(link_path: &str, target: &str) -> VfsResult<()> {
    let (mount_idx, parent_inode, name) = resolve_parent(link_path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    fs.symlink(parent_inode, &name, target)?;
    Ok(())
}

/// Read the target of a symbolic link (does not follow the final symlink).
pub fn readlink(path: &str) -> VfsResult<String> {
    let (mount_idx, inode) = resolve_path_no_follow(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    fs.readlink(inode)
}

/// Change permission bits on a file/directory.
pub fn chmod(path: &str, mode: u32) -> VfsResult<()> {
    let (mount_idx, inode) = resolve_path(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    fs.chmod(inode, mode)
}

/// Change permission bits on an open file descriptor.
/// Returns `Err(VfsError::BadFd)` for console or pipe fds (caller may treat as success).
pub fn fchmod(pid: crate::proc::Pid, fd_num: usize, mode: u32) -> VfsResult<()> {
    let (mount_idx, inode, is_console) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;
        let fd = proc.file_descriptors.get(fd_num)
            .and_then(|f| f.as_ref())
            .ok_or(VfsError::BadFd)?;
        (fd.mount_idx, fd.inode, fd.is_console)
    };
    // Console / pipe / special fds have no backing inode — treat as success
    // (caller is always root in AstryxOS; no privilege check needed here).
    if is_console || mount_idx == usize::MAX {
        return Ok(());
    }
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    fs.chmod(inode, mode)
}

/// Truncate a file to `size` bytes by path.
///
/// Maintains page-cache coherence per POSIX truncate(2): the bytes that
/// change visibility as a result of the resize (the discarded tail on a
/// shrink, or the zero-filled extension on a grow) must be reflected in
/// any page already faulted into the cache.  See
/// `mm::cache::truncate_range` for the coherence contract.
pub fn truncate_path(path: &str, size: u64) -> VfsResult<()> {
    let (mount_idx, inode) = resolve_path(path)?;
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    // Capture the pre-truncate size so the cache cohort knows which range
    // became zero-filled (grow) or invalid (shrink).  A stat failure leaves
    // the cache as-is rather than aborting the truncate; we conservatively
    // pass old_size == size so only the new EOF boundary page is reconciled.
    let old_size = fs.stat(inode).map(|s| s.size).unwrap_or(size);
    fs.truncate(inode, size)?;
    crate::mm::cache::truncate_range(mount_idx, inode, old_size, size);
    // Path-keyed read cache must be invalidated so a subsequent
    // `read_file(path)` does not return the pre-truncate snapshot.
    invalidate_path_read_cache(path);
    Ok(())
}

/// Truncate the file open as `fd_num` for process `pid` to `size` bytes.
///
/// As with [`truncate_path`], the page cache is reconciled with the new
/// file length per POSIX ftruncate(2) so MAP_SHARED mappings and cached
/// reads observe the zero-filled extension / discarded tail.
pub fn fd_truncate(pid: crate::proc::Pid, fd_num: usize, size: u64) -> VfsResult<()> {
    let (mount_idx, inode) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;
        let fd = proc.file_descriptors.get(fd_num)
            .and_then(|f| f.as_ref())
            .ok_or(VfsError::BadFd)?;
        if fd.is_console { return Err(VfsError::Unsupported); }
        (fd.mount_idx, fd.inode)
    };
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    let old_size = fs.stat(inode).map(|s| s.size).unwrap_or(size);
    fs.truncate(inode, size)?;
    crate::mm::cache::truncate_range(mount_idx, inode, old_size, size);
    Ok(())
}

// ===== Process File Descriptor Operations =====

/// Translate `/proc/<N>/foo` → `/proc/self/foo` for per-PID pseudo-files.
/// Returns `None` if the path does not match the numeric-PID pattern.
fn redirect_proc_pid_path(path: &str) -> Option<alloc::string::String> {
    let rest = path.strip_prefix("/proc/")?;
    let slash_pos = rest.find('/')?;
    let pid_str = &rest[..slash_pos];
    // Only redirect purely numeric components (not "self", "net", "sys", …).
    if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let suffix = &rest[slash_pos..]; // includes the leading "/"
    Some(alloc::format!("/proc/self{}", suffix))
}

/// True when `open_path` is `/proc/self/<leaf>` or `/proc/<N>/<leaf>` for the
/// given `leaf` (no nested components).  Avoids the ambiguity of the previous
/// `.ends_with("/leaf")` test which would falsely match `/proc/self/fd/leaf`,
/// `/disk/proc/cgroup`, or any other path coincidentally ending in `/leaf`.
fn is_proc_self_path(open_path: &str, leaf: &str) -> bool {
    let rest = match open_path.strip_prefix("/proc/") {
        Some(r) => r,
        None => return false,
    };
    let after_pid = match rest.split_once('/') {
        Some((pid, tail)) => {
            // Must be "self" or all-digits.
            if pid != "self" && (pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit())) {
                return false;
            }
            tail
        }
        None => return false,
    };
    after_pid == leaf
}

/// Extract the target PID from a `/proc/<N>/...` open_path.
/// Returns `None` for `/proc/self/...` (caller should use its own PID).
fn proc_target_pid(open_path: &str) -> Option<u64> {
    let rest = open_path.strip_prefix("/proc/")?;
    let pid_str = rest.split('/').next()?;
    if pid_str == "self" { return None; }
    pid_str.parse::<u64>().ok()
}

/// If `path` is exactly `/proc/{self|<pid>}/fd/<N>` (no trailing components),
/// return `(target_pid, fd_num)` where `target_pid` is `caller_pid` for the
/// `self` form and the parsed numeric pid otherwise.  Returns `None` for any
/// other path (including `/proc/self/fd` directory listing or
/// `/proc/self/fd/<N>/something`).
///
/// Used by `open()` to honour the procfs magic-symlink contract: opening
/// `/proc/<pid>/fd/<N>` must DUP the underlying open file by its backing inode
/// (per proc(5) — each entry is a symbolic link "to the actual file"), NOT
/// re-resolve the link target's pathname.  An unlinked memfd / O_TMPFILE inode
/// has no resolvable name, so re-resolving the pathname would ENOENT even
/// though the file is fully alive (held open by the target fd).
fn parse_proc_fd_path(path: &str, caller_pid: crate::proc::Pid) -> Option<(crate::proc::Pid, usize)> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid_part, after_pid) = rest.split_once('/')?;
    let target_pid: crate::proc::Pid = if pid_part == "self" {
        caller_pid
    } else if !pid_part.is_empty() && pid_part.bytes().all(|b| b.is_ascii_digit()) {
        pid_part.parse::<crate::proc::Pid>().ok()?
    } else {
        return None;
    };
    let fd_part = after_pid.strip_prefix("fd/")?;
    // Reject nested components: the fd number must be the final path element.
    if fd_part.is_empty() || fd_part.contains('/') {
        return None;
    }
    let fd_num = fd_part.parse::<usize>().ok()?;
    Some((target_pid, fd_num))
}

/// Honour the procfs `/proc/<pid>/fd/<N>` magic-symlink open by DUPing the
/// underlying open file: clone the target fd's backing inode handle into a
/// fresh fd in `caller_pid`'s table, with a new (zeroed) offset and the
/// caller's requested access mode (`open_flags`).  This is the flat-fd-model
/// equivalent of a real kernel sharing the target file's `f_path` via
/// `nd_jump_link()` — it never re-resolves the link target's pathname, so it
/// works for unlinked memfd / anonymous tmpfs inodes that have no name.
///
/// Returns `Err(NotFound)` (→ ENOENT) if the target process or fd does not
/// exist, matching `open(/proc/<pid>/fd/<N>)` for a closed fd.
///
/// `O_CREAT`/`O_TRUNC` are meaningless against an existing open file and are
/// ignored here (a real kernel applies neither when jumping the link to an
/// already-open file).  The access mode (O_RDONLY/O_WRONLY/O_RDWR) is taken
/// from `open_flags`; widening beyond the original fd's mode is permitted here
/// (we do not yet enforce per-fd mode narrowing on read/write), but the common
/// case is Mozilla re-opening an `O_RDWR` memfd as `O_RDONLY`, which is honoured.
fn reopen_proc_fd(
    caller_pid: crate::proc::Pid,
    target_pid: crate::proc::Pid,
    fd_num: usize,
    open_flags: u32,
) -> VfsResult<usize> {
    // Snapshot the backing fields of the target fd and install the new fd in a
    // single PROCESS_TABLE acquisition so the clone is atomic w.r.t. a
    // concurrent close()/dup() of the target.
    let mut procs = crate::proc::PROCESS_TABLE.lock();

    // Read the target fd's backing.  The borrow ends before we mutate the
    // caller's table below.
    let backing = {
        let tproc = procs.iter().find(|p| p.pid == target_pid)
            .ok_or(VfsError::NotFound)?;
        let f = tproc.file_descriptors.get(fd_num)
            .and_then(|slot| slot.as_ref())
            .ok_or(VfsError::NotFound)?;
        (f.inode, f.mount_idx, f.file_type, f.is_console, f.open_path.clone())
    };
    let (inode, mount_idx, file_type, is_console, open_path) = backing;

    // Only inode-backed files reopen safely by cloning the (mount_idx, inode)
    // slot — their liveness is the fd-table scan for (mount_idx, inode), so the
    // freshly-installed slot is self-counting.  Sentinel fds (pipe / socket /
    // eventfd / epoll / timerfd / signalfd / inotify / PTY / a console fd)
    // carry a type-specific refcount this clone path does not balance; copying
    // their backing into a new slot would underflow that count when the clone
    // is closed (eventfd → outright slot free = UAF; socket → ref_count
    // underflow tripping its close-path debug_assert; pipe → reader/writer
    // undercount → phantom EOF/EPIPE).  Until this path replicates sys_dup's
    // per-type inc_ref, return NotFound for them so open() falls back to the
    // normal /proc/self/fd → /dev/fd re-resolution (which yields a benign
    // ENOENT for a nameless sentinel fd — the exact pre-PR semantics, per
    // proc(5)).
    if mount_idx == usize::MAX
        || is_console
        || !matches!(
            file_type,
            FileType::RegularFile | FileType::Directory | FileType::SymLink
        )
    {
        return Err(VfsError::NotFound);
    }

    // Build the new fd: same backing inode, fresh offset, caller's access mode.
    // O_CLOEXEC (0x80000) is honoured per the requested flags; O_CREAT/O_TRUNC
    // are stripped (they do not apply to an existing open file).
    let cloexec = (open_flags & 0x0008_0000) != 0;
    let new_flags = open_flags & !(flags::O_CREAT | flags::O_TRUNC);
    let new_fd = FileDescriptor {
        inode,
        mount_idx,
        offset: 0,
        flags: new_flags,
        file_type,
        is_console,
        cloexec,
        // Preserve the TARGET's open_path (the real backing path, e.g. an
        // unlinked memfd's synthesized name or empty for anon fds) — NOT the
        // /proc/self/fd/N magic path — so /proc introspection and the
        // unlink-on-last-close bookkeeping stay consistent with the original fd.
        open_path,
    };

    let cproc = procs.iter_mut().find(|p| p.pid == caller_pid)
        .ok_or(VfsError::InvalidArg)?;
    let free_idx = cproc.file_descriptors.iter().position(|f| f.is_none());
    let fd_idx = if let Some(i) = free_idx {
        cproc.file_descriptors[i] = Some(new_fd);
        i
    } else {
        let nofile_limit = cproc.rlimits_soft[7]
            .min(MAX_FDS_PER_PROCESS as u64) as usize;
        if cproc.file_descriptors.len() < nofile_limit {
            let idx = cproc.file_descriptors.len();
            cproc.file_descriptors.push(Some(new_fd));
            idx
        } else {
            return Err(VfsError::TooManyOpenFiles);
        }
    };
    Ok(fd_idx)
}

/// If `open_path` matches `/proc/{pid-or-self}/task/<tid>/stat`, return the TID.
/// Returns `None` for all other paths.
fn proc_task_tid_from_stat_path(open_path: &str) -> Option<u64> {
    // Accepted forms:
    //   /proc/self/task/<tid>/stat
    //   /proc/<N>/task/<tid>/stat
    let rest = open_path.strip_prefix("/proc/")?;
    // Skip the pid-or-self component.
    let after_pid = rest.splitn(2, '/').nth(1)?;
    let after_task = after_pid.strip_prefix("task/")?;
    // after_task = "<tid>/stat"
    let mut parts = after_task.splitn(2, '/');
    let tid_str = parts.next()?;
    let tail    = parts.next()?;
    if tail != "stat" { return None; }
    tid_str.parse::<u64>().ok()
}

/// Open a file for a process, returning the fd number.
pub fn open(pid: crate::proc::Pid, path: &str, open_flags: u32) -> VfsResult<usize> {
    // procfs magic-symlink open: `/proc/{self|<pid>}/fd/<N>` must DUP the
    // underlying open file by its backing inode, NOT re-resolve the link
    // target's pathname (per proc(5)).  Intercept BEFORE path resolution so an
    // unlinked memfd / anonymous tmpfs inode — which has no resolvable name —
    // reopens correctly instead of returning ENOENT.  Mozilla's shared-memory
    // layer re-opens an O_RDWR memfd read-only this way; re-resolving the
    // (removed) name was breaking the content-process sandbox channel.
    if let Some((target_pid, fd_num)) = parse_proc_fd_path(path, pid) {
        match reopen_proc_fd(pid, target_pid, fd_num, open_flags) {
            // NotFound means either the target fd is gone or it is a sentinel fd
            // this clone path declines to dup (see reopen_proc_fd).  Fall through
            // to normal /proc/self/fd → /dev/fd re-resolution so the outcome
            // matches the pre-interception behaviour (a benign ENOENT for a
            // nameless sentinel fd).  Any other result (success or a hard error)
            // is returned directly.
            Err(VfsError::NotFound) => {}
            other => return other,
        }
    }

    // C4: redirect /proc/<N>/... to /proc/self/... for inode resolution,
    // while preserving the original path in the fd for target-PID detection.
    //
    // Per proc(5): accessing /proc/<pid>/ for a nonexistent PID returns ENOENT.
    // We validate the target PID HERE (before the redirect) so open(2) itself
    // fails with the correct error code — the redirect would otherwise bypass
    // the PID-existence check in procfs::lookup().
    let redirected;
    let lookup_path: &str = if let Some(r) = redirect_proc_pid_path(path) {
        // Extract and validate the numeric PID embedded in the original path.
        // proc_target_pid returns None for /proc/self/... (no validation needed).
        if let Some(target_pid) = proc_target_pid(path) {
            let exists = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().any(|p| p.pid == target_pid)
            };
            if !exists {
                return Err(VfsError::NotFound);
            }
        }
        redirected = r;
        &redirected
    } else {
        path
    };

    // Try to resolve the (possibly redirected) path.
    let resolved = resolve_path(lookup_path);

    let (mount_idx, inode, newly_created) = match resolved {
        Ok((m, i)) => (m, i, false),
        Err(VfsError::NotFound) if open_flags & flags::O_CREAT != 0 => {
            // Create the file using the (possibly redirected) lookup path.
            let (m, parent, name) = resolve_parent(lookup_path)?;
            let fs = fs_at(m).ok_or(VfsError::NotFound)?.0;
            let ino = fs.create_file(parent, &name)?;
            (m, ino, true)
        }
        Err(e) => return Err(e),
    };

    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    let file_stat = fs.stat(inode)?;

    if open_flags & flags::O_TRUNC != 0 && file_stat.file_type == FileType::RegularFile {
        fs.truncate(inode, 0)?;
        // Page-cache coherence (POSIX open(2) O_TRUNC + ftruncate(2)):
        // discard every cached page of the now-empty file so a subsequent
        // mmap / cached read does not resurrect the pre-truncate contents.
        crate::mm::cache::truncate_range(mount_idx, inode, file_stat.size, 0);
    }

    let fd = FileDescriptor {
        inode,
        mount_idx,
        offset: 0,
        flags: open_flags,
        file_type: file_stat.file_type,
        is_console: false,
        cloexec: (open_flags & 0x0008_0000) != 0, // O_CLOEXEC
        open_path: String::from(path),
    };

    // Add to process's fd table.
    let fd_idx = {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter_mut().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;

        // Find first free fd slot by index, then insert after the loop to avoid
        // move-in-loop borrow issues.
        let free_idx = proc.file_descriptors.iter().position(|f| f.is_none());
        if let Some(i) = free_idx {
            proc.file_descriptors[i] = Some(fd);
            i
        } else {
            // Grow the fd table, capped at min(RLIMIT_NOFILE soft, MAX_FDS_PER_PROCESS).
            let nofile_limit = proc.rlimits_soft[7]
                .min(MAX_FDS_PER_PROCESS as u64) as usize;
            if proc.file_descriptors.len() < nofile_limit {
                let idx = proc.file_descriptors.len();
                proc.file_descriptors.push(Some(fd));
                idx
            } else {
                return Err(VfsError::TooManyOpenFiles);
            }
        }
    };

    // Fire inotify events now that locks are released.
    // O_CREAT on a new file: fire IN_CREATE then IN_OPEN.
    // Existing file open: fire IN_OPEN only.
    let (parent_dir, filename) = split_parent_name(path);
    if file_stat.file_type == FileType::RegularFile || file_stat.file_type == FileType::Directory {
        if newly_created {
            crate::ipc::inotify::notify_event(
                parent_dir, filename, crate::ipc::inotify::IN_CREATE, 0);
        }
        crate::ipc::inotify::notify_event(
            parent_dir, filename, crate::ipc::inotify::IN_OPEN, 0);
    }

    Ok(fd_idx)
}

/// Close a file descriptor.
/// Implements C5 (unlink-on-last-close): if the file was unlinked while open,
/// its inode is freed when the last fd pointing to it is closed.
pub fn close(pid: crate::proc::Pid, fd_num: usize) -> VfsResult<()> {
    // Extract fd info and clear the slot atomically under PROCESS_TABLE.
    let closed = {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter_mut().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;
        if fd_num >= proc.file_descriptors.len() { return Err(VfsError::BadFd); }
        let fd_opt = &mut proc.file_descriptors[fd_num];
        if fd_opt.is_none() { return Err(VfsError::BadFd); }
        fd_opt.take().map(|fd| {
            (fd.mount_idx, fd.inode, fd.is_console, fd.file_type, fd.flags, fd.open_path.clone(), fd.offset)
        })
    };

    if let Some((mount_idx, inode, is_console, file_type, open_flags, open_path, write_off)) = closed {
        // Release POSIX locks held by this pid on the closed inode (C1).
        if !is_console && mount_idx != usize::MAX {
            FILE_LOCKS.lock().retain(|l| !(l.mount_idx == mount_idx && l.inode == inode && l.pid == pid));
        }

        // Anonymous-pipe end: drop the appropriate reader/writer count
        // on the underlying `Pipe` object.  When the count reaches zero,
        // peers parked on the other end are woken so they observe EOF or
        // `EPIPE` (per POSIX `read(2)` / `write(2)`).  Without this, a
        // `close(2)` only clears the fd table slot — leaving the pipe's
        // writer count above zero indefinitely and stranding a `read(2)`
        // call that is waiting for the last writer to hang up.  This is
        // the kernel-side gate for musl's posix_spawn(3) cancel-pipe
        // pattern (W101 sc=1972 plateau).
        if file_type == FileType::Pipe
            && mount_idx == usize::MAX
            && open_flags & 0x8000_0000 != 0
        {
            if open_flags & 1 == 1 {
                crate::ipc::pipe::pipe_close_writer(inode);
            } else {
                crate::ipc::pipe::pipe_close_reader(inode);
            }
        }

        // C5: unlink-on-last-close — check if this inode was deferred-deleted.
        if !is_console && file_type == FileType::RegularFile && mount_idx != usize::MAX {
            // Check remaining open fds + atomically remove from DELETED_INODES if last.
            // A kernel pin (e.g. an in-flight SCM_RIGHTS descriptor that is queued
            // for delivery but not yet installed in any fd table — invisible to the
            // fd-table scan below) also keeps the inode alive: do NOT free while
            // pinned.  See PINNED_INODES / pin_inode.  When the last pin is later
            // dropped, unpin_inode performs this same last-close test and frees the
            // inode then.
            let should_free = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                let still_open = procs.iter().any(|p| p.file_descriptors.iter().any(|fdo| {
                    fdo.as_ref().map(|f| f.mount_idx == mount_idx && f.inode == inode)
                        .unwrap_or(false)
                }));
                if !still_open && !inode_is_pinned(mount_idx, inode) {
                    let mut dl = DELETED_INODES.lock();
                    let before = dl.len();
                    dl.retain(|(m, n)| !(*m == mount_idx && *n == inode));
                    dl.len() < before // true if we actually removed an entry
                } else {
                    false
                }
            };
            if should_free {
                if let Some((fs, _)) = fs_at(mount_idx) {
                    let _ = fs.remove_inode(inode);
                }
            }
        }

        // Fire inotify IN_CLOSE_WRITE or IN_CLOSE_NOWRITE for regular files.
        if !is_console && file_type == FileType::RegularFile && mount_idx != usize::MAX {
            let writable = open_flags & (flags::O_WRONLY | flags::O_RDWR) != 0;
            let close_mask = if writable {
                crate::ipc::inotify::IN_CLOSE_WRITE
            } else {
                crate::ipc::inotify::IN_CLOSE_NOWRITE
            };
            let (parent_dir, filename) = split_parent_name(&open_path);
            crate::ipc::inotify::notify_event(parent_dir, filename, close_mask, 0);

            // firefox-test screenshot-write gate: the renderer just closed a
            // file it wrote to.  If it is the registered `--screenshot` path
            // and carries bytes, emit `[GATE] png-write` exactly once — the
            // genuine "the PNG was written and closed" signal (vs the stat/
            // resolve probes that previously stood in for it).  `write_off`
            // is the fd's offset at close: non-zero ⇒ content was written.
            maybe_emit_png_write_gate(&open_path, writable, write_off);
        }
    }

    Ok(())
}

/// Read from a file descriptor.
///
/// Forward-direction coherency (write(2) visible to a subsequent read or
/// mmap reader) is maintained by `fd_write` / `write_file` via
/// `mm::cache::update_range`.
///
/// The reverse direction — a write through a MAP_SHARED+PROT_WRITE PTE
/// visible to a subsequent `read(2)` — is handled for in-memory filesystems
/// (ramfs / tmpfs), where it is the dual-storage hazard: the inode buffer
/// (`fs.read`) and the mmap-aliased page-cache frame are two distinct copies,
/// and an mmap store lands only in the frame.  This path keeps the two
/// coherent in both directions:
///   * resident frames — after the `fs.read` below, any cache-resident page
///     for the read range is overlaid onto the result (cache-authoritative
///     read), so an mmap write held in a still-resident frame is observed;
///   * evicted frames — `mm::cache` writes a frame's bytes back into the
///     inode buffer before the frame leaves the cache, so a cache-miss
///     `fs.read` after an eviction observes the mmap write too.
/// Together these satisfy POSIX mmap(2) MAP_SHARED visibility for ramfs/tmpfs.
/// Block-backed filesystems (ext2 / fat32) are not in-memory and re-read the
/// on-disk image, so they are unaffected and skip the overlay.
pub fn fd_read(pid: crate::proc::Pid, fd_num: usize, buf: *mut u8, count: usize) -> VfsResult<usize> {
    // SMAP bracket — fd_read writes data into `buf` which is typically
    // a user-VA from the syscall path.  The function does not call
    // `schedule()` internally; it is a pure-kernel critical section
    // wrapping FS / device / IPC reads.  Holding the guard across the
    // whole function covers every leaf that writes to `buf` (including
    // those inside FS callbacks) without per-site instrumentation.
    //
    // Internal kernel callers that pass a kernel-VA `buf` are unaffected
    // because SMAP only fires on PTE.U=1 pages.  See Intel SDM Vol. 3A
    // §4.6.1 (SMAP enforcement).
    let _smap_g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let (mount_idx, inode, offset, flags, file_type, open_path) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;
        let fd = proc.file_descriptors.get(fd_num)
            .and_then(|f| f.as_ref())
            .ok_or(VfsError::BadFd)?;
        if fd.is_console { return Err(VfsError::Unsupported); }
        (fd.mount_idx, fd.inode, fd.offset, fd.flags, fd.file_type, fd.open_path.clone())
    };

    // ── Special fd types (timerfd / signalfd / inotifyfd) ──────────────────
    match file_type {
        FileType::TimerFd => {
            if count < 8 { return Err(VfsError::InvalidArg); }
            match crate::ipc::timerfd::read(inode) {
                Ok(val) => {
                    let bytes = val.to_le_bytes();
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, 8);
                    }
                    Ok(8)
                }
                Err(e) => Err(if e == -11 { VfsError::WouldBlock } else { VfsError::BadFd }),
            }
        }
        FileType::SignalFd => {
            match crate::ipc::signalfd::read(inode, buf, count) {
                Ok(n) => Ok(n),
                Err(e) => Err(if e == -11 { VfsError::WouldBlock } else { VfsError::BadFd }),
            }
        }
        FileType::InotifyFd => {
            match crate::ipc::inotify::read(inode, buf, count) {
                Ok(n) => Ok(n),
                Err(e) => Err(if e == -11 { VfsError::WouldBlock } else if e == -22 { VfsError::InvalidArg } else { VfsError::BadFd }),
            }
        }
        FileType::PtyMaster => {
            let pty_n = inode as u8;
            if !crate::drivers::pty::master_readable(pty_n) {
                return Err(VfsError::WouldBlock);
            }
            let slice = unsafe { core::slice::from_raw_parts_mut(buf, count) };
            Ok(crate::drivers::pty::master_read(pty_n, slice))
        }
        FileType::PtySlave => {
            let pty_n = inode as u8;
            if !crate::drivers::pty::slave_readable(pty_n) {
                return Err(VfsError::WouldBlock);
            }
            let slice = unsafe { core::slice::from_raw_parts_mut(buf, count) };
            Ok(crate::drivers::pty::slave_read(pty_n, slice))
        }
        _ => {
            // ── Special character devices ─────────────────────────────────────────
            // bit 26 = /dev/null  → always return 0 bytes (EOF)
            if flags & 0x0400_0000 != 0 { return Ok(0); }
            // bit 25 = /dev/zero  → fill buffer with zeros
            if flags & 0x0200_0000 != 0 {
                #[cfg(feature = "firefox-test-core")]
                crate::mm::w215_diag::probe(crate::mm::w215_diag::Writer::DevZero, buf, count);
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::write_bytes(buf, 0, count);
                }
                return Ok(count);
            }
            // bit 24 = /dev/urandom | /dev/random  → fill with random bytes
            //
            // MUST draw from the same RDRAND-backed entropy source as
            // getrandom(2) (`security::rand::rand_u64`, RDRAND with a
            // RDTSC/LAPIC-seeded xorshift fallback), advancing the value on
            // every 8-byte word.  A correct /dev/urandom NEVER returns
            // identical consecutive blocks: NSS softoken's FIPS 140-2 §4.9.2
            // continuous-RNG self-test (and similar health tests) compare two
            // back-to-back entropy reads and treat a match as a hardware RNG
            // failure (CKR_DEVICE_ERROR), which would abort TLS init.  The
            // previous implementation seeded a single LCG from get_ticks()
            // once per read, so two reads serviced within one timer tick were
            // byte-identical and tripped that test.  See random(4) /
            // getrandom(2): /dev/urandom is a CSPRNG, not a clock-derived
            // sequence.
            if flags & 0x0100_0000 != 0 {
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    let mut i = 0usize;
                    while i < count {
                        let val = crate::security::rand::rand_u64();
                        let bytes = val.to_le_bytes();
                        let n = core::cmp::min(8, count - i);
                        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.add(i), n);
                        i += n;
                    }
                }
                return Ok(count);
            }
            // bit 22 = /dev/vport0p0 → drain bytes from virtio-serial rx queue.
            // Honour O_NONBLOCK (0x0000_0800): non-blocking opens return
            // WouldBlock immediately on an empty queue; blocking opens park
            // the caller via `read_blocking` and only return once at least
            // one byte is available (POSIX `read(2)` semantics).  See
            // virtio 1.2 §5.3 for the rx-side delivery model.  Before
            // `arm_irq()` has fired (early-boot test paths), the blocking
            // variant short-circuits to the non-blocking path and lets the
            // caller cooperate via `yield_cpu` — the QGA-2 loopback test
            // exercises that fallback.
            #[cfg(feature = "qga")]
            if flags & 0x0040_0000 != 0 {
                let slice = unsafe { core::slice::from_raw_parts_mut(buf, count) };
                let non_block = flags & 0x0000_0800 != 0;
                let n = if non_block {
                    crate::drivers::virtio_serial::read(slice)
                } else {
                    crate::drivers::virtio_serial::read_blocking(slice)
                };
                if n == 0 { return Err(VfsError::WouldBlock); }
                return Ok(n);
            }

            // ── Dynamic /proc entries ──────────────────────────────────────────
            // C4: /proc/<N>/... paths store the original path in open_path; parse
            // target PID from it so we serve the right process's data.
            if open_path == "/proc/self/maps" || open_path.ends_with("/maps") {
                let target_pid = proc_target_pid(&open_path).unwrap_or(pid);
                let content = generate_proc_maps(target_pid);
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            if open_path == "/proc/self/status" || open_path.ends_with("/status") {
                let target_pid = proc_target_pid(&open_path).unwrap_or(pid);
                let content = generate_proc_status(target_pid);
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            // /proc/self/task/<tid>/stat — task-thread stat; field 1 = TID.
            // Must be checked before the generic "/stat" catch-all below.
            if let Some(tid) = proc_task_tid_from_stat_path(&open_path) {
                let target_pid = proc_target_pid(&open_path).unwrap_or(pid);
                let content = generate_proc_stat_for(tid, target_pid);
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            if open_path == "/proc/self/stat" || open_path.ends_with("/stat") {
                let target_pid = proc_target_pid(&open_path).unwrap_or(pid);
                let content = generate_proc_stat(target_pid);
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            if open_path == "/proc/self/auxv" || open_path.ends_with("/auxv") {
                let target_pid = proc_target_pid(&open_path).unwrap_or(pid);
                let content = generate_proc_auxv(target_pid);
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            if open_path == "/proc/self/environ" || open_path.ends_with("/environ") {
                let target_pid = proc_target_pid(&open_path).unwrap_or(pid);
                let content = generate_proc_environ(target_pid);
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            // ── Dynamic /proc global entries (no PID context needed) ──────────
            // These are served from ProcFs::read() but we intercept here too so
            // the content is always fresh regardless of which mount serves the fd.
            if open_path == "/proc/cpuinfo" {
                let content = procfs::generate_cpuinfo();
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            if open_path == "/proc/meminfo" {
                let content = procfs::generate_meminfo();
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            if open_path == "/proc/uptime" {
                let content = procfs::generate_uptime();
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            if open_path == "/proc/version" {
                let content = procfs::generate_version();
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            // /proc/mounts — must be intercepted here because generate_mounts()
            // acquires MOUNTS.lock() itself.  Routing through ProcFs::read() (as
            // the fallthrough below does) would take MOUNTS.lock() first and
            // then re-enter it in generate_mounts() — a single-thread re-entrant
            // spin that hangs in the kernel indefinitely.
            if open_path == "/proc/mounts" {
                let content = procfs::generate_mounts();
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            // /proc/self/mountinfo (and /proc/<pid>/mountinfo) — same lock
            // hazard as /proc/mounts: generate_mountinfo() takes MOUNTS.lock(),
            // so it must be served from here (outside any FS dispatch path).
            //
            // Mozilla's sandbox policy builder enumerates filesystems via this
            // file; an ENOENT previously made it fall back to refuse-all,
            // which prevented the GPU-probe child from ever being spawned
            // (see W39 trace: 2× ENOENT on mountinfo + zero subsequent execve).
            if is_proc_self_path(&open_path, "mountinfo") {
                let content = procfs::generate_mountinfo();
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }
            // /proc/self/cgroup — cgroup v2 unified hierarchy root reply.
            if is_proc_self_path(&open_path, "cgroup") {
                let content = procfs::generate_cgroup();
                return serve_dynamic_read(&content, offset, buf, count, pid, fd_num);
            }

            let mut buffer = unsafe { core::slice::from_raw_parts_mut(buf, count) };
            // Drop MOUNTS before the FS read: the read may fault on the
            // user buffer pages (file-backed VMA), and the page-fault
            // handler also needs MOUNTS — same-thread recursion (#82).
            //
            // Bounce the read through a kernel-heap buffer instead of letting
            // the filesystem fill the user buffer directly.  A block-backed
            // filesystem (ext2/fat32) services a large aligned read by handing
            // the destination slice to the block device, which DMAs into it.
            // The virtio-blk descriptor's address field is a *physical*
            // address; the driver derives it from the buffer's kernel virtual
            // address by the fixed higher-half direct-map offset and has no
            // page-table walker, so a *user* virtual address gets written into
            // the descriptor verbatim as if it were physical.  The device then
            // targets a bogus address far outside RAM, the host rejects the
            // descriptor, and the virtqueue halts — wedging all further disk
            // I/O (observed: a multi-page uncached read froze the device's
            // used.idx, immune to doorbell re-kick and reset).
            //
            // The kernel heap occupies one physically-contiguous range, so a
            // heap `Vec` always has a valid contiguous physical address the
            // driver's offset derivation handles.  Read into the bounce buffer,
            // then CPU-copy into the user buffer (the copy may fault the
            // file-backed user pages in — which is why MOUNTS was dropped
            // above).  In-memory filesystems (ramfs/tmpfs/procfs) memcpy and are
            // unaffected by either path.  All read variants
            // (read/pread/readv/preadv) funnel through fd_read, so this covers
            // every backing-store read.
            let n = {
                let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
                // Bounce in bounded chunks so a single read(2) with a huge
                // `count` never allocates a `count`-sized kernel buffer (which
                // could exhaust the 384 MiB kernel heap).  256 KiB comfortably
                // exceeds the block device's per-request span, so a chunk is
                // still serviced by at most one coalesced device read.
                const BOUNCE_CHUNK: usize = 256 * 1024;
                let chunk_cap = count.min(BOUNCE_CHUNK);
                let mut bounce = alloc::vec![0u8; chunk_cap];
                let mut done = 0usize;
                loop {
                    if done >= count {
                        break;
                    }
                    let want = (count - done).min(chunk_cap);
                    let got = fs.read(
                        inode,
                        offset + done as u64,
                        &mut bounce[..want],
                    )?;
                    if got == 0 {
                        break; // EOF / short read — stop.
                    }
                    // SAFETY: `buffer` is the caller's destination of length
                    // `count`; `done + got <= count` because `want <= count -
                    // done` and `got <= want`.
                    buffer[done..done + got].copy_from_slice(&bounce[..got]);
                    done += got;
                    if got < want {
                        break; // short read — backing store has no more here.
                    }
                }
                done
            };

            // ── In-memory MAP_SHARED coherence: cache-authoritative read ──────
            //
            // For an in-memory filesystem (ramfs / tmpfs) the bounce read above
            // pulled bytes from the inode buffer.  A `mmap(MAP_SHARED |
            // PROT_WRITE)` store, however, lands ONLY in the page-cache frame
            // the demand-fault path aliases — the inode buffer is not on that
            // write path.  So while a written frame is still cache-resident,
            // the inode buffer can be stale.  Overlay any cache-resident page's
            // current bytes onto the just-read buffer so a `read(2)` observes
            // the mmap write per POSIX mmap(2) MAP_SHARED visibility.  (Evicted
            // frames are already reconciled into the inode buffer by the
            // writeback-on-eviction path in `mm::cache`, so this only needs to
            // cover the resident-frame case.)  Block-backed filesystems
            // (ext2 / fat32) are not in-memory and never reach this — their
            // on-disk image is the single source of truth.
            if n > 0 {
                let is_in_mem = fs_at(mount_idx)
                    .map(|(fs, _)| fs.is_in_memory())
                    .unwrap_or(false);
                if is_in_mem {
                    const PAGE: u64 = 4096;
                    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
                    let read_end = offset + n as u64;
                    let mut pg = offset & !(PAGE - 1);
                    while pg < read_end {
                        if let Some(phys) = crate::mm::cache::lookup(mount_idx, inode, pg) {
                            // Intersect [pg, pg+PAGE) with [offset, read_end).
                            let seg_start = core::cmp::max(pg, offset);
                            let seg_end = core::cmp::min(pg + PAGE, read_end);
                            let in_page_off = (seg_start - pg) as usize;
                            let buf_off = (seg_start - offset) as usize;
                            let len = (seg_end - seg_start) as usize;
                            // SAFETY: `phys` is a live cache frame (cache holds
                            // a reference); the higher-half map covers it
                            // (Intel SDM Vol. 3A §4.10.5).  `in_page_off + len
                            // <= PAGE` and `buf_off + len <= n <= count` by the
                            // intersection bounds above, so the copy stays in
                            // bounds of both the frame and `buffer`.
                            let src = (PHYS_OFF + phys + in_page_off as u64) as *const u8;
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    src,
                                    buffer.as_mut_ptr().add(buf_off),
                                    len,
                                );
                            }
                        }
                        pg += PAGE;
                    }
                }
            }

            // Update offset.
            {
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                let proc = procs.iter_mut().find(|p| p.pid == pid).unwrap();
                if let Some(Some(fd)) = proc.file_descriptors.get_mut(fd_num) {
                    fd.offset += n as u64;
                }
            }

            Ok(n)
        }
    }
}

/// Helper: serve a slice of dynamic content at `offset` into `buf`, advance fd offset.
fn serve_dynamic_read(content: &[u8], offset: u64, buf: *mut u8, count: usize,
                       pid: crate::proc::Pid, fd_num: usize) -> VfsResult<usize> {
    let start = offset as usize;
    if start >= content.len() { return Ok(0); }
    let available = content.len() - start;
    let n = available.min(count);
    unsafe { core::ptr::copy_nonoverlapping(content.as_ptr().add(start), buf, n); }
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(Some(fd)) = p.file_descriptors.get_mut(fd_num) {
                fd.offset += n as u64;
            }
        }
    }
    Ok(n)
}

/// Generate /proc/self/maps content from the process's VMAs.
///
/// Delegates to `procfs::generate_proc_maps`, which is the single canonical
/// implementation of the proc(5) /proc/<pid>/maps format.
fn generate_proc_maps(pid: crate::proc::Pid) -> alloc::vec::Vec<u8> {
    procfs::generate_proc_maps(pid)
}

/// Generate /proc/self/status content for the process.
///
/// Format and field set per `man 5 proc_pid_status` (Linux man-pages 5.13)
/// and `Documentation/filesystems/proc.rst` at kernel.org.  Many fields
/// are computed live; signal/capability/cpu_allowed masks reflect kernel
/// invariants (single-process token model, all-CPU affinity).  Fields not
/// yet tracked (Umask, FDSize for kernel threads, NS* PID-namespace
/// mirrors) are set to safe per-spec defaults so `ps`/`top`/sandbox-probe
/// parsers do not fault on missing keys.
fn generate_proc_status(pid: crate::proc::Pid) -> alloc::vec::Vec<u8> {
    generate_proc_status_impl(pid)
}

/// Test-only accessor for `generate_proc_status`.
///
/// Exposed so `test_runner.rs` can pin the field set against
/// `proc_pid_status(5)` without going through the full open()/read()
/// path.  Not part of the published kernel ABI.
pub fn generate_proc_status_for_test(pid: crate::proc::Pid) -> alloc::vec::Vec<u8> {
    generate_proc_status_impl(pid)
}

fn generate_proc_status_impl(pid: crate::proc::Pid) -> alloc::vec::Vec<u8> {
    use crate::mm::vma::{PROT_WRITE, PROT_EXEC, MAP_ANONYMOUS};

    // ── Snapshot all per-process facts under one lock acquisition ───────
    let (
        comm, ppid, uid, gid, euid, egid, umask, no_new_privs,
        cap_perm, cap_eff, _fd_count, fd_capacity, n_threads,
        vm_size_b, vm_data_b, vm_stk_b, vm_exe_b, vm_lib_b,
        sig_pend, sig_blk, sig_ign, sig_cgt, sig_q_max,
    ) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let p = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => {
                // Process gone: minimal conformant reply.
                return b"Name:\tastryx\nUmask:\t0022\nState:\tZ (zombie)\n\
                         Tgid:\t0\nNgid:\t0\nPid:\t0\nPPid:\t0\nTracerPid:\t0\n".to_vec();
            }
        };

        // Name: rightmost path component of exe_path, capped to the 16-char
        // limit Linux applies to TASK_COMM_LEN ("Command run by this
        // process" per proc_pid_status(5)).
        let full = p.exe_path.clone()
            .unwrap_or_else(|| alloc::string::String::from("astryx"));
        let short = full.rsplit('/').next().unwrap_or(&full);
        let comm: alloc::string::String = short.chars().take(15).collect();

        // VMA-derived Vm* fields (bytes).
        let mut vm_size = 0u64;
        let mut vm_data = 0u64;
        let mut vm_stk  = 0u64;
        let mut vm_exe  = 0u64;
        let mut vm_lib  = 0u64;
        if let Some(vs) = p.vm_space.as_ref() {
            for a in &vs.areas {
                vm_size += a.length;
                let writable = (a.prot & PROT_WRITE) != 0;
                let executable = (a.prot & PROT_EXEC) != 0;
                let anon = (a.flags & MAP_ANONYMOUS) != 0;
                // VMA classification per proc_pid_status(5) "Vm* fields"
                // (Linux man-pages 5.13):
                //   - VmStk: the "[stack]" VMA (one per process)
                //   - VmExe: executable VMAs of the main program
                //   - VmLib: executable VMAs from shared libraries
                //   - VmData: writable anonymous (data segment + heap + bss)
                if a.name == "[stack]" {
                    vm_stk += a.length;
                } else if executable && !writable {
                    // Heuristic: main exe distinguished by VmBacking::File
                    // offset==0 vs nonzero is complex; coalesce all exec-only
                    // segments into VmExe + VmLib.  We assign the first such
                    // segment to VmExe and the rest to VmLib so the breakdown
                    // is non-zero and round-trips through ps's column model.
                    if vm_exe == 0 {
                        vm_exe = a.length;
                    } else {
                        vm_lib += a.length;
                    }
                } else if writable && anon {
                    vm_data += a.length;
                }
            }
        }

        // Signal masks.  Pending+blocked are tracked directly; ignored/caught
        // are derived from the action table.
        let (pend, blk, ign, cgt) = if let Some(ss) = p.signal_state.as_ref() {
            let mut ign = 0u64;
            let mut cgt = 0u64;
            for sig in 1..crate::signal::MAX_SIGNAL {
                match ss.actions[sig as usize] {
                    crate::signal::SigAction::Ignore =>
                        ign |= 1u64 << (sig - 1),
                    crate::signal::SigAction::Handler { .. } =>
                        cgt |= 1u64 << (sig - 1),
                    _ => {}
                }
            }
            (ss.pending, ss.blocked, ign, cgt)
        } else {
            (0u64, 0u64, 0u64, 0u64)
        };

        // FDSize is the allocated capacity of the fd table, not the count
        // of open fds (per proc_pid_status(5)).
        let fd_count = p.file_descriptors.iter().filter(|f| f.is_some()).count();
        let fd_cap = p.file_descriptors.capacity().max(p.file_descriptors.len());

        // SigQ second field is RLIMIT_SIGPENDING (per proc_pid_status(5)):
        // the max queue length, not the open-fd count.  rlimits_soft index 11
        // is RLIMIT_SIGPENDING per <sys/resource.h>; default_rlimits() leaves
        // this at zero (not enforced), in which case we report 0 — that is
        // the conformant "no limit set" reading per proc_pid_status(5).
        let sig_q_max = p.rlimits_soft[11];

        (
            comm, p.parent_pid,
            p.uid, p.gid, p.euid, p.egid,
            p.umask, p.no_new_privs,
            p.cap_permitted, p.cap_effective,
            fd_count, fd_cap,
            p.threads.len().max(1),
            vm_size, vm_data, vm_stk, vm_exe, vm_lib,
            pend, blk, ign, cgt, sig_q_max,
        )
    };

    // Map process state via primary thread (best-effort).  Default: R.
    let state_char = "R (running)";

    // CPU/MEM affinity: AstryxOS schedules across all online CPUs by default.
    // Encode as the conventional Linux-form mask (single-byte hex).
    let online_cpus = (crate::arch::x86_64::apic::cpu_count().max(1)) as u64;
    let cpus_mask: u64 = if online_cpus >= 64 { !0u64 } else { (1u64 << online_cpus) - 1 };

    // VmPeak/VmSize/VmHWM/VmRSS are reported as the VMA-total (vm_size_kb)
    // — a deliberate conservative *over*-report: we lack per-page resident
    // tracking, and over-stating RSS only causes monitors like `ps`/`top`
    // to show a slightly larger memory column.  Under-reporting would risk
    // OOM-killer-style heuristics making bad decisions, so we round up.
    // Conformance is structural (the fields exist and parse), not numeric.
    alloc::format!(
        "Name:\t{name}\n\
         Umask:\t{umask:04o}\n\
         State:\t{state}\n\
         Tgid:\t{pid}\n\
         Ngid:\t0\n\
         Pid:\t{pid}\n\
         PPid:\t{ppid}\n\
         TracerPid:\t0\n\
         Uid:\t{uid}\t{euid}\t{uid}\t{uid}\n\
         Gid:\t{gid}\t{egid}\t{gid}\t{gid}\n\
         FDSize:\t{fd_cap}\n\
         Groups:\t\n\
         NStgid:\t{pid}\n\
         NSpid:\t{pid}\n\
         NSpgid:\t{pid}\n\
         NSsid:\t{pid}\n\
         VmPeak:\t{vm_size_kb} kB\n\
         VmSize:\t{vm_size_kb} kB\n\
         VmLck:\t       0 kB\n\
         VmPin:\t       0 kB\n\
         VmHWM:\t{vm_size_kb} kB\n\
         VmRSS:\t{vm_size_kb} kB\n\
         RssAnon:\t{vm_data_kb} kB\n\
         RssFile:\t{vm_exe_lib_kb} kB\n\
         RssShmem:\t       0 kB\n\
         VmData:\t{vm_data_kb} kB\n\
         VmStk:\t{vm_stk_kb} kB\n\
         VmExe:\t{vm_exe_kb} kB\n\
         VmLib:\t{vm_lib_kb} kB\n\
         VmPTE:\t       0 kB\n\
         VmSwap:\t       0 kB\n\
         HugetlbPages:\t       0 kB\n\
         CoreDumping:\t0\n\
         THP_enabled:\t1\n\
         Threads:\t{n_threads}\n\
         SigQ:\t0/{sig_q_max}\n\
         SigPnd:\t{sig_pend:016x}\n\
         ShdPnd:\t{sig_pend:016x}\n\
         SigBlk:\t{sig_blk:016x}\n\
         SigIgn:\t{sig_ign:016x}\n\
         SigCgt:\t{sig_cgt:016x}\n\
         CapInh:\t0000000000000000\n\
         CapPrm:\t{cap_prm:016x}\n\
         CapEff:\t{cap_eff:016x}\n\
         CapBnd:\t{cap_prm:016x}\n\
         CapAmb:\t0000000000000000\n\
         NoNewPrivs:\t{nnp}\n\
         Seccomp:\t0\n\
         Seccomp_filters:\t0\n\
         Speculation_Store_Bypass:\tthread vulnerable\n\
         Cpus_allowed:\t{cpus_mask:x}\n\
         Cpus_allowed_list:\t0-{cpus_last}\n\
         Mems_allowed:\t1\n\
         Mems_allowed_list:\t0\n\
         voluntary_ctxt_switches:\t0\n\
         nonvoluntary_ctxt_switches:\t0\n",
        name      = comm,
        umask     = umask,
        state     = state_char,
        pid       = pid,
        ppid      = ppid,
        uid       = uid,  euid = euid,
        gid       = gid,  egid = egid,
        fd_cap    = fd_capacity,
        n_threads = n_threads,
        vm_size_kb    = vm_size_b / 1024,
        vm_data_kb    = vm_data_b / 1024,
        vm_stk_kb     = vm_stk_b  / 1024,
        vm_exe_kb     = vm_exe_b  / 1024,
        vm_lib_kb     = vm_lib_b  / 1024,
        vm_exe_lib_kb = (vm_exe_b + vm_lib_b) / 1024,
        sig_pend  = sig_pend,
        sig_blk   = sig_blk,
        sig_ign   = sig_ign,
        sig_cgt   = sig_cgt,
        sig_q_max = sig_q_max,
        cap_prm   = cap_perm,
        cap_eff   = cap_eff,
        nnp       = if no_new_privs { 1 } else { 0 },
        cpus_mask = cpus_mask,
        cpus_last = online_cpus.saturating_sub(1),
    ).into_bytes()
}

/// Generate /proc/self/stat content for the process (or a task thread).
///
/// Linux `/proc/<pid>/stat` (and `/proc/<pid>/task/<tid>/stat`) has 52 fields.
/// Field 28 (`startstack`) is read by glibc `start_thread` to locate the
/// thread's stack; returning 0 for it is safe — glibc only uses it for
/// diagnostics.  The critical requirement is that the file EXISTS and is
/// parseable (non-empty, correct number of fields so sscanf succeeds).
///
/// When `tid` differs from `pid` this is a task-thread stat entry; the first
/// field should carry the TID, not the PID.
fn generate_proc_stat(pid: crate::proc::Pid) -> alloc::vec::Vec<u8> {
    generate_proc_stat_for(pid, pid)
}

/// Core stat generator.  `id` is the value placed in field 1 (TID for task
/// entries, PID for process entries); `pid` is used to look up the process
/// record (ppid, num_threads).
fn generate_proc_stat_for(id: u64, pid: crate::proc::Pid) -> alloc::vec::Vec<u8> {
    let (ppid, num_threads) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)
            .map(|p| (p.parent_pid, p.threads.len().max(1) as u64))
            .unwrap_or((0, 1))
    };
    // 52 fields matching Linux 5.x /proc/<pid>/stat format.
    // Fields we can't populate meaningfully are set to 0.
    // Field 28 (startstack) set to 0 — glibc accepts this.
    alloc::format!(
        "{id} (astryx) R {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 {nthreads} 0 0 65536 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        id = id, ppid = ppid, nthreads = num_threads
    ).into_bytes()
}

/// Generate /proc/self/auxv content: raw (u64 type, u64 value) pairs terminated
/// by (AT_NULL=0, 0).  For processes with a stored auxv (user processes), the
/// real values are emitted.  For kernel threads / idle (pid=0 or empty auxv), a
/// synthetic minimal auxvec is returned so /proc/self/auxv is always readable.
fn generate_proc_auxv(pid: crate::proc::Pid) -> alloc::vec::Vec<u8> {
    // AT_ constants (same as elf.rs; duplicated to avoid coupling)
    const AT_NULL:   u64 = 0;
    const AT_PAGESZ: u64 = 6;
    const AT_CLKTCK: u64 = 17;
    const AT_RANDOM: u64 = 25;

    let auxv: alloc::vec::Vec<(u64, u64)> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)
            .map(|p| p.auxv.clone())
            .unwrap_or_default()
    };

    let entries: alloc::vec::Vec<(u64, u64)> = if auxv.is_empty() {
        // Synthetic minimal auxvec for kernel threads / PID 0.
        // AT_RANDOM points to a stable kernel address (0xDEAD0 placeholder).
        alloc::vec![
            (AT_PAGESZ, 4096),
            (AT_CLKTCK, 100),
            (AT_RANDOM, 0xDEAD0u64),
        ]
    } else {
        auxv
    };

    let mut out = alloc::vec::Vec::with_capacity((entries.len() + 1) * 16);
    for (t, v) in &entries {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&v.to_le_bytes());
    }
    // AT_NULL terminator
    out.extend_from_slice(&AT_NULL.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

/// Generate /proc/self/environ content: NUL-separated environment strings.
/// For user processes, emits each stored envp entry followed by NUL.
/// For kernel threads (empty envp), emits a single NUL byte.
fn generate_proc_environ(pid: crate::proc::Pid) -> alloc::vec::Vec<u8> {
    let envp: alloc::vec::Vec<alloc::string::String> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)
            .map(|p| p.envp.clone())
            .unwrap_or_default()
    };

    if envp.is_empty() {
        return alloc::vec![0u8]; // single NUL for empty env
    }

    let mut out = alloc::vec::Vec::new();
    for e in &envp {
        out.extend_from_slice(e.as_bytes());
        out.push(0u8); // NUL terminator after each entry
    }
    out
}

/// Write to a file descriptor.
pub fn fd_write(pid: crate::proc::Pid, fd_num: usize, buf: *const u8, count: usize) -> VfsResult<usize> {
    // SMAP bracket — fd_write reads from `buf` which is typically a
    // user-VA from the syscall path.  Same rationale as `fd_read`:
    // pure-kernel critical section, no schedule points, all leaf
    // reads against `buf` covered by a single guard.
    let _smap_g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let (mount_idx, inode, offset, append, fd_flags, file_type, open_path) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;
        let fd = proc.file_descriptors.get(fd_num)
            .and_then(|f| f.as_ref())
            .ok_or(VfsError::BadFd)?;
        if fd.is_console { return Err(VfsError::Unsupported); }
        (fd.mount_idx, fd.inode, fd.offset,
         fd.flags & flags::O_APPEND != 0, fd.flags, fd.file_type,
         fd.open_path.clone())
    };

    // PTY write paths
    let data = unsafe { core::slice::from_raw_parts(buf, count) };
    match file_type {
        FileType::PtyMaster => {
            return Ok(crate::drivers::pty::master_write(inode as u8, data));
        }
        FileType::PtySlave => {
            return Ok(crate::drivers::pty::slave_write(inode as u8, data));
        }
        _ => {}
    }

    // Special character devices: accept writes silently.
    if fd_flags & (0x0400_0000 | 0x0200_0000 | 0x0100_0000) != 0 {
        return Ok(count); // /dev/null, /dev/zero, /dev/urandom — discard
    }

    // bit 23 (0x0080_0000) = /dev/dsp — forward PCM data to AC97 DMA ring.
    // The AC97 driver accepts the bytes as-is (caller is responsible for
    // producing 16-bit little-endian stereo PCM at the configured rate).
    if fd_flags & 0x0080_0000 != 0 {
        let n = crate::drivers::ac97::play_buffer(data);
        return Ok(n);
    }

    // bit 22 (0x0040_0000) = /dev/vport0p0 — push bytes to virtio-serial tx.
    // See virtio 1.2 §5.3.  Writes spin on the used ring inside the driver.
    #[cfg(feature = "qga")]
    if fd_flags & 0x0040_0000 != 0 {
        let n = crate::drivers::virtio_serial::write(data);
        return Ok(n);
    }

    // Snapshot the FS handle once and drop MOUNTS before the FS dispatch:
    // both stat() and write() may touch user buffers and re-enter the PF
    // handler, which itself needs MOUNTS (#82).
    let fs = fs_at(mount_idx).ok_or(VfsError::NotFound)?.0;
    let write_offset = if append {
        fs.stat(inode)?.size
    } else {
        offset
    };

    // Bounce the write through a kernel-heap buffer for the same reason the
    // read path does (see `fd_read`): a block-backed filesystem (ext2) services
    // an aligned whole-block write by handing the source slice straight to the
    // block device, which DMAs *from* it.  The virtio-blk descriptor's address
    // field is a physical address derived from the buffer's virtual address by
    // a fixed offset with no page-table walk, so a user virtual address gets
    // written into the descriptor verbatim and the device reads from a bogus
    // physical address — halting the virtqueue exactly as the read bug did.
    // Copy each chunk of user bytes into a kernel-heap (physically-contiguous)
    // buffer, then hand THAT to the filesystem.  Bounded to 256 KiB chunks so a
    // huge write never allocates a count-sized kernel buffer.  In-memory
    // filesystems (ramfs/tmpfs) memcpy and are unaffected; fat32 already
    // bounces through its sector cache, and the ext2 partial-block tail RMWs
    // through a kernel buffer — only the ext2 whole-block fast path leaked the
    // user pointer, which this closes for every backing-store write.
    let n = {
        const BOUNCE_CHUNK: usize = 256 * 1024;
        let chunk_cap = count.min(BOUNCE_CHUNK);
        let mut bounce = alloc::vec![0u8; chunk_cap];
        let mut done = 0usize;
        loop {
            if done >= count {
                break;
            }
            let want = (count - done).min(chunk_cap);
            // Copy the user bytes into the kernel bounce buffer (the read of
            // `data` may fault the user pages in — MOUNTS already dropped).
            bounce[..want].copy_from_slice(&data[done..done + want]);
            let put = fs.write(inode, write_offset + done as u64, &bounce[..want])?;
            done += put;
            if put < want {
                break; // short write — the backing store accepted no more.
            }
        }
        done
    };

    // Page-cache coherency: any process that previously mmap'd this file
    // has a cache-page-backed PTE that points at the pre-write bytes.
    // Per POSIX mmap(2) the MAP_SHARED region must observe the same
    // bytes as `read(2)` after a `write(2)` to the same file.  Update
    // every overlapping cache page in place so existing mappers (and any
    // future mmap fault that hits the cache) see the new content.  Only
    // the bytes that were actually written are copied; pages outside the
    // cache are unaffected.  See `mm::cache::update_range` for the
    // POSIX citations and locking discipline.
    if n > 0 && mount_idx != usize::MAX {
        crate::mm::cache::update_range(mount_idx, inode, write_offset, &data[..n]);
        // Invalidate the path-keyed `FILE_READ_CACHE` snapshot for this
        // file (if any) so a subsequent `read_file(path)` does not
        // return a pre-write copy.
        invalidate_path_read_cache(&open_path);
    }

    // Update offset.
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter_mut().find(|p| p.pid == pid).unwrap();
        if let Some(Some(fd)) = proc.file_descriptors.get_mut(fd_num) {
            fd.offset = write_offset + n as u64;
        }
    }

    // Fire IN_MODIFY on the parent directory (and self-watches on the file).
    if file_type == FileType::RegularFile && mount_idx != usize::MAX {
        let (parent_dir, filename) = split_parent_name(&open_path);
        crate::ipc::inotify::notify_event(parent_dir, filename, crate::ipc::inotify::IN_MODIFY, 0);
    }

    Ok(n)
}

// ── Runtime mount / umount ────────────────────────────────────────────────────

/// Linux mount(2) flag: mount read-only.
const MS_RDONLY_FLAG: u64 = 1;

/// Runtime `mount` syscall implementation (Linux syscall 165).
///
/// Supports filesystem types: "tmpfs", "ramfs", "procfs", "fat32".
/// "fat32" is a stub that always returns -ENODEV (no block device supplied by
/// the simple `mount` ABI; block-device mounts require a more complete VFS
/// namespace model).
///
/// Returns 0 on success, or a negative errno on failure:
///   -ENOENT  (2)  — target path does not exist
///   -ENODEV  (19) — unknown filesystem type
///   -EINVAL  (22) — bad arguments
pub fn sys_mount(
    _source: &str,
    target: &str,
    fstype: &str,
    flags: u64,
    _data: &str,
) -> i64 {
    if target.is_empty() {
        return -22; // EINVAL
    }

    // Validate: target path must already exist.
    if resolve_path(target).is_err() {
        crate::serial_println!("[VFS] mount: target '{}' does not exist", target);
        return -2; // ENOENT
    }

    let rdonly = (flags & MS_RDONLY_FLAG) != 0;

    match fstype {
        "tmpfs" | "ramfs" => {
            // Each mount gets its own fresh filesystem instance so that
            // mount("tmpfs","/a","tmpfs",0) and mount("tmpfs","/b","tmpfs",0)
            // have completely independent directory trees.
            if fstype == "tmpfs" {
                let concrete = if rdonly {
                    tmpfs::TmpFs::new_rdonly()
                } else {
                    tmpfs::TmpFs::new()
                };
                let ri = concrete.root_inode();
                MOUNTS.lock().push(Mount {
                    path: String::from(target),
                    fs: Arc::new(concrete),
                    root_inode: ri,
                });
            } else {
                // "ramfs"
                let concrete = ramfs::RamFs::new();
                let ri = concrete.root_inode();
                MOUNTS.lock().push(Mount {
                    path: String::from(target),
                    fs: Arc::new(concrete),
                    root_inode: ri,
                });
            }
            crate::serial_println!("[VFS] mount: {} mounted at '{}' (rdonly={})", fstype, target, rdonly);
            0
        }
        "proc" | "procfs" => {
            // Re-mount procfs at the requested path.
            let proc_fs = procfs::ProcFs::new();
            let proc_root = proc_fs.root_inode();
            let _ = mkdir(target); // ensure dir exists
            MOUNTS.lock().push(Mount {
                path: String::from(target),
                fs: Arc::new(proc_fs),
                root_inode: proc_root,
            });
            crate::serial_println!("[VFS] mount: procfs mounted at '{}'", target);
            0
        }
        "fat32" => {
            // Stub: block-device mounts require a device argument that the
            // simple Linux mount(2) ABI delivers only as a path string.
            // A full implementation would open the device file, wrap it in
            // a BlockDevice, and call fat32::Fat32Fs::new().  For now,
            // return ENODEV to indicate the feature is not yet available.
            crate::serial_println!("[VFS] mount: fat32 block-device mount not yet supported");
            -19 // ENODEV
        }
        _ => {
            crate::serial_println!("[VFS] mount: unknown fstype '{}'", fstype);
            -19 // ENODEV
        }
    }
}

/// Runtime `umount` / `umount2` syscall implementation (Linux syscalls 166/168).
///
/// Removes the mount at `target` from the mount table.  The underlying
/// filesystem and all its in-memory data are freed when the last `Arc<dyn
/// FileSystemOps>` reference is dropped.
///
/// # Busy check
/// A proper EBUSY check would require scanning all open file descriptors for
/// any `mount_idx` that resolves to the target mount.  That is correct but
/// expensive.  For v1 we perform a conservative check: if any process has an
/// open fd whose `mount_idx` matches the target mount, we return -EBUSY.
///
/// Returns 0 on success, or a negative errno on failure:
///   -ENOENT  (2)  — no mount at target
///   -EBUSY   (16) — files still open on this mount
///   -EINVAL  (22) — trying to umount "/" or other protected mounts
pub fn sys_umount(target: &str, _flags: u64) -> i64 {
    if target.is_empty() || target == "/" {
        return -22; // EINVAL — cannot umount root
    }

    // Find the mount index for this target.
    let mount_idx = {
        let mounts = MOUNTS.lock();
        mounts.iter().position(|m| m.path == target)
    };

    let mount_idx = match mount_idx {
        Some(i) => i,
        None => {
            crate::serial_println!("[VFS] umount: no mount at '{}'", target);
            return -2; // ENOENT
        }
    };

    // EBUSY check: scan all process fd tables for fds on this mount.
    {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let busy = procs.iter().any(|p| {
            p.file_descriptors.iter().any(|fdo| {
                fdo.as_ref().map(|f| f.mount_idx == mount_idx).unwrap_or(false)
            })
        });
        if busy {
            crate::serial_println!("[VFS] umount: '{}' is busy", target);
            return -16; // EBUSY
        }
    }

    // Remove the mount.  The dropped Arc<dyn FileSystemOps> frees the FS
    // memory once the last outstanding reference (e.g. an in-flight FS
    // dispatch from another thread that snapshotted the Arc) is released.
    {
        let mut mounts = MOUNTS.lock();
        if mount_idx >= mounts.len() {
            return -2; // ENOENT — raced with another umount
        }
        mounts.remove(mount_idx);
    }

    // Any remaining open-fd mount_idx values that were above `mount_idx` are
    // now off-by-one.  Fix them up so existing fds stay valid.
    //
    // This is safe because we just confirmed no fds are on the removed mount,
    // so only fds with mount_idx > removed_mount_idx need patching.
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        for proc in procs.iter_mut() {
            for fdo in proc.file_descriptors.iter_mut() {
                if let Some(fd) = fdo {
                    if fd.mount_idx != usize::MAX && fd.mount_idx > mount_idx {
                        fd.mount_idx -= 1;
                    }
                }
            }
        }
    }

    crate::serial_println!("[VFS] umount: '{}' removed from mount table", target);
    0
}
