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
pub mod procfs;

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Maximum open files per process.
pub const MAX_FDS_PER_PROCESS: usize = 64;

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
}

/// A mounted filesystem.
pub struct Mount {
    pub path: String,
    pub fs: Box<dyn FileSystemOps>,
    pub root_inode: u64,
}

/// Mount table.
pub static MOUNTS: Mutex<Vec<Mount>> = Mutex::new(Vec::new());

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
}

impl FileDescriptor {
    pub fn console_stdin() -> Self {
        Self {
            inode: 0, mount_idx: 0, offset: 0,
            flags: flags::O_RDONLY, file_type: FileType::CharDevice,
            is_console: true,
        }
    }
    pub fn console_stdout() -> Self {
        Self {
            inode: 0, mount_idx: 0, offset: 0,
            flags: flags::O_WRONLY, file_type: FileType::CharDevice,
            is_console: true,
        }
    }
    pub fn console_stderr() -> Self {
        Self {
            inode: 0, mount_idx: 0, offset: 0,
            flags: flags::O_WRONLY, file_type: FileType::CharDevice,
            is_console: true,
        }
    }
}

/// Initialize the VFS with a root ramfs.
pub fn init() {
    let root_fs = ramfs::RamFs::new();
    let root_inode = root_fs.root_inode();

    MOUNTS.lock().push(Mount {
        path: String::from("/"),
        fs: Box::new(root_fs),
        root_inode,
    });

    // Create standard directories.
    let _ = mkdir("/dev");
    let _ = mkdir("/tmp");
    let _ = mkdir("/home");
    let _ = mkdir("/bin");
    let _ = mkdir("/etc");

    // Create /dev/null and /dev/console.
    let _ = create_file("/dev/null");
    let _ = create_file("/dev/console");

    // Create /etc/hostname with default content.
    if let Ok(()) = create_file("/etc/hostname") {
        let _ = write_file("/etc/hostname", b"astryx\n");
    }

    // Create /etc/motd.
    if let Ok(()) = create_file("/etc/motd") {
        let _ = write_file("/etc/motd", b"Welcome to AstryxOS!\n");
    }

    crate::serial_println!("[VFS] Initialized with root ramfs, standard directories created");
}

/// Mount a filesystem at the given path.
pub fn mount(path: &str, fs: Box<dyn FileSystemOps>, root_inode: u64) {
    // Ensure mount point directory exists in parent filesystem.
    let _ = mkdir(path);

    MOUNTS.lock().push(Mount {
        path: String::from(path),
        fs,
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

    // ── Real disk at /disk (try AHCI first, then ATA PIO) ──────────────
    if !init_ahci_disks() {
        init_ata_disks();
    }
}

/// Backwards-compatible alias for `init_disks`.
pub fn init_fat32() {
    init_disks();
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

                match part.partition_type {
                    partition::PartitionType::Fat32 => {
                        // Try FAT32 first
                        let pdev = partition::create_partition_device(
                            Box::new(AhciBlockDevice::new(port)),
                            part.start_lba,
                            part.sector_count,
                        );
                        match fat32::Fat32Fs::new(Box::new(pdev)) {
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
                        let pdev = partition::create_partition_device(
                            Box::new(AhciBlockDevice::new(port)),
                            part.start_lba,
                            part.sector_count,
                        );
                        if let Some(fs) = ntfs::try_mount_ntfs(Box::new(pdev)) {
                            let root_inode = fs.root_inode();
                            mount("/ntfs", Box::new(fs), root_inode);
                            crate::serial_println!("[VFS] NTFS partition mounted at /ntfs (AHCI port {})", port);
                            mounted_any = true;
                        }
                    }
                    partition::PartitionType::Ntfs => {
                        let pdev = partition::create_partition_device(
                            Box::new(AhciBlockDevice::new(port)),
                            part.start_lba,
                            part.sector_count,
                        );
                        if let Some(fs) = ntfs::try_mount_ntfs(Box::new(pdev)) {
                            let root_inode = fs.root_inode();
                            mount("/ntfs", Box::new(fs), root_inode);
                            crate::serial_println!("[VFS] NTFS partition mounted at /ntfs (AHCI port {})", port);
                            mounted_any = true;
                        }
                    }
                    _ => {
                        crate::serial_println!("[VFS]   Skipping unsupported partition type: {:?}", part.partition_type);
                    }
                }
            }
        } else {
            // No partition table — try whole disk as FAT32 (legacy behavior)
            crate::serial_println!("[VFS] No partitions found on AHCI port {}, trying whole disk as FAT32...", port);
            let device = Box::new(AhciBlockDevice::new(port));

            match fat32::Fat32Fs::new(device) {
                Ok(fs) => {
                    let root_inode = fs.root_inode();
                    mount("/disk", Box::new(fs), root_inode);
                    crate::serial_println!("[VFS] FAT32 whole-disk mounted at /disk (AHCI port {})", port);
                    mounted_any = true;
                }
                Err(e) => {
                    crate::serial_println!("[VFS] AHCI port {} is not FAT32: {:?}", port, e);
                }
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

                // Re-probe to get a fresh device for this partition
                let fresh_devs = crate::drivers::ata::probe_all();
                if let Some(fresh_dev) = fresh_devs.into_iter().nth(dev_idx) {
                    let pdev = partition::create_partition_device(
                        Box::new(fresh_dev),
                        part.start_lba,
                        part.sector_count,
                    );
                    match part.partition_type {
                        partition::PartitionType::Fat32 => {
                            match fat32::Fat32Fs::new(Box::new(pdev)) {
                                Ok(fs) => {
                                    let root_inode = fs.root_inode();
                                    mount("/disk", Box::new(fs), root_inode);
                                    crate::serial_println!("[VFS] FAT32 partition mounted at /disk (ATA dev {})", dev_idx);
                                    return;
                                }
                                Err(_) => {
                                    // Try NTFS on this partition instead
                                    let fresh_devs2 = crate::drivers::ata::probe_all();
                                    if let Some(fd) = fresh_devs2.into_iter().nth(dev_idx) {
                                        let pd = partition::create_partition_device(
                                            Box::new(fd), part.start_lba, part.sector_count,
                                        );
                                        if let Some(fs) = ntfs::try_mount_ntfs(Box::new(pd)) {
                                            let root_inode = fs.root_inode();
                                            mount("/ntfs", Box::new(fs), root_inode);
                                            crate::serial_println!("[VFS] NTFS partition mounted at /ntfs (ATA dev {})", dev_idx);
                                        }
                                    }
                                }
                            }
                        }
                        partition::PartitionType::Ntfs => {
                            if let Some(fs) = ntfs::try_mount_ntfs(Box::new(pdev)) {
                                let root_inode = fs.root_inode();
                                mount("/ntfs", Box::new(fs), root_inode);
                                crate::serial_println!("[VFS] NTFS partition mounted at /ntfs (ATA dev {})", dev_idx);
                            }
                        }
                        _ => {
                            crate::serial_println!("[VFS]   Skipping unsupported partition type: {:?}", part.partition_type);
                        }
                    }
                }
            }
        } else {
            crate::serial_println!("[VFS] No partitions on ATA device {}, trying whole disk...", dev_idx);
        }
    }

    // Fallback: try each ATA device as whole-disk FAT32
    let devices2 = crate::drivers::ata::probe_all();
    for dev in devices2 {
        let boxed: Box<dyn crate::drivers::block::BlockDevice> = Box::new(dev);
        match fat32::Fat32Fs::new(boxed) {
            Ok(fs) => {
                let root_inode = fs.root_inode();
                mount("/disk", Box::new(fs), root_inode);
                crate::serial_println!("[VFS] FAT32 whole-disk mounted at /disk (ATA)");
                return;
            }
            Err(_) => {}
        }
    }
    crate::serial_println!("[VFS] No real ATA disk found");
}


/// Resolve a path to (mount_index, inode).
fn resolve_path(path: &str) -> VfsResult<(usize, u64)> {
    let mounts = MOUNTS.lock();
    if mounts.is_empty() {
        return Err(VfsError::NotFound);
    }

    // Find the deepest mount point that is a prefix of the path.
    let mut best_mount = 0;
    let mut best_len = 0;
    for (i, mount) in mounts.iter().enumerate() {
        if path.starts_with(mount.path.as_str()) && mount.path.len() >= best_len {
            best_mount = i;
            best_len = mount.path.len();
        }
    }

    let mount = &mounts[best_mount];
    let relative = &path[best_len..];

    // Walk the path components.
    let mut current_inode = mount.root_inode;
    if !relative.is_empty() {
        for component in relative.split('/').filter(|s| !s.is_empty()) {
            current_inode = mount.fs.lookup(current_inode, component)?;
        }
    }

    Ok((best_mount, current_inode))
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

/// Create a file at the given absolute path.
pub fn create_file(path: &str) -> VfsResult<()> {
    let (mount_idx, parent_inode, name) = resolve_parent(path)?;
    let mounts = MOUNTS.lock();
    mounts[mount_idx].fs.create_file(parent_inode, &name)?;
    Ok(())
}

/// Create a directory.
pub fn mkdir(path: &str) -> VfsResult<()> {
    let (mount_idx, parent_inode, name) = resolve_parent(path)?;
    let mounts = MOUNTS.lock();
    mounts[mount_idx].fs.create_dir(parent_inode, &name)?;
    Ok(())
}

/// Remove a file or empty directory.
pub fn remove(path: &str) -> VfsResult<()> {
    let (mount_idx, parent_inode, name) = resolve_parent(path)?;
    let mounts = MOUNTS.lock();
    mounts[mount_idx].fs.remove(parent_inode, &name)?;
    Ok(())
}

/// Stat a file.
pub fn stat(path: &str) -> VfsResult<FileStat> {
    let (mount_idx, inode) = resolve_path(path)?;
    let mounts = MOUNTS.lock();
    mounts[mount_idx].fs.stat(inode)
}

/// Read directory contents. Returns (name, file_type) pairs.
pub fn readdir(path: &str) -> VfsResult<Vec<(String, FileType)>> {
    let (mount_idx, inode) = resolve_path(path)?;
    let mounts = MOUNTS.lock();
    let entries = mounts[mount_idx].fs.readdir(inode)?;
    Ok(entries.into_iter().map(|(name, _ino, ft)| (name, ft)).collect())
}

/// Write data to a file (overwrite from beginning).
pub fn write_file(path: &str, data: &[u8]) -> VfsResult<usize> {
    let (mount_idx, inode) = resolve_path(path)?;
    let mounts = MOUNTS.lock();
    mounts[mount_idx].fs.truncate(inode, 0)?;
    mounts[mount_idx].fs.write(inode, 0, data)
}

/// Read data from a file.
pub fn read_file(path: &str) -> VfsResult<Vec<u8>> {
    let (mount_idx, inode) = resolve_path(path)?;
    let mounts = MOUNTS.lock();
    let stat = mounts[mount_idx].fs.stat(inode)?;
    let mut buf = alloc::vec![0u8; stat.size as usize];
    let n = mounts[mount_idx].fs.read(inode, 0, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Append data to a file.
pub fn append_file(path: &str, data: &[u8]) -> VfsResult<usize> {
    let (mount_idx, inode) = resolve_path(path)?;
    let mounts = MOUNTS.lock();
    let stat = mounts[mount_idx].fs.stat(inode)?;
    mounts[mount_idx].fs.write(inode, stat.size, data)
}

/// Sync (flush) all dirty data in all mounted filesystems to their backing store.
pub fn sync_all() {
    let mounts = MOUNTS.lock();
    for mount in mounts.iter() {
        let _ = mount.fs.sync();
    }
}

/// Rename (move) a file or directory.
pub fn rename(old_path: &str, new_path: &str) -> VfsResult<()> {
    let (old_mount, old_parent, old_name) = resolve_parent(old_path)?;
    let (new_mount, new_parent, new_name) = resolve_parent(new_path)?;
    if old_mount != new_mount {
        return Err(VfsError::Unsupported); // cross-mount rename not supported
    }
    let mounts = MOUNTS.lock();
    mounts[old_mount].fs.rename(old_parent, &old_name, new_parent, &new_name)
}

/// Create a symbolic link at `link_path` pointing to `target`.
pub fn symlink(link_path: &str, target: &str) -> VfsResult<()> {
    let (mount_idx, parent_inode, name) = resolve_parent(link_path)?;
    let mounts = MOUNTS.lock();
    mounts[mount_idx].fs.symlink(parent_inode, &name, target)?;
    Ok(())
}

/// Read the target of a symbolic link.
pub fn readlink(path: &str) -> VfsResult<String> {
    let (mount_idx, inode) = resolve_path(path)?;
    let mounts = MOUNTS.lock();
    mounts[mount_idx].fs.readlink(inode)
}

/// Change permission bits on a file/directory.
pub fn chmod(path: &str, mode: u32) -> VfsResult<()> {
    let (mount_idx, inode) = resolve_path(path)?;
    let mounts = MOUNTS.lock();
    mounts[mount_idx].fs.chmod(inode, mode)
}

// ===== Process File Descriptor Operations =====

/// Open a file for a process, returning the fd number.
pub fn open(pid: crate::proc::Pid, path: &str, open_flags: u32) -> VfsResult<usize> {
    // Try to resolve the path.
    let resolved = resolve_path(path);

    let (mount_idx, inode) = match resolved {
        Ok((m, i)) => (m, i),
        Err(VfsError::NotFound) if open_flags & flags::O_CREAT != 0 => {
            // Create the file.
            let (m, parent, name) = resolve_parent(path)?;
            let mounts = MOUNTS.lock();
            let ino = mounts[m].fs.create_file(parent, &name)?;
            (m, ino)
        }
        Err(e) => return Err(e),
    };

    let file_stat = {
        let mounts = MOUNTS.lock();
        mounts[mount_idx].fs.stat(inode)?
    };

    if open_flags & flags::O_TRUNC != 0 && file_stat.file_type == FileType::RegularFile {
        let mounts = MOUNTS.lock();
        mounts[mount_idx].fs.truncate(inode, 0)?;
    }

    let fd = FileDescriptor {
        inode,
        mount_idx,
        offset: 0,
        flags: open_flags,
        file_type: file_stat.file_type,
        is_console: false,
    };

    // Add to process's fd table.
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = procs.iter_mut().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;

    // Find first free fd slot (skip 0,1,2 which are console).
    for i in 0..proc.file_descriptors.len() {
        if proc.file_descriptors[i].is_none() {
            proc.file_descriptors[i] = Some(fd);
            return Ok(i);
        }
    }

    // Grow the fd table.
    if proc.file_descriptors.len() < MAX_FDS_PER_PROCESS {
        let idx = proc.file_descriptors.len();
        proc.file_descriptors.push(Some(fd));
        return Ok(idx);
    }

    Err(VfsError::TooManyOpenFiles)
}

/// Close a file descriptor.
pub fn close(pid: crate::proc::Pid, fd_num: usize) -> VfsResult<()> {
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = procs.iter_mut().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;

    if fd_num >= proc.file_descriptors.len() {
        return Err(VfsError::BadFd);
    }
    if proc.file_descriptors[fd_num].is_none() {
        return Err(VfsError::BadFd);
    }

    proc.file_descriptors[fd_num] = None;
    Ok(())
}

/// Read from a file descriptor.
pub fn fd_read(pid: crate::proc::Pid, fd_num: usize, buf: *mut u8, count: usize) -> VfsResult<usize> {
    let (mount_idx, inode, offset) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;
        let fd = proc.file_descriptors.get(fd_num)
            .and_then(|f| f.as_ref())
            .ok_or(VfsError::BadFd)?;
        if fd.is_console { return Err(VfsError::Unsupported); }
        (fd.mount_idx, fd.inode, fd.offset)
    };

    let mut buffer = unsafe { core::slice::from_raw_parts_mut(buf, count) };
    let n = {
        let mounts = MOUNTS.lock();
        mounts[mount_idx].fs.read(inode, offset, &mut buffer)?
    };

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

/// Write to a file descriptor.
pub fn fd_write(pid: crate::proc::Pid, fd_num: usize, buf: *const u8, count: usize) -> VfsResult<usize> {
    let (mount_idx, inode, offset, append) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter().find(|p| p.pid == pid).ok_or(VfsError::InvalidArg)?;
        let fd = proc.file_descriptors.get(fd_num)
            .and_then(|f| f.as_ref())
            .ok_or(VfsError::BadFd)?;
        if fd.is_console { return Err(VfsError::Unsupported); }
        (fd.mount_idx, fd.inode, fd.offset, fd.flags & flags::O_APPEND != 0)
    };

    let data = unsafe { core::slice::from_raw_parts(buf, count) };
    let write_offset = if append {
        let mounts = MOUNTS.lock();
        mounts[mount_idx].fs.stat(inode)?.size
    } else {
        offset
    };

    let n = {
        let mounts = MOUNTS.lock();
        mounts[mount_idx].fs.write(inode, write_offset, data)?
    };

    // Update offset.
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter_mut().find(|p| p.pid == pid).unwrap();
        if let Some(Some(fd)) = proc.file_descriptors.get_mut(fd_num) {
            fd.offset = write_offset + n as u64;
        }
    }

    Ok(n)
}
