//! Minimal sysfs — `/sys` virtual filesystem
//!
//! Exposes just the `/sys/devices/system/cpu/` subtree that Firefox ESR 115
//! (and other Gecko-based applications) read during CPU topology detection in
//! `mozglue` / `nsBaseAppShell`.  Missing files here cause Firefox to call
//! `exit(1)` before its event loop starts.
//!
//! Required paths (confirmed by syscall tracing):
//!   /sys/devices/system/cpu/present            — "0\n"
//!   /sys/devices/system/cpu/possible           — "0\n"
//!   /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq — "2000000\n" (kHz)
//!   /sys/devices/system/cpu/cpu0/cache/index2/size        — "4096K\n"  (L2)
//!   /sys/devices/system/cpu/cpu0/cache/index3/size        — "8192K\n"  (L3)
//!
//! All other paths return ENOENT.  Directories resolve correctly so stat() on
//! any intermediate directory succeeds.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::{FileSystemOps, FileStat, FileType, VfsError, VfsResult};

// ── Inode constants ──────────────────────────────────────────────────────────
// Range 3000–3099 reserved for sysfs; procfs uses 2000–2xxx.

const INO_ROOT:              u64 = 3000; // /sys
const INO_DEVICES:           u64 = 3001; // /sys/devices
const INO_SYSTEM:            u64 = 3002; // /sys/devices/system
const INO_CPU_DIR:           u64 = 3003; // /sys/devices/system/cpu
const INO_CPU_PRESENT:       u64 = 3004; // .../cpu/present
const INO_CPU_POSSIBLE:      u64 = 3005; // .../cpu/possible
const INO_CPU0_DIR:          u64 = 3010; // .../cpu/cpu0
const INO_CPU0_CPUFREQ:      u64 = 3011; // .../cpu/cpu0/cpufreq
const INO_CPU0_FREQ_MAX:     u64 = 3012; // .../cpu/cpu0/cpufreq/cpuinfo_max_freq
const INO_CPU0_CACHE:        u64 = 3013; // .../cpu/cpu0/cache
const INO_CPU0_IDX2:         u64 = 3014; // .../cpu/cpu0/cache/index2
const INO_CPU0_IDX2_SIZE:    u64 = 3015; // .../cpu/cpu0/cache/index2/size
const INO_CPU0_IDX3:         u64 = 3016; // .../cpu/cpu0/cache/index3
const INO_CPU0_IDX3_SIZE:    u64 = 3017; // .../cpu/cpu0/cache/index3/size

// ── SysFs filesystem ─────────────────────────────────────────────────────────

pub struct SysFs;

impl SysFs {
    pub fn new() -> Self {
        SysFs
    }

    pub fn root_inode(&self) -> u64 {
        INO_ROOT
    }

    fn file_type_for(inode: u64) -> Option<FileType> {
        match inode {
            INO_ROOT
            | INO_DEVICES
            | INO_SYSTEM
            | INO_CPU_DIR
            | INO_CPU0_DIR
            | INO_CPU0_CPUFREQ
            | INO_CPU0_CACHE
            | INO_CPU0_IDX2
            | INO_CPU0_IDX3 => Some(FileType::Directory),

            INO_CPU_PRESENT
            | INO_CPU_POSSIBLE
            | INO_CPU0_FREQ_MAX
            | INO_CPU0_IDX2_SIZE
            | INO_CPU0_IDX3_SIZE => Some(FileType::RegularFile),

            _ => None,
        }
    }

    fn content(inode: u64) -> Option<&'static [u8]> {
        match inode {
            // Single CPU (cpu0 only).
            INO_CPU_PRESENT  => Some(b"0\n"),
            INO_CPU_POSSIBLE => Some(b"0\n"),
            // 2 GHz reported in kHz (matches /proc/cpuinfo cpu MHz: 2000.000).
            INO_CPU0_FREQ_MAX  => Some(b"2000000\n"),
            // L2 4 MiB, L3 8 MiB — plausible for a QEMU virtual CPU.
            INO_CPU0_IDX2_SIZE => Some(b"4096K\n"),
            INO_CPU0_IDX3_SIZE => Some(b"8192K\n"),
            _ => None,
        }
    }
}

impl FileSystemOps for SysFs {
    fn name(&self) -> &str { "sysfs" }

    fn lookup(&self, parent: u64, name: &str) -> VfsResult<u64> {
        match (parent, name) {
            (INO_ROOT,       "devices")         => Ok(INO_DEVICES),
            (INO_DEVICES,    "system")          => Ok(INO_SYSTEM),
            (INO_SYSTEM,     "cpu")             => Ok(INO_CPU_DIR),
            (INO_CPU_DIR,    "present")         => Ok(INO_CPU_PRESENT),
            (INO_CPU_DIR,    "possible")        => Ok(INO_CPU_POSSIBLE),
            (INO_CPU_DIR,    "cpu0")            => Ok(INO_CPU0_DIR),
            (INO_CPU0_DIR,   "cpufreq")         => Ok(INO_CPU0_CPUFREQ),
            (INO_CPU0_CPUFREQ, "cpuinfo_max_freq") => Ok(INO_CPU0_FREQ_MAX),
            (INO_CPU0_DIR,   "cache")           => Ok(INO_CPU0_CACHE),
            (INO_CPU0_CACHE, "index2")          => Ok(INO_CPU0_IDX2),
            (INO_CPU0_IDX2,  "size")            => Ok(INO_CPU0_IDX2_SIZE),
            (INO_CPU0_CACHE, "index3")          => Ok(INO_CPU0_IDX3),
            (INO_CPU0_IDX3,  "size")            => Ok(INO_CPU0_IDX3_SIZE),
            _ => Err(VfsError::NotFound),
        }
    }

    fn stat(&self, inode: u64) -> VfsResult<FileStat> {
        let file_type = Self::file_type_for(inode).ok_or(VfsError::NotFound)?;
        // Real Linux sysfs regular files report `st_size = 0`; userspace
        // discovers actual content length by reading until EOF. A non-zero
        // size here makes some readers (e.g. glibc's internal sysfs probes
        // used by Firefox's mozglue CPU topology detection) allocate a
        // 4 KiB buffer and treat everything past the short read as padding.
        let size = 0u64;
        let _ = file_type; // kept by design — stat semantics don't depend on FileType here
        Ok(FileStat {
            inode,
            file_type,
            size,
            permissions: match file_type {
                FileType::Directory   => 0o555,
                FileType::RegularFile => 0o444,
                _                     => 0o444,
            },
            created: 0, modified: 0, accessed: 0,
        })
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let content = Self::content(inode).ok_or(VfsError::IsADirectory)?;
        let start = offset as usize;
        if start >= content.len() { return Ok(0); }
        let available = &content[start..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }

    fn readdir(&self, inode: u64) -> VfsResult<Vec<(String, u64, FileType)>> {
        macro_rules! f { ($n:expr, $i:expr) => { (String::from($n), $i, FileType::RegularFile) }; }
        macro_rules! d { ($n:expr, $i:expr) => { (String::from($n), $i, FileType::Directory) }; }
        let entries: Vec<(String, u64, FileType)> = match inode {
            INO_ROOT       => alloc::vec![d!("devices", INO_DEVICES)],
            INO_DEVICES    => alloc::vec![d!("system",  INO_SYSTEM)],
            INO_SYSTEM     => alloc::vec![d!("cpu",     INO_CPU_DIR)],
            INO_CPU_DIR    => alloc::vec![
                f!("present",  INO_CPU_PRESENT),
                f!("possible", INO_CPU_POSSIBLE),
                d!("cpu0",     INO_CPU0_DIR),
            ],
            INO_CPU0_DIR   => alloc::vec![
                d!("cpufreq", INO_CPU0_CPUFREQ),
                d!("cache",   INO_CPU0_CACHE),
            ],
            INO_CPU0_CPUFREQ => alloc::vec![f!("cpuinfo_max_freq", INO_CPU0_FREQ_MAX)],
            INO_CPU0_CACHE => alloc::vec![
                d!("index2", INO_CPU0_IDX2),
                d!("index3", INO_CPU0_IDX3),
            ],
            INO_CPU0_IDX2  => alloc::vec![f!("size", INO_CPU0_IDX2_SIZE)],
            INO_CPU0_IDX3  => alloc::vec![f!("size", INO_CPU0_IDX3_SIZE)],
            _ => return Err(VfsError::NotADirectory),
        };
        Ok(entries)
    }

    // ── Unsupported write operations ─────────────────────────────────────────

    fn write(&self, _inode: u64, _offset: u64, _data: &[u8]) -> VfsResult<usize> {
        Err(VfsError::PermissionDenied)
    }
    fn create_file(&self, _parent: u64, _name: &str) -> VfsResult<u64> {
        Err(VfsError::PermissionDenied)
    }
    fn create_dir(&self, _parent: u64, _name: &str) -> VfsResult<u64> {
        Err(VfsError::PermissionDenied)
    }
    fn remove(&self, _parent: u64, _name: &str) -> VfsResult<()> {
        Err(VfsError::PermissionDenied)
    }
    fn truncate(&self, _inode: u64, _size: u64) -> VfsResult<()> {
        Err(VfsError::PermissionDenied)
    }
}
