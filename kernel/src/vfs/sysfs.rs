//! Minimal sysfs — `/sys` virtual filesystem
//!
//! Exposes just the `/sys/devices/system/cpu/` subtree that Firefox ESR 115
//! (and other Gecko-based applications) read during CPU topology detection in
//! `mozglue` / `nsBaseAppShell`.  Missing files here cause Firefox to call
//! `exit(1)` before its event loop starts.
//!
//! Required paths (confirmed by syscall tracing):
//!   /sys/devices/system/cpu/present            — "0-N\n" (cpulist)
//!   /sys/devices/system/cpu/possible           — "0-N\n" (cpulist)
//!   /sys/devices/system/cpu/online             — "0-N\n" (cpulist, sysconf _SC_NPROCESSORS_ONLN)
//!   /sys/devices/system/cpu/cpuX/cpufreq/cpuinfo_max_freq — "2000000\n" (kHz)
//!   /sys/devices/system/cpu/cpuX/cache/index2/size        — "4096K\n"  (L2)
//!   /sys/devices/system/cpu/cpuX/cache/index3/size        — "8192K\n"  (L3)
//!
//! Per-CPU directories `cpu0..cpu(N-1)` are enumerated dynamically from the
//! actual booted SMP CPU count (`apic::cpu_count()`).  All other paths return
//! ENOENT.  Directories resolve correctly so stat() on any intermediate
//! directory succeeds.
//!
//! The cpulist format used by `present`/`possible`/`online` is a comma-
//! separated list of decimal CPU indices and ranges (sysfs(5)); for a
//! contiguous boot-time CPU set we always emit the "0-N" range form.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{FileSystemOps, FileStat, FileType, VfsError, VfsResult};

// ── Inode constants ──────────────────────────────────────────────────────────
// Range 3000–3099 reserved for sysfs scalars / top-level dirs;
// 3100–3399 reserved for per-CPU directory subtrees (16 inodes per CPU
// × 16 CPUs = 256 inodes max), matching apic::MAX_CPUS.

const INO_ROOT:              u64 = 3000; // /sys
const INO_DEVICES:           u64 = 3001; // /sys/devices
const INO_SYSTEM:            u64 = 3002; // /sys/devices/system
const INO_CPU_DIR:           u64 = 3003; // /sys/devices/system/cpu
const INO_CPU_PRESENT:       u64 = 3004; // .../cpu/present
const INO_CPU_POSSIBLE:      u64 = 3005; // .../cpu/possible
const INO_CPU_ONLINE:        u64 = 3006; // .../cpu/online

// Per-CPU subtree: base + cpu_idx * stride + offset.
const INO_CPU_BASE:          u64 = 3100;
const INO_CPU_STRIDE:        u64 = 16;
// Offsets within a per-CPU block.
const OFF_DIR:               u64 = 0;  // cpuX/
const OFF_CPUFREQ:           u64 = 1;  // cpuX/cpufreq/
const OFF_FREQ_MAX:          u64 = 2;  // cpuX/cpufreq/cpuinfo_max_freq
const OFF_CACHE:             u64 = 3;  // cpuX/cache/
const OFF_IDX2:              u64 = 4;  // cpuX/cache/index2/
const OFF_IDX2_SIZE:         u64 = 5;  // cpuX/cache/index2/size
const OFF_IDX3:              u64 = 6;  // cpuX/cache/index3/
const OFF_IDX3_SIZE:         u64 = 7;  // cpuX/cache/index3/size

const MAX_CPUS_SYSFS: u64 = 16; // mirrors apic::MAX_CPUS

#[inline] fn cpu_dir_ino(cpu: u64)         -> u64 { INO_CPU_BASE + cpu * INO_CPU_STRIDE + OFF_DIR }
#[inline] fn cpu_cpufreq_ino(cpu: u64)     -> u64 { INO_CPU_BASE + cpu * INO_CPU_STRIDE + OFF_CPUFREQ }
#[inline] fn cpu_freq_max_ino(cpu: u64)    -> u64 { INO_CPU_BASE + cpu * INO_CPU_STRIDE + OFF_FREQ_MAX }
#[inline] fn cpu_cache_ino(cpu: u64)       -> u64 { INO_CPU_BASE + cpu * INO_CPU_STRIDE + OFF_CACHE }
#[inline] fn cpu_idx2_ino(cpu: u64)        -> u64 { INO_CPU_BASE + cpu * INO_CPU_STRIDE + OFF_IDX2 }
#[inline] fn cpu_idx2_size_ino(cpu: u64)   -> u64 { INO_CPU_BASE + cpu * INO_CPU_STRIDE + OFF_IDX2_SIZE }
#[inline] fn cpu_idx3_ino(cpu: u64)        -> u64 { INO_CPU_BASE + cpu * INO_CPU_STRIDE + OFF_IDX3 }
#[inline] fn cpu_idx3_size_ino(cpu: u64)   -> u64 { INO_CPU_BASE + cpu * INO_CPU_STRIDE + OFF_IDX3_SIZE }

/// Decode a per-CPU inode into `(cpu_idx, offset)` if it lies in the per-CPU
/// range; otherwise None.
fn decode_per_cpu(inode: u64) -> Option<(u64, u64)> {
    if inode < INO_CPU_BASE { return None; }
    let rel = inode - INO_CPU_BASE;
    let cpu = rel / INO_CPU_STRIDE;
    let off = rel % INO_CPU_STRIDE;
    if cpu >= MAX_CPUS_SYSFS { return None; }
    Some((cpu, off))
}

fn cpu_count() -> u64 {
    crate::arch::x86_64::apic::cpu_count() as u64
}

/// "0\n" if N==1, else "0-{N-1}\n" — the cpulist range form (sysfs(5)).
fn cpulist_range() -> String {
    let n = cpu_count().max(1);
    if n == 1 { String::from("0\n") } else { format!("0-{}\n", n - 1) }
}

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
            INO_ROOT | INO_DEVICES | INO_SYSTEM | INO_CPU_DIR => return Some(FileType::Directory),
            INO_CPU_PRESENT | INO_CPU_POSSIBLE | INO_CPU_ONLINE => return Some(FileType::RegularFile),
            _ => {}
        }
        if let Some((cpu, off)) = decode_per_cpu(inode) {
            if cpu >= cpu_count() { return None; }
            return match off {
                OFF_DIR | OFF_CPUFREQ | OFF_CACHE | OFF_IDX2 | OFF_IDX3 => Some(FileType::Directory),
                OFF_FREQ_MAX | OFF_IDX2_SIZE | OFF_IDX3_SIZE          => Some(FileType::RegularFile),
                _ => None,
            };
        }
        None
    }

    /// Returns the file content for a regular-file inode, owned, since some
    /// values (cpulist) are computed at boot from the live CPU count.
    fn content(inode: u64) -> Option<Vec<u8>> {
        match inode {
            INO_CPU_PRESENT | INO_CPU_POSSIBLE | INO_CPU_ONLINE => {
                return Some(cpulist_range().into_bytes());
            }
            _ => {}
        }
        if let Some((cpu, off)) = decode_per_cpu(inode) {
            if cpu >= cpu_count() { return None; }
            return match off {
                // 2 GHz reported in kHz (matches /proc/cpuinfo cpu MHz: 2000.000).
                OFF_FREQ_MAX  => Some(b"2000000\n".to_vec()),
                // L2 4 MiB, L3 8 MiB — plausible for a QEMU virtual CPU.
                OFF_IDX2_SIZE => Some(b"4096K\n".to_vec()),
                OFF_IDX3_SIZE => Some(b"8192K\n".to_vec()),
                _ => None,
            };
        }
        None
    }
}

impl FileSystemOps for SysFs {
    fn name(&self) -> &str { "sysfs" }

    fn lookup(&self, parent: u64, name: &str) -> VfsResult<u64> {
        // Top-level fixed paths.
        match (parent, name) {
            (INO_ROOT,    "devices")  => return Ok(INO_DEVICES),
            (INO_DEVICES, "system")   => return Ok(INO_SYSTEM),
            (INO_SYSTEM,  "cpu")      => return Ok(INO_CPU_DIR),
            (INO_CPU_DIR, "present")  => return Ok(INO_CPU_PRESENT),
            (INO_CPU_DIR, "possible") => return Ok(INO_CPU_POSSIBLE),
            (INO_CPU_DIR, "online")   => return Ok(INO_CPU_ONLINE),
            _ => {}
        }
        // /sys/devices/system/cpu/cpuN
        if parent == INO_CPU_DIR {
            if let Some(idx_str) = name.strip_prefix("cpu") {
                if let Ok(idx) = idx_str.parse::<u64>() {
                    if idx < cpu_count() {
                        return Ok(cpu_dir_ino(idx));
                    }
                }
            }
            return Err(VfsError::NotFound);
        }
        // Per-CPU subtree lookups.
        if let Some((cpu, off)) = decode_per_cpu(parent) {
            if cpu >= cpu_count() { return Err(VfsError::NotFound); }
            return match (off, name) {
                (OFF_DIR,     "cpufreq")          => Ok(cpu_cpufreq_ino(cpu)),
                (OFF_DIR,     "cache")            => Ok(cpu_cache_ino(cpu)),
                (OFF_CPUFREQ, "cpuinfo_max_freq") => Ok(cpu_freq_max_ino(cpu)),
                (OFF_CACHE,   "index2")           => Ok(cpu_idx2_ino(cpu)),
                (OFF_CACHE,   "index3")           => Ok(cpu_idx3_ino(cpu)),
                (OFF_IDX2,    "size")             => Ok(cpu_idx2_size_ino(cpu)),
                (OFF_IDX3,    "size")             => Ok(cpu_idx3_size_ino(cpu)),
                _ => Err(VfsError::NotFound),
            };
        }
        Err(VfsError::NotFound)
    }

    fn stat(&self, inode: u64) -> VfsResult<FileStat> {
        let file_type = Self::file_type_for(inode).ok_or(VfsError::NotFound)?;
        // Real Linux sysfs regular files report `st_size = 0`; userspace
        // discovers actual content length by reading until EOF.
        let size = 0u64;
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
        match inode {
            INO_ROOT       => return Ok(alloc::vec![d!("devices", INO_DEVICES)]),
            INO_DEVICES    => return Ok(alloc::vec![d!("system",  INO_SYSTEM)]),
            INO_SYSTEM     => return Ok(alloc::vec![d!("cpu",     INO_CPU_DIR)]),
            INO_CPU_DIR    => {
                let mut v: Vec<(String, u64, FileType)> = alloc::vec![
                    f!("present",  INO_CPU_PRESENT),
                    f!("possible", INO_CPU_POSSIBLE),
                    f!("online",   INO_CPU_ONLINE),
                ];
                let n = cpu_count();
                for cpu in 0..n {
                    v.push((format!("cpu{}", cpu), cpu_dir_ino(cpu), FileType::Directory));
                }
                return Ok(v);
            }
            _ => {}
        }
        if let Some((cpu, off)) = decode_per_cpu(inode) {
            if cpu >= cpu_count() { return Err(VfsError::NotADirectory); }
            return match off {
                OFF_DIR => Ok(alloc::vec![
                    d!("cpufreq", cpu_cpufreq_ino(cpu)),
                    d!("cache",   cpu_cache_ino(cpu)),
                ]),
                OFF_CPUFREQ => Ok(alloc::vec![f!("cpuinfo_max_freq", cpu_freq_max_ino(cpu))]),
                OFF_CACHE => Ok(alloc::vec![
                    d!("index2", cpu_idx2_ino(cpu)),
                    d!("index3", cpu_idx3_ino(cpu)),
                ]),
                OFF_IDX2 => Ok(alloc::vec![f!("size", cpu_idx2_size_ino(cpu))]),
                OFF_IDX3 => Ok(alloc::vec![f!("size", cpu_idx3_size_ino(cpu))]),
                _ => Err(VfsError::NotADirectory),
            };
        }
        Err(VfsError::NotADirectory)
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
