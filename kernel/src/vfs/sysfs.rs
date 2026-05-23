//! Minimal sysfs — `/sys` virtual filesystem
//!
//! Two subtrees are exposed today:
//!
//!   * `/sys/devices/system/cpu/...` — CPU topology files read by
//!     Firefox ESR 115 (mozglue / nsBaseAppShell) during start-up;
//!     missing files here cause Firefox to call `exit(1)` before its
//!     event loop starts.
//!
//!   * `/sys/class/net/<iface>/...` — per-interface attribute directories
//!     queried by Linux server binaries that perform network discovery
//!     via `glob("/sys/class/net/*")` (oracle endpoint agent's network
//!     collector, cloud-init's NoCloud datasource, anything based on
//!     `libnl`/`getifaddrs` with the `/sys` fallback).  The attribute set
//!     and content format follow
//!     `kernel.org/Documentation/ABI/testing/sysfs-class-net` and
//!     `Documentation/networking/operstates.rst`.
//!
//! Required CPU paths (confirmed by syscall tracing):
//!   /sys/devices/system/cpu/present            — "0-N\n" (cpulist)
//!   /sys/devices/system/cpu/possible           — "0-N\n" (cpulist)
//!   /sys/devices/system/cpu/online             — "0-N\n" (cpulist, sysconf _SC_NPROCESSORS_ONLN)
//!   /sys/devices/system/cpu/cpuX/cpufreq/cpuinfo_max_freq — "2000000\n" (kHz)
//!   /sys/devices/system/cpu/cpuX/cache/index2/size        — "4096K\n"  (L2)
//!   /sys/devices/system/cpu/cpuX/cache/index3/size        — "8192K\n"  (L3)
//!
//! Per-iface attribute set (each file ends with a newline per sysfs(5);
//! file sizes are reported as 0 per the ABI doc and userspace reads to
//! EOF):
//!   address     — "xx:xx:xx:xx:xx:xx\n"            (MAC, all-zero for lo)
//!   operstate   — one of up/down/unknown/...        (operstates.rst)
//!   mtu         — "<u32>\n"
//!   carrier     — "0\n" or "1\n"; EINVAL for lo     (no carrier concept)
//!   speed       — "<u32>\n" in Mb/s; "-1\n" for lo  (no link speed)
//!   flags       — "0x<hex u32>\n"                   (IFF_* mask)
//!   ifindex     — "<u32>\n"                         (RTM_GETLINK ifindex)
//!   type        — "<u16>\n"                         (ARPHRD_* code)
//!
//! Per-CPU directories `cpu0..cpu(N-1)` are enumerated dynamically from the
//! actual booted SMP CPU count (`apic::cpu_count()`).  Per-iface directories
//! are enumerated dynamically from `crate::net::list_ifaces()` on every
//! readdir / lookup (pull-on-read).  All other paths return ENOENT.
//! Directories resolve correctly so stat() on any intermediate directory
//! succeeds.
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

// ── Net subtree inode layout ─────────────────────────────────────────────────
// 3400–3499: fixed top-level dirs (/sys/class, /sys/class/net)
// 3500–3999: per-iface block of 16 inodes × up to ~31 ifaces
// The per-iface block is `INO_NET_IFACE_BASE + iface_idx * NET_IFACE_STRIDE`,
// where iface_idx is the position of the interface in `net::list_ifaces()`.
// Offsets within an iface block name attribute files (see NET_OFF_* below).
const INO_CLASS_DIR:        u64 = 3400; // /sys/class
const INO_NET_DIR:          u64 = 3401; // /sys/class/net
const INO_NET_IFACE_BASE:   u64 = 3500;
const NET_IFACE_STRIDE:     u64 = 16;
const MAX_NET_IFACES_SYSFS: u64 = 32; // bounds the 3500–3999 range; only ~2 are typical

// Per-iface attribute offsets within the 16-inode block.
const NET_OFF_DIR:       u64 = 0;  // <iface>/
const NET_OFF_ADDRESS:   u64 = 1;  // <iface>/address
const NET_OFF_OPERSTATE: u64 = 2;  // <iface>/operstate
const NET_OFF_MTU:       u64 = 3;  // <iface>/mtu
const NET_OFF_CARRIER:   u64 = 4;  // <iface>/carrier
const NET_OFF_SPEED:     u64 = 5;  // <iface>/speed
const NET_OFF_FLAGS:     u64 = 6;  // <iface>/flags
const NET_OFF_IFINDEX:   u64 = 7;  // <iface>/ifindex
const NET_OFF_TYPE:      u64 = 8;  // <iface>/type

#[inline] fn iface_dir_ino(i: u64)       -> u64 { INO_NET_IFACE_BASE + i * NET_IFACE_STRIDE + NET_OFF_DIR }
#[inline] fn iface_attr_ino(i: u64, o: u64) -> u64 { INO_NET_IFACE_BASE + i * NET_IFACE_STRIDE + o }

/// Decode an iface inode into `(iface_idx, attr_offset)` when in range.
fn decode_iface(inode: u64) -> Option<(u64, u64)> {
    if inode < INO_NET_IFACE_BASE || inode >= INO_NET_IFACE_BASE + MAX_NET_IFACES_SYSFS * NET_IFACE_STRIDE {
        return None;
    }
    let rel = inode - INO_NET_IFACE_BASE;
    let i   = rel / NET_IFACE_STRIDE;
    let off = rel % NET_IFACE_STRIDE;
    Some((i, off))
}

/// Render a per-iface attribute file's content given the iface index and
/// the attribute offset.  Returns `Some(bytes)` for readable scalars,
/// `None` for directories or out-of-range inodes.
///
/// Special encodings from kernel.org/Documentation/ABI/testing/sysfs-class-net:
///   - `carrier`: "1\n" or "0\n"; iface without carrier concept (loopback)
///     normally reports `EINVAL` on read.  We return `Some("0\n")` for
///     loopback rather than synthesise an error in the FS layer, so the
///     oracle collector observes a parseable value (it tolerates either).
///   - `speed`: positive integer or `-1\n` when undefined (loopback).
fn iface_attr_content(iface_idx: u64, off: u64) -> Option<Vec<u8>> {
    let ifaces = crate::net::list_ifaces();
    let info = ifaces.get(iface_idx as usize)?;
    let s = match off {
        NET_OFF_ADDRESS => format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            info.mac[0], info.mac[1], info.mac[2], info.mac[3], info.mac[4], info.mac[5],
        ),
        NET_OFF_OPERSTATE => {
            let mut s = String::from(info.operstate);
            s.push('\n');
            s
        }
        NET_OFF_MTU      => format!("{}\n", info.mtu),
        NET_OFF_CARRIER  => match info.carrier {
            Some(true)  => String::from("1\n"),
            Some(false) => String::from("0\n"),
            None        => String::from("0\n"), // loopback: no carrier concept
        },
        NET_OFF_SPEED    => match info.speed_mbps {
            Some(mb) => format!("{}\n", mb),
            None     => String::from("-1\n"), // loopback: no link speed
        },
        NET_OFF_FLAGS    => format!("0x{:x}\n", info.flags),
        NET_OFF_IFINDEX  => format!("{}\n", info.ifindex),
        NET_OFF_TYPE     => format!("{}\n", info.iftype),
        _ => return None,
    };
    Some(s.into_bytes())
}

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
            INO_ROOT | INO_DEVICES | INO_SYSTEM | INO_CPU_DIR
            | INO_CLASS_DIR | INO_NET_DIR
                => return Some(FileType::Directory),
            INO_CPU_PRESENT | INO_CPU_POSSIBLE | INO_CPU_ONLINE
                => return Some(FileType::RegularFile),
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
        if let Some((iface_idx, off)) = decode_iface(inode) {
            let nifaces = crate::net::list_ifaces().len() as u64;
            if iface_idx >= nifaces { return None; }
            return Some(match off {
                NET_OFF_DIR => FileType::Directory,
                _ => FileType::RegularFile,
            });
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
        if let Some((iface_idx, off)) = decode_iface(inode) {
            return iface_attr_content(iface_idx, off);
        }
        None
    }
}

impl FileSystemOps for SysFs {
    fn name(&self) -> &str { "sysfs" }

    fn lookup(&self, parent: u64, name: &str) -> VfsResult<u64> {
        // Top-level fixed paths.
        match (parent, name) {
            (INO_ROOT,       "devices")  => return Ok(INO_DEVICES),
            (INO_DEVICES,    "system")   => return Ok(INO_SYSTEM),
            (INO_SYSTEM,     "cpu")      => return Ok(INO_CPU_DIR),
            (INO_CPU_DIR,    "present")  => return Ok(INO_CPU_PRESENT),
            (INO_CPU_DIR,    "possible") => return Ok(INO_CPU_POSSIBLE),
            (INO_CPU_DIR,    "online")   => return Ok(INO_CPU_ONLINE),
            (INO_ROOT,       "class")    => return Ok(INO_CLASS_DIR),
            (INO_CLASS_DIR,  "net")      => return Ok(INO_NET_DIR),
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
        // /sys/class/net/<iface>
        if parent == INO_NET_DIR {
            let ifaces = crate::net::list_ifaces();
            for (idx, info) in ifaces.iter().enumerate() {
                if info.name == name {
                    return Ok(iface_dir_ino(idx as u64));
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
        // Per-iface attribute lookups (only valid under <iface>/ directory).
        if let Some((iface_idx, off)) = decode_iface(parent) {
            if off != NET_OFF_DIR { return Err(VfsError::NotADirectory); }
            let nifaces = crate::net::list_ifaces().len() as u64;
            if iface_idx >= nifaces { return Err(VfsError::NotFound); }
            let target_off = match name {
                "address"   => NET_OFF_ADDRESS,
                "operstate" => NET_OFF_OPERSTATE,
                "mtu"       => NET_OFF_MTU,
                "carrier"   => NET_OFF_CARRIER,
                "speed"     => NET_OFF_SPEED,
                "flags"     => NET_OFF_FLAGS,
                "ifindex"   => NET_OFF_IFINDEX,
                "type"      => NET_OFF_TYPE,
                _ => return Err(VfsError::NotFound),
            };
            return Ok(iface_attr_ino(iface_idx, target_off));
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
            INO_ROOT       => return Ok(alloc::vec![
                d!("devices", INO_DEVICES),
                d!("class",   INO_CLASS_DIR),
            ]),
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
            INO_CLASS_DIR  => return Ok(alloc::vec![d!("net", INO_NET_DIR)]),
            INO_NET_DIR    => {
                let ifaces = crate::net::list_ifaces();
                let mut v: Vec<(String, u64, FileType)> = Vec::with_capacity(ifaces.len());
                for (idx, info) in ifaces.iter().enumerate() {
                    v.push((info.name.clone(), iface_dir_ino(idx as u64), FileType::Directory));
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
        // Per-iface attribute readdir: only the iface directory (offset 0)
        // enumerates entries; reading "address"/"mtu"/etc. as a directory
        // returns NotADirectory which the VFS turns into ENOTDIR.
        if let Some((iface_idx, off)) = decode_iface(inode) {
            let nifaces = crate::net::list_ifaces().len() as u64;
            if iface_idx >= nifaces { return Err(VfsError::NotADirectory); }
            if off != NET_OFF_DIR { return Err(VfsError::NotADirectory); }
            return Ok(alloc::vec![
                f!("address",   iface_attr_ino(iface_idx, NET_OFF_ADDRESS)),
                f!("operstate", iface_attr_ino(iface_idx, NET_OFF_OPERSTATE)),
                f!("mtu",       iface_attr_ino(iface_idx, NET_OFF_MTU)),
                f!("carrier",   iface_attr_ino(iface_idx, NET_OFF_CARRIER)),
                f!("speed",     iface_attr_ino(iface_idx, NET_OFF_SPEED)),
                f!("flags",     iface_attr_ino(iface_idx, NET_OFF_FLAGS)),
                f!("ifindex",   iface_attr_ino(iface_idx, NET_OFF_IFINDEX)),
                f!("type",      iface_attr_ino(iface_idx, NET_OFF_TYPE)),
            ]);
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
