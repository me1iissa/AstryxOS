//! /proc Filesystem — Process & System Information
//!
//! Provides a virtual filesystem exposing kernel and process state
//! as readable files, inspired by Linux's procfs.
//!
//! Two independent interfaces are offered:
//!
//! 1. **Shell helper** — `read_procfs(path)` prints proc entries to the serial
//!    console. Used by the kernel debug shell. Unchanged from before.
//!
//! 2. **VFS-mounted filesystem** — `ProcFs` implements `FileSystemOps` and is
//!    mounted at `/proc` by `vfs::init()`.  Every `read()` call generates fresh
//!    content from live kernel state so userspace programs see up-to-date data.
//!
//! # Inode layout (ProcFs-internal; never exposed across a mount boundary)
//! ```
//! 2000  /proc (root dir)
//! 2001  cpuinfo
//! 2002  meminfo
//! 2003  uptime
//! 2004  version
//! 2005  mounts
//! 2006  cmdline  (kernel command line — NOT /proc/self/cmdline)
//! 2010  self/    (directory — resolved to caller's /proc/<pid>/ by VFS open)
//! 2011  self/maps
//! 2012  self/status
//! 2013  self/cmdline
//! 2014  self/stat
//! 2015  self/exe
//! 2016  self/comm
//! 2017  self/environ
//! 2018  self/auxv
//! 2020  self/fd/ (directory)
//! 2050  self/task/ (directory)
//! 2051  self/task/<tid>/ (shared inode — tid encoded in open_path)
//! 2052  self/task/<tid>/stat (shared inode)
//! 2060  self/mountinfo
//! 2061  self/cgroup
//! 2062  self/oom_score_adj
//! 2063  self/loginuid
//! 2030  sys/     (directory)
//! 2031  sys/vm/  (directory)
//! 2032  sys/kernel/ (directory)
//! 2033  sys/kernel/random/ (directory)
//! 2040  sys/vm/overcommit_memory
//! 2041  sys/vm/max_map_count
//! 2042  sys/kernel/pid_max
//! 2043  sys/kernel/random/uuid
//! ```

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::{FileSystemOps, FileStat, FileType, VfsError, VfsResult};

// ── Inode constants ──────────────────────────────────────────────────────────

const INO_ROOT:              u64 = 2000;
const INO_CPUINFO:           u64 = 2001;
const INO_MEMINFO:           u64 = 2002;
const INO_UPTIME:            u64 = 2003;
const INO_VERSION:           u64 = 2004;
const INO_MOUNTS:            u64 = 2005;
const INO_CMDLINE:           u64 = 2006;
const INO_KMSG:              u64 = 2008; // /proc/kmsg — kernel log ring snapshot
const INO_SELF_DIR:          u64 = 2010;
const INO_SELF_MAPS:         u64 = 2011;
const INO_SELF_STATUS:       u64 = 2012;
const INO_SELF_CMDLINE:      u64 = 2013;
const INO_SELF_STAT:         u64 = 2014;
const INO_SELF_EXE:          u64 = 2015;
const INO_SELF_COMM:         u64 = 2016;
const INO_SELF_ENVIRON:      u64 = 2017;
const INO_SELF_AUXV:         u64 = 2018;
const INO_SELF_FD_DIR:       u64 = 2020;
// /proc/self/task  — per-thread subtree required by glibc start_thread
// Range 2050-2059 reserved for task entries.
const INO_SELF_TASK_DIR:     u64 = 2050; // /proc/self/task/
const INO_SELF_TASK_TID_DIR: u64 = 2051; // /proc/self/task/<tid>/   (shared, tid in fd open_path)
const INO_SELF_TASK_STAT:    u64 = 2052; // /proc/self/task/<tid>/stat
// /proc/self/{mountinfo,cgroup,oom_score_adj,loginuid} — needed by glibc's
// scandir hook, Mozilla's sandbox policy builder, and various process-info
// probers (per proc(5)).  ENOENT here makes Mozilla fall back to a refuse-all
// sandbox policy that then prevents glxtest from ever being spawned.
const INO_SELF_MOUNTINFO:    u64 = 2060;
const INO_SELF_CGROUP:       u64 = 2061;
const INO_SELF_OOM_ADJ:      u64 = 2062;
const INO_SELF_LOGINUID:     u64 = 2063;
const INO_SYS_DIR:           u64 = 2030;
const INO_SYS_VM_DIR:        u64 = 2031;
const INO_SYS_KERNEL_DIR:    u64 = 2032;
const INO_SYS_KERNEL_RAND:   u64 = 2033;
const INO_STAT:              u64 = 2007;
const INO_OVERCOMMIT:        u64 = 2040;
const INO_MAX_MAP_COUNT:     u64 = 2041;
const INO_PID_MAX:           u64 = 2042;
const INO_RAND_UUID:         u64 = 2043;
// /proc/sys/net/ipv6/conf/{all,default}/disable_ipv6 — the Linux-faithful
// runtime IPv6 enable/disable sysctl (see net::ipver).  Reading returns
// "1\n" when IPv6 is disabled, "0\n" when enabled; writing "1"/"0" toggles it.
const INO_SYS_NET_DIR:       u64 = 2070; // sys/net/
const INO_SYS_NET_IPV6_DIR:  u64 = 2071; // sys/net/ipv6/
const INO_SYS_NET_IPV6_CONF: u64 = 2072; // sys/net/ipv6/conf/
const INO_SYS_NET_IPV6_ALL:  u64 = 2073; // sys/net/ipv6/conf/all/
const INO_SYS_NET_IPV6_DEF:  u64 = 2074; // sys/net/ipv6/conf/default/
const INO_DISABLE_IPV6_ALL:  u64 = 2075; // sys/net/ipv6/conf/all/disable_ipv6
const INO_DISABLE_IPV6_DEF:  u64 = 2076; // sys/net/ipv6/conf/default/disable_ipv6

// ── ProcFs filesystem ────────────────────────────────────────────────────────

/// A read-only virtual filesystem mounted at `/proc`.
///
/// All inode numbers are fixed constants — there is no mutable state.
/// Content is generated fresh on every `read()` call.
pub struct ProcFs;

impl ProcFs {
    pub fn new() -> Self {
        ProcFs
    }

    /// Return the inode number used as the root of this mount.
    pub fn root_inode(&self) -> u64 {
        INO_ROOT
    }

    fn file_type_for(inode: u64) -> Option<FileType> {
        match inode {
            INO_ROOT
            | INO_SELF_DIR
            | INO_SELF_FD_DIR
            | INO_SELF_TASK_DIR
            | INO_SELF_TASK_TID_DIR
            | INO_SYS_DIR
            | INO_SYS_VM_DIR
            | INO_SYS_KERNEL_DIR
            | INO_SYS_KERNEL_RAND
            | INO_SYS_NET_DIR
            | INO_SYS_NET_IPV6_DIR
            | INO_SYS_NET_IPV6_CONF
            | INO_SYS_NET_IPV6_ALL
            | INO_SYS_NET_IPV6_DEF => Some(FileType::Directory),

            INO_CPUINFO
            | INO_MEMINFO
            | INO_UPTIME
            | INO_VERSION
            | INO_MOUNTS
            | INO_CMDLINE
            | INO_KMSG
            | INO_STAT
            | INO_SELF_MAPS
            | INO_SELF_STATUS
            | INO_SELF_CMDLINE
            | INO_SELF_STAT
            | INO_SELF_EXE
            | INO_SELF_COMM
            | INO_SELF_ENVIRON
            | INO_SELF_AUXV
            | INO_SELF_TASK_STAT
            | INO_SELF_MOUNTINFO
            | INO_SELF_CGROUP
            | INO_SELF_OOM_ADJ
            | INO_SELF_LOGINUID
            | INO_OVERCOMMIT
            | INO_MAX_MAP_COUNT
            | INO_PID_MAX
            | INO_RAND_UUID
            | INO_DISABLE_IPV6_ALL
            | INO_DISABLE_IPV6_DEF => Some(FileType::RegularFile),

            // /proc/self/fd/<N> entries — modelled as symlinks per the Linux
            // procfs(5) contract.  Inode encoding: 3000 + fd_num (see
            // `lookup` and `readdir` for the encoding).  The cap of 4096
            // is 4× MAX_FDS_PER_PROCESS (currently 1024), giving headroom
            // for future expansion of the per-process fd table without
            // re-encoding inode numbers.
            n if n >= 3000 && n < 3000 + 4096 => Some(FileType::SymLink),

            _ => None,
        }
    }

    /// Generate the content for inodes that don't require caller-PID context.
    /// Returns `None` for inodes whose content is generated by `vfs::fd_read()`
    /// special-case dispatch (maps, status, stat, cmdline — all need PID).
    fn generate_content(inode: u64) -> Option<Vec<u8>> {
        match inode {
            INO_CPUINFO => Some(generate_cpuinfo()),
            INO_MEMINFO => Some(generate_meminfo()),
            INO_UPTIME  => Some(generate_uptime()),
            INO_VERSION => Some(generate_version()),
            INO_MOUNTS  => Some(generate_mounts()),
            INO_STAT    => Some(generate_stat()),
            INO_CMDLINE => Some(b"astryx_kernel root=/dev/ramdisk0 console=fb0\n".to_vec()),
            // /proc/kmsg — snapshot of the kernel log ring (the same ring
            // syslog(2)/klogctl reads).  A non-streaming snapshot read: each
            // open returns the current ring contents.  Backed by the shared
            // ring in `crate::util::dmesg`.
            INO_KMSG => Some(crate::util::dmesg::snapshot()),
            // /proc/self/maps — real content from the calling process's VMA table.
            // fd_read() intercepts this path first (see vfs/mod.rs) and delegates
            // to generate_proc_maps() with the caller's PID.  This arm is the
            // fallback when ProcFs::read() is invoked directly (e.g. from the
            // kernel debug shell or a stat-only probe).
            INO_SELF_MAPS     => Some(generate_proc_maps(crate::proc::current_pid())),
            INO_SELF_STATUS   => Some(b"Name:\tastryx\nState:\tR (running)\nPid:\t1\nPPid:\t0\n".to_vec()),
            INO_SELF_CMDLINE  => Some(b"astryx\0".to_vec()),
            INO_SELF_STAT     => Some(b"1 (astryx) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 65536 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n".to_vec()),
            // task/<tid>/stat — stub; real content generated by fd_read() using TID from path.
            INO_SELF_TASK_STAT => Some(b"1 (astryx) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 65536 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n".to_vec()),
            // /proc/self/mountinfo — stub (real content emitted by fd_read() to
            // avoid re-entering MOUNTS.lock(); see generate_mountinfo()).
            // Stub format per proc(5): the canonical 11-column mountinfo line.
            INO_SELF_MOUNTINFO => Some(b"1 0 0:1 / / rw,relatime shared:1 - ramfs ramfs rw\n".to_vec()),
            // /proc/self/cgroup — cgroup v2 unified hierarchy; no controllers.
            // The "0::/" form is the universal "process not in any cgroup" reply.
            INO_SELF_CGROUP    => Some(b"0::/\n".to_vec()),
            // /proc/self/oom_score_adj — readable score adjustment.  Mozilla
            // reads this to detect the [-1000, 1000] range; "0\n" is safe.
            INO_SELF_OOM_ADJ   => Some(b"0\n".to_vec()),
            // /proc/self/loginuid — per audit(7), -1 (0xFFFFFFFF as u32, written
            // as 4294967295) means "no audit login uid set" which is the
            // expected reply on a system without auditd.
            INO_SELF_LOGINUID  => Some(b"4294967295\n".to_vec()),
            INO_SELF_EXE      => Some(b"/disk/bin/init".to_vec()),
            INO_SELF_COMM     => Some(b"astryx\n".to_vec()),
            INO_SELF_ENVIRON  => Some(b"\0".to_vec()),
            // auxv is intercepted by fd_read() which generates live content.
            // Return a minimal AT_NULL pair as a non-empty stub.
            INO_SELF_AUXV     => {
                let mut v = [0u8; 16];
                // AT_NULL (0), 0 — valid terminated auxvec
                v[0..8].copy_from_slice(&0u64.to_le_bytes());
                v[8..16].copy_from_slice(&0u64.to_le_bytes());
                Some(v.to_vec())
            }
            INO_OVERCOMMIT    => Some(b"0\n".to_vec()),
            INO_MAX_MAP_COUNT => Some(b"65530\n".to_vec()),
            INO_PID_MAX       => Some(b"65536\n".to_vec()),
            INO_RAND_UUID     => Some(b"deadbeef-cafe-1234-5678-0a0b0c0d0e0f\n".to_vec()),
            // /proc/sys/net/ipv6/conf/{all,default}/disable_ipv6 — the value is
            // the logical negation of net::ipver::ipv6_enabled().  "1\n" means
            // IPv6 is disabled, "0\n" means it is enabled.  Both the `all` and
            // `default` nodes read the same global flag (AstryxOS has a single
            // network namespace / interface set).
            INO_DISABLE_IPV6_ALL | INO_DISABLE_IPV6_DEF => {
                if crate::net::ipver::ipv6_enabled() {
                    Some(b"0\n".to_vec())
                } else {
                    Some(b"1\n".to_vec())
                }
            }
            _ => None,
        }
    }
}

impl FileSystemOps for ProcFs {
    fn name(&self) -> &str { "procfs" }

    fn lookup(&self, parent_inode: u64, name: &str) -> VfsResult<u64> {
        match (parent_inode, name) {
            (INO_ROOT, "cpuinfo")           => Ok(INO_CPUINFO),
            (INO_ROOT, "meminfo")           => Ok(INO_MEMINFO),
            (INO_ROOT, "uptime")            => Ok(INO_UPTIME),
            (INO_ROOT, "version")           => Ok(INO_VERSION),
            (INO_ROOT, "mounts")            => Ok(INO_MOUNTS),
            (INO_ROOT, "cmdline")           => Ok(INO_CMDLINE),
            (INO_ROOT, "kmsg")              => Ok(INO_KMSG),
            (INO_ROOT, "stat")              => Ok(INO_STAT),
            (INO_ROOT, "self")              => Ok(INO_SELF_DIR),
            (INO_ROOT, "sys")               => Ok(INO_SYS_DIR),
            // /proc/<numeric-pid> — resolve to INO_SELF_DIR so that child
            // lookups (maps, status, …) use the shared per-process inode set.
            // The fd's open_path retains the original numeric path so fd_read()
            // can serve the *target* process's data (see vfs/mod.rs C4).
            //
            // Per proc(5): accessing /proc/<pid>/ for a nonexistent PID must
            // return ENOENT — we validate here rather than at read time so
            // that open(2) itself fails with the correct error code.
            (INO_ROOT, name) if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) => {
                let target_pid: crate::proc::Pid = name.parse().map_err(|_| VfsError::NotFound)?;
                let exists = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    procs.iter().any(|p| p.pid == target_pid)
                };
                if !exists {
                    return Err(VfsError::NotFound);
                }
                Ok(INO_SELF_DIR)
            }
            (INO_SELF_DIR, "maps")          => Ok(INO_SELF_MAPS),
            (INO_SELF_DIR, "status")        => Ok(INO_SELF_STATUS),
            (INO_SELF_DIR, "cmdline")       => Ok(INO_SELF_CMDLINE),
            (INO_SELF_DIR, "stat")          => Ok(INO_SELF_STAT),
            (INO_SELF_DIR, "exe")           => Ok(INO_SELF_EXE),
            (INO_SELF_DIR, "comm")          => Ok(INO_SELF_COMM),
            (INO_SELF_DIR, "environ")       => Ok(INO_SELF_ENVIRON),
            (INO_SELF_DIR, "auxv")          => Ok(INO_SELF_AUXV),
            (INO_SELF_DIR, "fd")            => Ok(INO_SELF_FD_DIR),
            // /proc/self/task/ — required by glibc start_thread for thread-specific stat
            (INO_SELF_DIR, "task")          => Ok(INO_SELF_TASK_DIR),
            // /proc/self/mountinfo — Mozilla sandbox policy enumerates filesystems
            // via this; ENOENT used to make it fall back to a refuse-all policy
            // that prevented glxtest from being spawned at all.
            (INO_SELF_DIR, "mountinfo")     => Ok(INO_SELF_MOUNTINFO),
            // /proc/self/cgroup — cgroup-aware userspace reads "0::/\n" for the
            // unified hierarchy root on a system without cgroup controllers.
            (INO_SELF_DIR, "cgroup")        => Ok(INO_SELF_CGROUP),
            // /proc/self/oom_score_adj — Mozilla / systemd / pulseaudio all
            // probe this; ENOENT makes them log noisy warnings.
            (INO_SELF_DIR, "oom_score_adj") => Ok(INO_SELF_OOM_ADJ),
            // /proc/self/loginuid — audit(7) login uid; -1 = unset.
            (INO_SELF_DIR, "loginuid")      => Ok(INO_SELF_LOGINUID),
            // /proc/self/task/<tid>/ — any numeric TID maps to the shared tid-dir inode.
            (INO_SELF_TASK_DIR, name)
                if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) => {
                Ok(INO_SELF_TASK_TID_DIR)
            }
            // /proc/self/task/<tid>/stat
            (INO_SELF_TASK_TID_DIR, "stat") => Ok(INO_SELF_TASK_STAT),
            (INO_SYS_DIR,  "vm")            => Ok(INO_SYS_VM_DIR),
            (INO_SYS_DIR,  "kernel")        => Ok(INO_SYS_KERNEL_DIR),
            (INO_SYS_DIR,  "net")           => Ok(INO_SYS_NET_DIR),
            (INO_SYS_VM_DIR, "overcommit_memory") => Ok(INO_OVERCOMMIT),
            (INO_SYS_VM_DIR, "max_map_count")     => Ok(INO_MAX_MAP_COUNT),
            (INO_SYS_KERNEL_DIR, "pid_max")       => Ok(INO_PID_MAX),
            (INO_SYS_KERNEL_DIR, "random")        => Ok(INO_SYS_KERNEL_RAND),
            (INO_SYS_KERNEL_RAND, "uuid")         => Ok(INO_RAND_UUID),
            // /proc/sys/net/ipv6/conf/{all,default}/disable_ipv6 — runtime IPv6
            // toggle (see net::ipver).  Path components per the Linux
            // ip-sysctl(7) layout.
            (INO_SYS_NET_DIR,        "ipv6")         => Ok(INO_SYS_NET_IPV6_DIR),
            (INO_SYS_NET_IPV6_DIR,   "conf")         => Ok(INO_SYS_NET_IPV6_CONF),
            (INO_SYS_NET_IPV6_CONF,  "all")          => Ok(INO_SYS_NET_IPV6_ALL),
            (INO_SYS_NET_IPV6_CONF,  "default")      => Ok(INO_SYS_NET_IPV6_DEF),
            (INO_SYS_NET_IPV6_ALL,   "disable_ipv6") => Ok(INO_DISABLE_IPV6_ALL),
            (INO_SYS_NET_IPV6_DEF,   "disable_ipv6") => Ok(INO_DISABLE_IPV6_DEF),
            // /proc/self/fd/<N> — any numeric name is accepted (returns a stub inode)
            (INO_SELF_FD_DIR, _) if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) => {
                // Use the fd number as part of the inode.  The VFS readlink syscall
                // handles /proc/self/fd/<N> specially anyway.
                let n: u64 = name.parse().unwrap_or(0);
                Ok(3000 + n)
            }
            _ => Err(VfsError::NotFound),
        }
    }

    fn stat(&self, inode: u64) -> VfsResult<FileStat> {
        // Dynamic files report size 0 — callers must not rely on size for reads.
        // The VFS fd_read() path advances the offset through serve_dynamic_read()
        // which re-generates content on every read call.
        let file_type = Self::file_type_for(inode)
            .ok_or(VfsError::NotFound)?;
        let size = match file_type {
            FileType::RegularFile => {
                // Provide a non-zero size hint so callers that pre-allocate a
                // buffer based on stat().size get *something* reasonable.
                // Dynamic files may produce more or fewer bytes; callers must
                // handle short or extended reads.
                4096u64
            }
            FileType::Directory => 0,
            _ => 0,
        };
        // oom_score_adj / loginuid are writable per proc(5).
        let perms = match inode {
            INO_SELF_OOM_ADJ | INO_SELF_LOGINUID => 0o644,
            // disable_ipv6 sysctls are writable per the Linux sysctl contract.
            INO_DISABLE_IPV6_ALL | INO_DISABLE_IPV6_DEF => 0o644,
            _ => match file_type {
                FileType::Directory   => 0o555,
                FileType::RegularFile => 0o444,
                _                     => 0o444,
            },
        };
        Ok(FileStat {
            inode,
            file_type,
            size,
            permissions: perms,
            created: 0,
            modified: 0,
            accessed: 0,
        })
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // For inodes whose content is generated entirely here.
        let content = Self::generate_content(inode)
            .ok_or(VfsError::IsADirectory)?;
        let start = offset as usize;
        if start >= content.len() {
            return Ok(0);
        }
        let available = &content[start..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }

    fn readdir(&self, inode: u64) -> VfsResult<Vec<(String, u64, FileType)>> {
        macro_rules! f { ($n:expr, $i:expr) => { (String::from($n), $i, FileType::RegularFile) }; }
        macro_rules! d { ($n:expr, $i:expr) => { (String::from($n), $i, FileType::Directory) }; }
        let entries: Vec<(String, u64, FileType)> = match inode {
            INO_ROOT => alloc::vec![
                f!("cpuinfo",  INO_CPUINFO),
                f!("meminfo",  INO_MEMINFO),
                f!("uptime",   INO_UPTIME),
                f!("version",  INO_VERSION),
                f!("mounts",   INO_MOUNTS),
                f!("cmdline",  INO_CMDLINE),
                f!("kmsg",     INO_KMSG),
                f!("stat",     INO_STAT),
                d!("self",     INO_SELF_DIR),
                d!("sys",      INO_SYS_DIR),
            ],
            INO_SELF_DIR => alloc::vec![
                f!("maps",          INO_SELF_MAPS),
                f!("status",        INO_SELF_STATUS),
                f!("cmdline",       INO_SELF_CMDLINE),
                f!("stat",          INO_SELF_STAT),
                f!("exe",           INO_SELF_EXE),
                f!("comm",          INO_SELF_COMM),
                f!("environ",       INO_SELF_ENVIRON),
                f!("auxv",          INO_SELF_AUXV),
                f!("mountinfo",     INO_SELF_MOUNTINFO),
                f!("cgroup",        INO_SELF_CGROUP),
                f!("oom_score_adj", INO_SELF_OOM_ADJ),
                f!("loginuid",      INO_SELF_LOGINUID),
                d!("fd",            INO_SELF_FD_DIR),
                d!("task",          INO_SELF_TASK_DIR),
            ],
            INO_SELF_TASK_DIR => {
                // Enumerate live threads of the calling process.
                let pid = crate::proc::current_pid();
                let procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter().find(|p| p.pid == pid) {
                    p.threads.iter()
                        .map(|&tid| (alloc::format!("{}", tid), INO_SELF_TASK_TID_DIR, FileType::Directory))
                        .collect()
                } else {
                    alloc::vec![]
                }
            }
            INO_SELF_TASK_TID_DIR => alloc::vec![
                f!("stat", INO_SELF_TASK_STAT),
            ],
            INO_SELF_FD_DIR => {
                // Return live fd entries for the calling process as symlinks.
                // Each open fd is represented as a DT_LNK entry named by fd number.
                let pid = crate::proc::current_pid();
                let procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter().find(|p| p.pid == pid) {
                    p.file_descriptors.iter().enumerate()
                        .filter_map(|(i, slot)| {
                            slot.as_ref().map(|_| {
                                (alloc::format!("{}", i), 3000 + i as u64, FileType::SymLink)
                            })
                        })
                        .collect()
                } else {
                    alloc::vec![]
                }
            }
            INO_SYS_DIR => alloc::vec![
                d!("vm",     INO_SYS_VM_DIR),
                d!("kernel", INO_SYS_KERNEL_DIR),
                d!("net",    INO_SYS_NET_DIR),
            ],
            INO_SYS_VM_DIR => alloc::vec![
                f!("overcommit_memory", INO_OVERCOMMIT),
                f!("max_map_count",     INO_MAX_MAP_COUNT),
            ],
            INO_SYS_KERNEL_DIR => alloc::vec![
                f!("pid_max", INO_PID_MAX),
                d!("random",  INO_SYS_KERNEL_RAND),
            ],
            INO_SYS_KERNEL_RAND => alloc::vec![
                f!("uuid", INO_RAND_UUID),
            ],
            // /proc/sys/net/ipv6/conf/{all,default}/disable_ipv6 (see net::ipver).
            INO_SYS_NET_DIR => alloc::vec![
                d!("ipv6", INO_SYS_NET_IPV6_DIR),
            ],
            INO_SYS_NET_IPV6_DIR => alloc::vec![
                d!("conf", INO_SYS_NET_IPV6_CONF),
            ],
            INO_SYS_NET_IPV6_CONF => alloc::vec![
                d!("all",     INO_SYS_NET_IPV6_ALL),
                d!("default", INO_SYS_NET_IPV6_DEF),
            ],
            INO_SYS_NET_IPV6_ALL => alloc::vec![
                f!("disable_ipv6", INO_DISABLE_IPV6_ALL),
            ],
            INO_SYS_NET_IPV6_DEF => alloc::vec![
                f!("disable_ipv6", INO_DISABLE_IPV6_DEF),
            ],
            _ => return Err(VfsError::NotADirectory),
        };
        Ok(entries)
    }

    // ── Unsupported write operations ─────────────────────────────────────────

    /// Writes to procfs are mostly rejected, but a handful of per-PID tunables
    /// (per proc(5)) accept writes that we silently swallow — Mozilla's
    /// `ContentProcessSandbox` and systemd's child handling both depend on
    /// being able to *write* to these without an error, even if the value is
    /// not persisted across reads.
    fn write(&self, inode: u64, _offset: u64, data: &[u8]) -> VfsResult<usize> {
        match inode {
            // oom_score_adj / loginuid — accept, discard.  POSIX has no
            // canonical behaviour here; the Linux contract is "write succeeds
            // and returns the byte count" (per proc(5) / man 5 proc).
            INO_SELF_OOM_ADJ | INO_SELF_LOGINUID => Ok(data.len()),
            // /proc/sys/net/ipv6/conf/{all,default}/disable_ipv6 — the
            // Linux-faithful runtime IPv6 toggle (see net::ipver).  Per the
            // sysctl contract a leading "1" disables IPv6, a leading "0"
            // enables it; the value is the negation of ipv6_enabled().  We
            // parse the first non-whitespace byte (echo writes "1\n").  An
            // unparseable value is rejected with EINVAL, matching the kernel
            // sysctl handler.  Both `all` and `default` map to the same global
            // flag (single network namespace).
            INO_DISABLE_IPV6_ALL | INO_DISABLE_IPV6_DEF => {
                let first = data.iter().find(|&&b| !b.is_ascii_whitespace());
                match first {
                    Some(b'0') => { crate::net::ipver::set_ipv6_enabled(true);  Ok(data.len()) }
                    Some(b'1') => { crate::net::ipver::set_ipv6_enabled(false); Ok(data.len()) }
                    _ => Err(VfsError::InvalidArg), // EINVAL
                }
            }
            _ => Err(VfsError::PermissionDenied),
        }
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

    /// Resolve `/proc/self/fd/<N>` symlinks to the path the corresponding fd
    /// was opened with.
    ///
    /// Per procfs(5), each entry in `/proc/<pid>/fd` is a symbolic link
    /// pointing at the underlying file.  Programs (notably runtime loaders
    /// and Mozilla's IPC layer) `openat(/proc/self/fd/<N>, ...)` to obtain
    /// an independently-flagged handle on the same file — typically a
    /// read-only dup of an `O_RDWR` memfd.
    ///
    /// The callable `pid` is the current task's pid (resolution always
    /// applies to the caller, since this filesystem only supports the
    /// `/proc/self/...` view; numeric pid paths are pre-redirected by
    /// `vfs::open()`).
    fn readlink(&self, inode: u64) -> VfsResult<String> {
        if !(3000..3000 + 4096).contains(&inode) {
            return Err(VfsError::Unsupported);
        }
        let fd_num = (inode - 3000) as usize;
        let pid = crate::proc::current_pid();
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs
            .iter()
            .find(|p| p.pid == pid)
            .ok_or(VfsError::NotFound)?;
        let fd = proc
            .file_descriptors
            .get(fd_num)
            .and_then(|slot| slot.as_ref())
            .ok_or(VfsError::NotFound)?;
        if fd.open_path.is_empty() {
            // Anonymous fd (pipe, eventfd, socket): synthesise a stable
            // name so callers that only need uniqueness still succeed.
            return Ok(alloc::format!("/dev/fd/{}", fd_num));
        }
        Ok(fd.open_path.clone())
    }
}

// ── Content generators ───────────────────────────────────────────────────────

/// Generate `/proc/cpuinfo` content using live CPUID data.
pub fn generate_cpuinfo() -> Vec<u8> {
    let mut out = Vec::new();

    // Query CPUID leaf 0 for vendor string.
    let (max_leaf, vendor) = {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let eax: u32;
            let ebx: u32;
            let ecx: u32;
            let edx: u32;
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "mov {ebx_out:e}, ebx",
                "pop rbx",
                inout("eax") 0u32 => eax,
                ebx_out = out(reg) ebx,
                out("ecx") ecx,
                out("edx") edx,
            );
            let mut v = [0u8; 12];
            v[0..4].copy_from_slice(&ebx.to_le_bytes());
            v[4..8].copy_from_slice(&edx.to_le_bytes());
            v[8..12].copy_from_slice(&ecx.to_le_bytes());
            (eax, v)
        }
        #[cfg(not(target_arch = "x86_64"))]
        { (0u32, *b"Unknown     ") }
    };

    let vendor_str = core::str::from_utf8(&vendor).unwrap_or("Unknown");

    // Query CPUID leaf 1 for family/model/stepping + feature flags.
    let (family, model, stepping, features_edx, features_ecx) = if max_leaf >= 1 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let eax: u32;
            let ecx: u32;
            let edx: u32;
            // rbx is reserved by LLVM — save/restore manually via push/pop.
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 1u32 => eax,
                out("ecx") ecx,
                out("edx") edx,
            );
            let stepping_id  = (eax >>  0) & 0xF;
            let model_id     = (eax >>  4) & 0xF;
            let family_id    = (eax >>  8) & 0xF;
            let ext_model    = (eax >> 16) & 0xF;
            let ext_family   = (eax >> 20) & 0xFF;
            let family = if family_id < 0xF {
                family_id
            } else {
                family_id + ext_family
            };
            let model = if family_id >= 6 {
                (ext_model << 4) | model_id
            } else {
                model_id
            };
            (family, model, stepping_id, edx, ecx)
        }
        #[cfg(not(target_arch = "x86_64"))]
        { (6u32, 0u32, 0u32, 0u32, 0u32) }
    } else {
        (6u32, 0u32, 0u32, 0u32, 0u32)
    };

    // Query CPUID leaf 0x80000002..0x80000004 for brand string.
    let brand = get_cpu_brand_string();

    // Build feature flag list from CPUID leaf 1 (EDX + ECX).
    //
    // Names follow Intel SDM Vol. 2A Table 3-8 (CPUID leaf 1 feature flag
    // mnemonics) and the lowercase strings Linux exports in /proc/cpuinfo.
    // Mozilla / FF probes this string for `sse2`, `sse4_1`, `clflush`,
    // `cmov`, `aes`, `avx2`, `bmi1`, `bmi2`, `rdrand` (see media/libcubeb,
    // js/src/jit/x86-shared/AssemblerBuffer-x86-shared.cpp).
    let mut flags = alloc::vec::Vec::<&str>::new();
    if features_edx & (1 <<  0) != 0 { flags.push("fpu"); }
    if features_edx & (1 <<  4) != 0 { flags.push("tsc"); }
    if features_edx & (1 <<  5) != 0 { flags.push("msr"); }
    if features_edx & (1 <<  6) != 0 { flags.push("pae"); }
    if features_edx & (1 <<  9) != 0 { flags.push("apic"); }
    if features_edx & (1 << 15) != 0 { flags.push("cmov"); }
    if features_edx & (1 << 19) != 0 { flags.push("clflush"); } // CLFSH: cache-line flush
    if features_edx & (1 << 23) != 0 { flags.push("mmx"); }
    if features_edx & (1 << 24) != 0 { flags.push("fxsr"); }
    if features_edx & (1 << 25) != 0 { flags.push("sse"); }
    if features_edx & (1 << 26) != 0 { flags.push("sse2"); }
    if features_ecx & (1 <<  0) != 0 { flags.push("pni"); } // SSE3 (Linux name)
    if features_ecx & (1 <<  1) != 0 { flags.push("pclmulqdq"); }
    if features_ecx & (1 <<  9) != 0 { flags.push("ssse3"); }
    if features_ecx & (1 << 12) != 0 { flags.push("fma"); }
    if features_ecx & (1 << 13) != 0 { flags.push("cx16"); } // CMPXCHG16B
    if features_ecx & (1 << 19) != 0 { flags.push("sse4_1"); }
    if features_ecx & (1 << 20) != 0 { flags.push("sse4_2"); }
    if features_ecx & (1 << 22) != 0 { flags.push("movbe"); }
    if features_ecx & (1 << 23) != 0 { flags.push("popcnt"); }
    if features_ecx & (1 << 25) != 0 { flags.push("aes"); }
    if features_ecx & (1 << 26) != 0 { flags.push("xsave"); }
    if features_ecx & (1 << 27) != 0 { flags.push("osxsave"); }
    if features_ecx & (1 << 28) != 0 { flags.push("avx"); }
    if features_ecx & (1 << 29) != 0 { flags.push("f16c"); }
    if features_ecx & (1 << 30) != 0 { flags.push("rdrand"); }

    // CPUID leaf 7 sub-leaf 0 — structured extended feature flags
    // (per Intel SDM Vol. 2A: CPUID — Returns Structured Extended Feature
    // Enumeration Information).  Mozilla's JIT and crypto code paths
    // probe `avx2`, `bmi1`, `bmi2` here.
    if max_leaf >= 7 {
        let (leaf7_ebx, leaf7_ecx) = {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let ebx: u32; let ecx: u32;
                core::arch::asm!(
                    "push rbx",
                    "cpuid",
                    "mov {ebx_out:e}, ebx",
                    "pop rbx",
                    inout("eax") 7u32 => _,
                    inout("ecx") 0u32 => ecx,
                    out("edx") _,
                    ebx_out = out(reg) ebx,
                );
                (ebx, ecx)
            }
            #[cfg(not(target_arch = "x86_64"))]
            { (0u32, 0u32) }
        };
        if leaf7_ebx & (1 <<  3) != 0 { flags.push("bmi1"); }
        if leaf7_ebx & (1 <<  5) != 0 { flags.push("avx2"); }
        if leaf7_ebx & (1 <<  8) != 0 { flags.push("bmi2"); }
        if leaf7_ebx & (1 << 19) != 0 { flags.push("adx"); }
        if leaf7_ebx & (1 << 29) != 0 { flags.push("sha_ni"); }
        let _ = leaf7_ecx;
    }

    // Always include x86_64 baseline flags.
    flags.push("lm"); // long mode
    flags.push("nx"); // no-execute
    flags.push("syscall");

    let flags_str = flags.join(" ");
    let ticks = crate::arch::x86_64::irq::get_ticks();
    // Estimate MHz from ticks: we run at 100 Hz PIT, so each tick = 10ms.
    // This is a rough placeholder — real TSC calibration would be needed.
    let _ = ticks;

    let content = alloc::format!(
        "processor\t: 0\n\
         vendor_id\t: {vendor}\n\
         cpu family\t: {family}\n\
         model\t\t: {model}\n\
         model name\t: {brand}\n\
         stepping\t: {stepping}\n\
         cpu MHz\t\t: 2000.000\n\
         cache size\t: 4096 KB\n\
         flags\t\t: {flags}\n\
         bogomips\t: 4000.00\n\
         address sizes\t: 48 bits virtual, 39 bits physical\n\
         \n",
        vendor   = vendor_str,
        family   = family,
        model    = model,
        brand    = brand,
        stepping = stepping,
        flags    = flags_str,
    );
    out.extend_from_slice(content.as_bytes());
    out
}

/// Read the CPU brand string from CPUID leaves 0x80000002-0x80000004.
fn get_cpu_brand_string() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        let max_ext = unsafe {
            let eax: u32;
            // rbx is reserved by LLVM — save/restore manually.
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 0x8000_0000u32 => eax,
                out("ecx") _,
                out("edx") _,
            );
            eax
        };
        if max_ext >= 0x8000_0004 {
            let mut brand = [0u8; 48];
            for i in 0u32..3 {
                let (a, b, c, d): (u32, u32, u32, u32) = unsafe {
                    let eax: u32; let ebx: u32; let ecx: u32; let edx: u32;
                    core::arch::asm!(
                        "push rbx",
                        "cpuid",
                        "mov {ebx_out:e}, ebx",
                        "pop rbx",
                        inout("eax") (0x8000_0002u32 + i) => eax,
                        ebx_out = out(reg) ebx,
                        out("ecx") ecx,
                        out("edx") edx,
                    );
                    (eax, ebx, ecx, edx)
                };
                let off = (i as usize) * 16;
                brand[off..off+4].copy_from_slice(&a.to_le_bytes());
                brand[off+4..off+8].copy_from_slice(&b.to_le_bytes());
                brand[off+8..off+12].copy_from_slice(&c.to_le_bytes());
                brand[off+12..off+16].copy_from_slice(&d.to_le_bytes());
            }
            // Trim leading spaces and trailing NULs.
            let trimmed = core::str::from_utf8(&brand)
                .unwrap_or("")
                .trim_matches('\0')
                .trim();
            if !trimmed.is_empty() {
                return String::from(trimmed);
            }
        }
    }
    String::from("QEMU Virtual CPU version 2.5+")
}

/// Generate `/proc/meminfo` content from live PMM stats.
pub fn generate_meminfo() -> Vec<u8> {
    let (total, used) = crate::mm::pmm::stats();
    let free = total.saturating_sub(used);
    let available = free;
    // Each PMM page = 4 KiB.
    let total_kb  = total    * 4;
    let free_kb   = free     * 4;
    let avail_kb  = available * 4;
    let content = alloc::format!(
        "MemTotal:       {total_kb:>8} kB\n\
         MemFree:        {free_kb:>8} kB\n\
         MemAvailable:   {avail_kb:>8} kB\n\
         Buffers:               0 kB\n\
         Cached:                0 kB\n\
         SwapCached:            0 kB\n\
         Active:                0 kB\n\
         Inactive:              0 kB\n\
         SwapTotal:             0 kB\n\
         SwapFree:              0 kB\n\
         Dirty:                 0 kB\n\
         Writeback:             0 kB\n\
         AnonPages:             0 kB\n\
         Mapped:                0 kB\n\
         Shmem:                 0 kB\n\
         PageSize:           4096 B\n",
        total_kb = total_kb,
        free_kb  = free_kb,
        avail_kb = avail_kb,
    );
    content.into_bytes()
}

/// Generate `/proc/uptime` content: `<seconds>.<hundredths> <idle_secs>.<hundredths>\n`.
pub fn generate_uptime() -> Vec<u8> {
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let secs = ticks / 100;
    let frac = ticks % 100;
    alloc::format!("{secs}.{frac:02} {secs}.{frac:02}\n", secs = secs, frac = frac)
        .into_bytes()
}

/// Generate `/proc/version` content.
pub fn generate_version() -> Vec<u8> {
    b"Linux version 5.15.0-astryx (AstryxOS Aether 0.1 x86_64) #1 SMP AstryxOS\n".to_vec()
}

/// Escape whitespace/backslash/hash chars with octal sequences so the output
/// round-trips cleanly through `getmntent_r`, `strtok(" \t")`, and similar
/// whitespace-splitting parsers (per fstab(5)).
///
/// Mangled characters: space (\040), tab (\011), newline (\012),
/// backslash (\134), hash (\043).  All other bytes pass through unchanged.
fn mangle_field(s: &str, out: &mut Vec<u8>) {
    for &b in s.as_bytes() {
        match b {
            b' '  => out.extend_from_slice(b"\\040"),
            b'\t' => out.extend_from_slice(b"\\011"),
            b'\n' => out.extend_from_slice(b"\\012"),
            b'\\' => out.extend_from_slice(b"\\134"),
            b'#'  => out.extend_from_slice(b"\\043"),
            _     => out.push(b),
        }
    }
}

/// Compute the fstab(5)-format mount options string for a (mountpoint, fstype) pair.
///
/// Per proc(5) and the kernel's MS_* mount flags, synthetic filesystems are
/// always exposed read-only and non-executable (no point opening files there
/// for `PROT_EXEC` mappings).  fat32 image data mounted under `/mnt` is the
/// in-memory test stub and is treated read-only for the same reason; the
/// real data disk at `/disk` is the only writable fat32 volume.  The root
/// ramfs at `/` and any other mount fall back to the default `rw,relatime`.
///
/// The substrings "ro", "noexec", "nosuid", and "nodev" must be matchable as
/// whole tokens by `hasmntopt(3)`-style consumers (libffi's
/// `open_temp_exec_file_mnt` is one such caller, per fstab(5)/getmntent(3)).
pub(crate) fn mount_opts_for(path: &str, fstype: &str) -> &'static str {
    match fstype {
        "procfs" | "sysfs" => "ro,noexec,nosuid,nodev,relatime",
        "fat32" if path == "/mnt" => "ro,noexec,relatime",
        _ => "rw,relatime",
    }
}

/// Generate `/proc/mounts` content from the live mount table.
///
/// Format per fstab(5): `<source> <mountpoint> <fstype> <opts> <freq> <passno>\n`
/// with exactly one space between fields.  Whitespace inside any field is
/// octal-escaped by [`mangle_field`] so single-pass tokenizers
/// (getmntent_r / strtok / split_whitespace) parse each line into six fields.
///
/// LOCKING: the caller must NOT hold `MOUNTS.lock()` when invoking this
/// function — it acquires that lock itself.  `fd_read()` handles this by
/// intercepting `/proc/mounts` before it reaches `ProcFs::read()`, which
/// would otherwise already be holding `MOUNTS` (recursive-lock deadlock).
pub fn generate_mounts() -> Vec<u8> {
    // Snapshot (path, fstype) pairs under the MOUNTS lock, then release it
    // before formatting.  Keeping the critical section small avoids blocking
    // concurrent mount/umount while a large /proc/mounts buffer is formatted.
    let snapshot: alloc::vec::Vec<(alloc::string::String, alloc::string::String)> = {
        let mounts = crate::vfs::MOUNTS.lock();
        mounts.iter()
            .map(|m| (m.path.clone(), alloc::string::String::from(m.fs.name())))
            .collect()
    };

    let mut out = alloc::vec::Vec::with_capacity(snapshot.len() * 48);
    for (path, fstype) in &snapshot {
        // source — use the fstype as the device identifier for synthetic
        // filesystems, matching fstab(5) convention (e.g. "proc /proc proc ...").
        mangle_field(fstype.as_str(), &mut out);
        out.push(b' ');
        // mountpoint
        mangle_field(path.as_str(), &mut out);
        out.push(b' ');
        // type
        mangle_field(fstype.as_str(), &mut out);
        out.push(b' ');
        // options — derived from (mountpoint, fstype).  Synthetic filesystems
        // (procfs, sysfs) and the in-memory fat32 test stub at /mnt are
        // exposed read-only + noexec so userspace tools that scan /proc/mounts
        // for an executable temp-file location (libffi, glib, etc.) skip them.
        out.extend_from_slice(mount_opts_for(path, fstype).as_bytes());
        out.push(b' ');
        // freq, passno — both zero for all synthetic mounts.
        out.extend_from_slice(b"0 0\n");
    }
    out
}

/// Generate `/proc/self/mountinfo` content from the live mount table.
///
/// Format per proc(5) and `Documentation/filesystems/proc.txt`:
///
/// ```text
/// mount_id parent_id major:minor root mount_point options optional_fields - fs_type source super_options
/// ```
///
/// Field semantics:
///   * `mount_id`         — unique identifier of the mount (monotonic from 1).
///   * `parent_id`        — id of the parent mount, or this id for the root.
///   * `major:minor`      — device identifier (synthetic for pseudo-FSes).
///   * `root`             — pathname of the directory in the FS which forms
///                          the root of this mount (always `/` unless bind-mount).
///   * `mount_point`      — pathname relative to the process's root.
///   * `options`          — per-mount options ("rw" / "ro" + relatime etc.).
///   * `optional_fields`  — zero or more `name:value`, terminated by `-`.
///   * `fs_type`          — filesystem driver name (e.g. "tmpfs", "ext2").
///   * `source`           — device/source name (e.g. "/dev/sda1", "tmpfs").
///   * `super_options`    — per-super-block options.
///
/// Mozilla's sandbox policy builder parses this to enumerate writable / read-
/// only mounts; ENOENT used to make it fall back to a refuse-all policy that
/// prevented the GPU-probe child (`glxtest`) from being spawned.
///
/// LOCKING: this function acquires `MOUNTS.lock()` itself.  Callers must not
/// hold it on entry.  `fd_read()` intercepts the path so this is always called
/// outside the dispatch path.
pub fn generate_mountinfo() -> Vec<u8> {
    // Snapshot under the MOUNTS lock, then release before formatting.
    let snapshot: alloc::vec::Vec<(alloc::string::String, alloc::string::String)> = {
        let mounts = crate::vfs::MOUNTS.lock();
        mounts.iter()
            .map(|m| (m.path.clone(), alloc::string::String::from(m.fs.name())))
            .collect()
    };

    let mut out = alloc::vec::Vec::with_capacity(snapshot.len() * 96);
    // The root mount is special: its parent_id is itself, by convention.
    // Subsequent mounts list mount #1 (the root "/") as parent — correct for a
    // single-level mount tree, which is all AstryxOS exposes.
    for (idx, (path, fstype)) in snapshot.iter().enumerate() {
        let mount_id = (idx as u32) + 1;
        // First mount is the root ("/") if present; otherwise treat all as
        // siblings of mount #1.
        let parent_id = if mount_id == 1 { 1 } else { 1 };
        // Synthetic device id — 0:N where N matches mount_id.  Real block
        // devices would carry their (major, minor) but the AstryxOS VFS does
        // not propagate that today; what matters for parsers is uniqueness.
        let major = 0u32;
        let minor = mount_id;

        // Options derived from (path, fstype) — same policy as /proc/mounts.
        let opts = mount_opts_for(path, fstype);

        // Source name — synthetic FSes use their fstype as the device name.
        let source = match fstype.as_str() {
            "procfs" => "proc",
            "sysfs"  => "sysfs",
            "tmpfs"  => "tmpfs",
            "ramfs"  => "ramfs",
            "devfs"  => "dev",
            _ => fstype.as_str(),
        };

        // Per-super-block options — we expose the same flags as the mount opts
        // (no need to distinguish since we never remount).
        let super_opts = if opts.contains("ro,") { "ro" } else { "rw" };

        // Build the line.  We DO NOT mangle these fields with octal escapes
        // (unlike /proc/mounts) because mountinfo parsers per proc(5) split on
        // single ASCII space and treat each field literally.  Whitespace in
        // mount points would still need escaping, but AstryxOS never creates
        // mount points with spaces.
        use core::fmt::Write;
        let mut line = alloc::string::String::with_capacity(96);
        let _ = write!(
            &mut line,
            "{mid} {pid} {maj}:{min} / {mnt} {opt} shared:1 - {fst} {src} {sopt}\n",
            mid  = mount_id,
            pid  = parent_id,
            maj  = major,
            min  = minor,
            mnt  = path,
            opt  = opts,
            fst  = fstype,
            src  = source,
            sopt = super_opts,
        );
        out.extend_from_slice(line.as_bytes());
    }

    // Guarantee a non-empty parseable file even if MOUNTS happens to be empty
    // mid-boot (defensive — should never occur once vfs::init() has run).
    if out.is_empty() {
        out.extend_from_slice(b"1 1 0:1 / / rw,relatime shared:1 - ramfs ramfs rw\n");
    }
    out
}

/// Generate `/proc/<pid>/cgroup` content.  AstryxOS does not implement
/// cgroups, so we emit the cgroup-v2 "process is not in any cgroup" reply,
/// which is what `cgroup-aware` userspace (systemd, runc, Mozilla, Docker)
/// expects on a system with the unified hierarchy mounted at root.
///
/// Format per cgroups(7) §"/proc/[pid]/cgroup":
/// `hierarchy-ID:controller-list:cgroup-path` — for v2 the hierarchy-ID is 0
/// and the controller-list is empty.
pub fn generate_cgroup() -> Vec<u8> {
    b"0::/\n".to_vec()
}

/// Generate `/proc/<pid>/maps` content from the process's live VMA table.
///
/// Each line follows the canonical six-field format specified in proc(5):
///
/// ```text
/// address           perms offset   dev   inode  pathname
/// 00400000-00452000 r-xp 00000000 00:00 0       /bin/foo
/// ```
///
/// Fields:
/// * `address`  — `start-end` in hex, no `0x` prefix, not zero-padded to a
///                fixed width (plain `%lx` per the kernel ABI).
/// * `perms`    — four characters: `r`/`-`, `w`/`-`, `x`/`-`,
///                `p` (private/CoW) or `s` (shared).  A mapping is shared
///                when `MAP_SHARED` is set in the VMA's flags; all other
///                mappings — including anonymous and file-backed private ones —
///                are private (`p`).
/// * `offset`   — file offset of the first byte mapped, 8-digit zero-padded
///                hex; zero for anonymous / device VMAs.
/// * `dev`      — device as `major:minor` in hex.  AstryxOS does not track
///                device IDs in the VMA table, so this is always `00:00`.
/// * `inode`    — decimal inode number of the mapped file; 0 for anonymous.
/// * `pathname` — file path, or a bracketed tag such as `[heap]`, `[stack]`,
///                `[vdso]`, `[vvar]`, `[anon]`.  May be empty for unnamed
///                anonymous ranges.  Separated from the inode field by spaces
///                to align to column 73 (matching the Linux kernel convention).
///
/// Output is capped at 100 KiB to bound allocation for processes with many
/// fine-grained mappings (e.g. dynamically-linked C++ binaries).
///
/// The output is sorted by start address; the VMA list is always maintained
/// in sorted order (`VmSpace::insert_vma`), so no re-sorting is needed here.
///
/// This function is the single source of truth for maps content.  Both the
/// VFS `fd_read` hot-path (`vfs/mod.rs`) and the ProcFs inode fallback
/// delegate to it.
pub fn generate_proc_maps(pid: crate::proc::Pid) -> Vec<u8> {
    use crate::mm::vma::{PROT_READ, PROT_WRITE, PROT_EXEC, MAP_SHARED, VmBacking};

    // Snapshot the VMA list while briefly holding PROCESS_TABLE, then release
    // the lock before formatting to keep the critical section tight.
    let vmas: Vec<crate::mm::vma::VmArea> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter()
            .find(|p| p.pid == pid)
            .and_then(|p| p.vm_space.as_ref().map(|vs| vs.areas.clone()))
            .unwrap_or_default()
    };

    // Upper bound: ~100 KiB.  Each line is at most ~100 bytes; 1024 VMAs fits
    // in that budget.  Truncate beyond that to avoid unbounded allocation.
    const MAX_BYTES: usize = 100 * 1024;
    let mut out = Vec::with_capacity(vmas.len().min(256) * 80);

    for vma in &vmas {
        if out.len() >= MAX_BYTES {
            break;
        }

        let r = if vma.prot & PROT_READ  != 0 { b'r' } else { b'-' };
        let w = if vma.prot & PROT_WRITE != 0 { b'w' } else { b'-' };
        let x = if vma.prot & PROT_EXEC  != 0 { b'x' } else { b'-' };
        // Shared iff MAP_SHARED is set; every other mapping (anonymous,
        // file-backed private, stack, heap) is private (CoW).
        let p = if vma.flags & MAP_SHARED != 0 { b's' } else { b'p' };

        // Extract offset and inode from the backing descriptor.
        let (offset, inode) = match &vma.backing {
            VmBacking::File { offset, inode, .. } => (*offset, *inode),
            _ => (0u64, 0u64),
        };

        // Format: start-end perms offset dev inode pathname\n
        // Use core::fmt::Write into a stack-local String to avoid nested allocs.
        use core::fmt::Write as FmtWrite;
        let mut line = alloc::string::String::with_capacity(96);
        let _ = write!(
            line,
            "{:x}-{:x} {}{}{}{} {:08x} 00:00 {}",
            vma.base,
            vma.end(),
            r as char, w as char, x as char, p as char,
            offset,
            inode,
        );
        // Pathname field: align to column 73 (matching the kernel's seq_printf
        // convention), then append the name.  Use at least one space.
        if !vma.name.is_empty() {
            // Pad with spaces so pathname starts at column 73 when possible.
            // Column index of the current end (0-based): line.len() chars so far.
            let col = line.len();
            let spaces = if col < 72 { 72 - col } else { 1 };
            for _ in 0..spaces {
                line.push(' ');
            }
            line.push_str(vma.name);
        }
        line.push('\n');
        out.extend_from_slice(line.as_bytes());
    }

    if out.is_empty() {
        // Safety net for kernel threads / processes with no user VMAs: emit
        // the vvar placeholder so parsers that require at least one line succeed.
        out.extend_from_slice(
            b"0000000000000000-0000000000001000 r--p 00000000 00:00 0 [vvar]\n"
        );
    }

    out
}

/// Generate `/proc/stat` content.
///
/// Firefox's CPU topology detection code reads this to determine the number of
/// online CPUs (lines starting with "cpu" followed by a digit) and get
/// aggregate scheduler ticks.  A minimal two-line file (aggregate + cpu0)
/// satisfies it.
pub fn generate_stat() -> Vec<u8> {
    let ticks = crate::arch::x86_64::irq::get_ticks();
    // Provide plausible user/nice/system/idle values derived from the PIT tick counter.
    // Fields: user nice system idle iowait irq softirq steal guest guest_nice
    let user   = ticks / 4;
    let system = ticks / 8;
    let idle   = ticks.saturating_sub(user + system);
    alloc::format!(
        "cpu  {user} 0 {system} {idle} 0 0 0 0 0 0\n\
         cpu0 {user} 0 {system} {idle} 0 0 0 0 0 0\n\
         intr 0\n\
         ctxt 0\n\
         btime 1700000000\n\
         processes 1\n\
         procs_running 1\n\
         procs_blocked 0\n",
        user   = user,
        system = system,
        idle   = idle,
    ).into_bytes()
}

// ── Legacy shell interface (unchanged) ──────────────────────────────────────

/// Read a /proc entry and display its contents to the serial console.
/// Used by the kernel debug shell — not involved in VFS file reads.
pub fn read_procfs(path: &str) {
    let clean = path.trim_start_matches('/');

    // Strip leading "proc/" if present
    let entry = if let Some(rest) = clean.strip_prefix("proc/") {
        rest
    } else if clean == "proc" || clean.is_empty() || clean == "/" {
        // List all entries
        crate::kprintln!("/proc:");
        crate::kprintln!("  cpuinfo");
        crate::kprintln!("  meminfo");
        crate::kprintln!("  uptime");
        crate::kprintln!("  version");
        crate::kprintln!("  net");
        crate::kprintln!("  mounts");
        crate::kprintln!("  cmdline");
        crate::kprintln!("  interrupts");
        crate::kprintln!("  processes");
        return;
    } else {
        clean
    };

    match entry {
        "cpuinfo"   => {
            let content = generate_cpuinfo();
            if let Ok(s) = core::str::from_utf8(&content) {
                crate::kprintln!("{}", s);
            }
        }
        "meminfo"   => {
            let content = generate_meminfo();
            if let Ok(s) = core::str::from_utf8(&content) {
                crate::kprintln!("{}", s);
            }
        }
        "uptime"    => {
            let content = generate_uptime();
            if let Ok(s) = core::str::from_utf8(&content) {
                crate::kprintln!("{}", s);
            }
        }
        "version"   => {
            let content = generate_version();
            if let Ok(s) = core::str::from_utf8(&content) {
                crate::kprintln!("{}", s);
            }
        }
        "net"       => show_net(),
        "mounts"    => {
            let content = generate_mounts();
            if let Ok(s) = core::str::from_utf8(&content) {
                crate::kprintln!("{}", s);
            }
        }
        "cmdline"   => crate::kprintln!("astryx_kernel root=/dev/ramdisk0 console=fb0"),
        "interrupts" => show_interrupts(),
        "processes" => show_processes(),
        _ => {
            if let Ok(_pid) = entry.parse::<u64>() {
                show_process_info(_pid);
            } else {
                crate::kprintln!("procfs: unknown entry '{}'", entry);
            }
        }
    }
}

fn show_net() {
    let mac = crate::net::our_mac();
    let ip = crate::net::our_ip();
    let gw = crate::net::gateway_ip();
    let mask = crate::net::subnet_mask();
    let (rx_p, tx_p, rx_b, tx_b) = crate::net::stats();
    let dns = crate::net::dns::get_nameserver();

    crate::kprintln!("Interface: eth0");
    crate::kprintln!("  HWaddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    crate::kprintln!("  IPv4:   {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    crate::kprintln!("  Mask:   {}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]);
    crate::kprintln!("  GW:     {}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
    crate::kprintln!("  DNS:    {}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3]);
    crate::kprintln!("  RX:     {} packets, {} bytes", rx_p, rx_b);
    crate::kprintln!("  TX:     {} packets, {} bytes", tx_p, tx_b);
}

fn show_interrupts() {
    let ticks = crate::arch::x86_64::irq::get_ticks();
    crate::kprintln!("  IRQ  Count       Description");
    crate::kprintln!("  ---  ----------  -----------");
    crate::kprintln!("    0  {:>10}  PIT Timer (100 Hz)", ticks);
    crate::kprintln!("    1  {:>10}  PS/2 Keyboard", "N/A");
    crate::kprintln!("   11  {:>10}  e1000 NIC", "N/A");
}

fn show_processes() {
    crate::kprintln!("  PID  State       Name");
    crate::kprintln!("  ---  ----------  ----");
    let count = crate::proc::process_count();
    for pid in 0..count as u64 + 2 {
        if let Some(name) = crate::proc::process_name(pid) {
            crate::kprintln!("  {:>3}  Active      {}", pid, name);
        }
    }
}

fn show_process_info(pid: u64) {
    match crate::proc::process_name(pid) {
        Some(name) => {
            crate::kprintln!("PID:    {}", pid);
            crate::kprintln!("Name:   {}", name);
            crate::kprintln!("State:  Active");
            crate::kprintln!("TID:    {}", crate::proc::current_tid());
        }
        None => crate::kprintln!("Process {} not found", pid),
    }
}
