# VFS & Filesystem Gaps

> Reference: Windows XP `base/ntos/fsrtl/` + `base/fs/` (625 C files),
>             Linux `fs/` (65 filesystems, `dcache.c`, `inode.c`, `locks.c`)
> AstryxOS: `vfs/mod.rs`, `vfs/fat32.rs`, `vfs/ext2.rs`, `vfs/ntfs.rs`,
>            `vfs/ramfs.rs`, `vfs/procfs.rs`

---

## What We Have

- Unified VFS trait (`FileSystemOps`): create_file, create_dir, remove, lookup, read, write, stat,
  readdir, truncate, sync
- `FileStat` with timestamps, permissions, size, inode number
- 64 file descriptors per process (hard limit in PCB)
- Four filesystem implementations: FAT32 (in-memory), ext2 (stub), NTFS (stub), RamFS, ProcFS
- File types: RegularFile, Directory, SymLink, CharDevice, BlockDevice, Pipe, Socket, and
  all special fd types (EventFd, TimerFd, SignalFd, InotifyFd, PtyMaster, PtySlave)
- Rename support (within same filesystem)
- Mount table (flat Vec, sorted by path depth)
- ProcFS: `/proc/self/maps`, `/proc/self/status`, `/proc/self/fd` (dynamic at read-time)

---

## Missing (Critical)

### Symbolic Link Resolution
**What**: When `open("/usr/bin/python")` resolves and `python` is a symlink to `python3.12`, the
VFS path walker must follow the link (up to MAXSYMLINKS=40 hops) before returning the final inode.

**Current state**: SymLink file type exists but is never followed — open returns the symlink inode
itself (wrong) or ENOENT.

**Impacts**:
- `/bin` → `/usr/bin` symlinks (common in modern Linux rootfs layout) break every binary lookup
- `ld-musl` is usually at a symlinked path
- Any package that installs via symlinks is silently broken

**Reference**: `linux/fs/namei.c` (`follow_link`, `trailing_symlink`);
`XP/base/ntos/fsrtl/fsrtlpc.c`

---

### File Locking (`flock` / `fcntl` locks)
**What**: Advisory and mandatory byte-range locks. `flock(fd, LOCK_EX)` for exclusive file lock.
`fcntl(F_SETLK)` / `fcntl(F_SETLKW)` for byte-range locks (POSIX).

**Impacts**:
- SQLite uses fcntl byte-range locks — will corrupt database if unimplemented
- Many Unix daemons use lock files (pid files via `flock(LOCK_EX|LOCK_NB)`)
- Firefox profile manager uses lock files to detect concurrent instances

**Reference**: `linux/fs/locks.c` (1,700 LOC); `XP/base/ntos/fsrtl/filtrctx.c`

---

### Extended Attributes (`xattr`)
**What**: Key-value metadata attached to files (beyond mode/owner/timestamps).
Linux uses namespaces: `user.`, `security.`, `trusted.`, `system.`.
Required for: SELinux labels, capabilities in filesystems, ACL storage (POSIX ACLs stored as xattr).

**Reference**: `linux/fs/xattr.c`; syscalls `setxattr(2)`, `getxattr(2)`, `listxattr(2)`

---

### Dentry Cache
**What**: A hash table mapping (parent_inode, name) → inode number. Without it, every path
component lookup must traverse the filesystem from the root. With 64-file processes and deep
directory trees, this is catastrophic for performance.

**Impacts**: Every `open()` on a nested path does O(depth) raw filesystem reads.
`/usr/lib/x86_64-linux-gnu/libssl.so.1.1` = 7 lookups every single open().

**Reference**: `linux/fs/dcache.c` (1,900 LOC, `dentry` struct, `d_lookup`, LRU);
`XP/base/ntos/cache/` (CcInitializeCacheMap)

---

### Inode Cache
**What**: Keep recently-used inodes in memory. On close, don't discard inode data — reuse on
next open. Prevents repeated reads of the same inode from disk.

**Reference**: `linux/fs/inode.c` (`iget5_locked`, `iput`, LRU inode list)

---

## Missing (High)

### Hard Links
**What**: Multiple directory entries pointing to the same inode. `link(oldpath, newpath)` creates
a hard link; `unlink()` decrements nlink and only frees inode when nlink reaches 0.

**Current state**: No link count tracking; `unlink()` immediately frees the inode/data.

**Reference**: `linux/fs/namei.c` (`vfs_link`); FAT32 does not support hard links (NTFS does)

---

### Atomic `rename()` with Unlink-on-Last-Close
**What**: Proper rename must be atomic (no window where neither old nor new path exists).
Also: if a file is unlinked while still open, its data must persist until the last fd is closed.

**Current state**: `unlink()` immediately frees data. Processes that open → unlink → use
(common temp file pattern) will have their data destroyed while they're reading it.

**Reference**: `linux/fs/namei.c` (`vfs_rename`); `linux/fs/inode.c` (`inode.i_nlink`)

---

### Mount / Umount
**What**: `mount(source, target, type, flags, data)` and `umount(target)`. Proper namespace-aware
mounting. Currently mounts are hardcoded in init.

**Reference**: `linux/fs/namespace.c` (`sys_mount`, `sys_umount`);
`XP/base/ntos/io/pnpmgr.c`

---

### atime / mtime / ctime Timestamp Updates
**What**: File access time (atime), modification time (mtime), and status change time (ctime)
must update on read/write/stat respectively. Many tools rely on these.

**Current state**: All timestamps return 0. `ls -l` always shows epoch.

---

### `sendfile()` / `splice()` / `copy_file_range()`
**What**: Zero-copy kernel-space data transfer between fds. `sendfile(out_fd, in_fd, offset, count)`
copies file data directly to a socket without user-space bounce buffer. Critical for web servers.

**Reference**: `linux/fs/sendfile.c`; `linux/fs/splice.c`; syscalls 40, 275, 326

---

### Proper `/proc` and `/sys` Population
**What**: `/proc` should expose per-process `/proc/N/` directories, not just `/proc/self/`.
`/proc/cpuinfo`, `/proc/meminfo`, `/proc/version`, `/proc/net/tcp`, `/proc/net/if_inet6` are
read by musl, glibc, and many utilities.

**Current state**: `/proc/self/` exists with maps/status/fd. No `/proc/N/` tree. No `/proc/cpuinfo`,
`/proc/meminfo`, etc. Firefox reads `/proc/cpuinfo` and `/proc/meminfo` at startup.

**Reference**: `linux/fs/proc/` (200+ files); `linux/fs/proc/array.c`, `linux/fs/proc/meminfo.c`

---

## Missing (Medium)

| Feature | Description | Reference |
|---------|-------------|-----------|
| Filesystem namespace | Separate mount table per process (containers) | `linux/fs/namespace.c` |
| `chroot()` | Restrict process root directory | `linux/fs/namei.c` |
| FAT32 write path | Currently read-only in memory; no cluster allocation | `XP/base/fs/fastfat/` |
| ext2 write path | Stub: no inode/block allocation | `linux/fs/ext2/` |
| File descriptor limits | `RLIMIT_NOFILE` enforcement (see rlimit in proc gaps) | — |
| Fsync directory | Flush directory metadata to persist rename | `linux/fs/inode.c` |
| 4096 file descriptor limit | Currently hardcoded at 64 | `linux/fs/file.c` |

---

## Missing (Low)

| Feature | Description |
|---------|-------------|
| `inotify` real events | Currently stub; never delivers events |
| `fanotify` | Filesystem event notification for AV scanners |
| `quota` | Per-UID/GID disk space enforcement |
| `fuse` / `virtiofs` | Userspace filesystem driver interface |
| NFS export | Generate file handles for NFS server |
| OverlayFS | Layered filesystem for containers |
| btrfs / NTFS full | Complete implementations |

---

## Implementation Order

1. **Symlink resolution** — path walker loop in VFS `lookup()`, follow up to 40 levels
2. **Timestamp updates** — add current_tick_to_timespec() → update on read/write/stat
3. **Unlink-on-last-close** — track `open_count` in inode; free data only when open_count AND nlink == 0
4. **fd limit expansion** — grow FD table from 64 to 1024 (dynamic Vec)
5. **Dentry cache** — `HashMap<(parent_ino, name), InodeId>` with LRU eviction
6. **File locking** — per-inode lock list with waitqueue; `fcntl(F_SETLK/F_SETLKW)`
7. **`/proc/N/` tree** — generate directory entries for all living PIDs in procfs
8. **`/proc/meminfo`** — report PMM free/used pages in Linux format
