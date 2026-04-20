# AstryxOS — Missing Features Action Plan

> Date: 2026-03-12
> Baseline: Session 30, 77/77 tests, SMP stable, Phase 6 Firefox foundation done
> Goal: Firefox runs real web pages, musl userspace stable, real apps (Python, curl, bash) work

---

## Priority Framework

Each item is rated by two axes:
- **Impact**: how many real-world apps / use-cases are unblocked
- **Effort**: implementation size (S=<200 LOC, M=200-800 LOC, L=800-3000 LOC, XL=3000+)

Items are ordered: high-impact + low-effort first, then high-impact + high-effort.

---

## Phase A — Quick Wins (1-2 sessions each, unblocks immediately)

These are small, self-contained, and unblock many things.

### A1. `/dev/null`, `/dev/zero`, `/dev/urandom` nodes  *(S, Critical)*
Virtually every Unix program opens these. Currently they're not in `/dev`.

```
/dev/null  → always succeeds, discards writes, EOF on read
/dev/zero  → reads return 0x00 bytes infinitely
/dev/urandom → reads from RDRAND, same as /dev/random
/dev/full  → writes return ENOSPC (for testing)
```

**Add in**: `init/mod.rs` at boot, register as CharDevice inodes in RamFS.
**Reference**: `linux/drivers/char/mem.c`

---

### A2. RTC Driver — Wall Clock Time  *(S, Critical)*
`clock_gettime(CLOCK_REALTIME)` must not return 0. HTTPS cert validation fails at year 0.

```
Read CMOS RTC via I/O ports 0x70/0x71 at boot
Convert BCD date/time → Unix timestamp (seconds since 1970-01-01)
Store in global BOOT_EPOCH_SECS: AtomicU64
clock_gettime: BOOT_EPOCH_SECS + (tick_count / TICKS_PER_SEC)
```

**Reference**: `linux/drivers/rtc/rtc-cmos.c` first 200 lines; CMOS register table

---

### A3. TSC-based High-Resolution Monotonic Clock  *(S, High)*
10ms tick resolution is too coarse for Firefox performance timers and media.

```
At boot: calibrate TSC frequency against PIT (read TSC before/after 10ms PIT wait)
Store tsc_hz: u64
clock_gettime(CLOCK_MONOTONIC): rdtsc() * 1_000_000_000 / tsc_hz → nanoseconds
clock_gettime(CLOCK_MONOTONIC_COARSE): tick_count * 10_000_000 (10ms in ns)
```

**Reference**: `linux/arch/x86/kernel/tsc.c`

---

### A4. `poll()` and `select()` Syscalls  *(M, Critical)*
Every non-modern app uses poll/select. ENOSYS → app fails hard.

```
Syscall 7 (poll): iterate fds array, check readiness via per-fd poll() method
Syscall 23 (select): convert fd_set bitmasks → poll array → call do_poll
Timeout: use nanosleep-style tick wait

Readiness model:
  Pipe read-end: ready if ring buffer not empty
  Pipe write-end: ready if ring buffer not full
  Socket: ready if recv_buf has data (or send_buf has space)
  eventfd/timerfd/signalfd: reuse existing is_readable()
```

**Reference**: `linux/fs/select.c` (600 LOC)

---

### A5. `pread64` / `pwrite64`  *(S, Critical)*
Thread-safe file I/O at arbitrary offset. Used by SQLite (Firefox profile database).

```
Syscall 17 (pread64): seek to offset, read, restore position atomically
Syscall 18 (pwrite64): seek to offset, write, restore position atomically
```

**Implementation**: 10 lines each. Just lseek+read/write+lseek-back, with fd lock.

---

### A6. `getrlimit` Returns Real Values  *(S, Critical)*
musl calls `getrlimit(RLIMIT_NOFILE)` at startup. Returning ENOSYS or 0 → musl caps FDs at 0.

```
Add RLimit struct to PCB: [RLimit; RLIM_NLIMITS]
Initialize with sensible defaults: RLIMIT_NOFILE=(1024, 65536), RLIMIT_STACK=(8MB, INFINITY)
getrlimit/setrlimit/prlimit64 read/write from PCB.rlimits
```

**Reference**: `linux/include/uapi/linux/resource.h`

---

### A7. `sysinfo`  *(S, High)*
Firefox reads total RAM to size caches. Returns ENOSYS → uses defaults.

```
Syscall 99: fill struct sysinfo {
  uptime: tick_count / TICKS_PER_SEC
  totalram: pmm::total_frames() * 4096
  freeram: pmm::free_frames() * 4096
  procs: PROCESS_TABLE.len() as u16
  mem_unit: 1
}
```

---

### A8. `memfd_create` (Syscall 319)  *(S, High)*
Anonymous file fd for JIT and Wayland shared buffers.

```
Create unnamed RamFS inode
Assign fd to current process
Support: ftruncate (set size), mmap (anonymous), read/write
Return fd
```

---

### A9. `/proc/cpuinfo` and `/proc/meminfo`  *(S, High)*
Read by Firefox, Python, bash, virtually everything at startup.

```
/proc/cpuinfo: emit one block per logical CPU (from APIC count)
  Fields: processor, vendor_id, cpu family, model, model name, stepping,
          cpu MHz (from TSC calibration), cache size, flags (sse2 sse4_1 avx2...)

/proc/meminfo: emit Linux-format key: value kB pairs
  MemTotal, MemFree, MemAvailable, Buffers, Cached, SwapTotal=0, SwapFree=0
```

**Add in**: `vfs/procfs.rs` as new path handlers.

---

### A10. Symlink Resolution in VFS  *(M, Critical)*
Apps will silently fail to find binaries if any path component is a symlink.

```
In vfs path_walk loop:
  On FS lookup returning SymLink: read link target, join with remaining path
  Limit: 40 hops (MAXSYMLINKS)
  Detect cycles: if hop_count > 40, return ELOOP
```

**Reference**: `linux/fs/namei.c` function `follow_link` (~150 LOC)

---

## Phase B — Networking Deep Dive (3-5 sessions)

### B1. Full TCP Data Transfer  *(XL, Critical)*
AstryxOS TCP has no actual data movement. This is the biggest single gap.

**Session B1a — Send/Recv buffers + ACK**:
```
Add to TcpSocket: send_buf: [u8; 65536], recv_buf: [u8; 65536]
                  snd_una: u32, snd_nxt: u32, rcv_nxt: u32
On write(): copy data to send_buf, send segment with PSH|ACK flag
On recv(): if Established and data segment arrives: copy to recv_buf, send ACK
           if read(): copy from recv_buf to user buffer
```

**Session B1b — Connection lifecycle**:
```
Proper ISN from rdtsc()
3WHS: SYN (snd_nxt++), SYN-ACK (rcv_nxt set), ACK → Established
FIN exchange: close() sends FIN, drive through FinWait1/2 → TimeWait → Closed
TIME_WAIT: 60s minimum before port reuse
RST: on invalid segment or abort
```

**Session B1c — Retransmission**:
```
Retransmit queue: VecDeque of (seq_num, data, send_time)
On send: push to retransmit queue
On ACK: remove acknowledged segments from queue
On timer: if oldest segment > RTO, retransmit + double RTO (Karn)
Fast retransmit: 3 duplicate ACKs → retransmit oldest unacked
```

**Session B1d — Congestion control**:
```
Fields: cwnd: u32, ssthresh: u32
Slow start: cwnd starts at 1 MSS, doubles each RTT until ssthresh
Cong avoidance: cwnd += MSS²/cwnd per ACK (linear growth)
On loss: ssthresh = cwnd/2, cwnd = 1 MSS
```

**Reference**: `linux/net/ipv4/tcp_output.c` + `tcp_input.c`; `reactos/drivers/network/tcpip/tcpip/`

---

### B2. `setsockopt` / `getsockopt` Real Implementation  *(M, Critical)*
Currently all socket options are ignored.

```
SO_REUSEADDR: set flag in socket; allow rebind of port in TIME_WAIT
SO_KEEPALIVE: enable periodic keepalive probe
TCP_NODELAY: disable Nagle (always flush after write)
SO_RCVBUF / SO_SNDBUF: resize recv/send buffers
IPV6_V6ONLY: mark socket as IPv6-only
SO_ERROR: return and clear pending async error
```

---

### B3. `sendmsg` / `recvmsg` Ancillary Data  *(M, High)*
SCM_RIGHTS fd passing over Unix domain sockets. Required for D-Bus and Wayland.

```
Parse msg_control (struct cmsghdr)
For SCM_RIGHTS: extract fd numbers from sender, dup into receiver's fd table
Limits: max 253 fds per message (SCM_MAX_FD)
Handle SOCK_CLOEXEC flag on received fds
```

**Reference**: `linux/net/unix/af_unix.c` function `unix_stream_sendmsg` (~300 LOC)

---

### B4. `poll()` Integration for Sockets/Pipes  *(M, High)*
Even with poll() syscall, fds need per-type readiness:

```
Socket: poll → check recv_buf.len() > 0 (EPOLLIN) or send space (EPOLLOUT)
Pipe: poll → ring_buf not empty (EPOLLIN) or not full (EPOLLOUT)
PTY master: poll → slave has written data (EPOLLIN)
Unix socket: poll → connected + recv queue non-empty
```

---

## Phase C — VFS Hardening (2-3 sessions)

### C1. File Locking (`fcntl F_SETLK`)  *(M, Critical)*
SQLite uses POSIX byte-range locks. Without this, Firefox IndexedDB will corrupt databases
when multiple processes access the profile simultaneously.

```
Per-inode lock list: Vec<FileLock { pid, type: Read/Write, start, end }>
F_SETLK: non-blocking; return EAGAIN if conflict
F_SETLKW: blocking; wait on per-inode waitqueue until lock available
F_GETLK: query if a lock would conflict (don't acquire)
flock(LOCK_EX): whole-file advisory exclusive lock
```

**Reference**: `linux/fs/locks.c` (1,700 LOC)

---

### C2. Timestamp Updates  *(S, High)*
All files show epoch timestamp. `ls -l` is useless.

```
In VFS:
  read() path: update inode.atime = current_time()
  write() path: update inode.mtime = inode.ctime = current_time()
  stat() path: return current atime/mtime/ctime
current_time(): BOOT_EPOCH_SECS + tick_count / TICKS_PER_SEC
```

---

### C3. Dentry Cache  *(M, High)*
Every deep path lookup scans entire filesystem tree. Catastrophic for performance.

```
DENTRY_CACHE: HashMap<(parent_inode_id, name_hash), InodeId>
LRU eviction when > 4096 entries
On lookup hit: return cached inode directly
On file delete/rename: invalidate affected entries
```

---

### C4. `/proc/N/` Process Directory Tree  *(M, Medium)*
Required for `ps`, `top`, `strace`, crash reporters.

```
/proc/<PID>/  → directory (one per living process)
/proc/<PID>/status  → name, PID, PPID, state, VMSize, VmRSS
/proc/<PID>/maps    → VMA list (already done for self)
/proc/<PID>/fd/     → symlinks to open file descriptions
/proc/<PID>/exe     → symlink to executable path
/proc/<PID>/cmdline → null-separated argv
/proc/<PID>/stat    → numeric fields (for ps(1))
```

---

### C5. Unlink-on-Last-Close  *(M, High)*
The temp-file pattern `open() → unlink() → use fd` requires the file to persist until closed.

```
Add open_count: AtomicU32 to inode
open(): increment open_count
close(): decrement; if open_count == 0 AND nlink == 0: free inode+data
unlink(): decrement nlink; if nlink == 0 AND open_count == 0: free inode+data
```

---

## Phase D — Process Management  (1-2 sessions)

### D1. Process Groups & Sessions  *(M, Critical)*
Shell job control requires this.

```
PCB fields: pgid: u32, sid: u32
setsid(): pgid = pid, sid = pid; detach from controlling TTY
setpgid(pid, pgid): move pid to group pgid
getpgrp() / getpgid() / getsid(): trivial reads
kill(-pgid, sig): iterate PROCESS_TABLE, send to all where proc.pgid == pgid
tcsetpgrp(fd, pgid): set TTY foreground group (TIOCSPGRP ioctl)
```

---

### D2. `rlimit` Enforcement  *(M, Critical)*
Even with getrlimit returning values, they need to be enforced.

```
RLIMIT_NOFILE: check in fd_alloc() — if fd_count >= soft_limit → EMFILE
RLIMIT_NPROC: check in fork() — if process_count >= limit → EAGAIN
RLIMIT_FSIZE: check in write() — if file_size >= limit → SIGXFSZ + EFBIG
RLIMIT_STACK: check in stack VMA growth — if stack_size >= limit → SIGSEGV
RLIMIT_AS: check in mmap() — if total VMA size >= limit → ENOMEM
```

---

### D3. Orphan Adoption (PID 1 re-parenting)  *(S, High)*
Prevent zombie accumulation.

```
In exit_group():
  Walk PROCESS_TABLE
  For each proc where proc.ppid == dying_pid:
    proc.ppid = 1  (re-parent to init)
  If dying process has zombie children: send SIGCHLD to init
```

---

## Phase E — Security Foundation  (1-2 sessions)

### E1. Capability Bitmask + `capget`/`capset`  *(M, High)*
Base for browser sandboxing.

```
Thread fields: cap_effective: u64, cap_permitted: u64, cap_inheritable: u64
At init: all caps set (root-equivalent)
capget(hdrp, datap): fill cap_user_data from current thread caps
capset(hdrp, datap): set caps (requires CAP_SETPCAP)
Wire cap checks: SOCK_RAW → CAP_NET_RAW; chroot → CAP_SYS_CHROOT
```

---

### E2. `prctl(PR_SET_NO_NEW_PRIVS)` + `prctl(PR_SET_NAME)`  *(S, High)*
Critical for Chrome/Firefox sandbox and process naming.

```
PCB field: no_new_privs: bool; comm: [u8; 16]
PR_SET_NO_NEW_PRIVS: set no_new_privs = true (irreversible)
PR_GET_NO_NEW_PRIVS: return flag
PR_SET_NAME: copy arg to comm (max 16 bytes)
PR_GET_NAME: return comm
Check no_new_privs in exec() before applying setuid bits
```

---

### E3. FD_CLOEXEC via `fcntl`  *(S, High)*
Without this, file descriptors leak across exec boundaries.

```
Per-fd flag: cloexec: bool
fcntl(F_GETFD): return FD_CLOEXEC bit if cloexec
fcntl(F_SETFD): set/clear cloexec from FD_CLOEXEC bit
In exec(): close all fds where cloexec == true before loading new image
dup3/pipe2/accept4/socket: SOCK_CLOEXEC / O_CLOEXEC flags set cloexec at creation
```

---

## Phase F — Memory Hardening  (2-3 sessions)

### F1. CoW Page Faults  *(L, Critical)*
Real fork() requires CoW. Without it, parent/child share pages and corrupt each other.

**Reference**: `linux/mm/memory.c` `do_wp_page()`;
`mm/refcount.rs` (already exists, build on it)

```
On #PF with error_code & WRITE:
  Find VMA for fault_addr
  If VMA is MAP_PRIVATE and page refcount > 1:
    Allocate new frame
    Copy 4 KiB from old frame to new frame
    Remap PTE to new frame, writable
    Decrement old frame refcount
  Else if VMA is MAP_PRIVATE and page not yet allocated:
    Allocate zeroed frame (demand zero)
    Map PTE
```

---

### F2. Stack Guard Page + Auto-Growth  *(M, High)*
musl stack starts at 8 MiB but only allocates top pages lazily.

```
Create user stack VMA with GUARD flag for last page
On #PF in guard page:
  If within RLIMIT_STACK: extend VMA downward, allocate page
  Else: deliver SIGSEGV
```

---

### F3. `madvise` / `mremap`  *(M, Medium)*
Firefox heap uses both. MADV_DONTNEED reclaims memory; mremap resizes allocations.

---

## Phase G — X11 / GUI  (2-3 sessions)

### G1. Clipboard / Selection (ICCCM)  *(M, Critical)*
Copy-paste between apps is completely broken.

```
Handle SetSelectionOwner request: record (selection_atom, window, time)
Handle GetSelectionOwner request: return recorded owner
Handle ConvertSelection request:
  If no owner: send SelectionNotify with property=None
  Else: send SelectionRequest event to owner window
        owner responds with SelectionNotify
```

---

### G2. RENDER Glyph Sets  *(L, High)*
Cairo uses RenderCompositeGlyphs for all text rendering. Without this, any GTK/Qt app's text
is blank.

```
RenderCreateGlyphSet(gsid, format)
RenderAddGlyphs(gsid, glyphids[], glyphinfos[], data): store glyph bitmaps server-side
RenderCompositeGlyphs8/16/32(op, src, dst, mask_format, gsid, items[]):
  For each glyph item: look up bitmap, composite onto dst picture at (x+bearing, y+bearing)
```

---

### G3. EWMH Properties  *(M, Medium)*
Window manager hints for maximize, fullscreen, window type.

```
Honor _NET_WM_STATE changes from ConfigureWindow/ClientMessage:
  _NET_WM_STATE_FULLSCREEN: resize window to screen, raise to top, remove decorations
  _NET_WM_STATE_MAXIMIZED_VERT/HORIZ: resize to available workspace
  _NET_WM_STATE_HIDDEN: unmap window (iconified)
Set _NET_SUPPORTED on root window at X11 init
```

---

## Summary Table

| Phase | Sessions | Critical Items |
|-------|----------|----------------|
| A — Quick Wins | 1-2 | /dev nodes, RTC, poll, pread, rlimit, sysinfo, symlinks |
| B — Networking | 3-5 | Full TCP, setsockopt, sendmsg, socket poll |
| C — VFS | 2-3 | File locks, timestamps, dentry cache, unlink-on-close |
| D — Process | 1-2 | Sessions, rlimit enforce, orphan adoption |
| E — Security | 1-2 | Capabilities, prctl, FD_CLOEXEC |
| F — Memory | 2-3 | CoW faults, stack growth, madvise |
| G — X11/GUI | 2-3 | Clipboard, RENDER glyphs, EWMH |

**Recommended session order**: A → D → E → C → B → F → G

Start with Phase A — every item is < 200 LOC and immediately unblocks real-world testing.
Then D/E (process/security foundations) which B and F depend on.
Then C (VFS hardening) which almost everything uses.
Then B (TCP — the biggest single gap).
Then F (memory — enables real fork/exec scale).
Then G (X11 polish for GUI apps).

---

## Reference Files for Each Phase

| Phase | Best Reference |
|-------|---------------|
| A1-A9 | `linux/drivers/char/mem.c`, `linux/fs/select.c`, `linux/kernel/sys.c` |
| B TCP | `linux/net/ipv4/tcp.c`, `linux/net/ipv4/tcp_input.c`, `reactos/drivers/network/tcpip/` |
| C VFS | `linux/fs/locks.c`, `linux/fs/dcache.c`, `linux/fs/proc/` |
| D Proc | `linux/kernel/sys.c`, `linux/kernel/exit.c` |
| E Sec | `linux/security/commoncap.c`, `linux/kernel/sys.c` (prctl) |
| F Mem | `linux/mm/memory.c`, `linux/mm/mmap.c` |
| G X11 | ICCCM spec, X Render spec §4.6, `xserver/render/glyph.c` |
