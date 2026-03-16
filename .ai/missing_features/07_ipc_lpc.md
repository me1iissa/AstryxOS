# IPC / LPC / ALPC Gaps

> Reference: Windows XP `base/ntos/lpc/` (15 C files), Linux `ipc/` (shm.c, msg.c, sem.c, mqueue.c)
> AstryxOS: `lpc/mod.rs`, `ipc/mod.rs`, `ipc/pipe.rs`, `ipc/epoll.rs`, `ipc/eventfd.rs`,
>            `ipc/timerfd.rs`, `ipc/signalfd.rs`, `ipc/sysv_shm.rs`, `ipc/inotify.rs`

---

## What We Have

- ALPC message port model: connection ports, communication ports, request/reply correlation
- Message queue per channel (MAX_QUEUED_MSGS=16), message IDs, timeout handling
- Datagram (one-way) messages
- AlpcView stub for shared memory (defined, not mapped)
- POSIX pipes: bidirectional ring buffers (4 KiB each), writer count, read/write ends
- `epoll`: fd list per process, EPOLLIN/EPOLLOUT/EPOLLERR/EPOLLET, edge-triggered
- `eventfd`: counter-based atomic signaling (EFD_SEMAPHORE, EFD_NONBLOCK)
- `timerfd`: PIT-tick timing (100 Hz), 64 slots, timerfd_settime/gettime/read
- `signalfd`: dequeue pending signals as SfdSiginfo structs
- `SysV SHM`: shmget/shmat/shmdt/shmctl, 64 segments, Device-VMA backing
- `inotify` stub: accepts add_watch/rm_watch/init, never delivers events

---

## Missing (Critical)

### POSIX Message Queues (`mq_open`, `mq_send`, `mq_receive`)
**What**: Named message queues accessible via `/dev/mqueue/`. Unlike SysV msgq, POSIX mqueues:
- Have a max message size and max queue depth
- Are accessible as file descriptors (can be used with `poll()`/`select()`)
- Support priority ordering
- Are created/opened by name, not by key

**Why critical**: musl and many D-Bus alternatives use POSIX mqueues for inter-process signaling.
Firefox sandbox communication may use this.

**Reference**: `linux/ipc/mqueue.c` (2,000 LOC); syscalls 240-243 (`mq_open`, `mq_unlink`,
`mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr`)

---

### SysV Semaphore Sets (`semget`, `semop`, `semctl`)
**What**: Arrays of semaphores accessed atomically via `semop()`. Unlike a single futex,
semaphore sets allow atomic increment/decrement across multiple semaphores in one call.
Used by PostgreSQL, Oracle DB, and many Unix daemons.

**Current state**: Only `futex` exists for synchronization. No semget/semop/semctl.

**Reference**: `linux/ipc/sem.c` (2,800 LOC); syscalls 64, 65, 66

---

### Robust Futex List (`FUTEX_ROBUST_LIST`)
**What**: A linked list of futexes that a process owns. On crash (abnormal death without releasing
mutexes), the kernel walks this list and sets the `FUTEX_OWNER_DIED` bit so waiting threads
can be notified.

**Why critical**: musl `pthread_mutex_lock` uses robust futexes by default. A process killed via
SIGSEGV without releasing its mutexes would deadlock all waiters forever without this.

**Reference**: `linux/kernel/futex/requeue.c` (`futex_set_robust_list`); syscall 310/311

---

### Pipe `poll()` / `select()` Integration
**What**: A pipe read-end fd should be readable (EPOLLIN) when data is available, and writable
(EPOLLOUT) when buffer is not full. Currently pipes don't integrate with epoll readiness.

**Why critical**: Shell pipelines (`cmd1 | cmd2`) use `poll()`/`select()` on pipe fds.
musl's stdio buffers also use this.

**Reference**: `linux/fs/pipe.c` (`pipe_poll`); `linux/include/linux/pipe_fs_i.h`

---

## Missing (High)

### ALPC View Mapping (Shared Memory via Port)
**What**: AlpcView allows clients and servers to share a memory region through an ALPC port.
The server calls `NtAlpcCreatePortSection`, the client maps it via `NtAlpcMapPortSection`.
Currently `AlpcView` struct exists in `lpc/mod.rs` but no pages are ever mapped.

**Reference**: `XP/base/ntos/lpc/` (`obapi.c`, view handling); `reactos/ntoskrnl/lpc/`

---

### ALPC Server: Multiple Pending Connections
**What**: An ALPC server can have multiple clients connecting simultaneously. Currently
`accept_connection()` only handles the first pending connection.

**Reference**: `XP/base/ntos/lpc/receive.c` (`NtAcceptConnectPort`)

---

### Futex: Shared Memory Mode (`FUTEX_PRIVATE_FLAG` inverse)
**What**: By default futex addresses are interpreted per-process (private). With shared futex,
the physical page backing the address is used as the key — allowing cross-process futex ops
on mmap'd shared memory. Required by some pthread implementations.

**Reference**: `linux/kernel/futex/futex.c` (`get_futex_key`); `futex(2)` FUTEX_PRIVATE_FLAG

---

### Condition Variables (`pthread_cond_wait`)
**What**: `pthread_cond_wait()` in musl is implemented via `futex(FUTEX_WAIT)` with a specific
sequence of mutex unlock → futex wait → mutex reacquire. The kernel just needs robust futex
semantics; the userspace musl implementation handles the rest.

**This is implicitly a futex correctness requirement**, not a new syscall.

---

## Missing (Medium)

| Feature | Description | Reference |
|---------|-------------|-----------|
| `inotify` real delivery | Actually enqueue events on file change | `linux/fs/notify/inotify/` |
| `fanotify` | File access notification with permission events | `linux/fs/notify/fanotify/` |
| `dnotify` (legacy) | Directory change notification via SIGIO | `linux/fs/notify/dnotify/` |
| `socketpair` full | Create connected Unix socket pair | `linux/net/unix/af_unix.c` |
| Pipe capacity control | `fcntl(F_SETPIPE_SZ)` to resize pipe buffer | `linux/fs/pipe.c` |
| `splice` | Zero-copy pipe ↔ file/socket transfer | `linux/fs/splice.c` |
| `vmsplice` | User memory → pipe zero-copy | `linux/fs/splice.c` |
| `tee` | Duplicate pipe data without consuming | `linux/fs/splice.c` |

---

## Missing (Low)

| Feature | Description |
|---------|-------------|
| SysV message queues | msgget/msgsnd/msgrcv (use POSIX mqueue instead) |
| Netlink | AF_NETLINK for kernel-user config communication |
| `memfd_create` | Anonymous file for JIT code / shared buffers |
| `userfaultfd` | User-space page fault handling |
| `pidfd` family | Process management via file descriptors |

---

## Implementation Notes

**Semaphore sets** are the most complex piece — the `semop()` atomicity guarantee (all-or-nothing
across multiple semaphores in one call) requires careful locking. See `linux/ipc/sem.c` for
the wait-array mechanism.

**Robust futex** is simpler than it looks: just add a `robust_list: Option<u64>` (user-space
pointer) to the PCB, set via `sys_set_robust_list()`, and walk it in `exit_group()` to
mark FUTEX_OWNER_DIED on each held futex.

**POSIX mqueues** can be layered as a virtual filesystem (`mqueue`) with special file descriptors
backed by a kernel queue struct. The file descriptor is pollable, making it natural to integrate
with epoll.
