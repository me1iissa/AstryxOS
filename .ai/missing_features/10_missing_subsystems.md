# Entirely Missing Subsystems

These are subsystems that do not exist in AstryxOS at all — no stub, no placeholder.
Compared against: Linux kernel, Windows XP, XNU.

---

## Tier 1 — High Impact (Block Firefox / Real Apps)

### Real-Time Clock (RTC) Driver
**What**: Read the CMOS real-time clock (I/O ports 0x70/0x71) to get wall-clock time.
Without this, `clock_gettime(CLOCK_REALTIME)` returns 0 (Unix epoch: 1970-01-01).
TLS/HTTPS certificate validation requires the current time — expired certs will be accepted
(year 0 < expiry) or rejected (every cert appears expired), depending on implementation.

**Scope**: ~100 lines. Read BCD-encoded date/time registers. Convert to Unix timestamp.
Store in a kernel variable; update via periodic tick addition.

**Reference**: `linux/drivers/rtc/rtc-cmos.c`; CMOS register map at port 0x70/0x71

---

### POSIX Capabilities Implementation
**What**: 64-bit bitmask (effective, permitted, inheritable, ambient, bounding) per thread.
`capget()` / `capset()` syscalls. Checked before privileged operations.

**Scope**: ~300 lines. Add fields to Thread struct. Implement capget/capset. Wire capability
checks to: `raw_socket()` (CAP_NET_RAW), `chroot()` (CAP_SYS_CHROOT), `mknod()` (CAP_MKNOD),
`kill()` to another UID (CAP_KILL).

**Reference**: `linux/security/commoncap.c`; `linux/include/uapi/linux/capability.h`

---

### `/dev` Population and `udev`-like Hotplug
**What**: Device nodes in `/dev` — `null`, `zero`, `random`, `urandom`, `full`, `tty`, `console`,
`ptmx`, `pts/`, `fb0`, `input/event0`, `input/mouse0`, `sda`, `sda1`, etc. Currently these
paths are hardcoded or missing. Apps that open `/dev/null` for garbage output will fail.

**Scope**: ~200 lines. Register device nodes in ramfs at boot time in `init/mod.rs`.
Add `/dev/null` (always succeeds, discards writes, EOF on read), `/dev/zero`, `/dev/urandom`.

**Reference**: `linux/drivers/char/mem.c` (null, zero, random, mem); sysfs + udev model

---

### `memfd_create` (Syscall 319)
**What**: Creates an anonymous file backed by memory. Returns an fd. Can be `mmap()`'d to
create shared memory without a filesystem path. Used by:
- Firefox SpiderMonkey JIT (creates executable memory without a temp file)
- Wayland shared buffer protocol
- Any code needing shared anonymous mmap without SysV SHM

**Scope**: ~80 lines. Create a RamFS inode with no path, return fd. Support mmap/ftruncate/read/write.

**Reference**: `linux/mm/memfd.c` (300 LOC); syscall 319 `memfd_create(2)`

---

### Monotonic High-Resolution Clock
**What**: `clock_gettime(CLOCK_MONOTONIC)` and `clock_gettime(CLOCK_MONOTONIC_RAW)` should
return nanosecond-precision time based on TSC or HPET. Currently returns tick-count * 10ms
which gives 10ms resolution.

Firefox performance.now() uses `CLOCK_MONOTONIC`. WebRTC / media timing requires sub-millisecond
precision.

**Scope**: ~150 lines. Calibrate TSC frequency against PIT at boot. Store `tsc_hz`.
In clock_gettime: `rdtsc()` → multiply by `1_000_000_000 / tsc_hz` → nanoseconds.

**Reference**: `linux/arch/x86/kernel/tsc.c` (`native_read_tsc`, TSC calibration);
`linux/kernel/time/timekeeping.c`

---

## Tier 2 — Production Quality

### Kernel Module Loading
**What**: `insmod` / `rmmod` load/unload ELF kernel modules at runtime. Drivers are compiled
as separate `.ko` files and loaded without rebooting.

**Current state**: All drivers are statically linked. Can't add drivers without recompiling the kernel.

**Note**: For AstryxOS's current scope (monolithic, single machine target), this may be deferred.
But it's important for future extensibility.

**Reference**: `linux/kernel/module/` (core.c, 3,000 LOC); ELF relocation application

---

### Containers / Linux Namespaces
**What**: Process isolation via 8 namespace types:
- **user_ns**: Isolated UID/GID maps (unprivileged containers)
- **pid_ns**: Isolated PID numbering (container PID 1)
- **mnt_ns**: Separate mount table per container
- **net_ns**: Separate network stack (routing, sockets) per container
- **ipc_ns**: Separate SysV IPC objects per container
- **uts_ns**: Separate hostname/domain name
- **cgroup_ns**: Separate cgroup hierarchy view
- **time_ns**: Separate clock_gettime offsets

**Scope**: Large — 2,000-5,000 LOC minimum per namespace type.

**Reference**: `linux/kernel/nsproxy.c`; `linux/kernel/user_namespace.c` (2,800 LOC)

---

### cgroups v2
**What**: Control groups for resource management:
- **cpu**: CPU time limits + weight
- **memory**: RAM + swap limits, OOM kill policy
- **io**: Block I/O throttle (IOPS/bandwidth)
- **pids**: Limit process count
- **net_cls**: Network traffic classification

**Reference**: `linux/kernel/cgroup/` (cgroup.c 5,000 LOC); cgroupfs

---

### eBPF / Tracing Infrastructure
**What**: In-kernel bytecode VM for: syscall filtering (seccomp), socket filtering (AF_PACKET),
XDP (eXpress Data Path for networking), performance tracing (kprobes, uprobes, tracepoints),
security hooks (LSM BPF).

**Scope**: Huge. Minimum for seccomp: BPF classic (cBPF) verifier + interpreter for syscall filtering.
Full eBPF is 20,000+ LOC.

**Reference**: `linux/kernel/bpf/` (core.c, verifier.c, syscall.c);
`linux/net/core/filter.c` (cBPF for seccomp)

---

### Audit Subsystem
**What**: Record privileged syscall invocations to a ring buffer. `auditctl` rules filter
which events are recorded. `auditd` userspace daemon reads events via netlink socket.

**Reference**: `linux/kernel/audit.c` (3,000 LOC); `linux/kernel/auditfilter.c`

---

## Tier 3 — Advanced / Future

### In-Kernel Cryptography API
**What**: Unified kernel crypto API for: AES, SHA, HMAC, RSA, elliptic curves.
Used by: dm-crypt (encrypted block devices), TLS (kTLS), IPsec, kernel module signature verification.

**Reference**: `linux/crypto/` (200+ files); `linux/include/crypto/`

---

### Block I/O Scheduler (blk-mq)
**What**: Multi-queue block device layer with pluggable I/O schedulers (deadline, mq-deadline,
bfq, kyber). Merges adjacent requests, reorders for optimal seek, provides per-process
I/O accounting and throttling.

**Reference**: `linux/block/blk-mq.c` (3,500 LOC); `linux/block/elevator.c`

---

### DMA-BUF / PRIME GPU Buffer Sharing
**What**: Export GPU memory buffers as file descriptors that can be imported by another
device driver (GPU→video encoder, GPU→display controller). Required for Wayland DMA-BUF protocol.

**Reference**: `linux/drivers/dma-buf/dma-buf.c`

---

### KVM Hypervisor Host Support
**What**: Allow AstryxOS to host virtual machines. Requires VMX/SVM CPU features, VMCS management,
EPT (Extended Page Tables) for guest memory isolation.

**Reference**: `linux/virt/kvm/` (kvm_main.c 5,000 LOC); `linux/arch/x86/kvm/`

---

### Watchdog Timer
**What**: Hardware or software watchdog that reboots the system if the kernel hangs.
Software watchdog: NMI fires if no reset within N seconds; kernel panic handler resets.
Useful for automated test environments.

**Reference**: `linux/drivers/watchdog/`; `linux/kernel/watchdog.c` (NMI watchdog)

---

### ACPI Full Implementation
**What**: Current `po/acpi.rs` is a stub. Full ACPI needs:
- DSDT/SSDT AML interpreter (to find device objects, power methods)
- ACPI S-states (S3 suspend-to-RAM, S4 hibernate, S5 shutdown)
- ACPI device power states (D0-D3)
- Thermal zones and fan control
- Battery and AC adapter
- CPU P-states (frequency scaling)
- ACPI hotplug notifications

**Reference**: `linux/drivers/acpi/` (200+ files); Linux uses `acpica` reference implementation

---

### Power Management Infrastructure
**What**: System-wide suspend/resume path:
- Device suspend in reverse probe order
- CPU offline (secondary CPUs parked)
- Save kernel state
- Set ACPI sleep state
- On wake: restore kernel state, bring CPUs online, device resume

**Reference**: `linux/kernel/power/` (suspend.c, hibernate.c);
`XP/base/ntos/po/` (power.c, acpi.c, hiber.c)

---

## Quick Wins (Can Implement in One Session Each)

| Feature | LOC Estimate | Impact |
|---------|-------------|--------|
| `/dev/null`, `/dev/zero`, `/dev/urandom` | ~100 | Stops crashes on common open() |
| RTC driver (wall clock) | ~150 | Fixes TLS cert time validation |
| TSC-based high-res monotonic clock | ~200 | Firefox performance.now() |
| `memfd_create` | ~100 | JIT, Wayland shared memory |
| `/proc/cpuinfo`, `/proc/meminfo` | ~150 | Firefox startup, `free` command |
| POSIX capabilities bitmask | ~300 | Browser sandbox base |
| Robust futex list | ~150 | pthread mutex robustness |
