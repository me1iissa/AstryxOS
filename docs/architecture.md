---
title: Architecture
nav_order: 2
---

# Architecture

AstryxOS is a hybrid kernel for UEFI x86-64. Its design borrows the NT
subsystem model: a compact **executive** at the centre, a **Hardware
Abstraction Layer** beneath it, and **personality subsystems** layered above
that each present one operating system's native ABI. Everything below a
personality — memory, scheduling, the VFS, IPC, networking, drivers — is shared.
Everything a personality adds is a thin translation from one OS's syscall and
binary conventions into executive primitives.

This page describes the layers from the top down.

{: .note }
Where this page references behaviour mandated by a standard, it cites the public
specification: the System V x86-64 psABI and the ELF standard for binary
layout; the Intel® 64 and IA-32 Architectures Software Developer's Manual
(Intel SDM) for `SYSCALL`/`SYSRET` and paging; POSIX and the Linux man-pages
for syscall semantics; and the relevant RFCs for the network stack.

---

## Personalities — the multi-ABI surface

A *personality subsystem* owns two things: a **syscall entry surface** and a
**binary loader**. A program never learns it is on AstryxOS; it makes the calls
it was compiled to make and gets the semantics it expects back.

| Personality | Entry surface | Binaries it loads | Maturity |
|---|---|---|---|
| **Linux x86-64** | the `SYSCALL` instruction (per the x86-64 psABI and the Intel SDM Vol. 2) | static ELF, PIE (`ET_DYN`), and fully dynamic ELF via the system's `ld.so` | Real upstream glibc- and musl-linked binaries run end-to-end |
| **NT / Win32** | software interrupt `INT 0x2E` (the classic NT syscall gate) | PE32+ images | Loader + a `KUSER_SHARED_DATA`-style stub subsystem |
| **Native Aether** | software interrupt `INT 0x2E` (Aether dispatch) | AstryxOS-native programs | First-party calls for the shell, demos, and tooling |

The Linux personality is the most developed because it is the one Firefox needs.
It dispatches **193+ Linux syscalls** through `kernel/src/subsys/linux/`,
alongside the **50+ native Aether calls** in `kernel/src/subsys/aether/`. The
two dispatchers share a single entry point in `kernel/src/syscall/` that routes
on the calling personality.

The most important property of a personality is that it is *honest*: it does not
emulate behaviour with a workaround, it implements the documented contract. When
an upstream binary trips, the response is to fix the personality (or the shared
executive beneath it) so that the documented ABI is satisfied — see
[Running Upstream Binaries](running-upstream-binaries.md) for the invariant and
the list of real ABI bugs this discipline has surfaced and fixed.

---

## The executive (shared core)

Below the personalities sits the Aether executive — the OS-agnostic machinery
that every personality is built on. It mirrors the NT executive's
responsibilities.

| Subsystem | Path | Responsibility |
|---|---|---|
| Memory manager | `mm/` | Physical memory manager (PMM), virtual memory manager (VMM), slab heap, page tables, ASLR, demand paging, OOM killer |
| Scheduler | `sched/` | SMP run queue: round-robin + priority (CoreSched), with anti-starvation aging so a runnable thread cannot be starved indefinitely |
| Process / thread | `proc/` | Process and thread control blocks, the ELF loader (static, PIE, dynamic) and the PE32+ loader |
| Virtual filesystem | `vfs/` | Mount table and the file/inode abstraction over every filesystem driver |
| IPC | `ipc/` | Pipes, Unix-domain sockets, SysV shared memory, `timerfd`, `signalfd`, `inotify`, PTYs |
| Networking | `net/` | The TCP/IP stack (see below) |
| X11 server | `x11/` | An in-kernel X11 server with seven extensions |
| Core executive | `ke/` | Spinlocks, DPCs, deferred work, wait/notify primitives |
| Object manager | `ob/` | Handles and reference counting |
| Security | `security/` | Capabilities (`capget`/`capset`), rlimits, `prctl`, `PR_SET_NO_NEW_PRIVS` |
| GUI / GDI | `gui/`, `gdi/`, `wm/` | Window manager, compositor, terminal emulator, desktop shell; the GDI device-context / surface / BitBlt engine |

The executive owns the hard concurrency invariants. Two recurring examples from
the project's history illustrate the level the code operates at:

- **Futex correctness.** `futex(2)` `FUTEX_WAIT` compares the 32-bit word at the
  user address against the supplied value. The comparison must be done in 32
  bits — a 64-bit compare sign-extends a high-bit-set value and breaks the
  contract. Getting this exactly right is what lets contended musl mutexes park
  and wake correctly.
- **Wake delivery under contention.** A scheduler timer that comes due must wake
  its sleeper even if a lock acquisition loses a race; a due-wake must never be
  silently dropped. The executive guarantees forward progress here.

---

## Memory management

The memory manager is a conventional two-level design — a physical frame
allocator under a per-address-space virtual memory manager — extended with the
features upstream dynamic binaries require:

- **Demand paging** for file- and anonymous-backed mappings, so `mmap(2)`
  regions are populated lazily on first touch.
- **ASLR** for both `ET_DYN` ELF images and PE images (`DYNAMIC_BASE`), so load
  addresses are randomised as on a hardened host.
- **`mremap(2)`** including in-place grow, which must preserve adjacent mappings
  rather than clobber them.
- **`PT_GNU_RELRO`** read-only hardening of the relocated GOT after startup.
- **A slab heap** for kernel objects and an **OOM killer** for memory pressure.

Page tables follow the x86-64 4-level paging layout described in the Intel SDM.

---

## Scheduling

CoreSched is an SMP scheduler combining round-robin fairness with priority. The
key correctness property for running real multi-process applications is
**anti-starvation aging**: a thread's effective priority rises with the time it
has spent waiting in the Ready queue, so a runnable thread (for example, a
freshly-spawned content-process child) is guaranteed to be scheduled rather than
sitting Ready forever behind higher-priority work. Without this, multi-process
startup can deadlock even though no thread is blocked.

---

## Process model and binary loading

`proc/` owns process and thread control blocks and the loaders. The ELF loader
honours exactly what the upstream toolchain emitted:

- `PT_LOAD` segments mapped with the correct protections;
- `PT_INTERP` — the path to the upstream dynamic linker, which is then loaded
  and run as the program interpreter;
- `PT_TLS` — thread-local storage, set up so libc's TLS model works unmodified;
- the relocation tables, including the compact `DT_RELR` form and `DT_GNU_HASH`
  symbol lookup;
- `PT_GNU_RELRO` for post-relocation hardening.

The exec path also constructs a variant-aware `LD_LIBRARY_PATH` derived from the
binary's `PT_INTERP`, so the upstream `ld.so` searches the same directories it
would on a normal install and resolves a program's bundled `.so` set.

The PE32+ loader parses Windows images natively, sets up the Win32 environment
block, and provides a `KUSER_SHARED_DATA`-style shared page so the image's CRT
can initialise.

---

## Filesystems and the VFS

The VFS presents a single mount tree over a set of filesystem drivers:

| Filesystem | Access | Notes |
|---|---|---|
| ramfs | read/write | Root VFS, in-memory |
| FAT32 | read/write | Cluster allocator: create, write, truncate, unlink |
| ext2 | read | Inode + directory traversal; backs the data disk that carries upstream libraries |
| NTFS | read | |
| procfs | read | `/proc/self`, `/proc/<pid>`, `cpuinfo`, `meminfo`, `uptime`, `maps`, `fd/` |
| tmpfs | read/write | Mounted at `/tmp` via `sys_mount` |

A subtle but load-bearing correctness rule lives here: a device-level read error
is **not** end-of-file. A failed read must propagate an error and must never
install a zero-filled page as valid data — otherwise file-backed memory silently
diverges from the disk, which corrupts code pages of large libraries.

---

## Networking

`net/` is a full TCP/IP stack implemented from scratch:

- **IPv4 and IPv6**, ARP, ICMP.
- **TCP** with the 3-way handshake, FIN teardown, retransmission, and congestion
  control, per the relevant RFCs.
- **UDP**, **DNS**, and **DHCP** for autoconfiguration.
- Drivers for **e1000** and **virtio-net**.

This is what lets upstream `wget`/`curl`, an `httpd`, and an OpenSSL TLS
handshake run over real sockets.

---

## Graphics: X11, GDI, and the shell

AstryxOS runs an **in-kernel X11 server** (`x11/`) implementing the core
protocol plus the RENDER, MIT-SHM, XKB, XFIXES, SYNC, and BIG-REQUESTS
extensions — enough for real X11 clients to connect and draw. Above it,
`gui/`, `wm/`, and `gdi/` provide a window manager, a compositor, a terminal
emulator, a desktop shell, and a GDI engine (device contexts, surfaces, BitBlt,
text, regions).

---

## Drivers and the HAL

The Hardware Abstraction Layer (`hal/`) isolates the executive from the
platform. The driver set covers what is needed to boot and run on QEMU and
comparable hardware:

| Category | Drivers |
|---|---|
| Block | ATA PIO, AHCI DMA, virtio-blk, partition table |
| Network | e1000, virtio-net |
| Audio | AC97 (`/dev/dsp`) |
| Input | PS/2 keyboard, PS/2 mouse |
| Display | Framebuffer, VMware SVGA stub |
| USB | xHCI enumeration (Tier 1 probe) |
| Serial | 16550 UART |
| Timer | PIT, LAPIC, HPET, RTC |

---

## Boot flow

1. **AstryxBoot**, a from-scratch UEFI bootloader (`bootloader/`), runs in the
   UEFI environment, loads the flat kernel binary, gathers a memory map and
   framebuffer info, and hands control to the kernel.
2. The kernel brings up the x86-64 platform: GDT, IDT, LAPIC, SMP AP startup,
   paging, and the executive subsystems in dependency order.
3. The personalities register their syscall surfaces, the VFS mounts the root
   and the data disk, and `init` (or the test runner, in test mode) starts.

---

## Source layout

```
kernel/src/
├── arch/       # x86-64: GDT, IDT, LAPIC, SMP, context switch, ISR delivery
├── mm/         # PMM, VMM, slab heap, page tables, ASLR, OOM killer
├── sched/      # CoreSched — SMP round-robin + priority, anti-starvation aging
├── proc/       # Process/thread control blocks, ELF + PE32+ loaders
├── vfs/        # VFS: ramfs, FAT32, ext2, NTFS, procfs, tmpfs
├── ipc/        # Pipes, Unix sockets, SysV SHM, timerfd, signalfd, inotify, PTY
├── net/        # TCP/IP stack, DNS, DHCP, e1000, virtio-net
├── x11/        # In-kernel X11 server (7 extensions)
├── gui/ wm/ gdi/   # Window manager, compositor, terminal, desktop, GDI engine
├── ke/ ob/     # Core executive (locks, DPCs, wait/notify) + object manager
├── security/   # Capabilities, rlimits, prctl
├── hal/        # Hardware Abstraction Layer
├── drivers/    # ATA, AHCI, virtio-blk/net, AC97, PS/2, xHCI, serial
├── nt/ win32/  # NT personality subsystem (Win32 ABI)
├── subsys/
│   ├── linux/  # Linux syscall dispatch (193+ syscalls)
│   ├── aether/ # Native Aether syscall dispatch (50+ calls)
│   └── win32/  # Win32 syscall dispatch
├── syscall/    # Syscall entry point and personality routing
└── test_runner.rs   # Headless integration test suite
```

---

## See also

- [Running Upstream Binaries](running-upstream-binaries.md) — the multi-ABI
  model in practice, the never-patch-the-binary invariant, and the Firefox push.
- [Getting Started](getting-started.md) — build it and run the tests.
- [Contributing & Dev Tooling](dev-tooling.md) — the harness, GDB autopsy, and
  the contribution flow.
