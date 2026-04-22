# AstryxOS

AstryxOS is a UEFI-native x86_64 research operating system written in Rust (~83 KLOC). Its
monolithic kernel, Aether, follows an NT-inspired subsystem model and provides full Linux ABI
compatibility, allowing unmodified glibc ELF binaries to run alongside native Aether and Win32
PE32+ applications. The long-horizon goal is a self-hosted desktop capable of running Firefox.

---

## At a glance

### Syscall ABIs

| ABI | Dispatch | Implemented |
|-----|----------|-------------|
| Linux x86_64 | `syscall` instruction | 193 syscalls handled |
| Native Aether | `INT 0x2E` | 50+ native calls |
| Win32 PE32+ | `INT 0x2E` (NT personality) | stub subsystem |

glibc-linked ELF binaries run end-to-end (hello world confirmed on data disk).

### Filesystems

| FS | Access | Notes |
|----|--------|-------|
| ramfs | read/write | Root VFS |
| FAT32 | read/write | Data disk; cluster allocator, create/write/truncate/unlink |
| ext2 | read-only | |
| NTFS | read-only | |
| procfs | read | /proc/self, /proc/\<pid\>, /proc/cpuinfo, /proc/meminfo, etc. |
| tmpfs | read/write | Mounted at /tmp via `sys_mount` |

### Networking

Full in-kernel TCP/IP stack: IPv4, IPv6, TCP (3WHS, FIN, retransmit, congestion),
UDP, ARP, ICMP/ICMPv6, DNS, DHCP client, Unix domain sockets (SCM_RIGHTS), e1000
and virtio-net drivers.

### Graphics

In-kernel X11 server: core protocol, RENDER, MIT-SHM, BIG-REQUESTS, XKB, XFIXES,
SYNC extensions. In-kernel window manager and GDI engine (text, BitBlt, regions,
surfaces). GUI desktop with compositing terminal emulator.

### Drivers

| Category | Drivers |
|----------|---------|
| Block | ATA PIO, AHCI DMA, virtio-blk, partition table |
| Network | e1000, virtio-net |
| Audio | AC97 (`/dev/dsp`) |
| Input | PS/2 keyboard, PS/2 mouse |
| Display | Framebuffer console, VMware SVGA stub |
| USB | xHCI enumeration (Tier 1 probe) |
| Serial | 16550 UART |
| Timer | PIT, LAPIC, HPET, RTC |

### Process model

fork/exec, ELF loader (static, PIE, position-independent; DT_RELR, DT_GNU_HASH),
PE32+ loader, dynamic linking via `ld-musl-x86_64.so.1`, POSIX signals with ISR
delivery, process groups, sessions, PTY, timerfd, signalfd, inotify, SysV SHM,
pipes, epoll, capabilities, rlimits.

### Test suite

143 headless tests run inside QEMU (no display required). Current status: **139/140
passing** (one test gated on optional Win32 PE feature).

---

## Quick start

### Prerequisites

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full dependency list and
step-by-step first-build guide.

Short version:
- Ubuntu 22.04+ or WSL2
- Rust nightly (`rustup toolchain install nightly`)
- `qemu-system-x86_64`, `mtools`, `gcc`, `musl-gcc`, OVMF firmware

### Build

```bash
./build.sh release
```

This builds the UEFI bootloader and the Aether kernel, then assembles the ESP
directory tree under `build/esp/`.

### Create the data disk

```bash
bash scripts/create-data-disk.sh
```

Produces `build/data.img` (512 MiB FAT32). Required for tests that exercise the
filesystem, dynamic linker, and glibc binary.

### Run the test suite

```bash
python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300
```

The watchdog builds the kernel (with `test-mode` feature), launches QEMU headless,
streams the serial log, detects panics and hangs, and exits with a structured code:

| Exit | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | Some tests failed |
| 2 | Hung (idle timeout) |
| 3 | Hard timeout |
| 4 | QEMU crashed |
| 5 | Build failed |

### Interactive debug session

```bash
python3 scripts/qemu-harness.py start --gdb-port 1234
# returns {"sid": "<id>", ...}
python3 scripts/qemu-harness.py wait <sid> "kernel ready" --ms 15000
python3 scripts/qemu-harness.py regs <sid>
python3 scripts/qemu-harness.py stop <sid>
```

See [docs/HARNESS.md](docs/HARNESS.md) for the full subcommand reference.

---

## Project layout

```
AstryxOS/
├── bootloader/         # AstryxBoot — custom UEFI bootloader
├── kernel/
│   └── src/
│       ├── arch/       # x86_64: GDT, IDT, LAPIC, SMP, context switch
│       ├── drivers/    # ATA, AHCI, virtio-blk/net, AC97, PS/2, xHCI, serial
│       ├── gdi/        # GDI engine: DC, surfaces, BitBlt, text, regions
│       ├── gui/        # Window manager, compositor, terminal, desktop
│       ├── hal/        # Hardware Abstraction Layer
│       ├── ipc/        # Pipes, Unix sockets, SysV SHM, timerfd, signalfd
│       ├── ke/         # Core executive: spinlocks, DPCs, wait/notify
│       ├── mm/         # PMM, VMM, heap, page tables, ASLR, OOM killer
│       ├── net/        # TCP/IP stack, DNS, DHCP, e1000, virtio-net
│       ├── nt/         # NT personality subsystem (Win32 ABI)
│       ├── ob/         # Object manager (handles, reference counting)
│       ├── proc/       # Process and thread control blocks, ELF/PE loader
│       ├── sched/      # CoreSched — SMP round-robin + priority
│       ├── security/   # Capabilities, rlimits, prctl
│       ├── subsys/
│       │   ├── aether/ # Native Aether syscall dispatch
│       │   ├── linux/  # Linux syscall dispatch (193 syscalls)
│       │   └── win32/  # Win32 syscall dispatch stub
│       ├── syscall/    # Syscall entry point and routing
│       ├── vfs/        # VFS layer: ramfs, FAT32, ext2, NTFS, procfs, tmpfs
│       ├── x11/        # In-kernel X11 server
│       └── test_runner.rs  # 143 headless integration tests
├── shared/             # Types shared between bootloader and kernel
├── tools/              # Host-side utilities
├── scripts/
│   ├── watch-test.py       # Test watchdog (primary CI entrypoint)
│   ├── qemu-harness.py     # Agentic QEMU session manager
│   ├── create-data-disk.sh # Build build/data.img
│   ├── build-musl.sh       # Build musl libc for the data disk
│   ├── install-glibc.sh    # Install glibc dynamic linker + libs
│   └── run-qemu.sh         # Manual QEMU launcher (interactive)
├── docs/
│   ├── QUICKSTART.md           # First-build guide for new contributors
│   ├── HARNESS.md              # qemu-harness.py reference
│   ├── DEVELOPMENT_PLAN.md     # Wave-based roadmap and status
│   ├── FIREFOX_PORT_ROADMAP.md # Firefox porting milestones
│   └── SOURCE_REVIEW_2026-04-20.md  # Dated architecture snapshot
├── build.sh            # Manual build script
└── rust-toolchain.toml # Pins nightly toolchain version
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | New contributor first-build guide |
| [docs/HARNESS.md](docs/HARNESS.md) | `qemu-harness.py` subcommand reference |
| [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) | Wave roadmap and current state |
| [docs/FIREFOX_PORT_ROADMAP.md](docs/FIREFOX_PORT_ROADMAP.md) | Firefox porting milestone tracker |
| [docs/SOURCE_REVIEW_2026-04-20.md](docs/SOURCE_REVIEW_2026-04-20.md) | Architecture snapshot (2026-04-20) |

---

## Wave summary (Wave 1–8 completed)

| Wave | Theme | Key deliverables |
|------|-------|-----------------|
| 1 | P0/P1 punch-list | bootloader errors, execve leak, procfs VFS, virtio-net, inotify, OOM killer |
| 2 | Driver hardening | driver stop sweep, ASLR (ET_DYN + PE), xHCI enumeration |
| 3 | Storage + audio | FAT32 read/write, AC97 `/dev/dsp` |
| 4 | Syscall refactor + tmpfs | split 7175-line `syscall/mod.rs`, `sys_mount` + tmpfs at `/tmp` |
| 5 | glibc dynamic linker | `ld-musl-x86_64.so.1`, glibc libs, `/etc` seed, glibc hello runs |
| 6 | ELF completeness | DT_RELR, DT_GNU_HASH, statx, getrandom, mremap, robust_list, membarrier |
| 7 | Debug harness | `qemu-harness.py` Tier 1 (session/log) + Tier 2 (GDB RSP stub) |
| 8 | X11 extensions | MIT-SHM, BIG-REQUESTS, XKB, XFIXES, SYNC, RENDER; glibc stack-canary fix |

Current headless test count: **143 total, 139/140 passing** (one Win32 PE test gated behind `win32-pe-test` feature flag).

---

## License

MIT. See [LICENSE](LICENSE).
