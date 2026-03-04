# AstryxOS

A UEFI-native x86_64 operating system written in Rust.

## Quick Start

```bash
# Build the OS
./build.sh release

# Run in QEMU
./scripts/run-qemu.sh
```

## Architecture

| Component | Name | Description |
|-----------|------|-------------|
| Kernel | **Aether** (v0.1) | Monolithic kernel with NT-inspired subsystem layers |
| Scheduler | **CoreSched** | Round-robin scheduler (priority planned) |
| Shell | **Orbit** | Interactive command shell (Phase 7) |
| Init System | **Ascension** | PID 1 init process (Phase 6) |
| Bootloader | **AstryxBoot** | Custom UEFI bootloader |

## Project Structure

```
AstryxOS/
├── .ai/                # AI guidelines, plan, progress tracking
├── bootloader/         # AstryxBoot — UEFI bootloader
├── kernel/             # Aether — kernel core
│   └── src/
│       ├── arch/       # Architecture-specific (x86_64)
│       ├── mm/         # Memory management (PMM, VMM, heap)
│       ├── proc/       # Process management
│       ├── sched/      # CoreSched scheduler
│       ├── syscall/    # System call interface
│       ├── io/         # I/O subsystem
│       ├── drivers/    # Device drivers (serial, console, keyboard)
│       └── hal/        # Hardware Abstraction Layer
├── shared/             # Shared types between bootloader and kernel
├── userspace/          # Userspace programs (Ascension, Orbit)
├── build.sh            # Build script
└── scripts/
    └── run-qemu.sh     # QEMU launcher
```

## Requirements

- Rust nightly toolchain
- QEMU with OVMF firmware
- Linux host (tested on Ubuntu)

## Features (Phase 0-3)

- [x] UEFI boot with custom bootloader
- [x] Framebuffer console with ASCII art logo
- [x] GDT/IDT/IRQ setup
- [x] Physical & virtual memory management (MMU)
- [x] Kernel heap allocator
- [x] PS/2 keyboard driver
- [x] Serial debug output
- [x] Timer (PIT at 100 Hz)
- [x] Process control blocks
- [x] Syscall interface (int 0x80 + syscall/sysret)
- [x] Kernel debug shell

## License

AstryxOS is a research/educational operating system.
