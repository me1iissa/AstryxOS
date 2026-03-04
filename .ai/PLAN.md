# AstryxOS — Master Build Plan

## Overview
AstryxOS is a UEFI-native x86_64 operating system written in Rust. It features a
microkernel-inspired design with a monolithic kernel (Aether) that provides MMU, IRQ,
syscall, process, I/O, scheduling, and driver subsystems. Userspace includes an init
system (Ascension) and a shell (Orbit). The system targets POSIX compatibility for
future application support.

---

## Phase 0: Foundation & Tooling ✅
**Goal**: Bootable UEFI binary that prints to screen via QEMU.

- [x] Project structure (Cargo workspace)
- [x] Rust nightly toolchain + `x86_64-unknown-uefi` target
- [x] UEFI bootloader stub using `uefi` crate
- [x] Framebuffer console output (text rendering)
- [ ] Boot splash / AstryxOS logo display
- [x] Handoff to kernel entry point
- [x] QEMU launch script with OVMF
- [x] ISO generation (FAT32 EFI System Partition)

## Phase 1: Aether Kernel Core ✅
**Goal**: Kernel with memory management, interrupts, and basic I/O.

- [x] GDT (Global Descriptor Table) setup
- [x] IDT (Interrupt Descriptor Table) setup
- [x] IRQ handling (PIC/APIC)
- [x] Physical memory manager (bitmap allocator)
- [x] Virtual memory manager (4-level page tables, MMU)
- [x] Kernel heap allocator
- [x] Serial port driver (for debug output)
- [x] Framebuffer text console driver
- [x] Timer (PIT/HPET/APIC timer)
- [x] Basic panic handler with stack trace

## Phase 2: Process & Scheduling ✅
**Goal**: Multitasking with kernel and user mode separation.

- [x] Process/Task structure (PCB)
- [x] Context switching (save/restore registers) — global_asm! for correct `ret` semantics
- [x] CoreSched scheduler (round-robin initially, priority later)
- [x] Kernel threads
- [x] User mode (Ring 3) transition
- [x] TSS (Task State Segment) setup
- [x] ELF binary loader
- [x] Process creation / fork / exec syscalls
- [x] waitpid() — zombie reaping with exit code

## Phase 3: Syscall Interface ✅
**Goal**: Clean syscall ABI for userspace programs.

- [x] Syscall entry via `syscall`/`sysret` (MSR setup)
- [x] Syscall dispatch table
- [x] Core syscalls: `write`, `read`, `open`, `close`, `exit`, `fork`, `exec`, `waitpid`
- [ ] `mmap` / `munmap` for userspace memory
- [x] `getpid`, `getppid`
- [ ] Signal framework (basic: SIGKILL, SIGTERM, SIGINT)

## Phase 4: I/O & Device Drivers ✅
**Goal**: Abstracted I/O system with driver model.

- [x] VFS (Virtual Filesystem) layer
- [x] Device driver trait/interface
- [x] RAM disk filesystem (initramfs)
- [x] Keyboard driver (PS/2 or USB HID basic)
- [x] Framebuffer/display driver
- [ ] Block device abstraction
- [ ] Character device abstraction
- [x] `/dev` device nodes

## Phase 5: Filesystem (partial)
**Goal**: Persistent filesystem support.

- [x] FAT32 read support (in-memory driver, VFS-integrated)
- [x] Simple in-memory filesystem (tmpfs / RamFS)
- [ ] FAT32 on real block device (ATA/AHCI, QEMU uses AHCI on q35)
- [ ] ext2 read support (stretch goal)
- [x] File descriptor table per process
- [x] Path resolution
- [x] NtStatus unified error model (shared/ntstatus.rs) — NT-inspired

## Phase 6: Ascension Init System
**Goal**: First userspace process that bootstraps the system.

- [ ] Ascension binary (PID 1)
- [ ] Parse init configuration
- [ ] Mount root filesystem
- [ ] Launch Orbit shell
- [ ] Basic service management (start/stop)

## Phase 7: Orbit Shell ✅
**Goal**: Interactive command shell for users.

- [x] Line editing (readline-like)
- [x] Command parsing & execution
- [x] Built-in commands: `cd`, `pwd`, `echo`, `exit`, `help`, `clear`
- [ ] External command execution (fork+exec)
- [ ] Environment variables
- [x] Pipe support (`|`) — stretch
- [ ] Redirection (`>`, `<`) — stretch

## Phase 8: POSIX & ELF Polish (partial)
**Goal**: Enough POSIX compliance to run simple C programs.

- [ ] POSIX signal handling
- [ ] POSIX file I/O semantics
- [ ] Basic libc shim (or musl port)
- [ ] ELF dynamic linking (stretch)
- [x] `/proc` pseudo-filesystem (stretch)

## Phase 9: Hardening & Polish (partial)
**Goal**: Stable, testable OS image.

- [ ] Kernel panic improvements
- [x] Memory protection (guard pages, NX)
- [x] Automated QEMU test harness
- [ ] Boot splash with AstryxOS logo
- [ ] Documentation and README

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────┐
│                  User Mode (Ring 3)             │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Orbit   │  │ Ascension│  │  User Apps   │  │
│  │ (Shell)  │  │  (Init)  │  │  (ELF bins)  │  │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  │
│       │              │               │          │
│───────┴──────────────┴───────────────┴──────────│
│              Syscall Interface                   │
│─────────────────────────────────────────────────│
│                Kernel Mode (Ring 0)             │
│  ┌──────────────── Aether ─────────────────┐    │
│  │  ┌──────────┐ ┌───────┐ ┌───────────┐  │    │
│  │  │CoreSched │ │  MMU  │ │  Syscalls  │  │    │
│  │  └──────────┘ └───────┘ └───────────┘  │    │
│  │  ┌──────────┐ ┌───────┐ ┌───────────┐  │    │
│  │  │   IRQ    │ │  I/O  │ │  Drivers   │  │    │
│  │  └──────────┘ └───────┘ └───────────┘  │    │
│  │  ┌──────────┐ ┌───────────────────┐    │    │
│  │  │   VFS    │ │  Process Manager  │    │    │
│  │  └──────────┘ └───────────────────┘    │    │
│  └─────────────────────────────────────────┘    │
│─────────────────────────────────────────────────│
│          UEFI Bootloader (AstryxBoot)           │
│─────────────────────────────────────────────────│
│              x86_64 Hardware                     │
└─────────────────────────────────────────────────┘
```

## Key Technical Decisions
1. **UEFI-only**: No legacy BIOS. Use UEFI boot services for initial setup, then exit boot services.
2. **Monolithic kernel**: All drivers in kernel space for simplicity (v1). Microkernel refactor possible in v2.
3. **Rust `no_std`**: Freestanding Rust with inline asm for arch code.
4. **4-level paging**: Standard x86_64 page tables (PML4 → PDPT → PD → PT).
5. **Higher-half kernel**: Kernel mapped at `0xFFFF_8000_0000_0000+`.
6. **ELF userspace**: All userspace binaries are ELF64.
7. **POSIX-first syscall design**: Model syscalls after POSIX for future compatibility.
