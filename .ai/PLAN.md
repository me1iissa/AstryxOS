# AstryxOS — Master Build Plan

## Overview
AstryxOS is a UEFI-native x86_64 operating system written in Rust. It features an
NT-inspired monolithic kernel (Aether) that provides MMU, IRQ, syscall, process, I/O,
scheduling, executive subsystems, and driver infrastructure. The kernel supports **three
environment subsystems**: Aether (native), Linux (compatibility), and Win32/WoW
(compatibility). Linux and Win32 are translation layers over the Aether kernel — not
re-implementations. Userspace includes an init system (Ascension) and a shell (Orbit).

> See `.ai/subsystem/` for detailed subsystem architecture docs:
> - `OVERVIEW.md` — Architecture diagram, current state, change list
> - `AETHER.md` — Aether native subsystem (50 syscalls, ptr+len ABI)
> - `LINUX.md` — Linux compat layer (~90 mapped, ~295 remaining)
> - `WIN32.md` — Win32/WoW subsystem (PE loader, SSDT, ntdll/kernel32)
> - `PLAN.md` — Phased implementation milestones

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

## Phase 8: Subsystem Architecture 🔧
**Goal**: Three environment subsystems — Aether (native), Linux (compat), Win32/WoW (compat).

- [ ] Create `kernel/src/subsys/` module tree (aether/, linux/, win32/)
- [ ] Rename `SubsystemType::Posix` → `SubsystemType::Aether`, add `SubsystemType::Linux`
- [ ] Unify `Process.linux_abi` with `Process.subsystem`
- [ ] Extract Aether dispatch from `syscall/mod.rs` → `subsys/aether/`
- [ ] Extract Linux dispatch from `syscall/mod.rs` → `subsys/linux/`
- [ ] Move Win32 framework from `win32/` → `subsys/win32/`
- [ ] ELF subsystem auto-detection (PT_INTERP, GNU notes)
- [ ] Linux errno translation layer (`subsys/linux/errno.rs`)
- [x] Signal delivery with ABI-specific trampolines
- [x] `/proc` pseudo-filesystem
- [x] 40+ Linux syscall mappings in dispatch_linux()
- [x] Win32 framework (SubsystemType, CSRSS, ALPC, OB, handles)
- [x] **Phase 3 (Compiler Toolchain)**: TinyCC 0.9.27 static binary deploys to `/disk/bin/tcc`; compiles + executes C inside AstryxOS (Test 63, 63/63 ✅)

## Phase 8b: GUI Terminal — Async Exec + Pipe Stdout ✅
**Goal**: Fix GUI terminal so `exec` doesn't freeze the desktop and child stdout is visible.

- [x] `proc/mod.rs`: `attach_stdout_pipe(pid, pipe_id)` — replaces child fd=1/fd=2 with pipe write-end
- [x] `gui/terminal.rs`: `RunningExec` state, async exec path in Enter handler, `poll_output()`
- [x] `gui/desktop.rs`: call `terminal::poll_output()` + `x11::poll()` each tick

## Phase 8c: libc Support — musl + PT_TLS ✅
**Goal**: Statically-linked musl binaries work on AstryxOS. Prerequisite for X11 clients.

- [x] `proc/elf.rs`: PT_TLS segment handling (allocate TLS template, set FS base)
- [x] `scripts/build-musl.sh`: cross-compile musl static archive → `/disk/lib/libc.a` + headers
- [x] musl hello binary confirmed working: arch_prctl + set_tid_address + exit_group dispatched correctly

## Phase 8d: X11 Server Integration ✅
**Goal**: Wire in-kernel Xastryx server into the desktop loop so X11 clients can connect.

- [x] `main.rs`: `x11::init()` at boot (Phase 10g, non-test mode only)
- [x] `gui/desktop.rs`: `x11::poll()` each tick
- [ ] Test: minimal Xlib client connecting to `:0` (next milestone)

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
7. **Three environment subsystems**: Aether (native, ptr+len ABI), Linux (translation layer, POSIX/glibc compat), Win32/WoW (NT API translation, PE binaries). All built on the Aether kernel executive.
8. **NT-inspired executive**: Object Manager, Handle Tables, ALPC, IRPs, Dispatcher Objects, Access Tokens, IRQL/DPC/APC — see `.ai/decisions/001-nt-inspired-architecture.md`.
