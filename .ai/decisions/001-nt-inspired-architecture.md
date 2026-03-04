# AstryxOS — Architecture Decision Record: NT-Inspired Hybrid Monolithic

## Context
Inspired by the Windows NT architecture (see: https://en.wikipedia.org/wiki/Architecture_of_Windows_NT),
AstryxOS uses a **monolithic kernel** with **clean subsystem boundaries** similar to NT's executive layer.

## Decision
While the kernel runs entirely in Ring 0 (monolithic), it is organized into distinct executive
subsystems with well-defined interfaces, similar to NT's:

| NT Concept | AstryxOS Equivalent | Module |
|---|---|---|
| HAL (Hardware Abstraction Layer) | `hal` | `kernel/src/hal/` |
| Executive / Object Manager | Aether core | `kernel/src/` |
| Process Manager | `proc` | `kernel/src/proc/` |
| Memory Manager | `mm` | `kernel/src/mm/` |
| I/O Manager | `io` | `kernel/src/io/` |
| Scheduler | CoreSched | `kernel/src/sched/` |
| Win32 Subsystem | (future) POSIX Subsystem | `kernel/src/subsys/` |

## Rationale
- Monolithic for v1 performance and simplicity
- NT-style layering allows future refactoring toward a hybrid/microkernel
- HAL provides hardware abstraction for potential multi-arch support
- Clean interfaces between subsystems enable testability

## Boot Architecture
```
UEFI Firmware
    → AstryxBoot (UEFI app, loads kernel ELF)
        → Aether Kernel (freestanding x86_64 binary)
            → HAL init → GDT/IDT/IRQ
            → Memory Manager init → PMM/VMM/Heap
            → Process Manager init → CoreSched
            → Syscall interface online
            → Launch Ascension (PID 1)
                → Launch Orbit shell
```
