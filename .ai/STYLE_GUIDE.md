# AstryxOS — AI Style Guidelines

## Project Identity
- **OS Name**: AstryxOS
- **Kernel Codename**: Aether (v1)
- **Scheduler**: CoreSched
- **Shell**: Orbit
- **Init System**: Ascension
- **Language**: Rust (with minimal inline assembly for arch-specific code)
- **Target**: x86_64 UEFI systems
- **Testing**: QEMU with OVMF firmware

## Code Style
- Follow Rust 2021 edition conventions
- Use `#![no_std]` and `#![no_main]` for kernel code
- All unsafe blocks must have `// SAFETY:` comments explaining invariants
- Prefer Rust abstractions over raw pointers where performance allows
- Module names: snake_case
- Type names: PascalCase
- Constants: SCREAMING_SNAKE_CASE
- Keep functions under 50 lines where possible; split complex logic into helpers

## Architecture Conventions
- Kernel code lives in `kernel/` (the Aether core)
- Userspace code lives in `userspace/`
- Bootloader/UEFI code lives in `bootloader/`
- Shared types/ABIs live in `shared/`
- Architecture-specific code goes in `kernel/src/arch/x86_64/`
- Device drivers go in `kernel/src/drivers/`
- All syscalls defined in `shared/src/syscall.rs` with matching kernel handlers

## Naming Conventions for Subsystems
| Subsystem | Internal Name | Directory |
|-----------|--------------|-----------|
| Kernel | Aether | `kernel/` |
| Scheduler | CoreSched | `kernel/src/sched/` |
| Shell | Orbit | `userspace/orbit/` |
| Init | Ascension | `userspace/ascension/` |
| Bootloader | AstryxBoot | `bootloader/` |

## Commit Message Format
```
[subsystem] short description

Longer description if needed.
```
Example: `[aether] add IRQ handler registration`

## Documentation
- Every public function/type must have doc comments (`///`)
- Each subsystem directory must have a `README.md`
- Architecture decisions go in `.ai/decisions/`

## Build Output
- Always produce a bootable ISO or EFI binary
- Build artifacts go in `target/` (Rust default) and `build/` (ISO output)
- The ISO must be UEFI-bootable (no legacy BIOS support)

## Testing
- Unit tests in each module where applicable
- Integration tests via QEMU automated boot
- Use `cargo test` for host-side logic tests
