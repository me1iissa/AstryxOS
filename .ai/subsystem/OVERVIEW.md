# AstryxOS — Subsystem Architecture Overview

> Last updated: 2026-03-05

## 1. Vision

AstryxOS provides **three environment subsystems** that run side-by-side on a single
kernel (Aether). This mirrors — and improves upon — the NT environment-subsystem model:

| Subsystem | Role | Binary ABI | Syscall ABI |
|-----------|------|------------|-------------|
| **Aether** | Primary / Native | AstryxOS ELF64 | Aether syscall numbers |
| **Linux** | POSIX compatibility | Linux ELF64 (musl / glibc) | Linux x86_64 ABI (`syscall`, numbers 0–547) |
| **Win32/WoW** | Windows compatibility | PE32+/PE32 (future) | NT system calls (Nt*/Zw*) |

The key design principle: **Aether is the canonical subsystem**. Linux and Win32 are
translation / compatibility layers that map foreign ABIs onto Aether kernel primitives.
This avoids duplicated kernel code — all three subsystems share the same scheduler,
memory manager, VFS, object manager, and device drivers.

## 2. Architecture Diagram

```
┌──────────────────────────────────────────────────────────┐
│  User Space                                              │
│                                                          │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Aether   │  │ Linux ELF64  │  │ Win32 PE32+       │  │
│  │ binaries │  │ (musl/glibc) │  │ (PE loader, WoW)  │  │
│  │ (libsys) │  │              │  │                    │  │
│  └────┬─────┘  └──────┬───────┘  └─────────┬─────────┘  │
│       │ SYSCALL        │ SYSCALL            │ INT 0x2E   │
│       │ (Aether #s)    │ (Linux #s)         │ (NT #s)    │
├───────┼────────────────┼────────────────────┼────────────┤
│  Kernel (Ring 0)       │                    │            │
│       │                │                    │            │
│       ▼                ▼                    ▼            │
│  ┌─────────┐   ┌──────────────┐   ┌────────────────┐    │
│  │ Aether  │   │ Linux Compat │   │ Win32/NT Compat│    │
│  │ Syscall │   │ Layer        │   │ Layer          │    │
│  │ Dispatch│   │ (translate → │   │ (translate →   │    │
│  │         │   │  Aether)     │   │  Aether)       │    │
│  └────┬────┘   └──────┬───────┘   └───────┬────────┘    │
│       │               │                   │              │
│       └───────────────┼───────────────────┘              │
│                       ▼                                  │
│               ┌───────────────┐                          │
│               │ Aether Kernel │                          │
│               │ (exec layer)  │                          │
│               ├───────────────┤                          │
│               │ MM │ VFS │ OB │ IO │ Sched │ Net │ IPC  │
│               └───────────────┘                          │
│               ┌───────────────┐                          │
│               │     HAL       │                          │
│               └───────────────┘                          │
└──────────────────────────────────────────────────────────┘
```

## 3. Current State (as of session 2026-03-05)

### What exists today

| Component | Status | Location |
|-----------|--------|----------|
| Aether syscall dispatch (50 native calls) | ✅ Working | `kernel/src/syscall/mod.rs` — `dispatch()` |
| Linux syscall translation (~90 calls mapped) | ✅ Partial | `kernel/src/syscall/mod.rs` — `dispatch_linux()` |
| `linux_abi` flag on Process | ✅ Working | `kernel/src/proc/mod.rs` — detects Linux ELFs |
| SubsystemType enum (Native/Posix/Win32) | ✅ Defined | `kernel/src/win32/mod.rs` |
| Win32Environment + CSRSS framework | ✅ Skeleton | `kernel/src/win32/mod.rs` |
| ALPC messaging (NT IPC) | ✅ Working | `kernel/src/lpc/mod.rs` |
| Object Manager (NT namespace) | ✅ Working | `kernel/src/ob/` |
| Handle Table per process | ✅ Working | `kernel/src/ob/handle.rs` |
| GDI primitives | ✅ Skeleton | `kernel/src/gdi/` |
| Window Manager | ✅ Working | `kernel/src/wm/` |
| GUI compositor + desktop | ✅ Working | `kernel/src/gui/` |

### What needs to change

1. **Rename `SubsystemType::Posix` → `SubsystemType::Aether`** — Aether is the native
   personality, not a POSIX clone. Linux compat provides POSIX.

2. **Add `SubsystemType::Linux`** — Separate from Aether; processes using Linux ABI
   numbers should be tagged `Linux`, not `Posix`.

3. **Move Linux dispatch out of `syscall/mod.rs`** — Create `kernel/src/subsys/linux/`
   as a proper subsystem module.

4. **Create `kernel/src/subsys/` directory** with:
   - `mod.rs` — SubsystemType, SubsystemContext, registry
   - `aether/` — Aether-native syscall dispatch (current `dispatch()`)
   - `linux/` — Linux compat layer (current `dispatch_linux()`)
   - `win32/` — Win32/NT compat layer (migrate from `kernel/src/win32/`)

5. **Unify the subsystem on the Process** — Use `SubsystemType` + `SubsystemContext`
   to replace both `linux_abi: bool` and `subsystem: SubsystemType`.

## 4. Subsystem Identification

### How processes get tagged

| Scenario | Subsystem | Detection |
|----------|-----------|-----------|
| Kernel-spawned Ascension/Orbit | Aether | Hardcoded at creation |
| AstryxOS ELF (links `libsys`) | Aether | Default; uses Aether syscall numbers |
| musl/glibc-linked ELF | Linux | ELF `.interp = /lib/ld-musl-x86_64.so.1` or presence of Linux-specific ELF notes |
| Static musl ELF | Linux | `PT_INTERP` absent + auxiliary vector analysis / explicit flag |
| PE32+ / PE32 executable | Win32 | PE magic (`MZ` + `PE\0\0`), loaded by NT PE loader |
| 16-bit DOS/Win16 | WoW (future) | MZ without PE signature |

### ELF subsystem detection heuristic

```
if file starts with 0x7F "ELF":
    if has PT_INTERP pointing to musl/glibc → Linux
    if has .note.GNU.property or .note.gnu.build → Linux
    if has .note.AstryxOS → Aether
    else → check for Linux-specific sections → Linux, else Aether
if file starts with "MZ":
    if has PE signature at e_lfanew → Win32
    else → DOS/WoW (future)
```

## 5. Syscall Entry Points

| Entry | Vector/Instruction | Used By |
|-------|-------------------|---------|
| `SYSCALL` (MSR-based) | IA32_LSTAR → `syscall_entry` | Aether + Linux |
| `INT 0x80` | IDT vector 128 → `int80_handler` | Legacy / fallback |
| `INT 0x2E` (future) | IDT vector 46 → `nt_syscall_handler` | Win32 |

The `syscall_entry` stub reads RAX (syscall number) and dispatches based on the
process's `SubsystemType`:
- **Aether** → `aether::dispatch(num, ...)`
- **Linux** → `linux::dispatch(num, ...)`
- **Win32** → `win32::dispatch(num, ...)` (INT 0x2E path, or SYSCALL if using ntdll-style fast syscalls)

## 6. References

- ReactOS subsystems: `reactos/subsystems/` — `csr/`, `mvdm/`, `win/`
- ReactOS win32ss: `reactos/win32ss/` — `gdi/`, `user/`, `drivers/`
- Linux syscall table: `linux/arch/x86/entry/syscalls/syscall_64.tbl` (385 native x86_64)
