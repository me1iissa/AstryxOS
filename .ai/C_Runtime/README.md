# AstryxOS — C Runtime Design

> Created: 2026-03-12
> Context: AstryxOS is NT-structured with three subsystem personalities (Aether, Win32, Linux)
> Goal: Support Win32 C runtime (MSVCRT + STL) and Linux C runtime (glibc / musl)

---

## The Core Insight

The most important thing to understand about C runtimes on NT-architecture systems:

> **The C runtime is NOT a kernel feature. It is a chain of userspace libraries sitting
> between application code and the kernel syscall interface.**

AstryxOS currently has NT service stubs *inside the kernel* (`nt/mod.rs`). That is wrong for
production use. The actual NT architecture places all of this in userspace:

```
App.exe → msvcrt.dll → kernel32.dll → ntdll.dll → INT 2E → kernel SSDT
App.elf → musl libc → SYSCALL → kernel Linux compat
App.elf → libaether → SYSCALL → kernel Aether native
```

The kernel just handles syscalls. Everything else lives in DLLs or shared libraries.

---

## Index

| File | Contents |
|------|----------|
| [01_architecture.md](01_architecture.md) | Three-personality model, layering diagram, NT vs Linux design |
| [02_win32_crt.md](02_win32_crt.md) | Win32 path: ntdll → kernel32 → msvcrt → STL |
| [03_linux_crt.md](03_linux_crt.md) | Linux path: musl (current), glibc, dynamic linking |
| [04_aether_crt.md](04_aether_crt.md) | Native Aether CRT: minimal Rust-C runtime |
| [05_startup_sequences.md](05_startup_sequences.md) | Process initialization for each personality |
| [06_action_plan.md](06_action_plan.md) | **What to build, in what order** |

---

## Current State (what exists)

| Component | Location | Status |
|-----------|----------|--------|
| NT service stubs | `kernel/src/nt/mod.rs` | ⚠️ In kernel (wrong place — should be userspace) |
| PE loader | `kernel/src/proc/pe.rs` | ✅ Complete — IAT patching, relocations |
| ELF loader | `kernel/src/proc/elf.rs` | ✅ Complete — PT_INTERP, PT_TLS, aux vectors |
| Subsystem routing | `kernel/src/subsys/mod.rs` | ✅ Complete — detects Linux/Win32/Aether |
| Linux errno | `kernel/src/subsys/linux/errno.rs` | ✅ Complete |
| Linux ~90 syscalls | `kernel/src/syscall/mod.rs` | ✅ Working (musl static confirmed) |
| Win32 SSDT table | `kernel/src/nt/mod.rs` | ⚠️ Defined but all stubs return 0 |
| Userspace ntdll.dll | — | ❌ Does not exist |
| Userspace kernel32.dll | — | ❌ Does not exist |
| Userspace msvcrt.dll | — | ❌ Does not exist |
| musl libc (static) | `build/disk/bin/hello` | ✅ Working since Session 23 |
| musl libc (dynamic) | — | ❌ No ld.so, .so loading not wired |
| glibc | — | ❌ Does not exist |
| STL (C++ runtime) | — | ❌ Does not exist |

---

## Reference Source Materials Available

| Source | Path | What to use it for |
|--------|------|---------------------|
| ReactOS msvcrt | `SupportingResources/reactos/dll/win32/msvcrt/` | Complete msvcrt reimplementation in C |
| ReactOS ntdll | `SupportingResources/reactos/dll/ntdll/` | ldr/, rtl/, dispatch/ |
| Linux kernel | `SupportingResources/linux/` | Syscall ABI, ELF aux vector conventions |
