---
title: Home
nav_order: 1
---

# AstryxOS

{: .fs-9 }
A hybrid-kernel operating system, written from scratch in Rust, that runs
**upstream, unmodified binaries** from other operating systems.
{: .fs-6 .fw-300 }

[Get started](getting-started.md){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Architecture](architecture.md){: .btn .fs-5 .mb-4 .mb-md-0 }

---

AstryxOS is a UEFI-native x86-64 research operating system (kernel codename
*Aether*). It takes the NT subsystem model as its architectural inspiration: a
small executive at the centre, a Hardware Abstraction Layer beneath it, and
**personality subsystems** layered above that each present one operating
system's native Application Binary Interface (ABI).

The practical result, and the whole point of the project, is this:

> You take a binary that was built for another operating system. You do not
> touch it. It runs.

A glibc- or musl-linked Linux ELF makes Linux `syscall`s through the
`SYSCALL` instruction gate and gets Linux semantics back. A Windows PE32+ image
makes NT calls through the `INT 0x2E` gate and gets NT semantics back. Same
kernel, multiple faces — and the binaries are exactly the ones the upstream
toolchains shipped.

{: .note }
The headline proof point is **upstream musl-linked Firefox**, driven toward a
headless `--screenshot`. These docs are honest about where that stands: Firefox
boots through the dynamic linker, initialises the compositor, spawns content
processes, and is now running the headless screenshot pipeline — see
[Running Upstream Binaries](running-upstream-binaries.md) for the exact current
state. There is no finished PNG yet; we describe the real progress, gate by
gate, not a finished demo.

---

## Why this matters

Most "compatibility layers" cheat: they recompile the library, ship a patched
libc, or wrap the program in a shim that rewrites what it does. AstryxOS holds a
single hard invariant instead:

> **If an upstream binary misbehaves on AstryxOS, the bug is in AstryxOS — not
> in the binary.** The fix goes in the kernel or the ABI layer, never in the
> binary, never in the libc, never in a shim.

The justification is the philosophical core of the Firefox work: the *same*
musl + libxul Firefox runs for millions of people on real Linux. If it runs
there and stalls here, AstryxOS has diverged from the documented ABI somewhere —
a syscall returning the wrong errno, a wakeup that never fires, a page served
with the wrong contents. The job is to find that divergence and close it with a
real, generally-correct fix that any conformant binary benefits from.

---

## What works today

- **Upstream glibc- and musl-linked Linux ELF binaries run end-to-end** — the
  upstream dynamic linker (`ld-musl-x86_64.so.1` / `ld-linux-x86-64.so.2`) runs
  as the program interpreter, processing `PT_INTERP`, `PT_TLS`, `PT_GNU_RELRO`,
  and the relocation tables (including the compact `DT_RELR` form and
  `DT_GNU_HASH` lookup) in-kernel.
- **193+ Linux syscalls** dispatched, plus 50+ native Aether calls. See the
  [Linux syscall coverage table](LINUX_SYSCALL_COVERAGE.md).
- **A real userspace** of upstream Linux tools: BusyBox and its 400+ applets,
  `wget`/`curl`, an `httpd`, `dropbear` sshd, `git`, an OpenSSL TLS handshake,
  and X11 clients against the in-kernel X server. See
  [Running Linux utilities](RUNNING_LINUX_UTILITIES.md).
- **A full TCP/IP stack** — IPv4, IPv6, TCP (3-way handshake, FIN, retransmit,
  congestion control), UDP, ARP, ICMP, DNS, DHCP.
- **An in-kernel X11 server** with RENDER, MIT-SHM, XKB, XFIXES, SYNC, and
  BIG-REQUESTS extensions, a window manager, compositor, and desktop shell.
- **Multiple filesystems** — FAT32 read/write, ext2, NTFS read-only, procfs,
  tmpfs, ramfs.
- **A from-scratch UEFI bootloader** (AstryxBoot) and SMP x86-64 kernel: PMM,
  VMM, slab heap, ASLR, an SMP round-robin + priority scheduler, capabilities,
  rlimits, and a broad driver set (ATA/AHCI/virtio-blk, e1000/virtio-net, AC97,
  PS/2, xHCI, serial).

---

## The shape of the system

```
        upstream binaries                       upstream binaries
   (Linux ELF: glibc / musl)                 (Windows PE32+ images)
              │                                        │
       SYSCALL instruction                       INT 0x2E gate
              │                                        │
   ┌──────────▼───────────┐               ┌────────────▼───────────┐
   │  Linux personality   │               │   NT / Win32 person.   │
   │  (subsys/linux)      │               │   (nt/, subsys/win32)  │
   └──────────┬───────────┘               └────────────┬───────────┘
              └───────────────┬────────────────────────┘
                              ▼
              ┌──────────────────────────────┐
              │   Aether executive (shared)  │
              │  mm · sched · proc · vfs ·   │
              │  ipc · net · x11 · ke · ob   │
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │  HAL + drivers (x86-64 SMP)  │
              └──────────────────────────────┘
```

Read the [Architecture](architecture.md) page for the full executive / HAL /
personality model and the dual syscall entry surface.

---

## Where to go next

| If you want to… | Read |
|---|---|
| Understand the kernel design | [Architecture](architecture.md) |
| Understand the "run upstream binaries" model and the Firefox push | [Running Upstream Binaries](running-upstream-binaries.md) |
| Build it and run the test suite | [Getting Started](getting-started.md) |
| Debug the kernel or contribute | [Contributing & Dev Tooling](dev-tooling.md) |

---

## A note on how AstryxOS is built

AstryxOS is also an experiment in agentic software development: most of its
~83 KLOC across 170+ Rust source files was written by AI agents working in
parallel worktrees, with human review at merge time. Kernel changes land via
reviewed pull requests with green CI — never direct to `master`. See
[Contributing & Dev Tooling](dev-tooling.md).

---

## License

MIT. Copyright (c) 2026 Melissa and AstryxOS Contributors.
