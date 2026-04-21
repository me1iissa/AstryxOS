# AstryxOS Development Plan

**Last updated:** 2026-04-20
**Target:** 1.0-RC1 — "Firefox boots to a rendered page inside AstryxOS."

This document is the operational companion to `SOURCE_REVIEW_2026-04-20.md`.
The review is the *diagnosis*; this is the *treatment plan*.

---

## Current state snapshot

- **~76.4 KLOC** kernel + tooling across 152 Rust files.
- **95/95 headless tests passing** per `.ai/PROGRESS.md`.
- **Dual ABI:** 181 Linux syscalls dispatched; 50 native Aether syscalls.
- **Firefox milestone:** content process has reached 56K+ syscalls, completes
  `vfork` → `execve`, but does not yet render a page end-to-end.
- **Active blockers** (per source review §6):
  - P0: `execve` leaks VmSpace pages; bootloader panics on missing kernel.
  - P1: virtio-net TX/RX stubbed; `/proc` not VFS-mounted; inotify silent;
    `syscall/mod.rs` is a 7175-line monolith; no driver stop sweep on shutdown.
  - P2: ASLR, font-rendered window titles, OOM killer, heap guard pages, mount
    syscall, swap, real xHCI, AC97 device file, FS journaling, sleep/hibernate.

---

## Wave 1 — in flight (parallel worktrees)

Four independent kernel engineers are working right now on bounded tasks that
do not share files. Each will come back with a feature branch to merge.

| # | Task | Priority | Scope |
|---|---|---|---|
| 1 | `fix/execve-vmspace-leak` | **P0** | Reclaim old VmSpace pages on `execve`. Regression test asserts stable PMM free-page count across repeated fork→execve. |
| 2 | `feat/procfs-vfs-mount` | **P1** | Plug `procfs` into the VFS at `/proc` with `cpuinfo`, `meminfo`, `uptime`, `version`, `self/maps`, `self/status`, `self/cmdline`. Unlocks glibc/Firefox checks. |
| 3 | `feat/virtio-net-functional` | **P1** | PCI-probed virtio-net driver with virtqueue TX/RX and IRQ handling, mirroring the `virtio_blk` pattern. e1000 kept as fallback. |
| 4 | `feat/inotify-real-events` | **P1** | Real event delivery from VFS hooks (CREATE/DELETE/MODIFY/MOVE), bounded event queues, poll/epoll integration. |

Expected merge order: 1 → 2 → 3 → 4. Build + headless test between merges.

---

## Wave 2 — queued after Wave 1 merges

These were held back from Wave 1 because they would conflict with the in-flight
agents (same files).

| # | Task | Priority | Why held |
|---|---|---|---|
| 5 | `fix/bootloader-friendly-errors` | **P0** | Independent of kernel Waves; parallelisable but trivial — held for batch. |
| 6 | `refactor/syscall-split` | **P1** | Splits the 7175-line `syscall/mod.rs` into `subsys/linux/syscall.rs` + `subsys/aether/syscall.rs` per the documented Phase 0.2 plan. Conflicts with Wave 1 agent 1 (execve) and agent 4 (inotify). Do after both merge. |
| 7 | `feat/driver-stop-sweep` | **P1** | Wire `po/shutdown.rs` to call every registered driver's `stop()`. Touches many files; safer in isolation. |

---

## Wave 3 — P2 hardening (independent, can parallelise)

Once Waves 1–2 are merged and stable, the following are good parallel-agent
candidates. Each is independently useful; none blocks Firefox rendering on
its own, but together they lift AstryxOS from "Firefox runs" to "Firefox is
robust."

1. **ASLR in the PE/ELF loaders** (`proc/pe.rs`, `proc/elf.rs`) — randomise
   the base for PIE / PE32+ / interpreter.
2. **Heap guard pages** (`mm/heap.rs`) — detect kernel heap overflow at the
   page-fault boundary instead of corrupting neighbouring allocations.
3. **OOM killer** (`mm/oom.rs`, new) — on PMM exhaustion, pick the largest-RSS
   non-critical process and send SIGKILL instead of panicking.
4. **Real `mount` syscall** — wire `sys_mount` into the VFS so userspace can
   mount filesystems at runtime (useful for tmpfs, devpts, debugfs).
5. **Font-rendered window titles** (`wm/decorator.rs:123`) — switch from
   bitmap to GDI `TextOut`.
6. **Mount syscall + tmpfs** — make `/tmp` real rather than bolted onto ramfs.
7. **AC97 as a device file** (`drivers/ac97.rs`, `vfs/mod.rs`) — expose at
   `/dev/dsp` or similar so userspace can produce audio.
8. **Real xHCI device enumeration** (`drivers/xhci.rs`) — currently a stub.
   Priority driven by USB HID / mass-storage need.

---

## Wave 4 — post-RC1 stretch

1. Swap / page eviction for memory-pressure response.
2. Filesystem journaling (ext4 / NTFS read-write).
3. Sleep / hibernate in Po.
4. KPTI (Meltdown mitigation). Requires PML4 layout rework.
5. AArch64 port. HAL is already structured for this.
6. NUMA awareness in scheduler + PMM.

---

## Process rules

1. **One change per branch.** No drive-by refactors during a fix.
2. **Headless test suite must pass** before merging any branch.
3. **New feature code ships with a regression test** in `test_runner.rs`.
4. **Commits land on `master`.** GitLab carries the original SHAs; GitHub
   carries the rewritten-author SHAs. Public pushes go via the mirror workflow
   (document the exact command in `scripts/` when we settle the flow).
5. **No leaked-source references** in comments or docs. ReactOS and Linux
   references are fine; proprietary Windows source trees are not.
6. **Every subsystem modification updates `.ai/PROGRESS.md`** with a dated
   entry explaining the change's motivation.

---

## Stretch Firefox-port follow-ups

These are in `docs/FIREFOX_PORT_ROADMAP.md` but worth calling out here:

- Full dynamic-linker interpreter path (`ld-musl-x86_64.so.1` as PT_INTERP).
- NSS / NSPR port.
- WebRender → framebuffer fast-path.
- Clipboard + DnD + printing polish.

These are all **post-RC1** by design. RC1 is "Firefox renders"; polish
follows.
