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

## Wave 1 — LANDED (2026-04-20/21)

All P0/P1 punch-list items from section 6 of the review, plus two P2s:

| Task | Priority | Branch | Status |
|---|---|---|---|
| `fix/bootloader-friendly-errors` | P0 | merged `578ef4c` | structured LoadError with 7 failure modes + UEFI halt |
| `fix/execve-vmspace-leak` | P0 | merged `fbdca79` | 17-page leak vs 24 tolerance across 3 exec iters |
| Win32 PE test gated | P0 | `38554f7` | unblocks headless runner |
| `feat/procfs-vfs-mount` | P1 | merged `55d615c` | cpuinfo/meminfo/uptime/version + self/maps/status/cmdline |
| `feat/virtio-net-functional` | P1 | merged `2935c3b` | PCI probe + virtqueue TX/RX; e1000 kept as fallback |
| `feat/inotify-real-events` | P1 | merged `4f05ad4` | CREATE/DELETE/MODIFY/MOVE from VFS hooks |
| `fix/inotify-modify-fd-readable` | P1 | merged `f972848` | MODIFY marks fd readable + wakes poll/epoll |
| `feat/oom-killer` | P2 | merged `1c437b7` | largest-RSS scoring, init/kernel protected |
| `feat/wm-gdi-title-text` | P2 | merged `a5057a5` | GDI text engine for title bars |
| `feat/heap-guard-pages` | P2 | merged `f2f0495` | PMM-reserved physical frames + not-present PTEs |
| watchdog `+rdtscp` fix | Tooling | `22abefa` | scripts/watch-test.py now matches run-test.sh CPU flags |

Result: **101/107 tests passing** (up from 95/95 baseline; 6 remaining failures are all infrastructure-dependent, need `build-musl.sh`, `build-tcc.sh`, or a dynamic-linker interp).

---

## Wave 2 — in flight (parallel worktrees)

| # | Task | Priority | Scope |
|---|---|---|---|
| 1 | `feat/driver-stop-sweep` | **P1** | Wire `po/shutdown.rs` to call every driver's `stop()` in order. |
| 2 | `feat/aslr-pe-elf` | **P2** | Randomise base for ET_DYN ELF + PE32+ DYNAMIC_BASE images. |
| 3 | `feat/xhci-device-enumeration` | **P2** | Real PCI probe + MMIO decode + root-hub port count (no endpoint setup yet). |

All three agents instructed to use `python3 scripts/watch-test.py --idle-timeout 45 --hard-timeout 300` as the canonical test command so hangs abort in 45 s.

---

## Wave 3 — queued

| # | Task | Priority | Notes |
|---|---|---|---|
| 4 | `refactor/syscall-split` | **P1** | Splits 7175-line `syscall/mod.rs` into `subsys/linux/syscall.rs` + `subsys/aether/syscall.rs`. Big refactor — sequential, not parallel. |
| 5 | `feat/mount-syscall-tmpfs` | **P2** | Wire `sys_mount` + real tmpfs at `/tmp`. Touches syscall/mod.rs so scheduled after split. |
| 6 | `feat/ac97-device-file` | **P2** | Expose AC97 at `/dev/dsp`. Touches `vfs/mod.rs` + `drivers/ac97.rs`. |
| 7 | `infra/musl-tcc-rebuild` | **Infrastructure** | Run `build-musl.sh` + `build-tcc.sh` + regenerate `data.img` so 6 disk-dependent tests move from FAIL to PASS. |

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
