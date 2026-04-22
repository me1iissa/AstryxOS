# AstryxOS Development Plan

**Last updated:** 2026-04-22
**Target:** 1.0-RC1 — "Firefox boots to a rendered page inside AstryxOS."

This document is the operational companion to `SOURCE_REVIEW_2026-04-20.md`.
The review is the *diagnosis*; this is the *treatment plan*.

---

## Current state snapshot

- **~83 KLOC** kernel + tooling across 170+ Rust files.
- **139/140 headless tests passing** (143 total; one Win32 PE test gated behind
  `win32-pe-test` feature flag).
- **Dual ABI:** 193 Linux syscalls dispatched; 50+ native Aether syscalls.
- **glibc milestone:** glibc-linked hello world runs end-to-end on the data disk
  (`ld-musl-x86_64.so.1` + glibc dynamic linker fully functional).
- **Firefox milestone:** content process has reached 56K+ syscalls, completes
  `vfork` → `execve`, but does not yet render a page end-to-end.
- **Active blockers** (post-Wave-8):
  - Firefox network I/O path not yet exercised end-to-end.
  - WebRender framebuffer fast-path not yet wired.
  - NSS/NSPR not yet ported.

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

## Wave 2 — LANDED

| # | Task | Priority | Branch | Status |
|---|---|---|---|---|
| 1 | Driver stop sweep | P1 | merged `b00fb91` | po::shutdown sweeps e1000/virtio_net/virtio_blk/ahci/ata/ac97/console/serial |
| 2 | ASLR for ET_DYN + PE DYNAMIC_BASE | P2 | merged `5b43bcb` | 28-bit entropy, page-granular; ET_EXEC deterministic |
| 3 | xHCI device enumeration | P2 | merged `f2e2765` | PCI probe + MMIO decode + root-hub port count |
| — | Brace-closure fix | — | `e6343eb` | Post-merge cleanup |

Result: **104/111 passing** (up from 101/107). +4 tests, +3 passing (+1 flaky network test introduced with driver-stop-sweep).

---

## Wave 3 — LANDED

| # | Task | Priority | Branch | Status |
|---|---|---|---|---|
| 1 | `feat/ac97-dev-dsp` | P2 | merged | AC97 at `/dev/dsp`; graceful ENODEV when absent |
| 2 | `feat/fat32-read-write` | P2 | merged | cluster allocator + create/write/truncate/unlink on FAT32 |

Result: **~111 tests passing**.

---

## Wave 4 — LANDED

| # | Task | Priority | Branch | Status |
|---|---|---|---|---|
| 1 | `refactor/syscall-split` | P1 | merged `d01bf9e` | split 7175-line `syscall/mod.rs` into `subsys/linux/` + `subsys/aether/` |
| 2 | `feat/mount-syscall-tmpfs` | P2 | merged `c733bc8` | `sys_mount` / `sys_umount` + real tmpfs at `/tmp` |

Result: **~113 tests passing**.

---

## Wave 5 — LANDED

| # | Task | Priority | Branch | Status |
|---|---|---|---|---|
| 1 | `infra/glibc-dynamic-linker` | P1 | merged `e6c8e3a` | `ld-musl-x86_64.so.1` + glibc libs + `/etc` seed on data disk |
| 2 | `test/glibc-hello-runs` | P1 | merged with above | oracle test: fork → exec glibc hello → check exit 0 |

Result: **glibc hello runs end-to-end**. ~120 tests passing.

---

## Wave 6 — LANDED

| # | Task | Priority | Branch | Status |
|---|---|---|---|---|
| 1 | `feat/procfs-auxv-environ-fd` | P1 | merged `07ff3d3` | `/proc/self/auxv`, `/proc/self/environ`, `/proc/<pid>/fd/` symlinks |
| 2 | `feat/glibc-critical-syscalls` | P1 | merged `41720e5` | statx, getrandom, mremap, set/get_robust_list, membarrier |
| 3 | `feat/elf-dt-relr-gnu-hash` | P1 | merged `62c8538` | ELF loader accepts DT_RELR packed relocations + DT_GNU_HASH |

Result: **~130 tests passing**.

---

## Wave 7 — LANDED

| # | Task | Priority | Branch | Status |
|---|---|---|---|---|
| 1 | `feat/qemu-harness-tier1` | Tooling | merged `67c2d1a` | agentic QEMU session manager — JSON protocol, session/log/events |
| 2 | `feat/qemu-harness-tier2` | Tooling | merged `26fae57` | GDB RSP stub client (regs/mem/sym/bp/step/cont/pause/resume) |

Result: full agentic debug harness available.

---

## Wave 8 — LANDED

| # | Task | Priority | Branch | Status |
|---|---|---|---|---|
| 1 | `feat/x11-extensions` | P2 | merged `a157034` | MIT-SHM, BIG-REQUESTS, XKB, XFIXES, SYNC, RENDER stubs |
| 2 | `test/x11-extension-audit` | P2 | merged `0e23c50` | 6 new tests verifying 5 pre-existing + RENDER extensions |
| 3 | `fix/tgkill-tgid` | P1 | merged `337fbbd` | tgkill uses tgid (arg1) not tid (arg2) for signal delivery |
| 4 | `fix/termios-struct-size` | P1 | merged `6dc5308` | Termios struct 36 bytes (not 60); fixes glibc stack-canary smash |

Result: **139/140 tests passing** (143 total, one Win32 PE test gated).

---

## Wave 9 — current priorities

| # | Task | Priority | Notes |
|---|---|---|---|
| 1 | Firefox network path | P0 | Exercise TCP connect through the virtio-net stack from Firefox content process |
| 2 | WebRender framebuffer | P1 | Wire WebRender software renderer output to kernel framebuffer |
| 3 | NSS/NSPR port | P1 | Needed for HTTPS; depends on DNS and TCP being stable |
| 4 | `feat/oom-kill-score-adj` | P2 | Extend OOM killer to honour `score_adj` via prctl |

---

## Post-RC1 stretch

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
