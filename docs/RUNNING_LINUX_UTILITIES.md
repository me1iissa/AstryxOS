# Running Linux utilities on AstryxOS

A user-facing guide to staging and booting AstryxOS with the various Linux
binary-compat demos enabled, post the FAT32 → ext2 substrate migration
(2026-05-24, PRs #455-#460).

## What works today

After one boot you can have a fully populated Linux userspace on the data
disk and exercise these from the kernel-side demo runners:

| Pivot | What it runs | Feature flag |
|---|---|---|
| **PIVOT-B** | busybox-static (400+ applets: ls, cat, sh, echo, du, wget...) | `busybox-test` |
| **PIVOT-B/2** | `wget http://10.0.2.2:8888/` against host SLIRP | `wget-test` |
| **PIVOT-C** | busybox httpd serving from `/disk/var/www/` | `httpd-test` |
| **PIVOT-D** | dropbear sshd (port 2222) | `sshd-test` |
| **PIVOT-E** | curl + jq + tar + nano + vim + htop + tmux + git | `pivot-e-test`, `pivot-e-tui-test`, `pivot-e-git-test` |
| **TLS** | openssl s_client end-to-end TLS handshake | `tls-test` |
| **Oracle** | Glibc-linked tokio + libssl agent (first-boot validation) | `oracle-test` or `oracle-daemon-test` |
| **xeyes** | X11 hello-world (Alpine's xeyes musl PIE) against Xastryx | `xeyes-test` |
| **Firefox** | Headless Firefox 132 + libxul (work in progress) | `firefox-test` |

Each is a single cargo feature; they're mutually exclusive at the
`main.rs` cfg-gate level. Pick one per build.

## Prerequisites (host)

Ubuntu 24.04 LTS works out of the box. You need:

```bash
sudo apt install qemu-system-x86 ovmf e2fsprogs
# (KVM strongly recommended — much faster than TCG)
ls /dev/kvm                 # should exist; add yourself to `kvm` group if not
```

Rust nightly is pinned in `rust-toolchain.toml`; `rustup` picks it up
automatically on first `cargo` invocation.

## One-time setup

```bash
cd /path/to/AstryxOS

# 1. Build the Alpine rootfs cache (used by all install-*.sh scripts).
#    First run downloads ~150 MB of Alpine packages; subsequent runs
#    are incremental.
bash scripts/install-firefox-musl.sh   # sets up ~/.cache/astryxos-tls/rootfs/
```

That bootstrap is shared by every other install script.

## Staging payload for a given pivot

For each pivot you want to try, run its install script (idempotent —
re-running just refreshes):

```bash
bash scripts/install-busybox-cli.sh        # PIVOT-B
bash scripts/install-pivot-e.sh            # curl + jq + tar (Tier B)
bash scripts/install-pivot-e-tui.sh        # nano + vim + htop + tmux (Tier C)
bash scripts/install-pivot-e-git.sh        # git + helpers (Tier D)
bash scripts/install-tls-stack.sh          # libssl + ca-certificates
bash scripts/install-sshd.sh               # dropbear
bash scripts/install-oracle.sh             # oracle binary (requires ORACLE_BIN env)
bash scripts/install-xeyes.sh              # xeyes + libxcb
```

These stage into `build/disk/` — a plain Unix directory tree.

## Build the data disk image (ext2)

After staging, snap the tree into an ext2 image:

```bash
bash scripts/create-data-disk.sh --force
```

This formats `build/data.img` as ext2 and populates it from
`build/disk/` in one unprivileged step (`mke2fs -d`, no root needed).
Symlinks, POSIX permissions, and hardlinks all survive the staging.

## Boot and run

```bash
# Build + start a session with the feature flag for your chosen pivot:
python3 scripts/qemu-harness.py start --features "pivot-e-tui-test"

# (returns a session id, e.g. "abc123")

# Wait for the demo to complete (regex matches a banner line):
python3 scripts/qemu-harness.py wait abc123 'PIVOT-E-TUI.*PASS' --ms 60000

# Or just tail the live serial log:
python3 scripts/qemu-harness.py tail abc123

# Stop when done:
python3 scripts/qemu-harness.py stop abc123
```

The harness writes everything to `~/.astryx-harness/<sid>.serial.log`
plus a structured event stream at `~/.astryx-harness/<sid>.events.jsonl`.

## What success looks like

Each pivot emits its own banner pattern; grep for `PASS`:

```
[PIVOT-B]      busybox basic 5/5 PASS
[PIVOT-E]      curl + jq + tar 3/3 PASS
[PIVOT-E-TUI]  nano + vim + htop + tmux 4/4 PASS
[PIVOT-E-GIT]  git init + add + commit + log + cat-file 6/6 PASS
[TLS]          openssl s_client handshake PASS-SUBSTRATE
[ORACLE]       10 heartbeats to host stub Conflux in 180s soak
[XEYES]        MapWindow reached
```

If a pivot fails, the serial log will show the exact syscall / faulty
path. Most failures with PIVOT-B-E are staging gaps (missing library,
wrong DT_NEEDED) rather than kernel bugs.

## Trying it yourself — quick path

The fastest "is this thing on?" smoke test:

```bash
bash scripts/install-busybox-cli.sh
bash scripts/create-data-disk.sh --force
SID=$(python3 scripts/qemu-harness.py start --features busybox-test \
     --json | jq -r .sid)
python3 scripts/qemu-harness.py wait $SID 'PIVOT-B.*PASS' --ms 60000
python3 scripts/qemu-harness.py stop $SID
```

Should print PASS within ~30 seconds (KVM) or ~2-3 minutes (TCG fallback).

## Things to know

- **Boot disk is FAT32 (ESP, UEFI requires it). Data disk is ext2.** The
  switch happened in PRs #455-#460; the kernel's `init_disks()` walker
  tries ext2 on any MBR partition tagged `0x83` (Linux native).
- **Symlinks work natively.** Older docs may reference FAT32-alias
  workarounds (`cp git-remote-http git-remote-https`) — those are gone.
- **The harness is the only sanctioned test entry point.** The various
  shell wrappers in `scripts/` (`run-test.sh`, `run-firefox-test.sh`,
  etc.) discard structured output; prefer `qemu-harness.py`.
- **Networking** is QEMU SLIRP NAT. Host is reachable at `10.0.2.2`;
  DNS at `10.0.2.3` (default). Override with
  `ASTRYXOS_NAMESERVER=8.8.8.8 bash scripts/create-data-disk.sh --force`.

## Where to look next

- `kernel/Cargo.toml` — full list of demo feature flags with comments
- `scripts/qemu-harness.py --help` — every subcommand
- `docs/EXT2_DATA_DISK_AUDIT_2026-05-24.md` — ext2 driver state
- `docs/EXT2_STAGING_MIGRATION_PLAN_2026-05-24.md` — how the swap landed
- `docs/DEVELOPMENT_PLAN.md` — overall project structure
