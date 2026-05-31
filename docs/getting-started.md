---
title: Getting Started
nav_order: 3
---

# Getting Started

This guide takes a fresh checkout to a building kernel and a passing test run by
the shortest path. It is tested on **Ubuntu 22.04 LTS** and **WSL2 (Ubuntu
22.04)**; other recent Debian-based distributions should work with minor
package-name changes.

{: .note }
For interactive kernel debugging (GDB autopsy, the in-kernel `kdb`, the Firefox
bring-up harness), continue to [Contributing & Dev Tooling](dev-tooling.md)
after your first passing test run.

---

## 1. Prerequisites

### System packages

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    musl-tools \
    mtools \
    qemu-system-x86 \
    ovmf \
    git \
    curl \
    python3
```

- **`musl-tools`** provides `musl-gcc`, used to build the musl libc that ships
  on the data disk.
- **`mtools`** (`mformat`, `mcopy`) is used by `create-data-disk.sh` to populate
  the FAT32 image.
- **`ovmf`** installs UEFI firmware under `/usr/share/OVMF/`. The build/test
  tooling expects `OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd` there. The package is
  `ovmf` on Ubuntu and `edk2-ovmf` on Fedora/Arch.

Verify the firmware is present:

```bash
ls /usr/share/OVMF/OVMF_CODE_4M.fd
```

If it is missing, see [OVMF path variations](#ovmf-path-variations) below.

### KVM (optional, recommended)

KVM cuts test wall-clock time dramatically (roughly 90 s → 15 s) and the
harness reaches deeper into long-running boots with it. The harness and
watchdog detect `/dev/kvm` automatically and enable it when present.

```bash
ls -la /dev/kvm
# If permission is denied:
sudo usermod -aG kvm "$USER"
# then log out/in, or: newgrp kvm
```

### Rust nightly

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

The repository pins the exact nightly in `rust-toolchain.toml`; cargo downloads
and uses the correct toolchain automatically. The kernel compiles the Rust
standard library from source via `-Zbuild-std`, which is why `rust-src` is
required.

---

## 2. Clone and build

```bash
git clone <repo-url> AstryxOS
cd AstryxOS
./build.sh release
```

A successful build produces:

```
build/esp/EFI/BOOT/BOOTX64.EFI    — UEFI bootloader
build/esp/EFI/astryx/kernel.bin   — flat kernel binary
```

The first build takes 2–4 minutes (it compiles `std` from source). Incremental
builds are much faster.

---

## 3. Create the data disk

The data disk is a FAT32 image holding the musl/glibc dynamic linker, shared
libraries, and `/etc` seed files. It is required for any test that exercises the
filesystem, the dynamic linker, or glibc/musl binary paths.

```bash
bash scripts/create-data-disk.sh
```

This produces `build/data.img`. If you also want the musl libc, the TCC
compiler, and glibc on the disk (for the disk-dependent test subset), run:

```bash
bash scripts/build-musl.sh
bash scripts/build-tcc.sh
bash scripts/install-glibc.sh
```

These are optional for a basic test run.

---

## 4. Run the test suite

The kernel ships a headless integration test runner (`kernel/src/test_runner.rs`)
covering the memory manager, scheduler, VFS, IPC, networking, the syscall ABIs,
and more.

```bash
python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300
```

The watchdog rebuilds the kernel in test mode, launches QEMU headless, streams
the annotated serial log, and exits on a pass/fail result or a timeout. A
passing run ends with output like:

```
[PASS] 139/140 tests passed
[WATCHDOG] QEMU exited cleanly (code 1 = pass)
```

To iterate without rebuilding:

```bash
python3 scripts/watch-test.py --no-build --idle-timeout 60 --hard-timeout 300
```

{: .note }
`watch-test.py` is the right tool for the **test suite**. For interactive
debugging and the Firefox bring-up, use `scripts/qemu-harness.py` instead — see
[Contributing & Dev Tooling](dev-tooling.md).

---

## 5. Boot it interactively

To boot a normal (non-test) kernel and drive it through the structured harness:

```bash
# start a session (prints JSON with the session id "sid")
python3 scripts/qemu-harness.py start

# wait for a boot marker, then read recent serial output
python3 scripts/qemu-harness.py wait <sid> "kernel ready" --ms 15000
python3 scripts/qemu-harness.py tail <sid>

# tear it down
python3 scripts/qemu-harness.py stop <sid>
```

To run the **upstream Firefox bring-up** (once the data disk is staged with the
Firefox payload), boot with the `firefox-test` feature and watch it advance the
gate ladder:

```bash
python3 scripts/qemu-harness.py start --features firefox-test
python3 scripts/qemu-harness.py ff-progress <sid>   # reports the deepest gate reached
python3 scripts/qemu-harness.py stop <sid>
```

See [Running Upstream Binaries](running-upstream-binaries.md) for what each gate
means and the honest current state of the Firefox screenshot pipeline.

---

## Common problems and fixes

### OVMF path variations

The tooling expects firmware at `/usr/share/OVMF/OVMF_CODE_4M.fd`. If your
distribution puts it elsewhere, the simplest fix is a symlink:

```bash
# Fedora / Arch (edk2-ovmf)
sudo ln -s /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd
sudo ln -s /usr/share/edk2/ovmf/OVMF_VARS.fd /usr/share/OVMF/OVMF_VARS_4M.fd
```

### `mtools` not found

`create-data-disk.sh` calls `mformat`/`mcopy` from the `mtools` package:

```bash
sudo apt-get install mtools    # Debian/Ubuntu
sudo dnf install mtools        # Fedora
```

### KVM permission denied

```bash
sudo usermod -aG kvm "$USER"
# then: newgrp kvm   (or log out/in)
```

### Build fails with `llvm-objcopy not found`

The build script converts the kernel ELF to a flat binary with `llvm-objcopy`
from the Rust sysroot, falling back to the system copy. If neither is present:

```bash
sudo apt-get install llvm
```

### `cargo` uses the wrong toolchain

The nightly date is pinned in `rust-toolchain.toml`. If cargo reports a missing
component:

```bash
rustup update nightly
rustup component add rust-src --toolchain nightly
```

### QEMU exits immediately

Most common causes: a missing `build/data.img` (run
`scripts/create-data-disk.sh`), missing OVMF firmware (see above), or an
unreliable nested-KVM setup under WSL2. The fuller troubleshooting list lives in
[docs/QUICKSTART.md](QUICKSTART.md).

---

## See also

- [Architecture](architecture.md) — how the kernel is structured.
- [Running Upstream Binaries](running-upstream-binaries.md) — the multi-ABI
  model and the Firefox bring-up.
- [Contributing & Dev Tooling](dev-tooling.md) — the harness, GDB autopsy,
  `kdb`, and the contribution workflow.
