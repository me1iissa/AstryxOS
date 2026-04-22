# Quick-start guide

This guide gets a fresh checkout building and running tests in the shortest
path possible.

---

## Prerequisites

Tested on Ubuntu 22.04 LTS and WSL2 running Ubuntu 22.04. Other recent
Debian-based distributions should work.

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

- `musl-tools` provides `musl-gcc`, needed to build the musl libc for the
  data disk.
- `mtools` is needed by `create-data-disk.sh` to populate the FAT32 image.
- `ovmf` installs UEFI firmware at `/usr/share/OVMF/`. The watchdog expects
  `OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd` at that path. On some systems the
  package name is `ovmf` (Ubuntu) or `edk2-ovmf` (Fedora/Arch).

Verify OVMF:

```bash
ls /usr/share/OVMF/OVMF_CODE_4M.fd
```

If the file is absent, see the [OVMF path variations](#ovmf-path-variations)
section below.

### KVM access (optional but recommended)

KVM reduces test wall-clock time from ~90 s to ~15 s.

```bash
# Check that KVM is accessible
ls -la /dev/kvm
# If you get "permission denied":
sudo usermod -aG kvm "$USER"
# Then log out and back in, or run: newgrp kvm
```

The watchdog and harness detect `/dev/kvm` automatically and add `-enable-kvm`
when present.

### Rust nightly

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Follow the prompts, then reload PATH:
source "$HOME/.cargo/env"

# Install nightly and the required build-std components
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

The repository pins the exact nightly version in `rust-toolchain.toml`. Cargo
will download and use the correct toolchain automatically.

---

## First build

Clone the repository and run the build script:

```bash
git clone <repo-url> AstryxOS
cd AstryxOS
./build.sh release
```

A successful build ends with no errors and produces:

```
build/esp/EFI/BOOT/BOOTX64.EFI   — UEFI bootloader
build/esp/EFI/astryx/kernel.bin  — flat kernel binary
```

The build takes 2–4 minutes on first run (Rust compiles the standard library
from source via `-Zbuild-std`). Subsequent incremental builds are much faster.

---

## Create the data disk

The data disk is a 512 MiB FAT32 image that holds the musl/glibc dynamic
linker, shared libraries, and `/etc` seed files. It is required for tests that
exercise the filesystem, dynamic linker, and glibc binary paths.

```bash
bash scripts/create-data-disk.sh
```

This produces `build/data.img`. If you also need the musl libc and TCC
compiler on the disk (for additional test coverage), run:

```bash
bash scripts/build-musl.sh
bash scripts/build-tcc.sh
bash scripts/install-glibc.sh
```

These are optional for basic test runs but required for the disk-dependent
test subset.

---

## First test run

Run the full headless test suite:

```bash
python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300
```

The watchdog will:

1. Rebuild the kernel with `test-mode` enabled.
2. Launch QEMU headless (no display window).
3. Stream the serial log to your terminal with colour annotations.
4. Exit when the kernel reports a pass or fail result, or when a timeout fires.

A passing run ends with output similar to:

```
[PASS] 139/140 tests passed
[WATCHDOG] QEMU exited cleanly (code 1 = pass)
```

Exit code 0 means all tests passed. Any non-zero exit code is described in the
table at the top of `scripts/watch-test.py`.

To re-run without rebuilding (useful during rapid iteration):

```bash
python3 scripts/watch-test.py --no-build --idle-timeout 60 --hard-timeout 300
```

---

## First debug session

Start an interactive harness session with the GDB stub enabled:

```bash
python3 scripts/qemu-harness.py start --gdb-port 1234
```

The command prints a JSON line with the session ID:

```json
{"sid": "abc123def456", "pid": 98765, "serial_log": "...", "gdb_port": 1234}
```

Use the `sid` value in subsequent commands:

```bash
# Wait up to 15 s for the kernel to finish booting
python3 scripts/qemu-harness.py wait abc123def456 "kernel ready" --ms 15000

# Stream the last 2 KiB of serial output
python3 scripts/qemu-harness.py tail abc123def456

# Pause and read register state
python3 scripts/qemu-harness.py pause abc123def456
python3 scripts/qemu-harness.py regs abc123def456

# Tear down
python3 scripts/qemu-harness.py stop abc123def456
```

See [docs/HARNESS.md](HARNESS.md) for the complete subcommand reference.

---

## Common problems and fixes

### OVMF path variations

The watchdog expects firmware at `/usr/share/OVMF/OVMF_CODE_4M.fd`. If your
distribution places it elsewhere, the simplest fix is a symlink:

```bash
# Fedora / Arch (edk2-ovmf)
sudo ln -s /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd
sudo ln -s /usr/share/edk2/ovmf/OVMF_VARS.fd /usr/share/OVMF/OVMF_VARS_4M.fd
```

Alternatively, edit the path constants at the top of
`scripts/watch-test.py`:

```python
OVMF_CODE     = Path("/your/path/to/OVMF_CODE.fd")
OVMF_VARS_SRC = Path("/your/path/to/OVMF_VARS.fd")
```

### `mtools` not found

`create-data-disk.sh` calls `mformat` and `mcopy`, which are part of the
`mtools` package.

```bash
sudo apt-get install mtools    # Debian/Ubuntu
sudo dnf install mtools        # Fedora
```

### KVM permission denied

```
/dev/kvm: Permission denied
```

Add yourself to the `kvm` group and re-login:

```bash
sudo usermod -aG kvm "$USER"
# then: newgrp kvm  (or log out/in)
```

### Build fails with `llvm-objcopy not found`

The build script uses `llvm-objcopy` from the Rust sysroot to convert the
kernel ELF to a flat binary. If the Rust sysroot does not contain it, install
the LLVM tools:

```bash
sudo apt-get install llvm
```

The build script falls back to the system `llvm-objcopy` if the sysroot copy
is absent.

### `cargo` uses wrong toolchain version

The repository pins the nightly date in `rust-toolchain.toml`. If cargo
complains about a missing component, update rustup:

```bash
rustup update nightly
rustup component add rust-src --toolchain nightly
```

### QEMU exits immediately with code 4 (crash)

The watchdog exits with code 4 when QEMU exits unexpectedly. Common causes:

- Missing `build/data.img` — run `bash scripts/create-data-disk.sh`.
- Missing OVMF firmware — see above.
- KVM crash (WSL2 nested virtualization limitation) — the watchdog retries
  without KVM automatically only if `/dev/kvm` is absent. If KVM is present
  but unreliable, remove it:

```bash
sudo rm /dev/kvm   # temporary; restored on reboot
```
