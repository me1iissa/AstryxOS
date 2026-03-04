#!/usr/bin/env bash
#
# Create a FAT32-formatted data disk image for AstryxOS.
#
# This generates a persistent data drive that QEMU attaches as a
# secondary SATA disk via the ICH9 AHCI controller (Q35 machine).
# The kernel's AHCI DMA driver reads it on port 1.
#
# Usage:
#   ./scripts/create-data-disk.sh           # Create default 64 MiB image
#   ./scripts/create-data-disk.sh 128       # Create 128 MiB image
#   ./scripts/create-data-disk.sh --force   # Recreate even if it exists
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DATA_IMG="${BUILD_DIR}/data.img"
SIZE_MB=64
FORCE=false

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        [0-9]*) SIZE_MB="$arg" ;;
    esac
done

# Skip if image exists and --force not given
if [ -f "${DATA_IMG}" ] && [ "$FORCE" = false ]; then
    echo "[DATA-DISK] ${DATA_IMG} already exists (use --force to recreate)"
    exit 0
fi

mkdir -p "${BUILD_DIR}"

echo "[DATA-DISK] Creating ${SIZE_MB} MiB FAT32 data disk..."

# Create empty image
dd if=/dev/zero of="${DATA_IMG}" bs=1M count="${SIZE_MB}" status=none

# Format as FAT32
if ! command -v mkfs.fat &>/dev/null; then
    echo "[DATA-DISK] ERROR: mkfs.fat not found. Install dosfstools:"
    echo "  sudo apt install dosfstools"
    exit 1
fi

mkfs.fat -F 32 -n "ASTRYXDATA" "${DATA_IMG}" >/dev/null

# Populate with initial files using mtools
if command -v mcopy &>/dev/null; then
    export MTOOLS_SKIP_CHECK=1

    # Create some initial directories and files
    mmd -i "${DATA_IMG}" "::home" 2>/dev/null || true
    mmd -i "${DATA_IMG}" "::docs" 2>/dev/null || true
    mmd -i "${DATA_IMG}" "::bin"  2>/dev/null || true

    # Create a welcome file
    echo "Welcome to AstryxOS persistent storage!" | mcopy -i "${DATA_IMG}" - "::welcome.txt"

    # Create a readme
    cat <<'EOF' | mcopy -i "${DATA_IMG}" - "::readme.txt"
AstryxOS Data Disk
==================
This is a FAT32-formatted persistent data drive.
Files written here survive reboots.

Directories:
  /home   - User home directories
  /docs   - Documentation
  /bin    - User binaries (ELF64)
EOF

    # Create a sample file in docs/
    echo "AstryxOS documentation placeholder." | mcopy -i "${DATA_IMG}" - "::docs/guide.txt"

    # Copy userspace binaries (if built)
    if [ -f "${BUILD_DIR}/hello" ]; then
        mcopy -i "${DATA_IMG}" "${BUILD_DIR}/hello" "::bin/hello"
        echo "[DATA-DISK] Copied hello binary to /bin/hello"
    fi

    echo "[DATA-DISK] Populated with initial files (mtools)"
else
    echo "[DATA-DISK] WARNING: mtools not found — disk created empty"
    echo "  Install mtools for pre-populated files: sudo apt install mtools"
fi

echo "[DATA-DISK] Created: ${DATA_IMG} (${SIZE_MB} MiB, FAT32)"
