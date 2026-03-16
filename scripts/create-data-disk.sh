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
SIZE_MB=512
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

    # Create /etc/ with standard system files (needed by glibc/NSS for Firefox)
    mmd -i "${DATA_IMG}" "::etc" 2>/dev/null || true
    printf 'astryx\n' | mcopy -i "${DATA_IMG}" - "::etc/hostname"
    printf '127.0.0.1 localhost\n::1 localhost\n127.0.1.1 astryx\n' | mcopy -i "${DATA_IMG}" - "::etc/hosts"
    printf 'nameserver 10.0.2.3\n' | mcopy -i "${DATA_IMG}" - "::etc/resolv.conf"
    printf 'hosts: files dns\n' | mcopy -i "${DATA_IMG}" - "::etc/nsswitch.conf"
    echo "[DATA-DISK] Created /etc/ (hostname, hosts, resolv.conf, nsswitch.conf)"

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

    # ── Copy userspace test binaries ─────────────────────────────────────────
    # Check build/ first, then userspace/ as fallback.
    # These are musl-linked ELF binaries built by scripts/build-musl.sh
    # or manually compiled in userspace/.
    USERSPACE="${ROOT_DIR}/userspace"
    TEST_BINS=(hello mmap_test dynamic_hello dynamic_hello_pie clone_thread_test socket_test)
    for bin in "${TEST_BINS[@]}"; do
        SRC=""
        if [ -f "${BUILD_DIR}/${bin}" ]; then
            SRC="${BUILD_DIR}/${bin}"
        elif [ -f "${USERSPACE}/${bin}" ]; then
            SRC="${USERSPACE}/${bin}"
        fi
        if [ -n "${SRC}" ]; then
            mcopy -o -i "${DATA_IMG}" "${SRC}" "::bin/${bin}"
            echo "[DATA-DISK] Copied ${bin} to /bin/${bin}"
        else
            echo "[DATA-DISK] WARNING: ${bin} not found (build/ or userspace/)"
        fi
    done

    # Create /lib for the musl dynamic linker (use our freshly built copy)
    mmd -i "${DATA_IMG}" "::lib" 2>/dev/null || true
    LD_MUSL="${BUILD_DIR}/disk/lib/ld-musl-x86_64.so.1"
    LIBC_SO="${BUILD_DIR}/disk/lib/libc.so"
    if [ -f "${LD_MUSL}" ]; then
        mcopy -o -i "${DATA_IMG}" "${LD_MUSL}" "::lib/ld-musl-x86_64.so.1"
        echo "[DATA-DISK] Copied ld-musl to /lib/ld-musl-x86_64.so.1"
    fi
    if [ -f "${LIBC_SO}" ]; then
        mcopy -o -i "${DATA_IMG}" "${LIBC_SO}" "::lib/libc.so"
        echo "[DATA-DISK] Copied libc.so to /lib/libc.so"
    fi

    # ── Dynamic linker + glibc (needed by Firefox and other glibc binaries) ──
    if [ -d "${BUILD_DIR}/disk/lib64" ]; then
        mmd -i "${DATA_IMG}" "::lib64" 2>/dev/null || true
        for f in "${BUILD_DIR}/disk/lib64/"*; do
            [ -f "${f}" ] && mcopy -i "${DATA_IMG}" "${f}" "::lib64/$(basename "${f}")"
        done
        echo "[DATA-DISK] Copied lib64/ (dynamic linker)"
    fi
    if [ -d "${BUILD_DIR}/disk/lib/x86_64-linux-gnu" ]; then
        mmd -i "${DATA_IMG}" "::lib/x86_64-linux-gnu" 2>/dev/null || true
        for f in "${BUILD_DIR}/disk/lib/x86_64-linux-gnu/"*; do
            [ -f "${f}" ] && mcopy -i "${DATA_IMG}" "${f}" "::lib/x86_64-linux-gnu/$(basename "${f}")"
        done
        echo "[DATA-DISK] Copied lib/x86_64-linux-gnu/ (glibc)"
    fi

    # Firefox binary and resources (built by scripts/build-firefox.sh)
    FIREFOX_BIN="${BUILD_DIR}/disk/bin/firefox"
    FIREFOX_LIB="${BUILD_DIR}/disk/lib/firefox"
    if [ -f "${FIREFOX_BIN}" ]; then
        mcopy -i "${DATA_IMG}" "${FIREFOX_BIN}" "::bin/firefox"
        echo "[DATA-DISK] Copied firefox binary to /bin/firefox"
    fi
    if [ -d "${FIREFOX_LIB}" ]; then
        mmd -i "${DATA_IMG}" "::lib/firefox" 2>/dev/null || true
        # Copy all files recursively (mtools mcopy -s for subdirs)
        mcopy -s -i "${DATA_IMG}" "${FIREFOX_LIB}/"* "::lib/firefox/" 2>/dev/null || \
        for f in "${FIREFOX_LIB}/"*; do
            [ -f "${f}" ] && mcopy -i "${DATA_IMG}" "${f}" "::lib/firefox/$(basename "${f}")"
        done
        echo "[DATA-DISK] Copied Firefox resources to /lib/firefox/"
    fi

    # ── TCC compiler + runtime (built by scripts/build-tcc.sh) ──────────────
    if [ -f "${BUILD_DIR}/disk/bin/tcc" ]; then
        mmd -i "${DATA_IMG}" "::lib/tcc"         2>/dev/null || true
        mmd -i "${DATA_IMG}" "::lib/tcc/include" 2>/dev/null || true
        mcopy -i "${DATA_IMG}" "${BUILD_DIR}/disk/bin/tcc" "::bin/tcc"
        echo "[DATA-DISK] Copied tcc binary to /bin/tcc"
        if [ -f "${BUILD_DIR}/disk/lib/tcc/libtcc1.a" ]; then
            mcopy -i "${DATA_IMG}" "${BUILD_DIR}/disk/lib/tcc/libtcc1.a" "::lib/tcc/libtcc1.a"
            echo "[DATA-DISK] Copied libtcc1.a to /lib/tcc/libtcc1.a"
        fi
        for f in "${BUILD_DIR}/disk/lib/tcc/include/"*; do
            [ -f "$f" ] && mcopy -i "${DATA_IMG}" "$f" "::lib/tcc/include/$(basename "$f")"
        done
        echo "[DATA-DISK] Copied TCC headers to /lib/tcc/include/"
    fi

    # ── Test programs (disk/test/) ───────────────────────────────────────────
    if [ -d "${BUILD_DIR}/disk/test" ]; then
        mmd -i "${DATA_IMG}" "::test" 2>/dev/null || true
        for f in "${BUILD_DIR}/disk/test/"*; do
            [ -f "${f}" ] && mcopy -i "${DATA_IMG}" "${f}" "::test/$(basename "${f}")"
        done
        echo "[DATA-DISK] Copied test/ sources to /test/"
    fi

    echo "[DATA-DISK] Populated with initial files (mtools)"
else
    echo "[DATA-DISK] WARNING: mtools not found — disk created empty"
    echo "  Install mtools for pre-populated files: sudo apt install mtools"
fi

echo "[DATA-DISK] Created: ${DATA_IMG} (${SIZE_MB} MiB, FAT32)"
