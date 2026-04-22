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
FIREFOX=false

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        --firefox) FIREFOX=true; FORCE=true ;;
        [0-9]*) SIZE_MB="$arg" ;;
    esac
done

# ── Stage glibc runtime libraries (non-fatal) ─────────────────────────────────
# install-glibc.sh copies host glibc to build/disk/lib64 and
# build/disk/lib/x86_64-linux-gnu.  We call it here so any --force re-run also
# refreshes the libraries.  Failure only produces a warning.
if [ -f "${ROOT_DIR}/scripts/install-glibc.sh" ]; then
    GLIBC_FLAGS=""
    [ "${FORCE}" = true ] && GLIBC_FLAGS="--force"
    bash "${ROOT_DIR}/scripts/install-glibc.sh" ${GLIBC_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
        echo "[DATA-DISK] WARNING: install-glibc.sh failed — glibc libs may be absent"
fi

# ── Compile glibc_hello oracle binary if source present ──────────────────────
GLIBC_HELLO_SRC="${ROOT_DIR}/userspace/glibc_hello.c"
GLIBC_HELLO_BIN="${BUILD_DIR}/glibc_hello"
if [ -f "${GLIBC_HELLO_SRC}" ]; then
    if [ ! -f "${GLIBC_HELLO_BIN}" ] || [ "${FORCE}" = true ] || \
       [ "${GLIBC_HELLO_SRC}" -nt "${GLIBC_HELLO_BIN}" ]; then
        if command -v gcc &>/dev/null; then
            gcc -O2 -o "${GLIBC_HELLO_BIN}" "${GLIBC_HELLO_SRC}"
            echo "[DATA-DISK] Compiled glibc_hello (glibc dynamic ELF)"
        else
            echo "[DATA-DISK] WARNING: gcc not found — cannot compile glibc_hello"
        fi
    fi
fi

# ── Compile x11_hello oracle binary (static, hand-built X11 protocol) ────────
# Prefer musl-gcc for a dependency-free static binary (no glibc init complexity).
# Fall back to gcc if musl-gcc is absent.
X11_HELLO_SRC="${ROOT_DIR}/userspace/x11_hello.c"
X11_HELLO_BIN="${BUILD_DIR}/x11_hello"
if [ -f "${X11_HELLO_SRC}" ]; then
    if [ ! -f "${X11_HELLO_BIN}" ] || [ "${FORCE}" = true ] || \
       [ "${X11_HELLO_SRC}" -nt "${X11_HELLO_BIN}" ]; then
        if command -v musl-gcc &>/dev/null; then
            musl-gcc -O2 -static -o "${X11_HELLO_BIN}" "${X11_HELLO_SRC}" 2>&1 | \
                grep -v 'warn_unused_result' || true
            echo "[DATA-DISK] Compiled x11_hello (musl static ELF, hand-built X11 protocol)"
        elif command -v gcc &>/dev/null; then
            gcc -O2 -static -o "${X11_HELLO_BIN}" "${X11_HELLO_SRC}" 2>&1 | \
                grep -v 'warn_unused_result' || true
            echo "[DATA-DISK] Compiled x11_hello (glibc static ELF, hand-built X11 protocol)"
        else
            echo "[DATA-DISK] WARNING: neither musl-gcc nor gcc found — cannot compile x11_hello"
        fi
    fi
fi

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

    # ── Seed /etc/ with minimal files required by glibc/NSS ─────────────────
    # glibc reads these at runtime for hostname resolution, user lookup, etc.
    # The linker also reads /etc/ld.so.conf to find shared library paths.
    mmd -i "${DATA_IMG}" "::etc" 2>/dev/null || true
    printf 'astryx\n' | mcopy -o -i "${DATA_IMG}" - "::etc/hostname"
    printf '127.0.0.1 localhost\n::1 localhost\n10.0.2.2 gateway\n' | \
        mcopy -o -i "${DATA_IMG}" - "::etc/hosts"
    printf 'nameserver 10.0.2.3\n' | mcopy -o -i "${DATA_IMG}" - "::etc/resolv.conf"
    printf 'hosts: files dns\npasswd: files\ngroup: files\n' | \
        mcopy -o -i "${DATA_IMG}" - "::etc/nsswitch.conf"
    printf 'root:x:0:0:root:/:/bin/sh\nuser:x:1000:1000:user:/home/user:/bin/sh\n' | \
        mcopy -o -i "${DATA_IMG}" - "::etc/passwd"
    printf 'root:x:0:\nuser:x:1000:\n' | \
        mcopy -o -i "${DATA_IMG}" - "::etc/group"
    # ld.so.conf: library search paths used by glibc dynamic linker
    printf '/lib64\n/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n' | \
        mcopy -o -i "${DATA_IMG}" - "::etc/ld.so.conf"
    # ld.so.cache: empty placeholder — linker falls back to ld.so.conf on miss
    printf '' | mcopy -o -i "${DATA_IMG}" - "::etc/ld.so.cache"
    echo "[DATA-DISK] Seeded /etc/ (hostname, hosts, resolv.conf, nsswitch.conf, passwd, group, ld.so.conf)"

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
    # glibc_hello is the oracle binary for all glibc compat work
    TEST_BINS=(hello mmap_test dynamic_hello dynamic_hello_pie clone_thread_test socket_test glibc_hello x11_hello)
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

    # ── Firefox shared library dependencies (--firefox flag) ───────────────
    if [ "$FIREFOX" = true ]; then
        echo "[DATA-DISK] Resolving Firefox shared library dependencies..."
        DISK_LIB="${BUILD_DIR}/disk/lib/x86_64-linux-gnu"
        mkdir -p "${DISK_LIB}"

        # Collect all transitive deps from Firefox's key .so files
        FF_DIR="${BUILD_DIR}/disk/lib/firefox"
        FF_LIBS=""
        for so in "${FF_DIR}/firefox-bin" "${FF_DIR}/libmozgtk.so" "${FF_DIR}/libxul.so"; do
            [ -f "${so}" ] && FF_LIBS="${FF_LIBS}$(ldd "${so}" 2>/dev/null | grep '=> /' | awk '{print $3}')"$'\n'
        done

        # Deduplicate and copy
        copied=0
        while IFS= read -r lib; do
            [ -z "${lib}" ] && continue
            bn="$(basename "${lib}")"
            if [ ! -f "${DISK_LIB}/${bn}" ] && [ -f "${lib}" ]; then
                cp "${lib}" "${DISK_LIB}/${bn}"
                copied=$((copied + 1))
            fi
        done <<< "$(echo "${FF_LIBS}" | sort -u)"

        # Copy all staged libs to disk image
        for f in "${DISK_LIB}/"*; do
            [ -f "${f}" ] && mcopy -o -i "${DATA_IMG}" "${f}" "::lib/x86_64-linux-gnu/$(basename "${f}")" 2>/dev/null
        done
        echo "[DATA-DISK] Copied ${copied} new Firefox dependency libraries"

        # Also ensure /proc, /sys, /tmp, /run directories exist (Firefox expects them)
        for d in proc sys tmp run; do
            mmd -i "${DATA_IMG}" "::${d}" 2>/dev/null || true
        done
        # /run/dbus stub
        mmd -i "${DATA_IMG}" "::run/dbus" 2>/dev/null || true

        # /tmp/ff-profile for Firefox profile
        mmd -i "${DATA_IMG}" "::tmp" 2>/dev/null || true
        mmd -i "${DATA_IMG}" "::tmp/ff-profile" 2>/dev/null || true
    fi

    echo "[DATA-DISK] Populated with initial files (mtools)"
else
    echo "[DATA-DISK] WARNING: mtools not found — disk created empty"
    echo "  Install mtools for pre-populated files: sudo apt install mtools"
fi

echo "[DATA-DISK] Created: ${DATA_IMG} (${SIZE_MB} MiB, FAT32)"
