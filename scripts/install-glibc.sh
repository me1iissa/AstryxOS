#!/usr/bin/env bash
#
# install-glibc.sh — Copy host glibc runtime to build/disk/lib64 and
# build/disk/lib/x86_64-linux-gnu/ for inclusion on the AstryxOS data disk.
#
# Usage:
#   ./scripts/install-glibc.sh          # Idempotent: skips files already present
#   ./scripts/install-glibc.sh --force  # Overwrite existing files
#
# The script resolves symlinks to the real .so files and copies them under
# their versioned names, then creates the well-known unversioned symlinks in
# the disk tree (lib64 + lib/x86_64-linux-gnu).
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_LIB64="${BUILD_DIR}/disk/lib64"
DISK_GNU="${BUILD_DIR}/disk/lib/x86_64-linux-gnu"

FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
    esac
done

# ── Locate the dynamic linker ────────────────────────────────────────────────
# Ubuntu/Debian: /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
# RHEL/Fedora:   /lib64/ld-linux-x86-64.so.2
# Resolve through symlinks to the real file.

LDLINUX_REAL=""
for candidate in \
    /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
    /lib64/ld-linux-x86-64.so.2 \
    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
    /usr/lib64/ld-linux-x86-64.so.2; do
    if [ -e "${candidate}" ]; then
        LDLINUX_REAL="$(readlink -f "${candidate}")"
        echo "[glibc] Found dynamic linker: ${candidate} -> ${LDLINUX_REAL}"
        break
    fi
done

if [ -z "${LDLINUX_REAL}" ]; then
    echo "[glibc] ERROR: Cannot locate ld-linux-x86-64.so.2 on this host."
    echo "        Install glibc: sudo apt install libc6"
    exit 1
fi

# ── Locate the search dirs for glibc shared libraries ────────────────────────
SEARCH_DIRS=(
    /lib/x86_64-linux-gnu
    /usr/lib/x86_64-linux-gnu
    /lib64
    /usr/lib64
)

find_lib() {
    local name="$1"
    for d in "${SEARCH_DIRS[@]}"; do
        local p="${d}/${name}"
        if [ -e "${p}" ]; then
            echo "${p}"
            return 0
        fi
    done
    return 1
}

# ── Mandatory libraries ───────────────────────────────────────────────────────
MANDATORY_LIBS=(
    libc.so.6
    libm.so.6
    libpthread.so.0
    libdl.so.2
    librt.so.1
    libresolv.so.2
)

# ── Optional libraries (best-effort) ─────────────────────────────────────────
OPTIONAL_LIBS=(
    libstdc++.so.6
    libgcc_s.so.1
)

mkdir -p "${DISK_LIB64}" "${DISK_GNU}"

# ── Helper: copy one library (resolves symlink) ───────────────────────────────
copy_lib() {
    local soname="$1"    # e.g. libc.so.6
    local src_path="$2"  # e.g. /lib/x86_64-linux-gnu/libc.so.6

    local real_src
    real_src="$(readlink -f "${src_path}")"
    local real_name
    real_name="$(basename "${real_src}")"   # e.g. libc-2.39.so or libc.so.6

    local dest_gnu="${DISK_GNU}/${real_name}"
    local dest_lib64="${DISK_LIB64}/${real_name}"

    # Copy the real versioned file
    for dest in "${dest_gnu}" "${dest_lib64}"; do
        if [ -f "${dest}" ] && [ "${FORCE}" = false ]; then
            echo "[glibc]   SKIP (exists): $(basename "${dest}")"
        else
            cp "${real_src}" "${dest}"
            echo "[glibc]   Copied: ${real_name} -> $(dirname "${dest}")/"
        fi
    done

    # Create soname symlink if soname != real_name
    if [ "${soname}" != "${real_name}" ]; then
        for dir in "${DISK_GNU}" "${DISK_LIB64}"; do
            local link="${dir}/${soname}"
            if [ ! -L "${link}" ] || [ "${FORCE}" = true ]; then
                ln -sf "${real_name}" "${link}"
                echo "[glibc]   Symlink: ${soname} -> ${real_name} in $(basename "${dir}")/"
            fi
        done
    fi
}

# ── Install the dynamic linker ────────────────────────────────────────────────
LD_SONAME="ld-linux-x86-64.so.2"
LD_REAL_NAME="$(basename "${LDLINUX_REAL}")"

for dest in "${DISK_GNU}/${LD_REAL_NAME}" "${DISK_LIB64}/${LD_REAL_NAME}"; do
    if [ -f "${dest}" ] && [ "${FORCE}" = false ]; then
        echo "[glibc]   SKIP (exists): ${LD_REAL_NAME}"
    else
        cp "${LDLINUX_REAL}" "${dest}"
        chmod +x "${dest}"
        echo "[glibc]   Copied: ${LD_REAL_NAME} -> $(dirname "${dest}")/"
    fi
done

# Symlink ld-linux-x86-64.so.2 -> real name in both locations
if [ "${LD_SONAME}" != "${LD_REAL_NAME}" ]; then
    for dir in "${DISK_GNU}" "${DISK_LIB64}"; do
        local_link="${dir}/${LD_SONAME}"
        if [ ! -L "${local_link}" ] || [ "${FORCE}" = true ]; then
            ln -sf "${LD_REAL_NAME}" "${local_link}"
            echo "[glibc]   Symlink: ${LD_SONAME} -> ${LD_REAL_NAME} in $(basename "${dir}")/"
        fi
    done
fi

# ── Install mandatory glibc libraries ─────────────────────────────────────────
echo "[glibc] Installing mandatory glibc libraries..."
for soname in "${MANDATORY_LIBS[@]}"; do
    src=""
    if src="$(find_lib "${soname}" 2>/dev/null)"; then
        copy_lib "${soname}" "${src}"
    else
        echo "[glibc] ERROR: mandatory library ${soname} not found on host."
        echo "        Install glibc: sudo apt install libc6"
        exit 1
    fi
done

# ── Install optional libraries ────────────────────────────────────────────────
echo "[glibc] Installing optional libraries (best-effort)..."
for soname in "${OPTIONAL_LIBS[@]}"; do
    src=""
    if src="$(find_lib "${soname}" 2>/dev/null)"; then
        copy_lib "${soname}" "${src}"
    else
        echo "[glibc]   OPTIONAL MISSING: ${soname} (skipping)"
    fi
done

echo "[glibc] Done. Libraries staged in:"
echo "        ${DISK_LIB64}/"
echo "        ${DISK_GNU}/"
ls -lh "${DISK_LIB64}/"* 2>/dev/null || true
