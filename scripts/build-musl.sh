#!/usr/bin/env bash
#
# build-musl.sh — Cross-compile musl libc for AstryxOS.
#
# AstryxOS implements the Linux x86_64 syscall ABI, so a vanilla musl build
# targeting x86_64-linux-musl works without any patching.
#
# Produces (under build/disk/):
#   lib/libc.a                  – static musl archive (link with: tcc -L/disk/lib -lc)
#   lib/crt1.o crti.o crtn.o   – C runtime startup objects
#   lib/ld-musl-x86_64.so.1    – dynamic linker (for ET_DYN binaries)
#   include/                   – musl public headers (stdio.h, stdlib.h, …)
#
# Inside AstryxOS the paths are accessed via the /disk mount:
#   /disk/lib/libc.a
#   /disk/lib/ld-musl-x86_64.so.1
#   /disk/include/
#
# Usage:
#   ./scripts/build-musl.sh           # build only if not already built
#   ./scripts/build-musl.sh --force   # always rebuild
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
MUSL_VERSION="1.2.5"
MUSL_TARBALL="musl-${MUSL_VERSION}.tar.gz"
MUSL_URL="https://musl.libc.org/releases/${MUSL_TARBALL}"
MUSL_SRC="${BUILD_DIR}/musl-src/musl-${MUSL_VERSION}"
MUSL_INSTALL="${BUILD_DIR}/musl-install"

FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

echo "=== AstryxOS musl libc build ==="

# ── Preflight checks ─────────────────────────────────────────────────────────
for tool in gcc make curl tar; do
    if ! command -v "$tool" &>/dev/null; then
        echo "ERROR: '$tool' not found. Install build-essential + curl." >&2
        exit 1
    fi
done

# ── Skip if already built ─────────────────────────────────────────────────────
if [[ $FORCE -eq 0 ]] && [[ -f "${DISK_DIR}/lib/libc.a" ]]; then
    echo "[musl] Already built — skipping (use --force to rebuild)."
    echo "[musl] libc.a: $(du -h "${DISK_DIR}/lib/libc.a" | cut -f1)"
    exit 0
fi

mkdir -p "${BUILD_DIR}/musl-src" "${MUSL_INSTALL}"

# ── Download ──────────────────────────────────────────────────────────────────
if [[ ! -f "${BUILD_DIR}/musl-src/${MUSL_TARBALL}" ]]; then
    echo "[musl] Downloading musl ${MUSL_VERSION}…"
    curl -L --retry 5 -o "${BUILD_DIR}/musl-src/${MUSL_TARBALL}" "${MUSL_URL}"
fi

# ── Extract ───────────────────────────────────────────────────────────────────
if [[ ! -d "${MUSL_SRC}" ]]; then
    echo "[musl] Extracting…"
    tar -xzf "${BUILD_DIR}/musl-src/${MUSL_TARBALL}" -C "${BUILD_DIR}/musl-src"
fi

# ── Configure ─────────────────────────────────────────────────────────────────
MUSL_BUILD="${BUILD_DIR}/musl-build"
mkdir -p "${MUSL_BUILD}"

echo "[musl] Configuring for x86_64 static + shared…"
(
    cd "${MUSL_BUILD}"
    "${MUSL_SRC}/configure"             \
        --prefix="${MUSL_INSTALL}"      \
        --syslibdir="${MUSL_INSTALL}/lib" \
        --disable-debug                 \
        --enable-static                 \
        --enable-shared                 \
        CC=gcc                          \
        AR=ar                           \
        RANLIB=ranlib                   \
        CFLAGS="-O2 -fno-stack-protector" \
        2>&1
)

# ── Build ──────────────────────────────────────────────────────────────────────
NPROC=$(nproc 2>/dev/null || echo 4)
echo "[musl] Building with ${NPROC} jobs…"
make -C "${MUSL_BUILD}" -j"${NPROC}"

# ── Install to staging ────────────────────────────────────────────────────────
echo "[musl] Installing to ${MUSL_INSTALL}…"
make -C "${MUSL_BUILD}" install

# ── Copy to disk image staging ────────────────────────────────────────────────
echo "[musl] Copying artefacts to ${DISK_DIR}…"

mkdir -p "${DISK_DIR}/lib"
mkdir -p "${DISK_DIR}/include"

# Static archive + CRT objects
cp -f "${MUSL_INSTALL}/lib/libc.a"    "${DISK_DIR}/lib/"
for obj in crt1.o crti.o crtn.o rcrt1.o Scrt1.o; do
    [[ -f "${MUSL_INSTALL}/lib/${obj}" ]] && cp -f "${MUSL_INSTALL}/lib/${obj}" "${DISK_DIR}/lib/"
done

# Dynamic linker (so X11 clients can use shared libs later)
if [[ -f "${MUSL_INSTALL}/lib/ld-musl-x86_64.so.1" ]]; then
    cp -f "${MUSL_INSTALL}/lib/ld-musl-x86_64.so.1" "${DISK_DIR}/lib/"
fi
if [[ -f "${MUSL_INSTALL}/lib/libc.so" ]]; then
    cp -f "${MUSL_INSTALL}/lib/libc.so" "${DISK_DIR}/lib/"
fi

# Public headers
rsync -a --delete "${MUSL_INSTALL}/include/" "${DISK_DIR}/include/" 2>/dev/null \
    || cp -rf "${MUSL_INSTALL}/include/." "${DISK_DIR}/include/"

echo ""
echo "=== musl build complete ==="
echo "  libc.a:  $(du -h "${DISK_DIR}/lib/libc.a" 2>/dev/null | cut -f1 || echo '?')"
echo "  headers: ${DISK_DIR}/include/"
echo ""
echo "To compile a C program inside AstryxOS:"
echo "  exec /disk/bin/tcc -L/disk/lib -I/disk/include -lc hello.c -o /tmp/hello"
echo "  exec /tmp/hello"
