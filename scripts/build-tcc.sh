#!/usr/bin/env bash
#
# Build TinyCC 0.9.27 as a static musl binary for AstryxOS.
#
# Produces:
#   build/disk/bin/tcc          – the TCC compiler executable (static, ~350 KB)
#   build/disk/lib/tcc/libtcc1.a – TCC runtime (used when NOT compiling with -nostdlib)
#   build/disk/lib/tcc/include/  – TCC's bundled C headers (stdarg.h, stddef.h, …)
#
# The runtime paths compiled into the TCC binary point inside AstryxOS:
#   tccdir  = /disk/lib/tcc          (libtcc1.a location)
#   sysinclude = /disk/lib/tcc/include
#   crtprefix  = /disk/lib/tcc
#
# Usage:
#   ./scripts/build-tcc.sh           # build only if not already built
#   ./scripts/build-tcc.sh --force   # always rebuild
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TCC_SRC="${ROOT_DIR}/TinyCC/tcc-0.9.27"
BUILD_DIR="${ROOT_DIR}/build"
OUT_BIN="${BUILD_DIR}/disk/bin/tcc"
OUT_LIB="${BUILD_DIR}/disk/lib/tcc"
FORCE=false

for arg in "$@"; do
    case "$arg" in --force) FORCE=true ;; esac
done

# ── Sanity checks ────────────────────────────────────────────────────────────
if [ ! -d "${TCC_SRC}" ]; then
    # Try to extract from archive
    ARCHIVE="${ROOT_DIR}/TinyCC/tcc-0.9.27.tar.bz2"
    if [ -f "${ARCHIVE}" ]; then
        echo "[BUILD-TCC] Extracting ${ARCHIVE}..."
        tar -xjf "${ARCHIVE}" -C "${ROOT_DIR}/TinyCC/"
    else
        echo "[BUILD-TCC] ERROR: ${TCC_SRC} not found and no archive at ${ARCHIVE}"
        exit 1
    fi
fi

if ! command -v musl-gcc &>/dev/null; then
    echo "[BUILD-TCC] ERROR: musl-gcc not found"
    echo "  Install: sudo apt install musl-tools"
    exit 1
fi

# ── Skip if already built ────────────────────────────────────────────────────
if [ -f "${OUT_BIN}" ] && [ "$FORCE" = false ]; then
    echo "[BUILD-TCC] ${OUT_BIN} already exists (use --force to rebuild)"
    exit 0
fi

# ── Apply null-guard patch if not already applied ───────────────────────────
# TCC 0.9.27 bug: fill_local_got_entries crashes with NULL s1->got->reloc
# when compiling -nostdlib programs (the GOT section exists but has no relocs).
TCCELF="${TCC_SRC}/tccelf.c"
if ! grep -q 'if (!s1->got->reloc)' "${TCCELF}"; then
    echo "[BUILD-TCC] Applying fill_local_got_entries null-guard patch..."
    perl -i -0pe 's|(static void fill_local_got_entries\(TCCState \*s1\)\n\{\n    ElfW_Rel \*rel;\n)(    for_each_elem)|${1}    if (!s1->got->reloc)\n        return;\n${2}|' "${TCCELF}"
    if grep -q 'if (!s1->got->reloc)' "${TCCELF}"; then
        echo "[BUILD-TCC] Patch applied."
    else
        echo "[BUILD-TCC] ERROR: patch failed — check ${TCCELF} manually"
        exit 1
    fi
fi

echo "[BUILD-TCC] Configuring TinyCC 0.9.27..."
cd "${TCC_SRC}"

./configure \
    --prefix=/tmp/tcc-build-output \
    --tccdir=/disk/lib/tcc \
    --cpu=x86_64 \
    --cc=musl-gcc \
    --extra-cflags="-O2" \
    --extra-ldflags="-static" \
    --sysincludepaths=/disk/lib/tcc/include \
    --crtprefix=/disk/lib/tcc \
    --enable-static

echo "[BUILD-TCC] Building TCC binary..."
make CC=musl-gcc CFLAGS="-O2" LDFLAGS="-static" -j"$(nproc)" tcc

echo "[BUILD-TCC] Building libtcc1.a (skipping bcheck.c — needs stdlib.h)..."
cd lib
../tcc -c libtcc1.c       -o libtcc1.o        -B..
../tcc -c alloca86_64.S   -o alloca86_64.o    -B..
../tcc -c alloca86_64-bt.S -o alloca86_64-bt.o -B..
../tcc -c va_list.c       -o va_list.o        -B..
ar rcs ../libtcc1.a libtcc1.o alloca86_64.o alloca86_64-bt.o va_list.o
cd ..

echo "[BUILD-TCC] Staging into build/disk/ ..."
mkdir -p "${OUT_LIB}/include"
mkdir -p "${BUILD_DIR}/disk/bin"

cp "${TCC_SRC}/tcc"        "${OUT_BIN}"
cp "${TCC_SRC}/libtcc1.a"  "${OUT_LIB}/libtcc1.a"
cp "${TCC_SRC}/include/"*  "${OUT_LIB}/include/"

echo "[BUILD-TCC] Done:"
echo "  binary : ${OUT_BIN}  ($(du -sh "${OUT_BIN}" | cut -f1))"
echo "  runtime: ${OUT_LIB}/libtcc1.a"
echo "  headers: $(ls "${OUT_LIB}/include/" | wc -l) file(s) in ${OUT_LIB}/include/"
