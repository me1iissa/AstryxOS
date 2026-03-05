#!/usr/bin/env bash
#
# AstryxOS — Firefox Dependency Library Builder (Phase 7)
#
# Cross-compiles the libraries required to build Firefox for AstryxOS.
# Target: x86_64-linux-musl (static libraries, loaded by AstryxOS dynamic linker)
#
# Prerequisites:
#   sudo apt install musl-tools musl-dev build-essential cmake nasm meson \
#                    pkg-config python3 wget tar xz-utils gzip bzip2 \
#                    autoconf automake libtool
#
# Usage:
#   ./scripts/build-firefox-deps.sh [--clean] [--lib <name>]
#
#   --clean         Remove sysroot and rebuild from scratch
#   --lib <name>    Build only the specified library
#   --jobs <N>      Parallel make jobs (default: nproc)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
SYSROOT="${BUILD_DIR}/sysroot"
SOURCES_DIR="${BUILD_DIR}/firefox-deps-src"
FFDEPS_DIR="${ROOT_DIR}/FFDeps"          # pre-downloaded tarballs live here
LOG_DIR="${BUILD_DIR}/firefox-deps-logs"
JOBS="$(nproc 2>/dev/null || echo 4)"
ONLY_LIB=""
CLEAN=false

# ── Argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean)    CLEAN=true;       shift ;;
        --lib)      ONLY_LIB="$2";   shift 2 ;;
        --jobs)     JOBS="$2";        shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# ── Cross-compiler setup ─────────────────────────────────────────────────────

# Prefer x86_64-linux-musl cross-compiler if available; otherwise musl-gcc wrapper
if command -v x86_64-linux-musl-gcc &>/dev/null; then
    CROSS="x86_64-linux-musl-"
    CC="${CROSS}gcc"
    CXX="${CROSS}g++"
    AR="ar"
    RANLIB="ranlib"
    STRIP="strip"
    # Use native binutils — x86_64-linux-musl-gcc is a wrapper, ar/ranlib don't exist
    if command -v x86_64-linux-musl-ar &>/dev/null; then
        AR="${CROSS}ar"
        RANLIB="${CROSS}ranlib"
        STRIP="${CROSS}strip"
    fi
elif command -v musl-gcc &>/dev/null; then
    CC="musl-gcc"
    CXX="musl-g++"
    AR="ar"
    RANLIB="ranlib"
    STRIP="strip"
    CROSS=""
else
    echo "ERROR: No musl cross-compiler found."
    echo "Install with: sudo apt install musl-tools"
    echo "Or build musl-cross-make: https://github.com/richfelker/musl-cross-make"
    exit 1
fi

CFLAGS="-O2 -fPIC -fno-omit-frame-pointer"
CXXFLAGS="${CFLAGS}"
LDFLAGS="-static"
HOST_TRIPLE="x86_64-linux-musl"
export CC CXX AR RANLIB STRIP CFLAGS CXXFLAGS LDFLAGS

# ── Directory setup ──────────────────────────────────────────────────────────

if [ "${CLEAN}" = true ] && [ -d "${SYSROOT}" ]; then
    echo "[CLEAN] Removing existing sysroot..."
    rm -rf "${SYSROOT}"
fi

mkdir -p "${SYSROOT}/lib" "${SYSROOT}/include" "${SYSROOT}/bin"
mkdir -p "${SOURCES_DIR}" "${LOG_DIR}"

PKG_CONFIG_PATH="${SYSROOT}/lib/pkgconfig"
PKG_CONFIG_LIBDIR="${SYSROOT}/lib/pkgconfig"
export PKG_CONFIG_PATH PKG_CONFIG_LIBDIR

# ── Helper functions ─────────────────────────────────────────────────────────

log() { echo "[BUILD] $*"; }
step() { echo; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo " Building: $1"; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }

download_extract() {
    local name="$1" url="$2" dir="$3"
    local filename; filename="$(basename "${url}")"
    local archive="${SOURCES_DIR}/${filename}"
    if [ ! -d "${SOURCES_DIR}/${dir}" ]; then
        if [ ! -f "${archive}" ]; then
            # Check FFDeps/ local cache first
            if [ -f "${FFDEPS_DIR}/${filename}" ]; then
                log "Using local archive for ${name}: FFDeps/${filename}"
                cp "${FFDEPS_DIR}/${filename}" "${archive}"
            else
                log "Downloading ${name}..."
                wget -q --show-progress -O "${archive}" "${url}"
            fi
        fi
        log "Extracting ${name}..."
        tar -xf "${archive}" -C "${SOURCES_DIR}"
    fi
}

should_build() {
    local name="$1"
    [ -z "${ONLY_LIB}" ] || [ "${ONLY_LIB}" = "${name}" ]
}

# ── Library versions ─────────────────────────────────────────────────────────

ZLIB_VER="1.3.2"
LIBPNG_VER="1.6.43"
LIBJPEG_VER="3.0.3"        # libjpeg-turbo
FREETYPE_VER="2.13.3"
PIXMAN_VER="0.43.4"
CAIRO_VER="1.18.0"
LIBFFI_VER="3.4.6"
SQLITE_VER="3460100"        # 3.46.1
LIBEVENT_VER="2.1.12"
FONTCONFIG_VER="2.15.0"
HARFBUZZ_VER="9.0.0"

# ── 1. zlib ──────────────────────────────────────────────────────────────────

if should_build "zlib"; then
    step "zlib ${ZLIB_VER}"
    download_extract zlib \
        "https://zlib.net/zlib-${ZLIB_VER}.tar.gz" \
        "zlib-${ZLIB_VER}"
    pushd "${SOURCES_DIR}/zlib-${ZLIB_VER}" > /dev/null
    ./configure \
        --prefix="${SYSROOT}" \
        --static \
        2>&1 | tee "${LOG_DIR}/zlib-configure.log"
    make -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/zlib-make.log"
    make install 2>&1 | tee "${LOG_DIR}/zlib-install.log"
    popd > /dev/null
    log "zlib ${ZLIB_VER} installed ✓"
fi

# ── 2. libpng ────────────────────────────────────────────────────────────────

if should_build "libpng"; then
    step "libpng ${LIBPNG_VER}"
    download_extract libpng \
        "https://download.sourceforge.net/libpng/libpng-${LIBPNG_VER}.tar.gz" \
        "libpng-${LIBPNG_VER}"
    pushd "${SOURCES_DIR}/libpng-${LIBPNG_VER}" > /dev/null
    ./configure \
        --host="${HOST_TRIPLE}" \
        --prefix="${SYSROOT}" \
        --disable-shared \
        --enable-static \
        CPPFLAGS="-I${SYSROOT}/include" \
        LDFLAGS="-L${SYSROOT}/lib -static" \
        2>&1 | tee "${LOG_DIR}/libpng-configure.log"
    make -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/libpng-make.log"
    make install 2>&1 | tee "${LOG_DIR}/libpng-install.log"
    popd > /dev/null
    log "libpng ${LIBPNG_VER} installed ✓"
fi

# ── 3. libjpeg-turbo ─────────────────────────────────────────────────────────

if should_build "libjpeg-turbo"; then
    step "libjpeg-turbo ${LIBJPEG_VER}"
    download_extract libjpeg-turbo \
        "https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/${LIBJPEG_VER}/libjpeg-turbo-${LIBJPEG_VER}.tar.gz" \
        "libjpeg-turbo-${LIBJPEG_VER}"
    pushd "${SOURCES_DIR}/libjpeg-turbo-${LIBJPEG_VER}" > /dev/null
    mkdir -p build-astryx && cd build-astryx
    cmake .. \
        -DCMAKE_SYSTEM_NAME=Linux \
        -DCMAKE_C_COMPILER="${CC}" \
        -DCMAKE_CXX_COMPILER="${CXX}" \
        -DCMAKE_INSTALL_PREFIX="${SYSROOT}" \
        -DENABLE_SHARED=OFF \
        -DENABLE_STATIC=ON \
        -DCMAKE_BUILD_TYPE=Release \
        2>&1 | tee "${LOG_DIR}/libjpeg-cmake.log"
    make -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/libjpeg-make.log"
    make install 2>&1 | tee "${LOG_DIR}/libjpeg-install.log"
    popd > /dev/null
    log "libjpeg-turbo ${LIBJPEG_VER} installed ✓"
fi

# ── 4. libffi ────────────────────────────────────────────────────────────────

if should_build "libffi"; then
    step "libffi ${LIBFFI_VER}"
    download_extract libffi \
        "https://github.com/libffi/libffi/releases/download/v${LIBFFI_VER}/libffi-${LIBFFI_VER}.tar.gz" \
        "libffi-${LIBFFI_VER}"
    pushd "${SOURCES_DIR}/libffi-${LIBFFI_VER}" > /dev/null
    ./configure \
        --host="${HOST_TRIPLE}" \
        --prefix="${SYSROOT}" \
        --disable-shared \
        --enable-static \
        2>&1 | tee "${LOG_DIR}/libffi-configure.log"
    make -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/libffi-make.log"
    make install 2>&1 | tee "${LOG_DIR}/libffi-install.log"
    popd > /dev/null
    log "libffi ${LIBFFI_VER} installed ✓"
fi

# ── 5. freetype2 ─────────────────────────────────────────────────────────────

if should_build "freetype"; then
    step "freetype ${FREETYPE_VER}"
    download_extract freetype \
        "https://download.savannah.gnu.org/releases/freetype/freetype-${FREETYPE_VER}.tar.gz" \
        "freetype-${FREETYPE_VER}"
    pushd "${SOURCES_DIR}/freetype-${FREETYPE_VER}" > /dev/null
    ./configure \
        --host="${HOST_TRIPLE}" \
        --prefix="${SYSROOT}" \
        --disable-shared \
        --enable-static \
        --with-zlib="${SYSROOT}" \
        --with-png="${SYSROOT}" \
        --without-harfbuzz \
        --without-bzip2 \
        CPPFLAGS="-I${SYSROOT}/include" \
        LDFLAGS="-L${SYSROOT}/lib -static" \
        2>&1 | tee "${LOG_DIR}/freetype-configure.log"
    make -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/freetype-make.log"
    make install 2>&1 | tee "${LOG_DIR}/freetype-install.log"
    popd > /dev/null
    log "freetype ${FREETYPE_VER} installed ✓"
fi

# ── 6. pixman ────────────────────────────────────────────────────────────────

if should_build "pixman"; then
    step "pixman ${PIXMAN_VER}"
    download_extract pixman \
        "https://cairographics.org/releases/pixman-${PIXMAN_VER}.tar.gz" \
        "pixman-${PIXMAN_VER}"
    pushd "${SOURCES_DIR}/pixman-${PIXMAN_VER}" > /dev/null
    meson setup build-astryx \
        --cross-file="${ROOT_DIR}/scripts/meson-musl-cross.ini" \
        --prefix="${SYSROOT}" \
        --default-library=static \
        -Dgtk=disabled \
        -Dtests=disabled \
        2>&1 | tee "${LOG_DIR}/pixman-meson.log"
    ninja -C build-astryx -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/pixman-ninja.log"
    ninja -C build-astryx install 2>&1 | tee "${LOG_DIR}/pixman-install.log"
    popd > /dev/null
    log "pixman ${PIXMAN_VER} installed ✓"
fi

# ── 7. cairo ─────────────────────────────────────────────────────────────────

if should_build "cairo"; then
    step "cairo ${CAIRO_VER}"
    download_extract cairo \
        "https://cairographics.org/releases/cairo-${CAIRO_VER}.tar.xz" \
        "cairo-${CAIRO_VER}"
    pushd "${SOURCES_DIR}/cairo-${CAIRO_VER}" > /dev/null
    meson setup build-astryx \
        --cross-file="${ROOT_DIR}/scripts/meson-musl-cross.ini" \
        --prefix="${SYSROOT}" \
        --default-library=static \
        -Dgl-backend=disabled \
        -Dglesv2=disabled \
        -Dgtk-doc=disabled \
        -Dspectre=disabled \
        -Dfontconfig=disabled \
        -Dxlib=disabled \
        -Dxlib-xcb=disabled \
        -Dquartz=disabled \
        -Dwin32=disabled \
        2>&1 | tee "${LOG_DIR}/cairo-meson.log"
    ninja -C build-astryx -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/cairo-ninja.log"
    ninja -C build-astryx install 2>&1 | tee "${LOG_DIR}/cairo-install.log"
    popd > /dev/null
    log "cairo ${CAIRO_VER} installed ✓"
fi

# ── 8. libevent ──────────────────────────────────────────────────────────────

if should_build "libevent"; then
    step "libevent ${LIBEVENT_VER}"
    download_extract libevent \
        "https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VER}-stable/libevent-${LIBEVENT_VER}-stable.tar.gz" \
        "libevent-${LIBEVENT_VER}-stable"
    pushd "${SOURCES_DIR}/libevent-${LIBEVENT_VER}-stable" > /dev/null
    ./configure \
        --host="${HOST_TRIPLE}" \
        --prefix="${SYSROOT}" \
        --disable-shared \
        --enable-static \
        --disable-openssl \
        --disable-samples \
        CPPFLAGS="-I${SYSROOT}/include" \
        LDFLAGS="-L${SYSROOT}/lib -static" \
        2>&1 | tee "${LOG_DIR}/libevent-configure.log"
    make -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/libevent-make.log"
    make install 2>&1 | tee "${LOG_DIR}/libevent-install.log"
    popd > /dev/null
    log "libevent ${LIBEVENT_VER} installed ✓"
fi

# ── 9. SQLite ─────────────────────────────────────────────────────────────────

if should_build "sqlite"; then
    step "SQLite ${SQLITE_VER}"
    SQLITE_DIR="sqlite-autoconf-${SQLITE_VER}"
    download_extract sqlite \
        "https://www.sqlite.org/2024/${SQLITE_DIR}.tar.gz" \
        "${SQLITE_DIR}"
    pushd "${SOURCES_DIR}/${SQLITE_DIR}" > /dev/null
    ./configure \
        --host="${HOST_TRIPLE}" \
        --prefix="${SYSROOT}" \
        --disable-shared \
        --enable-static \
        --disable-readline \
        2>&1 | tee "${LOG_DIR}/sqlite-configure.log"
    make -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/sqlite-make.log"
    make install 2>&1 | tee "${LOG_DIR}/sqlite-install.log"
    popd > /dev/null
    log "SQLite ${SQLITE_VER} installed ✓"
fi

# ── 10. NSS / NSPR (stub build — Firefox uses bundled copy) ──────────────────
# Firefox ships its own NSS/NSPR; we skip cross-compiling them here.
# The Firefox build system will use --with-system-nss=no (default) and build
# the bundled versions.

# ── 11. fontconfig (optional — for font enumeration) ─────────────────────────

if should_build "fontconfig"; then
    step "fontconfig ${FONTCONFIG_VER}"
    download_extract fontconfig \
        "https://www.freedesktop.org/software/fontconfig/release/fontconfig-${FONTCONFIG_VER}.tar.xz" \
        "fontconfig-${FONTCONFIG_VER}"
    pushd "${SOURCES_DIR}/fontconfig-${FONTCONFIG_VER}" > /dev/null
    ./configure \
        --host="${HOST_TRIPLE}" \
        --prefix="${SYSROOT}" \
        --disable-shared \
        --enable-static \
        --disable-docs \
        --with-freetype-config="${SYSROOT}/bin/freetype-config" \
        CPPFLAGS="-I${SYSROOT}/include" \
        LDFLAGS="-L${SYSROOT}/lib -static" \
        2>&1 | tee "${LOG_DIR}/fontconfig-configure.log"
    make -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/fontconfig-make.log"
    make install 2>&1 | tee "${LOG_DIR}/fontconfig-install.log"
    popd > /dev/null
    log "fontconfig ${FONTCONFIG_VER} installed ✓"
fi

# ── 12. harfbuzz ─────────────────────────────────────────────────────────────

if should_build "harfbuzz"; then
    step "harfbuzz ${HARFBUZZ_VER}"
    download_extract harfbuzz \
        "https://github.com/harfbuzz/harfbuzz/releases/download/${HARFBUZZ_VER}/harfbuzz-${HARFBUZZ_VER}.tar.xz" \
        "harfbuzz-${HARFBUZZ_VER}"
    pushd "${SOURCES_DIR}/harfbuzz-${HARFBUZZ_VER}" > /dev/null
    meson setup build-astryx \
        --cross-file="${ROOT_DIR}/scripts/meson-musl-cross.ini" \
        --prefix="${SYSROOT}" \
        --default-library=static \
        -Dglib=disabled \
        -Dgobject=disabled \
        -Dcairo=disabled \
        -Dfontconfig=disabled \
        -Dfreetype=enabled \
        -Dtests=disabled \
        -Ddocs=disabled \
        2>&1 | tee "${LOG_DIR}/harfbuzz-meson.log"
    ninja -C build-astryx -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/harfbuzz-ninja.log"
    ninja -C build-astryx install 2>&1 | tee "${LOG_DIR}/harfbuzz-install.log"
    popd > /dev/null
    log "harfbuzz ${HARFBUZZ_VER} installed ✓"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Firefox Dependency Libraries — Build Complete      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║   Sysroot: ${SYSROOT}"
echo "╠══════════════════════════════════════════════════════╣"
echo "║   Libraries available:"
for lib in "${SYSROOT}/lib/"lib*.a; do
    [ -f "${lib}" ] && printf "║     %-50s║\n" "$(basename "${lib}")"
done
echo "╚══════════════════════════════════════════════════════╝"
echo
echo "Next: ./scripts/build-firefox.sh  (configure + compile Firefox)"
