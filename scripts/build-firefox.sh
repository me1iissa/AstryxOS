#!/usr/bin/env bash
#
# AstryxOS — Firefox Build Script (Phase 7)
#
# Cross-compiles Firefox ESR for AstryxOS using the dependency sysroot
# built by scripts/build-firefox-deps.sh.
#
# Target:     x86_64-linux-musl
# Firefox:    ESR 115 (latest long-term support release)
# Renderer:   Software/Cairo (no OpenGL/Wayland/X11)
# GUI:        AstryxOS native (custom integration layer)
#
# Prerequisites:
#   1. Run scripts/build-firefox-deps.sh first
#   2. sudo apt install rustup clang lld nasm python3-pip cbindgen
#      pip3 install --user mach
#
# Usage:
#   ./scripts/build-firefox.sh [--configure-only] [--skip-download]
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
SYSROOT="${BUILD_DIR}/sysroot"
SOURCES_DIR="${BUILD_DIR}/firefox-deps-src"
FF_DIR="${SOURCES_DIR}/firefox-esr"
FF_BUILD="${BUILD_DIR}/firefox-build"
FF_INSTALL="${BUILD_DIR}/firefox-install"
LOG_DIR="${BUILD_DIR}/firefox-deps-logs"
JOBS="$(nproc 2>/dev/null || echo 4)"
CONFIGURE_ONLY=false
SKIP_DOWNLOAD=false

FIREFOX_ESR_VER="115.15.0esr"
FIREFOX_URL="https://archive.mozilla.org/pub/firefox/releases/${FIREFOX_ESR_VER}/source/firefox-${FIREFOX_ESR_VER}.source.tar.xz"

for arg in "$@"; do
    case "$arg" in
        --configure-only) CONFIGURE_ONLY=true ;;
        --skip-download)  SKIP_DOWNLOAD=true  ;;
        --jobs) JOBS="$2"; shift ;;
    esac
done

mkdir -p "${SOURCES_DIR}" "${FF_BUILD}" "${LOG_DIR}"

# ── Preflight: check all build prerequisites ─────────────────────────────────

preflight_ok=true

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "[MISSING CMD] $1  (hint: $2)"
        preflight_ok=false
    fi
}

check_pkg() {
    if ! dpkg -s "$1" &>/dev/null; then
        echo "[MISSING PKG] $1"
        preflight_ok=false
    fi
}

check_pkgconfig() {
    if ! pkg-config --exists "$1" 2>/dev/null; then
        echo "[MISSING PC ] $1  (hint: $2)"
        preflight_ok=false
    fi
}

echo "[PREFLIGHT] Checking build prerequisites..."

# ── Tools ──────────────────────────────────────────────────────────────────
check_cmd clang-18        "sudo apt install clang"
check_cmd clang++-18      "sudo apt install clang"
check_cmd lld-18          "sudo apt install lld"
check_cmd nasm            "sudo apt install nasm"
check_cmd rustc           "rustup install stable"
check_cmd cargo           "rustup install stable"
check_cmd cbindgen        "cargo install cbindgen"
check_cmd python3         "sudo apt install python3"
check_cmd gperf           "sudo apt install gperf"
check_cmd pkg-config      "sudo apt install pkg-config"
check_cmd node            "sudo apt install nodejs" 2>/dev/null || true  # optional

# ── System dev packages (pkg-config checks) ────────────────────────────────
check_pkgconfig gtk+-3.0        "sudo apt install libgtk-3-dev"
check_pkgconfig alsa            "sudo apt install libasound2-dev"
check_pkgconfig libpulse        "sudo apt install libpulse-dev"
check_pkgconfig x11-xcb         "sudo apt install libx11-xcb-dev"
check_pkgconfig xcb              "sudo apt install libxcb1-dev"
check_pkgconfig xcb-shm         "sudo apt install libxcb-shm0-dev"
check_pkgconfig xi               "sudo apt install libxi-dev"
check_pkgconfig xcomposite       "sudo apt install libxcomposite-dev"
check_pkgconfig xdamage          "sudo apt install libxdamage-dev"
check_pkgconfig xrandr           "sudo apt install libxrandr-dev"
check_pkgconfig xcursor          "sudo apt install libxcursor-dev"
check_pkgconfig xt               "sudo apt install libxt-dev"
check_pkgconfig dbus-1           "sudo apt install libdbus-1-dev"
check_pkgconfig dbus-glib-1      "sudo apt install libdbus-glib-1-dev"

# ── WASI sysroot (required for wasm-sandboxed-libraries) ──────────────────
if [ ! -d /usr/share/wasi-sysroot ] && [ ! -d /opt/wasi-sdk ]; then
    echo "[MISSING    ] WASI sysroot — add --without-wasm-sandboxed-libraries to mozconfig, or:"
    echo "              sudo apt install wasi-libc  OR  set WASI_SYSROOT"
    # Non-fatal: we disable sandboxed wasm below
fi

if [ "${preflight_ok}" = false ]; then
    echo ""
    echo "[PREFLIGHT] Install missing items above, then re-run."
    echo "            Quick fix: sudo apt install clang lld nasm libgtk-3-dev libasound2-dev libpulse-dev \\"
    echo "              libx11-xcb-dev libxcb1-dev libxcb-shm0-dev libxi-dev libxcomposite-dev \\"
    echo "              libxdamage-dev libxrandr-dev libxcursor-dev libxt-dev libdbus-1-dev libdbus-glib-1-dev"
    exit 1
fi

echo "[PREFLIGHT] All prerequisites satisfied."
echo

if [ ! -d "${SYSROOT}/lib" ]; then
    echo "ERROR: Sysroot not found at ${SYSROOT}"
    echo "Run: ./scripts/build-firefox-deps.sh"
    exit 1
fi

# ── Download Firefox ESR source ──────────────────────────────────────────────

if [ "${SKIP_DOWNLOAD}" = false ]; then
    ARCHIVE="${SOURCES_DIR}/firefox-${FIREFOX_ESR_VER}.source.tar.xz"
    if [ ! -f "${ARCHIVE}" ]; then
        echo "[DOWNLOAD] Fetching Firefox ESR ${FIREFOX_ESR_VER} source (~350 MB)..."
        wget -q --show-progress -O "${ARCHIVE}" "${FIREFOX_URL}"
    fi
    if [ ! -d "${FF_DIR}" ]; then
        echo "[EXTRACT] Extracting Firefox source..."
        mkdir -p "${FF_DIR}"
        tar -xf "${ARCHIVE}" -C "${FF_DIR}" --strip-components=1
    fi
fi

# ── Generate mach mozconfig ──────────────────────────────────────────────────

MOZCONFIG="${FF_BUILD}/mozconfig"
cat > "${MOZCONFIG}" <<EOF
# AstryxOS Firefox Build Configuration
# AstryxOS implements the Linux x86_64 ABI — this is a standard native build.
# Generated by scripts/build-firefox.sh

# ── Build type ─────────────────────────────────────────────────────────────
ac_add_options --enable-release
ac_add_options --enable-optimize="-O2"
ac_add_options --disable-debug
ac_add_options --disable-debug-symbols
ac_add_options --disable-tests

# ── Toolchain: Firefox recommends clang ────────────────────────────────────
CC="clang-18"
CXX="clang++-18"

# ── GUI toolkit ─────────────────────────────────────────────────────────────
ac_add_options --enable-application=browser
ac_add_options --enable-default-toolkit=cairo-gtk3

# ── Strip down features not needed for AstryxOS ────────────────────────────
ac_add_options --disable-eme
ac_add_options --disable-updater
ac_add_options --disable-crashreporter
ac_add_options --disable-backgroundtasks
ac_add_options --disable-accessibility
ac_add_options --disable-wasm-simd
ac_add_options --without-wasm-sandboxed-libraries

# ── Statically link C++ and GCC runtimes to reduce shared-lib deps ─────────
LDFLAGS="-static-libstdc++ -static-libgcc"
EOF

echo "[CONFIG] mozconfig written to ${MOZCONFIG}"
export MOZCONFIG

# ── Configure Firefox ────────────────────────────────────────────────────────

cat > "${FF_DIR}/.mozconfig" <<EOF
. "${MOZCONFIG}"
mk_add_options MOZ_OBJDIR=${FF_BUILD}
EOF

if [ "${CONFIGURE_ONLY}" = true ]; then
    echo "[CONFIG] Running ./mach configure only..."
    cd "${FF_DIR}" && ./mach configure 2>&1 | tee "${LOG_DIR}/firefox-configure.log"
    echo "[DONE] Configure complete. Build with: cd ${FF_DIR} && ./mach build"
    exit 0
fi

# ── Build Firefox ────────────────────────────────────────────────────────────

echo "[BUILD] Building Firefox ESR ${FIREFOX_ESR_VER}..."
echo "[BUILD] This will take 30-120 minutes depending on hardware."
echo "[BUILD] Logs: ${LOG_DIR}/firefox-build.log"

cd "${FF_DIR}"
./mach build -j"${JOBS}" 2>&1 | tee "${LOG_DIR}/firefox-build.log"

# ── Install into build/firefox-install/ ──────────────────────────────────────

mkdir -p "${FF_INSTALL}"
./mach install DESTDIR="${FF_INSTALL}" 2>&1 | tee "${LOG_DIR}/firefox-install.log"

# ── Package for AstryxOS data disk ──────────────────────────────────────────

echo "[PACKAGE] Copying Firefox binaries to data disk layout..."
mkdir -p "${BUILD_DIR}/disk/bin" "${BUILD_DIR}/disk/lib/firefox"

# Copy the main firefox binary
if [ -f "${FF_INSTALL}/usr/local/bin/firefox" ]; then
    cp "${FF_INSTALL}/usr/local/bin/firefox" "${BUILD_DIR}/disk/bin/firefox"
fi

# Copy the Firefox application files (XUL, resources, etc.)
if [ -d "${FF_INSTALL}/usr/local/lib/firefox" ]; then
    cp -r "${FF_INSTALL}/usr/local/lib/firefox/." "${BUILD_DIR}/disk/lib/firefox/"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Firefox Build Complete                             ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║   Install:  ${FF_INSTALL}"
echo "║   Disk:     ${BUILD_DIR}/disk/"
echo "╠══════════════════════════════════════════════════════╣"
echo "║   Next: add disk/ to data.img via create-data-disk.sh║"
echo "╚══════════════════════════════════════════════════════╝"
