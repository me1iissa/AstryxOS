#!/usr/bin/env bash
#
# install-fonts-real.sh — Install REAL libfontconfig + libfreetype (and their
# transitive dependencies) from the host into build/disk/, overwriting any
# stub copies that install-firefox-stubs.sh may have produced.
#
# Rationale
# ─────────
# Firefox ESR 115 (headless) calls a large number of fontconfig and freetype
# entry points during early init even though no glyphs are ever rendered.
# Mozilla's startup iterates Fc* result objects, derefs returned strings, and
# reads freetype face structures while building gfxPlatformFontList.  The
# generic stubs produced by install-firefox-stubs.sh satisfy the dynamic
# linker but return NULL/zero, which Mozilla turns into NULL-dereference
# SIGSEGVs (clusters tracked in W66/W70/W76/W82/W87 and the post-PR#176
# libxul cluster at libxul+0x185b8a4 / libxul+0x4056429).
#
# Iteration-based stub classifier work hit a ceiling; the right move is to
# replace these two libraries with the real upstream binaries from the host
# system.  Both are pure userland .so files that talk to glibc — they do not
# require kernel-side support beyond what AstryxOS already provides (mmap,
# openat, read, fstatat, basic /proc/self/maps).
#
# The disk delta is ~2 MiB:
#   libfontconfig.so.1.16.1        338 KB
#   libfreetype.so.6.20.5          870 KB
#   libexpat.so.1.11.2             183 KB   (fontconfig dep)
#   libz.so.1.3.1                  122 KB   (freetype dep, png compression)
#   libbz2.so.1.0.4                 83 KB   (freetype dep, PCF compression)
#   libpng16.so.16.57.0            232 KB   (freetype dep, png glyphs)
#   libbrotlidec.so.1.2.0           56 KB   (freetype dep, woff2 decoding)
#   libbrotlicommon.so.1.2.0       142 KB   (brotlidec dep)
#
# Compared to ongoing whack-a-mole on FcPatternGetString / FcConfigGetFonts /
# FcPatternGetBool / FcPatternGetInteger / FcPatternGetDouble / ... stub
# patches (six rounds and counting), one-time ~2 MiB of real library code is
# the better trade.
#
# Layout
# ──────
# Real libraries are copied under their versioned names (e.g.
# libfontconfig.so.1.16.1) with soname symlinks (libfontconfig.so.1) into
# BOTH build/disk/lib64/ and build/disk/lib/x86_64-linux-gnu/.  This matches
# the layout install-firefox-stubs.sh and install-glibc.sh already use and
# guarantees the runtime finds the real .so regardless of LD_LIBRARY_PATH
# ordering (kernel sets it to /opt/firefox:/lib64:/lib/x86_64-linux-gnu for
# firefox-test).
#
# install-firefox-stubs.sh writes its 13–65 KiB stub .so files first; this
# script is intended to run AFTER stubs and OVERWRITES the fontconfig +
# freetype entries with real binaries.  Stubs remain in place for every
# other GTK/X11/cairo/pango/glib library — they truly should not be called
# in headless mode (a separate bug class if they are).
#
# fontconfig also reads /etc/fonts/fonts.conf at FcInit time.  If the file is
# missing fontconfig falls back to a built-in default that scans /usr/share
# /fonts and ~/.fonts — both empty on AstryxOS.  Mozilla copes with an empty
# font set (PR #172 already installs one DejaVuSans.ttf + a minimal Fc set);
# this script writes a tiny /etc/fonts/fonts.conf that points fontconfig at
# /usr/share/fonts/ so it can find the staged DejaVu.
#
# Usage
# ─────
#   ./scripts/install-fonts-real.sh          # idempotent: skip files already
#                                            # present (and same size as host)
#   ./scripts/install-fonts-real.sh --force  # overwrite unconditionally
#
# Exit codes
# ──────────
#   0    success (or success-with-warnings: host missing optional deps)
#   1    host missing one of the mandatory libraries (libfontconfig /
#        libfreetype) — fix by `sudo apt install libfontconfig1 libfreetype6`
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# BUILD_DIR is overridable via ASTRYXOS_BUILD_DIR so an isolated variant build
# (create-data-disk.sh --build-dir) stages into that root instead of build/.
BUILD_DIR="${ASTRYXOS_BUILD_DIR:-${ROOT_DIR}/build}"
DISK_LIB64="${BUILD_DIR}/disk/lib64"
DISK_GNU="${BUILD_DIR}/disk/lib/x86_64-linux-gnu"
DISK_ETC_FONTS="${BUILD_DIR}/disk/etc/fonts"

FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
    esac
done

log() { echo "[fonts-real] $*"; }

mkdir -p "${DISK_LIB64}" "${DISK_GNU}" "${DISK_ETC_FONTS}"

# ── Host search dirs ─────────────────────────────────────────────────────────
SEARCH_DIRS=(
    /usr/lib/x86_64-linux-gnu
    /lib/x86_64-linux-gnu
    /usr/lib64
    /lib64
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

# ── Copy one library: resolve symlink, copy real file under its real name,
#    then create the soname symlink.  Mirrors install-glibc.sh's copy_lib.
# ────────────────────────────────────────────────────────────────────────────
copy_lib() {
    local soname="$1"      # e.g. libfontconfig.so.1
    local src_path="$2"    # e.g. /usr/lib/x86_64-linux-gnu/libfontconfig.so.1

    local real_src real_name
    real_src="$(readlink -f "${src_path}")"
    real_name="$(basename "${real_src}")"   # e.g. libfontconfig.so.1.16.1

    local host_size
    host_size="$(stat -c%s "${real_src}")"

    for dir in "${DISK_GNU}" "${DISK_LIB64}"; do
        local dest_real="${dir}/${real_name}"
        local dest_soname="${dir}/${soname}"

        if [ -f "${dest_real}" ] && [ "${FORCE}" = false ]; then
            # Re-check size: a stub file with the same name (unlikely for the
            # versioned name, but cheap to verify) would be much smaller.
            local existing_size
            existing_size="$(stat -c%s "${dest_real}" 2>/dev/null || echo 0)"
            if [ "${existing_size}" = "${host_size}" ]; then
                log "  SKIP (present): ${real_name} in $(basename "${dir}")/"
            else
                cp --preserve=timestamps "${real_src}" "${dest_real}"
                log "  Updated ${real_name} (was ${existing_size}, now ${host_size}) in $(basename "${dir}")/"
            fi
        else
            cp --preserve=timestamps "${real_src}" "${dest_real}"
            log "  Copied ${real_name} (${host_size} bytes) -> $(basename "${dir}")/"
        fi

        # Always (re)create the soname.  If a previous run from
        # install-firefox-stubs.sh dropped a 13-65 KB stub at the soname path
        # we want to replace it with a symlink to the real file.
        if [ "${soname}" != "${real_name}" ]; then
            # `ln -sf` over a regular file removes the file and creates the
            # symlink — exactly what we want for stub eviction.
            ln -sf "${real_name}" "${dest_soname}"
        fi
    done
}

# ── Mandatory libraries (fontconfig + freetype) ──────────────────────────────
# Missing either of these is a hard failure — they are the whole point of
# this script.
MANDATORY=(
    libfontconfig.so.1
    libfreetype.so.6
)

# ── Transitive deps required for the mandatory pair to dlopen-resolve.
# ──────────────────────────────────────────────────────────────────────
# These come from `ldd /usr/lib/x86_64-linux-gnu/libfontconfig.so.1` plus
# `ldd /usr/lib/x86_64-linux-gnu/libfreetype.so.6` on Ubuntu 24.04.  Each is
# also a pure userspace .so — copying suffices.  We treat them as mandatory:
# if the host is missing one, every library in this chain dlopens lazily and
# we get an "undefined symbol" at first FcInit/FT_Init_FreeType call.
#
# libz, libstdc++, and libgcc_s are already provided by install-glibc.sh
# (libz is provided indirectly via the glibc-deps path).  We still copy them
# here to be defensive — host glibc versions sometimes ship libz separately.
TRANSITIVE=(
    libexpat.so.1
    libz.so.1
    libbz2.so.1.0
    libpng16.so.16
    libbrotlidec.so.1
    libbrotlicommon.so.1
)

# ── Install mandatory libs (fail hard on miss) ───────────────────────────────
log "Installing real libfontconfig + libfreetype:"
for soname in "${MANDATORY[@]}"; do
    if src="$(find_lib "${soname}" 2>/dev/null)"; then
        copy_lib "${soname}" "${src}"
    else
        echo "[fonts-real] ERROR: mandatory library ${soname} not found on host."
        echo "             Install: sudo apt install libfontconfig1 libfreetype6"
        exit 1
    fi
done

# ── Install transitive deps (warn on miss) ───────────────────────────────────
log "Installing transitive dependencies:"
for soname in "${TRANSITIVE[@]}"; do
    if src="$(find_lib "${soname}" 2>/dev/null)"; then
        copy_lib "${soname}" "${src}"
    else
        log "  WARN: ${soname} not found on host — Firefox may dlopen-fail at"
        log "        runtime.  Install: sudo apt install zlib1g libbz2-1.0 \\"
        log "        libpng16-16 libbrotli1 libexpat1"
    fi
done

# ── Minimal /etc/fonts/fonts.conf ────────────────────────────────────────────
# fontconfig reads /etc/fonts/fonts.conf at FcInitLoadConfig time.  Without
# it FcInit falls back to a compiled-in default that scans the host build's
# package layout (/usr/share/fonts/X11/, /var/cache/fontconfig/, ...), which
# on AstryxOS resolve to ENOENT and trigger the "no fonts" fallback path.
#
# We write a tiny config that:
#   - points fontconfig at /usr/share/fonts/ on the guest disk
#   - declares a cache dir at /var/cache/fontconfig/ (PR #172 / build-firefox
#     -deps --copy-host-libs already populates this with fc-cache output)
#   - declares /tmp/fontconfig as a fallback cache dir so a writable
#     fallback exists if the cached entries are stale
#
# The two `<dir>` entries match what the Debian/Ubuntu default fonts.conf
# uses (truetype + dejavu lives under /usr/share/fonts/truetype/dejavu).
# `<cachedir>` order matters: fontconfig picks the first writable one.
FONTS_CONF="${DISK_ETC_FONTS}/fonts.conf"
if [ ! -f "${FONTS_CONF}" ] || [ "${FORCE}" = true ]; then
    cat > "${FONTS_CONF}" << 'XML_EOF'
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <!--
    Minimal AstryxOS fonts.conf for Firefox ESR 115 headless mode.

    Lists the on-disk font directories and cache locations.  fontconfig's
    default scan tree on Debian-derived hosts includes many paths we do not
    populate (X11 cores, urw-base35, OpenType collections) — pointing
    fontconfig at the smaller AstryxOS layout avoids hundreds of ENOENT
    probes during FcInit.
  -->
  <dir>/usr/share/fonts</dir>
  <dir prefix="default">fonts</dir>

  <!--
    Cache locations.  build-firefox-deps.sh --copy-host-libs (or a manual
    fc-cache run) populates the first.  /tmp/fontconfig is a runtime
    fallback in case the cached entries are stale or unreadable; the kernel
    has /tmp writable.
  -->
  <cachedir>/var/cache/fontconfig</cachedir>
  <cachedir>/tmp/fontconfig</cachedir>

  <!-- Default rendering hints — pulled from the freedesktop reference -->
  <match target="font">
    <edit mode="assign" name="rgba"><const>none</const></edit>
    <edit mode="assign" name="hinting"><bool>true</bool></edit>
    <edit mode="assign" name="hintstyle"><const>hintslight</const></edit>
    <edit mode="assign" name="antialias"><bool>true</bool></edit>
  </match>
</fontconfig>
XML_EOF
    log "  Wrote ${FONTS_CONF}"
else
    log "  SKIP (present): ${FONTS_CONF}"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo
log "Done.  Real libraries staged in:"
log "  ${DISK_LIB64}/"
log "  ${DISK_GNU}/"
log "Mandatory + transitive sizes:"
for soname in "${MANDATORY[@]}" "${TRANSITIVE[@]}"; do
    f="${DISK_LIB64}/${soname}"
    if [ -L "${f}" ]; then
        target="$(readlink "${f}")"
        size="$(stat -L -c%s "${f}" 2>/dev/null || echo '?')"
        printf '  %-32s -> %-32s (%s bytes)\n' "${soname}" "${target}" "${size}"
    elif [ -f "${f}" ]; then
        size="$(stat -c%s "${f}")"
        printf '  %-32s (%s bytes)\n' "${soname}" "${size}"
    fi
done
