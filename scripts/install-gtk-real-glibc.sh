#!/usr/bin/env bash
#
# install-gtk-real-glibc.sh — Overlay the REAL glibc GTK3 + X11 client-library
# closure onto the glibc-Firefox data-disk staging tree, replacing the headless
# no-op stubs that install-firefox-stubs.sh generates for the display-critical
# libraries.
#
# Why
# ───
# The glibc Firefox variant (Mozilla's official ESR 115 tarball) satisfies its
# GTK3/X11/GLib/Cairo/Pango DT_NEEDED entries with tiny no-op stubs
# (install-firefox-stubs.sh).  Those stubs deliberately make gdk_display_open()
# return NULL — Firefox can never open an X display, so it can only run
# --headless.  That is fine for the headless-screenshot demo, but it means the
# glibc variant cannot exercise the WINDOWED GTK path, which is exactly what the
# "does the ~50x wiki-load slowdown reproduce on glibc Firefox?" discriminator
# needs (the musl variant already ships a real Alpine GTK/X11 closure and can
# open the in-kernel X server).
#
# This script gives the glibc variant a real, working glibc GTK3 + X11 client
# closure so gdk_display_open() actually connects to the AstryxOS X server and
# GTK initialises for real.  It mirrors the paradigm already used by
# install-fonts-real.sh (real libfontconfig + libfreetype) and
# install-dbus-real.sh (real libdbus-1 + libsystemd): build stubs first, then
# overlay the real upstream binaries for the paths Firefox genuinely exercises,
# keeping stubs only where the real functionality is not needed headless.
#
# Source
# ──────
# The real libraries are upstream Ubuntu 24.04 LTS ("noble") binaries, fetched
# with `apt-get download` into an isolated apt sandbox (no system-wide install,
# no /etc/apt changes) and unpacked with `dpkg-deb -x`.  noble is chosen because:
#
#   * noble's glibc is 2.39, which is <= the glibc the image ships (the image
#     carries the host's glibc via install-glibc.sh; this build host is 2.43).
#     A GTK3 stack linked against glibc 2.39 runs unchanged on glibc >= 2.39, so
#     there is no version wall.
#   * noble is the reference glibc environment against which this exact Firefox
#     ESR 115 build is known to render, so the paired stack is a known-good one.
#   * noble's gdk-pixbuf does NOT drag in libglycin (a newer out-of-process
#     image-loader sandbox), keeping the closure to plain in-process libraries.
#
# The binaries are shipped AS-IS — never patched.  If a real library needed
# patching to load, that would be a kernel/ABI compatibility bug to fix in the
# kernel, not here.
#
# Closure (53 shared objects, ~23 MiB) — verified transitively complete at
# build time (see the completeness check below; the build ERRORS if any
# DT_NEEDED edge cannot be resolved inside the staging tree):
#
#   X11 client:   libX11 libX11-xcb libxcb libxcb-shm libxcb-render libXext
#                 libXcomposite libXdamage libXfixes libXrandr libXrender
#                 libXtst libXcursor libXi libXau libXdmcp libXinerama
#   GTK3 stack:   libgtk-3 libgdk-3 libgdk_pixbuf-2.0 libatk-1.0
#                 libatk-bridge-2.0 libatspi libcairo libcairo-gobject
#                 libpango-1.0 libpangocairo-1.0 libpangoft2-1.0 libharfbuzz
#                 libgraphite2 libfribidi libthai libdatrie libpixman-1
#                 libepoxy libxkbcommon libwayland-client libwayland-cursor
#                 libwayland-egl
#   GLib:         libglib-2.0 libgobject-2.0 libgio-2.0 libgmodule-2.0
#   support:      libpng16 libjpeg libbrotlicommon libbrotlidec libexpat libffi
#                 libpcre2-8 libblkid libmount libselinux libbsd libmd libz
#
# LEFT AS STUBS on purpose (real functionality not needed for display-open +
# basic render; mirrors what the musl image also does not exercise):
#   libasound.so.2       — ALSA audio; the discriminator does not need sound.
#   libdbus-glib-1.so.2  — deprecated GLib/DBus wrapper; modern GTK uses plain
#                          libdbus-1 (which install-dbus-real.sh ships real).
#
# ALREADY REAL via sibling scripts (skipped here):
#   libfontconfig.so.1, libfreetype.so.6   (install-fonts-real.sh)
#   libdbus-1.so.3, libsystemd.so.0        (install-dbus-real.sh)
#   libc/libm/libpthread/libdl/librt/libstdc++/libgcc_s + ld-linux
#                                          (install-glibc.sh)
#
# Layout
# ──────
# Real libraries are copied under their versioned names (e.g. libgtk-3.so.0.2409.32)
# with soname symlinks (libgtk-3.so.0) into BOTH ${BUILD_DIR}/disk/lib64/ and
# ${BUILD_DIR}/disk/lib/x86_64-linux-gnu/ — the same dual-location layout
# install-firefox-stubs.sh / install-glibc.sh / install-fonts-real.sh use, so the
# runtime resolves the real .so regardless of LD_LIBRARY_PATH ordering.  `ln -sf`
# over an existing stub file evicts it.
#
# Isolation
# ─────────
# BUILD_DIR (staging root) is overridable via ASTRYXOS_BUILD_DIR so a variant
# build (create-data-disk.sh --build-dir) stages into that root instead of
# build/, never touching the shared musl staging tree.  The noble deb cache +
# extraction tree live under ${ASTRYXOS_GTK_CACHE:-~/.cache/astryxos-gtk-glibc}
# and are reused across builds.
#
# Usage
# ─────
#   ./scripts/install-gtk-real-glibc.sh            # idempotent
#   ./scripts/install-gtk-real-glibc.sh --force    # re-download + re-stage
#
# Requires (host): apt-get, dpkg-deb, readelf (binutils), the ubuntu archive
# keyring (/usr/share/keyrings/ubuntu-archive-keyring.gpg, package
# ubuntu-keyring), and outbound access to archive.ubuntu.com.  No root, no sudo.
#
# References:
#   GTK3:        https://docs.gtk.org/gtk3/
#   fontconfig:  https://www.freedesktop.org/wiki/Software/fontconfig/
#   Debian pkgs: https://packages.ubuntu.com/noble/
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# Staging root — overridable so an isolated variant build stages into its own
# tree (matches install-glibc.sh / install-firefox-stubs.sh / ...).
BUILD_DIR="${ASTRYXOS_BUILD_DIR:-${ROOT_DIR}/build}"
DISK_LIB64="${BUILD_DIR}/disk/lib64"
DISK_GNU="${BUILD_DIR}/disk/lib/x86_64-linux-gnu"

# Reusable noble deb cache + extraction tree (like ~/.cache/astryxos-firefox).
CACHE_DIR="${ASTRYXOS_GTK_CACHE:-${HOME}/.cache/astryxos-gtk-glibc}"
APTROOT="${CACHE_DIR}/aptroot"
DEBS_DIR="${CACHE_DIR}/debs"
EXTRACT_DIR="${CACHE_DIR}/noble-extract"

# Ubuntu release to source the GTK/X11 closure from.  noble = 24.04 LTS, glibc
# 2.39.  Overridable for a different <= image-glibc release if ever needed.
NOBLE_SUITE="${ASTRYXOS_GTK_SUITE:-noble}"
ARCHIVE_MIRROR="http://archive.ubuntu.com/ubuntu"
SECURITY_MIRROR="http://security.ubuntu.com/ubuntu"
UBUNTU_KEYRING="/usr/share/keyrings/ubuntu-archive-keyring.gpg"

FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
    esac
done

log() { echo "[gtk-real] $*"; }
die() { echo "[gtk-real] ERROR: $*" >&2; exit 1; }

# ── The noble package set that OWNS the display-critical .so closure ──────────
# Curated so the .so DT_NEEDED closure of the display-critical libraries resolves
# transitively (the completeness check below verifies this and ERRORS on a gap,
# so a future noble edge change fails the build loudly instead of shipping a
# broken image).  Suite-pinned (not version-pinned): `apt-get download` always
# fetches the current candidate, and the completeness check is the safety net.
NOBLE_PKGS=(
    # X11 client libraries (X ships every extension as its own tiny .so)
    libx11-6 libx11-xcb1 libxau6 libxdmcp6 libxcb1 libxcb-shm0 libxcb-render0
    libxext6 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libxrender1
    libxtst6 libxcursor1 libxi6 libxinerama1
    # GTK3 + GDK + toolkit stack
    libgtk-3-0t64 libgdk-pixbuf-2.0-0 libatk1.0-0t64 libatk-bridge2.0-0t64
    libatspi2.0-0t64 libcairo2 libcairo-gobject2 libpango-1.0-0
    libpangocairo-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libgraphite2-3
    libfribidi0 libthai0 libdatrie1 libpixman-1-0 libepoxy0 libxkbcommon0
    libwayland-client0 libwayland-cursor0 libwayland-egl1
    # GLib
    libglib2.0-0t64
    # transitive .so support libraries
    libpng16-16t64 libjpeg-turbo8 libbrotli1 libexpat1 libffi8 libpcre2-8-0
    libblkid1 libmount1 libselinux1 libbsd0 libmd0 zlib1g
)

# ── The display-critical sonames libxul.so DT_NEEDEDs (BFS roots) ─────────────
# These are exactly the entries install-firefox-stubs.sh stubs that this script
# now makes real.  Everything reachable from them (minus PROVIDED, below) is
# staged real.
DIRECT_SONAMES=(
    libX11.so.6 libX11-xcb.so.1 libxcb.so.1 libxcb-shm.so.0 libXext.so.6
    libXcomposite.so.1 libXdamage.so.1 libXfixes.so.3 libXrandr.so.2
    libXrender.so.1 libXtst.so.6 libXcursor.so.1 libXi.so.6
    libgtk-3.so.0 libgdk-3.so.0 libpangocairo-1.0.so.0 libpango-1.0.so.0
    libatk-1.0.so.0 libcairo-gobject.so.2 libcairo.so.2 libgdk_pixbuf-2.0.so.0
    libgio-2.0.so.0 libgobject-2.0.so.0 libglib-2.0.so.0
)

# ── Sonames provided by sibling scripts — never overwrite, never ship here ────
PROVIDED_SONAMES=(
    libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libresolv.so.2
    ld-linux-x86-64.so.2 libstdc++.so.6 libgcc_s.so.1
    libfreetype.so.6 libfontconfig.so.1
    libdbus-1.so.3 libsystemd.so.0
)

# ── Step 1: acquire the noble closure into the reusable cache ─────────────────
acquire_noble() {
    [ -f "${UBUNTU_KEYRING}" ] || die \
        "missing ${UBUNTU_KEYRING} — install the 'ubuntu-keyring' package"
    command -v apt-get  >/dev/null || die "apt-get not found on host"
    command -v dpkg-deb >/dev/null || die "dpkg-deb not found on host"

    # Sentinel: a completed extraction with the marquee libraries present.
    local sentinel="${EXTRACT_DIR}/.gtk-real-complete"
    if [ "${FORCE}" = false ] && [ -f "${sentinel}" ] \
       && [ -e "${EXTRACT_DIR}/usr/lib/x86_64-linux-gnu/libgtk-3.so.0" ]; then
        log "noble closure already extracted in ${EXTRACT_DIR} (use --force to refresh)"
        return 0
    fi

    log "Preparing isolated apt sandbox for ${NOBLE_SUITE} in ${APTROOT}"
    rm -rf "${APTROOT}"
    mkdir -p "${APTROOT}/etc/apt/sources.list.d" \
             "${APTROOT}/etc/apt/preferences.d" \
             "${APTROOT}/var/lib/apt/lists/partial" \
             "${APTROOT}/var/cache/apt/archives/partial" \
             "${APTROOT}/var/lib/dpkg"
    # Empty dpkg status so apt-get download never assumes host state.
    : > "${APTROOT}/var/lib/dpkg/status"
    cat > "${APTROOT}/etc/apt/sources.list" <<EOF
deb [signed-by=${UBUNTU_KEYRING}] ${ARCHIVE_MIRROR} ${NOBLE_SUITE} main universe
deb [signed-by=${UBUNTU_KEYRING}] ${ARCHIVE_MIRROR} ${NOBLE_SUITE}-updates main universe
deb [signed-by=${UBUNTU_KEYRING}] ${SECURITY_MIRROR} ${NOBLE_SUITE}-security main universe
EOF

    local -a APT_OPTS=(
        -o Dir::Etc::sourcelist="${APTROOT}/etc/apt/sources.list"
        -o Dir::Etc::sourceparts="${APTROOT}/etc/apt/sources.list.d"
        -o Dir::Etc::preferencesparts="${APTROOT}/etc/apt/preferences.d"
        -o Dir::State::lists="${APTROOT}/var/lib/apt/lists"
        -o Dir::State::status="${APTROOT}/var/lib/dpkg/status"
        -o Dir::Cache="${APTROOT}/var/cache/apt"
        -o Dir::Cache::archives="${APTROOT}/var/cache/apt/archives"
        -o Acquire::Languages=none
    )

    log "apt-get update (isolated ${NOBLE_SUITE} indices)"
    apt-get "${APT_OPTS[@]}" update 2>&1 | sed 's/^/[gtk-real apt] /'

    log "Downloading ${#NOBLE_PKGS[@]} packages"
    rm -rf "${DEBS_DIR}"; mkdir -p "${DEBS_DIR}"
    ( cd "${DEBS_DIR}" && apt-get "${APT_OPTS[@]}" download "${NOBLE_PKGS[@]}" ) \
        2>&1 | sed 's/^/[gtk-real apt] /'

    log "Extracting into ${EXTRACT_DIR}"
    rm -rf "${EXTRACT_DIR}"; mkdir -p "${EXTRACT_DIR}"
    local d
    for d in "${DEBS_DIR}"/*.deb; do
        dpkg-deb -x "${d}" "${EXTRACT_DIR}"
    done
    touch "${sentinel}"
    log "Acquired $(ls "${DEBS_DIR}"/*.deb | wc -l) debs, $(find "${EXTRACT_DIR}" -name '*.so*' -type f | wc -l) .so files"
}

# ── Step 2: BFS the closure over the extracted tree and stage it ─────────────
# Python does the DT_NEEDED walk + copy, so the completeness check is exact.
stage_closure() {
    mkdir -p "${DISK_LIB64}" "${DISK_GNU}"
    FORCE="${FORCE}" \
    EXTRACT_DIR="${EXTRACT_DIR}" \
    DISK_LIB64="${DISK_LIB64}" \
    DISK_GNU="${DISK_GNU}" \
    DIRECT="${DIRECT_SONAMES[*]}" \
    PROVIDED="${PROVIDED_SONAMES[*]}" \
    python3 - <<'PYEOF'
import os, subprocess, sys, shutil

extract  = os.environ["EXTRACT_DIR"]
lib64    = os.environ["DISK_LIB64"]
gnu      = os.environ["DISK_GNU"]
force    = os.environ.get("FORCE") == "true"
direct   = os.environ["DIRECT"].split()
provided = set(os.environ["PROVIDED"].split())

# Index every real (non-symlink) .so in the extracted noble tree by soname and
# by basename, so we can resolve both "libgtk-3.so.0" and "libgtk-3.so.0.2409.32".
real_files = {}   # basename -> path (regular files only)
for root, _, files in os.walk(extract):
    for f in files:
        p = os.path.join(root, f)
        if ".so" in f and os.path.isfile(p) and not os.path.islink(p):
            real_files.setdefault(f, p)

def resolve(soname):
    """Return the path to the real file backing `soname` in the noble tree."""
    if soname in real_files:
        return real_files[soname]
    # soname is a symlink target like libX11.so.6 -> libX11.so.6.4.0; find the
    # real file whose name starts with the soname.
    cands = [p for b, p in real_files.items() if b == soname or b.startswith(soname + ".")]
    if cands:
        # Prefer the longest name (the fully-versioned real file).
        return sorted(cands, key=len)[-1]
    return None

def needed(path):
    r = subprocess.run(["readelf", "-d", path], capture_output=True, text=True)
    out = []
    for line in r.stdout.splitlines():
        if "(NEEDED)" in line and "[" in line:
            out.append(line.split("[")[-1].split("]")[0])
    return out

# BFS from the display-critical roots.
seen, queue, ship, gaps = set(), list(direct), [], []
while queue:
    s = queue.pop(0)
    if s in seen:
        continue
    seen.add(s)
    if s in provided:
        continue
    p = resolve(s)
    if p is None:
        gaps.append(s)
        continue
    ship.append((s, p))
    for n in needed(p):
        if n not in seen:
            queue.append(n)

if gaps:
    sys.stderr.write(
        "[gtk-real] ERROR: DT_NEEDED closure incomplete — these sonames are not\n"
        "[gtk-real]        present in the noble tree and are not provided by a\n"
        "[gtk-real]        sibling script:\n           " + " ".join(sorted(gaps)) + "\n"
        "[gtk-real]        Add the owning package(s) to NOBLE_PKGS and rebuild.\n")
    sys.exit(2)

def copy_lib(soname, real_src):
    real_name = os.path.basename(real_src)
    host_size = os.path.getsize(real_src)
    for d in (gnu, lib64):
        dest_real = os.path.join(d, real_name)
        if os.path.isfile(dest_real) and not force \
           and os.path.getsize(dest_real) == host_size:
            pass  # already present, same size
        else:
            shutil.copy2(real_src, dest_real)
        # (Re)create the soname symlink, evicting any stub file at that path.
        if soname != real_name:
            dest_soname = os.path.join(d, soname)
            if os.path.islink(dest_soname) or os.path.exists(dest_soname):
                os.remove(dest_soname)
            os.symlink(real_name, dest_soname)

total = 0
for soname, real_src in sorted(ship):
    copy_lib(soname, real_src)
    total += os.path.getsize(real_src)

print(f"[gtk-real] Staged {len(ship)} real shared objects "
      f"({total/1024/1024:.1f} MiB) into lib64 + lib/x86_64-linux-gnu")
# Record the closure so the caller can print / verify it.
with open(os.path.join(os.path.dirname(lib64), ".gtk-real-manifest"), "w") as mf:
    for soname, real_src in sorted(ship):
        mf.write(f"{soname}\t{os.path.basename(real_src)}\t{os.path.getsize(real_src)}\n")
PYEOF
}

# ── Step 3: sanity-check the fonts gate (owned by install-fonts-real.sh) ──────
# Real GTK needs a real fontconfig config + at least one real font for glyph
# rendering (the FCP gate).  Those are staged by install-fonts-real.sh
# (/etc/fonts/fonts.conf) and create-data-disk.sh (DejaVuSans.ttf).  We do NOT
# duplicate that here; we only WARN if they are absent so a mis-ordered build is
# caught before boot.
check_fonts() {
    local conf="${BUILD_DIR}/disk/etc/fonts/fonts.conf"
    local font="${BUILD_DIR}/disk/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    [ -f "${conf}" ] || log "  WARN: ${conf} absent — run install-fonts-real.sh (FCP fonts gate)"
    [ -f "${font}" ] || log "  WARN: ${font} absent — create-data-disk.sh stages DejaVu (FCP fonts gate)"
    [ -f "${conf}" ] && [ -f "${font}" ] && log "  fonts gate OK: fonts.conf + DejaVuSans.ttf present"
}

# ── Run ──────────────────────────────────────────────────────────────────────
log "Staging root: ${BUILD_DIR}/disk"
acquire_noble
stage_closure
check_fonts
log "Done.  Real glibc GTK3 + X11 closure overlaid; libasound / libdbus-glib-1"
log "       remain stubs (audio / deprecated DBus wrapper, not needed)."
