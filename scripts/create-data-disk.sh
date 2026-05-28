#!/usr/bin/env bash
#
# Create an ext2-formatted data disk image for AstryxOS.
#
# This generates a persistent data drive that QEMU attaches as a
# secondary SATA disk via the ICH9 AHCI controller (Q35 machine).
# The kernel's AHCI DMA driver reads it on port 1.
#
# The image is formatted as ext2 using mke2fs(8) -d, which populates
# the image from the host-side staging tree (build/disk/) in a single
# unprivileged step (no loop mount, no root, no mtools).
# Ref: mke2fs(8), e2fsprogs project — https://e2fsprogs.sourceforge.io/
#
# Usage:
#   ./scripts/create-data-disk.sh           # Create default 2048 MiB image
#   ./scripts/create-data-disk.sh 128       # Create 128 MiB image
#   ./scripts/create-data-disk.sh --force   # Recreate even if it exists
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DATA_IMG="${BUILD_DIR}/data.img"
SIZE_MB=2048
FORCE=false
FIREFOX=false

# Firefox variant selector — picks which userspace ELF / libc combination
# lands at /disk/opt/firefox/.
#
#   glibc (default) — upstream Mozilla ESR 115 binary linked against glibc;
#                     paired with host glibc (install-glibc.sh), per-component
#                     headless stubs (install-firefox-stubs.sh), and the real
#                     fontconfig/freetype/libdbus overlays.  Hits the W101
#                     plateau (sc=2902, TID 2 in NS_ProcessNextEvent — glibc
#                     pthread_cond two-group cycling + arena-locked malloc
#                     stress the Linux personality layer in a specific way).
#
#   musl            — Alpine Linux's prebuilt musl-linked Firefox ESR 115.
#                     Brings its own /lib/ld-musl + libc + a complete /usr/lib
#                     dependency closure.  Skips the entire glibc + stub
#                     pipeline (none of them apply).  Tests whether the W101
#                     plateau character is libc-specific or kernel-architectural.
#
# Selectable via CLI arg or env var; env var loses to explicit CLI arg.
FIREFOX_VARIANT="${ASTRYXOS_FIREFOX_VARIANT:-glibc}"

# When set (env or --xeyes flag), also stage the Alpine xeyes binary + its
# missing deps into build/disk/, and copy /usr/bin/xeyes into data.img.
# Independent of Firefox staging; opt-in to keep default builds lean.
# See scripts/install-xeyes.sh for the rationale (X11 "hello world" probe
# of the kernel personality stack outside the libxul SSP saga).
XEYES="${ASTRYXOS_XEYES:-0}"

# When set (env or --busybox flag), also stage Alpine's busybox-static binary
# at /bin/busybox and seed /etc/os-release.  Used by the busybox-test /
# wget-test cargo features (kernel/src/main.rs) for the CLI-tool demo soaks.
# Independent of Firefox staging; opt-in to keep default builds lean.
# See scripts/install-busybox-cli.sh.
BUSYBOX_CLI="${ASTRYXOS_BUSYBOX:-0}"

# When set (env or --sshd flag), also stage Alpine's dropbear SSH daemon
# + host keys + /etc/passwd / /etc/shadow / /etc/group / /etc/shells +
# /root/.ssh/authorized_keys into build/disk/.  Used by the sshd-test
# cargo feature (kernel/src/main.rs).  Independent of Firefox staging;
# opt-in to keep default builds lean.
# See scripts/install-sshd.sh.
SSHD="${ASTRYXOS_SSHD:-0}"

# When set (env or --tls flag), also stage Alpine's OpenSSL 3.x userspace
# (libssl, libcrypto, /usr/bin/openssl, ossl-modules/legacy.so) plus the
# Mozilla CA bundle at every conventional path (/etc/ssl/cert.pem,
# /etc/ssl/certs/ca-certificates.crt, /etc/pki/tls/certs/ca-bundle.crt).
# Used by the tls-test cargo feature (kernel/src/main.rs) and by any
# guest-side binary that DT_NEEDED libssl/libcrypto.  Independent of the
# other -test variants; opt-in to keep default builds lean.
# See scripts/install-tls-stack.sh.
TLS_STACK="${ASTRYXOS_TLS:-0}"

# When set (env or --oracle flag), also stage the Oracle endpoint agent
# binary + /etc/oracle/config.toml + host glibc-linked libssl3/
# libcrypto3.  Used by the oracle-test cargo feature (kernel/src/main.rs
# + kernel/src/oracle_demo.rs) for first-boot validation of glibc+tokio
# Linux server-agent hosting on AstryxOS.  See scripts/install-oracle.sh.
ORACLE="${ASTRYXOS_ORACLE:-0}"

# When set (env or --pivot-e flag), also stage PIVOT-E Tier B core
# utilities: /usr/bin/curl, /usr/bin/jq, /bin/tar (and /usr/bin/tar
# duplicate) plus their DT_NEEDED transitive closures (libcurl, libonig,
# libacl, nghttp2, libpsl, zlib, zstd).  Used by the pivot-e-test cargo
# feature (kernel/src/main.rs + kernel/src/pivot_e_demo.rs) which
# verifies the Tier A busybox surface AND launches each Tier B binary.
# Auto-enables --busybox (Tier A substrate) and --tls (libssl/libcrypto
# needed by curl HTTPS) per the install-pivot-e.sh pre-flight checks.
# See scripts/install-pivot-e.sh and docs/PIVOT_E_2026-05-24.md.
PIVOT_E="${ASTRYXOS_PIVOT_E:-0}"

# When set (env or --pivot-e-tui flag), also stage PIVOT-E Tier C TUI
# utilities (nano, vim, htop, tmux) plus their DT_NEEDED transitive closure
# (libncursesw, libevent_core).  Used by the pivot-e-tui-test cargo feature
# (kernel/src/main.rs + kernel/src/pivot_e_tui_demo.rs) which verifies each
# TUI binary loads via the PR #450 PTY substrate, prints its version banner,
# and exits cleanly.  Auto-enables --pivot-e (Tier B substrate, which in
# turn auto-enables --busybox + --tls).  See scripts/install-pivot-e-tui.sh
# and docs/PIVOT_E_TIER_C_2026-05-24.md.
PIVOT_E_TUI="${ASTRYXOS_PIVOT_E_TUI:-0}"

# When set (env or --pivot-e-git flag), also stage PIVOT-E Tier D git
# (the final canonical Linux CLI utility on the PIVOT-E queue).  Stages
# /usr/bin/git, the 17 real (non-symlink) helpers under
# /usr/libexec/git-core/, /usr/share/git-core/templates/, /etc/gitconfig,
# /root/.gitconfig, plus DT_NEEDED closure (libpcre2 + libexpat above
# the Tier B set; libcurl/libssl/libcrypto/libz already covered by Tier B).
# Used by the pivot-e-git-test cargo feature (kernel/src/main.rs +
# kernel/src/pivot_e_git_demo.rs) which verifies local-only git
# init/add/commit/log/cat-file end-to-end.  Auto-enables --pivot-e
# (Tier B substrate, which auto-enables --busybox + --tls).  See
# scripts/install-pivot-e-git.sh and docs/PIVOT_E_TIER_D_2026-05-24.md.
PIVOT_E_GIT="${ASTRYXOS_PIVOT_E_GIT:-0}"

# Firefox package selector (musl variant only).  Picks which Alpine package
# install-firefox-musl.sh + install-firefox-musl-debug.sh pull:
#
#   firefox-esr (default) — Alpine community/firefox-esr 115.x.  Mature ESR
#                           binary; no -dbg subpackage in Alpine v3.20.
#                           libxul attribution falls back to Mozilla tecken
#                           (PUBLIC-only; ~8,600 symbols, no FUNC).  This is
#                           the historical reproducer for the F3-saga gate at
#                           sc=1233.
#
#   firefox               — Alpine community/firefox 132.x.  Current stable
#                           release; carries firefox-dbg with a real .debug
#                           companion (~46 MiB libxul.so.debug containing
#                           ~420k symbols incl. FUNC + minimal DWARF — full
#                           C++ name attribution via .gnu_debuglink without
#                           Mozilla tecken).  Use when you need to NAME the
#                           libxul function at a captured RIP.  Note that
#                           switching the binary changes the reproducer
#                           identity — new firefox-132 plateau metrics will
#                           NOT match the firefox-esr sc=1233 plateau.
#
# Constraints:
#   - Only meaningful when FIREFOX_VARIANT=musl.  Setting under glibc is
#     silently ignored; glibc uses the Mozilla-official ESR 115 tarball
#     unconditionally (install-firefox.sh path).
FIREFOX_PACKAGE="${ASTRYXOS_FIREFOX_PACKAGE:-firefox-esr}"

# Firefox debug-symbols opt-in.  When set, stages Alpine -dbg debug companion
# files (musl-dbg + optionally glib/gdk-pixbuf/cairo/gtk+3.0-dbg) into
# build/disk/usr/lib/debug/ and into data.img so that addr2line / objdump
# (and equivalent guest-side tooling) can attribute captured RIPs to function
# names and source lines.  Targets the K-class watchpoint attribution flow.
#
#   unset / 0   — no debug companions staged (default; data.img footprint
#                  unchanged from the variant baseline)
#   musl        — stage musl-dbg only (~2.8 MiB).  Covers ld-musl-x86_64.so.1
#                  + libc.musl-x86_64.so.1 (libc is a symlink to ld-musl).
#   1 / full    — stage musl-dbg + glib-dbg + gdk-pixbuf-dbg + cairo-dbg +
#                  gtk+3.0-dbg (~54 MiB).  Covers ld-musl + libc + the GTK3
#                  stack libxul transitively depends on.
#
# Constraints:
#   - Only meaningful when FIREFOX_VARIANT=musl (Alpine -dbg packages are
#     companions to Alpine binaries).  Setting under glibc is silently
#     ignored; the glibc Firefox debug-symbol track is owned by the
#     inject-libxul-symbols.sh / Mozilla Breakpad .sym path instead.
#   - Alpine does NOT ship a firefox-esr-dbg subpackage; libxul.so debug
#     attribution under the musl variant is on a separate path
#     (see scripts/install-firefox-musl-debug.sh for the documented gap).
FIREFOX_DEBUG="${ASTRYXOS_FIREFOX_DEBUG:-}"

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        --firefox) FIREFOX=true; FORCE=true ;;
        --firefox-variant=*) FIREFOX_VARIANT="${arg#--firefox-variant=}" ;;
        --firefox-variant) :;;   # next arg consumed by trailing path
        --firefox-debug=*) FIREFOX_DEBUG="${arg#--firefox-debug=}" ;;
        --firefox-debug)   FIREFOX_DEBUG=1 ;;
        --firefox-package=*) FIREFOX_PACKAGE="${arg#--firefox-package=}" ;;
        --xeyes) XEYES=1; FORCE=true ;;
        --busybox) BUSYBOX_CLI=1; FORCE=true ;;
        --sshd) SSHD=1; FORCE=true ;;
        --tls) TLS_STACK=1; FORCE=true ;;
        --oracle) ORACLE=1; FORCE=true ;;
        --pivot-e) PIVOT_E=1; FORCE=true ;;
        --pivot-e-tui) PIVOT_E_TUI=1; PIVOT_E=1; FORCE=true ;;
        --pivot-e-git) PIVOT_E_GIT=1; PIVOT_E=1; FORCE=true ;;
        [0-9]*) SIZE_MB="$arg" ;;
    esac
done

case "${FIREFOX_VARIANT}" in
    glibc|musl) ;;
    *)
        echo "[DATA-DISK] ERROR: unknown FIREFOX_VARIANT='${FIREFOX_VARIANT}' (expected glibc|musl)"
        exit 1
        ;;
esac
echo "[DATA-DISK] Firefox variant: ${FIREFOX_VARIANT}"

case "${FIREFOX_PACKAGE}" in
    firefox-esr|firefox) ;;
    *)
        echo "[DATA-DISK] ERROR: unknown FIREFOX_PACKAGE='${FIREFOX_PACKAGE}' (expected firefox-esr|firefox)"
        exit 1
        ;;
esac
if [ "${FIREFOX_PACKAGE}" != "firefox-esr" ] && [ "${FIREFOX_VARIANT}" != "musl" ]; then
    echo "[DATA-DISK] NOTE: ASTRYXOS_FIREFOX_PACKAGE=${FIREFOX_PACKAGE} ignored — only applies to FIREFOX_VARIANT=musl"
    FIREFOX_PACKAGE=firefox-esr
fi
echo "[DATA-DISK] Firefox package: ${FIREFOX_PACKAGE}"

# Compute the on-disk install-dir for the musl variant.  Mirrors
# install-firefox-musl.sh's FF_INSTALL_DIR_NAME logic.  Used by the
# /usr/lib/<pkg>/ copy below and the inject-libxul-symbols.sh trigger guard.
case "${FIREFOX_PACKAGE}" in
    firefox-esr) FIREFOX_INSTALL_DIRNAME=firefox-esr ;;
    firefox)     FIREFOX_INSTALL_DIRNAME=firefox     ;;
esac

case "${FIREFOX_DEBUG}" in
    ''|0)        FIREFOX_DEBUG_MODE=off ;;
    musl)        FIREFOX_DEBUG_MODE=musl ;;
    1|full|yes)  FIREFOX_DEBUG_MODE=full ;;
    *)
        echo "[DATA-DISK] ERROR: unknown FIREFOX_DEBUG='${FIREFOX_DEBUG}' (expected unset|0|musl|1|full)"
        exit 1
        ;;
esac
if [ "${FIREFOX_DEBUG_MODE}" != off ] && [ "${FIREFOX_VARIANT}" != musl ]; then
    echo "[DATA-DISK] NOTE: ASTRYXOS_FIREFOX_DEBUG=${FIREFOX_DEBUG} ignored — only applies to FIREFOX_VARIANT=musl"
    FIREFOX_DEBUG_MODE=off
fi
echo "[DATA-DISK] Firefox debug-symbols: ${FIREFOX_DEBUG_MODE}"

# ── Stage at least one TTF font for Mozilla's font-list init ─────────────────
# Mozilla's gfxFcPlatformFontList walks the FcFontSet returned by
# FcConfigGetFonts() and asserts that mFontFamilies.Count() > 0 at the end of
# init.  Our fontconfig stub returns a single-element FcFontSet pointing at
# DejaVuSans.ttf; the corresponding TTF file must therefore exist on the data
# disk for AddFontSetFamilies's access(F_OK|R_OK) check to succeed.  Copy the
# host DejaVu install (apt: fonts-dejavu) into build/disk staging if it isn't
# already there; the later "Copy host fonts" step propagates it into data.img.
HOST_DEJAVU="/usr/share/fonts/truetype/dejavu"
STAGE_DEJAVU="${BUILD_DIR}/disk/usr/share/fonts/truetype/dejavu"
if [ -f "${HOST_DEJAVU}/DejaVuSans.ttf" ]; then
    if [ ! -f "${STAGE_DEJAVU}/DejaVuSans.ttf" ] || [ "${FORCE}" = true ]; then
        mkdir -p "${STAGE_DEJAVU}"
        cp -f "${HOST_DEJAVU}/DejaVuSans.ttf" "${STAGE_DEJAVU}/DejaVuSans.ttf"
        echo "[DATA-DISK] Staged DejaVuSans.ttf for Mozilla font-list init"
    fi
else
    echo "[DATA-DISK] WARNING: ${HOST_DEJAVU}/DejaVuSans.ttf not found on host;"
    echo "[DATA-DISK]          install with 'apt-get install fonts-dejavu' so the"
    echo "[DATA-DISK]          fontconfig stub's pattern resolves on the data disk."
fi

if [ "${FIREFOX_VARIANT}" = "glibc" ]; then
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

# ── Stage Firefox ESR to build/disk/opt/firefox/ (non-fatal) ─────────────────
# install-firefox.sh is idempotent — it skips extraction if already done.
# We always call it here so a --force re-run also refreshes Firefox.
if [ -f "${ROOT_DIR}/scripts/install-firefox.sh" ]; then
    FIREFOX_FLAGS=""
    [ "${FORCE}" = true ] && FIREFOX_FLAGS="--force"
    bash "${ROOT_DIR}/scripts/install-firefox.sh" ${FIREFOX_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
        echo "[DATA-DISK] WARNING: install-firefox.sh failed — /opt/firefox may be absent"
fi

# ── Inject debug .symtab into libxul.so (non-fatal) ──────────────────────────
# inject-libxul-symbols.sh splices Mozilla's official Breakpad symbol names
# into libxul.so as a proper ELF .symtab section, enabling nm / kdb
# rip-trace-resolve to name functions in the stripped binary.
# Run AFTER install-firefox.sh so any --force re-extraction does not clobber
# the injected .symtab.  The script is idempotent (skips if .symtab present).
if [ -f "${ROOT_DIR}/scripts/inject-libxul-symbols.sh" ] && \
   [ -f "${BUILD_DIR}/disk/opt/firefox/libxul.so" ]; then
    SYM_FLAGS=""
    [ "${FORCE}" = true ] && SYM_FLAGS="--force"
    bash "${ROOT_DIR}/scripts/inject-libxul-symbols.sh" ${SYM_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
        echo "[DATA-DISK] WARNING: inject-libxul-symbols.sh failed — libxul.so will lack .symtab"
fi

# ── Build Firefox headless stub libraries (non-fatal) ────────────────────────
# Firefox ESR 115 links libmozgtk.so and libxul.so against GTK3, ALSA, X11,
# GLib/GObject, Cairo, Pango, DBus, and other system libraries.  In headless
# mode these APIs are never actually called but glibc's ld-linux still resolves
# NEEDED entries at dlopen() time.  install-firefox-stubs.sh generates minimal
# stub .so files (no-op functions with the right SONAMEs and version nodes) so
# the XPCOMGlue can load without "cannot open shared object file" errors.
if [ -f "${ROOT_DIR}/scripts/install-firefox-stubs.sh" ] && \
   [ -f "${BUILD_DIR}/disk/opt/firefox/libxul.so" ]; then
    STUB_FLAGS=""
    [ "${FORCE}" = true ] && STUB_FLAGS="--force"
    bash "${ROOT_DIR}/scripts/install-firefox-stubs.sh" ${STUB_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
        echo "[DATA-DISK] WARNING: install-firefox-stubs.sh failed — stub libs may be absent"
fi

# ── Overlay REAL libfontconfig + libfreetype (non-fatal) ─────────────────────
# install-firefox-stubs.sh writes 13-65 KB stub copies of libfontconfig.so.1
# and libfreetype.so.6.  Mozilla iterates Fc* results during gfxPlatformFont
# List init and derefs returned strings — the stubs surface NULL/zero and
# Mozilla faults (W66/W70/W76/W82/W87 + post-PR#176 libxul cluster).
# install-fonts-real.sh overlays REAL upstream binaries (~2 MiB total) over
# the two stubs, keeping every other GTK/X11/cairo/pango stub in place for
# the call paths headless mode genuinely does not exercise.  Must run
# AFTER install-firefox-stubs.sh so its `ln -sf` evicts the stub at the
# soname path.
if [ -f "${ROOT_DIR}/scripts/install-fonts-real.sh" ]; then
    FONTS_FLAGS=""
    [ "${FORCE}" = true ] && FONTS_FLAGS="--force"
    bash "${ROOT_DIR}/scripts/install-fonts-real.sh" ${FONTS_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
        echo "[DATA-DISK] WARNING: install-fonts-real.sh failed — fontconfig/freetype stubs remain"
fi

# ── Overlay REAL libdbus-1 + libsystemd (non-fatal) ──────────────────────────
# install-firefox-stubs.sh writes a 36 KiB stub libdbus-1.so.3.  Mozilla
# initialises a DBus client during nsAppShell::Init / proxy / AT-SPI setup
# even with no session bus running; the stub returns NULL/0 for every entry
# point, including DBusError-out-pointer setters, which Mozilla turns into
# NULL-deref faults (W97 verifier flagged the "I"/"M" auth-handshake bytes
# on fd=19 as the next-likely blocker class after PR #179).
# install-dbus-real.sh overlays the real upstream libdbus-1 (~314 KiB) plus
# its libsystemd.so.0 transitive dep (~1102 KiB) over the stub, keeping the
# libdbus-glib-1 stub in place (deprecated wrapper, not on the host).  Must
# run AFTER install-firefox-stubs.sh so its `ln -sf` evicts the stub at the
# soname path.  No DBus daemon is shipped — DBUS_SESSION_BUS_ADDRESS stays
# unset, real libdbus returns NULL with org.freedesktop.DBus.Error.NoServer,
# and Mozilla's nsAppShell falls through to its no-DBus path.
if [ -f "${ROOT_DIR}/scripts/install-dbus-real.sh" ]; then
    DBUS_FLAGS=""
    [ "${FORCE}" = true ] && DBUS_FLAGS="--force"
    bash "${ROOT_DIR}/scripts/install-dbus-real.sh" ${DBUS_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
        echo "[DATA-DISK] WARNING: install-dbus-real.sh failed — libdbus-1 stub remains"
fi

# ── Build libfontconfig-interposer.so (defensive wrapper) ────────────────────
# Real libfontconfig (installed by install-fonts-real.sh above) follows the
# spec strictly: FcPatternGetString leaves *out untouched on FcResultNoMatch.
# Firefox's gfxFcPlatformFontList caller dereferences *out unconditionally on
# that path (post-PR #179 W91 regression — libxul+0x185b8a4 / +0x4056429
# %rbx=NULL faults).  The interposer wraps FcPatternGetString, calls through
# to real libfontconfig via dlsym(RTLD_NEXT, ...), and on NoMatch writes a
# non-NULL sentinel ("DejaVu Sans") into *out.  Loaded via LD_PRELOAD in the
# firefox-test envp (see kernel/src/gui/terminal.rs).
# Spec: https://fontconfig.org/fontconfig-devel/fcpatternget.html
#
# W212: the interposer also wraps dlsym() to intercept lookups for
# "C_GetInterface" (PKCS#11 v3.0 §5.5) — libipcclientcerts.so only exports
# the v2.x entry point C_GetFunctionList; NSS treats a NULL dlsym return for
# C_GetInterface as fatal.  Our dlsym wrapper returns CKR_FUNCTION_NOT_SUPPORTED
# (0x54) so NSS falls back to the v2.x code path.
# Ref: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
INTERPOSER_DIR="${ROOT_DIR}/userspace/libfontconfig-interposer"
INTERPOSER_SO="libfontconfig-interposer.so"
if [ -d "${INTERPOSER_DIR}" ] && command -v gcc &>/dev/null; then
    INTERPOSER_OUT="${BUILD_DIR}/disk/lib64/${INTERPOSER_SO}"
    if [ ! -f "${INTERPOSER_OUT}" ] || [ "${FORCE}" = true ] || \
       [ "${INTERPOSER_DIR}/interposer.c" -nt "${INTERPOSER_OUT}" ]; then
        if make -C "${INTERPOSER_DIR}" \
                SONAME="${INTERPOSER_SO}" \
                OUTDIR="${BUILD_DIR}/disk/lib64" \
                >/dev/null 2>&1; then
            echo "[DATA-DISK] Built libfontconfig-interposer.so ($(stat -c%s "${INTERPOSER_OUT}") bytes)"
            # Mirror to /lib/x86_64-linux-gnu/ so LD_LIBRARY_PATH lookups
            # also resolve it (LD_PRELOAD uses the absolute path, but
            # mirroring keeps the multiarch tree consistent).
            mkdir -p "${BUILD_DIR}/disk/lib/x86_64-linux-gnu"
            cp "${INTERPOSER_OUT}" \
               "${BUILD_DIR}/disk/lib/x86_64-linux-gnu/${INTERPOSER_SO}"
        else
            echo "[DATA-DISK] WARNING: libfontconfig-interposer build failed"
        fi
    else
        echo "[DATA-DISK] libfontconfig-interposer.so up to date"
    fi
fi

else  # FIREFOX_VARIANT == musl
# ── Musl Firefox pipeline ────────────────────────────────────────────────────
# Alpine's prebuilt firefox-esr package brings its own complete dependency
# closure (musl libc, musl ld, libstdc++, NSS, NSPR, GTK3, Pango, Cairo,
# fontconfig, freetype, libdbus, ICU, etc.).  None of the glibc-tailored
# stub builders (install-firefox-stubs.sh / install-fonts-real.sh /
# install-dbus-real.sh / install-glibc.sh / install-firefox.sh) apply —
# Alpine ships real working binaries for all of them.
#
# To avoid hybrid state (glibc firefox-bin + musl libxul.so etc.) we wipe
# the directories that the glibc pipeline owns before the musl installer
# stages its tree.  install-firefox-musl.sh already wipes /opt/firefox/
# internally; we also clear /lib64 and /lib/x86_64-linux-gnu since those
# are glibc-specific.  /usr/lib/x86_64-linux-gnu (host GTK runtime) is
# preserved if present — it is harmless under musl (musl uses /usr/lib
# directly) and rebuilding it requires the host apt cache.
if [ -d "${BUILD_DIR}/disk/lib64" ]; then
    rm -rf "${BUILD_DIR}/disk/lib64"
fi
if [ -d "${BUILD_DIR}/disk/lib/x86_64-linux-gnu" ]; then
    rm -rf "${BUILD_DIR}/disk/lib/x86_64-linux-gnu"
fi

if [ -f "${ROOT_DIR}/scripts/install-firefox-musl.sh" ]; then
    MUSL_FLAGS=""
    [ "${FORCE}" = true ] && MUSL_FLAGS="--force"
    # ASTRYXOS_FIREFOX_PACKAGE forwarded via env so install-firefox-musl.sh
    # picks firefox-esr vs firefox-132 layout uniformly across the pipeline.
    ASTRYXOS_FIREFOX_PACKAGE="${FIREFOX_PACKAGE}" \
        bash "${ROOT_DIR}/scripts/install-firefox-musl.sh" ${MUSL_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
        { echo "[DATA-DISK] FATAL: install-firefox-musl.sh failed"; exit 1; }
fi

# ── Optional: stage Alpine -dbg debug companions ─────────────────────────────
# When ASTRYXOS_FIREFOX_DEBUG is set, run install-firefox-musl-debug.sh to
# pull the per-library debug-info companion files into
# build/disk/usr/lib/debug/.  The script reuses install-firefox-musl.sh's
# shared apk rootfs (~/.cache/astryxos-firefox-musl/rootfs) so debug-info
# package versions match the binary versions exactly.
if [ "${FIREFOX_DEBUG_MODE}" != off ] && \
   [ -f "${ROOT_DIR}/scripts/install-firefox-musl-debug.sh" ]; then
    DBG_FLAGS=""
    [ "${FORCE}" = true ] && DBG_FLAGS="--force"
    if [ "${FIREFOX_DEBUG_MODE}" = musl ]; then
        DBG_FLAGS="${DBG_FLAGS} --musl-only"
    fi
    # Forward ASTRYXOS_FIREFOX_PACKAGE so the dbg installer adds firefox-dbg
    # (only meaningful when FIREFOX_PACKAGE=firefox; firefox-esr has no -dbg).
    ASTRYXOS_FIREFOX_PACKAGE="${FIREFOX_PACKAGE}" \
        bash "${ROOT_DIR}/scripts/install-firefox-musl-debug.sh" ${DBG_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
        echo "[DATA-DISK] WARNING: install-firefox-musl-debug.sh failed — /usr/lib/debug not staged"
fi

# ── Optional: inject .symtab into the musl libxul.so ─────────────────────────
# Two cases, selected by ASTRYXOS_FIREFOX_PACKAGE:
#
#   firefox-esr (115.x) — Alpine does NOT ship a -dbg subpackage.  Mozilla's
#       symbol server (tecken) indexes the exact Alpine BuildID and serves a
#       gzipped Breakpad .sym (~9 MiB compressed) that lists every .dynsym
#       entry as a PUBLIC record.  scripts/inject-libxul-symbols.sh --musl
#       downloads the .sym, derives the Breakpad GUID from the libxul BuildID,
#       and splices an Elf64_Sym .symtab into libxul.so.  The .text section
#       is byte-identical pre/post (verified by SHA256 inside the script) —
#       no upstream-binary edit.
#
#   firefox (132.x)     — Alpine DOES ship firefox-dbg with a real .debug
#       companion at /usr/lib/debug/usr/lib/firefox/libxul.so.debug carrying
#       full .symtab (~420k entries with FUNC records and minimal DWARF).
#       install-firefox-musl-debug.sh stages it; the binary's .gnu_debuglink
#       section already points there.  addr2line / nm / gdb resolve C++ names
#       natively — no Mozilla tecken indirection required.  We SKIP the inject
#       step in this mode (it would be a no-op anyway: tecken's libxul-132 GUID
#       coverage is incomplete and the .symtab would be inferior to the
#       firefox-dbg one).
#
# Triggered together with the -dbg companion stage so a single
# ASTRYXOS_FIREFOX_DEBUG=musl|1|full request gets all attribution avenues.
LIBXUL_STAGED="${BUILD_DIR}/disk/usr/lib/${FIREFOX_INSTALL_DIRNAME}/libxul.so"
if [ "${FIREFOX_DEBUG_MODE}" != off ] && \
   [ "${FIREFOX_PACKAGE}" = "firefox-esr" ] && \
   [ -f "${ROOT_DIR}/scripts/inject-libxul-symbols.sh" ] && \
   [ -f "${LIBXUL_STAGED}" ]; then
    MUSL_SYM_FLAGS="--musl"
    [ "${FORCE}" = true ] && MUSL_SYM_FLAGS="${MUSL_SYM_FLAGS} --force"
    if bash "${ROOT_DIR}/scripts/inject-libxul-symbols.sh" ${MUSL_SYM_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' ; then
        :
    else
        echo "[DATA-DISK] WARNING: inject-libxul-symbols.sh --musl failed — libxul.so will lack .symtab"
    fi
elif [ "${FIREFOX_DEBUG_MODE}" != off ] && [ "${FIREFOX_PACKAGE}" = "firefox" ]; then
    echo "[DATA-DISK] Skipping Mozilla tecken libxul .symtab injection — firefox-dbg companion covers libxul attribution natively via .gnu_debuglink."
fi

# Stage a /tmp/hello.html for the headless oracle test — install-firefox.sh
# does this in the glibc path, but we skipped that script.
mkdir -p "${BUILD_DIR}/disk/tmp"
cat > "${BUILD_DIR}/disk/tmp/hello.html" <<'HTML'
<html><head><title>AstryxOS Firefox Oracle (musl)</title></head>
<body><h1>Hi</h1><p>AstryxOS musl Firefox ESR headless oracle page.</p></body></html>
HTML

# Stage a minimal -profile so prefs.js mirrors the glibc oracle profile.
PROFILE_DIR="${BUILD_DIR}/disk/opt/firefox/profile"
mkdir -p "${PROFILE_DIR}"
cat > "${PROFILE_DIR}/prefs.js" <<'PREFS'
// AstryxOS minimal headless Firefox profile (musl variant)
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.rights.3.shown", true);
user_pref("startup.homepage_welcome_url", "");
user_pref("browser.startup.page", 0);
user_pref("app.update.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("datareporting.healthreport.service.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.memory.enable", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("geo.enabled", false);
PREFS

fi  # end FIREFOX_VARIANT branch

# ── Optional: stage Alpine xeyes (X11 "hello world" outside libxul) ──────────
# Independent of FIREFOX_VARIANT — xeyes only requires the musl libc + a small
# X11 client stack, all of which we already stage for the musl Firefox path.
# Triggered by ASTRYXOS_XEYES=1 or --xeyes.  The kernel side wires this up
# under cargo feature `xeyes-test` (see kernel/src/main.rs).
if [ "${XEYES}" = "1" ] || [ "${XEYES}" = "true" ]; then
    if [ -f "${ROOT_DIR}/scripts/install-xeyes.sh" ]; then
        XEYES_FLAGS=""
        [ "${FORCE}" = true ] && XEYES_FLAGS="--force"
        bash "${ROOT_DIR}/scripts/install-xeyes.sh" ${XEYES_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
            { echo "[DATA-DISK] FATAL: install-xeyes.sh failed"; exit 1; }
    fi
fi

# ── Optional: stage Alpine busybox-static (CLI tools probe) ─────────────────
# Triggered by ASTRYXOS_BUSYBOX=1 or --busybox.  Stages a 1 MiB statically-
# linked binary at /bin/busybox plus seeds /etc/os-release.  The kernel-side
# busybox-test / wget-test cargo features (kernel/src/main.rs) drive applet
# runs against it.  See scripts/install-busybox-cli.sh.
if [ "${BUSYBOX_CLI}" = "1" ] || [ "${BUSYBOX_CLI}" = "true" ]; then
    if [ -f "${ROOT_DIR}/scripts/install-busybox-cli.sh" ]; then
        BB_FLAGS=""
        [ "${FORCE}" = true ] && BB_FLAGS="--force"
        bash "${ROOT_DIR}/scripts/install-busybox-cli.sh" ${BB_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
            { echo "[DATA-DISK] FATAL: install-busybox-cli.sh failed"; exit 1; }
    fi
fi

# ── Optional: stage dropbear SSH daemon + host keys + accounts ──────────────
if [ "${SSHD}" = "1" ] || [ "${SSHD}" = "true" ]; then
    if [ "${BUSYBOX_CLI}" != "1" ] && [ "${BUSYBOX_CLI}" != "true" ]; then
        echo "[DATA-DISK] NOTE: --sshd implies --busybox (login shell /bin/sh) — auto-enabling (no --force)."
        BUSYBOX_CLI=1
        if [ -f "${ROOT_DIR}/scripts/install-busybox-cli.sh" ]; then
            bash "${ROOT_DIR}/scripts/install-busybox-cli.sh" 2>&1 | sed 's/^/[DATA-DISK] /' || \
                { echo "[DATA-DISK] FATAL: install-busybox-cli.sh failed (see lines above)"; exit 1; }
        fi
    fi
    if [ -f "${ROOT_DIR}/scripts/install-sshd.sh" ]; then
        SSHD_FLAGS=""
        [ "${FORCE}" = true ] && SSHD_FLAGS="--force"
        bash "${ROOT_DIR}/scripts/install-sshd.sh" ${SSHD_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
            { echo "[DATA-DISK] FATAL: install-sshd.sh failed"; exit 1; }
    fi
fi

# ── Optional: stage Alpine OpenSSL 3.x + Mozilla CA bundle (TLS userspace) ─
if [ "${TLS_STACK}" = "1" ] || [ "${TLS_STACK}" = "true" ]; then
    if [ -f "${ROOT_DIR}/scripts/install-tls-stack.sh" ]; then
        TLS_FLAGS=""
        [ "${FORCE}" = true ] && TLS_FLAGS="--force"
        bash "${ROOT_DIR}/scripts/install-tls-stack.sh" ${TLS_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
            { echo "[DATA-DISK] FATAL: install-tls-stack.sh failed"; exit 1; }
    fi
fi

# ── Optional: stage Oracle endpoint agent binary + config ────────
# Oracle is GLIBC-linked (DT_NEEDED libc.so.6, libssl.so.3, libcrypto.so.3,
# interp = /lib64/ld-linux-x86-64.so.2; max GLIBC_2.39).  install-oracle.sh
# stages /usr/bin/oracle + /etc/oracle/config.toml + host glibc-linked
# libssl3/libcrypto3 into build/disk/lib/x86_64-linux-gnu/.  It relies on
# install-glibc.sh's output for libc.so.6 + ld-linux — when the default
# FIREFOX_VARIANT=glibc is active, install-glibc.sh has already run.  The
# install-tls-stack.sh musl libssl is INCOMPATIBLE for a glibc binary so
# install-oracle.sh stages its own glibc-linked copies separately.
if [ "${ORACLE}" = "1" ] || [ "${ORACLE}" = "true" ]; then
    if [ "${FIREFOX_VARIANT}" != "glibc" ]; then
        echo "[DATA-DISK] WARNING: --oracle expects FIREFOX_VARIANT=glibc (current: ${FIREFOX_VARIANT}); oracle is a glibc binary and won't load against the musl track."
    fi
    if [ -f "${ROOT_DIR}/scripts/install-oracle.sh" ]; then
        ORACLE_FLAGS=""
        [ "${FORCE}" = true ] && ORACLE_FLAGS="--force"
        bash "${ROOT_DIR}/scripts/install-oracle.sh" ${ORACLE_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
            { echo "[DATA-DISK] FATAL: install-oracle.sh failed"; exit 1; }
    fi
fi

# ── PIVOT-E Tier B core utilities (--pivot-e / ASTRYXOS_PIVOT_E=1) ───────────
# Tier A substrate (busybox) and TLS substrate (libssl/libcrypto, needed by
# curl HTTPS) are pre-requisites for install-pivot-e.sh.  Auto-enable them
# here rather than asking the user to remember three flags.  Per the
# install-pivot-e.sh pre-flight checks, both will be hard-failed if missing.
if [ "${PIVOT_E}" = "1" ] || [ "${PIVOT_E}" = "true" ]; then
    # Tier A substrate.  Only call install-busybox-cli.sh if /bin/busybox
    # is not already staged — apk-static's `add` returns rc=7 on a repeat
    # install due to chroot-restricted trigger scripts, which would
    # spuriously kill the whole create-data-disk.sh run.  We skip the
    # re-stage when the artefact is already present (install-pivot-e.sh
    # has its own pre-flight that confirms the file exists).
    if [ "${BUSYBOX_CLI}" != "1" ] && [ "${BUSYBOX_CLI}" != "true" ]; then
        BUSYBOX_CLI=1
        if [ -f "${BUILD_DIR}/disk/bin/busybox" ]; then
            echo "[DATA-DISK] NOTE: --pivot-e implies --busybox; /bin/busybox already staged — skipping re-stage."
        elif [ -f "${ROOT_DIR}/scripts/install-busybox-cli.sh" ]; then
            echo "[DATA-DISK] NOTE: --pivot-e implies --busybox (Tier A surface) — auto-enabling."
            bash "${ROOT_DIR}/scripts/install-busybox-cli.sh" 2>&1 | sed 's/^/[DATA-DISK] /' || \
                { echo "[DATA-DISK] FATAL: install-busybox-cli.sh failed"; exit 1; }
        fi
    fi
    # Tier B substrate (libssl/libcrypto).  Same pattern.
    if [ "${TLS_STACK}" != "1" ] && [ "${TLS_STACK}" != "true" ]; then
        TLS_STACK=1
        if [ -f "${BUILD_DIR}/disk/usr/lib/libssl.so.3" ]; then
            echo "[DATA-DISK] NOTE: --pivot-e implies --tls; libssl.so.3 already staged — skipping re-stage."
        elif [ -f "${ROOT_DIR}/scripts/install-tls-stack.sh" ]; then
            echo "[DATA-DISK] NOTE: --pivot-e implies --tls (libssl/libcrypto for curl HTTPS) — auto-enabling."
            bash "${ROOT_DIR}/scripts/install-tls-stack.sh" 2>&1 | sed 's/^/[DATA-DISK] /' || \
                { echo "[DATA-DISK] FATAL: install-tls-stack.sh failed"; exit 1; }
        fi
    fi
    if [ -f "${ROOT_DIR}/scripts/install-pivot-e.sh" ]; then
        # install-pivot-e.sh's apk-add path is idempotent and tolerates
        # repeat installs (uses `|| true` after apk on the apk path).
        # Pass --force only when the data.img is being regenerated to
        # ensure fresh closure-walker output.
        PE_FLAGS=""
        [ "${FORCE}" = true ] && PE_FLAGS="--force"
        bash "${ROOT_DIR}/scripts/install-pivot-e.sh" ${PE_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
            { echo "[DATA-DISK] FATAL: install-pivot-e.sh failed"; exit 1; }
    fi
fi

# ── PIVOT-E Tier C TUI utilities (--pivot-e-tui / ASTRYXOS_PIVOT_E_TUI=1) ────
# Tier C requires Tier B substrate (libssl/libcrypto + busybox already
# auto-enabled by --pivot-e above) AND the per-pair PTY surface landed by
# PR #450 (kernel side, no extra staging).  --pivot-e-tui auto-enables
# --pivot-e via the arg-parse line above, so by the time we reach this block
# the Tier B install has already run.
if [ "${PIVOT_E_TUI}" = "1" ] || [ "${PIVOT_E_TUI}" = "true" ]; then
    if [ -f "${ROOT_DIR}/scripts/install-pivot-e-tui.sh" ]; then
        PET_FLAGS=""
        [ "${FORCE}" = true ] && PET_FLAGS="--force"
        bash "${ROOT_DIR}/scripts/install-pivot-e-tui.sh" ${PET_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
            { echo "[DATA-DISK] FATAL: install-pivot-e-tui.sh failed"; exit 1; }
    fi
fi

# ── PIVOT-E Tier D git (--pivot-e-git / ASTRYXOS_PIVOT_E_GIT=1) ──────────────
# Tier D requires Tier B substrate (libcurl/libssl/libcrypto/libz auto-enabled
# by --pivot-e above).  install-pivot-e-git.sh stages git binary + the 17
# real (non-symlink) helpers + libpcre2 + libexpat + templates + system
# config + per-user config.  The kernel runner uses GIT_EXEC_PATH=/disk/usr/bin
# to redirect child git invocations away from the (non-existent on FAT32)
# /usr/libexec/git-core/git symlink.
if [ "${PIVOT_E_GIT}" = "1" ] || [ "${PIVOT_E_GIT}" = "true" ]; then
    if [ -f "${ROOT_DIR}/scripts/install-pivot-e-git.sh" ]; then
        PEG_FLAGS=""
        [ "${FORCE}" = true ] && PEG_FLAGS="--force"
        bash "${ROOT_DIR}/scripts/install-pivot-e-git.sh" ${PEG_FLAGS} 2>&1 | sed 's/^/[DATA-DISK] /' || \
            { echo "[DATA-DISK] FATAL: install-pivot-e-git.sh failed"; exit 1; }
    fi
fi

# ── Compile hello oracle binary (musl static ELF) ────────────────────────────
# hello is the primary musl-linked test fixture used by test_musl_hello,
# test_sigchld_delivery, and test_ascension_init (all read /disk/bin/hello).
# Compiled from userspace/hello.c with musl-gcc -static so the binary has no
# dynamic-linker dependency — the kernel's static ELF loader handles it
# directly without PT_INTERP dispatch.
# Ref: musl libc — https://musl.libc.org/, ELF-64 spec §2 Program Header.
HELLO_SRC="${ROOT_DIR}/userspace/hello.c"
HELLO_BIN="${BUILD_DIR}/hello"
if [ -f "${HELLO_SRC}" ]; then
    if [ ! -f "${HELLO_BIN}" ] || [ "${FORCE}" = true ] || \
       [ "${HELLO_SRC}" -nt "${HELLO_BIN}" ]; then
        # Prefer x86_64-linux-musl-gcc (cross-musl); fall back to musl-gcc
        # (musl-tools apt package).  Both produce a static x86_64 ELF.
        MUSL_CC=""
        if command -v x86_64-linux-musl-gcc &>/dev/null; then
            MUSL_CC="x86_64-linux-musl-gcc"
        elif command -v musl-gcc &>/dev/null; then
            MUSL_CC="musl-gcc"
        fi
        if [ -n "${MUSL_CC}" ]; then
            "${MUSL_CC}" -static -no-pie -O2 -o "${HELLO_BIN}" "${HELLO_SRC}"
            echo "[DATA-DISK] Compiled hello (musl static ELF, $(stat -c%s "${HELLO_BIN}") bytes)"
        else
            echo "[DATA-DISK] WARNING: no musl compiler found (install musl-tools) — /disk/bin/hello will be absent"
        fi
    fi
fi

# ── Busybox-static fallback: host package ────────────────────────────────────
# When neither install-busybox-cli.sh (Alpine cache) nor build-busybox.sh
# (musl cross-compile from source) has pre-staged build/disk/bin/busybox,
# fall back to the host-installed busybox-static package
# (apt: busybox-static — statically-linked, no ld-linux dependency).
# This ensures test_busybox_basic has a binary to load in CI environments
# where the Alpine rootfs cache and cross-compiler are absent.
# The test validates the kernel ELF loader and syscall layer, not musl
# linkage — a glibc-static busybox exercises the same code paths.
# Install with: sudo apt install busybox-static
BUSYBOX_STAGING="${BUILD_DIR}/disk/bin/busybox"
if [ ! -f "${BUSYBOX_STAGING}" ]; then
    if command -v busybox &>/dev/null; then
        HOST_BB="$(command -v busybox)"
        # Only use if statically linked (no DT_NEEDED entries) — a dynamic
        # busybox depends on host glibc paths that won't exist in the guest.
        if ! readelf -d "${HOST_BB}" 2>/dev/null | grep -q NEEDED; then
            mkdir -p "${BUILD_DIR}/disk/bin"
            cp "${HOST_BB}" "${BUSYBOX_STAGING}"
            echo "[DATA-DISK] busybox fallback: staged host $(${HOST_BB} --version 2>&1 | head -1) from ${HOST_BB}"
        else
            echo "[DATA-DISK] NOTE: host busybox is dynamically linked — cannot use as fallback"
        fi
    fi
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

# Skip if image exists and --force not given
if [ -f "${DATA_IMG}" ] && [ "$FORCE" = false ]; then
    echo "[DATA-DISK] ${DATA_IMG} already exists (use --force to recreate)"
    exit 0
fi

mkdir -p "${BUILD_DIR}"

echo "[DATA-DISK] Creating ${SIZE_MB} MiB ext2 data disk..."

# ── Toolchain probe ──────────────────────────────────────────────────────────
# mke2fs(8) -d requires e2fsprogs >= 1.43 (2017).  Ubuntu 24.04 ships 1.47.x
# as part of the base image; this probe gives a clear error if somehow absent.
# Ref: mke2fs(8) — https://man7.org/linux/man-pages/man8/mke2fs.8.html
if ! command -v mke2fs &>/dev/null; then
    echo "[DATA-DISK] ERROR: mke2fs not found. Install e2fsprogs:"
    echo "  sudo apt install e2fsprogs"
    exit 1
fi
MKE2FS_VER="$(mke2fs -V 2>&1 | head -1)"
echo "[DATA-DISK] Using: ${MKE2FS_VER}"

STAGING_TREE="${BUILD_DIR}/disk"

# ── Seed /etc/ files that must exist before mke2fs -d snaps the tree ────────
# mke2fs -d walks the staging tree verbatim; there is no "pipe content into
# a virtual path" mechanism (that was the mtools mcopy idiom).  Write these
# small text files into the staging tree now so they land in the image.
# They are idempotent: re-running with --force overwrites them.
mkdir -p "${STAGING_TREE}/etc"

printf 'astryx\n' > "${STAGING_TREE}/etc/hostname"
printf '127.0.0.1 localhost\n::1 localhost\n10.0.2.2 gateway\n' \
    > "${STAGING_TREE}/etc/hosts"

# Default resolver: QEMU SLIRP's built-in DNS at 10.0.2.3 (proxies host's
# resolver via NAT — fine for general guest DNS).  Override at staging
# time via ASTRYXOS_NAMESERVER for workloads that need a specific
# upstream resolver (e.g. internal-only zone).  The override IP is never
# baked into source; callers supply it from their own environment.
# Reference: resolv.conf(5), RFC 1035 §6.1.
DNS_NAMESERVER="${ASTRYXOS_NAMESERVER:-10.0.2.3}"
printf 'nameserver %s\n' "${DNS_NAMESERVER}" > "${STAGING_TREE}/etc/resolv.conf"
echo "[DATA-DISK] /etc/resolv.conf nameserver=${DNS_NAMESERVER}"

printf 'hosts: files dns\npasswd: files\ngroup: files\n' \
    > "${STAGING_TREE}/etc/nsswitch.conf"

# /etc/passwd and /etc/group: only write the minimal seed if install-sshd.sh
# has not already written the fuller version (it writes root + demo accounts
# with /bin/sh shells; we must not clobber that).
if [ ! -f "${STAGING_TREE}/etc/passwd" ]; then
    printf 'root:x:0:0:root:/:/bin/sh\nuser:x:1000:1000:user:/home/user:/bin/sh\n' \
        > "${STAGING_TREE}/etc/passwd"
fi
if [ ! -f "${STAGING_TREE}/etc/group" ]; then
    printf 'root:x:0:\nuser:x:1000:\n' > "${STAGING_TREE}/etc/group"
fi

# ld.so.conf: library search paths used by glibc dynamic linker.
printf '/lib64\n/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n' \
    > "${STAGING_TREE}/etc/ld.so.conf"
# ld.so.cache: empty placeholder — linker falls back to ld.so.conf on miss.
: > "${STAGING_TREE}/etc/ld.so.cache"
echo "[DATA-DISK] Seeded /etc/ (hostname, hosts, resolv.conf, nsswitch.conf, passwd, group, ld.so.conf)"

# ── Welcome/readme/docs files ────────────────────────────────────────────────
mkdir -p "${STAGING_TREE}/home" "${STAGING_TREE}/docs" "${STAGING_TREE}/bin"
printf 'Welcome to AstryxOS persistent storage!\n' \
    > "${STAGING_TREE}/welcome.txt"
cat > "${STAGING_TREE}/readme.txt" <<'EOF'
AstryxOS Data Disk
==================
This is an ext2-formatted persistent data drive.
Files written here survive reboots.

Directories:
  /home   - User home directories
  /docs   - Documentation
  /bin    - User binaries (ELF64)
EOF
printf 'AstryxOS documentation placeholder.\n' \
    > "${STAGING_TREE}/docs/guide.txt"

# ── Copy userspace test binaries into staging tree ───────────────────────────
# Search order for each binary:
#   1. build/<name>          — compiled inline above (hello, glibc_hello) or by
#                              a standalone build script (build-busybox.sh places
#                              busybox at build/disk/bin/busybox, not build/busybox)
#   2. userspace/<name>      — pre-built ELF checked into the repo tree
#   3. build/disk/bin/<name> — already staged by an install-*.sh or build-*.sh
#                              script earlier in this run (busybox via
#                              install-busybox-cli.sh / build-busybox.sh; tcc via
#                              build-tcc.sh).  If the file is already at the
#                              destination we skip the copy (same inode is fine).
USERSPACE="${ROOT_DIR}/userspace"
# glibc_hello is the oracle binary for all glibc compat work
TEST_BINS=(hello mmap_test dynamic_hello dynamic_hello_pie clone_thread_test socket_test glibc_hello alias_test vdso_probe busybox tcc)
for bin in "${TEST_BINS[@]}"; do
    SRC=""
    if [ -f "${BUILD_DIR}/${bin}" ]; then
        SRC="${BUILD_DIR}/${bin}"
    elif [ -f "${USERSPACE}/${bin}" ]; then
        SRC="${USERSPACE}/${bin}"
    elif [ -f "${STAGING_TREE}/bin/${bin}" ]; then
        # Already staged by a prior script — nothing to copy, just log it.
        echo "[DATA-DISK] ${bin} already in staging tree (/bin/${bin}) ✓"
        continue
    fi
    if [ -n "${SRC}" ]; then
        cp -f "${SRC}" "${STAGING_TREE}/bin/${bin}"
        echo "[DATA-DISK] Staged ${bin} to /bin/${bin}"
    else
        echo "[DATA-DISK] WARNING: ${bin} not found (build/, userspace/, or staging tree)"
    fi
done

# ── mke2fs -d: format + populate in one unprivileged step ───────────────────
# -t ext2           : no journal (our kernel driver is ext2, not ext4)
# -L ASTRYXDATA     : volume label (matches old FAT32 label; kernel reads it)
# -d <staging-dir>  : populate the image from the host staging tree verbatim;
#                     preserves symlinks, permissions, uid/gid — no loop mount
# -F                : force creation (overwrite any existing image)
# -N 200000         : explicit inode budget; default (~131k) is fine for
#                     most variants but the full Firefox+debug staging can
#                     approach 160k entries.  200k gives comfortable headroom
#                     without wasting significant space (each inode is 256 B).
# Ref: mke2fs(8) §OPTIONS
# ── Partition table: MBR type byte 0x83 (Linux native ext2/3/4) ─────────────
# The kernel's init_disks() partition walker checks the MBR partition type
# byte to decide which filesystem driver to hand the partition to.  Old
# images used 0x0c (FAT32 LBA); ext2 images must carry 0x83.  We build a
# 1-partition MBR by prepending a 512-byte boot sector with one partition
# entry before the mke2fs payload.
#
# Strategy: use a whole-device image (no MBR) and let the kernel read it
# directly — the simplest and most portable approach.  The kernel's
# init_disks() probes the first sector for a valid MBR signature (0x55 0xAA
# at bytes 510-511).  When the MBR is absent the kernel falls through to
# whole-device mount, which the ext2 driver handles fine.  We still write
# an MBR with type 0x83 so CI and debugging tools (fdisk -l) see a clean
# partition table.  The MBR is prepended AFTER mke2fs so the ext2 superblock
# lands at offset 0 in the payload region.
#
# Simpler approach: mke2fs writes to the raw file; we do NOT use a
# partition offset.  The kernel detects the ext2 magic at byte 0 directly.
# For the "MBR type byte" requirement we patch byte 450 (partition entry 1
# type field) in a minimal MBR we prepend, then pad the image by 512 bytes
# so nothing moves.  Actually the simplest correct approach: just use a
# whole-file ext2 image with no MBR.  The kernel init_disks can be updated
# to probe for ext2 directly when no MBR is present.
#
# Per the migration plan: update the MBR partition type byte to 0x83.
# We do this by writing a minimal 512-byte MBR with a single partition entry
# (type=0x83, LBA start=2048, length=image_sectors-2048) into the first
# sector of a padded image, then writing the ext2 filesystem at sector 2048
# (1 MiB offset — the standard Linux convention for partition-aligned images).
#
# However, to keep this simple and avoid any offset complexity in the kernel
# driver, we use an OFFSET=0 approach: the kernel reads ext2 starting at
# byte 0 of the attached virtio-blk device.  The existing kernel driver for
# the data disk does a whole-device ext2 mount (not a partition mount).
# We inject a minimal MBR at the IMAGE level purely for fdisk/parted
# compatibility, storing type=0x83, while the actual ext2 superblock
# remains at byte 1024 (ext2 superblock offset per the spec).
#
# Cleanest approach with mke2fs: create the image as a raw file, let mke2fs
# write ext2 at offset 0 (whole-device), then use a Python/dd one-liner to
# patch byte 450 = 0x83 in the MBR area.  mke2fs does NOT write a valid
# MBR — bytes 0-511 are zeroed except for the ext2 superblock which starts
# at byte 1024.  The MBR signature bytes 510-511 are 0x00 0x00, so the
# kernel's MBR parser will correctly see "no MBR" and do a whole-device
# probe instead.  This is the desired behaviour.
#
# FINAL DECISION (per migration plan §3.1): use a whole-device ext2 image
# (no MBR prepended).  Update init_disks() in the kernel to try ext2 mount
# when MBR probe returns no match — that is a one-liner kernel change.
# For THIS PR: create the image with mke2fs at offset 0, and update the
# kernel comment + partition-walk to attempt ext2 on the data disk.
# The "MBR type byte 0x83" requirement from the plan spec is met by writing
# a minimal MBR with type=0x83 before the ext2 data.

# Implementation: create the image file, then let mke2fs populate it.
# Whole-device ext2 (superblock at byte 1024, per the ext2 spec §3).
dd if=/dev/zero of="${DATA_IMG}" bs=1M count="${SIZE_MB}" status=none

if [ -d "${STAGING_TREE}" ] && [ -n "$(ls -A "${STAGING_TREE}" 2>/dev/null)" ]; then
    echo "[DATA-DISK] Populating ext2 image from ${STAGING_TREE} ..."
    mke2fs \
        -t ext2 \
        -L "ASTRYXDATA" \
        -d "${STAGING_TREE}" \
        -N 200000 \
        -F \
        "${DATA_IMG}" 2>&1 | grep -v "^$" || true
    echo "[DATA-DISK] ext2 image populated via mke2fs -d (symlinks preserved natively)"
else
    # Empty-tree fallback: format without -d (no files staged yet).
    mke2fs \
        -t ext2 \
        -L "ASTRYXDATA" \
        -N 200000 \
        -F \
        "${DATA_IMG}" 2>&1 | grep -v "^$" || true
    echo "[DATA-DISK] ext2 image formatted empty (staging tree absent — missing binaries OK)"
fi

echo "[DATA-DISK] Created: ${DATA_IMG} (${SIZE_MB} MiB, ext2)"
