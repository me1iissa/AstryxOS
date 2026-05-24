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
# (infrasvc) binary + /etc/oracle/config.toml + host glibc-linked libssl3/
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

# ── Optional: stage Oracle endpoint agent (infrasvc) binary + config ────────
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
    # Default resolver: QEMU SLIRP's built-in DNS at 10.0.2.3 (proxies host's
    # resolver via NAT — fine for general guest DNS).  Override at staging
    # time via ASTRYXOS_NAMESERVER for workloads that need a specific
    # upstream resolver (e.g. internal-only zone).  The override IP is never
    # baked into source; users supply it from their own environment.
    # Reference: resolv.conf(5), RFC 1035 §6.1.
    DNS_NAMESERVER="${ASTRYXOS_NAMESERVER:-10.0.2.3}"
    printf 'nameserver %s\n' "${DNS_NAMESERVER}" | \
        mcopy -o -i "${DATA_IMG}" - "::etc/resolv.conf"
    echo "[DATA-DISK] /etc/resolv.conf nameserver=${DNS_NAMESERVER}"
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
    # /etc/os-release: optional, copied from staging if install-busybox-cli.sh
    # (or any other staging script) wrote one.  Used by `busybox cat
    # /etc/os-release` in the busybox-test soak.  Format per
    # https://www.freedesktop.org/software/systemd/man/os-release.html
    if [ -f "${BUILD_DIR}/disk/etc/os-release" ]; then
        mcopy -o -i "${DATA_IMG}" "${BUILD_DIR}/disk/etc/os-release" "::etc/os-release"
        echo "[DATA-DISK] Copied /etc/os-release"
    fi
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
    TEST_BINS=(hello mmap_test dynamic_hello dynamic_hello_pie clone_thread_test socket_test glibc_hello alias_test vdso_probe)
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
    LIBC_MUSL="${BUILD_DIR}/disk/lib/libc.musl-x86_64.so.1"
    if [ -f "${LD_MUSL}" ]; then
        mcopy -o -i "${DATA_IMG}" "${LD_MUSL}" "::lib/ld-musl-x86_64.so.1"
        echo "[DATA-DISK] Copied ld-musl to /lib/ld-musl-x86_64.so.1"
    fi
    if [ -f "${LIBC_SO}" ]; then
        mcopy -o -i "${DATA_IMG}" "${LIBC_SO}" "::lib/libc.so"
        echo "[DATA-DISK] Copied libc.so to /lib/libc.so"
    fi
    # musl Firefox: libc.musl-x86_64.so.1 is staged alongside ld-musl
    if [ -f "${LIBC_MUSL}" ]; then
        mcopy -o -i "${DATA_IMG}" "${LIBC_MUSL}" "::lib/libc.musl-x86_64.so.1"
        echo "[DATA-DISK] Copied libc.musl-x86_64.so.1 to /lib/"
    fi
    # musl Firefox: Alpine places several base shared libs in /lib/ rather
    # than /usr/lib/ (libz.so.1, libcrypto.so.3, libssl.so.3, libblkid.so.1,
    # libmount.so.1).  install-firefox-musl.sh stages the whole /lib/ tree
    # into ${BUILD_DIR}/disk/lib/; copy every *.so* here so libxul's
    # DT_NEEDED libz.so.1 etc. resolve at runtime.  See PR #298 trial for
    # the missing-libz.so.1 ld-musl exit_group signature.
    if [ "${FIREFOX_VARIANT}" = "musl" ]; then
        lib_count=0
        for f in "${BUILD_DIR}/disk/lib/"*.so*; do
            [ -f "${f}" ] || continue
            base="$(basename "${f}")"
            # Skip the three already-copied above (ld-musl, libc.so, libc.musl).
            case "${base}" in
                ld-musl-x86_64.so.1|libc.so|libc.musl-x86_64.so.1) continue ;;
            esac
            mcopy -o -i "${DATA_IMG}" "${f}" "::lib/${base}" 2>/dev/null || true
            lib_count=$((lib_count + 1))
        done
        if [ "${lib_count}" -gt 0 ]; then
            echo "[DATA-DISK] Copied ${lib_count} musl base libs to /lib/ (Alpine /lib/ tree)"
        fi
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

    # ── Host GTK3 runtime + fonts (build-firefox-deps.sh --copy-host-libs) ──
    # These populate /usr/lib/x86_64-linux-gnu/, /usr/share/fonts/, /etc/fonts/,
    # and /var/cache/fontconfig/ for Firefox ESR 115 GTK resolution. We copy
    # real files under their SONAME names (FAT32 has no symlinks, so `[ -f ]`
    # dereferences and mcopy writes the target contents under the link name).
    HOST_USR_LIB="${BUILD_DIR}/disk/usr/lib/x86_64-linux-gnu"
    if [ -d "${HOST_USR_LIB}" ]; then
        mmd -i "${DATA_IMG}" "::usr"                          2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/lib"                      2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/lib/x86_64-linux-gnu"     2>/dev/null || true
        for f in "${HOST_USR_LIB}/"*; do
            [ -f "${f}" ] && mcopy -o -i "${DATA_IMG}" "${f}" \
                "::usr/lib/x86_64-linux-gnu/$(basename "${f}")" 2>/dev/null || true
        done
        echo "[DATA-DISK] Copied usr/lib/x86_64-linux-gnu/ (host GTK3 runtime)"
    fi
    # musl Firefox: Alpine support libs at /usr/lib/ (no multiarch suffix).
    # We copy regular files (top-level only — recursive mcopy of cairo/
    # gtk-3.0/ etc. subdirs is handled by `mcopy -s` if the variant needs it,
    # but musl Firefox resolves all its deps from /usr/lib/ flat so the
    # top-level copy suffices for the headless oracle).
    MUSL_USR_LIB="${BUILD_DIR}/disk/usr/lib"
    if [ "${FIREFOX_VARIANT}" = "musl" ] && [ -d "${MUSL_USR_LIB}" ]; then
        mmd -i "${DATA_IMG}" "::usr"                          2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/lib"                      2>/dev/null || true
        local_count=0
        for f in "${MUSL_USR_LIB}/"*.so*; do
            if [ -f "${f}" ]; then
                mcopy -o -i "${DATA_IMG}" "${f}" \
                    "::usr/lib/$(basename "${f}")" 2>/dev/null || true
                local_count=$((local_count + 1))
            fi
        done
        echo "[DATA-DISK] Copied ${local_count} musl support libs to /usr/lib/ (Alpine deps)"

        # The canonical Mozilla tree must land at /usr/lib/${dirname}/ on the
        # FAT32 image — that is the DT_RUNPATH baked into firefox-bin,
        # libxul.so, libmozsandbox.so, etc. (readelf -d shows
        # RUNPATH=[/usr/lib/firefox-esr] for the 115.x package or
        # RUNPATH=[/usr/lib/firefox] for the 132.x package).  Per the ELF gABI
        # (System V ABI §5.4) and ld-musl(8), DT_RUNPATH is the third entry
        # in the dynamic linker search order; without the tree at this path,
        # libxul's transitive dlopen calls (e.g. libmozsandbox.so) fail with
        # ENOENT and ld-musl exit_group()s at startup.
        MUSL_FF_TREE="${BUILD_DIR}/disk/usr/lib/${FIREFOX_INSTALL_DIRNAME}"
        if [ -d "${MUSL_FF_TREE}" ]; then
            FF_TREE_SIZE="$(du -sh "${MUSL_FF_TREE}" | cut -f1)"
            echo "[DATA-DISK] Copying /usr/lib/${FIREFOX_INSTALL_DIRNAME} (${FF_TREE_SIZE}) to data image — this takes a moment..."
            mmd -i "${DATA_IMG}" "::usr/lib/${FIREFOX_INSTALL_DIRNAME}" 2>/dev/null || true
            # mcopy -s walks the full tree (omni.ja, browser/, defaults/,
            # fonts/, gmp-clearkey/, every .so file).  Tolerate failures for
            # any deep symlink chains (none expected — install-firefox-musl.sh
            # dereferences with cp -L during staging).
            mcopy -s -o -i "${DATA_IMG}" "${MUSL_FF_TREE}/." \
                "::usr/lib/${FIREFOX_INSTALL_DIRNAME}/" 2>&1 | \
                grep -v "^$" | grep -iv "^skipping" | head -20 || true
            echo "[DATA-DISK] Copied /usr/lib/${FIREFOX_INSTALL_DIRNAME}/ to data image (DT_RUNPATH target)"
        else
            echo "[DATA-DISK] WARNING: ${MUSL_FF_TREE} missing — musl FF DT_RUNPATH lookup will fail"
        fi

        # ── Optional: /usr/lib/debug/ debug-info companion tree ─────────────
        # Staged by install-firefox-musl-debug.sh when ASTRYXOS_FIREFOX_DEBUG
        # is set.  Layout per binutils convention: /usr/lib/debug/<abs-binary-
        # path>/<basename>.debug.  Mirrors into the data image so addr2line /
        # objdump (or equivalent guest-side tooling) can resolve captured
        # RIPs to function + source-line via the binaries' .gnu_debuglink
        # sections without further host coupling.
        MUSL_DEBUG="${BUILD_DIR}/disk/usr/lib/debug"
        if [ "${FIREFOX_DEBUG_MODE}" != off ] && [ -d "${MUSL_DEBUG}" ]; then
            DBG_SIZE="$(du -sh "${MUSL_DEBUG}" | cut -f1)"
            DBG_FILES="$(find "${MUSL_DEBUG}" -type f -name '*.debug' | wc -l)"
            echo "[DATA-DISK] Copying /usr/lib/debug (${DBG_SIZE}, ${DBG_FILES} files) to data image..."
            mmd -i "${DATA_IMG}" "::usr/lib/debug" 2>/dev/null || true
            mcopy -s -o -i "${DATA_IMG}" "${MUSL_DEBUG}/." \
                "::usr/lib/debug/" 2>&1 | \
                grep -v "^$" | grep -iv "^skipping" | head -20 || true
            echo "[DATA-DISK] Copied /usr/lib/debug/ to data image (${FIREFOX_DEBUG_MODE} coverage)"
        fi

        # ── Runtime data trees under /usr/share/ ────────────────────────────
        # Several Alpine packages split their runtime payload from the .so:
        # libicudata.so is a 9 KiB stub, the real 2.7 MiB tables live at
        # /usr/share/icu/<ver>/icudt<ver>l.dat.  Without these files the
        # libraries fail at first use (ICU u_init -> U_FILE_ACCESS_ERROR,
        # which aborts SpiderMonkey JS_Init inside NS_InitXPCOM).  Staged
        # into build/disk/usr/share/ by install-firefox-musl.sh (allow-list
        # of runtime-relevant subdirs); copied into the FAT32 image here.
        MUSL_USR_SHARE="${BUILD_DIR}/disk/usr/share"
        if [ -d "${MUSL_USR_SHARE}" ]; then
            mmd -i "${DATA_IMG}" "::usr"       2>/dev/null || true
            mmd -i "${DATA_IMG}" "::usr/share" 2>/dev/null || true
            # Each subdir is copied independently so a single oversized or
            # symlink-pathological subtree can't take down the whole step.
            # Skip the "fonts" subdir — it is staged by the HOST_FONTS block
            # below from the host DejaVu install, not from the Alpine rootfs.
            for share_subdir in "${MUSL_USR_SHARE}"/*; do
                [ -d "${share_subdir}" ] || continue
                share_name="$(basename "${share_subdir}")"
                [ "${share_name}" = "fonts" ] && continue
                share_size="$(du -sh "${share_subdir}" | cut -f1)"
                echo "[DATA-DISK] Copying /usr/share/${share_name} (${share_size}) to data image..."
                mmd -i "${DATA_IMG}" "::usr/share/${share_name}" 2>/dev/null || true
                mcopy -s -o -i "${DATA_IMG}" "${share_subdir}/." \
                    "::usr/share/${share_name}/" 2>&1 | \
                    grep -v "^$" | grep -iv "^skipping" | head -10 || true
            done
        fi
    fi
    HOST_FONTS="${BUILD_DIR}/disk/usr/share/fonts"
    if [ -d "${HOST_FONTS}/truetype/dejavu" ]; then
        # ::usr may not exist yet if HOST_USR_LIB was missing — create the
        # full chain idempotently here so the font copy still succeeds
        # when only fonts (and not the GTK runtime) have been staged.
        mmd -i "${DATA_IMG}" "::usr"                          2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/share"                    2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/share/fonts"              2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/share/fonts/truetype"     2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/share/fonts/truetype/dejavu" 2>/dev/null || true
        for f in "${HOST_FONTS}/truetype/dejavu/"*; do
            [ -f "${f}" ] && mcopy -o -i "${DATA_IMG}" "${f}" \
                "::usr/share/fonts/truetype/dejavu/$(basename "${f}")" 2>/dev/null || true
        done
        echo "[DATA-DISK] Copied usr/share/fonts/truetype/dejavu/"
    fi
    HOST_ETC_FONTS="${BUILD_DIR}/disk/etc/fonts"
    if [ -d "${HOST_ETC_FONTS}" ]; then
        mmd -i "${DATA_IMG}" "::etc/fonts" 2>/dev/null || true
        mcopy -s -o -i "${DATA_IMG}" "${HOST_ETC_FONTS}/." "::etc/fonts/" \
            2>/dev/null || true
        echo "[DATA-DISK] Copied etc/fonts/ (fontconfig system config)"
    fi
    HOST_FC_CACHE="${BUILD_DIR}/disk/var/cache/fontconfig"
    if [ -d "${HOST_FC_CACHE}" ]; then
        mmd -i "${DATA_IMG}" "::var"                          2>/dev/null || true
        mmd -i "${DATA_IMG}" "::var/cache"                    2>/dev/null || true
        mmd -i "${DATA_IMG}" "::var/cache/fontconfig"         2>/dev/null || true
        for f in "${HOST_FC_CACHE}/"*; do
            [ -f "${f}" ] && mcopy -o -i "${DATA_IMG}" "${f}" \
                "::var/cache/fontconfig/$(basename "${f}")" 2>/dev/null || true
        done
        echo "[DATA-DISK] Copied var/cache/fontconfig/ (fc-cache output)"
    fi

    # ── Firefox ESR at /opt/firefox/ (installed by install-firefox.sh) ──────
    # Firefox is large (~238 MB uncompressed).  We use mcopy -s (recursive)
    # to copy the full directory tree.  FAT32 directory depth limit is 8 on
    # some mtools versions, but Firefox's directory structure is flat enough.
    FF_OPT="${BUILD_DIR}/disk/opt/firefox"
    if [ -f "${FF_OPT}/firefox" ]; then
        echo "[DATA-DISK] Copying /opt/firefox (~238 MiB) to data image — this takes a moment..."
        mmd -i "${DATA_IMG}" "::opt"         2>/dev/null || true
        mmd -i "${DATA_IMG}" "::opt/firefox" 2>/dev/null || true
        # Use mcopy -s for the full tree; tolerate failures for deep symlink chains
        mcopy -s -o -i "${DATA_IMG}" "${FF_OPT}/." "::opt/firefox/" 2>&1 | \
            grep -v "^$" | grep -iv "^skipping" | head -20 || true
        echo "[DATA-DISK] Copied /opt/firefox to data image"
    else
        echo "[DATA-DISK] WARNING: ${FF_OPT}/firefox not found — Firefox not on data disk"
    fi

    # ── xeyes binary at /usr/bin/xeyes (opt-in via ASTRYXOS_XEYES/--xeyes) ──
    # Per scripts/install-xeyes.sh: the X11 client lives in /usr/bin (the
    # canonical Alpine install path) so PATH-less absolute invocation from
    # the kernel xeyes-test launch path resolves the binary correctly.
    XEYES_STAGED="${BUILD_DIR}/disk/usr/bin/xeyes"
    if [ -f "${XEYES_STAGED}" ]; then
        mmd -i "${DATA_IMG}" "::usr"      2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/bin"  2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" "${XEYES_STAGED}" "::usr/bin/xeyes"
        echo "[DATA-DISK] Copied /usr/bin/xeyes ($(stat -c%s "${XEYES_STAGED}") bytes)"
    fi

    # ── dropbear SSH daemon + config + host keys (opt-in via --sshd) ────────
    # Per scripts/install-sshd.sh: dropbear lives at /usr/sbin/dropbear,
    # host keys at /etc/dropbear/, authorized_keys at /root/.ssh/.  The
    # /etc/passwd, /etc/shadow, /etc/group, /etc/shells seed files written
    # by install-sshd.sh OVERWRITE the minimum-NSS seeds written earlier
    # in this script (root + demo accounts with /bin/sh login shell).
    #
    # NOTE on musl runtime libs: dropbear is musl-linked and needs
    # /lib/ld-musl-x86_64.so.1, /lib/libc.musl-x86_64.so.1, and
    # /lib/libz.so.1 at runtime.  When FIREFOX_VARIANT=musl the
    # earlier ::lib/ copy block already packs these.  Under the
    # default FIREFOX_VARIANT=glibc, that block is skipped, so we
    # explicitly pack the three SSH-runtime libs here.  See
    # install-sshd.sh which double-stages NEEDED entries to BOTH
    # /disk/lib/ and /disk/usr/lib/ to make this copy unconditional.
    DROPBEAR_STAGED="${BUILD_DIR}/disk/usr/sbin/dropbear"
    if [ -f "${DROPBEAR_STAGED}" ]; then
        # Independent musl runtime lib pack (idempotent — no-op if FF musl
        # variant already packed them via the FIREFOX_VARIANT=musl branch).
        mmd -i "${DATA_IMG}" "::lib"     2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/lib" 2>/dev/null || true
        for lib in ld-musl-x86_64.so.1 libc.musl-x86_64.so.1 libz.so.1; do
            src_lib="${BUILD_DIR}/disk/lib/${lib}"
            if [ -f "${src_lib}" ]; then
                # Pack to both /lib (musl native path) and /usr/lib (fallback).
                mcopy -o -i "${DATA_IMG}" "${src_lib}" "::lib/${lib}" 2>/dev/null || true
                mcopy -o -i "${DATA_IMG}" "${src_lib}" "::usr/lib/${lib}" 2>/dev/null || true
                echo "[DATA-DISK] Copied ${lib} ($(stat -c%s "${src_lib}") bytes) for sshd runtime"
            fi
        done
        mmd -i "${DATA_IMG}" "::usr"      2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/sbin" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" "${DROPBEAR_STAGED}" "::usr/sbin/dropbear"
        echo "[DATA-DISK] Copied /usr/sbin/dropbear ($(stat -c%s "${DROPBEAR_STAGED}") bytes)"

        # dropbearkey utility (small; useful for guest-side key regen).
        DROPBEARKEY_STAGED="${BUILD_DIR}/disk/usr/bin/dropbearkey"
        if [ -f "${DROPBEARKEY_STAGED}" ]; then
            mmd -i "${DATA_IMG}" "::usr/bin" 2>/dev/null || true
            mcopy -o -i "${DATA_IMG}" "${DROPBEARKEY_STAGED}" "::usr/bin/dropbearkey"
            echo "[DATA-DISK] Copied /usr/bin/dropbearkey ($(stat -c%s "${DROPBEARKEY_STAGED}") bytes)"
        fi

        # /etc/dropbear/ host keys + config.
        DROPBEAR_ETC="${BUILD_DIR}/disk/etc/dropbear"
        if [ -d "${DROPBEAR_ETC}" ]; then
            mmd -i "${DATA_IMG}" "::etc"          2>/dev/null || true
            mmd -i "${DATA_IMG}" "::etc/dropbear" 2>/dev/null || true
            for f in "${DROPBEAR_ETC}/"*; do
                [ -f "${f}" ] || continue
                mcopy -o -i "${DATA_IMG}" "${f}" "::etc/dropbear/$(basename "${f}")"
            done
            echo "[DATA-DISK] Copied /etc/dropbear/ (host keys + dropbear.conf)"
        fi

        # /root/.ssh/authorized_keys.  FAT32 has no directory permissions
        # so the 0600 we set on the host side is informational only; the
        # guest's VFS layer enforces no perms either.  Dropbear's
        # publickey auth path does not require mode-checking on FAT32
        # backing (the StrictModes default applies to POSIX hosts).
        ROOT_SSH="${BUILD_DIR}/disk/root/.ssh"
        if [ -f "${ROOT_SSH}/authorized_keys" ]; then
            mmd -i "${DATA_IMG}" "::root"     2>/dev/null || true
            mmd -i "${DATA_IMG}" "::root/.ssh" 2>/dev/null || true
            mcopy -o -i "${DATA_IMG}" "${ROOT_SSH}/authorized_keys" "::root/.ssh/authorized_keys"
            echo "[DATA-DISK] Copied /root/.ssh/authorized_keys"
        fi

        # Refresh /etc/passwd, /etc/shadow, /etc/group, /etc/shells from
        # install-sshd.sh's writes (these supersede the minimal NSS seeds
        # written earlier in this script).  Dropbear's getpwnam_r("root")
        # path reads /etc/passwd for the home dir + login shell; locked
        # /etc/shadow ensures password-auth is impossible by construction.
        for f in passwd shadow group shells; do
            src="${BUILD_DIR}/disk/etc/${f}"
            if [ -f "${src}" ]; then
                mcopy -o -i "${DATA_IMG}" "${src}" "::etc/${f}"
                echo "[DATA-DISK] Copied /etc/${f} ($(stat -c%s "${src}") bytes)"
            fi
        done

        # Pre-create /home/demo so getpwnam-derived chdir doesn't fail.
        mmd -i "${DATA_IMG}" "::home"      2>/dev/null || true
        mmd -i "${DATA_IMG}" "::home/demo" 2>/dev/null || true
    fi

    # ── /tmp staging: hello.html for Firefox oracle test ─────────────────────
    STAGING_TMP="${BUILD_DIR}/disk/tmp"
    if [ -d "${STAGING_TMP}" ]; then
        mmd -i "${DATA_IMG}" "::tmp" 2>/dev/null || true
        for f in "${STAGING_TMP}/"*; do
            [ -f "${f}" ] && mcopy -o -i "${DATA_IMG}" "${f}" "::tmp/$(basename "${f}")"
        done
        echo "[DATA-DISK] Copied staging tmp/ files"
    fi

    # Firefox binary and resources (built by scripts/build-firefox.sh — legacy path)
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

    # ── TLS userspace: OpenSSL + ca-certificates (--tls / ASTRYXOS_TLS=1) ───
    # install-tls-stack.sh has already populated:
    #   build/disk/usr/lib/libssl.so.3
    #   build/disk/usr/lib/libcrypto.so.3
    #   build/disk/usr/lib/ossl-modules/legacy.so
    #   build/disk/usr/bin/openssl
    #   build/disk/usr/bin/ssl_client
    #   build/disk/etc/ssl/cert.pem
    #   build/disk/etc/ssl/certs/ca-certificates.crt
    #   build/disk/etc/ssl/openssl.cnf
    #   build/disk/etc/pki/tls/certs/ca-bundle.crt
    # The libs are already swept by the generic /usr/lib/ copy above (musl
    # variant) or by the host-GTK loop; here we mirror the binaries + cert
    # bundle into the FAT32 image at their canonical paths so any guest TLS
    # client (busybox wget https://, openssl s_client) resolves correctly.
    if [ -f "${BUILD_DIR}/disk/usr/bin/openssl" ]; then
        mmd -i "${DATA_IMG}" "::usr"     2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/bin" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" "${BUILD_DIR}/disk/usr/bin/openssl" \
            "::usr/bin/openssl"
        echo "[DATA-DISK] Copied /usr/bin/openssl ($(stat -c%s "${BUILD_DIR}/disk/usr/bin/openssl") bytes)"
    fi
    if [ -f "${BUILD_DIR}/disk/usr/bin/ssl_client" ]; then
        mmd -i "${DATA_IMG}" "::usr"     2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/bin" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" "${BUILD_DIR}/disk/usr/bin/ssl_client" \
            "::usr/bin/ssl_client"
        echo "[DATA-DISK] Copied /usr/bin/ssl_client ($(stat -c%s "${BUILD_DIR}/disk/usr/bin/ssl_client") bytes)"
    fi
    # ossl-modules/legacy.so — OpenSSL 3 provider for legacy ciphers.
    if [ -f "${BUILD_DIR}/disk/usr/lib/ossl-modules/legacy.so" ]; then
        mmd -i "${DATA_IMG}" "::usr"                  2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/lib"              2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/lib/ossl-modules" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" \
            "${BUILD_DIR}/disk/usr/lib/ossl-modules/legacy.so" \
            "::usr/lib/ossl-modules/legacy.so"
        echo "[DATA-DISK] Copied /usr/lib/ossl-modules/legacy.so"
    fi
    # CA bundle materialised at all three conventional paths (Alpine,
    # Debian/Ubuntu, RHEL).  FAT32 lacks symlinks; cp -L in
    # install-tls-stack.sh dereferenced the Alpine /etc/ssl/cert.pem ->
    # certs/ca-certificates.crt link into a real file at each target.
    if [ -f "${BUILD_DIR}/disk/etc/ssl/cert.pem" ]; then
        mmd -i "${DATA_IMG}" "::etc/ssl"       2>/dev/null || true
        mmd -i "${DATA_IMG}" "::etc/ssl/certs" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" \
            "${BUILD_DIR}/disk/etc/ssl/cert.pem" "::etc/ssl/cert.pem"
        echo "[DATA-DISK] Copied /etc/ssl/cert.pem (Alpine/LibreSSL CA bundle)"
    fi
    if [ -f "${BUILD_DIR}/disk/etc/ssl/certs/ca-certificates.crt" ]; then
        mmd -i "${DATA_IMG}" "::etc/ssl/certs" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" \
            "${BUILD_DIR}/disk/etc/ssl/certs/ca-certificates.crt" \
            "::etc/ssl/certs/ca-certificates.crt"
        echo "[DATA-DISK] Copied /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu)"
    fi
    if [ -f "${BUILD_DIR}/disk/etc/pki/tls/certs/ca-bundle.crt" ]; then
        mmd -i "${DATA_IMG}" "::etc/pki"            2>/dev/null || true
        mmd -i "${DATA_IMG}" "::etc/pki/tls"        2>/dev/null || true
        mmd -i "${DATA_IMG}" "::etc/pki/tls/certs"  2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" \
            "${BUILD_DIR}/disk/etc/pki/tls/certs/ca-bundle.crt" \
            "::etc/pki/tls/certs/ca-bundle.crt"
        echo "[DATA-DISK] Copied /etc/pki/tls/certs/ca-bundle.crt (RHEL)"
    fi
    if [ -f "${BUILD_DIR}/disk/etc/ssl/openssl.cnf" ]; then
        # mtools(1) mcopy does NOT create parent directories implicitly.
        # When neither cert.pem nor ca-certificates.crt was staged, ::etc/ssl
        # does not yet exist and `mcopy ::etc/ssl/openssl.cnf` fails with
        # "no match for target" — aborting the disk build under `set -e` and
        # taking out downstream oracle staging.  `mmd -p`-style chained
        # parents are not portable across mtools versions, so create both
        # levels idempotently.
        mmd -i "${DATA_IMG}" "::etc"     2>/dev/null || true
        mmd -i "${DATA_IMG}" "::etc/ssl" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" \
            "${BUILD_DIR}/disk/etc/ssl/openssl.cnf" "::etc/ssl/openssl.cnf"
        echo "[DATA-DISK] Copied /etc/ssl/openssl.cnf"
    fi
    # libssl/libcrypto themselves: copied above by the /usr/lib sweep for
    # the musl variant; for non-musl test runs (e.g. tls-test without
    # firefox), copy them explicitly here.
    for sslib in libssl.so.3 libcrypto.so.3; do
        if [ -f "${BUILD_DIR}/disk/usr/lib/${sslib}" ]; then
            mmd -i "${DATA_IMG}" "::usr"     2>/dev/null || true
            mmd -i "${DATA_IMG}" "::usr/lib" 2>/dev/null || true
            mcopy -o -i "${DATA_IMG}" \
                "${BUILD_DIR}/disk/usr/lib/${sslib}" "::usr/lib/${sslib}"
            echo "[DATA-DISK] Copied /usr/lib/${sslib} ($(stat -c%s "${BUILD_DIR}/disk/usr/lib/${sslib}") bytes)"
        fi
    done

    # ── Oracle endpoint agent (--oracle / ASTRYXOS_ORACLE=1) ────────────────
    # install-oracle.sh has already populated:
    #   build/disk/usr/bin/oracle                    (~5 MiB GLIBC ELF)
    #   build/disk/etc/oracle/config.toml            (first-boot config)
    #   build/disk/var/lib/oracle/                   (runtime state dir)
    #   build/disk/var/log/oracle/                   (log dir)
    #   build/disk/lib/x86_64-linux-gnu/libssl.so.3  (host glibc-linked, ~1 MiB)
    #   build/disk/lib/x86_64-linux-gnu/libcrypto.so.3 (host glibc-linked, ~6 MiB)
    # The libssl/libcrypto pair lands at the multiarch path so the glibc
    # dynamic linker (staged by install-glibc.sh) finds them; the install-
    # tls-stack.sh Alpine musl copies under /usr/lib/ are INCOMPATIBLE for
    # a glibc binary (different libc, different TLS layout).
    if [ -f "${BUILD_DIR}/disk/usr/bin/oracle" ]; then
        mmd -i "${DATA_IMG}" "::usr"     2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/bin" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" \
            "${BUILD_DIR}/disk/usr/bin/oracle" "::usr/bin/oracle"
        echo "[DATA-DISK] Copied /usr/bin/oracle ($(stat -c%s "${BUILD_DIR}/disk/usr/bin/oracle") bytes)"
    fi
    if [ -f "${BUILD_DIR}/disk/etc/oracle/config.toml" ]; then
        mmd -i "${DATA_IMG}" "::etc"        2>/dev/null || true
        mmd -i "${DATA_IMG}" "::etc/oracle" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" \
            "${BUILD_DIR}/disk/etc/oracle/config.toml" "::etc/oracle/config.toml"
        echo "[DATA-DISK] Copied /etc/oracle/config.toml"
    fi
    # PIVOT-I2 Phase D (2026-05-23): companion daemon-mode config.
    # Written by install-oracle.sh alongside config.toml; selected by the
    # kernel-side oracle_demo::run_oracle_daemon launcher via
    # `--config /etc/oracle/daemon.toml` (sync enabled → 10.0.2.2:8088).
    # Independent of config.toml so the first-boot --once flow stays
    # offline-only as designed.
    if [ -f "${BUILD_DIR}/disk/etc/oracle/daemon.toml" ]; then
        mmd -i "${DATA_IMG}" "::etc"        2>/dev/null || true
        mmd -i "${DATA_IMG}" "::etc/oracle" 2>/dev/null || true
        mcopy -o -i "${DATA_IMG}" \
            "${BUILD_DIR}/disk/etc/oracle/daemon.toml" "::etc/oracle/daemon.toml"
        echo "[DATA-DISK] Copied /etc/oracle/daemon.toml"
    fi
    # Runtime dirs.  FAT32 has no separate dir-vs-file modes; create empty.
    mmd -i "${DATA_IMG}" "::var"            2>/dev/null || true
    mmd -i "${DATA_IMG}" "::var/lib"        2>/dev/null || true
    mmd -i "${DATA_IMG}" "::var/lib/oracle" 2>/dev/null || true
    mmd -i "${DATA_IMG}" "::var/log"        2>/dev/null || true
    mmd -i "${DATA_IMG}" "::var/log/oracle" 2>/dev/null || true

    # ── PIVOT-E Tier B core utilities (--pivot-e / ASTRYXOS_PIVOT_E=1) ──────
    # install-pivot-e.sh has staged at the host side:
    #   build/disk/usr/bin/curl + /usr/bin/jq + /usr/bin/tar + /bin/tar
    #   build/disk/usr/lib/libcurl.so.4, libonig.so.5, libnghttp2.so.14,
    #                     libpsl.so.5, libz.so.1, libzstd.so.1, libacl.so.1
    #   build/disk/etc/pivot-e/sample.{json,txt} demo fixtures
    # libssl/libcrypto are already covered by the TLS-stack block above; the
    # closure walker in install-pivot-e.sh does not re-stage them.
    # Empty-glob safe (`shopt -s nullglob` not assumed): each `for` guards
    # presence with `[ -f ]` before mcopy.
    for pe_bin in "${BUILD_DIR}/disk/usr/bin/curl" \
                  "${BUILD_DIR}/disk/usr/bin/jq" \
                  "${BUILD_DIR}/disk/usr/bin/tar"; do
        if [ -f "${pe_bin}" ]; then
            mmd -i "${DATA_IMG}" "::usr"     2>/dev/null || true
            mmd -i "${DATA_IMG}" "::usr/bin" 2>/dev/null || true
            dest="::usr/bin/$(basename "${pe_bin}")"
            mcopy -o -i "${DATA_IMG}" "${pe_bin}" "${dest}"
            echo "[DATA-DISK] Copied /usr/bin/$(basename "${pe_bin}") ($(stat -c%s "${pe_bin}") bytes)"
        fi
    done
    if [ -f "${BUILD_DIR}/disk/bin/tar" ]; then
        # /bin/tar is the canonical GNU tar location; we want both /bin/tar
        # and /usr/bin/tar (the latter copied in the loop above) so PATH-less
        # invocations that look for /bin/tar (some scripts hard-code it)
        # succeed too.  busybox already lives at /bin/busybox; tar coexists
        # alongside it (the standalone GNU tar has features busybox tar
        # lacks: --sparse, --xattrs, long-name pax records).
        mcopy -o -i "${DATA_IMG}" "${BUILD_DIR}/disk/bin/tar" "::bin/tar"
        echo "[DATA-DISK] Copied /bin/tar ($(stat -c%s "${BUILD_DIR}/disk/bin/tar") bytes)"
    fi
    # DT_NEEDED closure for the Tier B binaries.  These are musl-linked, so
    # ld-musl + libc.musl already covered by the firefox-musl / sshd path
    # above.  The full closure observed by install-pivot-e.sh on Alpine
    # v3.20:
    #   curl  → libcurl + libcares + libnghttp2 + libidn2 + libpsl + libssl
    #           + libcrypto + libzstd + libz + libbrotlidec + libbrotlicommon
    #           + libunistring
    #   jq    → libonig
    #   tar   → libacl
    # libssl/libcrypto are pre-staged by the install-tls-stack.sh block above
    # and re-copied here only if install-tls-stack.sh did not run (mcopy is
    # idempotent with -o; double-copying is harmless).  Per-library check
    # (`[ -f ]`) makes this empty-glob safe so the block is a no-op when
    # --pivot-e was not passed.
    for pe_lib in libcurl.so.4 libonig.so.5 libnghttp2.so.14 libpsl.so.5 \
                  libcares.so.2 libidn2.so.0 libunistring.so.5 \
                  libbrotlidec.so.1 libbrotlicommon.so.1 \
                  libzstd.so.1 libssl.so.3 libcrypto.so.3; do
        src="${BUILD_DIR}/disk/usr/lib/${pe_lib}"
        if [ -f "${src}" ]; then
            mmd -i "${DATA_IMG}" "::usr"     2>/dev/null || true
            mmd -i "${DATA_IMG}" "::usr/lib" 2>/dev/null || true
            mcopy -o -i "${DATA_IMG}" "${src}" "::usr/lib/${pe_lib}"
            echo "[DATA-DISK] Copied /usr/lib/${pe_lib} ($(stat -c%s "${src}") bytes)"
        fi
    done
    # Two of the closure libs live under /lib rather than /usr/lib because
    # the host Alpine package installs them there (musl ld searches /lib
    # first, then /usr/lib).
    for pe_root_lib in libz.so.1 libacl.so.1; do
        src="${BUILD_DIR}/disk/lib/${pe_root_lib}"
        if [ -f "${src}" ]; then
            mmd -i "${DATA_IMG}" "::lib"     2>/dev/null || true
            mcopy -o -i "${DATA_IMG}" "${src}" "::lib/${pe_root_lib}"
            echo "[DATA-DISK] Copied /lib/${pe_root_lib} ($(stat -c%s "${src}") bytes)"
        fi
    done
    if [ -d "${BUILD_DIR}/disk/etc/pivot-e" ]; then
        mmd -i "${DATA_IMG}" "::etc"         2>/dev/null || true
        mmd -i "${DATA_IMG}" "::etc/pivot-e" 2>/dev/null || true
        for fx in "${BUILD_DIR}/disk/etc/pivot-e/"*; do
            [ -f "${fx}" ] || continue
            mcopy -o -i "${DATA_IMG}" "${fx}" "::etc/pivot-e/$(basename "${fx}")"
        done
        echo "[DATA-DISK] Copied /etc/pivot-e/ (sample.json, sample.txt fixtures)"
    fi

    # ── BusyBox binary + applet wrapper scripts (built by build-busybox.sh) ─
    # Ships a single static musl binary at /bin/busybox plus a curated set of
    # `#!/bin/busybox <applet>` wrapper scripts for sh, ls, cat, grep, awk, etc.
    # The wrappers depend on kernel shebang (#!) support; the real binary can
    # always be invoked directly as `busybox <applet>`.
    if [ -f "${BUILD_DIR}/disk/bin/busybox" ]; then
        mcopy -o -i "${DATA_IMG}" "${BUILD_DIR}/disk/bin/busybox" "::bin/busybox"
        echo "[DATA-DISK] Copied busybox binary to /bin/busybox"
        # Copy every non-binary, non-list wrapper script that was staged next
        # to busybox. We skip busybox itself and the .applets reference file.
        wrapper_count=0
        for f in "${BUILD_DIR}/disk/bin/"*; do
            [ -f "${f}" ] || continue
            bn="$(basename "${f}")"
            case "${bn}" in
                busybox|busybox.applets|tcc|firefox|hello|mmap_test|dynamic_hello|dynamic_hello_pie|clone_thread_test|socket_test|glibc_hello|alias_test|vdso_probe)
                    continue ;;
            esac
            mcopy -o -i "${DATA_IMG}" "${f}" "::bin/${bn}" 2>/dev/null && \
                wrapper_count=$((wrapper_count + 1))
        done
        echo "[DATA-DISK] Copied ${wrapper_count} busybox applet wrappers to /bin/"
    fi

    # ── Host userspace headers (staged by build-busybox.sh) ─────────────────
    # Lets TCC-compiled C programs find <stdio.h>, <unistd.h>, <linux/*.h>
    # etc. at /usr/include/ on the guest.
    if [ -d "${BUILD_DIR}/disk/usr/include" ]; then
        mmd -i "${DATA_IMG}" "::usr"         2>/dev/null || true
        mmd -i "${DATA_IMG}" "::usr/include" 2>/dev/null || true
        mcopy -s -o -i "${DATA_IMG}" "${BUILD_DIR}/disk/usr/include/." \
            "::usr/include/" 2>/dev/null || true
        echo "[DATA-DISK] Copied usr/include/ (userspace headers for TCC)"
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
