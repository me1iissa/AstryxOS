#!/usr/bin/env bash
#
# install-firefox-musl.sh — Stage Alpine Linux's musl-linked Firefox
# (firefox-esr 115.x OR firefox 132.x) into the AstryxOS data-disk staging tree.
#
# Why musl?  The glibc Firefox plateau (sc=2902 frozen for 28+ min, TID 2 in
# NS_ProcessNextEvent) is hypothesised to be glibc-specific — glibc's
# pthread_cond two-group cycling (BZ 25847) and arena-locked malloc generate
# fundamentally different futex / mutex traffic than musl's single-slot
# cond_var and simpler allocator.  Swapping the libc tests whether the
# kernel publication paths intersect those primitives.
#
# Package selection via ASTRYXOS_FIREFOX_PACKAGE
# ----------------------------------------------
#
# Two Alpine community packages are supported:
#
#   firefox-esr (default; 115.24.0-r0 on v3.20) — Extended Support Release.
#     Mature, slow-moving binary; Mozilla tecken indexes its BuildID.  Alpine
#     does NOT ship firefox-esr-dbg, so libxul attribution falls back to
#     Mozilla Breakpad PUBLIC symbols (~8,600 entries; PUBLIC-only).
#
#   firefox (current; 132.0.2-r0 on v3.20) — Latest stable.  Alpine DOES ship
#     firefox-dbg (~47 MiB on data.img) carrying a real .debug companion with
#     full .symtab (~420k symbols incl. FUNC) and minimal DWARF — addr2line /
#     gdb / nm resolve C++ names via the .gnu_debuglink chain.  Chosen for any
#     investigation that needs to NAME the libxul function at a captured RIP.
#
# Layout-significant differences
# ------------------------------
#
#   Item                          firefox-esr (115.x)          firefox (132.x)
#   ─────────────────────────     ─────────────────────────    ─────────────────────────
#   Binary install dir            /usr/lib/firefox-esr         /usr/lib/firefox
#   DT_RUNPATH in Mozilla DSOs    /usr/lib/firefox-esr         /usr/lib/firefox
#   Alpine subpackage layout      -intl                        -intl, -dbg
#   Apk-tools-static name         "firefox-esr"                "firefox"
#   Sentinel binary on guest      firefox-esr                  firefox
#
# The path of the canonical Mozilla tree on the staged data-disk MUST match
# the DT_RUNPATH baked into each variant's DSOs (per ELF gABI §5.4); we honour
# that here by computing FF_INSTALL_DIR and FF_SENTINEL_BIN per package.
#
# What this script does
# ----------------------
#
#   1. Fetch apk-tools-static (statically-linked apk installer) and the
#      Alpine signing key, both from dl-cdn.alpinelinux.org.
#   2. Bootstrap a minimal Alpine rootfs in
#      ~/.cache/astryxos-firefox-musl/rootfs/ and `apk add firefox-esr`
#      (pulls 122 transitive deps + the musl libc itself).
#   3. Stage the rootfs into build/disk/ under the layout the kernel
#      pre-cache + ELF loader + dynamic-linker DT_RUNPATH expect:
#        - /disk/lib/ld-musl-x86_64.so.1     (interpreter, /lib/ in PT_INTERP)
#        - /disk/lib/libc.musl-x86_64.so.1   (musl libc, sibling of ld-musl)
#        - /disk/usr/lib/firefox-esr/...     (canonical Mozilla tree, matches
#                                              DT_RUNPATH baked into every
#                                              Mozilla DSO — readelf -d shows
#                                              RUNPATH=[/usr/lib/firefox-esr])
#        - /disk/opt/firefox/firefox-bin     (launcher mirror — small, kept
#                                              so the kernel launch and
#                                              pre-cache paths remain stable)
#        - /disk/usr/lib/                    (Alpine support libs flat:
#                                              libnss, libnspr, libsqlite,
#                                              ICU, GTK3, fontconfig, ...)
#
#      Per ELF gABI (System V ABI §5.4 "Shared Object Dependencies") and
#      ld-musl(8), the dynamic linker searches in order: LD_LIBRARY_PATH,
#      DT_RUNPATH, system defaults.  Placing Mozilla artefacts anywhere
#      other than DT_RUNPATH means transitive dlopen calls (libxul →
#      libmozsandbox.so etc.) fail with ENOENT and ld-musl exit_group()s.
#
# Idempotent — exits 0 if build/disk/opt/firefox/firefox-bin already exists
# and looks musl-linked.  Pass --force to rebuild.
#
# References (public)
#   - Alpine package index: https://pkgs.alpinelinux.org/packages?name=firefox-esr
#   - Alpine package CDN:   https://dl-cdn.alpinelinux.org/
#   - apk-tools:            https://gitlab.alpinelinux.org/alpine/apk-tools
#   - musl libc:            https://musl.libc.org/
#
# Usage:
#   bash scripts/install-firefox-musl.sh           # idempotent install
#   bash scripts/install-firefox-musl.sh --force   # rebuild rootfs + restage
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_OPT="${DISK_DIR}/opt/firefox"
DISK_LIB="${DISK_DIR}/lib"
DISK_USR_LIB="${DISK_DIR}/usr/lib"

CACHE_DIR="${HOME}/.cache/astryxos-firefox-musl"
APK_STATIC_DIR="${CACHE_DIR}/apk-tools"
ROOTFS="${CACHE_DIR}/rootfs"

# ── Pinned versions ──────────────────────────────────────────────────────────
# Bumping these is a deliberate act; do not auto-update.
ALPINE_VERSION="v3.20"
APK_TOOLS_VERSION="2.14.4-r1"
ALPINE_KEY="alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
ALPINE_KEY_URL="https://alpinelinux.org/keys/${ALPINE_KEY}"
APK_STATIC_URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/x86_64/apk-tools-static-${APK_TOOLS_VERSION}.apk"

# Package selection (env var + CLI override).  Default firefox-esr to preserve
# every existing caller's behaviour.
FIREFOX_PKG="${ASTRYXOS_FIREFOX_PACKAGE:-firefox-esr}"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        --package=*) FIREFOX_PKG="${arg#--package=}" ;;
        -h|--help)
            sed -n '2,60p' "$0"
            exit 0
            ;;
    esac
done

case "${FIREFOX_PKG}" in
    firefox-esr)
        # 115.x ESR — mirrors the glibc build (115.15.0 ESR).  Alpine layout:
        # /usr/lib/firefox-esr/{firefox-esr,libxul.so,...}.  No -dbg subpackage
        # — libxul attribution flows through Mozilla tecken (see
        # scripts/inject-libxul-symbols.sh --musl).
        FF_INSTALL_DIR_NAME="firefox-esr"
        FF_SENTINEL_BIN_NAME="firefox-esr"
        ;;
    firefox)
        # 132.x current — Alpine community/firefox at v3.20 ships 132.0.2-r0
        # with subpackages firefox-intl and firefox-dbg.  Alpine layout:
        # /usr/lib/firefox/{firefox,firefox-bin,libxul.so,...}.  -dbg companion
        # ships full .debug files with .symtab (~420k symbols including FUNC
        # records and minimal DWARF), so addr2line / nm / gdb resolve C++
        # function names automatically via the binary's .gnu_debuglink section
        # without any Mozilla tecken indirection.
        FF_INSTALL_DIR_NAME="firefox"
        FF_SENTINEL_BIN_NAME="firefox"
        ;;
    *)
        echo "[FF-MUSL] ERROR: unknown FIREFOX_PKG='${FIREFOX_PKG}' (expected firefox-esr|firefox)"
        echo "[FF-MUSL]        Set ASTRYXOS_FIREFOX_PACKAGE=firefox-esr|firefox or pass --package=..."
        exit 2
        ;;
esac

# Mozilla artefacts ship with DT_RUNPATH=/usr/lib/<package> baked into the
# ELF .dynamic section (where <package> is either "firefox-esr" or "firefox"
# depending on the build).  Per the ELF gABI (System V ABI §5.4 "Dynamic
# Linking — Shared Object Dependencies"), DT_RUNPATH is consulted when
# resolving DT_NEEDED entries.  FAT32 has no symlinks, so the canonical
# Mozilla tree (libxul.so, libmozsandbox.so, liblgpllibs.so, … and the
# browser/, defaults/, fonts/, gmp-clearkey/ subdirs) MUST be staged at this
# absolute path on disk for the dynamic linker to find them.
DISK_FF_TREE="${DISK_DIR}/usr/lib/${FF_INSTALL_DIR_NAME}"
FIREFOX_BIN="${DISK_OPT}/firefox-bin"

# Variant sentinel file lives at $DISK_OPT/.variant; we read it during the
# idempotency check so that switching packages forces a re-stage even when the
# raw files all exist (otherwise a prior firefox-esr stage would be reported
# "up-to-date" under a firefox-132 invocation that uses a different tree).
VARIANT_SENTINEL="${DISK_OPT}/.variant"
EXISTING_PKG=""
if [ -f "${VARIANT_SENTINEL}" ]; then
    EXISTING_PKG="$(grep -m1 '^package=' "${VARIANT_SENTINEL}" 2>/dev/null | cut -d= -f2 || true)"
fi

# ── Idempotency check ─────────────────────────────────────────────────────────
# We consider the install up-to-date if firefox-bin exists, is musl-linked
# (PT_INTERP = /lib/ld-musl-x86_64.so.1), the base shared libraries we stage
# from ${ROOTFS}/lib/ are present in ${DISK_LIB}, the canonical Mozilla tree
# is present at ${DISK_FF_TREE} (DT_RUNPATH), AND the variant sentinel reports
# the same package we are being asked to install (so a firefox-esr → firefox-132
# switch invalidates the cache automatically).
if [ "${FORCE}" = false ] && [ -f "${FIREFOX_BIN}" ] && \
   file "${FIREFOX_BIN}" 2>/dev/null | grep -q 'ld-musl' && \
   [ -e "${DISK_LIB}/libz.so.1" ] && \
   [ -e "${DISK_FF_TREE}/libxul.so" ] && \
   [ "${EXISTING_PKG}" = "${FIREFOX_PKG}" ]; then
    echo "[FF-MUSL] ${FIREFOX_BIN} present and musl-linked, base + runpath staged for ${FIREFOX_PKG} — skipping (use --force to reinstall)"
    exit 0
fi

echo "[FF-MUSL] Installing Alpine ${ALPINE_VERSION} musl ${FIREFOX_PKG}"

# ── Step 1: Fetch apk-tools-static + Alpine signing key (cached) ─────────────
mkdir -p "${APK_STATIC_DIR}" "${CACHE_DIR}"

APK_STATIC_APK="${APK_STATIC_DIR}/apk-tools-static.apk"
APK_BIN="${APK_STATIC_DIR}/sbin/apk.static"

if [ ! -x "${APK_BIN}" ] || [ "${FORCE}" = true ]; then
    echo "[FF-MUSL] Fetching apk-tools-static from ${APK_STATIC_URL}"
    curl -fsSL --max-time 120 -o "${APK_STATIC_APK}" "${APK_STATIC_URL}"
    tar -xzf "${APK_STATIC_APK}" -C "${APK_STATIC_DIR}" 2>/dev/null || true
    if [ ! -x "${APK_BIN}" ]; then
        echo "[FF-MUSL] ERROR: ${APK_BIN} not present after extraction"
        exit 1
    fi
fi

# ── Step 2: Bootstrap Alpine rootfs ──────────────────────────────────────────
# When switching packages we need a fresh rootfs (apk's solver can leave a
# hybrid state if we just `add firefox` over a `firefox-esr` rootfs).  Detect
# via the on-disk presence of the OTHER package's main install dir; if found,
# wipe so step 2 below installs cleanly.  Caller's explicit --force always wipes.
ALT_INSTALL_DIR=""
case "${FIREFOX_PKG}" in
    firefox-esr) ALT_INSTALL_DIR="${ROOTFS}/usr/lib/firefox" ;;
    firefox)     ALT_INSTALL_DIR="${ROOTFS}/usr/lib/firefox-esr" ;;
esac
if [ "${FORCE}" = true ] || \
   ( [ -n "${ALT_INSTALL_DIR}" ] && [ -d "${ALT_INSTALL_DIR}" ] ); then
    rm -rf "${ROOTFS}"
fi

# Sentinel for "package already installed in rootfs": the canonical binary file
# the package owns (firefox-esr's own ELF for ESR; "firefox-bin" for 132).
ROOTFS_FF_SENTINEL="${ROOTFS}/usr/lib/${FF_INSTALL_DIR_NAME}/${FF_SENTINEL_BIN_NAME}"
if [ ! -f "${ROOTFS_FF_SENTINEL}" ]; then
    echo "[FF-MUSL] Bootstrapping Alpine rootfs at ${ROOTFS}"
    mkdir -p "${ROOTFS}/etc/apk/keys" "${ROOTFS}/var/cache/apk"

    # Fetch signing key (public; published by Alpine for years)
    if [ ! -f "${ROOTFS}/etc/apk/keys/${ALPINE_KEY}" ]; then
        curl -fsSL --max-time 60 -o "${ROOTFS}/etc/apk/keys/${ALPINE_KEY}" "${ALPINE_KEY_URL}"
    fi

    cat > "${ROOTFS}/etc/apk/repositories" <<EOF
https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main
https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/community
EOF

    # apk.static will print chroot errors for post-install triggers because we
    # are running unprivileged; those affect only icon-cache regeneration and
    # similar housekeeping — the actual file install succeeds.  We exit 0 on
    # the trigger failures and verify the result by file presence below.
    "${APK_BIN}" \
        --root="${ROOTFS}" \
        --arch=x86_64 \
        --no-cache \
        --initdb \
        add "${FIREFOX_PKG}" 2>&1 \
        | sed 's/^/[FF-MUSL apk] /' \
        | tail -40 || true

    if [ ! -f "${ROOTFS_FF_SENTINEL}" ]; then
        echo "[FF-MUSL] ERROR: ${FIREFOX_PKG} not present in rootfs after apk add"
        echo "[FF-MUSL]        Expected file: ${ROOTFS_FF_SENTINEL}"
        exit 1
    fi
fi

INSTALLED_VERSION="$(grep -m1 "^P:${FIREFOX_PKG}\$" -A1 "${ROOTFS}/lib/apk/db/installed" 2>/dev/null | \
                     grep '^V:' | cut -d: -f2 || echo unknown)"
echo "[FF-MUSL] Alpine rootfs contains ${FIREFOX_PKG} ${INSTALLED_VERSION}"
echo "[FF-MUSL]   rootfs size: $(du -sh "${ROOTFS}" | cut -f1)"

# ── Step 3: Stage rootfs into build/disk/ ────────────────────────────────────
# We need a clean staging layout for create-data-disk.sh.  Two requirements:
#
#   (a) The ELF interpreter path baked into the binaries (/lib/ld-musl-x86_64.so.1
#       per PT_INTERP) must resolve.  Our kernel VFS maps /lib → /disk/lib, so
#       the file must land at build/disk/lib/ld-musl-x86_64.so.1.
#
#   (b) The kernel pre-cache (main.rs) hard-codes /disk/opt/firefox/firefox-bin
#       and /disk/opt/firefox/libxul.so.  We keep those paths so the pre-cache
#       still works; firefox-bin is renamed from Alpine's "firefox-esr".
#
# We DO NOT clobber a coexisting glibc Firefox install — the caller decides
# which variant to stage via create-data-disk.sh's variant selector.  But for
# safety, we wipe build/disk/opt/firefox/ before staging the musl tree so
# we cannot end up with a hybrid (glibc firefox-bin + musl libxul.so).

echo "[FF-MUSL] Staging musl Firefox into ${DISK_DIR}"

# (a) musl interpreter + libc + Alpine "base" shared libraries
#
# Alpine places several runtime libraries in /lib/ rather than /usr/lib/:
# the musl interpreter (ld-musl-x86_64.so.1) and libc symlink, plus a
# small but load-bearing set of "base" libs that firefox-esr's deps
# transitively pull in:
#
#   libz.so.1            (zlib       — used by libpng, libxml2, fontconfig,
#                                       libxul itself for compressed assets)
#   libcrypto.so.3       (openssl    — NSS depends on it; libxul uses it
#                                       for TLS / signature verification)
#   libssl.so.3          (openssl    — same as above)
#   libblkid.so.1        (util-linux — pulled by glib's GIO mount monitor)
#   libmount.so.1        (util-linux — same as above)
#
# Missing libz.so.1 specifically caused musl-FF to abort at sc≈548 during
# the library-load chain (libxul → libpng16 → libz lookup → ld-musl
# exit_group(255) on the unresolved DT_NEEDED) — see PR #298 trial.  We
# stage the entire /lib/ tree, dereferencing symlinks (FAT32 has none),
# to mirror the /usr/lib/ approach in step (c) — Alpine version bumps
# that move libs between /lib/ and /usr/lib/ then "just work" without
# further script changes.
mkdir -p "${DISK_LIB}"
for f in "${ROOTFS}"/lib/*; do
    [ -e "${f}" ] || continue
    name="$(basename "${f}")"
    # Skip apk's bookkeeping (/lib/apk/db/...); not useful at runtime.
    [ "${name}" = "apk" ] && continue
    if [ -L "${f}" ]; then
        # Symlink: dereference to a real file under the link name so the
        # dynamic linker finds e.g. libz.so.1 as a real ELF, not a
        # dangling link (FAT32 has no symlinks).
        cp -fL "${f}" "${DISK_LIB}/${name}"
    elif [ -f "${f}" ]; then
        cp -f  "${f}" "${DISK_LIB}/${name}"
    elif [ -d "${f}" ]; then
        # Recurse for subdirs (none expected today, but defensive against
        # Alpine layout changes).
        cp -aL "${f}" "${DISK_LIB}/" 2>/dev/null || \
            cp -a  "${f}" "${DISK_LIB}/"
    fi
done

# (b) Wipe prior /opt/firefox/ and BOTH possible /usr/lib/<pkg>/ trees so we
# cannot end up with a hybrid (e.g. glibc firefox-bin + musl libxul.so, or
# firefox-esr libxul.so left over from a prior run + firefox-132 firefox-bin).
# Step (c) below will repopulate /usr/lib/${FF_INSTALL_DIR_NAME}/ from the
# rootfs.
#
# DT_RUNPATH context: every Mozilla ELF (firefox-bin, libxul.so,
# libmozsandbox.so, ...) carries DT_RUNPATH=/usr/lib/<package-name> per
# readelf -d (where <package-name> is "firefox-esr" for 115.x or "firefox"
# for 132.x).  Per the ELF gABI (System V ABI §5.4 "Shared Object
# Dependencies") and ld-musl(8), DT_RUNPATH is consulted after
# LD_LIBRARY_PATH for DT_NEEDED resolution.  Placing the Mozilla tree
# anywhere else means libxul's dlopen for its sibling .so files fails with
# ENOENT and ld-musl exit_group()s.  The canonical tree must live at
# /disk/usr/lib/${FF_INSTALL_DIR_NAME}/ (mapped to guest path by the kernel's
# /usr → /disk/usr VFS symlink).
#
# We keep a minimal /opt/firefox/ duplicate consisting of firefox-bin alone
# (~795 KiB) so the kernel's launch path (kernel/src/main.rs:508) and
# pre-cache loader (kernel/src/main.rs:455) remain stable.  The launched
# ELF's DT_RUNPATH is absolute, not relative to its on-disk location.
rm -rf "${DISK_OPT}" "${DISK_DIR}/usr/lib/firefox-esr" "${DISK_DIR}/usr/lib/firefox"
mkdir -p "${DISK_OPT}"

# (c) Support libraries from Alpine's /usr/lib/.  Strip Alpine-specific
# build helpers (apk db, pkgconfig data, header dirs) and keep only the
# .so* files plus the directory structure.
mkdir -p "${DISK_USR_LIB}"
# We deliberately copy the whole /usr/lib tree (~325 MiB including the
# /usr/lib/firefox-esr/ subdir = ~206 MiB) so transitive deps (icu, libnss /
# nspr / nssutil / smime / sqlite, ffi, ssl3, GTK, libavcodec, ...) are all
# available AND the canonical Mozilla tree lands at the DT_RUNPATH path.
# `cp -aL` preserves hard-link relationships within the tree — Alpine ships
# several library SONAMEs as hard links to the fully-versioned file
# (libgtk-3.so.0 ↔ libgtk-3.so.0.2411.32, etc.).  Breaking those by
# walking the tree file-by-file would inflate /usr/lib from ~120 MiB
# (non-firefox-esr portion) to ~225 MiB.
cp -aL "${ROOTFS}/usr/lib/." "${DISK_USR_LIB}/" 2>/dev/null || true
# Drop apk's bookkeeping; not useful at runtime.
rm -rf "${DISK_USR_LIB}/apk" 2>/dev/null || true

# Within ${DISK_FF_TREE}: ensure both "firefox-bin" and "firefox" sentinel
# names exist so callers that follow the launcher's readlink("/proc/self/exe")
# + "-bin" convention (or its plain-name fallback) resolve there.
#
# Per-package starting point:
#   firefox-esr (115.x): Alpine ships the ELF as "firefox-esr".  We copy it
#                        as "firefox-bin" and "firefox" for caller convenience.
#                        Strip the Alpine-internal "firefox-esr-bin" symlink
#                        to /usr/bin/firefox-esr — we use the ELF directly.
#   firefox (132.x):     Alpine already ships both "firefox" and "firefox-bin"
#                        (firefox-bin is the real ELF; firefox is a small shell
#                        wrapper).  Nothing to rename.
case "${FIREFOX_PKG}" in
    firefox-esr)
        if [ -f "${DISK_FF_TREE}/firefox-esr" ]; then
            cp -f "${DISK_FF_TREE}/firefox-esr" "${DISK_FF_TREE}/firefox-bin"
            cp -f "${DISK_FF_TREE}/firefox-esr" "${DISK_FF_TREE}/firefox"
        fi
        rm -f "${DISK_FF_TREE}/firefox-esr-bin"
        ;;
    firefox)
        # Alpine community/firefox 132.x layout (verified via apk extract):
        #   /usr/lib/firefox/firefox      → real ELF (musl interp), what we run.
        #   /usr/lib/firefox/firefox-bin  → symlink to /usr/bin/firefox
        #                                    (the wrapper); cp -L resolves this
        #                                    to the wrapper script during staging,
        #                                    which is NOT the ELF we want.
        #   /usr/bin/firefox              → POSIX-sh wrapper "exec
        #                                    /usr/lib/firefox/firefox \"$@\"".
        #
        # We use the real ELF directly to bypass the wrapper.  Replace the
        # bogus firefox-bin (resolved from the symlink) with a copy of the
        # actual ELF so every caller — kernel pre-cache, kernel launch path,
        # test_runner — sees the same musl-PIE binary at "firefox-bin".
        if [ -f "${DISK_FF_TREE}/firefox" ]; then
            cp -f "${DISK_FF_TREE}/firefox" "${DISK_FF_TREE}/firefox-bin"
        fi
        ;;
esac

# Mirror firefox-bin into /disk/opt/firefox/ (kernel launch + pre-cache path
# stability).  Do NOT mirror the .so files — DT_RUNPATH is
# /usr/lib/${FF_INSTALL_DIR_NAME}/, so a duplicate libxul at /opt/firefox/
# would never be loaded and would waste ~160 MiB of FAT32 capacity.
cp -f "${DISK_FF_TREE}/firefox-bin" "${DISK_OPT}/firefox-bin"
cp -f "${DISK_FF_TREE}/firefox-bin" "${DISK_OPT}/firefox"

# (d) Etc — fontconfig / nss / dbus config that musl Firefox reads at runtime.
mkdir -p "${DISK_DIR}/etc"
for sub in fonts ssl nsswitch.conf hosts; do
    if [ -e "${ROOTFS}/etc/${sub}" ]; then
        cp -aL "${ROOTFS}/etc/${sub}" "${DISK_DIR}/etc/" 2>/dev/null || true
    fi
done

# (e) Drop a sentinel file so the kernel / scripts can detect which variant
# was installed without binary-probing /opt/firefox/firefox-bin.  The
# `package=` field is consumed by the idempotency check at the top of this
# script so an ESR→132 (or vice-versa) switch triggers a full re-stage.
cat > "${DISK_OPT}/.variant" <<EOF
variant=musl
package=${FIREFOX_PKG}
install_dir=/usr/lib/${FF_INSTALL_DIR_NAME}
alpine_version=${ALPINE_VERSION}
firefox_version=${INSTALLED_VERSION}
apk_tools_version=${APK_TOOLS_VERSION}
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# ── Step 4: Sanity-check the staged tree ─────────────────────────────────────
if [ ! -f "${FIREFOX_BIN}" ]; then
    echo "[FF-MUSL] ERROR: ${FIREFOX_BIN} missing after staging"
    exit 1
fi
if ! file "${FIREFOX_BIN}" 2>/dev/null | grep -q 'ld-musl'; then
    echo "[FF-MUSL] ERROR: ${FIREFOX_BIN} is not musl-linked"
    file "${FIREFOX_BIN}"
    exit 1
fi
if [ ! -f "${DISK_LIB}/ld-musl-x86_64.so.1" ]; then
    echo "[FF-MUSL] ERROR: ${DISK_LIB}/ld-musl-x86_64.so.1 missing"
    exit 1
fi
# Verify the canonical Mozilla tree landed at DT_RUNPATH.  libxul.so under
# /usr/lib/${FF_INSTALL_DIR_NAME}/ is the single most load-bearing file —
# every Mozilla DSO dlopen indirects through DT_RUNPATH to that directory.
# See readelf -d output: firefox-bin, libxul.so, libmozsandbox.so all have
# DT_RUNPATH=/usr/lib/<package> per ELF gABI §5.4.
if [ ! -f "${DISK_FF_TREE}/libxul.so" ]; then
    echo "[FF-MUSL] ERROR: ${DISK_FF_TREE}/libxul.so missing — DT_RUNPATH lookup will fail"
    exit 1
fi
if [ ! -f "${DISK_FF_TREE}/libmozsandbox.so" ]; then
    echo "[FF-MUSL] ERROR: ${DISK_FF_TREE}/libmozsandbox.so missing — first DT_NEEDED of libxul will fail"
    exit 1
fi
# Verify the base shared libs landed.  libz in particular is mandatory —
# libxul DT_NEEDEDs it (via libpng16 / libxml2), and ld-musl will
# exit_group on missing libz at first dlopen.  See PR #298 trial.
MISSING_BASE_LIBS=""
for lib in libz.so.1 libcrypto.so.3 libssl.so.3; do
    if [ ! -e "${DISK_LIB}/${lib}" ]; then
        MISSING_BASE_LIBS="${MISSING_BASE_LIBS} ${lib}"
    fi
done
if [ -n "${MISSING_BASE_LIBS}" ]; then
    echo "[FF-MUSL] ERROR: required base libs missing from ${DISK_LIB}:${MISSING_BASE_LIBS}"
    echo "[FF-MUSL]        Alpine may have moved them out of /lib/ in this release"
    echo "[FF-MUSL]        — check ${ROOTFS}/usr/lib/ and extend stage step (a)."
    exit 1
fi

echo "[FF-MUSL] Staged (${FIREFOX_PKG} ${INSTALLED_VERSION}):"
echo "[FF-MUSL]   firefox-bin (launcher):       $(stat -c%s "${FIREFOX_BIN}") bytes, musl PT_INTERP"
echo "[FF-MUSL]   firefox-bin (runpath):        $(stat -c%s "${DISK_FF_TREE}/firefox-bin") bytes"
echo "[FF-MUSL]   libxul.so (runpath):          $(stat -c%s "${DISK_FF_TREE}/libxul.so") bytes"
echo "[FF-MUSL]   libmozsandbox (runpath):      $(stat -c%s "${DISK_FF_TREE}/libmozsandbox.so") bytes"
echo "[FF-MUSL]   ld-musl:                      $(stat -c%s "${DISK_LIB}/ld-musl-x86_64.so.1") bytes"
echo "[FF-MUSL]   libz.so.1:                    $(stat -c%s "${DISK_LIB}/libz.so.1") bytes"
echo "[FF-MUSL]   /lib:                         $(du -sh "${DISK_LIB}" | cut -f1)"
echo "[FF-MUSL]   /opt/firefox (launcher):      $(du -sh "${DISK_OPT}" | cut -f1)"
echo "[FF-MUSL]   /usr/lib/${FF_INSTALL_DIR_NAME} (runpath): $(du -sh "${DISK_FF_TREE}" | cut -f1)"
echo "[FF-MUSL]   /usr/lib (total):             $(du -sh "${DISK_USR_LIB}" | cut -f1)"
echo "[FF-MUSL] Done."
