#!/usr/bin/env bash
#
# install-firefox-musl.sh — Stage Alpine Linux's musl-linked Firefox ESR
# into the AstryxOS data-disk staging tree.
#
# Why musl?  The glibc Firefox plateau (sc=2902 frozen for 28+ min, TID 2 in
# NS_ProcessNextEvent) is hypothesised to be glibc-specific — glibc's
# pthread_cond two-group cycling (BZ 25847) and arena-locked malloc generate
# fundamentally different futex / mutex traffic than musl's single-slot
# cond_var and simpler allocator.  Swapping the libc tests whether the
# kernel publication paths intersect those primitives.
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
#      pre-cache + ELF loader expect:
#        - /disk/lib/ld-musl-x86_64.so.1     (interpreter, /lib/ in PT_INTERP)
#        - /disk/lib/libc.musl-x86_64.so.1   (musl libc, symlink to ld-musl)
#        - /disk/opt/firefox/firefox-bin     (the ELF; kernel pre-cache target)
#        - /disk/opt/firefox/libxul.so       (kernel pre-cache target)
#        - /disk/opt/firefox/...              (all other Mozilla artefacts)
#        - /disk/usr/lib/                    (all Alpine support libs)
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
FIREFOX_BIN="${DISK_OPT}/firefox-bin"

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
FIREFOX_PKG="firefox-esr"   # 115.x ESR — mirrors the glibc build (115.15.0 ESR)

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
    esac
done

# ── Idempotency check ─────────────────────────────────────────────────────────
# We consider the install up-to-date if firefox-bin exists AND its PT_INTERP
# is /lib/ld-musl-x86_64.so.1 (which proves it is the musl variant, not the
# leftover glibc Firefox).
if [ "${FORCE}" = false ] && [ -f "${FIREFOX_BIN}" ] && \
   file "${FIREFOX_BIN}" 2>/dev/null | grep -q 'ld-musl'; then
    echo "[FF-MUSL] ${FIREFOX_BIN} present and musl-linked — skipping (use --force to reinstall)"
    exit 0
fi

echo "[FF-MUSL] Installing Alpine ${ALPINE_VERSION} musl Firefox ESR"

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
if [ "${FORCE}" = true ]; then
    rm -rf "${ROOTFS}"
fi

if [ ! -f "${ROOTFS}/usr/lib/firefox-esr/firefox-esr" ]; then
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

    if [ ! -f "${ROOTFS}/usr/lib/firefox-esr/firefox-esr" ]; then
        echo "[FF-MUSL] ERROR: firefox-esr not present in rootfs after apk add"
        exit 1
    fi
fi

INSTALLED_VERSION="$(grep -m1 '^P:firefox-esr$' -A1 "${ROOTFS}/lib/apk/db/installed" 2>/dev/null | \
                     grep '^V:' | cut -d: -f2 || echo unknown)"
echo "[FF-MUSL] Alpine rootfs contains firefox-esr ${INSTALLED_VERSION}"
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

# (a) musl interpreter + libc
mkdir -p "${DISK_LIB}"
cp -f "${ROOTFS}/lib/ld-musl-x86_64.so.1" "${DISK_LIB}/ld-musl-x86_64.so.1"
# libc.musl-x86_64.so.1 is a symlink to ld-musl in Alpine; FAT32 has no
# symlinks, so we copy the resolved file under the link name.
cp -fL "${ROOTFS}/lib/libc.musl-x86_64.so.1" "${DISK_LIB}/libc.musl-x86_64.so.1"

# (b) Firefox tree.  Clear any prior contents so we cannot end up with a
# glibc/musl hybrid in /disk/opt/firefox/.
rm -rf "${DISK_OPT}"
mkdir -p "${DISK_OPT}"

# Copy everything Alpine staged at /usr/lib/firefox-esr/ into /opt/firefox/.
# This preserves Mozilla's expected internal layout (omni.ja, browser/,
# defaults/, fonts/, etc.).
cp -aL "${ROOTFS}/usr/lib/firefox-esr/." "${DISK_OPT}/" 2>/dev/null || \
    cp -a  "${ROOTFS}/usr/lib/firefox-esr/." "${DISK_OPT}/"

# Rename Alpine's "firefox-esr" → "firefox-bin" so the kernel pre-cache
# path /disk/opt/firefox/firefox-bin works without kernel changes.  Also
# create a "firefox" alias for any caller using the unsuffixed name.
if [ -f "${DISK_OPT}/firefox-esr" ]; then
    cp -f "${DISK_OPT}/firefox-esr" "${DISK_OPT}/firefox-bin"
    cp -f "${DISK_OPT}/firefox-esr" "${DISK_OPT}/firefox"
fi
# firefox-esr-bin is an Alpine internal symlink to /usr/bin/firefox-esr (a
# shell wrapper); strip it — we're using the resolved ELF directly.
rm -f "${DISK_OPT}/firefox-esr-bin"

# (c) Support libraries from Alpine's /usr/lib/.  Strip Alpine-specific
# build helpers (apk db, pkgconfig data, header dirs) and keep only the
# .so* files plus the directory structure.
mkdir -p "${DISK_USR_LIB}"
# Copy every regular file (cp -L derefs symlinks → real bytes under link name,
# matching the FAT32-friendly approach used elsewhere in create-data-disk.sh).
# We deliberately copy the whole /usr/lib tree (~120 MiB) so transitive deps
# (icu, libnss/nspr/nssutil/smime/sqlite, ffi, ssl3, etc.) are all available.
cp -aL "${ROOTFS}/usr/lib/." "${DISK_USR_LIB}/" 2>/dev/null || true
# Drop the firefox-esr subdir from /usr/lib/ — we already staged it at
# /opt/firefox/ above; keeping two copies would waste ~205 MiB.
rm -rf "${DISK_USR_LIB}/firefox-esr"
# Drop apk's bookkeeping; not useful at runtime.
rm -rf "${DISK_USR_LIB}/apk" "${DISK_USR_LIB}/.." 2>/dev/null || true

# (d) Etc — fontconfig / nss / dbus config that musl Firefox reads at runtime.
mkdir -p "${DISK_DIR}/etc"
for sub in fonts ssl nsswitch.conf hosts; do
    if [ -e "${ROOTFS}/etc/${sub}" ]; then
        cp -aL "${ROOTFS}/etc/${sub}" "${DISK_DIR}/etc/" 2>/dev/null || true
    fi
done

# (e) Drop a sentinel file so the kernel / scripts can detect which variant
# was installed without binary-probing /opt/firefox/firefox-bin.
cat > "${DISK_OPT}/.variant" <<EOF
variant=musl
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

echo "[FF-MUSL] Staged:"
echo "[FF-MUSL]   firefox-bin: $(stat -c%s "${FIREFOX_BIN}") bytes, musl PT_INTERP"
echo "[FF-MUSL]   libxul.so:   $(stat -c%s "${DISK_OPT}/libxul.so") bytes"
echo "[FF-MUSL]   ld-musl:     $(stat -c%s "${DISK_LIB}/ld-musl-x86_64.so.1") bytes"
echo "[FF-MUSL]   /opt/firefox: $(du -sh "${DISK_OPT}" | cut -f1)"
echo "[FF-MUSL]   /usr/lib:     $(du -sh "${DISK_USR_LIB}" | cut -f1)"
echo "[FF-MUSL] Done."
