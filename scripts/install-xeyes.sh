#!/usr/bin/env bash
#
# install-xeyes.sh — Stage Alpine's `xeyes` (and the deps not already pulled in
# by the musl Firefox install) into the AstryxOS data-disk staging tree.
#
# Why xeyes?
# ----------
# xeyes is the canonical X11 "hello world": ~28 KB binary, no IPC fan-out, no
# JIT, no SSP-canary stamping, no DT_RUNPATH games.  It exercises:
#
#   - X11 protocol handshake (Xastryx server in kernel/src/x11/)
#   - libX11 socket round-trip + Xrender ARGB visual
#   - libXt application-shell event loop (XtAppMainLoop)
#   - libXmu shape mask + libXi pointer-motion events
#
# It does NOT exercise:
#   - vfork/posix_spawn (no SSP saga path)
#   - multi-process IPC
#   - any heavy allocator path that hits the FILE+0x58 W215 corruption
#   - DT_TLS / __stack_chk_guard stamping (the binary itself is built without
#     -fstack-protector; libX11/libXt have callsites but they reach a real
#     musl __stack_chk_guard via the static-TLS path)
#
# Per the F3 saga close (PR #368), Reframe B (SSP arm-site offset) is upstream
# libxul + musl behaviour.  xeyes is a smaller stresser of the same musl libc
# + ld-musl + X11 stack that does NOT enter the libxul indirect-call swamp,
# letting us prove the kernel can run a real Linux Alpine X11 binary end-to-end.
#
# What this script does
# ----------------------
#
#   1. Reuses the shared Alpine rootfs created by install-firefox-musl.sh at
#      ~/.cache/astryxos-firefox-musl/rootfs/ (so we don't fetch a second
#      Alpine bootstrap).  Adds `xeyes` to it via apk-static if not present.
#   2. Stages the xeyes ELF + the 5 deps not already in build/disk/usr/lib
#      (libXt.so.6, libXmu.so.6, libSM.so.6, libICE.so.6, libuuid.so.1).
#      Everything else (libX11, libXi, libXext, libXrender, libxcb*, ld-musl,
#      libc.musl) is shared with the Firefox stage and stays in place.
#   3. Stages the xeyes binary to build/disk/usr/bin/xeyes.
#
# create-data-disk.sh's musl branch already copies build/disk/usr/lib/*.so* to
# the data.img; the only data-disk-side wiring this script needs is for
# create-data-disk.sh to additionally copy /usr/bin/xeyes from build/disk
# into the FAT32 image (handled by a small `xeyes-test`-aware addition there).
#
# References (public)
#   - xeyes upstream: https://gitlab.freedesktop.org/xorg/app/xeyes
#   - Alpine xeyes:   https://pkgs.alpinelinux.org/package/v3.20/community/x86_64/xeyes
#   - X11 protocol:   https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html
#   - libXt manual:   https://www.x.org/releases/X11R7.7/doc/libXt/intrinsics.html
#   - musl libc:      https://musl.libc.org/
#
# Idempotent — exits 0 cleanly if every required artefact is already staged.
# Pass --force to refresh the rootfs and restage.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_USR_BIN="${DISK_DIR}/usr/bin"
DISK_USR_LIB="${DISK_DIR}/usr/lib"

# Reuse the musl Firefox cache — apk-static, keys, and a populated rootfs.
CACHE_DIR="${HOME}/.cache/astryxos-firefox-musl"
APK_STATIC="${CACHE_DIR}/apk-tools/sbin/apk.static"
ROOTFS="${CACHE_DIR}/rootfs"
ALPINE_KEYS="${ROOTFS}/etc/apk/keys"

ALPINE_VERSION="v3.20"
ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main"
ALPINE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/community"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help)
            sed -n '2,55p' "$0"
            exit 0
            ;;
    esac
done

# ── Sanity: the musl Firefox cache must exist (we share its bootstrap) ───────
if [ ! -x "${APK_STATIC}" ] || [ ! -d "${ROOTFS}" ] || [ ! -d "${ALPINE_KEYS}" ]; then
    echo "[XEYES] ERROR: shared Alpine rootfs not present at ${CACHE_DIR}"
    echo "[XEYES]        Run scripts/install-firefox-musl.sh first to bootstrap apk-static + ${ROOTFS}."
    exit 1
fi

# ── Step 1: install xeyes into the shared rootfs (skip if already there) ─────
XEYES_BIN="${ROOTFS}/usr/bin/xeyes"
if [ ! -x "${XEYES_BIN}" ] || [ "${FORCE}" = true ]; then
    echo "[XEYES] Installing xeyes via apk into ${ROOTFS} ..."
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --repository "${ALPINE_COMMUNITY}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --no-scripts \
        --update-cache \
        add xeyes 2>&1 | sed 's/^/[XEYES]   /'
fi

if [ ! -x "${XEYES_BIN}" ]; then
    echo "[XEYES] ERROR: xeyes binary still missing at ${XEYES_BIN} after apk add"
    exit 1
fi

# ── Step 2: stage xeyes binary + missing deps into build/disk/ ───────────────
mkdir -p "${DISK_USR_BIN}" "${DISK_USR_LIB}"

# xeyes ELF
cp -fL "${XEYES_BIN}" "${DISK_USR_BIN}/xeyes"
chmod +x "${DISK_USR_BIN}/xeyes"
echo "[XEYES] Staged usr/bin/xeyes ($(stat -c%s "${DISK_USR_BIN}/xeyes") bytes)"

# Deps not already staged by install-firefox-musl.sh.  Each entry is "src;dst"
# under ROOTFS / DISK respectively.  We copy both the SONAME symlink target
# (resolved via cp -L) and create the soname filename on the FAT32 staging
# side — FAT32 has no symlinks, so SONAME-as-file is the only resolution path.
declare -a NEEDED=(
    "usr/lib/libXt.so.6:usr/lib/libXt.so.6"
    "usr/lib/libXmu.so.6:usr/lib/libXmu.so.6"
    "usr/lib/libSM.so.6:usr/lib/libSM.so.6"
    "usr/lib/libICE.so.6:usr/lib/libICE.so.6"
    "lib/libuuid.so.1:usr/lib/libuuid.so.1"   # Alpine puts libuuid in /lib; mirror to /usr/lib for AstryxOS search
)

stage_count=0
for entry in "${NEEDED[@]}"; do
    src="${ROOTFS}/${entry%%:*}"
    dst="${DISK_DIR}/${entry##*:}"
    dst_dir="$(dirname "${dst}")"
    mkdir -p "${dst_dir}"
    if [ ! -f "${src}" ]; then
        echo "[XEYES] WARNING: ${src} missing in rootfs (apk add may have skipped a dep)"
        continue
    fi
    cp -fL "${src}" "${dst}"
    stage_count=$((stage_count + 1))
done
echo "[XEYES] Staged ${stage_count}/${#NEEDED[@]} dep libs to ${DISK_USR_LIB}"

# ── Step 3: sanity dump — every NEEDED entry of xeyes resolves under disk/ ───
echo "[XEYES] Validating dependency closure for ${DISK_USR_BIN}/xeyes ..."
missing=0
while IFS= read -r need; do
    case "${need}" in
        "libc.musl-x86_64.so.1")
            if [ ! -f "${DISK_DIR}/lib/${need}" ]; then
                echo "[XEYES]   MISSING /lib/${need} (musl libc — install-firefox-musl.sh should have staged it)"
                missing=$((missing + 1))
            fi ;;
        *)
            if [ ! -f "${DISK_USR_LIB}/${need}" ]; then
                echo "[XEYES]   MISSING /usr/lib/${need}"
                missing=$((missing + 1))
            fi ;;
    esac
done < <(readelf -d "${DISK_USR_BIN}/xeyes" | awk -F'[][]' '/NEEDED/ {print $2}')

if [ "${missing}" -gt 0 ]; then
    echo "[XEYES] ERROR: ${missing} NEEDED entries unresolved under build/disk/"
    echo "[XEYES]        xeyes will fail at ld-musl startup with ENOENT."
    exit 1
fi
echo "[XEYES] OK — every NEEDED entry resolves under build/disk/."
echo "[XEYES] Done.  Re-run scripts/create-data-disk.sh --force to refresh data.img."
