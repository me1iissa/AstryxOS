#!/usr/bin/env bash
#
# install-busybox-cli.sh — Stage Alpine's statically-linked busybox-static
# (1.36.1) into the AstryxOS data-disk staging tree as `/bin/busybox`, plus
# a small set of /etc seed files used by the busybox-test / wget-test
# CLI demo soaks.
#
# Why busybox-static?
# -------------------
# Single, self-contained, statically-linked ELF (~1 MB stripped, no
# ld-musl involvement, no DT_NEEDED entries).  Provides ~400 standard
# CLI applets (ls, cat, sh, echo, uname, du, wget, ...) selected via
# argv[0] or argv[1] (the BusyBox multi-call dispatch).  This is the
# narrowest possible AstryxOS-kernel proof for "can we run a real
# Linux CLI binary end-to-end" — no dynamic linker, no PLT/GOT, no
# TLS surprises, just the static ELF loader, syscalls, and brk/mmap.
#
# What this script does
# ---------------------
#
#   1. Reuses the shared Alpine rootfs created by install-firefox-musl.sh
#      at ~/.cache/astryxos-firefox-musl/rootfs/ — adds the
#      `busybox-static` package via apk-static if /bin/busybox.static is
#      not already present.  No second Alpine bootstrap.
#   2. Stages the static binary at build/disk/bin/busybox (the path the
#      existing test_runner::test_busybox_basic and the new
#      busybox-test / wget-test feature paths both consult).
#   3. Seeds build/disk/etc/os-release with an AstryxOS identifier so
#      `busybox cat /etc/os-release` produces deterministic output.
#
# Idempotent.  Pass --force to refresh the rootfs entry and restage.
#
# References (public)
#   - BusyBox upstream: https://busybox.net/
#   - Alpine busybox-static package:
#     https://pkgs.alpinelinux.org/package/v3.20/main/x86_64/busybox-static
#   - os-release spec:
#     https://www.freedesktop.org/software/systemd/man/os-release.html
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_BIN="${DISK_DIR}/bin"
DISK_ETC="${DISK_DIR}/etc"

# Shared Alpine rootfs — see install-firefox-musl.sh + install-xeyes.sh
CACHE_DIR="${HOME}/.cache/astryxos-firefox-musl"
APK_STATIC="${CACHE_DIR}/apk-tools/sbin/apk.static"
ROOTFS="${CACHE_DIR}/rootfs"
ALPINE_KEYS="${ROOTFS}/etc/apk/keys"

ALPINE_VERSION="v3.20"
ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    esac
done

# ── Sanity: the shared Alpine rootfs must exist ──────────────────────────────
if [ ! -x "${APK_STATIC}" ] || [ ! -d "${ROOTFS}" ] || [ ! -d "${ALPINE_KEYS}" ]; then
    echo "[BUSYBOX-CLI] ERROR: shared Alpine rootfs not present at ${CACHE_DIR}"
    echo "[BUSYBOX-CLI]        Run scripts/install-firefox-musl.sh first to bootstrap."
    exit 1
fi

# ── Step 1: install busybox-static into the shared rootfs (idempotent) ───────
BB_STATIC="${ROOTFS}/bin/busybox.static"
if [ ! -x "${BB_STATIC}" ] || [ "${FORCE}" = true ]; then
    echo "[BUSYBOX-CLI] Installing busybox-static via apk into ${ROOTFS} ..."
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --no-scripts \
        --update-cache \
        add busybox-static 2>&1 | sed 's/^/[BUSYBOX-CLI]   /'
fi

if [ ! -x "${BB_STATIC}" ]; then
    echo "[BUSYBOX-CLI] ERROR: ${BB_STATIC} still missing after apk add"
    exit 1
fi

# Sanity: verify the binary really is statically linked.  If a future
# Alpine release ships a dynamically-linked busybox-static (would be a
# packaging bug) the kernel test path would fail with ENOENT on
# ld-musl, not on a missing applet, and the failure mode would be
# confusing.  Detect at staging time instead.
if ! file "${BB_STATIC}" 2>/dev/null | grep -q 'statically linked'; then
    echo "[BUSYBOX-CLI] ERROR: ${BB_STATIC} is not statically linked:"
    file "${BB_STATIC}" 2>&1 | sed 's/^/[BUSYBOX-CLI]   /'
    exit 1
fi

# ── Step 2: stage as build/disk/bin/busybox ──────────────────────────────────
mkdir -p "${DISK_BIN}" "${DISK_ETC}"

cp -fL "${BB_STATIC}" "${DISK_BIN}/busybox"
chmod +x "${DISK_BIN}/busybox"
echo "[BUSYBOX-CLI] Staged /bin/busybox ($(stat -c%s "${DISK_BIN}/busybox") bytes, statically linked)"

# ── Step 3: seed /etc/os-release ─────────────────────────────────────────────
# `busybox cat /etc/os-release` is one of the demo applets; staging a
# deterministic file makes the captured stdout comparison deterministic.
# Format per freedesktop.org os-release(5).
cat > "${DISK_ETC}/os-release" <<'EOF'
NAME="AstryxOS"
ID=astryxos
VERSION_ID=demo
PRETTY_NAME="AstryxOS (demo)"
HOME_URL="https://example.org/astryxos"
EOF
echo "[BUSYBOX-CLI] Seeded /etc/os-release ($(stat -c%s "${DISK_ETC}/os-release") bytes)"

echo "[BUSYBOX-CLI] Done.  Re-run scripts/create-data-disk.sh --force to refresh data.img."
