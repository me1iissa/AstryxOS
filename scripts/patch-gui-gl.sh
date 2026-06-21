#!/usr/bin/env bash
# patch-gui-gl.sh — inject the software-OpenGL (Mesa llvmpipe) runtime closure
# the windowed (--ff-gui) Firefox path needs into an existing ext2 data image,
# WITHOUT a full create-data-disk.sh rebuild.
#
# Why this exists
# ---------------
# Firefox's GPU-feature probe (the `glxtest` child) and the content-process
# compositor/WebRender bring-up dlopen() the OpenGL client libraries by SONAME:
#
#     dlopen("libGL.so.1")      glxtest GLX path
#     dlopen("libEGL.so.1")     EGL path (also NEEDs libgbm.so.1)
#
# If those libraries are absent from the running image, the loader returns
# ENOENT, glxtest reports "libGL.so.1 missing" / "libEGL missing", GL is marked
# unavailable, and the content compositor child cannot initialise the software
# OpenGL context → CompositorBridgeChild AbnormalShutdown → the page never
# renders.  (Ref: ld.so(8) library search; dlopen(3); Mesa 3D docs for the
# Gallium llvmpipe software rasteriser.)
#
# scripts/install-firefox-musl.sh stages the full Mesa software-GL stack into
# build/disk/usr/lib (+ the Gallium DRI driver at
# build/disk/usr/lib/xorg/modules/dri/), and create-data-disk.sh snaps build/disk
# into the ext2 data.img with mke2fs -d.  A data image built BEFORE that staging
# existed (or that was assembled by a path which dropped the DRI driver dirs)
# ships GL-less.  Because the staleness is by CONTENT, not mtime, a freshly
# *written* image can still be GL-incomplete — exactly the failure this tool
# repairs.  It mirrors scripts/patch-gui-caches.sh: a one-shot, non-interactive
# debugfs -w injection (unprivileged, no mount, no 2 GiB rebuild).
#
# Usage
# -----
#   patch-gui-gl.sh --image <data.img> [--in-place] [--disk-dir <dir>]
#   patch-gui-gl.sh --verify <data.img>     (report-only; exit 0 iff complete)
#
# All output is structured "[GUI-GL] ..." lines.  Operates on a COPY
# ("<image>.gl-patched") unless --in-place is given.
#
# Refs: ld.so(8), dlopen(3), the ELF/dynamic-linking (gABI) standard,
# Mesa 3D documentation (Gallium / llvmpipe software rasteriser),
# debugfs(8), mke2fs(8) -d.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILD_DIR="${ASTRYXOS_BUILD_DIR:-${ROOT_DIR}/build}"
DISK_DIR="${BUILD_DIR}/disk"
IMAGE=""
IN_PLACE=0
VERIFY_ONLY=0

usage() {
    cat <<EOF
Usage: patch-gui-gl.sh [options]

  --image <data.img>     Inject the staged Mesa software-GL closure into this
                         ext2 image.
  --in-place             With --image: modify the image in place (default: a
                         "<image>.gl-patched" copy is produced and patched).
  --verify <data.img>    Report-only: list which GL closure members are present
                         / missing in the image.  Exit 0 iff the closure is
                         complete; non-zero otherwise.  No modification.
  --disk-dir <dir>       Staging tree the libs are copied FROM
                         (default: ${DISK_DIR}).
  -h, --help             This help.

Exit status: 0 on success; non-zero if a required member could not be injected
or (with --verify) the image is GL-incomplete.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="${2:?--image needs a path}"; shift 2 ;;
        --in-place) IN_PLACE=1; shift ;;
        --verify) IMAGE="${2:?--verify needs a path}"; VERIFY_ONLY=1; shift 2 ;;
        --disk-dir) DISK_DIR="${2:?--disk-dir needs a path}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[GUI-GL] ERROR: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

DISK_USR_LIB="${DISK_DIR}/usr/lib"
DRI_REL="usr/lib/xorg/modules/dri"

# ── The software-GL injection closure ────────────────────────────────────────
# Each entry is a path RELATIVE to the staging /usr/lib (or the staging root for
# the DRI driver).  This is the transitive dlopen closure of libGL.so.1 +
# libEGL.so.1 that is NOT already part of the base FF/X11 image, computed from
# their DT_NEEDED entries (readelf -d) minus the libraries every FF image
# already ships (libexpat, libxcb*, libX11*, libdrm.so.2, libwayland-client,
# libstdc++, libgcc_s, libz already-present, etc.).  The members listed here are
# the ones the Mesa staging step (install-firefox-musl.sh) adds on top of the
# base image.  Both the SONAME and its versioned real name are written because
# the staging tree carries them as independent (hardlinked) regular files, which
# is how mke2fs -d would lay them out; the loader resolves the SONAME form.
#
#   libGL.so.1        OpenGL/GLX dispatch (glxtest dlopen target)
#   libEGL.so.1       EGL client (FF probes it; NEEDs libgbm + libwayland-server)
#   libgbm.so.1       Generic Buffer Management (DT_NEEDED of libEGL)
#   libglapi.so.0     GL API dispatch (DT_NEEDED of libGL + libEGL + driver)
#   libwayland-server.so.0  DT_NEEDED of libEGL + libgbm
#   libxshmfence.so.1 DT_NEEDED of libGL + libEGL
#   libXxf86vm.so.1   DT_NEEDED of libGL
#   libLLVM-17.so     llvmpipe JIT backend (DT_NEEDED of the Gallium driver)
#   libelf.so.1       DT_NEEDED of the Gallium driver
#   libz.so.1         DT_NEEDED of the Gallium driver (often base, injected if absent)
#
# The Gallium DRI driver itself (the llvmpipe pipe driver) lives under
# xorg/modules/dri/ — libGL's compiled-in default LIBGL_DRIVERS_PATH — as a
# single 34 MiB object hardlinked under three names; swrast_dri.so is the name
# the loader opens for software rendering.
GL_LIBS=(
    libGL.so.1            libGL.so.1.2.0
    libEGL.so.1           libEGL.so.1.0.0
    libgbm.so.1           libgbm.so.1.0.0
    libglapi.so.0         libglapi.so.0.0.0
    libwayland-server.so.0
    libxshmfence.so.1
    libXxf86vm.so.1
    libLLVM-17.so         libLLVM-17.0.6.so
    libelf.so.1           libelf-0.191.so
    libz.so.1
)
# DRI driver objects (under usr/lib/xorg/modules/dri/).  swrast_dri.so is the
# load target for software rendering; libgallium_dri.so is the canonical object.
DRI_DRIVERS=(
    swrast_dri.so
    libgallium_dri.so
)

# Members that MUST be present for the GL pipeline to come up (the verify gate).
# These are the SONAMEs the loader resolves + the software DRI driver.
GL_REQUIRED=(
    "/usr/lib/libGL.so.1"
    "/usr/lib/libEGL.so.1"
    "/usr/lib/libgbm.so.1"
    "/usr/lib/libglapi.so.0"
    "/usr/lib/libLLVM-17.so"
    "/usr/lib/libelf.so.1"
    "/usr/lib/libwayland-server.so.0"
    "/usr/lib/libxshmfence.so.1"
    "/usr/lib/libXxf86vm.so.1"
    "/usr/lib/xorg/modules/dri/swrast_dri.so"
)

# ── image present-check ──────────────────────────────────────────────────────
img_has() {  # img_has <image> <abs-path>  -> 0 if a regular file inode exists
    debugfs -R "stat $2" "$1" 2>/dev/null | grep -q 'Inode:'
}

# ── inject a staged regular file into the image at its absolute disk path ─────
# Mirrors patch-gui-caches.sh inject_into_image: ensure parent dirs, idempotent
# rm then write, then stat-verify it landed.
inject_file() {
    local img="$1" staged="$2" abs="$3"
    [ -f "${staged}" ] || { echo "[GUI-GL] inject skip ${abs}: not staged (${staged})"; return 0; }
    local dir; dir="$(dirname "${abs}")"
    local p="" seg _segs
    IFS='/' read -ra _segs <<< "${dir#/}"
    for seg in "${_segs[@]}"; do
        p="${p}/${seg}"
        debugfs -w -R "mkdir ${p}" "${img}" >/dev/null 2>&1 || true
    done
    debugfs -w -R "rm ${abs}" "${img}" >/dev/null 2>&1 || true
    if debugfs -w -R "write ${staged} ${abs}" "${img}" 2>&1 | grep -qiE 'error|not found|no such'; then
        echo "[GUI-GL] ERROR: debugfs write failed for ${abs}"
        return 1
    fi
    if img_has "${img}" "${abs}"; then
        echo "[GUI-GL] injected ${abs} ($(stat -c%s "${staged}") bytes)"
    else
        echo "[GUI-GL] ERROR: ${abs} not present after debugfs write"
        return 1
    fi
}

# ── verify mode ──────────────────────────────────────────────────────────────
do_verify() {  # do_verify <image>
    local img="$1" missing=0 present=0
    echo "[GUI-GL] verify image: ${img}"
    local m
    for m in "${GL_REQUIRED[@]}"; do
        if img_has "${img}" "${m}"; then
            echo "[GUI-GL]   PRESENT ${m}"
            present=$((present + 1))
        else
            echo "[GUI-GL]   MISSING ${m}"
            missing=$((missing + 1))
        fi
    done
    echo "[GUI-GL] verify: ${present}/${#GL_REQUIRED[@]} required GL members present"
    if [ "${missing}" -eq 0 ]; then
        echo "[GUI-GL][ok] image carries the complete software-GL closure"
        return 0
    fi
    echo "[GUI-GL][MISSING] image is GL-incomplete (${missing} member(s) absent) — run patch-gui-gl.sh --image ${img} --in-place"
    return 1
}

# ── main ─────────────────────────────────────────────────────────────────────
command -v debugfs >/dev/null 2>&1 || { echo "[GUI-GL] ERROR: debugfs not found (apt-get install e2fsprogs)"; exit 1; }
[ -n "${IMAGE}" ] || { echo "[GUI-GL] ERROR: --image or --verify is required" >&2; usage >&2; exit 2; }
[ -f "${IMAGE}" ] || { echo "[GUI-GL] ERROR: image not found: ${IMAGE}"; exit 1; }

if [ "${VERIFY_ONLY}" -eq 1 ]; then
    do_verify "${IMAGE}"
    exit $?
fi

echo "[GUI-GL] staging tree: ${DISK_DIR}"
echo "[GUI-GL] image:        ${IMAGE}"

TARGET="${IMAGE}"
if [ "${IN_PLACE}" -eq 0 ]; then
    TARGET="${IMAGE}.gl-patched"
    echo "[GUI-GL] copying ${IMAGE} -> ${TARGET} (use --in-place to patch the original)"
    cp -f --reflink=auto "${IMAGE}" "${TARGET}"
fi

rc=0
for lib in "${GL_LIBS[@]}"; do
    inject_file "${TARGET}" "${DISK_USR_LIB}/${lib}" "/usr/lib/${lib}" || rc=1
done
for drv in "${DRI_DRIVERS[@]}"; do
    inject_file "${TARGET}" "${DISK_DIR}/${DRI_REL}/${drv}" "/usr/lib/xorg/modules/dri/${drv}" || rc=1
done

echo "[GUI-GL] image patched: ${TARGET} (rc=${rc})"
if [ "${rc}" -eq 0 ]; then
    do_verify "${TARGET}" || rc=1
fi
exit "${rc}"
