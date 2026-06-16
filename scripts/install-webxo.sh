#!/usr/bin/env bash
#
# install-webxo.sh — Build the WebXO C++ HTTP server as a musl-linked
# userspace binary and stage it (plus a tiny docroot) into the AstryxOS
# data-disk staging tree.  This is the userspace half of the web-server
# demo; the kernel half is the `webxo-test` cargo feature (a userspace
# launcher mirroring sshd_demo.rs) and, for the combined "SSH + HTTP on
# one instance" demo, the persistent sshd-test runner.
#
# Why WebXO?
# ----------
# WebXO is a small (~600 KB total) static-page HTTP/1.1 server.  It speaks
# a narrow, well-understood syscall surface — socket(2), setsockopt(2)
# (SO_REUSEADDR), bind(2), listen(2), accept(2), recv(2)/send(2), plus a
# C++ std::thread worker pool (clone(2) + futex(2)) and ifstream-based
# file reads (openat/read/close).  Every one of those is already exercised
# end-to-end on this image by the musl Firefox port and the dropbear SSH
# service, so the server's runtime dependency closure is already present:
# the musl loader + libc, libstdc++, libgcc_s and libz are all staged by
# the earlier install-firefox-musl.sh / install-glibc pipeline.  Building
# WebXO therefore needs ZERO new shared-library staging.
#
# Linkage choice
# --------------
# WebXO upstream builds a separate shared library (libWebX.so) plus a thin
# executable that links against it.  For the AstryxOS image we instead
# compile every translation unit directly into ONE self-contained dynamic
# executable.  This avoids needing an extra LD_LIBRARY_PATH entry or an
# install of a versioned .so into the guest's loader search path — the
# binary depends only on the already-staged system libraries (libstdc++,
# libgcc_s, libz, libc.musl).  Smaller blast radius, one file to launch.
#
# What this script does
# ---------------------
#   1. Reuses the shared Alpine rootfs at ~/.cache/astryxos-firefox-musl/
#      rootfs/ (bootstrapped by install-firefox-musl.sh) and apk-adds
#      `build-base` (gcc, g++, musl-dev, make) + `zlib-dev` into it if the
#      compiler is not already present.  No second Alpine bootstrap.
#   2. Copies the WebXO source tree into a build directory inside the
#      rootfs and compiles it with the rootfs's musl g++ via a chroot-less
#      invocation (the musl loader runs the compiler driver, which then
#      drives cc1plus/as/ld out of the rootfs).  Output is a single
#      dynamic musl ELF: WebXOServer.
#   3. Stages the binary at build/disk/usr/bin/webxo and resolves its
#      shared-library closure, copying any NEEDED lib that is not already
#      present under build/disk/{lib,usr/lib}.
#   4. Stages a minimal docroot at build/disk/var/www/ with an index.html
#      that identifies the running AstryxOS instance, plus the WebXO error
#      pages the server serves for 404/500.
#
# Idempotent — exits 0 if the binary is already staged and source is
# unchanged.  Pass --force to rebuild.
#
# References (public):
#   - HTTP/1.1 semantics:   RFC 9110, RFC 7230
#   - POSIX sockets:        socket(2), bind(2), listen(2), accept(2),
#                           send(2), recv(2), setsockopt(2) SO_REUSEADDR
#   - musl loader usage:    ld-musl(8) (running a musl ELF via the loader
#                           with --library-path)
#   - QEMU SLIRP hostfwd:   https://www.qemu.org/docs/master/system/devices/net.html
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_USR_BIN="${DISK_DIR}/usr/bin"
DISK_USR_LIB="${DISK_DIR}/usr/lib"
DISK_LIB="${DISK_DIR}/lib"
DISK_WWW="${DISK_DIR}/var/www"

# Shared Alpine rootfs — same one used by install-firefox-musl.sh,
# install-sshd.sh, install-busybox-cli.sh.
CACHE_DIR="${HOME}/.cache/astryxos-firefox-musl"
APK_STATIC="${CACHE_DIR}/apk-tools/sbin/apk.static"
ROOTFS="${CACHE_DIR}/rootfs"
ALPINE_KEYS="${ROOTFS}/etc/apk/keys"

ALPINE_VERSION="v3.20"
ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main"
ALPINE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/community"

# WebXO source location.  The canonical source lives outside the repo (it
# is not vendored into the AstryxOS tree to keep the repo lean); this
# variable can be overridden to point at a checkout.  Default probes a few
# conventional locations.
WEBXO_SRC="${WEBXO_SRC:-}"

MUSL_LOADER="${ROOTFS}/lib/ld-musl-x86_64.so.1"
MUSL_LIBPATH="${ROOTFS}/usr/lib:${ROOTFS}/lib"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        --src=*) WEBXO_SRC="${arg#--src=}" ;;
        -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    esac
done

# ── Sanity: the shared Alpine rootfs must exist ──────────────────────────────
if [ ! -x "${APK_STATIC}" ] || [ ! -d "${ROOTFS}" ] || [ ! -d "${ALPINE_KEYS}" ]; then
    echo "[WEBXO] ERROR: shared Alpine rootfs not present at ${CACHE_DIR}"
    echo "[WEBXO]        Run scripts/install-firefox-musl.sh first to bootstrap."
    exit 1
fi

# ── Locate the WebXO source tree ─────────────────────────────────────────────
# WebXO is an external project (https://github.com/KillerDucks/WebXO); its
# source is NOT vendored into this repo.  Point this script at a checkout via
# the WEBXO_SRC environment variable or --src=/path/to/WebXO.  A few neutral
# conventional locations are probed as a convenience.
if [ -z "${WEBXO_SRC}" ]; then
    for cand in \
        "${HOME}/WebXO" \
        "${HOME}/src/WebXO" \
        "${ROOT_DIR}/../WebXO"; do
        if [ -f "${cand}/CMakeLists.txt" ] && [ -d "${cand}/src/WebXLib" ]; then
            WEBXO_SRC="${cand}"
            break
        fi
    done
fi
if [ -z "${WEBXO_SRC}" ] || [ ! -d "${WEBXO_SRC}/src/WebXLib" ]; then
    echo "[WEBXO] ERROR: WebXO source not found."
    echo "[WEBXO]        Set WEBXO_SRC=/path/to/WebXO or pass --src=/path/to/WebXO"
    echo "[WEBXO]        (a checkout of https://github.com/KillerDucks/WebXO containing src/WebXLib/)."
    exit 1
fi
echo "[WEBXO] Using WebXO source at ${WEBXO_SRC}"

DISK_BIN_OUT="${DISK_USR_BIN}/webxo"

# ── Idempotency: skip if already staged and not forced ──────────────────────
if [ "${FORCE}" != true ] && [ -x "${DISK_BIN_OUT}" ]; then
    # Rebuild only if any source file is newer than the staged binary.
    if [ -z "$(find "${WEBXO_SRC}/src" -newer "${DISK_BIN_OUT}" -print -quit 2>/dev/null)" ]; then
        echo "[WEBXO] ${DISK_BIN_OUT} already staged and up to date; nothing to do (--force to rebuild)."
        exit 0
    fi
fi

# ── Step 1: ensure a musl g++ toolchain is in the rootfs ─────────────────────
ROOTFS_GXX="${ROOTFS}/usr/bin/g++"
if [ ! -x "${ROOTFS_GXX}" ] || [ "${FORCE}" = true ]; then
    echo "[WEBXO] Installing build-base + zlib-dev via apk into ${ROOTFS} ..."
    set +o pipefail
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --repository "${ALPINE_COMMUNITY}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --no-scripts \
        --update-cache \
        add build-base zlib-dev 2>&1 | sed 's/^/[WEBXO]   /' || true
    set -o pipefail
fi
if [ ! -x "${ROOTFS_GXX}" ]; then
    echo "[WEBXO] ERROR: g++ still missing after apk add build-base"
    exit 1
fi

# ── Step 2: compile WebXO into one self-contained musl executable ────────────
# We build inside the rootfs so the musl g++ driver, cc1plus, as and ld are
# all resolved from the rootfs (and so the produced ELF links against the
# rootfs's musl libc / libstdc++).  The build dir lives under the rootfs's
# /tmp so paths the compiler emits are rootfs-relative.
BUILD_REL="/tmp/webxo-build"
BUILD_ABS="${ROOTFS}${BUILD_REL}"
rm -rf "${BUILD_ABS}"
mkdir -p "${BUILD_ABS}/src"
cp -a "${WEBXO_SRC}/src/." "${BUILD_ABS}/src/"

# Compile flags (public-spec rationale):
#   -std=c++17                 — WebXO uses <filesystem>; c++17 folds it into
#                                libstdc++ proper (no separate -lstdc++fs on
#                                modern toolchains).
#   -O2                        — release optimisation.
#   -pthread                   — std::thread worker pool (clone(2)+futex(2)).
#   -static-libstdc++ / -static-libgcc were considered but REJECTED: the
#                                guest already has the shared libstdc++ /
#                                libgcc_s staged, and a dynamic link keeps
#                                the binary small + matches the proven FF
#                                runtime closure.
# We compile inside a chroot into the rootfs so the gcc driver resolves
# cc1plus / as / ld / its include + libexec dirs entirely from rootfs-internal
# paths (running the driver from outside the rootfs via the loader breaks its
# libexec-relative path computation).  chroot needs privilege; the rootfs was
# bootstrapped the same way (apk under sudo), so this matches the existing
# install-* convention.
#
# Glob all library .cpp + the main TU (paths are rootfs-relative under
# ${BUILD_REL}).
SRCS=$(cd "${BUILD_ABS}" && ls src/WebXLib/*.cpp src/pMain.cpp 2>/dev/null | tr '\n' ' ')
echo "[WEBXO] Compiling (chroot): ${SRCS}"

# A tiny driver script placed inside the rootfs and executed under chroot.
COMPILE_SH="${BUILD_ABS}/compile.sh"
cat > "${COMPILE_SH}" <<EOF
#!/bin/sh
set -e
cd ${BUILD_REL}
# WebXO's Directory.* uses std::experimental::filesystem (the pre-C++17
# Filesystem TS), whose symbols live in the static archive libstdc++fs.a,
# not in libstdc++.so.  Link it statically (-lstdc++fs) so those symbols
# fold into the binary — this adds no new runtime shared-library dependency.
g++ -std=c++17 -O2 -pthread -I src -I src/WebXLib ${SRCS} -lstdc++fs -lz -o webxo
EOF
chmod +x "${COMPILE_SH}"

sudo chroot "${ROOTFS}" /bin/sh "${BUILD_REL}/compile.sh" 2>&1 | sed 's/^/[WEBXO]   /'

# chroot writes webxo as root; make it readable/copyable by the build user.
sudo chown "$(id -u):$(id -g)" "${BUILD_ABS}/webxo" 2>/dev/null || true

if [ ! -x "${BUILD_ABS}/webxo" ]; then
    echo "[WEBXO] ERROR: compile did not produce ${BUILD_ABS}/webxo"
    exit 1
fi
echo "[WEBXO] Compiled webxo ($(stat -c%s "${BUILD_ABS}/webxo") bytes)"

# ── Step 3: stage the binary + resolve its shared-library closure ────────────
mkdir -p "${DISK_USR_BIN}" "${DISK_USR_LIB}" "${DISK_LIB}"
cp -fL "${BUILD_ABS}/webxo" "${DISK_BIN_OUT}"
chmod +x "${DISK_BIN_OUT}"
echo "[WEBXO] Staged /usr/bin/webxo ($(stat -c%s "${DISK_BIN_OUT}") bytes)"

echo "[WEBXO] Resolving webxo shared-library closure ..."
copied_count=0
missing_count=0
while IFS= read -r need; do
    case "${need}" in
        "libc.musl-x86_64.so.1"|"ld-musl-x86_64.so.1")
            if [ ! -f "${DISK_LIB}/${need}" ]; then
                echo "[WEBXO]   MISSING /lib/${need} (musl libc/loader — install-firefox-musl.sh should stage it)"
                missing_count=$((missing_count + 1))
            fi ;;
        *)
            for src_dir in "${ROOTFS}/usr/lib" "${ROOTFS}/lib"; do
                if [ -f "${src_dir}/${need}" ]; then
                    if [ ! -f "${DISK_LIB}/${need}" ]; then
                        cp -fL "${src_dir}/${need}" "${DISK_LIB}/${need}"
                        echo "[WEBXO]   Staged /lib/${need} ($(stat -c%s "${DISK_LIB}/${need}") bytes)"
                        copied_count=$((copied_count + 1))
                    fi
                    if [ ! -f "${DISK_USR_LIB}/${need}" ]; then
                        cp -fL "${src_dir}/${need}" "${DISK_USR_LIB}/${need}"
                    fi
                    continue 2
                fi
            done
            echo "[WEBXO]   WARNING: ${need} not found in rootfs — staging may be incomplete"
            ;;
    esac
done < <(readelf -d "${DISK_BIN_OUT}" 2>/dev/null | awk -F'[][]' '/NEEDED/ {print $2}')
echo "[WEBXO] Closed dependency: copied ${copied_count} new libs; ${missing_count} missing pre-reqs."

# ── Step 4: stage a minimal docroot ──────────────────────────────────────────
# Served from /var/www/ASTRYX (the basepath the launcher passes).  index.html
# identifies the running instance so a host curl gets a recognisable page.
DOCROOT="${DISK_WWW}/ASTRYX"
mkdir -p "${DOCROOT}"
cat > "${DOCROOT}/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AstryxOS — WebXO</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto;
           padding: 0 1rem; line-height: 1.5; color: #16181d; }
    h1 { font-size: 2rem; }
    code { background: #f0f1f4; padding: .1rem .35rem; border-radius: 4px; }
    .ok { color: #1a7f37; font-weight: 600; }
  </style>
</head>
<body>
  <h1>It works.</h1>
  <p class="ok">This page is served by <strong>WebXO</strong> running as a
     userspace process on a live <strong>AstryxOS</strong> instance.</p>
  <p>The same instance is reachable over SSH (dropbear) on TCP&nbsp;22.
     This HTTP server is bound to <code>0.0.0.0:8080</code> inside the guest
     and forwarded to your LAN by the QEMU host.</p>
  <p>Server: <code>WebXO/1.6.0</code> &middot; HTTP/1.1 (RFC&nbsp;9110)</p>
</body>
</html>
HTML
echo "[WEBXO] Staged docroot ${DOCROOT}/index.html"

# Stage the WebXO error pages alongside the docroot so 404/500 render the
# server's own templates rather than a bare status line.
if [ -d "${WEBXO_SRC}/ErrorPages" ]; then
    mkdir -p "${DISK_WWW}/ErrorPages"
    cp -fL "${WEBXO_SRC}/ErrorPages/"*.html "${DISK_WWW}/ErrorPages/" 2>/dev/null || true
    echo "[WEBXO] Staged error pages into ${DISK_WWW}/ErrorPages/"
fi

echo "[WEBXO] === DONE === webxo staged at /usr/bin/webxo, docroot at /var/www/ASTRYX"
echo "[WEBXO]     Launch on the guest with: webxo --basepath=/disk/var/www/ASTRYX --port=8080"
