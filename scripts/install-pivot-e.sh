#!/usr/bin/env bash
#
# install-pivot-e.sh — Stage PIVOT-E Tier B core utilities (curl, jq, GNU
# tar) plus their DT_NEEDED transitive closures into the AstryxOS
# data-disk staging tree.  Companion to the existing Tier A surface,
# which is the 305 applets shipped inside the statically-linked
# /bin/busybox already staged by install-busybox-cli.sh.
#
# What is "Tier B"?
# -----------------
# Standalone Alpine binaries that are not part of busybox and need their
# full library closure walked + staged:
#
#   /usr/bin/curl    — curl 8.x (libcurl + zlib + nghttp2 + libpsl + zstd
#                      + libssl/libcrypto from install-tls-stack.sh).
#                      Exercises the AF_INET socket(2)/connect(2)/sendto(2)
#                      path PLUS dynamic-linker DT_NEEDED resolution of a
#                      deeper closure than wget needs.
#
#   /usr/bin/jq      — jq 1.7 (oniguruma regex + libc.musl).  Pure
#                      compute, no syscalls beyond read/write/exit — used
#                      to validate "real Linux CLI binary, non-trivial
#                      DT_NEEDED set, runs end-to-end".
#
#   /bin/tar         — GNU tar 1.35 (libacl + libc.musl).  Provides the
#                      extended-attribute / sparse-file / long-name shapes
#                      busybox tar cannot do.  Symlinked at /usr/bin/tar
#                      conventionally; we stage it under both names so
#                      PATH-less hard-coded paths (/bin/tar) still resolve.
#
# Tier A (the 305 busybox-static applets including grep, sed, awk, find,
# head, tail, wc, cat, sort, uniq, md5sum, sha256sum, du, df, vi, tar)
# is already staged by install-busybox-cli.sh; this script does NOT
# re-stage busybox.  If /bin/busybox is missing we abort with a hint.
#
# What this stages
# ----------------
#
#   1. /usr/bin/curl                (256 KiB, musl-PIE)
#   2. /usr/bin/jq                  (313 KiB, musl-PIE)
#   3. /bin/tar + /usr/bin/tar      (366 KiB each, musl-PIE)
#   4. /usr/lib/libcurl.so.4        (curl HTTP transport library)
#   5. /usr/lib/libonig.so.5        (jq regex engine)
#   6. /usr/lib/libacl.so.1         (tar POSIX.1e ACL support)
#   7. Transitive closure of all of the above (nghttp2, libpsl, zlib,
#      zstd, libssl/libcrypto) — walked with the same BFS resolver used
#      by install-oracle.sh, but scoped to the musl runtime tree
#      (/usr/lib and /lib, NOT /lib/x86_64-linux-gnu which is the glibc
#      multiarch path).
#
# All staging mirrors the convention used by install-tls-stack.sh + the
# musl Firefox install — musl ld searches /lib then /usr/lib, so every
# .so lands under /usr/lib unless its host source path was /lib/...
#
# References (public)
#   - curl(1): https://curl.se/docs/manpage.html
#   - jq(1):   https://stedolan.github.io/jq/manual/
#   - tar(1):  https://www.gnu.org/software/tar/manual/tar.html
#   - musl ld search order: man:ld-musl-x86_64.so.1(8)
#   - System V ABI (ELF gABI) §5.4 — DT_RPATH/DT_RUNPATH search order
#   - Alpine v3.20 main/community packages:
#     https://pkgs.alpinelinux.org/packages?branch=v3.20
#
# Idempotent.  Pass --force to refresh the rootfs (apk add --upgrade) +
# restage.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_BIN="${DISK_DIR}/bin"
DISK_USR_BIN="${DISK_DIR}/usr/bin"
DISK_USR_LIB="${DISK_DIR}/usr/lib"
DISK_LIB="${DISK_DIR}/lib"

# Shared TLS staging rootfs — install-tls-stack.sh already bootstraps
# this Alpine tree.  We add curl/jq/tar packages on top.  Independent
# from the firefox-musl rootfs so parallel dispatches do not race on
# apk add.
CACHE_DIR="${HOME}/.cache/astryxos-tls"
ROOTFS="${CACHE_DIR}/rootfs"
ALPINE_KEYS="${ROOTFS}/etc/apk/keys"

# apk-static binary is shared with firefox-musl (read-only).
APK_STATIC="${HOME}/.cache/astryxos-firefox-musl/apk-tools/sbin/apk.static"

ALPINE_VERSION="v3.20"
ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main"
ALPINE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/community"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help) sed -n '2,70p' "$0"; exit 0 ;;
        *) echo "[PIVOT-E] WARN: ignoring unknown arg '${arg}'" ;;
    esac
done

# ── Pre-flight: Tier A (busybox) must already be staged ──────────────────────
if [ ! -x "${DISK_BIN}/busybox" ]; then
    echo "[PIVOT-E] ERROR: /bin/busybox is not staged at ${DISK_BIN}/busybox"
    echo "[PIVOT-E]        Run scripts/install-busybox-cli.sh first (Tier A surface)."
    exit 1
fi

# ── Pre-flight: apk-static + shared TLS rootfs ───────────────────────────────
if [ ! -x "${APK_STATIC}" ]; then
    echo "[PIVOT-E] ERROR: apk.static not present at ${APK_STATIC}"
    echo "[PIVOT-E]        Run scripts/install-firefox-musl.sh first to bootstrap."
    exit 1
fi
if [ ! -d "${ROOTFS}" ] || [ ! -d "${ALPINE_KEYS}" ]; then
    echo "[PIVOT-E] ERROR: shared TLS rootfs not present at ${ROOTFS}"
    echo "[PIVOT-E]        Run scripts/install-tls-stack.sh first to bootstrap."
    exit 1
fi

# ── Step 1: apk add curl, jq, tar into the shared TLS rootfs ─────────────────
# These pull in oniguruma, libcurl, libpsl, nghttp2, zlib, zstd, libacl.
NEEDED_BINS="${ROOTFS}/usr/bin/curl ${ROOTFS}/usr/bin/jq ${ROOTFS}/bin/tar"
NEED_INSTALL=false
for b in ${NEEDED_BINS}; do
    [ -f "${b}" ] || NEED_INSTALL=true
done
if [ "${NEED_INSTALL}" = true ] || [ "${FORCE}" = true ]; then
    echo "[PIVOT-E] Installing curl + jq + tar into ${ROOTFS} via apk ..."
    # The "errors updating directory permissions" warning is expected when
    # apk runs outside a chroot; the package contents are still extracted.
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --repository "${ALPINE_COMMUNITY}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --update-cache \
        add curl jq tar 2>&1 | sed 's/^/[PIVOT-E]   /' || true
fi
for b in ${NEEDED_BINS}; do
    if [ ! -f "${b}" ]; then
        echo "[PIVOT-E] ERROR: ${b} still missing after apk add"
        exit 1
    fi
done

# ── Step 2: stage the Tier B binaries ────────────────────────────────────────
mkdir -p "${DISK_BIN}" "${DISK_USR_BIN}" "${DISK_USR_LIB}" "${DISK_LIB}"

# curl + jq under /usr/bin (canonical Alpine paths).  GNU tar lives at
# /bin/tar with a /usr/bin/tar duplicate so both canonical paths resolve.
cp -fL "${ROOTFS}/usr/bin/curl" "${DISK_USR_BIN}/curl"
chmod +x "${DISK_USR_BIN}/curl"
echo "[PIVOT-E] Staged /usr/bin/curl ($(stat -c%s "${DISK_USR_BIN}/curl") bytes)"

cp -fL "${ROOTFS}/usr/bin/jq" "${DISK_USR_BIN}/jq"
chmod +x "${DISK_USR_BIN}/jq"
echo "[PIVOT-E] Staged /usr/bin/jq ($(stat -c%s "${DISK_USR_BIN}/jq") bytes)"

cp -fL "${ROOTFS}/bin/tar" "${DISK_BIN}/tar"
chmod +x "${DISK_BIN}/tar"
cp -fL "${ROOTFS}/bin/tar" "${DISK_USR_BIN}/tar"
chmod +x "${DISK_USR_BIN}/tar"
echo "[PIVOT-E] Staged /bin/tar + /usr/bin/tar ($(stat -c%s "${DISK_BIN}/tar") bytes each)"

# ── Step 3: walk DT_NEEDED transitive closure for each Tier B binary ─────────
# Pattern mirrors install-oracle.sh's BFS walker (PR #441) but targets the
# musl runtime tree.  Library names are resolved by:
#   1. ${ROOTFS}/usr/lib/${soname}
#   2. ${ROOTFS}/lib/${soname}
# This stays inside the Alpine rootfs so we never accidentally cross-pollute
# with a host glibc .so.
#
# Skip-list: musl libc itself (libc.musl-x86_64.so.1) is already staged by
# install-firefox-musl.sh as /lib/ld-musl-x86_64.so.1 (the same file
# under two names — musl ld is musl libc).  We do not re-stage it.
declare -A STAGED_SOS
MUSL_LIBC="libc.musl-x86_64.so.1"
SKIP_BASE_SET="${MUSL_LIBC} ld-musl-x86_64.so.1"

resolve_in_rootfs() {
    local soname="$1"
    for d in usr/lib lib; do
        if [ -e "${ROOTFS}/${d}/${soname}" ]; then
            echo "${ROOTFS}/${d}/${soname}"
            return 0
        fi
    done
    return 1
}

stage_one_so() {
    local soname="$1"
    local src_path="$2"
    local real_path real_name dest_dir
    real_path="$(readlink -f "${src_path}")"
    real_name="$(basename "${real_path}")"
    # Mirror the source directory layout (usr/lib stays in usr/lib;
    # lib stays in lib) so musl ld's search order works without an
    # /etc/ld-musl-x86_64.path file.
    case "${src_path}" in
        "${ROOTFS}/usr/lib/"*) dest_dir="${DISK_USR_LIB}" ;;
        "${ROOTFS}/lib/"*)     dest_dir="${DISK_LIB}" ;;
        *)                     dest_dir="${DISK_USR_LIB}" ;;
    esac
    cp -fL "${real_path}" "${dest_dir}/${soname}"
    if [ "${soname}" != "${real_name}" ]; then
        cp -fL "${real_path}" "${dest_dir}/${real_name}"
    fi
    STAGED_SOS["${soname}"]=1
    STAGED_SOS["${real_name}"]=1
    local size; size="$(stat -c%s "${dest_dir}/${soname}")"
    echo "[PIVOT-E]   staged ${dest_dir#${DISK_DIR}}/${soname}$([ "${soname}" != "${real_name}" ] && echo " (+${real_name})") (${size} bytes)"
}

walk_dt_needed_closure() {
    local label="$1"; shift
    local -a queue=("$@")
    local -A visited
    for r in "${queue[@]}"; do visited["$(readlink -f "${r}")"]=1; done
    local total=0 skipped=0 missing=0
    while [ ${#queue[@]} -gt 0 ]; do
        local cur="${queue[0]}"
        queue=("${queue[@]:1}")
        while IFS= read -r dep; do
            [ -z "${dep}" ] && continue
            if printf '%s' "${SKIP_BASE_SET}" | tr ' ' '\n' | grep -qFx "${dep}"; then
                skipped=$((skipped + 1)); continue
            fi
            [ -n "${STAGED_SOS[${dep}]:-}" ] && continue
            local resolved
            if ! resolved="$(resolve_in_rootfs "${dep}")"; then
                echo "[PIVOT-E]   MISSING dep: ${dep} (no copy in rootfs)"
                missing=$((missing + 1))
                STAGED_SOS["${dep}"]=1
                continue
            fi
            local real_resolved
            real_resolved="$(readlink -f "${resolved}")"
            if [ -n "${visited[${real_resolved}]:-}" ]; then continue; fi
            visited["${real_resolved}"]=1
            stage_one_so "${dep}" "${resolved}"
            queue+=("${real_resolved}")
            total=$((total + 1))
        done < <(readelf -d "${cur}" 2>/dev/null \
                 | awk -F'[][]' '/NEEDED/ {print $2}')
    done
    echo "[PIVOT-E] [${label}] closure: ${total} staged, ${skipped} skipped (base musl), ${missing} missing"
}

echo "[PIVOT-E] Walking DT_NEEDED transitive closure for Tier B binaries ..."
walk_dt_needed_closure "curl" "${ROOTFS}/usr/bin/curl"
walk_dt_needed_closure "jq"   "${ROOTFS}/usr/bin/jq"
walk_dt_needed_closure "tar"  "${ROOTFS}/bin/tar"

# ── Step 4: seed test fixtures used by the pivot-e-test runner ───────────────
# A small JSON file at /etc/pivot-e/sample.json lets `jq` parse a known
# input without depending on the runtime command-line shell quoting.
# A tiny text file at /etc/pivot-e/sample.txt is the grep / sort / wc
# fixture.  Both are deterministic so the demo runner can assert exact
# bytes when needed.
DISK_ETC_PIVOT_E="${DISK_DIR}/etc/pivot-e"
mkdir -p "${DISK_ETC_PIVOT_E}"
cat > "${DISK_ETC_PIVOT_E}/sample.json" <<'EOF'
{"name":"AstryxOS","release":"demo","year":2026,"features":["mm","sched","ipc","ob","ke","vfs","net"]}
EOF
cat > "${DISK_ETC_PIVOT_E}/sample.txt" <<'EOF'
alpha
bravo
charlie
delta
echo
foxtrot
golf
hotel
india
juliet
EOF
echo "[PIVOT-E] Wrote fixture /etc/pivot-e/sample.json ($(stat -c%s "${DISK_ETC_PIVOT_E}/sample.json") bytes)"
echo "[PIVOT-E] Wrote fixture /etc/pivot-e/sample.txt ($(stat -c%s "${DISK_ETC_PIVOT_E}/sample.txt") bytes)"

# ── Summary ──────────────────────────────────────────────────────────────────
echo "[PIVOT-E] Done.  Summary:"
echo "[PIVOT-E]   - /usr/bin/curl    ($(stat -c%s "${DISK_USR_BIN}/curl") bytes)"
echo "[PIVOT-E]   - /usr/bin/jq      ($(stat -c%s "${DISK_USR_BIN}/jq") bytes)"
echo "[PIVOT-E]   - /bin/tar         ($(stat -c%s "${DISK_BIN}/tar") bytes)"
echo "[PIVOT-E]   - /usr/bin/tar     ($(stat -c%s "${DISK_USR_BIN}/tar") bytes)"
echo "[PIVOT-E]   - /usr/lib/* + /lib/* — DT_NEEDED closures staged above"
echo "[PIVOT-E]   - /etc/pivot-e/sample.{json,txt} — demo fixtures"
echo "[PIVOT-E]"
echo "[PIVOT-E] Note: musl libc + ld-musl come from install-firefox-musl.sh."
echo "[PIVOT-E] Re-run scripts/create-data-disk.sh --pivot-e --force to refresh data.img."
