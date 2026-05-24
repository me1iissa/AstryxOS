#!/usr/bin/env bash
#
# install-pivot-e-git.sh — Stage PIVOT-E Tier D git on top of the Tier B
# DT_NEEDED substrate (libcurl, libssl, libcrypto, libz already staged by
# install-pivot-e.sh + install-tls-stack.sh).  Companion to:
#
#   install-busybox-cli.sh    — Tier A (305 busybox applets)
#   install-pivot-e.sh        — Tier B (curl, jq, GNU tar + closure)
#   install-pivot-e-tui.sh    — Tier C (nano, vim, htop, tmux + ncurses)
#   install-pivot-e-git.sh    — Tier D (git, this file)
#
# What is "Tier D"?
# -----------------
# git is the final canonical Linux CLI utility on the original PIVOT-E
# queue.  Its dependency surface is small (libpcre2 + libz + libc.musl,
# plus libcurl + libexpat for HTTPS clone), but its on-disk footprint
# is wide — the Alpine `git` package ships ~158 entries under
# /usr/libexec/git-core/, of which 141 are symlinks back to /usr/bin/git
# and 17 are real helper binaries (git-http-fetch, git-http-push,
# git-remote-http, git-merge-{octopus,one-file,resolve}, etc.).
#
# AstryxOS uses FAT32 for the data disk and FAT32 has no symlinks.  Two
# implications:
#
#   1. The git binary is staged ONCE at /usr/bin/git.  At runtime the
#      kernel demo runner sets GIT_EXEC_PATH=/disk/usr/bin so the git
#      sub-process spawned by `git commit` (e.g. "git maintenance run")
#      resolves to /disk/usr/bin/git rather than the canonical
#      /usr/libexec/git-core/git symlink.
#
#   2. The non-symlink helpers (the 17 real ELF binaries needed for the
#      HTTPS-clone protocol path: git-http-fetch, git-remote-http, etc.)
#      ARE staged as real files under /usr/libexec/git-core/ — they are
#      not symlinks and they fit the FAT32 file model.  Their footprint
#      is small (~80 KiB each) and copying the union avoids per-feature
#      gates.
#
# What this stages
# ----------------
#
#   1. /usr/bin/git                     (~2.9 MiB, musl-PIE)
#   2. /usr/libexec/git-core/git-*      (17 real helpers; symlinks omitted)
#   3. /usr/lib/libpcre2-8.so.0         (regex engine for git pattern matches)
#   4. /usr/lib/libexpat.so.1           (HTTPS dumb-client XML for git-http)
#   5. /usr/share/git-core/templates/   (init template tree — copied verbatim)
#   6. /etc/gitconfig                   (system config — minimal)
#   7. /root/.gitconfig                 (per-user fallback for git commit)
#
# libcurl/libssl/libcrypto/libz are already staged by install-pivot-e.sh
# (Tier B) and install-tls-stack.sh; we do not re-stage them.
#
# The DT_NEEDED closure walker is the same BFS pattern used by Tier B/C,
# scoped to the musl runtime tree at /usr/lib and /lib.
#
# References (public)
#   - git(1):           https://git-scm.com/docs/git
#   - gitrepository-layout(5):
#                       https://git-scm.com/docs/gitrepository-layout
#   - git-config(1) GIT_EXEC_PATH / GIT_CONFIG_NOSYSTEM:
#                       https://git-scm.com/docs/git-config
#   - libcurl(3):       https://curl.se/libcurl/c/
#   - libpcre2(3):      https://www.pcre.org/current/doc/html/pcre2.html
#   - libexpat(3):      https://libexpat.github.io/
#   - musl ld search:   man:ld-musl-x86_64.so.1(8)
#   - System V ABI (ELF gABI) §5.4 — DT_NEEDED resolution order
#   - Alpine v3.20 packages: https://pkgs.alpinelinux.org/packages?branch=v3.20
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
DISK_USR_LIBEXEC_GIT="${DISK_DIR}/usr/libexec/git-core"
DISK_USR_SHARE_GIT_TEMPLATES="${DISK_DIR}/usr/share/git-core/templates"
DISK_LIB="${DISK_DIR}/lib"
DISK_ETC="${DISK_DIR}/etc"
DISK_ROOT="${DISK_DIR}/root"

# Shared TLS staging rootfs — install-tls-stack.sh + install-pivot-e.sh
# already bootstrap this Alpine tree.  We add `git` on top.
CACHE_DIR="${HOME}/.cache/astryxos-tls"
ROOTFS="${CACHE_DIR}/rootfs"
ALPINE_KEYS="${ROOTFS}/etc/apk/keys"
APK_STATIC="${HOME}/.cache/astryxos-firefox-musl/apk-tools/sbin/apk.static"

ALPINE_VERSION="v3.20"
ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main"
ALPINE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/community"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help) sed -n '2,70p' "$0"; exit 0 ;;
        *) echo "[PIVOT-E-GIT] WARN: ignoring unknown arg '${arg}'" ;;
    esac
done

# ── Pre-flight: Tier B substrate (curl + libssl + libcurl) must be staged ────
if [ ! -x "${DISK_USR_BIN}/curl" ]; then
    echo "[PIVOT-E-GIT] ERROR: /usr/bin/curl is not staged at ${DISK_USR_BIN}/curl"
    echo "[PIVOT-E-GIT]        Run scripts/install-pivot-e.sh first (Tier B substrate)."
    exit 1
fi
if [ ! -x "${APK_STATIC}" ]; then
    echo "[PIVOT-E-GIT] ERROR: apk.static not present at ${APK_STATIC}"
    echo "[PIVOT-E-GIT]        Run scripts/install-firefox-musl.sh first to bootstrap."
    exit 1
fi
if [ ! -d "${ROOTFS}" ] || [ ! -d "${ALPINE_KEYS}" ]; then
    echo "[PIVOT-E-GIT] ERROR: shared TLS rootfs not present at ${ROOTFS}"
    echo "[PIVOT-E-GIT]        Run scripts/install-tls-stack.sh first to bootstrap."
    exit 1
fi

# ── Step 1: apk add git + git-init-template into the shared TLS rootfs ───────
# `git` pulls in libpcre2 + libexpat + libcurl + libz (latter two already
# in the rootfs from Tier B).  `git-init-template` ships /usr/share/git-core/
# templates which `git init` copies into freshly created .git/ dirs.
if [ ! -f "${ROOTFS}/usr/bin/git" ] || [ "${FORCE}" = true ]; then
    echo "[PIVOT-E-GIT] Installing git + git-init-template into ${ROOTFS} via apk ..."
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --repository "${ALPINE_COMMUNITY}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --update-cache \
        add git git-init-template 2>&1 \
        | sed 's/^/[PIVOT-E-GIT]   /' || true
fi
if [ ! -f "${ROOTFS}/usr/bin/git" ]; then
    echo "[PIVOT-E-GIT] ERROR: ${ROOTFS}/usr/bin/git still missing after apk add"
    exit 1
fi

# ── Step 2: stage the git binary at /usr/bin/git ─────────────────────────────
mkdir -p "${DISK_BIN}" "${DISK_USR_BIN}" "${DISK_USR_LIB}" "${DISK_LIB}" \
         "${DISK_USR_LIBEXEC_GIT}" "${DISK_USR_SHARE_GIT_TEMPLATES}" \
         "${DISK_ETC}" "${DISK_ROOT}"

cp -fL "${ROOTFS}/usr/bin/git" "${DISK_USR_BIN}/git"
chmod +x "${DISK_USR_BIN}/git"
echo "[PIVOT-E-GIT] Staged /usr/bin/git ($(stat -c%s "${DISK_USR_BIN}/git") bytes)"

# ── Step 3: stage the 17 REAL (non-symlink) git-core helpers ─────────────────
# Symlinks back to /usr/bin/git are NOT staged (FAT32 has no symlinks; at
# runtime GIT_EXEC_PATH=/disk/usr/bin overrides the default helper-exec
# directory).  Real binaries ARE staged: they implement the HTTPS-clone
# protocol path (git-http-fetch, git-http-push, git-remote-http) and the
# helper-script set (git-mergetool, git-submodule, git-filter-branch, ...).
helper_count=0
total_helper_bytes=0
for helper in "${ROOTFS}/usr/libexec/git-core/"*; do
    [ -f "${helper}" ] || continue           # skip dirs
    [ ! -L "${helper}" ] || continue          # skip symlinks (handled via GIT_EXEC_PATH)
    name="$(basename "${helper}")"
    cp -fL "${helper}" "${DISK_USR_LIBEXEC_GIT}/${name}"
    chmod +x "${DISK_USR_LIBEXEC_GIT}/${name}" 2>/dev/null || true
    sz="$(stat -c%s "${DISK_USR_LIBEXEC_GIT}/${name}")"
    helper_count=$((helper_count + 1))
    total_helper_bytes=$((total_helper_bytes + sz))
done
echo "[PIVOT-E-GIT] Staged ${helper_count} real helpers in /usr/libexec/git-core/ (${total_helper_bytes} bytes total)"

# ── Step 4: walk DT_NEEDED transitive closure for git + the helpers ──────────
# Pattern mirrors install-pivot-e.sh / install-pivot-e-tui.sh.  We add the
# real helpers to the queue too — git-remote-http needs libcurl + libexpat
# which the main git binary does NOT directly pull in.
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
    local soname="$1" src_path="$2"
    local real_path real_name dest_dir
    real_path="$(readlink -f "${src_path}")"
    real_name="$(basename "${real_path}")"
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
    echo "[PIVOT-E-GIT]   staged ${dest_dir#${DISK_DIR}}/${soname}$([ "${soname}" != "${real_name}" ] && echo " (+${real_name})") (${size} bytes)"
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
                echo "[PIVOT-E-GIT]   MISSING dep: ${dep} (no copy in rootfs)"
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
    echo "[PIVOT-E-GIT] [${label}] closure: ${total} staged, ${skipped} skipped (base musl), ${missing} missing"
}

echo "[PIVOT-E-GIT] Walking DT_NEEDED transitive closure for git + git-core helpers ..."
walk_dt_needed_closure "git" "${ROOTFS}/usr/bin/git"
# git-remote-http is the critical helper for HTTPS clone — it pulls libcurl
# + libexpat.  We walk it explicitly so the closure resolves even if the
# main git binary's NEEDED set doesn't yet reference libcurl on this Alpine
# build (it does on 2.45 but we audit defensively).
if [ -f "${ROOTFS}/usr/libexec/git-core/git-remote-http" ]; then
    walk_dt_needed_closure "git-remote-http" \
        "${ROOTFS}/usr/libexec/git-core/git-remote-http"
fi

# ── Step 5: stage /usr/share/git-core/templates/ (init template tree) ────────
# `git init` copies these into the new .git/ directory.  Empty templates is
# fine for a smoke test but the apk package ships a stock hooks/ + info/ +
# description.  We mirror exactly what's in the rootfs.
if [ -d "${ROOTFS}/usr/share/git-core/templates" ]; then
    # cp -aL would dereference symlinks AND preserve attrs; we want plain
    # recursive copy (FAT32 ignores perms beyond x bit).  Use a per-file
    # loop so symlinks inside templates become real files.
    find "${ROOTFS}/usr/share/git-core/templates" -type f -print0 |
        while IFS= read -r -d '' src; do
            rel="${src#${ROOTFS}/usr/share/git-core/templates/}"
            dest="${DISK_USR_SHARE_GIT_TEMPLATES}/${rel}"
            mkdir -p "$(dirname "${dest}")"
            cp -fL "${src}" "${dest}"
        done
    template_count="$(find "${DISK_USR_SHARE_GIT_TEMPLATES}" -type f | wc -l)"
    echo "[PIVOT-E-GIT] Staged ${template_count} template files in /usr/share/git-core/templates/"
fi

# ── Step 6: write /etc/gitconfig + /root/.gitconfig defaults ─────────────────
# Git refuses to commit without user.name + user.email.  We pre-set a
# project default in /etc/gitconfig so `git commit` works out of the box;
# tests pass -c user.name=... -c user.email=... on the command line for
# byte-determinism but the system file is a safety net.
#
# init.defaultBranch=master keeps the test's `git log --oneline` parsing
# straightforward (the hint warning otherwise floods serial).
cat > "${DISK_ETC}/gitconfig" <<'EOF'
# AstryxOS system-wide git config (PIVOT-E Tier D, 2026-05-24).
# Per git-config(7) §FILES, /etc/gitconfig is the system-scope file.
[user]
    name = AstryxOS PIVOT-E
    email = pivot-e@astryxos.local
[init]
    defaultBranch = master
[safe]
    directory = *
[core]
    pager = cat
[advice]
    detachedHead = false
EOF
echo "[PIVOT-E-GIT] Wrote /etc/gitconfig ($(stat -c%s "${DISK_ETC}/gitconfig") bytes)"

cat > "${DISK_ROOT}/.gitconfig" <<'EOF'
# AstryxOS root-user git config (PIVOT-E Tier D, 2026-05-24).
[user]
    name = AstryxOS root
    email = root@astryxos.local
EOF
echo "[PIVOT-E-GIT] Wrote /root/.gitconfig ($(stat -c%s "${DISK_ROOT}/.gitconfig") bytes)"

# ── Step 7: seed a small smoke-test fixture ──────────────────────────────────
# /etc/pivot-e is already created by install-pivot-e.sh; we extend it with
# a tiny "git-fixture.txt" that the kernel runner adds and commits.
DISK_ETC_PIVOT_E="${DISK_DIR}/etc/pivot-e"
mkdir -p "${DISK_ETC_PIVOT_E}"
cat > "${DISK_ETC_PIVOT_E}/git-fixture.txt" <<'EOF'
PIVOT-E Tier D smoke fixture.
Committed by the pivot-e-git-test kernel runner on first boot.
EOF
echo "[PIVOT-E-GIT] Wrote fixture /etc/pivot-e/git-fixture.txt ($(stat -c%s "${DISK_ETC_PIVOT_E}/git-fixture.txt") bytes)"

# ── Summary ──────────────────────────────────────────────────────────────────
echo "[PIVOT-E-GIT] Done.  Summary:"
echo "[PIVOT-E-GIT]   - /usr/bin/git                ($(stat -c%s "${DISK_USR_BIN}/git") bytes)"
echo "[PIVOT-E-GIT]   - /usr/libexec/git-core/      (${helper_count} real helpers)"
echo "[PIVOT-E-GIT]   - /usr/share/git-core/templates/"
echo "[PIVOT-E-GIT]   - /etc/gitconfig + /root/.gitconfig"
echo "[PIVOT-E-GIT]   - /usr/lib/* — DT_NEEDED closure (libpcre2 + libexpat above the Tier B set)"
echo "[PIVOT-E-GIT]"
echo "[PIVOT-E-GIT] Re-run scripts/create-data-disk.sh --pivot-e-git --force to refresh data.img."
