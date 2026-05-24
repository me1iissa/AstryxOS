#!/usr/bin/env bash
#
# install-pivot-e-tui.sh — Stage PIVOT-E Tier C TUI utilities (nano, vim,
# htop, tmux) plus their DT_NEEDED transitive closures into the AstryxOS
# data-disk staging tree.  Companion to install-pivot-e.sh (Tier B) and
# install-busybox-cli.sh (Tier A).
#
# What is "Tier C"?
# -----------------
# Standalone Alpine musl-PIE binaries that depend on the per-pair PTY +
# termios substrate landed in PR #450 (/dev/ptmx alloc, /dev/pts/N read+
# write, TIOCGPTN, TIOCSPTLCK, TIOCGWINSZ, TIOCSWINSZ, TCGETS, TCSETS,
# TCSETSW, TCSETSF, TIOCGPGRP, TIOCSPGRP).  The four utilities staged here
# are the canonical Linux TUI surface:
#
#   /usr/bin/nano    — GNU nano 8.0 (ncurses TUI text editor)
#   /usr/bin/vim     — Vim 9.1.0707 (ncurses TUI editor; busybox vi is
#                      Tier A as a fallback)
#   /usr/bin/htop    — htop 3.3.0 (ncurses TUI process monitor)
#   /usr/bin/tmux    — tmux 3.4 (libevent + ncurses terminal multiplexer)
#
# All four share DT_NEEDED libncursesw + libc.musl.  tmux additionally
# pulls libevent_core (PR #446 epoll dup(2) ABI already covers libevent's
# epoll-based event loop).  None depend on glibc — they are pure musl-PIE.
#
# What this stages
# ----------------
#
#   1. /usr/bin/nano                  (~290 KiB)
#   2. /usr/bin/vim                   (~2.7 MiB)
#   3. /usr/bin/htop                  (~260 KiB)
#   4. /usr/bin/tmux                  (~750 KiB)
#   5. /usr/lib/libncursesw.so.6      (ncurses 6.4 wide-char build)
#   6. /usr/lib/libevent_core-2.1.so.7 (libevent core, tmux only)
#   7. Transitive closure of the above (walker reuses install-pivot-e.sh
#      pattern — BFS over readelf -d NEEDED; scoped to the musl runtime
#      tree at /usr/lib and /lib).
#
# Terminfo is already staged by install-pivot-e.sh (PR #450 added the
# ncurses-terminfo-base subset under /etc/terminfo/).  ncurses honours
# TERM=xterm + /etc/terminfo/x/xterm by default.
#
# Idempotent.  Pass --force to refresh the rootfs (apk add --upgrade) +
# restage.
#
# References (public)
#   - GNU nano:    https://www.nano-editor.org/dist/v8/nano.html
#   - Vim:         https://vimhelp.org/
#   - htop:        https://htop.dev/
#   - tmux:        https://github.com/tmux/tmux/wiki
#   - musl ld search order: man:ld-musl-x86_64.so.1(8)
#   - ncurses(3X): https://invisible-island.net/ncurses/man/ncurses.3x.html
#   - terminfo(5): https://invisible-island.net/ncurses/man/terminfo.5.html
#   - System V ABI (ELF gABI) §5.4 — DT_RPATH/DT_RUNPATH search order
#   - Alpine v3.20 packages: https://pkgs.alpinelinux.org/packages?branch=v3.20
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_BIN="${DISK_DIR}/bin"
DISK_USR_BIN="${DISK_DIR}/usr/bin"
DISK_USR_LIB="${DISK_DIR}/usr/lib"
DISK_LIB="${DISK_DIR}/lib"
DISK_ETC="${DISK_DIR}/etc"

# Shared TLS staging rootfs — install-tls-stack.sh + install-pivot-e.sh
# already bootstrap this Alpine tree.  We add nano/vim/htop/tmux packages
# on top.  Independent from the firefox-musl rootfs so parallel dispatches
# do not race on apk add.
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
        -h|--help) sed -n '2,55p' "$0"; exit 0 ;;
        *) echo "[PIVOT-E-TUI] WARN: ignoring unknown arg '${arg}'" ;;
    esac
done

# ── Pre-flight: Tier A (busybox) + Tier B (curl/jq/tar) must be staged ───────
if [ ! -x "${DISK_BIN}/busybox" ]; then
    echo "[PIVOT-E-TUI] ERROR: /bin/busybox is not staged at ${DISK_BIN}/busybox"
    echo "[PIVOT-E-TUI]        Run scripts/install-busybox-cli.sh first (Tier A surface)."
    exit 1
fi
if [ ! -x "${DISK_USR_BIN}/curl" ]; then
    echo "[PIVOT-E-TUI] ERROR: /usr/bin/curl is not staged at ${DISK_USR_BIN}/curl"
    echo "[PIVOT-E-TUI]        Run scripts/install-pivot-e.sh first (Tier B substrate)."
    exit 1
fi

# ── Pre-flight: apk-static + shared TLS rootfs ───────────────────────────────
if [ ! -x "${APK_STATIC}" ]; then
    echo "[PIVOT-E-TUI] ERROR: apk.static not present at ${APK_STATIC}"
    echo "[PIVOT-E-TUI]        Run scripts/install-firefox-musl.sh first to bootstrap."
    exit 1
fi
if [ ! -d "${ROOTFS}" ] || [ ! -d "${ALPINE_KEYS}" ]; then
    echo "[PIVOT-E-TUI] ERROR: shared TLS rootfs not present at ${ROOTFS}"
    echo "[PIVOT-E-TUI]        Run scripts/install-tls-stack.sh first to bootstrap."
    exit 1
fi

# ── Step 1: apk add nano vim htop tmux + ncurses-terminfo-base ───────────────
# These pull in libncursesw, libevent (for tmux), vim-common (for vim runtime
# tags), and the terminfo entries (which Tier C utilities resolve at
# startup via TERM=xterm and /etc/terminfo/x/xterm).
NEEDED_BINS="${ROOTFS}/usr/bin/nano ${ROOTFS}/usr/bin/vim ${ROOTFS}/usr/bin/htop ${ROOTFS}/usr/bin/tmux"
NEED_INSTALL=false
for b in ${NEEDED_BINS}; do
    [ -f "${b}" ] || NEED_INSTALL=true
done
if [ "${NEED_INSTALL}" = true ] || [ "${FORCE}" = true ]; then
    echo "[PIVOT-E-TUI] Installing nano + vim + htop + tmux into ${ROOTFS} via apk ..."
    # The "errors updating directory permissions" + "busybox.trigger: chroot"
    # warnings are expected when apk runs outside a chroot; the package
    # contents are still extracted.  We tolerate them via `|| true`.
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --repository "${ALPINE_COMMUNITY}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --update-cache \
        add nano vim htop tmux ncurses ncurses-terminfo-base 2>&1 \
        | sed 's/^/[PIVOT-E-TUI]   /' || true
fi
for b in ${NEEDED_BINS}; do
    if [ ! -f "${b}" ]; then
        echo "[PIVOT-E-TUI] ERROR: ${b} still missing after apk add"
        exit 1
    fi
done

# ── Step 2: stage the Tier C binaries ────────────────────────────────────────
mkdir -p "${DISK_BIN}" "${DISK_USR_BIN}" "${DISK_USR_LIB}" "${DISK_LIB}"

stage_bin() {
    local name="$1" src_path="$2"
    cp -fL "${src_path}" "${DISK_USR_BIN}/${name}"
    chmod +x "${DISK_USR_BIN}/${name}"
    local size; size="$(stat -c%s "${DISK_USR_BIN}/${name}")"
    echo "[PIVOT-E-TUI] Staged /usr/bin/${name} (${size} bytes)"
}

stage_bin nano "${ROOTFS}/usr/bin/nano"
stage_bin vim  "${ROOTFS}/usr/bin/vim"
stage_bin htop "${ROOTFS}/usr/bin/htop"
stage_bin tmux "${ROOTFS}/usr/bin/tmux"

# ── Step 3: walk DT_NEEDED transitive closure for each Tier C binary ─────────
# Pattern mirrors install-pivot-e.sh's walker (PR #441 origin), scoped to
# the musl runtime tree.  Library names are resolved by:
#   1. ${ROOTFS}/usr/lib/${soname}
#   2. ${ROOTFS}/lib/${soname}
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
    echo "[PIVOT-E-TUI]   staged ${dest_dir#${DISK_DIR}}/${soname}$([ "${soname}" != "${real_name}" ] && echo " (+${real_name})") (${size} bytes)"
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
                echo "[PIVOT-E-TUI]   MISSING dep: ${dep} (no copy in rootfs)"
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
    echo "[PIVOT-E-TUI] [${label}] closure: ${total} staged, ${skipped} skipped (base musl), ${missing} missing"
}

echo "[PIVOT-E-TUI] Walking DT_NEEDED transitive closure for Tier C binaries ..."
walk_dt_needed_closure "nano" "${ROOTFS}/usr/bin/nano"
walk_dt_needed_closure "vim"  "${ROOTFS}/usr/bin/vim"
walk_dt_needed_closure "htop" "${ROOTFS}/usr/bin/htop"
walk_dt_needed_closure "tmux" "${ROOTFS}/usr/bin/tmux"

# ── Step 4: terminfo — already staged by create-data-disk.sh PR #450 ─────────
# /usr/share/terminfo/ is populated by create-data-disk.sh with the
# high-impact entries (xterm, xterm-256color, vt100, vt220, linux, screen,
# dumb, ansi, tmux, tmux-256color).  Alpine ncurses searches /etc/terminfo
# THEN /usr/share/terminfo so the existing PR #450 staging covers our Tier C
# utilities (htop/tmux/nano/vim are explicitly named in PR #450's intent
# comment at create-data-disk.sh L938).  No additional staging needed.

# ── Step 5: stage minimal nano syntax-files dir so nano doesn't warn ─────────
# nano warns on stderr if /usr/share/nano/* is missing.  We stage the
# directory empty (no syntax files); this silences the warning without
# pulling the ~700 KiB nanorc.gz tree.
mkdir -p "${DISK_DIR}/usr/share/nano"

# ── Step 6: stage /tmp scratch space for tmux server socket + nano backups ───
# tmux requires a writable /tmp for its server socket
# (/tmp/tmux-<uid>/default).  AstryxOS already provides /tmp as a writable
# tmpfs once the FS is up; nothing to stage at install time.  This block
# exists as documentation — if a future regression breaks /tmp, the failure
# mode will be: tmux exits with "lost server" or "no server running".

# ── Summary ──────────────────────────────────────────────────────────────────
echo "[PIVOT-E-TUI] Done.  Summary:"
echo "[PIVOT-E-TUI]   - /usr/bin/nano   ($(stat -c%s "${DISK_USR_BIN}/nano") bytes)"
echo "[PIVOT-E-TUI]   - /usr/bin/vim    ($(stat -c%s "${DISK_USR_BIN}/vim") bytes)"
echo "[PIVOT-E-TUI]   - /usr/bin/htop   ($(stat -c%s "${DISK_USR_BIN}/htop") bytes)"
echo "[PIVOT-E-TUI]   - /usr/bin/tmux   ($(stat -c%s "${DISK_USR_BIN}/tmux") bytes)"
echo "[PIVOT-E-TUI]   - /usr/lib/libncursesw.so.6 + closure"
echo "[PIVOT-E-TUI]   - /usr/lib/libevent_core-2.1.so.7 (tmux)"
echo "[PIVOT-E-TUI]   - /usr/share/terminfo/ — staged by create-data-disk.sh (PR #450)"
echo "[PIVOT-E-TUI]"
echo "[PIVOT-E-TUI] Note: musl libc + ld-musl come from install-firefox-musl.sh."
echo "[PIVOT-E-TUI] Re-run scripts/create-data-disk.sh --pivot-e-tui --force to refresh data.img."
