#!/usr/bin/env bash
#
# install-firefox-musl-debug.sh — Stage Alpine debug-symbol companion packages
# alongside the musl Firefox install so that addr2line / nm can attribute RIPs
# captured at runtime (e.g. by the K-class DR hardware watchpoint and the
# rip-trace-resolve harness subcommand) to named functions.
#
# Background
# ----------
#
# Alpine ships per-package "-dbg" subpackages whose contents live under
# /usr/lib/debug/<original-path>/<name>.debug.  The corresponding stripped
# binaries carry a .gnu_debuglink section pointing at <name>.debug, so binutils
# tools (addr2line, objdump --line-numbers, gdb, nm) automatically locate the
# companion debug file when it is present in the standard debug-info search
# path (binary dir, .debug/, or /usr/lib/debug/<binary's absolute path>/).
#
# Coverage matrix for the musl Firefox stack
# ------------------------------------------
#
#   Package                 Ships -dbg?  Stages
#   ──────────────────────  ───────────  ──────────────────────────────────────
#   musl                    YES          /usr/lib/debug/lib/ld-musl-x86_64.so.1.debug
#                                          (also covers libc.musl-x86_64.so.1 —
#                                          libc is a symlink to ld-musl)
#   glib                    YES          /usr/lib/debug/usr/lib/libglib-2.0.so.*.debug
#                                          /usr/lib/debug/usr/lib/libgobject-2.0.so.*.debug
#                                          /usr/lib/debug/usr/lib/libgio-2.0.so.*.debug
#   gdk-pixbuf              YES          /usr/lib/debug/usr/lib/libgdk_pixbuf-2.0.so.*.debug
#   cairo                   YES          /usr/lib/debug/usr/lib/libcairo.so.*.debug
#   gtk+3.0                 YES          /usr/lib/debug/usr/lib/libgtk-3.so.*.debug
#                                          /usr/lib/debug/usr/lib/libgdk-3.so.*.debug
#   firefox-esr             NO           — Alpine does not ship a -dbg subpackage
#                                          for firefox-esr in v3.20.  See the
#                                          APKBUILD at community/firefox-esr/:
#                                          subpackages="$pkgname-intl" only.
#                                          (Compare community/firefox/ which DOES
#                                          ship firefox-dbg.)
#
# Implication for libxul.so attribution
# -------------------------------------
#
# Because Alpine does not ship debug symbols for firefox-esr, addr2line cannot
# resolve RIPs inside libxul.so by .gnu_debuglink alone.  Three options exist:
#
#   1. Coarse function-level names via Mozilla's tecken symbol server.  Alpine
#      uploads to tecken keyed by its exact ELF BuildID, so the .sym matches
#      the Alpine libxul byte-for-byte (no VMA drift).  The .sym contains
#      PUBLIC-only records (Alpine builds without DWARF), so coverage is
#      .dynsym names plus their entry-point VMAs — ~8,600 symbols, enough to
#      attribute K-class RIP fires to within a function (file/line not
#      recoverable).  scripts/inject-libxul-symbols.sh --musl handles this
#      automatically; create-data-disk.sh wires it whenever
#      ASTRYXOS_FIREFOX_DEBUG is set with FIREFOX_VARIANT=musl.
#
#   2. Build firefox-esr from source inside an Alpine builder with
#      --disable-strip and --disable-install-strip.  Multi-hour, multi-GiB.
#      Out of scope for this script.
#
#   3. Switch the data-disk from firefox-esr-115.x to firefox-132.x and use
#      Alpine's firefox-dbg (47.9 MiB installed).  Changes the reproducer.
#      Coordinator-level decision; not done by this script.
#
# Layout written to build/disk/
# -----------------------------
#
# The Alpine apk packages already place files at /usr/lib/debug/<...>; we
# preserve that layout in build/disk/ so the kernel VFS maps /usr/lib/debug
# the same way it maps /usr/lib/ (via the /usr → /disk/usr symlink).  No
# .gnu_debuglink rewrites are required.  Per binutils' debug-info-resolution
# algorithm (see GDB §18.2 "Debugging Information in Separate Files"), tools
# search in this order when a .gnu_debuglink section names "X.debug":
#
#   (a) <binary-dir>/X.debug
#   (b) <binary-dir>/.debug/X.debug
#   (c) <global-debug-dir>/<absolute-path-of-binary>/X.debug
#
# Alpine packages target (c) with global-debug-dir = /usr/lib/debug.
#
# Size budget on the FAT32 data image (2 GiB total)
# -------------------------------------------------
#
# Empirical sizes (Alpine v3.20 main + community, x86_64) when staged:
#
#   musl-dbg                ~ 2.8 MiB  ← always staged (target use-case)
#   glib-dbg                ~ 12 MiB
#   gdk-pixbuf-dbg          ~  1 MiB
#   cairo-dbg               ~  5 MiB
#   gtk+3.0-dbg             ~ 21 MiB
#   ──────────────────────  ────────
#   TOTAL                   ~ 42 MiB
#
# Within the current ~360 MiB musl FF data-image footprint, leaving headroom
# for kernel binaries, fonts, busybox, and FAT32 metadata overhead.
#
# Usage
# -----
#
#   bash scripts/install-firefox-musl-debug.sh           # idempotent install
#   bash scripts/install-firefox-musl-debug.sh --force   # re-download + restage
#   bash scripts/install-firefox-musl-debug.sh --musl-only
#                                                        # stage musl-dbg only
#                                                        # (~2.8 MiB, target the
#                                                        #  K-class SSP fires)
#
# Environment
# -----------
#
#   ASTRYXOS_FIREFOX_DEBUG=1   set by create-data-disk.sh when the caller wants
#                              the debug companions included in data.img.
#
# References (public)
# -------------------
#
#   - GDB §18.2 "Debugging Information in Separate Files":
#     https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html
#   - Alpine package index:
#     https://pkgs.alpinelinux.org/packages?name=*-dbg&branch=v3.20&arch=x86_64
#   - Mozilla Breakpad symbol format:
#     https://chromium.googlesource.com/breakpad/breakpad/+/HEAD/docs/symbol_files.md
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_DEBUG_DIR="${DISK_DIR}/usr/lib/debug"

CACHE_DIR="${HOME}/.cache/astryxos-firefox-musl"
APK_BIN="${CACHE_DIR}/apk-tools/sbin/apk.static"
ROOTFS="${CACHE_DIR}/rootfs"

# Pinned set of -dbg packages we know Alpine v3.20 ships for the FF stack.
# Adding a package here is a deliberate act; the script verifies each one
# landed under ${ROOTFS}/usr/lib/debug/ after `apk add`.
ALL_DBG_PKGS=(musl-dbg glib-dbg gdk-pixbuf-dbg cairo-dbg gtk+3.0-dbg)
MUSL_ONLY_DBG_PKGS=(musl-dbg)

FORCE=false
MUSL_ONLY=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        --musl-only) MUSL_ONLY=true ;;
        -h|--help)
            sed -n '2,90p' "$0"
            exit 0
            ;;
        *)
            echo "[FF-MUSL-DBG] ERROR: unknown arg '${arg}'" >&2
            exit 2
            ;;
    esac
done

DBG_PKGS=("${ALL_DBG_PKGS[@]}")
if [ "${MUSL_ONLY}" = true ]; then
    DBG_PKGS=("${MUSL_ONLY_DBG_PKGS[@]}")
fi

# ── Preconditions ────────────────────────────────────────────────────────────
# install-firefox-musl.sh must have run first (we share its rootfs + apk.static
# cache so debug companion versions are guaranteed to match the binaries).
if [ ! -x "${APK_BIN}" ]; then
    echo "[FF-MUSL-DBG] ERROR: ${APK_BIN} not present."
    echo "[FF-MUSL-DBG]        Run scripts/install-firefox-musl.sh first."
    exit 1
fi
if [ ! -d "${ROOTFS}/lib/apk/db" ]; then
    echo "[FF-MUSL-DBG] ERROR: Alpine rootfs at ${ROOTFS} not initialised."
    echo "[FF-MUSL-DBG]        Run scripts/install-firefox-musl.sh first."
    exit 1
fi

# ── Idempotency check ─────────────────────────────────────────────────────────
# We consider the install up-to-date when every requested -dbg package's
# top-level marker file exists under ${DISK_DEBUG_DIR}.  musl-dbg is the
# canonical marker (always staged); the others only when full mode requested.
if [ "${FORCE}" = false ] && \
   [ -f "${DISK_DEBUG_DIR}/lib/ld-musl-x86_64.so.1.debug" ]; then
    if [ "${MUSL_ONLY}" = true ]; then
        echo "[FF-MUSL-DBG] musl-dbg already staged at ${DISK_DEBUG_DIR}/lib/ — skipping (use --force to reinstall)"
        exit 0
    fi
    # In full mode also require one GTK-stack marker to consider it complete.
    if compgen -G "${DISK_DEBUG_DIR}/usr/lib/libgtk-3.so.*.debug" > /dev/null; then
        echo "[FF-MUSL-DBG] full debug stack already staged at ${DISK_DEBUG_DIR}/ — skipping (use --force to reinstall)"
        exit 0
    fi
fi

echo "[FF-MUSL-DBG] Staging Alpine debug companions: ${DBG_PKGS[*]}"

# ── Step 1: apk add the -dbg packages into the shared Alpine rootfs ──────────
# install-firefox-musl.sh already created the rootfs, signing key, and
# repositories file.  We reuse them so debug-symbol package versions are
# guaranteed to match the binary versions exactly (apk's solver picks the
# same release).
#
# We intentionally do NOT pass --no-cache here so apk re-uses any downloads
# left behind by install-firefox-musl.sh; for forced runs the script's
# upstream --force handling already wipes the rootfs.
"${APK_BIN}" \
    --root="${ROOTFS}" \
    --arch=x86_64 \
    --no-progress \
    add "${DBG_PKGS[@]}" 2>&1 \
    | sed 's/^/[FF-MUSL-DBG apk] /' \
    | tail -40 || true

# Verify musl-dbg landed (canonical marker; the rest are best-effort because
# Alpine's solver may resolve different transitive deps on different days).
if [ ! -f "${ROOTFS}/usr/lib/debug/lib/ld-musl-x86_64.so.1.debug" ]; then
    echo "[FF-MUSL-DBG] ERROR: musl-dbg did not deposit ld-musl-x86_64.so.1.debug"
    echo "[FF-MUSL-DBG]        ${ROOTFS}/usr/lib/debug/lib/ contents:"
    ls -la "${ROOTFS}/usr/lib/debug/lib/" 2>&1 | sed 's/^/[FF-MUSL-DBG]   /'
    exit 1
fi

# ── Step 2: Stage /usr/lib/debug/ tree into build/disk/ ──────────────────────
# Alpine's apk places every -dbg payload under /usr/lib/debug/<abs-binary-path>/.
# We mirror those payloads — and ONLY those — into build/disk/usr/lib/debug/.
# Idempotency note: install-firefox-musl-debug.sh shares the rootfs with
# install-firefox-musl.sh; prior `--force` invocations or earlier full-mode
# runs may leave -dbg packages installed that the current invocation did NOT
# request.  Blanket-copying ${ROOTFS}/usr/lib/debug/ would stage those into
# data.img.  Instead we read apk's per-package file list and copy only the
# files that belong to the packages requested on this invocation.
#
# `apk info -L <pkg>` prints the absolute (rootfs-relative) paths of every
# file in <pkg>; lines starting with the package header and blank lines are
# filtered.  No .gnu_debuglink rewrites are required — the binaries already
# have the section pointing at the correct basename, and binutils' debug-info
# search algorithm finds the file at /usr/lib/debug/<bin-abs-path>/<basename>.
mkdir -p "${DISK_DEBUG_DIR}"

# Wipe a prior stage tree before re-staging so a `--musl-only` invocation
# following a full-mode one drops the previously-staged gtk/glib/cairo/
# pixbuf debug files.  Done before the per-package copy loop, not as part
# of the loop, so a single file-system pass replaces the whole tree.
rm -rf "${DISK_DEBUG_DIR}"
mkdir -p "${DISK_DEBUG_DIR}"

copied_count=0
for pkg in "${DBG_PKGS[@]}"; do
    # apk info -L lists owned files, one per line, sans leading slash.
    # Header line "<pkg> contains:" is dropped by tail -n +2.
    while IFS= read -r relpath; do
        [ -z "${relpath}" ] && continue
        # We only care about files under usr/lib/debug/ — the rest of the
        # -dbg package's payload (typically empty) goes nowhere useful.
        case "${relpath}" in
            usr/lib/debug/*) ;;
            *) continue ;;
        esac
        src="${ROOTFS}/${relpath}"
        # In Alpine -dbg packages, usr/lib/debug entries are mostly regular
        # files (the .debug data) plus a few directory entries (which we
        # create implicitly via `mkdir -p` below).
        if [ -f "${src}" ]; then
            # Strip the leading "usr/lib/debug/" so we land at
            # ${DISK_DEBUG_DIR}/<rest>.
            rest="${relpath#usr/lib/debug/}"
            mkdir -p "${DISK_DEBUG_DIR}/$(dirname "${rest}")"
            cp -fL "${src}" "${DISK_DEBUG_DIR}/${rest}"
            copied_count=$((copied_count + 1))
        fi
    done < <("${APK_BIN}" --root="${ROOTFS}" info -L "${pkg}" 2>/dev/null | tail -n +2)
done

DBG_FILE_COUNT="$(find "${DISK_DEBUG_DIR}" -type f -name '*.debug' 2>/dev/null | wc -l)"
DBG_TREE_SIZE="$(du -sh "${DISK_DEBUG_DIR}" 2>/dev/null | cut -f1)"
echo "[FF-MUSL-DBG] Staged ${DBG_FILE_COUNT} .debug files to ${DISK_DEBUG_DIR} (${DBG_TREE_SIZE})"

# ── Step 3: Sanity-check addr2line resolution (host-side) ────────────────────
# binutils' addr2line searches for the .gnu_debuglink companion in three places
# (see GDB §18.2 "Debugging Information in Separate Files"):
#   (a) the binary's directory                <bin-dir>/<name>.debug
#   (b) the binary's .debug subdirectory       <bin-dir>/.debug/<name>.debug
#   (c) the global debug-info directory        /usr/lib/debug/<abs-bin-path>/<name>.debug
#
# Path (c) on the host points at the host's /usr/lib/debug — not our staging
# tree.  addr2line has no CLI flag to override (c) (objdump and gdb both do via
# --debug-file-directory, but addr2line does not as of binutils 2.42).
#
# To verify resolution without polluting build/disk/ with adjacent symlinks
# that would inflate data.img (FAT32 has no symlinks, mcopy dereferences), we
# stage a temporary verification root under a host-only mktemp dir, symlink the
# binary and its companion into the binutils-friendly layout, and run
# addr2line there.  No on-disk artefact is left behind in build/disk/.
STAGED_LD_MUSL="${DISK_DIR}/lib/ld-musl-x86_64.so.1"
STAGED_LD_MUSL_DBG="${DISK_DEBUG_DIR}/lib/ld-musl-x86_64.so.1.debug"
if [ -f "${STAGED_LD_MUSL}" ] && [ -f "${STAGED_LD_MUSL_DBG}" ] && \
   command -v addr2line >/dev/null 2>&1; then
    VERIFY_DIR="$(mktemp -d -t astryxos-ff-musl-dbg-verify-XXXXXX)"
    trap 'rm -rf "${VERIFY_DIR}"' EXIT
    ln -sf "${STAGED_LD_MUSL}"     "${VERIFY_DIR}/ld-musl-x86_64.so.1"
    ln -sf "${STAGED_LD_MUSL_DBG}" "${VERIFY_DIR}/ld-musl-x86_64.so.1.debug"
    # 0x5e880 sits inside __unmapself in musl 1.2.5 (the symbol observed by
    # the K-class watchpoint investigation).  Failure here means the
    # .gnu_debuglink section is corrupt or the companion file did not stage.
    RESOLVED="$(addr2line --inlines --functions --demangle \
        -e "${VERIFY_DIR}/ld-musl-x86_64.so.1" 0x5e880 2>&1 | head -1)"
    if [ -n "${RESOLVED}" ] && [ "${RESOLVED}" != "??" ]; then
        echo "[FF-MUSL-DBG] addr2line verification: 0x5e880 → ${RESOLVED}"
    else
        echo "[FF-MUSL-DBG] WARNING: addr2line could not resolve 0x5e880 in ld-musl (got '${RESOLVED}')"
        echo "[FF-MUSL-DBG]          .gnu_debuglink lookup chain may be broken — check"
        echo "[FF-MUSL-DBG]          readelf --string-dump=.gnu_debuglink ${STAGED_LD_MUSL}"
    fi
    rm -rf "${VERIFY_DIR}"
    trap - EXIT
else
    echo "[FF-MUSL-DBG] NOTE: skipped addr2line check (ld-musl staged: $([ -f ${STAGED_LD_MUSL} ] && echo yes || echo no); addr2line: $(command -v addr2line >/dev/null 2>&1 && echo yes || echo no))"
fi

echo "[FF-MUSL-DBG] Done."
echo "[FF-MUSL-DBG]   Layout: ${DISK_DEBUG_DIR}/<abs-binary-path>/<basename>.debug"
echo "[FF-MUSL-DBG]   Total:  ${DBG_TREE_SIZE} across ${DBG_FILE_COUNT} files"
echo "[FF-MUSL-DBG]   Coverage: musl libc + ld-musl; +GTK/glib/cairo/pixbuf when not --musl-only"
echo "[FF-MUSL-DBG]   libxul: handled by scripts/inject-libxul-symbols.sh --musl"
echo "[FF-MUSL-DBG]           (Mozilla tecken keyed by Alpine ELF BuildID; PUBLIC-only,"
echo "[FF-MUSL-DBG]            ~8,600 entries; VMAs byte-exact vs Alpine libxul)."
