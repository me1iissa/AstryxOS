#!/usr/bin/env bash
#
# Build BusyBox 1.36.1 as a static musl binary for AstryxOS, plus stage a
# minimal host-header tree so TCC-compiled C programs can find <stdio.h>,
# <unistd.h>, and friends.
#
# Produces:
#   build/disk/bin/busybox              - static musl binary (~1 MB stripped)
#   build/disk/bin/<applet>             - tiny shebang wrapper scripts
#   build/disk/usr/include/*            - curated host userspace headers
#
# Notes:
#   - FAT32 has no symlinks. Rather than 300 copies of the 1 MB binary we
#     ship a curated subset of wrapper scripts: `#!/bin/busybox <applet>`.
#     This only works if the kernel's exec path honours #! shebang lines;
#     if it does not today, that is the next step. The single real binary
#     at /bin/busybox works unconditionally.
#   - --list-full is written to build/disk/bin/busybox.applets for reference.
#
# Usage:
#   ./scripts/build-busybox.sh           # skip if already built
#   ./scripts/build-busybox.sh --force   # always rebuild
#   ./scripts/build-busybox.sh --headers-only
#                                         # skip busybox, refresh headers only
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
BUSYBOX_VER="1.36.1"
BUSYBOX_SRC_DIR="${ROOT_DIR}/BusyBox/busybox-${BUSYBOX_VER}"
BUSYBOX_ARCHIVE="${ROOT_DIR}/BusyBox/busybox-${BUSYBOX_VER}.tar.bz2"
BUSYBOX_URL="https://busybox.net/downloads/busybox-${BUSYBOX_VER}.tar.bz2"
BUSYBOX_SHA256="b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314"

DISK_BIN="${BUILD_DIR}/disk/bin"
DISK_USR_INCLUDE="${BUILD_DIR}/disk/usr/include"
OUT_BIN="${DISK_BIN}/busybox"
LOG_FILE="${BUILD_DIR}/busybox-build.log"

FORCE=false
HEADERS_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --force)         FORCE=true ;;
        --headers-only)  HEADERS_ONLY=true ;;
    esac
done

log() { echo "[BUILD-BUSYBOX] $*"; }

# ── Pick the compiler (match build-firefox-deps.sh preference order) ─────────
pick_cc() {
    if command -v x86_64-linux-musl-gcc &>/dev/null; then
        echo "x86_64-linux-musl-gcc"
    elif command -v musl-gcc &>/dev/null; then
        echo "musl-gcc"
    else
        log "ERROR: No musl compiler found. Install musl-tools."
        exit 1
    fi
}

# ── Stage host headers under build/disk/usr/include/ ────────────────────────
# Target size ~5 MB. We skip the huge C++/Python/X11/GTK/Wayland/glib trees;
# those are neither reachable from <stdio.h> nor useful on a kernel-only
# development image.
stage_headers() {
    log "Staging host headers into ${DISK_USR_INCLUDE}/ ..."

    # Fresh copy — prior runs may have included subtrees we now exclude.
    rm -rf "${DISK_USR_INCLUDE}"
    mkdir -p "${DISK_USR_INCLUDE}"

    # Allow-list approach. Host /usr/include can balloon to 100 MB+ on dev
    # boxes (LLVM, valgrind, pulse, google, unicode, gtk, ...). We only want
    # the subset reachable from <stdio.h>/<unistd.h>/POSIX + kernel UAPI.

    # ── Top-level public headers ────────────────────────────────────────────
    # Allow-listed .h files at /usr/include/*.h — the standard C / POSIX set
    # plus the few common extras (elf.h, getopt.h, pty.h, ...). Dev-box hosts
    # will have Z3, zstd, wayland-*, etc. sitting at this level; we want none
    # of those on the guest.
    local toplevel_hdrs=(
        aio.h aliases.h alloca.h ar.h argp.h argz.h assert.h byteswap.h
        complex.h cpio.h crypt.h ctype.h dirent.h dlfcn.h elf.h endian.h
        envz.h err.h errno.h error.h execinfo.h fcntl.h features.h
        fenv.h fmtmsg.h fnmatch.h fstab.h fts.h ftw.h gconv.h getopt.h
        glob.h gnu-versions.h grp.h gshadow.h iconv.h ifaddrs.h inttypes.h
        iso646.h langinfo.h lastlog.h libgen.h libintl.h libio.h limits.h
        link.h locale.h malloc.h math.h mcheck.h memory.h mntent.h
        monetary.h mqueue.h netdb.h nl_types.h nss.h obstack.h paths.h
        poll.h printf.h pthread.h pty.h pwd.h re_comp.h regex.h regexp.h
        resolv.h sched.h search.h semaphore.h setjmp.h shadow.h signal.h
        spawn.h stab.h stdc-predef.h stdint.h stdio.h stdio_ext.h
        stdlib.h string.h strings.h stropts.h syscall.h sysexits.h
        syslog.h tar.h termio.h termios.h tgmath.h threads.h time.h
        uchar.h ucontext.h ulimit.h unistd.h ustat.h utime.h utmp.h
        utmpx.h values.h wait.h wchar.h wctype.h wordexp.h xlocale.h
    )
    for h in "${toplevel_hdrs[@]}"; do
        [ -f "/usr/include/${h}" ] && cp "/usr/include/${h}" "${DISK_USR_INCLUDE}/${h}"
    done

    # ── Curated directory allow-list ────────────────────────────────────────
    # Kernel UAPI + POSIX-adjacent dirs. Everything here is:
    #   a) reachable from the standard C headers, or
    #   b) a known UAPI namespace used by portable C code.
    local dirs=(
        arpa                   # <arpa/inet.h>
        asm-generic            # kernel UAPI
        bits                   # only present at root on some distros
        gnu                    # glibc extensions (dirs, lib-names)
        linux                  # kernel UAPI — largest subtree, ~7 MB
        netinet                # <netinet/in.h>, <netinet/tcp.h>
        net                    # <net/if.h>, <net/route.h>
        sys                    # falls back to /usr/include/sys if present
    )
    for d in "${dirs[@]}"; do
        if [ -d "/usr/include/${d}" ]; then
            cp -r "/usr/include/${d}" "${DISK_USR_INCLUDE}/"
        fi
    done

    # ── Multiarch glibc layout ──────────────────────────────────────────────
    # On Debian/Ubuntu, sys/, bits/, gnu/, asm/ live under
    # /usr/include/x86_64-linux-gnu/. We flatten them directly into the top
    # level so TCC's default search (/disk/usr/include) picks them up without
    # needing an extra -isystem path.
    for sub in sys bits gnu asm; do
        local src="/usr/include/x86_64-linux-gnu/${sub}"
        local dst="${DISK_USR_INCLUDE}/${sub}"
        if [ -d "${src}" ]; then
            mkdir -p "${dst}"
            cp -rn "${src}/." "${dst}/" 2>/dev/null || true
        fi
    done

    # A handful of header files live directly at /usr/include/x86_64-linux-gnu/
    # (e.g. a.out.h, ieee754.h, fpu_control.h, …). Copy the short list.
    local mh_hdrs=( a.out.h ieee754.h fpu_control.h expat_config.h ffi.h ffitarget.h )
    for h in "${mh_hdrs[@]}"; do
        if [ -f "/usr/include/x86_64-linux-gnu/${h}" ] \
           && [ ! -f "${DISK_USR_INCLUDE}/${h}" ]; then
            cp "/usr/include/x86_64-linux-gnu/${h}" "${DISK_USR_INCLUDE}/${h}"
        fi
    done

    local sz
    sz="$(du -sh "${DISK_USR_INCLUDE}" | cut -f1)"
    log "Headers staged: ${sz} in ${DISK_USR_INCLUDE}"
}

# ── Headers-only fast path ──────────────────────────────────────────────────
if [ "${HEADERS_ONLY}" = true ]; then
    stage_headers
    exit 0
fi

# ── Fetch BusyBox source if missing ─────────────────────────────────────────
mkdir -p "${ROOT_DIR}/BusyBox"
if [ ! -d "${BUSYBOX_SRC_DIR}" ]; then
    if [ ! -f "${BUSYBOX_ARCHIVE}" ]; then
        log "Downloading BusyBox ${BUSYBOX_VER} from ${BUSYBOX_URL}..."
        if command -v wget &>/dev/null; then
            wget -q --show-progress -O "${BUSYBOX_ARCHIVE}" "${BUSYBOX_URL}"
        else
            curl -fSL -o "${BUSYBOX_ARCHIVE}" "${BUSYBOX_URL}"
        fi
    fi
    log "Verifying sha256..."
    actual_sha="$(sha256sum "${BUSYBOX_ARCHIVE}" | awk '{print $1}')"
    if [ "${actual_sha}" != "${BUSYBOX_SHA256}" ]; then
        log "ERROR: sha256 mismatch"
        log "  expected: ${BUSYBOX_SHA256}"
        log "  actual:   ${actual_sha}"
        exit 1
    fi
    log "Extracting ${BUSYBOX_ARCHIVE}..."
    tar -xjf "${BUSYBOX_ARCHIVE}" -C "${ROOT_DIR}/BusyBox/"
fi

# ── Skip if already built ───────────────────────────────────────────────────
if [ -f "${OUT_BIN}" ] && [ "${FORCE}" = false ]; then
    log "${OUT_BIN} already exists (use --force to rebuild)"
    stage_headers  # headers are cheap + idempotent
    exit 0
fi

CC_BIN="$(pick_cc)"
log "Using CC=${CC_BIN}"

cd "${BUSYBOX_SRC_DIR}"

# ── Configure ───────────────────────────────────────────────────────────────
log "Running 'make defconfig'..."
make defconfig >/dev/null

# Enable static linking.
sed -i 's|^# CONFIG_STATIC is not set$|CONFIG_STATIC=y|' .config

# CONFIG_TC uses recent netlink attrs (TCA_*) we may not expose; disable.
sed -i 's|^CONFIG_TC=y$|# CONFIG_TC is not set|' .config || true
# FEATURE_TC_INGRESS etc. — guard against leftover sub-options.
sed -i 's|^CONFIG_FEATURE_TC_INGRESS=y$|# CONFIG_FEATURE_TC_INGRESS is not set|' .config || true

# musl doesn't ship <linux/if_slip.h> pieces that some sub-applets want;
# disable SLIP/PPP if they surface as link errors (defaults usually drop them).

# Drop the build-host gcc sanity check that hard-codes gcc's arch sniffing
# and breaks under musl-gcc wrappers.
sed -i 's|^CONFIG_WERROR=y$|# CONFIG_WERROR is not set|' .config || true

# Force CC in the generated .config (Kconfig reads HOSTCC from env, CC from
# the Makefile variable). Pass via the make command line below.

# ── Kernel-UAPI header overlay ──────────────────────────────────────────────
# musl's sysroot (both musl-gcc's wrapped path and x86_64-linux-musl-gcc's
# dedicated sysroot) does NOT ship <linux/*.h>, <asm/*.h>, or <asm-generic/*.h>.
# BusyBox needs many of them (console-tools, mount, mdev, ...). We follow the
# same pattern as build-firefox-deps.sh: copy the host's kernel UAPI headers
# into a dedicated overlay dir and put it on the include path via EXTRA_CFLAGS.
# Critically we do NOT pass -I/usr/include — that would pull in glibc's
# headers and break musl.
KHDRS="${BUILD_DIR}/busybox-khdrs"
if [ ! -d "${KHDRS}/linux" ]; then
    log "Setting up kernel-UAPI header overlay at ${KHDRS}..."
    mkdir -p "${KHDRS}"
    [ -d /usr/include/linux ]       && cp -r /usr/include/linux       "${KHDRS}/"
    [ -d /usr/include/asm-generic ] && cp -r /usr/include/asm-generic "${KHDRS}/"
    [ -d /usr/include/mtd ]         && cp -r /usr/include/mtd         "${KHDRS}/"
    [ -d /usr/include/scsi ]        && cp -r /usr/include/scsi        "${KHDRS}/"
    if [ -d /usr/include/x86_64-linux-gnu/asm ]; then
        cp -r /usr/include/x86_64-linux-gnu/asm "${KHDRS}/"
    elif [ -d /usr/include/asm ]; then
        cp -r /usr/include/asm "${KHDRS}/"
    fi
fi
EXTRA_CFLAGS="-I${KHDRS}"

# ── Build ───────────────────────────────────────────────────────────────────
log "Building busybox (log: ${LOG_FILE})..."
mkdir -p "${BUILD_DIR}"

# First attempt. We tee to the log so tail/grep works for forensics.
BUILD_OK=false
if make -j"$(nproc)" CC="${CC_BIN}" HOSTCC=gcc \
        EXTRA_CFLAGS="${EXTRA_CFLAGS}" 2>&1 | tee "${LOG_FILE}" | tail -20; then
    if [ -f busybox ]; then
        BUILD_OK=true
    fi
fi

# One retry: disable utmp/wtmp if a related symbol failed to resolve.
if [ "${BUILD_OK}" = false ]; then
    if grep -qE "undefined reference to \`(getutent|setutent|endutent|updwtmp|logwtmp)'" "${LOG_FILE}"; then
        log "Link failure looks like utmp/wtmp; disabling CONFIG_FEATURE_UTMP/WTMP and retrying..."
        sed -i 's|^CONFIG_FEATURE_UTMP=y$|# CONFIG_FEATURE_UTMP is not set|' .config || true
        sed -i 's|^CONFIG_FEATURE_WTMP=y$|# CONFIG_FEATURE_WTMP is not set|' .config || true
        yes "" | make oldconfig >/dev/null || true
        make -j"$(nproc)" CC="${CC_BIN}" HOSTCC=gcc \
             EXTRA_CFLAGS="${EXTRA_CFLAGS}" 2>&1 | tee "${LOG_FILE}" | tail -20
        [ -f busybox ] && BUILD_OK=true
    fi
fi

if [ "${BUILD_OK}" = false ] || [ ! -f busybox ]; then
    log "ERROR: BusyBox build failed — see ${LOG_FILE}"
    exit 1
fi

# ── Install into build/disk/ ────────────────────────────────────────────────
mkdir -p "${DISK_BIN}"
cp busybox "${OUT_BIN}"
chmod 755 "${OUT_BIN}"

# Keep an unstripped copy for debugging purposes, then strip the on-disk one.
UNSTRIPPED_SIZE="$(du -h busybox | cut -f1)"
if command -v strip &>/dev/null; then
    strip "${OUT_BIN}" || true
fi
STRIPPED_SIZE="$(du -h "${OUT_BIN}" | cut -f1)"
log "busybox size: ${UNSTRIPPED_SIZE} unstripped -> ${STRIPPED_SIZE} stripped"

# Applet list for reference + potential future automation.
./busybox --list-full > "${OUT_BIN}.applets" 2>/dev/null || \
    ./busybox --list > "${OUT_BIN}.applets"
APPLET_COUNT="$(wc -l < "${OUT_BIN}.applets")"
log "Applets enabled: ${APPLET_COUNT}"

# ── Wrapper scripts for the pragmatic applet subset ─────────────────────────
# FAT32 has no symlinks; shipping 300 copies would blow the disk budget.
# We create #!/bin/busybox <applet> wrappers only for the most-used applets.
# If the kernel does not yet honour #! the real /bin/busybox still works by
# invoking `busybox <applet>` directly.
WRAPPERS=(
    sh ash bash ls cat echo grep find mkdir rmdir rm cp mv pwd env
    uname ps mount umount chmod chown ln sed awk head tail wc sort
    uniq tr cut test true false sleep date df du ln ln printf
    which whoami id hostname clear reset dmesg
    tar gzip gunzip zcat
    less more cmp diff stat touch
    dirname basename tee xargs yes seq
    kill killall ps top free
    nc ping wget
)

# Dedup while preserving order.
declare -A SEEN
WRAPPER_COUNT=0
for applet in "${WRAPPERS[@]}"; do
    [ -n "${SEEN[$applet]:-}" ] && continue
    SEEN[$applet]=1
    # Only emit a wrapper if busybox actually provides the applet. The
    # list entries are relative paths (e.g. "bin/sh", "usr/bin/awk"), so
    # we check each plausible install location.
    if ! grep -Fxq "bin/${applet}"      "${OUT_BIN}.applets" \
       && ! grep -Fxq "usr/bin/${applet}"  "${OUT_BIN}.applets" \
       && ! grep -Fxq "sbin/${applet}"     "${OUT_BIN}.applets" \
       && ! grep -Fxq "usr/sbin/${applet}" "${OUT_BIN}.applets"; then
        continue
    fi
    wrapper="${DISK_BIN}/${applet}"
    printf '#!/bin/busybox %s\n' "${applet}" > "${wrapper}"
    chmod 755 "${wrapper}"
    WRAPPER_COUNT=$((WRAPPER_COUNT + 1))
done
log "Wrote ${WRAPPER_COUNT} applet wrapper scripts in ${DISK_BIN}/"

# ── Stage headers (cheap and idempotent) ────────────────────────────────────
stage_headers

# ── Summary ─────────────────────────────────────────────────────────────────
log "Done."
log "  binary        : ${OUT_BIN}"
log "  applet list   : ${OUT_BIN}.applets (${APPLET_COUNT} applets)"
log "  wrappers      : ${WRAPPER_COUNT} files in ${DISK_BIN}/"
log "  headers       : $(du -sh "${DISK_USR_INCLUDE}" | cut -f1) in ${DISK_USR_INCLUDE}/"
log "  total on-disk : $(du -sh "${DISK_BIN}" "${DISK_USR_INCLUDE}" 2>/dev/null | awk '{s+=$1} END {print s" (approx)"}' || true)"
