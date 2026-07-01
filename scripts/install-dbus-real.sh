#!/usr/bin/env bash
#
# install-dbus-real.sh — Install REAL libdbus-1.so.3 (and its transitive
# libsystemd.so.0 dependency) from the host into build/disk/, overwriting any
# stub copy that install-firefox-stubs.sh may have produced.
#
# Rationale
# ─────────
# Firefox ESR 115 (headless) initialises a DBus client during nsAppShell::Init
# / nsThreadManager / proxy / AT-SPI registration, even with no session bus
# running.  Mozilla expects libdbus to:
#
#   - return a NULL DBusConnection* from dbus_bus_get() when the environment
#     does not advertise a session bus (DBUS_SESSION_BUS_ADDRESS unset, no
#     /var/run/dbus/system_bus_socket reachable);
#   - populate the DBusError struct passed to that call with a sensible
#     error name + message ("org.freedesktop.DBus.Error.NoServer");
#   - thread the result through dbus_error_is_set() / dbus_error_free() so
#     Mozilla's no-DBus fallback branch in nsAppShell takes effect.
#
# The generic stub written by install-firefox-stubs.sh satisfies the dynamic
# linker but returns NULL/0 for every entry point, including the
# DBusError-out-pointer setters.  Mozilla then iterates a NULL list, reads
# uninitialised dbus_error.name (NULL char*) inside a printf, or derefs a
# stub-returned NULL handler-app pointer — the same NULL-fault class that
# fontconfig stubs produced before PR #179.  W97's verifier flagged Mozilla
# writing the single-byte "I" / "M" markers to fd=19 (the DBus auth-protocol
# greeting + AUTH command first bytes) as the next-likely blocker.
#
# Real libdbus is a pure userspace .so that talks to glibc — every syscall
# it issues (socket, connect, sendmsg, recvmsg, poll, close, getuid,
# getsockopt) is already implemented by AstryxOS.  Its one transitive
# dependency on Debian/Ubuntu is libsystemd.so.0 (for sd_journal_send and
# sd_listen_fds — libdbus uses neither in the no-session-bus path, but the
# dynamic linker still resolves the NEEDED entry at load time).  libsystemd
# in turn depends only on libm + libc, both already provided by
# install-glibc.sh.
#
# Disk delta (Ubuntu 24.04 host):
#   libdbus-1.so.3.38.3    314 KiB
#   libsystemd.so.0.42.0  1102 KiB
#
# Total ~1.4 MiB.  The DBus daemon itself (`dbus-daemon`) is NOT shipped —
# DBUS_SESSION_BUS_ADDRESS stays unset, dbus_bus_get returns NULL with a
# well-formed DBusError, and Mozilla's nsAppShell falls through to its
# no-DBus path.  Headless Mozilla installs without a session bus are a
# supported configuration upstream, so the "I"/"M" handshake bytes never
# reach a real bus and Mozilla advances past the DBus init step.
#
# Layout
# ──────
# Real libraries are copied under their versioned names (e.g.
# libdbus-1.so.3.38.3) with soname symlinks (libdbus-1.so.3) into BOTH
# build/disk/lib64/ and build/disk/lib/x86_64-linux-gnu/.  This matches the
# layout install-firefox-stubs.sh, install-glibc.sh, and install-fonts-real.sh
# already use and guarantees the runtime finds the real .so regardless of
# LD_LIBRARY_PATH ordering.
#
# install-firefox-stubs.sh writes its 36 KiB stub libdbus-1.so.3 first; this
# script is intended to run AFTER stubs (and AFTER install-fonts-real.sh, for
# ordering consistency) and OVERWRITES the libdbus-1 entry with a real
# binary.  The libdbus-glib-1.so.2 stub is LEFT in place — that wrapper
# library is deprecated upstream and is not on the host as of Ubuntu 24.04;
# modern Mozilla calls plain libdbus-1 instead.
#
# Usage
# ─────
#   ./scripts/install-dbus-real.sh           # idempotent: skip files already
#                                            # present (and same size as host)
#   ./scripts/install-dbus-real.sh --force   # overwrite unconditionally
#
# Exit codes
# ──────────
#   0    success (or success-with-warnings: host missing optional deps)
#   1    host missing the mandatory libdbus-1.so.3 — fix by
#        `sudo apt install libdbus-1-3`
#
# Reference: dbus.freedesktop.org/doc/api/html/group__DBusBus.html
#            (dbus_bus_get behaviour when DBUS_SESSION_BUS_ADDRESS is unset)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# BUILD_DIR is overridable via ASTRYXOS_BUILD_DIR so an isolated variant build
# (create-data-disk.sh --build-dir) stages into that root instead of build/.
BUILD_DIR="${ASTRYXOS_BUILD_DIR:-${ROOT_DIR}/build}"
DISK_LIB64="${BUILD_DIR}/disk/lib64"
DISK_GNU="${BUILD_DIR}/disk/lib/x86_64-linux-gnu"

FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
    esac
done

log() { echo "[dbus-real] $*"; }

mkdir -p "${DISK_LIB64}" "${DISK_GNU}"

# ── Host search dirs ─────────────────────────────────────────────────────────
SEARCH_DIRS=(
    /usr/lib/x86_64-linux-gnu
    /lib/x86_64-linux-gnu
    /usr/lib64
    /lib64
)

find_lib() {
    local name="$1"
    for d in "${SEARCH_DIRS[@]}"; do
        local p="${d}/${name}"
        if [ -e "${p}" ]; then
            echo "${p}"
            return 0
        fi
    done
    return 1
}

# ── Copy one library: resolve symlink, copy real file under its real name,
#    then create the soname symlink.  Mirrors install-fonts-real.sh's copy_lib.
# ────────────────────────────────────────────────────────────────────────────
copy_lib() {
    local soname="$1"      # e.g. libdbus-1.so.3
    local src_path="$2"    # e.g. /usr/lib/x86_64-linux-gnu/libdbus-1.so.3

    local real_src real_name
    real_src="$(readlink -f "${src_path}")"
    real_name="$(basename "${real_src}")"   # e.g. libdbus-1.so.3.38.3

    local host_size
    host_size="$(stat -c%s "${real_src}")"

    for dir in "${DISK_GNU}" "${DISK_LIB64}"; do
        local dest_real="${dir}/${real_name}"
        local dest_soname="${dir}/${soname}"

        if [ -f "${dest_real}" ] && [ "${FORCE}" = false ]; then
            local existing_size
            existing_size="$(stat -c%s "${dest_real}" 2>/dev/null || echo 0)"
            if [ "${existing_size}" = "${host_size}" ]; then
                log "  SKIP (present): ${real_name} in $(basename "${dir}")/"
            else
                cp --preserve=timestamps "${real_src}" "${dest_real}"
                log "  Updated ${real_name} (was ${existing_size}, now ${host_size}) in $(basename "${dir}")/"
            fi
        else
            cp --preserve=timestamps "${real_src}" "${dest_real}"
            log "  Copied ${real_name} (${host_size} bytes) -> $(basename "${dir}")/"
        fi

        # Always (re)create the soname.  If install-firefox-stubs.sh dropped
        # a 36 KiB stub at the soname path we want to replace it with a
        # symlink to the real file — `ln -sf` over a regular file removes
        # the file and creates the symlink.
        if [ "${soname}" != "${real_name}" ]; then
            ln -sf "${real_name}" "${dest_soname}"
        fi
    done
}

# ── Mandatory library: libdbus-1.so.3 ────────────────────────────────────────
# Missing this is a hard failure — it is the whole point of this script.
MANDATORY=(
    libdbus-1.so.3
)

# ── Transitive deps required for libdbus-1 to dlopen-resolve ────────────────
# From `ldd /usr/lib/x86_64-linux-gnu/libdbus-1.so.3` on Ubuntu 24.04:
#   linux-vdso.so.1         (kernel-provided, skip)
#   libsystemd.so.0         (NEEDED — sd_journal_send / sd_listen_fds, unused
#                            in no-session-bus path but resolved at load time)
#   libc.so.6               (already provided by install-glibc.sh)
#   libm.so.6               (already provided by install-glibc.sh)
#   /lib64/ld-linux-x86-64.so.2 (already provided by install-glibc.sh)
#
# Only libsystemd is new; we treat it as mandatory because the dynamic
# linker refuses to load libdbus without it (DT_NEEDED is checked at load,
# not at first call).  libsystemd's own NEEDED entries are just libm + libc
# + ld-linux, all already on disk via install-glibc.sh — no further
# transitive chain to ship (libcap, liblzma, libzstd, libgcrypt are NOT
# pulled in by stock Ubuntu libsystemd.so.0 as of 24.04).
MANDATORY+=(
    libsystemd.so.0
)

# ── Install mandatory libs (fail hard on miss) ───────────────────────────────
log "Installing real libdbus-1 + libsystemd:"
for soname in "${MANDATORY[@]}"; do
    if src="$(find_lib "${soname}" 2>/dev/null)"; then
        copy_lib "${soname}" "${src}"
    else
        echo "[dbus-real] ERROR: mandatory library ${soname} not found on host."
        echo "             Install: sudo apt install libdbus-1-3 libsystemd0"
        exit 1
    fi
done

# ── Sanity-check libsystemd transitive chain ────────────────────────────────
# Defensive: if a future host pulls a libsystemd build with additional
# NEEDED entries (libcap, liblzma, libzstd, libgcrypt) we want a loud warning
# so the next build sees it before Firefox dlopens.  Use readelf to print
# the libsystemd DT_NEEDED list; anything beyond {libm.so.6, libc.so.6,
# ld-linux-x86-64.so.2} triggers a hint.
EXPECTED_SYSTEMD_NEEDED="libm.so.6 libc.so.6 ld-linux-x86-64.so.2"
if command -v readelf >/dev/null 2>&1; then
    systemd_path="$(find_lib libsystemd.so.0 2>/dev/null || true)"
    if [ -n "${systemd_path}" ]; then
        actual="$(readelf -d "${systemd_path}" 2>/dev/null \
                  | awk '/\(NEEDED\)/ { gsub(/[\[\]]/,"",$NF); print $NF }' \
                  | tr '\n' ' ' | sed 's/ $//')"
        for n in ${actual}; do
            case " ${EXPECTED_SYSTEMD_NEEDED} " in
                *" ${n} "*) ;;
                *)
                    log "  WARN: libsystemd.so.0 has unexpected NEEDED entry ${n}"
                    log "        — Firefox may dlopen-fail at runtime.  Audit"
                    log "        the host package or rebuild libdbus without"
                    log "        --enable-systemd."
                    ;;
            esac
        done
    fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo
log "Done.  Real libraries staged in:"
log "  ${DISK_LIB64}/"
log "  ${DISK_GNU}/"
log "Mandatory sizes:"
for soname in "${MANDATORY[@]}"; do
    f="${DISK_LIB64}/${soname}"
    if [ -L "${f}" ]; then
        target="$(readlink "${f}")"
        size="$(stat -L -c%s "${f}" 2>/dev/null || echo '?')"
        printf '  %-32s -> %-32s (%s bytes)\n' "${soname}" "${target}" "${size}"
    elif [ -f "${f}" ]; then
        size="$(stat -c%s "${f}")"
        printf '  %-32s (%s bytes)\n' "${soname}" "${size}"
    fi
done
