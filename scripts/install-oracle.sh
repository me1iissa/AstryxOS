#!/usr/bin/env bash
#
# install-oracle.sh — Stage an endpoint-agent binary into the AstryxOS
# data-disk staging tree.  This is the userspace half of the oracle-test
# cargo feature; the kernel half is `kernel/src/oracle_demo.rs`.
#
# The agent itself is a private artefact — this script does not bundle it.
# Supply the binary at staging time via one of:
#
#   ORACLE_BIN=/path/to/local/binary       bash scripts/install-oracle.sh
#   ORACLE_PACKAGE_URL=https://...         bash scripts/install-oracle.sh
#   ORACLE_PACKAGE_URL=...
#   ORACLE_PACKAGE_TOKEN=...               bash scripts/install-oracle.sh
#
# The cached copy at ~/.cache/astryxos-oracle/oracle is reused on subsequent
# runs unless --force is passed.  If neither ORACLE_BIN nor ORACLE_PACKAGE_URL
# is set and no cached copy exists, the script exits with a hint.
#
# What this script does
# ---------------------
#
#   1. Resolves the agent binary from $ORACLE_BIN, $ORACLE_PACKAGE_URL (with
#      optional $ORACLE_PACKAGE_TOKEN bearer/PRIVATE-TOKEN header), or the
#      cache.  Exits non-zero with a hint when none are available.
#   2. Verifies the binary is x86_64 ELF and prints DT_NEEDED so we know
#      which runtime libs must be present.  The bundled DT_NEEDED closure
#      walker (Phase 2) reads this and stages each transitive .so under
#      build/disk/lib/x86_64-linux-gnu/.
#   3. Stages the binary at build/disk/usr/bin/oracle.
#   4. Writes a minimum /etc/oracle/config.toml with network/system/hardware
#      collectors enabled and sync disabled.
#   5. Creates the runtime dirs (/var/lib/oracle, /var/log/oracle,
#      /etc/oracle).
#
# Idempotent — exits 0 cleanly if every artefact is staged.  Pass --force
# to re-download + re-stage even if cached.
#
# References (public)
#   - tokio Rust runtime:     https://tokio.rs/
#   - sd_notify(3):           https://www.freedesktop.org/software/systemd/man/sd_notify.html
#   - systemd.service(5):     https://www.freedesktop.org/software/systemd/man/systemd.service.html
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_USR_BIN="${DISK_DIR}/usr/bin"
DISK_ETC_ORACLE="${DISK_DIR}/etc/oracle"
DISK_VAR_LIB_ORACLE="${DISK_DIR}/var/lib/oracle"
DISK_VAR_LOG_ORACLE="${DISK_DIR}/var/log/oracle"
# The agent is glibc-linked, so its DT_NEEDED libs must come from the
# host's glibc track — NOT from install-tls-stack.sh which stages Alpine
# musl-linked versions (ABI-incompatible).  The host's OpenSSL 3 libs live
# in /lib/x86_64-linux-gnu/ (Debian/Ubuntu multiarch path) and stage into
# the canonical glibc-track location at build/disk/lib/x86_64-linux-gnu/
# alongside install-glibc.sh's output.
DISK_GLIBC_LIB="${DISK_DIR}/lib/x86_64-linux-gnu"

# Host-side persistent cache.  Separate from any Alpine rootfs because the
# binary is glibc-linked, not musl — it doesn't share a runtime with the
# sshd dropbear / openssl staging.
ORACLE_CACHE_DIR="${HOME}/.cache/astryxos-oracle"
ORACLE_BIN_CACHED="${ORACLE_CACHE_DIR}/oracle"

# Caller-supplied configuration — none of these have defaults.  The fetch
# logic below selects, in order:
#   1. $ORACLE_BIN              (local file path)
#   2. $ORACLE_PACKAGE_URL      (HTTPS endpoint, optionally with
#                                $ORACLE_PACKAGE_TOKEN for a private package)
#   3. $ORACLE_BIN_CACHED       (cache hit from a prior run)
ORACLE_BIN="${ORACLE_BIN:-}"
ORACLE_PACKAGE_URL="${ORACLE_PACKAGE_URL:-}"
ORACLE_PACKAGE_TOKEN="${ORACLE_PACKAGE_TOKEN:-}"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
    esac
done

# ── Step 1: locate (or fetch) the agent binary ───────────────────────────────
mkdir -p "${ORACLE_CACHE_DIR}"

if [ ! -f "${ORACLE_BIN_CACHED}" ] || [ "${FORCE}" = true ]; then
    if [ -n "${ORACLE_BIN}" ] && [ -f "${ORACLE_BIN}" ]; then
        cp -fL "${ORACLE_BIN}" "${ORACLE_BIN_CACHED}"
        chmod +x "${ORACLE_BIN_CACHED}"
        echo "[ORACLE] Cached local ORACLE_BIN -> ${ORACLE_BIN_CACHED}"
    elif [ -n "${ORACLE_PACKAGE_URL}" ]; then
        echo "[ORACLE] Fetching ORACLE_PACKAGE_URL ..."
        CURL_AUTH=()
        if [ -n "${ORACLE_PACKAGE_TOKEN}" ]; then
            # Support either bearer ("Bearer <tok>") or PRIVATE-TOKEN style;
            # pass both — endpoints ignore the one they don't honour.
            CURL_AUTH=(--header "PRIVATE-TOKEN: ${ORACLE_PACKAGE_TOKEN}"
                       --header "Authorization: Bearer ${ORACLE_PACKAGE_TOKEN}")
        fi
        if ! curl -sfL "${CURL_AUTH[@]}" \
                "${ORACLE_PACKAGE_URL}" -o "${ORACLE_BIN_CACHED}.tmp"; then
            echo "[ORACLE] ERROR: curl failed to fetch ORACLE_PACKAGE_URL"
            rm -f "${ORACLE_BIN_CACHED}.tmp"
            exit 1
        fi
        mv -f "${ORACLE_BIN_CACHED}.tmp" "${ORACLE_BIN_CACHED}"
        chmod +x "${ORACLE_BIN_CACHED}"
    else
        echo "[ORACLE] ERROR: no binary available."
        echo "[ORACLE]        Set ORACLE_BIN=/path/to/binary"
        echo "[ORACLE]        or  ORACLE_PACKAGE_URL=https://..."
        echo "[ORACLE]            ORACLE_PACKAGE_TOKEN=<tok>   (if private)"
        echo "[ORACLE]        or  stage a copy at ${ORACLE_BIN_CACHED}"
        exit 1
    fi
fi

# ── Step 2: verify ELF shape ─────────────────────────────────────────────────
if ! file "${ORACLE_BIN_CACHED}" | grep -q 'ELF 64-bit.*x86-64'; then
    echo "[ORACLE] ERROR: ${ORACLE_BIN_CACHED} is not an x86_64 ELF binary"
    file "${ORACLE_BIN_CACHED}"
    exit 1
fi

ORACLE_SIZE="$(stat -c%s "${ORACLE_BIN_CACHED}")"
echo "[ORACLE] Cached binary: ${ORACLE_BIN_CACHED} (${ORACLE_SIZE} bytes)"
echo "[ORACLE] DT_NEEDED entries:"
readelf -d "${ORACLE_BIN_CACHED}" 2>/dev/null \
    | awk -F'[][]' '/NEEDED/ {print "[ORACLE]   - "$2}'

# Print the highest GLIBC_x.y symbol version required.  If the host glibc
# staged by install-glibc.sh is older than this, the dynamic linker will
# fail with "version `GLIBC_x.y' not found" before main() runs.
MAX_GLIBC="$(objdump -p "${ORACLE_BIN_CACHED}" 2>/dev/null \
    | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' \
    | sort -uV | tail -1)"
echo "[ORACLE] Maximum GLIBC symbol version required: ${MAX_GLIBC:-<unknown>}"

# ── Step 3: stage at /usr/bin/oracle ─────────────────────────────────────────
mkdir -p "${DISK_USR_BIN}"
cp -fL "${ORACLE_BIN_CACHED}" "${DISK_USR_BIN}/oracle"
chmod +x "${DISK_USR_BIN}/oracle"
echo "[ORACLE] Staged /usr/bin/oracle (${ORACLE_SIZE} bytes)"

# ── Step 4: write /etc/oracle/config.toml ────────────────────────────────────
# First-boot config is deliberately minimal:
#   - sync.enabled = false       (offline-only first boot; no remote reachout)
#   - polling.interval_secs = 60 (one tick per minute; --once exits after one)
#   - logging.enable_platform_log = false  (no systemd journal on AstryxOS)
#   - logging.enable_file = false (avoid file-write gate on first boot;
#                                  we want stdout/stderr only so the kernel
#                                  pipe captures everything)
#   - polling.collectors.process.enabled = false (cross-PID procfs walk
#                                                 may not be fully fleshed)
#   - polling.collectors.security.enabled = false (file-integrity SHA over
#                                                  /etc/sshd_config etc.;
#                                                  files may not exist)
# Network + system + hardware collectors are kept on — those are the
# coverage paths the first-boot demo wants to exercise.
mkdir -p "${DISK_ETC_ORACLE}"
cat > "${DISK_ETC_ORACLE}/config.toml" <<'EOF'
# Oracle Endpoint Agent — AstryxOS first-boot config (PIVOT-I2, 2026-05-23).
# Deliberately minimal: sync disabled (no remote reachout), file logging
# disabled (stdout only), heavy collectors (process, security) disabled.
# The first-boot demo runs `oracle --mode console --once` which exits
# after a single observation cycle — this config keeps the cycle short
# enough that the kernel pipe doesn't fill before exit.
[service]
name = "oracle"
display_name = "Oracle Endpoint Agent"
description = "Oracle endpoint agent (AstryxOS first-boot)"

[host_metadata]
# environment, classification, tags omitted — defaults to host-derived

[polling]
interval_secs = 60
include_loopback = false
changes_only = false

[polling.collectors.network]
enabled = true

[polling.collectors.system]
enabled = true

[polling.collectors.hardware]
enabled = true

[polling.collectors.process]
# Cross-PID /proc/[pid]/* walk — disabled for first-boot until cross-PID
# procfs is verified.  Re-enable once /proc/<N>/cmdline coverage lands.
enabled = false

[polling.collectors.security]
# File-integrity SHA-256 over /etc/sshd_config, /etc/sudoers, /etc/shadow,
# /etc/passwd, /etc/group, /etc/pam.d/, ~root/.ssh/authorized_keys.
# Disabled because some of these may not exist on a fresh first boot.
enabled = false

[polling.collectors.connections]
enabled = false  # netlink-sock-diag — out of scope on AstryxOS

[polling.collectors.software]
enabled = false  # apt/dpkg/rpm enumeration — out of scope

[polling.collectors.performance]
enabled = false  # /proc/loadavg/etc — minor; out of scope for first-boot

[sync]
# Network egress is the long-term integration point but out of scope
# for the first-boot trial.  Enabled in the daemon-mode config below.
enabled = false

[logging]
enable_platform_log = false
enable_file = false
console_level = "info"
EOF
echo "[ORACLE] Staged /etc/oracle/config.toml"

# ── Step 4b: write /etc/oracle/daemon.toml (PIVOT-I2 Phase D, 2026-05-23) ────
# Daemon-mode config is used by the oracle-daemon-test cargo feature.
# Sync is ENABLED with a caller-supplied URL (default points at the
# loopback stub-Conflux on host port 8088 — set ORACLE_SYNC_URL to point
# at a different endpoint when staging for a real Conflux trial).  Use
# plain HTTP for the first-boot stub to bypass TLS until the kernel-side
# TLS substrate is verified end-to-end.
ORACLE_SYNC_URL_DEFAULT="http://10.0.2.2:8088/heartbeat"
ORACLE_SYNC_URL="${ORACLE_SYNC_URL:-${ORACLE_SYNC_URL_DEFAULT}}"
cat > "${DISK_ETC_ORACLE}/daemon.toml" <<EOF
# Oracle Endpoint Agent — AstryxOS daemon-mode config (Phase D, 2026-05-23).
# Used by the oracle-daemon-test cargo feature.  Sync ENABLED with caller-
# supplied URL (ORACLE_SYNC_URL env, default \${ORACLE_SYNC_URL_DEFAULT}).
[service]
name = "oracle"
display_name = "Oracle Endpoint Agent"
description = "Oracle endpoint agent (AstryxOS daemon mode)"

[host_metadata]

[polling]
interval_secs = 10
include_loopback = false
changes_only = false

[polling.collectors.network]
enabled = true

[polling.collectors.system]
enabled = true

[polling.collectors.hardware]
enabled = false  # skip DMI walk in daemon mode (cheaper polling cycle)

[polling.collectors.process]
enabled = false

[polling.collectors.security]
enabled = false

[polling.collectors.connections]
enabled = false

[polling.collectors.software]
enabled = false

[polling.collectors.performance]
enabled = false

[sync]
enabled = true
url = "${ORACLE_SYNC_URL}"
# Plain HTTP for first-boot stub validation — TLS engaged when the
# server URL has scheme https:// and the user-supplied CA bundle is
# staged via install-tls-stack.sh.
interval_secs = 30
timeout_secs = 10

[logging]
enable_platform_log = false
enable_file = false
console_level = "info"
EOF
echo "[ORACLE] Staged /etc/oracle/daemon.toml (sync url=${ORACLE_SYNC_URL})"

# ── Step 5: create runtime dirs ──────────────────────────────────────────────
mkdir -p "${DISK_VAR_LIB_ORACLE}" "${DISK_VAR_LOG_ORACLE}"
echo "[ORACLE] Created /var/lib/oracle and /var/log/oracle"

# ── Step 6: walk DT_NEEDED transitive closure (BFS) ──────────────────────────
# Glibc-linked oracle DT_NEEDS libssl/libcrypto/libgcc_s plus a transitive
# tail (libnghttp2, libidn2, libpsl, libzstd, libz, libbrotli*, libunistring,
# libcares, ...) that neither install-glibc.sh nor install-tls-stack.sh
# stages today.  The walker iterates each binary's NEEDED entries and copies
# anything new under build/disk/lib/x86_64-linux-gnu/ until the closure
# stabilises.  Skips base-glibc libs (libc, libm, libpthread, libdl, librt,
# libresolv, libutil, ld-linux-x86-64) which install-glibc.sh owns.
mkdir -p "${DISK_GLIBC_LIB}"

# Comma-separated list of NEEDED entries that install-glibc.sh stages.  We
# skip these in the walker to avoid double-staging and to keep the boundary
# clean between install-glibc.sh (base C runtime) and install-oracle.sh
# (oracle-specific transitive closure).
GLIBC_BASE_SKIP_RE='^(libc|libm|libpthread|libdl|librt|libresolv|libutil|ld-linux-x86-64)\.so'

declare -A VISITED=()
declare -A STAGED=()
QUEUE=("${DISK_USR_BIN}/oracle")
STAGED_COUNT=0
SKIPPED_COUNT=0

resolve_lib_path() {
    local soname="$1"
    # Try ldconfig first (fast path), then /usr/lib/x86_64-linux-gnu, then
    # /lib/x86_64-linux-gnu, then /lib64.
    local path
    path="$(ldconfig -p 2>/dev/null \
        | awk -v n="${soname}" '$1==n && $2 ~ /x86-64/ {print $NF; exit}')"
    if [ -z "${path}" ]; then
        for dir in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu /lib64 /usr/lib64; do
            if [ -f "${dir}/${soname}" ]; then
                path="${dir}/${soname}"
                break
            fi
        done
    fi
    echo "${path}"
}

stage_one_lib() {
    local soname="$1"
    local hostpath="$2"
    if [ -z "${hostpath}" ] || [ ! -f "${hostpath}" ]; then
        echo "[ORACLE] WARN: ${soname} not found on host (oracle may fail to load)"
        return 1
    fi
    # Resolve symlink to real file but stage BOTH the symlink (under the
    # SONAME) and the real file (under its versioned name) so the loader's
    # name lookup matches what DT_NEEDED says.
    local realpath
    realpath="$(readlink -f "${hostpath}")"
    local realname
    realname="$(basename "${realpath}")"
    cp -fL "${realpath}" "${DISK_GLIBC_LIB}/${realname}"
    if [ "${realname}" != "${soname}" ]; then
        ( cd "${DISK_GLIBC_LIB}" && ln -sf "${realname}" "${soname}" )
    fi
    local size
    size="$(stat -c%s "${DISK_GLIBC_LIB}/${realname}")"
    echo "[ORACLE]   staged ${soname} -> ${realname} (${size} bytes)"
    STAGED_COUNT=$((STAGED_COUNT + 1))
}

while [ "${#QUEUE[@]}" -gt 0 ]; do
    cur="${QUEUE[0]}"
    QUEUE=("${QUEUE[@]:1}")
    key="$(readlink -f "${cur}" 2>/dev/null || echo "${cur}")"
    [ -n "${VISITED[$key]:-}" ] && continue
    VISITED[$key]=1
    if [ ! -f "${cur}" ]; then continue; fi
    while IFS= read -r soname; do
        [ -z "${soname}" ] && continue
        if echo "${soname}" | grep -qE "${GLIBC_BASE_SKIP_RE}"; then
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            continue
        fi
        if [ -n "${STAGED[$soname]:-}" ]; then continue; fi
        STAGED[$soname]=1
        hostpath="$(resolve_lib_path "${soname}")"
        stage_one_lib "${soname}" "${hostpath}" || true
        if [ -n "${hostpath}" ]; then
            QUEUE+=("${hostpath}")
        fi
    done < <(readelf -d "${cur}" 2>/dev/null \
                | awk -F'[][]' '/NEEDED/ {print $2}')
done

echo "[ORACLE] DT_NEEDED closure: ${STAGED_COUNT} libs staged, ${SKIPPED_COUNT} base-glibc skipped"
echo "[ORACLE] Done."
