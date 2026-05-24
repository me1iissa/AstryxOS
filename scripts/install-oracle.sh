#!/usr/bin/env bash
#
# install-oracle.sh — Stage the Oracle endpoint agent (infrasvc) binary and
# its config files into the AstryxOS data-disk staging tree.  This is the
# userspace half of the oracle first-boot demo (PIVOT-I2, 2026-05-23);
# the kernel half is the `oracle-test` cargo feature.
#
# What is oracle?
# ---------------
# Oracle is a Rust+tokio observability agent from the user's internal
# infrastructure-services/infrasvc GitLab project.  It polls /sys, /proc,
# DMI, and ships heartbeats to the Conflux endpoint.  See
# docs/INFRASVC_ORACLE_AUDIT_2026-05-23.md for the full audit + roadmap.
#
# First-boot scope
# ----------------
# This install stages the production GLIBC-linked binary (from the
# infrasvc release at /api/v4/projects/24/packages/generic/infrasvc/...).
# The kernel-side `oracle-test` cargo feature launches it with
# `oracle --mode console --once` so it runs a single observation cycle
# and exits, surfacing whichever syscall/file gate fires first.  We
# explicitly DISABLE sync (sync.enabled=false in /etc/oracle/config.toml)
# so the agent does not attempt to reach Conflux — the first-boot goal
# is observation surface coverage, not C2 connectivity.
#
# What this script does
# ---------------------
#
#   1. Looks for a cached copy of the oracle binary at
#      ~/.cache/astryxos-oracle/oracle.  If absent, attempts to fetch the
#      latest release from the GitLab generic-package endpoint using the
#      `glab` CLI token (private project — requires auth).  If the fetch
#      fails the script exits non-zero with a hint.
#   2. Verifies the binary is x86_64 ELF and prints DT_NEEDED so we know
#      which runtime libs must be present.  Oracle is glibc-linked
#      (DT_NEEDED libc.so.6, libssl.so.3, libcrypto.so.3, etc.) so it
#      will pull from the glibc track staged by install-glibc.sh — NOT
#      the musl track used by sshd/dropbear.
#   3. Stages oracle at build/disk/usr/bin/oracle.
#   4. Writes a minimum /etc/oracle/config.toml with sync disabled so
#      the agent does an offline-only first-boot.
#   5. Creates the runtime dirs (/var/lib/oracle, /var/log/oracle,
#      /etc/oracle) that systemd's ExecStartPre=install -d would
#      ordinarily create.
#
# Idempotent — exits 0 cleanly if every artefact is staged.  Pass --force
# to re-download + re-stage even if cached.
#
# References (public)
#   - tokio Rust runtime:     https://tokio.rs/
#   - sd_notify(3):           https://www.freedesktop.org/software/systemd/man/sd_notify.html
#   - systemd.service(5):     https://www.freedesktop.org/software/systemd/man/systemd.service.html
#   - GitLab packages API:    https://docs.gitlab.com/ee/api/packages.html
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_USR_BIN="${DISK_DIR}/usr/bin"
DISK_ETC_ORACLE="${DISK_DIR}/etc/oracle"
DISK_VAR_LIB_ORACLE="${DISK_DIR}/var/lib/oracle"
DISK_VAR_LOG_ORACLE="${DISK_DIR}/var/log/oracle"
# Oracle is GLIBC-linked, so libssl3/libcrypto3 must come from the host's
# glibc track — NOT from install-tls-stack.sh which stages the Alpine
# musl-linked versions (incompatible for a glibc binary).  The host's
# OpenSSL 3 libs live in /lib/x86_64-linux-gnu/ (Debian/Ubuntu multiarch
# path) and stage into the canonical glibc-track location at
# build/disk/lib/x86_64-linux-gnu/ alongside install-glibc.sh's output.
DISK_GLIBC_LIB="${DISK_DIR}/lib/x86_64-linux-gnu"

# Host-side persistent cache.  Separate from any Alpine rootfs because
# oracle is glibc-linked, not musl — it doesn't share a runtime with the
# sshd dropbear / openssl staging.
ORACLE_CACHE_DIR="${HOME}/.cache/astryxos-oracle"
ORACLE_BIN_CACHED="${ORACLE_CACHE_DIR}/oracle"

# GitLab package endpoint.  Project 24 = infrastructure-services/infrasvc.
# The release tag is the abbreviated commit SHA; release 7b03aa65 ships
# the v0.x oracle build with HttpSync wired (matches the audit's pinned
# version).  Bump the tag here when chasing a newer release; the kernel-
# side feature gate doesn't care which version.
GITLAB_HOST="svn.hyperlxc.co.uk"
GITLAB_PROJECT_ID="24"
ORACLE_RELEASE_TAG="7b03aa65"
ORACLE_PACKAGE_URL="https://${GITLAB_HOST}/api/v4/projects/${GITLAB_PROJECT_ID}/packages/generic/infrasvc/${ORACLE_RELEASE_TAG}/infrasvc-amd64"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help)
            sed -n '2,60p' "$0"
            exit 0
            ;;
    esac
done

# ── Step 1: locate (or fetch) the oracle binary ──────────────────────────────
mkdir -p "${ORACLE_CACHE_DIR}"

if [ ! -f "${ORACLE_BIN_CACHED}" ] || [ "${FORCE}" = true ]; then
    echo "[ORACLE] Fetching ${ORACLE_PACKAGE_URL} ..."
    # Use the glab-cli config token rather than asking the operator for one.
    GLAB_CFG="${HOME}/.config/glab-cli/config.yml"
    if [ ! -r "${GLAB_CFG}" ]; then
        echo "[ORACLE] ERROR: glab not configured at ${GLAB_CFG}; cannot fetch private package."
        echo "[ORACLE]        Run 'glab auth login --hostname ${GITLAB_HOST}' first, or stage"
        echo "[ORACLE]        the binary manually at ${ORACLE_BIN_CACHED}."
        exit 1
    fi
    # The yaml has lines like 'token: glpat-xxx'; pick the first one under
    # the svn.hyperlxc.co.uk: stanza.  Defensive: don't print the token.
    TOKEN="$(awk "/${GITLAB_HOST}:/,0" "${GLAB_CFG}" | grep -E '^\s*token:' | head -1 | awk '{print $2}')"
    if [ -z "${TOKEN}" ]; then
        echo "[ORACLE] ERROR: no token found in ${GLAB_CFG} under host ${GITLAB_HOST}"
        exit 1
    fi
    if ! curl -sfL --header "PRIVATE-TOKEN: ${TOKEN}" \
            "${ORACLE_PACKAGE_URL}" -o "${ORACLE_BIN_CACHED}.tmp"; then
        echo "[ORACLE] ERROR: curl failed to fetch ${ORACLE_PACKAGE_URL}"
        rm -f "${ORACLE_BIN_CACHED}.tmp"
        exit 1
    fi
    mv -f "${ORACLE_BIN_CACHED}.tmp" "${ORACLE_BIN_CACHED}"
    chmod +x "${ORACLE_BIN_CACHED}"
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
#   - sync.enabled = false       (no Conflux reachout — offline-only first boot)
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
# Deliberately minimal: sync disabled (no Conflux reachout), file logging
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

[logging]
level = "info"
enable_file = false
enable_platform_log = false

[sync]
# Disabled for first-boot: we are NOT attempting Conflux reachout on the
# first AstryxOS boot.  Once the substrate is proven, flip to true +
# point at a reachable Conflux dev-server.
enabled = false

[patching]
enforcement_enabled = false
refresh_interval_hours = 24
EOF
echo "[ORACLE] Wrote /etc/oracle/config.toml (sync disabled, process+security collectors off)"

# ── Step 4a: write /etc/oracle/daemon.toml (PIVOT-I2 Phase D, 2026-05-23) ────
# Companion config used by --features oracle-daemon-test (kernel-side launcher
# is `oracle_demo::run_oracle_daemon`).  Differs from the first-boot config
# in three places:
#
#   - [sync] enabled = true + server_url points at the QEMU SLIRP host
#     alias 10.0.2.2:8088 where `scripts/oracle-stub-conflux.py` listens
#     (plain HTTP, no TLS — defers I1 work per audit §7).
#   - [polling] interval_secs = 10 so heartbeats fire ~every 10 s instead
#     of every 60 s, keeping the demo soak short.
#   - [polling] changes_only = false so every poll iteration triggers a
#     heartbeat, even when nothing on the host changed.  The first-boot
#     config uses changes_only=false too; explicit here for emphasis.
#
# This config exists IN PARALLEL with config.toml; the kernel-side launcher
# selects which file to use via the `--config /etc/oracle/<file>` CLI flag,
# so the existing --once first-boot flow remains untouched.
cat > "${DISK_ETC_ORACLE}/daemon.toml" <<'EOF'
# Oracle Endpoint Agent — AstryxOS daemon-mode config (PIVOT-I2 Phase D, 2026-05-23).
# Companion to /etc/oracle/config.toml; selected by the kernel-side
# oracle_demo::run_oracle_daemon launcher via `--config /etc/oracle/daemon.toml`.
# Enables sync to the host-side stub Conflux on 10.0.2.2:8088 (the QEMU SLIRP
# gateway alias).  Per audit §7 ("Minimum viable demo — defer I1 path"):
# plain HTTP, no TLS substrate dependency.
[service]
name = "oracle"
display_name = "Oracle Endpoint Agent"
description = "Oracle endpoint agent (AstryxOS daemon-mode demo)"

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
enabled = true

[polling.collectors.process]
enabled = false

[polling.collectors.security]
enabled = false

[logging]
level = "info"
enable_file = false
enable_platform_log = false

[sync]
# Enabled for the daemon-mode demo.  Target is the QEMU SLIRP gateway
# alias 10.0.2.2 where `scripts/oracle-stub-conflux.py` listens on port
# 8088 (plain HTTP, no TLS — defers I1 ca-certificates work).
#
# server_url is the BASE URL — oracle's infrasvc::sync::HttpSync appends
# the canonical Conflux v1 path `/v1/hosts/<hostname>/heartbeat` itself,
# so this URL must NOT carry a `/heartbeat` (or any other) trailing path.
# The stub `scripts/oracle-stub-conflux.py` accepts both the canonical
# `/v1/hosts/<hostname>/heartbeat` shape and the legacy `/heartbeat`
# fallback — see its do_POST router for the full match.
enabled = true
server_url = "http://10.0.2.2:8088"
interval_secs = 10

[patching]
enforcement_enabled = false
refresh_interval_hours = 24
EOF
echo "[ORACLE] Wrote /etc/oracle/daemon.toml (sync enabled → 10.0.2.2:8088, 10s heartbeat)"

# ── Step 4b: walk oracle's DT_NEEDED transitive closure ──────────────────────
# Oracle's *direct* DT_NEEDED is just libssl.so.3, libcrypto.so.3, libgcc_s.so.1,
# libm.so.6, libc.so.6 — but libcrypto.so.3 itself pulls in libz.so.1 and
# libzstd.so.1, neither of which are staged by install-glibc.sh (which only
# stages base glibc) or by install-tls-stack.sh (Alpine-musl — incompatible
# with a glibc binary).  Without those transitive libs, ld-linux exits with
# "libzstd.so.1: cannot open shared object file" before any oracle code runs.
#
# We therefore walk the closure with a BFS over `readelf -d ... | grep NEEDED`,
# resolving each library via `ldconfig -p` or a fixed search-dir list, and
# staging every reachable .so into ${DISK_GLIBC_LIB} (the canonical Debian
# multiarch path, which `create-data-disk.sh` mcopies into data.img at
# /lib/x86_64-linux-gnu/).  Per the ELF gABI (System V ABI §5.4) and ld.so(8)
# the dynamic linker searches DT_RPATH/DT_RUNPATH then LD_LIBRARY_PATH then
# /etc/ld.so.cache then default paths (/lib, /usr/lib); our staging covers the
# default-path branch which is what oracle and its DT_NEEDED chain rely on
# (oracle has no DT_RPATH/DT_RUNPATH per readelf -d).
#
# FAT32 has no symlinks, so we stage every reachable name as a *real file*
# (cp -L dereferences host symlinks).  When a host symlink resolves to a
# differently-named file (libzstd.so.1 -> libzstd.so.1.5.7), we stage BOTH
# names so DT_NEEDED resolution (which looks for libzstd.so.1) AND any
# runtime dlopen of the versioned name both succeed.
#
# Skip-list: base glibc libs (libc, libm, libpthread, libdl, librt, libresolv,
# ld-linux) are already staged by install-glibc.sh under their host-versioned
# real names (e.g. libc.so.6 -> libc.so.6).  We re-check via the staged tree;
# if install-glibc.sh has run, we let those win.  Otherwise we stage them too,
# which is harmless.
declare -A STAGED_SOS
SKIP_BASE_SET="libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libresolv.so.2 ld-linux-x86-64.so.2 ld-linux.so.2"

# Resolve a SONAME (e.g. libzstd.so.1) to an absolute host path.  Prefer
# ldconfig -p (authoritative on the host) then fall back to a fixed search
# list for environments where ldconfig is unavailable or stale.
resolve_soname() {
    local soname="$1"
    local p
    if command -v ldconfig >/dev/null 2>&1; then
        p="$(ldconfig -p 2>/dev/null | awk -v n="${soname}" '$1==n {print $NF; exit}')"
        [ -n "${p}" ] && [ -e "${p}" ] && { echo "${p}"; return 0; }
    fi
    for src_dir in /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib64 /usr/lib64 /lib /usr/lib; do
        if [ -e "${src_dir}/${soname}" ]; then
            echo "${src_dir}/${soname}"; return 0
        fi
    done
    return 1
}

# Stage one resolved .so under both its SONAME and its real (versioned) name.
# Marks both names in STAGED_SOS so subsequent BFS iterations don't redo work.
stage_one_so() {
    local soname="$1"
    local src_path="$2"
    local real_path real_name
    real_path="$(readlink -f "${src_path}")"
    real_name="$(basename "${real_path}")"
    cp -fL "${real_path}" "${DISK_GLIBC_LIB}/${soname}"
    if [ "${soname}" != "${real_name}" ]; then
        cp -fL "${real_path}" "${DISK_GLIBC_LIB}/${real_name}"
    fi
    STAGED_SOS["${soname}"]=1
    STAGED_SOS["${real_name}"]=1
    echo "[ORACLE]   staged ${soname}$([ "${soname}" != "${real_name}" ] && echo " (+${real_name})") ($(stat -c%s "${DISK_GLIBC_LIB}/${soname}") bytes, src=${src_path})"
}

# BFS over DT_NEEDED, rooted at the oracle ELF.  Queue holds absolute paths;
# we extract DT_NEEDED of each, resolve to host paths, enqueue + stage.
walk_dt_needed_closure() {
    local root="$1"
    local -a queue=("${root}")
    local -A visited
    visited["$(readlink -f "${root}")"]=1
    local total=0 skipped=0 missing=0
    while [ ${#queue[@]} -gt 0 ]; do
        local cur="${queue[0]}"
        queue=("${queue[@]:1}")
        while IFS= read -r dep; do
            [ -z "${dep}" ] && continue
            # Skip base glibc — owned by install-glibc.sh
            if printf '%s' "${SKIP_BASE_SET}" | tr ' ' '\n' | grep -qFx "${dep}"; then
                skipped=$((skipped + 1)); continue
            fi
            [ -n "${STAGED_SOS[${dep}]:-}" ] && continue
            local resolved
            if ! resolved="$(resolve_soname "${dep}")"; then
                echo "[ORACLE]   MISSING dep: ${dep} (no host copy located)"
                missing=$((missing + 1))
                STAGED_SOS["${dep}"]=1   # don't re-warn
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
    echo "[ORACLE] DT_NEEDED closure: ${total} staged, ${skipped} skipped (base glibc), ${missing} missing"
}

mkdir -p "${DISK_GLIBC_LIB}"
echo "[ORACLE] Walking DT_NEEDED transitive closure rooted at ${ORACLE_BIN_CACHED}"
walk_dt_needed_closure "${ORACLE_BIN_CACHED}"

# Sanity: libssl/libcrypto + libzstd (the known transitive that wedged
# oracle pre-walker) must be present after the walk.
for required in libssl.so.3 libcrypto.so.3 libzstd.so.1 libz.so.1; do
    if [ ! -f "${DISK_GLIBC_LIB}/${required}" ]; then
        echo "[ORACLE] WARNING: closure walk did not stage ${required} —"
        echo "[ORACLE]          install with 'sudo apt install libssl3 libzstd1 zlib1g' before re-running."
    fi
done

# ── Step 5: create runtime dirs ──────────────────────────────────────────────
# systemd's oracle.service uses ExecStartPre=install -d /var/lib/oracle
# /var/log/oracle.  Mirror that here so the agent's logging.enable_file
# code-path (when re-enabled) finds the directory present.
mkdir -p "${DISK_VAR_LIB_ORACLE}" "${DISK_VAR_LOG_ORACLE}"
echo "[ORACLE] Created /var/lib/oracle and /var/log/oracle"

# ── Summary ──────────────────────────────────────────────────────────────────
echo "[ORACLE] Done.  Summary:"
echo "[ORACLE]   - /usr/bin/oracle             (${ORACLE_SIZE} bytes)"
echo "[ORACLE]   - /etc/oracle/config.toml     (first-boot config)"
echo "[ORACLE]   - /var/lib/oracle/            (runtime state dir)"
echo "[ORACLE]   - /var/log/oracle/            (log dir)"
echo "[ORACLE]"
echo "[ORACLE] glibc DT_NEEDED — install-glibc.sh must have staged libc + libssl."
echo "[ORACLE] Re-run scripts/create-data-disk.sh --oracle --force to refresh data.img."
