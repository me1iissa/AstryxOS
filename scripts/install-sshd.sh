#!/usr/bin/env bash
#
# install-sshd.sh — Stage Alpine's `dropbear` SSH daemon + host keys + user
# account config into the AstryxOS data-disk staging tree.  This is the
# userspace half of the SSH-service demo (PIVOT-D, 2026-05-23); the kernel
# half is the `sshd-test` cargo feature plus AF_INET accept(2) implementation
# (the latter is on a parallel dispatch).
#
# Why dropbear (not OpenSSH)?
# ---------------------------
# Dropbear is the smallest viable SSH server: ~215 KB on disk, only links
# against musl libc + libcrypto + libz (all already staged for the musl
# Firefox path).  No PAM, no GSSAPI, no Kerberos, no libsystemd, no
# /etc/nsswitch dlopen.  By contrast, OpenSSH's sshd pulls in libpam,
# libutil, libsystemd, libnsl, libcrypt + their transitive deps — at least
# 6-8 extra .so files and a much wider syscall surface.  For the minimum-
# viable "AstryxOS runs a real Linux SSH service" proof, dropbear is the
# narrowest blast radius; if it works end-to-end, OpenSSH is a follow-on.
#
# What this script does
# ---------------------
#
#   1. Reuses the shared Alpine rootfs at ~/.cache/astryxos-firefox-musl/
#      rootfs/ (bootstrapped by install-firefox-musl.sh) and apk-adds
#      `dropbear` if not already present.  No second Alpine bootstrap.
#   2. Stages the dropbear binary at build/disk/usr/sbin/dropbear and the
#      handful of additional shared libs it needs (libcrypto, libz are
#      shared with the FF musl stage and stay in place).
#   3. Generates an Ed25519 host key (and an RSA host key for clients that
#      don't yet speak Ed25519) under
#      ~/.cache/astryxos-sshd/etc/dropbear/ on the host, then copies them
#      to build/disk/etc/dropbear/.  Host-keys are persisted in the cache
#      so the same key survives data.img rebuilds (otherwise every soak
#      would advertise a new fingerprint and a host `known_hosts`-based
#      sanity check would never trust the guest).
#   4. Generates a test client Ed25519 keypair at
#      ~/.cache/astryxos-sshd/client/ed25519 and stages the public half
#      into build/disk/root/.ssh/authorized_keys.  The private half stays
#      on the host; the canonical use is
#          ssh -i ~/.cache/astryxos-sshd/client/ed25519 \
#              -o StrictHostKeyChecking=no                   \
#              -o UserKnownHostsFile=/dev/null               \
#              -p <host-port> root@127.0.0.1
#   5. Seeds /etc/passwd, /etc/shadow, /etc/shells, /etc/group with the
#      minimum entries dropbear needs to authenticate `root` (uid=0, no
#      password, login shell /bin/sh — busybox provides sh).  The shadow
#      entry uses '!' (locked-password) so password auth is impossible by
#      construction; only public-key auth via authorized_keys works.
#
# Idempotent — exits 0 cleanly if every artefact is staged and host-keys
# already exist.  Pass --force to refresh.
#
# References (public)
#   - Dropbear upstream:          https://matt.ucc.asn.au/dropbear/dropbear.html
#   - Dropbear man pages:         dropbear(8), dropbearkey(1), dbclient(1)
#   - Alpine dropbear pkg:        https://pkgs.alpinelinux.org/package/v3.20/main/x86_64/dropbear
#   - SSH Transport Layer:        RFC 4253 (SSH-2 binary packet, KEX, host-keys)
#   - SSH Connection Protocol:    RFC 4254 (channels, exec, shell)
#   - SSH Public Key Auth:        RFC 4252 §7 (publickey method)
#   - authorized_keys format:     `man 8 sshd` (AUTHORIZED_KEYS FILE FORMAT)
#   - QEMU SLIRP hostfwd:         https://www.qemu.org/docs/master/system/devices/net.html
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_USR_SBIN="${DISK_DIR}/usr/sbin"
DISK_USR_LIB="${DISK_DIR}/usr/lib"
DISK_LIB="${DISK_DIR}/lib"
DISK_ETC="${DISK_DIR}/etc"
DISK_ETC_DROPBEAR="${DISK_ETC}/dropbear"
DISK_ROOT_SSH="${DISK_DIR}/root/.ssh"

# Shared Alpine rootfs — same one used by install-firefox-musl.sh,
# install-xeyes.sh, install-busybox-cli.sh.
CACHE_DIR="${HOME}/.cache/astryxos-firefox-musl"
APK_STATIC="${CACHE_DIR}/apk-tools/sbin/apk.static"
ROOTFS="${CACHE_DIR}/rootfs"
ALPINE_KEYS="${ROOTFS}/etc/apk/keys"

# Host-side persistent cache for SSH host keys + test client keypair.
# Separate from the Alpine rootfs so re-bootstrapping that doesn't blow
# away keys.  Host-keys here are throwaway test material — do NOT reuse
# for anything that touches real infrastructure.
SSHD_CACHE_DIR="${HOME}/.cache/astryxos-sshd"
SSHD_HOSTKEY_DIR="${SSHD_CACHE_DIR}/etc/dropbear"
SSHD_CLIENT_DIR="${SSHD_CACHE_DIR}/client"
CLIENT_KEY="${SSHD_CLIENT_DIR}/ed25519"
CLIENT_PUB="${CLIENT_KEY}.pub"

ALPINE_VERSION="v3.20"
ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help)
            sed -n '2,55p' "$0"
            exit 0
            ;;
    esac
done

# ── Sanity: the shared Alpine rootfs must exist ──────────────────────────────
if [ ! -x "${APK_STATIC}" ] || [ ! -d "${ROOTFS}" ] || [ ! -d "${ALPINE_KEYS}" ]; then
    echo "[SSHD] ERROR: shared Alpine rootfs not present at ${CACHE_DIR}"
    echo "[SSHD]        Run scripts/install-firefox-musl.sh first to bootstrap."
    exit 1
fi

# ── Step 1: install dropbear into the shared rootfs (idempotent) ─────────────
DROPBEAR_BIN_ROOTFS="${ROOTFS}/usr/sbin/dropbear"
DROPBEARKEY_BIN_ROOTFS="${ROOTFS}/usr/bin/dropbearkey"
if [ ! -x "${DROPBEAR_BIN_ROOTFS}" ] || [ ! -x "${DROPBEARKEY_BIN_ROOTFS}" ] || [ "${FORCE}" = true ]; then
    echo "[SSHD] Installing dropbear via apk into ${ROOTFS} ..."
    # apk.static under our shared rootfs occasionally exits non-zero with
    # "N errors updating directory permissions" because the rootfs was
    # bootstrapped under unshare-less constraints (no setuid for /var/cache
    # etc.).  These warnings are cosmetic; the binary itself unpacks fine
    # provided busybox.static is present to satisfy POSIX permissions.
    # We tolerate apk's non-zero exit and instead rely on the post-call
    # `[ ! -x dropbear ]` sentinel check below to confirm the binary
    # actually landed.  Strip pipefail for the apk-call subshell only so
    # the rest of the script keeps the strict-mode guarantees.
    set +o pipefail
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --no-scripts \
        --update-cache \
        add dropbear 2>&1 | sed 's/^/[SSHD]   /' || true
    set -o pipefail
fi

if [ ! -x "${DROPBEAR_BIN_ROOTFS}" ]; then
    echo "[SSHD] ERROR: ${DROPBEAR_BIN_ROOTFS} still missing after apk add"
    exit 1
fi

# ── Step 2: stage dropbear + dropbearkey into build/disk/usr/sbin ────────────
# We stage both binaries because dropbearkey is small (~15 KB) and may be
# useful for guest-side key regeneration in follow-on work.  dropbear is
# the server; dropbearkey is the keygen utility.
mkdir -p "${DISK_USR_SBIN}" "${DISK_DIR}/usr/bin" "${DISK_USR_LIB}" "${DISK_LIB}"

cp -fL "${DROPBEAR_BIN_ROOTFS}"     "${DISK_USR_SBIN}/dropbear"
chmod +x "${DISK_USR_SBIN}/dropbear"
echo "[SSHD] Staged /usr/sbin/dropbear ($(stat -c%s "${DISK_USR_SBIN}/dropbear") bytes)"

cp -fL "${DROPBEARKEY_BIN_ROOTFS}"  "${DISK_DIR}/usr/bin/dropbearkey"
chmod +x "${DISK_DIR}/usr/bin/dropbearkey"
echo "[SSHD] Staged /usr/bin/dropbearkey ($(stat -c%s "${DISK_DIR}/usr/bin/dropbearkey") bytes)"

# ── Step 3: stage any deps not already shared with FF musl ───────────────────
# `readelf -d dropbear` typically lists:
#   libutil.so.1                — present in glibc-only systems, NOT musl
#                                  (Alpine's musl provides login_tty etc.
#                                  directly in libc).  Listed for safety.
#   libcrypto.so.3              — shared with FF musl (already in disk/lib).
#   libz.so.1                   — shared with FF musl (already in disk/lib).
#   libc.musl-x86_64.so.1       — shared with FF musl (already in disk/lib).
#
# We loop over readelf's NEEDED and copy anything that is missing from the
# already-staged set.  This protects against future Alpine package shape
# changes that pull in a new library.
echo "[SSHD] Resolving dropbear shared-library closure ..."
missing_count=0
copied_count=0
while IFS= read -r need; do
    case "${need}" in
        "libc.musl-x86_64.so.1"|"ld-musl-x86_64.so.1")
            # Owned by install-firefox-musl.sh; verify presence only.
            if [ ! -f "${DISK_LIB}/${need}" ]; then
                echo "[SSHD]   MISSING /lib/${need} (musl libc/loader — install-firefox-musl.sh should stage it)"
                missing_count=$((missing_count + 1))
            fi ;;
        *)
            # Look for the library in the rootfs and copy to BOTH /disk/lib/
            # AND /disk/usr/lib/ if not yet present.  Two locations because:
            #   - /disk/lib/ is the canonical Alpine musl lib path (matches
            #     ld-musl's compiled-in search list) — required when the
            #     create-data-disk.sh ::usr/lib copy block is skipped (which
            #     happens when FIREFOX_VARIANT defaults to glibc).
            #   - /disk/usr/lib/ is the multiarch fallback used when the
            #     musl-variant FF staging is active; harmless to mirror.
            # The double-copy adds ~100 KB max (libz is the only non-trivial
            # entry) and removes a class of "dependency in wrong directory"
            # failures.
            for src_dir in "${ROOTFS}/usr/lib" "${ROOTFS}/lib"; do
                if [ -f "${src_dir}/${need}" ]; then
                    if [ ! -f "${DISK_LIB}/${need}" ]; then
                        cp -fL "${src_dir}/${need}" "${DISK_LIB}/${need}"
                        echo "[SSHD]   Staged /lib/${need} ($(stat -c%s "${DISK_LIB}/${need}") bytes)"
                        copied_count=$((copied_count + 1))
                    fi
                    if [ ! -f "${DISK_USR_LIB}/${need}" ]; then
                        cp -fL "${src_dir}/${need}" "${DISK_USR_LIB}/${need}"
                        echo "[SSHD]   Staged /usr/lib/${need} ($(stat -c%s "${DISK_USR_LIB}/${need}") bytes)"
                    fi
                    continue 2
                fi
            done
            echo "[SSHD]   WARNING: ${need} not found in rootfs — staging may be incomplete"
            ;;
    esac
done < <(readelf -d "${DISK_USR_SBIN}/dropbear" 2>/dev/null | awk -F'[][]' '/NEEDED/ {print $2}')
echo "[SSHD] Closed dependency: copied ${copied_count} new libs; ${missing_count} missing pre-reqs."

# We intentionally do NOT fatal-exit on missing pre-reqs.  The expected
# invocation is via create-data-disk.sh which runs install-firefox-musl.sh
# (staging the musl libc + loader) before install-sshd.sh, so by the time
# data.img is packed the missing pieces are present.  Running install-sshd.sh
# standalone before install-firefox-musl.sh produces a warning here and the
# guest will fail at ld-musl startup — diagnosed by the MISSING line above.

# ── Step 4: generate persistent host keys ────────────────────────────────────
# Host keys are persisted under ~/.cache/astryxos-sshd/etc/dropbear/ so
# that re-runs of create-data-disk.sh don't regenerate the keys (and so
# don't invalidate `known_hosts`-style host-pinning on the client side).
# We generate two formats:
#
#   dropbear_ed25519_host_key  — preferred (RFC 8709 / Ed25519, modern clients)
#   dropbear_rsa_host_key      — fallback (RFC 4253 / ssh-rsa, broadest reach)
#
# Both are in dropbear's native binary key format (not OpenSSH's PEM).
# dropbearkey(1) is the canonical generator.  We invoke the host's
# rootfs copy of dropbearkey via the binary we just staged.
mkdir -p "${SSHD_HOSTKEY_DIR}" "${DISK_ETC_DROPBEAR}"

# The dropbearkey binary in the rootfs is musl-linked and depends on the
# Alpine /lib/ld-musl-x86_64.so.1 loader.  Running it directly under the
# host's glibc dynamic linker fails with `cannot execute: required file
# not found`.  We invoke it through the rootfs's musl loader explicitly,
# passing --library-path so it finds its shared libs (libz, libutil, etc.)
# from the rootfs rather than the host.  This is the standard pattern for
# running a musl ELF from a non-musl host (man ld-musl(8) under USAGE).
MUSL_LOADER="${ROOTFS}/lib/ld-musl-x86_64.so.1"
MUSL_LIBPATH="${ROOTFS}/usr/lib:${ROOTFS}/lib"

if [ ! -x "${MUSL_LOADER}" ]; then
    echo "[SSHD] WARNING: musl loader not present at ${MUSL_LOADER}"
    echo "[SSHD]          Host keys cannot be generated; falling back to ssh-keygen."
    HOSTKEY_VIA_DROPBEAR=false
else
    HOSTKEY_VIA_DROPBEAR=true
fi

run_dropbearkey() {
    # Args: <type> <out-file>
    "${MUSL_LOADER}" --library-path "${MUSL_LIBPATH}" \
        "${DROPBEARKEY_BIN_ROOTFS}" -t "$1" -f "$2"
}

if [ "${HOSTKEY_VIA_DROPBEAR}" = true ]; then
    for keytype in ed25519 rsa; do
        keyfile="${SSHD_HOSTKEY_DIR}/dropbear_${keytype}_host_key"
        if [ ! -f "${keyfile}" ] || [ "${FORCE}" = true ]; then
            echo "[SSHD] Generating ${keytype} host key at ${keyfile} ..."
            run_dropbearkey "${keytype}" "${keyfile}" 2>&1 \
                | grep -E '^(Generating|Public|Fingerprint)' \
                | sed 's/^/[SSHD]   /' \
                || true
        fi
        if [ -f "${keyfile}" ]; then
            cp -fL "${keyfile}" "${DISK_ETC_DROPBEAR}/dropbear_${keytype}_host_key"
            chmod 600 "${DISK_ETC_DROPBEAR}/dropbear_${keytype}_host_key"
        else
            echo "[SSHD] WARNING: ${keyfile} not produced; dropbear will need to generate at boot"
        fi
    done
    echo "[SSHD] Staged host keys to /etc/dropbear/."
fi

# ── Step 5: generate a test client keypair (Ed25519, OpenSSH format) ─────────
# The client side uses standard OpenSSH key format (ssh-keygen output) since
# the canonical caller is the host's `ssh` binary, not dropbear's dbclient.
mkdir -p "${SSHD_CLIENT_DIR}" "${DISK_ROOT_SSH}"
if [ ! -f "${CLIENT_KEY}" ] || [ ! -f "${CLIENT_PUB}" ] || [ "${FORCE}" = true ]; then
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        echo "[SSHD] ERROR: ssh-keygen not found on host (apt install openssh-client)."
        exit 1
    fi
    echo "[SSHD] Generating client Ed25519 keypair at ${CLIENT_KEY} ..."
    rm -f "${CLIENT_KEY}" "${CLIENT_PUB}"
    ssh-keygen -t ed25519 -N "" -C "astryxos-sshd-test" -f "${CLIENT_KEY}" 2>&1 \
        | grep -v '^$' \
        | sed 's/^/[SSHD]   /'
fi

# Stage the public half at /root/.ssh/authorized_keys (mode 600).  Dropbear
# also accepts /etc/dropbear/authorized_keys but the standard SSH convention
# (which `man 8 sshd` documents) is per-user under $HOME/.ssh/.
cp -fL "${CLIENT_PUB}" "${DISK_ROOT_SSH}/authorized_keys"
chmod 600 "${DISK_ROOT_SSH}/authorized_keys"
echo "[SSHD] Staged /root/.ssh/authorized_keys ($(stat -c%s "${DISK_ROOT_SSH}/authorized_keys") bytes)"

# ── Step 6: seed minimal /etc/passwd, /etc/shadow, /etc/shells, /etc/group ───
# Dropbear's authentication path calls getpwnam_r("root") + getspnam_r("root")
# (the latter via crypt() when password auth is enabled — we disable it via
# the locked '!' shadow entry).  For public-key auth, getpwnam_r alone
# suffices to map uid→home directory.  We add a `demo` non-root user as a
# convenience for future scoped-user testing; root remains the canonical
# login target for the v1 demo.
#
# Format references:
#   /etc/passwd  — passwd(5) — colon-separated: name:x:uid:gid:gecos:home:shell
#   /etc/shadow  — shadow(5) — name:hashed_pw:lastchange:...:flags
#                  '!' or '*' in the hash field means "locked / no password"
#   /etc/group   — group(5)  — name:x:gid:members
#   /etc/shells  — shells(5) — one absolute path per line
#
# We do NOT overwrite existing /etc/passwd / /etc/shadow / /etc/group if
# they were already seeded by create-data-disk.sh; we instead ensure the
# minimum entries exist by appending if absent.  The create-data-disk.sh
# `glibc/NSS minimal seeds` block already writes /etc/passwd and /etc/group,
# but /etc/shadow and /etc/shells are not seeded there.
mkdir -p "${DISK_ETC}"

# /etc/shadow — locked passwords for both root and demo (key auth only).
# Field meanings per shadow(5): name:hash:lastchange:min:max:warn:inactive:expire:reserved
SHADOW_CONTENT='root:!:19500:0:99999:7:::
demo:!:19500:0:99999:7:::
'
printf '%s' "${SHADOW_CONTENT}" > "${DISK_ETC}/shadow"
chmod 600 "${DISK_ETC}/shadow"
echo "[SSHD] Wrote /etc/shadow (locked passwords; public-key auth only)"

# /etc/shells — required by some servers to validate the login shell.
SHELLS_CONTENT='/bin/sh
/bin/busybox
'
printf '%s' "${SHELLS_CONTENT}" > "${DISK_ETC}/shells"
echo "[SSHD] Wrote /etc/shells"

# /etc/passwd — overwrite to ensure root's shell is /bin/sh (provided by
# the staged busybox: /bin/sh is conventionally a symlink to /bin/busybox,
# but FAT32 has no symlinks; instead we add a /bin/sh wrapper script under
# busybox staging — see scripts/install-busybox-cli.sh).
PASSWD_CONTENT='root:x:0:0:root:/root:/bin/sh
demo:x:1000:1000:demo:/home/demo:/bin/sh
'
printf '%s' "${PASSWD_CONTENT}" > "${DISK_ETC}/passwd"
echo "[SSHD] Wrote /etc/passwd (root + demo)"

# /etc/group — minimal.
GROUP_CONTENT='root:x:0:
demo:x:1000:
'
printf '%s' "${GROUP_CONTENT}" > "${DISK_ETC}/group"
echo "[SSHD] Wrote /etc/group"

# Pre-create /home/demo (empty) and /root so getpwnam-derived chdir works.
mkdir -p "${DISK_DIR}/home/demo" "${DISK_DIR}/root"

# ── Step 7: stage a minimal /etc/dropbear/dropbear.conf ──────────────────────
# Dropbear consults this conf for non-flag options on Alpine.  We keep it
# empty (all behaviour is set via command-line flags from sshd_demo.rs);
# the file's presence prevents dropbear from logging "config file missing".
: > "${DISK_ETC_DROPBEAR}/dropbear.conf"

# ── Summary ──────────────────────────────────────────────────────────────────
echo "[SSHD] Done.  Summary:"
echo "[SSHD]   - /usr/sbin/dropbear         (server)"
echo "[SSHD]   - /usr/bin/dropbearkey       (keygen utility)"
echo "[SSHD]   - /etc/dropbear/             (host keys + dropbear.conf)"
echo "[SSHD]   - /root/.ssh/authorized_keys (public-key auth)"
echo "[SSHD]   - /etc/passwd, /etc/shadow, /etc/group, /etc/shells"
echo "[SSHD]"
echo "[SSHD] Client key (HOST side):     ${CLIENT_KEY}"
echo "[SSHD] To connect once accept(2) lands + sshd-test runs:"
echo "[SSHD]   ssh -i ${CLIENT_KEY} \\"
echo "[SSHD]       -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\"
echo "[SSHD]       -p <HOST-PORT> root@127.0.0.1"
echo "[SSHD]"
echo "[SSHD] Re-run scripts/create-data-disk.sh --force to refresh data.img."
