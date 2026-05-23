#!/usr/bin/env bash
#
# install-tls-stack.sh — Stage Alpine's TLS userspace (OpenSSL 3.x +
# ca-certificates) into the AstryxOS data-disk staging tree so guest-side
# binaries (busybox wget, openssl s_client, anything DT_NEEDED libssl /
# libcrypto) can drive real HTTPS handshakes.
#
# Why a separate Alpine rootfs?
# -----------------------------
# The shared firefox-musl rootfs at ~/.cache/astryxos-firefox-musl/ is
# treated as an immutable input by parallel dispatches (xeyes, busybox,
# musl firefox).  Mutating it (`apk add ca-certificates openssl`) would
# race with sibling agents.  We instead keep a dedicated TLS staging
# rootfs at ~/.cache/astryxos-tls/ and copy individual files out of it.
#
# What this stages
# ----------------
#
#   1. /usr/lib/libssl.so.3      (Alpine libssl3 3.3.x, OpenSSL 3 ABI)
#   2. /usr/lib/libcrypto.so.3   (Alpine libcrypto3 3.3.x)
#   3. /usr/lib/ossl-modules/legacy.so
#                                (OpenSSL 3 provider for legacy ciphers;
#                                openssl s_client refuses to load when
#                                the providers directory is missing)
#   4. /usr/bin/openssl          (Alpine openssl 3.3.x CLI, musl-PIE)
#   5. /etc/ssl/certs/ca-certificates.crt
#                                (Mozilla CA bundle, ~3700 lines, PEM concat)
#   6. /etc/ssl/cert.pem         (duplicate of the bundle — FAT32 has no
#                                symlinks so the conventional "cert.pem
#                                -> certs/ca-certificates.crt" Alpine
#                                symlink is materialised as a file copy)
#   7. /etc/ssl/openssl.cnf      (default OpenSSL configuration; openssl
#                                CLI consults this for [openssl_conf]
#                                provider activation)
#   8. /etc/pki/tls/certs/ca-bundle.crt
#                                (RHEL convention — Mozilla NSS rejects
#                                certs lookups at non-canonical paths)
#
# OpenSSL 3 looks for ossl-modules at $OPENSSLDIR/ossl-modules/ (compiled
# in as /usr/lib/ossl-modules on Alpine).  Providers are loaded on
# demand; legacy.so covers DES/MD4 etc. needed by some test cases.
#
# CA bundle path conventions covered (per public docs):
#   - Alpine / musl wolfssl:    /etc/ssl/cert.pem
#   - Debian / Ubuntu:          /etc/ssl/certs/ca-certificates.crt
#   - RHEL / Fedora / CentOS:   /etc/pki/tls/certs/ca-bundle.crt
#   - SUSE:                     /etc/ssl/ca-bundle.pem (same as Debian)
#   - LibreSSL:                 /etc/ssl/cert.pem
#
# Idempotent.  Pass --force to refresh the rootfs and restage.
#
# References (public)
#   - OpenSSL 3.x release notes: https://www.openssl.org/news/openssl-3.0-notes.html
#   - OpenSSL providers / ossl-modules:
#     https://www.openssl.org/docs/man3.0/man7/provider.html
#   - Alpine ca-certificates package:
#     https://pkgs.alpinelinux.org/package/v3.20/main/x86_64/ca-certificates
#   - Mozilla CA bundle:
#     https://curl.se/docs/caextract.html  (upstream-equivalent format)
#   - RFC 8446 (TLS 1.3): https://datatracker.ietf.org/doc/html/rfc8446
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_DIR="${BUILD_DIR}/disk"
DISK_USR_LIB="${DISK_DIR}/usr/lib"
DISK_USR_BIN="${DISK_DIR}/usr/bin"
DISK_OSSL_MODULES="${DISK_USR_LIB}/ossl-modules"
DISK_ETC_SSL="${DISK_DIR}/etc/ssl"
DISK_ETC_SSL_CERTS="${DISK_ETC_SSL}/certs"
DISK_ETC_PKI="${DISK_DIR}/etc/pki/tls/certs"

# Dedicated TLS-staging rootfs (independent of the firefox-musl shared one,
# so parallel dispatches cannot race on apk add).
CACHE_DIR="${HOME}/.cache/astryxos-tls"
ROOTFS="${CACHE_DIR}/rootfs"
ALPINE_KEYS="${ROOTFS}/etc/apk/keys"

# apk-static binary is shared with firefox-musl (same Alpine apk-tools
# tree — used read-only).
APK_STATIC="${HOME}/.cache/astryxos-firefox-musl/apk-tools/sbin/apk.static"
APK_KEYS_SRC="${HOME}/.cache/astryxos-firefox-musl/rootfs/etc/apk/keys"

ALPINE_VERSION="v3.20"
ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main"

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        -h|--help) sed -n '2,55p' "$0"; exit 0 ;;
    esac
done

# ── Sanity: apk-static and source keys must exist (provided by
#    install-firefox-musl.sh; we read but never write them). ──────────────
if [ ! -x "${APK_STATIC}" ]; then
    echo "[TLS-STACK] ERROR: apk.static not present at ${APK_STATIC}"
    echo "[TLS-STACK]        Run scripts/install-firefox-musl.sh first to bootstrap."
    exit 1
fi
if [ ! -d "${APK_KEYS_SRC}" ]; then
    echo "[TLS-STACK] ERROR: Alpine apk keys not present at ${APK_KEYS_SRC}"
    exit 1
fi

# ── Step 1: bootstrap the dedicated TLS rootfs (idempotent). ─────────────
mkdir -p "${ROOTFS}/etc/apk"
if [ ! -d "${ALPINE_KEYS}" ] || [ "${FORCE}" = true ]; then
    rm -rf "${ALPINE_KEYS}"
    cp -r "${APK_KEYS_SRC}" "${ALPINE_KEYS}"
    echo "[TLS-STACK] Seeded Alpine apk keys at ${ALPINE_KEYS}"
fi

# Check whether the packages we need are already present (idempotent fast
# path — second run with no --force is a few ms, not a full apk fetch).
NEED_INSTALL=false
for f in \
    "${ROOTFS}/usr/lib/libssl.so.3" \
    "${ROOTFS}/usr/lib/libcrypto.so.3" \
    "${ROOTFS}/usr/lib/ossl-modules/legacy.so" \
    "${ROOTFS}/usr/bin/openssl" \
    "${ROOTFS}/etc/ssl/certs/ca-certificates.crt"
do
    if [ ! -e "${f}" ]; then
        NEED_INSTALL=true
        break
    fi
done
if [ "${FORCE}" = true ]; then
    NEED_INSTALL=true
fi

if [ "${NEED_INSTALL}" = true ]; then
    echo "[TLS-STACK] Installing TLS packages into ${ROOTFS} via apk ..."
    "${APK_STATIC}" \
        --repository "${ALPINE_MAIN}" \
        --keys-dir "${ALPINE_KEYS}" \
        --root "${ROOTFS}" \
        --arch x86_64 \
        --no-scripts \
        --initdb \
        --update-cache \
        add ca-certificates ca-certificates-bundle openssl libcrypto3 libssl3 \
            musl-utils 2>&1 | sed 's/^/[TLS-STACK]   /'
fi

# ── Step 2: stage the libraries into build/disk/usr/lib/ ─────────────────
# libssl/libcrypto may already exist there from install-firefox-musl.sh;
# we overwrite with the dedicated TLS-rootfs copy so versions are pinned
# from a known source (3.3.7 at time of writing).  apk symlinks libssl.so
# in /usr/lib to a real file in /lib (Alpine convention); cp -L follows
# the link so we end up with a real file in build/disk/usr/lib/.
mkdir -p "${DISK_USR_LIB}" "${DISK_USR_BIN}" "${DISK_OSSL_MODULES}" \
         "${DISK_ETC_SSL}" "${DISK_ETC_SSL_CERTS}" "${DISK_ETC_PKI}"

for lib in libssl.so.3 libcrypto.so.3; do
    SRC="${ROOTFS}/usr/lib/${lib}"
    if [ ! -e "${SRC}" ]; then
        # Fall back to /lib (where Alpine actually keeps the file in some
        # versions; usr-merge transition).
        SRC="${ROOTFS}/lib/${lib}"
    fi
    if [ -e "${SRC}" ]; then
        cp -fL "${SRC}" "${DISK_USR_LIB}/${lib}"
        echo "[TLS-STACK] Staged /usr/lib/${lib} ($(stat -c%s "${DISK_USR_LIB}/${lib}") bytes)"
    else
        echo "[TLS-STACK] WARNING: ${lib} not found in ${ROOTFS}"
    fi
done

# ── Step 3: OpenSSL 3 providers (ossl-modules/legacy.so) ─────────────────
# OpenSSL 3 split legacy ciphers (DES, MD4, etc.) into a separate provider
# module that must be loadable from $OPENSSLDIR/ossl-modules/.  Even when
# the active cipher suite is TLS 1.3 (which uses no legacy ciphers), the
# `openssl` CLI tries to load the legacy provider for its built-in tests
# and refuses to start if the directory is missing entirely.
for mod in legacy.so; do
    SRC="${ROOTFS}/usr/lib/ossl-modules/${mod}"
    if [ -e "${SRC}" ]; then
        cp -fL "${SRC}" "${DISK_OSSL_MODULES}/${mod}"
        echo "[TLS-STACK] Staged /usr/lib/ossl-modules/${mod}"
    fi
done

# ── Step 4: openssl CLI ──────────────────────────────────────────────────
if [ -x "${ROOTFS}/usr/bin/openssl" ]; then
    cp -fL "${ROOTFS}/usr/bin/openssl" "${DISK_USR_BIN}/openssl"
    chmod +x "${DISK_USR_BIN}/openssl"
    echo "[TLS-STACK] Staged /usr/bin/openssl ($(stat -c%s "${DISK_USR_BIN}/openssl") bytes)"
else
    echo "[TLS-STACK] WARNING: openssl CLI not found"
fi

# ── Step 5: CA bundle + path-convention duplicates ───────────────────────
# Alpine ships a single Mozilla CA bundle at /etc/ssl/certs/ca-certificates.crt
# (PEM concatenation, ~3700 lines, ~300 KiB) and a symlink
# /etc/ssl/cert.pem -> certs/ca-certificates.crt.  FAT32 has no symlinks
# so we materialise the link target as a duplicate file at each
# conventional path.  Three convention paths are covered:
#
#   - Alpine / musl wolfssl / LibreSSL:    /etc/ssl/cert.pem
#   - Debian / Ubuntu / SUSE:              /etc/ssl/certs/ca-certificates.crt
#   - RHEL / Fedora / CentOS:              /etc/pki/tls/certs/ca-bundle.crt
#
# Adding all three has negligible cost (~900 KiB total) and means any
# upstream TLS client compiled with any of these defaults Just Works.
BUNDLE_SRC="${ROOTFS}/etc/ssl/certs/ca-certificates.crt"
if [ -f "${BUNDLE_SRC}" ]; then
    cp -fL "${BUNDLE_SRC}" "${DISK_ETC_SSL_CERTS}/ca-certificates.crt"
    cp -fL "${BUNDLE_SRC}" "${DISK_ETC_SSL}/cert.pem"
    cp -fL "${BUNDLE_SRC}" "${DISK_ETC_PKI}/ca-bundle.crt"
    BSIZE="$(stat -c%s "${BUNDLE_SRC}")"
    BLINES="$(wc -l < "${BUNDLE_SRC}")"
    echo "[TLS-STACK] Staged CA bundle (${BSIZE} bytes, ${BLINES} lines) at:"
    echo "[TLS-STACK]   /etc/ssl/certs/ca-certificates.crt   (Debian/Ubuntu)"
    echo "[TLS-STACK]   /etc/ssl/cert.pem                    (Alpine/LibreSSL)"
    echo "[TLS-STACK]   /etc/pki/tls/certs/ca-bundle.crt     (RHEL)"
else
    echo "[TLS-STACK] WARNING: CA bundle not found at ${BUNDLE_SRC}"
fi

# ── Step 6: openssl.cnf ──────────────────────────────────────────────────
# openssl(1) reads this on startup for [openssl_conf] sections — provider
# activation, default cipher suites, FIPS mode.  Without a config file
# openssl uses compiled-in defaults which omit the providers list; the
# legacy provider then fails to load on demand.
if [ -f "${ROOTFS}/etc/ssl/openssl.cnf" ]; then
    cp -fL "${ROOTFS}/etc/ssl/openssl.cnf" "${DISK_ETC_SSL}/openssl.cnf"
    echo "[TLS-STACK] Staged /etc/ssl/openssl.cnf"
fi

# ── Step 7: ssl_client (busybox HTTPS helper) ────────────────────────────
# busybox wget invokes /usr/bin/ssl_client to handle the TLS layer on
# `https://` URLs.  Alpine's busybox-static package already includes
# ssl_client as a separately-installable applet; stage the dynamically-
# linked helper here so `busybox wget https://...` resolves.  Without this
# helper the kernel-side wget-test path falls back to "wget: SSL not
# supported, install libssl".
if [ -x "${ROOTFS}/usr/bin/ssl_client" ]; then
    cp -fL "${ROOTFS}/usr/bin/ssl_client" "${DISK_USR_BIN}/ssl_client"
    chmod +x "${DISK_USR_BIN}/ssl_client"
    echo "[TLS-STACK] Staged /usr/bin/ssl_client ($(stat -c%s "${DISK_USR_BIN}/ssl_client") bytes)"
fi

# ── Step 8: musl dynamic linker (PT_INTERP target) ───────────────────────
# Both the openssl CLI and ssl_client are dynamically-linked (musl-PIE);
# their PT_INTERP header points at /lib/ld-musl-x86_64.so.1.  Stage the
# linker into build/disk/lib/ so the kernel ELF loader can resolve the
# interpreter.  Also stage libc.musl-x86_64.so.1 (a symlink on Alpine
# pointing back at ld-musl; cp -L materialises the real bytes — needed
# for static deduplication on FAT32 which lacks symlinks).
DISK_LIB="${DISK_DIR}/lib"
mkdir -p "${DISK_LIB}"
for lib in ld-musl-x86_64.so.1 libc.musl-x86_64.so.1; do
    SRC="${ROOTFS}/lib/${lib}"
    if [ -e "${SRC}" ]; then
        cp -fL "${SRC}" "${DISK_LIB}/${lib}"
        echo "[TLS-STACK] Staged /lib/${lib} ($(stat -c%s "${DISK_LIB}/${lib}") bytes)"
    fi
done

echo "[TLS-STACK] Done.  Re-run scripts/create-data-disk.sh --tls --force to refresh data.img."
