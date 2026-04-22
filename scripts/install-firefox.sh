#!/usr/bin/env bash
#
# install-firefox.sh — Stage Firefox ESR for the AstryxOS data disk
#
# Workflow:
#   1. Look for Firefox ESR on the host system (/usr/lib/firefox-esr, etc.)
#   2. If not found locally, download from Mozilla CDN and cache to
#      ~/.cache/astryxos-firefox/ to avoid re-downloads.
#   3. Extract to build/disk/opt/firefox/
#   4. Create a minimal Firefox profile under build/disk/opt/firefox/profile/
#      with prefs that disable telemetry, skip first-run, and disable network
#      so the headless oracle test runs predictably.
#
# Idempotent: exits 0 immediately if build/disk/opt/firefox/firefox already
# exists (use --force to reinstall).
#
# Usage:
#   bash scripts/install-firefox.sh           # Install if absent
#   bash scripts/install-firefox.sh --force   # Reinstall unconditionally
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_OPT="${BUILD_DIR}/disk/opt/firefox"
FIREFOX_BIN="${DISK_OPT}/firefox"
CACHE_DIR="${HOME}/.cache/astryxos-firefox"
TARBALL_NAME="firefox-115.15.0esr.tar.bz2"
TARBALL="${CACHE_DIR}/${TARBALL_NAME}"
MOZILLA_URL="https://ftp.mozilla.org/pub/firefox/releases/115.15.0esr/linux-x86_64/en-US/${TARBALL_NAME}"
FORCE=false

for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
    esac
done

# ── Idempotency check ─────────────────────────────────────────────────────────
if [ -f "${FIREFOX_BIN}" ] && [ "${FORCE}" = false ]; then
    echo "[FIREFOX] ${FIREFOX_BIN} already exists — skipping (use --force to reinstall)"
    exit 0
fi

echo "[FIREFOX] Installing Firefox ESR to ${DISK_OPT}..."

# ── Step 1: Locate Firefox ────────────────────────────────────────────────────
HOST_FF_DIR=""
for candidate in /usr/lib/firefox-esr /usr/lib/firefox /opt/firefox; do
    if [ -x "${candidate}/firefox" ] || [ -x "${candidate}/firefox-esr" ]; then
        HOST_FF_DIR="${candidate}"
        echo "[FIREFOX] Found Firefox on host at ${HOST_FF_DIR}"
        break
    fi
done

if [ -z "${HOST_FF_DIR}" ] && [ -x /snap/firefox/current/firefox.launcher ]; then
    # Snap Firefox is a confined launcher, not a bare ELF — skip it
    echo "[FIREFOX] Snap Firefox present but confined — ignoring, will download ESR tarball"
fi

# ── Step 2: Download if not on host and not already cached ───────────────────
if [ -z "${HOST_FF_DIR}" ]; then
    mkdir -p "${CACHE_DIR}"
    if [ ! -f "${TARBALL}" ] || [ "${FORCE}" = true ]; then
        echo "[FIREFOX] Downloading ${MOZILLA_URL}..."
        if command -v curl &>/dev/null; then
            curl -L --max-time 300 -o "${TARBALL}" "${MOZILLA_URL}"
        elif command -v wget &>/dev/null; then
            wget -q --timeout=300 -O "${TARBALL}" "${MOZILLA_URL}"
        else
            echo "[FIREFOX] ERROR: curl/wget not found — cannot download Firefox"
            exit 1
        fi
        echo "[FIREFOX] Downloaded $(du -sh "${TARBALL}" | cut -f1)"
    else
        echo "[FIREFOX] Using cached ${TARBALL} ($(du -sh "${TARBALL}" | cut -f1))"
    fi
fi

# ── Step 3: Extract / copy to build/disk/opt/firefox/ ────────────────────────
mkdir -p "${DISK_OPT}"

if [ -n "${HOST_FF_DIR}" ]; then
    # Copy directly from host install
    echo "[FIREFOX] Copying from ${HOST_FF_DIR}..."
    cp -a "${HOST_FF_DIR}/." "${DISK_OPT}/"
    # Normalise binary name to 'firefox'
    if [ ! -f "${DISK_OPT}/firefox" ] && [ -f "${DISK_OPT}/firefox-esr" ]; then
        cp "${DISK_OPT}/firefox-esr" "${DISK_OPT}/firefox"
    fi
else
    # Extract tarball — creates a 'firefox/' subdirectory inside the archive
    echo "[FIREFOX] Extracting ${TARBALL}..."
    TMP_EXTRACT=$(mktemp -d)
    trap 'rm -rf "${TMP_EXTRACT}"' EXIT
    tar -xjf "${TARBALL}" -C "${TMP_EXTRACT}"
    # The archive extracts as: firefox-115.15.0esr/ or firefox/
    EXTRACTED_DIR=$(find "${TMP_EXTRACT}" -maxdepth 1 -type d | grep -v "^${TMP_EXTRACT}$" | head -1)
    if [ -z "${EXTRACTED_DIR}" ]; then
        echo "[FIREFOX] ERROR: Failed to find extracted directory in ${TMP_EXTRACT}"
        exit 1
    fi
    echo "[FIREFOX] Extracted to ${EXTRACTED_DIR}"
    # Move contents (not the wrapper dir) into DISK_OPT
    cp -a "${EXTRACTED_DIR}/." "${DISK_OPT}/"
    rm -rf "${TMP_EXTRACT}"
    trap - EXIT
fi

# Verify the binary exists
if [ ! -f "${FIREFOX_BIN}" ]; then
    echo "[FIREFOX] ERROR: ${FIREFOX_BIN} not present after extraction"
    exit 1
fi

echo "[FIREFOX] Firefox binary: $(file "${FIREFOX_BIN}" | cut -d: -f2- | xargs)"
echo "[FIREFOX] Directory size: $(du -sh "${DISK_OPT}" | cut -f1)"

# ── Step 4: Write minimal Firefox profile ────────────────────────────────────
# This profile lives at /opt/firefox/profile/ on the guest.
# Firefox reads it via -profile /opt/firefox/profile on the CLI.
PROFILE_DIR="${DISK_OPT}/profile"
mkdir -p "${PROFILE_DIR}"

cat > "${PROFILE_DIR}/prefs.js" <<'PREFS'
// AstryxOS minimal headless Firefox profile
// Disable telemetry, update checks, first-run, safebrowsing, and network
// so the oracle test runs as a pure ELF/syscall stress test.

// ── First-run / UI ────────────────────────────────────────────────────────────
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.rights.3.shown", true);
user_pref("browser.firstrun.show.uidiscovery", false);
user_pref("browser.firstrun.show.localepicker", false);
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("startup.homepage_override_url", "");
user_pref("browser.startup.page", 0);

// ── Updates ───────────────────────────────────────────────────────────────────
user_pref("app.update.enabled", false);
user_pref("app.update.auto", false);
user_pref("app.update.service.enabled", false);

// ── Telemetry ─────────────────────────────────────────────────────────────────
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("datareporting.healthreport.service.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);

// ── Safe Browsing (network calls) ─────────────────────────────────────────────
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.update.enabled", false);

// ── Network: disable almost everything ───────────────────────────────────────
user_pref("network.http.spdy.enabled", false);
user_pref("network.http.spdy.enabled.http2", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);

// ── Crash reporter ────────────────────────────────────────────────────────────
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("breakpad.reportURL", "");

// ── Extension / addon system ──────────────────────────────────────────────────
user_pref("extensions.update.enabled", false);
user_pref("extensions.update.autoUpdateDefault", false);
user_pref("extensions.getAddons.cache.enabled", false);

// ── Misc ──────────────────────────────────────────────────────────────────────
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.memory.enable", false);
user_pref("devtools.chrome.enabled", false);
user_pref("security.ssl.enable_ocsp_stapling", false);
user_pref("geo.enabled", false);
PREFS

echo "[FIREFOX] Wrote profile prefs.js to ${PROFILE_DIR}/prefs.js"

# ── Step 5: Write /tmp/hello.html (guest-side, via disk staging) ─────────────
# create-data-disk.sh will mcopy this onto the FAT32 image at ::tmp/hello.html
STAGING_TMP="${BUILD_DIR}/disk/tmp"
mkdir -p "${STAGING_TMP}"
cat > "${STAGING_TMP}/hello.html" <<'HTML'
<html>
<head><title>AstryxOS Firefox Oracle</title></head>
<body>
<h1>Hi</h1>
<p>AstryxOS Firefox ESR headless oracle page.</p>
</body>
</html>
HTML
echo "[FIREFOX] Wrote staging tmp/hello.html"

echo "[FIREFOX] Done. Firefox ESR staged at ${DISK_OPT}"
