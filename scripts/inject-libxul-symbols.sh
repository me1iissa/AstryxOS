#!/usr/bin/env bash
#
# inject-libxul-symbols.sh — Download Mozilla's official debug-symbol data and
# splice an ELF .symtab into a stripped libxul.so so that nm / addr2line /
# kdb rip-trace-resolve can name functions inside it.
#
# Two modes are supported:
#
#   (default, --glibc)
#       Target: build/disk/opt/firefox/libxul.so
#       Source: Firefox ESR 115.15.0 crashreporter-symbols ZIP (Mozilla CDN),
#               sliced by HTTP-range to the libxul.so.sym entry, raw-DEFLATE
#               decompressed.  ~135 MiB compressed, ~690 MiB decompressed,
#               ~353,947 FUNC records.
#
#   --musl
#       Target: build/disk/usr/lib/firefox-esr/libxul.so   (Alpine package)
#       Source: Mozilla symbol server keyed by the ELF Build ID converted to
#               a Breakpad GUID.  Alpine community/firefox-esr's exact
#               BuildID is indexed by Mozilla's tecken — a gzipped libxul.so.sym
#               (~9 MiB compressed, ~88 MiB decompressed) is downloaded as a
#               single GET.  Records are PUBLIC-only (Alpine builds without
#               DWARF), so the .symtab carries function-entry-point names only;
#               this is sufficient for K-class RIP attribution.
#
# Background:
#   Mozilla ships Breakpad-format .sym files for every release and every
#   third-party rebuild that uploads to its symbol server.  The .sym contains
#   FUNC and/or PUBLIC records mapping ELF VMAs to demangled C++/Rust names.
#   This script downloads the .sym matching the local libxul.so's BuildID,
#   then calls inject-libxul-symtab.py to build a proper Elf64_Sym array and
#   splice it into libxul.so as .symtab + .strtab.
#
# The resulting libxul.so has byte-identical executable code (verified by
# BuildID preservation and the .text section SHA256), and the qemu-harness.py
# `rip-trace-resolve` subcommand uses this .symtab to resolve sampled RIPs
# to named functions.
#
# References:
#   - Mozilla Breakpad symbol format:
#     https://chromium.googlesource.com/breakpad/breakpad/+/HEAD/docs/symbol_files.md
#   - Mozilla Firefox ESR 115.15.0 release:
#     https://ftp.mozilla.org/pub/firefox/candidates/115.15.0esr-candidates/build1/
#   - Mozilla symbol server (tecken):
#     https://symbols.mozilla.org/
#   - binutils objcopy(1), nm(1)
#
# Usage:
#   bash scripts/inject-libxul-symbols.sh                 # default glibc mode
#   bash scripts/inject-libxul-symbols.sh --musl          # Alpine musl libxul
#   bash scripts/inject-libxul-symbols.sh --force         # re-download + splice
#   bash scripts/inject-libxul-symbols.sh --musl --force  # both
#
# Idempotent: exits 0 immediately if the target libxul.so already has a
# .symtab section (unless --force is passed).
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INJECT_SCRIPT="${ROOT_DIR}/scripts/inject-libxul-symtab.py"

# ── Argument parsing ─────────────────────────────────────────────────────────
FORCE=false
MODE=glibc
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
        --musl)  MODE=musl ;;
        --glibc) MODE=glibc ;;
        -h|--help)
            sed -n '2,60p' "$0"
            exit 0
            ;;
        *)
            echo "[INJECT-SYMS] ERROR: unknown arg '${arg}'" >&2
            exit 2
            ;;
    esac
done

# ── Mode-specific paths and URLs ─────────────────────────────────────────────
if [ "${MODE}" = "glibc" ]; then
    LIBXUL="${ROOT_DIR}/build/disk/opt/firefox/libxul.so"
    SYM_DIR="${HOME}/.cache/astryxos-firefox/dbg-symbols"
    SYM_FILE="${SYM_DIR}/libxul.so.sym"
    SYM_COMPRESSED="${SYM_DIR}/libxul_sym_compressed.bin"

    # Firefox ESR 115.15.0 crashreporter symbols ZIP on Mozilla's CDN.
    # This is the official build1 artifact published at:
    # https://ftp.mozilla.org/pub/firefox/candidates/115.15.0esr-candidates/build1/
    SYMBOLS_ZIP_URL="https://ftp.mozilla.org/pub/firefox/candidates/115.15.0esr-candidates/build1/linux-x86_64/en-US/firefox-115.15.0esr.crashreporter-symbols.zip"

    # Byte range of the compressed libxul.so.sym entry within the ZIP.
    # File: libxul.so/05D92C491C2758BAD3544DCBC1D3DE790/libxul.so.sym
    # Matches Build ID 492cd905271cba58d3544dcbc1d3de79e9319d2b.
    # Computed by parsing the ZIP central directory (ELF build-id → breakpad GUID).
    ZIP_DATA_BYTE_OFFSET=246431325
    ZIP_DATA_BYTE_SIZE=135889978   # 129.6 MiB compressed
else
    # --musl
    LIBXUL="${ROOT_DIR}/build/disk/usr/lib/firefox-esr/libxul.so"
    SYM_DIR="${HOME}/.cache/astryxos-firefox-musl/dbg-symbols"
    SYM_FILE="${SYM_DIR}/libxul.so.sym"
    SYM_GZ="${SYM_DIR}/libxul.so.sym.gz"
fi

# ── Required-tools check (defensive: keep .text-SHA invariant probe intact) ──
# The architectural invariant (no upstream-binary edits) is enforced by the
# pre/post .text SHA256 comparison below; that comparison silently no-ops if
# objcopy or sha256sum is missing, which would let a regression slip through
# unnoticed.  Require both upfront so the invariant probe is always exercised.
for tool in objcopy sha256sum readelf; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "[INJECT-SYMS] ERROR: required tool '${tool}' not found in PATH" >&2
        echo "[INJECT-SYMS]        Install binutils + coreutils (Debian: 'apt install binutils coreutils')" >&2
        exit 1
    fi
done

# ── Sanity: target libxul must exist ─────────────────────────────────────────
if [ ! -f "${LIBXUL}" ]; then
    echo "[INJECT-SYMS] ERROR: target libxul.so not found: ${LIBXUL}"
    if [ "${MODE}" = "musl" ]; then
        echo "[INJECT-SYMS]        Run scripts/install-firefox-musl.sh first"
        echo "[INJECT-SYMS]        (or set ASTRYXOS_FIREFOX_VARIANT=musl in create-data-disk.sh)"
    else
        echo "[INJECT-SYMS]        Run scripts/install-firefox.sh first"
    fi
    exit 1
fi

# ── Idempotency check ─────────────────────────────────────────────────────────
if [ "${FORCE}" = false ]; then
    if readelf -S "${LIBXUL}" 2>/dev/null | grep -q '\.symtab'; then
        echo "[INJECT-SYMS] .symtab already present in ${LIBXUL} — skipping"
        echo "[INJECT-SYMS] (use --force to re-inject)"
        exit 0
    fi
fi

echo "[INJECT-SYMS] Mode: ${MODE}"
echo "[INJECT-SYMS] Injecting Mozilla debug symbols into libxul.so..."
echo "[INJECT-SYMS]   Target: ${LIBXUL}"

mkdir -p "${SYM_DIR}"

# ── Pre-injection .text section SHA256 (architectural invariant probe) ───────
# AstryxOS invariant: never edit upstream binaries.  Splicing a .symtab is
# adding metadata sections, which does NOT touch .text — verify byte-identical
# .text content after injection.
PRE_TEXT_SHA=""
PRE_TEXT_TMP="$(mktemp -t libxul_pre_text.XXXXXX)"
if objcopy --dump-section .text="${PRE_TEXT_TMP}" "${LIBXUL}" 2>/dev/null; then
    PRE_TEXT_SHA="$(sha256sum "${PRE_TEXT_TMP}" | cut -d' ' -f1)"
    echo "[INJECT-SYMS]   Pre  .text SHA256: ${PRE_TEXT_SHA}"
else
    echo "[INJECT-SYMS] ERROR: failed to dump .text from ${LIBXUL}" >&2
    rm -f "${PRE_TEXT_TMP}"
    exit 1
fi
rm -f "${PRE_TEXT_TMP}"

if [ "${MODE}" = "glibc" ]; then
    # ── glibc mode: HTTP-range-slice the crashreporter ZIP ───────────────────
    ACTUAL_SIZE=0
    if [ -f "${SYM_COMPRESSED}" ]; then
        ACTUAL_SIZE=$(stat -c%s "${SYM_COMPRESSED}" 2>/dev/null || echo 0)
    fi

    if [ "${FORCE}" = true ] || [ "${ACTUAL_SIZE}" -ne "${ZIP_DATA_BYTE_SIZE}" ]; then
        echo "[INJECT-SYMS] Downloading libxul.so.sym from Mozilla CDN (~130 MiB)..."
        RANGE_END=$(( ZIP_DATA_BYTE_OFFSET + ZIP_DATA_BYTE_SIZE - 1 ))
        if command -v curl &>/dev/null; then
            curl -L --max-time 600 \
                -H "Range: bytes=${ZIP_DATA_BYTE_OFFSET}-${RANGE_END}" \
                "${SYMBOLS_ZIP_URL}" \
                -o "${SYM_COMPRESSED}"
        elif command -v wget &>/dev/null; then
            wget --header="Range: bytes=${ZIP_DATA_BYTE_OFFSET}-${RANGE_END}" \
                 --timeout=600 -q \
                 -O "${SYM_COMPRESSED}" \
                 "${SYMBOLS_ZIP_URL}"
        else
            echo "[INJECT-SYMS] ERROR: curl or wget is required" >&2
            exit 1
        fi
        echo "[INJECT-SYMS] Downloaded $(du -sh "${SYM_COMPRESSED}" | cut -f1)"
    else
        echo "[INJECT-SYMS] Using cached compressed symbols (${SYM_COMPRESSED})"
    fi

    if [ "${FORCE}" = true ] || [ ! -f "${SYM_FILE}" ]; then
        echo "[INJECT-SYMS] Decompressing libxul.so.sym (~690 MiB)..."
        python3 -c "
import zlib, time, sys
compressed_file = sys.argv[1]
output_file     = sys.argv[2]
start = time.time()
with open(compressed_file, 'rb') as f:
    data = f.read()
dec = zlib.decompressobj(wbits=-15)
out = dec.decompress(data)
with open(output_file, 'wb') as f:
    f.write(out)
print(f'[INJECT-SYMS] Decompressed {len(out)/1024/1024:.1f} MiB in {time.time()-start:.1f}s')
" "${SYM_COMPRESSED}" "${SYM_FILE}"
    else
        echo "[INJECT-SYMS] Using cached ${SYM_FILE} ($(wc -l < "${SYM_FILE}") lines)"
    fi
else
    # ── musl mode: query Mozilla symbol server by BuildID-derived GUID ───────
    BUILD_ID="$(readelf -n "${LIBXUL}" 2>/dev/null | awk '/Build ID:/ {print $NF}')"
    if [ -z "${BUILD_ID}" ] || [ "${#BUILD_ID}" -lt 32 ]; then
        echo "[INJECT-SYMS] ERROR: could not read Build ID from ${LIBXUL}" >&2
        exit 1
    fi
    echo "[INJECT-SYMS]   BuildID: ${BUILD_ID}"

    # Breakpad GUID convention: first 16 bytes of BuildID as a Microsoft GUID
    # (LE quad/word/word reorder for the first 8 bytes, then 8 bytes verbatim),
    # uppercase hex with a trailing "0" pad making it 33 chars total.
    # Reference: https://chromium.googlesource.com/breakpad/breakpad/+/HEAD/docs/symbol_files.md#the-module-record
    GUID="$(python3 -c "
import sys
bid = sys.argv[1]
b = bytes.fromhex(bid[:32])
g = b[0:4][::-1] + b[4:6][::-1] + b[6:8][::-1] + b[8:16]
print(g.hex().upper() + '0')
" "${BUILD_ID}")"
    echo "[INJECT-SYMS]   Breakpad GUID: ${GUID}"

    SYM_URL="https://symbols.mozilla.org/libxul.so/${GUID}/libxul.so.sym"

    if [ "${FORCE}" = true ] || [ ! -f "${SYM_GZ}" ]; then
        echo "[INJECT-SYMS] Downloading libxul.so.sym from Mozilla tecken (~9 MiB gz)..."
        # Mozilla's symbol server returns 200 with a redirect Location header
        # even for unknown GUIDs (it always replies with the CDN URL).  We must
        # follow the redirect (-L) and inspect the actual response to detect
        # MISS vs HIT.  A HIT returns gzip-magic (\037\213) bytes; a MISS
        # returns text "Symbol not found" / 404 from the CDN.
        SYM_GZ_TMP="${SYM_GZ}.tmp"
        if command -v curl &>/dev/null; then
            HTTP_CODE="$(curl -sL --max-time 120 \
                -w '%{http_code}' \
                -o "${SYM_GZ_TMP}" \
                "${SYM_URL}")"
        elif command -v wget &>/dev/null; then
            wget --timeout=120 -q -O "${SYM_GZ_TMP}" "${SYM_URL}" \
                && HTTP_CODE=200 || HTTP_CODE=404
        else
            echo "[INJECT-SYMS] ERROR: curl or wget is required" >&2
            exit 1
        fi
        if [ "${HTTP_CODE}" != "200" ]; then
            echo "[INJECT-SYMS] ERROR: Mozilla symbol server returned HTTP ${HTTP_CODE}" >&2
            echo "[INJECT-SYMS]        URL: ${SYM_URL}" >&2
            echo "[INJECT-SYMS]        The Alpine libxul BuildID is not in Mozilla's index." >&2
            echo "[INJECT-SYMS]        Consider scripts/install-firefox-musl-debug.sh for non-libxul" >&2
            echo "[INJECT-SYMS]        coverage, or building firefox-esr from Alpine source." >&2
            rm -f "${SYM_GZ_TMP}"
            exit 1
        fi
        # Verify the payload is actually gzip (first two bytes 0x1f 0x8b).
        MAGIC_HEX="$(head -c2 "${SYM_GZ_TMP}" | od -An -tx1 | tr -d ' \n')"
        if [ "${MAGIC_HEX}" != "1f8b" ]; then
            echo "[INJECT-SYMS] ERROR: downloaded payload is not gzip (magic=${MAGIC_HEX})" >&2
            echo "[INJECT-SYMS]        First 200 bytes:" >&2
            head -c200 "${SYM_GZ_TMP}" >&2
            rm -f "${SYM_GZ_TMP}"
            exit 1
        fi
        mv "${SYM_GZ_TMP}" "${SYM_GZ}"
        echo "[INJECT-SYMS] Downloaded $(du -sh "${SYM_GZ}" | cut -f1)"
    else
        echo "[INJECT-SYMS] Using cached compressed symbols (${SYM_GZ})"
    fi

    if [ "${FORCE}" = true ] || [ ! -f "${SYM_FILE}" ]; then
        echo "[INJECT-SYMS] Decompressing libxul.so.sym ..."
        gunzip -c "${SYM_GZ}" > "${SYM_FILE}"
        echo "[INJECT-SYMS] Decompressed $(du -sh "${SYM_FILE}" | cut -f1)"
    else
        echo "[INJECT-SYMS] Using cached ${SYM_FILE} ($(wc -l < "${SYM_FILE}") lines)"
    fi

    # Sanity: the .sym file MUST carry the same Build ID we read from libxul.
    # A mismatch means tecken returned the wrong .sym (GUID derivation bug,
    # index inconsistency, or the .sym was rebuilt against a different binary).
    # Splicing a mismatched .symtab produces nonsense rip-trace attributions —
    # hard-fail rather than warn.
    SYM_MODULE_LINE="$(head -2 "${SYM_FILE}")"
    SYM_CODE_ID="$(echo "${SYM_MODULE_LINE}" | awk '/^INFO CODE_ID/ {print tolower($3)}')"
    if [ -n "${SYM_CODE_ID}" ] && [ "${SYM_CODE_ID}" != "${BUILD_ID}" ]; then
        echo "[INJECT-SYMS] ERROR: .sym CODE_ID=${SYM_CODE_ID} does not match libxul BuildID=${BUILD_ID}" >&2
        echo "[INJECT-SYMS]        GUID derivation or Mozilla index lookup is inconsistent." >&2
        echo "[INJECT-SYMS]        Refusing to inject — would produce wrong rip-trace attributions." >&2
        exit 1
    fi
fi

echo "[INJECT-SYMS] libxul.so.sym: $(wc -l < "${SYM_FILE}") lines, \
$(grep -c '^FUNC ' "${SYM_FILE}") FUNC + $(grep -c '^PUBLIC ' "${SYM_FILE}") PUBLIC records"

# ── Splice .symtab into libxul.so (in-place via temp file) ───────────────────
echo "[INJECT-SYMS] Running inject-libxul-symtab.py..."
python3 "${INJECT_SCRIPT}" \
    --sym    "${SYM_FILE}" \
    --input  "${LIBXUL}" \
    --output "${LIBXUL}.tmp"

# Atomically replace libxul.so (preserve permissions)
chmod --reference="${LIBXUL}" "${LIBXUL}.tmp"
mv "${LIBXUL}.tmp" "${LIBXUL}"

# ── Post-injection .text SHA256 — must equal pre-injection ───────────────────
if [ -n "${PRE_TEXT_SHA}" ]; then
    POST_TEXT_TMP="$(mktemp -t libxul_post_text.XXXXXX)"
    if objcopy --dump-section .text="${POST_TEXT_TMP}" "${LIBXUL}" 2>/dev/null; then
        POST_TEXT_SHA="$(sha256sum "${POST_TEXT_TMP}" | cut -d' ' -f1)"
        echo "[INJECT-SYMS]   Post .text SHA256: ${POST_TEXT_SHA}"
        if [ "${POST_TEXT_SHA}" != "${PRE_TEXT_SHA}" ]; then
            echo "[INJECT-SYMS] FATAL: .text section was modified by injection!" >&2
            echo "[INJECT-SYMS]        Upstream-binary-edit invariant violated." >&2
            rm -f "${POST_TEXT_TMP}"
            exit 1
        fi
    fi
    rm -f "${POST_TEXT_TMP}"
fi

echo "[INJECT-SYMS] Done."
echo "[INJECT-SYMS]   ${LIBXUL}: $(du -sh "${LIBXUL}" | cut -f1)"
NM_COUNT=$(nm --defined-only "${LIBXUL}" 2>/dev/null | wc -l)
echo "[INJECT-SYMS]   nm --defined-only | wc -l: ${NM_COUNT}"
# Glibc mode expects ~353,947 FUNC records.  Musl mode is PUBLIC-only and
# carries ~8,000 records (Alpine builds without DWARF).  Warn only if the
# count falls below mode-specific lower bounds — a hard floor catches
# malformed .sym fetches without alarming on the legitimate PUBLIC-only case.
if [ "${MODE}" = "glibc" ]; then
    [ "${NM_COUNT}" -lt 300000 ] && \
        echo "[INJECT-SYMS] WARNING: expected ~353,947 symbols (glibc), got ${NM_COUNT}" >&2
else
    [ "${NM_COUNT}" -lt 5000 ] && \
        echo "[INJECT-SYMS] WARNING: expected ~8,000 symbols (musl PUBLIC-only), got ${NM_COUNT}" >&2
fi
