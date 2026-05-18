#!/usr/bin/env bash
#
# inject-libxul-symbols.sh — Download Mozilla's official debug-symbol package
# for Firefox ESR 115.15.0 and splice a .symtab into the libxul.so that is
# staged in build/disk/opt/firefox/.
#
# Background:
#   Mozilla ships Breakpad-format .sym files for every release.  These contain
#   FUNC records mapping ELF VMAs to demangled C++/Rust function names.
#   This script downloads the libxul.so.sym file for the exact Build ID of the
#   locally installed libxul.so, then calls inject-libxul-symtab.py to build a
#   proper Elf64_Sym array and splice it into libxul.so as .symtab + .strtab.
#
# The resulting libxul.so has identical executable code (verified by Build ID
# preservation) and can be queried with `nm --defined-only` for 353,947 named
# functions.  The qemu-harness.py `rip-trace-resolve` subcommand uses this
# .symtab to resolve sampled RIPs to named functions.
#
# References:
#   - Mozilla Breakpad symbol format:
#     https://chromium.googlesource.com/breakpad/breakpad/+/HEAD/docs/symbol_files.md
#   - Mozilla Firefox ESR 115.15.0 release:
#     https://ftp.mozilla.org/pub/firefox/candidates/115.15.0esr-candidates/build1/
#   - binutils objcopy(1), nm(1)
#
# Usage:
#   bash scripts/inject-libxul-symbols.sh            # splice if absent
#   bash scripts/inject-libxul-symbols.sh --force    # re-download and re-splice
#
# Idempotent: exits 0 immediately if libxul.so already has .symtab
# (unless --force is passed).
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LIBXUL="${ROOT_DIR}/build/disk/opt/firefox/libxul.so"
SYM_DIR="${HOME}/.cache/astryxos-firefox/dbg-symbols"
SYM_FILE="${SYM_DIR}/libxul.so.sym"
SYM_COMPRESSED="${SYM_DIR}/libxul_sym_compressed.bin"
INJECT_SCRIPT="${ROOT_DIR}/scripts/inject-libxul-symtab.py"

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

FORCE=false
for arg in "$@"; do
    case "${arg}" in
        --force) FORCE=true ;;
    esac
done

# ── Idempotency check ─────────────────────────────────────────────────────────
if [ "${FORCE}" = false ]; then
    if readelf -S "${LIBXUL}" 2>/dev/null | grep -q '\.symtab'; then
        echo "[INJECT-SYMS] .symtab already present in ${LIBXUL} — skipping"
        echo "[INJECT-SYMS] (use --force to re-inject)"
        exit 0
    fi
fi

echo "[INJECT-SYMS] Injecting Mozilla debug symbols into libxul.so..."
echo "[INJECT-SYMS]   Target: ${LIBXUL}"

mkdir -p "${SYM_DIR}"

# ── Step 1: Download compressed symbol data via HTTP range request ────────────
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

# ── Step 2: Decompress raw DEFLATE stream to libxul.so.sym ────────────────────
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

echo "[INJECT-SYMS] libxul.so.sym: $(wc -l < "${SYM_FILE}") lines, \
$(grep -c '^FUNC ' "${SYM_FILE}") FUNC records"

# ── Step 3: Splice .symtab into libxul.so (in-place via temp file) ────────────
echo "[INJECT-SYMS] Running inject-libxul-symtab.py..."
python3 "${INJECT_SCRIPT}" \
    --sym    "${SYM_FILE}" \
    --input  "${LIBXUL}" \
    --output "${LIBXUL}.tmp"

# Atomically replace libxul.so (preserve permissions)
chmod --reference="${LIBXUL}" "${LIBXUL}.tmp"
mv "${LIBXUL}.tmp" "${LIBXUL}"

echo "[INJECT-SYMS] Done."
echo "[INJECT-SYMS]   ${LIBXUL}: $(du -sh "${LIBXUL}" | cut -f1)"
NM_COUNT=$(nm --defined-only "${LIBXUL}" 2>/dev/null | wc -l)
echo "[INJECT-SYMS]   nm --defined-only | wc -l: ${NM_COUNT}"
if [ "${NM_COUNT}" -lt 300000 ]; then
    echo "[INJECT-SYMS] WARNING: expected ~353,947 symbols, got ${NM_COUNT}" >&2
fi
