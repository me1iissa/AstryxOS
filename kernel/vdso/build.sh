#!/bin/bash
# Build the AstryxOS vDSO shared object.
#
# Produces kernel/vdso/vdso.so — a minimal position-independent shared object
# that the kernel embeds and maps into every user process.
#
# Requirements:
#   x86_64-linux-musl-gcc (or x86_64-linux-gnu-gcc as fallback)
#   GNU ld (part of binutils)
#
# Called from kernel/build.rs at cargo build time.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-${SCRIPT_DIR}/vdso.so}"

# Prefer musl-targeted compiler to avoid any glibc/host-specific sections.
# Fall back to the generic x86_64 Linux gcc if musl isn't present.
if command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
    CC="x86_64-linux-musl-gcc"
elif command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
    CC="x86_64-linux-gnu-gcc"
else
    echo "error: no x86_64 cross-compiler found" >&2
    exit 1
fi

# -nostdlib      : no CRT, no libc — the vDSO must be self-contained
# -fPIC          : position-independent code (load anywhere)
# -fvisibility=hidden : symbols not in the version script are hidden
# -Os            : minimise size
# -fno-stack-protector : no __stack_chk_fail reference (would need extern sym)
# -fno-asynchronous-unwind-tables : strip .eh_frame — saves ~1 KiB
# --version-script : export only the four vDSO symbols under LINUX_2.6
# -Bsymbolic     : bind symbol references to definitions in this DSO
# -soname        : the "filename" glibc uses to key the vDSO lookup
# -s             : strip debug info from the final output
"${CC}" \
    -nostdlib \
    -fPIC \
    -fvisibility=hidden \
    -Os \
    -fno-stack-protector \
    -fno-asynchronous-unwind-tables \
    -shared \
    -Wl,--version-script="${SCRIPT_DIR}/vdso.lds" \
    -Wl,-Bsymbolic \
    -Wl,-soname,linux-vdso.so.1 \
    -Wl,-s \
    -o "${OUT}" \
    "${SCRIPT_DIR}/vdso.c"

echo "vDSO built: ${OUT} ($(wc -c < "${OUT}") bytes)"
