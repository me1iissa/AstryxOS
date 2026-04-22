#!/usr/bin/env bash
#
# install-firefox-stubs.sh — Build minimal stub shared libraries for
# Firefox ESR 115 headless mode on AstryxOS.
#
# Firefox's libmozgtk.so and libxul.so have NEEDED entries for GTK3,
# ALSA, X11, GLib/GObject/GIO, Cairo, Pango, DBus, and other system
# libraries.  On a standard Linux desktop these come from the distro's
# package manager.  AstryxOS provides only the glibc core runtime;
# the remaining libraries do not exist on the data disk.
#
# In --headless mode Firefox never calls the vast majority of these
# functions (GTK widget creation, ALSA audio output, X11 rendering, etc.)
# but glibc's dynamic linker still resolves NEEDED entries and versioned
# symbol references at dlopen() time.  Without the stub files the linker
# prints "cannot open shared object file" or "undefined symbol" and the
# XPCOMGlue returns NS_ERROR_FAILURE, which makes Firefox exit 255 before
# any real work is done.
#
# Stubs are tiny ELF shared objects (~14–80 KiB) that:
#   - Have the correct SONAME so ld-linux finds them
#   - Export every symbol libmozgtk.so / libxul.so imports, as no-op stubs
#   - Declare the correct version nodes (e.g. ALSA_0.9, ALSA_0.9.0rc4)
#
# The stubs are placed in build/disk/lib64/ alongside glibc.  When
# create-data-disk.sh copies lib64/ to the FAT32 image the stubs go too.
#
# Usage:
#   ./scripts/install-firefox-stubs.sh          # Idempotent
#   ./scripts/install-firefox-stubs.sh --force  # Rebuild even if present
#
# Prerequisites:
#   gcc (host toolchain), readelf/nm (binutils)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DISK_LIB64="${BUILD_DIR}/disk/lib64"
FF_DIR="${BUILD_DIR}/disk/opt/firefox"
STUB_DIR="${BUILD_DIR}/firefox-stubs"

FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
    esac
done

mkdir -p "${STUB_DIR}" "${DISK_LIB64}"

# ── Helpers ──────────────────────────────────────────────────────────────────

log() { echo "[FF-STUBS] $*"; }

# Build one stub shared library.
#   $1  soname  (e.g. "libasound.so.2")
#   $2  c_src   (path to generated .c stub)
#   $3  vscript (path to GNU version script, or "" for none)
build_stub() {
    local soname="$1"
    local c_src="$2"
    local vscript="$3"
    local out="${STUB_DIR}/${soname}"

    if [ -f "${DISK_LIB64}/${soname}" ] && [ "${FORCE}" = false ]; then
        log "  ${soname} already present — skip (use --force to rebuild)"
        return 0
    fi

    local gcc_args=(-shared -fPIC -nostartfiles -o "${out}" "${c_src}"
                    -Wl,-soname,"${soname}")
    if [ -n "${vscript}" ]; then
        gcc_args+=(-Wl,--version-script="${vscript}")
    fi

    if gcc "${gcc_args[@]}" 2>/dev/null; then
        cp "${out}" "${DISK_LIB64}/${soname}"
        log "  ${soname}: $(stat -c%s "${out}") bytes"
    else
        log "  WARNING: failed to build stub for ${soname}"
    fi
}

# ── Common empty-stub template ────────────────────────────────────────────────
EMPTY_C="${STUB_DIR}/stub_empty.c"
cat > "${EMPTY_C}" << 'C_EOF'
/* AstryxOS empty stub: satisfies ld-linux NEEDED without providing real symbols. */
void __attribute__((weak)) __gmon_start__(void) {}
C_EOF

# ── Collect required symbols from libxul.so and libmozgtk.so ─────────────────
# Both libraries live in /opt/firefox/ on the data-disk staging tree.

LIBXUL="${FF_DIR}/libxul.so"
LIBMOZGTK="${FF_DIR}/libmozgtk.so"

if [ ! -f "${LIBXUL}" ]; then
    log "WARNING: ${LIBXUL} not found — skipping stub generation"
    log "         Run scripts/install-firefox.sh first"
    exit 0
fi

log "Collecting undefined symbols from libxul.so and libmozgtk.so ..."

# Python helper: generate stub .c and version scripts for each library.
python3 - "${LIBXUL}" "${LIBMOZGTK}" "${STUB_DIR}" << 'PYEOF'
import subprocess, sys, os, collections

libxul   = sys.argv[1]
libmozgtk = sys.argv[2]
stub_dir  = sys.argv[3]

def get_undef(path):
    """Return dict name->version for undefined dynamic symbols in 'path'."""
    r = subprocess.run(['nm', '-D', path], capture_output=True, text=True, timeout=60)
    out = {}
    for line in r.stdout.splitlines():
        if ' U ' not in line:
            continue
        sym = line.split(' U ')[-1].strip()
        if '@' in sym:
            name, ver = sym.split('@', 1)
        else:
            name, ver = sym, ''
        out[name] = ver
    return out

# Merge undefs from both libraries
undef = {}
for path in [libxul, libmozgtk]:
    if os.path.exists(path):
        undef.update(get_undef(path))

print(f"[FF-STUBS]   Total undefined symbols: {len(undef)}")

# Classify each symbol to its providing library (best-effort by name prefix).
def classify(name):
    p = name
    if p.startswith('snd_'):                       return 'libasound.so.2'
    if p.startswith('FT_') or p.startswith('FTC_'): return 'libfreetype.so.6'
    if p.startswith('Fc'):                          return 'libfontconfig.so.1'
    if p.startswith('pango_') and 'cairo' in p:    return 'libpangocairo-1.0.so.0'
    if p.startswith('pango_'):                      return 'libpango-1.0.so.0'
    if p.startswith('atk_'):                        return 'libatk-1.0.so.0'
    if p.startswith('cairo_gobject'):               return 'libcairo-gobject.so.2'
    if p.startswith('cairo_'):                      return 'libcairo.so.2'
    if p.startswith('gdk_pixbuf'):                  return 'libgdk_pixbuf-2.0.so.0'
    if p.startswith('dbus_g_'):                     return 'libdbus-glib-1.so.2'
    if p.startswith('dbus_'):                       return 'libdbus-1.so.3'
    if p.startswith('xcb_shm'):                     return 'libxcb-shm.so.0'
    if p.startswith('xcb_'):                        return 'libxcb.so.1'
    if p == 'XGetXCBConnection':                    return 'libX11-xcb.so.1'
    if p.startswith('Xcursor'):                     return 'libXcursor.so.1'
    if p.startswith('XI'):                          return 'libXi.so.6'
    if p.startswith('XComposite'):                  return 'libXcomposite.so.1'
    if p.startswith('XDamage'):                     return 'libXdamage.so.1'
    if p.startswith('XFixes'):                      return 'libXfixes.so.3'
    if p.startswith('XRR'):                         return 'libXrandr.so.2'
    if p.startswith('XRender'):                     return 'libXrender.so.1'
    if (p.startswith('XShm') or p.startswith('DPMS')):  return 'libXext.so.6'
    if p.startswith('gtk_'):                        return 'libgtk-3.so.0'
    if p.startswith('gdk_'):                        return 'libgdk-3.so.0'
    if p.startswith('g_io_') or p.startswith('g_file_') or p.startswith('g_socket') \
       or p.startswith('g_resolver') or p.startswith('g_cancellable') \
       or p.startswith('g_async') or p.startswith('g_app_info') \
       or p.startswith('g_content_type'):           return 'libgio-2.0.so.0'
    if p.startswith('g_object') or p.startswith('g_type') or p.startswith('g_value') \
       or p.startswith('g_signal') or p.startswith('g_closure') or p.startswith('g_param') \
       or p.startswith('g_initially') or p.startswith('g_cclosure') \
       or p.startswith('g_binding'):                return 'libgobject-2.0.so.0'
    if p.startswith('g_'):                          return 'libglib-2.0.so.0'
    if p.startswith('X'):                           return 'libX11.so.6'
    return None

# Group by library
by_lib = collections.defaultdict(dict)  # lib -> {name: version}
for name, ver in undef.items():
    lib = classify(name)
    if lib:
        by_lib[lib][name] = ver

# For each library: write .c stub + version script
for lib, syms in sorted(by_lib.items()):
    safe = lib.replace('.', '_').replace('-', '_')
    c_path  = os.path.join(stub_dir, f'stub_{safe}.c')
    vs_path = os.path.join(stub_dir, f'stub_{safe}.vscript')

    # Group by version
    by_ver = collections.defaultdict(set)
    for name, ver in syms.items():
        by_ver[ver if ver else ''].add(name)

    has_versions = any(v for v in by_ver)

    with open(c_path, 'w') as f:
        f.write(f'/* AstryxOS stub {lib} for headless Firefox ESR 115. */\n\n')
        for name in sorted(syms):
            f.write(f'void* {name}(void) {{ return (void*)0; }}\n')
        f.write('\nvoid __attribute__((weak)) __gmon_start__(void) {}\n')

    if has_versions:
        with open(vs_path, 'w') as f:
            # Write a version node for each distinct version tag
            for ver, names in sorted(by_ver.items()):
                if not ver:
                    continue
                f.write(f'{ver} {{\n  global:\n')
                for n in sorted(names):
                    f.write(f'    {n};\n')
                f.write('  local: *;\n};\n\n')
            # Also write an unversioned section for any unversioned symbols
            if '' in by_ver:
                f.write('{\n  global:\n')
                for n in sorted(by_ver['']):
                    f.write(f'    {n};\n')
                f.write('  __gmon_start__;\n')
                f.write('  local: *;\n};\n')
    else:
        # No versioned symbols: simple export-all version script
        with open(vs_path, 'w') as f:
            f.write('{\n  global:\n')
            for n in sorted(syms):
                f.write(f'    {n};\n')
            f.write('  __gmon_start__;\n')
            f.write('  local: *;\n};\n')

    print(f"[FF-STUBS]   Generated stubs for {lib} ({len(syms)} symbols)")

# Write a manifest of all libraries to build
libs_file = os.path.join(stub_dir, 'libs.txt')
with open(libs_file, 'w') as f:
    for lib in sorted(by_lib):
        f.write(lib + '\n')
print(f"[FF-STUBS] Wrote library list to {libs_file}")
PYEOF

# ── Build each stub ───────────────────────────────────────────────────────────
if [ ! -f "${STUB_DIR}/libs.txt" ]; then
    log "No libs.txt generated — nothing to build"
    exit 0
fi

log "Building stub shared libraries ..."
while IFS= read -r soname; do
    safe="${soname//./_}"
    safe="${safe//-/_}"
    c_src="${STUB_DIR}/stub_${safe}.c"
    vscript="${STUB_DIR}/stub_${safe}.vscript"
    [ -f "${c_src}" ] || continue
    vs_arg=""
    [ -f "${vscript}" ] && vs_arg="${vscript}"
    build_stub "${soname}" "${c_src}" "${vs_arg}"
done < "${STUB_DIR}/libs.txt"

log "Done.  Stubs are in ${DISK_LIB64}/"
log "Re-run create-data-disk.sh --force to embed them in the FAT32 image."
