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
# Firefox runs with LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/disk/lib/firefox.
# The first entry is searched before /lib64, so any older copy of these
# stubs at the multiarch path takes precedence.  We install the freshly
# generated stubs to BOTH locations so the runtime always picks the
# current version regardless of LD_LIBRARY_PATH order.
DISK_MULTIARCH="${BUILD_DIR}/disk/lib/x86_64-linux-gnu"
FF_DIR="${BUILD_DIR}/disk/opt/firefox"
STUB_DIR="${BUILD_DIR}/firefox-stubs"

FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
    esac
done

mkdir -p "${STUB_DIR}" "${DISK_LIB64}" "${DISK_MULTIARCH}"

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

    if [ -f "${DISK_LIB64}/${soname}" ] && [ -f "${DISK_MULTIARCH}/${soname}" ] && [ "${FORCE}" = false ]; then
        log "  ${soname} already present — skip (use --force to rebuild)"
        return 0
    fi

    # -lc: allocator stubs forward to glibc malloc/free, so we need libc.
    # -nostartfiles keeps the stub tiny (no crt0 overhead) while still
    # allowing libc function calls via the PLT.
    local gcc_args=(-shared -fPIC -nostartfiles -o "${out}" "${c_src}"
                    -Wl,-soname,"${soname}" -lc)
    if [ -n "${vscript}" ]; then
        gcc_args+=(-Wl,--version-script="${vscript}")
    fi

    if gcc "${gcc_args[@]}" 2>/dev/null; then
        cp "${out}" "${DISK_LIB64}/${soname}"
        cp "${out}" "${DISK_MULTIARCH}/${soname}"
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
# Symbols are classified into categories that get appropriate stub bodies
# instead of a blanket NULL return, so Firefox progresses further into init.
python3 - "${LIBXUL}" "${LIBMOZGTK}" "${STUB_DIR}" << 'PYEOF'
import subprocess, sys, os, collections, re

libxul    = sys.argv[1]
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

# ── Library classifier ────────────────────────────────────────────────────────
def classify_lib(name):
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

# ── Symbol-body classifier ────────────────────────────────────────────────────
# Returns a string: one of 'alloc', 'free', 'strdup', 'strdup_printf',
# 'strndup', 'realloc', 'slice_alloc', 'slice_free', 'bool_true',
# 'ref_passthrough', 'unref_noop', 'opaque_ptr', 'null' (default).

# Exact-name overrides take priority over pattern matching.
_EXACT_CATEGORY = {
    # --- allocators ---
    'g_malloc':            'alloc',
    'g_malloc0':           'alloc0',
    'g_malloc_n':          'alloc',
    'g_try_malloc':        'alloc',
    'g_try_malloc0':       'alloc0',
    'g_realloc':           'realloc',
    'g_try_realloc':       'realloc',
    'g_free':              'free',
    'g_slice_alloc':       'slice_alloc',
    'g_slice_alloc0':      'slice_alloc0',
    'g_slice_free1':       'slice_free',
    # --- string helpers ---
    'g_strdup':            'strdup',
    'g_strndup':           'strndup',
    'g_strdup_printf':     'strdup_printf',
    'g_strdup_vprintf':    'strdup_printf',
    # --- bool-success inits ---
    'gtk_init_check':      'bool_true',
    'gtk_init':            'void_noop',
    # gtk_parse_args returns gboolean (TRUE on success). Default 'null'
    # → 0 = FALSE makes XREMain::XRE_mainStartup take the `if
    # (!gtk_parse_args(...)) return 1;` branch at nsAppRunner.cpp:4820,
    # ending the process with exit_group(1) before any widget setup.
    # Spec: GTK3 docs — gtk_parse_args() — TRUE if init successful.
    'gtk_parse_args':      'bool_true',
    # gdk_display_open / gdk_display_get_default deliberately keep the
    # default 'null' classifier (return NULL).  Returning an opaque_ptr
    # convinces GTK init dependents that the X display is valid and they
    # then busy-loop trying to use it, hanging dlopen.  NULL is the
    # canonical "no display, run without one" signal.
    'g_thread_init':       'void_noop',
    'g_thread_init_with_errorcheck_mutexes': 'void_noop',
    # --- ref / unref ---
    'g_object_ref':        'ref_passthrough',
    'g_object_ref_sink':   'ref_passthrough',
    'g_type_class_ref':    'ref_passthrough',
    'g_type_class_peek':   'ref_passthrough',
    'g_object_unref':      'unref_noop',
    'g_type_class_unref':  'unref_noop',
    # --- opaque object constructors ---
    'g_object_new':        'opaque_ptr',
    'gtk_window_new':      'opaque_ptr',
    'gtk_style_context_new': 'opaque_ptr',
    'cairo_create':        'opaque_ptr',
    'g_type_register_static': 'opaque_ptr',
    'g_type_register_static_simple': 'opaque_ptr',
}

# Pattern-based rules applied when no exact match.
# Each entry: (compiled_regex, category)
_PATTERN_RULES = [
    # allocators: names ending with _new, _alloc, _malloc, _calloc
    (re.compile(r'(?:_new|_alloc|_malloc|_calloc)$'),          'opaque_ptr'),
    # free/unref: names ending with _free, _unref, _destroy, _close, _release
    (re.compile(r'(?:_free|_unref|_destroy|_close|_release)$'), 'unref_noop'),
    # ref: names ending with _ref or _ref_sink
    (re.compile(r'_ref(?:_sink)?$'),                            'ref_passthrough'),
    # boolean init checks ending _check
    (re.compile(r'_init_check$'),                               'bool_true'),
    # void inits
    (re.compile(r'_init$'),                                     'void_noop'),
]

def classify_body(name):
    if name in _EXACT_CATEGORY:
        return _EXACT_CATEGORY[name]
    for pat, cat in _PATTERN_RULES:
        if pat.search(name):
            return cat
    return 'null'

# ── C body emitter ────────────────────────────────────────────────────────────
# We emit a single variadic signature `void* name(...)` for almost everything —
# this avoids argument-count mismatches at the ABI level.  The few exceptions
# that need typed signatures (free, strdup, etc.) are handled explicitly.

# Static placeholder object that opaque-ptr stubs can point to — valid read-
# only memory that survives the lifetime of the process.  Using a single global
# avoids returning stack addresses.
_C_PREAMBLE = """\
/* AstryxOS smart stub — {lib}
 * Generated by install-firefox-stubs.sh for headless Firefox ESR 115.
 * Symbols are classified into categories with plausible return values so
 * Firefox progresses further into GTK/GLib init before hitting real missing
 * functionality. */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/* Singleton placeholder: returned by object-constructor stubs.
 * Read-only, always non-NULL, safe to pass back into unref/free stubs. */
static const int _stub_placeholder = 0;

"""

def emit_stub(name, cat):
    """Return C source lines for one stub function."""
    if cat == 'alloc':
        # g_malloc(gsize n) — forward to malloc, same ABI (size_t arg)
        return (
            f'void* {name}(unsigned long n) {{\n'
            f'    return malloc((size_t)n);\n'
            f'}}\n'
        )
    elif cat == 'alloc0':
        return (
            f'void* {name}(unsigned long n) {{\n'
            f'    return calloc(1, (size_t)n);\n'
            f'}}\n'
        )
    elif cat == 'realloc':
        return (
            f'void* {name}(void* p, unsigned long n) {{\n'
            f'    return realloc(p, (size_t)n);\n'
            f'}}\n'
        )
    elif cat == 'free':
        return (
            f'void {name}(void* p) {{\n'
            f'    free(p);\n'
            f'}}\n'
        )
    elif cat == 'slice_alloc':
        return (
            f'void* {name}(unsigned long block_size) {{\n'
            f'    return malloc((size_t)block_size);\n'
            f'}}\n'
        )
    elif cat == 'slice_alloc0':
        return (
            f'void* {name}(unsigned long block_size) {{\n'
            f'    return calloc(1, (size_t)block_size);\n'
            f'}}\n'
        )
    elif cat == 'slice_free':
        return (
            f'void {name}(unsigned long block_size, void* mem_block) {{\n'
            f'    (void)block_size;\n'
            f'    free(mem_block);\n'
            f'}}\n'
        )
    elif cat == 'strdup':
        return (
            f'char* {name}(const char* s) {{\n'
            f'    if (!s) return (char*)malloc(1);\n'
            f'    size_t n = strlen(s) + 1;\n'
            f'    char* d = (char*)malloc(n);\n'
            f'    if (d) memcpy(d, s, n);\n'
            f'    return d;\n'
            f'}}\n'
        )
    elif cat == 'strndup':
        return (
            f'char* {name}(const char* s, unsigned long n) {{\n'
            f'    if (!s) return (char*)calloc(1, 1);\n'
            f'    size_t len = strnlen(s, (size_t)n);\n'
            f'    char* d = (char*)malloc(len + 1);\n'
            f'    if (d) {{ memcpy(d, s, len); d[len] = \'\\0\'; }}\n'
            f'    return d;\n'
            f'}}\n'
        )
    elif cat == 'strdup_printf':
        # g_strdup_printf(fmt, ...) — use vasprintf
        return (
            f'char* {name}(const char* fmt, ...) {{\n'
            f'    va_list ap;\n'
            f'    char* out = (char*)malloc(1);\n'
            f'    if (out) out[0] = \'\\0\';\n'
            f'    if (!fmt) return out;\n'
            f'    va_start(ap, fmt);\n'
            f'    char* tmp = (char*)malloc(4096);\n'
            f'    if (tmp) {{\n'
            f'        vsnprintf(tmp, 4096, fmt, ap);\n'
            f'        free(out);\n'
            f'        out = tmp;\n'
            f'    }}\n'
            f'    va_end(ap);\n'
            f'    return out;\n'
            f'}}\n'
        )
    elif cat == 'bool_true':
        # Returns int 1 (TRUE) — init-check functions
        return (
            f'int {name}(...) {{\n'
            f'    return 1;\n'
            f'}}\n'
        )
    elif cat == 'void_noop':
        return (
            f'void {name}(...) {{\n'
            f'}}\n'
        )
    elif cat == 'ref_passthrough':
        # g_object_ref(gpointer obj) — return the same pointer
        return (
            f'void* {name}(void* obj) {{\n'
            f'    return obj ? obj : (void*)&_stub_placeholder;\n'
            f'}}\n'
        )
    elif cat == 'unref_noop':
        # g_object_unref — ignore, free stubs are separate
        return (
            f'void {name}(...) {{\n'
            f'}}\n'
        )
    elif cat == 'opaque_ptr':
        # Returns a non-NULL placeholder pointer — object constructors,
        # type-system functions, etc.
        return (
            f'void* {name}(...) {{\n'
            f'    return (void*)&_stub_placeholder;\n'
            f'}}\n'
        )
    else:  # 'null' — original behaviour
        return (
            f'void* {name}(...) {{\n'
            f'    return (void*)0;\n'
            f'}}\n'
        )

# ── Group symbols by library ──────────────────────────────────────────────────
by_lib = collections.defaultdict(dict)  # lib -> {name: version}
for name, ver in undef.items():
    lib = classify_lib(name)
    if lib:
        by_lib[lib][name] = ver

# ── Write .c stubs + version scripts ─────────────────────────────────────────
for lib, syms in sorted(by_lib.items()):
    safe   = lib.replace('.', '_').replace('-', '_')
    c_path = os.path.join(stub_dir, f'stub_{safe}.c')
    vs_path = os.path.join(stub_dir, f'stub_{safe}.vscript')

    # Count per category for the log line
    cat_counts = collections.Counter()

    with open(c_path, 'w') as f:
        f.write(_C_PREAMBLE.format(lib=lib))
        for name in sorted(syms):
            cat = classify_body(name)
            cat_counts[cat] += 1
            f.write(emit_stub(name, cat))
            f.write('\n')
        f.write('void __attribute__((weak)) __gmon_start__(void) {}\n')

    # Version script
    by_ver = collections.defaultdict(set)
    for name, ver in syms.items():
        by_ver[ver if ver else ''].add(name)

    has_versions = any(v for v in by_ver)

    if has_versions:
        with open(vs_path, 'w') as f:
            for ver, names in sorted(by_ver.items()):
                if not ver:
                    continue
                f.write(f'{ver} {{\n  global:\n')
                for n in sorted(names):
                    f.write(f'    {n};\n')
                f.write('  local: *;\n};\n\n')
            if '' in by_ver:
                f.write('{\n  global:\n')
                for n in sorted(by_ver['']):
                    f.write(f'    {n};\n')
                f.write('  __gmon_start__;\n')
                f.write('  local: *;\n};\n')
    else:
        with open(vs_path, 'w') as f:
            f.write('{\n  global:\n')
            for n in sorted(syms):
                f.write(f'    {n};\n')
            f.write('  __gmon_start__;\n')
            f.write('  local: *;\n};\n')

    summary = ' '.join(f'{k}={v}' for k, v in sorted(cat_counts.items()) if v)
    print(f"[FF-STUBS]   {lib} ({len(syms)} syms: {summary})")

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

# ── Always-required empty stubs ───────────────────────────────────────────────
# These libraries appear in libxul.so's DT_NEEDED list but import zero symbols
# that can be attributed to them by the classify() function above (because the
# actual callers go through gdk/gtk wrappers, etc.).  ld-linux still refuses to
# start the process if the .so file is absent — so we emit empty stubs here.
declare -A FORCED_STUBS=(
    [libXrender.so.1]="stub_libXrender_so_1"
    [libXtst.so.6]="stub_libXtst_so_6"
    [libXcursor.so.1]="stub_libXcursor_so_1"
    [libpangocairo-1.0.so.0]="stub_libpangocairo_1_0_so_0"
)

for soname in "${!FORCED_STUBS[@]}"; do
    base="${FORCED_STUBS[$soname]}"
    c_src="${STUB_DIR}/${base}.c"
    if [ ! -f "${c_src}" ]; then
        cat > "${c_src}" << EOF
/* AstryxOS empty stub: ${soname} — satisfies DT_NEEDED without real symbols. */
void __attribute__((weak)) __gmon_start__(void) {}
EOF
    fi
    build_stub "${soname}" "${c_src}" ""
done

log "Done.  Stubs are in ${DISK_LIB64}/"
log "Re-run create-data-disk.sh --force to embed them in the FAT32 image."
