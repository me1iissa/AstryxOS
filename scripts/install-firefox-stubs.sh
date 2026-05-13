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
    # --- process spawning ---
    # Mozilla calls g_spawn_async_with_pipes() to launch the glxtest /
    # vaapitest helper binaries.  A 'null' stub returns 0 (FALSE) but the
    # caller still polls the (uninitialised) stdout fd, hangs for the
    # 4-second timeout, then NULL-derefs in the no-GPU fallback path.
    # The 'spawn_with_pipes' body forwards to posix_spawn so the child
    # actually runs and writes its result.  Spec: GLib docs —
    # https://docs.gtk.org/glib/func.spawn_async_with_pipes.html
    'g_spawn_async_with_pipes': 'spawn_with_pipes',
    'g_spawn_async':            'spawn_async',
    'g_spawn_sync':             'spawn_sync',
    'g_spawn_command_line_async': 'spawn_command_line_async',
    'g_spawn_command_line_sync':  'spawn_command_line_sync',
    'g_spawn_close_pid':        'void_noop',
    'g_spawn_check_exit_status':'bool_true',
    'g_spawn_check_wait_status':'bool_true',
    # --- fontconfig: pointer-returning entries Mozilla's font-list init
    # path expects to be non-NULL.  These either don't match the
    # constructor pattern rule (no trailing _new) or are getters that
    # legitimately produce FcConfig* / FcFontSet* / FcPattern* objects.
    #
    # gfxFcPlatformFontList walks systemFonts->nfont in a for-loop and
    # asserts MOZ_RELEASE_ASSERT(mFontFamilies.Count() > 0) at the end.
    # If nfont==0 the loop body never runs, mFontFamilies stays empty,
    # and the assert fires when GetDefaultFontFamily falls back.  We
    # therefore route FcConfigGetFonts / FcFontList / FcFontSort to the
    # 'fcfontset_one' stub — a single-element FcFontSet pointing at a
    # real-ish FcPattern for DejaVu Sans, so the iterator finds exactly
    # one font and AddPatternToFontList inserts one mFontFamilies entry.
    # FcFontMatch / FcFontRenderPrepare return the same pattern.  Spec:
    # https://fontconfig.org/fontconfig-devel/fcfontsetcreate.html and
    # https://fontconfig.org/fontconfig-devel/fcpatterncreate.html.
    'FcPatternCreate':         'opaque_ptr',
    'FcPatternDuplicate':      'opaque_ptr',
    'FcNameParse':             'opaque_ptr',
    'FcObjectSetBuild':        'opaque_ptr',
    'FcConfigGetCurrent':      'opaque_ptr',
    'FcConfigGetFonts':        'fcfontset_one',
    'FcConfigReference':       'opaque_ptr',
    'FcFontList':              'fcfontset_one',
    'FcFontMatch':             'fcpattern_one',
    'FcFontSort':              'fcfontset_one',
    'FcFontRenderPrepare':     'fcpattern_one',
    # FcPatternGet* — typed stubs that return FcResult (int).
    #
    # Mozilla's gfxFontconfigFontEntry / gfxFontconfigUtils helpers call
    # FcPatternGetBool/Integer/Double on the FcPattern result of
    # FcFontMatch / FcFontRenderPrepare, then on EVERY return path check
    # `if (result) { /* failure */ }`.  Several of those failure branches
    # then write back into the pattern pointer (`pat->flags |= FOO`) —
    # which faults if `pat` is NULL (i.e. the caller passed an
    # uninitialised handle on the no-pattern path).
    #
    # The 'fc_no_match' classifier returns 1 = FcResultNoMatch unmodified,
    # which is spec-correct but pushes Mozilla into those NULL-deref
    # failure branches.  Pre-PR-#172 the default 'null' classifier
    # returned 0 = FcResultMatch and left `*[arg4]` uninitialised; on the
    # lucky-zero stack frame Mozilla took the success branch with b=0 and
    # never derefed the NULL pattern, which is why the issue was hidden.
    #
    # The 'fc_get_*_zero' classifiers reproduce that lucky-zero behaviour
    # deterministically: populate `*[arg4]` with a zero value of the
    # correct type, then return 0 = FcResultMatch.  Mozilla takes the
    # success branch with b=0/i=0/d=0.0, doesn't touch the (possibly
    # NULL) pattern pointer, and continues init.
    #
    # FcPatternGetString already has a typed populate-output body
    # (recognises the DejaVu Sans sentinel pattern, writes a real
    # path/family for FC_FILE / FC_FAMILY).  FcPatternGetCharSet /
    # LangSet / FTFace remain on 'fc_no_match' — their callers in
    # Mozilla's font-list path handle the NoMatch return cleanly and do
    # not write back into the (possibly NULL) pattern.
    #
    # Spec: https://fontconfig.org/fontconfig-devel/fcpatternget.html
    'FcPatternGetString':      'fc_pattern_get_string',
    'FcPatternGetBool':        'fc_get_bool_zero',
    'FcPatternGetInteger':     'fc_get_int_zero',
    'FcPatternGetDouble':      'fc_get_double_zero',
    'FcPatternGetCharSet':     'fc_no_match',
    'FcPatternGetLangSet':     'fc_no_match',
    'FcPatternGetFTFace':      'fc_no_match',
    'FcPatternGet':            'fc_no_match',
    # FcNameUnparse returns char* (FcChar8*) — Mozilla wraps in
    # nsDependentCString which deref's the buffer; pointing at the
    # zeroed placeholder gives it a valid empty NUL-terminated string.
    'FcNameUnparse':           'opaque_ptr',
    # FcInitBringUptoDate returns FcBool — TRUE (1) keeps Mozilla's
    # init-success path; default 'null' returns 0/FALSE which can
    # trigger fallback paths that re-read the (still NULL) config.
    'FcInitBringUptoDate':     'bool_true',
    # FcGetVersion returns int (e.g. 21300 = "2.13.0"). gfxFcPlatformFontList
    # gates several "old fontconfig" code paths on FcGetVersion() < 20900.
    # Default 'null' returns 0, which forces the OLD path that then calls
    # FcNameUnparse and constructs nsDependentCString on the result.
    # Returning a modern version steers Mozilla into the safer new path.
    # Spec: https://fontconfig.org/fontconfig-devel/fcgetversion.html
    'FcGetVersion':            'fc_version',
}

# Pattern-based rules applied when no exact match.
# Each entry: (compiled_regex, category)
#
# Conventions seen in libxul's undefined-symbol set:
#   *_new       — GLib/GTK/Pango idiom (lowercase, trailing _new)
#   *_alloc     — generic
#   *_create    — Cairo / XCB / wayland idiom (lowercase, trailing _create
#                 or _create_<variant> e.g. cairo_image_surface_create,
#                 cairo_image_surface_create_for_data)
#   *Create     — fontconfig / X11 idiom (CamelCase, trailing Create
#                 e.g. FcPatternCreate, XDamageCreate)
# Every one of these is a pointer-returning constructor that, when
# stubbed to return NULL, gives Mozilla a NULL ref-counted handle which
# is then dereferenced further in.  Classify them all as opaque_ptr so
# the stub returns the zeroed _stub_placeholder.
_PATTERN_RULES = [
    # constructors: names ending with _new, _alloc, _malloc, _calloc
    (re.compile(r'(?:_new|_alloc|_malloc|_calloc)$'),          'opaque_ptr'),
    # constructors (Cairo/XCB idiom): _create, or _create_<variant>
    # e.g. cairo_image_surface_create, cairo_image_surface_create_for_data
    (re.compile(r'_create(?:_[A-Za-z0-9_]+)?$'),               'opaque_ptr'),
    # constructors (fontconfig/X11 idiom): CamelCase Create — covers both
    # the SUFFIX form (FcPatternCreate, XDamageCreate, XFixesCreateRegion)
    # and the PREFIX form (XCreatePixmap, XCreateGC, XCreateBitmapFromData,
    # XCreateImage, XCreateWindow, XCreateColormap, XCreateRegion).
    # The leading char class is `[A-Z][A-Za-z0-9]*` (≥1 char) — previously
    # ≥2 chars, which silently excluded the X-prefix family.  All matched
    # names are pointer-returning constructors per the Xlib spec; returning
    # the zeroed _stub_placeholder is safe because Mozilla's worker init
    # paths use these results as opaque handles (Pixmap/GC/Colormap IDs
    # are XIDs treated as resources, not dereferenced in the stub library).
    # Spec: X11 protocol §10, Xlib programming manual.
    (re.compile(r'[A-Z][A-Za-z0-9]*Create(?:[A-Z][A-Za-z0-9]*)?$'), 'opaque_ptr'),
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
/* AstryxOS smart stub — __STUB_LIB__
 * Generated by install-firefox-stubs.sh for headless Firefox ESR 115.
 * Symbols are classified into categories with plausible return values so
 * Firefox progresses further into GTK/GLib init before hitting real missing
 * functionality. */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

/* Singleton placeholder: returned by object-constructor stubs.
 * Read-only, always non-NULL, safe to pass back into unref/free stubs.
 *
 * Sized at 128 bytes so callers that treat the result as a struct and
 * read fields beyond the first int (e.g. fontconfig FcFontSet has
 * {int nfont; int sfont; FcPattern **fonts;} — 16 bytes; nsRefPtr-wrapped
 * Mozilla iterators dereference offsets up to ~64 bytes during shape /
 * lang-tag walks) all observe zero values rather than adjacent rodata.
 * For pointer-returning getters this gives a safe "empty zero-initialised
 * object" without ever needing a real backing allocation.
 *
 * Spec: https://fontconfig.org/fontconfig-devel/fcfontsetcreate.html
 * (FcFontSet layout: nfont @ offset 0 — the loop-bound — drives every
 * Mozilla iterator that calls these stubs.) */
static const long _stub_placeholder[16] = {0};

/* ── FcFontSet one-element stub ───────────────────────────────────────────
 * Mozilla's gfxFcPlatformFontList iterates set->nfont; if the value is
 * zero the assert MOZ_RELEASE_ASSERT(mFontFamilies.Count() > 0) fires.
 * We expose a single-element FcFontSet whose only FcPattern is a typed
 * marker that FcPatternGetString recognises as "DejaVu Sans / file =
 * /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf".  AddFontSetFamilies
 * then calls access(F_OK|R_OK) on the path — the TTF is installed on
 * the data disk by create-data-disk.sh, so the access() succeeds and
 * one entry is inserted into mFontFamilies.  Layout per public spec:
 *   typedef struct _FcFontSet {
 *       int nfont;        // [+0] number of fonts in set
 *       int sfont;        // [+4] allocated capacity
 *       FcPattern **fonts;// [+8] array of pattern pointers
 *   } FcFontSet;
 * Spec: https://fontconfig.org/fontconfig-devel/fcfontset-type.html */

/* Sentinel value distinguishing the DejaVu pattern from _stub_placeholder.
 * FcPatternGetString reads this first word; if it matches, the typed
 * string-return path runs.  Other FcPattern* pointers fall through to
 * the generic NoMatch path. */
#define _STUB_FCPATTERN_MAGIC 0x5354554246434641UL  /* "AFCFBUTS" */

static const unsigned long _stub_fcpattern_one[8]
    __attribute__((unused)) = {
    _STUB_FCPATTERN_MAGIC, 0, 0, 0, 0, 0, 0, 0,
};

static void * const _stub_fcfontset_fonts[1]
    __attribute__((unused)) = {
    (void *)&_stub_fcpattern_one,
};

/* C99 designated initialisers keep the layout robust if FcFontSet ever
 * grows trailing fields.  We zero everything else and pin the three
 * fields the public ABI specifies. */
static const struct {
    int    nfont;
    int    sfont;
    void * fonts;
} _stub_fcfontset_one __attribute__((unused)) = {
    .nfont = 1,
    .sfont = 1,
    .fonts = (void *)_stub_fcfontset_fonts,
};

/* The single font we advertise.  Path matches the canonical Debian /
 * Ubuntu DejaVu install location and the build/disk staging path used
 * by create-data-disk.sh. */
static const char _stub_font_path[]   __attribute__((unused))
    = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf";
static const char _stub_font_family[] __attribute__((unused))
    = "DejaVu Sans";

/* GSpawnFlags bits we honour (spec: GLib docs — GSpawnFlags).
 * Others (LEAVE_DESCRIPTORS_OPEN, FILE_AND_ARGV_ZERO, etc.) are ignored —
 * Mozilla's glxtest/vaapitest callers don't set them. */
#define _GSPAWN_LEAVE_DESCRIPTORS_OPEN  (1 << 0)
#define _GSPAWN_DO_NOT_REAP_CHILD       (1 << 1)
#define _GSPAWN_SEARCH_PATH             (1 << 2)
#define _GSPAWN_STDOUT_TO_DEV_NULL      (1 << 3)
#define _GSPAWN_STDERR_TO_DEV_NULL      (1 << 4)
#define _GSPAWN_CHILD_INHERITS_STDIN    (1 << 5)
#define _GSPAWN_CLOEXEC_PIPES           (1 << 8)

/* Internal helper: build a posix_spawn-driven child given GLib semantics.
 * On success returns 0 and writes the child PID and (if requested) the
 * parent-side pipe fds.  On failure returns -errno and leaves the fd
 * out-parameters untouched.  No GError is allocated — callers that pass
 * a non-NULL **err set *err = NULL on success and leave it NULL on
 * failure (Mozilla checks the return value, not *err).
 *
 * Each of stdin_fd/stdout_fd/stderr_fd is one of:
 *   -1  → caller doesn't want a pipe (inherit or /dev/null per flags)
 *   non-NULL pointer → caller wants the parent-side fd written here. */
static int __attribute__((unused))
_stub_spawn_core(const char *working_directory,
                            char **argv,
                            char **envp,
                            int flags,
                            int *stdin_fd_out,
                            int *stdout_fd_out,
                            int *stderr_fd_out,
                            int *child_pid_out)
{
    if (!argv || !argv[0]) return -EINVAL;

    posix_spawn_file_actions_t fa;
    posix_spawnattr_t          sa;
    int rc;

    if ((rc = posix_spawn_file_actions_init(&fa)) != 0) return -rc;
    if ((rc = posix_spawnattr_init(&sa)) != 0) {
        posix_spawn_file_actions_destroy(&fa);
        return -rc;
    }

    int p_in[2]  = {-1, -1};
    int p_out[2] = {-1, -1};
    int p_err[2] = {-1, -1};
    int devnull_r = -1, devnull_w = -1;

    /* stdin: pipe (caller wants parent-write fd), inherit, or /dev/null. */
    if (stdin_fd_out) {
        if (pipe(p_in) != 0) { rc = -errno; goto fail; }
        posix_spawn_file_actions_adddup2(&fa, p_in[0], 0);
        posix_spawn_file_actions_addclose(&fa, p_in[0]);
        posix_spawn_file_actions_addclose(&fa, p_in[1]);
    } else if (!(flags & _GSPAWN_CHILD_INHERITS_STDIN)) {
        devnull_r = open("/dev/null", O_RDONLY);
        if (devnull_r >= 0) {
            posix_spawn_file_actions_adddup2(&fa, devnull_r, 0);
            posix_spawn_file_actions_addclose(&fa, devnull_r);
        }
    }

    /* stdout: pipe, /dev/null, or inherit. */
    if (stdout_fd_out) {
        if (pipe(p_out) != 0) { rc = -errno; goto fail; }
        posix_spawn_file_actions_adddup2(&fa, p_out[1], 1);
        posix_spawn_file_actions_addclose(&fa, p_out[1]);
        posix_spawn_file_actions_addclose(&fa, p_out[0]);
    } else if (flags & _GSPAWN_STDOUT_TO_DEV_NULL) {
        if (devnull_w < 0) devnull_w = open("/dev/null", O_WRONLY);
        if (devnull_w >= 0) {
            posix_spawn_file_actions_adddup2(&fa, devnull_w, 1);
        }
    }

    /* stderr: pipe, /dev/null, or inherit. */
    if (stderr_fd_out) {
        if (pipe(p_err) != 0) { rc = -errno; goto fail; }
        posix_spawn_file_actions_adddup2(&fa, p_err[1], 2);
        posix_spawn_file_actions_addclose(&fa, p_err[1]);
        posix_spawn_file_actions_addclose(&fa, p_err[0]);
    } else if (flags & _GSPAWN_STDERR_TO_DEV_NULL) {
        if (devnull_w < 0) devnull_w = open("/dev/null", O_WRONLY);
        if (devnull_w >= 0) {
            posix_spawn_file_actions_adddup2(&fa, devnull_w, 2);
        }
    }

    if (devnull_w >= 0)
        posix_spawn_file_actions_addclose(&fa, devnull_w);

    /* working directory — GLib spec: NULL means inherit caller's cwd.
     * posix_spawn_file_actions_addchdir_np is a glibc 2.29+ extension;
     * fall back to chdir() in the parent if absent.  Mozilla's helper
     * call passes NULL, so this is rarely exercised. */
    (void)working_directory;

    char **env = envp ? envp : environ;
    pid_t pid = 0;

    if (flags & _GSPAWN_SEARCH_PATH) {
        rc = posix_spawnp(&pid, argv[0], &fa, &sa, argv, env);
    } else {
        rc = posix_spawn(&pid, argv[0], &fa, &sa, argv, env);
    }
    if (rc != 0) { rc = -rc; goto fail; }

    /* Parent: close child-side fds, return parent-side fds. */
    if (p_in[0]  >= 0) close(p_in[0]);
    if (p_out[1] >= 0) close(p_out[1]);
    if (p_err[1] >= 0) close(p_err[1]);
    if (devnull_r >= 0) close(devnull_r);
    if (devnull_w >= 0) close(devnull_w);

    if (stdin_fd_out)  *stdin_fd_out  = p_in[1];
    if (stdout_fd_out) *stdout_fd_out = p_out[0];
    if (stderr_fd_out) *stderr_fd_out = p_err[0];
    if (child_pid_out) *child_pid_out = (int)pid;

    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&sa);
    return 0;

fail:
    if (p_in[0]  >= 0) close(p_in[0]);
    if (p_in[1]  >= 0) close(p_in[1]);
    if (p_out[0] >= 0) close(p_out[0]);
    if (p_out[1] >= 0) close(p_out[1]);
    if (p_err[0] >= 0) close(p_err[0]);
    if (p_err[1] >= 0) close(p_err[1]);
    if (devnull_r >= 0) close(devnull_r);
    if (devnull_w >= 0) close(devnull_w);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&sa);
    return rc;
}

/* Drain an fd into a malloc'd, NUL-terminated buffer.  Caller owns the
 * returned pointer.  Returns NULL on alloc failure. */
static char *__attribute__((unused))
_stub_drain_fd(int fd, size_t *len_out)
{
    size_t cap = 4096, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len + 1 >= cap) {
            size_t nc = cap * 2;
            char *nb = (char*)realloc(buf, nc);
            if (!nb) { free(buf); return NULL; }
            buf = nb; cap = nc;
        }
        ssize_t n = read(fd, buf + len, cap - len - 1);
        if (n > 0) { len += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    buf[len] = '\0';
    if (len_out) *len_out = len;
    return buf;
}

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
    elif cat == 'fcfontset_one':
        # FcConfigGetFonts / FcFontList / FcFontSort — return the
        # singleton one-element FcFontSet so Mozilla's per-font iterator
        # finds exactly one entry.  Variadic signature handles the
        # different argument counts (FcConfigGetFonts takes 2, FcFontList
        # takes 4, FcFontSort takes 5).  Spec:
        # https://fontconfig.org/fontconfig-devel/fcconfiggetfonts.html
        return (
            f'void* {name}(...) {{\n'
            f'    return (void*)&_stub_fcfontset_one;\n'
            f'}}\n'
        )
    elif cat == 'fcpattern_one':
        # FcFontMatch / FcFontRenderPrepare — return the singleton
        # DejaVu Sans FcPattern.  Mozilla's render-pattern path then
        # calls FcPatternGetString(p, FC_FILE, ...) which our typed
        # stub satisfies.  Spec:
        # https://fontconfig.org/fontconfig-devel/fcfontmatch.html
        return (
            f'void* {name}(...) {{\n'
            f'    return (void*)&_stub_fcpattern_one;\n'
            f'}}\n'
        )
    elif cat == 'fc_no_match':
        # FcPatternGet* (CharSet / LangSet / FTFace / generic) — return
        # FcResultNoMatch (1) so Mozilla treats the field as absent and
        # falls through to its default-handling branches.  Critically
        # NOT 'null' (which returns 0 = FcResultMatch and leaves the
        # out-pointer uninitialised, causing downstream UB).  Spec:
        # https://fontconfig.org/fontconfig-devel/fcresult.html
        return (
            f'int {name}(...) {{\n'
            f'    return 1; /* FcResultNoMatch */\n'
            f'}}\n'
        )
    elif cat == 'fc_get_bool_zero':
        # FcResult FcPatternGetBool(const FcPattern *p, const char
        # *object, int id, FcBool *b).  Populate *b with FcFalse (0)
        # and return FcResultMatch (0) so Mozilla takes the success
        # branch with b == 0 and never falls into failure paths that
        # may dereference the (possibly NULL) pattern pointer to set
        # error flags (orb $0x2, 0x9c(%rbx) at libxul+0x185b8a4).
        # The NULL-out-pointer guard returns NoMatch — if the caller
        # didn't supply a buffer they can't read uninitialised data.
        # Spec: https://fontconfig.org/fontconfig-devel/fcpatterngetbool.html
        # (FcBool is int per fontconfig.h.)
        return (
            f'int {name}(const void* p, const char* object, int id, int* b) {{\n'
            f'    (void)p; (void)object; (void)id;\n'
            f'    if (!b) return 1; /* defensive: NULL out-pointer → NoMatch */\n'
            f'    *b = 0; /* FcFalse */\n'
            f'    return 0; /* FcResultMatch */\n'
            f'}}\n'
        )
    elif cat == 'fc_get_int_zero':
        # FcResult FcPatternGetInteger(const FcPattern *p, const char
        # *object, int id, int *i).  Same shape as fc_get_bool_zero:
        # populate *i with 0 and return Match.  Spec:
        # https://fontconfig.org/fontconfig-devel/fcpatterngetinteger.html
        return (
            f'int {name}(const void* p, const char* object, int id, int* i) {{\n'
            f'    (void)p; (void)object; (void)id;\n'
            f'    if (!i) return 1;\n'
            f'    *i = 0;\n'
            f'    return 0;\n'
            f'}}\n'
        )
    elif cat == 'fc_get_double_zero':
        # FcResult FcPatternGetDouble(const FcPattern *p, const char
        # *object, int id, double *d).  Populate *d with 0.0 and return
        # Match.  Spec:
        # https://fontconfig.org/fontconfig-devel/fcpatterngetdouble.html
        return (
            f'int {name}(const void* p, const char* object, int id, double* d) {{\n'
            f'    (void)p; (void)object; (void)id;\n'
            f'    if (!d) return 1;\n'
            f'    *d = 0.0;\n'
            f'    return 0;\n'
            f'}}\n'
        )
    elif cat == 'fc_pattern_get_string':
        # FcResult FcPatternGetString(const FcPattern *p, const char
        # *object, int id, FcChar8 **s).  Returns FcResultMatch (0) for
        # FC_FILE / FC_FAMILY queries against the DejaVu Sans pattern
        # and FcResultNoMatch (1) otherwise.  Only id == 0 satisfies a
        # match — the per-language loops in FindCanonicalNameIndex /
        # AddPatternToFontList's otherFamilyNames walk increment id
        # past zero and need the NoMatch to terminate.  Spec:
        # https://fontconfig.org/fontconfig-devel/fcpatterngetstring.html
        return (
            f'int {name}(const void* p, const char* object, int id, const char** out) {{\n'
            f'    if (!out) return 1;\n'
            f'    *out = (const char*)0;\n'
            f'    /* Only the DejaVu pattern carries real strings.  Other\n'
            f'     * FcPattern pointers (e.g. _stub_placeholder) fall through. */\n'
            f'    if (!p) return 1;\n'
            f'    const unsigned long* w = (const unsigned long*)p;\n'
            f'    if (w[0] != {hex(0x5354554246434641)}UL) return 1;\n'
            f'    if (id != 0 || !object) return 1;\n'
            f'    if (strcmp(object, "file") == 0) {{\n'
            f'        *out = _stub_font_path;\n'
            f'        return 0;\n'
            f'    }}\n'
            f'    if (strcmp(object, "family") == 0) {{\n'
            f'        *out = _stub_font_family;\n'
            f'        return 0;\n'
            f'    }}\n'
            f'    return 1;\n'
            f'}}\n'
        )
    elif cat == 'fc_version':
        # FcGetVersion() returns int (encoded major*10000+minor*100+rev).
        # 21300 = fontconfig 2.13.0 — picked to (a) clear the < 20900
        # legacy-fontconfig branch at gfxFcPlatformFontList:1673 and
        # (b) avoid the 21094..21101 charset-parse-bug range. Spec:
        # https://fontconfig.org/fontconfig-devel/fcgetversion.html
        return (
            f'int {name}(void) {{\n'
            f'    return 21300;\n'
            f'}}\n'
        )
    elif cat == 'spawn_with_pipes':
        # g_spawn_async_with_pipes(working_directory, argv, envp, flags,
        #     child_setup, user_data,
        #     *child_pid, *stdin_fd, *stdout_fd, *stderr_fd, **error)
        # Spec: https://docs.gtk.org/glib/func.spawn_async_with_pipes.html
        # Returns gboolean (1 on success).  child_setup is ignored — Mozilla
        # passes NULL for the glxtest call path.
        return (
            f'int {name}(const char* working_directory,\n'
            f'             char** argv, char** envp, int flags,\n'
            f'             void* child_setup, void* user_data,\n'
            f'             int* child_pid,\n'
            f'             int* stdin_fd, int* stdout_fd, int* stderr_fd,\n'
            f'             void** error) {{\n'
            f'    (void)child_setup; (void)user_data;\n'
            f'    if (error) *error = (void*)0;\n'
            f'    int rc = _stub_spawn_core(working_directory, argv, envp,\n'
            f'                              flags,\n'
            f'                              stdin_fd, stdout_fd, stderr_fd,\n'
            f'                              child_pid);\n'
            f'    return rc == 0 ? 1 : 0;\n'
            f'}}\n'
        )
    elif cat == 'spawn_async':
        # g_spawn_async(working_directory, argv, envp, flags, child_setup,
        #     user_data, *child_pid, **error)
        return (
            f'int {name}(const char* working_directory,\n'
            f'             char** argv, char** envp, int flags,\n'
            f'             void* child_setup, void* user_data,\n'
            f'             int* child_pid, void** error) {{\n'
            f'    (void)child_setup; (void)user_data;\n'
            f'    if (error) *error = (void*)0;\n'
            f'    int rc = _stub_spawn_core(working_directory, argv, envp,\n'
            f'                              flags, (int*)0, (int*)0, (int*)0,\n'
            f'                              child_pid);\n'
            f'    return rc == 0 ? 1 : 0;\n'
            f'}}\n'
        )
    elif cat == 'spawn_sync':
        # g_spawn_sync(working_directory, argv, envp, flags, child_setup,
        #     user_data, **standard_output, **standard_error, *wait_status,
        #     **error)
        # Spec: https://docs.gtk.org/glib/func.spawn_sync.html
        # Captures stdout/stderr into freshly malloc'd buffers (caller owns)
        # then waitpid()s the child.
        return (
            f'int {name}(const char* working_directory,\n'
            f'             char** argv, char** envp, int flags,\n'
            f'             void* child_setup, void* user_data,\n'
            f'             char** standard_output, char** standard_error,\n'
            f'             int* wait_status, void** error) {{\n'
            f'    (void)child_setup; (void)user_data;\n'
            f'    if (error) *error = (void*)0;\n'
            f'    int out_fd = -1, err_fd = -1;\n'
            f'    int pid = 0;\n'
            f'    int rc = _stub_spawn_core(working_directory, argv, envp,\n'
            f'                              flags, (int*)0,\n'
            f'                              standard_output ? &out_fd : (int*)0,\n'
            f'                              standard_error  ? &err_fd : (int*)0,\n'
            f'                              &pid);\n'
            f'    if (rc != 0) return 0;\n'
            f'    if (standard_output) {{\n'
            f'        *standard_output = _stub_drain_fd(out_fd, (size_t*)0);\n'
            f'        close(out_fd);\n'
            f'    }}\n'
            f'    if (standard_error) {{\n'
            f'        *standard_error = _stub_drain_fd(err_fd, (size_t*)0);\n'
            f'        close(err_fd);\n'
            f'    }}\n'
            f'    int status = 0;\n'
            f'    while (waitpid(pid, &status, 0) < 0) {{\n'
            f'        if (errno != EINTR) break;\n'
            f'    }}\n'
            f'    if (wait_status) *wait_status = status;\n'
            f'    return 1;\n'
            f'}}\n'
        )
    elif cat == 'spawn_command_line_async':
        # g_spawn_command_line_async(command_line, **error) — splits on
        # whitespace and runs as if argv[0..n].  Mozilla doesn't call this
        # on the demo path, but include for completeness.  Splits on
        # single-byte whitespace only — no quoting / escape handling.
        return (
            f'int {name}(const char* command_line, void** error) {{\n'
            f'    if (error) *error = (void*)0;\n'
            f'    if (!command_line) return 0;\n'
            f'    char* dup = strdup(command_line);\n'
            f'    if (!dup) return 0;\n'
            f'    char* argv[64] = {{0}};\n'
            f'    int argc = 0;\n'
            f'    char* p = dup;\n'
            f'    while (*p && argc < 63) {{\n'
            f'        while (*p == \' \' || *p == \'\\t\') p++;\n'
            f'        if (!*p) break;\n'
            f'        argv[argc++] = p;\n'
            f'        while (*p && *p != \' \' && *p != \'\\t\') p++;\n'
            f'        if (*p) *p++ = \'\\0\';\n'
            f'    }}\n'
            f'    argv[argc] = (char*)0;\n'
            f'    int pid = 0;\n'
            f'    int rc = _stub_spawn_core((const char*)0, argv, (char**)0,\n'
            f'                              _GSPAWN_SEARCH_PATH,\n'
            f'                              (int*)0, (int*)0, (int*)0, &pid);\n'
            f'    free(dup);\n'
            f'    return rc == 0 ? 1 : 0;\n'
            f'}}\n'
        )
    elif cat == 'spawn_command_line_sync':
        # g_spawn_command_line_sync(command_line, **stdout, **stderr,
        #     *wait_status, **error)
        return (
            f'int {name}(const char* command_line,\n'
            f'             char** standard_output, char** standard_error,\n'
            f'             int* wait_status, void** error) {{\n'
            f'    if (error) *error = (void*)0;\n'
            f'    if (!command_line) return 0;\n'
            f'    char* dup = strdup(command_line);\n'
            f'    if (!dup) return 0;\n'
            f'    char* argv[64] = {{0}};\n'
            f'    int argc = 0;\n'
            f'    char* p = dup;\n'
            f'    while (*p && argc < 63) {{\n'
            f'        while (*p == \' \' || *p == \'\\t\') p++;\n'
            f'        if (!*p) break;\n'
            f'        argv[argc++] = p;\n'
            f'        while (*p && *p != \' \' && *p != \'\\t\') p++;\n'
            f'        if (*p) *p++ = \'\\0\';\n'
            f'    }}\n'
            f'    argv[argc] = (char*)0;\n'
            f'    int out_fd = -1, err_fd = -1;\n'
            f'    int pid = 0;\n'
            f'    int rc = _stub_spawn_core((const char*)0, argv, (char**)0,\n'
            f'                              _GSPAWN_SEARCH_PATH, (int*)0,\n'
            f'                              standard_output ? &out_fd : (int*)0,\n'
            f'                              standard_error  ? &err_fd : (int*)0,\n'
            f'                              &pid);\n'
            f'    free(dup);\n'
            f'    if (rc != 0) return 0;\n'
            f'    if (standard_output) {{\n'
            f'        *standard_output = _stub_drain_fd(out_fd, (size_t*)0);\n'
            f'        close(out_fd);\n'
            f'    }}\n'
            f'    if (standard_error) {{\n'
            f'        *standard_error = _stub_drain_fd(err_fd, (size_t*)0);\n'
            f'        close(err_fd);\n'
            f'    }}\n'
            f'    int status = 0;\n'
            f'    while (waitpid(pid, &status, 0) < 0) {{\n'
            f'        if (errno != EINTR) break;\n'
            f'    }}\n'
            f'    if (wait_status) *wait_status = status;\n'
            f'    return 1;\n'
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
        f.write(_C_PREAMBLE.replace('__STUB_LIB__', lib))
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
