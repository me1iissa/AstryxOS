/*
 * libfontconfig-interposer.so — defensive FcPatternGet* *out wrappers
 * and PKCS#11 v3.0 shims for libipcclientcerts.so.
 *
 * Real upstream libfontconfig follows the spec strictly: when an
 * FcPatternGet* getter returns a non-Match FcResult (e.g.
 * FcResultNoMatch == 1) the caller-supplied output pointer is left
 * untouched and the contents are undefined.  See:
 *   https://fontconfig.org/fontconfig-devel/fcpatternget.html
 *   https://fontconfig.org/fontconfig-devel/fcpatterngetbool.html
 *   https://fontconfig.org/fontconfig-devel/fcpatterngetinteger.html
 *   https://fontconfig.org/fontconfig-devel/fcpatterngetdouble.html
 *   https://fontconfig.org/fontconfig-devel/fcpatterngetmatrix.html
 *   https://fontconfig.org/fontconfig-devel/fcpatterngetcharset.html
 *   https://fontconfig.org/fontconfig-devel/fcpatterngetlangset.html
 *   https://fontconfig.org/fontconfig-devel/fcpatterngetftface.html
 *   https://fontconfig.org/fontconfig-devel/fcpatterngetrange.html
 *   https://fontconfig.org/fontconfig-devel/fcresult.html
 *
 * Firefox's gfxFcPlatformFontList per-language alias enumeration in
 * libxul (vaddr regions exhibited at +0x185b8a4 and +0x4056429 in the
 * shipping ESR 115 build) iterates a list of font slots, calling
 * FcPatternGet*(p, ..., id, &slot) for each id, and on the non-Match
 * path dereferences `*slot` unconditionally — slot still holds whatever
 * value the caller staged before the call, which is commonly NULL.
 * The result is a %rbx=NULL fault at the next `mov 0x..(%rbx), <reg>`
 * or `orb $.., 0x..(%rbx)` instruction.
 *
 * PR #188 fixed FcPatternGetString.  W128 traced the next post-#188
 * SIGSEGV cluster (libxul+0x4b8db40, libxul+0x2f99429) to the same
 * defect in the sister FcPatternGet* family.  This file wraps the full
 * FcPatternGet* family — it dlsym()s each real implementation from
 * libfontconfig.so.1 via RTLD_NEXT, calls through, and on the non-Match
 * path writes a defined sentinel value into *out so the buggy caller
 * dereferences a valid object instead of NULL.
 *
 * W137 found an additional failure mode: when the primary SIGSEGV is
 * caused by a corrupted FcPattern* (observed rbx=1 and rbx=4 — tiny
 * integer constants, not valid heap pointers), Mozilla's signal handler
 * re-enters FcPatternGet* with the same corrupted pointer, producing a
 * double-fault that prevents the crash diagnostic from printing.  The
 * fc_ptr_is_plausible() guard below catches this: any pointer below the
 * first readable page boundary (0x1000) is treated as corrupt and the
 * wrapper returns NoMatch with a safe sentinel immediately, without
 * calling into the real libfontconfig or touching the bad address.
 *
 * The interposer must be loaded before libfontconfig.so.1.  Inject via
 * LD_PRELOAD=/lib64/libfontconfig-interposer.so in the firefox-test
 * environment — set in kernel/src/gui/terminal.rs.  Real libfontconfig
 * remains in place for every other call.
 *
 * This is a userspace-side workaround for a Mozilla caller bug; the
 * upstream libfontconfig binary is never patched, preserving the
 * "no upstream binary edits" invariant.
 *
 * ── PKCS#11 v3.0 C_GetInterface shim ────────────────────────────────
 *
 * W212: Firefox's content process (pid=3) loads libipcclientcerts.so as
 * a PKCS#11 module.  NSS's module loader resolves C_GetInterface (the
 * PKCS#11 v3.0 entry point defined in OASIS PKCS #11 v3.0 §5.5) from
 * the loaded module handle.  libipcclientcerts.so only exports the v2.x
 * entry point C_GetFunctionList; C_GetInterface is absent.  NSS treats
 * the missing symbol as fatal → pid=3 SIGABRT.
 *
 * Fix: this interposer wraps dlsym().  When the caller looks up
 * "C_GetInterface" on any handle, we return a stub that returns
 * CKR_FUNCTION_NOT_SUPPORTED (0x54 per PKCS #11 v3.0 Table 1), telling
 * NSS that the module does not implement the v3.0 interface.  NSS then
 * falls back to the v2.x C_GetFunctionList path that libipcclientcerts
 * exports correctly.
 *
 * The interposer is already LD_PRELOADed before every Firefox child
 * process, so this wrapper fires for every dlsym() call in the process
 * regardless of which library issued it.
 *
 * Reference: OASIS PKCS #11 Cryptographic Token Interface Base
 * Specification v3.0 §5.5 C_GetInterface, §11 Return values.
 * https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* fontconfig public ABI (from <fontconfig/fontconfig.h>).
 *
 *   typedef int FcBool;
 *   typedef unsigned char FcChar8;
 *   typedef enum _FcResult {
 *       FcResultMatch, FcResultNoMatch, FcResultTypeMismatch,
 *       FcResultNoId,  FcResultOutOfMemory
 *   } FcResult;
 *   typedef struct _FcPattern FcPattern;
 *   typedef struct _FcMatrix  { double xx, xy, yx, yy; } FcMatrix;
 *   typedef struct _FcCharSet FcCharSet;
 *   typedef struct _FcLangSet FcLangSet;
 *   typedef struct _FcRange   FcRange;
 *   typedef struct FT_FaceRec_ *FT_Face;
 *
 *   FcResult FcPatternGetString (const FcPattern *, const char *, int, FcChar8 **);
 *   FcResult FcPatternGetBool   (const FcPattern *, const char *, int, FcBool *);
 *   FcResult FcPatternGetInteger(const FcPattern *, const char *, int, int *);
 *   FcResult FcPatternGetDouble (const FcPattern *, const char *, int, double *);
 *   FcResult FcPatternGetMatrix (const FcPattern *, const char *, int, FcMatrix **);
 *   FcResult FcPatternGetCharSet(const FcPattern *, const char *, int, FcCharSet **);
 *   FcResult FcPatternGetLangSet(const FcPattern *, const char *, int, FcLangSet **);
 *   FcResult FcPatternGetFTFace (const FcPattern *, const char *, int, FT_Face *);
 *   FcResult FcPatternGetRange  (const FcPattern *, const char *, int, FcRange **);
 */
typedef int           FcResult;
typedef int           FcBool;
typedef void          FcPattern;
typedef unsigned char FcChar8;
typedef struct { double xx, xy, yx, yy; } FcMatrix;
typedef void          FcCharSet;   /* opaque */
typedef void          FcLangSet;   /* opaque */
typedef void          FcRange;     /* opaque */
typedef void         *FT_Face;     /* opaque pointer */

#define FC_RESULT_MATCH       0
#define FC_RESULT_NO_MATCH    1

/* ────────────────────────────────────────────────────────────────────
 * Pointer plausibility guard (W137 double-fault prevention).
 *
 * When a primary SIGSEGV is caused by a corrupted FcPattern* — W137
 * observed rbx=1 and rbx=4, small integer constants never produced by
 * malloc — Mozilla's signal handler re-enters the same FcPatternGet*
 * wrapper with the identically corrupted pointer, causing a second
 * fault before the crash diagnostic can be printed.
 *
 * Any userspace heap or .data pointer will be above the first 4 KiB
 * page boundary (address 0x1000).  A pointer below that threshold
 * cannot be a valid FcPattern* and must be treated as corrupt.  We
 * return NoMatch with a safe sentinel immediately rather than passing
 * the bad address into libfontconfig or dereferencing it ourselves.
 *
 * The threshold is deliberately conservative — 0x1000 (4096).  Real
 * heap allocations on x86-64 Linux are at minimum around 0x100000 in
 * practice; 0x1000 gives a wide margin without risking false positives
 * on low-but-valid pointers such as .text or vDSO mappings.
 * ──────────────────────────────────────────────────────────────────── */
static inline int
fc_ptr_is_plausible(const void *p)
{
    return p != NULL && ((uintptr_t)p) >= 0x1000u;
}

/* ────────────────────────────────────────────────────────────────────
 * Sentinel storage for non-NULL writes on the NoMatch path.
 *
 * For string output we use a small NUL-terminated literal so a caller
 * that walks the bytes terminates on the first iteration.  For the
 * opaque struct outputs we provide an over-sized zero-initialised
 * buffer aligned to 8 bytes — large enough to cover any reasonable
 * field offset Mozilla might probe.  The identity matrix is a defined
 * value chosen because Mozilla applies it directly to glyph
 * transformations and an all-zero matrix would collapse glyph metrics.
 * ──────────────────────────────────────────────────────────────────── */

/* "DejaVu Sans" matches the family the firefox-stubs generator uses
 * for the in-process font list.  Reused by FcPatternGetString. */
static const FcChar8 fc_stub_family[] = "DejaVu Sans";

static FcMatrix      fc_stub_identity_matrix = { 1.0, 0.0, 0.0, 1.0 };
static unsigned char fc_stub_charset[256]    __attribute__((aligned(8))) = {0};
static unsigned char fc_stub_langset[256]    __attribute__((aligned(8))) = {0};
static unsigned char fc_stub_range[64]       __attribute__((aligned(8))) = {0};

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetString — string output.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetString_t)(const FcPattern *, const char *,
                                         int, FcChar8 **);

FcResult
FcPatternGetString(const FcPattern *p, const char *object, int n,
                   FcChar8 **s)
{
    static FcPatternGetString_t real = NULL;

    if (!real) {
        real = (FcPatternGetString_t)dlsym(RTLD_NEXT, "FcPatternGetString");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (s) *s = (FcChar8 *)fc_stub_family;
        return FC_RESULT_NO_MATCH;
    }

    if (!s) {
        return real ? real(p, object, n, s) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *s = (FcChar8 *)fc_stub_family;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, s);
    if (r != FC_RESULT_MATCH && *s == NULL) {
        *s = (FcChar8 *)fc_stub_family;
    }
    return r;
}

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetBool — int (FcBool) output.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetBool_t)(const FcPattern *, const char *,
                                       int, FcBool *);

FcResult
FcPatternGetBool(const FcPattern *p, const char *object, int n, FcBool *b)
{
    static FcPatternGetBool_t real = NULL;

    if (!real) {
        real = (FcPatternGetBool_t)dlsym(RTLD_NEXT, "FcPatternGetBool");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (b) *b = 0;
        return FC_RESULT_NO_MATCH;
    }

    if (!b) {
        return real ? real(p, object, n, b) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *b = 0;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, b);
    if (r != FC_RESULT_MATCH) {
        /* The spec leaves *b undefined on non-Match; choose 0 (FcFalse)
         * so callers that read the byte after a NoMatch see a defined
         * value instead of stack garbage. */
        *b = 0;
    }
    return r;
}

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetInteger — int output.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetInteger_t)(const FcPattern *, const char *,
                                          int, int *);

FcResult
FcPatternGetInteger(const FcPattern *p, const char *object, int n, int *i)
{
    static FcPatternGetInteger_t real = NULL;

    if (!real) {
        real = (FcPatternGetInteger_t)dlsym(RTLD_NEXT, "FcPatternGetInteger");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (i) *i = 0;
        return FC_RESULT_NO_MATCH;
    }

    if (!i) {
        return real ? real(p, object, n, i) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *i = 0;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, i);
    if (r != FC_RESULT_MATCH) {
        *i = 0;
    }
    return r;
}

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetDouble — double output.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetDouble_t)(const FcPattern *, const char *,
                                         int, double *);

FcResult
FcPatternGetDouble(const FcPattern *p, const char *object, int n, double *d)
{
    static FcPatternGetDouble_t real = NULL;

    if (!real) {
        real = (FcPatternGetDouble_t)dlsym(RTLD_NEXT, "FcPatternGetDouble");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (d) *d = 0.0;
        return FC_RESULT_NO_MATCH;
    }

    if (!d) {
        return real ? real(p, object, n, d) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *d = 0.0;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, d);
    if (r != FC_RESULT_MATCH) {
        *d = 0.0;
    }
    return r;
}

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetMatrix — FcMatrix* output.
 *
 * Mozilla feeds the returned matrix straight into glyph transforms;
 * the identity matrix is the safe defined value.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetMatrix_t)(const FcPattern *, const char *,
                                         int, FcMatrix **);

FcResult
FcPatternGetMatrix(const FcPattern *p, const char *object, int n, FcMatrix **m)
{
    static FcPatternGetMatrix_t real = NULL;

    if (!real) {
        real = (FcPatternGetMatrix_t)dlsym(RTLD_NEXT, "FcPatternGetMatrix");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (m) *m = &fc_stub_identity_matrix;
        return FC_RESULT_NO_MATCH;
    }

    if (!m) {
        return real ? real(p, object, n, m) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *m = &fc_stub_identity_matrix;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, m);
    if (r != FC_RESULT_MATCH && *m == NULL) {
        *m = &fc_stub_identity_matrix;
    }
    return r;
}

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetCharSet — opaque FcCharSet* output.
 *
 * The real FcCharSet header is not public ABI; treat as opaque and
 * point callers at a zero-initialised aligned scratch large enough to
 * cover any structure version Mozilla might probe.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetCharSet_t)(const FcPattern *, const char *,
                                          int, FcCharSet **);

FcResult
FcPatternGetCharSet(const FcPattern *p, const char *object, int n,
                    FcCharSet **c)
{
    static FcPatternGetCharSet_t real = NULL;

    if (!real) {
        real = (FcPatternGetCharSet_t)dlsym(RTLD_NEXT, "FcPatternGetCharSet");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (c) *c = (FcCharSet *)fc_stub_charset;
        return FC_RESULT_NO_MATCH;
    }

    if (!c) {
        return real ? real(p, object, n, c) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *c = (FcCharSet *)fc_stub_charset;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, c);
    if (r != FC_RESULT_MATCH && *c == NULL) {
        *c = (FcCharSet *)fc_stub_charset;
    }
    return r;
}

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetLangSet — opaque FcLangSet* output.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetLangSet_t)(const FcPattern *, const char *,
                                          int, FcLangSet **);

FcResult
FcPatternGetLangSet(const FcPattern *p, const char *object, int n,
                    FcLangSet **l)
{
    static FcPatternGetLangSet_t real = NULL;

    if (!real) {
        real = (FcPatternGetLangSet_t)dlsym(RTLD_NEXT, "FcPatternGetLangSet");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (l) *l = (FcLangSet *)fc_stub_langset;
        return FC_RESULT_NO_MATCH;
    }

    if (!l) {
        return real ? real(p, object, n, l) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *l = (FcLangSet *)fc_stub_langset;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, l);
    if (r != FC_RESULT_MATCH && *l == NULL) {
        *l = (FcLangSet *)fc_stub_langset;
    }
    return r;
}

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetFTFace — FT_Face (FreeType face) output.
 *
 * Unlike the other getters, Mozilla checks the FT_Face for NULL before
 * dereferencing.  Keep NULL on the NoMatch path so the existing NULL
 * check in libxul fires and the no-face fallback path executes.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetFTFace_t)(const FcPattern *, const char *,
                                         int, FT_Face *);

FcResult
FcPatternGetFTFace(const FcPattern *p, const char *object, int n, FT_Face *f)
{
    static FcPatternGetFTFace_t real = NULL;

    if (!real) {
        real = (FcPatternGetFTFace_t)dlsym(RTLD_NEXT, "FcPatternGetFTFace");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (f) *f = NULL;
        return FC_RESULT_NO_MATCH;
    }

    if (!f) {
        return real ? real(p, object, n, f) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *f = NULL;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, f);
    if (r != FC_RESULT_MATCH) {
        /* Mozilla NULL-checks before deref — leave defined NULL. */
        *f = NULL;
    }
    return r;
}

/* ────────────────────────────────────────────────────────────────────
 * FcPatternGetRange — opaque FcRange* output.
 * ──────────────────────────────────────────────────────────────────── */
typedef FcResult (*FcPatternGetRange_t)(const FcPattern *, const char *,
                                        int, FcRange **);

FcResult
FcPatternGetRange(const FcPattern *p, const char *object, int n, FcRange **r)
{
    static FcPatternGetRange_t real = NULL;

    if (!real) {
        real = (FcPatternGetRange_t)dlsym(RTLD_NEXT, "FcPatternGetRange");
    }

    /* Bogus FcPattern* — bail before touching the bad address. */
    if (!fc_ptr_is_plausible(p)) {
        if (r) *r = (FcRange *)fc_stub_range;
        return FC_RESULT_NO_MATCH;
    }

    if (!r) {
        return real ? real(p, object, n, r) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        *r = (FcRange *)fc_stub_range;
        return FC_RESULT_NO_MATCH;
    }

    FcResult res = real(p, object, n, r);
    if (res != FC_RESULT_MATCH && *r == NULL) {
        *r = (FcRange *)fc_stub_range;
    }
    return res;
}

/* ────────────────────────────────────────────────────────────────────
 * PKCS#11 v3.0 C_GetInterface stub.
 *
 * OASIS PKCS #11 v3.0 §5.5:
 *   CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName,
 *                        CK_VERSION_PTR  pVersion,
 *                        CK_INTERFACE_PTR_PTR ppInterface,
 *                        CK_FLAGS flags);
 *
 * All PKCS#11 types are ultimately either pointers or unsigned longs.
 * We use void* / unsigned long here to avoid pulling in the full
 * PKCS#11 header; the ABI is identical on x86-64 System V.
 *
 * Returning CKR_FUNCTION_NOT_SUPPORTED (0x54) is the correct response
 * when a v2.x-only module is queried for a v3.0 interface: the caller
 * (NSS) must fall back to C_GetFunctionList per PKCS #11 v3.0 §6.1.
 * ──────────────────────────────────────────────────────────────────── */
static unsigned long
pkcs11_C_GetInterface_not_supported(void *pInterfaceName,
                                    void *pVersion,
                                    void **ppInterface,
                                    unsigned long flags)
{
    (void)pInterfaceName;
    (void)pVersion;
    (void)ppInterface;
    (void)flags;
    /* CKR_FUNCTION_NOT_SUPPORTED = 0x00000054 per PKCS #11 v3.0 Table 1. */
    return 0x00000054UL;
}

/* ────────────────────────────────────────────────────────────────────
 * dlsym wrapper — intercept C_GetInterface lookups.
 *
 * glibc's dlsym(handle, name) finds only symbols exported by <handle>
 * and its transitive DT_NEEDED dependencies.  libipcclientcerts.so
 * exports only C_GetFunctionList (v2.x); C_GetInterface is absent.
 * We interpose dlsym so that any lookup for "C_GetInterface" — on any
 * handle — returns our stub above, giving NSS the graceful-failure
 * response instead of a NULL that it treats as fatal.
 *
 * Bootstrap problem: dlsym cannot call dlsym(RTLD_NEXT, "dlsym") to
 * find itself (infinite recursion).  The POSIX-standard workaround is
 * dlvsym, which bypasses the wrapper because it requests a versioned
 * symbol — the version node lives at a different PLT slot.
 * GLIBC_2.2.5 is the version under which dlsym has been exported since
 * glibc 2.2.5; all Firefox-target systems carry it.
 *
 * All other lookups are forwarded to the real dlsym.
 * ──────────────────────────────────────────────────────────────────── */
typedef void *(*dlsym_fn)(void *handle, const char *name);

void *
dlsym(void *handle, const char *name)
{
    static dlsym_fn real_dlsym = NULL;

    /* Intercept first: avoids any risk of a reentrant bootstrap call
     * while real_dlsym is being initialised on the first dlsym call.
     * POSIX dlsym(3) guarantees name is non-NULL. */
    if (strcmp(name, "C_GetInterface") == 0) {
        return (void *)pkcs11_C_GetInterface_not_supported;
    }

    /* Bootstrap the real dlsym via dlvsym.  dlvsym is NOT interposed by
     * this wrapper (different symbol name), so this call does not
     * recurse.  The version string "GLIBC_2.2.5" is the stable glibc
     * ABI version for dlsym on all Linux x86-64 platforms. */
    if (!real_dlsym) {
        real_dlsym = (dlsym_fn)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    }

    if (!real_dlsym) {
        return NULL;
    }

    return real_dlsym(handle, name);
}
