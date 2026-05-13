/*
 * libfontconfig-interposer.so — defensive FcPatternGet* *out wrappers.
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
 * The interposer must be loaded before libfontconfig.so.1.  Inject via
 * LD_PRELOAD=/lib64/libfontconfig-interposer.so in the firefox-test
 * environment — set in kernel/src/gui/terminal.rs.  Real libfontconfig
 * remains in place for every other call.
 *
 * This is a userspace-side workaround for a Mozilla caller bug; the
 * upstream libfontconfig binary is never patched, preserving the
 * "no upstream binary edits" invariant.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

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
