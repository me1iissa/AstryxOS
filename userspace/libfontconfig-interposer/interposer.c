/*
 * libfontconfig-interposer.so — defensive FcPatternGetString *out wrapper.
 *
 * Real upstream libfontconfig follows the spec strictly: when
 * FcPatternGetString() returns FcResultNoMatch (1) it leaves the
 * caller-supplied output pointer untouched and the contents are
 * undefined.  See:
 *   https://fontconfig.org/fontconfig-devel/fcpatternget.html
 *   https://fontconfig.org/fontconfig-devel/fcresult.html
 *
 * Firefox's gfxFcPlatformFontList per-language alias enumeration in
 * libxul (vaddr regions exhibited at +0x185b8a4 and +0x4056429 in the
 * shipping ESR 115 build) iterates a list of font slots, calling
 * FcPatternGetString(p, ..., id, &slot) for each id, and on
 * FcResultNoMatch dereferences `*slot` unconditionally — slot still
 * holds whatever value the caller staged before the call, which is
 * commonly NULL.  The result is a %rbx=NULL fault at the next
 * `mov 0x..(%rbx), <reg>` or `orb $.., 0x..(%rbx)` instruction.
 *
 * This interposer wraps FcPatternGetString — it dlsym()s the real
 * implementation from libfontconfig.so.1 via RTLD_NEXT, calls through,
 * and on FcResultNoMatch additionally writes a non-NULL sentinel
 * pointer into *out so the buggy caller dereferences a valid empty
 * NUL-terminated string instead of NULL.
 *
 * The interposer must be loaded before libfontconfig.so.1.  Inject via
 * LD_PRELOAD=/lib64/libfontconfig-interposer.so in the firefox-test
 * environment — set in kernel/src/gui/terminal.rs.  Real libfontconfig
 * remains in place for every other call.
 *
 * This is userspace-side workaround for a Mozilla caller bug; the
 * upstream libfontconfig binary is never patched, preserving the
 * "no upstream binary edits" invariant.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

/* fontconfig public ABI (from <fontconfig/fontconfig.h>):
 *   typedef unsigned char FcChar8;
 *   typedef enum _FcResult {
 *       FcResultMatch, FcResultNoMatch, FcResultTypeMismatch,
 *       FcResultNoId,  FcResultOutOfMemory
 *   } FcResult;
 *   typedef struct _FcPattern FcPattern;
 *   FcResult FcPatternGetString(const FcPattern *p, const char *object,
 *                               int n, FcChar8 **s);
 */
typedef int FcResult;
typedef void FcPattern;
typedef unsigned char FcChar8;

#define FC_RESULT_MATCH       0
#define FC_RESULT_NO_MATCH    1

/* Non-NULL, NUL-terminated sentinel.  "DejaVu Sans" is also the family
 * the firefox-stubs generator uses for the in-process font list. */
static const FcChar8 fc_stub_family[] = "DejaVu Sans";

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
        /* Caller supplied no output buffer — nothing to defend against. */
        return real ? real(p, object, n, s) : FC_RESULT_NO_MATCH;
    }

    if (!real) {
        /* dlsym failed (real libfontconfig not loaded?) — surface a
         * defined result so the caller's NoMatch fault-path still sees
         * a valid pointer. */
        *s = (FcChar8 *)fc_stub_family;
        return FC_RESULT_NO_MATCH;
    }

    FcResult r = real(p, object, n, s);
    if (r != FC_RESULT_MATCH && *s == NULL) {
        /* Mozilla's caller dereferences *s on the NoMatch path.  Write
         * a non-NULL sentinel; the spec leaves *s undefined on
         * non-Match results so this is conformant — we are choosing a
         * defined value where libfontconfig would leave it unchanged. */
        *s = (FcChar8 *)fc_stub_family;
    }
    return r;
}
