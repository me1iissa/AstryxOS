/*
 * vdso_probe.c — end-to-end correctness + cost probe for __vdso_clock_gettime.
 *
 * Why this exists
 * ----------------
 * The in-kernel vDSO tests (`test_vdso_clock_gettime_subtick_ns`,
 * `test_vdso_clock_gettime_progress_subms`) call `crate::syscall::sys_clock_gettime`
 * directly — they exercise the kernel-side TSC formula, not the symbol an
 * actual user process resolves via AT_SYSINFO_EHDR.  Sampling under Firefox
 * shows TID 2 spending a large fraction of its plateau samples at the first
 * instruction of `__vdso_clock_gettime` (vdso ELF .text page 0x7efff0002000),
 * which is consistent with either (a) a tight, productive vDSO hot loop or
 * (b) every call silently falling through to a SYSCALL.  This probe answers
 * which: it resolves the userspace symbol the way libc does, calls it
 * directly, and reports:
 *
 *   [VDSO-PROBE] resolve __vdso_clock_gettime=<addr> __vdso_gettimeofday=<addr>
 *   [VDSO-PROBE] correctness mono=PASS|FAIL distinct=<n>/<N> min_delta_ns=...
 *   [VDSO-PROBE] cost calls=<N> total_tsc=<...> ns_per_call=<...>
 *
 * Public references:
 *   vdso(7)             — AT_SYSINFO_EHDR semantics + symbol versioning
 *   clock_gettime(2)    — CLOCK_MONOTONIC semantics + monotonicity invariant
 *   ELF-64 spec         — PT_LOAD, p_vaddr/p_filesz, .dynsym / .dynstr layout
 *   Intel SDM Vol. 2B   — RDTSC instruction semantics + serialisation
 *   System V ABI x86_64 — initial process stack: argc, argv, envp, auxv layout
 *
 * No libc dependency: every operation is a raw syscall or pure userspace
 * arithmetic.  Build (from the userspace/ dir):
 *
 *   gcc -O2 -nostdlib -nostartfiles -static -fno-stack-protector \
 *       -o vdso_probe vdso_probe.c
 */

#include <stddef.h>
#include <stdint.h>

/* ── Linux x86_64 syscall numbers (UAPI) ──────────────────────────────────── */
#define SYS_write          1
#define SYS_exit          60
#define SYS_exit_group   231

/* ── ELF64 layout constants ───────────────────────────────────────────────── */
#define EI_NIDENT      16
#define ELFCLASS64      2
#define ELFDATA2LSB     1
#define ET_DYN          3
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define DT_NULL         0
#define DT_STRTAB       5
#define DT_SYMTAB       6
#define DT_STRSZ       10
#define DT_SYMENT      11

typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;
} Elf64_Dyn;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

/* ── auxv ─────────────────────────────────────────────────────────────────── */
#define AT_NULL          0
#define AT_SYSINFO_EHDR 33

typedef struct { uint64_t a_type; uint64_t a_val; } Elf64_auxv_t;

/* ── struct timespec ──────────────────────────────────────────────────────── */
typedef struct { int64_t tv_sec; int64_t tv_nsec; } timespec_t;

/* CLOCK_MONOTONIC per clock_gettime(2). */
#define CLOCK_MONOTONIC  1

/* ── Raw syscall wrappers ─────────────────────────────────────────────────── */
static inline long _sc1(long nr, long a1) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1) : "rcx","r11","memory");
    return r;
}
static inline long _sc3(long nr, long a1, long a2, long a3) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
                     : "rcx","r11","memory");
    return r;
}
static long sys_write(int fd, const void *buf, size_t n) {
    return _sc3(SYS_write, fd, (long)buf, (long)n);
}
static void sys_exit_group(int code) __attribute__((noreturn));
static void sys_exit_group(int code) {
    _sc1(SYS_exit_group, code);
    /* exit_group(2) never returns; this loop satisfies the compiler. */
    for (;;) { }
}

/* ── Line buffer + tiny print helpers (no libc) ───────────────────────────── *
 *
 * To keep the harness's syscall-ring mirror coherent (it records at write
 * granularity, not line granularity), we buffer one logical line into
 * `g_linebuf` and flush with a single `sys_write` per line.  Buffer is
 * 512 bytes — generous for the longest probe line.
 */
static char g_linebuf[512];
static size_t g_linelen = 0;

__attribute__((noinline))
static size_t kstrlen(const char *s) {
    size_t n = 0;
    /* Inline asm fence keeps the compiler from recognising this as
     * libc strlen and emitting a call to the unavailable extern. */
    __asm__ volatile("" ::: "memory");
    while (s[n]) n++;
    return n;
}

static void linebuf_flush(void) {
    if (g_linelen) sys_write(1, g_linebuf, g_linelen);
    g_linelen = 0;
}
static void linebuf_append(const char *s, size_t n) {
    if (g_linelen + n > sizeof(g_linebuf)) n = sizeof(g_linebuf) - g_linelen;
    for (size_t i = 0; i < n; i++) {
        g_linebuf[g_linelen++] = s[i];
        if (s[i] == '\n') linebuf_flush();
    }
}
static void kprint(const char *s) { linebuf_append(s, kstrlen(s)); }
static void kprint_u64_hex(uint64_t v) {
    char buf[18] = "0x0000000000000000";
    for (int i = 0; i < 16; i++) {
        int nyb = (int)((v >> (60 - i * 4)) & 0xF);
        buf[2 + i] = (char)(nyb < 10 ? '0' + nyb : 'a' + nyb - 10);
    }
    linebuf_append(buf, 18);
}
static void kprint_u64_dec(uint64_t v) {
    char buf[24];
    int i = 23;
    buf[i--] = 0;
    if (v == 0) { buf[i--] = '0'; }
    while (v) { buf[i--] = (char)('0' + (v % 10)); v /= 10; }
    linebuf_append(&buf[i + 1], (size_t)(22 - i));
}

/* String comparison without libc. */
static int kstreq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == *b;
}

/* ── RDTSC helper ─────────────────────────────────────────────────────────── *
 *
 * Per Intel SDM Vol. 2B (RDTSC): returns the 64-bit TSC in EDX:EAX.  Under
 * KVM, RDTSC normally runs without a VMEXIT (TSC virtualisation is by TSC
 * offset, not by trap), so the value is real cycle-accurate hardware time.
 * We do NOT serialise with LFENCE because we want the lowest-overhead
 * measurement possible — out-of-order completion of a few cycles is well
 * below the noise floor of the per-call cost we're after (~10–1000 ns).
 */
static inline uint64_t rdtsc_(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* ── ELF symbol resolution ────────────────────────────────────────────────── */
/*
 * Resolve `name` in the vDSO ELF at runtime virtual address `base`.
 *
 * The vDSO is a position-independent shared object; its in-memory layout
 * is exactly what the kernel maps from `kernel/vdso/vdso.so`.  Per the
 * ELF-64 spec, dynamic linkage info lives in a PT_DYNAMIC segment whose
 * d_tag entries point at the .dynsym and .dynstr tables (DT_SYMTAB,
 * DT_STRTAB, DT_SYMENT).  Symbol values are addends to the load base.
 *
 * Returns the runtime address of the named symbol, or 0 if not found.
 */
static uint64_t vdso_resolve(uint64_t base, const char *name) {
    if (base == 0) return 0;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E'
        || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F') {
        return 0;
    }
    if (eh->e_ident[4] != ELFCLASS64 || eh->e_ident[5] != ELFDATA2LSB) return 0;

    const Elf64_Phdr *ph = (const Elf64_Phdr *)(base + eh->e_phoff);
    const Elf64_Dyn  *dyn = NULL;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(base + ph[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    const Elf64_Sym *symtab = NULL;
    const char      *strtab = NULL;
    uint64_t         strsz  = 0;
    uint64_t         syment = sizeof(Elf64_Sym);
    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        /* DT_STRTAB/DT_SYMTAB values in a vDSO are link-time addresses
         * (small positives, < 0x10000).  Treat anything < base as a
         * link-relative offset and rebase; anything >= base is already an
         * absolute runtime address.  This handles both linker variants. */
        switch (d->d_tag) {
            case DT_STRTAB:
                strtab = (const char *)(d->d_val < base ? base + d->d_val : d->d_val);
                break;
            case DT_SYMTAB:
                symtab = (const Elf64_Sym *)(d->d_val < base ? base + d->d_val : d->d_val);
                break;
            case DT_STRSZ:  strsz  = d->d_val; break;
            case DT_SYMENT: syment = d->d_val; break;
            default: break;
        }
    }
    if (!symtab || !strtab) return 0;

    /* We don't know the symbol-count upfront (no DT_HASH parsing here),
     * but the vDSO has a tiny .dynsym — bounded by .dynstr size, since
     * every symbol's st_name indexes into .dynstr.  Walk until we hit a
     * symbol whose st_name is >= strsz (out of range = end-of-table or
     * we walked past it). */
    for (uint64_t i = 0; i < 64; i++) {
        const Elf64_Sym *sym = (const Elf64_Sym *)((const uint8_t *)symtab + i * syment);
        if (sym->st_name == 0) continue;
        if (sym->st_name >= strsz) break;
        const char *sname = strtab + sym->st_name;
        if (kstreq(sname, name)) {
            uint64_t v = sym->st_value;
            return v < base ? base + v : v;
        }
    }
    return 0;
}

/* ── auxv parsing ─────────────────────────────────────────────────────────── *
 *
 * Per the System V ABI x86_64 supplement, the kernel hands `_start` a stack
 * laid out as:
 *
 *   [argc] [argv[0]..argv[argc-1]] [NULL] [envp[0]..] [NULL] [auxv...] [AT_NULL]
 *
 * We pass `argc` + a pointer to argv[0] into here from the asm `_start`,
 * walk past argv and envp, then iterate the auxv until AT_NULL.
 */
static uint64_t find_at_sysinfo_ehdr(int argc, char **argv) {
    char **p = argv;
    /* Skip argv[0..argc-1]. */
    for (int i = 0; i < argc; i++) p++;
    /* Skip the argv terminator. */
    if (*p == NULL) p++; /* defensive */
    /* Walk envp until NULL. */
    while (*p != NULL) p++;
    p++; /* skip envp NULL terminator */
    /* p now points at the first Elf64_auxv_t. */
    Elf64_auxv_t *aux = (Elf64_auxv_t *)p;
    while (aux->a_type != AT_NULL) {
        if (aux->a_type == AT_SYSINFO_EHDR) return aux->a_val;
        aux++;
    }
    return 0;
}

/* ── _start: minimal ELF entry that hands argc/argv to C ──────────────────── */
__asm__(
    ".global _start\n"
    "_start:\n"
    "    mov (%rsp), %rdi\n"        /* argc */
    "    lea 8(%rsp), %rsi\n"       /* argv */
    "    xor %rbp, %rbp\n"
    "    and $-16, %rsp\n"          /* RSP%16 == 0 before the call;
                                       the call pushes 8 → callee sees
                                       RSP%16 == 8, which is what the
                                       SysV x86_64 ABI requires at
                                       function entry */
    "    call vdso_probe_main\n"
    "    ud2\n"
);

void vdso_probe_main(int argc, char **argv) __attribute__((used, noreturn));

/* Function-pointer type for __vdso_clock_gettime. */
typedef int (*clock_gettime_fn)(int, timespec_t *);

void vdso_probe_main(int argc, char **argv) {
    kprint("[VDSO-PROBE] start\n");

    uint64_t base = find_at_sysinfo_ehdr(argc, argv);
    kprint("[VDSO-PROBE] AT_SYSINFO_EHDR="); kprint_u64_hex(base); kprint("\n");
    if (base == 0) {
        kprint("[VDSO-PROBE] FAIL no AT_SYSINFO_EHDR in auxv — vDSO not mapped\n");
        sys_exit_group(2);
    }

    uint64_t clk = vdso_resolve(base, "__vdso_clock_gettime");
    uint64_t gtd = vdso_resolve(base, "__vdso_gettimeofday");
    kprint("[VDSO-PROBE] resolve __vdso_clock_gettime=");
    kprint_u64_hex(clk); kprint(" __vdso_gettimeofday=");
    kprint_u64_hex(gtd); kprint("\n");
    if (clk == 0) {
        kprint("[VDSO-PROBE] FAIL __vdso_clock_gettime symbol not found\n");
        sys_exit_group(2);
    }

    clock_gettime_fn vcg = (clock_gettime_fn)clk;

    /* ── Phase 2: correctness ──────────────────────────────────────────────
     * Take N back-to-back samples; verify monotonicity, count distinct
     * values, and report the min positive delta we observed.  A correct
     * TSC-derived vDSO should produce a distinct value on the vast
     * majority of calls (sub-ns granularity once you account for the
     * RDTSC pipeline cost). */
    const int N = 1000;
    timespec_t prev = {0, 0}, cur = {0, 0};
    int monotone_breaks = 0;
    int distinct = 0;
    uint64_t min_delta_ns = ~(uint64_t)0;
    int rc = vcg(CLOCK_MONOTONIC, &prev);
    if (rc != 0) {
        kprint("[VDSO-PROBE] FAIL initial __vdso_clock_gettime rc=");
        kprint_u64_dec((uint64_t)(int64_t)rc);
        kprint(" — vDSO returning errno (-22 = EINVAL)\n");
        sys_exit_group(2);
    }
    for (int i = 1; i < N; i++) {
        rc = vcg(CLOCK_MONOTONIC, &cur);
        if (rc != 0) {
            kprint("[VDSO-PROBE] FAIL call ");
            kprint_u64_dec((uint64_t)i);
            kprint(" rc="); kprint_u64_dec((uint64_t)(int64_t)rc); kprint("\n");
            sys_exit_group(2);
        }
        uint64_t cur_ns  = (uint64_t)cur.tv_sec * 1000000000ULL + (uint64_t)cur.tv_nsec;
        uint64_t prev_ns = (uint64_t)prev.tv_sec * 1000000000ULL + (uint64_t)prev.tv_nsec;
        if (cur_ns < prev_ns) {
            monotone_breaks++;
        } else if (cur_ns > prev_ns) {
            distinct++;
            uint64_t d = cur_ns - prev_ns;
            if (d < min_delta_ns) min_delta_ns = d;
        }
        prev = cur;
    }

    kprint("[VDSO-PROBE] correctness mono=");
    kprint(monotone_breaks == 0 ? "PASS" : "FAIL");
    kprint(" monotone_breaks="); kprint_u64_dec((uint64_t)monotone_breaks);
    kprint(" distinct="); kprint_u64_dec((uint64_t)distinct);
    kprint("/"); kprint_u64_dec((uint64_t)(N - 1));
    kprint(" min_delta_ns=");
    if (distinct > 0) kprint_u64_dec(min_delta_ns);
    else              kprint("inf");
    kprint("\n");

    /* ── Phase 3: cost ─────────────────────────────────────────────────────
     * Measure 1,000,000 back-to-back __vdso_clock_gettime calls using
     * RDTSC at start and end.  The TSC frequency we report is whatever
     * the host CPU runs at; we don't know it exactly here, but the
     * `ns_per_call` we compute uses the clock_gettime delta over the
     * same window — so it is independent of TSC frequency. */
    const int M = 1000000;
    timespec_t ts_a, ts_b;
    rc = vcg(CLOCK_MONOTONIC, &ts_a);
    if (rc != 0) goto cost_skip;
    uint64_t tsc_a = rdtsc_();
    timespec_t dump;
    for (int i = 0; i < M; i++) {
        /* The `dump` argument prevents the compiler from CSEing away
         * the call; volatile cast on the pointer ensures the write is
         * not optimised out. */
        vcg(CLOCK_MONOTONIC, (timespec_t *)&dump);
    }
    uint64_t tsc_b = rdtsc_();
    rc = vcg(CLOCK_MONOTONIC, &ts_b);
    if (rc != 0) goto cost_skip;

    uint64_t tsc_delta = tsc_b - tsc_a;
    uint64_t ns_delta  =
        ((uint64_t)ts_b.tv_sec * 1000000000ULL + (uint64_t)ts_b.tv_nsec) -
        ((uint64_t)ts_a.tv_sec * 1000000000ULL + (uint64_t)ts_a.tv_nsec);
    uint64_t ns_per_call = ns_delta / (uint64_t)M;

    kprint("[VDSO-PROBE] cost calls=");
    kprint_u64_dec((uint64_t)M);
    kprint(" tsc_delta="); kprint_u64_dec(tsc_delta);
    kprint(" ns_delta=");  kprint_u64_dec(ns_delta);
    kprint(" ns_per_call="); kprint_u64_dec(ns_per_call);
    kprint("\n");

    /* Pass/fail thresholds:
     *  - correctness mono == PASS (always required)
     *  - distinct > 0 (clock advanced)
     *  - ns_per_call < 500 (a well-tuned vDSO is in the ~10-100 ns range;
     *    >500 ns suggests every call is taking a SYSCALL or VMEXIT). */
    int pass = (monotone_breaks == 0) && (distinct > 0) && (ns_per_call < 500);
    kprint("[VDSO-PROBE] verdict=");
    kprint(pass ? "PASS" : "FAIL");
    kprint("\n");
    sys_exit_group(pass ? 0 : 1);

cost_skip:
    kprint("[VDSO-PROBE] cost SKIPPED (vDSO returned error mid-cost-loop)\n");
    sys_exit_group(1);
}
