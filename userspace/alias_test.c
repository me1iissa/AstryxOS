/*
 * alias_test.c — deterministic page-aliasing reproducer for the W8 race.
 *
 * Demand-paging aliasing race shape (W8, repeatedly observed under Firefox
 * load): under SMP, two CPUs concurrently fault on different pages of the
 * same MAP_PRIVATE file, race through the readahead / cache::insert /
 * page_ref_inc path, and one PTE ends up pointing at a physical frame whose
 * content does not match the file segment the VMA promises.
 *
 * This binary reproduces the shape in seconds rather than minutes:
 *
 *   1. Build a 30 MiB synthetic file with deterministic content
 *      byte[off] = (uint8_t)(off ^ (off >> 13) ^ 0xA5) -- so every byte is
 *      a pure function of its file offset. Any mismatch between
 *      mapped[off] and expected_byte(off) is a kernel-side aliasing bug.
 *
 *   2. Spawn N worker threads via raw clone(CLONE_VM|CLONE_THREAD|CLONE_SIGHAND).
 *      Each thread independently mmap()s the SAME file MAP_PRIVATE, walks
 *      it at a stride of 8 bytes per page, and verifies the page-aligned
 *      first 8 bytes match the expected pattern.
 *
 *   3. The worker repeats this loop until either:
 *        - the global deadline (tick budget) is exhausted, OR
 *        - the global fault budget is exhausted, OR
 *        - a mismatch is found (the worker prints one [ALIAS-TEST] line and
 *          atomically increments the global mismatch counter).
 *
 *   4. Main thread waits for every worker to set its "done" flag, prints
 *      one summary `[ALIAS-TEST] total=X mismatch=Y workers=N` line, and
 *      exits with status 0 (pass) or 1 (mismatch).
 *
 * Concurrency design rationale:
 *
 *   The bug surfaces when multiple CPUs race the demand-paging readahead in
 *   the page-fault handler.  With only two vCPUs (the AstryxOS default
 *   SMP=2 configuration), N=8 worker threads guarantees that at any moment
 *   at least two are inside the kernel's page-fault path on different CPUs.
 *   The pages each worker touches are deterministically derived from its
 *   worker id and the iteration count, so different workers fault the same
 *   pages at slightly different moments -- creating the (insert,evict,
 *   page_ref_inc) interleavings that W8 captures.
 *
 *   Each iteration of the inner loop munmap()s and re-mmap()s the file at
 *   a fresh virtual address, which forces a fresh demand-paging walk on
 *   the next access.  Without munmap(), the second iteration would all
 *   hit the existing PTEs and never re-touch the cache.
 *
 * Exit codes:
 *   0  — completed without observing any aliasing mismatch.
 *   1  — at least one [ALIAS-TEST] mismatch line was printed; details on
 *        the serial console.
 *   2  — infrastructure failure (open/write/mmap setup failed).  Never
 *        printed under normal operation; indicates the test fixture is
 *        broken rather than the kernel.
 *
 * No libc dependency: every operation is a raw syscall, exit happens
 * directly through SYS_exit_group.  Build (from the userspace/ dir):
 *
 *   gcc -O2 -nostdlib -nostartfiles -static -fno-stack-protector \
 *       -o alias_test alias_test.c
 *
 * The build/data.img packer (scripts/create-data-disk.sh) will copy
 * userspace/alias_test to /disk/bin/alias_test inside the FAT image.
 * The kernel test runner reads the binary from there in test-mode.
 *
 * Per POSIX mmap(2): "If [PROT_READ] specifies that the page may be read,
 * an attempt to access it must always observe the contents that the
 * underlying file would yield."  This test asserts exactly that invariant.
 */

#include <stddef.h>
#include <stdint.h>

/* ── Linux x86_64 syscall numbers ────────────────────────────────────────── */
#define SYS_read           0
#define SYS_write          1
#define SYS_open           2
#define SYS_close          3
#define SYS_mmap           9
#define SYS_munmap        11
#define SYS_clone         56
#define SYS_exit          60
#define SYS_ftruncate     77
#define SYS_unlink        87
#define SYS_exit_group   231
#define SYS_sched_yield   24

/* mmap flags / prot bits (uapi/asm-generic/mman-common.h) */
#define PROT_READ          0x1
#define PROT_WRITE         0x2
#define MAP_PRIVATE        0x02
#define MAP_ANONYMOUS      0x20
#define MAP_FAILED         ((void *)-1L)

/* open(2) flags */
#define O_RDONLY           0x0
#define O_RDWR             0x2
#define O_CREAT          0x40
#define O_TRUNC         0x200

/* clone(2) flags */
#define CLONE_VM         0x00000100
#define CLONE_FS         0x00000200
#define CLONE_FILES      0x00000400
#define CLONE_SIGHAND    0x00000800
#define CLONE_THREAD     0x00010000

/* ── Tunables ────────────────────────────────────────────────────────────── */
#define FILE_PAGES       (8 * 1024)        /* 32 MiB total */
#define PAGE_SIZE             4096
#define FILE_SIZE        ((uint64_t)FILE_PAGES * PAGE_SIZE)
#define N_WORKERS                8         /* > vCPUs to force overlap */
#define WORKER_STACK_SZ   (32 * 1024)
#define FAULT_BUDGET       100000          /* ~100k page faults total */
#define MAX_MISMATCH_PRINTS    16          /* cap serial spam */

/* Where workers map their MAP_PRIVATE windows; widely spaced so different
 * workers never overlap.  Each worker gets a 64 MiB slot starting at
 * MMAP_BASE + worker_id * MMAP_SLOT. */
#define MMAP_BASE     ((uint64_t)0x100000000000UL)   /* 16 TiB */
#define MMAP_SLOT     ((uint64_t)64 * 1024 * 1024)

/* ── Raw syscall wrappers ───────────────────────────────────────────────── */
static inline long _sc1(long nr, long a1) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1) : "rcx","r11","memory");
    return r;
}
static inline long _sc2(long nr, long a1, long a2) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2) : "rcx","r11","memory");
    return r;
}
static inline long _sc3(long nr, long a1, long a2, long a3) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2), "d"(a3) : "rcx","r11","memory");
    return r;
}
static inline long _sc6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    long r;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx","r11","memory");
    return r;
}

static long sys_write(int fd, const void *buf, size_t n) {
    return _sc3(SYS_write, fd, (long)buf, (long)n);
}
static long sys_open(const char *p, int flags, int mode) {
    return _sc3(SYS_open, (long)p, flags, mode);
}
static long sys_close(int fd) { return _sc1(SYS_close, fd); }
static long sys_ftruncate(int fd, uint64_t len) {
    return _sc2(SYS_ftruncate, fd, (long)len);
}
static long sys_unlink(const char *p) { return _sc1(SYS_unlink, (long)p); }
static void *sys_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t off) {
    return (void *)_sc6(SYS_mmap, (long)addr, (long)len, prot, flags, fd, (long)off);
}
static long sys_munmap(void *addr, uint64_t len) {
    return _sc2(SYS_munmap, (long)addr, (long)len);
}
static long sys_exit_group(int code) { return _sc1(SYS_exit_group, code); }
static long sys_exit(int code) { return _sc1(SYS_exit, code); }
static long sys_sched_yield(void) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(SYS_sched_yield) : "rcx","r11","memory");
    return r;
}

/* ── Tiny print helpers (no libc) ────────────────────────────────────────── */
static size_t kstrlen(const char *s) {
    size_t n = 0; while (s[n]) n++; return n;
}
static void kprint(const char *s) { sys_write(1, s, kstrlen(s)); }
static void kprint_u64_hex(uint64_t v) {
    char buf[19] = "0x0000000000000000";
    for (int i = 0; i < 16; i++) {
        int nyb = (int)((v >> (60 - i * 4)) & 0xF);
        buf[2 + i] = (char)(nyb < 10 ? '0' + nyb : 'a' + nyb - 10);
    }
    sys_write(1, buf, 18);
}
static void kprint_u64_dec(uint64_t v) {
    char buf[24];
    int i = 23;
    buf[i--] = 0;
    if (v == 0) { buf[i--] = '0'; }
    while (v) { buf[i--] = (char)('0' + (v % 10)); v /= 10; }
    sys_write(1, &buf[i + 1], (size_t)(22 - i));
}

/* ── Deterministic content function ──────────────────────────────────────── */
static inline uint8_t expected_byte(uint64_t file_off) {
    /* Mix offset bits so adjacent offsets and adjacent pages do not share a
     * value -- any aliasing that copies the wrong PAGE_SIZE-aligned source
     * will produce a mismatch within the first 8 bytes. */
    uint64_t v = file_off;
    v ^= v >> 13;
    v ^= v >> 7;
    v += 0xA5A5A5A5UL;
    return (uint8_t)(v & 0xFF);
}

/* ── Shared state across workers ─────────────────────────────────────────── */
typedef struct {
    /* Read-only after setup. */
    int file_fd;
    /* Shared atomic counters (workers update via xadd). */
    volatile uint64_t total_faults;
    volatile uint64_t total_mismatches;
    volatile uint64_t mismatch_prints;
    volatile uint32_t done_mask;          /* bit i set when worker i exits */
} alias_shared_t;

static alias_shared_t g_shared __attribute__((aligned(64)));

/* Worker stacks (page-aligned, big enough for the inline mmap path). */
static char worker_stacks[N_WORKERS][WORKER_STACK_SZ]
    __attribute__((aligned(4096)));

static inline uint64_t atomic_fetch_add_u64(volatile uint64_t *p, uint64_t v) {
    return __atomic_fetch_add(p, v, __ATOMIC_RELAXED);
}
static inline uint32_t atomic_or_u32(volatile uint32_t *p, uint32_t v) {
    return __atomic_fetch_or(p, v, __ATOMIC_RELAXED);
}

/* ── Worker thread ───────────────────────────────────────────────────────── */
/*
 * Each worker:
 *   - mmap()s the file MAP_PRIVATE at its dedicated slot
 *   - walks every 16th page (256 KiB step) verifying the first 8 bytes
 *   - munmap()s + remmaps to force fresh demand-paging on next iter
 *   - stops once the global fault budget is exhausted
 *
 * The worker is invoked via raw clone(CLONE_VM|CLONE_THREAD|CLONE_SIGHAND).
 * On entry, RDI holds the worker id (we pass it via the stack frame: see
 * spawn_worker below).  The worker never returns; it exits via SYS_exit.
 */
extern void worker_main(uint64_t worker_id) __attribute__((used));
void worker_main(uint64_t worker_id) {
    /* Each worker iterates until the global fault budget is exhausted. */
    uint64_t local_faults = 0;
    /* Phase-shift starting page so workers don't all touch page 0 first. */
    uint64_t page_cursor = (worker_id * 37) & (FILE_PAGES - 1);

    while (atomic_fetch_add_u64(&g_shared.total_faults, 0) < FAULT_BUDGET) {
        /* Map the whole file MAP_PRIVATE at our dedicated slot. */
        void *want = (void *)(MMAP_BASE + worker_id * MMAP_SLOT);
        void *mapped = sys_mmap(want, FILE_SIZE,
                                PROT_READ,
                                MAP_PRIVATE,
                                g_shared.file_fd, 0);
        if (mapped == MAP_FAILED) {
            kprint("[ALIAS-TEST] worker mmap FAILED\n");
            atomic_fetch_add_u64(&g_shared.total_mismatches, 1);
            break;
        }
        const uint8_t *base = (const uint8_t *)mapped;

        /* Walk a subset of pages this iteration, advancing the cursor so
         * successive iterations cover a different stride.  16 pages per
         * inner loop keeps the per-iteration runtime small enough that
         * the deadline check stays responsive. */
        for (int i = 0; i < 64; i++) {
            uint64_t pg = page_cursor & (FILE_PAGES - 1);
            uint64_t off = pg * PAGE_SIZE;
            /* Trigger a fault on this page.  Volatile so the compiler
             * cannot CSE away the load. */
            const volatile uint8_t *p = base + off;
            for (int k = 0; k < 8; k++) {
                uint8_t got = p[k];
                uint8_t want_b = expected_byte(off + (uint64_t)k);
                if (got != want_b) {
                    /* Cap the number of lines we print to bound the
                     * serial spam if every page is wrong. */
                    uint64_t n = atomic_fetch_add_u64(&g_shared.mismatch_prints, 1);
                    if (n < MAX_MISMATCH_PRINTS) {
                        kprint("[ALIAS-TEST] vma_offset=");
                        kprint_u64_hex(off + (uint64_t)k);
                        kprint(" expected=");
                        kprint_u64_hex((uint64_t)want_b);
                        kprint(" got=");
                        kprint_u64_hex((uint64_t)got);
                        kprint(" tid=");
                        kprint_u64_dec(worker_id);
                        kprint(" iter=");
                        kprint_u64_dec(local_faults);
                        kprint("\n");
                    }
                    atomic_fetch_add_u64(&g_shared.total_mismatches, 1);
                    /* Continue scanning so we get an upper bound on the
                     * mismatch rate, but only print up to the cap. */
                }
            }
            local_faults++;
            page_cursor += 17;            /* coprime with FILE_PAGES=8192 */
        }

        atomic_fetch_add_u64(&g_shared.total_faults, 64);

        /* Drop the mapping so next iteration starts cold. */
        sys_munmap(mapped, FILE_SIZE);

        /* Yield periodically so other workers / the main thread get a
         * fair share of the CPU.  Without this on small SMP=1 configs
         * one worker monopolises a CPU and the others never run. */
        sys_sched_yield();
    }

    /* Mark this worker done. */
    atomic_or_u32(&g_shared.done_mask, 1u << (uint32_t)worker_id);

    /* Exit just this thread.  CLONE_THREAD means our exit doesn't terminate
     * the process — the leader will exit_group once all bits are set. */
    sys_exit(0);
    /* Belt-and-braces: never reached. */
    for (;;) {}
}

/*
 * Spawn one worker using raw Linux clone(2).
 *
 * The Linux x86_64 clone ABI for SYS_clone:
 *   RDI=flags, RSI=stack, RDX=ptid, R10=ctid, R8=tls
 *   Return: child sees 0 in RAX, parent sees new TID (or negative errno).
 *
 * AstryxOS-specific constraint: the new thread is created with all
 * general-purpose registers cleared except RAX (set to 0 to indicate
 * "child returned from clone").  RDX, R8-R15 are zero on first
 * scheduling.  So we cannot pre-load a register with the worker id and
 * expect it to survive.
 *
 * Instead we encode the worker id on the child's stack: the kernel uses
 * the `new_stack` argument as the child's RSP exactly as-is, so storing
 * the worker id at *(new_stack) makes it accessible via `pop %rdi`
 * (which also re-aligns RSP to 16-byte for the subsequent SysV `call`).
 *
 * Stack layout we set up:
 *
 *     stack_top:   [worker_id]   <- *(rsp) on child entry
 *     stack_top+8: [garbage]     <- popping word brings rsp to stack_top+8
 *
 * After `pop %rdi`, RSP = stack_top+8 (which we arranged to be 16-aligned).
 * The subsequent `call` pushes 8 bytes -> RSP%16 == 8 inside worker_main,
 * matching the SysV convention GCC's -O2 prologue assumes.
 */
static long spawn_worker(uint64_t worker_id) {
    /* Per-worker stack base. */
    char *stack_top = worker_stacks[worker_id] + WORKER_STACK_SZ;
    /* Align down to 16-byte to make subsequent alignment math trivial. */
    stack_top = (char *)((uintptr_t)stack_top & ~(uintptr_t)15);
    /* Reserve one 16-byte slot: low 8 bytes holds the worker id, the
     * upper 8 bytes is an unused frame-marker pad.  After `pop %rdi`
     * (which consumes the low 8 bytes), RSP = stack_top - 8, which is
     * 8 mod 16 -- the misalignment SysV expects at the moment of a
     * `call` instruction.  The subsequent `call worker_main` pushes
     * 8 more bytes, bringing RSP to 0 mod 16 inside worker_main, which
     * is what GCC's -O2 prologue assumes when emitting movaps. */
    stack_top -= 16;
    *(uint64_t *)stack_top = worker_id;          /* low slot: worker id */
    *(uint64_t *)(stack_top + 8) = 0xDEADBEEF;   /* high slot: marker */

    long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;

    long ret;
    register long r10 __asm__("r10") = 0;
    register long r8  __asm__("r8")  = 0;
    __asm__ volatile(
        "syscall\n\t"
        "test %%rax, %%rax\n\t"
        "jnz 1f\n\t"
        /* Child path: kernel set RSP = stack_top, all GPRs (except RAX=0)
         * are zero.  Pop the worker id into RDI per SysV AMD64 calling
         * convention.  The `pop` advances RSP by 8 to the marker slot;
         * after the subsequent `call` RSP%16 == 0 inside worker_main. */
        "pop %%rdi\n\t"
        "call worker_main\n\t"
        /* worker_main should never return; belt-and-braces exit. */
        "mov $60, %%eax\n\t"          /* SYS_exit */
        "xor %%edi, %%edi\n\t"
        "syscall\n\t"
        "1:\n\t"
        : "=a"(ret)
        : "a"(SYS_clone), "D"(flags), "S"(stack_top),
          "d"(0), "r"(r10), "r"(r8)
        : "rcx","r11","memory"
    );
    return ret;
}

/* ── Helpers: file population, write loop ────────────────────────────────── */
static int write_full(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    while (n) {
        long w = sys_write(fd, p, n);
        if (w <= 0) return -1;
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

/* Populate the file with the deterministic pattern using a 64 KiB
 * write-buffer.  Returns 0 on success, -1 on any write failure. */
static int populate_file(int fd) {
    static uint8_t buf[65536] __attribute__((aligned(4096)));
    const uint64_t chunk = sizeof(buf);
    uint64_t written = 0;
    while (written < FILE_SIZE) {
        for (uint64_t i = 0; i < chunk; i++) {
            buf[i] = expected_byte(written + i);
        }
        if (write_full(fd, buf, (size_t)chunk) < 0) return -1;
        written += chunk;
    }
    return 0;
}

/* ── Main entry ──────────────────────────────────────────────────────────── */
/*
 * The Linux ELF ABI hands _start a RSP that is 16-byte aligned modulo 16
 * (i.e. RSP%16 == 0).  GCC's SysV calling convention, in contrast, assumes
 * that at function entry RSP%16 == 8 (the would-be return-address slot).
 * Compiling a C `_start` with -O2 therefore emits `movaps %xmm, off(%rsp)`
 * instructions whose effective address relies on the misalignment-by-8 that
 * a `call` would have introduced -- and faults with #GP on the first such
 * store.  Fix: stub `_start` is asm-only, aligns the stack to the SysV
 * convention by pushing a fake return slot, and jumps into the C entry. */
__asm__(
    ".global _start\n"
    "_start:\n"
    "    xor %rbp, %rbp\n"               /* clear frame pointer */
    /* The Linux ELF entry hands us RSP%16 == 0 (no caller `call` was
     * executed).  SysV expects RSP%16 == 8 at function entry (the
     * call-instruction return-address slot).  `call` here pushes 8
     * bytes, so the callee sees RSP%16 == 8 -- exactly what GCC's
     * -O2 emit-prologue assumes when computing offsets for stack
     * spills, including 16-byte `movaps`/`movdqa` accesses. */
    "    call alias_test_main\n"         /* never returns */
    "    ud2\n"
);

void alias_test_main(void) __attribute__((used, noreturn));
void alias_test_main(void) {
    kprint("[ALIAS-TEST] start workers=");
    kprint_u64_dec(N_WORKERS);
    kprint(" pages=");
    kprint_u64_dec(FILE_PAGES);
    kprint(" fault_budget=");
    kprint_u64_dec(FAULT_BUDGET);
    kprint("\n");

    /* Step 1: try a few candidate paths for the test file.  /tmp is the
     * primary target; /disk/tmp is the fallback. */
    const char *path1 = "/tmp/alias_test.bin";
    const char *path2 = "/disk/tmp/alias_test.bin";
    int fd = (int)sys_open(path1, O_RDWR | O_CREAT | O_TRUNC, 0644);
    const char *path_used = path1;
    if (fd < 0) {
        fd = (int)sys_open(path2, O_RDWR | O_CREAT | O_TRUNC, 0644);
        path_used = path2;
    }
    if (fd < 0) {
        kprint("[ALIAS-TEST] FAIL open returned ");
        kprint_u64_dec((uint64_t)-fd);
        kprint("\n");
        sys_exit_group(2);
    }
    (void)path_used;

    /* Step 2: extend to FILE_SIZE and write the deterministic pattern. */
    if (sys_ftruncate(fd, FILE_SIZE) < 0) {
        kprint("[ALIAS-TEST] FAIL ftruncate\n");
        sys_exit_group(2);
    }
    if (populate_file(fd) < 0) {
        kprint("[ALIAS-TEST] FAIL populate_file\n");
        sys_exit_group(2);
    }
    kprint("[ALIAS-TEST] file populated, spawning workers\n");

    /* Reopen RDONLY for the workers' MAP_PRIVATE so we never accidentally
     * exercise the write-back path. */
    sys_close(fd);
    fd = (int)sys_open(path_used, O_RDONLY, 0);
    if (fd < 0) {
        kprint("[ALIAS-TEST] FAIL reopen RDONLY\n");
        sys_exit_group(2);
    }
    g_shared.file_fd = fd;

    /* Step 3: spawn N_WORKERS threads. */
    for (uint64_t w = 0; w < N_WORKERS; w++) {
        long r = spawn_worker(w);
        if (r < 0) {
            kprint("[ALIAS-TEST] FAIL clone worker=");
            kprint_u64_dec(w);
            kprint(" err=");
            kprint_u64_dec((uint64_t)-r);
            kprint("\n");
            /* Mark this worker "done" so the main loop doesn't wait for it. */
            atomic_or_u32(&g_shared.done_mask, 1u << (uint32_t)w);
        }
    }

    /* Step 4: wait until every worker has set its done bit.  We must yield
     * actively (sched_yield) rather than only `pause`, because on a
     * single-CPU configuration this main thread otherwise hogs the
     * processor and starves the workers. */
    const uint32_t want_mask = (N_WORKERS >= 32) ? 0xFFFFFFFFu : ((1u << N_WORKERS) - 1u);
    while ((__atomic_load_n(&g_shared.done_mask, __ATOMIC_RELAXED) & want_mask) != want_mask) {
        sys_sched_yield();
        for (int i = 0; i < 2000; i++) __asm__ volatile("pause");
    }

    /* Step 5: summary. */
    uint64_t total = __atomic_load_n(&g_shared.total_faults, __ATOMIC_RELAXED);
    uint64_t mism  = __atomic_load_n(&g_shared.total_mismatches, __ATOMIC_RELAXED);
    kprint("[ALIAS-TEST] total=");
    kprint_u64_dec(total);
    kprint(" mismatch=");
    kprint_u64_dec(mism);
    kprint(" workers=");
    kprint_u64_dec(N_WORKERS);
    kprint("\n");

    /* Clean up the test file so subsequent runs start fresh. */
    sys_close(fd);
    sys_unlink(path_used);

    sys_exit_group(mism == 0 ? 0 : 1);
    for (;;) {}
}
