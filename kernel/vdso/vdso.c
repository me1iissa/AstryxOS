/*
 * AstryxOS vDSO — minimal Linux-ABI compatibility shim
 *
 * Provides the four symbols glibc probes via AT_SYSINFO_EHDR:
 *   __vdso_clock_gettime, __vdso_gettimeofday, __vdso_time, __vdso_getcpu
 *
 * v1: pure syscall fallback — no shared-memory fast path.
 * The shared-memory optimisation (kernel writes a timestamp page, vDSO reads
 * it locklessly) is deferred; this is the correct Linux fallback behaviour.
 *
 * glibc looks for these symbols with version string "LINUX_2.6". We
 * provide that via a GNU version script (see vdso.lds).
 *
 * Compiled with: -nostdlib -fPIC -fvisibility=hidden
 * Linked with:   --version-script=vdso.lds -Bsymbolic --no-undefined
 */

/*
 * Linux syscall numbers (x86_64 ABI).
 * We hard-code these rather than pulling in <sys/syscall.h> to keep the
 * build hermetic and avoid any dependency on the host libc headers.
 */
#define SYS_clock_gettime  228
#define SYS_gettimeofday   96
#define SYS_time           201
#define SYS_getcpu         309

/*
 * Minimal struct definitions matching the Linux UAPI.
 * We cannot include <time.h> (no libc) so we declare just what we need.
 */
struct timespec {
    long tv_sec;
    long tv_nsec;
};

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

/*
 * Raw inline syscall helpers — avoids any PLT / GOT / relocation.
 *
 * The syscall instruction on x86_64 uses:
 *   rax = syscall number
 *   rdi, rsi, rdx, r10, r8, r9 = arguments (up to 6)
 *   Return value in rax (negative errno on error).
 */

static __inline__ long
__syscall2(long nr, long a0, long a1)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "0" (nr), "D" (a0), "S" (a1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static __inline__ long
__syscall3(long nr, long a0, long a1, long a2)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "0" (nr), "D" (a0), "S" (a1), "d" (a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/*
 * __vdso_clock_gettime(clockid_t clk_id, struct timespec *tp)
 *
 * Falls back to the clock_gettime(2) syscall.
 * Returns 0 on success, -errno on failure.
 */
__attribute__((visibility("default")))
int __vdso_clock_gettime(int clk_id, struct timespec *tp)
{
    return (int)__syscall2(SYS_clock_gettime, (long)clk_id, (long)tp);
}

/*
 * __vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
 *
 * Falls back to the gettimeofday(2) syscall.
 * Returns 0 on success, -errno on failure.
 */
__attribute__((visibility("default")))
int __vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    return (int)__syscall2(SYS_gettimeofday, (long)tv, (long)tz);
}

/*
 * __vdso_time(long *tloc)
 *
 * Falls back to the time(2) syscall.
 * Returns seconds since epoch on success, -errno on failure.
 */
__attribute__((visibility("default")))
long __vdso_time(long *tloc)
{
    return __syscall2(SYS_time, (long)tloc, 0L);
}

/*
 * __vdso_getcpu(unsigned *cpu, unsigned *node, void *tcache)
 *
 * Falls back to the getcpu(2) syscall.
 * Returns 0 on success, -errno on failure.
 * Note: the third argument (tcache) is ignored since Linux 2.6.24.
 */
__attribute__((visibility("default")))
int __vdso_getcpu(unsigned *cpu, unsigned *node, void *tcache)
{
    return (int)__syscall3(SYS_getcpu, (long)cpu, (long)node, (long)tcache);
}
