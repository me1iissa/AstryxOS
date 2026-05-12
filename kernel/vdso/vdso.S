/*
 * AstryxOS vDSO — Linux-ABI virtual Dynamic Shared Object.
 *
 * Provides the four symbols glibc / musl probe via AT_SYSINFO_EHDR:
 *   __vdso_clock_gettime, __vdso_gettimeofday, __vdso_time, __vdso_getcpu
 *
 * Fast-path strategy:
 *
 *   - clock_gettime(CLOCK_REALTIME / CLOCK_MONOTONIC) and gettimeofday()
 *     read a kernel-maintained "vvar" page mapped at a FIXED OFFSET
 *     relative to the vDSO ELF base.  The seqlock pattern (read seq → read
 *     fields → reread seq → retry on change) guards against torn reads
 *     while the kernel is updating fields.
 *
 *   - High-resolution clocks compute nanoseconds from the host TSC:
 *
 *         ns = (rdtsc - tsc_at_boot) * tsc_ns_mult >> tsc_ns_shift
 *
 *     The (mult, shift) pair is computed once at boot by the kernel
 *     (kernel/src/proc/vdso.rs::publish_tsc_calibration) to match the
 *     measured TSC frequency, giving nanosecond resolution without
 *     entering the kernel.  Mozilla `mozilla::TimeStamp::Now()` and glibc
 *     `clock_gettime(CLOCK_MONOTONIC)` therefore see a real ns-precision
 *     clock — earlier tick-quantised implementations returned the same
 *     value for ~10 ms of wall time, which trapped libxul timing loops
 *     in zero-elapsed-time busy spins.
 *
 *   - CLOCK_*_COARSE callers explicitly trade precision for speed
 *     (per clock_gettime(2)).  The COARSE path uses the cheaper tick
 *     counter (10 ms granularity) since precision is not required.
 *
 *   - getcpu reads IA32_TSC_AUX via RDTSCP.  The kernel writes the
 *     logical CPU index into IA32_TSC_AUX during AP startup, so
 *     userspace recovers it locklessly with no syscall.
 *
 *   - Unsupported clock ids fall through to a raw syscall.
 *
 * Memory layout (per process):
 *
 *   user_base + 0x0000 ─ vvar page (R, no-X, no-W, kernel-writable)
 *   user_base + 0x1000 ─ vDSO ELF page (R, X, no-W)
 *
 * AT_SYSINFO_EHDR = user_base + 0x1000   (the vDSO ELF header).
 *
 * The vDSO is linked as a position-independent shared object whose own
 * virtual base is 0.  RIP-relative references to vvar fields use absolute
 * symbol values defined here as (-0x1000 + field_offset).  Since x86-64
 * RIP-relative addressing computes (target - rip_of_next_insn) at link
 * time and adds the runtime RIP, an absolute target value of -0x1000 +
 * field_offset combined with rip_of_next_insn = vdso_base + insn_offset
 * yields a final memory operand of vdso_base + insn_offset + (-0x1000 +
 * field_offset - insn_offset_after_rel) = (vdso_base - 0x1000) + field
 * regardless of where in user space the kernel chose to map the pair.
 *
 * Public references:
 *   vdso(7)             — vDSO ABI, AT_SYSINFO_EHDR, symbol versioning
 *   clock_gettime(2)    — clk_id semantics, struct timespec
 *   gettimeofday(2)     — struct timeval, struct timezone (deprecated)
 *   time(2)             — seconds-since-epoch return convention
 *   getcpu(2)           — *cpu / *node / *unused argument convention
 *   System V ABI x86-64 — calling convention, RDI/RSI/RDX/RCX/R8/R9
 *   ELF-64 spec         — DT_VERSYM / GNU version symbol table
 *   Intel SDM Vol 2, RDTSC / RDTSCP / MUL / SHRD — instruction semantics
 */

	.text
	.code64

/* ── Linux x86_64 syscall numbers (UAPI; do not change) ─────────────── */
	.equ SYS_clock_gettime,  228
	.equ SYS_gettimeofday,    96
	.equ SYS_time,           201
	.equ SYS_getcpu,         309

/* ── Clock IDs (clock_gettime(2)) ───────────────────────────────────── *
 *
 * Linux UAPI:  REALTIME=0, MONOTONIC=1, MONOTONIC_RAW=4,
 *              REALTIME_COARSE=5, MONOTONIC_COARSE=6, BOOTTIME=7
 *
 * BOOTTIME (7) includes time spent suspended which we don't track, so it
 * falls through to the syscall.  All five other IDs are served from
 * userspace — the HRES family uses the TSC fast path; COARSE uses the
 * tick counter directly.
 */
	.equ CLOCK_REALTIME,         0
	.equ CLOCK_MONOTONIC,        1
	.equ CLOCK_MONOTONIC_RAW,    4
	.equ CLOCK_REALTIME_COARSE,  5
	.equ CLOCK_MONOTONIC_COARSE, 6

/* ── Numeric constants ─────────────────────────────────────────────── */
	.equ TICK_HZ,           100      /* PIT programmed at 100 Hz */
	.equ NS_PER_TICK,       10000000 /* 10 ms */
	.equ US_PER_TICK,       10000    /* 10 ms in microseconds */
	.equ NS_PER_SEC,        1000000000

/* ── vvar layout ────────────────────────────────────────────────────
 *
 * The vvar field symbols are PROVIDE()'d in vdso.lds at virtual addresses
 * below 0 so RIP-relative references in .text resolve to fixed negative
 * 32-bit displacements at link time.  At runtime, the kernel maps a real
 * page one page below the vDSO ELF so each rip-relative reference reaches
 * the corresponding kernel-maintained field.
 *
 * KEEP IN SYNC with `struct VvarPage` in kernel/src/proc/vdso.rs
 * (VVAR_OFF_*) and the field layout in kernel/vdso/vdso.lds.
 */


/* ── __vdso_clock_gettime ───────────────────────────────────────────────
 *
 * int __vdso_clock_gettime(clockid_t clk_id, struct timespec *tp)
 *
 * Args:    rdi = clk_id, rsi = tp
 * Return:  rax = 0 on success, negative errno on failure.
 */
	.globl __vdso_clock_gettime
	.type  __vdso_clock_gettime, @function
__vdso_clock_gettime:
	.cfi_startproc
	test    %rsi, %rsi
	jz      .Lcg_einval

	cmp     $CLOCK_REALTIME,         %edi
	je      .Lcg_realtime_hres
	cmp     $CLOCK_REALTIME_COARSE,  %edi
	je      .Lcg_realtime_coarse
	cmp     $CLOCK_MONOTONIC,        %edi
	je      .Lcg_monotonic_hres
	cmp     $CLOCK_MONOTONIC_RAW,    %edi
	je      .Lcg_monotonic_hres
	cmp     $CLOCK_MONOTONIC_COARSE, %edi
	je      .Lcg_monotonic_coarse
	jmp     .Lcg_syscall            /* unsupported id → kernel */

/*
 * High-resolution monotonic: ns = (rdtsc - tsc_at_boot) * mult >> shift.
 *
 * Register layout during the seqlock-guarded read window:
 *
 *   r8d = seq snapshot
 *   r10 = tsc_at_boot
 *   r11 = ns_mult
 *   ecx = ns_shift (only low byte used by `shrd`)
 *   r12 = wall_secs (realtime path only — saved/restored on entry/exit)
 *
 * The TSC read happens INSIDE the seqlock window so writers that change
 * tsc_at_boot mid-read force a retry — without this, a rare but real
 * race could see a delta computed against the old anchor while the new
 * one was already in mult/shift, producing a wildly wrong ns.
 */
.Lcg_monotonic_hres:
1:	movl    vvar_seq(%rip), %r8d
	testl   $1, %r8d
	jnz     1b                              /* writer in progress */
	movq    vvar_tsc_at_boot(%rip), %r10
	movq    vvar_tsc_ns_mult(%rip),  %r11
	movl    vvar_tsc_ns_shift(%rip), %ecx
	test    %r11, %r11                       /* calibration ready? */
	jz      .Lcg_mono_coarse_from_hres       /* fall back to tick */
	rdtsc                                    /* edx:eax = current TSC */
	shlq    $32, %rdx
	orq     %rdx, %rax                       /* rax = full 64-bit TSC */
	lfence                                   /* serialise vs. retry */
	movl    vvar_seq(%rip), %r9d
	cmpl    %r8d, %r9d
	jne     1b

	subq    %r10, %rax                       /* rax = tsc - tsc_at_boot */
	mulq    %r11                             /* rdx:rax = delta * mult */
	shrdq   %cl, %rdx, %rax                  /* rax = low 64 of (>> cl) */
	/* rax = ns since boot.  Split into sec / nsec. */
	movq    %rax, %r8                        /* preserve ns */
	movq    $NS_PER_SEC, %r11
	xorq    %rdx, %rdx
	divq    %r11                             /* rax = sec, rdx = nsec */
	movq    %rax, 0(%rsi)
	movq    %rdx, 8(%rsi)
	xorl    %eax, %eax
	ret

.Lcg_realtime_hres:
1:	movl    vvar_seq(%rip), %r8d
	testl   $1, %r8d
	jnz     1b
	movq    vvar_tsc_at_boot(%rip),  %r10
	movq    vvar_tsc_ns_mult(%rip),  %r11
	movl    vvar_tsc_ns_shift(%rip), %ecx
	movq    vvar_wall_secs(%rip),    %r9
	test    %r11, %r11
	jz      .Lcg_real_coarse_from_hres
	rdtsc
	shlq    $32, %rdx
	orq     %rdx, %rax
	lfence
	movl    vvar_seq(%rip), %edi
	cmpl    %r8d, %edi
	jne     1b

	subq    %r10, %rax
	mulq    %r11
	shrdq   %cl, %rdx, %rax                  /* rax = ns since boot */
	movq    $NS_PER_SEC, %r11
	xorq    %rdx, %rdx
	divq    %r11                             /* rax = sec, rdx = nsec */
	addq    %r9,  %rax                       /* + wall_secs */
	movq    %rax, 0(%rsi)
	movq    %rdx, 8(%rsi)
	xorl    %eax, %eax
	ret

/*
 * COARSE paths (and the calibration-not-ready fallback) use the 10 ms
 * tick counter directly — same precision as Linux's CLOCK_*_COARSE.
 */
.Lcg_realtime_coarse:
.Lcg_real_coarse_from_hres:
1:	movl    vvar_seq(%rip), %r8d
	testl   $1, %r8d
	jnz     1b
	movq    vvar_ticks(%rip),     %rax
	movq    vvar_wall_secs(%rip), %rcx
	lfence
	movl    vvar_seq(%rip), %r9d
	cmpl    %r8d, %r9d
	jne     1b

	movq    $TICK_HZ, %r11
	xorq    %rdx, %rdx
	divq    %r11
	addq    %rcx, %rax
	movq    %rax, 0(%rsi)
	movq    %rdx, %rax
	imulq   $NS_PER_TICK, %rax
	movq    %rax, 8(%rsi)
	xorl    %eax, %eax
	ret

.Lcg_monotonic_coarse:
.Lcg_mono_coarse_from_hres:
1:	movl    vvar_seq(%rip), %r8d
	testl   $1, %r8d
	jnz     1b
	movq    vvar_ticks(%rip), %rax
	lfence
	movl    vvar_seq(%rip), %r9d
	cmpl    %r8d, %r9d
	jne     1b

	movq    $TICK_HZ, %r11
	xorq    %rdx, %rdx
	divq    %r11
	movq    %rax, 0(%rsi)
	movq    %rdx, %rax
	imulq   $NS_PER_TICK, %rax
	movq    %rax, 8(%rsi)
	xorl    %eax, %eax
	ret

.Lcg_einval:
	movq    $-22, %rax              /* -EINVAL */
	ret

.Lcg_syscall:
	movq    $SYS_clock_gettime, %rax
	syscall
	ret
	.cfi_endproc
	.size __vdso_clock_gettime, .-__vdso_clock_gettime


/* ── __vdso_gettimeofday ───────────────────────────────────────────────
 *
 * int __vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
 *
 * struct timeval { time_t tv_sec; suseconds_t tv_usec; }   (16 bytes on x86_64)
 *
 * Per gettimeofday(2), tz is obsolete: glibc passes 0 in modern callers; if
 * non-NULL we zero the two int fields for compatibility.
 *
 * Args:    rdi = tv, rsi = tz
 * Return:  rax = 0 on success.
 */
	.globl __vdso_gettimeofday
	.type  __vdso_gettimeofday, @function
__vdso_gettimeofday:
	.cfi_startproc
	test    %rdi, %rdi
	jz      .Lgtod_zero_tz_only

1:	movl    vvar_seq(%rip), %r8d
	testl   $1, %r8d
	jnz     1b
	movq    vvar_tsc_at_boot(%rip),  %r10
	movq    vvar_tsc_ns_mult(%rip),  %r11
	movl    vvar_tsc_ns_shift(%rip), %ecx
	movq    vvar_wall_secs(%rip),    %r9
	test    %r11, %r11
	jz      .Lgtod_from_ticks
	rdtsc
	shlq    $32, %rdx
	orq     %rdx, %rax
	lfence
	movl    vvar_seq(%rip), %edx
	cmpl    %r8d, %edx
	jne     1b

	subq    %r10, %rax
	mulq    %r11
	shrdq   %cl, %rdx, %rax                  /* rax = ns since boot */
	movq    $NS_PER_SEC, %r11
	xorq    %rdx, %rdx
	divq    %r11                             /* rax = sec, rdx = nsec */
	addq    %r9, %rax                        /* + wall_secs */
	movq    %rax, 0(%rdi)
	movq    %rdx, %rax
	movq    $1000, %r11
	xorq    %rdx, %rdx
	divq    %r11                             /* rax = nsec/1000 = usec */
	movq    %rax, 8(%rdi)
	jmp     .Lgtod_zero_tz_only

/* Calibration not yet published — fall back to 10 ms tick. */
.Lgtod_from_ticks:
1:	movl    vvar_seq(%rip), %r8d
	testl   $1, %r8d
	jnz     1b
	movq    vvar_ticks(%rip),     %rax
	movq    vvar_wall_secs(%rip), %rcx
	lfence
	movl    vvar_seq(%rip), %r9d
	cmpl    %r8d, %r9d
	jne     1b

	movq    $TICK_HZ, %r11
	xorq    %rdx, %rdx
	divq    %r11
	addq    %rcx, %rax
	movq    %rax, 0(%rdi)
	movq    %rdx, %rax
	imulq   $US_PER_TICK, %rax
	movq    %rax, 8(%rdi)

.Lgtod_zero_tz_only:
	test    %rsi, %rsi
	jz      .Lgtod_done
	movl    $0, 0(%rsi)
	movl    $0, 4(%rsi)
.Lgtod_done:
	xorl    %eax, %eax
	ret
	.cfi_endproc
	.size __vdso_gettimeofday, .-__vdso_gettimeofday


/* ── __vdso_time ───────────────────────────────────────────────────────
 *
 * time_t __vdso_time(time_t *tloc)
 *
 * Returns seconds since the UNIX epoch and writes the same value to *tloc
 * if non-NULL.  Second-granularity, so the cheap tick-counter path is
 * sufficient — no TSC reading.
 *
 * Args:    rdi = tloc
 * Return:  rax = seconds since epoch.
 */
	.globl __vdso_time
	.type  __vdso_time, @function
__vdso_time:
	.cfi_startproc
1:	movl    vvar_seq(%rip), %r8d
	testl   $1, %r8d
	jnz     1b
	movq    vvar_ticks(%rip),     %rax
	movq    vvar_wall_secs(%rip), %rcx
	lfence
	movl    vvar_seq(%rip), %r9d
	cmpl    %r8d, %r9d
	jne     1b

	movq    $TICK_HZ, %r11
	xorq    %rdx, %rdx
	divq    %r11
	addq    %rcx, %rax              /* rax = secs */

	test    %rdi, %rdi
	jz      .Lt_done
	movq    %rax, 0(%rdi)
.Lt_done:
	ret
	.cfi_endproc
	.size __vdso_time, .-__vdso_time


/* ── __vdso_getcpu ─────────────────────────────────────────────────────
 *
 * int __vdso_getcpu(unsigned *cpu, unsigned *node, void *unused)
 *
 * RDTSCP returns the logical CPU index in ECX (kernel writes IA32_TSC_AUX
 * = cpu_index on every AP at startup).  NUMA node is hard-coded to 0
 * (single node).
 *
 * Args:    rdi = cpu, rsi = node, rdx = unused
 * Return:  rax = 0.
 */
	.globl __vdso_getcpu
	.type  __vdso_getcpu, @function
__vdso_getcpu:
	.cfi_startproc
	rdtscp                          /* eax/edx/ecx: tsc[lo]/[hi]/aux */
	test    %rdi, %rdi
	jz      1f
	movl    %ecx, 0(%rdi)
1:	test    %rsi, %rsi
	jz      2f
	movl    $0, 0(%rsi)
2:	xorl    %eax, %eax
	ret
	.cfi_endproc
	.size __vdso_getcpu, .-__vdso_getcpu


/*
 * vvar_* symbols are defined in vdso.lds at virtual addresses below 0,
 * so rip-relative references in the code above resolve to fixed negative
 * 32-bit displacements at link time and reach the kernel-supplied vvar
 * page wherever the kernel maps the vDSO at runtime.
 */

/* No executable stack. */
	.section .note.GNU-stack, "", @progbits
