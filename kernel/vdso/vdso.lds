/*
 * GNU version script for the AstryxOS vDSO.
 *
 * glibc's vDSO probe (dl-vdso.c) looks for symbols under version "LINUX_2.6".
 * All four vDSO entry points must be exported with this version string for
 * glibc (and musl, which also checks for LINUX_2.6 in its vdso_init) to
 * recognise the vDSO and bypass the syscall instruction.
 */
LINUX_2.6 {
    global:
        __vdso_clock_gettime;
        __vdso_gettimeofday;
        __vdso_time;
        __vdso_getcpu;
    local: *;
};
