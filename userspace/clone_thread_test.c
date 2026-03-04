/* clone_thread_test.c — tests CLONE_VM | CLONE_THREAD via raw syscall
 *
 * Compiled: musl-gcc -O2 -static -no-pie -o clone_thread_test clone_thread_test.c
 *
 * The child thread is detected by the clone() syscall returning 0 (fork-like
 * semantics via SYSCALL_USER_RIP).  It sets a volatile flag then exits directly
 * via syscall so no function-return stack frames are needed.
 */

#include <unistd.h>
#include <stdint.h>

#define CLONE_VM      0x00000100L
#define CLONE_SIGHAND 0x00000800L
#define CLONE_THREAD  0x00010000L

#define SYS_clone     56L
#define SYS_exit      60L
#define SYS_nanosleep 35L
#define SYS_exit_group 231L

/* Shared flag written by child, polled by parent. */
static volatile int child_ran = 0;

/* Separate stack for the child thread (8 KiB). */
static char child_stack[8192] __attribute__((aligned(16)));

static void print(const char *s) {
    while (*s) { write(1, s, 1); s++; }
}

int main(void) {
    long flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;

    /* Point new_sp at the top of child_stack (stacks grow downward). */
    char *new_sp = child_stack + sizeof(child_stack);
    new_sp = (char *)((uintptr_t)new_sp & ~15UL); /* 16-byte align */

    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_clone), "D"(flags), "S"(new_sp), "d"(0L)
        : "rcx", "r11", "memory"
    );

    if (ret < 0) {
        print("clone_thread_test: FAIL clone syscall error\n");
        __asm__ volatile("syscall" : : "a"(SYS_exit), "D"(1L) : "memory");
        __builtin_unreachable();
    }

    if (ret == 0) {
        /*
         * Child thread.  We are running on child_stack with no valid
         * call frames above us — never attempt to return from main.
         * Write the done flag and exit immediately via syscall.
         */
        child_ran = 1;
        print("clone_thread_test: child OK\n");
        __asm__ volatile("syscall" : : "a"(SYS_exit), "D"(0L) : "memory");
        __builtin_unreachable();
    }

    /* Parent: busy-wait with periodic yields until child sets the flag. */
    int timeout = 100000;
    while (!child_ran && timeout-- > 0) {
        /* nanosleep(NULL, NULL) — our stub just yields the CPU */
        long zero = 0L;
        __asm__ volatile("syscall"
            : : "a"(SYS_nanosleep), "D"(zero), "S"(zero) : "rcx", "r11", "memory");
    }

    if (!child_ran) {
        print("clone_thread_test: FAIL child timed out\n");
        __asm__ volatile("syscall" : : "a"(SYS_exit_group), "D"(1L) : "memory");
        __builtin_unreachable();
    }

    print("clone_thread_test: parent OK\n");
    __asm__ volatile("syscall" : : "a"(SYS_exit_group), "D"(0L) : "memory");
    __builtin_unreachable();
}
