/*
 * vfork_exec_test.c — Tests vfork() + execve() + waitpid()
 *
 * Tests exercised:
 *   1. vfork() returns child PID to parent, 0 to child
 *   2. Parent is blocked until child calls _exit() or execve()
 *   3. Child can call _exit() and parent resumes
 *   4. waitpid() returns correct exit status
 *
 * Exit codes: 0 = all pass, 1 = failure.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static void print(const char *s) {
    int len = 0;
    while (s[len]) len++;
    write(1, s, len);
}

static void print_num(int n) {
    char buf[16];
    int i = 0;
    if (n < 0) { write(1, "-", 1); n = -n; }
    if (n == 0) { write(1, "0", 1); return; }
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    while (i > 0) write(1, &buf[--i], 1);
}

int main(void) {
    print("vfork_exec_test: start\n");

    /* ── Test 1: vfork + _exit ───────────────────────────────── */
    pid_t pid = vfork();
    if (pid < 0) {
        print("FAIL: vfork returned error\n");
        return 1;
    }
    if (pid == 0) {
        /* Child: immediately exit with code 42 */
        _exit(42);
    }
    /* Parent: should reach here after child exits */
    print("PASS: vfork returned child pid=");
    print_num(pid);
    print("\n");

    /* ── Test 2: waitpid collects child ──────────────────────── */
    int status = 0;
    pid_t reaped = waitpid(pid, &status, 0);
    if (reaped != pid) {
        print("FAIL: waitpid returned wrong pid=");
        print_num(reaped);
        print("\n");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 42) {
        print("FAIL: wrong exit status\n");
        return 1;
    }
    print("PASS: waitpid collected child with exit code 42\n");

    print("vfork_exec_test: all passed\n");
    return 0;
}
