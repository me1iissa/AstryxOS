/* socket_test.c — exercises Linux socket syscalls as file descriptors
 *
 * Tests:
 *   1. socket(AF_INET, SOCK_STREAM, 0)  → get a fd
 *   2. socket(AF_INET, SOCK_DGRAM, 0)   → get a fd
 *   3. bind(udp_fd, 0.0.0.0:9090, 16)  → should succeed
 *   4. getsockname(udp_fd, ...) → family == AF_INET
 *   5. setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, 1)
 *   6. getsockopt(tcp_fd, SOL_SOCKET, SO_ERROR, &err) → err == 0
 *   7. close(tcp_fd), close(udp_fd)
 *   8. socket(AF_UNIX, SOCK_STREAM, 0) → get a fd, then close
 *
 * Compiled: musl-gcc -O2 -static -no-pie -o socket_test socket_test.c
 */

#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

/* Linux syscall numbers (x86-64) */
#define SYS_read        0
#define SYS_write       1
#define SYS_close       3
#define SYS_socket      41
#define SYS_connect     42
#define SYS_accept      43
#define SYS_sendto      44
#define SYS_recvfrom    45
#define SYS_bind        49
#define SYS_listen      50
#define SYS_getsockname 51
#define SYS_setsockopt  54
#define SYS_getsockopt  55
#define SYS_exit_group  231

#define AF_UNIX         1
#define AF_INET         2
#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOL_SOCKET      1
#define SO_REUSEADDR    2
#define SO_ERROR        4

/* Minimal sockaddr_in (16 bytes) */
typedef struct {
    uint16_t sin_family;
    uint16_t sin_port;   /* big-endian */
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
} SockaddrIn;

static long syscall6(long nr, long a, long b, long c, long d, long e, long f) {
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}
#define syscall0(n)             syscall6(n, 0, 0, 0, 0, 0, 0)
#define syscall1(n,a)           syscall6(n,(long)(a), 0, 0, 0, 0, 0)
#define syscall3(n,a,b,c)       syscall6(n,(long)(a),(long)(b),(long)(c), 0, 0, 0)
#define syscall5(n,a,b,c,d,e)   syscall6(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e), 0)

static void print(const char *s) { while(*s) { write(1,s,1); s++; } }
static void fail(const char *msg) { print("FAIL: "); print(msg); print("\n"); syscall1(SYS_exit_group, 1); }

int main(void) {
    /* 1. TCP socket */
    long tcp_fd = syscall3(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0) fail("socket(AF_INET,SOCK_STREAM)");
    print("socket_test: tcp_fd OK\n");

    /* 2. UDP socket */
    long udp_fd = syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) fail("socket(AF_INET,SOCK_DGRAM)");
    print("socket_test: udp_fd OK\n");

    /* 3. bind UDP to 0.0.0.0:9090 */
    SockaddrIn addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port   = (uint16_t)((9090 >> 8) | (9090 << 8)); /* htons(9090) */
    addr.sin_addr   = 0; /* INADDR_ANY */
    long r = syscall3(SYS_bind, udp_fd, (long)&addr, 16);
    if (r < 0) fail("bind udp");
    print("socket_test: bind OK\n");

    /* 4. getsockname — family must be AF_INET */
    SockaddrIn got = { 0 };
    uint32_t alen = 16;
    r = syscall3(SYS_getsockname, udp_fd, (long)&got, (long)&alen);
    if (r < 0) fail("getsockname");
    if (got.sin_family != AF_INET) fail("getsockname: bad family");
    print("socket_test: getsockname OK\n");

    /* 5. setsockopt SO_REUSEADDR */
    int optval = 1;
    r = syscall5(SYS_setsockopt, tcp_fd, SOL_SOCKET, SO_REUSEADDR, (long)&optval, 4);
    if (r < 0) fail("setsockopt");
    print("socket_test: setsockopt OK\n");

    /* 6. getsockopt SO_ERROR → expect 0 */
    int err = 99;
    uint32_t errlen = 4;
    r = syscall5(SYS_getsockopt, tcp_fd, SOL_SOCKET, SO_ERROR, (long)&err, (long)&errlen);
    if (r < 0) fail("getsockopt");
    if (err != 0) fail("SO_ERROR non-zero");
    print("socket_test: getsockopt SO_ERROR=0 OK\n");

    /* 7. close both */
    if (syscall1(SYS_close, tcp_fd) < 0) fail("close tcp");
    if (syscall1(SYS_close, udp_fd) < 0) fail("close udp");
    print("socket_test: close OK\n");

    /* 8. AF_UNIX socket */
    long unix_fd = syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (unix_fd < 0) fail("socket(AF_UNIX)");
    if (syscall1(SYS_close, unix_fd) < 0) fail("close unix");
    print("socket_test: AF_UNIX OK\n");

    print("socket_test: ALL PASSED\n");
    syscall1(SYS_exit_group, 0);
    __builtin_unreachable();
}
