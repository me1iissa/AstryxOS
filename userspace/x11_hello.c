/*
 * x11_hello.c — minimal X11 oracle client
 *
 * Connects to /tmp/.X11-unix/X0, sends the X11 connection setup (little-endian,
 * protocol 11.0, no auth), parses the setup reply, creates + maps a 400x300
 * InputOutput window, waits 500 ms, destroys the window, and exits 0.
 *
 * Built with: gcc -O2 -static -o build/x11_hello userspace/x11_hello.c
 *
 * No Xlib dependency — all X11 wire protocol is hand-built here.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sched.h>

/* ── X11 protocol constants ──────────────────────────────────────────────── */

#define X11_LE              0x6C   /* 'l' — little-endian byte order mark */
#define X11_PROTO_MAJOR     11
#define X11_PROTO_MINOR     0

/* Opcodes we use */
#define OP_CREATE_WINDOW    1
#define OP_DESTROY_WINDOW   4
#define OP_MAP_WINDOW       8

/* CreateWindow value-list masks */
#define CW_BACK_PIXEL       0x0002
#define CW_EVENT_MASK       0x0800

/* ── Little-endian write helpers ─────────────────────────────────────────── */

static void w16(uint8_t *b, int off, uint16_t v)
{
    b[off+0] = v & 0xFF;
    b[off+1] = (v >> 8) & 0xFF;
}

static void w32(uint8_t *b, int off, uint32_t v)
{
    b[off+0] = v & 0xFF;
    b[off+1] = (v >> 8) & 0xFF;
    b[off+2] = (v >> 16) & 0xFF;
    b[off+3] = (v >> 24) & 0xFF;
}

static uint16_t r16(const uint8_t *b, int off)
{
    return (uint16_t)b[off] | ((uint16_t)b[off+1] << 8);
}

static uint32_t r32(const uint8_t *b, int off)
{
    return (uint32_t)b[off]
         | ((uint32_t)b[off+1] << 8)
         | ((uint32_t)b[off+2] << 16)
         | ((uint32_t)b[off+3] << 24);
}

/* ── Blocking I/O helpers ─────────────────────────────────────────────────── */

static int xwrite(int fd, const void *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n = (int)write(fd, (const char *)buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int xread(int fd, void *buf, int len)
{
    /*
     * Blocking read with EAGAIN retry.
     *
     * AstryxOS Unix sockets are non-blocking by default: a read when the
     * buffer is empty returns -1/EAGAIN rather than blocking.  We yield the
     * CPU on EAGAIN so the kernel X11 server gets time to poll the socket and
     * push the reply, then retry.  Limit retries to avoid hanging forever.
     */
    int got = 0;
    int retries = 0;
    const int MAX_RETRIES = 100000;
    while (got < len && retries < MAX_RETRIES) {
        int n = (int)read(fd, (char *)buf + got, len - got);
        if (n > 0) {
            got += n;
            retries = 0;   /* reset retry counter on progress */
        } else if (n == 0) {
            break;   /* EOF */
        } else {
            /* n < 0: EAGAIN or other error */
            if (errno == EAGAIN || errno == EINTR) {
                sched_yield();
                retries++;
            } else {
                break;   /* real error */
            }
        }
    }
    return got;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* 1. Open Unix socket and connect to the X server ───────────────────── */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        write(2, "x11_hello: socket() failed\n", 27);
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/.X11-unix/X0", sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        write(2, "x11_hello: connect() failed\n", 28);
        close(fd);
        return 1;
    }

    /* 2. Send connection setup request ──────────────────────────────────── */
    /*
     * X11 ClientHello (little-endian, no auth):
     *   [0]   byte-order = 0x6C ('l')
     *   [1]   pad
     *   [2-3] protocol-major = 11
     *   [4-5] protocol-minor = 0
     *   [6-7] auth-name-len = 0
     *   [8-9] auth-data-len = 0
     *   [10-11] pad
     */
    uint8_t hello[12];
    memset(hello, 0, sizeof(hello));
    hello[0] = X11_LE;
    hello[2] = X11_PROTO_MAJOR;
    hello[4] = X11_PROTO_MINOR;
    /* auth name = "MIT-MAGIC-COOKIE-1", length = 18; auth data = empty */
    w16(hello, 6, 18);   /* auth-name-len */
    w16(hello, 8, 0);    /* auth-data-len */

    /*
     * After the fixed 12-byte header, the protocol requires:
     *   auth-name (18 bytes) + 2 bytes pad (to align to 4) = 20 bytes
     *   auth-data (0 bytes)
     * Total setup request = 12 + 20 = 32 bytes.
     */
    uint8_t setup_req[32];
    memset(setup_req, 0, sizeof(setup_req));
    setup_req[0] = X11_LE;
    w16(setup_req, 2, X11_PROTO_MAJOR);
    w16(setup_req, 4, X11_PROTO_MINOR);
    w16(setup_req, 6, 18);   /* auth-name-len */
    w16(setup_req, 8,  0);   /* auth-data-len */
    /* auth-name at bytes 12..29 */
    memcpy(setup_req + 12, "MIT-MAGIC-COOKIE-1", 18);
    /* 2 bytes of pad already zero */

    if (xwrite(fd, setup_req, sizeof(setup_req)) != (int)sizeof(setup_req)) {
        write(2, "x11_hello: write setup failed\n", 30);
        close(fd);
        return 1;
    }

    /* 3. Read and parse the server setup reply ──────────────────────────── */
    uint8_t rep[256];
    memset(rep, 0, sizeof(rep));

    /* Read at least 8 bytes to check the success byte and length */
    int n = xread(fd, rep, 8);
    if (n < 8) {
        write(2, "x11_hello: short setup reply\n", 29);
        close(fd);
        return 1;
    }

    if (rep[0] != 1) {
        /* Failure or authenticate replies */
        write(2, "x11_hello: server rejected setup\n", 33);
        close(fd);
        return 1;
    }

    /* additional-data length in 4-byte units */
    uint16_t add_units = r16(rep, 6);
    int      add_bytes = (int)add_units * 4;
    int      total     = 8 + add_bytes;

    /* Read the rest of the setup reply (up to our buffer size) */
    int remaining = total - 8;
    if (remaining > (int)(sizeof(rep) - 8))
        remaining = (int)(sizeof(rep) - 8);
    if (remaining > 0) {
        xread(fd, rep + 8, remaining);
    }

    /*
     * Parse root window id and default visual from the setup reply.
     * The Xastryx setup reply layout (build_setup_ok in x11/mod.rs):
     *
     *   Bytes  0- 7: fixed header (success=1, pad, major, minor, add_units)
     *   Bytes  8-11: release-number
     *   Bytes 12-15: resource-id-base
     *   Bytes 16-19: resource-id-mask
     *   Bytes 20-23: motion-buffer-size
     *   Bytes 24-25: vendor-length (7 = "Xastryx")
     *   Bytes 26-27: max-request-length
     *   Byte   28:   number-of-screens
     *   Byte   29:   number-of-formats
     *   ...
     *   Bytes 40-46: vendor string "Xastryx"
     *   Bytes 48-50: root-depth, n_formats(32), n_formats(32)
     *   ...
     *   Bytes 56-59: root-window-id = 1
     *   Bytes 60-63: default-colormap = 1
     *   Bytes 64-67: white-pixel
     *   Bytes 68-71: black-pixel
     *   ...
     *   Bytes 76-77: screen-width  = 1920
     *   Bytes 78-79: screen-height = 1080
     *   ...
     *   Bytes 104-107: visual-id = 32
     *
     * We derive these offsets by hand from build_setup_ok() in kernel/src/x11/mod.rs.
     * Minimum reply to cover offset 59 = 60 bytes total.
     */
    uint32_t root_wid  = (total >= 60) ? r32(rep, 56) : 1u;
    uint32_t visual_id = (total >= 108) ? r32(rep, 104) : 32u;

    /* Fall back to known-good values if the reply is shorter than expected */
    if (root_wid  == 0) root_wid  = 1;
    if (visual_id == 0) visual_id = 32;

    uint32_t res_base = (total >= 16) ? r32(rep, 12) : 0x00400000u;
    uint32_t res_mask = (total >= 20) ? r32(rep, 16) : 0x001FFFFFu;

    /* Allocate the first resource id inside the server's allowed range */
    uint32_t wid = res_base | 1u;   /* window resource id */

    /* 4. CreateWindow (opcode 1) — 400x300 InputOutput at (10,10) ──────── */
    /*
     * Wire format (little-endian):
     *   [0]     opcode=1
     *   [1]     depth=0 (CopyFromParent)
     *   [2-3]   request-length in 4-byte words
     *   [4-7]   window-id
     *   [8-11]  parent-id (root)
     *   [12-13] x
     *   [14-15] y
     *   [16-17] width
     *   [18-19] height
     *   [20-21] border-width
     *   [22-23] window-class (1 = InputOutput)
     *   [24-27] visual-id (0 = CopyFromParent)
     *   [28-31] value-mask
     *   [32-35] bg-pixel  (if CW_BACK_PIXEL in vmask)
     *   [36-39] event-mask (if CW_EVENT_MASK in vmask)
     *
     * vmask = CW_BACK_PIXEL(0x0002) | CW_EVENT_MASK(0x0800)
     * → two value-list entries → total = 40 bytes = 10 words
     */
    uint8_t create_win[40];
    memset(create_win, 0, sizeof(create_win));
    create_win[0] = OP_CREATE_WINDOW;
    create_win[1] = 0;                        /* depth = CopyFromParent */
    w16(create_win, 2, 10);                   /* request-length = 10 words */
    w32(create_win, 4,  wid);                 /* window id */
    w32(create_win, 8,  root_wid);            /* parent = root */
    w16(create_win, 12, 10);                  /* x = 10 */
    w16(create_win, 14, 10);                  /* y = 10 */
    w16(create_win, 16, 400);                 /* width */
    w16(create_win, 18, 300);                 /* height */
    w16(create_win, 20, 0);                   /* border-width */
    w16(create_win, 22, 1);                   /* class = InputOutput */
    w32(create_win, 24, 0);                   /* visual = CopyFromParent */
    w32(create_win, 28, CW_BACK_PIXEL | CW_EVENT_MASK);
    w32(create_win, 32, 0x003C6090);          /* bg-pixel: steel-blue */
    w32(create_win, 36, 0x00008000);          /* event-mask: ExposureMask */

    if (xwrite(fd, create_win, sizeof(create_win)) != (int)sizeof(create_win)) {
        write(2, "x11_hello: CreateWindow write failed\n", 37);
        close(fd);
        return 1;
    }

    /* 5. MapWindow (opcode 8) ────────────────────────────────────────────── */
    /*
     *   [0]    opcode=8
     *   [1]    pad
     *   [2-3]  request-length=2 words
     *   [4-7]  window-id
     */
    uint8_t map_win[8];
    memset(map_win, 0, sizeof(map_win));
    map_win[0] = OP_MAP_WINDOW;
    w16(map_win, 2, 2);
    w32(map_win, 4, wid);

    if (xwrite(fd, map_win, sizeof(map_win)) != (int)sizeof(map_win)) {
        write(2, "x11_hello: MapWindow write failed\n", 34);
        close(fd);
        return 1;
    }

    /* 6. Signal success ─────────────────────────────────────────────────── */
    write(1, "X11 window mapped\n", 18);

    /* 7. Sleep 500 ms so the WM can observe the window ─────────────────── */
    struct timespec ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = 500000000L;  /* 500 ms */
    nanosleep(&ts, NULL);

    /* 8. DestroyWindow (opcode 4) ───────────────────────────────────────── */
    uint8_t destroy_win[8];
    memset(destroy_win, 0, sizeof(destroy_win));
    destroy_win[0] = OP_DESTROY_WINDOW;
    w16(destroy_win, 2, 2);
    w32(destroy_win, 4, wid);

    xwrite(fd, destroy_win, sizeof(destroy_win));

    /* 9. Close the socket and exit ──────────────────────────────────────── */
    close(fd);
    return 0;
}
