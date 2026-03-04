/*
 * mmap_test.c — Tests mmap() file-backed and anonymous mappings.
 *
 * Tests exercised:
 *   1. Anonymous mmap (MAP_ANONYMOUS | MAP_PRIVATE) read/write
 *   2. munmap of anonymous region
 *   3. File-backed mmap: open a file, mmap it at a non-zero offset, verify contents
 *   4. MAP_FIXED placement
 *
 * Exit codes: 0 = all pass, 1 = failure.
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* Minimal write() wrapper so we avoid printf / libc formatting */
static void print(const char *s) {
    int len = 0;
    while (s[len]) len++;
    write(1, s, len);
}

int main(void) {
    print("mmap_test: start\n");

    /* ── Test 1: anonymous mmap ──────────────────────────────────────── */
    void *anon = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anon == MAP_FAILED) {
        print("FAIL: anonymous mmap returned MAP_FAILED\n");
        return 1;
    }
    /* Write a pattern and read it back */
    unsigned char *p = (unsigned char *)anon;
    for (int i = 0; i < 256; i++) p[i] = (unsigned char)i;
    for (int i = 0; i < 256; i++) {
        if (p[i] != (unsigned char)i) {
            print("FAIL: anonymous mmap readback mismatch\n");
            return 1;
        }
    }
    print("PASS: anonymous mmap\n");

    /* ── Test 2: munmap ──────────────────────────────────────────────── */
    if (munmap(anon, 4096) != 0) {
        print("FAIL: munmap returned error\n");
        return 1;
    }
    print("PASS: munmap\n");

    /* ── Test 3: file-backed mmap at non-zero offset ─────────────────── */
    /*
     * Write a known pattern to a temp file, then mmap a page at offset 4096.
     * This exercises the arg6 (offset) path that was previously broken.
     */
    int fd = open("/tmp/mmap_test.bin", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        /* Try /disk/tmp if /tmp not available */
        fd = open("/disk/tmp/mmap_test.bin", O_RDWR | O_CREAT | O_TRUNC, 0644);
    }
    if (fd >= 0) {
        /* Write two pages: page 0 = 0xAA, page 1 = 0xBB */
        unsigned char page0[4096], page1[4096];
        memset(page0, 0xAA, 4096);
        memset(page1, 0xBB, 4096);
        write(fd, page0, 4096);
        write(fd, page1, 4096);

        /* mmap the SECOND page (offset = 4096) */
        void *mapped = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 4096);
        if (mapped == MAP_FAILED) {
            print("FAIL: file-backed mmap at offset 4096 returned MAP_FAILED\n");
            close(fd);
            return 1;
        }
        unsigned char *mp = (unsigned char *)mapped;
        int ok = 1;
        for (int i = 0; i < 4096; i++) {
            if (mp[i] != 0xBB) { ok = 0; break; }
        }
        munmap(mapped, 4096);
        close(fd);
        if (!ok) {
            print("FAIL: file-backed mmap offset read wrong data (arg6 broken?)\n");
            return 1;
        }
        print("PASS: file-backed mmap at non-zero offset\n");
    } else {
        print("SKIP: file-backed mmap (no writable tmp dir)\n");
    }

    /* ── Test 4: MAP_FIXED ───────────────────────────────────────────── */
    void *fixed = mmap((void *)0x500000, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (fixed == MAP_FAILED || fixed != (void *)0x500000) {
        print("FAIL: MAP_FIXED mmap\n");
        return 1;
    }
    ((unsigned char *)fixed)[0] = 0x42;
    if (((unsigned char *)fixed)[0] != 0x42) {
        print("FAIL: MAP_FIXED readback\n");
        return 1;
    }
    munmap(fixed, 4096);
    print("PASS: MAP_FIXED mmap\n");

    print("mmap_test: all passed\n");
    return 0;
}
