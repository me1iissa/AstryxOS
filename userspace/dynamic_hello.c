#include <unistd.h>

static void print(const char *s) {
    while (*s) { write(1, s, 1); s++; }
}

int main(void) {
    print("dynamic_hello: loaded via ld-musl\n");
    return 0;
}
