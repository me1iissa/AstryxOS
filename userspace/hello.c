/*
 * hello.c — First musl libc program for AstryxOS
 *
 * Compile: musl-gcc -static -no-pie -O2 -o build/hello userspace/hello.c
 * Expected syscalls: arch_prctl, set_tid_address, (mmap/brk for setup),
 *                    writev or write, exit_group
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[], char *envp[])
{
    printf("Hello from AstryxOS userspace!\n");
    printf("argc = %d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("  argv[%d] = \"%s\"\n", i, argv[i]);
    for (int i = 0; envp[i]; i++)
        printf("  env[%d]  = \"%s\"\n", i, envp[i]);
    return 0;
}
