/* AstryxOS Kernel (Aether) Linker Script
 *
 * The kernel is loaded as a flat binary at physical address 0x100000 (1 MiB).
 * It is also mapped at the higher-half virtual address 0xFFFF_8000_0000_0000.
 */

ENTRY(_start)

KERNEL_PHYS_BASE = 0x100000;
KERNEL_VIRT_BASE = 0xFFFF800000000000;

SECTIONS
{
    /* Start at physical load address */
    . = KERNEL_PHYS_BASE;

    .text ALIGN(4K) : AT(ADDR(.text))
    {
        __text_start = .;
        *(.text.boot)    /* Boot entry point first */
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata))
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4K) : AT(ADDR(.data))
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    .bss ALIGN(4K) : AT(ADDR(.bss))
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Kernel end marker (page-aligned) */
    . = ALIGN(4K);
    __kernel_end = .;

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
        *(.note.*)
    }
}
