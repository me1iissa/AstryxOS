/* AstryxOS Kernel (Aether) Linker Script
 *
 * The kernel is loaded as a flat binary at physical address KERNEL_PHYS_BASE
 * (1 MiB), but linked at the higher-half virtual address
 * KERNEL_VIRT_BASE + KERNEL_PHYS_BASE (0xFFFF_8000_0010_0000).
 *
 * Using AT() on each section keeps the LMA (load/physical address) at
 * KERNEL_PHYS_BASE so that objcopy -O binary produces a compact flat file,
 * while all symbols (statics, functions) get higher-half VMAs that are
 * accessible via PML4[256] in every address space.  This prevents user-mode
 * ELF segments loaded in PML4[0] (0x400000+) from aliasing kernel statics.
 */

ENTRY(_start)

KERNEL_PHYS_BASE = 0x100000;
KERNEL_VIRT_BASE = 0xFFFF800000000000;

SECTIONS
{
    /* VMA at higher-half; LMA at physical base via AT(). */
    . = KERNEL_VIRT_BASE + KERNEL_PHYS_BASE;

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VIRT_BASE)
    {
        __text_start = .;
        *(.text.boot)    /* Boot entry point first */
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VIRT_BASE)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VIRT_BASE)
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VIRT_BASE)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Kernel end marker (page-aligned) */
    . = ALIGN(4K);
    __kernel_end = .;

    /* DWARF debug sections — address 0 means not loaded into memory.
     * objcopy -O binary omits these from kernel.bin automatically.
     * Kept in the ELF so GDB can use symbols, line numbers, and types. */
    .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
    .debug_abbrev   0 : { *(.debug_abbrev) }
    .debug_loc      0 : { *(.debug_loc) }
    .debug_loclists 0 : { *(.debug_loclists) }
    .debug_str      0 : { *(.debug_str) }
    .debug_str_offsets 0 : { *(.debug_str_offsets) }
    .debug_line     0 : { *(.debug_line) }
    .debug_line_str 0 : { *(.debug_line_str) }
    .debug_ranges   0 : { *(.debug_ranges) }
    .debug_rnglists 0 : { *(.debug_rnglists) }
    .debug_frame    0 : { *(.debug_frame) }
    .debug_aranges  0 : { *(.debug_aranges) }
    .debug_pubnames 0 : { *(.debug_pubnames) }
    .debug_pubtypes 0 : { *(.debug_pubtypes) }
    .debug_macro    0 : { *(.debug_macro) }
    .debug_addr     0 : { *(.debug_addr) }
    .debug_names    0 : { *(.debug_names) }

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
        *(.note.*)
    }
}
