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

    /* LLVM source-based coverage sections (kernel `coverage` feature).
     *
     * When the kernel is built with `-C instrument-coverage`, rustc emits
     * these sections per crate.  The linker auto-generates `__start_X`
     * and `__stop_X` symbols for sections that follow C-identifier
     * naming rules, which the in-kernel coverage dumper walks at exit.
     *
     * When the `coverage` feature is OFF the kernel is not built with
     * -C instrument-coverage, the input sections are empty, and these
     * output sections collapse to zero bytes — the default kernel image
     * remains byte-identical to the pre-coverage build.  We always emit
     * the named sections so the start/stop symbols resolve in either
     * build (the in-kernel walker tolerates start == stop). */
    .llvm_prf_cnts ALIGN(8) : AT(ADDR(.llvm_prf_cnts) - KERNEL_VIRT_BASE)
    {
        __start___llvm_prf_cnts = .;
        KEEP(*(__llvm_prf_cnts))
        __stop___llvm_prf_cnts = .;
    }
    .llvm_prf_data ALIGN(8) : AT(ADDR(.llvm_prf_data) - KERNEL_VIRT_BASE)
    {
        __start___llvm_prf_data = .;
        KEEP(*(__llvm_prf_data))
        __stop___llvm_prf_data = .;
    }
    .llvm_prf_names ALIGN(8) : AT(ADDR(.llvm_prf_names) - KERNEL_VIRT_BASE)
    {
        __start___llvm_prf_names = .;
        KEEP(*(__llvm_prf_names))
        __stop___llvm_prf_names = .;
    }
    /* Note: `.llvm_covmap` and `.llvm_covfun` are emitted by LLVM as
     * non-allocated metadata sections (no `A` flag).  We intentionally
     * do NOT place them in this script — letting rust-lld put them at
     * vaddr 0 as ELF-only debug-style sections keeps them out of the
     * runtime kernel image (saving ~1 MiB of RAM) while still leaving
     * them readable by host-side `llvm-cov` against the ELF.  The
     * in-kernel coverage dumper only walks the three allocated `prf_*`
     * sections; the host post-processor reads covmap/covfun from
     * `target/x86_64-astryx/release/astryx-kernel` directly. */

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
