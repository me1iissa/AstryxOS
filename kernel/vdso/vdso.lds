/*
 * GNU linker script for the AstryxOS vDSO.
 *
 * The vDSO is a tiny position-independent shared object embedded in the
 * kernel image and mapped into every user process at execve time.
 *
 * Layout in vaddr space (PIC; the entire object relocates as a unit):
 *
 *   base - 0x1000   vvar page  (kernel-managed; mapped separately at
 *                               runtime, NOT part of any PT_LOAD).
 *   base + 0x0000   ELF header + dynamic info
 *   base + 0x1000   .text  (single PT_LOAD covers both pages,
 *                           file-offset == vaddr 1:1)
 *
 * AT_SYSINFO_EHDR is set by the kernel ELF loader to user_base — the
 * runtime address of the vDSO ELF header.
 *
 * The vvar fields are PROVIDE()'d at virtual addresses BELOW 0 so that
 * RIP-relative loads from .text resolve to fixed negative 32-bit
 * displacements at link time.  At runtime, the kernel maps a real page
 * at user_base - 0x1000 (the vvar page) so each rip-relative reference
 * lands on the corresponding kernel-maintained field.
 *
 * Symbol versioning: glibc / musl look up the four __vdso_* symbols
 * under version "LINUX_2.6" via standard GNU symbol versioning.
 *
 * Public references:
 *   ELF-64 spec — PT_LOAD, p_vaddr/p_filesz/p_memsz, dynamic linking
 *   GNU ld manual — VERSION script, PHDRS, PROVIDE, "." location counter
 *   vdso(7)    — AT_SYSINFO_EHDR semantics, version-symbol conventions
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

ENTRY(__vdso_clock_gettime)

PHDRS {
	text     PT_LOAD    FILEHDR PHDRS FLAGS(5);   /* R + X header + code */
	dynamic  PT_DYNAMIC FLAGS(4);
}

SECTIONS {
	/*
	 * Anchor the vvar page one page BELOW the loaded image so RIP-
	 * relative references in .text encode a fixed negative displacement
	 * that the kernel mapping reproduces at runtime.
	 */
	. = -0x1000;

	vvar_seq       = . + 0x00;   /* u32 — sequence counter        */
	vvar_tick_hz   = . + 0x04;   /* u32 — PIT frequency           */
	vvar_ticks     = . + 0x08;   /* u64 — monotonic PIT ticks     */
	vvar_wall_secs = . + 0x10;   /* u64 — UNIX seconds at boot    */

	/*
	 * Place ELF header + program headers + dynamic info at vaddr 0
	 * (file offset 0).  The PT_LOAD covers [0, end) with file-offset
	 * == vaddr so the kernel can map the bytes 1:1 at user_base.
	 */
	. = 0;
	. = . + SIZEOF_HEADERS;
	.hash           : { *(.hash) }                  :text
	.gnu.hash       : { *(.gnu.hash) }              :text
	.dynsym         : { *(.dynsym) }                :text
	.dynstr         : { *(.dynstr) }                :text
	.gnu.version    : { *(.gnu.version) }           :text
	.gnu.version_d  : { *(.gnu.version_d) }         :text
	.gnu.version_r  : { *(.gnu.version_r) }         :text
	.dynamic        : { *(.dynamic) }               :text :dynamic
	.rodata         : { *(.rodata*) }               :text
	.note           : { *(.note*) }                 :text
	.eh_frame_hdr   : { *(.eh_frame_hdr) }          :text
	.eh_frame       : { *(.eh_frame) }              :text

	/* .text starts on a fresh page boundary so AT_SYSINFO_EHDR + 0x1000
	 * is the conventional code-page address.  Most callers don't care
	 * about this alignment, but it makes the in-process map predictable. */
	. = ALIGN(0x1000);
	.text           : { *(.text*) }                 :text

	/DISCARD/       : { *(.comment) *(.debug*) *(.note.GNU-stack) }
}

VERSION {
	LINUX_2.6 {
	global:
		__vdso_clock_gettime;
		__vdso_gettimeofday;
		__vdso_time;
		__vdso_getcpu;
	local: *;
	};
}
