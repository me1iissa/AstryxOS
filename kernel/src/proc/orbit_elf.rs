//! Embedded "Orbit" shell ELF64 binary for Ring 3.
//!
//! Orbit is the AstryxOS user-mode shell process. This hand-crafted ELF64
//! executable:
//! 1. Calls `write(1, "Orbit: AstryxOS user shell\n", 27)` via SYSCALL
//! 2. Enters an infinite `yield()` loop (placeholder for future interactive REPL)
//!
//! In future phases, Orbit will read from stdin, parse commands, and execute
//! programs. For now it serves as proof that a user-mode shell process can be
//! launched and scheduled.
//!
//! The binary is a single PT_LOAD segment loaded at virtual address 0x400000.
//! Total size: 188 bytes.
//!
//! # Layout
//! ```text
//! Offset 0x00: ELF64 Header (64 bytes)
//! Offset 0x40: Program Header (56 bytes)
//! Offset 0x78: Code (41 bytes)
//! Offset 0xA1: Data — "Orbit: AstryxOS user shell\n" (27 bytes)
//! ```
//!
//! # Generated assembly (x86_64)
//! ```asm
//! _start:                             ; 0x400078
//!     mov rax, 1                      ; SYS_WRITE
//!     mov rdi, 1                      ; fd = stdout
//!     lea rsi, [rip + 0x14]           ; buf = "Orbit: AstryxOS user shell\n"
//!     mov rdx, 27                     ; count
//!     syscall
//!
//! .loop:                              ; 0x400096
//!     mov rax, 13                     ; SYS_YIELD
//!     syscall
//!     jmp .loop                       ; eb f5 (-0x0b)
//!
//! msg:                                ; 0x4000A1
//!     db "Orbit: AstryxOS user shell", 0x0A
//! ```

/// The complete Orbit shell ELF64 binary (188 bytes).
pub static ORBIT_ELF: [u8; 188] = [
    // ── ELF64 Header (64 bytes) ────────────────────────────────────────
    0x7F, 0x45, 0x4C, 0x46, // e_ident[0..4]: magic "\x7fELF"
    0x02,                   // e_ident[4]: EI_CLASS = ELFCLASS64
    0x01,                   // e_ident[5]: EI_DATA = ELFDATA2LSB
    0x01,                   // e_ident[6]: EI_VERSION = EV_CURRENT
    0x00,                   // e_ident[7]: EI_OSABI = ELFOSABI_NONE
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_ident[8..16]: padding

    0x02, 0x00,             // e_type: ET_EXEC
    0x3E, 0x00,             // e_machine: EM_X86_64
    0x01, 0x00, 0x00, 0x00, // e_version: EV_CURRENT

    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry: 0x400078
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff: 64 (0x40)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff: 0

    0x00, 0x00, 0x00, 0x00, // e_flags: 0
    0x40, 0x00,             // e_ehsize: 64
    0x38, 0x00,             // e_phentsize: 56
    0x01, 0x00,             // e_phnum: 1
    0x00, 0x00,             // e_shentsize: 0
    0x00, 0x00,             // e_shnum: 0
    0x00, 0x00,             // e_shstrndx: 0

    // ── Program Header (56 bytes) ──────────────────────────────────────
    0x01, 0x00, 0x00, 0x00, // p_type: PT_LOAD
    0x05, 0x00, 0x00, 0x00, // p_flags: PF_R | PF_X
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset: 0
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr: 0x400000
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr: 0x400000
    0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz: 188 (0xBC)
    0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz: 188
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align: 0x1000

    // ── Code (41 bytes at file offset 0x78) ────────────────────────────
    // Virtual address: 0x400078

    // write(1, msg, 27) — SYS_WRITE
    // mov rax, 1
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
    // mov rdi, 1          ; fd = stdout
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,
    // lea rsi, [rip + 0x14] ; buf = msg (RIP after this insn = 0x40008D, msg at 0x4000A1)
    0x48, 0x8D, 0x35, 0x14, 0x00, 0x00, 0x00,
    // mov rdx, 27         ; count
    0x48, 0xC7, 0xC2, 0x1B, 0x00, 0x00, 0x00,
    // syscall
    0x0F, 0x05,

    // .loop (offset 0x96, vaddr 0x400096):
    // yield() — SYS_YIELD
    // mov rax, 13
    0x48, 0xC7, 0xC0, 0x0D, 0x00, 0x00, 0x00,
    // syscall
    0x0F, 0x05,

    // jmp .loop           ; offset = 0x96 - 0xA1 = -0x0B = 0xF5
    0xEB, 0xF5,

    // ── Data: "Orbit: AstryxOS user shell\n" (27 bytes at offset 0xA1) ─
    // Virtual address: 0x4000A1
    0x4F, 0x72, 0x62, 0x69, 0x74, 0x3A, 0x20,                         // "Orbit: "
    0x41, 0x73, 0x74, 0x72, 0x79, 0x78, 0x4F, 0x53, 0x20,             // "AstryxOS "
    0x75, 0x73, 0x65, 0x72, 0x20,                                       // "user "
    0x73, 0x68, 0x65, 0x6C, 0x6C, 0x0A,                                 // "shell\n"
];
