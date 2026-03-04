//! Embedded "Ascension" init process ELF64 binary for Ring 3.
//!
//! Ascension is the AstryxOS init process (PID 1). This hand-crafted ELF64
//! executable:
//! 1. Calls `write(1, "Ascension: AstryxOS init started\n", 33)` via SYSCALL
//! 2. Calls `getpid()` to confirm PID
//! 3. Enters an infinite loop: `yield()` then `waitpid(-1, NULL, WNOHANG)` to
//!    reap zombie children.
//!
//! The binary is a single PT_LOAD segment loaded at virtual address 0x400000.
//! Total size: 229 bytes.
//!
//! # Layout
//! ```text
//! Offset 0x00: ELF64 Header (64 bytes)
//! Offset 0x40: Program Header (56 bytes)
//! Offset 0x78: Code (76 bytes)
//! Offset 0xC4: Data — "Ascension: AstryxOS init started\n" (33 bytes)
//! ```
//!
//! # Generated assembly (x86_64)
//! ```asm
//! _start:                             ; 0x400078
//!     mov rax, 1                      ; SYS_WRITE
//!     mov rdi, 1                      ; fd = stdout
//!     lea rsi, [rip + 0x37]           ; buf = "Ascension: AstryxOS init started\n"
//!     mov rdx, 33                     ; count
//!     syscall
//!
//!     mov rax, 8                      ; SYS_GETPID
//!     syscall                         ; rax = our PID
//!
//! .loop:                              ; 0x40009F
//!     mov rax, 13                     ; SYS_YIELD
//!     syscall
//!
//!     mov rax, 7                      ; SYS_WAITPID
//!     mov rdi, -1                     ; pid = -1 (any child)
//!     xor rsi, rsi                    ; status_ptr = NULL
//!     mov rdx, 1                      ; options = WNOHANG
//!     syscall
//!
//!     jmp .loop                       ; eb db (-0x25)
//!
//! msg:                                ; 0x4000C4
//!     db "Ascension: AstryxOS init started", 0x0A
//! ```

/// The complete Ascension init ELF64 binary (229 bytes).
pub static ASCENSION_ELF: [u8; 229] = [
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
    0xE5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz: 229 (0xE5)
    0xE5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz: 229
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align: 0x1000

    // ── Code (76 bytes at file offset 0x78) ────────────────────────────
    // Virtual address: 0x400078

    // write(1, msg, 33) — SYS_WRITE
    // mov rax, 1
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
    // mov rdi, 1          ; fd = stdout
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,
    // lea rsi, [rip + 0x37] ; buf = msg (RIP after this insn = 0x40008D, msg at 0x4000C4)
    0x48, 0x8D, 0x35, 0x37, 0x00, 0x00, 0x00,
    // mov rdx, 33         ; count
    0x48, 0xC7, 0xC2, 0x21, 0x00, 0x00, 0x00,
    // syscall
    0x0F, 0x05,

    // getpid() — SYS_GETPID
    // mov rax, 8
    0x48, 0xC7, 0xC0, 0x08, 0x00, 0x00, 0x00,
    // syscall
    0x0F, 0x05,

    // .loop (offset 0x9F, vaddr 0x40009F):
    // yield() — SYS_YIELD
    // mov rax, 13
    0x48, 0xC7, 0xC0, 0x0D, 0x00, 0x00, 0x00,
    // syscall
    0x0F, 0x05,

    // waitpid(-1, NULL, WNOHANG) — SYS_WAITPID
    // mov rax, 7
    0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00,
    // mov rdi, -1         ; pid = any child
    0x48, 0xC7, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF,
    // xor rsi, rsi        ; status_ptr = NULL
    0x48, 0x31, 0xF6,
    // mov rdx, 1          ; options = WNOHANG
    0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
    // syscall
    0x0F, 0x05,

    // jmp .loop           ; offset = 0x9F - 0xC4 = -0x25 = 0xDB
    0xEB, 0xDB,

    // ── Data: "Ascension: AstryxOS init started\n" (33 bytes at offset 0xC4) ──
    // Virtual address: 0x4000C4
    0x41, 0x73, 0x63, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, // "Ascension: "
    0x41, 0x73, 0x74, 0x72, 0x79, 0x78, 0x4F, 0x53, 0x20,             // "AstryxOS "
    0x69, 0x6E, 0x69, 0x74, 0x20,                                       // "init "
    0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x0A,                     // "started\n"
];
