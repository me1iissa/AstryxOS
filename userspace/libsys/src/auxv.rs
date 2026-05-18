//! Auxiliary-vector parsing and vDSO symbol resolution.
//!
//! # Background
//!
//! Per the System V ABI x86_64 supplement §3.4.1 (initial process
//! stack), the kernel hands `_start` a stack laid out as:
//!
//! ```text
//!   [argc]
//!   [argv[0]..argv[argc-1]] [NULL]
//!   [envp[0]..]              [NULL]
//!   [auxv[0]..]              [AT_NULL]
//!   [strings & 16 random bytes]
//! ```
//!
//! Each `auxv` entry is two `usize`-sized fields: `(a_type, a_un.a_val)`
//! per the ELF gABI auxiliary-vector format.  Entries terminate when
//! `a_type == AT_NULL` (0).
//!
//! This module exposes a [`getauxval`]-equivalent and a [`vdso_lookup`]
//! helper so native binaries (and libsys-internal code wanting the
//! vDSO fast path) don't each re-implement the auxv walk.  See
//! `getauxval(3)` and `vdso(7)` for the canonical reference.

#![allow(dead_code)]

use core::mem;
use core::ptr;

// ── AT_* type tags (ELF gABI; values match Linux UAPI elf.h) ────────

/// End-of-auxv sentinel.
pub const AT_NULL: u64 = 0;
/// File descriptor of the program (set by `execve(2)` when not via interpreter).
pub const AT_EXECFD: u64 = 2;
/// Program-header table address in the process image.
pub const AT_PHDR: u64 = 3;
/// Size in bytes of one program-header entry.
pub const AT_PHENT: u64 = 4;
/// Number of program-header entries.
pub const AT_PHNUM: u64 = 5;
/// System page size.
pub const AT_PAGESZ: u64 = 6;
/// Base address of the dynamic interpreter (`ld-linux.so` / `ld-musl.so`).
pub const AT_BASE: u64 = 7;
/// Program entry point.
pub const AT_ENTRY: u64 = 9;
/// Real user ID.
pub const AT_UID: u64 = 11;
/// Effective user ID.
pub const AT_EUID: u64 = 12;
/// Real group ID.
pub const AT_GID: u64 = 13;
/// Effective group ID.
pub const AT_EGID: u64 = 14;
/// Hardware-capability bitmask (CPUID-derived on x86_64).
pub const AT_HWCAP: u64 = 16;
/// `times(2)` clock frequency.
pub const AT_CLKTCK: u64 = 17;
/// Address of 16 random bytes (used by glibc/musl SSP and stack canary).
pub const AT_RANDOM: u64 = 25;
/// Base address of the vDSO ELF header (see `vdso(7)`).
pub const AT_SYSINFO_EHDR: u64 = 33;

/// One auxv entry as the kernel deposits it on the stack.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuxvEntry {
    pub a_type: u64,
    pub a_val: u64,
}

/// Iterator over a process's auxv given `(argc, argv)` as received in
/// `_start`.
pub struct AuxvIter {
    cursor: *const AuxvEntry,
}

impl AuxvIter {
    /// Build an iterator from `argc` + `argv` as received at process
    /// entry.  Returns an iterator positioned at the first auxv entry.
    ///
    /// # Safety
    /// `argv` must point at a valid `argc + 1`-element array (with a
    /// NULL terminator) followed in memory by `envp` (NULL-terminated)
    /// followed by the auxv.  This is the layout the ELF gABI initial
    /// process stack guarantees.
    pub unsafe fn from_argc_argv(argc: usize, argv: *const *const u8) -> AuxvIter {
        let mut p = argv;
        // Skip argv[0..argc].
        for _ in 0..argc {
            p = p.add(1);
        }
        // Skip the argv NULL terminator (defensively: if argv was
        // truncated for some reason, we still try to find a NULL).
        if !(*p).is_null() {
            // Some kernels are lax; walk forward looking for the NULL.
            while !(*p).is_null() {
                p = p.add(1);
            }
        }
        p = p.add(1); // step over the argv terminator NULL
        // Walk envp[] until its NULL terminator.
        while !(*p).is_null() {
            p = p.add(1);
        }
        p = p.add(1); // step over the envp terminator NULL
        AuxvIter { cursor: p as *const AuxvEntry }
    }

    /// Build an iterator from a raw pointer that already points at the
    /// first auxv entry.  Useful when the caller already saved a
    /// pointer (e.g. from a `_start` shim).
    ///
    /// # Safety
    /// `ptr` must point at a valid sequence of [`AuxvEntry`]s
    /// terminated by `AT_NULL`.
    pub unsafe fn from_raw(ptr: *const AuxvEntry) -> AuxvIter {
        AuxvIter { cursor: ptr }
    }
}

impl Iterator for AuxvIter {
    type Item = AuxvEntry;

    fn next(&mut self) -> Option<AuxvEntry> {
        // SAFETY: the constructors document the invariant that the
        // cursor reaches `AT_NULL` before running off any mapping.
        let e = unsafe { ptr::read(self.cursor) };
        if e.a_type == AT_NULL {
            return None;
        }
        // SAFETY: same invariant — advance one entry.
        self.cursor = unsafe { self.cursor.add(1) };
        Some(e)
    }
}

/// `getauxval(3)`-style lookup: scan the auxv for the first entry
/// whose `a_type == kind` and return its value, or `0` if absent.
///
/// Per the glibc `getauxval(3)` man page, a present-but-zero value and
/// an absent entry both return `0` in the legacy API.  Callers that
/// need to distinguish should use [`getauxval_opt`].
///
/// # Safety
/// See [`AuxvIter::from_argc_argv`].
pub unsafe fn getauxval(argc: usize, argv: *const *const u8, kind: u64) -> u64 {
    getauxval_opt(argc, argv, kind).unwrap_or(0)
}

/// `Option<u64>`-returning variant of [`getauxval`] that distinguishes
/// "entry absent" from "entry present with value 0".
///
/// # Safety
/// See [`AuxvIter::from_argc_argv`].
pub unsafe fn getauxval_opt(
    argc: usize,
    argv: *const *const u8,
    kind: u64,
) -> Option<u64> {
    for e in AuxvIter::from_argc_argv(argc, argv) {
        if e.a_type == kind {
            return Some(e.a_val);
        }
    }
    None
}

// ── vDSO symbol resolution ──────────────────────────────────────────

#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

/// Resolve `name` against the vDSO ELF mapped at `base` (typically the
/// value returned by `getauxval(AT_SYSINFO_EHDR)`).
///
/// Returns the runtime address of the named symbol, or `0` if the
/// vDSO is malformed or the symbol is absent.  Symbol-version filters
/// are NOT applied — callers that need versioning should use
/// `__vdso_clock_gettime` (LINUX_2.6) etc., which the AstryxOS vDSO
/// exports under exactly the bare name (no `@@LINUX_2.6` suffix).
///
/// # Safety
/// `base` must either be `0` (returns `0`) or point at a valid ELF64
/// shared-object image (the vDSO).  The function does NOT validate
/// every offset; it trusts the kernel-provided vDSO image to be
/// well-formed.  See `vdso(7)` and the ELF-64 gABI for the layout
/// it assumes.
pub unsafe fn vdso_lookup(base: u64, name: &[u8]) -> u64 {
    if base == 0 {
        return 0;
    }
    let eh = &*(base as *const Elf64Ehdr);
    // Magic: 0x7F 'E' 'L' 'F'.
    if eh.e_ident[0] != 0x7F
        || eh.e_ident[1] != b'E'
        || eh.e_ident[2] != b'L'
        || eh.e_ident[3] != b'F'
        || eh.e_ident[4] != ELFCLASS64
        || eh.e_ident[5] != ELFDATA2LSB
    {
        return 0;
    }
    // Walk phdrs to find PT_DYNAMIC.
    let phbase = base.wrapping_add(eh.e_phoff) as *const Elf64Phdr;
    let mut dyn_ptr: *const Elf64Dyn = ptr::null();
    for i in 0..eh.e_phnum as isize {
        let ph = &*phbase.offset(i);
        if ph.p_type == PT_DYNAMIC {
            // p_vaddr in a PIE/DSO is link-relative; rebase to load base.
            dyn_ptr = base.wrapping_add(ph.p_vaddr) as *const Elf64Dyn;
            break;
        }
    }
    if dyn_ptr.is_null() {
        return 0;
    }

    // Walk DT_* entries collecting DT_SYMTAB / DT_STRTAB / DT_STRSZ /
    // DT_SYMENT.  Per the ELF gABI, DT_STRTAB and DT_SYMTAB values in
    // a DSO are *runtime* addresses on most loaders, but a hand-rolled
    // vDSO linker can emit link-time offsets instead.  Accept both:
    // if d_val < base, treat as offset; otherwise as absolute.
    let mut strtab: *const u8 = ptr::null();
    let mut symtab: *const Elf64Sym = ptr::null();
    let mut strsz: u64 = 0;
    let mut syment: u64 = mem::size_of::<Elf64Sym>() as u64;
    let mut d = dyn_ptr;
    loop {
        let e = &*d;
        if e.d_tag == DT_NULL {
            break;
        }
        match e.d_tag {
            DT_STRTAB => {
                let v = if e.d_val < base { base + e.d_val } else { e.d_val };
                strtab = v as *const u8;
            }
            DT_SYMTAB => {
                let v = if e.d_val < base { base + e.d_val } else { e.d_val };
                symtab = v as *const Elf64Sym;
            }
            DT_STRSZ => strsz = e.d_val,
            DT_SYMENT => syment = e.d_val,
            _ => {}
        }
        d = d.add(1);
    }
    if strtab.is_null() || symtab.is_null() || strsz == 0 || syment == 0 {
        return 0;
    }

    // Walk .dynsym.  We don't parse DT_HASH; instead bound the scan by
    // .dynstr size — every symbol has st_name < strsz, so an entry
    // whose st_name is >= strsz signals we've walked off the end.
    // 64 is a generous cap for the AstryxOS vDSO (~6 exports today).
    for i in 0..64u64 {
        let sym = &*(symtab as *const u8).add((i * syment) as usize).cast::<Elf64Sym>();
        if sym.st_name == 0 {
            continue;
        }
        if sym.st_name as u64 >= strsz {
            break;
        }
        let s = strtab.add(sym.st_name as usize);
        if cstr_eq(s, name) {
            let v = if sym.st_value < base {
                base + sym.st_value
            } else {
                sym.st_value
            };
            return v;
        }
    }
    0
}

/// Compare a C-style NUL-terminated string at `s` against a Rust byte
/// slice `name` (without NUL).
///
/// # Safety
/// `s` must be NUL-terminated within a readable mapping.
unsafe fn cstr_eq(mut s: *const u8, name: &[u8]) -> bool {
    for &b in name {
        if *s != b {
            return false;
        }
        s = s.add(1);
    }
    *s == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    /// Build a fake stack-tail of the form `[argv... NULL envp... NULL auxv... AT_NULL]`
    /// and verify auxv parsing.
    fn build_fake_stack(
        argv: &[*const u8],
        envp: &[*const u8],
        auxv: &[AuxvEntry],
    ) -> alloc::vec::Vec<usize> {
        let mut out = alloc::vec::Vec::new();
        for &p in argv {
            out.push(p as usize);
        }
        out.push(0); // argv NULL terminator
        for &p in envp {
            out.push(p as usize);
        }
        out.push(0); // envp NULL terminator
        // auxv pairs:
        for e in auxv {
            out.push(e.a_type as usize);
            out.push(e.a_val as usize);
        }
        out.push(0); // AT_NULL
        out.push(0);
        out
    }

    #[test]
    fn getauxval_finds_entries() {
        let argv: &[*const u8] = &[b"prog\0".as_ptr()];
        let envp: &[*const u8] = &[b"PATH=/bin\0".as_ptr()];
        let auxv = [
            AuxvEntry { a_type: AT_PAGESZ, a_val: 4096 },
            AuxvEntry { a_type: AT_SYSINFO_EHDR, a_val: 0xdead_beef },
            AuxvEntry { a_type: AT_RANDOM, a_val: 0xcafe_babe },
        ];
        let stack = build_fake_stack(argv, envp, &auxv);
        let argc = argv.len();
        let argv_ptr = stack.as_ptr() as *const *const u8;

        unsafe {
            assert_eq!(getauxval(argc, argv_ptr, AT_PAGESZ), 4096);
            assert_eq!(getauxval(argc, argv_ptr, AT_SYSINFO_EHDR), 0xdead_beef);
            assert_eq!(getauxval(argc, argv_ptr, AT_RANDOM), 0xcafe_babe);
            assert_eq!(getauxval(argc, argv_ptr, AT_HWCAP), 0); // absent
            assert_eq!(getauxval_opt(argc, argv_ptr, AT_HWCAP), None);
            assert_eq!(
                getauxval_opt(argc, argv_ptr, AT_PAGESZ),
                Some(4096)
            );
        }
    }

    #[test]
    fn auxv_iter_terminates_on_at_null() {
        let argv: &[*const u8] = &[];
        let envp: &[*const u8] = &[];
        let auxv = [
            AuxvEntry { a_type: AT_PAGESZ, a_val: 4096 },
            AuxvEntry { a_type: AT_ENTRY, a_val: 0x401000 },
        ];
        let stack = build_fake_stack(argv, envp, &auxv);
        let argc = argv.len();
        let argv_ptr = stack.as_ptr() as *const *const u8;
        unsafe {
            let count = AuxvIter::from_argc_argv(argc, argv_ptr).count();
            assert_eq!(count, 2);
        }
    }

    #[test]
    fn auxv_entry_layout_matches_kernel() {
        // Two u64s per entry — same as the kernel's push order in
        // proc/elf.rs stack builder.
        assert_eq!(size_of::<AuxvEntry>(), 16);
    }

    #[test]
    fn vdso_lookup_returns_zero_for_zero_base() {
        unsafe {
            assert_eq!(vdso_lookup(0, b"__vdso_clock_gettime"), 0);
        }
    }

    #[test]
    fn cstr_eq_basic() {
        unsafe {
            assert!(cstr_eq(b"hello\0".as_ptr(), b"hello"));
            assert!(!cstr_eq(b"hello\0".as_ptr(), b"hell"));
            assert!(!cstr_eq(b"hell\0".as_ptr(), b"hello"));
            assert!(!cstr_eq(b"world\0".as_ptr(), b"hello"));
        }
    }
}
