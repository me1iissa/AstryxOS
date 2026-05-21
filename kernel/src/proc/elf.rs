//! ELF64 Binary Loader
//!
//! Parses and loads statically-linked ELF64 executables into a process
//! address space. This is the foundation for user-mode process execution.
//!
//! # Supported Features
//! - ELF64 format (x86_64)
//! - Statically-linked executables (ET_EXEC)
//! - PT_LOAD segments mapped into user address space
//! - User-mode entry point (Ring 3)
//!
//! # Address Space Layout
//! ```text
//! 0x0000_0000_0040_0000  Program text/data (loaded from ELF)
//! ...
//! 0x0000_7FFF_FFFF_0000  User stack (grows down, 64 KiB default)
//! 0xFFFF_8000_0000_0000+ Kernel space (not accessible from user mode)
//! ```

extern crate alloc;

use crate::mm::{pmm, vmm};
use crate::mm::vma::{VmArea, VmBacking, VmFlags, VmProt, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_PRIVATE, MAP_ANONYMOUS, MAP_STACK};
use alloc::vec::Vec;

/// Convert a physical page address to a kernel-accessible virtual pointer.
/// Uses the higher-half direct map (0xFFFF_8000_0000_0000) which works
/// regardless of which user CR3 is active (shared via PML4[256-511]).
#[inline(always)]
fn phys_to_virt(phys: u64) -> *mut u8 {
    (0xFFFF_8000_0000_0000u64 + phys) as *mut u8
}

/// Kernel-side cache for dynamic interpreter binaries.
///
/// Interpreters (ld-musl, ld-linux) are 300-840 KiB. On WSL2/KVM each ATA PIO
/// sector read requires a hypervisor exit (~100 µs), making reads take 60-300
/// seconds. Caching in kernel RAM makes all subsequent execs instant.
/// Supports up to 4 different interpreters (ld-musl, ld-linux, etc.).
static INTERP_CACHE: spin::Mutex<alloc::vec::Vec<(alloc::string::String, alloc::vec::Vec<u8>)>> =
    spin::Mutex::new(alloc::vec::Vec::new());

/// Return the interpreter binary, reading from disk only on cache miss.
fn read_interpreter_cached(path: &str) -> Result<alloc::vec::Vec<u8>, crate::vfs::VfsError> {
    {
        let cache = INTERP_CACHE.lock();
        for (ref p, ref data) in cache.iter() {
            if p == path {
                return Ok(data.clone());
            }
        }
    }
    // Cache miss — read from VFS (slow).
    crate::serial_println!("[ELF] INTERP cache miss for '{}' — reading from disk (slow)...", path);
    let data = crate::vfs::read_file(path)?;
    crate::serial_println!("[ELF] INTERP loaded {} bytes, caching", data.len());
    let mut cache = INTERP_CACHE.lock();
    if cache.len() >= 4 { cache.remove(0); } // LRU eviction
    cache.push((alloc::string::String::from(path), data.clone()));
    Ok(data)
}

/// ELF magic number: \x7fELF
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class: 64-bit
const ELFCLASS64: u8 = 2;
/// ELF data: little-endian
const ELFDATA2LSB: u8 = 1;
/// ELF type: executable
const ET_EXEC: u16 = 2;
/// ELF machine: x86_64
const EM_X86_64: u16 = 62;

/// Program header type: loadable segment
const PT_LOAD: u32 = 1;
/// Program header type: interpreter path (e.g. "/lib/ld-musl-x86_64.so.1")
const PT_INTERP: u32 = 3;
/// Program header type: dynamic linking information
const PT_DYNAMIC: u32 = 2;
/// Program header type: program header table location
const PT_PHDR: u32 = 6;
/// Program header type: thread-local storage template
const PT_TLS: u32 = 7;

/// Dynamic section tag: packed relative relocations array address
const DT_RELR: u64 = 36;
/// Dynamic section tag: packed relative relocations array size in bytes
const DT_RELRSZ: u64 = 35;
/// Dynamic section tag: size of one DT_RELR entry (always 8 on x86_64)
const DT_RELRENT: u64 = 37;
/// Dynamic section tag: GNU hash table (tolerate, do not reject when DT_HASH absent)
const DT_GNU_HASH: u64 = 0x6ffffef5;
/// Dynamic section tag: end of dynamic array
const DT_NULL: u64 = 0;
/// Dynamic section tag: address of the legacy single initialiser function
/// (ELF gABI §5.7 / System V AMD64 ABI §3.3.3 — `_init`).
const DT_INIT: u64 = 12;
/// Dynamic section tag: virtual address of the function-pointer array of
/// constructor entries that the dynamic linker invokes after relocations
/// (ELF gABI §5.7 / glibc `_dl_init`).
const DT_INIT_ARRAY: u64 = 25;
/// Dynamic section tag: total byte size of DT_INIT_ARRAY.
const DT_INIT_ARRAYSZ: u64 = 27;
/// Dynamic section tag: virtual address of the preinit function-pointer array
/// (executable image only — runs before any constructor in DT_INIT_ARRAY).
const DT_PREINIT_ARRAY: u64 = 32;
/// Dynamic section tag: total byte size of DT_PREINIT_ARRAY.
const DT_PREINIT_ARRAYSZ: u64 = 33;

/// ELF type: dynamically-linked shared object / PIE
const ET_DYN: u16 = 3;

/// Default (un-randomised) virtual address at which the dynamic interpreter
/// would be loaded.  Retained as the lower bound of the interpreter ASLR
/// window and as a compile-time anchor for references in tooling.
///
/// At runtime `interp_aslr_base()` returns a per-`exec()` randomised base
/// inside `[INTERP_ASLR_MIN, INTERP_ASLR_MAX)` so that the dynamic linker
/// — and every shared library it subsequently mmaps below itself — lands
/// at a different VA each boot.  See `interp_aslr_base()` for the layout
/// rationale (System V AMD64 ABI §3.3.3, vdso(7), mmap(2)).
const INTERP_BASE_DEFAULT: u64 = 0x7F00_0000_0000;

/// Lower bound of the interpreter ASLR window.  Set well above the default
/// `mmap` allocation region (`MMAP_BASE = 0x7F00_0000_0000`, growing
/// downward) so that randomised interpreter placements never collide with
/// addresses the anonymous-mmap allocator hands back to `ld-musl`.
const INTERP_ASLR_MIN: u64 = 0x7F40_0000_0000;

/// Upper bound (exclusive) of the interpreter ASLR window.  Set well below
/// `USER_STACK_TOP - USER_STACK_MAX` = `0x7FFF_FFF0_0000` so a fully-grown
/// 1 MiB user stack cannot collide with the interpreter image (which is
/// at most a few MiB for ld-musl / ld-linux).  Window size = 512 GiB.
const INTERP_ASLR_MAX: u64 = 0x7FC0_0000_0000;

/// Entropy bits for the interpreter ASLR window.  27 bits page-aligned
/// covers `2^27 * 4 KiB = 512 GiB`, exactly matching the window above.
/// Collision probability across two `exec()` calls is `1 / 2^27 ≈ 7.5e-9`,
/// comparable to the main-binary PIE-ASLR entropy (28 bits, see `ASLR_BITS`).
const INTERP_ASLR_BITS: u32 = 27;

/// Public surface for the `test_aslr_shared_lib` kernel test.  Forwards
/// to the private `interp_aslr_base()` so the test can assert that two
/// successive calls produce 4 KiB-aligned values inside the configured
/// window and (probabilistically) differ.  Not used outside `test_runner`.
#[inline]
pub fn test_only_interp_aslr_base() -> u64 {
    interp_aslr_base()
}

/// Compute a per-`exec()` randomised base for the dynamic interpreter.
///
/// Returns a 4 KiB-aligned address in `[INTERP_ASLR_MIN, INTERP_ASLR_MAX)`.
/// Each call returns a fresh random value, so two `exec("./prog")` calls in
/// the same boot — and the same binary across different boots — get
/// distinct interpreter VAs.  The dynamic linker's subsequent
/// `mmap(MAP_ANONYMOUS)` calls for shared libraries (DT_NEEDED entries
/// such as `libxul`, `libc.musl-x86_64.so.1`) are satisfied by
/// `VmSpace::find_free_range`, whose first VMA-overlap point depends on
/// the interpreter's placement — so randomising the interpreter
/// transitively randomises every shared-library VA in the process.
///
/// References:
/// - ELF gABI §5.4 (Program Loading)
/// - System V AMD64 ABI §3.3.3 (Address Space Layout)
/// - mmap(2) regarding kernel-chosen VAs when `addr == NULL`
#[inline]
fn interp_aslr_base() -> u64 {
    let offset = crate::security::rand::aslr_page_offset(INTERP_ASLR_BITS);
    let base = INTERP_ASLR_MIN.saturating_add(offset);
    // Clamp into the window.  The mask in `aslr_page_offset` already keeps
    // `offset < 2^INTERP_ASLR_BITS * 4 KiB`, but a defensive ceiling check
    // protects against future entropy-bit miscalibration.
    if base >= INTERP_ASLR_MAX {
        INTERP_ASLR_MIN
    } else {
        base
    }
}

/// Segment flags
const PF_X: u32 = 1; // Execute
const PF_W: u32 = 2; // Write
const PF_R: u32 = 4; // Read

/// Default user stack virtual address (top of lower half)
const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;
/// Eager (pre-mapped) stack pages — covers initial argc/argv/env setup.
const USER_STACK_PAGES: usize = 16;
const USER_STACK_SIZE: u64 = (USER_STACK_PAGES * pmm::PAGE_SIZE) as u64;
/// Maximum stack size (lazy VMA — demand-paged on growth): 1 MiB.
const USER_STACK_MAX: u64 = 1024 * 1024;
/// One guard page below the maximum stack region.
const USER_STACK_GUARD: u64 = pmm::PAGE_SIZE as u64;

/// ELF64 Header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// ELF64 Program Header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Auxiliary vector entry types (ELF standard / Linux ABI).
pub const AT_NULL: u64    = 0;   // End of auxvec
pub const AT_PHDR: u64    = 3;   // Program headers address in memory
pub const AT_PHENT: u64   = 4;   // Size of each program header entry
pub const AT_PHNUM: u64   = 5;   // Number of program headers
pub const AT_PAGESZ: u64  = 6;   // System page size
pub const AT_ENTRY: u64   = 9;   // Program entry point
pub const AT_UID: u64     = 11;  // Real user ID
pub const AT_EUID: u64    = 12;  // Effective user ID
pub const AT_GID: u64     = 13;  // Real group ID
pub const AT_EGID: u64    = 14;  // Effective group ID
pub const AT_BASE: u64    = 7;   // Base address of interpreter
pub const AT_HWCAP: u64   = 16;  // Hardware capability bitmask (CPU features)
pub const AT_CLKTCK: u64  = 17;  // Frequency of times() clock (100 Hz)
pub const AT_RANDOM: u64  = 25;  // Address of 16 random bytes
pub const AT_SYSINFO_EHDR: u64 = 33; // Base address of the vDSO ELF header (vdso(7))
// musl reads AT_PHDR/AT_PHNUM to find PT_TLS and validates p_filesz ≤ p_memsz.
// We don't need a custom AT_ for TLS — musl uses PT_TLS from the phdrs directly.

/// Result of loading an ELF binary.
pub struct ElfLoadResult {
    /// Entry point virtual address.
    pub entry_point: u64,
    /// User stack pointer (top of allocated stack).
    pub user_stack_ptr: u64,
    /// Physical pages allocated (for cleanup on process exit).
    pub allocated_pages: Vec<u64>,
    /// Lowest virtual address loaded.
    pub load_base: u64,
    /// Highest virtual address loaded.
    pub load_end: u64,
    /// VMAs created for the loaded segments and user stack.
    pub vmas: Vec<VmArea>,
    /// FS.base value to set for the initial thread (TCB virtual address).
    /// 0 if the binary has no PT_TLS segment.
    pub tls_base: u64,
    /// Auxiliary vector passed to the process (same entries placed on the stack).
    /// Format: Vec of (AT_type, value) pairs; the AT_NULL terminator is NOT included.
    /// Used by /proc/self/auxv to expose the process auxvec.
    pub auxv: Vec<(u64, u64)>,
    /// Runtime address of the vDSO ELF header in this process, or 0 if vDSO
    /// mapping failed.  Mirrors the AT_SYSINFO_EHDR auxv entry; exposed for
    /// tests and for /proc/self/maps.  See `kernel/src/proc/vdso.rs`.
    pub vdso_base: u64,
}

/// Errors from ELF loading.
#[derive(Debug)]
pub enum ElfError {
    /// Data too small to contain an ELF header.
    TooSmall,
    /// Invalid ELF magic number.
    BadMagic,
    /// Not a 64-bit ELF.
    Not64Bit,
    /// Not little-endian.
    NotLittleEndian,
    /// Not an executable (ET_EXEC).
    NotExecutable,
    /// Not x86_64.
    WrongArch,
    /// No loadable segments.
    NoLoadSegments,
    /// Out of physical memory.
    OutOfMemory,
    /// Segment address in kernel space.
    AddressInKernelSpace,
    /// PT_INTERP path could not be found on the VFS.
    InterpNotFound,
    /// PT_INTERP binary failed to load.
    InterpLoad,
    /// `e_phnum` exceeds the implementation cap (defence against DoS via
    /// huge program-header tables — System V ABI does not bound this, but
    /// real binaries stay well below 64 entries).
    TooManyPhdrs,
    /// PT_LOAD segment with `p_filesz > p_memsz` — malformed per System V
    /// ABI Chapter 5 ("Program Loading"), the file image must fit within
    /// the memory image.
    BadSegmentSize,
    /// PT_LOAD segment requested both PF_W and PF_X (write+execute).
    /// Rejected at load time to enforce W^X; runtime JIT pages must
    /// instead `mprotect()` the writable→executable transition explicitly.
    WritableExecutable,
}

impl From<ElfError> for astryx_shared::NtStatus {
    fn from(e: ElfError) -> Self {
        use astryx_shared::ntstatus::*;
        match e {
            ElfError::TooSmall => STATUS_INVALID_IMAGE_TOO_SMALL,
            ElfError::BadMagic => STATUS_INVALID_IMAGE_FORMAT,
            ElfError::Not64Bit => STATUS_INVALID_IMAGE_CLASS,
            ElfError::NotLittleEndian => STATUS_INVALID_IMAGE_ENDIAN,
            ElfError::NotExecutable => STATUS_INVALID_IMAGE_TYPE,
            ElfError::WrongArch => STATUS_INVALID_IMAGE_MACHINE,
            ElfError::NoLoadSegments => STATUS_INVALID_IMAGE_NO_LOAD,
            ElfError::OutOfMemory => STATUS_NO_MEMORY,
            ElfError::AddressInKernelSpace => STATUS_INVALID_IMAGE_KERNEL_ADDR,
            ElfError::InterpNotFound => STATUS_INVALID_IMAGE_FORMAT,
            ElfError::InterpLoad => STATUS_INVALID_IMAGE_FORMAT,
            ElfError::TooManyPhdrs => STATUS_INVALID_IMAGE_FORMAT,
            ElfError::BadSegmentSize => STATUS_INVALID_IMAGE_FORMAT,
            ElfError::WritableExecutable => STATUS_INVALID_IMAGE_FORMAT,
        }
    }
}

/// Maximum program-header entries accepted from an ELF image.
///
/// The ELF header field `e_phnum` is a u16, so a malicious image can
/// advertise up to 65535 entries.  Real binaries observed in the wild —
/// libxul, ld-linux, glibc, statically-linked Rust binaries — all stay
/// well below 64 entries; a static OS kernel image with embedded vDSO
/// uses ~16.  Capping at 256 leaves ~4× headroom for legitimate edge
/// cases (heavily-instrumented or multi-NOTE binaries) while preventing
/// a 65535-entry attacker payload from forcing 65535 `unsafe` pointer
/// reads in the load loops.  Per System V ABI Chapter 5 this field is
/// "the number of entries in the program header table" — the spec does
/// not mandate a cap, so the cap is policy.  CWE-119.
const MAX_PHDRS: usize = 256;

/// Deterministic load base for ET_EXEC (fixed-address) executables.
/// PIE / ET_DYN executables use a *randomised* base instead (see below).
const PIE_BASE: u64 = 0x0000_0000_0040_0000; // 4 MiB — deterministic fallback only

/// ASLR entropy for ET_DYN (PIE) main executables: 28 bits.
///
/// With 28 bits of page-granular entropy the random window covers
/// 2^28 * 4 KiB = 1 TiB.  Load addresses are uniformly distributed over
/// [PIE_BASE, PIE_BASE + 1 TiB) — well within the user lower-half.
/// Collision probability on a single fork is 1 / 2^28 ≈ 4e-9.
const ASLR_BITS: u32 = 28;

/// Compute a randomised load base for an ET_DYN binary.
///
/// Returns `PIE_BASE + random_4k_aligned_offset` where the offset has
/// `ASLR_BITS` bits of entropy.  The result is guaranteed to be in
/// user address space (below 0xFFFF_8000_0000_0000).
#[inline]
fn pie_aslr_base() -> u64 {
    let offset = crate::security::rand::aslr_page_offset(ASLR_BITS);
    // Saturating add: if somehow PIE_BASE + offset overflows user space,
    // fall back to PIE_BASE.  In practice 4 MiB + 1 TiB << 128 TiB limit.
    let base = PIE_BASE.saturating_add(offset);
    if base >= 0xFFFF_8000_0000_0000 { PIE_BASE } else { base }
}

/// ELF64 Dynamic section entry (Elf64_Dyn).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Dyn {
    d_tag: u64,
    d_val: u64, // union d_un: both d_val and d_ptr are u64
}

/// Apply one DT_RELR relocation slot at link-time virtual address `slot_lva`.
///
/// Translates `slot_lva` to a physical address via `mapped_pages`, then adds
/// `load_bias` to the u64 stored at that location.
///
/// `mapped_pages` — (page_vaddr_at_runtime, phys_addr) pairs built during PT_LOAD.
/// `load_bias`    — bias added to all virtual addresses for this binary.
/// `slot_lva`     — link-time virtual address of the relocation target.
///
/// Returns `false` and logs if the page containing `slot_lva` is not found.
#[inline]
fn relr_patch_slot(
    mapped_pages: &[(u64, u64)],
    load_bias: u64,
    slot_lva: u64,
) -> bool {
    // The slot's runtime VA is slot_lva + load_bias.
    let slot_rva = slot_lva.wrapping_add(load_bias);
    let page_rva = slot_rva & !0xFFF;
    let byte_off = (slot_rva & 0xFFF) as usize;

    for &(page_va, phys) in mapped_pages {
        if page_va == page_rva {
            // SAFETY: `phys` is a valid PMM page, mapped into the direct map.
            // `byte_off + 8 <= PAGE_SIZE` because slot_rva is within this page
            // and a u64 cannot straddle a 4 KiB boundary (slots are 8-byte aligned
            // by the DT_RELR spec — the ELF linker guarantees alignment).
            unsafe {
                let ptr = phys_to_virt(phys).add(byte_off) as *mut u64;
                let old = core::ptr::read(ptr);
                core::ptr::write(ptr, old.wrapping_add(load_bias));
            }
            return true;
        }
    }
    crate::serial_println!(
        "[ELF] DT_RELR: slot_lva={:#x} (rva={:#x}) not in mapped pages",
        slot_lva, slot_rva
    );
    false
}

/// Apply DT_RELR packed relative relocations.
///
/// Called after PT_LOAD segments are loaded. `relr_off` and `relr_sz` are the
/// file offset and byte length of the DT_RELR table within `data`.
/// `load_bias` is the ASLR offset applied to all VAs.
/// `mapped_pages` is the (runtime_page_va, phys) table built during PT_LOAD.
///
/// # DT_RELR encoding (64-bit, little-endian)
/// Each 8-byte word is either:
///   - An **address entry** (bit 0 == 0): sets the current group base to this
///     link-time VA.  This word is also a pointer slot — we relocate it too.
///   - A **bitmap entry** (bit 0 == 1): bits 1..63 describe up to 63 pointer
///     slots at base, base+8, …, base+496.  Bit N set (counting from 1) means
///     relocate the slot at `base + (N-1)*8`.  After processing the 63 slots,
///     advance base by 63*8 = 504 bytes.
///
/// Reference: <https://sourceware.org/glibc/wiki/RelativeRelocations>
fn apply_relr_relocations(
    data: &[u8],
    relr_off: usize,
    relr_sz: usize,
    load_bias: u64,
    mapped_pages: &[(u64, u64)],
) {
    if load_bias == 0 || relr_sz == 0 {
        // No bias → all stored addresses are already correct runtime values.
        return;
    }

    let n_words = relr_sz / 8;
    let mut base_lva: u64 = 0; // current link-time VA of the group base

    for i in 0..n_words {
        let off = relr_off + i * 8;
        if off + 8 > data.len() {
            break;
        }
        let word = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());

        if word & 1 == 0 {
            // Address entry: this word itself is a pointer slot AND sets base_lva.
            // Apply the relocation to this slot first.
            base_lva = word; // link-time VA stored in the RELR entry = slot address
            relr_patch_slot(mapped_pages, load_bias, base_lva);
            // base_lva now points just past this address entry; the next bitmap
            // (if any) starts from the slot AFTER this one.
            base_lva = base_lva.wrapping_add(8);
        } else {
            // Bitmap entry: strip marker bit, then scan bits 0..62.
            // Bit 0 after stripping → slot at base_lva + 0*8 = base_lva
            // Bit 1 after stripping → slot at base_lva + 1*8
            // ...
            // Bit 62 after stripping → slot at base_lva + 62*8
            let mut bitmap = word >> 1;
            let mut slot_off: u64 = 0;
            while bitmap != 0 {
                if bitmap & 1 != 0 {
                    relr_patch_slot(mapped_pages, load_bias, base_lva.wrapping_add(slot_off));
                }
                bitmap >>= 1;
                slot_off = slot_off.wrapping_add(8);
            }
            // Advance base by 63 slots (the 63 bits that could have been set).
            base_lva = base_lva.wrapping_add(63 * 8);
        }
    }
}

/// Parse the PT_DYNAMIC section of a loaded ELF and return
/// `(relr_file_offset, relr_sz, has_gnu_hash)`.
///
/// `data`     — raw ELF binary bytes.
/// `phdrs`    — (p_type, p_offset, p_vaddr, p_filesz) tuples extracted from program headers.
/// `load_bias`— PIE ASLR bias (0 for ET_EXEC).
///
/// The DT_RELR/DT_RELRSZ entries store *virtual addresses* (not file offsets).
/// We convert VA → file offset by: `file_off = va - bias - (segment_vaddr - segment_foffset)`.
/// For a minimal single-segment ET_DYN binary the segment's p_vaddr == 0 so
/// `file_off = va - bias`.  For multi-segment binaries we search the PT_LOAD
/// that covers the VA.
fn parse_dynamic_for_relr(
    data: &[u8],
    header: &Elf64Header,
    load_bias: u64,
) -> (usize, usize, bool) {
    let ph_off  = header.e_phoff as usize;
    let ph_sz   = header.e_phentsize as usize;
    let ph_cnt  = header.e_phnum as usize;

    // Collect PT_LOAD segments so we can VA→file-offset translate.
    let mut loads: alloc::vec::Vec<(u64, u64, u64)> = alloc::vec::Vec::new(); // (p_vaddr, p_offset, p_filesz)
    let mut dyn_off: usize = 0;
    let mut dyn_sz: usize  = 0;

    for i in 0..ph_cnt {
        let base = ph_off + i * ph_sz;
        if base + ph_sz > data.len() { continue; }
        let phdr = unsafe { &*(data.as_ptr().add(base) as *const Elf64Phdr) };
        if phdr.p_type == PT_LOAD {
            loads.push((phdr.p_vaddr, phdr.p_offset, phdr.p_filesz));
        }
        if phdr.p_type == PT_DYNAMIC {
            dyn_off = phdr.p_offset as usize;
            dyn_sz  = phdr.p_filesz as usize;
        }
    }

    if dyn_sz == 0 || dyn_off + dyn_sz > data.len() {
        return (0, 0, false);
    }

    // VA → file offset translation helper.
    // For a PIE binary loaded at link-time base 0 (typical), all VAs from the
    // dynamic section are link-time VAs, so file_off = va (since p_vaddr == 0
    // and p_offset == 0 for the first load segment in a minimal PIE).
    let va_to_file_off = |va: u64| -> Option<usize> {
        // Try each PT_LOAD segment.
        for &(seg_va, seg_off, seg_filesz) in &loads {
            if va >= seg_va && va < seg_va + seg_filesz {
                return Some((seg_off + (va - seg_va)) as usize);
            }
        }
        None
    };

    let n_entries = dyn_sz / 16; // each Elf64_Dyn is 16 bytes
    let mut relr_va:  u64 = 0;
    let mut relr_sz:  u64 = 0;
    let mut has_gnu_hash = false;

    for i in 0..n_entries {
        let base = dyn_off + i * 16;
        if base + 16 > data.len() { break; }
        let dyn_entry = unsafe { &*(data.as_ptr().add(base) as *const Elf64Dyn) };
        match dyn_entry.d_tag {
            DT_NULL    => break,
            DT_RELR    => { relr_va  = dyn_entry.d_val; }
            DT_RELRSZ  => { relr_sz  = dyn_entry.d_val; }
            DT_GNU_HASH => { has_gnu_hash = true; }
            _ => {}
        }
    }

    let relr_file_off = if relr_va != 0 && relr_sz != 0 {
        // DT_RELR stores a link-time VA (not adjusted by bias).
        // Subtract bias first to get the link-time VA, then convert to file offset.
        let lva = relr_va.wrapping_sub(load_bias);
        va_to_file_off(lva).unwrap_or(0)
    } else {
        0
    };

    (relr_file_off, relr_sz as usize, has_gnu_hash)
}

/// ── [ELF/INIT-ARRAY] diagnostic helper (feature-gated, byte-identical off) ──
///
/// Per ELF gABI §5.7 and System V AMD64 ABI §3.3.3, the dynamic linker invokes
/// DT_PREINIT_ARRAY → DT_INIT → DT_INIT_ARRAY after relocations.  We emit one
/// `[ELF/INIT-ARRAY]` line per kernel-side ELF load with those addresses plus
/// the first four DT_INIT_ARRAY fn_ptr CONTENTS (read through `mapped_pages`),
/// each fn_ptr's backing physical frame and W215 `pte_share_count` (PR #270).
/// NULL / non-text fn_ptrs → constructor table never relocated; plausible
/// text-range values → fault is post-init.  Diagnostic only.
#[cfg(feature = "elf-init-array-diag")]
const ELF_INIT_ARRAY_DIAG_MAX: u32 = 8;

#[cfg(feature = "elf-init-array-diag")]
static ELF_INIT_ARRAY_DIAG_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Read the u64 at runtime VA `va` via `mapped_pages` (page_va → phys lookup
/// + direct-map deref).  DT_INIT_ARRAY entries are 8-byte aligned per System
/// V AMD64 ABI §3.4 so cross-page reads are guarded only defensively.
#[cfg(feature = "elf-init-array-diag")]
fn read_u64_from_mapped(mapped_pages: &[(u64, u64)], va: u64) -> Option<u64> {
    let page_va = va & !0xFFF;
    let off = (va & 0xFFF) as usize;
    if off + 8 > 0x1000 { return None; }
    for &(pv, phys) in mapped_pages {
        if pv == page_va {
            // SAFETY: `phys` is a PMM-backed page mapped into the direct map;
            // `off + 8 <= PAGE_SIZE` by the boundary check above.
            let v = unsafe {
                core::ptr::read(phys_to_virt(phys).add(off) as *const u64)
            };
            return Some(v);
        }
    }
    None
}

/// Emit `[ELF/INIT-ARRAY] binary=<tag> ...` for a freshly-loaded ELF.  Bounded
/// to `ELF_INIT_ARRAY_DIAG_MAX` images per boot (then a single OVERFLOW line).
#[cfg(feature = "elf-init-array-diag")]
fn emit_init_array_diag(
    data: &[u8],
    header: &Elf64Header,
    load_bias: u64,
    mapped_pages: &[(u64, u64)],
    tag: &str,
) {
    use core::sync::atomic::Ordering;
    let prev = ELF_INIT_ARRAY_DIAG_COUNT.fetch_add(1, Ordering::Relaxed);
    if prev >= ELF_INIT_ARRAY_DIAG_MAX {
        if prev == ELF_INIT_ARRAY_DIAG_MAX {
            crate::serial_println!("[ELF/INIT-ARRAY] OVERFLOW cap={}", ELF_INIT_ARRAY_DIAG_MAX);
        }
        return;
    }

    let ph_off  = header.e_phoff as usize;
    let ph_sz   = header.e_phentsize as usize;
    let ph_cnt  = header.e_phnum as usize;
    let mut dyn_off: usize = 0;
    let mut dyn_sz:  usize = 0;
    for i in 0..ph_cnt {
        let base = ph_off + i * ph_sz;
        if base + ph_sz > data.len() { continue; }
        let phdr = unsafe { &*(data.as_ptr().add(base) as *const Elf64Phdr) };
        if phdr.p_type == PT_DYNAMIC {
            dyn_off = phdr.p_offset as usize;
            dyn_sz  = phdr.p_filesz as usize;
            break;
        }
    }
    if dyn_sz == 0 || dyn_off + dyn_sz > data.len() {
        crate::serial_println!(
            "[ELF/INIT-ARRAY] binary={} no_pt_dynamic bias={:#x}", tag, load_bias
        );
        return;
    }

    // Walk DT_ entries.  Stored values for DT_INIT / DT_INIT_ARRAY /
    // DT_PREINIT_ARRAY are link-time VAs; runtime VA = link-time VA + bias.
    let n = dyn_sz / 16;
    let mut dt_init_lva:       u64 = 0;
    let mut init_array_lva:    u64 = 0;
    let mut init_array_sz:     u64 = 0;
    let mut preinit_lva:       u64 = 0;
    let mut preinit_sz:        u64 = 0;
    for i in 0..n {
        let base = dyn_off + i * 16;
        if base + 16 > data.len() { break; }
        let e = unsafe { &*(data.as_ptr().add(base) as *const Elf64Dyn) };
        match e.d_tag {
            DT_NULL            => break,
            DT_INIT            => dt_init_lva       = e.d_val,
            DT_INIT_ARRAY      => init_array_lva    = e.d_val,
            DT_INIT_ARRAYSZ    => init_array_sz     = e.d_val,
            DT_PREINIT_ARRAY   => preinit_lva       = e.d_val,
            DT_PREINIT_ARRAYSZ => preinit_sz        = e.d_val,
            _ => {}
        }
    }

    let init_array_va    = if init_array_lva != 0 { init_array_lva.wrapping_add(load_bias) } else { 0 };
    let preinit_array_va = if preinit_lva    != 0 { preinit_lva.wrapping_add(load_bias) }    else { 0 };
    let dt_init_va       = if dt_init_lva    != 0 { dt_init_lva.wrapping_add(load_bias) }    else { 0 };

    // Read up to four fn_ptrs from DT_INIT_ARRAY, resolve each VA's backing
    // physical frame, sample the W215 pte_share_count invariant from PR #270.
    let mut fns: [u64; 4] = [0; 4];
    let mut fn_phys: [u64; 4] = [0; 4];
    let mut fn_share: [u16; 4] = [0; 4];
    let mut fn_count: usize = 0;
    if init_array_va != 0 && init_array_sz >= 8 {
        let max = core::cmp::min(4, (init_array_sz / 8) as usize);
        for j in 0..max {
            let slot_va = init_array_va.wrapping_add((j as u64) * 8);
            match read_u64_from_mapped(mapped_pages, slot_va) {
                Some(v) => {
                    fns[j] = v;
                    if v != 0 {
                        let page_va = v & !0xFFF;
                        for &(pv, phys) in mapped_pages {
                            if pv == page_va {
                                fn_phys[j]  = phys;
                                fn_share[j] = crate::mm::refcount::pte_share_count(phys);
                                break;
                            }
                        }
                    }
                    fn_count = j + 1;
                }
                None => break,
            }
        }
    }

    // Emit on one serial line.  Use a single println! to avoid interleaving
    // across CPUs (the SMP-safe `serial_println!` already serialises one call).
    crate::serial_println!(
        "[ELF/INIT-ARRAY] binary={} bias={:#x} init_array_va={:#x} sz={} \
         fn_ptr[0]={:#x} phys[0]={:#x} sc[0]={} \
         fn_ptr[1]={:#x} phys[1]={:#x} sc[1]={} \
         fn_ptr[2]={:#x} phys[2]={:#x} sc[2]={} \
         fn_ptr[3]={:#x} phys[3]={:#x} sc[3]={} \
         n_read={} preinit_array_va={:#x} preinit_sz={} dt_init_va={:#x}",
        tag, load_bias, init_array_va, init_array_sz,
        fns[0], fn_phys[0], fn_share[0],
        fns[1], fn_phys[1], fn_share[1],
        fns[2], fn_phys[2], fn_share[2],
        fns[3], fn_phys[3], fn_share[3],
        fn_count, preinit_array_va, preinit_sz, dt_init_va,
    );
}

/// Build-time no-op when feature is disabled — keeps default builds byte-
/// identical to master.
#[cfg(not(feature = "elf-init-array-diag"))]
#[inline(always)]
fn emit_init_array_diag(
    _data: &[u8], _header: &Elf64Header, _load_bias: u64,
    _mapped_pages: &[(u64, u64)], _tag: &str,
) {}

/// Validate and parse an ELF64 header.
///
/// Accepts both ET_EXEC (non-PIE) and ET_DYN (PIE) executables.
pub fn validate_elf(data: &[u8]) -> Result<&Elf64Header, ElfError> {
    if data.len() < core::mem::size_of::<Elf64Header>() {
        return Err(ElfError::TooSmall);
    }

    let header = unsafe { &*(data.as_ptr() as *const Elf64Header) };

    if header.e_ident[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    if header.e_ident[4] != ELFCLASS64 {
        return Err(ElfError::Not64Bit);
    }
    if header.e_ident[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    if header.e_type != ET_EXEC && header.e_type != ET_DYN {
        return Err(ElfError::NotExecutable);
    }
    if header.e_machine != EM_X86_64 {
        return Err(ElfError::WrongArch);
    }

    Ok(header)
}

/// Load an ELF64 executable into a specific address space.
///
/// Maps all PT_LOAD segments and allocates a user stack.
/// Handles PT_INTERP: if present, loads the interpreter (dynamic linker)
/// at a per-`exec()` randomised base inside the interpreter ASLR window
/// (see `interp_aslr_base()`) and sets it as the actual entry point,
/// passing the main executable's entry via AT_ENTRY in the auxiliary
/// vector.
///
/// # Arguments
/// * `data` — Complete ELF binary contents.
/// * `cr3` — Physical address of the PML4 to map into.
///
/// # Safety
/// `cr3` must point to a valid PML4 page table with kernel-half mapped.
pub fn load_elf(data: &[u8], cr3: u64) -> Result<ElfLoadResult, ElfError> {
    load_elf_with_args(data, cr3, &["astryx"], &["HOME=/", "PATH=/bin:/disk/bin"])
}

/// Like `load_elf` but lets the caller specify `argv` and `envp` that will be
/// laid out on the initial user stack for the new process.
pub fn load_elf_with_args(data: &[u8], cr3: u64, argv: &[&str], envp: &[&str]) -> Result<ElfLoadResult, ElfError> {
    let header = validate_elf(data)?;
    let mut allocated_pages: Vec<u64> = Vec::new();
    // Track pages mapped by THIS load_elf call, for overlap detection.
    let mut mapped_pages: Vec<(u64, u64)> = Vec::new();
    let mut vmas: Vec<VmArea> = Vec::new();
    let mut load_base = u64::MAX;
    let mut load_end = 0u64;
    let mut has_load = false;

    // ── First pass: find PT_INTERP and PT_PHDR ──────────────────────
    let ph_offset = header.e_phoff as usize;
    let ph_size = header.e_phentsize as usize;
    let ph_count = header.e_phnum as usize;

    // Cap `e_phnum` (CWE-119).  Without this cap a 65535-entry attacker
    // image forces 65535 unsafe pointer reads through the load loops
    // below — see MAX_PHDRS commentary for the rationale on the cap.
    if ph_count > MAX_PHDRS {
        crate::serial_println!(
            "[ELF] reject e_phnum={} (exceeds cap of {}) — CWE-119",
            ph_count, MAX_PHDRS,
        );
        return Err(ElfError::TooManyPhdrs);
    }

    let mut interp_path: Option<alloc::string::String> = None;
    let mut phdr_vaddr: u64 = 0; // PT_PHDR virtual address (for AT_PHDR)

    // PT_TLS: filesz bytes of initialised template + (memsz-filesz) bytes of zeros.
    struct TlsInfo { offset: usize, filesz: usize, memsz: usize, align: usize }
    let mut tls_info: Option<TlsInfo> = None;

    for i in 0..ph_count {
        let offset = ph_offset + i * ph_size;
        if offset + ph_size > data.len() { continue; }
        let phdr = unsafe { &*(data.as_ptr().add(offset) as *const Elf64Phdr) };

        if phdr.p_type == PT_PHDR {
            phdr_vaddr = phdr.p_vaddr;
        }
        if phdr.p_type == PT_INTERP {
            let path_start = phdr.p_offset as usize;
            let path_end = path_start + phdr.p_filesz as usize;
            if path_end <= data.len() {
                let raw = &data[path_start..path_end];
                // Strip null terminator
                let raw = raw.split(|&b| b == 0).next().unwrap_or(raw);
                interp_path = Some(alloc::string::String::from_utf8_lossy(raw).into_owned());
            }
        }
        if phdr.p_type == PT_TLS {
            tls_info = Some(TlsInfo {
                offset:  phdr.p_offset as usize,
                filesz:  phdr.p_filesz as usize,
                memsz:   phdr.p_memsz  as usize,
                align:   phdr.p_align  as usize,
            });
        }
    }

    // ── Compute PIE bias for ET_DYN (PIE) main executables ──────────
    // For ET_EXEC, bias = 0 (segments load at their literal link-time vaddr).
    // For ET_DYN, we choose a *random* base (ASLR) so exploit code cannot
    // predict absolute addresses.  All segments in the image receive the
    // same bias so intra-image relative references still resolve correctly.
    let pie_bias: u64 = if header.e_type == ET_DYN {
        // Find minimum PT_LOAD vaddr so we can compute the bias.
        let mut min_vaddr = u64::MAX;
        for i in 0..ph_count {
            let offset = ph_offset + i * ph_size;
            if offset + ph_size > data.len() { continue; }
            let phdr = unsafe { &*(data.as_ptr().add(offset) as *const Elf64Phdr) };
            if phdr.p_type == PT_LOAD && phdr.p_vaddr < min_vaddr {
                min_vaddr = phdr.p_vaddr;
            }
        }
        if min_vaddr == u64::MAX { 0 } else {
            // ASLR: randomise the load base for each exec() of a PIE binary.
            pie_aslr_base().wrapping_sub(min_vaddr & !0xFFF)
        }
    } else {
        // ET_EXEC: fixed load address — never randomise.
        0
    };

    // ── Second pass: load PT_LOAD segments ──────────────────────────
    for i in 0..ph_count {
        let offset = ph_offset + i * ph_size;
        if offset + ph_size > data.len() {
            continue;
        }

        let phdr = unsafe { &*(data.as_ptr().add(offset) as *const Elf64Phdr) };

        if phdr.p_type != PT_LOAD {
            continue;
        }

        has_load = true;

        let vaddr = phdr.p_vaddr.wrapping_add(pie_bias); // bias=0 for ET_EXEC
        let memsz = phdr.p_memsz;
        let filesz = phdr.p_filesz;
        let file_offset = phdr.p_offset as usize;

        // Security: reject segments in kernel space.
        if vaddr >= 0xFFFF_8000_0000_0000 {
            return Err(ElfError::AddressInKernelSpace);
        }

        // Per System V ABI Chapter 5 ("Program Loading"): "The bytes from
        // the file are mapped to the beginning of the memory segment; the
        // remaining `p_memsz` minus `p_filesz` bytes are zero-filled."  An
        // image with `p_filesz > p_memsz` is malformed — the file image is
        // larger than the in-memory image it is supposed to fit inside.
        // Reject it rather than rely on downstream `min()` clamps to mask
        // the issue (defence in depth — CWE-119).
        if filesz > memsz {
            crate::serial_println!(
                "[ELF] reject PT_LOAD p_filesz={:#x} > p_memsz={:#x} (System V ABI ch. 5 violation)",
                filesz, memsz,
            );
            return Err(ElfError::BadSegmentSize);
        }

        // Enforce W^X at load time (CWE-269 — improper privilege
        // management).  A PT_LOAD segment with both PF_W and PF_X set
        // would land in memory as a writable+executable mapping — a
        // ready-made code-injection target for any out-of-bounds write
        // bug elsewhere in the process.  Legitimate JITs must request
        // the writable→executable transition explicitly via mprotect(2),
        // which gives the kernel a chance to enforce policy at the
        // transition point.  ELF segments do not need W+X to function.
        if phdr.p_flags & PF_W != 0 && phdr.p_flags & PF_X != 0 {
            crate::serial_println!(
                "[ELF] reject PT_LOAD with both PF_W and PF_X set (W^X policy — CWE-269)",
            );
            return Err(ElfError::WritableExecutable);
        }

        // Track load range.
        if vaddr < load_base { load_base = vaddr; }
        if vaddr + memsz > load_end { load_end = vaddr + memsz; }

        // Determine page flags.
        let mut flags = vmm::PAGE_PRESENT | vmm::PAGE_USER;
        if phdr.p_flags & PF_W != 0 {
            flags |= vmm::PAGE_WRITABLE;
        }
        if phdr.p_flags & PF_X == 0 {
            flags |= vmm::PAGE_NO_EXECUTE;
        }

        // Map pages for this segment.
        let page_start = vaddr & !0xFFF;
        let page_end = (vaddr + memsz + 0xFFF) & !0xFFF;

        // Build a VMA for this segment.
        let mut seg_prot: VmProt = PROT_READ;
        if phdr.p_flags & PF_W != 0 { seg_prot |= PROT_WRITE; }
        if phdr.p_flags & PF_X != 0 { seg_prot |= PROT_EXEC; }
        vmas.push(VmArea {
            base: page_start,
            length: page_end - page_start,
            prot: seg_prot,
            flags: MAP_PRIVATE,
            backing: VmBacking::Anonymous,
            name: "[elf]",
        });

        for page_vaddr in (page_start..page_end).step_by(pmm::PAGE_SIZE) {
            // Check if this page was already mapped by a PREVIOUS segment
            // within this load_elf call (overlapping PT_LOAD segments).
            let (phys, already_mapped) = if let Some(&(_, existing_phys)) = mapped_pages.iter().find(|&&(va, _)| va == page_vaddr) {
                (existing_phys, true)
            } else {
                let p = pmm::alloc_page().ok_or(ElfError::OutOfMemory)?;
                allocated_pages.push(p);
                // Zero the new page.
                unsafe { core::ptr::write_bytes(phys_to_virt(p), 0, pmm::PAGE_SIZE); }
                (p, false)
            };

            // Copy file data into this page if applicable.
            let page_offset_in_segment = page_vaddr.saturating_sub(vaddr);
            if page_offset_in_segment < filesz {
                let copy_start = if page_vaddr < vaddr {
                    (vaddr - page_vaddr) as usize
                } else {
                    0
                };
                let data_offset = if page_vaddr >= vaddr {
                    file_offset + (page_vaddr - vaddr) as usize
                } else {
                    file_offset
                };
                let remaining_file = if data_offset < file_offset + filesz as usize {
                    (file_offset + filesz as usize) - data_offset
                } else {
                    0
                };
                let copy_len = remaining_file.min(pmm::PAGE_SIZE - copy_start);

                if copy_len > 0 && data_offset < data.len() {
                    let actual_len = copy_len.min(data.len() - data_offset);
                    unsafe {
                        let dst = phys_to_virt(phys).add(copy_start);
                        let src = data.as_ptr().add(data_offset);
                        core::ptr::copy_nonoverlapping(src, dst, actual_len);
                    }
                }
            }

            if !already_mapped {
                // Map the page into the target page table.
                if !vmm::map_page_in(cr3, page_vaddr, phys, flags) {
                    // Cleanup: every prior page in `allocated_pages` had
                    // `page_ref_set(phys, 1)` applied after its successful
                    // map_page_in.  The current iteration's page has NOT
                    // had page_ref_set called yet (refcount==0 already), so
                    // unconditionally clearing the refcount before free is
                    // a no-op for it and the correct decrement for all
                    // already-mapped predecessors.  Without this, the W215
                    // pte_share_count free-time invariant would quarantine
                    // every successfully-mapped frame on this OOM path,
                    // leaking them for the rest of the boot.
                    for &page in &allocated_pages {
                        crate::mm::refcount::page_ref_set(page, 0);
                        pmm::free_page(page);
                    }
                    return Err(ElfError::OutOfMemory);
                }
                // Set refcount for the newly allocated page.
                crate::mm::refcount::page_ref_set(phys, 1);
                mapped_pages.push((page_vaddr, phys));
            }
        }
    }

    if !has_load {
        return Err(ElfError::NoLoadSegments);
    }

    // ── [ELF/INIT-ARRAY] diagnostic (D1 framing-falsifier) ──────────────
    // ELF gABI §5.7: dynamic linker invokes DT_PREINIT_ARRAY → DT_INIT →
    // DT_INIT_ARRAY after relocations.  Emit the constructor-table VAs +
    // first four fn_ptrs (resolved through `mapped_pages` while the image
    // is hot) so post-mortem diagnostics can distinguish "constructor
    // table never relocated" from "constructors ran, fault is elsewhere".
    // Feature-gated; default builds remain byte-identical.
    let _diag_tag = if interp_path.is_some() { "main" } else { "main-static" };
    emit_init_array_diag(data, header, pie_bias, &mapped_pages, _diag_tag);

    // ── Apply DT_RELR packed relative relocations (PIE + ASLR) ─────────
    //
    // For ET_DYN with ASLR, all stored absolute pointers in .got/.data need
    // the load bias added.  The DT_RELR table encodes which slots to patch.
    //
    // CRITICAL ABI INVARIANT — only patch a STATIC PIE binary (no PT_INTERP):
    //
    //   Real Linux NEVER applies DT_RELR (or any relocations) to a
    //   dynamically-linked ET_DYN binary.  The dynamic linker
    //   (ld-linux-x86-64.so.2 / ld-musl-x86_64.so.1) applies DT_RELR itself
    //   as part of `_dl_relocate_object` / `do_relr_relocs`, after running
    //   its own bootstrap.  See:
    //     * musl ldso/dynlink.c — `do_relr_relocs` (called from `reloc_all`)
    //     * glibc elf/dl-reloc.c — `elf_dynamic_do_Rel*` path
    //   ELF gABI says DT_REL* tables describe relocations to be performed
    //   by the dynamic linker, not the kernel.
    //
    //   If the kernel also applies DT_RELR, each covered slot ends up with
    //   `bias + bias + link_time_value` instead of `bias + link_time_value`
    //   — the value's high bits land in the non-canonical / unmapped range
    //   and the first indirect call through any such slot (init_array
    //   entry, vtable, function-pointer table in .data.rel.ro) faults.
    //
    //   Static PIE binaries (ET_DYN with NO PT_INTERP) embed their own
    //   `_dlstart` in `crt1.o` that self-applies relocations.  For those,
    //   the kernel is the only relocator — we still need to apply DT_RELR.
    //
    //   ET_EXEC (pie_bias==0) and static PIE without DT_RELR are no-ops via
    //   the guard inside `apply_relr_relocations`.
    let is_static_pie = interp_path.is_none();
    if pie_bias != 0 && is_static_pie {
        let (relr_off, relr_sz, _has_gnu_hash) =
            parse_dynamic_for_relr(data, header, 0 /* link-time bias = 0 for ET_DYN */);
        if relr_sz > 0 {
            crate::serial_println!(
                "[ELF] DT_RELR: applying {} bytes at file offset {:#x} with bias={:#x} (static PIE)",
                relr_sz, relr_off, pie_bias
            );
            apply_relr_relocations(data, relr_off, relr_sz, pie_bias, &mapped_pages);
        }
    } else if pie_bias != 0 && interp_path.is_some() {
        // Dynamic PIE: log that we are deliberately skipping kernel-side
        // DT_RELR so post-mortem diagnostics can distinguish "skipped" from
        // "no DT_RELR present".
        let (_relr_off, relr_sz, _) =
            parse_dynamic_for_relr(data, header, 0);
        if relr_sz > 0 {
            crate::serial_println!(
                "[ELF] DT_RELR: deferring {} bytes to dynamic linker (PT_INTERP present)",
                relr_sz
            );
        }
    }

    // Allocate user stack (grows down from USER_STACK_TOP).
    // The full VMA covers USER_STACK_MAX (1 MiB) for lazy growth; only the
    // top USER_STACK_PAGES are pre-mapped below.  A PROT_NONE guard page sits
    // immediately below the VMA to catch runaway stack overflows.
    let stack_bottom_eager = USER_STACK_TOP - USER_STACK_SIZE;
    let stack_bottom_max   = USER_STACK_TOP - USER_STACK_MAX;
    let guard_page_base    = stack_bottom_max - USER_STACK_GUARD;
    let stack_bottom = stack_bottom_eager; // kept for page-mapping loop below

    // Guard page — PROT_NONE, never demand-paged.
    vmas.push(VmArea {
        base: guard_page_base,
        length: USER_STACK_GUARD,
        prot: crate::mm::vma::PROT_NONE,
        flags: MAP_PRIVATE | MAP_ANONYMOUS,
        backing: VmBacking::Anonymous,
        name: "[stack guard]",
    });
    // Full lazy-growth region below the eager zone.
    if stack_bottom_max < stack_bottom_eager {
        vmas.push(VmArea {
            base:   stack_bottom_max,
            length: USER_STACK_MAX - USER_STACK_SIZE,
            prot:   PROT_READ | PROT_WRITE,
            flags:  MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
            backing: VmBacking::Anonymous,
            name: "[stack grow]",
        });
    }
    // Eager top region (pre-mapped).
    vmas.push(VmArea {
        base: stack_bottom,
        length: USER_STACK_SIZE,
        prot: PROT_READ | PROT_WRITE,
        flags: MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
        backing: VmBacking::Anonymous,
        name: "[stack]",
    });

    // Track (vaddr, phys) for each stack page so setup_user_stack can write
    // the argc/argv/envp/auxvec layout directly to physical memory.
    let mut stack_pages: Vec<(u64, u64)> = Vec::new();

    for page_vaddr in (stack_bottom..USER_STACK_TOP).step_by(pmm::PAGE_SIZE) {
        let phys = pmm::alloc_page().ok_or(ElfError::OutOfMemory)?;
        allocated_pages.push(phys);

        unsafe {
            core::ptr::write_bytes(phys_to_virt(phys), 0, pmm::PAGE_SIZE);
        }

        let flags = vmm::PAGE_PRESENT | vmm::PAGE_WRITABLE | vmm::PAGE_USER | vmm::PAGE_NO_EXECUTE;
        if !vmm::map_page_in(cr3, page_vaddr, phys, flags) {
            // Cleanup mirrors the PT_LOAD path above: clear refcount on
            // every page before free so the W215 pte_share_count free-time
            // invariant does not quarantine the successfully-mapped
            // predecessors.  The current page is still at refcount==0
            // (page_ref_set has not yet been called) so the clear is a
            // no-op for it.
            for &page in &allocated_pages {
                crate::mm::refcount::page_ref_set(page, 0);
                pmm::free_page(page);
            }
            return Err(ElfError::OutOfMemory);
        }

        // Set refcount for the newly allocated page.
        crate::mm::refcount::page_ref_set(phys, 1);
        stack_pages.push((page_vaddr, phys));
    }

    // ── Load interpreter if PT_INTERP was found ─────────────────────
    // For PIE binaries, apply the bias to get the actual loaded entry point.
    let mut actual_entry = header.e_entry.wrapping_add(pie_bias);
    let mut interp_base_for_auxv: u64 = 0;

    if let Some(ref path) = interp_path {
        // Map /lib/ld-musl-x86_64.so.1 → /disk/lib/ld-musl-x86_64.so.1
        let disk_path = if path.starts_with('/') {
            alloc::format!("/disk{}", path)
        } else {
            alloc::format!("/disk/{}", path)
        };

        // Pick a fresh per-`exec()` randomised base for the interpreter so
        // that ld-musl and every shared library it subsequently mmaps land
        // at different VAs each boot (System V AMD64 ABI §3.3.3, mmap(2),
        // vdso(7)).  See `interp_aslr_base()` for the layout rationale.
        let interp_base = interp_aslr_base();

        crate::serial_println!("[ELF] PT_INTERP: loading interpreter '{}'", disk_path);
        match read_interpreter_cached(&disk_path) {
            Ok(interp_data) => {
                crate::serial_println!("[ELF] PT_INTERP: {} bytes (cached)", interp_data.len());
                match load_elf_dyn(&interp_data, cr3, interp_base, &mut allocated_pages, &mut vmas) {
                    Ok(interp_entry) => {
                        crate::serial_println!(
                            "[ELF] Interpreter loaded at {:#x}, entry={:#x}",
                            interp_base, interp_entry
                        );
                        actual_entry = interp_entry;
                        interp_base_for_auxv = interp_base;
                    }
                    Err(e) => {
                        crate::serial_println!("[ELF] Interpreter load failed: {:?}", e);
                        return Err(ElfError::InterpLoad);
                    }
                }
            }
            Err(e) => {
                crate::serial_println!("[ELF] Interpreter not found at '{}': {:?}", disk_path, e);
                return Err(ElfError::InterpNotFound);
            }
        }
    }

    // ── Set up initial TLS block for PT_TLS (musl / glibc compat) ───
    // Layout (GNU/musl variant 2, x86-64):
    //   [ tls_template | padding | TCB (8 bytes) ]
    //   FS.base → TCB (which self-points back for __builtin_thread_pointer)
    //
    // musl's __init_tls walks AT_PHDR to find PT_TLS; it copies the template
    // itself at runtime.  All we must do is allocate a zeroed TLS area and set
    // FS.base to a valid TCB so early TLS accesses (errno, stack protector)
    // don't fault before musl initialises things properly.
    let tls_base_for_thread: u64 = if let Some(ref ti) = tls_info {
        let align  = ti.align.max(8);
        let memsz  = (ti.memsz + align - 1) & !(align - 1);
        // Total allocation = aligned TLS area + 8-byte TCB self-pointer
        let total  = memsz + 8;

        // Allocate from the PMM and map into the process address space.
        // We pick a fixed VA in the upper user area: 0x0000_7FFF_FFF0_0000.
        let tls_virt: u64 = 0x0000_7FFF_FFF0_0000;
        let npages = (total + pmm::PAGE_SIZE - 1) / pmm::PAGE_SIZE;

        if let Some(tls_phys) = crate::mm::pmm::alloc_pages(npages) {
            // Zero entire TLS area.
            let tls_slice = unsafe {
                core::slice::from_raw_parts_mut(phys_to_virt(tls_phys), total)
            };
            tls_slice.fill(0);

            // Copy the initialised data template (p_filesz bytes).
            let filesz = ti.filesz.min(ti.memsz);
            if filesz > 0 && ti.offset + filesz <= data.len() {
                tls_slice[..filesz].copy_from_slice(&data[ti.offset..ti.offset + filesz]);
            }

            // Write TCB self-pointer at offset `memsz` (points to itself).
            let tcb_va   = tls_virt + memsz as u64;
            let tcb_phys = tls_phys + memsz as u64;
            unsafe { *(phys_to_virt(tcb_phys) as *mut u64) = tcb_va; }

            // Track TLS pages so they are freed on process exit (same as PT_LOAD pages).
            for pi in 0..npages {
                allocated_pages.push(tls_phys + (pi * pmm::PAGE_SIZE) as u64);
            }

            // Register TLS region as a VMA so /proc/self/maps and CoW fork see it.
            vmas.push(VmArea {
                base:    tls_virt,
                length:  (npages * pmm::PAGE_SIZE) as u64,
                prot:    PROT_READ | PROT_WRITE,
                flags:   MAP_PRIVATE | MAP_ANONYMOUS,
                backing: VmBacking::Anonymous,
                name:    "[tls]",
            });

            // Map TLS pages into the process page tables (one page at a time).
            let flags = vmm::PAGE_PRESENT | vmm::PAGE_USER | vmm::PAGE_WRITABLE;
            for pi in 0..npages {
                vmm::map_page_in(
                    cr3,
                    tls_virt + (pi * pmm::PAGE_SIZE) as u64,
                    tls_phys + (pi * pmm::PAGE_SIZE) as u64,
                    flags,
                );
            }

            crate::serial_println!(
                "[ELF] PT_TLS: memsz={} filesz={} tcb_va={:#x}",
                ti.memsz, ti.filesz, tcb_va
            );
            tcb_va // FS.base = TCB virtual address
        } else {
            0
        }
    } else {
        0
    };

    // ── Build extra auxvec entries for dynamic linking ───────────────
    // AT_PHDR, AT_PHENT, AT_PHNUM: let the interpreter find the main binary's .dynamic
    // AT_BASE: where the interpreter was loaded (0 for static binaries)
    let mut extra_auxv: Vec<(u64, u64)> = Vec::new();
    // AT_PHDR: address of the program headers in the loaded process
    let loaded_phdr_vaddr = if phdr_vaddr != 0 {
        phdr_vaddr.wrapping_add(pie_bias)
    } else {
        load_base.wrapping_add(header.e_phoff)
    };
    extra_auxv.push((AT_PHDR,  loaded_phdr_vaddr));
    extra_auxv.push((AT_PHENT, header.e_phentsize as u64));
    extra_auxv.push((AT_PHNUM, header.e_phnum as u64));
    if interp_base_for_auxv != 0 {
        extra_auxv.push((AT_BASE, interp_base_for_auxv));
    }

    // ── Map the vDSO + vvar pages into the new process ───────────────
    // Provides __vdso_clock_gettime / __vdso_gettimeofday / __vdso_time /
    // __vdso_getcpu — see kernel/src/proc/vdso.rs and vdso(7).  A failed
    // mapping is non-fatal: the process still works via raw syscalls.
    let vdso_base = super::vdso::map_vdso(cr3, &mut vmas).unwrap_or(0);
    if vdso_base != 0 {
        extra_auxv.push((AT_SYSINFO_EHDR, vdso_base));
    }

    // Sets up the Linux ABI initial stack: argc, argv, envp, auxvec.
    // AT_ENTRY must be the REAL loaded entry (with PIE bias applied).
    let user_stack_ptr = setup_user_stack(
        &stack_pages,
        stack_bottom,
        argv,
        envp,
        header.e_entry.wrapping_add(pie_bias), // AT_ENTRY
        &extra_auxv,
    );

    // Build the auxv snapshot for /proc/self/auxv.
    // Mirrors the entries placed on the stack by setup_user_stack().
    // AT_HWCAP / AT_HWCAP2 are read from CPUID here too; we accept the tiny
    // overhead (two CPUID executions per exec) to keep this self-contained.
    let at_random_va = USER_STACK_TOP - 16; // matches setup_user_stack step-1 placement
    let (at_hwcap, at_hwcap2): (u64, u64) = {
        let edx: u64; let ecx: u64;
        unsafe {
            core::arch::asm!(
                "push rbx", "xor ecx, ecx", "mov eax, 1", "cpuid", "pop rbx",
                out("eax") _,
                lateout("ecx") ecx,
                lateout("edx") edx,
            );
        }
        (edx, ecx)
    };
    pub const AT_HWCAP2_AUX: u64 = 26;
    let mut auxv_snap: Vec<(u64, u64)> = Vec::new();
    auxv_snap.push((AT_PAGESZ, pmm::PAGE_SIZE as u64));
    auxv_snap.push((AT_HWCAP,  at_hwcap));
    auxv_snap.push((AT_HWCAP2_AUX, at_hwcap2));
    auxv_snap.push((AT_CLKTCK, 100));
    auxv_snap.push((AT_RANDOM, at_random_va));
    auxv_snap.push((AT_ENTRY,  header.e_entry.wrapping_add(pie_bias)));
    auxv_snap.push((AT_UID,    0));
    auxv_snap.push((AT_EUID,   0));
    auxv_snap.push((AT_GID,    0));
    auxv_snap.push((AT_EGID,   0));
    for &pair in &extra_auxv { auxv_snap.push(pair); }

    Ok(ElfLoadResult {
        entry_point: actual_entry,  // interpreter entry if dynamic, else main entry
        user_stack_ptr,
        allocated_pages,
        load_base,
        load_end,
        vmas,
        tls_base: tls_base_for_thread,
        auxv: auxv_snap,
        vdso_base,
    })
}

/// Quick check: is this data an ELF binary?
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == ELF_MAGIC
}

/// Quick check: is this data a `#!` shebang script?
pub fn is_shebang(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'#' && data[1] == b'!'
}

/// Maximum number of nested shebang layers we will follow before giving up.
/// Linux uses BINPRM_MAX_RECURSION = 4 (`fs/exec.c`). Matches POSIX intent of
/// preventing `#!` loops without limiting any legitimate use.
pub const SHEBANG_MAX_RECURSION: usize = 4;

/// Maximum length of a `#!` first line (excluding the `#!` itself).  Linux
/// uses BINPRM_BUF_SIZE=256 but historically 127 is the POSIX-portable cap;
/// we stick with 127 since it covers every real-world interpreter path.
const SHEBANG_MAX_LINE: usize = 127;

/// Result of resolving a `#!` chain for an exec() call.
pub struct ShebangResolved {
    /// The final (interpreter) ELF bytes that should be loaded.
    pub elf_data: alloc::vec::Vec<u8>,
    /// The rewritten argv, as owned strings.
    ///
    /// Layout for `#!<interp> <opt_arg>` exec'd as `[script, a1, a2]`:
    ///   `[interp, opt_arg?, script, a1, a2]`
    pub argv: alloc::vec::Vec<alloc::string::String>,
    /// The final resolved interpreter path (useful for debug/tracing).
    pub interp_path: alloc::string::String,
}

/// Parse a single `#!` line into `(interpreter, optional_arg)`.
///
/// The rules we follow (aligned with Linux `fs/binfmt_script.c`):
///   * Strip the leading `#!`.
///   * Stop at the first `\n` or after at most `SHEBANG_MAX_LINE` bytes.
///   * Trim leading whitespace (spaces and tabs).
///   * The interpreter is everything up to the first whitespace run.
///   * After the interpreter, skip one whitespace run, then the remainder
///     (trailing whitespace stripped) is a *single* argument — Linux does NOT
///     tokenise further, and neither do we. This matches `strace`-observed
///     behaviour and is what busybox/perl/etc. rely on.
///
/// Returns `None` if the interpreter field is empty.
fn parse_shebang_line(data: &[u8]) -> Option<(alloc::string::String, Option<alloc::string::String>)> {
    if data.len() < 2 || &data[0..2] != b"#!" {
        return None;
    }
    // Clamp to first newline or SHEBANG_MAX_LINE bytes after the `#!`.
    let mut end = 2;
    while end < data.len() && end - 2 < SHEBANG_MAX_LINE {
        if data[end] == b'\n' { break; }
        end += 1;
    }
    let line = &data[2..end];

    // Skip leading whitespace.
    let mut i = 0;
    while i < line.len() && (line[i] == b' ' || line[i] == b'\t') { i += 1; }
    // Interpreter token: up to next whitespace.
    let interp_start = i;
    while i < line.len() && line[i] != b' ' && line[i] != b'\t' { i += 1; }
    let interp_end = i;
    if interp_start == interp_end { return None; }
    let interp = core::str::from_utf8(&line[interp_start..interp_end]).ok()?.into();

    // Skip whitespace between interpreter and optional arg.
    while i < line.len() && (line[i] == b' ' || line[i] == b'\t') { i += 1; }
    // The remainder is a single argument. Trim trailing whitespace.
    let mut j = line.len();
    while j > i && (line[j - 1] == b' ' || line[j - 1] == b'\t' || line[j - 1] == b'\r') { j -= 1; }
    let opt_arg = if i < j {
        Some(core::str::from_utf8(&line[i..j]).ok()?.into())
    } else {
        None
    };

    Some((interp, opt_arg))
}

/// Resolve a potentially-shebang exec request into a concrete ELF + argv.
///
/// Given the file bytes and argv for an `exec(script_path, argv, envp)` call,
/// if the file starts with `#!` this reads the interpreter, rewrites argv to
/// `[interp, (opt_arg)?, script_path, argv[1..]]`, and repeats (up to
/// `SHEBANG_MAX_RECURSION` layers) until an ELF is reached.
///
/// On success returns `Ok(ShebangResolved)` whose `elf_data` is an ELF binary.
/// If the file was already an ELF, returns the same data and the original argv
/// untouched.
///
/// Errors are encoded as negative errno values (ENOEXEC=-8, ELOOP=-40).
/// VFS errors from reading the interpreter are mapped via
/// `subsys::linux::errno::vfs_err`.
pub fn resolve_shebang(
    script_path: &str,
    data: alloc::vec::Vec<u8>,
    argv: &[&str],
) -> Result<ShebangResolved, i64> {
    let mut cur_data = data;
    let mut cur_path: alloc::string::String = script_path.into();
    // Own the argv so we can rewrite it across recursion layers.
    let mut cur_argv: alloc::vec::Vec<alloc::string::String> =
        argv.iter().map(|s| (*s).into()).collect();
    if cur_argv.is_empty() {
        cur_argv.push(cur_path.clone());
    }

    for _depth in 0..SHEBANG_MAX_RECURSION {
        if is_elf(&cur_data) {
            return Ok(ShebangResolved {
                elf_data: cur_data,
                argv: cur_argv,
                interp_path: cur_path,
            });
        }
        if !is_shebang(&cur_data) {
            return Err(-8); // ENOEXEC
        }
        let (interp, opt_arg) = match parse_shebang_line(&cur_data) {
            Some(p) => p,
            None => return Err(-8), // ENOEXEC — malformed #!
        };

        // Read the interpreter. Use the same cache path ELF loader uses, so
        // repeated shebang-dispatched execs of the same interp don't re-hit
        // the disk (busybox wrappers all point at /bin/busybox).
        let interp_data = match read_interpreter_cached(&interp) {
            Ok(d) => d,
            Err(e) => return Err(crate::subsys::linux::errno::vfs_err(e)),
        };
        if interp_data.is_empty() {
            return Err(-8); // ENOEXEC
        }

        // Rewrite argv: [interp, opt_arg?, script_path, original[1..]]
        let tail: alloc::vec::Vec<alloc::string::String> = if cur_argv.len() > 1 {
            cur_argv[1..].iter().cloned().collect()
        } else {
            alloc::vec::Vec::new()
        };
        let mut new_argv = alloc::vec::Vec::with_capacity(2 + tail.len());
        new_argv.push(interp.clone());
        if let Some(a) = opt_arg { new_argv.push(a); }
        new_argv.push(cur_path.clone());
        new_argv.extend(tail);

        cur_data = interp_data;
        cur_path = interp;
        cur_argv = new_argv;
    }

    Err(-40) // ELOOP — too many #! layers
}

/// Test-only: apply DT_RELR relocations to an in-memory image buffer.
///
/// This version treats the buffer as both the file image AND the runtime image
/// (i.e., the pages are already kernel-visible and the load_bias was already
/// applied to the addresses).  Used exclusively by `test_runner.rs` to verify
/// the DT_RELR algorithm without spinning up a full process address space.
///
/// `image`     — mutable byte slice of the loaded image (writable, kernel-mapped)
/// `load_base` — base address at which the image is logically loaded
/// `relr_off`  — byte offset of the DT_RELR table within `image`
/// `relr_sz`   — byte length of the DT_RELR table
/// `load_bias` — value to add to each slot (= load_base for a binary loaded at bias)
///
/// Each slot in the DT_RELR table is a u64 within `image` at
/// `(slot_link_time_va - 0) + 0 == slot_link_time_va` (for min_vaddr=0 PIE).
/// The slot values are incremented in-place by `load_bias`.
#[cfg(feature = "test-mode")]
pub fn apply_relr_in_place(image: &mut [u8], relr_off: usize, relr_sz: usize, load_bias: u64) {
    if load_bias == 0 || relr_sz == 0 || relr_off + relr_sz > image.len() {
        return;
    }

    let n_words = relr_sz / 8;
    let mut base_lva: u64 = 0;

    for i in 0..n_words {
        let off = relr_off + i * 8;
        if off + 8 > image.len() { break; }
        let word = u64::from_le_bytes(image[off..off + 8].try_into().unwrap());

        if word & 1 == 0 {
            // Address entry: this word is the link-time VA of the next slot,
            // AND the slot itself gets relocated.
            base_lva = word;
            // Patch the slot at base_lva (which is an offset into image for min_vaddr=0 PIE).
            let slot_off = base_lva as usize;
            if slot_off + 8 <= image.len() {
                let old = u64::from_le_bytes(image[slot_off..slot_off + 8].try_into().unwrap());
                image[slot_off..slot_off + 8].copy_from_slice(&(old.wrapping_add(load_bias)).to_le_bytes());
            }
            base_lva = base_lva.wrapping_add(8);
        } else {
            // Bitmap entry.
            let mut bitmap = word >> 1;
            let mut slot_delta: u64 = 0;
            while bitmap != 0 {
                if bitmap & 1 != 0 {
                    let slot_off = (base_lva.wrapping_add(slot_delta)) as usize;
                    if slot_off + 8 <= image.len() {
                        let old = u64::from_le_bytes(image[slot_off..slot_off + 8].try_into().unwrap());
                        image[slot_off..slot_off + 8].copy_from_slice(&(old.wrapping_add(load_bias)).to_le_bytes());
                    }
                }
                bitmap >>= 1;
                slot_delta = slot_delta.wrapping_add(8);
            }
            base_lva = base_lva.wrapping_add(63 * 8);
        }
    }
}

/// Test-only: parse PT_DYNAMIC for DT_RELR info and DT_GNU_HASH presence.
/// Returns `(relr_file_off, relr_sz, has_gnu_hash)`.
#[cfg(feature = "test-mode")]
pub fn parse_dynamic_test(data: &[u8]) -> (usize, usize, bool) {
    match validate_elf(data) {
        Ok(h) => parse_dynamic_for_relr(data, h, 0),
        Err(_) => (0, 0, false),
    }
}

/// Load an ET_DYN shared object (dynamic linker / shared library) at a fixed base.
///
/// All PT_LOAD segments are loaded with a bias so that the lowest-address
/// segment starts at `base`. Returns the interpreter's entry point.
///
/// Pages are pushed into `allocated_pages` so the caller can free them on exit.
/// VMAs for each loaded segment are pushed into `vmas` so the process's VmSpace
/// covers interpreter pages and can free them via the VMA walk on exit.
fn load_elf_dyn(
    data: &[u8],
    cr3: u64,
    base: u64,
    allocated_pages: &mut Vec<u64>,
    vmas: &mut Vec<VmArea>,
) -> Result<u64, ElfError> {
    if data.len() < core::mem::size_of::<Elf64Header>() {
        return Err(ElfError::TooSmall);
    }
    let header = unsafe { &*(data.as_ptr() as *const Elf64Header) };
    if header.e_ident[0..4] != ELF_MAGIC   { return Err(ElfError::BadMagic); }
    if header.e_ident[4] != ELFCLASS64      { return Err(ElfError::Not64Bit); }
    if header.e_ident[5] != ELFDATA2LSB     { return Err(ElfError::NotLittleEndian); }
    if header.e_type != ET_DYN              { return Err(ElfError::NotExecutable); }
    if header.e_machine != EM_X86_64       { return Err(ElfError::WrongArch); }

    let ph_offset = header.e_phoff as usize;
    let ph_size   = header.e_phentsize as usize;
    let ph_count  = header.e_phnum as usize;

    // Same MAX_PHDRS cap as the main loader (CWE-119) — see commentary on
    // `MAX_PHDRS` for the rationale.  An untrusted interpreter image must
    // not be allowed to force 65535 unsafe pointer reads.
    if ph_count > MAX_PHDRS {
        crate::serial_println!(
            "[ELF/interp] reject e_phnum={} (exceeds cap of {}) — CWE-119",
            ph_count, MAX_PHDRS,
        );
        return Err(ElfError::TooManyPhdrs);
    }

    // Find the lowest PT_LOAD vaddr to compute the load bias.
    let mut min_vaddr = u64::MAX;
    for i in 0..ph_count {
        let offset = ph_offset + i * ph_size;
        if offset + ph_size > data.len() { continue; }
        let phdr = unsafe { &*(data.as_ptr().add(offset) as *const Elf64Phdr) };
        if phdr.p_type == PT_LOAD && phdr.p_vaddr < min_vaddr {
            min_vaddr = phdr.p_vaddr;
        }
    }
    if min_vaddr == u64::MAX { return Err(ElfError::NoLoadSegments); }

    // bias = base - page-aligned min_vaddr
    let bias = base.wrapping_sub(min_vaddr & !0xFFF);
    let mut mapped_pages: Vec<(u64, u64)> = Vec::new();

    for i in 0..ph_count {
        let offset = ph_offset + i * ph_size;
        if offset + ph_size > data.len() { continue; }
        let phdr = unsafe { &*(data.as_ptr().add(offset) as *const Elf64Phdr) };
        if phdr.p_type != PT_LOAD { continue; }

        let vaddr     = phdr.p_vaddr.wrapping_add(bias);
        let memsz     = phdr.p_memsz;
        let filesz    = phdr.p_filesz;
        let file_off  = phdr.p_offset as usize;

        if vaddr >= 0xFFFF_8000_0000_0000 { return Err(ElfError::AddressInKernelSpace); }

        // System V ABI Chapter 5: p_filesz must not exceed p_memsz.
        if filesz > memsz {
            crate::serial_println!(
                "[ELF/interp] reject PT_LOAD p_filesz={:#x} > p_memsz={:#x}",
                filesz, memsz,
            );
            return Err(ElfError::BadSegmentSize);
        }

        // W^X policy — reject simultaneous PF_W and PF_X (CWE-269).
        if phdr.p_flags & PF_W != 0 && phdr.p_flags & PF_X != 0 {
            crate::serial_println!(
                "[ELF/interp] reject PT_LOAD with both PF_W and PF_X set (W^X policy)",
            );
            return Err(ElfError::WritableExecutable);
        }

        let mut flags = vmm::PAGE_PRESENT | vmm::PAGE_USER;
        if phdr.p_flags & PF_W != 0 { flags |= vmm::PAGE_WRITABLE; }
        if phdr.p_flags & PF_X == 0 { flags |= vmm::PAGE_NO_EXECUTE; }

        let page_start = vaddr & !0xFFF;
        let page_end   = (vaddr + memsz + 0xFFF) & !0xFFF;

        // Register a VMA for this interpreter segment so the parent's VmSpace
        // covers interpreter pages and free_process_memory can free them.
        let mut seg_prot: VmProt = PROT_READ;
        if phdr.p_flags & PF_W != 0 { seg_prot |= PROT_WRITE; }
        if phdr.p_flags & PF_X != 0 { seg_prot |= PROT_EXEC; }
        vmas.push(VmArea {
            base: page_start,
            length: page_end - page_start,
            prot: seg_prot,
            flags: MAP_PRIVATE,
            backing: VmBacking::Anonymous,
            name: "[interp]",
        });

        for page_vaddr in (page_start..page_end).step_by(pmm::PAGE_SIZE) {
            let (phys, already) = if let Some(&(_, p)) =
                mapped_pages.iter().find(|&&(va, _)| va == page_vaddr) {
                (p, true)
            } else {
                let p = pmm::alloc_page().ok_or(ElfError::OutOfMemory)?;
                allocated_pages.push(p);
                unsafe { core::ptr::write_bytes(phys_to_virt(p), 0, pmm::PAGE_SIZE); }
                (p, false)
            };

            // Copy file content into the page.
            let seg_base = phdr.p_vaddr.wrapping_add(bias);
            let page_seg_off = page_vaddr.saturating_sub(seg_base);
            if page_seg_off < filesz {
                let copy_start = if page_vaddr < seg_base { (seg_base - page_vaddr) as usize } else { 0 };
                let data_offset = if page_vaddr >= seg_base {
                    file_off + (page_vaddr - seg_base) as usize
                } else { file_off };
                let remaining = (file_off + filesz as usize).saturating_sub(data_offset);
                let copy_len = remaining.min(pmm::PAGE_SIZE - copy_start);
                if copy_len > 0 && data_offset < data.len() {
                    let actual = copy_len.min(data.len() - data_offset);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr().add(data_offset),
                            phys_to_virt(phys).add(copy_start),
                            actual,
                        );
                    }
                }
            }

            if !already {
                if !vmm::map_page_in(cr3, page_vaddr, phys, flags) {
                    return Err(ElfError::OutOfMemory);
                }
                crate::mm::refcount::page_ref_set(phys, 1);
                mapped_pages.push((page_vaddr, phys));
            }
        }
    }

    // ── [ELF/INIT-ARRAY] diagnostic for the interpreter image ───────────
    // ld-musl / ld-linux is itself an ET_DYN with its own DT_INIT_ARRAY
    // (`_dl_init` family); record the constructor-table addresses + first
    // four fn_ptrs as loaded.  Per ELF gABI §5.7 the interpreter's own
    // bootstrap (`_dl_start`) drives these — the kernel never invokes them.
    emit_init_array_diag(data, header, bias, &mapped_pages, "interp");

    // ── DT_RELR for the interpreter: DO NOT apply from the kernel ───────
    //
    // On real Linux, the kernel NEVER applies DT_RELR (or any relocations) to
    // the ELF interpreter (ld-linux-x86-64.so.2).  The interpreter is loaded
    // verbatim — raw file bytes — and its own bootstrap code (`_dl_start`)
    // detects the load bias via PC-relative tricks, then applies its own
    // DT_RELR in `_dl_relocate_object`.
    //
    // We previously called `apply_relr_relocations` here, which patched the
    // interpreter's .data.rel.ro slots.  When ld-linux then ran its bootstrap
    // and applied the same DT_RELR a second time, each slot received
    // `bias + bias + link_time_value` instead of `bias + link_time_value`,
    // producing a non-canonical address and a General Protection Fault the
    // first time one of those function-pointer slots was called.
    //
    // Fix: leave the interpreter pages unpatched; let ld-linux relocate itself.

    Ok(header.e_entry.wrapping_add(bias))
}

// ── Linux ABI initial stack layout ──────────────────────────────────────────
//
// musl's _start (and glibc's) expects this layout at the RSP on entry:
//
//   [high address]
//     16 random bytes (for AT_RANDOM)
//     env strings: "HOME=/\0", "PATH=/bin\0", ...
//     argv strings: "program\0", ...
//     (padding for 16-byte alignment)
//     auxvec: pairs of (type, value), terminated by (AT_NULL, 0)
//     NULL                           ← envp terminator
//     ptr to env_string[n-1]
//     ...
//     ptr to env_string[0]
//     NULL                           ← argv terminator
//     ptr to argv_string[n-1]
//     ...
//     ptr to argv_string[0]
//     argc (u64)                     ← RSP points here
//   [low address]

/// Write a u64 into the user stack at the given virtual address.
///
/// Translates the vaddr to the corresponding physical page and writes
/// directly. Panics if vaddr is outside the stack range.
fn stack_write_u64(
    stack_pages: &[(u64, u64)],
    stack_bottom: u64,
    vaddr: u64,
    value: u64,
) {
    let page_vaddr = vaddr & !0xFFF;
    let offset = (vaddr & 0xFFF) as usize;
    for &(pv, phys) in stack_pages {
        if pv == page_vaddr {
            unsafe {
                let dst = phys_to_virt(phys).add(offset) as *mut u64;
                core::ptr::write(dst, value);
            }
            // Track B (Phase 5, 2026-05-21) — record the kernel-direct-map
            // write into the stack-page provenance ring.  The window gate
            // inside `record_write` drops VAs outside the 0x3f thread-stack
            // range, so the main-thread initial-stack writes
            // (USER_STACK_TOP=0x7fff_…) are dropped harmlessly while the
            // 0x3f-range writes are captured.
            #[cfg(feature = "stack-prov")]
            crate::mm::stack_prov::record_write(
                vaddr, value, crate::mm::stack_prov::SITE_ELF_AUXV,
            );
            return;
        }
    }
    panic!(
        "setup_user_stack: vaddr {:#x} not in stack range [{:#x}..)",
        vaddr, stack_bottom,
    );
}

/// Write a byte slice into the user stack at the given virtual address.
fn stack_write_bytes(
    stack_pages: &[(u64, u64)],
    _stack_bottom: u64,
    vaddr: u64,
    data: &[u8],
) {
    // Handle page-crossing writes byte by byte (strings are short).
    for (i, &b) in data.iter().enumerate() {
        let addr = vaddr + i as u64;
        let page_vaddr = addr & !0xFFF;
        let offset = (addr & 0xFFF) as usize;
        for &(pv, phys) in stack_pages {
            if pv == page_vaddr {
                unsafe {
                    let dst = phys_to_virt(phys).add(offset);
                    core::ptr::write(dst, b);
                }
                break;
            }
        }
    }
    // Track B (Phase 5, 2026-05-21) — record ONE stack-prov entry per
    // byte-slice write, packing the first up-to-8 bytes as the `value`
    // (little-endian).  Per-byte recording would flood the small ring;
    // the first-byte packing is enough to disambiguate string writes
    // from u64 writes in the post-mortem.
    #[cfg(feature = "stack-prov")]
    if !data.is_empty() {
        let mut val: u64 = 0;
        let n = core::cmp::min(8, data.len());
        for j in 0..n {
            val |= (data[j] as u64) << (j * 8);
        }
        crate::mm::stack_prov::record_write(
            vaddr, val, crate::mm::stack_prov::SITE_ELF_AUXV_BYTES,
        );
    }
}

/// Set up the initial user stack with the Linux ABI layout.
///
/// Writes argc, argv pointers, envp pointers, auxiliary vector, and
/// all strings into the stack pages. Returns the adjusted user RSP
/// (pointing to argc, 16-byte aligned).
fn setup_user_stack(
    stack_pages: &[(u64, u64)],
    stack_bottom: u64,
    argv: &[&str],
    envp: &[&str],
    entry_point: u64,
    extra_auxv: &[(u64, u64)],
) -> u64 {
    let stack_top = USER_STACK_TOP;

    // ── Step 1: Write strings at the top of the stack ───────────────────
    // We write from top downward: random bytes, then env strings, then argv strings.

    let mut sp = stack_top;

    // 16 random bytes for AT_RANDOM (Linux ELF aux-vector ABI, getauxval(3)).
    //
    // The auxiliary vector entry AT_RANDOM points to 16 bytes of high-entropy
    // data that the C runtime consumes to seed __stack_chk_guard (and, on
    // glibc, the pointer-mangling cookie).  Per the ELF gABI §6
    // stack-protector convention the userspace runtime is responsible for
    // zeroing one byte of the canary (musl zeroes byte 1; glibc zeroes
    // byte 0) so that string-manipulation bugs cannot leak the canary in
    // full — the kernel MUST supply 16 high-entropy bytes regardless.
    //
    // Previously this slot was filled by a per-byte arithmetic expression
    // whose (i+1) increment was lost in the high-bit truncation
    // `(seed*K + i+1) >> 33` — all 16 bytes resolved to the same value,
    // producing fill patterns like 0x9a9a9a9a9a9a9a9a.  After musl's
    // byte-1 zeroing the runtime canary became 0x9a9a9a9a9a9a009a, which
    // is statistically distinguishable from a random canary and, more
    // importantly, identical across every musl process — defeating SSP's
    // exploit-mitigation purpose entirely.
    //
    // Use the kernel RNG (RDRAND when available, RDTSC+xorshift fallback)
    // for two 64-bit draws to fill the slot.  Each draw is independent so
    // all 16 bytes carry full entropy.
    sp -= 16;
    let at_random_addr = sp;
    let random_bytes: [u8; 16] = {
        let lo = crate::security::rand::rand_u64();
        let hi = crate::security::rand::rand_u64();
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&lo.to_le_bytes());
        buf[8..16].copy_from_slice(&hi.to_le_bytes());
        buf
    };
    stack_write_bytes(stack_pages, stack_bottom, at_random_addr, &random_bytes);

    // Write environment strings and record their vaddrs
    let mut env_addrs: Vec<u64> = Vec::new();
    for &env in envp.iter() {
        let bytes = env.as_bytes();
        sp -= (bytes.len() + 1) as u64; // +1 for null terminator
        stack_write_bytes(stack_pages, stack_bottom, sp, bytes);
        stack_write_bytes(stack_pages, stack_bottom, sp + bytes.len() as u64, &[0]);
        env_addrs.push(sp);
    }

    // Write argv strings and record their vaddrs
    let mut arg_addrs: Vec<u64> = Vec::new();
    for &arg in argv.iter() {
        let bytes = arg.as_bytes();
        sp -= (bytes.len() + 1) as u64;
        stack_write_bytes(stack_pages, stack_bottom, sp, bytes);
        stack_write_bytes(stack_pages, stack_bottom, sp + bytes.len() as u64, &[0]);
        arg_addrs.push(sp);
    }

    // ── Step 2: Compute space needed for the structured region ──────────
    // We need to align and then push: auxvec, envp[], argv[], argc

    // auxvec: standard 10 pairs + extra_auxv pairs + AT_NULL terminator
    //   (AT_PAGESZ, AT_HWCAP, AT_HWCAP2, AT_CLKTCK, AT_RANDOM, AT_ENTRY, AT_UID, AT_EUID, AT_GID, AT_EGID) = 10 base
    let num_aux_pairs = 10 + extra_auxv.len() + 1; // +1 for AT_NULL
    let auxvec_u64s = num_aux_pairs * 2;

    // envp: env_addrs.len() + 1 (null terminator)
    let envp_u64s = env_addrs.len() + 1;

    // argv: arg_addrs.len() + 1 (null terminator)
    let argv_u64s = arg_addrs.len() + 1;

    // argc: 1 u64
    let total_u64s = 1 + argv_u64s + envp_u64s + auxvec_u64s;

    // Align sp down to 16 bytes first, then ensure the total is aligned.
    sp = sp & !0xF; // align string region end

    // The total frame must keep RSP 16-byte aligned at _start.
    // RSP % 16 == 0 at _start. Since each u64 is 8 bytes:
    // total_u64s * 8 must be a multiple of 16, i.e., total_u64s must be even.
    let total_u64s = if total_u64s % 2 != 0 { total_u64s + 1 } else { total_u64s };

    sp -= (total_u64s * 8) as u64;
    let rsp = sp; // This is where argc will be

    // ── Step 3: Write the structured data ───────────────────────────────
    let mut pos = rsp;

    // argc
    stack_write_u64(stack_pages, stack_bottom, pos, argv.len() as u64);
    pos += 8;

    // argv pointers
    for &addr in &arg_addrs {
        stack_write_u64(stack_pages, stack_bottom, pos, addr);
        pos += 8;
    }
    stack_write_u64(stack_pages, stack_bottom, pos, 0); // NULL terminator
    pos += 8;

    // envp pointers
    for &addr in &env_addrs {
        stack_write_u64(stack_pages, stack_bottom, pos, addr);
        pos += 8;
    }
    stack_write_u64(stack_pages, stack_bottom, pos, 0); // NULL terminator
    pos += 8;

    // Auxiliary vector: standard entries + extra (AT_PHDR, AT_PHENT, AT_PHNUM, AT_BASE) + NULL
    // AT_HWCAP: on x86_64 Linux, this is CPUID.01H:EDX verbatim.
    // glibc IFUNC resolvers compare AT_HWCAP against CPUID to select
    // optimized memcpy/memset/zlib implementations.  If AT_HWCAP doesn't
    // match the CPU's actual feature bits, IFUNC may choose wrong code
    // paths (e.g., SSE3 memcpy when the CPU has it but AT_HWCAP says no),
    // causing subtle data corruption in zlib, malloc, etc.
    // AT_HWCAP/AT_HWCAP2: on x86_64 Linux, HWCAP = CPUID.01H:EDX,
    // HWCAP2 = CPUID.01H:ECX.  glibc IFUNC resolvers compare both
    // against CPUID to select optimized code paths (memcpy, zlib, etc.).
    // Read directly from CPUID so the values match what glibc detects.
    let (at_hwcap, at_hwcap2): (u64, u64) = {
        let edx: u64;
        let ecx: u64;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "xor ecx, ecx",  // sub-leaf 0
                "mov eax, 1",
                "cpuid",
                "pop rbx",
                out("eax") _,
                lateout("ecx") ecx,
                lateout("edx") edx,
            );
        }
        (edx, ecx)
    };
    pub const AT_HWCAP2: u64 = 26;
    let base_aux: [(u64, u64); 10] = [
        (AT_PAGESZ, pmm::PAGE_SIZE as u64),
        (AT_HWCAP,  at_hwcap),
        (AT_HWCAP2, at_hwcap2),
        (AT_CLKTCK, 100),           // PIT runs at 100 Hz
        (AT_RANDOM, at_random_addr),
        (AT_ENTRY, entry_point),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
    ];
    for (atype, aval) in base_aux {
        stack_write_u64(stack_pages, stack_bottom, pos, atype);
        pos += 8;
        stack_write_u64(stack_pages, stack_bottom, pos, aval);
        pos += 8;
    }
    for &(atype, aval) in extra_auxv {
        stack_write_u64(stack_pages, stack_bottom, pos, atype);
        pos += 8;
        stack_write_u64(stack_pages, stack_bottom, pos, aval);
        pos += 8;
    }
    // AT_NULL terminator
    stack_write_u64(stack_pages, stack_bottom, pos, AT_NULL);
    pos += 8;
    stack_write_u64(stack_pages, stack_bottom, pos, 0);
    #[allow(unused_assignments)]
    { pos += 8; }

    rsp
}
