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
/// Program header type: program header table location
const PT_PHDR: u32 = 6;
/// Program header type: thread-local storage template
const PT_TLS: u32 = 7;

/// ELF type: dynamically-linked shared object / PIE
const ET_DYN: u16 = 3;

/// Virtual address at which the dynamic interpreter is loaded.
/// Placed below the main stack: 0x7F00_0000_0000 has plenty of room for
/// a 4 MiB interpreter without touching the stack at 0x7FFF_FFFF_0000.
const INTERP_BASE: u64 = 0x7F00_0000_0000;

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
        }
    }
}

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
/// at INTERP_BASE and sets it as the actual entry point, passing the
/// main executable's entry via AT_ENTRY in the auxiliary vector.
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
                    for &page in &allocated_pages {
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
            for &page in &allocated_pages {
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

        crate::serial_println!("[ELF] PT_INTERP: loading interpreter '{}'", disk_path);
        match read_interpreter_cached(&disk_path) {
            Ok(interp_data) => {
                crate::serial_println!("[ELF] PT_INTERP: {} bytes (cached)", interp_data.len());
                match load_elf_dyn(&interp_data, cr3, INTERP_BASE, &mut allocated_pages, &mut vmas) {
                    Ok(interp_entry) => {
                        crate::serial_println!(
                            "[ELF] Interpreter loaded at {:#x}, entry={:#x}",
                            INTERP_BASE, interp_entry
                        );
                        actual_entry = interp_entry;
                        interp_base_for_auxv = INTERP_BASE;
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

    Ok(ElfLoadResult {
        entry_point: actual_entry,  // interpreter entry if dynamic, else main entry
        user_stack_ptr,
        allocated_pages,
        load_base,
        load_end,
        vmas,
        tls_base: tls_base_for_thread,
    })
}

/// Quick check: is this data an ELF binary?
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == ELF_MAGIC
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

    // 16 random bytes for AT_RANDOM
    sp -= 16;
    let at_random_addr = sp;
    // Use RDRAND if available, otherwise use a simple seed from the PIT tick counter.
    let random_bytes: [u8; 16] = {
        let mut buf = [0u8; 16];
        let seed = crate::arch::x86_64::irq::TICK_COUNT
            .load(core::sync::atomic::Ordering::Relaxed);
        for i in 0..16 {
            // Simple PRNG: xorshift-like mixing of seed + index
            let v = seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64 + 1);
            buf[i] = (v >> 33) as u8;
        }
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
