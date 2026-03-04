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

/// Segment flags
const PF_X: u32 = 1; // Execute
const PF_W: u32 = 2; // Write
const PF_R: u32 = 4; // Read

/// Default user stack virtual address (top of lower half)
const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;
/// Default user stack size: 64 KiB (16 pages)
const USER_STACK_PAGES: usize = 16;
const USER_STACK_SIZE: u64 = (USER_STACK_PAGES * pmm::PAGE_SIZE) as u64;

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
pub const AT_RANDOM: u64  = 25;  // Address of 16 random bytes

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
        }
    }
}

/// Validate and parse an ELF64 header.
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
    if header.e_type != ET_EXEC {
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
/// Returns the entry point, stack pointer, and VMAs for Ring 3 execution.
///
/// # Arguments
/// * `data` — Complete ELF binary contents.
/// * `cr3` — Physical address of the PML4 to map into.
///
/// # Safety
/// `cr3` must point to a valid PML4 page table with kernel-half mapped.
pub fn load_elf(data: &[u8], cr3: u64) -> Result<ElfLoadResult, ElfError> {
    let header = validate_elf(data)?;
    let mut allocated_pages: Vec<u64> = Vec::new();
    // Track pages mapped by THIS load_elf call, for overlap detection.
    // (virt_to_phys_in can't be used because new_user deep-clones the
    // identity map, making every low address appear "already mapped".)
    let mut mapped_pages: Vec<(u64, u64)> = Vec::new();
    let mut vmas: Vec<VmArea> = Vec::new();
    let mut load_base = u64::MAX;
    let mut load_end = 0u64;
    let mut has_load = false;

    // Parse and load program headers.
    let ph_offset = header.e_phoff as usize;
    let ph_size = header.e_phentsize as usize;
    let ph_count = header.e_phnum as usize;

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

        let vaddr = phdr.p_vaddr;
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
                unsafe { core::ptr::write_bytes(p as *mut u8, 0, pmm::PAGE_SIZE); }
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
                        let dst = (phys as *mut u8).add(copy_start);
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
    let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
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
            core::ptr::write_bytes(phys as *mut u8, 0, pmm::PAGE_SIZE);
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

    // Set up the Linux ABI initial stack: argc, argv, envp, auxvec.
    let user_stack_ptr = setup_user_stack(
        &stack_pages,
        stack_bottom,
        &["astryx"],           // argv (program name placeholder)
        &["HOME=/", "PATH=/bin:/disk/bin"],  // envp
        header.e_entry,        // entry point (for AT_ENTRY)
    );

    Ok(ElfLoadResult {
        entry_point: header.e_entry,
        user_stack_ptr,
        allocated_pages,
        load_base,
        load_end,
        vmas,
    })
}

/// Quick check: is this data an ELF binary?
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == ELF_MAGIC
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
                let dst = (phys as *mut u8).add(offset) as *mut u64;
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
                    let dst = (phys as *mut u8).add(offset);
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

    // auxvec: (AT_PAGESZ, AT_RANDOM, AT_ENTRY, AT_UID, AT_EUID, AT_GID, AT_EGID, AT_NULL)
    // = 8 pairs = 16 u64s
    let num_aux_pairs = 8;
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

    // Auxiliary vector
    let aux_entries: [(u64, u64); 8] = [
        (AT_PAGESZ, pmm::PAGE_SIZE as u64),
        (AT_RANDOM, at_random_addr),
        (AT_ENTRY, entry_point),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_NULL, 0), // terminator
    ];
    for (atype, aval) in aux_entries {
        stack_write_u64(stack_pages, stack_bottom, pos, atype);
        pos += 8;
        stack_write_u64(stack_pages, stack_bottom, pos, aval);
        pos += 8;
    }

    rsp
}
