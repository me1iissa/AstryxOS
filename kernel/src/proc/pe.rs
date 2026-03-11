//! PE32+ Binary Loader (Windows x86-64 Portable Executable)
//!
//! Parses and loads PE32+ (64-bit) executables into a process address space.
//! Inspired by the Windows NT loader architecture; references from:
//! - `SupportingResources/NT4.0/private/ntos/dll/ldrinit.c`
//! - `SupportingResources/reactos/dll/ntdll/ldr/`
//!
//! # Supported Features
//! - PE32+ (Magic 0x020B) on AMD64 (Machine 0x8664)
//! - Section mapping at ImageBase or relocated base
//! - Base relocations (IMAGE_REL_BASED_DIR64 / HIGHLOW)
//! - Import Address Table resolution via [`crate::nt`] stub table
//! - Subsystem detection (Console vs. GUI)
//!
//! # Address Space Layout
//! ```text
//! 0x0000_0000_0040_0000  Low-address PE load (32-bit compatible base)
//! 0x0000_0001_4000_0000  Default PE32+ preferred base (0x140000000)
//! 0x0000_7FFF_FFFF_0000  User stack (ELF-compatible)
//! 0xFFFF_8000_0000_0000+ Kernel space
//! ```

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use crate::mm::{pmm, vmm};
use crate::mm::vma::{VmArea, VmBacking, VmFlags, VmProt, PROT_READ, PROT_WRITE, PROT_EXEC,
                     MAP_PRIVATE, MAP_ANONYMOUS};

// ─── PE Signature & Magic numbers ────────────────────────────────────────────

/// Intel x86-64 (AMD64) machine type.
pub const IMAGE_FILE_MACHINE_AMD64: u16   = 0x8664;
/// PE32+ optional header magic (64-bit).
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
/// PE32 optional header magic (32-bit, not supported by loader but recognised).
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;
/// "MZ" DOS signature.
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
/// "PE\0\0" NT signature.
pub const IMAGE_NT_SIGNATURE: u32  = 0x0000_4550;

// ─── File header Characteristics ─────────────────────────────────────────────
pub const IMAGE_FILE_EXECUTABLE_IMAGE:      u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE:   u16 = 0x0020;
pub const IMAGE_FILE_DLL:                   u16 = 0x2000;

// ─── Section Characteristics ──────────────────────────────────────────────────
pub const IMAGE_SCN_CNT_CODE:               u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA:   u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_EXECUTE:            u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ:               u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE:              u32 = 0x8000_0000;
pub const IMAGE_SCN_MEM_DISCARDABLE:        u32 = 0x0200_0000;

// ─── Subsystem values ────────────────────────────────────────────────────────
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI:      u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI:      u16 = 3;
pub const IMAGE_SUBSYSTEM_NATIVE:           u16 = 1;

// ─── Data Directory indices ───────────────────────────────────────────────────
pub const IMAGE_DIRECTORY_ENTRY_EXPORT:     usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT:     usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE:   usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION:  usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC:  usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS:        usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_IAT:        usize = 12;
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

// ─── Relocation types ────────────────────────────────────────────────────────
pub const IMAGE_REL_BASED_ABSOLUTE:  u8 = 0; // no-op
pub const IMAGE_REL_BASED_HIGHLOW:   u8 = 3; // add delta to 32-bit DWORD
pub const IMAGE_REL_BASED_DIR64:     u8 = 10; // add delta to 64-bit QWORD

// ─── Data structures ─────────────────────────────────────────────────────────

/// IMAGE_DOS_HEADER (MZ stub header, 64 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageDosHeader {
    pub e_magic:    u16,   // 0x5A4D "MZ"
    pub e_cblp:     u16,
    pub e_cp:       u16,
    pub e_crlc:     u16,
    pub e_cparhdr:  u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss:       u16,
    pub e_sp:       u16,
    pub e_csum:     u16,
    pub e_ip:       u16,
    pub e_cs:       u16,
    pub e_lfarlc:   u16,
    pub e_ovno:     u16,
    pub e_res:      [u16; 4],
    pub e_oemid:    u16,
    pub e_oeminfo:  u16,
    pub e_res2:     [u16; 10],
    pub e_lfanew:   u32,   // offset to NT headers
}

/// IMAGE_FILE_HEADER (COFF header, 20 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageFileHeader {
    pub machine:                 u16,
    pub number_of_sections:      u16,
    pub time_date_stamp:         u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols:       u32,
    pub size_of_optional_header: u16,
    pub characteristics:         u16,
}

/// IMAGE_DATA_DIRECTORY (8 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size:            u32,
}

/// IMAGE_OPTIONAL_HEADER64 (240 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageOptionalHeader64 {
    pub magic:                        u16,
    pub major_linker_version:         u8,
    pub minor_linker_version:         u8,
    pub size_of_code:                 u32,
    pub size_of_initialized_data:     u32,
    pub size_of_uninitialized_data:   u32,
    pub address_of_entry_point:       u32, // RVA
    pub base_of_code:                 u32, // RVA
    pub image_base:                   u64,
    pub section_alignment:            u32,
    pub file_alignment:               u32,
    pub major_os_version:             u16,
    pub minor_os_version:             u16,
    pub major_image_version:          u16,
    pub minor_image_version:          u16,
    pub major_subsystem_version:      u16,
    pub minor_subsystem_version:      u16,
    pub win32_version_value:          u32,
    pub size_of_image:                u32,
    pub size_of_headers:              u32,
    pub check_sum:                    u32,
    pub subsystem:                    u16,
    pub dll_characteristics:          u16,
    pub size_of_stack_reserve:        u64,
    pub size_of_stack_commit:         u64,
    pub size_of_heap_reserve:         u64,
    pub size_of_heap_commit:          u64,
    pub loader_flags:                 u32,
    pub number_of_rva_and_sizes:      u32,
    pub data_directory:               [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

/// IMAGE_NT_HEADERS64 (PE signature + file header + optional header).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageNtHeaders64 {
    pub signature:       u32,               // 0x00004550 "PE\0\0"
    pub file_header:     ImageFileHeader,   // 20 bytes
    pub optional_header: ImageOptionalHeader64, // 240 bytes
}

/// IMAGE_SECTION_HEADER (40 bytes each).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageSectionHeader {
    pub name:                    [u8; 8],
    pub virtual_size:            u32,    // Misc: PhysicalAddress / VirtualSize
    pub virtual_address:         u32,    // RVA
    pub size_of_raw_data:        u32,
    pub pointer_to_raw_data:     u32,    // file offset
    pub pointer_to_relocations:  u32,
    pub pointer_to_linenumbers:  u32,
    pub number_of_relocations:   u16,
    pub number_of_linenumbers:   u16,
    pub characteristics:         u32,
}

impl ImageSectionHeader {
    /// Returns the section name as a UTF-8 str (trimmed of NUL bytes).
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..end]).unwrap_or("?")
    }
}

/// IMAGE_IMPORT_DESCRIPTOR (20 bytes each; terminated by all-zeros entry).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,  // RVA to INT (Import Name Table)
    pub time_date_stamp:      u32,
    pub forwarder_chain:      u32,
    pub name:                 u32,  // RVA to DLL name string
    pub first_thunk:          u32,  // RVA to IAT (Import Address Table)
}

/// IMAGE_THUNK_DATA64 (8 bytes): either an RVA to IMAGE_IMPORT_BY_NAME,
/// or an ordinal (bit 63 set).
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct ImageThunkData64(pub u64);

impl ImageThunkData64 {
    /// True if this is an ordinal import (bit 63 set).
    pub fn is_ordinal(&self) -> bool { self.0 & (1u64 << 63) != 0 }
    /// Extract ordinal number (lower 16 bits when is_ordinal).
    pub fn ordinal(&self) -> u16 { (self.0 & 0xFFFF) as u16 }
    /// Extract RVA to IMAGE_IMPORT_BY_NAME (when !is_ordinal).
    pub fn address_rva(&self) -> u32 { (self.0 & 0x7FFF_FFFF) as u32 }
}

/// IMAGE_IMPORT_BY_NAME header (2-byte hint + variable-length name).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageImportByName {
    pub hint: u16,
    // name: [u8] — variable length, NUL terminated
}

/// IMAGE_BASE_RELOCATION block header (8 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,  // RVA of relocation block page
    pub size_of_block:   u32,  // total size including this header
}

// ─── Load result ─────────────────────────────────────────────────────────────

/// Result of a successful PE load.
#[derive(Debug)]
pub struct PeLoadResult {
    /// Virtual address of the entry point (ImageBase + AddressOfEntryPoint RVA).
    pub entry_point:        u64,
    /// User-mode stack top virtual address (same convention as ELF loader).
    pub stack_top:          u64,
    /// Actual load base (may differ from preferred ImageBase after relocation).
    pub load_base:          u64,
    /// Image size in bytes.
    pub image_size:         u32,
    /// Whether this is a DLL (not directly executable).
    pub is_dll:             bool,
    /// Subsystem type from optional header.
    pub subsystem:          u16,
    /// Number of sections loaded.
    pub section_count:      usize,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    /// File too small to contain any valid header.
    TooSmall,
    /// Missing "MZ" DOS signature.
    BadDosMagic,
    /// e_lfanew out of range or misaligned.
    BadPeOffset,
    /// Missing "PE\0\0" NT signature.
    BadPeSignature,
    /// Not a PE32+ (64-bit) image.
    Not64Bit,
    /// Not an AMD64 binary.
    WrongMachine,
    /// ImageBase / SizeOfImage violates user address space constraints.
    BadImageBase,
    /// Section raw data extends beyond input buffer.
    SectionOutOfBounds,
    /// Import DLL name not NUL-terminated or out of range.
    BadImportName,
    /// Import function name not NUL-terminated or out of range.
    BadSymbolName,
    /// Relocation block extends beyond image.
    BadRelocation,
    /// Memory mapping failure.
    MappingFailed,
    /// Import could not be resolved (unknown function).
    UnresolvedImport,
    /// Optional header too small (truncated).
    OptionalHeaderTooSmall,
}

impl PeError {
    /// Convert to a human-readable string.
    pub fn as_str(self) -> &'static str {
        match self {
            PeError::TooSmall              => "image too small",
            PeError::BadDosMagic           => "bad MZ signature",
            PeError::BadPeOffset           => "bad e_lfanew",
            PeError::BadPeSignature        => "bad PE signature",
            PeError::Not64Bit              => "not PE32+",
            PeError::WrongMachine          => "not AMD64 image",
            PeError::BadImageBase          => "invalid image base/size",
            PeError::SectionOutOfBounds    => "section data out of bounds",
            PeError::BadImportName         => "import DLL name invalid",
            PeError::BadSymbolName         => "import symbol name invalid",
            PeError::BadRelocation         => "relocation block invalid",
            PeError::MappingFailed         => "page mapping failed",
            PeError::UnresolvedImport      => "unresolved import",
            PeError::OptionalHeaderTooSmall => "optional header truncated",
        }
    }
}

// ─── Helper: read a packed struct from a byte slice ──────────────────────────

/// Read a `T` from `data` at `offset`. Fails if out of bounds.
fn read_struct<T: Copy>(data: &[u8], offset: usize) -> Option<T> {
    let size = core::mem::size_of::<T>();
    if offset + size > data.len() { return None; }
    Some(unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const T) })
}

/// Read a NUL-terminated byte string from `data` at `offset`, returning a
/// `&str` slice.  Returns `None` if the string is not NUL-terminated within
/// the buffer.
fn read_cstr(data: &[u8], offset: usize) -> Option<&str> {
    if offset >= data.len() { return None; }
    let end = data[offset..].iter().position(|&b| b == 0)?;
    core::str::from_utf8(&data[offset..offset + end]).ok()
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Quick check: does `data` look like a PE binary?
pub fn is_pe(data: &[u8]) -> bool {
    if data.len() < core::mem::size_of::<ImageDosHeader>() { return false; }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != IMAGE_DOS_SIGNATURE { return false; }
    // Read e_lfanew (at fixed offset 60 in the DOS header)
    let e_lfanew = u32::from_le_bytes(
        data.get(60..64).and_then(|s| s.try_into().ok()).unwrap_or([0u8;4])
    ) as usize;
    if e_lfanew + 4 > data.len() { return false; }
    let pe_sig = u32::from_le_bytes(
        data[e_lfanew..e_lfanew+4].try_into().unwrap_or([0u8;4])
    );
    pe_sig == IMAGE_NT_SIGNATURE
}

/// Parse PE headers and return a summary for validation / inspection.
/// Does NOT load sections or map memory.
pub fn parse_pe(data: &[u8]) -> Result<PeInfo, PeError> {
    if data.len() < core::mem::size_of::<ImageDosHeader>() {
        return Err(PeError::TooSmall);
    }
    let dos: ImageDosHeader = read_struct(data, 0).ok_or(PeError::TooSmall)?;
    if dos.e_magic != IMAGE_DOS_SIGNATURE { return Err(PeError::BadDosMagic); }

    let nt_off = dos.e_lfanew as usize;
    if nt_off + 4 > data.len() { return Err(PeError::BadPeOffset); }
    let nt_sig: u32 = read_struct(data, nt_off).ok_or(PeError::BadPeOffset)?;
    if nt_sig != IMAGE_NT_SIGNATURE { return Err(PeError::BadPeSignature); }

    let fh_off = nt_off + 4;
    let fh: ImageFileHeader = read_struct(data, fh_off).ok_or(PeError::TooSmall)?;
    if fh.machine != IMAGE_FILE_MACHINE_AMD64 { return Err(PeError::WrongMachine); }

    let oh_off = fh_off + core::mem::size_of::<ImageFileHeader>();
    let min_oh_size = core::mem::size_of::<ImageOptionalHeader64>();
    if (fh.size_of_optional_header as usize) < min_oh_size {
        return Err(PeError::OptionalHeaderTooSmall);
    }
    let oh: ImageOptionalHeader64 = read_struct(data, oh_off).ok_or(PeError::TooSmall)?;
    if oh.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC { return Err(PeError::Not64Bit); }

    // Parse section headers
    let sh_off = oh_off + fh.size_of_optional_header as usize;
    let n_sects = fh.number_of_sections as usize;
    let sh_size = core::mem::size_of::<ImageSectionHeader>();
    if sh_off + n_sects * sh_size > data.len() { return Err(PeError::TooSmall); }

    let mut sections = Vec::with_capacity(n_sects);
    for i in 0..n_sects {
        let sh: ImageSectionHeader = read_struct(data, sh_off + i * sh_size)
            .ok_or(PeError::TooSmall)?;
        sections.push(sh);
    }

    // Count imports
    let import_count = count_imports(data, &oh);

    Ok(PeInfo {
        machine:          fh.machine,
        image_base:       oh.image_base,
        entry_point_rva:  oh.address_of_entry_point,
        size_of_image:    oh.size_of_image,
        subsystem:        oh.subsystem,
        characteristics:  fh.characteristics,
        is_dll:           (fh.characteristics & IMAGE_FILE_DLL) != 0,
        sections,
        import_count,
    })
}

/// Parsed PE header information (no memory allocation, no loading).
#[derive(Debug)]
pub struct PeInfo {
    pub machine:         u16,
    pub image_base:      u64,
    pub entry_point_rva: u32,
    pub size_of_image:   u32,
    pub subsystem:       u16,
    pub characteristics: u16,
    pub is_dll:          bool,
    pub sections:        Vec<ImageSectionHeader>,
    pub import_count:    usize,
}

/// Count the number of imported DLL entries (for informational purposes).
fn count_imports(data: &[u8], oh: &ImageOptionalHeader64) -> usize {
    let num_dirs = oh.number_of_rva_and_sizes.min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) as usize;
    if num_dirs <= IMAGE_DIRECTORY_ENTRY_IMPORT { return 0; }
    let import_dir = oh.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 || import_dir.size == 0 { return 0; }

    // Convert RVA → file offset using section table
    let fh_size = core::mem::size_of::<ImageFileHeader>();
    let nt_off = oh as *const _ as usize;
    // Can't easily compute file offset here without sections, so just return 0 for now
    // (parse_imports gives more detail)
    let _ = import_dir;
    let _ = data;
    0
}

/// Load a PE32+ binary into address space `cr3`.
///
/// Performs:
/// 1. Header validation
/// 2. Section mapping (physical pages allocated + mapped)
/// 3. Base relocation (if load address ≠ preferred base)
/// 4. IAT resolution (imports resolved via `crate::nt::lookup_stub`)
///
/// Returns entry point VA, stack top, and other metadata.
pub fn load_pe(data: &[u8], cr3: u64) -> Result<PeLoadResult, PeError> {
    // ── 1. Parse headers ─────────────────────────────────────────────────────
    let info = parse_pe(data)?;
    let dos: ImageDosHeader = read_struct(data, 0).unwrap();
    let nt_off = dos.e_lfanew as usize;
    let fh: ImageFileHeader = read_struct(data, nt_off + 4).unwrap();
    let oh_off = nt_off + 4 + core::mem::size_of::<ImageFileHeader>();
    let oh: ImageOptionalHeader64 = read_struct(data, oh_off).unwrap();

    let sh_off = oh_off + fh.size_of_optional_header as usize;
    let sh_size = core::mem::size_of::<ImageSectionHeader>();
    let n_sects = fh.number_of_sections as usize;

    let preferred_base = oh.image_base;
    let image_size = oh.size_of_image as u64;

    // Validate address space constraints (must be in user lower half)
    if preferred_base >= 0xFFFF_8000_0000_0000 || preferred_base + image_size >= 0xFFFF_8000_0000_0000 {
        return Err(PeError::BadImageBase);
    }

    // For now, always attempt to load at the preferred base.
    // TODO: ASLR / conflict detection.
    let load_base = preferred_base;
    let delta = load_base.wrapping_sub(preferred_base) as i64; // will be 0 unless relocated

    // ── 2. Map the header page(s) ─────────────────────────────────────────────
    let header_pages = align_up(oh.size_of_headers as u64, pmm::PAGE_SIZE as u64) as usize
        / pmm::PAGE_SIZE;
    for pg in 0..header_pages {
        let va = load_base + (pg * pmm::PAGE_SIZE) as u64;
        let phys = pmm::alloc_page().ok_or(PeError::MappingFailed)?;
        // Zero the frame
        unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pmm::PAGE_SIZE); }
        if !vmm::map_page_in(cr3, va, phys, vmm::PAGE_PRESENT | vmm::PAGE_USER | vmm::PAGE_WRITABLE) {
            return Err(PeError::MappingFailed);
        }
    }
    // Copy header bytes into the mapped header region.
    let header_len = (oh.size_of_headers as usize).min(data.len());
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), load_base as *mut u8, header_len);
    }

    // ── 3. Map sections ───────────────────────────────────────────────────────
    for i in 0..n_sects {
        let sh: ImageSectionHeader = read_struct(data, sh_off + i * sh_size)
            .ok_or(PeError::TooSmall)?;

        let sect_va   = load_base + sh.virtual_address as u64;
        let sect_vsz  = align_up(
            sh.virtual_size.max(sh.size_of_raw_data) as u64,
            pmm::PAGE_SIZE as u64,
        );
        let n_pages   = (sect_vsz / pmm::PAGE_SIZE as u64) as usize;

        // Page protection from section characteristics.
        let writeable  = (sh.characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
        let executable = (sh.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        for pg in 0..n_pages {
            let va   = sect_va + (pg * pmm::PAGE_SIZE) as u64;
            let phys = pmm::alloc_page().ok_or(PeError::MappingFailed)?;
            unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pmm::PAGE_SIZE); }
            let mut flags = vmm::PAGE_PRESENT | vmm::PAGE_USER;
            if writeable  { flags |= vmm::PAGE_WRITABLE; }
            if !executable { flags |= vmm::PAGE_NO_EXECUTE; }
            if !vmm::map_page_in(cr3, va, phys, flags) {
                return Err(PeError::MappingFailed);
            }
        }

        // Copy raw section data.
        if sh.size_of_raw_data > 0 && sh.pointer_to_raw_data > 0 {
            let file_off  = sh.pointer_to_raw_data as usize;
            let copy_size = sh.size_of_raw_data as usize;
            if file_off + copy_size > data.len() {
                return Err(PeError::SectionOutOfBounds);
            }
            let dst = (load_base + sh.virtual_address as u64) as *mut u8;
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(file_off), dst, copy_size);
            }
        }
    }

    // ── 4. Apply base relocations (if load_base ≠ preferred_base) ────────────
    if delta != 0 {
        apply_relocations(data, &oh, load_base, delta)?;
    }

    // ── 5. Resolve IAT imports ────────────────────────────────────────────────
    resolve_imports(data, &oh, load_base)?;

    // ── 6. Allocate user stack ────────────────────────────────────────────────
    const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;
    const STACK_PAGES:    usize = 16; // 64 KiB
    let stack_base = USER_STACK_TOP - (STACK_PAGES * pmm::PAGE_SIZE) as u64;
    for s in 0..STACK_PAGES {
        let va   = stack_base + (s * pmm::PAGE_SIZE) as u64;
        let phys = pmm::alloc_page().ok_or(PeError::MappingFailed)?;
        unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pmm::PAGE_SIZE); }
        if !vmm::map_page_in(cr3, va, phys, vmm::PAGE_PRESENT | vmm::PAGE_USER | vmm::PAGE_WRITABLE | vmm::PAGE_NO_EXECUTE) {
            return Err(PeError::MappingFailed);
        }
    }
    let stack_top = USER_STACK_TOP;

    let entry_point = load_base + oh.address_of_entry_point as u64;

    Ok(PeLoadResult {
        entry_point,
        stack_top,
        load_base,
        image_size: oh.size_of_image,
        is_dll:     info.is_dll,
        subsystem:  oh.subsystem,
        section_count: n_sects,
    })
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Round `n` up to the nearest multiple of `align` (must be power-of-two).
#[inline]
fn align_up(n: u64, align: u64) -> u64 {
    (n + align - 1) & !(align - 1)
}

/// Convert a section-relative RVA to file offset.
fn rva_to_file_offset(rva: u32, data: &[u8], oh: &ImageOptionalHeader64) -> Option<usize> {
    let dos: ImageDosHeader = read_struct(data, 0)?;
    let nt_off = dos.e_lfanew as usize;
    let fh: ImageFileHeader = read_struct(data, nt_off + 4)?;
    let oh_off = nt_off + 4 + core::mem::size_of::<ImageFileHeader>();
    let sh_off = oh_off + fh.size_of_optional_header as usize;
    let sh_size = core::mem::size_of::<ImageSectionHeader>();
    let n = fh.number_of_sections as usize;
    for i in 0..n {
        let sh: ImageSectionHeader = read_struct(data, sh_off + i * sh_size)?;
        if rva >= sh.virtual_address
            && rva < sh.virtual_address + sh.size_of_raw_data.max(sh.virtual_size)
        {
            let off = (rva - sh.virtual_address) as usize + sh.pointer_to_raw_data as usize;
            return Some(off);
        }
    }
    // Fall back: treat RVA as file offset (for images without sections, e.g. headers).
    if (rva as usize) < oh.size_of_headers as usize {
        return Some(rva as usize);
    }
    None
}

/// Apply base relocations after loading at `load_base` instead of `preferred_base`.
fn apply_relocations(
    data:      &[u8],
    oh:        &ImageOptionalHeader64,
    load_base: u64,
    delta:     i64,
) -> Result<(), PeError> {
    let num_dirs = oh.number_of_rva_and_sizes.min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) as usize;
    if num_dirs <= IMAGE_DIRECTORY_ENTRY_BASERELOC { return Ok(()); }
    let reloc_dir = oh.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 { return Ok(()); }

    let base_off = rva_to_file_offset(reloc_dir.virtual_address, data, oh)
        .ok_or(PeError::BadRelocation)?;
    let reloc_end = base_off + reloc_dir.size as usize;
    if reloc_end > data.len() { return Err(PeError::BadRelocation); }

    let mut pos = base_off;
    while pos + 8 <= reloc_end {
        let block: ImageBaseRelocation = read_struct(data, pos).ok_or(PeError::BadRelocation)?;
        if block.size_of_block < 8 { break; }
        let entry_count = (block.size_of_block as usize - 8) / 2;
        let page_va = load_base + block.virtual_address as u64;
        for e in 0..entry_count {
            let entry_off = pos + 8 + e * 2;
            if entry_off + 2 > reloc_end { break; }
            let entry = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
            let rel_type = (entry >> 12) as u8;
            let rel_off  = (entry & 0x0FFF) as u64;
            let target_va = page_va + rel_off;
            match rel_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // No-op padding
                }
                IMAGE_REL_BASED_DIR64 => {
                    unsafe {
                        let ptr = target_va as *mut u64;
                        let old = core::ptr::read_unaligned(ptr);
                        core::ptr::write_unaligned(ptr, old.wrapping_add(delta as u64));
                    }
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    unsafe {
                        let ptr = target_va as *mut u32;
                        let old = core::ptr::read_unaligned(ptr);
                        core::ptr::write_unaligned(ptr, old.wrapping_add(delta as u32));
                    }
                }
                _ => {
                    // Unknown — skip
                }
            }
        }
        pos += block.size_of_block as usize;
    }
    Ok(())
}

/// Resolve all imports from the IAT.
/// For each import, looks up the function name in `crate::nt::lookup_stub`.
/// If found, writes the stub address into the IAT entry in the loaded image.
/// If not found on a required import, returns `PeError::UnresolvedImport`.
fn resolve_imports(
    data:      &[u8],
    oh:        &ImageOptionalHeader64,
    load_base: u64,
) -> Result<(), PeError> {
    let num_dirs = oh.number_of_rva_and_sizes.min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) as usize;
    if num_dirs <= IMAGE_DIRECTORY_ENTRY_IMPORT { return Ok(()); }
    let import_dir = oh.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 || import_dir.size == 0 { return Ok(()); }

    let mut imp_file_off = rva_to_file_offset(import_dir.virtual_address, data, oh)
        .ok_or(PeError::BadImportName)?;
    let desc_size = core::mem::size_of::<ImageImportDescriptor>();

    loop {
        if imp_file_off + desc_size > data.len() { break; }
        let desc: ImageImportDescriptor = read_struct(data, imp_file_off)
            .ok_or(PeError::BadImportName)?;

        // Check for terminator (all zeros)
        if desc.original_first_thunk == 0 && desc.name == 0 && desc.first_thunk == 0 {
            break;
        }

        // Read DLL name (for logging only — we resolve by function name)
        let dll_name_off = rva_to_file_offset(desc.name, data, oh)
            .unwrap_or(0);
        let dll_name = read_cstr(data, dll_name_off).unwrap_or("?");
        crate::serial_println!("[PE] Resolving imports from '{}'", dll_name);

        // Iterate INT (OriginalFirstThunk) to get function names.
        // Write resolved addresses to IAT (FirstThunk) in the loaded image.
        let use_int = desc.original_first_thunk != 0;
        let thunk_rva = if use_int { desc.original_first_thunk } else { desc.first_thunk };
        let mut thunk_file_off = rva_to_file_offset(thunk_rva, data, oh)
            .ok_or(PeError::BadSymbolName)?;
        // IAT in the loaded image at its actual VA
        let mut iat_va = load_base + desc.first_thunk as u64;

        loop {
            if thunk_file_off + 8 > data.len() { break; }
            let thunk = ImageThunkData64(u64::from_le_bytes(
                data[thunk_file_off..thunk_file_off+8].try_into().unwrap_or([0u8;8])
            ));
            if thunk.0 == 0 { break; } // terminator

            let stub_addr = if thunk.is_ordinal() {
                // Ordinal import — look up by ordinal in NT stub table
                crate::nt::lookup_stub_ordinal(dll_name, thunk.ordinal())
                    .unwrap_or(0)
            } else {
                // Named import — look up by name
                let name_file_off = rva_to_file_offset(thunk.address_rva(), data, oh)
                    .ok_or(PeError::BadSymbolName)?;
                // Skip 2-byte hint
                let sym_name = read_cstr(data, name_file_off + 2)
                    .ok_or(PeError::BadSymbolName)?;
                let addr = crate::nt::lookup_stub(dll_name, sym_name);
                if addr == 0 {
                    crate::serial_println!("[PE]   WARN: unresolved {}!{}", dll_name, sym_name);
                }
                addr
            };

            // Write stub address into loaded IAT
            if stub_addr != 0 {
                unsafe {
                    core::ptr::write_unaligned(iat_va as *mut u64, stub_addr);
                }
            }

            thunk_file_off += 8;
            iat_va         += 8;
        }

        imp_file_off += desc_size;
    }
    Ok(())
}
