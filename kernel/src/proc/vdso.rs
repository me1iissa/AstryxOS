//! vDSO — virtual Dynamic Shared Object
//!
//! Maps a small position-independent shared object into every user process
//! address space so that glibc / musl can call clock_gettime, gettimeofday,
//! time, and getcpu without a full syscall round-trip.
//!
//! # v1 design
//! All four vDSO functions fall back to the real syscall.  The shared-memory
//! fast path (kernel writes a timestamp page, vDSO reads it locklessly) is
//! deferred to a follow-up.  This is the correct Linux fallback behaviour and
//! is sufficient for glibc's vDSO probe to succeed.
//!
//! # Memory layout
//! The vDSO image is page-aligned.  We round its size up to a whole number of
//! pages, allocate fresh physical pages, copy the bytes in, mark R+X, and
//! register a VMA named "[vdso]".
//!
//! The virtual address chosen (VDSO_BASE) is placed just below the interpreter
//! load base (INTERP_BASE = 0x7F00_0000_0000), leaving plenty of room in the
//! lower half.
//!
//! # AT_SYSINFO_EHDR
//! We record the mapped vDSO base in ElfLoadResult.vdso_base.  The ELF
//! loader adds AT_SYSINFO_EHDR pointing at it before handing off to
//! setup_user_stack() so the value lands in both the initial stack auxvec
//! and the /proc/self/auxv snapshot.

extern crate alloc;

use alloc::vec::Vec;
use crate::mm::{pmm, vmm};
use crate::mm::vma::{VmArea, VmBacking, MAP_PRIVATE, PROT_READ, PROT_EXEC};

/// Embedded vDSO ELF image produced at build time by kernel/build.rs.
///
/// The build script compiles kernel/vdso/vdso.c into a position-independent
/// shared object and places it at OUT_DIR/vdso.so.  We embed it here as a
/// static byte array so no file I/O is needed at load time.
static VDSO_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vdso.so"));

/// Virtual address at which the vDSO is mapped in every user process.
///
/// Located 4 MiB below the interpreter base (0x7F00_0000_0000) so there is
/// no overlap with either the interpreter or the stack.  The 4 MiB gap is
/// large enough for the interpreter's BSS to expand without colliding.
pub const VDSO_BASE: u64 = 0x7EFF_C000_0000;

/// Map the vDSO into the address space described by `cr3`.
///
/// Allocates ceil(VDSO_IMAGE.len() / PAGE_SIZE) physical pages, copies the
/// vDSO bytes in, marks the pages Present + User + (no write) + Execute, and
/// returns:
///   - the list of physical pages (to be freed on process exit alongside the
///     normal allocated_pages vec),
///   - a VmArea describing the mapping (name "[vdso]", PROT_READ|EXEC), and
///   - the virtual base address (always VDSO_BASE).
///
/// Returns `None` if physical memory is exhausted.
///
/// # Safety
/// `cr3` must point to a valid, kernel-mapped PML4.
pub fn map_vdso(
    cr3: u64,
    allocated_pages: &mut Vec<u64>,
    vmas: &mut Vec<VmArea>,
) -> Option<u64> {
    let image = VDSO_IMAGE;
    let image_len = image.len();

    // Round size up to a whole number of pages.
    let n_pages = (image_len + pmm::PAGE_SIZE - 1) / pmm::PAGE_SIZE;
    let mapped_len = n_pages * pmm::PAGE_SIZE;

    let vdso_virt_base = VDSO_BASE;

    // Allocate and fill pages.
    for i in 0..n_pages {
        let phys = pmm::alloc_page()?;

        // Zero the page first (handles the last partial page correctly).
        // SAFETY: phys is a freshly allocated PMM page, directly mapped.
        unsafe {
            core::ptr::write_bytes(phys_to_virt(phys), 0, pmm::PAGE_SIZE);
        }

        // Copy the relevant slice of the vDSO image into this page.
        let src_start = i * pmm::PAGE_SIZE;
        let src_end = (src_start + pmm::PAGE_SIZE).min(image_len);
        if src_start < image_len {
            let dst = unsafe {
                core::slice::from_raw_parts_mut(
                    phys_to_virt(phys),
                    src_end - src_start,
                )
            };
            dst.copy_from_slice(&image[src_start..src_end]);
        }

        let page_vaddr = vdso_virt_base + (i * pmm::PAGE_SIZE) as u64;

        // Map R+X, no write.
        // PAGE_NO_EXECUTE is NOT set so the vDSO code is executable.
        let flags = vmm::PAGE_PRESENT | vmm::PAGE_USER;
        if !vmm::map_page_in(cr3, page_vaddr, phys, flags) {
            // Mapping failed — free this page and all previously allocated ones.
            pmm::free_page(phys);
            // Callers must free allocated_pages on any error path; we push
            // pages we successfully allocated before returning None so
            // the caller's cleanup loop catches them.
            return None;
        }

        // Track refcount so the page is freed correctly on exit.
        crate::mm::refcount::page_ref_set(phys, 1);
        allocated_pages.push(phys);
    }

    // Register a single VMA covering the entire vDSO mapping.
    vmas.push(VmArea {
        base:    vdso_virt_base,
        length:  mapped_len as u64,
        prot:    PROT_READ | PROT_EXEC,
        flags:   MAP_PRIVATE,
        backing: VmBacking::Anonymous,
        name:    "[vdso]",
    });

    crate::serial_println!(
        "[vDSO] mapped {} bytes ({} pages) at {:#x}",
        image_len, n_pages, vdso_virt_base
    );

    Some(vdso_virt_base)
}

/// Convert a physical address to its kernel direct-map virtual address.
/// Mirrors the same helper in elf.rs — duplicated here to keep this module
/// self-contained without introducing a cross-module dependency on a private fn.
#[inline(always)]
fn phys_to_virt(phys: u64) -> *mut u8 {
    (0xFFFF_8000_0000_0000u64 + phys) as *mut u8
}

/// Return the size of the embedded vDSO image (for tests).
pub fn vdso_image_size() -> usize {
    VDSO_IMAGE.len()
}

/// AT_SYSINFO_EHDR auxvec type constant (= 33 per Linux UAPI).
pub const AT_SYSINFO_EHDR: u64 = 33;
