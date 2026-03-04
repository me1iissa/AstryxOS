//! Virtual Memory Area (VMA) Management
//!
//! Tracks virtual memory regions for each process's address space.
//! Each VMA describes a contiguous range of virtual pages with uniform
//! protection and backing.
//!
//! # Design
//! - `VmArea` — A single contiguous virtual memory region.
//! - `VmSpace` — Per-process virtual address space (owns a CR3 + VMA list).
//! - Operations: find, insert, remove, split, merge, page fault handling.
//!
//! VMAs are kept sorted by base address in a `Vec<VmArea>`. For the small
//! VMA counts typical of early OS use (<100), linear search is acceptable.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// VMA protection flags (mmap-compatible).
pub type VmProt = u32;
/// Page is readable.
pub const PROT_READ: VmProt = 1 << 0;
/// Page is writable.
pub const PROT_WRITE: VmProt = 1 << 1;
/// Page is executable.
pub const PROT_EXEC: VmProt = 1 << 2;
/// No access (guard page).
pub const PROT_NONE: VmProt = 0;

/// VMA mapping flags (mmap-compatible).
pub type VmFlags = u32;
/// Mapping is shared (writes visible to other mappers).
pub const MAP_SHARED: VmFlags = 1 << 0;
/// Mapping is private (copy-on-write).
pub const MAP_PRIVATE: VmFlags = 1 << 1;
/// Map at a fixed address (don't auto-pick).
pub const MAP_FIXED: VmFlags = 1 << 4;
/// Anonymous mapping (not file-backed).
pub const MAP_ANONYMOUS: VmFlags = 1 << 5;
/// Stack region (grows downward).
pub const MAP_STACK: VmFlags = 1 << 17;

/// What backs a VMA's pages.
#[derive(Debug, Clone)]
pub enum VmBacking {
    /// Anonymous memory (zero-filled on first access).
    Anonymous,
    /// File-backed mapping (inode + mount index + file offset).
    File {
        mount_idx: usize,
        inode: u64,
        offset: u64,
    },
    /// Device memory (framebuffer, MMIO) — never swapped, identity-mapped.
    Device {
        phys_base: u64,
    },
}

/// A Virtual Memory Area — one contiguous region in a process's address space.
#[derive(Clone)]
pub struct VmArea {
    /// Start virtual address (page-aligned).
    pub base: u64,
    /// Length in bytes (page-aligned).
    pub length: u64,
    /// Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC).
    pub prot: VmProt,
    /// Mapping flags (MAP_PRIVATE, MAP_SHARED, MAP_ANONYMOUS, etc.).
    pub flags: VmFlags,
    /// What backs this VMA.
    pub backing: VmBacking,
    /// Human-readable label for debugging (e.g., "[heap]", "[stack]", "libc.so").
    pub name: &'static str,
}

impl VmArea {
    /// End address (exclusive).
    pub fn end(&self) -> u64 {
        self.base + self.length
    }

    /// Check if a virtual address falls within this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Check if this VMA overlaps with a given range [base, base+length).
    pub fn overlaps(&self, base: u64, length: u64) -> bool {
        self.base < base + length && base < self.end()
    }

    /// Convert VMA protection flags to x86_64 page table flags.
    pub fn to_page_flags(&self) -> u64 {
        use crate::mm::vmm;
        let mut flags = vmm::PAGE_PRESENT;
        if self.prot & PROT_WRITE != 0 {
            flags |= vmm::PAGE_WRITABLE;
        }
        if self.prot & PROT_EXEC == 0 {
            flags |= vmm::PAGE_NO_EXECUTE;
        }
        // User-space VMAs get PAGE_USER
        if self.base < 0x0000_8000_0000_0000 {
            flags |= vmm::PAGE_USER;
        }
        flags
    }
}

impl fmt::Debug for VmArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prot_str = [
            if self.prot & PROT_READ != 0 { 'r' } else { '-' },
            if self.prot & PROT_WRITE != 0 { 'w' } else { '-' },
            if self.prot & PROT_EXEC != 0 { 'x' } else { '-' },
        ];
        write!(
            f,
            "VMA {:#018x}-{:#018x} {}{}{} {}",
            self.base,
            self.end(),
            prot_str[0],
            prot_str[1],
            prot_str[2],
            self.name,
        )
    }
}

// ============================================================================
// VmSpace — Per-Process Virtual Address Space
// ============================================================================

/// A process's virtual address space: a CR3 + collection of VMAs.
pub struct VmSpace {
    /// Physical address of the PML4 page table root.
    pub cr3: u64,
    /// Sorted list of VMAs (by base address, non-overlapping).
    pub areas: Vec<VmArea>,
    /// Next hint address for mmap auto-placement.
    pub mmap_hint: u64,
    /// Program break (end of the heap segment).
    pub brk: u64,
    /// Start of the heap segment.
    pub brk_start: u64,
}

/// Default user-space mmap starting address.
const MMAP_BASE: u64 = 0x0000_7F00_0000_0000;

/// Default user-space heap start.
const HEAP_BASE: u64 = 0x0000_0040_0000_0000;

impl VmSpace {
    /// Create a new empty address space for a kernel process (shares kernel CR3).
    pub fn new_kernel() -> Self {
        Self {
            cr3: crate::mm::vmm::get_cr3(),
            areas: Vec::new(),
            mmap_hint: MMAP_BASE,
            brk: HEAP_BASE,
            brk_start: HEAP_BASE,
        }
    }

    /// Create a new user address space with its own PML4.
    ///
    /// The new PML4 clones the kernel-half (entries 256-511) from the current CR3,
    /// ensuring the kernel is always mapped. It also deep-clones PML4 entry 0
    /// (the identity map of the first 4 GiB) so that kernel code, kernel stacks,
    /// and page-table data remain accessible when CR3 is switched to this table.
    /// The deep clone creates private copies of the PDPT and PD levels so that
    /// per-process modifications (e.g., splitting a 2 MiB huge page to overlay
    /// user ELF segments) don't affect the kernel's own page tables.
    pub fn new_user() -> Option<Self> {
        let new_pml4 = crate::mm::pmm::alloc_page()?;

        // Zero the entire PML4
        unsafe {
            core::ptr::write_bytes(new_pml4 as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
        }

        // Clone kernel-half entries (256-511) from the current PML4.
        // These are shallow copies and share the same underlying page tables
        // (kernel mappings are identical across all processes).
        let current_cr3 = crate::mm::vmm::get_cr3();
        unsafe {
            let src = current_cr3 as *const u64;
            let dst = new_pml4 as *mut u64;
            for i in 256..512 {
                *dst.add(i) = *src.add(i);
            }
        }

        // Deep-clone PML4 entry 0 (identity map of the first 4 GiB).
        // We create private copies of the PDPT and PD tables so that
        // map_page_in can split 2 MiB huge pages for user mappings
        // without affecting the kernel's page tables.
        unsafe {
            let src_pml4 = current_cr3 as *const u64;
            let pml4_entry0 = *src_pml4.add(0);
            if pml4_entry0 & crate::mm::vmm::PAGE_PRESENT != 0 {
                let src_pdpt = (pml4_entry0 & crate::mm::vmm::ADDR_MASK) as *const u64;

                // Allocate a new PDPT page for this process.
                let new_pdpt = crate::mm::pmm::alloc_page()?;
                core::ptr::write_bytes(new_pdpt as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
                let dst_pdpt = new_pdpt as *mut u64;

                // Copy each PDPT entry, deep-cloning any PD it references.
                for pdpt_idx in 0..512 {
                    let pdpt_entry = *src_pdpt.add(pdpt_idx);
                    if pdpt_entry & crate::mm::vmm::PAGE_PRESENT == 0 {
                        continue;
                    }
                    // 1 GiB huge page — just copy as-is (rare, usually only PDs)
                    if pdpt_entry & crate::mm::vmm::PAGE_HUGE != 0 {
                        *dst_pdpt.add(pdpt_idx) = pdpt_entry;
                        continue;
                    }

                    // Clone the PD page.
                    let src_pd = (pdpt_entry & crate::mm::vmm::ADDR_MASK) as *const u64;
                    let new_pd = crate::mm::pmm::alloc_page()?;
                    core::ptr::copy_nonoverlapping(src_pd as *const u8, new_pd as *mut u8, 4096);

                    // Install the cloned PD into our private PDPT,
                    // preserving the original flags.
                    let flags = pdpt_entry & !crate::mm::vmm::ADDR_MASK;
                    *dst_pdpt.add(pdpt_idx) = new_pd | flags;
                }

                // Install the private PDPT into PML4 entry 0.
                let flags0 = pml4_entry0 & !crate::mm::vmm::ADDR_MASK;
                let dst_pml4 = new_pml4 as *mut u64;
                *dst_pml4.add(0) = new_pdpt | flags0;
            }
        }

        Some(Self {
            cr3: new_pml4,
            areas: Vec::new(),
            mmap_hint: MMAP_BASE,
            brk: HEAP_BASE,
            brk_start: HEAP_BASE,
        })
    }

    /// Clone this address space for fork (copy-on-write).
    ///
    /// Creates a new PML4 that shares the same physical pages but marks all
    /// writable user-space pages as read-only in both parent and child.
    /// The page fault handler will implement the actual copy.
    pub fn clone_for_fork(&self) -> Option<Self> {
        use crate::mm::vmm::{read_pte, write_pte, map_page_in, invlpg};
        use crate::mm::vmm::{PAGE_PRESENT, PAGE_WRITABLE};
        use crate::mm::refcount::page_ref_inc;

        const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
        const PAGE_SIZE: u64 = 0x1000;

        let new_space = Self::new_user()?;

        // Walk all user VMAs and set up CoW mappings
        for vma in &self.areas {
            let mut addr = vma.base;
            let end = vma.base + vma.length;
            while addr < end {
                let pte = read_pte(self.cr3, addr);
                if pte & PAGE_PRESENT != 0 {
                    let phys = pte & ADDR_MASK;
                    let flags_no_write = pte & !ADDR_MASK & !PAGE_WRITABLE;

                    // Clear WRITABLE in parent PTE
                    write_pte(self.cr3, addr, (pte & ADDR_MASK) | flags_no_write);
                    invlpg(addr);

                    // Map same physical page in child without WRITABLE
                    map_page_in(new_space.cr3, addr, phys, flags_no_write);

                    // Increment reference count so the page isn't freed prematurely
                    page_ref_inc(phys);
                }
                addr += PAGE_SIZE;
            }
        }

        // Copy VMA list to child
        let mut child_areas = Vec::with_capacity(self.areas.len());
        for vma in &self.areas {
            child_areas.push(vma.clone());
        }

        Some(VmSpace {
            cr3: new_space.cr3,
            areas: child_areas,
            mmap_hint: self.mmap_hint,
            brk: self.brk,
            brk_start: self.brk_start,
        })
    }

    /// Find the VMA containing the given virtual address.
    pub fn find_vma(&self, addr: u64) -> Option<&VmArea> {
        // Binary search would be better for large VMA counts, but linear is
        // fine for < 100 VMAs.
        self.areas.iter().find(|vma| vma.contains(addr))
    }

    /// Find the VMA containing the given virtual address (mutable).
    pub fn find_vma_mut(&mut self, addr: u64) -> Option<&mut VmArea> {
        self.areas.iter_mut().find(|vma| vma.contains(addr))
    }

    /// Insert a new VMA, maintaining sorted order by base address.
    /// Returns an error if the new VMA overlaps with any existing one.
    pub fn insert_vma(&mut self, vma: VmArea) -> Result<(), VmaError> {
        // Check for overlaps
        for existing in &self.areas {
            if existing.overlaps(vma.base, vma.length) {
                return Err(VmaError::Overlap);
            }
        }

        // Find insertion point (sorted by base)
        let pos = self.areas.iter().position(|v| v.base > vma.base)
            .unwrap_or(self.areas.len());
        self.areas.insert(pos, vma);
        Ok(())
    }

    /// Remove all VMAs that overlap with the range [base, base+length).
    /// Partially overlapping VMAs are split or shrunk.
    pub fn remove_range(&mut self, base: u64, length: u64) -> Result<(), VmaError> {
        let end = base + length;
        let mut i = 0;

        while i < self.areas.len() {
            let vma = &self.areas[i];

            if !vma.overlaps(base, length) {
                // No overlap — keep as-is
                i += 1;
                continue;
            }

            if vma.base >= base && vma.end() <= end {
                // Completely contained — remove
                self.areas.remove(i);
                continue;
            }

            if vma.base < base && vma.end() > end {
                // Range punches a hole in the middle — split into two
                let left = VmArea {
                    base: vma.base,
                    length: base - vma.base,
                    prot: vma.prot,
                    flags: vma.flags,
                    backing: vma.backing.clone(),
                    name: vma.name,
                };
                let right = VmArea {
                    base: end,
                    length: vma.end() - end,
                    prot: vma.prot,
                    flags: vma.flags,
                    backing: vma.backing.clone(),
                    name: vma.name,
                };
                self.areas.remove(i);
                self.areas.insert(i, right);
                self.areas.insert(i, left);
                i += 2;
                continue;
            }

            if vma.base < base {
                // Overlap on the right side — shrink
                let mut vma = self.areas.remove(i);
                vma.length = base - vma.base;
                self.areas.insert(i, vma);
                i += 1;
                continue;
            }

            // Overlap on the left side — shrink from left
            let mut vma = self.areas.remove(i);
            let old_base = vma.base;
            vma.base = end;
            vma.length -= end - old_base;
            self.areas.insert(i, vma);
            i += 1;
        }

        Ok(())
    }

    /// Find a free virtual address range of the given size.
    /// Searches from `mmap_hint` downward (top-down allocation like Linux).
    pub fn find_free_range(&self, size: u64) -> Option<u64> {
        let size = page_align_up(size);

        // Try the hint first
        let mut candidate = self.mmap_hint;

        // Simple strategy: walk down from the hint, checking each candidate
        // against existing VMAs.
        for _ in 0..1000 {
            if candidate < size {
                return None; // Ran out of address space
            }

            let base = candidate - size;
            let overlaps = self.areas.iter().any(|vma| vma.overlaps(base, size));
            if !overlaps && base >= 0x1000 {
                // Found a free spot
                return Some(base);
            }

            // Move candidate below the overlapping VMA
            if let Some(vma) = self.areas.iter().rev().find(|v| v.base < candidate && v.end() > base) {
                candidate = vma.base;
            } else {
                candidate -= size;
            }
        }

        None
    }

    /// Adjust the program break (brk syscall).
    ///
    /// If `new_brk` > current brk, expand the heap VMA (or create one).
    /// If `new_brk` < current brk, shrink/unmap pages.
    /// Returns the new brk value.
    pub fn adjust_brk(&mut self, new_brk: u64) -> u64 {
        let new_brk = page_align_up(new_brk);

        if new_brk < self.brk_start {
            return self.brk; // Can't shrink below heap start
        }

        if new_brk == self.brk {
            return self.brk;
        }

        if new_brk > self.brk {
            // Expanding: ensure we have a heap VMA
            if let Some(heap_vma) = self.areas.iter_mut().find(|v| v.name == "[heap]") {
                heap_vma.length = new_brk - heap_vma.base;
            } else {
                // Create the heap VMA
                let heap_vma = VmArea {
                    base: self.brk_start,
                    length: new_brk - self.brk_start,
                    prot: PROT_READ | PROT_WRITE,
                    flags: MAP_PRIVATE | MAP_ANONYMOUS,
                    backing: VmBacking::Anonymous,
                    name: "[heap]",
                };
                let _ = self.insert_vma(heap_vma);
            }
        } else {
            // Shrinking: save old brk before modifying, then unmap freed pages
            let old_brk = self.brk;

            if let Some(heap_vma) = self.areas.iter_mut().find(|v| v.name == "[heap]") {
                if new_brk <= self.brk_start {
                    // Remove the heap VMA entirely
                    self.areas.retain(|v| v.name != "[heap]");
                } else {
                    heap_vma.length = new_brk - heap_vma.base;
                }
            }

            // Unmap pages in [new_brk, old_brk)
            let mut page_addr = new_brk;
            while page_addr < old_brk {
                crate::mm::vmm::unmap_page_in(self.cr3, page_addr);
                crate::mm::vmm::invlpg(page_addr);
                page_addr += 0x1000;
            }
        }

        self.brk = new_brk;
        self.brk
    }

    /// Dump all VMAs for debugging.
    pub fn dump(&self) {
        crate::serial_println!("  VmSpace CR3={:#x}, {} VMAs, brk={:#x}:", self.cr3, self.areas.len(), self.brk);
        for vma in &self.areas {
            crate::serial_println!("    {:?}", vma);
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// VMA operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaError {
    /// The requested range overlaps with an existing VMA.
    Overlap,
    /// Out of virtual address space.
    NoSpace,
    /// Out of physical memory.
    OutOfMemory,
    /// Invalid arguments.
    InvalidArg,
    /// Permission denied.
    PermissionDenied,
}

// ============================================================================
// Helpers
// ============================================================================

/// Align an address up to the next page boundary.
pub fn page_align_up(addr: u64) -> u64 {
    (addr + 0xFFF) & !0xFFF
}

/// Align an address down to the page boundary.
pub fn page_align_down(addr: u64) -> u64 {
    addr & !0xFFF
}
