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

    /// Create a VmSpace that uses an existing CR3 (e.g., for vfork children
    /// that share the parent's page tables but need their own VMA tracking).
    pub fn from_existing_cr3(cr3: u64) -> Self {
        Self {
            cr3,
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
        // Higher-half physical-to-virtual offset — same as vmm::PHYS_OFF.
        // We use this instead of raw physical pointers so that accesses go
        // through the stable kernel higher-half mapping (PML4[256-511]) rather
        // than the identity map (PML4[0]), which can be split/modified by user
        // mmap() calls after a process has been running for a while.
        const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

        let new_pml4 = crate::mm::pmm::alloc_page()?;

        // Zero the entire PML4 via the higher-half mapping.
        unsafe {
            core::ptr::write_bytes((PHYS_OFF + new_pml4) as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
        }

        // Clone kernel-half entries (256-511) from the current PML4.
        // These are shallow copies and share the same underlying page tables
        // (kernel mappings are identical across all processes).
        let current_cr3 = crate::mm::vmm::get_cr3();
        unsafe {
            let src = (PHYS_OFF + current_cr3) as *const u64;
            let dst = (PHYS_OFF + new_pml4) as *mut u64;
            for i in 256..512 {
                *dst.add(i) = *src.add(i);
            }
        }

        // PML4[0] (user virtual address space, 0x0 – 0x7FFF_FFFF_FFFF) starts
        // completely empty.  map_page_in() will allocate PDPT/PD/PT pages as
        // needed when user ELF segments and anonymous regions are mapped.
        //
        // NOTE: do NOT copy the kernel's PML4[0] identity map here.  The kernel
        // identity map includes the first 4 GiB (physical == virtual for 0..4 GiB),
        // which means address 0x0 would be present in every user process.  That
        // allows a NULL function-pointer call to execute code from physical address
        // 0x0 (BIOS area) instead of faulting cleanly.
        //
        // The kernel always uses PHYS_OFF (0xFFFF_8000_0000_0000 + phys) for its
        // own memory accesses, so PML4[0] is not needed by any kernel subsystem
        // after the higher-half switch.

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
    /// `actual_cr3` must be the process's real running CR3 (from `proc.cr3` in
    /// the process table).  `self.cr3` may be stale if `proc.cr3` was updated
    /// (e.g. by exec) without a corresponding update to the VmSpace.
    ///
    /// Walks `actual_cr3`'s page tables directly (PML4[0..256] → PDPT → PD → PT),
    /// allocating fresh PT structures for the child at each level.  Every present
    /// 4 KB PTE is write-protected in the parent and mirrored read-only in the
    /// child; the page fault handler performs the actual physical copy on write.
    ///
    /// Also syncs `self.cr3 = actual_cr3` so subsequent VmSpace operations
    /// (demand-paging, CoW handling) use the correct page tables.
    pub fn clone_for_fork(&mut self, actual_cr3: u64) -> Option<Self> {
        use crate::mm::vmm::{PAGE_PRESENT, PAGE_WRITABLE, PAGE_HUGE, ADDR_MASK};
        use crate::mm::pmm;
        use crate::mm::refcount::page_ref_inc;

        const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

        let hw_cr3: u64;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) hw_cr3, options(nomem, nostack)); }

        // Sync self.cr3 to actual_cr3 so future VmSpace ops are consistent.
        // Log if there was a discrepancy (helps diagnose root cause).
        if self.cr3 != actual_cr3 {
            crate::serial_println!(
                "[FORK-COW] WARN: vm_space.cr3={:#x} != actual_cr3={:#x} (hw_cr3={:#x}); syncing",
                self.cr3, actual_cr3, hw_cr3
            );
            self.cr3 = actual_cr3;
        }

        crate::serial_println!("[FORK-COW] clone_for_fork START cr3={:#x} hw_cr3={:#x} vmas={}", actual_cr3, hw_cr3, self.areas.len());
        for vma in &self.areas {
            crate::serial_println!("[FORK-COW]   VMA [{:#x}..{:#x}) prot={:#x} flags={:#x} {:?}", vma.base, vma.base + vma.length, vma.prot, vma.flags, vma.backing);
        }

        // Allocate a fresh, zeroed PML4 for the child.
        let child_pml4_phys = match pmm::alloc_page() {
            Some(p) => p,
            None => { crate::serial_println!("[FORK-COW] alloc_page failed for child PML4 (OOM)"); return None; }
        };
        unsafe {
            core::ptr::write_bytes((PHYS_OFF + child_pml4_phys) as *mut u8, 0, 4096);
        }

        // Copy kernel-half (PML4 entries 256-511) from actual_cr3 — these are
        // shallow shared entries identical across all processes.
        unsafe {
            let src = (PHYS_OFF + actual_cr3) as *const u64;
            let dst = (PHYS_OFF + child_pml4_phys) as *mut u64;
            for i in 256..512usize {
                *dst.add(i) = *src.add(i);
            }
        }

        // Walk parent's user page tables (PML4[0..256]).
        // At each level allocate a fresh table for the child so the child's
        // PD/PT pages are never shared with the parent's.
        let mut total_pages_cow: u64 = 0;
        unsafe {
            let parent_pml4 = (PHYS_OFF + actual_cr3) as *mut u64;
            let child_pml4  = (PHYS_OFF + child_pml4_phys) as *mut u64;

            for pml4_idx in 0..256usize {
                let pml4e = *parent_pml4.add(pml4_idx);
                if pml4e & PAGE_PRESENT == 0 { continue; }
                crate::serial_println!("[FORK-COW] PML4[{}] present (phys={:#x})", pml4_idx, pml4e & ADDR_MASK);

                let parent_pdpt_phys = pml4e & ADDR_MASK;

                // Fresh PDPT for child.
                let child_pdpt_phys = pmm::alloc_page()?;
                core::ptr::write_bytes((PHYS_OFF + child_pdpt_phys) as *mut u8, 0, 4096);
                *child_pml4.add(pml4_idx) = child_pdpt_phys | (pml4e & !ADDR_MASK);

                let parent_pdpt = (PHYS_OFF + parent_pdpt_phys) as *mut u64;
                let child_pdpt  = (PHYS_OFF + child_pdpt_phys)  as *mut u64;

                for pdpt_idx in 0..512usize {
                    let pdpte = *parent_pdpt.add(pdpt_idx);
                    if pdpte & PAGE_PRESENT == 0 { continue; }

                    // 1 GB huge page — write-protect in both, no CoW split.
                    if pdpte & PAGE_HUGE != 0 {
                        let flags_ro = (pdpte & !ADDR_MASK) & !PAGE_WRITABLE;
                        let phys_1g  = pdpte & !0x3FFF_FFFFu64;
                        *parent_pdpt.add(pdpt_idx) = phys_1g | flags_ro;
                        *child_pdpt .add(pdpt_idx) = phys_1g | flags_ro;
                        continue;
                    }

                    let parent_pd_phys = pdpte & ADDR_MASK;

                    // Fresh PD for child.
                    let child_pd_phys = pmm::alloc_page()?;
                    core::ptr::write_bytes((PHYS_OFF + child_pd_phys) as *mut u8, 0, 4096);
                    *child_pdpt.add(pdpt_idx) = child_pd_phys | (pdpte & !ADDR_MASK);

                    let parent_pd = (PHYS_OFF + parent_pd_phys) as *mut u64;
                    let child_pd  = (PHYS_OFF + child_pd_phys)  as *mut u64;

                    for pd_idx in 0..512usize {
                        let pde = *parent_pd.add(pd_idx);
                        if pde & PAGE_PRESENT == 0 { continue; }

                        // 2 MB huge page — write-protect in both and ref-count sub-pages.
                        if pde & PAGE_HUGE != 0 {
                            let phys_2m     = pde & 0x000F_FFFF_FFE0_0000u64;
                            let flags_ro    = (pde & !ADDR_MASK) & !PAGE_WRITABLE;
                            *parent_pd.add(pd_idx) = phys_2m | flags_ro;
                            *child_pd .add(pd_idx) = phys_2m | flags_ro;
                            for sub in 0..512u64 {
                                page_ref_inc(phys_2m + sub * 0x1000);
                            }
                            continue;
                        }

                        let parent_pt_phys = pde & ADDR_MASK;

                        // Fresh PT for child.
                        let child_pt_phys = pmm::alloc_page()?;
                        core::ptr::write_bytes((PHYS_OFF + child_pt_phys) as *mut u8, 0, 4096);
                        *child_pd.add(pd_idx) = child_pt_phys | (pde & !ADDR_MASK);

                        let parent_pt = (PHYS_OFF + parent_pt_phys) as *mut u64;
                        let child_pt  = (PHYS_OFF + child_pt_phys)  as *mut u64;

                        for pt_idx in 0..512usize {
                            let pte = *parent_pt.add(pt_idx);
                            if pte & PAGE_PRESENT == 0 { continue; }

                            let phys       = pte & ADDR_MASK;
                            let flags_ro   = (pte & !ADDR_MASK) & !PAGE_WRITABLE;

                            // Write-protect parent PTE in place.
                            *parent_pt.add(pt_idx) = phys | flags_ro;

                            // Child PTE: same physical page, read-only.
                            *child_pt.add(pt_idx) = phys | flags_ro;

                            // Keep page alive until both mappings are gone.
                            page_ref_inc(phys);
                            total_pages_cow += 1;
                        }
                    }
                }
            }
        }

        // Flush TLB: parent PTEs were write-protected so stale entries must
        // be evicted so the next write triggers a CoW page fault.
        crate::mm::vmm::flush_tlb();
        crate::serial_println!("[FORK-COW] total {} 4KB pages CoW'd into child CR3={:#x}", total_pages_cow, child_pml4_phys);

        // Copy VMA list to child.
        let mut child_areas = Vec::with_capacity(self.areas.len());
        for vma in &self.areas {
            child_areas.push(vma.clone());
        }

        Some(VmSpace {
            cr3: child_pml4_phys,
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
    ///
    /// For file-backed VMAs, split pieces have their backing offset adjusted so
    /// that each piece still maps the correct portion of the file.  Without this
    /// adjustment, glibc's ld-linux (which uses an initial PROT_READ file-backed
    /// reservation to reserve the full library span, then overwrites individual
    /// segments with MAP_FIXED) would read stale/wrong file data from the
    /// remnant reservation pages, corrupting its internal load-address
    /// structures and producing garbage mprotect/relocation addresses.
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
                // Range punches a hole in the middle — split into two pieces.
                // The right piece starts at `end`, which is `end - vma.base`
                // bytes into the original VMA.  For file-backed VMAs the
                // backing offset of the right piece must be advanced by that
                // same delta so page faults still read from the correct file
                // position.
                let right_delta = end - vma.base;
                let left = VmArea {
                    base: vma.base,
                    length: base - vma.base,
                    prot: vma.prot,
                    flags: vma.flags,
                    backing: vma.backing.clone(),   // left piece: offset unchanged
                    name: vma.name,
                };
                let right_backing = match &vma.backing {
                    VmBacking::File { mount_idx, inode, offset } => VmBacking::File {
                        mount_idx: *mount_idx,
                        inode: *inode,
                        offset: offset + right_delta,
                    },
                    other => other.clone(),
                };
                let right = VmArea {
                    base: end,
                    length: vma.end() - end,
                    prot: vma.prot,
                    flags: vma.flags,
                    backing: right_backing,
                    name: vma.name,
                };
                self.areas.remove(i);
                self.areas.insert(i, right);
                self.areas.insert(i, left);
                i += 2;
                continue;
            }

            if vma.base < base {
                // Overlap on the right side — shrink (left portion kept).
                // The kept portion starts at vma.base with unchanged offset.
                let mut vma = self.areas.remove(i);
                vma.length = base - vma.base;
                self.areas.insert(i, vma);
                i += 1;
                continue;
            }

            // Overlap on the left side — shrink from left.
            // The kept portion starts at `end`, which is `end - old_base`
            // bytes into the original VMA.  Advance the file offset accordingly.
            let mut vma = self.areas.remove(i);
            let old_base = vma.base;
            let left_delta = end - old_base;
            if let VmBacking::File { offset, .. } = &mut vma.backing {
                *offset += left_delta;
            }
            vma.base = end;
            vma.length -= left_delta;
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
