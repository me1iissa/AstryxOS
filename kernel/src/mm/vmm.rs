//! Virtual Memory Manager (VMM)
//!
//! Manages x86_64 4-level page tables for the Aether kernel.
//! Provides page mapping/unmapping and virtual address space management.
//! Supports both the kernel's page table and per-process page tables.

use super::pmm;
use core::arch::asm;
use spin::Mutex;

/// Page table entry flags.
pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITABLE: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
pub const PAGE_WRITE_THROUGH: u64 = 1 << 3;
pub const PAGE_NO_CACHE: u64 = 1 << 4;
pub const PAGE_HUGE: u64 = 1 << 7;
pub const PAGE_GLOBAL: u64 = 1 << 8;
pub const PAGE_NO_EXECUTE: u64 = 1 << 63;

/// Address mask for page table entries (bits 12-51).
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// VMM lock.
static VMM_LOCK: Mutex<()> = Mutex::new(());

/// The kernel's primary page table CR3, captured during VMM init.
/// Used to restore the CR3 on CPUs that were using a user process's page
/// table when that process exits (e.g. AP idle after a user thread dies).
static KERNEL_CR3: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Return the kernel's primary page table CR3.
/// Returns 0 if VMM has not been initialised yet (safe — callers check != 0).
#[inline]
pub fn get_kernel_cr3() -> u64 {
    KERNEL_CR3.load(core::sync::atomic::Ordering::Relaxed)
}

/// Initialize the VMM.
///
/// 1. Reserves the physical pages that back the higher-half kernel heap
///    (so `alloc_page` never hands them out).
/// 2. Creates independent PD copies for the higher-half mapping
///    (PML4[256]) so that splitting 2 MiB huge pages via the identity
///    map (PML4[0]) for user ELF loading does not corrupt the kernel
///    heap mapping.
pub fn init() {
    // Reserve physical pages that back the higher-half kernel heap.
    // HEAP_START 0xFFFF_8000_0080_0000 → physical 0x0080_0000 (8 MiB).
    // Starting at 8 MiB avoids overlap with the kernel image (ends < 6 MiB).
    // Heap size is 128 MiB.
    let heap_phys_start = 0x0080_0000u64;
    let heap_phys_end = heap_phys_start + (128 * 1024 * 1024) as u64;
    pmm::reserve_range(heap_phys_start, heap_phys_end);

    // Separate the PD pages between the identity map (PML4[0]) and the
    // higher-half map (PML4[256]).  The bootloader sets both PDPTs to
    // share the same PD0-PD3 pages.  Without this separation, splitting
    // a 2 MiB huge page for user ELF loading via the identity map would
    // also corrupt the corresponding higher-half mapping.
    unsafe { separate_higher_half_pds(); }

    // Capture the kernel's page table root so any CPU that departs a user
    // address space can restore to a known-good kernel CR3.
    let cr3: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)); }
    KERNEL_CR3.store(cr3, core::sync::atomic::Ordering::Relaxed);

    crate::serial_println!("[VMM] Virtual memory manager initialized");
}

/// Clone the PD pages under PML4[256] (higher-half) so they are
/// independent of the identity-map PDs under PML4[0].
///
/// # Safety
/// Must be called once during early init, before the heap is used.
unsafe fn separate_higher_half_pds() {
    let cr3 = get_cr3();
    let pml4_ptr = cr3 as *const u64;

    // Read PML4[256] → PDPT_HIGHER
    let pml4_256 = *pml4_ptr.add(256);
    if pml4_256 & PAGE_PRESENT == 0 {
        return;
    }

    let pdpt_phys = pml4_256 & ADDR_MASK;
    let pdpt_ptr = pdpt_phys as *mut u64;

    for i in 0..512 {
        let pdpt_entry = *pdpt_ptr.add(i);
        if pdpt_entry & PAGE_PRESENT == 0 {
            continue;
        }
        // 1 GiB huge page — leave as-is (uncommon in our setup).
        if pdpt_entry & PAGE_HUGE != 0 {
            continue;
        }

        // Allocate a fresh PD page and copy the original contents.
        let old_pd = (pdpt_entry & ADDR_MASK) as *const u8;
        let new_pd = match pmm::alloc_page() {
            Some(p) => p,
            None => {
                crate::serial_println!("[VMM] WARN: cannot alloc PD copy for higher-half");
                return;
            }
        };
        core::ptr::copy_nonoverlapping(old_pd, new_pd as *mut u8, 4096);

        // Update PDPT_HIGHER to point to the cloned PD, preserving flags.
        let flags = pdpt_entry & !ADDR_MASK;
        *pdpt_ptr.add(i) = new_pd | flags;
    }

    // Flush TLB so all higher-half accesses use the new PD pages.
    flush_tlb();
}

/// Get the current PML4 (CR3) physical address.
pub fn get_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: Reading CR3 is safe; it just returns the current page table root.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3 & ADDR_MASK
}

/// Map a virtual page to a physical page.
///
/// # Arguments
/// * `virt_addr` - Virtual address to map (must be page-aligned).
/// * `phys_addr` - Physical address to map to (must be page-aligned).
/// * `flags` - Page table entry flags (PRESENT, WRITABLE, USER, etc.).
///
/// # Returns
/// `true` if the mapping was successful, `false` on failure (e.g., out of memory).
pub fn map_page(virt_addr: u64, phys_addr: u64, flags: u64) -> bool {
    let _lock = VMM_LOCK.lock();

    let pml4_phys = get_cr3();

    // Extract page table indices from virtual address
    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    // SAFETY: We hold the VMM lock. We walk and potentially allocate page table pages.
    unsafe {
        // Walk PML4 -> PDPT
        let pdpt_phys = match get_or_create_entry(pml4_phys, pml4_idx, flags) {
            Some(addr) => addr,
            None => return false,
        };

        // Walk PDPT -> PD
        let pd_phys = match get_or_create_entry(pdpt_phys, pdpt_idx, flags) {
            Some(addr) => addr,
            None => return false,
        };

        // Walk PD -> PT
        let pt_phys = match get_or_create_entry(pd_phys, pd_idx, flags) {
            Some(addr) => addr,
            None => return false,
        };

        // Set the final page table entry
        let pt_ptr = pt_phys as *mut u64;
        let entry_ptr = pt_ptr.add(pt_idx);
        *entry_ptr = (phys_addr & ADDR_MASK) | flags | PAGE_PRESENT;
    }

    true
}

/// Unmap a virtual page.
pub fn unmap_page(virt_addr: u64) {
    let _lock = VMM_LOCK.lock();

    let pml4_phys = get_cr3();

    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    // SAFETY: We hold the VMM lock. Walking page tables to clear an entry.
    unsafe {
        let pml4_ptr = pml4_phys as *const u64;
        let pml4_entry = *pml4_ptr.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 {
            return;
        }

        let pdpt_phys = pml4_entry & ADDR_MASK;
        let pdpt_ptr = pdpt_phys as *const u64;
        let pdpt_entry = *pdpt_ptr.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 {
            return;
        }

        let pd_phys = pdpt_entry & ADDR_MASK;
        let pd_ptr = pd_phys as *const u64;
        let pd_entry = *pd_ptr.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 {
            return;
        }

        let pt_phys = pd_entry & ADDR_MASK;
        let pt_ptr = pt_phys as *mut u64;
        *pt_ptr.add(pt_idx) = 0;

        // Flush TLB for this address
        invlpg(virt_addr);
    }
}

/// Flush a TLB entry for a specific virtual address.
pub fn invlpg(virt_addr: u64) {
    // SAFETY: INVLPG is safe to call; it just invalidates one TLB entry.
    unsafe {
        asm!("invlpg [{}]", in(reg) virt_addr, options(nostack, preserves_flags));
    }
}

/// Flush the entire TLB by reloading CR3.
pub fn flush_tlb() {
    // SAFETY: Reloading CR3 flushes the TLB. This is a standard operation.
    unsafe {
        let cr3 = get_cr3();
        asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// Get or create a page table entry, returning the physical address of the next-level table.
///
/// If the existing entry is a 2 MiB huge page (PRESENT + HUGE), it is *split*
/// into 512 × 4 KiB page-table entries so that individual sub-pages can be
/// remapped (e.g., overlaying user ELF pages onto the kernel identity map).
///
/// # Safety
/// Caller must hold VMM_LOCK. The `table_phys` must point to a valid page table.
unsafe fn get_or_create_entry(table_phys: u64, index: usize, flags: u64) -> Option<u64> {
    let table_ptr = table_phys as *mut u64;
    let entry = *table_ptr.add(index);

    if entry & PAGE_PRESENT != 0 {
        // Check for a 2 MiB huge page that needs splitting.
        if entry & PAGE_HUGE != 0 {
            // Allocate a new 4 KiB page table.
            let new_pt = pmm::alloc_page()?;
            let pt_ptr = new_pt as *mut u64;

            // Compute the base physical address of the 2 MiB range.
            let huge_base = entry & 0x000F_FFFF_FFE0_0000; // 2 MiB aligned
            // Preserve per-entry flags from the huge page (minus HUGE).
            let per_entry_flags = (entry & !ADDR_MASK) & !PAGE_HUGE;

            // Fill all 512 × 4 KiB entries identically.
            for i in 0..512 {
                let phys = huge_base + (i as u64) * 0x1000;
                *pt_ptr.add(i) = phys | per_entry_flags;
            }

            // Replace the PD entry: pointer to new PT, drop HUGE flag,
            // keep PRESENT + WRITABLE + USER if set.
            let mut new_flags = (entry & !ADDR_MASK) & !PAGE_HUGE;
            // Propagate PAGE_USER from the caller's flags so Ring 3 can
            // access pages under this intermediate entry.
            if flags & PAGE_USER != 0 {
                new_flags |= PAGE_USER;
            }
            *table_ptr.add(index) = new_pt | new_flags;

            return Some(new_pt);
        }

        // Normal (non-huge) entry — propagate PAGE_USER if the caller
        // requests it and the entry doesn't already have it.  x86_64
        // requires PAGE_USER at every level for Ring 3 access.
        if flags & PAGE_USER != 0 && entry & PAGE_USER == 0 {
            *table_ptr.add(index) = entry | PAGE_USER;
        }
        Some(entry & ADDR_MASK)
    } else {
        // Allocate a new page table page
        let new_page = pmm::alloc_page()?;

        // Zero the new page
        let new_ptr = new_page as *mut u8;
        core::ptr::write_bytes(new_ptr, 0, pmm::PAGE_SIZE);

        // Set the entry
        *table_ptr.add(index) = new_page | PAGE_PRESENT | PAGE_WRITABLE | (flags & PAGE_USER);

        Some(new_page)
    }
}
/// Translate a virtual address to a physical address.
/// Returns None if the address is not mapped.
pub fn virt_to_phys(virt_addr: u64) -> Option<u64> {
    let pml4_phys = get_cr3();

    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;
    let offset = virt_addr & 0xFFF;

    // SAFETY: Reading page table entries at physical addresses. The page tables
    // are set up by the bootloader and maintained by us.
    unsafe {
        let pml4_ptr = pml4_phys as *const u64;
        let pml4_entry = *pml4_ptr.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 {
            return None;
        }

        let pdpt_ptr = (pml4_entry & ADDR_MASK) as *const u64;
        let pdpt_entry = *pdpt_ptr.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 {
            return None;
        }
        // Check for 1 GiB huge page
        if pdpt_entry & PAGE_HUGE != 0 {
            let base = pdpt_entry & 0x000F_FFFF_C000_0000;
            return Some(base | (virt_addr & 0x3FFF_FFFF));
        }

        let pd_ptr = (pdpt_entry & ADDR_MASK) as *const u64;
        let pd_entry = *pd_ptr.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 {
            return None;
        }
        // Check for 2 MiB huge page
        if pd_entry & PAGE_HUGE != 0 {
            let base = pd_entry & 0x000F_FFFF_FFE0_0000;
            return Some(base | (virt_addr & 0x1F_FFFF));
        }

        let pt_ptr = (pd_entry & ADDR_MASK) as *const u64;
        let pt_entry = *pt_ptr.add(pt_idx);
        if pt_entry & PAGE_PRESENT == 0 {
            return None;
        }

        Some((pt_entry & ADDR_MASK) | offset)
    }
}

// ============================================================================
// Per-Process Page Table Operations
// ============================================================================

/// Map a virtual page in an arbitrary page table (identified by `pml4_phys`).
///
/// This does NOT modify the current CR3 — it writes to the specified page table.
/// Used for setting up mappings in a new process's address space.
///
/// # Safety
/// `pml4_phys` must point to a valid PML4 page table.
pub fn map_page_in(pml4_phys: u64, virt_addr: u64, phys_addr: u64, flags: u64) -> bool {
    let _lock = VMM_LOCK.lock();

    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    unsafe {
        let pdpt_phys = match get_or_create_entry(pml4_phys, pml4_idx, flags) {
            Some(addr) => addr,
            None => return false,
        };
        let pd_phys = match get_or_create_entry(pdpt_phys, pdpt_idx, flags) {
            Some(addr) => addr,
            None => return false,
        };
        let pt_phys = match get_or_create_entry(pd_phys, pd_idx, flags) {
            Some(addr) => addr,
            None => return false,
        };

        let pt_ptr = pt_phys as *mut u64;
        *pt_ptr.add(pt_idx) = (phys_addr & ADDR_MASK) | flags | PAGE_PRESENT;
    }

    true
}

/// Unmap a virtual page in an arbitrary page table.
pub fn unmap_page_in(pml4_phys: u64, virt_addr: u64) {
    let _lock = VMM_LOCK.lock();

    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4_ptr = pml4_phys as *const u64;
        let pml4_entry = *pml4_ptr.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return; }

        let pdpt_phys = pml4_entry & ADDR_MASK;
        let pdpt_ptr = pdpt_phys as *const u64;
        let pdpt_entry = *pdpt_ptr.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return; }

        let pd_phys = pdpt_entry & ADDR_MASK;
        let pd_ptr = pd_phys as *const u64;
        let pd_entry = *pd_ptr.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return; }

        let pt_phys = pd_entry & ADDR_MASK;
        let pt_ptr = pt_phys as *mut u64;
        *pt_ptr.add(pt_idx) = 0;
    }
}

/// Read a PTE from an arbitrary page table.
/// Returns the raw PTE value, or 0 if unmapped.
pub fn read_pte(pml4_phys: u64, virt_addr: u64) -> u64 {
    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4_ptr = pml4_phys as *const u64;
        let pml4_entry = *pml4_ptr.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return 0; }

        let pdpt_ptr = (pml4_entry & ADDR_MASK) as *const u64;
        let pdpt_entry = *pdpt_ptr.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return 0; }
        if pdpt_entry & PAGE_HUGE != 0 { return pdpt_entry; }

        let pd_ptr = (pdpt_entry & ADDR_MASK) as *const u64;
        let pd_entry = *pd_ptr.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return 0; }
        if pd_entry & PAGE_HUGE != 0 { return pd_entry; }

        let pt_ptr = (pd_entry & ADDR_MASK) as *const u64;
        *pt_ptr.add(pt_idx)
    }
}

/// Write a PTE in an arbitrary page table (used for CoW flag manipulation).
/// Does NOT create intermediate table levels — the mapping must already exist.
pub fn write_pte(pml4_phys: u64, virt_addr: u64, pte: u64) {
    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4_ptr = pml4_phys as *const u64;
        let pml4_entry = *pml4_ptr.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return; }

        let pdpt_ptr = (pml4_entry & ADDR_MASK) as *const u64;
        let pdpt_entry = *pdpt_ptr.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return; }

        let pd_ptr = (pdpt_entry & ADDR_MASK) as *const u64;
        let pd_entry = *pd_ptr.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return; }

        let pt_ptr = (pd_entry & ADDR_MASK) as *mut u64;
        *pt_ptr.add(pt_idx) = pte;
    }
}

/// Switch the active page table (CR3).
///
/// # Safety
/// The new CR3 must point to a valid PML4 with the kernel half mapped.
pub unsafe fn switch_cr3(new_cr3: u64) {
    asm!("mov cr3, {}", in(reg) new_cr3, options(nostack, preserves_flags));
}

/// Translate a virtual address to physical using a specific page table.
pub fn virt_to_phys_in(pml4_phys: u64, virt_addr: u64) -> Option<u64> {
    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;
    let offset = virt_addr & 0xFFF;

    unsafe {
        let pml4_ptr = pml4_phys as *const u64;
        let pml4_entry = *pml4_ptr.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return None; }

        let pdpt_ptr = (pml4_entry & ADDR_MASK) as *const u64;
        let pdpt_entry = *pdpt_ptr.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return None; }
        if pdpt_entry & PAGE_HUGE != 0 {
            return Some((pdpt_entry & 0x000F_FFFF_C000_0000) | (virt_addr & 0x3FFF_FFFF));
        }

        let pd_ptr = (pdpt_entry & ADDR_MASK) as *const u64;
        let pd_entry = *pd_ptr.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return None; }
        if pd_entry & PAGE_HUGE != 0 {
            return Some((pd_entry & 0x000F_FFFF_FFE0_0000) | (virt_addr & 0x1F_FFFF));
        }

        let pt_ptr = (pd_entry & ADDR_MASK) as *const u64;
        let pt_entry = *pt_ptr.add(pt_idx);
        if pt_entry & PAGE_PRESENT == 0 { return None; }

        Some((pt_entry & ADDR_MASK) | offset)
    }
}
