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

/// Physical-to-virtual offset for the kernel's higher-half identity map.
///
/// The bootloader maps all physical RAM at both virtual 0 (identity map, via
/// PML4[0]) AND at PHYS_OFF (higher-half, via PML4[256-511]).  User-process
/// page tables shallow-copy PML4[256-511] from the kernel, so the higher-half
/// is ALWAYS accessible regardless of which CR3 is active.
///
/// The identity map (PML4[0]) is deep-cloned per-process and its PT entries
/// are overwritten when ELF segments are loaded at low virtual addresses
/// (e.g. 0x400000).  Any physical address that falls within a region the ELF
/// occupies can no longer be reached via `phys as *mut u64` while the user
/// CR3 is active.  Using `PHYS_OFF + phys` avoids this problem entirely.
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Convert a physical page-table address to a kernel-accessible virtual pointer.
#[inline(always)]
unsafe fn p2v(phys: u64) -> *mut u64 {
    (PHYS_OFF + phys) as *mut u64
}

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

    // Extend the higher-half physical map to cover physical addresses 1-4 GiB.
    //
    // The bootloader only maps 0..RAM (≤1 GiB) at PHYS_OFF.  Physical addresses
    // above 1 GiB are MMIO (framebuffer at ~2 GiB, LAPIC at 0xFEE00000, IOAPIC
    // at 0xFEC00000, etc.) and are not yet mapped.
    //
    // Without this, kernel MMIO writes that use `PHYS_OFF + phys` fail when the
    // kernel interrupt handler runs with a user-process CR3 (which inherits only
    // PML4[256-511] from the kernel, not PML4[0] the identity map).
    //
    // We add 2 MiB huge-page entries for PDPT[1], PDPT[2], PDPT[3] under
    // PML4[256] (PHYS_OFF range).  Specific MMIO drivers that need stronger
    // cache attributes (e.g. LAPIC uses PAGE_NO_CACHE) will later split the
    // relevant 2 MiB entry into 4 KiB pages via `map_page()`.
    unsafe { extend_higher_half_to_4gib(); }

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

    // Read PML4[256] → PDPT_HIGHER
    let pml4_256 = *p2v(cr3).add(256);
    if pml4_256 & PAGE_PRESENT == 0 {
        return;
    }

    let pdpt_phys = pml4_256 & ADDR_MASK;

    for i in 0..512 {
        let pdpt_entry = *p2v(pdpt_phys).add(i);
        if pdpt_entry & PAGE_PRESENT == 0 {
            continue;
        }
        // 1 GiB huge page — leave as-is (uncommon in our setup).
        if pdpt_entry & PAGE_HUGE != 0 {
            continue;
        }

        // Allocate a fresh PD page and copy the original contents.
        let old_pd_phys = pdpt_entry & ADDR_MASK;
        let new_pd = match pmm::alloc_page() {
            Some(p) => p,
            None => {
                crate::serial_println!("[VMM] WARN: cannot alloc PD copy for higher-half");
                return;
            }
        };
        core::ptr::copy_nonoverlapping(
            (PHYS_OFF + old_pd_phys) as *const u8,
            (PHYS_OFF + new_pd) as *mut u8,
            4096,
        );

        // Update PDPT_HIGHER to point to the cloned PD, preserving flags.
        let flags = pdpt_entry & !ADDR_MASK;
        *p2v(pdpt_phys).add(i) = new_pd | flags;
    }

    // Flush TLB so all higher-half accesses use the new PD pages.
    flush_tlb();
}

/// Extend the kernel's higher-half physical map to cover 1 GiB – 4 GiB.
///
/// The bootloader maps physical 0..RAM (≤ 1 GiB) at PHYS_OFF via PML4[256].
/// Physical addresses above 1 GiB (MMIO: framebuffer, LAPIC, IOAPIC, etc.)
/// are not mapped.  This function adds PDPT entries [1], [2], [3] under
/// PML4[256] so that `PHYS_OFF + phys` is valid for ANY physical address
/// 0 < phys < 4 GiB.
///
/// Each PDPT entry points to a new PD filled with 512 × 2 MiB write-back
/// huge pages.  Drivers that require stronger cache attributes (e.g. LAPIC
/// needs PAGE_NO_CACHE) should call `map_page()` afterwards to split the
/// relevant 2 MiB entry into 4 KiB pages.
///
/// # Safety
/// Must be called once from `vmm::init()`, after `separate_higher_half_pds()`.
unsafe fn extend_higher_half_to_4gib() {
    let cr3 = get_cr3();
    let pml4_entry = *p2v(cr3).add(256);
    if pml4_entry & PAGE_PRESENT == 0 {
        crate::serial_println!("[VMM] WARN: PML4[256] not present — cannot extend higher-half");
        return;
    }
    let pdpt_phys = pml4_entry & ADDR_MASK;

    // PDPT entries 1, 2, 3 cover physical 1 GiB – 4 GiB.
    for pdpt_idx in 1usize..=3 {
        // Skip if already present (e.g. machine has > 1 GiB RAM mapped by bootloader).
        if *p2v(pdpt_phys).add(pdpt_idx) & PAGE_PRESENT != 0 {
            continue;
        }

        // Allocate a fresh PD page.
        let new_pd = match pmm::alloc_page() {
            Some(p) => p,
            None => {
                crate::serial_println!("[VMM] WARN: OOM extending higher-half (pdpt_idx={})", pdpt_idx);
                continue;
            }
        };

        // Fill PD with 512 × 2 MiB write-back huge pages covering this 1 GiB chunk.
        let chunk_base = (pdpt_idx as u64) * 0x4000_0000; // 1 GiB per PDPT entry
        let pd_ptr = p2v(new_pd);
        for pd_i in 0usize..512 {
            let phys = chunk_base + (pd_i as u64) * 0x0020_0000; // 2 MiB per PD entry
            *pd_ptr.add(pd_i) = phys | PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGE;
        }

        // Install PDPT entry.
        *p2v(pdpt_phys).add(pdpt_idx) = new_pd | PAGE_PRESENT | PAGE_WRITABLE;
    }

    flush_tlb();
    crate::serial_println!("[VMM] Higher-half extended to cover physical 0..4 GiB");
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
        let pt_ptr = p2v(pt_phys);
        let entry_ptr = pt_ptr.add(pt_idx);
        *entry_ptr = (phys_addr & ADDR_MASK) | flags | PAGE_PRESENT;
    }

    true
}

/// Install a not-present (guard) PTE at `virt_addr` in the *kernel* page table.
///
/// Creates the intermediate PT levels as needed (so the walk succeeds), but
/// writes a zero final PTE — keeping the present bit clear.  Any access to this
/// address will raise a page fault.
///
/// The caller must separately call `pmm::reserve_range` for the physical frame
/// that would correspond to this virtual address (`virt_addr - PHYS_OFF`) so
/// that the PMM never hands that frame out and creates a direct-map alias.
pub fn install_not_present_guard(virt_addr: u64) -> bool {
    let _lock = VMM_LOCK.lock();

    let pml4_phys = get_cr3();

    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx   = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx   = ((virt_addr >> 12) & 0x1FF) as usize;

    // SAFETY: We hold VMM_LOCK. We walk and potentially allocate PT pages, then
    // write a zero (not-present) PTE to the leaf slot.  Intermediate entries are
    // created without PAGE_USER so the guard is kernel-only.
    unsafe {
        // Walk PML4 → PDPT
        let pdpt_phys = match get_or_create_entry(pml4_phys, pml4_idx, 0) {
            Some(a) => a,
            None => return false,
        };
        // Walk PDPT → PD
        let pd_phys = match get_or_create_entry(pdpt_phys, pdpt_idx, 0) {
            Some(a) => a,
            None => return false,
        };
        // Walk PD → PT (may split a 2 MiB huge page if one exists here)
        let pt_phys = match get_or_create_entry(pd_phys, pd_idx, 0) {
            Some(a) => a,
            None => return false,
        };

        // Write a zero PTE — present bit is clear, so any access faults.
        // We do NOT encode a physical address: the guard page has no backing.
        let pt_ptr = p2v(pt_phys);
        *pt_ptr.add(pt_idx) = 0;

        // Ensure the CPU's TLB reflects the not-present entry (it may have
        // cached a stale entry from a previous mapping at this VA).
        invlpg(virt_addr);
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
        let pml4_entry = *p2v(pml4_phys).add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return; }

        let pdpt_entry = *p2v(pml4_entry & ADDR_MASK).add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return; }

        let pd_entry = *p2v(pdpt_entry & ADDR_MASK).add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return; }

        *p2v(pd_entry & ADDR_MASK).add(pt_idx) = 0;

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
    // Access via higher-half so ELF-loaded identity-map overwrites don't affect us.
    let table_ptr = p2v(table_phys);
    let entry = *table_ptr.add(index);

    if entry & PAGE_PRESENT != 0 {
        // Check for a 2 MiB huge page that needs splitting.
        if entry & PAGE_HUGE != 0 {
            // Allocate a new 4 KiB page table.
            let new_pt = pmm::alloc_page()?;
            let pt_ptr = p2v(new_pt);

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

        // Zero the new page via higher-half (identity-map may be corrupted).
        core::ptr::write_bytes((PHYS_OFF + new_page) as *mut u8, 0, pmm::PAGE_SIZE);

        // Set the entry via higher-half.
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

    unsafe {
        let pml4_entry = *p2v(pml4_phys).add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return None; }

        let pdpt_entry = *p2v(pml4_entry & ADDR_MASK).add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return None; }
        if pdpt_entry & PAGE_HUGE != 0 {
            return Some((pdpt_entry & 0x000F_FFFF_C000_0000) | (virt_addr & 0x3FFF_FFFF));
        }

        let pd_entry = *p2v(pdpt_entry & ADDR_MASK).add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return None; }
        if pd_entry & PAGE_HUGE != 0 {
            return Some((pd_entry & 0x000F_FFFF_FFE0_0000) | (virt_addr & 0x1F_FFFF));
        }

        let pt_entry = *p2v(pd_entry & ADDR_MASK).add(pt_idx);
        if pt_entry & PAGE_PRESENT == 0 { return None; }

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

        let pt_ptr = p2v(pt_phys);
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
        let pml4_entry = *p2v(pml4_phys).add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return; }

        let pdpt_entry = *p2v(pml4_entry & ADDR_MASK).add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return; }

        let pd_entry = *p2v(pdpt_entry & ADDR_MASK).add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return; }

        *p2v(pd_entry & ADDR_MASK).add(pt_idx) = 0;
    }
}

/// Unmap every present page in `[base, base+length)` from an arbitrary page
/// table, drop one reference on the underlying physical frame, and free the
/// frame when the last reference goes away.  Each cleared PTE is followed by
/// `invlpg` on the calling CPU.
///
/// This helper exists so the upper-level mmap / munmap paths can run the
/// expensive bulk-unmap loop **without holding `PROCESS_TABLE`**.  It only
/// needs the PML4 physical address and the VMM/PMM/refcount globals it
/// already serialises on internally.
///
/// `base` and `length` are caller-validated to be page-aligned and bounded
/// to a user-process VMA range.
///
/// Returns the number of frames actually freed (rc reached zero).  Pages
/// that were never demand-paged are skipped.
pub fn unmap_and_free_range_in(pml4_phys: u64, base: u64, length: u64) -> usize {
    let mut freed = 0usize;
    let mut pg = base;
    let end = base.saturating_add(length);
    while pg < end {
        if let Some(phys) = virt_to_phys_in(pml4_phys, pg) {
            unmap_page_in(pml4_phys, pg);
            invlpg(pg);
            let new_rc = crate::mm::refcount::page_ref_dec(phys);
            if new_rc == 0 {
                pmm::free_page(phys);
                freed += 1;
            }
        }
        pg += 0x1000;
    }
    freed
}

/// Read a PTE from an arbitrary page table.
/// Returns the raw PTE value, or 0 if unmapped.
pub fn read_pte(pml4_phys: u64, virt_addr: u64) -> u64 {
    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4_entry = *p2v(pml4_phys).add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return 0; }

        let pdpt_entry = *p2v(pml4_entry & ADDR_MASK).add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return 0; }
        if pdpt_entry & PAGE_HUGE != 0 { return pdpt_entry; }

        let pd_entry = *p2v(pdpt_entry & ADDR_MASK).add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return 0; }
        if pd_entry & PAGE_HUGE != 0 { return pd_entry; }

        *p2v(pd_entry & ADDR_MASK).add(pt_idx)
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
        let pml4_entry = *p2v(pml4_phys).add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return; }

        let pdpt_entry = *p2v(pml4_entry & ADDR_MASK).add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return; }

        let pd_entry = *p2v(pdpt_entry & ADDR_MASK).add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return; }

        *p2v(pd_entry & ADDR_MASK).add(pt_idx) = pte;
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
        let pml4_entry = *p2v(pml4_phys).add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return None; }

        let pdpt_entry = *p2v(pml4_entry & ADDR_MASK).add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return None; }
        if pdpt_entry & PAGE_HUGE != 0 {
            return Some((pdpt_entry & 0x000F_FFFF_C000_0000) | (virt_addr & 0x3FFF_FFFF));
        }

        let pd_entry = *p2v(pdpt_entry & ADDR_MASK).add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return None; }
        if pd_entry & PAGE_HUGE != 0 {
            return Some((pd_entry & 0x000F_FFFF_FFE0_0000) | (virt_addr & 0x1F_FFFF));
        }

        let pt_entry = *p2v(pd_entry & ADDR_MASK).add(pt_idx);
        if pt_entry & PAGE_PRESENT == 0 { return None; }

        Some((pt_entry & ADDR_MASK) | offset)
    }
}
