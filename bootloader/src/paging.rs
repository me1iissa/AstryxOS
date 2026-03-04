//! Page table setup for the Aether kernel.
//!
//! Sets up 4-level x86_64 page tables with:
//! - Identity mapping of first 4 GiB (physical == virtual)
//! - Higher-half mapping at 0xFFFF_8000_0000_0000 -> 0x0 (first 4 GiB)
//!
//! Uses 2 MiB huge pages for efficiency (PDE level mapping).

use core::arch::asm;

/// Page table entry flags.
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const HUGE_PAGE: u64 = 1 << 7; // 2 MiB page (at PD level)

/// Number of 2 MiB pages to map (4 GiB / 2 MiB = 2048).
const PAGES_TO_MAP: usize = 2048;

/// Page table structure: 512 entries of 8 bytes each = 4096 bytes (one page).
#[repr(C, align(4096))]
struct PageTable {
    entries: [u64; 512],
}

/// Static page tables.
/// We need: 1 PML4 + 2 PDPT (identity + higher-half) + 4 PD tables (1 GiB each)
/// For 4 GiB with 2 MiB pages: PML4 -> PDPT -> PD (512 entries * 2MiB = 1 GiB per PD)
static mut PML4: PageTable = PageTable { entries: [0; 512] };
static mut PDPT_IDENTITY: PageTable = PageTable { entries: [0; 512] };
static mut PDPT_HIGHER: PageTable = PageTable { entries: [0; 512] };
static mut PD0: PageTable = PageTable { entries: [0; 512] };
static mut PD1: PageTable = PageTable { entries: [0; 512] };
static mut PD2: PageTable = PageTable { entries: [0; 512] };
static mut PD3: PageTable = PageTable { entries: [0; 512] };

/// Set up page tables and load them into CR3.
///
/// # Safety
/// Must be called with interrupts disabled and after exiting UEFI boot services.
/// The static page table memory must not be in a region that gets overwritten.
pub unsafe fn setup_page_tables() {
    // Get raw pointers to all tables
    let pml4 = &raw mut PML4;
    let pdpt_identity = &raw mut PDPT_IDENTITY;
    let pdpt_higher = &raw mut PDPT_HIGHER;
    let pd0 = &raw mut PD0;
    let pd1 = &raw mut PD1;
    let pd2 = &raw mut PD2;
    let pd3 = &raw mut PD3;

    // Zero all tables
    zero_table(pml4);
    zero_table(pdpt_identity);
    zero_table(pdpt_higher);
    zero_table(pd0);
    zero_table(pd1);
    zero_table(pd2);
    zero_table(pd3);

    // Set up Page Directory tables with 2 MiB huge pages
    // PD0: maps 0x0000_0000 - 0x3FFF_FFFF (0-1 GiB)
    // PD1: maps 0x4000_0000 - 0x7FFF_FFFF (1-2 GiB)
    // PD2: maps 0x8000_0000 - 0xBFFF_FFFF (2-3 GiB)
    // PD3: maps 0xC000_0000 - 0xFFFF_FFFF (3-4 GiB)
    let pd_tables: [*mut PageTable; 4] = [pd0, pd1, pd2, pd3];

    for (pd_idx, pd_ptr) in pd_tables.iter().enumerate() {
        let pd = &mut **pd_ptr;
        for i in 0..512 {
            let phys_addr = (pd_idx * 512 + i) as u64 * 0x20_0000; // 2 MiB per entry
            if (pd_idx * 512 + i) < PAGES_TO_MAP {
                pd.entries[i] = phys_addr | PRESENT | WRITABLE | HUGE_PAGE;
            }
        }
    }

    // PDPT for identity mapping (PML4 entry 0)
    (*pdpt_identity).entries[0] = table_addr_raw(pd0) | PRESENT | WRITABLE;
    (*pdpt_identity).entries[1] = table_addr_raw(pd1) | PRESENT | WRITABLE;
    (*pdpt_identity).entries[2] = table_addr_raw(pd2) | PRESENT | WRITABLE;
    (*pdpt_identity).entries[3] = table_addr_raw(pd3) | PRESENT | WRITABLE;

    // PDPT for higher-half mapping (PML4 entry 256, for 0xFFFF_8000_0000_0000)
    (*pdpt_higher).entries[0] = table_addr_raw(pd0) | PRESENT | WRITABLE;
    (*pdpt_higher).entries[1] = table_addr_raw(pd1) | PRESENT | WRITABLE;
    (*pdpt_higher).entries[2] = table_addr_raw(pd2) | PRESENT | WRITABLE;
    (*pdpt_higher).entries[3] = table_addr_raw(pd3) | PRESENT | WRITABLE;

    // PML4 entry 0: identity map
    (*pml4).entries[0] = table_addr_raw(pdpt_identity) | PRESENT | WRITABLE;

    // PML4 entry 256: higher-half kernel (0xFFFF_8000_0000_0000)
    (*pml4).entries[256] = table_addr_raw(pdpt_higher) | PRESENT | WRITABLE;

    // Load PML4 into CR3
    let pml4_addr = table_addr_raw(pml4);
    asm!(
        "mov cr3, {}",
        in(reg) pml4_addr,
        options(nostack, preserves_flags)
    );
}

/// Get the physical address of a page table from a raw pointer.
fn table_addr_raw(table: *const PageTable) -> u64 {
    table as u64
}

/// Zero out a page table via raw pointer.
unsafe fn zero_table(table: *mut PageTable) {
    for entry in (*table).entries.iter_mut() {
        *entry = 0;
    }
}
