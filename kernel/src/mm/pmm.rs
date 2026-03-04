//! Physical Memory Manager (PMM)
//!
//! Uses a bitmap allocator to track physical page frames (4 KiB each).
//! Processes the UEFI memory map to find usable regions.

use astryx_shared::{BootInfo, MemoryType};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Page size: 4 KiB.
pub const PAGE_SIZE: usize = 4096;

/// Maximum physical memory we track: 4 GiB (1M pages).
const MAX_PAGES: usize = 1024 * 1024;

/// Bitmap: 1 bit per page. MAX_PAGES / 8 bytes.
const BITMAP_SIZE: usize = MAX_PAGES / 8;

/// Static bitmap for physical page tracking.
/// 0 = free, 1 = used/reserved.
static mut BITMAP: [u8; BITMAP_SIZE] = [0xFF; BITMAP_SIZE]; // Start all as used

/// Lock for bitmap operations.
static PMM_LOCK: Mutex<()> = Mutex::new(());

/// Total available pages.
static TOTAL_PAGES: AtomicU64 = AtomicU64::new(0);
/// Used pages.
static USED_PAGES: AtomicU64 = AtomicU64::new(0);

/// Initialize the PMM from the UEFI memory map.
pub fn init(boot_info: &BootInfo) {
    let _lock = PMM_LOCK.lock();
    let mut total_available = 0u64;

    for i in 0..boot_info.memory_map.entry_count as usize {
        let entry = &boot_info.memory_map.entries[i];

        if entry.memory_type == MemoryType::Available {
            let start_page = (entry.physical_start / PAGE_SIZE as u64) as usize;
            let page_count = entry.page_count as usize;

            for page in start_page..start_page + page_count {
                if page < MAX_PAGES {
                    unsafe {
                        mark_page_free(page);
                    }
                    total_available += 1;
                }
            }
        }
    }

    // Mark kernel region as used (1 MiB + kernel size)
    let kernel_start = (boot_info.kernel_phys_base / PAGE_SIZE as u64) as usize;
    let kernel_pages = ((boot_info.kernel_size + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;
    for page in kernel_start..kernel_start + kernel_pages + 256 {
        // +256 pages for boot info and early structures
        if page < MAX_PAGES {
            // SAFETY: We hold the PMM lock and page is in bounds.
            unsafe {
                mark_page_used(page);
            }
            if total_available > 0 {
                total_available -= 1;
            }
        }
    }

    // Mark first 1 MiB as reserved (BIOS, VGA, etc.)
    for page in 0..256 {
        // SAFETY: We hold the PMM lock and page is in bounds.
        unsafe {
            mark_page_used(page);
        }
    }

    TOTAL_PAGES.store(total_available, Ordering::Relaxed);
    USED_PAGES.store(0, Ordering::Relaxed);

    crate::serial_println!(
        "[PMM] Initialized: {} MiB available ({} pages)",
        total_available * 4 / 1024,
        total_available
    );
}

/// Allocate a single physical page frame.
/// Returns the physical address, or None if out of memory.
pub fn alloc_page() -> Option<u64> {
    let _lock = PMM_LOCK.lock();

    // SAFETY: We hold the PMM lock. Searching bitmap for free page.
    unsafe {
        for byte_idx in 0..BITMAP_SIZE {
            if BITMAP[byte_idx] != 0xFF {
                // Found a byte with at least one free bit
                for bit in 0..8 {
                    if BITMAP[byte_idx] & (1 << bit) == 0 {
                        let page = byte_idx * 8 + bit;
                        mark_page_used(page);
                        USED_PAGES.fetch_add(1, Ordering::Relaxed);
                        return Some((page * PAGE_SIZE) as u64);
                    }
                }
            }
        }
    }

    None
}

/// Free a physical page frame.
pub fn free_page(phys_addr: u64) {
    let page = (phys_addr / PAGE_SIZE as u64) as usize;
    if page >= MAX_PAGES {
        return;
    }

    let _lock = PMM_LOCK.lock();
    // SAFETY: We hold the PMM lock and page is in bounds.
    unsafe {
        mark_page_free(page);
    }
    USED_PAGES.fetch_sub(1, Ordering::Relaxed);
}

/// Allocate `count` contiguous physical pages.
/// Returns the physical address of the first page.
pub fn alloc_pages(count: usize) -> Option<u64> {
    if count == 0 {
        return None;
    }

    let _lock = PMM_LOCK.lock();

    // SAFETY: We hold the PMM lock. Linear search for contiguous free pages.
    unsafe {
        let mut start = 0;
        let mut found = 0;

        for page in 0..MAX_PAGES {
            let byte_idx = page / 8;
            let bit = page % 8;

            if BITMAP[byte_idx] & (1 << bit) == 0 {
                if found == 0 {
                    start = page;
                }
                found += 1;
                if found == count {
                    // Mark all pages as used
                    for p in start..start + count {
                        mark_page_used(p);
                    }
                    USED_PAGES.fetch_add(count as u64, Ordering::Relaxed);
                    return Some((start * PAGE_SIZE) as u64);
                }
            } else {
                found = 0;
            }
        }
    }

    None
}

/// Reserve a physical address range so `alloc_page` will never hand it out.
///
/// Used to protect memory that is implicitly mapped by the bootloader's
/// 2 MiB huge pages (e.g., the kernel heap's backing physical range).
pub fn reserve_range(start: u64, end: u64) {
    let _lock = PMM_LOCK.lock();
    let start_page = (start / PAGE_SIZE as u64) as usize;
    let end_page = ((end + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;
    for page in start_page..end_page {
        if page < MAX_PAGES {
            // SAFETY: We hold the PMM lock and page is in bounds.
            unsafe { mark_page_used(page); }
        }
    }
}

/// Get memory statistics.
pub fn stats() -> (u64, u64) {
    (
        TOTAL_PAGES.load(Ordering::Relaxed),
        USED_PAGES.load(Ordering::Relaxed),
    )
}

/// Mark a page as used in the bitmap.
///
/// # Safety
/// Caller must hold PMM_LOCK and ensure page is in bounds.
unsafe fn mark_page_used(page: usize) {
    BITMAP[page / 8] |= 1 << (page % 8);
}

/// Mark a page as free in the bitmap.
///
/// # Safety
/// Caller must hold PMM_LOCK and ensure page is in bounds.
unsafe fn mark_page_free(page: usize) {
    BITMAP[page / 8] &= !(1 << (page % 8));
}
