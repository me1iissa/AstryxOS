//! Kernel Heap Allocator
//!
//! Linked-list free-list allocator for the kernel heap.
//! Supports proper allocation and deallocation with coalescing of adjacent free blocks.
//!
//! ## Heap base placement
//!
//! The heap virtual base is computed at runtime in `init()` from the
//! `__kernel_end` linker symbol so the heap always sits above whatever the
//! linker actually placed BSS at.  Default builds (where BSS fits under
//! 8 MiB) keep the historical layout — `HEAP_START_MIN_VA = 0xFFFF_8000_0080_0000`
//! — for byte-identical behaviour.  Heavy diagnostic feature combinations
//! (`firefox-test,w215-diag,f3-watch,file-buf-witness`) grow BSS past
//! 8 MiB; in those builds the heap follows BSS rather than overlapping it,
//! avoiding the silent free-list corruption that first surfaced in Phase 2
//! QA on 2026-05-21.
//!
//! `vmm::init()` calls `compute_heap_layout()` to reserve the backing
//! frames in the PMM before any `pmm::alloc_page()` runs; `init()` here
//! latches the same layout and wires the global allocator.  Both call
//! sites get identical answers because `__kernel_end` is a link-time
//! constant.  See Intel SDM Vol. 3A §4.3 (IA-32e 2 MiB paging) for the
//! 2 MiB-aligned base rationale.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

/// Kernel heap size: 128 MiB (sufficient for 1920×1080 GUI with multiple window surfaces).
pub const HEAP_SIZE: usize = 128 * 1024 * 1024;

/// Minimum heap base virtual address — phys 8 MiB in the higher-half map.
///
/// Preserves the historical layout for small kernel builds.  When BSS fits
/// below 8 MiB (default `firefox-test`) the computed layout pins the heap
/// here and the build is byte-identical to pre-dynamic-heap kernels.
const HEAP_START_MIN_VA: usize = 0xFFFF_8000_0080_0000;

/// One 2 MiB huge page.  Heap base is rounded up to this alignment so it
/// always falls on a 2 MiB boundary matching the bootloader's higher-half
/// huge-page map.  See Intel SDM Vol. 3A §4.3.
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Physical-to-virtual offset for the kernel's higher-half map (PML4[256-511]).
/// Matches `shared::KERNEL_VIRT_BASE` and `vmm::PHYS_OFF`.
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

extern "C" {
    /// 4 KiB-aligned symbol emitted by `kernel/linker.ld` immediately after
    /// `.bss` (see `__kernel_end = .;`).  Used to position the heap above
    /// whatever the linker actually placed BSS at, so feature-gated
    /// diagnostic statics that inflate BSS (e.g. `w215_diag` shadow tables
    /// at ~1.65 MiB) do not silently overlap the heap.
    static __kernel_end: u8;
}

/// Runtime-latched heap virtual base, computed in `heap::init()` from the
/// `__kernel_end` linker symbol.  `0` until `heap::init()` runs.  All
/// external callers (idt page-fault guard, test_runner) must read through
/// `heap_start()` / `heap_guard_*_va()` so the "not yet initialised"
/// sentinel is honoured.
static HEAP_START_VA: AtomicUsize = AtomicUsize::new(0);

/// Returns the kernel heap base virtual address, or `0` if `heap::init()`
/// has not yet executed.
#[inline]
pub fn heap_start() -> usize {
    HEAP_START_VA.load(Ordering::Relaxed)
}

/// Returns the not-present guard page VA immediately below the heap base,
/// or `0` if `heap::init()` has not yet executed.
#[inline]
pub fn heap_guard_below_va() -> u64 {
    let base = HEAP_START_VA.load(Ordering::Relaxed);
    if base == 0 { 0 } else { base as u64 - 0x1000 }
}

/// Returns the not-present guard page VA immediately above the heap, or
/// `0` if `heap::init()` has not yet executed.
#[inline]
pub fn heap_guard_above_va() -> u64 {
    let base = HEAP_START_VA.load(Ordering::Relaxed);
    if base == 0 { 0 } else { (base + HEAP_SIZE) as u64 }
}

/// Compute the kernel heap layout — virtual base, physical base, physical
/// end-exclusive — by aligning past the linker's `__kernel_end` symbol.
///
/// Called twice during early boot: once from `vmm::init()` to reserve the
/// backing frames in the PMM before any `pmm::alloc_page()` can hand them
/// out, and once from `heap::init()` to wire the allocator.  Both calls
/// agree because `__kernel_end` is a link-time constant.
///
/// Returns `(va_start, phys_start, phys_end_exclusive)`.
pub fn compute_heap_layout() -> (usize, u64, u64) {
    // SAFETY: `__kernel_end` is a linker-defined symbol; taking its
    // address is always safe.  Its higher-half VA translates back to a
    // physical address via `va - PHYS_OFF`.
    let kernel_end_va: u64 = unsafe { &__kernel_end as *const u8 as u64 };
    let kernel_end_phys: u64 = kernel_end_va.saturating_sub(PHYS_OFF);

    // Round up past kernel_end by ≥1 page (so there is always a strictly
    // non-present byte between BSS and the below-guard PTE), then to the
    // next 2 MiB huge-page boundary so the heap base aligns with the
    // bootloader's higher-half huge-page map.
    let candidate_phys = (kernel_end_phys + 0x1000 + HUGE_PAGE_SIZE as u64 - 1)
        & !(HUGE_PAGE_SIZE as u64 - 1);

    // Honour the historical lower bound (HEAP_START_MIN_VA, phys 0x80_0000)
    // so default builds with BSS < 8 MiB get byte-identical layout.
    let min_phys = (HEAP_START_MIN_VA as u64).saturating_sub(PHYS_OFF);
    let phys_start = core::cmp::max(candidate_phys, min_phys);
    let phys_end = phys_start + HEAP_SIZE as u64;
    let va_start = (phys_start + PHYS_OFF) as usize;

    (va_start, phys_start, phys_end)
}

/// Physical frame backing the below-guard VA, for PMM reservation.
#[inline]
fn heap_guard_below_phys() -> u64 {
    heap_guard_below_va().saturating_sub(PHYS_OFF)
}

/// Physical frame backing the above-guard VA, for PMM reservation.
#[inline]
fn heap_guard_above_phys() -> u64 {
    heap_guard_above_va().saturating_sub(PHYS_OFF)
}

/// Minimum block size — must be large enough to hold a FreeBlock header.
const MIN_BLOCK_SIZE: usize = core::mem::size_of::<FreeBlock>();

/// Global kernel allocator.
#[global_allocator]
static ALLOCATOR: LockedHeapAllocator = LockedHeapAllocator(Mutex::new(LinkedListAllocator {
    head: ptr::null_mut(),
    initialized: false,
    total_bytes: 0,
    allocated_bytes: 0,
}));

/// Header for a free block in the free list.
#[repr(C)]
struct FreeBlock {
    /// Size of this free block (including the header).
    size: usize,
    /// Pointer to the next free block, or null.
    next: *mut FreeBlock,
}

/// Header stored just before every returned allocation.
/// Stores the original block start address and total block size.
#[repr(C)]
struct AllocHeader {
    /// Start address of the entire block (including any alignment padding before this header).
    block_start: usize,
    /// Total size of the entire block.
    block_size: usize,
}

const ALLOC_HEADER_SIZE: usize = core::mem::size_of::<AllocHeader>();

/// Linked-list free-list heap allocator with first-fit strategy and coalescing.
struct LinkedListAllocator {
    /// Head of the free list.
    head: *mut FreeBlock,
    /// Whether the allocator has been initialized.
    initialized: bool,
    /// Total bytes under management.
    total_bytes: usize,
    /// Currently allocated bytes (approximate, includes overhead).
    allocated_bytes: usize,
}

// SAFETY: We protect all access behind a spin::Mutex.
unsafe impl Send for LinkedListAllocator {}

impl LinkedListAllocator {
    /// Initialize the heap with a single large free block.
    fn init(&mut self, heap_start: usize, heap_size: usize) {
        let block = heap_start as *mut FreeBlock;
        unsafe {
            (*block).size = heap_size;
            (*block).next = ptr::null_mut();
        }
        self.head = block;
        self.total_bytes = heap_size;
        self.allocated_bytes = 0;
        self.initialized = true;
    }

    /// Allocate memory with the given layout.
    fn alloc(&mut self, layout: Layout) -> *mut u8 {
        if !self.initialized {
            return ptr::null_mut();
        }

        let align = layout.align().max(core::mem::align_of::<AllocHeader>());

        // Walk the free list looking for first fit.
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = self.head;

        while !current.is_null() {
            let block_addr = current as usize;
            let block_size = unsafe { (*current).size };

            // The user data must be aligned, and we need an AllocHeader just before it.
            let data_start = align_up(block_addr + ALLOC_HEADER_SIZE, align);
            let total_needed = (data_start + layout.size()) - block_addr;

            if block_size >= total_needed {
                let remainder = block_size - total_needed;
                let next_block = unsafe { (*current).next };

                if remainder >= MIN_BLOCK_SIZE + 16 {
                    // Split: create a new free block after the allocation.
                    let new_free_addr = block_addr + total_needed;
                    let new_free = new_free_addr as *mut FreeBlock;
                    unsafe {
                        (*new_free).size = remainder;
                        (*new_free).next = next_block;
                    }

                    if prev.is_null() {
                        self.head = new_free;
                    } else {
                        unsafe { (*prev).next = new_free; }
                    }

                    // Write the allocation header just before user data.
                    let header_ptr = (data_start - ALLOC_HEADER_SIZE) as *mut AllocHeader;
                    unsafe {
                        (*header_ptr).block_start = block_addr;
                        (*header_ptr).block_size = total_needed;
                    }
                    self.allocated_bytes += total_needed;
                } else {
                    // Use the entire block (don't split tiny remainders).
                    if prev.is_null() {
                        self.head = next_block;
                    } else {
                        unsafe { (*prev).next = next_block; }
                    }

                    // Write the allocation header.
                    let header_ptr = (data_start - ALLOC_HEADER_SIZE) as *mut AllocHeader;
                    unsafe {
                        (*header_ptr).block_start = block_addr;
                        (*header_ptr).block_size = block_size;
                    }
                    self.allocated_bytes += block_size;
                }

                return data_start as *mut u8;
            }

            prev = current;
            current = unsafe { (*current).next };
        }

        // Out of memory.
        ptr::null_mut()
    }

    /// Deallocate memory and coalesce adjacent free blocks.
    fn dealloc(&mut self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() || !self.initialized {
            return;
        }

        // Read the allocation header to find the original block.
        let header_ptr = (ptr as usize - ALLOC_HEADER_SIZE) as *const AllocHeader;
        let block_start = unsafe { (*header_ptr).block_start };
        let block_size = unsafe { (*header_ptr).block_size };

        self.allocated_bytes = self.allocated_bytes.saturating_sub(block_size);
        self.insert_free_block(block_start, block_size);
    }

    /// Insert a free block in address-sorted order, coalescing with neighbors.
    fn insert_free_block(&mut self, addr: usize, size: usize) {
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = self.head;

        // Find insertion point (sorted by address).
        while !current.is_null() && (current as usize) < addr {
            prev = current;
            current = unsafe { (*current).next };
        }

        // Write the new free block.
        let new_block = addr as *mut FreeBlock;
        unsafe {
            (*new_block).size = size;
            (*new_block).next = current;
        }

        // Link it into the list.
        if prev.is_null() {
            self.head = new_block;
        } else {
            unsafe { (*prev).next = new_block; }
        }

        // Try to merge with next block.
        if !current.is_null() && addr + size == current as usize {
            unsafe {
                (*new_block).size += (*current).size;
                (*new_block).next = (*current).next;
            }
        }

        // Try to merge with previous block.
        if !prev.is_null() {
            let prev_end = prev as usize + unsafe { (*prev).size };
            if prev_end == addr {
                unsafe {
                    (*prev).size += (*new_block).size;
                    (*prev).next = (*new_block).next;
                }
            }
        }
    }
}

/// Thread-safe wrapper around the heap allocator.
struct LockedHeapAllocator(Mutex<LinkedListAllocator>);

unsafe impl GlobalAlloc for LockedHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = self.0.lock().alloc(layout);
        if !ptr.is_null() {
            crate::perf::record_heap_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::perf::record_heap_free(layout.size());
        self.0.lock().dealloc(ptr, layout)
    }
}

/// Get heap statistics: (total_bytes, allocated_bytes, free_bytes).
pub fn stats() -> (usize, usize, usize) {
    let alloc = ALLOCATOR.0.lock();
    let free = alloc.total_bytes.saturating_sub(alloc.allocated_bytes);
    (alloc.total_bytes, alloc.allocated_bytes, free)
}

/// Initialize the kernel heap.
///
/// Computes the heap base from the linker's `__kernel_end` symbol so the
/// heap follows BSS dynamically (see module docs).  Panics if the heap
/// would extend past 1 GiB phys (outside the bootloader's huge-page map)
/// — this is a build-misconfiguration assertion that catches kernels
/// grown so large they would extend the heap into MMIO territory.
pub fn init() {
    let (va_start, phys_start, phys_end) = compute_heap_layout();

    // Sanity: the bootloader maps phys 0..1 GiB into PML4[256] via 2 MiB
    // huge pages; `vmm::extend_higher_half_to_4gib` later covers 1..4 GiB
    // but that path is for MMIO, not RAM-backed heap.  A heap extending
    // past 1 GiB phys means the kernel image+BSS is multiple-hundred-MiB
    // — investigate before papering over.
    assert!(
        phys_end <= 0x4000_0000,
        "[HEAP] heap layout phys_end={:#x} exceeds 1 GiB — kernel image too large?",
        phys_end,
    );

    HEAP_START_VA.store(va_start, Ordering::Relaxed);
    ALLOCATOR.0.lock().init(va_start, HEAP_SIZE);

    crate::serial_println!(
        "[HEAP] Initialized at {:#x}-{:#x} (phys {:#x}-{:#x}, {} KiB) — linked-list allocator",
        va_start,
        va_start + HEAP_SIZE,
        phys_start,
        phys_end,
        HEAP_SIZE / 1024
    );
}

/// Install 4 KiB guard pages immediately below and above the heap region.
///
/// # Guard layout
/// ```
/// heap_guard_below_va()         (not-present PTE)  ← underflow trap
/// heap_start()                  (heap, 128 MiB)
/// heap_start() + HEAP_SIZE  (= heap_guard_above_va(), not-present PTE) ← overflow trap
/// ```
///
/// # Physical-alias prevention
/// The bootloader maps all physical RAM at both the identity map (PML4[0]) and the
/// higher-half (PML4[256]) using 2 MiB huge pages.  The physical frames that
/// correspond to the guard VAs (`guard_va - PHYS_OFF`) are inside UEFI CONVENTIONAL
/// memory and could normally be handed out by the PMM, which would mean another
/// caller could access them via `PHYS_OFF + phys` even though the guard PTE is
/// not-present — defeating the guard silently.
///
/// To prevent this we call `pmm::reserve_range` on those frames *before* writing
/// the not-present PTEs, so the PMM bitmap marks them as permanently used.  The
/// guard PTEs themselves have no physical backing (PTE value = 0); the reservation
/// merely prevents the direct-map alias.
pub fn init_guard_pages() {
    use crate::mm::{pmm, vmm};

    let below_va    = heap_guard_below_va();
    let above_va    = heap_guard_above_va();
    let below_phys  = heap_guard_below_phys();
    let above_phys  = heap_guard_above_phys();
    let base        = heap_start() as u64;

    debug_assert!(base != 0, "init_guard_pages called before heap::init");

    // Reserve the physical frames for both guard pages.
    // This must happen before installing PTEs so that no racing allocation can
    // grab those frames in the window between the PMM free-mark and the PTE write.
    pmm::reserve_range(below_phys, below_phys + 0x1000);
    pmm::reserve_range(above_phys, above_phys + 0x1000);

    // Install not-present PTEs (creates PT hierarchy, writes PTE = 0).
    if !vmm::install_not_present_guard(below_va) {
        crate::serial_println!("[HEAP GUARD] WARN: failed to install below-guard at {:#x}", below_va);
    }
    if !vmm::install_not_present_guard(above_va) {
        crate::serial_println!("[HEAP GUARD] WARN: failed to install above-guard at {:#x}", above_va);
    }

    crate::serial_println!(
        "[HEAP GUARD] Guard pages installed: below={:#x} above={:#x} (heap {:#x}..{:#x})",
        below_va,
        above_va,
        base,
        base + HEAP_SIZE as u64,
    );
}

/// Align a value up to the given alignment.
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}