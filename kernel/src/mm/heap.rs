//! Kernel Heap Allocator
//!
//! Linked-list free-list allocator for the kernel heap.
//! Supports proper allocation and deallocation with coalescing of adjacent free blocks.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use spin::Mutex;

/// Kernel heap start address.
///
/// Placed in the higher-half mapping (PML4 entry 256) at the virtual address
/// corresponding to physical 4 MiB.  This keeps the heap accessible even when
/// CR3 points to a user-process page table (which clones PML4 entries 256-511
/// from the kernel) while leaving the identity-mapped low-address range free
/// for user ELF segment mappings.
const HEAP_START: usize = 0xFFFF_8000_0040_0000;
/// Kernel heap size: 128 MiB (sufficient for 1920×1080 GUI with multiple window surfaces).
const HEAP_SIZE: usize = 128 * 1024 * 1024;

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
pub fn init() {
    ALLOCATOR.0.lock().init(HEAP_START, HEAP_SIZE);
    crate::serial_println!(
        "[HEAP] Initialized at 0x{:x}-0x{:x} ({} KiB) — linked-list allocator",
        HEAP_START,
        HEAP_START + HEAP_SIZE,
        HEAP_SIZE / 1024
    );
}

/// Align a value up to the given alignment.
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}