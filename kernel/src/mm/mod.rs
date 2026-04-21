//! Memory Management Subsystem
//!
//! Provides physical memory management (PMM), virtual memory management (VMM),
//! and kernel heap allocation.

pub mod cache;
pub mod heap;
pub mod oom;
pub mod pmm;
pub mod refcount;
pub mod vma;
pub mod vmm;

use astryx_shared::BootInfo;

/// Initialize the memory management subsystem.
pub fn init(boot_info: &BootInfo) {
    crate::serial_println!("[MM] Starting PMM init...");
    pmm::init(boot_info);
    crate::serial_println!("[MM] PMM done, starting VMM init...");
    vmm::init();
    crate::serial_println!("[MM] VMM done, starting heap init...");
    heap::init();
    crate::serial_println!("[MM] Heap done, installing heap guard pages...");
    heap::init_guard_pages();
    crate::serial_println!("[MM] Heap guard pages installed, starting refcount init...");
    refcount::init();
    crate::serial_println!("[MM] Memory management subsystem initialized");
}
