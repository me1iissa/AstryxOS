//! Memory Management Subsystem
//!
//! Provides physical memory management (PMM), virtual memory management (VMM),
//! and kernel heap allocation.

pub mod cache;
pub mod heap;
pub mod oom;
pub mod pmm;
pub mod refcount;
pub mod tlb;
pub mod vma;
pub mod vmm;
// W215 Arm-1 diagnostic (CRC walker + DR plumbing).  Gated behind
// `w215-diag` (a strict superset of `firefox-test`) so the 2 MiB
// shadow-table BSS is only present when the diagnostic is requested.
// See `Cargo.toml` for the underlying PMM-vs-BSS rationale.
#[cfg(feature = "w215-diag")]
pub mod w215_crc;
#[cfg(feature = "firefox-test")]
pub mod w215_diag;
// PSE 2026-05-20: `[VMA-DUMP]` on fatal user-mode exceptions.  Used by
// `vma-dump-on-gp` to anchor PIE-ASLR bases at the moment a process is
// torn down.  See `vma_dump.rs` for line format and emission cap.
#[cfg(feature = "vma-dump-on-gp")]
pub mod vma_dump;

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
