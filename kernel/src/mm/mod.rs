//! Memory Management Subsystem
//!
//! Provides physical memory management (PMM), virtual memory management (VMM),
//! and kernel heap allocation.

pub mod cache;
pub mod dma_pin;
pub mod heap;
pub mod oom;
pub mod pmm;
pub mod refcount;
pub mod tlb;
pub mod vma;
pub mod vmm;
// File-struct buffer corruption witness for the B-1 gate (musl
// `memchr+0x31` NULL-deref).  Always-built (no feature gate on the
// module declaration) so call sites compile in both configurations;
// the witness body is feature-gated to `file-buf-witness` and emits
// nothing in default builds.  Cite: musl 1.2.5 public FILE layout,
// Intel SDM Vol. 3A §4.10.5 (TLB invariants).  See module-level doc.
pub mod file_buf_witness;
// W215 Arm-1 diagnostic (CRC walker + DR plumbing).  Gated behind
// `w215-diag` (a strict superset of `firefox-test`) so the 2 MiB
// shadow-table BSS is only present when the diagnostic is requested.
// See `Cargo.toml` for the underlying PMM-vs-BSS rationale.
#[cfg(feature = "w215-diag")]
pub mod w215_crc;
#[cfg(feature = "firefox-test-core")]
pub mod w215_diag;
// PSE 2026-05-20: `[VMA-DUMP]` on fatal user-mode exceptions.  Used by
// `vma-dump-on-gp` to anchor PIE-ASLR bases at the moment a process is
// torn down.  See `vma_dump.rs` for line format and emission cap.
#[cfg(feature = "vma-dump-on-gp")]
pub mod vma_dump;

// Stack-page write provenance ring — F3 BUCKET writer attribution.
// Records kernel-mode writes to user VAs in the 0x3f thread-stack range
// (`[0x3f00_0000_0000, 0x4000_0000_0000)` per Phase 4 `phase_4_post_aslr…`
// memory).  Dumped at `[SSP-DIAG-STACK-PROV]` time keyed on
// `saved_slot_phys`.  Closes the kernel-direct-map blind spot of the
// `f3-watch` linear-VA DR0–DR3 channel (Intel SDM Vol. 3B §17.2.4).
// Diagnostic-only; gated behind `stack-prov` so default builds are
// byte-identical to master.
#[cfg(feature = "stack-prov")]
pub mod stack_prov;

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
    // DMA pin ledger — holds device-owned frames out of PMM reuse while an
    // in-flight transfer references them (VIRTIO 1.2 §2.7.13.3).  Must follow
    // heap+refcount init: it heap-allocates its per-PFN table.
    dma_pin::init();

    // Every boot-time frame reservation has now run (kernel image and low
    // 1 MiB in `pmm::init`; the static kernel heap and its guard frames in
    // `vmm::init` / `heap::init_guard_pages`).  Report the accounting the rest
    // of the system reads, and cross-check the counters against the bitmap
    // they describe: `alloc_page` succeeds or fails on the bitmap alone, so a
    // non-zero drift means every free-memory readout on the machine
    // (`/proc/meminfo`, sysinfo(2), the page-cache low-memory guard) is
    // quoting memory the allocator cannot produce.
    let acct = pmm::accounting_snapshot();
    crate::serial_println!(
        "[PMM] Accounting: total={} pages ({} MiB) reserved={} ({} MiB) used={} \
         free={} ({} MiB) bitmap_free={} drift={}",
        acct.total,
        acct.total * 4 / 1024,
        acct.reserved,
        acct.reserved * 4 / 1024,
        acct.used,
        acct.counter_free,
        acct.counter_free * 4 / 1024,
        acct.bitmap_free,
        acct.drift(),
    );
    if acct.drift() != 0 {
        crate::serial_println!(
            "[PMM] WARN: free-frame counter disagrees with the bitmap by {} pages \
             — free-memory readouts are wrong by that much",
            acct.drift(),
        );
    }

    crate::serial_println!("[MM] Memory management subsystem initialized");
}
