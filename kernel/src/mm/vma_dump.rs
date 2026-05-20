//! `[VMA-DUMP]` — full address-space snapshot emitter for fatal user-mode
//! exceptions.  Used by the `vma-dump-on-gp` feature to anchor PIE-ASLR
//! bases (libxul, ld-musl, anonymous JIT regions, heap, stacks) at the
//! moment the kernel decides to deliver SIGSEGV / SIGBUS / SIGILL to a
//! firefox-test process.
//!
//! Distinct from the existing `[SIGNAL/VMA]` and `[FAULT/PHYS]` diagnostic
//! channels:
//!
//!   * `[SIGNAL/VMA]` (see `signal::signal_vma_snapshot`) emits at most
//!     8 entries — only RIP-containing, CR2-containing, and executable
//!     file-backed neighbours.  Sufficient for symbolicating the trap
//!     site itself, **insufficient** for cross-anchoring a stack-residue
//!     address against the heap or anonymous JIT VMAs.
//!
//!   * `[FAULT/PHYS]` reports the physical frame backing the RIP page
//!     and the in-VMA offset — useful for the aliasing-class hypotheses
//!     (W190/W196/W215) but does not enumerate the address space.
//!
//! `[VMA-DUMP]` emits every VMA up to a 1024-line paranoia cap, including
//! anonymous mappings, stacks, and heap, with the physical frame backing
//! the first page of each VMA.  Cap raised from 256 → 1024 per empirical
//! measurement 2026-05-20 (sid=059b127fb103): firefox-bin clone-VM child
//! exceeds 256 VMAs at trap time.
//!
//! ## Emission cap
//!
//! Capped at **4 dumps per boot** via `VMA_DUMP_EMISSIONS`.  Each dump
//! emits one `[VMA-DUMP-BEGIN]` banner, up to 1024 `[VMA-DUMP]` rows, and
//! one `[VMA-DUMP-END]` banner.  After the 4th dump the helper becomes a
//! no-op.  This bounds the serial volume even under a fault storm.
//!
//! ## Line format
//!
//! ```text
//! [VMA-DUMP-BEGIN] pid=<n> tid=<n> cr3=<paddr> vma_count=<n>
//! [VMA-DUMP] pid=<n> tid=<n> idx=<i> base=<vaddr> end=<vaddr> size=<bytes> prot=<rwx> file=<0|1> anon=<0|1> name="<label>" first_page_phys=<paddr|UNMAPPED> [file_offset=<off> elf_load_delta=<delta> mount=<idx> inode=<inode>]
//! [VMA-DUMP-END] pid=<n> tid=<n>
//! ```
//!
//! Field semantics mirror the existing `kdb procmaps` op
//! (`kdb::op_procmaps`) so a harness consumer that already parses one
//! can parse the other with trivial pattern adjustment.
//!
//! ## ISR safety
//!
//! Acquires `proc::PROCESS_TABLE` for the snapshot, releases before
//! `serial_println!`.  Mirrors `signal::emit_fault_phys_for_fatal`'s
//! lock order — both run from the same fatal-fault ISR paths and have
//! coexisted with no deadlock since PR #197.  No allocator use on the
//! hot path: VMA fields are copied into a local stack buffer (one entry
//! at a time, written then printed) so the dump is allocation-free.
//!
//! ## Specs
//!
//! Cite: Intel SDM Vol. 3A §6.15 (`#GP`), §4.5 (4-Level Paging),
//! POSIX `mmap(2)` (`PROT_READ`/`WRITE`/`EXEC`), ELF-64 gABI §3
//! (Program Loading).  No reference-corpus citation.

#![cfg(feature = "vma-dump-on-gp")]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

/// Max `[VMA-DUMP-BEGIN]…END` dumps emitted per boot.  See module docs.
const MAX_VMA_DUMPS_PER_BOOT: u32 = 4;

/// Max VMA rows per dump.  Bounded so a runaway VmSpace with thousands
/// of micro-VMAs cannot flood the serial port.  Empirical measurement
/// 2026-05-20 (sid=059b127fb103) shows the firefox-bin clone-VM child's
/// VmSpace contains >256 VMAs at trap time and a 256-cap truncates
/// before the RIP-covering VMA, defeating the diagnostic's purpose.
/// Raised to 1024 to cover the observed worst case plus headroom.  At
/// ~256 chars/line × 4 dumps/boot the absolute serial-volume cap is
/// ~1 MiB — well within the harness's serial-log capacity.
const MAX_VMAS_PER_DUMP: usize = 1024;

/// Per-boot emission counter.  Each fatal user-mode exception with the
/// `vma-dump-on-gp` feature live consumes one slot.  `Relaxed` ordering
/// is fine: the counter is only used for rate-limiting, never for any
/// happens-before relationship.
static VMA_DUMP_EMISSIONS: AtomicU32 = AtomicU32::new(0);

/// Emit a full VMA snapshot for the trapping process.
///
/// Called from the fatal-#PF and fatal-#UD/#GP/#AC handlers in
/// `arch/x86_64/idt.rs` immediately after `[FAULT/PHYS]`.  Bounded by
/// `MAX_VMA_DUMPS_PER_BOOT`.
///
/// `pid` is the trapping process; `cr3` is the live CR3 read in ISR
/// context (always equal to the trapping process's PML4 phys).
///
/// For CLONE_VM children whose own `vm_space` is `None` (see
/// `signal::emit_fault_phys_for_fatal` for the matching pattern), we
/// fall back to the parent's VmSpace — that is the address space the
/// child is actually executing in.
pub fn dump_for_fault(pid: u64, cr3: u64) {
    // Bounded emission: bump the counter; if we exceed the cap, bail
    // before touching PROCESS_TABLE.  `fetch_add` semantics: we always
    // increment, so once the cap is hit the counter stays above it and
    // every subsequent call returns immediately.
    let n = VMA_DUMP_EMISSIONS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_VMA_DUMPS_PER_BOOT {
        return;
    }

    let tid = crate::proc::current_tid();

    // Snapshot under PROCESS_TABLE; clone the VMA fields out so we can
    // release the lock before any serial_println!.  Each entry is small
    // (5 × u64 + a &'static str + flags), so the local Vec stays well
    // under one page even at the 256-entry cap.
    struct Row {
        base: u64,
        end: u64,
        prot: u32,
        name: &'static str,
        file_backed: bool,
        anonymous: bool,
        file_offset: u64,
        elf_load_delta: u64,
        mount_idx: usize,
        inode: u64,
        first_page_phys: Option<u64>,
    }

    let rows: alloc::vec::Vec<Row> = {
        use crate::mm::vma::VmBacking;
        let procs = crate::proc::PROCESS_TABLE.lock();
        let p = procs.iter().find(|p| p.pid == pid);
        let direct_space = p.and_then(|p| p.vm_space.as_ref());
        // CLONE_VM fallback: a child with shared CR3 and no own VmSpace
        // runs in the parent's address space; report the parent's VMAs.
        // Mirrors `signal::emit_fault_phys_for_fatal`'s lookup.
        let space = if direct_space.is_some() {
            direct_space
        } else if let Some(c) = p {
            let parent_pid = c.parent_pid;
            let cr3_child = c.cr3;
            procs
                .iter()
                .find(|q| q.pid == parent_pid && q.cr3 == cr3_child && cr3_child != 0)
                .and_then(|q| q.vm_space.as_ref())
        } else {
            None
        };

        let mut out: alloc::vec::Vec<Row> = alloc::vec::Vec::new();
        if let Some(space) = space {
            for a in space.areas.iter().take(MAX_VMAS_PER_DUMP) {
                let (file_backed, file_offset, elf_load_delta, mount_idx, inode) = match a.backing {
                    VmBacking::File {
                        offset,
                        elf_load_delta,
                        mount_idx,
                        inode,
                    } => (true, offset, elf_load_delta, mount_idx, inode),
                    _ => (false, 0u64, 0u64, 0usize, 0u64),
                };
                let anonymous = matches!(a.backing, VmBacking::Anonymous);
                let first_page_phys = crate::mm::vmm::virt_to_phys_in(cr3, a.base);
                out.push(Row {
                    base: a.base,
                    end: a.end(),
                    prot: a.prot,
                    name: a.name,
                    file_backed,
                    anonymous,
                    file_offset,
                    elf_load_delta,
                    mount_idx,
                    inode,
                    first_page_phys,
                });
            }
        }
        out
    };

    // ── Emit ────────────────────────────────────────────────────────────────
    crate::serial_println!(
        "[VMA-DUMP-BEGIN] pid={} tid={} cr3={:#x} vma_count={}",
        pid,
        tid,
        cr3,
        rows.len(),
    );
    for (i, r) in rows.iter().enumerate() {
        let mut fb = [b'-'; 3];
        if r.prot & crate::mm::vma::PROT_READ != 0 {
            fb[0] = b'r';
        }
        if r.prot & crate::mm::vma::PROT_WRITE != 0 {
            fb[1] = b'w';
        }
        if r.prot & crate::mm::vma::PROT_EXEC != 0 {
            fb[2] = b'x';
        }
        let prot_str = core::str::from_utf8(&fb).unwrap_or("---");
        match r.first_page_phys {
            Some(phys) if r.file_backed => {
                crate::serial_println!(
                    "[VMA-DUMP] pid={} tid={} idx={} base={:#x} end={:#x} size={:#x} prot={} file=1 anon=0 name=\"{}\" first_page_phys={:#x} file_offset={:#x} elf_load_delta={:#x} mount={} inode={:#x}",
                    pid, tid, i, r.base, r.end, r.end - r.base, prot_str, r.name,
                    phys, r.file_offset, r.elf_load_delta, r.mount_idx, r.inode,
                );
            }
            None if r.file_backed => {
                crate::serial_println!(
                    "[VMA-DUMP] pid={} tid={} idx={} base={:#x} end={:#x} size={:#x} prot={} file=1 anon=0 name=\"{}\" first_page_phys=UNMAPPED file_offset={:#x} elf_load_delta={:#x} mount={} inode={:#x}",
                    pid, tid, i, r.base, r.end, r.end - r.base, prot_str, r.name,
                    r.file_offset, r.elf_load_delta, r.mount_idx, r.inode,
                );
            }
            Some(phys) => {
                crate::serial_println!(
                    "[VMA-DUMP] pid={} tid={} idx={} base={:#x} end={:#x} size={:#x} prot={} file=0 anon={} name=\"{}\" first_page_phys={:#x}",
                    pid, tid, i, r.base, r.end, r.end - r.base, prot_str,
                    r.anonymous as u8, r.name, phys,
                );
            }
            None => {
                crate::serial_println!(
                    "[VMA-DUMP] pid={} tid={} idx={} base={:#x} end={:#x} size={:#x} prot={} file=0 anon={} name=\"{}\" first_page_phys=UNMAPPED",
                    pid, tid, i, r.base, r.end, r.end - r.base, prot_str,
                    r.anonymous as u8, r.name,
                );
            }
        }
    }
    crate::serial_println!("[VMA-DUMP-END] pid={} tid={}", pid, tid);
}
