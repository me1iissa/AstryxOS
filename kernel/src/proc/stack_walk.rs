//! User-space stack-frame walker for fault-time caller-chain diagnostics.
//!
//! When the kernel terminates a Ring-3 process following a fatal exception
//! (SIGSEGV, SIGILL, SIGBUS, etc.) the faulting RIP names the instruction
//! that trapped but gives no information about the call chain that led
//! there.  This module walks the RBP-linked frame chain from the kernel
//! exception handler, emitting up to `MAX_DEPTH` frames as structured
//! `[STACK]` / `[STACK/VMA]` log lines without acquiring any blocking lock.
//!
//! ## Frame layout (System V AMD64 ABI §3.4.1)
//!
//! With `-fno-omit-frame-pointer` (the default for Mozilla libxul and most
//! system libraries), every frame satisfies:
//!
//! ```text
//!   [rbp + 0]  = saved RBP of caller frame
//!   [rbp + 8]  = return address (saved RIP of caller)
//! ```
//!
//! The chain terminates when `saved_rbp` is zero (bottom of the main thread
//! stack) or when any sanity guard fires.
//!
//! ## Safety model
//!
//! All user-memory reads go through `read_user_u64`, which performs the
//! 4-level page-table walk using the process's CR3 (passed in by the
//! caller) and reads the physical frame via the kernel's direct physical map
//! (`PHYS_OFF`).  No `unsafe { ptr::read }` on a user virtual address is
//! ever issued.  A page-table miss results in an `Err` return and terminates
//! the walk gracefully rather than causing a nested kernel fault.
//!
//! ## Lock ordering
//!
//! `stack_walk_user` does NOT hold `PROCESS_TABLE`.  The caller is expected
//! to have already dropped it (the same discipline used by `emit_signal_vma_banner`
//! and the `[UD/VMA]` emission block).  VMA resolution acquires
//! `PROCESS_TABLE` briefly per frame; this is the same pattern used by the
//! existing Ring-3 diagnostics.
//!
//! ## Output format
//!
//! ```text
//! [STACK] pid=1 tid=3 depth=0 rip=0x7efff... rbp=0x7fff... (faulting frame)
//! [STACK/VMA] pid=1 tid=3 depth=0 rip=0x7efff... vma_base=0x7efff... vma_end=0x7f000... file=libxul.so offset_in_vma=0x1234 offset_in_file=0x1234 vaddr_in_elf=0x5678
//! [STACK] pid=1 tid=3 depth=1 rip=0x7effa... rbp=0x7fff...
//! [STACK/VMA] pid=1 tid=3 depth=1 rip=0x7effa... vma_base=...
//! ...
//! [STACK] terminated reason=saved_rbp_zero depth=N
//! ```

/// Highest user-space virtual address (exclusive).  Identical to
/// `signal::USER_ADDR_END`; repeated here to keep this module self-contained.
const USER_ADDR_END: u64 = 0x0000_8000_0000_0000;

/// Physical-to-virtual offset for the kernel's direct physical map.
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Maximum number of frames emitted.  Capped to bound serial output per fault.
const MAX_DEPTH: usize = 20;

/// Minimum valid user-space address.  Addresses below this (within the first
/// page) are always invalid; catching NULL-derived offsets early avoids a
/// pointless page-table walk.
const USER_ADDR_MIN: u64 = 0x1000;

/// Read a `u64` from the user address `va` in the page table rooted at
/// `cr3`, using the direct physical map for the actual memory access.
///
/// Returns `Ok(value)` if the address is mapped and readable, `Err(())`
/// if the page-table walk finds no present mapping.
///
/// The read is performed as a volatile load to prevent the compiler from
/// speculating the access across an absent page.
#[inline]
fn read_user_u64(cr3: u64, va: u64) -> Result<u64, ()> {
    match crate::mm::vmm::virt_to_phys_in(cr3, va) {
        Some(phys) => {
            // SAFETY: `phys` is a valid physical address returned by the page-
            // table walker.  `PHYS_OFF + phys` is within the kernel's direct
            // physical map, which covers all installed RAM.  The volatile load
            // prevents the compiler from hoisting this past the page-table check.
            let val = unsafe {
                core::ptr::read_volatile((PHYS_OFF + phys) as *const u64)
            };
            Ok(val)
        }
        None => Err(()),
    }
}

/// Attempt to read a `u64` from `va`; if the first 8-byte word spans a page
/// boundary, each byte is read separately via individual physical translations.
///
/// Most frame-pointer reads are naturally aligned (the ABI requires RSP to be
/// 16-byte aligned at call sites), but this handles the rare cross-page case
/// without a kernel fault.
#[inline]
fn read_user_u64_safe(cr3: u64, va: u64) -> Result<u64, ()> {
    // Fast path: both start and end are on the same 4 KiB page.
    let page_start = va & !0xFFF;
    let page_end   = (va + 7) & !0xFFF;
    if page_start == page_end {
        return read_user_u64(cr3, va);
    }
    // Slow path: 8 bytes straddle a page boundary — read byte-by-byte.
    let mut buf = [0u8; 8];
    for i in 0..8u64 {
        match crate::mm::vmm::virt_to_phys_in(cr3, va + i) {
            Some(phys) => {
                buf[i as usize] = unsafe {
                    core::ptr::read_volatile((PHYS_OFF + phys) as *const u8)
                };
            }
            None => return Err(()),
        }
    }
    Ok(u64::from_le_bytes(buf))
}

/// Emit a `[STACK/VMA]` line for the given `rip` at the specified `depth`.
///
/// Acquires `PROCESS_TABLE` briefly via `find_vma_with_parent_fallback`,
/// which transparently consults the parent's VmSpace for a CLONE_VM child
/// (whose own bookkeeping is intentionally empty — see `clone(2)` /
/// `vfork(2)` "CLONE_VM").  The lock is dropped before calling
/// `serial_println!` (COM1 is slow and must not be held across the
/// spinlock; identical discipline to `emit_signal_vma_banner`).
fn emit_stack_vma_line(pid: u64, tid: u64, depth: usize, rip: u64) {
    // ── Phase 1: snapshot VMA data under the lock ────────────────────────────
    let hit = crate::proc::find_vma_with_parent_fallback(pid, rip);

    // ── Phase 2: emit after the lock is released ─────────────────────────────
    let v = match hit {
        None => {
            crate::serial_println!(
                "[STACK/VMA] pid={} tid={} depth={} rip={:#x} no_vma=1",
                pid, tid, depth, rip,
            );
            return;
        }
        Some(v) => v,
    };
    let offset_in_vma = rip - v.vma_base;
    let offset_in_file = if v.file_backed {
        v.file_offset + offset_in_vma
    } else {
        0
    };
    let vaddr_in_elf = if v.file_backed && v.elf_load_delta != 0 {
        offset_in_file.wrapping_add(v.elf_load_delta)
    } else {
        0
    };
    // Suffix marks a parent-inherited (CLONE_VM child) resolution so a
    // reader can tell at a glance that the diagnostic walked the parent's
    // bookkeeping rather than the child's own.
    let suffix = if v.inherited { " inherited_from_parent=1" } else { "" };
    if v.file_backed && vaddr_in_elf != 0 {
        crate::serial_println!(
            "[STACK/VMA] pid={} tid={} depth={} rip={:#x} \
             vma_base={:#x} vma_end={:#x} file={} \
             offset_in_vma={:#x} offset_in_file={:#x} vaddr_in_elf={:#x}{}",
            pid, tid, depth, rip,
            v.vma_base, v.vma_end, v.name,
            offset_in_vma, offset_in_file, vaddr_in_elf, suffix,
        );
    } else if v.file_backed {
        crate::serial_println!(
            "[STACK/VMA] pid={} tid={} depth={} rip={:#x} \
             vma_base={:#x} vma_end={:#x} file={} \
             offset_in_vma={:#x} offset_in_file={:#x}{}",
            pid, tid, depth, rip,
            v.vma_base, v.vma_end, v.name,
            offset_in_vma, offset_in_file, suffix,
        );
    } else {
        // Anonymous or device mapping.
        crate::serial_println!(
            "[STACK/VMA] pid={} tid={} depth={} rip={:#x} \
             vma_base={:#x} vma_end={:#x} file=<anon> offset_in_vma={:#x}{}",
            pid, tid, depth, rip,
            v.vma_base, v.vma_end, offset_in_vma, suffix,
        );
    }
}

/// Walk the user-space RBP-linked frame chain starting from the faulting
/// frame and emit up to `MAX_DEPTH` frames as `[STACK]` / `[STACK/VMA]`
/// log lines.
///
/// # Arguments
///
/// * `pid`  — Process ID, used to tag log lines and look up the VmSpace.
/// * `tid`  — Thread ID, used to tag log lines.
/// * `rip0` — RIP at the faulting instruction (depth-0 frame).
/// * `rbp0` — RBP at the faulting instruction (depth-0 frame).
///
/// CR3 is read from the hardware register inside this function.  The
/// exception handler must not have switched CR3 before calling; in
/// practice, all Ring-3 exception paths stay on the process CR3 until
/// `exit_group` tears down the address space.
///
/// # Termination conditions
///
/// The walk stops (emitting a `[STACK] terminated reason=…` line) when:
///
/// * `rbp` is zero (bottom of the main-thread stack, as set by the C
///   runtime or dynamic linker entry point).
/// * `rbp` is not 8-byte aligned (corrupted or non-frame-pointer code).
/// * `rbp` is outside `[USER_ADDR_MIN, USER_ADDR_END)`.
/// * Reading `[rbp+0]` or `[rbp+8]` fails (unmapped page).
/// * `saved_rbp <= rbp` (frames must advance toward higher addresses as
///   the stack grows downward — violation means corrupted chain or a leaf
///   function compiled without a frame pointer).
/// * `MAX_DEPTH` frames have been emitted.
///
/// # Lock ordering
///
/// This function must NOT be called while `PROCESS_TABLE` is held.
/// It briefly acquires and releases it once per frame for VMA resolution
/// (the same discipline used by `emit_signal_vma_banner`).
pub fn stack_walk_user(pid: u64, tid: u64, rip0: u64, rbp0: u64) {
    // Read the current page-table root.  Intel SDM Vol. 3A §2.5: CR3
    // holds the physical base address of the PML4 table.  Reading it at
    // CPL 0 (inside the exception handler) reflects the process's own
    // address space because no CR3 switch has occurred yet.
    let cr3: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)); }
    let cr3 = cr3 & crate::mm::vmm::ADDR_MASK;
    // ── Depth-0: the faulting frame itself ──────────────────────────────────
    crate::serial_println!(
        "[STACK] pid={} tid={} depth=0 rip={:#x} rbp={:#x} (faulting frame)",
        pid, tid, rip0, rbp0,
    );
    if rip0 >= USER_ADDR_MIN && rip0 < USER_ADDR_END {
        emit_stack_vma_line(pid, tid, 0, rip0);
    }

    let mut rbp = rbp0;

    for depth in 1..MAX_DEPTH {
        // ── Sanity: rbp must be a plausible user-space frame-pointer ────────
        if rbp == 0 {
            crate::serial_println!(
                "[STACK] terminated reason=saved_rbp_zero depth={}",
                depth,
            );
            break;
        }
        if rbp & 0x7 != 0 {
            crate::serial_println!(
                "[STACK] terminated reason=rbp_misaligned depth={} rbp={:#x}",
                depth, rbp,
            );
            break;
        }
        if rbp < USER_ADDR_MIN || rbp >= USER_ADDR_END {
            crate::serial_println!(
                "[STACK] terminated reason=rbp_out_of_range depth={} rbp={:#x}",
                depth, rbp,
            );
            break;
        }

        // ── Read saved RBP at [rbp+0] ────────────────────────────────────────
        let saved_rbp = match read_user_u64_safe(cr3, rbp) {
            Ok(v) => v,
            Err(_) => {
                crate::serial_println!(
                    "[STACK] terminated reason=read_fault_rbp depth={} rbp={:#x}",
                    depth, rbp,
                );
                break;
            }
        };

        // ── Read saved RIP at [rbp+8] ────────────────────────────────────────
        let saved_rip = match read_user_u64_safe(cr3, rbp + 8) {
            Ok(v) => v,
            Err(_) => {
                crate::serial_println!(
                    "[STACK] terminated reason=read_fault_rip depth={} rbp={:#x}",
                    depth, rbp,
                );
                break;
            }
        };

        // ── Emit this frame ──────────────────────────────────────────────────
        crate::serial_println!(
            "[STACK] pid={} tid={} depth={} rip={:#x} rbp={:#x}",
            pid, tid, depth, saved_rip, saved_rbp,
        );
        if saved_rip >= USER_ADDR_MIN && saved_rip < USER_ADDR_END {
            emit_stack_vma_line(pid, tid, depth, saved_rip);
        } else if saved_rip != 0 {
            // Kernel address or zero in the return slot — log but don't walk VMA.
            crate::serial_println!(
                "[STACK/VMA] pid={} tid={} depth={} rip={:#x} out_of_user_range=1",
                pid, tid, depth, saved_rip,
            );
        }

        // ── Advance: stack grows downward so valid saved_rbp > current rbp ──
        // Per System V AMD64 ABI §3.4.1: the frame pointer of any callee
        // frame is at a higher address than the frame pointer of its caller.
        if saved_rbp <= rbp {
            crate::serial_println!(
                "[STACK] terminated reason=frame_did_not_advance depth={} \
                 rbp={:#x} saved_rbp={:#x}",
                depth + 1, rbp, saved_rbp,
            );
            break;
        }

        rbp = saved_rbp;
    }
}
