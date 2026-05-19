//! Vfork canary snapshot-pair + sibling-syscall tagger diagnostic.
//!
//! Diagnostic-only instrumentation that names the writer of the parent's SSP
//! canary slots during the `CLONE_VM|CLONE_VFORK` window.  No functional
//! behaviour change — every code path here is gated behind the
//! `vfork-canary-diag` Cargo feature.
//!
//! # Channels
//!
//!  1. **Parent saved-canary `[rbp-8]` snapshot pair** — at vfork pre-block /
//!     post-wake, read the canary slot that the parent's *caller* frame
//!     stored in its function prologue (`mov rax, fs:0x28 ; mov [rbp-8], rax`).
//!     The parent's RBP at syscall entry points at the libc syscall wrapper's
//!     frame; chasing one saved-RBP link lands at the libxul caller's frame,
//!     whose `[rbp-8]` slot is the SSP location the epilogue will re-read.
//!     Per System V AMD64 ABI §3.4.5.2 + GCC SSP convention.
//!
//!  2. **Master canary `%fs:0x28` snapshot pair** — at the same two points,
//!     re-read the live `IA32_FS_BASE` MSR (Intel SDM Vol. 3A §6.8) plus
//!     `*(fs_base + 0x28)`.  Divergence across the window means the master
//!     canary itself was rewritten, not just an individual stack copy.
//!
//!  3. **Sibling-thread syscall tagging** — between the vfork-block and the
//!     parent's wake, every syscall entry from a thread whose
//!     `(tid != parent.tid && pid == parent.pid)` emits a `[VFORK-SIB]`
//!     line carrying its RIP, RSP, syscall number, and CR3.  Bounded at
//!     200 lines per vfork window via a `static AtomicUsize` counter that
//!     is reset on each window enter.
//!
//! # Why a separate module
//!
//! This file owns all of the vfork-window state so the snapshot helper can
//! call `enter_vfork_window` / `exit_vfork_window` without crossing module
//! boundaries, and so the per-syscall hot path
//! (`maybe_log_sibling_syscall`) can be a single inline atomic load with
//! no string formatting on the off-path (i.e. when no vfork is active).
//!
//! # Refs
//!  - POSIX vfork(2): pubs.opengroup.org/onlinepubs/9699919799/functions/vfork.html
//!  - POSIX clone(2): linux man-pages-5.13 clone(2)
//!  - Intel SDM Vol. 3A §6.8 (IA32_FS_BASE MSR)
//!  - System V AMD64 ABI §3.4.5.2 (SSP / stack-protector frame layout)

#![cfg(feature = "vfork-canary-diag")]

extern crate alloc;

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Active vfork-window parent identity, packed as `(pid << 32) | (tid & 0xFFFF_FFFF)`.
/// Zero = no vfork in flight.  Single AtomicU64 instead of two atomics so that
/// `maybe_log_sibling_syscall` can do a single relaxed load on the fast path.
static VFORK_ACTIVE_PACKED: AtomicU64 = AtomicU64::new(0);

/// Bounded per-window sibling-syscall log counter.  Reset to 0 on
/// `enter_vfork_window`.  Capped at `MAX_SIB_LOGS` to keep serial-log volume
/// bounded even if the parent stays blocked for many seconds.
static SIB_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Hard cap on `[VFORK-SIB]` lines per vfork window.
const MAX_SIB_LOGS: usize = 200;

/// Begin tracking the vfork window.  Stores the parent's identity for the
/// sibling-syscall tagger and resets the per-window log budget.
///
/// Safe to call from the parent's syscall body just before `schedule()`.
pub fn enter_vfork_window(parent_pid: u64, parent_tid: u64) {
    let packed = (parent_pid << 32) | (parent_tid & 0xFFFF_FFFF);
    VFORK_ACTIVE_PACKED.store(packed, Ordering::Release);
    SIB_LOG_COUNT.store(0, Ordering::Release);
    crate::serial_println!(
        "[VFORK-WIN-ENTER] parent_pid={} parent_tid={}",
        parent_pid, parent_tid
    );
}

/// End tracking.  Subsequent sibling-syscall checks become no-ops.
pub fn exit_vfork_window() {
    let prev = VFORK_ACTIVE_PACKED.swap(0, Ordering::AcqRel);
    let logs = SIB_LOG_COUNT.load(Ordering::Acquire);
    let prev_pid = prev >> 32;
    let prev_tid = prev & 0xFFFF_FFFF;
    crate::serial_println!(
        "[VFORK-WIN-EXIT] parent_pid={} parent_tid={} sib_logs_total={}",
        prev_pid, prev_tid, logs
    );
}

/// Sibling-syscall tagger.  Called once per syscall entry from the Linux
/// dispatcher.  Off-path cost is a single relaxed atomic load + branch.
///
/// When a vfork window is active AND the calling thread is in the parent's
/// process AND the calling thread is NOT the parent thread itself, emit one
/// `[VFORK-SIB]` line (bounded at `MAX_SIB_LOGS` lines per window).
///
/// `caller_rip` is the leaf user RIP (from `get_user_rip`) — i.e. the
/// instruction immediately after the `syscall` instruction.  `user_rsp` is
/// the userland stack pointer at syscall entry.
#[inline]
pub fn maybe_log_sibling_syscall(syscall_nr: u64) {
    let packed = VFORK_ACTIVE_PACKED.load(Ordering::Acquire);
    if packed == 0 {
        return; // No vfork window active — fast path.
    }
    let parent_pid = packed >> 32;
    let parent_tid = packed & 0xFFFF_FFFF;

    let my_pid = crate::proc::current_pid_lockless();
    let my_tid = crate::proc::current_tid();

    // Same-process, different-thread (the parent itself is blocked on
    // schedule() while the window is open, so its own syscalls cannot reach
    // here; but the explicit tid check guards against any future relaxation
    // of that invariant).
    if my_pid != parent_pid || my_tid == parent_tid {
        return;
    }

    let n = SIB_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_SIB_LOGS {
        // Once cap is hit, emit one summary line and then silently drop.
        if n == MAX_SIB_LOGS {
            crate::serial_println!(
                "[VFORK-SIB-CAP] parent_pid={} parent_tid={} cap={}",
                parent_pid, parent_tid, MAX_SIB_LOGS
            );
        }
        return;
    }

    // Read the sibling thread's userland frame.  `get_user_rsp_rbp` returns
    // (user_rsp, user_rbp); `get_user_rip` returns the RIP stashed by the
    // syscall stub before dispatch.
    let user_rip = unsafe { crate::syscall::get_user_rip() };
    let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
    let cr3 = crate::mm::vmm::get_cr3();

    crate::serial_println!(
        "[VFORK-SIB] parent_pid={} parent_tid={} sib_tid={} sib_pid={} \
         nr={} rip={:#x} rsp={:#x} rbp={:#x} cr3={:#x} idx={}",
        parent_pid, parent_tid, my_tid, my_pid,
        syscall_nr, user_rip, user_rsp, user_rbp, cr3, n
    );
}

/// Three-channel canary snapshot.  Emits:
///   `[VFORK-CANARY-PRE/POST]   pid=… tid=… rbp=… saved_canary_addr=… \
///                              saved_canary_val=… saved_canary_phys=…`
///   `[VFORK-FSCANARY-PRE/POST] pid=… tid=… fs_base=… fs28_addr=… \
///                              fs28_val=… fs28_phys=…`
///
/// `label` is one of `"PRE"` / `"POST"` and selects the line-tag suffix.
/// The function reads the parent's userland frame to locate `[rbp-8]`; if
/// the chain cannot be walked it emits a `state=…` diagnostic in place of
/// the missing values so the post-processor still gets a row.
pub fn snapshot_canaries(label: &str, parent_pid: u64, parent_tid: u64) {
    // ── Channel 2: master canary (fs:0x28) ───────────────────────────────────
    let fs_base = unsafe { crate::hal::rdmsr(0xC000_0100) };
    let fs28_addr = fs_base.wrapping_add(0x28);
    let (fs28_val_str, fs28_phys_str) = read_userland_qword(fs28_addr);

    crate::serial_println!(
        "[VFORK-FSCANARY-{}] pid={} tid={} fs_base={:#x} fs28_addr={:#x} \
         fs28_val={} fs28_phys={}",
        label, parent_pid, parent_tid,
        fs_base, fs28_addr, fs28_val_str, fs28_phys_str
    );

    // ── Channel 1: parent saved-canary [rbp-8] ────────────────────────────────
    //
    // `get_user_rsp_rbp` returns the (user_rsp, user_rbp) pair saved on this
    // CPU's syscall frame at entry.  user_rbp at this point is the libc
    // syscall wrapper's frame pointer; the wrapper's prologue did `push rbp;
    // mov rbp, rsp`, so `*(user_rbp) = saved_RBP_of_caller`.  The caller is
    // typically the libxul function that issued the spawn — and ITS `[rbp-8]`
    // slot (= `*(user_rbp) - 8`) is the SSP slot the epilogue will compare
    // against `fs:0x28`.  We dump BOTH the wrapper-frame `[rbp-8]` and the
    // caller-frame `[rbp-8]` so the post-processor can pick whichever frame
    // the SSP-instrumented function actually owns.
    let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
    if user_rbp == 0 {
        crate::serial_println!(
            "[VFORK-CANARY-{}] pid={} tid={} state=no_user_frame rsp={:#x}",
            label, parent_pid, parent_tid, user_rsp
        );
        return;
    }

    // Wrapper-frame [rbp-8]: the SSP slot of the libc syscall wrapper itself.
    let wrap_canary_addr = user_rbp.wrapping_sub(8);
    let (wrap_val_str, wrap_phys_str) = read_userland_qword(wrap_canary_addr);

    // Walk one frame up: saved_caller_rbp = *(user_rbp).
    let caller_rbp_opt = read_userland_qword_raw(user_rbp);
    let (caller_rbp_str, caller_canary_addr_str,
         caller_val_str, caller_phys_str) = match caller_rbp_opt {
        Some(0) | None => (
            alloc::string::String::from("?"),
            alloc::string::String::from("?"),
            alloc::string::String::from("?"),
            alloc::string::String::from("?"),
        ),
        Some(crbp) => {
            let caller_addr = crbp.wrapping_sub(8);
            let (val_s, phys_s) = read_userland_qword(caller_addr);
            (
                alloc::format!("{:#x}", crbp),
                alloc::format!("{:#x}", caller_addr),
                val_s,
                phys_s,
            )
        }
    };

    crate::serial_println!(
        "[VFORK-CANARY-{}] pid={} tid={} rsp={:#x} rbp={:#x} \
         wrap_addr={:#x} wrap_val={} wrap_phys={} \
         caller_rbp={} caller_addr={} caller_val={} caller_phys={}",
        label, parent_pid, parent_tid,
        user_rsp, user_rbp,
        wrap_canary_addr, wrap_val_str, wrap_phys_str,
        caller_rbp_str, caller_canary_addr_str, caller_val_str, caller_phys_str
    );
}

/// Read a userland u64 + resolve its physical address.  Returns
/// `("?", "?")` if the address is unmapped / non-canonical.
///
/// Both halves go through `validate_user_ptr` and `virt_to_phys_in` so that
/// a corrupt RBP chain cannot fault the snapshot helper.
fn read_userland_qword(addr: u64) -> (alloc::string::String, alloc::string::String) {
    if !crate::syscall::validate_user_ptr(addr, 8) {
        return (
            alloc::string::String::from("?"),
            alloc::string::String::from("?"),
        );
    }
    let cr3 = crate::mm::vmm::get_cr3();
    let phys_str = match crate::mm::vmm::virt_to_phys_in(cr3, addr) {
        Some(p) => alloc::format!("{:#x}", p),
        None => alloc::string::String::from("?"),
    };
    let val_str = match unsafe { crate::syscall::user_read_u64(addr) } {
        Some(v) => alloc::format!("{:#x}", v),
        None => alloc::string::String::from("?"),
    };
    (val_str, phys_str)
}

/// Same as `read_userland_qword` but returns the raw value if successful, so
/// the caller can do arithmetic on it (used for the saved-RBP chain walk).
fn read_userland_qword_raw(addr: u64) -> Option<u64> {
    if !crate::syscall::validate_user_ptr(addr, 8) {
        return None;
    }
    unsafe { crate::syscall::user_read_u64(addr) }
}

// ─── Full parent-stack-VMA page-provenance dump (W215 axis-N+1) ───────────
//
// Tech-lead cross-walk on the post-#328 10-trial soak (0/10 page_pa swaps
// in the narrow RSP+8 KiB window, 0/10 refcount mismatches) identified
// that the SSP-failing parent frame sits *upstream* of the narrow window:
// musl's `__clone` syscall stub strips the frame pointer at syscall-entry,
// so an RBP-chain walk from the syscall-handler view terminates at depth
// 1, and the doomed frame's page is outside the 8 KiB capture range.
//
// This dispatch extends provenance capture to **every present page in the
// parent's `[stack]` VMA(s)** at the same two snapshot points
// (`pre_block.clone` and `post_wake.clone`).  Three discriminators:
//
//   (α)  Same `page_va` pre vs post, different `page_pa`     → W215-class
//        aliasing on a stack page outside the narrow window.
//   (β)  Same `(page_va, page_pa)` pre vs post, different `refcount`
//        without an explicit map/unmap                       → race in
//        page-table refcount accounting on the stack VMA.
//   (γ)  `present=true` → `present=false` → `present=true`   → cache
//        eviction inside the window.
//   (δ)  `writable=true` → `writable=false` → `writable=true` → PR #270
//        `pte_share_count` race signature.
//
// Per Intel SDM Vol. 3A §4.10.4–§4.10.5 (paging and TLB invariants) and
// POSIX `mmap(2)` semantics for `MAP_STACK`.

/// Hard cap on per-snapshot page-provenance rows.  USER_STACK_MAX = 1 MiB
/// = 256 pages, so 512 covers both the lazy and eager `[stack]` VMAs and
/// leaves headroom if a process has unusual stack VMA shapes.  Each row is
/// ~180 bytes serialised → ≤92 KiB per snapshot, ≤184 KiB per trial — well
/// within the soak-runner's serial-log budget.
const MAX_STACK_PROV_ROWS: usize = 512;

/// Page-provenance snapshot row.  Held in a fixed-size on-stack buffer so
/// that the entire VMA-iteration phase runs without allocator traffic, then
/// emitted in a single batch under PROCESS_TABLE-unlocked serial I/O.
#[derive(Copy, Clone)]
struct StackPageProv {
    page_va: u64,
    page_pa: u64,
    pte:     u64,
    refcount: u16,
}

/// Walk every present page in the parent process's stack VMA(s) and emit
/// one `[STACK-PAGE-PROV-FULL]` row per page, plus a summary line.
///
/// `label` is `"PRE"` or `"POST"` and tags the snapshot pair.
///
/// Per Intel SDM Vol. 3A §4.5 (paging structures, PTE layout) the PTE
/// returned by `lookup_pte_in` carries the physical frame in
/// `bits[51:12]` and access/protection flags in `bits[11:0]`.
pub fn snapshot_stack_page_provenance(label: &str, parent_pid: u64, parent_tid: u64) {
    // Step 1 — under PROCESS_TABLE lock, collect (cr3, [(base,end,name); N])
    // for the parent's `[stack]` VMAs.  Copy into a fixed-size stack array
    // so PROCESS_TABLE can be released before any serial-print, avoiding
    // both lock-order issues and serial-log interleaving inside the lock.
    let (parent_cr3, vmas, vma_count) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let parent = match procs.iter().find(|p| p.pid == parent_pid) {
            Some(p) => p,
            None => {
                drop(procs);
                crate::serial_println!(
                    "[STACK-PAGE-PROV-FULL] when={} pid={} tid={} state=no_parent",
                    label, parent_pid, parent_tid);
                return;
            }
        };
        let space = match parent.vm_space.as_ref() {
            Some(s) => s,
            None => {
                let cr3 = parent.cr3;
                drop(procs);
                crate::serial_println!(
                    "[STACK-PAGE-PROV-FULL] when={} pid={} tid={} state=no_vmspace cr3={:#x}",
                    label, parent_pid, parent_tid, cr3);
                return;
            }
        };
        // Up to 4 stack VMAs (lazy [stack] + eager [stack] + optional
        // [vfork-stack] + headroom).  Any more is anomalous — emit a
        // diagnostic but bound the iteration.
        let mut vmas: [(u64, u64, &'static str); 4] =
            [(0, 0, ""); 4];
        let mut n = 0usize;
        for area in space.areas.iter() {
            if area.name == "[stack]" || area.name == "[vfork-stack]" {
                if n < vmas.len() {
                    vmas[n] = (area.base, area.end(), area.name);
                    n += 1;
                }
            }
        }
        (parent.cr3, vmas, n)
    };

    if vma_count == 0 {
        crate::serial_println!(
            "[STACK-PAGE-PROV-FULL] when={} pid={} tid={} state=no_stack_vma cr3={:#x}",
            label, parent_pid, parent_tid, parent_cr3);
        return;
    }

    // Step 2 — for each [stack] VMA, iterate every 4 KiB page, query the
    // PTE in the parent's PML4, and (when PRESENT) capture phys + flags +
    // refcount into the row buffer.  Skip absent pages — only present
    // pages carry useful provenance.
    let mut rows: [StackPageProv; MAX_STACK_PROV_ROWS] =
        [StackPageProv { page_va: 0, page_pa: 0, pte: 0, refcount: 0 };
         MAX_STACK_PROV_ROWS];
    let mut row_idx = 0usize;
    let mut total_present = 0u64;
    let mut total_writable = 0u64;
    let mut total_refcount_sum: u64 = 0;
    let mut overflowed = false;

    for vi in 0..vma_count {
        let (base, end, _name) = vmas[vi];
        let mut va = base;
        while va < end {
            if let Some(pte) = crate::mm::vmm::lookup_pte_in(parent_cr3, va) {
                // PAGE_PRESENT guaranteed by lookup_pte_in success.
                let phys = pte & crate::mm::vmm::ADDR_MASK;
                let rc = crate::mm::refcount::pte_share_count(phys);
                total_present += 1;
                if pte & crate::mm::vmm::PAGE_WRITABLE != 0 {
                    total_writable += 1;
                }
                total_refcount_sum = total_refcount_sum.saturating_add(rc as u64);
                if row_idx < MAX_STACK_PROV_ROWS {
                    rows[row_idx] = StackPageProv {
                        page_va: va,
                        page_pa: phys,
                        pte,
                        refcount: rc,
                    };
                    row_idx += 1;
                } else {
                    overflowed = true;
                }
            }
            va = va.wrapping_add(crate::mm::pmm::PAGE_SIZE as u64);
        }
    }

    // Step 3 — emit captured rows.  One line per present page so the
    // post-processor can `grep '\[STACK-PAGE-PROV-FULL\] when=PRE'` then
    // diff against the POST set in a single awk pass.
    for i in 0..row_idx {
        let r = &rows[i];
        let present = r.pte & crate::mm::vmm::PAGE_PRESENT != 0;
        let writable = r.pte & crate::mm::vmm::PAGE_WRITABLE != 0;
        crate::serial_println!(
            "[STACK-PAGE-PROV-FULL] when={} pid={} tid={} \
             page_va={:#x} page_pa={:#x} refcount={} pte={:#x} \
             present={} writable={}",
            label, parent_pid, parent_tid,
            r.page_va, r.page_pa, r.refcount, r.pte,
            present, writable);
    }

    // Step 4 — summary line.  Carries vma_count so the post-processor can
    // verify both lazy and eager [stack] VMAs were covered, and the
    // overflowed flag so a cap-truncated capture is loud.
    crate::serial_println!(
        "[STACK-PAGE-PROV-FULL] when={} pid={} tid={} \
         summary=true vma_count={} total_present={} total_writable={} \
         total_refcount_sum={} emitted_rows={} cap={} overflowed={}",
        label, parent_pid, parent_tid,
        vma_count, total_present, total_writable,
        total_refcount_sum, row_idx, MAX_STACK_PROV_ROWS, overflowed);
}
