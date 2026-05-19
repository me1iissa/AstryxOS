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
