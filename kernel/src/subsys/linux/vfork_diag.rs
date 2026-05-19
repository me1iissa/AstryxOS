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
//!  4. **`[STACK-CANARY-WALK]` (axis-N+1)** — at pre-block, walk up to
//!     16 frames of the parent's RBP chain and emit each frame's
//!     `[rbp-8]` slot.  Locates the SSP-instrumented frame whose canary
//!     the epilogue will re-read on return; many libxul frames are
//!     SSP-instrumented and a downstream post-processor wants to pick
//!     the doomed one.  Per System V AMD64 ABI §3.4.1.
//!
//!  5. **`[STACK-CANARY-FINEGRAIN]` (axis-N+1)** — 32×256-byte Fletcher-32
//!     CRC of the parent's stack window at pre-block / post-wake.  The
//!     8 KiB-wide `vfork_canary_snapshot` CRC only proves identity over
//!     the whole window; chunking localises any sub-window write to a
//!     256-byte band.
//!
//!  6. **`[STACK-PAGE-PROV]` (axis-N+1)** — at pre-block / post-wake, for
//!     each 4 KiB page in the parent's stack window, dump
//!     `(page_va, page_pa, refcount, present, writable)`.  W215-class
//!     aliasing on the user-stack VMA shows up as a `(page_va same,
//!     page_pa changed)` row across the wait — i.e. a different physical
//!     frame is now mapped at the same virtual address than was mapped
//!     when the SSP prologue stored the canary.
//!
//!  7. **`fs:0x28` DR0 write-watch** — re-arm `DR0` (write-only, 8 bytes)
//!     on the master canary slot for the duration of the vfork window.
//!     Per System V x86_64 ABI §6.4 (TLS variant II), `fs:0x28` is
//!     `__stack_chk_guard` and must never be written outside `__init_ssp`.
//!     Any `#DB` from this region during vfork names the kernel-mode
//!     writer corrupting the master canary.  Intel SDM Vol. 3B §17.2.4.
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

// ─── Axis-N+1: three additional stack-provenance channels ────────────────────
//
// Tech-lead cross-walk verdict (W215 axis-N+1): the SSP-canary mismatch on
// vfork-parent wake is consistent with the parent's saved-canary slot at
// `[rbp-8]` of some SSP-instrumented frame already being zero BEFORE the
// vfork window opened.  The existing 8 KiB-wide window CRC only proves no
// NEW writes happened in the window, not that the slot was non-zero on
// entry.  These three channels expose enough state to discriminate
// (a) pre-existing zero vs (b) in-window kernel write vs (c) W215-class
// page-aliasing on the user-stack VMA.
//
// Refs:
//  - System V AMD64 ABI §3.4.1 (frame-pointer chain)
//  - System V x86_64 psABI §6.4 (TLS variant II — `__stack_chk_guard` at
//    `fs:0x28`)
//  - Intel SDM Vol. 3B §17.2.4 / §17.2.5 (debug-register breakpoints)

/// Maximum frames emitted by `[STACK-CANARY-WALK]`.  Sized to cover the
/// libxul `posix_spawn`-caller chain plus a few callee frames; the W215
/// axis-N+1 cliff fires somewhere around `[rbp-8] + 0x1d60` above the
/// vfork-entry RSP, so 16 frames is generous.
const MAX_WALK_FRAMES: usize = 16;

/// Maximum 256-byte chunks emitted by `[STACK-CANARY-FINEGRAIN]`.  8 KiB /
/// 256 B = 32 chunks — matches the existing 8 KiB window the surrounding
/// `vfork_canary_snapshot` already captures.
const FINEGRAIN_CHUNKS: usize = 32;
const FINEGRAIN_CHUNK_SIZE: usize = 256;
const FINEGRAIN_WIN_SIZE: usize = FINEGRAIN_CHUNKS * FINEGRAIN_CHUNK_SIZE; // 8 KiB

/// Maximum 4 KiB pages emitted by `[STACK-PAGE-PROV]`.  Matches the
/// finegrain window so the two channels stay alignable in post-processing.
const PAGE_PROV_PAGES: usize = FINEGRAIN_WIN_SIZE / 4096; // 2 pages

/// Walk up to `MAX_WALK_FRAMES` of the parent's user RBP chain at vfork
/// pre-block and emit, for each frame, the `[rbp-8]` slot the SSP epilogue
/// will check on return.  Locates the doomed SSP frame for a downstream
/// post-processor that knows which libxul caller is mismatching.
///
/// Per System V AMD64 ABI §3.4.1, with `-fno-omit-frame-pointer` every
/// frame has `[rbp+0] = saved_rbp` and `[rbp+8] = saved_rip`.  GCC SSP
/// (`-fstack-protector*`) writes the canary at `[rbp-8]` in the prologue
/// (`mov rax, fs:0x28 ; mov [rbp-8], rax`) and the epilogue re-reads it
/// before the function returns.
pub fn snapshot_stack_canary_walk(label: &str, parent_pid: u64, parent_tid: u64) {
    let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
    if user_rbp == 0 {
        crate::serial_println!(
            "[STACK-CANARY-WALK] {} pid={} tid={} state=no_user_frame rsp={:#x}",
            label, parent_pid, parent_tid, user_rsp,
        );
        return;
    }

    let mut rbp = user_rbp;
    for frame_idx in 0..MAX_WALK_FRAMES {
        // Sanity guards — same shape as `proc::stack_walk::stack_walk_user`.
        // `USER_ADDR_END` matches the kernel-wide constant.
        const USER_ADDR_END: u64 = 0x0000_8000_0000_0000;
        const USER_ADDR_MIN: u64 = 0x1000;
        if rbp == 0 {
            crate::serial_println!(
                "[STACK-CANARY-WALK] {} pid={} tid={} frame_idx={} state=rbp_zero",
                label, parent_pid, parent_tid, frame_idx,
            );
            return;
        }
        if rbp & 0x7 != 0 || rbp < USER_ADDR_MIN || rbp >= USER_ADDR_END {
            crate::serial_println!(
                "[STACK-CANARY-WALK] {} pid={} tid={} frame_idx={} \
                 state=rbp_bad rbp={:#x}",
                label, parent_pid, parent_tid, frame_idx, rbp,
            );
            return;
        }

        let saved_rbp = match read_userland_qword_raw(rbp) {
            Some(v) => v,
            None => {
                crate::serial_println!(
                    "[STACK-CANARY-WALK] {} pid={} tid={} frame_idx={} \
                     state=read_fault_rbp rbp={:#x}",
                    label, parent_pid, parent_tid, frame_idx, rbp,
                );
                return;
            }
        };
        let saved_rip = read_userland_qword_raw(rbp.wrapping_add(8)).unwrap_or(0);
        let canary = read_userland_qword_raw(rbp.wrapping_sub(8));

        let canary_str = canary
            .map(|v| alloc::format!("{:#x}", v))
            .unwrap_or_else(|| alloc::string::String::from("?"));
        crate::serial_println!(
            "[STACK-CANARY-WALK] {} pid={} tid={} frame_idx={} rbp={:#x} \
             saved_rbp_at_rbp={:#x} saved_rip_at_rbp+8={:#x} canary_at_rbp-8={}",
            label, parent_pid, parent_tid, frame_idx, rbp,
            saved_rbp, saved_rip, canary_str,
        );

        // Per §3.4.1: stack grows downward, so caller's RBP must be at a
        // higher address than callee's.  A non-advancing chain means a
        // leaf without -fno-omit-frame-pointer or a corrupted slot —
        // stop walking, don't loop.
        if saved_rbp <= rbp {
            crate::serial_println!(
                "[STACK-CANARY-WALK] {} pid={} tid={} frame_idx={} \
                 state=did_not_advance saved_rbp={:#x}",
                label, parent_pid, parent_tid, frame_idx + 1, saved_rbp,
            );
            return;
        }
        rbp = saved_rbp;
    }
    crate::serial_println!(
        "[STACK-CANARY-WALK] {} pid={} tid={} state=max_depth depth={}",
        label, parent_pid, parent_tid, MAX_WALK_FRAMES,
    );
}

/// Emit a Fletcher-32 CRC per 256-byte chunk over the 8 KiB window above
/// the parent's RSP at vfork-entry.  Identity across all 32 chunks rules
/// in pre-existing corruption; any single-chunk delta pre→post localises
/// the kernel write to a 256-byte band.
///
/// Fletcher-32 is the same checksum used by the surrounding
/// `vfork_canary_snapshot` window CRC — keeps the two channels
/// numerically comparable.
pub fn snapshot_stack_finegrain(label: &str, parent_pid: u64, parent_tid: u64) {
    let (user_rsp, _user_rbp) = crate::syscall::get_user_rsp_rbp();
    if user_rsp == 0 {
        crate::serial_println!(
            "[STACK-CANARY-FINEGRAIN] {} pid={} tid={} state=no_rsp",
            label, parent_pid, parent_tid,
        );
        return;
    }
    let win_base = user_rsp;
    if !crate::syscall::validate_user_ptr(win_base, FINEGRAIN_WIN_SIZE) {
        crate::serial_println!(
            "[STACK-CANARY-FINEGRAIN] {} pid={} tid={} state=win_unmapped base={:#x}",
            label, parent_pid, parent_tid, win_base,
        );
        return;
    }
    let buf = match unsafe { crate::syscall::user_slice_snapshot(win_base, FINEGRAIN_WIN_SIZE) } {
        Some(b) => b,
        None => {
            crate::serial_println!(
                "[STACK-CANARY-FINEGRAIN] {} pid={} tid={} state=snapshot_failed base={:#x}",
                label, parent_pid, parent_tid, win_base,
            );
            return;
        }
    };
    debug_assert_eq!(buf.len(), FINEGRAIN_WIN_SIZE);

    for chunk_idx in 0..FINEGRAIN_CHUNKS {
        let start = chunk_idx * FINEGRAIN_CHUNK_SIZE;
        let end = start + FINEGRAIN_CHUNK_SIZE;
        let chunk = &buf[start..end];
        // Fletcher-32 (matches the surrounding 8 KiB-window CRC formula
        // in syscall.rs::vfork_canary_snapshot — modulo 65535 over u8
        // stream).  Stable, no_std-friendly, no heap alloc.
        let mut sum1: u32 = 0;
        let mut sum2: u32 = 0;
        for b in chunk {
            sum1 = (sum1.wrapping_add(*b as u32)) % 65535;
            sum2 = (sum2.wrapping_add(sum1)) % 65535;
        }
        let crc: u32 = (sum2 << 16) | sum1;
        let lo = win_base + start as u64;
        let hi = win_base + end as u64;
        crate::serial_println!(
            "[STACK-CANARY-FINEGRAIN] {} pid={} tid={} chunk_idx={} crc={:#x} \
             range={:#x}..{:#x}",
            label, parent_pid, parent_tid, chunk_idx, crc, lo, hi,
        );
    }
}

/// Per-4-KiB-page provenance dump for the parent stack window.  Emits
/// `(page_va, page_pa, refcount, present, writable)` for each page.
///
/// W215-class aliasing shape: `page_va` identical pre/post but `page_pa`
/// differs → a different physical frame is mapped at the same VA.
/// Refcount mismatch (e.g. 1 → 0 or 1 → 2) indicates an in-window
/// `clone_for_fork` / cache-share / unmap raced the parent.
///
/// CR3 read inside the helper so a future caller from a different code
/// path needn't pass it.  All reads go through `virt_to_phys_in` so an
/// unmapped slot reports `phys=?` instead of faulting.
pub fn snapshot_stack_page_prov(label: &str, parent_pid: u64, parent_tid: u64) {
    let (user_rsp, _user_rbp) = crate::syscall::get_user_rsp_rbp();
    if user_rsp == 0 {
        crate::serial_println!(
            "[STACK-PAGE-PROV] when={} pid={} tid={} state=no_rsp",
            label, parent_pid, parent_tid,
        );
        return;
    }
    let cr3 = crate::mm::vmm::get_cr3();
    let win_base = user_rsp & !0xFFF; // page-align down

    for i in 0..PAGE_PROV_PAGES {
        let page_va = win_base + (i as u64) * 4096;
        // Translate via the per-CR3 walker (matches `proc::stack_walk`).
        let (phys_str, present, writable) =
            match crate::mm::vmm::virt_to_phys_in(cr3, page_va) {
                Some(phys) => {
                    // virt_to_phys_in only returns Some when the leaf PTE is
                    // present.  We don't have a direct "is writable" read,
                    // so we infer it via a second walk that checks for a
                    // not-present-then-walked slot vs returning Some.  For
                    // simplicity report `present=true writable=?` — the
                    // page-fault path is the authoritative writable test.
                    (alloc::format!("{:#x}", phys), true, infer_writable(cr3, page_va))
                }
                None => (alloc::string::String::from("?"), false, false),
            };
        let refcount = match crate::mm::vmm::virt_to_phys_in(cr3, page_va) {
            Some(phys) => crate::mm::refcount::page_ref_count(phys),
            None => 0,
        };
        crate::serial_println!(
            "[STACK-PAGE-PROV] when={} pid={} tid={} page_va={:#x} page_pa={} \
             refcount={} present={} writable={}",
            label, parent_pid, parent_tid, page_va, phys_str,
            refcount, present, writable,
        );
    }
}

/// Best-effort PTE-writability probe for `[STACK-PAGE-PROV]`.  Walks the
/// PML4→PDPT→PD→PT chain and AND-reduces the W bit at every level (per
/// Intel SDM Vol. 3A §4.6.1: the effective permission is the AND of all
/// intermediate W bits).  Returns `false` on any unmapped intermediate.
fn infer_writable(cr3: u64, va: u64) -> bool {
    // Constants mirror `mm::vmm`: PAGE_PRESENT=1, PAGE_WRITABLE=2,
    // ADDR_MASK extracts the 4 KiB-aligned phys.
    const PAGE_PRESENT: u64 = 1 << 0;
    const PAGE_WRITABLE: u64 = 1 << 1;
    const PAGE_HUGE: u64 = 1 << 7;
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pt_idx = ((va >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4_entry = *(((cr3 & ADDR_MASK) + PHYS_OFF) as *const u64).add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 { return false; }
        let mut writable = pml4_entry & PAGE_WRITABLE != 0;
        let pdpt_entry = *(((pml4_entry & ADDR_MASK) + PHYS_OFF) as *const u64).add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 { return false; }
        writable &= pdpt_entry & PAGE_WRITABLE != 0;
        if pdpt_entry & PAGE_HUGE != 0 { return writable; }
        let pd_entry = *(((pdpt_entry & ADDR_MASK) + PHYS_OFF) as *const u64).add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 { return false; }
        writable &= pd_entry & PAGE_WRITABLE != 0;
        if pd_entry & PAGE_HUGE != 0 { return writable; }
        let pt_entry = *(((pd_entry & ADDR_MASK) + PHYS_OFF) as *const u64).add(pt_idx);
        if pt_entry & PAGE_PRESENT == 0 { return false; }
        writable & (pt_entry & PAGE_WRITABLE != 0)
    }
}

/// Re-arm DR0 (write-only, 8 bytes) on `fs:0x28` (the master canary slot,
/// `__stack_chk_guard` per System V x86_64 psABI §6.4) for the duration
/// of the vfork window.  Any kernel-mode store to that slot fires a `#DB`
/// and emits `[W215/DR-WATCH-FIRE]` naming the writer.
///
/// No-op if the master canary's physical frame cannot be resolved (the
/// thread hasn't faulted in its TCB yet, or `fs_base` is zero).
///
/// Belt-and-braces channel — the master canary slot should NEVER be
/// written outside `__init_ssp`.  Any fire here is a separate corruption
/// channel worth knowing about, orthogonal to the saved-`[rbp-8]` story.
pub fn arm_master_canary_watch() {
    let fs_base = unsafe { crate::hal::rdmsr(0xC000_0100) };
    if fs_base == 0 {
        return;
    }
    let fs28_addr = fs_base.wrapping_add(0x28);
    if !crate::syscall::validate_user_ptr(fs28_addr, 8) {
        return;
    }
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = match crate::mm::vmm::virt_to_phys_in(cr3, fs28_addr) {
        Some(p) => p,
        None => {
            crate::serial_println!(
                "[VFORK-FS28-WATCH] state=fs28_unmapped fs_base={:#x} fs28_addr={:#x}",
                fs_base, fs28_addr,
            );
            return;
        }
    };
    // `arm_write_watchpoint` programs DR0 with `PHYS_OFF + phys` (per the
    // module-level docs).  The watch fires on any write to that linear
    // address — the kernel's direct physical map covers all installed RAM
    // so any aliased VA mapping the same frame will also trip the watch.
    // Returns false if DR0 is already armed (CRC walker's slot); in that
    // case we just emit a state line and continue.  The vfork window
    // remains useful without this belt-and-braces channel.
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let linear = PHYS_OFF + phys + (fs28_addr & 0xFFF);
    let armed = crate::arch::x86_64::debug_reg::arm_write_watchpoint(
        linear, 8, phys, 0xFFFF_FFFF_FFFF_FFFE /* inode sentinel: fs28 */, 0x28,
    );
    crate::serial_println!(
        "[VFORK-FS28-WATCH] state={} fs_base={:#x} fs28_addr={:#x} phys={:#x} linear={:#x}",
        if armed { "armed" } else { "dr0_busy" },
        fs_base, fs28_addr, phys, linear,
    );
}

/// Disarm the DR0 master-canary watch if the vfork window closes without
/// the watch firing.  Idempotent — safe to call when DR0 is unowned or
/// when the watch was a one-shot consumed by `#DB`.
pub fn disarm_master_canary_watch() {
    crate::arch::x86_64::debug_reg::release_slot(0);
}
