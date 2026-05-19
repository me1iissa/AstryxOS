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
//!
//! # Axis-N+1 widened diagnostic (SSP-epilogue scan + full-stack-VMA provenance)
//!
//! The prior `snapshot_canaries` helper depends on the parent's user RBP being
//! a usable frame pointer.  Empirically that fails when the parent's last
//! caller is musl's `__clone` (or any function that invalidates RBP in its
//! prologue), leaving the snapshot one frame too shallow.  Three additional
//! channels widen the capture window without relying on the RBP chain:
//!
//!  - `[STACK-SSP-FRAME]`  — Method 1: byte-pattern scan of the parent's
//!    stack VMA.  For every qword that decodes as a canonical user-space VA
//!    landing in an executable VMA, scan a 256-byte window forward from that
//!    saved-RIP for the SSP epilogue byte sequence
//!    `48 33 04 25 28 00 00 00` (`xor rax, fs:0x28` with the GCC-emitted
//!    `64` segment override checked separately).  Each hit names a frame
//!    whose caller is SSP-instrumented; its `[rbp-8]` canary slot is
//!    emitted with the slot's current value and physical address.
//!
//!  - `[STACK-PAGE-CRC]`   — Method 2: per-page Fletcher-32 over every
//!    present page in the parent's stack VMA, pre-block and post-wake.
//!    Combined with Method 1 the per-page deltas localise the byte range
//!    that changed during vfork; without Method 1 the deltas still tell
//!    a SHARED-PAGE-ALIASING story (whole-page swap → CRC delta on a page
//!    whose phys also changed).
//!
//!  - `[STACK-CANARY-WATCH]` — Method 3: after Method 1 emits one or more
//!    `[STACK-SSP-FRAME]` lines, the highest-priority frame's canary slot
//!    is fed into the W215 DR1–DR3 pool via
//!    `arch::x86_64::debug_reg::arm_canary_slot_watchpoint`.  If a
//!    kernel-mode store hits the slot during the vfork window the
//!    `#DB` handler emits `[W215/DR-WATCH-FIRE]` with the writer's RIP.
//!
//! # Refs (Method 1/2/3)
//!  - System V x86_64 psABI §6.4 (SSP)
//!  - Intel SDM Vol. 3B §17.2.4 / §17.2.5 (DR0–DR3 / #DB / DR6 / DR7)

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

// ───────────────────────────────────────────────────────────────────────────
// Axis-N+1 widened diagnostics: SSP-epilogue scan + full-stack-VMA provenance
// ───────────────────────────────────────────────────────────────────────────

/// Highest user-space virtual address (exclusive).  Identical to
/// `syscall::USER_VA_LIMIT` and `proc::stack_walk::USER_ADDR_END`.
const USER_ADDR_END: u64 = 0x0000_8000_0000_0000;
const USER_ADDR_MIN: u64 = 0x1000;
const PAGE_SIZE_U64: u64 = 4096;

/// Cap on per-vfork-window `[STACK-SSP-FRAME]` lines.  Each match is one
/// line plus one [STACK-CANARY-WATCH-ARM] attempt; cap keeps serial bounded
/// even if a stack contains hundreds of saved RIPs.
const MAX_SSP_FRAMES_PER_WINDOW: usize = 64;

/// SSP-epilogue byte signature variants.  System V x86_64 psABI §6.4 and the
/// GCC-emitted code at `-fstack-protector` produce one of:
///
///   ```text
///   48 33 04 25 28 00 00 00       xor rax, ds:[0x28]            (rare)
///   64 48 33 04 25 28 00 00 00    xor rax, fs:[0x28]            (default)
///   ```
///
/// We accept either form and report which signature matched on the
/// `[STACK-SSP-FRAME]` line via `sig=fs|ds`.  The fs-prefixed form is the
/// overwhelmingly common case on x86_64 with `__stack_chk_guard` at
/// `fs:0x28` (musl pthread_impl.h canary layout, glibc TLS Variant II).
const SSP_EPILOGUE_NOSEG: [u8; 8] = [0x48, 0x33, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00];

/// Saved (user_rsp, user_rbp, user_rip) for the parent thread, sampled from
/// the parent's KERNEL stack — not the per-CPU `frame_rsp` slot, which is
/// overwritten by every subsequent syscall on the same CPU.  Per the
/// `syscall_entry` save layout in `kernel/src/syscall/mod.rs`:
///   - `*(kstack_top -  8)` = user RSP (slot 14)
///   - `*(kstack_top - 16)` = user RIP (RCX; slot 13)
///   - `*(kstack_top - 32)` = user RBP (slot 11)
///
/// Returns `None` if the parent thread has no kernel stack registered
/// (kernel-only thread, or thread struct missing).  All reads go through
/// `kstack_top - N` on the kernel direct map, so no SMAP / page-fault risk.
fn get_parent_user_frame(parent_tid: u64) -> Option<(u64, u64, u64)> {
    let threads = crate::proc::THREAD_TABLE.lock();
    let t = threads.iter().find(|t| t.tid == parent_tid)?;
    if t.kernel_stack_base == 0 || t.kernel_stack_size == 0 {
        return None;
    }
    let kstack_top = t.kernel_stack_base + t.kernel_stack_size;
    let rsp = unsafe { *((kstack_top -  8) as *const u64) };
    let rip = unsafe { *((kstack_top - 16) as *const u64) };
    let rbp = unsafe { *((kstack_top - 32) as *const u64) };
    Some((rsp, rip, rbp))
}

/// Look up the VMA covering `addr` for process `pid`; returns
/// `(base, end, prot, is_file, name)`.  Snapshot is taken under
/// `PROCESS_TABLE` and the lock is dropped before return.
fn lookup_user_vma(pid: u64, addr: u64) -> Option<(u64, u64, u32, bool, &'static str)> {
    use crate::mm::vma::VmBacking;
    let procs = crate::proc::PROCESS_TABLE.lock();
    let p = procs.iter().find(|p| p.pid == pid)?;
    let vs = p.vm_space.as_ref()?;
    let vma = vs.find_vma(addr)?;
    let is_file = matches!(vma.backing, VmBacking::File { .. });
    Some((vma.base, vma.end(), vma.prot as u32, is_file, vma.name))
}

/// Fletcher-32 over a byte slice, returning `(value, byte_count)`.  RFC 1146
/// modulus 65535; produced as `(sum2 << 16) | sum1`.  Stable across boots so
/// pre/post comparison is straightforward.
fn fletcher32(buf: &[u8]) -> u32 {
    let mut s1: u32 = 0;
    let mut s2: u32 = 0;
    for b in buf {
        s1 = s1.wrapping_add(*b as u32) % 65535;
        s2 = s2.wrapping_add(s1) % 65535;
    }
    (s2 << 16) | s1
}

/// Read up to `len` bytes from user VA `va` via the page-table walker
/// (`virt_to_phys_in`) and the kernel direct physical map (PHYS_OFF).  Stops
/// at the first unmapped page; returns the bytes read.  No SMAP bracket
/// needed — the read goes through the kernel direct map, not the user VA.
///
/// Bounded at `len` ≤ 8 KiB to keep stack-allocated buffers small; callers
/// that want bigger windows should re-invoke per-page.
fn read_user_bytes_via_phys(cr3: u64, va: u64, len: usize) -> alloc::vec::Vec<u8> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(len);
    let mut i = 0usize;
    while i < len {
        let cur = va + i as u64;
        let phys = match crate::mm::vmm::virt_to_phys_in(cr3, cur) {
            Some(p) => p,
            None => break,
        };
        // Read up to the rest of this page or the rest of the request,
        // whichever is smaller.
        let page_end_va = (cur & !(PAGE_SIZE_U64 - 1)) + PAGE_SIZE_U64;
        let chunk = core::cmp::min(len - i, (page_end_va - cur) as usize);
        for j in 0..chunk {
            let b = unsafe {
                core::ptr::read_volatile((PHYS_OFF + phys + j as u64) as *const u8)
            };
            out.push(b);
        }
        i += chunk;
    }
    out
}

/// Read a single u64 from user VA `va` via the direct physical map,
/// returning `None` on unmapped or misaligned address.
fn read_user_u64_via_phys(cr3: u64, va: u64) -> Option<u64> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    if va & 7 != 0 { return None; }
    let bytes = read_user_bytes_via_phys(cr3, va, 8);
    if bytes.len() != 8 { return None; }
    let _ = PHYS_OFF;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Find the SSP-epilogue byte pattern inside `buf`.  Returns
/// `Some((offset, sig_label))` on first match.  `sig_label` is one of
/// `"fs"` (a `0x64` prefix sits immediately before the 8-byte body) or
/// `"ds"`/`"plain"` (no segment prefix — the 8-byte body matches at the
/// start of an instruction).
fn find_ssp_epilogue(buf: &[u8]) -> Option<(usize, &'static str)> {
    let n = buf.len();
    if n < SSP_EPILOGUE_NOSEG.len() { return None; }
    let pat = &SSP_EPILOGUE_NOSEG;
    let mut i = 0usize;
    while i + pat.len() <= n {
        if buf[i] == pat[0]
            && buf[i + 1] == pat[1]
            && buf[i + 2] == pat[2]
            && buf[i + 3] == pat[3]
            && buf[i + 4] == pat[4]
            && buf[i + 5] == pat[5]
            && buf[i + 6] == pat[6]
            && buf[i + 7] == pat[7]
        {
            // Check for a preceding 0x64 (FS segment prefix) — disambiguate
            // `xor rax, fs:[0x28]` (the SSP epilogue) from the bare 64-bit
            // absolute-addressing form (which is rare but technically legal).
            let sig = if i > 0 && buf[i - 1] == 0x64 { "fs" } else { "ds" };
            return Some((i, sig));
        }
        i += 1;
    }
    None
}

/// Last successfully-located canary slot from `ssp_epilogue_scan` during the
/// current vfork window.  Read by `arm_canary_watch_if_located` so Method 3
/// only arms after Method 1 has produced a target.  `0` = none located.
static LATEST_CANARY_SLOT: AtomicU64 = AtomicU64::new(0);

/// **Method 1** — SSP-epilogue byte-pattern scan over the parent's stack
/// VMA.
///
/// Per System V x86_64 psABI §6.4, every SSP-instrumented function ends
/// with `xor rax, fs:0x28 ; je .ok ; call __stack_chk_fail`.  Walk every
/// 8-byte slot in the parent's stack VMA looking for plausible saved
/// return-addresses (canonical user VAs that fall in an executable file-
/// backed VMA), then read 256 bytes forward from each candidate's
/// destination RIP and look for the SSP-epilogue byte pattern.  Each match
/// names an SSP-instrumented caller frame whose `[rbp-8]` canary slot the
/// epilogue will read.
///
/// Emits `[STACK-SSP-FRAME] saved_rip=… rip_decoded=… rbp=… canary_at_rbp-8=… …`
/// for each hit, up to `MAX_SSP_FRAMES_PER_WINDOW`.
///
/// Returns the address of the first canary slot located (or 0 if none), so
/// callers (Method 3 — DR watch arm) can target it.
pub fn ssp_epilogue_scan(label: &str, parent_pid: u64, parent_tid: u64) -> u64 {
    use core::fmt::Write;

    let Some((rsp, _rip, _rbp)) = get_parent_user_frame(parent_tid) else {
        crate::serial_println!(
            "[STACK-SSP-FRAME] {} pid={} tid={} state=no_parent_frame",
            label, parent_pid, parent_tid,
        );
        return 0;
    };
    if rsp == 0 || rsp < USER_ADDR_MIN || rsp >= USER_ADDR_END {
        crate::serial_println!(
            "[STACK-SSP-FRAME] {} pid={} tid={} state=bad_rsp rsp={:#x}",
            label, parent_pid, parent_tid, rsp,
        );
        return 0;
    }
    let Some((stk_base, stk_end, stk_prot, _, stk_name)) =
        lookup_user_vma(parent_pid, rsp) else
    {
        crate::serial_println!(
            "[STACK-SSP-FRAME] {} pid={} tid={} state=no_stack_vma rsp={:#x}",
            label, parent_pid, parent_tid, rsp,
        );
        return 0;
    };

    let cr3 = crate::mm::vmm::get_cr3();
    crate::serial_println!(
        "[STACK-SSP-FRAME-WIN] {} pid={} tid={} rsp={:#x} vma=[{:#x},{:#x}) name={} prot={:#x}",
        label, parent_pid, parent_tid, rsp, stk_base, stk_end, stk_name, stk_prot,
    );

    // Walk slot-by-slot from rsp toward the top of the stack VMA.  Cap the
    // walk distance to keep diagnostic time bounded — stacks larger than
    // 256 KiB are unusual for libxul, and the matched-frame count cap
    // (MAX_SSP_FRAMES_PER_WINDOW) provides a second safety net.
    let walk_top = core::cmp::min(stk_end, rsp.saturating_add(256 * 1024));
    let mut emitted: usize = 0;
    let mut first_canary: u64 = 0;
    let mut slot_va = rsp & !0x7;
    while slot_va + 8 <= walk_top && emitted < MAX_SSP_FRAMES_PER_WINDOW {
        let saved_rip = match read_user_u64_via_phys(cr3, slot_va) {
            Some(v) => v,
            None => { slot_va += 8; continue; }
        };
        // Cheap filter: canonical user-space VA and not in the first page.
        if saved_rip < USER_ADDR_MIN || saved_rip >= USER_ADDR_END {
            slot_va += 8; continue;
        }
        // Filter by VMA — only consider candidates landing in an executable
        // file-backed VMA (libxul.so / libc / ld-musl).  Anonymous VMAs and
        // non-executable mappings are never function-call targets.
        let (vma_base, _vma_end, prot, is_file, vma_name) =
            match lookup_user_vma(parent_pid, saved_rip) {
                Some(v) => v,
                None => { slot_va += 8; continue; }
            };
        const PROT_EXEC: u32 = 4;
        if prot & PROT_EXEC == 0 || !is_file {
            slot_va += 8; continue;
        }
        // Read 256 bytes from `saved_rip` and look for the SSP-epilogue
        // byte signature.  The signature can appear at any byte offset
        // within the caller's function body, but the call returns AT
        // `saved_rip`, so the epilogue (if present) sits within the
        // remainder of the caller's body — almost always inside 256 B.
        let scan = read_user_bytes_via_phys(cr3, saved_rip, 256);
        let Some((sig_off, sig_kind)) = find_ssp_epilogue(&scan) else {
            slot_va += 8; continue;
        };

        // The frame's saved-RBP sits in the slot immediately below the
        // saved-RIP per System V AMD64 ABI §3.4.1 (`push rbp` precedes
        // every standard `call`).  Read it to identify the canary slot.
        let saved_rbp_va = slot_va.wrapping_sub(8);
        let saved_rbp = read_user_u64_via_phys(cr3, saved_rbp_va).unwrap_or(0);
        let canary_addr = saved_rbp.wrapping_sub(8);
        let canary_val_str = match read_user_u64_via_phys(cr3, canary_addr) {
            Some(v) => alloc::format!("{:#x}", v),
            None => alloc::string::String::from("?"),
        };
        let canary_phys_str = match crate::mm::vmm::virt_to_phys_in(cr3, canary_addr) {
            Some(p) => alloc::format!("{:#x}", p),
            None => alloc::string::String::from("?"),
        };
        let mut line = alloc::string::String::with_capacity(256);
        let _ = write!(&mut line,
            "[STACK-SSP-FRAME] {} pid={} tid={} idx={} saved_rip_slot={:#x} \
             saved_rip={:#x} rip_decoded={}+{:#x} sig={} sig_off={} \
             saved_rbp={:#x} canary_at_rbp-8={:#x} canary_val={} canary_phys={}",
            label, parent_pid, parent_tid, emitted, slot_va,
            saved_rip, vma_name, saved_rip.wrapping_sub(vma_base), sig_kind, sig_off,
            saved_rbp, canary_addr, canary_val_str, canary_phys_str,
        );
        crate::serial_println!("{}", line);
        if first_canary == 0
            && canary_addr >= USER_ADDR_MIN
            && canary_addr < USER_ADDR_END
        {
            first_canary = canary_addr;
        }
        emitted += 1;
        // Skip past this frame's saved-RIP slot.  Frames are at least a
        // few qwords apart, so stepping forward by 16 bytes avoids
        // re-matching the same slot from a one-byte-offset scan.
        slot_va += 16;
    }
    crate::serial_println!(
        "[STACK-SSP-FRAME-SUMMARY] {} pid={} tid={} emitted={} cap={} first_canary={:#x}",
        label, parent_pid, parent_tid, emitted, MAX_SSP_FRAMES_PER_WINDOW, first_canary,
    );

    // Remember the first canary slot for Method 3's optional DR re-arm.
    // Only store the PRE-block value: POST-wake calls re-scan but should
    // not overwrite (we want the same slot pre/post for the watch line).
    if first_canary != 0 && label == "PRE" {
        LATEST_CANARY_SLOT.store(first_canary, Ordering::Release);
    }
    first_canary
}

/// **Method 2** — Per-page Fletcher-32 CRC over every present page in the
/// parent's stack VMA.  Emits one `[STACK-PAGE-CRC]` line per page with
/// `va`, `phys`, and `crc`.  Combined with the PRE/POST pair the
/// post-processor can locate any page whose CRC changed (in-window write)
/// or whose phys changed (page-aliasing).
///
/// Bounded at 64 pages (256 KiB) of stack walk per call to keep serial
/// log volume bounded — stacks beyond that are vanishingly rare for the
/// libxul vfork window.
pub fn full_stack_vma_provenance(label: &str, parent_pid: u64, parent_tid: u64) {
    let Some((rsp, _rip, _rbp)) = get_parent_user_frame(parent_tid) else {
        crate::serial_println!(
            "[STACK-PAGE-CRC] {} pid={} tid={} state=no_parent_frame",
            label, parent_pid, parent_tid,
        );
        return;
    };
    if rsp == 0 || rsp < USER_ADDR_MIN || rsp >= USER_ADDR_END {
        crate::serial_println!(
            "[STACK-PAGE-CRC] {} pid={} tid={} state=bad_rsp rsp={:#x}",
            label, parent_pid, parent_tid, rsp,
        );
        return;
    }
    let Some((stk_base, stk_end, _prot, _is_file, _name)) =
        lookup_user_vma(parent_pid, rsp) else
    {
        crate::serial_println!(
            "[STACK-PAGE-CRC] {} pid={} tid={} state=no_stack_vma rsp={:#x}",
            label, parent_pid, parent_tid, rsp,
        );
        return;
    };

    let cr3 = crate::mm::vmm::get_cr3();
    let walk_low  = rsp & !(PAGE_SIZE_U64 - 1);
    let walk_high = core::cmp::min(stk_end, walk_low.saturating_add(64 * PAGE_SIZE_U64));
    let _ = stk_base; // VMA base printed once per-window via the summary below.
    crate::serial_println!(
        "[STACK-PAGE-CRC-WIN] {} pid={} tid={} rsp={:#x} walk=[{:#x},{:#x})",
        label, parent_pid, parent_tid, rsp, walk_low, walk_high,
    );

    let mut page_va = walk_low;
    let mut emitted = 0usize;
    while page_va + PAGE_SIZE_U64 <= walk_high {
        let phys = match crate::mm::vmm::virt_to_phys_in(cr3, page_va) {
            Some(p) => p,
            None => {
                crate::serial_println!(
                    "[STACK-PAGE-CRC] {} pid={} tid={} va={:#x} state=unmapped",
                    label, parent_pid, parent_tid, page_va,
                );
                page_va += PAGE_SIZE_U64;
                continue;
            }
        };
        let bytes = read_user_bytes_via_phys(cr3, page_va, PAGE_SIZE_U64 as usize);
        let crc = fletcher32(&bytes);
        crate::serial_println!(
            "[STACK-PAGE-CRC] {} pid={} tid={} va={:#x} phys={:#x} crc={:#010x} bytes={}",
            label, parent_pid, parent_tid, page_va, phys, crc, bytes.len(),
        );
        emitted += 1;
        page_va += PAGE_SIZE_U64;
    }
    crate::serial_println!(
        "[STACK-PAGE-CRC-SUMMARY] {} pid={} tid={} pages_emitted={}",
        label, parent_pid, parent_tid, emitted,
    );
}

/// **Method 3** — After `ssp_epilogue_scan(PRE, ...)` has located a doomed
/// frame's canary slot, arm a write-only hardware watchpoint on the slot's
/// user linear address for the duration of the vfork window.
///
/// The DR pool is the W215 four-slot scheme (`arch::x86_64::debug_reg`); we
/// prefer DR1/DR2/DR3 so the post-hoc CRC walker's DR0 is not stolen.  If
/// no canary slot was located (Method 1 returned 0) this is a no-op — the
/// scan-and-arm sequence is one-shot per vfork window.
///
/// Per Intel SDM Vol. 3B §17.2.4 the linear-address compare happens on
/// every memory access, regardless of CPL, so the watch catches both
/// (a) kernel-mode stores via the direct physical map AND (b) user-mode
/// stores via the same user VA from the parent's sibling threads (which
/// share CR3 during vfork).  A fire emits `[W215/DR-WATCH-FIRE]` with
/// the writer's RIP per the existing handler in `debug_reg.rs`.
///
/// Returns the slot index (0..=3) on a successful arm, or `None` if
/// either no canary was located or the DR pool was exhausted.
pub fn arm_canary_watch_if_located(parent_pid: u64, parent_tid: u64) -> Option<u8> {
    let canary_va = LATEST_CANARY_SLOT.load(Ordering::Acquire);
    if canary_va == 0 {
        crate::serial_println!(
            "[STACK-CANARY-WATCH] pid={} tid={} state=no_target",
            parent_pid, parent_tid,
        );
        return None;
    }
    // The slot must still be mapped — if a vfork-time mmap/munmap removed
    // it the arm would silently miss.
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = match crate::mm::vmm::virt_to_phys_in(cr3, canary_va) {
        Some(p) => p,
        None => {
            crate::serial_println!(
                "[STACK-CANARY-WATCH] pid={} tid={} state=unmapped canary={:#x}",
                parent_pid, parent_tid, canary_va,
            );
            return None;
        }
    };
    let slot = crate::arch::x86_64::debug_reg::arm_user_va_watchpoint(canary_va, 8);
    match slot {
        Some(s) => {
            crate::serial_println!(
                "[STACK-CANARY-WATCH] pid={} tid={} state=armed slot={} canary_va={:#x} phys={:#x}",
                parent_pid, parent_tid, s, canary_va, phys,
            );
            Some(s)
        }
        None => {
            crate::serial_println!(
                "[STACK-CANARY-WATCH] pid={} tid={} state=pool_exhausted canary_va={:#x}",
                parent_pid, parent_tid, canary_va,
            );
            None
        }
    }
}

/// Clear the latest-canary slot at vfork exit so a stale value from a
/// previous window does not leak into the next.
pub fn reset_canary_target() {
    LATEST_CANARY_SLOT.store(0, Ordering::Release);
}
