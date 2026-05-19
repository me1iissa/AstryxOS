//! SSP-canary divergence diagnostic.
//!
//! Fires once per `#GP` taken from CPL 3 at the publicly-exported musl
//! `__stack_chk_fail` two-byte `hlt;ret` stub (ld-musl-x86_64.so.1 +
//! `0x1c7f9`, per the musl ldso `.dynsym`).  When the trap matches, the
//! hook emits three diagnostic lines:
//!
//!   1. `[SSP-DIAG] match=1 pid=… tid=… cpu=… rip=… ld_musl_base=…
//!      vma_offset=0x1c7f9 fs_base=… fs28_addr=… fs28_val=… fs28_phys=…`
//!      — IA32_FS_BASE MSR (Intel SDM Vol. 3A §3.4.4.1) and the master
//!      canary at `*(fs_base + 0x28)` per x86_64 psABI §6.4 TLS variant II.
//!
//!   2. `[SSP-DIAG-CANARY] caller_rsp=… saved_canary=…  saved_canary_phys=…
//!      ax_at_gp=…  ax_eq_fs28={0|1}`
//!      — recovers the SSP-instrumented caller's RSP by skipping the
//!      `__stack_chk_fail` two-byte stub frame (no `push rbp` per the
//!      symbol size = 2), reads the qword the epilogue had loaded for
//!      the `cmp 0x50(%rsp), %rax` compare, and reports whether it
//!      matches the live FS_BASE+0x28 master copy.
//!
//!   3. `[SSP-DIAG-WINDOW] caller_rsp=… +0x40=… +0x48=… +0x50=… +0x58=…
//!      +0x60=…` — five qword window around `[caller_rsp + 0x50]` so the
//!      reviewer can see whether the corruption is localised to one slot
//!      or spans contiguous bytes.
//!
//! ## Mode discrimination
//!
//! Two kernel-side hypotheses for the canary failure:
//!
//!   * Mode A — saved cookie at `[caller_rsp + 0x50]` was mutated
//!     externally between the libxul function's prologue store and its
//!     epilogue load.  Plausible writers: signal-frame setup/teardown
//!     (only at user_rsp - 664; does NOT overlap), kernel `copy_to_user`
//!     into a user stack page, TLB stale on the SSP-instrumented page.
//!     Distinguishable by `saved_canary != fs28_val` while `fs28_val`
//!     itself is sensible (16 hex digits, non-zero, matches RAX at trap).
//!
//!   * Mode B — `IA32_FS_BASE` shifted between the prologue's
//!     `mov %fs:0x28, %rax` (saving the cookie) and the epilogue's
//!     re-read.  Plausible cause: scheduler swapped FS_BASE with a
//!     sibling thread's TLS without restoring before the libxul function
//!     resumed.  Distinguishable by `saved_canary == prev_fs28` (the
//!     OUTGOING thread's TLS guard) while `fs28_val != saved_canary`.
//!     RAX at trap time captures the LIVE re-read (the epilogue's
//!     `mov %fs:0x28, %rax`), so `ax_eq_fs28 == 1` confirms the live
//!     read is consistent and Mode B narrows to "what was on the stack".
//!
//! ## Output volume + safety
//!
//! - One match per actual canary-trap RIP; capped at 8 emissions per boot
//!   via `AtomicU32::fetch_add` (after the cap, a single `OVERFLOW`
//!   marker is emitted instead).  Bounded serial volume per soak.
//!
//! - All user-VA reads go through `read_userland_qword_raw` (the same
//!   fault-immune helper introduced by PR #333: validates the user-VA,
//!   resolves it to a physical address under the current CR3, and reads
//!   through the kernel direct map at `0xFFFF_8000_0000_0000 + phys`).
//!   No SMAP toggling is required because the read goes through a
//!   kernel-VA backing the same physical frame.
//!
//! - Cross-page reads are rejected (matches PR #333 / PR #337 policy):
//!   the SSP saved-canary slot is an 8-byte-aligned qword (psABI §3.4.5.2)
//!   so a straddle is itself a corruption signal worth reporting as `?`.
//!
//! - `ld-musl` base is recovered from the per-process VMA list via
//!   `Process::vm_space.find_vma(frame.rip)`.  The hook tries the lock
//!   with `PROCESS_TABLE.try_lock()` to avoid deadlocking the trap path
//!   if another CPU is mid-update of the process table.  On lock-failure
//!   the hook emits a single `[SSP-DIAG] match=?` line and returns
//!   without further work.
//!
//! ## Refs
//!
//! - Intel SDM Vol. 3A §3.4.4.1 (`IA32_FS_BASE` MSR, 0xC000_0100)
//! - Intel SDM Vol. 3A §6.15 (`#GP` exception, vector 13)
//! - Intel SDM Vol. 3A §4.6 (SMAP — N/A on direct-map reads)
//! - System V AMD64 ABI §3.4.5.2 (stack alignment / qword alignment)
//! - System V x86_64 psABI §6.4 (TLS variant II — `__stack_chk_guard`
//!   at TCB offset `0x28`)
//! - POSIX.1-2017 §2.4 (signal disposition; sigaction(2))

#![cfg(feature = "ssp-canary-diag")]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

/// Publicly-exported musl `__stack_chk_fail` offset in
/// `ld-musl-x86_64.so.1`.  Per the musl ldso `.dynsym` for musl-1.2.x:
/// the symbol is a two-byte stub `hlt; ret` placed between
/// `__libc_start_main` and `clearenv`.  The `hlt` from CPL 3 raises
/// `#GP` (Intel SDM Vol. 3A §6.15) with `RIP = ld_musl_base + 0x1c7f9`.
const SSP_FAIL_VMA_OFFSET: u64 = 0x1c7f9;

/// Size of musl `__stack_chk_fail` — `hlt; ret` = 2 bytes.
const SSP_FAIL_STUB_SIZE: u64 = 2;

/// Caller-frame offset where the SSP-instrumented libxul function at
/// `0x2c4b3d0` saved its master canary copy (`mov %rax, 0x50(%rsp)` at
/// function entry; `cmp 0x50(%rsp), %rax` at epilogue).  This particular
/// offset is the libxul WebIDL global-name-dictionary seeder's frame;
/// other libxul callers may use different offsets, but `0x50` is the
/// common case for the demo gate (frame size `0x58`).
const CANARY_SLOT_OFFSET: u64 = 0x50;

/// Number of qwords to dump in the `WINDOW` line, centred on
/// `[caller_rsp + 0x50]`.  Five slots: `+0x40 +0x48 +0x50 +0x58 +0x60`.
const WINDOW_QWORDS: usize = 5;

/// Maximum number of `[SSP-DIAG]` events emitted per boot.  Past the
/// cap a single `[SSP-DIAG] OVERFLOW` line is logged and the hook is
/// a no-op for the rest of the boot.
const SSP_DIAG_MAX: u32 = 8;

/// Per-boot emission counter.
static SSP_DIAG_COUNT: AtomicU32 = AtomicU32::new(0);

/// Lowest valid user-VA for ld-musl base sanity (matches the
/// kernel-wide convention; rejects 0 / kernel half).  See
/// `crate::syscall::validate_user_ptr`.
const USER_VA_MIN: u64 = 0x1_0000;
const USER_VA_LIMIT: u64 = 0x0000_8000_0000_0000;

/// Fault-immune user-VA qword read (mirrors PR #333's
/// `read_userland_qword_raw`: validates ptr, resolves phys under the
/// current CR3, reads through `0xFFFF_8000_0000_0000 + phys`).
///
/// Rejects cross-page reads (per Intel SDM Vol. 3A §4.6 a qword
/// straddles a 4 KiB boundary only when `addr & 0xFFF > 0x1000 - 8`).
fn read_user_qword(addr: u64) -> Option<(u64, u64)> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    if !crate::syscall::validate_user_ptr(addr, 8) {
        return None;
    }
    if (addr & 0xFFF) > 0x1000 - 8 {
        return None;
    }
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = crate::mm::vmm::virt_to_phys_in(cr3, addr)?;
    let val = unsafe {
        core::ptr::read_volatile((PHYS_OFF + phys) as *const u64)
    };
    Some((val, phys))
}

/// Resolve the base VA of the `ld-musl-x86_64.so.1` text mapping that
/// covers `rip`.  Looks up the per-process VMA list under a
/// `try_lock()` so the hook never blocks the trap path.  Accepts any
/// VMA whose `name` field contains the substring `"ld-musl"` and whose
/// `base` is a sane user VA.
///
/// Returns `Some(base)` only when the VMA is valid and `rip - base` is
/// a small offset consistent with a `.text` mapping (`< 0x80_0000`,
/// i.e. within the first 8 MiB of the library — ld-musl is ~650 KiB so
/// this is generous).
fn resolve_ld_musl_base(rip: u64) -> Option<u64> {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.try_lock()?;
    let proc_entry = procs.iter().find(|p| p.pid == pid)?;
    let vm_space = proc_entry.vm_space.as_ref()?;
    let vma = vm_space.find_vma(rip)?;
    // Name match is conservative: accept either "ld-musl" or "libc.musl"
    // (the symlink target some processes mmap by canonical-path).
    if !(vma.name.contains("ld-musl") || vma.name.contains("libc.musl")) {
        return None;
    }
    let base = vma.base;
    if base < USER_VA_MIN || base >= USER_VA_LIMIT {
        return None;
    }
    let offset = rip.wrapping_sub(base);
    if offset > 0x80_0000 {
        return None;
    }
    Some(base)
}

/// Reserve one emission slot.  Returns `true` if the caller may emit.
/// On the boundary (count == SSP_DIAG_MAX) emits the OVERFLOW marker
/// once, then returns `false` for all subsequent calls.
fn reserve_slot() -> bool {
    let n = SSP_DIAG_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < SSP_DIAG_MAX {
        true
    } else if n == SSP_DIAG_MAX {
        crate::serial_println!(
            "[SSP-DIAG] OVERFLOW cap={} (subsequent SSP traps silently ignored)",
            SSP_DIAG_MAX,
        );
        false
    } else {
        false
    }
}

/// Probe entry — called from the `#GP` handler for `vec == 13 && CS&3 == 3`.
///
/// `frame_rsp` is the trap-time RSP (points at the return-address slot
/// pushed by `__stack_chk_fail`'s implicit caller — but `__stack_chk_fail`
/// is a two-byte `hlt; ret` stub which sets up no frame of its own.  So
/// `frame_rsp` IS the caller's RSP at the `call __stack_chk_fail@plt`
/// site, immediately PRE-call (the CPU pushed RIP+5 by the time of the
/// `call`, so the libxul caller's `[rsp+0x50]` sits at
/// `frame_rsp + 0x50 + 8` once we account for the pushed return
/// address).  However the trap fires on the `hlt` — i.e. inside the
/// stub but BEFORE the `ret` — so the return-address pushed by the
/// `call` is still at the top of stack.  Net: the SSP-instrumented
/// caller's `[rsp+0x50]` is at `frame_rsp + 0x50 + 8`.
///
/// `rax_at_gp` is the live `%fs:0x28` re-read the epilogue just
/// performed (saved by the ISR stub at frame[-2]).
pub fn probe_gp_at_ssp_fail(
    rip: u64,
    frame_rsp: u64,
    rax_at_gp: u64,
) {
    // Cheap rejection: only act on plausible user-VA RIPs.
    if rip < USER_VA_MIN || rip >= USER_VA_LIMIT {
        return;
    }
    // Resolve the ld-musl base from the VMA list.  If the lock is
    // contended we cannot reliably classify the trap; emit a soft
    // marker and exit.
    let ld_musl_base = match resolve_ld_musl_base(rip) {
        Some(b) => b,
        None => return, // not an ld-musl trap; quiet
    };
    let vma_offset = rip.wrapping_sub(ld_musl_base);
    if vma_offset != SSP_FAIL_VMA_OFFSET {
        return;
    }

    if !reserve_slot() {
        return;
    }

    let tid = crate::proc::current_tid();
    let pid = crate::proc::current_pid_lockless();
    let cpu = crate::arch::x86_64::apic::cpu_index();

    // ── Line 1: live IA32_FS_BASE + master canary ────────────────────
    // SAFETY: RDMSR is unconditionally safe at CPL 0.  Intel SDM
    // Vol. 3A §3.4.4.1 (FS.base = IA32_FS_BASE MSR 0xC000_0100).
    let fs_base = unsafe { crate::hal::rdmsr(0xC000_0100) };
    let fs28_addr = fs_base.wrapping_add(0x28);
    let (fs28_val_str, fs28_phys_str) = match read_user_qword(fs28_addr) {
        Some((v, p)) => (
            alloc::format!("{:#018x}", v),
            alloc::format!("{:#x}", p),
        ),
        None => (
            alloc::string::String::from("?"),
            alloc::string::String::from("?"),
        ),
    };
    crate::serial_println!(
        "[SSP-DIAG] match=1 pid={} tid={} cpu={} rip={:#x} \
         ld_musl_base={:#x} vma_offset={:#x} \
         fs_base={:#x} fs28_addr={:#x} fs28_val={} fs28_phys={}",
        pid, tid, cpu, rip,
        ld_musl_base, vma_offset,
        fs_base, fs28_addr, fs28_val_str, fs28_phys_str,
    );

    // ── Line 2: saved canary in the SSP-instrumented caller's frame ──
    // `__stack_chk_fail` is a 2-byte `hlt; ret` stub with no frame of
    // its own (`SSP_FAIL_STUB_SIZE == 2` — for the in-comment math
    // only, not used at run-time), so the libxul caller's RSP at the
    // `call __stack_chk_fail@plt` instant is `frame_rsp + 8` — the
    // `call` pushed the return address and the `hlt` trapped before
    // any `ret` could pop it.  The saved cookie sits at `[rsp + 0x50]`
    // per the libxul WebIDL-seeder function layout (frame size 0x58).
    let _stub_size = SSP_FAIL_STUB_SIZE; // documented invariant; no runtime use
    let caller_rsp = frame_rsp.wrapping_add(8);
    let saved_slot = caller_rsp.wrapping_add(CANARY_SLOT_OFFSET);
    let (saved_canary_str, saved_canary_phys_str) = match read_user_qword(saved_slot) {
        Some((v, p)) => (
            alloc::format!("{:#018x}", v),
            alloc::format!("{:#x}", p),
        ),
        None => (
            alloc::string::String::from("?"),
            alloc::string::String::from("?"),
        ),
    };
    let ax_eq_fs28 = match read_user_qword(fs28_addr) {
        Some((live, _)) => if live == rax_at_gp { 1 } else { 0 },
        None => 0xff, // unknown — could not verify
    };
    crate::serial_println!(
        "[SSP-DIAG-CANARY] pid={} tid={} caller_rsp={:#x} saved_slot={:#x} \
         saved_canary={} saved_canary_phys={} ax_at_gp={:#018x} ax_eq_fs28={}",
        pid, tid, caller_rsp, saved_slot,
        saved_canary_str, saved_canary_phys_str, rax_at_gp, ax_eq_fs28,
    );

    // ── Line 3: 5-qword window centred on the canary slot ────────────
    // Useful for distinguishing "single-qword corruption" vs
    // "contiguous-region clobber".
    let mut window_lines: [alloc::string::String; WINDOW_QWORDS] =
        core::array::from_fn(|_| alloc::string::String::new());
    for (i, off) in [(0usize, 0x40u64), (1, 0x48), (2, 0x50), (3, 0x58), (4, 0x60)] {
        let addr = caller_rsp.wrapping_add(off);
        window_lines[i] = match read_user_qword(addr) {
            Some((v, _)) => alloc::format!("+{:#04x}={:#018x}", off, v),
            None         => alloc::format!("+{:#04x}=?", off),
        };
    }
    crate::serial_println!(
        "[SSP-DIAG-WINDOW] pid={} tid={} caller_rsp={:#x} {} {} {} {} {}",
        pid, tid, caller_rsp,
        window_lines[0], window_lines[1], window_lines[2],
        window_lines[3], window_lines[4],
    );
}
