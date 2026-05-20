//! SSP-canary divergence diagnostic.
//!
//! Fires once per `#GP` taken from CPL 3 at a two-byte `hlt; ret` stub
//! inside the user-mode `ld-musl-x86_64.so.1` mapping.  This is the
//! shape of musl's publicly-exported `__stack_chk_fail` symbol (2-byte
//! body — opcode `0xF4 0xC3`).  When the trap matches, the hook emits
//! three diagnostic lines:
//!
//!   1. `[SSP-DIAG] match=1 pid=… tid=… cpu=… rip=… ld_musl_base=…
//!      vma_offset=… fs_base=… fs28_addr=… fs28_val=… fs28_phys=…`
//!      — IA32_FS_BASE MSR (Intel SDM Vol. 3A §3.4.4.1) and the master
//!      canary at `*(fs_base + 0x28)` per x86_64 psABI §6.4 TLS variant II.
//!      `vma_offset` is the *load-relative* offset (`rip - vma.base`),
//!      which is NOT the same as the symbol's file offset in the ELF
//!      image because `PT_LOAD` entries can place `.text` at a non-zero
//!      `p_offset` with `p_vaddr = 0` (per SysV gABI / `elf(5)`).  This
//!      is precisely why this diagnostic gates on instruction-byte
//!      content rather than a hard-coded offset.
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

/// musl `__stack_chk_fail` body — `hlt; ret` = 2 bytes / opcodes
/// `0xF4 0xC3` (Intel SDM Vol. 2A — `HLT` / `RET`).  Executing `HLT`
/// from CPL 3 raises `#GP` (Intel SDM Vol. 3A §6.15).  This diagnostic
/// classifies a `#GP` as "SSP fail" by READING the two bytes at
/// `rip` (load-relative; safe through the kernel direct map) and
/// requiring `[0xF4, 0xC3]`.
///
/// Note on what we deliberately do NOT use: the symbol's *file offset*
/// inside `ld-musl-x86_64.so.1` (currently `0x1c7f9`).  A `PT_LOAD`
/// segment may map a file offset `p_offset` at a load-relative VA of
/// `p_vaddr` (SysV gABI / `elf(5)`); for ld-musl the text segment is
/// loaded with `p_offset = 0x14000, p_vaddr = 0x0`, so the load-relative
/// VMA offset of `__stack_chk_fail` is `0x1c7f9 - 0x14000 = 0x87f9` —
/// NOT `0x1c7f9`.  A future musl rebuild can shift either side.  The
/// `HLT; RET` byte sequence is far more robust.
const SSP_FAIL_OPCODES: [u8; 2] = [0xF4, 0xC3];

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

/// Independent per-boot cap on `[SSP-DIAG] reject` lines so a verifier
/// can distinguish "hook never reached the precondition" from "hook
/// reached but content gate said no".  Bounded so a bad-RIP storm
/// cannot flood the serial log.
const SSP_REJECT_MAX: u32 = 4;
static SSP_REJECT_COUNT: AtomicU32 = AtomicU32::new(0);

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

/// Read N bytes (N ≤ 8) from a user VA through the kernel direct map,
/// rejecting cross-page straddles.  Returns `Err(CrossPage)` so the
/// caller can emit a specific rejection reason.  Same fault-immune
/// path as [`read_user_qword`].
#[derive(Copy, Clone)]
enum SspReadErr {
    Invalid,
    CrossPage,
}

fn read_user_bytes2(addr: u64) -> Result<[u8; 2], SspReadErr> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    if !crate::syscall::validate_user_ptr(addr, 2) {
        return Err(SspReadErr::Invalid);
    }
    // 2-byte read straddles only when `addr & 0xFFF == 0xFFF`.
    if (addr & 0xFFF) > 0x1000 - 2 {
        return Err(SspReadErr::CrossPage);
    }
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = crate::mm::vmm::virt_to_phys_in(cr3, addr)
        .ok_or(SspReadErr::Invalid)?;
    let p = (PHYS_OFF + phys) as *const u8;
    let b0 = unsafe { core::ptr::read_volatile(p) };
    let b1 = unsafe { core::ptr::read_volatile(p.add(1)) };
    Ok([b0, b1])
}

/// Reserve a rejection-log slot.  Same shape as [`reserve_slot`] but
/// against the independent `SSP_REJECT_COUNT` budget.
fn reserve_reject_slot() -> bool {
    let n = SSP_REJECT_COUNT.fetch_add(1, Ordering::Relaxed);
    n < SSP_REJECT_MAX
}

/// Resolve the load-relative base VA of whatever user mapping covers
/// `rip`.  Looks up the per-process VMA list under a `try_lock()` so
/// the hook never blocks the trap path.
///
/// Per saga discipline (prefer content gates over symbolic ones), this
/// function deliberately does NOT filter by VMA name: the AstryxOS ELF
/// loader names PT_LOAD segments `"[elf]"` and PT_INTERP segments
/// `"[interp]"` (see `proc/elf.rs`), neither of which contains the
/// substring `"ld-musl"`.  A name-based gate is therefore brittle by
/// construction.  The upstream gates that protect this hook are:
///   * `idt.rs` only calls the hook on `vector == 13 && CS&3 == 3`
///     (user-mode `#GP`, Intel SDM Vol. 3A §6.15).
///   * The caller-side content gate then requires the 2 bytes at `rip`
///     to be `HLT; RET` (`0xF4 0xC3`).  Per Intel SDM Vol. 2A `HLT`
///     is a privileged instruction; executing it at CPL 3 raises `#GP`.
/// Combined, those two conditions uniquely identify a musl
/// `__stack_chk_fail`-shaped stub regardless of which mapping it lives
/// in, so the VMA name is irrelevant.
///
/// Returns `Some(base)` when a VMA covers `rip`, its `base` is a sane
/// user VA, and `rip - base < 0x80_0000` (8 MiB — generous bound for
/// any reasonable shared library `.text` segment).  Emits a bounded
/// `reject` line when the lock is contended or no VMA covers `rip`,
/// so a verifier can distinguish "hook never reached the precondition"
/// from "hook reached but content gate said no".
fn resolve_ld_musl_base(rip: u64) -> Option<u64> {
    let pid = crate::proc::current_pid_lockless();
    let procs = match crate::proc::PROCESS_TABLE.try_lock() {
        Some(g) => g,
        None => {
            if reserve_reject_slot() {
                crate::serial_println!(
                    "[SSP-DIAG] reject reason=lock_busy rip={:#x}",
                    rip,
                );
            }
            return None;
        }
    };
    let proc_entry = procs.iter().find(|p| p.pid == pid)?;
    let vm_space = proc_entry.vm_space.as_ref()?;
    let vma = match vm_space.find_vma(rip) {
        Some(v) => v,
        None => {
            if reserve_reject_slot() {
                crate::serial_println!(
                    "[SSP-DIAG] reject reason=no_vma rip={:#x}",
                    rip,
                );
            }
            return None;
        }
    };
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

    // Content gate: require the 2 bytes at RIP to be `HLT; RET`
    // (`0xF4 0xC3`) — the musl `__stack_chk_fail` body.  This is
    // robust to PT_LOAD-driven offset shifts (SysV gABI / `elf(5)`)
    // and to future musl rebuilds that move the symbol.  Reads go
    // through the same fault-immune direct-map path used elsewhere
    // in this file (PR #333).
    let cs_user = 1u8; // hook is only called from CPL 3 #GP; recorded for logs.
    match read_user_bytes2(rip) {
        Ok(bytes) => {
            if bytes != SSP_FAIL_OPCODES {
                if reserve_reject_slot() {
                    crate::serial_println!(
                        "[SSP-DIAG] reject reason=bytes \
                         rip={:#x} bytes={:02x} {:02x} cs={} vma_offset={:#x}",
                        rip, bytes[0], bytes[1], cs_user, vma_offset,
                    );
                }
                return;
            }
        }
        Err(SspReadErr::CrossPage) => {
            if reserve_reject_slot() {
                crate::serial_println!(
                    "[SSP-DIAG] reject reason=cross_page \
                     rip={:#x} cs={} vma_offset={:#x}",
                    rip, cs_user, vma_offset,
                );
            }
            return;
        }
        Err(SspReadErr::Invalid) => {
            if reserve_reject_slot() {
                crate::serial_println!(
                    "[SSP-DIAG] reject reason=read_invalid \
                     rip={:#x} cs={} vma_offset={:#x}",
                    rip, cs_user, vma_offset,
                );
            }
            return;
        }
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
