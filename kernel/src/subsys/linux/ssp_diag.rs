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
//!   if another CPU is mid-update of the process table.  On lock
//!   contention or absent VMA, the hook emits a single bounded
//!   `[SSP-DIAG] reject reason=…` line (capped at `SSP_REJECT_MAX`
//!   events per boot) and returns without further work.
//!
//! ## RIP-disambiguator
//!
//! After the three primary diagnostic lines, four additional lines fire
//! to distinguish *why* the SSP canary check failed when the saved-cookie
//! value is not a canary-shaped quantity (e.g. it is byte-identical
//! across boots while `fs28_val` varies — see PR #309 entropy):
//!
//!   * `[SSP-DIAG-RA]` — the return-address slot one qword above the
//!     trap RSP (`*[trap_rsp + 8]`), plus the VMA covering it and its
//!     protection bits.  Per System V AMD64 ABI §3.2.2 a callee finds
//!     its return address at `[rsp]` immediately after the `CALL`; here
//!     `trap_rsp` points at the address pushed by `call __stack_chk_fail`,
//!     so `[trap_rsp + 8]` is the caller-to-its-caller return address.
//!     If this slot is not an `r-x` user mapping the trap is not a normal
//!     SSP failure.
//!   * `[SSP-DIAG-PROLOGUE]` — walk backward from the SSP-trap RA looking
//!     for the canonical canary-storing prologue:
//!     `SUB RSP, 0x58` (Intel SDM Vol. 2A: REX.W + 83 /5 ib = `48 83 ec 58`),
//!     followed within 32 bytes by `MOV %fs:0x28, %rax`
//!     (`64 48 8b 04 25 28 00 00 00`) and `MOV %rax, 0x50(%rsp)`
//!     (`48 89 44 24 50`).  This is the exact byte sequence generated by
//!     `-fstack-protector-strong` for a function with frame size 0x58
//!     storing the canary at `[rsp + 0x50]`.  If the walk fails (no
//!     prologue in the preceding 1024 bytes), the trap was reached by
//!     tail-call, sigreturn-mid-frame, or RIP-attribution rot — not by
//!     normal canary-fail flow.
//!   * `[SSP-DIAG-RBP]` — walk 4 frames of the saved-RBP chain starting
//!     from the trap-time RBP (System V AMD64 ABI §3.2.2: `[rbp] =
//!     saved_rbp`, `[rbp + 8] = return_addr`).  Validates monotonic
//!     upward movement and `r-x` return-address VMAs.  A break indicates
//!     omit-frame-pointer code or a corrupted frame chain.
//!   * `[SSP-DIAG-SIGNALS]` — per-thread signal-delivered counter
//!     snapshot (POSIX.1-2017 sigaction(2)).  Zero rules out
//!     sigreturn-mid-frame as the trap precondition.
//!
//! These four lines share the same `SSP_DIAG_MAX` per-boot emission cap
//! as the primary lines; they fire as one tightly-coupled batch.
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

/// Read `len` (≤ 32) bytes from user-VA `addr` into `out`, refusing to
/// cross a 4 KiB boundary.  Same fault-immune direct-map path as
/// [`read_user_qword`] / [`read_user_bytes2`].  Returns the number of
/// bytes actually copied (always `len` on success).
///
/// Cross-page failures are reported back as `Err(CrossPage)` so the
/// prologue walker can chunk its reads page-by-page rather than emit a
/// silent zero result.
fn read_user_bytes_n(addr: u64, out: &mut [u8]) -> Result<(), SspReadErr> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let len = out.len() as u64;
    if len == 0 { return Ok(()); }
    if len > 32 { return Err(SspReadErr::Invalid); }
    if !crate::syscall::validate_user_ptr(addr, out.len()) {
        return Err(SspReadErr::Invalid);
    }
    if (addr & 0xFFF) + len > 0x1000 {
        return Err(SspReadErr::CrossPage);
    }
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = crate::mm::vmm::virt_to_phys_in(cr3, addr)
        .ok_or(SspReadErr::Invalid)?;
    let p = (PHYS_OFF + phys) as *const u8;
    for i in 0..out.len() {
        out[i] = unsafe { core::ptr::read_volatile(p.add(i)) };
    }
    Ok(())
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

// ── RIP-disambiguator helpers ──────────────────────────────────────────────
//
// The disambiguator block below is content-based: it walks the user
// instruction stream backward from the SSP trap's return address looking
// for the canonical canary-storing prologue produced by GCC/Clang under
// `-fstack-protector-strong`.  Per System V AMD64 ABI §3.4.5.2, a frame
// that stores a canary at `[rsp + 0x50]` for an 0x58-byte frame must
// have executed the sequence:
//
//   48 83 ec 58           ; SUB RSP, 0x58
//                         ;   REX.W + 83 /5 ib  (Intel SDM Vol. 2A "SUB")
//   64 48 8b 04 25 28 00 00 00
//                         ; MOV RAX, %fs:0x28
//                         ;   FS prefix (64) + REX.W + 8B /r (MOV r64, m64)
//                         ;   ModRM 04 25 = [disp32]; disp32 = 0x00000028
//                         ;   (Intel SDM Vol. 2A "MOV", Vol. 3A §3.4.4.1)
//   48 89 44 24 50        ; MOV [RSP+0x50], RAX
//                         ;   REX.W + 89 /r (MOV r/m64, r64)
//                         ;   ModRM 44 (mod=01 /r=RAX r/m=100 SIB)
//                         ;   SIB 24 (base=RSP idx=none); disp8=0x50
//
// We don't hard-code the function offset (saga discipline: a future
// libxul rebuild will move it); we hard-code the BYTE SEQUENCE per the
// above ISA encoding.  The first byte sequence is the leader; if found,
// we walk forward up to 32 bytes for the canary-store pair.

/// `SUB RSP, 0x58` byte sequence (REX.W + 83 /5 ib + imm8=0x58).
const PROLOGUE_SUB_RSP_58: [u8; 4] = [0x48, 0x83, 0xec, 0x58];

/// `MOV RAX, %fs:0x28` (FS prefix + REX.W + 8B + SIB-only disp32=0x28).
const PROLOGUE_MOV_FS28_RAX: [u8; 9] =
    [0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00];

/// `MOV [RSP+0x50], RAX` (REX.W + 89 /r + SIB + disp8=0x50).
const PROLOGUE_MOV_RAX_RSP50: [u8; 5] = [0x48, 0x89, 0x44, 0x24, 0x50];

/// How far back from the SSP-trap RA we walk looking for the prologue
/// leader byte sequence.  1 KiB matches typical function sizes for
/// SSP-instrumented C++ code in libxul; longer functions exist but the
/// canary-fail branch is almost always within 1 KiB of the prologue
/// because the canary-store happens at function entry and the
/// canary-check happens at function exit (epilogue).
const PROLOGUE_SCAN_BACK: u64 = 1024;

/// Number of frames to walk in the RBP saved-frame chain.
const RBP_CHAIN_DEPTH: usize = 4;

/// VMA permission encoding for emission.  `r-x` is the expected
/// permission for the SSP-trap RA, the prologue leader, and every saved
/// return address in the RBP chain (per AMD64 ABI §3.4.1 — `.text` is
/// loaded read+execute).
fn perms_str(prot: crate::mm::vma::VmProt) -> &'static str {
    use crate::mm::vma::{PROT_READ, PROT_WRITE, PROT_EXEC};
    let r = prot & PROT_READ  != 0;
    let w = prot & PROT_WRITE != 0;
    let x = prot & PROT_EXEC  != 0;
    match (r, w, x) {
        (true,  false, true ) => "r-x",
        (true,  true,  true ) => "rwx",
        (true,  true,  false) => "rw-",
        (true,  false, false) => "r--",
        (false, false, true ) => "--x",
        (false, true,  false) => "-w-",
        (false, true,  true ) => "-wx",
        (false, false, false) => "---",
    }
}

/// Resolve the VMA covering `addr` and return `(base, end, perms)`.
/// Uses the same `try_lock()` discipline as [`resolve_ld_musl_base`] so
/// the lookup never blocks the trap path.  Returns `None` if the lock is
/// contended (no log line — the caller will already have emitted enough
/// context).
fn lookup_vma_perms(addr: u64) -> Option<(u64, u64, &'static str)> {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.try_lock()?;
    let proc_entry = procs.iter().find(|p| p.pid == pid)?;
    let vm_space = proc_entry.vm_space.as_ref()?;
    let vma = vm_space.find_vma(addr)?;
    Some((vma.base, vma.base + vma.length, perms_str(vma.prot)))
}

/// Walk backward up to `PROLOGUE_SCAN_BACK` bytes from `trap_ra` for
/// the 4-byte `SUB RSP, 0x58` leader, then scan the next 32 bytes for
/// the `MOV %fs:0x28, %rax` and `MOV %rax, 0x50(%rsp)` pair.  Byte-wise
/// (we cannot know instruction boundaries without a disassembler);
/// false positives for the 4-byte leader are rare.  Returns
/// `(Some(prologue_rip), mov_fs28_found, mov_save_found)`.
fn walk_prologue(trap_ra: u64) -> (Option<u64>, bool, bool) {
    let start = trap_ra.saturating_sub(PROLOGUE_SCAN_BACK);
    let mut probe = trap_ra;
    while probe > start {
        probe = probe.saturating_sub(1);
        // Read 4 bytes at probe and compare with the leader.
        let mut buf = [0u8; 4];
        match read_user_bytes_n(probe, &mut buf) {
            Ok(()) => {}
            Err(SspReadErr::CrossPage) | Err(SspReadErr::Invalid) => continue,
        }
        if buf != PROLOGUE_SUB_RSP_58 {
            continue;
        }
        // Leader found.  Walk forward up to 32 bytes for the canary store
        // pair.  We re-read in two chunks to avoid >32-byte limit of
        // read_user_bytes_n.
        let mut tail = [0u8; 16];
        let _ = read_user_bytes_n(probe.wrapping_add(4), &mut tail);
        let mut tail2 = [0u8; 16];
        let _ = read_user_bytes_n(probe.wrapping_add(20), &mut tail2);
        let window = {
            let mut w = [0u8; 32];
            w[..16].copy_from_slice(&tail);
            w[16..].copy_from_slice(&tail2);
            w
        };
        let mov_fs28_found = (0..=23).any(|i| {
            window[i..i + 9] == PROLOGUE_MOV_FS28_RAX
        });
        let mov_save_found = (0..=27).any(|i| {
            window[i..i + 5] == PROLOGUE_MOV_RAX_RSP50
        });
        return (Some(probe), mov_fs28_found, mov_save_found);
    }
    (None, false, false)
}

/// Format an RBP-chain frame as a single space-delimited token suitable
/// for inclusion in the `[SSP-DIAG-RBP]` line.
fn fmt_rbp_frame(
    depth: usize,
    rbp: u64,
    ret: Option<u64>,
    ret_perms: Option<&'static str>,
) -> alloc::string::String {
    match (ret, ret_perms) {
        (Some(r), Some(p)) =>
            alloc::format!("rbp[{}]={:#x} ret={:#x} ret_perms={}", depth, rbp, r, p),
        (Some(r), None) =>
            alloc::format!("rbp[{}]={:#x} ret={:#x} ret_vma=?", depth, rbp, r),
        _ =>
            alloc::format!("rbp[{}]={:#x} ret=?", depth, rbp),
    }
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
///
/// `user_rbp_at_gp` is the saved user RBP at trap time (saved by the
/// ISR stub at frame[-12]).  Per System V AMD64 ABI §3.2.2, when the
/// caller is built with frame pointers it satisfies `[rbp + 0] =
/// saved_rbp` and `[rbp + 8] = return_address`; the RIP-disambiguator
/// uses this to walk the call chain.
pub fn probe_gp_at_ssp_fail(
    rip: u64,
    frame_rsp: u64,
    rax_at_gp: u64,
    user_rbp_at_gp: u64,
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

    // ── [SSP-DIAG-PROV] — Track K phys-provenance for the canary slot ─────
    //
    // F3 hypothesis (per [[track-k-f3-provenance-2026-05-20]]): the libxul
    // function's prologue stored a real canary at VA `saved_slot`, but
    // between prologue and epilogue the page-table mapping for that VA was
    // either replaced (a different phys is now backing the same VA — PTE-
    // replace mechanism) OR the underlying frame was freed+realloced and
    // a sibling thread's content is now visible at the same VA.
    //
    // The diagnostic prints four lines:
    //
    // 1. `[FAULT/PHYS/FREESHADOW]` for the canary slot's current phys —
    //    if hit, the printed caller-RIP names the kernel `pmm::free_page`
    //    call site (addr2line against the kernel ELF) for the frame that
    //    is currently backing the slot.  A FREE hit AFTER the libxul
    //    prologue is the smoking-gun signature of free-then-realloc.
    // 2. `[FAULT/PHYS/ALLOCSHADOW]` for the same phys — names the
    //    `pmm::alloc_page_locked` caller-RIP that handed the frame out;
    //    when paired with FREESHADOW, gives the full FREE→ALLOC pair.
    // 3. `[FAULT/STACK-PTE]` for the canary slot VA — names the most-
    //    recent `map_page_in` / `unmap_page_in` / `write_pte` operator
    //    for that VA in the current address space.  An entry with a
    //    `kind=MAP` and `tick > prologue_tick` is the smoking-gun
    //    signature of PTE-replace.
    // 4. `[FAULT/PHYS/ALLOCSHADOW]` + `[FAULT/PHYS/FREESHADOW]` for the
    //    PTE-ring's recorded `old_phys` — names the prior frame that
    //    backed the slot before the most-recent PTE-change.  Lets the
    //    operator distinguish "the prologue saw frame X, then frame X was
    //    freed and replaced by Y" from "the slot was first mapped at PTE
    //    install time".
    //
    // Per Intel SDM Vol. 3A §4.10.5, paging-structure changes must be
    // globally visible before any frame they reference is repurposed.
    // The diagnostic above lets a reviewer reconstruct the operator-of-
    // record chain that violates the invariant when F3 fires.
    let saved_slot_phys = match read_user_qword(saved_slot) {
        Some((_v, p)) => p & !0xFFFu64,
        None => 0,
    };
    if saved_slot_phys != 0 {
        crate::serial_println!(
            "[SSP-DIAG-PROV] pid={} tid={} saved_slot={:#x} saved_slot_phys={:#x}",
            pid, tid, saved_slot, saved_slot_phys,
        );
        crate::mm::w215_diag::dump_free_shadow_for_phys(saved_slot_phys);
        crate::mm::w215_diag::dump_alloc_shadow_for_phys(saved_slot_phys);
    } else {
        crate::serial_println!(
            "[SSP-DIAG-PROV] pid={} tid={} saved_slot={:#x} saved_slot_phys=UNMAPPED",
            pid, tid, saved_slot,
        );
    }
    let prior_phys = crate::mm::w215_diag::dump_pte_change_for_va(saved_slot);
    if prior_phys != 0 && prior_phys != saved_slot_phys {
        // The PTE-ring recorded a `old_phys` distinct from the slot's
        // current `saved_slot_phys` — confirming a PTE-replace operation
        // happened on this VA.  Dump the FREE/ALLOC shadows for the prior
        // frame so the operator can see whether it has been recycled.
        crate::serial_println!(
            "[SSP-DIAG-PROV-PRIOR] pid={} tid={} prior_phys={:#x}",
            pid, tid, prior_phys,
        );
        crate::mm::w215_diag::dump_free_shadow_for_phys(prior_phys);
        crate::mm::w215_diag::dump_alloc_shadow_for_phys(prior_phys);
    }

    // ── [SSP-DIAG-STACK-PROV] — Track B stack-page write provenance ──────
    //
    // The `f3-watch` DR0–DR3 channel (per [[k2b-f3-user-writer-2026-05-20]])
    // only catches writes whose access goes through the **linear** address
    // (Intel SDM Vol. 3B §17.2.4: data-breakpoint watchpoints trap on
    // linear-VA only).  But every kernel→user-page write today goes
    // through the kernel direct map (`PHYS_OFF + phys`) — signal-frame
    // builders, vfork helper-stack seeds, the auxv/argv setup path in
    // `proc::elf::setup_user_stack`, etc.  Those writes are invisible to
    // DR-watchpoints.
    //
    // This block names any kernel-mode writer that landed on the same
    // physical frame as `saved_slot` while the VA was inside the 0x3f
    // thread-stack window.  Output cap is bounded by the surrounding
    // `SSP_DIAG_MAX` budget; the ring itself is statically-allocated and
    // cannot leak.  See `mm/stack_prov.rs` for the on-record contract.
    #[cfg(feature = "stack-prov")]
    if saved_slot_phys != 0 {
        crate::mm::stack_prov::dump_for_phys(saved_slot_phys);
    }

    // ── RIP-disambiguator block — see module header for the truth table.

    // ── Line 4: [SSP-DIAG-RA] — caller's return-address slot one qword
    //   up from trap RSP (System V AMD64 ABI §3.2.2).
    let ra_into_caller_caller_addr = frame_rsp.wrapping_add(8);
    let (ra_str, ra_vma_str) = match read_user_qword(ra_into_caller_caller_addr) {
        Some((v, _)) => {
            let vma = lookup_vma_perms(v);
            let s = match vma {
                Some((base, end, perms)) => alloc::format!(
                    "ra_vma_start={:#x} ra_vma_end={:#x} ra_vma_perms={}",
                    base, end, perms,
                ),
                None => alloc::string::String::from(
                    "ra_vma_start=? ra_vma_end=? ra_vma_perms=?"),
            };
            (alloc::format!("{:#018x}", v), s)
        }
        None => (
            alloc::string::String::from("?"),
            alloc::string::String::from(
                "ra_vma_start=? ra_vma_end=? ra_vma_perms=?"),
        ),
    };
    crate::serial_println!(
        "[SSP-DIAG-RA] pid={} tid={} ra_slot={:#x} ra={} {}",
        pid, tid, ra_into_caller_caller_addr, ra_str, ra_vma_str,
    );

    // ── Line 5: [SSP-DIAG-PROLOGUE] — walk back from the libxul caller's
    //   SSP-trap RA (`[trap_rsp + 0]`) for the canary-storing prologue.
    let (trap_ra_val, _) = read_user_qword(frame_rsp).unwrap_or((0, 0));
    let (prologue_rip, mov_fs28, mov_save) = if trap_ra_val != 0 {
        walk_prologue(trap_ra_val)
    } else {
        (None, false, false)
    };
    let prologue_bytes_str = match prologue_rip {
        Some(rip) => {
            let mut buf = [0u8; 16];
            match read_user_bytes_n(rip, &mut buf) {
                Ok(()) => alloc::format!(
                    "bytes={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} \
                     {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                    buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ),
                Err(_) => alloc::string::String::from("bytes=?"),
            }
        }
        None => alloc::string::String::from("bytes=?"),
    };
    crate::serial_println!(
        "[SSP-DIAG-PROLOGUE] pid={} tid={} trap_ra={:#x} \
         prologue_found={} prologue_rip={} mov_fs28={} mov_save={} {}",
        pid, tid, trap_ra_val,
        if prologue_rip.is_some() { 1 } else { 0 },
        match prologue_rip {
            Some(r) => alloc::format!("{:#x}", r),
            None    => alloc::string::String::from("?"),
        },
        if mov_fs28 { 1 } else { 0 },
        if mov_save { 1 } else { 0 },
        prologue_bytes_str,
    );

    // ── Line 6: [SSP-DIAG-RBP] — saved-RBP chain (4 frames).
    //   Per AMD64 ABI §3.2.2: `[rbp+0] = saved_rbp_prev`,
    //   `[rbp+8] = return_address`; stack grows down → RBP must
    //   increase across frames.
    let mut rbp_parts: alloc::vec::Vec<alloc::string::String> =
        alloc::vec::Vec::with_capacity(RBP_CHAIN_DEPTH);
    let mut chain_break: Option<(usize, &'static str)> = None;
    let mut cur_rbp = user_rbp_at_gp;
    for depth in 0..RBP_CHAIN_DEPTH {
        if cur_rbp < USER_VA_MIN || cur_rbp >= USER_VA_LIMIT {
            chain_break = Some((depth, "non_canonical"));
            break;
        }
        let saved_rbp = match read_user_qword(cur_rbp) {
            Some((v, _)) => v,
            None => {
                chain_break = Some((depth, "rbp_read_fail"));
                break;
            }
        };
        let ret_addr = read_user_qword(cur_rbp.wrapping_add(8)).map(|(v, _)| v);
        let ret_perms = match ret_addr {
            Some(r) => lookup_vma_perms(r).map(|(_, _, p)| p),
            None    => None,
        };
        rbp_parts.push(fmt_rbp_frame(depth, cur_rbp, ret_addr, ret_perms));
        // Validate: next RBP must be strictly greater (stack grows down,
        // so saved frames are at higher addresses) and still in user VA.
        if depth + 1 < RBP_CHAIN_DEPTH {
            if saved_rbp <= cur_rbp {
                chain_break = Some((depth + 1, "not_monotonic"));
                break;
            }
            cur_rbp = saved_rbp;
        }
    }
    let break_str = match chain_break {
        Some((n, reason)) => alloc::format!("rbp_chain_break={} reason={}", n, reason),
        None              => alloc::string::String::from("rbp_chain_break=none"),
    };
    let joined = {
        let mut s = alloc::string::String::new();
        for (i, p) in rbp_parts.iter().enumerate() {
            if i > 0 { s.push(' '); }
            s.push_str(p);
        }
        s
    };
    crate::serial_println!(
        "[SSP-DIAG-RBP] pid={} tid={} rbp0={:#x} {} {}",
        pid, tid, user_rbp_at_gp, joined, break_str,
    );

    // ── Line 7: [SSP-DIAG-SIGNALS] — per-thread signal-delivered count
    //   (POSIX.1-2017 sigaction(2)).  Zero → sigreturn-mid-frame ruled
    //   out; `?` → cache evicted, cross-check the `[SIGNAL]` log lines.
    let sig_str = match crate::signal::signal_delivered_count(tid as u64) {
        Some(n) => alloc::format!("{}", n),
        None    => alloc::string::String::from("?"),
    };
    crate::serial_println!(
        "[SSP-DIAG-SIGNALS] pid={} tid={} signals_delivered={}",
        pid, tid, sig_str,
    );

    // ── FS-base-trace dump (feature `fs-base-trace`) ────────────────
    // Co-emitted with `[SSP-DIAG]` so the reviewer sees the trapping
    // TID's FS.base event history alongside the trap-time `fs_base`
    // and `fs28_val`.  Distinguishes the kernel-side
    // "FS.base shifted between prologue and epilogue" hypothesis
    // (`new_fs != old_fs` event in the window, kind=write_fs_base or
    // arch_prctl_set_fs) from the userspace foreign-frame hypothesis
    // (no FS.base change events since the initial `arch_prctl_set_fs`).
    // Intel SDM Vol. 3A §3.4.4.1; saga rule: this dump is bounded by
    // `FS_BASE_DUMP_MAX` so adding it to the SSP-DIAG emission preserves
    // bounded-output invariants.
    #[cfg(feature = "fs-base-trace")]
    crate::subsys::linux::fs_base_trace::dump_for_tid(tid as u64);
}
