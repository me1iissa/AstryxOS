//! F3 data-write DR watchpoint on the deterministic SSP-canary slot at
//! `parent_rsp + 0x58` (= the user VA whose contents PR #421 named as
//! `0x30` byte-invariant across trials).
//!
//! # Why a write-DR watch (companion to PR #421)
//!
//! PR #421 armed an instruction-execute DR on musl `__stack_chk_fail+0x0`
//! and captured the SSP epilogue's caller-frame snapshot.  That named the
//! *slot* — user VA `parent_rsp + 0x58` = `0x7ffffffee4c0` for the
//! reproducible boot — but did not name the *writer*.  The dispositive
//! evidence we still need is the RIP of the instruction that stamps the
//! observed `0x30` byte into the slot AFTER the musl SSP prologue's
//! canary store has already happened.
//!
//! Per Intel SDM Vol. 3B §17.2.4 Table 17-2 the DR control encoding for
//! a data-write watchpoint on an 8-byte qword is `R/W = 01b` (write only)
//! and `LEN = 10b` (8 bytes — the qword form, valid on x86_64 per
//! §17.2.5).  Per §17.3.1.1 data-breakpoint exceptions are *traps* —
//! taken AFTER the writing instruction has retired — so the `#DB` frame's
//! `rip` points to the NEXT instruction.  The writer's RIP is recovered
//! by reading backwards from that anchor (see "Writer-RIP reconstruction"
//! below).
//!
//! # What this captures
//!
//! On a single fire, emits one `[F3/WRITE-DR-FIRE]` block containing:
//!
//!   * All 15 saved GPRs (RAX–R15) + RFLAGS + RIP-after-trap + CS + DR6
//!   * The post-write value at the watched slot (the `0x30` byte we
//!     expect, confirming the writer stored the corrupting value)
//!   * 9 qwords at `[rsp..rsp+0x40]` (the writer's local frame context)
//!   * 16 bytes at `[rip_after_trap - 0x10]` so a post-processor can
//!     disassemble backward to the writing instruction itself
//!   * The KERNEL_VIRTUAL_TICKS ordinal at fire time (per-CPU TSC tick)
//!   * The most recent `[VFORK/CANARY] post_wake.*` epoch index
//!
//! All offsets and library-relative RIPs should be byte-identical across
//! ASLR-normalised boots; a divergence indicates non-determinism leak.
//!
//! # Writer-RIP reconstruction
//!
//! Per Intel SDM Vol. 3B §17.3.1.1: "All data breakpoint exceptions are
//! reported as traps."  A trap fires after the offending instruction
//! retires — so by the time the `#DB` is dispatched, the writer's RIP
//! is already incremented past the store.  The standard
//! post-processor flow is:
//!
//!   1. Capture `rip_after_trap` from the `#DB` frame (this is the RIP
//!      of the instruction the CPU *would have* executed next).
//!   2. Capture 16 bytes at `[rip_after_trap - 0x10]` from the user
//!      address space.
//!   3. Disassemble those 16 bytes; the writing instruction is the one
//!      whose end aligns to `rip_after_trap`.
//!
//! AMD64 instructions are 1..15 bytes (Intel SDM Vol. 2A §2.1) so 16
//! bytes always covers the prior instruction.  Symbolisation against
//! the per-trial libxul/libc bases (resolved at arm time and emitted in
//! the fire line) then names the writer function and offset.
//!
//! # Arm site
//!
//! `try_arm_after_post_wake(pid, tid)` is called from the Linux
//! clone(2) / clone3(2) syscall path in `subsys/linux/syscall.rs`,
//! immediately after the existing `vfork_canary_snapshot("post_wake.clone*", …)`
//! emission.  Path-gated to PID 1 only (the firefox-bin init thread)
//! and bounded by a single boot-wide one-shot — once the DR fires the
//! slot disarms.
//!
//! The slot VA is **discovered** at arm time, not assumed.  Empirical
//! evidence from PR #421's first deployment trial (this branch's
//! ad-hoc dispatch) showed that the `parent_user_rsp` captured at the
//! vfork wake is NOT the same as the `rsp` value the SSP epilogue
//! sees at fail time — the wake unwinds back through several frames
//! before the SSP-failing function is re-entered.  So the simple
//! `parent_user_rsp + 0x58` derivation from PR #421's epilogue-time
//! frame is wrong when applied at wake-time.
//!
//! Instead, the arm hook resolves the slot VA by **scanning the
//! parent's post-wake 8 KiB user-stack window for the master canary
//! value** (the qword stored at `fs:0x28`).  The SSP prologue's
//! canary store deposits this exact qword into `[rbp-8]` of every
//! `-fstack-protector` instrumented function; the first matching
//! qword above `parent_user_rsp` is the dispositive slot (per System
//! V AMD64 ABI §3.4.1 and GCC manual §3.20).  When a later writer
//! overwrites it with the observed `0x30` byte the write-DR fires on
//! the corrupting instruction.
//!
//! If the master canary cannot be read (FS_BASE misconfigured, slot
//! unmapped, etc.) the arm is skipped and the diagnostic emits a
//! `state=no_canary` line.  If the scan finds no match in the window
//! the arm emits `state=no_match_in_window` so the post-processor
//! can diagnose missing instrumentation.
//!
//! # Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4 Table 17-2 (DR0–DR3 / DR7 encoding;
//!     RW=01b / LEN=10b for 8-byte write breakpoints).
//!   * Intel SDM Vol. 3B §17.2.5 (DR6 / DR7 — 8-byte LEN encoding
//!     valid on x86_64).
//!   * Intel SDM Vol. 3B §17.3.1.1 (#DB data-breakpoint trap timing —
//!     taken after the watched instruction retires).
//!   * Intel SDM Vol. 3A §6.15 (#DB vector 1 dispatch).
//!   * Intel SDM Vol. 2A §2.1 (instruction length 1..15 bytes — used by
//!     the writer-RIP reconstruction window sizing).
//!   * System V AMD64 ABI §3.4.1 (SSP / `__stack_chk_guard`),
//!     §3.4.5.2 (frame-pointer convention).
//!   * GCC manual §3.20 (`-fstack-protector` epilogue check).
//!   * POSIX `vfork(3p)`, `clone(2)`, `clone3(2)`.
//!   * PR #421 (code-fetch caller-frame snapshot — names the slot),
//!     PR #420 (autopsy verdict, byte-invariant `0x30` in the slot),
//!     PR #417 (libxul SSP-shape audit).

#![cfg(feature = "f3-codeDR-write-watch")]

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Bytes of user stack to scan above `parent_user_rsp` looking for the
/// master canary qword.  Matches the existing 8 KiB
/// `vfork_canary_snapshot` window (`subsys/linux/syscall.rs`).  Per
/// PR #420 / #421 the SSP-failing frame's `[rbp-8]` slot lives at
/// `parent_rsp + ~0x1db8` for the libxul / musl frame layout in the
/// reproducer; an 8 KiB window comfortably covers any plausible
/// `-fstack-protector` instrumented caller chain above the
/// vfork-wake's stack pointer.
const STACK_SCAN_BYTES: usize = 0x2000;

/// Maximum number of canary-matches to arm per post_wake invocation.
/// The hardware exposes 4 DR slots (Intel SDM Vol. 3B §17.2.4); the
/// F3 arm path uses `arm_linear_watchpoint` which preferentially
/// picks DR1/DR2/DR3 and falls back to DR0.  Capping the per-arm
/// canary-match arms at 2 leaves room for the dedicated empirical-
/// offset arm (below) plus DR0 for the legacy W215 CRC walker.
const MAX_HITS: usize = 2;

/// Empirical offset above `parent_user_rsp` where the SSP-failing
/// frame's `[rbp-8]` canary slot lives in the FF + musl reproducer.
/// Derived from PR #420 / #421 / this branch's v1 deployment evidence:
///
///   * Post_wake parent_rsp captured at the vfork-wake syscall is
///     `0x7ffffffec708` (byte-identical across all observed boots —
///     the kernel's `USER_STACK_TOP` is deterministic).
///   * SSP-fail captured RSP is `0x7ffffffee468` (byte-identical
///     across PR #420 / PR #421 / this branch's v1 first-trial soak
///     evidence — also deterministic, set by libxul's posix_spawn
///     call site).
///   * SSP-fail slot per PR #421 is `[rsp+0x58]` =
///     `0x7ffffffee4c0`.
///   * Delta: `0x7ffffffee4c0 - 0x7ffffffec708 = 0x1db8`.
///
/// Arming this fixed offset catches BOTH the prologue's canary
/// stamp (the first legitimate write to the slot, when the SSP-
/// failing function is later entered) AND any subsequent foreign
/// store (the corrupting `0x30` write).  The fire-cap on
/// `WATCH_KIND_F3_WRITE_DR` (set in `arch/x86_64/debug_reg.rs`)
/// determines how many writes get logged before the slot self-
/// disarms.
const EMPIRICAL_FAIL_SLOT_OFFSET: u64 = 0x1db8;

/// PID gate — only the firefox-bin init thread's process.
const F3_TARGET_PID: u64 = 1;

/// Watch width in bytes.  Per Intel SDM Vol. 3B §17.2.4 Table 17-2 the
/// supported LEN encodings are 1/2/4/8 bytes; the slot we care about is
/// the 8-byte SSP-canary qword, so 8 bytes (LEN=10b) is the natural
/// width.  Picked up by `arm_linear_watchpoint` which maps 8 → LEN=10b
/// in `dr7_bits_for_slot`.
const WATCH_LEN: u8 = 8;

/// Bytes of instruction-stream context to capture below `rip_after_trap`
/// for the post-processor's backward-disassembly pass.  Per Intel SDM
/// Vol. 2A §2.1 AMD64 instructions are 1..15 bytes, so 16 bytes always
/// brackets the prior instruction that issued the offending store.
const BACK_INSN_BYTES: usize = 16;

/// One-shot arm flag.  `true` after the first successful arm.
static ARMED_ONCE: AtomicBool = AtomicBool::new(false);

/// Per-arm fire counter.  Incremented on every `record_fire` call;
/// included in the fire line so the post-processor can sequence
/// multiple writes to the same slot.  Bounded above by the
/// `F3_FIRE_CAP` (`32`) check in
/// `arch::x86_64::debug_reg::handle_db_exception` — beyond that the
/// slot self-disarms and a final fire with `one_shot=1` is emitted.
static FIRE_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Snapshot of the per-CPU virtual tick counter at the arm time.
static ARM_TICK: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the resolved target VA at arm time — emitted in the fire
/// line so post-processing can confirm the trap matched the armed slot.
/// Zero means "not yet armed".
static ARMED_TARGET_VA: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the parent user RSP at arm time — emitted in the fire
/// line so post-processing can correlate against the
/// `[VFORK/CANARY] post_wake` evidence.
static ARMED_PARENT_RSP: AtomicU64 = AtomicU64::new(0);

/// Resolve the parent's user RSP from its kernel-stack saved frame.
/// Per the `syscall_entry` save layout in `kernel/src/syscall/mod.rs`
/// the parent's user RSP sits at `kstack_top - 8` (frame slot 14).
/// Mirrors `vfork_canary_snapshot`'s read; returns `None` if the
/// thread can't be found or has no kernel stack.
fn parent_user_rsp_for(parent_tid: u64) -> Option<u64> {
    let threads = crate::proc::THREAD_TABLE.try_lock()?;
    let t = threads.iter().find(|t| t.tid == parent_tid)?;
    let kstack_top = t.kernel_stack_base + t.kernel_stack_size;
    if kstack_top == 0 {
        return None;
    }
    // SAFETY: kstack_top is a kernel-mapped address; the qword at
    // kstack_top - 8 is the parent's saved user RSP per the syscall
    // entry stub.  Read through the kernel VA (not user VA) so no
    // SMAP bracket is required.
    let rsp = unsafe { core::ptr::read_volatile((kstack_top - 8) as *const u64) };
    Some(rsp)
}

/// Scan `[parent_rsp, parent_rsp + STACK_SCAN_BYTES)` in 8-byte strides
/// for **all** qwords equal to `canary` and return up to `MAX_HITS`
/// matching user VAs in ascending-address order.  Walks via
/// `user_slice_snapshot` (SMAP-bracketed) so the kernel-mode read is
/// safe even with SMAP enabled (Intel SDM Vol. 3A §4.6).
///
/// Per System V AMD64 ABI §3.4.1 the SSP prologue stores the master
/// canary verbatim into `[rbp-8]` of every instrumented function;
/// when several instrumented frames are stacked above `parent_rsp`
/// the canary appears multiple times.  PR #420 / #421 evidence shows
/// the SSP-FAILING frame is several callers ABOVE the closest match
/// — i.e. its slot is HIGHER in the stack window (closer to the
/// 8 KiB ceiling), not at the first match.  Returning all matches
/// lets the arm site cover every plausible slot with one DR slot per
/// match (Intel SDM Vol. 3B §17.2.4 — 4 DR slots per CPU, of which
/// the F3 arm path consumes DR1..DR3 first by convention).
fn scan_window_for_canary(parent_rsp: u64, canary: u64, out: &mut [u64; MAX_HITS]) -> usize {
    if parent_rsp == 0 {
        return 0;
    }
    if !crate::syscall::validate_user_ptr(parent_rsp, STACK_SCAN_BYTES) {
        return 0;
    }
    let Some(buf) = (unsafe {
        crate::syscall::user_slice_snapshot(parent_rsp, STACK_SCAN_BYTES)
    }) else { return 0; };
    let canary_bytes = canary.to_le_bytes();
    let mut off = 0usize;
    let mut n_total = 0usize;
    // First pass: count matches and record up to MAX_HITS LATEST.  A
    // ring of size MAX_HITS keeps the highest-address matches, which
    // is what the SSP-failing-frame heuristic above wants.
    let mut ring: [u64; MAX_HITS] = [0; MAX_HITS];
    while off + 8 <= buf.len() {
        if buf[off..off + 8] == canary_bytes {
            ring[n_total % MAX_HITS] = parent_rsp.wrapping_add(off as u64);
            n_total += 1;
        }
        off += 8;
    }
    let kept = core::cmp::min(n_total, MAX_HITS);
    if kept == 0 {
        return 0;
    }
    // Re-order the ring into ascending-address `out[0..kept]`.  Ring
    // start index = (n_total - kept) % MAX_HITS; entries from there
    // (mod MAX_HITS) are already in ascending order because the scan
    // is forward-stride.
    let start = (n_total - kept) % MAX_HITS;
    for i in 0..kept {
        out[i] = ring[(start + i) % MAX_HITS];
    }
    kept
}

/// Try to arm the data-write DR watchpoint after the existing
/// `[VFORK/CANARY] post_wake.*` snapshot completes.  Called from
/// `subsys/linux/syscall.rs` at both the clone(2) and clone3(2)
/// post-wake sites.  Bounded by `ARMED_ONCE` to a single arm per boot.
///
/// On the qualifying call (PID 1, ARMED_ONCE was false):
///   * Resolves `parent_user_rsp` from the THREAD_TABLE slot-14 read.
///   * Reads the master canary from FS_BASE + 0x28 (Intel SDM Vol. 3A
///     §3.4.4.1, ELF gABI stack-protector §6).
///   * Scans the parent's 8 KiB post-wake stack window for the first
///     qword equal to the master canary — that location is the
///     SSP slot `[rbp-8]` of the nearest instrumented caller frame
///     (System V AMD64 ABI §3.4.1; GCC manual §3.20).
///   * Captures the current TICK_COUNT in `ARM_TICK`.
///   * Issues `arm_linear_watchpoint(slot_va, 8, WATCH_KIND_F3_WRITE_DR)`,
///     which programs a write-only / 8-byte DR slot per Intel SDM
///     Vol. 3B §17.2.4 Table 17-2.
///   * Emits an `[F3/WRITE-DR/ARM]` diagnostic line.
///
/// Returns early on non-target PIDs, on the second/subsequent arm
/// attempt, on a missing parent RSP, on a missing or unmapped master
/// canary, on a scan miss, or on an arm-pool exhaustion (resetting
/// ARMED_ONCE in the exhaustion case so a later post_wake can retry).
pub fn try_arm_after_post_wake(pid: u64, tid: u64) {
    if pid != F3_TARGET_PID {
        return;
    }
    if ARMED_ONCE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let cr3 = crate::mm::vmm::get_cr3();
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    ARM_TICK.store(tick, Ordering::Relaxed);

    let Some(parent_rsp) = parent_user_rsp_for(tid) else {
        ARMED_ONCE.store(false, Ordering::Release);
        crate::serial_println!(
            "[F3/WRITE-DR/ARM] state=no_parent_rsp pid={} tid={} cpu={} \
             cr3={:#x} tick={}",
            pid, tid, cpu, cr3, tick,
        );
        return;
    };
    if parent_rsp == 0 {
        ARMED_ONCE.store(false, Ordering::Release);
        crate::serial_println!(
            "[F3/WRITE-DR/ARM] state=zero_parent_rsp pid={} tid={} cpu={} \
             cr3={:#x} tick={}",
            pid, tid, cpu, cr3, tick,
        );
        return;
    }

    // Read the master canary from `fs:0x28`.  Per Intel SDM Vol. 3A
    // §3.4.4.1 the FS_BASE MSR is `0xC000_0100`; per ELF gABI stack-
    // protector §6 the per-thread canary lives at offset 0x28 in the
    // TCB (`__stack_chk_guard`).
    let fs_base = unsafe { crate::hal::rdmsr(0xC000_0100) };
    let canary_addr = fs_base.wrapping_add(0x28);
    let canary_opt: Option<u64> = if crate::syscall::validate_user_ptr(canary_addr, 8) {
        unsafe { crate::syscall::user_read_u64(canary_addr) }
    } else {
        None
    };
    let Some(canary) = canary_opt else {
        ARMED_ONCE.store(false, Ordering::Release);
        crate::serial_println!(
            "[F3/WRITE-DR/ARM] state=no_canary pid={} tid={} cpu={} \
             cr3={:#x} fs_base={:#x} parent_rsp={:#x} tick={}",
            pid, tid, cpu, cr3, fs_base, parent_rsp, tick,
        );
        return;
    };

    use crate::arch::x86_64::debug_reg::{
        arm_linear_watchpoint, ArmPhysResult, WATCH_KIND_F3_WRITE_DR,
    };

    // ── Arm slot #1: empirical SSP-fail slot offset ──────────────────
    //
    // PR #420 / #421 / this branch's v1 first-trial soak evidence
    // shows the SSP-failing-frame's canary slot lives at a stable
    // offset above `parent_user_rsp` (see EMPIRICAL_FAIL_SLOT_OFFSET).
    // At post_wake time the slot does NOT yet contain the canary —
    // the failing function has not been entered — so it will not
    // match the canary-scan below.  Arming it directly catches both
    // the prologue's first canary stamp AND any subsequent corrupting
    // write (per Intel SDM Vol. 3B §17.3.1.1, each retired write
    // triggers a fresh `#DB`).  The slot stays armed up to
    // `F3_FIRE_CAP` fires (32) before self-disarming.
    let empirical_va = parent_rsp.wrapping_add(EMPIRICAL_FAIL_SLOT_OFFSET);
    let mut armed_count = 0usize;
    ARMED_TARGET_VA.store(empirical_va, Ordering::Release);
    ARMED_PARENT_RSP.store(parent_rsp, Ordering::Release);
    {
        let result = arm_linear_watchpoint(empirical_va, WATCH_LEN, WATCH_KIND_F3_WRITE_DR);
        let (state, dr_slot) = match result {
            ArmPhysResult::Armed(s)      => { armed_count += 1; ("armed", s as i32) }
            ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
            ArmPhysResult::NotAligned    => ("not_aligned", -1),
            ArmPhysResult::OutOfRange    => ("out_of_range", -1),
        };
        crate::serial_println!(
            "[F3/WRITE-DR/ARM] state={} origin=empirical pid={} tid={} cpu={} cr3={:#x} \
             fs_base={:#x} canary={:#x} parent_rsp={:#x} slot_offset={:#x} \
             target_va={:#x} dr_slot={} kind_tag={} len={} tick={}",
            state, pid, tid, cpu, cr3, fs_base, canary, parent_rsp,
            EMPIRICAL_FAIL_SLOT_OFFSET, empirical_va, dr_slot,
            WATCH_KIND_F3_WRITE_DR, WATCH_LEN, tick,
        );
    }

    // ── Arm slots #2..#N: highest-address canary matches ─────────────
    //
    // Scan the 8 KiB window above parent_rsp for qwords that equal
    // the master canary (per System V AMD64 ABI §3.4.1; GCC manual
    // §3.20 — SSP prologue stores the canary verbatim into `[rbp-8]`).
    // Multiple matches mean multiple instrumented frames are stacked
    // above `parent_rsp`.  We arm the HIGHEST-address `MAX_HITS`
    // matches — those are likeliest to overlap or neighbour the
    // SSP-failing frame.  No-match is informational, not fatal — the
    // empirical-offset arm above carries the diagnostic.
    let mut hits: [u64; MAX_HITS] = [0; MAX_HITS];
    let n_hits = scan_window_for_canary(parent_rsp, canary, &mut hits);
    for i in 0..n_hits {
        let slot_va = hits[i];
        // Skip if this scan-hit coincides with the empirical arm
        // above — no point burning a second DR slot on the same VA.
        if slot_va == empirical_va {
            continue;
        }
        debug_assert_eq!(slot_va & 0x7, 0);
        let result = arm_linear_watchpoint(slot_va, WATCH_LEN, WATCH_KIND_F3_WRITE_DR);
        let (state, dr_slot) = match result {
            ArmPhysResult::Armed(s)      => { armed_count += 1; ("armed", s as i32) }
            ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
            ArmPhysResult::NotAligned    => ("not_aligned", -1),
            ArmPhysResult::OutOfRange    => ("out_of_range", -1),
        };
        let slot_offset = slot_va.wrapping_sub(parent_rsp);
        crate::serial_println!(
            "[F3/WRITE-DR/ARM] state={} origin=canary_scan hit_idx={} of {} \
             pid={} tid={} cpu={} cr3={:#x} fs_base={:#x} canary={:#x} \
             parent_rsp={:#x} slot_offset={:#x} target_va={:#x} \
             dr_slot={} kind_tag={} len={} tick={}",
            state, i, n_hits, pid, tid, cpu, cr3, fs_base, canary, parent_rsp,
            slot_offset, slot_va, dr_slot, WATCH_KIND_F3_WRITE_DR, WATCH_LEN, tick,
        );
    }
    if n_hits == 0 {
        crate::serial_println!(
            "[F3/WRITE-DR/ARM] state=scan_no_match pid={} tid={} cpu={} \
             cr3={:#x} fs_base={:#x} canary={:#x} parent_rsp={:#x} \
             window_bytes={} tick={}",
            pid, tid, cpu, cr3, fs_base, canary, parent_rsp,
            STACK_SCAN_BYTES, tick,
        );
    }
    if armed_count == 0 {
        // Even the empirical arm failed to claim a slot — reset
        // ARMED_ONCE so a later post_wake can retry.  Rare in the FF
        // demo path (DR slots are mostly free at PID-1 vfork time).
        ARMED_ONCE.store(false, Ordering::Release);
    }
}

/// Fire hook called from `arch::x86_64::debug_reg::handle_db_exception`
/// when the firing slot's `kind_tag == WATCH_KIND_F3_WRITE_DR`.  Emits
/// the dispositive `[F3/WRITE-DR-FIRE]` dump with the writer's GPR set,
/// the post-write value at the slot, the writer's local frame context,
/// and a 16-byte window below `rip_after_trap` for backward
/// disassembly.
///
/// Per Intel SDM Vol. 3B §17.3.1.1 the data-breakpoint trap fires
/// AFTER the writer instruction retires, so `rip` here is the
/// instruction-following-the-write — the actual writer RIP must be
/// recovered by disassembling backwards from this anchor (the 16-byte
/// window is sized per Intel SDM Vol. 2A §2.1).
///
/// Fires up to `F3_FIRE_CAP` times per slot per boot (cap enforced in
/// `handle_db_exception` via the kind-tag policy).  Each fire emits a
/// `[F3/WRITE-DR-FIRE] fire_idx=N` line so the post-processor can
/// order the writers; identifying the corrupting `0x30` writer is a
/// matter of finding the first fire whose `post_value` does not equal
/// the master canary.
pub fn record_fire(
    slot: u8,
    rip_after_trap: u64,
    rsp: u64,
    rflags: u64,
    cs: u64,
    cr3: u64,
    gprs: Option<&crate::arch::x86_64::debug_reg::Gprs>,
) {
    let fire_idx = FIRE_COUNT.fetch_add(1, Ordering::Relaxed);

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let pid = crate::proc::current_pid_lockless();
    let tid = crate::proc::current_tid();
    let arm_tick = ARM_TICK.load(Ordering::Relaxed);
    let fire_tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let expected_va = ARMED_TARGET_VA.load(Ordering::Acquire);
    let parent_rsp = ARMED_PARENT_RSP.load(Ordering::Acquire);

    // Read the post-write value at the slot via the kernel page-table
    // walk (safe in #DB context — no user-pointer dereference, no SMAP
    // bracket needed since we walk PHYS_OFF + phys).  Per Intel SDM
    // Vol. 3B §17.3.1.1 the writer's store has already retired by
    // the time the `#DB` is dispatched, so the qword here reflects
    // what the writer just stored.
    let post_value = read_user_qword_via_walk(cr3, expected_va);

    crate::serial_println!(
        "[F3/WRITE-DR-FIRE] slot={} fire_idx={} pid={} tid={} cpu={} cr3={:#x} \
         rip_after_trap={:#x} cs={:#x} rflags={:#x} rsp={:#x} \
         arm_tick={} fire_tick={} \
         expected_va={:#x} parent_rsp={:#x} post_value={} \
         note=trap_after_retire_per_SDM_17_3_1_1",
        slot, fire_idx, pid, tid, cpu, cr3, rip_after_trap, cs, rflags, rsp,
        arm_tick, fire_tick, expected_va, parent_rsp,
        post_value.map(|v| alloc::format!("{:#018x}", v))
            .unwrap_or_else(|| alloc::string::String::from("(unmapped)")),
    );

    // GPR dump — per `debug_reg::Gprs` index map:
    //   [0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=rbp [5]=rbx
    //   [6]=r11 [7]=r10 [8]=r9  [9]=r8  [10]=rdi [11]=rsi
    //   [12]=rdx [13]=rcx [14]=rax
    match gprs {
        Some(g) => {
            crate::serial_println!(
                "[F3/WRITE-DR-FIRE/GPR] rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
                g[14], g[5], g[13], g[12],
            );
            crate::serial_println!(
                "[F3/WRITE-DR-FIRE/GPR] rsi={:#018x} rdi={:#018x} rbp={:#018x} r8={:#018x}",
                g[11], g[10], g[4], g[9],
            );
            crate::serial_println!(
                "[F3/WRITE-DR-FIRE/GPR] r9={:#018x}  r10={:#018x} r11={:#018x} r12={:#018x}",
                g[8], g[7], g[6], g[3],
            );
            crate::serial_println!(
                "[F3/WRITE-DR-FIRE/GPR] r13={:#018x} r14={:#018x} r15={:#018x}",
                g[2], g[1], g[0],
            );
        }
        None => {
            crate::serial_println!("[F3/WRITE-DR-FIRE/GPR] state=unavailable");
        }
    }

    // Writer's local frame — 9 qwords at [rsp..rsp+0x40].  Names the
    // immediate locals / saved registers of the function that issued
    // the store; sized just larger than a typical small-function
    // prologue area (System V AMD64 ABI §3.2.2).
    dump_user_qwords(cr3, "FRAME", rsp, 9);

    // Backward instruction-bytes window for writer-RIP recovery.  Per
    // Intel SDM Vol. 2A §2.1 AMD64 instructions are 1..15 bytes, so a
    // 16-byte read below `rip_after_trap` always brackets the writer's
    // store opcode.  Post-processor reassembles upward to identify the
    // exact instruction.
    let back_base = rip_after_trap.wrapping_sub(BACK_INSN_BYTES as u64);
    dump_user_bytes(cr3, "INSN", back_base, BACK_INSN_BYTES);
}

/// Read a qword at a user VA by walking the page tables and reading
/// through the PHYS_OFF direct map.  Returns `None` if the VA is
/// unmapped or non-canonical.  Safe to call from `#DB` context with
/// `IF=0` (no user-pointer deref).
fn read_user_qword_via_walk(cr3: u64, va: u64) -> Option<u64> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let phys = crate::mm::vmm::virt_to_phys_in(cr3, va)?;
    let v = unsafe {
        core::ptr::read_volatile((PHYS_OFF + phys) as *const u64)
    };
    Some(v)
}

/// Read `count` qwords starting at user VA `base` under `cr3` and emit
/// one `[F3/WRITE-DR-FIRE/<tag>] [base+offset] VA = VAL` line per qword.
/// Same shape as PR #421's helper.
fn dump_user_qwords(cr3: u64, tag: &str, base: u64, count: usize) {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    for i in 0..count {
        let va = base.wrapping_add((i * 8) as u64);
        match crate::mm::vmm::virt_to_phys_in(cr3, va) {
            Some(phys) => {
                let v = unsafe {
                    core::ptr::read_volatile((PHYS_OFF + phys) as *const u64)
                };
                crate::serial_println!(
                    "[F3/WRITE-DR-FIRE/{}] [base+{:#04x}] va={:#018x} = {:#018x}",
                    tag, i * 8, va, v,
                );
            }
            None => {
                crate::serial_println!(
                    "[F3/WRITE-DR-FIRE/{}] [base+{:#04x}] va={:#018x} = (unmapped)",
                    tag, i * 8, va,
                );
            }
        }
    }
}

/// Read `count` bytes starting at user VA `base` under `cr3` and emit
/// one `[F3/WRITE-DR-FIRE/<tag>] [base+offset] VA = bb bb bb bb bb bb bb bb`
/// line of 8 bytes hex per line.  Used to capture the
/// instruction-stream window for writer-RIP reconstruction.
fn dump_user_bytes(cr3: u64, tag: &str, base: u64, count: usize) {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    // Walk one page-aligned chunk at a time; the window is small
    // (16 bytes) so a single qword-pair pass is enough in practice.
    let mut emitted = 0usize;
    while emitted < count {
        let va = base.wrapping_add(emitted as u64);
        let line_len = core::cmp::min(8, count - emitted);
        match crate::mm::vmm::virt_to_phys_in(cr3, va) {
            Some(phys) => {
                // Bound the read to the remaining count and avoid
                // straddling a page boundary in a single read.
                let page_off = (va & 0xFFF) as usize;
                let bytes_to_end_of_page = 4096 - page_off;
                let chunk = core::cmp::min(line_len, bytes_to_end_of_page);
                let mut buf = [0u8; 8];
                for j in 0..chunk {
                    buf[j] = unsafe {
                        core::ptr::read_volatile((PHYS_OFF + phys + j as u64) as *const u8)
                    };
                }
                crate::serial_println!(
                    "[F3/WRITE-DR-FIRE/{}] [base+{:#04x}] va={:#018x} \
                     bytes={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    tag, emitted, va,
                    buf[0], buf[1], buf[2], buf[3],
                    buf[4], buf[5], buf[6], buf[7],
                );
                emitted += chunk;
                if chunk == 0 {
                    break;
                }
            }
            None => {
                crate::serial_println!(
                    "[F3/WRITE-DR-FIRE/{}] [base+{:#04x}] va={:#018x} = (unmapped)",
                    tag, emitted, va,
                );
                emitted += line_len;
            }
        }
    }
}
