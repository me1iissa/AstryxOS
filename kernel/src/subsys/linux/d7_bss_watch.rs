//! D7 PT_TLS BSS-slot writer trap.
//!
//! ## What this catches
//!
//! Phase 7 PSE end-to-end identified that the deterministic firefox-bin
//! `tid=1` NULL deref at `firefox-bin + 0x207dc` is preconditioned on the
//! TLS variable at `[fs:-0x18]` being **non-zero** when first read.  Per
//! ELF gABI §5.2 (PT_LOAD / PT_TLS) the `memsz > filesz` tail of a PT_TLS
//! segment is BSS and must be zero on first access; firefox-bin's PT_TLS
//! is `MemSiz=0x20, FileSiz=0` (pure BSS), so the qword at
//! `fs_base - 0x18` MUST read as zero at the very first user-mode
//! instruction.  Mozilla's `mozilla::baseprofiler::detail::
//! GetThreadRegistrationTime` (statically linked into firefox-bin) reads
//! the slot, and:
//!
//!   * zero → early-return at `0x2077d` (Linux behaviour);
//!   * non-zero → slow path at `0x207ce` that derefs `[rax + 0x38]`
//!     (NULL on the leaked-pointer case) and faults at `0x207dc`.
//!
//! Three hypothesis classes survive (PSE Phase 3):
//!
//!   * **Z1** — anon-PF returned a non-zero frame on first access (no
//!     runtime write).  Mechanism: cache-hit aliasing a written frame,
//!     or generation-abort retry re-using without re-zeroing.  D7
//!     falsifier: **zero** `[W215/DR-WATCH-FIRE]` captures across a
//!     trial that reaches the fault.
//!   * **Z2** — TLS zero at install, but a sibling kernel writer hits
//!     the slot before BaseProfiler reads.  Candidates: robust-futex
//!     teardown, CoW collision at the TCB / TLS-var boundary, signal-
//!     stack copy.  D7 signature: ≥ 1 capture with `cs=0x08` and a
//!     kernel RIP.
//!   * **Z3** — `arch_prctl(ARCH_SET_FS)` accepts a new fs_base but the
//!     bootstrap TLS contents alias the new mapping via stale TLB or a
//!     shared frame.  D7 signature: captures from user-mode (`cs=0x23`)
//!     RIPs inside musl/ld-musl that perform a TLS write that resolves
//!     to the slot's linear address.
//!
//! ## Mechanism
//!
//! Hardware watchpoints (Intel SDM Vol. 3B §17.2.4 — DR0–DR3, DR7) trap
//! `#DB` (vector 1) on the CPU that performs a write whose linear address
//! matches the programmed slot.  DR registers hold linear addresses
//! (post-segment, pre-paging); on x86_64 with flat segments that equals
//! the user virtual address the instruction stream specifies.  Per Intel
//! SDM Vol. 3B §17.3.1.1, the `#DB` frame's `rip` is the instruction
//! **after** the write (data-breakpoint trap-style), but the kernel's
//! existing `[W215/DR-WATCH-FIRE]` fire-line prints that RIP raw — the
//! post-processor can subtract the writer instruction's length via
//! addr2line / objdump if a fine-grained file:line is needed.
//!
//! We arm a single linear-VA channel:
//!
//!   * **DR{slot} — user-VA channel** at `fs_base - 0x18` (the qword the
//!     `mov 0x20(%rbx), %rax` epilogue path of `GetThreadRegistrationTime`
//!     subsequently dereferences via `rbx = %fs:0` from the linear-VA
//!     `fs_base - 0x18`).  Catches any write — user-mode or kernel-mode
//!     — whose linear address resolves to this VA on TID 1's CR3.
//!
//! No PHYS_OFF channel: the F3 SSP-canary case had a known backing phys
//! at execve completion; here the TLS slot is in a PT_TLS-allocated
//! anon mapping whose backing phys is not deterministic across boots,
//! and the principal Z1 hypothesis is **about** the phys backing being
//! wrong from the start — a PHYS_OFF arm on the current backing would
//! miss the case where the bug is the choice of backing frame itself.
//! The user-VA arm catches every write through the user mapping
//! (kernel `copy_to_user`, user-mode store, anon-PF zero-fill if it
//! were happening) regardless of which phys backs the page.
//!
//! ## When the arm happens
//!
//! Inside `proc::write_fs_base()` immediately after the existing
//! `fs-base-trace` hook, on the first WRMSR that:
//!
//!   * transitions FS.base from zero to a non-zero value, AND
//!   * is performed for `pid == 1` `tid == 1` (firefox-bin init thread —
//!     pid=1 is firefox-bin under the Linux personality, per
//!     [PSE Phase 1](docs/SC1171_PSE_END_TO_END_2026-05-22.md)), AND
//!   * the new fs_base value is at least `0x18` (so `fs_base - 0x18`
//!     does not underflow).
//!
//! The arm is one-shot per boot (`D7_ARM_MAX = 1`).  Subsequent
//! WRMSRs to fs_base (context switches, arch_prctl from sibling threads)
//! do not re-arm — the watched VA is fixed at first arm and the slot
//! is held until the slot self-disarms at `F3_FIRE_CAP`.
//!
//! ## No-fix discipline
//!
//! Per saga-discipline Rule 1 (phys-provenance FIRST), this module emits
//! diagnostic data only.  It does NOT mutate page tables, allocate frames,
//! change any lock order, or run any logic outside the WRMSR-precondition
//! path when `D7_ARM_COUNT == 0`.  Captured fires identify the writer; a
//! *separate* coordinator-dispatched fix uses that identification to
//! target the exact path.
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7 layout).
//!   * Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap timing).
//!   * Intel SDM Vol. 3A §3.4.4.1 (`IA32_FS_BASE` MSR `0xC000_0100`).
//!   * Intel SDM Vol. 3A §4.10 (TLB management).
//!   * ELF gABI §5.2 (PT_LOAD / PT_TLS `memsz > filesz` zero-fill).
//!   * System V AMD64 ABI §3.4.4 (TLS variant II layout: TLS variables
//!     live at negative offsets from `%fs`).

#![cfg(feature = "d7-bss-watch")]

use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of arm cycles per boot.  D7 is single-shot per boot:
/// the first qualifying `write_fs_base()` arms, all subsequent calls
/// observe the saturated counter and bail.  Slot self-disarms at
/// `F3_FIRE_CAP` (=32) fires; if the cap is reached and another arm
/// is desired (rare — would require a re-run of the diagnostic) the
/// log shows `state=arm_cap_reached` and a re-boot is the recovery.
const D7_ARM_MAX: u32 = 1;

/// Per-boot arm cycle counter.  Counts accepted arms only; refused arms
/// (precondition failed) do not bump this.
static D7_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Offset of the watched qword from `fs_base`.  Per the PSE objdump of
/// `firefox-bin + 0x20771`:
///
/// ```
/// 20771: mov  -0x18(%rbx), %rax    ; rbx = fs_base, so VA = fs_base - 0x18
/// ```
///
/// System V AMD64 ABI §3.4.4 places TLS variables at negative offsets
/// from `%fs` (variant II).  The slot at `[fs:-0x18]` is part of the
/// firefox-bin PT_TLS segment's BSS tail (memsz=0x20, filesz=0).
const TLS_SLOT_OFFSET_FROM_FS_BASE: u64 = 0x18;

/// Length of the watched access in bytes.  Matches `mov -0x18(%rbx), %rax`
/// which loads 8 bytes.  DR LEN field encoding for 8 bytes is `0b10`
/// (Intel SDM Vol. 3B §17.2.4 Table 17-2 — the 8-byte form is x86_64-
/// specific and requires the address be 8-aligned, which `fs_base - 0x18`
/// satisfies provided `fs_base & 7 == 0`).
const TLS_SLOT_LEN: u8 = 8;

/// Target pid for the D7 arm.  Per the Linux personality's bootstrap
/// (kernel/src/main.rs spawns firefox-bin as the first userspace
/// process via the `firefox-test` feature), pid=1 is always firefox-bin
/// in the firefox-test build.
const D7_TARGET_PID: u64 = 1;

/// Target tid for the D7 arm.  The firefox-bin launcher runs the
/// main thread as tid=1; per PSE Phase 1 the faulting thread is
/// always `tid=1` across the byte-perfect deterministic 3/3 trials.
const D7_TARGET_TID: u64 = 1;

/// Atomically claim the single arm slot.  Returns `Ok(())` if the slot
/// was claimed (this is the first qualifying call), or `Err(())` if the
/// cap is already reached.  Uses `compare_exchange` so a refused-arm
/// path never grows the counter past `D7_ARM_MAX`.
fn claim_arm() -> Result<(), ()> {
    loop {
        let cur = D7_ARM_COUNT.load(Ordering::Relaxed);
        if cur >= D7_ARM_MAX {
            return Err(());
        }
        if D7_ARM_COUNT
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Hook called from `proc::write_fs_base()` after the existing
/// `fs-base-trace` event record but before (or after — order does not
/// matter, the WRMSR is independent of the DR arm) the actual WRMSR.
///
/// Arguments are the pre/post FS.base values as seen at the call site.
/// All gating decisions are made here so the call site stays a single
/// unconditional invocation.
///
/// Preconditions for an actual arm:
///   1. The arm slot has not been claimed yet (`D7_ARM_COUNT < D7_ARM_MAX`).
///   2. `old_fs == 0` AND `new_fs != 0` — the zero-to-non-zero transition
///      uniquely identifies the *first* fs_base write for this thread.
///      Context-switch restores (`old_fs == new_fs`) and arch_prctl
///      re-sets (both non-zero) are excluded — D7 wants the slot watched
///      *before* the first user instruction, which is the very first
///      `write_fs_base()` call on the thread.
///   3. `new_fs >= TLS_SLOT_OFFSET_FROM_FS_BASE` — otherwise
///      `new_fs - 0x18` underflows.  (No realistic fs_base hits this;
///      defence-in-depth.)
///   4. `(new_fs - TLS_SLOT_OFFSET_FROM_FS_BASE) & (TLS_SLOT_LEN - 1) == 0`
///      — the slot must be naturally aligned for the DR 8-byte LEN
///      encoding.  Equivalent to `new_fs & 7 == 0` since the offset is
///      a multiple of 8.  Intel SDM Vol. 3B §17.2.4 silently widens
///      misaligned addresses to the LEN field's mask, which would catch
///      unrelated nearby writes — refuse the arm and log if violated.
///   5. `pid == 1` AND `tid == 1` — firefox-bin init thread per PSE
///      Phase 1.
///
/// Each rejected precondition emits a one-line `[D7/TLS-18-ARM] state=…`
/// trace so a post-processor can see why an arm did not happen.  On
/// success: one `[D7/TLS-18-ARM]` line followed by per-fire
/// `[W215/DR-WATCH-FIRE] kind_tag=3 …` lines from the existing
/// `handle_db_exception` path.
pub fn try_arm_after_fs_base_write(pid: u64, tid: u64, old_fs: u64, new_fs: u64) {
    // Fast precondition check: only the very first fs_base write for
    // the target thread is interesting.  All other writes are common
    // (context switch on every preemption) and must not pay the cost
    // of the more expensive checks below.
    if pid != D7_TARGET_PID || tid != D7_TARGET_TID {
        return;
    }
    if old_fs != 0 || new_fs == 0 {
        return;
    }

    // Already-armed or capped: bail silently after a one-shot trace.
    if D7_ARM_COUNT.load(Ordering::Relaxed) >= D7_ARM_MAX {
        return;
    }

    // Underflow / alignment guards.  These violations are essentially
    // impossible for a real musl TLS layout but the diagnostic should
    // be honest about why it did not arm if they ever occur.
    if new_fs < TLS_SLOT_OFFSET_FROM_FS_BASE {
        crate::serial_println!(
            "[D7/TLS-18-ARM] state=refused_underflow pid={} tid={} new_fs={:#x} \
             offset={:#x}",
            pid, tid, new_fs, TLS_SLOT_OFFSET_FROM_FS_BASE,
        );
        return;
    }
    let watch_va = new_fs - TLS_SLOT_OFFSET_FROM_FS_BASE;
    if watch_va & (TLS_SLOT_LEN as u64 - 1) != 0 {
        crate::serial_println!(
            "[D7/TLS-18-ARM] state=refused_misaligned pid={} tid={} new_fs={:#x} \
             watch_va={:#x} len={}",
            pid, tid, new_fs, watch_va, TLS_SLOT_LEN,
        );
        return;
    }

    // Claim the single arm slot.  After this point any concurrent caller
    // will see `D7_ARM_COUNT == D7_ARM_MAX` and bail at the early check;
    // we are the unique arming context.
    if claim_arm().is_err() {
        return;
    }

    let cpu = crate::arch::x86_64::apic::cpu_index();

    use crate::arch::x86_64::debug_reg::{
        arm_linear_watchpoint, ArmPhysResult, WATCH_KIND_D7_BSS,
    };

    let result = arm_linear_watchpoint(watch_va, TLS_SLOT_LEN, WATCH_KIND_D7_BSS);
    let (state, slot) = match result {
        ArmPhysResult::Armed(s)      => ("armed", s as i32),
        ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
        ArmPhysResult::NotAligned    => ("not_aligned", -1),
        ArmPhysResult::OutOfRange    => ("out_of_range", -1),
    };

    crate::serial_println!(
        "[D7/TLS-18-ARM] state={} pid={} tid={} cpu={} new_fs={:#x} \
         watch_va={:#x} len={} slot={} kind_tag={}",
        state, pid, tid, cpu, new_fs, watch_va, TLS_SLOT_LEN, slot,
        WATCH_KIND_D7_BSS,
    );
}
