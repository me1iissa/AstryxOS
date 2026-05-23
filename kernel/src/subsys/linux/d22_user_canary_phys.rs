//! D22 — PHYS_OFF channel for user-canary phys-aliasing detection (Wave 13).
//!
//! ## What this catches
//!
//! After PR #404 (D21 user-canary writer trap) captured the user-mode SSP
//! prologue stores as legitimate musl writes, and the subsequent multi-lens
//! audits (PR #406 abi-compat B1/B2 rejection, PR #407 aether parent-RSP
//! Mechanisms A/B/C rejection) eliminated every mechanism that could
//! shift the parent's `iretq`-restored RSP or rewrite the canary slot in
//! place, the convergent verdict is **Mechanism D — phys-aliasing on the
//! user stack**.  The libxul SSP prologue stores the canary at user VA
//! `0x7ffffffee458` and the epilogue's `XOR [rbp-8], rax` loads from the
//! same linear VA, but the **physical frame backing that VA differs**
//! between the store and the load.
//!
//! This is the same class of bug as PR #248 H3a/H3b (W215 family on a
//! file-backed shared cache); D22 surfaces it on the **user stack**
//! surface.  Per Intel SDM Vol. 3A §4.10.5 the page-table machinery must
//! ensure paging-structure changes are globally visible before a frame
//! they reference is reused; a TLB-stale or PTE-replace race on the
//! user-stack VA between prologue and epilogue is the falsifiable
//! signature.
//!
//! ## The dispositive primitive
//!
//! Two complementary hardware-watchpoint channels armed at the same
//! vfork-pre-block hook site that D21 uses (`subsys/linux/syscall.rs`
//! clone(56) / clone3(435) PRE-block tails):
//!
//! 1. **Channel A — linear user-VA.**  Programmed via
//!    `arm_linear_watchpoint(canary_va, 8, WATCH_KIND_D22_USER_CANARY_PHYS)`.
//!    Mirrors D21's **raw-offset** arm: `[parent_user_rsp + 0x1d58] - 8`
//!    = `[parent_user_rsp + 0x1d50]`, the 8-byte qword adjacent to the
//!    existing `s_1d58` probe.  Per Trial 1 evidence (kind_tag=7 fires
//!    at this exact linear address) this is the VA where the user-mode
//!    SSP prologue actually writes; the RBP-derived alternative
//!    (`*(probe_va) - 8`) lands on a slot the writer never touches.
//!    D22 records the **arm-time backing phys** in a per-slot table so
//!    the fire emission can name `phys_at_write`.
//!
//! 2. **Channel B — PHYS_OFF mirror.**  Programmed via
//!    `arm_phys_slot_watchpoint(frame_base, offset_in_frame, 8)` on the
//!    same physical frame that backed the user VA at arm time.  Per
//!    Intel SDM Vol. 3B §17.2.4 DR0–DR3 compare on linear addresses; the
//!    kernel direct-map invariant gives `linear = PHYS_OFF + phys` for
//!    every frame, so this channel fires on any CPU's kernel-mode write
//!    that touches the frame through the direct map.  Catches writes
//!    that BYPASS the user-VA mapping (typical `write_bytes` / memset
//!    paths in kernel code), which the user-VA channel cannot see.
//!
//! This is the same two-channel pattern PR #356 (K2b F3 saga) established
//! for the user-stack canary axis.  D22 reuses it without modification.
//!
//! ## The dispositive comparison
//!
//! At fire time, `handle_db_exception` (already in
//! `arch/x86_64/debug_reg.rs`) calls `record_d22_fire` on any slot tagged
//! `WATCH_KIND_D22_USER_CANARY_PHYS`.  We:
//!
//!   * Re-walk the user VA → phys under the firing CPU's CR3 (Intel SDM
//!     Vol. 3A §4.6) — that's `phys_at_write` for this fire.
//!   * Emit `[D22/USER-CANARY-PHYS] tid=N pid=M write_va=0xX
//!     phys_at_write=0xP_w channel={raw|phys}` with the writer RIP / CS
//!     / CR3 already captured by the surrounding fire line.
//!
//! At the read site — `subsys::linux::ssp_diag::probe_gp_at_ssp_fail`,
//! called from the CPL-3 `#GP` ISR path for any musl `__stack_chk_fail`
//! trap — we:
//!
//!   * Re-walk the same VA → phys under the trapping CR3 — that's
//!     `phys_at_read`.
//!   * Emit `[D22/SSP-CHECK] tid=N pid=M read_va=0xX phys_at_read=0xP_r
//!     expected=0xM observed=0xV` with the master canary from
//!     `IA32_FS_BASE+0x28` (System V AMD64 ABI §3.4.5.2) and the stored
//!     value at the saved-canary slot.
//!
//! For the same `tid:pid` pair, comparing the recorded `phys_at_write`
//! values against `phys_at_read` is dispositive:
//!
//!   * **`phys_at_write == phys_at_read`** → Mechanism D rejected.  The
//!     prologue's store and the epilogue's load resolve to the same
//!     phys.  The corruption must come from a writer that DID modify
//!     the slot between the two — re-cross-walk required.
//!   * **`phys_at_write != phys_at_read`** → Mechanism D confirmed.
//!     The fix lives in `mm/vmm.rs` parent stack-expansion / vfork-wake
//!     PTE-management path (~30–80 LOC per PR #407's recommendation).
//!
//! ## Channel selection rationale
//!
//! D21 (PR #404) explicitly chose NOT to arm a PHYS_OFF channel because
//! the launcher's saved-canary slot's backing phys is **not deterministic
//! across boots** (mallocng + per-process mmap-hint jitter from PR #364
//! randomises heap; stack frame layout depends on libxul codegen).
//!
//! D22 sidesteps that constraint by arming the PHYS_OFF channel on the
//! **observed** backing phys at arm-time rather than a hard-coded
//! constant.  At the moment of vfork-pre-block the canary VA is already
//! mapped (the libxul SSP prologue has run on the parent before issuing
//! the clone(2) syscall, so the slot is populated) — we read it, capture
//! the live phys via `virt_to_phys_in(cr3, canary_va)` (Intel SDM Vol. 3A
//! §4.6), and arm DR{slot} on `PHYS_OFF + phys`.  No per-boot jitter
//! issue because we use the actual frame, not a guess.
//!
//! ## No-fix discipline
//!
//! Per the saga-discipline rules ([[feedback_saga_diagnostic_discipline_2026_05_20]]),
//! this module emits diagnostic data only.  It does NOT mutate page
//! tables, allocate frames, change any lock order, or perform any
//! syscall-altering side effects.  The hook lives in the existing
//! PRE-block tail alongside D21 / `snapshot_canaries` /
//! `arm_master_canary_watch`, so D22 inherits the same atomic-load
//! fast-path on off-target calls.  Bounded by `D22_ARM_MAX` total arms
//! per boot plus the `F3_FIRE_CAP` per-slot fire bound enforced by
//! `handle_db_exception`.
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7 layout — write-only LEN=8
//!     encoding).
//!   * Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap-after-retire —
//!     captured RIP is the instruction AFTER the writer's store).
//!   * Intel SDM Vol. 3A §4.6 (page-table walk semantics — virt→phys).
//!   * Intel SDM Vol. 3A §4.10.5 (TLB-coherency invariant — paging-
//!     structure changes globally visible before frame reuse).
//!   * System V AMD64 ABI §3.2.2 (stack frame layout — `[rbp+0]` saved
//!     RBP, `[rbp-8]` SSP slot per GCC SSP convention).
//!   * System V AMD64 ABI §3.4.5.2 / §6.4 (TLS variant II;
//!     `__stack_chk_guard` at `fs:0x28`).
//!   * POSIX `vfork(3p)` (parent suspended until child `_exit` /
//!     `execve`, shared address space).
//!   * CWE-121 (stack-based buffer overflow taxonomy).
//!   * Prior art: PR #248 (W215 H3a/H3b file-backed cache phys-alias),
//!     PR #356 (K2b two-channel `linear_watchpoint` +
//!     `phys_watchpoint` pattern), PR #404 (D21 user-canary linear-VA
//!     channel — same arm site), PR #407 (Wave 12 aether audit —
//!     Mechanisms A/B/C rejected, Mechanism D = this).

#![cfg(feature = "d22-user-canary-phys")]

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Target pid — per PR #398 the failure is deterministic on PID 1 (the
/// firefox-bin launcher).  Mirrors D21's gating.
const D22_TARGET_PID: u64 = 1;

/// Maximum arm cycles per boot.  Each successful arm consumes 1 DR slot
/// (channel A or B) until `F3_FIRE_CAP = 32` fires self-disarm it.
/// Bounded ABOVE D21's cap to leave room for both channels arming
/// concurrently: if the first vfork-PRE-block accepts both channels,
/// that's 2 of the 4-slot DR pool; the next event can accept another
/// pair if pool space permits.  Refused arms (cap reached, pool
/// exhausted, RBP chain unreadable) do NOT consume a count, so the
/// budget is honest.
const D22_ARM_MAX: u32 = 4;

/// Maximum post-wake arm cycles per boot for the PR #423 follow-up
/// PHYS_OFF channel below.  Tracked separately from `D22_ARM_MAX` so
/// the pre-block arm budget (above) cannot starve the post-wake arm
/// path that PR #423 evidence proved is the dispositive site.  Each
/// arm consumes one DR slot until the per-slot `F3_FIRE_CAP = 32`
/// fires self-disarm it.
const D22_POSTWAKE_ARM_MAX: u32 = 2;

/// Per-boot accepted-arm counter.  Mirrors D21's CAS-claim discipline.
static D22_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Per-boot post-wake arm counter, paired with `D22_POSTWAKE_ARM_MAX`.
static D22_POSTWAKE_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Empirical offset above the parent's post-wake `parent_user_rsp`
/// where the libxul SSP-instrumented caller-frame's `[rbp-8]` canary
/// slot lives in the FF + musl reproducer.
///
/// Derived from PR #420 / #421 / #423 cross-boot evidence (every soak
/// observed the same byte-identical relationship):
///
///   * Post_wake `parent_rsp = 0x7ffffffec708` (deterministic — the
///     kernel `USER_STACK_TOP` is set by the loader, not ASLR).
///   * SSP-fail captured `rsp = 0x7ffffffee468` (deterministic — set
///     by the libxul `posix_spawn` caller's frame layout, which is
///     fixed at link time).
///   * SSP-fail slot per PR #421 caller-frame snapshot is
///     `[rsp+0x58] = 0x7ffffffee4c0`.
///   * Delta: `0x7ffffffee4c0 - 0x7ffffffec708 = 0x1db8`.
///
/// This offset is the **post-wake** anchor — distinct from the
/// `SAVED_RBP_OFFSET_FROM_RSP = 0x1d58` that the pre-block path uses,
/// because pre-block and post-wake see different RSP contexts even
/// though both observe the parent thread (vfork semantics: parent
/// blocks on the kernel-side semaphore, then resumes on the SAME
/// syscall frame, but the user-stack region above that RSP has been
/// observed to differ in the SSP-canary slot's backing phys — the
/// hypothesis this PHYS_OFF arm is built to falsify or confirm).
///
/// Per PR #423's 3-trial KVM soak the linear-VA write watchpoint on
/// this slot returned **0/3 fires**, yet PR #421 proved the slot's
/// stored qword IS overwritten with `0x30` byte-for-byte across all
/// trials.  Per Intel SDM Vol. 3B §17.2.4, DR0–DR3 compare on linear
/// addresses; a write that targets the slot via the kernel direct
/// map (`PHYS_OFF + phys`) rather than via the user VA mapping is
/// therefore invisible to a user-VA arm — but visible to a PHYS_OFF
/// arm.  This module's post-wake PHYS_OFF arm is the dispositive
/// channel for that hypothesis (the same two-channel pattern PR #356
/// K2b established for the F3 saga).
const POSTWAKE_FAIL_SLOT_OFFSET: u64 = 0x1db8;

/// Per-DR-slot recorded arm-time `(write_va, phys_at_write, channel)`
/// for D22 entries.  Indexed by DR slot 0..3 (mirrors
/// `arch::x86_64::debug_reg::N_DR_SLOTS`).  `phys_at_write == 0` means
/// the slot is not a D22 arm or the live phys was unmapped at arm time.
///
/// Channel encoding: 1 = linear (channel A — user-VA arm), 2 = phys
/// (channel B — PHYS_OFF mirror).  0 = unset / not a D22 slot.
///
/// Lock-free seqlock-style publish on arm; lock-free read on fire.  Per
/// Intel SDM Vol. 3B §17.3.1.1 each fire reads exactly once after the
/// retire, so a fire cannot observe a torn arm-time entry.
const N_DR_SLOTS: usize = 4;
static SLOT_WRITE_VA: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static SLOT_PHYS_AT_WRITE: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static SLOT_CHANNEL: [AtomicU32; N_DR_SLOTS] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

const CHANNEL_LINEAR: u32 = 1;
const CHANNEL_PHYS: u32 = 2;

/// Same anchor offset D21 uses to reach the libxul SSP-instrumented
/// caller's saved RBP through the parent's saved syscall frame.  Per
/// PR #404's doc + the existing `[VFORK/CANARY]` `s_1d58` probe.
const SAVED_RBP_OFFSET_FROM_RSP: u64 = 0x1d58;

/// User-VA range bounds (canonical lower half).
const USER_ADDR_MIN: u64 = 0x1000;
const USER_ADDR_END: u64 = 0x0000_8000_0000_0000;

/// Kernel direct-map base (`PHYS_OFF`).  Linear address of a frame is
/// `PHYS_OFF + phys` per the AstryxOS higher-half kernel invariant.
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Atomically claim an arm slot via CAS.  Returns `Ok(())` once the
/// counter has been bumped from `< D22_ARM_MAX`, `Err(())` once the cap
/// is reached.  Mirrors `d21_user_canary_watch::claim_arm`.
fn claim_arm() -> Result<(), ()> {
    loop {
        let cur = D22_ARM_COUNT.load(Ordering::Relaxed);
        if cur >= D22_ARM_MAX {
            return Err(());
        }
        if D22_ARM_COUNT
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Resolve `(user_rsp, user_rbp)` for `parent_tid` from the saved
/// syscall frame at the top of that thread's kernel stack.  Mirrors
/// `d21_user_canary_watch::get_parent_user_rsp_rbp` byte-for-byte —
/// the frame layout `[..., rbp(slot 12), ..., user_rsp(slot 15)]` is
/// the `syscall_entry` invariant, see `kernel/src/syscall/mod.rs`.
fn get_parent_user_rsp_rbp(parent_tid: u64) -> (u64, u64) {
    let kstack_top = {
        let threads = crate::proc::THREAD_TABLE.lock();
        threads.iter().find(|t| t.tid == parent_tid)
            .map(|t| t.kernel_stack_base + t.kernel_stack_size)
            .unwrap_or(0)
    };
    if kstack_top == 0 {
        return (0, 0);
    }
    // SAFETY: reads are inside the thread's own kernel stack — always
    // mapped, always present at CPL 0.  See d21_user_canary_watch.
    let user_rsp = unsafe { *((kstack_top - 8) as *const u64) };
    let user_rbp = unsafe { *((kstack_top - 32) as *const u64) };
    (user_rsp, user_rbp)
}

/// Read a user qword via the kernel direct map, returning
/// `Some((value, phys))` on success.  Fault-immune (load goes through
/// `PHYS_OFF + phys`, not the user VA) so a not-present user PTE
/// returns `None`.  Per Intel SDM Vol. 3A §4.6 the walker fails on the
/// first not-present level.  Mirrors `d21_user_canary_watch::
/// read_user_qword`.
fn read_user_qword(addr: u64) -> Option<(u64, u64)> {
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

/// Record an arm in the per-slot table.  Called by `try_arm_at_vfork_
/// preblock` after a successful `arm_linear_watchpoint` /
/// `arm_phys_slot_watchpoint`.  The phys may be 0 for the channel-A
/// arm if the live `virt_to_phys_in` walk returned `None` at arm time
/// — that's recorded verbatim so the fire emission can flag it.
fn note_arm(slot: u8, write_va: u64, phys_at_write: u64, channel: u32) {
    let i = slot as usize;
    if i >= N_DR_SLOTS { return; }
    // Order: publish va + phys BEFORE the channel tag.  The fire path
    // gates on channel != 0; if it observes a non-zero channel it
    // must see consistent va/phys.  Release on the channel store
    // pairs with the Acquire on `SLOT_CHANNEL` in `record_d22_fire`.
    SLOT_WRITE_VA[i].store(write_va, Ordering::Relaxed);
    SLOT_PHYS_AT_WRITE[i].store(phys_at_write, Ordering::Relaxed);
    SLOT_CHANNEL[i].store(channel, Ordering::Release);
}

/// Hook called from `arch::x86_64::debug_reg::handle_db_exception` for
/// every fire whose slot is tagged `WATCH_KIND_D22_USER_CANARY_PHYS`.
/// Emits the per-fire `[D22/USER-CANARY-PHYS]` diagnostic line that
/// names `(tid, pid, write_va, phys_at_write_now, channel)`.
///
/// `phys_at_write_now` is re-resolved from the current CR3 (the firing
/// CPU's CR3 = the writer's CR3 per Intel SDM Vol. 3B §17.3.1.1 trap-
/// after-retire semantics — the writer's store retired before the
/// `#DB` was taken, so CR3 is unchanged from the writer's view).  If
/// the VA is unmapped at fire time, we fall back to the arm-time
/// `phys_at_write` recorded by `note_arm`.
///
/// Safe to call from ISR context: no locks, no allocations beyond the
/// existing `serial_println!` ring.  Off-D22 slots return early at the
/// `channel == 0` check (one atomic load + branch).
pub fn record_d22_fire(slot: u8, rip: u64, cs: u64, cr3: u64) {
    let i = slot as usize;
    if i >= N_DR_SLOTS {
        return;
    }
    let channel = SLOT_CHANNEL[i].load(Ordering::Acquire);
    if channel == 0 {
        return;
    }
    let write_va = SLOT_WRITE_VA[i].load(Ordering::Relaxed);
    let arm_phys = SLOT_PHYS_AT_WRITE[i].load(Ordering::Relaxed);

    // Re-walk under the firing CR3.  Per Intel SDM Vol. 3A §4.6 this
    // gives the authoritative current phys for the VA under that
    // address space; if it differs from arm-time, the page table moved.
    let fire_phys = crate::mm::vmm::virt_to_phys_in(cr3, write_va).unwrap_or(0);

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let tid = crate::proc::current_tid();
    let pid = crate::proc::current_pid_lockless();
    let channel_str = match channel {
        CHANNEL_LINEAR => "raw",
        CHANNEL_PHYS   => "phys",
        _              => "?",
    };
    crate::serial_println!(
        "[D22/USER-CANARY-PHYS] tid={} pid={} cpu={} rip={:#x} cs={:#x} cr3={:#x} \
         write_va={:#x} phys_at_arm={:#x} phys_at_write={:#x} channel={} slot={}",
        tid, pid, cpu, rip, cs, cr3,
        write_va, arm_phys, fire_phys, channel_str, slot,
    );
}

/// Hook called from `subsys::linux::ssp_diag::probe_gp_at_ssp_fail` on
/// every musl `__stack_chk_fail` CPL-3 `#GP` (after the
/// content-gate has already verified the trap RIP points at `HLT;RET`,
/// so we're guaranteed to be on the SSP path).
///
/// Emits `[D22/SSP-CHECK] tid=N pid=M read_va=0xX phys_at_read=0xP_r
/// expected=0xM observed=0xV` — the read-time half of the dispositive
/// comparison.  `expected` is the master canary at `IA32_FS_BASE +
/// 0x28` (System V AMD64 ABI §3.4.5.2, TLS variant II); `observed` is
/// the qword now sitting at the saved-canary slot.
///
/// Bounded to one emission per CPL-3 `#GP` event by relying on
/// `ssp_diag`'s own `reserve_slot()` budgeting upstream.  Pure
/// diagnostic — no side effects.
pub fn record_ssp_check(read_va: u64, expected: u64, observed: u64) {
    let cr3 = crate::mm::vmm::get_cr3();
    let phys_at_read = crate::mm::vmm::virt_to_phys_in(cr3, read_va)
        .unwrap_or(0);
    let cpu = crate::arch::x86_64::apic::cpu_index();
    let tid = crate::proc::current_tid();
    let pid = crate::proc::current_pid_lockless();
    crate::serial_println!(
        "[D22/SSP-CHECK] tid={} pid={} cpu={} cr3={:#x} read_va={:#x} \
         phys_at_read={:#x} expected={:#018x} observed={:#018x}",
        tid, pid, cpu, cr3, read_va, phys_at_read, expected, observed,
    );
}

/// Hook called from the clone(2) / clone3(2) PRE-block tail in
/// `kernel/src/subsys/linux/syscall.rs`, immediately after D21's arm
/// (so D22 sees the same vfork-pre-block window).  Off-path cost on
/// non-target callers: one integer compare + one relaxed atomic load.
///
/// On a qualifying call (PID 1, arm-count not saturated), arms BOTH
/// channels on the libxul-caller-frame SSP slot:
///
///   1. **Channel A (linear)** — `arm_linear_watchpoint(canary_va, 8,
///      WATCH_KIND_D22_USER_CANARY_PHYS)`.  Same VA D21 computes from
///      the `[parent_user_rsp + 0x1d58]` saved-RBP probe (System V
///      AMD64 ABI §3.2.2).
///   2. **Channel B (phys)** — `arm_phys_slot_watchpoint(frame_base,
///      offset_in_frame, 8)` on the observed backing frame.  If the
///      live `virt_to_phys_in(cr3, canary_va)` walk returns `None`
///      (slot unmapped at PRE-block), channel B is skipped and a
///      `state=phys_unmapped` line is emitted; channel A still arms.
///
/// Each accepted arm consumes one DR slot until `F3_FIRE_CAP = 32`
/// fires self-disarm it.  The total per-boot arm count is bounded
/// by `D22_ARM_MAX`.
///
/// Per Intel SDM Vol. 3B §17.2.4 a linear arm fires on any CPU's
/// write whose translation resolves to the watched linear address
/// under SOME CR3; a phys arm fires on any CPU's write whose
/// translation resolves to `PHYS_OFF + phys`.  Together they cover
/// the user-VA path AND the kernel-direct-map path for the same
/// underlying frame — the two-channel pattern PR #356 established.
///
/// **STATUS — superseded but retained (2026-05-23).** This hook
/// arms the 0x1d50 saved-RBP slot, not the actual SSP-fail slot at
/// 0x1db8 (see PR #421 / PR #423 evidence in
/// `docs/SSP_KERNEL_WRITER_NAMED_2026-05-23.md`).  The replacement
/// `try_arm_ssp_slot_phys` below is what `syscall.rs` calls; this
/// function is preserved for callers from external crates / tests
/// that may have referenced it under the PR #408 API.
#[allow(dead_code)]
pub fn try_arm_at_vfork_preblock(parent_pid: u64, parent_tid: u64) {
    // Fast precondition checks — keep the hot path cheap.  Same shape
    // as D21's gate.
    if parent_pid != D22_TARGET_PID {
        return;
    }
    if D22_ARM_COUNT.load(Ordering::Relaxed) >= D22_ARM_MAX {
        return;
    }

    // Resolve the parent's user RSP from the saved syscall frame.
    let (user_rsp, _ignored_rbp) = get_parent_user_rsp_rbp(parent_tid);
    if user_rsp == 0 {
        crate::serial_println!(
            "[D22/ARM] pid={} tid={} state=no_user_frame",
            parent_pid, parent_tid,
        );
        return;
    }

    let probe_va = user_rsp.wrapping_add(SAVED_RBP_OFFSET_FROM_RSP);
    if probe_va < USER_ADDR_MIN || probe_va >= USER_ADDR_END {
        crate::serial_println!(
            "[D22/ARM] pid={} tid={} state=probe_va_oor user_rsp={:#x} probe_va={:#x}",
            parent_pid, parent_tid, user_rsp, probe_va,
        );
        return;
    }

    // Watch the **raw-offset** candidate VA: `[user_rsp + 0x1d58] - 8`
    // (the qword adjacent to the existing `s_1d58` probe).  Per the
    // D21 evidence trail (PR #404 + Trial 1 [W215/DR-WATCH-FIRE]
    // kind_tag=7 lines), this is the VA where the user-mode SSP
    // prologue actually writes — the RBP-derived candidate
    // (`*(probe_va) - 8`) lands on a different slot that the writer
    // does not touch.  D22 focuses both channels on the proven hot
    // VA so the dispositive phys-aliasing comparison is on the right
    // slot.  System V AMD64 ABI §3.2.2 SSP convention applies to the
    // resulting linear address regardless of which candidate was
    // chosen.
    let canary_va = user_rsp
        .wrapping_add(SAVED_RBP_OFFSET_FROM_RSP)
        .wrapping_sub(8);

    // Validate canary VA — must be 8-byte aligned and in user range.
    // If not, neither channel can arm safely (per Intel SDM Vol. 3B
    // §17.2.4 Table 17-2 LEN=8 requires natural alignment).
    if canary_va & 0x7 != 0
        || canary_va < USER_ADDR_MIN
        || canary_va >= USER_ADDR_END
    {
        crate::serial_println!(
            "[D22/ARM] pid={} tid={} state=canary_va_invalid \
             user_rsp={:#x} probe_va={:#x} canary_va={:#x}",
            parent_pid, parent_tid, user_rsp, probe_va, canary_va,
        );
        return;
    }

    // Resolve diagnostic context once.
    let cpu = crate::arch::x86_64::apic::cpu_index();
    let cr3 = crate::mm::vmm::get_cr3();
    let (canary_val_opt, canary_phys_opt) = match read_user_qword(canary_va) {
        Some((v, p)) => (Some(v), Some(p)),
        None         => (None, None),
    };

    use crate::arch::x86_64::debug_reg::{
        arm_linear_watchpoint, arm_phys_slot_watchpoint, retag_slot,
        ArmPhysResult, WATCH_KIND_D22_USER_CANARY_PHYS,
    };

    // ── Channel A — linear user-VA arm ───────────────────────────────
    if claim_arm().is_ok() {
        let result = arm_linear_watchpoint(
            canary_va, 8, WATCH_KIND_D22_USER_CANARY_PHYS,
        );
        let (state, slot) = match result {
            ArmPhysResult::Armed(s)      => ("armed", s as i32),
            ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
            ArmPhysResult::NotAligned    => ("not_aligned", -1),
            ArmPhysResult::OutOfRange    => ("out_of_range", -1),
        };
        if let ArmPhysResult::Armed(s) = result {
            note_arm(s, canary_va, canary_phys_opt.unwrap_or(0), CHANNEL_LINEAR);
        }
        let canary_val_str = match canary_val_opt {
            Some(v) => alloc::format!("{:#018x}", v),
            None    => alloc::string::String::from("unmapped"),
        };
        let canary_phys_str = match canary_phys_opt {
            Some(p) => alloc::format!("{:#x}", p),
            None    => alloc::string::String::from("unmapped"),
        };
        crate::serial_println!(
            "[D22/ARM] channel=raw state={} pid={} tid={} cpu={} cr3={:#x} \
             user_rsp={:#x} canary_va={:#x} canary_val={} canary_phys={} \
             slot={} len=8 kind_tag={}",
            state, parent_pid, parent_tid, cpu, cr3,
            user_rsp, canary_va, canary_val_str, canary_phys_str,
            slot, WATCH_KIND_D22_USER_CANARY_PHYS,
        );
    }

    // ── Channel B — PHYS_OFF mirror arm ──────────────────────────────
    // Requires a known live backing phys (otherwise there's nothing to
    // mirror).  Per Intel SDM Vol. 3A §4.6 a missing walk result means
    // the user PTE was not-present at arm time; the channel-A linear
    // arm still covers any subsequent install + write.
    let walked_phys = match canary_phys_opt {
        Some(p) => p,
        None => {
            crate::serial_println!(
                "[D22/ARM] channel=phys state=phys_unmapped pid={} tid={} cpu={} \
                 cr3={:#x} canary_va={:#x}",
                parent_pid, parent_tid, cpu, cr3, canary_va,
            );
            return;
        }
    };
    if D22_ARM_COUNT.load(Ordering::Relaxed) >= D22_ARM_MAX {
        return;
    }
    if claim_arm().is_ok() {
        let frame_base = walked_phys & !0xFFFu64;
        let off_in_frame = walked_phys & 0xFFFu64;
        let result = arm_phys_slot_watchpoint(frame_base, off_in_frame, 8);
        let (state, slot) = match result {
            ArmPhysResult::Armed(s)      => ("armed", s as i32),
            ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
            ArmPhysResult::NotAligned    => ("not_aligned", -1),
            ArmPhysResult::OutOfRange    => ("out_of_range", -1),
        };
        // The `arm_phys_slot_watchpoint` path tags the slot LEGACY
        // (one-shot disarm).  Promote it to
        // `WATCH_KIND_D22_USER_CANARY_PHYS` so the persistent-arm /
        // `F3_FIRE_CAP` policy applies and `record_d22_fire` routes the
        // diagnostic.  Mirrors D16's retag_slot pattern (PR #382).
        if let ArmPhysResult::Armed(s) = result {
            retag_slot(s as usize, WATCH_KIND_D22_USER_CANARY_PHYS);
            // Record using the canary VA as the witness — the phys arm
            // fires on writes to `PHYS_OFF + phys`, and at fire time we
            // want to re-walk the canary VA to compare arm-phys vs
            // fire-phys for the dispositive comparison.
            note_arm(s, canary_va, walked_phys, CHANNEL_PHYS);
        }
        let linear = PHYS_OFF.wrapping_add(walked_phys);
        crate::serial_println!(
            "[D22/ARM] channel=phys state={} pid={} tid={} cpu={} cr3={:#x} \
             canary_va={:#x} canary_phys={:#x} mirror_linear={:#x} \
             slot={} len=8 kind_tag={}",
            state, parent_pid, parent_tid, cpu, cr3,
            canary_va, walked_phys, linear,
            slot, WATCH_KIND_D22_USER_CANARY_PHYS,
        );
    }
}

/// Atomically claim a post-wake arm slot via CAS.  Same shape as
/// `claim_arm` above but on the post-wake counter.
fn claim_postwake_arm() -> Result<(), ()> {
    loop {
        let cur = D22_POSTWAKE_ARM_COUNT.load(Ordering::Relaxed);
        if cur >= D22_POSTWAKE_ARM_MAX {
            return Err(());
        }
        if D22_POSTWAKE_ARM_COUNT
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Hook called from the clone(56) / clone3(435) PRE-block tail in
/// `kernel/src/subsys/linux/syscall.rs`, immediately after the
/// existing `vfork_canary_snapshot("pre_block.cloneX", …)` and the
/// pre-block `try_arm_at_vfork_preblock` arms, **and** again at the
/// matching post-wake tail as a fallback (in case the slot's phys
/// changes between pre-block and post-wake — Mechanism D's
/// signature).  Off-path cost on non-target callers: one integer
/// compare + one relaxed atomic load.
///
/// ## Why arm at the SSP-fail slot offset and via PHYS_OFF
///
/// PR #423's 3-trial KVM soak armed a **linear-VA** write DR on the
/// SSP-fail slot at `parent_rsp + 0x1db8` (= `0x7ffffffee4c0`,
/// byte-identical across boots) at the post-wake site and observed
/// **0/3 fires**, while PR #421 proved the slot's stored qword IS
/// overwritten with `0x30` byte-for-byte across all three trials.
///
/// Per Intel SDM Vol. 3B §17.2.4, DR0–DR3 compare on linear
/// addresses; the user-VA arm therefore covers only writes whose
/// translation resolves to the watched linear address.  A write that
/// targets the slot's backing physical frame via the kernel direct
/// map (`PHYS_OFF + phys`) is invisible to the user-VA arm — its
/// linear address is in the higher half, not the user range.
///
/// This hook arms exactly that complementary channel: a write-only
/// 8-byte DR on `PHYS_OFF + virt_to_phys(parent_rsp + 0x1db8)`.
/// If the corrupting writer is kernel-mode (CS = 0x08 / 0x10) and
/// uses a direct-map mapping rather than the user VA, the next
/// retired store to that frame fires `#DB` and `record_d22_fire`
/// emits the writer's RIP + GPRs + CR3 + CS.  Per Intel SDM Vol. 3B
/// §17.3.1.1 data-breakpoint exceptions are traps taken AFTER the
/// writing instruction retires, so the `#DB` RIP points one
/// instruction past the store — sufficient for post-processing to
/// disassemble backward and name the kernel function.
///
/// ## Why both pre-block and post-wake call sites
///
/// First-deployment evidence (trial 1, 2026-05-23) showed the slot
/// at `0x7ffffffee4c0` already contains `0x30` AT POST-WAKE ARM TIME
/// (`canary_val=0x0000000000000030`), meaning the corrupting write
/// happened during the vfork-wait window.  A post-wake arm therefore
/// cannot catch it (the writing instruction has already retired).
/// Arming at PRE-block — before `schedule()` suspends the parent —
/// places the watchpoint BEFORE the writing window opens.
///
/// The post-wake call site is preserved as a fallback for the
/// (Mechanism-D-shaped) case where the slot's backing frame
/// CHANGES between pre-block and post-wake; if that happens, the
/// pre-block arm watches the old phys and is silent, while the
/// post-wake arm catches the next write to the new phys.  Bounded
/// arm budget (`D22_POSTWAKE_ARM_MAX = 2`) covers both call sites
/// per vfork without unbounded growth.
///
/// ## Why not also re-arm the linear channel here
///
/// PR #423 already established that the linear-VA channel is silent
/// on this slot at this site.  Re-arming it would burn a DR slot
/// without adding information.  The existing pre-block
/// `try_arm_at_vfork_preblock` keeps the linear channel for its
/// (separate) 0x1d50 anchor.
///
/// ## Bounding
///
/// At most `D22_POSTWAKE_ARM_MAX = 2` arms per boot, separate from
/// the pre-block budget so the two channels do not compete.  Each
/// successful arm consumes one DR slot until `F3_FIRE_CAP = 32`
/// fires self-disarm it.  Refused arms (cap reached, pool exhausted,
/// VA unmapped, walk failed) do NOT consume a count.
///
/// ## Diagnostic-only
///
/// Per the saga-discipline rules
/// ([[feedback_saga_diagnostic_discipline_2026_05_20]]) this hook
/// mutates no page tables, allocates no frames, changes no lock
/// order, and performs no syscall-altering side effects.
pub fn try_arm_ssp_slot_phys(parent_pid: u64, parent_tid: u64, site: &'static str) {
    // Fast precondition checks — keep the hot path cheap.  Same
    // shape as the pre-block gate above.
    if parent_pid != D22_TARGET_PID {
        return;
    }
    if D22_POSTWAKE_ARM_COUNT.load(Ordering::Relaxed) >= D22_POSTWAKE_ARM_MAX {
        return;
    }

    // Resolve the parent's user RSP from the saved syscall frame.
    // After `schedule()` returns from the vfork-wait, the parent
    // thread is once again the running context and its kstack-top
    // word still holds the saved user RSP from syscall entry.
    let (user_rsp, _ignored_rbp) = get_parent_user_rsp_rbp(parent_tid);
    if user_rsp == 0 {
        crate::serial_println!(
            "[D22/SSP-PHYS-ARM] site={} pid={} tid={} state=no_user_frame",
            site, parent_pid, parent_tid,
        );
        return;
    }

    // Compute the candidate canary VA at the **post-wake** anchor
    // offset (0x1db8, per PR #423 evidence — distinct from the
    // pre-block 0x1d58 anchor).  Per System V AMD64 ABI §3.2.2 SSP
    // convention applies to the resulting linear address regardless
    // of which anchor was chosen; the offset only selects which
    // call-chain frame's `[rbp-8]` slot is observed.
    let canary_va = user_rsp.wrapping_add(POSTWAKE_FAIL_SLOT_OFFSET);

    // Validate VA — must be 8-byte aligned and in user range.
    // Per Intel SDM Vol. 3B §17.2.4 Table 17-2 LEN=8 requires
    // natural alignment; misalignment would silently widen the
    // breakpoint via the Intel-defined LEN encoding and catch
    // unrelated writes.
    if canary_va & 0x7 != 0
        || canary_va < USER_ADDR_MIN
        || canary_va >= USER_ADDR_END
    {
        crate::serial_println!(
            "[D22/SSP-PHYS-ARM] site={} pid={} tid={} state=canary_va_invalid \
             user_rsp={:#x} canary_va={:#x}",
            site, parent_pid, parent_tid, user_rsp, canary_va,
        );
        return;
    }

    // Walk the user VA → phys under the parent's CR3 (which is the
    // currently-loaded CR3 because we are running in the parent's
    // syscall body post-`schedule()`).  Per Intel SDM Vol. 3A §4.6
    // the walker returns `None` if any level is not-present; in that
    // case there is nothing to mirror and we emit a state line.
    let cpu = crate::arch::x86_64::apic::cpu_index();
    let cr3 = crate::mm::vmm::get_cr3();
    let (canary_val_opt, canary_phys_opt) = match read_user_qword(canary_va) {
        Some((v, p)) => (Some(v), Some(p)),
        None         => (None, None),
    };
    let walked_phys = match canary_phys_opt {
        Some(p) => p,
        None => {
            crate::serial_println!(
                "[D22/SSP-PHYS-ARM] site={} state=phys_unmapped pid={} tid={} cpu={} \
                 cr3={:#x} user_rsp={:#x} canary_va={:#x}",
                site, parent_pid, parent_tid, cpu, cr3, user_rsp, canary_va,
            );
            return;
        }
    };

    use crate::arch::x86_64::debug_reg::{
        arm_phys_slot_watchpoint, retag_slot,
        ArmPhysResult, WATCH_KIND_D22_USER_CANARY_PHYS,
    };

    if claim_postwake_arm().is_err() {
        return;
    }

    let frame_base = walked_phys & !0xFFFu64;
    let off_in_frame = walked_phys & 0xFFFu64;
    let result = arm_phys_slot_watchpoint(frame_base, off_in_frame, 8);
    let (state, slot) = match result {
        ArmPhysResult::Armed(s)      => ("armed", s as i32),
        ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
        ArmPhysResult::NotAligned    => ("not_aligned", -1),
        ArmPhysResult::OutOfRange    => ("out_of_range", -1),
    };
    // Promote the legacy tag set by `arm_phys_slot_watchpoint` to
    // `WATCH_KIND_D22_USER_CANARY_PHYS` so the persistent-arm /
    // `F3_FIRE_CAP` policy applies and `record_d22_fire` routes the
    // diagnostic — same retag pattern as the pre-block path above
    // and PR #382's D16 precedent.
    if let ArmPhysResult::Armed(s) = result {
        retag_slot(s as usize, WATCH_KIND_D22_USER_CANARY_PHYS);
        note_arm(s, canary_va, walked_phys, CHANNEL_PHYS);
    }
    let linear = PHYS_OFF.wrapping_add(walked_phys);
    let canary_val_str = match canary_val_opt {
        Some(v) => alloc::format!("{:#018x}", v),
        None    => alloc::string::String::from("unmapped"),
    };
    crate::serial_println!(
        "[D22/SSP-PHYS-ARM] site={} channel=phys state={} pid={} tid={} cpu={} cr3={:#x} \
         user_rsp={:#x} canary_va={:#x} canary_val={} canary_phys={:#x} \
         mirror_linear={:#x} slot={} len=8 kind_tag={} offset={:#x}",
        site, state, parent_pid, parent_tid, cpu, cr3,
        user_rsp, canary_va, canary_val_str, walked_phys,
        linear, slot, WATCH_KIND_D22_USER_CANARY_PHYS,
        POSTWAKE_FAIL_SLOT_OFFSET,
    );
}
