//! W215 diagnostic — DR0–DR3 write-only watchpoints.
//!
//! Per Intel SDM Vol. 3B §17.2.4 (Debug Address Registers DR0–DR3) and
//! §17.2.5 (Debug Status Register DR6 / Debug Control Register DR7), each
//! CPU has four hardware breakpoint slots whose linear address, size, and
//! access-type are programmed via DR0–DR3 and DR7.  A write-only data
//! breakpoint on a kernel linear address triggers `#DB` (vector 1) on the
//! CPU that performs a write whose data spans the watched range; the
//! instruction pointer captured in the interrupt frame is the RIP of the
//! offending instruction.
//!
//! This module exposes a four-slot watchpoint scheme used by the W215
//! page-cache CRC walker (`mm/w215_crc.rs`) and the cache::insert
//! pre-arming hook (`mm/cache.rs`) to identify the kernel code path that
//! mutates a cache-resident frame.  Slot assignment convention:
//!
//!   - DR0 — reserved for **post-hoc** arming by the CRC walker after a
//!     mismatch is detected (the historical Arm-1 single-slot behaviour).
//!   - DR1, DR2, DR3 — used **at insert time** as a pre-arming pool over
//!     suspect cache keys (libxul cluster), round-robin.  Earlier capture
//!     than DR0 because the watch fires the moment the upstream writer
//!     stores, before any cache-evict / memset chain can play out.
//!
//! ## Cross-CPU synchronisation
//!
//! DR0–DR7 are per-CPU registers (Intel SDM Vol. 3B §17.2).  To watch a
//! set of linear addresses on every CPU we publish the desired per-slot
//! `(addr, ctrl)` pairs to static atomic arrays, bump a global
//! `SYNC_GENERATION`, and rely on each CPU to notice the gen-bump on its
//! next pass through `apply_pending_if_stale()` (called from the timer
//! ISR) and re-program its own DR0–DR3 + DR7 from the published atomics.
//!
//! ### Why no IPI broadcast
//!
//! Both arm sites (`arm_write_watchpoint`, post-hoc from the CRC walker,
//! and the `#DB` fire path in `handle_db_exception`) run in interrupt
//! context with `IF=0`.  A `send_ipi`-style broadcast from inside the
//! timer ISR can interact badly with peer CPUs that are themselves in
//! their own timer ISR — both spinning on `LAPIC ICR_LO bit 12`
//! ("delivery status", Intel SDM Vol. 3A §10.6.1) while the destination's
//! `IF=0` keeps the IPI undispatched.  Empirically the broadcast path
//! deadlocked under multi-CPU contention: the originator's
//! `[W215/DR-ARM]` `serial_println!` (sequenced **after** the broadcast)
//! never emitted, and no peer ever ran the IPI handler.
//!
//! Linux follows the same restriction: `arch_install_hw_breakpoint`
//! programs only the local CPU and is `lockdep_assert_irqs_disabled()`
//! (atomic, this-cpu only); cross-CPU installation in Linux is deferred
//! to `smp_call_function`, which only runs in process context with `IF=1`.
//! See `Documentation/locking/hwspinlock.rst` and Intel SDM Vol. 3B
//! §17.2.4 for the per-CPU DR programming contract.
//!
//! The lazy-gen protocol is one-shot per arm: the originator publishes
//! per-slot atomics, increments `SYNC_GENERATION`, and programs its own
//! DRs immediately.  Every other CPU calls `apply_pending_if_stale()` at
//! the top of its timer ISR (cheap fast-path: one atomic load + compare);
//! when its locally cached generation lags the global, it re-runs
//! `program_local_drs`.  Worst-case latency is one timer tick
//! (`TICK_HZ = 100`, i.e. ≤ 10 ms) — far below the W215 capture window.
//!
//! ## Public surface
//!
//! - `arm_write_watchpoint(linear_addr, len, phys, inode, file_offset)` —
//!     post-hoc arm on DR0; returns `true` if DR0 was available.
//! - `arm_preinsert_watchpoint(linear_addr, len, phys, inode, file_offset)` —
//!     insert-time arm on DR1/DR2/DR3 round-robin; returns `Some(slot)`
//!     if a slot was free, `None` if all three were busy.
//! - `apply_pending_if_stale()` — call from each CPU's timer ISR.  Fast
//!     path (gen-equal) is two atomic loads; slow path reprograms DRs.
//! - `apply_pending_to_this_cpu()` — unconditional re-program; called
//!     from `ap_rust_entry` so a CPU that comes online after arm picks
//!     up the watchpoints.
//! - `handle_w215_dr_sync_ipi()` — IPI handler; back-compat only, no
//!     current sender (cross-CPU sync went lazy-gen-polled).
//! - `handle_db_exception(...)` — `#DB` dispatcher; returns `true` if the
//!   trap belonged to W215 and was consumed.
//! - `is_armed()` — back-compat: true if DR0 is armed.
//! - `stats()` — `(arm_count, fire_count)` summary.
//!
//! No fix-it logic lives here; the module is diagnostic-only.

#![cfg(any(feature = "w215-diag", feature = "582-diag"))]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering};

/// LAPIC vector used to broadcast a DR update to other CPUs.
///
/// Chosen to sit immediately above the TLB shootdown vector (`0xF0`,
/// see `mm/tlb.rs`) and below the spurious-interrupt vector (`0xFF`).
/// No other AstryxOS handler installs here.
pub const W215_DR_SYNC_VECTOR: u8 = 0xF1;

/// Number of hardware breakpoint slots (DR0–DR3).  Per Intel SDM Vol. 3B
/// §17.2.4, x86_64 always exposes exactly four.
pub const N_DR_SLOTS: usize = 4;

/// Per-slot armed flag.
static ARMED: [AtomicBool; N_DR_SLOTS] = [
    AtomicBool::new(false), AtomicBool::new(false),
    AtomicBool::new(false), AtomicBool::new(false),
];
/// Per-slot watched linear address (`PHYS_OFF + phys`).
static ARMED_ADDR: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Per-slot DR7-shaped local control bits, in the canonical positions for
/// that slot.  See `slot_dr7_bits` for the layout.
static ARMED_CTRL: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Per-slot phys / cache-key snapshot for the fire-line.
static ARMED_PHYS: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static ARMED_KEY_INODE: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static ARMED_KEY_OFFSET: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Per-slot watch-kind tag.  Encodes the policy/owner that armed the slot
/// so the `#DB` fire-line can route the diagnostic to the right consumer.
/// Values:
///   0 — unset / legacy (cache CRC walker / pre-insert pool / kdb manual)
///   1 — F3 user-VA stack-canary watch (see `subsys/linux/f3_watch.rs`)
///   2 — F3 PHYS_OFF stack-canary mirror (same)
///   3 — D7 PT_TLS BSS-slot watch (see `subsys/linux/d7_bss_watch.rs`).
///       Same persistent-arm policy as the F3 tags (capped at
///       `F3_FIRE_CAP` fires per slot per boot, see `handle_db_exception`).
///   4 — D15 `RegisteredThread::mThreadInfo` slot watch (see
///       `subsys/linux/d15_mthread_watch.rs`).  Catches writes (or absence
///       of writes) to the heap-object qword at `[*(fs:-0x18) + 0x38]`
///       for firefox-bin pid=1.  Same persistent-arm + `F3_FIRE_CAP`
///       policy as D7.
///   5 — D16 SSP-canary saved-slot watch (see
///       `subsys/linux/d16_canary_watch.rs`).  Catches writes to the
///       saved-canary stack qword at user VA `0x7ffffffee4c0` (and its
///       deterministic backing phys `0x127114c0` via `PHYS_OFF`) on the
///       firefox-bin pid=1 init thread.  Used to name the writer of the
///       observed `0x30`-byte mismatch in musl `__stack_chk_fail`.
///       Same persistent-arm + `F3_FIRE_CAP` policy as D7/D15.
///   6 — D20 kernel-stack canary watch (see
///       `subsys/linux/d20_kstack_canary_watch.rs`).  Catches writes to
///       the kernel-stack canary qword at `[kernel_stack_base, +8)` for
///       the first N PID-2 thread creations — the post-#396/#397
///       STACK_CANARY_CORRUPT bugcheck victim (PID 2 TID 5).  Same
///       persistent-arm + `F3_FIRE_CAP` policy.  Per Intel SDM Vol. 3B
///       §17.3.1.1 each fire names one retired writer.
///   7 — D21 PID-1 user stack-frame saved-canary watch (see
///       `subsys/linux/d21_user_canary_watch.rs`).  Catches writes to
///       the libxul-caller-frame `[rbp-8]` SSP slot for the PID 1 init
///       thread at the moment of the `CLONE_VM|CLONE_VFORK` PRE-block.
///       Names the user-mode SSP-canary writer for the post-PR-#400
///       `__stack_chk_fail` at ld-musl+0x1c7f9 (PR #398 evidence).
///       Same persistent-arm + `F3_FIRE_CAP` policy.
///   8 — D22 PID-1 user-canary PHYS_OFF channel (see
///       `subsys/linux/d22_user_canary_phys.rs`).  Pairs with the D21
///       linear-VA arm to catch the **phys-aliasing** mechanism (D
///       per PR #407 Wave 12 verdict): user-stack canary VA whose
///       backing physical frame differs between prologue store and
///       epilogue load.  Same two-channel pattern PR #356 established
///       for K2b.  Same persistent-arm + `F3_FIRE_CAP` policy.  The
///       `record_d22_fire` hook re-walks the user VA under the
///       firing CR3 to name `phys_at_write`; `record_ssp_check` in
///       the CPL-3 `#GP` path names `phys_at_read` for the
///       dispositive comparison.
/// Future axes may take additional tags without disturbing existing arms.
pub const WATCH_KIND_LEGACY:        u32 = 0;
pub const WATCH_KIND_F3_USER:       u32 = 1;
pub const WATCH_KIND_F3_PHYS:       u32 = 2;
pub const WATCH_KIND_D7_BSS:        u32 = 3;
pub const WATCH_KIND_D15_MTHRD:     u32 = 4;
pub const WATCH_KIND_D16_CANARY:    u32 = 5;
pub const WATCH_KIND_D20_KSTACK:    u32 = 6;
pub const WATCH_KIND_D21_USER_CANARY: u32 = 7;
pub const WATCH_KIND_D22_USER_CANARY_PHYS: u32 = 8;
///   9 — F3 code-fetch (instruction-execute) watch on the user-VA of
///       musl `__stack_chk_fail+0x0` (see
///       `subsys/linux/f3_code_dr_watch.rs`).  Differs from kinds 1–8
///       in DR7 encoding: RW=00b (instruction execute) + LEN=00b
///       (must be 1-byte per Intel SDM Vol. 3B §17.2.4 Table 17-2).
///       Per §17.3.1.1, instruction-fetch breakpoints are *faults*
///       (taken before the instruction retires), so the `#DB` frame's
///       `rip` is the watched address itself — convenient for naming
///       the SSP-fail entry as the dispositive caller-frame snapshot
///       point.  One-shot disarm policy (`one_shot=true` for this
///       kind), matching legacy slots — a single fire produces the
///       full dump and the slot releases for any later diagnostic.
pub const WATCH_KIND_F3_CODE_DR:     u32 = 9;
///  10 — #582 torn-saved-RFLAGS-slot watch.  Arms an 8-byte *data-write*
///       watch on a context-switch victim's saved-RFLAGS slot
///       (`Thread::context.rsp + 0`, the qword the `pushfq` in
///       `switch_context_asm` last stored before the save site).  The
///       goal is to name the out-of-band store that tears that slot to a
///       TF-set value while the victim sits Ready/Blocked (the kernel-mode
///       `#DB`/`UNEXPECTED_KERNEL_MODE_TRAP 0x7f` root).  Per Intel SDM
///       Vol. 3B §17.3.1.1 a data-write breakpoint is a *trap* (taken
///       after the writer's store retires), so the watched qword read at
///       fire time reflects exactly what the writer just stored.  The
///       fire path (`arch::x86_64::db582::record_fire`) classifies the
///       writer RIP as the legitimate `switch_context_asm` re-save (benign
///       churn — re-arm and continue) versus an out-of-band RIP (the
///       catch).  Persistent across fires (its own cap) so the watch can
///       sit through many benign re-saves until the foreign writer hits.
pub const WATCH_KIND_D582_RFLAGS:    u32 = 10;
static ARMED_KIND: [AtomicU32; N_DR_SLOTS] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

/// Per-slot fire count.  Final report sums to the legacy single counter.
static DR_FIRE_COUNT: [AtomicU32; N_DR_SLOTS] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

/// Per-slot fire CAP for `WATCH_KIND_F3_*` arms.  After this many
/// `#DB` events the slot self-disarms and the post-processor sees a
/// final `[W215/DR-WATCH-FIRE] one_shot=1 …` line for the cap-th hit.
/// Bounded to keep the serial log readable when the user-VA slot
/// catches a hot write loop (e.g. a memset across the saved-canary
/// slot); above the cap the writer identity is already known from
/// the first ~N fires.
const F3_FIRE_CAP: u32 = 32;

/// Per-slot fire CAP for `WATCH_KIND_D16_CANARY` arms when the D18
/// extension is enabled.  D17 (PR #383) found 32 fires exhausted the
/// cap before the 0x30-byte writer was captured — the 32nd entry was
/// a libxul write of part of the "screenshot" string, meaning the
/// real corrupting writer was the 33rd+ store to the slot.  Raising
/// the cap lets D18 attribute the actual corrupting write at the
/// price of a larger log window; the writer-naming budget (CPL=3 vs
/// CPL=0) is unchanged.  Bounded to avoid unbounded fire loops on a
/// hot prologue path.
///
/// At `F3_FIRE_CAP` × 8-line emission (fire line + 7 stack qwords +
/// per-fire D17 records) ≈ 250 lines, vs `D16_FIRE_CAP` × 8 ≈ 2 KiB
/// lines per boot — well inside the serial-log retention window
/// (per `~/.astryx-harness/<sid>.serial.log` rotation).
///
/// Cited under POSIX `__stack_chk_fail(3)` semantics and Intel SDM
/// Vol. 3B §17.3.1.1 (trap-after-retire — each fire names one
/// retired writer; raising the cap names more writers without
/// changing fire-time semantics).
#[cfg(feature = "d18-extended-d16")]
const D16_FIRE_CAP: u32 = 256;
#[cfg(not(feature = "d18-extended-d16"))]
const D16_FIRE_CAP: u32 = F3_FIRE_CAP;

/// Per-slot fire CAP for `WATCH_KIND_D582_RFLAGS` arms.  The watch sits on
/// a switch-victim's saved-RFLAGS slot and is *expected* to fire on every
/// legitimate `switch_context_asm` re-save of that same victim (benign
/// churn — the `db582` fire path classifies those and does not emit a
/// catch line for them).  The cap must therefore be high enough that the
/// slot survives many benign re-saves before the out-of-band writer hits;
/// the fire path self-limits the *logged* output to a small budget so the
/// raised cap does not flood serial.  Per Intel SDM Vol. 3B §17.3.1.1 each
/// fire still names exactly one retired writer.
const D582_FIRE_CAP: u32 = 1_000_000;

/// Number of arm broadcasts issued since boot (sum across slots).
static ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Round-robin cursor over the pre-insert pool {DR1, DR2, DR3}.  Lives
/// outside the per-slot atomic array because the policy is "pick first
/// free starting from cursor, then advance".
static PREINS_CURSOR: AtomicU32 = AtomicU32::new(0);

/// Global publish generation.  Incremented every time any slot's published
/// state (`ARMED`, `ARMED_ADDR`, `ARMED_CTRL`) changes.  Peer CPUs compare
/// this to their `LOCAL_SYNC_GENERATION` slot at the top of their timer
/// ISR via `apply_pending_if_stale()`; a stale local gen triggers a
/// re-`program_local_drs` so the slot's enable bits in DR7 reach every CPU
/// within one tick (≤ 10 ms at `TICK_HZ = 100`).
static SYNC_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Per-CPU cached snapshot of `SYNC_GENERATION` at the last
/// `program_local_drs` on that CPU.  Sized to `super::apic::MAX_CPUS`.
/// Equal to global → DRs are up to date; less than global → re-program.
static LOCAL_SYNC_GENERATION: [AtomicU64; super::apic::MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; super::apic::MAX_CPUS]
};

/// Per-slot DR7 R/W and LEN field positions.
///
/// Per Intel SDM Vol. 3B §17.2.4 Table 17-2 (DR7 layout):
///   - L{i} = bit 2*i           (local enable)
///   - G{i} = bit 2*i + 1       (global enable)
///   - R/W{i} = bits 16+4*i .. 17+4*i
///   - LEN{i} = bits 18+4*i .. 19+4*i
///   - LE   = bit 8, GE = bit 9 (exact-data-match — recommended)
///   - bit 10 reserved, must be 1
fn dr7_bits_for_slot(slot: usize, len: u8) -> u64 {
    debug_assert!(slot < N_DR_SLOTS);
    let rw: u64 = 0b01;        // write-only
    let len_field: u64 = match len {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        8 => 0b10,             // 8-byte form is valid on x86_64 per §17.2.5
        _ => 0b11,
    };
    let li = 2 * slot as u64;
    let gi = li + 1;
    let rw_pos = 16 + (4 * slot as u64);
    let len_pos = rw_pos + 2;
    let mut ctrl: u64 = 0;
    ctrl |= 1 << li;           // L{slot}
    ctrl |= 1 << gi;           // G{slot}
    ctrl |= rw << rw_pos;
    ctrl |= len_field << len_pos;
    ctrl
}

/// Read DR7.
#[inline(always)]
fn read_dr7() -> u64 {
    let dr7: u64;
    unsafe {
        core::arch::asm!("mov {}, dr7", out(reg) dr7, options(nomem, nostack, preserves_flags));
    }
    dr7
}

#[inline(always)]
fn write_dr7(val: u64) {
    unsafe {
        core::arch::asm!("mov dr7, {}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
fn write_dr_n(slot: usize, addr: u64) {
    // DR0–DR3 are not addressable by index in the `mov drN, reg` syntax —
    // the operand encodes the register number.  Use a match.
    unsafe {
        match slot {
            0 => core::arch::asm!("mov dr0, {}", in(reg) addr, options(nomem, nostack, preserves_flags)),
            1 => core::arch::asm!("mov dr1, {}", in(reg) addr, options(nomem, nostack, preserves_flags)),
            2 => core::arch::asm!("mov dr2, {}", in(reg) addr, options(nomem, nostack, preserves_flags)),
            3 => core::arch::asm!("mov dr3, {}", in(reg) addr, options(nomem, nostack, preserves_flags)),
            _ => {}
        }
    }
}

/// Program DR0–DR3 + DR7 on the current CPU from the published per-slot
/// atomics.  No-op when no slot is armed.
///
/// Always sets bit 10 (reserved-1) and clears LE/GE — exact-data-match is
/// optional on modern silicon and our R/W=write-only filter does not need
/// it, while LE/GE introduces an extra latency requirement on some CPUs.
///
/// Safe to call from interrupt context: only touches debug registers and
/// the atomics, never holds a lock.
#[inline(never)]
fn program_local_drs() {
    // Re-build DR7 from per-slot enables.  When a slot has been disarmed
    // we *must* explicitly clear its enable bits in DR7, otherwise a
    // formerly-watched address that the kernel writes again (typical:
    // disarm because Arm-1 captured the writer, then a follow-on write
    // happens through the same address before our IPI propagates) will
    // re-trip the trap and bugcheck.  This is the fix for PR #260 Issue 1.
    let mut dr7: u64 = 1 << 10; // reserved bit
    let mut any_armed = false;
    for slot in 0..N_DR_SLOTS {
        if !ARMED[slot].load(Ordering::Acquire) {
            // Slot is disarmed.  Leave DR{slot} value as-is (writing 0
            // would be safe, but is unnecessary because L{slot}=G{slot}=0
            // suppresses the breakpoint regardless of DR{slot} contents).
            continue;
        }
        let addr = ARMED_ADDR[slot].load(Ordering::Relaxed);
        if addr == 0 {
            // Defensive: a zero addr with ARMED=true means a publish-tear;
            // skip this slot rather than catch every kernel-page-zero read.
            continue;
        }
        let ctrl = ARMED_CTRL[slot].load(Ordering::Relaxed);
        write_dr_n(slot, addr);
        dr7 |= ctrl;
        any_armed = true;
    }
    // Always commit DR7 — even when `any_armed == false` we want to clear
    // any stale enable bits that may remain from a previous arm.  This is
    // the explicit-clear path that closes PR #260 Issue 1.
    let _ = any_armed; // retained for readability
    unsafe {
        // Clear DR6 before re-programming DR7 to avoid an immediate
        // spurious `#DB` from a stale B0..B3.  Per Intel SDM Vol. 3B
        // §17.2.5 the B bits are sticky until cleared by software.
        core::arch::asm!("mov dr6, {}", in(reg) 0u64, options(nomem, nostack, preserves_flags));
    }
    write_dr7(dr7);
}

/// Apply the currently armed watchpoints to this CPU.  Called from
/// `apic::ap_rust_entry` so a CPU that comes online after Arm-1 fires
/// picks up the watchpoint, and from the IPI handler (retained for
/// back-compat — the IPI path is no longer the primary sync mechanism).
///
/// Always re-programs; the local-gen snapshot is updated as a side effect.
pub fn apply_pending_to_this_cpu() {
    // Sample the global gen BEFORE programming so a concurrent
    // arm/disarm that bumps the gen between our DR write and our
    // snapshot store causes the next `apply_pending_if_stale` to
    // re-program rather than miss the update.
    let gen = SYNC_GENERATION.load(Ordering::Acquire);
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(gen, Ordering::Release);
    }
}

/// Cheap fast-path called at the top of every CPU's timer ISR.  If the
/// per-CPU cached `LOCAL_SYNC_GENERATION` matches the global
/// `SYNC_GENERATION`, returns immediately (two atomic loads + compare).
/// Otherwise re-programs DR0–DR3 + DR7 on the current CPU and refreshes
/// the local snapshot.
///
/// This is the cross-CPU sync mechanism — see the module-level docs for
/// why we use a polled-gen instead of an IPI broadcast.  Safe to call
/// from ISR context: never holds a lock, never sends an IPI, never
/// calls `serial_println!` on the fast path.
#[inline]
pub fn apply_pending_if_stale() {
    let global = SYNC_GENERATION.load(Ordering::Acquire);
    let cpu = super::apic::cpu_index();
    if cpu >= super::apic::MAX_CPUS {
        return;
    }
    let local = LOCAL_SYNC_GENERATION[cpu].load(Ordering::Acquire);
    if local == global {
        return;
    }
    // Stale — refresh.  Sample the global again BEFORE programming so
    // we don't store a snapshot newer than what we just programmed.
    let g2 = SYNC_GENERATION.load(Ordering::Acquire);
    program_local_drs();
    LOCAL_SYNC_GENERATION[cpu].store(g2, Ordering::Release);
}

/// Internal: attempt to claim slot `slot`, returning `true` on success.
/// Publishes the slot's address/control/key atomics on success.
fn try_arm_slot(
    slot: usize,
    linear_addr: u64,
    len: u8,
    phys: u64,
    inode: u64,
    file_offset: u64,
) -> bool {
    if ARMED[slot]
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    let ctrl = dr7_bits_for_slot(slot, len);
    ARMED_ADDR[slot].store(linear_addr, Ordering::Relaxed);
    ARMED_CTRL[slot].store(ctrl, Ordering::Relaxed);
    ARMED_PHYS[slot].store(phys, Ordering::Relaxed);
    ARMED_KEY_INODE[slot].store(inode, Ordering::Relaxed);
    ARMED_KEY_OFFSET[slot].store(file_offset, Ordering::Relaxed);
    // Default to LEGACY; callers that need a different tag
    // (`arm_linear_watchpoint`) overwrite this after a successful arm.
    // Per-slot reset ensures a slot that was previously F3 and got
    // re-armed by the legacy walker does not carry stale routing.
    ARMED_KIND[slot].store(WATCH_KIND_LEGACY, Ordering::Relaxed);
    true
}

/// Post-hoc arm on DR0 (the CRC walker's slot).  Returns `true` if DR0
/// was free and got armed.  Back-compat name with PR #260.
///
/// Cross-CPU sync is **lazy** via `SYNC_GENERATION` — we bump the gen
/// and program our own DRs; peer CPUs notice the gen-bump in their
/// next `apply_pending_if_stale()` (timer ISR top).  See the
/// module-level docs for the rationale (the prior `broadcast_dr_sync`
/// IPI path deadlocked from ISR-to-ISR contention and the post-hoc
/// `[W215/DR-ARM]` `serial_println!` never emitted).
pub fn arm_write_watchpoint(
    linear_addr: u64,
    len: u8,
    phys: u64,
    inode: u64,
    file_offset: u64,
) -> bool {
    if !try_arm_slot(0, linear_addr, len, phys, inode, file_offset) {
        return false;
    }
    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    // Emit the [W215/DR-ARM] line BEFORE programming DRs so the arm is
    // recorded in the serial log even if a downstream step (program, gen
    // bump) hangs or aborts.  The original ordering put the println after
    // `broadcast_dr_sync` — when the broadcast deadlocked, the line was
    // never emitted and the diagnostic looked silent.
    crate::serial_println!(
        "[W215/DR-ARM] slot=0 linear={:#x} phys={:#x} inode={} offset={:#x}",
        linear_addr, phys, inode, file_offset,
    );
    // Bump the publish gen FIRST so a peer CPU racing into
    // `apply_pending_if_stale` after our program_local_drs returns sees
    // the new global gen and re-programs.  Release pairs with the
    // Acquire on `SYNC_GENERATION` in `apply_pending_if_stale`.
    SYNC_GENERATION.fetch_add(1, Ordering::Release);
    program_local_drs();
    // Refresh our own local-gen snapshot so we don't loop on stale.
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    true
}

/// Pre-insert arm: try DR1, then DR2, then DR3, advancing the round-robin
/// cursor.  Returns `Some(slot)` if a slot was free, `None` otherwise.
///
/// Called from `cache::insert` for entries whose `(mount, inode)` falls in
/// the W215 libxul cluster.  Diagnostic-only.
pub fn arm_preinsert_watchpoint(
    linear_addr: u64,
    len: u8,
    phys: u64,
    inode: u64,
    file_offset: u64,
) -> Option<u8> {
    // Start at PREINS_CURSOR mod 3, scan {DR1, DR2, DR3} once.
    let start = (PREINS_CURSOR.fetch_add(1, Ordering::Relaxed) as usize) % 3;
    for off in 0..3usize {
        let slot = 1 + ((start + off) % 3);
        if try_arm_slot(slot, linear_addr, len, phys, inode, file_offset) {
            ARM_COUNT.fetch_add(1, Ordering::Relaxed);
            // Emit println BEFORE DR programming and gen bump so the arm
            // is recorded even if a downstream step aborts.  Matches the
            // post-hoc `arm_write_watchpoint` ordering.
            crate::serial_println!(
                "[W215/DR-ARM] slot={} linear={:#x} phys={:#x} inode={} offset={:#x} kind=preinsert",
                slot, linear_addr, phys, inode, file_offset,
            );
            // Bump the publish gen so peer CPUs pick up this slot on
            // their next timer-ISR `apply_pending_if_stale` call.  We DO
            // NOT broadcast a sync IPI from the cache::insert hot path:
            //   - Insert can run with cache locks held;
            //   - the cost of an IPI on every steady-state insert is
            //     meaningful during prepopulate;
            //   - the writer the watch is meant to catch is
            //     overwhelmingly likely to be on the same CPU that
            //     committed the insert (CoW / memset paths run in
            //     thread context on the faulting CPU), so the local
            //     program_local_drs below is what matters most.
            SYNC_GENERATION.fetch_add(1, Ordering::Release);
            program_local_drs();
            let cpu = super::apic::cpu_index();
            if cpu < super::apic::MAX_CPUS {
                LOCAL_SYNC_GENERATION[cpu].store(
                    SYNC_GENERATION.load(Ordering::Acquire),
                    Ordering::Release,
                );
            }
            return Some(slot as u8);
        }
    }
    None
}

/// IPI handler for `W215_DR_SYNC_VECTOR`.
///
/// Retained for IDT-slot back-compat (the IDT vector `0xF1` is wired in
/// `idt.rs`; removing the slot would shift other vectors), but no caller
/// currently sends this vector — cross-CPU DR sync went lazy-gen-polled
/// (`apply_pending_if_stale` from each CPU's timer ISR) after the
/// IPI-from-ISR deadlock investigation.  See module-level docs.
///
/// If the vector ever does fire (e.g. a future caller restores the
/// broadcast path for non-ISR contexts), the handler does the right
/// thing: re-program this CPU's DRs and EOI.
pub extern "C" fn handle_w215_dr_sync_ipi() {
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    super::apic::lapic_eoi();
}

/// Read DR6.
#[inline(always)]
fn read_dr6() -> u64 {
    let dr6: u64;
    unsafe {
        core::arch::asm!("mov {}, dr6", out(reg) dr6, options(nomem, nostack, preserves_flags));
    }
    dr6
}

#[inline(always)]
fn write_dr6(val: u64) {
    unsafe {
        core::arch::asm!("mov dr6, {}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

/// Read CR3.
#[inline(always)]
fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Inspect DR6 to see whether this `#DB` is a W215 watchpoint firing.
///
/// On a hit:
///   - Disarms the slot globally (one-shot capture per slot).
///   - Emits `[W215/DR-WATCH-FIRE] slot=N ...` with RIP, CR3, phys, key.
///   - Dumps 8 qwords at and below RSP.
///   - Clears B0..B3 in DR6.
///   - Re-broadcasts the DR sync so other CPUs disarm their copy of the
///     just-fired slot.
///   - Returns `true` to tell the dispatcher this trap is consumed.
///
/// If multiple slots fire on the same `#DB` (rare but legal — Intel SDM
/// Vol. 3B §17.2.5 says all hit bits are reported in DR6), each is logged
/// and disarmed.
///
/// Returns `false` if the trap is not a W215 watchpoint.
/// GPR snapshot passed through from the IDT ISR stub.  Index layout matches
/// the saved-frame walk in `arch/x86_64/idt.rs` (the `isr_no_error!`
/// macro pushes r15 first / rax last; the slice index reflects the same
/// order so a consumer can address registers by name without arithmetic):
///
///   `[0] = r15, [1] = r14, [2] = r13, [3] = r12, [4] = rbp, [5] = rbx,
///    [6] = r11, [7] = r10, [8] = r9,  [9] = r8,  [10] = rdi, [11] = rsi,
///    [12] = rdx, [13] = rcx, [14] = rax`
///
/// Passed as `Option<&Gprs>` so callers that don't have the saved frame
/// available (none currently; reserved for future ISR shapes) can still
/// invoke the dispatcher.
pub type Gprs = [u64; 15];

pub fn handle_db_exception(
    rip: u64,
    rsp: u64,
    rflags: u64,
    cs: u64,
    gprs: Option<&Gprs>,
) -> bool {
    let dr6 = read_dr6();
    let hit_mask = dr6 & 0xF;
    if hit_mask == 0 {
        return false;
    }
    // Check that at least one of the hit slots is one we armed.
    let mut consumed = false;
    let cpu = super::apic::cpu_index();
    let cr3 = read_cr3();
    for slot in 0..N_DR_SLOTS {
        if (hit_mask & (1u64 << slot)) == 0 {
            continue;
        }
        if !ARMED[slot].load(Ordering::Acquire) {
            // Stale sticky bit for a slot we never armed.  Clear it and
            // skip; do NOT treat as consumed — the trap may belong to
            // someone else (e.g. an INT1 instruction).
            continue;
        }
        let phys = ARMED_PHYS[slot].load(Ordering::Relaxed);
        let inode = ARMED_KEY_INODE[slot].load(Ordering::Relaxed);
        let offset = ARMED_KEY_OFFSET[slot].load(Ordering::Relaxed);
        let addr = ARMED_ADDR[slot].load(Ordering::Relaxed);
        let kind_tag = ARMED_KIND[slot].load(Ordering::Relaxed);
        // For F3-routed slots we want to keep the slot armed across fires
        // — the prologue write is just one of N writes we expect, and the
        // smoking-gun foreign write may come later.  The legacy one-shot
        // disarm is preserved only for `WATCH_KIND_LEGACY` slots.  Per
        // Intel SDM Vol. 3B §17.2.5, leaving DR{slot} and DR7 enable bits
        // armed across an EOI'd `#DB` is supported behaviour — the next
        // matching write on any CPU re-triggers `#DB` on that CPU.
        //
        // Diagnostic emission is still bounded (per-slot via
        // `DR_FIRE_COUNT`'s saturating increment) so an F3 slot cannot
        // flood the serial log; the post-processor reads at most
        // `u32::MAX` fires per slot per boot — far above any plausible
        // write rate for a single stack qword.
        let fire_idx = DR_FIRE_COUNT[slot].fetch_add(1, Ordering::Relaxed);
        // F3 slots persist across fires up to F3_FIRE_CAP; legacy slots
        // disarm one-shot.  When an F3 slot reaches its cap, treat the
        // capping fire as one_shot=1 so the post-processor sees the
        // closing marker; subsequent writes will not re-trigger because
        // the slot is now disarmed.
        //
        // D16 (`WATCH_KIND_D16_CANARY`) uses its own cap (`D16_FIRE_CAP`)
        // so the D18 extension can raise the per-boot fire budget for
        // the SSP-canary slot without affecting D7/D15/F3 caps.  Per
        // Intel SDM Vol. 3B §17.3.1.1 each fire still names one
        // retired writer; the cap controls how many writers we log,
        // not the timing of the trap.
        let cap = match kind_tag {
            WATCH_KIND_D16_CANARY => D16_FIRE_CAP,
            WATCH_KIND_D582_RFLAGS => D582_FIRE_CAP,
            _ => F3_FIRE_CAP,
        };
        let one_shot = match kind_tag {
            WATCH_KIND_LEGACY => true,
            _ => fire_idx + 1 >= cap,
        };
        if one_shot {
            ARMED[slot].store(false, Ordering::Release);
            ARMED_ADDR[slot].store(0, Ordering::Relaxed);
            ARMED_CTRL[slot].store(0, Ordering::Relaxed);
            ARMED_KIND[slot].store(WATCH_KIND_LEGACY, Ordering::Relaxed);
        }

        // #582 RFLAGS-slot watch — route to the dedicated classifier and
        // SKIP the generic `[W215/DR-WATCH-FIRE]` + stack dump below.  The
        // D582 watch fires on every benign `switch_context_asm` re-save of
        // the watched victim; emitting the verbose generic dump per fire
        // would flood serial.  `record_fire` self-limits its output and
        // only emits loudly on an out-of-band writer (the catch).  Gated
        // on `582-diag`.  Marking the trap consumed and continuing keeps
        // the slot armed for the next fire (re-armable) unless `one_shot`
        // already disarmed it at the cap.
        #[cfg(feature = "582-diag")]
        if kind_tag == WATCH_KIND_D582_RFLAGS {
            crate::arch::x86_64::db582::record_fire(
                slot as u8, fire_idx, rip, rsp, rflags, cs, cr3, addr, gprs,
            );
            consumed = true;
            continue;
        }

        crate::serial_println!(
            "[W215/DR-WATCH-FIRE] slot={} fire_idx={} cpu={} rip={:#x} cs={:#x} \
             rflags={:#x} cr3={:#x} phys={:#x} linear={:#x} key=(_,{},{:#x}) \
             dr6={:#x} kind_tag={} one_shot={}",
            slot, fire_idx, cpu, rip, cs, rflags, cr3, phys, addr, inode, offset,
            dr6, kind_tag, one_shot as u8,
        );
        // D17 hook — record the (rip, canary-VA, current-phys, current-value)
        // for D16-tagged fires so the SSP-fail `#GP` post-processor can
        // compare against the read-time phys.  Intel SDM Vol. 3B §17.3.1.1
        // says the `#DB` is taken after the writer's store retires, so the
        // qword we read through the direct map now reflects what the
        // writer just stored.  Gated on `d17-aliasing-test`.
        #[cfg(feature = "d17-aliasing-test")]
        if kind_tag == WATCH_KIND_D16_CANARY {
            crate::subsys::linux::d17_aliasing_test::record_d16_fire(rip, cs, cr3);
        }
        // D22 hook — emit the per-fire `[D22/USER-CANARY-PHYS]` line
        // for D22-tagged slots.  Captures `phys_at_write` (re-walked
        // under the firing CR3) for the dispositive comparison
        // against the read-time `phys_at_read` emitted by the SSP
        // `#GP` path's `record_ssp_check`.  Per Intel SDM Vol. 3B
        // §17.3.1.1 the writer's store has already retired by the
        // time `#DB` is taken, so the walk is authoritative for the
        // writer's address space.  Gated on `d22-user-canary-phys`.
        #[cfg(feature = "d22-user-canary-phys")]
        if kind_tag == WATCH_KIND_D22_USER_CANARY_PHYS {
            crate::subsys::linux::d22_user_canary_phys::record_d22_fire(
                slot as u8, rip, cs, cr3,
            );
        }
        // F3 code-DR hook — emit the `[F3/CODE-DR-FIRE]` dump for
        // instruction-fetch fires on the musl `__stack_chk_fail+0x0`
        // user VA (PR #420 autopsy verdict).  Per Intel SDM Vol. 3B
        // §17.3.1.1 instruction breakpoints are faults taken before
        // the watched instruction retires, so `rip == watched VA` and
        // the GPRs / RSP / RBP reflect the SSP-instrumented caller's
        // frame at the moment of `__stack_chk_fail`'s call.  The
        // dump is the dispositive saga-closing evidence (names the
        // caller frame, lets a post-processor diff saved-canary vs
        // fs:0x28).  Gated on `f3-codeDR-watch`.
        #[cfg(feature = "f3-codeDR-watch")]
        if kind_tag == WATCH_KIND_F3_CODE_DR {
            crate::subsys::linux::f3_code_dr_watch::record_fire(
                slot as u8, rip, rsp, rflags, cs, cr3, gprs,
            );
        }
        crate::serial_println!(
            "[W215/DR-WATCH-FIRE/STACK] slot={} cpu={} rip={:#x} rsp={:#x}",
            slot, cpu, rip, rsp,
        );
        for i in 0..8usize {
            let p = rsp.wrapping_add((i * 8) as u64);
            if p >= 0xFFFF_8000_0000_0000 {
                let v = unsafe { core::ptr::read_volatile(p as *const u64) };
                crate::serial_println!(
                    "[W215/DR-WATCH-FIRE/STACK]   [rsp+{:#04x}] {:#018x} = {:#018x}",
                    i * 8, p, v,
                );
            } else {
                crate::serial_println!(
                    "[W215/DR-WATCH-FIRE/STACK]   [rsp+{:#04x}] {:#018x} = (user)",
                    i * 8, p,
                );
            }
        }
        consumed = true;
    }

    // Clear sticky B0..B3 regardless — leaving them set would re-trigger
    // the trap on next #DB even if the underlying slot is now disarmed.
    write_dr6(dr6 & !0xF);

    if consumed {
        // Bump publish gen so peer CPUs notice the disarm and re-program
        // (clearing the disarmed slot's enable bits in their DR7).
        // Release pairs with Acquire in `apply_pending_if_stale`.
        SYNC_GENERATION.fetch_add(1, Ordering::Release);
        // Re-program local DRs (this also clears DR7 enable bits for the
        // disarmed slots — the explicit-DR7-clear fix from PR #260 Issue 1).
        program_local_drs();
        // Refresh local-gen snapshot.
        if cpu < super::apic::MAX_CPUS {
            LOCAL_SYNC_GENERATION[cpu].store(
                SYNC_GENERATION.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
        // NOTE: no IPI broadcast — `#DB` is an ISR context (`IF=0`); see
        // module-level docs for the IPI-from-ISR deadlock that this
        // closes.  Peer CPUs disarm on their next `apply_pending_if_stale`
        // call (one timer-tick latency, ≤ 10 ms).
        true
    } else {
        // Hit bits set but no W215 slot owns them — let the generic
        // dispatcher handle the trap.
        false
    }
}

/// Return `(arm_count, fire_count)` summary for the final report.
/// `fire_count` is the sum across all four slots.
pub fn stats() -> (u32, u32) {
    let mut fires = 0u32;
    for slot in 0..N_DR_SLOTS {
        fires = fires.wrapping_add(DR_FIRE_COUNT[slot].load(Ordering::Relaxed));
    }
    (ARM_COUNT.load(Ordering::Relaxed), fires)
}

/// Per-slot fire counts, for the `[W215/ARM1/STATS]` line.
pub fn per_slot_fires() -> [u32; N_DR_SLOTS] {
    [
        DR_FIRE_COUNT[0].load(Ordering::Relaxed),
        DR_FIRE_COUNT[1].load(Ordering::Relaxed),
        DR_FIRE_COUNT[2].load(Ordering::Relaxed),
        DR_FIRE_COUNT[3].load(Ordering::Relaxed),
    ]
}

/// Back-compat: returns true if DR0 (post-hoc walker slot) is armed.
/// Used by the CRC walker to avoid re-arming over its own active capture.
pub fn is_armed() -> bool {
    ARMED[0].load(Ordering::Acquire)
}

/// Manually release `slot` if it is armed.  Idempotent — returns `true`
/// iff the slot transitioned from armed to disarmed.
///
/// Used by short-lived diagnostic windows that arm a watchpoint at the
/// start of the window and want to release it at the end if it did not
/// fire (the on-fire path is one-shot and self-releasing, see
/// `handle_db_exception`).  Mirrors that path's local-DR reprogramming
/// + lazy-gen propagation so peer CPUs notice the disarm at their next
/// `apply_pending_if_stale`.
///
/// Safe to call outside ISR context (the disarm itself is just a few
/// atomic stores + a `program_local_drs`).  Per Intel SDM Vol. 3B
/// §17.2.4, clearing L{slot}/G{slot} in DR7 suffices to silence the
/// breakpoint regardless of DR{slot} contents.
pub fn release_slot(slot: usize) -> bool {
    if slot >= N_DR_SLOTS {
        return false;
    }
    if ARMED[slot]
        .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false; // already disarmed
    }
    ARMED_ADDR[slot].store(0, Ordering::Relaxed);
    ARMED_CTRL[slot].store(0, Ordering::Relaxed);
    SYNC_GENERATION.fetch_add(1, Ordering::Release);
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    true
}

/// Outcome of a `kdb arm-phys` request.  Reported back to the kdb caller
/// verbatim as a small JSON object.
#[derive(Copy, Clone, Debug)]
pub enum ArmPhysResult {
    /// Successfully armed DR{slot} on `PHYS_OFF + phys`.
    Armed(u8),
    /// `phys` is not page-aligned (4 KiB).
    NotAligned,
    /// `phys` lies above the highest installed RAM frame.  We refuse to
    /// program a DR on a linear address that the bootloader's PHYS_OFF
    /// identity map does not cover — the watch would never fire and would
    /// instead consume a slot indefinitely.
    OutOfRange,
    /// All four DR slots are busy.  Caller should wait for an existing
    /// watch to fire (one-shot disarm releases the slot) and retry.
    PoolExhausted,
}

/// Manually arm a write-only watchpoint on `PHYS_OFF + phys + off` where
/// `phys` is the base of the containing 4 KiB physical frame and `off`
/// is a byte offset in `[0, 4096)`.  `len` must be 1, 2, 4, or 8 per
/// Intel SDM Vol. 3B §17.2.4 Table 17-2.  Used by the ELF write-trace
/// diagnostic (`subsys/linux/elf_write_trace.rs`) to watch a specific
/// 8-byte slot within an ld-musl `.data.rel.ro` page.
///
/// Slot selection: prefer DR1/DR2/DR3 (the pre-insert pool) so a manual
/// arm doesn't clobber the CRC walker's post-hoc slot (DR0).  Fall back
/// to DR0 only if all three pre-insert slots are busy.
///
/// Cross-CPU sync is the same lazy-gen protocol used by
/// `arm_write_watchpoint` / `arm_preinsert_watchpoint`: bump
/// `SYNC_GENERATION` and program our own DRs; peer CPUs pick up the
/// change in their next `apply_pending_if_stale()` (≤ one timer tick).
pub fn arm_phys_slot_watchpoint(phys: u64, off: u64, len: u8) -> ArmPhysResult {
    // Validate page alignment of the frame base.
    if phys & 0xFFF != 0 {
        return ArmPhysResult::NotAligned;
    }
    // Validate offset + length stays inside the 4 KiB frame.  Per Intel
    // SDM Vol. 3B §17.2.4 Table 17-2 the DR address may be any byte; we
    // restrict to one-frame windows so the diagnostic doesn't mis-report
    // when a write to the adjacent frame's leading bytes fires.
    if off >= 4096 || off + (len as u64) > 4096 {
        return ArmPhysResult::NotAligned;
    }
    // Width must be one of {1, 2, 4, 8}.
    match len {
        1 | 2 | 4 | 8 => {}
        _ => return ArmPhysResult::NotAligned,
    }
    // The watch address must be naturally aligned to `len` per the same
    // table; reject otherwise (a misaligned arm silently widens via the
    // Intel-defined LEN encoding and would catch unrelated writes).
    if off & (len as u64 - 1) != 0 {
        return ArmPhysResult::NotAligned;
    }
    // Validate that the frame falls inside installed RAM.
    let (total_pages, _) = crate::mm::pmm::stats();
    let ram_top = total_pages.saturating_mul(crate::mm::pmm::PAGE_SIZE as u64);
    if phys >= ram_top {
        return ArmPhysResult::OutOfRange;
    }

    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let linear = PHYS_OFF.wrapping_add(phys).wrapping_add(off);
    let inode: u64 = 0;
    let file_offset: u64 = off;

    let mut armed_slot: Option<u8> = None;
    for slot in [1usize, 2, 3, 0] {
        if try_arm_slot(slot, linear, len, phys.wrapping_add(off), inode, file_offset) {
            armed_slot = Some(slot as u8);
            break;
        }
    }
    let Some(slot) = armed_slot else {
        return ArmPhysResult::PoolExhausted;
    };

    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::serial_println!(
        "[W215/DR-ARM] slot={} linear={:#x} phys={:#x} inode={} offset={:#x} kind=slot len={}",
        slot, linear, phys.wrapping_add(off), inode, file_offset, len,
    );
    SYNC_GENERATION.fetch_add(1, Ordering::Release);
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    ArmPhysResult::Armed(slot)
}

/// Manually arm a write-only watchpoint on `PHYS_OFF + phys` from a kdb
/// command, bypassing the `cache::insert` pre-arm key filter.  Useful when
/// a corrupted phys has already been observed by the CRC walker but the
/// pre-arm path missed it (different cache key, or pool was full at insert
/// time).
///
/// `len` is fixed at 8 bytes (a single qword starting at the supplied
/// phys), per Intel SDM Vol. 3B §17.2.4 Table 17-2 — wider windows cost
/// extra slots and the diagnostic only needs to catch the first write.
///
/// Slot selection: prefer DR1/DR2/DR3 (the pre-insert pool) so a manual
/// arm doesn't clobber the CRC walker's post-hoc slot (DR0).  Fall back
/// to DR0 only if all three pre-insert slots are busy.
///
/// Cross-CPU sync is the same lazy-gen protocol used by
/// `arm_write_watchpoint` / `arm_preinsert_watchpoint`: bump
/// `SYNC_GENERATION` and program our own DRs; peer CPUs pick up the
/// change in their next `apply_pending_if_stale()` (≤ one timer tick).
pub fn arm_phys_watchpoint(phys: u64) -> ArmPhysResult {
    // Validate page alignment.  An unaligned phys would cause the watch
    // to straddle two physical frames in the PHYS_OFF map, which is not
    // what the diagnostic asks for.
    if phys & 0xFFF != 0 {
        return ArmPhysResult::NotAligned;
    }
    // Validate that the phys falls inside the installed RAM window.
    // `pmm::stats().0` is the total number of physical frames the PMM
    // knows about; the bootloader's PHYS_OFF identity map covers the
    // same window.  Linear addresses above this would fault on access.
    let (total_pages, _) = crate::mm::pmm::stats();
    let ram_top = total_pages.saturating_mul(crate::mm::pmm::PAGE_SIZE as u64);
    if phys >= ram_top {
        return ArmPhysResult::OutOfRange;
    }

    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let linear = PHYS_OFF.wrapping_add(phys);
    let len: u8 = 8;
    // inode/offset are unknown at the manual-arm site; the [W215/DR-WATCH-FIRE]
    // line still tags the slot/phys/RIP, which is what the caller actually needs.
    let inode: u64 = 0;
    let file_offset: u64 = 0;

    // Try DR1, DR2, DR3 first (manual arm should not steal DR0 from the
    // CRC walker if avoidable), then fall back to DR0.
    let mut armed_slot: Option<u8> = None;
    for slot in [1usize, 2, 3, 0] {
        if try_arm_slot(slot, linear, len, phys, inode, file_offset) {
            armed_slot = Some(slot as u8);
            break;
        }
    }
    let Some(slot) = armed_slot else {
        return ArmPhysResult::PoolExhausted;
    };

    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::serial_println!(
        "[W215/DR-ARM] slot={} linear={:#x} phys={:#x} inode={} offset={:#x} kind=manual",
        slot, linear, phys, inode, file_offset,
    );
    // Bump publish gen so peer CPUs pick up the new arm on their next
    // timer-ISR `apply_pending_if_stale` call.  Release pairs with the
    // Acquire in `apply_pending_if_stale`.
    SYNC_GENERATION.fetch_add(1, Ordering::Release);
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    ArmPhysResult::Armed(slot)
}

/// Arm a write-only watchpoint on an arbitrary linear address — the kind
/// of arm the K2b F3 diagnostic needs.  Unlike `arm_phys_watchpoint` /
/// `arm_phys_slot_watchpoint`, this does NOT translate through `PHYS_OFF`:
/// the supplied `linear_addr` is programmed directly into DR{slot}, so the
/// watchpoint fires on writes that the CPU's translation resolves to that
/// linear address regardless of which physical frame backs it at write
/// time (Intel SDM Vol. 3B §17.2.4 — DR0–DR3 store linear, not physical,
/// addresses; the breakpoint match is checked on the post-segment / pre-
/// paging linear stream).
///
/// This is the right shape for catching foreign-frame writers on a fixed
/// user VA whose backing phys may change between prologue and epilogue
/// (the F3 hypothesis): a DR armed on the user VA fires on every write
/// the CPU performs to that linear address while the owning process's
/// CR3 is loaded, including kernel-mode writes through the user-VA mapping
/// (CoW path) — but it will MISS kernel writes that bypass the user
/// mapping and hit `PHYS_OFF + phys` instead (typical direct-map
/// `write_bytes` shape).  The complementary `arm_phys_slot_watchpoint`
/// call on the current backing frame catches that channel.
///
/// `kind_tag` is propagated to the `#DB` fire-line so the post-processor
/// can route the event to the F3 consumer rather than the legacy W215
/// cache-walker path.  Use one of the `WATCH_KIND_*` constants.
///
/// Slot selection: try DR1/DR2/DR3 first (the pre-insert pool) so the
/// F3 arm does not clobber the CRC walker's post-hoc slot (DR0).  Fall
/// back to DR0 only if all three pre-insert slots are busy.
///
/// `len` must be one of {1, 2, 4, 8} and `linear_addr` must be naturally
/// aligned to `len` per Intel SDM Vol. 3B §17.2.4 Table 17-2 (the LEN
/// encoding silently widens misaligned addresses, which would catch
/// unrelated nearby writes).
///
/// Cross-CPU sync is the same lazy-gen protocol used by all other arm
/// paths: bump `SYNC_GENERATION` and program our own DRs; peer CPUs
/// pick up the change in their next `apply_pending_if_stale()` call
/// (≤ one timer tick, ≤ 10 ms at TICK_HZ=100).
pub fn arm_linear_watchpoint(
    linear_addr: u64,
    len: u8,
    kind_tag: u32,
) -> ArmPhysResult {
    match len {
        1 | 2 | 4 | 8 => {}
        _ => return ArmPhysResult::NotAligned,
    }
    if linear_addr & (len as u64 - 1) != 0 {
        return ArmPhysResult::NotAligned;
    }

    let mut armed_slot: Option<u8> = None;
    for slot in [1usize, 2, 3, 0] {
        // `phys`, `inode`, `file_offset` carried through as zero — the
        // linear-arm path does not have those keys (the watch is on a
        // virtual address, not a cache entry).  The `#DB` fire-line
        // includes `linear` regardless so the post-processor has the
        // address it actually needs.
        if try_arm_slot(slot, linear_addr, len, 0, 0, 0) {
            ARMED_KIND[slot].store(kind_tag, Ordering::Relaxed);
            armed_slot = Some(slot as u8);
            break;
        }
    }
    let Some(slot) = armed_slot else {
        return ArmPhysResult::PoolExhausted;
    };

    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::serial_println!(
        "[W215/DR-ARM] slot={} linear={:#x} phys=0 inode=0 offset=0 \
         kind=linear kind_tag={} len={}",
        slot, linear_addr, kind_tag, len,
    );
    SYNC_GENERATION.fetch_add(1, Ordering::Release);
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    ArmPhysResult::Armed(slot)
}

/// #582 — arm an 8-byte data-write watch on a switch victim's saved-RFLAGS
/// slot (`Thread::context.rsp + 0`).  Always uses DR0 (the post-hoc slot,
/// kept clear of the W215 cache pre-insert pool on DR1/DR2/DR3) so the
/// scheduler arm site never contends with a render-path arm.
///
/// Re-armable / rotating: if DR0 already carries a D582 watch, it is
/// disarmed and re-pointed at `linear_addr`, letting the scheduler move
/// the watch from one victim to the next over time without leaking the
/// slot.  If DR0 carries some *other* kind (a legacy/F3 arm), this is a
/// no-op (returns `false`) so the diagnostic never steals a slot another
/// investigation owns.
///
/// `linear_addr` must be 8-byte aligned and higher-half (a kernel-stack
/// VA); callers gate on the slot reading the healthy `0x202` first.
/// Cross-CPU propagation uses the same lazy-gen protocol as every other
/// arm path (peers re-program at their next timer-ISR
/// `apply_pending_if_stale`).  Per Intel SDM Vol. 3B §17.2.4 the watch is
/// a per-CPU data-write breakpoint; §17.3.1.1 makes the fire a trap, so
/// the fire handler reads the just-stored value through the direct map.
/// #582 — the TID whose saved-RFLAGS slot DR0's D582 watch belongs to.
/// `u64::MAX` = no D582 watch.  The scheduler disarms the watch when it
/// switches INTO this TID (the slot becomes live stack on resume, so any
/// further store to it is ordinary stack reuse, not the tear we hunt).
#[cfg(feature = "582-diag")]
static D582_WATCHED_TID: AtomicU64 = AtomicU64::new(u64::MAX);

#[cfg(feature = "582-diag")]
pub fn arm_d582_rflags_watchpoint(linear_addr: u64) -> bool {
    arm_d582_rflags_watchpoint_for(linear_addr, u64::MAX)
}

/// #582 — arm the RFLAGS-slot watch and record the owning TID so the
/// scheduler can disarm it on that TID's resume (see [`d582_disarm_if_tid`]).
#[cfg(feature = "582-diag")]
pub fn arm_d582_rflags_watchpoint_for(linear_addr: u64, owner_tid: u64) -> bool {
    const SLOT: usize = 0;
    if linear_addr < 0xFFFF_8000_0000_0000 || (linear_addr & 0x7) != 0 {
        return false;
    }
    // If DR0 is armed for a *non*-D582 kind, do not disturb it.
    if ARMED[SLOT].load(Ordering::Acquire)
        && ARMED_KIND[SLOT].load(Ordering::Relaxed) != WATCH_KIND_D582_RFLAGS
    {
        return false;
    }
    // Claim / re-point DR0.  Reset the per-slot fire count so the cap
    // applies per-victim rather than accumulating across rotations.
    ARMED[SLOT].store(true, Ordering::Release);
    ARMED_ADDR[SLOT].store(linear_addr, Ordering::Relaxed);
    ARMED_CTRL[SLOT].store(dr7_bits_for_slot(SLOT, 8), Ordering::Relaxed);
    ARMED_PHYS[SLOT].store(0, Ordering::Relaxed);
    ARMED_KEY_INODE[SLOT].store(0, Ordering::Relaxed);
    ARMED_KEY_OFFSET[SLOT].store(0, Ordering::Relaxed);
    ARMED_KIND[SLOT].store(WATCH_KIND_D582_RFLAGS, Ordering::Relaxed);
    DR_FIRE_COUNT[SLOT].store(0, Ordering::Relaxed);
    D582_WATCHED_TID.store(owner_tid, Ordering::Release);
    let n = ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    // Bounded arm-confirmation heartbeat: emit the first few arms so an
    // investigator can confirm the scheduler arm site is live and on which
    // CPU it programmed DR0.  Diagnostic-only.
    {
        static D582_ARM_LOGGED: AtomicU32 = AtomicU32::new(0);
        if D582_ARM_LOGGED.fetch_add(1, Ordering::Relaxed) < 8 {
            let cpu = super::apic::cpu_index();
            crate::serial_println!(
                "[582/ARM] slot=0 cpu={} linear={:#x} arm_count={} kind_tag={}",
                cpu, linear_addr, n, WATCH_KIND_D582_RFLAGS,
            );
        }
    }
    SYNC_GENERATION.fetch_add(1, Ordering::Release);
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    true
}

/// #582 — true if DR0 currently carries a D582 RFLAGS-slot watch (used by
/// the scheduler arm site to decide whether to rotate the watch).
#[cfg(feature = "582-diag")]
pub fn d582_is_armed() -> bool {
    ARMED[0].load(Ordering::Acquire)
        && ARMED_KIND[0].load(Ordering::Relaxed) == WATCH_KIND_D582_RFLAGS
}

/// #582 — the linear address DR0's D582 watch currently points at (0 if
/// none).  Lets the scheduler avoid re-arming on the same victim slot.
#[cfg(feature = "582-diag")]
pub fn d582_armed_addr() -> u64 {
    if d582_is_armed() {
        ARMED_ADDR[0].load(Ordering::Relaxed)
    } else {
        0
    }
}

/// #582 — the TID that owns DR0's current D582 watch (`u64::MAX` if none).
/// Read by the fire path to compare against the writing TID: writer ==
/// owner ⇒ the owner's own-stack activity; writer != owner ⇒ a foreign
/// thread stored to a parked victim's saved frame (the #582 tear).
#[cfg(feature = "582-diag")]
pub fn d582_watched_tid() -> u64 {
    D582_WATCHED_TID.load(Ordering::Acquire)
}

/// #582 — disarm DR0's D582 watch if it belongs to `tid`.  Called by the
/// scheduler just before switching INTO `tid`: on resume the watched
/// saved-RFLAGS slot becomes live stack within the resuming thread's frame,
/// so any later store to it is ordinary stack reuse (a `String::clone`
/// memcpy, a local-variable write, …), NOT the #582 tear.  Leaving the
/// watch armed across resume produced a flood of false-positive catches
/// with `tf_tear=0` at non-`switch_context_asm` RIPs.  Returns `true` if a
/// watch was disarmed.  Cheap fast-path: one atomic load + compare when no
/// D582 watch is live or the TID does not match.
#[cfg(feature = "582-diag")]
pub fn d582_disarm_if_tid(tid: u64) -> bool {
    const SLOT: usize = 0;
    if D582_WATCHED_TID.load(Ordering::Acquire) != tid {
        return false;
    }
    if !d582_is_armed() {
        D582_WATCHED_TID.store(u64::MAX, Ordering::Release);
        return false;
    }
    ARMED[SLOT].store(false, Ordering::Release);
    ARMED_ADDR[SLOT].store(0, Ordering::Relaxed);
    ARMED_CTRL[SLOT].store(0, Ordering::Relaxed);
    ARMED_KIND[SLOT].store(WATCH_KIND_LEGACY, Ordering::Relaxed);
    D582_WATCHED_TID.store(u64::MAX, Ordering::Release);
    // Publish the disarm so peer CPUs clear DR7 enable bits at their next
    // `apply_pending_if_stale` (timer-ISR top).
    SYNC_GENERATION.fetch_add(1, Ordering::Release);
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    true
}

/// Build DR7 control bits for an instruction-execute breakpoint on `slot`.
///
/// Per Intel SDM Vol. 3B §17.2.4 Table 17-2 instruction breakpoints
/// REQUIRE `R/W = 00b` (execute) and `LEN = 00b` (1-byte) — the LEN
/// field is the only encoding ignored for execute breakpoints but the
/// processor still requires it to be `00b` for compatibility.  Sets
/// L{slot} + G{slot} like the data-watch path.
fn dr7_bits_for_code_slot(slot: usize) -> u64 {
    debug_assert!(slot < N_DR_SLOTS);
    let li = 2 * slot as u64;
    let gi = li + 1;
    // R/W field = 00b (instruction execute), LEN field = 00b (1-byte).
    // Both default to 0 in the bit positions, so the per-slot ctrl word
    // is simply the L/G enables.
    (1u64 << li) | (1u64 << gi)
}

/// Arm an instruction-execute (code-fetch) watchpoint on `linear_addr`.
/// Unlike `arm_linear_watchpoint` (which arms a write-only data watch),
/// this fires when the CPU's instruction stream retires a fetch from
/// the watched linear address — i.e. when execution reaches the
/// `linear_addr`'th byte under the current CR3.
///
/// `linear_addr` should be the first byte of the target instruction
/// (Intel SDM Vol. 3B §17.2.4 — code breakpoints match the linear
/// address of the first opcode byte).  `kind_tag` is propagated to the
/// `#DB` fire-line for post-processor routing.
///
/// Slot selection: try DR1/DR2/DR3 first (the pre-insert pool) to
/// avoid clobbering the CRC walker's post-hoc slot (DR0); fall back to
/// DR0 only if all three are busy.  Cross-CPU sync uses the same
/// lazy-gen protocol as every other arm path.
///
/// Per Intel SDM Vol. 3A §6.15 the `#DB` raised by an instruction
/// breakpoint is a **fault** (taken before the watched instruction
/// retires), so the interrupt-frame `rip` equals `linear_addr`; the
/// fire handler can use that as the dispositive marker.
pub fn arm_code_watchpoint(linear_addr: u64, kind_tag: u32) -> ArmPhysResult {
    let mut armed_slot: Option<u8> = None;
    for slot in [1usize, 2, 3, 0] {
        // Use the data-watch try_arm_slot to claim the slot atomics,
        // then overwrite the control word with the code-fetch encoding
        // (RW=00, LEN=00) before the SYNC_GENERATION bump publishes
        // the slot to peer CPUs.
        if try_arm_slot(slot, linear_addr, 1, 0, 0, 0) {
            ARMED_CTRL[slot].store(dr7_bits_for_code_slot(slot), Ordering::Relaxed);
            ARMED_KIND[slot].store(kind_tag, Ordering::Relaxed);
            armed_slot = Some(slot as u8);
            break;
        }
    }
    let Some(slot) = armed_slot else {
        return ArmPhysResult::PoolExhausted;
    };

    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::serial_println!(
        "[W215/DR-ARM] slot={} linear={:#x} phys=0 inode=0 offset=0 \
         kind=code kind_tag={} len=1",
        slot, linear_addr, kind_tag,
    );
    SYNC_GENERATION.fetch_add(1, Ordering::Release);
    program_local_drs();
    let cpu = super::apic::cpu_index();
    if cpu < super::apic::MAX_CPUS {
        LOCAL_SYNC_GENERATION[cpu].store(
            SYNC_GENERATION.load(Ordering::Acquire),
            Ordering::Release,
        );
    }
    ArmPhysResult::Armed(slot)
}

/// Read the kind-tag for a slot (0..3).  Out-of-range → `WATCH_KIND_LEGACY`.
/// Used by `handle_db_exception` to tag the fire-line, and by external
/// diagnostic consumers (`subsys/linux/f3_watch.rs`) to decide whether to
/// emit follow-on lines.
pub fn slot_kind_tag(slot: usize) -> u32 {
    if slot >= N_DR_SLOTS {
        return WATCH_KIND_LEGACY;
    }
    ARMED_KIND[slot].load(Ordering::Relaxed)
}

/// Promote / demote a slot's kind tag *after* it has already been armed
/// by one of the legacy paths (`arm_phys_slot_watchpoint` etc.).  Used by
/// `subsys/linux/f3_watch.rs` to re-tag a slot it just armed via the
/// PHYS_OFF helper — without retagging, the slot would be treated as
/// `WATCH_KIND_LEGACY` and disarm one-shot on the first fire, defeating
/// the persistent-arm policy the F3 diagnostic needs.
///
/// Out-of-range slot index → no-op.  Does not change `ARMED[slot]` or
/// any address/control register state; only updates the routing tag for
/// the next `#DB` to read.
pub fn retag_slot(slot: usize, kind_tag: u32) {
    if slot >= N_DR_SLOTS {
        return;
    }
    ARMED_KIND[slot].store(kind_tag, Ordering::Relaxed);
}
