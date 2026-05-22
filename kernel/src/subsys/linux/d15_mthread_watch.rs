//! D15 `RegisteredThread::mThreadInfo` slot writer trap.
//!
//! ## What this catches
//!
//! Phase 2-E ([[docs/SC1171_PHASE2_E_HEAP_REUSE_2026-05-22.md]]) confirmed
//! the sc=1171 fault at `firefox-bin + 0x207dc` reads `[r14+0x20]` with
//! `r14 = *( *(fs:-0x18) + 0x38 )` (D9 disasm).  D8 captures the OUTER
//! heap pointer `*(fs:-0x18)` (the `RegisteredThread*`) at fault time but
//! shows the INNER field — `RegisteredThread::mThreadInfo` at heap-object
//! offset `+0x38` — reads zero.  Phase 2-A established the outer heap
//! object is allocator-clean (Mozilla's ctor of `RegisteredThread` writes
//! `mThreadInfo` in init-list order, and the page is anon-mmap zero-fill
//! per POSIX `mmap(2)`).  Phase 2-E excluded page-table aliasing of the
//! outer object via the post-W215 `pte_share_count` invariant.
//!
//! What remains is: **who zeroed (or never wrote) the heap qword at
//! `*(fs:-0x18) + 0x38`** between Mozilla's `RegisteredThread` ctor and
//! the read at `firefox-bin + 0x207ce`.
//!
//! D15 arms a write-only hardware watchpoint on that exact heap VA so the
//! `#DB` trap fires on every CPU write to it, naming the writer RIP / CS /
//! CR3.  Three signature classes are expected:
//!
//!   * **D15-CTOR-ONLY** — one capture at user CPL-3 (CS=0x23) from the
//!     Mozilla `RegisteredThread::RegisteredThread` ctor, then no further
//!     writes before the sc=1171 fault.  Read-side bug: the ctor wrote
//!     a non-NULL `mThreadInfo` but the read sees zero anyway — implicates
//!     a *read-side* aliasing (the read goes to a different phys than the
//!     ctor wrote).  Cross-walks Phase 2-E's page-table-aliasing arm.
//!   * **D15-ZERO-CAPTURES** — no fire at all between arm and fault.  The
//!     ctor never wrote `mThreadInfo`, or it wrote it before the arm
//!     (which races the TLS publish — see "When the arm happens" below).
//!     Implicates a partial-ctor path (e.g. C++ exception unwound past
//!     init-list, or a sibling-thread observation of a half-published
//!     object).
//!   * **D15-LATE-WRITER** — one or more captures AFTER the ctor's write
//!     with the final captured RIP being a non-Mozilla writer (musl,
//!     kernel direct-map via PHYS_OFF would NOT fire on this VA — the
//!     watchpoint sees only user-VA writes — so a fire here is necessarily
//!     a user-mode store).  Implicates a stale-pointer overwrite from
//!     another libxul code path or a sibling thread.
//!
//! ## Mechanism
//!
//! Hardware watchpoints (Intel SDM Vol. 3B §17.2.4 — DR0–DR3, DR7) trap
//! `#DB` (vector 1) on the CPU that performs a write whose linear address
//! matches the programmed slot.  DR registers hold linear (post-segment,
//! pre-paging) addresses; on x86_64 with flat segments that equals the
//! virtual address the instruction stream specifies.  Per Intel SDM Vol.
//! 3B §17.3.1.1 data-breakpoint traps are *post*-execution: the `#DB`
//! frame's `rip` points at the instruction AFTER the writer.
//!
//! D15 arms a single linear-VA channel via the existing K2b primitive
//! `arch::x86_64::debug_reg::arm_linear_watchpoint(va, 8, kind)` (PR #356).
//! No PHYS_OFF mirror — the heap-object's backing phys is allocator-
//! controlled and not deterministic across boots; a PHYS_OFF arm on the
//! current backing would miss the case where the bug is the choice of
//! backing frame itself.  The user-VA arm catches every write through
//! the user mapping (Mozilla ctor, sibling-thread store, hypothetical
//! kernel `copy_to_user`) regardless of which phys backs the page.
//!
//! ## When the arm happens
//!
//! The challenge D15 solves: unlike D7 (PT_TLS slot at the static VA
//! `fs_base - 0x18`) and F3 (canary at the deterministic stack VA
//! `0x7ffffffee4c0`), the D15 target VA is the HEAP address that
//! `*(fs:-0x18)` POINTS AT, which is per-boot non-deterministic
//! (mallocng arenas mmap into the jittered `[0x7EFF, 0x7F00)` band per
//! F3-v2 PR #368).  Three observed values across three trials:
//!
//!     trial 1: 0x7eff71201810
//!     trial 2: 0x7eff8d681d50  (the value Phase 2-E referenced)
//!     trial 3: 0x7effdf100670
//!
//! Strategy: dispatch hook on every Linux syscall from pid=1 (firefox-bin
//! per [[project_sc1171_litmus_test_worked_2026_05_21]]).  On each call,
//! cheap-check whether the arm slot has been claimed; if not, read
//! `[fs:-0x18]` through the kernel direct map.  The very first call where
//! that qword is non-zero is the "TLS slot just got published" moment:
//! we capture the value (= the live `RegisteredThread*`), add `+0x38`, and
//! arm the linear DR on that VA.
//!
//! This necessarily MISSES the ctor's write to `mThreadInfo` (which
//! happens before the TLS publish — Mozilla writes the field in init-list
//! order, then stores the object pointer to TLS).  That trade-off is
//! intentional: we cannot predict the heap VA at boot, and arming after
//! the publish still catches every subsequent write — which is exactly
//! what's needed to identify the "zeroed by …" writer if any exists.
//! D15-ZERO-CAPTURES is then the falsifier for "a later writer zeroed
//! the field" — the field was either never written OR was written only
//! by the ctor and then misaligned by a read-side aliasing.
//!
//! ## One-shot arm semantics
//!
//! `D15_ARM_MAX = 1` — the arm slot is single-claim per boot.  After
//! arming, the DR slot persists across fires up to the existing
//! `F3_FIRE_CAP` (=32) per the `handle_db_exception` policy for non-
//! LEGACY `kind_tag` values.  An exhausted cap is logged at the 32nd
//! fire (`one_shot=1`) so a re-boot is the recovery path for a hot
//! write loop on this VA.
//!
//! ## No-fix discipline
//!
//! Per the saga-discipline rules ([[feedback_saga_diagnostic_discipline_2026_05_20]]),
//! this module emits diagnostic data only.  It does NOT mutate page
//! tables, allocate frames, change any lock order, or perform any
//! syscall-altering side effects.  All gating is in the fast path:
//! a pid != 1 syscall pays a single atomic load + branch (the
//! `D15_ARM_COUNT >= D15_ARM_MAX` check).
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7 layout).
//!   * Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap timing).
//!   * Intel SDM Vol. 3A §3.4.4.1 (`IA32_FS_BASE` MSR `0xC000_0100`).
//!   * Intel SDM Vol. 3A §4.10 (TLB management).
//!   * Mozilla `mozglue/baseprofiler/core/RegisteredThread.{h,cpp}`
//!     (searchfox).
//!   * System V AMD64 ABI §3.4.4 (TLS variant II layout).
//!   * POSIX `mmap(2)` (anonymous-mapping zero-fill on first access).

#![cfg(feature = "d15-mthread-watch")]

use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of arm cycles per boot.  Single-shot: once the inner
/// heap slot is watched, subsequent syscalls observe the saturated
/// counter and bail in the fast path.
const D15_ARM_MAX: u32 = 1;

/// Per-boot arm cycle counter.  Counts accepted arms only; refused arms
/// (precondition failed) do not bump this so the watcher keeps polling
/// until the TLS slot transitions to non-zero.
static D15_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Target pid.  Per the Linux personality's bootstrap, pid=1 is always
/// firefox-bin in the firefox-test build (see PSE Phase 1 / D7).
const D15_TARGET_PID: u64 = 1;

/// Target tid.  TID 1 is the firefox-bin init thread that hits the
/// sc=1171 fault per the byte-perfect 3/3 deterministic captures.
const D15_TARGET_TID: u64 = 1;

/// Offset of the `RegisteredThread*` from `fs_base` (the OUTER pointer).
/// Per System V AMD64 ABI §3.4.4 TLS variables live at negative offsets
/// from `%fs` (variant II).  `fs:-0x18` is the `sRegisteredThread*` TLS
/// slot per D9 disasm of `firefox-bin + 0x20771`
/// (`mov -0x18(%rbx), %rax` with `rbx = fs_base`).
const FS_TLS_OFFSET: u64 = 0x18;

/// Offset of `mThreadInfo` (`RefPtr<ThreadInfo>`, raw `ThreadInfo*`)
/// within the `RegisteredThread` heap object.  Per D9 disasm of
/// `firefox-bin + 0x207ce`: `mov 0x38(%rax), %r14` where
/// `rax = *(fs:-0x18) = RegisteredThread*`.  The fault at
/// `firefox-bin + 0x207dc` then reads `[r14+0x20]` with `r14=0`,
/// confirming `mThreadInfo` is zero at the moment of the deref.
const MTHREADINFO_OFFSET: u64 = 0x38;

/// Length of the watched access in bytes (`mThreadInfo` is a pointer).
/// DR LEN field encoding for 8 bytes is `0b10` (Intel SDM Vol. 3B
/// §17.2.4 Table 17-2), requires the watched address to be 8-aligned —
/// which holds since the outer pointer is qword-aligned by allocator
/// convention and `+0x38` preserves alignment.
const WATCH_LEN: u8 = 8;

/// Read a user qword through the kernel direct physical map.  Returns
/// `Some(value)` if the VA resolves under the current CR3, `None`
/// otherwise.  Read goes through `PHYS_OFF + phys` so it never faults
/// on a not-present user PTE.  Per Intel SDM Vol. 3A §4.6 an 8-byte
/// access straddles only when `(addr & 0xFFF) > 0x1000 - 8`; in that
/// rare case `None` is returned.  The `fs:-0x18` slot is naturally
/// 8-aligned so non-straddle is the expected case.
fn read_user_qword(addr: u64) -> Option<u64> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    if !crate::syscall::validate_user_ptr(addr, 8) { return None; }
    if (addr & 0xFFF) > 0x1000 - 8 { return None; }
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = crate::mm::vmm::virt_to_phys_in(cr3, addr)?;
    let val = unsafe {
        core::ptr::read_volatile((PHYS_OFF + phys) as *const u64)
    };
    Some(val)
}

/// Atomically claim the single arm slot.  Returns `Ok(())` on first
/// qualifying call, `Err(())` once the cap is reached.
fn claim_arm() -> Result<(), ()> {
    loop {
        let cur = D15_ARM_COUNT.load(Ordering::Relaxed);
        if cur >= D15_ARM_MAX {
            return Err(());
        }
        if D15_ARM_COUNT
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Hook called from `subsys::linux::syscall::dispatch` on every Linux
/// syscall entry.  Bails immediately for pid/tid mismatch or after the
/// arm has been claimed (fast path: one relaxed atomic load + two
/// integer compares).
///
/// On a qualifying call, reads `[fs:-0x18]` through the direct map; if
/// the qword is non-zero, captures it as the live `RegisteredThread*`
/// and arms a DR linear-VA write-only watchpoint on `that_value + 0x38`.
///
/// Subsequent fires emit `[W215/DR-WATCH-FIRE] kind_tag=4 …` lines via
/// the existing `handle_db_exception` path.
pub fn try_arm_at_syscall(pid: u64, tid: u64) {
    // Fast precondition check.  Off-path cost on every syscall from
    // pid != 1: one relaxed atomic load + branch.  D15 must not perturb
    // the firefox-test syscall throughput when the arm is already
    // claimed.
    if pid != D15_TARGET_PID || tid != D15_TARGET_TID {
        return;
    }
    if D15_ARM_COUNT.load(Ordering::Relaxed) >= D15_ARM_MAX {
        return;
    }

    // Read FS.base via the WRMSR-shadow MSR (Intel SDM Vol. 3A §3.4.4.1).
    const IA32_FS_BASE: u32 = 0xC000_0100;
    let fs_base = unsafe { crate::hal::rdmsr(IA32_FS_BASE) };
    if fs_base < FS_TLS_OFFSET {
        // Underflow guard — defence-in-depth; not expected for a real
        // musl TLS layout.
        return;
    }
    let tls_va = fs_base - FS_TLS_OFFSET;

    // Read the TLS slot through the direct map.  Returns None if the
    // page isn't present yet (very early in process lifetime); we just
    // retry on the next syscall in that case.
    let tls_val = match read_user_qword(tls_va) {
        Some(v) => v,
        None    => return,
    };
    if tls_val == 0 {
        // `sRegisteredThread` not yet published.  Retry on next syscall.
        return;
    }

    // Compute the inner-field VA and validate alignment.  Per Intel
    // SDM Vol. 3B §17.2.4 the LEN encoding silently masks misaligned
    // addresses, which would catch unrelated nearby writes — refuse
    // the arm with a trace if the heap pointer is not qword-aligned.
    let watch_va = tls_val.wrapping_add(MTHREADINFO_OFFSET);
    if watch_va & (WATCH_LEN as u64 - 1) != 0 {
        crate::serial_println!(
            "[D15/MTHRD-ARM] state=refused_misaligned pid={} tid={} \
             tls_val={:#x} watch_va={:#x} len={}",
            pid, tid, tls_val, watch_va, WATCH_LEN,
        );
        return;
    }

    // Claim the single arm slot.  After this point any concurrent caller
    // sees the saturated counter and bails at the fast-path check; we are
    // the unique arming context.
    if claim_arm().is_err() {
        return;
    }

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let cr3 = crate::mm::vmm::get_cr3();
    let watch_phys = crate::mm::vmm::virt_to_phys_in(cr3, watch_va);

    use crate::arch::x86_64::debug_reg::{
        arm_linear_watchpoint, ArmPhysResult, WATCH_KIND_D15_MTHRD,
    };

    let result = arm_linear_watchpoint(watch_va, WATCH_LEN, WATCH_KIND_D15_MTHRD);
    let (state, slot) = match result {
        ArmPhysResult::Armed(s)      => ("armed", s as i32),
        ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
        ArmPhysResult::NotAligned    => ("not_aligned", -1),
        ArmPhysResult::OutOfRange    => ("out_of_range", -1),
    };

    // Read the current value at the watched VA so a post-processor can
    // see whether `mThreadInfo` is already zero at arm time (likely)
    // or non-zero (would suggest the ctor wrote it before the TLS
    // publish and a later writer zeroed it after this arm).
    let mthread_val = read_user_qword(watch_va);

    match (mthread_val, watch_phys) {
        (Some(v), Some(p)) => crate::serial_println!(
            "[D15/MTHRD-ARM] state={} pid={} tid={} cpu={} fs_base={:#x} \
             tls_val={:#x} watch_va={:#x} watch_phys={:#x} mthread_val={:#x} \
             len={} slot={} kind_tag={}",
            state, pid, tid, cpu, fs_base, tls_val, watch_va, p, v,
            WATCH_LEN, slot, WATCH_KIND_D15_MTHRD,
        ),
        (Some(v), None) => crate::serial_println!(
            "[D15/MTHRD-ARM] state={} pid={} tid={} cpu={} fs_base={:#x} \
             tls_val={:#x} watch_va={:#x} watch_phys=? mthread_val={:#x} \
             len={} slot={} kind_tag={}",
            state, pid, tid, cpu, fs_base, tls_val, watch_va, v,
            WATCH_LEN, slot, WATCH_KIND_D15_MTHRD,
        ),
        (None, _) => crate::serial_println!(
            "[D15/MTHRD-ARM] state={} pid={} tid={} cpu={} fs_base={:#x} \
             tls_val={:#x} watch_va={:#x} watch_phys=? mthread_val=? \
             len={} slot={} kind_tag={}",
            state, pid, tid, cpu, fs_base, tls_val, watch_va,
            WATCH_LEN, slot, WATCH_KIND_D15_MTHRD,
        ),
    }
}
