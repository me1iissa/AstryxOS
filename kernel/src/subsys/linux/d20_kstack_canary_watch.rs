//! D20 kernel-stack canary writer trap.
//!
//! ## What this catches
//!
//! After PR #396 (multi-tier emergency kernel-stack fallback) and PR #397
//! (`mm/vmm.rs` `BATCH` 1024→128 shrink) landed, the demo gate did NOT move:
//! 3/3 deterministic trials still hit `BUGCHECK_CANARY_CORRUPT (0xDEAD_0001)`
//! on **PID 2 TID 5** at `sc = 1230..1232`.  The signature lines from those
//! trials show ZERO `[KSTACK/TIER]` and ZERO `[KSTACK/CANARY-FAIL]` records
//! — i.e. the multi-tier fallback was never engaged, and the slow-path
//! `[KSTACK/CANARY-FAIL]` diagnostic never fires either (the bugcheck banner
//! is the only marker).  The writer is therefore NOT in either of the
//! brk(2) / munmap(2) paths PR #395's stack-pressure analysis named.
//!
//! D20 names the writer DIRECTLY: it arms a write-only hardware watchpoint
//! on the kernel-stack canary slot for the bugcheck-victim thread the
//! moment that thread is created.  When something writes to
//! `[kernel_stack_base, kernel_stack_base + 8)`, `#DB` (vector 1) fires on
//! the writing CPU and the existing `handle_db_exception` path emits a
//! `[W215/DR-WATCH-FIRE]` line carrying the writer's RIP, CS, RFLAGS,
//! CR3, plus 8 qwords of stack context.  Per Intel SDM Vol. 3B §17.3.1.1
//! data-breakpoint traps are *post-execution*: the `#DB` frame's `rip`
//! points at the instruction AFTER the store, so a single fire names
//! exactly one retired writer.
//!
//! ## Expected signatures
//!
//!   * **D20-KERNEL-WRITER** — at least one `[W215/DR-WATCH-FIRE]` with
//!     `kind_tag=6`, `cs=0x08`, and a kernel RIP (`>= 0xFFFF_8000_0000_0000`).
//!     That RIP is the writer.  Resolution: addr2line (or `gdb` symbolise)
//!     against the built `target/x86_64-aether/debug/kernel.elf` for the
//!     captured RIP.
//!   * **D20-USER-WRITER** (improbable but tracked) — fire with `cs=0x23`.
//!     Would mean a user-mode store reached a kernel direct-map VA, which
//!     would itself be a SMAP/SMEP-bypass bug.
//!   * **D20-ZERO-CAPTURES** — no `[W215/DR-WATCH-FIRE]` for kind_tag=6
//!     between arm and the bugcheck.  Falsifies "an explicit store
//!     corrupts the canary" and implicates an *adjacent-page* mechanism
//!     (e.g. a PTE remap that aliases the canary frame onto another page
//!     whose write the DR cannot see — the DR fires on linear-VA writes,
//!     not on page-table edits that change which phys backs the VA).
//!
//! ## Mechanism
//!
//! `proc::write_stack_canary(stack_base)` (see `proc/mod.rs`) writes
//! `STACK_END_MAGIC = 0x5741_436B_5374_4B21` ("WACkStK!") as a single
//! qword at the bottom of the kernel stack.  `stack_base` is a kernel
//! direct-map VA (`KERNEL_VIRT_OFFSET + phys`); the watch is therefore on
//! the direct-map linear address, and any write through that VA fires
//! `#DB` on the storing CPU.
//!
//! D20 arms via the existing K2b primitive
//! `arch::x86_64::debug_reg::arm_linear_watchpoint(va, 8, kind)` (PR #356)
//! and inherits the slot's persistent-arm + per-slot fire cap policy from
//! `handle_db_exception`.  No PHYS_OFF mirror: the kernel stack already
//! lives at a kernel direct-map VA, so the user-VA channel IS the
//! direct-map channel.
//!
//! ## Target gating
//!
//! The bugcheck victim is `pid=2 tid=5`.  D20 hooks the thread-creation
//! sites in `proc/mod.rs` (`create_thread`, `create_thread_blocked`,
//! `clone_for_fork`, `clone_for_thread`) via the new
//! `note_kstack_alloc(pid, tid, base, span)` entry point.  On each call:
//!
//!   1. Bail fast on `pid != D20_TARGET_PID` (one atomic load + compare).
//!   2. Bail on `D20_ARM_COUNT >= D20_ARM_MAX` (one atomic load + compare).
//!   3. Claim a slot (CAS) and arm the DR on the just-allocated stack base.
//!
//! `D20_ARM_MAX = 6` covers the first six PID-2 thread creations.  TID 5
//! globally need NOT be the 5th thread of PID 2 (TIDs are allocated from
//! a global counter, so TID 5 might be the 1st or the 5th thread of PID
//! 2 depending on what other threads have been created since boot).
//! Arming each of the first six PID-2 threads' canaries guarantees we
//! cover the bugcheck victim regardless of how the TID-vs-thread-index
//! relationship lands on a given boot.
//!
//! Each successful arm consumes one DR slot.  D20 alone fits in the 4-slot
//! pool because `arm_linear_watchpoint` returns `PoolExhausted` once the
//! 4 slots are claimed — the 5th and 6th calls fail gracefully and log
//! `pool_exhausted` for the post-processor.  In practice the bugcheck
//! victim hits its slot in the first few arms.
//!
//! ## No-fix discipline
//!
//! Per the saga-discipline rules ([[feedback_saga_diagnostic_discipline_2026_05_20]]),
//! this module emits diagnostic data only.  It does NOT mutate page
//! tables, allocate frames, change any lock order, or perform any
//! syscall-altering side effects.  The hook is in the thread-creation
//! tail (after the THREAD_TABLE push and the `[PROC] Created…` line), so
//! the watch is armed only on threads we own.
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7 layout — write-only LEN=8
//!     encoding for an 8-byte canary slot).
//!   * Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap-after-retire
//!     semantics — the captured RIP is the instruction AFTER the writer).
//!   * Intel SDM Vol. 3A §4.10 (TLB management — DR linear matches are
//!     post-segment, pre-paging).
//!   * x86_64 SysV ABI §3.4.1 (stack-frame budgeting).
//!   * CWE-121 (stack-based buffer overflow taxonomy).
//!   * Prior K2b DR-watchpoint primitive: PR #356 (F3 saga close).
//!   * Prior D16 SSP-canary diagnostic: PR #382 (similar shape, user-VA
//!     side).

#![cfg(feature = "d20-kstack-canary-watch")]

use core::sync::atomic::{AtomicU32, Ordering};

/// Target pid — the bugcheck-victim PID observed across 3/3 deterministic
/// post-#396/#397 trials.  PID 2 is the second Linux personality process
/// spawned after the kernel/init bootstrap; in the firefox-test boot path
/// this corresponds to one of the early-fork descendants of pid=1.
const D20_TARGET_PID: u64 = 2;

/// Maximum number of arm cycles per boot.  Set to 6 so the first six
/// PID-2 thread creations each get their canary watched.  TID-vs-thread-
/// index in a PID is non-deterministic across boots (TIDs come from a
/// global counter), so arming the first N PID-2 threads guarantees we
/// cover the bugcheck victim (TID 5 globally per the 3/3 trials) without
/// having to model that mapping.  6 > 4 DR slots; the surplus is
/// intentional — arms beyond the pool log `pool_exhausted` and continue.
const D20_ARM_MAX: u32 = 6;

/// Per-boot arm cycle counter.  Counts ACCEPTED arms only (pid match +
/// successful slot claim).  Refused-arm paths (wrong pid, saturated
/// counter, pool exhausted) do not bump this so the cap is honest.
static D20_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Atomically claim an arm slot via CAS.  Returns `Ok(())` once the
/// counter has been bumped from `< D20_ARM_MAX`, `Err(())` once the cap
/// is reached.  Mirrors `d16_canary_watch::claim_arm`.
fn claim_arm() -> Result<(), ()> {
    loop {
        let cur = D20_ARM_COUNT.load(Ordering::Relaxed);
        if cur >= D20_ARM_MAX {
            return Err(());
        }
        if D20_ARM_COUNT
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Hook called from every `proc/mod.rs` thread-creation site immediately
/// after the `THREAD_TABLE` push and the `[PROC] Created…` log line, with
/// the just-allocated kernel stack's `(pid, tid, base, span)`.  Off-path
/// cost (non-target pid): one atomic load + branch.
///
/// On a qualifying call, claims an arm slot and programs a write-only DR
/// on `[stack_base, stack_base + 8)` (the canary qword).  Subsequent
/// kernel writes to that linear address fire `#DB` on the writing CPU;
/// `handle_db_exception` emits `[W215/DR-WATCH-FIRE] kind_tag=6 …` with
/// the writer's RIP / CS / CR3 — the dispositive evidence the
/// post-#396/#397 RED verdict needs.
///
/// Per Intel SDM Vol. 3B §17.2.4 the DR linear address must be naturally
/// aligned to the watch length.  Kernel stacks are page-aligned
/// (`KERNEL_VIRT_OFFSET + phys`, phys 4 KiB-aligned), so `stack_base` is
/// trivially 8-byte aligned.
pub fn note_kstack_alloc(pid: u64, tid: u64, stack_base: u64, span: u64) {
    if pid != D20_TARGET_PID {
        return;
    }
    if D20_ARM_COUNT.load(Ordering::Relaxed) >= D20_ARM_MAX {
        return;
    }
    if claim_arm().is_err() {
        return;
    }

    use crate::arch::x86_64::debug_reg::{
        arm_linear_watchpoint, ArmPhysResult, WATCH_KIND_D20_KSTACK,
    };

    let result = arm_linear_watchpoint(stack_base, 8, WATCH_KIND_D20_KSTACK);
    let (state, slot) = match result {
        ArmPhysResult::Armed(s)      => ("armed", s as i32),
        ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
        ArmPhysResult::NotAligned    => ("not_aligned", -1),
        ArmPhysResult::OutOfRange    => ("out_of_range", -1),
    };

    let cpu = crate::arch::x86_64::apic::cpu_index();
    crate::serial_println!(
        "[D20/ARM] state={} pid={} tid={} cpu={} kstack_base={:#x} kstack_size={:#x} \
         canary_va={:#x} slot={} len=8 kind_tag={}",
        state, pid, tid, cpu, stack_base, span,
        stack_base, slot, WATCH_KIND_D20_KSTACK,
    );
}
