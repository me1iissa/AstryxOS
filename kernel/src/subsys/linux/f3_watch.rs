//! K2b F3 foreign-frame writer trap.
//!
//! ## What this catches
//!
//! The F3 hypothesis (per the dispositive SSP soak verdict): the libxul
//! `mozilla::widget::FireGLXTestProcess` function's prologue stores a real
//! stack canary at user VA `[rbp - 8]` (= caller's `[rsp + 0x50]`), but by
//! the time the epilogue re-reads that slot it sees a different value —
//! `0x30` — that is **byte-identical across boots with different PR-#309
//! entropy**.  The neighbour qwords at `+0x40..+0x60` form a coherent
//! foreign frame (self-referential pointer, heap pointer near TID 3 TLS,
//! small counts) — not random aliasing noise.
//!
//! Five independent SSP-DIAG captures over three master-tip increments
//! show the same fingerprint.  That determinism rules out Mode A (random
//! corruption of the saved canary by a sibling writer) and Mode B-1
//! (sysretq FS_BASE leak — falsified 2/2 by `ax_eq_fs28 = 1`).  What
//! remains is F3: between the prologue and the epilogue, the linear
//! address `[rbp - 8]` resolves to a *different physical frame* than the
//! one the prologue wrote.  The mechanism is one of:
//!
//!   * **K-CLONE-FORK**: `clone_for_fork` walks the parent's page tables
//!     and installs CoW PTEs via direct stores (`mm/vma.rs`), bypassing
//!     `map_page_in`/`write_pte`.  The new PTE points at a different phys
//!     than the parent's, but the TLB shootdown reorder leaves the
//!     parent's CPU briefly translating the VA through the new PTE.
//!   * **K-VMA-GROW**: stack-VMA grow code allocates a new phys for an
//!     extended stack range and installs the PTE via a non-bookkeeping
//!     path that doesn't go through `map_page_in`.  The VA `[rbp - 8]`
//!     was in the old stack window; the grow's PTE-install replaces it.
//!   * **K-TLB-STALE**: no kernel write happens at all — the CPU's TLB
//!     has a stale entry for the VA pointing at an older phys, while the
//!     in-memory page table now points at a new phys.  The CPU's user
//!     read goes to the stale phys; that phys's contents are foreign
//!     because the new owner has been writing through `PHYS_OFF` to the
//!     real frame.  This mode is falsified by **zero captures** on the
//!     user-VA arm: the kernel never wrote through the user VA, the only
//!     writes hit the PHYS_OFF mirror of the new owner's frame.
//!
//! ## Mechanism
//!
//! Hardware watchpoints (Intel SDM Vol. 3B §17.2.4 — DR0–DR3, DR7) trap
//! `#DB` (vector 1) on the CPU that performs a write whose linear address
//! matches a programmed slot.  DR0–DR3 hold *linear* addresses (post-
//! segment, pre-paging); on x86_64 with flat segments, that equals the
//! virtual address the instruction stream specified.  The `#DB` exception
//! frame's `rip` is the instruction *after* the write (trap-style for
//! data breakpoints; Intel SDM Vol. 3B §17.3.1.1).  Subtracting the
//! instruction's length gives the writer's instruction RIP, which
//! addr2line resolves to the kernel symbol responsible.
//!
//! We arm two slots (Intel SDM Vol. 3B §17.2.4 — DR0–DR3 are per-CPU
//! registers, propagated to peer CPUs by the lazy-gen protocol in
//! `arch/x86_64/debug_reg.rs::apply_pending_if_stale`):
//!
//!   * **DR{a} — user-VA channel** at `0x7ffffffee4c0` (the deterministic
//!     `[caller_rsp + 0x50]` slot per the SSP-DIAG-CANARY captures).
//!     Catches any write whose linear address resolves through TID 1's
//!     CR3 to this VA.  Includes user-mode writes from TID 1's libxul
//!     prologue (expected, ~once per call) plus any kernel-mode writer
//!     that explicitly uses the user-VA mapping (uncommon — kernel
//!     usually writes through `PHYS_OFF`).
//!   * **DR{b} — `PHYS_OFF + backing_phys` channel** for the current
//!     backing phys at arm time.  Catches kernel-mode direct-map writes
//!     to that specific frame from any CPU regardless of CR3.  Misses
//!     writes to a *different* phys that ends up backing the VA later
//!     (the F3 PTE-replace mechanism); the K-CLONE-FORK and K-VMA-GROW
//!     modes are expected to fire on a phys we did not arm, so this slot
//!     primarily acts as a control — a fire here would indicate K-CLONE-
//!     FORK / K-VMA-GROW happening to land on the same phys we sampled,
//!     which falsifies the "in-place corruption" framing.
//!
//! The arms are persistent (not one-shot) up to `F3_FIRE_CAP` (=32) hits
//! per slot — see `arch/x86_64/debug_reg.rs::handle_db_exception`.  The
//! prologue write is expected to fire on every call to the SSP-
//! instrumented function; the smoking-gun foreign write may come later,
//! so the diagnostic must survive multiple fires.
//!
//! ## When the arm happens
//!
//! At firefox-bin execve completion (`crate::syscall::sys_exec` immediately
//! after `switch_cr3(new_cr3)`).  At that point:
//!   * The new VmSpace is installed; the user stack VMA exists.
//!   * No user code has run yet — the libxul prologue has not stored the
//!     canary, so the first DR fire we see on the user-VA channel will
//!     be that prologue's store (`MOV [RSP+0x50], RAX` per the SSP-DIAG
//!     prologue scanner).  That's the "before" fingerprint.
//!   * Subsequent fires before the `__stack_chk_fail` trap are candidate
//!     foreign writes.
//!
//! The execve hook is gated by a path-substring match on `"firefox-bin"`
//! to avoid arming for the boot init thread, the early `--start-shell`
//! path, or any contentproc launch — all of which would consume DR slots
//! that the verifier needs for the firefox-bin TID 1.  Multiple matches
//! across a single boot are bounded by `F3_ARM_MAX`.
//!
//! ## No-fix dispatch discipline
//!
//! Per the W215 saga anti-pattern memo, this module emits diagnostic data
//! only.  It does NOT mutate page tables, allocate frames, or change any
//! lock order.  The captured fires identify the writer; a *separate*
//! coordinator-dispatched fix uses that identification to target the
//! exact path.
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4, Table 17-2 (DR0–DR3 / DR7 encoding).
//!   * Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap timing).
//!   * Intel SDM Vol. 3A §4.10 (TLB management).
//!   * System V AMD64 ABI §6.4 (SSP / `__stack_chk_guard`).
//!   * POSIX clone(2), execve(2) — process-image-replacement semantics.

#![cfg(feature = "f3-watch")]

use core::sync::atomic::{AtomicU32, Ordering};

/// Canary slot user VA — `caller_rsp + 0x50` per the dispositive SSP-DIAG
/// captures (verified 5/5 trials across master tips `61e11fe` and `22cdd86`,
/// see qa-engineer ssp_mode_a_vs_b_dispositive_2026_05_20).  The libxul
/// `mozilla::widget::FireGLXTestProcess` function's frame-size 0x58 layout
/// places the SSP-protected `[rbp - 8]` at this fixed VA when TID 1 reaches
/// the function — determinism comes from the stack-VMA bottom being fixed
/// at `0x7ffffffe0000` plus a deterministic argv/envp/auxv layout above it.
///
/// A future libxul or musl rebuild may shift the layout; the address is
/// listed in `[F3-WATCH]` log lines so a post-processor can detect drift
/// and the next dispatch can update the constant.
const CANARY_SLOT_VA: u64 = 0x0000_7fff_fffe_e4c0;

/// Maximum number of `[F3-WATCH]` arm cycles per boot.  An arm cycle
/// consists of one user-VA arm plus one `PHYS_OFF + phys` arm.  Bounded
/// so a misconfigured execve loop cannot exhaust the DR pool indefinitely.
const F3_ARM_MAX: u32 = 4;

/// Per-boot arm cycle counter.
static F3_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Substring used to gate the execve hook.  Matches both
/// `/disk/usr/lib/firefox-esr/firefox-bin` (musl) and
/// `/disk/opt/firefox/firefox-bin` (glibc).  Other binaries that happen
/// to live in a `firefox-bin` path would also match; in practice this
/// hook only fires for the headless demo execve, and `F3_ARM_MAX` bounds
/// the worst case.
const FIREFOX_BIN_SUBSTRING: &str = "firefox-bin";

/// Path-substring gate.  Case-sensitive path match — the firefox-bin path
/// is canonical lowercase, so this is intentional.
fn path_matches(path: &str) -> bool {
    path.contains(FIREFOX_BIN_SUBSTRING)
}

/// Atomically claim an arm-cycle index in the range `[0, F3_ARM_MAX)`.
/// Returns `Ok(arm_idx)` if a slot was claimed, or `Err(())` if the cap is
/// already reached.  Uses `compare_exchange` (not `fetch_add`) so a
/// refused-arm path never grows the counter past `F3_ARM_MAX` — the
/// boot-bound on log emissions is then exactly `F3_ARM_MAX` accepted arms
/// plus one `cap_reached` line.
fn claim_arm_idx() -> Result<u32, ()> {
    loop {
        let cur = F3_ARM_COUNT.load(Ordering::Relaxed);
        if cur >= F3_ARM_MAX {
            return Err(());
        }
        if F3_ARM_COUNT
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(cur);
        }
    }
}

/// Resolve the current backing phys for the canary slot VA under the
/// process's CR3.  Returns `None` if the VA is currently unmapped — which
/// is the expected case at execve time: the stack VMA exists but the
/// individual page hasn't been demand-paged yet.  In that case we arm only
/// the user-VA channel; a later `arm_after_first_fire` cycle can sample
/// the phys at the prologue fire and arm the PHYS_OFF channel then.
fn resolve_canary_phys(cr3: u64, va: u64) -> Option<u64> {
    crate::mm::vmm::virt_to_phys_in(cr3, va)
}

/// Arm both DR channels for the canary slot.  Called from `sys_exec`
/// immediately after `switch_cr3(new_cr3)` when `path_matches(final_path)`.
///
/// `cr3` should be the freshly-installed user CR3 (the call site is
/// post-`switch_cr3`).  `entry_rip` and `entry_rsp` are recorded in the
/// arm log line so a post-processor can correlate this arm with the
/// subsequent SSP-DIAG fire.
///
/// Idempotent up to `F3_ARM_MAX`: subsequent calls beyond the cap emit a
/// single `[F3-WATCH] state=cap_reached` line and bail.
pub fn arm_after_execve(final_path: &str, cr3: u64, entry_rip: u64, entry_rsp: u64) {
    if !path_matches(final_path) {
        return;
    }

    let arm_idx = match claim_arm_idx() {
        Ok(idx) => idx,
        Err(()) => {
            // First refused arm only: claim the one-shot transition
            // emission via a separate AtomicBool so the cap_reached line
            // fires exactly once even under concurrent execve races.
            use core::sync::atomic::AtomicBool;
            static CAP_REPORTED: AtomicBool = AtomicBool::new(false);
            if CAP_REPORTED
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                crate::serial_println!(
                    "[F3-WATCH] state=cap_reached arm_idx={} cap={}",
                    F3_ARM_MAX, F3_ARM_MAX,
                );
            }
            return;
        }
    };

    let pid = crate::proc::current_pid_lockless();
    let tid = crate::proc::current_tid();
    let cpu = crate::arch::x86_64::apic::cpu_index();

    use crate::arch::x86_64::debug_reg::{
        arm_linear_watchpoint, arm_phys_slot_watchpoint,
        ArmPhysResult, WATCH_KIND_F3_USER, WATCH_KIND_F3_PHYS,
    };

    // ── User-VA channel ────────────────────────────────────────────────
    let user_result = arm_linear_watchpoint(CANARY_SLOT_VA, 8, WATCH_KIND_F3_USER);
    let (user_state, user_slot) = match user_result {
        ArmPhysResult::Armed(s)        => ("armed", s as i32),
        ArmPhysResult::PoolExhausted   => ("pool_exhausted", -1),
        ArmPhysResult::NotAligned      => ("not_aligned", -1),
        ArmPhysResult::OutOfRange      => ("out_of_range", -1),
    };
    crate::serial_println!(
        "[F3-WATCH] kind=user_va arm_idx={} pid={} tid={} cpu={} cr3={:#x} \
         entry_rip={:#x} entry_rsp={:#x} canary_va={:#x} slot={} state={} \
         path=\"{}\"",
        arm_idx, pid, tid, cpu, cr3, entry_rip, entry_rsp,
        CANARY_SLOT_VA, user_slot, user_state, final_path,
    );

    // ── PHYS_OFF channel ───────────────────────────────────────────────
    // Resolve the current backing phys.  At execve time the canary VA
    // is almost certainly unmapped (stack is demand-paged); we still
    // attempt the lookup so the log line records the state, and the
    // PHYS_OFF arm is skipped when no phys is available yet.
    //
    // A follow-on arming after the first user-VA fire would catch the
    // post-prologue phys; for K2b we keep the diagnostic minimal and
    // rely on the K-TLB-STALE falsifier (zero user-VA fires) being
    // dispositive without needing the PHYS_OFF mirror.
    match resolve_canary_phys(cr3, CANARY_SLOT_VA) {
        Some(phys) => {
            let frame_phys = phys & !0xFFFu64;
            let off_in_frame = CANARY_SLOT_VA & 0xFFFu64;
            let phys_result = arm_phys_slot_watchpoint(frame_phys, off_in_frame, 8);
            let (phys_state, phys_slot) = match phys_result {
                ArmPhysResult::Armed(s)        => ("armed", s as i32),
                ArmPhysResult::PoolExhausted   => ("pool_exhausted", -1),
                ArmPhysResult::NotAligned      => ("not_aligned", -1),
                ArmPhysResult::OutOfRange      => ("out_of_range", -1),
            };
            // arm_phys_slot_watchpoint tags the slot LEGACY; promote it
            // to F3_PHYS so the post-processor knows it belongs to this
            // diagnostic and applies the persistent-arm + F3_FIRE_CAP
            // policy (otherwise the slot would self-disarm one-shot).
            if let ArmPhysResult::Armed(s) = phys_result {
                crate::arch::x86_64::debug_reg::retag_slot(
                    s as usize, WATCH_KIND_F3_PHYS);
            }
            crate::serial_println!(
                "[F3-WATCH] kind=phys_off arm_idx={} pid={} tid={} cpu={} \
                 cr3={:#x} canary_va={:#x} phys={:#x} frame_phys={:#x} \
                 off={:#x} slot={} state={}",
                arm_idx, pid, tid, cpu, cr3, CANARY_SLOT_VA, phys, frame_phys,
                off_in_frame, phys_slot, phys_state,
            );
        }
        None => {
            crate::serial_println!(
                "[F3-WATCH] kind=phys_off arm_idx={} pid={} tid={} cpu={} \
                 cr3={:#x} canary_va={:#x} state=va_unmapped \
                 note=phys_arm_skipped",
                arm_idx, pid, tid, cpu, cr3, CANARY_SLOT_VA,
            );
        }
    }
}

