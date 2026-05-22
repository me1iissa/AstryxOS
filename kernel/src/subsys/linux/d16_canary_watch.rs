//! D16 SSP-canary saved-slot writer trap.
//!
//! ## What this catches
//!
//! Post-F3-saga-closure (PR #368 `mmap_hint MAP_FIXED` gate) the
//! `sc=1170/1171` plateau shifted to a new gate: 3/3 deterministic trials
//! land in musl's `__stack_chk_fail` at `ld-musl-x86_64.so.1 + 0x87f9`
//! (`sc = 1230..1232`).  The saved canary qword on stack reads `0x30` in
//! the low byte while the master canary at `fs:0x28` is unchanged — this
//! is the F3 SSP fingerprint reappearing at a different RIP.
//!
//! Critical observation across 3 boots:
//!
//!   * **Canary slot VA = `0x7ffffffee4c0`** (the same `[caller_rsp + 0x50]`
//!     slot the F3 saga tracked, per the SSP-DIAG-CANARY captures).
//!   * **Canary slot backing phys = `0x127114c0`** — *deterministic across
//!     all 3 trials*.  PR #368's per-process jitter affects mmap-hint
//!     placement but the initial-stack frame for `pid=1` lands on the
//!     same PMM-allocated phys each boot.
//!
//! Deterministic phys is the killer feature: it lets us arm a DR write-
//! only watchpoint on `PHYS_OFF + 0x127114c0` (the kernel direct-map
//! linear address that aliases the same frame, Intel SDM Vol. 3A §4.10
//! and the AstryxOS PHYS_OFF identity-map invariant).  That arm catches
//! kernel-mode writers to the backing frame from any CPU regardless of
//! CR3 — including writes that bypass the user-VA mapping entirely (the
//! K-TLB-STALE / K-DIRECT-MAP modes the F3 user-VA arm cannot see).
//!
//! ## Mechanism
//!
//! Hardware watchpoints (Intel SDM Vol. 3B §17.2.4 — DR0–DR3, DR7) trap
//! `#DB` (vector 1) on the CPU that performs a write whose linear address
//! matches a programmed slot.  Per Intel SDM Vol. 3B §17.3.1.1 the `#DB`
//! is taken AFTER the offending store retires; the interrupt frame's
//! `rip` points at the instruction after the writer.
//!
//! D16 arms two channels via the existing K2b primitives (PR #356):
//!
//!   * **PHYS_OFF channel** — `arm_phys_slot_watchpoint(0x127114c0, 0x4c0,
//!     8)`.  Fires on any CPU's kernel-mode write whose linear address
//!     resolves to `PHYS_OFF + 0x127114c0`.  This is the deterministic-
//!     phys anchor; it is armed eagerly at firefox-bin execve completion
//!     without waiting for the user stack page to be demand-paged.  Per
//!     Intel SDM Vol. 3B §17.2.4 the linear address in DR{slot} is
//!     compared against post-segment, pre-paging linear addresses, so a
//!     kernel `write_bytes` through `PHYS_OFF + phys` trips this channel.
//!   * **User-VA channel** — `arm_linear_watchpoint(0x7ffffffee4c0, 8,
//!     WATCH_KIND_D16_CANARY)`.  Fires on writes the CPU resolves through
//!     firefox-bin's CR3 to that user VA.  Includes user-mode prologue
//!     stores from libxul / musl (expected, the F3 saga showed these
//!     fire on every entry to the SSP-instrumented function) plus any
//!     kernel writer that takes the user-VA route (uncommon).  Late-
//!     armed from the syscall-entry hook — see "When the arm happens".
//!
//! Both slots are tagged `WATCH_KIND_D16_CANARY`, which inherits the
//! persistent-arm + `F3_FIRE_CAP`=32 policy from the
//! `handle_db_exception` dispatcher.  A user-mode prologue write loop
//! cannot flood the serial log beyond the per-slot cap.
//!
//! ## Expected signatures
//!
//!   * **D16-CTOR-ONLY** — one or more user-mode (`CS = 0x23`) fires from
//!     the libxul / musl SSP prologue at the start of the function, then
//!     no kernel-mode (`CS = 0x08`) fires before the `__stack_chk_fail`
//!     trap.  Implicates the read-side: the prologue wrote a correct
//!     canary, but the epilogue's read goes to a phys that has a
//!     different value (page-table aliasing or TLB stale).
//!   * **D16-KERNEL-WRITER** — at least one `CS = 0x08` fire on the
//!     PHYS_OFF channel with a kernel RIP.  Names the kernel direct-map
//!     writer responsible for the `0x30` corruption.  Resolution: addr2line
//!     against the kernel ELF on the captured RIP.
//!   * **D16-FOREIGN-USER-WRITER** — a `CS = 0x23` fire from a non-TID-1
//!     thread (sibling-thread write through the same user-VA mapping
//!     after a clone(2) shared-VM).  Less likely but cross-walks the
//!     "shared stack page" hypothesis.
//!   * **D16-ZERO-CAPTURES** — no fires at all.  Falsifies "a writer
//!     corrupts the slot between prologue and epilogue" and implicates
//!     the read-side aliasing arm (the prologue's correct write goes to
//!     a different phys than the epilogue's read).  Phys arm is meant
//!     to rule out the "kernel direct-map writer" arm — if PHYS_OFF
//!     channel sees nothing, the corruption is not a kernel store.
//!
//! ## When the arm happens
//!
//! The PHYS_OFF channel arms **at firefox-bin execve completion**
//! (`crate::syscall::sys_exec` immediately after `switch_cr3(new_cr3)`),
//! gated by `path_matches(final_path)` against the firefox-bin substring.
//! At that point:
//!
//!   * The new VmSpace is installed.
//!   * No user code has run yet — the libxul SSP prologue has not stored
//!     the canary, so the first PHYS_OFF fire would be the prologue.
//!   * The deterministic phys `0x127114c0` is the expected backing for
//!     the canary slot.  The arm logs the captured phys so a post-
//!     processor can detect drift (a future PMM placement change might
//!     shift this; the constant should then be updated).
//!
//! The user-VA channel arms **lazily from the Linux syscall-entry hook**
//! — same shape as D15.  On each call from `pid=1 / tid=1` the hook
//! reads the canary VA through the kernel direct map; the first non-
//! zero read claims the single arm slot and arms the user-VA DR.  This
//! necessarily MISSES the first user-mode prologue write (which happens
//! before any syscall).  The PHYS_OFF channel covers that gap: it is
//! armed eagerly and will catch the prologue write through the direct
//! map.
//!
//! Both channels are bounded by `D16_ARM_MAX` for the user-VA latch
//! plus the `F3_FIRE_CAP` per-slot fire bound.
//!
//! ## No-fix discipline
//!
//! Per the saga-discipline rules (Rule 4 — "framing IS the bug" — and
//! Rule 1 — "phys-provenance FIRST"), this module emits diagnostic data
//! only.  It does NOT mutate page tables, allocate frames, change any
//! lock order, or perform any syscall-altering side effects.  All gating
//! is in the fast path: a `pid != 1` syscall pays a single atomic load +
//! branch (the `D16_USER_ARM_COUNT >= D16_ARM_MAX` check).
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7 layout, R/W/LEN encoding).
//!   * Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap timing).
//!   * Intel SDM Vol. 3A §4.10 (TLB management / page-table coherence).
//!   * Intel SDM Vol. 3A §3.4.4.1 (`IA32_FS_BASE` MSR `0xC000_0100`).
//!   * System V AMD64 ABI §3.4.1 (SSP / `__stack_chk_guard` model).
//!   * POSIX `execve(2)` (process-image replacement semantics).
//!   * CWE-121 (stack-based buffer overflow).
//!   * CWE-587 (assignment of a fixed address to a pointer — for the
//!     canary-corruption taxonomy).
//!   * musl libc `src/env/__stack_chk_fail.c` (the `0x87f9` site).

#![cfg(feature = "d16-canary-watch")]

use core::sync::atomic::{AtomicU32, Ordering};

/// Saved-canary slot user VA.  Per the dispositive F3-saga SSP-DIAG
/// captures the libxul SSP-instrumented function places `[rbp - 8]` /
/// `[caller_rsp + 0x50]` at this fixed VA on TID 1.  Determinism comes
/// from the initial-stack VMA being fixed at `0x7ffffffe0000` plus a
/// deterministic argv/envp/auxv layout above it.  See also
/// `f3_watch::CANARY_SLOT_VA`.
const CANARY_SLOT_VA: u64 = 0x0000_7fff_fffe_e4c0;

/// Deterministic backing physical frame for the canary slot, observed
/// byte-perfect across 3 KVM trials post-PR #368.  This is the killer
/// anchor for D16 — even if the user-VA mapping is not yet established
/// at execve time (demand-paged stack), the PHYS_OFF arm can target this
/// frame directly.  Phys is page-aligned (`& !0xFFF == 0x12711000`); the
/// canary qword lives at offset `0x4c0` within the frame.
///
/// If a future PMM allocation policy change shifts this, the `[D16/ARM]`
/// log line records the captured phys at arm time so a post-processor
/// can detect drift and the next dispatch can update the constant.
const CANARY_SLOT_PHYS: u64 = 0x1271_1000;
const CANARY_SLOT_PHYS_OFF: u64 = 0x4c0;

/// Length of the watched access in bytes — the canary is a single qword.
/// DR LEN field encoding for 8 bytes is `0b10` (Intel SDM Vol. 3B
/// §17.2.4 Table 17-2), requires natural 8-byte alignment which both
/// `CANARY_SLOT_VA` (`...e4c0`) and `CANARY_SLOT_PHYS + offset`
/// (`...14c0`) satisfy.
const WATCH_LEN: u8 = 8;

/// Substring used to gate the execve hook.  Matches both musl
/// (`/disk/usr/lib/firefox-esr/firefox-bin`) and glibc
/// (`/disk/opt/firefox/firefox-bin`).  Same shape as `f3_watch`.
const FIREFOX_BIN_SUBSTRING: &str = "firefox-bin";

/// Maximum number of user-VA arm cycles per boot.  Bounded so a
/// misconfigured execve loop or a repeated syscall-entry path cannot
/// exhaust the DR pool indefinitely.  PHYS_OFF channel has its own
/// `D16_PHYS_ARM_COUNT` cap.
const D16_ARM_MAX: u32 = 1;

/// Per-boot user-VA arm cycle counter (claimed by the syscall-entry
/// hook on first qualifying `pid=1 / tid=1` call where the canary VA
/// reads non-zero).
static D16_USER_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Per-boot PHYS_OFF arm cycle counter (claimed by the execve hook).
static D16_PHYS_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Target pid — per the Linux personality bootstrap, pid=1 is firefox-bin
/// in the `firefox-test` build (see PSE Phase 1 / D7 / D15).
const D16_TARGET_PID: u64 = 1;

/// Target tid — TID 1 is the firefox-bin init thread that hits the
/// `__stack_chk_fail` site per the byte-perfect 3/3 deterministic captures.
const D16_TARGET_TID: u64 = 1;

/// Path-substring gate.  Case-sensitive: the firefox-bin path is
/// canonical lowercase.
fn path_matches(path: &str) -> bool {
    path.contains(FIREFOX_BIN_SUBSTRING)
}

/// Read a user qword through the kernel direct physical map.  Returns
/// `Some(value)` if the VA resolves under the current CR3, `None`
/// otherwise.  Read goes through `PHYS_OFF + phys` so it never faults
/// on a not-present user PTE.  Per Intel SDM Vol. 3A §4.6 an 8-byte
/// access straddles only when `(addr & 0xFFF) > 0x1000 - 8`; in that
/// rare case `None` is returned.  `CANARY_SLOT_VA` is qword-aligned
/// (`...e4c0`) so non-straddle is the expected case.
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

/// Atomically claim a counter slot via CAS.  Returns `Ok(())` if the
/// counter was below `D16_ARM_MAX` and is now incremented; `Err(())`
/// once the cap is reached.  Refused-arm paths do NOT bump the counter.
fn claim_arm(counter: &AtomicU32) -> Result<(), ()> {
    loop {
        let cur = counter.load(Ordering::Relaxed);
        if cur >= D16_ARM_MAX {
            return Err(());
        }
        if counter
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Arm the PHYS_OFF channel at execve completion.  Called from
/// `crate::syscall::sys_exec` immediately after `switch_cr3(new_cr3)`
/// (mirroring the `f3_watch::arm_after_execve` hook site).  Path-gated
/// on the firefox-bin substring.
///
/// The PHYS_OFF arm targets the deterministic backing frame
/// `CANARY_SLOT_PHYS + CANARY_SLOT_PHYS_OFF = 0x127114c0`.  Per Intel
/// SDM Vol. 3B §17.2.4 the DR{slot} comparison is on linear addresses;
/// the kernel direct-map invariant gives us linear == `PHYS_OFF + phys`
/// for any frame, so a write through the direct map to this frame fires
/// the trap on the writer CPU.
///
/// The arm logs the captured `(cr3, current backing phys for
/// CANARY_SLOT_VA)` so a post-processor can verify the deterministic
/// phys hypothesis still holds; a drift would surface as
/// `current_phys != 0x127114c0` in the log line.
pub fn arm_after_execve(final_path: &str, cr3: u64, entry_rip: u64, entry_rsp: u64) {
    if !path_matches(final_path) {
        return;
    }
    if claim_arm(&D16_PHYS_ARM_COUNT).is_err() {
        return;
    }

    let pid = crate::proc::current_pid_lockless();
    let tid = crate::proc::current_tid();
    let cpu = crate::arch::x86_64::apic::cpu_index();

    // For diagnostic correlation: try to resolve the canary VA's current
    // backing phys.  At execve time the stack page is usually unmapped
    // (demand-paging), in which case this returns None — that's fine,
    // the PHYS_OFF arm proceeds against the hard-coded deterministic
    // phys regardless.
    let current_phys = crate::mm::vmm::virt_to_phys_in(cr3, CANARY_SLOT_VA);

    use crate::arch::x86_64::debug_reg::{
        arm_phys_slot_watchpoint, retag_slot,
        ArmPhysResult, WATCH_KIND_D16_CANARY,
    };

    let result = arm_phys_slot_watchpoint(
        CANARY_SLOT_PHYS, CANARY_SLOT_PHYS_OFF, WATCH_LEN,
    );
    let (state, slot) = match result {
        ArmPhysResult::Armed(s)      => ("armed", s as i32),
        ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
        ArmPhysResult::NotAligned    => ("not_aligned", -1),
        ArmPhysResult::OutOfRange    => ("out_of_range", -1),
    };
    // arm_phys_slot_watchpoint tags the slot LEGACY; promote it to
    // D16_CANARY so the post-processor applies the persistent-arm +
    // F3_FIRE_CAP policy (otherwise the slot would self-disarm one-shot
    // on the first prologue write).
    if let ArmPhysResult::Armed(s) = result {
        retag_slot(s as usize, WATCH_KIND_D16_CANARY);
    }

    match current_phys {
        Some(p) => crate::serial_println!(
            "[D16/ARM] channel=phys_off state={} pid={} tid={} cpu={} cr3={:#x} \
             entry_rip={:#x} entry_rsp={:#x} canary_va={:#x} \
             canary_phys_target={:#x} canary_phys_current={:#x} \
             slot={} len={} kind_tag={} path=\"{}\"",
            state, pid, tid, cpu, cr3, entry_rip, entry_rsp,
            CANARY_SLOT_VA,
            CANARY_SLOT_PHYS.wrapping_add(CANARY_SLOT_PHYS_OFF),
            p, slot, WATCH_LEN, WATCH_KIND_D16_CANARY, final_path,
        ),
        None => crate::serial_println!(
            "[D16/ARM] channel=phys_off state={} pid={} tid={} cpu={} cr3={:#x} \
             entry_rip={:#x} entry_rsp={:#x} canary_va={:#x} \
             canary_phys_target={:#x} canary_phys_current=unmapped \
             slot={} len={} kind_tag={} path=\"{}\"",
            state, pid, tid, cpu, cr3, entry_rip, entry_rsp,
            CANARY_SLOT_VA,
            CANARY_SLOT_PHYS.wrapping_add(CANARY_SLOT_PHYS_OFF),
            slot, WATCH_LEN, WATCH_KIND_D16_CANARY, final_path,
        ),
    }
}

/// Hook called from `subsys::linux::syscall::dispatch` on every Linux
/// syscall entry.  Bails immediately for pid/tid mismatch or after the
/// user-VA arm has been claimed (fast path: one atomic load + two
/// integer compares).
///
/// On a qualifying call where the canary slot reads non-zero (i.e. the
/// libxul SSP prologue has already published its canary), claims the
/// arm slot and programs a write-only DR on the user VA.  Subsequent
/// writes from any code path that resolves through the firefox-bin
/// CR3 to `CANARY_SLOT_VA` emit `[W215/DR-WATCH-FIRE] kind_tag=5 …`
/// via the existing `handle_db_exception` path.
///
/// This necessarily MISSES the prologue's initial store (which fires
/// before any syscall on this thread).  The PHYS_OFF arm
/// (`arm_after_execve`) covers that gap.
pub fn try_arm_at_syscall(pid: u64, tid: u64) {
    // Fast precondition check — keep the hot path cheap.  Off-path cost
    // on every syscall from non-target pid: one relaxed atomic load +
    // branch.
    if pid != D16_TARGET_PID || tid != D16_TARGET_TID {
        return;
    }
    if D16_USER_ARM_COUNT.load(Ordering::Relaxed) >= D16_ARM_MAX {
        return;
    }

    // Read the canary slot via the direct map.  None means the page is
    // not yet present — retry on the next syscall.
    let canary_val = match read_user_qword(CANARY_SLOT_VA) {
        Some(v) => v,
        None    => return,
    };
    if canary_val == 0 {
        // SSP prologue hasn't published yet (or this isn't the SSP-
        // instrumented function on the call stack yet).  Retry next
        // syscall.  The canary is randomised at process start so any
        // non-zero value is acceptable as a "published" signal.
        return;
    }

    // Claim the single arm slot.  After this point any concurrent caller
    // sees the saturated counter and bails at the fast-path check.
    if claim_arm(&D16_USER_ARM_COUNT).is_err() {
        return;
    }

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let cr3 = crate::mm::vmm::get_cr3();
    let backing_phys = crate::mm::vmm::virt_to_phys_in(cr3, CANARY_SLOT_VA);

    use crate::arch::x86_64::debug_reg::{
        arm_linear_watchpoint, ArmPhysResult, WATCH_KIND_D16_CANARY,
    };

    let result = arm_linear_watchpoint(CANARY_SLOT_VA, WATCH_LEN, WATCH_KIND_D16_CANARY);
    let (state, slot) = match result {
        ArmPhysResult::Armed(s)      => ("armed", s as i32),
        ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
        ArmPhysResult::NotAligned    => ("not_aligned", -1),
        ArmPhysResult::OutOfRange    => ("out_of_range", -1),
    };

    match backing_phys {
        Some(p) => crate::serial_println!(
            "[D16/ARM] channel=user_va state={} pid={} tid={} cpu={} cr3={:#x} \
             canary_va={:#x} canary_val={:#x} backing_phys={:#x} \
             phys_match_expected={} slot={} len={} kind_tag={}",
            state, pid, tid, cpu, cr3, CANARY_SLOT_VA, canary_val, p,
            (p == CANARY_SLOT_PHYS.wrapping_add(CANARY_SLOT_PHYS_OFF)) as u8,
            slot, WATCH_LEN, WATCH_KIND_D16_CANARY,
        ),
        None => crate::serial_println!(
            "[D16/ARM] channel=user_va state={} pid={} tid={} cpu={} cr3={:#x} \
             canary_va={:#x} canary_val={:#x} backing_phys=unmapped \
             slot={} len={} kind_tag={}",
            state, pid, tid, cpu, cr3, CANARY_SLOT_VA, canary_val,
            slot, WATCH_LEN, WATCH_KIND_D16_CANARY,
        ),
    }
}
