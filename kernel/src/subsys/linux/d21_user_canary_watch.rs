//! D21 PID-1 vfork-window user stack-frame saved-canary writer trap.
//!
//! ## What this catches
//!
//! After the kernel-mode `STACK_CANARY_CORRUPT` class was closed by PRs
//! #388 → #400 (kernel canary corruption at CPL=0), the demo gate moved
//! to a **user-mode** SSP failure on PID 1.  Two fresh-master reproductions
//! land at the byte-identical ld-musl-x86_64.so.1 offset `+0x1c7f9`, which
//! `objdump -d` identifies as `__stack_chk_fail` (`f4 c3` = HLT;RET).
//! Executing `HLT` from CPL=3 raises `#GP(0)` per Intel SDM Vol. 2A
//! ("HLT" instruction reference); AstryxOS's IDT path encodes that as
//! `exit_group(-13)`.
//!
//! The TCB-side master canary at `FS:0x28` is **stable** across the
//! vfork window per the existing `[VFORK/CANARY] pre_block.clone` /
//! `[VFORK/CANARY] post_wake.clone` snapshots — the value
//! `0x8ce3ae1ad2ee0005` is identical pre and post.  Therefore the
//! corruption is on a **stack-frame saved-canary slot** that some libxul
//! function wrote in its SSP prologue (`mov rax, fs:0x28 ; mov [rbp-8],
//! rax` per System V AMD64 ABI §3.4.5.2) and that something between the
//! prologue and the epilogue mutates.
//!
//! D21 names the writer DIRECTLY by arming a write-only hardware
//! watchpoint on the saved-canary stack slot for PID 1's main thread at
//! the moment the vfork-parent blocks (`pre_block.clone`).  Any
//! subsequent write — kernel-mode (`CS=0x08`) or user-mode (`CS=0x23`,
//! e.g. a sibling thread that shares the parent's VM during the
//! `CLONE_VM|CLONE_VFORK` window) — fires `#DB` on the writing CPU and
//! the existing `[W215/DR-WATCH-FIRE]` line names the writer's RIP, CS,
//! CR3, plus 8 qwords of stack context.  Per Intel SDM Vol. 3B
//! §17.3.1.1 the data-breakpoint trap is taken AFTER the offending
//! store retires; the captured RIP is the instruction immediately
//! after the writer.
//!
//! ## Why the parent-of-vfork PRE-block point
//!
//! Empirically the `__stack_chk_fail` site is reached AFTER the
//! `CLONE_VM|CLONE_VFORK` parent has woken from `schedule()` (the
//! existing `[VFORK/CANARY] post_wake.clone` line emits before the
//! `[EXC] vec=13` line).  The natural watchpoint window is therefore:
//!
//!   * Arm at the PRE-block snapshot point (parent has saved its
//!     SSP-instrumented caller frame's `[rbp-8]` slot, vfork-window
//!     about to open).
//!   * Catch any write — by the cloned child running in the parent's
//!     VM, by a sibling thread, or by a kernel path — to that exact
//!     user VA between then and the parent's next syscall after wake.
//!   * The `F3_FIRE_CAP` policy in `handle_db_exception` self-disarms
//!     the slot at the cap so a hot prologue cannot flood the serial
//!     log.
//!
//! ## Channel selection
//!
//! D21 arms a **user-VA** linear watchpoint via
//! `arm_linear_watchpoint(canary_va, 8, WATCH_KIND_D21_USER_CANARY)`.
//! Per Intel SDM Vol. 3B §17.2.4 DR0–DR3 store linear addresses; the
//! comparison is on the post-segment, pre-paging linear stream, so
//! the watch fires when ANY CPU performs a write whose translation
//! resolves to that linear address under SOME CR3.  In practice the
//! interesting writers are either:
//!
//!   * **The vfork child** (running with the parent's VM until execve
//!     or exit), which shares the parent's CR3 → user-mode write
//!     visible at the watched user VA.
//!   * **A sibling thread of the parent** (shares the same `pid` and
//!     hence the same VM under AstryxOS's CLONE_VM model), which
//!     would also resolve the user VA under the same CR3.
//!   * **A kernel writer** that takes the user-VA route through the
//!     parent's CR3 (uncommon — most kernel writes go via the
//!     `PHYS_OFF` direct map).
//!
//! We do NOT arm a complementary PHYS_OFF channel (unlike D16) because
//! the backing phys for the launcher's saved-canary slot is **not
//! deterministic** across boots — mallocng + per-process mmap-hint
//! jitter (PR #364) randomises the heap, and stack frame layout
//! depends on libxul codegen.  The user-VA channel alone is what the
//! axis needs.
//!
//! ## Expected signatures
//!
//!   * **D21-USER-CANARY-WRITE** — at least one `[W215/DR-WATCH-FIRE]
//!     kind_tag=7` line with `cs=0x23` and a user RIP in the
//!     `[ld-musl_base, ld-musl_base + 0x40000)` range (musl) or the
//!     libxul code range.  That RIP is the writer.  Resolution:
//!     `addr2line` against the appropriate user-mode binary at the
//!     captured RIP minus that binary's ASLR base.
//!   * **D21-KERNEL-WRITER** — fire with `cs=0x08` and a kernel RIP
//!     (`>= 0xFFFF_8000_0000_0000`).  Would name a kernel-mode writer
//!     reaching the user VA — the strongest evidence for a kernel-
//!     side mutation of the user stack across the vfork wake.
//!   * **D21-ZERO-CAPTURES** — no fires at all.  Falsifies "a writer
//!     corrupts the canary slot between prologue and epilogue" on this
//!     channel and points at either (a) the wrong saved-canary slot
//!     was identified (RBP-chain walked into a non-SSP frame) or (b)
//!     the corruption is a phys-aliasing event (the prologue wrote
//!     the correct value to phys P1 but the epilogue reads from phys
//!     P2 — same VA, different phys — which a linear-VA watchpoint
//!     cannot see).  Either outcome routes the next dispatch.
//!
//! ## Target gating
//!
//! Per PR #398's reproducible #GP evidence, the failure is deterministic
//! on **PID 1** — the firefox-bin launcher.  Empirically the calling TID
//! varies (a sibling worker thread of PID 1 issues the
//! `CLONE_VM|CLONE_VFORK` for glxtest; the `exit_group(-13)` post-line
//! reports `caller_tid=2` in the 2/2 dispositive reproductions).  D21
//! is therefore gated on `parent_pid == D21_TARGET_PID` only — any
//! PID-1 thread's vfork PRE-block qualifies, bounded by the
//! `D21_ARM_MAX` total-arm cap.  Off-target calls pay one atomic load
//! + branch.
//!
//! ## Candidate canary slot resolution
//!
//! Per System V AMD64 ABI §3.2.2, a function compiled with GCC SSP
//! (`-fstack-protector*`) writes the canary at `[rbp-8]` in its
//! prologue.  However the musl libc syscall wrapper and downstream
//! glue are compiled with `-fomit-frame-pointer` (musl's project-wide
//! convention to free up `rbp` as a GPR for size optimisation), so
//! walking the `*(rbp)` chain from the syscall wrapper's saved RBP
//! does not reach the SSP-instrumented libxul frame — it lands on a
//! poisoned non-pointer value (`0xfffffffc7ff7fdff` in dispositive
//! reproductions).  The frame-pointer-walking shape used by D16 (the
//! D16-equivalent for the launcher initial-stack frame) is therefore
//! not applicable here.
//!
//! Empirical anchor (`s_1d58` / `s_1d60` slots in the existing
//! `[VFORK/CANARY]` snapshot, see `subsys/linux/syscall.rs::vfork_
//! canary_snapshot`): the libxul `posix_spawn` caller's frame base
//! is reachable by reading the qword at `[parent_user_rsp + 0x1d58]`
//! and interpreting it as the saved RBP of that frame.  Per
//! System V AMD64 ABI §3.2.2 the SSP slot for that frame is at
//! `saved_RBP - 8`.  D21 reads that derived VA and arms on it.
//!
//! Hardening (defence-in-depth): if the derived VA fails validation
//! (zero, misaligned, out of the user range), D21 falls back to
//! arming the raw `[parent_user_rsp + 0x1d58 - 8]` slot — the
//! 8-byte qword adjacent to the existing `s_1d58` probe.  This is
//! the "best guess" slot in the absence of a confirmed frame
//! pointer.  Per Intel SDM Vol. 3B §17.2.4 a DR watch on an
//! 8-byte-aligned linear address is valid regardless of whether the
//! slot is the actual SSP location, so a fallback arm is
//! diagnostically useful even if the slot turns out to be unrelated:
//! a fire (or lack of fires) narrows the search.
//!
//! The complementary `[STACK-CANARY-WALK]` channel emitted on the
//! same PRE-block point (from `vfork_diag::snapshot_stack_canary_walk`)
//! provides additional candidate frame addresses for a post-processor
//! that wants to correlate the D21 capture with the broader chain.
//!
//! ## No-fix discipline
//!
//! Per the saga-discipline rules ([[feedback_saga_diagnostic_discipline_2026_05_20]]),
//! this module emits diagnostic data only.  It does NOT mutate page
//! tables, allocate frames, change any lock order, or perform any
//! syscall-altering side effects.  The hook is in the existing PRE-block
//! tail (alongside `snapshot_canaries`, `snapshot_stack_canary_walk`,
//! `arm_master_canary_watch`), so D21 inherits the same call timing
//! and the same atomic-load fast path on off-target calls.
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7 layout — write-only LEN=8
//!     encoding for the 8-byte canary slot).
//!   * Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap-after-retire —
//!     the captured RIP is the instruction AFTER the writer's store).
//!   * Intel SDM Vol. 3A §4.10 (TLB management — DR linear matches are
//!     on the post-segment, pre-paging linear stream).
//!   * Intel SDM Vol. 2A "HLT" — `HLT` at CPL>0 raises `#GP(0)` (the
//!     mechanism by which musl's `__stack_chk_fail` terminates the
//!     process on AstryxOS).
//!   * System V AMD64 ABI §3.2.2 (stack frame layout — caller's saved
//!     RBP at `[rbp+0]`, saved RIP at `[rbp+8]`, locals below rbp,
//!     SSP slot conventionally at `[rbp-8]`).
//!   * System V AMD64 ABI §3.4.5.2 / §6.4 (TLS variant II;
//!     `__stack_chk_guard` at `fs:0x28`).
//!   * POSIX `vfork(3p)` — parent suspended until child `_exit` or
//!     `execve`; shared address space until then.
//!   * CWE-121 (stack-based buffer overflow taxonomy).
//!   * Prior D20 DR-watchpoint primitive: PR #399 (kernel-stack canary
//!     channel, same fire-emission shape).
//!   * Prior D16 DR-watchpoint primitive: PR #382 (user-VA SSP-canary
//!     slot, same arm-linear-watchpoint API).
//!   * PR #398 — PID 1 `exit_group(-13)` investigation (the
//!     dispositive evidence trail that named this axis).

#![cfg(feature = "d21-user-canary-watch")]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

/// Target pid — per PR #398, the failure is deterministic on PID 1, the
/// firefox-bin launcher.  PID 1 is the Linux personality's init process in
/// the `firefox-test` build.
const D21_TARGET_PID: u64 = 1;

/// Maximum number of arm cycles per boot.  Set to 4 so the first four
/// PID-1 vfork-PRE-block events each get their saved-canary slot watched.
/// Empirically the failure path runs through one vfork (glxtest spawn
/// from PID 1's TID 2 worker thread per PR #398), but bounding above 1
/// covers the possibility that a sibling thread runs a second
/// `CLONE_VM|CLONE_VFORK` before the SSP failure trips, and lets the
/// first arm survive in the steady state across multiple PRE-block events
/// without `D21_ARM_COUNT` saturating after a single benign arm.  4 ≤
/// the 4-slot DR pool but D21 may share with D7/D15/D16/F3 — refused arms
/// from a saturated pool log `pool_exhausted` and continue.  Each
/// accepted arm consumes one DR slot until `handle_db_exception` reaches
/// `F3_FIRE_CAP = 32` fires and self-disarms it.
const D21_ARM_MAX: u32 = 4;

/// Per-boot arm cycle counter.  Counts ACCEPTED arms only (target pid+tid
/// match, RBP chain resolves, slot claim succeeds).  Refused-arm paths
/// (wrong pid, cap reached, RBP chain unreadable, pool exhausted) do
/// not bump this so the cap is honest.
static D21_ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Atomically claim an arm slot via CAS.  Returns `Ok(())` once the
/// counter has been bumped from `< D21_ARM_MAX`, `Err(())` once the cap
/// is reached.  Mirrors `d16_canary_watch::claim_arm` /
/// `d20_kstack_canary_watch::claim_arm`.
fn claim_arm() -> Result<(), ()> {
    loop {
        let cur = D21_ARM_COUNT.load(Ordering::Relaxed);
        if cur >= D21_ARM_MAX {
            return Err(());
        }
        if D21_ARM_COUNT
            .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Resolve `(user_rsp, user_rbp)` for `parent_tid` from the saved syscall
/// frame at the top of that thread's kernel stack.  Mirrors the helper
/// in `vfork_diag::get_parent_user_rsp_rbp` (same call-site convention,
/// inlined here to avoid an unstable cross-module visibility dependency
/// — both modules are diagnostic-gated and may be compiled
/// independently).
///
/// Per the `syscall_entry` save layout in `kernel/src/syscall/mod.rs`
/// (frame slots `[rdi, rsi, rdx, r8, r9, r10, r15, r14, r13, r12, rbx,
/// rbp, r11, rcx, user_rsp]`):
///
///   kstack_top - 1*8  = saved user_rsp
///   kstack_top - 4*8  = saved user_rbp
///
/// Stable across pre-block and post-wake because `schedule()` does not
/// modify the saved syscall frame.  Returns `(0, 0)` if the thread is
/// not in `THREAD_TABLE` (a race with thread teardown — should never
/// hit on a parent that is about to call `schedule()`).
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
    // SAFETY: the kernel stack is in the kernel's virtual address space
    // (always present, always writable from CPL 0).  The two reads are
    // from `kstack_top - 8` and `kstack_top - 32`, both inside the
    // bottom 15 qwords pushed by `syscall_entry` — i.e. within the
    // thread's own kernel stack span.  No user-memory access.
    let user_rsp = unsafe { *((kstack_top - 8) as *const u64) };
    let user_rbp = unsafe { *((kstack_top - 32) as *const u64) };
    (user_rsp, user_rbp)
}

/// Read a userland qword via the kernel direct physical map.  Returns
/// `Some(value, phys)` if the VA is mapped under the current CR3,
/// `None` otherwise.  Mirrors `vfork_diag::read_userland_qword_raw`.
///
/// Fault-immune: the actual load is from the kernel direct map
/// (`PHYS_OFF + phys`), not the user VA, so a not-present user PTE
/// returns `None` instead of faulting.  Per Intel SDM Vol. 3A §4.6 the
/// virt→phys walker checks the present bit at every level.
///
/// 8-byte qword reads only — splitting across a 4 KiB page boundary
/// returns `None`.  Per Intel SDM Vol. 3A §4.6 an 8-byte access spans
/// only when the low 12 bits of the base address exceed `0x1000 - 8`;
/// the saved-canary slot at `[rbp-8]` is 8-byte aligned (System V
/// AMD64 ABI §3.2.2 + GCC SSP convention), so non-straddle is the
/// expected case.
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

/// Offset from `parent_user_rsp` at which the existing `[VFORK/CANARY]`
/// snapshot finds the libxul `posix_spawn` caller's saved RBP qword
/// (see `subsys/linux/syscall.rs::vfork_canary_snapshot` — the `s_1d58`
/// probe).  Empirically deterministic across 2/2 dispositive PR #398
/// reproductions on PID 1 musl firefox-bin: `s_1d58 = 0x7ffffffee4c0`
/// in both cases, which the comment in the existing helper documents
/// as a "plausible `[rbp-8]` canary location for libxul-shaped callers".
///
/// This is the value-at-offset that we interpret as a frame pointer
/// for the SSP-instrumented frame; the actual canary slot lives at
/// `saved_RBP - 8` per System V AMD64 ABI §3.2.2.
const SAVED_RBP_OFFSET_FROM_RSP: u64 = 0x1d58;

/// True SSP canary slot offset from `parent_user_rsp`, corrected from
/// the previous `SAVED_RBP_OFFSET_FROM_RSP - 8` (= 0x1d50) raw-offset
/// arm site per the PR #425 verdict.
///
/// ## EVIDENCE (PR #425 dispositive arithmetic)
///
/// Let `fail_rsp` be RSP at entry to musl `__stack_chk_fail` from the
/// libxul SSP-failing function `f` (libxul+0x4670270).  The autopsy in
/// PR #424/425 captured `fail_rsp = 0x7ffffffee468`.  Per Intel SDM
/// Vol. 2A §3.3 (CALL semantics) the call pushed a return RIP, so RSP
/// at the `call __stack_chk_fail` instruction is `fail_rsp + 8`.  Per
/// the PR #417 disassembly of `f`'s prologue (`push rbp; push r15;
/// push r14; push r13; push r12; push rbx` then `sub rsp, 0x1e8`),
/// the prologue consumed `6 * 8 + 0x1e8 = 0x220` bytes.  Thus
/// `entry_rsp = fail_rsp + 0x220 = 0x7ffffffee688`.
///
/// The compiler places the SSP canary at `[rbp - 8]` per the GCC SSP
/// convention.  In `f`, `rbp = entry_rsp - 8` (set by `push rbp; mov
/// rbp, rsp`), so the canary slot is at `entry_rsp - 0x10`... but the
/// PR #417 disassembly shows the canary is actually stored at
/// `[function-local rsp + 0x1e0]` — relative to RSP AFTER the `sub
/// rsp, 0x1e8`.  That same slot, expressed relative to `entry_rsp`,
/// is `entry_rsp - (0x1e8 - 0x1e0) - 6*8 = entry_rsp - 0x8 - 0x30 =
/// entry_rsp - 0x38`.  Concretely: `canary_va = 0x7ffffffee688 - 0x38
/// = 0x7ffffffee650`.
///
/// Expressed relative to `parent_user_rsp` (= the value of RSP saved
/// in the parent thread's syscall frame on its kernel stack, which
/// the vfork-PRE-block snapshot probes), the offset is `0x1f48`:
/// `parent_user_rsp + 0x1f48 = 0x7ffffffee650`.  Equivalently,
/// `fail_rsp + 0x1e8 = 0x7ffffffee650`.
///
/// ## SAFETY (why the prior raw-offset arm was wrong)
///
/// The previous raw-offset arm computed `user_rsp + 0x1d58 - 8 =
/// user_rsp + 0x1d50 = 0x7ffffffee4c0`.  That VA sits **400 bytes
/// (0x190) below** the true canary slot, INSIDE `f`'s WebRender
/// diagnostic string-builder buffer at `[rsp+0x40..0xd0]` (PR #417
/// disassembly).  The `0x30` byte observed there was ASCII `'0'`
/// from the inner decimal-formatting loop — NOT a canary write.
///
/// References: System V AMD64 ABI §3.2.2 (stack frame layout) +
/// §3.4.5 (TLS variant II for `IA32_FS_BASE + 0x28` master canary);
/// Intel SDM Vol. 2A §3.3 (CALL push); GCC `-fstack-protector` SSP
/// convention.
const SSP_CANARY_OFFSET_FROM_RSP: u64 = 0x1f48;

/// Hook called from the Linux clone(2) / clone3(2) PRE-block site
/// (`kernel/src/subsys/linux/syscall.rs`) immediately before the
/// parent enters `schedule()` for the vfork wait.  Off-path cost on
/// non-target callers: one integer compare + one relaxed atomic load.
///
/// On a qualifying call (PID 1, arm-count not saturated), arms two
/// candidate SSP slots in the parent's stack window:
///
///   1. **RBP-derived** — read `*(parent_user_rsp + 0x1d58)` and treat
///      it as a saved RBP value; arm on `(saved_RBP - 8)` if it
///      validates as a user-stack VA.  This is the "right" SSP slot
///      per System V AMD64 ABI §3.2.2 if the value at offset `0x1d58`
///      is indeed a frame pointer.  Per PR #398's 2/2 dispositive
///      reproductions this slot is `0x7ffffffee4c0`, giving a canary
///      VA of `0x7ffffffee4b8`.
///
///   2. **Raw-offset** (fallback / cross-check) — arm on
///      `parent_user_rsp + 0x1d58 - 8`, the 8-byte qword adjacent to
///      the existing `s_1d58` probe slot.  Provides coverage when the
///      RBP-derived strategy lands on the wrong frame or when the
///      slot at `0x1d58` is not actually a frame pointer.
///
/// Each successful arm consumes one DR slot until `F3_FIRE_CAP = 32`
/// fires and `handle_db_exception` self-disarms it (the persistent-arm
/// policy inherited from the `WATCH_KIND_D21_USER_CANARY` tag).  The
/// total per-boot arm count is bounded by `D21_ARM_MAX`.
///
/// Per Intel SDM Vol. 3B §17.2.4 a linear-arm fires on any CPU's
/// write whose translation resolves to the watched linear address
/// under SOME CR3 — including the vfork child running in the
/// parent's CR3, sibling threads sharing the parent's VM, and any
/// kernel writer that resolves via the parent's CR3 rather than the
/// direct map.
pub fn try_arm_at_vfork_preblock(parent_pid: u64, parent_tid: u64) {
    // Fast precondition checks — keep the hot path cheap.  Off-path cost
    // for non-target callers is one integer compare plus one relaxed
    // atomic load.  Any TID on the target PID qualifies (per PR #398
    // the caller TID varies; the cap is enforced by `D21_ARM_MAX`).
    if parent_pid != D21_TARGET_PID {
        return;
    }
    if D21_ARM_COUNT.load(Ordering::Relaxed) >= D21_ARM_MAX {
        return;
    }

    // Resolve the parent's user RSP from the saved syscall frame on
    // its kernel stack.  Mirrors the well-tested vfork_canary_snapshot
    // and vfork_diag::get_parent_user_rsp_rbp shape.
    let (user_rsp, _ignored_rbp) = get_parent_user_rsp_rbp(parent_tid);
    if user_rsp == 0 {
        crate::serial_println!(
            "[D21/ARM] pid={} tid={} state=no_user_frame",
            parent_pid, parent_tid,
        );
        return;
    }

    // Validate the probe slot lives inside the user range.  Per System V
    // AMD64 ABI §3.2.2 the user stack lives at the top of the canonical
    // user VA range; the SSP slot is at a fixed positive offset from
    // RSP at vfork entry.
    const USER_ADDR_END: u64 = 0x0000_8000_0000_0000;
    const USER_ADDR_MIN: u64 = 0x1000;
    let probe_va = user_rsp.wrapping_add(SAVED_RBP_OFFSET_FROM_RSP);
    if probe_va < USER_ADDR_MIN || probe_va >= USER_ADDR_END {
        crate::serial_println!(
            "[D21/ARM] pid={} tid={} state=probe_va_oor user_rsp={:#x} probe_va={:#x}",
            parent_pid, parent_tid, user_rsp, probe_va,
        );
        return;
    }

    // Read the value at `[user_rsp + 0x1d58]`.  Per the existing
    // vfork_canary_snapshot diagnostic this is interpreted as a saved
    // RBP for the libxul SSP-instrumented frame.
    let saved_rbp_opt = read_user_qword(probe_va);

    // Resolve the cpu / cr3 once for the diagnostic banners.
    let cpu = crate::arch::x86_64::apic::cpu_index();
    let cr3 = crate::mm::vmm::get_cr3();

    use crate::arch::x86_64::debug_reg::{
        arm_linear_watchpoint, ArmPhysResult, WATCH_KIND_D21_USER_CANARY,
    };

    // Candidate 1 — RBP-derived.  Take `saved_RBP - 8` per System V
    // AMD64 ABI §3.2.2 SSP convention.  Validate the derived VA is a
    // qword-aligned user-stack address before arming.
    let rbp_derived_va = match saved_rbp_opt {
        Some((saved_rbp, _)) if saved_rbp != 0
            && saved_rbp & 0x7 == 0
            && saved_rbp >= USER_ADDR_MIN
            && saved_rbp < USER_ADDR_END
            => Some(saved_rbp.wrapping_sub(8)),
        _ => None,
    };

    if let Some(canary_va) = rbp_derived_va {
        if claim_arm().is_ok() {
            let (canary_val, canary_phys) = match read_user_qword(canary_va) {
                Some((v, p)) => (alloc::format!("{:#x}", v), alloc::format!("{:#x}", p)),
                None         => (alloc::string::String::from("unmapped"),
                                 alloc::string::String::from("unmapped")),
            };
            let result = arm_linear_watchpoint(canary_va, 8, WATCH_KIND_D21_USER_CANARY);
            let (state, slot) = match result {
                ArmPhysResult::Armed(s)      => ("armed", s as i32),
                ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
                ArmPhysResult::NotAligned    => ("not_aligned", -1),
                ArmPhysResult::OutOfRange    => ("out_of_range", -1),
            };
            let saved_rbp = saved_rbp_opt.map(|(v, _)| v).unwrap_or(0);
            crate::serial_println!(
                "[D21/ARM] channel=rbp_derived state={} pid={} tid={} cpu={} cr3={:#x} \
                 user_rsp={:#x} probe_va={:#x} saved_rbp={:#x} canary_va={:#x} \
                 canary_val={} canary_phys={} slot={} len=8 kind_tag={}",
                state, parent_pid, parent_tid, cpu, cr3,
                user_rsp, probe_va, saved_rbp, canary_va, canary_val, canary_phys,
                slot, WATCH_KIND_D21_USER_CANARY,
            );
        }
    } else {
        // Log the negative outcome so a post-processor knows the
        // RBP-derived channel was skipped (no saved-RBP value or
        // failed validation).
        let saved_rbp_str = match saved_rbp_opt {
            Some((v, _)) => alloc::format!("{:#x}", v),
            None         => alloc::string::String::from("unmapped"),
        };
        crate::serial_println!(
            "[D21/ARM] channel=rbp_derived state=skipped pid={} tid={} cpu={} cr3={:#x} \
             user_rsp={:#x} probe_va={:#x} saved_rbp={}",
            parent_pid, parent_tid, cpu, cr3, user_rsp, probe_va, saved_rbp_str,
        );
    }

    // Candidate 2 — raw-offset fallback.  Always attempt (subject to
    // D21_ARM_MAX) so we have a cross-check even when the RBP-derived
    // channel succeeds; both can fire under the cap.  The slot at
    // `[user_rsp + SSP_CANARY_OFFSET_FROM_RSP]` (= `user_rsp +
    // 0x1f48`) is the true SSP-canary slot of the libxul SSP-failing
    // function `f` (libxul+0x4670270) per the PR #425 verdict — see
    // the SSP_CANARY_OFFSET_FROM_RSP doc-comment for the dispositive
    // arithmetic.  The previous arm site `user_rsp + 0x1d58 - 8`
    // (= `user_rsp + 0x1d50`) was 0x190 bytes (400 bytes) below the
    // true slot and landed inside `f`'s WebRender diagnostic
    // string-builder buffer.
    if D21_ARM_COUNT.load(Ordering::Relaxed) < D21_ARM_MAX {
        let raw_canary_va = user_rsp
            .wrapping_add(SSP_CANARY_OFFSET_FROM_RSP);
        if raw_canary_va & 0x7 == 0
            && raw_canary_va >= USER_ADDR_MIN
            && raw_canary_va < USER_ADDR_END
            && claim_arm().is_ok()
        {
            let (canary_val, canary_phys) = match read_user_qword(raw_canary_va) {
                Some((v, p)) => (alloc::format!("{:#x}", v), alloc::format!("{:#x}", p)),
                None         => (alloc::string::String::from("unmapped"),
                                 alloc::string::String::from("unmapped")),
            };
            let result = arm_linear_watchpoint(raw_canary_va, 8, WATCH_KIND_D21_USER_CANARY);
            let (state, slot) = match result {
                ArmPhysResult::Armed(s)      => ("armed", s as i32),
                ArmPhysResult::PoolExhausted => ("pool_exhausted", -1),
                ArmPhysResult::NotAligned    => ("not_aligned", -1),
                ArmPhysResult::OutOfRange    => ("out_of_range", -1),
            };
            crate::serial_println!(
                "[D21/ARM] channel=raw_offset state={} pid={} tid={} cpu={} cr3={:#x} \
                 user_rsp={:#x} canary_va={:#x} canary_val={} canary_phys={} \
                 slot={} len=8 kind_tag={}",
                state, parent_pid, parent_tid, cpu, cr3,
                user_rsp, raw_canary_va, canary_val, canary_phys,
                slot, WATCH_KIND_D21_USER_CANARY,
            );
        }
    }
}
