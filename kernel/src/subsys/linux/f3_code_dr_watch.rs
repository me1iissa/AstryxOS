//! F3 code-fetch (instruction-execute) DR0 watchpoint on the deterministic
//! musl `__stack_chk_fail+0x0` user VA.
//!
//! # Why a code-DR watch
//!
//! PR #420 autopsy verdict: the SSP failure is deterministic at user-VA
//! `0x7f41a4b567f9` (= ld-musl-x86_64.so.1 + 0x1c7f9), BuildID
//! `cc77a6e278a161964ce8abdbe0751ad333aff469`, opcode bytes `f4 c3`
//! (= HLT;RET — the musl `__stack_chk_fail` abort stub).  Two
//! independent KVM trials at INFRA-3 seed `0xCAFEF00DCAFEF00D`
//! reproduce the trap RIP byte-for-byte, the backing phys
//! (`0x12911000`), the TLS master canary at `fs:0x28`
//! (`0x37b9354151870065`, invariant across both trials), and the last
//! syscall ordinal (`1226`, `futex_wake` from the vfork child).
//!
//! The data-watch channels (D21 linear-VA, D22 PHYS_OFF) named the
//! *writers* of the canary slot as legitimate musl prologue pushes.
//! The remaining question — "is the canary AT WRITE TIME different
//! from the canary AT CHECK TIME?" — needs the *caller-frame
//! snapshot* at the precise moment the SSP epilogue invokes
//! `__stack_chk_fail`.  A code-fetch DR (Intel SDM Vol. 3B §17.2.4
//! RW=00b LEN=00b) fires as a fault before the abort instruction
//! retires (Intel SDM Vol. 3A §6.15 #DB fault timing for instruction
//! breakpoints), so the `#DB` frame's `rip == __stack_chk_fail+0x0`
//! and the saved GPRs / RSP / RBP reflect the SSP caller's frame at
//! the dispositive instant.
//!
//! # What this captures
//!
//! On a single fire, emits one `[F3/CODE-DR-FIRE]` block containing:
//!
//!   * All 15 saved GPRs (RAX–R15) + RFLAGS + RIP + CS
//!   * 16 qwords above RSP (`[rsp..rsp+0x80]`)
//!   * 4 qwords around RBP (`[rbp-0x10..rbp+0x10]`)
//!   * The KERNEL_VIRTUAL_TICKS ordinal at fire time (per-CPU TSC
//!     tick counter, used by INFRA-3 record/replay correlation)
//!   * The most recent `[VFORK/CANARY] post_wake.*` epoch index
//!
//! All offsets and values are byte-identical across the deterministic
//! reproduction at seed `0xCAFEF00DCAFEF00D`; a divergence between
//! trials indicates non-determinism leak (escalate to record/replay).
//!
//! # Arm site
//!
//! `try_arm_after_post_wake(pid, tid)` is called from the Linux
//! clone(2) / clone3(2) syscall path in `subsys/linux/syscall.rs`,
//! immediately after the existing `vfork_canary_snapshot("post_wake.clone*", …)`
//! emission.  Path-gated to PID 1 only (the firefox-bin init thread)
//! and bounded by a single boot-wide one-shot — once the DR fires
//! the slot disarms (`one_shot=true` per the LEGACY policy applied
//! to `WATCH_KIND_F3_CODE_DR` in `handle_db_exception`).
//!
//! # Refs
//!
//!   * Intel SDM Vol. 3B §17.2.4 Table 17-2 (DR0–DR3 / DR7 encoding;
//!     RW=00b / LEN=00b for instruction breakpoints).
//!   * Intel SDM Vol. 3B §17.3.1.1 (#DB instruction-breakpoint fault
//!     timing — taken before the watched instruction retires).
//!   * Intel SDM Vol. 3A §6.15 (#DB vector 1 dispatch).
//!   * System V AMD64 ABI §3.4.1 (SSP / `__stack_chk_guard`).
//!   * GCC manual §3.20 (`-fstack-protector` epilogue check).
//!   * POSIX `vfork(3p)`, `clone(2)`, `clone3(2)`.
//!   * PR #420 (autopsy verdict, byte-identical 2/2 reproduction).
//!   * PR #417 (libxul SSP-shape audit, `[rsp+0x1e0]` slot framing).

#![cfg(feature = "f3-codeDR-watch")]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// musl `__stack_chk_fail+0x0` file-offset within ld-musl-x86_64.so.1.
///
/// Per PR #420 autopsy: BuildID `cc77a6e278a161964ce8abdbe0751ad333aff469`,
/// libc file offset `0x1c7f9`, opcode bytes `f4 c3` (= HLT;RET — the
/// musl SSP abort stub).  Combined with the per-trial ASLR-randomised
/// ld-musl base (resolved at arm time via `find_ld_musl_base`), gives
/// the per-trial target user VA.
///
/// PR #420 reproduced this BYTE-IDENTICAL across two INFRA-3 trials at
/// seed `0xCAFEF00DCAFEF00D` (trial-2 RIP = `0x7f41a4b567f9` =
/// `ld-musl_base + 0x1c7f9`).  In KVM trials without the INFRA-3 seed
/// fix-up the libc base randomises per boot, so the watched VA must
/// be derived from the live VMA name lookup.  A future ld-musl
/// rebuild that shifts `__stack_chk_fail` to a different offset will
/// invalidate this constant; the arm hook logs the resolved VA so a
/// post-processor can detect drift.
const SSP_FAIL_LIBC_OFFSET: u64 = 0x1c7f9;

/// VMA name-substring used to locate the dynamic loader's VMAs in
/// the parent process's address space.  Per `kernel/src/proc/elf.rs`
/// the ELF loader tags every page belonging to a PT_INTERP image
/// (`/disk/lib/ld-musl-x86_64.so.1` for the musl personality) with
/// the static string `[interp]`; the loader spans several VMAs
/// (`.text`, `.rodata`, `.data`, `.bss`) all sharing this name.
/// Walking for the lowest matching base recovers the interp load
/// address — i.e. `ld-musl_base` — to which the static libc-side
/// `__stack_chk_fail` offset (`SSP_FAIL_LIBC_OFFSET = 0x1c7f9`) is
/// added to produce the per-trial target VA.
const LD_MUSL_NAME_SUBSTR: &str = "[interp]";

/// PID gate — only the firefox-bin init thread's process.  PID 1 is
/// assigned to firefox-bin in the demo path (per the existing
/// `D21_TARGET_PID = 1` / `f3_watch` path-substring gate logic).
const F3_TARGET_PID: u64 = 1;

/// One-shot arm flag.  `true` after the first successful arm; the
/// fire path (Intel SDM Vol. 3B §17.3.1.1 fault-before-retire) sets
/// the slot to disarm exactly once, but the boot-wide flag prevents
/// re-arming if the syscall hook fires again before fire (e.g. a
/// second post_wake snapshot in the same boot for a subsequent
/// clone).  Using a `compare_exchange(false → true)` so a refused
/// arm path emits the `cap_reached` diagnostic exactly once.
static ARMED_ONCE: AtomicBool = AtomicBool::new(false);

/// Fire-once flag.  Set the first time `record_fire` runs; subsequent
/// fires (should not happen given one-shot disarm + ARMED_ONCE, but
/// defensive) skip the dump emission so the serial log doesn't grow
/// unboundedly.  Per Intel SDM Vol. 3B §17.3.1.1 each `#DB` is one
/// retired-instruction event; a second fire would indicate a stale
/// sticky DR6.B0 we did not clear, which is a separate bug class.
static FIRED_ONCE: AtomicBool = AtomicBool::new(false);

/// Snapshot of the per-CPU virtual tick counter at the last
/// `post_wake.clone*` snapshot.  Captured by the arm hook and emitted
/// on fire as the "epoch" anchor.  Per AstryxOS TICK_HZ=100 contract
/// this rolls at ~10ms granularity; sufficient to distinguish the
/// pre-fire vs post-fire ordering against the vfork wake without
/// requiring INFRA-3 record/replay.
static ARM_TICK: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the resolved target VA at arm time — recorded so the
/// fire-line can emit `expected_va == rip` as a sanity check.  Zero
/// means "not yet armed".
static ARMED_TARGET_VA: AtomicU64 = AtomicU64::new(0);

/// Walk the parent process's VMA table for an entry whose `name`
/// contains `LD_MUSL_NAME_SUBSTR` and return its base.  Returns the
/// LOWEST matching base across all `[base, base+0x40000)` candidate
/// VMAs (a single shared object can span multiple VMAs — `.text`,
/// `.rodata`, `.data`, `.bss` — each with its own VmArea).
///
/// Uses `try_lock()` on `PROCESS_TABLE` so a contended lock returns
/// `None` rather than blocking (this hook can be called from a hot
/// syscall path).  Returns `None` if no PID 1 entry exists or no VMA
/// matches.  Per `mm::vma::VmArea::name` the field is a
/// `&'static str` populated by the ELF loader.
fn find_ld_musl_base(pid: u64) -> Option<u64> {
    // try_lock + ?: a contended PROCESS_TABLE lock returns None so the
    // caller resets ARMED_ONCE and retries on the next post_wake (no
    // diagnostic needed for the busy-retry path — there are many
    // post_wake invocations per boot, and only one needs to succeed).
    let procs = crate::proc::PROCESS_TABLE.try_lock()?;
    let proc_entry = procs.iter().find(|p| p.pid == pid)?;
    let vm_space = proc_entry.vm_space.as_ref()?;
    let mut best: Option<u64> = None;
    for vma in vm_space.areas.iter() {
        if vma.name.contains(LD_MUSL_NAME_SUBSTR) {
            best = Some(match best {
                Some(b) => b.min(vma.base),
                None    => vma.base,
            });
        }
    }
    best
}

/// Try to arm the code-fetch DR0 watchpoint after the existing
/// `[VFORK/CANARY] post_wake.*` snapshot completes.  Called from
/// `subsys/linux/syscall.rs` at both the clone(2) and clone3(2)
/// post-wake sites.  Bounded by `ARMED_ONCE` to a single arm per
/// boot.
///
/// On the qualifying call (PID 1, ARMED_ONCE was false):
///   * Captures the current TICK_COUNT in `ARM_TICK` for the fire
///     emission's epoch field.
///   * Issues `arm_code_watchpoint(SSP_FAIL_USER_VA, WATCH_KIND_F3_CODE_DR)`,
///     which programs an instruction-breakpoint DR slot with
///     RW=00b / LEN=00b per Intel SDM Vol. 3B §17.2.4.
///   * Emits an `[F3/CODE-DR/ARM]` diagnostic line for the post-
///     processor to correlate with the fire that follows.
///
/// Returns early (no log emission, no state change) on non-target
/// PIDs and on the second/subsequent arm attempt.
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

    // Resolve the per-trial ld-musl base.  ASLR randomises the base
    // across boots, so a static VA would only match in trials whose
    // entropy seed happens to land on the autopsy reproduction's
    // base.  Walking the parent's VMA table for an `ld-musl` name
    // match is O(N) over a small (~30) VMA list and runs at most
    // once per boot (gated by ARMED_ONCE).
    let ld_musl_base = match find_ld_musl_base(pid) {
        Some(b) => b,
        None    => {
            // Reset ARMED_ONCE so a later post_wake invocation gets
            // another shot (e.g. if the VMA wasn't installed yet).
            // Bounded by F3_TARGET_PID + the natural post_wake cadence.
            ARMED_ONCE.store(false, Ordering::Release);
            crate::serial_println!(
                "[F3/CODE-DR/ARM] state=no_ld_musl pid={} tid={} cpu={} \
                 cr3={:#x} tick={}",
                pid, tid, cpu, cr3, tick,
            );
            return;
        }
    };
    let target_va = ld_musl_base.wrapping_add(SSP_FAIL_LIBC_OFFSET);

    use crate::arch::x86_64::debug_reg::{
        arm_code_watchpoint, ArmPhysResult, WATCH_KIND_F3_CODE_DR,
    };
    ARMED_TARGET_VA.store(target_va, Ordering::Release);
    let result = arm_code_watchpoint(target_va, WATCH_KIND_F3_CODE_DR);
    let (state, slot) = match result {
        ArmPhysResult::Armed(s)        => ("armed", s as i32),
        ArmPhysResult::PoolExhausted   => ("pool_exhausted", -1),
        ArmPhysResult::NotAligned      => ("not_aligned", -1),
        ArmPhysResult::OutOfRange      => ("out_of_range", -1),
    };
    crate::serial_println!(
        "[F3/CODE-DR/ARM] state={} pid={} tid={} cpu={} cr3={:#x} \
         ld_musl_base={:#x} target_va={:#x} libc_offset={:#x} \
         slot={} kind_tag={} tick={}",
        state, pid, tid, cpu, cr3, ld_musl_base, target_va,
        SSP_FAIL_LIBC_OFFSET, slot, WATCH_KIND_F3_CODE_DR, tick,
    );
}

/// Fire hook called from `arch::x86_64::debug_reg::handle_db_exception`
/// when the firing slot's `kind_tag == WATCH_KIND_F3_CODE_DR`.  Emits the
/// dispositive `[F3/CODE-DR-FIRE]` dump and a stack/RBP window suitable
/// for diffing against the PR #420 autopsy reproduction.
///
/// `gprs` follows the `debug_reg::Gprs` layout
/// (r15 first / rax last); see that type's docstring for the index map.
/// `None` (caller had no saved frame) degrades gracefully — registers
/// log as `?` so the post-processor can still match on RIP and stack.
///
/// One-shot — second fire (defensive, should not happen) is silently
/// dropped.
pub fn record_fire(
    slot: u8,
    rip: u64,
    rsp: u64,
    rflags: u64,
    cs: u64,
    cr3: u64,
    gprs: Option<&crate::arch::x86_64::debug_reg::Gprs>,
) {
    if FIRED_ONCE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let pid = crate::proc::current_pid_lockless();
    let tid = crate::proc::current_tid();
    let arm_tick = ARM_TICK.load(Ordering::Relaxed);
    let fire_tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);

    // Banner line — anchors the dump to the watched VA + epoch + caller.
    let expected_va = ARMED_TARGET_VA.load(Ordering::Acquire);
    crate::serial_println!(
        "[F3/CODE-DR-FIRE] slot={} pid={} tid={} cpu={} cr3={:#x} \
         rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} arm_tick={} fire_tick={} \
         expected_va={:#x} rip_eq_expected={}",
        slot, pid, tid, cpu, cr3, rip, cs, rflags, rsp,
        arm_tick, fire_tick, expected_va, (rip == expected_va) as u8,
    );

    // GPR dump — per `debug_reg::Gprs` index map:
    //   [0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=rbp [5]=rbx
    //   [6]=r11 [7]=r10 [8]=r9  [9]=r8  [10]=rdi [11]=rsi
    //   [12]=rdx [13]=rcx [14]=rax
    let rbp = match gprs {
        Some(g) => {
            crate::serial_println!(
                "[F3/CODE-DR-FIRE/GPR] rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
                g[14], g[5], g[13], g[12],
            );
            crate::serial_println!(
                "[F3/CODE-DR-FIRE/GPR] rsi={:#018x} rdi={:#018x} rbp={:#018x} r8={:#018x}",
                g[11], g[10], g[4], g[9],
            );
            crate::serial_println!(
                "[F3/CODE-DR-FIRE/GPR] r9={:#018x}  r10={:#018x} r11={:#018x} r12={:#018x}",
                g[8], g[7], g[6], g[3],
            );
            crate::serial_println!(
                "[F3/CODE-DR-FIRE/GPR] r13={:#018x} r14={:#018x} r15={:#018x}",
                g[2], g[1], g[0],
            );
            g[4]
        }
        None => {
            crate::serial_println!("[F3/CODE-DR-FIRE/GPR] state=unavailable");
            0
        }
    };

    // Stack window — 16 qwords above RSP.  Per System V AMD64 ABI §3.4.1
    // the SSP epilogue's `call __stack_chk_fail` has just pushed the
    // return address as the top-of-stack word, so `[rsp+0]` is the
    // SSP-instrumented caller's RIP-after-call.
    dump_user_qwords(cr3, "RSP", rsp, 16);

    // RBP window — 4 qwords spanning `[rbp-0x10, rbp+0x10)`.  Per
    // System V AMD64 ABI §3.2.2 the SSP slot lives at `[rbp-8]` for
    // GCC `-fstack-protector` epilogues; capturing this window names
    // both the saved-canary slot value at fire time and the saved
    // caller-RBP at `[rbp+0]`.
    if rbp != 0 {
        let base = rbp.wrapping_sub(0x10);
        dump_user_qwords(cr3, "RBP", base, 4);
    } else {
        crate::serial_println!("[F3/CODE-DR-FIRE/RBP] state=no_gprs");
    }
}

/// Read `count` qwords starting at user VA `base` under `cr3` and emit
/// one `[F3/CODE-DR-FIRE/<tag>] [base+offset] VA = VAL` line per qword.
/// Unmapped or non-canonical addresses emit `(unmapped)` instead.
///
/// Walks the page tables via `mm::vmm::virt_to_phys_in` and reads via
/// the `PHYS_OFF` direct map — never dereferences a raw user pointer,
/// safe to call from #DB context with `IF=0` (Intel SDM Vol. 3A §4.6 +
/// §4.10 for the walk; AstryxOS PHYS_OFF at `0xFFFF_8000_0000_0000`).
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
                    "[F3/CODE-DR-FIRE/{}] [base+{:#04x}] va={:#018x} = {:#018x}",
                    tag, i * 8, va, v,
                );
            }
            None => {
                crate::serial_println!(
                    "[F3/CODE-DR-FIRE/{}] [base+{:#04x}] va={:#018x} = (unmapped)",
                    tag, i * 8, va,
                );
            }
        }
    }
}
