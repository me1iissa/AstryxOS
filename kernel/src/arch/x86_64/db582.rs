//! #582 torn-saved-RFLAGS-slot writer classifier (diagnostic-only).
//!
//! Background.  On SMP, a context-switch *victim* thread's saved
//! `switch_context_asm` frame is occasionally found byte-for-byte intact
//! EXCEPT its saved-RFLAGS slot, which holds a torn value with the trap
//! flag (`RFLAGS.TF`, bit 8) set instead of the healthy `0x202`.  When
//! that thread is later resumed, the restore epilogue's `popfq`
//! (`proc/thread.rs::switch_context_asm`) loads TF=1, the CPU
//! single-steps the next instruction, and a kernel-mode `#DB`
//! (Exception 1) raises `UNEXPECTED_KERNEL_MODE_TRAP` (0x7f).
//!
//! This module is the fire path for `WATCH_KIND_D582_RFLAGS` — an 8-byte
//! data-write watchpoint armed by `sched::schedule()` on a freshly-saved
//! victim's RFLAGS slot (`Thread::context.rsp + 0`).  Per Intel SDM
//! Vol. 3B §17.3.1.1 a data-write breakpoint is a *trap* (taken after the
//! offending store retires), so:
//!   - the `#DB` frame's `rip` is the RIP of the writing instruction;
//!   - the qword now resident at the watched linear address is exactly
//!     what the writer just stored.
//!
//! Classification.  Every legitimate re-save of the watched victim is a
//! `pushfq` store inside `switch_context_asm`.  Those fires are *benign
//! churn*; we count them but do not flood serial.  Any writer whose RIP
//! lies OUTSIDE `switch_context_asm` is the catch — we emit the full
//! `[582/CATCH]` dump (writer RIP, TID, PID, CR3, CPU, the written value,
//! the watched linear address, the TF-bit state, and the GPR file).
//!
//! Diagnostic-only; no fix-it logic.  Gated on the `582-diag` feature.

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

/// `RFLAGS.TF` — trap flag, bit 8 (Intel SDM Vol. 1 §3.4.3.3).  A torn
/// saved-RFLAGS slot with this bit set is the #582 signature.
const RFLAGS_TF: u64 = 1 << 8;

/// Healthy saved-RFLAGS seed (IF=1, reserved-bit-1=1), matching
/// `init_thread_stack`'s `0x202` seed.  Used only as the reference value in
/// catch lines; the arm-site gate uses [`rflags_is_healthy`] because a live
/// thread's saved `pushfq` also carries condition-code flags.
pub const RFLAGS_HEALTHY: u64 = 0x202;

/// `RFLAGS` bit 1 is reserved and always reads 1 (Intel SDM Vol. 1
/// §3.4.3).
const RFLAGS_RESERVED1: u64 = 1 << 1;

/// True if a saved-RFLAGS slot value is *structurally healthy* for arming.
///
/// A `switch_context_asm` frame is saved with `pushfq` while `schedule()`
/// holds CLI across the whole switch, so the saved RFLAGS legitimately has
/// **IF=0** (interrupts masked) — the init-seed `0x202` (IF=1) is only the
/// first-run case.  A live kernel thread also carries arbitrary
/// condition-code flags (ZF/SF/PF/CF/OF).  The only invariants we can rely
/// on for a non-torn saved frame are therefore: reserved-bit-1 set (always
/// 1) and the high reserved bits (≥ bit 22) clear; the #582 tear is
/// specifically TF (bit 8) SET, so we additionally require TF clear at arm
/// time.  Keying on TF-clear (not IF) is what lets the gate accept the
/// IF=0 frames the switch path actually produces.  Cite Intel SDM Vol. 1
/// §3.4.3 (EFLAGS layout; bits 22–63 reserved/0, bit 1 reserved/1).
pub fn rflags_is_healthy(val: u64) -> bool {
    (val & RFLAGS_RESERVED1) != 0
        && (val & RFLAGS_TF) == 0
        && (val >> 22) == 0
}

/// Half-open span (bytes) used to classify a writer RIP as the legitimate
/// `switch_context_asm` re-save.  The asm body (save + restore) is well
/// under 0x80 bytes; any in-range writer is the expected `pushfq`/`mov
/// [rdi],rsp` save store, not the foreign tear.
const SWITCH_CTX_SPAN: u64 = 0x80;

/// Cumulative count of *benign* fires (legitimate `switch_context_asm`
/// re-saves of the watched victim).  Read by tooling to confirm the watch
/// is live and seeing churn even when no catch lands.
pub static BENIGN_SAVE_FIRES: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of out-of-band fires (writers outside
/// `switch_context_asm`) — the catch counter.
pub static OUT_OF_BAND_FIRES: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of out-of-band fires that additionally wrote a
/// TF-set value (the dispositive #582 signature).
pub static TF_TEAR_FIRES: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of self-stack fires — a non-`switch_context_asm` writer
/// whose RSP lies on the SAME kernel stack as the watched slot (the owner
/// thread operating on its own stack; NOT a foreign tear).
pub static SELF_STACK_FIRES: AtomicU64 = AtomicU64::new(0);

/// Bounded budget for the `[582/SELF]` heartbeat.
const SELF_LOG_BUDGET: u32 = 8;
static SELF_LOGGED: AtomicU32 = AtomicU32::new(0);

/// Bounded budget for the loud `[582/CATCH]` dump so a hot foreign writer
/// cannot flood serial.  After this many catches the counters keep
/// incrementing but the verbose dump is suppressed.
const CATCH_LOG_BUDGET: u32 = 16;
static CATCH_LOGGED: AtomicU32 = AtomicU32::new(0);

/// Bounded budget for a *sampled* benign-churn heartbeat so an
/// investigator can confirm the watch is firing on the legit save path
/// (proves the instrument is alive) without flooding serial.
const BENIGN_LOG_BUDGET: u32 = 16;
static BENIGN_LOGGED: AtomicU32 = AtomicU32::new(0);

/// Address of `switch_context_asm` (the legitimate save site).  Taken via
/// the extern symbol; mcmodel=kernel may truncate the linker constant to
/// its physical LMA, so reconstruct the higher-half VMA the same way
/// `init_thread_stack` does for function pointers (set bit 47+).
fn switch_context_asm_base() -> u64 {
    extern "C" {
        fn switch_context_asm(old_rsp_ptr: *mut u64, new_rsp: u64, ctx_valid_ptr: *mut u8);
    }
    let raw = switch_context_asm as *const () as u64;
    if raw & (1u64 << 47) == 0 {
        // Truncated to LMA — add the kernel virtual base to recover the
        // mapped higher-half address.
        raw | 0xFFFF_8000_0000_0000
    } else {
        raw
    }
}

/// True if `rip` falls within the legitimate `switch_context_asm` body.
fn rip_is_legit_save(rip: u64) -> bool {
    let base = switch_context_asm_base();
    rip >= base && rip < base.wrapping_add(SWITCH_CTX_SPAN)
}

/// Fire hook for a `WATCH_KIND_D582_RFLAGS` `#DB`.  Called from
/// `debug_reg::handle_db_exception` for each hit on DR0's D582 watch.
///
/// `watched_addr` is the linear address of the saved-RFLAGS slot the
/// watch was armed on; `rip`/`cr3`/`cs`/`rflags`/`rsp` are the writer's
/// interrupt-frame fields; `gprs` is the saved GPR file (writer registers).
#[allow(clippy::too_many_arguments)]
pub fn record_fire(
    slot: u8,
    fire_idx: u32,
    rip: u64,
    rsp: u64,
    rflags: u64,
    cs: u64,
    cr3: u64,
    watched_addr: u64,
    gprs: Option<&crate::arch::x86_64::debug_reg::Gprs>,
) {
    // Read the value the writer just stored.  Per Intel SDM Vol. 3B
    // §17.3.1.1 the data-write `#DB` is a trap, so the qword resident at
    // the watched VA now reflects the retired store.  The slot is a
    // higher-half kernel-stack VA mapped in every CR3 (PML4[256-511]), so
    // a direct read is well-defined regardless of the firing CR3 and safe
    // with IF=0.
    let written: u64 = if watched_addr >= 0xFFFF_8000_0000_0000 {
        unsafe { core::ptr::read_volatile(watched_addr as *const u64) }
    } else {
        0
    };
    let tf_set = (written & RFLAGS_TF) != 0;

    if rip_is_legit_save(rip) {
        // Benign churn: the legitimate `switch_context_asm` re-save of the
        // watched victim.  Count it; emit a bounded heartbeat so an
        // investigator can confirm the watch is alive.
        let n = BENIGN_SAVE_FIRES.fetch_add(1, Ordering::Relaxed);
        let logged = BENIGN_LOGGED.fetch_add(1, Ordering::Relaxed);
        if logged < BENIGN_LOG_BUDGET {
            let cpu = crate::arch::x86_64::apic::cpu_index();
            crate::serial_println!(
                "[582/BENIGN] slot={} fire_idx={} n={} cpu={} legit-save rip={:#x} \
                 watched={:#x} written={:#x} tf={}",
                slot, fire_idx, n, cpu, rip, watched_addr, written, tf_set as u8,
            );
        }
        return;
    }

    // Writer-vs-owner discrimination (the PRIMARY catch test).  The watch
    // records the TID that owns the parked saved frame.  The CURRENT thread
    // (the writer) is read here.  If they are the SAME thread, the write is
    // the owner operating on its own stack — the slot has become the live
    // RSP top of the resuming/running owner, or the owner's own switch /
    // interrupt activity.  That is NOT the #582 tear (a FOREIGN store
    // landing on a *parked* victim's frame).  Classifying on TID identity
    // (not RSP proximity) is robust to the prime suspected mechanism — a
    // stale `TSS.RSP0` letting a DIFFERENT thread's interrupt frame land on
    // the victim's stack VA (Intel SDM Vol. 3A §6.14): that writer's RSP
    // would be ON the victim's stack (rsp ≈ watched) yet the writing TID is
    // NOT the owner, so it must still be flagged as the catch.
    let owner_tid = crate::arch::x86_64::debug_reg::d582_watched_tid();
    let writer_tid = crate::proc::current_tid() as u64;
    let same_stack = {
        let lo = watched_addr.wrapping_sub(0x1000);
        let hi = watched_addr.wrapping_add(0x1000);
        rsp >= lo && rsp <= hi
    };
    if writer_tid == owner_tid {
        // The owner thread itself wrote to its own saved slot (resume /
        // own-stack reuse / its own interrupt frame).  Count + bounded log;
        // not a tear.
        let n = SELF_STACK_FIRES.fetch_add(1, Ordering::Relaxed);
        let logged = SELF_LOGGED.fetch_add(1, Ordering::Relaxed);
        if logged < SELF_LOG_BUDGET {
            let cpu = crate::arch::x86_64::apic::cpu_index();
            crate::serial_println!(
                "[582/SELF] slot={} fire_idx={} n={} cpu={} owner_tid={} writer_tid={} \
                 same_stack={} rip={:#x} rsp={:#x} watched={:#x} written={:#x} tf={} \
                 (owner==writer, own-stack, not a tear)",
                slot, fire_idx, n, cpu, owner_tid, writer_tid, same_stack as u8,
                rip, rsp, watched_addr, written, tf_set as u8,
            );
        }
        return;
    }

    // ── OUT-OF-BAND FOREIGN WRITER — THE CATCH ──────────────────────────
    // A DIFFERENT thread (`writer_tid != owner_tid`) stored to the parked
    // victim's saved RFLAGS slot.  This is the #582 tear if `tf_set` (TF=1
    // stored).  `same_stack=1` here is the strong stale-TSS.RSP0 signature
    // (a foreign interrupt frame on the victim's own stack VA); `same_stack=0`
    // is a genuinely unrelated foreign store.
    let n_oob = OUT_OF_BAND_FIRES.fetch_add(1, Ordering::Relaxed);
    if tf_set {
        TF_TEAR_FIRES.fetch_add(1, Ordering::Relaxed);
    }
    let logged = CATCH_LOGGED.fetch_add(1, Ordering::Relaxed);
    if logged >= CATCH_LOG_BUDGET {
        return;
    }

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let pid = crate::proc::current_pid_lockless();
    let tid = crate::proc::current_tid();
    let fire_tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let base = switch_context_asm_base();

    // Loud banner — names the writer (RIP + the four "who/where" fields)
    // and the dispositive value (written + TF state).  `tf_tear=1` is the
    // exact #582 signature (an out-of-band store of a TF-set value onto a
    // switch victim's saved-RFLAGS slot).
    crate::serial_println!(
        "[582/CATCH] OUT-OF-BAND WRITER slot={} oob_n={} cpu={} writer_tid={} owner_tid={} \
         pid={} cr3={:#x} writer_rip={:#x} cs={:#x} writer_rflags={:#x} writer_rsp={:#x} \
         watched_linear={:#x} same_stack={} written={:#x} tf_tear={} healthy={:#x} \
         switch_ctx_base={:#x} fire_tick={} fire_idx={}",
        slot, n_oob, cpu, tid, owner_tid, pid, cr3, rip, cs, rflags, rsp,
        watched_addr, same_stack as u8, written, tf_set as u8, RFLAGS_HEALTHY,
        base, fire_tick, fire_idx,
    );

    // Owner-state dump — name the parked victim's scheduler state at the
    // moment of the foreign write.  A still-resumable owner (Ready/Blocked/
    // Sleeping with ctx_rsp_valid=1) whose saved frame is being foreign-
    // written is the dispositive #582 tear; an owner already Dead/absent
    // (the watch was disarmed at reap, so absent normally means already
    // gone) tells us the catch is a stale-owner recycle artefact.  Uses a
    // non-blocking `try_lock` (safe in `#DB` context, IF=0).
    match crate::proc::d582_owner_state(owner_tid) {
        Some((st, ctx_valid, last_cpu, kbase, ksize)) => {
            let st_name = match st {
                0 => "Ready", 1 => "Running", 2 => "Blocked",
                3 => "Sleeping", 4 => "Dead", _ => "?",
            };
            let in_frame =
                watched_addr >= kbase && watched_addr < kbase.wrapping_add(ksize);
            crate::serial_println!(
                "[582/CATCH/OWNER] owner_tid={} state={} ctx_rsp_valid={} last_cpu={} \
                 kstack=[{:#x},{:#x}) watched_in_owner_frame={}",
                owner_tid, st_name, ctx_valid as u8, last_cpu,
                kbase, kbase.wrapping_add(ksize), in_frame as u8,
            );
        }
        None => {
            crate::serial_println!(
                "[582/CATCH/OWNER] owner_tid={} state=absent-or-contended \
                 (already reaped, or THREAD_TABLE busy)",
                owner_tid,
            );
        }
    }

    // Writer GPR file — per `debug_reg::Gprs` index map:
    //   [0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=rbp [5]=rbx
    //   [6]=r11 [7]=r10 [8]=r9  [9]=r8  [10]=rdi [11]=rsi
    //   [12]=rdx [13]=rcx [14]=rax
    match gprs {
        Some(g) => {
            crate::serial_println!(
                "[582/CATCH/GPR] rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
                g[14], g[5], g[13], g[12],
            );
            crate::serial_println!(
                "[582/CATCH/GPR] rsi={:#018x} rdi={:#018x} rbp={:#018x} r8={:#018x}",
                g[11], g[10], g[4], g[9],
            );
            crate::serial_println!(
                "[582/CATCH/GPR] r9={:#018x}  r10={:#018x} r11={:#018x} r12={:#018x}",
                g[8], g[7], g[6], g[3],
            );
            crate::serial_println!(
                "[582/CATCH/GPR] r13={:#018x} r14={:#018x} r15={:#018x}",
                g[2], g[1], g[0],
            );
        }
        None => {
            crate::serial_println!("[582/CATCH/GPR] state=unavailable");
        }
    }

    // Writer-stack window — 8 qwords at and above the writer's RSP.  If the
    // foreign store is an interrupt-frame push (e.g. a stale TSS.RSP0
    // landing an exception frame on the victim's VA), the writer RSP and
    // these qwords name the interrupt path; if it's an ordinary store, they
    // name the writer's call frame.  Higher-half only (safe, IF=0).
    for i in 0..8usize {
        let p = rsp.wrapping_add((i * 8) as u64);
        if p >= 0xFFFF_8000_0000_0000 {
            let v = unsafe { core::ptr::read_volatile(p as *const u64) };
            crate::serial_println!(
                "[582/CATCH/STK]   [rsp+{:#04x}] {:#018x} = {:#018x}", i * 8, p, v,
            );
        } else {
            crate::serial_println!(
                "[582/CATCH/STK]   [rsp+{:#04x}] {:#018x} = (non-higher-half)", i * 8, p,
            );
        }
    }

    // Window around the watched slot — 4 qwords spanning the saved
    // callee-saved registers just above the RFLAGS slot, so the catch line
    // shows whether the tear is isolated to RFLAGS (the #582 signature) or
    // part of a wider clobber.  `[watched+0]` is the RFLAGS slot itself.
    for i in 0..4usize {
        let p = watched_addr.wrapping_add((i * 8) as u64);
        if p >= 0xFFFF_8000_0000_0000 {
            let v = unsafe { core::ptr::read_volatile(p as *const u64) };
            crate::serial_println!(
                "[582/CATCH/SLOT]  [watched+{:#04x}] {:#018x} = {:#018x}", i * 8, p, v,
            );
        }
    }
}

/// `(benign, self_stack, out_of_band_foreign, tf_tear)` fire counts —
/// read by tooling/kdb.
pub fn stats() -> (u64, u64, u64, u64) {
    (
        BENIGN_SAVE_FIRES.load(Ordering::Relaxed),
        SELF_STACK_FIRES.load(Ordering::Relaxed),
        OUT_OF_BAND_FIRES.load(Ordering::Relaxed),
        TF_TEAR_FIRES.load(Ordering::Relaxed),
    )
}
