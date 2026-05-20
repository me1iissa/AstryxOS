//! Producer-side snapshot of every exiting thread, keyed by (pid, tid), with
//! a lookup at the kernel-mode fatal-trap site.  Diagnostic-only.
//!
//! # Problem framing
//!
//! Observed pattern (3/3 KVM trials post-PR-344):
//!
//! ```text
//! [CLEARTID]      tid=44 pid=1 clear_addr=0x7eff69375ce8
//! [CLEARTID]      tid=44 cr3=0x36911000
//! [FUTEX_WAKE_EXIT] pid=1 uaddr=0x7eff69375ce8 key_present=false
//! <kernel #GP or #PF on tid=43 (sibling) — RIP ≈ 0x7000 or 0x7002>
//! ```
//!
//! The trapping RIP (`0x7000` / `0x7002`) is not a valid kernel text address
//! — the kernel is loaded in the higher half (`0xFFFF_8000_0010_0000`).  CS=8
//! (kernel CS) and RSP in the higher-half kernel-stack range means a kernel
//! thread successfully fetched and tried to execute at an unrelated low
//! address.  The most likely shape is "the resuming thread's
//! `switch_context_asm` `ret` popped a clobbered return-address slot from its
//! saved kernel stack".  See Intel SDM Vol. 3A §6.15 (#GP) and AMD64 ABI §3.4
//! (callee-saved register layout on the kernel stack).
//!
//! # Why producer-side capture
//!
//! By the time the trap fires, the dying sibling (TID 44) is removed from
//! `THREAD_TABLE` by `reap_dead_threads_sched` and its kernel stack is either
//! zeroed (into the dead-stack cache) or returned to the PMM.  Reconstructing
//! its exit-time CR3, `clear_child_tid` address, and `context.rsp` at the
//! trap site is impossible — the rows are gone.
//!
//! We solve this by snapshotting the exit-time state at the **producer**
//! (`proc::exit_thread`, right after the `[CLEARTID]` line emits) into a
//! lossy per-process ring keyed by `(pid, tid)`.  At trap time, the kernel
//! looks up "any recently-exited sibling of the trapping thread" against the
//! ring and prints the snapshot.  The framing-falsifier observable is whether
//! the dying sibling's `clear_addr` (or anywhere it wrote during exit_thread)
//! aliases the trapping thread's kernel-stack VA range.  See the
//! `feedback-diagnostic-capture-at-clone` agent-memory note (W215 axis-N
//! continuation) for the general producer-vs-consumer pattern.
//!
//! Default builds are byte-identical when `kernel-gp-trap-diag` is off — the
//! `record_exit` and `dump_for_kernel_trap` helpers compile to no-ops via
//! `#[cfg(feature = "kernel-gp-trap-diag")]` at call sites.
//!
//! # Citations
//!
//! - Intel SDM Vol. 3A §6.15 (#GP semantics & error-code format)
//! - Intel SDM Vol. 3A §4.5 (4-level paging, canonical addresses)
//! - System V AMD64 ABI §3.4 (kernel-mode trap-frame layout, RFLAGS preserve)
//! - POSIX clone(2) — `CLONE_CHILD_CLEARTID` exit-time write + futex wake

#![cfg(feature = "kernel-gp-trap-diag")]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Maximum exit snapshots retained in the lossy ring.  16 entries is enough
/// to cover several CLEARTID storms (Firefox content-process spawn flurries
/// hit ~10 worker exits over ~100 ms); newer entries overwrite older ones.
const RING_LEN: usize = 16;

/// One producer-side snapshot taken at thread-exit time, right after the
/// `[CLEARTID]` line and `[FUTEX_WAKE_EXIT]` line emit.
#[derive(Clone, Copy)]
struct ExitSnap {
    /// Lamport-ordered sequence number (monotonic across boot).  0 = empty
    /// slot.  Used by the consumer to determine recency.
    seq: u64,
    /// Process ID of the exiting thread.
    pid: u64,
    /// Thread ID of the exiting thread.
    tid: u64,
    /// Exit-time CR3 of the exiting thread's process (what `write_u32_to_user`
    /// in `exit_thread`'s CLEARTID arm dereferences against).
    cr3: u64,
    /// Exit-time `clear_child_tid` user VA (the target of the CLEARTID
    /// `write_u32_to_user`).
    clear_addr: u64,
    /// Saved `context.rsp` of the exiting thread immediately before the call
    /// to `schedule()` in `exit_thread`.  If this aliases a sibling's kernel
    /// stack we have direct evidence of stack-VA collision.
    saved_context_rsp: u64,
    /// Kernel-stack base (lowest addr, higher-half VA) of the exiting thread.
    /// Reaper will release this back to the dead-stack cache or PMM; if a
    /// sibling's RSP at trap time lands inside `[base, base + size)` we have
    /// direct evidence of post-exit stack reuse.
    kernel_stack_base: u64,
    /// Kernel-stack size of the exiting thread (bytes).
    kernel_stack_size: u64,
    /// CPU index on which `exit_thread` was running.
    cpu: u32,
}

const EMPTY: ExitSnap = ExitSnap {
    seq: 0,
    pid: 0,
    tid: 0,
    cr3: 0,
    clear_addr: 0,
    saved_context_rsp: 0,
    kernel_stack_base: 0,
    kernel_stack_size: 0,
    cpu: 0,
};

/// Lossy ring; spin::Mutex is the same primitive every other producer-side
/// diagnostic uses (see `mm::w215_diag`, `subsys::linux::clone_args_diag`).
static RING: spin::Mutex<[ExitSnap; RING_LEN]> =
    spin::Mutex::new([EMPTY; RING_LEN]);
static RING_HEAD: AtomicU64 = AtomicU64::new(0);

/// Emission cap on the consumer side.  4 dumps/boot is enough to capture
/// the first few recurrences without flooding serial; once we have evidence,
/// we don't need more.
const MAX_DUMPS_PER_BOOT: u32 = 4;
static DUMPS_EMITTED: AtomicU32 = AtomicU32::new(0);

/// Snapshot the dying thread's exit-time state.  Called from
/// `proc::exit_thread` immediately after the `[CLEARTID]` and
/// `[FUTEX_WAKE_EXIT]` emissions, before `schedule()`.
///
/// `saved_context_rsp` is the value of `context.rsp` that the *next*
/// `switch_context_asm` invocation will read for this thread — captured
/// before the lock is dropped, so it reflects the value at the time of
/// the producer's commit.
pub fn record_exit(
    pid: u64,
    tid: u64,
    cr3: u64,
    clear_addr: u64,
    saved_context_rsp: u64,
    kernel_stack_base: u64,
    kernel_stack_size: u64,
) {
    let seq = RING_HEAD.fetch_add(1, Ordering::Relaxed) + 1;
    let cpu = crate::arch::x86_64::apic::cpu_index() as u32;
    let snap = ExitSnap {
        seq,
        pid,
        tid,
        cr3,
        clear_addr,
        saved_context_rsp,
        kernel_stack_base,
        kernel_stack_size,
        cpu,
    };
    let slot = ((seq - 1) as usize) % RING_LEN;
    let mut ring = RING.lock();
    ring[slot] = snap;
    drop(ring);
    // Producer-side wiring trace: lets the operator confirm `record_exit`
    // fires per `proc::exit_thread`.  Cheap (one serial line per exit) and
    // confined to the feature-gated build.
    crate::serial_println!(
        "[KGP-DIAG] exit_snapshot: seq={} pid={} tid={} cpu={} clear_addr={:#x} ctx_rsp={:#x}",
        seq, pid, tid, cpu, clear_addr, saved_context_rsp
    );
}

/// Outcome of a consumer-side ring lookup.  `Contended` discriminates the
/// case where `try_lock` failed (so we know nothing) from `Empty` (no
/// snapshot exists for this pid).
enum LookupResult {
    Found(ExitSnap),
    Empty,
    Contended,
}

/// Look up the most-recent exit snapshot in the same process as the
/// trapping thread.
///
/// Consumer-side: uses `try_lock` because this is invoked from the
/// kernel-mode fatal-trap path, which can fire while another CPU (or this
/// CPU, mid-`record_exit`) holds RING.  Blocking on a non-reentrant
/// `spin::Mutex` would hang the kernel before `ke_bugcheck` runs.  On
/// contention we return `Contended`; producer-side `RING.lock()` in
/// `record_exit` is UNCHANGED.
fn find_most_recent_in_pid(pid: u64) -> LookupResult {
    let ring = match RING.try_lock() {
        Some(g) => g,
        None => return LookupResult::Contended,
    };
    let mut best: Option<ExitSnap> = None;
    for slot in ring.iter() {
        if slot.seq == 0 || slot.pid != pid {
            continue;
        }
        if best.map(|b| slot.seq > b.seq).unwrap_or(true) {
            best = Some(*slot);
        }
    }
    match best {
        Some(s) => LookupResult::Found(s),
        None => LookupResult::Empty,
    }
}

/// Print up to 64 bytes around `addr` as eight `u64` words, lossy-ly via
/// the bypass serial path.  Uses `read_u64_volatile` for fault-immunity
/// shape, but the caller must verify `addr` is in the higher-half kernel
/// range.
fn dump_stack_window(label: &str, addr: u64) {
    crate::serial_println!("[KGP-DIAG] {} addr={:#x}:", label, addr);
    if addr == 0 || addr < 0xFFFF_8000_0000_0000 || (addr & 0x7) != 0 {
        crate::serial_println!("[KGP-DIAG]   <skipped: not a higher-half aligned address>");
        return;
    }
    for i in 0..8u64 {
        let p = addr + i * 8;
        // SAFETY: caller has verified higher-half; we re-check above.  If the
        // page is not mapped we will re-fault and the bugcheck-reentry guard
        // halts — strictly better than corrupting later diagnostic output.
        let v = unsafe {
            crate::util::no_alloc_fmt::read_u64_volatile(p as *const u64)
        };
        crate::serial_println!("[KGP-DIAG]   [{:#x}] = {:#018x}", p, v);
    }
}

/// Called from the kernel-mode fatal-trap path (`exception_handler` in
/// `arch/x86_64/idt.rs`, just before `ke_bugcheck`) when the trap satisfies
/// the gate:
///   - `cs & 3 == 0` (kernel-mode)
///   - vector ∈ {13, 14} (#GP / #PF)
///   - `rip < 0x10000` (suspicious low-address kernel jump)
///
/// Emits the snapshot of the most-recently-exited sibling of the trapping
/// thread.  Bounded to `MAX_DUMPS_PER_BOOT` so a fault loop cannot flood
/// the serial path.
pub fn dump_for_kernel_trap(vector: u64, rip: u64, rsp: u64, error_code: u64) {
    // First-line gate: ignore unless vector is #GP/#PF AND the RIP is the
    // suspicious-low-address shape the dispatch is targeting.  Other fatal
    // kernel exceptions get the normal bugcheck banner only.
    if vector != 13 && vector != 14 {
        return;
    }
    if rip >= 0x10000 {
        return;
    }
    // Bounded emission.
    let prev = DUMPS_EMITTED.fetch_add(1, Ordering::Relaxed);
    if prev >= MAX_DUMPS_PER_BOOT {
        return;
    }

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let trap_tid = crate::proc::current_tid();
    let trap_pid = crate::proc::current_pid_lockless();

    crate::serial_println!(
        "[KGP-DIAG] === kernel-mode fatal trap at low RIP (dump #{}) ===",
        prev + 1
    );
    crate::serial_println!(
        "[KGP-DIAG] vec={} err={:#x} rip={:#x} rsp={:#x} cpu={} trap_tid={} trap_pid={}",
        vector, error_code, rip, rsp, cpu, trap_tid, trap_pid
    );

    // Dump the kernel-stack window around the IRET frame / saved-RIP slot.
    // For a #GP/#PF taken in kernel mode with no IST and no privilege change,
    // the CPU pushed SS:RSP:RFLAGS:CS:RIP:error_code onto the same kernel
    // stack — so `rsp` here is the post-push RSP.  Print [rsp .. rsp+64) so
    // the operator can see what the CPU read as the candidate return address
    // and which neighbouring slots look stack-frame-like.  See Intel SDM
    // Vol. 3A §6.14 (interrupt stack frame, no privilege change).
    dump_stack_window("trap_rsp_window", rsp);

    // Print the trapping thread's kernel-stack bookkeeping so the operator
    // can decide whether `rsp` is in the expected range.  Use `try_lock`:
    // acquiring THREAD_TABLE from a kernel-mode fatal-trap handler is
    // unsafe (per `proc/mod.rs` THREAD_TABLE doc): a syscall on this CPU
    // may already hold THREAD_TABLE, producing a non-recoverable same-CPU
    // re-entrant deadlock on the non-reentrant `spin::Mutex` and hanging
    // the kernel before `ke_bugcheck` runs.  On contention we skip the
    // trap-thread bookkeeping line — the producer-side snapshot below is
    // sufficient to discriminate the framing-falsifier.
    if let Some(threads) = crate::proc::THREAD_TABLE.try_lock() {
        if let Some(t) = threads.iter().find(|t| t.tid == trap_tid) {
            crate::serial_println!(
                "[KGP-DIAG] trap_thread: kstack=[{:#x}..{:#x}] size={:#x} state={:?} ctx_rsp={:#x}",
                t.kernel_stack_base,
                t.kernel_stack_base + t.kernel_stack_size,
                t.kernel_stack_size,
                t.state,
                t.context.rsp,
            );
            // Also dump the FIRST 8 qwords of the kernel stack (the
            // canary region) and the LAST 8 qwords below stack_top
            // (where switch_context_asm's saved RIP / callee-saveds live).
            if t.kernel_stack_size >= 64 {
                let near_top = t.kernel_stack_base + t.kernel_stack_size - 64;
                drop(threads); // release lock before second emission
                dump_stack_window("trap_thread_kstack_top-64", near_top);
                // INTENTIONAL FALL-THROUGH: producer-side lookup +
                // framing-falsifier line MUST follow.  Earlier revision
                // returned here, suppressing the line the dispatch exists
                // to emit.
            } else {
                drop(threads);
            }
        } else {
            drop(threads);
        }
    } else {
        crate::serial_println!(
            "[KGP-DIAG] trap_thread: <THREAD_TABLE held on this CPU; skipping>"
        );
    }

    // ── Producer-side lookup: most-recent exit in the same process ──
    match find_most_recent_in_pid(trap_pid) {
        LookupResult::Found(snap) => {
            crate::serial_println!(
                "[KGP-DIAG] recent_exit: seq={} pid={} tid={} cpu={} cr3={:#x} clear_addr={:#x} \
                 saved_context_rsp={:#x} kstack=[{:#x}..{:#x}]",
                snap.seq,
                snap.pid,
                snap.tid,
                snap.cpu,
                snap.cr3,
                snap.clear_addr,
                snap.saved_context_rsp,
                snap.kernel_stack_base,
                snap.kernel_stack_base + snap.kernel_stack_size,
            );
            // Framing-falsifier: does the dying sibling's kernel stack
            // overlap the trapping thread's RSP?
            let kbase = snap.kernel_stack_base;
            let ktop = kbase + snap.kernel_stack_size;
            let stack_overlap = rsp >= kbase && rsp < ktop;
            crate::serial_println!(
                "[KGP-DIAG] framing: trap_rsp_in_recent_exit_kstack={}",
                stack_overlap
            );
        }
        LookupResult::Empty => {
            crate::serial_println!(
                "[KGP-DIAG] recent_exit: <no producer-side snapshot for pid={}>",
                trap_pid
            );
        }
        LookupResult::Contended => {
            crate::serial_println!(
                "[KGP-DIAG] recent_exit: <RING contended>"
            );
        }
    }

    crate::serial_println!("[KGP-DIAG] === end ===");
}
