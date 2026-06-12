//! Userspace RIP sampler — periodically dump the user RIP, RSP, RBP and a
//! frame-pointer chain walk for any thread that has been preempted while
//! running in Ring 3 without issuing a syscall for several seconds.
//!
//! # Why
//!
//! Some Mozilla wedges leave the main thread (pid=1, tid=1) spinning in
//! userspace on a condition variable or POSIX semaphore that the kernel
//! cannot observe — the lock is owned entirely by the userspace runtime
//! and never reaches the futex ABI.  The kernel's heartbeat shows a
//! plateau in `sc=` (syscall count) and there is no clue which userspace
//! function is parked.  This module emits a periodic `[SAMPLE]` line
//! with the interrupted user RIP and a short RBP chain so the offending
//! libxul function can be identified offline with `addr2line` / `objdump`.
//!
//! # When it fires
//!
//! From the LAPIC timer ISR every [`SAMPLE_INTERVAL_TICKS`] ticks (~5 s at
//! 100 Hz), provided that:
//!   1. The interrupted context was Ring 3 (CS & 3 == 3) — kernel-mode
//!      preemptions are ignored.
//!   2. The current TID is non-zero — idle threads are skipped.
//!   3. The current TID has been the same across the last
//!      [`SILENT_THRESHOLD_TICKS`] without issuing a syscall.
//!
//! # Cost
//!
//! Behind `firefox-test`.  Hot path is a single atomic load + branch in
//! the syscall dispatch (`record_syscall`) and the timer ISR
//! (`maybe_sample`).  The walk itself is rate-limited by the
//! "consecutive silent ticks" check, so a healthy thread issuing
//! syscalls regularly never pays the walk cost.
//!
//! # Safety
//!
//! The sampler runs in interrupt context with IF=0.  It MUST NOT take
//! any kernel mutex, and MUST NOT fault.  All user-memory reads go
//! through [`crate::mm::vmm::virt_to_phys_in`] which walks the page
//! tables in software — an unmapped page returns `None` rather than
//! faulting on the in-flight read.  See Intel SDM Vol 3A §4.5 for the
//! 4-level paging walk used by the resolver.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::apic::MAX_CPUS;
use crate::arch::x86_64::idt::InterruptFrame;

/// Tick interval between consecutive sample emissions for a given thread.
/// 500 ticks at 100 Hz = ~5 s.
const SAMPLE_INTERVAL_TICKS: u64 = 500;

/// Number of ticks of "no syscall from this thread" required before the
/// sampler considers the thread to be parked in userspace.
/// 500 ticks = ~5 s.  Long enough that ordinary CPU-bound work (font cache
/// build, ICU init) does not trigger; short enough that a real wedge is
/// caught well before the 10-minute firefox-test watchdog limit.
const SILENT_THRESHOLD_TICKS: u64 = 500;

/// Per-Tid syscall-activity table.  Direct-mapped by `tid % TID_SLOTS`.
///
/// Each slot is a `(tid, last_syscall_tick, last_sample_tick)` triple of
/// relaxed atomics — the entire structure is lock-free.  The `tid` field
/// disambiguates which thread last wrote to the slot, since two thread
/// IDs that hash to the same slot would otherwise race on the tick.  When
/// the slot's TID does not match the thread we're sampling, we treat the
/// slot as "no data for this thread" and skip.
///
/// 256 slots covers a typical Mozilla worker pool (~150 threads) without
/// frequent collisions on the dense low-TID range that the most interesting
/// threads (pid=1 tid=1, the renderer main) occupy.  On collision the
/// behaviour is benign: the sampler simply waits one more "real" syscall
/// from the colliding thread before producing useful output.
const TID_SLOTS: usize = 256;

/// One slot in the syscall-activity table.
///
/// `last_syscall_nr` and `last_syscall_arg0` are written alongside
/// `last_syscall_tick` so that diagnostic readers (kdb `thread-park-audit`)
/// can answer "which syscall is this TID parked inside, and what is the
/// primary argument" without an expensive walk of the per-PID syscall ring.
/// Writers store nr/arg0 *before* the tick, so a reader that sees a fresh
/// tick is guaranteed to see the matching nr and arg0 (Release/Acquire-free
/// here because the tid field already publishes ownership of the slot; the
/// nr/arg0 store-order is just "store these first so they precede tick").
#[repr(C, align(64))] // cache-line aligned to avoid false sharing
struct TidSlot {
    tid: AtomicU64,
    last_syscall_tick: AtomicU64,
    last_sample_tick: AtomicU64,
    /// Syscall number of the most recent dispatch entry for this slot's TID.
    /// `u64::MAX` means "no syscall recorded yet for the current slot owner".
    last_syscall_nr: AtomicU64,
    /// First argument (RDI on x86_64) of the most recent syscall.  For
    /// poll/epoll_wait this is the fd-array pointer or epfd; for read/write
    /// it is the fd; for futex it is the uaddr.  Diagnostic-only.
    last_syscall_arg0: AtomicU64,
    /// Second argument (RSI on x86_64) of the most recent syscall.  For
    /// poll(2) this is `nfds` — together with `last_syscall_arg0` (the
    /// pollfd array pointer) it lets the kdb `user-mem` op read and decode
    /// the exact live pollfd set of a parked poller.  Diagnostic-only.
    last_syscall_arg1: AtomicU64,
    /// Last user-mode RIP observed for this TID by the per-tick sampler.
    /// Updated every Ring-3 timer-ISR tick, regardless of the silent-for
    /// threshold that gates the serial `[SAMPLE]` emission.  Stays at 0
    /// for kernel threads and TIDs that have never run in Ring 3 under
    /// this slot.  Used by kdb `proc` / `proc-list` / `rip-trace` to
    /// surface where a long-running thread is currently parked in
    /// userspace (cf. `user_entry_rip` which is the frozen entry RIP).
    last_user_rip: AtomicU64,
    /// Last user-mode RBP observed alongside `last_user_rip`.  Same update
    /// cadence and consumer set.  Required by `rip-trace` to walk the
    /// frame-pointer chain off-tick on the kdb thread without taking any
    /// per-thread lock.
    last_user_rbp: AtomicU64,
    /// Last user-mode RSP observed alongside `last_user_rip`.  Required by
    /// `rip-trace`'s RSP-scan fallback for binaries built with
    /// `-fomit-frame-pointer` (the firefox-bin/libxul case as of 2026-05):
    /// when the RBP-chain walk terminates at depth ≤ 1 because RBP is being
    /// used as a general-purpose register, the scanner falls back to
    /// inspecting words on the user stack for canonical user-code addresses
    /// — the same heuristic the `[SC-USTACK]` exit-time dumper has used
    /// since 2026-04.
    last_user_rsp: AtomicU64,
    /// Monotonically incremented every time `last_user_rip` is updated.
    /// `rip-trace` reads this between successive samples to decide whether
    /// the kernel has produced a fresh observation since the previous
    /// loop iteration, so the histogram counts distinct ticks rather than
    /// repeats of the same sample.
    rip_sample_seq: AtomicU64,
}

static TID_TABLE: [TidSlot; TID_SLOTS] = [
    const { TidSlot {
        tid: AtomicU64::new(0),
        last_syscall_tick: AtomicU64::new(u64::MAX),
        last_sample_tick: AtomicU64::new(0),
        last_syscall_nr: AtomicU64::new(u64::MAX),
        last_syscall_arg0: AtomicU64::new(0),
        last_syscall_arg1: AtomicU64::new(0),
        last_user_rip: AtomicU64::new(0),
        last_user_rbp: AtomicU64::new(0),
        last_user_rsp: AtomicU64::new(0),
        rip_sample_seq: AtomicU64::new(0),
    } }; TID_SLOTS
];

#[inline]
fn slot_for(tid: u64) -> &'static TidSlot {
    &TID_TABLE[(tid as usize) & (TID_SLOTS - 1)]
}

/// Record a syscall entry: stamp the calling thread's last-syscall tick,
/// the syscall number, and the first user argument.
///
/// Called from [`crate::syscall::dispatch`] on every Linux/Aether syscall.
/// Lock-free: four relaxed atomic stores in the common case (slot already
/// owned by this TID).  Safe from any context where `current_tid()` and
/// `cpu_index()` are valid — the syscall entry runs at CPL 0 on the
/// thread's own kernel stack, so this trivially holds.
///
/// Store order: tid → nr → arg0 → tick.  A reader that observes a fresh
/// tick is guaranteed to see the matching nr/arg0 even under Relaxed
/// ordering because all four atomics share a cache line (Intel SDM Vol 3A
/// §8.2.3: WB total-store-order for same-line single-quadword writes).
#[inline]
pub fn record_syscall(tid: u64, tick: u64, nr: u64, arg0: u64, arg1: u64) {
    let slot = slot_for(tid);
    // Claim the slot (no CAS — last writer wins on hash collisions).
    slot.tid.store(tid, Ordering::Relaxed);
    slot.last_syscall_nr.store(nr, Ordering::Relaxed);
    slot.last_syscall_arg0.store(arg0, Ordering::Relaxed);
    slot.last_syscall_arg1.store(arg1, Ordering::Relaxed);
    slot.last_syscall_tick.store(tick, Ordering::Relaxed);
}

/// Snapshot of one TID slot for diagnostic readers (kdb).
///
/// `last_user_rip` / `last_user_rbp` / `rip_sample_seq` are populated by
/// the per-tick sampler in `maybe_sample` on every Ring-3 preemption.
/// They reflect the *current* user-mode RIP of the slot's TID, in
/// contrast to `Thread::user_entry_rip` which is the immutable entry
/// trampoline RIP set once at thread creation.  Both fields read 0 on a
/// slot that has only ever held a kernel-mode thread.
#[derive(Clone, Copy)]
pub struct TidSyscallSample {
    pub tid: u64,
    pub last_syscall_tick: u64,
    pub last_syscall_nr: u64,
    pub last_syscall_arg0: u64,
    pub last_syscall_arg1: u64,
    pub last_user_rip: u64,
    pub last_user_rbp: u64,
    pub rip_sample_seq: u64,
}

/// Read the per-TID syscall sample.  Returns `Some` only when the slot is
/// owned by the requested `tid` (TID-hash collisions return `None` rather
/// than fabricating a wrong attribution).  Used by kdb `thread-park-audit`
/// to classify what each thread is parked inside, and by kdb `rip-trace`
/// to poll the current user RIP across a sampling window.
pub fn read_sample(tid: u64) -> Option<TidSyscallSample> {
    let slot = slot_for(tid);
    let slot_tid = slot.tid.load(Ordering::Relaxed);
    if slot_tid != tid { return None; }
    // Tick last (see store order above).  If a writer is mid-update, we
    // may see a stale tick paired with new nr/arg0 — harmless for diag.
    let last_syscall_nr = slot.last_syscall_nr.load(Ordering::Relaxed);
    let last_syscall_arg0 = slot.last_syscall_arg0.load(Ordering::Relaxed);
    let last_syscall_arg1 = slot.last_syscall_arg1.load(Ordering::Relaxed);
    let last_syscall_tick = slot.last_syscall_tick.load(Ordering::Relaxed);
    let last_user_rip = slot.last_user_rip.load(Ordering::Relaxed);
    let last_user_rbp = slot.last_user_rbp.load(Ordering::Relaxed);
    let rip_sample_seq = slot.rip_sample_seq.load(Ordering::Relaxed);
    if last_syscall_tick == u64::MAX && rip_sample_seq == 0 { return None; }
    Some(TidSyscallSample {
        tid,
        last_syscall_tick,
        last_syscall_nr,
        last_syscall_arg0,
        last_syscall_arg1,
        last_user_rip,
        last_user_rbp,
        rip_sample_seq,
    })
}

/// Read just the per-TID user-RIP snapshot for `rip-trace` polling.
///
/// Returns `(rip, rbp, seq)` if the slot is owned by `tid` and the RIP
/// has been written at least once; `None` otherwise.  The returned
/// `seq` lets the caller distinguish a freshly-published sample from a
/// repeat read of the previous one across loop iterations.  Pure
/// atomic loads — safe from any context.
pub fn read_user_rip(tid: u64) -> Option<(u64, u64, u64)> {
    let slot = slot_for(tid);
    if slot.tid.load(Ordering::Relaxed) != tid { return None; }
    let seq = slot.rip_sample_seq.load(Ordering::Relaxed);
    if seq == 0 { return None; }
    // Read seq → rip → rbp → seq again.  If the second read sees a
    // newer seq the writer ran between our two loads; bail (caller
    // will retry on the next outer-loop iteration).
    let rip = slot.last_user_rip.load(Ordering::Relaxed);
    let rbp = slot.last_user_rbp.load(Ordering::Relaxed);
    let seq2 = slot.rip_sample_seq.load(Ordering::Relaxed);
    if seq != seq2 { return None; }
    Some((rip, rbp, seq))
}

/// Read the per-TID `(rip, rbp, rsp, seq)` snapshot.  Same atomic-loads
/// contract as `read_user_rip` (returns `None` if a writer interleaved or
/// the slot is owned by a different TID); used by `rip-trace`'s RSP-scan
/// fallback for `-fomit-frame-pointer` binaries where the RBP chain
/// terminates immediately.  See `op_rip_trace` for the scan heuristic.
pub fn read_user_rip_rsp(tid: u64) -> Option<(u64, u64, u64, u64)> {
    let slot = slot_for(tid);
    if slot.tid.load(Ordering::Relaxed) != tid { return None; }
    let seq = slot.rip_sample_seq.load(Ordering::Relaxed);
    if seq == 0 { return None; }
    let rip = slot.last_user_rip.load(Ordering::Relaxed);
    let rbp = slot.last_user_rbp.load(Ordering::Relaxed);
    let rsp = slot.last_user_rsp.load(Ordering::Relaxed);
    let seq2 = slot.rip_sample_seq.load(Ordering::Relaxed);
    if seq != seq2 { return None; }
    Some((rip, rbp, rsp, seq))
}

/// Software walk a user-VA `u64` under `cr3`.  Exposed for kdb
/// `rip-trace` so the kdb thread (running on its own kernel stack) can
/// walk a *foreign* thread's frame-pointer chain without taking any
/// per-thread lock.  Returns `None` on unmapped, kernel-half, or
/// cross-page-with-the-second-page-unmapped reads — never faults.  See
/// Intel SDM Vol 3A §4.5 for the 4-level paging walk.
pub fn read_user_u64_at(cr3: u64, va: u64) -> Option<u64> {
    read_user_u64(cr3, va)
}

/// Maybe emit a userspace RIP sample from the timer ISR.
///
/// `frame` is the IRETQ-frame the CPU pushed when interrupting the user
/// thread; `saved_rbp` is the value of RBP that the timer-ISR naked stub
/// pushed onto the kernel stack just before calling `timer_tick`.
///
/// # Caller contract
///
/// Runs in interrupt context with IF=0 on the kernel stack of the
/// interrupted thread.  The function takes no kernel locks (it uses
/// `current_pid_lockless` and per-CPU atomics) and performs no
/// allocation.  User-memory reads use software page-table walks and
/// return `None` on unmapped pages — they cannot fault.
pub fn maybe_sample(tick: u64, frame: &InterruptFrame, saved_rbp: u64) {
    // Only sample on Ring 3 preemptions.  Kernel-mode preemptions surface
    // their own diagnostics through the bugcheck / watchdog paths.
    if frame.cs & 3 != 3 {
        return;
    }

    let cpu = crate::arch::x86_64::apic::cpu_index();
    if cpu >= MAX_CPUS { return; }

    let tid = crate::proc::current_tid();
    if tid == 0 {
        // Idle thread — never sample.
        return;
    }

    // Has this thread been continuously running in Ring 3 for
    // SILENT_THRESHOLD_TICKS without issuing a syscall?  The per-Tid slot
    // is direct-mapped by tid hash; if the slot holds a different TID
    // (collision or never-recorded), skip — we'll sample once the thread
    // issues at least one syscall.
    let slot = slot_for(tid);
    let slot_tid = slot.tid.load(Ordering::Relaxed);
    if slot_tid != tid {
        return;
    }

    // ── Always-on lightweight RIP/RBP publish ────────────────────────
    //
    // Publish the interrupted user RIP+RBP on EVERY Ring-3 tick,
    // independent of the silent-for / interval gates that throttle the
    // serial `[SAMPLE]` block below.  This is the data source for
    // kdb `rip-trace` (and the corrected `proc`/`proc-list` "current
    // user RIP" column).  Two relaxed atomic stores per tick on the
    // hot path; the cache line is already dirty in L1 because the slot
    // owns the syscall counters this same TID just bumped.
    //
    // Store order: rip → rbp → seq (Release).  A reader that observes
    // a fresh `seq` is guaranteed to see the matching rip/rbp because
    // all three live in the same cache line (Intel SDM Vol 3A §8.2.3
    // total-store-order for same-line writes); the Release on `seq`
    // additionally orders against any future kdb-thread Acquire.
    slot.last_user_rip.store(frame.rip, Ordering::Relaxed);
    slot.last_user_rbp.store(saved_rbp, Ordering::Relaxed);
    slot.last_user_rsp.store(frame.rsp, Ordering::Relaxed);
    slot.rip_sample_seq.fetch_add(1, Ordering::Release);

    let last_sc   = slot.last_syscall_tick.load(Ordering::Relaxed);
    let last_smpl = slot.last_sample_tick.load(Ordering::Relaxed);
    if last_sc == u64::MAX {
        return;
    }
    let silent_for = tick.saturating_sub(last_sc);
    if silent_for < SILENT_THRESHOLD_TICKS {
        return;
    }
    // Throttle: at most one block per SAMPLE_INTERVAL_TICKS.
    if tick.saturating_sub(last_smpl) < SAMPLE_INTERVAL_TICKS {
        return;
    }
    slot.last_sample_tick.store(tick, Ordering::Relaxed);

    // Read FS_BASE for TLS context.  RDMSR is safe at CPL 0; this is the
    // active thread's FS.base because the scheduler restored it on its
    // last switch-in.  Intel SDM Vol 3A §4.10: IA32_FS_BASE MSR 0xC000_0100.
    // SAFETY: RDMSR with the architectural FS.base MSR is always safe at
    // CPL 0; the timer ISR runs at CPL 0.
    let fs_base = unsafe { crate::hal::rdmsr(0xC000_0100) };
    let pid = crate::proc::current_pid_lockless();

    crate::serial_println!(
        "[SAMPLE] tid={} pid={} cpu={} tick={} silent_for={} \
         user_rip={:#018x} user_rsp={:#018x} rbp={:#018x} fs_base={:#018x}",
        tid, pid, cpu, tick, silent_for,
        frame.rip, frame.rsp, saved_rbp, fs_base,
    );

    // Walk the RBP chain in user memory.  Each frame in a -fno-omit-frame-
    // pointer build follows the System V x86-64 convention:
    //   [rbp + 0] = saved caller RBP
    //   [rbp + 8] = return RIP into caller
    // We bail on the first unmapped slot, on misaligned / kernel-half
    // pointers, and on any descent (cycle guard).
    //
    // Use the active CR3 to translate user VAs — we are on the same page
    // tables as the interrupted thread because the timer ISR did not
    // switch CR3.
    let cr3 = read_cr3();
    walk_user_rbp_chain(cr3, saved_rbp);
}

/// Walk and print up to 5 frames of the user RBP chain.
fn walk_user_rbp_chain(cr3: u64, start_rbp: u64) {
    const MAX_FRAMES: u32 = 5;
    let mut cur = start_rbp;
    for i in 0..MAX_FRAMES {
        if cur == 0 || cur < 0x1000 { break; }
        if cur >= astryx_shared::KERNEL_VIRT_BASE { break; }
        if cur & 0x7 != 0 { break; }
        let saved_rbp = match read_user_u64(cr3, cur) {
            Some(v) => v,
            None => break,
        };
        let saved_rip = match read_user_u64(cr3, cur.wrapping_add(8)) {
            Some(v) => v,
            None => break,
        };
        crate::serial_println!(
            "[SAMPLE] frame[{}] rbp={:#018x} rip={:#018x}",
            i, saved_rbp, saved_rip
        );
        // Cycle / descent guard: frame pointers walk UP the stack.
        if saved_rbp <= cur { break; }
        cur = saved_rbp;
    }
}

/// Page-fault-safe read of a u64 from user VA `va` under page table `cr3`.
/// Mirrors `crate::syscall::ring::read_user_u64_safe` but is duplicated
/// here to keep that helper private to its module.  Software walks the
/// 4-level page tables — see Intel SDM Vol 3A §4.5.
fn read_user_u64(cr3: u64, va: u64) -> Option<u64> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

    if va >= astryx_shared::KERNEL_VIRT_BASE { return None; }
    let end = va.checked_add(8)?;
    if end > astryx_shared::KERNEL_VIRT_BASE { return None; }

    let phys0 = crate::mm::vmm::virt_to_phys_in(cr3, va)?;
    let page_off = va & 0xFFF;
    if page_off + 8 > 0x1000 {
        // Cross-page: resolve second page once, splice the two halves.
        let va_next = (va & !0xFFF).wrapping_add(0x1000);
        let phys_next = crate::mm::vmm::virt_to_phys_in(cr3, va_next)?;
        let first_len = (0x1000 - page_off) as usize;
        let mut bytes = [0u8; 8];
        unsafe {
            for i in 0..first_len {
                bytes[i] = core::ptr::read_volatile(
                    (PHYS_OFF + phys0 + i as u64) as *const u8);
            }
            for i in first_len..8 {
                bytes[i] = core::ptr::read_volatile(
                    (PHYS_OFF + phys_next + (i - first_len) as u64) as *const u8);
            }
        }
        return Some(u64::from_le_bytes(bytes));
    }
    unsafe {
        Some(core::ptr::read_unaligned((PHYS_OFF + phys0) as *const u64))
    }
}

#[inline]
fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3,
                         options(nomem, nostack, preserves_flags));
    }
    cr3
}
