//! OOM (Out-Of-Memory) Killer
//!
//! When the PMM is exhausted and a physical-page allocation fails, the OOM
//! killer is invoked to recover memory by terminating the process with the
//! largest resident set.
//!
//! # Scoring policy
//! RSS is computed as the sum of all VMA lengths divided by PAGE_SIZE.  VMAs
//! are walked from the process's `VmSpace::areas` list; every mapped region
//! counts equally regardless of backing type, because we don't have per-page
//! resident/swapped tracking yet.  This over-counts a little (includes VMAs
//! that haven't been faulted in yet) but is conservative in the right
//! direction: we'd rather kill a process that *has* a large address space than
//! one that doesn't.
//!
//! Tie-breaking: among equal RSS scores, the process with the highest PID is
//! targeted first (higher PID ≈ created more recently ≈ youngest, matching
//! the "most recent wins the kill" policy from Linux).
//!
//! # Protected PIDs
//! - PID 0  — idle / kernel process.
//! - PID 1  — init / first user process.
//! - Any process whose `vm_space` is `None` — kernel threads.
//!
//! # Lock ordering
//! This function acquires `PROCESS_TABLE` lock exactly once, reads it, then
//! releases it before calling `signal::kill`, which acquires the same lock
//! internally.  Never holds `PROCESS_TABLE` and calls into code that takes
//! `THREAD_TABLE` at the same time.
//!
//! The `PROCESS_TABLE` acquisition is **bounded and non-blocking** — see
//! [`invoke_oom_killer`] for why a plain `lock()` here deadlocks the machine.

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use crate::proc::Pid;

/// Bound on the `PROCESS_TABLE` acquisition retry loop in
/// [`invoke_oom_killer`].  Sized like the TLB shootdown ACK bound in
/// `mm::tlb::shootdown_range_inner`: long enough that ordinary contention
/// (a peer holding `PROCESS_TABLE` for a table walk) always resolves inside
/// it, short enough that an unresolvable acquisition terminates instead of
/// wedging the CPU.
const PROCESS_TABLE_ACQUIRE_BOUND: u32 = 10_000_000;

/// Count of OOM invocations that gave up because `PROCESS_TABLE` could not be
/// acquired within [`PROCESS_TABLE_ACQUIRE_BOUND`].  A non-zero value means
/// the allocator failed closed rather than reclaiming; read by Test 750.
static OOM_LOCK_GIVEUPS: AtomicU64 = AtomicU64::new(0);

/// Snapshot of [`OOM_LOCK_GIVEUPS`].
pub fn lock_giveup_count() -> u64 {
    OOM_LOCK_GIVEUPS.load(Ordering::Relaxed)
}

/// Invoke the OOM killer to reclaim memory.
///
/// Selects the highest-RSS non-init user process, delivers `SIGKILL`, and
/// returns the killed PID.  Returns `None` if no eligible target exists, or
/// if `PROCESS_TABLE` could not be acquired within the retry bound.
///
/// `needed_frames` is purely informational — logged for diagnostics.
///
/// # Why `PROCESS_TABLE` is acquired non-blockingly
///
/// The sole production caller is `pmm::alloc_page`'s exhaustion slow path, and
/// `alloc_page` is reachable from contexts that **already hold**
/// `PROCESS_TABLE`, as well as from the `#PF` handler, which runs on an
/// interrupt gate with IF=0 (Intel SDM Vol. 3A §6.8.1/§6.12.1).  Because
/// `PROCESS_TABLE` is a plain non-reentrant spinlock, a blocking `lock()` here
/// can never complete in either case:
///
/// * **Self-deadlock** — the faulting/allocating thread is itself the holder,
///   so the byte it spins on can only be released by code it will never reach.
/// * **IF=0 convoy** — a peer CPU holding `PROCESS_TABLE` across a TLB
///   shootdown cannot get its ACK from a CPU that is IF-masked inside the
///   page-fault handler, so neither side progresses.  This is the same class
///   already closed for `mm_sem` by `mm::vma::mm_sem_read_draining` and for
///   the write-fault path by dropping `PROCESS_TABLE` before its shootdown.
///
/// Either way the OOM killer never reaches its first statement, no process is
/// ever killed, no memory is reclaimed, and every subsequent allocator caller
/// piles onto the same lock byte until the machine is wedged in Ring 0.
///
/// The acquisition is therefore two-tier:
///
/// 1. **Fast reject** when this CPU already owns `PROCESS_TABLE`
///    (`proc::process_table_held_here`).  This is the dominant shape, not a
///    corner case, so it must not be handled by spinning: the anonymous
///    demand-fault arm holds the lock across the fault, and waiting out the
///    bound there would burn ~1.4 s with interrupts disabled on **every**
///    IF=0 allocation failure before failing anyway.
/// 2. **Bounded retry** otherwise, mirroring `mm_sem_read_draining`:
///    `try_lock` while servicing this CPU's own incoming shootdown slot on
///    every iteration, so an IF=0 caller does not present as dead weight to a
///    peer's shootdown while it waits.  The bound is generous because, with
///    tier 1 in place, reaching it means a peer genuinely is not releasing.
///
/// Both tiers **fail closed** — returning `None` propagates an ordinary
/// allocation failure to the caller, which is recoverable; a wedge is not.
///
/// Note what this does and does not buy: reclamation from the fault path is
/// **not** restored by tier 1 — a caller holding the lock still cannot read
/// the table, so the frame is still not allocated and the process still dies.
/// What changes is that it dies promptly and legibly instead of taking the
/// machine down with it.
pub fn invoke_oom_killer(needed_frames: usize) -> Option<Pid> {
    // Collect (pid, rss_pages) for all eligible processes.  We take the lock,
    // do a read-only walk, collect into a small local vec, and release before
    // calling kill() (which re-acquires PROCESS_TABLE).
    // Fast reject: this CPU already owns PROCESS_TABLE.  There is nothing to
    // wait for — the byte can only be released by code this call sits
    // underneath — so spinning out the full retry bound would burn ~1.4 s with
    // interrupts disabled and then fail anyway.  This is the DOMINANT shape,
    // not a corner case: `handle_page_fault`'s anonymous demand-fault arm holds
    // PROCESS_TABLE across the fault, so every IF=0 allocation failure arrives
    // here already owning it.  Returning immediately turns a 1.4 s
    // interrupts-disabled stall into a no-op.
    if crate::proc::process_table_held_here() {
        let total = OOM_LOCK_GIVEUPS.fetch_add(1, Ordering::Relaxed) + 1;
        if total <= 8 || total % 1024 == 0 {
            crate::serial_println!(
                "[OOM] caller already owns PROCESS_TABLE (needed={} frames) — cannot reclaim \
                 from here; failing the allocation; giveups={}",
                needed_frames, total,
            );
        }
        return None;
    }

    let candidates: alloc::vec::Vec<(Pid, u64)> = {
        let procs = {
            let mut guard = None;
            let mut iters: u32 = 0;
            while iters < PROCESS_TABLE_ACQUIRE_BOUND {
                if let Some(g) = crate::proc::PROCESS_TABLE.try_lock() {
                    guard = Some(g);
                    break;
                }
                // Lock-free and EOI-free, so it is safe with interrupts
                // disabled while this CPU holds none of the locks it is
                // waiting on.  See `mm::tlb::drain_incoming_shootdown_if_smp`.
                crate::mm::tlb::drain_incoming_shootdown_if_smp();
                core::hint::spin_loop();
                iters += 1;
            }
            match guard {
                Some(g) => g,
                None => {
                    let total = OOM_LOCK_GIVEUPS.fetch_add(1, Ordering::Relaxed) + 1;
                    crate::serial_println!(
                        "[OOM] PROCESS_TABLE unacquirable after {} iters (needed={} frames) \
                         — failing the allocation instead of wedging; giveups={}",
                        PROCESS_TABLE_ACQUIRE_BOUND, needed_frames, total,
                    );
                    return None;
                }
            }
        };

        procs
            .iter()
            .filter(|p| {
                // Skip PID 0 (idle/kernel) and PID 1 (init).
                if p.pid == 0 || p.pid == 1 {
                    return false;
                }
                // Skip kernel threads — they have no user address space.
                if p.vm_space.is_none() {
                    return false;
                }
                // Skip zombies — already dying; killing them again is pointless.
                if p.state == crate::proc::ProcessState::Zombie {
                    return false;
                }
                true
            })
            .map(|p| {
                let rss = rss_pages(p);
                (p.pid, rss)
            })
            .collect()
    }; // PROCESS_TABLE lock released here

    if candidates.is_empty() {
        crate::serial_println!(
            "[OOM] no eligible targets (needed={} frames) — cannot recover",
            needed_frames
        );
        return None;
    }

    // Pick the candidate with the maximum RSS.  On ties, prefer the highest
    // PID (youngest process by creation order).
    let (target_pid, target_rss) = candidates
        .iter()
        .copied()
        .max_by(|(pid_a, rss_a), (pid_b, rss_b)| {
            rss_a.cmp(rss_b).then(pid_a.cmp(pid_b))
        })
        .expect("non-empty candidates must yield a maximum");

    crate::serial_println!(
        "[OOM] killed pid={} rss={} pages, need={} pages",
        target_pid, target_rss, needed_frames
    );

    // Deliver SIGKILL.  signal::kill() acquires PROCESS_TABLE internally.
    let result = crate::signal::kill(target_pid, crate::signal::SIGKILL);
    if result != 0 {
        crate::serial_println!(
            "[OOM] WARN: kill(pid={}, SIGKILL) returned {} — process may have already exited",
            target_pid, result
        );
    }

    Some(target_pid)
}

/// Compute the RSS (resident set size) of a process in pages.
///
/// Sums the lengths of all VMAs in the process's virtual address space and
/// converts to pages.  This is an approximation: it counts all *mapped*
/// regions, not only physically-present pages, because AstryxOS does not
/// yet maintain a per-page present/absent bitmap.  The approximation is
/// acceptable for OOM scoring — a process with a large mapped footprint is
/// a good kill candidate whether or not every page has been faulted in.
fn rss_pages(proc: &crate::proc::Process) -> u64 {
    match proc.vm_space.as_ref() {
        None => 0,
        Some(vm) => {
            vm.areas
                .iter()
                .map(|vma| vma.length / crate::mm::pmm::PAGE_SIZE as u64)
                .sum()
        }
    }
}

// ── Unit-testable scoring helpers ───────────────────────────────────────────
//
// The test runner exercises these through direct calls rather than through the
// full OOM path (which requires a running PMM and is hard to exhaust safely).

/// Score a slice of (pid, rss) pairs and return the winning PID.
///
/// Exported for testing.  Production callers should use `invoke_oom_killer`.
pub fn score_pick(candidates: &[(Pid, u64)]) -> Option<Pid> {
    candidates
        .iter()
        .copied()
        .max_by(|(pid_a, rss_a), (pid_b, rss_b)| {
            rss_a.cmp(rss_b).then(pid_a.cmp(pid_b))
        })
        .map(|(pid, _rss)| pid)
}
