//! OOM (Out-Of-Memory) Killer
//!
//! When the PMM is exhausted and a physical-page allocation fails, the OOM
//! killer is invoked to recover memory by terminating the process with the
//! largest resident set.
//!
//! # Scoring policy
//!
//! Candidates are ranked by **resident** pages — the frames a process has
//! actually faulted in, read from the per-address-space counter in
//! [`crate::mm::rss`].  That is the quantity killing the process returns to
//! the allocator, and therefore the only one that answers the question the
//! killer is asking.
//!
//! This was previously the sum of all VMA *lengths*, i.e. the process's
//! virtual size.  A reservation costs no physical memory until it is touched,
//! so scoring by it selects whoever asked for the most address space rather
//! than whoever is using the most memory: a browser content process holding an
//! 8.5 GiB anonymous reservation scored "10.5 GiB RSS" on a 1 GiB machine and
//! was picked near-deterministically, whatever its real footprint.
//!
//! A frame mapped by several address spaces (fork-CoW, `MAP_SHARED`, SysV SHM)
//! counts once in each of them.  That is deliberate and is the standard
//! meaning of resident set size — the score estimates the pressure relieved by
//! killing this process, not exclusive ownership.
//!
//! Two kinds of candidate are refused rather than ranked, and the refusal is
//! implemented in [`select_victim`] — not left to a `max_by` that would in fact
//! return the highest PID once every score reached zero:
//!
//! * a process whose address space is **not tracked** (the resident-set table
//!   was saturated when it started) — never killed on the strength of a number
//!   nobody measured;
//! * a process measured at **zero resident pages** — killing it reclaims
//!   nothing, so the allocation fails either way and the process is spent for
//!   free.
//!
//! When that leaves no candidate the killer reclaims nothing and says so.  The
//! caller then fails an allocation, which is recoverable; there is no
//! "kill someone anyway" fallback, because every candidate such a fallback
//! could reach is one of the two cases above.
//!
//! Tie-breaking: among equal scores, the process with the highest PID is
//! targeted first (higher PID ≈ created more recently ≈ youngest, matching the
//! "most recent wins the kill" policy).
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

    // Score every eligible process while the table is held; rank afterwards.
    let candidates: alloc::vec::Vec<Candidate> = {
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
            .map(|p| Candidate {
                pid: p.pid,
                score: oom_score(p.vm_space.as_ref()),
                mapped: mapped_pages(p.vm_space.as_ref()),
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

    // `untracked` and `zero_resident` are counted separately: the first means
    // the resident-set table had no slot (a measurement gap), the second means
    // it measured the process and found no frames (a real answer).  Both are
    // refused by `select_victim`, but only the first says the decision was
    // made with incomplete information.
    let untracked = candidates.iter().filter(|c| c.score.is_none()).count();
    let zero_resident = candidates
        .iter()
        .filter(|c| c.score == Some(0))
        .count();

    let target_pid = match select_victim(&candidates) {
        Some(pid) => pid,
        None => {
            crate::serial_println!(
                "[OOM] no candidate holds reclaimable memory (needed={} frames) — \
                 failing the allocation; candidates={} untracked={} zero_resident={} \
                 rss_slots_full={}",
                needed_frames,
                candidates.len(),
                untracked,
                zero_resident,
                crate::mm::rss::attach_failures(),
            );
            return None;
        }
    };

    // Both figures are logged because their ratio is the whole point: a victim
    // with a large `mapped` and a small `rss` is one that reserved address
    // space it never touched, and killing it frees `rss`, not `mapped`.
    let victim = candidates
        .iter()
        .find(|c| c.pid == target_pid)
        .copied()
        .expect("select_victim returns a pid from the list it was given");
    crate::serial_println!(
        "[OOM] killed pid={} rss={} pages ({} KiB) mapped={} pages need={} pages \
         candidates={} untracked={} zero_resident={} rss_slots_full={}",
        target_pid,
        victim.score.unwrap_or(0),
        victim.score.unwrap_or(0) * 4,
        victim.mapped,
        needed_frames,
        candidates.len(),
        untracked,
        zero_resident,
        crate::mm::rss::attach_failures(),
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

/// **The** OOM victim score: resident pages, in 4 KiB units.
///
/// A lock-free read of the per-address-space counter maintained by `mm::rss`
/// at every leaf-PTE install and clear.  Deliberately *not* a page-table walk:
/// this runs when the machine is already out of frames, and the whole point of
/// the `PROCESS_TABLE` handling above is to keep this path short and
/// non-blocking.
///
/// `None` means "not measured" and is distinct from `Some(0)`:
///
/// * `None` — no address space (a kernel thread), or the resident-set table
///   had no slot for this one.  [`select_victim`] refuses to rank it.
/// * `Some(0)` — measured, and it holds no frames.
///
/// Taking this from `vm.areas` lengths instead is the defect this module was
/// changed to fix; see the module-level note.  Test 753 drives this exact
/// function against an address space whose virtual size and resident set
/// differ by four orders of magnitude, so that substitution fails the suite.
pub fn oom_score(vm_space: Option<&crate::mm::vma::VmSpace>) -> Option<u64> {
    crate::mm::rss::resident_pages(vm_space?.cr3)
}

/// Sum of the process's VMA lengths in pages — its *virtual* size.
///
/// Explicitly **not** the score (see [`oom_score`]); carried alongside it so
/// the gap between what a process reserved and what it actually touched is
/// legible in the one line the killer emits.
pub fn mapped_pages(vm_space: Option<&crate::mm::vma::VmSpace>) -> u64 {
    match vm_space {
        None => 0,
        Some(vm) => vm
            .areas
            .iter()
            .map(|vma| vma.length / crate::mm::pmm::PAGE_SIZE as u64)
            .sum(),
    }
}

/// One scored OOM candidate.
#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    pub pid: Pid,
    /// [`oom_score`] for this process.
    pub score: Option<u64>,
    /// [`mapped_pages`], carried for the log line only — never ranked on.
    pub mapped: u64,
}

/// Select the OOM victim from a scored candidate list.
///
/// **This is the production selector**: [`invoke_oom_killer`] calls exactly
/// this function, so a test that drives it is testing the decision the machine
/// actually makes.  It previously existed twice — an inline `max_by` in the
/// killer and a `score_pick` helper that only tests called — which let the
/// tested copy stay correct while the live one regressed.  There is now one.
///
/// Two kinds of candidate are refused outright rather than ranked, which is
/// where the module's "never killed on the strength of a number nobody
/// measured" guarantee is actually implemented:
///
/// * **untracked** (`score == None`) — nothing measured this address space, so
///   choosing it would be a guess.
/// * **zero-resident** (`score == Some(0)`) — it holds no frames, so killing
///   it reclaims nothing and the allocation that triggered the OOM fails
///   anyway.  Spending a process for no memory is strictly worse than failing
///   the allocation.
///
/// If that leaves nothing the answer is `None` and the caller fails the
/// allocation, which is recoverable.  There is deliberately **no** "kill
/// someone anyway" fallback, because every candidate it could fall back to is
/// one of the two cases above.  A plain `max_by` over the whole list has the
/// opposite behaviour: with every score zero it silently returns the highest
/// PID.
///
/// Among the rest the largest resident set wins; ties go to the highest PID
/// (youngest by creation order).
pub fn select_victim(candidates: &[Candidate]) -> Option<Pid> {
    candidates
        .iter()
        .filter_map(|c| match c.score {
            Some(pages) if pages > 0 => Some((c.pid, pages)),
            _ => None,
        })
        .max_by(|(pid_a, rss_a), (pid_b, rss_b)| rss_a.cmp(rss_b).then(pid_a.cmp(pid_b)))
        .map(|(pid, _)| pid)
}
