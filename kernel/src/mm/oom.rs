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

extern crate alloc;

use crate::proc::Pid;

/// Invoke the OOM killer to reclaim memory.
///
/// Selects the highest-RSS non-init user process, delivers `SIGKILL`, and
/// returns the killed PID.  Returns `None` if no eligible target exists.
///
/// `needed_frames` is purely informational — logged for diagnostics.
pub fn invoke_oom_killer(needed_frames: usize) -> Option<Pid> {
    // Collect (pid, rss_pages) for all eligible processes.  We take the lock,
    // do a read-only walk, collect into a small local vec, and release before
    // calling kill() (which re-acquires PROCESS_TABLE).
    let candidates: alloc::vec::Vec<(Pid, u64)> = {
        let procs = crate::proc::PROCESS_TABLE.lock();

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
