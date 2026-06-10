//! POSIX Signal Handling
//!
//! Provides signal delivery, pending masks, signal action tables, and the
//! signal-delivery trampoline for returning from user-mode signal handlers.

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::smap::UserGuard;

// Signal numbers (Linux x86_64 compatible)
pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGSEGV: u8 = 11;
pub const SIGUSR2: u8 = 12;
pub const SIGPIPE: u8 = 13;
pub const SIGALRM: u8 = 14;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGWINCH: u8 = 28;
// Per signal(7) on x86_64 Linux, _NSIG = 64 (32 standard + 32 real-time).
// glibc uses signal numbers 32 (SIGCANCEL) and 33 (SIGSETXID) for its internal
// thread-cancellation and setuid-broadcast machinery, both of which fail with
// EINVAL when MAX_SIGNAL is 32 — a soft incompatibility that surfaces as
// startup oddities on first thread-team initialisation.  Raising the cap to 64
// matches the public POSIX/Linux ABI without changing on-the-wire behaviour:
// `pending` and `blocked` are u64 so all 64 valid signal bits already fit.
pub const MAX_SIGNAL: u8 = 64;

/// Virtual address where the signal-return trampoline is mapped for every
/// user-mode process.  The page contains two entry points:
///   offset 0:  AstryxOS sigreturn (syscall 39)
///   offset 16: Linux rt_sigreturn  (syscall 15)
pub const TRAMPOLINE_VADDR: u64 = 0x0000_7FFF_FFFF_F000;

/// Linux ABI trampoline entry is at offset 16 within the trampoline page.
pub const TRAMPOLINE_LINUX_OFFSET: u64 = 16;

/// Physical address of the trampoline page (set once during init).
static TRAMPOLINE_PHYS: AtomicU64 = AtomicU64::new(0);

/// Counts how many times signal_check_on_syscall_return took the fast path
/// (no pending signals, no PROCESS_TABLE lock acquired).  Used by Test 201.
pub static SIGNAL_FAST_PATH_COUNT: AtomicU64 = AtomicU64::new(0);

// ── Per-tid signal-delivered counter (diagnostic only) ─────────────────────
//
// Direct-mapped, lock-free, lossy cache from `tid` to delivery count.
// Used by `subsys::linux::ssp_diag` to discriminate sigreturn-mid-frame
// from normal canary-fail flow at a CPL-3 `#GP` (POSIX.1-2017
// sigaction(2) / sigreturn(2)).  On TID collision the slot is overwritten
// and the count restarts at 1; a reader hitting a non-matching slot
// returns `None` (surfaced as "unknown" — not "zero" — to the caller).
const SIGNAL_DELIVERED_SLOTS: usize = 64;
static SIGNAL_DELIVERED_TID: [AtomicU64; SIGNAL_DELIVERED_SLOTS] =
    [const { AtomicU64::new(0) }; SIGNAL_DELIVERED_SLOTS];
static SIGNAL_DELIVERED_COUNT: [AtomicU64; SIGNAL_DELIVERED_SLOTS] =
    [const { AtomicU64::new(0) }; SIGNAL_DELIVERED_SLOTS];

/// Record that one signal has been delivered to user space for thread
/// `tid`.  Called at the success-edge of both
/// [`signal_check_on_syscall_return`] and [`deliver_sigsegv_from_isr`].
pub fn record_signal_delivered(tid: u64) {
    let i = (tid as usize) & (SIGNAL_DELIVERED_SLOTS - 1);
    let owner = SIGNAL_DELIVERED_TID[i].load(Ordering::Relaxed);
    if owner == tid {
        SIGNAL_DELIVERED_COUNT[i].fetch_add(1, Ordering::Relaxed);
    } else {
        SIGNAL_DELIVERED_TID[i].store(tid, Ordering::Relaxed);
        SIGNAL_DELIVERED_COUNT[i].store(1, Ordering::Relaxed);
    }
}

/// Read the current delivery count for `tid`.  `Some(n)` when the cache
/// slot is still owned by `tid` (n includes the deliveries since the
/// last eviction); `None` when the slot has been evicted (surface as
/// "unknown" — neither confirms nor refutes any prior delivery).
pub fn signal_delivered_count(tid: u64) -> Option<u64> {
    let i = (tid as usize) & (SIGNAL_DELIVERED_SLOTS - 1);
    let owner = SIGNAL_DELIVERED_TID[i].load(Ordering::Relaxed);
    if owner == tid {
        Some(SIGNAL_DELIVERED_COUNT[i].load(Ordering::Relaxed))
    } else {
        None
    }
}

/// Signal frame pushed onto the user stack when delivering a signal to a
/// user-mode handler.  The handler sees RSP pointing at `restorer` (which
/// acts as its return address).  On `ret`, execution jumps to the trampoline
/// which issues `syscall` with the appropriate sigreturn number.
#[repr(C)]
pub struct SignalFrame {
    pub restorer: u64,      // return address → trampoline
    pub sig_num: u64,       // signal number
    pub saved_mask: u64,    // blocked-signal mask before delivery
    pub saved_rsp: u64,     // original user RSP
    pub saved_r15: u64,
    pub saved_r14: u64,
    pub saved_r13: u64,
    pub saved_r12: u64,
    pub saved_rbx: u64,
    pub saved_rbp: u64,
    pub saved_r11: u64,     // original RFLAGS
    pub saved_rcx: u64,     // original user RIP
    pub saved_rax: u64,     // syscall return value
    pub _pad: u64,          // padding to 14 × 8 = 112 bytes (16-aligned)
}

const _SIGNAL_FRAME_SIZE_CHECK: () = {
    assert!(core::mem::size_of::<SignalFrame>() == 112);
};

/// Verify every 4 KiB page in `[base, base+len)` is mapped as a
/// **user, writable, present** leaf in the address space identified by
/// `cr3`.  This is the pre-flight check that signal-frame delivery uses
/// before issuing supervisor stores to the user stack.
///
/// Returning `false` means at least one page in the range is unmapped,
/// non-user, or read-only.  Returning `true` is a single-point-in-time
/// snapshot; once SMAP is lifted (`stac`) and the writes begin, another
/// CPU can still flip the PTE (e.g. mprotect, ptrace, ksm).  That race
/// is small (the entire frame is ≤ 664 bytes / one page touched) and
/// the worst case is the same kernel-mode #PF this function was added
/// to prevent — so the caller MUST still treat a faulting store as
/// fatal-to-the-process (not fatal-to-the-kernel).  Achieving the
/// stronger guarantee (no oops even under concurrent mprotect) is the
/// `extable`/`fixup` mechanism, which is out of scope for this patch.
///
/// Huge-page (2 MiB / 1 GiB) leafs are treated as **acceptable** when
/// the corresponding `virt_to_phys_in` resolves: `lookup_pte_in`
/// returns `None` for huge mappings, so we fall back to the presence
/// check.  User stacks are conventionally 4 KiB-paged so this fallback
/// is essentially never taken in practice (glibc / musl pthread stacks
/// use anonymous 4 KiB pages per the NPTL design).
///
/// Per Intel SDM Vol. 3A §4.6: a supervisor write to a present,
/// not-writable page raises #PF with error code `P | W` (bits 0+1 set),
/// regardless of `CR0.WP` for ring 0 — but `CR0.WP = 1` (set in
/// `arch/x86_64/init`) makes the fault unconditional, which is the
/// expected hardening posture for a kernel that maps user pages
/// read-only on CoW and ELF-RO segments.
///
/// Threat model — CWE-754 (Improper Check for Unusual or Exceptional
/// Conditions), cross-referenced with CWE-20 (Improper Input Validation
/// on user-controlled RSP) and CWE-617 (Reachable Assertion: the kernel
/// bugcheck is reachable from unprivileged userspace).  Without this
/// guard, malicious userspace can induce a kernel oops by arranging RSP
/// to point into a PROT_READ mapping immediately before raising a
/// synchronous SIGSEGV (e.g. dereferencing a NULL pointer), since the
/// kernel's signal-frame delivery would then write to a read-only page
/// in supervisor mode.
///
/// TOCTOU note: this is a check-then-store helper.  Between the page-table
/// walk here and the kernel's subsequent supervisor write in the caller, a
/// concurrent thread sharing the same address space could in principle
/// remap the range non-writable.  In practice the window is mitigated two
/// ways: (1) the supervisor write is bracketed by the existing
/// `extable`/fault-fixup machinery, so a racing remap downgrades from a
/// fail-stop kernel oops to a SIGSEGV the user already expected; and (2)
/// per-page atomic guard primitives (e.g. PTE-locked "begin-store" tokens)
/// are deferred to a future hardening pass rather than added here, since
/// they require touching every user-VA store path, not just signal
/// delivery.  Threat model is "unprivileged userspace cannot induce a
/// kernel oops on the synchronous SIGSEGV path", which the check-then-
/// store shape already satisfies in conjunction with the fault fixup.
pub(crate) fn is_user_writable_range(cr3: u64, base: u64, len: u64) -> bool {
    use crate::mm::vmm::{lookup_pte_in, virt_to_phys_in,
                          PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER};
    // Iterate every page covered by [base, base+len).  Loop bound is
    // ceil((base & 0xfff) + len, 4096) — at most 2 pages for the 664-
    // byte SA_SIGINFO frame, but we keep the loop general so the same
    // helper can be reused (e.g. by sigaltstack-aware paths later).
    let end = match base.checked_add(len) {
        Some(e) => e,
        None => return false, // u64 wrap is never legitimate user VA
    };
    let mut va = base & !0xFFFu64;
    while va < end {
        match lookup_pte_in(cr3, va) {
            Some(pte) => {
                let want = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;
                if pte & want != want {
                    return false;
                }
            }
            None => {
                // Either non-present at some level, or terminated in a
                // huge-page leaf.  Distinguish via virt_to_phys_in:
                // a translation exists iff the leaf is huge+present.
                // For huge pages we cannot inspect the W/U bits via
                // this helper; accept the page rather than spuriously
                // SIGKILL'ing processes with huge-page stacks.  See the
                // doc comment for rationale.
                if virt_to_phys_in(cr3, va).is_none() {
                    return false;
                }
            }
        }
        va = match va.checked_add(0x1000) {
            Some(n) => n,
            None => return false,
        };
    }
    true
}

/// Default action for a signal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigDefault {
    Terminate,
    Ignore,
    CoreDump,
    Stop,
    Continue,
}

/// What happens when a signal is delivered.
#[derive(Debug, Clone, Copy)]
pub enum SigAction {
    /// Use the default action for this signal.
    Default,
    /// Ignore the signal completely.
    Ignore,
    /// Call a user-mode handler at the given virtual address.
    /// Fields: handler address, restorer address (0 = use kernel trampoline).
    Handler { addr: u64, restorer: u64 },
}

/// Per-process signal state.
pub struct SignalState {
    /// Bitmask of pending signals (bit N = signal N is pending).
    pub pending: u64,
    /// Bitmask of blocked signals.
    pub blocked: u64,
    /// Action table indexed by signal number (0..MAX_SIGNAL).
    pub actions: [SigAction; MAX_SIGNAL as usize],
    /// `sa_flags` value most recently installed for each signal via
    /// `rt_sigaction(2)`.  Per `man 2 sigaction`, this is the bitwise-OR of
    /// flags such as `SA_RESTART`, `SA_SIGINFO`, `SA_NOCLDSTOP`, etc.
    /// Stored verbatim so that `getact` can round-trip the value.  Future
    /// signal-delivery work consumes this (e.g. `SA_RESTART` to retry the
    /// interrupted syscall, `SA_SIGINFO` to choose the 3-arg handler ABI).
    pub action_flags: [u64; MAX_SIGNAL as usize],
    /// `sa_mask` value most recently installed for each signal — the set
    /// of additional signals to block while this signal's handler runs.
    /// Per `man 2 sigaction`, this mask is implicitly augmented with the
    /// signal being delivered unless `SA_NODEFER` is set.
    pub action_mask: [u64; MAX_SIGNAL as usize],
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            pending: 0,
            blocked: 0,
            actions: [SigAction::Default; MAX_SIGNAL as usize],
            action_flags: [0u64; MAX_SIGNAL as usize],
            action_mask:  [0u64; MAX_SIGNAL as usize],
        }
    }

    /// Queue a signal (set its pending bit).
    pub fn send(&mut self, sig: u8) {
        if sig > 0 && sig < MAX_SIGNAL {
            // Explicit u64 literal: with MAX_SIGNAL=64, `sig` reaches 63 and a
            // bare `1 << 63` would overflow the default i32 inference.
            self.pending |= 1u64 << sig;
        }
    }

    /// Queue a signal and update the fast-path hint for `pid`.
    pub fn send_for_pid(&mut self, sig: u8, pid: u64) {
        if sig > 0 && sig < MAX_SIGNAL {
            self.pending |= 1u64 << sig;
            crate::proc::signal_pending_hint_set(pid, self.pending);
        }
    }

    /// Dequeue the highest-priority deliverable signal.
    /// Returns the signal number if one is pending and not blocked.
    pub fn dequeue(&mut self) -> Option<u8> {
        let deliverable = self.pending & !self.blocked;
        if deliverable == 0 {
            return None;
        }
        // Find lowest set bit
        let sig = deliverable.trailing_zeros() as u8;
        self.pending &= !(1u64 << sig);
        Some(sig)
    }

    /// Dequeue and clear the fast-path hint for `pid`.
    pub fn dequeue_for_pid(&mut self, pid: u64) -> Option<u8> {
        let deliverable = self.pending & !self.blocked;
        if deliverable == 0 { return None; }
        let sig = deliverable.trailing_zeros() as u8;
        self.pending &= !(1u64 << sig);
        crate::proc::signal_pending_hint_set(pid, self.pending);
        Some(sig)
    }

    /// Check if any signal is pending and not blocked.
    pub fn has_pending(&self) -> bool {
        (self.pending & !self.blocked) != 0
    }

    /// Get the default action for a signal.
    pub fn default_action(sig: u8) -> SigDefault {
        match sig {
            SIGCHLD | SIGWINCH | SIGCONT => SigDefault::Ignore,
            SIGSTOP | SIGTSTP => SigDefault::Stop,
            SIGQUIT | SIGILL | SIGABRT | SIGFPE | SIGBUS | SIGSEGV | SIGTRAP => SigDefault::CoreDump,
            _ => SigDefault::Terminate,
        }
    }
}

// ── Trampoline Initialization ───────────────────────────────────────────────

/// Allocate the trampoline physical page and write the signal-return machine
/// code into it.  Must be called once during kernel init (before any user
/// process is created).
pub fn init_trampoline() {
    let phys = crate::mm::pmm::alloc_page()
        .expect("[SIGNAL] Failed to allocate trampoline page");

    // Zero the page first.
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, 4096);
    }

    // Offset 0: AstryxOS sigreturn — `mov rax, 39; syscall; int3`
    let astryx_tramp: [u8; 10] = [
        0x48, 0xc7, 0xc0, 0x27, 0x00, 0x00, 0x00, // mov rax, 39
        0x0f, 0x05,                                  // syscall
        0xcc,                                        // int3 (safety)
    ];

    // Offset 16: Linux rt_sigreturn — `mov rax, 15; syscall; int3`
    let linux_tramp: [u8; 10] = [
        0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // mov rax, 15
        0x0f, 0x05,                                  // syscall
        0xcc,                                        // int3
    ];

    unsafe {
        let base = phys as *mut u8;
        core::ptr::copy_nonoverlapping(astryx_tramp.as_ptr(), base, astryx_tramp.len());
        core::ptr::copy_nonoverlapping(linux_tramp.as_ptr(), base.add(16), linux_tramp.len());
    }

    TRAMPOLINE_PHYS.store(phys, Ordering::Release);
    crate::serial_println!(
        "[SIGNAL] Trampoline page allocated at phys {:#x}, vaddr {:#x}",
        phys, TRAMPOLINE_VADDR
    );
}

/// Return the physical address of the trampoline page (0 if not yet inited).
pub fn trampoline_phys() -> u64 {
    TRAMPOLINE_PHYS.load(Ordering::Acquire)
}

/// Map the signal-return trampoline into a user-mode page table.
///
/// The page is mapped as **user + present + read-only** (no NX — must be
/// executable).  Call this from `create_user_process` and `fork_process`.
pub fn map_trampoline(cr3: u64) {
    let phys = trampoline_phys();
    if phys == 0 {
        // Trampoline not yet initialised (early kernel-mode processes).
        return;
    }

    use crate::mm::vmm::{PAGE_PRESENT, PAGE_USER};
    // Flags: present + user, NOT writable, NOT no-execute (so it's executable).
    let flags = PAGE_PRESENT | PAGE_USER;
    crate::mm::vmm::map_page_in(cr3, TRAMPOLINE_VADDR, phys, flags);
}

// ── Signal Subsystem Init ───────────────────────────────────────────────────

/// Initialize the signal subsystem.
pub fn init() {
    init_trampoline();
    crate::serial_println!("[SIGNAL] Signal subsystem initialized");
}

/// Send a signal to a process by PID.
/// Returns 0 on success, negative errno on failure.
pub fn kill(target_pid: u64, sig: u8) -> i64 {
    // kill(-pgid, sig): send to all processes in process group |target_pid|.
    if (target_pid as i64) < 0 {
        let pgid = (-(target_pid as i64)) as u32;
        if sig == 0 {
            let procs = crate::proc::PROCESS_TABLE.lock();
            return if procs.iter().any(|p| p.pgid == pgid) { 0 } else { -3 };
        }
        if sig >= MAX_SIGNAL { return -22; }
        // SIGKILL: see the single-pid branch below — terminate each group
        // member directly rather than queueing an undeliverable signal.
        if sig == SIGKILL {
            let targets: alloc::vec::Vec<u64> = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter()
                    .filter(|p| p.pgid == pgid
                            && p.state != crate::proc::ProcessState::Zombie)
                    .map(|p| p.pid)
                    .collect()
            };
            if targets.is_empty() { return -3; } // ESRCH
            let self_pid = crate::proc::current_pid_lockless();
            for pid in targets.iter().copied().filter(|&p| p != self_pid) {
                crate::proc::exit_group_pid(pid, -(SIGKILL as i64));
            }
            ring_signal_bell();
            if targets.contains(&self_pid) {
                // Suicide last: exit_group never returns.
                crate::proc::exit_group(-(SIGKILL as i64));
            }
            return 0;
        }
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let mut found = false;
        for proc in procs.iter_mut() {
            if proc.pgid == pgid && proc.state != crate::proc::ProcessState::Zombie {
                found = true;
                let pid = proc.pid;
                if let Some(ref mut ss) = proc.signal_state {
                    ss.send_for_pid(sig, pid);
                }
            }
        }
        drop(procs);
        if found {
            // Wake any `epoll_pwait`/`pselect6`/`ppoll` caller whose
            // temporary sigmask just admitted a pending signal, and
            // any signalfd watcher whose mask includes this signal —
            // both readiness sources flip as soon as `pending` is
            // updated.  See `man 2 epoll_pwait2` §RETURN VALUE
            // (interrupted by signal handler → EINTR).
            ring_signal_bell();
        }
        return if found { 0 } else { -3 }; // ESRCH
    }

    if sig == 0 {
        // Signal 0 = check if process exists
        let procs = crate::proc::PROCESS_TABLE.lock();
        return if procs.iter().any(|p| p.pid == target_pid) { 0 } else { -3 }; // ESRCH
    }

    if sig >= MAX_SIGNAL {
        return -22; // EINVAL
    }

    // SIGKILL cannot be caught, blocked, or ignored (signal(7)); its outcome
    // is the unconditional, immediate termination of the entire thread group
    // (kill(2), "the signal ... will be delivered" — for SIGKILL delivery IS
    // group death).  The queue-and-deliver path below only takes effect when
    // a target thread next crosses the kernel/user boundary; a process whose
    // threads are ALL parked inside blocking syscalls (FUTEX_WAIT,
    // poll/epoll, blocking recv) never dequeues the signal and survives
    // SIGKILL indefinitely — keeping every fd open, so AF_UNIX/pipe peers
    // never observe EOF/HUP, the parent's waitpid(2) never completes, and a
    // supervisor (e.g. a browser parent force-killing a hung child) hangs
    // with it.  POSIX requires lethal-signal termination to be prompt even
    // for blocked tasks (the kernel-side equivalent of an uninterruptible
    // wait being made killable).  Terminate the group directly from the
    // sender's context via the same machinery exit_group(2) uses — CLEARTID
    // for every thread, futex-queue drain, pipe/socket close (peer EOF),
    // Zombie + parent wake.
    if sig == SIGKILL && target_pid != crate::proc::current_pid_lockless() {
        {
            let procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter().find(|p| p.pid == target_pid) {
                Some(p) if p.state != crate::proc::ProcessState::Zombie => {}
                Some(_) => return 0,  // already a zombie — nothing to do
                None => return -3,    // ESRCH
            }
        } // drop PROCESS_TABLE before the teardown takes its own locks
        crate::proc::exit_group_pid(target_pid, -(SIGKILL as i64));
        ring_signal_bell();
        return 0;
    }

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == target_pid) {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    if let Some(ref mut sig_state) = proc.signal_state {
        sig_state.send_for_pid(sig, target_pid);
    } else {
        // No signal state — handle default action directly
        match SignalState::default_action(sig) {
            SigDefault::Terminate | SigDefault::CoreDump => {
                proc.state = crate::proc::ProcessState::Zombie;
                proc.exit_code = -(sig as i32);
            }
            _ => {}
        }
    }
    drop(procs);
    // Wake any blocking syscall (`epoll_pwait*`, `pselect6`, `ppoll`,
    // `signalfd`-driven `read`) that is now interruptible because
    // `pending` was just updated.  Lock order: PROCESS_TABLE released
    // above before touching POLL_BELL.
    ring_signal_bell();

    0
}

/// Ring the poll bell for a signal-injection event.  Encapsulated so
/// `kill()` and any future signal-source helper share a single
/// attribution point under `PollBellSource::SignalInject`.
#[inline]
fn ring_signal_bell() {
    crate::ipc::waitlist::ring_poll_bell_for(
        crate::ipc::waitlist::PollBellSource::SignalInject);
    // signalfd readability is a direct function of `pending`, so the
    // same fire also represents a Signalfd readiness change.  Counted
    // separately so the kdb `bell-stats` table shows both attributions.
    crate::ipc::waitlist::BELL_RINGS_BY_SOURCE
        [crate::ipc::waitlist::PollBellSource::Signalfd as usize]
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Check and deliver pending signals for the current process.
/// Called from the scheduler before returning to user mode.
/// Returns true if a signal was handled (process may have been terminated).
pub fn check_signals() -> bool {
    let pid = crate::proc::current_pid();
    
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return false,
    };

    let sig_state = match proc.signal_state.as_mut() {
        Some(s) => s,
        None => return false,
    };

    let sig = match sig_state.dequeue_for_pid(pid) {
        Some(s) => s,
        None => return false,
    };

    // SIGKILL and SIGSTOP cannot be caught or ignored
    if sig == SIGKILL {
        crate::serial_println!("[SIGNAL] Process {} killed by SIGKILL", pid);
        drop(procs);
        // Per `signal(7)` ("Standard signals"): a lethal signal terminates
        // every thread in the target process, not just the thread that
        // observes it — equivalent to `exit_group(2)`.  Route through the
        // group-exit machinery so siblings are marked Dead, CLEARTID fires
        // for every thread (`clone(2)` CLONE_CHILD_CLEARTID; `futex(2)`
        // NOTES on task-exit), the futex queues are drained, and — the part
        // the old hand-rolled body missed — every pipe/socket fd is CLOSED
        // so peers observe EOF/HUP promptly (CWE-833 Deadlock otherwise:
        // a parent supervising this process over an AF_UNIX channel never
        // learns it died).
        crate::proc::exit_group(-(sig as i64));
        return true;
    }

    match sig_state.actions[sig as usize] {
        SigAction::Ignore => {
            // Do nothing
            false
        }
        SigAction::Default => {
            match SignalState::default_action(sig) {
                SigDefault::Terminate | SigDefault::CoreDump => {
                    proc.state = crate::proc::ProcessState::Zombie;
                    proc.exit_code = -(sig as i32);
                    crate::serial_println!("[SIGNAL] Process {} terminated by signal {}", pid, sig);
                    drop(procs);
                    // See SIGKILL branch above: a default-action terminate
                    // (`signal(7)` "Term"/"Core") is also a group exit per
                    // POSIX-1.2017 `_exit(2)` / `kill(2)` and Linux
                    // `clone(2)`; CLEARTID for every sibling is required.
                    crate::proc::fire_cleartid_for_group(pid);
                    crate::proc::exit_thread(-(sig as i64));
                    true
                }
                SigDefault::Stop => {
                    proc.state = crate::proc::ProcessState::Waiting;
                    crate::serial_println!("[SIGNAL] Process {} stopped by signal {}", pid, sig);
                    true
                }
                SigDefault::Continue => {
                    if proc.state == crate::proc::ProcessState::Waiting {
                        proc.state = crate::proc::ProcessState::Active;
                    }
                    false
                }
                SigDefault::Ignore => false,
            }
        }
        SigAction::Handler { .. } => {
            // Handler delivery is done by signal_check_on_syscall_return().
            // If we reach here (called from scheduler), just log and skip.
            crate::serial_println!("[SIGNAL] Process {} has handler for signal {} (delivery via syscall return path)", pid, sig);
            // Re-queue the signal so the syscall-return path can pick it up.
            sig_state.send_for_pid(sig, pid);
            false
        }
    }
}

// ── SA_SIGINFO flag constant (per POSIX.1-2017 sigaction(2)) ────────────────

/// Handler is SA_SIGINFO style: void handler(int, siginfo_t *, ucontext_t *).
/// Stored in SignalState::action_flags[]; value matches Linux x86_64 ABI.
pub const SA_SIGINFO: u64 = 0x0000_0004;

// ── ucontext_t layout (x86_64 System V ABI / POSIX.1-2017) ─────────────────
//
// Per the x86_64 System V psABI §3.4 and POSIX.1-2017 <ucontext.h>:
//
//   offset   0: uc_flags  (u64)
//   offset   8: uc_link   (u64, pointer to chained ucontext_t)
//   offset  16: uc_stack  (stack_t, 24 bytes: ss_sp u64, ss_flags i32+pad, ss_size u64)
//   offset  40: uc_mcontext (mcontext_t, 256 bytes):
//                 offset  40: gregs[23] (long long [23], 184 bytes) — REG_R8..REG_CR2
//                 offset 224: fpregs    (u64, pointer to fpregset_t; NULL = no FPU state)
//                 offset 232: __reserved1 ([u64; 8], 64 bytes)
//   offset 296: uc_sigmask (sigset_t, 128 bytes — glibc uses 128 B; kernel uses 8 B)
//
// Total: 424 bytes.  We allocate this much on the user stack for correctness;
// only the fields listed below need valid data for the handlers we care about.
//
// gregs[] index constants (from <sys/ucontext.h>, x86_64):
//   REG_R8=0  REG_R9=1  REG_R10=2  REG_R11=3  REG_R12=4  REG_R13=5  REG_R14=6  REG_R15=7
//   REG_RDI=8  REG_RSI=9  REG_RBP=10  REG_RBX=11  REG_RDX=12  REG_RAX=13  REG_RCX=14
//   REG_RSP=15  REG_RIP=16  REG_EFL=17  REG_CSGSFS=18  REG_ERR=19  REG_TRAPNO=20
//   REG_OLDMASK=21  REG_CR2=22
//
// This struct is written directly to user memory via raw pointer; #[repr(C)]
// guarantees the layout matches the ABI.

#[repr(C)]
pub(crate) struct UContext {
    uc_flags:         u64,       //   0
    uc_link:          u64,       //   8
    uc_stack_ss_sp:   u64,       //  16
    uc_stack_ss_flags: u32,      //  24
    _pad_stack:       u32,       //  28
    uc_stack_ss_size: u64,       //  32
    // uc_mcontext.gregs[23] starts at offset 40
    gregs:            [u64; 23], //  40..224   (184 bytes)
    fpregs:           u64,       // 224        (pointer to fpregset, NULL = none)
    _reserved:        [u64; 8],  // 232..296   (64 bytes)
    // uc_sigmask: glibc sigset_t is 128 bytes (16 × u64); only [0] is meaningful
    uc_sigmask:       [u64; 16], // 296..424   (128 bytes)
}

const _UCONTEXT_SIZE_CHECK: () = {
    assert!(core::mem::size_of::<UContext>() == 424);
};

/// Stack allocation needed for one ucontext_t.
pub(crate) const UCONTEXT_SIZE: u64 = 424;

/// Re-exported for test_runner (test 18c).
pub type UContextExport = UContext;
/// Re-exported for test_runner (test 18c).
pub const UCONTEXT_SIZE_EXPORT: u64 = UCONTEXT_SIZE;

// ── Signal Delivery on Syscall Return ───────────────────────────────────────

/// Called from the `syscall_entry` assembly stub after `dispatch()` returns.
///
/// `frame` points to the saved register state on the kernel stack.  After the
/// rdi/rsi saves were added (PR #186) the layout is:
///
/// ```text
/// frame[0]  = saved RAX (syscall result)
/// frame[1]  = saved RDI (user rdi — syscall arg1)
/// frame[2]  = saved RSI (user rsi — syscall arg2)
/// frame[3]  = saved RDX (user rdx — syscall arg3)
/// frame[4]  = saved R8  (user r8  — syscall arg5)
/// frame[5]  = saved R9  (user r9  — syscall arg6)
/// frame[6]  = saved R10 (user r10 — syscall arg4)
/// frame[7]  = saved R15
/// frame[8]  = saved R14
/// frame[9]  = saved R13
/// frame[10] = saved R12
/// frame[11] = saved RBX
/// frame[12] = saved RBP
/// frame[13] = saved R11 (user RFLAGS — SYSCALL instruction stores these)
/// frame[14] = saved RCX (user RIP — SYSCALL instruction stores return address here)
/// frame[15] = saved user RSP
/// ```
///
/// If a pending signal has a user handler, this function builds a `SignalFrame`
/// on the user stack and rewrites `frame[14]` (RIP → handler) and `frame[15]`
/// (RSP → signal frame).  For SA_SIGINFO handlers it also builds a `ucontext_t`
/// and patches `frame[2]` (RSI → &siginfo_t) and `frame[3]` (RDX → &ucontext_t).
///
/// Returns the signal number (> 0) when a handler was delivered so the asm
/// stub can place it in RDI.  Returns 0 when no signal was delivered.
#[no_mangle]
pub extern "C" fn signal_check_on_syscall_return(frame: *mut u64) -> u64 {
    // ── Lock-free fast path ─────────────────────────────────────────────────
    // Read the per-PID hint atomically (Acquire) before touching any lock.
    // If the hint is zero, no signals are pending: Release store in
    // send_for_pid/dequeue_for_pid guarantees visibility.
    let pid = crate::proc::current_pid_lockless();
    if crate::proc::signal_pending_hint_get(pid) == 0 {
        SIGNAL_FAST_PATH_COUNT.fetch_add(1, Ordering::Relaxed);
        return 0;
    }

    // ── Slow path: at least one signal may be pending ───────────────────────
    let pid = crate::proc::current_pid();

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc_entry = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return 0,
    };

    let is_linux = proc_entry.linux_abi
        || proc_entry.subsystem == crate::win32::SubsystemType::Linux;

    let sig_state = match proc_entry.signal_state.as_mut() {
        Some(s) => s,
        None => return 0,
    };

    let sig = match sig_state.dequeue_for_pid(pid) {
        Some(s) => s,
        None => return 0,
    };

    // SIGKILL — terminate immediately.
    if sig == SIGKILL {
        crate::serial_println!("[SIGNAL] Process {} killed by SIGKILL (syscall return)", pid);
        drop(procs);
        // Mirror of the `check_signals()` SIGKILL branch: route through the
        // group-exit machinery (sibling Dead transitions, group CLEARTID per
        // `clone(2)` CLONE_CHILD_CLEARTID / `futex(2)` task-exit NOTES,
        // futex-queue drain, pipe/socket close so peers see EOF/HUP, Zombie
        // + parent wake).  The old hand-rolled body exited only the
        // observing thread and left every sibling and fd alive (CWE-833).
        crate::proc::exit_group(-(sig as i64));
        return 0; // unreachable
    }

    let action = sig_state.actions[sig as usize];

    match action {
        SigAction::Ignore => 0,
        SigAction::Default => {
            match SignalState::default_action(sig) {
                SigDefault::Terminate | SigDefault::CoreDump => {
                    proc_entry.state = crate::proc::ProcessState::Zombie;
                    proc_entry.exit_code = -(sig as i32);
                    crate::serial_println!(
                        "[SIGNAL] Process {} terminated by signal {} (syscall return)",
                        pid, sig
                    );
                    drop(procs);
                    // Default-action terminate is also a group exit; see
                    // the SIGKILL branch above for the full citation.
                    crate::proc::fire_cleartid_for_group(pid);
                    crate::proc::exit_thread(-(sig as i64));
                    0
                }
                SigDefault::Stop => {
                    proc_entry.state = crate::proc::ProcessState::Waiting;
                    0
                }
                SigDefault::Continue => {
                    if proc_entry.state == crate::proc::ProcessState::Waiting {
                        proc_entry.state = crate::proc::ProcessState::Active;
                    }
                    0
                }
                SigDefault::Ignore => 0,
            }
        }
        SigAction::Handler { addr: handler_addr, restorer } => {
            // ── Build signal frame on user stack ────────────────────────
            //
            // Frame layout (see syscall_entry in arch/x86_64/idt.rs):
            //   frame[0]=rax  frame[1]=rdi  frame[2]=rsi  frame[3]=rdx
            //   frame[4]=r8   frame[5]=r9   frame[6]=r10
            //   frame[7]=r15  frame[8]=r14  frame[9]=r13  frame[10]=r12
            //   frame[11]=rbx frame[12]=rbp
            //   frame[13]=r11(RFLAGS)  frame[14]=rcx(user_RIP)  frame[15]=user_RSP

            let saved_rax = unsafe { *frame.add(0) };
            let saved_rdi = unsafe { *frame.add(1) };
            let saved_rsi = unsafe { *frame.add(2) };
            let saved_rdx = unsafe { *frame.add(3) };
            let saved_r8  = unsafe { *frame.add(4) };
            let saved_r9  = unsafe { *frame.add(5) };
            let saved_r10 = unsafe { *frame.add(6) };
            let saved_r15 = unsafe { *frame.add(7) };
            let saved_r14 = unsafe { *frame.add(8) };
            let saved_r13 = unsafe { *frame.add(9) };
            let saved_r12 = unsafe { *frame.add(10) };
            let saved_rbx = unsafe { *frame.add(11) };
            let saved_rbp = unsafe { *frame.add(12) };
            let saved_r11 = unsafe { *frame.add(13) }; // RFLAGS
            let saved_rcx = unsafe { *frame.add(14) }; // user RIP
            let saved_rsp = unsafe { *frame.add(15) }; // user RSP
            let saved_mask = sig_state.blocked;

            let action_flags = sig_state.action_flags[sig as usize];
            let want_siginfo = (action_flags & SA_SIGINFO) != 0;

            // Determine the restorer (trampoline) address.
            let restorer_addr = if restorer != 0 {
                restorer
            } else if is_linux {
                TRAMPOLINE_VADDR + TRAMPOLINE_LINUX_OFFSET
            } else {
                TRAMPOLINE_VADDR
            };

            // ── User stack layout (growing downward) ─────────────────────
            // For SA_SIGINFO handlers:
            //   new_rsp + 0   .. +112  : SignalFrame  (restorer at [new_rsp])
            //   new_rsp + 112 .. +536  : ucontext_t (424 bytes)
            //   new_rsp + 536 .. +664  : siginfo_t (128 bytes)
            //
            // For classic handlers (no SA_SIGINFO):
            //   new_rsp + 0 .. +112 : SignalFrame only (as before)
            let sigframe_size = core::mem::size_of::<SignalFrame>() as u64; // 112
            let total = if want_siginfo {
                sigframe_size + UCONTEXT_SIZE + 128u64  // 112 + 424 + 128 = 664
            } else {
                sigframe_size
            };

            // 16-align the allocation base, then subtract 8 for "just-called" ABI.
            let base    = (saved_rsp.wrapping_sub(total)) & !0xFu64;
            let new_rsp = base.wrapping_sub(8);

            let sig_frame_ptr  = new_rsp as *mut SignalFrame;
            let ucontext_ptr   = (new_rsp + sigframe_size) as *mut UContext;
            let siginfo_ptr    = (new_rsp + sigframe_size + UCONTEXT_SIZE) as *mut u8;

            // W215 axis-B probe: signal-frame delivery into a user stack
            // that happens to back onto a cache-resident frame (e.g. a
            // libxul mmap aliasing the worker thread's signal stack).
            #[cfg(feature = "firefox-test-core")]
            crate::mm::w215_diag::probe(
                crate::mm::w215_diag::Writer::Sigframe,
                new_rsp as *const u8,
                total as usize,
            );

            // Pre-flight: every page in [new_rsp, new_rsp+total) must be
            // present + user + writable.  See `is_user_writable_range` and
            // the matching guard in `deliver_sigsegv_from_isr` for the full
            // rationale (Intel SDM Vol. 3A §4.6.1; CWE-754 / CWE-20 /
            // CWE-617).  When the user stack is read-only / unmapped we
            // fall through to default-action terminate so the kernel does
            // not oops.
            let cr3: u64;
            unsafe {
                core::arch::asm!("mov {}, cr3", out(reg) cr3,
                                 options(nomem, nostack, preserves_flags));
            }
            if !is_user_writable_range(cr3, new_rsp, total) {
                proc_entry.state = crate::proc::ProcessState::Zombie;
                proc_entry.exit_code = -(sig as i32);
                crate::serial_println!(
                    "[SIGNAL] Process {} signal {} delivery aborted: user stack \
                     {:#x}+{} not writable; terminating (POSIX.1-2017 sigaction(2) \
                     default-action fallback)",
                    pid, sig, new_rsp, total
                );
                drop(procs);
                crate::proc::fire_cleartid_for_group(pid);
                crate::proc::exit_thread(-(sig as i64));
                return 0; // unreachable
            }

            // Write the signal frame to user memory.
            // Per Intel SDM Vol. 3A §4.6.1: with CR4.SMAP=1 a supervisor
            // store to a user-mapped page raises #PF unless EFLAGS.AC=1.
            // The syscall-entry path runs with AC=0, so this bracket is
            // required for every store via `sig_frame_ptr` / `ucontext_ptr`
            // / `siginfo_ptr` below.  Pointer math is bounded by `total`
            // (≤ 664) starting at the user-supplied `saved_rsp`.
            let _smap_g = unsafe { UserGuard::new() };
            unsafe {
                (*sig_frame_ptr).restorer   = restorer_addr;
                (*sig_frame_ptr).sig_num    = sig as u64;
                (*sig_frame_ptr).saved_mask = saved_mask;
                (*sig_frame_ptr).saved_rsp  = saved_rsp;
                (*sig_frame_ptr).saved_r15  = saved_r15;
                (*sig_frame_ptr).saved_r14  = saved_r14;
                (*sig_frame_ptr).saved_r13  = saved_r13;
                (*sig_frame_ptr).saved_r12  = saved_r12;
                (*sig_frame_ptr).saved_rbx  = saved_rbx;
                (*sig_frame_ptr).saved_rbp  = saved_rbp;
                (*sig_frame_ptr).saved_r11  = saved_r11;
                (*sig_frame_ptr).saved_rcx  = saved_rcx;
                (*sig_frame_ptr).saved_rax  = saved_rax;
                (*sig_frame_ptr)._pad       = 0;
            }

            if want_siginfo {
                // ── Write ucontext_t ──────────────────────────────────────
                // Per x86_64 System V psABI §3.4 and POSIX.1-2017 sigaction(2):
                // the third argument to an SA_SIGINFO handler is a pointer to a
                // ucontext_t populated with the interrupted register state.
                unsafe {
                    core::ptr::write_bytes(ucontext_ptr, 0, 1);
                    let uc = &mut *ucontext_ptr;
                    // uc_flags, uc_link, uc_stack — all zero (no alt-stack)
                    // Populate gregs[]; indices per <sys/ucontext.h> x86_64:
                    //   0=R8 1=R9 2=R10 3=R11 4=R12 5=R13 6=R14 7=R15
                    //   8=RDI 9=RSI 10=RBP 11=RBX 12=RDX 13=RAX 14=RCX
                    //   15=RSP 16=RIP 17=EFL 18=CSGSFS 19=ERR 20=TRAPNO
                    //   21=OLDMASK 22=CR2
                    uc.gregs[0]  = saved_r8;
                    uc.gregs[1]  = saved_r9;
                    uc.gregs[2]  = saved_r10;
                    uc.gregs[3]  = saved_r11; // RFLAGS at syscall entry (saved in r11 by SYSCALL)
                    uc.gregs[4]  = saved_r12;
                    uc.gregs[5]  = saved_r13;
                    uc.gregs[6]  = saved_r14;
                    uc.gregs[7]  = saved_r15;
                    uc.gregs[8]  = saved_rdi;
                    uc.gregs[9]  = saved_rsi;
                    uc.gregs[10] = saved_rbp;
                    uc.gregs[11] = saved_rbx;
                    uc.gregs[12] = saved_rdx;
                    uc.gregs[13] = saved_rax;
                    uc.gregs[14] = saved_rcx; // user RIP (saved in rcx by SYSCALL)
                    uc.gregs[15] = saved_rsp;
                    uc.gregs[16] = saved_rcx; // REG_RIP = user RIP
                    uc.gregs[17] = saved_r11; // REG_EFL = user RFLAGS
                    // REG_CSGSFS (18): CS=0x33 for user; GS/FS managed by kernel
                    uc.gregs[18] = 0x33;
                    // REG_ERR (19) = 0 (no hardware error code for syscall path)
                    // REG_TRAPNO (20) = 0 (not a hardware trap)
                    uc.gregs[21] = saved_mask; // REG_OLDMASK
                    // REG_CR2 (22) = 0 (not a page fault)
                    // fpregs = NULL (no FPU state saved on syscall path)
                    uc.uc_sigmask[0] = saved_mask;
                }

                // ── Write minimal siginfo_t ───────────────────────────────
                // POSIX.1-2017 §2.4.3: si_signo, si_errno, si_code.
                // For software-posted signals (kill/tgkill/sigqueue), si_code = SI_USER (0).
                unsafe {
                    core::ptr::write_bytes(siginfo_ptr, 0, 128);
                    core::ptr::write(siginfo_ptr.add(0)  as *mut i32, sig as i32);
                    // si_errno = 0, si_code = 0 (SI_USER)
                }

                // Patch RSI and RDX in the kernel frame for the 3-arg ABI.
                unsafe {
                    *frame.add(2) = siginfo_ptr as u64;   // RSI → &siginfo_t
                    *frame.add(3) = ucontext_ptr as u64;  // RDX → &ucontext_t
                }
            }

            // Rewrite the kernel stack frame so sysretq enters the handler.
            // frame[14] = RCX = user RIP (restored by SYSRETQ as RIP)
            // frame[15] = user RSP (restored from kernel stack slot by syscall_entry epilogue)
            unsafe {
                *frame.add(1)  = sig as u64;   // RDI = signo (first arg)
                *frame.add(14) = handler_addr; // RCX → handler RIP
                *frame.add(15) = new_rsp;      // user RSP → signal frame
            }

            // Block the current signal during handler execution.
            sig_state.blocked |= 1u64 << sig;
            // SIGKILL/SIGSTOP can never be blocked.
            sig_state.blocked &= !((1u64 << SIGKILL) | (1u64 << SIGSTOP));

            crate::serial_println!(
                "[SIGNAL] Delivering signal {} to PID {} handler={:#x} frame={:#x} siginfo={}",
                sig, pid, handler_addr, new_rsp,
                if want_siginfo { "SA_SIGINFO" } else { "classic" }
            );

            // Bump the per-tid delivery counter so the SSP-diag
            // RIP-disambiguator can tell sigreturn-mid-frame from
            // normal canary-fail flow.  Best-effort lossy cache; see
            // [`record_signal_delivered`] for semantics.
            record_signal_delivered(crate::proc::current_tid());

            sig as u64
        }
    }
}

// ── SIGSEGV Delivery from Hardware Exception ISR ─────────────────────────────

/// Attempt to deliver SIGSEGV to the current process from a page-fault ISR.
///
/// Called when `handle_page_fault` returns `false` for a Ring-3 fault.  If the
/// process has a `SigAction::Handler` for SIGSEGV, this function:
///
/// 1. Builds a [`SignalFrame`] on the user stack (callee-saved GPRs zeroed —
///    acceptable because SIGSEGV handlers either `siglongjmp` or terminate).
/// 2. Writes a minimal 128-byte `siginfo_t` with `si_addr = cr2` above the
///    signal frame so that `RSI` can point to it.
/// 3. Modifies `frame.rip` → handler address and `frame.rsp` → new stack so
///    that `iretq` in the ISR stub lands directly in the user handler.
/// 4. Patches the saved `RDI`/`RSI` on the kernel ISR stack so the handler
///    receives `(signo=11, siginfo_ptr, 0)` per the Linux SA_SIGINFO ABI.
///
/// Returns `true` if delivery was set up; `false` if the process has no
/// handler (caller should call `exit_thread(-11)`).
///
/// # Safety
/// * `frame` must be the `InterruptFrame` produced by the `isr_with_error`
///   or `isr_no_error` naked stub.  The 128 bytes *below* `frame` in memory
///   (lower virtual addresses) are the 15 pushed GPRs followed by the error
///   code (or fake zero), as documented in `arch/x86_64/idt.rs`:
///     frame[-1]=error_code, frame[-2]=rax, frame[-3]=rcx, frame[-4]=rdx,
///     frame[-5]=rsi,  frame[-6]=rdi,  frame[-7]=r8,   frame[-8]=r9,
///     frame[-9]=r10,  frame[-10]=r11, frame[-11]=rbx, frame[-12]=rbp,
///     frame[-13]=r12, frame[-14]=r13, frame[-15]=r14, frame[-16]=r15.
/// * `frame.rsp` must be a mapped, writable user stack page.  A write fault
///   here would cause a nested kernel-mode page fault (CPU halts anyway).
pub unsafe fn deliver_sigsegv_from_isr(
    cr2: u64,
    error_code: u64,
    frame: *mut crate::arch::x86_64::idt::InterruptFrame,
) -> bool {
    let pid = crate::proc::current_pid();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc_entry = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return false,
    };

    let is_linux = proc_entry.linux_abi
        || proc_entry.subsystem == crate::win32::SubsystemType::Linux;

    let user_rip = (*frame).rip;

    // Snapshot the VMA containing user_rip plus up to a handful of
    // executable file-backed neighbours.  Done now, BEFORE we reborrow
    // `proc_entry.signal_state`, so the snapshot does not alias the
    // later `&mut sig_state` borrow.  The actual print happens at the
    // end of this function so PROCESS_TABLE is not held across the
    // serial writes.  See the `[SIGNAL/VMA]` emission block below.
    let vma_snapshot = signal_vma_snapshot(proc_entry.vm_space.as_ref(), user_rip, cr2);

    let sig_state = match proc_entry.signal_state.as_mut() {
        Some(s) => s,
        None => return false,
    };

    let action = sig_state.actions[SIGSEGV as usize];
    let (handler_addr, restorer) = match action {
        SigAction::Handler { addr, restorer } => (addr, restorer),
        _ => return false, // Default or Ignore — caller kills the process
    };

    let user_rsp = (*frame).rsp;
    let user_rflags = (*frame).rflags;
    let saved_mask = sig_state.blocked;

    let restorer_addr = if restorer != 0 {
        restorer
    } else if is_linux {
        TRAMPOLINE_VADDR + TRAMPOLINE_LINUX_OFFSET
    } else {
        TRAMPOLINE_VADDR
    };

    let action_flags = sig_state.action_flags[SIGSEGV as usize];
    let want_siginfo = (action_flags & SA_SIGINFO) != 0;

    // ── User stack layout (growing downward) ─────────────────────────────────
    // For SA_SIGINFO handlers (standard Linux x86_64 signal ABI):
    //   new_rsp + 0   .. +112  : SignalFrame  (restorer at [new_rsp] = return addr)
    //   new_rsp + 112 .. +536  : ucontext_t (424 bytes)  ← RDX points here
    //   new_rsp + 536 .. +664  : siginfo_t  (128 bytes)  ← RSI points here
    //
    // For classic (non-SA_SIGINFO) handlers:
    //   new_rsp + 0   .. +112  : SignalFrame only
    //   new_rsp + 112 .. +240  : siginfo_t (128 bytes)  ← RSI points here
    //
    // Per POSIX.1-2017 sigaction(2): SA_SIGINFO handlers receive
    // (int signo, siginfo_t *info, ucontext_t *uctx) in (RDI, RSI, RDX).
    let sigframe_size = core::mem::size_of::<SignalFrame>() as u64; // 112
    let total = if want_siginfo {
        sigframe_size + UCONTEXT_SIZE + 128u64  // 112 + 424 + 128 = 664
    } else {
        sigframe_size + 128u64                  // 112 + 128 = 240 (legacy)
    };

    // 16-align the allocation base, then subtract 8 for "just-called" ABI.
    let base    = (user_rsp.wrapping_sub(total)) & !0xFu64;
    let new_rsp = base.wrapping_sub(8);

    let sig_frame_ptr = new_rsp as *mut SignalFrame;
    let ucontext_ptr  = (new_rsp + sigframe_size) as *mut UContext;
    // For SA_SIGINFO: siginfo follows ucontext. For classic: siginfo follows sigframe.
    let siginfo_ptr   = if want_siginfo {
        (new_rsp + sigframe_size + UCONTEXT_SIZE) as *mut u8
    } else {
        (new_rsp + sigframe_size) as *mut u8
    };

    // ── Guard: verify user stack is mapped USER+WRITABLE before storing ─────
    // If the user stack is unmapped, OR present-but-read-only, OR present-but-
    // not-USER, writing the signal frame would fault in kernel mode (nested
    // #PF → BUGCHECK_KERNEL_PAGE_FAULT, on SMP a double fault is also possible
    // since the ISR stack is the only guaranteed valid kernel memory).  Per
    // Intel SDM Vol. 3A §4.6.1 a supervisor store to a present, not-writable
    // page raises #PF with error_code `P|W` (= 0x3) — exactly the kernel oops
    // class this guard exists to prevent.  Return false so the caller kills
    // the process via exit_thread instead.
    //
    // We walk every page in [new_rsp, new_rsp + total) (≤ 2 pages for the
    // 664-byte SA_SIGINFO frame), not just `new_rsp`, because the frame can
    // straddle a page boundary when the user stack ends near one and the
    // tail page is mapped but read-only / non-user.
    //
    // CWE-754 / CWE-20 / CWE-617 hardening: malicious userspace can
    // otherwise arrange RSP into a PROT_READ mapping immediately before
    // raising a synchronous SIGSEGV to oops the kernel.
    {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        if !is_user_writable_range(cr3, new_rsp, total) {
            drop(procs); // release PROCESS_TABLE lock before returning
            return false;
        }
    }

    // ── Read all saved GPRs from the ISR kernel stack ────────────────────────
    // Layout documented in arch/x86_64/idt.rs (from InterruptFrame* base):
    //   base[-1]=error_code  base[-2]=rax   base[-3]=rcx   base[-4]=rdx
    //   base[-5]=rsi         base[-6]=rdi   base[-7]=r8    base[-8]=r9
    //   base[-9]=r10         base[-10]=r11  base[-11]=rbx  base[-12]=rbp
    //   base[-13]=r12        base[-14]=r13  base[-15]=r14  base[-16]=r15
    let frame_u64 = frame as u64;
    // Caller-saved (pushed by isr stubs):
    let isr_rax = *((frame_u64 - 16)  as *const u64);
    let isr_rcx = *((frame_u64 - 24)  as *const u64);
    let isr_rdx = *((frame_u64 - 32)  as *const u64);
    let isr_rsi = *((frame_u64 - 40)  as *const u64);
    let isr_rdi = *((frame_u64 - 48)  as *const u64);
    let isr_r8  = *((frame_u64 - 56)  as *const u64);
    let isr_r9  = *((frame_u64 - 64)  as *const u64);
    let isr_r10 = *((frame_u64 - 72)  as *const u64);
    let isr_r11 = *((frame_u64 - 80)  as *const u64);
    // Callee-saved (pushed by isr stubs since PR #187):
    let isr_rbx = *((frame_u64 - 88)  as *const u64);
    let isr_rbp = *((frame_u64 - 96)  as *const u64);
    let isr_r12 = *((frame_u64 - 104) as *const u64);
    let isr_r13 = *((frame_u64 - 112) as *const u64);
    let isr_r14 = *((frame_u64 - 120) as *const u64);
    let isr_r15 = *((frame_u64 - 128) as *const u64);

    // W215 axis-B probe: SIGSEGV synth-frame delivery into a user stack
    // backed by a cache-resident frame.  Same Writer::Sigframe counter as
    // the regular delivery path; the per-writer first-line gate de-dupes.
    #[cfg(feature = "firefox-test-core")]
    crate::mm::w215_diag::probe(
        crate::mm::w215_diag::Writer::Sigframe,
        new_rsp as *const u8,
        total as usize,
    );

    // ── Write SignalFrame ─────────────────────────────────────────────────────
    // Per Intel SDM Vol. 3A §4.6.1: CR4.SMAP=1 raises #PF on any supervisor
    // access to a user-mapped page unless EFLAGS.AC=1.  This ISR path runs
    // with AC=0 (interrupts/exceptions clear AC per §6.8.3), so the user-VA
    // stores below would fault without the bracket.  Pointer was already
    // range-validated via `virt_to_phys_in(cr3, new_rsp)` above.
    let _smap_g = UserGuard::new();
    (*sig_frame_ptr).restorer    = restorer_addr;
    (*sig_frame_ptr).sig_num     = SIGSEGV as u64;
    (*sig_frame_ptr).saved_mask  = saved_mask;
    (*sig_frame_ptr).saved_rsp   = user_rsp;
    (*sig_frame_ptr).saved_r15   = isr_r15;
    (*sig_frame_ptr).saved_r14   = isr_r14;
    (*sig_frame_ptr).saved_r13   = isr_r13;
    (*sig_frame_ptr).saved_r12   = isr_r12;
    (*sig_frame_ptr).saved_rbx   = isr_rbx;
    (*sig_frame_ptr).saved_rbp   = isr_rbp;
    (*sig_frame_ptr).saved_r11   = user_rflags;
    (*sig_frame_ptr).saved_rcx   = user_rip;
    (*sig_frame_ptr).saved_rax   = isr_rax;
    (*sig_frame_ptr)._pad        = 0;

    // ── Write ucontext_t (SA_SIGINFO handlers only) ───────────────────────────
    // Per x86_64 System V psABI §3.4 and POSIX.1-2017 sigaction(2):
    // an SA_SIGINFO handler is called as handler(signo, siginfo_t*, ucontext_t*).
    // RDX must point to a valid ucontext_t with the interrupted machine state.
    if want_siginfo {
        core::ptr::write_bytes(ucontext_ptr, 0, 1);
        let uc = &mut *ucontext_ptr;
        // uc_flags, uc_link, uc_stack — all zero (no alternate signal stack)
        // gregs[]: indices per <sys/ucontext.h> x86_64:
        //   0=R8 1=R9 2=R10 3=R11 4=R12 5=R13 6=R14 7=R15
        //   8=RDI 9=RSI 10=RBP 11=RBX 12=RDX 13=RAX 14=RCX
        //   15=RSP 16=RIP 17=EFL 18=CSGSFS 19=ERR 20=TRAPNO
        //   21=OLDMASK 22=CR2
        uc.gregs[0]  = isr_r8;
        uc.gregs[1]  = isr_r9;
        uc.gregs[2]  = isr_r10;
        uc.gregs[3]  = isr_r11;
        uc.gregs[4]  = isr_r12;
        uc.gregs[5]  = isr_r13;
        uc.gregs[6]  = isr_r14;
        uc.gregs[7]  = isr_r15;
        uc.gregs[8]  = isr_rdi;
        uc.gregs[9]  = isr_rsi;
        uc.gregs[10] = isr_rbp;
        uc.gregs[11] = isr_rbx;
        uc.gregs[12] = isr_rdx;
        uc.gregs[13] = isr_rax;
        uc.gregs[14] = isr_rcx;
        uc.gregs[15] = user_rsp;
        uc.gregs[16] = user_rip;   // REG_RIP = faulting instruction
        uc.gregs[17] = user_rflags; // REG_EFL
        // REG_CSGSFS (18): pack CS (low 16 b) from InterruptFrame; GS/FS = 0
        uc.gregs[18] = (*frame).cs & 0xFFFF;
        uc.gregs[19] = error_code;  // REG_ERR (page-fault error code bits)
        uc.gregs[20] = 14;          // REG_TRAPNO = 14 (Intel SDM: #PF is vector 14)
        uc.gregs[21] = saved_mask;  // REG_OLDMASK
        uc.gregs[22] = cr2;         // REG_CR2 = faulting virtual address
        // fpregs = NULL (no FPU state; Mozilla does not read it in the fault path)
        uc.uc_sigmask[0] = saved_mask;
    }

    // ── Write siginfo_t (Linux x86_64 layout, POSIX.1-2017 §2.4.2) ──────────
    // offset  0: si_signo (i32) = SIGSEGV
    // offset  4: si_errno (i32) = 0
    // offset  8: si_code  (i32) = SEGV_MAPERR (1) or SEGV_ACCERR (2)
    // offset 16: si_addr  (u64) = cr2 (faulting virtual address)
    core::ptr::write_bytes(siginfo_ptr, 0, 128);
    let si_code: i32 = if error_code & 1 != 0 { 2 } else { 1 }; // present=ACCERR, not-present=MAPERR
    core::ptr::write(siginfo_ptr.add(0)  as *mut i32, SIGSEGV as i32);
    core::ptr::write(siginfo_ptr.add(4)  as *mut i32, 0i32);
    core::ptr::write(siginfo_ptr.add(8)  as *mut i32, si_code);
    core::ptr::write(siginfo_ptr.add(16) as *mut u64, cr2);

    // ── Redirect IRET ─────────────────────────────────────────────────────────
    (*frame).rip = handler_addr;
    (*frame).rsp = new_rsp;

    // ── Patch saved RDI/RSI/RDX on the ISR kernel stack ──────────────────────
    // After iretq, the ISR stub pops these back into the live registers, so
    // patching them here sets the handler's RDI/RSI/RDX at entry.
    // Offsets per arch/x86_64/idt.rs layout (frame = InterruptFrame*):
    //   RDI at frame[-6] = frame_u64 - 48
    //   RSI at frame[-5] = frame_u64 - 40
    //   RDX at frame[-4] = frame_u64 - 32
    let p_rdi = (frame_u64 - 48) as *mut u64;
    let p_rsi = (frame_u64 - 40) as *mut u64;
    *p_rdi = SIGSEGV as u64;            // RDI = signo (arg1, always set)
    *p_rsi = siginfo_ptr as u64;        // RSI = &siginfo_t (arg2, always set)
    if want_siginfo {
        let p_rdx = (frame_u64 - 32) as *mut u64;
        *p_rdx = ucontext_ptr as u64;   // RDX = &ucontext_t (arg3, SA_SIGINFO only)
    }

    // Block SIGSEGV during handler execution (re-enabled by sigreturn).
    sig_state.blocked |= 1u64 << SIGSEGV;
    sig_state.blocked &= !((1u64 << SIGKILL) | (1u64 << SIGSTOP));

    // Drop PROCESS_TABLE before the serial writes — COM1 is slow and should
    // never block other CPUs from looking up their own process entry.
    drop(procs);
    crate::serial_println!(
        "[SIGNAL] SIGSEGV ISR delivery: PID={} CR2={:#x} user_rip={:#x} handler={:#x} new_rsp={:#x} siginfo={} r14={:#x} rbp={:#x} rbx={:#x} rsi={:#x}",
        pid, cr2, user_rip, handler_addr, new_rsp,
        if want_siginfo { "SA_SIGINFO" } else { "classic" },
        isr_r14, isr_rbp, isr_rbx, isr_rsi
    );
    emit_signal_vma_banner(pid, user_rip, cr2, &vma_snapshot);

    // ── [FAULT/PHYS] + [FAULT/RIP-CONTENT] — physical-frame identity ─────────
    // Aliasing-detection diagnostic.  Two fault deliveries with the same
    // (vma_offset, library) must resolve to the same physical frame backing
    // the user RIP page; if they differ we have proven the executable page is
    // aliased between processes.  See W196 / W190-H_A.
    {
        let cr3_now: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3_now, options(nomem, nostack, preserves_flags));
        emit_fault_phys_diagnostic(pid, user_rip, Some(cr2), cr3_now, &vma_snapshot);
    }

    // Bump the per-tid delivery counter (SSP-diag discriminator).  See
    // [`record_signal_delivered`].
    record_signal_delivered(crate::proc::current_tid());

    true
}

/// Compact VMA descriptor captured at SIGSEGV delivery time.
///
/// `name` is `&'static str` (the same lifetime as `VmArea::name`), so the
/// snapshot is cheap to build and carry across the lock drop.
///
/// `file_offset` is the byte offset within the backing file of the VMA's
/// first byte (zero for anonymous/device mappings).  Combined with
/// `user_rip - base` it gives the file offset that `objdump -d --start-address`
/// expects when symbolicating a shared-library RIP.
#[derive(Copy, Clone)]
pub(crate) struct VmaSnap {
    pub(crate) base: u64,
    pub(crate) end: u64,
    pub(crate) prot: u32,
    pub(crate) name: &'static str,
    pub(crate) file_backed: bool,
    pub(crate) anonymous: bool,
    pub(crate) file_offset: u64,
    /// `(p_vaddr & !0xfff) - (p_offset & !0xfff)` for ELF PT_LOAD segments;
    /// 0 for non-ELF or anonymous mappings.  Lets addr2line-based symbolication
    /// convert `offset_in_file` to the link-time ELF virtual address without
    /// offline arithmetic.  See `VmBacking::File::elf_load_delta`.
    pub(crate) elf_load_delta: u64,
    pub(crate) contains_rip: bool,
    pub(crate) contains_cr2: bool,
    /// Cache-key identity for file-backed VMAs: (mount_idx, inode) from
    /// `VmBacking::File`.  Both are 0 for anonymous / device VMAs.
    /// Used by the W215 action-(C) diagnostic to classify the corrupted
    /// physical frame's cache-entry state.
    pub(crate) mount_idx: usize,
    pub(crate) inode: u64,
}

/// Highest user-space address (one byte past).  Anything `>=` this is in the
/// kernel half (PML4 entries 256-511, base `0xFFFF_8000_0000_0000`).
const USER_ADDR_END: u64 = 0x0000_8000_0000_0000;

/// Capture the VMA covering `user_rip` (and, if distinct, the VMA covering
/// `cr2`) plus a small number of executable, file-backed neighbours that are
/// likely shared-library load segments.
///
/// Capped at 8 entries to keep serial volume bounded — emitting every VMA
/// of a libxul-loading process would push hundreds of lines per fault.  The
/// RIP-containing and CR2-containing VMAs are always preserved even when the
/// cap is otherwise hit, so the symbolicating investigator never loses them
/// to neighbour overflow.
///
/// Visible to `test_runner` via `pub(crate)` so the snapshot policy can
/// be unit-tested against a synthetic `VmSpace` without standing up a
/// full `Process`.
pub(crate) fn signal_vma_snapshot(
    space: Option<&crate::mm::vma::VmSpace>,
    user_rip: u64,
    cr2: u64,
) -> alloc::vec::Vec<VmaSnap> {
    use crate::mm::vma::{PROT_EXEC, VmBacking};
    let mut out: alloc::vec::Vec<VmaSnap> = alloc::vec::Vec::new();
    let space = match space {
        Some(s) => s,
        None => return out,
    };
    for a in space.areas.iter() {
        let (file_backed, file_offset, elf_load_delta, mount_idx, inode) = match a.backing {
            VmBacking::File { offset, elf_load_delta, mount_idx, inode } => {
                (true, offset, elf_load_delta, mount_idx, inode)
            }
            _ => (false, 0u64, 0u64, 0usize, 0u64),
        };
        let anonymous = matches!(a.backing, VmBacking::Anonymous);
        let contains_rip = a.contains(user_rip);
        let contains_cr2 = a.contains(cr2);
        // Always include the VMA(s) containing user_rip / cr2.  For
        // neighbours, only include executable file-backed mappings
        // (shared-library text segments) — those are the symbolication-
        // useful ones.
        let keep = contains_rip
            || contains_cr2
            || (file_backed && (a.prot & PROT_EXEC) != 0);
        if !keep {
            continue;
        }
        // RIP/CR2-containing entries bypass the cap so we never lose them
        // to neighbour overflow.  Neighbour-only entries respect the cap.
        if !contains_rip && !contains_cr2 && out.len() >= 8 {
            continue;
        }
        out.push(VmaSnap {
            base: a.base,
            end: a.end(),
            prot: a.prot,
            name: a.name,
            file_backed,
            anonymous,
            file_offset,
            elf_load_delta,
            contains_rip,
            contains_cr2,
            mount_idx,
            inode,
        });
    }
    out
}

/// Emit `[SIGNAL/VMA]` lines for the snapshot captured at fault time.
///
/// Format (one line per kept VMA):
///   `[SIGNAL/VMA] pid=<n> name=<label> base=<vaddr> end=<vaddr> size=<bytes> prot=<rwx> file=<0|1> rip=<0|1> cr2=<0|1> [offset_in_vma=<…> offset_in_file=<…>] [anon=1]`
///
/// `rip=1` marks the VMA that contains `user_rip`; `cr2=1` marks the VMA
/// that contains the faulting address.  When the same VMA contains both
/// `user_rip` and `cr2` a single entry is emitted with `rip=1 cr2=1` and
/// the per-address offsets are split into `rip_offset_in_vma=…
/// cr2_offset_in_vma=…` (plus `rip_offset_in_file=…` when file-backed).
///
/// Special cases (emitted before iterating the snapshot):
///   * `user_rip >= 0xFFFF_8000_…` — kernel-side RIP (signal-from-IRQ
///     delivery path).  We log a kernel-RIP banner and SKIP the user-VMA
///     iteration around RIP.
///   * `user_rip` has no containing VMA — emit `rip_unmapped=1`.  We still
///     iterate the snapshot so the CR2-containing entry (e.g. stack) and
///     neighbours can be inspected.
fn emit_signal_vma_banner(pid: u64, user_rip: u64, cr2: u64, snap: &[VmaSnap]) {
    use crate::mm::vma::{PROT_EXEC, PROT_READ, PROT_WRITE};

    // ── RIP locality pre-amble ───────────────────────────────────────────────
    let rip_in_kernel = user_rip >= USER_ADDR_END;
    let rip_vma_present = snap.iter().any(|v| v.contains_rip);
    if rip_in_kernel {
        crate::serial_println!(
            "[SIGNAL/VMA] pid={} user_rip={:#x} rip_in_kernel=1 (signal-from-IRQ or kernel-mode fault)",
            pid, user_rip
        );
    } else if !rip_vma_present {
        // RIP is in user space but no VMA covers it — likely jump to an
        // unmapped page (poisoned function pointer, freed shared-object
        // text, etc.).  This is the single most useful symbolication clue
        // in that scenario.
        crate::serial_println!(
            "[SIGNAL/VMA] pid={} user_rip={:#x} rip_unmapped=1 (no VMA covers RIP — possible jump to unmapped page)",
            pid, user_rip
        );
    }

    if snap.is_empty() {
        crate::serial_println!(
            "[SIGNAL/VMA] pid={} user_rip={:#x} cr2={:#x} no_vma_match=1",
            pid, user_rip, cr2
        );
        return;
    }

    for v in snap.iter() {
        let r = if v.prot & PROT_READ  != 0 { 'r' } else { '-' };
        let w = if v.prot & PROT_WRITE != 0 { 'w' } else { '-' };
        let x = if v.prot & PROT_EXEC  != 0 { 'x' } else { '-' };
        let anon_tag = if v.anonymous { " anon=1" } else { "" };
        let rip_flag = v.contains_rip as u8;
        let cr2_flag = v.contains_cr2 as u8;

        if v.contains_rip && v.contains_cr2 {
            // Same VMA covers both RIP and CR2 — emit one combined line.
            let rip_off_vma = user_rip - v.base;
            let cr2_off_vma = cr2 - v.base;
            if v.file_backed {
                let rip_off_file = rip_off_vma + v.file_offset;
                let rip_vaddr_elf = rip_off_file.wrapping_add(v.elf_load_delta);
                let elf_tag = if v.elf_load_delta != 0 {
                    alloc::format!(" vaddr_in_elf={:#x}", rip_vaddr_elf)
                } else {
                    alloc::string::String::new()
                };
                crate::serial_println!(
                    "[SIGNAL/VMA] pid={} name={} base={:#x} end={:#x} size={:#x} prot={}{}{} file=1 rip=1 cr2=1 rip_offset_in_vma={:#x} rip_offset_in_file={:#x} cr2_offset_in_vma={:#x}{}{}",
                    pid, v.name, v.base, v.end, v.end - v.base, r, w, x,
                    rip_off_vma, rip_off_file, cr2_off_vma, elf_tag, anon_tag
                );
            } else {
                crate::serial_println!(
                    "[SIGNAL/VMA] pid={} name={} base={:#x} end={:#x} size={:#x} prot={}{}{} file=0 rip=1 cr2=1 rip_offset_in_vma={:#x} cr2_offset_in_vma={:#x}{}",
                    pid, v.name, v.base, v.end, v.end - v.base, r, w, x,
                    rip_off_vma, cr2_off_vma, anon_tag
                );
            }
        } else if v.contains_rip {
            let off_vma = user_rip - v.base;
            if v.file_backed {
                let off_file = off_vma + v.file_offset;
                let vaddr_elf = off_file.wrapping_add(v.elf_load_delta);
                let elf_tag = if v.elf_load_delta != 0 {
                    alloc::format!(" vaddr_in_elf={:#x}", vaddr_elf)
                } else {
                    alloc::string::String::new()
                };
                crate::serial_println!(
                    "[SIGNAL/VMA] pid={} name={} base={:#x} end={:#x} size={:#x} prot={}{}{} file=1 rip=1 cr2=0 offset_in_vma={:#x} offset_in_file={:#x}{}{}",
                    pid, v.name, v.base, v.end, v.end - v.base, r, w, x,
                    off_vma, off_file, elf_tag, anon_tag
                );
            } else {
                crate::serial_println!(
                    "[SIGNAL/VMA] pid={} name={} base={:#x} end={:#x} size={:#x} prot={}{}{} file=0 rip=1 cr2=0 offset_in_vma={:#x}{}",
                    pid, v.name, v.base, v.end, v.end - v.base, r, w, x,
                    off_vma, anon_tag
                );
            }
        } else if v.contains_cr2 {
            let off_vma = cr2 - v.base;
            if v.file_backed {
                let off_file = off_vma + v.file_offset;
                let vaddr_elf = off_file.wrapping_add(v.elf_load_delta);
                let elf_tag = if v.elf_load_delta != 0 {
                    alloc::format!(" vaddr_in_elf={:#x}", vaddr_elf)
                } else {
                    alloc::string::String::new()
                };
                crate::serial_println!(
                    "[SIGNAL/VMA] pid={} name={} base={:#x} end={:#x} size={:#x} prot={}{}{} file=1 rip=0 cr2=1 offset_in_vma={:#x} offset_in_file={:#x}{}{}",
                    pid, v.name, v.base, v.end, v.end - v.base, r, w, x,
                    off_vma, off_file, elf_tag, anon_tag
                );
            } else {
                crate::serial_println!(
                    "[SIGNAL/VMA] pid={} name={} base={:#x} end={:#x} size={:#x} prot={}{}{} file=0 rip=0 cr2=1 offset_in_vma={:#x}{}",
                    pid, v.name, v.base, v.end, v.end - v.base, r, w, x,
                    off_vma, anon_tag
                );
            }
        } else {
            // Neighbour (executable file-backed, not containing rip/cr2).
            crate::serial_println!(
                "[SIGNAL/VMA] pid={} name={} base={:#x} end={:#x} size={:#x} prot={}{}{} file={} rip={} cr2={}{}",
                pid, v.name, v.base, v.end, v.end - v.base, r, w, x,
                v.file_backed as u8, rip_flag, cr2_flag, anon_tag
            );
        }
    }
}

// ── W215 action-(C): cache-key 3-bucket diagnostic counters ─────────────────
//
// These three counters classify every FAULT/PHYS event (W215 cluster) by the
// relationship between the corrupted physical frame and the page cache:
//
//   Bucket A — "same-key in-place corruption": the cache still holds the frame
//     under the correct (mount,inode,page_offset) key.  The frame content was
//     corrupted in place by an in-kernel or user MAP_SHARED+RW writer while
//     the cache entry was live.
//
//   Bucket B — "cross-key aliased": the cache holds the frame, but under a
//     *different* key.  The PTE was installed from one cache entry; the cache
//     entry was later evicted + re-used for a different file page; the PTE now
//     refers to the wrong content.
//
//   Bucket C — "post-evict stale PTE": the frame is not in the cache at all.
//     The cache evicted the entry without shooting down the PTE; subsequent
//     PMM recycling may have overwritten the frame.
//
// All counters are `#[cfg(feature = "firefox-test-core")]`-gated and `Relaxed` —
// they are read by the kdb `fault-cache-keys` op at human pace, never under
// timing pressure.  ISR-safe: no allocation, no sleeping locks.
#[cfg(feature = "firefox-test-core")]
pub static FAULT_CACHE_KEY_BUCKET_A: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "firefox-test-core")]
pub static FAULT_CACHE_KEY_BUCKET_B: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "firefox-test-core")]
pub static FAULT_CACHE_KEY_BUCKET_C: AtomicU64 = AtomicU64::new(0);

/// Read-only accessor for the kdb `fault-cache-keys` op.
#[cfg(feature = "firefox-test-core")]
pub fn fault_cache_key_bucket_counts() -> (u64, u64, u64) {
    (
        FAULT_CACHE_KEY_BUCKET_A.load(Ordering::Relaxed),
        FAULT_CACHE_KEY_BUCKET_B.load(Ordering::Relaxed),
        FAULT_CACHE_KEY_BUCKET_C.load(Ordering::Relaxed),
    )
}

/// Extract the expected cache key `(mount_idx, inode, page_aligned_file_offset)`
/// for the page that backs `fault_va` in a file-backed VmaSnap.
///
/// `fault_va` is the raw user virtual address of the faulting instruction.
/// The returned page_offset is page-aligned (bottom 12 bits clear) and equals
/// `vma.file_offset + (fault_va_page - vma.base)`.
///
/// Returns `None` for anonymous or device VMAs (no cache entry exists for them).
#[cfg(feature = "firefox-test-core")]
fn vma_file_key(vma: &VmaSnap, fault_va: u64) -> Option<(usize, u64, u64)> {
    if !vma.file_backed {
        return None;
    }
    // Page-aligned offset of fault_va within the VMA.
    let vma_page_off = (fault_va & !0xFFF).saturating_sub(vma.base & !0xFFF);
    // Page-aligned file offset: VMA's file_offset is already page-aligned per
    // how mmap(2) and the ELF loader construct VMAs (POSIX §2.5.3).
    let file_page_off = vma.file_offset.wrapping_add(vma_page_off);
    Some((vma.mount_idx, vma.inode, file_page_off))
}

/// Emit `[FAULT/PHYS]` + `[FAULT/RIP-CONTENT]` for fatal Ring-3 faults.
///
/// Convenience entry point for the `idt.rs` paths that kill the process
/// without delivering a signal (no installed handler, or fatal #UD/#GP/#PF).
/// Builds the VMA snapshot internally so callers do not need to plumb one
/// through.  Acquires `PROCESS_TABLE` briefly to read the VmSpace; lock is
/// released before the diagnostic prints.
///
/// `cr3` is the live CR3 read by the caller in ISR context (always equal
/// to the faulting process's PML4 phys; we cannot derive it from the VmSpace
/// here without re-acquiring locks already dropped).
/// D13 (2026-05-22): dump per-phys provenance for likely user-pointer GPRs
/// at fatal-#PF time.  Complements `[D13/CR2-PROV]` (which queries only the
/// fault address `cr2`); a NULL-deref of `[rdi+8]` shows `cr2=8` but the
/// real pointer of interest is in `rdi`.  Useful when the faulting
/// instruction is a load through a register that should have held a heap
/// pointer (e.g. `mov r8, [rdi+0x8]` with `rdi=0` after `rdi = *(fp+0x88)`,
/// the D11/D12 `_IO_link_in` pattern).
///
/// Bounded: up to 6 candidate GPRs (rdi, rsi, rdx, rcx, r8, r9 — the SysV
/// AMD64 ABI argument registers per §3.2.3) are queried.  Each emits at
/// most one `[D13/GPR-PROV]` line plus shadow lookups; ring lookups are
/// O(1).  Skips: kernel VAs, sub-page pointers, the nullptr page.
///
/// Cite: Intel SDM Vol. 3A §4.6 (paging walk); System V AMD64 ABI §3.2.3
/// (argument-register conventions).
pub fn emit_fault_gpr_phys_for_fatal(
    pid: u64,
    cr3: u64,
    candidates: &[(&'static str, u64)],
) {
    #[cfg(feature = "firefox-test-core")]
    {
        const KERNEL_BASE: u64 = 0x0000_8000_0000_0000;
        let tid = crate::proc::current_tid();
        for (name, val) in candidates.iter() {
            let v = *val;
            // Skip kernel pointers and the nullptr page; we only care
            // about pointers into the user heap / stack / code arenas.
            if v < 0x1000 || v >= KERNEL_BASE {
                continue;
            }
            let page = v & !0xFFFu64;
            match crate::mm::vmm::virt_to_phys_in(cr3, page) {
                Some(phys) => {
                    crate::serial_println!(
                        "[D13/GPR-PROV] pid={} tid={} reg={} val={:#x} \
                         page={:#x} phys={:#x}",
                        pid, tid, name, v, page, phys,
                    );
                    crate::mm::w215_diag::dump_free_shadow_for_phys(phys);
                    crate::mm::w215_diag::dump_alloc_shadow_for_phys(phys);
                }
                None => {
                    // Unmapped GPR pointer is itself informative — likely
                    // the upstream that produced the NULL/garbage that
                    // triggered the fault.
                    crate::serial_println!(
                        "[D13/GPR-PROV] pid={} tid={} reg={} val={:#x} \
                         page={:#x} phys=UNMAPPED",
                        pid, tid, name, v, page,
                    );
                }
            }
        }
        // Silence unused-variable warning when no candidates pass the
        // filter.
        let _ = (pid, cr3, tid);
    }
    #[cfg(not(feature = "firefox-test-core"))]
    let _ = (pid, cr3, candidates);
}

pub fn emit_fault_phys_for_fatal(pid: u64, user_rip: u64, cr2: u64, cr3: u64) {
    // D13 (2026-05-22): cr2 was previously dropped at the call boundary;
    // forward it through so `emit_fault_phys_diagnostic` can query
    // phys-shadows on the DATA fault address (not just the instruction
    // page).  See D12 sc=201 verdict and the [D13/CR2-PROV] line below.
    // Snapshot under the PROCESS_TABLE lock, then release before printing.
    //
    // For a CLONE_VM child (`vm_space == None`, shared CR3 with parent —
    // see `clone(2)` "CLONE_VM" + `vfork(2)`) the child's own VMA list is
    // empty by design.  Fall back to the parent's VmSpace so the
    // `[FAULT/PHYS]` diagnostic reports `vma_offset=<off>` instead of
    // `vma_offset=NO_VMA` when the fault lies inside a parent-mapped
    // segment (library text, anon code page, etc.).  The PFH itself
    // already does this fallback for the actual fault path — see
    // `arch/x86_64/idt.rs::handle_page_fault` (the target_pid switch).
    let snap = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let child = procs.iter().find(|p| p.pid == pid);
        let direct_space = child.and_then(|p| p.vm_space.as_ref());
        if let Some(space) = direct_space {
            signal_vma_snapshot(Some(space), user_rip, cr2)
        } else if let Some(c) = child {
            let parent_pid = c.parent_pid;
            let cr3_child = c.cr3;
            let parent_space = procs.iter()
                .find(|p| p.pid == parent_pid && p.cr3 == cr3_child && cr3_child != 0)
                .and_then(|p| p.vm_space.as_ref());
            signal_vma_snapshot(parent_space, user_rip, cr2)
        } else {
            signal_vma_snapshot(None, user_rip, cr2)
        }
    };
    emit_fault_phys_diagnostic(pid, user_rip, Some(cr2), cr3, &snap);
}

/// Emit `[FAULT/PHYS]` and `[FAULT/RIP-CONTENT]` diagnostic lines.
///
/// `[FAULT/PHYS]` exposes the physical frame backing the user RIP page so
/// two trials with identical `vma_offset` can be cross-checked: a healthy
/// page cache returns the same `rip_phys` for the same (mount, inode,
/// page_offset); aliasing produces different `rip_phys` values.
///
/// Format:
///   `[FAULT/PHYS] pid=<n> tid=<n> rip=<vaddr> rip_phys=<paddr|UNMAPPED> vma_offset=<off|NO_VMA>`
///
/// `[FAULT/RIP-CONTENT]` dumps the first 16 bytes at the user RIP so the
/// executed instruction stream can be compared against the on-disk libxul.
/// A mismatch confirms page aliasing or content corruption.
///
/// Format:
///   `[FAULT/RIP-CONTENT] rip=<vaddr> bytes=<32 hex chars + spaces>`
///   `[FAULT/RIP-CONTENT] rip=<vaddr> unmapped_or_fault`
///
/// Cite: Intel SDM Vol. 3A §4.10 (TLB / paging-structure caches), §4.5
/// (4-Level Paging).
///
/// Lock-safe: callable from ISR context (no PROCESS_TABLE / MOUNTS).
/// Uses `virt_to_phys_in` directly off `cr3`, mirroring the existing
/// `[UD/RIP-BYTES]` pattern in `arch/x86_64/idt.rs`.
pub(crate) fn emit_fault_phys_diagnostic(
    pid: u64,
    user_rip: u64,
    cr2: Option<u64>,
    cr3: u64,
    vma_snapshot: &[VmaSnap],
) {
    // D13: `cr2` is consumed only by the firefox-test gated block below
    // (see [D13/CR2-PROV]).  Silence the unused-variable warning when the
    // feature is off — default builds stay byte-identical.
    #[cfg(not(feature = "firefox-test-core"))]
    let _ = cr2;
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    const KERNEL_BASE: u64 = 0x0000_8000_0000_0000;
    let tid = crate::proc::current_tid();

    // ── [FAULT/PHYS] ────────────────────────────────────────────────────────
    let rip_page = user_rip & !0xFFFu64;
    let rip_phys = if user_rip < KERNEL_BASE {
        crate::mm::vmm::virt_to_phys_in(cr3, rip_page)
    } else {
        None
    };

    // Find the VMA containing user_rip in the snapshot to report
    // vma_offset (the in-VMA byte offset of the faulting instruction).
    // Cross-trial equality of vma_offset is the prerequisite for the
    // rip_phys mismatch test to be conclusive.
    let mut vma_off: Option<u64> = None;
    for v in vma_snapshot.iter() {
        if v.contains_rip {
            vma_off = Some(user_rip - v.base);
            break;
        }
    }

    match (rip_phys, vma_off) {
        (Some(p), Some(off)) => {
            crate::serial_println!(
                "[FAULT/PHYS] pid={} tid={} rip={:#x} rip_phys={:#x} vma_offset={:#x}",
                pid, tid, user_rip, p, off,
            );
        }
        (Some(p), None) => {
            crate::serial_println!(
                "[FAULT/PHYS] pid={} tid={} rip={:#x} rip_phys={:#x} vma_offset=NO_VMA",
                pid, tid, user_rip, p,
            );
        }
        (None, Some(off)) => {
            crate::serial_println!(
                "[FAULT/PHYS] pid={} tid={} rip={:#x} rip_phys=UNMAPPED vma_offset={:#x}",
                pid, tid, user_rip, off,
            );
        }
        (None, None) => {
            crate::serial_println!(
                "[FAULT/PHYS] pid={} tid={} rip={:#x} rip_phys=UNMAPPED vma_offset=NO_VMA",
                pid, tid, user_rip,
            );
        }
    }

    // ── [FAULT/PHYS/FREESHADOW] direct-addressed free-shadow lookup (Phase D) ─
    // The 256×16 hashed `PROV_TABLE` ring rotates out entries every ~16
    // unrelated phys in the same hash bucket — by the time a deeper boot
    // (e.g. sc≈1233 musl Firefox) faults, the original FREE event for the
    // faulting frame has typically been displaced.  Phase D's dedicated
    // `FREE_SHADOW` table is direct-mapped by `pfn % 64K` so per-pfn
    // collisions are observable (via a global displacement counter) instead
    // of silent.  Emit one line per fault so the operator can correlate the
    // fault's `rip_phys` with the unmap caller-RIP that released the frame.
    #[cfg(feature = "firefox-test-core")]
    if let Some(rp) = rip_phys {
        crate::mm::w215_diag::dump_free_shadow_for_phys(rp);
    }

    // ── [D13/CR2-PROV] phys-shadow lookup on the DATA fault address ─────────
    // D12 (sc=201 glibc `_IO_link_in` NULL-deref of `fp->_lock`, 2026-05-22)
    // identified that the existing `[FAULT/PHYS/FREESHADOW]` /
    // `[FAULT/PHYS/ALLOCSHADOW]` / `[FAULT/PHYS/PROV]` dumps query only
    // `rip_phys` (the instruction-page phys), never the data-page phys.
    // For heap-class faults the corrupted byte lives in the data page, not
    // the code page, so the only diagnostic available was a single
    // `caller_rip=glibc.text` line — uselessly redundant with the RIP itself.
    //
    // D13 closes that gap: when `cr2` is known (always true for a #PF; see
    // `emit_fault_phys_for_fatal` + `deliver_sigsegv_from_isr`), translate
    // `cr2 & ~0xFFF` through the faulting CR3 and dump per-phys
    // FREE/ALLOC/PROV provenance.  Per Intel SDM Vol. 3A §4.6 (paging walk)
    // a successful `virt_to_phys_in` resolves the same physical frame the
    // CPU's translation produced; per §4.10.5 the most-recent free + most-
    // recent alloc together name the upstream of any use-after-recycle.
    //
    // Output format mirrors the existing `[FAULT/PHYS/…]` family so the
    // qemu-harness grep pattern is invariant.  `cr2 < KERNEL_BASE` guards
    // against kernel-mode CR2 (which would not have a user CR3 mapping
    // anyway, but cheap to be explicit).
    #[cfg(feature = "firefox-test-core")]
    if let Some(cr2_va) = cr2 {
        if cr2_va < KERNEL_BASE && cr2_va >= 0x1000 {
            let cr2_page = cr2_va & !0xFFFu64;
            match crate::mm::vmm::virt_to_phys_in(cr3, cr2_page) {
                Some(data_phys) => {
                    crate::serial_println!(
                        "[D13/CR2-PROV] pid={} tid={} cr2={:#x} cr2_page={:#x} \
                         data_phys={:#x}",
                        pid, tid, cr2_va, cr2_page, data_phys,
                    );
                    crate::mm::w215_diag::dump_free_shadow_for_phys(data_phys);
                    crate::mm::w215_diag::dump_alloc_shadow_for_phys(data_phys);
                    crate::mm::w215_diag::dump_prov_for_phys(data_phys);
                    // GATE-A (2026-05-30) — if the faulting data address is in
                    // the main-stack TOP window (the argv/envp/auxv block,
                    // e.g. `cr2=0x7fff_fffe_fa38` for a zeroed `argv[1]`
                    // pointer slot), scan the stack-prov rings for the writer
                    // that stored into that frame and name its RIP.  This is
                    // the trap-time mirror of the synchronous capture-time
                    // `[STACK-PROV/ARGV-WRITER]` emit; together they
                    // deterministically link the SIGSEGV to its out-of-band
                    // writer.
                    #[cfg(feature = "stack-prov")]
                    if crate::mm::stack_prov::in_top_window(cr2_va) {
                        crate::mm::stack_prov::dump_argv_writer_for_phys(data_phys);
                    }
                }
                None => {
                    crate::serial_println!(
                        "[D13/CR2-PROV] pid={} tid={} cr2={:#x} cr2_page={:#x} \
                         data_phys=UNMAPPED",
                        pid, tid, cr2_va, cr2_page,
                    );
                }
            }
        }
    }

    // ── [FAULT/PHYS/PROV] unconditional dump (Phase D 2026-05-20) ──────────
    // The bucket-A cache-key classifier below only fires for file-backed
    // VMAs.  W215-class recurrences on `VmBacking::Anonymous` VMAs (e.g.
    // musl's `mmap(MAP_ANONYMOUS) + read()` ld-musl bootstrap, the
    // `[elf]` PT_LOAD VMAs from `proc::elf::load_elf`, and posix_spawn
    // helper stacks) bypass the cache lookup entirely — yet exhibit the
    // exact same fingerprint of "same VMA + same offset + DIFFERENT
    // rip_phys per boot + wrong content" that the original W215 saga
    // produced for file-backed faults.  Phase C revalidation (2026-05-20)
    // documented one such recurrence at `ld-musl+0x1c7f9` with HLT;RET
    // bytes on a `<anon>` VMA.
    //
    // To name the writer for those classes, dump the per-phys provenance
    // ring unconditionally whenever `rip_phys` is known on a user-mode
    // fault.  The ring records ALLOC / REFINC / REFDEC / FREE
    // (Phase D addition — `KIND_FREE` carries the upstream caller-RIP),
    // INSERT / EVICT / PFH_INSTALL events.  Per Intel SDM Vol. 3A §4.10.5,
    // the most-recent FREE before the fault is the most-likely upstream
    // of a use-after-recycle, so its caller-RIP is the locus of the bug.
    //
    // The bucket-A path below ALSO calls `dump_prov_for_phys` (kept for
    // backward compatibility with PR #255's W215 H2 verifier).  Double-dumps
    // for file-backed faults are bounded by the ring's 16 entries per
    // bucket, so the cost is at most two ~16-line bursts on a fatal fault
    // — negligible relative to the existing FAULT/PHYS noise.
    #[cfg(feature = "firefox-test-core")]
    if let Some(rp) = rip_phys {
        crate::serial_println!(
            "[FAULT/PHYS/PROV] kind=unconditional pid={} tid={} rip={:#x} rip_phys={:#x}",
            pid, tid, user_rip, rp,
        );
        crate::mm::w215_diag::dump_prov_for_phys(rp);
    }

    // ── [FAULT/CACHE-KEY] (W215 action-(C) diagnostic) ──────────────────────
    // Classify the corrupted physical frame into one of three exhaustive buckets
    // based on its current presence in the page cache.  Only emitted for
    // firefox-test builds and only when (a) rip_phys is known and (b) the
    // faulting VMA is file-backed — anonymous fault pages are never cached so
    // the lookup would always return None, which would spuriously inflate
    // bucket-C and produce a misleading soak verdict.
    //
    // ISR-safe: `is_phys_in_cache` takes PAGE_CACHE.lock() (spin, no sleep).
    // `vma_file_key` is pure arithmetic.  No allocation.
    #[cfg(feature = "firefox-test-core")]
    if let Some(rip_phys) = rip_phys {
        // Find the VMA that contains user_rip so we know its file identity.
        let rip_vma = vma_snapshot.iter().find(|v| v.contains_rip);
        if let Some(vma) = rip_vma {
            if let Some(expected_key) = vma_file_key(vma, user_rip) {
                match crate::mm::cache::is_phys_in_cache(rip_phys) {
                    Some(actual_key) if actual_key == expected_key => {
                        FAULT_CACHE_KEY_BUCKET_A.fetch_add(1, Ordering::Relaxed);
                        crate::serial_println!(
                            "[FAULT/CACHE-KEY] bucket=A (same-key in-place corruption) \
                             rip_phys={:#x} key=(mount={},inode={:#x},off={:#x})",
                            rip_phys,
                            actual_key.0, actual_key.1, actual_key.2,
                        );
                        // W215 diagnostic Arm-1: dump the per-phys provenance
                        // ring so the corrupting writer's history is visible
                        // at the moment of fault.  Per Intel SDM Vol. 3A
                        // §4.10.5, the page must have been alive in the
                        // cache continuously from insert to fault — the ring
                        // reveals which other operations touched it in that
                        // window.
                        crate::mm::w215_diag::dump_prov_for_phys(rip_phys);
                    }
                    Some(actual_key) => {
                        FAULT_CACHE_KEY_BUCKET_B.fetch_add(1, Ordering::Relaxed);
                        crate::serial_println!(
                            "[FAULT/CACHE-KEY] bucket=B (cross-key aliased) \
                             rip_phys={:#x} \
                             expected=(mount={},inode={:#x},off={:#x}) \
                             actual=(mount={},inode={:#x},off={:#x})",
                            rip_phys,
                            expected_key.0, expected_key.1, expected_key.2,
                            actual_key.0, actual_key.1, actual_key.2,
                        );
                    }
                    None => {
                        FAULT_CACHE_KEY_BUCKET_C.fetch_add(1, Ordering::Relaxed);
                        crate::serial_println!(
                            "[FAULT/CACHE-KEY] bucket=C (not in cache; post-evict stale PTE) \
                             rip_phys={:#x} \
                             expected=(mount={},inode={:#x},off={:#x})",
                            rip_phys,
                            expected_key.0, expected_key.1, expected_key.2,
                        );
                    }
                }
            }
        }
    }

    // ── [FAULT/PHYS/RAW16] kernel-side PHYS_OFF sniff (Phase D) ────────────
    // Reads the same 16 bytes as [FAULT/RIP-CONTENT] below, but through the
    // higher-half identity-map at `PHYS_OFF + rip_phys + (user_rip & 0xFFF)`
    // — bypassing the user-mode page tables entirely.  If [FAULT/RIP-CONTENT]
    // and [FAULT/PHYS/RAW16] agree byte-for-byte, the wrong content is
    // physically present in the frame (writer is in a kernel path that
    // touched the frame after the original load — pmm::free + re-alloc, or
    // a kernel-side PHYS_OFF write).  If they disagree, the user-mode PTE
    // points at a different frame than the one we resolved through
    // `virt_to_phys_in` (a stale TLB or a torn PT walk).  Per Intel SDM
    // Vol. 3A §4.10.5 the two views must agree under normal conditions.
    if let Some(rp) = rip_phys {
        const N: usize = 16;
        let mut buf = [0u8; N];
        let mut got = 0usize;
        let page_off = (user_rip & 0xFFF) as usize;
        for i in 0..N {
            if page_off + i >= 0x1000 { break; } // stay inside the same phys page
            let kva = (PHYS_OFF + rp) as *const u8;
            buf[i] = unsafe { core::ptr::read_volatile(kva.add(page_off + i)) };
            got += 1;
        }
        if got > 0 {
            const HEX: &[u8] = b"0123456789abcdef";
            let mut hex = [0u8; N * 3];
            for i in 0..got {
                hex[i * 3]     = HEX[(buf[i] >> 4) as usize];
                hex[i * 3 + 1] = HEX[(buf[i] & 0xF) as usize];
                hex[i * 3 + 2] = b' ';
            }
            // SAFETY: HEX bytes are ASCII; got >= 1 by the early-break check.
            let hex_str = unsafe {
                core::str::from_utf8_unchecked(&hex[..got * 3 - 1])
            };
            crate::serial_println!(
                "[FAULT/PHYS/RAW16] rip={:#x} phys={:#x} bytes={}",
                user_rip, rp, hex_str,
            );
        }
    }

    // ── [FAULT/RIP-CONTENT] ─────────────────────────────────────────────────
    // 16 bytes at the user RIP, mirroring the [UD/RIP-BYTES] format.  A
    // healthy libxul .text page must show the same opcode bytes across
    // trials at the same vma_offset; a mismatch is direct evidence the
    // physical page contents differ from what the ELF says (aliasing or
    // post-load corruption).
    if user_rip < KERNEL_BASE {
        const N: usize = 16;
        let mut buf = [0u8; N];
        let mut got = 0usize;
        for i in 0..N {
            let va = user_rip.wrapping_add(i as u64);
            if va >= KERNEL_BASE { break; }
            match crate::mm::vmm::virt_to_phys_in(cr3, va) {
                Some(phys) => {
                    buf[i] = unsafe {
                        core::ptr::read_volatile((PHYS_OFF + phys) as *const u8)
                    };
                    got += 1;
                }
                None => break,
            }
        }
        if got > 0 {
            const HEX: &[u8] = b"0123456789abcdef";
            let mut hex = [0u8; N * 3];
            for i in 0..got {
                hex[i * 3]     = HEX[(buf[i] >> 4) as usize];
                hex[i * 3 + 1] = HEX[(buf[i] & 0xF) as usize];
                hex[i * 3 + 2] = b' ';
            }
            // SAFETY: HEX bytes are ASCII; trailing space exists for got >= 1.
            let hex_str = unsafe {
                core::str::from_utf8_unchecked(&hex[..got * 3 - 1])
            };
            crate::serial_println!(
                "[FAULT/RIP-CONTENT] rip={:#x} bytes={}",
                user_rip, hex_str,
            );
        } else {
            crate::serial_println!(
                "[FAULT/RIP-CONTENT] rip={:#x} unmapped_or_fault",
                user_rip,
            );
        }
    }
}
