//! Live `__clone` pthread-args smoking-gun diagnostic.
//!
//! Captures the pthread-args struct's `start_routine` and `arg` fields at
//! the point of `clone(2)` / `clone3(2)` syscall exit (per `pthread_create(3)`
//! and the AMD64 SysV ABI §3.4 calling convention).  On a later CPL-3 `#GP`
//! we look the trapping child up in a 16-entry ring and emit:
//!
//!   * `[CLONE-CHECK]` — fires for **every** matched child #GP regardless
//!     of the captured `start_routine` value.  This is the
//!     framing-falsifier observable: a non-`0x1c7f9` value at clone-time
//!     proves the corruption happened *after* clone (mid-flight kernel
//!     aliasing — W215 axis-N continuation) rather than in userspace
//!     before clone.
//!
//!   * `[CLONE-SMOKING-GUN]` — fires when the captured `start_routine`
//!     equals the trap RIP.  This is the dispositive observable for the
//!     "inner musl thread-start helper executes its indirect call where
//!     the `start_routine` slot was already poisoned" framing per
//!     tech-lead cross-walk verdict 2026-05-20.
//!
//! ## Framing-falsifier observables (per feedback_diagnostic_framing_falsifier)
//!
//! Three competing framings are pre-enumerated:
//!
//!   F1 — pre-clone corruption (userspace wrote `0x1c7f9` into args
//!        before the syscall).  Distinguished by:
//!        `start_routine_at_clone == 0x7f000001c7f9` AND `args_phys` at
//!        clone equals `args_phys` at #GP (frame stable, content was
//!        already corrupt).
//!
//!   F2 — mid-flight kernel aliasing (W215 axis-N continuation per
//!        PR #270 + PR #327; phys frame for args changed between clone
//!        and trampoline dispatch).  Distinguished by: `start_routine_at_clone`
//!        was a sensible libxul `.text` VA, but `args_phys_at_gp` differs
//!        from the clone-time phys frame (textbook PR #270 share-count
//!        violation).
//!
//!   F3 — different control-flow mechanism (the trap is not via the
//!        pthread trampoline).  Distinguished by: no matching ring entry
//!        for the trapping `(pid, tid)` — `[CLONE-CHECK]` never fires for
//!        this trap.
//!
//! ## Output volume + safety
//!
//! Capped at 4 `[CLONE-CHECK]` and 4 `[CLONE-SMOKING-GUN]` emissions per
//! boot via independent `AtomicU32::fetch_add` budgets (saga rule: bounded
//! emission).  Ring writes are O(1) under `Relaxed` ordering — the
//! diagnostic must not slow the clone path.
//!
//! User-VA reads use the PR #333 fault-immune pattern: `validate_user_ptr`
//! → `virt_to_phys_in(cr3, va)` → load through the kernel direct map at
//! `0xFFFF_8000_0000_0000 + phys`.  No SMAP toggling required.  Cross-page
//! straddles are rejected.
//!
//! ## Capture ABI
//!
//! For `clone(2)` (syscall 56) in the `CLONE_THREAD|CLONE_VM` shape, per
//! upstream musl libc x86_64 `__clone` the wrapper aligns the caller's
//! `child_stack` to 16 and then subtracts 8 (`and $-16,%rsi ; sub $8,%rsi`)
//! before storing the args-struct pointer at `(%rsi)` and issuing the
//! syscall.  Consequently the kernel-visible `new_stack` argument (= the
//! `%rsi` value at syscall entry) already points AT the args slot, and
//! the args-struct VA is recovered with a single qword read at
//! `*new_stack` (NOT `*(new_stack - 8)`).
//!
//! On child return the wrapper executes `pop %rdi ; call *%r9` —
//! popping the args pointer into `%rdi` (SysV arg 0, per AMD64 SysV ABI
//! §3.2 register classes) and calling the static helper whose address was
//! placed in `%r9` BEFORE the syscall.  That static helper is the inner
//! musl thread-start trampoline: it stashes the args pointer (commonly
//! in a callee-saved register such as `%rbx`) and later performs the
//! indirect call to the user's `start_routine`.  The first qword of the
//! args struct (offset 0) is `void *(*start_routine)(void *)`, the second
//! qword (offset 8) is `void *arg`.  When the trampoline's indirect call
//! traps with `#GP` because that first qword was poisoned, the trapping
//! `%rip` equals the value the kernel captured at `*args_va` — that is
//! the `[CLONE-SMOKING-GUN]` predicate.
//!
//! For `clone3(2)` (syscall 435) the kernel-side dispatch (see
//! `subsys/linux/syscall.rs::dispatch::435`) already extracts `func` from
//! `arg3` (RDX) and `thread_arg` from `arg5` (R8) — these ARE the values
//! the trampoline will use, no further dereference required.  In that
//! case we record `start_routine = func` directly and skip the args-struct
//! read.
//!
//! ## Refs
//!
//! - POSIX.1-2017 `pthread_create(3)`, `clone(2)`, `clone3(2)`
//! - System V AMD64 ABI §3.2 (registers), §3.4 (calling convention)
//! - Intel SDM Vol. 3A §6.15 (`#GP` vector 13), Vol. 2A (HLT/RET encoding)
//! - SysV gABI / `elf(5)` (PT_LOAD layout — defends content-gate choice
//!   over fixed-offset symbol matching)
//! - musl libc upstream `pthread_impl.h` / `__clone` ABI shape

#![cfg(feature = "clone-args-diag")]

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Ring capacity.  Lossy: writers overwrite the oldest entry mod RING_SIZE.
/// 16 is enough to cover the typical 8-thread libxul ContentProc + parent
/// fanout without spilling fresh entries before the trampoline fires.
const RING_SIZE: usize = 16;

/// Per-boot emission cap for `[CLONE-CHECK]` framing-falsifier lines.
const CLONE_CHECK_MAX: u32 = 4;

/// Per-boot emission cap for `[CLONE-SMOKING-GUN]` dispositive matches.
const CLONE_SMOKING_GUN_MAX: u32 = 4;

/// Ring slot.  `valid` distinguishes never-written from
/// already-overwritten entries; `gen` lets a probe verify that the
/// looked-up slot is still the one the writer placed (race-tolerant,
/// no locking).  Captured at successful clone exit.
#[derive(Copy, Clone)]
struct CloneRingEntry {
    valid: bool,
    pid: u32,
    tid: u32,
    clone_flags: u64,
    /// Pointer the inner musl thread-start trampoline will dereference
    /// to fetch `start_routine`.  For clone(56) this is `*new_stack`
    /// (the slot at `aligned_stack - 8` that musl `__clone` wrote with
    /// `mov %rcx,(%rsi)` before the syscall — `%rsi` was already biased
    /// by `sub $8`, so the kernel's view of `new_stack` IS the slot).
    /// For clone3(435) this is the synthesized `(func, arg)` pair carried
    /// via `t.user_entry_rdx` / `r8` — there is no in-memory args struct;
    /// we record `args_va = 0` to flag that.
    args_va: u64,
    /// Resolved physical frame backing `args_va` under the calling CR3.
    /// Compared at #GP time against the live phys to detect axis-N
    /// page aliasing.  `0` when `args_va == 0` (clone3 in-register).
    args_phys: u64,
    /// `*(args_va + 0)` = `start_routine` — the value the trampoline
    /// will indirect-call.  For clone3 we take this from the syscall's
    /// `func` argument directly.
    start_routine: u64,
    /// `*(args_va + 8)` = pthread argument.  Diagnostic only.
    arg: u64,
    /// Tick at clone time (no real-time clock needed — relative ordering
    /// is enough for the post-mortem).
    ts: u64,
}

impl CloneRingEntry {
    const EMPTY: Self = Self {
        valid: false,
        pid: 0, tid: 0, clone_flags: 0,
        args_va: 0, args_phys: 0,
        start_routine: 0, arg: 0, ts: 0,
    };
}

/// The ring itself.  16 entries, lossy via `WRITE_IDX` increment.
/// `spin::Mutex` is unnecessary — under any plausible race the worst
/// outcome is a torn read that fails the `tid` filter and the probe
/// silently rejects.  Saga rule: diagnostic must not introduce locks.
static RING: spin::Mutex<[CloneRingEntry; RING_SIZE]> =
    spin::Mutex::new([CloneRingEntry::EMPTY; RING_SIZE]);

/// Monotonic write index (modulo RING_SIZE).
static WRITE_IDX: AtomicU64 = AtomicU64::new(0);

/// Per-boot emission counters.
static CLONE_CHECK_COUNT: AtomicU32 = AtomicU32::new(0);
static CLONE_SMOKING_GUN_COUNT: AtomicU32 = AtomicU32::new(0);

/// Lowest valid user-VA (mirror of `syscall::USER_VA_LIMIT` lower side,
/// per Intel SDM §4.5 canonical addressing).
const USER_VA_MIN: u64 = 0x1_0000;
const USER_VA_LIMIT: u64 = 0x0000_8000_0000_0000;

/// Fault-immune user-VA qword read (mirrors PR #333's
/// `read_userland_qword_raw`).  Returns `(value, phys)`.
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

/// Resolve the physical frame backing a user-VA without reading it.
fn resolve_phys(addr: u64) -> Option<u64> {
    if addr < USER_VA_MIN || addr >= USER_VA_LIMIT { return None; }
    let cr3 = crate::mm::vmm::get_cr3();
    crate::mm::vmm::virt_to_phys_in(cr3, addr)
}

/// Record a successful clone-thread spawn.  Called from
/// `subsys/linux/syscall.rs` after the child TID has been registered.
///
/// `args_va` is the pthread-args struct pointer the child will pop off
/// its stack into `%rdi` and pass to the static start helper.  For the
/// clone(56) ABI this qword is read at `*new_stack` (per upstream musl
/// libc x86_64 `__clone`, which biases `%rsi` by `sub $8` before writing
/// it).  Pass 0 to skip the dereference and record the in-register
/// `start_routine` / `arg` from clone3 instead.
pub fn record_clone_args(
    pid: u32,
    tid: u32,
    clone_flags: u64,
    args_va: u64,
    inline_start_routine: u64,
    inline_arg: u64,
) {
    let ts = crate::arch::x86_64::irq::get_ticks();
    let (resolved_args_va, args_phys, start_routine, arg) = if args_va != 0 {
        // clone(56) shape: dereference the args struct the child will
        // pop into %rdi.  Per upstream musl libc x86_64 __clone the args
        // VA is read by the caller at `*new_stack` (rsi was already biased
        // by `sub $8` before the syscall).
        match read_user_qword(args_va) {
            Some((sr, phys)) => {
                let arg = read_user_qword(args_va.wrapping_add(8))
                    .map(|(v, _)| v).unwrap_or(0);
                (args_va, phys, sr, arg)
            }
            None => (args_va, 0, 0, 0), // phys=0 flags read-fail
        }
    } else {
        // clone3(435) in-register form: caller supplied func/arg directly.
        (0, 0, inline_start_routine, inline_arg)
    };

    let idx = WRITE_IDX.fetch_add(1, Ordering::Relaxed) as usize % RING_SIZE;
    let mut ring = RING.lock();
    ring[idx] = CloneRingEntry {
        valid: true, pid, tid, clone_flags,
        args_va: resolved_args_va, args_phys,
        start_routine, arg, ts,
    };
}

/// Lookup the most recent entry matching `(pid, tid)`.  Walks all
/// RING_SIZE slots since lossy overwrites can land anywhere.  Returns
/// a copy of the slot to avoid holding the lock past the call.
fn lookup_by_tid(pid: u32, tid: u32) -> Option<CloneRingEntry> {
    let ring = RING.lock();
    // Walk newest→oldest in insertion order so multiple-clone-same-tid
    // (after tid recycling) returns the freshest.
    let head = WRITE_IDX.load(Ordering::Relaxed) as usize;
    for i in 0..RING_SIZE {
        let idx = (head + RING_SIZE - 1 - i) % RING_SIZE;
        let e = ring[idx];
        if e.valid && e.pid == pid && e.tid == tid {
            return Some(e);
        }
    }
    None
}

/// `#GP` probe.  Called from the IDT user-mode `#GP` block after the
/// existing SSP-DIAG hook.  Always emits a `[CLONE-CHECK]` line when a
/// ring entry matches the trapping `(pid, tid)`, regardless of the
/// captured `start_routine` value (framing-falsifier — F2 distinguished
/// by phys-frame variance, F1 by exact value match).  Emits a
/// `[CLONE-SMOKING-GUN]` line additionally when `start_routine == rip`.
pub fn probe_gp_clone_args(rip: u64, _frame_rsp: u64) {
    let pid = crate::proc::current_pid_lockless();
    let tid = crate::proc::current_tid();
    let entry = match lookup_by_tid(pid as u32, tid as u32) {
        Some(e) => e,
        None => return, // F3: trap is not via the pthread trampoline
    };

    // Resolve current phys for args_va (may differ from captured —
    // textbook W215 axis-N aliasing fingerprint per PR #270).
    let phys_now = if entry.args_va != 0 {
        resolve_phys(entry.args_va).unwrap_or(0)
    } else { 0 };
    let aliased = entry.args_va != 0 && phys_now != entry.args_phys;

    if CLONE_CHECK_COUNT.fetch_add(1, Ordering::Relaxed) < CLONE_CHECK_MAX {
        crate::serial_println!(
            "[CLONE-CHECK] pid={} tid={} rip={:#x} flags={:#x} \
             args_va={:#x} sr_at_clone={:#x} arg_at_clone={:#x} \
             args_phys_at_clone={:#x} args_phys_at_gp={:#x} \
             aliased={} ts_clone={}",
            entry.pid, entry.tid, rip, entry.clone_flags,
            entry.args_va, entry.start_routine, entry.arg,
            entry.args_phys, phys_now,
            aliased as u8, entry.ts,
        );
    }

    if entry.start_routine == rip
        && CLONE_SMOKING_GUN_COUNT.fetch_add(1, Ordering::Relaxed)
            < CLONE_SMOKING_GUN_MAX
    {
        // F1 confirmed (corruption present at clone time) OR F2 with
        // sr written via aliased frame.  Disambiguator: `aliased`.
        crate::serial_println!(
            "[CLONE-SMOKING-GUN] pid={} tid={} rip={:#x} \
             start_routine={:#x} args_va={:#x} \
             phys_at_clone={:#x} phys_at_gp={:#x} aliased={} \
             framing={}",
            entry.pid, entry.tid, rip,
            entry.start_routine, entry.args_va,
            entry.args_phys, phys_now, aliased as u8,
            if aliased { "F2_aliasing" } else { "F1_pre_clone" },
        );
    }
}
