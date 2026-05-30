//! Syscall Interface
//!
//! Provides the system call entry point and dispatch table.
//! Supports both `int 0x80` (IDT-based) and `syscall`/`sysret` (MSR-based).
//!
//! # GDT Layout for SYSRET
//! - 0x08: Kernel Code, 0x10: Kernel Data
//! - 0x18: User Data, 0x20: User Code
//! STAR[47:32] = 0x08 (kernel CS; kernel SS = 0x08+8 = 0x10)
//! STAR[63:48] = 0x10 (user SS = 0x10+8 = 0x18|3; user CS = 0x10+16 = 0x20|3)
//!
//! # Ring 3 Support
//! When a SYSCALL instruction is executed from Ring 3, the CPU does NOT switch
//! stacks. The entry point must manually swap to the kernel stack using the
//! SYSCALL_KERNEL_RSP global, then restore the user stack on SYSRETQ.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use astryx_shared::syscall::*;
use spin::Mutex;

/// Per-process syscall ring buffer (firefox-test diagnostic aid).  Active
/// code is feature-gated inside; the module itself compiles out cleanly when
/// the feature is off because nothing outside the module references it.
#[cfg(feature = "firefox-test")]
pub mod ring;

/// Stub `ring` module for builds without the firefox-test feature.  Provides
/// the `is_tracked()` predicate so generic syscall-trace gates can compile
/// uniformly; always returns false because no PIDs are tracked outside of
/// the firefox-test diagnostic build.
#[cfg(not(feature = "firefox-test"))]
pub mod ring {
    #[inline]
    pub fn is_tracked(_pid: u64) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════════════
// W215 H3a diagnostic counters
// ═══════════════════════════════════════════════════════════════════════════════

/// Number of `mmap(MAP_SHARED|PROT_WRITE, fd≥0)` calls on file-backed fds.
///
/// A non-zero count indicates that some caller created a MAP_SHARED+writable
/// mapping of a regular file (not a memfd, not /dev/*).  If the file is the
/// libxul binary, any write through this mapping lands directly in the page
/// cache frame, corrupting the content every other MAP_PRIVATE reader copies
/// from the cache — which is precisely the W215 H3a failure chain.
///
/// Only armed in `firefox-test` builds.  Zero cost in all others.
#[cfg(feature = "firefox-test")]
static SYS_MMAP_SHARED_WRITE_FILEBACKED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

#[cfg(feature = "firefox-test")]
pub fn sys_mmap_shared_write_filebacked_count() -> u64 {
    SYS_MMAP_SHARED_WRITE_FILEBACKED.load(core::sync::atomic::Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════════════════════
// User pointer validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Validate that a user-space pointer is safe to access from the kernel.
///
/// Returns `true` if the entire range `[ptr, ptr+len)` lies in the
/// canonical user half (below `USER_VA_LIMIT`), is non-null, and does
/// not wrap around.
///
/// # Canonical-address discipline (CWE-119 / CWE-823)
///
/// On x86_64 the linear address space is split into two canonical halves
/// separated by a non-canonical hole (per Intel SDM Vol. 3A §3.3.7.1):
///
/// - `[0x0000_0000_0000_0000, 0x0000_8000_0000_0000)` — user canonical
/// - `[0x0000_8000_0000_0000, 0xFFFF_8000_0000_0000)` — non-canonical hole
/// - `[0xFFFF_8000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF]` — kernel canonical
///
/// Any deref of a non-canonical address raises #GP, not #PF.  The kernel
/// page-fault handler cannot recover #GP cleanly, so a syscall arm that
/// dereferences a non-canonical user pointer (e.g. one just below the
/// kernel half because a length check rolled `end` into the kernel half
/// but the *base* sat in the non-canonical hole) panics the kernel.
///
/// Pre-cycle-3, this helper only checked `end <= KERNEL_VIRT_BASE`,
/// which silently admitted the entire non-canonical hole — so a base
/// like `KERNEL_VIRT_BASE - 8` with `len=4` passed validation and the
/// subsequent deref #GP-panicked.  This is the same CWE class as the
/// audit's C2 finding (iovec kernel-VA, closed in PR #242), generalised
/// from "kernel half" to "anything outside the user canonical half".
///
/// The strict bound is now `ptr < USER_VA_LIMIT` and `end <= USER_VA_LIMIT`,
/// where `USER_VA_LIMIT = 0x0000_8000_0000_0000`.  No legitimate user
/// process can hold a mapping in `[USER_VA_LIMIT, KERNEL_VIRT_BASE)` —
/// the CPU itself rejects loads/stores there — so the tighter bound has
/// no false-positive surface.
pub const USER_VA_LIMIT: u64 = 0x0000_8000_0000_0000;

#[inline]
pub(crate) fn validate_user_ptr(ptr: u64, len: usize) -> bool {
    if ptr == 0 || len == 0 {
        return len == 0 && ptr == 0; // null + zero-length is acceptable
    }
    // Reject any base in the non-canonical hole or the kernel half.
    if ptr >= USER_VA_LIMIT {
        return false;
    }
    let end = ptr.checked_add(len as u64);
    match end {
        // The endpoint exclusive bound is USER_VA_LIMIT itself
        // (a buffer ending at the first non-canonical byte is fine).
        Some(e) => e <= USER_VA_LIMIT,
        None => false, // overflow
    }
}

/// Snapshot a user buffer into a kernel-resident `Vec<u8>` under one
/// SMAP bracket.
///
/// This is the **preferred** helper for any caller that intends to read
/// every byte of a user buffer — it eliminates the footgun shape of
/// returning a borrowed `&[u8]` whose backing memory is still a user
/// page (which faults under SMAP, per Intel SDM Vol. 3A §4.6, once the
/// caller's `UserGuard` scope ends).
///
/// On invalid pointer / overflow returns `None` (caller should surface
/// EFAULT to the user).  On `len == 0` returns `Some(empty)`.
///
/// # Safety
///
/// Caller must ensure no concurrent kernel thread is writing to the
/// same user page during the snapshot — the snapshot is non-atomic.
#[inline]
pub(crate) unsafe fn user_slice_snapshot(ptr: u64, len: usize) -> Option<alloc::vec::Vec<u8>> {
    if len == 0 { return Some(alloc::vec::Vec::new()); }
    if !validate_user_ptr(ptr, len) { return None; }
    let buf: alloc::vec::Vec<u8> = {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::slice::from_raw_parts(ptr as *const u8, len).to_vec()
    };
    Some(buf)
}

/// Validate and create a *borrowed* slice over user memory.
///
/// **Footgun warning**: the returned `&[u8]` borrows directly from a
/// user page.  This function brackets the *materialisation* with
/// STAC/CLAC, but the bracket drops on return — any caller that
/// reads from the returned slice afterwards needs its **own**
/// `UserGuard` scope wrapping those reads, or the access will fault
/// under SMAP (Intel SDM Vol. 3A §4.6).  Prefer
/// [`user_slice_snapshot`] when the caller will hold the data past
/// a single tight bracket.
///
/// # Safety
///
/// In addition to the SMAP discipline above, the caller assumes
/// responsibility for ensuring the underlying user memory remains
/// mapped and unmodified for the slice's borrow lifetime (TOCTOU).
#[inline]
pub(crate) unsafe fn user_slice_unbracketed<'a>(ptr: u64, len: usize) -> Option<&'a [u8]> {
    if len == 0 { return Some(&[]); }
    if !validate_user_ptr(ptr, len) { return None; }
    let _g = crate::arch::x86_64::smap::UserGuard::new();
    Some(core::slice::from_raw_parts(ptr as *const u8, len))
}

/// Mutable counterpart to [`user_slice_unbracketed`] — same footgun
/// warning applies.  The caller MUST wrap any writes through the
/// returned `&mut [u8]` in a `UserGuard` scope (or use a bracketed
/// copy helper).  Prefer copy-out-then-copy-in patterns when the
/// write set is bounded.
#[inline]
pub(crate) unsafe fn user_slice_mut_unbracketed<'a>(ptr: u64, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 { return Some(&mut []); }
    if !validate_user_ptr(ptr, len) { return None; }
    let _g = crate::arch::x86_64::smap::UserGuard::new();
    Some(core::slice::from_raw_parts_mut(ptr as *mut u8, len))
}

/// Read a u32 from a validated user address. Returns None on bad address.
///
/// STAC/CLAC bracketed (per Intel SDM Vol. 3A §4.6): when SMAP is
/// enabled, the deref runs with EFLAGS.AC=1 and AC is cleared on
/// return.  When SMAP is not enabled (older CPU / TCG without `+smap`)
/// the bracket collapses to a single relaxed load + branch.
#[inline]
pub(crate) unsafe fn user_read_u32(addr: u64) -> Option<u32> {
    if !validate_user_ptr(addr, 4) { return None; }
    if addr % 4 != 0 { return None; } // alignment check
    let _g = crate::arch::x86_64::smap::UserGuard::new();
    Some(core::ptr::read_volatile(addr as *const u32))
}

/// Write a u32 to a validated user address in the CURRENT address space.
/// Returns `true` on success, `false` on a bad / non-canonical / kernel-half
/// or misaligned address (caller should surface EFAULT).
///
/// Symmetric with [`user_read_u32`]: a direct volatile store under an SMAP
/// bracket, used where the target word lives in the *caller's own* address
/// space (same CR3) — e.g. `FUTEX_WAKE_OP`'s modify of `*uaddr2`.  This is
/// distinct from [`write_u32_to_user`], which walks an arbitrary CR3 and
/// resolves through the owning `VmSpace` for the cross-address-space
/// CLONE_CHILD_CLEARTID exit path; that machinery is unnecessary (and, for a
/// page that is present+writable but not VMA-tracked, can refuse the write)
/// when the writer is the page's own process.
#[inline]
pub(crate) unsafe fn user_write_u32(addr: u64, val: u32) -> bool {
    if !validate_user_ptr(addr, 4) { return false; }
    if addr % 4 != 0 { return false; } // alignment check
    let _g = crate::arch::x86_64::smap::UserGuard::new();
    core::ptr::write_volatile(addr as *mut u32, val);
    true
}

/// Read a u64 from a validated user address. Returns None on bad address.
///
/// SMAP-bracketed — see [`user_read_u32`].
#[inline]
pub(crate) unsafe fn user_read_u64(addr: u64) -> Option<u64> {
    if !validate_user_ptr(addr, 8) { return None; }
    if addr % 8 != 0 { return None; } // alignment check
    let _g = crate::arch::x86_64::smap::UserGuard::new();
    Some(core::ptr::read_volatile(addr as *const u64))
}

/// Read a Linux `struct timespec` (two consecutive `u64` fields,
/// `tv_sec` and `tv_nsec`) from a validated user address under a
/// **single** SMAP bracket.
///
/// The naive shape — `user_read_u64(p)` + `user_read_u64(p + 8)` —
/// pays two `STAC` + `CLAC` pairs and two `validate_user_ptr` calls
/// for what should be one bracket and one range check.  This helper
/// validates the full 16-byte range once and reads both fields under
/// one [`UserGuard`].  Per Intel SDM Vol. 3A §4.6 the bracket cost is
/// the CR4-class CPU state toggle, which dominates the per-read cost
/// for these tiny reads.
///
/// Returns `None` (caller surfaces `-EFAULT`) on a misaligned or
/// out-of-range pointer.  Returns the raw `(tv_sec, tv_nsec)` pair;
/// callers must apply the POSIX `timespec` validity check
/// (`tv_nsec < 1_000_000_000`) themselves since the appropriate error
/// code (`EINVAL` vs caller-specific) is syscall-dependent.
#[inline]
pub(crate) unsafe fn user_read_timespec(addr: u64) -> Option<(u64, u64)> {
    if !validate_user_ptr(addr, 16) { return None; }
    if addr % 8 != 0 { return None; } // alignment check
    let _g = crate::arch::x86_64::smap::UserGuard::new();
    let p = addr as *const u64;
    let tv_sec  = core::ptr::read_volatile(p);
    let tv_nsec = core::ptr::read_volatile(p.add(1));
    Some((tv_sec, tv_nsec))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Futex wait queue — keyed by (pid, uaddr)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Key shape: `(pid, uaddr)` — the FUTEX_PRIVATE key per `futex(2)`.
//
// Per `futex(2)` (Linux man-pages, "FUTEX_PRIVATE_FLAG" and "Priority-inheritance
// futexes"):
//
//   * FUTEX_PRIVATE futexes are scoped to a single process and identified by
//     the tuple `(mm_struct, virtual address)`.  We approximate `mm_struct`
//     with `pid` — correct because every process has its own page tables and
//     no two processes share the `mm` of a Linux task on AstryxOS.
//
//   * FUTEX_SHARED futexes are scoped to a backing object and identified by
//     the tuple `(inode, page offset within file)` for file-backed mappings
//     or by an anonymous-mapping anchor for `MAP_SHARED|MAP_ANONYMOUS`.
//     Two processes that map the same shared region at different virtual
//     addresses must still hash to the same key, otherwise a
//     `pthread_mutex_lock` in process A and the matching wake in process B
//     will miss.
//
// This implementation uses the FUTEX_PRIVATE key shape for ALL futex
// operations, including those with the FUTEX_PRIVATE_FLAG clear.  This is
// correct in practice when:
//
//   (a) The futex is FUTEX_PRIVATE (FUTEX_PRIVATE_FLAG set, or implied by
//       the caller's intent — `pthread_mutexattr_setpshared(_, PROCESS_PRIVATE)`
//       and similar default to FUTEX_PRIVATE).
//   (b) The futex is FUTEX_SHARED AND both processes have mapped the shared
//       region at the same `uaddr` (common when a parent forks and the child
//       inherits identical mappings, or when both ends explicitly request
//       MAP_FIXED at the same VA).
//
// Cross-process FUTEX_SHARED synchronisation across DIFFERENT virtual
// addresses is NOT supported.  No upstream binary on the current demo path
// (musl-FF strace differential 2026-05-20) uses it.  When a use case
// emerges, change `(u64, u64)` to a `FutexKey` enum with `Private(pid, va)`
// and `Shared(mount_idx, inode, page_off)` variants, derive the shared
// variant from `vma::lookup(pid, uaddr)` on every WAIT/WAKE/REQUEUE entry,
// and back-fill tests with a two-process MAP_SHARED+pthread_mutex case.
//
// Refs: `futex(2)` Linux man-pages; POSIX.1-2017 §pthread_mutexattr_getpshared.
pub(crate) static FUTEX_WAITERS: Mutex<BTreeMap<(u64, u64), Vec<u64>>> = Mutex::new(BTreeMap::new());

/// Destination key for waiters that a `FUTEX_REQUEUE` / `FUTEX_CMP_REQUEUE`
/// moved off their original WAIT queue.
///
/// A thread parked in the `FUTEX_WAIT` branch records its *original* `uaddr`
/// in its on-stack frame and, after `schedule()` returns, removes itself from
/// the `(pid, uaddr)` bucket.  But a `FUTEX_REQUEUE` may have meanwhile moved
/// that TID into the `(pid, uaddr2)` bucket — per `futex(2)`, requeue updates
/// the waiter's queue key to `uaddr2` (the kernel-internal "`q->key = key2`"
/// invariant).  Without tracking that move, a timeout-after-requeue would scan
/// the wrong bucket and (a) leave a stale waiter orphaned in `(pid, uaddr2)`
/// for a later wake to spuriously pop, and (b) misclassify the timeout as a
/// successful wake (returning 0 instead of ETIMEDOUT).
///
/// This map records `(pid, tid) → dest_uaddr` for exactly the window between a
/// requeue moving the TID and that TID's WAIT branch running its post-wake
/// cleanup.  The cleanup consults it to scan the bucket the waiter actually
/// sits in, then removes the entry.  Keyed by `(pid, tid)`: a TID is unique
/// within a process and at most one requeue destination is live per parked
/// waiter.  Lock order: acquired only while NOT holding `FUTEX_WAITERS` for
/// the requeue insert (insert happens after the `FUTEX_WAITERS` critical
/// section in the REQUEUE branch) and acquired *inside* the `FUTEX_WAITERS`
/// critical section in the WAIT cleanup — to keep a single, consistent order
/// (`FUTEX_WAITERS` → `FUTEX_REQUEUE_DEST`), the requeue insert takes
/// `FUTEX_REQUEUE_DEST` while still holding `FUTEX_WAITERS`.
///
/// Ref: `futex(2)` Linux man-pages (FUTEX_REQUEUE / FUTEX_CMP_REQUEUE).
pub(crate) static FUTEX_REQUEUE_DEST: Mutex<BTreeMap<(u64, u64), u64>> = Mutex::new(BTreeMap::new());

/// Outcome of `futex_wait_check_and_enqueue`.
#[derive(Debug)]
pub(crate) enum FutexWaitOutcome {
    /// Caller is now enqueued and marked Blocked; caller MUST call schedule().
    Enqueued,
    /// `*uaddr != val` — caller should return EAGAIN without parking.
    ValueMismatch,
    /// User-pointer read failed — caller should return EFAULT without parking.
    Fault,
}

/// Atomic check-then-queue for FUTEX_WAIT.
///
/// Performs the value-vs-`val` comparison and the wait-queue enqueue under a
/// single `FUTEX_WAITERS` critical section, then transitions the calling
/// thread to `Blocked` under `THREAD_TABLE` while still holding
/// `FUTEX_WAITERS`.  This is the single atomic step the lost-wakeup fix
/// hinges on: any concurrent FUTEX_WAKE on `(pid, uaddr)` either runs before
/// us (and updates `*uaddr` so we observe `ValueMismatch`) or after (and
/// finds us already in the queue + Blocked).  No window for `woken=0` on a
/// thread that is on the verge of registering as a waiter.
///
/// Lock order: `FUTEX_WAITERS` → `THREAD_TABLE`.  Both are released on
/// return; the caller invokes `schedule()` after this returns `Enqueued`.
///
/// `read_u32` is called *under* `FUTEX_WAITERS` to read the futex word.
/// For the Linux syscall path it wraps `user_read_u32(uaddr)`; the test
/// path uses a kernel-mode reader so the same critical section is exercised
/// without needing a real user mapping.  The closure must be cheap and must
/// not acquire any kernel locks.
pub(crate) fn futex_wait_check_and_enqueue<R>(
    pid: u64,
    uaddr: u64,
    val: u64,
    tid: u64,
    wake_tick: u64,
    read_u32: R,
) -> FutexWaitOutcome
where
    R: FnOnce() -> Option<u32>,
{
    let mut waiters = FUTEX_WAITERS.lock();

    let current = match read_u32() {
        Some(v) => v,
        None => return FutexWaitOutcome::Fault,
    };
    if current as u64 != val {
        return FutexWaitOutcome::ValueMismatch;
    }

    waiters.entry((pid, uaddr)).or_insert_with(Vec::new).push(tid);

    // Mark Blocked under THREAD_TABLE while still holding FUTEX_WAITERS.
    //
    // Race hazard guarded here: between our `waiters.push(tid)` above and the
    // THREAD_TABLE acquisition below, a peer CPU running `exit_group_inner`
    // for this process can have already taken THREAD_TABLE, transitioned us
    // to Dead, released THREAD_TABLE, and be spinning on FUTEX_WAITERS (which
    // we still hold).  Without the guard below we would unconditionally
    // overwrite Dead with Blocked, leaving a "Blocked but not in any wait
    // queue" thread that schedule() never picks and the reaper never reaps.
    //
    // Defensive: if state is already Dead, undo our queue push (exit_group's
    // `futex_drain_pid` will run when we release FUTEX_WAITERS, but draining
    // is keyed on (pid, _) and we have just made the queue non-empty under a
    // valid key — the drain still works, but it costs an extra branch.  Pop
    // explicitly so the queue is clean immediately).  Skip the state write.
    // Returning Enqueued is the right outcome: the caller will call
    // schedule(), which will skip this Dead thread, and the next pass of
    // reap_dead_threads_sched will reclaim it.
    {
        let mut threads = crate::proc::THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            if t.state == crate::proc::ThreadState::Dead {
                // Undo the queue push we just made.
                if let Some(list) = waiters.get_mut(&(pid, uaddr)) {
                    if let Some(pos) = list.iter().rposition(|&x| x == tid) {
                        list.remove(pos);
                    }
                    if list.is_empty() {
                        waiters.remove(&(pid, uaddr));
                    }
                }
            } else {
                t.state = crate::proc::ThreadState::Blocked;
                t.wake_tick = wake_tick;
            }
        }
    }

    FutexWaitOutcome::Enqueued
}

/// SCM_RIGHTS pending fd transfers.
/// Key = receiving unix socket id.  Value = list of FileDescriptors to deliver.
static PENDING_SCM: Mutex<Vec<(u64, Vec<crate::vfs::FileDescriptor>)>> = Mutex::new(Vec::new());

/// Queue SCM_RIGHTS fds to be delivered when `receiver_id` calls recvmsg.
pub fn scm_queue(receiver_id: u64, fds: Vec<crate::vfs::FileDescriptor>) {
    PENDING_SCM.lock().push((receiver_id, fds));
}

/// Pop SCM_RIGHTS fds for `receiver_id`.  Returns None if nothing pending.
pub fn scm_dequeue(receiver_id: u64) -> Option<Vec<crate::vfs::FileDescriptor>> {
    let mut q = PENDING_SCM.lock();
    let pos = q.iter().position(|(id, _)| *id == receiver_id)?;
    Some(q.remove(pos).1)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Per-CPU SYSCALL data — replaces the old global statics for SMP safety.
//
// Each CPU has its own `PerCpuSyscallData` slot so that concurrent SYSCALL
// instructions on different cores do not clobber each other's saved RSP/RIP.
//
// The `syscall_entry` naked-asm stub uses SWAPGS to load GS with a pointer
// to the active CPU's slot, then uses GS-relative addressing (offsets 0, 8,
// 16) to swap stacks and save the return RIP.
//
// `set_kernel_rsp()` and `get_user_rip()` index the array by LAPIC-ID-based
// cpu_index(), safe because each CPU only accesses its own slot.
//
// NOTE: if user-space ever uses ARCH_SET_GS / ARCH_GET_GS, the scheduler
// must also save/restore IA32_KERNEL_GS_BASE on context switch to keep per-
// thread GS state correct.  Currently no user code sets GS.
// ═══════════════════════════════════════════════════════════════════════════════

use crate::arch::x86_64::apic::MAX_CPUS;

/// Per-CPU scratch data for the SYSCALL entry stub.
/// Must be `#[repr(C)]` so the assembly can rely on fixed offsets.
#[repr(C, align(64))] // cache-line aligned to avoid false sharing
pub struct PerCpuSyscallData {
    /// Kernel stack top for this CPU's current user thread (offset 0).
    pub kernel_rsp: u64,
    /// Saved user RSP on SYSCALL entry (offset 8).
    pub user_rsp: u64,
    /// Saved user RIP (RCX) on SYSCALL entry (offset 16).
    pub user_rip: u64,
    /// Kernel RSP after all user-reg pushes (offset 24).
    /// Points at: [rdi, rsi, rdx, r8, r9, r10, r15, r14, r13, r12, rbx, rbp, r11, rcx, user_rsp]
    /// Written by syscall_entry naked_asm; read by read_fork_user_regs().
    pub frame_rsp: u64,
}

/// Per-CPU array.  Indexed by `cpu_index()` (LAPIC ID >> 24, capped at MAX_CPUS).
#[no_mangle]
pub static mut PER_CPU_SYSCALL: [PerCpuSyscallData; MAX_CPUS] = {
    const INIT: PerCpuSyscallData = PerCpuSyscallData {
        kernel_rsp: 0,
        user_rsp: 0,
        user_rip: 0,
        frame_rsp: 0,
    };
    [INIT; MAX_CPUS]
};

use crate::arch::x86_64::apic::cpu_index;

/// Set the kernel RSP for syscall handling on the **current** CPU.
/// Called by the scheduler on every context switch to a user-mode thread.
///
/// # Safety
/// Must only be called with a valid kernel stack top address.
pub unsafe fn set_kernel_rsp(rsp: u64) {
    // Validate: must be 0 (idle thread) or a higher-half kernel address.
    if rsp != 0 && rsp < 0xFFFF_8000_0000_0000 {
        crate::serial_println!(
            "[KERN_RSP] PANIC: bad value {:#x} cpu={}",
            rsp, cpu_index()
        );
        panic!("set_kernel_rsp: non-higher-half value");
    }
    let cpu = cpu_index();
    PER_CPU_SYSCALL[cpu].kernel_rsp = rsp;
}

/// Read the saved user RIP for the **current** CPU.
/// Used by clone() to know where the child should resume.
#[inline]
pub unsafe fn get_user_rip() -> u64 {
    let cpu = cpu_index();
    PER_CPU_SYSCALL[cpu].user_rip
}

/// Read the user RSP / RBP values captured at syscall entry on the current
/// CPU.  Returns `(0, 0)` if no syscall frame is active — e.g. when called
/// from a context that did not enter via SYSCALL (int 0x80 path, test
/// harness, IDT exception path).  The values come from the per-CPU
/// `frame_rsp` slot populated by `syscall_entry`; see its frame-layout
/// comment for offsets.
///
/// SAFETY: `frame_rsp` is written by `syscall_entry` and is NEVER cleared
/// on SYSRETQ — it remains stale across the syscall return.  A caller that
/// reaches this function from outside the syscall path (most importantly
/// the IDT exception path that calls `proc::exit_group` on a fatal user
/// fault, per PR #166) would otherwise dereference a pointer to whatever
/// kernel memory used to host the prior syscall's saved-register frame,
/// which has since been overwritten by ISR pushes, scheduler context
/// saves, or — in the worst case — freed entirely with its underlying
/// physical pages reallocated to unrelated kernel objects.  A raw deref
/// in that state produced a KERNEL_PAGE_FAULT bugcheck under firefox-test
/// when the corrupted return path eventually IRET'd to RIP=0 (W86).
///
/// Defence: validate that the saved frame pointer lies inside the **current
/// thread's** kernel stack range before dereferencing.  The current
/// thread's kernel stack top is `PER_CPU_SYSCALL[cpu].kernel_rsp`; the
/// stack extends downward by `KERNEL_STACK_SIZE_BYTES`.  If `frame_rsp`
/// falls outside this window, treat it as stale and return `(0, 0)` —
/// downstream callers (`dump_exit_stack`, `dump_for_exit`) treat zero as
/// "no usable frame" and emit empty diagnostic output rather than fault.
///
/// Used by the firefox-test exit-time stack snapshot.
pub fn get_user_rsp_rbp() -> (u64, u64) {
    let cpu = cpu_index();
    let pcs = unsafe { &PER_CPU_SYSCALL[cpu as usize] };
    let rsp = pcs.frame_rsp;
    let kstack_top = pcs.kernel_rsp;
    if rsp == 0 { return (0, 0); }

    // The frame must occupy 15 u64 slots starting at `rsp`, so the entire
    // window [rsp, rsp + 15*8) must lie within the current thread's
    // kernel stack [kstack_top - KERNEL_STACK_SIZE_BYTES, kstack_top).
    // Reject anything outside that window as a stale pointer left behind
    // by a prior syscall on a different thread (or by a context that did
    // not pass through `syscall_entry` at all).
    const FRAME_TOP_OFF: u64 = 15 * 8;
    let stack_low = kstack_top.saturating_sub(KERNEL_STACK_SIZE_BYTES);
    if kstack_top == 0
        || rsp < stack_low
        || rsp.saturating_add(FRAME_TOP_OFF) > kstack_top
        || rsp & 0x7 != 0
    {
        return (0, 0);
    }
    unsafe {
        let p = rsp as *const u64;
        // Frame layout from syscall_entry:
        //   [11]=rbp   [14]=user_rsp
        (*p.add(14), *p.add(11))
    }
}

/// Maximum kernel-stack span used by `get_user_rsp_rbp` / `read_fork_user_regs`
/// to validate a saved syscall frame pointer.  Mirrors the per-thread
/// `KERNEL_STACK_PAGES * 4096` allocation in `proc::mod` (64 pages = 256 KiB).
/// Kept private here to avoid a cross-module `pub` of an internal constant;
/// any drift will be caught by Test 211 (which exercises both the in-range
/// and out-of-range branches).
const KERNEL_STACK_SIZE_BYTES: u64 = 64 * 4096;

/// Mark the per-CPU syscall frame as invalid.  Called from the IDT exception
/// path (`arch/x86_64/idt.rs`) just before delivering a fatal user-mode
/// signal via `proc::exit_group`, so that the firefox-test diagnostic dump
/// inside `exit_group` does not consult the previous syscall's saved frame
/// (which has since been overwritten or freed; see `get_user_rsp_rbp` for
/// the full rationale and W86 for the user-visible symptom).
///
/// Idempotent and lock-free.  Safe to call from any context where
/// `cpu_index()` is valid.
#[inline]
pub fn invalidate_syscall_frame() {
    let cpu = cpu_index();
    unsafe { PER_CPU_SYSCALL[cpu as usize].frame_rsp = 0; }
}

/// Read the user-mode caller return address at `[rsp]`.  For System V x86_64,
/// the C `syscall()` wrapper (`libc/sysdeps/unix/sysv/linux/x86_64/syscall.S`)
/// issues the hardware `syscall` instruction directly; `syscall` does NOT
/// push a return address, so the top-of-stack at syscall entry is still the
/// return address to the wrapper's caller.  This gives us an immediate "who
/// called the libc syscall wrapper" frame without needing a full stack walk.
///
/// Returns `0` if the frame is not active or the read is unsafe.
///
/// NOTE: the read walks the active user CR3 (we are still on the user page
/// tables at the first instruction of the syscall handler, before any CR3
/// switch).  If the stack page is not mapped we return 0.  The read is
/// unguarded — a subsequent page fault would be fatal — so callers should
/// only invoke this from the syscall entry path where user_rsp is provably
/// mapped.
pub fn get_user_caller_rip() -> u64 {
    let (user_rsp, _) = get_user_rsp_rbp();
    if user_rsp == 0 { return 0; }
    // Sanity bounds: must be in a plausible user-space range and 8-byte
    // aligned.  Anything else is a corrupted frame; return 0 rather than
    // fault.
    if user_rsp < 0x1000 || user_rsp >= astryx_shared::KERNEL_VIRT_BASE { return 0; }
    if user_rsp & 0x7 != 0 { return 0; }
    // Fault-safe deref: walk the current process's page table.  A raw
    // *(user_rsp) deref hangs the syscall handler if user_rsp is in an
    // mmap'd-but-not-demand-paged stack page (the deref page-faults
    // inside the syscall path, observed during dlopen of libXfixes
    // which mmaps a fresh stack page just before issuing the next
    // syscall).  Returning 0 is acceptable — caller_rip is diagnostic
    // only and never load-bearing.
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let cr3 = crate::mm::vmm::get_cr3();
    match crate::mm::vmm::virt_to_phys_in(cr3, user_rsp) {
        Some(phys) => unsafe {
            core::ptr::read_unaligned((PHYS_OFF + phys) as *const u64)
        },
        None => 0,
    }
}

/// Return the kernel RSP set for the current CPU's active user thread.
/// Used by exit_group / current_tid_reliable to recover from a scheduling
/// race where PER_CPU_CURRENT_TID was transiently set to 0 by the idle path.
pub fn get_current_kernel_rsp() -> u64 {
    unsafe { PER_CPU_SYSCALL[cpu_index()].kernel_rsp }
}

/// Set the per-CPU logical CPU index in `IA32_TSC_AUX` (MSR 0xC0000103).
///
/// Must be called once per CPU **before** any call to `cpu_index()` / `current_tid()`.
/// The BSP calls this with `0` inside `syscall::init()`; each AP calls this
/// with its true APIC ID (read via LAPIC MMIO while the kernel CR3 is still
/// active) at the very start of `ap_rust_entry()`.
///
/// After this call `cpu_index()` / `current_apic_id()` return the correct
/// per-CPU index via `RDTSCP` (which reads `IA32_TSC_AUX` into ECX without
/// a VMEXIT — see `arch::x86_64::apic::cpu_index` for the rationale).
/// That path works regardless of which CR3 is loaded.
pub fn set_per_cpu_id(cpu_id: u8) {
    unsafe {
        crate::hal::wrmsr(0xC000_0103, cpu_id as u64);
    }
}

/// When set to a non-zero value, every Linux syscall made by the process
/// with that PID is printed to the serial console (used for debugging).
pub static DEBUG_TRACE_PID: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Global Linux syscall counter for the Firefox oracle test.
/// Incremented on every Linux syscall dispatch from any user-mode PID.
/// Reset to zero by the test before spawning Firefox, then read after
/// the process exits (or times out) to report progress.
pub static FIREFOX_SYSCALL_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Initialize the syscall interface.
pub fn init() {
    // BSP is always CPU 0.  Setting IA32_TSC_AUX = 0 here ensures that
    // current_apic_id() returns 0 for the BSP from now on, even while a
    // user-process page table is active.
    set_per_cpu_id(0);
    init_ap();
    crate::serial_println!("[SYSCALL] Initialized (int 0x80 + syscall/sysret)");
}

/// Configure the per-CPU syscall MSRs (EFER.SCE, STAR, LSTAR, SFMASK).
///
/// Must be called on **every** logical CPU (BSP and each AP) before that CPU
/// can run Ring-3 threads.  `init()` calls this for the BSP; `ap_rust_entry`
/// calls this for each AP.
pub fn init_ap() {
    unsafe {
        // Enable SCE (System Call Extensions) and NXE (No-Execute Enable) in IA32_EFER.
        // SCE = bit 0: required for syscall/sysret.
        // NXE = bit 11: required so the NX (bit 63) page-table flag is honoured
        //       instead of triggering a reserved-bit page fault.
        let efer = crate::hal::rdmsr(0xC000_0080);
        crate::hal::wrmsr(0xC000_0080, efer | (1 << 0) | (1 << 11));

        // IA32_STAR — Segment selectors for syscall/sysret
        // SYSCALL: CS = STAR[47:32], SS = STAR[47:32]+8
        // SYSRET:  SS = STAR[63:48]+8, CS = STAR[63:48]+16 (with RPL=3 added by CPU)
        // We want: kernel CS=0x08, SS=0x10; user CS=0x20|3, SS=0x18|3
        // So STAR[47:32]=0x08, STAR[63:48]=0x10
        let star_value = (0x08u64 << 32) | (0x10u64 << 48);
        crate::hal::wrmsr(0xC000_0081, star_value);

        // IA32_LSTAR — Syscall entry point
        // Fix truncated function pointer from mcmodel=kernel.
        crate::hal::wrmsr(0xC000_0082, crate::proc::thread::fixup_fn_ptr(syscall_entry as *const () as u64));

        // IA32_FMASK — RFLAGS bits to clear on SYSCALL entry.
        //
        // Per Intel SDM Vol. 3A §6.8.8 (SYSCALL flag-masking) every bit set in
        // FMASK is cleared in RFLAGS by the CPU as part of the SYSCALL
        // transition into ring 0.  We mask:
        //   - bit  8 (TF) — kernel must not run with single-step on a user-
        //                   controlled bit.
        //   - bit  9 (IF) — kernel must enter with interrupts disabled until
        //                   the entry stub has switched to the kernel stack.
        //   - bit 10 (DF) — System V AMD64 ABI requires DF=0 on call boundaries.
        //   - bit 18 (AC) — CWE-269 / CWE-693.  Without this bit masked, an
        //                   unprivileged ring-3 process can set EFLAGS.AC=1
        //                   from userspace (the AC bit is not privileged) and
        //                   issue SYSCALL.  The kernel then runs every code-
        //                   path that lacks an explicit UserGuard with SMAP
        //                   silently disabled, converting any latent
        //                   unbracketed user-pointer dereference from a
        //                   fail-stop fault into an arbitrary-kernel-write
        //                   primitive.  Masking AC here forces the kernel to
        //                   enter with AC=0 regardless of the user RFLAGS,
        //                   so SMAP only relaxes via an explicit STAC from
        //                   inside [`crate::arch::x86_64::smap::UserGuard`].
        //                   The companion fix at the IDT-gate level
        //                   (SMAP-gated CLAC prologue at the top of every
        //                   ring-3-callable IDT stub in
        //                   `kernel/src/arch/x86_64/idt.rs`) covers the
        //                   INT 0x80 / INT 0x2E / exception entry paths,
        //                   which bypass FMASK.
        const FMASK: u64 = 0x40700;
        crate::hal::wrmsr(0xC000_0084, FMASK);

        // ── Per-CPU data for SWAPGS ─────────────────────────────────
        // Set IA32_KERNEL_GS_BASE (0xC000_0102) to this CPU's slot in
        // PER_CPU_SYSCALL.  On SYSCALL entry, `swapgs` will load GS
        // from this MSR so the stub can use GS-relative addressing.
        let cpu = cpu_index();
        let base = &PER_CPU_SYSCALL[cpu] as *const PerCpuSyscallData as u64;
        crate::hal::wrmsr(0xC000_0102, base);
    }
}

/// Syscall dispatch — thin router, called from the asm `syscall_entry` stub and
/// the `int 0x80` IDT handler.
///
/// Routes to the correct subsystem handler based on the `SubsystemType` of the
/// current process. Public API for external callers lives in `crate::subsys::*`.
///
/// # ABI (Linux x86_64 register convention, shared by Aether and Linux paths)
/// - RAX: syscall number; RDI/RSI/RDX/R10/R8/R9: args 1–6
/// Global syscall counter for heartbeat diagnostics.
static SYSCALL_TOTAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub fn syscall_count() -> u64 { SYSCALL_TOTAL.load(core::sync::atomic::Ordering::Relaxed) }

pub fn dispatch(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    SYSCALL_TOTAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    crate::perf::record_syscall(num);

    // kdb syscall-trend ring: append (tick, pid, nr) so the kdb
    // `syscall-trend` op can produce a per-PID histogram of recent activity.
    // Wait-free; no allocation; produces zero overhead in non-kdb builds.
    #[cfg(feature = "kdb")]
    {
        let pid = crate::proc::current_pid_lockless();
        crate::perf::record_syscall_event(pid, num);
    }

    // Userspace-RIP-sampler bookkeeping: stamp the current CPU's
    // last-syscall tick so the timer ISR can detect threads that have
    // not issued any syscall for SILENT_THRESHOLD_TICKS while still
    // running in Ring 3 (W149 / W152).  Also stash the syscall nr and
    // arg0 so kdb `thread-park-audit` (PNG-1) can classify what each
    // blocked thread is parked inside without a syscall-ring walk.
    // Lock-free; four relaxed atomic stores. Behind firefox-test so
    // production builds pay nothing.
    #[cfg(feature = "firefox-test")]
    {
        let tid = crate::proc::current_tid();
        let tick = crate::arch::x86_64::irq::TICK_COUNT
            .load(core::sync::atomic::Ordering::Relaxed);
        crate::proc::sample::record_syscall(tid, tick, num, arg1);
    }

    let result = if crate::subsys::linux::syscall::is_linux_abi() {
        dispatch_linux(num, arg1, arg2, arg3, arg4, arg5, arg6)
    } else {
        dispatch_aether(num, arg1, arg2, arg3, arg4, arg5, arg6)
    };

    // Deferred preemption: check if the timer ISR set NEED_RESCHEDULE during
    // syscall execution.  We do this HERE (not from the timer ISR) to avoid
    // a self-deadlock: syscall handlers hold THREAD_TABLE with interrupts
    // enabled; if the ISR fires mid-lock and calls schedule() →
    // THREAD_TABLE.lock(), the same CPU spins forever on its own lock.
    // At this call site all syscall locks have been released.
    crate::sched::check_reschedule();

    result
}

/// Aether native syscall handler — for processes with `SubsystemType::Aether`.
///
/// Implements all native AstryxOS system calls (`SYS_EXIT` .. `SYS_SYNC`).
/// Exposed as `pub` so `crate::subsys::aether` can wrap it without creating a
/// circular dependency.  Prefer routing through `crate::syscall::dispatch()`.
///
/// # Phase 0.1 boundary
/// The match body will migrate to `crate::subsys::aether::syscall` in Phase 1.
/// Aether native syscall dispatch — delegates to `subsys/aether/syscall.rs`.
///
/// Exposed as `pub` so `crate::subsys::aether` can wrap it and so that
/// the test runner can call `crate::syscall::dispatch_aether()` directly.
/// The implementation body lives in `crate::subsys::aether::syscall::dispatch`.
pub fn dispatch_aether(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    crate::subsys::aether::syscall::dispatch(num, arg1, arg2, arg3, arg4, arg5, arg6)
}

/// Syscall entry point for the `syscall` instruction.
///
/// This handles syscalls from BOTH Ring 0 (kernel) and Ring 3 (user).
/// For Ring 3, the CPU does NOT switch stacks, so we must do it manually.
///
/// On entry (set by CPU):
///   RCX = return RIP
///   R11 = return RFLAGS
///   RSP = user stack (UNCHANGED by SYSCALL instruction)
///   RAX = syscall number
///   RDI, RSI, RDX, R10, R8, R9 = arguments
/// Read callee-saved registers from the current CPU's syscall entry frame.
/// syscall_entry stores kernel RSP (after all user-reg pushes) in per-CPU
/// slot gs:[24] (PerCpuSyscallData::frame_rsp).
///
/// Frame layout (u64 slots from frame_rsp, low → high):
///   [0]=rdi  [1]=rsi  [2]=rdx  [3]=r8  [4]=r9  [5]=r10
///   [6]=r15  [7]=r14  [8]=r13  [9]=r12  [10]=rbx  [11]=rbp
///   [12]=r11  [13]=rcx  [14]=user_rsp
pub(crate) fn read_fork_user_regs() -> crate::proc::ForkUserRegs {
    let cpu = cpu_index();
    let pcs = unsafe { &PER_CPU_SYSCALL[cpu as usize] };
    let rsp = pcs.frame_rsp;
    let kstack_top = pcs.kernel_rsp;
    if rsp == 0 {
        return crate::proc::ForkUserRegs::default();
    }
    // Same bounds check as `get_user_rsp_rbp`: refuse to read from a
    // saved-frame pointer that does not lie inside the current thread's
    // kernel stack, which would otherwise risk a kernel #PF if the page
    // were unmapped or returning garbage if it had been overwritten by
    // unrelated kernel work since the prior syscall.  The 15-slot frame
    // span matches the syscall_entry pushes (see layout comment above).
    const FRAME_TOP_OFF: u64 = 15 * 8;
    let stack_low = kstack_top.saturating_sub(KERNEL_STACK_SIZE_BYTES);
    if kstack_top == 0
        || rsp < stack_low
        || rsp.saturating_add(FRAME_TOP_OFF) > kstack_top
        || rsp & 0x7 != 0
    {
        return crate::proc::ForkUserRegs::default();
    }
    unsafe {
        let p = rsp as *const u64;
        crate::proc::ForkUserRegs {
            rbp: *p.add(11),
            rbx: *p.add(10),
            r12: *p.add(9),
            r13: *p.add(8),
            r14: *p.add(7),
            r15: *p.add(6),
            // R9 lives at frame slot 4 per the layout comment above.
            // Captured so clone(CLONE_THREAD) children can preserve the
            // entry-function pointer that musl's `__clone` stashes there.
            r9:  *p.add(4),
        }
    }
}

///
/// Callee-saved registers (RBX, RBP, R12-R15) are preserved.
/// Caller-saved registers (RDI, RSI, RDX, R10, R8, R9) may be clobbered.
#[unsafe(naked)]
extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // ── Step 1: Switch to kernel stack (per-CPU via SWAPGS) ─────
        // SWAPGS loads GS with KERNEL_GS_BASE → points at this CPU's
        // PerCpuSyscallData.  Save user RSP at offset 8, load kernel
        // RSP from offset 0, save user RIP (RCX) at offset 16.
        "swapgs",
        "mov gs:[8], rsp",               // per_cpu.user_rsp = user RSP
        "mov rsp, gs:[0]",               // RSP = per_cpu.kernel_rsp
        "mov gs:[16], rcx",              // per_cpu.user_rip = user RIP

        // ── Step 2: Save user context on kernel stack ───────────────
        // These are restored on SYSRETQ.
        "push qword ptr gs:[8]",         // saved user RSP
        "push rcx",                      // return RIP
        "push r11",                      // return RFLAGS
        // Done with GS-relative accesses; swap back so kernel code
        // runs with the user's GS (harmless — kernel never uses GS).
        // This also ensures KERNEL_GS_BASE is back to the per-CPU
        // pointer for the next SWAPGS at entry.
        "swapgs",
        // Callee-saved registers (user expects these preserved):
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Linux syscall ABI: ALL registers except RAX/RCX/R11 must be preserved.
        // Caller-saved in C ABI (RDX, R8, R9, R10) are clobbered by our arg
        // rearrangement and by the dispatch Rust function, so save them here.
        // 4 extra pushes → 13 total × 8 = 104 bytes; 104 % 16 = 8, so
        // RSP % 16 == 8 before call ✓ (same alignment as without these saves).
        // These are kept on the stack THROUGH signal_check so that signal_check
        // (a Rust function that follows the C ABI) cannot clobber r8/r9/r10/rdx.
        // The signal handler frame layout is therefore:
        //   frame[0]  = rax (syscall result)
        //   frame[1]  = rdx (user rdx)
        //   frame[2]  = r8  (user r8)
        //   frame[3]  = r9  (user r9)
        //   frame[4]  = r10 (user r10)
        //   frame[5]  = r15 … frame[13] = user RSP
        "push r10",
        "push r9",
        "push r8",
        "push rdx",
        // Save RSI and RDI — Linux syscall ABI requires ALL regs except
        // RAX/RCX/R11 to be preserved.  Without saving these, kernel
        // addresses leak into user space after SYSRET, causing crashes
        // when glibc stores the leaked values in data structures.
        "push rsi",
        "push rdi",
        // Save frame RSP into per-CPU slot for fork/clone to capture parent's
        // callee-saved regs.  At this point GS → user_gs_base (post-swapgs above),
        // so we must swapgs→kernel_gs, write, swapgs→user_gs.
        // Interrupts are still disabled (no sti yet), so the swapgs sequence is safe.
        // RSP points to: [rdi,rsi,rdx,r8,r9,r10,r15,r14,r13,r12,rbx,rbp,r11,rcx,user_rsp]
        "swapgs",              // GS → KERNEL_GS_BASE (per-CPU struct)
        "mov gs:[24], rsp",    // per_cpu.frame_rsp = frame RSP
        "swapgs",              // GS → user_gs_base (restore)

        // ── Step 3: Re-enable interrupts for syscall handling ───────
        "sti",

        // ── Step 4: Set up C calling convention for dispatch() ──────
        // Linux syscall ABI:  rax=num, rdi=a1, rsi=a2, rdx=a3, r10=a4, r8=a5, r9=a6
        // C calling convention (System V AMD64):
        //   rdi=num, rsi=a1, rdx=a2, rcx=a3, r8=a4, r9=a5, [rsp+8]=a6
        // We push a6 (R9) onto the stack as the 7th argument before shuffling,
        // so dispatch(num,a1,a2,a3,a4,a5,a6) gets all six syscall args.
        "sub rsp, 8",       // align + make room for arg6 on stack
        "mov [rsp], r9",    // arg6 (R9) → stack slot
        "mov r9, r8",       // arg5 -> r9
        "mov r8, r10",      // arg4 -> r8
        "mov rcx, rdx",     // arg3 -> rcx
        "mov rdx, rsi",     // arg2 -> rdx
        "mov rsi, rdi",     // arg1 -> rsi
        "mov rdi, rax",     // num  -> rdi
        "call {dispatch}",
        "add rsp, 8",       // pop the arg6 stack slot
        // Result in RAX.
        // NOTE: do NOT pop rdx/r8/r9/r10 yet — they must survive signal_check.

        // ── Step 5: Check for pending signals before returning ──────
        // Push RAX (syscall result) onto the stack so signal_check can
        // see it as frame[0], with frame[1..4]=rdx/r8/r9/r10 and frame[5..13].
        "push rax",
        "mov rdi, rsp",                 // arg1 = pointer to frame
        "call {signal_check}",
        // RAX = signal number (>0) if a handler was set up, 0 otherwise.
        "test rax, rax",
        "jz 2f",
        // Signal delivered: put signal number in RDI for the handler.
        "mov rdi, rax",
        "pop rax",                       // discard saved result
        "jmp 3f",
        "2:",
        "pop rax",                       // restore original syscall result
        "3:",

        // ── Step 4b: Restore caller-saved scratch regs ──────────────
        // Pop AFTER signal_check so the Rust function cannot clobber them.
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop r8",
        "pop r9",
        "pop r10",

        // ── Step 6: Disable interrupts before touching user state ───
        "cli",

        // ── Step 7: Restore user context ────────────────────────────
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "pop r11",          // RFLAGS for SYSRETQ
        "pop rcx",          // RIP for SYSRETQ
        "pop rsp",          // Restore user RSP (switches back to user stack)

        // ── Step 8: Return to Ring 3 ────────────────────────────────
        "sysretq",

        dispatch = sym dispatch,
        signal_check = sym crate::signal::signal_check_on_syscall_return,
    );
}

/// Dispatch a syscall from the int 0x80 IDT handler.
/// Called by the generic exception handler with vector=0x80.
/// The caller's registers are on the interrupt frame.
#[no_mangle]
pub extern "C" fn syscall_int80_dispatch(
    num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64
) -> i64 {
    dispatch(num, arg1, arg2, arg3, arg4, arg5, 0)
}

// ===== exec() Implementation ================================================

/// Execute a new program, replacing the current process image.
///
/// Execute a new program, replacing the current process image.
///
/// When called from user mode (via SYSCALL), this replaces the caller's
/// address space with the new program. On success it never returns —
/// execution continues at the new program's entry point.
///
/// When called from kernel mode (e.g., test dispatch), it falls back to
/// creating a new user-mode process (since there is no SYSCALL frame to return through).
///
/// Arguments: arg1 = path pointer, arg2 = path length.
pub(crate) fn sys_exec(path_ptr: u64, path_len: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
    // Copy the path into a kernel-resident String under a SMAP bracket so
    // subsequent uses (logging, VFS lookup, shebang resolution) do not
    // re-enter user space.  Anonymising the user borrow this way means we
    // only need ONE UserGuard scope for the path read regardless of how
    // far downstream the value travels.
    let path_owned = {
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        let slice = unsafe {
            core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize)
        };
        match core::str::from_utf8(slice) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => return -22, // EINVAL
        }
    };
    let path = path_owned.as_str();

    crate::serial_println!("[SYSCALL] exec(\"{}\")", path);

    // Read the target file from VFS.
    let file_data = match crate::vfs::read_file(path) {
        Ok(data) => data,
        Err(e) => {
            crate::serial_println!("[SYSCALL] exec: file not found: {:?}", e);
            return crate::subsys::linux::errno::vfs_err(e);
        }
    };

    // Read argv and envp arrays from user memory (null ptr → empty).
    let mut argv_owned = crate::subsys::linux::syscall::read_user_argv(argv_ptr);
    let envp_owned = crate::subsys::linux::syscall::read_user_argv(envp_ptr);

    // Default argv to [path] if caller passed NULL — before shebang resolution,
    // because `resolve_shebang` needs argv[0] to rewrite the new argv tail.
    if argv_owned.is_empty() {
        argv_owned.push(alloc::string::String::from(path));
    }

    // Resolve `#!` shebangs. If the file is already an ELF, this is a no-op.
    // Otherwise it reads the interpreter chain (up to SHEBANG_MAX_RECURSION
    // levels), rewrites argv, and returns the final interpreter ELF + argv.
    //
    // `final_path` is what `/proc/self/exe` and AT_EXECFN should resolve to —
    // i.e. the interpreter for a shebang-dispatched script, or the user-
    // requested path for a direct ELF execve(2).  Per Linux `proc(5)`:
    //   "/proc/[pid]/exe is a symbolic link containing the actual pathname
    //    of the executed command."
    let (elf_data, argv_owned, final_path) = {
        let argv_refs: alloc::vec::Vec<&str> = argv_owned.iter().map(|s| s.as_str()).collect();
        match crate::proc::elf::resolve_shebang(path, file_data, &argv_refs) {
            Ok(r) => (r.elf_data, r.argv, r.interp_path),
            Err(e) => {
                crate::serial_println!("[SYSCALL] exec: shebang/load error: {}", e);
                return e;
            }
        }
    };

    // Log the final argv so content-process roles (--contentproc <type> <fd>)
    // are visible in the serial trace.  Truncated to 16 args and 2 KiB
    // cumulative bytes to avoid log spam on deeply-nested command lines while
    // still capturing rich Mozilla/Firefox child-process command lines that
    // typically run to 12-14 args including JSON/--appdir/--profile pairs
    // (W120/W121 motivating case).  If truncation occurs, an `[EXEC argv-cont]`
    // continuation line emits the remaining args' tail.
    {
        const MAX_ARGS_SHOWN: usize = 16;
        const BYTE_BUDGET: usize = 2048;
        const BUF: usize = 2304; // headroom for quotes/spaces/binary placeholders
        let pid = crate::proc::current_pid_lockless();
        let tid = crate::proc::current_tid();
        let total_args = argv_owned.len();
        // Build a compact representation into a fixed-size stack buffer.
        // We use a simple byte-array writer to stay no_std / no-alloc.
        let mut buf = [0u8; BUF];
        let mut pos = 0usize;
        let mut byte_budget: usize = BYTE_BUDGET;
        let mut args_shown: usize = 0;

        macro_rules! push_byte {
            ($b:expr) => {
                if pos < BUF - 1 {
                    buf[pos] = $b;
                    pos += 1;
                }
            };
        }
        macro_rules! push_str {
            ($s:expr) => {
                for b in $s.as_bytes() {
                    push_byte!(*b);
                }
            };
        }

        for (i, arg) in argv_owned.iter().enumerate() {
            if i >= MAX_ARGS_SHOWN || byte_budget == 0 {
                break;
            }
            if i > 0 {
                push_byte!(b' ');
            }
            push_byte!(b'"');
            // Check for non-printable bytes; if any, emit <binary len=N> instead.
            let all_print = arg.bytes().all(|b| b >= 0x20 && b < 0x7f);
            if all_print {
                let take = arg.len().min(byte_budget);
                for b in arg.as_bytes()[..take].iter() {
                    push_byte!(*b);
                }
                byte_budget = byte_budget.saturating_sub(arg.len());
            } else {
                // Non-printable: emit placeholder without counting against budget.
                push_str!("<binary len=");
                // Emit decimal length inline.
                let n = arg.len();
                if n >= 1000 { push_byte!(b'0' + ((n / 1000) % 10) as u8); }
                if n >= 100  { push_byte!(b'0' + ((n / 100) % 10) as u8); }
                if n >= 10   { push_byte!(b'0' + ((n / 10) % 10) as u8); }
                push_byte!(b'0' + (n % 10) as u8);
                push_byte!(b'>');
            }
            push_byte!(b'"');
            args_shown += 1;
        }

        // NUL-terminate for safety, then convert the used slice.
        buf[pos] = 0;
        let shown = unsafe { core::str::from_utf8_unchecked(&buf[..pos]) };
        let truncated = total_args > args_shown || byte_budget == 0;
        if truncated {
            crate::serial_println!(
                "[EXEC] pid={} tid={} argv={} ({} of {} args shown)",
                pid, tid, shown, args_shown, total_args
            );
            // Emit a continuation line if there are more args to show — keeps
            // long Mozilla command lines (~14 args including IPC fds, JSON
            // prefs, etc.) fully greppable from the serial trace.
            if total_args > args_shown {
                let mut cont = [0u8; BUF];
                let mut cpos = 0usize;
                let mut cbudget: usize = BYTE_BUDGET;
                macro_rules! cpush_byte {
                    ($b:expr) => {
                        if cpos < BUF - 1 {
                            cont[cpos] = $b;
                            cpos += 1;
                        }
                    };
                }
                for (j, arg) in argv_owned.iter().enumerate().skip(args_shown) {
                    if j - args_shown >= MAX_ARGS_SHOWN || cbudget == 0 {
                        break;
                    }
                    if cpos > 0 { cpush_byte!(b' '); }
                    cpush_byte!(b'"');
                    let all_print = arg.bytes().all(|b| b >= 0x20 && b < 0x7f);
                    if all_print {
                        let take = arg.len().min(cbudget);
                        for b in arg.as_bytes()[..take].iter() { cpush_byte!(*b); }
                        cbudget = cbudget.saturating_sub(arg.len());
                    } else {
                        for b in b"<binary>" { cpush_byte!(*b); }
                    }
                    cpush_byte!(b'"');
                }
                cont[cpos] = 0;
                let cshown = unsafe { core::str::from_utf8_unchecked(&cont[..cpos]) };
                crate::serial_println!(
                    "[EXEC argv-cont] pid={} tid={} argv={}",
                    pid, tid, cshown
                );
            }
        } else {
            crate::serial_println!(
                "[EXEC] pid={} tid={} argv={} ({} args)",
                pid, tid, shown, total_args
            );
        }
    }

    // Validate it's an ELF binary (resolve_shebang guarantees this on Ok).
    if !crate::proc::elf::is_elf(&elf_data) {
        crate::serial_println!("[SYSCALL] exec: not an ELF binary");
        return -8; // ENOEXEC
    }

    // Build &[&str] slices valid for the duration of this call.
    let argv_strs: alloc::vec::Vec<&str> = argv_owned.iter().map(|s| s.as_str()).collect();
    let envp_strs: alloc::vec::Vec<&str> = envp_owned.iter().map(|s| s.as_str()).collect();

    let argv_slice: &[&str] = &argv_strs;
    let envp_slice: &[&str] = if envp_strs.is_empty() {
        &["HOME=/", "PATH=/bin:/disk/bin"]
    } else {
        &envp_strs
    };

    let pid = crate::proc::current_pid_lockless();

    // Classify the caller into one of three execve(2) dispatch cases:
    //
    //   (A) Kernel-mode caller — no user address space at all.  We synthesise
    //       a fresh user process from the ELF (legacy path).  Identified by:
    //       `vm_space.is_none() && (cr3 == 0 || cr3 == kernel_cr3)`.
    //
    //   (B) User-mode caller that owns its own VmSpace.  Standard execve(2):
    //       build a new VmSpace, swap it in, free the old.  Identified by:
    //       `vm_space.is_some()`.
    //
    //   (C) User-mode caller in a shared-VM state — the canonical
    //       `posix_spawn(3) / vfork(2)` shape after `fork_process_share_vm`:
    //       no owned VmSpace but a user CR3 inherited from the parent.  We
    //       build a fresh VmSpace, install it, switch CR3 — but we MUST NOT
    //       free the old CR3 (it belongs to the parent and is still in use).
    //       Identified by: `vm_space.is_none() && cr3 != kernel_cr3 && cr3 != 0`.
    //
    // Per POSIX `posix_spawn(3)` and `vfork(2)`, the parent unblocks the
    // moment the child successfully installs a new image — case (C) calls
    // `wake_vfork_parent()` once the new CR3 is loaded, closing the
    // parent-unblock latency from the 500-tick safety timeout to a few µs.
    let kernel_cr3 = crate::mm::vmm::get_kernel_cr3();
    let (has_vm_space, proc_cr3) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        match procs.iter().find(|p| p.pid == pid) {
            Some(p) => (p.vm_space.is_some(), p.cr3),
            None    => (false, 0),
        }
    };
    let is_shared_vm_child =
        !has_vm_space && proc_cr3 != 0 && proc_cr3 != kernel_cr3;

    if !has_vm_space && !is_shared_vm_child {
        // (A) Kernel caller — create a new user process (legacy path).
        // Use `final_path` (post-shebang interpreter path) so /proc/self/exe
        // resolves to the actual ELF that runs, not the script entry point.
        match crate::proc::usermode::create_user_process_with_args(final_path.as_str(), &elf_data, argv_slice, envp_slice) {
            Ok(new_pid) => {
                // ELFs loaded from disk use the Linux syscall ABI.
                {
                    let mut procs = crate::proc::PROCESS_TABLE.lock();
                    if let Some(p) = procs.iter_mut().find(|p| p.pid == new_pid) {
                        p.linux_abi = true;
                        p.subsystem = crate::win32::SubsystemType::Linux;
                    }
                }
                crate::serial_println!("[SYSCALL] exec: created process PID {} (linux_abi=true)", new_pid);
                return new_pid as i64;
            }
            Err(e) => {
                crate::serial_println!("[SYSCALL] exec: ELF load failed: {:?}", e);
                return -22;
            }
        }
    }

    // ── User-mode exec: replace the current process image ──────────
    // Both (B) and (C) share most of the replace-image work.  The only
    // difference is the post-condition handling of the old address space:
    //   (B): `old_vm_space = Some(_)` → must be freed.
    //   (C): `old_vm_space = None`    → nothing to free; parent retains its
    //        page tables.  We log the shared-VM exec so the timeline of a
    //        posix_spawn cycle is greppable.
    if is_shared_vm_child {
        crate::serial_println!(
            "[SYSCALL] exec: shared-VM child PID {} cr3={:#x} → installing fresh VmSpace",
            pid, proc_cr3,
        );
    }

    // 1. Create a fresh address space and load the new ELF into it.
    let mut new_vm_space = match crate::mm::vma::VmSpace::new_user() {
        Some(vs) => vs,
        None => return -12, // ENOMEM
    };

    let result = match crate::proc::elf::load_elf_with_args(&elf_data, new_vm_space.cr3, argv_slice, envp_slice) {
        Ok(r) => r,
        Err(e) => {
            crate::serial_println!("[SYSCALL] exec: ELF load failed: {:?}", e);
            return -22;
        }
    };

    // Insert VMAs into the new VmSpace.
    for vma in result.vmas {
        let _ = new_vm_space.insert_vma(vma);
    }

    let new_cr3 = new_vm_space.cr3;
    let entry_rip = result.entry_point;
    let entry_rsp = result.user_stack_ptr;
    // Capture the new image's TCB VA before the SYSRET-frame rewrite at
    // step 6 — step 5d below WRMSRs this into `IA32_FS_BASE` so the new
    // image's `_start` enters user mode with FS.base pointing at PT_TLS
    // (not the launcher's freed TCB).  Per ELF gABI §3.5 / System V
    // AMD64 ABI §3.4.2; `0` for static binaries with no PT_TLS segment.
    let entry_tls_base = result.tls_base;

    crate::serial_println!(
        "[SYSCALL] exec: replacing PID {} image → entry={:#x} stack={:#x} cr3={:#x}",
        pid, entry_rip, entry_rsp, new_cr3
    );

    // 2. Update the process's address space, atomically swapping in the new
    //    VmSpace and extracting the old one so we can free it afterwards.
    //
    //    We do NOT free the old VmSpace while holding PROCESS_TABLE lock —
    //    free_vm_space walks page tables and calls into the PMM (which has its
    //    own lock).  Holding two locks in that order could deadlock with the
    //    PMM's internal locking.  Instead we take ownership of the old VmSpace
    //    here, release PROCESS_TABLE, and free afterwards (below).
    let old_vm_space = {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let mut extracted = None;
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            // Swap in the new address space.
            p.cr3 = new_cr3;
            // Option::replace returns the prior value:
            //   (B) `Some(old)` — the previous private VmSpace, must be freed.
            //   (C) `None`      — the shared-VM child case: there was nothing
            //                     here, and the parent still owns its own
            //                     `vm_space` + `cr3`.  We must NOT touch those.
            extracted = p.vm_space.replace(new_vm_space);
            // ELFs loaded from disk use the Linux syscall ABI.
            p.linux_abi = true;
            p.subsystem = crate::win32::SubsystemType::Linux;
            // Update /proc/self/exe to the new image's path.  Per `proc(5)`,
            // the symlink target follows the executed program across
            // execve(2) — including the case where the caller forked from
            // another binary (posix_spawn fast path, vfork+exec).  Without
            // this update, readlink("/proc/self/exe") in the new image would
            // return the *parent's* path (or the fallback for case-C), which
            // breaks any program that derives sibling resource paths from
            // its own location (Mozilla's dependentlibs.list is the W120
            // motivating case).
            p.exe_path = Some(final_path.clone());
            // Close all FDs marked close-on-exec (O_CLOEXEC / FD_CLOEXEC).
            //
            // Pipes, unix sockets, and other refcount-bearing objects
            // need their open-file-description count dropped HERE, not
            // just the fd slot zeroed.  Without this, the canonical musl
            // posix_spawn(3) cancel-pipe pattern hangs: the parent calls
            // `pipe2(O_CLOEXEC)` then clones; the child execve(2) into
            // the new image purges its CLOEXEC fds but never tells the
            // pipe that one writer just left, so the parent's blocked
            // `read(2)` on the other end never observes EOF (per POSIX
            // `read(2)`: "If no process has the pipe open for writing,
            // read() shall return 0 to indicate end-of-file").  W101
            // sc=1972 plateau motivating case.
            for fd_slot in p.file_descriptors.iter_mut() {
                if let Some(f) = fd_slot.as_ref() {
                    if f.cloexec {
                        // Drop pipe refcounts before clearing the slot.
                        crate::proc::close_pipe_fd(f);
                        // Drop unix-socket refcount too — parallel of the
                        // same gap for AF_UNIX inherit-through-vfork.  An
                        // AF_INET socket reaches `crate::net::socket` via
                        // its own table and is not refcounted via the
                        // unix layer; gate accordingly.
                        if f.file_type == crate::vfs::FileType::Socket
                            && f.flags & crate::syscall::UNIX_SOCKET_FLAG != 0
                        {
                            crate::net::unix::close(f.inode);
                        }
                    }
                }
                if matches!(fd_slot, Some(f) if f.cloexec) {
                    *fd_slot = None;
                }
            }
        }
        extracted
    };

    // 3. Get kernel stack info for this thread.
    let kstack_top = {
        let tid = crate::proc::current_tid();
        let threads = crate::proc::THREAD_TABLE.lock();
        let t = threads.iter().find(|t| t.tid == tid)
            .expect("sys_exec: current thread not found");
        t.kernel_stack_base + t.kernel_stack_size
    };

    // 4. Switch to the new page table.
    //    This MUST happen before free_vm_space() so the hardware CR3 no longer
    //    references the old page tables when we free their backing frames.
    unsafe { crate::mm::vmm::switch_cr3(new_cr3); }

    // 4a. K2b F3 foreign-frame writer trap arm — gated on `f3-watch` and
    //     additionally guarded by the F3 module's own path-substring check
    //     against `"firefox-bin"` plus a per-boot `F3_ARM_MAX` cap.  Posts
    //     two `[F3-WATCH]` lines (one per channel: user-VA and PHYS_OFF)
    //     and arms persistent DR write-only watchpoints on the canary
    //     slot at `0x7ffffffee4c0`.  Subsequent writes from any CPU emit
    //     `[W215/DR-WATCH-FIRE] kind_tag=1|2 …` naming the writer RIP +
    //     CR3 — see `subsys/linux/f3_watch.rs` for the F3-mode → RIP map.
    //
    //     Diagnostic-only; no behavioural change to the execve path.
    //     Refs: Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7); System V AMD64
    //     ABI §6.4 (SSP / `__stack_chk_guard`); POSIX execve(2).
    #[cfg(feature = "f3-watch")]
    crate::subsys::linux::f3_watch::arm_after_execve(
        final_path.as_str(), new_cr3, entry_rip, entry_rsp,
    );

    // 4a.bis. D16 SSP-canary PHYS_OFF channel arm.  Anchors on the
    //     deterministic backing phys `0x127114c0` observed byte-identical
    //     across 3 KVM trials post-PR #368.  Eager arm at execve time
    //     means the prologue's first store will fire on the PHYS_OFF
    //     channel without needing the user stack page to be demand-paged
    //     first.  The complementary user-VA channel is late-armed from
    //     the Linux syscall-entry hook (`subsys/linux/syscall::dispatch`).
    //
    //     Diagnostic-only; no behavioural change to the execve path.
    //     Refs: Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7); Intel SDM
    //     Vol. 3A §4.10 (TLB / PHYS_OFF coherence); System V AMD64 ABI
    //     §3.4.1 (SSP / `__stack_chk_guard`); POSIX execve(2).
    #[cfg(feature = "d16-canary-watch")]
    crate::subsys::linux::d16_canary_watch::arm_after_execve(
        final_path.as_str(), new_cr3, entry_rip, entry_rsp,
    );

    // 4b. Reclaim the old address space now that the hardware no longer uses it.
    //     free_vm_space() walks old VMAs, decrements CoW refcounts, frees any
    //     anonymous pages whose refcount reaches zero, and releases the old PT
    //     structures (PT/PD/PDPT/PML4) back to the PMM.
    //     This is safe: we hold no locks, the new CR3 is active, and the old
    //     VmSpace is local (not referenced by any other thread or CPU).
    //
    //     For Case (C) — shared-VM child — `old_vm_space` is None.  The
    //     parent still owns the page tables we were borrowing, and the
    //     `if let` arm is skipped: we do NOT free anything.  This is the
    //     invariant that keeps vfork(2)/posix_spawn(3) safe.
    if let Some(old_space) = old_vm_space {
        crate::proc::free_vm_space(old_space);
    }

    // 5. Update kernel stack pointers for Ring 3 transitions.
    unsafe {
        crate::arch::x86_64::gdt::update_tss_rsp0(kstack_top);
        set_kernel_rsp(kstack_top);
    }

    // 5a. Vfork isolated-stack cleanup (Case C — shared-VM child).
    //
    //     If the clone(2)/vfork(2) machinery allocated a per-child stack
    //     VMA in the parent's address space (so the child could not
    //     overflow into the parent's frame — see
    //     `proc::alloc_vfork_child_stack`), unmap it now before unblocking
    //     the parent.  At this point the new VmSpace is installed and the
    //     hardware CR3 is the child's NEW cr3, so the unmap targets the
    //     **parent's** page tables (looked up via the parent's pid) — not
    //     the address space we are currently executing on.
    //
    //     The parent never reads from the vfork stack region — it remains
    //     blocked in `schedule()` with its own RSP elsewhere — so the
    //     unmap is race-free with respect to the parent thread.
    if is_shared_vm_child {
        let (parent_pid, isolated_stack, isolated_tls) = {
            let tid = crate::proc::current_tid();
            let procs = crate::proc::PROCESS_TABLE.lock();
            let threads = crate::proc::THREAD_TABLE.lock();
            let parent_pid = procs
                .iter()
                .find(|p| p.pid == pid)
                .map(|p| p.parent_pid)
                .unwrap_or(0);
            let t = threads.iter().find(|t| t.tid == tid);
            let isolated_stack = t.and_then(|t| t.vfork_isolated_stack);
            let isolated_tls = t.and_then(|t| t.vfork_isolated_tls);
            (parent_pid, isolated_stack, isolated_tls)
        };
        if let Some((base, length)) = isolated_stack {
            if parent_pid != 0 {
                crate::proc::vfork_isolated_stack_cleanup(parent_pid, base, length);
            }
            // Clear the field so a later (e.g. exit) path does not try to
            // unmap a now-stale range.
            let tid = crate::proc::current_tid();
            let mut threads = crate::proc::THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                t.vfork_isolated_stack = None;
            }
        }

        // Companion: drop the per-vfork-child TLS page.  execve(2) is about
        // to install a fresh VmSpace via the standard ELF load path, which
        // includes a real `__init_tls` allocating a new TCB; the bridge
        // page provisioned at clone time has done its job and must not
        // survive into the new image as a stray `[vfork-tls]` mapping in
        // the parent's address space.
        if let Some((base, length)) = isolated_tls {
            if parent_pid != 0 {
                crate::proc::vfork_isolated_tls_cleanup(parent_pid, base, length);
            }
            let tid = crate::proc::current_tid();
            let mut threads = crate::proc::THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                t.vfork_isolated_tls = None;
            }
        }
    }

    // 5b. vfork completion: wake the blocked parent NOW.  The new mm is
    //     installed, the old one is reclaimed, the CR3 is loaded, and the
    //     kernel stack is rebound to TSS — the child is fully ready to run
    //     the new image even before we finish patching the syscall return
    //     frame below.  Waking here closes the parent-unblock latency to
    //     a few µs (vs the 500-tick safety timeout that previously masked
    //     this).  Per `vfork(2)` and the POSIX `posix_spawn(3)` contract,
    //     the parent must unblock when the child successfully installs a
    //     new image — reaching this point in execve(2) is that moment.
    wake_vfork_parent();

    // 5c. Reset the per-thread thread-exit protocol slots on the surviving
    //     thread per `execve(2)` ABI.  The new image must start with a
    //     clean `clear_child_tid` and `robust_list` slate — if it cares
    //     about either, it will re-register via `set_tid_address(2)` and
    //     `set_robust_list(2)` from its own startup code (glibc/musl
    //     `__libc_setup_tls` and the pthread bootstrap).
    //
    //     Why this matters: the calling thread's `clear_child_tid` was
    //     registered by the *previous* image against a user VA that is
    //     about to be unmapped and replaced.  If the slot survives the
    //     exec, the kernel's eventual `exit_thread` zero-store +
    //     `FUTEX_WAKE` (the CLONE_CHILD_CLEARTID protocol per
    //     `clone(2)`) would land on whatever VA the new image happens to
    //     have at that offset — under firefox-bin the worst case is
    //     BaseProfiler's `RegisteredThread::mThreadInfo` storage, where
    //     a stale zero-store produces an unrelated NULL deref far away
    //     from any exit path.  The same shape applies to
    //     `robust_list_head` / `robust_list_len` per `set_robust_list(2)`
    //     /`get_robust_list(2)`: the kernel would walk a head pointer
    //     into the new image's memory at the next exit.
    //
    //     Threat-model: CWE-672 (Operation on Resource After Expiration
    //     or Release).  Stale per-thread state surviving exec violates
    //     the `execve(2)` process-image cleanslate guarantee.
    //
    //     Note: `tls_base` / FS.base is handled separately in step 5d
    //     below; see the rationale there.  (An earlier rev of this code
    //     deferred FS.base entirely to the new image's
    //     `arch_prctl(ARCH_SET_FS, ...)`; that window proved to be a
    //     CWE-908 use-of-uninitialised-resource hazard because the old
    //     image's TCB VA had already been unmapped at step 4b.)
    exec_reset_thread_exit_slots(crate::proc::current_tid());

    // 5d. Point FS.base at the NEW image's PT_TLS TCB before SYSRETQ.
    //
    //     The previous image's FS.base still lives in the CPU's
    //     `IA32_FS_BASE` MSR (`0xC000_0100`) at this point — SYSCALL
    //     does NOT touch it (Intel SDM Vol. 2B `SYSCALL`/`SYSRETQ`).
    //     But the previous image's TLS pages are gone: step 4 swapped
    //     CR3 to the new VmSpace and step 4b called `free_vm_space()`,
    //     which decremented refcounts on the old VMAs, freed any
    //     anonymous pages whose refcount reached zero, and released
    //     the old PT structures back to the PMM (see
    //     `proc::free_vm_space`).  Leaving FS.base pointing into the
    //     freed TCB VA opens a window between the SYSRETQ into the
    //     new `_start` and the new image's first
    //     `arch_prctl(ARCH_SET_FS, ...)` (or musl's `__init_tls`)
    //     during which any TLS-relative read or write — including
    //     dynamic linker code paths, early constructors with
    //     `__thread` storage, and stack-protector epilogue checks at
    //     `%fs:0x28` (System V AMD64 ABI §6.4) — lands in
    //     uninitialised or reused physical memory at the new VA's
    //     PT_TLS template.  Empirically (sc=1171 firefox-bin gate)
    //     the read returns plausible-looking-but-residual data and
    //     the offending function (`GetThreadRegistrationTime`,
    //     mozglue BaseProfiler) faults later at
    //     `mov rbx,[r14+0x20]` with `r14 == NULL`.
    //
    //     The fix mirrors the existing FS.base setup on the initial
    //     `enter_user_mode` path (`proc/usermode.rs` — the WRMSR at
    //     the bootstrap site).  After this point FS.base names the
    //     new image's TCB; once the new image runs and issues its own
    //     `arch_prctl(ARCH_SET_FS, ...)` (or musl `__set_thread_area`
    //     under glibc-compat) the MSR is overwritten with the
    //     userspace-chosen TCB — there is no conflict.
    //
    //     Threat-model: CWE-908 (Use of Uninitialized Resource).
    //
    //     Refs:
    //       * Intel SDM Vol. 3A §3.4.4 / §3.4.4.1 (`IA32_FS_BASE` MSR,
    //         FS segment loading; SYSCALL/SYSRETQ do not modify it)
    //       * Intel SDM Vol. 2B (`SYSCALL`, `SYSRETQ`)
    //       * `execve(2)` — process-image replacement (new image's
    //         TLS template comes from PT_TLS per the ELF gABI §3.5)
    //       * `arch_prctl(2)` (ARCH_SET_FS / ARCH_GET_FS)
    //       * `clone(2)` (CLONE_SETTLS interaction)
    //       * System V AMD64 ABI §3.4.2 (Thread-Local Storage variant II)
    exec_set_thread_tls_base(crate::proc::current_tid(), entry_tls_base);
    unsafe { crate::proc::write_fs_base(entry_tls_base); }

    // 6. Modify the syscall return frame on the kernel stack so that when
    //    we return through syscall_entry's epilogue, SYSRETQ jumps to the
    //    new entry point with the new stack.
    //    Layout (from syscall_entry):
    //      kstack_top - 8  = user RSP
    //      kstack_top - 16 = RCX (user RIP)
    //      kstack_top - 24 = R11 (RFLAGS)
    //      kstack_top - 32 = RBP
    //      kstack_top - 40 = RBX
    //      kstack_top - 48 = R12
    //      kstack_top - 56 = R13
    //      kstack_top - 64 = R14
    //      kstack_top - 72 = R15
    unsafe {
        *((kstack_top - 8)  as *mut u64) = entry_rsp;   // user RSP
        *((kstack_top - 16) as *mut u64) = entry_rip;   // user RIP (via RCX → SYSRETQ)
        *((kstack_top - 24) as *mut u64) = 0x202;       // RFLAGS (IF set)
        *((kstack_top - 32) as *mut u64) = 0;           // RBP
        *((kstack_top - 40) as *mut u64) = 0;           // RBX
        *((kstack_top - 48) as *mut u64) = 0;           // R12
        *((kstack_top - 56) as *mut u64) = 0;           // R13
        *((kstack_top - 64) as *mut u64) = 0;           // R14
        *((kstack_top - 72) as *mut u64) = 0;           // R15
    }

    crate::serial_println!("[SYSCALL] exec: process image replaced, returning to new entry");

    // (vfork wake already happened in step 5b above — see comment there.)

    // Return 0 — dispatch puts this in RAX. When syscall_entry does SYSRETQ,
    // it restores the modified frame and jumps to the new entry point.
    // Note: for a true exec, the return value in RAX is irrelevant because
    // the new process image doesn't expect a return value from exec.
    0
}

/// Wake the vfork parent if the current thread is a vfork child.
/// Called from both sys_exec() and exit_thread().
pub fn wake_vfork_parent() {
    let tid = crate::proc::current_tid();
    let parent_tid = {
        let threads = crate::proc::THREAD_TABLE.lock();
        threads.iter().find(|t| t.tid == tid)
            .and_then(|t| t.vfork_parent_tid)
    };
    if let Some(ptid) = parent_tid {
        crate::serial_println!("[VFORK] child tid={} waking parent tid={}", tid, ptid);
        let mut threads = crate::proc::THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.vfork_parent_tid = None;
        }
        if let Some(p) = threads.iter_mut().find(|t| t.tid == ptid) {
            if p.state == crate::proc::ThreadState::Blocked {
                p.state = crate::proc::ThreadState::Ready;
            }
        }
    }
}

/// Reset the per-thread thread-exit protocol slots on `execve(2)`.
///
/// Per `execve(2)`, the new image starts with no `CLONE_CHILD_CLEARTID`
/// address registered and no robust-futex list; if the new image cares
/// about either it will re-register via `set_tid_address(2)` and
/// `set_robust_list(2)` from its own startup code (glibc/musl pthread
/// bootstrap).  Carrying the old image's values across exec would let a
/// later `exit_thread` zero-store + `FUTEX_WAKE` (the
/// `CLONE_CHILD_CLEARTID` protocol per `clone(2)`) land on whatever VA
/// the new image happens to have at that offset — under firefox-bin the
/// worst case is BaseProfiler's `RegisteredThread::mThreadInfo` storage,
/// where a stale zero-store produces an unrelated NULL deref far away
/// from any exit path.  The robust-list head/len fields have the same
/// shape per `set_robust_list(2)`/`get_robust_list(2)`: the kernel would
/// walk a stale head pointer at the next exit.
///
/// Threat-model: CWE-672 (Operation on Resource After Expiration or
/// Release).  Stale per-thread state surviving exec violates the
/// `execve(2)` process-image cleanslate guarantee.
///
/// Called by `sys_exec` (post-image-install, pre-SYSRET-frame-rewrite)
/// and by the `execve(2)` ABI test in `test_runner.rs`.
pub(crate) fn exec_reset_thread_exit_slots(tid: crate::proc::Tid) {
    let mut threads = crate::proc::THREAD_TABLE.lock();
    if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
        t.clear_child_tid  = 0;
        t.robust_list_head = 0;
        t.robust_list_len  = 0;
    }
}

/// Point the surviving thread's `tls_base` (and, via the companion
/// `proc::write_fs_base` call at the `sys_exec` site, the CPU's
/// `IA32_FS_BASE` MSR) at the new image's PT_TLS TCB virtual address.
///
/// Required to satisfy the `execve(2)` cleanslate contract: SYSCALL on
/// x86-64 does not touch FS.base (Intel SDM Vol. 2B `SYSCALL` /
/// `SYSRETQ`), so without this, SYSRETQ would return into the new
/// image's `_start` with the **previous** image's FS.base loaded — and
/// that VA's backing pages were freed at the prior `free_vm_space`
/// step.  The first TLS-relative load (`%fs:0x28` stack-protector
/// canary, ELF `.tdata` access, dynamic linker `_dl_*` thread-local,
/// or musl `__init_tls` self-check) would read uninitialised or
/// reused physical memory.
///
/// `new_tls_base` is `result.tls_base` from `proc::elf::load_elf_*`:
/// the TCB self-pointer VA computed during PT_TLS layout, or `0` for
/// a static binary with no PT_TLS.  When `0`, the helper still stores
/// the value and the caller still WRMSRs `0` — mirroring the
/// unconditional write at the initial `enter_user_mode` site so
/// CLONE_VM children with no TLS explicitly zero the CPU MSR rather
/// than inheriting a stale ancestor value.
///
/// Threat-model: CWE-908 (Use of Uninitialized Resource) — without
/// this, the kernel returns to user mode with FS.base pointing into
/// memory that was just freed.
///
/// Refs:
///   * Intel SDM Vol. 3A §3.4.4 / §3.4.4.1 — IA32_FS_BASE MSR
///   * Intel SDM Vol. 2B — SYSCALL/SYSRETQ (no MSR side effects)
///   * `execve(2)` — process-image replacement
///   * `arch_prctl(2)` — ARCH_SET_FS / ARCH_GET_FS
///   * `clone(2)` — CLONE_SETTLS
///   * System V AMD64 ABI §3.4.2 / §6.4 — TLS variant II, stack
///     protector at `%fs:0x28`
///   * ELF gABI §3.5 — Thread-local storage
pub(crate) fn exec_set_thread_tls_base(tid: crate::proc::Tid, new_tls_base: u64) {
    let mut threads = crate::proc::THREAD_TABLE.lock();
    if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
        t.tls_base = new_tls_base;
    }
}

/// Kernel-callable exec: load and run an ELF binary from the VFS.
///
/// This is called from the kernel shell for `exec` commands. Unlike the
/// syscall version, this blocks until the process exits (cooperative).
pub fn kernel_exec(path: &str) -> Result<crate::proc::Pid, i64> {
    crate::serial_println!("[EXEC] Loading '{}'...", path);

    let elf_data = match crate::vfs::read_file(path) {
        Ok(data) => data,
        Err(e) => {
            crate::serial_println!("[EXEC] File not found: {:?}", e);
            return Err(crate::subsys::linux::errno::vfs_err(e));
        }
    };

    if !crate::proc::elf::is_elf(&elf_data) {
        crate::serial_println!("[EXEC] Not an ELF binary");
        return Err(-8);
    }

    match crate::proc::usermode::create_user_process(path, &elf_data) {
        Ok(pid) => {
            crate::serial_println!("[EXEC] Process PID {} created, scheduling...", pid);
            // Yield to let the new process run.
            crate::sched::yield_cpu();
            Ok(pid)
        }
        Err(e) => {
            crate::serial_println!("[EXEC] ELF load failed: {:?}", e);
            Err(-22)
        }
    }
}

// ===== fork() Implementation ================================================

/// Fork the current process.
///
/// Creates a new process that is a copy of the current one. Both processes
/// share the same address space (since we use a single page table currently).
///
/// Returns:
/// - In parent: child PID (> 0)
/// - In child: 0
/// - On error: negative errno
///
/// Note: Since AstryxOS currently uses a single shared address space (one CR3),
/// fork creates a new process + thread that shares the same code/data pages.
/// This is similar to vfork() semantics — the child should call exec() promptly.
pub(crate) fn sys_fork() -> i64 {
    sys_fork_impl(0, 0)
}

/// Fork implementation shared by sys_fork() (syscall 57) and clone()-style fork (syscall 56).
/// `clone_flags` and `child_tidptr` are only used when called from clone().
pub(crate) fn sys_fork_impl(clone_flags: u64, child_tidptr: u64) -> i64 {
    const CLONE_CHILD_SETTID: u64 = 0x01000000;
    const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

    let parent_pid = crate::proc::current_pid_lockless();
    let parent_tid = crate::proc::current_tid();

    // Capture parent's callee-saved regs from the syscall entry frame BEFORE
    // fork_process() takes THREAD_TABLE lock (which changes the frame context).
    let parent_regs = read_fork_user_regs();

    crate::serial_println!("[SYSCALL] fork() from PID {} TID {}", parent_pid, parent_tid);

    // Create a new process (child) with a new PID and thread.
    match crate::proc::fork_process(parent_pid, parent_tid, &parent_regs) {
        Some((child_pid, child_tid)) => {
            crate::serial_println!("[SYSCALL] fork: child PID {} created", child_pid);

            // Parent callee-saved regs are now baked into the child's kernel stack
            // by fork_process() → init_fork_child_stack().  No need for set_fork_user_regs.

            // CLONE_CHILD_SETTID: write child TID to child_tidptr in child's address space.
            // Since child shares physical pages with parent (CoW, not yet written), writing
            // through the child's CR3 is equivalent to writing to the shared physical page.
            if clone_flags & CLONE_CHILD_SETTID != 0 && child_tidptr != 0 {
                let child_cr3 = crate::proc::get_process_cr3(child_pid).unwrap_or(0);
                if child_cr3 != 0 {
                    write_u32_to_user(child_cr3, child_tidptr, child_tid as u32);
                    crate::serial_println!("[FORK] CLONE_CHILD_SETTID: wrote tid={} to {:#x}", child_tid, child_tidptr);
                }
            }

            // CLONE_CHILD_CLEARTID: store child_tidptr in thread so exit() can futex-wake it.
            if clone_flags & CLONE_CHILD_CLEARTID != 0 && child_tidptr != 0 {
                crate::proc::set_clear_child_tid(child_pid, child_tid, child_tidptr);
            }

            // Now that fork_user_regs are written, unblock the child so the scheduler
            // can pick it up.  The child was created Blocked to prevent an AP from
            // scheduling it before its register state was initialised.
            crate::proc::unblock_process(child_pid);

            child_pid as i64 // Return child PID to parent
        }
        None => {
            crate::serial_println!("[SYSCALL] fork: failed to create child");
            -12 // ENOMEM
        }
    }
}

/// Write a 32-bit value to a virtual address in the CURRENT process's page tables.
/// Used for CLONE_CHILD_SETTID / CLONE_PARENT_SETTID in the clone3 thread path
/// (CLONE_VM: parent and child share address space → same CR3).
pub(crate) unsafe fn write_u32_to_user_current(vaddr: u64, val: u32) {
    let cr3 = crate::mm::vmm::get_cr3();
    write_u32_to_user(cr3, vaddr, val);
}

/// Public wrapper for CLONE_CHILD_CLEARTID in exit path (proc/mod.rs).
pub fn write_u32_to_user_pub(cr3: u64, vaddr: u64, val: u32) {
    write_u32_to_user(cr3, vaddr, val);
}

/// Drain all FUTEX_WAITERS entries belonging to `pid`.
///
/// Called from `proc::exit_group` (and its synchronous-fault callers) once
/// every thread of the dying process has been marked `Dead`.  The dead
/// threads are already unschedulable, but leaving their TIDs in the wait
/// queue would:
///   1. Poison diagnostics — `kdb futex` and the `[FUTEX_WAKE_EXIT]` trace
///      would show ghost waiters that can never be woken.
///   2. Cause future `futex_wake` calls on the same `(pid, uaddr)` key
///      (possible if a future PID-reuse occurs before the key is GC'd) to
///      attempt to wake threads that no longer exist.
///
/// Per futex(2) NOTES: "If a process exits while threads of that process
/// are blocked on a futex, those threads are woken (with a wake-up
/// indicating the futex is in an inconsistent state)."  We achieve the
/// equivalent here: the threads themselves are already Dead, so we just
/// clean up the queue keyed by `(pid, _)`.
pub fn futex_drain_pid(pid: u64) {
    let mut waiters = FUTEX_WAITERS.lock();
    let dead_keys: alloc::vec::Vec<(u64, u64)> = waiters
        .keys()
        .filter(|&&(p, _)| p == pid)
        .copied()
        .collect();
    for key in dead_keys {
        waiters.remove(&key);
    }
    // Drain any lingering requeue-destination records for this pid so a
    // PID-reuse cannot inherit a stale `(pid, tid) → uaddr2` mapping.  Same
    // FUTEX_WAITERS → FUTEX_REQUEUE_DEST lock order as the requeue/WAIT paths.
    let mut dest = FUTEX_REQUEUE_DEST.lock();
    let dead_dest: alloc::vec::Vec<(u64, u64)> = dest
        .keys()
        .filter(|&&(p, _)| p == pid)
        .copied()
        .collect();
    for key in dead_dest {
        dest.remove(&key);
    }
}

/// Wake futex waiters from the exit path (CLONE_CHILD_CLEARTID).
/// This is called from proc::exit_thread when a thread with clear_child_tid exits.
pub fn futex_wake_for_exit(pid: u64, uaddr: u64, max_wake: u64) {
    #[cfg(feature = "firefox-test")]
    let key_present;
    let tids_to_wake: alloc::vec::Vec<u64> = {
        let mut waiters = FUTEX_WAITERS.lock();
        #[cfg(feature = "firefox-test")]
        {
            key_present = waiters.contains_key(&(pid, uaddr));
        }
        if let Some(list) = waiters.get_mut(&(pid, uaddr)) {
            let mut result = alloc::vec::Vec::new();
            let mut woken = 0u64;
            while !list.is_empty() && woken < max_wake {
                result.push(list.remove(0));
                woken += 1;
            }
            if list.is_empty() {
                waiters.remove(&(pid, uaddr));
            }
            result
        } else {
            alloc::vec::Vec::new()
        }
    };
    #[cfg(feature = "firefox-test")]
    {
        // Snapshot remaining keys for diagnosis if our lookup missed.
        let waiters = FUTEX_WAITERS.lock();
        let other_keys: alloc::vec::Vec<(u64, u64)> = waiters
            .keys()
            .filter(|&&(p, _)| p == pid)
            .copied()
            .collect();
        crate::serial_println!(
            "[FUTEX_WAKE_EXIT] pid={} uaddr={:#x} key_present={} woken={:?} remaining_pid_keys={:?}",
            pid, uaddr, key_present, tids_to_wake, other_keys
        );
    }
    // Wake the threads (no lock held).
    let mut threads = crate::proc::THREAD_TABLE.lock();
    for wake_tid in tids_to_wake {
        if let Some(t) = threads.iter_mut().find(|t| t.tid == wake_tid) {
            if t.state == crate::proc::ThreadState::Blocked {
                t.state = crate::proc::ThreadState::Ready;
            }
        }
    }
}

/// Write a 32-bit value to a virtual address through the given CR3's page tables.
///
/// Used for CLONE_CHILD_SETTID and — critically — for CLONE_CHILD_CLEARTID on
/// the thread-exit path (`proc::exit_thread`).  Per clone(2)
/// `CLONE_CHILD_CLEARTID` and `set_tid_address(2)`, the kernel must zero the
/// `clear_child_tid` word in the *dying thread's* address space and then
/// futex-wake any waiter — this is how a surviving thread that parked on that
/// word (e.g. via a `while (*addr == val) futex(FUTEX_WAIT, …)` loop) learns the
/// thread has gone.  If the write is dropped, the woken waiter re-reads the old
/// value and re-parks forever (POSIX futex(2) semantics: a wake without the
/// guarded value actually changing is a spurious wake the waiter ignores).
///
/// The target word is not guaranteed to be backed by a present, writable PTE at
/// exit time: the page may be lazily demand-paged (never touched in this CR3),
/// or present-but-read-only after a copy-on-write fork.  Silently skipping the
/// write in those cases is the bug this function guards against.  We therefore
/// resolve the page the same way a hardware write fault would — demand-fault an
/// anonymous page in, or break COW — before performing the store, mirroring the
/// page-fault handler's anonymous/COW install logic (Intel SDM Vol. 3A §4.10.5,
/// §8.2.3 for the ordering used around the install).
pub(crate) fn write_u32_to_user(cr3: u64, vaddr: u64, val: u32) {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    use crate::mm::vmm::{read_pte, ADDR_MASK, PAGE_PRESENT, PAGE_WRITABLE};

    let mut pte = read_pte(cr3, vaddr);

    // Slow path: the PTE is non-present (lazily demand-paged) or present but
    // not writable (copy-on-write).  Resolve it through the owning VmSpace so
    // the store below always lands on the exact frame the surviving thread
    // reads.  On any unrecoverable condition (no VMA, non-writable VMA, OOM)
    // `resolve_user_write_page` returns false and we fall through without
    // writing — the same observable outcome as the historical no-op, but only
    // for genuinely-unmapped targets rather than every lazily-paged one.
    if pte & PAGE_PRESENT == 0 || pte & PAGE_WRITABLE == 0 {
        if !resolve_user_write_page(cr3, vaddr) {
            return;
        }
        pte = read_pte(cr3, vaddr);
        // If resolution still did not leave us a present, writable PTE, abort
        // rather than write through a stale/RO translation.
        if pte & PAGE_PRESENT == 0 || pte & PAGE_WRITABLE == 0 {
            return;
        }
    }

    let phys = (pte & ADDR_MASK) + (vaddr & 0xFFF);
    // W215 axis-B probe: check if the resolved phys page is cache-resident.
    // This writer hits via PHYS_OFF direct map, bypassing user-PTE permission
    // bits — a candidate W215 corruption path.
    #[cfg(feature = "firefox-test")]
    {
        let phys_page = phys & !0xFFFu64;
        if let Some(key) = crate::mm::cache::is_phys_in_cache(phys_page) {
            use core::sync::atomic::Ordering;
            crate::mm::w215_diag::CLEARTID_OVER_CACHE.fetch_add(1, Ordering::Relaxed);
            // Per-writer first-line gate handled internally by the
            // `probe` helper; we replicate that here because we already
            // have the phys/key in hand and don't want to re-walk.
            static FIRST: core::sync::atomic::AtomicBool =
                core::sync::atomic::AtomicBool::new(false);
            if !FIRST.swap(true, Ordering::Relaxed) {
                let pid = crate::proc::current_pid_lockless();
                crate::serial_println!(
                    "[H_W/clear-tid] pid={} vaddr={:#x} phys={:#x} key=({},{:#x},{:#x})",
                    pid, vaddr, phys_page, key.0, key.1, key.2,
                );
            }
        }
    }
    // GATE-A (2026-05-30) — observability-only: if this u32 store lands in the
    // main-stack TOP window (where the argc/argv/envp/auxv block lives), record
    // the kernel-direct-map write with its writer-RIP BEFORE the store mutates
    // the slot.  CLONE_CHILD_CLEARTID writes `0`; if `clear_child_tid` ever
    // points at (or aliases) a non-zero argv pointer slot, this names the
    // out-of-band argv-zeroing writer.  No-op (≤1 cmp+branch) for the
    // overwhelming common case where `vaddr` is a libc `.bss`/`.data` word
    // outside the TOP window — the hot CLEARTID path is untouched.
    #[cfg(feature = "stack-prov")]
    crate::mm::stack_prov::record_top_window_write_cr3(
        vaddr, val as u64, cr3, crate::mm::stack_prov::SITE_CLEARTID,
    );
    unsafe {
        core::ptr::write_volatile((PHYS_OFF + phys) as *mut u32, val);
    }
    // Publish the store before any subsequent futex wake.  The dying thread's
    // CLEARTID write is the userspace unlock the surviving waiter is parked on
    // (clone(2) CLONE_CHILD_CLEARTID); the waiter re-checks `*addr == val`
    // after being woken (POSIX futex(2)), so the zero must be globally visible
    // before `futex_wake_for_exit` runs or the waiter re-parks.  A release
    // fence orders this store ahead of the wake's queue mutation (Intel SDM
    // Vol. 3A §8.2.2 — stores are not reordered with older stores, but the
    // fence also forbids the compiler from sinking the write past the wake).
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
}

/// Demand-fault (or COW-break) the user page containing `vaddr` in the address
/// space identified by `cr3`, so a subsequent direct write through the PHYS_OFF
/// direct map lands on a present, writable, process-private frame.
///
/// This is the non-interrupt-context analogue of the write-fault arms of
/// `arch::x86_64::idt::handle_page_fault`: it is invoked from the thread-exit
/// path (`write_u32_to_user` → CLONE_CHILD_CLEARTID) where no real `#PF` will
/// be taken because the write goes through the kernel direct map rather than
/// the user PTE.  It reproduces only the two arms reachable for a
/// `clear_child_tid` target — which musl/glibc guarantee is a writable libc
/// global (anonymous `.bss`/`.data`) or a COW page after fork:
///
///   * **not-present + writable anonymous VMA** → allocate a zeroed frame and
///     install it RW|User (clone(2) guarantees the word is mapped; an unwritten
///     `.bss`/lock word reads as zero, which is the correct content).
///   * **present + read-only COW** → if the frame is shared (`refcount > 1`)
///     copy it to a private frame, else flip the existing frame writable;
///     shoot down stale read-only TLB entries on sibling CPUs.
///
/// Returns `true` if the page is now present and writable, `false` for any
/// unrecoverable case (no covering VMA, a non-writable VMA, OOM) — in which
/// case the caller declines the write, preserving the historical no-op outcome
/// but only for genuinely-unresolvable targets.
///
/// Locking: takes `PROCESS_TABLE` only in short snapshot critical sections and
/// drops it before `map_page_in` / `write_pte` (which take the per-CR3 `mm_sem`
/// in read mode).  It is called from `exit_thread` with no table lock held, so
/// no lock-order inversion is introduced.  Cite Intel SDM Vol. 3A §4.10.5
/// (TLB/paging-structure caches) and §8.2.3 (memory-ordering of stores).
fn resolve_user_write_page(cr3: u64, vaddr: u64) -> bool {
    use crate::mm::vmm::{
        read_pte, map_page_in, write_pte, ADDR_MASK,
        PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER,
    };
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let page_addr = crate::mm::vma::page_align_down(vaddr);

    let pte = read_pte(cr3, page_addr);

    // ── Arm A: present-but-read-only — break copy-on-write ──────────────────
    if pte & PAGE_PRESENT != 0 {
        if pte & PAGE_WRITABLE != 0 {
            return true; // already writable; nothing to do
        }
        // Confirm the VMA actually permits writes before breaking COW; a
        // genuinely read-only mapping (e.g. a const .rodata word) must not be
        // promoted — that would be a real protection error.
        let writable_vma = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter()
                .find(|p| p.cr3 == cr3)
                .and_then(|p| p.vm_space.as_ref())
                .and_then(|vs| vs.find_vma(page_addr))
                .map(|vma| vma.prot & crate::mm::vma::PROT_WRITE != 0)
                .unwrap_or(false)
        };
        if !writable_vma {
            return false;
        }
        let old_phys = pte & ADDR_MASK;
        let flags = (pte & !ADDR_MASK) | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;
        if crate::mm::refcount::page_ref_count(old_phys) > 1 {
            // Shared frame — copy to a private one.
            let new_phys = match crate::mm::pmm::alloc_page() {
                Some(p) => p,
                None => return false,
            };
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (PHYS_OFF + old_phys) as *const u8,
                    (PHYS_OFF + new_phys) as *mut u8,
                    crate::mm::pmm::PAGE_SIZE,
                );
            }
            let _ = crate::mm::refcount::page_ref_dec(old_phys);
            crate::mm::refcount::page_ref_set(new_phys, 1);
            map_page_in(cr3, page_addr, new_phys, flags);
        } else {
            // Sole owner — just flip the writable bit in place.
            write_pte(cr3, page_addr, old_phys | flags);
        }
        crate::mm::tlb::shootdown_page(cr3, page_addr);
        return true;
    }

    // ── Arm B: not present — demand-fault an anonymous frame ────────────────
    // Look up the covering VMA and require it to be writable (a clear_child_tid
    // target is always a writable libc global per clone(2)).  We install a
    // zeroed RW|User frame; for an untouched .bss/lock word zero IS the correct
    // file/anon content, and the caller immediately overwrites it with the
    // CLEARTID value anyway.
    let install_flags = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        match procs.iter()
            .find(|p| p.cr3 == cr3)
            .and_then(|p| p.vm_space.as_ref())
            .and_then(|vs| vs.find_vma(page_addr))
        {
            Some(vma) if vma.prot & crate::mm::vma::PROT_WRITE != 0 => {
                // Build flags from the VMA but force writable+user+present; the
                // VMA's own to_page_flags already encodes NX correctly.
                vma.to_page_flags() | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER
            }
            _ => return false, // no VMA, or non-writable VMA → real error
        }
    };
    let phys = match crate::mm::pmm::alloc_page() {
        Some(p) => p,
        None => return false,
    };
    unsafe {
        core::ptr::write_bytes((PHYS_OFF + phys) as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
    }
    crate::mm::refcount::page_ref_set(phys, 1);
    map_page_in(cr3, page_addr, phys, install_flags);
    crate::mm::vmm::invlpg(page_addr);
    true
}

// ===== waitpid() Implementation =============================================

/// Wait for a child process to change state.
///
/// `pid`:
///   - `> 0`: Wait for the specific child process.
///   - `-1`:  Wait for any child process.
///
/// Returns the PID of the process that changed state, or negative errno.
pub(crate) fn sys_waitpid(pid: i64, options: u32) -> i64 {
    let parent_pid = crate::proc::current_pid_lockless();
    let wnohang = (options & 1) != 0; // WNOHANG = 1

    crate::serial_println!("[SYSCALL] waitpid({}, opts=0x{:x}) from PID {}", pid, options, parent_pid);

    // Try to reap immediately.
    if let Some((child_pid, exit_code)) = crate::proc::waitpid(parent_pid, pid) {
        crate::serial_println!(
            "[SYSCALL] waitpid: child PID {} exited with code {}",
            child_pid, exit_code
        );
        return child_pid as i64;
    }

    if wnohang {
        return 0; // No zombie yet, WNOHANG → return 0.
    }

    // Block the parent thread until a child exits.
    // We use wake_tick = u64::MAX-1 as a sentinel for "blocked in waitpid".
    // exit_thread() wakes us when a child process becomes a zombie.
    let max_attempts = 200; // Safety limit: ~200 wakeup cycles (~20 seconds at 100Hz)
    for _ in 0..max_attempts {
        {
            let tid = crate::proc::current_tid();
            let mut threads = crate::proc::THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                t.state = crate::proc::ThreadState::Blocked;
                t.wake_tick = u64::MAX - 1; // sentinel: blocked in waitpid
            }
        }
        crate::sched::schedule();

        // We were woken up — try to reap.
        if let Some((child_pid, exit_code)) = crate::proc::waitpid(parent_pid, pid) {
            crate::serial_println!(
                "[SYSCALL] waitpid: child PID {} exited with code {}",
                child_pid, exit_code
            );
            return child_pid as i64;
        }
    }

    -10 // ECHILD — no matching child found after many attempts
}

// ===== ioctl dispatcher =====================================================

/// ioctl — dispatch based on which device the fd refers to.
pub(crate) fn sys_ioctl(fd_num: usize, request: u64, arg_ptr: *mut u8) -> i64 {
    // Look up the fd's open_path and file_type FIRST.  Historically fds
    // 0..=2 were short-circuited to `tty_ioctl` on the assumption they
    // were always the kernel console, but a process that closes its
    // stdio and then opens `/dev/ptmx` (or any other char device) can
    // legitimately receive fd 0/1/2 back from the open path — POSIX
    // `open(2)` guarantees the lowest free descriptor.  Routing by
    // file_type instead of by fd number keeps the per-pair termios
    // contract intact for those callers.
    let (open_path, file_type, inode, is_console, fd_present) = {
        let pid = crate::proc::current_pid_lockless();
        let procs = crate::proc::PROCESS_TABLE.lock();
        let fd_opt = procs.iter()
            .find(|p| p.pid == pid)
            .and_then(|p| p.file_descriptors.get(fd_num))
            .and_then(|f| f.as_ref());
        match fd_opt {
            Some(f) => (f.open_path.clone(), f.file_type, f.inode, f.is_console, true),
            None    => (alloc::string::String::new(), crate::vfs::FileType::RegularFile, 0, false, false),
        }
    };

    // Console fds (is_console=true) → TTY0.  This is set by the kernel
    // init path on the initial stdio fds for processes inheriting the
    // physical console, and stays distinct from /dev/ptmx PTY masters.
    //
    // Legacy stdio fall-back: if the caller targets fd 0/1/2 but the
    // process has no fd table populated (kernel test threads, very early
    // boot, or callers that never inherited stdio), route to `TTY0`
    // anyway.  This preserves POSIX `tty(4)` semantics for TIOCGPGRP /
    // TIOCGETSID / TIOCGWINSZ on stdio in environments where the kernel
    // is the sole driver of the physical console.  A real fd with
    // `is_console=false` (e.g. an `open("/dev/ptmx")` that happens to
    // land on fd 0 after `close(0)`) still routes by file_type below.
    if is_console || (!fd_present && fd_num <= 2) {
        return crate::drivers::tty::tty_ioctl(request, arg_ptr);
    }

    // PTY ioctls.  Both ends route through per-pair handlers so a TUI
    // setting raw mode on its slave does not perturb the kernel-console
    // `TTY0` (which `drivers::tty::tty_ioctl` mutates).  See POSIX
    // `termios(3)` for the per-fd attribute model and `pty(7)` for the
    // master/slave distinction.
    match file_type {
        crate::vfs::FileType::PtyMaster => {
            return sys_pty_master_ioctl(inode as u8, request, arg_ptr);
        }
        crate::vfs::FileType::PtySlave => {
            return sys_pty_slave_ioctl(inode as u8, request, arg_ptr);
        }
        _ => {}
    }

    if open_path == "/dev/fb0" {
        sys_fbdev_ioctl(request, arg_ptr)
    } else if open_path.starts_with("/dev/input/") {
        sys_input_ioctl(request, arg_ptr)
    } else if open_path.starts_with("/dev/tty") || open_path.starts_with("/dev/pts") || open_path == "/dev/console" {
        crate::drivers::tty::tty_ioctl(request, arg_ptr)
    } else if open_path == "/dev/dsp" {
        sys_dsp_ioctl(request, arg_ptr)
    } else {
        0 // silently accept unknown ioctls
    }
}

/// Ioctls for the PTY master side (/dev/ptmx).
///
/// The master handles PTY-management ioctls (`TIOCGPTN`, `TIOCSPTLCK`,
/// `TIOCGPTLCK`) and the winsize accessors (`TIOCGWINSZ`, `TIOCSWINSZ`).
/// `TCGETS` / `TCSETS` on the master end are routed to the same per-pair
/// `Termios` the slave sees, which is the documented Linux semantics for
/// PTY pairs — `man pty(7)` and `Documentation/admin-guide/devices.txt`
/// section "PTY major/minor allocation".
pub(crate) fn sys_pty_master_ioctl(pty_n: u8, request: u64, arg_ptr: *mut u8) -> i64 {
    // TIOCGPTN (0x80045430) — get slave number
    const TIOCGPTN:   u64 = 0x8004_5430;
    // TIOCSPTLCK (0x40045431) — set slave lock (0 = unlock)
    const TIOCSPTLCK: u64 = 0x4004_5431;
    // TIOCGPTLCK (0x80045439) — get lock state
    const TIOCGPTLCK: u64 = 0x8004_5439;
    // Per-pair termios + winsize accessors shared with the slave path.
    use crate::drivers::tty::{
        TCGETS, TCSETS, TCSETSW, TCSETSF,
        TIOCGWINSZ, TIOCSWINSZ, TIOCGPGRP, TIOCSPGRP,
        TIOCSCTTY, TIOCNOTTY, TIOCGETSID,
        Winsize,
    };

    // SMAP bracket — arg_ptr is a user-VA from the syscall arg.
    // Bracketing once at the top covers all match arms.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    match request {
        TIOCGPTN => {
            if !arg_ptr.is_null() {
                unsafe { core::ptr::write(arg_ptr as *mut u32, pty_n as u32); }
            }
            0
        }
        TIOCSPTLCK => {
            if !arg_ptr.is_null() {
                let lock_val = unsafe { core::ptr::read(arg_ptr as *const i32) };
                if lock_val == 0 {
                    crate::drivers::pty::unlock_slave(pty_n);
                }
            }
            0
        }
        TIOCGPTLCK => {
            if !arg_ptr.is_null() {
                unsafe { core::ptr::write(arg_ptr as *mut i32, 0i32); } // unlocked
            }
            0
        }
        TIOCGWINSZ => {
            if !arg_ptr.is_null() {
                let ws = crate::drivers::pty::get_winsize_full(pty_n);
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut Winsize, ws); }
            }
            0
        }
        TIOCSWINSZ => {
            if !arg_ptr.is_null() {
                let ws = unsafe { core::ptr::read_unaligned(arg_ptr as *const Winsize) };
                crate::drivers::pty::set_winsize_full(pty_n, ws);
            }
            0
        }
        TCGETS => pty_tcgets(pty_n, arg_ptr),
        TCSETS  => pty_tcsets(pty_n, arg_ptr, /*flush=*/false),
        TCSETSW => pty_tcsets(pty_n, arg_ptr, /*flush=*/false),
        TCSETSF => pty_tcsets(pty_n, arg_ptr, /*flush=*/true),
        TIOCGPGRP => {
            if !arg_ptr.is_null() {
                let pgid = crate::drivers::pty::get_fg_pgid(pty_n) as i32;
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut i32, pgid); }
            }
            0
        }
        TIOCSPGRP => {
            if !arg_ptr.is_null() {
                let pgid = unsafe { core::ptr::read_unaligned(arg_ptr as *const i32) };
                crate::drivers::pty::set_fg_pgid(pty_n, pgid as u32);
            }
            0
        }
        TIOCSCTTY | TIOCNOTTY => 0,  // controlling-tty stubs
        TIOCGETSID => {
            if !arg_ptr.is_null() {
                let pid = crate::proc::current_pid() as i32;
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut i32, pid); }
            }
            0
        }
        _ => 0, // Accept all other ioctls silently
    }
}

/// Ioctls for the PTY slave side (/dev/pts/N).
///
/// Mirror image of `sys_pty_master_ioctl` minus the PTMX-specific
/// requests (`TIOCGPTN`, `TIOCSPTLCK`).  Per POSIX `termios(3)` and
/// `pty(7)`, `tcgetattr`/`tcsetattr` on a slave fd MUST operate on the
/// same `Termios` the master sees — both ends share the line-discipline
/// configuration.
pub(crate) fn sys_pty_slave_ioctl(pty_n: u8, request: u64, arg_ptr: *mut u8) -> i64 {
    use crate::drivers::tty::{
        TCGETS, TCSETS, TCSETSW, TCSETSF,
        TIOCGWINSZ, TIOCSWINSZ, TIOCGPGRP, TIOCSPGRP,
        TIOCSCTTY, TIOCNOTTY, TIOCGETSID,
        Winsize,
    };

    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    match request {
        TCGETS => pty_tcgets(pty_n, arg_ptr),
        TCSETS  => pty_tcsets(pty_n, arg_ptr, /*flush=*/false),
        TCSETSW => pty_tcsets(pty_n, arg_ptr, /*flush=*/false),
        TCSETSF => pty_tcsets(pty_n, arg_ptr, /*flush=*/true),
        TIOCGWINSZ => {
            if !arg_ptr.is_null() {
                let ws = crate::drivers::pty::get_winsize_full(pty_n);
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut Winsize, ws); }
            }
            0
        }
        TIOCSWINSZ => {
            if !arg_ptr.is_null() {
                let ws = unsafe { core::ptr::read_unaligned(arg_ptr as *const Winsize) };
                crate::drivers::pty::set_winsize_full(pty_n, ws);
            }
            0
        }
        TIOCGPGRP => {
            if !arg_ptr.is_null() {
                let pgid = crate::drivers::pty::get_fg_pgid(pty_n) as i32;
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut i32, pgid); }
            }
            0
        }
        TIOCSPGRP => {
            if !arg_ptr.is_null() {
                let pgid = unsafe { core::ptr::read_unaligned(arg_ptr as *const i32) };
                crate::drivers::pty::set_fg_pgid(pty_n, pgid as u32);
            }
            0
        }
        TIOCSCTTY | TIOCNOTTY => 0,
        TIOCGETSID => {
            if !arg_ptr.is_null() {
                let pid = crate::proc::current_pid() as i32;
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut i32, pid); }
            }
            0
        }
        _ => 0,  // Accept all other ioctls silently (e.g. TIOCMGET, FIONREAD)
    }
}

/// Shared TCGETS handler — copies the pair's `Termios` into `arg_ptr`.
/// Must be called inside an enclosing `UserGuard` bracket (the caller
/// `sys_pty_*_ioctl` brackets the whole match).
fn pty_tcgets(pty_n: u8, arg_ptr: *mut u8) -> i64 {
    use crate::drivers::tty::Termios;
    if arg_ptr.is_null() { return -14; } // EFAULT
    let t = crate::drivers::pty::get_termios(pty_n);
    unsafe { core::ptr::write_unaligned(arg_ptr as *mut Termios, t); }
    0
}

/// Shared TCSETS / TCSETSW / TCSETSF handler.  `flush=true` selects the
/// TCSETSF (TCSAFLUSH) variant which also discards both ring buffers
/// before applying the new attributes — POSIX `termios(3)`.
fn pty_tcsets(pty_n: u8, arg_ptr: *const u8, flush: bool) -> i64 {
    use crate::drivers::tty::Termios;
    if arg_ptr.is_null() { return -14; } // EFAULT
    let t = unsafe { core::ptr::read_unaligned(arg_ptr as *const Termios) };
    if flush {
        crate::drivers::pty::set_termios_flush(pty_n, t);
    } else {
        crate::drivers::pty::set_termios(pty_n, t);
    }
    0
}

// ===== fbdev ioctls =========================================================

/// FBIOGET_VSCREENINFO / FBIOPUT_VSCREENINFO / FBIOGET_FSCREENINFO
///
/// Writes Linux-compatible `fb_var_screeninfo` (160 bytes) and
/// `fb_fix_screeninfo` (80 bytes) structs into user space when queried.
pub(crate) fn sys_fbdev_ioctl(request: u64, arg_ptr: *mut u8) -> i64 {
    const FBIOGET_VSCREENINFO: u64 = 0x4600;
    const FBIOPUT_VSCREENINFO: u64 = 0x4601;
    const FBIOGET_FSCREENINFO: u64 = 0x4602;
    // FBIOPAN_DISPLAY
    const FBIOPAN_DISPLAY:     u64 = 0x4606;

    // Get current display parameters from the SVGA driver.
    let (fb_phys, width, height, pitch) =
        match crate::drivers::vmware_svga::get_framebuffer() {
            Some(v) => v,
            None    => return -6, // ENXIO
        };
    let bpp:    u32 = 32;
    let line_length: u32 = pitch * (bpp / 8); // bytes per line

    // SMAP bracket — arg_ptr is a user-VA for the syscall arg.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    match request {
        FBIOGET_VSCREENINFO => {
            // struct fb_var_screeninfo — 160 bytes
            if arg_ptr.is_null() { return -14; } // EFAULT
            unsafe {
                core::ptr::write_bytes(arg_ptr, 0, 160);
                write_u32(arg_ptr, 0,  width);          // xres
                write_u32(arg_ptr, 4,  height);         // yres
                write_u32(arg_ptr, 8,  width);          // xres_virtual
                write_u32(arg_ptr, 12, height);         // yres_virtual
                write_u32(arg_ptr, 24, bpp);            // bits_per_pixel
                // Red:   offset=16, length=8
                write_u32(arg_ptr, 32, 16); write_u32(arg_ptr, 36, 8);
                // Green: offset=8,  length=8
                write_u32(arg_ptr, 40, 8);  write_u32(arg_ptr, 44, 8);
                // Blue:  offset=0,  length=8
                write_u32(arg_ptr, 48, 0);  write_u32(arg_ptr, 52, 8);
                // Alpha: offset=24, length=8
                write_u32(arg_ptr, 56, 24); write_u32(arg_ptr, 60, 8);
            }
            0
        }
        FBIOPUT_VSCREENINFO => {
            // Parse requested width/height from the struct and try to set mode.
            if arg_ptr.is_null() { return -14; }
            let (req_w, req_h) = unsafe {
                (read_u32(arg_ptr, 0), read_u32(arg_ptr, 4))
            };
            if req_w > 0 && req_h > 0 {
                crate::drivers::vmware_svga::set_mode(req_w, req_h, bpp);
            }
            0
        }
        FBIOGET_FSCREENINFO => {
            // struct fb_fix_screeninfo — 80 bytes
            if arg_ptr.is_null() { return -14; }
            unsafe {
                core::ptr::write_bytes(arg_ptr, 0, 80);
                // id[0..16]: "AstryxFB"
                let id = b"AstryxFB";
                core::ptr::copy_nonoverlapping(id.as_ptr(), arg_ptr, id.len());
                // smem_start (phys base) at offset 16 — 8-byte pointer
                core::ptr::write_unaligned(arg_ptr.add(16) as *mut u64, fb_phys.to_le());
                // smem_len = height * line_length
                let smem_len = height * line_length;
                write_u32(arg_ptr, 24, smem_len);
                // visual = 2 (TRUECOLOR) at offset 36
                write_u32(arg_ptr, 36, 2);
                // line_length at offset 48
                write_u32(arg_ptr, 48, line_length);
            }
            0
        }
        FBIOPAN_DISPLAY => 0, // silently accept panning requests
        _ => -25, // ENOTTY for unknown fb ioctls
    }
}

/// Write a little-endian u32 at `offset` bytes from `base`.
#[inline(always)]
pub(crate) unsafe fn write_u32(base: *mut u8, offset: usize, val: u32) {
    core::ptr::write_unaligned(base.add(offset) as *mut u32, val.to_le());
}

/// Read a little-endian u32 at `offset` bytes from `base`.
#[inline(always)]
pub(crate) unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(core::ptr::read_unaligned(base.add(offset) as *const u32))
}

// ===== input device (evdev) ioctls ==========================================

pub(crate) fn sys_input_ioctl(request: u64, arg_ptr: *mut u8) -> i64 {
    // EVIOCGVERSION = _IOR('E', 0x01, int) = 0x80044501
    const EVIOCGVERSION: u64 = 0x80044501;
    // EVIOCGID = _IOR('E', 0x02, struct input_id) = 0x80084502  (16 bytes)
    const EVIOCGID:      u64 = 0x80084502;
    // EVIOCGNAME(n) — ioctl cmd varies with size; match the top byte
    // Typically 0x80nn4506 where nn = buffer len
    // We just check bits 0-23 (type + nr, ignore size).
    let req_lo = request & 0x0000_FFFF; // direction+type+nr stripped of size

    // SMAP bracket — arg_ptr is a user-VA.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    match request {
        EVIOCGVERSION => {
            if !arg_ptr.is_null() {
                // EV_VERSION = 0x010001
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut u32, 0x0001_0001u32.to_le()); }
            }
            0
        }
        EVIOCGID => {
            // struct input_id { u16 bustype, vendor, product, version }
            if !arg_ptr.is_null() {
                unsafe {
                    core::ptr::write_bytes(arg_ptr, 0, 8);
                    // bustype = BUS_VIRTUAL (6)
                    core::ptr::write_unaligned(arg_ptr as *mut u16, 6u16.to_le());
                }
            }
            0
        }
        _ if req_lo == 0x4506 => {
            // EVIOCGNAME — return empty string
            if !arg_ptr.is_null() {
                unsafe { *arg_ptr = 0; }
            }
            1 // number of bytes written
        }
        _ => 0, // silently accept all other evdev ioctls
    }
}

// ===== /dev/dsp (OSS audio) ioctls =========================================

/// OSS SNDCTL_DSP_* ioctls for the AC97 audio device (/dev/dsp).
///
/// Supported commands (minimal OSS subset):
///   SNDCTL_DSP_SPEED   (0xC0045002) — set sample rate (44100 and 48000 only)
///   SNDCTL_DSP_SETFMT  (0xC0045005) — set sample format (AFMT_S16_LE only)
///   SNDCTL_DSP_CHANNELS(0xC0045006) — set channel count (stereo = 2 only)
///
/// Any other ioctl is accepted silently (returns 0) so programs that probe
/// optional capabilities don't abort.
pub(crate) fn sys_dsp_ioctl(request: u64, arg_ptr: *mut u8) -> i64 {
    // OSS ioctl numbers — _IOWR('P', N, int)
    // SNDCTL_DSP_SPEED    = 0xC004_5002
    // SNDCTL_DSP_SETFMT   = 0xC004_5005
    // SNDCTL_DSP_CHANNELS = 0xC004_5006
    const SNDCTL_DSP_SPEED:    u64 = 0xC004_5002;
    const SNDCTL_DSP_SETFMT:   u64 = 0xC004_5005;
    const SNDCTL_DSP_CHANNELS: u64 = 0xC004_5006;
    // AFMT_S16_LE format tag
    const AFMT_S16_LE: i32 = 0x0000_0010;

    // SMAP bracket — arg_ptr is a user-VA.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    match request {
        SNDCTL_DSP_SPEED => {
            // arg_ptr points to an int (sample rate); on success the driver
            // writes back the actual rate it will use.  We accept 44100 and
            // 48000; the AC97 hardware is always configured for 48000.
            if arg_ptr.is_null() { return -22; } // EINVAL
            let rate = unsafe { core::ptr::read_unaligned(arg_ptr as *const i32) };
            match rate {
                44100 | 48000 => {
                    // Write back 48000 — that is what the hardware runs at.
                    unsafe { core::ptr::write_unaligned(arg_ptr as *mut i32, 48000i32); }
                    0
                }
                _ => -22, // EINVAL — unsupported rate
            }
        }
        SNDCTL_DSP_SETFMT => {
            // arg_ptr points to an int (format); write back accepted format or EINVAL.
            if arg_ptr.is_null() { return -22; }
            let fmt = unsafe { core::ptr::read_unaligned(arg_ptr as *const i32) };
            if fmt == AFMT_S16_LE {
                // Accepted — write back the same value.
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut i32, AFMT_S16_LE); }
                0
            } else {
                -22 // EINVAL — only 16-bit LE PCM supported
            }
        }
        SNDCTL_DSP_CHANNELS => {
            // arg_ptr points to an int (channel count); stereo (2) only.
            if arg_ptr.is_null() { return -22; }
            let channels = unsafe { core::ptr::read_unaligned(arg_ptr as *const i32) };
            if channels == 2 {
                unsafe { core::ptr::write_unaligned(arg_ptr as *mut i32, 2i32); }
                0
            } else {
                -22 // EINVAL — only stereo supported
            }
        }
        _ => 0, // Accept unknown DSP ioctls silently (e.g. capability probes)
    }
}

// ===== mmap / munmap / brk ==================================================

/// mmap — Map virtual memory into the current process's address space.
///
/// Supports both anonymous (MAP_ANONYMOUS) and file-backed mappings.
/// Actual physical pages are allocated on demand via the page-fault handler.
pub(crate) fn sys_mmap(addr_hint: u64, length: u64, prot: u32, flags: u32, fd: u64, offset: u64) -> i64 {
    use crate::mm::vma::*;

    if length == 0 {
        return -22; // EINVAL
    }

    let length = page_align_up(length);
    let pid = crate::proc::current_pid_lockless();

    // MAP_FIXED_NOREPLACE (Linux 4.17+, flag 0x100000): like MAP_FIXED but the
    // kernel should return EEXIST if the range is already mapped.  Modern glibc
    // (2.31+) and ld-linux use this flag when loading library segments so that
    // they can detect address-space conflicts.  Without recognising it we fell
    // through to find_free_range() and silently placed the library at a
    // completely different address — corrupting all relocation offsets and
    // producing non-canonical pointers that caused a GPF later.
    //
    // For our purposes: honour the requested address just like MAP_FIXED.
    // For NOREPLACE semantics: if the range overlaps an existing VMA, return
    // EEXIST.  ld-linux never pre-reserves with PROT_NONE when using
    // MAP_FIXED_NOREPLACE, so this check is safe.
    const MAP_FIXED_NOREPLACE: u32 = 0x0010_0000;
    let is_fixed = flags & (MAP_FIXED as u32 | MAP_FIXED_NOREPLACE) != 0;
    let is_noreplace = flags & MAP_FIXED_NOREPLACE != 0;
    // MAP_STACK | MAP_ANONYMOUS non-FIXED: route through the dedicated
    // stack-ASLR window with per-call fresh entropy (see
    // `mm::vma::STACK_ASLR_MIN` / `find_free_stack_range`).
    let is_stack_alloc = !is_fixed
        && (flags & MAP_STACK as u32 != 0)
        && (flags & MAP_ANONYMOUS as u32 != 0);

    // ── Phase 1 — choose base address, resolve fd, build the VMA. ────────────
    //
    // Lock is held only while we read the per-process state we need.  We
    // capture cr3 plus the resolved VmBacking and decided base address, then
    // drop the lock so the bulk page-table edit (Phase 2) and the heavy
    // unmap-and-free loop don't block other CPUs' page faults / kdb queries.
    //
    // For MAP_FIXED-without-NOREPLACE the unmap loop is the long-running
    // step (one VMM_LOCK + PMM_LOCK round-trip per page); previously it ran
    // with PROCESS_TABLE held, which froze the rest of the kernel for the
    // duration of every library-segment overlay during ld-linux's load.
    //
    // (backing, name, base, cr3) is computed atomically under the lock so
    // address-space invariants are preserved at decision time.
    let mmap_setup = {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3, // ESRCH
        };

        // Ensure process has a VmSpace.
        // For vfork children (vm_space=None, shared parent CR3): create a VmSpace
        // that uses the process's actual CR3 (shared with parent) so mmap pages
        // go into the correct page table.
        //
        // We share the parent's mm_sem Arc rather than allocating a fresh one,
        // so that when the child's VmSpace is later dropped its Drop impl does
        // NOT evict the registry entry (strong_count will be > 1 while the
        // parent's VmSpace is still alive).  Using the registry helper avoids a
        // second linear scan of PROCESS_TABLE: mm_sem_for_cr3 returns the Arc
        // already registered under this cr3, which belongs to the parent.
        if proc.vm_space.is_none() {
            let proc_cr3 = proc.cr3;
            if proc_cr3 != 0 {
                // Borrow the parent's mm_sem via the registry (no second table
                // scan needed; the parent's VmSpace construction already
                // registered it).
                let parent_sem = crate::mm::vma::mm_sem_for_cr3(proc_cr3)
                    .unwrap_or_else(|| {
                        // No parent entry — fall back to a fresh lock and
                        // register it so subsequent lookups succeed.
                        let fresh = alloc::sync::Arc::new(spin::RwLock::new(()));
                        crate::mm::vma::register_mm_sem(proc_cr3, fresh.clone());
                        fresh
                    });
                proc.vm_space = Some(VmSpace::from_existing_cr3(proc_cr3, parent_sem));
            } else {
                proc.vm_space = Some(VmSpace::new_kernel());
            }
        }
        let space = proc.vm_space.as_mut().unwrap();

        // Choose base address.
        //
        // For non-FIXED `MAP_STACK | MAP_ANONYMOUS` allocations route through
        // `find_free_stack_range`, which places the VMA inside the dedicated
        // stack-ASLR window with per-call fresh entropy rather than the
        // deterministic-after-libxul `find_free_range` downward walk.  See
        // `mm::vma::STACK_ASLR_MIN` for the layout rationale.  POSIX mmap(2)
        // gives the kernel full latitude over the chosen VA when
        // `addr == NULL` and `MAP_FIXED` is unset, so this routing is
        // ABI-conformant.
        let chosen_base = if is_fixed {
            let b = page_align_down(addr_hint);
            if b == 0 {
                return -22; // EINVAL
            }
            if is_noreplace {
                let conflict = space.areas.iter().any(|vma| vma.overlaps(b, length));
                if conflict {
                    return -17; // EEXIST
                }
            }
            b
        } else if is_stack_alloc {
            match space.find_free_stack_range(length) {
                Some(b) => b,
                None => return -12, // ENOMEM
            }
        } else {
            match space.find_free_range(length) {
                Some(b) => b,
                None => return -12, // ENOMEM
            }
        };

        // Resolve backing type while we still hold the lock (fd lookup needs
        // proc.file_descriptors).
        let is_anon = flags & MAP_ANONYMOUS as u32 != 0
            || fd == u64::MAX
            || fd as i64 == -1;

        // Capture the resolved fd path (for shared-library files only) so we
        // can emit a `[FFTEST/mmap-so]` trace AFTER dropping the lock.  Letting
        // the print happen under PROCESS_TABLE could block other CPUs on a
        // slow serial port.  The capture is gated to match the emit cfg
        // below — `test-mode` or `firefox-test` — so we don't pay the
        // String allocation in throughput-only builds.
        #[cfg(any(feature = "firefox-test", feature = "test-mode"))]
        let so_trace_path: Option<alloc::string::String> = {
            let fd_num = fd as usize;
            proc.file_descriptors
                .get(fd_num)
                .and_then(|f| f.as_ref())
                .and_then(|e| {
                    let p = &e.open_path;
                    if p.ends_with(".so") || p.contains(".so.") {
                        Some(alloc::string::String::from(p.as_str()))
                    } else { None }
                })
        };

        let (vma_backing, vma_name) = if is_anon {
            (VmBacking::Anonymous, "[mmap]")
        } else {
            let fd_num = fd as usize;
            match proc.file_descriptors.get(fd_num).and_then(|f| f.as_ref()) {
                Some(fd_entry) if fd_entry.open_path == "/dev/fb0" => {
                    if let Some((phys_base, _w, _h, _pitch)) =
                        crate::drivers::vmware_svga::get_framebuffer()
                    {
                        (VmBacking::Device { phys_base }, "[fb0]")
                    } else {
                        return -6; // ENXIO
                    }
                }
                Some(fd_entry) if fd_entry.open_path.starts_with("/dev/dri/") => {
                    (VmBacking::Anonymous, "[dri-stub]")
                }
                Some(fd_entry) if !fd_entry.is_console => {
                    let page_offset = offset & !0xFFF;
                    // For MAP_FIXED / MAP_FIXED_NOREPLACE file mappings the
                    // caller (typically the dynamic linker) places the segment
                    // at the ELF link-time virtual address, so we can recover
                    // the segment's p_vaddr from the chosen base.  The delta
                    // `(p_vaddr & !0xfff) - (p_offset & !0xfff)` is a constant
                    // across the whole segment and is used by the #UD / #GP
                    // diagnostic paths to convert `offset_in_file` → the ELF
                    // virtual address that addr2line expects.
                    //
                    // For auto-placed (non-fixed) mappings there is no ELF
                    // relationship — set delta to 0.
                    //
                    // Ref: ELF-64 Object File Format §3 (Program Loading).
                    let elf_load_delta = if is_fixed {
                        chosen_base.wrapping_sub(page_offset)
                    } else {
                        0
                    };
                    (VmBacking::File {
                        mount_idx: fd_entry.mount_idx,
                        inode: fd_entry.inode,
                        offset: page_offset,
                        elf_load_delta,
                    }, "[mmap-file]")
                }
                _ => return -9, // EBADF
            }
        };

        #[cfg(any(feature = "firefox-test", feature = "test-mode"))]
        {
            (space.cr3, vma_backing, vma_name, chosen_base, so_trace_path)
        }
        #[cfg(not(any(feature = "firefox-test", feature = "test-mode")))]
        {
            (space.cr3, vma_backing, vma_name, chosen_base)
        }
    };
    #[cfg(any(feature = "firefox-test", feature = "test-mode"))]
    let (cr3, backing, name, base, so_trace_path_out) = mmap_setup;
    #[cfg(not(any(feature = "firefox-test", feature = "test-mode")))]
    let (cr3, backing, name, base) = mmap_setup;

    // W215 H3a diagnostic: count MAP_SHARED+PROT_WRITE file-backed mappings.
    //
    // The check is after argument decode and backing resolution (above), but
    // before any phase-2/3 VMA edit, so the metadata is stable.  Per POSIX
    // mmap(2), MAP_SHARED+PROT_WRITE on a regular file installs a user PTE
    // that aliases the page-cache frame directly with PAGE_WRITABLE set — any
    // store through the mapping writes into the cache frame itself.  If the
    // file is a shared library (.so), subsequent MAP_PRIVATE+PROT_WRITE
    // demand-page faults copy the already-written (e.g. relocated) content
    // into their private frame, producing wrong code bytes at the original
    // file offset (the W215 H3a hypothesis).
    #[cfg(feature = "firefox-test")]
    if (flags & MAP_SHARED as u32 != 0) && (prot & PROT_WRITE != 0) {
        if let VmBacking::File { mount_idx: m, inode: ino, .. } = &backing {
            SYS_MMAP_SHARED_WRITE_FILEBACKED
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            crate::serial_println!(
                "[H3a/mmap] SHARED+WRITE filebacked mount={} inode={:#x} fd={} len={:#x} off={:#x} pid={}",
                m, ino, fd, length, offset, pid,
            );
        }
    }

    // Emit shared-library mmap trace AFTER the PROCESS_TABLE lock is dropped
    // so a slow serial path cannot block the process table.  Format:
    //   [FFTEST/mmap-so] pid=<n> base=<vaddr> len=<bytes> off=<file-off>
    //                    prot=<prot> fd=<fd> path=<path>
    // The first executable LOAD segment for a given .so is the load base;
    // later segments are placed by ld-linux at base+seg_vaddr via MAP_FIXED.
    //
    // The host symboliser in `qemu-harness.py` consumes these lines to
    // resolve user RIPs to `<library>+offset`.  Emit on any of:
    //   - `firefox-test` (W101 plateau investigation requires symbolised
    //     RIP samples; the cost is one log line per mmap, ~80 lines total
    //     across a Firefox boot)
    //   - `test-mode` (headless dynamic-linker tests verify placement)
    // The previous `firefox-trace-verbose` gate was an oversight — without
    // mmap-so traces the harness symbolicator cannot resolve user RIPs to
    // `<lib>+offset`, which made `rip-trace`'s output uninterpretable for
    // PIE binaries.
    #[cfg(any(feature = "firefox-test", feature = "test-mode"))]
    if let Some(path) = so_trace_path_out {
        crate::serial_println!(
            "[FFTEST/mmap-so] pid={} base={:#x} len={:#x} off={:#x} prot={:#x} fd={} path={}",
            pid, base, length, offset, prot, fd, path
        );
    }

    // ── MAP_FIXED replacement: split into three phases ──────────────────────
    //
    // POSIX mmap(2) requires MAP_FIXED to silently replace any existing
    // mappings that overlap [base, base+length).  We perform the
    // replacement under separate lock acquisitions so the writer never
    // blocks faults on a heavy bulk page-table edit (libxul's execve
    // teardown unmaps hundreds of MiB):
    //
    //   Phase 2a (lock):       remove the overlapping VMA records.
    //   Phase 2b (lock-free):  unmap_and_free_range_in clears the PTEs
    //                          and decrements/frees the backing frames.
    //   Phase 3  (lock):       insert the new VMA record.
    //
    // The race window admitted by an earlier ordering (Phase 2b first,
    // Phase 2a second — i.e. PT cleared while a stale VMA still describes
    // the range) is closed by performing the VMA removal FIRST.  A fault
    // arriving after Phase 2a runs find_vma under PROCESS_TABLE and finds
    // no covering VMA, returning false → SIGSEGV — the expected outcome
    // for a concurrent access into a region the user has just asked the
    // kernel to replace.  A fault arriving before Phase 2a sees the old
    // VMA, demand-pages into the range, and the PTE it installs is cleared
    // by Phase 2b a moment later — also expected MAP_FIXED-replacement
    // behaviour.  See arch::x86_64::idt::handle_page_fault for the lookup.
    //
    // ── File-backed safety: the page cache holds its own refcount ──
    //
    // For file-backed mappings the "before-Phase-2a" sub-case deserves an
    // explicit safety argument because Phase 2b runs lock-free.  Sequence:
    //
    //   T0  CPU1 #PF on `addr` ∈ [base, base+length).  find_vma returns
    //       the OLD file-backed VMA.
    //   T1  CPU1 demand-pages: cache::lookup hits, returns frame F.
    //       page_ref_inc(F) → rc=2 (cache's ref + new PTE's ref).
    //       (If the cache miss path: pmm::alloc_page → cache::insert,
    //        which does its own page_ref_inc(F) → rc=1 for the cache;
    //        the demand-page code then does a second page_ref_inc(F) →
    //        rc=2 before installing the PTE.  See idt.rs::handle_page_fault.)
    //   T2  CPU0 Phase 2a: remove_range under PROCESS_TABLE.
    //   T3  CPU0 Phase 2b: unmap_and_free_range_in walks PTEs lock-free,
    //       finds F installed by CPU1, page_ref_dec(F) → rc=1.
    //       rc != 0 ⇒ pmm::free_page(F) is NOT called; F stays alive.
    //   T4  Cache still owns its reference to F; subsequent lookups still
    //       hit; Phase 3 installs the new VMA describing the same range.
    //
    // The invariant — "every PTE pointing at a cached frame F holds its
    // own ref on F, distinct from the cache's ref" — is enforced by
    // every map_page_in call site in handle_page_fault: each is paired
    // with a page_ref_inc (or, for MAP_PRIVATE-writable, an alloc_page
    // + page_ref_set(_, 1) for a private copy whose lifetime is tied
    // to that PTE alone).  See kernel/src/mm/cache.rs and
    // kernel/src/mm/refcount.rs.
    //
    // Non-MAP_FIXED skips Phases 2a/2b entirely — there is nothing to
    // clear.
    if is_fixed && !is_noreplace {
        // Phase 2a — remove the overlapping VMA records under PROCESS_TABLE.
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(space) = proc.vm_space.as_mut() {
                let _ = space.remove_range(base, length);
            }
        }
        drop(procs);

        // Phase 2b — clear the PTEs and release the backing frames without
        // holding PROCESS_TABLE.  unmap_and_free_range_in serialises on
        // VMM_LOCK + PMM_LOCK internally; concurrent kdb proc-list /
        // proc <pid> queries can still progress (they use try_lock_brief
        // — see kdb.rs).
        crate::mm::vmm::unmap_and_free_range_in(cr3, base, length);
    }

    let vma = VmArea {
        base,
        length,
        prot,
        flags,
        backing,
        name,
    };

    // `[MMAP]` is verbose: every dlopen / runtime malloc / JIT page emits a
    // line, which under the demo workload runs into the thousands.  Gate it
    // behind `firefox-trace-verbose`; the `[SC]` / `[SC-RET]` pair under
    // `syscall-trace` already records the mmap return value and length.
    #[cfg(all(feature = "firefox-test", feature = "firefox-trace-verbose"))]
    {
        let r = if prot & PROT_READ  != 0 { 'r' } else { '-' };
        let w = if prot & PROT_WRITE != 0 { 'w' } else { '-' };
        let x = if prot & PROT_EXEC  != 0 { 'x' } else { '-' };
        crate::serial_println!("[MMAP] pid={} base={:#x} len={:#x} prot={}{}{} fd={} off={:#x} {}",
            pid, base, length, r, w, x, fd as i64, offset, name);
    }

    // Phase 3 — install the new VMA under PROCESS_TABLE.
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3, // ESRCH (process exited between phases)
    };
    let space = match proc.vm_space.as_mut() {
        Some(s) => s,
        None => return -3,
    };

    match space.insert_vma(vma) {
        Ok(()) => {
            // Lower `mmap_hint` only when this allocation participates in the
            // NULL-hint downward-walk regime — i.e. neither MAP_FIXED nor a
            // MAP_STACK kernel-chosen allocation.  See
            // `VmSpace::note_mmap_placement` for the full rationale; the
            // critical case is MAP_FIXED at a PIE-biased shared-library load
            // base, which would otherwise destroy the per-process entropy
            // seeded by `randomised_mmap_hint()` before any NULL-hint
            // allocation is ever issued (POSIX mmap(2), CWE-330).
            let hint_before = space.mmap_hint;
            space.note_mmap_placement(base, is_fixed, is_stack_alloc);
            let hint_after = space.mmap_hint;
            #[cfg(all(feature = "firefox-test", feature = "firefox-trace-verbose"))]
            crate::serial_println!(
                "[MMAP-HINT] pid={} base={:#x} hint_before={:#x} hint_after={:#x} is_fixed={} is_stack_alloc={}",
                pid, base, hint_before, hint_after, is_fixed as u8, is_stack_alloc as u8
            );
            let _ = (hint_before, hint_after);
            base as i64
        }
        Err(_) => {
            crate::serial_println!(
                "[MMAP-ERR] pid={} insert_vma failed: base={:#x} len={:#x} flags={:#x} fd={}",
                pid, base, length, flags, fd as i64
            );
            -12 // ENOMEM
        }
    }
}

/// munmap — Unmap a region of the current process's address space.
///
/// For each mapped page the reference count is decremented.  When it
/// reaches zero the physical frame is returned to the PMM.
pub(crate) fn sys_munmap(addr: u64, length: u64) -> i64 {
    use crate::mm::vma::page_align_up;

    if length == 0 || addr & 0xFFF != 0 {
        return -22; // EINVAL
    }

    let length = page_align_up(length);
    let pid = crate::proc::current_pid_lockless();

    // ── Phase 1 (lock) — capture cr3 AND remove the VMA records first. ────
    //
    // The remove_range call MUST happen before the lock-free PTE clear so
    // that a concurrent page fault on another CPU cannot find a stale VMA
    // covering the range and demand-page a fresh frame into it.  The
    // page-fault handler's `find_vma` lookup runs under PROCESS_TABLE
    // (see arch::x86_64::idt::handle_page_fault), so once Phase 1 commits
    // a fault on the unmapped range will return None → SIGSEGV (the
    // expected outcome for an unmapped address).
    //
    // Phase 2 (the bulk PTE clear + frame free) runs WITHOUT the lock so
    // unmapping a large region (e.g. ld-linux's libxul placeholder during
    // execve teardown) doesn't stall every other CPU's page-fault handler
    // or freeze kdb introspection.
    let cr3 = {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let space = match proc.vm_space.as_mut() {
            Some(s) => s,
            None => return 0, // No address space — nothing to unmap.
        };
        let cr3 = space.cr3;
        let _ = space.remove_range(addr, length);
        cr3
    }; // PROCESS_TABLE released here

    // ── Phase 2 (lock-free) — clear PTEs and release backing frames. ──────
    crate::mm::vmm::unmap_and_free_range_in(cr3, addr, length);

    0
}

/// brk — Adjust the program break (heap end).
///
/// If `new_brk` is 0, returns the current break.
/// Otherwise sets the break and returns the new value.
pub(crate) fn sys_brk(new_brk: u64) -> i64 {
    let pid = crate::proc::current_pid_lockless();

    // ── kstack-depth probe at brk entry ──────────────────────────────
    // The STACK_CANARY_CORRUPT investigation (post-task #229) needs to
    // know how deep the kernel stack is when `sys_brk` runs, so the
    // brk path can be correlated with later canary-fail events.  We
    // capture the live RSP and emit a single structured line under
    // `syscall-trace`.  The probe is `#[inline(never)]` indirectly via
    // the function boundary so the captured RSP includes this frame.
    #[cfg(feature = "syscall-trace")]
    {
        let tid = crate::proc::current_tid();
        let rsp_live = crate::proc::current_kernel_rsp_live();
        let (kstack_base, kstack_size) = {
            let threads = crate::proc::THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == tid)
                .map(|t| (t.kernel_stack_base, t.kernel_stack_size))
                .unwrap_or((0, 0))
        };
        let kstack_top = kstack_base.wrapping_add(kstack_size);
        let depth_used = if kstack_base > 0 {
            kstack_top.wrapping_sub(rsp_live)
        } else { 0 };
        let was_emergency = crate::proc::was_emergency_kstack(kstack_base);
        crate::serial_println!(
            "[BRK/ENTRY] tid={} pid={} new_brk={:#x} rsp={:#x} base={:#x} size={:#x} top={:#x} depth={:#x} was_emergency_4k={}",
            tid, pid, new_brk, rsp_live, kstack_base, kstack_size, kstack_top, depth_used, was_emergency,
        );
    }

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    if proc.vm_space.is_none() {
        proc.vm_space = Some(crate::mm::vma::VmSpace::new_kernel());
    }
    let space = proc.vm_space.as_mut().unwrap();

    if new_brk == 0 {
        return space.brk as i64;
    }

    space.adjust_brk(new_brk) as i64
}

// ===== Identity / credential syscalls =======================================

pub(crate) fn sys_getppid() -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.parent_pid as i64,
        None => -3,
    }
}

pub(crate) fn sys_getuid() -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.uid as i64,
        None => -3,
    }
}

pub(crate) fn sys_getgid() -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.gid as i64,
        None => -3,
    }
}

pub(crate) fn sys_geteuid() -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.euid as i64,
        None => -3,
    }
}

pub(crate) fn sys_getegid() -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.egid as i64,
        None => -3,
    }
}

pub(crate) fn sys_umask(new_mask: u32) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => {
            let old = p.umask;
            p.umask = new_mask & 0o777;
            old as i64
        }
        None => -3,
    }
}

// ===== VFS syscalls =========================================================

pub(crate) fn sys_getcwd(buf: *mut u8, size: usize) -> i64 {
    if buf.is_null() || size == 0 {
        return -22; // EINVAL
    }

    // Pointer validation is done at the user/kernel boundary (Linux
    // dispatch_body arm 79; Aether dispatch).  Kernel-internal callers
    // bypass — see sys_open_linux for the rationale.

    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let cwd = proc.cwd.as_bytes();
    if cwd.len() >= size {
        return -34; // ERANGE
    }

    // SMAP-bracketed write to the user buffer.  The pointer was checked
    // for null above; full range validation happens at the dispatch arm.
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::ptr::copy_nonoverlapping(cwd.as_ptr(), buf, cwd.len());
        *buf.add(cwd.len()) = 0; // null-terminate
    }

    cwd.len() as i64
}

pub(crate) fn sys_chdir(path_ptr: *const u8, path_len: usize) -> i64 {
    // Owned copy under SMAP bracket — same pattern as sys_exec, so the
    // downstream stat/PROCESS_TABLE work runs against a kernel String.
    let path_owned = {
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        let slice = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
        match core::str::from_utf8(slice) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => return -22,
        }
    };
    let path = path_owned.as_str();

    // Verify the path exists and is a directory
    match crate::vfs::stat(path) {
        Ok(st) => {
            if st.file_type != crate::vfs::FileType::Directory {
                return -20; // ENOTDIR
            }
        }
        Err(e) => return crate::subsys::linux::errno::vfs_err(e),
    }

    let pid = crate::proc::current_pid_lockless();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => {
            p.cwd = alloc::string::String::from(path);
            0
        }
        None => -3,
    }
}

pub(crate) fn sys_mkdir(path_ptr: *const u8, path_len: usize) -> i64 {
    // SMAP-bracketed copy — see sys_chdir for rationale.
    let path_owned = {
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        let slice = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
        match core::str::from_utf8(slice) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => return -22,
        }
    };
    match crate::vfs::mkdir(path_owned.as_str()) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

pub(crate) fn sys_rmdir(path_ptr: *const u8, path_len: usize) -> i64 {
    let path_owned = {
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        let slice = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
        match core::str::from_utf8(slice) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => return -22,
        }
    };
    match crate::vfs::remove(path_owned.as_str()) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// Kernel stat buffer layout (64 bytes, matches what userspace expects):
/// Offsets (all little-endian):
///   0: u64  inode
///   8: u32  file_type (0=regular, 1=dir, 2=symlink, 3=chardev, 4=blkdev, 5=pipe)
///  12: u32  permissions
///  16: u64  size
///  24: u64  (reserved)
///  32: u64  (reserved)
///  40..64: padding
const STAT_BUF_SIZE: usize = 64;

pub(crate) fn fill_stat_buf(st: &crate::vfs::FileStat, buf: *mut u8) {
    // SMAP bracket — the writes through `out` all hit user memory when
    // `buf` is a user-VA (the common case from sys_stat / sys_fstat /
    // sys_lstat).  Kernel-internal callers (test_runner) pass kernel
    // buffers, for which SMAP is silent.  Bracketing here covers all
    // sites that pass the buffer through fill_stat_buf.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let out = unsafe { core::slice::from_raw_parts_mut(buf, STAT_BUF_SIZE) };
    // Zero everything first
    for b in out.iter_mut() {
        *b = 0;
    }
    let ino = st.inode.to_le_bytes();
    out[0..8].copy_from_slice(&ino);

    let ft: u32 = match st.file_type {
        crate::vfs::FileType::RegularFile => 0,
        crate::vfs::FileType::Directory => 1,
        crate::vfs::FileType::SymLink => 2,
        crate::vfs::FileType::CharDevice => 3,
        crate::vfs::FileType::BlockDevice => 4,
        crate::vfs::FileType::Pipe => 5,
        crate::vfs::FileType::EventFd => 5,    // report as FIFO
        crate::vfs::FileType::TimerFd | crate::vfs::FileType::SignalFd |
        crate::vfs::FileType::InotifyFd => 5,  // report as FIFO
        crate::vfs::FileType::PtyMaster | crate::vfs::FileType::PtySlave => 2, // DT_CHR
        crate::vfs::FileType::Socket  => 12,   // DT_SOCK substitute
    };
    out[8..12].copy_from_slice(&ft.to_le_bytes());
    out[12..16].copy_from_slice(&st.permissions.to_le_bytes());
    out[16..24].copy_from_slice(&st.size.to_le_bytes());
}

pub(crate) fn sys_stat(path_ptr: *const u8, path_len: usize, stat_buf: *mut u8) -> i64 {
    let path_owned = {
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        let slice = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
        match core::str::from_utf8(slice) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => return -22,
        }
    };
    match crate::vfs::stat(path_owned.as_str()) {
        Ok(st) => {
            fill_stat_buf(&st, stat_buf);
            0
        }
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

pub(crate) fn sys_fstat(fd_num: usize, stat_buf: *mut u8) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let fd = match proc.file_descriptors.get(fd_num).and_then(|f| f.as_ref()) {
        Some(fd) => fd,
        None => return -9, // EBADF
    };

    if fd.is_console {
        // Synthesize a stat for console fds
        let st = crate::vfs::FileStat {
            inode: 0,
            file_type: crate::vfs::FileType::CharDevice,
            size: 0,
            permissions: 0o666,
            created: 0,
            modified: 0,
            accessed: 0,
        };
        fill_stat_buf(&st, stat_buf);
        return 0;
    }

    let mount_idx = fd.mount_idx;
    let inode = fd.inode;
    drop(procs);

    // Snapshot the Arc<FS> under MOUNTS and drop the lock before dispatching
    // stat().  Block-backed FS stat() reaches virtio I/O which calls
    // schedule(); holding the non-yielding MOUNTS spinlock across that point
    // produces a cross-thread spinlock deadlock on SMP (confirmed GDB autopsy
    // — see PR #476).  Per POSIX fstat(2): the implementation must not hold a
    // non-reentrant kernel lock across a potentially blocking I/O operation.
    match crate::vfs::fs_at(mount_idx) {
        Some((fs, _)) => match fs.stat(inode) {
            Ok(st) => {
                fill_stat_buf(&st, stat_buf);
                0
            }
            Err(e) => crate::subsys::linux::errno::vfs_err(e),
        },
        None => -9,
    }
}

pub(crate) fn sys_lseek(fd_num: usize, offset: i64, whence: u32) -> i64 {
    const SEEK_SET: u32 = 0;
    const SEEK_CUR: u32 = 1;
    const SEEK_END: u32 = 2;

    let pid = crate::proc::current_pid_lockless();

    // ── SEEK_SET / SEEK_CUR: no FS I/O needed ─────────────────────────────
    // Handle these entirely under PROCESS_TABLE and return early.  All
    // borrows from `procs` end when the enclosing block closes, which lets us
    // take the lock again below for SEEK_END without confusing the borrow
    // checker.
    if whence == SEEK_SET || whence == SEEK_CUR {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let fd = match proc.file_descriptors.get_mut(fd_num).and_then(|f| f.as_mut()) {
            Some(fd) => fd,
            None => return -9,
        };
        if fd.is_console {
            return -29; // ESPIPE
        }
        if whence == SEEK_SET {
            if offset < 0 {
                return -22; // EINVAL
            }
            fd.offset = offset as u64;
            return offset;
        } else {
            // SEEK_CUR
            let new_off = fd.offset as i64 + offset;
            if new_off < 0 {
                return -22;
            }
            fd.offset = new_off as u64;
            return new_off;
        }
    }

    if whence != SEEK_END {
        return -22; // EINVAL — unknown whence
    }

    // ── SEEK_END: must query file size via FS stat() ──────────────────────
    // Block-backed filesystems (ext2, fat32, ntfs) reach virtio block I/O
    // which calls schedule(); holding the non-yielding PROCESS_TABLE or
    // MOUNTS spinlock across that yields a cross-thread SMP deadlock
    // (GDB-confirmed: PR #476).
    //
    // Per POSIX lseek(2) §DESCRIPTION: the new offset for SEEK_END is
    // the file size plus the signed adjustment `offset`.
    //
    // Protocol:
    //   Step A — acquire PROCESS_TABLE; validate fd; snapshot mount_idx +
    //             inode (Copy types — no borrows escape the block); drop.
    //   Step B — call fs_at() + stat() with NO spinlocks held.
    //   Step C — reacquire PROCESS_TABLE; re-validate fd identity (the fd
    //             may have been closed or recycled while we were in stat());
    //             store the new offset.

    // Step A: snapshot under PROCESS_TABLE (all borrows end at block close).
    let (mount_idx, inode) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -9,
        };
        let fd = match proc.file_descriptors.get(fd_num).and_then(|f| f.as_ref()) {
            Some(fd) => fd,
            None => return -9, // EBADF
        };
        if fd.is_console {
            return -29; // ESPIPE
        }
        (fd.mount_idx, fd.inode)
    }; // PROCESS_TABLE released here

    // Step B: stat() with no kernel spinlocks held.
    // fs_at() acquires MOUNTS, clones the Arc<FS>, drops MOUNTS, returns.
    let file_size = match crate::vfs::fs_at(mount_idx) {
        Some((fs, _)) => match fs.stat(inode) {
            Ok(st) => st.size,
            Err(_) => return -9, // EIO / stat failed
        },
        None => return -9, // mount entry disappeared
    };

    let new_off = file_size as i64 + offset;
    if new_off < 0 {
        return -22; // EINVAL — per POSIX lseek(2)
    }

    // Step C: reacquire and re-validate.  close(2) on another thread while
    // lseek(2) is in-flight is valid per POSIX; return EBADF for stale fds.
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -9, // process exited between steps A and C
    };
    let fd = match proc.file_descriptors.get_mut(fd_num).and_then(|f| f.as_mut()) {
        Some(f) => f,
        None => return -9, // fd closed while stat was in-flight (EBADF)
    };
    // Identity guard: if the slot was recycled to a different file the
    // computed offset is stale — treat as EBADF.
    if fd.mount_idx != mount_idx || fd.inode != inode {
        return -9;
    }
    fd.offset = new_off as u64;
    new_off
}

pub(crate) fn sys_dup(old_fd: usize) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let mut fd_clone = match proc.file_descriptors.get(old_fd).and_then(|f| f.as_ref()) {
        Some(fd) => fd.clone(),
        None => return -9,
    };

    // Per POSIX dup(2): "The duplicate descriptor shall have its
    // close-on-exec flag cleared."
    fd_clone.cloexec = false;

    // Bump the underlying resource's open-file-description refcount so
    // that a close(2) on either the old or new fd does not prematurely
    // destroy the shared object.  Per POSIX.1-2017 §2.14 and dup(2):
    // "the duplicate and original file descriptors refer to the same open
    // file description".  Gate on UNIX_SOCKET_FLAG rather than mount_idx
    // alone: AF_INET sockets also use mount_idx==usize::MAX but have a
    // distinct refcount path.
    if fd_clone.file_type == crate::vfs::FileType::Socket
        && fd_clone.flags & UNIX_SOCKET_FLAG != 0
    {
        crate::net::unix::inc_ref(fd_clone.inode);
    }
    // Same for anonymous pipe ends — the duplicate must count as an
    // independent reader/writer reference.  Without this, `close(2)` on
    // either fd drops the pipe's count to zero and the still-open end
    // observes a phantom EOF / EPIPE.
    if fd_clone.file_type == crate::vfs::FileType::Pipe
        && fd_clone.mount_idx == usize::MAX
        && fd_clone.flags & 0x8000_0000 != 0
    {
        if fd_clone.flags & 1 == 1 {
            crate::ipc::pipe::pipe_add_writer(fd_clone.inode);
        } else {
            crate::ipc::pipe::pipe_add_reader(fd_clone.inode);
        }
    }

    // Find lowest free fd
    for i in 0..proc.file_descriptors.len() {
        if proc.file_descriptors[i].is_none() {
            proc.file_descriptors[i] = Some(fd_clone);
            return i as i64;
        }
    }

    if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let idx = proc.file_descriptors.len();
        proc.file_descriptors.push(Some(fd_clone));
        return idx as i64;
    }

    -24 // EMFILE
}

pub(crate) fn sys_dup2(old_fd: usize, new_fd: usize) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    if old_fd == new_fd {
        // Check old_fd is valid
        return match proc.file_descriptors.get(old_fd).and_then(|f| f.as_ref()) {
            Some(_) => new_fd as i64,
            None => -9,
        };
    }

    let mut fd_clone = match proc.file_descriptors.get(old_fd).and_then(|f| f.as_ref()) {
        Some(fd) => fd.clone(),
        None => return -9,
    };

    // Per POSIX dup2(2): the duplicate's close-on-exec flag is cleared.
    fd_clone.cloexec = false;

    // Bump the underlying resource's open-file-description refcount.
    // Same rationale as sys_dup above (POSIX.1-2017 §2.14 / dup2(2)).
    // Use UNIX_SOCKET_FLAG to exclude AF_INET sockets (W216 review).
    if fd_clone.file_type == crate::vfs::FileType::Socket
        && fd_clone.flags & UNIX_SOCKET_FLAG != 0
    {
        crate::net::unix::inc_ref(fd_clone.inode);
    }
    // Same for anonymous pipe ends.
    if fd_clone.file_type == crate::vfs::FileType::Pipe
        && fd_clone.mount_idx == usize::MAX
        && fd_clone.flags & 0x8000_0000 != 0
    {
        if fd_clone.flags & 1 == 1 {
            crate::ipc::pipe::pipe_add_writer(fd_clone.inode);
        } else {
            crate::ipc::pipe::pipe_add_reader(fd_clone.inode);
        }
    }

    // Grow the table if needed
    while proc.file_descriptors.len() <= new_fd {
        proc.file_descriptors.push(None);
    }

    // Close existing fd at new_fd: per POSIX dup2(2), "If `fildes2` is
    // already a valid open file descriptor, it shall be closed first,
    // unless `fildes` is equal to `fildes2`."  Drop pipe-end refcounts
    // (and unix-socket refcounts) on the displaced fd before overwriting
    // the slot, so the underlying object sees the close.
    if let Some(prev) = proc.file_descriptors[new_fd].take() {
        crate::proc::close_pipe_fd(&prev);
        if prev.file_type == crate::vfs::FileType::Socket
            && prev.flags & UNIX_SOCKET_FLAG != 0
        {
            crate::net::unix::close(prev.inode);
        }
    }
    proc.file_descriptors[new_fd] = Some(fd_clone);
    new_fd as i64
}

/// pipe(pipefd[2]) — create a pipe.
///
/// Writes exactly 8 bytes: `int pipefd[2]` = two 4-byte signed integers,
/// as specified by pipe(2) — https://man7.org/linux/man-pages/man2/pipe.2.html
/// and POSIX.1-2017.  The previous `*mut u64` signature wrote 16 bytes
/// (2 × u64), which overran the caller's 8-byte buffer (CWE-787).
///
/// `fds_out` must point to a buffer of at least 8 bytes (2 × sizeof(int)).
/// Pointer validation is performed at the user/kernel boundary
/// (Linux dispatch arm 22; Aether dispatch); kernel-internal callers
/// bypass — see sys_open_linux for the rationale.
pub(crate) fn sys_pipe(fds_out: *mut u32) -> i64 {
    if fds_out.is_null() {
        return -22; // EINVAL
    }

    let pipe_id = crate::ipc::pipe::create_pipe();
    let pid = crate::proc::current_pid_lockless();

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    // Create read-end FD
    let read_fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode: pipe_id,
        offset: 0,
        flags: 0x8000_0000, // Pipe read end
        is_console: false,
        cloexec: false,
        file_type: crate::vfs::FileType::Pipe,
        open_path: alloc::string::String::new(),
    };

    // Create write-end FD
    let write_fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode: pipe_id,
        offset: 0,
        flags: 0x8000_0001, // Pipe write end
        is_console: false,
        cloexec: false,
        file_type: crate::vfs::FileType::Pipe,
        open_path: alloc::string::String::new(),
    };

    // Find two free FD slots
    let mut read_idx = None;
    let mut write_idx = None;
    for i in 0..proc.file_descriptors.len() {
        if proc.file_descriptors[i].is_none() {
            if read_idx.is_none() {
                read_idx = Some(i);
            } else if write_idx.is_none() {
                write_idx = Some(i);
                break;
            }
        }
    }

    // Extend if needed
    if read_idx.is_none() {
        if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
            read_idx = Some(proc.file_descriptors.len());
            proc.file_descriptors.push(None);
        } else {
            return -24; // EMFILE
        }
    }
    if write_idx.is_none() {
        if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
            write_idx = Some(proc.file_descriptors.len());
            proc.file_descriptors.push(None);
        } else {
            return -24; // EMFILE
        }
    }

    let ri = read_idx.unwrap();
    let wi = write_idx.unwrap();

    proc.file_descriptors[ri] = Some(read_fd);
    proc.file_descriptors[wi] = Some(write_fd);

    // Write exactly 8 bytes: int pipefd[2] per pipe(2) ABI.
    // write_unaligned is used defensively; the caller's pipefd[] may not be
    // 4-byte aligned (musl/glibc do not guarantee stack-frame alignment of
    // individual locals beyond their declared type).
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::ptr::write_unaligned(fds_out,        ri as u32);
        core::ptr::write_unaligned(fds_out.add(1), wi as u32);
    }

    crate::serial_println!("[SYSCALL] pipe() -> [{}, {}] (pipe_id={})", ri, wi, pipe_id);
    0
}

/// Check if a file descriptor is a pipe.
pub(crate) fn is_pipe_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.mount_idx == usize::MAX && f.flags & 0x8000_0000 != 0)
        .unwrap_or(false)
}

/// Check if a file descriptor is a socket.
pub(crate) fn is_socket_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.mount_idx == usize::MAX && f.flags & 0x4000_0000 != 0)
        .unwrap_or(false)
}

/// Allocate a new socket fd for the given process, returning the fd number.
///
/// `cloexec` and `nonblock` are extracted from the `type` argument of
/// `socket(2)` (SOCK_CLOEXEC = 0x80000, SOCK_NONBLOCK = 0x800) and must be
/// applied to the resulting fd atomically — POSIX.1-2017 socket(2).
/// O_NONBLOCK is stored as bit 0x0800 in the fd flags field so that
/// subsequent `fcntl(F_GETFL)` calls see it correctly.
pub(crate) fn alloc_socket_fd(
    pid: u64,
    socket_id: u64,
    sock_type: u32,
    cloexec: bool,
    nonblock: bool,
) -> i64 {
    let mut flag_bits: u32 = 0x4000_0000 | (sock_type & 0x03); // SOCKET_FD | type
    if nonblock {
        flag_bits |= 0x0800; // O_NONBLOCK
    }
    let fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode: socket_id,
        offset: 0,
        flags: flag_bits,
        is_console: false,
        cloexec,
        file_type: crate::vfs::FileType::CharDevice,
        open_path: alloc::string::String::new(),
    };
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3, // ESRCH
    };
    for i in 0..proc.file_descriptors.len() {
        if proc.file_descriptors[i].is_none() {
            proc.file_descriptors[i] = Some(fd);
            return i as i64;
        }
    }
    if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let idx = proc.file_descriptors.len();
        proc.file_descriptors.push(Some(fd));
        idx as i64
    } else {
        -24 // EMFILE
    }
}

/// Get the pipe_id for a pipe file descriptor.
pub(crate) fn get_pipe_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(0)
}

/// Get the socket_id for a socket file descriptor.
pub(crate) fn get_socket_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

/// Check if a file descriptor is an eventfd.
pub(crate) fn is_eventfd_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.file_type == crate::vfs::FileType::EventFd)
        .unwrap_or(false)
}

/// Get the eventfd slot ID for a file descriptor.
pub(crate) fn get_eventfd_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

// ── timerfd / signalfd / inotifyfd helpers ────────────────────────────────────

pub(crate) fn is_timerfd_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.file_type == crate::vfs::FileType::TimerFd)
        .unwrap_or(false)
}

pub(crate) fn get_timerfd_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

pub(crate) fn is_signalfd_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.file_type == crate::vfs::FileType::SignalFd)
        .unwrap_or(false)
}

pub(crate) fn get_signalfd_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

pub(crate) fn is_inotify_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.file_type == crate::vfs::FileType::InotifyFd)
        .unwrap_or(false)
}

pub(crate) fn get_inotify_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

// ── Poll fd readiness helper ──────────────────────────────────────────────────

/// Compute revents for a single fd given the requested events mask.
/// Returns 0 if fd is not ready for any of the requested events.
///
/// `POLLHUP` is *unconditional* per POSIX `poll(2)` — it is reported
/// regardless of whether the caller requested it in `events`.  On a pipe
/// read-end whose every writer has closed, the kernel must set
/// `POLLHUP`; if data is still buffered it must coexist with `POLLIN`
/// so userspace can drain the remainder before observing EOF.
pub(crate) fn poll_revents(pid: u64, fd: usize, events: u16) -> u16 {
    const POLLIN:    u16 = 0x0001;
    const POLLOUT:   u16 = 0x0004;
    const POLLHUP:   u16 = 0x0010;
    const POLLRDHUP: u16 = 0x2000;
    // Treat fd 0/1/2 as the console stdin/stdout/stderr ONLY when they are
    // genuinely a console fd or are not open at all.  A process may
    // `close()` a standard descriptor and `socketpair()` / `pipe()` / `dup()`
    // a typed fd back into slot 0, 1, or 2 (POSIX guarantees the lowest free
    // descriptor is reused — IEEE 1003.1-2017 §2.14).  Special-casing by fd
    // *number* alone would shadow that real fd and report it as a plain
    // console stream, dropping POLLHUP/POLLIN/POLLRDHUP — the very edge
    // `poll(2)` must surface.  This mirrors the `is_console || (!fd_present
    // && fd_num <= 2)` test used by the TTY/ioctl path, and the `is_console`
    // dispatch in `epoll_poll_events`.
    if fd <= 2 && fd_is_console_or_absent(pid, fd) {
        return if fd == 0 { events & POLLIN } else { events & POLLOUT };
    }
    if is_eventfd_fd(pid, fd) {
        if crate::ipc::eventfd::is_readable(get_eventfd_id(pid, fd)) { events & POLLIN } else { 0 }
    } else if is_unix_socket_fd(pid, fd) {
        let uid = get_unix_socket_id(pid, fd);
        let has_d = crate::net::unix::has_data(uid);
        let has_p = crate::net::unix::has_pending(uid);
        let readable = has_d || has_p;
        #[cfg(feature = "firefox-test")]
        if pid >= 1 && events & POLLIN != 0 {
            crate::serial_println!("[UNIXPOLL] pid={} fd={} uid={} has_data={} avail={} events={:#x}",
                pid, fd, uid, has_d, crate::net::unix::bytes_available(uid), events);
        }
        let mut rev = 0u16;
        if readable { rev |= events & POLLIN; }
        rev |= events & POLLOUT; // connected sockets always writable
        // `poll(2)` distinguishes a read-side half-close from a full
        // hang-up, so we report them separately (matching the `epoll(7)`
        // EPOLLRDHUP / EPOLLHUP split):
        if crate::net::unix::read_shutdown(uid) {
            // Read-side half-close (peer `shutdown(SHUT_WR)`, or we did
            // `shutdown(SHUT_RD)`; the connection is still up and still
            // writable).  The read end becomes readable — `read()` returns
            // 0 (EOF) — so `POLLIN` is raised even with an empty buffer, and
            // `POLLRDHUP` ("read EOF, write still valid") is reported when
            // the caller asked for it.  POLLOUT (above) stays set.  No
            // POLLHUP: the connection is not fully dead.  POLLIN is the bit
            // NSPR's wait loop keys on.
            rev |= events & POLLIN;
            rev |= events & POLLRDHUP;
        }
        if crate::net::unix::fully_hung_up(uid) {
            // Full hang-up (SHUT_RDWR both directions, or either endpoint
            // fully closed).  Per POSIX `poll(2)`, `POLLHUP` is reported
            // unconditionally (independent of the requested `events`), and
            // coexists with `POLLIN` while a draining reader observes EOF —
            // mirroring the pipe read-end branch below.
            rev |= POLLHUP;
            rev |= events & POLLIN;
        }
        rev
    } else if is_socket_fd(pid, fd) {
        let sid = get_socket_id(pid, fd);
        let mut rev = 0u16;
        if crate::net::socket::socket_has_data(sid) { rev |= events & POLLIN; }
        rev |= events & POLLOUT;
        rev
    } else if is_pipe_fd(pid, fd) {
        let pipe_id = get_pipe_id(pid, fd);
        let is_read_end = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid)
                .and_then(|p| p.file_descriptors.get(fd))
                .and_then(|f| f.as_ref())
                .map(|f| f.flags & 0x1 == 0)
                .unwrap_or(false)
        };
        if is_read_end {
            // Per POSIX `poll(2)`:
            //   * `POLLIN`  — data is available to read.
            //   * `POLLHUP` — the peer (writer) has closed; reported even
            //                 when the caller did not request it.  When
            //                 buffered data remains, `POLLHUP` is set
            //                 alongside `POLLIN` so a draining reader can
            //                 consume the tail before observing EOF.
            let mut rev = 0u16;
            if crate::ipc::pipe::pipe_has_data(pipe_id) {
                rev |= events & POLLIN;
            }
            if crate::ipc::pipe::pipe_writer_closed(pipe_id) {
                rev |= POLLHUP;
            }
            rev
        } else {
            events & POLLOUT
        }
    } else if is_timerfd_fd(pid, fd) {
        if crate::ipc::timerfd::is_readable(get_timerfd_id(pid, fd)) { events & POLLIN } else { 0 }
    } else if is_signalfd_fd(pid, fd) {
        if crate::ipc::signalfd::is_readable(get_signalfd_id(pid, fd)) { events & POLLIN } else { 0 }
    } else if is_inotify_fd(pid, fd) {
        if crate::ipc::inotify::is_readable(get_inotify_id(pid, fd)) { events & POLLIN } else { 0 }
    } else {
        events & (POLLIN | POLLOUT) // regular file always ready
    }
}

/// Returns true if `fd` is a console fd or is not currently open in `pid`.
///
/// Used by `poll_revents` to decide whether fds 0/1/2 should be treated as
/// the default console stdin/stdout/stderr.  A descriptor that has been
/// re-bound to a socket/pipe/eventfd (after `close()` + reuse of the low
/// slot) is `is_console == false` *and* present, so this returns false and
/// the typed-fd readiness logic runs instead.  Mirrors the
/// `is_console || (!fd_present && fd_num <= 2)` predicate in the TTY/ioctl
/// path (IEEE 1003.1-2017 §2.14, lowest-free-descriptor reuse).
fn fd_is_console_or_absent(pid: u64, fd: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd))
    {
        // Slot present and occupied: console only if explicitly flagged.
        Some(Some(f)) => f.is_console,
        // Slot absent or closed: fall back to the default-console assumption.
        _ => true,
    }
}

// ── AF_UNIX socket helpers ────────────────────────────────────────────────────

pub(crate) const UNIX_SOCKET_FLAG: u32 = 0x0080_0000; // bit 23: fd is an AF_UNIX socket

/// Check if a file descriptor is an AF_UNIX socket.
pub(crate) fn is_unix_socket_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.mount_idx == usize::MAX
              && f.flags & 0x4000_0000 != 0
              && f.flags & UNIX_SOCKET_FLAG != 0)
        .unwrap_or(false)
}

/// Get the unix socket id for a file descriptor.
pub(crate) fn get_unix_socket_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

/// Allocate a new AF_UNIX socket fd, returning the fd number or negative errno.
///
/// `cloexec` sets `FD_CLOEXEC` on the new fd (per `socket(2)` `SOCK_CLOEXEC`).
/// `nonblock` sets `O_NONBLOCK` in the fd's status flags so subsequent
/// read/write calls return -EAGAIN instead of blocking (per `socket(2)`
/// `SOCK_NONBLOCK`).
pub(crate) fn alloc_unix_socket_fd(pid: u64, unix_id: u64, cloexec: bool, nonblock: bool) -> i64 {
    // O_NONBLOCK = 0x800 (Linux ABI).  Stored in the lower 12 bits of
    // `flags` so fcntl(F_GETFL/F_SETFL) round-trips and read/write paths
    // can branch on it.
    let mut flag_bits: u32 = 0x4000_0000 | UNIX_SOCKET_FLAG; // SOCKET_FD | UNIX_FLAG
    if nonblock { flag_bits |= 0x0800; }
    let fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode: unix_id,
        offset: 0,
        flags: flag_bits,
        is_console: false,
        cloexec,
        file_type: crate::vfs::FileType::Socket,
        open_path: alloc::string::String::new(),
    };
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };
    for i in 0..proc.file_descriptors.len() {
        if proc.file_descriptors[i].is_none() {
            proc.file_descriptors[i] = Some(fd);
            return i as i64;
        }
    }
    if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let idx = proc.file_descriptors.len();
        proc.file_descriptors.push(Some(fd));
        idx as i64
    } else {
        -24 // EMFILE
    }
}

/// uname buffer layout (5 fields, 65 bytes each = 325 bytes):
///   sysname, nodename, release, version, machine
///
/// We report sysname="Linux" with a Linux-shaped release string so that
/// glibc, NSS, NSPR, and applications such as Mozilla Firefox take their
/// regular Linux code paths (their feature detection branches on
/// `uname.sysname == "Linux"` and parses release as
/// `<major>.<minor>.<patch>`; values < 3.0 disable modern features).
/// The Linux-compatible release embeds an "-astryx" suffix so the OS is
/// still self-identifying, and the version field carries the AstryxOS
/// branding for any caller that prints it.  Per POSIX `uname(2)`.
pub(crate) fn sys_uname(buf: *mut u8) -> i64 {
    const FIELD_LEN: usize = 65;
    const TOTAL_LEN: usize = FIELD_LEN * 5; // 325 bytes (5 × utsname fields)

    // Pointer validation is done at the user/kernel boundary (the Linux
    // dispatch_body arm for syscall 63, and the Aether dispatch arm for
    // syscall 0x32).  Internal kernel callers (test_runner, etc.) pass
    // kernel-resident buffers and must bypass the strict user check —
    // see the same pattern in sys_open_linux.

    let fields: [&[u8]; 5] = [
        b"Linux",                       // sysname
        b"astryx",                      // nodename
        b"5.15.0-astryx",               // release (Linux-compat, parses as 5.15.0)
        b"#1 SMP AstryxOS Aether",      // version
        b"x86_64",                      // machine
    ];

    // SMAP bracket — `buf` is a user-VA for the syscall path.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let out = unsafe { core::slice::from_raw_parts_mut(buf, TOTAL_LEN) };
    for b in out.iter_mut() {
        *b = 0;
    }

    for (i, field) in fields.iter().enumerate() {
        let offset = i * FIELD_LEN;
        let len = field.len().min(FIELD_LEN - 1);
        out[offset..offset + len].copy_from_slice(&field[..len]);
    }

    0
}

pub(crate) fn sys_nanosleep(milliseconds: u64) -> i64 {
    if milliseconds == 0 {
        crate::sched::yield_cpu();
        return 0;
    }

    // Convert milliseconds to timer ticks (assuming ~1000 Hz PIT).
    let ticks = if milliseconds == 0 { 1 } else { milliseconds };
    crate::proc::sleep_ticks(ticks);
    0
}

pub(crate) fn sys_unlink(path_ptr: *const u8, path_len: usize) -> i64 {
    let path_owned = {
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        let slice = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
        match core::str::from_utf8(slice) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => return -22,
        }
    };
    match crate::vfs::remove(path_owned.as_str()) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

pub(crate) fn sys_sigaction(sig: u8, handler_addr: u64) -> i64 {
    use crate::signal::{SigAction, SIGKILL, SIGSTOP, MAX_SIGNAL};
    
    if sig == 0 || sig >= MAX_SIGNAL || sig == SIGKILL || sig == SIGSTOP {
        return -22; // EINVAL — can't change SIGKILL/SIGSTOP
    }

    let pid = crate::proc::current_pid_lockless();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let sig_state = match proc.signal_state.as_mut() {
        Some(s) => s,
        None => return -1, // EPERM — kernel process
    };

    let action = match handler_addr {
        0 => SigAction::Default,
        1 => SigAction::Ignore,
        addr => SigAction::Handler { addr, restorer: 0 },
    };

    sig_state.actions[sig as usize] = action;
    0
}

pub(crate) fn sys_sigprocmask(how: u32, new_mask: u64) -> i64 {
    const SIG_BLOCK: u32 = 0;
    const SIG_UNBLOCK: u32 = 1;
    const SIG_SETMASK: u32 = 2;

    let pid = crate::proc::current_pid_lockless();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let sig_state = match proc.signal_state.as_mut() {
        Some(s) => s,
        None => return -1,
    };

    let old_mask = sig_state.blocked;

    match how {
        SIG_BLOCK => sig_state.blocked |= new_mask,
        SIG_UNBLOCK => sig_state.blocked &= !new_mask,
        SIG_SETMASK => sig_state.blocked = new_mask,
        _ => return -22,
    }

    // SIGKILL and SIGSTOP can never be blocked
    sig_state.blocked &= !((1u64 << crate::signal::SIGKILL) | (1u64 << crate::signal::SIGSTOP));

    old_mask as i64
}

/// sigreturn — Restore the process context saved by signal delivery.
///
/// When the signal trampoline calls `syscall` with SYS_SIGRETURN (39) or
/// Linux's rt_sigreturn (15), the user RSP points into the signal frame
/// (past the popped restorer address).  We read the saved registers from
/// the frame, write them back onto the kernel stack so that the normal
/// `sysretq` epilogue restores the original user context.
///
/// Returns the original `saved_rax` value which dispatch() puts into RAX.
pub(crate) fn sys_sigreturn() -> i64 {
    // The user RSP at syscall entry (saved per-CPU before we switched
    // stacks) is in PER_CPU_SYSCALL[cpu].user_rsp.  After the handler's
    // `ret` popped the restorer and the trampoline issued `syscall`, RSP
    // points at the SignalFrame.sig_num field (restorer was consumed by ret).
    let user_rsp = unsafe { PER_CPU_SYSCALL[cpu_index()].user_rsp };

    // Read the signal frame from user memory.
    // user_rsp points to sig_num (offset 8 in SignalFrame).
    // restorer was consumed by ret → it's at user_rsp - 8.
    let frame_base = user_rsp.wrapping_sub(8);
    // Validate the entire frame lies within the user-space address range
    // before dereferencing any field.  A crafted frame_base pointing into
    // kernel VA would allow a ring-3 caller to read arbitrary kernel memory
    // via the field reads below.  Per POSIX sigaction(2) / ABI contract,
    // the signal frame is always a user-space stack allocation; a kernel-VA
    // value is unambiguously invalid — return EFAULT (§14.4 POSIX.1-2017).
    if !validate_user_ptr(frame_base, core::mem::size_of::<crate::signal::SignalFrame>()) {
        return -crate::subsys::linux::errno::EFAULT;
    }
    let frame_ptr = frame_base as *const crate::signal::SignalFrame;

    let (sig_num, saved_mask, saved_rsp, saved_r15, saved_r14, saved_r13,
         saved_r12, saved_rbx, saved_rbp, saved_r11, saved_rcx, saved_rax);
    // SMAP bracket — frame_base has already been range-validated by
    // validate_user_ptr above so the UserGuard is safe to lift AC.
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        sig_num   = (*frame_ptr).sig_num;
        saved_mask = (*frame_ptr).saved_mask;
        saved_rsp = (*frame_ptr).saved_rsp;
        saved_r15 = (*frame_ptr).saved_r15;
        saved_r14 = (*frame_ptr).saved_r14;
        saved_r13 = (*frame_ptr).saved_r13;
        saved_r12 = (*frame_ptr).saved_r12;
        saved_rbx = (*frame_ptr).saved_rbx;
        saved_rbp = (*frame_ptr).saved_rbp;
        saved_r11 = (*frame_ptr).saved_r11;
        saved_rcx = (*frame_ptr).saved_rcx;
        saved_rax = (*frame_ptr).saved_rax;
    }

    crate::serial_println!(
        "[SIGNAL] sigreturn: restoring context for signal {} (rip={:#x}, rsp={:#x})",
        sig_num, saved_rcx, saved_rsp
    );

    // Restore the blocked-signal mask.
    {
        let pid = crate::proc::current_pid_lockless();
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc_entry) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(ref mut ss) = proc_entry.signal_state {
                ss.blocked = saved_mask;
                // SIGKILL/SIGSTOP can never be blocked.
                ss.blocked &= !((1u64 << crate::signal::SIGKILL) | (1u64 << crate::signal::SIGSTOP));
            }
        }
    }

    // Write the original registers back onto the kernel stack frame.
    // The kernel stack frame layout (from syscall_entry) relative to
    // the per-CPU kernel_rsp:
    //   ksp - 8  = user RSP
    //   ksp - 16 = RCX (user RIP)
    //   ksp - 24 = R11 (user RFLAGS)
    //   ksp - 32 = RBP
    //   ksp - 40 = RBX
    //   ksp - 48 = R12
    //   ksp - 56 = R13
    //   ksp - 64 = R14
    //   ksp - 72 = R15
    let ksp = unsafe { PER_CPU_SYSCALL[cpu_index()].kernel_rsp };
    // Sanitise RFLAGS before restoring it as the user's EFLAGS via SYSRETQ.
    // The signal frame is user-controlled memory; a crafted handler can
    // request RFLAGS.IOPL=3 (bits 13:12) to enable IN/OUT/CLI/STI from
    // ring 3 — a privilege escalation to ring-0-equivalent I/O capability.
    // We also clear NT (bit 14), RF (bit 16), VM (bit 17), and AC (bit 18,
    // SMAP-bypass when SMAP becomes active), and force IF (bit 9) so a
    // sigreturn cannot leave the user with interrupts permanently masked.
    // Per Intel SDM Vol. 3A §3.4.3 (EFLAGS register) and the BadIRET class
    // (CVE-2014-9322); CWE-269 (Improper Privilege Management).
    const RFLAGS_USER_MASK: u64 = !((0x3u64 << 12)   // IOPL
                                  | (1u64 << 14)     // NT
                                  | (1u64 << 16)     // RF
                                  | (1u64 << 17)     // VM
                                  | (1u64 << 18));   // AC
    let sanitised_rflags = (saved_r11 & RFLAGS_USER_MASK) | (1u64 << 9); // force IF
    unsafe {
        *((ksp -  8) as *mut u64) = saved_rsp;
        *((ksp - 16) as *mut u64) = saved_rcx;  // user RIP
        *((ksp - 24) as *mut u64) = sanitised_rflags;
        *((ksp - 32) as *mut u64) = saved_rbp;
        *((ksp - 40) as *mut u64) = saved_rbx;
        *((ksp - 48) as *mut u64) = saved_r12;
        *((ksp - 56) as *mut u64) = saved_r13;
        *((ksp - 64) as *mut u64) = saved_r14;
        *((ksp - 72) as *mut u64) = saved_r15;
    }

    // Return original RAX — dispatch() returns this, the asm puts it
    // into RAX, and the signal check after dispatch will see the restored
    // frame.  If another signal is pending it will be delivered (correct
    // nested-signal behaviour).
    saved_rax as i64
}

/// getrandom — Fill a buffer with pseudo-random bytes.
///
/// Per getrandom(2): on success returns the number of bytes filled, which
/// equals `count` when called without GRND_NONBLOCK and no signal interrupts.
///
/// Flags (Linux `<sys/random.h>` / `<linux/random.h>`):
///   GRND_NONBLOCK (0x01) — return EAGAIN if the entropy pool is not ready.
///                          We treat our PRNG as always ready, so this flag
///                          is accepted but never causes EAGAIN.
///   GRND_RANDOM   (0x02) — draw from /dev/random pool (legacy). We have one
///                          pool, so this is accepted and ignored.
///   GRND_INSECURE (0x04) — return possibly-non-cryptographic bytes without
///                          blocking.  Accepted; our PRNG path is already
///                          identical for the secure / insecure cases.
///
/// Any flag outside the documented set returns EINVAL, matching the Linux
/// kernel since v5.6 (commit 91e2cef "random: return EINVAL for invalid
/// flags").  Silently accepting unknown flag bits is a CWE-20 (Improper
/// Input Validation) hazard: a future flag that introduces
/// security-sensitive semantics (e.g. a "must be in a particular pool"
/// guarantee) would be honoured-by-name but not by behaviour, leaving
/// callers with a false sense of compliance.  Failing-closed on unknown
/// bits forces the question to surface as an explicit ABI update.
///
/// Implementation: attempt RDRAND up to 10 retries per 8-byte word; if
/// RDRAND is unavailable or consistently fails (CF=0), fall back to a
/// xorshift64 PRNG seeded from the TSC.  Either path fills exactly `count`
/// bytes and returns `count`.
pub(crate) fn sys_getrandom(buf: *mut u8, count: usize, flags: u32) -> i64 {
    // Reject unknown flag bits — per getrandom(2) ERRORS and the Linux
    // kernel implementation (drivers/char/random.c::sys_getrandom).
    // GRND_NONBLOCK=0x01 | GRND_RANDOM=0x02 | GRND_INSECURE=0x04.
    const GRND_KNOWN_MASK: u32 = 0x01 | 0x02 | 0x04;
    if flags & !GRND_KNOWN_MASK != 0 {
        return -22; // EINVAL
    }
    if buf.is_null() || count == 0 {
        return -22; // EINVAL
    }
    // Range-validate the destination buffer is wholly in user space.
    // Without this check a process can pass a kernel address (e.g. the
    // kernel heap base) and obtain a kernel-mode write primitive whose
    // contents are attacker-influenceable via repeated calls — CWE-119
    // (Improper Restriction of Operations within the Bounds of a Memory
    // Buffer); see also CWE-823 (Use of Out-of-range Pointer Offset).
    if !validate_user_ptr(buf as u64, count) {
        return -14; // EFAULT
    }

    #[cfg(feature = "firefox-test")]
    crate::mm::w215_diag::probe(crate::mm::w215_diag::Writer::Getrandom, buf, count);

    // Record/replay: fill from the deterministic kernel PRNG instead of
    // RDRAND / TSC-seeded xorshift.  This is the same chokepoint that
    // ASLR and AT_RANDOM funnel through via `security::rand::rand_u64`,
    // so the bytes returned here are byte-stable across runs with the
    // same `astryx.rng_seed=` cmdline value.  See
    // `crate::record_replay` for the protocol.
    #[cfg(feature = "record-replay")]
    {
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        let out = unsafe { core::slice::from_raw_parts_mut(buf, count) };
        let mut i = 0;
        while i < count {
            let val = crate::security::rand::rand_u64();
            let bytes = val.to_le_bytes();
            let n = (count - i).min(8);
            out[i..i + n].copy_from_slice(&bytes[..n]);
            i += n;
        }
        return count as i64;
    }

    // SMAP bracket — every iteration below writes through `out` which
    // backs the user buffer.  Held for the full fill so RDRAND and the
    // xorshift fallback both run with AC=1.  CPUID / RDRAND themselves
    // do not touch memory, so the AC region is purely the user write
    // surface.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let out = unsafe { core::slice::from_raw_parts_mut(buf, count) };

    // Detect RDRAND support via CPUID leaf 1, ECX bit 30.
    let has_rdrand = unsafe {
        let mut ecx: u32;
        // rbx is reserved by LLVM as the PIC base; save/restore manually.
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            in("eax") 1u32,
            lateout("ecx") ecx,
            out("edx") _,
        );
        ecx & (1 << 30) != 0
    };

    // Try RDRAND with a bounded retry budget.  Intel recommends up to 10
    // retries; if all fail the hardware RNG is busy or absent.  Fall back to
    // the TSC-seeded xorshift rather than spinning forever.
    let mut rdrand_succeeded = false;
    if has_rdrand {
        let mut i = 0;
        'fill: while i < count {
            let mut filled = false;
            for _ in 0..10 {
                let mut val: u64;
                let ok: u8;
                unsafe {
                    core::arch::asm!(
                        "rdrand {val}",
                        "setc {ok}",
                        val = out(reg) val,
                        ok = out(reg_byte) ok,
                    );
                }
                if ok != 0 {
                    let bytes = val.to_le_bytes();
                    let n = (count - i).min(8);
                    out[i..i + n].copy_from_slice(&bytes[..n]);
                    i += n;
                    filled = true;
                    break;
                }
            }
            if !filled {
                // RDRAND exhausted retries — abandon and fall back.
                break 'fill;
            }
        }
        if i >= count {
            rdrand_succeeded = true;
        }
    }

    if !rdrand_succeeded {
        // xorshift64 seeded from the TSC.  Mix in a pointer address for
        // additional entropy across calls in the same TSC window.
        let mut state: u64 = unsafe {
            let lo: u32;
            let hi: u32;
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi);
            ((hi as u64) << 32) | lo as u64
        };
        // XOR with the output buffer address to differentiate concurrent
        // callers that happen to read the TSC at the same tick.
        state ^= buf as u64;
        if state == 0 {
            state = 0xDEAD_BEEF_CAFE_BABE;
        }
        for byte in out.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
    }

    // Per getrandom(2): return the number of bytes filled on success.
    count as i64
}

// ===== Linux Syscall ABI Compatibility Layer ================================
//
// The Linux dispatch body and all Linux-specific helpers have moved to
// `kernel/src/subsys/linux/syscall.rs`.  This section provides:
//   - `dispatch_linux()` — thin delegating stub for backward compat
//   - Re-exports of functions called directly by test_runner.rs

/// Linux compatibility syscall dispatch — delegates to `subsys/linux/syscall.rs`.
///
/// Exposed as `pub` so that `crate::subsys::linux::dispatch()` and the test
/// runner can call it directly by the old name.  The implementation body lives
/// in `crate::subsys::linux::syscall::dispatch`.
pub fn dispatch_linux(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    crate::subsys::linux::syscall::dispatch(num, arg1, arg2, arg3, arg4, arg5, arg6)
}

// Re-export Linux-specific functions that are called directly from test_runner.rs
// and from other kernel modules via `crate::syscall::`.
pub use crate::subsys::linux::syscall::{
    sys_arch_prctl,
    sys_set_tid_address,
    sys_clock_gettime,
    sys_writev,
    sys_futex_linux,
};

// ===== Kernel-internal test helpers =========================================
//
// These thin public wrappers expose syscall internals to the headless test
// suite without going through the full syscall dispatch path.  They are
// only used from test_runner.rs and are safe to call from kernel context
// (current_pid() returns the test process PID, which is always valid).

// ── Kernel-dispatch bypass machinery (test-mode / firefox-test only) ─────────
//
// Gated on `test-mode` and `firefox-test` features.  In production builds
// these items are omitted entirely; `user_ptr_check_bypassed()` is provided
// as a constant-false stub so all call sites compile without modification and
// the compiler eliminates the dead `if !user_ptr_check_bypassed()` branches
// through constant folding.
//
// The preemption hazard this gating prevents: a test thread holding
// KernelDispatchGuard that is preempted (via schedule()) leaves the per-CPU
// counter > 0 while the CPU runs a different task.  Any concurrent user-mode
// syscall arriving on that CPU would then bypass validate_user_ptr.  Limiting
// the machinery to test builds eliminates this exposure in production images.

/// Per-CPU bypass counter for the user-mode pointer-range checks at the
/// Linux dispatch arms.  In-kernel test code that drives `dispatch_linux`
/// with kernel-VA buffers (e.g. `b"/etc/passwd\0".as_ptr()`) must wrap the
/// call in [`KernelDispatchGuard`] so the per-arm `validate_user_ptr` /
/// `user_path_ptr_ok` gates skip the check for the lifetime of the guard.
///
/// The bypass is INTENTIONALLY scoped (RAII) so a forgotten guard cannot
/// permanently disable the security check; if a test panics inside the
/// guard, Drop still decrements.  Real user-mode SYSCALL traffic never
/// passes through this counter — the asm `syscall_entry` path leaves the
/// counter at zero, so the dispatch arms enforce validation as designed.
///
/// Only present in `test-mode` and `firefox-test` builds.
#[cfg(any(feature = "test-mode", feature = "firefox-test"))]
pub static KERNEL_DISPATCH_BYPASS: [core::sync::atomic::AtomicU64; MAX_CPUS] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; MAX_CPUS]
};

/// Returns `true` if the current CPU is inside a `KernelDispatchGuard`
/// scope and the per-arm user-pointer validation should be skipped.
///
/// In production builds (neither `test-mode` nor `firefox-test`) this always
/// returns `false` — the bypass machinery does not exist and validation is
/// never skipped.  The compiler eliminates the surrounding dead branches.
#[inline]
pub fn user_ptr_check_bypassed() -> bool {
    #[cfg(any(feature = "test-mode", feature = "firefox-test"))]
    {
        let cpu = cpu_index();
        KERNEL_DISPATCH_BYPASS[cpu].load(core::sync::atomic::Ordering::Acquire) > 0
    }
    #[cfg(not(any(feature = "test-mode", feature = "firefox-test")))]
    {
        false
    }
}

/// RAII guard that enables [`user_ptr_check_bypassed`] for the current CPU
/// for its lifetime.  Used by in-kernel test wrappers (e.g.
/// [`dispatch_linux_kernel`]) that legitimately pass kernel pointers to
/// the Linux dispatcher.
///
/// Only present in `test-mode` and `firefox-test` builds.
#[cfg(any(feature = "test-mode", feature = "firefox-test"))]
pub struct KernelDispatchGuard {
    cpu: usize,
}

#[cfg(any(feature = "test-mode", feature = "firefox-test"))]
impl KernelDispatchGuard {
    #[inline]
    pub fn new() -> Self {
        let cpu = cpu_index();
        KERNEL_DISPATCH_BYPASS[cpu]
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        Self { cpu }
    }
}

#[cfg(any(feature = "test-mode", feature = "firefox-test"))]
impl Drop for KernelDispatchGuard {
    #[inline]
    fn drop(&mut self) {
        KERNEL_DISPATCH_BYPASS[self.cpu]
            .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    }
}

/// Kernel-test wrapper around [`dispatch_linux`] that bypasses the
/// user-pointer range checks for its duration.  Use this from
/// `test_runner.rs` when driving a syscall with kernel-resident buffers
/// (e.g. `b"/etc/passwd\0".as_ptr()`).
///
/// Real user-mode SYSCALL traffic must NOT use this — it would defeat
/// the CWE-823 validation gates.
///
/// Only present in `test-mode` and `firefox-test` builds.
#[cfg(any(feature = "test-mode", feature = "firefox-test"))]
pub fn dispatch_linux_kernel(num: u64, arg1: u64, arg2: u64, arg3: u64,
                              arg4: u64, arg5: u64, arg6: u64) -> i64 {
    let _g = KernelDispatchGuard::new();
    dispatch_linux(num, arg1, arg2, arg3, arg4, arg5, arg6)
}

/// Open a file from a kernel string literal.  Equivalent to `open(path, flags, 0)`
/// but callable without a user-space address-space context.
pub fn sys_open_test(path: &str, flags: u32) -> i64 {
    // Append a NUL so read_cstring_from_user can find the end.
    // We construct a small stack buffer to avoid heap allocation in the hot path.
    use alloc::vec;
    let mut buf = vec![0u8; path.len() + 1];
    buf[..path.len()].copy_from_slice(path.as_bytes());
    // buf ends with 0 already (vec![] zero-initialises).
    crate::subsys::linux::syscall::sys_open_linux(buf.as_ptr() as u64, flags as u64, 0)
}

/// Write `count` bytes from kernel buffer `buf` to file descriptor `fd_num`.
pub fn sys_write_test(fd_num: usize, buf: *const u8, count: usize) -> i64 {
    crate::subsys::linux::syscall::sys_write_linux(fd_num as u64, buf as u64, count as u64)
}

/// Close file descriptor `fd_num` in the current process.
pub fn sys_close_test(fd_num: usize) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    match crate::vfs::close(pid, fd_num) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// Issue an ioctl on `fd_num`.  arg_ptr may point into kernel memory.
pub fn sys_ioctl_test(fd_num: usize, request: u64, arg_ptr: *mut u8) -> i64 {
    sys_ioctl(fd_num, request, arg_ptr)
}

/// Call the /dev/dsp ioctl handler directly (no fd lookup required).
/// Used by tests when AC97 is absent and a real fd cannot be opened.
pub fn dsp_ioctl_test(request: u64, arg_ptr: *mut u8) -> i64 {
    sys_dsp_ioctl(request, arg_ptr)
}

/// Mount a filesystem at `target`.  Callable from kernel test context.
pub fn sys_mount_test(source: &str, target: &str, fstype: &str, flags: u64) -> i64 {
    crate::vfs::sys_mount(source, target, fstype, flags, "")
}

/// Unmount the filesystem at `target`.  Callable from kernel test context.
pub fn sys_umount_test(target: &str) -> i64 {
    crate::vfs::sys_umount(target, 0)
}

/// Read `count` bytes from file descriptor `fd_num` into kernel buffer `buf`.
pub fn sys_read_test(fd_num: usize, buf: *mut u8, count: usize) -> i64 {
    crate::subsys::linux::syscall::sys_read_linux(fd_num as u64, buf as u64, count as u64)
}
