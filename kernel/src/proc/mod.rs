//! Process & Thread Management Subsystem
//!
//! Manages process control blocks, threads, context switching, and lifecycle.
//! Inspired by the NT Process Manager executive component.
//!
//! # Architecture
//! - Each **Process** owns an address space (CR3) and a collection of threads.
//! - Each **Thread** has its own kernel stack and saved register context.
//! - The scheduler operates on threads, not processes.
//! - PID 0 is the idle process (runs when no other thread is ready).

extern crate alloc;

pub mod ascension_elf;
pub mod elf;
pub mod hello_elf;
pub mod hello_pe;
pub mod hello_win32_pe;
pub mod orbit_elf;
pub mod pe;
pub mod proc_metrics;
#[cfg(feature = "qga")]
pub mod qga_elf;
// `sample` provides the per-TID syscall + Ring-3 RIP tracker.  Writers
// (timer ISR + syscall dispatch) are gated behind `firefox-test`, but
// the module itself is always compiled so kdb introspection ops
// (proc-list / proc / thread-park-audit / rip-trace) can reference its
// types and helpers unconditionally.  The static slot table is ~16 KiB
// BSS — negligible.  Readers behave correctly when no writes have ever
// happened (all slots return None / 0).
pub mod sample;
pub mod stack_walk;
pub mod thread;
pub mod usermode;
pub mod vdso;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Process ID type.
pub type Pid = u64;
/// Thread ID type.
pub type Tid = u64;

/// Process state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Active — has at least one running/ready thread.
    Active,
    /// All threads are blocked or sleeping.
    Waiting,
    /// Terminated, waiting for parent to collect status.
    Zombie,
}

/// Thread state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Ready to run (in the scheduler's run queue).
    Ready,
    /// Currently executing on a CPU.
    Running,
    /// Blocked waiting for I/O, mutex, or event.
    Blocked,
    /// Sleeping for a specified number of ticks.
    Sleeping,
    /// Thread has exited.
    Dead,
}

/// Saved CPU register context for context switching.
///
/// This matches the stack layout used by our context switch assembly.
/// Callee-saved registers only — the System V ABI says
/// rbx, rbp, r12-r15 are callee-saved. We also save rsp and rip.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cr3: u64,
}

impl Default for CpuContext {
    fn default() -> Self {
        Self {
            r15: 0, r14: 0, r13: 0, r12: 0,
            rbx: 0, rbp: 0, rsp: 0,
            rflags: 0x202, // IF flag set
            cr3: 0,
        }
    }
}

/// Thread Control Block (TCB).
/// User-mode callee-saved registers captured at fork() time.
/// The fork child restores these before iretq so that the parent's
/// stack frame (e.g. glibc's __fork epilogue) looks identical in the child.
///
/// `#[repr(C)]` is required because `jump_to_user_mode`'s naked asm reads
/// the six fields via fixed byte offsets (0, 8, 16, 24, 32, 40).  Changing
/// field order without updating the offsets in `usermode.rs` would silently
/// corrupt the fork child's register state.  See POSIX clone(2):
/// "The contents of [callee-saved registers] are unchanged in the child."
/// (https://man7.org/linux/man-pages/man2/clone.2.html)
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ForkUserRegs {
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Parent's R9 at the syscall site.
    ///
    /// musl libc's `__clone` (clone2 ABI, x86-64) stashes the thread entry
    /// function pointer in R9 across the `syscall` instruction:
    ///
    /// ```text
    ///   mov    %rdi,%r11        // r11 = func (caller's rdi)
    ///   mov    %rdx,%rdi        // ...
    ///   mov    %r11,%r9         // r9  = func (preserved across syscall)
    ///   syscall                  // → kernel
    ///   test   %eax,%eax
    ///   jnz    1f
    ///   xor    %ebp,%ebp
    ///   pop    %rdi              // arg from new stack
    ///   call   *%r9              // ← must hold parent's R9 (= func)
    /// ```
    ///
    /// Per POSIX clone(2) and the Linux kernel x86-64 syscall ABI, all
    /// caller-saved registers except RAX/RCX/R11 must survive a syscall
    /// in both the parent and child paths.  Linux's `start_thread` for a
    /// clone child returns from the syscall via IRETQ with the parent's
    /// register snapshot intact (RAX zeroed for the child).  When the
    /// kernel zeros R9 in the child, musl's `call *%r9` jumps to NULL.
    ///
    /// See: <https://git.musl-libc.org/cgit/musl/tree/src/thread/x86_64/clone.s>
    pub r9: u64,
}

pub struct Thread {
    /// Thread ID (globally unique).
    pub tid: Tid,
    /// Owning process ID.
    pub pid: Pid,
    /// Thread state.
    pub state: ThreadState,
    /// Saved CPU context (for context switch).
    ///
    /// Heap-allocated for the same reason as `ctx_rsp_valid`: the picker
    /// captures `&mut cur.context.rsp` as a raw pointer under
    /// `THREAD_TABLE.lock()`, drops the lock, and only later passes that
    /// pointer to `switch_context_asm` which executes `mov [rdi], rsp`
    /// to save the outgoing RSP.  If `THREAD_TABLE: Vec<Thread>` reallocates
    /// in the lock-drop window, an embedded `CpuContext` would dangle and
    /// the save would write into freed memory; the resumed-side read
    /// (`cur.context.rsp` under a fresh lock) would then return the stale
    /// pre-switch value, restoring the wrong stack.  A `Box<CpuContext>`
    /// has a stable heap address for the lifetime of the `Thread`.
    pub context: alloc::boxed::Box<CpuContext>,
    /// Kernel stack base (lowest address; stack grows down).
    pub kernel_stack_base: u64,
    /// Kernel stack size in bytes.
    pub kernel_stack_size: u64,
    /// If sleeping, the tick count at which to wake.
    pub wake_tick: u64,
    /// Thread name (for debugging).
    pub name: [u8; 32],
    /// Exit code.
    pub exit_code: i64,
    /// FPU/SSE state saved by `fxsave` (512 bytes, 16-byte aligned).
    /// `None` means the thread has never used FPU — lazy allocation.
    pub fpu_state: Option<alloc::boxed::Box<FpuState>>,
    /// User-mode entry RIP (for user_mode_bootstrap / fork_child_return).
    pub user_entry_rip: u64,
    /// User-mode entry RSP (for user_mode_bootstrap / fork_child_return).
    pub user_entry_rsp: u64,
    /// Extra registers for clone3 children: RDX = func, R8 = arg.
    /// glibc 2.34+ passes the thread function in RDX and argument in R8
    /// (saved from RCX before the syscall) rather than on the child stack.
    /// Zero for clone2-style threads (they get fn/arg from the stack).
    pub user_entry_rdx: u64,
    pub user_entry_r8:  u64,
    /// Current scheduling priority (0–31; higher = higher priority).
    pub priority: u8,
    /// Base priority to decay back to after a boost.
    pub base_priority: u8,
    /// Thread-local storage base address (loaded into FS_BASE on context switch).
    /// 0 means no TLS area is allocated for this thread.
    pub tls_base: u64,
    /// GS.base for Win32 threads (TEB address).  0 for Linux/native threads.
    /// Loaded into GS_BASE (MSR 0xC000_0101) in `user_mode_bootstrap`.
    pub gs_base: u64,
    /// CPU affinity: if `Some(cpu_id)`, schedule only on that CPU.
    /// `None` means the thread can run on any CPU.
    pub cpu_affinity: Option<u8>,
    /// Last CPU this thread ran on (for cache affinity).
    pub last_cpu: u8,
    /// True until this thread has been scheduled for the first time.
    /// schedule() skips the premature CR3 switch for first-run threads so
    /// that user_mode_bootstrap() can correctly switch to the user CR3
    /// after the initial context-switch lands on the kernel stack.
    pub first_run: bool,
    /// True when context.rsp holds a valid saved kernel RSP.
    ///
    /// Set to `false` in schedule() just before marking the thread Ready,
    /// and set back to `true` inside switch_context_asm right after saving
    /// the RSP.  Other CPUs' schedulers skip threads where this is `false`
    /// to prevent using a stale kernel RSP before the owning CPU has
    /// finished saving the new one (SMP context-switch race guard).
    ///
    /// Heap-allocated via `Box` so the address is stable across `Vec` growth
    /// of `THREAD_TABLE`.  The picker captures `as_ptr()` under the table
    /// lock and the asm `mov byte ptr [rdx], 1` write happens AFTER the lock
    /// is dropped — if another CPU pushes a new thread and the Vec
    /// reallocates in that window, an embedded AtomicBool's address would
    /// dangle.  The `Box` indirection guarantees the address survives any
    /// movement of the surrounding `Thread` value.
    pub ctx_rsp_valid: alloc::boxed::Box<core::sync::atomic::AtomicBool>,
    /// Virtual address to clear (write 0 + futex-wake) on thread exit.
    /// Set by CLONE_CHILD_CLEARTID flag in clone(). 0 = not set.
    pub clear_child_tid: u64,
    /// User callee-saved registers at fork time.  Written by sys_fork_impl
    /// after fork_process() and read by fork_child_entry() to restore the
    /// parent's register state before iretq (so glibc's __fork epilogue,
    /// which reads [rbp-0x38] for the stack canary, uses the correct frame).
    pub fork_user_regs: ForkUserRegs,
    /// vfork completion: TID of the parent thread to wake when this child
    /// calls execve() or exit().  None = not a vfork child.
    /// Linux equivalent: task_struct->vfork_done (completion semaphore).
    pub vfork_parent_tid: Option<u64>,
    /// Linux robust futex list head (set_robust_list / get_robust_list).
    /// Stored as a raw user-space pointer; the kernel only passes it back
    /// on get_robust_list — it never dereferences it in normal operation.
    pub robust_list_head: u64,
    /// Length of the robust list structure (always sizeof(struct robust_list_head)
    /// = 24 bytes in practice, but stored verbatim as passed by glibc).
    pub robust_list_len: usize,
    /// Per `clone(2)`/`vfork(2)`: when a `CLONE_VM|CLONE_VFORK` child is given
    /// a `new_stack` argument that lies inside the parent's user stack frame
    /// (the canonical pattern produced by `posix_spawn(3)` implementations
    /// that allocate the child's stack as a small local buffer of the
    /// parent's `posix_spawn()` frame, e.g. `char stack[1024+PATH_MAX]`), the
    /// kernel substitutes a freshly-allocated isolated stack so that the
    /// child's stack growth cannot clobber the parent's stack region while
    /// the address space is shared.  Linux suspends the parent during
    /// `CLONE_VFORK` so child writes are not raced against, but POSIX
    /// `vfork(2)` still leaves the parent observable to corruption after it
    /// resumes — including any saved stack-protector canary copies that
    /// SSP-instrumented callers (libxul) place on the stack.  This field
    /// records the `(base, length)` of the isolated stack VMA so the
    /// kernel can unmap it from the parent's address space on
    /// `execve(2)` / vfork-child exit.  `None` for every non-vfork
    /// path (initial thread, fork-style clone with a fresh CR3, kernel
    /// threads, AP idle threads).
    pub vfork_isolated_stack: Option<(u64, u64)>,
    /// Per `clone(2)`/`vfork(2)`: companion to `vfork_isolated_stack`.  The
    /// `CLONE_VM|CLONE_VFORK` child path provisions a minimal per-vfork-child
    /// "thread-control block" page so the child can read its `%fs:0`-relative
    /// state before `execve(2)` installs a fresh TCB.  Per the System V x86_64
    /// ABI §3.4.2 (Thread-Local Storage / Variant II) and the ELF gABI §3.5,
    /// libc TLS reads on x86_64 begin with `mov %fs:0,%REG` to materialise
    /// the TCB address; with `tls_base == 0` that fault would block the
    /// musl `posix_spawn(3)` child helper at its first cancellable libc
    /// syscall (`close(2)`).  The provisioned page is zero-initialised so
    /// the byte at `%fs:0x28` is 0 (not the parent's stack-protector canary)
    /// — preserving the canary-isolation invariant — and pre-populates only
    /// the self-pointer at offset 0 plus the `canceldisable` byte at offset
    /// 64 (POSIX `pthread_setcancelstate(3)` PTHREAD_CANCEL_DISABLE).  This
    /// field records `(base, length)` so the kernel can unmap it at
    /// `execve(2)` / vfork-child exit.  `None` for every non-vfork path.
    pub vfork_isolated_tls: Option<(u64, u64)>,
}

impl Thread {
    /// True if this thread may be reaped (removed from THREAD_TABLE and its
    /// kernel stack freed).  Excludes idle threads (tid=0) and AP idle threads
    /// (tid < 0x1000 by convention) which are permanent fixtures.
    pub fn is_reapable(&self) -> bool {
        self.state == ThreadState::Dead && self.tid != 0 && self.tid < 0x1000
    }
}

// ── Priority Constants (NT-style) ────────────────────────────────────

/// Idle thread priority.
pub const PRIORITY_IDLE: u8 = 0;
/// Lowest dynamic priority.
pub const PRIORITY_LOWEST: u8 = 1;
/// Below-normal priority.
pub const PRIORITY_BELOW_NORMAL: u8 = 6;
/// Normal thread priority (default for user threads).
pub const PRIORITY_NORMAL: u8 = 8;
/// Above-normal priority.
pub const PRIORITY_ABOVE_NORMAL: u8 = 10;
/// High priority (kernel worker threads).
pub const PRIORITY_HIGH: u8 = 13;
/// Time-critical (realtime base).
pub const PRIORITY_TIME_CRITICAL: u8 = 15;
/// Maximum priority.
pub const PRIORITY_MAX: u8 = 31;
/// Priority boost given when a wait is satisfied.
pub const PRIORITY_BOOST_WAIT: u8 = 2;
/// Priority boost given on I/O completion.
pub const PRIORITY_BOOST_IO: u8 = 1;

/// 512-byte FXSAVE area, 16-byte aligned.
#[repr(C, align(16))]
pub struct FpuState {
    pub data: [u8; 512],
}

impl FpuState {
    pub fn new_zeroed() -> Self {
        Self { data: [0u8; 512] }
    }
}

/// Process Control Block (PCB).
pub struct Process {
    /// Process ID.
    pub pid: Pid,
    /// Parent process ID.
    pub parent_pid: Pid,
    /// Process name.
    pub name: [u8; 64],
    /// Process state.
    pub state: ProcessState,
    /// Page table root (CR3 physical address).
    pub cr3: u64,
    /// Thread IDs belonging to this process.
    pub threads: Vec<Tid>,
    /// Exit code.
    pub exit_code: i32,
    /// Open file descriptors (index = fd number).
    pub file_descriptors: Vec<Option<crate::vfs::FileDescriptor>>,
    /// Current working directory path.
    pub cwd: alloc::string::String,
    /// Real user ID.
    pub uid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective user ID (for setuid binaries).
    pub euid: u32,
    /// Effective group ID (for setgid binaries).
    pub egid: u32,
    /// Process group ID (for job control and kill(-pgid)).
    pub pgid: u32,
    /// Session ID.
    pub sid: u32,
    /// If true, exec() cannot gain new privileges (PR_SET_NO_NEW_PRIVS).
    pub no_new_privs: bool,
    /// Linux capability permitted set (bitmask; all bits set = root).
    pub cap_permitted: u64,
    /// Linux capability effective set.
    pub cap_effective: u64,
    /// Per-resource soft limits (indices = Linux RLIMIT_* constants).
    pub rlimits_soft: [u64; 16],
    /// Supplementary group IDs.
    pub supplementary_groups: Vec<u32>,
    /// File creation mask (umask).
    pub umask: u32,
    /// Virtual memory address space.
    pub vm_space: Option<crate::mm::vma::VmSpace>,
    /// Signal handling state.
    pub signal_state: Option<crate::signal::SignalState>,
    /// Whether this process uses Linux x86_64 syscall ABI numbers.
    /// When true, the syscall dispatcher routes via the Linux number table.
    pub linux_abi: bool,
    /// NT-style per-process handle table.
    pub handle_table: Option<crate::ob::handle::HandleTable>,
    /// Environment subsystem personality for this process.
    pub subsystem: crate::win32::SubsystemType,
    /// NT-style access token ID (from the token registry).
    pub token_id: Option<u64>,
    /// Path of the main executable (for /proc/self/exe via readlink).
    pub exe_path: Option<alloc::string::String>,
    /// Per-process epoll instances.  Keyed by epfd.
    pub epoll_sets: alloc::vec::Vec<crate::ipc::epoll::EpollInstance>,
    /// Auxiliary vector pairs stored at exec time.  Same values placed on the
    /// initial stack; exposed via /proc/self/auxv as raw (type, value) u64 pairs.
    /// Empty for kernel threads and the idle process.
    pub auxv: Vec<(u64, u64)>,
    /// Environment strings stored at exec time; exposed via /proc/self/environ
    /// as NUL-separated bytes.  Empty for kernel threads.
    pub envp: Vec<alloc::string::String>,
    /// POSIX alarm()/setitimer(ITIMER_REAL) deadline in PIT ticks.
    /// 0 means no alarm is set.  Checked at dispatch entry — SIGALRM is
    /// delivered lazily (on the next syscall after expiry) to avoid acquiring
    /// PROCESS_TABLE inside the timer ISR.
    pub alarm_deadline_ticks: u64,
    /// ITIMER_REAL interval in ticks (0 = one-shot).  Non-zero means the alarm
    /// is automatically re-armed after each expiry.
    pub alarm_interval_ticks: u64,
    /// Parent-death signal — `prctl(PR_SET_PDEATHSIG, sig)` per `prctl(2)`.
    /// When the parent of this process exits (or its parent thread dies, in
    /// the Linux semantics), this signal is delivered to the child.  0 = no
    /// signal (the default, and the post-exec reset value per the man page).
    /// Stored as a byte so it fits the signal number range 1..=64.
    pub pdeath_signal: u8,
}

/// Next PID counter.
static NEXT_PID: AtomicU64 = AtomicU64::new(1);
/// Next TID counter.
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

// ── Per-PID signal-pending hint table ──────────────────────────────────────
//
// A flat array of AtomicU64 — one entry per PID — tracking the raw `pending`
// bitmask for that process.  The signal_check_on_syscall_return() fast path
// reads this without acquiring PROCESS_TABLE, short-circuiting the lock on the
// common case of no pending signals.
//
// Invariant: hint[pid] == 0  ⟹  no signals are pending for that process.
// A non-zero hint may be a false positive (e.g. signal was blocked but pending
// stays set) — the slow path (under PROCESS_TABLE lock) resolves ambiguity.
// A false negative (hint == 0 but a signal IS pending) is impossible given
// Release/Acquire ordering on every write/read pair.

/// Upper bound on PIDs covered by the hint table.
pub const SIGNAL_HINT_TABLE_SIZE: usize = 256;

static SIGNAL_PENDING_HINT: [AtomicU64; SIGNAL_HINT_TABLE_SIZE] =
    [const { AtomicU64::new(0) }; SIGNAL_HINT_TABLE_SIZE];

/// Update the signal-pending hint for `pid`.
/// Must be called (with Release ordering) whenever `SignalState::pending` changes.
#[inline]
pub fn signal_pending_hint_set(pid: Pid, pending: u64) {
    if (pid as usize) < SIGNAL_HINT_TABLE_SIZE {
        SIGNAL_PENDING_HINT[pid as usize].store(pending, Ordering::Release);
    }
}

/// Read the signal-pending hint for `pid` (Acquire ordering).
/// Returns 1 (conservative: forces slow path) for out-of-range PIDs.
#[inline]
pub fn signal_pending_hint_get(pid: Pid) -> u64 {
    if (pid as usize) < SIGNAL_HINT_TABLE_SIZE {
        SIGNAL_PENDING_HINT[pid as usize].load(Ordering::Acquire)
    } else {
        1 // out-of-range: conservatively force the slow path
    }
}

/// Process table.
pub static PROCESS_TABLE: Mutex<Vec<Process>> = Mutex::new(Vec::new());
/// Thread table.
pub static THREAD_TABLE: Mutex<Vec<Thread>> = Mutex::new(Vec::new());

/// Bounded-spin acquire of `THREAD_TABLE` with a loud panic on exhaustion.
///
/// Used (under `firefox-test`) at hot read-only call sites that previously
/// called `THREAD_TABLE.lock()` unconditionally.  A `MutexGuard` leaked from
/// a prior panic (kernel builds with `panic = "abort"`) would otherwise turn
/// every subsequent acquirer into a silent infinite spin — both vCPUs idle
/// at the spin loop with no diagnostic output.  Converting the call to
/// `thread_table_try_lock_or_panic` turns that silent hang into an immediate
/// panic identifying the *next* contender, which is enough signal to triangulate
/// the leaking owner across runs.
///
/// `site` is a static string (e.g. `"proc::current_pid"`) included in the panic
/// message.  `max_spins` bounds the wait.  Each iteration is a `PAUSE` hint
/// (~5–25 CPU cycles, ~2–10 ns on modern silicon under KVM), so the default
/// `THREAD_TABLE_DIAG_SPINS` is roughly a 50–100 ms upper bound under KVM and
/// several seconds under TCG before declaring the lock leaked.  A smaller
/// bound (10_000 spins ≈ a few µs under KVM) caused false-positive panics
/// during Firefox bringup once the cmdline-handler chain dispatched and many
/// concurrent worker threads competed with the timer-ISR scheduler picker for
/// `THREAD_TABLE`.  The bound exists to surface true deadlocks, not raw
/// contention.
#[cfg(feature = "firefox-test")]
pub const THREAD_TABLE_DIAG_SPINS: u32 = 10_000_000;

#[cfg(feature = "firefox-test")]
#[inline]
pub fn thread_table_try_lock_or_panic(
    site: &'static str,
    max_spins: u32,
) -> spin::MutexGuard<'static, Vec<Thread>> {
    for _ in 0..max_spins {
        if let Some(g) = THREAD_TABLE.try_lock() {
            return g;
        }
        core::hint::spin_loop();
    }
    panic!(
        "THREAD_TABLE deadlocked at {}: {} spins exhausted (likely lock leak from prior panic; build is panic=abort so MutexGuard::drop never runs)",
        site, max_spins
    );
}

/// Currently running thread ID — per-CPU, indexed by APIC ID.
/// With SMP, each CPU tracks its own running thread.
static PER_CPU_CURRENT_TID: [AtomicU64; crate::arch::x86_64::apic::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::apic::MAX_CPUS];

/// Currently running process PID — per-CPU, kept in sync with `PER_CPU_CURRENT_TID`.
///
/// Maintained as a parallel atomic so interrupt-context code (notably the
/// page-fault handler) can read the current PID without acquiring
/// `THREAD_TABLE`.  Acquiring that lock from the PF handler is unsafe: a
/// kernel-mode #PF can fire while a syscall on the same CPU already holds
/// THREAD_TABLE, producing a non-recoverable same-CPU re-entrant deadlock on
/// the non-reentrant `spin::Mutex`.  Reading this atomic is wait-free.
///
/// Update discipline: every `set_current_tid` call site that knows the PID
/// must call `set_current_pid` immediately afterwards.  The two stores are
/// independent atomics so there is a brief window during context switches
/// where they disagree; readers in interrupt context must therefore tolerate
/// a stale-but-self-consistent (tid, pid) pair — which is exactly the same
/// invariant `recover_current_tid` already documents.
static PER_CPU_CURRENT_PID: [AtomicU64; crate::arch::x86_64::apic::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::apic::MAX_CPUS];

/// Kernel stack size per thread: 256 KiB (64 pages).
/// Firefox's deep call chains (VFS → FAT32 → ATA + socket → DNS → NSS + signal
/// delivery + serial formatting) can exceed 128 KiB.  256 KiB provides headroom
/// while we audit stack-hungry code paths for optimization.
const KERNEL_STACK_PAGES: usize = 64;
const KERNEL_STACK_SIZE: u64 = (KERNEL_STACK_PAGES * 4096) as u64;
/// Public alias for sched dead-stack cache to compare page counts.
pub const KERNEL_STACK_PAGES_PUB: usize = KERNEL_STACK_PAGES;

/// Allocate a kernel stack, checking the dead-stack cache first (NT pattern).
/// Returns `(stack_base_virt, stack_top_virt)`.
///
/// Allocation order under PMM fragmentation:
///   1. dead-stack cache hit (always 256 KiB)
///   2. contiguous `pmm::alloc_pages(64)` — 256 KiB normal path
///   3. tiered emergency fallback: 16 KiB → 8 KiB → 4 KiB (each contiguous)
///
/// The actual span is always `stack_top - stack_base`.  Callers MUST stamp
/// `Thread.kernel_stack_size` with that computed span (NOT the compile-time
/// `KERNEL_STACK_SIZE` constant) so that bound checks and stack-depth
/// accounting in `sched::schedule` and the syscall-trace path stay honest
/// for every tier.  Stamping the constant unconditionally produced
/// STACK_CANARY_CORRUPT on emergency threads — see PR #391 diagnostic and
/// the kstack-honesty fix in PR #392.
fn alloc_kernel_stack() -> Option<(u64, u64)> {
    // Try the dead-stack cache first — avoids PMM allocator overhead.
    // The cache returns the honest byte-extent stamped at push time
    // (see `sched::pop_dead_stack`).  The call-site gate in
    // `reap_dead_threads_sched` refuses any non-`KERNEL_STACK_SIZE`
    // entry, so `cached_size` is `KERNEL_STACK_SIZE` in production —
    // but using the returned size (rather than the constant) keeps the
    // pair `(base, top)` exactly bracketing the cached allocation, so
    // future loosening of the cache gate cannot silently extend
    // `stack_top` past the real allocation boundary.
    if let Some((cached_base, cached_size)) = crate::sched::pop_dead_stack() {
        write_stack_canary(cached_base);
        return Some((cached_base, cached_base + cached_size));
    }
    // Try contiguous allocation first (fast path).
    if let Some(phys_stack) = crate::mm::pmm::alloc_pages(KERNEL_STACK_PAGES) {
        let stack_base = KERNEL_VIRT_OFFSET + phys_stack;
        let stack_top = stack_base + KERNEL_STACK_SIZE;
        write_stack_canary(stack_base);
        return Some((stack_base, stack_top));
    }
    // Contiguous 256 KiB allocation failed (PMM fragmented by page cache).
    // Walk down progressively smaller contiguous tiers before giving up:
    // 16 KiB (4 pages) → 8 KiB (2 pages) → 4 KiB (1 page).  16 KiB matches
    // x86_64 SysV ABI §3.4.1 minimum stack frame budgets observed in practice
    // for short syscall paths and pthread_create(3) rationale (16 KiB is the
    // smallest size POSIX requires implementations to honour when the caller
    // does not specify PTHREAD_STACK_MIN explicitly), giving comfortable
    // headroom over the 4 KiB single-page fallback that PR #392 made honest.
    //
    // Empirical motivation: the H1 STACK_CANARY_CORRUPT trial in PR #394 showed
    // brk() peak push-depth on 4 KiB stacks reaching RSP = (base + small),
    // where a subsequent `push %reg` writes (RSP - 8) = stack_base and zeroes
    // the canary.  Widening to 16 KiB / 8 KiB makes that overflow materially
    // less likely without requiring a full vmalloc-style remap (still tracked
    // separately).  The bugcheck still fires if any tier overflows; the larger
    // tier is the mitigation, not the cure.
    //
    // Behavioural contract: if every wider tier fails, fall through to the
    // 4 KiB tier and keep it.  Refusing to spawn a thread is worse than the
    // residual canary risk (the diagnostic still attributes the failure).
    const SMALL_KSTACK_TIERS: &[(usize, u64)] = &[
        (4, 16 * 1024), // tier 4: 4 pages × 4 KiB = 16 KiB
        (2,  8 * 1024), // tier 2: 2 pages × 4 KiB =  8 KiB
        (1,  4 * 1024), // tier 1: 1 page  × 4 KiB =  4 KiB (legacy emergency)
    ];
    for &(pages, span_bytes) in SMALL_KSTACK_TIERS {
        let phys_opt = if pages == 1 {
            crate::mm::pmm::alloc_page()
        } else {
            crate::mm::pmm::alloc_pages(pages)
        };
        let Some(phys) = phys_opt else { continue };
        let stack_base = KERNEL_VIRT_OFFSET + phys;
        let stack_top = stack_base + span_bytes;
        write_stack_canary(stack_base);
        // Record in the emergency-stack ring so the canary-corruption
        // diagnostic in `sched::schedule` retains attribution for every
        // sub-256-KiB tier (not just 4 KiB).  `was_emergency_kstack` is the
        // single channel readers use; one ring covers every short tier.
        record_emergency_kstack(stack_base);
        crate::serial_println!(
            "[KSTACK/TIER] base={:#x} size={}K tier={} (PMM fragmented)",
            stack_base, span_bytes / 1024, pages,
        );
        if pages == 1 {
            // Preserve the legacy attribution line for the 4 KiB tier so
            // existing log-grep tooling and the PR #391 diagnostic chain
            // keep firing on the narrowest fallback specifically.
            crate::serial_println!(
                "[KSTACK/EMERGENCY] base={:#x} size=4K (PMM fragmented)",
                stack_base,
            );
        }
        return Some((stack_base, stack_top));
    }
    None
}

/// Emit a one-shot diagnostic line if `stack_base` was just handed out from
/// any of the small-stack emergency-fallback tiers (16 KiB / 8 KiB / 4 KiB).
/// Called by every `alloc_kernel_stack` consumer immediately after stamping
/// the Thread, so the operator can see which (pid, tid) is running on a
/// constrained stack and at which tier.  Per Intel SDM Vol 3A §6.2 (stack-
/// fault exceptions) and the x86_64 SysV ABI §3.4.1 (stack growth
/// direction), kernel paths on any short stack must keep total frame depth
/// ≤ `span` or risk overwriting the bottom-of-stack canary.
#[inline]
fn note_if_emergency_kstack(pid: Pid, tid: Tid, stack_base: u64, span: u64) {
    if span < KERNEL_STACK_SIZE && was_emergency_kstack(stack_base) {
        crate::serial_println!(
            "[KSTACK/EMERGENCY-THREAD] tid={} pid={} base={:#x} size={}K \
             — kernel paths must keep depth <= {}K",
            tid, pid, stack_base, span / 1024, span / 1024,
        );
    }
}

/// Magic value written at the bottom of every kernel stack for overflow
/// detection.  Matches Linux's STACK_END_MAGIC (0x57AC6E9D), extended to
/// 64 bits.  Checked in schedule() and exit_thread().
pub const STACK_END_MAGIC: u64 = 0x5741_436B_5374_4B21; // "WACkStK!"

/// Write the stack canary at the bottom of a kernel stack.
#[inline]
pub fn write_stack_canary(stack_base: u64) {
    if stack_base >= KERNEL_VIRT_OFFSET {
        unsafe { core::ptr::write_volatile(stack_base as *mut u64, STACK_END_MAGIC); }
    }
}

/// Check the stack canary. Returns true if intact, false if corrupted.
#[inline]
pub fn check_stack_canary(stack_base: u64) -> bool {
    if stack_base < KERNEL_VIRT_OFFSET || stack_base == 0 { return true; } // skip for idle/untracked stacks
    unsafe { core::ptr::read_volatile(stack_base as *const u64) == STACK_END_MAGIC }
}

/// Read the live u64 stored at the kernel-stack canary slot.  Used by the
/// canary-corruption diagnostic in `sched::schedule` to emit the observed
/// bytes when the check fails — no panic path, so we can format/print.
#[inline]
pub fn read_stack_canary(stack_base: u64) -> u64 {
    if stack_base < KERNEL_VIRT_OFFSET || stack_base == 0 { return 0; }
    unsafe { core::ptr::read_volatile(stack_base as *const u64) }
}

/// Read another u64 from the canary region (offset in bytes from base).
/// Returns 0 if the address would be outside the higher-half kernel map.
///
/// `byte_offset` is asserted to be strictly less than one page (0x1000),
/// so the helper can never read more than 4 KiB above `stack_base`.  The
/// current call sites pass 8 / 16 / 24, which satisfy this trivially; the
/// assert guards against future misuse (e.g. someone passing an arbitrary
/// frame-pointer delta and accidentally walking off the canary region).
#[inline]
pub fn read_stack_word_at(stack_base: u64, byte_offset: u64) -> u64 {
    debug_assert!(byte_offset < 0x1000,
        "read_stack_word_at: byte_offset {:#x} exceeds one page", byte_offset);
    let addr = stack_base.wrapping_add(byte_offset);
    if addr < KERNEL_VIRT_OFFSET { return 0; }
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

/// Read the current CPU's RSP via inline assembly.  Safe to call from any
/// kernel context; observes only the live register.  Used by syscall-trace
/// and the canary diagnostic to compute stack depth (top - rsp).
#[inline(always)]
pub fn current_kernel_rsp_live() -> u64 {
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    rsp
}

// ── Emergency-stack-fallback recorder ────────────────────────────────────
//
// When `alloc_kernel_stack` falls back from the normal 256 KiB path to any
// of the smaller emergency tiers (16 KiB / 8 KiB / 4 KiB — see
// `SMALL_KSTACK_TIERS`), callers stamp the honest span into
// `Thread.kernel_stack_size` (PR #392, kstack-size honesty).  That span
// alone, however, doesn't say *why* a thread is on a short stack — a
// future allocator might return 16 KiB for reasons other than emergency
// fallback.  This diagnostic-only ring complements the now-honest in-
// Thread span by attributing the emergency origin even after a stack base
// is later reused: if the same base reappears within the ring's 16-entry
// window, the canary-corruption diagnostic in `sched::schedule` can still
// answer "was this thread on an emergency-tier stack?" rather than
// "merely on a short stack".  All sub-256-KiB tiers are recorded; the
// `was_emergency_4k` label on the `[KSTACK/CANARY-FAIL]` line is retained
// for backward-compat but now means "any emergency-tier base", with the
// observed `size` field disambiguating which tier.
//
// Lock-free SPSC-ish ring; the writer is the alloc path (one writer at a
// time under PMM_LOCK), the readers are diagnostic emitters that tolerate
// torn reads (worst-case: false negative).
const EMERGENCY_KSTACK_RING_LEN: usize = 16;
static EMERGENCY_KSTACK_RING: [AtomicU64; EMERGENCY_KSTACK_RING_LEN] =
    [const { AtomicU64::new(0) }; EMERGENCY_KSTACK_RING_LEN];
static EMERGENCY_KSTACK_HEAD: AtomicU64 = AtomicU64::new(0);

/// Record that `stack_base` was just handed out from the 4 KiB
/// emergency-fallback path.  Called from `alloc_kernel_stack`.
///
/// Visibility is `pub(crate)` — the single legitimate caller is the
/// fallback arm of `alloc_kernel_stack` within this module; the
/// readers (`was_emergency_kstack`) are also crate-local.  External
/// callers have no legitimate need to mark arbitrary bases as
/// "emergency-fallback origins".
pub(crate) fn record_emergency_kstack(stack_base: u64) {
    let slot = (EMERGENCY_KSTACK_HEAD.fetch_add(1, Ordering::Relaxed)
        as usize) % EMERGENCY_KSTACK_RING_LEN;
    EMERGENCY_KSTACK_RING[slot].store(stack_base, Ordering::Relaxed);
}

/// Return true iff `stack_base` matches a recently-recorded emergency
/// 4 KiB fallback base.  Best-effort: the ring holds the last 16 entries.
pub fn was_emergency_kstack(stack_base: u64) -> bool {
    if stack_base == 0 { return false; }
    for i in 0..EMERGENCY_KSTACK_RING_LEN {
        if EMERGENCY_KSTACK_RING[i].load(Ordering::Relaxed) == stack_base {
            return true;
        }
    }
    false
}

/// Notification hook called by every thread-creation site immediately
/// after the new `Thread` is published to `THREAD_TABLE`, carrying the
/// just-allocated kernel stack base, total span, owning pid, and tid.
/// Currently used only by the D20 kernel-stack canary watchpoint
/// diagnostic (`subsys/linux/d20_kstack_canary_watch.rs`) to arm a DR
/// write-only breakpoint on `[stack_base, stack_base + 8)` for the
/// post-#396/#397 STACK_CANARY_CORRUPT bugcheck victim profile.
///
/// Off-feature builds compile this to a no-op — zero overhead and
/// byte-identical artefact.  Default builds (no `d20-kstack-canary-watch`)
/// elide the call entirely.
///
/// Safe to call with `stack_base == 0` / non-higher-half (the D20
/// implementation gates on the target pid before doing anything).  Per
/// Intel SDM Vol. 3B §17.2.4 the watch is on the kernel direct-map
/// linear address; `stack_base = KERNEL_VIRT_OFFSET + phys` already
/// satisfies the natural-alignment requirement (LEN=8 wants 8-byte
/// alignment, and `phys` is page-aligned from PMM).
#[inline]
pub fn note_kstack_alloc(pid: Pid, tid: Tid, stack_base: u64, span: u64) {
    #[cfg(feature = "d20-kstack-canary-watch")]
    crate::subsys::linux::d20_kstack_canary_watch::note_kstack_alloc(
        pid as u64, tid as u64, stack_base, span,
    );
    // Off-feature: zero-cost no-op.
    let _ = (pid, tid, stack_base, span);
}

/// Higher-half virtual offset.  The bootloader identity-maps the first 4 GiB
/// of RAM at both virtual 0x0 and 0xFFFF_8000_0000_0000.  Kernel stacks are
/// allocated from PMM (physical addresses) but accessed via the higher-half
/// map so they remain valid after CR3 switches to user page tables (which
/// shallow-clone PML4[256-511] from the kernel).
pub const KERNEL_VIRT_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Default per-process soft rlimit values (mirrors `sys_getrlimit` defaults).
fn default_rlimits() -> [u64; 16] {
    const INF: u64 = u64::MAX;
    [INF, INF, INF, 8*1024*1024, INF, INF, 1024, 1024, INF, INF, INF, 0, INF, 0, 0, INF]
}

/// Initialize the process manager.
///
/// Allocates a proper higher-half kernel stack for the BSP idle thread (TID 0)
/// and switches to it.  The UEFI bootstrap stack is at a physical address in
/// the identity-mapped region (PML4[0]).  When schedule() later switches CR3
/// to a user process's page table, PML4[0] is replaced with user mappings and
/// the bootstrap stack becomes unmapped — any stack access causes a double
/// fault.  By giving TID 0 a higher-half kernel stack (PML4[256-511], shared
/// with all user page tables), this crash is prevented.
pub fn init() {
    // Allocate a proper higher-half kernel stack for TID 0 (BSP idle thread).
    // This replaces the UEFI bootstrap stack (which is identity-mapped only)
    // with a stack that survives CR3 switches to user page tables.
    let idle_phys_stack = crate::mm::pmm::alloc_pages(KERNEL_STACK_PAGES)
        .expect("Failed to allocate BSP idle kernel stack");
    let idle_stack_base = KERNEL_VIRT_OFFSET + idle_phys_stack;
    let idle_stack_top = idle_stack_base + KERNEL_STACK_SIZE;
    write_stack_canary(idle_stack_base);

    // Create the idle process (PID 0) and its main thread (TID 0).
    let idle_proc = Process {
        pid: 0,
        parent_pid: 0,
        name: {
            let mut name = [0u8; 64];
            name[..4].copy_from_slice(b"idle");
            name
        },
        state: ProcessState::Active,
        cr3: crate::mm::vmm::get_cr3(),
        threads: Vec::from([0u64]),
        exit_code: 0,
        file_descriptors: Vec::new(),
        cwd: alloc::string::String::from("/"),
        uid: 0,
        gid: 0,
        euid: 0,
        egid: 0,
        pgid: 0,
        sid: 0,
        no_new_privs: false,
        cap_permitted: !0u64,
        cap_effective: !0u64,
        rlimits_soft: default_rlimits(),
        supplementary_groups: Vec::new(),
        umask: 0o022,
        vm_space: None,
        signal_state: None,
        linux_abi: false,
        handle_table: None,
        subsystem: crate::win32::SubsystemType::Native,
        token_id: None,
        exe_path: None,
        epoll_sets: alloc::vec::Vec::new(),
        auxv: Vec::new(),
        envp: Vec::new(),
        alarm_deadline_ticks: 0,
        alarm_interval_ticks: 0,
        pdeath_signal: 0,
    };

    let idle_thread = Thread {
        tid: 0,
        pid: 0,
        state: ThreadState::Running,
        context: alloc::boxed::Box::new(CpuContext {
            rsp: 0,
            cr3: crate::mm::vmm::get_cr3(),
            ..CpuContext::default()
        }),
        kernel_stack_base: idle_stack_base,
        kernel_stack_size: KERNEL_STACK_SIZE,
        wake_tick: u64::MAX,
        name: {
            let mut name = [0u8; 32];
            name[..11].copy_from_slice(b"idle_thread");
            name
        },
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: 0,
        user_entry_rsp: 0,
        user_entry_rdx: 0,
        user_entry_r8:  0,
        priority: PRIORITY_IDLE,
        base_priority: PRIORITY_IDLE,
        tls_base: 0,
        // Pin the BSP idle thread to CPU 0.  This prevents AP schedulers from
        // stealing it while context.rsp is still 0 (before the first
        // switch_context save), which would load RSP=0 and triple-fault.
        cpu_affinity: Some(0),
        last_cpu: 0,
        first_run: false,
        ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
        clear_child_tid: 0,
        fork_user_regs: ForkUserRegs::default(),
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
        vfork_isolated_stack: None,
        vfork_isolated_tls: None,
    };

    PROCESS_TABLE.lock().push(idle_proc);
    THREAD_TABLE.lock().push(idle_thread);
    proc_metrics::register(0);
    set_current_tid(0);
    set_current_pid(0);

    crate::serial_println!(
        "[PROC] Process manager initialized (idle PID 0, TID 0, kstack={:#x}–{:#x})",
        idle_stack_base, idle_stack_top
    );

    // NOTE: We do NOT switch the BSP stack here.  The UEFI bootstrap stack
    // remains active for kernel_main.  schedule()'s Phase 1 CR3 switch to
    // kernel_cr3 ensures the identity map stays active for the bootstrap
    // stack during context switches.  TID 0's kernel_stack_base/size are
    // used for TSS.RSP[0] and per_cpu.kernel_rsp by the scheduler.

    // Initialise the global vDSO + vvar pages.  Must run after PMM and
    // refcount, before any user process is loaded — see
    // `kernel/src/proc/vdso.rs` and vdso(7).
    vdso::init();
}

use crate::arch::x86_64::apic::cpu_index;

/// Get the currently running thread's TID (per-CPU).
pub fn current_tid() -> Tid {
    PER_CPU_CURRENT_TID[cpu_index()].load(Ordering::Relaxed)
}

/// Set the currently running thread's TID (per-CPU).
pub fn set_current_tid(tid: Tid) {
    PER_CPU_CURRENT_TID[cpu_index()].store(tid, Ordering::Relaxed);
}

/// Set the currently running process's PID (per-CPU).
///
/// Must be called from every `set_current_tid` call site that knows the
/// owning PID, so the PF handler's lockless `current_pid_lockless()` lookup
/// stays in sync with the THREAD_TABLE-derived authoritative answer.
pub fn set_current_pid(pid: Pid) {
    PER_CPU_CURRENT_PID[cpu_index()].store(pid, Ordering::Relaxed);
}

/// Read the currently running process's PID without taking any lock.
///
/// Designed for interrupt-context callers (page-fault handler, NMI, etc.)
/// where acquiring `THREAD_TABLE` could deadlock — a kernel-mode #PF can
/// fire while a syscall on the same CPU already holds the lock, and
/// `spin::Mutex` is not reentrant.
///
/// Returns 0 if no user thread is currently scheduled (idle thread, AP
/// startup before first context switch).  Callers that hit a 0 result
/// should treat the fault as unresolvable rather than retry-with-lock —
/// the cost of dropping the resolution attempt is a SIGSEGV at worst,
/// far better than a hard hang.
#[inline]
pub fn current_pid_lockless() -> Pid {
    PER_CPU_CURRENT_PID[cpu_index()].load(Ordering::Relaxed)
}

/// Get the currently running process's PID.
pub fn current_pid() -> Pid {
    let tid = current_tid();
    #[cfg(feature = "firefox-test")]
    let threads = thread_table_try_lock_or_panic(
        "proc::current_pid", THREAD_TABLE_DIAG_SPINS);
    #[cfg(not(feature = "firefox-test"))]
    let threads = THREAD_TABLE.lock();
    threads.iter().find(|t| t.tid == tid).map(|t| t.pid).unwrap_or(0)
}

/// Resolve the effective credentials (pid, uid, gid) of the currently
/// running process for use by syscall implementations that must record the
/// caller's identity (e.g. AF_UNIX SO_PEERCRED capture per `unix(7)`).
///
/// Returns `(pid, euid, egid)` — the effective IDs, matching Linux's
/// per-FD ucred capture which uses the credentials in effect at the time
/// of the syscall, not the real IDs.  Per `unix(7)` SO_PEERCRED and
/// POSIX.1-2017 §getsockopt.
///
/// If the PID is not in PROCESS_TABLE (kernel idle thread or transient
/// race with process teardown), returns `(0, 0, 0)` — a structurally
/// detectable "no credentials" sentinel that authorisers can compare
/// against a non-zero allowlist.
pub fn current_creds_lockless() -> (Pid, u32, u32) {
    let pid = current_pid_lockless();
    let procs = PROCESS_TABLE.lock();
    if let Some(p) = procs.iter().find(|p| p.pid == pid) {
        (pid, p.euid, p.egid)
    } else {
        (pid, 0, 0)
    }
}

/// Recover the current TID even when `PER_CPU_CURRENT_TID` is transiently 0.
///
/// `PER_CPU_CURRENT_TID[cpu]` can be 0 when the timer ISR preempts the idle
/// thread's brief window between calling `set_current_tid(new_tid)` and the
/// new thread's first instruction.  In that window, kernel-mode faults and
/// syscalls see tid=0 (idle) even though the kernel stack belongs to a real
/// user thread.  This slow-path fallback matches the kernel stack top
/// (`get_current_kernel_rsp()`) against every thread's stack range to find
/// the true owner.
///
/// **MUST NOT be called from interrupt context** — this function takes
/// `THREAD_TABLE.lock()` on the slow path.  A kernel-mode #PF or timer ISR
/// firing on a CPU that already holds `THREAD_TABLE` would re-enter the
/// non-reentrant `spin::Mutex` and deadlock the CPU permanently (see #55).
/// Interrupt handlers must use `current_tid()` (lock-free fast path) and
/// accept the transient-zero window, or use `current_pid_lockless()` which
/// is maintained per-CPU specifically for ISR consumption.
pub fn recover_current_tid() -> Tid {
    let tid = current_tid();
    if tid != 0 { return tid; }
    let kstack_top = crate::syscall::get_current_kernel_rsp();
    if kstack_top == 0 { return 0; }
    #[cfg(feature = "firefox-test")]
    let threads = thread_table_try_lock_or_panic(
        "proc::recover_current_tid", THREAD_TABLE_DIAG_SPINS);
    #[cfg(not(feature = "firefox-test"))]
    let threads = THREAD_TABLE.lock();
    threads.iter()
        .find(|t| {
            t.tid != 0
                && t.kernel_stack_base > 0
                && t.kernel_stack_base + t.kernel_stack_size == kstack_top
        })
        .map(|t| t.tid)
        .unwrap_or(0)
}

/// Create a new kernel process with a single thread.
/// Create a kernel process with the main thread initially Blocked.
/// The caller must mark the thread Ready after patching user-mode entry info.
pub fn create_kernel_process_suspended(name: &str, entry_point: u64) -> Pid {
    create_kernel_process_inner(name, entry_point, ThreadState::Blocked)
}

pub fn create_kernel_process(name: &str, entry_point: u64) -> Pid {
    create_kernel_process_inner(name, entry_point, ThreadState::Ready)
}

fn create_kernel_process_inner(name: &str, entry_point: u64, initial_state: ThreadState) -> Pid {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    // Allocate kernel stack (tries dead-stack cache first, then PMM).
    let (stack_base, stack_top) = alloc_kernel_stack()
        .expect("Failed to allocate kernel stack");
    // Stamp the REAL span on the Thread — not KERNEL_STACK_SIZE — so the
    // 4 KiB emergency-fallback case can't trick depth/bound math into
    // reading past the canary.  See `alloc_kernel_stack` doc-comment.
    let kstack_span = stack_top - stack_base;

    let cr3 = crate::mm::vmm::get_cr3();

    // Set up the initial stack so that when switch_context "returns" into this
    // thread, it starts at thread_entry_trampoline → entry_point.
    let initial_rsp = thread::init_thread_stack(stack_top, entry_point);

    let context = CpuContext {
        rsp: initial_rsp,
        rbp: 0,
        rbx: thread::fixup_fn_ptr(entry_point),
        r12: 0, r13: 0, r14: 0, r15: 0,
        rflags: 0x202,
        cr3,
    };

    let mut proc_name = [0u8; 64];
    let bytes = name.as_bytes();
    let len = bytes.len().min(63);
    proc_name[..len].copy_from_slice(&bytes[..len]);

    let mut thread_name = [0u8; 32];
    let tname = b"main";
    thread_name[..tname.len()].copy_from_slice(tname);

    let process = Process {
        pid,
        parent_pid: 0,
        name: proc_name,
        state: ProcessState::Active,
        cr3,
        threads: Vec::from([tid]),
        exit_code: 0,
        file_descriptors: {
            // Pre-populate stdin(0), stdout(1), stderr(2)
            let mut fds = Vec::new();
            fds.push(Some(crate::vfs::FileDescriptor::console_stdin()));
            fds.push(Some(crate::vfs::FileDescriptor::console_stdout()));
            fds.push(Some(crate::vfs::FileDescriptor::console_stderr()));
            fds
        },
        cwd: alloc::string::String::from("/"),
        uid: 0,
        gid: 0,
        euid: 0,
        egid: 0,
        pgid: pid as u32,
        sid: pid as u32,
        no_new_privs: false,
        cap_permitted: !0u64,
        cap_effective: !0u64,
        rlimits_soft: default_rlimits(),
        supplementary_groups: Vec::new(),
        umask: 0o022,
        vm_space: None,
        signal_state: None,
        linux_abi: false,
        handle_table: Some(crate::ob::handle::HandleTable::new()),
        subsystem: crate::win32::SubsystemType::Aether,
        token_id: None,
        exe_path: None,
        epoll_sets: alloc::vec::Vec::new(),
        auxv: Vec::new(),
        envp: Vec::new(),
        alarm_deadline_ticks: 0,
        alarm_interval_ticks: 0,
        pdeath_signal: 0,
    };

    let thread = Thread {
        tid,
        pid,
        state: initial_state,
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: kstack_span,
        wake_tick: u64::MAX,
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: 0,
        user_entry_rsp: 0,
        user_entry_rdx: 0,
        user_entry_r8:  0,
        priority: PRIORITY_HIGH,
        base_priority: PRIORITY_HIGH,
        tls_base: 0,
        cpu_affinity: None,
        last_cpu: 0,
        first_run: false,
        ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
        clear_child_tid: 0,
        fork_user_regs: ForkUserRegs::default(),
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
        vfork_isolated_stack: None,
        vfork_isolated_tls: None,
    };

    PROCESS_TABLE.lock().push(process);
    THREAD_TABLE.lock().push(thread);
    proc_metrics::register(pid);

    crate::serial_println!("[PROC] Created kernel process '{}' PID {} TID {}", name, pid, tid);
    note_if_emergency_kstack(pid, tid, stack_base, kstack_span);
    note_kstack_alloc(pid, tid, stack_base, kstack_span);
    pid
}

/// Create a new thread in an existing process.
pub fn create_thread(pid: Pid, name: &str, entry_point: u64) -> Option<Tid> {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    let (stack_base, stack_top) = alloc_kernel_stack()?;
    let kstack_span = stack_top - stack_base; // honest span (may be 4 KiB)

    let cr3 = {
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)?.cr3
    };

    let initial_rsp = thread::init_thread_stack(stack_top, entry_point);

    let context = CpuContext {
        rsp: initial_rsp,
        rbp: 0,
        rbx: entry_point,
        r12: 0, r13: 0, r14: 0, r15: 0,
        rflags: 0x202,
        cr3,
    };

    let mut thread_name = [0u8; 32];
    let bytes = name.as_bytes();
    let len = bytes.len().min(31);
    thread_name[..len].copy_from_slice(&bytes[..len]);

    let thread = Thread {
        tid,
        pid,
        state: ThreadState::Ready,
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: kstack_span,
        wake_tick: u64::MAX,
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: 0,
        user_entry_rsp: 0,
        user_entry_rdx: 0,
        user_entry_r8:  0,
        priority: PRIORITY_NORMAL,
        base_priority: PRIORITY_NORMAL,
        tls_base: 0,
        cpu_affinity: None,
        last_cpu: 0,
        first_run: false,
        ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
        clear_child_tid: 0,
        fork_user_regs: ForkUserRegs::default(),
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
        vfork_isolated_stack: None,
        vfork_isolated_tls: None,
    };

    THREAD_TABLE.lock().push(thread);
    PROCESS_TABLE.lock().iter_mut()
        .find(|p| p.pid == pid)
        .map(|p| p.threads.push(tid));

    crate::serial_println!("[PROC] Created thread '{}' TID {} in PID {}", name, tid, pid);
    note_if_emergency_kstack(pid, tid, stack_base, kstack_span);
    note_kstack_alloc(pid, tid, stack_base, kstack_span);
    Some(tid)
}

/// Like `create_thread`, but the new thread starts in `Blocked` state so the
/// caller can safely populate `user_entry_rip` / `user_entry_rsp` / `tls_base`
/// before the scheduler can pick it up.  Caller must transition the thread to
/// `ThreadState::Ready` when it is ready to run.
pub fn create_thread_blocked(pid: Pid, name: &str, entry_point: u64) -> Option<Tid> {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    let (stack_base, stack_top) = alloc_kernel_stack()?;
    let kstack_span = stack_top - stack_base; // honest span (may be 4 KiB)

    let cr3 = {
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)?.cr3
    };

    let initial_rsp = thread::init_thread_stack(stack_top, entry_point);

    let context = CpuContext {
        rsp: initial_rsp,
        rbp: 0,
        rbx: entry_point,
        r12: 0, r13: 0, r14: 0, r15: 0,
        rflags: 0x202,
        cr3,
    };

    let mut thread_name = [0u8; 32];
    let bytes = name.as_bytes();
    let len = bytes.len().min(31);
    thread_name[..len].copy_from_slice(&bytes[..len]);

    let thread = Thread {
        tid,
        pid,
        state: ThreadState::Blocked, // caller must mark Ready when prepared
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: kstack_span,
        wake_tick: u64::MAX, // indefinite — caller marks Ready explicitly
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: 0,
        user_entry_rsp: 0,
        user_entry_rdx: 0,
        user_entry_r8:  0,
        priority: PRIORITY_NORMAL,
        base_priority: PRIORITY_NORMAL,
        tls_base: 0,
        cpu_affinity: None,
        last_cpu: 0,
        first_run: false,
        ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
        clear_child_tid: 0,
        fork_user_regs: ForkUserRegs::default(),
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
        vfork_isolated_stack: None,
        vfork_isolated_tls: None,
    };

    THREAD_TABLE.lock().push(thread);
    PROCESS_TABLE.lock().iter_mut()
        .find(|p| p.pid == pid)
        .map(|p| p.threads.push(tid));

    crate::serial_println!("[PROC] Created thread (blocked) '{}' TID {} in PID {}", name, tid, pid);
    note_if_emergency_kstack(pid, tid, stack_base, kstack_span);
    note_kstack_alloc(pid, tid, stack_base, kstack_span);
    Some(tid)
}
pub fn exit_thread(exit_code: i64) {
    let tid = recover_current_tid();
    let pid;
    let parent_pid;

    // ── Stack canary check before cleanup ────────────────────────────
    {
        let threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter().find(|t| t.tid == tid) {
            if t.kernel_stack_base > 0 && !check_stack_canary(t.kernel_stack_base) {
                crate::serial_println!(
                    "[EXIT] STACK OVERFLOW: tid={} pid={} stack_base={:#x}",
                    tid, t.pid, t.kernel_stack_base
                );
                // Don't panic — we're already exiting. Just log the warning.
            }
        }
    }

    // Do NOT mark this thread Dead yet — see exit_group() for the reasoning.
    // We get our PID here but defer the Dead transition until after all cleanup.
    {
        let threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter().find(|t| t.tid == tid) {
            pid = t.pid;
        } else {
            return;
        }
    }

    // Check if all OTHER threads in the process are dead.
    // IMPORTANT: Never hold THREAD_TABLE and PROCESS_TABLE simultaneously —
    // other code paths (test runner, scheduler) may acquire them in the
    // opposite order, causing an ABBA deadlock on SMP.

    // Step 1: Get thread TID list + parent_pid from PROCESS_TABLE only.
    let (thread_tids, ppid) = {
        let procs = PROCESS_TABLE.lock();
        let (tids, pp) = procs.iter().find(|p| p.pid == pid)
            .map(|p| (p.threads.clone(), p.parent_pid))
            .unwrap_or_default();
        (tids, pp)
    };
    parent_pid = ppid;

    // Step 2: Check thread states from THREAD_TABLE only.
    // Count us as Dead even though we haven't set the flag yet — we ARE exiting.
    let all_dead = {
        let threads = THREAD_TABLE.lock();
        thread_tids.iter().all(|&t| {
            if t == tid { return true; } // caller is exiting — treat as dead
            threads.iter().find(|th| th.tid == t)
                .map(|th| th.state == ThreadState::Dead)
                .unwrap_or(true)
        })
    };

    // Step 3: If all dead, mark process as Zombie via PROCESS_TABLE only.
    if all_dead {
        let mut procs = PROCESS_TABLE.lock();
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            proc.state = ProcessState::Zombie;
            proc.exit_code = exit_code as i32;
        }
    }

    // ALWAYS switch to kernel CR3 before any cleanup or schedule().
    // This ensures the CPU never holds a stale user CR3 when entering
    // schedule() — the NT model (unconditional CR3 load) handles the
    // incoming thread's CR3, but the outgoing thread must not leave
    // a user CR3 that could be freed underneath it.
    {
        let kc3 = crate::mm::vmm::get_kernel_cr3();
        let cur = crate::mm::vmm::get_cr3();
        if kc3 != 0 && cur != kc3 {
            // Order: set the NEW (kernel) bit, write CR3, clear the OLD bit.
            // At every intermediate state at least one mask names this CPU
            // so a concurrent shootdown cannot miss us; the IPI handler's
            // running-CR3 equality check filters out wrong-CR3 invalidations.
            crate::mm::tlb::note_cr3_load(kc3);
            unsafe { crate::mm::vmm::switch_cr3(kc3); }
            crate::mm::tlb::note_cr3_unload(cur);
        }
    }

    // Free user memory now that the process is Zombie.  No locks held here.
    if all_dead {
        free_process_memory(pid);
    }

    // Vfork isolated-stack cleanup: if this thread is a vfork child that
    // was given a kernel-allocated isolated stack by `alloc_vfork_child_stack`
    // and exited WITHOUT execve(2) (the execve case is handled in
    // `syscall::sys_exec` step 5a), unmap the stack from the parent's
    // address space now.  The parent is still alive (zombie-able) and owns
    // the cr3 we mapped against; failing to unmap here would leak the VMA
    // until the parent itself exits.
    //
    // Ordering: this runs BEFORE `wake_vfork_parent()` to match the
    // canonical sys_exec Case C order — the parent must observe the
    // teardown completed (mapping unmapped, TLB shootdown ack'd) before
    // it is unblocked, so a parent thread that immediately runs and
    // reuses the same VA range cannot race against our pending unmap.
    {
        let isolated = {
            let threads = THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == tid)
                .and_then(|t| t.vfork_isolated_stack)
        };
        if let Some((base, length)) = isolated {
            if parent_pid != 0 {
                vfork_isolated_stack_cleanup(parent_pid, base, length);
            }
            let mut threads = THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                t.vfork_isolated_stack = None;
            }
        }
    }

    // Vfork isolated-TLS cleanup: companion to the stack cleanup above.
    // The per-vfork-child TCB page lives in the parent's address space —
    // tearing it down here (before `wake_vfork_parent()`) ensures the parent
    // never sees a stale `[vfork-tls]` VMA after resume.
    {
        let isolated_tls = {
            let threads = THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == tid)
                .and_then(|t| t.vfork_isolated_tls)
        };
        if let Some((base, length)) = isolated_tls {
            if parent_pid != 0 {
                vfork_isolated_tls_cleanup(parent_pid, base, length);
            }
            let mut threads = THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                t.vfork_isolated_tls = None;
            }
        }
    }

    // vfork completion: if this is a vfork child exiting without exec, wake parent.
    // Per POSIX vfork(2): the parent resumes only after the child terminates
    // or has called one of the exec(3) family.
    crate::syscall::wake_vfork_parent();

    // CLONE_CHILD_CLEARTID: write 0 to the child_tid address and futex-wake it.
    // This is how glibc's pthread_join knows the thread has exited — it does
    // futex_wait on the tid field in the TCB until this wake arrives.
    {
        let clear_addr = {
            let threads = THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == tid)
                .map(|t| t.clear_child_tid)
                .unwrap_or(0)
        };
        #[cfg(feature = "firefox-test")]
        crate::serial_println!(
            "[CLEARTID] tid={} pid={} clear_addr={:#x}",
            tid, pid, clear_addr
        );
        if clear_addr != 0 {
            // Write 0 to the tid address (in the process's user address space).
            let cr3 = {
                let procs = PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid).map(|p| p.cr3).unwrap_or(0)
            };
            #[cfg(feature = "firefox-test")]
            crate::serial_println!("[CLEARTID] tid={} cr3={:#x}", tid, cr3);
            if cr3 != 0 {
                crate::syscall::write_u32_to_user_pub(cr3, clear_addr, 0);
            }
            // Futex-wake any thread waiting on this address.
            crate::syscall::futex_wake_for_exit(pid, clear_addr, 1);
        }
    }

    // Wake parent threads waiting in waitpid, and mark current thread Dead.
    // Both ops are THREAD_TABLE-only with no PROCESS_TABLE access between them,
    // so one lock acquisition covers both.
    //
    // Producer-side snapshot for `ke::gp_trap_diag` is collected inside the
    // same lock so it captures the exit-time state atomically — see
    // `kernel/src/ke/gp_trap_diag.rs`.  Feature-gated; default builds are
    // byte-identical.  Cite: Intel SDM Vol. 3A §6.15 (#GP / kernel-mode trap
    // framing); POSIX clone(2) `CLONE_CHILD_CLEARTID`.
    #[cfg(feature = "kernel-gp-trap-diag")]
    let exit_snap: Option<(u64, u64, u64, u64)>;
    #[cfg(not(feature = "kernel-gp-trap-diag"))]
    let exit_snap: Option<()> = None;
    {
        let mut threads = THREAD_TABLE.lock();
        for t in threads.iter_mut() {
            if t.pid == parent_pid && t.state == ThreadState::Blocked && t.wake_tick == u64::MAX - 1 {
                // wake_tick == u64::MAX - 1  is our sentinel for "blocked in waitpid"
                t.state = ThreadState::Ready;
            }
        }
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.state = ThreadState::Dead;
            t.exit_code = exit_code;
            // Signal that the CPU is about to leave this thread's kernel stack.
            // switch_context_asm will set ctx_rsp_valid=true after saving RSP,
            // which is the AP's cue that the stack is safe to free.  Without
            // this, the AP can race to free the stack while BSP is still on it.
            t.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);

            #[cfg(feature = "kernel-gp-trap-diag")]
            {
                exit_snap = Some((
                    t.context.rsp,
                    t.kernel_stack_base,
                    t.kernel_stack_size,
                    t.clear_child_tid,
                ));
            }
        } else {
            #[cfg(feature = "kernel-gp-trap-diag")]
            { exit_snap = None; }
        }
    }
    // Commit the producer-side snapshot now that the lock is released.  The
    // `cr3` we captured earlier in the CLEARTID block was the snapshot at
    // CLEARTID time and is the value `write_u32_to_user_pub` dereferenced
    // against — re-derive it here from PROCESS_TABLE to be sure.
    #[cfg(feature = "kernel-gp-trap-diag")]
    if let Some((ctx_rsp, kstack_base, kstack_size, clear_addr)) = exit_snap {
        let cr3 = {
            let procs = PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid).map(|p| p.cr3).unwrap_or(0)
        };
        crate::ke::gp_trap_diag::record_exit(
            pid, tid, cr3, clear_addr, ctx_rsp, kstack_base, kstack_size,
        );
    }

    // Deliver SIGCHLD to parent (no locks held).
    if all_dead && parent_pid != 0 {
        let _ = crate::signal::kill(parent_pid, crate::signal::SIGCHLD);
    }

    // ── Metrics: clear last-syscall slot when this thread's exit completes
    //               the process's teardown ────────────────────────────────
    //
    // Same rationale as in `exit_group_inner`: exit_thread is `-> !`, so
    // `proc_metrics::leave_syscall` is never invoked from the normal
    // syscall-return path.  Without this clear, the dump would report
    // `STUCK_IN_NR=60@<N>t` (exit) for the now-zombie process every interval
    // until it is reaped.  Only clear when this thread's exit transitioned
    // the process to Zombie (`all_dead`); other threads in the same process
    // may still be alive and their syscall activity will overwrite the slot
    // normally.
    if all_dead {
        proc_metrics::leave_syscall(pid);
    }

    // Yield to scheduler — we're dead, should never return.
    // Wrap in a loop: if the scheduler is disabled (between tests on SMP),
    // schedule() returns early.  Without the loop, exit_thread (which is -> !)
    // would exhibit undefined behavior.  Spin-wait until the scheduler is
    // re-enabled, then schedule() will context-switch away permanently.
    loop {
        crate::sched::schedule();
        // schedule() returned — scheduler probably disabled.
        while !crate::sched::is_active() {
            core::hint::spin_loop();
        }
    }
}

/// Free all physical memory owned by a process (user page frames + page tables).
///
/// Walks the process's VmSpace VMAs, decrements refcounts of all present pages
/// (both anonymous and file-backed), and frees any whose refcount reaches zero.
/// Also frees the private user-half page table structures (PT → PD → PDPT → PML4).
///
/// Call after marking the process Zombie and after all threads are Dead, but
/// before removing the process from PROCESS_TABLE.  Safe to call from the
/// exiting thread's kernel stack since the scheduler will not reschedule any
/// Dead thread.
pub fn free_process_memory(pid: Pid) {
    use crate::mm::{refcount, pmm, vmm};
    use crate::mm::vma::VmBacking;

    // Take the VmSpace out of the Process.  Setting cr3=0 prevents the scheduler
    // from accidentally switching to the freed PML4.
    let vm_space = {
        let mut procs = PROCESS_TABLE.lock();
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            proc.cr3 = 0;
            proc.vm_space.take()
        } else {
            return;
        }
    };

    let vm_space = match vm_space {
        Some(vs) => vs,
        None => return, // Kernel process or already freed
    };

    let cr3 = vm_space.cr3;

    // W216 mm_sem write-lock: exclude every concurrent PTE-mutating reader
    // (page-fault demand-page, mmap/munmap/mprotect/madvise/brk) until the
    // bulk free completes.  Holding the lock across the shootdown ensures
    // no reader can race the PTE clear and resurrect a frame we are about
    // to return to the PMM.
    let _mm_write = vm_space.mm_sem.write();

    // Shoot down every TLB entry tagged with this CR3 across every CPU
    // BEFORE the backing frames are recycled.  Without this an AP that
    // briefly held the CR3 might still cache a translation pointing at
    // a frame the PMM is about to hand to a different process —
    // classic use-after-free, observable as a GPF in random user code.
    // The full-range request triggers a CR3-reload on each target
    // (cheaper than per-page invlpg over the entire user half).
    let shootdown_clean = crate::mm::tlb::shootdown_full_user(cr3);

    // Walk all VMAs and free physical frames.
    //
    // Both anonymous and file-backed VMAs have their frames ref-counted: every
    // present PTE holds one reference that was incremented when the page was
    // faulted or mapped in.  File-backed pages are shared with the page cache
    // (cache holds rc=1, each mapping PTE adds rc=1); decrementing here drops
    // the mapping ref.  If the cache also drops its ref later (eviction), rc
    // reaches zero and the frame is freed then.  Device VMAs are MMIO — they
    // have no backing frames in the PMM and must be skipped.
    //
    // Skipping file-backed PTEs (the pre-fix behaviour) left a permanent rc=1
    // from the mapping ref, preventing the cache from ever reclaiming those
    // frames.  Under Firefox bringup, every shared library segment leaked its
    // entire working set, inflating PMM pressure and increasing the probability
    // that the next-fit allocator wrapped around into frames still cached by
    // the page-aliasing path (W216 audit).
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PAGE_PRESENT: u64 = 1;

    for vma in &vm_space.areas {
        // Skip MMIO device VMAs — their "physical addresses" are I/O registers,
        // not PMM-tracked frames; decrementing their refcount would corrupt the
        // PMM's bookkeeping.
        if let VmBacking::Device { .. } = &vma.backing { continue; }

        let mut addr = vma.base;
        while addr < vma.base + vma.length {
            let pte = vmm::read_pte(cr3, addr);
            if pte & PAGE_PRESENT != 0 {
                let phys = pte & ADDR_MASK;
                if refcount::page_ref_dec(phys) == 0 {
                    // If the shootdown did not receive all ACKs, defer the
                    // PMM release until every CPU has passed through a
                    // quiescent state (timer ISR tick), guaranteeing TLB
                    // drain before the frame is recycled.
                    if shootdown_clean {
                        pmm::free_page(phys);
                    } else {
                        crate::mm::tlb::quarantine_free(phys);
                    }
                }
            }
            addr += 0x1000;
        }
    }

    // Free the private user-half page table structures.
    free_user_page_tables(cr3);

    crate::serial_println!("[PROC] PID {} memory freed", pid);
}

/// Free all physical pages and page table structures owned by a VmSpace.
///
/// This is the execve teardown path: the caller already holds the new VmSpace
/// and passes the old one in by value.  Ownership is consumed, so there is no
/// risk of double-free.
///
/// Walks every anonymous and file-backed VMA, decrements the per-page refcount,
/// and frees any physical frame whose refcount reaches zero (CoW pages shared
/// with a child are not freed until the last reference drops).  Then frees the
/// private user-half page table structures (PT → PD → PDPT → PML4).
///
/// # Safety contract for the caller
/// The caller MUST have already switched the hardware CR3 away from this
/// VmSpace before calling this function (or be about to do so imminently).
/// Because exec atomically replaces the VmSpace in the process table first and
/// THEN switches CR3, the window where the CPU might still speculatively
/// access the old page tables is eliminated by the CR3 switch that follows
/// immediately after the process-table update.
pub fn free_vm_space(vm_space: crate::mm::vma::VmSpace) {
    use crate::mm::{refcount, pmm, vmm};
    use crate::mm::vma::VmBacking;

    let cr3 = vm_space.cr3;

    // Guard: never free the kernel CR3 or a zero/already-freed one.
    let kernel_cr3 = crate::mm::vmm::get_kernel_cr3();
    if cr3 == 0 || cr3 == kernel_cr3 {
        return;
    }

    // W216 mm_sem write-lock: see matching commentary in
    // `free_process_memory`.  The exec teardown path is at lower risk than
    // free_process_memory because exec already replaced the cr3 in the
    // process table, but a sibling syscall in flight before the cr3 swap
    // could still hold a `mm_sem` read guard; the write here drains it
    // before any frame returns to the PMM.
    let _mm_write = vm_space.mm_sem.write();

    // Shoot down the entire user half BEFORE recycling frames; see the
    // matching comment in free_process_memory above.  Even though the
    // caller has already switched away from this CR3, sibling threads
    // on other CPUs that have not yet reached the next context-switch
    // could still hold cached translations into this address space.
    let shootdown_clean = crate::mm::tlb::shootdown_full_user(cr3);

    // Walk all VMAs and decrement/free the backing physical pages.
    //
    // Identical semantics to the free_process_memory path: both anonymous and
    // file-backed VMAs hold one refcount per mapped PTE.  File-backed mappings
    // share frames with the page cache (cache holds rc=1, PTE holds rc=1);
    // dropping the PTE ref here allows the cache to reclaim the frame on
    // eviction.  Device VMAs are MMIO and must be skipped.
    //
    // The pre-fix code skipped file-backed VMAs, leaking the PTE ref
    // permanently and preventing cache reclamation of every shared-library
    // segment loaded by execve — the dominant allocation pattern during
    // Firefox bringup (W216 audit teardown-leak finding).
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PAGE_PRESENT: u64 = 1;

    for vma in &vm_space.areas {
        if let VmBacking::Device { .. } = &vma.backing { continue; }

        let mut addr = vma.base;
        while addr < vma.base + vma.length {
            let pte = vmm::read_pte(cr3, addr);
            if pte & PAGE_PRESENT != 0 {
                let phys = pte & ADDR_MASK;
                if refcount::page_ref_dec(phys) == 0 {
                    if shootdown_clean {
                        pmm::free_page(phys);
                    } else {
                        crate::mm::tlb::quarantine_free(phys);
                    }
                }
            }
            addr += 0x1000;
        }
    }

    // Free the private user-half page table structures (PDPT / PD / PT / PML4).
    free_user_page_tables(cr3);

    crate::serial_println!("[PROC] old VmSpace (cr3={:#x}) freed", cr3);
}

/// Free all page table structs in the user-half (PML4[0..256]) of the given
/// PML4 physical address, then free the PML4 page itself.
///
/// Only touches PML4 entries 0-255 (user space).  Entries 256-511 are
/// shallow copies of the kernel half and must not be freed.
///
/// # Safety
/// `cr3` must be a valid PML4 physical address.
/// All user page *frames* must already have been freed/unmapped before calling.
///
/// Page table entries are read via KERNEL_VIRT_OFFSET (higher-half direct map),
/// NOT the identity map.  This is safe regardless of which CR3 is active —
/// the higher-half mapping (PML4[256-511]) is shared across all page tables.
fn free_user_page_tables(cr3: u64) {
    use crate::mm::pmm;
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PAGE_PRESENT: u64 = 1;
    const PAGE_HUGE: u64 = 0x80;

    // Guard: don't free kernel CR3 or a zero/already-freed CR3.
    let kernel_cr3 = crate::mm::vmm::get_kernel_cr3();
    if cr3 == 0 || cr3 == kernel_cr3 { return; }

    // Drop the per-CR3 active-CPU tracking entry — no CPU should be
    // running on this address space any more (the caller has switched
    // every still-live thread off it before invoking the teardown
    // path), and leaving the entry would leak BTreeMap nodes across
    // the lifetime of the kernel.
    crate::mm::tlb::forget_cr3(cr3);

    /// Convert physical address to a kernel-accessible virtual pointer
    /// using the higher-half direct map (not identity map).
    #[inline(always)]
    unsafe fn p2v(phys: u64) -> *const u64 {
        (KERNEL_VIRT_OFFSET + phys) as *const u64
    }

    unsafe {
        let pml4 = p2v(cr3);
        for i in 0..256usize {
            let pml4e = core::ptr::read_volatile(pml4.add(i));
            if pml4e & PAGE_PRESENT == 0 { continue; }
            let pdpt_phys = pml4e & ADDR_MASK;
            let pdpt = p2v(pdpt_phys);
            for j in 0..512usize {
                let pdpte = core::ptr::read_volatile(pdpt.add(j));
                if pdpte & PAGE_PRESENT == 0 { continue; }
                if pdpte & PAGE_HUGE != 0 { continue; } // 1 GiB huge page — skip
                let pd_phys = pdpte & ADDR_MASK;
                let pd = p2v(pd_phys);
                for k in 0..512usize {
                    let pde = core::ptr::read_volatile(pd.add(k));
                    if pde & PAGE_PRESENT == 0 { continue; }
                    if pde & PAGE_HUGE != 0 { continue; } // 2 MiB huge page — skip
                    let pt_phys = pde & ADDR_MASK;
                    pmm::free_page(pt_phys);
                }
                pmm::free_page(pd_phys);
            }
            pmm::free_page(pdpt_phys);
        }
        pmm::free_page(cr3);
    }
}

/// exit_group(status) — Linux semantics: terminate ALL threads in the process,
/// then mark the process as Zombie.  Called by:
///   - the exit_group(231) syscall (cooperative termination)
///   - synchronous fatal CPU exceptions in user mode (#GP, #PF, #UD, #DE …)
///     when no signal handler is installed; see arch/x86_64/idt.rs.
///
/// POSIX (signal(7)) requires that default actions for SIGSEGV / SIGBUS /
/// SIGFPE / SIGILL terminate the **entire thread group**, not just the
/// faulting thread.  Otherwise sibling threads parked on POSIX semaphores,
/// pthread condition variables, or futexes that the dead thread was meant
/// to signal would deadlock indefinitely.
///
/// The implementation lives in `exit_group_inner`; this wrapper resolves the
/// caller's pid/tid and yields after teardown.  Tests use
/// `exit_group_pid` to drive teardown on a synthetic target process without
/// killing the test runner thread itself.
pub fn exit_group(exit_code: i64) {
    let tid = recover_current_tid();
    let pid = {
        let threads = THREAD_TABLE.lock();
        match threads.iter().find(|t| t.tid == tid) {
            Some(t) => t.pid,
            None => { crate::sched::schedule(); return; }
        }
    };

    // ── Firefox-test diagnostic dump ─────────────────────────────────────────
    // On non-zero exit, first dump a userspace stack snapshot (RSP/RBP,
    // 128 bytes of stack top, RBP chain up to 8 frames) so the harness can
    // resolve the call chain that led to `exit(1)`.  Then spill the
    // per-process syscall ring buffer to serial.  Both must run BEFORE any
    // teardown so the caller's CR3 and VMAs are still live.  Neither dump
    // takes locks that conflict with the teardown below.
    #[cfg(feature = "firefox-test")]
    {
        if pid >= 1 {
            if exit_code != 0 {
                let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
                let cr3 = crate::mm::vmm::get_cr3();
                crate::syscall::ring::dump_exit_stack(pid, cr3, user_rsp, user_rbp);
                crate::syscall::ring::dump_for_exit(pid, exit_code);
            } else {
                crate::syscall::ring::drop_ring(pid);
            }
        }
    }

    exit_group_inner(pid, tid, exit_code, /* yield_self = */ true);
}

/// Out-of-band exit_group: terminate every thread in `pid` and mark the
/// process Zombie.  The caller is **not** assumed to be one of the dying
/// threads — useful when the test runner triggers teardown of a synthetic
/// target process, or when a future kernel watchdog needs to reap a
/// runaway process from a different context.
///
/// The calling thread is left in whatever state it was in (Running) and
/// returns normally to its caller after teardown.
pub fn exit_group_pid(pid: Pid, exit_code: i64) {
    // calling_tid = 0 means "no thread in the dying group is special";
    // every thread gets the Dead transition in one pass.
    exit_group_inner(pid, 0, exit_code, /* yield_self = */ false);
}

fn exit_group_inner(pid: Pid, calling_tid: Tid, exit_code: i64, yield_self: bool) {
    crate::serial_println!(
        "[PROC] PID {} exit_group({}) caller_tid={}",
        pid, exit_code, calling_tid
    );

    // Honour CLONE_CHILD_CLEARTID for every live thread in the dying
    // group BEFORE any sibling is marked Dead and BEFORE
    // `futex_drain_pid` evicts the wait queue.  Per `clone(2)`
    // ("C library/kernel ABI differences"): "When the thread terminates,
    // the kernel writes a 0 to that location, and any thread waiting on
    // a futex at that address will be woken."  Linux runs this for every
    // task that traverses `do_exit()`, including the caller of
    // `exit_group(2)` and each sibling reaped during group termination.
    //
    // Without this step, a cross-thread joiner parked in `FUTEX_WAIT` on
    // a sibling's joinstate is never woken when the group exits —
    // `futex_drain_pid` (a few lines below) silently drops the waiter
    // without delivering a wake, so `pthread_join(3)` blocks until a
    // non-existent event.  CWE-833 (Deadlock).
    //
    // Lock discipline: the helper snapshots under THREAD_TABLE.lock(),
    // drops, then performs the write + wake (which themselves acquire
    // FUTEX_WAITERS and THREAD_TABLE).  Must run with no kernel locks
    // held, which is the state at function entry.
    fire_cleartid_for_group(pid);

    // Kill every OTHER thread in the process immediately, but NOT the caller
    // (if the caller is itself a thread of this process).
    //
    // CRITICAL: interrupts are re-enabled in syscall_entry before dispatch() is
    // called (STI at step 3).  If the calling thread marks ITSELF as Dead here,
    // a timer interrupt can preempt it mid-cleanup (before Zombie is set).
    // The scheduler then sees a Dead thread and never reschedules it, so the
    // Zombie transition never completes and the parent waits forever.
    //
    // By keeping the caller in its current state (Running → Ready on preemption),
    // if preempted it will be rescheduled and finish the Zombie/parent-wake steps.
    // We mark the caller Dead last, just before calling schedule().
    //
    // INVARIANT: do NOT touch `ctx_rsp_valid` on siblings.  Sibling threads are
    // Blocked / Ready / Sleeping when we reach here, meaning their context was
    // saved long ago by switch_context_asm and `ctx_rsp_valid` is true.  The
    // reaper at `sched::reap_dead_threads_sched` filters Dead threads by
    // `ctx_rsp_valid == true` precisely so it can safely free a kernel stack
    // whose context-save has completed.  Forcing the flag false here would
    // strand every sibling as Dead-but-unreapable, leaking its 16 KiB kernel
    // stack until the process slot itself is recycled.  Mozilla's 51-thread
    // worker pool would lose ~800 KiB per teardown.  Only the caller of
    // exit_group (which is still executing on its own stack) gets
    // `ctx_rsp_valid=false`, and only on the yield_self path below where
    // switch_context_asm will re-set it after saving RSP.
    {
        let mut threads = THREAD_TABLE.lock();
        for t in threads.iter_mut() {
            if t.pid == pid && t.tid != calling_tid && t.state != ThreadState::Dead {
                t.state = ThreadState::Dead;
                t.exit_code = exit_code;
            }
        }
    }

    // Drain the futex wait queue of any entries owned by this process.  The
    // sibling threads we just marked Dead may have been parked on FUTEX_WAIT
    // (e.g. inside pthread_cond_wait / sem_wait / pthread_join).  The
    // scheduler will never reschedule a Dead thread, but leaving stale TIDs
    // in `FUTEX_WAITERS` poisons future diagnostics and would let a phantom
    // FUTEX_WAKE on the same uaddr from an unrelated process try to wake
    // dead TIDs.  Per futex(2): if the task whose stack hosts the futex
    // word dies, the kernel owes any future operation a clean state.
    crate::syscall::futex_drain_pid(pid);

    // Close pipe and socket fds before marking Zombie so peers see EOF / peer-close
    // promptly.  Iterate a snapshot to avoid holding PROCESS_TABLE while calling
    // into PIPE_TABLE / unix socket TABLE (lock ordering: resource table before
    // PROCESS_TABLE).
    let (pipe_ends, socket_ids): (alloc::vec::Vec<(u64, bool)>, alloc::vec::Vec<u64>) = {
        let procs = PROCESS_TABLE.lock();
        let (mut pipes, mut sockets) = (alloc::vec::Vec::new(), alloc::vec::Vec::new());
        if let Some(p) = procs.iter().find(|p| p.pid == pid) {
            for f in p.file_descriptors.iter().filter_map(|f| f.as_ref()) {
                if f.file_type == crate::vfs::FileType::Pipe
                    && f.mount_idx == usize::MAX
                    && f.flags & 0x8000_0000 != 0
                {
                    pipes.push((f.inode, f.flags & 1 == 1));
                } else if f.file_type == crate::vfs::FileType::Socket
                    && f.flags & crate::syscall::UNIX_SOCKET_FLAG != 0
                {
                    sockets.push(f.inode);
                }
            }
        }
        (pipes, sockets)
    };
    for (pipe_id, is_write) in pipe_ends {
        if is_write {
            crate::ipc::pipe::pipe_close_writer(pipe_id);
        } else {
            crate::ipc::pipe::pipe_close_reader(pipe_id);
        }
    }
    // Decrement the refcount on each inherited unix socket; only the last
    // close tears the slot down and notifies the peer.
    for socket_id in socket_ids {
        crate::net::unix::close(socket_id);
    }

    // Release POSIX file locks held by this process (C1).
    crate::vfs::FILE_LOCKS.lock().retain(|l| l.pid != pid);

    // Mark the process as Zombie, record exit code, and re-parent its live children
    // to PID 1 (orphan adoption) so they don't accumulate as un-reapable zombies.
    //
    // Also collect any of THIS process's own Zombie children: their would-be
    // reaper (us) is now dying, so re-parenting them to PID 1 only helps if PID 1
    // is alive and reaping.  When PID 1 is itself the exiting process — common in
    // the Firefox-on-AstryxOS case where firefox-bin is the only userspace
    // process — they would orphan to "no one" and leak their PROCESS_TABLE entry
    // and metrics slot for the rest of the kernel's lifetime.  Reap them inline
    // before yielding so the table stays bounded.
    //
    // Per POSIX wait(2): "If the parent terminates without waiting for the child,
    // the init process shall inherit the child."  Without a userspace init,
    // we play that role here for any zombie whose adoptive parent (PID 1) is
    // itself exiting or already a zombie.
    let (parent_pid, orphan_zombie_pids, pdeath_deliveries): (
        Pid,
        alloc::vec::Vec<(Pid, alloc::vec::Vec<Tid>)>,
        alloc::vec::Vec<(Pid, u8)>,
    ) = {
        let mut procs = PROCESS_TABLE.lock();
        let pp = procs.iter().find(|p| p.pid == pid).map(|p| p.parent_pid).unwrap_or(0);
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            proc.state = ProcessState::Zombie;
            proc.exit_code = exit_code as i32;
        }
        // Determine whether the conventional adopter (PID 1) is alive and able
        // to eventually reap: if PID 1 is the dying process, missing, or itself
        // a Zombie, downstream zombies will never be reaped through wait4().
        // In that case promote them to "ready to reap" right here.
        let pid1_alive = pid != 1 && procs.iter().any(|p|
            p.pid == 1 && p.state != ProcessState::Zombie);
        // Re-parent surviving (non-Zombie) children to PID 1.  Their lifecycle
        // continues normally; PID 1's exit will sweep them via the same path.
        //
        // Collect children whose `pdeath_signal` is non-zero so we can deliver
        // the parent-death signal after releasing PROCESS_TABLE.  Per
        // `prctl(2)` PR_SET_PDEATHSIG: "Set the parent-death signal of the
        // calling process to arg2 (either a signal value in the range 1..maxsig,
        // or 0 to clear).  This is the signal that the calling process will get
        // when its parent dies."  Signal delivery cannot happen under the
        // PROCESS_TABLE lock — crate::signal::kill() re-enters it.
        let mut pdeath_deliveries: alloc::vec::Vec<(Pid, u8)> = alloc::vec::Vec::new();
        for p in procs.iter_mut() {
            if p.parent_pid == pid && p.state != ProcessState::Zombie {
                if p.pdeath_signal != 0 {
                    pdeath_deliveries.push((p.pid, p.pdeath_signal));
                }
                p.parent_pid = 1;
            }
        }
        // Collect Zombie children of the dying PID (and, when PID 1 cannot
        // reap, Zombie children of PID 1 too — they are about to be doubly
        // orphaned).  Returned to the caller as (pid, [tid, …]) and removed
        // from PROCESS_TABLE in the same critical section to keep observers
        // from racing against half-removed entries.
        let mut orphans: alloc::vec::Vec<(Pid, alloc::vec::Vec<Tid>)> =
            alloc::vec::Vec::new();
        let mut i = 0;
        while i < procs.len() {
            let p = &procs[i];
            let direct_orphan = p.parent_pid == pid && p.state == ProcessState::Zombie;
            let pid1_orphan = !pid1_alive
                && p.parent_pid == 1
                && p.state == ProcessState::Zombie
                && p.pid != pid;
            if direct_orphan || pid1_orphan {
                let cpid = p.pid;
                let tids = p.threads.clone();
                procs.swap_remove(i);
                orphans.push((cpid, tids));
                continue;
            }
            i += 1;
        }
        (pp, orphans, pdeath_deliveries)
    };
    // Deliver PR_SET_PDEATHSIG signals to children that requested them.
    // signal::kill() acquires PROCESS_TABLE, so this must run after the lock
    // is dropped.  Per prctl(2): "The setting is not inherited by children
    // created by fork(2)/clone(2) and is cleared when [...] the credentials
    // change."  Storage of the value is per-process; reset on exec().
    for (cpid, sig) in &pdeath_deliveries {
        let _ = crate::signal::kill(*cpid, *sig as u8);
    }
    // Drop reaped orphans' threads + metrics outside the PROCESS_TABLE lock
    // (lock order: PROCESS_TABLE then THREAD_TABLE — see waitpid()).
    if !orphan_zombie_pids.is_empty() {
        let mut threads = THREAD_TABLE.lock();
        for (_cpid, tids) in &orphan_zombie_pids {
            threads.retain(|t| !tids.contains(&t.tid));
        }
        drop(threads);
        for (cpid, _) in &orphan_zombie_pids {
            proc_metrics::unregister(*cpid);
            crate::serial_println!(
                "[PROC] auto-reaped orphan zombie PID {} (parent {} exiting)",
                cpid, pid
            );
        }
    }

    // Switch to the kernel page tables BEFORE freeing user page tables.
    // Only relevant when the caller is on the user CR3 of the dying process —
    // out-of-band callers (yield_self == false) are already on the kernel CR3.
    if yield_self {
        let kc3 = crate::mm::vmm::get_kernel_cr3();
        let cur = crate::mm::vmm::get_cr3();
        if kc3 != 0 && cur != kc3 {
            // Same bracket order as elsewhere: set NEW bit, write CR3,
            // clear OLD bit.  See sched/mod.rs for the rationale.
            crate::mm::tlb::note_cr3_load(kc3);
            unsafe { crate::mm::vmm::switch_cr3(kc3); }
            crate::mm::tlb::note_cr3_unload(cur);
        }
    }
    // Free user memory (no locks held).
    free_process_memory(pid);

    // Vfork isolated-stack cleanup: same rationale as exit_thread (see
    // there for the longer comment).  We harvest the field from the
    // calling thread (the vfork child) and unmap the recorded VMA from
    // the parent's address space.  Out-of-band callers (yield_self==false)
    // do not own a calling_tid of the dying process, so they skip this.
    //
    // Ordering: runs BEFORE `wake_vfork_parent()` to match sys_exec
    // Case C — the parent must observe a fully torn-down mapping before
    // it is unblocked.
    if yield_self && calling_tid != 0 && parent_pid != 0 {
        let isolated = {
            let threads = THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == calling_tid)
                .and_then(|t| t.vfork_isolated_stack)
        };
        if let Some((base, length)) = isolated {
            vfork_isolated_stack_cleanup(parent_pid, base, length);
            let mut threads = THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == calling_tid) {
                t.vfork_isolated_stack = None;
            }
        }

        // Companion: vfork isolated-TLS cleanup.  Same ordering rationale —
        // parent must observe the mapping torn down before it resumes.
        let isolated_tls = {
            let threads = THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == calling_tid)
                .and_then(|t| t.vfork_isolated_tls)
        };
        if let Some((base, length)) = isolated_tls {
            vfork_isolated_tls_cleanup(parent_pid, base, length);
            let mut threads = THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == calling_tid) {
                t.vfork_isolated_tls = None;
            }
        }
    }

    // vfork completion: if the caller is a vfork child fatal-faulting mid-
    // execve (e.g. a synchronous fatal CPU exception routed here from
    // arch/x86_64/idt.rs), the parent is parked in TASK_KILLABLE-style sleep
    // on `vfork_parent_tid` and only this wake will release it.  Without it,
    // the parent stays Blocked until the 5-second vfork timeout fires.
    // Per POSIX vfork(2): parent resumes only after child terminates or execs.
    //
    // Lock discipline: wake_vfork_parent() takes THREAD_TABLE.  We hold no
    // locks here (the sibling-Dead pass at the top released THREAD_TABLE,
    // and futex_drain_pid / PROCESS_TABLE / FILE_LOCKS sections have all
    // completed).  Out-of-band callers (yield_self == false) skip this:
    // they are healthy threads in a different process — not a vfork child.
    if yield_self {
        crate::syscall::wake_vfork_parent();
    }

    // Wake parent threads blocked in waitpid, and mark calling thread Dead
    // (only when the caller is itself a thread of the dying process).
    {
        let mut threads = THREAD_TABLE.lock();
        for t in threads.iter_mut() {
            if t.pid == parent_pid && t.state == ThreadState::Blocked && t.wake_tick == u64::MAX - 1 {
                t.state = ThreadState::Ready;
            }
        }
        if yield_self {
            if let Some(t) = threads.iter_mut().find(|t| t.tid == calling_tid) {
                t.state = ThreadState::Dead;
                t.exit_code = exit_code;
                // Signal that the CPU is about to leave this thread's kernel stack.
                // switch_context_asm will set ctx_rsp_valid=true after saving RSP,
                // which is the AP's cue that the stack is safe to free.
                t.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
            }
        }
    }

    // Deliver SIGCHLD to parent (no locks held).
    if parent_pid != 0 {
        let _ = crate::signal::kill(parent_pid, crate::signal::SIGCHLD);
    }

    // ── Metrics: clear the dying process's last-syscall slot ────────────────
    //
    // `proc_metrics::leave_syscall` is normally called at the tail of the
    // syscall dispatcher after the match returns.  exit_group(231) never
    // returns to the dispatcher (the caller is marked Dead and yields to
    // `schedule()` below, which never comes back), so the slot's
    // `last_sc_nr` would remain pinned at 231 long after teardown is
    // complete.  The periodic dump then reports `STUCK_IN_NR=231@<N>t`
    // for the exited process every interval until the parent reaps it
    // (via `waitpid` → `unregister`) — and forever if no one reaps.
    //
    // Clear it explicitly here so the diagnostic correctly reflects the
    // truth: teardown is done; the process is a zombie awaiting reap, not
    // a thread stuck in a syscall.  Symmetric with `leave_syscall` from
    // the normal return path.  `proc_metrics::leave_syscall` is wait-free
    // and takes no locks (one atomic store), so it is safe to invoke even
    // immediately before `schedule()` switches us off-CPU permanently.
    proc_metrics::leave_syscall(pid);

    // Yield — we're dead and should never return.  Out-of-band callers
    // (yield_self == false) return normally; the caller is a healthy thread
    // in a different process and has more work to do.
    if yield_self {
        crate::sched::schedule();
    }
}

/// Put the current thread to sleep for `ticks` timer ticks.
pub fn sleep_ticks(ticks: u64) {
    let tid = current_tid();
    let current_tick = crate::arch::x86_64::irq::get_ticks();

    {
        let mut threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            // INVARIANT: Release-store ctx_rsp_valid=false BEFORE transitioning to
            // Sleeping.  A peer CPU that wakes this thread (via the scheduler tick)
            // between the state write and schedule() must not load a stale RSP.
            t.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
            t.state = ThreadState::Sleeping;
            t.wake_tick = current_tick + ticks;
        }
    }

    crate::sched::schedule();
}

/// Get current process count.
pub fn process_count() -> usize {
    PROCESS_TABLE.lock().len()
}

/// Get current thread count.
pub fn thread_count() -> usize {
    THREAD_TABLE.lock().len()
}

/// Get process name by PID.
pub fn process_name(pid: Pid) -> Option<alloc::string::String> {
    let procs = PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid).map(|p| {
        let len = p.name.iter().position(|&b| b == 0).unwrap_or(64);
        alloc::string::String::from_utf8_lossy(&p.name[..len]).into_owned()
    })
}

/// Return the CR3 of a process (for CLONE_CHILD_SETTID kernel writes).
pub fn get_process_cr3(pid: Pid) -> Option<u64> {
    let procs = PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid).map(|p| p.cr3)
}

/// Result of a VMA lookup that transparently falls back to the parent's
/// bookkeeping for a CLONE_VM child.
///
/// Per `clone(2)` "CLONE_VM" + `vfork(2)`, the child runs with the parent's
/// page tables (same CR3) but the kernel records its `Process.vm_space` as
/// `None` so the parent retains exclusive ownership of the VMA list and the
/// child's exit path is a no-op for the parent's address space.  That works
/// for fault handling (the PFH already has the parent-CR3 fallback path,
/// see `arch/x86_64/idt.rs::handle_page_fault`), but it misleads the
/// **diagnostic** printers: a fault inside the parent's text segment in a
/// shared-VM child reports `no_vma=1` / `vma_offset=NO_VMA` even though the
/// physical mapping is valid — because the lookup short-circuits on the
/// child's empty VMA list before consulting the parent's.
///
/// This helper does the obvious thing: try the child's VmSpace first, then
/// — if the child is in the `CLONE_VM` shared-VM state (no VmSpace + same
/// CR3 as the parent) — re-try against the parent's.  The `inherited` flag
/// lets the caller annotate the diagnostic line so a reader can tell at a
/// glance which address space the VMA came from.
#[derive(Copy, Clone, Default)]
pub struct VmaLookupHit {
    pub vma_base: u64,
    pub vma_end:  u64,
    pub prot:     u32,
    pub name:     &'static str,
    pub file_backed: bool,
    pub file_offset: u64,
    pub elf_load_delta: u64,
    pub mount_idx: usize,
    pub inode: u64,
    /// True when the VMA was resolved via the parent's VmSpace (the calling
    /// process is a CLONE_VM child whose own bookkeeping is empty).
    pub inherited: bool,
}

/// Look up `addr` in `pid`'s VmSpace, transparently falling back to the
/// parent's when `pid` is a CLONE_VM child (no own VmSpace, same CR3 as
/// parent).
///
/// `None` means neither child nor parent has a VMA covering `addr`.
///
/// Acquires `PROCESS_TABLE` briefly; the returned value owns no borrows so
/// the caller can use it after the lock is dropped.  Diagnostic-only — the
/// PFH at `arch/x86_64/idt.rs::handle_page_fault` performs its own
/// parent-VmSpace fallback for the actual fault path and does not call
/// this helper.
pub fn find_vma_with_parent_fallback(pid: Pid, addr: u64) -> Option<VmaLookupHit> {
    use crate::mm::vma::VmBacking;

    fn extract(vma: &crate::mm::vma::VmArea, inherited: bool) -> VmaLookupHit {
        let (file_backed, file_offset, elf_load_delta, mount_idx, inode) = match vma.backing {
            VmBacking::File { offset, elf_load_delta, mount_idx, inode } => {
                (true, offset, elf_load_delta, mount_idx, inode)
            }
            _ => (false, 0u64, 0u64, 0usize, 0u64),
        };
        VmaLookupHit {
            vma_base: vma.base,
            vma_end:  vma.end(),
            prot:     vma.prot,
            name:     vma.name,
            file_backed,
            file_offset,
            elf_load_delta,
            mount_idx,
            inode,
            inherited,
        }
    }

    let procs = PROCESS_TABLE.lock();
    let child = procs.iter().find(|p| p.pid == pid)?;

    // Direct hit on the child's own VmSpace.
    if let Some(space) = child.vm_space.as_ref() {
        if let Some(vma) = space.find_vma(addr) {
            return Some(extract(vma, false));
        }
        // Child has its own VmSpace but it doesn't cover `addr`.  Do NOT
        // fall back to the parent: that child has diverged (post-execve or
        // fork-with-CoW) and its VMA list is authoritative.
        return None;
    }

    // Child has no VmSpace (CLONE_VM shared-VM state).  Try the parent if
    // the CR3 matches — otherwise the relationship is something else
    // (kernel thread, idle, AP) and we have no VMA list to consult.
    let child_cr3 = child.cr3;
    let parent_pid = child.parent_pid;
    if child_cr3 == 0 || parent_pid == 0 {
        return None;
    }
    let parent = procs.iter().find(|p| p.pid == parent_pid)?;
    if parent.cr3 != child_cr3 {
        return None;
    }
    let parent_space = parent.vm_space.as_ref()?;
    let vma = parent_space.find_vma(addr)?;
    Some(extract(vma, true))
}

/// Store the clear_child_tid address in a thread for CLONE_CHILD_CLEARTID.
/// When that thread exits, the kernel will write 0 to that address and wake futex.
pub fn set_clear_child_tid(pid: Pid, tid: Tid, tidptr: u64) {
    let mut threads = THREAD_TABLE.lock();
    if let Some(t) = threads.iter_mut().find(|t| t.pid == pid && t.tid == tid) {
        t.clear_child_tid = tidptr;
    }
}

/// Fire the `CLONE_CHILD_CLEARTID` protocol on every non-Dead thread of
/// `pid` whose `clear_child_tid` is non-zero, then zero the per-thread
/// thread-exit ABI slots (`clear_child_tid`, `robust_list_head`,
/// `robust_list_len`) so the same write cannot be re-played by a later
/// reaper or by re-use of the `Thread` slot.
///
/// Per Linux `clone(2)` (CLONE_CHILD_CLEARTID): "When the thread
/// terminates, the kernel writes a 0 to that location, and any thread
/// waiting on a futex at that address will be woken."  Linux runs this
/// protocol on **every** task that traverses `do_exit()`, including the
/// thread that calls `exit_group(2)` and every sibling reaped during the
/// group termination.  A glibc / musl joiner parked in `FUTEX_WAIT` on a
/// sibling's joinstate (the address registered via `CLONE_CHILD_CLEARTID`)
/// is otherwise never woken when the group exits — `futex_drain_pid`
/// silently removes the waiter without delivering a wake, so the joiner's
/// `pthread_join(3)` blocks until a non-existent event.
///
/// AstryxOS's `exit_thread` already honours this protocol for the calling
/// thread on the per-thread exit path.  `exit_group_inner`, by contrast,
/// previously marked siblings (and on `yield_self == true`, the caller)
/// `Dead` without firing the wake — leaving any cross-thread joiner
/// parked indefinitely.
///
/// Lock discipline: the function snapshots `(tid, uaddr)` tuples under
/// `THREAD_TABLE.lock()`, drops the lock, performs the `write_u32_to_user`
/// + `futex_wake_for_exit` for each, then re-acquires the lock to zero
/// the slots.  `futex_wake_for_exit` itself takes `FUTEX_WAITERS.lock()`
/// then `THREAD_TABLE.lock()` to mark woken waiters `Ready`; calling it
/// while holding `THREAD_TABLE` would deadlock.  This mirrors the
/// snapshot-drop-write-wake pattern in `exit_thread` (lines 1258-1287).
///
/// Robust-list teardown is intentionally **not** performed here: AstryxOS
/// stores `robust_list_head` as an opaque user pointer and never walks it
/// (no userspace currently registers robust mutexes against the kernel —
/// the slot is round-tripped for `get_robust_list(2)` only).  We simply
/// zero the field so a future `Thread`-slot reuse cannot re-fire stale
/// values.
///
/// Caller contract: must hold no kernel-level locks (PROCESS_TABLE,
/// THREAD_TABLE, FUTEX_WAITERS, FILE_LOCKS, …).  Call once at the top of
/// the group-exit path, before any sibling is marked `Dead`.
///
/// Threat-model:
///   * CWE-833 (Deadlock) — without the wake, `pthread_join(3)` on a
///     sibling that died via `exit_group(2)` blocks forever.
///   * CWE-672 (Operation on Resource After Expiration or Release) — the
///     zeroing of the per-thread slots ensures a recycled `Thread` value
///     cannot replay an inherited `clear_child_tid` against unrelated
///     user-VA.
///
/// Refs:
///   * Linux `clone(2)` — CLONE_CHILD_CLEARTID, set_child_tid, FUTEX_WAKE
///     on task exit ("C library / kernel ABI differences").
///   * Linux `futex(2)` — NOTES on task-exit semantics.
///   * Linux `set_tid_address(2)`.
///   * POSIX-1.2017 `pthread_join(3)`, `pthread_exit(3)`.
///
/// Visibility: `pub(crate)` so the `exit_group(2)` ABI test in
/// `kernel/src/test_runner.rs` can exercise the helper without driving
/// the full `exit_group_inner` (which would tear down the test runner).
pub(crate) fn fire_cleartid_for_group(pid: Pid) {
    // (1) Snapshot user-VA writers under THREAD_TABLE.lock(): every
    //     non-Dead thread in this process with a registered CLEARTID slot.
    //     A tuple list is used (not a map) to keep ordering deterministic
    //     and to bound allocation to the live thread count.
    let writers: alloc::vec::Vec<(Tid, u64)> = {
        let threads = THREAD_TABLE.lock();
        threads
            .iter()
            .filter(|t| t.pid == pid
                     && t.state != ThreadState::Dead
                     && t.clear_child_tid != 0)
            .map(|t| (t.tid, t.clear_child_tid))
            .collect()
    };
    if writers.is_empty() {
        return;
    }
    // (2) Resolve the process's CR3 once.  All threads in the same
    //     process share the same VmSpace by construction (clone(2) without
    //     CLONE_VM produces a separate Pid), so a single CR3 covers every
    //     `clear_child_tid` user-VA in the snapshot.
    let cr3 = {
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid).map(|p| p.cr3).unwrap_or(0)
    };
    // (3) For each writer: zero the user-VA and FUTEX_WAKE one waiter.
    //     `write_u32_to_user` is fault-immune (it returns early if the
    //     PTE is not Present), matching the "best effort" semantics
    //     `exit_thread` already provides for a torn-down VmSpace.
    //     `futex_wake_for_exit` is a no-op if no waiter is parked on the
    //     uaddr.
    for (tid, uaddr) in &writers {
        #[cfg(feature = "firefox-test")]
        crate::serial_println!(
            "[CLEARTID/group] pid={} tid={} clear_addr={:#x} cr3={:#x}",
            pid, tid, uaddr, cr3
        );
        let _ = tid; // silence unused-binding warning when feature off
        if cr3 != 0 {
            crate::syscall::write_u32_to_user_pub(cr3, *uaddr, 0);
        }
        crate::syscall::futex_wake_for_exit(pid, *uaddr, 1);
    }
    // (4) Re-acquire THREAD_TABLE briefly and zero the per-thread slots
    //     so a recycled `Thread` value cannot replay these writes against
    //     unrelated user-VA in a future image.  Mirrors the
    //     `exec_reset_thread_exit_slots` slate that `sys_exec` applies
    //     across `execve(2)`.
    let mut threads = THREAD_TABLE.lock();
    for t in threads.iter_mut().filter(|t| t.pid == pid) {
        t.clear_child_tid = 0;
        t.robust_list_head = 0;
        t.robust_list_len = 0;
    }
}

/// Store the parent's user-mode callee-saved registers in the fork child's
/// thread entry so fork_child_entry() can restore them before iretq.
pub fn set_fork_user_regs(pid: Pid, tid: Tid, regs: ForkUserRegs) {
    let mut threads = THREAD_TABLE.lock();
    if let Some(t) = threads.iter_mut().find(|t| t.pid == pid && t.tid == tid) {
        t.fork_user_regs = regs;
    }
}

/// Increment the open-file-description reference count for every socket fd
/// in `fds`.
///
/// Called immediately after the fd table is duplicated during `fork(2)` /
/// `clone(2)` (without `CLONE_FILES`).  Without this bump, a `close(2)` in
/// the child or parent would decrement the count to zero and destroy the
/// shared socket object, leaving the other process with a dangling reference.
///
/// Per POSIX.1-2017 §2.14 and `man 2 fork`: "open file descriptors shall
/// be duplicated in the child process; the duplicate descriptors in the
/// child refer to the same open file descriptions as the corresponding
/// descriptors in the parent."
fn inc_socket_refs_for_fork(fds: &[Option<crate::vfs::FileDescriptor>]) {
    for fd in fds.iter().filter_map(|f| f.as_ref()) {
        // Gate on UNIX_SOCKET_FLAG (bit 23) rather than mount_idx alone:
        // AF_INET sockets also use mount_idx==usize::MAX but are tracked
        // separately and must not be passed to net::unix::inc_ref.
        if fd.file_type == crate::vfs::FileType::Socket
            && fd.flags & crate::syscall::UNIX_SOCKET_FLAG != 0
        {
            crate::net::unix::inc_ref(fd.inode);
        }
    }
}

/// Bump pipe reader/writer refcounts for every pipe fd that the child
/// inherits via fork/vfork/clone-without-`CLONE_FILES`.  Each pipe end fd
/// references the same in-kernel `Pipe` object, so a duplicate fd table
/// must add one reader (or one writer) per copied pipe end.  Without this
/// bump, the FIRST `close(2)` in either process would drop the counter to
/// zero — making the surviving end either see a premature EOF (read side)
/// or premature `EPIPE` (write side).
///
/// Per POSIX.1-2017 §2.14 and `man 2 fork`: "open file descriptors shall
/// be duplicated in the child process; the duplicate descriptors in the
/// child refer to the same open file descriptions as the corresponding
/// descriptors in the parent."  The open file description (struct file in
/// Linux terms) is the refcount-bearing entity, NOT the fd number itself.
///
/// Identifies pipe fds by the same shape used elsewhere
/// (see `proc::handle_exit_or_kill_thread` and
/// `vfs::FileDescriptor::pipe_{read,write}_end`):
/// `file_type == Pipe`, `mount_idx == usize::MAX`, `flags & 0x8000_0000 != 0`.
/// Bit 0 of `flags` distinguishes the write end (1) from the read end (0).
fn inc_pipe_refs_for_fork(fds: &[Option<crate::vfs::FileDescriptor>]) {
    for fd in fds.iter().filter_map(|f| f.as_ref()) {
        if fd.file_type == crate::vfs::FileType::Pipe
            && fd.mount_idx == usize::MAX
            && fd.flags & 0x8000_0000 != 0
        {
            if fd.flags & 1 == 1 {
                crate::ipc::pipe::pipe_add_writer(fd.inode);
            } else {
                crate::ipc::pipe::pipe_add_reader(fd.inode);
            }
        }
    }
}

/// Drop the pipe-end refcount associated with a single `FileDescriptor`
/// that is about to be cleared (e.g. by `close(2)`, by `execve(2)`'s
/// `FD_CLOEXEC` purge, or by `dup2(2)` overwriting an existing slot).
///
/// Per POSIX `close(2)`: "If `fildes` is the last file descriptor referring
/// to the open file description, the resources associated with the open
/// file description shall be released."  For an anonymous pipe, "release"
/// means decrementing the appropriate reader or writer count; when that
/// count reaches zero the kernel wakes any peer parked on the other end so
/// it observes EOF (`read(2)` returns 0) or `EPIPE` (`write(2)`).
///
/// Caller must have already removed the fd from the process's fd table
/// before invoking this; the helper does not touch `PROCESS_TABLE`.
pub fn close_pipe_fd(fd: &crate::vfs::FileDescriptor) {
    if fd.file_type != crate::vfs::FileType::Pipe { return; }
    if fd.mount_idx != usize::MAX { return; }
    if fd.flags & 0x8000_0000 == 0 { return; }
    if fd.flags & 1 == 1 {
        crate::ipc::pipe::pipe_close_writer(fd.inode);
    } else {
        crate::ipc::pipe::pipe_close_reader(fd.inode);
    }
}

/// Fork a process: create a child that is a copy of the parent.
///
/// If the parent has a VmSpace, performs Copy-on-Write (CoW) fork:
/// both parent and child share the same physical pages, marked read-only.
/// Write faults trigger a copy via the page fault handler.
///
/// The child gets:
/// - New PID and TID
/// - Copy of parent's file descriptors
/// - Same CWD
/// - Its own kernel stack
/// - Parent PID set to the caller
/// - (If user-mode) Returns to the same instruction as the parent with RAX=0
///
/// Returns the child PID, or None on failure.
pub fn fork_process(parent_pid: Pid, _parent_tid: Tid, parent_regs: &ForkUserRegs) -> Option<(Pid, Tid)> {
    let child_pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let child_tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    // Allocate kernel stack for the child (higher-half virtual address).
    let (stack_base, stack_top) = alloc_kernel_stack()?;
    let kstack_span = stack_top - stack_base; // honest span (may be 4 KiB)

    // Copy parent's file descriptors, CWD, and security credentials.
    let (fds, cwd, parent_name, parent_uid, parent_gid, parent_euid, parent_egid,
         parent_groups, parent_umask, parent_linux_abi, parent_subsystem, parent_token_id,
         parent_pgid, parent_sid, parent_no_new_privs, parent_cap_permitted,
         parent_cap_effective, parent_rlimits_soft, parent_exe_path) = {
        let procs = PROCESS_TABLE.lock();
        let parent = procs.iter().find(|p| p.pid == parent_pid)?;
        (
            parent.file_descriptors.clone(),
            parent.cwd.clone(),
            parent.name,
            parent.uid,
            parent.gid,
            parent.euid,
            parent.egid,
            parent.supplementary_groups.clone(),
            parent.umask,
            parent.linux_abi,
            parent.subsystem,
            parent.token_id,
            parent.pgid,
            parent.sid,
            parent.no_new_privs,
            parent.cap_permitted,
            parent.cap_effective,
            parent.rlimits_soft,
            parent.exe_path.clone(),
        )
    };

    // Bump the refcount on every socket fd now held by both parent and child.
    // Without this, the first close(2) from either process would drop the
    // count to zero and destroy the shared socket object, breaking the peer.
    inc_socket_refs_for_fork(&fds);
    // Same rationale for anonymous pipes — without this bump, parent's
    // posix_spawn cancel-pipe loses one writer the moment the child's exec
    // purges its CLOEXEC fd, so parent's `read` would see premature EOF
    // (or worse, refcount underflow on the second close).
    inc_pipe_refs_for_fork(&fds);

    // Enforce RLIMIT_NPROC: count non-zombie processes.
    {
        let procs = PROCESS_TABLE.lock();
        let count = procs.iter().filter(|p| p.state != ProcessState::Zombie).count();
        if count >= parent_rlimits_soft[6] as usize {
            return None; // EAGAIN: too many processes
        }
    }

    // Read the parent's user-mode return address, stack pointer, and TLS base
    // from the parent's thread struct / kernel stack.
    let (user_rip, user_rsp, parent_tls_base) = {
        let threads = THREAD_TABLE.lock();
        if let Some(parent_thread) = threads.iter().find(|t| t.tid == _parent_tid) {
            let tls = parent_thread.tls_base;
            if parent_thread.kernel_stack_base > 0 && parent_thread.kernel_stack_size > 0 {
                let kstack_top = parent_thread.kernel_stack_base + parent_thread.kernel_stack_size;
                // syscall_entry layout: offset -16 = RCX (user RIP), offset -8 = user RSP
                unsafe {
                    let rip = *((kstack_top - 16) as *const u64);
                    let rsp = *((kstack_top - 8) as *const u64);
                    (rip, rsp, tls)
                }
            } else {
                (0u64, 0u64, tls)
            }
        } else {
            (0u64, 0u64, 0u64)
        }
    };

    // Perform CoW clone of the parent's VmSpace (if it has one).
    let (child_cr3, child_vm_space) = {
        let mut procs = PROCESS_TABLE.lock();
        let parent = procs.iter_mut().find(|p| p.pid == parent_pid)?;
        // Read the actual running CR3 before mutably borrowing vm_space.
        // This ensures clone_for_fork walks the correct page tables even
        // if vm_space.cr3 is stale (e.g., after exec updated proc.cr3).
        let actual_cr3 = parent.cr3;
        if let Some(ref mut parent_vs) = parent.vm_space {
            match parent_vs.clone_for_fork(actual_cr3) {
                Some(child_vs) => {
                    let cr3 = child_vs.cr3;
                    (cr3, Some(child_vs))
                }
                None => {
                    // CoW clone failed (OOM) — fall back to shared CR3
                    (parent.cr3, None)
                }
            }
        } else {
            // Kernel process, no user address space
            (crate::mm::vmm::get_cr3(), None)
        }
    };

    // Map the signal-return trampoline into the child's address space.
    crate::signal::map_trampoline(child_cr3);

    // Build the fork child's kernel stack with a pre-built IRETQ frame.
    // Linux pattern: copy_thread() + ret_from_fork_asm.  The child's first
    // context switch lands directly in ret_from_fork_asm (pure asm), which
    // restores TLS + RBX, zeroes scratch regs, and does IRETQ to Ring 3.
    crate::serial_println!(
        "[FORK] child PID {} stack: rip={:#x} rsp={:#x} tls={:#x} rbp={:#x} rbx={:#x}",
        child_pid, user_rip, user_rsp, parent_tls_base, parent_regs.rbp, parent_regs.rbx
    );
    // Use user_mode_bootstrap (same path as clone threads) for the fork child.
    // This ensures proper CR3 switch, TSS.RSP0, TLS setup before entering Ring 3.
    // The child's user_entry_rip starts at the original clone return point.
    // The caller (CLONE_VM handler) may override user_entry_rip/rsp after
    // fork_process returns to use the new_stack provided by glibc.
    let initial_rsp = thread::init_thread_stack(
        stack_top, crate::proc::usermode::user_mode_bootstrap as *const () as u64,
    );

    let context = CpuContext {
        rsp: initial_rsp,
        rbp: 0,
        rbx: crate::proc::thread::fixup_fn_ptr(
            crate::proc::usermode::user_mode_bootstrap as *const () as u64
        ),
        r12: 0, r13: 0, r14: 0, r15: 0,
        rflags: 0x202,
        cr3: child_cr3,
    };

    let mut child_name = [0u8; 64];
    // Copy parent name and append ".child"
    let name_len = parent_name.iter().position(|&b| b == 0).unwrap_or(parent_name.len());
    let base_len = name_len.min(57); // Leave room for ".child"
    child_name[..base_len].copy_from_slice(&parent_name[..base_len]);

    let mut thread_name = [0u8; 32];
    thread_name[..4].copy_from_slice(b"main");

    let child_proc = Process {
        pid: child_pid,
        parent_pid,
        name: child_name,
        state: ProcessState::Active,
        cr3: child_cr3,
        threads: Vec::from([child_tid]),
        exit_code: 0,
        file_descriptors: fds,
        cwd,
        uid: parent_uid,
        gid: parent_gid,
        euid: parent_euid,
        egid: parent_egid,
        pgid: parent_pgid,
        sid: parent_sid,
        no_new_privs: parent_no_new_privs,
        cap_permitted: parent_cap_permitted,
        cap_effective: parent_cap_effective,
        rlimits_soft: parent_rlimits_soft,
        supplementary_groups: parent_groups,
        umask: parent_umask,
        vm_space: child_vm_space,
        signal_state: Some(crate::signal::SignalState::new()),
        linux_abi: parent_linux_abi,
        handle_table: Some(crate::ob::handle::HandleTable::new()),
        subsystem: parent_subsystem,
        token_id: parent_token_id,
        // POSIX: the executable identity survives fork(2).  /proc/self/exe in
        // the child must resolve to the same image as the parent until the
        // child calls execve(2).  Linux propagates `mm->exe_file` through
        // copy_mm()/dup_mm(); we mirror that by cloning `parent.exe_path`.
        exe_path: parent_exe_path,
        epoll_sets: alloc::vec::Vec::new(),
        auxv: Vec::new(),
        envp: Vec::new(),
        // POSIX: alarm state is NOT inherited across fork (POSIX.1-2008 §2.4)
        alarm_deadline_ticks: 0,
        alarm_interval_ticks: 0,
        pdeath_signal: 0,
    };

    let child_thread = Thread {
        tid: child_tid,
        pid: child_pid,
        // Start Blocked so sys_fork_impl can write fork_user_regs before the
        // child is scheduled.  unblock_process() is called after set_fork_user_regs().
        state: ThreadState::Blocked,
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: kstack_span,
        wake_tick: u64::MAX,
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: user_rip, // clone3 handler overrides with original_rip + func/arg
        user_entry_rsp: user_rsp,
        user_entry_rdx: 0,
        user_entry_r8:  0,
        priority: PRIORITY_NORMAL,
        base_priority: PRIORITY_NORMAL,
        tls_base: parent_tls_base, // inherit parent's FS.base so fork child has working TLS
        cpu_affinity: None,
        last_cpu: 0,
        first_run: true, // goes through user_mode_bootstrap (CR3 switch, TSS, TLS)
        ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
        clear_child_tid: 0,
        // Propagate parent's callee-saved regs (RBP/RBX/R12-R15) into the child.
        // glibc's _Fork@@GLIBC_2.34 epilogue reads `-0x18(%rbp)` for its stack
        // canary check immediately after the clone3 syscall — if %rbp is zero
        // in the child the load faults at -0x18 and the child dies before any
        // IPC handshake.  Per POSIX clone(2), callee-saved registers must be
        // unchanged in the child relative to the parent's clone() callsite.
        fork_user_regs: *parent_regs,
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
        vfork_isolated_stack: None,
        vfork_isolated_tls: None,
    };

    PROCESS_TABLE.lock().push(child_proc);
    THREAD_TABLE.lock().push(child_thread);
    proc_metrics::register(child_pid);

    crate::serial_println!(
        "[PROC] fork: child PID {} TID {} (parent PID {}, CoW={})",
        child_pid, child_tid, parent_pid, user_rip != 0
    );
    note_if_emergency_kstack(child_pid, child_tid, stack_base, kstack_span);
    note_kstack_alloc(child_pid, child_tid, stack_base, kstack_span);

    Some((child_pid, child_tid))
}

/// Fork a process under `CLONE_VM` semantics: the child shares the parent's
/// virtual memory (no copy-on-write).  Writes by the child are immediately
/// visible to the parent and vice-versa.
///
/// This mirrors `fork_process` but skips the page-table clone step and instead
/// reuses the parent's `cr3` directly.  The child's `Process` carries
/// `vm_space = None` so that `free_process_memory` / `free_vm_space` are no-ops
/// on the child's exit path — the parent retains exclusive ownership of the
/// address space.
///
/// Per `clone3(2)`: when `CLONE_VM` is specified without `CLONE_THREAD`, glibc
/// uses this path to implement both `vfork(2)` and the `posix_spawn(3)`
/// fast-path (`__spawnix`).  The child typically calls `execve(2)` shortly
/// after — at which point a fresh VmSpace replaces the shared one.
///
/// The caller is responsible for:
///  - Overriding `user_entry_rip`, `user_entry_rsp`, `user_entry_rdx`,
///    `user_entry_r8` on the child thread before unblocking, so the child
///    lands at the clone3 return site with the new stack and helper-fn args.
///  - Setting `vfork_parent_tid` and blocking the parent when `CLONE_VFORK`
///    is also set.
pub fn fork_process_share_vm(
    parent_pid: Pid,
    _parent_tid: Tid,
    parent_regs: &ForkUserRegs,
) -> Option<(Pid, Tid)> {
    let child_pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let child_tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    // Allocate a fresh kernel stack for the child.  Kernel stacks are never
    // shared — only user-mode memory follows `CLONE_VM`.
    let (stack_base, stack_top) = alloc_kernel_stack()?;
    let kstack_span = stack_top - stack_base; // honest span (may be 4 KiB)

    // Copy parent's file descriptors, CWD, and security credentials.
    // Per clone(2)/clone3(2):
    //   - WITH CLONE_FILES, the child SHARES the parent's descriptor table
    //     (writes are mutually visible).
    //   - WITHOUT CLONE_FILES, the child gets its OWN COPY of the parent's
    //     table at clone time (independent after that point).
    // We always copy — the safer of the two semantics for callers that
    // forgot CLONE_FILES.  The posix_spawn(3) fast-path (__spawnix → execve)
    // then drops any FDs flagged O_CLOEXEC / FD_CLOEXEC at execve time;
    // FDs without CLOEXEC survive into the new image, which is the
    // intended POSIX behaviour.
    let (fds, cwd, parent_name, parent_uid, parent_gid, parent_euid, parent_egid,
         parent_groups, parent_umask, parent_linux_abi, parent_subsystem, parent_token_id,
         parent_pgid, parent_sid, parent_no_new_privs, parent_cap_permitted,
         parent_cap_effective, parent_rlimits_soft, parent_cr3, parent_exe_path) = {
        let procs = PROCESS_TABLE.lock();
        let parent = procs.iter().find(|p| p.pid == parent_pid)?;
        (
            parent.file_descriptors.clone(),
            parent.cwd.clone(),
            parent.name,
            parent.uid, parent.gid, parent.euid, parent.egid,
            parent.supplementary_groups.clone(),
            parent.umask, parent.linux_abi, parent.subsystem, parent.token_id,
            parent.pgid, parent.sid, parent.no_new_privs,
            parent.cap_permitted, parent.cap_effective, parent.rlimits_soft,
            parent.cr3,
            parent.exe_path.clone(),
        )
    };

    // Bump socket fd refcounts for the duplicated table (same rationale as
    // fork_process — POSIX.1-2017 §2.14 / man 2 fork).
    inc_socket_refs_for_fork(&fds);
    // And bump pipe fd refcounts so the parent's posix_spawn cancel-pipe
    // (and any other inherited pipe end) survives until BOTH the parent's
    // copy AND the child's copy are closed.  See `inc_pipe_refs_for_fork`.
    inc_pipe_refs_for_fork(&fds);

    // RLIMIT_NPROC.
    {
        let procs = PROCESS_TABLE.lock();
        let count = procs.iter().filter(|p| p.state != ProcessState::Zombie).count();
        if count >= parent_rlimits_soft[6] as usize {
            return None; // EAGAIN
        }
    }

    // Read parent's user-mode return site and TLS base.  RIP/RSP from the
    // parent's syscall frame; the caller will override them per clone_args.
    let (user_rip, user_rsp, parent_tls_base) = {
        let threads = THREAD_TABLE.lock();
        if let Some(parent_thread) = threads.iter().find(|t| t.tid == _parent_tid) {
            let tls = parent_thread.tls_base;
            if parent_thread.kernel_stack_base > 0 && parent_thread.kernel_stack_size > 0 {
                let kstack_top = parent_thread.kernel_stack_base + parent_thread.kernel_stack_size;
                unsafe {
                    let rip = *((kstack_top - 16) as *const u64);
                    let rsp = *((kstack_top - 8) as *const u64);
                    (rip, rsp, tls)
                }
            } else { (0u64, 0u64, tls) }
        } else { (0u64, 0u64, 0u64) }
    };

    // Map the signal-return trampoline into the (shared) parent CR3.  This is
    // idempotent — `map_trampoline` already accepts being called against a
    // CR3 that has the trampoline mapped.
    crate::signal::map_trampoline(parent_cr3);

    // Build the child's kernel stack with the standard user_mode_bootstrap
    // entry path.  user_mode_bootstrap will load user_entry_rip/rsp/rdx/r8
    // from the THREAD_TABLE and IRETQ to Ring 3.
    let initial_rsp = thread::init_thread_stack(
        stack_top, crate::proc::usermode::user_mode_bootstrap as *const () as u64,
    );

    let context = CpuContext {
        rsp: initial_rsp,
        rbp: 0,
        rbx: crate::proc::thread::fixup_fn_ptr(
            crate::proc::usermode::user_mode_bootstrap as *const () as u64
        ),
        r12: 0, r13: 0, r14: 0, r15: 0,
        rflags: 0x202,
        cr3: parent_cr3, // SHARED — same page tables as parent
    };

    // Child name = parent name + ".vm" suffix for debug logs.
    let mut child_name = [0u8; 64];
    let name_len = parent_name.iter().position(|&b| b == 0).unwrap_or(parent_name.len());
    let base_len = name_len.min(60);
    child_name[..base_len].copy_from_slice(&parent_name[..base_len]);
    let suffix = b".vm";
    let suf_len = suffix.len().min(64 - base_len);
    child_name[base_len..base_len+suf_len].copy_from_slice(&suffix[..suf_len]);

    let mut thread_name = [0u8; 32];
    thread_name[..4].copy_from_slice(b"main");

    let child_proc = Process {
        pid: child_pid,
        parent_pid,
        name: child_name,
        state: ProcessState::Active,
        cr3: parent_cr3, // SHARED — scheduler will load the parent's PML4
        threads: Vec::from([child_tid]),
        exit_code: 0,
        file_descriptors: fds,
        cwd,
        uid: parent_uid, gid: parent_gid, euid: parent_euid, egid: parent_egid,
        pgid: parent_pgid, sid: parent_sid,
        no_new_privs: parent_no_new_privs,
        cap_permitted: parent_cap_permitted,
        cap_effective: parent_cap_effective,
        rlimits_soft: parent_rlimits_soft,
        supplementary_groups: parent_groups,
        umask: parent_umask,
        // vm_space = None signals "shared address space owned by parent".
        // free_process_memory / free_vm_space short-circuit on None, so
        // child exit never touches the parent's page tables or frames.
        vm_space: None,
        signal_state: Some(crate::signal::SignalState::new()),
        linux_abi: parent_linux_abi,
        handle_table: Some(crate::ob::handle::HandleTable::new()),
        subsystem: parent_subsystem,
        token_id: parent_token_id,
        // Per POSIX clone(2)/fork(2): the child's executable identity matches
        // the parent until/unless the child execve(2)s.  /proc/self/exe must
        // therefore resolve to the parent's exe path immediately after the
        // clone returns — critical for posix_spawn(3) middleware that calls
        // `readlink("/proc/self/exe")` *before* the exec stage runs.
        exe_path: parent_exe_path,
        epoll_sets: alloc::vec::Vec::new(),
        auxv: Vec::new(),
        envp: Vec::new(),
        alarm_deadline_ticks: 0,
        alarm_interval_ticks: 0,
        pdeath_signal: 0,
    };

    let child_thread = Thread {
        tid: child_tid,
        pid: child_pid,
        // Start Blocked so the clone3 dispatcher can fill user_entry_*
        // before the scheduler picks the child.
        state: ThreadState::Blocked,
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: kstack_span,
        wake_tick: u64::MAX,
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: user_rip, // overridden by clone3 dispatcher
        user_entry_rsp: user_rsp,
        user_entry_rdx: 0,
        user_entry_r8:  0,
        priority: PRIORITY_NORMAL,
        base_priority: PRIORITY_NORMAL,
        // TLS base starts at 0 here so a CLONE_VM|CLONE_VFORK child cannot
        // read the parent's stack-protector canary at `%fs:0x28`.  See the
        // unconditional WRMSR site in `proc::usermode::enter_user_mode`
        // (~L347-353): when `tls_base == 0` the user-mode entry path
        // explicitly zeros FS.base via WRMSR before jumping to user mode.
        // Skipping that WRMSR (i.e. inheriting the parent's FS.base by
        // leaving the MSR alone) would let the child's stack-guard epilogue
        // read a valid-looking parent canary from %fs:0x28 and so corrupt
        // the SSP comparison.
        //
        // For the `posix_spawn(3)` child path, the clone(2) dispatcher
        // (kernel/src/subsys/linux/syscall.rs arm 56) immediately calls
        // `alloc_vfork_child_tls(parent_pid)` to provision a fresh, zeroed,
        // child-private TCB page mapped into the shared address space and
        // overwrites `tls_base` here with the returned VA.  The new page
        // preserves the canary-isolation invariant (its byte at +0x28 is 0,
        // not the parent's canary) while giving the child a valid `%fs:0`
        // self-pointer so the first cancellable libc syscall (`close(2)`)
        // does not fault.  See `alloc_vfork_child_tls` for the layout and
        // the System V x86_64 ABI §3.4.2 / ELF gABI §3.5 references.
        //
        // Refs: POSIX clone(2) / vfork(2) / posix_spawn(3);
        //       System V x86_64 ABI §3.4.2 (TLS / Variant II);
        //       Intel SDM Vol. 3A §3.4.4, §6.8 (WRMSR FS_BASE).
        tls_base: 0,
        cpu_affinity: None,
        last_cpu: 0,
        first_run: true,
        ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
        clear_child_tid: 0,
        fork_user_regs: *parent_regs,
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
        vfork_isolated_stack: None,
        vfork_isolated_tls: None,
    };

    PROCESS_TABLE.lock().push(child_proc);
    THREAD_TABLE.lock().push(child_thread);
    proc_metrics::register(child_pid);

    crate::serial_println!(
        "[PROC] fork_share_vm: child PID {} TID {} (parent PID {} CR3={:#x}, shared)",
        child_pid, child_tid, parent_pid, parent_cr3
    );
    note_if_emergency_kstack(child_pid, child_tid, stack_base, kstack_span);
    note_kstack_alloc(child_pid, child_tid, stack_base, kstack_span);

    // VFORK/CHILD-STACK diagnostic — record the child's initial user RSP at
    // *clone-time*.  The value here is the parent-frame RSP as captured by
    // `fork_process_share_vm`; the caller (`syscall.rs` arm 56) substitutes
    // a kernel-allocated isolated stack via `alloc_vfork_child_stack` before
    // the child is unblocked, so the runtime `user_entry_rsp` the child
    // actually starts on is NOT the value shown here (see the subsequent
    // `[VFORK-STACK] alloc base=… top=… new_rsp=…` line for the substituted
    // RSP).  This print is therefore captured *before* the RSP swap and is
    // cosmetic only — included for the historical record of which parent
    // frame the caller passed.  Per POSIX vfork(2) and clone(2) "CLONE_VM"
    // the child shares the parent's address space; the kernel does not
    // carve out a private stack on its own, but the syscall.rs arm 56 path
    // does it for vfork-shaped clones so the child cannot overflow into
    // an SSP-instrumented parent frame (ELF gABI §6 stack-protector).
    let parent_frame_rsp_at_clone = user_rsp;
    let child_uses_parent_frame_at_clone = user_rsp != 0;
    crate::serial_println!(
        "[VFORK/CHILD-STACK] pid={} parent_pid={} parent_frame_rsp_at_clone={:#x} \
         child_uses_parent_frame_at_clone={} note=runtime_rsp_substituted_by_caller \
         parent_tls_base={:#x} child_tls_base=0",
        child_pid, parent_pid,
        parent_frame_rsp_at_clone,
        child_uses_parent_frame_at_clone,
        parent_tls_base,
    );

    Some((child_pid, child_tid))
}

/// Allocate an **isolated user-mode stack** for a `CLONE_VM|CLONE_VFORK` child
/// so that the child's stack growth cannot clobber the parent's stack region
/// while the address space is shared.
///
/// # Why this exists
///
/// Some libc `posix_spawn(3)` implementations (and the underlying
/// `posix_spawnp(3)`) place the child's stack as an on-stack local of the
/// **parent's `posix_spawn()` frame**, roughly:
///
/// ```c
/// char stack[1024+PATH_MAX];
/// pid = __clone(child, stack+sizeof stack,
///               CLONE_VM|CLONE_VFORK|SIGCHLD, &args);
/// ```
///
/// `1024 + PATH_MAX = 1024 + 4096 = 5120` bytes — small enough that the
/// child helper can overflow it after a chain of `sigaction` /
/// `pthread_sigmask` / `execve` setup calls.  Once the child's RSP descends
/// past `&stack[0]` it lands in the parent's neighbouring frame:
/// `posix_spawn()` locals (`args`, `ec`, `cs`, ...) first, then the caller
/// frame of `posix_spawn()` (typically libxul's spawn shim), and so on
/// upward through the call chain.
///
/// `CLONE_VFORK` suspends the parent — the parent does not *execute*
/// instructions while the child is alive — but the corrupted parent-stack
/// bytes are not restored when the parent resumes.  In particular,
/// stack-protector instrumented callers (SSP-enabled libxul) save the canary
/// **on the stack** in their prologue and re-read it in the epilogue; if the
/// child overwrote that copy, the epilogue compares the corrupted value
/// against `fs:0x28` and triggers `__stack_chk_fail` → `a_crash` → #GP.
///
/// # What this helper does
///
/// 1. Allocates a 64 KiB anonymous VMA in the shared address space (parent's
///    `VmSpace`, which the child is borrowing via the shared `cr3`).
/// 2. Eagerly maps the top 4 KiB page of that VMA so the kernel can write the
///    libc-pushed `arg` word into it without faulting; lower pages remain
///    demand-paged by the standard PFH.
/// 3. Reads the 8-byte word at the parent-supplied `new_stack` address —
///    the canonical x86_64 SysV `__clone` preamble writes the helper's `arg`
///    pointer there immediately before the syscall via `mov %rcx, (%rsi)`.
///    After the child wakes, its first user instructions are
///    `pop %rdi; call *%r9`, which expect `arg` to be at the very top of its
///    stack.
/// 4. Writes that `arg` word to the corresponding slot in the new isolated
///    stack so the child's `pop %rdi` reads the right value.
/// 5. Returns the new RSP value (`new_top - 8`) for the caller to install on
///    `Thread.user_entry_rsp` in place of the parent-frame `new_stack`.
///
/// # Cleanup
///
/// The base+length of the isolated stack is recorded by the caller on
/// `Thread.vfork_isolated_stack`.  It is unmapped from the parent's address
/// space in two places:
///   * `execve(2)` case (C) — `syscall::sys_exec` after the new VmSpace is
///     installed and the parent is woken via `wake_vfork_parent()`.
///   * Vfork-child exit (`exit`, `exit_group`, or fatal signal) — via
///     `vfork_isolated_stack_cleanup()` invoked from the thread-exit path.
///
/// # References
///
/// * POSIX `vfork(2)` / `posix_spawn(3)`
/// * Linux `clone(2)` / `clone3(2)` (ABI for the `stack` argument)
/// * x86_64 SysV ABI - calling convention for the `__clone` shim
/// * ELF gABI §6 (stack-protector canary placement)
pub fn alloc_vfork_child_stack(parent_pid: Pid, parent_new_stack: u64) -> Option<u64> {
    use crate::mm::vma::{VmArea, VmBacking, VmaError,
                         PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_STACK,
                         page_align_up};
    use crate::mm::vmm::{PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER, PAGE_NO_EXECUTE};

    // Stack size for the isolated VMA.  64 KiB is far larger than any path
    // the libc child-helper can realistically push (a few hundred bytes of
    // sigaction loops + execve preamble), but small enough that leaking one
    // per posix_spawn invocation between vfork start and execve completion
    // costs at most a few hundred KiB in steady state.
    const VFORK_STACK_SIZE: u64 = 64 * 1024;

    // -- Phase 0: validate the attacker-controlled `parent_new_stack` pointer.
    //
    // `parent_new_stack` is arg2 of `clone(2)` and is fully attacker-controlled
    // from userspace.  Phase 1 below dereferences it inside a `UserGuard`
    // (SMAP-disabled) bracket, which means a kernel-VA value would let an
    // unprivileged caller read 8 bytes of arbitrary kernel memory via the
    // ABI's normal return path.  Per Intel SDM Vol. 3A §4.6 SMAP only blocks
    // userspace pointers being dereferenced WITHOUT an explicit AC toggle;
    // the kernel is responsible for input validation before any STAC.
    //
    // Per POSIX `clone(2)`, `new_stack` must reference an address in the
    // calling process's address space; per the SysV x86_64 ABI the libc
    // `__clone` preamble writes the arg word at `(%rsi)` as a 8-byte store,
    // so an 8-byte-misaligned value cannot be the genuine output of the
    // preamble and is also rejected to keep the read path well-defined.
    //
    // Refs: POSIX clone(2), Intel SDM Vol. 3A §4.6, CWE-822, CWE-200.
    if !crate::syscall::validate_user_ptr(parent_new_stack, 8) {
        return None;
    }
    if parent_new_stack & 0x7 != 0 {
        return None;
    }

    // -- Phase 1: read the helper-arg word the libc preamble pushed onto the
    // parent stack.
    //
    // We are still executing in the parent's syscall context, so the user-VA
    // `parent_new_stack` is directly readable under SMAP.  The 8-byte read
    // is what the libc `__clone` shim wrote via `mov %rcx,(%rsi)`; the child
    // will `pop %rdi` from this slot as its first user instruction.
    let arg_word: u64 = unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::ptr::read(parent_new_stack as *const u64)
    };

    // ── Phase 2: locate the parent's VmSpace and pick a free address range.
    //
    // Route through `find_free_stack_range` (dedicated stack-ASLR window,
    // per-process base + per-call jitter, disjoint from the general
    // mmap downward walk) rather than the bare `find_free_range`.  This
    // matches the routing in `syscall::sys_mmap` for `MAP_STACK |
    // MAP_ANONYMOUS` non-FIXED allocations and gives the vfork child's
    // isolated stack the same per-spawn entropy.  See `mm::vma::STACK_ASLR_MIN`
    // for the layout rationale.  Falls through to `find_free_range`
    // internally when the window is full, so behaviour is at least as
    // permissive as before.
    let length = page_align_up(VFORK_STACK_SIZE);
    let (parent_cr3, base) = {
        let mut procs = PROCESS_TABLE.lock();
        let p = procs.iter_mut().find(|p| p.pid == parent_pid)?;
        let space = p.vm_space.as_mut()?;
        let base = space.find_free_stack_range(length)?;

        // Insert the VMA so subsequent page-faults inside the range are
        // demand-paged by the standard handler.  We also pre-map the top
        // page below (Phase 3) so the immediate `pop %rdi` succeeds without
        // ever entering the PFH.
        let vma = VmArea {
            base,
            length,
            prot: PROT_READ | PROT_WRITE,
            flags: MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
            backing: VmBacking::Anonymous,
            name: "[vfork-stack]",
        };
        if let Err(VmaError::Overlap) = space.insert_vma(vma) {
            // Should never happen — find_free_range just told us this range
            // was clear.  Bail rather than corrupting the VMA list.
            return None;
        }
        (p.cr3, base)
    };

    // ── Phase 3: eagerly back the top page with a fresh frame, write the
    // helper-arg word at `top - 8`, and install a writable user PTE.
    //
    // The page must be writable + user + non-executable.  We don't bother
    // pre-mapping the rest of the VMA — the PFH will allocate frames as the
    // child grows the stack downward (typical: only the top few pages get
    // touched before the child execve's).
    let top = base + length;
    let top_page_va = top - 0x1000;
    let frame = crate::mm::pmm::alloc_page()?;
    // Zero the frame and write the arg word at offset 0xff8 (== top - 8 mod 4 KiB).
    // PHYS_OFF = higher-half physical→virtual identity offset (kernel.org
    // documents this layout informally; locally it is `0xFFFF_8000_0000_0000`).
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    unsafe {
        let kva = (PHYS_OFF + frame) as *mut u8;
        core::ptr::write_bytes(kva, 0, 4096);
        core::ptr::write((kva.add(0x1000 - 8)) as *mut u64, arg_word);
    }
    // Track B (Phase 5, 2026-05-21) — record this kernel-direct-map write
    // into the stack-page provenance ring.  The write is invisible to
    // `f3-watch`'s DR0–DR3 channel because it goes through `PHYS_OFF +
    // frame`, not through the user-VA mapping.  Per Intel SDM Vol. 3B
    // §17.2.4 data-breakpoint watchpoints trap on linear-VA only.  The
    // VA we report (`top - 8`) is what the helper-arg word will appear
    // at once the PTE below is installed — the same VA the child's
    // `pop %rdi` will read it from.
    #[cfg(feature = "stack-prov")]
    crate::mm::stack_prov::record_write(
        top - 8,
        arg_word,
        crate::mm::stack_prov::SITE_VFORK_STACK_SEED,
    );
    let flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER | PAGE_NO_EXECUTE;
    if !crate::mm::vmm::map_page_in(parent_cr3, top_page_va, frame, flags) {
        // Map failed — free the frame and bail.  The VMA stays in the parent's
        // list and will be cleaned up at the next address-space teardown.
        crate::mm::pmm::free_page(frame);
        return None;
    }
    // Bump the page refcount so the unmap path drops it cleanly later.
    crate::mm::refcount::page_ref_inc(frame);

    crate::serial_println!(
        "[VFORK-STACK] alloc base={:#x} top={:#x} new_rsp={:#x} arg={:#x} (parent_rsp={:#x})",
        base, top, top - 8, arg_word, parent_new_stack
    );

    Some(top - 8)
}

/// Tear down an isolated vfork-child stack VMA from the **parent's** address
/// space.  Called from `execve(2)` (case C — shared-VM child installing a
/// fresh image) and from the vfork-child exit path.
///
/// The caller passes the `(base, length)` previously recorded on
/// `Thread.vfork_isolated_stack` plus the parent's `cr3`.  The VMA's pages
/// are unmapped via `unmap_and_free_range_in` (which decrements refcounts
/// and frees frames whose ref reaches zero) and the VmSpace entry is
/// removed via `remove_range`.
///
/// Safe to call multiple times — repeated calls on the same `(base, length)`
/// are no-ops because the VMA / PTEs have already been removed.
pub fn vfork_isolated_stack_cleanup(parent_pid: Pid, base: u64, length: u64) {
    // First unmap the PTEs and free the physical frames in the parent's CR3.
    let parent_cr3 = {
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == parent_pid).map(|p| p.cr3).unwrap_or(0)
    };
    if parent_cr3 == 0 { return; }

    let unmapped = crate::mm::vmm::unmap_and_free_range_in(parent_cr3, base, length);

    // Then remove the VMA entry from the parent's VmSpace.
    {
        let mut procs = PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == parent_pid) {
            if let Some(space) = p.vm_space.as_mut() {
                let _ = space.remove_range(base, length);
            }
        }
    }

    crate::serial_println!(
        "[VFORK-STACK] cleanup parent_pid={} cr3={:#x} base={:#x} length={:#x} unmapped_pages={}",
        parent_pid, parent_cr3, base, length, unmapped
    );
}

/// Allocate a **minimal per-vfork-child TLS page** so that the child's
/// `%fs:0`-relative reads do not fault before `execve(2)` can install a
/// fresh image.
///
/// # Why this exists
///
/// Per the System V x86_64 ABI §3.4.2 ("Thread-Local Storage") and the ELF
/// gABI §3.5, the Variant II TLS model on x86_64 places a "thread-control
/// block" (TCB) at the address the FS segment base points to.  The first
/// 8 bytes of the TCB are required to be a self-pointer: every TLS-relative
/// helper in libc starts by issuing `mov %fs:0,%REG` to materialise the
/// TCB address.  See also Intel SDM Vol. 3A §3.4.4 for `FS_BASE` / `GS_BASE`
/// segmentation semantics in 64-bit mode.
///
/// `CLONE_VM|CLONE_VFORK` children inherit `tls_base = 0` (set by
/// `fork_process_share_vm`).  This is the safer choice for stack-protector
/// canary isolation — see the comment on the Thread initializer there —
/// but it leaves the child unable to read its own TCB.  The first thing
/// the `posix_spawn(3)` child helper does after the `clone(2)` syscall
/// returns is invoke `close(2)` to drop the parent-pipe write fd; per
/// POSIX, `close(3)` is a cancellation point, so the libc routes through
/// its cancellable-syscall wrapper which reads `%fs:0` to materialise the
/// thread pointer.  With `tls_base == 0` that first deref faults at VA 0.
///
/// # What this helper does
///
/// 1. Allocates a 4 KiB anonymous VMA in the shared address space.
/// 2. Backs it with a fresh, zeroed page.  Zeroed bytes give the child a
///    safe-by-default TCB: a 0 canary at `%fs:0x28`, a 0 cancel flag, etc.
///    None of those values aliases the parent's, so the `tls_base = 0`
///    invariant's intent (no canary leakage from the parent's TLS) is
///    preserved.
/// 3. Writes the TCB self-pointer at offset 0 — the ABI-required field
///    every libc-TLS read starts with.
/// 4. Writes the per-thread cancel-state byte at offset 64 to a non-zero
///    value so the cancellable-syscall wrapper short-circuits to the raw
///    `__syscall(2)` path — matching the parent's own behaviour, which
///    already called `pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, …)`
///    around the `clone(2)` per POSIX `posix_spawn(3)`.
/// 5. Maps the page with PRESENT|WRITABLE|USER|NX into the parent's CR3 so
///    the child (which runs on `parent_cr3`) can read and write it without
///    invoking the page-fault handler.
/// 6. Returns the base VA (== TCB self-pointer value).  The caller stores
///    it in `Thread.tls_base` and the user-mode entry path writes it to
///    `FS_BASE` (MSR `0xC000_0100`) before IRETQ to Ring 3.
///
/// # Why this is safe vs. the canary-isolation goal
///
/// The original `tls_base = 0` choice existed to guarantee the child could
/// NOT read the parent's canary at `%fs:0x28`.  Routing the child's
/// FS.base to a fresh, zero-initialised page achieves the same isolation:
/// byte 0x28 of the new page is 0, not the parent's canary.  An
/// SSP-instrumented function inside the child pushes 0 to its frame in
/// prologue and compares against 0 in epilogue — canary self-consistent
/// within the child.  The parent never reads this page because (a) the
/// parent is blocked in `vfork(2)` until the child execs/exits, and (b)
/// on resume the parent's FS.base is its own (unchanged) TCB.
///
/// # Cleanup
///
/// The base+length is recorded on `Thread.vfork_isolated_tls` and unmapped
/// at the same three sites that release `vfork_isolated_stack`:
///   * `execve(2)` case (C) — `syscall::sys_exec` after the new VmSpace is
///     installed and the parent is woken via `wake_vfork_parent()`.
///   * Vfork-child exit (`exit`, `exit_group`, or fatal signal) — via
///     `vfork_isolated_tls_cleanup()` from the thread-exit path.
///
/// # References
///
/// * POSIX `vfork(2)` / `posix_spawn(3)` / `pthread_setcancelstate(3)`
/// * System V x86_64 ABI §3.4.2 (TLS / Variant II)
/// * ELF gABI §3.5 (Thread-local storage)
/// * Intel SDM Vol. 3A §3.4.4 (FS / GS segment base in 64-bit mode)
/// * Intel SDM Vol. 3A §4.6 (SMAP semantics)
pub fn alloc_vfork_child_tls(parent_pid: Pid) -> Option<u64> {
    use crate::mm::vma::{VmArea, VmBacking, VmaError,
                         PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS,
                         page_align_up};
    use crate::mm::vmm::{PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER, PAGE_NO_EXECUTE};

    // One 4 KiB page is sufficient: the runtime TCB plus the handful of
    // bytes the cancellable-syscall path reads (`%fs:0` plus single-byte
    // fields near `+0x40`) all live within the first page.  The child
    // never enters the standard `__init_tls` block expansion before
    // `execve(2)` — execve installs a fresh image that runs its own
    // libc-init sequence.
    const VFORK_TLS_SIZE: u64 = 4096;

    // Cancel-state byte position inside the TCB.  Per POSIX
    // `pthread_setcancelstate(3)` and the SysV `<pthread.h>` ABI, the
    // `canceldisable` member of a `struct pthread` lands at byte offset 64
    // after `self`, `dtv`, `prev`, `next`, `sysinfo`, `canary` (6×8 = 48)
    // and the implementation-internal `tid`, `errno_val`, `detach_state`,
    // `cancel` (4×4 = 16).  PTHREAD_CANCEL_DISABLE == 1 per POSIX.
    const TCB_CANCELDISABLE_OFFSET: usize = 64;
    const PTHREAD_CANCEL_DISABLE: u8 = 1;

    let length = page_align_up(VFORK_TLS_SIZE);

    // ── Phase 1: locate the parent's VmSpace and find a free range.
    let (parent_cr3, base) = {
        let mut procs = PROCESS_TABLE.lock();
        let p = procs.iter_mut().find(|p| p.pid == parent_pid)?;
        let space = p.vm_space.as_mut()?;
        let base = space.find_free_range(length)?;

        let vma = VmArea {
            base,
            length,
            prot: PROT_READ | PROT_WRITE,
            flags: MAP_PRIVATE | MAP_ANONYMOUS,
            backing: VmBacking::Anonymous,
            name: "[vfork-tls]",
        };
        if let Err(VmaError::Overlap) = space.insert_vma(vma) {
            return None;
        }
        (p.cr3, base)
    };

    // ── Phase 2: allocate the backing frame, zero it, and lay down the
    // minimal TCB: self-pointer at offset 0; cancel-state byte at offset 64.
    let frame = crate::mm::pmm::alloc_page()?;
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    unsafe {
        let kva = (PHYS_OFF + frame) as *mut u8;
        core::ptr::write_bytes(kva, 0, 4096);
        core::ptr::write(kva as *mut u64, base);
        *kva.add(TCB_CANCELDISABLE_OFFSET) = PTHREAD_CANCEL_DISABLE;
    }
    // Track B (Phase 5, 2026-05-21) — record the TCB self-pointer write
    // and the cancel-disable byte write into the stack-prov ring.  The
    // VA reported for the self-pointer is `base` (where the TLS page is
    // about to be mapped); for the byte write we report
    // `base + TCB_CANCELDISABLE_OFFSET`.  See `mm/stack_prov.rs` for the
    // direct-map blind-spot rationale.
    #[cfg(feature = "stack-prov")]
    {
        crate::mm::stack_prov::record_write(
            base, base, crate::mm::stack_prov::SITE_VFORK_TLS_INIT,
        );
        crate::mm::stack_prov::record_write(
            base + TCB_CANCELDISABLE_OFFSET as u64,
            PTHREAD_CANCEL_DISABLE as u64,
            crate::mm::stack_prov::SITE_VFORK_TLS_INIT,
        );
    }

    let flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER | PAGE_NO_EXECUTE;
    if !crate::mm::vmm::map_page_in(parent_cr3, base, frame, flags) {
        crate::mm::pmm::free_page(frame);
        let mut procs = PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == parent_pid) {
            if let Some(space) = p.vm_space.as_mut() {
                let _ = space.remove_range(base, length);
            }
        }
        return None;
    }
    crate::mm::refcount::page_ref_inc(frame);

    crate::serial_println!(
        "[VFORK-TLS] alloc parent_pid={} cr3={:#x} base={:#x} length={:#x} \
         self_ptr={:#x} canceldisable_off={} canceldisable=1",
        parent_pid, parent_cr3, base, length, base, TCB_CANCELDISABLE_OFFSET
    );

    Some(base)
}

/// Tear down the per-vfork-child TLS page from the parent's address space.
/// Symmetric to `vfork_isolated_stack_cleanup`; safe to call multiple
/// times.
pub fn vfork_isolated_tls_cleanup(parent_pid: Pid, base: u64, length: u64) {
    let parent_cr3 = {
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == parent_pid).map(|p| p.cr3).unwrap_or(0)
    };
    if parent_cr3 == 0 { return; }

    let unmapped = crate::mm::vmm::unmap_and_free_range_in(parent_cr3, base, length);

    {
        let mut procs = PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == parent_pid) {
            if let Some(space) = p.vm_space.as_mut() {
                let _ = space.remove_range(base, length);
            }
        }
    }

    crate::serial_println!(
        "[VFORK-TLS] cleanup parent_pid={} cr3={:#x} base={:#x} length={:#x} unmapped_pages={}",
        parent_pid, parent_cr3, base, length, unmapped
    );
}

/// Apply `CLONE_CLEAR_SIGHAND` semantics to a process's signal-action table.
///
/// Per `clone3(2)`: every signal whose current handler is not `SIG_IGN` is
/// reset to `SIG_DFL`.  `SIG_IGN` is preserved.  `sa_flags` and `sa_mask` are
/// cleared for signals that get reset.
///
/// Returns `true` if the process was found and modified; `false` otherwise.
/// The signal-pending hint is recomputed to clear any stale bits implied by
/// the reset.
pub fn clear_sighand(pid: Pid) -> bool {
    let mut procs = PROCESS_TABLE.lock();
    let p = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return false,
    };
    let ss = match p.signal_state.as_mut() {
        Some(s) => s,
        None => return false,
    };
    for sig in 0..(crate::signal::MAX_SIGNAL as usize) {
        match ss.actions[sig] {
            crate::signal::SigAction::Ignore => {
                // SIG_IGN preserved across CLONE_CLEAR_SIGHAND.
            }
            _ => {
                ss.actions[sig] = crate::signal::SigAction::Default;
                ss.action_flags[sig] = 0;
                ss.action_mask[sig]  = 0;
            }
        }
    }
    true
}

/// Create a vfork child: new process (new PID) sharing the parent's address space.
///
/// Unlike `fork_process` (CoW clone), this shares the parent's CR3 directly.
/// The child MUST call execve() or _exit() — writing to shared memory is
/// undefined behavior (but works in practice for the vfork+exec pattern).
///
/// Linux equivalent: copy_process() with CLONE_VM flag.
pub fn vfork_process(parent_pid: Pid, parent_tid: Tid, parent_regs: &ForkUserRegs) -> Option<(Pid, Tid)> {
    let child_pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let child_tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    let (stack_base, stack_top) = alloc_kernel_stack()?;
    let kstack_span = stack_top - stack_base; // honest span (may be 4 KiB)

    // Copy parent's file descriptors and credentials.
    let (fds, cwd, parent_name, parent_cr3, parent_tls_base,
         parent_linux_abi, parent_pgid, parent_sid, parent_exe_path) = {
        let procs = PROCESS_TABLE.lock();
        let parent = procs.iter().find(|p| p.pid == parent_pid)?;
        let fds = parent.file_descriptors.clone();
        let cwd = parent.cwd.clone();
        let name = parent.name;
        (fds, cwd, name, parent.cr3, 0u64, parent.linux_abi, parent.pgid, parent.sid,
         parent.exe_path.clone())
    };

    // Bump socket fd refcounts for the duplicated table (same rationale as
    // fork_process — POSIX.1-2017 §2.14 / man 2 fork).
    inc_socket_refs_for_fork(&fds);
    // And pipe fd refcounts.
    inc_pipe_refs_for_fork(&fds);

    // Get parent's TLS base from thread struct.
    let parent_tls = {
        let threads = THREAD_TABLE.lock();
        threads.iter().find(|t| t.tid == parent_tid)
            .map(|t| t.tls_base).unwrap_or(0)
    };

    // Read user RIP/RSP from parent's kernel stack (syscall frame).
    let (user_rip, user_rsp) = {
        let threads = THREAD_TABLE.lock();
        if let Some(pt) = threads.iter().find(|t| t.tid == parent_tid) {
            if pt.kernel_stack_base > 0 && pt.kernel_stack_size > 0 {
                let kstack_top = pt.kernel_stack_base + pt.kernel_stack_size;
                unsafe {
                    let rip = *((kstack_top - 16) as *const u64);
                    let rsp = *((kstack_top - 8) as *const u64);
                    (rip, rsp)
                }
            } else { (0, 0) }
        } else { (0, 0) }
    };

    // The parent called clone() via glibc's __clone wrapper. The child's user_rip
    // from get_user_rip() points to the instruction AFTER the `syscall` in __clone:
    //   syscall            ; ← parent was here
    //   test rax, rax      ; ← user_rip points here (saved by SYSCALL hardware)
    //   jl .error
    //   je .child           ; ← child path: pop rax; pop rdi; call *rax (WRONG for vfork!)
    //   ret                 ; ← parent path: return to caller with RAX=child_pid
    //
    // The child path expects fn/arg on the stack (pushed by __clone's prologue).
    // But for vfork, the child shares the parent's stack which has no fn/arg.
    // Calling *rax would jump to garbage → crash.
    //
    // FIX: Skip the child path entirely. Set user_rip to the `ret` instruction
    // (parent return path). The child returns from clone() to the caller with
    // RAX=0, and the caller (Firefox) checks RAX to know it's the child.
    //
    // Layout: test(3B) + jl(2B) + je(2B) = 7 bytes from user_rip to ret.
    let child_rip = user_rip + 7; // skip test;jl;je → land on `ret`

    crate::serial_println!(
        "[VFORK] child PID {} CR3={:#x} rip={:#x}(+7={:#x}) rsp={:#x} tls={:#x}",
        child_pid, parent_cr3, user_rip, child_rip, user_rsp, parent_tls
    );

    // Build the fork child's kernel stack with pre-built IRETQ frame.
    // Child uses parent's RSP (shared address space). The child's `ret` from
    // clone() pops the correct return address from the parent's stack frame.
    // Note: the child may corrupt the parent's stack canary (causing "stack
    // smashing detected" in the child), but the parent continues fine.
    let initial_rsp = thread::init_fork_child_stack(
        stack_top, child_rip, user_rsp, parent_tls, parent_regs,
    );

    // Use the normal thread_entry_trampoline → user_mode_bootstrap path.
    // user_mode_bootstrap handles CR3 switch, TSS.RSP0, TLS, then IRETQ.
    // This avoids the ret_from_fork_asm CR3-skip bug.
    let initial_rsp = thread::init_thread_stack(
        stack_top, crate::proc::usermode::user_mode_bootstrap as *const () as u64,
    );

    let context = CpuContext {
        rsp: initial_rsp,
        rbp: 0,
        rbx: crate::proc::usermode::user_mode_bootstrap as *const () as u64,
        r12: 0, r13: 0, r14: 0, r15: 0,
        rflags: 0x202,
        cr3: parent_cr3,
    };

    let mut child_name = [0u8; 64];
    let name_len = parent_name.iter().position(|&b| b == 0).unwrap_or(parent_name.len()).min(57);
    child_name[..name_len].copy_from_slice(&parent_name[..name_len]);
    let suffix = b".vfork";
    let suf_len = suffix.len().min(64 - name_len);
    child_name[name_len..name_len+suf_len].copy_from_slice(&suffix[..suf_len]);

    let mut thread_name = [0u8; 32];
    thread_name[..4].copy_from_slice(b"main");

    let child_proc = Process {
        pid: child_pid,
        parent_pid,
        name: child_name,
        state: ProcessState::Active,
        cr3: parent_cr3, // SHARED with parent
        threads: Vec::from([child_tid]),
        exit_code: 0,
        file_descriptors: fds,
        cwd,
        uid: 0, gid: 0, euid: 0, egid: 0,
        pgid: parent_pgid, sid: parent_sid,
        no_new_privs: false,
        cap_permitted: 0, cap_effective: 0,
        rlimits_soft: default_rlimits(),
        supplementary_groups: Vec::new(),
        umask: 0o022,
        vm_space: None, // No VmSpace — shares parent's page tables directly
        signal_state: Some(crate::signal::SignalState::new()),
        linux_abi: parent_linux_abi,
        handle_table: Some(crate::ob::handle::HandleTable::new()),
        subsystem: crate::win32::SubsystemType::Native,
        token_id: None,
        // vfork child inherits the parent's executable identity until exec(2);
        // see fork_process for rationale (POSIX clone(2)/fork(2)).
        exe_path: parent_exe_path,
        epoll_sets: alloc::vec::Vec::new(),
        auxv: Vec::new(),
        envp: Vec::new(),
        alarm_deadline_ticks: 0,
        alarm_interval_ticks: 0,
        pdeath_signal: 0,
    };

    let child_thread = Thread {
        tid: child_tid,
        pid: child_pid,
        state: ThreadState::Ready, // Ready immediately (parent blocks itself)
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: kstack_span,
        wake_tick: u64::MAX,
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: child_rip, // skip clone child path → land on `ret`
        user_entry_rsp: user_rsp,  // parent's stack (shared vfork)
        user_entry_rdx: 0,         // RAX=0 (fork child return) set by jump_to_user_mode
        user_entry_r8: 0,
        priority: PRIORITY_NORMAL,
        base_priority: PRIORITY_NORMAL,
        tls_base: parent_tls,
        cpu_affinity: None,
        last_cpu: 0,
        first_run: true,  // Goes through user_mode_bootstrap (handles CR3, TSS, TLS)
        ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
        clear_child_tid: 0,
        // Propagate parent callee-saved regs into the vfork child for the same
        // reason as fork_process: glibc's clone wrapper / `_Fork` epilogue
        // touches %rbp on return.  Per POSIX clone(2).
        fork_user_regs: *parent_regs,
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
        vfork_isolated_stack: None,
        vfork_isolated_tls: None,
    };

    PROCESS_TABLE.lock().push(child_proc);
    THREAD_TABLE.lock().push(child_thread);
    proc_metrics::register(child_pid);
    note_if_emergency_kstack(child_pid, child_tid, stack_base, kstack_span);
    note_kstack_alloc(child_pid, child_tid, stack_base, kstack_span);

    Some((child_pid, child_tid))
}

/// Redirect a newly-spawned process's stdout (fd=1) and stderr (fd=2) to
/// the write-end of an anonymous pipe.  Call this immediately after
/// `create_user_process_with_args` returns, before the first scheduler tick
/// lets the child run.
///
/// The caller owns the pipe's read-end and must close it when done
/// (via `crate::ipc::pipe::pipe_close_reader`).
pub fn attach_stdout_pipe(pid: Pid, pipe_id: u64) {
    let write_fd = crate::vfs::FileDescriptor::pipe_write_end(pipe_id);
    // Also increment writers count so the pipe stays alive while both
    // fd=1 and fd=2 hold a reference.
    crate::ipc::pipe::pipe_add_writer(pipe_id);

    let mut procs = PROCESS_TABLE.lock();
    if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
        while proc.file_descriptors.len() <= 2 {
            proc.file_descriptors.push(None);
        }
        proc.file_descriptors[1] = Some(write_fd.clone());
        proc.file_descriptors[2] = Some(write_fd);
    }
}

/// Mark the initial thread of a process as Ready so the scheduler can run it.
///
/// Used together with `create_kernel_process_suspended` (or
/// `create_user_process_with_args_blocked`) to allow the caller to perform
/// setup (e.g. attaching pipe fds) before the thread can be scheduled.
pub fn unblock_process(pid: Pid) {
    let mut threads = THREAD_TABLE.lock();
    if let Some(t) = threads.iter_mut().find(|t| t.pid == pid && t.state == ThreadState::Blocked) {
        t.state = ThreadState::Ready;
    }
}

/// Wait for a child process to exit (reap a zombie).
///
/// `parent_pid`: the calling process.
/// `wait_pid`: specific PID to wait for, or -1 for any child.
///
/// Returns `Some((child_pid, exit_code))` if a zombie child is found, or `None`.
pub fn waitpid(parent_pid: Pid, wait_pid: i64) -> Option<(Pid, i32)> {
    // Step 1: Find and remove zombie child from PROCESS_TABLE.
    // Collect thread TIDs while we have the lock, but do NOT lock THREAD_TABLE
    // simultaneously — that causes ABBA deadlocks on SMP.
    let (child_pid, exit_code, thread_tids) = {
        let mut procs = PROCESS_TABLE.lock();

        let idx = procs.iter().position(|p| {
            p.parent_pid == parent_pid
                && p.state == ProcessState::Zombie
                && (wait_pid < 0 || p.pid == wait_pid as u64)
        })?;

        let child = &procs[idx];
        let pid = child.pid;
        let code = child.exit_code;
        let tids: Vec<Tid> = child.threads.clone();

        // Remove the child process entry.
        procs.remove(idx);

        (pid, code, tids)
    }; // PROCESS_TABLE lock dropped

    // Step 2: Reap the child's threads (THREAD_TABLE only).
    {
        let mut threads = THREAD_TABLE.lock();
        threads.retain(|t| !thread_tids.contains(&t.tid));
    }

    // Free per-process metrics slot so the PID can be reused.
    proc_metrics::unregister(child_pid);

    crate::serial_println!(
        "[PROC] waitpid: reaped PID {} (exit_code={})",
        child_pid, exit_code
    );

    Some((child_pid, exit_code))
}

/// Assign an access token to a process by PID.
pub fn assign_token(pid: u64, token_id: u64) {
    let mut procs = PROCESS_TABLE.lock();
    if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
        p.token_id = Some(token_id);
    }
}

/// Set the priority of a thread by TID.
/// Returns the previous priority, or `None` if the thread doesn't exist.
pub fn set_thread_priority(tid: Tid, priority: u8) -> Option<u8> {
    let priority = priority.min(PRIORITY_MAX);
    let mut threads = THREAD_TABLE.lock();
    if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
        let prev = t.priority;
        t.priority = priority;
        t.base_priority = priority;
        Some(prev)
    } else {
        None
    }
}

/// Get the priority of a thread by TID.
pub fn get_thread_priority(tid: Tid) -> Option<u8> {
    let threads = THREAD_TABLE.lock();
    threads.iter().find(|t| t.tid == tid).map(|t| t.priority)
}

/// Wait for a thread to exit.  Blocks the caller until the target thread
/// is in the Dead state.  Returns the exit code.
///
/// Uses true blocking via short sleeps and re-checking.
pub fn thread_join(target_tid: Tid) -> Option<i64> {
    loop {
        {
            let threads = THREAD_TABLE.lock();
            if let Some(t) = threads.iter().find(|t| t.tid == target_tid) {
                if t.state == ThreadState::Dead {
                    return Some(t.exit_code);
                }
            } else {
                return None; // thread doesn't exist (already reaped)
            }
        }
        // Sleep briefly (5 ticks = 50ms) and re-check.
        sleep_ticks(5);
    }
}

// ── TLS (Thread-Local Storage) ──────────────────────────────────────────────

/// MSR for FS base address (per-thread TLS).
const IA32_FS_BASE: u32 = 0xC000_0100;
/// MSR for GS base address (per-CPU data).
const IA32_GS_BASE: u32 = 0xC000_0101;
/// MSR for kernel GS base (swapped with SWAPGS).
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Size of the per-thread TLS area in bytes.
pub const TLS_SIZE: usize = 256;

/// Allocate a TLS area for the given thread and set its FS base.
/// Returns the base address, or None on allocation failure.
pub fn alloc_tls(tid: Tid) -> Option<u64> {
    let pages = (TLS_SIZE + 4095) / 4096;
    let base = crate::mm::pmm::alloc_pages(pages)?;
    // Zero the area.
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0, TLS_SIZE);
    }
    let mut threads = THREAD_TABLE.lock();
    if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
        t.tls_base = base;
    }
    Some(base)
}

/// Write the FS base MSR (per-thread TLS pointer).
///
/// # Safety
/// Must only be called with a valid virtual address.
pub unsafe fn write_fs_base(base: u64) {
    // FS_BASE-trace probe: record (old_fs, new_fs, caller_rip) into the
    // per-boot ring BEFORE the WRMSR so a later SSP-canary `#GP` can dump
    // the trapping TID's FS.base history.  Captures every write that
    // routes through this canonical kernel API: `restore_tls_for_current`
    // (scheduler context-switch, sched/mod.rs) and `enter_user_mode`
    // (boot, exec, fork-child bootstrap via `user_mode_bootstrap`).
    // Diagnostic-only; gated behind `fs-base-trace`.  Intel SDM Vol. 3A
    // §3.4.4.1 (`IA32_FS_BASE` MSR).
    #[cfg(feature = "fs-base-trace")]
    {
        let old_fs = crate::hal::rdmsr(IA32_FS_BASE);
        // Best-effort caller RIP: use the current `RIP` indirectly via
        // a return-address read.  The kernel-mode return address sits
        // at `[rsp + 0]` for an inlined frame, but `write_fs_base` is
        // marked `#[inline(never)]`-implicit via `pub unsafe fn`; just
        // pass 0 as the site marker — the kind+old/new pair already
        // names the path well enough.
        crate::subsys::linux::fs_base_trace::record_event(
            crate::subsys::linux::fs_base_trace::KIND_WRITE_FS_BASE,
            old_fs,
            base,
            0,
        );
    }

    // D7 PT_TLS BSS-slot watcher arm.  Triggered exactly once per boot
    // on the first qualifying `write_fs_base()` (pid=1, tid=1, zero →
    // non-zero transition), i.e. immediately before the firefox-bin
    // init thread first enters Ring 3.  All gating lives inside
    // `try_arm_after_fs_base_write`; the call site is unconditional
    // when the feature is enabled so a single read of FS.base feeds
    // both probes.  Diagnostic-only; gated behind `d7-bss-watch`.
    // Refs: Intel SDM Vol. 3B §17.2.4; ELF gABI §5.2; PSE Phase 4
    // dispatch in `docs/SC1171_PSE_END_TO_END_2026-05-22.md`.
    #[cfg(feature = "d7-bss-watch")]
    {
        let old_fs = crate::hal::rdmsr(IA32_FS_BASE);
        let pid = current_pid_lockless();
        let tid = current_tid();
        crate::subsys::linux::d7_bss_watch::try_arm_after_fs_base_write(
            pid as u64, tid as u64, old_fs, base,
        );
    }

    let lo = base as u32;
    let hi = (base >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") IA32_FS_BASE,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack)
    );
}

/// Write the GS base MSR (per-CPU data pointer).
///
/// # Safety
/// Must only be called with a valid virtual address.
pub unsafe fn write_gs_base(base: u64) {
    let lo = base as u32;
    let hi = (base >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") IA32_GS_BASE,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack)
    );
}

/// Restore the FS base for the current thread (called after context switch).
pub fn restore_tls_for_current() {
    let tid = current_tid();
    let base = {
        let threads = THREAD_TABLE.lock();
        threads.iter().find(|t| t.tid == tid).map(|t| t.tls_base).unwrap_or(0)
    };
    // Write unconditionally: if base==0 (vfork/CLONE_VM child that was never
    // assigned a TLS block) we must zero FS.base explicitly.  Skipping the
    // WRMSR would leave the previous thread's FS.base on this CPU, causing the
    // SSP epilogue to read the *parent's* canary and raise #GP.
    unsafe { write_fs_base(base); }
}

// ── Thread Reaper ───────────────────────────────────────────────────────────

/// Reap (remove) dead threads from the thread table, freeing their resources.
///
/// Skips thread 0 (idle thread) and any AP idle threads (TID >= 0x1000).
/// Returns the number of threads reaped.
pub fn reap_dead_threads() -> usize {
    let mut reaped = 0;
    let mut threads = THREAD_TABLE.lock();

    // Collect indices of dead threads to remove (skip idle threads).
    let dead_indices: Vec<usize> = threads.iter().enumerate()
        .filter(|(_, t)| t.is_reapable())
        .map(|(i, _)| i)
        .collect();

    // Remove in reverse order to keep indices stable.
    for &idx in dead_indices.iter().rev() {
        let t = &threads[idx];
        let stack_base = t.kernel_stack_base;
        let stack_pages = if t.kernel_stack_size > 0 {
            (t.kernel_stack_size as usize + 4095) / 4096
        } else {
            0
        };
        let tls = t.tls_base;

        // Remove from table
        threads.swap_remove(idx);
        reaped += 1;

        // Free kernel stack pages (convert higher-half back to physical).
        //
        // Zero each page before returning it to PMM.  A dead thread's
        // kernel stack contains saved register state (RIP, RSP, callee-
        // saved GPRs) and local kernel pointers that look like valid
        // kernel-space addresses (0xFFFF_8000… range).  PMM does not
        // zero on free or alloc, so a subsequent pmm::alloc_page call
        // from the page-cache fill path (or any other path that performs
        // a partial write) could expose these bytes to user-space.  The
        // unconditional wipe makes freed kernel-stack pages opaque — any
        // future short-read or partial-copy path sees zeros rather than
        // kernel pointer fragments.  Per Intel SDM Vol. 3A §4.10.5, the
        // hardware applies no such guarantee.
        if stack_base > 0 && stack_pages > 0 {
            let phys_base = if stack_base >= KERNEL_VIRT_OFFSET {
                stack_base - KERNEL_VIRT_OFFSET
            } else {
                stack_base // Legacy physical-address stacks (TID 0)
            };
            for p in 0..stack_pages {
                let pa = phys_base + (p * 4096) as u64;
                // SAFETY: the virtual address KERNEL_VIRT_OFFSET + pa is the
                // higher-half direct-map alias of this physical page.  The
                // thread has been removed from THREAD_TABLE; no other CPU
                // holds a reference to this stack (the context-switch path
                // ensures the thread is not scheduled after is_reapable()).
                unsafe {
                    core::ptr::write_bytes(
                        (KERNEL_VIRT_OFFSET + pa) as *mut u8,
                        0,
                        4096,
                    );
                }
                crate::mm::pmm::free_page(pa);
            }
        }

        // Free TLS area (1 page)
        if tls > 0 {
            crate::mm::pmm::free_page(tls);
        }
    }

    reaped
}
