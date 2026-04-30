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
pub mod thread;
pub mod usermode;

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
#[derive(Clone, Copy, Default)]
pub struct ForkUserRegs {
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
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
}

/// Next PID counter.
static NEXT_PID: AtomicU64 = AtomicU64::new(1);
/// Next TID counter.
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

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
/// Returns (stack_base_virt, stack_top_virt).
fn alloc_kernel_stack() -> Option<(u64, u64)> {
    // Try the dead-stack cache first — avoids PMM allocator overhead.
    if let Some(cached_base) = crate::sched::pop_dead_stack() {
        write_stack_canary(cached_base);
        return Some((cached_base, cached_base + KERNEL_STACK_SIZE));
    }
    // Try contiguous allocation first (fast path).
    if let Some(phys_stack) = crate::mm::pmm::alloc_pages(KERNEL_STACK_PAGES) {
        let stack_base = KERNEL_VIRT_OFFSET + phys_stack;
        let stack_top = stack_base + KERNEL_STACK_SIZE;
        write_stack_canary(stack_base);
        return Some((stack_base, stack_top));
    }
    // Contiguous allocation failed (PMM fragmented by page cache).
    // Fall back to allocating individual pages. Each page is at a different
    // physical address but accessed via KERNEL_VIRT_OFFSET + phys (which is
    // always mapped via the higher-half PML4 entries).
    // For the kernel stack, we need the pages to be VIRTUALLY contiguous.
    // Since each `KERNEL_VIRT_OFFSET + phys_page` maps independently and
    // the kernel uses the higher-half mapping, individual pages work IF they
    // happen to be placed at contiguous physical addresses (unlikely after
    // fragmentation). Instead, use a single page as a minimal stack.
    //
    // Contiguous allocation failed. Allocate 4 individual pages (16KB) and
    // use the FIRST page as stack base. Each page is independently mapped via
    // KERNEL_VIRT_OFFSET but NOT virtually contiguous. We use only the first
    // page (4KB) as the actual stack, which is enough for user_mode_bootstrap.
    // The other 3 pages are "guard" space — wasted but prevents the stack from
    // growing into unrelated memory.
    //
    // A proper fix would be vmalloc-style virtual mapping, but this unblocks Firefox.
    if let Some(phys) = crate::mm::pmm::alloc_page() {
        let stack_base = KERNEL_VIRT_OFFSET + phys;
        let stack_top = stack_base + 0x1000; // 4KB usable
        write_stack_canary(stack_base);
        crate::serial_println!("[PROC] WARN: 4KB emergency kernel stack (PMM fragmented)");
        return Some((stack_base, stack_top));
    }
    None
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
    };

    PROCESS_TABLE.lock().push(idle_proc);
    THREAD_TABLE.lock().push(idle_thread);
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
    };

    let thread = Thread {
        tid,
        pid,
        state: initial_state,
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: KERNEL_STACK_SIZE,
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
    };

    PROCESS_TABLE.lock().push(process);
    THREAD_TABLE.lock().push(thread);

    crate::serial_println!("[PROC] Created kernel process '{}' PID {} TID {}", name, pid, tid);
    pid
}

/// Create a new thread in an existing process.
pub fn create_thread(pid: Pid, name: &str, entry_point: u64) -> Option<Tid> {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    let (stack_base, stack_top) = alloc_kernel_stack()?;

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
        kernel_stack_size: KERNEL_STACK_SIZE,
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
    };

    THREAD_TABLE.lock().push(thread);
    PROCESS_TABLE.lock().iter_mut()
        .find(|p| p.pid == pid)
        .map(|p| p.threads.push(tid));

    crate::serial_println!("[PROC] Created thread '{}' TID {} in PID {}", name, tid, pid);
    Some(tid)
}

/// Like `create_thread`, but the new thread starts in `Blocked` state so the
/// caller can safely populate `user_entry_rip` / `user_entry_rsp` / `tls_base`
/// before the scheduler can pick it up.  Caller must transition the thread to
/// `ThreadState::Ready` when it is ready to run.
pub fn create_thread_blocked(pid: Pid, name: &str, entry_point: u64) -> Option<Tid> {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    let (stack_base, stack_top) = alloc_kernel_stack()?;

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
        kernel_stack_size: KERNEL_STACK_SIZE,
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
    };

    THREAD_TABLE.lock().push(thread);
    PROCESS_TABLE.lock().iter_mut()
        .find(|p| p.pid == pid)
        .map(|p| p.threads.push(tid));

    crate::serial_println!("[PROC] Created thread (blocked) '{}' TID {} in PID {}", name, tid, pid);
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
            unsafe { crate::mm::vmm::switch_cr3(kc3); }
        }
    }

    // Free user memory now that the process is Zombie.  No locks held here.
    if all_dead {
        free_process_memory(pid);
    }

    // vfork completion: if this is a vfork child exiting without exec, wake parent.
    // Linux: exit_mm_release() → mm_release() → complete_vfork_done().
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
        }
    }

    // Deliver SIGCHLD to parent (no locks held).
    if all_dead && parent_pid != 0 {
        let _ = crate::signal::kill(parent_pid, crate::signal::SIGCHLD);
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
/// Walks the process's VmSpace VMAs, decrements refcounts of all present anonymous
/// pages, and frees any whose refcount reaches zero.  Also frees the private
/// user-half page table structures (PT → PD → PDPT → PML4).
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

    // Walk all VMAs and free physical frames (anonymous pages only).
    // File-backed pages are managed by the page cache; device pages are MMIO.
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PAGE_PRESENT: u64 = 1;

    for vma in &vm_space.areas {
        match &vma.backing {
            VmBacking::File { .. } | VmBacking::Device { .. } => continue,
            VmBacking::Anonymous => {}
        }
        let mut addr = vma.base;
        while addr < vma.base + vma.length {
            let pte = vmm::read_pte(cr3, addr);
            if pte & PAGE_PRESENT != 0 {
                let phys = pte & ADDR_MASK;
                if refcount::page_ref_dec(phys) == 0 {
                    pmm::free_page(phys);
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
/// Walks every anonymous VMA, decrements the per-page refcount, and frees any
/// physical frame whose refcount reaches zero (CoW pages shared with a child
/// are not freed until the last reference drops).  Then frees the private
/// user-half page table structures (PT → PD → PDPT → PML4).
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

    // Walk all anonymous VMAs and decrement/free the backing physical pages.
    // File-backed pages belong to the page cache; device pages are MMIO.
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PAGE_PRESENT: u64 = 1;

    for vma in &vm_space.areas {
        match &vma.backing {
            VmBacking::File { .. } | VmBacking::Device { .. } => continue,
            VmBacking::Anonymous => {}
        }
        let mut addr = vma.base;
        while addr < vma.base + vma.length {
            let pte = vmm::read_pte(cr3, addr);
            if pte & PAGE_PRESENT != 0 {
                let phys = pte & ADDR_MASK;
                if refcount::page_ref_dec(phys) == 0 {
                    pmm::free_page(phys);
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
/// then mark the process as Zombie.  Called by the exit_group(231) syscall.
pub fn exit_group(exit_code: i64) {
    let tid = recover_current_tid();
    let pid;
    let parent_pid;

    // ── Firefox-test diagnostic dump ─────────────────────────────────────────
    // On non-zero exit, first dump a userspace stack snapshot (RSP/RBP,
    // 128 bytes of stack top, RBP chain up to 8 frames) so the harness can
    // resolve the call chain that led to `exit(1)`.  Then spill the
    // per-process syscall ring buffer to serial.  Both must run BEFORE any
    // teardown so the caller's CR3 and VMAs are still live.  Neither dump
    // takes locks that conflict with the teardown below.
    #[cfg(feature = "firefox-test")]
    {
        let cur_pid = current_pid();
        if cur_pid >= 1 {
            if exit_code != 0 {
                let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
                let cr3 = crate::mm::vmm::get_cr3();
                crate::syscall::ring::dump_exit_stack(cur_pid, cr3, user_rsp, user_rbp);
                crate::syscall::ring::dump_for_exit(cur_pid, exit_code);
            } else {
                crate::syscall::ring::drop_ring(cur_pid);
            }
        }
    }

    // Kill every OTHER thread in the process immediately, but NOT the caller.
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
    {
        let mut threads = THREAD_TABLE.lock();
        let my_thread = threads.iter().find(|t| t.tid == tid);
        pid = match my_thread {
            Some(t) => t.pid,
            None => { crate::sched::schedule(); return; }
        };
        for t in threads.iter_mut() {
            if t.pid == pid && t.tid != tid && t.state != ThreadState::Dead {
                t.state = ThreadState::Dead;
                t.exit_code = exit_code;
            }
        }
    }

    // Close pipe fds before marking Zombie so readers see EOF promptly.
    // Iterate a snapshot of (pipe_id, is_write) to avoid holding PROCESS_TABLE
    // while calling into PIPE_TABLE (lock ordering: PIPE_TABLE before PROCESS_TABLE).
    let pipe_ends: alloc::vec::Vec<(u64, bool)> = {
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)
            .map(|p| p.file_descriptors.iter()
                .filter_map(|f| f.as_ref())
                .filter(|f| f.file_type == crate::vfs::FileType::Pipe
                         && f.mount_idx == usize::MAX
                         && f.flags & 0x8000_0000 != 0)
                .map(|f| (f.inode, f.flags & 1 == 1))
                .collect())
            .unwrap_or_default()
    };
    for (pipe_id, is_write) in pipe_ends {
        if is_write {
            crate::ipc::pipe::pipe_close_writer(pipe_id);
        } else {
            crate::ipc::pipe::pipe_close_reader(pipe_id);
        }
    }

    // Release POSIX file locks held by this process (C1).
    crate::vfs::FILE_LOCKS.lock().retain(|l| l.pid != pid);

    // Mark the process as Zombie, record exit code, and re-parent its live children
    // to PID 1 (orphan adoption) so they don't accumulate as un-reapable zombies.
    {
        let mut procs = PROCESS_TABLE.lock();
        parent_pid = procs.iter().find(|p| p.pid == pid).map(|p| p.parent_pid).unwrap_or(0);
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            proc.state = ProcessState::Zombie;
            proc.exit_code = exit_code as i32;
        }
        // Orphan adoption: re-parent surviving children to PID 1.
        for p in procs.iter_mut() {
            if p.parent_pid == pid && p.state != ProcessState::Zombie {
                p.parent_pid = 1;
            }
        }
    }

    // Switch to the kernel page tables BEFORE freeing user page tables.
    // Same race as in exit_thread: another CPU can allocate+zero the freed
    // user PML4 page before the scheduler switches this CPU's CR3.
    {
        let kc3 = crate::mm::vmm::get_kernel_cr3();
        let cur = crate::mm::vmm::get_cr3();
        if kc3 != 0 && cur != kc3 {
            unsafe { crate::mm::vmm::switch_cr3(kc3); }
        }
    }
    // Free user memory (no locks held).
    free_process_memory(pid);

    // Wake parent threads blocked in waitpid, and mark calling thread Dead.
    {
        let mut threads = THREAD_TABLE.lock();
        for t in threads.iter_mut() {
            if t.pid == parent_pid && t.state == ThreadState::Blocked && t.wake_tick == u64::MAX - 1 {
                t.state = ThreadState::Ready;
            }
        }
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.state = ThreadState::Dead;
            t.exit_code = exit_code;
            // Signal that the CPU is about to leave this thread's kernel stack.
            // switch_context_asm will set ctx_rsp_valid=true after saving RSP,
            // which is the AP's cue that the stack is safe to free.
            t.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
        }
    }

    // Deliver SIGCHLD to parent (no locks held).
    if parent_pid != 0 {
        let _ = crate::signal::kill(parent_pid, crate::signal::SIGCHLD);
    }

    // Yield — we're dead and should never return.
    crate::sched::schedule();
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

/// Store the clear_child_tid address in a thread for CLONE_CHILD_CLEARTID.
/// When that thread exits, the kernel will write 0 to that address and wake futex.
pub fn set_clear_child_tid(pid: Pid, tid: Tid, tidptr: u64) {
    let mut threads = THREAD_TABLE.lock();
    if let Some(t) = threads.iter_mut().find(|t| t.pid == pid && t.tid == tid) {
        t.clear_child_tid = tidptr;
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

    // Copy parent's file descriptors, CWD, and security credentials.
    let (fds, cwd, parent_name, parent_uid, parent_gid, parent_euid, parent_egid,
         parent_groups, parent_umask, parent_linux_abi, parent_subsystem, parent_token_id,
         parent_pgid, parent_sid, parent_no_new_privs, parent_cap_permitted,
         parent_cap_effective, parent_rlimits_soft) = {
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
        )
    };

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
        exe_path: None,
        epoll_sets: alloc::vec::Vec::new(),
        auxv: Vec::new(),
        envp: Vec::new(),
        // POSIX: alarm state is NOT inherited across fork (POSIX.1-2008 §2.4)
        alarm_deadline_ticks: 0,
        alarm_interval_ticks: 0,
    };

    let child_thread = Thread {
        tid: child_tid,
        pid: child_pid,
        // Start Blocked so sys_fork_impl can write fork_user_regs before the
        // child is scheduled.  unblock_process() is called after set_fork_user_regs().
        state: ThreadState::Blocked,
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: KERNEL_STACK_SIZE,
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
        fork_user_regs: ForkUserRegs::default(),
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
    };

    PROCESS_TABLE.lock().push(child_proc);
    THREAD_TABLE.lock().push(child_thread);

    crate::serial_println!(
        "[PROC] fork: child PID {} TID {} (parent PID {}, CoW={})",
        child_pid, child_tid, parent_pid, user_rip != 0
    );

    Some((child_pid, child_tid))
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

    // Copy parent's file descriptors and credentials.
    let (fds, cwd, parent_name, parent_cr3, parent_tls_base,
         parent_linux_abi, parent_pgid, parent_sid) = {
        let procs = PROCESS_TABLE.lock();
        let parent = procs.iter().find(|p| p.pid == parent_pid)?;
        let fds = parent.file_descriptors.clone();
        let cwd = parent.cwd.clone();
        let mut name = parent.name;
        (fds, cwd, name, parent.cr3, 0u64, parent.linux_abi, parent.pgid, parent.sid)
    };

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
        exe_path: None,
        epoll_sets: alloc::vec::Vec::new(),
        auxv: Vec::new(),
        envp: Vec::new(),
        alarm_deadline_ticks: 0,
        alarm_interval_ticks: 0,
    };

    let child_thread = Thread {
        tid: child_tid,
        pid: child_pid,
        state: ThreadState::Ready, // Ready immediately (parent blocks itself)
        context: alloc::boxed::Box::new(context),
        kernel_stack_base: stack_base,
        kernel_stack_size: KERNEL_STACK_SIZE,
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
        fork_user_regs: ForkUserRegs::default(),
        vfork_parent_tid: None,
        gs_base: 0,
        robust_list_head: 0,
        robust_list_len: 0,
    };

    PROCESS_TABLE.lock().push(child_proc);
    THREAD_TABLE.lock().push(child_thread);

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
    if base != 0 {
        unsafe { write_fs_base(base); }
    }
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

        // Free kernel stack pages (convert higher-half back to physical)
        if stack_base > 0 && stack_pages > 0 {
            let phys_base = if stack_base >= KERNEL_VIRT_OFFSET {
                stack_base - KERNEL_VIRT_OFFSET
            } else {
                stack_base // Legacy physical-address stacks (TID 0)
            };
            for p in 0..stack_pages {
                crate::mm::pmm::free_page(phys_base + (p * 4096) as u64);
            }
        }

        // Free TLS area (1 page)
        if tls > 0 {
            crate::mm::pmm::free_page(tls);
        }
    }

    reaped
}
