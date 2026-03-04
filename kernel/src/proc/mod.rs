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
pub mod orbit_elf;
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
    pub rip: u64,
    pub rflags: u64,
    pub cr3: u64,
}

impl Default for CpuContext {
    fn default() -> Self {
        Self {
            r15: 0, r14: 0, r13: 0, r12: 0,
            rbx: 0, rbp: 0, rsp: 0, rip: 0,
            rflags: 0x202, // IF flag set
            cr3: 0,
        }
    }
}

/// Thread Control Block (TCB).
pub struct Thread {
    /// Thread ID (globally unique).
    pub tid: Tid,
    /// Owning process ID.
    pub pid: Pid,
    /// Thread state.
    pub state: ThreadState,
    /// Saved CPU context (for context switch).
    pub context: CpuContext,
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
    /// Current scheduling priority (0–31; higher = higher priority).
    pub priority: u8,
    /// Base priority to decay back to after a boost.
    pub base_priority: u8,
    /// Thread-local storage base address (loaded into FS_BASE on context switch).
    /// 0 means no TLS area is allocated for this thread.
    pub tls_base: u64,
    /// CPU affinity: if `Some(cpu_id)`, schedule only on that CPU.
    /// `None` means the thread can run on any CPU.
    pub cpu_affinity: Option<u8>,
    /// Last CPU this thread ran on (for cache affinity).
    pub last_cpu: u8,
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
}

/// Next PID counter.
static NEXT_PID: AtomicU64 = AtomicU64::new(1);
/// Next TID counter.
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

/// Process table.
pub static PROCESS_TABLE: Mutex<Vec<Process>> = Mutex::new(Vec::new());
/// Thread table.
pub static THREAD_TABLE: Mutex<Vec<Thread>> = Mutex::new(Vec::new());

/// Currently running thread ID — per-CPU, indexed by APIC ID.
/// With SMP, each CPU tracks its own running thread.
static PER_CPU_CURRENT_TID: [AtomicU64; crate::arch::x86_64::apic::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::apic::MAX_CPUS];

/// Kernel stack size per thread: 16 KiB (4 pages).
const KERNEL_STACK_PAGES: usize = 4;
const KERNEL_STACK_SIZE: u64 = (KERNEL_STACK_PAGES * 4096) as u64;

/// Higher-half virtual offset.  The bootloader identity-maps the first 4 GiB
/// of RAM at both virtual 0x0 and 0xFFFF_8000_0000_0000.  Kernel stacks are
/// allocated from PMM (physical addresses) but accessed via the higher-half
/// map so they remain valid after CR3 switches to user page tables (which
/// shallow-clone PML4[256-511] from the kernel).
const KERNEL_VIRT_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Initialize the process manager.
pub fn init() {
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
        supplementary_groups: Vec::new(),
        umask: 0o022,
        vm_space: None,
        signal_state: None,
        linux_abi: false,
        handle_table: None,
        subsystem: crate::win32::SubsystemType::Native,
        token_id: None,
    };

    let idle_thread = Thread {
        tid: 0,
        pid: 0,
        state: ThreadState::Running,
        context: CpuContext {
            rip: 0,
            rsp: 0,
            cr3: crate::mm::vmm::get_cr3(),
            ..CpuContext::default()
        },
        kernel_stack_base: 0,
        kernel_stack_size: 0,
        wake_tick: 0,
        name: {
            let mut name = [0u8; 32];
            name[..11].copy_from_slice(b"idle_thread");
            name
        },
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: 0,
        user_entry_rsp: 0,
        priority: PRIORITY_IDLE,
        base_priority: PRIORITY_IDLE,
        tls_base: 0,
        // Pin the BSP idle thread to CPU 0.  This prevents AP schedulers from
        // stealing it while context.rsp is still 0 (before the first
        // switch_context save), which would load RSP=0 and triple-fault.
        cpu_affinity: Some(0),
        last_cpu: 0,
    };

    PROCESS_TABLE.lock().push(idle_proc);
    THREAD_TABLE.lock().push(idle_thread);
    set_current_tid(0);

    crate::serial_println!("[PROC] Process manager initialized (idle process PID 0, TID 0)");
}

/// Get the current CPU index (APIC ID) for per-CPU data access.
#[inline(always)]
fn cpu_index() -> usize {
    crate::arch::x86_64::apic::current_apic_id() as usize
}

/// Get the currently running thread's TID (per-CPU).
pub fn current_tid() -> Tid {
    PER_CPU_CURRENT_TID[cpu_index()].load(Ordering::Relaxed)
}

/// Set the currently running thread's TID (per-CPU).
pub fn set_current_tid(tid: Tid) {
    PER_CPU_CURRENT_TID[cpu_index()].store(tid, Ordering::Relaxed);
}

/// Get the currently running process's PID.
pub fn current_pid() -> Pid {
    let tid = current_tid();
    let threads = THREAD_TABLE.lock();
    threads.iter().find(|t| t.tid == tid).map(|t| t.pid).unwrap_or(0)
}

/// Create a new kernel process with a single thread.
pub fn create_kernel_process(name: &str, entry_point: u64) -> Pid {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    // Allocate kernel stack and use its higher-half virtual address.
    let phys_stack = crate::mm::pmm::alloc_pages(KERNEL_STACK_PAGES)
        .expect("Failed to allocate kernel stack");
    let stack_base = KERNEL_VIRT_OFFSET + phys_stack;
    let stack_top = stack_base + KERNEL_STACK_SIZE;

    let cr3 = crate::mm::vmm::get_cr3();

    // Set up the initial stack so that when switch_context "returns" into this
    // thread, it starts at thread_entry_trampoline → entry_point.
    let initial_rsp = thread::init_thread_stack(stack_top, entry_point);

    let context = CpuContext {
        rip: 0, // Not used directly — switch_context uses RSP-based return
        rsp: initial_rsp,
        rbp: 0,
        rbx: entry_point,
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
        supplementary_groups: Vec::new(),
        umask: 0o022,
        vm_space: None,
        signal_state: None,
        linux_abi: false,
        handle_table: Some(crate::ob::handle::HandleTable::new()),
        subsystem: crate::win32::SubsystemType::Posix,
        token_id: None,
    };

    let thread = Thread {
        tid,
        pid,
        state: ThreadState::Ready,
        context,
        kernel_stack_base: stack_base,
        kernel_stack_size: KERNEL_STACK_SIZE,
        wake_tick: 0,
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: 0,
        user_entry_rsp: 0,
        priority: PRIORITY_HIGH,
        base_priority: PRIORITY_HIGH,
        tls_base: 0,
        cpu_affinity: None,
        last_cpu: 0,
    };

    PROCESS_TABLE.lock().push(process);
    THREAD_TABLE.lock().push(thread);

    crate::serial_println!("[PROC] Created kernel process '{}' PID {} TID {}", name, pid, tid);
    pid
}

/// Create a new thread in an existing process.
pub fn create_thread(pid: Pid, name: &str, entry_point: u64) -> Option<Tid> {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    let phys_stack = crate::mm::pmm::alloc_pages(KERNEL_STACK_PAGES)?;
    let stack_base = KERNEL_VIRT_OFFSET + phys_stack;
    let stack_top = stack_base + KERNEL_STACK_SIZE;

    let cr3 = {
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)?.cr3
    };

    let initial_rsp = thread::init_thread_stack(stack_top, entry_point);

    let context = CpuContext {
        rip: 0,
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
        context,
        kernel_stack_base: stack_base,
        kernel_stack_size: KERNEL_STACK_SIZE,
        wake_tick: 0,
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: 0,
        user_entry_rsp: 0,
        priority: PRIORITY_NORMAL,
        base_priority: PRIORITY_NORMAL,
        tls_base: 0,
        cpu_affinity: None,
        last_cpu: 0,
    };

    THREAD_TABLE.lock().push(thread);
    PROCESS_TABLE.lock().iter_mut()
        .find(|p| p.pid == pid)
        .map(|p| p.threads.push(tid));

    crate::serial_println!("[PROC] Created thread '{}' TID {} in PID {}", name, tid, pid);
    Some(tid)
}

/// Terminate the current thread.
pub fn exit_thread(exit_code: i64) {
    let tid = current_tid();
    let pid;
    let parent_pid;

    {
        let mut threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.state = ThreadState::Dead;
            t.exit_code = exit_code;
            pid = t.pid;
        } else {
            return;
        }
    }

    // Check if all threads in the process are dead.
    {
        let threads = THREAD_TABLE.lock();
        let mut procs = PROCESS_TABLE.lock();
        parent_pid = procs.iter().find(|p| p.pid == pid).map(|p| p.parent_pid).unwrap_or(0);
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            let all_dead = proc.threads.iter().all(|&tid| {
                threads.iter().find(|t| t.tid == tid)
                    .map(|t| t.state == ThreadState::Dead)
                    .unwrap_or(true)
            });
            if all_dead {
                proc.state = ProcessState::Zombie;
                proc.exit_code = exit_code as i32;
            }
        }
    }

    // Wake parent threads that are Blocked (waiting in waitpid).
    {
        let mut threads = THREAD_TABLE.lock();
        for t in threads.iter_mut() {
            if t.pid == parent_pid && t.state == ThreadState::Blocked && t.wake_tick == u64::MAX - 1 {
                // wake_tick == u64::MAX - 1  is our sentinel for "blocked in waitpid"
                t.state = ThreadState::Ready;
            }
        }
    }

    // Yield to scheduler — we're dead, should never return.
    crate::sched::schedule();
}

/// Put the current thread to sleep for `ticks` timer ticks.
pub fn sleep_ticks(ticks: u64) {
    let tid = current_tid();
    let current_tick = crate::arch::x86_64::irq::get_ticks();

    {
        let mut threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
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
pub fn fork_process(parent_pid: Pid, _parent_tid: Tid) -> Option<Pid> {
    let child_pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let child_tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);

    // Allocate kernel stack for the child (higher-half virtual address).
    let phys_stack = crate::mm::pmm::alloc_pages(KERNEL_STACK_PAGES)?;
    let stack_base = KERNEL_VIRT_OFFSET + phys_stack;
    let stack_top = stack_base + KERNEL_STACK_SIZE;

    // Copy parent's file descriptors, CWD, and security credentials.
    let (fds, cwd, parent_name, parent_uid, parent_gid, parent_euid, parent_egid, parent_groups, parent_umask, parent_linux_abi, parent_token_id) = {
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
            parent.token_id,
        )
    };

    // Read the parent's user-mode return address and stack pointer from the
    // saved syscall frame on the parent's kernel stack (if it exists).
    let (user_rip, user_rsp) = {
        let threads = THREAD_TABLE.lock();
        if let Some(parent_thread) = threads.iter().find(|t| t.tid == _parent_tid) {
            if parent_thread.kernel_stack_base > 0 && parent_thread.kernel_stack_size > 0 {
                let kstack_top = parent_thread.kernel_stack_base + parent_thread.kernel_stack_size;
                // syscall_entry layout: offset -16 = RCX (user RIP), offset -8 = user RSP
                unsafe {
                    let rip = *((kstack_top - 16) as *const u64);
                    let rsp = *((kstack_top - 8) as *const u64);
                    (rip, rsp)
                }
            } else {
                (0u64, 0u64)
            }
        } else {
            (0u64, 0u64)
        }
    };

    // Perform CoW clone of the parent's VmSpace (if it has one).
    let (child_cr3, child_vm_space) = {
        let mut procs = PROCESS_TABLE.lock();
        let parent = procs.iter_mut().find(|p| p.pid == parent_pid)?;
        if let Some(ref parent_vs) = parent.vm_space {
            match parent_vs.clone_for_fork() {
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

    // The child's main thread starts at fork_child_entry.
    let initial_rsp = thread::init_thread_stack(stack_top, fork_child_entry as *const () as u64);

    let context = CpuContext {
        rip: 0,
        rsp: initial_rsp,
        rbp: 0,
        rbx: fork_child_entry as *const () as u64,
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
        supplementary_groups: parent_groups,
        umask: parent_umask,
        vm_space: child_vm_space,
        signal_state: Some(crate::signal::SignalState::new()),
        linux_abi: parent_linux_abi,
        handle_table: Some(crate::ob::handle::HandleTable::new()),
        subsystem: crate::win32::SubsystemType::Posix,
        token_id: parent_token_id,
    };

    let child_thread = Thread {
        tid: child_tid,
        pid: child_pid,
        state: ThreadState::Ready,
        context,
        kernel_stack_base: stack_base,
        kernel_stack_size: KERNEL_STACK_SIZE,
        wake_tick: 0,
        name: thread_name,
        exit_code: 0,
        fpu_state: None,
        user_entry_rip: user_rip,
        user_entry_rsp: user_rsp,
        priority: PRIORITY_NORMAL,
        base_priority: PRIORITY_NORMAL,
        tls_base: 0,
        cpu_affinity: None,
        last_cpu: 0,
    };

    PROCESS_TABLE.lock().push(child_proc);
    THREAD_TABLE.lock().push(child_thread);

    crate::serial_println!(
        "[PROC] fork: child PID {} TID {} (parent PID {}, CoW={})",
        child_pid, child_tid, parent_pid, user_rip != 0
    );

    Some(child_pid)
}

/// Entry point for forked child threads.
///
/// If the child has user_entry_rip set (user-mode fork), it returns to
/// user mode at the parent's saved instruction with RAX=0.
/// Otherwise (kernel-mode fork), it simply exits with code 0.
fn fork_child_entry() {
    let (entry_rip, entry_rsp, kernel_stack_top) = {
        let tid = current_tid();
        let threads = THREAD_TABLE.lock();
        let t = threads.iter().find(|t| t.tid == tid)
            .expect("fork_child_entry: current thread not found");
        (t.user_entry_rip, t.user_entry_rsp, t.kernel_stack_base + t.kernel_stack_size)
    };

    if entry_rip == 0 {
        // Kernel-only fork — no user context to return to.
        crate::serial_println!("[PROC] fork child running (PID {}, kernel-only)", current_pid());
        exit_thread(0);
        return;
    }

    crate::serial_println!(
        "[PROC] fork child PID {} returning to user mode RIP={:#x} RSP={:#x}",
        current_pid(), entry_rip, entry_rsp
    );

    // Switch to the child's page table.
    let cr3 = {
        let pid = current_pid();
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid).map(|p| p.cr3).unwrap_or(0)
    };
    if cr3 != 0 && cr3 != crate::mm::vmm::get_cr3() {
        unsafe { crate::mm::vmm::switch_cr3(cr3); }
    }

    // Set up kernel stack for Ring 3 → Ring 0 transitions.
    unsafe {
        crate::arch::x86_64::gdt::update_tss_rsp0(kernel_stack_top);
        crate::syscall::set_kernel_rsp(kernel_stack_top);
    }

    // Jump to user mode with RAX=0 (fork returns 0 in child).
    unsafe {
        use crate::arch::x86_64::gdt;
        core::arch::asm!(
            "xor rax, rax",     // fork returns 0 in child
            "push {ss}",        // SS
            "push {rsp_val}",   // RSP
            "push {rflags}",    // RFLAGS (IF set)
            "push {cs}",        // CS
            "push {rip_val}",   // RIP
            "iretq",
            ss = in(reg) gdt::USER_DATA_SELECTOR as u64,
            rsp_val = in(reg) entry_rsp,
            rflags = in(reg) 0x202u64,
            cs = in(reg) gdt::USER_CODE_SELECTOR as u64,
            rip_val = in(reg) entry_rip,
            options(noreturn),
        );
    }
}

/// Wait for a child process to exit (reap a zombie).
///
/// `parent_pid`: the calling process.
/// `wait_pid`: specific PID to wait for, or -1 for any child.
///
/// Returns `Some((child_pid, exit_code))` if a zombie child is found, or `None`.
pub fn waitpid(parent_pid: Pid, wait_pid: i64) -> Option<(Pid, i32)> {
    let mut procs = PROCESS_TABLE.lock();

    // Find a zombie child matching the criteria.
    let idx = procs.iter().position(|p| {
        p.parent_pid == parent_pid
            && p.state == ProcessState::Zombie
            && (wait_pid < 0 || p.pid == wait_pid as u64)
    })?;

    let child = &procs[idx];
    let child_pid = child.pid;
    let exit_code = child.exit_code;

    // Reap: clean up the child's threads.
    let thread_tids: Vec<Tid> = child.threads.clone();
    {
        let mut threads = THREAD_TABLE.lock();
        threads.retain(|t| !thread_tids.contains(&t.tid));
    }

    // Remove the child process entry.
    procs.remove(idx);

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
        .filter(|(_, t)| {
            t.state == ThreadState::Dead
                && t.tid != 0           // never reap idle
                && t.tid < 0x1000       // never reap AP idle threads
        })
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
