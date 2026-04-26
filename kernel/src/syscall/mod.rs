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
// User pointer validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Validate that a user-space pointer is safe to access from the kernel.
///
/// Returns `true` if the entire range `[ptr, ptr+len)` lies in user space
/// (below `KERNEL_VIRT_BASE`), is non-null, and does not wrap around.
#[inline]
pub(crate) fn validate_user_ptr(ptr: u64, len: usize) -> bool {
    if ptr == 0 || len == 0 {
        return len == 0 && ptr == 0; // null + zero-length is acceptable
    }
    let end = ptr.checked_add(len as u64);
    match end {
        Some(e) => e <= astryx_shared::KERNEL_VIRT_BASE,
        None => false, // overflow
    }
}

/// Validate and create a slice from a user pointer. Returns `None` on failure.
#[inline]
pub(crate) unsafe fn user_slice<'a>(ptr: u64, len: usize) -> Option<&'a [u8]> {
    if len == 0 { return Some(&[]); }
    if !validate_user_ptr(ptr, len) { return None; }
    Some(core::slice::from_raw_parts(ptr as *const u8, len))
}

/// Validate and create a mutable slice from a user pointer.
#[inline]
pub(crate) unsafe fn user_slice_mut<'a>(ptr: u64, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 { return Some(&mut []); }
    if !validate_user_ptr(ptr, len) { return None; }
    Some(core::slice::from_raw_parts_mut(ptr as *mut u8, len))
}

/// Read a u32 from a validated user address. Returns None on bad address.
#[inline]
pub(crate) unsafe fn user_read_u32(addr: u64) -> Option<u32> {
    if !validate_user_ptr(addr, 4) { return None; }
    if addr % 4 != 0 { return None; } // alignment check
    Some(core::ptr::read_volatile(addr as *const u32))
}

/// Read a u64 from a validated user address. Returns None on bad address.
#[inline]
pub(crate) unsafe fn user_read_u64(addr: u64) -> Option<u64> {
    if !validate_user_ptr(addr, 8) { return None; }
    if addr % 8 != 0 { return None; } // alignment check
    Some(core::ptr::read_volatile(addr as *const u64))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Futex wait queue — keyed by virtual address
// ═══════════════════════════════════════════════════════════════════════════════

/// Futex wait queue: maps (pid, uaddr) -> list of waiting TIDs.
pub(crate) static FUTEX_WAITERS: Mutex<BTreeMap<(u64, u64), Vec<u64>>> = Mutex::new(BTreeMap::new());

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
/// harness).  The values come from the per-CPU `frame_rsp` slot populated
/// by `syscall_entry`; see its frame-layout comment for offsets.
///
/// Used by the firefox-test exit-time stack snapshot.
pub fn get_user_rsp_rbp() -> (u64, u64) {
    let cpu = cpu_index();
    let rsp = unsafe { PER_CPU_SYSCALL[cpu as usize].frame_rsp };
    if rsp == 0 { return (0, 0); }
    unsafe {
        let p = rsp as *const u64;
        // Frame layout from syscall_entry:
        //   [11]=rbp   [14]=user_rsp
        (*p.add(14), *p.add(11))
    }
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
/// After this call `current_apic_id()` returns the correct per-CPU index from
/// `rdmsr(IA32_TSC_AUX)`, which works regardless of which CR3 is loaded.
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

        // IA32_FMASK — RFLAGS mask on syscall (clear IF, TF, DF)
        crate::hal::wrmsr(0xC000_0084, 0x700);

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
    let rsp = unsafe { PER_CPU_SYSCALL[cpu as usize].frame_rsp };
    if rsp == 0 {
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
    let path = unsafe {
        let slice = core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize);
        match core::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -22, // EINVAL
        }
    };

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
    let (elf_data, argv_owned) = {
        let argv_refs: alloc::vec::Vec<&str> = argv_owned.iter().map(|s| s.as_str()).collect();
        match crate::proc::elf::resolve_shebang(path, file_data, &argv_refs) {
            Ok(r) => (r.elf_data, r.argv),
            Err(e) => {
                crate::serial_println!("[SYSCALL] exec: shebang/load error: {}", e);
                return e;
            }
        }
    };

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

    let pid = crate::proc::current_pid();

    // Check if the current process has a VmSpace (user-mode caller).
    // If not, fall back to creating a new process (kernel-mode caller).
    let has_vm_space = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)
            .map(|p| p.vm_space.is_some())
            .unwrap_or(false)
    };

    if !has_vm_space {
        // Kernel caller — create a new user process (legacy path).
        match crate::proc::usermode::create_user_process_with_args(path, &elf_data, argv_slice, envp_slice) {
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
            // mem::replace gives us the old VmSpace (may be None for kernel
            // processes, but we already checked has_vm_space above).
            extracted = p.vm_space.replace(new_vm_space);
            // ELFs loaded from disk use the Linux syscall ABI.
            p.linux_abi = true;
            p.subsystem = crate::win32::SubsystemType::Linux;
            // Close all FDs marked close-on-exec (O_CLOEXEC / FD_CLOEXEC).
            for fd_slot in p.file_descriptors.iter_mut() {
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

    // 4b. Reclaim the old address space now that the hardware no longer uses it.
    //     free_vm_space() walks old VMAs, decrements CoW refcounts, frees any
    //     anonymous pages whose refcount reaches zero, and releases the old PT
    //     structures (PT/PD/PDPT/PML4) back to the PMM.
    //     This is safe: we hold no locks, the new CR3 is active, and the old
    //     VmSpace is local (not referenced by any other thread or CPU).
    if let Some(old_space) = old_vm_space {
        crate::proc::free_vm_space(old_space);
    }

    // 5. Update kernel stack pointers for Ring 3 transitions.
    unsafe {
        crate::arch::x86_64::gdt::update_tss_rsp0(kstack_top);
        set_kernel_rsp(kstack_top);
    }

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

    // vfork completion: if this is a vfork child, wake the blocked parent.
    // Linux: mm_release() → complete_vfork_done() in fs/exec.c:1459.
    wake_vfork_parent();

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

    let parent_pid = crate::proc::current_pid();
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

/// Wake futex waiters from the exit path (CLONE_CHILD_CLEARTID).
/// This is called from proc::exit_thread when a thread with clear_child_tid exits.
pub fn futex_wake_for_exit(pid: u64, uaddr: u64, max_wake: u64) {
    let tids_to_wake: alloc::vec::Vec<u64> = {
        let mut waiters = FUTEX_WAITERS.lock();
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
/// Used for CLONE_CHILD_SETTID.
pub(crate) fn write_u32_to_user(cr3: u64, vaddr: u64, val: u32) {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    use crate::mm::vmm::{read_pte, ADDR_MASK, PAGE_PRESENT};
    let pte = read_pte(cr3, vaddr);
    if pte & PAGE_PRESENT == 0 { return; }
    let phys = (pte & ADDR_MASK) + (vaddr & 0xFFF);
    unsafe {
        core::ptr::write_volatile((PHYS_OFF + phys) as *mut u32, val);
    }
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
    let parent_pid = crate::proc::current_pid();
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
    // TTY / console fds (0-2) always go to tty_ioctl.
    if fd_num <= 2 {
        return crate::drivers::tty::tty_ioctl(request, arg_ptr);
    }

    // Look up the fd's open_path and file_type.
    let (open_path, file_type, inode) = {
        let pid = crate::proc::current_pid();
        let procs = crate::proc::PROCESS_TABLE.lock();
        let fd_opt = procs.iter()
            .find(|p| p.pid == pid)
            .and_then(|p| p.file_descriptors.get(fd_num))
            .and_then(|f| f.as_ref());
        match fd_opt {
            Some(f) => (f.open_path.clone(), f.file_type, f.inode),
            None    => (alloc::string::String::new(), crate::vfs::FileType::RegularFile, 0),
        }
    };

    // PTY ioctls
    match file_type {
        crate::vfs::FileType::PtyMaster => {
            return sys_pty_master_ioctl(inode as u8, request, arg_ptr);
        }
        crate::vfs::FileType::PtySlave => {
            return crate::drivers::tty::tty_ioctl(request, arg_ptr);
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
pub(crate) fn sys_pty_master_ioctl(pty_n: u8, request: u64, arg_ptr: *mut u8) -> i64 {
    // TIOCGPTN (0x80045430) — get slave number
    const TIOCGPTN:   u64 = 0x8004_5430;
    // TIOCSPTLCK (0x40045431) — set slave lock (0 = unlock)
    const TIOCSPTLCK: u64 = 0x4004_5431;
    // TIOCGPTLCK (0x80045439) — get lock state
    const TIOCGPTLCK: u64 = 0x8004_5439;
    // TIOCGWINSZ (0x5413) / TIOCSWINSZ (0x5414)
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;

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
                let (cols, rows) = crate::drivers::pty::get_winsz(pty_n);
                unsafe {
                    core::ptr::write(arg_ptr as *mut u16, rows);
                    core::ptr::write((arg_ptr as *mut u16).add(1), cols);
                    core::ptr::write((arg_ptr as *mut u16).add(2), 0u16); // xpixel
                    core::ptr::write((arg_ptr as *mut u16).add(3), 0u16); // ypixel
                }
            }
            0
        }
        TIOCSWINSZ => {
            if !arg_ptr.is_null() {
                let rows = unsafe { core::ptr::read(arg_ptr as *const u16) };
                let cols = unsafe { core::ptr::read((arg_ptr as *const u16).add(1)) };
                crate::drivers::pty::set_winsz(pty_n, cols, rows);
            }
            0
        }
        _ => 0, // Accept all other ioctls silently
    }
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
    let pid = crate::proc::current_pid();

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
    let (cr3, backing, name, base) = {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3, // ESRCH
        };

        // Ensure process has a VmSpace.
        // For vfork children (vm_space=None, shared parent CR3): create a VmSpace
        // that uses the process's actual CR3 (shared with parent) so mmap pages
        // go into the correct page table.
        if proc.vm_space.is_none() {
            let proc_cr3 = proc.cr3;
            if proc_cr3 != 0 {
                proc.vm_space = Some(VmSpace::from_existing_cr3(proc_cr3));
            } else {
                proc.vm_space = Some(VmSpace::new_kernel());
            }
        }
        let space = proc.vm_space.as_mut().unwrap();

        // Choose base address.
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
                    (VmBacking::File {
                        mount_idx: fd_entry.mount_idx,
                        inode: fd_entry.inode,
                        offset: page_offset,
                    }, "[mmap-file]")
                }
                _ => return -9, // EBADF
            }
        };

        (space.cr3, vma_backing, vma_name, chosen_base)
    };

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

    #[cfg(feature = "firefox-test")]
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
            if base < space.mmap_hint {
                space.mmap_hint = base;
            }
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
    let pid = crate::proc::current_pid();

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
    let pid = crate::proc::current_pid();

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
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.parent_pid as i64,
        None => -3,
    }
}

pub(crate) fn sys_getuid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.uid as i64,
        None => -3,
    }
}

pub(crate) fn sys_getgid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.gid as i64,
        None => -3,
    }
}

pub(crate) fn sys_geteuid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.euid as i64,
        None => -3,
    }
}

pub(crate) fn sys_getegid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.egid as i64,
        None => -3,
    }
}

pub(crate) fn sys_umask(new_mask: u32) -> i64 {
    let pid = crate::proc::current_pid();
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

    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let cwd = proc.cwd.as_bytes();
    if cwd.len() >= size {
        return -34; // ERANGE
    }

    unsafe {
        core::ptr::copy_nonoverlapping(cwd.as_ptr(), buf, cwd.len());
        *buf.add(cwd.len()) = 0; // null-terminate
    }

    cwd.len() as i64
}

pub(crate) fn sys_chdir(path_ptr: *const u8, path_len: usize) -> i64 {
    let path = unsafe {
        let slice = core::slice::from_raw_parts(path_ptr, path_len);
        match core::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -22,
        }
    };

    // Verify the path exists and is a directory
    match crate::vfs::stat(path) {
        Ok(st) => {
            if st.file_type != crate::vfs::FileType::Directory {
                return -20; // ENOTDIR
            }
        }
        Err(e) => return crate::subsys::linux::errno::vfs_err(e),
    }

    let pid = crate::proc::current_pid();
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
    let path = unsafe {
        let slice = core::slice::from_raw_parts(path_ptr, path_len);
        match core::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -22,
        }
    };

    match crate::vfs::mkdir(path) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

pub(crate) fn sys_rmdir(path_ptr: *const u8, path_len: usize) -> i64 {
    let path = unsafe {
        let slice = core::slice::from_raw_parts(path_ptr, path_len);
        match core::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -22,
        }
    };

    match crate::vfs::remove(path) {
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
    let path = unsafe {
        let slice = core::slice::from_raw_parts(path_ptr, path_len);
        match core::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -22,
        }
    };

    match crate::vfs::stat(path) {
        Ok(st) => {
            fill_stat_buf(&st, stat_buf);
            0
        }
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

pub(crate) fn sys_fstat(fd_num: usize, stat_buf: *mut u8) -> i64 {
    let pid = crate::proc::current_pid();
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

    let mounts = crate::vfs::MOUNTS.lock();
    match mounts.get(mount_idx) {
        Some(m) => match m.fs.stat(inode) {
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
    let pid = crate::proc::current_pid();
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

    const SEEK_SET: u32 = 0;
    const SEEK_CUR: u32 = 1;
    const SEEK_END: u32 = 2;

    let mount_idx = fd.mount_idx;
    let inode = fd.inode;

    let new_offset = match whence {
        SEEK_SET => offset,
        SEEK_CUR => fd.offset as i64 + offset,
        SEEK_END => {
            // Need to look up file size
            let mounts = crate::vfs::MOUNTS.lock();
            match mounts.get(mount_idx).and_then(|m| m.fs.stat(inode).ok()) {
                Some(st) => st.size as i64 + offset,
                None => return -9,
            }
        }
        _ => return -22,
    };

    if new_offset < 0 {
        return -22;
    }

    fd.offset = new_offset as u64;
    new_offset
}

pub(crate) fn sys_dup(old_fd: usize) -> i64 {
    let pid = crate::proc::current_pid();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let fd_clone = match proc.file_descriptors.get(old_fd).and_then(|f| f.as_ref()) {
        Some(fd) => fd.clone(),
        None => return -9,
    };

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
    let pid = crate::proc::current_pid();
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

    let fd_clone = match proc.file_descriptors.get(old_fd).and_then(|f| f.as_ref()) {
        Some(fd) => fd.clone(),
        None => return -9,
    };

    // Grow the table if needed
    while proc.file_descriptors.len() <= new_fd {
        proc.file_descriptors.push(None);
    }

    // Close existing fd at new_fd (silently)
    proc.file_descriptors[new_fd] = Some(fd_clone);
    new_fd as i64
}

pub(crate) fn sys_pipe(fds_out: *mut u64) -> i64 {
    if fds_out.is_null() {
        return -22; // EINVAL
    }

    let pipe_id = crate::ipc::pipe::create_pipe();
    let pid = crate::proc::current_pid();

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

    // Write [read_fd, write_fd] to user buffer
    unsafe {
        *fds_out = ri as u64;
        *fds_out.add(1) = wi as u64;
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
pub(crate) fn alloc_socket_fd(pid: u64, socket_id: u64, sock_type: u32) -> i64 {
    let fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode: socket_id,
        offset: 0,
        flags: 0x4000_0000 | (sock_type & 0x03), // SOCKET_FD | type
        is_console: false,
        cloexec: false,
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
pub(crate) fn poll_revents(pid: u64, fd: usize, events: u16) -> u16 {
    const POLLIN:  u16 = 0x0001;
    const POLLOUT: u16 = 0x0004;
    if fd <= 2 {
        if fd == 0 { events & POLLIN } else { events & POLLOUT }
    } else if is_eventfd_fd(pid, fd) {
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
            if crate::ipc::pipe::pipe_has_data(pipe_id) { events & POLLIN } else { 0 }
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

// ── AF_UNIX socket helpers ────────────────────────────────────────────────────

const UNIX_SOCKET_FLAG: u32 = 0x0080_0000; // bit 23: fd is an AF_UNIX socket

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
pub(crate) fn alloc_unix_socket_fd(pid: u64, unix_id: u64) -> i64 {
    let fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode: unix_id,
        offset: 0,
        flags: 0x4000_0000 | UNIX_SOCKET_FLAG, // SOCKET_FD | UNIX_FLAG
        is_console: false,
        cloexec: false,
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
pub(crate) fn sys_uname(buf: *mut u8) -> i64 {
    const FIELD_LEN: usize = 65;
    let fields: [&[u8]; 5] = [
        b"AstryxOS",      // sysname
        b"astryx",        // nodename
        b"0.1.0",         // release
        b"Phase 6",       // version
        b"x86_64",        // machine
    ];

    let out = unsafe { core::slice::from_raw_parts_mut(buf, FIELD_LEN * 5) };
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
    let path = unsafe {
        let slice = core::slice::from_raw_parts(path_ptr, path_len);
        match core::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -22,
        }
    };

    match crate::vfs::remove(path) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

pub(crate) fn sys_sigaction(sig: u8, handler_addr: u64) -> i64 {
    use crate::signal::{SigAction, SIGKILL, SIGSTOP, MAX_SIGNAL};
    
    if sig == 0 || sig >= MAX_SIGNAL || sig == SIGKILL || sig == SIGSTOP {
        return -22; // EINVAL — can't change SIGKILL/SIGSTOP
    }

    let pid = crate::proc::current_pid();
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

    let pid = crate::proc::current_pid();
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
    let frame_ptr = frame_base as *const crate::signal::SignalFrame;

    let (sig_num, saved_mask, saved_rsp, saved_r15, saved_r14, saved_r13,
         saved_r12, saved_rbx, saved_rbp, saved_r11, saved_rcx, saved_rax);
    unsafe {
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
        let pid = crate::proc::current_pid();
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
    unsafe {
        *((ksp -  8) as *mut u64) = saved_rsp;
        *((ksp - 16) as *mut u64) = saved_rcx;  // user RIP
        *((ksp - 24) as *mut u64) = saved_r11;  // RFLAGS
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
/// Uses RDRAND if available, otherwise a simple xorshift PRNG seeded from
/// the TSC.
pub(crate) fn sys_getrandom(buf: *mut u8, count: usize) -> i64 {
    if buf.is_null() || count == 0 {
        return -22;
    }

    let out = unsafe { core::slice::from_raw_parts_mut(buf, count) };

    // Try RDRAND first
    let has_rdrand = unsafe {
        let mut ecx: u32;
        // rbx is reserved by LLVM, so save/restore it manually.
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

    if has_rdrand {
        let mut i = 0;
        while i < count {
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
            }
        }
    } else {
        // Fallback: xorshift64 seeded from TSC
        let mut state: u64 = unsafe {
            let lo: u32;
            let hi: u32;
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi);
            ((hi as u64) << 32) | lo as u64
        };
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
    let pid = crate::proc::current_pid();
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
