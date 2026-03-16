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

// ═══════════════════════════════════════════════════════════════════════════════
// User pointer validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Validate that a user-space pointer is safe to access from the kernel.
///
/// Returns `true` if the entire range `[ptr, ptr+len)` lies in user space
/// (below `KERNEL_VIRT_BASE`), is non-null, and does not wrap around.
#[inline]
fn validate_user_ptr(ptr: u64, len: usize) -> bool {
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
unsafe fn user_slice<'a>(ptr: u64, len: usize) -> Option<&'a [u8]> {
    if len == 0 { return Some(&[]); }
    if !validate_user_ptr(ptr, len) { return None; }
    Some(core::slice::from_raw_parts(ptr as *const u8, len))
}

/// Validate and create a mutable slice from a user pointer.
#[inline]
unsafe fn user_slice_mut<'a>(ptr: u64, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 { return Some(&mut []); }
    if !validate_user_ptr(ptr, len) { return None; }
    Some(core::slice::from_raw_parts_mut(ptr as *mut u8, len))
}

/// Read a u32 from a validated user address. Returns None on bad address.
#[inline]
unsafe fn user_read_u32(addr: u64) -> Option<u32> {
    if !validate_user_ptr(addr, 4) { return None; }
    if addr % 4 != 0 { return None; } // alignment check
    Some(core::ptr::read_volatile(addr as *const u32))
}

/// Read a u64 from a validated user address. Returns None on bad address.
#[inline]
unsafe fn user_read_u64(addr: u64) -> Option<u64> {
    if !validate_user_ptr(addr, 8) { return None; }
    if addr % 8 != 0 { return None; } // alignment check
    Some(core::ptr::read_volatile(addr as *const u64))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Futex wait queue — keyed by virtual address
// ═══════════════════════════════════════════════════════════════════════════════

/// Futex wait queue: maps (pid, uaddr) -> list of waiting TIDs.
static FUTEX_WAITERS: Mutex<BTreeMap<(u64, u64), Vec<u64>>> = Mutex::new(BTreeMap::new());

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
        crate::hal::wrmsr(0xC000_0082, syscall_entry as *const () as u64);

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
pub fn dispatch(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    crate::perf::record_syscall(num);

    let result = if is_linux_abi() {
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
pub fn dispatch_aether(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    match num {
        SYS_EXIT => {
            crate::serial_println!("[SYSCALL] exit({})", arg1 as i32);
            crate::proc::exit_thread(arg1 as i64);
            0 // unreachable
        }
        SYS_WRITE => {
            // write(fd, buf, count) -> count or -errno
            let fd = arg1;
            let count = arg3 as usize;

            if count == 0 { return 0; }

            let slice = match unsafe { user_slice(arg2, count) } {
                Some(s) => s,
                None => return -14, // EFAULT
            };

            // Special fd types take priority over fd-number shortcuts
            let pid = crate::proc::current_pid();
            if is_pipe_fd(pid, fd as usize) {
                let pipe_id = get_pipe_id(pid, fd as usize);
                match crate::ipc::pipe::pipe_write(pipe_id, slice) {
                    Some(n) => n as i64,
                    None => -9, // EBADF
                }
            } else {
                // Try VFS first; fall back to TTY for fd 1/2 if no file open.
                #[cfg(feature = "firefox-test")]
                if fd == 2 {
                    let s = core::str::from_utf8(slice).unwrap_or("<binary>");
                    crate::serial_println!("[FF/stderr] pid={} {:?}", pid, s);
                }
                match crate::vfs::fd_write(pid, fd as usize, arg2 as *const u8, count) {
                    Ok(n) => n as i64,
                    Err(_) if fd == 1 || fd == 2 => {
                        crate::drivers::tty::TTY0.lock().write(slice);
                        count as i64
                    }
                    Err(_) => -9, // EBADF
                }
            }
        }
        SYS_READ => {
            let fd = arg1;
            let count = arg3 as usize;

            let buf = match unsafe { user_slice_mut(arg2, count) } {
                Some(s) => s,
                None => return -14, // EFAULT
            };

            // Special fd types take priority over fd-number shortcuts
            let pid = crate::proc::current_pid();
            if is_pipe_fd(pid, fd as usize) {
                let pipe_id = get_pipe_id(pid, fd as usize);
                match crate::ipc::pipe::pipe_read(pipe_id, buf) {
                    Some(n) => n as i64,
                    None => -9, // EBADF
                }
            } else {
                // Try VFS first; fall back to TTY stdin for fd 0 if no file open.
                match crate::vfs::fd_read(pid, fd as usize, arg2 as *mut u8, count) {
                    Ok(n) => n as i64,
                    Err(_) if fd == 0 => {
                        // stdin — read through TTY line discipline
                        let mut attempts = 0u32;
                        loop {
                            {
                                let mut tty = crate::drivers::tty::TTY0.lock();
                                crate::drivers::tty::pump_keyboard(&mut tty);
                                let n = tty.read(buf, count);
                                if n > 0 {
                                    return n as i64;
                                }
                            }
                            attempts += 1;
                            if attempts > 100_000 {
                                return 0;
                            }
                            crate::hal::halt();
                        }
                    }
                    Err(_) => -9,
                }
            }
        }
        SYS_OPEN => {
            // open(path, flags) -> fd or -errno
            let path_len = arg2 as usize;
            let flags = arg3 as u32;

            let path = match unsafe { user_slice(arg1, path_len) } {
                Some(s) => core::str::from_utf8(s).unwrap_or(""),
                None => return -14, // EFAULT
            };

            let pid = crate::proc::current_pid();
            match crate::vfs::open(pid, path, flags) {
                Ok(fd) => fd as i64,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        SYS_CLOSE => {
            let fd = arg1 as usize;
            let pid = crate::proc::current_pid();
            match crate::vfs::close(pid, fd) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        SYS_GETPID => {
            crate::proc::current_pid() as i64
        }
        SYS_YIELD => {
            crate::sched::yield_cpu();
            0
        }
        SYS_FORK => {
            sys_fork()
        }
        SYS_EXEC => {
            // exec(path_ptr, path_len) — Aether ABI has no argv/envp
            sys_exec(arg1, arg2, 0, 0)
        }
        SYS_WAITPID => {
            // waitpid(pid, options)
            sys_waitpid(arg1 as i64, arg2 as u32)
        }
        SYS_MMAP => {
            // mmap(addr, length, prot, flags, fd, offset)
            sys_mmap(arg1, arg2, arg3 as u32, arg4 as u32, arg5, arg6)
        }
        SYS_MUNMAP => {
            // munmap(addr, length)
            sys_munmap(arg1, arg2)
        }
        SYS_BRK => {
            // brk(new_brk) -> current brk
            sys_brk(arg1)
        }
        SYS_GETPPID => {
            sys_getppid()
        }
        SYS_GETCWD => {
            // getcwd(buf, size) -> length or -errno
            sys_getcwd(arg1 as *mut u8, arg2 as usize)
        }
        SYS_CHDIR => {
            // chdir(path_ptr, path_len) -> 0 or -errno
            sys_chdir(arg1 as *const u8, arg2 as usize)
        }
        SYS_MKDIR => {
            // mkdir(path_ptr, path_len) -> 0 or -errno
            sys_mkdir(arg1 as *const u8, arg2 as usize)
        }
        SYS_RMDIR => {
            // rmdir(path_ptr, path_len) -> 0 or -errno
            sys_rmdir(arg1 as *const u8, arg2 as usize)
        }
        SYS_STAT => {
            // stat(path_ptr, path_len, stat_buf) -> 0 or -errno
            sys_stat(arg1 as *const u8, arg2 as usize, arg3 as *mut u8)
        }
        SYS_FSTAT => {
            // fstat(fd, stat_buf) -> 0 or -errno
            sys_fstat(arg1 as usize, arg2 as *mut u8)
        }
        SYS_LSEEK => {
            // lseek(fd, offset, whence) -> new offset or -errno
            sys_lseek(arg1 as usize, arg2 as i64, arg3 as u32)
        }
        SYS_DUP => {
            // dup(fd) -> new_fd or -errno
            sys_dup(arg1 as usize)
        }
        SYS_DUP2 => {
            // dup2(oldfd, newfd) -> new_fd or -errno
            sys_dup2(arg1 as usize, arg2 as usize)
        }
        SYS_PIPE => {
            // pipe(fds_out) -> 0 or -errno
            sys_pipe(arg1 as *mut u64)
        }
        SYS_UNAME => {
            // uname(buf) -> 0
            sys_uname(arg1 as *mut u8)
        }
        SYS_NANOSLEEP => {
            // nanosleep(milliseconds) -> 0
            sys_nanosleep(arg1)
        }
        SYS_GETUID => {
            sys_getuid()
        }
        SYS_GETGID => {
            sys_getgid()
        }
        SYS_GETEUID => {
            sys_geteuid()
        }
        SYS_GETEGID => {
            sys_getegid()
        }
        SYS_UMASK => {
            // umask(new_mask) -> old_mask
            sys_umask(arg1 as u32)
        }
        SYS_UNLINK => {
            // unlink(path_ptr, path_len) -> 0 or -errno
            sys_unlink(arg1 as *const u8, arg2 as usize)
        }
        SYS_GETRANDOM => {
            // getrandom(buf, count) -> count or -errno
            sys_getrandom(arg1 as *mut u8, arg2 as usize)
        }
        SYS_KILL => {
            // kill(pid, sig) -> 0 or -errno
            crate::signal::kill(arg1, arg2 as u8)
        }
        SYS_SIGACTION => {
            // sigaction(sig, handler_addr) -> 0 or -errno
            // Simplified: arg1 = signal, arg2 = handler address (0 = SIG_DFL, 1 = SIG_IGN)
            sys_sigaction(arg1 as u8, arg2)
        }
        SYS_SIGPROCMASK => {
            // sigprocmask(how, new_mask) -> old_mask or -errno
            sys_sigprocmask(arg1 as u32, arg2)
        }
        SYS_SIGRETURN => {
            sys_sigreturn()
        }
        SYS_IOCTL => {
            let fd = arg1;
            let request = arg2;
            let arg_ptr = arg3 as *mut u8;
            // TTY ioctls apply to fd 0, 1, or 2 (stdin/stdout/stderr)
            if fd <= 2 {
                crate::drivers::tty::tty_ioctl(request, arg_ptr)
            } else {
                -25 // ENOTTY
            }
        }
        SYS_CHMOD => {
            // chmod(path_ptr, path_len, mode) -> 0 or -errno
            // Stub: acknowledge but no-op since our VFS doesn't store permissions yet
            0
        }
        SYS_CHOWN => {
            // chown(path_ptr, path_len, uid) -> 0 or -errno
            // Stub: acknowledge but no-op
            0
        }
        SYS_SOCKET => {
            // socket(domain, type, protocol) -> socket_id or -errno
            let sock_type = match arg2 {
                1 => crate::net::socket::SocketType::Tcp,
                2 => crate::net::socket::SocketType::Udp,
                _ => return -22, // EINVAL
            };
            crate::net::socket::socket_create(sock_type) as i64
        }
        SYS_BIND => {
            // bind(socket_id, port, _) -> 0 or -errno
            let socket_id = arg1;
            let port = arg2 as u16;
            match crate::net::socket::socket_bind(socket_id, port) {
                Ok(()) => 0,
                Err(_) => -98, // EADDRINUSE
            }
        }
        SYS_CONNECT => {
            // connect(socket_id, ip_packed, port) -> 0 or -errno
            let socket_id = arg1;
            let ip_packed = arg2 as u32;
            let remote_ip = [
                ((ip_packed >> 24) & 0xFF) as u8,
                ((ip_packed >> 16) & 0xFF) as u8,
                ((ip_packed >> 8) & 0xFF) as u8,
                (ip_packed & 0xFF) as u8,
            ];
            let port = arg3 as u16;
            match crate::net::socket::socket_connect(socket_id, remote_ip, port) {
                Ok(()) => 0,
                Err(_) => -111, // ECONNREFUSED
            }
        }
        SYS_SENDTO => {
            // sendto(socket_id, buf_ptr, buf_len, ip_packed, port) -> bytes_sent or -errno
            let socket_id = arg1;
            let buf_ptr = arg2 as *const u8;
            let buf_len = arg3 as usize;
            let ip_packed = arg4 as u32;
            let port = arg5 as u16;
            if buf_len == 0 { return 0; }
            let data = unsafe { core::slice::from_raw_parts(buf_ptr, buf_len) };
            if ip_packed == 0 {
                // No destination — use connected destination (like send())
                match crate::net::socket::socket_send(socket_id, data) {
                    Ok(n) => n as i64,
                    Err(_) => -89, // EDESTADDRREQ
                }
            } else {
                let dst_ip = [
                    ((ip_packed >> 24) & 0xFF) as u8,
                    ((ip_packed >> 16) & 0xFF) as u8,
                    ((ip_packed >> 8) & 0xFF) as u8,
                    (ip_packed & 0xFF) as u8,
                ];
                match crate::net::socket::socket_sendto(socket_id, dst_ip, port, data) {
                    Ok(n) => n as i64,
                    Err(_) => -89,
                }
            }
        }
        SYS_RECVFROM => {
            // recvfrom(socket_id, buf_ptr, buf_len, _, _) -> bytes_received or -errno
            let socket_id = arg1;
            let buf_ptr = arg2 as *mut u8;
            let buf_len = arg3 as usize;
            match crate::net::socket::socket_recv(socket_id) {
                Ok(data) => {
                    let copy_len = data.len().min(buf_len);
                    if copy_len > 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, copy_len);
                        }
                    }
                    copy_len as i64
                }
                Err(_) => -11, // EAGAIN
            }
        }
        SYS_LISTEN => {
            // listen(socket_id, backlog) -> 0 or -errno
            let socket_id = arg1;
            let port = arg2 as u16;
            match crate::net::socket::socket_bind(socket_id, port) {
                Ok(()) => 0,
                Err(_) => -98,
            }
        }
        SYS_ACCEPT => {
            // accept(socket_id, _, _) -> new_socket_id or -errno
            // Stub: we don't have separate accept semantics yet
            -38 // ENOSYS for now
        }
        SYS_CLONE => {
            // clone() — simplified, just fork for now
            sys_fork()
        }
        SYS_FUTEX => {
            // futex(uaddr, op, val, timeout_ptr, uaddr2)
            sys_futex_linux(arg1, arg2, arg3, arg4, arg5)
        }
        SYS_SYNC => {
            // sync() — flush all dirty filesystem data to disk
            crate::vfs::sync_all();
            0
        }
        // 158: arch_prctl(code, addr) — TLS/FS-base setup.
        // Handled here as a defensive fallback for Linux ELF processes that
        // race through the scheduler before the caller sets linux_abi=true.
        158 => sys_arch_prctl(arg1, arg2),
        _ => {
            crate::serial_println!("[SYSCALL] Unknown syscall: {}", num);
            -38 // ENOSYS
        }
    }
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
fn read_fork_user_regs() -> crate::proc::ForkUserRegs {
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
fn sys_exec(path_ptr: u64, path_len: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
    let path = unsafe {
        let slice = core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize);
        match core::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -22, // EINVAL
        }
    };

    crate::serial_println!("[SYSCALL] exec(\"{}\")", path);

    // Read ELF binary from VFS.
    let elf_data = match crate::vfs::read_file(path) {
        Ok(data) => data,
        Err(e) => {
            crate::serial_println!("[SYSCALL] exec: file not found: {:?}", e);
            return crate::subsys::linux::errno::vfs_err(e);
        }
    };

    // Validate it's an ELF binary.
    if !crate::proc::elf::is_elf(&elf_data) {
        crate::serial_println!("[SYSCALL] exec: not an ELF binary");
        return -8; // ENOEXEC
    }

    // Read argv and envp arrays from user memory (null ptr → empty).
    let argv_owned = read_user_argv(argv_ptr);
    let envp_owned = read_user_argv(envp_ptr);

    // Build &[&str] slices valid for the duration of this call.
    let argv_strs: alloc::vec::Vec<&str> = argv_owned.iter().map(|s| s.as_str()).collect();
    let envp_strs: alloc::vec::Vec<&str> = envp_owned.iter().map(|s| s.as_str()).collect();

    // Default argv to [path] if caller passed NULL.
    let argv_slice: &[&str] = if argv_strs.is_empty() { &[path] } else { &argv_strs };
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

    // 2. Update the process's address space.
    // TODO: unmap old user pages and free old VmSpace physical pages.
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.cr3 = new_cr3;
            p.vm_space = Some(new_vm_space);
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
    }

    // 3. Get kernel stack info for this thread.
    let kstack_top = {
        let tid = crate::proc::current_tid();
        let threads = crate::proc::THREAD_TABLE.lock();
        let t = threads.iter().find(|t| t.tid == tid)
            .expect("sys_exec: current thread not found");
        t.kernel_stack_base + t.kernel_stack_size
    };

    // 4. Switch to the new page table.
    unsafe { crate::mm::vmm::switch_cr3(new_cr3); }

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
fn sys_fork() -> i64 {
    sys_fork_impl(0, 0)
}

/// Fork implementation shared by sys_fork() (syscall 57) and clone()-style fork (syscall 56).
/// `clone_flags` and `child_tidptr` are only used when called from clone().
fn sys_fork_impl(clone_flags: u64, child_tidptr: u64) -> i64 {
    const CLONE_CHILD_SETTID: u64 = 0x01000000;
    const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

    let parent_pid = crate::proc::current_pid();
    let parent_tid = crate::proc::current_tid();

    // Capture parent's callee-saved regs from the syscall entry frame BEFORE
    // fork_process() takes THREAD_TABLE lock (which changes the frame context).
    let parent_regs = read_fork_user_regs();

    crate::serial_println!("[SYSCALL] fork() from PID {} TID {}", parent_pid, parent_tid);

    // Create a new process (child) with a new PID and thread.
    match crate::proc::fork_process(parent_pid, parent_tid) {
        Some((child_pid, child_tid)) => {
            crate::serial_println!("[SYSCALL] fork: child PID {} created", child_pid);

            // Store parent callee-saved regs into child thread so fork_child_entry
            // can restore them before iretq — critical for glibc __fork epilogue.
            crate::proc::set_fork_user_regs(child_pid, child_tid, parent_regs);

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
unsafe fn write_u32_to_user_current(vaddr: u64, val: u32) {
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
fn write_u32_to_user(cr3: u64, vaddr: u64, val: u32) {
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
fn sys_waitpid(pid: i64, options: u32) -> i64 {
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
fn sys_ioctl(fd_num: usize, request: u64, arg_ptr: *mut u8) -> i64 {
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
    } else {
        0 // silently accept unknown ioctls
    }
}

/// Ioctls for the PTY master side (/dev/ptmx).
fn sys_pty_master_ioctl(pty_n: u8, request: u64, arg_ptr: *mut u8) -> i64 {
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
fn sys_fbdev_ioctl(request: u64, arg_ptr: *mut u8) -> i64 {
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
unsafe fn write_u32(base: *mut u8, offset: usize, val: u32) {
    core::ptr::write_unaligned(base.add(offset) as *mut u32, val.to_le());
}

/// Read a little-endian u32 at `offset` bytes from `base`.
#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(core::ptr::read_unaligned(base.add(offset) as *const u32))
}

// ===== input device (evdev) ioctls ==========================================

fn sys_input_ioctl(request: u64, arg_ptr: *mut u8) -> i64 {
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

// ===== mmap / munmap / brk ==================================================

/// mmap — Map virtual memory into the current process's address space.
///
/// Supports both anonymous (MAP_ANONYMOUS) and file-backed mappings.
/// Actual physical pages are allocated on demand via the page-fault handler.
fn sys_mmap(addr_hint: u64, length: u64, prot: u32, flags: u32, fd: u64, offset: u64) -> i64 {
    use crate::mm::vma::*;

    if length == 0 {
        return -22; // EINVAL
    }

    let length = page_align_up(length);
    let pid = crate::proc::current_pid();

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    // Ensure process has a VmSpace; lazily create one for kernel processes.
    if proc.vm_space.is_none() {
        proc.vm_space = Some(VmSpace::new_kernel());
    }
    let space = proc.vm_space.as_mut().unwrap();

    // Choose base address
    let base = if flags & MAP_FIXED as u32 != 0 {
        let base = page_align_down(addr_hint);
        if base == 0 {
            return -22; // EINVAL
        }
        // Remove any existing mappings in the range
        let _ = space.remove_range(base, length);
        base
    } else {
        match space.find_free_range(length) {
            Some(b) => b,
            None => return -12, // ENOMEM
        }
    };

    // Determine backing type: file-backed or anonymous
    let is_anon = flags & MAP_ANONYMOUS as u32 != 0
        || fd == u64::MAX
        || fd as i64 == -1;

    let (backing, name) = if is_anon {
        (VmBacking::Anonymous, "[mmap]")
    } else {
        // File-backed or device-backed mapping: look up the fd.
        let fd_num = fd as usize;
        match proc.file_descriptors.get(fd_num).and_then(|f| f.as_ref()) {
            Some(fd_entry) if fd_entry.open_path == "/dev/fb0" => {
                // Framebuffer mmap → device-backed VMA using SVGA physical base.
                if let Some((phys_base, _w, _h, _pitch)) =
                    crate::drivers::vmware_svga::get_framebuffer()
                {
                    (VmBacking::Device { phys_base }, "[fb0]")
                } else {
                    return -6; // ENXIO
                }
            }
            // /dev/dri/card0 and other device stubs → anonymous (renders nothing)
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

    let vma = VmArea {
        base,
        length,
        prot,
        flags,
        backing,
        name,
    };

    match space.insert_vma(vma) {
        Ok(()) => {
            // Update mmap hint for next allocation
            if base < space.mmap_hint {
                space.mmap_hint = base;
            }
            base as i64
        }
        Err(_) => -12, // ENOMEM
    }
}

/// munmap — Unmap a region of the current process's address space.
///
/// For each mapped page the reference count is decremented.  When it
/// reaches zero the physical frame is returned to the PMM.
fn sys_munmap(addr: u64, length: u64) -> i64 {
    use crate::mm::vma::*;

    if length == 0 || addr & 0xFFF != 0 {
        return -22; // EINVAL
    }

    let length = page_align_up(length);
    let pid = crate::proc::current_pid();

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    if let Some(space) = proc.vm_space.as_mut() {
        let cr3 = space.cr3;
        let mut page = addr;
        while page < addr + length {
            if let Some(phys) = crate::mm::vmm::virt_to_phys_in(cr3, page) {
                crate::mm::vmm::unmap_page_in(cr3, page);
                crate::mm::vmm::invlpg(page);
                // Decrement refcount; free the frame when no references remain.
                let new_rc = crate::mm::refcount::page_ref_dec(phys);
                if new_rc == 0 {
                    crate::mm::pmm::free_page(phys);
                }
            }
            page += 0x1000;
        }
        let _ = space.remove_range(addr, length);
    }

    0
}

/// brk — Adjust the program break (heap end).
///
/// If `new_brk` is 0, returns the current break.
/// Otherwise sets the break and returns the new value.
fn sys_brk(new_brk: u64) -> i64 {
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

fn sys_getppid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.parent_pid as i64,
        None => -3,
    }
}

fn sys_getuid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.uid as i64,
        None => -3,
    }
}

fn sys_getgid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.gid as i64,
        None => -3,
    }
}

fn sys_geteuid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.euid as i64,
        None => -3,
    }
}

fn sys_getegid() -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p.egid as i64,
        None => -3,
    }
}

fn sys_umask(new_mask: u32) -> i64 {
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

fn sys_getcwd(buf: *mut u8, size: usize) -> i64 {
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

fn sys_chdir(path_ptr: *const u8, path_len: usize) -> i64 {
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

fn sys_mkdir(path_ptr: *const u8, path_len: usize) -> i64 {
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

fn sys_rmdir(path_ptr: *const u8, path_len: usize) -> i64 {
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

fn fill_stat_buf(st: &crate::vfs::FileStat, buf: *mut u8) {
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

fn sys_stat(path_ptr: *const u8, path_len: usize, stat_buf: *mut u8) -> i64 {
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

fn sys_fstat(fd_num: usize, stat_buf: *mut u8) -> i64 {
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

fn sys_lseek(fd_num: usize, offset: i64, whence: u32) -> i64 {
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

fn sys_dup(old_fd: usize) -> i64 {
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

fn sys_dup2(old_fd: usize, new_fd: usize) -> i64 {
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

fn sys_pipe(fds_out: *mut u64) -> i64 {
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
fn is_pipe_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.mount_idx == usize::MAX && f.flags & 0x8000_0000 != 0)
        .unwrap_or(false)
}

/// Check if a file descriptor is a socket.
fn is_socket_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.mount_idx == usize::MAX && f.flags & 0x4000_0000 != 0)
        .unwrap_or(false)
}

/// Allocate a new socket fd for the given process, returning the fd number.
fn alloc_socket_fd(pid: u64, socket_id: u64, sock_type: u32) -> i64 {
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
fn get_pipe_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(0)
}

/// Get the socket_id for a socket file descriptor.
fn get_socket_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

/// Check if a file descriptor is an eventfd.
fn is_eventfd_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.file_type == crate::vfs::FileType::EventFd)
        .unwrap_or(false)
}

/// Get the eventfd slot ID for a file descriptor.
fn get_eventfd_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

// ── timerfd / signalfd / inotifyfd helpers ────────────────────────────────────

fn is_timerfd_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.file_type == crate::vfs::FileType::TimerFd)
        .unwrap_or(false)
}

fn get_timerfd_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

fn is_signalfd_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.file_type == crate::vfs::FileType::SignalFd)
        .unwrap_or(false)
}

fn get_signalfd_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

fn is_inotify_fd(pid: u64, fd_num: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.file_type == crate::vfs::FileType::InotifyFd)
        .unwrap_or(false)
}

fn get_inotify_id(pid: u64, fd_num: usize) -> u64 {
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
fn poll_revents(pid: u64, fd: usize, events: u16) -> u16 {
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
        0
    } else {
        events & (POLLIN | POLLOUT) // regular file always ready
    }
}

// ── AF_UNIX socket helpers ────────────────────────────────────────────────────

const UNIX_SOCKET_FLAG: u32 = 0x0080_0000; // bit 23: fd is an AF_UNIX socket

/// Check if a file descriptor is an AF_UNIX socket.
fn is_unix_socket_fd(pid: u64, fd_num: usize) -> bool {
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
fn get_unix_socket_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(u64::MAX)
}

/// Allocate a new AF_UNIX socket fd, returning the fd number or negative errno.
fn alloc_unix_socket_fd(pid: u64, unix_id: u64) -> i64 {
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
fn sys_uname(buf: *mut u8) -> i64 {
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

fn sys_nanosleep(milliseconds: u64) -> i64 {
    if milliseconds == 0 {
        crate::sched::yield_cpu();
        return 0;
    }

    // Convert milliseconds to timer ticks (assuming ~1000 Hz PIT).
    let ticks = if milliseconds == 0 { 1 } else { milliseconds };
    crate::proc::sleep_ticks(ticks);
    0
}

fn sys_unlink(path_ptr: *const u8, path_len: usize) -> i64 {
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

fn sys_sigaction(sig: u8, handler_addr: u64) -> i64 {
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

fn sys_sigprocmask(how: u32, new_mask: u64) -> i64 {
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
fn sys_sigreturn() -> i64 {
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
fn sys_getrandom(buf: *mut u8, count: usize) -> i64 {
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
// musl-libc (and other Linux binaries) use Linux x86_64 syscall numbers which
// differ from AstryxOS's custom numbering (0–49). This layer translates Linux
// numbers to AstryxOS handlers, adding Linux-specific syscalls needed for a
// static musl-linked "hello world" (printf + file I/O + malloc).

/// Check whether the current process uses the Linux syscall ABI.
fn is_linux_abi() -> bool {
    let pid = crate::proc::current_pid();
    if pid != 0 {
        // Fast path: PER_CPU_CURRENT_TID is correct.
        let procs = crate::proc::PROCESS_TABLE.lock();
        return procs.iter().find(|p| p.pid == pid).map(|p| {
            p.linux_abi || p.subsystem == crate::win32::SubsystemType::Linux
        }).unwrap_or(false);
    }

    // Slow-path: PER_CPU_CURRENT_TID is stale (scheduling race — the timer
    // preempted a user thread and switched to the idle thread, setting
    // PER_CPU_CURRENT_TID[0]=0, but the SYSCALL was already in-flight for the
    // user thread).
    //
    // PER_CPU_SYSCALL[cpu].kernel_rsp is set to a user thread's kernel-stack top
    // whenever that thread is scheduled in, and is NOT overwritten when kernel/idle
    // threads run (they have kernel_stack_base==0, so the scheduler skips the
    // set_kernel_rsp call).  We can therefore identify the thread that owns the
    // current SYSCALL by matching its kernel_stack_base+size against kernel_rsp.
    let kstack_top = unsafe { PER_CPU_SYSCALL[cpu_index()].kernel_rsp };
    if kstack_top == 0 {
        return false; // No user thread has been set up on this CPU yet.
    }
    let thread_pid = {
        let threads = crate::proc::THREAD_TABLE.lock();
        threads.iter()
            .find(|t| {
                t.tid != 0
                    && t.kernel_stack_base > 0
                    && t.kernel_stack_base + t.kernel_stack_size == kstack_top
            })
            .map(|t| t.pid)
    };
    if let Some(pid) = thread_pid {
        if pid != 0 {
            let procs = crate::proc::PROCESS_TABLE.lock();
            return procs.iter().find(|p| p.pid == pid).map(|p| {
                p.linux_abi || p.subsystem == crate::win32::SubsystemType::Linux
            }).unwrap_or(false);
        }
    }
    false
}

/// Read a null-terminated C string from user memory.
/// Returns a byte slice excluding the null terminator, limited to 4096 bytes.
fn read_cstring_from_user(ptr: u64) -> &'static [u8] {
    if ptr == 0 {
        return b"";
    }
    let start = ptr as *const u8;
    let mut len = 0usize;
    unsafe {
        while len < 4096 && *start.add(len) != 0 {
            len += 1;
        }
        core::slice::from_raw_parts(start, len)
    }
}

/// Read a null-terminated array of C string pointers (char *argv[]) from user memory.
/// Returns a Vec of owned strings. Stops at NULL pointer or 256 entries.
fn read_user_argv(ptr: u64) -> alloc::vec::Vec<alloc::string::String> {
    let mut result = alloc::vec::Vec::new();
    if ptr == 0 {
        return result;
    }
    let array = ptr as *const u64;
    for i in 0..256usize {
        let str_ptr = unsafe { *array.add(i) };
        if str_ptr == 0 {
            break;
        }
        let bytes = read_cstring_from_user(str_ptr);
        let s = alloc::string::String::from_utf8_lossy(bytes).into_owned();
        result.push(s);
    }
    result
}

/// Dispatch a Linux x86_64 syscall.
///
/// Maps Linux syscall numbers to AstryxOS handlers, handling differences
/// in argument encoding (e.g., C strings vs ptr+len for paths).
pub fn dispatch_linux(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    // ── Per-PID debug trace ───────────────────────────────────────────────────
    let trace_pid = DEBUG_TRACE_PID.load(core::sync::atomic::Ordering::Relaxed);
    let do_trace = trace_pid != 0 && crate::proc::current_pid() == trace_pid;
    if do_trace {
        crate::serial_println!("[TRACE] pid={} sys={} a1={:#x} a2={:#x} a3={:#x}",
            trace_pid, num, arg1, arg2, arg3);
    }

    // ── Transient debug trace: log Linux syscalls from user processes ─────────
    #[cfg(feature = "firefox-test")]
    {
        static TRACE_N: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);
        let pid = crate::proc::current_pid();
        if pid >= 1 {
            let n = TRACE_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if n < 10000 {
                crate::serial_println!("[LINUX-SYS] #{} pid={} num={} a1={:#x}", n, pid, num, arg1);
            }
        }
    }
    #[cfg(not(feature = "firefox-test"))]
    {
        static TRACE_N: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);
        let pid = crate::proc::current_pid();
        if pid >= 12 {
            let n = TRACE_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if n < 500 {
                crate::serial_println!("[LINUX-SYS] #{} pid={} num={} a1={:#x}", n, pid, num, arg1);
            }
        }
    }
    match num {
        // 0: read(fd, buf, count)
        0 => sys_read_linux(arg1, arg2, arg3),
        // 1: write(fd, buf, count)
        1 => sys_write_linux(arg1, arg2, arg3),
        // 2: open(pathname, flags, mode)
        2 => sys_open_linux(arg1, arg2, arg3),
        // 3: close(fd)
        3 => {
            let fd = arg1 as usize;
            let pid = crate::proc::current_pid();
            // If it's a unix socket fd, close the underlying unix socket.
            if is_unix_socket_fd(pid, fd) {
                let unix_id = get_unix_socket_id(pid, fd);
                crate::net::unix::close(unix_id);
            // If it's an AF_INET socket fd, close the underlying socket.
            } else if is_socket_fd(pid, fd) {
                let socket_id = get_socket_id(pid, fd);
                crate::net::socket::socket_close(socket_id);
            }
            // If it's an eventfd, free the counter slot.
            if is_eventfd_fd(pid, fd) {
                let efd_id = get_eventfd_id(pid, fd);
                crate::ipc::eventfd::close(efd_id);
            }
            // Free timerfd / signalfd / inotifyfd slots.
            if is_timerfd_fd(pid, fd) {
                crate::ipc::timerfd::close(get_timerfd_id(pid, fd));
            }
            if is_signalfd_fd(pid, fd) {
                crate::ipc::signalfd::close(get_signalfd_id(pid, fd));
            }
            if is_inotify_fd(pid, fd) {
                crate::ipc::inotify::close(get_inotify_id(pid, fd));
            }
            // If it's an epoll fd, remove the EpollInstance.
            {
                let is_epoll = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    procs.iter().find(|p| p.pid == pid)
                        .and_then(|p| p.file_descriptors.get(fd))
                        .and_then(|f| f.as_ref())
                        .map(|f| f.open_path == "[epoll]")
                        .unwrap_or(false)
                };
                if is_epoll {
                    let mut procs = crate::proc::PROCESS_TABLE.lock();
                    if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                        p.epoll_sets.retain(|e| e.epfd != fd);
                    }
                }
            }
            match crate::vfs::close(pid, fd) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 4: stat(pathname, statbuf)
        4 => sys_stat_linux(arg1, arg2),
        // 5: fstat(fd, statbuf)
        5 => sys_fstat_linux(arg1 as usize, arg2 as *mut u8),
        // 6: lstat(pathname, statbuf) — same as stat for us (no symlink follow)
        6 => sys_stat_linux(arg1, arg2),
        // 8: lseek(fd, offset, whence)
        8 => sys_lseek(arg1 as usize, arg2 as i64, arg3 as u32),
        // 9: mmap(addr, len, prot, flags, fd, offset)
        9 => sys_mmap(arg1, arg2, arg3 as u32, arg4 as u32, arg5, arg6),
        // 10: mprotect(addr, len, prot)
        10 => sys_mprotect(arg1, arg2, arg3),
        // 11: munmap(addr, len)
        11 => sys_munmap(arg1, arg2),
        // 12: brk(new_brk)
        12 => sys_brk(arg1),
        // 13: rt_sigaction(sig, act, oldact, sigsetsize)
        13 => sys_rt_sigaction_linux(arg1, arg2, arg3, arg4),
        // 14: rt_sigprocmask(how, set, oldset, sigsetsize)
        14 => sys_rt_sigprocmask_linux(arg1, arg2, arg3, arg4),
        // 15: rt_sigreturn
        15 => sys_sigreturn(),
        // 16: ioctl(fd, request, arg)
        16 => {
            let fd_num = arg1 as usize;
            let request = arg2;
            let arg_ptr = arg3 as *mut u8;
            sys_ioctl(fd_num, request, arg_ptr)
        }
        // 20: writev(fd, iov, iovcnt)
        20 => sys_writev(arg1, arg2, arg3),
        // 21: access(pathname, mode)
        21 => sys_access(arg1, arg2),
        // 24: sched_yield
        24 => {
            crate::sched::yield_cpu();
            0
        }
        // 39: getpid
        39 => crate::proc::current_pid() as i64,
        // 7: poll(fds, nfds, timeout) — wait for events on fds
        7 => {
            let nfds = arg2 as i64;
            let pid  = crate::proc::current_pid();
            let timeout_ms = arg3 as i64; // -1 = block; 0 = no wait

            if nfds <= 0 || arg1 == 0 {
                return 0;
            }

            // Poll entry logging disabled — deep call stack + serial formatting
            // was contributing to kernel stack overflow for Firefox.
            #[cfg(feature = "firefox-test")]
            if false && pid >= 1 {
                crate::serial_println!("[POLL_ENTRY] pid={} nfds={} timeout={}",
                    pid, nfds, timeout_ms);
            }

            // Inner check: evaluate all pollfds, write revents, return ready count.
            // struct pollfd { int fd; short events; short revents; } = 8 bytes
            let do_check = |clear: bool, log: bool| -> i64 {
                let mut ready = 0i64;
                for i in 0..nfds as u64 {
                    let base = (arg1 + i * 8) as *mut u8;
                    let (fd_val, events) = unsafe {
                        (core::ptr::read_unaligned(base as *const i32),
                         core::ptr::read_unaligned(base.add(4) as *const u16))
                    };
                    if fd_val < 0 {
                        if clear { unsafe { core::ptr::write_unaligned(base.add(6) as *mut u16, 0); } }
                        continue;
                    }
                    let revents = poll_revents(pid, fd_val as usize, events);
                    // Per-fd poll logging disabled to reduce kernel stack pressure.
                    let _ = log;
                    unsafe { core::ptr::write_unaligned(base.add(6) as *mut u16, revents); }
                    if revents != 0 { ready += 1; }
                }
                ready
            };

            let ready = do_check(false, true);
            if ready == 0 && timeout_ms != 0 {
                // Pump X11 once immediately after the initial check so the server can
                // process any pending requests from Firefox and write replies to its
                // socket buffer.  Then check AGAIN before the first yield — if X11
                // already wrote a reply, we can return without yielding at all.
                crate::x11::poll();
                let r = do_check(true, true);
                if r > 0 {
                    #[cfg(feature = "firefox-test")]
                    if pid >= 1 { crate::serial_println!("[POLL_RET] pid={} ret={} (post-x11-poll)", pid, r); }
                    return r;
                }
                let max_retries: usize = if timeout_ms < 0 { 64 } else {
                    ((timeout_ms as usize / 10).max(1)).min(64)
                };
                for _ in 0..max_retries {
                    crate::sched::yield_cpu();
                    // Pump X11 on each retry so concurrent X11 replies appear promptly.
                    crate::x11::poll();
                    let r = do_check(true, true);
                    if r > 0 {
                        #[cfg(feature = "firefox-test")]
                        if pid >= 1 { crate::serial_println!("[POLL_RET] pid={} ret={} (retry)", pid, r); }
                        return r;
                    }
                }
                #[cfg(feature = "firefox-test")]
                if pid >= 1 { crate::serial_println!("[POLL_RET] pid={} ret=0 (timeout)", pid); }
                0
            } else {
                #[cfg(feature = "firefox-test")]
                if pid >= 1 { crate::serial_println!("[POLL_RET] pid={} ret={} (immediate)", pid, ready); }
                ready
            }
        }
        // 17: pread64(fd, buf, count, offset)
        17 => {
            let fd = arg1 as usize;
            let buf = arg2 as *mut u8;
            let count = arg3 as usize;
            let offset = arg4 as i64;
            let pid = crate::proc::current_pid();
            // Save, seek, read, restore
            let saved = sys_lseek(fd, 0, 1 /*SEEK_CUR*/);
            let sk = sys_lseek(fd, offset, 0 /*SEEK_SET*/);
            if sk < 0 { return sk; }
            let n = crate::vfs::fd_read(pid, fd, buf, count);
            if saved >= 0 { let _ = sys_lseek(fd, saved, 0); }
            match n {
                Ok(n) => n as i64,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 18: pwrite64(fd, buf, count, offset)
        18 => {
            let fd = arg1 as usize;
            let buf = arg2 as *const u8;
            let count = arg3 as usize;
            let offset = arg4 as i64;
            let pid = crate::proc::current_pid();
            let saved = sys_lseek(fd, 0, 1);
            let sk = sys_lseek(fd, offset, 0);
            if sk < 0 { return sk; }
            let n = crate::vfs::fd_write(pid, fd, buf, count);
            if saved >= 0 { let _ = sys_lseek(fd, saved, 0); }
            match n {
                Ok(n) => n as i64,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 19: readv(fd, iov, iovcnt) — scatter-gather read
        19 => sys_readv(arg1, arg2, arg3),
        // 29: shmget(key, size, shmflg) — get/create shared memory segment
        29 => crate::ipc::sysv_shm::shmget(arg1 as i32, arg2, arg3 as i32),
        // 30: shmat(shmid, shmaddr, shmflg) — attach shared memory
        30 => crate::ipc::sysv_shm::shmat(arg1 as u32, arg2, arg3 as i32),
        // 31: shmdt(shmaddr) — detach shared memory
        31 => crate::ipc::sysv_shm::shmdt(arg1),
        // 65: shmctl(shmid, cmd, buf) — control shared memory
        65 => crate::ipc::sysv_shm::shmctl(arg1 as u32, arg2 as i32, arg3),
        // 32: dup(oldfd) — duplicate fd to lowest available slot
        32 => sys_dup(arg1 as usize),
        // 33: dup2(oldfd, newfd) — duplicate fd to specific slot
        33 => sys_dup2(arg1 as usize, arg2 as usize),
        // 34: pause() — sleep until signal (stub: yield)
        34 => {
            crate::sched::yield_cpu();
            -4 // EINTR
        }
        // 35: nanosleep(req, rem) — struct timespec { tv_sec: i64, tv_nsec: i64 }
        35 => sys_nanosleep_linux(arg1, arg2),
        // 40: sendfile(out_fd, in_fd, offset_ptr, count)
        40 => sys_sendfile(arg1 as usize, arg2 as usize, arg3, arg4 as usize),
        // ── Phase 4: Socket syscalls (sockets as file descriptors) ───────────
        // 41: socket(domain, type, protocol) → fd
        41 => {
            let domain = arg1 as u32;  // AF_INET=2, AF_UNIX=1, AF_INET6=10
            let sock_type = arg2 & 0xFF; // strip SOCK_NONBLOCK/SOCK_CLOEXEC
            let pid = crate::proc::current_pid();
            if domain == 1 {
                // AF_UNIX: use net::unix module
                let unix_id = crate::net::unix::create();
                if unix_id == u64::MAX { return -24; } // EMFILE
                alloc_unix_socket_fd(pid, unix_id)
            } else if domain == 2 || domain == 10 {
                // AF_INET / AF_INET6
                let net_type = match sock_type {
                    1 => crate::net::socket::SocketType::Tcp,
                    _ => crate::net::socket::SocketType::Udp,
                };
                let socket_id = crate::net::socket::socket_create(net_type);
                alloc_socket_fd(pid, socket_id, sock_type as u32)
            } else {
                -22 // EINVAL — unsupported domain
            }
        }
        // 42: connect(sockfd, addr, addrlen)
        42 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            let addr_ptr = arg2;
            let addrlen = arg3 as usize;
            if addrlen < 2 || addr_ptr == 0 { return -22; }
            let family = unsafe { core::ptr::read_unaligned(addr_ptr as *const u16) };

            if family == 1 {
                // AF_UNIX — sockaddr_un { sa_family: u16, sun_path: [u8; 108] }
                if !is_unix_socket_fd(pid, fd) { return -9; }
                let unix_id = get_unix_socket_id(pid, fd);
                let path_bytes = if addrlen > 2 {
                    unsafe { core::slice::from_raw_parts((addr_ptr + 2) as *const u8, (addrlen - 2).min(108)) }
                } else { return -22; };
                // Strip trailing NUL
                let plen = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
                #[cfg(feature = "firefox-test")]
                if pid >= 1 {
                    if let Ok(p) = core::str::from_utf8(&path_bytes[..plen]) {
                        crate::serial_println!("[FF/connect] pid={} path={}", pid, p);
                    }
                }
                crate::net::unix::connect(unix_id, &path_bytes[..plen])
            } else {
                if !is_socket_fd(pid, fd) { return -9; }
                let socket_id = get_socket_id(pid, fd);
                if family == 2 && addrlen >= 16 {
                    // sockaddr_in
                    let bytes = unsafe { core::slice::from_raw_parts(addr_ptr as *const u8, 16) };
                    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                    let ip = [bytes[4], bytes[5], bytes[6], bytes[7]];
                    match crate::net::socket::socket_connect(socket_id, ip, port) {
                        Ok(()) => {
                            // For TCP: wait up to 3s for connection to become Established.
                            let local_port = {
                                let socks = crate::net::socket::SOCKETS.lock();
                                socks.iter().find(|s| s.id == socket_id).map(|s| s.local_port)
                            };
                            if let Some(lport) = local_port {
                                let deadline = crate::arch::x86_64::irq::get_ticks() + 300;
                                loop {
                                    crate::net::poll();
                                    match crate::net::tcp::get_state(lport) {
                                        Some(crate::net::tcp::TcpState::Established) => break,
                                        Some(crate::net::tcp::TcpState::Closed)
                                        | Some(crate::net::tcp::TcpState::TimeWait) => {
                                            return -111; // ECONNREFUSED
                                        }
                                        _ => {}
                                    }
                                    if crate::arch::x86_64::irq::get_ticks() >= deadline {
                                        return -110; // ETIMEDOUT
                                    }
                                    crate::sched::yield_cpu();
                                }
                            }
                            0
                        }
                        Err(_) => -111, // ECONNREFUSED
                    }
                } else {
                    0 // AF_INET6 stub
                }
            }
        }
        // 43: accept(sockfd, addr, addrlen) — AF_UNIX real; AF_INET stub
        43 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            if is_unix_socket_fd(pid, fd) {
                let unix_id = get_unix_socket_id(pid, fd);
                match crate::net::unix::accept(unix_id) {
                    peer_id if peer_id >= 0 => {
                        // Allocate an fd for the accepted connected socket.
                        alloc_unix_socket_fd(pid, peer_id as u64)
                    }
                    e => e, // EAGAIN or error
                }
            } else {
                -11 // EAGAIN (AF_INET accept stub: no real listener)
            }
        }
        // 44: sendto(sockfd, buf, len, flags, addr, addrlen)
        44 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            let buf_ptr = arg2 as *const u8;
            let len = arg3 as usize;
            let data = unsafe { core::slice::from_raw_parts(buf_ptr, len) };
            if is_unix_socket_fd(pid, fd) {
                let unix_id = get_unix_socket_id(pid, fd);
                crate::net::unix::write(unix_id, data)
            } else {
                if !is_socket_fd(pid, fd) { return -9; }
                let socket_id = get_socket_id(pid, fd);
                let addr_ptr = arg5;
                let addrlen = arg6 as usize;
                if addr_ptr != 0 && addrlen >= 16 {
                    let bytes = unsafe { core::slice::from_raw_parts(addr_ptr as *const u8, 16) };
                    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
                    if family == 2 {
                        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                        let ip = [bytes[4], bytes[5], bytes[6], bytes[7]];
                        match crate::net::socket::socket_sendto(socket_id, ip, port, data) {
                            Ok(n) => n as i64,
                            Err(_) => -104,
                        }
                    } else { len as i64 }
                } else {
                    match crate::net::socket::socket_send(socket_id, data) {
                        Ok(n) => n as i64,
                        Err(_) => -104,
                    }
                }
            }
        }
        // 45: recvfrom(sockfd, buf, len, flags, addr, addrlen)
        45 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            let buf_ptr = arg2 as *mut u8;
            let len = arg3 as usize;
            if is_unix_socket_fd(pid, fd) {
                let unix_id = get_unix_socket_id(pid, fd);
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };
                crate::net::unix::read(unix_id, buf)
            } else {
                if !is_socket_fd(pid, fd) { return -9; }
                let socket_id = get_socket_id(pid, fd);
                match crate::net::socket::socket_recv(socket_id) {
                    Ok(data) => {
                        let n = data.len().min(len);
                        if n > 0 { unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, n); } }
                        n as i64
                    }
                    Err(_) => -11,
                }
            }
        }
        // 46: sendmsg(sockfd, msg, flags) — use single-buffer fast path
        46 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            let msghdr_ptr = arg2 as *const u64;
            if msghdr_ptr.is_null() { return -22; }
            let iov_ptr = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(2)) }; // offset 16
            let iov_len = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(3)) }; // offset 24
            if iov_ptr == 0 || iov_len == 0 { return 0; }
            let iovecs = unsafe { core::slice::from_raw_parts(iov_ptr as *const [u64; 2], iov_len as usize) };
            let mut total = 0usize;
            for iov in iovecs {
                let base = iov[0] as *const u8;
                let slen = iov[1] as usize;
                if slen == 0 { continue; }
                let data = unsafe { core::slice::from_raw_parts(base, slen) };
                if is_unix_socket_fd(pid, fd) {
                    let unix_id = get_unix_socket_id(pid, fd);
                    match crate::net::unix::write(unix_id, data) {
                        n if n >= 0 => total += n as usize,
                        e => return e,
                    }
                } else {
                    if !is_socket_fd(pid, fd) { return -9; }
                    let socket_id = get_socket_id(pid, fd);
                    match crate::net::socket::socket_send(socket_id, data) {
                        Ok(n) => total += n,
                        Err(_) => return -104,
                    }
                }
            }
            // Handle SCM_RIGHTS in msg_control (Unix sockets only).
            // msghdr layout (x86_64): msg_control at byte-offset 32 (u64 index 4),
            // msg_controllen at byte-offset 40 (u64 index 5).
            if is_unix_socket_fd(pid, fd) {
                let ctrl_ptr = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(4)) };
                let ctrl_len = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(5)) } as usize;
                if ctrl_ptr != 0 && ctrl_len >= 16 {
                    let ctrl = ctrl_ptr as *const u8;
                    // cmsghdr: cmsg_len(u64@0), cmsg_level(i32@8), cmsg_type(i32@12)
                    let cmsg_len   = unsafe { core::ptr::read_unaligned(ctrl as *const u64) } as usize;
                    let cmsg_level = unsafe { core::ptr::read_unaligned((ctrl_ptr + 8)  as *const i32) };
                    let cmsg_type  = unsafe { core::ptr::read_unaligned((ctrl_ptr + 12) as *const i32) };
                    const SOL_SOCKET_I32: i32 = 1;
                    const SCM_RIGHTS_I32: i32 = 1;
                    if cmsg_level == SOL_SOCKET_I32 && cmsg_type == SCM_RIGHTS_I32 && cmsg_len > 16 {
                        let nfds = (cmsg_len.min(ctrl_len) - 16) / 4;
                        let fd_arr = (ctrl_ptr + 16) as *const i32;
                        let sender_fds: Vec<crate::vfs::FileDescriptor> = {
                            let procs = crate::proc::PROCESS_TABLE.lock();
                            if let Some(p) = procs.iter().find(|p| p.pid == pid) {
                                (0..nfds).filter_map(|i| {
                                    let fd_n = unsafe { core::ptr::read_unaligned(fd_arr.add(i)) } as usize;
                                    if fd_n < p.file_descriptors.len() {
                                        p.file_descriptors[fd_n].clone()
                                    } else { None }
                                }).collect()
                            } else { Vec::new() }
                        };
                        if !sender_fds.is_empty() {
                            let unix_id  = get_unix_socket_id(pid, fd);
                            let peer_id  = crate::net::unix::get_peer(unix_id);
                            if peer_id != u64::MAX {
                                scm_queue(peer_id, sender_fds);
                            }
                        }
                    }
                }
            }
            total as i64
        }
        // 47: recvmsg(sockfd, msg, flags) — via socket_recv / unix::read
        47 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            let msghdr_ptr = arg2 as *const u64;
            if msghdr_ptr.is_null() { return -22; }
            let iov_ptr = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(2)) };
            let iov_len = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(3)) };
            if iov_ptr == 0 || iov_len == 0 { return -22; }
            let iov = unsafe { core::slice::from_raw_parts(iov_ptr as *const [u64; 2], 1) };
            let dst = iov[0][0] as *mut u8;
            let cap = iov[0][1] as usize;
            let bytes_read: i64;
            if is_unix_socket_fd(pid, fd) {
                let unix_id = get_unix_socket_id(pid, fd);
                let buf = unsafe { core::slice::from_raw_parts_mut(dst, cap) };
                bytes_read = crate::net::unix::read(unix_id, buf);
                // Deliver pending SCM_RIGHTS fds into receiver's fd table.
                if bytes_read >= 0 {
                    if let Some(scm_fds) = scm_dequeue(unix_id) {
                        // Allocate fds in the receiver's process.
                        let new_fd_nums: Vec<i32> = {
                            let mut procs = crate::proc::PROCESS_TABLE.lock();
                            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                                scm_fds.into_iter().map(|fdesc| {
                                    // Find free slot.
                                    let slot = p.file_descriptors.iter()
                                        .position(|e| e.is_none())
                                        .unwrap_or(p.file_descriptors.len());
                                    if slot == p.file_descriptors.len() {
                                        p.file_descriptors.push(Some(fdesc));
                                    } else {
                                        p.file_descriptors[slot] = Some(fdesc);
                                    }
                                    slot as i32
                                }).collect()
                            } else { Vec::new() }
                        };
                        // Write SCM_RIGHTS cmsghdr into msg_control.
                        let ctrl_ptr = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(4)) };
                        let ctrl_len = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(5)) } as usize;
                        if ctrl_ptr != 0 && ctrl_len >= 16 + new_fd_nums.len() * 4 {
                            let needed = 16 + new_fd_nums.len() * 4;
                            unsafe {
                                core::ptr::write_unaligned(ctrl_ptr as *mut u64, needed as u64);
                                core::ptr::write_unaligned((ctrl_ptr + 8)  as *mut i32, 1i32); // SOL_SOCKET
                                core::ptr::write_unaligned((ctrl_ptr + 12) as *mut i32, 1i32); // SCM_RIGHTS
                                for (i, &new_fd) in new_fd_nums.iter().enumerate() {
                                    core::ptr::write_unaligned((ctrl_ptr + 16 + i as u64 * 4) as *mut i32, new_fd);
                                }
                            }
                            unsafe { core::ptr::write_unaligned(msghdr_ptr.add(5) as *mut u64, needed as u64); }
                        } else if ctrl_ptr != 0 {
                            // No room — zero out msg_controllen.
                            unsafe { core::ptr::write_unaligned(msghdr_ptr.add(5) as *mut u64, 0u64); }
                        }
                    } else {
                        // No SCM to deliver — set msg_controllen to 0.
                        let ctrl_ptr = unsafe { core::ptr::read_unaligned(msghdr_ptr.add(4)) };
                        if ctrl_ptr != 0 {
                            unsafe { core::ptr::write_unaligned(msghdr_ptr.add(5) as *mut u64, 0u64); }
                        }
                    }
                }
            } else {
                if !is_socket_fd(pid, fd) { return -9; }
                let socket_id = get_socket_id(pid, fd);
                bytes_read = match crate::net::socket::socket_recv(socket_id) {
                    Ok(data) => {
                        if data.is_empty() { 0 }
                        else {
                            let n = data.len().min(cap);
                            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n); }
                            n as i64
                        }
                    }
                    Err(_) => -11,
                };
            }
            bytes_read
        }
        // 48: shutdown(sockfd, how) — stub success
        48 => 0,
        // 49: bind(sockfd, addr, addrlen)
        49 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            let addr_ptr = arg2;
            let addrlen = arg3 as usize;
            if addrlen < 2 || addr_ptr == 0 { return -22; }
            let family = unsafe { core::ptr::read_unaligned(addr_ptr as *const u16) };
            if family == 1 {
                // AF_UNIX — sockaddr_un
                if !is_unix_socket_fd(pid, fd) { return -9; }
                let unix_id = get_unix_socket_id(pid, fd);
                let path_bytes = if addrlen > 2 {
                    unsafe { core::slice::from_raw_parts((addr_ptr + 2) as *const u8, (addrlen - 2).min(108)) }
                } else { return -22; };
                let plen = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
                crate::net::unix::bind(unix_id, &path_bytes[..plen])
            } else if family == 2 && addrlen >= 8 {
                if !is_socket_fd(pid, fd) { return -9; }
                let socket_id = get_socket_id(pid, fd);
                let bytes = unsafe { core::slice::from_raw_parts(addr_ptr as *const u8, 8) };
                let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                match crate::net::socket::socket_bind(socket_id, port) {
                    Ok(()) => 0,
                    Err(_) => -98, // EADDRINUSE
                }
            } else {
                0 // unknown family stub
            }
        }
        // 50: listen(sockfd, backlog)
        50 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            if is_unix_socket_fd(pid, fd) {
                let unix_id = get_unix_socket_id(pid, fd);
                crate::net::unix::listen(unix_id)
            } else {
                0 // AF_INET stub
            }
        }
        // 51: getsockname(sockfd, addr, addrlen)
        51 => {
            let pid = crate::proc::current_pid();
            let fd = arg1 as usize;
            if !is_socket_fd(pid, fd) { return -9; }
            let addr_ptr = arg2;
            let addrlen_ptr = arg3 as *mut u32;
            if addr_ptr != 0 {
                // Write sockaddr_in { AF_INET=2, port=0, addr=0.0.0.0 }
                let out = unsafe { core::slice::from_raw_parts_mut(addr_ptr as *mut u8, 16) };
                out.iter_mut().for_each(|b| *b = 0);
                out[0] = 2; // AF_INET
            }
            if !addrlen_ptr.is_null() {
                unsafe { core::ptr::write(addrlen_ptr, 16u32); }
            }
            0
        }
        // 52: getpeername(sockfd, addr, addrlen) — stub same as getsockname
        52 => {
            let addr_ptr = arg2;
            let addrlen_ptr = arg3 as *mut u32;
            if addr_ptr != 0 {
                let out = unsafe { core::slice::from_raw_parts_mut(addr_ptr as *mut u8, 16) };
                out.iter_mut().for_each(|b| *b = 0);
                out[0] = 2;
            }
            if !addrlen_ptr.is_null() {
                unsafe { core::ptr::write(addrlen_ptr, 16u32); }
            }
            0
        }
        // 53: socketpair(domain, type, protocol, sv[2]) — AF_UNIX loopback pair
        53 => {
            let domain = arg1 as u32;
            let sv_ptr = arg4 as *mut u32;
            if sv_ptr.is_null() { return -22; }
            if domain == 1 {
                // AF_UNIX socketpair
                let pid = crate::proc::current_pid();
                let (a, b) = crate::net::unix::socketpair();
                if a == u64::MAX { return -24; }
                let fd_a = alloc_unix_socket_fd(pid, a);
                if fd_a < 0 {
                    crate::net::unix::close(a);
                    crate::net::unix::close(b);
                    return fd_a;
                }
                let fd_b = alloc_unix_socket_fd(pid, b);
                if fd_b < 0 {
                    // Clean up fd_a: close the fd and the unix socket
                    crate::net::unix::close(a);
                    crate::net::unix::close(b);
                    return fd_b;
                }
                unsafe {
                    core::ptr::write(sv_ptr,       fd_a as u32);
                    core::ptr::write(sv_ptr.add(1), fd_b as u32);
                }
                0
            } else {
                -38 // ENOSYS for non-UNIX socketpair
            }
        }
        // 54: setsockopt(sockfd, level, optname, optval, optlen)
        54 => {
            let pid   = crate::proc::current_pid();
            let fd    = arg1 as usize;
            let level = arg2;
            let opt   = arg3;
            let val   = if arg4 != 0 { unsafe { core::ptr::read_unaligned(arg4 as *const u32) } }
                        else         { 0u32 };
            if is_socket_fd(pid, fd) {
                let sid = get_socket_id(pid, fd);
                crate::net::socket::socket_setsockopt(sid, level, opt, val) as i64
            } else {
                0 // AF_UNIX: ignore (no per-socket options tracked yet)
            }
        }
        // 55: getsockopt(sockfd, level, optname, optval, optlen)
        55 => {
            let pid    = crate::proc::current_pid();
            let fd     = arg1 as usize;
            let level  = arg2;
            let opt    = arg3;
            let optval = arg4 as *mut u32;
            let optlen = arg5 as *mut u32;
            // Check AF_UNIX FIRST — unix socket fds also have the
            // 0x4000_0000 socket flag set, so is_socket_fd returns true
            // for them.  But TCP/UDP socket_getsockopt returns 0 when the
            // unix socket ID isn't found, causing Firefox's
            // CHECK(buf_len > 0) to ABORT.
            let val = if is_unix_socket_fd(pid, fd) {
                const SOL_SOCKET:  u64 = 1;
                const SO_TYPE:     u64 = 3;
                const SO_RCVBUF:   u64 = 8;
                const SO_SNDBUF:   u64 = 7;
                const SO_ERROR:    u64 = 4;
                const SO_PEERCRED: u64 = 17;
                match (level, opt) {
                    (SOL_SOCKET, SO_TYPE)   => 1,  // SOCK_STREAM
                    (SOL_SOCKET, SO_RCVBUF) => 87380,
                    (SOL_SOCKET, SO_SNDBUF) => 131072,
                    (SOL_SOCKET, SO_ERROR)  => 0,
                    (SOL_SOCKET, SO_PEERCRED) => {
                        // Return struct ucred { pid, uid, gid } = 12 bytes
                        if !optval.is_null() {
                            unsafe {
                                let p = optval as *mut u8;
                                core::ptr::write(p as *mut u32, crate::proc::current_pid() as u32);
                                core::ptr::write(p.add(4) as *mut u32, 0); // uid
                                core::ptr::write(p.add(8) as *mut u32, 0); // gid
                            }
                        }
                        if !optlen.is_null() { unsafe { core::ptr::write(optlen, 12u32); } }
                        return 0i64;
                    }
                    _ => 0,
                }
            } else if is_socket_fd(pid, fd) {
                let sid = get_socket_id(pid, fd);
                crate::net::socket::socket_getsockopt(sid, level, opt)
            } else {
                // Unknown fd type — return sensible defaults
                const SOL_SOCKET:  u64 = 1;
                const SO_TYPE:     u64 = 3;
                const SO_RCVBUF:   u64 = 8;
                const SO_SNDBUF:   u64 = 7;
                match (level, opt) {
                    (SOL_SOCKET, SO_TYPE)   => 1,
                    (SOL_SOCKET, SO_RCVBUF) => 87380,
                    (SOL_SOCKET, SO_SNDBUF) => 131072,
                    _ => 0,
                }
            };
            if !optval.is_null() { unsafe { core::ptr::write(optval, val); } }
            if !optlen.is_null() { unsafe { core::ptr::write(optlen, 4u32); } }
            0
        }
        // 56: clone(flags, stack, parent_tid, child_tid, tls)
        // Linux x86-64 clone ABI: rdi=flags, rsi=stack, rdx=ptid, r10=ctid, r8=tls
        // In our dispatch: arg1=rdi, arg2=rsi, arg3=rdx, arg4=r10, arg5=r8
        56 => {
            let flags = arg1;
            let new_stack = arg2;
            let tls = arg5;   // r8 → arg5 (NOT arg4 which is ctid/r10)
            const CLONE_THREAD: u64 = 0x00010000;
            const CLONE_VM:     u64 = 0x00000100;
            const CLONE_SETTLS: u64 = 0x00080000;
            if flags & CLONE_THREAD != 0 && flags & CLONE_VM != 0 {
                // pthread_create-style clone: new thread in same address space.
                let user_rip = unsafe { get_user_rip() };
                let tls_val = if flags & CLONE_SETTLS != 0 { tls } else { 0 };
                let pid = crate::proc::current_pid();
                let parent_tidptr = arg3; // rdx = parent_tid
                let child_tidptr  = arg4; // r10 = child_tid
                match crate::proc::usermode::create_user_thread(pid, user_rip, new_stack, tls_val, 0, 0) {
                    Some(tid) => {
                        crate::serial_println!("[CLONE] Thread TID {} spawned in PID {}", tid, pid);

                        // CLONE_CHILD_SETTID: write TID into child's TCB tid field.
                        const CLONE_CHILD_SETTID: u64 = 0x01000000;
                        if flags & CLONE_CHILD_SETTID != 0 && child_tidptr != 0 {
                            unsafe { write_u32_to_user_current(child_tidptr, tid as u32); }
                        }
                        const CLONE_PARENT_SETTID: u64 = 0x00100000;
                        if flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
                            unsafe { write_u32_to_user_current(parent_tidptr, tid as u32); }
                        }
                        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
                        if flags & CLONE_CHILD_CLEARTID != 0 && child_tidptr != 0 {
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid as u64) {
                                t.clear_child_tid = child_tidptr;
                            }
                        }

                        tid as i64
                    }
                    None => -11, // EAGAIN
                }
            } else if flags & (CLONE_VM as u64) != 0 {
                // CLONE_VM without CLONE_THREAD = vfork-style.
                // Linux pattern: CoW fork + parent blocks until child execs/exits.
                // Child signals completion via vfork_parent_tid in exec/exit paths.
                const CLONE_VFORK: u64 = 0x00004000;
                let is_vfork = flags & CLONE_VFORK != 0;
                let parent_tid = crate::proc::current_tid();
                crate::serial_println!("[VFORK] pid={} flags={:#x} vfork={} parent_tid={}",
                    crate::proc::current_pid(), flags, is_vfork, parent_tid);

                let child_tidptr = arg4; // r10 = ctid
                let child_pid = sys_fork_impl(flags, child_tidptr);

                if child_pid > 0 && is_vfork {
                    // Store parent TID in child thread so exec/exit can wake us.
                    // The child's first (and only) thread has the same PID.
                    {
                        let mut threads = crate::proc::THREAD_TABLE.lock();
                        for t in threads.iter_mut() {
                            if t.pid == child_pid as u64 {
                                t.vfork_parent_tid = Some(parent_tid);
                                break;
                            }
                        }
                    }

                    // Block parent until child signals completion.
                    // Linux: wait_for_vfork_done() uses completion semaphore.
                    // We use Blocked state + schedule() — child wakes us.
                    {
                        let mut threads = crate::proc::THREAD_TABLE.lock();
                        if let Some(t) = threads.iter_mut().find(|t| t.tid == parent_tid) {
                            t.state = crate::proc::ThreadState::Blocked;
                            t.wake_tick = u64::MAX; // indefinite block
                        }
                    }
                    crate::sched::schedule();
                    // Resumed: child called exec or exit and woke us.
                }

                child_pid
            } else {
                // Fork-style clone: new address space copy.
                // Pass flags and child_tidptr for CLONE_CHILD_SETTID support.
                sys_fork_impl(flags, arg4)
            }
        }
        // 57: fork
        57 => sys_fork(),
        // 74: fsync(fd) — flush file data to storage (stub: VFS has no dirty state yet)
        74 => 0,
        // 75: fdatasync(fd) — flush file data (no metadata) to storage (stub)
        75 => 0,
        // 77: ftruncate(fd, length) — truncate open file to given length
        77 => {
            let pid = crate::proc::current_pid();
            match crate::vfs::fd_truncate(pid, arg1 as usize, arg2) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 82: rename(oldpath, newpath) — C strings
        82 => {
            let old_raw = read_cstring_from_user(arg1);
            let new_raw = read_cstring_from_user(arg2);
            let old_str = core::str::from_utf8(&old_raw).unwrap_or("");
            let new_str = core::str::from_utf8(&new_raw).unwrap_or("");
            match crate::vfs::rename(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 89: readlink(path, buf, bufsiz) — C string path
        // Special-cased for /proc/self/exe → returns current process executable path.
        89 => {
            let raw = read_cstring_from_user(arg1);
            let path_str = core::str::from_utf8(&raw).unwrap_or("");
            let buf = arg2 as *mut u8;
            let bufsiz = arg3 as usize;

            // /proc/self/exe — resolve to current process exe path.
            let target_str: alloc::string::String = if path_str == "/proc/self/exe"
                || path_str == "/proc/self/fd/exe"
            {
                let pid = crate::proc::current_pid();
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.exe_path.as_ref())
                    .map(|s| s.clone())
                    .unwrap_or_else(|| alloc::string::String::from("/bin/init"))
            } else if path_str.starts_with("/proc/self/fd/") {
                // /proc/self/fd/<N> — returns the open_path for fd N.
                let fd_part = &path_str["/proc/self/fd/".len()..];
                let fd_num = fd_part.parse::<usize>().unwrap_or(usize::MAX);
                let pid = crate::proc::current_pid();
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.file_descriptors.get(fd_num))
                    .and_then(|f| f.as_ref())
                    .map(|f| f.open_path.clone())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| {
                        alloc::format!("/dev/fd/{}", fd_num)
                    })
            } else {
                match crate::vfs::readlink(path_str) {
                    Ok(t) => t,
                    Err(_) => return -22, // EINVAL
                }
            };

            let bytes = target_str.as_bytes();
            let len = bytes.len().min(bufsiz);
            if len > 0 {
                unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len); }
            }
            len as i64
        }
        // 157: prctl(option, arg2, arg3, arg4, arg5)
        157 => {
            const PR_SET_NAME: u64              = 15;
            const PR_GET_NAME: u64              = 16;
            const PR_SET_DUMPABLE: u64          = 4;
            const PR_GET_DUMPABLE: u64          = 3;
            const PR_SET_PDEATHSIG: u64         = 1;
            const PR_SET_CHILD_SUBREAPER: u64   = 36;
            const PR_GET_CHILD_SUBREAPER: u64   = 37;
            const PR_SET_NO_NEW_PRIVS: u64      = 38;
            const PR_GET_NO_NEW_PRIVS: u64      = 39;
            const PR_SET_SECCOMP: u64           = 22;
            const PR_GET_SECCOMP: u64           = 21;
            const PR_SET_KEEPCAPS: u64          = 8;
            const PR_GET_KEEPCAPS: u64          = 7;
            const PR_CAP_AMBIENT: u64           = 47;
            match arg1 {
                PR_SET_NAME => 0,   // ignore thread name
                PR_GET_NAME => {
                    let buf = arg2 as *mut u8;
                    let name = b"astryx\0";
                    unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), buf, name.len()); }
                    0
                }
                PR_SET_DUMPABLE          => 0,
                PR_GET_DUMPABLE          => 0,
                PR_SET_PDEATHSIG         => 0,
                PR_SET_CHILD_SUBREAPER   => 0, // stub: accept but no real subreaper support
                PR_GET_CHILD_SUBREAPER   => {
                    // Report "not a subreaper"
                    if arg2 != 0 {
                        unsafe { core::ptr::write_unaligned(arg2 as *mut u32, 0); }
                    }
                    0
                }
                PR_SET_NO_NEW_PRIVS      => {
                    if arg2 == 1 {
                        let pid = crate::proc::current_pid();
                        let mut procs = crate::proc::PROCESS_TABLE.lock();
                        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                            p.no_new_privs = true;
                        }
                    }
                    0
                }
                PR_GET_NO_NEW_PRIVS      => {
                    let pid = crate::proc::current_pid();
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    procs.iter().find(|p| p.pid == pid)
                        .map(|p| if p.no_new_privs { 1i64 } else { 0i64 })
                        .unwrap_or(0)
                }
                PR_SET_SECCOMP           => 0, // stub: accept any seccomp mode
                PR_GET_SECCOMP           => 0, // SECCOMP_MODE_DISABLED
                PR_SET_KEEPCAPS          => 0,
                PR_GET_KEEPCAPS          => 0,
                PR_CAP_AMBIENT           => 0, // no ambient capability support
                _                        => 0, // permissive default
            }
        }
        // 186: gettid — return current kernel thread ID
        186 => crate::proc::current_tid() as i64,
        // 187: readahead(fd, offset, count) — pre-cache pages; no page cache, return success
        187 => 0,
        // 203: sched_setaffinity(pid, cpusetsize, mask) — stub (accept any)
        203 => 0,
        // 204: sched_getaffinity(pid, cpusetsize, mask) — report CPU 0 only
        204 => {
            let buf = arg3 as *mut u8;
            let bufsiz = arg2 as usize;
            if buf != core::ptr::null_mut() {
                // Zero the buffer, then set bit 0 (CPU 0).
                unsafe {
                    core::ptr::write_bytes(buf, 0, bufsiz.min(128));
                    if bufsiz >= 1 { core::ptr::write(buf, 0x01); }
                }
            }
            0
        }
        // 209: io_setup stub
        209 => -38,
        // 213: epoll_create(size) — same semantics as epoll_create1(0)
        213 => sys_epoll_create1(0),
        // 232: epoll_wait(epfd, events_ptr, maxevents, timeout_ms)
        232 => sys_epoll_wait(arg1 as usize, arg2, arg3 as usize, arg4 as i32),
        // 233: epoll_ctl(epfd, op, fd, event_ptr)
        233 => sys_epoll_ctl(arg1 as usize, arg2, arg3 as usize, arg4),
        // 273: set_robust_list(head, len) — stub
        273 => 0,
        // 274: get_robust_list(pid, head_ptr, len_ptr) — stub
        274 => 0,
        // 281: epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)
        //      Same as epoll_wait but with optional signal mask — we ignore the mask.
        281 => sys_epoll_wait(arg1 as usize, arg2, arg3 as usize, arg4 as i32),
        // 291: epoll_create1(flags)
        291 => sys_epoll_create1(arg1 as u32),
        // 309: getcpu(cpu, node, cache) — stub
        309 => {
            if arg1 != 0 { unsafe { core::ptr::write(arg1 as *mut u32, 0); } }
            if arg2 != 0 { unsafe { core::ptr::write(arg2 as *mut u32, 0); } }
            0
        }
        // 59: execve(pathname, argv, envp) — pathname is C string
        59 => {
            let path_bytes = read_cstring_from_user(arg1);
            sys_exec(arg1, path_bytes.len() as u64, arg2, arg3)
        }
        // 60: exit(status)
        60 => {
            crate::proc::exit_thread(arg1 as i64);
            0
        }
        // 61: wait4(pid, wstatus, options, rusage)
        61 => sys_waitpid(arg1 as i64, arg3 as u32),
        // 62: kill(pid, sig)
        62 => crate::signal::kill(arg1, arg2 as u8),
        // 72: fcntl(fd, cmd, arg)
        72 => sys_fcntl(arg1, arg2, arg3),
        // 79: getcwd(buf, size)
        79 => sys_getcwd(arg1 as *mut u8, arg2 as usize),
        // 80: chdir(pathname) — C string
        80 => sys_chdir_linux(arg1),
        // 81: fchdir(fd) — change CWD to the directory opened as fd
        81 => sys_fchdir_linux(arg1),
        // 83: mkdir(pathname, mode) — C string
        83 => sys_mkdir_linux(arg1, arg2),
        // 84: rmdir(pathname) — C string
        84 => sys_rmdir_linux(arg1),
        // 87: unlink(pathname) — C string
        87 => sys_unlink_linux(arg1),
        // 88: symlink(oldpath, newpath) — C strings
        88 => {
            let old_raw = read_cstring_from_user(arg1);
            let new_raw = read_cstring_from_user(arg2);
            let old_str = core::str::from_utf8(old_raw).unwrap_or("");
            let new_str = core::str::from_utf8(new_raw).unwrap_or("");
            match crate::vfs::symlink(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => -(e as usize as i64),
            }
        }
        // 96: gettimeofday(tv, tz)
        96 => sys_gettimeofday(arg1, arg2),
        // 102: getuid
        102 => sys_getuid(),
        // 104: getgid
        104 => sys_getgid(),
        // 107: geteuid
        107 => sys_geteuid(),
        // 108: getegid
        108 => sys_getegid(),
        // 110: getppid
        110 => sys_getppid(),
        // 131: sigaltstack(ss, old_ss) — stub
        131 => 0,
        // 158: arch_prctl(code, addr)
        158 => sys_arch_prctl(arg1, arg2),
        // 125: capget(_capuser_header_t hdrp, capuser_data_t datap)
        125 => {
            // Return all capabilities (root-equivalent) for the calling process.
            // struct __user_cap_data_struct: effective(u32), permitted(u32), inheritable(u32)
            // For version 3 (0x20080522), two consecutive structs are expected (64-bit caps).
            if arg2 != 0 && validate_user_ptr(arg2, 24) {
                let pid = crate::proc::current_pid();
                let procs = crate::proc::PROCESS_TABLE.lock();
                let (eff, perm) = procs.iter().find(|p| p.pid == pid)
                    .map(|p| (p.cap_effective as u32, p.cap_permitted as u32))
                    .unwrap_or((!0u32, !0u32));
                drop(procs);
                unsafe {
                    let p = arg2 as *mut u32;
                    // struct 0: effective, permitted, inheritable
                    core::ptr::write_unaligned(p,         eff);
                    core::ptr::write_unaligned(p.add(1),  perm);
                    core::ptr::write_unaligned(p.add(2),  0u32); // inheritable
                    // struct 1: upper 32 bits (always 0 for us)
                    core::ptr::write_unaligned(p.add(3),  0u32);
                    core::ptr::write_unaligned(p.add(4),  0u32);
                    core::ptr::write_unaligned(p.add(5),  0u32);
                }
            }
            0
        }
        // 126: capset(_capuser_header_t hdrp, const capuser_data_t datap)
        126 => {
            // Accept capability drops; update effective/permitted in PCB.
            if arg2 != 0 && validate_user_ptr(arg2, 12) {
                let pid = crate::proc::current_pid();
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    let dp = arg2 as *const u32;
                    let eff  = unsafe { core::ptr::read_unaligned(dp) };
                    let perm = unsafe { core::ptr::read_unaligned(dp.add(1)) };
                    p.cap_effective  = eff  as u64;
                    p.cap_permitted  = perm as u64;
                }
            }
            0
        }
        // 160: setrlimit(resource, rlim) — update per-process soft limit
        160 => {
            let resource = arg1 as usize;
            if resource >= 16 { return -22; } // EINVAL
            if !validate_user_ptr(arg2, 16) { return -14; } // EFAULT
            let soft = unsafe { core::ptr::read_unaligned(arg2 as *const u64) };
            let pid = crate::proc::current_pid();
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.rlimits_soft[resource] = soft;
            }
            0
        }
        // 202: futex(uaddr, futex_op, val, ...)
        202 => sys_futex_linux(arg1, arg2, arg3, arg4, arg5),
        // 217: getdents64(fd, dirp, count)
        217 => sys_getdents64(arg1, arg2, arg3),
        // 218: set_tid_address(tidptr)
        218 => sys_set_tid_address(arg1),
        // 228: clock_gettime(clockid, tp)
        228 => sys_clock_gettime(arg1, arg2),
        // 231: exit_group(status) — terminate all threads in the process
        231 => {
            crate::serial_println!("[SYSCALL/Linux] exit_group({})", arg1 as i32);
            crate::proc::exit_group(arg1 as i64);
            0
        }
        // 234: tgkill(tgid, tid, sig)
        234 => crate::signal::kill(arg2, arg3 as u8),
        // 247: waitid(idtype, id, infop, options, rusage)
        // idtype: P_ALL=0, P_PID=1, P_PGID=2
        // options: WEXITED=4, WNOHANG=1, WSTOPPED=2, WCONTINUED=8
        247 => {
            let idtype  = arg1 as u32;
            let id      = arg2 as i64;
            let infop   = arg3 as *mut u8; // siginfo_t*
            let options = arg4 as u32;
            const WNOHANG:  u32 = 1;
            const WEXITED:  u32 = 4;
            let pid: i64 = match idtype {
                0 => -1,    // P_ALL  — any child
                1 => id,    // P_PID  — specific pid
                2 => -id,   // P_PGID — process group (approximate as -pgid)
                _ => return -22, // EINVAL
            };
            if options & WEXITED == 0 { return -22; } // must request at least WEXITED
            let ret = sys_waitpid(pid, if options & WNOHANG != 0 { WNOHANG } else { 0 });
            if ret > 0 && !infop.is_null() {
                // Fill minimal siginfo_t: si_signo=SIGCHLD(17), si_errno=0,
                // si_code=CLD_EXITED(1), si_pid=child_pid, si_status=exit_code
                // siginfo_t is 128 bytes; we only fill the first 20 bytes.
                unsafe {
                    core::ptr::write_bytes(infop, 0, 128);
                    core::ptr::write_unaligned(infop.add(0)  as *mut i32, 17); // si_signo = SIGCHLD
                    core::ptr::write_unaligned(infop.add(8)  as *mut i32, 1);  // si_code  = CLD_EXITED
                    core::ptr::write_unaligned(infop.add(12) as *mut i32, ret as i32); // si_pid
                }
            }
            if ret > 0 { 0 } else { ret } // waitid returns 0 on success (not child pid)
        }
        // 257: openat(dirfd, pathname, flags, mode)
        257 => sys_openat(arg1, arg2, arg3, arg4),
        // 262: newfstatat(dirfd, pathname, statbuf, flags)
        262 => sys_newfstatat(arg1, arg2, arg3, arg4),
        // 302: prlimit64(pid, resource, new_limit, old_limit)
        302 => {
            // GET old limit if requested
            if arg4 != 0 {
                let r = sys_getrlimit(arg2, arg4);
                if r < 0 { return r; }
            }
            // SET new limit if provided
            if arg3 != 0 && (arg2 as usize) < 16 && validate_user_ptr(arg3, 16) {
                let soft = unsafe { core::ptr::read_unaligned(arg3 as *const u64) };
                let pid  = crate::proc::current_pid();
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    p.rlimits_soft[arg2 as usize] = soft;
                }
            }
            0
        }
        // 318: getrandom(buf, buflen, flags)
        318 => sys_getrandom(arg1 as *mut u8, arg2 as usize),
        // 334: rseq(rseq, rseq_len, flags, sig)
        334 => -38, // ENOSYS

        // ─── Phase 6 additions ────────────────────────────────────────────

        // 137: statfs(path, buf) — filesystem statistics
        137 => sys_statfs_linux(arg1, arg2 as *mut u8),
        // 138: fstatfs(fd, buf) — filesystem statistics (fd-based)
        138 => sys_fstatfs_linux(arg1 as usize, arg2 as *mut u8),
        // 266: symlinkat(oldpath, newdirfd, newpath)
        266 => {
            let old_raw = read_cstring_from_user(arg1);
            let new_raw = read_cstring_from_user(arg3);
            let old_str = core::str::from_utf8(old_raw).unwrap_or("");
            let new_str = core::str::from_utf8(new_raw).unwrap_or("");
            match crate::vfs::symlink(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => -(e as usize as i64),
            }
        }
        // 269: faccessat(dirfd, pathname, mode, flags) — access + dirfd
        269 => sys_faccessat_linux(arg1, arg2, arg3),
        // 280: utimensat(dirfd, pathname, times, flags) — stub success
        280 => 0,
        // 284: eventfd(initval, flags) / 290: eventfd2(initval, flags)
        284 | 290 => sys_eventfd_linux(arg1 as u64),
        // 293: pipe2(pipefd, flags) — like pipe but with O_CLOEXEC/O_NONBLOCK
        293 => sys_pipe2_linux(arg1 as *mut u32, arg2 as u32),
        // 435: clone3(clone_args *args, size_t size)
        // clone_args layout (offsets in bytes):
        //   0:  flags(u64), 8: pidfd(u64), 16: child_tid(u64), 24: parent_tid(u64),
        //   32: exit_signal(u64), 40: stack(u64), 48: stack_size(u64), 56: tls(u64)
        //
        // glibc 2.34+ __clone3_wrapper passes thread fn in rdx (arg3) and thread arg
        // in r8 (arg5) through the syscall; the child does:  mov rdi, r8; call *rdx.
        // We must preserve these into the new thread's registers via user_entry_rdx/r8.
        435 => {
            if arg2 < 56 || arg1 == 0 { return -22i64; } // EINVAL: struct too small
            let clone_flags   = unsafe { *(arg1 as *const u64) };
            let stack_ptr     = unsafe { *((arg1 + 40) as *const u64) };
            let stack_size    = unsafe { *((arg1 + 48) as *const u64) };
            let tls           = unsafe { *((arg1 + 56) as *const u64) };
            let child_tidptr  = unsafe { *((arg1 + 16) as *const u64) };
            let parent_tidptr = unsafe { *((arg1 + 24) as *const u64) };
            let sp = if stack_ptr != 0 { stack_ptr + stack_size } else { 0 };
            const CLONE_THREAD: u64 = 0x00010000;
            const CLONE_VM:     u64 = 0x00000100;
            const CLONE_SETTLS: u64 = 0x00080000;
            if clone_flags & CLONE_THREAD != 0 && clone_flags & CLONE_VM != 0 {
                // pthread_create via clone3: glibc passes func in rdx (arg3), arg in r8 (arg5).
                let func       = arg3; // Linux rdx = thread function
                let thread_arg = arg5; // Linux r8  = thread argument (glibc's saved rcx)
                let user_rip   = unsafe { get_user_rip() };
                let tls_val    = if clone_flags & CLONE_SETTLS != 0 { tls } else { 0 };
                let pid        = crate::proc::current_pid();
                crate::serial_println!(
                    "[CLONE3] CLONE_THREAD pid={} rip={:#x} sp={:#x} tls={:#x} func={:#x} arg={:#x}",
                    pid, user_rip, sp, tls_val, func, thread_arg
                );
                match crate::proc::usermode::create_user_thread(pid, user_rip, sp, tls_val, func, thread_arg) {
                    Some(tid) => {
                        crate::serial_println!("[CLONE3] Thread TID {} spawned in PID {}", tid, pid);

                        // CLONE_CHILD_SETTID: write the child TID into the child's TLS/TCB.
                        // glibc's pthread_create sets this so that the TCB's `tid` field is
                        // populated — required for pthread_rwlock, pthread_mutex, etc. which
                        // read THREAD_GETMEM(THREAD_SELF, tid).  Without this, the tid field
                        // is 0 and glibc's rwlock returns EDEADLK (0 == __cur_writer's 0).
                        const CLONE_CHILD_SETTID: u64 = 0x01000000;
                        if clone_flags & CLONE_CHILD_SETTID != 0 && child_tidptr != 0 {
                            unsafe { write_u32_to_user_current(child_tidptr, tid as u32); }
                        }

                        // CLONE_PARENT_SETTID: write child TID into parent's address space.
                        const CLONE_PARENT_SETTID: u64 = 0x00100000;
                        if clone_flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
                            unsafe { write_u32_to_user_current(parent_tidptr, tid as u32); }
                        }

                        // CLONE_CHILD_CLEARTID: store address for futex wake on thread exit.
                        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
                        if clone_flags & CLONE_CHILD_CLEARTID != 0 && child_tidptr != 0 {
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid as u64) {
                                t.clear_child_tid = child_tidptr;
                            }
                        }

                        tid as i64
                    }
                    None => -11, // EAGAIN
                }
            } else {
                dispatch_linux(56, clone_flags, sp, parent_tidptr, child_tidptr, tls, 0)
            }
        }

        // ─── Phase 7: Firefox dependency syscalls ─────────────────────────

        // 28: madvise(addr, len, advice)
        28 => sys_madvise(arg1, arg2, arg3),
        // 73: flock(fd, operation) — advisory file locking; stub success
        73 => 0,
        // 98: getrusage(who, usage) — resource usage; return zeroed struct
        98 => {
            if arg2 != 0 {
                unsafe { core::ptr::write_bytes(arg2 as *mut u8, 0, 144); }
            }
            0
        }
        // 99: sysinfo(info) — system statistics
        99 => {
            if arg1 != 0 {
                // struct sysinfo: 11 fields, 64 bytes total
                unsafe { core::ptr::write_bytes(arg1 as *mut u8, 0, 64); }
                // uptime (seconds) at offset 0
                let ticks = crate::arch::x86_64::irq::get_ticks();
                let uptime = (ticks / 100) as i64; // 100 Hz
                unsafe { *(arg1 as *mut i64) = uptime; }
                // totalram / freeram at offsets 8 / 16 (u64 each)
                unsafe {
                    let p = arg1 as *mut u64;
                    *p.add(1) = 256 * 1024 * 1024; // 256 MiB totalram
                    *p.add(2) = 128 * 1024 * 1024; // 128 MiB freeram
                    *p.add(9) = 1; // mem_unit = 1 byte
                }
            }
            0
        }
        // 229: clock_getres(clk_id, res) — returns 1 ns resolution for all clocks
        229 => {
            if arg2 != 0 {
                unsafe {
                    let ts = arg2 as *mut u64;
                    *ts       = 0; // tv_sec = 0
                    *ts.add(1) = 1; // tv_nsec = 1 (nanosecond resolution)
                }
            }
            0
        }
        // 267: readlinkat(dirfd, pathname, buf, bufsiz)
        267 => {
            const AT_FDCWD: i64 = -100;
            let raw = read_cstring_from_user(arg2);
            let path_str = core::str::from_utf8(raw).unwrap_or("");
            // If AT_FDCWD or absolute path, delegate to readlink logic
            let full_path: alloc::string::String = if arg1 as i64 == AT_FDCWD || path_str.starts_with('/') {
                alloc::string::String::from(path_str)
            } else {
                // Relative path — prepend fd's directory
                let pid = crate::proc::current_pid();
                let base = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    let proc = match procs.iter().find(|p| p.pid == pid) {
                        Some(p) => p,
                        None => return -3,
                    };
                    let idx = arg1 as usize;
                    if idx >= proc.file_descriptors.len() { return -9; }
                    match &proc.file_descriptors[idx] {
                        Some(f) => f.open_path.clone(),
                        None => return -9,
                    }
                };
                let mut s = alloc::string::String::from(base.trim_end_matches('/'));
                s.push('/');
                s.push_str(path_str);
                s
            };
            let buf = arg3 as *mut u8;
            let bufsiz = arg4 as usize;
            // /proc/self/exe special case
            let target: alloc::string::String = if full_path == "/proc/self/exe" {
                let pid = crate::proc::current_pid();
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.exe_path.as_ref())
                    .map(|s| s.clone())
                    .unwrap_or_else(|| alloc::string::String::from("/bin/init"))
            } else {
                match crate::vfs::readlink(&full_path) {
                    Ok(t) => t,
                    Err(_) => return -22,
                }
            };
            let bytes = target.as_bytes();
            let len = bytes.len().min(bufsiz);
            if len > 0 { unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len); } }
            len as i64
        }
        // 271: ppoll(fds, nfds, tmo_p, sigmask, sigsetsize) — poll with timeout+mask
        271 => {
            // Delegate to poll (syscall 7), ignoring sigmask
            let timeout_ms: i64 = if arg3 == 0 {
                0 // null timeout → return immediately
            } else {
                -1 // wait indefinitely (we don't support real timeouts here)
            };
            dispatch_linux(7, arg1, arg2, timeout_ms as u64, 0, 0, 0)
        }
        // 283: timerfd_create(clockid, flags)
        283 => sys_timerfd_create(arg1 as u32),
        // 286: timerfd_settime(fd, flags, new_value, old_value)
        286 => sys_timerfd_settime(arg1, arg2 as u32, arg3, arg4),
        // 287: timerfd_gettime(fd, curr_value)
        287 => sys_timerfd_gettime(arg1, arg2),
        // 288: accept4(sockfd, addr, addrlen, flags) — delegate to accept(43)
        288 => dispatch_linux(43, arg1, arg2, arg3, 0, 0, 0),
        // 289: signalfd4(fd, mask, sizemask, flags)
        289 => sys_signalfd4(arg1, arg2, arg3, arg4 as u32),
        // 253: inotify_add_watch(fd, pathname, mask)
        253 => sys_inotify_add_watch(arg1, arg2, arg3 as u32),
        // 254: inotify_rm_watch(fd, wd)
        254 => sys_inotify_rm_watch(arg1, arg2 as i32),
        // 294: inotify_init1(flags)
        294 => sys_inotify_init1(arg1 as u32),
        // 319: memfd_create(name, flags) — create an anonymous in-memory file
        319 => sys_memfd_create(arg1, arg2),
        // 23: select(nfds, readfds, writefds, exceptfds, timeout)
        23 => sys_select_linux(arg1, arg2, arg3, arg4, arg5),
        // 25: mremap(old_addr, old_size, new_size, flags, [new_addr])
        25 => sys_mremap(arg1, arg2, arg3, arg4, arg5),
        // 63: uname(buf)
        63 => sys_uname(arg1 as *mut u8),
        // 76: truncate(path, length)
        76 => {
            let path_bytes = read_cstring_from_user(arg1);
            let path_str = core::str::from_utf8(path_bytes).unwrap_or("");
            match crate::vfs::truncate_path(path_str, arg2) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 90: chmod(pathname, mode)
        90 => {
            let path_bytes = read_cstring_from_user(arg1);
            let path_str = core::str::from_utf8(path_bytes).unwrap_or("");
            match crate::vfs::chmod(path_str, arg2 as u32) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 91: fchmod(fd, mode) — stub (mode not stored per-inode yet)
        91 => 0,
        // 92: chown(path, uid, gid) — stub (no uid/gid yet)
        92 => 0,
        // 93: fchown(fd, uid, gid) — stub
        93 => 0,
        // 94: lchown(path, uid, gid) — stub (no symlink uid/gid yet)
        94 => 0,
        // 97: getrlimit(resource, rlim)
        97 => sys_getrlimit(arg1, arg2),
        // 109: setpgid(pid, pgid) — real: update pgid in PCB
        109 => {
            let target = if arg1 == 0 { crate::proc::current_pid() } else { arg1 };
            let new_pgid = if arg2 == 0 { target as u32 } else { arg2 as u32 };
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter_mut().find(|p| p.pid == target) {
                Some(p) => { p.pgid = new_pgid; 0 }
                None    => -3, // ESRCH
            }
        }
        // 111: getpgrp() — return caller's pgid
        111 => {
            let pid = crate::proc::current_pid();
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid).map(|p| p.pgid as i64).unwrap_or(pid as i64)
        }
        // 112: setsid() — become session leader with new sid/pgid
        112 => {
            let pid = crate::proc::current_pid();
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.pgid = pid as u32;
                p.sid  = pid as u32;
            }
            pid as i64
        }
        // 121: getpgid(pid) — return pgid of target (0 = caller)
        121 => {
            let target = if arg1 == 0 { crate::proc::current_pid() } else { arg1 };
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == target).map(|p| p.pgid as i64).unwrap_or(-3)
        }
        // 122: getsid(pid) — return session id
        122 => {
            let target = if arg1 == 0 { crate::proc::current_pid() } else { arg1 };
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == target).map(|p| p.sid as i64).unwrap_or(-3)
        }
        // 230: clock_nanosleep(clockid, flags, req, rem)
        230 => sys_nanosleep_linux(arg3, arg4),
        // 292: dup3(oldfd, newfd, flags) — like dup2 + optional O_CLOEXEC
        292 => {
            let ret = sys_dup2(arg1 as usize, arg2 as usize);
            if ret >= 0 && (arg3 & 0x0008_0000) != 0 {
                // O_CLOEXEC: set cloexec on the new fd
                let pid = crate::proc::current_pid();
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(f)) = proc.file_descriptors.get_mut(arg2 as usize) {
                        f.cloexec = true;
                    }
                }
            }
            ret
        }
        // 332: statx(dirfd, pathname, flags, mask, statxbuf) — extended stat
        332 => {
            // Simplified: delegate to stat, then fill statx fields
            let path_bytes = read_cstring_from_user(arg2);
            let path       = match core::str::from_utf8(path_bytes) { Ok(s) => s, Err(_) => return -22 };
            if arg5 == 0 { return -14; } // EFAULT
            match crate::vfs::stat(path) {
                Ok(st) => {
                    // struct statx is 256 bytes; zero the whole thing first
                    unsafe { core::ptr::write_bytes(arg5 as *mut u8, 0, 256); }
                    let p = arg5 as *mut u32;
                    unsafe {
                        *p       = 0x7ff; // stx_mask  — all fields valid
                        *p.add(1) = 4096; // stx_blksize
                        // stx_nlink at offset 8: u32
                        *(arg5 as *mut u32).add(2) = 1;
                        // stx_size at offset 48: u64
                        *(arg5 as *mut u64).add(6) = st.size;
                        // stx_mode at offset 20: u16 (type + perm bits)
                        let mode: u16 = match st.file_type {
                            crate::vfs::FileType::Directory   => 0o040_755,
                            crate::vfs::FileType::SymLink     => 0o120_777,
                            _                                 => 0o100_644,
                        };
                        *(arg5 as *mut u16).add(10) = mode;
                        // stx_ino at offset 32: u64
                        *(arg5 as *mut u64).add(4) = st.inode;
                    }
                    0
                }
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }

        // ─── Phase 1 batch 2: small stubs / wrappers for bash + coreutils ─────

        // 22: pipe(pipefd[2]) — same as pipe2 with no flags
        22 => sys_pipe(arg1 as *mut u64),
        // 26: msync(addr, length, flags) — memory hint; always succeeds
        26 => 0,
        // 27: mincore(addr, length, vec) — report all pages as resident
        27 => {
            let pages = ((arg2 + 0xFFF) / 0x1000) as usize;
            if arg3 != 0 && validate_user_ptr(arg3, pages) {
                unsafe { core::ptr::write_bytes(arg3 as *mut u8, 1, pages); }
            }
            0
        }
        // 95: umask(mask) — set file creation mask
        95 => sys_umask(arg1 as u32),
        // 100: times(buf) — CPU usage times; return zero struct
        100 => {
            if arg1 != 0 && validate_user_ptr(arg1, 32) {
                unsafe { core::ptr::write_bytes(arg1 as *mut u8, 0, 32); }
            }
            0
        }
        // 105: setuid(uid) — stub (always root in AstryxOS)
        105 => 0,
        // 106: setgid(gid) — stub
        106 => 0,
        // 114: setreuid(ruid, euid) — stub
        114 => 0,
        // 115: getgroups(size, list) — no supplemental groups
        115 => 0,
        // 116: setgroups(size, list) — stub success
        116 => 0,
        // 117: setresuid(ruid, euid, suid) — stub
        117 => 0,
        // 118: getresuid(ruid, euid, suid) — all zero (root)
        118 => {
            for ptr in [arg1, arg2, arg3] {
                if ptr != 0 && validate_user_ptr(ptr, 4) {
                    unsafe { core::ptr::write(ptr as *mut u32, 0u32); }
                }
            }
            0
        }
        // 119: setresgid(rgid, egid, sgid) — stub
        119 => 0,
        // 120: getresgid(rgid, egid, sgid) — all zero
        120 => {
            for ptr in [arg1, arg2, arg3] {
                if ptr != 0 && validate_user_ptr(ptr, 4) {
                    unsafe { core::ptr::write(ptr as *mut u32, 0u32); }
                }
            }
            0
        }
        // 127: rt_sigpending(set, sigsetsize) — stub: no pending signals
        127 => {
            if arg1 != 0 && validate_user_ptr(arg1, arg2 as usize) {
                unsafe { core::ptr::write_bytes(arg1 as *mut u8, 0, arg2 as usize); }
            }
            0
        }
        // 128: rt_sigtimedwait(set, info, timeout, sigsetsize) — stub EINTR
        128 => -4, // EINTR
        // 130: rt_sigsuspend(mask, sigsetsize) — yield + EINTR
        130 => {
            crate::sched::yield_cpu();
            -4 // EINTR
        }
        // 161: chroot(path) — stub success
        161 => 0,
        // 162: sync() — flush filesystem
        162 => { crate::vfs::sync_all(); 0 }
        // 163: acct(filename) — stub  
        163 => -38, // ENOSYS
        // 164: settimeofday — stub
        164 => 0,
        // 168: poll(fds, nfds, timeout) — same as syscall 7
        168 => dispatch_linux(7, arg1, arg2, arg3, 0, 0, 0),
        // 185: rt_sigaction alias (some binaries use 185 on x86-64) — stub
        185 => sys_rt_sigaction_linux(arg1, arg2, arg3, arg4),
        // 198: lgetxattr — ENODATA (no extended attributes)
        196 | 197 | 198 | 199 | 200 | 201 => -61, // ENODATA
        // 270: pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)
        270 => sys_select_linux(arg1, arg2, arg3, arg4, arg5),
        // 285: fallocate(fd, mode, offset, len) — stub success
        285 => 0,
        // 295: openat2(dirfd, path, how, size) — forward to openat (ignore resolve flags)
        295 => {
            // openat2 struct how: { flags: u64, mode: u64, resolve: u64 }
            // arg1=dirfd, arg2=path, arg3=*how, arg4=sizeof(how)
            let how_flags = if arg3 != 0 { unsafe { *(arg3 as *const u64) } } else { 0 };
            let how_mode  = if arg3 != 0 { unsafe { *((arg3 + 8) as *const u64) } } else { 0o644 };
            dispatch_linux(257, arg1, arg2, how_flags, how_mode, 0, 0) // openat
        }
        // 316: renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        316 => {
            let old_raw = read_cstring_from_user(arg2);
            let new_raw = read_cstring_from_user(arg4);
            let old_str = core::str::from_utf8(old_raw).unwrap_or("");
            let new_str = core::str::from_utf8(new_raw).unwrap_or("");
            match crate::vfs::rename(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 355: close_range(first, last, flags) — close a range of fds
        355 => {
            let pid = crate::proc::current_pid();
            let first = arg1 as usize;
            let last = (arg2 as usize).min(4095);
            for fd in first..=last {
                let _ = crate::vfs::close(pid, fd);
            }
            0
        }
        // 149: mlock(addr, len)   — no-op (no swapping in AstryxOS)
        149 => 0,
        // 150: munlock(addr, len) — no-op
        150 => 0,
        // 151: mlockall(flags)    — no-op
        151 => 0,
        // 152: munlockall()       — no-op
        152 => 0,
        // 322: execveat(dirfd, path, argv, envp, flags)
        322 => {
            // If path is empty and AT_EMPTY_PATH (0x1000) set, exec fd directly — unsupported
            let path_bytes = read_cstring_from_user(arg2);
            let path_str   = core::str::from_utf8(path_bytes).unwrap_or("");
            if path_str.is_empty() {
                return -38; // ENOSYS — fd-based execveat not supported
            }
            // Otherwise delegate to execve (59) ignoring dirfd (absolute path required)
            dispatch_linux(59, arg2, arg3, arg4, 0, 0, 0)
        }
        // 326: copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
        // Delegate to sendfile (40); arg1=fd_in, arg3=fd_out, arg2=off_in, arg5=len
        326 => sys_sendfile(arg3 as usize, arg1 as usize, arg2, arg5 as usize),
        // 424: pidfd_send_signal — ENOSYS
        424 => -38,
        // 443-445: landlock_* — ENOSYS
        443 | 444 | 445 => -38,

        // Explicit ENOSYS for syscalls that would silently fail otherwise
        // (give the process a chance to fall back rather than misinterpreting 0)
        210 | 211 | 214 | 215 | 216 | 237 | 255 => -38, // ENOSYS

        _ => {
            crate::serial_println!("[SYSCALL/Linux] Unknown Linux syscall: {}", num);
            -38 // ENOSYS
        }
    }
}

// ── Linux-ABI syscall wrappers ──────────────────────────────────────────────

/// nanosleep(req, rem) — struct timespec { tv_sec: i64, tv_nsec: i64 }.
/// Also used by clock_nanosleep() (syscall 230) for the `req` field.
/// Timer resolution: 100 Hz → 1 tick = 10 ms.
fn sys_nanosleep_linux(req_ptr: u64, _rem_ptr: u64) -> i64 {
    if req_ptr == 0 {
        // NULL req pointer — invalid, but yield the CPU first so callers that
        // use nanosleep(NULL,NULL) as a cooperative yield hint don't busy-spin.
        crate::sched::yield_cpu();
        return -22; // EINVAL
    }
    if !validate_user_ptr(req_ptr, 16) { return -14; } // EFAULT
    let (tv_sec, tv_nsec) = unsafe {
        let p = req_ptr as *const i64;
        (core::ptr::read_unaligned(p), core::ptr::read_unaligned(p.add(1)))
    };
    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
        return -22; // EINVAL
    }
    // Convert timespec → timer ticks (100 Hz, 10 ms/tick), rounded up.
    let ms = (tv_sec as u64) * 1000 + (tv_nsec as u64) / 1_000_000;
    let ticks = (ms + 9) / 10;
    if ticks > 0 {
        crate::proc::sleep_ticks(ticks);
    } else {
        // Zero-duration sleep — still yield so other threads can run.
        crate::sched::yield_cpu();
    }
    0
}

/// getrlimit(resource, rlim) — fill `struct rlimit { rlim_cur, rlim_max }` (2×u64).
/// Also called by prlimit64() for GET operations.
fn sys_getrlimit(resource: u64, rlim_ptr: u64) -> i64 {
    if !validate_user_ptr(rlim_ptr, 16) { return -14; } // EFAULT
    const RLIM_INFINITY: u64 = u64::MAX;
    // Hard limits (max) are fixed; soft limits come from per-process rlimits_soft.
    let hard: u64 = match resource {
        3  => RLIM_INFINITY,        // RLIMIT_STACK hard = unlimited
        7  => 65536,                // RLIMIT_NOFILE hard
        _  => RLIM_INFINITY,
    };
    // Read per-process soft limit.
    let soft = if resource < 16 {
        let pid = crate::proc::current_pid();
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)
            .map(|p| p.rlimits_soft[resource as usize])
            .unwrap_or(RLIM_INFINITY)
    } else {
        RLIM_INFINITY
    };
    unsafe {
        let p = rlim_ptr as *mut u64;
        core::ptr::write_unaligned(p,        soft);
        core::ptr::write_unaligned(p.add(1), hard);
    }
    0
}

/// select(nfds, readfds, writefds, exceptfds, timeout_tv)
///
/// fd_set is a bitmask: bit `n` set means fd `n` is of interest.
/// On return, unready bits are cleared.  Returns total ready fd count.
/// Non-blocking for regular files (always ready); single yield for sockets/pipes.
fn sys_select_linux(
    nfds: u64, readfds: u64, writefds: u64, _exceptfds: u64, timeout: u64,
) -> i64 {
    let pid = crate::proc::current_pid();
    let nfds = nfds.min(1024) as usize;
    let mut ready = 0i64;

    for fd in 0..nfds {
        let byte_off = (fd / 8) as u64;
        let bit      = 1u8 << (fd % 8);

        let r_req = readfds  != 0
            && validate_user_ptr(readfds  + byte_off, 1)
            && unsafe { *((readfds  + byte_off) as *const u8) & bit != 0 };
        let w_req = writefds != 0
            && validate_user_ptr(writefds + byte_off, 1)
            && unsafe { *((writefds + byte_off) as *const u8) & bit != 0 };

        if !r_req && !w_req { continue; }

        // Determine readiness (mirrors poll logic)
        let can_read = if fd <= 1 {
            fd == 0 // stdin always readable; stdout/stderr not
        } else if is_eventfd_fd(pid, fd) {
            crate::ipc::eventfd::is_readable(get_eventfd_id(pid, fd))
        } else if is_pipe_fd(pid, fd) {
            crate::ipc::pipe::pipe_has_data(get_pipe_id(pid, fd))
        } else if is_unix_socket_fd(pid, fd) {
            let uid = get_unix_socket_id(pid, fd);
            crate::net::unix::has_data(uid) || crate::net::unix::has_pending(uid)
        } else if is_socket_fd(pid, fd) {
            crate::net::socket::socket_has_data(get_socket_id(pid, fd))
        } else if is_timerfd_fd(pid, fd) {
            crate::ipc::timerfd::is_readable(get_timerfd_id(pid, fd))
        } else if is_signalfd_fd(pid, fd) {
            crate::ipc::signalfd::is_readable(get_signalfd_id(pid, fd))
        } else if is_inotify_fd(pid, fd) {
            false
        } else {
            true // regular file: always ready
        };
        let can_write = fd != 0; // stdin (fd=0) not writable; stdout/stderr/others are

        if r_req {
            if can_read { ready += 1; }
            else {
                // Clear unready bit
                unsafe { *((readfds + byte_off) as *mut u8) &= !bit; }
            }
        }
        if w_req {
            if can_write { ready += 1; }
            else {
                unsafe { *((writefds + byte_off) as *mut u8) &= !bit; }
            }
        }
    }

    let do_rescan = |ready: &mut i64| {
        *ready = 0;
        for fd in 0..nfds {
            let byte_off = (fd / 8) as u64;
            let bit      = 1u8 << (fd % 8);
            let r_req = readfds != 0
                && validate_user_ptr(readfds + byte_off, 1)
                && unsafe { *((readfds + byte_off) as *const u8) & bit != 0 };
            let w_req = writefds != 0
                && validate_user_ptr(writefds + byte_off, 1)
                && unsafe { *((writefds + byte_off) as *const u8) & bit != 0 };
            if !r_req && !w_req { continue; }
            let revents = poll_revents(pid, fd, if r_req { 0x0001 } else { 0x0004 });
            if r_req && revents & 0x0001 != 0 { *ready += 1; }
            else if r_req { unsafe { *((readfds + byte_off) as *mut u8) &= !bit; } }
            if w_req && revents & 0x0004 != 0 { *ready += 1; }
            else if w_req { unsafe { *((writefds + byte_off) as *mut u8) &= !bit; } }
        }
    };

    if ready == 0 {
        // SMP fix: pump x11 once, then retry up to 64 times yielding each iteration
        // to give CPU 0's desktop loop time to finish writing replies.
        let non_zero_timeout = timeout != 0;
        crate::x11::poll();
        for _ in 0..64 {
            crate::sched::yield_cpu();
            do_rescan(&mut ready);
            if ready > 0 || !non_zero_timeout { break; }
        }
    }
    ready
}

/// madvise(addr, len, advice) — memory usage hint.
///
/// MADV_DONTNEED (4) and MADV_FREE (8): free physical pages in range so the
/// next access re-allocates a zero-filled page. All other values are no-ops.
fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    const MADV_DONTNEED: u64 = 4;
    const MADV_FREE:     u64 = 8;
    if advice != MADV_DONTNEED && advice != MADV_FREE { return 0; }
    if len == 0 { return 0; }

    let pid = crate::proc::current_pid();
    let start = addr & !0xFFF;
    let end   = (addr + len + 0xFFF) & !0xFFF;

    let cr3_opt = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)
            .and_then(|p| p.vm_space.as_ref())
            .map(|vs| vs.cr3)
    };
    let cr3 = match cr3_opt { Some(c) => c, None => return 0 };

    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let mut page = start;
    while page < end {
        let pte = crate::mm::vmm::read_pte(cr3, page);
        if pte & 1 != 0 {
            // Present — free the physical page.
            let phys = pte & 0x000F_FFFF_FFFF_F000;
            // Zero-out and unmap; next access demand-pages a fresh zeroed page.
            unsafe {
                core::ptr::write_bytes((PHYS_OFF + phys) as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
            }
            crate::mm::vmm::write_pte(cr3, page, 0);
            crate::mm::vmm::invlpg(page);
            let rc = crate::mm::refcount::page_ref_count(phys);
            if rc <= 1 {
                crate::mm::refcount::page_ref_set(phys, 0);
                crate::mm::pmm::free_page(phys);
            } else {
                crate::mm::refcount::page_ref_dec(phys);
            }
        }
        page += crate::mm::pmm::PAGE_SIZE as u64;
    }
    0
}

/// mremap(old_addr, old_size, new_size, flags, [new_addr])
///
/// Flags: MREMAP_MAYMOVE (1) — allowed to move mapping; MREMAP_FIXED (2) — use new_addr.
/// Returns the new mapping address on success, -errno on failure.
fn sys_mremap(old_addr: u64, old_size: u64, new_size: u64, flags: u64, new_addr: u64) -> i64 {
    use crate::mm::vma::{MAP_ANONYMOUS, MAP_FIXED};
    if new_size == 0 { return -22; } // EINVAL
    const MREMAP_MAYMOVE: u64 = 1;
    const MREMAP_FIXED:   u64 = 2;

    // Shrink: munmap the tail and return the same address.
    if new_size <= old_size {
        if new_size < old_size {
            let _ = sys_munmap(old_addr + new_size, old_size - new_size);
        }
        return old_addr as i64;
    }

    // Grow — first try in-place extension.
    let ext_size = new_size - old_size;
    let ext_addr = old_addr + old_size;

    if flags & MREMAP_FIXED == 0 {
        // Attempt in-place: MAP_FIXED at the adjacent address.
        let r = sys_mmap(ext_addr, ext_size, 0x3 /*PROT_READ|PROT_WRITE*/,
            MAP_ANONYMOUS | MAP_FIXED, u64::MAX, 0);
        if r == ext_addr as i64 {
            return old_addr as i64; // grown in place
        }
        // In-place failed; move if allowed.
        if flags & MREMAP_MAYMOVE != 0 {
            let dest = sys_mmap(0, new_size, 0x3, MAP_ANONYMOUS, u64::MAX, 0);
            if dest < 0 { return -12; } // ENOMEM
            unsafe {
                core::ptr::copy_nonoverlapping(
                    old_addr as *const u8, dest as *mut u8, old_size as usize);
            }
            let _ = sys_munmap(old_addr, old_size);
            return dest;
        }
        -12 // ENOMEM — cannot grow in-place, move not allowed
    } else {
        // MREMAP_FIXED: must place at new_addr exactly.
        let dest = sys_mmap(new_addr, new_size, 0x3,
            MAP_ANONYMOUS | MAP_FIXED, u64::MAX, 0);
        if dest < 0 { return dest; }
        unsafe {
            core::ptr::copy_nonoverlapping(
                old_addr as *const u8, dest as *mut u8, old_size.min(new_size) as usize);
        }
        let _ = sys_munmap(old_addr, old_size);
        dest
    }
}

/// Linux read(fd, buf, count) — same semantics as AstryxOS read.
fn sys_read_linux(fd: u64, buf: u64, count: u64) -> i64 {
    let buf_ptr = buf as *mut u8;
    let count = count as usize;
    let pid = crate::proc::current_pid();

    // ── Special fd types take priority over the fd-number shortcuts ─────────
    // Must check these BEFORE the `fd == 0` stdin branch because kernel tests
    // and user processes may allocate eventfd/pipe/socket at fd 0.
    if is_pipe_fd(pid, fd as usize) {
        let pipe_id = get_pipe_id(pid, fd as usize);
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };
        return match crate::ipc::pipe::pipe_read(pipe_id, buf) {
            Some(n) => n as i64,
            None => -9,
        };
    } else if is_unix_socket_fd(pid, fd as usize) {
        let unix_id = get_unix_socket_id(pid, fd as usize);
        let avail = crate::net::unix::bytes_available(unix_id);
        let buf_sl = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };
        let ret = crate::net::unix::read(unix_id, buf_sl);
        #[cfg(feature = "firefox-test")]
        if pid >= 1 {
            crate::serial_println!("[XSOCK] read fd={} uid={} want={} avail={} got={}",
                fd, unix_id, count, avail, ret);
        }
        return ret;
    } else if is_socket_fd(pid, fd as usize) {
        let socket_id = get_socket_id(pid, fd as usize);
        return match crate::net::socket::socket_recv(socket_id) {
            Ok(data) => {
                let n = data.len().min(count);
                unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, n); }
                n as i64
            }
            Err(_) => -11, // EAGAIN
        };
    } else if is_eventfd_fd(pid, fd as usize) {
        if count < 8 { return -22; } // EINVAL
        let efd_id = get_eventfd_id(pid, fd as usize);
        return match crate::ipc::eventfd::read(efd_id) {
            Ok(val) => {
                let bytes = val.to_le_bytes();
                unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, 8); }
                8
            }
            Err(e) => e,
        };
    } else if is_timerfd_fd(pid, fd as usize) {
        if count < 8 { return -22; } // EINVAL
        let tfd_id = get_timerfd_id(pid, fd as usize);
        return match crate::ipc::timerfd::read(tfd_id) {
            Ok(val) => {
                let bytes = val.to_le_bytes();
                unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, 8); }
                8
            }
            Err(e) => e,
        };
    } else if is_signalfd_fd(pid, fd as usize) {
        let sfd_id = get_signalfd_id(pid, fd as usize);
        return match crate::ipc::signalfd::read(sfd_id, buf_ptr, count) {
            Ok(n) => n as i64,
            Err(e) => e,
        };
    } else if is_inotify_fd(pid, fd as usize) {
        return -11; // EAGAIN — no events
    }

    // ── VFS file descriptors (covers ALL fds including 0/1/2) ──────────────
    // Try VFS first; if fd 0 has no VFS file open (BadFd), fall through to TTY.
    match crate::vfs::fd_read(pid, fd as usize, buf_ptr, count) {
        Ok(n) => return n as i64,
        Err(crate::vfs::VfsError::BadFd) if fd == 0 => { /* fall through to TTY stdin */ }
        Err(_) if fd == 0 => { /* fall through to TTY stdin */ }
        Err(_) => return -9, // EBADF for non-stdin fds
    }

    // fd 0 with no VFS file → stdin via TTY line discipline.
    // Limit spin-wait to 500 iterations (~5ms at 100Hz timer) so that a
    // user process calling read(0, …) in a loop does not stall the entire
    // system for seconds waiting for keyboard input that will never arrive
    // (especially in headless test mode).
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };
    let mut attempts = 0u32;
    loop {
        {
            let mut tty = crate::drivers::tty::TTY0.lock();
            crate::drivers::tty::pump_keyboard(&mut tty);
            let n = tty.read(buf, count);
            if n > 0 {
                return n as i64;
            }
        }
        attempts += 1;
        if attempts > 500 {
            return 0;
        }
        core::hint::spin_loop();
    }
}

/// Linux write(fd, buf, count) — same semantics as AstryxOS write.
fn sys_write_linux(fd: u64, buf: u64, count: u64) -> i64 {
    let buf_ptr = buf as *const u8;
    let count = count as usize;

    if count == 0 { return 0; }

    #[cfg(feature = "firefox-test")]
    if fd == 2 {
        let pid = crate::proc::current_pid();
        if pid >= 1 {
            let slice = unsafe { core::slice::from_raw_parts(buf_ptr, count.min(512)) };
            let s = core::str::from_utf8(slice).unwrap_or("<binary>");
            crate::serial_println!("[FF/stderr] pid={} {:?}", pid, s);
        }
    }

    // ── Special fd types take priority over the fd-number shortcuts ─────────
    // Must check these BEFORE the `fd == 1/2` stdout/stderr branch because
    // kernel tests and user processes may allocate pipe/socket/eventfd at fd 1.
    let pid = crate::proc::current_pid();
    if is_pipe_fd(pid, fd as usize) {
        let pipe_id = get_pipe_id(pid, fd as usize);
        let slice = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
        return match crate::ipc::pipe::pipe_write(pipe_id, slice) {
            Some(n) => n as i64,
            None => -9,
        };
    } else if is_unix_socket_fd(pid, fd as usize) {
        let data = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
        let unix_id = get_unix_socket_id(pid, fd as usize);
        return crate::net::unix::write(unix_id, data);
    } else if is_socket_fd(pid, fd as usize) {
        let socket_id = get_socket_id(pid, fd as usize);
        let data = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
        return match crate::net::socket::socket_send(socket_id, data) {
            Ok(n) => n as i64,
            Err(_) => -104, // ECONNRESET
        };
    } else if is_eventfd_fd(pid, fd as usize) {
        if count < 8 { return -22; } // EINVAL
        let efd_id = get_eventfd_id(pid, fd as usize);
        let val = unsafe { core::ptr::read_unaligned(buf_ptr as *const u64) };
        return match crate::ipc::eventfd::write(efd_id, u64::from_le(val)) {
            Ok(()) => 8,
            Err(e) => e,
        };
    }

    // ── VFS file descriptors (covers ALL fds including 0/1/2) ──────────────
    // Try VFS first; if fd 1/2 has no VFS file open (BadFd), fall through to TTY.
    match crate::vfs::fd_write(pid, fd as usize, buf_ptr, count) {
        Ok(n) => return n as i64,
        Err(_) if fd == 1 || fd == 2 => { /* fall through to TTY stdout/stderr */ }
        Err(_) => return -9, // EBADF for other fds
    }

    // fd 1/2 with no VFS file → TTY stdout/stderr.
    let slice = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
    crate::drivers::tty::TTY0.lock().write(slice);
    count as i64
}

/// Linux open(pathname, flags, mode) — pathname is a C string.
fn sys_open_linux(pathname: u64, flags: u64, _mode: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };
    let pid = crate::proc::current_pid();
    #[cfg(feature = "firefox-test")]
    crate::serial_println!("[FF/open] pid={} path={}", pid, path);

    // Refresh /proc/self/maps with dynamic per-process VMA content before opening.
    if path == "/proc/self/maps" {
        refresh_proc_maps(pid);
    }
    // Refresh /proc/self/status with live PID, PPID, FDSize, VmRSS.
    if path == "/proc/self/status" {
        refresh_proc_status(pid);
    }

    // ── PTY: /dev/ptmx → allocate pair, return master fd ─────────────────
    if path == "/dev/ptmx" {
        return match crate::drivers::pty::alloc() {
            Some(pty_n) => {
                let fd = crate::vfs::FileDescriptor::pty_master(pty_n);
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    let slot = p.file_descriptors.iter().position(|s| s.is_none()).unwrap_or_else(|| {
                        p.file_descriptors.push(None);
                        p.file_descriptors.len() - 1
                    });
                    p.file_descriptors[slot] = Some(fd);
                    slot as i64
                } else {
                    -22
                }
            }
            None => -24, // EMFILE
        };
    }
    // ── PTY: /dev/pts/N → return slave fd ────────────────────────────────
    if path.starts_with("/dev/pts/") {
        if let Ok(n) = path["/dev/pts/".len()..].parse::<u8>() {
            let fd = crate::vfs::FileDescriptor::pty_slave(n);
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                let slot = p.file_descriptors.iter().position(|s| s.is_none()).unwrap_or_else(|| {
                    p.file_descriptors.push(None);
                    p.file_descriptors.len() - 1
                });
                p.file_descriptors[slot] = Some(fd);
                return slot as i64;
            }
        }
        return -2; // ENOENT
    }

    match crate::vfs::open(pid, path, flags as u32) {
        Ok(fd_num) => {
            // Special character devices: tag the fd with a device kind flag so
            // fd_read/fd_write can give them proper behaviour.
            //   bit 26 (0x0400_0000) = /dev/null
            //   bit 25 (0x0200_0000) = /dev/zero
            //   bit 24 (0x0100_0000) = /dev/urandom | /dev/random
            let dev_flag: u32 = match path {
                "/dev/null"                    => 0x0400_0000,
                "/dev/zero"                    => 0x0200_0000,
                "/dev/urandom" | "/dev/random" => 0x0100_0000,
                _ => 0,
            };
            if dev_flag != 0 {
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(f)) = p.file_descriptors.get_mut(fd_num) {
                        f.flags |= dev_flag;
                    }
                }
            }
            fd_num as i64
        }
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// Linux stat(pathname, statbuf) — pathname is a C string, Linux stat layout.
fn sys_stat_linux(pathname: u64, stat_buf: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };
    match crate::vfs::stat(path) {
        Ok(st) => {
            fill_linux_stat(stat_buf as *mut u8, &st);
            0
        }
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// Linux fstat(fd, statbuf) — uses Linux stat layout.
fn sys_fstat_linux(fd_num: usize, stat_buf: *mut u8) -> i64 {
    let pid = crate::proc::current_pid();
    let procs = crate::proc::PROCESS_TABLE.lock();
    let proc_entry = match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let fd = match proc_entry.file_descriptors.get(fd_num).and_then(|f| f.as_ref()) {
        Some(fd) => fd,
        None => return -9,
    };

    if fd.is_console {
        let st = crate::vfs::FileStat {
            inode: 0,
            file_type: crate::vfs::FileType::CharDevice,
            size: 0,
            permissions: 0o666,
            created: 0,
            modified: 0,
            accessed: 0,
        };
        fill_linux_stat(stat_buf, &st);
        return 0;
    }

    let mount_idx = fd.mount_idx;
    let inode = fd.inode;
    drop(procs);

    let mounts = crate::vfs::MOUNTS.lock();
    match mounts.get(mount_idx) {
        Some(m) => match m.fs.stat(inode) {
            Ok(st) => {
                fill_linux_stat(stat_buf, &st);
                0
            }
            Err(e) => crate::subsys::linux::errno::vfs_err(e),
        },
        None => -9,
    }
}

/// Linux chdir(pathname) — pathname is a C string.
fn sys_chdir_linux(pathname: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    sys_chdir(path_bytes.as_ptr(), path_bytes.len())
}

/// fchdir(fd) — change CWD to the directory referred to by `fd`.
fn sys_fchdir_linux(fd: u64) -> i64 {
    let pid = crate::proc::current_pid();
    let open_path = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3, // ESRCH
        };
        let fd_idx = fd as usize;
        if fd_idx >= proc.file_descriptors.len() { return -9; } // EBADF
        match &proc.file_descriptors[fd_idx] {
            Some(f) => f.open_path.clone(),
            None => return -9,
        }
    };
    if open_path.is_empty() { return -9; } // EBADF — path unknown
    sys_chdir(open_path.as_ptr(), open_path.len())
}

/// faccessat(dirfd, pathname, mode, flags) — access check relative to dirfd.
fn sys_faccessat_linux(dirfd: u64, pathname: u64, mode: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    // If AT_FDCWD or an absolute path, behave like access()
    if dirfd as i64 == AT_FDCWD {
        return sys_access(pathname, mode);
    }
    // Try to get the base directory from the fd and reconstruct full path
    let pid = crate::proc::current_pid();
    let base = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let idx = dirfd as usize;
        if idx >= proc.file_descriptors.len() { return -9; }
        match &proc.file_descriptors[idx] {
            Some(f) => f.open_path.clone(),
            None => return -9,
        }
    };
    let rel_bytes = read_cstring_from_user(pathname);
    let rel = match core::str::from_utf8(rel_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };
    // Build full path: base + "/" + rel (if rel is absolute, use as-is)
    let full = if rel.starts_with('/') {
        alloc::string::String::from(rel)
    } else {
        let mut s = alloc::string::String::from(base.trim_end_matches('/'));
        s.push('/');
        s.push_str(rel);
        s
    };
    match crate::vfs::stat(&full) {
        Ok(_) => 0,
        Err(_) => -2, // ENOENT
    }
}

/// Linux mkdir(pathname, mode) — pathname is a C string.
fn sys_mkdir_linux(pathname: u64, _mode: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    sys_mkdir(path_bytes.as_ptr(), path_bytes.len())
}

/// Linux rmdir(pathname) — pathname is a C string.
fn sys_rmdir_linux(pathname: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    sys_rmdir(path_bytes.as_ptr(), path_bytes.len())
}

/// Linux unlink(pathname) — pathname is a C string.
fn sys_unlink_linux(pathname: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    sys_unlink(path_bytes.as_ptr(), path_bytes.len())
}

/// Fill a Linux x86_64 `struct stat` buffer (144 bytes).
///
/// Layout:
///   dev:u64(0), ino:u64(8), nlink:u64(16), mode:u32(24), uid:u32(28),
///   gid:u32(32), pad:u32(36), rdev:u64(40), size:i64(48), blksize:i64(56),
///   blocks:i64(64), atime_sec:u64(72), atime_nsec:u64(80), mtime_sec:u64(88),
///   mtime_nsec:u64(96), ctime_sec:u64(104), ctime_nsec:u64(112), unused[3]:i64
const LINUX_STAT_SIZE: usize = 144;

fn fill_linux_stat(buf: *mut u8, st: &crate::vfs::FileStat) {
    let out = unsafe { core::slice::from_raw_parts_mut(buf, LINUX_STAT_SIZE) };
    for b in out.iter_mut() {
        *b = 0;
    }
    // dev (offset 0)
    out[0..8].copy_from_slice(&1u64.to_le_bytes());
    // ino (offset 8)
    out[8..16].copy_from_slice(&st.inode.to_le_bytes());
    // nlink (offset 16)
    out[16..24].copy_from_slice(&1u64.to_le_bytes());
    // mode (offset 24): Linux file type + permissions
    let mode: u32 = match st.file_type {
        crate::vfs::FileType::RegularFile => 0o100000 | st.permissions,
        crate::vfs::FileType::Directory   => 0o040000 | st.permissions,
        crate::vfs::FileType::SymLink     => 0o120000 | st.permissions,
        crate::vfs::FileType::CharDevice  => 0o020000 | st.permissions,
        crate::vfs::FileType::BlockDevice => 0o060000 | st.permissions,
        crate::vfs::FileType::Pipe        => 0o010000 | st.permissions,
        crate::vfs::FileType::EventFd     => 0o010000 | st.permissions, // FIFO
        crate::vfs::FileType::TimerFd | crate::vfs::FileType::SignalFd |
        crate::vfs::FileType::InotifyFd  => 0o010000 | st.permissions, // FIFO
        crate::vfs::FileType::PtyMaster | crate::vfs::FileType::PtySlave => 0o020000 | 0o666, // S_IFCHR
        crate::vfs::FileType::Socket      => 0o140000 | st.permissions, // S_IFSOCK
    };
    out[24..28].copy_from_slice(&mode.to_le_bytes());
    // uid (offset 28), gid (offset 32): 0
    // rdev (offset 40): 0
    // size (offset 48)
    out[48..56].copy_from_slice(&(st.size as i64).to_le_bytes());
    // blksize (offset 56)
    out[56..64].copy_from_slice(&4096i64.to_le_bytes());
    // blocks (offset 64): ceil(size / 512)
    let blocks = (st.size + 511) / 512;
    out[64..72].copy_from_slice(&(blocks as i64).to_le_bytes());
    // st_atim (offset 72): accessed time (seconds + nanoseconds)
    out[72..80].copy_from_slice(&(st.accessed as i64).to_le_bytes());
    // st_atim.tv_nsec (offset 80): 0
    // st_mtim (offset 88): modified time
    out[88..96].copy_from_slice(&(st.modified as i64).to_le_bytes());
    // st_mtim.tv_nsec (offset 96): 0
    // st_ctim (offset 104): created time (use as ctime)
    out[104..112].copy_from_slice(&(st.created as i64).to_le_bytes());
    // st_ctim.tv_nsec (offset 112): 0
}

// ── New Linux-specific syscalls ─────────────────────────────────────────────

/// arch_prctl(code, addr) — Set/get architecture-specific thread state.
///
/// Used by musl to set FS base for Thread-Local Storage (TLS).
pub fn sys_arch_prctl(code: u64, addr: u64) -> i64 {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;

    match code {
        ARCH_SET_FS => {
            // Write to FS.base via MSR 0xC0000100 and persist in thread struct
            unsafe { crate::hal::wrmsr(0xC000_0100, addr); }
            // Update the thread's tls_base so scheduler restores it on re-schedule
            let tid = crate::proc::current_tid();
            {
                let mut threads = crate::proc::THREAD_TABLE.lock();
                if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                    t.tls_base = addr;
                }
            }
            0
        }
        ARCH_GET_FS => {
            let fs = unsafe { crate::hal::rdmsr(0xC000_0100) };
            if addr != 0 {
                unsafe { *(addr as *mut u64) = fs; }
            }
            0
        }
        ARCH_SET_GS => {
            unsafe { crate::hal::wrmsr(0xC000_0101, addr); }
            0
        }
        ARCH_GET_GS => {
            let gs = unsafe { crate::hal::rdmsr(0xC000_0101) };
            if addr != 0 {
                unsafe { *(addr as *mut u64) = gs; }
            }
            0
        }
        _ => -22 // EINVAL
    }
}

/// set_tid_address(tidptr) — Store clear_child_tid pointer, return current TID.
/// glibc calls this during thread startup to register the address that should
/// be written to 0 and futex-woken when the thread exits (CLONE_CHILD_CLEARTID).
pub fn sys_set_tid_address(tidptr: u64) -> i64 {
    let tid = crate::proc::current_tid();
    if tidptr != 0 {
        let mut threads = crate::proc::THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.clear_child_tid = tidptr;
        }
    }
    tid as i64
}

/// clock_gettime(clockid, tp) — Get time from a clock.
///
/// tp points to a struct timespec { u64 tv_sec, u64 tv_nsec }.
/// CLOCK_REALTIME (0): wall-clock time from CMOS RTC + PIT sub-second.
/// CLOCK_MONOTONIC (1) and others: monotonic PIT ticks since boot.
pub fn sys_clock_gettime(clk_id: u64, tp: u64) -> i64 {
    const CLOCK_REALTIME:  u64 = 0;
    const CLOCK_MONOTONIC: u64 = 1;
    if tp == 0 {
        return -22; // EINVAL
    }
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let (secs, nsecs) = if clk_id == CLOCK_REALTIME {
        // Read wall-clock seconds from CMOS RTC; add sub-second from PIT.
        let wall_secs = crate::drivers::rtc::read_unix_time();
        let sub_nsecs = (ticks % 100) * 10_000_000u64; // 10 ms per PIT tick
        (wall_secs, sub_nsecs)
    } else {
        // CLOCK_MONOTONIC / CLOCK_MONOTONIC_RAW / CLOCK_PROCESS_CPUTIME_ID etc.
        // All return PIT-tick-based monotonic time.
        let s = ticks / 100;
        let ns = (ticks % 100) * 10_000_000u64;
        (s, ns)
    };
    let _ = CLOCK_MONOTONIC; // suppress unused warning
    let buf = unsafe { core::slice::from_raw_parts_mut(tp as *mut u8, 16) };
    buf[0..8].copy_from_slice(&secs.to_le_bytes());
    buf[8..16].copy_from_slice(&nsecs.to_le_bytes());
    0
}

/// mprotect(addr, len, prot) — Change protection on memory region.
///
/// Walks the page table for every mapped page in [addr, addr+len) and updates
/// the PTE flags to match the requested protection.  Also updates the VMA prot
/// field so future page-fault allocations use the right flags.
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    use crate::mm::vma::{page_align_down, page_align_up, PROT_READ, PROT_WRITE, PROT_EXEC};
    use crate::mm::vmm::{read_pte, write_pte, invlpg, PAGE_PRESENT, PAGE_WRITABLE,
                         PAGE_USER, PAGE_NO_EXECUTE};

    if len == 0 {
        return 0;
    }

    // Must be page-aligned.
    if addr & 0xFFF != 0 {
        return -22; // EINVAL
    }

    let base  = page_align_down(addr);
    let end   = page_align_up(addr.wrapping_add(len));
    let prot  = prot as u32;
    let pid   = crate::proc::current_pid();

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let space = match proc.vm_space.as_mut() {
        Some(s) => s,
        None => return -22,
    };
    let cr3 = space.cr3;

    // Update VMA prot fields that overlap this range, splitting VMAs as needed
    // so that only the exact [base, end) portion gets the new prot.
    let new_prot = prot;
    let mut i = 0;
    while i < space.areas.len() {
        let vma_base = space.areas[i].base;
        let vma_end  = space.areas[i].end();
        let old_prot = space.areas[i].prot;
        let flags    = space.areas[i].flags;
        let backing  = space.areas[i].backing.clone();
        let name     = space.areas[i].name;

        // No overlap — skip
        if vma_end <= base || vma_base >= end {
            i += 1;
            continue;
        }

        // Fully covered — just update in place, no split
        if vma_base >= base && vma_end <= end {
            space.areas[i].prot = new_prot;
            i += 1;
            continue;
        }

        // Partial overlap — remove and re-insert as up to 3 pieces.
        // CRITICAL: for file-backed VMAs, each split piece must have its
        // file offset adjusted by (piece.base - original_vma_base) so that
        // demand-paging reads from the correct file position.
        space.areas.remove(i);
        let overlap_start = vma_base.max(base);
        let overlap_end   = vma_end.min(end);

        // Helper: adjust file offset in backing for a split piece
        let adjust_backing = |b: &crate::mm::vma::VmBacking, piece_base: u64| -> crate::mm::vma::VmBacking {
            match b {
                crate::mm::vma::VmBacking::File { mount_idx, inode, offset } => {
                    crate::mm::vma::VmBacking::File {
                        mount_idx: *mount_idx,
                        inode: *inode,
                        offset: offset + (piece_base - vma_base),
                    }
                }
                other => other.clone(),
            }
        };

        let mut pieces: alloc::vec::Vec<crate::mm::vma::VmArea> = alloc::vec::Vec::new();
        if vma_base < base {
            pieces.push(crate::mm::vma::VmArea {
                base: vma_base, length: base - vma_base,
                prot: old_prot, flags, backing: adjust_backing(&backing, vma_base), name,
            });
        }
        pieces.push(crate::mm::vma::VmArea {
            base: overlap_start, length: overlap_end - overlap_start,
            prot: new_prot, flags, backing: adjust_backing(&backing, overlap_start), name,
        });
        if vma_end > end {
            pieces.push(crate::mm::vma::VmArea {
                base: end, length: vma_end - end,
                prot: old_prot, flags, backing: adjust_backing(&backing, end), name,
            });
        }
        let n = pieces.len();
        for piece in pieces.into_iter().rev() {
            space.areas.insert(i, piece);
        }
        i += n;
    }

    // Walk every page and retag PTEs.
    let mut page = base;
    while page < end {
        let pte = read_pte(cr3, page);
        if pte & PAGE_PRESENT != 0 {
            let phys = pte & 0x000F_FFFF_FFFF_F000;
            // Start from PRESENT | USER; add WRITABLE or NO_EXECUTE as needed.
            let mut new_flags = PAGE_PRESENT | PAGE_USER;
            if prot & PROT_WRITE != 0 {
                new_flags |= PAGE_WRITABLE;
            }
            if prot & PROT_EXEC == 0 {
                new_flags |= PAGE_NO_EXECUTE;
            }
            write_pte(cr3, page, phys | new_flags);
            invlpg(page);
        }
        page = page.wrapping_add(0x1000);
    }

    0
}

/// writev(fd, iov, iovcnt) — Write from multiple buffers.
pub fn sys_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    // struct iovec { void *iov_base; size_t iov_len; } = [u64; 2]
    if iovcnt == 0 { return 0; }
    let iovecs = unsafe {
        core::slice::from_raw_parts(iov_ptr as *const [u64; 2], iovcnt as usize)
    };
    let mut total = 0i64;
    for iov in iovecs {
        let base = iov[0];
        let len = iov[1] as usize;
        if len == 0 { continue; }
        let result = sys_write_linux(fd, base, len as u64);
        if result < 0 { return result; }
        total += result;
    }
    total
}

/// readv(fd, iov, iovcnt) — Scatter-gather read.
///
/// Reads from `fd` into multiple buffers described by the iovec array.
/// struct iovec { void *iov_base; size_t iov_len; } = [u64; 2] on x86_64.
fn sys_readv(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    if iovcnt == 0 { return 0; }
    let iovecs = unsafe {
        core::slice::from_raw_parts(iov_ptr as *const [u64; 2], iovcnt as usize)
    };
    let mut total = 0i64;
    for iov in iovecs {
        let base = iov[0];
        let len = iov[1] as usize;
        if len == 0 { continue; }
        let result = sys_read_linux(fd, base, len as u64);
        if result < 0 { return if total > 0 { total } else { result }; }
        total += result;
        if (result as usize) < len { break; } // short read — stop
    }
    total
}

/// fcntl(fd, cmd, arg) — File descriptor control.
fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    const F_DUPFD:    u64 = 0;
    const F_GETFD:    u64 = 1;
    const F_SETFD:    u64 = 2;
    const F_GETFL:    u64 = 3;
    const F_SETFL:    u64 = 4;
    const F_GETLK:    u64 = 5;
    const F_SETLK:    u64 = 6;
    const F_SETLKW:   u64 = 7;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const FD_CLOEXEC: u64 = 1;
    // struct flock (x86_64): l_type(i16@0), l_whence(i16@2), l_start(i64@8), l_len(i64@16), l_pid(i32@24)
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    let pid = crate::proc::current_pid();
    match cmd {
        F_GETLK | F_SETLK | F_SETLKW => {
            if arg == 0 { return -22; } // EINVAL: null flock pointer
            let l_type  = unsafe { *(arg as *const i16) };
            let l_start = unsafe { *((arg + 8)  as *const i64) } as u64;
            let l_len   = unsafe { *((arg + 16) as *const i64) } as u64;

            // Get fd's backing (mount_idx, inode).
            let (mount_idx, inode) = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                match procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.file_descriptors.get(fd as usize)?.as_ref())
                {
                    Some(f) if !f.is_console => (f.mount_idx, f.inode),
                    _ => return -9, // EBADF
                }
            };

            if cmd == F_GETLK {
                let locks = crate::vfs::FILE_LOCKS.lock();
                let conflict = locks.iter().find(|l| {
                    l.mount_idx == mount_idx && l.inode == inode && l.pid != pid
                        && (l_type == F_WRLCK || l.lock_type == F_WRLCK)
                });
                if let Some(lk) = conflict {
                    unsafe {
                        *(arg as *mut i16)        = lk.lock_type;
                        *((arg + 8)  as *mut i64) = lk.start as i64;
                        *((arg + 16) as *mut i64) = lk.end as i64;
                        *((arg + 24) as *mut i32) = lk.pid as i32;
                    }
                } else {
                    unsafe { *(arg as *mut i16) = F_UNLCK; }
                }
                return 0;
            }

            // F_SETLK / F_SETLKW — acquire or release.
            if l_type == F_UNLCK {
                crate::vfs::FILE_LOCKS.lock().retain(|l| {
                    !(l.mount_idx == mount_idx && l.inode == inode && l.pid == pid)
                });
                return 0;
            }
            // Check for conflict (we don't block for F_SETLKW — return EAGAIN).
            {
                let locks = crate::vfs::FILE_LOCKS.lock();
                if locks.iter().any(|l| {
                    l.mount_idx == mount_idx && l.inode == inode && l.pid != pid
                        && (l_type == F_WRLCK || l.lock_type == F_WRLCK)
                }) {
                    return -11; // EAGAIN
                }
            }
            let mut locks = crate::vfs::FILE_LOCKS.lock();
            locks.retain(|l| !(l.mount_idx == mount_idx && l.inode == inode && l.pid == pid));
            locks.push(crate::vfs::FileLockEntry {
                mount_idx, inode, pid,
                start: l_start, end: l_len, lock_type: l_type,
            });
            0
        }
        F_DUPFD => sys_dup(fd as usize),
        F_DUPFD_CLOEXEC => {
            let newfd = sys_dup(fd as usize);
            if newfd >= 0 {
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(f)) = proc.file_descriptors.get_mut(newfd as usize) {
                        f.cloexec = true;
                    }
                }
            }
            newfd
        }
        F_GETFD => {
            let procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc) = procs.iter().find(|p| p.pid == pid) {
                if let Some(Some(f)) = proc.file_descriptors.get(fd as usize) {
                    return if f.cloexec { FD_CLOEXEC as i64 } else { 0 };
                }
            }
            -9 // EBADF
        }
        F_SETFD => {
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                if let Some(Some(f)) = proc.file_descriptors.get_mut(fd as usize) {
                    f.cloexec = (arg & FD_CLOEXEC) != 0;
                    return 0;
                }
            }
            -9 // EBADF
        }
        F_GETFL => {
            let procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc) = procs.iter().find(|p| p.pid == pid) {
                if let Some(Some(f)) = proc.file_descriptors.get(fd as usize) {
                    return (f.flags & 0x0FFF) as i64; // return access mode + status flags
                }
            }
            -9 // EBADF
        }
        F_SETFL => 0, // ignore flag changes (O_NONBLOCK etc.)
        _ => -22 // EINVAL
    }
}

/// sendfile(out_fd, in_fd, offset_ptr, count) — Copy data between file descriptors.
///
/// If offset_ptr is non-NULL, reads from *offset_ptr rather than in_fd's current
/// position, and updates *offset_ptr to reflect bytes read (in_fd's offset unchanged).
/// If offset_ptr is NULL, uses and advances in_fd's current file offset.
fn sys_sendfile(out_fd: usize, in_fd: usize, offset_ptr: u64, count: usize) -> i64 {
    if count == 0 { return 0; }
    let max_chunk: usize = 65536; // send at most 64 KiB at a time
    let len = count.min(max_chunk);
    let pid = crate::proc::current_pid();

    // Snapshot in_fd info and the read offset.
    let (in_mount, in_inode, in_offset_cur) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p, None => return -3,
        };
        match proc.file_descriptors.get(in_fd).and_then(|f| f.as_ref()) {
            Some(f) => (f.mount_idx, f.inode, f.offset),
            None => return -9,
        }
    };
    let read_offset: u64 = if offset_ptr != 0 {
        unsafe { core::ptr::read_unaligned(offset_ptr as *const u64) }
    } else {
        in_offset_cur
    };

    // Read data from in_fd into a heap buffer.
    let mut buf: alloc::vec::Vec<u8> = alloc::vec![0u8; len];
    let n = {
        let mounts = crate::vfs::MOUNTS.lock();
        match mounts.get(in_mount) {
            Some(m) => match m.fs.read(in_inode, read_offset, &mut buf) {
                Ok(n) => n,
                Err(_) => return -5,
            },
            None => return -9,
        }
    };
    if n == 0 { return 0; }
    buf.truncate(n);

    // Snapshot out_fd info.
    let out_info = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p, None => return -3,
        };
        proc.file_descriptors.get(out_fd).and_then(|f| f.as_ref()).map(|f| {
            (f.is_console, f.file_type, f.mount_idx, f.inode, f.offset,
             f.flags & 0x8000_0001)
        })
    };
    let (is_console, file_type, out_mount, out_inode, out_offset, pipe_flags) = match out_info {
        Some(x) => x, None => return -9,
    };
    if is_console {
        crate::serial_print!("{}", core::str::from_utf8(&buf).unwrap_or("?"));
    } else if file_type == crate::vfs::FileType::Pipe {
        if pipe_flags & 1 != 0 {
            crate::ipc::pipe::pipe_write(out_inode, &buf);
        } else {
            return -9;
        }
    } else {
        let mounts = crate::vfs::MOUNTS.lock();
        match mounts.get(out_mount) {
            Some(m) => {
                let _ = m.fs.write(out_inode, out_offset, &buf);
                drop(mounts);
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(fd)) = proc.file_descriptors.get_mut(out_fd) {
                        fd.offset += n as u64;
                    }
                }
            }
            None => return -9,
        }
    }

    // Update the read offset.
    if offset_ptr != 0 {
        unsafe { core::ptr::write_unaligned(offset_ptr as *mut u64, read_offset + n as u64); }
    } else {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(Some(fd)) = proc.file_descriptors.get_mut(in_fd) {
                fd.offset += n as u64;
            }
        }
    }

    n as i64
}

/// access(pathname, mode) — Check user's permissions for a file.
fn sys_access(pathname: u64, _mode: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };
    match crate::vfs::stat(path) {
        Ok(_) => 0,
        Err(_) => -2, // ENOENT
    }
}

/// gettimeofday(tv, tz) — Get the time of day.
///
/// tv points to struct timeval { u64 tv_sec, u64 tv_usec }.
fn sys_gettimeofday(tv: u64, _tz: u64) -> i64 {
    if tv == 0 {
        return 0;
    }
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let secs = ticks / 100;
    let usecs = (ticks % 100) * 10_000; // 10ms per tick → microseconds
    let buf = unsafe { core::slice::from_raw_parts_mut(tv as *mut u8, 16) };
    buf[0..8].copy_from_slice(&secs.to_le_bytes());
    buf[8..16].copy_from_slice(&usecs.to_le_bytes());
    0
}

/// getdents64(fd, dirp, count) — Read directory entries.
///
/// Each entry: { d_ino: u64, d_off: u64, d_reclen: u16, d_type: u8, d_name: [u8] }
fn sys_getdents64(fd: u64, buf: u64, count: u64) -> i64 {
    let pid = crate::proc::current_pid();
    let (mount_idx, inode, offset, open_path) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let fd_entry = match proc_entry.file_descriptors.get(fd as usize).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return -9,
        };
        (fd_entry.mount_idx, fd_entry.inode, fd_entry.offset, fd_entry.open_path.clone())
    };

    // ── Special case: /proc/self/fd — synthesise entries from the fd table ──
    if open_path == "/proc/self/fd" || open_path == "/proc/self/fd/" {
        return getdents64_proc_fd(pid, fd as usize, buf, count, offset);
    }

    // Read directory entries from VFS
    let entries = {
        let mounts = crate::vfs::MOUNTS.lock();
        match mounts.get(mount_idx) {
            Some(m) => match m.fs.readdir(inode) {
                Ok(e) => e,
                Err(e) => return crate::subsys::linux::errno::vfs_err(e),
            },
            None => return -9,
        }
    };

    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
    let mut pos = 0usize;
    let mut entry_idx = offset as usize;

    while entry_idx < entries.len() {
        let (ref name, ino, ft) = entries[entry_idx];
        let name_bytes = name.as_bytes();
        // d_reclen: 8(ino) + 8(off) + 2(reclen) + 1(type) + name_len + 1(null) + padding
        let fixed_len = 19 + name_bytes.len() + 1;
        let reclen = (fixed_len + 7) & !7; // align to 8

        if pos + reclen > count as usize {
            break;
        }

        // d_ino (offset 0)
        out[pos..pos+8].copy_from_slice(&ino.to_le_bytes());
        // d_off (offset 8)
        out[pos+8..pos+16].copy_from_slice(&((entry_idx + 1) as u64).to_le_bytes());
        // d_reclen (offset 16)
        out[pos+16..pos+18].copy_from_slice(&(reclen as u16).to_le_bytes());
        // d_type (offset 18)
        out[pos+18] = match ft {
            crate::vfs::FileType::RegularFile => 8,  // DT_REG
            crate::vfs::FileType::Directory   => 4,  // DT_DIR
            crate::vfs::FileType::SymLink     => 10, // DT_LNK
            crate::vfs::FileType::CharDevice  => 2,  // DT_CHR
            crate::vfs::FileType::BlockDevice => 6,  // DT_BLK
            crate::vfs::FileType::Pipe        => 1,  // DT_FIFO
            crate::vfs::FileType::EventFd     => 1,  // DT_FIFO
            crate::vfs::FileType::TimerFd | crate::vfs::FileType::SignalFd |
            crate::vfs::FileType::InotifyFd  => 1,  // DT_FIFO
            crate::vfs::FileType::PtyMaster | crate::vfs::FileType::PtySlave => 2, // DT_CHR
            crate::vfs::FileType::Socket      => 12, // DT_SOCK
        };
        // d_name (offset 19)
        let nlen = name_bytes.len().min(reclen - 20);
        out[pos+19..pos+19+nlen].copy_from_slice(&name_bytes[..nlen]);
        out[pos+19+nlen] = 0; // null terminator
        // Zero padding
        for i in (pos+20+nlen)..pos+reclen {
            out[i] = 0;
        }

        pos += reclen;
        entry_idx += 1;
    }

    // Update the fd offset to track entries returned
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc_entry) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(Some(fd_entry)) = proc_entry.file_descriptors.get_mut(fd as usize) {
                fd_entry.offset = entry_idx as u64;
            }
        }
    }

    pos as i64
}

/// Synthesise getdents64 output for the virtual /proc/self/fd directory.
///
/// Entries: "." and ".." (DT_DIR), then one DT_LNK entry per open fd.
/// `dir_fd` is the fd that was opened on "/proc/self/fd" — its offset is
/// updated so repeated calls advance through the listing correctly.
fn getdents64_proc_fd(pid: u64, dir_fd: usize, buf: u64, count: u64, start_idx: u64) -> i64 {
    // Snapshot the list of open (fd_number, open_path) pairs.
    let fds_snap: alloc::vec::Vec<(usize, alloc::string::String)> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter().find(|p| p.pid == pid) {
            p.file_descriptors.iter().enumerate()
                .filter_map(|(i, slot)| slot.as_ref().map(|f| (i, f.open_path.clone())))
                .collect()
        } else {
            return -3; // ESRCH
        }
    };

    // Virtual entries: [".", ".."] + one per open fd
    // We represent each as (name, inode, d_type).
    // d_type: DT_DIR=4, DT_LNK=10
    let mut virtual_entries: alloc::vec::Vec<(alloc::string::String, u64, u8)> = alloc::vec::Vec::new();
    virtual_entries.push((alloc::string::String::from("."),  100, 4));
    virtual_entries.push((alloc::string::String::from(".."), 99,  4));
    for (fd_num, _) in &fds_snap {
        let name = alloc::format!("{}", fd_num);
        let ino = 200 + *fd_num as u64;
        virtual_entries.push((name, ino, 10)); // DT_LNK
    }

    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
    let mut pos = 0usize;
    let mut entry_idx = start_idx as usize;

    while entry_idx < virtual_entries.len() {
        let (ref name, ino, d_type) = virtual_entries[entry_idx];
        let name_bytes = name.as_bytes();
        let fixed_len = 19 + name_bytes.len() + 1; // all fixed fields + name + NUL
        let reclen = (fixed_len + 7) & !7;          // align to 8

        if pos + reclen > count as usize {
            break;
        }

        // d_ino [0..8]
        out[pos..pos+8].copy_from_slice(&ino.to_le_bytes());
        // d_off [8..16]
        out[pos+8..pos+16].copy_from_slice(&((entry_idx + 1) as u64).to_le_bytes());
        // d_reclen [16..18]
        out[pos+16..pos+18].copy_from_slice(&(reclen as u16).to_le_bytes());
        // d_type [18]
        out[pos+18] = d_type;
        // d_name [19..19+n+1]
        let nlen = name_bytes.len().min(reclen - 20);
        out[pos+19..pos+19+nlen].copy_from_slice(&name_bytes[..nlen]);
        out[pos+19+nlen] = 0;
        // zero padding
        for b in out[pos+20+nlen..pos+reclen].iter_mut() { *b = 0; }

        pos += reclen;
        entry_idx += 1;
    }

    // Persist updated offset so the next call resumes where we left off.
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(Some(f)) = p.file_descriptors.get_mut(dir_fd) {
                f.offset = entry_idx as u64;
            }
        }
    }

    pos as i64
}

/// openat(dirfd, pathname, flags, mode) — Open file relative to directory fd.
fn sys_openat(dirfd: u64, pathname: u64, flags: u64, mode: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    if dirfd as i64 == AT_FDCWD {
        return sys_open_linux(pathname, flags, mode);
    }

    // Real directory fd — resolve pathname relative to it.
    let path_bytes = read_cstring_from_user(pathname);
    let rel_path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return -22, // EINVAL
    };

    // If pathname is absolute, ignore dirfd.
    if rel_path.starts_with('/') {
        return sys_open_linux(pathname, flags, mode);
    }

    // Empty path with AT_EMPTY_PATH — not supported yet.
    if rel_path.is_empty() {
        return -22; // EINVAL
    }

    // Get the directory path from the dirfd.
    let pid = crate::proc::current_pid();
    let dir_path = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3, // ESRCH
        };
        let fd_idx = dirfd as usize;
        match proc_entry.file_descriptors.get(fd_idx).and_then(|f| f.as_ref()) {
            Some(fd) => fd.open_path.clone(),
            None => return -9, // EBADF
        }
    };

    // Build full path: dir_path + "/" + rel_path
    let full_path = if dir_path.ends_with('/') {
        alloc::format!("{}{}", dir_path, rel_path)
    } else {
        alloc::format!("{}/{}", dir_path, rel_path)
    };

    // Open via the normal VFS path.
    match crate::vfs::open(pid, &full_path, flags as u32) {
        Ok(fd_num) => fd_num as i64,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// newfstatat(dirfd, pathname, statbuf, flags) — stat relative to directory fd.
fn sys_newfstatat(dirfd: u64, pathname: u64, statbuf: u64, flags: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    const AT_EMPTY_PATH: u64 = 0x1000;

    // AT_EMPTY_PATH with empty pathname → fstat the dirfd itself.
    if flags & AT_EMPTY_PATH != 0 {
        let path_bytes = read_cstring_from_user(pathname);
        if path_bytes.is_empty() {
            return sys_fstat_linux(dirfd as usize, statbuf as *mut u8);
        }
    }

    if pathname == 0 {
        return sys_fstat_linux(dirfd as usize, statbuf as *mut u8);
    }

    let path_bytes = read_cstring_from_user(pathname);
    if path_bytes.is_empty() {
        return sys_fstat_linux(dirfd as usize, statbuf as *mut u8);
    }
    let path_str = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };

    // Absolute path or AT_FDCWD — resolve directly.
    if dirfd as i64 == AT_FDCWD || path_str.starts_with('/') {
        return sys_stat_linux(pathname, statbuf);
    }

    // Relative path with real dirfd — resolve relative to dirfd's path.
    let pid = crate::proc::current_pid();
    let dir_path = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let fd_idx = dirfd as usize;
        match proc_entry.file_descriptors.get(fd_idx).and_then(|f| f.as_ref()) {
            Some(fd) => fd.open_path.clone(),
            None => return -9, // EBADF
        }
    };

    let full_path = if dir_path.ends_with('/') {
        alloc::format!("{}{}", dir_path, path_str)
    } else {
        alloc::format!("{}/{}", dir_path, path_str)
    };

    match crate::vfs::stat(&full_path) {
        Ok(st) => {
            fill_linux_stat(statbuf as *mut u8, &st);
            0
        }
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// rt_sigaction for Linux ABI.
///
/// Linux struct kernel_sigaction:
///   sa_handler: u64, sa_flags: u64, sa_restorer: u64, sa_mask: [u64; 1]
fn sys_rt_sigaction_linux(sig: u64, act: u64, oldact: u64, _sigsetsize: u64) -> i64 {
    use crate::signal::{SigAction, SIGKILL, SIGSTOP, MAX_SIGNAL};

    const SA_RESTORER: u64 = 0x04000000;
    /// Minimum valid user-space pointer: reject anything below one page.
    const USER_PTR_MIN: u64 = 0x1000;
    /// Maximum valid user-space pointer (below the kernel half).
    const USER_PTR_MAX: u64 = 0x0000_8000_0000_0000;

    let sig = sig as u8;
    if sig == 0 || sig >= MAX_SIGNAL || sig == SIGKILL || sig == SIGSTOP {
        return -22;
    }

    // Validate pointer arguments before acquiring any locks to avoid
    // a page-fault-induced deadlock (page fault handler needs PROCESS_TABLE
    // which we would already hold).
    if oldact != 0 && (oldact < USER_PTR_MIN || oldact >= USER_PTR_MAX) {
        return -14; // EFAULT
    }
    if act != 0 && (act < USER_PTR_MIN || act >= USER_PTR_MAX) {
        return -14; // EFAULT
    }

    let pid = crate::proc::current_pid();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc_entry = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let sig_state = match proc_entry.signal_state.as_mut() {
        Some(s) => s,
        None => return -1,
    };

    // Save old action if requested
    if oldact != 0 {
        let (handler_addr, restorer_addr): (u64, u64) = match sig_state.actions[sig as usize] {
            SigAction::Default => (0, 0),
            SigAction::Ignore => (1, 0),
            SigAction::Handler { addr, restorer } => (addr, restorer),
        };
        let out = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, 32) };
        out[0..8].copy_from_slice(&handler_addr.to_le_bytes());
        out[8..16].copy_from_slice(&0u64.to_le_bytes()); // sa_flags
        out[16..24].copy_from_slice(&restorer_addr.to_le_bytes());
        out[24..32].copy_from_slice(&0u64.to_le_bytes()); // sa_mask
    }

    // Set new action if provided
    if act != 0 {
        let inp = unsafe { core::slice::from_raw_parts(act as *const u8, 32) };
        let handler_addr = u64::from_le_bytes(inp[0..8].try_into().unwrap());
        let sa_flags = u64::from_le_bytes(inp[8..16].try_into().unwrap());
        let sa_restorer = u64::from_le_bytes(inp[16..24].try_into().unwrap());

        let restorer = if sa_flags & SA_RESTORER != 0 && sa_restorer != 0 {
            sa_restorer
        } else {
            0 // use kernel trampoline
        };

        let action = match handler_addr {
            0 => SigAction::Default,
            1 => SigAction::Ignore,
            addr => SigAction::Handler { addr, restorer },
        };
        sig_state.actions[sig as usize] = action;
    }

    0
}

/// rt_sigprocmask for Linux ABI.
fn sys_rt_sigprocmask_linux(how: u64, set: u64, oldset: u64, _sigsetsize: u64) -> i64 {
    const USER_PTR_MIN: u64 = 0x1000;
    const USER_PTR_MAX: u64 = 0x0000_8000_0000_0000;
    if oldset != 0 && (oldset < USER_PTR_MIN || oldset >= USER_PTR_MAX) {
        return -14; // EFAULT
    }
    if set != 0 && (set < USER_PTR_MIN || set >= USER_PTR_MAX) {
        return -14; // EFAULT
    }

    let pid = crate::proc::current_pid();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc_entry = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let sig_state = match proc_entry.signal_state.as_mut() {
        Some(s) => s,
        None => return -1,
    };

    // Save old mask
    if oldset != 0 {
        let out = unsafe { core::slice::from_raw_parts_mut(oldset as *mut u8, 8) };
        out[0..8].copy_from_slice(&sig_state.blocked.to_le_bytes());
    }

    // Apply new mask
    if set != 0 {
        let inp = unsafe { core::slice::from_raw_parts(set as *const u8, 8) };
        let new_mask = u64::from_le_bytes(inp[0..8].try_into().unwrap());

        const SIG_BLOCK: u64 = 0;
        const SIG_UNBLOCK: u64 = 1;
        const SIG_SETMASK: u64 = 2;

        match how {
            SIG_BLOCK => sig_state.blocked |= new_mask,
            SIG_UNBLOCK => sig_state.blocked &= !new_mask,
            SIG_SETMASK => sig_state.blocked = new_mask,
            _ => return -22,
        }
        sig_state.blocked &= !((1u64 << crate::signal::SIGKILL) | (1u64 << crate::signal::SIGSTOP));
    }

    0
}

/// futex — Wait/Wake/Requeue implementation for musl/pthread compatibility.
///
/// Supported ops:
///   0  FUTEX_WAIT          Block if *uaddr==val, optional timeout in arg4
///   1  FUTEX_WAKE          Wake up to val waiters on uaddr
///   4  FUTEX_REQUEUE       Wake val waiters, requeue up-to val2 to uaddr2
///   5  FUTEX_CMP_REQUEUE   Like REQUEUE but check *uaddr==val3 first
///   9  FUTEX_WAIT_BITSET   Like WAIT (bitset ignored)
///  10  FUTEX_WAKE_BITSET   Like WAKE (bitset ignored)
fn sys_futex_linux(uaddr: u64, futex_op: u64, val: u64, timeout_ptr: u64, uaddr2: u64) -> i64 {
    let op = futex_op & 0x7F; // Strip FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME
    let pid = crate::proc::current_pid();

    // Helper: read timeout as nanoseconds from struct timespec { tv_sec: i64, tv_nsec: i64 }
    let timeout_ns: Option<u64> = if timeout_ptr != 0 {
        let tv_sec  = unsafe { user_read_u64(timeout_ptr) }.unwrap_or(0);
        let tv_nsec = unsafe { user_read_u64(timeout_ptr + 8) }.unwrap_or(0);
        Some(tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec))
    } else {
        None
    };

    match op {
        0 | 9 => {
            // FUTEX_WAIT / FUTEX_WAIT_BITSET: block if *uaddr == val
            let current = match unsafe { user_read_u32(uaddr) } {
                Some(v) => v,
                None => return -14, // EFAULT
            };
            if current as u64 != val {
                return -11; // EAGAIN — value changed
            }

            let tid = crate::proc::current_tid();
            {
                let mut waiters = FUTEX_WAITERS.lock();
                waiters.entry((pid, uaddr)).or_insert_with(Vec::new).push(tid);
            }

            // Block the thread with optional timeout deadline (approximate via tick count).
            {
                let mut threads = crate::proc::THREAD_TABLE.lock();
                if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                    t.state = crate::proc::ThreadState::Blocked;
                    // Approximate: 100 Hz tick, so 1 tick = 10 ms = 10_000_000 ns
                    t.wake_tick = if let Some(ns) = timeout_ns {
                        let now = crate::arch::x86_64::irq::get_ticks();
                        let delta_ticks = (ns / 10_000_000).max(1);
                        now.saturating_add(delta_ticks)
                    } else {
                        u64::MAX
                    };
                }
            }
            crate::sched::schedule();

            // Woken (or timed out). Clean up from wait queue.
            let mut timed_out = false;
            {
                let mut waiters = FUTEX_WAITERS.lock();
                if let Some(list) = waiters.get_mut(&(pid, uaddr)) {
                    let before = list.len();
                    list.retain(|&t| t != tid);
                    if list.len() < before { timed_out = true; } // still in list → woken; removed → timed out
                    if list.is_empty() {
                        waiters.remove(&(pid, uaddr));
                    }
                }
            }
            // If we removed ourselves from the waiter list, the scheduler woke us = timeout.
            // If the list entry was already gone, FUTEX_WAKE removed us = success.
            if timed_out {
                -110 // ETIMEDOUT
            } else {
                0
            }
        }
        1 | 10 => {
            // FUTEX_WAKE / FUTEX_WAKE_BITSET: wake up to val waiters
            let max_wake = if val == 0 { u64::MAX } else { val };
            let mut woken = 0u64;

            let tids_to_wake: Vec<u64> = {
                let mut waiters = FUTEX_WAITERS.lock();
                if let Some(list) = waiters.get_mut(&(pid, uaddr)) {
                    let mut result = Vec::new();
                    while !list.is_empty() && woken < max_wake {
                        result.push(list.remove(0));
                        woken += 1;
                    }
                    if list.is_empty() {
                        waiters.remove(&(pid, uaddr));
                    }
                    result
                } else {
                    Vec::new()
                }
            };

            {
                let mut threads = crate::proc::THREAD_TABLE.lock();
                for &t in &tids_to_wake {
                    if let Some(th) = threads.iter_mut().find(|th| th.tid == t) {
                        if th.state == crate::proc::ThreadState::Blocked {
                            th.state = crate::proc::ThreadState::Ready;
                            th.wake_tick = 0;
                        }
                    }
                }
            }

            woken as i64
        }
        4 | 5 => {
            // FUTEX_REQUEUE / FUTEX_CMP_REQUEUE
            // arg3=val (wake count), arg4=val2 (requeue count), arg5=uaddr2
            // For CMP_REQUEUE, also check *uaddr == val3 (we reuse val as val1, uaddr2 as uaddr2)
            // val2 is passed in timeout_ptr slot (Linux ABI: arg4 = val2 for REQUEUE)
            let val2 = timeout_ptr; // requeue limit (positional arg4)

            if op == 5 {
                // CMP_REQUEUE: verify *uaddr == val (the 6th argument would be val3, skip for simplicity)
                let current = match unsafe { user_read_u32(uaddr) } {
                    Some(v) => v,
                    None => return -14,
                };
                if current as u64 != val {
                    return -11; // EAGAIN
                }
            }

            let max_wake = val;
            let max_requeue = val2;
            let mut woken = 0u64;
            let mut requeued = 0u64;

            let tids_to_wake: Vec<u64>;
            let tids_to_requeue: Vec<u64>;

            {
                let mut waiters = FUTEX_WAITERS.lock();
                let src = waiters.remove(&(pid, uaddr)).unwrap_or_default();
                let mut wake_list = Vec::new();
                let mut requeue_list = Vec::new();
                for tid in src {
                    if woken < max_wake {
                        wake_list.push(tid);
                        woken += 1;
                    } else if requeued < max_requeue {
                        requeue_list.push(tid);
                        requeued += 1;
                    }
                }
                // Requeue to uaddr2
                if !requeue_list.is_empty() {
                    waiters.entry((pid, uaddr2)).or_insert_with(Vec::new).extend(requeue_list.iter());
                }
                tids_to_wake = wake_list;
                tids_to_requeue = requeue_list;
                let _ = tids_to_requeue; // used above
            }

            {
                let mut threads = crate::proc::THREAD_TABLE.lock();
                for &t in &tids_to_wake {
                    if let Some(th) = threads.iter_mut().find(|th| th.tid == t) {
                        if th.state == crate::proc::ThreadState::Blocked {
                            th.state = crate::proc::ThreadState::Ready;
                            th.wake_tick = 0;
                        }
                    }
                }
            }

            (woken + requeued) as i64
        }
        _ => -38, // ENOSYS
    }
}

// ── Phase 6 syscall implementations ────────────────────────────────────────

/// eventfd(initval, flags) — Create a counter-based signaling fd.
fn sys_eventfd_linux(initval: u64) -> i64 {
    let efd_id = crate::ipc::eventfd::create(initval, 0);
    if efd_id == u64::MAX {
        return -24; // EMFILE
    }

    let pid = crate::proc::current_pid();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => {
            crate::ipc::eventfd::close(efd_id);
            return -3;
        }
    };

    let fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode:     efd_id,
        offset:    0,
        flags:     0x0001_0000, // eventfd marker
        is_console: false,
        cloexec: false,
        file_type: crate::vfs::FileType::EventFd,
        open_path: alloc::string::String::new(),
    };

    // Find a free slot.
    let mut slot = None;
    for (i, f) in proc.file_descriptors.iter().enumerate() {
        if f.is_none() { slot = Some(i); break; }
    }
    let idx = if let Some(i) = slot {
        i
    } else if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let i = proc.file_descriptors.len();
        proc.file_descriptors.push(None);
        i
    } else {
        crate::ipc::eventfd::close(efd_id);
        return -24; // EMFILE
    };

    proc.file_descriptors[idx] = Some(fd);
    idx as i64
}

/// pipe2(pipefd[2], flags) — Create a pipe with optional flags.
///
/// flags may include:
///   O_CLOEXEC (0x0008_0000) — set close-on-exec (stored but not enforced yet)
///   O_NONBLOCK (0x0800)     — set non-blocking (stored but not enforced yet)
fn sys_pipe2_linux(fds_out: *mut u32, flags: u32) -> i64 {
    if fds_out.is_null() {
        return -22; // EINVAL
    }

    let pipe_id = crate::ipc::pipe::create_pipe();
    let pid = crate::proc::current_pid();

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let extra_flags: u32 = flags & (0x0008_0000 | 0x0800); // cloexec | nonblock

    let pipe_cloexec = (extra_flags & 0x0008_0000) != 0;
    let read_fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode:     pipe_id,
        offset:    0,
        flags:     0x8000_0000 | extra_flags, // read end
        is_console: false,
        cloexec:   pipe_cloexec,
        file_type: crate::vfs::FileType::Pipe,
        open_path: alloc::string::String::new(),
    };
    let write_fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode:     pipe_id,
        offset:    0,
        flags:     0x8000_0001 | extra_flags, // write end
        is_console: false,
        cloexec:   pipe_cloexec,
        file_type: crate::vfs::FileType::Pipe,
        open_path: alloc::string::String::new(),
    };

    let mut read_idx  = None;
    let mut write_idx = None;
    for (i, f) in proc.file_descriptors.iter().enumerate() {
        if f.is_none() {
            if read_idx.is_none()       { read_idx  = Some(i); }
            else if write_idx.is_none() { write_idx = Some(i); break; }
        }
    }

    // Extend fd table if needed
    let ri = if let Some(i) = read_idx {
        i
    } else if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let i = proc.file_descriptors.len();
        proc.file_descriptors.push(None);
        i
    } else {
        return -24; // EMFILE
    };
    let wi = if let Some(i) = write_idx {
        i
    } else if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let i = proc.file_descriptors.len();
        proc.file_descriptors.push(None);
        i
    } else {
        return -24; // EMFILE
    };

    proc.file_descriptors[ri] = Some(read_fd);
    proc.file_descriptors[wi] = Some(write_fd);

    unsafe {
        core::ptr::write_unaligned(fds_out,          ri as u32);
        core::ptr::write_unaligned(fds_out.add(1),   wi as u32);
    }
    0
}

/// statfs(path, buf) — Report filesystem statistics.
///
/// struct statfs (120 bytes on x86_64):
///   u64 f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree
///   u32[2] f_fsid
///   u64 f_namelen, f_frsize, f_flags
///   u64[4] f_spare
fn sys_statfs_linux(path_ptr: u64, buf: *mut u8) -> i64 {
    if buf.is_null() { return -14; }
    let path_raw = read_cstring_from_user(path_ptr);
    let path = core::str::from_utf8(path_raw).unwrap_or("");

    // Check the path exists (ignore error — statfs on /proc etc. always ok).
    let _ = crate::vfs::stat(path);

    fill_statfs_buf(buf);
    0
}

/// fstatfs(fd, buf) — filesystem statistics for an open fd.
fn sys_fstatfs_linux(_fd: usize, buf: *mut u8) -> i64 {
    if buf.is_null() { return -14; }
    fill_statfs_buf(buf);
    0
}

/// Write a plausible statfs structure into `buf` (120 bytes).
fn fill_statfs_buf(buf: *mut u8) {
    // Wipe first.
    unsafe { core::ptr::write_bytes(buf, 0, 120); }
    // Use EXT2_SUPER_MAGIC (0xEF53) as f_type — widely recognised.
    let p = buf as *mut u64;
    unsafe {
        *p.add(0)  = 0xEF53;   // f_type
        *p.add(1)  = 4096;     // f_bsize
        *p.add(2)  = 1024*128; // f_blocks (~512 MiB)
        *p.add(3)  = 1024*64;  // f_bfree
        *p.add(4)  = 1024*64;  // f_bavail
        *p.add(5)  = 32768;    // f_files
        *p.add(6)  = 32768;    // f_ffree
        // f_fsid at offset 56 — leave 0
        // f_namelen at byte 64 = index 8 of u64 array
        *p.add(8)  = 255;      // f_namelen
        *p.add(9)  = 4096;     // f_frsize
        *p.add(10) = 0;        // f_flags (ST_RDONLY=1? leave 0 = rw)
    }
}

/// Regenerate /proc/self/maps for `pid` from the process's live VMA list.
///
/// memfd_create(name, flags) — create an anonymous in-memory file.
/// Returns an fd pointing to a freshly created, unlinkable tmpfs file.
/// The file lives at a hidden path /tmp/.memfd_NNNN and is deleted on close.
fn sys_memfd_create(_name: u64, _flags: u64) -> i64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static MEMFD_COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = MEMFD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = crate::proc::current_pid();

    // Build path /tmp/.memfd_NNNN
    let mut path_buf = [0u8; 32];
    let prefix = b"/tmp/.memfd_";
    path_buf[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();
    let mut n = seq;
    let mut digits = [0u8; 20];
    let mut dlen = 0usize;
    if n == 0 { digits[0] = b'0'; dlen = 1; }
    while n > 0 { digits[dlen] = b'0' + (n % 10) as u8; dlen += 1; n /= 10; }
    for i in (0..dlen).rev() { path_buf[pos] = digits[i]; pos += 1; }
    let path_str = core::str::from_utf8(&path_buf[..pos]).unwrap_or("/tmp/.memfd_0");

    // Create the backing file in VFS
    if crate::vfs::create_file(path_str).is_err() {
        return -28; // ENOSPC
    }

    // Open it read/write
    match crate::vfs::open(pid, path_str, crate::vfs::flags::O_RDWR) {
        Ok(fd_num) => fd_num as i64,
        Err(_) => -12, // ENOMEM
    }
}

/// Generate and write /proc/self/status for `pid` with live process data.
fn refresh_proc_status(pid: u64) {
    use alloc::string::String;

    // Snapshot the fields we need while holding the lock briefly.
    let (ppid, name_bytes, fd_count, vm_rss_kb) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter().find(|p| p.pid == pid) {
            let ppid = p.parent_pid;
            let name_end = p.name.iter().position(|&b| b == 0).unwrap_or(8);
            let name_bytes = p.name[..name_end].to_vec();
            let fd_count = p.file_descriptors.iter().filter(|f| f.is_some()).count();
            // Estimate VmRSS from VMA list sizes.
            let vm_rss_kb: u64 = p.vm_space.as_ref()
                .map(|vs| vs.areas.iter().map(|a| a.length / 1024).sum())
                .unwrap_or(4096);
            (ppid, name_bytes, fd_count, vm_rss_kb)
        } else {
            return;
        }
    };

    let name_str = core::str::from_utf8(&name_bytes).unwrap_or("astryx");
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

    macro_rules! emit {
        ($($arg:tt)*) => {{
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, $($arg)*);
            out.extend_from_slice(s.as_bytes());
        }};
    }

    emit!("Name:\t{}\n", name_str);
    emit!("State:\tR (running)\n");
    emit!("Tgid:\t{}\n", pid);
    emit!("Pid:\t{}\n", pid);
    emit!("PPid:\t{}\n", ppid);
    emit!("TracerPid:\t0\n");
    emit!("Uid:\t0\t0\t0\t0\n");
    emit!("Gid:\t0\t0\t0\t0\n");
    emit!("FDSize:\t{}\n", fd_count.next_power_of_two().max(256));
    emit!("Groups:\n");
    emit!("VmPeak:\t{} kB\n", vm_rss_kb);
    emit!("VmSize:\t{} kB\n", vm_rss_kb);
    emit!("VmLck:\t0 kB\n");
    emit!("VmRSS:\t{} kB\n", vm_rss_kb);
    emit!("VmData:\t{} kB\n", vm_rss_kb / 2);
    emit!("VmStk:\t128 kB\n");
    emit!("VmExe:\t0 kB\n");
    emit!("VmLib:\t0 kB\n");
    emit!("VmPTE:\t0 kB\n");
    emit!("Threads:\t1\n");
    emit!("SigPnd:\t0000000000000000\n");
    emit!("ShdPnd:\t0000000000000000\n");
    emit!("SigBlk:\t0000000000000000\n");
    emit!("SigIgn:\t0000000000000000\n");
    emit!("SigCgt:\t0000000000000000\n");
    emit!("CapInh:\t0000000000000000\n");
    emit!("CapPrm:\t0000003fffffffff\n");
    emit!("CapEff:\t0000003fffffffff\n");
    emit!("CapBnd:\t0000003fffffffff\n");
    emit!("CapAmb:\t0000000000000000\n");
    emit!("Cpus_allowed:\t1\n");
    emit!("Cpus_allowed_list:\t0\n");
    emit!("voluntary_ctxt_switches:\t0\n");
    emit!("nonvoluntary_ctxt_switches:\t0\n");

    let _ = crate::vfs::write_file("/proc/self/status", &out);
}

/// This is called every time a process opens /proc/self/maps so the content
/// always reflects the current address space.  We snapshot the VMA list while
/// holding PROCESS_TABLE, release the lock, then format + write the VFS file.
fn refresh_proc_maps(pid: u64) {
    use crate::mm::vma::{VmProt, PROT_READ, PROT_WRITE, PROT_EXEC};

    // Snapshot VMA data (base, end, prot, name) without holding any lock while
    // we format and write the VFS file (which acquires its own locks).
    struct VmaSnap {
        base: u64,
        end:  u64,
        prot: VmProt,
        name: &'static str,
    }

    let snaps: Vec<VmaSnap> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter().find(|p| p.pid == pid) {
            if let Some(ref vs) = p.vm_space {
                vs.areas.iter().map(|a| VmaSnap {
                    base: a.base,
                    end:  a.end(),
                    prot: a.prot,
                    name: a.name,
                }).collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    if snaps.is_empty() {
        return;
    }

    // Format each VMA entry.  Linux /proc/maps format:
    //   aaaa-bbbb rwxp 00000000 00:00 0 pathname\n
    let mut out = Vec::new();
    for s in &snaps {
        let r = if s.prot & PROT_READ  != 0 { b'r' } else { b'-' };
        let w = if s.prot & PROT_WRITE != 0 { b'w' } else { b'-' };
        let x = if s.prot & PROT_EXEC  != 0 { b'x' } else { b'-' };
        // Write base address
        write_hex64(&mut out, s.base);
        out.push(b'-');
        write_hex64(&mut out, s.end);
        out.push(b' ');
        out.push(r); out.push(w); out.push(x); out.push(b'p');
        // offset dev ino
        out.extend_from_slice(b" 00000000 00:00 0");
        if !s.name.is_empty() {
            out.push(b' ');
            out.push(b' ');
            out.extend_from_slice(s.name.as_bytes());
        }
        out.push(b'\n');
    }

    let _ = crate::vfs::write_file("/proc/self/maps", &out);
}

/// Write a 64-bit value as 16 lowercase hex digits into a Vec<u8>.
fn write_hex64(out: &mut Vec<u8>, mut v: u64) {
    let mut buf = [0u8; 16];
    for i in (0..16).rev() {
        let nibble = (v & 0xF) as u8;
        buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        v >>= 4;
    }
    out.extend_from_slice(&buf);
}

// ─── epoll helpers ───────────────────────────────────────────────────────────

/// Determine the current ready event mask for fd `fd` in process `pid`.
///
/// Rules:
///  - fd 0 (stdin):        0 (no interactive keyboard in test mode)
///  - fd 1/2 (stdout/err): EPOLLOUT
///  - pipe read-end:       EPOLLIN if data available
///  - pipe write-end:      EPOLLOUT always
///  - regular file/dir:    EPOLLIN | EPOLLOUT
///  - closed/invalid:      EPOLLERR
/// Poll the readiness events for `fd` in process `pid`.
/// Returns a bitmask of EPOLL* flags that are currently set.
fn epoll_poll_events(pid: u64, fd: usize) -> u32 {
    use crate::ipc::epoll::{EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP};

    // Snapshot fd metadata with a brief lock hold.
    let info: Option<(u64, u32, bool, bool, crate::vfs::FileType)> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid).and_then(|proc| {
            proc.file_descriptors.get(fd)?.as_ref().map(|f| {
                let is_epoll = f.open_path.as_str() == "[epoll]";
                (f.inode, f.flags, f.is_console, is_epoll, f.file_type)
            })
        })
    };

    match info {
        None => match fd { 0 => 0, 1 | 2 => EPOLLOUT, _ => EPOLLERR },
        Some((_, _, _, true, _)) => 0,
        Some((_, _, true, _, _)) => EPOLLOUT,
        Some((inode, _flags, false, false, crate::vfs::FileType::EventFd)) => {
            if crate::ipc::eventfd::is_readable(inode) { EPOLLIN } else { 0 }
        }
        Some((inode, _flags, false, false, crate::vfs::FileType::TimerFd)) => {
            if crate::ipc::timerfd::is_readable(inode) { EPOLLIN } else { 0 }
        }
        Some((inode, _flags, false, false, crate::vfs::FileType::SignalFd)) => {
            if crate::ipc::signalfd::is_readable(inode) { EPOLLIN } else { 0 }
        }
        Some((_inode, _flags, false, false, crate::vfs::FileType::InotifyFd)) => {
            0 // stub: never delivers events
        }
        Some((inode, _flags, false, false, crate::vfs::FileType::PtyMaster)) => {
            if crate::drivers::pty::master_readable(inode as u8) { EPOLLIN | EPOLLOUT } else { EPOLLOUT }
        }
        Some((inode, _flags, false, false, crate::vfs::FileType::PtySlave)) => {
            if crate::drivers::pty::slave_readable(inode as u8) { EPOLLIN | EPOLLOUT } else { EPOLLOUT }
        }
        Some((inode, flags, false, false, _)) => {
            if flags & 0x8000_0000 != 0 {
                // Pipe fd
                if flags & 0x01 == 0 {
                    if crate::ipc::pipe::pipe_has_data(inode)    { EPOLLIN }
                    else if crate::ipc::pipe::pipe_is_eof(inode) { EPOLLHUP }
                    else { 0 }
                } else {
                    EPOLLOUT
                }
            } else {
                EPOLLIN | EPOLLOUT
            }
        }
    }
}

/// epoll_create / epoll_create1 — allocate a new epoll fd.
fn sys_epoll_create1(_flags: u32) -> i64 {
    let pid = crate::proc::current_pid();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None    => return -9, // EBADF
    };
    // Find the lowest free fd slot.
    let slot = proc.file_descriptors.iter().position(|f| f.is_none())
        .unwrap_or_else(|| {
            proc.file_descriptors.push(None);
            proc.file_descriptors.len() - 1
        });
    // Extend fd table if needed.
    while proc.file_descriptors.len() <= slot {
        proc.file_descriptors.push(None);
    }
    proc.file_descriptors[slot] = Some(crate::vfs::FileDescriptor {
        inode:     0,
        mount_idx: 0,
        offset:    0,
        flags:     0,
        file_type: crate::vfs::FileType::CharDevice,
        is_console: false,
        cloexec:   false,
        open_path: alloc::string::String::from("[epoll]"),
    });
    proc.epoll_sets.push(crate::ipc::epoll::EpollInstance::new(slot));
    slot as i64
}

/// epoll_ctl — add/modify/delete a watched fd.
fn sys_epoll_ctl(epfd: usize, op: u64, fd: usize, event_ptr: u64) -> i64 {
    use crate::ipc::epoll::{EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD, EpollEvent};
    let pid = crate::proc::current_pid();

    // Read the caller's epoll_event (only needed for ADD / MOD).
    let (events, data) = if event_ptr != 0 && op != EPOLL_CTL_DEL {
        let ev = unsafe { core::ptr::read_unaligned(event_ptr as *const EpollEvent) };
        (ev.events, ev.data)
    } else {
        (0u32, 0u64)
    };

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None    => return -9, // EBADF
    };

    // Verify epfd refers to an epoll object.
    let is_epoll = proc.file_descriptors.get(epfd)
        .and_then(|f| f.as_ref())
        .map(|f| f.open_path == "[epoll]")
        .unwrap_or(false);
    if !is_epoll { return -9; } // EBADF

    let inst = match proc.epoll_sets.iter_mut().find(|e| e.epfd == epfd) {
        Some(i) => i,
        None    => return -9, // EBADF
    };

    match op {
        EPOLL_CTL_ADD => {
            if inst.add(fd, events, data) { 0 } else { -17 } // EEXIST
        }
        EPOLL_CTL_DEL => {
            if inst.del(fd) { 0 } else { -2 } // ENOENT
        }
        EPOLL_CTL_MOD => {
            if inst.modify(fd, events, data) { 0 } else { -2 } // ENOENT
        }
        _ => -22, // EINVAL
    }
}

/// epoll_wait — collect ready events into caller's buffer.
fn sys_epoll_wait(epfd: usize, events_ptr: u64, maxevents: usize, timeout_ms: i32) -> i64 {
    use crate::ipc::epoll::{EpollEvent, EPOLLERR};
    if maxevents == 0 { return -22; } // EINVAL
    let pid = crate::proc::current_pid();

    // ── Step 1: snapshot the watch list while briefly holding the lock ────────
    let watches_snap: alloc::vec::Vec<(usize, u32, u64)> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None    => return -9, // EBADF
        };
        let is_epoll = proc.file_descriptors.get(epfd)
            .and_then(|f| f.as_ref())
            .map(|f| f.open_path == "[epoll]")
            .unwrap_or(false);
        if !is_epoll { return -9; }
        let inst = match proc.epoll_sets.iter().find(|e| e.epfd == epfd) {
            Some(i) => i,
            None    => return -9,
        };
        inst.watches.iter().map(|w| (w.fd, w.events, w.data)).collect()
    }; // lock released here

    // ── Step 2: poll without holding the lock ────────────────────────────────
    let do_poll = |fired: &mut alloc::vec::Vec<EpollEvent>| {
        for &(fd, subscribed, data) in &watches_snap {
            if fired.len() >= maxevents { break; }
            let ready_ev = epoll_poll_events(pid, fd);
            let interest = subscribed & (ready_ev | EPOLLERR);
            if interest != 0 {
                fired.push(EpollEvent { events: interest, data });
            }
        }
    };

    let mut fired: alloc::vec::Vec<EpollEvent> = alloc::vec::Vec::new();
    do_poll(&mut fired);

    // If nothing ready and caller is willing to wait, yield one tick then retry.
    if fired.is_empty() && timeout_ms != 0 {
        crate::proc::sleep_ticks(1);
        do_poll(&mut fired);
    }

    // ── Step 3: copy events to the caller's buffer ───────────────────────────
    let count = fired.len();
    if count > 0 && events_ptr != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(
                fired.as_ptr(),
                events_ptr as *mut EpollEvent,
                count,
            );
        }
    }
    count as i64
}

// ============================================================================
// timerfd syscalls
// ============================================================================

/// `timerfd_create(clockid, flags)` — allocate a timer notification fd.
fn sys_timerfd_create(clockid: u32) -> i64 {
    let slot_id = crate::ipc::timerfd::create(clockid);
    if slot_id == u64::MAX { return -24; } // EMFILE

    let pid = crate::proc::current_pid();
    let fd = crate::vfs::FileDescriptor::timer_fd(slot_id);

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => { crate::ipc::timerfd::close(slot_id); return -3; }
    };
    for (i, slot) in proc.file_descriptors.iter().enumerate() {
        if slot.is_none() {
            proc.file_descriptors[i] = Some(fd);
            return i as i64;
        }
    }
    if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let idx = proc.file_descriptors.len();
        proc.file_descriptors.push(Some(fd));
        return idx as i64;
    }
    crate::ipc::timerfd::close(slot_id);
    -24 // EMFILE
}

/// `timerfd_settime(fd, flags, *new_value, *old_value)` — arm/disarm a timer.
///
/// `new_value` is a `struct itimerspec { it_interval, it_value }` where each
/// timespec is `{ tv_sec: i64, tv_nsec: i64 }` (16 bytes each, 32 bytes total).
fn sys_timerfd_settime(fd_num: u64, flags: u32, new_value_ptr: u64, old_value_ptr: u64) -> i64 {
    let pid = crate::proc::current_pid();
    if !is_timerfd_fd(pid, fd_num as usize) { return -9; } // EBADF
    let slot_id = get_timerfd_id(pid, fd_num as usize);

    // Read new_value itimerspec (32 bytes): interval (16) then value (16).
    if !validate_user_ptr(new_value_ptr, 32) { return -14; } // EFAULT
    let (int_sec, int_nsec, val_sec, val_nsec) = unsafe {
        let p = new_value_ptr as *const i64;
        let int_sec  = *p.add(0) as u64;
        let int_nsec = *p.add(1) as u64;
        let val_sec  = *p.add(2) as u64;
        let val_nsec = *p.add(3) as u64;
        (int_sec, int_nsec, val_sec, val_nsec)
    };
    let interval_ns = int_sec.saturating_mul(1_000_000_000).saturating_add(int_nsec);
    let value_ns    = val_sec.saturating_mul(1_000_000_000).saturating_add(val_nsec);

    match crate::ipc::timerfd::settime(slot_id, flags, value_ns, interval_ns) {
        None => -9, // EBADF
        Some((old_int_ns, old_val_ns)) => {
            // Optionally write old_value back.
            if old_value_ptr != 0 && validate_user_ptr(old_value_ptr, 32) {
                let old_int_sec  = (old_int_ns / 1_000_000_000) as i64;
                let old_int_nsec = (old_int_ns % 1_000_000_000) as i64;
                let old_val_sec  = (old_val_ns / 1_000_000_000) as i64;
                let old_val_nsec = (old_val_ns % 1_000_000_000) as i64;
                unsafe {
                    let p = old_value_ptr as *mut i64;
                    *p.add(0) = old_int_sec;
                    *p.add(1) = old_int_nsec;
                    *p.add(2) = old_val_sec;
                    *p.add(3) = old_val_nsec;
                }
            }
            0
        }
    }
}

/// `timerfd_gettime(fd, *curr_value)` — read current timer setting.
fn sys_timerfd_gettime(fd_num: u64, curr_value_ptr: u64) -> i64 {
    let pid = crate::proc::current_pid();
    if !is_timerfd_fd(pid, fd_num as usize) { return -9; } // EBADF
    let slot_id = get_timerfd_id(pid, fd_num as usize);
    let (interval_ns, value_ns) = crate::ipc::timerfd::gettime(slot_id);

    if curr_value_ptr != 0 && validate_user_ptr(curr_value_ptr, 32) {
        let int_sec  = (interval_ns / 1_000_000_000) as i64;
        let int_nsec = (interval_ns % 1_000_000_000) as i64;
        let val_sec  = (value_ns   / 1_000_000_000) as i64;
        let val_nsec = (value_ns   % 1_000_000_000) as i64;
        unsafe {
            let p = curr_value_ptr as *mut i64;
            *p.add(0) = int_sec;
            *p.add(1) = int_nsec;
            *p.add(2) = val_sec;
            *p.add(3) = val_nsec;
        }
    }
    0
}

// ============================================================================
// signalfd4 syscall
// ============================================================================

/// `signalfd4(fd, *sigmask, sizemask, flags)` — create or update a signalfd.
///
/// If `fd == -1`, create a new signalfd. Otherwise update the mask of fd.
fn sys_signalfd4(fd_num: u64, mask_ptr: u64, sizemask: u64, _flags: u32) -> i64 {
    if sizemask < 8 || !validate_user_ptr(mask_ptr, 8) { return -22; } // EINVAL/EFAULT
    let sigmask = unsafe { *(mask_ptr as *const u64) };
    let pid = crate::proc::current_pid();

    // fd == u64::MAX means -1 (create new).
    if fd_num == u64::MAX || fd_num as i64 == -1 {
        let slot_id = crate::ipc::signalfd::create(pid, sigmask);
        if slot_id == u64::MAX { return -24; } // EMFILE

        let fd = crate::vfs::FileDescriptor::signal_fd(slot_id);
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => { crate::ipc::signalfd::close(slot_id); return -3; }
        };
        for (i, slot) in proc.file_descriptors.iter().enumerate() {
            if slot.is_none() {
                proc.file_descriptors[i] = Some(fd);
                return i as i64;
            }
        }
        if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
            let idx = proc.file_descriptors.len();
            proc.file_descriptors.push(Some(fd));
            return idx as i64;
        }
        crate::ipc::signalfd::close(slot_id);
        -24 // EMFILE
    } else {
        // Update existing signalfd's mask.
        if !is_signalfd_fd(pid, fd_num as usize) { return -9; } // EBADF
        crate::ipc::signalfd::update_mask(get_signalfd_id(pid, fd_num as usize), sigmask);
        fd_num as i64
    }
}

// ============================================================================
// inotify syscalls
// ============================================================================

/// `inotify_init1(flags)` — create an inotify file descriptor.
fn sys_inotify_init1(_flags: u32) -> i64 {
    let slot_id = crate::ipc::inotify::create();
    if slot_id == u64::MAX { return -24; } // EMFILE

    let pid = crate::proc::current_pid();
    let fd = crate::vfs::FileDescriptor::inotify_fd(slot_id);

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => { crate::ipc::inotify::close(slot_id); return -3; }
    };
    for (i, slot) in proc.file_descriptors.iter().enumerate() {
        if slot.is_none() {
            proc.file_descriptors[i] = Some(fd);
            return i as i64;
        }
    }
    if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let idx = proc.file_descriptors.len();
        proc.file_descriptors.push(Some(fd));
        return idx as i64;
    }
    crate::ipc::inotify::close(slot_id);
    -24
}

/// `inotify_add_watch(fd, pathname, mask)` — add a watch descriptor.
fn sys_inotify_add_watch(fd_num: u64, path_ptr: u64, mask: u32) -> i64 {
    let pid = crate::proc::current_pid();
    if !is_inotify_fd(pid, fd_num as usize) { return -9; } // EBADF
    let id = get_inotify_id(pid, fd_num as usize);
    let path_bytes = read_cstring_from_user(path_ptr);
    let path = core::str::from_utf8(path_bytes).unwrap_or("");
    let wd = crate::ipc::inotify::add_watch(id, path, mask);
    if wd < 0 { -1 } else { wd as i64 }
}

/// `inotify_rm_watch(fd, wd)` — remove a watch descriptor.
fn sys_inotify_rm_watch(fd_num: u64, wd: i32) -> i64 {
    let pid = crate::proc::current_pid();
    if !is_inotify_fd(pid, fd_num as usize) { return -9; } // EBADF
    let id = get_inotify_id(pid, fd_num as usize);
    if crate::ipc::inotify::rm_watch(id, wd) { 0 } else { -22 }
}
