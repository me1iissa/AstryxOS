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

// ═══════════════════════════════════════════════════════════════════════════════
// Futex wait queue — keyed by virtual address
// ═══════════════════════════════════════════════════════════════════════════════

/// Futex wait queue: maps (pid, uaddr) -> list of waiting TIDs.
static FUTEX_WAITERS: Mutex<BTreeMap<(u64, u64), Vec<u64>>> = Mutex::new(BTreeMap::new());

/// Kernel stack pointer for the current thread. Set by the scheduler on
/// every context switch to a user-mode thread. SYSCALL entry loads RSP from
/// this before doing any stack operations.
///
/// On a single-CPU system this is safe: only one thread can execute SYSCALL
/// at a time, and it is set before the thread runs.
#[no_mangle]
pub static mut SYSCALL_KERNEL_RSP: u64 = 0;

/// Scratch space for saving the user RSP during syscall handling.
#[no_mangle]
pub static mut SYSCALL_USER_RSP: u64 = 0;

/// Set the kernel RSP for syscall handling (called on context switches).
///
/// # Safety
/// Must only be called with a valid kernel stack top address.
pub unsafe fn set_kernel_rsp(rsp: u64) {
    SYSCALL_KERNEL_RSP = rsp;
}

/// Initialize the syscall interface.
pub fn init() {
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
        // Enable SCE (System Call Extensions) in IA32_EFER
        let efer = crate::hal::rdmsr(0xC000_0080);
        crate::hal::wrmsr(0xC000_0080, efer | 1);

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
    }
}

/// Syscall dispatch — called from both int 0x80 handler and syscall instruction.
///
/// Arguments follow Linux x86_64 ABI:
/// - RAX: syscall number
/// - RDI: arg1, RSI: arg2, RDX: arg3, R10: arg4, R8: arg5, R9: arg6
///
/// Returns result in RAX.
pub fn dispatch(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    crate::perf::record_syscall(num);
    // Check if the current process uses Linux syscall ABI
    if is_linux_abi() {
        return dispatch_linux(num, arg1, arg2, arg3, arg4, arg5);
    }
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

            if fd == 1 || fd == 2 {
                crate::drivers::tty::TTY0.lock().write(slice);
                count as i64
            } else if is_pipe_fd(crate::proc::current_pid(), fd as usize) {
                let pipe_id = get_pipe_id(crate::proc::current_pid(), fd as usize);
                match crate::ipc::pipe::pipe_write(pipe_id, slice) {
                    Some(n) => n as i64,
                    None => -9, // EBADF
                }
            } else {
                // Try VFS
                let pid = crate::proc::current_pid();
                match crate::vfs::fd_write(pid, fd as usize, arg2 as *const u8, count) {
                    Ok(n) => n as i64,
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

            if fd == 0 {
                // stdin — read through TTY line discipline
                let mut attempts = 0u32;
                loop {
                    {
                        let mut tty = crate::drivers::tty::TTY0.lock();
                        // Pump pending scancodes into the TTY
                        crate::drivers::tty::pump_keyboard(&mut tty);
                        let n = tty.read(buf, count);
                        if n > 0 {
                            return n as i64;
                        }
                    }
                    // No data yet — yield and retry
                    attempts += 1;
                    if attempts > 100_000 {
                        // Avoid infinite busy-loop in test mode
                        return 0;
                    }
                    crate::hal::halt();
                }
            } else if is_pipe_fd(crate::proc::current_pid(), fd as usize) {
                let pipe_id = get_pipe_id(crate::proc::current_pid(), fd as usize);
                match crate::ipc::pipe::pipe_read(pipe_id, buf) {
                    Some(n) => n as i64,
                    None => -9, // EBADF
                }
            } else {
                let pid = crate::proc::current_pid();
                match crate::vfs::fd_read(pid, fd as usize, arg2 as *mut u8, count) {
                    Ok(n) => n as i64,
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
                Err(e) => -(e as i64),
            }
        }
        SYS_CLOSE => {
            let fd = arg1 as usize;
            let pid = crate::proc::current_pid();
            match crate::vfs::close(pid, fd) {
                Ok(()) => 0,
                Err(e) => -(e as i64),
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
            // exec(path_ptr, path_len)
            sys_exec(arg1, arg2)
        }
        SYS_WAITPID => {
            // waitpid(pid, options)
            sys_waitpid(arg1 as i64, arg2 as u32)
        }
        SYS_MMAP => {
            // mmap(addr, length, prot, flags, fd, offset)
            sys_mmap(arg1, arg2, arg3 as u32, arg4 as u32, arg5, 0)
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
            // futex(uaddr, op, val)
            sys_futex_linux(arg1, arg2, arg3)
        }
        SYS_SYNC => {
            // sync() — flush all dirty filesystem data to disk
            crate::vfs::sync_all();
            0
        }
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
///
/// Callee-saved registers (RBX, RBP, R12-R15) are preserved.
/// Caller-saved registers (RDI, RSI, RDX, R10, R8, R9) may be clobbered.
#[unsafe(naked)]
extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // ── Step 1: Switch to kernel stack ──────────────────────────
        // Save user RSP into the scratch global, load kernel RSP.
        "mov [{user_rsp}], rsp",
        "mov rsp, [{kernel_rsp}]",

        // ── Step 2: Save user context on kernel stack ───────────────
        // These are restored on SYSRETQ.
        "push qword ptr [{user_rsp}]",  // saved user RSP
        "push rcx",                      // return RIP
        "push r11",                      // return RFLAGS
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

        // ── Step 3: Re-enable interrupts for syscall handling ───────
        "sti",

        // ── Step 4: Set up C calling convention for dispatch() ──────
        // Syscall ABI:  rax=num, rdi=a1, rsi=a2, rdx=a3, r10=a4, r8=a5
        // C convention:  rdi=num, rsi=a1, rdx=a2, rcx=a3, r8=a4,  r9=a5
        "mov r9, r8",       // arg5 -> r9
        "mov r8, r10",      // arg4 -> r8
        "mov rcx, rdx",     // arg3 -> rcx
        "mov rdx, rsi",     // arg2 -> rdx
        "mov rsi, rdi",     // arg1 -> rsi
        "mov rdi, rax",     // num  -> rdi
        "call {dispatch}",
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

        kernel_rsp = sym SYSCALL_KERNEL_RSP,
        user_rsp = sym SYSCALL_USER_RSP,
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
    dispatch(num, arg1, arg2, arg3, arg4, arg5)
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
fn sys_exec(path_ptr: u64, path_len: u64) -> i64 {
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
            return -(e as i64);
        }
    };

    // Validate it's an ELF binary.
    if !crate::proc::elf::is_elf(&elf_data) {
        crate::serial_println!("[SYSCALL] exec: not an ELF binary");
        return -8; // ENOEXEC
    }

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
        match crate::proc::usermode::create_user_process(path, &elf_data) {
            Ok(new_pid) => {
                // ELFs loaded from disk use the Linux syscall ABI.
                {
                    let mut procs = crate::proc::PROCESS_TABLE.lock();
                    if let Some(p) = procs.iter_mut().find(|p| p.pid == new_pid) {
                        p.linux_abi = true;
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

    let result = match crate::proc::elf::load_elf(&elf_data, new_vm_space.cr3) {
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

    // Return 0 — dispatch puts this in RAX. When syscall_entry does SYSRETQ,
    // it restores the modified frame and jumps to the new entry point.
    // Note: for a true exec, the return value in RAX is irrelevant because
    // the new process image doesn't expect a return value from exec.
    0
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
            return Err(-(e as i64));
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
    let parent_pid = crate::proc::current_pid();
    let parent_tid = crate::proc::current_tid();

    crate::serial_println!("[SYSCALL] fork() from PID {} TID {}", parent_pid, parent_tid);

    // Create a new process (child) with a new PID and thread.
    let child_pid = crate::proc::fork_process(parent_pid, parent_tid);

    match child_pid {
        Some(pid) => {
            crate::serial_println!("[SYSCALL] fork: child PID {} created", pid);
            pid as i64 // Return child PID to parent
        }
        None => {
            crate::serial_println!("[SYSCALL] fork: failed to create child");
            -12 // ENOMEM
        }
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
        // File-backed mapping: look up the fd to get (mount_idx, inode)
        let fd_num = fd as usize;
        match proc.file_descriptors.get(fd_num).and_then(|f| f.as_ref()) {
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
        Err(e) => return -(e as i64),
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
        Err(e) => -(e as i64),
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
        Err(e) => -(e as i64),
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
        Err(e) => -(e as i64),
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
            Err(e) => -(e as i64),
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
        file_type: crate::vfs::FileType::Pipe,
    };

    // Create write-end FD
    let write_fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode: pipe_id,
        offset: 0,
        flags: 0x8000_0001, // Pipe write end
        is_console: false,
        file_type: crate::vfs::FileType::Pipe,
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

/// Get the pipe_id for a pipe file descriptor.
fn get_pipe_id(pid: u64, fd_num: usize) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd_num))
        .and_then(|f| f.as_ref())
        .map(|f| f.inode)
        .unwrap_or(0)
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
        Err(e) => -(e as i64),
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
    // The user RSP at syscall entry (saved by the CPU before we switched
    // stacks) is in SYSCALL_USER_RSP.  After the handler's `ret` popped
    // the restorer and the trampoline issued `syscall`, RSP points at the
    // SignalFrame.sig_num field (restorer was consumed by ret).
    let user_rsp = unsafe { SYSCALL_USER_RSP };

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
    // SYSCALL_KERNEL_RSP:
    //   ksp - 8  = user RSP
    //   ksp - 16 = RCX (user RIP)
    //   ksp - 24 = R11 (user RFLAGS)
    //   ksp - 32 = RBP
    //   ksp - 40 = RBX
    //   ksp - 48 = R12
    //   ksp - 56 = R13
    //   ksp - 64 = R14
    //   ksp - 72 = R15
    let ksp = unsafe { SYSCALL_KERNEL_RSP };
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
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid).map(|p| p.linux_abi).unwrap_or(false)
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

/// Dispatch a Linux x86_64 syscall.
///
/// Maps Linux syscall numbers to AstryxOS handlers, handling differences
/// in argument encoding (e.g., C strings vs ptr+len for paths).
pub fn dispatch_linux(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    crate::serial_println!("[SYSCALL/Linux] #{} ({:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
        num, arg1, arg2, arg3, arg4, arg5);
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
            match crate::vfs::close(pid, fd) {
                Ok(()) => 0,
                Err(e) => -(e as i64),
            }
        }
        // 4: stat(pathname, statbuf)
        4 => sys_stat_linux(arg1, arg2),
        // 5: fstat(fd, statbuf)
        5 => sys_fstat_linux(arg1 as usize, arg2 as *mut u8),
        // 8: lseek(fd, offset, whence)
        8 => sys_lseek(arg1 as usize, arg2 as i64, arg3 as u32),
        // 9: mmap(addr, len, prot, flags, fd, offset)
        9 => sys_mmap(arg1, arg2, arg3 as u32, arg4 as u32, arg5, 0),
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
            let fd = arg1;
            let request = arg2;
            let arg_ptr = arg3 as *mut u8;
            if fd <= 2 {
                crate::drivers::tty::tty_ioctl(request, arg_ptr)
            } else {
                -25 // ENOTTY
            }
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
        // 56: clone (simplified → fork)
        56 => sys_fork(),
        // 57: fork
        57 => sys_fork(),
        // 59: execve(pathname, argv, envp) — pathname is C string
        59 => {
            let path_bytes = read_cstring_from_user(arg1);
            sys_exec(arg1, path_bytes.len() as u64)
        }
        // 60: exit(status)
        60 => {
            crate::serial_println!("[SYSCALL/Linux] exit({})", arg1 as i32);
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
        // 83: mkdir(pathname, mode) — C string
        83 => sys_mkdir_linux(arg1, arg2),
        // 84: rmdir(pathname) — C string
        84 => sys_rmdir_linux(arg1),
        // 87: unlink(pathname) — C string
        87 => sys_unlink_linux(arg1),
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
        // 160: setrlimit(resource, rlim) — stub
        160 => 0,
        // 202: futex(uaddr, futex_op, val, ...)
        202 => sys_futex_linux(arg1, arg2, arg3),
        // 217: getdents64(fd, dirp, count)
        217 => sys_getdents64(arg1, arg2, arg3),
        // 218: set_tid_address(tidptr)
        218 => sys_set_tid_address(arg1),
        // 228: clock_gettime(clockid, tp)
        228 => sys_clock_gettime(arg1, arg2),
        // 231: exit_group(status)
        231 => {
            crate::serial_println!("[SYSCALL/Linux] exit_group({})", arg1 as i32);
            crate::proc::exit_thread(arg1 as i64);
            0
        }
        // 234: tgkill(tgid, tid, sig)
        234 => crate::signal::kill(arg2, arg3 as u8),
        // 257: openat(dirfd, pathname, flags, mode)
        257 => sys_openat(arg1, arg2, arg3, arg4),
        // 262: newfstatat(dirfd, pathname, statbuf, flags)
        262 => sys_newfstatat(arg1, arg2, arg3, arg4),
        // 302: prlimit64(pid, resource, new_limit, old_limit) — stub
        302 => 0,
        // 318: getrandom(buf, buflen, flags)
        318 => sys_getrandom(arg1 as *mut u8, arg2 as usize),
        // 334: rseq(rseq, rseq_len, flags, sig)
        334 => -38, // ENOSYS
        _ => {
            crate::serial_println!("[SYSCALL/Linux] Unknown Linux syscall: {}", num);
            -38 // ENOSYS
        }
    }
}

// ── Linux-ABI syscall wrappers ──────────────────────────────────────────────

/// Linux read(fd, buf, count) — same semantics as AstryxOS read.
fn sys_read_linux(fd: u64, buf: u64, count: u64) -> i64 {
    let buf_ptr = buf as *mut u8;
    let count = count as usize;

    if fd == 0 {
        // stdin
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
            if attempts > 100_000 {
                return 0;
            }
            crate::hal::halt();
        }
    } else if is_pipe_fd(crate::proc::current_pid(), fd as usize) {
        let pipe_id = get_pipe_id(crate::proc::current_pid(), fd as usize);
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };
        match crate::ipc::pipe::pipe_read(pipe_id, buf) {
            Some(n) => n as i64,
            None => -9,
        }
    } else {
        let pid = crate::proc::current_pid();
        match crate::vfs::fd_read(pid, fd as usize, buf_ptr, count) {
            Ok(n) => n as i64,
            Err(_) => -9,
        }
    }
}

/// Linux write(fd, buf, count) — same semantics as AstryxOS write.
fn sys_write_linux(fd: u64, buf: u64, count: u64) -> i64 {
    let buf_ptr = buf as *const u8;
    let count = count as usize;

    if count == 0 { return 0; }

    if fd == 1 || fd == 2 {
        let slice = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
        crate::drivers::tty::TTY0.lock().write(slice);
        count as i64
    } else if is_pipe_fd(crate::proc::current_pid(), fd as usize) {
        let pipe_id = get_pipe_id(crate::proc::current_pid(), fd as usize);
        let slice = unsafe { core::slice::from_raw_parts(buf_ptr, count) };
        match crate::ipc::pipe::pipe_write(pipe_id, slice) {
            Some(n) => n as i64,
            None => -9,
        }
    } else {
        let pid = crate::proc::current_pid();
        match crate::vfs::fd_write(pid, fd as usize, buf_ptr, count) {
            Ok(n) => n as i64,
            Err(_) => -9,
        }
    }
}

/// Linux open(pathname, flags, mode) — pathname is a C string.
fn sys_open_linux(pathname: u64, flags: u64, _mode: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };
    let pid = crate::proc::current_pid();
    match crate::vfs::open(pid, path, flags as u32) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
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
        Err(e) => -(e as i64),
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
            Err(e) => -(e as i64),
        },
        None => -9,
    }
}

/// Linux chdir(pathname) — pathname is a C string.
fn sys_chdir_linux(pathname: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    sys_chdir(path_bytes.as_ptr(), path_bytes.len())
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
pub fn sys_set_tid_address(tidptr: u64) -> i64 {
    let _ = tidptr; // Store for future use (CLONE_CHILD_CLEARTID)
    crate::proc::current_tid() as i64
}

/// clock_gettime(clockid, tp) — Get time from a clock.
///
/// tp points to a struct timespec { u64 tv_sec, u64 tv_nsec }.
pub fn sys_clock_gettime(clk_id: u64, tp: u64) -> i64 {
    let _ = clk_id; // CLOCK_REALTIME=0, CLOCK_MONOTONIC=1 — treat the same
    if tp == 0 {
        return -22; // EINVAL
    }
    let ticks = crate::arch::x86_64::irq::get_ticks();
    // Assuming ~100 Hz timer (PIT default configuration)
    let secs = ticks / 100;
    let nsecs = (ticks % 100) * 10_000_000; // 10ms per tick
    let buf = unsafe { core::slice::from_raw_parts_mut(tp as *mut u8, 16) };
    buf[0..8].copy_from_slice(&secs.to_le_bytes());
    buf[8..16].copy_from_slice(&nsecs.to_le_bytes());
    0
}

/// mprotect(addr, len, prot) — Change protection on memory region.
///
/// Stub: returns 0 (pretend success). Full page-table manipulation deferred.
fn sys_mprotect(_addr: u64, _len: u64, _prot: u64) -> i64 {
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

/// fcntl(fd, cmd, arg) — File descriptor control.
fn sys_fcntl(fd: u64, cmd: u64, _arg: u64) -> i64 {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    match cmd {
        F_DUPFD => sys_dup(fd as usize),
        F_GETFD => 0,
        F_SETFD => 0,
        F_GETFL => 0o2, // O_RDWR
        F_SETFL => 0,
        _ => -22 // EINVAL
    }
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
    let (mount_idx, inode, offset) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let fd_entry = match proc_entry.file_descriptors.get(fd as usize).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return -9,
        };
        (fd_entry.mount_idx, fd_entry.inode, fd_entry.offset)
    };

    // Read directory entries from VFS
    let entries = {
        let mounts = crate::vfs::MOUNTS.lock();
        match mounts.get(mount_idx) {
            Some(m) => match m.fs.readdir(inode) {
                Ok(e) => e,
                Err(e) => return -(e as i64),
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

/// openat(dirfd, pathname, flags, mode) — Open file relative to directory fd.
fn sys_openat(dirfd: u64, pathname: u64, flags: u64, mode: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    if dirfd as i64 == AT_FDCWD {
        return sys_open_linux(pathname, flags, mode);
    }
    -22 // EINVAL
}

/// newfstatat(dirfd, pathname, statbuf, flags) — stat relative to directory fd.
fn sys_newfstatat(dirfd: u64, pathname: u64, statbuf: u64, _flags: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    if dirfd as i64 == AT_FDCWD || pathname != 0 {
        let path_bytes = read_cstring_from_user(pathname);
        if path_bytes.is_empty() {
            return sys_fstat_linux(dirfd as usize, statbuf as *mut u8);
        }
        return sys_stat_linux(pathname, statbuf);
    }
    sys_fstat_linux(dirfd as usize, statbuf as *mut u8)
}

/// rt_sigaction for Linux ABI.
///
/// Linux struct kernel_sigaction:
///   sa_handler: u64, sa_flags: u64, sa_restorer: u64, sa_mask: [u64; 1]
fn sys_rt_sigaction_linux(sig: u64, act: u64, oldact: u64, _sigsetsize: u64) -> i64 {
    use crate::signal::{SigAction, SIGKILL, SIGSTOP, MAX_SIGNAL};

    const SA_RESTORER: u64 = 0x04000000;

    let sig = sig as u8;
    if sig == 0 || sig >= MAX_SIGNAL || sig == SIGKILL || sig == SIGSTOP {
        return -22;
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

/// futex — Wait/Wake implementation for musl/pthread compatibility.
///
/// FUTEX_WAIT(0): if *uaddr == val, block the calling thread until woken.
/// FUTEX_WAKE(1): wake up to val waiters blocked on uaddr.
fn sys_futex_linux(uaddr: u64, futex_op: u64, val: u64) -> i64 {
    let op = futex_op & 0x7F; // Mask out FUTEX_PRIVATE_FLAG
    let pid = crate::proc::current_pid();

    match op {
        0 => {
            // FUTEX_WAIT: if *uaddr == val, block until woken
            let current = match unsafe { user_read_u32(uaddr) } {
                Some(v) => v,
                None => return -14, // EFAULT
            };
            if current as u64 != val {
                return -11; // EAGAIN — value changed
            }

            // Add ourselves to the wait queue.
            let tid = crate::proc::current_tid();
            {
                let mut waiters = FUTEX_WAITERS.lock();
                waiters.entry((pid, uaddr)).or_insert_with(Vec::new).push(tid);
            }

            // Block the thread. We'll be woken by FUTEX_WAKE.
            {
                let mut threads = crate::proc::THREAD_TABLE.lock();
                if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                    t.state = crate::proc::ThreadState::Blocked;
                    t.wake_tick = u64::MAX; // indefinite block
                }
            }
            crate::sched::schedule();

            // When we return here, we've been woken.
            // Clean up: remove ourselves from wait queue (if still there).
            {
                let mut waiters = FUTEX_WAITERS.lock();
                if let Some(list) = waiters.get_mut(&(pid, uaddr)) {
                    list.retain(|&t| t != tid);
                    if list.is_empty() {
                        waiters.remove(&(pid, uaddr));
                    }
                }
            }
            0
        }
        1 => {
            // FUTEX_WAKE: wake up to val waiters
            let mut woken = 0u64;
            let max_wake = if val == 0 { u64::MAX } else { val };

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

            // Wake the threads.
            if !tids_to_wake.is_empty() {
                let mut threads = crate::proc::THREAD_TABLE.lock();
                for &tid in &tids_to_wake {
                    if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                        if t.state == crate::proc::ThreadState::Blocked {
                            t.state = crate::proc::ThreadState::Ready;
                        }
                    }
                }
            }

            woken as i64
        }
        _ => -38, // ENOSYS
    }
}