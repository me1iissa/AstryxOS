//! AstryxOS Userspace Syscall Library
//!
//! Provides raw syscall wrappers for user-mode programs running on AstryxOS.
//! Uses the `syscall` instruction with the Linux-like ABI:
//!   - `rax` = syscall number
//!   - `rdi` = arg1, `rsi` = arg2, `rdx` = arg3, `r10` = arg4, `r8` = arg5
//!   - Return value in `rax`
//!
//! # Syscall Numbers
//! ```text
//! SYS_EXIT    = 0    SYS_WRITE   = 1    SYS_READ    = 2
//! SYS_OPEN    = 3    SYS_CLOSE   = 4    SYS_FORK    = 5
//! SYS_EXEC    = 6    SYS_WAITPID = 7    SYS_GETPID  = 8
//! SYS_MMAP    = 9    SYS_MUNMAP  = 10   SYS_BRK     = 11
//! SYS_IOCTL   = 12   SYS_YIELD   = 13
//! ```
//!
//! # Note
//! This crate requires `#![no_std]` and a custom freestanding target.
//! Currently these programs are cross-compiled by hand into ELF binaries
//! embedded in the kernel. This source serves as reference documentation.

#![no_std]

use core::arch::asm;

pub const SYS_EXIT: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_READ: u64 = 2;
pub const SYS_OPEN: u64 = 3;
pub const SYS_CLOSE: u64 = 4;
pub const SYS_FORK: u64 = 5;
pub const SYS_EXEC: u64 = 6;
pub const SYS_WAITPID: u64 = 7;
pub const SYS_GETPID: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MUNMAP: u64 = 10;
pub const SYS_BRK: u64 = 11;
pub const SYS_IOCTL: u64 = 12;
pub const SYS_YIELD: u64 = 13;

// ── Extended AstryxOS syscalls ──────────────────────────────────────────
pub const SYS_GETPPID: u64 = 14;
pub const SYS_GETCWD: u64 = 15;
pub const SYS_CHDIR: u64 = 16;
pub const SYS_MKDIR: u64 = 17;
pub const SYS_RMDIR: u64 = 18;
pub const SYS_STAT: u64 = 19;
pub const SYS_FSTAT: u64 = 20;
pub const SYS_LSEEK: u64 = 21;
pub const SYS_DUP: u64 = 22;
pub const SYS_DUP2: u64 = 23;
pub const SYS_PIPE: u64 = 24;
pub const SYS_UNAME: u64 = 25;
pub const SYS_NANOSLEEP: u64 = 26;
pub const SYS_GETUID: u64 = 27;
pub const SYS_GETGID: u64 = 28;
pub const SYS_GETEUID: u64 = 29;
pub const SYS_GETEGID: u64 = 30;
pub const SYS_UMASK: u64 = 31;
pub const SYS_CHMOD: u64 = 32;
pub const SYS_CHOWN: u64 = 33;
pub const SYS_UNLINK: u64 = 34;
pub const SYS_GETRANDOM: u64 = 35;
pub const SYS_KILL: u64 = 36;
pub const SYS_SIGACTION: u64 = 37;
pub const SYS_SIGPROCMASK: u64 = 38;
pub const SYS_SIGRETURN: u64 = 39;
pub const SYS_SOCKET: u64 = 40;
pub const SYS_BIND: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_SENDTO: u64 = 43;
pub const SYS_RECVFROM: u64 = 44;
pub const SYS_LISTEN: u64 = 45;
pub const SYS_ACCEPT: u64 = 46;
pub const SYS_CLONE: u64 = 47;
pub const SYS_FUTEX: u64 = 48;
pub const SYS_SYNC: u64 = 49;

/// Linux x86_64 syscall numbers (for musl-libc compatibility).
///
/// When a process has `linux_abi = true`, the kernel dispatches syscalls
/// using these numbers instead of the AstryxOS numbers above.
pub mod linux {
    pub const SYS_READ: u64 = 0;
    pub const SYS_WRITE: u64 = 1;
    pub const SYS_OPEN: u64 = 2;
    pub const SYS_CLOSE: u64 = 3;
    pub const SYS_STAT: u64 = 4;
    pub const SYS_FSTAT: u64 = 5;
    pub const SYS_LSEEK: u64 = 8;
    pub const SYS_MMAP: u64 = 9;
    pub const SYS_MPROTECT: u64 = 10;
    pub const SYS_MUNMAP: u64 = 11;
    pub const SYS_BRK: u64 = 12;
    pub const SYS_RT_SIGACTION: u64 = 13;
    pub const SYS_RT_SIGPROCMASK: u64 = 14;
    pub const SYS_RT_SIGRETURN: u64 = 15;
    pub const SYS_IOCTL: u64 = 16;
    pub const SYS_WRITEV: u64 = 20;
    pub const SYS_ACCESS: u64 = 21;
    pub const SYS_SCHED_YIELD: u64 = 24;
    pub const SYS_GETPID: u64 = 39;
    pub const SYS_CLONE: u64 = 56;
    pub const SYS_FORK: u64 = 57;
    pub const SYS_EXECVE: u64 = 59;
    pub const SYS_EXIT: u64 = 60;
    pub const SYS_WAIT4: u64 = 61;
    pub const SYS_KILL: u64 = 62;
    pub const SYS_FCNTL: u64 = 72;
    pub const SYS_GETCWD: u64 = 79;
    pub const SYS_CHDIR: u64 = 80;
    pub const SYS_MKDIR: u64 = 83;
    pub const SYS_RMDIR: u64 = 84;
    pub const SYS_UNLINK: u64 = 87;
    pub const SYS_GETTIMEOFDAY: u64 = 96;
    pub const SYS_GETUID: u64 = 102;
    pub const SYS_GETGID: u64 = 104;
    pub const SYS_GETEUID: u64 = 107;
    pub const SYS_GETEGID: u64 = 108;
    pub const SYS_GETPPID: u64 = 110;
    pub const SYS_SIGALTSTACK: u64 = 131;
    pub const SYS_ARCH_PRCTL: u64 = 158;
    pub const SYS_SETRLIMIT: u64 = 160;
    pub const SYS_FUTEX: u64 = 202;
    pub const SYS_GETDENTS64: u64 = 217;
    pub const SYS_SET_TID_ADDRESS: u64 = 218;
    pub const SYS_CLOCK_GETTIME: u64 = 228;
    pub const SYS_EXIT_GROUP: u64 = 231;
    pub const SYS_TGKILL: u64 = 234;
    pub const SYS_OPENAT: u64 = 257;
    pub const SYS_NEWFSTATAT: u64 = 262;
    pub const SYS_PRLIMIT64: u64 = 302;
    pub const SYS_GETRANDOM: u64 = 318;
    pub const SYS_RSEQ: u64 = 334;
}

/// Perform a raw syscall with 0 arguments.
#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    ret
}

/// Perform a raw syscall with 1 argument.
#[inline(always)]
pub unsafe fn syscall1(nr: u64, arg1: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    ret
}

/// Perform a raw syscall with 2 arguments.
#[inline(always)]
pub unsafe fn syscall2(nr: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    ret
}

/// Perform a raw syscall with 3 arguments.
#[inline(always)]
pub unsafe fn syscall3(nr: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    ret
}

/// Perform a raw syscall with 4 arguments.
#[inline(always)]
pub unsafe fn syscall4(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    ret
}

/// Perform a raw syscall with 5 arguments.
#[inline(always)]
pub unsafe fn syscall5(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        in("r8") arg5,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    ret
}

// ── High-level wrappers ────────────────────────────────────────────────

/// Terminate the current process with the given exit code.
pub fn exit(code: u64) -> ! {
    unsafe { syscall1(SYS_EXIT, code); }
    // Should never return, but just in case:
    loop { unsafe { asm!("hlt"); } }
}

/// Write `count` bytes from `buf` to file descriptor `fd`.
pub fn write(fd: u64, buf: *const u8, count: u64) -> u64 {
    unsafe { syscall3(SYS_WRITE, fd, buf as u64, count) }
}

/// Read up to `count` bytes from file descriptor `fd` into `buf`.
pub fn read(fd: u64, buf: *mut u8, count: u64) -> u64 {
    unsafe { syscall3(SYS_READ, fd, buf as u64, count) }
}

/// Get the current process ID.
pub fn getpid() -> u64 {
    unsafe { syscall0(SYS_GETPID) }
}

/// Yield the CPU to the scheduler.
pub fn yield_cpu() {
    unsafe { syscall0(SYS_YIELD); }
}

/// Fork the current process. Returns 0 in child, child PID in parent.
pub fn fork() -> u64 {
    unsafe { syscall0(SYS_FORK) }
}

/// Wait for a child process. Returns the PID that exited.
pub fn waitpid(pid: i64, status_ptr: *mut u64, options: u64) -> u64 {
    unsafe { syscall3(SYS_WAITPID, pid as u64, status_ptr as u64, options) }
}

/// Open a file (AstryxOS ABI: path_ptr + path_len + flags).
pub fn open(path_ptr: *const u8, path_len: u64, flags: u64) -> u64 {
    unsafe { syscall3(SYS_OPEN, path_ptr as u64, path_len, flags) }
}

/// Close a file descriptor.
pub fn close(fd: u64) -> u64 {
    unsafe { syscall1(SYS_CLOSE, fd) }
}

/// Get the parent process ID.
pub fn getppid() -> u64 {
    unsafe { syscall0(SYS_GETPPID) }
}

/// Get the current working directory.
pub fn getcwd(buf: *mut u8, size: u64) -> u64 {
    unsafe { syscall2(SYS_GETCWD, buf as u64, size) }
}

/// Request random bytes.
pub fn getrandom(buf: *mut u8, count: u64) -> u64 {
    unsafe { syscall2(SYS_GETRANDOM, buf as u64, count) }
}

/// Adjust the program break (heap end).
pub fn brk(new_brk: u64) -> u64 {
    unsafe { syscall1(SYS_BRK, new_brk) }
}

/// Map anonymous memory.
pub fn mmap(addr: u64, length: u64, prot: u64, flags: u64) -> u64 {
    unsafe { syscall4(SYS_MMAP, addr, length, prot, flags) }
}

/// Unmap memory.
pub fn munmap(addr: u64, length: u64) -> u64 {
    unsafe { syscall2(SYS_MUNMAP, addr, length) }
}

/// Sleep for a given number of milliseconds.
pub fn nanosleep(millis: u64) -> u64 {
    unsafe { syscall1(SYS_NANOSLEEP, millis) }
}
