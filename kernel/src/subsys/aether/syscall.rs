//! Aether Native Syscall Dispatch
//!
//! Contains the `dispatch()` function for the Aether native ABI
//! (syscall numbers 0–49 defined in `astryx_shared::syscall`).
//!
//! All helper functions (sys_exec, sys_fork, sys_mmap, …) remain in
//! `kernel/src/syscall/mod.rs` as `pub(crate)` items and are reached via
//! `crate::syscall::`.  This keeps the shared-helper code in one place
//! while establishing the clean subsystem-module boundary required by
//! Phase 0.1 of the subsystem split plan.
//!
//! # Phase 0.1 boundary
//! Implementation bodies live here; the forwarding stub in
//! `crate::subsys::aether::dispatch()` delegates to this function.

use astryx_shared::syscall::*;

/// Aether native syscall dispatch.
///
/// Dispatches syscall numbers `0..=49` (plus the `158` arch_prctl fallback)
/// to their AstryxOS native implementations.
pub fn dispatch(
    num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, arg6: u64,
) -> i64 {
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

            let slice = match unsafe { crate::syscall::user_slice(arg2, count) } {
                Some(s) => s,
                None => return -14, // EFAULT
            };

            // Special fd types take priority over fd-number shortcuts
            let pid = crate::proc::current_pid();
            if crate::syscall::is_pipe_fd(pid, fd as usize) {
                let pipe_id = crate::syscall::get_pipe_id(pid, fd as usize);
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

            let buf = match unsafe { crate::syscall::user_slice_mut(arg2, count) } {
                Some(s) => s,
                None => return -14, // EFAULT
            };

            // Special fd types take priority over fd-number shortcuts
            let pid = crate::proc::current_pid();
            if crate::syscall::is_pipe_fd(pid, fd as usize) {
                let pipe_id = crate::syscall::get_pipe_id(pid, fd as usize);
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

            let path = match unsafe { crate::syscall::user_slice(arg1, path_len) } {
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
            crate::syscall::sys_fork()
        }
        SYS_EXEC => {
            // exec(path_ptr, path_len) — Aether ABI has no argv/envp
            crate::syscall::sys_exec(arg1, arg2, 0, 0)
        }
        SYS_WAITPID => {
            // waitpid(pid, options)
            crate::syscall::sys_waitpid(arg1 as i64, arg2 as u32)
        }
        SYS_MMAP => {
            // mmap(addr, length, prot, flags, fd, offset)
            crate::syscall::sys_mmap(arg1, arg2, arg3 as u32, arg4 as u32, arg5, arg6)
        }
        SYS_MUNMAP => {
            // munmap(addr, length)
            crate::syscall::sys_munmap(arg1, arg2)
        }
        SYS_BRK => {
            // brk(new_brk) -> current brk
            crate::syscall::sys_brk(arg1)
        }
        SYS_GETPPID => {
            crate::syscall::sys_getppid()
        }
        SYS_GETCWD => {
            // getcwd(buf, size) -> length or -errno
            crate::syscall::sys_getcwd(arg1 as *mut u8, arg2 as usize)
        }
        SYS_CHDIR => {
            // chdir(path_ptr, path_len) -> 0 or -errno
            crate::syscall::sys_chdir(arg1 as *const u8, arg2 as usize)
        }
        SYS_MKDIR => {
            // mkdir(path_ptr, path_len) -> 0 or -errno
            crate::syscall::sys_mkdir(arg1 as *const u8, arg2 as usize)
        }
        SYS_RMDIR => {
            // rmdir(path_ptr, path_len) -> 0 or -errno
            crate::syscall::sys_rmdir(arg1 as *const u8, arg2 as usize)
        }
        SYS_STAT => {
            // stat(path_ptr, path_len, stat_buf) -> 0 or -errno
            crate::syscall::sys_stat(arg1 as *const u8, arg2 as usize, arg3 as *mut u8)
        }
        SYS_FSTAT => {
            // fstat(fd, stat_buf) -> 0 or -errno
            crate::syscall::sys_fstat(arg1 as usize, arg2 as *mut u8)
        }
        SYS_LSEEK => {
            // lseek(fd, offset, whence) -> new offset or -errno
            crate::syscall::sys_lseek(arg1 as usize, arg2 as i64, arg3 as u32)
        }
        SYS_DUP => {
            // dup(fd) -> new_fd or -errno
            crate::syscall::sys_dup(arg1 as usize)
        }
        SYS_DUP2 => {
            // dup2(oldfd, newfd) -> new_fd or -errno
            crate::syscall::sys_dup2(arg1 as usize, arg2 as usize)
        }
        SYS_PIPE => {
            // pipe(fds_out) -> 0 or -errno
            crate::syscall::sys_pipe(arg1 as *mut u64)
        }
        SYS_UNAME => {
            // uname(buf) -> 0
            crate::syscall::sys_uname(arg1 as *mut u8)
        }
        SYS_NANOSLEEP => {
            // nanosleep(milliseconds) -> 0
            crate::syscall::sys_nanosleep(arg1)
        }
        SYS_GETUID => {
            crate::syscall::sys_getuid()
        }
        SYS_GETGID => {
            crate::syscall::sys_getgid()
        }
        SYS_GETEUID => {
            crate::syscall::sys_geteuid()
        }
        SYS_GETEGID => {
            crate::syscall::sys_getegid()
        }
        SYS_UMASK => {
            // umask(new_mask) -> old_mask
            crate::syscall::sys_umask(arg1 as u32)
        }
        SYS_UNLINK => {
            // unlink(path_ptr, path_len) -> 0 or -errno
            crate::syscall::sys_unlink(arg1 as *const u8, arg2 as usize)
        }
        SYS_GETRANDOM => {
            // getrandom(buf, count) -> count or -errno
            crate::syscall::sys_getrandom(arg1 as *mut u8, arg2 as usize)
        }
        SYS_KILL => {
            // kill(pid, sig) -> 0 or -errno
            crate::signal::kill(arg1, arg2 as u8)
        }
        SYS_SIGACTION => {
            // sigaction(sig, handler_addr) -> 0 or -errno
            // Simplified: arg1 = signal, arg2 = handler address (0 = SIG_DFL, 1 = SIG_IGN)
            crate::syscall::sys_sigaction(arg1 as u8, arg2)
        }
        SYS_SIGPROCMASK => {
            // sigprocmask(how, new_mask) -> old_mask or -errno
            crate::syscall::sys_sigprocmask(arg1 as u32, arg2)
        }
        SYS_SIGRETURN => {
            crate::syscall::sys_sigreturn()
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
            crate::syscall::sys_fork()
        }
        SYS_FUTEX => {
            // futex(uaddr, op, val, timeout_ptr, uaddr2, val3)
            // val3 carries the bitset for FUTEX_WAIT_BITSET/FUTEX_WAKE_BITSET; see futex(2).
            // Aether subsystem currently dispatches without arg6, so pass 0 (== unused for
            // the ops Aether code actually invokes).
            crate::subsys::linux::syscall::sys_futex_linux(arg1, arg2, arg3, arg4, arg5, 0)
        }
        SYS_SYNC => {
            // sync() — flush all dirty filesystem data to disk
            crate::vfs::sync_all();
            0
        }
        // 158: arch_prctl(code, addr) — TLS/FS-base setup.
        // Handled here as a defensive fallback for Linux ELF processes that
        // race through the scheduler before the caller sets linux_abi=true.
        158 => crate::subsys::linux::syscall::sys_arch_prctl(arg1, arg2),
        _ => {
            crate::serial_println!("[SYSCALL] Unknown syscall: {}", num);
            -38 // ENOSYS
        }
    }
}
