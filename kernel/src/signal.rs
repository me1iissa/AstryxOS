//! POSIX Signal Handling
//!
//! Provides signal delivery, pending masks, signal action tables, and the
//! signal-delivery trampoline for returning from user-mode signal handlers.

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

// Signal numbers (Linux x86_64 compatible)
pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGSEGV: u8 = 11;
pub const SIGUSR2: u8 = 12;
pub const SIGPIPE: u8 = 13;
pub const SIGALRM: u8 = 14;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGWINCH: u8 = 28;
pub const MAX_SIGNAL: u8 = 32;

/// Virtual address where the signal-return trampoline is mapped for every
/// user-mode process.  The page contains two entry points:
///   offset 0:  AstryxOS sigreturn (syscall 39)
///   offset 16: Linux rt_sigreturn  (syscall 15)
pub const TRAMPOLINE_VADDR: u64 = 0x0000_7FFF_FFFF_F000;

/// Linux ABI trampoline entry is at offset 16 within the trampoline page.
pub const TRAMPOLINE_LINUX_OFFSET: u64 = 16;

/// Physical address of the trampoline page (set once during init).
static TRAMPOLINE_PHYS: AtomicU64 = AtomicU64::new(0);

/// Signal frame pushed onto the user stack when delivering a signal to a
/// user-mode handler.  The handler sees RSP pointing at `restorer` (which
/// acts as its return address).  On `ret`, execution jumps to the trampoline
/// which issues `syscall` with the appropriate sigreturn number.
#[repr(C)]
pub struct SignalFrame {
    pub restorer: u64,      // return address → trampoline
    pub sig_num: u64,       // signal number
    pub saved_mask: u64,    // blocked-signal mask before delivery
    pub saved_rsp: u64,     // original user RSP
    pub saved_r15: u64,
    pub saved_r14: u64,
    pub saved_r13: u64,
    pub saved_r12: u64,
    pub saved_rbx: u64,
    pub saved_rbp: u64,
    pub saved_r11: u64,     // original RFLAGS
    pub saved_rcx: u64,     // original user RIP
    pub saved_rax: u64,     // syscall return value
    pub _pad: u64,          // padding to 14 × 8 = 112 bytes (16-aligned)
}

const _SIGNAL_FRAME_SIZE_CHECK: () = {
    assert!(core::mem::size_of::<SignalFrame>() == 112);
};

/// Default action for a signal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigDefault {
    Terminate,
    Ignore,
    CoreDump,
    Stop,
    Continue,
}

/// What happens when a signal is delivered.
#[derive(Debug, Clone, Copy)]
pub enum SigAction {
    /// Use the default action for this signal.
    Default,
    /// Ignore the signal completely.
    Ignore,
    /// Call a user-mode handler at the given virtual address.
    /// Fields: handler address, restorer address (0 = use kernel trampoline).
    Handler { addr: u64, restorer: u64 },
}

/// Per-process signal state.
pub struct SignalState {
    /// Bitmask of pending signals (bit N = signal N is pending).
    pub pending: u64,
    /// Bitmask of blocked signals.
    pub blocked: u64,
    /// Action table indexed by signal number (0..MAX_SIGNAL).
    pub actions: [SigAction; MAX_SIGNAL as usize],
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            pending: 0,
            blocked: 0,
            actions: [SigAction::Default; MAX_SIGNAL as usize],
        }
    }

    /// Queue a signal (set its pending bit).
    pub fn send(&mut self, sig: u8) {
        if sig > 0 && sig < MAX_SIGNAL {
            self.pending |= 1 << sig;
        }
    }

    /// Dequeue the highest-priority deliverable signal.
    /// Returns the signal number if one is pending and not blocked.
    pub fn dequeue(&mut self) -> Option<u8> {
        let deliverable = self.pending & !self.blocked;
        if deliverable == 0 {
            return None;
        }
        // Find lowest set bit
        let sig = deliverable.trailing_zeros() as u8;
        self.pending &= !(1 << sig);
        Some(sig)
    }

    /// Check if any signal is pending and not blocked.
    pub fn has_pending(&self) -> bool {
        (self.pending & !self.blocked) != 0
    }

    /// Get the default action for a signal.
    pub fn default_action(sig: u8) -> SigDefault {
        match sig {
            SIGCHLD | SIGWINCH | SIGCONT => SigDefault::Ignore,
            SIGSTOP | SIGTSTP => SigDefault::Stop,
            SIGQUIT | SIGILL | SIGABRT | SIGFPE | SIGBUS | SIGSEGV | SIGTRAP => SigDefault::CoreDump,
            _ => SigDefault::Terminate,
        }
    }
}

// ── Trampoline Initialization ───────────────────────────────────────────────

/// Allocate the trampoline physical page and write the signal-return machine
/// code into it.  Must be called once during kernel init (before any user
/// process is created).
pub fn init_trampoline() {
    let phys = crate::mm::pmm::alloc_page()
        .expect("[SIGNAL] Failed to allocate trampoline page");

    // Zero the page first.
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, 4096);
    }

    // Offset 0: AstryxOS sigreturn — `mov rax, 39; syscall; int3`
    let astryx_tramp: [u8; 10] = [
        0x48, 0xc7, 0xc0, 0x27, 0x00, 0x00, 0x00, // mov rax, 39
        0x0f, 0x05,                                  // syscall
        0xcc,                                        // int3 (safety)
    ];

    // Offset 16: Linux rt_sigreturn — `mov rax, 15; syscall; int3`
    let linux_tramp: [u8; 10] = [
        0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // mov rax, 15
        0x0f, 0x05,                                  // syscall
        0xcc,                                        // int3
    ];

    unsafe {
        let base = phys as *mut u8;
        core::ptr::copy_nonoverlapping(astryx_tramp.as_ptr(), base, astryx_tramp.len());
        core::ptr::copy_nonoverlapping(linux_tramp.as_ptr(), base.add(16), linux_tramp.len());
    }

    TRAMPOLINE_PHYS.store(phys, Ordering::Release);
    crate::serial_println!(
        "[SIGNAL] Trampoline page allocated at phys {:#x}, vaddr {:#x}",
        phys, TRAMPOLINE_VADDR
    );
}

/// Return the physical address of the trampoline page (0 if not yet inited).
pub fn trampoline_phys() -> u64 {
    TRAMPOLINE_PHYS.load(Ordering::Acquire)
}

/// Map the signal-return trampoline into a user-mode page table.
///
/// The page is mapped as **user + present + read-only** (no NX — must be
/// executable).  Call this from `create_user_process` and `fork_process`.
pub fn map_trampoline(cr3: u64) {
    let phys = trampoline_phys();
    if phys == 0 {
        // Trampoline not yet initialised (early kernel-mode processes).
        return;
    }

    use crate::mm::vmm::{PAGE_PRESENT, PAGE_USER};
    // Flags: present + user, NOT writable, NOT no-execute (so it's executable).
    let flags = PAGE_PRESENT | PAGE_USER;
    crate::mm::vmm::map_page_in(cr3, TRAMPOLINE_VADDR, phys, flags);
}

// ── Signal Subsystem Init ───────────────────────────────────────────────────

/// Initialize the signal subsystem.
pub fn init() {
    init_trampoline();
    crate::serial_println!("[SIGNAL] Signal subsystem initialized");
}

/// Send a signal to a process by PID.
/// Returns 0 on success, negative errno on failure.
pub fn kill(target_pid: u64, sig: u8) -> i64 {
    if sig == 0 {
        // Signal 0 = check if process exists
        let procs = crate::proc::PROCESS_TABLE.lock();
        return if procs.iter().any(|p| p.pid == target_pid) { 0 } else { -3 }; // ESRCH
    }

    if sig >= MAX_SIGNAL {
        return -22; // EINVAL
    }

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == target_pid) {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    if let Some(ref mut sig_state) = proc.signal_state {
        sig_state.send(sig);
    } else {
        // No signal state — handle default action directly
        match SignalState::default_action(sig) {
            SigDefault::Terminate | SigDefault::CoreDump => {
                proc.state = crate::proc::ProcessState::Zombie;
                proc.exit_code = -(sig as i32);
            }
            _ => {}
        }
    }

    crate::serial_println!("[SIGNAL] kill(pid={}, sig={}) delivered", target_pid, sig);
    0
}

/// Check and deliver pending signals for the current process.
/// Called from the scheduler before returning to user mode.
/// Returns true if a signal was handled (process may have been terminated).
pub fn check_signals() -> bool {
    let pid = crate::proc::current_pid();
    
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return false,
    };

    let sig_state = match proc.signal_state.as_mut() {
        Some(s) => s,
        None => return false,
    };

    let sig = match sig_state.dequeue() {
        Some(s) => s,
        None => return false,
    };

    // SIGKILL and SIGSTOP cannot be caught or ignored
    if sig == SIGKILL {
        proc.state = crate::proc::ProcessState::Zombie;
        proc.exit_code = -(sig as i32);
        crate::serial_println!("[SIGNAL] Process {} killed by SIGKILL", pid);
        drop(procs);
        crate::proc::exit_thread(-(sig as i64));
        return true;
    }

    match sig_state.actions[sig as usize] {
        SigAction::Ignore => {
            // Do nothing
            false
        }
        SigAction::Default => {
            match SignalState::default_action(sig) {
                SigDefault::Terminate | SigDefault::CoreDump => {
                    proc.state = crate::proc::ProcessState::Zombie;
                    proc.exit_code = -(sig as i32);
                    crate::serial_println!("[SIGNAL] Process {} terminated by signal {}", pid, sig);
                    drop(procs);
                    crate::proc::exit_thread(-(sig as i64));
                    true
                }
                SigDefault::Stop => {
                    proc.state = crate::proc::ProcessState::Waiting;
                    crate::serial_println!("[SIGNAL] Process {} stopped by signal {}", pid, sig);
                    true
                }
                SigDefault::Continue => {
                    if proc.state == crate::proc::ProcessState::Waiting {
                        proc.state = crate::proc::ProcessState::Active;
                    }
                    false
                }
                SigDefault::Ignore => false,
            }
        }
        SigAction::Handler { .. } => {
            // Handler delivery is done by signal_check_on_syscall_return().
            // If we reach here (called from scheduler), just log and skip.
            crate::serial_println!("[SIGNAL] Process {} has handler for signal {} (delivery via syscall return path)", pid, sig);
            // Re-queue the signal so the syscall-return path can pick it up.
            sig_state.send(sig);
            false
        }
    }
}

// ── Signal Delivery on Syscall Return ───────────────────────────────────────

/// Called from the `syscall_entry` assembly stub after `dispatch()` returns.
///
/// `frame` points to the saved register state on the kernel stack:
///
/// ```text
/// frame[0]  = saved RAX (syscall result, pushed by asm)
/// frame[1]  = saved RDX (user rdx — kept on stack past signal_check)
/// frame[2]  = saved R8  (user r8)
/// frame[3]  = saved R9  (user r9)
/// frame[4]  = saved R10 (user r10)
/// frame[5]  = saved R15
/// frame[6]  = saved R14
/// frame[7]  = saved R13
/// frame[8]  = saved R12
/// frame[9]  = saved RBX
/// frame[10] = saved RBP
/// frame[11] = saved R11 (RFLAGS)
/// frame[12] = saved RCX (user RIP)
/// frame[13] = saved user RSP
/// ```
///
/// If a pending signal has a user handler, this function builds a `SignalFrame`
/// on the user stack and rewrites `frame[12]` (RIP → handler) and `frame[13]`
/// (RSP → signal frame).
///
/// Returns the signal number (> 0) when a handler was delivered so the asm
/// stub can place it in RDI.  Returns 0 when no signal was delivered.
#[no_mangle]
pub extern "C" fn signal_check_on_syscall_return(frame: *mut u64) -> u64 {
    let pid = crate::proc::current_pid();

    // Fast path: most syscalls have no pending signals.
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc_entry = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return 0,
    };

    let is_linux = proc_entry.linux_abi
        || proc_entry.subsystem == crate::win32::SubsystemType::Linux;

    let sig_state = match proc_entry.signal_state.as_mut() {
        Some(s) => s,
        None => return 0,
    };

    if !sig_state.has_pending() {
        return 0;
    }

    let sig = match sig_state.dequeue() {
        Some(s) => s,
        None => return 0,
    };

    // SIGKILL — terminate immediately.
    if sig == SIGKILL {
        proc_entry.state = crate::proc::ProcessState::Zombie;
        proc_entry.exit_code = -(sig as i32);
        crate::serial_println!("[SIGNAL] Process {} killed by SIGKILL (syscall return)", pid);
        drop(procs);
        crate::proc::exit_thread(-(sig as i64));
        return 0; // unreachable
    }

    let action = sig_state.actions[sig as usize];

    match action {
        SigAction::Ignore => 0,
        SigAction::Default => {
            match SignalState::default_action(sig) {
                SigDefault::Terminate | SigDefault::CoreDump => {
                    proc_entry.state = crate::proc::ProcessState::Zombie;
                    proc_entry.exit_code = -(sig as i32);
                    crate::serial_println!(
                        "[SIGNAL] Process {} terminated by signal {} (syscall return)",
                        pid, sig
                    );
                    drop(procs);
                    crate::proc::exit_thread(-(sig as i64));
                    0
                }
                SigDefault::Stop => {
                    proc_entry.state = crate::proc::ProcessState::Waiting;
                    0
                }
                SigDefault::Continue => {
                    if proc_entry.state == crate::proc::ProcessState::Waiting {
                        proc_entry.state = crate::proc::ProcessState::Active;
                    }
                    0
                }
                SigDefault::Ignore => 0,
            }
        }
        SigAction::Handler { addr: handler_addr, restorer } => {
            // ── Build signal frame on user stack ────────────────────────

            // Read saved context from the kernel stack frame.
            let saved_rax = unsafe { *frame.add(0) };
            let saved_r15 = unsafe { *frame.add(5) };
            let saved_r14 = unsafe { *frame.add(6) };
            let saved_r13 = unsafe { *frame.add(7) };
            let saved_r12 = unsafe { *frame.add(8) };
            let saved_rbx = unsafe { *frame.add(9) };
            let saved_rbp = unsafe { *frame.add(10) };
            let saved_r11 = unsafe { *frame.add(11) };
            let saved_rcx = unsafe { *frame.add(12) };
            let saved_rsp = unsafe { *frame.add(13) };
            let saved_mask = sig_state.blocked;

            // Determine the restorer (trampoline) address.
            let restorer_addr = if restorer != 0 {
                restorer
            } else if is_linux {
                TRAMPOLINE_VADDR + TRAMPOLINE_LINUX_OFFSET
            } else {
                TRAMPOLINE_VADDR
            };

            // Compute new user RSP for the signal frame.
            // SignalFrame is 112 bytes (14 × 8).  We want the handler to
            // enter with RSP ≡ 8 (mod 16) — standard "just called" ABI.
            let frame_size = core::mem::size_of::<SignalFrame>() as u64; // 112
            let new_rsp = (saved_rsp - frame_size) & !0xFu64;
            // new_rsp is 16-aligned.  Subtract 8 so RSP % 16 == 8.
            let new_rsp = new_rsp.wrapping_sub(8);
            // Ensure the frame fits (new_rsp + frame_size <= saved_rsp).

            // Write the signal frame to user memory.
            let sig_frame_ptr = new_rsp as *mut SignalFrame;
            unsafe {
                (*sig_frame_ptr).restorer  = restorer_addr;
                (*sig_frame_ptr).sig_num   = sig as u64;
                (*sig_frame_ptr).saved_mask = saved_mask;
                (*sig_frame_ptr).saved_rsp = saved_rsp;
                (*sig_frame_ptr).saved_r15 = saved_r15;
                (*sig_frame_ptr).saved_r14 = saved_r14;
                (*sig_frame_ptr).saved_r13 = saved_r13;
                (*sig_frame_ptr).saved_r12 = saved_r12;
                (*sig_frame_ptr).saved_rbx = saved_rbx;
                (*sig_frame_ptr).saved_rbp = saved_rbp;
                (*sig_frame_ptr).saved_r11 = saved_r11;
                (*sig_frame_ptr).saved_rcx = saved_rcx;
                (*sig_frame_ptr).saved_rax = saved_rax;
                (*sig_frame_ptr)._pad      = 0;
            }

            // Rewrite the kernel stack frame so sysretq enters the handler.
            unsafe {
                *frame.add(12) = handler_addr; // RCX → handler RIP
                *frame.add(13) = new_rsp;      // user RSP → signal frame
            }

            // Block the current signal during handler execution.
            sig_state.blocked |= 1u64 << sig;
            // SIGKILL/SIGSTOP can never be blocked.
            sig_state.blocked &= !((1u64 << SIGKILL) | (1u64 << SIGSTOP));

            crate::serial_println!(
                "[SIGNAL] Delivering signal {} to PID {} handler={:#x} frame={:#x}",
                sig, pid, handler_addr, new_rsp
            );

            sig as u64
        }
    }
}
