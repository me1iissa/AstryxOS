//! User-mode (Ring 3) Transition Support
//!
//! Provides primitives for:
//! - Creating user-mode processes from ELF binaries
//! - Transitioning from kernel mode (Ring 0) to user mode (Ring 3)
//! - The kernel-side bootstrap that runs when a user thread is first scheduled
//!
//! # Architecture
//! User-mode entry is via IRETQ (pushes SS, RSP, RFLAGS, CS, RIP and pops them
//! atomically, switching privilege level). Return from user mode is via SYSCALL
//! (handled by syscall_entry) or interrupts (handled via IDT + TSS.rsp[0]).

extern crate alloc;
use crate::arch::x86_64::gdt;
use crate::proc::{self, elf, PROCESS_TABLE, THREAD_TABLE};
use core::arch::asm;

/// Create a user-mode thread in an existing process (for clone(CLONE_THREAD)).
///
/// Allocates a kernel stack, starts the thread at `user_mode_bootstrap`,
/// which will IRETQ to `user_rip` with RSP = `user_rsp` and FS.base = `tls`
/// (if `tls != 0`).
///
/// Returns the new thread's TID on success.
pub fn create_user_thread(
    pid: proc::Pid,
    user_rip: u64,
    user_rsp: u64,
    tls: u64,
) -> Option<proc::Tid> {
    // Create the thread as Blocked so the scheduler cannot run it before
    // user_entry_rip / user_entry_rsp / tls_base are set.
    let tid = proc::create_thread_blocked(pid, "clone-child", user_mode_bootstrap as *const () as u64)?;

    let cr3 = {
        let procs = PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)?.cr3
    };

    // Populate the run-time fields and mark the thread Ready in one lock region.
    {
        let mut threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.user_entry_rip = user_rip;
            t.user_entry_rsp = user_rsp;
            t.tls_base       = tls;
            t.context.cr3    = cr3;
            t.state          = proc::ThreadState::Ready; // safe to schedule now
        }
    }

    crate::serial_println!(
        "[USER] Created clone thread TID {} in PID {}: RIP={:#x} RSP={:#x} TLS={:#x}",
        tid, pid, user_rip, user_rsp, tls
    );
    Some(tid)
}

/// Create a user-mode process from an ELF binary.
///
/// This parses the ELF, creates a per-process page table via VmSpace::new_user(),
/// maps PT_LOAD segments with PAGE_USER into the new address space, allocates a
/// user stack, and creates a kernel thread whose entry is `user_mode_bootstrap`.
/// When scheduled, the thread transitions to Ring 3 via IRETQ.
///
/// Returns the PID on success.
pub fn create_user_process(name: &str, elf_data: &[u8]) -> Result<proc::Pid, elf::ElfError> {
    create_user_process_with_args(name, elf_data, &[name], &["HOME=/", "PATH=/bin:/disk/bin"])
}

/// Like `create_user_process` but passes explicit `argv` and `envp` to the
/// new process's initial stack (System V AMD64 ABI layout).
///
/// The thread is immediately marked Ready so the scheduler can run it.
pub fn create_user_process_with_args(
    name: &str,
    elf_data: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<proc::Pid, elf::ElfError> {
    create_user_process_impl(name, elf_data, argv, envp, true)
}

/// Like `create_user_process_with_args` but leaves the initial thread
/// in `Blocked` state so the caller can perform setup (e.g. attaching pipe
/// fds) before the process can be scheduled.
///
/// Call `proc::unblock_process(pid)` when ready to allow scheduling.
pub fn create_user_process_with_args_blocked(
    name: &str,
    elf_data: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<proc::Pid, elf::ElfError> {
    create_user_process_impl(name, elf_data, argv, envp, false)
}

fn create_user_process_impl(
    name: &str,
    elf_data: &[u8],
    argv: &[&str],
    envp: &[&str],
    start_ready: bool,
) -> Result<proc::Pid, elf::ElfError> {
    crate::serial_println!("[USER] Loading ELF binary '{}' ({} bytes)", name, elf_data.len());

    // Create a fresh user address space with its own PML4.
    let mut vm_space = crate::mm::vma::VmSpace::new_user()
        .ok_or(elf::ElfError::OutOfMemory)?;


    // Load ELF into the new page table with the provided argv/envp.
    let result = elf::load_elf_with_args(elf_data, vm_space.cr3, argv, envp)?;

    crate::serial_println!(
        "[USER] ELF loaded: entry={:#x}, stack={:#x}, range={:#x}-{:#x}, {} pages, {} VMAs",
        result.entry_point, result.user_stack_ptr,
        result.load_base, result.load_end,
        result.allocated_pages.len(), result.vmas.len()
    );

    // Insert VMAs into the VmSpace.
    for vma in result.vmas {
        let _ = vm_space.insert_vma(vma);
    }

    let user_cr3 = vm_space.cr3;
    let entry_rip = result.entry_point;
    let entry_rsp = result.user_stack_ptr;

    // Map the signal-return trampoline into the new address space.
    crate::signal::map_trampoline(user_cr3);

    // Create the process with its thread initially Blocked so no AP can
    // schedule it before we patch in the correct RIP/RSP/CR3.
    let pid = proc::create_kernel_process_suspended(name, user_mode_bootstrap as *const () as u64);

    // Patch the process with our per-process page table and exe path.
    // Set linux_abi HERE (before the thread is marked Ready) to eliminate
    // the race where the AP schedules the thread before the caller can set it.
    {
        let mut procs = PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.cr3 = user_cr3;
            p.vm_space = Some(vm_space);
            p.exe_path = Some(alloc::string::String::from(name));
            p.linux_abi = true;
            p.subsystem = crate::win32::SubsystemType::Linux;
        }
    }

    // Patch the thread's user-mode entry info and CR3.
    // Mark Ready only if start_ready — callers that need post-spawn setup
    // (e.g. pipe attachment) pass false and call unblock_process() later.
    {
        let mut threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.pid == pid) {
            t.user_entry_rip = entry_rip;
            t.user_entry_rsp = entry_rsp;
            t.context.cr3 = user_cr3;
            // Set initial FS.base from PT_TLS (0 = no TLS segment).
            if result.tls_base != 0 {
                t.tls_base = result.tls_base;
            }
            // Mark first_run so schedule() withholds the CR3 switch until
            // user_mode_bootstrap() explicitly switches to the user CR3.
            // Without this, schedule() switches CR3 before switch_context,
            // but the new kernel stack may not be mapped in the user PML4.
            t.first_run = true;
            if start_ready {
                t.state = proc::ThreadState::Ready;
            }
            // else: remains Blocked — caller owns the Ready transition
        }
    }

    crate::serial_println!(
        "[USER] Process '{}' PID {} {} (cr3={:#x}, {} physical pages)",
        name, pid,
        if start_ready { "ready for Ring 3" } else { "suspended (blocked)" },
        user_cr3, result.allocated_pages.len()
    );

    Ok(pid)
}

/// Bootstrap function for user-mode threads.
///
/// This runs in Ring 0 on the thread's kernel stack when the thread is
/// first scheduled. It:
/// 1. Reads the user-mode entry point and stack pointer from the thread struct.
/// 2. Switches to the per-process page table (CR3).
/// 3. Configures TSS.rsp[0] and SYSCALL_KERNEL_RSP for Ring 3 → Ring 0 transitions.
/// 4. Performs IRETQ to enter Ring 3.
fn user_mode_bootstrap() {
    crate::serial_println!("[BOOT] tid={} entering bootstrap", crate::proc::current_tid());

    // Clear first_run immediately so that if this thread is ever re-scheduled
    // (after returning from user mode via a future syscall exit path), schedule()
    // will correctly switch CR3 for it. This also pairs with the first_run guard
    // in schedule() that skipped the premature CR3 switch on our first dispatch.
    {
        let tid = proc::current_tid();
        let mut threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.first_run = false;
        }
    }

    let (entry_rip, entry_rsp, kernel_stack_top, user_cr3, tls_base) = {
        let tid = proc::current_tid();
        let threads = THREAD_TABLE.lock();
        let thread = threads.iter().find(|t| t.tid == tid)
            .expect("bootstrap: current thread not found");
        (
            thread.user_entry_rip,
            thread.user_entry_rsp,
            thread.kernel_stack_base + thread.kernel_stack_size,
            thread.context.cr3,
            thread.tls_base,
        )
    };

    crate::serial_println!(
        "[USER] Bootstrap: entering Ring 3 at RIP={:#x}, RSP={:#x}, CR3={:#x}",
        entry_rip, entry_rsp, user_cr3
    );

    // Switch to the per-process page table.
    let current_cr3 = crate::mm::vmm::get_cr3();
    if user_cr3 != 0 && user_cr3 != current_cr3 {
        unsafe { crate::mm::vmm::switch_cr3(user_cr3); }
    }

    // Set kernel stack for Ring 3 → Ring 0 transitions.
    unsafe {
        gdt::update_tss_rsp0(kernel_stack_top);
        crate::syscall::set_kernel_rsp(kernel_stack_top);
    }

    // Set per-thread TLS (FS.base) if assigned (clone(CLONE_SETTLS) or arch_prctl).
    if tls_base != 0 {
        unsafe { proc::write_fs_base(tls_base); }
    }

    // Jump to user mode via IRETQ. This never returns.
    unsafe { jump_to_user_mode(entry_rip, entry_rsp); }
}

/// Transition to user mode (Ring 3) via IRETQ.
///
/// Pushes an interrupt return frame onto the current stack and executes
/// IRETQ to atomically switch to Ring 3 with the given RIP and RSP.
///
/// # Safety
/// - `entry_rip` must point to valid, executable, Ring 3-accessible code.
/// - `entry_rsp` must point to a valid, Ring 3-accessible stack.
/// - This function never returns.
#[inline(never)]
pub unsafe fn jump_to_user_mode(entry_rip: u64, entry_rsp: u64) -> ! {
    asm!(
        // Build IRETQ frame on current (kernel) stack:
        //   [RSP+32] SS
        //   [RSP+24] RSP (user)
        //   [RSP+16] RFLAGS
        //   [RSP+8]  CS
        //   [RSP+0]  RIP (user)
        "push {ss}",       // SS = USER_DATA_SELECTOR (0x1B)
        "push {rsp_val}",  // RSP = user stack pointer
        "push {rflags}",   // RFLAGS = 0x202 (IF set, IOPL=0)
        "push {cs}",       // CS = USER_CODE_SELECTOR (0x23)
        "push {rip_val}",  // RIP = entry point
        // RAX = 0 on Ring 3 entry. Required for clone() children (syscall return
        // value must be 0 in child). Harmless for static binary _start.
        "xor eax, eax",
        "iretq",
        ss = in(reg) gdt::USER_DATA_SELECTOR as u64,
        rsp_val = in(reg) entry_rsp,
        rflags = in(reg) 0x202u64,
        cs = in(reg) gdt::USER_CODE_SELECTOR as u64,
        rip_val = in(reg) entry_rip,
        options(noreturn)
    );
}
