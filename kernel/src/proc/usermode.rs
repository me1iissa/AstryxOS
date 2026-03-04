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

use crate::arch::x86_64::gdt;
use crate::proc::{self, elf, PROCESS_TABLE, THREAD_TABLE};
use core::arch::asm;

/// Create a user-mode process from an ELF binary.
///
/// This parses the ELF, creates a per-process page table via VmSpace::new_user(),
/// maps PT_LOAD segments with PAGE_USER into the new address space, allocates a
/// user stack, and creates a kernel thread whose entry is `user_mode_bootstrap`.
/// When scheduled, the thread transitions to Ring 3 via IRETQ.
///
/// Returns the PID on success.
pub fn create_user_process(name: &str, elf_data: &[u8]) -> Result<proc::Pid, elf::ElfError> {
    crate::serial_println!("[USER] Loading ELF binary '{}' ({} bytes)", name, elf_data.len());

    // Create a fresh user address space with its own PML4.
    let mut vm_space = crate::mm::vma::VmSpace::new_user()
        .ok_or(elf::ElfError::OutOfMemory)?;

    // Load ELF into the new page table.
    let result = elf::load_elf(elf_data, vm_space.cr3)?;

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

    // Create a kernel process whose main thread starts at user_mode_bootstrap.
    // Then patch it with our per-process page table and user entry info.
    let pid = proc::create_kernel_process(name, user_mode_bootstrap as *const () as u64);

    // Patch the process with our per-process page table.
    {
        let mut procs = PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.cr3 = user_cr3;
            p.vm_space = Some(vm_space);
        }
    }

    // Store entry point and user RSP in the thread for user_mode_bootstrap to read.
    {
        let mut threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.pid == pid) {
            t.user_entry_rip = entry_rip;
            t.user_entry_rsp = entry_rsp;
            t.context.cr3 = user_cr3;
        }
    }

    crate::serial_println!(
        "[USER] Process '{}' PID {} ready for Ring 3 (cr3={:#x}, {} physical pages)",
        name, pid, user_cr3, result.allocated_pages.len()
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
    let (entry_rip, entry_rsp, kernel_stack_top, user_cr3) = {
        let tid = proc::current_tid();
        let threads = THREAD_TABLE.lock();
        let thread = threads.iter().find(|t| t.tid == tid)
            .expect("bootstrap: current thread not found");
        (
            thread.user_entry_rip,
            thread.user_entry_rsp,
            thread.kernel_stack_base + thread.kernel_stack_size,
            thread.context.cr3,
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

    // Set kernel stack for:
    // - TSS.rsp[0]: CPU loads this on interrupt from Ring 3
    // - SYSCALL_KERNEL_RSP: we load this manually in syscall_entry
    unsafe {
        gdt::update_tss_rsp0(kernel_stack_top);
        crate::syscall::set_kernel_rsp(kernel_stack_top);
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
        "iretq",
        ss = in(reg) gdt::USER_DATA_SELECTOR as u64,
        rsp_val = in(reg) entry_rsp,
        rflags = in(reg) 0x202u64,
        cs = in(reg) gdt::USER_CODE_SELECTOR as u64,
        rip_val = in(reg) entry_rip,
        options(noreturn)
    );
}
