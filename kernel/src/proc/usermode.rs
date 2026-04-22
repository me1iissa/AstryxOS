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
    entry_rdx: u64,
    entry_r8: u64,
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
            t.user_entry_rdx = entry_rdx;
            t.user_entry_r8  = entry_r8;
            t.tls_base       = tls;
            t.context.cr3    = cr3;
            t.state          = proc::ThreadState::Ready; // safe to schedule now
        }
    }

    crate::serial_println!(
        "[USER] Created clone thread TID {} in PID {}: RIP={:#x} RSP={:#x} TLS={:#x} RDX={:#x} R8={:#x}",
        tid, pid, user_rip, user_rsp, tls, entry_rdx, entry_r8
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
            // Store auxv/envp for /proc/self/auxv and /proc/self/environ.
            p.auxv = result.auxv.clone();
            p.envp = envp.iter().map(|s| alloc::string::String::from(*s)).collect();
            // Initialize signal state for Linux user processes.
            // Without this, rt_sigaction returns -1 and signal handlers
            // (SIGSEGV, SIGBUS, etc.) are never installed — processes get
            // killed on first NULL deref instead of invoking their handler.
            if p.signal_state.is_none() {
                p.signal_state = Some(crate::signal::SignalState::new());
            }
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
pub fn user_mode_bootstrap() {
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

    let (entry_rip, entry_rsp, entry_rdx, entry_r8, kernel_stack_top, user_cr3, tls_base, gs_base) = {
        let tid = proc::current_tid();
        let threads = THREAD_TABLE.lock();
        let thread = match threads.iter().find(|t| t.tid == tid) {
            Some(t) => t,
            None => {
                crate::serial_println!("[BOOT] FATAL: tid={} not found in THREAD_TABLE!", tid);
                drop(threads);
                proc::exit_thread(-1);
                loop {} // unreachable
            }
        };
        (
            thread.user_entry_rip,
            thread.user_entry_rsp,
            thread.user_entry_rdx,
            thread.user_entry_r8,
            thread.kernel_stack_base + thread.kernel_stack_size,
            thread.context.cr3,
            thread.tls_base,
            thread.gs_base,
        )
    };

    crate::serial_println!(
        "[USER] Bootstrap tid={}: Ring 3 at RIP={:#x} RSP={:#x} CR3={:#x} RDX={:#x} R8={:#x}",
        proc::current_tid(), entry_rip, entry_rsp, user_cr3, entry_rdx, entry_r8
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

    // Set GS.base to TEB address for Win32 threads.
    if gs_base != 0 {
        unsafe { proc::write_gs_base(gs_base); }
    }

    // Jump to user mode via IRETQ. This never returns.
    crate::serial_println!(
        "[BOOT] jump_to_user_mode: rip={:#x} rsp={:#x} rdx={:#x} r8={:#x}",
        entry_rip, entry_rsp, entry_rdx, entry_r8);
    unsafe { jump_to_user_mode(entry_rip, entry_rsp, entry_rdx, entry_r8); }
}

/// Transition to user mode (Ring 3) via IRETQ.
///
/// Pushes an interrupt return frame onto the current stack and executes
/// IRETQ to atomically switch to Ring 3 with the given RIP, RSP, RDX, and R8.
///
/// # Safety
/// - `entry_rip` must point to valid, executable, Ring 3-accessible code.
/// - `entry_rsp` must point to a valid, Ring 3-accessible stack.
/// - `entry_rdx` / `entry_r8`: thread function and argument for glibc clone3 children
///   (glibc 2.34+ passes `func` in RDX and `arg` in R8 through the clone3 syscall;
///   set both to 0 for initial processes and clone2-style threads).
/// - This function never returns.
/// Transition to user mode via IRETQ.
///
/// # Arguments
/// RDI = entry_rip, RSI = entry_rsp, RDX = entry_rdx, RCX = entry_r8
///
/// # Safety
/// Must be called with valid user-space RIP/RSP.
#[unsafe(naked)]
pub unsafe extern "C" fn jump_to_user_mode(_entry_rip: u64, _entry_rsp: u64, _entry_rdx: u64, _entry_r8: u64) -> ! {
    core::arch::naked_asm!(
        // Args: rdi=rip, rsi=rsp, rdx=rdx_val, rcx=r8_val
        // Build IRETQ frame
        "push 0x1B",       // SS = USER_DATA_SELECTOR
        "push rsi",        // RSP = user stack pointer (arg2)
        "push 0x202",      // RFLAGS (IF set)
        "push 0x23",       // CS = USER_CODE_SELECTOR
        "push rdi",        // RIP = entry point (arg1)
        // Set R8 from arg4 (rcx), RDX stays as arg3
        "mov r8, rcx",
        // RAX = 0 (fork child return value / harmless for initial process)
        "xor eax, eax",
        // Zero all other GPRs to prevent kernel address leaks
        "xor esi, esi",
        "xor edi, edi",
        "xor ecx, ecx",
        "xor r9d, r9d",
        "xor r10d, r10d",
        "xor r11d, r11d",
        "xor ebx, ebx",
        "xor ebp, ebp",
        "xor r12d, r12d",
        "xor r13d, r13d",
        "xor r14d, r14d",
        "xor r15d, r15d",
        "iretq",
    );
}

/// Create a Win32 user-mode process from a PE32+ binary.
///
/// Allocates a fresh user address space, maps a per-process NT syscall
/// trampoline page at `NT_STUB_PAGE_VA`, builds a minimal TEB at
/// `0x7FFE_F000`, loads the PE image, and starts the initial thread.
///
/// Returns the PID on success.
pub fn create_win32_process(name: &str, pe_data: &[u8]) -> Result<proc::Pid, crate::proc::pe::PeError> {
    crate::serial_println!("[WIN32] Loading PE binary '{}' ({} bytes)", name, pe_data.len());

    // ── 1. Create a fresh user address space ─────────────────────────────────
    let mut vm_space = crate::mm::vma::VmSpace::new_user()
        .ok_or(crate::proc::pe::PeError::MappingFailed)?;
    let user_cr3 = vm_space.cr3;

    // ── 2. Allocate and map the NT stub trampoline page ───────────────────────
    let tramp_phys = crate::mm::pmm::alloc_page()
        .ok_or(crate::proc::pe::PeError::MappingFailed)?;
    // Physical addresses must be accessed via the higher-half PHYS_OFF mapping —
    // the identity map (PML4[0]) may have been modified by earlier user processes.
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    unsafe { core::ptr::write_bytes((PHYS_OFF + tramp_phys) as *mut u8, 0, crate::mm::pmm::PAGE_SIZE); }

    // Write MOV RAX / INT 0x2E / RET stubs for every NT_STUB_TABLE entry.
    unsafe { crate::nt::build_stub_trampoline_page((PHYS_OFF + tramp_phys) as *mut u8); }

    // Map trampoline page at NT_STUB_PAGE_VA as user-readable+executable.
    if !crate::mm::vmm::map_page_in(
        user_cr3,
        crate::nt::NT_STUB_PAGE_VA,
        tramp_phys,
        crate::mm::vmm::PAGE_PRESENT | crate::mm::vmm::PAGE_USER,
        // PAGE_NO_EXECUTE intentionally omitted — trampoline must be executable
    ) {
        return Err(crate::proc::pe::PeError::MappingFailed);
    }

    // Register trampoline VMA.
    let _ = vm_space.insert_vma(crate::mm::vma::VmArea {
        base:    crate::nt::NT_STUB_PAGE_VA,
        length:  crate::mm::pmm::PAGE_SIZE as u64,
        prot:    crate::mm::vma::PROT_READ | crate::mm::vma::PROT_EXEC,
        flags:   crate::mm::vma::MAP_PRIVATE | crate::mm::vma::MAP_ANONYMOUS,
        backing: crate::mm::vma::VmBacking::Anonymous,
        name:    "[nt-trampoline]",
    });

    // ── 3. Allocate a minimal TEB at 0x7FFE_F000 ─────────────────────────────
    const TEB_VA: u64 = 0x7FFE_F000;
    let teb_phys = crate::mm::pmm::alloc_page()
        .ok_or(crate::proc::pe::PeError::MappingFailed)?;
    unsafe { core::ptr::write_bytes((PHYS_OFF + teb_phys) as *mut u8, 0, crate::mm::pmm::PAGE_SIZE); }
    unsafe {
        let teb = (PHYS_OFF + teb_phys) as *mut u64;
        core::ptr::write_unaligned(teb.add(0),  0xFFFF_FFFF_FFFF_FFFFu64); // ExceptionList
        core::ptr::write_unaligned(teb.add(6),  TEB_VA);                   // NT_TIB.Self (+0x30)
        // ClientId.UniqueProcess at +0x68 = index 13
        core::ptr::write_unaligned(teb.add(13), crate::proc::current_pid() as u64);
    }
    if !crate::mm::vmm::map_page_in(
        user_cr3, TEB_VA, teb_phys,
        crate::mm::vmm::PAGE_PRESENT | crate::mm::vmm::PAGE_USER | crate::mm::vmm::PAGE_WRITABLE | crate::mm::vmm::PAGE_NO_EXECUTE,
    ) {
        return Err(crate::proc::pe::PeError::MappingFailed);
    }
    let _ = vm_space.insert_vma(crate::mm::vma::VmArea {
        base:    TEB_VA,
        length:  crate::mm::pmm::PAGE_SIZE as u64,
        prot:    crate::mm::vma::PROT_READ | crate::mm::vma::PROT_WRITE,
        flags:   crate::mm::vma::MAP_PRIVATE | crate::mm::vma::MAP_ANONYMOUS,
        backing: crate::mm::vma::VmBacking::Anonymous,
        name:    "[teb]",
    });
    // ── 4. Load the PE image into the new address space ───────────────────────
    // No CR3 switch needed: load_pe writes all data via PHYS_OFF, same as ELF loader.
    let result = crate::proc::pe::load_pe(pe_data, user_cr3, crate::nt::NT_STUB_PAGE_VA);
    let pe = result?;

    crate::serial_println!(
        "[WIN32] PE loaded: entry={:#x}, stack={:#x}, image_base={:#x}",
        pe.entry_point, pe.stack_top, pe.load_base
    );

    // ── 5. Map signal trampoline (needed for POSIX signals even in Win32) ─────
    crate::signal::map_trampoline(user_cr3);

    // ── 6. Create process ─────────────────────────────────────────────────────
    let pid = proc::create_kernel_process_suspended(name, user_mode_bootstrap as *const () as u64);

    {
        let mut procs = PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.cr3      = user_cr3;
            p.vm_space = Some(vm_space);
            p.exe_path = Some(alloc::string::String::from(name));
            p.linux_abi = false; // Win32 process
            p.subsystem = crate::win32::SubsystemType::Win32;
        }
    }

    {
        let mut threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.pid == pid) {
            t.user_entry_rip = pe.entry_point;
            t.user_entry_rsp = pe.stack_top;
            t.context.cr3    = user_cr3;
            t.gs_base        = TEB_VA; // Win32 convention: GS.base = TEB
            t.first_run      = true;
            t.state          = proc::ThreadState::Ready;
        }
    }

    crate::serial_println!("[WIN32] Process '{}' PID {} ready (cr3={:#x})", name, pid, user_cr3);
    Ok(pid)
}
