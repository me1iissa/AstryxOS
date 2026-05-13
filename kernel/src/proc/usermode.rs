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
    create_user_process_impl(name, elf_data, argv, envp, true, true)
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
    create_user_process_impl(name, elf_data, argv, envp, false, true)
}

/// Create a native AstryxOS (Aether) user-mode process from an ELF binary.
///
/// Unlike `create_user_process`, the resulting process has `linux_abi = false`
/// and `SubsystemType::Aether`, so its syscalls dispatch through
/// `subsys/aether/syscall.rs` and use the small AstryxOS numbering scheme
/// (`SYS_EXIT=0`, `SYS_WRITE=1`, ...).  Use this for binaries built against
/// `userspace/libsys/` — e.g. the QGA daemon (Phase QGA-2).
///
/// The thread is immediately marked Ready so the scheduler can run it.
pub fn create_aether_process(
    name: &str,
    elf_data: &[u8],
) -> Result<proc::Pid, elf::ElfError> {
    create_user_process_impl(
        name,
        elf_data,
        &[name],
        &["HOME=/", "PATH=/bin:/disk/bin"],
        true,   // start_ready
        false,  // linux_abi = false → Aether dispatch
    )
}

fn create_user_process_impl(
    name: &str,
    elf_data: &[u8],
    argv: &[&str],
    envp: &[&str],
    start_ready: bool,
    linux_abi: bool,
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
    // Set linux_abi / subsystem HERE (before the thread is marked Ready) to
    // eliminate the race where the AP schedules the thread before the
    // caller can set it.  Aether-native callers (e.g. the QGA daemon)
    // pass linux_abi=false so syscalls dispatch through
    // `subsys/aether/syscall.rs` with the small AstryxOS numbering.
    {
        let mut procs = PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.cr3 = user_cr3;
            p.vm_space = Some(vm_space);
            p.exe_path = Some(alloc::string::String::from(name));
            p.linux_abi = linux_abi;
            p.subsystem = if linux_abi {
                crate::win32::SubsystemType::Linux
            } else {
                crate::win32::SubsystemType::Aether
            };
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

    let (entry_rip, entry_rsp, entry_rdx, entry_r8, kernel_stack_top, mut user_cr3, tls_base, gs_base, pid, fork_regs) = {
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
            thread.pid,
            // Snapshot fork_user_regs by value while the lock is held; we
            // pass it by pointer below, but copying onto our own stack means
            // the pointer remains valid after the THREAD_TABLE lock drops
            // even if the Vec reallocates.
            thread.fork_user_regs,
        )
    };

    // Defensive: if the thread's context.cr3 was never propagated by the
    // creator (e.g. a future code path creates the thread before the
    // owning process's cr3 is known, or a fork/clone helper forgets to
    // copy it), fall back to the owning process's cr3.  Without this
    // recovery user_mode_bootstrap would IRETQ with stale-or-zero CR3
    // and #PF immediately on the first user instruction.  Persist the
    // value back to the thread so any subsequent re-entry into bootstrap
    // (or schedule()'s CR3 switch) sees a consistent non-zero cr3.
    if user_cr3 == 0 {
        let p_cr3 = {
            let procs = PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid).map(|p| p.cr3).unwrap_or(0)
        };
        if p_cr3 != 0 {
            crate::serial_println!(
                "[BOOT] tid={} pid={}: context.cr3 was 0, propagating from process cr3={:#x}",
                proc::current_tid(), pid, p_cr3
            );
            user_cr3 = p_cr3;
            let tid = proc::current_tid();
            let mut threads = THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                t.context.cr3 = p_cr3;
            }
        }
    }

    crate::serial_println!(
        "[USER] Bootstrap tid={}: Ring 3 at RIP={:#x} RSP={:#x} CR3={:#x} RDX={:#x} R8={:#x}",
        proc::current_tid(), entry_rip, entry_rsp, user_cr3, entry_rdx, entry_r8
    );

    // Switch to the per-process page table.
    let current_cr3 = crate::mm::vmm::get_cr3();
    if user_cr3 != 0 && user_cr3 != current_cr3 {
        // Bracket the CR3 write with active-CPU mask updates so the
        // TLB shootdown protocol can target this CPU correctly.
        // Order: set NEW bit → write CR3 → clear OLD bit.  This avoids
        // the "neither bit set" window in which a concurrent shootdown
        // for the new CR3 could miss this CPU.  See mm/tlb.rs.
        crate::mm::tlb::note_cr3_load(user_cr3);
        unsafe { crate::mm::vmm::switch_cr3(user_cr3); }
        crate::mm::tlb::note_cr3_unload(current_cr3);
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
    //
    // `fork_regs` is `ForkUserRegs::default()` (all zeros) for every code path
    // except fork/vfork/clone3 children — in those cases it holds the parent's
    // callee-saved register snapshot (RBP/RBX/R12-R15) captured in the syscall
    // entry frame.  Propagating them is required by POSIX clone(2): the child
    // sees the same register state the parent had at the clone() callsite, so
    // glibc's `_Fork` epilogue (which reads `-0x18(%rbp)` for its stack canary)
    // does not fault on a NULL base pointer.
    //
    // Pass a pointer to the on-stack snapshot rather than the values directly
    // — `jump_to_user_mode` is a 4-arg naked function and we already use all
    // four argument registers (RDI/RSI/RDX/RCX) for RIP/RSP/RDX_val/R8_val.
    crate::serial_println!(
        "[BOOT] jump_to_user_mode: rip={:#x} rsp={:#x} rdx={:#x} r8={:#x} fork_regs=[rbp={:#x} rbx={:#x} r12={:#x}]",
        entry_rip, entry_rsp, entry_rdx, entry_r8,
        fork_regs.rbp, fork_regs.rbx, fork_regs.r12);
    unsafe { jump_to_user_mode(entry_rip, entry_rsp, entry_rdx, entry_r8, &fork_regs as *const _); }
}

/// Transition to user mode (Ring 3) via IRETQ.
///
/// Pushes an interrupt return frame onto the current stack and executes
/// IRETQ to atomically switch to Ring 3 with the given RIP, RSP, RDX, and R8.
///
/// `fork_regs` carries the parent's callee-saved register snapshot for fork /
/// vfork / clone3 children.  For brand-new processes / threads (initial exec,
/// `create_user_thread`), the caller passes a pointer to an all-zero
/// `ForkUserRegs` so the child enters userspace with cleared callee-saves —
/// preserving the original kernel-data-leak protection.
///
/// # Arguments
/// RDI = entry_rip, RSI = entry_rsp, RDX = entry_rdx, RCX = entry_r8,
/// R8 (incoming, SysV arg 5) = pointer to ForkUserRegs
///
/// # Safety
/// - `entry_rip` must point to valid, executable, Ring 3-accessible code.
/// - `entry_rsp` must point to a valid, Ring 3-accessible stack.
/// - `entry_rdx` / `entry_r8`: thread function and argument for glibc clone3 children
///   (glibc 2.34+ passes `func` in RDX and `arg` in R8 through the clone3 syscall;
///   set both to 0 for initial processes and clone2-style threads).
/// - `fork_regs` must be a valid pointer to a `ForkUserRegs` (`#[repr(C)]`,
///   6 × u64 in order rbp/rbx/r12/r13/r14/r15) that lives at least until iretq.
/// - This function never returns.
#[unsafe(naked)]
pub unsafe extern "C" fn jump_to_user_mode(
    _entry_rip: u64,
    _entry_rsp: u64,
    _entry_rdx: u64,
    _entry_r8: u64,
    _fork_regs: *const crate::proc::ForkUserRegs,
) -> ! {
    core::arch::naked_asm!(
        // Args (System V AMD64 ABI):
        //   rdi = rip, rsi = rsp, rdx = rdx_val, rcx = r8_val, r8 = fork_regs ptr
        //
        // Strategy:
        //   1. Build IRETQ frame from rdi/rsi (caller-saved by ABI, free to clobber).
        //   2. Move r8_val into r8 — but r8 currently holds fork_regs.  Use r9 as
        //      a scratch first: stash fork_regs in r9 (also caller-saved), then
        //      mov r8 = rcx (r8_val), then load callee-saves from [r9 + offsets].
        //   3. After loading all callee-saves and arg-pass regs, xor the caller-
        //      saved scratch regs (rax/rcx/rdi/rsi/r9/r10/r11) and iretq.
        //
        // ForkUserRegs layout (#[repr(C)] — see proc/mod.rs):
        //   +0  = rbp, +8  = rbx, +16 = r12, +24 = r13, +32 = r14, +40 = r15
        //
        // Build IRETQ frame.
        "push 0x1B",        // SS = USER_DATA_SELECTOR
        "push rsi",         // RSP = user stack pointer (arg2)
        "push 0x202",       // RFLAGS (IF set)
        "push 0x23",        // CS = USER_CODE_SELECTOR
        "push rdi",         // RIP = entry point (arg1)
        // Stash fork_regs pointer in r9 before clobbering r8.
        "mov r9, r8",
        // r8 = entry_r8 value (from arg4 / rcx).
        "mov r8, rcx",
        // Load callee-saved registers from the ForkUserRegs struct pointed to by r9.
        // For fresh processes the caller passes an all-zero struct, so this is a
        // no-op (and the protection of zeroing kernel data is preserved).
        "mov rbp, [r9 + 0]",     // ForkUserRegs.rbp
        "mov rbx, [r9 + 8]",     // ForkUserRegs.rbx
        "mov r12, [r9 + 16]",    // ForkUserRegs.r12
        "mov r13, [r9 + 24]",    // ForkUserRegs.r13
        "mov r14, [r9 + 32]",    // ForkUserRegs.r14
        "mov r15, [r9 + 40]",    // ForkUserRegs.r15
        // Zero the remaining caller-saved regs that might still hold kernel data.
        // RDX and R8 already hold the values the child expects to see.
        "xor eax, eax",
        "xor esi, esi",
        "xor edi, edi",
        "xor ecx, ecx",
        "xor r9d, r9d",
        "xor r10d, r10d",
        "xor r11d, r11d",
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
