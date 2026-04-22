//! Interrupt Descriptor Table (IDT) for x86_64.
//!
//! Handles CPU exceptions and hardware interrupts.
//! Supports IST (Interrupt Stack Table) for critical exceptions.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

/// Global page fault counter for heartbeat diagnostics.
static PAGE_FAULT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub fn page_fault_count() -> u64 { PAGE_FAULT_TOTAL.load(Ordering::Relaxed) }

/// Number of IDT entries (256 vectors).
const IDT_ENTRIES: usize = 256;

/// IDT entry (16 bytes for x86_64).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,        // IST offset (bits 0-2), rest zero
    type_attr: u8,  // Type and attributes
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

impl IdtEntry {
    const fn empty() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            _reserved: 0,
        }
    }

    /// Set the handler for this IDT entry.
    fn set_handler(&mut self, handler: u64, selector: u16, ist: u8, ring: u8) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = selector;
        self.ist = ist;
        // Present | Interrupt Gate (0xE) | DPL (ring)
        self.type_attr = 0x80 | ((ring & 3) << 5) | 0x0E;
        self._reserved = 0;
    }
}

/// IDT pointer for LIDT instruction.
#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

/// The static IDT.
static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::empty(); IDT_ENTRIES];

static IDT_INIT: Once<()> = Once::new();

/// CPU exception names for debugging.
static EXCEPTION_NAMES: [&str; 32] = [
    "Division Error",
    "Debug",
    "Non-Maskable Interrupt",
    "Breakpoint",
    "Overflow",
    "Bound Range Exceeded",
    "Invalid Opcode",
    "Device Not Available",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Invalid TSS",
    "Segment Not Present",
    "Stack-Segment Fault",
    "General Protection Fault",
    "Page Fault",
    "Reserved",
    "x87 Floating-Point",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating-Point",
    "Virtualization",
    "Control Protection",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Hypervisor Injection",
    "VMM Communication",
    "Security Exception",
    "Reserved",
];

/// Interrupt frame pushed by CPU on interrupt/exception.
#[repr(C)]
pub struct InterruptFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Initialize the IDT with exception and IRQ handlers.
pub fn init() {
    IDT_INIT.call_once(|| {
        let kernel_cs = super::gdt::KERNEL_CODE_SELECTOR;

        // Fix truncated function pointers from mcmodel=kernel.
        // See proc/thread.rs fixup_fn_ptr for details.
        let fix = crate::proc::thread::fixup_fn_ptr;

        // SAFETY: We're in single-threaded init. Setting up IDT entries.
        unsafe {
            // CPU exceptions (0-31)
            IDT[0].set_handler(fix(isr_divide_error as *const () as u64), kernel_cs, 0, 0);
            IDT[1].set_handler(fix(isr_debug as *const () as u64), kernel_cs, 0, 0);
            IDT[2].set_handler(fix(isr_nmi as *const () as u64), kernel_cs, 0, 0);
            IDT[3].set_handler(fix(isr_breakpoint as *const () as u64), kernel_cs, 0, 3); // Allow from userspace
            IDT[4].set_handler(fix(isr_overflow as *const () as u64), kernel_cs, 0, 0);
            IDT[5].set_handler(fix(isr_bound_range as *const () as u64), kernel_cs, 0, 0);
            IDT[6].set_handler(fix(isr_invalid_opcode as *const () as u64), kernel_cs, 0, 0);
            IDT[7].set_handler(fix(isr_device_not_available as *const () as u64), kernel_cs, 0, 0);
            IDT[8].set_handler(fix(isr_double_fault as *const () as u64), kernel_cs, 2, 0); // IST 2 for double fault
            IDT[10].set_handler(fix(isr_invalid_tss as *const () as u64), kernel_cs, 0, 0);
            IDT[11].set_handler(fix(isr_segment_not_present as *const () as u64), kernel_cs, 0, 0);
            IDT[12].set_handler(fix(isr_stack_segment as *const () as u64), kernel_cs, 0, 0);
            IDT[13].set_handler(fix(isr_general_protection as *const () as u64), kernel_cs, 0, 0);
            IDT[14].set_handler(fix(isr_page_fault as *const () as u64), kernel_cs, 0, 0);
            IDT[16].set_handler(fix(isr_x87_fp as *const () as u64), kernel_cs, 0, 0);
            IDT[17].set_handler(fix(isr_alignment_check as *const () as u64), kernel_cs, 0, 0);
            IDT[18].set_handler(fix(isr_machine_check as *const () as u64), kernel_cs, 0, 0);
            IDT[19].set_handler(fix(isr_simd_fp as *const () as u64), kernel_cs, 0, 0);

            // Hardware IRQs (32-47) — set up in irq module
            // IRQ0 (timer) = vector 32
            // IRQ1 (keyboard) = vector 33
            // etc.
            IDT[32].set_handler(fix(super::irq::irq_timer_handler as *const () as u64), kernel_cs, 0, 0);
            IDT[33].set_handler(fix(super::irq::irq_keyboard_handler as *const () as u64), kernel_cs, 0, 0);
            IDT[43].set_handler(fix(super::irq::irq_e1000_handler as *const () as u64), kernel_cs, 0, 0);
            IDT[44].set_handler(fix(super::irq::irq_mouse_handler as *const () as u64), kernel_cs, 0, 0);

            // Syscall interrupt (vector 0x80) — for int 0x80 style syscalls
            IDT[0x80].set_handler(fix(isr_syscall_int80 as *const () as u64), kernel_cs, 0, 3);

            // NT syscall gate (vector 0x2E) — Windows INT 0x2E compatibility
            IDT[0x2E].set_handler(fix(isr_syscall_int2e as *const () as u64), kernel_cs, 0, 3);

            // Load IDT — fix truncated base address from mcmodel=kernel
            let idt_ptr = IdtPointer {
                limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
                base: fix((&raw const IDT) as *const IdtEntry as u64),
            };
            asm!(
                "lidt [{}]",
                in(reg) &idt_ptr,
                options(readonly, nostack, preserves_flags)
            );
        }
    });

    // Verify IDT handler addresses are higher-half (mcmodel=kernel fixup check)
    unsafe {
        let pf_entry = &IDT[14];
        let handler = pf_entry.offset_low as u64
            | ((pf_entry.offset_mid as u64) << 16)
            | ((pf_entry.offset_high as u64) << 32);
        let timer_entry = &IDT[32];
        let timer_handler = timer_entry.offset_low as u64
            | ((timer_entry.offset_mid as u64) << 16)
            | ((timer_entry.offset_high as u64) << 32);
        let sc_entry = &IDT[0x80];
        let sc_handler = sc_entry.offset_low as u64
            | ((sc_entry.offset_mid as u64) << 16)
            | ((sc_entry.offset_high as u64) << 32);
        crate::serial_println!(
            "[IDT] PF={:#x} Timer={:#x} INT80={:#x} (should be 0xFFFF8000...)",
            handler, timer_handler, sc_handler
        );
    }
    crate::serial_println!("[IDT] Initialized with {} vectors", IDT_ENTRIES);
}

// ============================================================
// Exception handlers (naked functions to properly save state)
// ============================================================

/// Common exception handler called from stubs.
#[no_mangle]
extern "C" fn exception_handler(vector: u64, error_code: u64, frame: &mut InterruptFrame) {
    // Debug trace for non-page-fault exceptions from user mode.
    if frame.cs & 3 == 3 && vector != 14 {
        crate::serial_println!(
            "[EXC] vec={} err={:#x} RIP={:#x} CS={:#x} RSP={:#x}",
            vector, error_code, frame.rip, frame.cs, frame.rsp
        );
    }

    let name = if (vector as usize) < EXCEPTION_NAMES.len() {
        EXCEPTION_NAMES[vector as usize]
    } else {
        "Unknown"
    };

    // Page fault handler — try to resolve via VMA/CoW before panicking
    if vector == 14 {
        crate::perf::record_page_fault();
        let cr2: u64;
        unsafe {
            asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        }

        #[cfg(feature = "firefox-test")]
        {
            use core::sync::atomic::{AtomicU64, Ordering};
            static PF_TOTAL_LOG: AtomicU64 = AtomicU64::new(0);
            static PF_WRITE: AtomicU64 = AtomicU64::new(0);
            static PF_NOTPRESENT: AtomicU64 = AtomicU64::new(0);
            let tot = PF_TOTAL_LOG.fetch_add(1, Ordering::Relaxed);
            if error_code & 2 != 0 { PF_WRITE.fetch_add(1, Ordering::Relaxed); }
            else { PF_NOTPRESENT.fetch_add(1, Ordering::Relaxed); }
            if tot > 0 && tot % 1_000_000 == 0 {
                crate::serial_println!(
                    "[PF/stat] total={} write={} notpresent={} err_sample={:#x} cr2={:#x}",
                    tot,
                    PF_WRITE.load(Ordering::Relaxed),
                    PF_NOTPRESENT.load(Ordering::Relaxed),
                    error_code, cr2
                );
            }
        }

        if handle_page_fault(cr2, error_code, frame) {
            // Deferred preemption: check if a reschedule is pending.
            // This is a safe point — all locks released, returning to user mode.
            // This replaces the broken ISR-direct schedule() approach.
            if frame.cs & 3 == 3 {
                crate::sched::check_reschedule();
            }
            return; // Fault resolved
        }

        // Unresolvable — print diagnostics
        crate::serial_println!(
            "\n!!! Page Fault (error_code=0x{:x})",
            error_code
        );
        crate::serial_println!("  CR2 (fault addr): 0x{:016x}", cr2);
        crate::serial_println!("  RIP: 0x{:016x}", frame.rip);
        crate::serial_println!("  CS:  0x{:04x}", frame.cs);
        crate::serial_println!("  RSP: 0x{:016x}", frame.rsp);
        crate::serial_println!(
            "  Flags: {} {} {} {}",
            if error_code & 1 != 0 { "PRESENT" } else { "not-present" },
            if error_code & 2 != 0 { "WRITE" } else { "READ" },
            if error_code & 4 != 0 { "USER" } else { "KERNEL" },
            if error_code & 16 != 0 { "IFETCH" } else { "" },
        );

        // Dump user GPRs saved on the ISR stack (below the InterruptFrame).
        // The isr_with_error stub pushes: rax,rbx,rcx,rdx,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15,rbp
        // in that order (rax first at highest address / last pushed).
        // The saved regs are BELOW frame (lower addresses) since the CPU pushed error+frame
        // THEN the stub pushed caller-saved regs.
        #[cfg(feature = "firefox-test")]
        if error_code & 4 != 0 {
            // Read saved GPRs from the ISR stack.  Layout below frame:
            //   [frame-8]   = error_code (pushed by CPU)
            //   [frame-16]  = rax
            //   [frame-24]  = rbx
            //   [frame-32]  = rcx
            //   [frame-40]  = rdx
            //   [frame-48]  = rsi
            //   [frame-56]  = rdi
            //   [frame-64]  = r8  ... etc
            // ISR stub push order: rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11
            // frame[-1]=error_code, frame[-2]=rax, frame[-3]=rcx, frame[-4]=rdx,
            // frame[-5]=rsi, frame[-6]=rdi, frame[-7]=r8, frame[-8]=r9, frame[-9]=r10, frame[-10]=r11
            let base = frame as *const InterruptFrame as *const u64;
            unsafe {
                let rax = *base.sub(2);
                let rcx = *base.sub(3);
                let rdx = *base.sub(4);
                let rsi = *base.sub(5);
                let rdi = *base.sub(6);
                let r8  = *base.sub(7);
                crate::serial_println!(
                    "  User GPRs: RAX={:#x} RCX={:#x} RDX={:#x} RSI={:#x} RDI={:#x} R8={:#x}",
                    rax, rcx, rdx, rsi, rdi, r8
                );
            }
        }

        // If the fault came from Ring 3, try to deliver SIGSEGV first.
        if error_code & 4 != 0 {
            let delivered = unsafe {
                crate::signal::deliver_sigsegv_from_isr(
                    cr2,
                    error_code,
                    frame as *mut InterruptFrame,
                )
            };
            if delivered {
                return; // IRET will go to the signal handler
            }
            // Re-enable interrupts BEFORE any serial prints: serial_println! spins on
            // SERIAL mutex. If the BSP holds SERIAL (e.g. during ELF loading output)
            // and the AP ISR tries to print with interrupts disabled, we deadlock.
            // Enabling interrupts here also allows idle thread's `hlt` to wake after
            // schedule() is called from exit_thread.
            crate::hal::enable_interrupts();
            crate::serial_println!("  Killing user process (page fault in Ring 3, no handler)");
            // Dump user stack to aid crash analysis
            {
                let rsp = frame.rsp;
                let cr3: u64;
                unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)); }
                crate::serial_println!("  Stack dump (RSP={:#x} CR3={:#x}):", rsp, cr3);
                for i in 0..16usize {
                    let addr = rsp + (i * 8) as u64;
                    if let Some(phys) = crate::mm::vmm::virt_to_phys_in(cr3, addr) {
                        let virt = phys + astryx_shared::KERNEL_VIRT_BASE;
                        let val = unsafe { core::ptr::read_volatile(virt as *const u64) };
                        crate::serial_println!("    [RSP+{:#04x}] {:#018x} = {:#018x}", i*8, addr, val);
                    } else {
                        crate::serial_println!("    [RSP+{:#04x}] {:#018x} = (unmapped)", i*8, addr);
                    }
                }
                // Dump IRET frame fields
                crate::serial_println!("  RFLAGS={:#018x}", frame.rflags);
            }
            crate::proc::exit_thread(-11i64); // SIGSEGV
            return;
        }

        // Kernel-mode page fault → bugcheck (structured crash report)
        crate::ke::bugcheck::ke_bugcheck(
            crate::ke::bugcheck::BUGCHECK_KERNEL_PAGE_FAULT,
            cr2,             // P1: fault address
            error_code,      // P2: error code
            frame.rip,       // P3: instruction that faulted
            frame.rsp,       // P4: stack pointer at fault
        );
    }

    // Enable interrupts early for Ring 3 exceptions so serial_println! can acquire
    // the SERIAL mutex without deadlocking (BSP may hold it during ELF loading).
    // For kernel-mode exceptions we keep interrupts disabled until halt.
    if frame.cs & 3 == 3 {
        crate::hal::enable_interrupts();
    }

    crate::serial_println!(
        "\n!!! Exception #{}: {} (error_code=0x{:x}) cpu={} tid={}",
        vector,
        name,
        error_code,
        crate::arch::x86_64::apic::cpu_index(),
        crate::proc::current_tid(),
    );
    crate::serial_println!("  RIP: 0x{:016x}", frame.rip);
    crate::serial_println!("  CS:  0x{:04x}", frame.cs);
    crate::serial_println!("  RFLAGS: 0x{:016x}", frame.rflags);
    crate::serial_println!("  RSP: 0x{:016x}", frame.rsp);
    crate::serial_println!("  SS:  0x{:04x}", frame.ss);

    // Double Fault diagnostics: print TSS.RSP[0] and per_cpu.kernel_rsp
    // to identify whether the corruption is in the TSS or SYSCALL path.
    if vector == 8 {
        let tss_rsp0 = unsafe { crate::arch::x86_64::gdt::read_tss_rsp0() };
        let kern_rsp = crate::syscall::get_current_kernel_rsp();
        crate::serial_println!("  TSS.RSP[0]={:#x}  per_cpu.kernel_rsp={:#x}", tss_rsp0, kern_rsp);
    }

    if vector == 3 {
        // Breakpoint — continue execution
        return;
    }

    // If the fault came from Ring 3, kill the process instead of halting
    if frame.cs & 3 == 3 {
        // Print saved GPRs from ISR stack for debugging.
        // ISR stub pushes: rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11, then error_code, then IRETQ frame.
        // frame points to IRETQ frame. Saved regs are below: frame-8=err, frame-16=rax, frame-24=rcx, ...
        let fp = frame as *const InterruptFrame as u64;
        let (rax, rcx, rdx, rsi, rdi, r8) = unsafe {
            (
                *((fp - 16) as *const u64),  // RAX
                *((fp - 24) as *const u64),  // RCX
                *((fp - 32) as *const u64),  // RDX
                *((fp - 40) as *const u64),  // RSI
                *((fp - 48) as *const u64),  // RDI
                *((fp - 56) as *const u64),  // R8
            )
        };
        crate::serial_println!("  User GPRs: RAX={:#x} RCX={:#x} RDX={:#x} RSI={:#x} RDI={:#x} R8={:#x}",
            rax, rcx, rdx, rsi, rdi, r8);
        crate::serial_println!("  Killing user process (exception in Ring 3)");
        crate::proc::exit_thread(-(vector as i64));
        return;
    }

    // Fatal kernel exception → bugcheck
    let bugcode = if vector == 8 {
        crate::ke::bugcheck::BUGCHECK_DOUBLE_FAULT
    } else if vector == 13 {
        crate::ke::bugcheck::BUGCHECK_KERNEL_GPF
    } else {
        crate::ke::bugcheck::BUGCHECK_UNEXPECTED_TRAP
    };
    crate::ke::bugcheck::ke_bugcheck(
        bugcode,
        vector as u64,      // P1: exception vector
        error_code as u64,  // P2: error code
        frame.rip,          // P3: RIP
        frame.rsp,          // P4: RSP
    );
}

/// Attempt to handle a page fault.
///
/// Returns `true` if the fault was successfully resolved (demand-paging, CoW),
/// `false` if it's a genuine fault that should kill the process or panic.
///
/// # Error code bits
/// - Bit 0: Present (1 = protection violation, 0 = not-present)
/// - Bit 1: Write (1 = write, 0 = read)
/// - Bit 2: User (1 = user mode, 0 = kernel mode)
/// - Bit 4: Instruction fetch
fn handle_page_fault(faulting_addr: u64, error_code: u64, _frame: &mut InterruptFrame) -> bool {
    PAGE_FAULT_TOTAL.fetch_add(1, Ordering::Relaxed);
    let is_present = error_code & 1 != 0;
    let is_write = error_code & 2 != 0;
    let _is_user = error_code & 4 != 0;

    // === Kernel Heap Guard Page Detection ===
    //
    // The 4 KiB pages immediately below and above the kernel heap are mapped
    // not-present to catch heap underflow and overflow at the page boundary.
    // Detect these before the normal demand-paging path and panic loudly — a
    // guard hit means kernel heap corruption, not a recoverable page fault.
    //
    // Guards only fire for kernel-mode faults (bit 2 clear).  A user-mode
    // access to a kernel higher-half address would already be caught by the
    // CPU's ring-level check (GP fault) before reaching here; guard detection
    // is purely a defence-in-depth for buggy kernel allocations.
    {
        use crate::mm::heap::{HEAP_GUARD_BELOW_VA, HEAP_GUARD_ABOVE_VA, HEAP_START, HEAP_SIZE};
        let is_below_guard = faulting_addr >= HEAP_GUARD_BELOW_VA
                          && faulting_addr <  HEAP_GUARD_BELOW_VA + 0x1000;
        let is_above_guard = faulting_addr >= HEAP_GUARD_ABOVE_VA
                          && faulting_addr <  HEAP_GUARD_ABOVE_VA + 0x1000;
        if is_below_guard || is_above_guard {
            // Do not hold any lock — panic is unrecoverable.
            panic!(
                "[KERNEL HEAP GUARD] overflow at {:#x} (heap range: {:#x}..{:#x})",
                faulting_addr,
                HEAP_START as u64,
                (HEAP_START + HEAP_SIZE) as u64,
            );
        }
    }

    let pid = crate::proc::recover_current_pid();

    // Look up the faulting address in the process's VmSpace.
    // For vfork children (sharing parent's CR3), also check the parent's VmSpace
    // if the child's own VmSpace doesn't have a matching VMA.
    let (parent_pid_for_fallback, own_cr3) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return false,
        };
        (proc.parent_pid, proc.cr3)
    };

    // Determine which PID's VmSpace to use for this fault.
    // Try own process first; if it has no VMA for this address, try the parent.
    // This handles vfork children that share the parent's page tables.
    let target_pid = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let has_vma = procs.iter().find(|p| p.pid == pid)
            .and_then(|p| p.vm_space.as_ref())
            .and_then(|vs| vs.find_vma(faulting_addr))
            .is_some();
        if has_vma {
            pid
        } else if parent_pid_for_fallback != 0 {
            // Check if parent has the same CR3 (shared address space = vfork)
            let parent_cr3 = procs.iter().find(|p| p.pid == parent_pid_for_fallback)
                .map(|p| p.cr3).unwrap_or(0);
            if parent_cr3 == own_cr3 && parent_cr3 != 0 {
                parent_pid_for_fallback
            } else {
                pid // Different CR3 — not a vfork child, use own VmSpace
            }
        } else {
            pid
        }
    };

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == target_pid) {
        Some(p) => p,
        None => return false,
    };
    let vm_space = match proc.vm_space.as_mut() {
        Some(vs) => vs,
        None => return false,
    };

    let page_addr = crate::mm::vma::page_align_down(faulting_addr);
    let cr3 = vm_space.cr3;

    // === Copy-on-Write (early path): present+write faults must be handled
    // even when the VMA list is incomplete (e.g., fork child whose parent
    // vm_space.areas was stale). Check this before the VMA lookup so that
    // pages CoW'd via clone_for_fork are always writable by their sole owner.
    if is_present && is_write {
        use crate::mm::vmm::{PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER};
        const PHYS_OFF_COW: u64 = 0xFFFF_8000_0000_0000;

        // Determine page flags from the VMA if available; fall back to RW|User
        // for pages with no registered VMA (orphaned CoW pages after fork).
        let page_flags = match vm_space.find_vma(faulting_addr) {
            Some(vma) => {
                if vma.prot & crate::mm::vma::PROT_WRITE == 0 {
                    return false; // Genuine write-protection fault — SIGSEGV
                }
                vma.to_page_flags()
            }
            None => {
                // No VMA but page is present — treat as RW|User (CoW orphan).
                PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER
            }
        };

        let pte = crate::mm::vmm::read_pte(cr3, page_addr);
        let old_phys = pte & 0x000F_FFFF_FFFF_F000;

        if crate::mm::refcount::page_ref_count(old_phys) > 1 {
            // Shared page — make a private copy
            if let Some(new_phys) = crate::mm::pmm::alloc_page() {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (PHYS_OFF_COW + old_phys) as *const u8,
                        (PHYS_OFF_COW + new_phys) as *mut u8,
                        crate::mm::pmm::PAGE_SIZE,
                    );
                }
                crate::mm::refcount::page_ref_dec(old_phys);
                crate::mm::refcount::page_ref_set(new_phys, 1);
                crate::mm::vmm::map_page_in(cr3, page_addr, new_phys, page_flags);
                crate::mm::vmm::invlpg(page_addr);
                return true;
            }
            return false; // OOM
        } else {
            // Single owner — just make it writable
            let new_pte = old_phys | page_flags | PAGE_PRESENT;
            crate::mm::vmm::write_pte(cr3, page_addr, new_pte);
            crate::mm::vmm::invlpg(page_addr);
            return true;
        }
    }

    // === Demand Paging: VMA required ===
    let vma = match vm_space.find_vma(faulting_addr) {
        Some(v) => v,
        None => return false, // Fault outside any VMA — SIGSEGV
    };

    // PROT_NONE VMAs (guard pages) — never accessible in any mode.
    if vma.prot == crate::mm::vma::PROT_NONE { return false; }

    // === NX fixup: page is PRESENT but marked NX, VMA says PROT_EXEC ===
    // This happens when a page was demand-faulted for read/write before the
    // execute permission was needed, or after mprotect changed permissions.
    let is_ifetch = error_code & 0x10 != 0;
    if is_present && is_ifetch && (vma.prot & crate::mm::vma::PROT_EXEC != 0) {
        let pte = crate::mm::vmm::read_pte(cr3, page_addr);
        if pte & crate::mm::vmm::PAGE_NO_EXECUTE != 0 {
            // Clear NX bit to allow execution
            let new_pte = pte & !crate::mm::vmm::PAGE_NO_EXECUTE;
            crate::mm::vmm::write_pte(cr3, page_addr, new_pte);
            crate::mm::vmm::invlpg(page_addr);
            return true;
        }
    }

    // (is_write on a !is_present page: check VMA write permission)
    if is_write && (vma.prot & crate::mm::vma::PROT_WRITE == 0) {
        return false; // Permission denied — SIGSEGV
    }

    let page_flags = vma.to_page_flags();

    if !is_present {
        // === Demand Paging: page not yet mapped ===

        // For file-backed VMAs we must drop the PROCESS_TABLE lock before
        // accessing the VFS (which takes MOUNTS), so extract the info first.
        let file_info = match &vma.backing {
            crate::mm::vma::VmBacking::File { mount_idx, inode, offset } => {
                Some((*mount_idx, *inode, *offset, vma.base, vma.base + vma.length))
            }
            _ => None,
        };

        if let Some((mount_idx, inode, file_base_offset, vma_base, vma_end)) = file_info {
            // Release PROCESS_TABLE to avoid deadlock with MOUNTS.
            drop(procs);

            // Enable interrupts during the file read so the timer ISR can
            // fire. ATA PIO reads can take 10-100ms; without re-enabling
            // interrupts, the CPU appears dead (no heartbeat, no scheduling).
            // Safe: all kernel locks are released at this point.
            crate::hal::enable_interrupts();

            let page_offset_in_vma = page_addr - vma_base;
            let file_page_offset = file_base_offset + page_offset_in_vma;

            #[cfg(feature = "firefox-test")]
            {
                static PF_FILE_N: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
                let n = PF_FILE_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if n < 20 {
                    let hw_cr3: u64;
                    unsafe { core::arch::asm!("mov {}, cr3", out(reg) hw_cr3, options(nomem, nostack)); }
                    // Higher-half physical accessor (safe: PML4[256-511] shallow-copied to user CR3)
                    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
                    let pml4i = ((page_addr >> 39) & 0x1FF) as usize;
                    let pdpti = ((page_addr >> 30) & 0x1FF) as usize;
                    let pdi   = ((page_addr >> 21) & 0x1FF) as usize;
                    let pti   = ((page_addr >> 12) & 0x1FF) as usize;
                    let cr3p  = hw_cr3 & 0x000F_FFFF_FFFF_F000;
                    let (pml4e, pdpte, pde, pte_hw) = unsafe {
                        let pml4e = *((PHYS_OFF + cr3p + pml4i as u64 * 8) as *const u64);
                        let pdpte = if pml4e & 1 != 0 {
                            *((PHYS_OFF + (pml4e & 0x000F_FFFF_FFFF_F000) + pdpti as u64 * 8) as *const u64)
                        } else { 0 };
                        let pde = if pdpte & 1 != 0 && pdpte & (1<<7) == 0 {
                            *((PHYS_OFF + (pdpte & 0x000F_FFFF_FFFF_F000) + pdi as u64 * 8) as *const u64)
                        } else { 0 };
                        let pte_hw = if pde & 1 != 0 && pde & (1<<7) == 0 {
                            *((PHYS_OFF + (pde & 0x000F_FFFF_FFFF_F000) + pti as u64 * 8) as *const u64)
                        } else { 0 };
                        (pml4e, pdpte, pde, pte_hw)
                    };
                    crate::serial_println!("[PF/file] #{} err={:#x} addr={:#x} hw_cr3={:#x} vm_cr3={:#x}",
                        n, error_code, page_addr, hw_cr3, cr3);
                    crate::serial_println!("[PF/walk] PML4[{}]={:#x} PDPT[{}]={:#x} PD[{}]={:#x} PT[{}]={:#x}",
                        pml4i, pml4e, pdpti, pdpte, pdi, pde, pti, pte_hw);
                }
            }

            // 1. Check the page cache
            if let Some(cached_phys) = crate::mm::cache::lookup(mount_idx, inode, file_page_offset) {
                // MAP_PRIVATE + writable: give the process a private copy so
                // writes (e.g., GOT/PLT relocations) don't corrupt the shared
                // cache page. Without this, a second process loading the same
                // library sees PID 1's relocated pointers as garbage.
                let is_writable = page_flags & crate::mm::vmm::PAGE_WRITABLE != 0;
                if is_writable {
                    if let Some(private_phys) = crate::mm::pmm::alloc_page() {
                        const COW_OFF: u64 = 0xFFFF_8000_0000_0000;
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (COW_OFF + cached_phys) as *const u8,
                                (COW_OFF + private_phys) as *mut u8,
                                crate::mm::pmm::PAGE_SIZE,
                            );
                        }
                        crate::mm::refcount::page_ref_set(private_phys, 1);
                        crate::mm::vmm::map_page_in(cr3, page_addr, private_phys, page_flags);
                        crate::mm::vmm::invlpg(page_addr);
                    } else {
                        // OOM fallback: share the cached page (may cause issues)
                        crate::mm::refcount::page_ref_inc(cached_phys);
                        crate::mm::vmm::map_page_in(cr3, page_addr, cached_phys, page_flags);
                        crate::mm::vmm::invlpg(page_addr);
                    }
                } else {
                    // Read-only: share the cached page directly
                    crate::mm::refcount::page_ref_inc(cached_phys);
                    crate::mm::vmm::map_page_in(cr3, page_addr, cached_phys, page_flags);
                    crate::mm::vmm::invlpg(page_addr);
                }
                #[cfg(feature = "firefox-test")]
                {
                    static PF_CACHED_N: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
                    let n2 = PF_CACHED_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    if n2 < 20 {
                        const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
                        let pml4i = ((page_addr >> 39) & 0x1FF) as usize;
                        let pdpti = ((page_addr >> 30) & 0x1FF) as usize;
                        let pdi   = ((page_addr >> 21) & 0x1FF) as usize;
                        let pti   = ((page_addr >> 12) & 0x1FF) as usize;
                        let hw_cr3: u64;
                        unsafe { core::arch::asm!("mov {}, cr3", out(reg) hw_cr3, options(nomem, nostack)); }
                        let cr3p  = hw_cr3 & 0x000F_FFFF_FFFF_F000;
                        let (pml4e, pdpte, pde, pte_hw) = unsafe {
                            let pml4e = *((PHYS_OFF + cr3p + pml4i as u64 * 8) as *const u64);
                            let pdpte = if pml4e & 1 != 0 {
                                *((PHYS_OFF + (pml4e & 0x000F_FFFF_FFFF_F000) + pdpti as u64 * 8) as *const u64)
                            } else { 0 };
                            let pde = if pdpte & 1 != 0 && pdpte & (1<<7) == 0 {
                                *((PHYS_OFF + (pdpte & 0x000F_FFFF_FFFF_F000) + pdi as u64 * 8) as *const u64)
                            } else { 0 };
                            let pte_hw = if pde & 1 != 0 && pde & (1<<7) == 0 {
                                *((PHYS_OFF + (pde & 0x000F_FFFF_FFFF_F000) + pti as u64 * 8) as *const u64)
                            } else { 0 };
                            (pml4e, pdpte, pde, pte_hw)
                        };
                        crate::serial_println!("[PF/cache] #{} addr={:#x} phys={:#x}", n2, page_addr, cached_phys);
                        crate::serial_println!("[PF/after] PML4[{}]={:#x} PDPT[{}]={:#x} PD[{}]={:#x} PT[{}]={:#x}",
                            pml4i, pml4e, pdpti, pdpte, pdi, pde, pti, pte_hw);
                    }
                }
                return true;
            }

            // 2. Not cached — allocate pages and read from the filesystem.
            // READAHEAD: Read 32 pages (128 KB) at once to amortize disk I/O.
            // On WSL2/KVM, each ATA PIO sector read costs ~100µs. By reading
            // 256 sectors (128 KB) in one batch instead of 8 (4 KB), we reduce
            // 47,000 page faults for a 194 MB library to ~1,500 batches.
            const PHYS_OFF_FILE: u64 = 0xFFFF_8000_0000_0000;
            const READAHEAD_PAGES: u64 = 32; // 128 KB readahead

            // Allocate the faulting page + readahead pages (best effort).
            // Fixed-size array to avoid alloc dependency in the ISR path.
            let mut pages_to_map: [(u64, u64, u64); READAHEAD_PAGES as usize] = [(0, 0, 0); READAHEAD_PAGES as usize];
            let mut n_pages = 0usize;
            {
                let mounts = crate::vfs::MOUNTS.lock();
                if mount_idx < mounts.len() {
                    // Get file size to bound readahead
                    let file_size = mounts[mount_idx].fs.stat(inode)
                        .map(|s| s.size).unwrap_or(0);

                    for pg_idx in 0..READAHEAD_PAGES {
                        let vaddr = page_addr + pg_idx * 0x1000;
                        let foff = file_page_offset + pg_idx * 0x1000;
                        // Don't readahead past VMA boundary (different VMAs may have different permissions)
                        if vaddr >= vma_end { break; }
                        // Don't read past end of file
                        if foff >= file_size { break; }
                        // Don't readahead pages that are already cached/mapped
                        if pg_idx > 0 {
                            if crate::mm::cache::lookup(mount_idx, inode, foff).is_some() { continue; }
                            // Check if already mapped in PTE
                            let existing = crate::mm::vmm::read_pte(cr3, vaddr);
                            if existing & 1 != 0 { continue; } // already present
                        }
                        if let Some(phys) = crate::mm::pmm::alloc_page() {
                            unsafe {
                                core::ptr::write_bytes((PHYS_OFF_FILE + phys) as *mut u8, 0, 0x1000);
                            }
                            let buf = unsafe {
                                core::slice::from_raw_parts_mut(
                                    (PHYS_OFF_FILE + phys) as *mut u8, 0x1000)
                            };
                            let _ = mounts[mount_idx].fs.read(inode, foff, buf);
                            pages_to_map[n_pages] = (vaddr, phys, foff);
                            n_pages += 1;
                        } else {
                            break; // OOM — stop readahead
                        }
                    }
                }
            }

            // Map all readahead pages and insert into cache.
            // IMPORTANT: for MAP_PRIVATE writable VMAs (e.g. .data/.bss of shared libs),
            // the cache page must stay CLEAN (original file content) so that future
            // processes get unmodified file data. We insert the clean frame into the
            // cache and give each writable mapping a PRIVATE COPY, exactly as the
            // cache-hit path does. Without this, ld-linux's GOT relocations would write
            // into the shared cache page, corrupting it for every subsequent process
            // that loads the same library (observed crash: cpp_hello sees glibc_hello's
            // relocated pointers in libc's .dynamic section).
            const PHYS_COW: u64 = 0xFFFF_8000_0000_0000;
            let is_writable_vma = page_flags & crate::mm::vmm::PAGE_WRITABLE != 0;
            let mapped_faulting = n_pages > 0;
            for i in 0..n_pages {
                let (vaddr, phys, foff) = pages_to_map[i];
                // Always insert the clean page into the shared cache.
                crate::mm::cache::insert(mount_idx, inode, foff, phys);
                // For writable VMAs: give this process a private copy so writes
                // (GOT relocations, BSS init, etc.) don't corrupt the cache page.
                // For read-only VMAs: share the cache page directly (saves memory).
                if is_writable_vma {
                    if let Some(private_phys) = crate::mm::pmm::alloc_page() {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (PHYS_COW + phys) as *const u8,
                                (PHYS_COW + private_phys) as *mut u8,
                                crate::mm::pmm::PAGE_SIZE,
                            );
                        }
                        crate::mm::refcount::page_ref_set(private_phys, 1);
                        crate::mm::vmm::map_page_in(cr3, vaddr, private_phys, page_flags);
                    } else {
                        // OOM fallback: share the cache page (may cause reloc corruption)
                        crate::mm::refcount::page_ref_inc(phys);
                        crate::mm::vmm::map_page_in(cr3, vaddr, phys, page_flags);
                    }
                } else {
                    // Read-only: share the cache page (safe — no writes expected).
                    crate::mm::refcount::page_ref_inc(phys);
                    crate::mm::vmm::map_page_in(cr3, vaddr, phys, page_flags);
                }
                crate::mm::vmm::invlpg(vaddr);
            }

            // Log progress periodically
            #[cfg(feature = "firefox-test")]
            {
                static PF_VERIFY_N: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
                let vn = PF_VERIFY_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if vn % 100 == 0 || vn < 5 {
                    crate::serial_println!(
                        "[PF/readahead] #{} addr={:#x} readahead={} pages",
                        vn, page_addr, n_pages);
                }
            }

            if mapped_faulting {
                return true;  // Readahead handled the faulting page + extras.
            }

            // Fallback: readahead failed entirely — allocate single page.
            if let Some(phys) = crate::mm::pmm::alloc_page() {
                unsafe {
                    core::ptr::write_bytes((PHYS_OFF_FILE + phys) as *mut u8, 0, 0x1000);
                }
                {
                    let mounts = crate::vfs::MOUNTS.lock();
                    if mount_idx < mounts.len() {
                        let buf = unsafe {
                            core::slice::from_raw_parts_mut(
                                (PHYS_OFF_FILE + phys) as *mut u8, 0x1000)
                        };
                        let _ = mounts[mount_idx].fs.read(inode, file_page_offset, buf);
                    }
                }
                crate::mm::cache::insert(mount_idx, inode, file_page_offset, phys);
                crate::mm::refcount::page_ref_inc(phys);
                crate::mm::vmm::map_page_in(cr3, page_addr, phys, page_flags);
                crate::mm::vmm::invlpg(page_addr);
                return true;
            }
            return false; // OOM
        }

        // Use the stable higher-half mapping (PHYS_OFF) for all physical
        // memory accesses — the identity map in PML4[0] may have been
        // corrupted by user mmap() operations splitting 2MiB huge pages.
        const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

        match &vma.backing {
            crate::mm::vma::VmBacking::Anonymous => {
                #[cfg(feature = "firefox-test")]
                {
                    static ANON_PF_N: core::sync::atomic::AtomicU64
                        = core::sync::atomic::AtomicU64::new(0);
                    let n = ANON_PF_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    // Sample every 500K anonymous faults to see address distribution.
                    if n % 500_000 == 0 {
                        crate::serial_println!(
                            "[PF/anon] #{} addr={:#x} vma=[{:#x}..{:#x}] is_write={}",
                            n, page_addr, vma.base, vma.end(), is_write
                        );
                    }
                }
                // Allocate a zeroed page
                if let Some(phys) = crate::mm::pmm::alloc_page() {
                    unsafe {
                        core::ptr::write_bytes((PHYS_OFF + phys) as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
                    }
                    crate::mm::refcount::page_ref_set(phys, 1);
                    crate::mm::vmm::map_page_in(cr3, page_addr, phys, page_flags);
                    crate::mm::vmm::invlpg(page_addr);
                    return true;
                }
                return false; // OOM
            }
            crate::mm::vma::VmBacking::Device { phys_base } => {
                // Identity-map device memory (no allocation needed)
                let offset = page_addr - vma.base;
                let phys = phys_base + offset;
                crate::mm::vmm::map_page_in(cr3, page_addr, phys, page_flags | crate::mm::vmm::PAGE_NO_CACHE);
                crate::mm::vmm::invlpg(page_addr);
                return true;
            }
            crate::mm::vma::VmBacking::File { .. } => unreachable!(),
        }
    }

    false
}

// ISR stub macro — creates a naked function that pushes state and calls exception_handler
macro_rules! isr_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            // Naked ISR stub. Saves registers, pushes vector/error code, calls handler.
            core::arch::naked_asm!(
                "push 0",           // Fake error code
                "push rax",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "mov rdi, {vector}", // arg1: vector
                "mov rsi, 0",        // arg2: error code (0)
                "lea rdx, [rsp + 80]", // arg3: pointer to InterruptFrame
                "call {handler}",
                "pop r11",
                "pop r10",
                "pop r9",
                "pop r8",
                "pop rdi",
                "pop rsi",
                "pop rdx",
                "pop rcx",
                "pop rax",
                "add rsp, 8",       // Pop fake error code
                "iretq",
                vector = const $vector,
                handler = sym exception_handler,
            );
        }
    };
}

macro_rules! isr_with_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            // Naked ISR stub for exceptions that push an error code.
            core::arch::naked_asm!(
                // Error code already on stack from CPU
                "push rax",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "mov rdi, {vector}", // arg1: vector
                "mov rsi, [rsp + 72]", // arg2: error code (at offset)
                "lea rdx, [rsp + 80]", // arg3: pointer to InterruptFrame
                "call {handler}",
                "pop r11",
                "pop r10",
                "pop r9",
                "pop r8",
                "pop rdi",
                "pop rsi",
                "pop rdx",
                "pop rcx",
                "pop rax",
                "add rsp, 8",       // Pop error code
                "iretq",
                vector = const $vector,
                handler = sym exception_handler,
            );
        }
    };
}

// Generate ISR stubs
isr_no_error!(isr_divide_error, 0u64);
isr_no_error!(isr_debug, 1u64);
isr_no_error!(isr_nmi, 2u64);
isr_no_error!(isr_breakpoint, 3u64);
isr_no_error!(isr_overflow, 4u64);
isr_no_error!(isr_bound_range, 5u64);
isr_no_error!(isr_invalid_opcode, 6u64);
isr_no_error!(isr_device_not_available, 7u64);
isr_with_error!(isr_double_fault, 8u64);
isr_with_error!(isr_invalid_tss, 10u64);
isr_with_error!(isr_segment_not_present, 11u64);
isr_with_error!(isr_stack_segment, 12u64);
isr_with_error!(isr_general_protection, 13u64);
isr_with_error!(isr_page_fault, 14u64);
isr_no_error!(isr_x87_fp, 16u64);
isr_with_error!(isr_alignment_check, 17u64);
isr_no_error!(isr_machine_check, 18u64);
isr_no_error!(isr_simd_fp, 19u64);

/// INT 0x80 syscall handler — saves full register state, calls dispatch, restores state.
#[unsafe(naked)]
extern "C" fn isr_syscall_int80() {
    core::arch::naked_asm!(
        // Save all scratch registers
        "push 0",           // Fake error code placeholder (for uniform frame)
        "push rax",         // Save syscall number
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",

        // Call dispatch(num=rax, a1=rdi, a2=rsi, a3=rdx, a4=r10, a5=r8)
        // Map to C calling convention: rdi, rsi, rdx, rcx, r8, r9
        // Save original arg values before shuffling
        "mov r11, r8",      // Save a5
        "mov r9, r11",      // a5 -> r9 (6th param)
        "mov r8, r10",      // a4 -> r8 (5th param)
        "mov rcx, rdx",     // a3 -> rcx (4th param)
        "mov rdx, rsi",     // a2 -> rdx (3rd param)
        "mov rsi, rdi",     // a1 -> rsi (2nd param)
        "mov rdi, [rsp + 72]", // num (saved rax) -> rdi (1st param)
        "call {dispatch}",

        // Result in RAX — store it where RAX was saved on the stack
        "mov [rsp + 72], rax",

        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",          // Restored to be the return value
        "add rsp, 8",       // Pop fake error code
        "iretq",

        dispatch = sym crate::syscall::dispatch,
    );
}
/// INT 0x2E syscall handler — NT-ABI gate for Win32 compatibility.
///
/// NT ABI register convention:
///   - RAX = syscall number
///   - RCX = arg1  (return address in SYSCALL path, but for INT stays as arg1)
///   - RDX = arg2
///   - R8  = arg3
///   - R9  = arg4
///
/// Maps to `dispatch_nt_int2e(num, a1, a2, a3, a4, a5)` in C calling convention:
///   rdi=num, rsi=a1, rdx=a2, rcx=a3, r8=a4, r9=0
#[unsafe(naked)]
extern "C" fn isr_syscall_int2e() {
    core::arch::naked_asm!(
        // Save all scratch registers (same layout as isr_syscall_int80)
        "push 0",           // Fake error code placeholder
        "push rax",         // save syscall number (live: rax)  → [rsp+64]
        "push rcx",         // save NT a1          (live: rcx)  → [rsp+56]
        "push rdx",         // save NT a2          (live: rdx)  → [rsp+48]
        "push rsi",         // callee-saved                     → [rsp+40]
        "push rdi",         // callee-saved                     → [rsp+32]
        "push r8",          // save NT a3          (live: r8)   → [rsp+24]
        "push r9",          // save NT a4          (live: r9)   → [rsp+16]
        "push r10",         // callee-saved                     → [rsp+8]
        "push r11",         // callee-saved                     → [rsp+0]

        // Map NT ABI → C calling convention.
        // Use live register values (push does not change source register).
        // Order is carefully chosen to avoid read-after-write clobbers:
        "mov rdi, rax",     // C arg1 = num  (rax still live)
        "mov rsi, rcx",     // C arg2 = a1   (rcx still live; rsi was saved)
        // rdx stays as-is  (C arg3 = a2; rdx == NT a2)
        "mov rcx, r8",      // C arg4 = a3   (r8 still live; clobbers rcx — already saved)
        "mov r8, r9",       // C arg5 = a4   (r9 still live; r8 already consumed above)
        "xor r9, r9",       // C arg6 = a5 = 0

        "call {dispatch}",

        // Store return value over saved rax slot so pop rax gives return value
        "mov [rsp + 64], rax",

        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",          // NT service return value (NTSTATUS)
        "add rsp, 8",       // pop fake error code
        "iretq",

        dispatch = sym crate::nt::dispatch_nt_int2e,
    );
}