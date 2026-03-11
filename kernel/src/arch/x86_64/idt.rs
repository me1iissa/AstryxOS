//! Interrupt Descriptor Table (IDT) for x86_64.
//!
//! Handles CPU exceptions and hardware interrupts.
//! Supports IST (Interrupt Stack Table) for critical exceptions.

use core::arch::asm;
use spin::Once;

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

        // SAFETY: We're in single-threaded init. Setting up IDT entries.
        unsafe {
            // CPU exceptions (0-31)
            IDT[0].set_handler(isr_divide_error as *const () as u64, kernel_cs, 0, 0);
            IDT[1].set_handler(isr_debug as *const () as u64, kernel_cs, 0, 0);
            IDT[2].set_handler(isr_nmi as *const () as u64, kernel_cs, 0, 0);
            IDT[3].set_handler(isr_breakpoint as *const () as u64, kernel_cs, 0, 3); // Allow from userspace
            IDT[4].set_handler(isr_overflow as *const () as u64, kernel_cs, 0, 0);
            IDT[5].set_handler(isr_bound_range as *const () as u64, kernel_cs, 0, 0);
            IDT[6].set_handler(isr_invalid_opcode as *const () as u64, kernel_cs, 0, 0);
            IDT[7].set_handler(isr_device_not_available as *const () as u64, kernel_cs, 0, 0);
            IDT[8].set_handler(isr_double_fault as *const () as u64, kernel_cs, 2, 0); // IST 2 for double fault
            IDT[10].set_handler(isr_invalid_tss as *const () as u64, kernel_cs, 0, 0);
            IDT[11].set_handler(isr_segment_not_present as *const () as u64, kernel_cs, 0, 0);
            IDT[12].set_handler(isr_stack_segment as *const () as u64, kernel_cs, 0, 0);
            IDT[13].set_handler(isr_general_protection as *const () as u64, kernel_cs, 0, 0);
            IDT[14].set_handler(isr_page_fault as *const () as u64, kernel_cs, 0, 0);
            IDT[16].set_handler(isr_x87_fp as *const () as u64, kernel_cs, 0, 0);
            IDT[17].set_handler(isr_alignment_check as *const () as u64, kernel_cs, 0, 0);
            IDT[18].set_handler(isr_machine_check as *const () as u64, kernel_cs, 0, 0);
            IDT[19].set_handler(isr_simd_fp as *const () as u64, kernel_cs, 0, 0);

            // Hardware IRQs (32-47) — set up in irq module
            // IRQ0 (timer) = vector 32
            // IRQ1 (keyboard) = vector 33
            // etc.
            IDT[32].set_handler(super::irq::irq_timer_handler as *const () as u64, kernel_cs, 0, 0);
            IDT[33].set_handler(super::irq::irq_keyboard_handler as *const () as u64, kernel_cs, 0, 0);
            IDT[43].set_handler(super::irq::irq_e1000_handler as *const () as u64, kernel_cs, 0, 0);
            IDT[44].set_handler(super::irq::irq_mouse_handler as *const () as u64, kernel_cs, 0, 0);

            // Syscall interrupt (vector 0x80) — for int 0x80 style syscalls
            IDT[0x80].set_handler(isr_syscall_int80 as *const () as u64, kernel_cs, 0, 3);

            // NT syscall gate (vector 0x2E) — Windows INT 0x2E compatibility
            IDT[0x2E].set_handler(isr_syscall_int2e as *const () as u64, kernel_cs, 0, 3);

            // Load IDT
            let idt_ptr = IdtPointer {
                limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
                base: (&raw const IDT) as *const IdtEntry as u64,
            };
            asm!(
                "lidt [{}]",
                in(reg) &idt_ptr,
                options(readonly, nostack, preserves_flags)
            );
        }
    });

    crate::serial_println!("[IDT] Initialized with {} vectors", IDT_ENTRIES);
}

// ============================================================
// Exception handlers (naked functions to properly save state)
// ============================================================

/// Common exception handler called from stubs.
#[no_mangle]
extern "C" fn exception_handler(vector: u64, error_code: u64, frame: &InterruptFrame) {
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

        if handle_page_fault(cr2, error_code, frame) {
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

        // If the fault came from Ring 3, kill the process instead of halting
        if error_code & 4 != 0 {
            crate::serial_println!("  Killing user process (page fault in Ring 3)");
            crate::proc::exit_thread(-11i64); // SIGSEGV
            return;
        }

        // Kernel-mode page fault — print CPU context before halting
        let cpu_id = crate::arch::x86_64::apic::current_apic_id();
        let tid = crate::proc::current_tid();
        let cr3: u64;
        unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)); }
        crate::serial_println!(
            "  KERNEL FAULT: CPU={} TID={} CR3={:#x} (halting this CPU)",
            cpu_id, tid, cr3
        );
        loop {
            unsafe { asm!("cli; hlt", options(nomem, nostack)); }
        }
    }

    crate::serial_println!(
        "\n!!! Exception #{}: {} (error_code=0x{:x})",
        vector,
        name,
        error_code
    );
    crate::serial_println!("  RIP: 0x{:016x}", frame.rip);
    crate::serial_println!("  CS:  0x{:04x}", frame.cs);
    crate::serial_println!("  RFLAGS: 0x{:016x}", frame.rflags);
    crate::serial_println!("  RSP: 0x{:016x}", frame.rsp);
    crate::serial_println!("  SS:  0x{:04x}", frame.ss);

    if vector == 3 {
        // Breakpoint — continue execution
        return;
    }

    // If the fault came from Ring 3, kill the process instead of halting
    if frame.cs & 3 == 3 {
        crate::serial_println!("  Killing user process (exception in Ring 3)");
        crate::proc::exit_thread(-(vector as i64));
        return;
    }

    // Fatal kernel exception — halt
    loop {
        unsafe {
            asm!("cli; hlt", options(nomem, nostack));
        }
    }
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
fn handle_page_fault(faulting_addr: u64, error_code: u64, _frame: &InterruptFrame) -> bool {
    let is_present = error_code & 1 != 0;
    let is_write = error_code & 2 != 0;
    let _is_user = error_code & 4 != 0;

    let pid = crate::proc::recover_current_pid();

    // Look up the faulting address in the process's VmSpace
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return false,
    };

    let vm_space = match proc.vm_space.as_mut() {
        Some(vs) => vs,
        None => return false, // No VmSpace — can't handle
    };

    let vma = match vm_space.find_vma(faulting_addr) {
        Some(v) => v,
        None => return false, // Fault outside any VMA — SIGSEGV
    };

    // Check permission: write to non-writable VMA?
    if is_write && (vma.prot & crate::mm::vma::PROT_WRITE == 0) {
        return false; // Permission denied — SIGSEGV
    }

    let page_addr = crate::mm::vma::page_align_down(faulting_addr);
    let page_flags = vma.to_page_flags();
    let cr3 = vm_space.cr3;

    if !is_present {
        // === Demand Paging: page not yet mapped ===

        // For file-backed VMAs we must drop the PROCESS_TABLE lock before
        // accessing the VFS (which takes MOUNTS), so extract the info first.
        let file_info = match &vma.backing {
            crate::mm::vma::VmBacking::File { mount_idx, inode, offset } => {
                Some((*mount_idx, *inode, *offset, vma.base))
            }
            _ => None,
        };

        if let Some((mount_idx, inode, file_base_offset, vma_base)) = file_info {
            // Release PROCESS_TABLE to avoid deadlock with MOUNTS.
            drop(procs);

            let page_offset_in_vma = page_addr - vma_base;
            let file_page_offset = file_base_offset + page_offset_in_vma;

            // 1. Check the page cache
            if let Some(cached_phys) = crate::mm::cache::lookup(mount_idx, inode, file_page_offset) {
                crate::mm::refcount::page_ref_inc(cached_phys);
                crate::mm::vmm::map_page_in(cr3, page_addr, cached_phys, page_flags);
                crate::mm::vmm::invlpg(page_addr);
                return true;
            }

            // 2. Not cached — allocate a page, read from the filesystem
            if let Some(phys) = crate::mm::pmm::alloc_page() {
                unsafe {
                    core::ptr::write_bytes(phys as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
                }

                // Read file data into the page.
                {
                    let mounts = crate::vfs::MOUNTS.lock();
                    if mount_idx < mounts.len() {
                        let buf = unsafe {
                            core::slice::from_raw_parts_mut(
                                phys as *mut u8,
                                crate::mm::pmm::PAGE_SIZE,
                            )
                        };
                        let _ = mounts[mount_idx].fs.read(inode, file_page_offset, buf);
                    }
                }

                // Insert into the page cache (gives cache its own refcount).
                crate::mm::cache::insert(mount_idx, inode, file_page_offset, phys);
                // Add a mapping reference.
                crate::mm::refcount::page_ref_inc(phys);

                crate::mm::vmm::map_page_in(cr3, page_addr, phys, page_flags);
                crate::mm::vmm::invlpg(page_addr);
                return true;
            }
            return false; // OOM
        }

        match &vma.backing {
            crate::mm::vma::VmBacking::Anonymous => {
                // Allocate a zeroed page
                if let Some(phys) = crate::mm::pmm::alloc_page() {
                    unsafe {
                        core::ptr::write_bytes(phys as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
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

    if is_present && is_write {
        // === Copy-on-Write: page is mapped but read-only, VMA says writable ===
        let pte = crate::mm::vmm::read_pte(cr3, page_addr);
        let old_phys = pte & 0x000F_FFFF_FFFF_F000;

        if crate::mm::refcount::page_ref_count(old_phys) > 1 {
            // Shared page — make a private copy
            if let Some(new_phys) = crate::mm::pmm::alloc_page() {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        old_phys as *const u8,
                        new_phys as *mut u8,
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
            let new_pte = (old_phys) | page_flags | crate::mm::vmm::PAGE_PRESENT;
            crate::mm::vmm::write_pte(cr3, page_addr, new_pte);
            crate::mm::vmm::invlpg(page_addr);
            return true;
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