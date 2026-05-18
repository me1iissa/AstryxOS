//! Interrupt Descriptor Table (IDT) for x86_64.
//!
//! Handles CPU exceptions and hardware interrupts.
//! Supports IST (Interrupt Stack Table) for critical exceptions.

extern crate alloc;

use alloc::sync::Arc;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

/// Global page fault counter for heartbeat diagnostics.
static PAGE_FAULT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub fn page_fault_count() -> u64 { PAGE_FAULT_TOTAL.load(Ordering::Relaxed) }

/// W215 H3a diagnostic: number of times a writable PTE install aliased a
/// physical frame that is simultaneously held as a *different* key in the page
/// cache.  A non-zero value means some caller is installing a PAGE_WRITABLE PTE
/// whose backing frame the cache knows under a different (mount,inode,offset)
/// tuple — i.e., a MAP_SHARED+PROT_WRITE mapping of a cache-resident file page,
/// where the installer's intent differs from the cache's recorded key.
///
/// Only armed in `firefox-test` builds; zero cost in all others.
#[cfg(feature = "firefox-test")]
pub(crate) static PFH_WRITABLE_ALIAS_CACHE: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "firefox-test")]
pub fn pfh_writable_alias_cache_count() -> u64 {
    PFH_WRITABLE_ALIAS_CACHE.load(Ordering::Relaxed)
}

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
            IDT[45].set_handler(fix(super::irq::irq_virtio_blk_handler as *const () as u64), kernel_cs, 0, 0);
            IDT[46].set_handler(fix(super::irq::irq_virtio_serial_handler as *const () as u64), kernel_cs, 0, 0);

            // Cross-CPU TLB shootdown IPI (vector 0xF0).  Sender is the
            // remote CPU that just rewrote a PTE; this handler runs the
            // local invalidation and acks the per-CPU payload slot.
            // See `mm/tlb.rs` and Intel SDM Vol 3A §10.6.1.
            IDT[0xF0].set_handler(fix(super::irq::irq_tlb_shootdown_handler as *const () as u64), kernel_cs, 0, 0);

            // W215 Arm-1 DR0/DR7 sync IPI (vector 0xF1).  Per Intel SDM
            // Vol. 3B §17.2.4, DR0–DR3 are per-CPU; this vector lets the
            // sender CPU publish a new (addr, ctrl) pair and have every
            // online CPU pick it up by reprogramming its own DRs.
            // Diagnostic-only; gated on `w215-diag` (superset of
            // `firefox-test`).  When the feature is off the vector
            // stays unassigned and the spurious-IRQ handler catches any
            // stray IPI — see the IPI-broadcast `cpu_count` invariant.
            #[cfg(feature = "w215-diag")]
            IDT[0xF1].set_handler(fix(super::irq::irq_w215_dr_sync_handler as *const () as u64), kernel_cs, 0, 0);

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
    // W215 Arm-1 diagnostic: a `#DB` (vector 1) trap may originate from the
    // hardware write-watchpoint armed by the cache CRC walker.  Dispatch
    // to the W215 handler first; if it consumes the trap, return to the
    // interrupted RIP without printing any further diagnostics.  Per
    // Intel SDM Vol. 3B §17.2.5 (Debug Status Register DR6), B0..B3
    // identify which DRn triggered.  Diagnostic-only; gated on
    // `w215-diag` so non-diagnostic builds carry no DR0 dispatch.
    #[cfg(feature = "w215-diag")]
    if vector == 1 {
        if crate::arch::x86_64::debug_reg::handle_db_exception(
            frame.rip, frame.rsp, frame.rflags, frame.cs,
        ) {
            return;
        }
    }

    // Debug trace for non-page-fault exceptions from user mode.
    if frame.cs & 3 == 3 && vector != 14 {
        crate::serial_println!(
            "[EXC] vec={} err={:#x} RIP={:#x} CS={:#x} RSP={:#x}",
            vector, error_code, frame.rip, frame.cs, frame.rsp
        );
        // For GP fault from dlerror (known crash site): dump GOT and ld-linux state.
        // RIP=0x7effffae4c7c is libc dlerror "call *0x378(%r13)" where r13 = _rtld_global_ro ptr.
        // Dump the libc GOT slot (at libc_base + 0x202eb0) and the ld-linux .data.rel.ro page
        // at the function pointer slot (ld_base + 0x37e18) to diagnose relocation failures.
        if vector == 13 {
            // SAFETY: current_tid() is a lock-free atomic read — safe in ISR context.
            // Do NOT call current_pid() here: it acquires THREAD_TABLE lock which can
            // deadlock if the exception fires while another CPU holds that lock.
            let tid = crate::proc::current_tid();
            let cr3: u64;
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)); }
            // Dump 16 qwords around the RSP to see the call stack.
            let rsp = frame.rsp;
            crate::serial_println!("[GPF-DBG] tid={} RSP={:#x} CR3={:#x}", tid, rsp, cr3);
            for i in 0..8usize {
                let addr = rsp + (i * 8) as u64;
                if let Some(phys) = crate::mm::vmm::virt_to_phys_in(cr3, addr) {
                    let val = unsafe {
                        core::ptr::read_volatile(
                            (0xFFFF_8000_0000_0000u64 + phys) as *const u64
                        )
                    };
                    crate::serial_println!("[GPF-DBG]   [RSP+{:#03x}]={:#018x}", i*8, val);
                }
            }
            // Dump relevant addresses: libc base detection via known RIP offset
            // and ld-linux base at INTERP_BASE=0x7F00_0000_0000.
            let ldlinux_relro_slot: u64 = 0x7F00_0003_7e18; // _rtld_global_ro+0x378
            if let Some(phys) = crate::mm::vmm::virt_to_phys_in(cr3, ldlinux_relro_slot) {
                let val = unsafe {
                    core::ptr::read_volatile(
                        (0xFFFF_8000_0000_0000u64 + phys) as *const u64
                    )
                };
                crate::serial_println!("[GPF-DBG] ldlinux[0x37e18]={:#018x} (should=0x7F00_0000_1640)", val);
            } else {
                crate::serial_println!("[GPF-DBG] ldlinux[0x37e18]=UNMAPPED");
            }
            // Libc GOT slot: libc_base = RIP - 0x97c7c, GOT_slot = libc_base + 0x202eb0
            if frame.rip >= 0x97c7c {
                let libc_base = frame.rip - 0x97c7c;
                let got_slot = libc_base + 0x202eb0;
                crate::serial_println!("[GPF-DBG] libc_base={:#x} got_slot={:#x}", libc_base, got_slot);
                if let Some(phys) = crate::mm::vmm::virt_to_phys_in(cr3, got_slot) {
                    let val = unsafe {
                        core::ptr::read_volatile(
                            (0xFFFF_8000_0000_0000u64 + phys) as *const u64
                        )
                    };
                    crate::serial_println!("[GPF-DBG] libc.GOT[_rtld_global_ro]={:#018x} (should=0x7F00_0003_7aa0)", val);
                } else {
                    crate::serial_println!("[GPF-DBG] libc.GOT[_rtld_global_ro]=UNMAPPED");
                }
            }
        }
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

        // ── Tier-0 trace: one self-contained line per page fault ─────────────
        // Emitted BEFORE resolution so we see every fault, not just unresolved
        // ones.  Grepped by qemu-harness.py via `^\[PF\] `.
        //
        // We read tid from per-CPU atomics only and resolve pid via a
        // try-locked walk of THREAD_TABLE.  If the lock is contended (e.g.
        // the fault happened while another CPU is editing the thread table),
        // we emit `pid=?` rather than block — the trace is diagnostic, not
        // load-bearing.
        #[cfg(feature = "pf-trace")]
        {
            let tid = crate::proc::current_tid();
            // Resolve pid without blocking: if THREAD_TABLE is contended we
            // emit pid=0 rather than deadlock.  Trace is diagnostic-only.
            let pid = match crate::proc::THREAD_TABLE.try_lock() {
                Some(threads) => threads.iter()
                    .find(|t| t.tid == tid).map(|t| t.pid).unwrap_or(0),
                None => 0,
            };
            crate::serial_println!(
                "[PF] cr2={:#x} rip={:#x} code={:#x} pid={} tid={}",
                cr2, frame.rip, error_code, pid, tid,
            );
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

        // ── SMAP-fault triage ─────────────────────────────────────────────
        // Per Intel SDM Vol. 3A §4.6, when CR4.SMAP=1 and EFLAGS.AC=0, a
        // supervisor-mode access to a user-mapped page (PTE.U=1) faults with
        // the same #PF error-code shape as an ordinary access fault.  The
        // CoW / demand-paging arms below "resolve" such a fault by tweaking
        // the PTE, but the PTE was never the problem — AC=0 is — so the
        // retry on IRET re-fires the same fault.  Result: 400M+ #PF / sec
        // until the scheduler watchdog bugchecks (observed: PID 2 glxtest
        // stuck >60K ticks at CR2=0x7ffffffedfe8).  Catch the loop here:
        // when the fault is from supervisor mode (error bit 2 clear) AND
        // SMAP is enabled AND the faulting frame had AC=0 AND the PTE has
        // U=1 AND the CR2 is a user-half address, this is a kernel bug —
        // a kernel codepath dereferenced a user pointer without bracketing
        // it in `crate::arch::x86_64::smap::UserGuard`.  Surface the RIP
        // and bugcheck so the offending site is named in the dump rather
        // than burning the CPU in a silent retry storm.
        if (error_code & 4) == 0
            && crate::arch::x86_64::smap::SMAP_ENABLED.load(Ordering::Relaxed)
            && (frame.rflags & (1u64 << 18)) == 0
            && cr2 < 0x0000_8000_0000_0000
        {
            // Inspect the PTE: only flag this as SMAP if the page is user-mapped
            // (PTE.U=1).  A supervisor access to a kernel page (PTE.U=0) is a
            // genuine kernel bug of a different class (e.g. NULL deref); let
            // the normal handler path take it through the bugcheck.
            let cr3_now: u64;
            unsafe { asm!("mov {}, cr3", out(reg) cr3_now, options(nomem, nostack, preserves_flags)); }
            let page_addr = cr2 & !0xFFF;
            let pte = crate::mm::vmm::read_pte(cr3_now, page_addr);
            // PAGE_USER = 1 << 2; PAGE_PRESENT = 1 << 0.
            if pte & 1 != 0 && pte & 4 != 0 {
                // Dump the ISR-saved GPRs BEFORE invoking ke_bugcheck (which
                // clobbers them).  Layout per isr_with_error macro:
                //   frame[-2]=rax  frame[-3]=rcx  frame[-4]=rdx  frame[-5]=rsi
                //   frame[-6]=rdi  frame[-7]=r8   frame[-8]=r9   frame[-9]=r10
                //   frame[-10]=r11 frame[-11]=rbx frame[-12]=rbp frame[-13]=r12
                //   frame[-14]=r13 frame[-15]=r14 frame[-16]=r15
                // The faulting RIP almost always pinpoints the inner copy
                // primitive; the caller is recovered from RDI/RSI (the
                // copy_nonoverlapping dst/src) and the RBP-chain backtrace.
                let base = frame as *const InterruptFrame as *const u64;
                let (rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11,
                     rbx, rbp, r12, r13, r14, r15) = unsafe {(
                    *base.sub(2),  *base.sub(3),  *base.sub(4),
                    *base.sub(5),  *base.sub(6),  *base.sub(7),
                    *base.sub(8),  *base.sub(9),  *base.sub(10),
                    *base.sub(11), *base.sub(12), *base.sub(13),
                    *base.sub(14), *base.sub(15), *base.sub(16),
                )};
                crate::serial_println!(
                    "\n[SMAP/FAULT] supervisor access to user page \
                     cr2={:#x} rip={:#x} code={:#x} pte={:#x} cr3={:#x} \
                     rflags={:#x} cpu={} pid={} tid={}",
                    cr2, frame.rip, error_code, pte, cr3_now, frame.rflags,
                    crate::arch::x86_64::apic::cpu_index(),
                    crate::proc::current_pid_lockless(),
                    crate::proc::current_tid(),
                );
                crate::serial_println!(
                    "[SMAP/FAULT/regs] rax={:#018x} rcx={:#018x} rdx={:#018x} rsi={:#018x}",
                    rax, rcx, rdx, rsi);
                crate::serial_println!(
                    "[SMAP/FAULT/regs] rdi={:#018x} r8 ={:#018x} r9 ={:#018x} r10={:#018x}",
                    rdi, r8, r9, r10);
                crate::serial_println!(
                    "[SMAP/FAULT/regs] r11={:#018x} rbx={:#018x} rbp={:#018x} r12={:#018x}",
                    r11, rbx, rbp, r12);
                crate::serial_println!(
                    "[SMAP/FAULT/regs] r13={:#018x} r14={:#018x} r15={:#018x} rsp={:#018x}",
                    r13, r14, r15, frame.rsp);
                // Walk a few kernel return addresses from the saved RBP so
                // the caller chain is visible without GDB attach.  Stops at
                // first non-canonical / unmapped frame.
                {
                    let mut bp = rbp;
                    for depth in 0..8 {
                        if bp == 0 || bp < 0xFFFF_8000_0000_0000
                                   || bp > 0xFFFF_FFFF_FFFF_F000 {
                            break;
                        }
                        let saved_rip = unsafe {
                            core::ptr::read_volatile((bp + 8) as *const u64)
                        };
                        let next_bp = unsafe {
                            core::ptr::read_volatile(bp as *const u64)
                        };
                        crate::serial_println!(
                            "[SMAP/FAULT/bt] #{} rbp={:#x} ret={:#x}",
                            depth, bp, saved_rip);
                        if next_bp <= bp { break; }
                        bp = next_bp;
                    }
                }
                // RBP may be 0 or a non-pointer (memcpy's `rep` setup blows
                // it away in many compilations).  As a fallback dump a few
                // u64s near the top of the kernel stack — the immediate
                // memcpy caller's return address is at [RSP] (it pushed
                // nothing) and surrounding slots often pin the actual
                // calling frame for slow-stepping.
                {
                    let ksp = frame.rsp;
                    if ksp >= 0xFFFF_8000_0000_0000 && ksp < 0xFFFF_FFFF_FFFF_F000 {
                        for i in 0..16usize {
                            let addr = ksp + (i * 8) as u64;
                            let v = unsafe {
                                core::ptr::read_volatile(addr as *const u64)
                            };
                            crate::serial_println!(
                                "[SMAP/FAULT/stk] +{:#04x} {:#x} = {:#x}",
                                i*8, addr, v);
                        }
                    }
                }
                crate::ke::bugcheck::ke_bugcheck(
                    crate::ke::bugcheck::BUGCHECK_KERNEL_PAGE_FAULT,
                    cr2,
                    error_code,
                    frame.rip,
                    pte,
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

        // Dump all 16 user GPRs saved on the ISR stack (below the InterruptFrame).
        //
        // isr_with_error push order (see macro comment for full layout):
        //   rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11, rbx, rbp, r12, r13, r14, r15
        // frame[-1]=error_code, frame[-2]=rax, ..., frame[-16]=r15
        if error_code & 4 != 0 {
            let base = frame as *const InterruptFrame as *const u64;
            let (rax, rcx, rdx, rsi, rdi, r8,
                 r9,  r10, r11, rbx, rbp, r12, r13, r14, r15,
                 fs_base, gs_base) = unsafe {
                let rax = *base.sub(2);
                let rcx = *base.sub(3);
                let rdx = *base.sub(4);
                let rsi = *base.sub(5);
                let rdi = *base.sub(6);
                let r8  = *base.sub(7);
                let r9  = *base.sub(8);
                let r10 = *base.sub(9);
                let r11 = *base.sub(10);
                let rbx = *base.sub(11);
                let rbp = *base.sub(12);
                let r12 = *base.sub(13);
                let r13 = *base.sub(14);
                let r14 = *base.sub(15);
                let r15 = *base.sub(16);
                // FS.base (IA32_FS_BASE, MSR 0xC000_0100) — used for TLS base
                // Intel SDM Vol 3A §10.6: RDMSR is safe at CPL 0.
                let fs_base = crate::hal::rdmsr(0xC000_0100);
                // GS.base (IA32_GS_BASE, MSR 0xC000_0101) — used for per-CPU/TLS
                let gs_base = crate::hal::rdmsr(0xC000_0101);
                (rax, rcx, rdx, rsi, rdi, r8,
                 r9, r10, r11, rbx, rbp, r12, r13, r14, r15,
                 fs_base, gs_base)
            };
            crate::serial_println!(
                "[#PF/regs] rax={:#018x} rcx={:#018x} rdx={:#018x} rsi={:#018x}",
                rax, rcx, rdx, rsi
            );
            crate::serial_println!(
                "[#PF/regs] rdi={:#018x} r8 ={:#018x} r9 ={:#018x} r10={:#018x}",
                rdi, r8, r9, r10
            );
            crate::serial_println!(
                "[#PF/regs] r11={:#018x} rbx={:#018x} rbp={:#018x} r12={:#018x}",
                r11, rbx, rbp, r12
            );
            crate::serial_println!(
                "[#PF/regs] r13={:#018x} r14={:#018x} r15={:#018x}",
                r13, r14, r15
            );
            crate::serial_println!(
                "[#PF/regs] fs_base={:#018x} gs_base={:#018x}",
                fs_base, gs_base
            );
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
            // Walk the RBP-linked frame chain to emit a caller-chain backtrace.
            // RBP is saved at frame[-12] by the ISR push sequence:
            //   frame[-2]=rax … frame[-11]=rbx frame[-12]=rbp (see isr_with_error layout).
            // Per System V AMD64 ABI §3.4.1, with -fno-omit-frame-pointer each
            // frame satisfies [rbp+0]=saved_rbp, [rbp+8]=return_address.
            {
                let base = frame as *const InterruptFrame as *const u64;
                let rbp_at_fault = unsafe { *base.sub(12) };
                let pid = crate::proc::current_pid_lockless();
                let tid = crate::proc::current_tid();
                crate::proc::stack_walk::stack_walk_user(pid, tid, frame.rip, rbp_at_fault);
            }
            // Aliasing-detection diagnostic: emit [FAULT/PHYS] +
            // [FAULT/RIP-CONTENT] so two trials with the same vma_offset
            // can be cross-checked for physical-frame identity.  Different
            // rip_phys at the same vma_offset proves the libxul code page
            // is aliased into multiple address spaces (W196 / W190-H_A).
            // Cite: Intel SDM Vol. 3A §4.10 (paging-structure caches).
            {
                let cr3_now: u64;
                unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3_now, options(nomem, nostack, preserves_flags)); }
                let pid = crate::proc::current_pid_lockless();
                crate::signal::emit_fault_phys_for_fatal(pid, frame.rip, cr2, cr3_now);
            }
            // POSIX signal(7): the default action for SIGSEGV is "terminate
            // the process (core dump)" — the entire thread group, not just
            // the faulting thread.  Calling exit_thread would leave sibling
            // threads parked on the dead thread's condvars / semaphores /
            // futexes indefinitely.  Use exit_group so the whole thread
            // group is torn down.
            //
            // Invalidate the per-CPU saved-syscall-frame pointer first: we
            // did NOT pass through `syscall_entry`, so any value still
            // sitting in `frame_rsp` belongs to a prior syscall on this CPU
            // and points at kernel memory that has since been reused.  The
            // firefox-test diagnostic dump inside `exit_group` reads that
            // slot via `syscall::get_user_rsp_rbp()`; without this clear
            // the deref produced a KERNEL_PAGE_FAULT bugcheck (W86).
            crate::syscall::invalidate_syscall_frame();
            crate::proc::exit_group(-11i64); // SIGSEGV
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
        // Print all 16 saved GPRs from ISR stack for debugging.
        // See isr_with_error / isr_no_error macro comments for the full stack layout.
        // frame[-1]=error_code, frame[-2]=rax, ..., frame[-16]=r15
        let base = frame as *const InterruptFrame as *const u64;
        let (rax, rcx, rdx, rsi, rdi, r8,
             r9, r10, r11, rbx, rbp, r12, r13, r14, r15) = unsafe {
            (
                *base.sub(2),   // RAX
                *base.sub(3),   // RCX
                *base.sub(4),   // RDX
                *base.sub(5),   // RSI
                *base.sub(6),   // RDI
                *base.sub(7),   // R8
                *base.sub(8),   // R9
                *base.sub(9),   // R10
                *base.sub(10),  // R11
                *base.sub(11),  // RBX
                *base.sub(12),  // RBP
                *base.sub(13),  // R12
                *base.sub(14),  // R13
                *base.sub(15),  // R14
                *base.sub(16),  // R15
            )
        };
        crate::serial_println!(
            "  [exc/regs] rax={:#018x} rcx={:#018x} rdx={:#018x} rsi={:#018x}",
            rax, rcx, rdx, rsi);
        crate::serial_println!(
            "  [exc/regs] rdi={:#018x} r8 ={:#018x} r9 ={:#018x} r10={:#018x}",
            rdi, r8, r9, r10);
        crate::serial_println!(
            "  [exc/regs] r11={:#018x} rbx={:#018x} rbp={:#018x} r12={:#018x}",
            r11, rbx, rbp, r12);
        crate::serial_println!(
            "  [exc/regs] r13={:#018x} r14={:#018x} r15={:#018x}",
            r13, r14, r15);
        crate::serial_println!("  Killing user process (exception in Ring 3)");

        // For Ring-3 #UD (vector 6) emit three diagnostic lines:
        //
        //   [UD/VMA]       — VMA range + ELF virtual address for addr2line
        //   [UD/RIP-BYTES] — 16 bytes at RIP (distinguishes ud2/vtable/garbage)
        //   [UD/RDI-BYTES] — 64 bytes at RDI (C++ `this` pointer; vtable at [0])
        //
        // Together the three lines let an investigator run addr2line directly on
        // `vaddr_in_elf` without offline arithmetic, identify whether the fault
        // is a `ud2` (0f 0b) macro, a vtable dispatch (48 8b 07 ff 60 XX), or a
        // mid-instruction jump to garbage, and inspect the object header for
        // heap-corruption signatures (0xe2e2..., 0xdeadbeef, NUL pad, etc.).
        //
        // Lock ordering: PROCESS_TABLE is not held on any path that delivers a
        // Ring-3 #UD; the snapshot and byte reads are done before the lock is
        // dropped and before invalidate_syscall_frame / exit_group.
        //
        // RIP/RDI reads use virt_to_phys_in + PHYS_OFF — the same safe-user-read
        // pattern used elsewhere in this file.  A non-canonical or unmapped
        // address emits `unmapped_or_fault` rather than panicking.
        if vector == 6 {
            // Read current CR3 for user page-table walks.
            let ud_cr3: u64;
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) ud_cr3, options(nomem, nostack)); }

            let rip = frame.rip;
            let pid = crate::proc::current_pid_lockless();
            let tid = crate::proc::current_tid();
            let procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc_entry) = procs.iter().find(|p| p.pid == pid) {
                if let Some(vm_space) = proc_entry.vm_space.as_ref() {
                    if let Some(vma) = vm_space.find_vma(rip) {
                        use crate::mm::vma::VmBacking;
                        let (file_name, file_offset, elf_load_delta) = match &vma.backing {
                            VmBacking::File { offset, elf_load_delta, .. } => {
                                (vma.name, *offset, *elf_load_delta)
                            }
                            _ => ("<anon>", 0u64, 0u64),
                        };
                        let offset_in_vma  = rip - vma.base;
                        let offset_in_file = file_offset + offset_in_vma;
                        // vaddr_in_elf: the link-time ELF virtual address, i.e. the
                        // value addr2line expects.  Defined by ELF-64 §3 (Program
                        // Loading): for each PT_LOAD segment, runtime_va - bias =
                        // p_vaddr, and file_offset = p_offset + (runtime_va - bias -
                        // p_vaddr + p_offset_page).  The delta encodes
                        // (p_vaddr_page - p_offset_page) which is constant for the
                        // segment.
                        if elf_load_delta != 0 {
                            let vaddr_in_elf = offset_in_file.wrapping_add(elf_load_delta);
                            crate::serial_println!(
                                "[UD/VMA] pid={} tid={} rip={:#x} vma_base={:#x} vma_end={:#x} \
                                 file={} offset_in_file={:#x} offset_in_vma={:#x} vaddr_in_elf={:#x}",
                                pid, tid, rip, vma.base, vma.end(),
                                file_name, offset_in_file, offset_in_vma, vaddr_in_elf,
                            );
                        } else {
                            crate::serial_println!(
                                "[UD/VMA] pid={} tid={} rip={:#x} vma_base={:#x} vma_end={:#x} \
                                 file={} offset_in_file={:#x} offset_in_vma={:#x}",
                                pid, tid, rip, vma.base, vma.end(),
                                file_name, offset_in_file, offset_in_vma,
                            );
                        }
                    } else {
                        crate::serial_println!(
                            "[UD/VMA] pid={} tid={} rip={:#x} no_vma_match=1",
                            pid, tid, rip,
                        );
                    }
                }
            }
            // Drop PROCESS_TABLE — all subsequent work uses ud_cr3 directly.
            drop(procs);

            // ── [UD/RIP-BYTES]: 16 bytes at RIP ────────────────────────────────
            // Allows instant classification:
            //   0f 0b      → ud2 (MOZ_CRASH / MOZ_RELEASE_ASSERT macro)
            //   48 8b 07 ff 60 XX → vtable slot XX/8 indirect call (C++ vtable dispatch)
            //   other      → mid-instruction jump-to-garbage / stack smash / etc.
            //
            // Intel SDM Vol 2B §4.3: UD2 encoding is 0F 0B.
            {
                const N: usize = 16;
                const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
                const KERNEL_BASE: u64 = 0x0000_8000_0000_0000;

                if rip < KERNEL_BASE {
                    let mut buf = [0u8; N];
                    let mut got = 0usize;
                    for i in 0..N {
                        let va = rip.wrapping_add(i as u64);
                        if va >= KERNEL_BASE { break; }
                        match crate::mm::vmm::virt_to_phys_in(ud_cr3, va) {
                            Some(phys) => {
                                buf[i] = unsafe {
                                    core::ptr::read_volatile((PHYS_OFF + phys) as *const u8)
                                };
                                got += 1;
                            }
                            None => break,
                        }
                    }
                    if got > 0 {
                        // Format as space-separated hex pairs (e.g. "0f 0b 66 2e").
                        let mut hex = [0u8; N * 3];
                        const HEX: &[u8] = b"0123456789abcdef";
                        for i in 0..got {
                            hex[i * 3]     = HEX[(buf[i] >> 4) as usize];
                            hex[i * 3 + 1] = HEX[(buf[i] & 0xF) as usize];
                            hex[i * 3 + 2] = b' ';
                        }
                        // SAFETY: hex contains only ASCII bytes from HEX + spaces.
                        let hex_str = unsafe {
                            core::str::from_utf8_unchecked(&hex[..got * 3 - 1])
                        };
                        crate::serial_println!(
                            "[UD/RIP-BYTES] rip={:#x} bytes={}",
                            rip, hex_str,
                        );
                    } else {
                        crate::serial_println!(
                            "[UD/RIP-BYTES] rip={:#x} unmapped_or_fault",
                            rip,
                        );
                    }
                }
            }

            // ── [UD/RDI-BYTES]: 64 bytes at RDI ────────────────────────────────
            // x86_64 System V ABI §3.2.3: the first integer/pointer argument
            // (and the C++ implicit `this` pointer for member functions) is
            // passed in %rdi.  The vtable pointer of a polymorphic C++ object
            // lives at offset 0 of `this`, so the first 8 bytes give the vtable
            // address.  The remaining bytes expose object fields that may show
            // heap-corruption patterns (0xe2e2…, 0xdeadbeef, ASCII slop).
            {
                const N: usize = 64;
                const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
                const KERNEL_BASE: u64 = 0x0000_8000_0000_0000;

                if rdi < KERNEL_BASE && rdi != 0 {
                    let mut buf = [0u8; N];
                    let mut got = 0usize;
                    for i in 0..N {
                        let va = rdi.wrapping_add(i as u64);
                        if va >= KERNEL_BASE { break; }
                        match crate::mm::vmm::virt_to_phys_in(ud_cr3, va) {
                            Some(phys) => {
                                buf[i] = unsafe {
                                    core::ptr::read_volatile((PHYS_OFF + phys) as *const u8)
                                };
                                got += 1;
                            }
                            None => break,
                        }
                    }
                    if got > 0 {
                        // Emit as four lines of 16 hex pairs each for readability.
                        const HEX: &[u8] = b"0123456789abcdef";
                        let rows = (got + 15) / 16;
                        for row in 0..rows {
                            let start = row * 16;
                            let end   = (start + 16).min(got);
                            let mut hex = [0u8; 16 * 3];
                            let row_len = end - start;
                            for i in 0..row_len {
                                hex[i * 3]     = HEX[(buf[start + i] >> 4) as usize];
                                hex[i * 3 + 1] = HEX[(buf[start + i] & 0xF) as usize];
                                hex[i * 3 + 2] = b' ';
                            }
                            let hex_str = unsafe {
                                core::str::from_utf8_unchecked(&hex[..row_len * 3 - 1])
                            };
                            crate::serial_println!(
                                "[UD/RDI-BYTES] rdi={:#x} off={:#x} bytes={}",
                                rdi, start, hex_str,
                            );
                        }
                    } else {
                        crate::serial_println!(
                            "[UD/RDI-BYTES] rdi={:#x} unmapped_or_fault",
                            rdi,
                        );
                    }
                } else if rdi == 0 {
                    crate::serial_println!("[UD/RDI-BYTES] rdi=0x0 null_this_pointer");
                } else {
                    crate::serial_println!(
                        "[UD/RDI-BYTES] rdi={:#x} kernel_address_skip",
                        rdi,
                    );
                }
            }
        }

        // Walk the RBP-linked frame chain to emit a caller-chain backtrace
        // before tearing down the process.  RBP is at frame[-12] in the
        // ISR push sequence (see isr_with_error / isr_no_error layout).
        // Per System V AMD64 ABI §3.4.1, with -fno-omit-frame-pointer each
        // frame satisfies [rbp+0]=saved_rbp, [rbp+8]=return_address.
        {
            let base = frame as *const InterruptFrame as *const u64;
            let rbp_at_fault = unsafe { *base.sub(12) };
            let pid = crate::proc::current_pid_lockless();
            let tid = crate::proc::current_tid();
            crate::proc::stack_walk::stack_walk_user(pid, tid, frame.rip, rbp_at_fault);
        }
        // Aliasing-detection diagnostic: emit [FAULT/PHYS] +
        // [FAULT/RIP-CONTENT] for fatal #UD/#GP/#AC so the same mismatch
        // test that applies to fatal #PF (Ring-3 SIGSEGV path above) also
        // covers exceptions whose terminal cause may be aliased text bytes
        // misinterpreted as opcodes.  cr2 has no meaning for non-#PF
        // vectors here, so pass 0.  Cite: Intel SDM Vol. 3A §4.10.
        {
            let cr3_now: u64;
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3_now, options(nomem, nostack, preserves_flags)); }
            let pid = crate::proc::current_pid_lockless();
            crate::signal::emit_fault_phys_for_fatal(pid, frame.rip, 0, cr3_now);
        }
        // POSIX signal(7): synchronous fatal CPU exceptions in user mode
        // (#DE → SIGFPE, #UD → SIGILL, #DF / #SS / #GP / #AC / #MC → SIGBUS|SIGSEGV)
        // default to thread-group termination.  Calling exit_thread would
        // leave sibling threads in the same process parked on condvars,
        // semaphores, or futexes that the dead thread was meant to signal.
        //
        // Invalidate the per-CPU saved-syscall-frame pointer first.  See
        // the matching call in the user-mode #PF SIGSEGV path above for
        // the full rationale: `exit_group`'s firefox-test diagnostic dump
        // reads `syscall::PER_CPU_SYSCALL[cpu].frame_rsp` which was set
        // by a prior syscall and now aliases freed-or-overwritten kernel
        // memory.  Without the clear, the dump's raw deref produced a
        // KERNEL_PAGE_FAULT bugcheck under firefox-test (W86).
        crate::syscall::invalidate_syscall_frame();
        crate::proc::exit_group(-(vector as i64));
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
    // Per-process PF counter.  Lockless: takes neither THREAD_TABLE nor
    // PROCESS_TABLE; one bounds-check + one Acquire load + one Relaxed
    // bump in the live-PID path.  Safe from interrupt context.
    {
        let _pf_pid = crate::proc::current_pid_lockless();
        if _pf_pid >= 1 {
            crate::proc::proc_metrics::bump_page_fault(_pf_pid);
        }
    }
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

    // Lockless PID lookup: the page-fault handler runs in interrupt context
    // (IF=0 on entry via the interrupt gate).  A kernel-mode #PF can fire
    // while a syscall on the same CPU already holds THREAD_TABLE — taking
    // the lock here would either deadlock the same CPU on its own held lock
    // (spin::Mutex is not reentrant) or, under panic=abort, surface a stuck
    // 0x01 lock byte forever after any earlier panic stranded the guard.
    // The per-CPU PID atomic is updated at every context switch (see
    // proc::set_current_pid) so this read is always current for a non-idle
    // thread.  An idle thread on this CPU (pid=0) has no VmSpace to consult,
    // so we bail out and let the existing PROCESS_TABLE.iter().find() miss
    // path return false.
    let pid = crate::proc::current_pid_lockless();

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

        // W216 H_5j-B (unified concurrency): sample VmSpace generation before
        // the CoW copy + install sequence.  A sibling CPU running
        // `sys_munmap` / `MAP_FIXED` Phase 2b / `MADV_DONTNEED` /
        // `clone_for_fork` can mutate the address space — and free `old_phys`
        // — while we are mid-copy.  Re-checking the generation immediately
        // before the install ensures we abort instead of installing a PTE
        // pointing at a frame the sibling has just queued for free.  See
        // `VmSpace::generation` doc-comment.
        let gen_at_start = vm_space.generation.load(core::sync::atomic::Ordering::Acquire);

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
                // Re-check generation right before install — Acquire pairs
                // with the Release fetch_add in `bump_generation_for_cr3`
                // and `VmSpace::*` mutators (Intel SDM Vol. 3A §8.2.3).
                let gen_now = vm_space.generation.load(core::sync::atomic::Ordering::Acquire);
                if gen_now != gen_at_start {
                    #[cfg(feature = "firefox-test")]
                    {
                        static CNT: core::sync::atomic::AtomicU64 =
                            core::sync::atomic::AtomicU64::new(0);
                        let n = CNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                        if n < 5 || n % 500 == 0 {
                            crate::serial_println!(
                                "[PF/gen-abort] COW-COPY #{} addr={:#x} \
                                 gen_at_start={} gen_now={} — dropping new frame",
                                n, page_addr, gen_at_start, gen_now);
                        }
                    }
                    crate::mm::pmm::free_page(new_phys);
                    return false;
                }
                // CoW: old_phys may still be shared with the parent; we
                // only release this process's reference.  The CoW copy
                // (new_phys) takes sole ownership, refcount set to 1 below.
                let _ = crate::mm::refcount::page_ref_dec(old_phys);
                crate::mm::refcount::page_ref_set(new_phys, 1);
                crate::mm::vmm::map_page_in(cr3, page_addr, new_phys, page_flags);
                // Cross-CPU shootdown: sibling threads sharing the
                // parent's CR3 may have the old read-only translation
                // cached.  Without this they keep faulting on every
                // write until their TLB happens to evict the entry.
                crate::mm::tlb::shootdown_page(cr3, page_addr);
                return true;
            }
            return false; // OOM
        } else {
            // Single owner — just make it writable.  The in-place PTE bit
            // flip does NOT install a new physical frame, so no aliasing
            // race is possible here; the gen-check above is overkill for
            // this sub-arm and the result is unused — but the cheap sample
            // pays for itself by keeping the source readable as a single
            // entry-point for the whole CoW arm.
            let new_pte = old_phys | page_flags | PAGE_PRESENT;
            crate::mm::vmm::write_pte(cr3, page_addr, new_pte);
            crate::mm::tlb::shootdown_page(cr3, page_addr);
            return true;
        }
    }

    // === Demand Paging: VMA required ===
    let vma = match vm_space.find_vma(faulting_addr) {
        Some(v) => v,
        None => return false, // Fault outside any VMA — SIGSEGV
    };

    // === Permission-match gate (POSIX) ===========================================
    // Before allocating any frame or touching the PTE we verify the fault class
    // against the VMA's declared protection.  Demand-paging is only legitimate
    // when the access matches a permission the VMA actually grants; otherwise we
    // must surface SIGSEGV so user code sees a deterministic failure instead of
    // silently acquiring a page it was never entitled to.
    //
    // Without this gate the handler would still allocate a zero page (or load a
    // file page) and install a PTE whose effective permissions happen to match
    // the VMA — the access would then proceed on the retry, papering over the
    // userspace bug and, for unknown-VMA faults, leaking kernel frames into the
    // address space.  The `find_vma` miss path above already returns false; this
    // additional check hardens the in-VMA case and covers PROT_NONE guard pages.
    //
    // The decision policy lives in `mm::vma::fault_access_permitted` so the unit
    // tests and the handler share one source of truth.
    let access = crate::mm::vma::FaultAccess::from_error_code(error_code);
    if !crate::mm::vma::fault_access_permitted(vma.prot, access) {
        return false;
    }

    let is_ifetch = matches!(access, crate::mm::vma::FaultAccess::InstructionFetch);

    // === NX fixup: page is PRESENT but marked NX, VMA says PROT_EXEC ===
    // This happens when a page was demand-faulted for read/write before the
    // execute permission was needed, or after mprotect changed permissions.
    if is_present && is_ifetch && (vma.prot & crate::mm::vma::PROT_EXEC != 0) {
        let pte = crate::mm::vmm::read_pte(cr3, page_addr);
        if pte & crate::mm::vmm::PAGE_NO_EXECUTE != 0 {
            // Clear NX bit to allow execution.  Cross-CPU shootdown
            // because another thread on another CPU might be holding
            // an NX-marked TLB entry for the same page and #PF on the
            // first ifetch.
            let new_pte = pte & !crate::mm::vmm::PAGE_NO_EXECUTE;
            crate::mm::vmm::write_pte(cr3, page_addr, new_pte);
            crate::mm::tlb::shootdown_page(cr3, page_addr);
            return true;
        }
    }

    let page_flags = vma.to_page_flags();

    if !is_present {
        // === Demand Paging: page not yet mapped ===

        // For file-backed VMAs we must drop the PROCESS_TABLE lock before
        // accessing the VFS (which takes MOUNTS), so extract the info first.
        // We also capture MAP_SHARED here: a writable MAP_SHARED file mapping
        // must alias the cache page directly (so other mappers see writes —
        // posix mmap(2) MAP_SHARED contract).  MAP_PRIVATE writable mappings
        // get the per-process COW copy that protects the cache from GOT/PLT
        // relocations bleeding between independent loads of the same .so.
        let file_info = match &vma.backing {
            crate::mm::vma::VmBacking::File { mount_idx, inode, offset, .. } => {
                let is_shared = vma.flags & crate::mm::vma::MAP_SHARED != 0;
                Some((*mount_idx, *inode, *offset, vma.base, vma.base + vma.length, is_shared))
            }
            _ => None,
        };

        if let Some((mount_idx, inode, file_base_offset, vma_base, vma_end, is_shared)) = file_info {
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

            // 1. Check the page cache (atomic lookup-and-acquire)
            //
            // `lookup_and_acquire` increments the physical frame's reference
            // count while the cache lock is still held.  This closes the
            // W190-H_A race: a bare `cache::lookup` followed by a separate
            // `page_ref_inc` admits a window in which a concurrent
            // `cache::insert` collision can evict the entry (dropping the
            // cache's ref), a sibling `munmap`/`execve` can drop the last PTE
            // ref (driving rc → 0), and `pmm::alloc_page` can recycle the
            // frame before this CPU reaches its own `page_ref_inc`.  By
            // acquiring the guard ref under the cache lock that window is
            // reduced to zero: no insert eviction can execute against the
            // same key while we hold the lock, so no munmap can concurrently
            // drive rc to zero.
            //
            // Per Intel SDM Vol. 3A §4.10.5 and POSIX mmap(2), every PTE
            // installation must guarantee the target frame is alive at the
            // moment of install.  The guard ref from `lookup_and_acquire`
            // satisfies that guarantee for all three sub-arms below.
            if let Some(cached_phys) = crate::mm::cache::lookup_and_acquire(mount_idx, inode, file_page_offset) {
                // === W216 H_4h fix: re-validate VMA before installing cache-hit PTE ===
                //
                // PROCESS_TABLE was dropped at line ~1071 and interrupts re-enabled
                // before this branch.  A concurrent sys_mmap(MAP_FIXED) on a sibling
                // CPU could have replaced the captured VMA between that drop and now:
                //   Phase 2a — old VMA removed from VmSpace, frames unmapped+freed
                //   Phase 2b — pages returned to PMM; PMM may re-issue them
                //   Phase 3  — new VMA (different backing) inserted
                //
                // Without this check we would install `cached_phys` — content valid
                // for the OLD (inode, file_page_offset) — at a VA whose current VMA
                // describes a different backing object.  Because libxul is fully
                // prepopulated, `cached_phys` holds non-zero bytes from the PREVIOUS
                // offset rather than kernel-page bytes, which is exactly the "non-zero
                // bytes from a different libxul offset" symptom observed in the W215
                // post-all-4-fixes verifier.
                //
                // The fix mirrors the identical guard PR #226 (W216 Hypothesis-V)
                // applied to the readahead and single-page paths: re-acquire
                // PROCESS_TABLE briefly, confirm the (mount_idx, inode,
                // file_base_offset, vma_base, vma_end) tuple still matches the
                // snapshot captured before interrupts were re-enabled, and abandon
                // if it has changed.
                //
                // If the VMA is stale we release the guard ref from
                // `lookup_and_acquire` so the cache's own reference remains the sole
                // holder (freeing the frame only if the cache has also evicted it).
                // The user will re-fault against the new VMA and receive correct data.
                //
                // Lock ordering preserved: PROCESS_TABLE (top) → nothing else.
                // MOUNTS is NOT held here; cache/PMM locks are NOT held here.
                // W216 H_5j-B (unified concurrency): capture the VmSpace
                // generation Arc + post-revalidate sample under the same
                // PROCESS_TABLE critical section as the revalidate.  Re-checked
                // immediately before each `map_page_in` in the install sub-arms
                // below to catch sibling-CPU VMA mutations that fire between
                // this revalidate and the install.
                let mut ch_vm_generation:
                    Option<alloc::sync::Arc<core::sync::atomic::AtomicU64>> = None;
                let mut ch_gen_at_revalidate: u64 = 0;
                let still_valid = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    let vs_opt = procs.iter()
                        .find(|p| p.pid == target_pid)
                        .and_then(|p| p.vm_space.as_ref());
                    if let Some(vs) = vs_opt {
                        ch_vm_generation = Some(vs.generation.clone());
                        ch_gen_at_revalidate =
                            vs.generation.load(core::sync::atomic::Ordering::Acquire);
                    }
                    vs_opt
                        .and_then(|vs| vs.find_vma(faulting_addr))
                        .map(|v| {
                            matches!(&v.backing,
                                crate::mm::vma::VmBacking::File {
                                    mount_idx: m, inode: ino, offset: o, ..
                                } if *m == mount_idx && *ino == inode && *o == file_base_offset)
                            && v.base == vma_base
                            && v.base + v.length == vma_end
                        })
                        .unwrap_or(false)
                };
                if !still_valid {
                    // Release the guard ref — cache's own ref keeps the frame
                    // alive, or frees it if the cache evicted the entry between
                    // our lookup and now.
                    let _ = crate::mm::refcount::page_ref_dec(cached_phys);
                    #[cfg(feature = "firefox-test")]
                    crate::serial_println!(
                        "[PF/revalidate] CACHE-HIT VMA stale addr={:#x} \
                         mount={} inode={} foff={:#x} — abandoning",
                        faulting_addr, mount_idx, inode, file_page_offset);
                    return false;
                }

                // Closure: per-arm generation re-check.  Returns true if the
                // caller should abort (and the caller must release `cached_phys`
                // appropriately before returning false).  The CoW-copy sub-arm
                // additionally frees its freshly-allocated `private_phys` via
                // its own check immediately before installing.
                let gen_unchanged = || -> bool {
                    match ch_vm_generation.as_ref() {
                        Some(g) => {
                            let now = g.load(core::sync::atomic::Ordering::Acquire);
                            now == ch_gen_at_revalidate
                        }
                        None => true,
                    }
                };

                // MAP_PRIVATE + writable: give the process a private copy so
                // writes (e.g., GOT/PLT relocations) don't corrupt the shared
                // cache page. Without this, a second process loading the same
                // library sees PID 1's relocated pointers as garbage.
                //
                // MAP_SHARED + writable: per mmap(2), writes through the
                // mapping must be visible to all other mappings of the same
                // file region.  Aliasing the cache page directly satisfies
                // the contract — a subsequent MAP_SHARED|PROT_READ mapping of
                // the same inode/offset hits the same cache frame and sees
                // the writes.  Mozilla's freeze-shmem dance (memfd_create →
                // ftruncate → MAP_SHARED|RW write → seal → MAP_SHARED|RO
                // read in the same process) depends on this aliasing.
                let is_writable = page_flags & crate::mm::vmm::PAGE_WRITABLE != 0;
                let needs_private_copy = is_writable && !is_shared;
                if needs_private_copy {
                    if let Some(private_phys) = crate::mm::pmm::alloc_page() {
                        const COW_OFF: u64 = 0xFFFF_8000_0000_0000;
                        unsafe {
                            // SAFETY: `lookup_and_acquire` guarantees `cached_phys`
                            // is alive for the duration of this block by holding a
                            // guard ref.  The copy reads from the cache frame and
                            // writes to the freshly-allocated `private_phys` frame;
                            // there is no aliasing between source and destination.
                            core::ptr::copy_nonoverlapping(
                                (COW_OFF + cached_phys) as *const u8,
                                (COW_OFF + private_phys) as *mut u8,
                                crate::mm::pmm::PAGE_SIZE,
                            );
                        }
                        // W216 H_5j-B (unified concurrency): re-check generation
                        // immediately before install — see arm-level closure.
                        if !gen_unchanged() {
                            #[cfg(feature = "firefox-test")]
                            {
                                static CNT: core::sync::atomic::AtomicU64 =
                                    core::sync::atomic::AtomicU64::new(0);
                                let n = CNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                                if n < 5 || n % 500 == 0 {
                                    crate::serial_println!(
                                        "[PF/gen-abort] CACHE-PRIVATE #{} addr={:#x} \
                                         gen_at_rev={} — releasing private+cache refs",
                                        n, page_addr, ch_gen_at_revalidate);
                                }
                            }
                            crate::mm::pmm::free_page(private_phys);
                            let _ = crate::mm::refcount::page_ref_dec(cached_phys);
                            return false;
                        }
                        crate::mm::refcount::page_ref_set(private_phys, 1);
                        crate::mm::vmm::map_page_in(cr3, page_addr, private_phys, page_flags);
                        crate::mm::vmm::invlpg(page_addr);
                        // Release the guard ref acquired by `lookup_and_acquire`.
                        // The PTE now refers to `private_phys`, not `cached_phys`;
                        // the cache still holds its own independent reference to
                        // `cached_phys`, so this dec will not free the frame.
                        let _ = crate::mm::refcount::page_ref_dec(cached_phys);
                    } else {
                        // PMM exhausted: cannot allocate a private copy.
                        //
                        // Aliasing the shared cache page with PAGE_WRITABLE set
                        // is unsafe — a subsequent write (e.g., ld-linux GOT
                        // relocation) would corrupt the cache frame, which may
                        // be concurrently mapped read-only into other processes.
                        // Those processes would inherit PIE-biased pointers from
                        // an unrelated address space, producing SIGSEGV / #GP at
                        // random virtual addresses (W184/W185 root cause).
                        //
                        // Fail the fault instead.  Per POSIX mmap(2) and
                        // Intel SDM Vol. 3A §4.10.5, demand-paging is permitted
                        // to signal the faulting thread (SIGSEGV) when physical
                        // backing cannot be allocated, giving the same visible
                        // behaviour as an ENOMEM mmap failure.
                        //
                        // Release the guard ref before returning so the cache's
                        // reference remains the sole holder.  If the cache entry
                        // was evicted between our lookup and now this dec may
                        // be the last ref; the frame is freed correctly.
                        let _ = crate::mm::refcount::page_ref_dec(cached_phys);
                        return false;
                    }
                } else {
                    // MAP_SHARED writable, or any read-only mapping: alias
                    // the cache page directly so writes are visible to other
                    // mappers and reads see the latest content.
                    //
                    // The guard ref from `lookup_and_acquire` IS the PTE's
                    // reference — do NOT call `page_ref_inc` again here.
                    // Steady state after install: cache holds one ref,
                    // this PTE holds one ref (the promoted guard ref) = rc ≥ 2.
                    //
                    // W216 H_5j-B (unified concurrency): re-check generation
                    // immediately before install.  On abort we release the
                    // guard ref so the cache's own reference remains the sole
                    // holder of `cached_phys`.
                    if !gen_unchanged() {
                        #[cfg(feature = "firefox-test")]
                        {
                            static CNT: core::sync::atomic::AtomicU64 =
                                core::sync::atomic::AtomicU64::new(0);
                            let n = CNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                            if n < 5 || n % 500 == 0 {
                                crate::serial_println!(
                                    "[PF/gen-abort] CACHE-ALIAS #{} addr={:#x} \
                                     gen_at_rev={} — releasing guard ref",
                                    n, page_addr, ch_gen_at_revalidate);
                            }
                        }
                        let _ = crate::mm::refcount::page_ref_dec(cached_phys);
                        return false;
                    }
                    // W215 H3a diagnostic: check whether cached_phys is held
                    // under a different key in the cache — which would mean a
                    // MAP_SHARED+PROT_WRITE PTE is about to alias a page the cache
                    // knows under a different (mount,inode,offset) identity.
                    // Only file-backed installs (is_shared && is_writable) reach
                    // this arm; anonymous frames are never in the cache.
                    #[cfg(feature = "firefox-test")]
                    if is_writable {
                        if let Some((c_mount, c_inode, c_off)) =
                            crate::mm::cache::is_phys_in_cache(cached_phys)
                        {
                            // The cache key recorded at insert time should match
                            // our installer's key.  A mismatch means the frame has
                            // been re-inserted under a different identity since the
                            // readahead/prepopulate inserted it, or a concurrent
                            // cache::insert replaced our entry with a different frame
                            // and then re-used this phys under a new key — both
                            // are aliasing bugs.
                            if c_mount != mount_idx || c_inode != inode || c_off != file_page_offset {
                                PFH_WRITABLE_ALIAS_CACHE.fetch_add(1, Ordering::Relaxed);
                                crate::serial_println!(
                                    "[H3a] ALIAS-CACHE writable phys={:#x} \
                                     cache_key=({},{:#x},{:#x}) installer_key=({},{:#x},{:#x}) \
                                     rip={:#x}",
                                    cached_phys,
                                    c_mount, c_inode, c_off,
                                    mount_idx, inode, file_page_offset,
                                    _frame.rip,
                                );
                            }
                        }
                    }
                    crate::mm::vmm::map_page_in(cr3, page_addr, cached_phys, page_flags);
                    crate::mm::vmm::invlpg(page_addr);
                    // Guard ref is intentionally NOT released — it has been
                    // promoted to the PTE reference.
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
            // W215 source-content reference snapshot — first 64 bytes of
            // each readahead page's file contents captured immediately
            // after `fs.read` returns Ok.  Passed through to
            // `cache::insert_with_expected` so the post-install guard can
            // detect a sibling-CPU writer that mutated the frame between
            // the FS read and the cache install.  Diagnostic-only.
            #[cfg(feature = "w215-diag")]
            let mut pages_snapshot: [[u8; 64]; READAHEAD_PAGES as usize] =
                [[0u8; 64]; READAHEAD_PAGES as usize];
            let mut n_pages = 0usize;
            // Recursive-lock hazard avoidance (closes #78, mirrors the
            // PROCESS_TABLE fix from PR #77 / issue #76):
            //
            // If the holder of `MOUNTS` is currently executing a VFS syscall
            // whose buffer pages are not yet faulted in, that syscall will
            // generate a kernel-mode #PF on its way through `copy_to_user`
            // / `copy_from_user`.  The PF handler then needs `MOUNTS` to
            // service the demand-page; under a blocking `lock()` the same
            // CPU spins forever on a lock its current syscall already owns.
            //
            // `try_lock()` sidesteps the hazard: on contention we skip
            // readahead entirely and let the slower single-page fallback
            // below decide between spin-yield and graceful retry.  The
            // skipped readahead is not a correctness loss — it merely
            // forfeits the I/O batching opportunity for this one fault.
            // Snapshot the FS handle once and drop MOUNTS before any FS
            // dispatch.  Holding MOUNTS across `stat`/`read` re-introduces
            // the cross-CPU hazard PR #81 closed *and* the same-thread
            // hazard issue #82 closed.  Once the Arc is cloned out, the
            // FS object stays alive even if another CPU racily umounts.
            let fs_opt: Option<Arc<dyn crate::vfs::FileSystemOps>> = {
                if let Some(mounts) = crate::vfs::MOUNTS.try_lock() {
                    mounts.get(mount_idx).map(|m| m.fs.clone())
                } else {
                    // Contended: skip readahead entirely (lost batching, not
                    // correctness — the single-page fallback below will
                    // handle the faulting page).
                    None
                }
            };
            if let Some(fs) = fs_opt {
                let file_size = fs.stat(inode).map(|s| s.size).unwrap_or(0);

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
                        // W215 diagnostic Arm-1+2: open the pre-insert
                        // race window for `phys` at the readahead site.
                        #[cfg(feature = "firefox-test")]
                        {
                            crate::mm::w215_diag::prov_record(
                                phys,
                                crate::mm::w215_diag::KIND_PHYS_OFF_WRITE_PRE_INSERT,
                                crate::mm::w215_diag::pack_cache_key(inode, foff),
                            );
                            crate::mm::w215_diag::preins_register(
                                phys,
                                crate::mm::w215_diag::SITE_PFH_READAHEAD,
                                mount_idx, inode, foff,
                            );
                        }
                        let buf = unsafe {
                            core::slice::from_raw_parts_mut(
                                (PHYS_OFF_FILE + phys) as *mut u8, 0x1000)
                        };
                        // Filesystem-read failures (e.g. transient block-device
                        // timeouts) MUST NOT silently produce a zero-filled
                        // mapping: the page cache treats whatever frame we
                        // hand it as the authoritative file contents, so a
                        // single failed read poisons the cache for every
                        // subsequent mapper of (mount,inode,offset).  POSIX
                        // ABI on file-backed I/O failure during demand-page
                        // is a SIGBUS / SIGSEGV; we deliver SIGSEGV by
                        // failing the page-fault below, releasing the frame
                        // here so it can be reused.  For pg_idx > 0 (pure
                        // readahead) the fault will retry on next access; for
                        // pg_idx == 0 (the faulting page) the user-mode
                        // signal handler observes the failure rather than
                        // executing against zeroed-out code/data.
                        if fs.read(inode, foff, buf).is_err() {
                            crate::mm::pmm::free_page(phys);
                            #[cfg(feature = "firefox-test")]
                            crate::serial_println!(
                                "[PF/io-err] readahead read failed inode={} foff={:#x} pg_idx={}",
                                inode, foff, pg_idx);
                            // Stop the readahead burst — sequential pages from
                            // the same backing file are likely to fail too.
                            break;
                        }
                        // W215 reference snapshot: capture the first 64 bytes
                        // of the just-read page right now, before any
                        // intervening kernel work (VMA revalidate, gen-check,
                        // sibling readahead iterations).  This is the moment
                        // the kernel KNOWS the frame holds the file bytes;
                        // any later divergence at cache::insert time is the
                        // W215 writer.  See cache::insert_with_expected.
                        #[cfg(feature = "w215-diag")]
                        unsafe {
                            let src = (PHYS_OFF_FILE + phys) as *const u8;
                            for b in 0..64 {
                                pages_snapshot[n_pages][b] =
                                    core::ptr::read_volatile(src.add(b));
                            }
                        }
                        pages_to_map[n_pages] = (vaddr, phys, foff);
                        n_pages += 1;
                    } else {
                        break; // OOM — stop readahead
                    }
                }
            }

            // === W216 Hypothesis-V fix: post-I/O VMA re-validation (readahead path) ===
            //
            // The PROCESS_TABLE lock was dropped at line ~1071 before the
            // filesystem read(s) above.  During the I/O, a sibling CPU could have
            // executed sys_mmap(MAP_FIXED) Phase 2a+2b — removing the old VMA from
            // the VmSpace and unmapping+freeing the underlying physical frames —
            // before installing the replacement VMA in Phase 3.  If we proceed to
            // install freshly-read frames into PTEs whose VMA has been replaced, the
            // user will see old-file bytes at an address that now belongs to an
            // anonymous or different-file mapping, replicating the W215 aliasing
            // observed as [FAULT/PHYS] events in libxul's 0x4b*-region.
            //
            // === W216 H_5j-A escalation: the install loop also needs exclusion ===
            //
            // PR #226 added the cheap revalidate immediately below as an early-out
            // for the case where the VMA was already replaced during I/O.  That
            // closes the racing TEARDOWN-then-INSTALL ordering.  It does NOT close
            // the racing INSTALL-then-TEARDOWN ordering: after a successful
            // revalidate, the up-to-32-iteration `cache::insert` + `map_page_in`
            // loop below runs with no exclusion against a concurrent munmap /
            // MAP_FIXED Phase 2b on a sibling CPU.  `map_page_in` internally takes
            // `mm_sem` in read mode, and `unmap_and_free_range_in` also takes it in
            // read mode — `spin::RwLock` admits unbounded concurrent readers, so
            // the two paths are NOT mutually exclusive.  A sibling CPU can drain
            // frames between our iterations, leaving our late-loop PTEs aliasing
            // recycled physical frames (the residual 5th-class aliasing that
            // remained after PRs #222 / #225 / #226 / #230).
            //
            // Lock ordering preserved: PROCESS_TABLE (top) → nothing else here.
            // MOUNTS is NOT held at this point; cache/PMM locks are NOT held yet.
            // W216 H_5j-B: also capture the VmSpace generation Arc + a
            // post-revalidate sample so we can detect any further VMA-list
            // mutation that happens BETWEEN this revalidate and each
            // cache::insert + map_page_in iteration in the install loop
            // below.  PR #226's revalidate alone catches mutations that
            // happened during the I/O phase; the install loop itself can
            // span microseconds during which a sibling CPU running
            // sys_munmap / MAP_FIXED Phase 2b / MADV_DONTNEED can drain
            // frames out from under us.  See `VmSpace::generation`.
            let mut vm_generation: Option<alloc::sync::Arc<core::sync::atomic::AtomicU64>> = None;
            let mut gen_at_revalidate: u64 = 0;
            if n_pages > 0 {
                let still_valid = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    let vs_opt = procs.iter()
                        .find(|p| p.pid == target_pid)
                        .and_then(|p| p.vm_space.as_ref());
                    if let Some(vs) = vs_opt {
                        vm_generation = Some(vs.generation.clone());
                        gen_at_revalidate =
                            vs.generation.load(core::sync::atomic::Ordering::Acquire);
                    }
                    vs_opt
                        .and_then(|vs| vs.find_vma(faulting_addr))
                        .map(|v| {
                            matches!(&v.backing,
                                crate::mm::vma::VmBacking::File {
                                    mount_idx: m, inode: ino, offset: o, ..
                                } if *m == mount_idx && *ino == inode && *o == file_base_offset)
                            && v.base == vma_base
                            && v.base + v.length == vma_end
                        })
                        .unwrap_or(false)
                };
                if !still_valid {
                    // VMA replaced or removed during I/O.  Free all frames we
                    // allocated, then abandon the fault.  The user will re-fault
                    // against the new VMA and receive correct data.
                    #[cfg(feature = "firefox-test")]
                    crate::serial_println!(
                        "[PF/revalidate] READAHEAD VMA stale after I/O addr={:#x} \
                         mount={} inode={} foff={:#x} — dropping {} pages",
                        faulting_addr, mount_idx, inode, file_base_offset, n_pages);
                    for i in 0..n_pages {
                        let (_vaddr, phys, _foff) = pages_to_map[i];
                        crate::mm::pmm::free_page(phys);
                    }
                    return false;
                }
            }

            // Map all readahead pages and insert into cache.  Three regimes
            // need to be distinguished and the per-arm logic below must match
            // the cache-hit path (lines ~786-820):
            //
            // - MAP_PRIVATE + writable: give the process a private COPY of
            //   the cache page so its writes (GOT relocations, BSS init, etc.)
            //   don't corrupt the cache for parallel loaders of the same .so.
            //   Without this, ld-linux's GOT relocations would observably
            //   poison subsequent processes (cpp_hello saw glibc_hello's
            //   relocated pointers in libc's .dynamic section).
            // - MAP_SHARED + writable: ALIAS the cache page so that writes
            //   are visible to other mappers of the same (mount,inode,off).
            //   Required by mmap(2)'s MAP_SHARED contract; Mozilla's
            //   freeze-shmem dance (rw-then-ro re-mmap of a memfd) breaks
            //   silently if violated.
            // - Read-only mappings (private or shared): alias the cache page;
            //   no write visibility question and aliasing saves memory.
            const PHYS_COW: u64 = 0xFFFF_8000_0000_0000;
            let is_writable_vma = page_flags & crate::mm::vmm::PAGE_WRITABLE != 0;
            let needs_private_copy_vma = is_writable_vma && !is_shared;
            let mapped_faulting = n_pages > 0;

            for i in 0..n_pages {
                let (vaddr, phys, foff) = pages_to_map[i];

                // W215 diagnostic Arm-1: record the install event for the
                // provenance ring.  The install-race witness probe is
                // deferred to AFTER `cache::insert` below — by then this
                // CPU's own pre-insert witness has been cleared by
                // `preins_clear_on_insert`, so a remaining witness means
                // a DIFFERENT CPU is mid-write on the same phys.
                #[cfg(feature = "firefox-test")]
                crate::mm::w215_diag::prov_record(
                    phys,
                    crate::mm::w215_diag::KIND_PFH_INSTALL,
                    crate::mm::w215_diag::pack_cache_key(inode, foff),
                );

                // W216 H_5j-B: per-iteration generation re-check.  Any sibling
                // CPU that mutated the address space (sys_munmap, MAP_FIXED
                // Phase 2b, MADV_DONTNEED, mprotect, sysv_shm push/remove,
                // brk grow/shrink, clone_for_fork CoW write-protect) since
                // the post-revalidate sample bumps `vm_space.generation`.
                // A mismatch means the snapshot we computed before this
                // iteration is no longer authoritative — abort the install
                // loop, free remaining frames, return false so the user
                // re-faults against the new VMA.  Per Intel SDM Vol. 3A
                // §8.2.3, this Acquire load pairs with the Release fetch_add
                // in `bump_generation_for_cr3` and `VmSpace::*` mutators.
                if let Some(g) = vm_generation.as_ref() {
                    let gen_now = g.load(core::sync::atomic::Ordering::Acquire);
                    if gen_now != gen_at_revalidate {
                        #[cfg(feature = "firefox-test")]
                        crate::serial_println!(
                            "[PF/gen-abort] READAHEAD addr={:#x} mount={} inode={} \
                             foff={:#x} gen_at_rev={} gen_now={} — releasing {} \
                             unmapped frames",
                            faulting_addr, mount_idx, inode, file_base_offset,
                            gen_at_revalidate, gen_now, n_pages.saturating_sub(i));
                        // Release every frame we have not yet installed.
                        // Frames already installed in earlier iterations (i'
                        // < i) are reachable via PTE refs and the cache, so
                        // they remain valid; the user keeps observing them
                        // through the existing PTEs.
                        for j in i..n_pages {
                            let (_v, p, _f) = pages_to_map[j];
                            crate::mm::pmm::free_page(p);
                        }
                        return false;
                    }
                }

                // ---- Bug-B fix: guard reference ----------------------------
                // Acquire a guard reference on `phys` BEFORE inserting it into
                // the page cache.  Without this, the following race is possible
                // on SMP systems:
                //
                //  CPU-A: cache::insert(foff, phys_A)  → cache ref = 1
                //  CPU-B: cache::insert(foff, phys_B)  → evicts phys_A
                //                                        cache ref(phys_A) → 0
                //                                        PMM frees phys_A
                //  CPU-A: page_ref_inc(phys_A)         → refcount resurrected
                //  CPU-A: map_page_in(vaddr, phys_A)   → PTE → kernel frame
                //
                // Holding a guard ref keeps phys alive even if the cache
                // evicts our entry before we finish installing the PTE.
                // The guard ref is released after the PTE install is complete
                // (or after we decide to discard the frame), restoring the
                // steady-state of cache-ref(1) + PTE-ref(1) = 2 for aliased
                // pages, or cache-ref(1) for private-copy paths.
                crate::mm::refcount::page_ref_inc(phys);

                // Always insert the clean page into the shared cache.
                // Pass the reference snapshot captured immediately after
                // fs.read so cache::insert can detect a sibling-CPU
                // writer that mutated the frame in the window between
                // the FS read and this cache install (W215 wrong-content
                // guard).  On non-diag builds the snapshot array does
                // not exist and we fall through to the plain insert.
                #[cfg(feature = "w215-diag")]
                crate::mm::cache::insert_with_expected(
                    mount_idx, inode, foff, phys, Some(&pages_snapshot[i]),
                );
                #[cfg(not(feature = "w215-diag"))]
                crate::mm::cache::insert(mount_idx, inode, foff, phys);

                // W215 diagnostic: MAP_SHARED + PROT_WRITE pages are expected
                // to mutate in-place (POSIX mmap(2) MAP_SHARED contract).  Mark
                // the shadow CRC entry so the walker suppresses false-positive
                // CRC-MISMATCH emission for these legitimate aliased writers.
                #[cfg(feature = "w215-diag")]
                if is_shared && is_writable_vma {
                    crate::mm::w215_crc::mark_writable_shared(phys);
                }

                // W215 diagnostic Arm-2: my own pre-insert witness is now
                // cleared (by preins_clear_on_insert inside cache::insert).
                // If a witness for this phys is STILL present, a sibling
                // CPU registered a pre-insert for the same phys — the
                // smoking-gun race for axis A.
                #[cfg(feature = "firefox-test")]
                crate::mm::w215_diag::preins_check_install(
                    phys, mount_idx, inode, foff,
                );

                // If another CPU already installed a PTE for this address,
                // discard our redundant frame: remove our cache entry (only if
                // it still names our phys — a concurrent insert may have
                // already replaced it with a different frame) and drop the
                // guard ref.  With the guard still held, phys cannot have been
                // handed to the PMM yet, so the dec-to-zero here is safe.
                let existing_pte = crate::mm::vmm::read_pte(cr3, vaddr);
                if existing_pte & crate::mm::vmm::PAGE_PRESENT != 0 {
                    // Another CPU won the race for this vaddr.  Our frame is
                    // redundant.  Conditionally evict from cache (only if our
                    // phys is still the cached value) then release the guard.
                    crate::mm::cache::evict_if_phys(mount_idx, inode, foff, phys);
                    // Guard ref + the ref we'd have used for the PTE both drop;
                    // cache::evict_if_phys already released the cache ref if it
                    // matched, so we only need to release the guard ref here.
                    // page_ref_dec returns the new count; if zero, the frame has
                    // no remaining holders and must be returned to the PMM.
                    if crate::mm::refcount::page_ref_dec(phys) == 0 {
                        crate::mm::pmm::free_page(phys);
                    }
                    crate::mm::vmm::invlpg(vaddr);
                    continue;
                }

                // MAP_PRIVATE + writable: give this process a private copy so
                // writes (GOT relocations, BSS init, etc.) don't corrupt the
                // cache page (which a parallel loader of the same .so still
                // expects to be the unrelocated file contents).
                //
                // MAP_SHARED + writable: alias the cache page so writes are
                // visible to other mappers — required by mmap(2) MAP_SHARED.
                //
                // Read-only VMAs: alias the cache page (saves memory).
                if needs_private_copy_vma {
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
                        // Cache keeps its ref to phys (the clean shared copy).
                        // Drop guard ref — steady state: cache ref(phys) = 1.
                        let _ = crate::mm::refcount::page_ref_dec(phys);
                    } else {
                        // PMM exhausted: cannot allocate a private copy.
                        //
                        // Aliasing the shared cache page with PAGE_WRITABLE set
                        // is unsafe: a subsequent ld-linux GOT relocation would
                        // corrupt the cache frame, which may be concurrently
                        // mapped read-only into other processes.  Those processes
                        // would inherit PIE-biased pointers, producing SIGSEGV /
                        // #GP at random VAs (W184/W185 root cause).
                        //
                        // Fail the fault instead.  Per POSIX mmap(2) and
                        // Intel SDM Vol. 3A §4.10.5, demand-paging is permitted
                        // to signal the faulting thread (SIGSEGV) when physical
                        // backing cannot be allocated.
                        //
                        // Refcount accounting: guard ref acquired at the top of
                        // this iteration must be released; cache::insert already
                        // holds the cache ref (rc → 1 steady state after drop).
                        let _ = crate::mm::refcount::page_ref_dec(phys);
                        return false;
                    }
                } else {
                    // MAP_SHARED writable, or any read-only mapping: alias
                    // the cache page directly.
                    //
                    // W215 H3a diagnostic: the cache entry for (mount,inode,foff)
                    // was just inserted by us (cache::insert above), so under
                    // normal operation the cache key WILL match our installer key.
                    // A mismatch here means another CPU raced in with a different
                    // key for the same phys between our insert and this check —
                    // a structural aliasing bug distinct from the MAP_SHARED case
                    // in the cache-hit arm above.
                    #[cfg(feature = "firefox-test")]
                    if is_writable_vma {
                        if let Some((c_mount, c_inode, c_off)) =
                            crate::mm::cache::is_phys_in_cache(phys)
                        {
                            if c_mount != mount_idx || c_inode != inode || c_off != foff {
                                PFH_WRITABLE_ALIAS_CACHE.fetch_add(1, Ordering::Relaxed);
                                crate::serial_println!(
                                    "[H3a] ALIAS-CACHE readahead phys={:#x} \
                                     cache_key=({},{:#x},{:#x}) installer_key=({},{:#x},{:#x}) \
                                     rip={:#x}",
                                    phys,
                                    c_mount, c_inode, c_off,
                                    mount_idx, inode, foff,
                                    _frame.rip,
                                );
                            }
                        }
                    }
                    crate::mm::refcount::page_ref_inc(phys);
                    crate::mm::vmm::map_page_in(cr3, vaddr, phys, page_flags);
                    // Drop guard ref — steady state: cache(1) + PTE(1) = 2.
                    let _ = crate::mm::refcount::page_ref_dec(phys);
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
                // W215 diagnostic Arm-1+2: open the pre-insert race window
                // for `phys` at the single-page fallback site.
                #[cfg(feature = "firefox-test")]
                {
                    crate::mm::w215_diag::prov_record(
                        phys,
                        crate::mm::w215_diag::KIND_PHYS_OFF_WRITE_PRE_INSERT,
                        crate::mm::w215_diag::pack_cache_key(inode, file_page_offset),
                    );
                    crate::mm::w215_diag::preins_register(
                        phys,
                        crate::mm::w215_diag::SITE_PFH_SINGLEPAGE,
                        mount_idx, inode, file_page_offset,
                    );
                }
                // Snapshot the FS handle out of MOUNTS (one short critical
                // section) and dispatch the read with the lock released.
                // This is the fix for issues #78 (cross-CPU contention) and
                // #82 (same-thread recursion when the FS read itself faults
                // on a kernel buffer): once we hold an Arc, the FS object
                // is alive without us blocking any other CPU and without
                // re-entering MOUNTS from the nested PF handler.
                //
                // If MOUNTS happens to be momentarily contended we spin
                // briefly; cross-CPU contention is bounded because no FS
                // dispatches happen under the lock anymore — only the Arc
                // clone, which is a couple of atomic ops.
                let mut spin_iters: u32 = 0;
                const SPIN_BOUND: u32 = 1 << 24;
                let fs_opt: Option<Arc<dyn crate::vfs::FileSystemOps>> = loop {
                    if let Some(mounts) = crate::vfs::MOUNTS.try_lock() {
                        break mounts.get(mount_idx).map(|m| m.fs.clone());
                    }
                    core::hint::spin_loop();
                    spin_iters += 1;
                    // Bounded spin (defence-in-depth): if a non-VFS callsite
                    // ever holds MOUNTS across an FS dispatch and the FS
                    // dispatch faults on a kernel buffer, the same-thread
                    // recursion would wedge here.  Drop the page rather than
                    // wedge — `cache::insert` and the map_page_in below will
                    // skip on the None path.
                    if spin_iters >= SPIN_BOUND {
                        crate::serial_println!(
                            "[PF] MOUNTS spin exceeded bound at faulting_addr={:#x} \
                             rip={:#x} — leaving page unread (likely same-thread \
                             MOUNTS recursion outside vfs::*; see #82 follow-up)",
                            faulting_addr, _frame.rip,
                        );
                        break None;
                    }
                };
                // W215 single-page reference snapshot — populated right
                // after fs.read returns Ok, consumed by the
                // cache::insert_with_expected call below.  See readahead-
                // path snapshot for rationale.  Diagnostic-only.
                #[cfg(feature = "w215-diag")]
                let mut sp_snapshot: [u8; 64] = [0u8; 64];
                if let Some(fs) = fs_opt {
                    let buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            (PHYS_OFF_FILE + phys) as *mut u8, 0x1000)
                    };
                    // See readahead-path commentary above: a failed
                    // filesystem read here MUST NOT install a zero-filled
                    // page into the cache, since later mappers of the same
                    // (mount,inode,offset) will accept the cached frame as
                    // authoritative file contents.  Free the frame and let
                    // the page-fault propagate as SIGSEGV — POSIX-equivalent
                    // behaviour for I/O errors during demand-page.
                    if fs.read(inode, file_page_offset, buf).is_err() {
                        crate::mm::pmm::free_page(phys);
                        #[cfg(feature = "firefox-test")]
                        crate::serial_println!(
                            "[PF/io-err] single-page read failed inode={} foff={:#x} addr={:#x}",
                            inode, file_page_offset, page_addr);
                        return false;
                    }
                    // Snapshot the first 64 bytes immediately.  Any later
                    // divergence at cache::insert is a sibling-CPU writer.
                    #[cfg(feature = "w215-diag")]
                    unsafe {
                        let src = (PHYS_OFF_FILE + phys) as *const u8;
                        for b in 0..64 {
                            sp_snapshot[b] = core::ptr::read_volatile(src.add(b));
                        }
                    }
                } else {
                    // We never even reached the FS dispatch (MOUNTS spin
                    // bound exhausted).  Don't poison the cache with a
                    // zero page — fail the fault.
                    crate::mm::pmm::free_page(phys);
                    return false;
                }
                // === W216 Hypothesis-V fix: post-I/O VMA re-validation (single-page path) ===
                //
                // Same race as the readahead path above.  Between the PROCESS_TABLE
                // drop (before I/O) and here, a sibling CPU running sys_mmap
                // MAP_FIXED Phase 2b may have freed the frames backing this VA and
                // replaced the VMA with a new one.  Re-validate before installing.
                // W216 H_5j-B: capture the VmSpace generation post-revalidate
                // and re-check it just before the cache::insert + map_page_in
                // below.  Single-page path has one install, but a sibling CPU
                // can still mutate the address space between the revalidate
                // critical section and the install — same race class as the
                // readahead arm above.  See `VmSpace::generation` doc comment.
                let mut sp_vm_generation:
                    Option<alloc::sync::Arc<core::sync::atomic::AtomicU64>> = None;
                let mut sp_gen_at_revalidate: u64 = 0;
                {
                    let still_valid = {
                        let procs = crate::proc::PROCESS_TABLE.lock();
                        let vs_opt = procs.iter()
                            .find(|p| p.pid == target_pid)
                            .and_then(|p| p.vm_space.as_ref());
                        if let Some(vs) = vs_opt {
                            sp_vm_generation = Some(vs.generation.clone());
                            sp_gen_at_revalidate =
                                vs.generation.load(core::sync::atomic::Ordering::Acquire);
                        }
                        vs_opt
                            .and_then(|vs| vs.find_vma(faulting_addr))
                            .map(|v| {
                                matches!(&v.backing,
                                    crate::mm::vma::VmBacking::File {
                                        mount_idx: m, inode: ino, offset: o, ..
                                    } if *m == mount_idx && *ino == inode && *o == file_base_offset)
                                && v.base == vma_base
                                && v.base + v.length == vma_end
                            })
                            .unwrap_or(false)
                    };
                    if !still_valid {
                        // VMA replaced during I/O.  Release the frame and let
                        // the user re-fault against the replacement VMA.
                        #[cfg(feature = "firefox-test")]
                        crate::serial_println!(
                            "[PF/revalidate] SINGLE-PAGE VMA stale after I/O addr={:#x} \
                             mount={} inode={} foff={:#x} — dropping frame",
                            faulting_addr, mount_idx, inode, file_page_offset);
                        crate::mm::pmm::free_page(phys);
                        return false;
                    }
                }
                // W216 H_5j-B: re-check generation immediately before install.
                if let Some(g) = sp_vm_generation.as_ref() {
                    let gen_now = g.load(core::sync::atomic::Ordering::Acquire);
                    if gen_now != sp_gen_at_revalidate {
                        #[cfg(feature = "firefox-test")]
                        crate::serial_println!(
                            "[PF/gen-abort] SINGLE-PAGE addr={:#x} mount={} inode={} \
                             foff={:#x} gen_at_rev={} gen_now={} — dropping frame",
                            faulting_addr, mount_idx, inode, file_page_offset,
                            sp_gen_at_revalidate, gen_now);
                        crate::mm::pmm::free_page(phys);
                        return false;
                    }
                }
                // Bug-B fix (single-page fallback): hold a guard reference
                // before inserting into the cache, mirroring the readahead-
                // path fix above.  Without the guard, a concurrent cache::insert
                // for the same (mount,inode,offset) can evict our entry and
                // drop phys's refcount to zero — handing the frame to the PMM
                // for reuse — in the window between cache::insert returning and
                // the PTE installation below.
                crate::mm::refcount::page_ref_inc(phys);
                // Pass the post-fs.read snapshot so the cache insert can
                // detect a sibling-CPU writer that mutated the frame in
                // the window between the FS read and this install.
                #[cfg(feature = "w215-diag")]
                crate::mm::cache::insert_with_expected(
                    mount_idx, inode, file_page_offset, phys, Some(&sp_snapshot),
                );
                #[cfg(not(feature = "w215-diag"))]
                crate::mm::cache::insert(mount_idx, inode, file_page_offset, phys);

                // W215 diagnostic: mark MAP_SHARED + PROT_WRITE pages as
                // legitimate aliased writers so the CRC walker suppresses
                // false-positive mismatch emission.  `is_writable_spf` is
                // declared below; inline the flag expression here to keep
                // this block in the natural insert-call sequence.
                #[cfg(feature = "w215-diag")]
                if is_shared && (page_flags & crate::mm::vmm::PAGE_WRITABLE != 0) {
                    crate::mm::w215_crc::mark_writable_shared(phys);
                }

                // W215 diagnostic Arm-2 (single-page fallback): same
                // semantic as the readahead path — own witness now cleared,
                // a residual witness is a sibling-CPU race on the same phys.
                #[cfg(feature = "firefox-test")]
                crate::mm::w215_diag::preins_check_install(
                    phys, mount_idx, inode, file_page_offset,
                );

                // Bug-C fix (single-page fallback): MAP_PRIVATE + writable
                // mappings must receive a private copy of the cache page, not
                // an alias.  Aliasing the shared frame with PAGE_WRITABLE set
                // allows ld-linux GOT relocations to corrupt the cache page,
                // which any concurrent MAP_PRIVATE reader of the same
                // (mount,inode,offset) will inherit — yielding PIE-biased
                // pointers that fault at random virtual addresses depending on
                // which process's base they were computed for (W184/W185/W188
                // root cause).
                //
                // Mirrors the same guard applied in the cache-hit path
                // (lines ~1098-1122) and the readahead OOM-fallback path
                // (lines ~1349-1370).  Per POSIX mmap(2) and Intel SDM
                // Vol. 3A §4.10.5, demand-paging may fail with SIGSEGV when
                // physical backing cannot be obtained — observable behaviour
                // identical to ENOMEM from mmap(2).
                let is_writable_spf = page_flags & crate::mm::vmm::PAGE_WRITABLE != 0;
                let needs_private_copy_spf = is_writable_spf && !is_shared;
                if needs_private_copy_spf {
                    if let Some(private_phys) = crate::mm::pmm::alloc_page() {
                        const COW_SPF: u64 = 0xFFFF_8000_0000_0000;
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (COW_SPF + phys) as *const u8,
                                (COW_SPF + private_phys) as *mut u8,
                                crate::mm::pmm::PAGE_SIZE,
                            );
                        }
                        crate::mm::refcount::page_ref_set(private_phys, 1);
                        crate::mm::vmm::map_page_in(cr3, page_addr, private_phys, page_flags);
                        crate::mm::vmm::invlpg(page_addr);
                        // Cache keeps its own ref to phys (clean shared copy).
                        // Release guard — steady state: cache ref(phys) = 1.
                        let _ = crate::mm::refcount::page_ref_dec(phys);
                    } else {
                        // PMM exhausted: cannot allocate a private copy.
                        //
                        // Aliasing the shared cache page with PAGE_WRITABLE set
                        // is unsafe — a subsequent write (e.g., ld-linux GOT
                        // relocation) would corrupt the cache frame for all
                        // other concurrent mappers of this (mount,inode,offset).
                        // Fail the fault instead.  Per POSIX mmap(2) and
                        // Intel SDM Vol. 3A §4.10.5, demand-paging is permitted
                        // to signal the faulting thread (SIGSEGV) when physical
                        // backing cannot be allocated.
                        //
                        // Refcount accounting: cache::insert holds the cache ref
                        // (rc → 1 steady state after guard drop); release only
                        // the guard ref acquired above.
                        let _ = crate::mm::refcount::page_ref_dec(phys);
                        return false;
                    }
                } else {
                    // MAP_SHARED writable, or any read-only mapping: alias the
                    // cache page directly.  Writes via MAP_SHARED are visible to
                    // all other mappers — required by mmap(2) MAP_SHARED contract.
                    //
                    // W215 H3a diagnostic: mirror the readahead-arm check.
                    // The single-page path inserts under (mount_idx, inode,
                    // file_page_offset); if is_phys_in_cache returns a different
                    // key, a concurrent re-insertion race has occurred.
                    #[cfg(feature = "firefox-test")]
                    if is_writable_spf {
                        if let Some((c_mount, c_inode, c_off)) =
                            crate::mm::cache::is_phys_in_cache(phys)
                        {
                            if c_mount != mount_idx || c_inode != inode || c_off != file_page_offset {
                                PFH_WRITABLE_ALIAS_CACHE.fetch_add(1, Ordering::Relaxed);
                                crate::serial_println!(
                                    "[H3a] ALIAS-CACHE single-page phys={:#x} \
                                     cache_key=({},{:#x},{:#x}) installer_key=({},{:#x},{:#x}) \
                                     rip={:#x}",
                                    phys,
                                    c_mount, c_inode, c_off,
                                    mount_idx, inode, file_page_offset,
                                    _frame.rip,
                                );
                            }
                        }
                    }
                    // W215 diagnostic Arm-1 (single-page alias install
                    // — install-race witness already probed above after
                    // cache::insert).
                    #[cfg(feature = "firefox-test")]
                    crate::mm::w215_diag::prov_record(
                        phys,
                        crate::mm::w215_diag::KIND_PFH_INSTALL,
                        crate::mm::w215_diag::pack_cache_key(inode, file_page_offset),
                    );
                    crate::mm::refcount::page_ref_inc(phys); // PTE reference
                    crate::mm::vmm::map_page_in(cr3, page_addr, phys, page_flags);
                    crate::mm::vmm::invlpg(page_addr);
                    // Release guard — steady state: cache(1) + PTE(1) = 2.
                    let _ = crate::mm::refcount::page_ref_dec(phys);
                }
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
                // W216 H_5j-B (unified concurrency): sample the VmSpace
                // generation before the allocation+zero+install sequence.
                // Anonymous faults have a narrower race window than file-backed
                // (no I/O drop of PROCESS_TABLE) but a sibling-CPU
                // sys_munmap / MAP_FIXED Phase 2b can still mutate the VMA list
                // between the find_vma above and the install below; the check
                // keeps the abort-and-retry invariant uniform across all PFH
                // install arms.  See `VmSpace::generation`.
                let gen_at_start =
                    vm_space.generation.load(core::sync::atomic::Ordering::Acquire);
                // Allocate a zeroed page
                if let Some(phys) = crate::mm::pmm::alloc_page() {
                    unsafe {
                        core::ptr::write_bytes((PHYS_OFF + phys) as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
                    }
                    // Re-check generation immediately before install.
                    let gen_now =
                        vm_space.generation.load(core::sync::atomic::Ordering::Acquire);
                    if gen_now != gen_at_start {
                        #[cfg(feature = "firefox-test")]
                        {
                            static CNT: core::sync::atomic::AtomicU64 =
                                core::sync::atomic::AtomicU64::new(0);
                            let n = CNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                            if n < 5 || n % 500 == 0 {
                                crate::serial_println!(
                                    "[PF/gen-abort] ANON #{} addr={:#x} \
                                     gen_at_start={} gen_now={} — releasing frame",
                                    n, page_addr, gen_at_start, gen_now);
                            }
                        }
                        crate::mm::pmm::free_page(phys);
                        return false;
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

// ISR stub macro — creates a naked function that pushes state and calls exception_handler.
//
// Stack layout on entry to exception_handler (addresses increase upward):
//
//   [rsp+0]   r15   ← last pushed (lowest addr)
//   [rsp+8]   r14
//   [rsp+16]  r13
//   [rsp+24]  r12
//   [rsp+32]  rbp
//   [rsp+40]  rbx
//   [rsp+48]  r11
//   [rsp+56]  r10
//   [rsp+64]  r9
//   [rsp+72]  r8
//   [rsp+80]  rdi
//   [rsp+88]  rsi
//   [rsp+96]  rdx
//   [rsp+104] rcx
//   [rsp+112] rax   ← first pushed (highest addr before InterruptFrame)
//   [rsp+120] error_code (real for isr_with_error, 0 for isr_no_error)
//   [rsp+128] InterruptFrame { rip, cs, rflags, rsp, ss }  ← rdx arg to handler
//
// Equivalently, from an `InterruptFrame*` pointer `frame`:
//   frame[-1] = error_code
//   frame[-2] = rax
//   frame[-3] = rcx
//   frame[-4] = rdx
//   frame[-5] = rsi
//   frame[-6] = rdi
//   frame[-7] = r8
//   frame[-8] = r9
//   frame[-9] = r10
//   frame[-10]= r11
//   frame[-11]= rbx
//   frame[-12]= rbp
//   frame[-13]= r12
//   frame[-14]= r13
//   frame[-15]= r14
//   frame[-16]= r15
macro_rules! isr_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            // Naked ISR stub. Saves all GPRs, calls handler, restores, irets.
            core::arch::naked_asm!(
                // ── SMAP entry guard ────────────────────────────────────
                // Force EFLAGS.AC=0 at the gate.  An IDT entry leaves AC
                // at whatever the interrupted context held; for a ring-3
                // entry an attacker may have set AC=1 from userspace
                // (the AC bit is not privileged — CWE-269 / CWE-693).
                // Without this clear, any latent unbracketed kernel-side
                // user-pointer deref runs with SMAP disabled, converting
                // a fail-stop fault into an arbitrary-kernel-write
                // primitive.  Per Intel SDM Vol. 2A (CLAC) the
                // instruction raises #UD if CR4.SMAP=0, so we gate the
                // emit on the `SMAP_ENABLED` runtime flag.
                "cmp byte ptr [rip + {smap_enabled}], 0",
                "je 90f",
                "clac",
                "90:",
                "push 0",           // Fake error code
                // caller-saved (scratch) registers
                "push rax",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                // callee-saved registers (needed for full GPR dump)
                "push rbx",
                "push rbp",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "mov rdi, {vector}",   // arg1: vector
                "mov rsi, 0",          // arg2: error code (0)
                "lea rdx, [rsp + 128]", // arg3: pointer to InterruptFrame
                "call {handler}",
                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop rbp",
                "pop rbx",
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
                smap_enabled = sym crate::arch::x86_64::smap::SMAP_ENABLED,
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
                // ── SMAP entry guard ────────────────────────────────────
                // See `isr_no_error!` for the threat model.  Same
                // rationale: clear EFLAGS.AC at the IDT gate so a
                // ring-3 attacker cannot inherit AC=1 into the kernel
                // and bypass SMAP on any unbracketed user-pointer
                // deref.  Intel SDM Vol. 3A §4.6.1 (SMAP), §6.4
                // (interrupt RFLAGS preserve), Vol. 2A (CLAC #UD on
                // CR4.SMAP=0 — hence the runtime gate).
                "cmp byte ptr [rip + {smap_enabled}], 0",
                "je 90f",
                "clac",
                "90:",
                // Error code already on stack from CPU
                // caller-saved (scratch) registers
                "push rax",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                // callee-saved registers (needed for full GPR dump)
                "push rbx",
                "push rbp",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "mov rdi, {vector}",    // arg1: vector
                "mov rsi, [rsp + 120]", // arg2: error code (rax×8 + callee×6 = 15×8 = 120 above rsp)
                "lea rdx, [rsp + 128]", // arg3: pointer to InterruptFrame (15 regs + error = 128)
                "call {handler}",
                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop rbp",
                "pop rbx",
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
                smap_enabled = sym crate::arch::x86_64::smap::SMAP_ENABLED,
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
        // ── SMAP entry guard ────────────────────────────────────────────
        // INT 0x80 enters from ring 3 with the user RFLAGS preserved per
        // Intel SDM Vol. 3A §6.4 (interrupt RFLAGS preserve).  An
        // attacker may set EFLAGS.AC=1 from userspace (the AC bit is not
        // privileged — CWE-269 / CWE-693) and call INT 0x80 to enter the
        // kernel with SMAP silently lifted.  Force AC=0 at the gate; the
        // companion FMASK setting in `kernel/src/syscall/mod.rs` covers
        // the SYSCALL path, which bypasses the IDT.  CLAC raises #UD on
        // CR4.SMAP=0 (Intel SDM Vol. 2A), so the emit is gated on the
        // runtime `SMAP_ENABLED` flag.
        "cmp byte ptr [rip + {smap_enabled}], 0",
        "je 90f",
        "clac",
        "90:",
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
        smap_enabled = sym crate::arch::x86_64::smap::SMAP_ENABLED,
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
        // ── SMAP entry guard ────────────────────────────────────────────
        // Same threat model as isr_syscall_int80 above: a ring-3
        // attacker can pre-set EFLAGS.AC=1 and INT 0x2E into the kernel
        // with SMAP silently lifted (CWE-269 / CWE-693).  Clear AC at
        // the gate; gate on `SMAP_ENABLED` to avoid #UD on non-SMAP
        // CPUs (Intel SDM Vol. 2A — CLAC).
        "cmp byte ptr [rip + {smap_enabled}], 0",
        "je 90f",
        "clac",
        "90:",
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
        smap_enabled = sym crate::arch::x86_64::smap::SMAP_ENABLED,
    );
}