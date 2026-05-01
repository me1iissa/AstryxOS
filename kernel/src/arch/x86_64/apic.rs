//! Local APIC / I/O APIC / SMP support for x86_64
//!
//! Provides APIC initialization, I/O APIC redirection, and AP (Application Processor)
//! bootstrap. On systems without APIC (or single-CPU), gracefully falls back.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

// === LAPIC Constants ===
const IA32_APIC_BASE_MSR: u32 = 0x1B;
const LAPIC_ID: u32            = 0x020;
const LAPIC_VERSION: u32       = 0x030;
const LAPIC_TPR: u32           = 0x080;
const LAPIC_EOI: u32           = 0x0B0;
const LAPIC_SVR: u32           = 0x0F0;
const LAPIC_ICR_LO: u32        = 0x300;
const LAPIC_ICR_HI: u32        = 0x310;
const LAPIC_TIMER_LVT: u32     = 0x320;
const LAPIC_TIMER_INIT: u32    = 0x380;
const LAPIC_TIMER_CURRENT: u32 = 0x390;
const LAPIC_TIMER_DIVIDE: u32  = 0x3E0;

// I/O APIC registers
const IOAPIC_REGSEL: u32 = 0x00;
const IOAPIC_WIN: u32    = 0x10;
const IOAPIC_ID: u8      = 0x00;
const IOAPIC_VER: u8     = 0x01;
const IOAPIC_REDTBL: u8  = 0x10;

// APIC IPI delivery modes
const ICR_INIT: u32    = 0x0000_0500;
const ICR_STARTUP: u32 = 0x0000_0600;
const ICR_ASSERT: u32  = 0x0000_4000;

/// Maximum supported CPUs.
pub const MAX_CPUS: usize = 16;

/// LAPIC base address (MMIO).
static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// I/O APIC base address.
static IOAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// BSP (Boot Strap Processor) APIC ID.
static BSP_APIC_ID: AtomicU8 = AtomicU8::new(0);

/// Number of active CPUs (starts at 1 for BSP).
static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// Whether APIC is available and initialized.
static APIC_ENABLED: AtomicBool = AtomicBool::new(false);

/// AP started flags.
static AP_STARTED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

use crate::hal::{rdmsr, wrmsr};

/// Check if APIC is available via CPUID.
fn has_apic() -> bool {
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            lateout("ecx") _,
            lateout("edx") edx,
            options(nomem, nostack)
        );
    }
    edx & (1 << 9) != 0
}

// LAPIC MMIO read/write
fn lapic_read(reg: u32) -> u32 {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return 0;
    }
    unsafe { core::ptr::read_volatile((base + reg as u64) as *const u32) }
}

fn lapic_write(reg: u32, val: u32) {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    unsafe {
        core::ptr::write_volatile((base + reg as u64) as *mut u32, val);
    }
}

// I/O APIC read/write
fn ioapic_read(reg: u8) -> u32 {
    let base = IOAPIC_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return 0;
    }
    unsafe {
        core::ptr::write_volatile(base as *mut u32, reg as u32);
        core::ptr::read_volatile((base + 0x10) as *const u32)
    }
}

fn ioapic_write(reg: u8, val: u32) {
    let base = IOAPIC_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    unsafe {
        core::ptr::write_volatile(base as *mut u32, reg as u32);
        core::ptr::write_volatile((base + 0x10) as *mut u32, val);
    }
}

/// Disable the legacy 8259 PIC by masking all IRQs.
fn disable_pic() {
    unsafe {
        crate::hal::outb(0xA1, 0xFF); // Mask all on PIC2
        crate::hal::outb(0x21, 0xFF); // Mask all on PIC1
    }
    crate::serial_println!("[APIC] Legacy 8259 PIC disabled");
}

/// Initialize the Local APIC.
pub fn init() {
    if !has_apic() {
        crate::serial_println!("[APIC] No APIC detected — staying with 8259 PIC");
        return;
    }

    // Read APIC base from MSR
    let apic_base_msr = unsafe { rdmsr(IA32_APIC_BASE_MSR) };
    let base_phys = apic_base_msr & 0xFFFF_FFFF_FFFF_F000;

    // Map LAPIC MMIO into the kernel's higher-half so it remains accessible
    // from any CR3 (including user-process page tables that don't have PML4[0]).
    // User processes inherit PML4[256-511] from the kernel, so this mapping is
    // visible from all processes without USER bit.
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let lapic_virt = PHYS_OFF + base_phys;
    use crate::mm::vmm::{PAGE_WRITABLE, PAGE_NO_CACHE, PAGE_WRITE_THROUGH,
                         PAGE_GLOBAL, PAGE_PRESENT};
    // MMIO pages must NOT have PAGE_NO_EXECUTE (NX bit, bit 63). On APs,
    // EFER.NXE is not yet set when ap_rust_entry first reads the LAPIC ID.
    // With NXE=0, bit 63 in any PTE is a *reserved bit* → #PF(RSVD) on ANY
    // access (data or code), not only instruction fetches.
    let mmio_flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_CACHE
                   | PAGE_WRITE_THROUGH | PAGE_GLOBAL;
    crate::mm::vmm::map_page(lapic_virt, base_phys, mmio_flags);
    LAPIC_BASE.store(lapic_virt, Ordering::Relaxed);

    // Disable legacy PIC before enabling APIC
    disable_pic();

    // Enable APIC via MSR (set global enable + base)
    unsafe {
        wrmsr(IA32_APIC_BASE_MSR, apic_base_msr | (1 << 11));
    }

    // Set spurious interrupt vector register (SVR) — enable APIC + vector 0xFF
    lapic_write(LAPIC_SVR, 0x1FF); // Enable (bit 8) + vector 0xFF

    // Set task priority to 0 (accept all interrupts)
    lapic_write(LAPIC_TPR, 0);

    // Read BSP APIC ID
    let bsp_id = (lapic_read(LAPIC_ID) >> 24) as u8;
    BSP_APIC_ID.store(bsp_id, Ordering::Relaxed);

    // Set up LAPIC timer
    // Use divide-by-16 for calibration
    lapic_write(LAPIC_TIMER_DIVIDE, 0x03); // Divide by 16

    // Calibrate using PIT: count LAPIC ticks in ~10ms
    let calibration_ticks = calibrate_lapic_timer();

    // Configure periodic timer at ~100 Hz
    // We measured ticks in 10ms, so this gives us ~100 Hz
    let timer_count = calibration_ticks;
    lapic_write(LAPIC_TIMER_LVT, 0x20000 | 32); // Periodic | vector 32
    lapic_write(LAPIC_TIMER_INIT, timer_count);

    crate::serial_println!(
        "[APIC] Local APIC initialized: BSP ID={}, base={:#x}, timer count={}",
        bsp_id,
        base_phys,
        timer_count
    );

    // Try to initialize I/O APIC
    init_ioapic();

    APIC_ENABLED.store(true, Ordering::Relaxed);
    crate::serial_println!("[APIC] APIC subsystem fully initialized");
}

/// Calibrate LAPIC timer using the PIT.
fn calibrate_lapic_timer() -> u32 {
    // Use PIT Channel 2 for calibration
    unsafe {
        // Set PIT channel 2 to one-shot mode
        crate::hal::outb(0x61, (crate::hal::inb(0x61) & 0xFD) | 0x01);
        crate::hal::outb(0x43, 0xB0); // Channel 2, lobyte/hibyte, one-shot

        // 11932 ticks at 1193182 Hz ≈ 10ms
        crate::hal::outb(0x42, (11932 & 0xFF) as u8);
        crate::hal::outb(0x42, (11932 >> 8) as u8);
    }

    // Reset LAPIC timer with max count
    lapic_write(LAPIC_TIMER_INIT, 0xFFFF_FFFF);

    // Wait for PIT channel 2 to expire
    unsafe {
        // Gate on
        let val = crate::hal::inb(0x61) & 0xFE;
        crate::hal::outb(0x61, val);
        crate::hal::outb(0x61, val | 1);

        // Wait for output bit (bit 5 of port 0x61)
        while crate::hal::inb(0x61) & 0x20 == 0 {}
    }

    // Read how many ticks elapsed
    let elapsed = 0xFFFF_FFFF - lapic_read(LAPIC_TIMER_CURRENT);

    // Stop the timer temporarily
    lapic_write(LAPIC_TIMER_INIT, 0);

    if elapsed == 0 {
        // Fallback value if calibration failed
        100_000
    } else {
        elapsed
    }
}

/// Initialize I/O APIC (default address 0xFEC00000).
fn init_ioapic() {
    // Map I/O APIC MMIO into the kernel higher-half (same reasoning as LAPIC).
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let ioapic_phys: u64 = 0xFEC0_0000;
    let ioapic_virt: u64 = PHYS_OFF + ioapic_phys;
    use crate::mm::vmm::{PAGE_WRITABLE, PAGE_NO_CACHE, PAGE_WRITE_THROUGH,
                         PAGE_GLOBAL, PAGE_PRESENT};
    let mmio_flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_CACHE
                   | PAGE_WRITE_THROUGH | PAGE_GLOBAL; // no NX — see LAPIC comment above
    crate::mm::vmm::map_page(ioapic_virt, ioapic_phys, mmio_flags);
    IOAPIC_BASE.store(ioapic_virt, Ordering::Relaxed);

    let ver = ioapic_read(IOAPIC_VER);
    let max_entries = ((ver >> 16) & 0xFF) as u8;
    crate::serial_println!(
        "[APIC] I/O APIC version={:#x}, max_entries={}",
        ver & 0xFF,
        max_entries + 1
    );

    // Route keyboard IRQ (ISA IRQ1) to BSP at vector 33
    let bsp_id = BSP_APIC_ID.load(Ordering::Relaxed);

    // Map ISA IRQ 1 (keyboard) → vector 33, to BSP
    ioapic_route_irq(1, 33, bsp_id);

    crate::serial_println!(
        "[APIC] I/O APIC: IRQ1 (keyboard) → vector 33, APIC ID {}",
        bsp_id
    );

    // Map ISA IRQ 12 (mouse) → vector 44, to BSP
    ioapic_route_irq(12, 44, bsp_id);

    crate::serial_println!(
        "[APIC] I/O APIC: IRQ12 (mouse) → vector 44, APIC ID {}",
        bsp_id
    );
}

/// Route an IRQ through the I/O APIC (edge-triggered, active-high — for ISA IRQs).
pub fn ioapic_route_irq(irq: u8, vector: u8, dest_apic_id: u8) {
    let redtbl_offset = IOAPIC_REDTBL + irq * 2;

    // Low 32 bits: vector, delivery mode (fixed=0), polarity, trigger mode
    let lo: u32 = vector as u32; // Fixed delivery, edge-triggered, active high
    // High 32 bits: destination APIC ID in bits 24-31
    let hi: u32 = (dest_apic_id as u32) << 24;

    ioapic_write(redtbl_offset + 1, hi);
    ioapic_write(redtbl_offset, lo);
}

/// Route a PCI IRQ through the I/O APIC (level-triggered, active-low — for PCI INTx).
pub fn ioapic_route_irq_level(irq: u8, vector: u8, dest_apic_id: u8) {
    let redtbl_offset = IOAPIC_REDTBL + irq * 2;

    // Low 32 bits: vector | bit 13 (active-low) | bit 15 (level-triggered)
    let lo: u32 = vector as u32 | (1 << 13) | (1 << 15);
    // High 32 bits: destination APIC ID in bits 24-31
    let hi: u32 = (dest_apic_id as u32) << 24;

    ioapic_write(redtbl_offset + 1, hi);
    ioapic_write(redtbl_offset, lo);
}

/// Send End-of-Interrupt to the Local APIC.
pub fn lapic_eoi() {
    lapic_write(LAPIC_EOI, 0);
}

/// Check if APIC is enabled and active.
pub fn is_enabled() -> bool {
    APIC_ENABLED.load(Ordering::Relaxed)
}

/// Get the number of active CPUs.
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Relaxed)
}

/// Get the bootstrap-processor's APIC ID.  Used by drivers to target the
/// BSP for legacy PCI INTx routing through the IO-APIC.
pub fn bsp_apic_id() -> u8 {
    BSP_APIC_ID.load(Ordering::Relaxed)
}

/// Get the current CPU's logical index.
///
/// Reads `IA32_TSC_AUX` (MSR 0xC0000103), which is initialised to the CPU's
/// APIC ID by `crate::syscall::set_per_cpu_id()` during CPU startup.  Using
/// an MSR avoids any page-table dependency, so this function works correctly
/// even after a user-process CR3 switch (unlike the previous LAPIC MMIO read,
/// which could return 0 when the LAPIC identity mapping was not present in the
/// active user page table).
///
/// # Initialisation contract
/// `crate::syscall::set_per_cpu_id(apic_id)` MUST be called on every CPU
/// before any call to `cpu_index()` or `current_tid()`.  For the BSP this
/// happens inside `crate::syscall::init()`; for each AP it happens at the
/// very top of `ap_rust_entry()` using the LAPIC-read APIC ID.
pub fn current_apic_id() -> u8 {
    // IA32_TSC_AUX (MSR 0xC000_0103) holds the APIC ID written at init.
    unsafe { rdmsr(0xC000_0103) as u8 }
}

/// Get the current CPU index, bounded to `[0, MAX_CPUS)`.
/// Use this instead of `current_apic_id() as usize` at every call site.
#[inline(always)]
pub fn cpu_index() -> usize {
    let id = current_apic_id() as usize;
    if id >= MAX_CPUS { 0 } else { id }
}

/// Send an IPI (Inter-Processor Interrupt) to a specific APIC ID.
pub fn send_ipi(dest_apic_id: u8, vector: u8) {
    if !is_enabled() {
        return;
    }
    lapic_write(LAPIC_ICR_HI, (dest_apic_id as u32) << 24);
    lapic_write(LAPIC_ICR_LO, vector as u32 | ICR_ASSERT);
    // Wait for delivery
    while lapic_read(LAPIC_ICR_LO) & (1 << 12) != 0 {}
}

/// Bootstrap application processors (APs).
///
/// Writes a 16-bit real-mode trampoline at physical 0x8000, then sends the
/// INIT–SIPI–SIPI sequence to every AP found via a simple APIC-ID scan
/// (QEMU always assigns contiguous IDs starting at 0).
///
/// Each AP transitions 16-bit real → 32-bit protected → 64-bit long mode,
/// loads the BSP's GDT + IDT, enables its local APIC, and enters
/// `ap_rust_entry()`.
pub fn start_aps() {
    if !is_enabled() {
        return;
    }

    let bsp_id = BSP_APIC_ID.load(Ordering::Relaxed);

    // ── 1. Write the AP trampoline at 0x8000 ────────────────────────
    // We place a small bootloader there.  The trampoline is hand-crafted
    // machine code that:
    //   • starts in 16-bit real mode (CS:IP = 0x0800:0x0000)
    //   • loads a temporary GDT with a flat 32-bit segment and a 64-bit segment
    //   • enables protected mode (CR0.PE)
    //   • jumps to 32-bit stub that enables PAE + long-mode (EFER.LME),
    //     loads BSP's CR3, sets CR0.PG, and does a far jump to 64-bit code
    //   • in 64-bit mode: loads BSP's GDT & IDT, sets RSP from the
    //     per-AP stack stored at TRAMPOLINE_STACK_PTR, and calls ap_rust_entry
    //
    // Communication addresses (identity-mapped, below 1 MiB):
    //   0x7000  — BSP CR3               (u64)
    //   0x7008  — AP stack pointer       (u64)
    //   0x7010  — Pointer to GDT desc    (10 bytes: limit u16 + base u64)
    //   0x7020  — Pointer to IDT desc    (10 bytes: limit u16 + base u64)
    //   0x7030  — Pointer to ap_rust_entry (u64)
    //   0x7038  — AP APIC ID passed by BSP (u8, but stored as u64 for alignment)

    const TRAMPOLINE_ADDR: u64 = 0x8000;
    const DATA_ADDR: u64       = 0x7000;

    // Write communication data
    unsafe {
        // CR3 — read the current page table root
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        core::ptr::write_volatile(DATA_ADDR as *mut u64, cr3);        // [0x7000] = CR3

        // Stack will be set per-AP before each SIPI (placeholder 0)
        core::ptr::write_volatile((DATA_ADDR + 0x08) as *mut u64, 0); // [0x7008] = stack

        // GDT descriptor — reuse BSP's loaded GDT (read SGDT)
        let mut gdt_desc: [u8; 10] = [0; 10];
        core::arch::asm!("sgdt [{}]", in(reg) gdt_desc.as_mut_ptr(), options(nostack));
        core::ptr::copy_nonoverlapping(
            gdt_desc.as_ptr(),
            (DATA_ADDR + 0x10) as *mut u8,
            10,
        );

        // IDT descriptor — reuse BSP's loaded IDT (read SIDT)
        let mut idt_desc: [u8; 10] = [0; 10];
        core::arch::asm!("sidt [{}]", in(reg) idt_desc.as_mut_ptr(), options(nostack));
        core::ptr::copy_nonoverlapping(
            idt_desc.as_ptr(),
            (DATA_ADDR + 0x20) as *mut u8,
            10,
        );

        // ap_rust_entry pointer
        core::ptr::write_volatile(
            (DATA_ADDR + 0x30) as *mut u64,
            ap_rust_entry as *const () as u64,
        );
    }

    // ── Write the trampoline machine code ────────────────────────────
    // This is a minimal 16→32→64 transition blob.
    write_trampoline(TRAMPOLINE_ADDR);

    // ── Ensure trampoline + data pages are executable ────────────────
    // UEFI/OVMF often marks data pages with the NX (No-Execute) bit.
    // The AP trampoline MUST execute code from these pages, so clear NX
    // at every level of the page-table walk.
    unsafe {
        ensure_page_executable(DATA_ADDR);       // 0x7000
        ensure_page_executable(TRAMPOLINE_ADDR); // 0x8000
    }
    crate::serial_println!("[SMP] Trampoline pages marked executable");

    // ── 2. Send INIT-SIPI-SIPI to each AP ───────────────────────────
    // We scan APIC IDs 0..MAX_CPUS, skipping the BSP.
    // QEMU allocates contiguous APIC IDs, so this works.
    let sipi_vector = (TRAMPOLINE_ADDR >> 12) as u32; // 0x08 for 0x8000

    crate::serial_println!("[SMP] Starting AP scan (BSP={}, vector={})", bsp_id, sipi_vector);

    let mut consecutive_fails: u8 = 0;

    for ap_id in 0..(MAX_CPUS as u8) {
        if ap_id == bsp_id {
            continue;
        }

        // Stop early after 1 consecutive non-responsive AP
        if consecutive_fails >= 1 {
            break;
        }

        crate::serial_println!("[SMP] Trying AP {}...", ap_id);

        // Allocate a 16 KiB stack for this AP
        let ap_stack = crate::mm::pmm::alloc_pages(4); // 4 pages = 16 KiB
        let ap_stack = match ap_stack {
            Some(s) => s,
            None => {
                crate::serial_println!("[SMP] Failed to allocate stack for AP {}", ap_id);
                continue;
            }
        };
        // Convert physical stack top to kernel virtual so the AP's RSP lives in
        // the higher-half (accessible even when user CR3 is active via PML4[256]).
        // Using a physical address here would be fine while the kernel CR3 is
        // active (identity map), but the first context-switch saves RSP into the
        // thread's context.rsp — that physical value could be re-mapped by a user
        // process page table if PMM later hands out the same physical page.
        let ap_stack_top = ap_stack + 16384 + crate::proc::KERNEL_VIRT_OFFSET;

        // Write AP stack pointer and APIC ID into the data area
        unsafe {
            core::ptr::write_volatile((DATA_ADDR + 0x08) as *mut u64, ap_stack_top);
            core::ptr::write_volatile((DATA_ADDR + 0x38) as *mut u64, ap_id as u64);
        }

        // Send INIT IPI
        lapic_write(LAPIC_ICR_HI, (ap_id as u32) << 24);
        lapic_write(LAPIC_ICR_LO, ICR_INIT | ICR_ASSERT);
        // Wait for delivery (with timeout)
        for _ in 0..1000u32 {
            if lapic_read(LAPIC_ICR_LO) & (1 << 12) == 0 { break; }
        }

        // 10 ms delay — reduced inner loop count for QEMU TCG
        delay_microseconds(1_000);

        // De-assert INIT
        lapic_write(LAPIC_ICR_HI, (ap_id as u32) << 24);
        lapic_write(LAPIC_ICR_LO, ICR_INIT); // level de-assert
        for _ in 0..1000u32 {
            if lapic_read(LAPIC_ICR_LO) & (1 << 12) == 0 { break; }
        }

        // Send SIPI #1
        lapic_write(LAPIC_ICR_HI, (ap_id as u32) << 24);
        lapic_write(LAPIC_ICR_LO, ICR_STARTUP | sipi_vector);
        for _ in 0..1000u32 {
            if lapic_read(LAPIC_ICR_LO) & (1 << 12) == 0 { break; }
        }

        // Brief delay then check
        delay_microseconds(200);

        // Check if AP started
        if AP_STARTED[ap_id as usize].load(Ordering::Acquire) {
            CPU_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::serial_println!("[SMP] AP {} started (after SIPI #1)", ap_id);
            consecutive_fails = 0;
            continue;
        }

        // Send SIPI #2 (retry per Intel spec)
        lapic_write(LAPIC_ICR_HI, (ap_id as u32) << 24);
        lapic_write(LAPIC_ICR_LO, ICR_STARTUP | sipi_vector);
        for _ in 0..1000u32 {
            if lapic_read(LAPIC_ICR_LO) & (1 << 12) == 0 { break; }
        }

        // Wait up to ~10 ms for the AP to start (reduced for QEMU TCG)
        for _ in 0..10 {
            delay_microseconds(500);
            if AP_STARTED[ap_id as usize].load(Ordering::Acquire) {
                break;
            }
        }

        if AP_STARTED[ap_id as usize].load(Ordering::Acquire) {
            CPU_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::serial_println!("[SMP] AP {} started (after SIPI #2)", ap_id);
            consecutive_fails = 0;
        } else {
            consecutive_fails += 1;
        }
    }

    let total = CPU_COUNT.load(Ordering::Relaxed);
    crate::serial_println!(
        "[SMP] AP bootstrap complete: {} CPU(s) online (BSP={})",
        total,
        bsp_id
    );
}

/// Ensure that the page containing `phys_addr` is executable (clear the NX bit).
///
/// UEFI/OVMF page tables frequently set the NX (No-Execute, bit 63) bit on
/// data pages.  The AP trampoline at 0x8000 lives in such a region.
/// If the AP's EFER.NXE = 0 and any PTE in the walk has bit 63 set, the
/// hardware treats it as a reserved-bit violation (#PF) on *every* access
/// — not only instruction fetches — which causes an immediate triple-fault
/// because the AP has no IDT yet.
///
/// Even with NXE = 1 the NX bit would block instruction fetches, so we
/// unconditionally clear it at every level of the page-table walk.
unsafe fn ensure_page_executable(virt_addr: u64) {
    let cr3: u64;
    core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    let pml4_phys = cr3 & 0x000F_FFFF_FFFF_F000;

    const NX: u64 = 1u64 << 63;

    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx   = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx   = ((virt_addr >> 12) & 0x1FF) as usize;

    // --- PML4 ---
    let pml4_ptr = pml4_phys as *mut u64;
    let pml4e = core::ptr::read_volatile(pml4_ptr.add(pml4_idx));
    if pml4e & 1 == 0 { return; }
    if pml4e & NX != 0 {
        core::ptr::write_volatile(pml4_ptr.add(pml4_idx), pml4e & !NX);
    }

    let pdpt_phys = pml4e & 0x000F_FFFF_FFFF_F000;
    let pdpt_ptr = pdpt_phys as *mut u64;
    let pdpte = core::ptr::read_volatile(pdpt_ptr.add(pdpt_idx));
    if pdpte & 1 == 0 { return; }
    if pdpte & NX != 0 {
        core::ptr::write_volatile(pdpt_ptr.add(pdpt_idx), pdpte & !NX);
    }
    // 1 GiB huge page — nothing deeper to walk
    if pdpte & 0x80 != 0 {
        core::arch::asm!("invlpg [{}]", in(reg) virt_addr, options(nostack));
        return;
    }

    let pd_phys = pdpte & 0x000F_FFFF_FFFF_F000;
    let pd_ptr = pd_phys as *mut u64;
    let pde = core::ptr::read_volatile(pd_ptr.add(pd_idx));
    if pde & 1 == 0 { return; }
    if pde & NX != 0 {
        core::ptr::write_volatile(pd_ptr.add(pd_idx), pde & !NX);
    }
    // 2 MiB huge page — nothing deeper
    if pde & 0x80 != 0 {
        core::arch::asm!("invlpg [{}]", in(reg) virt_addr, options(nostack));
        return;
    }

    let pt_phys = pde & 0x000F_FFFF_FFFF_F000;
    let pt_ptr = pt_phys as *mut u64;
    let pte = core::ptr::read_volatile(pt_ptr.add(pt_idx));
    if pte & 1 == 0 { return; }
    if pte & NX != 0 {
        core::ptr::write_volatile(pt_ptr.add(pt_idx), pte & !NX);
    }
    core::arch::asm!("invlpg [{}]", in(reg) virt_addr, options(nostack));
}

/// Busy-wait delay using a simple counted loop.
/// Approximate microsecond granularity (calibrated-ish for ~1 GHz+ CPUs).
fn delay_microseconds(us: u64) {
    // Use a volatile read loop to prevent optimization.
    // Reduced inner loop for QEMU TCG (where PAUSE is slow).
    for _ in 0..us {
        for _ in 0..50 {
            unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
        }
    }
}

/// Write the 16-bit real-mode → 64-bit long-mode trampoline at the given
/// physical address (which must be page-aligned and below 1 MiB).
fn write_trampoline(addr: u64) {
    // The trampoline is assembled manually as a byte sequence.
    // It does:
    //   1. 16-bit: cli, load temporary GDT, enable PE → 32-bit
    //   2. 32-bit: enable PAE, set EFER.LME, load CR3, enable PG → 64-bit
    //   3. 64-bit: lgdt (BSP's GDT), lidt (BSP's IDT), set RSP, call ap_rust_entry
    //
    // All data pointers are at 0x7000.

    // Temporary GDT for the transition (placed at trampoline + 0x100)
    let tmp_gdt_addr = addr + 0x100;

    // Write the temporary GDT (3 entries: null, 32-bit code, 64-bit code)
    unsafe {
        let gdt = tmp_gdt_addr as *mut u64;
        // Entry 0: Null
        core::ptr::write_volatile(gdt.add(0), 0u64);
        // Entry 1 (0x08): 32-bit code, flat, ring 0
        core::ptr::write_volatile(gdt.add(1), 0x00CF9A000000FFFFu64);
        // Entry 2 (0x10): 64-bit code, ring 0
        core::ptr::write_volatile(gdt.add(2), 0x00AF9A000000FFFFu64);
        // Entry 3 (0x18): 32-bit data, flat, ring 0
        core::ptr::write_volatile(gdt.add(3), 0x00CF92000000FFFFu64);
    }

    // Build the trampoline machine code
    let code: &[u8] = &[
        // ── 16-bit real mode ──  (org 0x8000, CS:IP = 0x0800:0x0000)
        0xFA,                       // 0x00: cli
        0x31, 0xC0,                 // 0x01: xor eax, eax
        0x8E, 0xD8,                 // 0x03: mov ds, ax
        0x8E, 0xC0,                 // 0x05: mov es, ax
        0x8E, 0xD0,                 // 0x07: mov ss, ax

        // Load temporary GDT (at trampoline + 0x100)
        // LGDT [0x80F0] — GDT pointer is at trampoline + 0xF0
        0x0F, 0x01, 0x16,          // 0x09: lgdt [imm16]
        0xF0, 0x80,                 // 0x0C: = 0x80F0

        // Enable PE (protected mode)
        0x0F, 0x20, 0xC0,          // 0x0E: mov eax, cr0
        0x66, 0x83, 0xC8, 0x01,    // 0x11: or eax, 1
        0x0F, 0x22, 0xC0,          // 0x15: mov cr0, eax

        // Far jump to 32-bit code at (trampoline + 0x30)
        // JMP 0x08:0x00008030
        0x66, 0xEA,                 // 0x18: jmp far 0x08:imm32
        0x30, 0x80, 0x00, 0x00,    // 0x1A: offset = 0x00008030
        0x08, 0x00,                 // 0x1E: segment = 0x0008

        // Padding to 0x30
        0x90, 0x90, 0x90, 0x90,    // 0x20-0x23
        0x90, 0x90, 0x90, 0x90,    // 0x24-0x27
        0x90, 0x90, 0x90, 0x90,    // 0x28-0x2B
        0x90, 0x90, 0x90, 0x90,    // 0x2C-0x2F

        // ── 32-bit protected mode ──  (offset 0x30)
        // Set data segments to 0x18 (32-bit data)
        0xB8, 0x18, 0x00, 0x00, 0x00,  // 0x30: mov eax, 0x18
        0x8E, 0xD8,                     // 0x35: mov ds, ax
        0x8E, 0xD0,                     // 0x37: mov ss, ax
        0x8E, 0xC0,                     // 0x39: mov es, ax

        // Enable PAE (CR4.PAE = bit 5)
        0x0F, 0x20, 0xE0,              // 0x3B: mov eax, cr4
        0x0F, 0xBA, 0xE8, 0x05,        // 0x3E: bts eax, 5
        0x0F, 0x22, 0xE0,              // 0x42: mov cr4, eax

        // Load CR3 from [0x7000]
        0x8B, 0x05, 0x00, 0x70, 0x00, 0x00, // 0x45: mov eax, [0x7000]  (CR3 low 32)
        0x0F, 0x22, 0xD8,                    // 0x4B: mov cr3, eax

        // Enable long mode (EFER.LME = bit 8)
        0xB9, 0x80, 0x00, 0x00, 0xC0, // 0x4E: mov ecx, 0xC0000080  (IA32_EFER)
        0x0F, 0x32,                    // 0x53: rdmsr
        0x0F, 0xBA, 0xE8, 0x08,       // 0x55: bts eax, 8  (LME)
        0x0F, 0x30,                    // 0x59: wrmsr

        // Enable paging (CR0.PG = bit 31)
        0x0F, 0x20, 0xC0,             // 0x5B: mov eax, cr0
        0x0F, 0xBA, 0xE8, 0x1F,       // 0x5E: bts eax, 31
        0x0F, 0x22, 0xC0,             // 0x62: mov cr0, eax

        // Indirect far jump to 64-bit code via pointer at offset 0x70
        // (0xEA direct far jump is INVALID in compatibility mode / IA-32e)
        // JMP FAR [0x8070] — reads 6-byte far pointer (EIP32 + CS16)
        0xFF, 0x2D,                     // 0x65: jmp far [disp32]
        0x70, 0x80, 0x00, 0x00,        // 0x67: disp32 = 0x00008070
        0x90, 0x90, 0x90, 0x90, 0x90,  // 0x6B-0x6F: nop padding

        // Far pointer data for the indirect jump (at offset 0x70)
        0x80, 0x80, 0x00, 0x00,        // 0x70: target EIP = 0x00008080
        0x10, 0x00,                     // 0x74: target CS  = 0x0010
        // Padding to 0x80
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 0x76-0x7D
        0x90, 0x90,                                        // 0x7E-0x7F

        // ── 64-bit long mode ──  (offset 0x80)
        // Load BSP's GDT from [0x7010] (10-byte descriptor)
        // lgdt [0x7010]
        0x0F, 0x01, 0x14, 0x25,        // 0x80: lgdt [abs32]
        0x10, 0x70, 0x00, 0x00,        // 0x84: = 0x00007010

        // Load BSP's IDT from [0x7020]
        // lidt [0x7020]
        0x0F, 0x01, 0x1C, 0x25,        // 0x88: lidt [abs32]
        0x20, 0x70, 0x00, 0x00,        // 0x8C: = 0x00007020

        // Load RSP from [0x7008] — MUST happen before any push/retfq
        // because RSP is 0 after INIT, and push would wrap to 0xFFFF…FFF8
        // (unmapped) causing an immediate triple-fault.
        0x48, 0x8B, 0x24, 0x25,        // 0x90: mov rsp, [abs32]
        0x08, 0x70, 0x00, 0x00,        // 0x94: = 0x00007008

        // Reload CS by a far return
        // push 0x08 (kernel code selector)
        0x6A, 0x08,                     // 0x98: push 0x08
        // mov rax, 0x80A8 (trampoline + 0xA8, our next instruction after retfq)
        0x48, 0xB8,                     // 0x9A: mov rax, imm64
        0xA8, 0x80, 0x00, 0x00,        // 0x9C: low 4 bytes of 0x80A8
        0x00, 0x00, 0x00, 0x00,        // 0xA0: high 4 bytes
        0x50,                           // 0xA4: push rax
        0x48, 0xCB,                     // 0xA5: retfq

        0x90,                           // 0xA7: nop (padding)

        // ── After CS reload ──  (offset 0xA8)
        // Set data segments to 0x10 (kernel data selector)
        0x48, 0xC7, 0xC0, 0x10, 0x00, 0x00, 0x00, // 0xA8: mov rax, 0x10
        0x8E, 0xD8,                     // 0xAF: mov ds, ax
        0x8E, 0xC0,                     // 0xB1: mov es, ax
        0x8E, 0xE0,                     // 0xB3: mov fs, ax
        0x8E, 0xE8,                     // 0xB5: mov gs, ax
        0x8E, 0xD0,                     // 0xB7: mov ss, ax

        // Zero RBP
        0x48, 0x31, 0xED,              // 0xB9: xor rbp, rbp

        // Call ap_rust_entry (address at [0x7030])
        0xFF, 0x14, 0x25,              // 0xBC: call [abs32]
        0x30, 0x70, 0x00, 0x00,        // 0xBF: = 0x00007030

        // If ap_rust_entry returns, halt
        0xFA,                           // 0xC3: cli
        0xF4,                           // 0xC4: hlt
        0xEB, 0xFC,                     // 0xC5: jmp -2 (loop)
    ];

    unsafe {
        // Copy trampoline code
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            addr as *mut u8,
            code.len(),
        );

        // Write temporary GDT pointer at trampoline + 0xF0
        // Format: u16 limit, u32 base (16-bit mode uses 24-bit base, but we'll
        // set the full 32 bits; the CPU ignores the top byte in real mode LGDT)
        let gdt_limit: u16 = (4 * 8 - 1) as u16;  // 4 entries
        let gdt_base: u32 = tmp_gdt_addr as u32;
        let gdt_ptr_addr = (addr + 0xF0) as *mut u8;
        core::ptr::copy_nonoverlapping(
            &gdt_limit as *const u16 as *const u8,
            gdt_ptr_addr,
            2,
        );
        core::ptr::copy_nonoverlapping(
            &gdt_base as *const u32 as *const u8,
            gdt_ptr_addr.add(2),
            4,
        );
    }
}

/// AP entry point in Rust (called from the trampoline in 64-bit mode).
///
/// # Safety
/// Called once per AP after the trampoline transitions to long mode.
/// Must not return.
#[no_mangle]
pub extern "C" fn ap_rust_entry() -> ! {
    // Enable EFER.NXE (bit 11) before ANY memory access through the kernel
    // higher-half page tables. Without NXE=1, bit 63 in a PTE is a reserved bit
    // and triggers #PF(error=0x9, PRESENT|RSVD) on every access (data or code).
    // The BSP enables NXE inside syscall::init_ap(), but APs cannot call that
    // until after lapic_read() below, so we set the bit here directly.
    unsafe {
        let efer = rdmsr(0xC000_0080);
        wrmsr(0xC000_0080, efer | (1 << 11)); // EFER.NXE
    }

    // Read our APIC ID
    let apic_id = (lapic_read(LAPIC_ID) >> 24) as u8;

    // Enable SSE on this AP (BSP does it in arch::x86_64::init)
    crate::arch::x86_64::enable_sse();

    // Enable local APIC
    let apic_base_msr = unsafe { rdmsr(IA32_APIC_BASE_MSR) };
    unsafe {
        wrmsr(IA32_APIC_BASE_MSR, apic_base_msr | (1 << 11));
    }

    // Initialise this AP's per-CPU ID FIRST — before any call to cpu_index()
    // or current_apic_id().  set_per_cpu_id writes apic_id to IA32_TSC_AUX so
    // that current_apic_id() returns the correct per-CPU value from rdmsr.
    // apic_id was read from the LAPIC MMIO above while the kernel CR3 is still
    // active, so it is guaranteed to be correct.
    // MUST be before init_ap_tss() which calls current_apic_id() internally.
    crate::syscall::set_per_cpu_id(apic_id);

    // Load the AP's own per-CPU TSS so that Ring 3 → Ring 0 interrupt stack
    // switches use this AP's dedicated rsp[0] instead of sharing with other APs.
    // This must happen before we enable interrupts or enter Ring 3.
    // current_apic_id() now returns the correct apic_id (set above).
    unsafe { crate::arch::x86_64::gdt::init_ap_tss(); }

    // Set SVR (enable APIC + spurious vector 0xFF)
    lapic_write(LAPIC_SVR, 0x1FF);
    // Accept all interrupts
    lapic_write(LAPIC_TPR, 0);

    // Configure LAPIC timer (same settings as BSP — periodic, vector 32)
    lapic_write(LAPIC_TIMER_DIVIDE, 0x03);   // divide by 16
    lapic_write(LAPIC_TIMER_LVT, 0x20000 | 32); // periodic | vector 32
    lapic_write(LAPIC_TIMER_INIT, 100_000);  // approximate — will be close to BSP

    // Create an idle thread for this AP so the scheduler can track it.
    // We use a special TID = 0x1000 + apic_id to avoid conflicts.
    let ap_idle_tid = 0x1000 + apic_id as u64;
    {
        use crate::proc::{Thread, ThreadState, CpuContext, THREAD_TABLE, PRIORITY_IDLE};
        let ap_thread = Thread {
            tid: ap_idle_tid,
            pid: 0, // Part of the idle process
            state: ThreadState::Running,
            context: alloc::boxed::Box::new(CpuContext {
                // Store the kernel CR3 so schedule() switches back to kernel
                // page tables when this idle thread is selected, rather than
                // leaving a stale (and potentially freed) user process CR3.
                cr3: crate::mm::vmm::get_cr3(),
                ..CpuContext::default()
            }),
            // kernel_stack_base = 0: AP idle thread is never reaped (is_reapable() returns
            // false for tid >= 0x1000), and setting a non-zero base would cause
            // set_kernel_rsp(ap_stack_top) when this thread is scheduled, corrupting
            // the SYSCALL kernel RSP for subsequent user threads on this CPU.
            kernel_stack_base: 0,
            kernel_stack_size: 0,
            wake_tick: 0,
            name: {
                let mut name = [0u8; 32];
                let prefix = b"ap_idle_";
                let digit = b'0' + apic_id;
                name[..prefix.len()].copy_from_slice(prefix);
                name[prefix.len()] = digit;
                name
            },
            exit_code: 0,
            fpu_state: None,
            user_entry_rip: 0,
            user_entry_rsp: 0,
            user_entry_rdx: 0,
            user_entry_r8: 0,
            priority: PRIORITY_IDLE,
            base_priority: PRIORITY_IDLE,
            tls_base: 0,
            // Pin each AP idle thread to its own CPU.  AP idle threads have
            // context.rsp = 0 (never been through init_thread_stack), so any
            // other CPU stealing them would load RSP=0 and triple-fault.
            cpu_affinity: Some(apic_id),
            last_cpu: 0,
            first_run: false,
            ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
            clear_child_tid: 0,
            fork_user_regs: crate::proc::ForkUserRegs::default(),
            vfork_parent_tid: None,
            gs_base: 0,
            robust_list_head: 0,
            robust_list_len: 0,
        };
        THREAD_TABLE.lock().push(ap_thread);
    }

    // Set this AP's current thread ID and matching PID for the lock-free
    // current_pid_lockless() path used by interrupt handlers.
    crate::proc::set_current_tid(ap_idle_tid);
    crate::proc::set_current_pid(0); // AP idle is on PID 0 (the idle process).

    // Mark ourselves as started
    AP_STARTED[apic_id as usize].store(true, Ordering::Release);

    crate::serial_println!(
        "[SMP] AP {} online, LAPIC enabled, idle TID={}, entering scheduler",
        apic_id,
        ap_idle_tid
    );

    // Set up syscall/sysret MSRs for this AP — these are per-CPU and must be
    // configured before any user thread runs on this CPU.  The BSP does this
    // in syscall::init() (Phase 6), but APs bypass that path.
    crate::syscall::init_ap();

    // Enable interrupts and enter scheduling loop.
    // After each timer interrupt wakes this AP from HLT, check if a reschedule
    // is needed and switch to any ready thread.  check_reschedule() is safe
    // here because the idle thread holds no locks.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }

    loop {
        // HLT until next timer interrupt.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
        // Reset watchdog: the AP idle thread is alive and responding to interrupts.
        // Without this, the watchdog fires on idle CPUs with no threads to schedule.
        crate::arch::x86_64::irq::reset_watchdog_counter();
        // Check for pending reschedule after being woken by the timer ISR.
        crate::sched::check_reschedule();
    }
}
