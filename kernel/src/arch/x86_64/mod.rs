//! x86_64 architecture-specific code.

pub mod apic;
pub mod gdt;
pub mod idt;
pub mod irq;

/// Initialize all x86_64 architecture components.
pub fn init() {
    gdt::init();
    idt::init();
    irq::init();
    enable_sse();
    crate::serial_println!("[x86_64] Architecture initialized (GDT, IDT, IRQ, SSE)");
}

/// Enable SSE/SSE2 support on the current CPU.
///
/// This sets CR4.OSFXSR (bit 9) and CR4.OSXMMEXCPT (bit 10) so the OS
/// advertises FXSAVE/FXRSTOR support, and clears CR0.EM (bit 2) while
/// setting CR0.MP (bit 1) so SSE instructions execute without #UD.
pub fn enable_sse() {
    unsafe {
        let cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        // Set OSFXSR (bit 9) and OSXMMEXCPT (bit 10)
        let cr4 = cr4 | (1 << 9) | (1 << 10);
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack));

        let cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        // Clear EM (bit 2), set MP (bit 1)
        let cr0 = (cr0 & !(1u64 << 2)) | (1u64 << 1);
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack));
    }
}
