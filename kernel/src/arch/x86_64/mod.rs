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
    crate::serial_println!("[x86_64] Architecture initialized (GDT, IDT, IRQ)");
}
