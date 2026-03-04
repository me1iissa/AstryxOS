//! ACPI Power Control
//!
//! Hardware-level shutdown and reboot for QEMU q35 machines.

/// ACPI shutdown (S5 state) for QEMU/q35.
///
/// QEMU supports shutdown via the ACPI PM1a control block.
/// On the q35 chipset the PM1a_CNT register is at I/O port 0x0604.
/// Writing SLP_TYPa=5 (bits 12:10) | SLP_EN (bit 13) triggers S5.
pub fn acpi_shutdown() {
    crate::serial_println!("[Po] ACPI shutdown: entering S5 state...");

    // QEMU q35: PM1a_CNT port = 0x0604, value 0x2000 triggers shutdown
    unsafe {
        crate::hal::outw(0x0604, 0x2000);
    }

    // Fallback: older QEMU / Bochs ACPI port
    unsafe {
        crate::hal::outw(0xB004, 0x2000);
    }

    // If ACPI did not power us off, halt forever
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

/// System reboot via multiple fallback methods.
pub fn system_reboot() {
    crate::serial_println!("[Po] System reboot initiating...");

    // Method 1: Keyboard controller reset (0xFE to port 0x64)
    unsafe {
        crate::hal::outb(0x64, 0xFE);
    }

    // Method 2: Triple fault — load a null IDT and trigger an exception
    unsafe {
        let null_idt: [u8; 10] = [0; 10];
        core::arch::asm!(
            "lidt [{}]",
            in(reg) &null_idt as *const _,
            options(nostack)
        );
        core::arch::asm!("int3", options(nostack));
    }

    // If we're still alive, just halt
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}
