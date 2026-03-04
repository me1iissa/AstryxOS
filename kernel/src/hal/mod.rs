//! Hardware Abstraction Layer (HAL)
//!
//! Provides hardware-agnostic interfaces inspired by the Windows NT HAL.
//! Currently supports x86_64 only but structured for future portability.

/// Initialize the HAL.
pub fn init() {
    // Disable interrupts during early init
    // SAFETY: We need interrupts off while setting up IDT/GDT.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

/// Halt the CPU until the next interrupt.
#[inline]
pub fn halt() {
    // SAFETY: HLT is always safe, just pauses until next interrupt.
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

/// Disable interrupts.
#[inline]
pub fn disable_interrupts() {
    // SAFETY: CLI disables interrupts. This is a standard kernel operation.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

/// Enable interrupts.
#[inline]
pub fn enable_interrupts() {
    // SAFETY: STI enables interrupts. Called after IDT is set up.
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

/// Read from an I/O port.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Caller guarantees port is valid.
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Write to an I/O port.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller guarantees port and value are valid.
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Read a 16-bit value from an I/O port.
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    core::arch::asm!(
        "in ax, dx",
        out("ax") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Write a 16-bit value to an I/O port.
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    core::arch::asm!(
        "out dx, ax",
        in("dx") port,
        in("ax") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Read a 32-bit value from an I/O port.
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Write a 32-bit value to an I/O port.
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Read a Model Specific Register.
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    core::arch::asm!(
        "rdmsr",
        out("eax") low,
        out("edx") high,
        in("ecx") msr,
        options(nomem, nostack, preserves_flags)
    );
    (high as u64) << 32 | low as u64
}

/// Write a Model Specific Register.
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}
