//! x86_64 architecture-specific code.

pub mod apic;
// DR0 W-watchpoint plumbing for the W215 Arm-1 CRC walker.
// Gated behind `w215-diag` together with the walker itself.
#[cfg(feature = "w215-diag")]
pub mod debug_reg;
pub mod gdt;
pub mod idt;
pub mod irq;

/// Initialize all x86_64 architecture components.
pub fn init() {
    gdt::init();
    idt::init();
    irq::init();
    enable_sse();
    enable_cpu_security_features();
    crate::serial_println!("[x86_64] Architecture initialized (GDT, IDT, IRQ, SSE, SMEP)");
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

/// Enable hardware-enforced kernel/user separation features in CR4.
///
/// Currently enables CR4.SMEP (bit 20) — Supervisor Mode Execution
/// Prevention. With SMEP set, any attempt to fetch and execute an
/// instruction from a user-mapped page (PTE.U/S=1) while CPL<3 causes a
/// page fault. This neutralises the ret2usr class of kernel exploits
/// where a corrupted kernel function pointer is steered into ROP/JOP
/// gadgets staged in attacker-controlled user memory.
///
/// SMEP availability is reported via CPUID.(EAX=07H,ECX=00H):EBX[bit 7]
/// per Intel SDM Vol. 2A §3.2 (CPUID — CPU Identification) and Vol. 3A
/// §2.5 (Control Registers — CR4). Setting CR4.SMEP on a CPU that does
/// not advertise the feature raises #GP, so the bit is gated on the
/// CPUID probe.
///
/// SMAP (CR4 bit 21, CPUID 7:0 EBX[20]) is intentionally NOT enabled
/// here. Enabling SMAP requires every legitimate kernel access to user
/// memory to be bracketed by STAC/CLAC (EFLAGS.AC=1) per Intel SDM
/// Vol. 3A §4.6.1; the current `validate_user_ptr` family performs raw
/// dereferences without that bracketing, so enabling SMAP without first
/// refactoring those helpers would cause a #PF on every legitimate user
/// copy. SMAP enablement is deferred to a follow-up that introduces
/// `stac()`/`clac()` wrappers and audits every unsafe user pointer
/// dereference.
///
/// Called on the BSP from `init()` and on each AP from `apic::ap_main`.
///
/// Mitigates: CVE-2017-7308-class kernel-pointer-corruption exploits
/// (CWE-119 / CWE-269) by removing the user-mapped-page execution
/// primitive even when a kernel UAF or vtable confusion gives the
/// attacker control of an indirect-branch target.
pub fn enable_cpu_security_features() {
    let (smep_supported, _smap_supported) = unsafe {
        let ebx: u32;
        // CPUID leaf 7, sub-leaf 0: structured extended feature flags.
        // EBX bit 7 = SMEP, EBX bit 20 = SMAP (Intel SDM Vol. 2A §3.2).
        // RBX is reserved as the PIC base — save/restore it manually.
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            ebx = out(reg) ebx,
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => _,
            out("edx") _,
        );
        ((ebx & (1 << 7)) != 0, (ebx & (1 << 20)) != 0)
    };

    if !smep_supported {
        crate::serial_println!("[x86_64] SMEP not advertised by CPU — skipping (insecure CPU)");
        return;
    }

    unsafe {
        let cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        let cr4 = cr4 | (1u64 << 20); // CR4.SMEP
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack));
    }
}
