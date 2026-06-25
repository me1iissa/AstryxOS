//! x86_64 architecture-specific code.

pub mod apic;
// DR0 W-watchpoint plumbing for the W215 Arm-1 CRC walker (and the #582
// RFLAGS-slot probe).  Gated behind `w215-diag` (the walker) or `582-diag`
// (the #582 probe) since both consume the shared DR0–DR3 facility.
#[cfg(any(feature = "w215-diag", feature = "582-diag"))]
pub mod debug_reg;
// #582 torn-saved-RFLAGS-slot writer classifier.  Fire path for the DR0
// data-write watch the scheduler arms on switch victims.  Gated behind
// `582-diag` (which pulls in the `w215-diag` DR plumbing).
#[cfg(feature = "582-diag")]
pub mod db582;
pub mod gdt;
pub mod idt;
pub mod irq;
pub mod smap;
// CoW-private userspace execution breakpoints (debug-only).  Gated behind
// `kdb` since the only consumer is the KDB `ubreak` op surface.
#[cfg(feature = "kdb")]
pub mod ubreak;

/// Initialize all x86_64 architecture components.
pub fn init() {
    gdt::init();
    idt::init();
    irq::init();
    enable_sse();
    enable_cpu_security_features();
    crate::serial_println!("[x86_64] Architecture initialized (GDT, IDT, IRQ, SSE, SMEP, SMAP)");
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
/// Also enables CR4.SMAP (bit 21) when CPUID.(EAX=07H,ECX=00H):EBX[bit
/// 20] advertises support and after the STAC/CLAC bracketing in the
/// syscall layer has been audited (see `arch::x86_64::smap` module).
/// With SMAP set, the CPU raises #PF on any supervisor-mode access to
/// a user-mapped page (PTE.U/S=1) unless EFLAGS.AC=1.  Per Intel SDM
/// Vol. 3A §4.6, this defeats the class of kernel bugs that
/// inadvertently dereference an attacker-controlled user pointer —
/// converting an arbitrary-write primitive into a fail-stop fault.
///
/// SMAP enablement publishes `smap::SMAP_ENABLED = true`; every
/// legitimate user-pointer access in the kernel goes through a
/// `UserGuard` (or `stac_if_smap`/`clac_if_smap`) which reads that
/// atomic and issues STAC/CLAC accordingly.  Tests / kernel paths that
/// drive a syscall handler with a kernel-VA buffer are unaffected:
/// SMAP only fires on user-mapped pages.
///
/// Also enables CR4.UMIP (bit 11) — User-Mode Instruction Prevention —
/// when CPUID.(EAX=07H,ECX=00H):ECX[bit 2] advertises support.  Per
/// Intel SDM Vol. 3A §2.5 and Vol. 2A entries for SGDT/SIDT/SLDT/STR/
/// SMSW, with UMIP=1 each of those five instructions raises #GP when
/// executed at CPL>0.  The instructions are otherwise unprivileged and
/// leak CPL-0 internal state to user mode:
///
///   - SGDT — linear address of the GDT (defeats kernel-base randomisation)
///   - SIDT — linear address of the IDT
///   - SLDT — selector of the current LDT
///   - STR  — selector of the current task register
///   - SMSW — image of the lower 16 bits of CR0 (PE/MP/EM/TS/ET/NE bits)
///
/// These leaks form the recon primitive in the SLDT-info-leak class
/// (CVE-2017-15281 / CVE-2017-0911 / Hertzbleed-style fingerprinting)
/// and are a prerequisite for any future ROP-into-kernel exploit that
/// depends on the IDT/GDT base.  Closing the leak at the CPU level is
/// strictly stronger than any software mitigation (the CPU enforces
/// the #GP unconditionally regardless of which path the user took to
/// reach the instruction).  CWE-200 (Exposure of Sensitive Information
/// to an Unauthorized Actor) / CWE-203 (Observable Discrepancy).
///
/// Called on the BSP from `init()` and on each AP from `apic::ap_main`.
///
/// Mitigates: CVE-2017-7308-class kernel-pointer-corruption exploits
/// (CWE-119 / CWE-269) by removing the user-mapped-page execution
/// primitive even when a kernel UAF or vtable confusion gives the
/// attacker control of an indirect-branch target.  SMAP additionally
/// closes the BadIRET / ret2usr-data class (CVE-2014-9322) by
/// converting unintentional user-pointer dereferences into faults.
/// UMIP closes the kernel-address-leak recon class that those exploits
/// depend on to locate their target gadgets.
pub fn enable_cpu_security_features() {
    let (smep_supported, smap_supported, umip_supported) = unsafe {
        let ebx: u32;
        let ecx: u32;
        // CPUID leaf 7, sub-leaf 0: structured extended feature flags.
        // EBX bit 7  = SMEP   (Intel SDM Vol. 2A §3.2)
        // EBX bit 20 = SMAP   (Intel SDM Vol. 2A §3.2)
        // ECX bit 2  = UMIP   (Intel SDM Vol. 2A §3.2 — leaf 7 ECX flags)
        // RBX is reserved as the PIC base — save/restore it manually.
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            ebx = out(reg) ebx,
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => ecx,
            out("edx") _,
        );
        (
            (ebx & (1 << 7))  != 0,
            (ebx & (1 << 20)) != 0,
            (ecx & (1 << 2))  != 0,
        )
    };

    if !smep_supported {
        crate::serial_println!("[x86_64] SMEP not advertised by CPU — skipping (insecure CPU)");
        return;
    }

    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        cr4 |= 1u64 << 20; // CR4.SMEP
        if smap_supported {
            cr4 |= 1u64 << 21; // CR4.SMAP
        }
        if umip_supported {
            cr4 |= 1u64 << 11; // CR4.UMIP
        }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack));
    }

    if smap_supported {
        // Publish AFTER CR4 has actually been written so any STAC issued
        // through a UserGuard cannot precede the SMAP-on transition.
        // `Relaxed` is sufficient: bracketing helpers do their own
        // dependent loads on the same atomic, and the publication
        // happens once per CPU, on that CPU, before any user pointer is
        // dereferenced — there is no cross-thread visibility ordering
        // to enforce (the atomic exists to gate runtime instruction
        // emission, not to synchronise data).
        smap::SMAP_ENABLED.store(true, core::sync::atomic::Ordering::Relaxed);
        crate::serial_println!("[x86_64] SMAP enabled (CR4.SMAP=1, EFLAGS.AC gated by STAC/CLAC)");
    } else {
        crate::serial_println!("[x86_64] SMAP not advertised by CPU — skipping");
    }
    if umip_supported {
        // Per Intel SDM Vol. 3A §2.5 (CR4.UMIP) and Vol. 2A entries for
        // SGDT/SIDT/SLDT/STR/SMSW, once CR4.UMIP=1 those five
        // instructions raise #GP from CPL>0.  The publication is for
        // diagnostic visibility only; nothing in the kernel branches on
        // a runtime UMIP_ENABLED flag — the CPU enforces it unconditionally.
        UMIP_ENABLED.store(true, core::sync::atomic::Ordering::Relaxed);
        crate::serial_println!("[x86_64] UMIP enabled (CR4.UMIP=1, SGDT/SIDT/SLDT/STR/SMSW #GP at CPL>0)");
    } else {
        crate::serial_println!("[x86_64] UMIP not advertised by CPU — skipping");
    }
}

/// Diagnostic indicator: set once CR4.UMIP has been written on at least
/// one CPU.  Not consulted by any hot path — the CPU enforces UMIP at
/// every instruction boundary regardless of this flag.  Exists so the
/// test runner and `kdb cpu-features` can confirm enablement.
pub static UMIP_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
