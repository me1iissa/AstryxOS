//! Global Descriptor Table (GDT) for x86_64.
//!
//! Sets up the GDT with kernel code/data segments and a TSS for
//! interrupt stack switching and user mode transitions.
//!
//! # SMP Note
//! Each CPU must have its **own** TSS so that `TSS.rsp[0]` (the kernel stack
//! pointer used on Ring 3 → Ring 0 privilege transitions) is not clobbered by
//! another CPU scheduling a different thread.  We embed two TSS descriptors in
//! the *shared* GDT:
//!   - 0x28 — BSP TSS  (loaded by BSP at startup)
//!   - 0x38 — AP  TSS  (loaded by each AP in `ap_rust_entry`)
//!
//! `update_tss_rsp0` reads the current APIC ID and writes to the matching TSS.

use core::arch::asm;
use core::mem::size_of;
use spin::Once;

/// GDT entry (8 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
}

/// TSS entry in GDT (16 bytes — two GDT slots).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TssDescriptor {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
    base_upper: u32,
    _reserved: u32,
}

/// Task State Segment (TSS) for x86_64.
#[repr(C, packed)]
pub struct Tss {
    _reserved0: u32,
    /// Stack pointers for privilege level transitions (RSP0-RSP2).
    pub rsp: [u64; 3],
    _reserved1: u64,
    /// Interrupt Stack Table (IST1-IST7).
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// I/O Map Base Address.
    pub iomap_base: u16,
}

/// GDT with kernel/user segments + two TSS descriptors (one per CPU).
///
/// Segment order is specifically arranged for SYSRET compatibility:
/// - 0x00: Null
/// - 0x08: Kernel Code (Ring 0)
/// - 0x10: Kernel Data (Ring 0)
/// - 0x18: User Data (Ring 3)  <-- SYSRET SS = STAR[63:48]+8
/// - 0x20: User Code (Ring 3)  <-- SYSRET CS = STAR[63:48]+16
/// - 0x28: BSP TSS (16 bytes, spans 0x28-0x37)
/// - 0x38: AP  TSS (16 bytes, spans 0x38-0x47)
#[repr(C, align(16))]
struct Gdt {
    null: GdtEntry,           // 0x00: Null descriptor
    kernel_code: GdtEntry,    // 0x08: Kernel code (Ring 0, 64-bit)
    kernel_data: GdtEntry,    // 0x10: Kernel data (Ring 0)
    user_data: GdtEntry,      // 0x18: User data (Ring 3)
    user_code: GdtEntry,      // 0x20: User code (Ring 3, 64-bit)
    tss_bsp: TssDescriptor,   // 0x28: BSP TSS (16 bytes, spans 0x28-0x37)
    tss_ap:  TssDescriptor,   // 0x38: AP  TSS (16 bytes, spans 0x38-0x47)
}

/// GDT pointer structure for LGDT instruction.
#[repr(C, packed)]
struct GdtPointer {
    limit: u16,
    base: u64,
}

/// Segment selectors.
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub const USER_DATA_SELECTOR: u16 = 0x18 | 3; // RPL 3  → 0x1B
pub const USER_CODE_SELECTOR: u16 = 0x20 | 3; // RPL 3  → 0x23
pub const TSS_SELECTOR:     u16 = 0x28;       // BSP TSS
pub const TSS_AP_SELECTOR:  u16 = 0x38;       // AP  TSS

/// BSP interrupt stack (16 KiB).
static mut INTERRUPT_STACK: [u8; 16384] = [0; 16384];
/// BSP double-fault stack (16 KiB).
static mut DOUBLE_FAULT_STACK: [u8; 16384] = [0; 16384];

/// AP interrupt stack (16 KiB) — used when an AP receives an interrupt
/// from Ring 3 *before* a thread-specific kernel stack is available.
static mut AP_INTERRUPT_STACK: [u8; 16384] = [0; 16384];
/// AP double-fault stack (16 KiB).
static mut AP_DOUBLE_FAULT_STACK: [u8; 16384] = [0; 16384];

/// BSP Task State Segment.
static mut TSS_BSP: Tss = Tss {
    _reserved0: 0,
    rsp: [0; 3],
    _reserved1: 0,
    ist: [0; 7],
    _reserved2: 0,
    _reserved3: 0,
    iomap_base: size_of::<Tss>() as u16,
};

/// AP Task State Segment (one is sufficient for our 2-CPU setup).
static mut TSS_AP: Tss = Tss {
    _reserved0: 0,
    rsp: [0; 3],
    _reserved1: 0,
    ist: [0; 7],
    _reserved2: 0,
    _reserved3: 0,
    iomap_base: size_of::<Tss>() as u16,
};

/// Helper to build a zeroed TssDescriptor (used for static initialisation
/// before the real addresses are known at runtime).
const ZERO_TSS_DESC: TssDescriptor = TssDescriptor {
    limit_low: 0, base_low: 0, base_mid: 0,
    access: 0, granularity: 0, base_high: 0,
    base_upper: 0, _reserved: 0,
};

static mut GDT_INSTANCE: Gdt = Gdt {
    null: GdtEntry {
        limit_low: 0, base_low: 0, base_mid: 0,
        access: 0, granularity: 0, base_high: 0,
    },
    kernel_code: GdtEntry {
        limit_low: 0xFFFF, base_low: 0, base_mid: 0,
        access: 0x9A, // Present, Ring 0, Code, Execute/Read
        granularity: 0xAF, // 64-bit, 4K granularity
        base_high: 0,
    },
    kernel_data: GdtEntry {
        limit_low: 0xFFFF, base_low: 0, base_mid: 0,
        access: 0x92, // Present, Ring 0, Data, Read/Write
        granularity: 0xCF,
        base_high: 0,
    },
    // 0x18: User Data — MUST come before User Code for SYSRET
    user_data: GdtEntry {
        limit_low: 0xFFFF, base_low: 0, base_mid: 0,
        access: 0xF2, // Present, Ring 3, Data, Read/Write
        granularity: 0xCF,
        base_high: 0,
    },
    // 0x20: User Code
    user_code: GdtEntry {
        limit_low: 0xFFFF, base_low: 0, base_mid: 0,
        access: 0xFA, // Present, Ring 3, Code, Execute/Read
        granularity: 0xAF,
        base_high: 0,
    },
    tss_bsp: ZERO_TSS_DESC, // filled in by init()
    tss_ap:  ZERO_TSS_DESC, // filled in by init_ap_tss()
};

static GDT_INIT: Once<()> = Once::new();

/// Build a TssDescriptor from a TSS pointer.
#[inline]
unsafe fn make_tss_descriptor(tss_ptr: *const Tss) -> TssDescriptor {
    let addr = tss_ptr as u64;
    let limit = (size_of::<Tss>() - 1) as u16;
    TssDescriptor {
        limit_low:   limit,
        base_low:    addr as u16,
        base_mid:    (addr >> 16) as u8,
        access:      0x89, // Present, DPL=0, 64-bit TSS Available
        granularity: ((limit >> 8) & 0x0F) as u8,
        base_high:   (addr >> 24) as u8,
        base_upper:  (addr >> 32) as u32,
        _reserved:   0,
    }
}

/// Initialize the GDT with kernel/user segments and the BSP TSS.
/// Also pre-populates the AP TSS descriptor so APs only need to call
/// `init_ap_tss()` and `ltr TSS_AP_SELECTOR`.
pub fn init() {
    GDT_INIT.call_once(|| {
        // SAFETY: Single-threaded kernel init path.
        unsafe {
            // ── BSP TSS stacks ────────────────────────────────────────
            TSS_BSP.rsp[0] = (&raw const INTERRUPT_STACK) as *const u8 as u64
                           + size_of::<[u8; 16384]>() as u64;
            TSS_BSP.ist[0] = (&raw const INTERRUPT_STACK) as *const u8 as u64
                           + size_of::<[u8; 16384]>() as u64;
            TSS_BSP.ist[1] = (&raw const DOUBLE_FAULT_STACK) as *const u8 as u64
                           + size_of::<[u8; 16384]>() as u64;

            // ── AP TSS stacks (populated now; AP loads TR later) ──────
            TSS_AP.rsp[0] = (&raw const AP_INTERRUPT_STACK) as *const u8 as u64
                          + size_of::<[u8; 16384]>() as u64;
            TSS_AP.ist[0] = (&raw const AP_INTERRUPT_STACK) as *const u8 as u64
                          + size_of::<[u8; 16384]>() as u64;
            TSS_AP.ist[1] = (&raw const AP_DOUBLE_FAULT_STACK) as *const u8 as u64
                          + size_of::<[u8; 16384]>() as u64;

            // ── Write TSS descriptors into the GDT ───────────────────
            GDT_INSTANCE.tss_bsp = make_tss_descriptor(&raw const TSS_BSP);
            GDT_INSTANCE.tss_ap  = make_tss_descriptor(&raw const TSS_AP);

            // ── Load GDT ──────────────────────────────────────────────
            let gdt_ptr = GdtPointer {
                limit: (size_of::<Gdt>() - 1) as u16,
                base:  &raw const GDT_INSTANCE as *const Gdt as u64,
            };
            asm!(
                "lgdt [{}]",
                in(reg) &gdt_ptr,
                options(readonly, nostack, preserves_flags)
            );

            // ── Reload CS via far return ──────────────────────────────
            asm!(
                "push {sel}",
                "lea {tmp}, [rip + 2f]",
                "push {tmp}",
                "retfq",
                "2:",
                sel = in(reg) KERNEL_CODE_SELECTOR as u64,
                tmp = lateout(reg) _,
                options(preserves_flags),
            );

            // ── Reload data segments ──────────────────────────────────
            asm!(
                "mov ds, {0:x}",
                "mov es, {0:x}",
                "mov fs, {0:x}",
                "mov gs, {0:x}",
                "mov ss, {0:x}",
                in(reg) KERNEL_DATA_SELECTOR as u64,
                options(nostack, preserves_flags)
            );

            // ── Load BSP TSS ──────────────────────────────────────────
            asm!(
                "ltr {0:x}",
                in(reg) TSS_SELECTOR as u64,
                options(nostack, preserves_flags)
            );
        }
    });

    crate::serial_println!("[GDT] Initialized: BSP TSS=0x28, AP TSS=0x38");
}

/// Called once per AP (from `ap_rust_entry`) to load the AP's own TR.
///
/// The AP TSS descriptor was already written into the shared GDT during
/// `init()`, so the AP only needs to execute `ltr TSS_AP_SELECTOR`.
///
/// # Safety
/// Must be called on the AP core, after the BSP GDT has been loaded.
pub unsafe fn init_ap_tss() {
    asm!(
        "ltr {0:x}",
        in(reg) TSS_AP_SELECTOR as u64,
        options(nostack, preserves_flags)
    );
    crate::serial_println!("[GDT] AP loaded TR=0x38 (AP TSS)");
}

/// Update the **current CPU's** TSS.rsp[0].
///
/// Each CPU has its own TSS (BSP → TSS_BSP, all APs → TSS_AP) so that
/// Ring 3 → Ring 0 interrupt stack switches are fully independent.
///
/// Must be called on every context switch to a user-mode thread.
///
/// # Safety
/// `stack_top` must be a valid, mapped kernel-stack address.
pub unsafe fn update_tss_rsp0(stack_top: u64) {
    let apic_id = super::apic::current_apic_id();
    if apic_id == 0 {
        TSS_BSP.rsp[0] = stack_top;
    } else {
        // All non-BSP CPUs share TSS_AP for now (sufficient for smp=2).
        TSS_AP.rsp[0] = stack_top;
    }
}
