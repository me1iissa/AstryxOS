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

/// LVT Timer register mode field (bits 18:17), Intel SDM Vol. 3A §11.5.1 /
/// §11.5.4.1.  `00b` one-shot, `01b` periodic (bit 17), `10b` TSC-deadline
/// (bit 18).  We use periodic by default and TSC-deadline when the CPU
/// advertises it (CPUID.01H:ECX[24]) — KVM injects TSC-deadline reliably even
/// for the BSP vCPU, whereas its emulated *periodic* counter can wedge and not
/// resume (the SMP "de-facto single core" failure mode).
const LAPIC_LVT_TIMER_PERIODIC: u32     = 0x2_0000; // bit 17
const LAPIC_LVT_TIMER_TSC_DEADLINE: u32 = 0x4_0000; // bit 18

/// `IA32_TSC_DEADLINE` MSR (index 6E0H).  In TSC-deadline mode a write arms a
/// single interrupt at the absolute target TSC value; writing 0 disarms.
/// Intel SDM Vol. 3A §11.5.4.1.
const IA32_TSC_DEADLINE_MSR: u32 = 0x6E0;

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

/// AP online-report wait budget used by `start_aps()` after the second SIPI.
///
/// The loop polls the AP's self-published online flag every
/// `AP_ONLINE_WAIT_STEP_US` microseconds for up to `AP_ONLINE_WAIT_STEPS`
/// iterations, breaking the instant the flag appears.  The product
/// (`500 µs × 2000 = 1 s`) is the worst-case wait for a CPU that never
/// reports; a healthy AP exits the loop as soon as it has finished its
/// bringup.  This is generous versus the AP's typical sub-millisecond report
/// time under KVM, yet bounded so a genuinely-dead AP cannot stall boot.
const AP_ONLINE_WAIT_STEPS: u32 = 2000;
const AP_ONLINE_WAIT_STEP_US: u64 = 500;

/// LAPIC base address (MMIO).
static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// I/O APIC base address.
static IOAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// BSP (Boot Strap Processor) APIC ID.
static BSP_APIC_ID: AtomicU8 = AtomicU8::new(0);

/// Cached number of online CPUs, published by `recount_online_cpus()`.
///
/// This is a *cache*, not the source of truth: the authoritative online
/// state is the per-CPU [`AP_STARTED`] flag that each AP sets for itself
/// once it has reached its scheduler idle loop (mirroring the way a CPU is
/// added to the online set by the CPU itself in a standard x86 SMP bringup,
/// rather than by the boot processor guessing from a fixed-length timeout).
///
/// Keeping a cache lets the hot `cpu_count()` reader avoid scanning the flag
/// array on every call; it is refreshed by the BSP after each AP reports and
/// can also be recomputed on demand.  It starts at 1 for the BSP, which is
/// online from the moment this code runs.
static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// Whether APIC is available and initialized.
static APIC_ENABLED: AtomicBool = AtomicBool::new(false);

/// LAPIC periodic timer initial-count value calibrated by the BSP.
///
/// Captured at the end of [`init`] after the PIT-driven calibration.  APs
/// then read this value when programming their own LAPIC timer in
/// `ap_rust_entry`, so every CPU's periodic timer fires at the same ~100 Hz
/// regardless of LAPIC bus frequency.
///
/// Before BSP calibration this reads as 0; APs MUST NOT consult it until the
/// BSP has stored a non-zero value.  The BSP brings up APs only after
/// completing its own LAPIC init, so this ordering is naturally established.
static LAPIC_TIMER_PERIOD: AtomicU32 = AtomicU32::new(0);

/// Whether the LAPIC timer runs in TSC-deadline mode (vs periodic).
///
/// Set once at BSP boot from CPUID.01H:ECX[bit 24] (Intel SDM Vol. 3A
/// §11.5.4.1).  When true, every CPU programs its LVT timer in TSC-deadline
/// mode and re-arms the absolute deadline from its own timer ISR each tick
/// (the mode is one-shot per write).  When false (e.g. the TCG baseline CPU
/// model, which does not advertise the feature) every CPU falls back to the
/// classic periodic count.  A single machine-wide decision keeps the BSP and
/// every AP in the same mode.
static TSC_DEADLINE_MODE: AtomicBool = AtomicBool::new(false);

/// LAPIC timer period expressed in TSC cycles, for TSC-deadline re-arming.
///
/// Derived at BSP calibration from the same PIT window that produces the
/// periodic initial-count (`tsc_per_10ms` ≈ one ~10 ms tick at TICK_HZ=100).
/// Read by the timer ISR (`rdtsc() + period` is the next deadline) and by APs
/// when arming their first deadline.  0 before calibration.
static LAPIC_TSC_DEADLINE_PERIOD: AtomicU64 = AtomicU64::new(0);

/// Cached "running under a hypervisor" flag, decided once at BSP init from
/// CPUID.01H:ECX[bit 31] (see [`hypervisor_present`]).  Cached in an AtomicBool
/// exactly like [`TSC_DEADLINE_MODE`] so the idle-halt decision path reads it
/// with no CPUID (a CPUID under some VMMs is an intercepted VM-exit).
static HYPERVISOR_PRESENT: AtomicBool = AtomicBool::new(false);

/// Read CPUID.01H:ECX once.  Two conventional feature bits live in this leaf:
/// bit 24 = TSC-deadline timer (Intel SDM Vol. 3A §11.5.4.1); bit 31 =
/// "hypervisor present" — reserved-0 on physical CPUs, set by mainstream VMMs
/// (Intel SDM Vol. 2A CPUID, AMD APM Vol. 3).  A single CPUID feeds both
/// probes so the (potentially intercepted) instruction runs once at init.
fn cpuid_01h_ecx() -> u32 {
    let ecx: u32;
    // RBX is reserved by the compiler (PIC base); save/restore around CPUID.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") _,
            options(nostack),
        );
    }
    ecx
}

/// True iff the CPU advertises TSC-deadline timer support
/// (CPUID.01H:ECX[bit 24]).  Intel SDM Vol. 3A §11.5.4.1.
fn cpuid_has_tsc_deadline() -> bool {
    (cpuid_01h_ecx() & (1 << 24)) != 0
}

/// True iff CPUID.01H:ECX[bit 31] — the conventional "hypervisor present" flag
/// — is set.  Reserved-0 on physical CPUs; set by mainstream VMMs (KVM,
/// Hyper-V, VMware, Xen).  Intel SDM Vol. 2A (CPUID), AMD APM Vol. 3.  Because
/// it is a convention (not architecturally guaranteed, and can be hidden under
/// nested virtualisation), callers that must be robust OR it with a build-time
/// signal — see `irq::force_spin_uni`.
fn cpuid_hypervisor_present() -> bool {
    (cpuid_01h_ecx() & (1u32 << 31)) != 0
}

/// Cached "running under a hypervisor" flag (CPUID.01H:ECX[31]), decided once
/// at BSP init.  Read on the idle-halt decision path with no CPUID.
pub fn hypervisor_present() -> bool {
    HYPERVISOR_PRESENT.load(Ordering::Acquire)
}

/// Whether the LAPIC timer is in TSC-deadline mode for this boot.
pub fn tsc_deadline_mode() -> bool {
    TSC_DEADLINE_MODE.load(Ordering::Acquire)
}

/// Per-CPU online flag — the authoritative SMP online state.
///
/// `AP_STARTED[i]` is set to `true` by application processor `i` **itself**,
/// from `ap_rust_entry()`, once it has enabled its local APIC, installed its
/// per-CPU TSS/syscall MSRs, created its idle thread, and is about to enter
/// the scheduler.  A CPU therefore counts as online exactly when it has
/// published this flag, so the user-visible CPU count never races a fixed
/// boot-time delay: a healthy AP that reports late is still counted.  The BSP
/// (`AP_STARTED[BSP_APIC_ID]`) does not set this flag — it is unconditionally
/// online and accounted for separately in [`recount_online_cpus()`].
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

    // Calibrate using PIT: count LAPIC ticks AND TSC cycles in ~10 ms.
    let (calibration_ticks, tsc_per_10ms) = calibrate_lapic_timer();
    crate::arch::x86_64::irq::set_tsc_calibration(tsc_per_10ms);

    // Decide the timer mode once for the whole machine.  TSC-deadline
    // (CPUID.01H:ECX[24]) is preferred: KVM injects it reliably for every
    // vCPU including the BSP, whereas its emulated periodic counter can wedge
    // post-bringup and never resume (Intel SDM Vol. 3A §11.5.4 — a wedged
    // periodic counter does not spontaneously restart), the SMP "de-facto
    // single core" failure mode that the irq.rs self-heal otherwise has to
    // limp around.  A CPU model that does not advertise the feature (e.g. the
    // TCG baseline) falls back to periodic.
    let use_deadline = cpuid_has_tsc_deadline();
    TSC_DEADLINE_MODE.store(use_deadline, Ordering::Release);

    // Cache the "hypervisor present" flag once, on the BSP, next to the timer-
    // mode decision (both are CPUID.01H:ECX bits).  The idle-halt decision path
    // (`irq::force_spin_uni`) reads this cached value with no CPUID, so a
    // single-vCPU VM refuses the bare `hlt` at idle and self-clocks on the TSC.
    HYPERVISOR_PRESENT.store(cpuid_hypervisor_present(), Ordering::Release);

    // Publish the calibrated period for APs to copy (see `ap_rust_entry`).
    // Both representations are published: the periodic initial-count and the
    // per-tick TSC-cycle delta used to compute TSC-deadline targets.
    let timer_count = calibration_ticks;
    LAPIC_TIMER_PERIOD.store(timer_count, Ordering::Release);
    LAPIC_TSC_DEADLINE_PERIOD.store(tsc_per_10ms, Ordering::Release);

    // Program this CPU's LAPIC timer in the chosen mode and arm it.
    arm_lapic_timer();

    crate::serial_println!(
        "[APIC] Local APIC initialized: BSP ID={}, base={:#x}, timer count={}, mode={}",
        bsp_id,
        base_phys,
        timer_count,
        if use_deadline { "tsc-deadline" } else { "periodic" }
    );

    // Try to initialize I/O APIC
    init_ioapic();

    APIC_ENABLED.store(true, Ordering::Relaxed);
    crate::serial_println!("[APIC] APIC subsystem fully initialized");
}

/// Calibrate LAPIC timer using the PIT.
///
/// Returns `(lapic_ticks_per_10ms, tsc_cycles_per_10ms)`.  The TSC
/// measurement is the source of truth for `TICK_COUNT` updates (see
/// `arch::x86_64::irq::timer_tick`); the LAPIC count drives periodic
/// preemption.
fn calibrate_lapic_timer() -> (u32, u64) {
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

    // Sample TSC at the start of the 10 ms window so we can compute the
    // TSC-per-tick ratio against the same PIT-measured baseline.
    let tsc_start: u64 = {
        let lo: u32; let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
                             options(nomem, nostack, preserves_flags));
        }
        ((hi as u64) << 32) | lo as u64
    };

    // Wait for PIT channel 2 to expire
    unsafe {
        // Gate on
        let val = crate::hal::inb(0x61) & 0xFE;
        crate::hal::outb(0x61, val);
        crate::hal::outb(0x61, val | 1);

        // Wait for output bit (bit 5 of port 0x61)
        while crate::hal::inb(0x61) & 0x20 == 0 {}
    }

    // Sample TSC at the end of the window and compute the delta.
    let tsc_end: u64 = {
        let lo: u32; let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
                             options(nomem, nostack, preserves_flags));
        }
        ((hi as u64) << 32) | lo as u64
    };

    // Read how many ticks elapsed
    let elapsed = 0xFFFF_FFFF - lapic_read(LAPIC_TIMER_CURRENT);

    // Stop the timer temporarily
    lapic_write(LAPIC_TIMER_INIT, 0);

    let tsc_per_10ms = tsc_end.wrapping_sub(tsc_start);

    let lapic_count = if elapsed == 0 {
        // Fallback value if calibration failed
        100_000
    } else {
        elapsed
    };
    (lapic_count, tsc_per_10ms)
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

/// Read back a (lo, hi) IO-APIC redirect entry for diagnostics.  Used by
/// driver `arm_irq()` paths to confirm that the route they programmed
/// actually landed (shared-IRQ debugging is otherwise blind).
pub fn ioapic_read_entry(irq: u8) -> (u32, u32) {
    let redtbl_offset = IOAPIC_REDTBL + irq * 2;
    let lo = ioapic_read(redtbl_offset);
    let hi = ioapic_read(redtbl_offset + 1);
    (lo, hi)
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

/// Re-arm the calling CPU's LAPIC periodic timer.
///
/// Rewrites the timer LVT (periodic | vector 32) and the initial-count
/// register with the calibrated period. This is the standard recovery for a
/// LAPIC periodic timer that has stopped delivering interrupts: under KVM a
/// single vCPU subjected to a sustained framebuffer-MMIO VM-exit storm can
/// have its LAPIC timer-interrupt delivery suppressed and **not** spontaneously
/// resume once the storm ends (the periodic counter wedges). On a multi-core
/// machine a sibling CPU keeps the global clock alive so this is invisible; on
/// a single core there is no sibling, so the BSP idle path calls this to keep
/// the timer — and therefore the scheduler tick and `TICK_COUNT` — alive.
///
/// Re-programs the timer with the FULL from-scratch sequence rather than just
/// rewriting the initial count: the divide-configuration register, then a fresh
/// (masked → unmasked) LVT, then the initial count. This mirrors the boot-time
/// `init_timer` path exactly. A minimal re-arm that rewrites only the LVT and
/// initial-count register was observed NOT to resume injection on a wedged KVM
/// LAPIC (the timer-ISR counter stayed frozen): per Intel SDM Vol. 3A §11.5.1
/// the down-counter is derived through the divide-configuration register, and a
/// counter wedged with a stale/indeterminate divisor latch does not re-latch on
/// a bare initial-count write. The order is mandated by §11.5.4 — the LVT mode
/// and divide configuration must be established *before* the initial-count write
/// that (re)starts the count. The mask→unmask of LVT bit 16 forces the hardware
/// to re-evaluate the timer LVT from a known-masked state so the subsequent
/// initial-count write re-latches cleanly.
///
/// Safe to call from any context: it touches only this CPU's LAPIC MMIO and the
/// values written are the immutable boot-time calibration. No-op before
/// calibration (period == 0) or if the APIC is disabled.
pub fn rearm_timer() {
    if !is_enabled() {
        return;
    }
    rearm_timer_inner();
}

/// Mode-aware LAPIC-timer re-arm body, callable before `APIC_ENABLED` is
/// published (the boot `init` path arms the timer before flipping the flag).
fn rearm_timer_inner() {
    if tsc_deadline_mode() {
        // TSC-deadline: re-establish the LVT mode (10b) and arm a fresh
        // absolute deadline.  The mode is one-shot per write, so a wedged
        // counter (the periodic failure mode this whole path exists for)
        // cannot occur — but re-asserting the LVT is cheap and keeps the
        // recovery semantics identical for both modes.
        lapic_write(LAPIC_TIMER_LVT, LAPIC_LVT_TIMER_TSC_DEADLINE | 32);
        arm_tsc_deadline_next();
        return;
    }
    let period = LAPIC_TIMER_PERIOD.load(Ordering::Acquire);
    if period == 0 {
        return;
    }
    // Stop the counter and mask the timer LVT first, so the re-program starts
    // from a known-quiescent state (Intel SDM Vol. 3A §11.5.4: an initial-count
    // write of 0 stops the timer).
    lapic_write(LAPIC_TIMER_INIT, 0);
    lapic_write(LAPIC_TIMER_LVT, 0x10000 | 32); // masked (bit 16) | vector 32
    // Re-establish the divide configuration (divide by 16) — the step a bare
    // LVT+init re-arm omitted (§11.5.1: the count is clocked through this
    // register; a stale divisor latch prevents a wedged counter from resuming).
    lapic_write(LAPIC_TIMER_DIVIDE, 0x03);
    // Fresh periodic, unmasked LVT, then start the counter with the calibrated
    // period — order per §11.5.4 (mode/divide before the count that starts it).
    lapic_write(LAPIC_TIMER_LVT, LAPIC_LVT_TIMER_PERIODIC | 32); // periodic | vec 32
    lapic_write(LAPIC_TIMER_INIT, period);
}

/// Program the calling CPU's LAPIC timer in the machine-wide chosen mode and
/// arm the first interrupt.  Used by the BSP `init` path and by each AP at
/// bringup so all CPUs run the same mode.
///
/// Periodic: divide-by-16, LVT periodic | vector 32, calibrated initial-count.
/// TSC-deadline: LVT TSC-deadline (bits 18:17 = 10b) | vector 32, then a first
/// deadline of `rdtsc() + period` cycles (Intel SDM Vol. 3A §11.5.4.1).  The
/// divide-configuration register is irrelevant in TSC-deadline mode (the timer
/// is clocked off the TSC, not the LAPIC bus divisor).
pub fn arm_lapic_timer() {
    if tsc_deadline_mode() {
        // Establish TSC-deadline mode before the first deadline write — the
        // LVT mode field must be 10b for the IA32_TSC_DEADLINE write to take
        // effect (§11.5.4.1: in other modes a write to the MSR is ignored).
        lapic_write(LAPIC_TIMER_LVT, LAPIC_LVT_TIMER_TSC_DEADLINE | 32);
        arm_tsc_deadline_next();
    } else {
        let period = LAPIC_TIMER_PERIOD.load(Ordering::Acquire);
        lapic_write(LAPIC_TIMER_DIVIDE, 0x03); // divide by 16
        lapic_write(LAPIC_TIMER_LVT, LAPIC_LVT_TIMER_PERIODIC | 32);
        lapic_write(LAPIC_TIMER_INIT, period);
    }
}

/// Arm the next TSC-deadline (`rdtsc() + period` cycles) by writing the
/// IA32_TSC_DEADLINE MSR.  Called from the timer ISR every tick — TSC-deadline
/// is one-shot per write (Intel SDM Vol. 3A §11.5.4.1).
///
/// An `mfence` precedes the WRMSR because a write to IA32_TSC_DEADLINE is NOT
/// serializing (Intel SDM Vol. 3A §11.5.4.1 / the architectural-MSR note): the
/// fence orders the `rdtsc` that produced the deadline ahead of the MSR write
/// so the hardware never sees a stale/out-of-order base.  A target already in
/// the past simply fires immediately on the next vmentry (KVM) / instruction
/// boundary (HW), which self-corrects a missed tick rather than wedging.
#[inline]
pub fn arm_tsc_deadline_next() {
    let period = LAPIC_TSC_DEADLINE_PERIOD.load(Ordering::Acquire);
    if period == 0 {
        return; // pre-calibration
    }
    let deadline = next_tsc_deadline(crate::arch::x86_64::irq::rdtsc(), period);
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
        wrmsr(IA32_TSC_DEADLINE_MSR, deadline);
    }
}

/// Pure next-deadline computation, factored out of [`arm_tsc_deadline_next`] so
/// the cadence arithmetic can be unit-tested without writing the MSR.  The next
/// absolute TSC target is `now + period`, using wrapping addition so a TSC near
/// the 64-bit wrap still produces a deadline the LAPIC compares correctly (the
/// hardware comparison is modulo-2^64; Intel SDM Vol. 3A §11.5.4.1).
#[inline]
pub fn next_tsc_deadline(now: u64, period: u64) -> u64 {
    now.wrapping_add(period)
}

/// Check if APIC is enabled and active.
pub fn is_enabled() -> bool {
    APIC_ENABLED.load(Ordering::Relaxed)
}

/// Get the number of online CPUs (BSP + every AP that has reported online).
///
/// Reads the cached value published by [`recount_online_cpus()`].  The cache
/// is authoritative because the count is recomputed from the per-CPU
/// [`AP_STARTED`] online flags every time an AP reports during bringup, so a
/// CPU is reflected here precisely when it has published itself online — never
/// gated by a fixed boot-time timeout.  This is what feeds the user-visible
/// `/sys/devices/system/cpu/{online,present,possible}` files and the
/// `_SC_NPROCESSORS_ONLN` count, so it MUST equal the true number of CPUs
/// running the scheduler.
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Relaxed)
}

/// Recompute the online-CPU count from the authoritative [`AP_STARTED`]
/// online flags and republish it into the [`CPU_COUNT`] cache.
///
/// Online = the BSP (always online once `init()` has run) plus every AP that
/// has set its own `AP_STARTED` flag in `ap_rust_entry()`.  Returns the fresh
/// count.  Called by the BSP after each AP reports during `start_aps()`, and
/// usable on demand (e.g. from diagnostics) to reconcile the cache with the
/// real online set.  Cheap: a single pass over the fixed-size flag array.
pub fn recount_online_cpus() -> u32 {
    let bsp = BSP_APIC_ID.load(Ordering::Relaxed) as usize;
    // The BSP is online and never sets its own AP_STARTED flag.
    let mut n: u32 = 1;
    for (i, started) in AP_STARTED.iter().enumerate() {
        if i != bsp && started.load(Ordering::Acquire) {
            n += 1;
        }
    }
    CPU_COUNT.store(n, Ordering::Relaxed);
    n
}

/// Get the bootstrap-processor's APIC ID.  Used by drivers to target the
/// BSP for legacy PCI INTx routing through the IO-APIC.
pub fn bsp_apic_id() -> u8 {
    BSP_APIC_ID.load(Ordering::Relaxed)
}

/// Get the current CPU's logical index.
///
/// Reads `IA32_TSC_AUX` (initialised to the CPU's APIC ID by
/// `crate::syscall::set_per_cpu_id()` during CPU startup) via the **`RDTSCP`**
/// instruction.  Using `RDTSCP` rather than `RDMSR(IA32_TSC_AUX)` is critical
/// for KVM guests: `RDMSR` of `IA32_TSC_AUX` (`0xC000_0103`) unconditionally
/// triggers a VMEXIT to the host (≈46,000 cycles per call observed in the
/// AstryxOS microbench, versus ≈30 cycles for `RDTSCP`).  `RDTSCP` is one of
/// the architecturally non-trapping reads of `IA32_TSC_AUX` documented in
/// Intel SDM Vol 2B (Instruction Set Reference) and AMD APM Vol 3.
///
/// Going via an MSR-backed register (rather than an LAPIC MMIO read) also
/// avoids any page-table dependency, so this function works correctly even
/// after a user-process CR3 switch — the previous LAPIC MMIO path returned
/// 0 when the LAPIC identity mapping was not present in the active user
/// page table.
///
/// # Initialisation contract
/// `crate::syscall::set_per_cpu_id(apic_id)` MUST be called on every CPU
/// before any call to `cpu_index()` or `current_apic_id()`.  For the BSP
/// this happens inside `crate::syscall::init()`; for each AP it happens at
/// the very top of `ap_rust_entry()` using the LAPIC-read APIC ID.
///
/// # Migration
/// The returned index is a snapshot taken on the CPU that executed the
/// instruction.  If the scheduler migrates the calling thread between
/// the read and the use of the value, the index is stale.  Callers that
/// require an atomic CPU-bound read must disable preemption around the
/// call.  This contract is unchanged from the previous `RDMSR`-based
/// implementation.
#[inline(always)]
pub fn cpu_index() -> usize {
    let aux: u32;
    // SAFETY: RDTSCP is supported on all CPUs AstryxOS targets (KVM with
    // `-cpu host` exposes CPUID 0x80000001 EDX bit 27 — RDTSCP — on every
    // modern Intel/AMD host; the vDSO `__vdso_getcpu` uses the same
    // instruction unconditionally).  RDTSCP reads the TSC into EDX:EAX
    // and the IA32_TSC_AUX MSR into ECX; we discard the TSC outputs.
    // RDTSCP touches no memory, no stack, and leaves RFLAGS unchanged
    // (Intel SDM Vol 2B, RDTSCP — Read Time-Stamp Counter and Processor
    // ID), so `nomem, nostack, preserves_flags` are correct.
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("eax") _,            // tsc[31:0]   — discarded
            out("edx") _,            // tsc[63:32]  — discarded
            lateout("ecx") aux,      // ia32_tsc_aux
            options(nomem, nostack, preserves_flags),
        );
    }
    let id = aux as usize;
    if id >= MAX_CPUS { 0 } else { id }
}

/// Get the current CPU's logical APIC ID (u8).
///
/// Thin wrapper around `cpu_index()` for callers that want the APIC-ID
/// type.  See `cpu_index()` for the full implementation and contract.
#[inline(always)]
pub fn current_apic_id() -> u8 {
    cpu_index() as u8
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

/// Send an IPI without waiting for the delivery-status bit to clear
/// (fire-and-forget).
///
/// Used by the reschedule IPI (Perf P2 phase 3c): the sender only needs to
/// kick the target CPU into noticing a freshly-runnable thread, and the target
/// has already had its `NEED_RESCHEDULE` flag set before this call — so even if
/// the ICR's previous send is still draining, no correctness depends on this
/// particular write landing synchronously, and spinning on the delivery bit
/// from inside a wake path (sometimes with interrupts disabled) would only add
/// latency.  Per Intel SDM Vol. 3A §10.6.1 the write to ICR_LOW issues the IPI;
/// we set ICR_HIGH (destination) first, then ICR_LOW, and return immediately.
///
/// A short bounded wait for any *prior* in-flight IPI to drain precedes the
/// write so this send is not silently dropped by overwriting an ICR that has
/// not yet latched; the bound keeps it from becoming an unbounded spin if the
/// LAPIC is wedged.
pub fn send_ipi_noblock(dest_apic_id: u8, vector: u8) {
    if !is_enabled() {
        return;
    }
    // Bounded drain of any prior in-flight IPI (delivery-status bit 12).  Do
    // NOT spin unboundedly here — this runs on wake paths that may hold a lock
    // or have interrupts disabled.
    //
    // Cap-out behaviour: if the bound is reached while a *prior* IPI has not yet
    // latched (only possible when a timer preempts a blocking `send_ipi` mid-send
    // into a `schedule()`→reschedule-IPI on the same CPU), the unconditional ICR
    // write below would overwrite that pending IPI.  That degrades to: the
    // overwritten IPI is dropped → if it was a TLB shootdown, the sender's
    // ack-spin times out and falls onto the conservative deferred-flush
    // quarantine path (no UAF, no stale-translation correctness loss).  The
    // blocking `send_ipi` carries the identical cap-class on its own delivery
    // wait, so this introduces no new correctness hazard — the cap exists
    // precisely so a wedged LAPIC cannot turn a wake into an unbounded ring-0
    // spin with interrupts disabled.
    let mut spins = 0u32;
    while lapic_read(LAPIC_ICR_LO) & (1 << 12) != 0 {
        spins += 1;
        if spins > 10_000 {
            break;
        }
        core::hint::spin_loop();
    }
    lapic_write(LAPIC_ICR_HI, (dest_apic_id as u32) << 24);
    lapic_write(LAPIC_ICR_LO, vector as u32 | ICR_ASSERT);
    // Return immediately — no post-send delivery wait.
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
            let total = recount_online_cpus();
            crate::serial_println!(
                "[SMP] AP {} online (after SIPI #1), {} CPU(s) online", ap_id, total);
            consecutive_fails = 0;
            continue;
        }

        // Send SIPI #2 (the BSP issues a second Startup IPI if the AP has not
        // reported after the first, per the Intel SDM Vol. 3A multiple-
        // processor (MP) initialization protocol).
        lapic_write(LAPIC_ICR_HI, (ap_id as u32) << 24);
        lapic_write(LAPIC_ICR_LO, ICR_STARTUP | sipi_vector);
        for _ in 0..1000u32 {
            if lapic_read(LAPIC_ICR_LO) & (1 << 12) == 0 { break; }
        }

        // Wait for the AP to publish its online flag.
        //
        // The AP marks itself online (`AP_STARTED[ap_id]`) from
        // `ap_rust_entry()` only after a substantial init sequence: enabling
        // EFER.NXE/SSE/SMEP/SMAP, reading its LAPIC ID, programming its LAPIC
        // timer, allocating its idle thread (a heap allocation plus a
        // `THREAD_TABLE` lock that may be contended), and configuring its
        // per-CPU syscall MSRs.  Under KVM that work can take far longer than
        // a handful of milliseconds — and if the host briefly deschedules the
        // vCPU it is longer still.  The previous ~5 ms ceiling routinely
        // expired before a perfectly healthy AP reported, so the BSP declared
        // it absent and the online count under-reported (the AP was running
        // its scheduler idle loop the whole time).
        //
        // Use a generous bounded wait so a healthy AP is always observed.  The
        // poll is a fast relaxed-load loop that breaks the instant the flag
        // appears, so the common case costs only as long as the AP actually
        // needs; the ceiling only bounds the genuinely-absent case.  This
        // mirrors the standard SMP bringup contract where the boot CPU waits
        // for the AP's self-published "alive" state rather than guessing from
        // a fixed delay.
        for _ in 0..AP_ONLINE_WAIT_STEPS {
            delay_microseconds(AP_ONLINE_WAIT_STEP_US);
            if AP_STARTED[ap_id as usize].load(Ordering::Acquire) {
                break;
            }
        }

        if AP_STARTED[ap_id as usize].load(Ordering::Acquire) {
            let total = recount_online_cpus();
            crate::serial_println!(
                "[SMP] AP {} online (after SIPI #2), {} CPU(s) online", ap_id, total);
            consecutive_fails = 0;
        } else {
            crate::serial_println!(
                "[SMP] AP {} did not report online within {} ms — treating as absent",
                ap_id,
                (AP_ONLINE_WAIT_STEPS as u64 * AP_ONLINE_WAIT_STEP_US) / 1000);
            consecutive_fails += 1;
        }
    }

    // Final reconciliation: publish the count from the authoritative online
    // flags so that even an AP that set its flag between our last poll and
    // here is reflected.
    let total = recount_online_cpus();
    crate::serial_println!(
        "[SMP] AP bootstrap complete: {} CPU(s) online (BSP={})",
        total,
        bsp_id
    );

    // SMP is now live — enable the full cross-CPU TLB shootdown protocol.
    // Until this point only the BSP exists, so local invlpg was sufficient.
    if total > 1 {
        crate::mm::tlb::mark_smp_active();
    }
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
    // Enable CR4.SMEP and CR4.SMAP on this AP.  Each CPU has its own CR4,
    // so the BSP's setting does not propagate.  Per Intel SDM Vol. 3A
    // §2.5 (CR4 fields) and §4.6 (SMAP semantics).
    crate::arch::x86_64::enable_cpu_security_features();

    // Enable local APIC
    let apic_base_msr = unsafe { rdmsr(IA32_APIC_BASE_MSR) };
    unsafe {
        wrmsr(IA32_APIC_BASE_MSR, apic_base_msr | (1 << 11));
    }

    // Initialise this AP's per-CPU ID FIRST — before any call to cpu_index()
    // or current_apic_id().  set_per_cpu_id writes apic_id to IA32_TSC_AUX so
    // that cpu_index() (via RDTSCP) returns the correct per-CPU value.
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

    // Configure LAPIC timer in the same machine-wide mode the BSP chose
    // (TSC-deadline when available, else periodic) and arm the first
    // interrupt.  Using the BSP-published calibration keeps every CPU's
    // preemption granularity identical; `arm_lapic_timer` falls back to a
    // conservative periodic count if the BSP calibration has not yet been
    // published (it always has by the time an AP runs, but the guard keeps a
    // timer firing rather than leaving the AP without any preemption).
    if LAPIC_TIMER_PERIOD.load(Ordering::Acquire) == 0 && !tsc_deadline_mode() {
        lapic_write(LAPIC_TIMER_DIVIDE, 0x03);
        lapic_write(LAPIC_TIMER_LVT, LAPIC_LVT_TIMER_PERIODIC | 32);
        lapic_write(LAPIC_TIMER_INIT, 100_000);
    } else {
        arm_lapic_timer();
    }

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
            ready_since_tick: 0,
            mirror_slot: None,
            ctx_rsp_valid: alloc::boxed::Box::new(core::sync::atomic::AtomicBool::new(true)),
            clear_child_tid: 0,
            fork_user_regs: crate::proc::ForkUserRegs::default(),
            vfork_parent_tid: None,
            gs_base: 0,
            robust_list_head: 0,
            robust_list_len: 0,
            vfork_isolated_stack: None,
            vfork_isolated_tls: None,
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

    // Publish ourselves as a viable TLB-shootdown target BEFORE enabling
    // interrupts.  IDT, GDT, per-CPU TSC_AUX, idle-thread bookkeeping, and
    // the LAPIC are all live at this point, so handle_shootdown_ipi() on
    // vector 0xF0 can execute safely.  Doing this here, rather than waiting
    // for `start_aps` to return on the BSP, closes the per-AP window where
    // the BSP could shoot down an address space this AP had already loaded
    // but where SMP_ACTIVE was still false.  See mm/tlb.rs.
    crate::mm::tlb::mark_self_smp_online();

    // W215 Arm-1 diagnostic: if a CRC-walker mismatch already armed the
    // DR0 write-watchpoint before this AP came online, apply it now.
    // Per Intel SDM Vol. 3B §17.2.4, DR0–DR3 are per-CPU and must be
    // programmed on every CPU that should participate in the trap.  Also
    // required by `582-diag` so an AP that comes online after the #582
    // RFLAGS-slot watch is armed picks up DR0.
    #[cfg(any(feature = "w215-diag", feature = "582-diag"))]
    crate::arch::x86_64::debug_reg::apply_pending_to_this_cpu();

    // Enter the scheduling loop.  Each iteration waits one quantum, then checks
    // for a pending reschedule and switches to any ready thread.
    // check_reschedule() is safe here because the idle thread holds no locks.
    loop {
        // Wait one quantum.  `sched_wait_quantum` halts (`sti; hlt; cli`) while
        // this AP's LAPIC timer is delivering, but if this AP's own periodic
        // timer wedges (KVM injection suppression) it re-arms the local LAPIC
        // and spins (`sti; pause; cli`) instead — so an idle AP whose timer dies
        // re-arms ITSELF rather than depending solely on a sibling's cross-CPU
        // poke to limp it along (Intel SDM Vol. 3A §11.5.4).  This keeps the
        // dead-timer self-heal symmetric between the BSP reactor and idle APs.
        crate::arch::x86_64::irq::sched_wait_quantum();
        // Reset watchdog: the AP idle thread is alive and responding to interrupts.
        // Without this, the watchdog fires on idle CPUs with no threads to schedule.
        crate::arch::x86_64::irq::reset_watchdog_counter();
        // Check for pending reschedule after waking.
        crate::sched::check_reschedule();
    }
}
