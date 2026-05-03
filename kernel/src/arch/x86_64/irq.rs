//! Interrupt Request (IRQ) handling for x86_64.
//!
//! Uses the legacy 8259 PIC (Programmable Interrupt Controller) remapped to
//! vectors 32-47. Future versions will support APIC/x2APIC.

use crate::hal;
use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use super::apic::MAX_CPUS;

// ── Watchdog counter (per-CPU) ──────────────────────────────────────────────
// Incremented every timer tick. Reset to 0 on successful context switch.
// If a CPU exceeds WATCHDOG_LIMIT ticks without a switch → bugcheck.

static WATCHDOG_COUNTER: [AtomicU32; MAX_CPUS] =
    [const { AtomicU32::new(0) }; MAX_CPUS];
/// 120 seconds at 100 Hz.  Must be generous enough for ATA PIO transfers
/// in nested virtualisation (WSL2/KVM) which can stall a CPU for 60-90s
/// while loading large shared libraries (e.g., Firefox's libxul.so = 194 MB).
/// The external Python watchdog (tools/qemu-watchdog.py) handles faster
/// hang detection via serial output monitoring.
///
/// Under the `firefox-test` feature the limit is raised to 10 minutes because
/// Firefox's NSS / PK11 / ICU / font-cache initialisation performs long
/// CPU-bound work with no syscalls or page faults, and the shorter production
/// limit would false-positive during that phase.
#[cfg(feature = "firefox-test")]
const WATCHDOG_LIMIT: u32 = 60_000;
#[cfg(not(feature = "firefox-test"))]
const WATCHDOG_LIMIT: u32 = 12_000;

/// Reset the watchdog counter for the current CPU.
/// Called by schedule() after a successful context switch.
#[inline]
pub fn reset_watchdog_counter() {
    let cpu = super::apic::cpu_index();
    WATCHDOG_COUNTER[cpu as usize].store(0, Ordering::Relaxed);
}

/// PIC I/O ports.
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// PIC initialization command words.
const ICW1_INIT: u8 = 0x11;
const ICW4_8086: u8 = 0x01;

/// IRQ vector offset (remapped from 0-15 to 32-47).
pub const IRQ_OFFSET: u8 = 32;

/// End-of-Interrupt command.
const PIC_EOI: u8 = 0x20;

/// Timer tick counter.
///
/// Advances at exactly `TICK_HZ` (≈100 Hz) regardless of how many CPUs
/// are online.  The value is *wall-clock-derived* from TSC, not the sum of
/// per-CPU LAPIC ISR entries — a buggy approach where N online CPUs each
/// independently bump `+= 1` would make the apparent monotonic clock
/// advance N× faster than wall time, which silently breaks every consumer
/// that schedules deadlines from CLOCK_MONOTONIC (the userspace vDSO fast
/// path among them).  See `timer_tick` for the TSC-monotone update logic.
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// TSC value at boot — captured by [`set_tsc_calibration`] right after the
/// PIT-driven LAPIC calibration completes.  Used as the "epoch" against
/// which `timer_tick` recomputes `TICK_COUNT` each interrupt.
pub(crate) static TSC_AT_BOOT: AtomicU64 = AtomicU64::new(0);

/// TSC cycles per tick (100 Hz → 10 ms).  Captured at boot from the same
/// PIT-driven calibration window used to size the LAPIC initial-count.
/// Zero before calibration; once non-zero it is treated as immutable.
pub(crate) static TSC_PER_TICK: AtomicU64 = AtomicU64::new(0);

/// Per-CPU count of timer-ISR entries.  Diagnostic-only; used by the
/// `clock_monotonic_rate` regression test (and by anyone debugging where
/// timer interrupts are landing).  Increments on every timer ISR entry
/// regardless of which CPU.
pub static TIMER_ISR_PER_CPU: [AtomicU64; super::apic::MAX_CPUS] =
    [const { AtomicU64::new(0) }; super::apic::MAX_CPUS];

/// Number of times TICK_COUNT was advanced (CAS won by some CPU).
/// Should be approximately equal to the wall-clock tick count, *not* to
/// the sum of per-CPU ISR entries.
pub static TICK_COUNT_BUMPS: AtomicU64 = AtomicU64::new(0);

/// Read the TSC.  Standard `rdtsc` — no fences (we only need ordering
/// against ourselves on the same CPU).
#[inline(always)]
fn rdtsc() -> u64 {
    let lo: u32; let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
                         options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// Tick rate.  Kept consistent with the LAPIC/PIT calibration target
/// (~100 Hz) and with the vDSO `tick_hz` field.
pub const TICK_HZ: u64 = 100;

/// Record the TSC frequency the BSP measured during LAPIC calibration so
/// `timer_tick` can derive a wall-locked `TICK_COUNT`.  Must be called
/// once on the BSP after `calibrate_lapic_timer` completes.
pub fn set_tsc_calibration(tsc_per_10ms: u64) {
    if tsc_per_10ms == 0 { return; }
    let _ = TSC_AT_BOOT.compare_exchange(
        0, rdtsc(), Ordering::AcqRel, Ordering::Relaxed);
    let _ = TSC_PER_TICK.compare_exchange(
        0, tsc_per_10ms, Ordering::AcqRel, Ordering::Relaxed);
}

/// Keyboard scancode buffer (simple ring buffer).
static mut KEYBOARD_BUFFER: [u8; 256] = [0; 256];
static KEYBOARD_WRITE: AtomicU64 = AtomicU64::new(0);
static KEYBOARD_READ: AtomicU64 = AtomicU64::new(0);

/// Initialize the 8259 PIC and remap IRQs to vectors 32-47.
pub fn init() {
    // SAFETY: Programming the 8259 PIC via I/O ports. Standard initialization.
    unsafe {
        // Save masks
        let _mask1 = hal::inb(PIC1_DATA);
        let _mask2 = hal::inb(PIC2_DATA);

        // Start initialization sequence (ICW1)
        hal::outb(PIC1_COMMAND, ICW1_INIT);
        io_wait();
        hal::outb(PIC2_COMMAND, ICW1_INIT);
        io_wait();

        // ICW2: Vector offset
        hal::outb(PIC1_DATA, IRQ_OFFSET);
        io_wait();
        hal::outb(PIC2_DATA, IRQ_OFFSET + 8);
        io_wait();

        // ICW3: Cascade configuration
        hal::outb(PIC1_DATA, 4); // PIC2 at IRQ2
        io_wait();
        hal::outb(PIC2_DATA, 2); // Cascade identity
        io_wait();

        // ICW4: 8086 mode
        hal::outb(PIC1_DATA, ICW4_8086);
        io_wait();
        hal::outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Mask all IRQs except IRQ0 (timer) and IRQ1 (keyboard)
        hal::outb(PIC1_DATA, 0b1111_1000); // Enable IRQ0, IRQ1, and IRQ2 (cascade)
        hal::outb(PIC2_DATA, 0b1110_1111); // Unmask IRQ12 (mouse) on PIC2

        // Set up PIT (Programmable Interval Timer) for ~100 Hz
        // Channel 0, Rate Generator, lo/hi byte
        let divisor: u16 = 11932; // 1193182 / 100 ≈ 11932
        hal::outb(0x43, 0x36); // Channel 0, lo/hi, rate generator
        hal::outb(0x40, (divisor & 0xFF) as u8);
        hal::outb(0x40, (divisor >> 8) as u8);
    }

    crate::serial_println!("[IRQ] PIC remapped to vectors 32-47, timer at ~100 Hz");
}

/// Send End-of-Interrupt to the PIC.
///
/// # Safety
/// Must be called at the end of every IRQ handler.
pub unsafe fn send_eoi(irq: u8) {
    if irq >= 8 {
        hal::outb(PIC2_COMMAND, PIC_EOI);
    }
    hal::outb(PIC1_COMMAND, PIC_EOI);
}

/// Small I/O delay.
fn io_wait() {
    // SAFETY: Writing to port 0x80 causes a small delay. Standard technique.
    unsafe {
        hal::outb(0x80, 0);
    }
}

/// Read a scancode from the keyboard buffer.
/// Returns None if the buffer is empty.
pub fn read_scancode() -> Option<u8> {
    let r = KEYBOARD_READ.load(Ordering::Relaxed);
    let w = KEYBOARD_WRITE.load(Ordering::Relaxed);
    if r == w {
        return None;
    }
    // SAFETY: We maintain read/write indices correctly for the ring buffer.
    let code = unsafe { KEYBOARD_BUFFER[(r % 256) as usize] };
    KEYBOARD_READ.store(r + 1, Ordering::Relaxed);
    Some(code)
}

/// Get the current tick count.
pub fn get_ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

// ============================================================
// Hardware IRQ handlers (called from IDT stubs)
// ============================================================

/// Generate a naked ISR stub that saves caller-saved registers, calls
/// `$handler`, then restores and `iretq`s.  All four hardware IRQ stubs
/// are identical in structure; this macro removes the duplication.
macro_rules! irq_stub {
    ($name:ident, $handler:ident) => {
        #[unsafe(naked)]
        pub extern "C" fn $name() {
            core::arch::naked_asm!(
                "push rax", "push rcx", "push rdx",
                "push rsi", "push rdi",
                "push r8",  "push r9",  "push r10", "push r11",
                "call {handler}",
                "pop r11",  "pop r10",  "pop r9",   "pop r8",
                "pop rdi",  "pop rsi",
                "pop rdx",  "pop rcx",  "pop rax",
                "iretq",
                handler = sym $handler,
            );
        }
    };
}

// Timer ISR with deferred preemption: saves ALL registers (caller + callee),
// calls timer_tick(), then checks if preemption is needed for Ring 3 threads.
// If so, calls schedule() which may context-switch. When the preempted thread
// is rescheduled later, schedule() returns here, we pop the saved regs, and
// IRETQ resumes the user code with correct state.
//
// This is safe because:
// - All 15 GPRs are saved on the interrupted thread's kernel stack
// - schedule()'s switch_context saves RSP; when rescheduled, RSP is restored
//   to point to our saved regs, and schedule() returns to us
// - FPU state is saved/restored by schedule() via fxsave/fxrstor
#[unsafe(naked)]
pub extern "C" fn irq_timer_handler() {
    core::arch::naked_asm!(
        // Save ALL registers (caller + callee saved)
        "push rax", "push rcx", "push rdx",
        "push rsi", "push rdi",
        "push r8",  "push r9",  "push r10", "push r11",
        "push rbx", "push rbp",
        "push r12", "push r13", "push r14", "push r15",
        // Call timer handler (tick count, scheduler bookkeeping, EOI)
        "call {timer_tick}",
        // Check if we should preempt: is the interrupted context Ring 3?
        // IRETQ frame CS is at RSP + 15*8 (15 pushed regs) + 8 (RIP) = RSP + 128
        "mov rax, [rsp + 128]",  // interrupted CS
        "test rax, 3",           // Ring 3?
        "jz 2f",                 // skip if kernel mode — never preempt kernel
        // Check NEED_RESCHEDULE for this CPU
        "call {check_resched}",
        "2:",
        // Restore all registers
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop rbp", "pop rbx",
        "pop r11",  "pop r10",  "pop r9",   "pop r8",
        "pop rdi",  "pop rsi",
        "pop rdx",  "pop rcx",  "pop rax",
        "iretq",
        timer_tick = sym timer_tick,
        check_resched = sym crate::sched::check_reschedule,
    );
}

irq_stub!(irq_keyboard_handler, keyboard_interrupt);

/// Timer interrupt logic.
extern "C" fn timer_tick() {
    // Bail immediately if a bugcheck is in progress — avoid lock contention.
    if crate::ke::bugcheck::is_bugcheck_active() {
        if super::apic::is_enabled() { super::apic::lapic_eoi(); }
        return;
    }

    // Each CPU's LAPIC delivers its own periodic timer interrupt at ~100 Hz.
    // The TICK_COUNT is the *single global* monotonic time-of-day source —
    // it must therefore advance at exactly one CPU's tick rate, NOT the sum
    // across CPUs.  Letting every CPU bump TICK_COUNT scales the apparent
    // wall-clock by the number of online CPUs, which silently breaks every
    // CLOCK_MONOTONIC consumer (including the userspace vDSO clock_gettime
    // fast path used by glibc / NSPR / Mozilla event loops).
    //
    // Rule:
    //   * BSP advances TICK_COUNT and the vvar page.
    //   * APs handle preemption / per-CPU scheduling locally and EOI, but
    //     do NOT touch the global tick counter or vvar.
    //
    // If the BSP is HLT-idle, KVM/the LAPIC will still deliver the BSP's
    // periodic timer to wake it (this is the standard x86 timer model:
    // the LAPIC timer is independent of the CPU's HLT state).
    let cpu = super::apic::cpu_index();
    let is_bsp = cpu == 0;
    if cpu < super::apic::MAX_CPUS {
        TIMER_ISR_PER_CPU[cpu].fetch_add(1, Ordering::Relaxed);
    }

    // Compute the wall-clock-correct TICK_COUNT from the TSC delta.  Any
    // CPU may run this — whoever wins the CAS publishes the new value.
    // This is independent of the ISR firing rate, so it is safe for every
    // online CPU to participate (KVM occasionally suppresses BSP timer
    // delivery; trusting BSP-only would freeze the clock in that case).
    //
    // Before calibration is published (very early boot, before LAPIC init),
    // fall back to a single-bump-per-ISR scheme just so timing-dependent
    // boot code doesn't see a frozen clock.
    let tsc_per_tick = TSC_PER_TICK.load(Ordering::Acquire);
    let new_tick: u64;
    if tsc_per_tick != 0 {
        let now_tsc = rdtsc();
        let tsc_at_boot = TSC_AT_BOOT.load(Ordering::Acquire);
        let elapsed = now_tsc.wrapping_sub(tsc_at_boot);
        new_tick = elapsed / tsc_per_tick;
    } else {
        // BSP only during pre-calibration to avoid CPU-count scaling.
        if !is_bsp {
            // No tick advance from APs before calibration — they will
            // catch up once the BSP publishes TSC_PER_TICK.
            // (Just EOI and return below — same as if the tick happened.)
            new_tick = TICK_COUNT.load(Ordering::Relaxed);
        } else {
            new_tick = TICK_COUNT.load(Ordering::Relaxed) + 1;
        }
    }

    // Monotone CAS: only publish if `new_tick` exceeds the current value.
    // The loop is bounded — if another CPU wins, its value is at least as
    // new and we can stop.
    let mut cur = TICK_COUNT.load(Ordering::Relaxed);
    let tick = loop {
        if new_tick <= cur {
            break cur; // someone else (or our previous ISR) is already ahead
        }
        match TICK_COUNT.compare_exchange_weak(
            cur, new_tick, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => {
                TICK_COUNT_BUMPS.fetch_add(1, Ordering::Relaxed);
                // Update vvar only when WE published the new value, so we
                // don't double-write between racing CPUs.
                crate::proc::vdso::vvar_tick(new_tick);
                break new_tick;
            }
            Err(observed) => {
                cur = observed;
                // Loop to recheck — the new value may already exceed ours.
            }
        }
    };
    crate::perf::record_interrupt(32); // IRQ0 = vector 32

    // ── Heartbeat: emit every 500 ticks (~5s at 100 Hz) ─────────────
    // Gives the external watchdog (tools/qemu-watchdog.py) a signal that
    // the timer ISR is still firing.  Zero cost in production builds.
    // Only the BSP emits — it is the authoritative tick source.
    #[cfg(any(feature = "test-mode", feature = "firefox-test"))]
    {
        if is_bsp && tick > 0 && tick % 500 == 0 {
            crate::serial_println!("[HB] tick={} cpu={} pf={} sc={}",
                tick, cpu,
                crate::arch::x86_64::idt::page_fault_count(),
                crate::syscall::syscall_count());
        }
    }

    // ── Watchdog counter ─────────────────────────────────────────────
    // Incremented every tick.  Reset to 0 by reset_watchdog_counter()
    // called from schedule() on successful context switch.  If it reaches
    // the limit, a CPU has been stuck for >10s → bugcheck.
    // Per-CPU counter advances on each CPU's own LAPIC firing — independent
    // of whether this CPU updates the global TICK_COUNT.
    {
        // Only check when the scheduler is active — before it's enabled,
        // all kernel init runs on CPU 0 without context switches.
        if crate::sched::is_active() {
            // Don't watchdog idle threads — they legitimately wait in hlt
            // without calling schedule() when no user threads are assigned.
            let current_tid = crate::proc::current_tid();
            // Lockless PID read: timer ISR runs with IF=0 in interrupt
            // context.  Acquiring THREAD_TABLE here could deadlock the same
            // CPU if a syscall mid-flight on this CPU already holds it.
            let is_idle = current_tid == 0 || {
                // AP idle threads have PID 0
                crate::proc::current_pid_lockless() == 0
            };
            if is_idle {
                WATCHDOG_COUNTER[cpu as usize].store(0, Ordering::Relaxed);
            } else {
                let wd = WATCHDOG_COUNTER[cpu as usize].fetch_add(1, Ordering::Relaxed);
                if wd >= WATCHDOG_LIMIT {
                    crate::ke::bugcheck::ke_bugcheck(
                        crate::ke::bugcheck::BUGCHECK_SCHEDULER_DEADLOCK,
                        cpu as u64,
                        wd as u64,
                        tick as u64,
                        0,
                    );
                }
            }
        }
    }

    // Notify the scheduler about the tick.
    crate::sched::timer_tick_schedule();

    // Send EOI: use APIC if enabled, otherwise fall back to PIC.
    if super::apic::is_enabled() {
        super::apic::lapic_eoi();
    } else {
        // SAFETY: Sending EOI after handling the timer interrupt.
        unsafe {
            send_eoi(0);
        }
    }

    // NOTE: check_reschedule() is intentionally NOT called here.
    //
    // Calling schedule() from ISR context causes a deadlock: syscall handlers
    // acquire THREAD_TABLE with interrupts enabled (after STI in syscall_entry).
    // If a timer fires while THREAD_TABLE is held, check_reschedule() → schedule()
    // → THREAD_TABLE.lock() spins forever on the same CPU (self-deadlock).
    //
    // Preemption is handled instead at two safe points:
    //   1. End of syscall dispatch() — after all locks are released (BSP path).
    //   2. AP idle loop — after each HLT wakeup (AP path, in apic.rs).
}

irq_stub!(irq_mouse_handler, mouse_interrupt);
irq_stub!(irq_e1000_handler, e1000_interrupt);
irq_stub!(irq_virtio_blk_handler, virtio_blk_interrupt);

/// Virtio-blk PCI INTx interrupt logic.
///
/// Per virtio 1.0 §4.1.4.5 we ack the device by reading its ISR status
/// register (read-to-clear), walk the used ring for completions, and
/// wake the blocked submitter.  All of that is in the driver — this stub
/// only routes to it.
extern "C" fn virtio_blk_interrupt() {
    crate::perf::record_interrupt(crate::drivers::virtio_blk::VIRTIO_BLK_IRQ_VECTOR);
    crate::drivers::virtio_blk::handle_irq();
    // EOI is sent by handle_irq itself (LAPIC) — keep this stub narrow so
    // the ack-then-EOI ordering matches the rest of the device's spec
    // contract (read ISR before EOI for level-triggered PCI INTx).
}

/// E1000 NIC interrupt logic.
/// We run with IMS=0 (polling), so this should rarely fire.
/// Just acknowledge the interrupt source and send EOI.
extern "C" fn e1000_interrupt() {
    // Read ICR to clear the interrupt source (must precede EOI for
    // level-triggered PCI interrupts to avoid re-assertion).
    let _icr = crate::net::e1000::acknowledge_irq();

    // NOTE: Do NOT call poll_rx() here — it acquires multiple Mutexes
    // and in test mode prints to serial, which would deadlock if this
    // interrupt fires while the main thread holds any of those locks.

    // Send EOI.
    if super::apic::is_enabled() {
        super::apic::lapic_eoi();
    } else {
        unsafe { send_eoi(11); }
    }
}

/// Mouse interrupt logic.
extern "C" fn mouse_interrupt() {
    crate::perf::record_interrupt(44); // IRQ12 = vector 44
    crate::drivers::mouse::handle_irq();

    // Send EOI: use APIC if enabled, otherwise fall back to PIC.
    if super::apic::is_enabled() {
        super::apic::lapic_eoi();
    } else {
        // SAFETY: Sending EOI after handling the mouse interrupt.
        unsafe {
            send_eoi(12);
        }
    }
}

/// Keyboard interrupt logic.
extern "C" fn keyboard_interrupt() {
    crate::perf::record_interrupt(33); // IRQ1 = vector 33
    // SAFETY: Reading keyboard data port 0x60.
    let scancode = unsafe { hal::inb(0x60) };

    // Store in ring buffer
    let w = KEYBOARD_WRITE.load(Ordering::Relaxed);
    // SAFETY: Ring buffer write with atomic index.
    unsafe {
        KEYBOARD_BUFFER[(w % 256) as usize] = scancode;
    }
    KEYBOARD_WRITE.store(w + 1, Ordering::Relaxed);

    // Send EOI: use APIC if enabled, otherwise fall back to PIC.
    if super::apic::is_enabled() {
        super::apic::lapic_eoi();
    } else {
        // SAFETY: Sending EOI after handling the keyboard interrupt.
        unsafe {
            send_eoi(1);
        }
    }
}
