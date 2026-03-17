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
const WATCHDOG_LIMIT: u32 = 12000;

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
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

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

irq_stub!(irq_timer_handler,    timer_tick);
irq_stub!(irq_keyboard_handler, keyboard_interrupt);

/// Timer interrupt logic.
extern "C" fn timer_tick() {
    // Bail immediately if a bugcheck is in progress — avoid lock contention.
    if crate::ke::bugcheck::is_bugcheck_active() {
        if super::apic::is_enabled() { super::apic::lapic_eoi(); }
        return;
    }

    let tick = TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::perf::record_interrupt(32); // IRQ0 = vector 32

    // ── Heartbeat: emit every 500 ticks (~5s at 100 Hz) ─────────────
    // Gives the external watchdog (tools/qemu-watchdog.py) a signal that
    // the timer ISR is still firing.  Zero cost in production builds.
    #[cfg(any(feature = "test-mode", feature = "firefox-test"))]
    {
        if tick > 0 && tick % 500 == 0 {
            let cpu = super::apic::cpu_index();
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
    {
        let cpu = super::apic::cpu_index();
        // Only check when the scheduler is active — before it's enabled,
        // all kernel init runs on CPU 0 without context switches.
        if crate::sched::is_active() {
            // Don't watchdog idle threads — they legitimately wait in hlt
            // without calling schedule() when no user threads are assigned.
            let current_tid = crate::proc::current_tid();
            let is_idle = current_tid == 0 || {
                // AP idle threads have PID 0
                crate::proc::recover_current_pid() == 0
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
