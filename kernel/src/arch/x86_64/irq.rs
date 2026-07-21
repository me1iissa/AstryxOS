//! Interrupt Request (IRQ) handling for x86_64.
//!
//! Uses the legacy 8259 PIC (Programmable Interrupt Controller) remapped to
//! vectors 32-47. Future versions will support APIC/x2APIC.

use crate::hal;
use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use super::apic::MAX_CPUS;

// ── Watchdog counter (per-CPU) ──────────────────────────────────────────────
// Incremented every timer tick. Reset to 0 on successful context switch.
// If a CPU exceeds WATCHDOG_LIMIT ticks without a switch → bugcheck.

static WATCHDOG_COUNTER: [AtomicU32; MAX_CPUS] =
    [const { AtomicU32::new(0) }; MAX_CPUS];

/// Always-on per-CPU breadcrumb of the most recent idle-wait decision, so a
/// future field wedge is decidable from a passive, host-side RAM read without
/// a rebuild (0 = none yet, 1 = Halt, 2 = Spin).  One relaxed store per idle
/// wait at each of the two check-then-halt sites (`sched_wait_quantum` and the
/// reactor idle in `main.rs`); no `rdmsr`, no lock — observer-safe by design.
static LAST_IDLE_DECISION: [AtomicU8; MAX_CPUS] =
    [const { AtomicU8::new(0) }; MAX_CPUS];

/// Read the most recent idle-wait decision breadcrumb for `cpu`
/// (0 = none, 1 = Halt, 2 = Spin).  Diagnostic-only; out-of-range → 0.
pub fn last_idle_decision(cpu: usize) -> u8 {
    if cpu < MAX_CPUS {
        LAST_IDLE_DECISION[cpu].load(Ordering::Relaxed)
    } else {
        0
    }
}
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
#[cfg(feature = "firefox-test-core")]
const WATCHDOG_LIMIT: u32 = 60_000;
#[cfg(not(feature = "firefox-test-core"))]
const WATCHDOG_LIMIT: u32 = 12_000;

/// Reset the watchdog counter for the current CPU.
/// Called by schedule() after a successful context switch.
#[inline]
pub fn reset_watchdog_counter() {
    let cpu = super::apic::cpu_index();
    WATCHDOG_COUNTER[cpu as usize].store(0, Ordering::Relaxed);
}

/// Read the watchdog counter of an arbitrary CPU (diagnostic-only).  A high
/// value means that CPU has gone many ticks without a context switch (its
/// current thread is CPU-bound or it is wedged); a low value means it is
/// switching threads regularly.  Out-of-range index returns 0.
pub fn watchdog_counter(cpu: usize) -> u32 {
    if cpu < MAX_CPUS {
        WATCHDOG_COUNTER[cpu].load(Ordering::Relaxed)
    } else {
        0
    }
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
///
/// # Reading this counter
///
/// This is the *raw ISR-published* count.  It advances only while the LAPIC
/// periodic timer ISR (`timer_tick`) is delivering; if that timer stops
/// (e.g. a KVM vCPU whose LAPIC injection is suppressed — Intel SDM Vol. 3A
/// §11.5.4) the value **freezes** while wall time keeps moving.  Therefore any
/// code that makes a *time-dependent decision* — a timeout, a deadline, a
/// quiescence window, a throttle, a rate limiter — MUST read [`get_ticks`]
/// (which returns `max(TICK_COUNT, tsc_floor)` and so keeps advancing off the
/// invariant TSC, Intel SDM Vol. 3B §17.17) and NOT this field directly.  Read
/// `TICK_COUNT` directly only for diagnostics that specifically want the
/// ISR-published value (liveness checks, ISR-vs-TSC skew probes).
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
pub fn rdtsc() -> u64 {
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
///
/// Also publishes the calibration into the vDSO vvar page so userspace
/// `__vdso_clock_gettime` can compute TSC-precise ns without entering
/// the kernel.  Prior implementations published only `TICK_COUNT` (10 ms
/// quantum), which silently coarsened every Mozilla/glibc TimeStamp
/// reading by ~10000× — see `vdso.S` for the user-side formula.
pub fn set_tsc_calibration(tsc_per_10ms: u64) {
    if tsc_per_10ms == 0 { return; }
    let now_tsc = rdtsc();
    let _ = TSC_AT_BOOT.compare_exchange(
        0, now_tsc, Ordering::AcqRel, Ordering::Relaxed);
    let _ = TSC_PER_TICK.compare_exchange(
        0, tsc_per_10ms, Ordering::AcqRel, Ordering::Relaxed);
    // Mirror the calibration into the vvar page so userspace reads the
    // same epoch the in-kernel monotonic path uses.  Order of operations
    // matters: the atomics above MUST be populated first so any concurrent
    // in-kernel `vdso::monotonic_ns()` call sees a consistent pair.
    let tsc_at_boot  = TSC_AT_BOOT.load(Ordering::Acquire);
    let tsc_per_tick = TSC_PER_TICK.load(Ordering::Acquire);
    crate::proc::vdso::publish_tsc_calibration(tsc_at_boot, tsc_per_tick);
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
///
/// `TICK_COUNT` is normally advanced by the periodic LAPIC timer ISR
/// (`timer_tick`). On a multi-core machine *any* online CPU's LAPIC ISR
/// republishes the TSC-derived value, so the count stays wall-locked even
/// if one CPU's LAPIC delivery is briefly suppressed. On a **single core**
/// there is no second CPU to keep it fresh: under KVM a sustained burst of
/// framebuffer MMIO VM-exits (the GUI compositor's `compose()` loop) can
/// suppress LAPIC timer-interrupt delivery to the only CPU indefinitely.
/// Any `while get_ticks() … { compose(); }` settle loop then spins forever
/// in Ring 0 — and because the kernel is never preempted (the timer ISR
/// deliberately never reschedules kernel-mode contexts, see
/// `irq_timer_handler`), the lock-holder / kdb thread can never run. This
/// is the single-core init deadlock.
///
/// Fix: derive a floor for the tick value directly from the TSC, using the
/// same boot epoch and cycles-per-tick the ISR uses, and return the larger
/// of the published count and that TSC-derived floor. The TSC is the
/// invariant time source (Intel SDM Vol. 3B §17.17 — constant-rate TSC),
/// so progress is guaranteed whenever the timer is delivered *or* the TSC
/// advances, which is always. `max()` keeps the result monotone and never
/// races the ISR backwards: when the ISR is firing it is already at or
/// ahead of the floor, so SMP behaviour is unchanged.
pub fn get_ticks() -> u64 {
    let published = TICK_COUNT.load(Ordering::Relaxed);

    // Before calibration completes TSC_PER_TICK is 0; there is no usable
    // TSC epoch yet, so fall back to the published count alone. (Boot code
    // that runs before LAPIC calibration does not spin on get_ticks().)
    let tsc_per_tick = TSC_PER_TICK.load(Ordering::Acquire);
    if tsc_per_tick == 0 {
        return published;
    }

    let tsc_at_boot = TSC_AT_BOOT.load(Ordering::Acquire);
    let elapsed = rdtsc().wrapping_sub(tsc_at_boot);
    let tsc_floor = elapsed / tsc_per_tick;

    if tsc_floor > published { tsc_floor } else { published }
}

/// Convert a *relative* nanosecond timeout into the smallest scheduler tick
/// at which the requested interval is GUARANTEED to have fully elapsed.
///
/// The scheduler's due-wake scan fires a sleeper when `get_ticks() >=
/// wake_tick`.  Because [`get_ticks`] returns the **floor** of the TSC-derived
/// tick (it discards the 0–10 ms already elapsed inside the current tick),
/// naively computing `wake_tick = get_ticks() + ceil(ns / 10ms)` under-counts
/// by the fractional part of the current tick: the wait can return up to one
/// whole tick (~10 ms) EARLY.  For a 10 ms `pthread_cond_timedwait` that is a
/// ~100 % early return, which trips timing-sensitive userspace state machines.
///
/// POSIX (`man 2 clock_nanosleep`, `man 2 futex` TIMEOUTS) permits a timed
/// wait to over-shoot its deadline but never to return before the requested
/// interval has elapsed.  To honour that, we build the deadline at the
/// precision userspace measured against — the invariant TSC (Intel SDM Vol. 3B
/// §17.17, constant-rate TSC) — rather than the coarse 10 ms tick:
///
///   1. `deadline_tsc = rdtsc() + ns_to_cycles(ns)`  (absolute TSC deadline).
///   2. `wake_tick = ceil((deadline_tsc - tsc_at_boot) / tsc_per_tick)`.
///
/// The ceiling guarantees `get_ticks() >= wake_tick` cannot become true until
/// the floored tick has advanced *past* the fractional deadline, so the
/// observed sleep is always `>= ns` (over-shoot bounded by one tick, never
/// under-shoot).  This eliminates the 10 ms quantization error entirely while
/// reusing the existing `wake_tick` mechanism — no parallel deadline state on
/// the scheduler hot path.
///
/// Before LAPIC calibration completes (`tsc_per_tick == 0`) there is no usable
/// TSC epoch; fall back to the coarse tick arithmetic, but still round the tick
/// count UP and add one so the wait never under-shoots in that early window.
pub fn relative_ns_to_wake_tick(ns: u64) -> u64 {
    let tsc_per_tick = TSC_PER_TICK.load(Ordering::Acquire);
    if tsc_per_tick == 0 {
        // No TSC epoch yet (pre-calibration). Coarse fallback: round up and
        // add one tick so the wait lasts AT LEAST the requested interval.
        let now = get_ticks();
        let delta_ticks = ns.div_ceil(10_000_000).saturating_add(1);
        return now.saturating_add(delta_ticks);
    }

    // ns → TSC cycles: cycles = ns * tsc_per_tick / 10_000_000  (10 ms/tick).
    // Use u128 for the intermediate product so a multi-second timeout cannot
    // overflow before the divide (tsc_per_tick is ~10^7 on a 1 GHz part, ns
    // can be up to ~10^18 for the legal tv_sec range).
    let ns_cycles =
        ((ns as u128).saturating_mul(tsc_per_tick as u128) / 10_000_000u128) as u64;

    let tsc_at_boot = TSC_AT_BOOT.load(Ordering::Acquire);
    let elapsed_now = rdtsc().wrapping_sub(tsc_at_boot);
    let deadline_cycles = elapsed_now.saturating_add(ns_cycles);

    // ceil(deadline_cycles / tsc_per_tick): the smallest tick whose floor is
    // at or beyond the absolute deadline. `now >= wake_tick` then cannot fire
    // before `elapsed >= deadline_cycles`, i.e. before `ns` has elapsed.
    deadline_cycles.div_ceil(tsc_per_tick)
}

/// Number of times the BSP idle path detected a starved LAPIC timer and
/// drove a scheduler tick from the TSC instead. Diagnostic-only; non-zero
/// means the single-core LAPIC-suppression recovery path (see [`idle_tick`])
/// fired.
pub static TIMER_REARM_COUNT: AtomicU64 = AtomicU64::new(0);

/// Last TSC-floor tick at which the BSP idle path drove a software scheduler
/// tick. Used to rate-limit the software tick to ~`TICK_HZ`.
static LAST_SOFT_TICK: AtomicU64 = AtomicU64::new(0);

/// Per-CPU LAPIC-timer liveness snapshot for [`cpu_timer_live`].  Element
/// `[cpu]` stores `(last_seen_isr_count, tsc_at_observation)`: the value of
/// `TIMER_ISR_PER_CPU[cpu]` the last time this CPU checked its own liveness,
/// and the TSC at that check.  A check whose ISR count has not advanced AND
/// whose TSC has moved more than the liveness window ⇒ this CPU's own periodic
/// timer has wedged (KVM LAPIC-injection suppression, Intel SDM Vol. 3A
/// §11.5.4 — a wedged periodic counter does not spontaneously resume).
///
/// Why per-CPU and not the global `TICK_COUNT`: `TICK_COUNT` is TSC-derived and
/// CAS-published by *whichever* online CPU's timer ISR runs (see `timer_tick`),
/// so on SMP a single healthy sibling keeps the GLOBAL clock fresh and masks a
/// LOCALLY dead timer.  A CPU whose own LAPIC has stopped delivering would see
/// `TICK_COUNT` tracking the TSC perfectly (the sibling maintains it) and wrongly
/// conclude its timer is healthy — then `hlt` into a sleep its own dead timer
/// never wakes.  This per-CPU ISR-advancement check is immune to that masking.
static CPU_TIMER_SEEN: [(AtomicU64, AtomicU64); super::apic::MAX_CPUS] =
    [const { (AtomicU64::new(0), AtomicU64::new(0)) }; super::apic::MAX_CPUS];

/// Per-CPU sticky "this CPU's LAPIC periodic timer is currently dead" flag.
///
/// Set the moment [`cpu_timer_live`] first declares the local timer wedged;
/// cleared only when the local `TIMER_ISR_PER_CPU` count is observed to advance
/// (a real recovery — the timer started delivering again).  It is sticky on
/// purpose: a wedged KVM LAPIC does not reliably resume after a re-arm (Intel
/// SDM Vol. 3A §11.5.4 restarts the *counter*, but KVM may keep suppressing
/// *injection*), so without stickiness `cpu_timer_live` would optimistically
/// report "healthy" again as soon as it re-anchored the TSC inside the liveness
/// window — and the caller would `hlt` straight back into the dead-timer trap,
/// only to be woken ~one window later by the sibling poke (a low-duty-cycle
/// limp at ~1/window Hz instead of a CPU that keeps running).  Sticky-dead makes
/// a CPU with a wedged timer SPIN continuously (self-clocked off the TSC) until
/// the hardware timer genuinely recovers.
static CPU_TIMER_DEAD: [core::sync::atomic::AtomicBool; super::apic::MAX_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; super::apic::MAX_CPUS];

/// Per-CPU count of consecutive futile re-arms since this CPU's timer was last
/// declared dead.  Reset to 0 whenever the ISR advances (recovery).  Once it
/// reaches [`MAX_FUTILE_REARMS`] the periodic re-arm retry STOPS for this CPU
/// (the host — typically KVM — is permanently suppressing injection on this
/// vCPU; no amount of re-programming the guest LAPIC will revive it) and the
/// CPU relies purely on the TSC-clocked spin + cross-CPU poke to stay scheduled.
/// This bounds futile LAPIC-MMIO writes on a permanently-dead timer while still
/// giving a transiently-wedged timer many chances to resume.
static CPU_TIMER_DEAD_REARMS: [AtomicU64; super::apic::MAX_CPUS] =
    [const { AtomicU64::new(0) }; super::apic::MAX_CPUS];

/// Cap on consecutive periodic re-arms of a dead timer before giving up on
/// re-programming it (≈ a few seconds of retries at one re-arm per liveness
/// window).  A genuinely transient wedge resumes well within this; a
/// host-suppressed timer never will, so stop churning LAPIC MMIO and let the
/// spin + cross-CPU poke carry the CPU.
const MAX_FUTILE_REARMS: u64 = 32;

/// True iff `cpu`'s LAPIC periodic timer has been declared dead and not yet
/// recovered.  Diagnostic accessor for the kdb `cpu-state` survey.
pub fn cpu_timer_dead(cpu: usize) -> bool {
    if cpu < super::apic::MAX_CPUS {
        CPU_TIMER_DEAD[cpu].load(Ordering::Relaxed)
    } else {
        false
    }
}

/// Test-only: force `cpu`'s sticky dead-timer flag, so the idle-wait liveness
/// test can simulate a wedged LAPIC deterministically (no real dead timer, no
/// KVM dependency) and prove the spin arm advances the run queue off the TSC.
#[cfg(feature = "test-mode")]
pub fn test_set_cpu_timer_dead(cpu: usize, dead: bool) {
    if cpu < super::apic::MAX_CPUS {
        CPU_TIMER_DEAD[cpu].store(dead, Ordering::Relaxed);
    }
}

/// Count of per-CPU LAPIC re-arms triggered by [`cpu_timer_live`] detecting a
/// locally-wedged timer.  Diagnostic-only; a non-zero value on the BSP under
/// SMP is the signature of the dead-CPU0-LAPIC self-heal firing.
pub static PERCPU_TIMER_REARM_COUNT: AtomicU64 = AtomicU64::new(0);

/// Snapshot of [`PERCPU_TIMER_REARM_COUNT`].
pub fn percpu_timer_rearm_count() -> u64 {
    PERCPU_TIMER_REARM_COUNT.load(Ordering::Relaxed)
}

/// IPI vector for the cross-CPU timer-wake poke (see `timer_wake_interrupt`).
/// 0xF0 = TLB shootdown, 0xF1 = W215 DR-sync, 0xF2 = reschedule IPI
/// (Perf P2 phase 3c), 0xF3 = timer-wake.  A distinct vector per IPI class
/// keeps each handler body independent (Intel SDM Vol. 3A §10.6.1).
pub const TIMER_WAKE_VECTOR: u8 = 0xF3;

/// Number of timer-wake IPIs SENT (a live CPU poked a sibling whose timer ISR
/// went stale) and RECEIVED.  Diagnostic-only; a non-zero `sent` under SMP is
/// the signature of the dead-sibling-LAPIC self-heal driving the poke.
pub static TIMER_WAKE_IPI_SENT: AtomicU64 = AtomicU64::new(0);
pub static TIMER_WAKE_IPI_RECEIVED: AtomicU64 = AtomicU64::new(0);

/// Per-CPU `(last_seen_isr, tsc_at_observation)` used by the timer-ISR sender to
/// detect a sibling whose own timer ISR has gone stale.  Distinct from
/// `CPU_TIMER_SEEN` (which the SELF-check in `cpu_timer_live` owns) so the two
/// liveness observers never clobber each other's anchors.
static SIBLING_TIMER_SEEN: [(AtomicU64, AtomicU64); super::apic::MAX_CPUS] =
    [const { (AtomicU64::new(0), AtomicU64::new(0)) }; super::apic::MAX_CPUS];

/// Snapshots of the timer-wake IPI counters.
pub fn timer_wake_ipi_sent() -> u64 { TIMER_WAKE_IPI_SENT.load(Ordering::Relaxed) }
pub fn timer_wake_ipi_received() -> u64 { TIMER_WAKE_IPI_RECEIVED.load(Ordering::Relaxed) }

/// From a LIVE CPU's timer ISR, poke any sibling whose own timer ISR has gone
/// stale (its LAPIC periodic timer wedged) so it cannot sleep through a dead
/// timer.  Called once per local tick by `timer_tick`; cheap (a handful of
/// atomic reads, an IPI only when a sibling is actually found stale).
///
/// "Stale" = the sibling's `TIMER_ISR_PER_CPU` count has not advanced across a
/// `STALE_WINDOW`-tick wall-clock window (TSC-measured against our own publish
/// rate).  We re-anchor the observation whenever the sibling advances OR we
/// poke it, so a single sibling is poked at most ~once per window rather than
/// every tick — enough to keep it awake and re-arming without an IPI storm.
fn poke_stale_siblings(this_cpu: usize, tsc_now: u64, tsc_per_tick: u64) {
    /// Wall-clock window (100 Hz ticks) a sibling's timer may be silent before
    /// we consider it wedged and poke it.  ~20 ticks (≈200 ms) is well clear of
    /// normal ISR jitter yet keeps the reactor's worst-case stall short.
    const STALE_WINDOW: u64 = 20;
    if tsc_per_tick == 0 {
        return;
    }
    let ncpus = (super::apic::cpu_count() as usize).min(super::apic::MAX_CPUS);
    for cpu in 0..ncpus {
        if cpu == this_cpu {
            continue;
        }
        let isr_now = TIMER_ISR_PER_CPU[cpu].load(Ordering::Relaxed);
        let seen_isr = SIBLING_TIMER_SEEN[cpu].0.load(Ordering::Relaxed);
        let seen_tsc = SIBLING_TIMER_SEEN[cpu].1.load(Ordering::Relaxed);

        // First observation, or the sibling's timer advanced: it is alive.
        // Re-anchor and move on.
        if seen_tsc == 0 || isr_now != seen_isr {
            SIBLING_TIMER_SEEN[cpu].0.store(isr_now, Ordering::Relaxed);
            SIBLING_TIMER_SEEN[cpu].1.store(tsc_now, Ordering::Relaxed);
            continue;
        }

        // Sibling's timer ISR has not advanced since our last observation.  How
        // long (wall-clock) has it been silent?
        let silent = tsc_now.wrapping_sub(seen_tsc) / tsc_per_tick;
        if silent < STALE_WINDOW {
            continue;
        }

        // Wedged sibling: poke it.  Any interrupt resumes it from `hlt`; its own
        // idle/wait path then re-arms its LAPIC (cpu_timer_live).  Re-anchor the
        // TSC (keep the stale ISR count) so we re-poke at most once per window.
        super::apic::send_ipi(cpu as u8, TIMER_WAKE_VECTOR);
        TIMER_WAKE_IPI_SENT.fetch_add(1, Ordering::Relaxed);
        SIBLING_TIMER_SEEN[cpu].1.store(tsc_now, Ordering::Relaxed);
    }
}

/// Check whether the CALLING CPU's own LAPIC periodic timer is still
/// delivering interrupts, and re-arm it if it has wedged.
///
/// Returns `true` if this CPU's `TIMER_ISR_PER_CPU` count has advanced since the
/// previous check (or the liveness window has not yet elapsed) — i.e. the local
/// timer is delivering.  Returns `false` if the local timer has gone silent for
/// more than `window_ticks` of wall-clock (TSC-measured) while this CPU was
/// active; in that case it has already issued a `rearm_timer()` for the local
/// LAPIC (Intel SDM Vol. 3A §11.5.4 — rewriting the LVT + initial-count restarts
/// a wedged periodic counter) so the caller MUST NOT `hlt` (a dead timer offers
/// no wakeup) but should spin and re-drive cooperative work.
///
/// Unlike the global `TICK_COUNT`-vs-TSC check this is per-CPU and so detects a
/// locally-dead timer even when a healthy sibling keeps the global clock fresh
/// (the SMP "de-facto single core" failure mode).  Cheap: two atomic reads, an
/// `rdtsc`, and — only when wedged — a re-arm.  `window_ticks` is in 100 Hz
/// ticks; ~10 (≈100 ms) tolerates normal ISR jitter without false re-arms.
///
/// The pure decision logic is factored into [`timer_live_decision`] so it can be
/// unit-tested without LAPIC hardware; `cpu_timer_live` is the thin per-CPU shell
/// that gathers the inputs (atomics, `rdtsc`, `cpu_index`) and applies the side
/// effects (re-arm, counter updates) the decision asks for.

/// Outcome of the per-CPU timer-liveness decision (the hardware-free core of
/// [`cpu_timer_live`]).  Lets the state machine be exercised in `test_runner`
/// without a real LAPIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerLiveDecision {
    /// Timer is delivering (ISR advanced, or still within the tolerance window).
    /// `clear_dead` is true when a previously-dead timer has genuinely recovered.
    Live { clear_dead: bool },
    /// Timer is wedged: report unhealthy (caller must spin, not `hlt`).
    /// `rearm` is true when the caller should issue a from-scratch LAPIC re-arm
    /// this call (bounded by the futile-re-arm cap once already dead).
    Dead { rearm: bool },
}

/// Pure liveness decision shared by [`cpu_timer_live`] and its unit test.
///
/// Inputs (all caller-gathered):
///   * `isr_advanced` — did `TIMER_ISR_PER_CPU[cpu]` change since the last anchor?
///   * `first_obs`    — is this the first observation for this CPU (no anchor yet)?
///   * `silent_ticks` — wall-clock ticks since the anchor TSC (0 if `isr_advanced`).
///   * `window_ticks` — tolerance window before declaring a silent timer wedged.
///   * `already_dead` — is the sticky dead flag currently set?
///   * `rearms_so_far`— consecutive futile re-arms since this CPU went dead.
///   * `max_rearms`   — the futile-re-arm cap ([`MAX_FUTILE_REARMS`]).
///
/// The decision is total and side-effect-free; the caller maps it onto the
/// atomics + the `rearm_timer()` MMIO.
pub fn timer_live_decision(
    isr_advanced: bool,
    first_obs: bool,
    silent_ticks: u64,
    window_ticks: u64,
    already_dead: bool,
    rearms_so_far: u64,
    max_rearms: u64,
) -> TimerLiveDecision {
    // ISR advanced (or first observation): alive; clear sticky-dead on recovery.
    if first_obs || isr_advanced {
        return TimerLiveDecision::Live { clear_dead: already_dead };
    }
    // Already declared dead: stay dead, but re-arm once per window until the
    // futile-re-arm cap, then stop churning LAPIC MMIO and rely on spin + poke.
    if already_dead {
        let rearm = silent_ticks >= window_ticks && rearms_so_far < max_rearms;
        return TimerLiveDecision::Dead { rearm };
    }
    // Not yet dead: within tolerance ⇒ still live; past the window ⇒ declare dead
    // and re-arm now.
    if silent_ticks < window_ticks {
        TimerLiveDecision::Live { clear_dead: false }
    } else {
        TimerLiveDecision::Dead { rearm: true }
    }
}

pub fn cpu_timer_live(window_ticks: u64) -> bool {
    let tsc_per_tick = TSC_PER_TICK.load(Ordering::Acquire);
    if tsc_per_tick == 0 {
        return true; // pre-calibration — the timer is not expected yet
    }
    let cpu = super::apic::cpu_index();
    if cpu >= super::apic::MAX_CPUS {
        return true;
    }
    let isr_now = TIMER_ISR_PER_CPU[cpu].load(Ordering::Relaxed);
    let tsc_now = rdtsc();
    let seen_isr = CPU_TIMER_SEEN[cpu].0.load(Ordering::Relaxed);
    let seen_tsc = CPU_TIMER_SEEN[cpu].1.load(Ordering::Relaxed);
    let already_dead = CPU_TIMER_DEAD[cpu].load(Ordering::Relaxed);
    let rearms = CPU_TIMER_DEAD_REARMS[cpu].load(Ordering::Relaxed);

    let first_obs = seen_tsc == 0;
    let isr_advanced = isr_now != seen_isr;
    // `silent_ticks` is meaningful only when the ISR has NOT advanced; the
    // decision ignores it on the advanced/first-obs path.
    let silent_ticks = tsc_now.wrapping_sub(seen_tsc) / tsc_per_tick;

    match timer_live_decision(
        isr_advanced, first_obs, silent_ticks, window_ticks,
        already_dead, rearms, MAX_FUTILE_REARMS,
    ) {
        TimerLiveDecision::Live { clear_dead } => {
            // Record the fresh anchor and, on a genuine recovery, clear the
            // sticky-dead flag + futile-re-arm counter.
            CPU_TIMER_SEEN[cpu].0.store(isr_now, Ordering::Relaxed);
            CPU_TIMER_SEEN[cpu].1.store(tsc_now, Ordering::Relaxed);
            if clear_dead {
                CPU_TIMER_DEAD[cpu].store(false, Ordering::Relaxed);
                CPU_TIMER_DEAD_REARMS[cpu].store(0, Ordering::Relaxed);
            }
            true
        }
        TimerLiveDecision::Dead { rearm } => {
            // Declare dead (idempotent) and, if the decision asked for it, issue
            // the full from-scratch re-arm and bump the bounded retry counter.
            if !already_dead {
                CPU_TIMER_DEAD[cpu].store(true, Ordering::Relaxed);
            }
            if rearm {
                super::apic::rearm_timer();
                PERCPU_TIMER_REARM_COUNT.fetch_add(1, Ordering::Relaxed);
                // First re-arm at declaration seeds the counter at 1; subsequent
                // periodic retries increment it toward the cap.
                if already_dead {
                    CPU_TIMER_DEAD_REARMS[cpu].fetch_add(1, Ordering::Relaxed);
                } else {
                    CPU_TIMER_DEAD_REARMS[cpu].store(1, Ordering::Relaxed);
                }
                CPU_TIMER_SEEN[cpu].1.store(tsc_now, Ordering::Relaxed);
            } else if silent_ticks >= window_ticks {
                // Past the cap: stop re-arming but re-anchor so a long-dead
                // timer's `silent_ticks` divide never overflows.
                CPU_TIMER_SEEN[cpu].1.store(tsc_now, Ordering::Relaxed);
            }
            false
        }
    }
}

/// Outcome of the idle-wait decision (see [`idle_bare_hlt_ok`] /
/// [`sched_wait_decision`]): either halt (the LAPIC timer is a trustworthy sole
/// wake) or spin on the TSC clock (a bare `hlt` would risk an un-wakeable trap).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IdleAction {
    Halt,
    Spin,
}

/// Should an idle wait enter a bare `hlt`, or must it spin on the TSC clock?
///
/// Bare `hlt` is only safe when the LAPIC timer is a trustworthy sole wake.  On
/// a hypervisor (or any test/FF build, where CPUID.01H:ECX[31] may be hidden
/// under nested virtualisation) with exactly ONE online CPU, the LAPIC timer
/// can stop *delivering* mid-halt with no backstop — under KVM oversubscription
/// a stuck in-service timer vector raises PPR and blocks the pending re-armed
/// timer and device IRQs from ever waking the halted CPU (Intel SDM Vol. 3A
/// §10.8.3.1 / §10.8.4).  With no sibling to send a `TIMER_WAKE` IPI (0xF3),
/// nothing ends the halt, so we must NOT halt — we spin on `get_ticks()` (a TSC
/// floor, Intel SDM Vol. 3B §17.17 invariant TSC), which does not depend on
/// interrupt *delivery* at all.  SMP keeps halting: a wedged CPU is woken by the
/// sibling `TIMER_WAKE` IPI.  Bare metal keeps halting: no hypervisor injection
/// suppression, idle power preserved.
///
/// Pure, total, hardware-free — the unit-testable core of the decision.
pub fn idle_bare_hlt_ok(timer_live: bool, cpus: u32, force_spin_uni: bool) -> bool {
    timer_live && !(cpus == 1 && force_spin_uni)
}

/// Test-only overrides for the three idle-wait decision inputs, so
/// [`sched_wait_decision`] can be exercised with pinned `(live, cpus, force)`
/// without real hardware.  `LIVE`/`FORCE` are tri-state (0 = use the live
/// value, 1 = force `false`, 2 = force `true`); `CPUS` is 0 = real
/// [`super::apic::cpu_count`], else the forced count.  Absent in production
/// builds — the decision reads the real inputs with zero overhead.
#[cfg(feature = "test-mode")]
pub(crate) mod idle_decision_test {
    use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
    pub static LIVE: AtomicU8 = AtomicU8::new(0);
    pub static FORCE: AtomicU8 = AtomicU8::new(0);
    pub static CPUS: AtomicU32 = AtomicU32::new(0);
    fn tristate(v: Option<bool>) -> u8 {
        match v { None => 0, Some(false) => 1, Some(true) => 2 }
    }
    /// Pin the decision inputs; `None` on `live`/`force` means "use the live
    /// value", `None`/`0` on `cpus` means "use the real count".
    pub fn set(live: Option<bool>, cpus: Option<u32>, force: Option<bool>) {
        LIVE.store(tristate(live), Ordering::Relaxed);
        FORCE.store(tristate(force), Ordering::Relaxed);
        CPUS.store(cpus.unwrap_or(0), Ordering::Relaxed);
    }
    /// Restore all three inputs to their real hardware/build values.
    pub fn clear() {
        LIVE.store(0, Ordering::Relaxed);
        FORCE.store(0, Ordering::Relaxed);
        CPUS.store(0, Ordering::Relaxed);
    }
}

/// The `timer_live` input to the idle decision — real `cpu_timer_live(10)`,
/// with a test-only override.
#[inline]
fn idle_live_input() -> bool {
    #[cfg(feature = "test-mode")]
    match idle_decision_test::LIVE.load(Ordering::Relaxed) {
        1 => return false,
        2 => return true,
        _ => {}
    }
    cpu_timer_live(10)
}

/// The `cpus` input to the idle decision — real online count, with a test-only
/// override.
#[inline]
fn idle_cpus_input() -> u32 {
    #[cfg(feature = "test-mode")]
    {
        let c = idle_decision_test::CPUS.load(Ordering::Relaxed);
        if c != 0 {
            return c;
        }
    }
    super::apic::cpu_count()
}

/// Whether the idle path must force a spin on a uniprocessor rather than halt.
///
/// Test/FF builds always force it (immune to a hidden CPUID.01H:ECX[31] under
/// nested KVM/WSL2); real single-vCPU VMs pick it up at runtime from the cached
/// hypervisor-present flag (Intel SDM Vol. 2A CPUID, AMD APM Vol. 3).  Bare
/// metal returns false, so bare-metal uniprocessors keep halting at idle.
#[inline]
pub(crate) fn force_spin_uni() -> bool {
    #[cfg(feature = "test-mode")]
    match idle_decision_test::FORCE.load(Ordering::Relaxed) {
        1 => return false,
        2 => return true,
        _ => {}
    }
    cfg!(any(feature = "test-mode", feature = "firefox-test-core"))
        || super::apic::hypervisor_present()
}

/// The idle-wait decision actually executed by [`sched_wait_quantum`]: reads the
/// live inputs (test-overridable) and maps them onto [`idle_bare_hlt_ok`].  The
/// `asm` arm is chosen solely by this return, so a unit test of this function
/// tests the exact branch the scheduler runs.
pub(crate) fn sched_wait_decision() -> IdleAction {
    if idle_bare_hlt_ok(idle_live_input(), idle_cpus_input(), force_spin_uni()) {
        IdleAction::Halt
    } else {
        IdleAction::Spin
    }
}

/// Idle-wait one quantum from a scheduler wait-path: sleep until the next wake,
/// but never sleep into a dead-timer trap.
///
/// The scheduler's "no Ready peer" wait paths classically execute
/// `sti; hlt; cli`, relying on this CPU's periodic LAPIC timer to wake it ~10 ms
/// later so it can re-run the picker.  On SMP a CPU whose LAPIC periodic timer
/// has wedged (KVM injection suppression — see [`cpu_timer_live`]) has no such
/// wakeup: a blind `hlt` there sleeps until an unrelated asynchronous IRQ
/// happens to land on the CPU, which under a single-vCPU-affine IRQ routing is
/// effectively never — the CPU drops out of scheduling entirely (the
/// "de-facto single core" failure mode).
///
/// This helper makes the wait timer-fault-tolerant, deciding via
/// [`sched_wait_decision`]:
///   * **Halt** → `sti; hlt; cli` as before (cheap; the timer wakes us).  Chosen
///     when the local timer is live AND (SMP, or bare-metal uniprocessor) — a
///     wedged SMP CPU is backstopped by the sibling `TIMER_WAKE` IPI (0xF3).
///   * **Spin** → drive a software scheduler tick from the TSC and spin briefly
///     (`sti; pause; cli`) WITHOUT halting, so the CPU re-enters the picker on
///     its own clock and any peer that becomes Ready is picked up promptly.
///     Chosen when the local timer is wedged (as before) OR on a
///     hypervisor/test uniprocessor, where a mid-halt LAPIC delivery failure has
///     no backstop (see [`idle_bare_hlt_ok`]).
///
/// The `sti` window in both arms lets a pending IRQ/IPI (including a TLB
/// shootdown IPI, #643, or a future reschedule IPI, #648) land before the CPU
/// blocks/spins, so this composes with the cross-CPU IPI paths unchanged.
#[inline]
pub fn sched_wait_quantum() {
    let cpu = super::apic::cpu_index();
    match sched_wait_decision() {
        IdleAction::Halt => {
            if cpu < MAX_CPUS {
                LAST_IDLE_DECISION[cpu].store(1, Ordering::Relaxed);
            }
            // Healthy local timer: halt until the next tick (or any wake).  The
            // STI shadow guarantees `hlt` executes before any pending interrupt,
            // so this is race-free.
            unsafe { core::arch::asm!("sti; hlt; cli", options(nomem, nostack)); }
        }
        IdleAction::Spin => {
            if cpu < MAX_CPUS {
                LAST_IDLE_DECISION[cpu].store(2, Ordering::Relaxed);
            }
            // Local timer wedged, or a hypervisor/test uniprocessor with no
            // halt backstop.  Keep the run queue moving on the TSC clock and
            // spin instead of halting.
            crate::sched::timer_tick_schedule();
            unsafe { core::arch::asm!("sti; pause; cli", options(nomem, nostack)); }
        }
    }
}

/// Reactor-idle variant of the idle-halt decision (BSP poll loop, `main.rs`):
/// the caller has already computed timer health via [`idle_tick`], so this
/// applies the same [`idle_bare_hlt_ok`] predicate + `force_spin_uni` gate,
/// records the `LAST_IDLE_DECISION` breadcrumb, and returns `true` if the
/// caller may `hlt`, `false` if it must spin.  Routes the second identical
/// check-then-halt TOCTOU through one shared predicate.
pub fn reactor_idle_may_halt(timer_ok: bool) -> bool {
    let halt = idle_bare_hlt_ok(timer_ok, super::apic::cpu_count(), force_spin_uni());
    let cpu = super::apic::cpu_index();
    if cpu < MAX_CPUS {
        LAST_IDLE_DECISION[cpu].store(if halt { 1 } else { 2 }, Ordering::Relaxed);
    }
    halt
}

/// Cooperative idle step for the BSP polling/soak loop.
///
/// Returns `true` if the LAPIC timer is healthy (the caller may safely `hlt`
/// and rely on the next timer interrupt to wake it) and `false` if the timer
/// is starved (the caller MUST NOT `hlt` — there is no wakeup source — and
/// should spin-yield instead).
///
/// Background: under KVM a lone vCPU can have its LAPIC periodic timer
/// suppressed by a sustained framebuffer-MMIO VM-exit storm (the GUI
/// compositor) and **not** resume even after the storm ends. Rewriting the
/// LAPIC initial-count does not reliably un-wedge KVM's injection, so a
/// dead timer means: (a) `TICK_COUNT` would freeze — already handled by
/// [`get_ticks`] reading a TSC floor; (b) the scheduler tick
/// (`timer_tick_schedule`, which wakes timed-out sleepers and rotates the
/// run queue) would never run; and (c) a blind `hlt` would sleep forever.
///
/// This routine makes the single core self-clocking. When the TSC shows the
/// published `TICK_COUNT` has fallen `slack` ticks behind real time, it:
///   1. attempts a LAPIC re-arm (cheap; helps if the timer is merely masked),
///   2. drives `timer_tick_schedule()` directly from the idle thread once per
///      elapsed tick (rate-limited via `LAST_SOFT_TICK`) so timed waits and
///      run-queue rotation make progress on the live TSC clock, and
///   3. reports the timer as unhealthy so the caller spin-yields instead of
///      hlt-ing into a dead-timer sleep.
///
/// On a healthy timer — every SMP run, and single-core once the LAPIC is
/// delivering — the published count tracks the TSC within ~1 tick, so this is
/// a cheap comparison that returns `true` and the caller `hlt`s normally.
/// `timer_tick_schedule()` is ISR-context-safe (it `try_lock`s `THREAD_TABLE`
/// and only sets reschedule flags), so calling it from the idle thread is
/// sound.
///
/// `slack` is in ticks (10 ms units at 100 Hz). ~5 (≈50 ms) tolerates the
/// normal one-tick ISR publish lag without firing spuriously.
pub fn idle_tick(slack: u64) -> bool {
    let tsc_per_tick = TSC_PER_TICK.load(Ordering::Acquire);
    if tsc_per_tick == 0 {
        return true; // pre-calibration: nothing to drive yet, hlt is fine
    }
    let published = TICK_COUNT.load(Ordering::Relaxed);
    let tsc_at_boot = TSC_AT_BOOT.load(Ordering::Acquire);
    let elapsed = rdtsc().wrapping_sub(tsc_at_boot);
    let tsc_floor = elapsed / tsc_per_tick;

    // Timer healthy: the ISR is keeping TICK_COUNT within `slack` of the TSC.
    //
    // On SMP this GLOBAL check is necessary but not sufficient: `TICK_COUNT` is
    // maintained by whichever online CPU's timer ISR runs, so a healthy sibling
    // keeps it fresh and masks a LOCALLY-dead timer on the calling CPU (the
    // "de-facto single core" failure mode where one CPU's LAPIC periodic timer
    // wedges under KVM and the other carries the whole clock).  So even when the
    // global clock looks healthy, gate the `hlt` on this CPU's OWN timer being
    // live — `cpu_timer_live` re-arms a locally-wedged LAPIC and returns false,
    // and a CPU whose own timer is dead must spin (not `hlt` into a sleep its
    // timer can never end).  Window ~10 ticks (≈100 ms) tolerates ISR jitter.
    if tsc_floor <= published.wrapping_add(slack) {
        if cpu_timer_live(10) {
            return true;
        }
        // Global clock fine but the local timer just wedged: keep the run queue
        // moving with a software tick before reporting unhealthy so the caller
        // spins instead of hlt-ing.
        crate::sched::timer_tick_schedule();
        return false;
    }

    // Timer starved. Try to revive it (harmless if it's just masked), then
    // drive a software scheduler tick from the TSC so the system keeps
    // running on the single core regardless of LAPIC delivery.
    super::apic::rearm_timer();

    // Rate-limit the software tick to ~one per real elapsed tick so we don't
    // burn the run queue's time-slice accounting faster than wall time.
    let last = LAST_SOFT_TICK.load(Ordering::Relaxed);
    if tsc_floor > last {
        LAST_SOFT_TICK.store(tsc_floor, Ordering::Relaxed);
        TIMER_REARM_COUNT.fetch_add(1, Ordering::Relaxed);
        crate::sched::timer_tick_schedule();
    }
    false
}

// ============================================================
// Hardware IRQ handlers (called from IDT stubs)
// ============================================================

/// Generate a naked ISR stub that saves caller-saved registers, calls
/// `$handler`, then restores and `iretq`s.  All four hardware IRQ stubs
/// are identical in structure; this macro removes the duplication.
///
/// ## SMAP entry guard
///
/// Hardware IRQs fire asynchronously on ring-3 contexts and per Intel SDM
/// Vol. 3A §6.4 the CPU pushes the interrupted RFLAGS unchanged onto the
/// kernel stack — leaving the live EFLAGS.AC at whatever the user held.
/// EFLAGS.AC is not a privileged bit, so a ring-3 attacker can set AC=1
/// and rely on an asynchronous IRQ to enter the kernel with SMAP silently
/// lifted (CWE-269 / CWE-693).  Today the hardware-IRQ paths below only
/// touch the kernel direct-physical map, but the post-#302 invariant —
/// "AC=0 at every ring-3 → ring-0 boundary unless inside a nested
/// `UserGuard`" — must hold for every entry to keep the property
/// composable.  Per Intel SDM Vol. 2A (CLAC) the instruction raises #UD
/// if CR4.SMAP=0, so the emit is gated on the runtime `SMAP_ENABLED`
/// flag set by `arch::x86_64::enable_cpu_security_features`.
macro_rules! irq_stub {
    ($name:ident, $handler:ident) => {
        #[unsafe(naked)]
        pub extern "C" fn $name() {
            core::arch::naked_asm!(
                // ── SMAP entry guard — see macro-level doc comment ──
                "cmp byte ptr [rip + {smap_enabled}], 0",
                "je 90f",
                "clac",
                "90:",
                "push rax", "push rcx", "push rdx",
                "push rsi", "push rdi",
                "push r8",  "push r9",  "push r10", "push r11",
                "call {handler}",
                "pop r11",  "pop r10",  "pop r9",   "pop r8",
                "pop rdi",  "pop rsi",
                "pop rdx",  "pop rcx",  "pop rax",
                "iretq",
                handler = sym $handler,
                smap_enabled = sym crate::arch::x86_64::smap::SMAP_ENABLED,
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
//
// Stack layout just after the 15 register pushes (and immediately before
// `call {timer_tick}`):
//   rsp+  0 .. rsp+112  : 15 saved GPRs (r15 at +0 → rax at +112)
//   rsp+120             : interrupted RIP (CPU-pushed IRETQ frame start)
//   rsp+128             : interrupted CS
//   rsp+136             : interrupted RFLAGS
//   rsp+144             : interrupted RSP
//   rsp+152             : interrupted SS
// The saved RBP is at rsp+32 (r15, r14, r13, r12 = 4 slots above it).
#[unsafe(naked)]
pub extern "C" fn irq_timer_handler() {
    core::arch::naked_asm!(
        // ── SMAP entry guard ────────────────────────────────────────────
        // Asynchronous LAPIC timer IRQ may land on a ring-3 context that
        // set EFLAGS.AC=1 in userspace (the AC bit is not privileged —
        // CWE-269 / CWE-693).  Per Intel SDM Vol. 3A §6.4 the CPU
        // preserves the interrupted RFLAGS into the IRETQ frame and
        // leaves the live AC bit alone, so a kernel-side user-pointer
        // deref taken in the ISR would run with SMAP silently lifted.
        // The timer ISR itself does not deref user pointers today, but
        // the post-#302 invariant — "AC=0 at every ring-3 → ring-0
        // boundary unless inside a nested `UserGuard`" — must hold here
        // for the property to compose with any future user-mode helper
        // the timer path calls (e.g. activity-metrics probes).  CLAC
        // raises #UD if CR4.SMAP=0 (Intel SDM Vol. 2A), so the emit is
        // gated on the runtime `SMAP_ENABLED` flag.
        "cmp byte ptr [rip + {smap_enabled}], 0",
        "je 90f",
        "clac",
        "90:",
        // Save ALL registers (caller + callee saved)
        "push rax", "push rcx", "push rdx",
        "push rsi", "push rdi",
        "push r8",  "push r9",  "push r10", "push r11",
        "push rbx", "push rbp",
        "push r12", "push r13", "push r14", "push r15",
        // Call timer handler (tick count, scheduler bookkeeping, EOI)
        "call {timer_tick}",
        // Userspace-RIP sampler (W149 / W152).  Behind `firefox-test`;
        // the sym below resolves to a no-op stub in non-firefox builds.
        // Args (System V x86-64):
        //   rdi = &InterruptFrame (the CPU-pushed IRET frame at rsp+120)
        //   rsi = saved user RBP  (pushed at rsp+32 in the prologue above)
        "lea rdi, [rsp + 120]",
        "mov rsi, [rsp + 32]",
        "call {sample_tick}",
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
        sample_tick = sym sample_tick_trampoline,
        check_resched = sym crate::sched::check_reschedule,
        smap_enabled = sym crate::arch::x86_64::smap::SMAP_ENABLED,
    );
}

/// Trampoline from the timer-ISR asm into the userspace-RIP sampler.
///
/// Receives `(frame_ptr, saved_rbp)` System-V style (RDI/RSI).  The asm
/// stub is structurally identical regardless of whether the sampler is
/// compiled in, so we provide a no-op stub when `firefox-test` is off
/// and dispatch into [`crate::proc::sample::maybe_sample`] otherwise.
///
/// SAFETY: `frame_ptr` is guaranteed valid by the ISR stub — it points
/// into the interrupted thread's kernel stack at the CPU-pushed IRETQ
/// frame.  The frame lives until the matching IRETQ at the end of the
/// stub, so the borrow created here is valid for the lifetime of this
/// function call.
#[no_mangle]
extern "C" fn sample_tick_trampoline(
    _frame_ptr: *const super::idt::InterruptFrame,
    _saved_rbp: u64,
) {
    #[cfg(feature = "firefox-test-core")]
    {
        // Skip the sampler entirely while a bugcheck is in flight; the
        // interrupted state may already be garbage and we don't want to
        // multiply diagnostic output.
        if crate::ke::bugcheck::is_bugcheck_active() { return; }
        let tick = TICK_COUNT.load(Ordering::Relaxed);
        // SAFETY: see the function-level doc comment.
        let frame = unsafe { &*_frame_ptr };
        crate::proc::sample::maybe_sample(tick, frame, _saved_rbp);
    }
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
    // it must therefore advance at wall-clock rate (~TICK_HZ), independent
    // of how many CPUs are online and firing.  Letting every CPU naively
    // `+= 1` scales the apparent wall-clock by the number of online CPUs,
    // which silently breaks every CLOCK_MONOTONIC consumer (including the
    // userspace vDSO clock_gettime fast path used by glibc / NSPR / Mozilla
    // event loops).
    //
    // Mechanism: TICK_COUNT is TSC-derived.  Any CPU running this ISR
    // computes `expected = (rdtsc - tsc_at_boot) / tsc_per_tick` and
    // monotonically CAS-publishes it.  Multiple CPUs racing converge to
    // the same value; whichever wins the CAS is the sole vvar-page
    // updater for that step.
    let cpu = super::apic::cpu_index();
    let is_bsp = cpu == 0;
    if cpu < super::apic::MAX_CPUS {
        TIMER_ISR_PER_CPU[cpu].fetch_add(1, Ordering::Relaxed);
    }

    // ── Re-arm the TSC-deadline timer (one-shot per write) ──────────────────
    // In TSC-deadline mode (Intel SDM Vol. 3A §11.5.4.1) each write to
    // IA32_TSC_DEADLINE arms a single interrupt, so the ISR must program the
    // next deadline every tick.  Done here, near the top, so the cadence is
    // measured interrupt-to-interrupt (the next deadline is `rdtsc() + period`
    // from now, independent of how long the rest of this ISR takes).  No-op in
    // periodic mode.  This is what keeps every vCPU's timer alive under KVM:
    // TSC-deadline injection is reliable for the BSP vCPU, unlike the emulated
    // periodic counter that wedged (the "de-facto single core" failure mode).
    if super::apic::tsc_deadline_mode() {
        super::apic::arm_tsc_deadline_next();
    }

    // ── EOI the interrupt controller BEFORE the tick body ───────────────────
    // Acknowledge the LAPIC (clear the in-service bit for vector 32) here, right
    // after re-arming the next deadline and *before* the bookkeeping below
    // (TICK_COUNT CAS, timerfd ring, TLB grace-period, metrics,
    // timer_tick_schedule).  This is the conventional "ack the interrupt
    // controller first, run the handler body second" ordering.
    //
    // Why this collapses the in-service window: the CPU auto-sets the vISR bit
    // for vector 32 on acceptance and it is cleared only by this EOI write
    // (Intel SDM Vol. 3A §10.8.4).  While it is set, PPR is raised to class 2
    // (SDM Vol. 3A §10.8.3.1), blocking delivery of the next same-priority
    // timer.  Issuing the EOI here shrinks the in-service window from the whole
    // ISR body down to ~2 instructions.
    //
    // Re-entrancy safety: vector 32 is installed as an interrupt gate (IDT
    // type 0x8E), so RFLAGS.IF is cleared for the entire handler (SDM Vol. 3A
    // §6.12.1) and no production callee re-enables interrupts.  Per SDM Vol. 3A
    // §10.8.4, EOI only *allows* the next same-or-lower-priority interrupt to be
    // delivered; with IF=0 that delivery cannot occur until IRETQ.  So EOI-early
    // does NOT re-enter this ISR — the next timer is delivered only after IRETQ,
    // the intended periodic cadence.  This is a behavior-preserving reorder of
    // the single EOI, not an added one (the bugcheck-bail above still EOIs+
    // returns on its own path; there is no second EOI on the normal tail).
    if super::apic::is_enabled() {
        super::apic::lapic_eoi();
    } else {
        // SAFETY: Sending EOI after accepting the timer interrupt.
        unsafe {
            send_eoi(0);
        }
    }

    // INVARIANT: no `sti`/enable_interrupts between this EOI and IRETQ — the
    // early EOI removes the in-service PPR interlock (which previously blocked a
    // nested same-priority timer even with IF=1), so IF=0 is now the SOLE
    // re-entrancy guard for the tick body below.  A future timer-path helper
    // that re-enabled interrupts here would silently reintroduce ISR
    // re-entrancy; this assertion catches that in debug/test builds and
    // compiles out entirely in release (zero production cost).
    debug_assert!(
        !crate::hal::interrupts_enabled(),
        "timer_tick: interrupts must stay masked after the early EOI — IF=0 is \
         the sole re-entrancy guard once the in-service interlock is dropped"
    );

    // ── Cross-CPU dead-timer wake (SMP self-heal) ───────────────────────────
    // Our own LAPIC timer is clearly delivering (we are inside its ISR).  Poke
    // any SIBLING whose own timer ISR has gone stale — a CPU whose LAPIC
    // periodic timer wedged (KVM injection suppression) and that may have
    // halted on the assumption its timer would wake it.  Without this a healthy
    // CPU keeps the global clock alive while a wedged sibling sleeps forever,
    // carrying the whole machine alone (the SMP "de-facto single core" failure
    // mode).  Cheap and self-rate-limited (one poke per sibling per ~200 ms);
    // a uniprocessor finds no siblings and does nothing.  See
    // `poke_stale_siblings` + `timer_wake_interrupt`.
    {
        let tpt = TSC_PER_TICK.load(Ordering::Acquire);
        if tpt != 0 && cpu < super::apic::MAX_CPUS {
            poke_stale_siblings(cpu, rdtsc(), tpt);
        }
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
    let mut we_published = false;
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
                we_published = true;
                break new_tick;
            }
            Err(observed) => {
                cur = observed;
                // Loop to recheck — the new value may already exceed ours.
            }
        }
    };
    crate::perf::record_interrupt(32); // IRQ0 = vector 32

    // ── Record/replay: virtual tick advance on the publishing CPU ───
    // Only the CPU that actually CAS'd a new TICK_COUNT advances the
    // virtual counter — under SMP every other CPU's LAPIC ISR fires
    // too but loses the race, so this stays one increment per real
    // wall-clock tick rather than (cpus * ticks).  See
    // `crate::record_replay` for the deterministic-time contract.
    #[cfg(feature = "record-replay")]
    {
        if we_published {
            crate::record_replay::advance_virtual_ticks();
        }
    }

    // ── Heartbeat: emit every 500 ticks (~5s at 100 Hz) ─────────────
    // Gives the external watchdog (tools/qemu-watchdog.py) a signal that
    // the timer ISR is still firing.  Zero cost in production builds.
    //
    // Emit whenever WE were the CPU that published a tick crossing a 500
    // boundary.  This is at most one emit per boundary (the CAS guarantees
    // one publisher) regardless of which CPU is actually firing the LAPIC
    // — under KVM, the BSP's LAPIC is sometimes silent while APs deliver,
    // so a BSP-only emit would mute the heartbeat entirely.
    #[cfg(any(feature = "test-mode", feature = "firefox-test-core"))]
    {
        if we_published && tick > 0 {
            // Emit if THIS publish crossed a 500-tick boundary.
            // (cur was the previous value before we CAS'd; tick is what
            //  we published.)
            let prev_500 = cur / 500;
            let now_500  = tick / 500;
            if now_500 > prev_500 {
                crate::serial_println!("[HB] tick={} cpu={} pf={} sc={}",
                    tick, cpu,
                    crate::arch::x86_64::idt::page_fault_count(),
                    crate::syscall::syscall_count());
            }
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

    // Wake any poll/epoll/select caller watching a timerfd whose
    // scheduled expiry has just been reached.  Lockless check via
    // the earliest-expiry hint; rings the bell at most once per arm
    // cycle (the hint is bumped to u64::MAX on fire) so a quiescent
    // armed timer does not incur a tick-cost ring storm.  See
    // `crate::ipc::timerfd::maybe_ring_from_tick`.
    crate::ipc::timerfd::maybe_ring_from_tick(tick);

    // Advance TLB quarantine-free grace-period tracking.  Must be called
    // from every CPU's timer ISR so that `tlb::on_cpu_tick` can compute
    // the global minimum tick and drain entries whose quiescent state
    // has been satisfied.  This call is inexpensive when the quarantine
    // ring is empty (a single atomic load that fast-paths out).
    crate::mm::tlb::on_cpu_tick(tick);

    // W215 Arm-1 diagnostic: cheap fast-path that re-syncs this CPU's
    // DR0–DR3 + DR7 from the global publish state if another CPU armed
    // (or disarmed) a watchpoint since this CPU last looked.  Replaces
    // the prior IPI-based cross-CPU sync, which deadlocked under ISR-to-
    // ISR LAPIC contention (originator's `[W215/DR-ARM]` line never
    // emitted).  See `debug_reg.rs` module-level docs.  Fast path is two
    // atomic loads + compare; slow path is bounded by `program_local_drs`
    // (≤ 4 DR writes + 1 DR7 write).  Must run BEFORE the CRC walker so
    // a peer-CPU arm propagates before this CPU re-evaluates the cache.
    // Also required by `582-diag`: the #582 RFLAGS-slot watch is armed on
    // one CPU but must catch a cross-CPU writer, so peers must pick up the
    // DR0 arm here (the lazy-gen propagation point).
    #[cfg(any(feature = "w215-diag", feature = "582-diag"))]
    crate::arch::x86_64::debug_reg::apply_pending_if_stale();

    // Per-process activity-metrics dump.  Wait-free fast path: one
    // atomic load + a saturating subtract; only the CPU whose tick
    // crosses the boundary CAS-claims the publish slot and emits.  See
    // `crate::proc::proc_metrics::maybe_emit_periodic`.
    crate::proc::proc_metrics::maybe_emit_periodic(tick);

    // W215 Arm-1 diagnostic: walk a small slice of the page cache and
    // CRC32 each entry against the value captured at insert time.  On
    // mismatch, arm a hardware DR0 write-watchpoint via
    // `arch::x86_64::debug_reg::arm_write_watchpoint` so the offending
    // kernel write site self-identifies through `#DB`.  Per Intel SDM
    // Vol. 3B §17.2.4 (Debug Address Registers).  Diagnostic-only;
    // gated behind `w215-diag` (a superset of `firefox-test`) because
    // the walker's shadow table is a ~2 MiB BSS static that exposes a
    // latent PMM-vs-BSS reservation gap on the demo path.
    #[cfg(feature = "w215-diag")]
    crate::mm::w215_crc::crc_walk_tick(cpu as u32);

    // Notify the scheduler about the tick.
    // NOTE: the LAPIC has already been EOI'd near the top of this ISR (right
    // after the TSC-deadline re-arm), so the interrupt controller is
    // acknowledged before all of the bookkeeping above runs.  There is
    // deliberately no EOI here — a second EOI would be a spurious write.
    crate::sched::timer_tick_schedule();

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
irq_stub!(irq_virtio_serial_handler, virtio_serial_interrupt);
irq_stub!(irq_tlb_shootdown_handler, tlb_shootdown_interrupt);
irq_stub!(irq_timer_wake_handler, timer_wake_interrupt);
irq_stub!(irq_resched_handler, resched_interrupt);
#[cfg(feature = "w215-diag")]
irq_stub!(irq_w215_dr_sync_handler, w215_dr_sync_interrupt);

/// Reschedule IPI body (vector 0xF2, Perf P2 phase 3c).
///
/// A remote CPU made a thread runnable on THIS CPU and poked it via
/// `sched::resched_cpu` → `apic::send_ipi_noblock`.  The handler does the
/// minimum possible work: set this CPU's `NEED_RESCHEDULE` flag and EOI.  It
/// takes NO lock and runs NO scheduler logic in interrupt context — the actual
/// context switch happens at the next `sched::check_reschedule()` (syscall/IRQ
/// return), exactly as a timer-tick preemption does.  Because it is
/// lock-free it cannot interact with the TLB-shootdown IPI's ACK spin: there is
/// no shared lock to contend and the EOI takes no lock (it is issued whenever
/// the LAPIC is enabled, which it always is for a CPU servicing this IPI).
extern "C" fn resched_interrupt() {
    crate::sched::note_resched_ipi();
    crate::sched::set_need_reschedule_local();
    if super::apic::is_enabled() { super::apic::lapic_eoi(); }
}

/// Cross-CPU timer-wake IPI body (vector 0xF3).
///
/// Sent by a CPU whose own LAPIC timer is delivering to a SIBLING whose
/// per-CPU timer-ISR count has gone stale — i.e. a CPU whose LAPIC periodic
/// timer has wedged (KVM injection suppression; Intel SDM Vol. 3A §11.5.4 — a
/// wedged periodic counter does not spontaneously resume).  A CPU that has
/// halted (`hlt`) on the assumption its timer will wake it would otherwise
/// sleep until an unrelated asynchronous IRQ happens to land on it; under
/// single-vCPU-affine IRQ routing that is effectively never, so the CPU drops
/// out of scheduling entirely (the SMP "de-facto single core" failure mode).
///
/// The IPI itself is the cure: delivering ANY interrupt resumes the target
/// from `hlt`, after which its idle/wait path re-runs `cpu_timer_live`, detects
/// the locally-dead timer, re-arms its own LAPIC and drives a software tick.
/// This handler therefore only needs to record the poke and EOI; it also drives
/// a scheduler tick so a freshly-Ready peer is picked up immediately on the
/// woken CPU rather than waiting for the next loop iteration.
extern "C" fn timer_wake_interrupt() {
    TIMER_WAKE_IPI_RECEIVED.fetch_add(1, Ordering::Relaxed);
    crate::sched::timer_tick_schedule();
    if super::apic::is_enabled() { super::apic::lapic_eoi(); }
}

/// W215 Arm-1 DR0/DR7 sync IPI body.  Programs this CPU's DR0/DR7 from
/// the values published by `arch::x86_64::debug_reg::arm_write_watchpoint`.
/// EOIs the LAPIC.  Diagnostic-only; gated behind `w215-diag`.
#[cfg(feature = "w215-diag")]
extern "C" fn w215_dr_sync_interrupt() {
    crate::arch::x86_64::debug_reg::handle_w215_dr_sync_ipi();
}

/// Cross-CPU TLB shootdown IPI logic.
///
/// Reads this CPU's shootdown payload slot, invalidates the requested
/// range if the active CR3 matches the target, and acknowledges via
/// `pending=0`.  EOIs the LAPIC at the end.  See `mm/tlb.rs`.
extern "C" fn tlb_shootdown_interrupt() {
    crate::mm::tlb::handle_shootdown_ipi();
}

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

/// Virtio-serial PCI INTx interrupt logic.  Same contract as virtio-blk —
/// ack via ISR_STATUS read, walk used ring for received bytes, deposit
/// into the driver's rx ring buffer, wake any thread parked in
/// `read_blocking()`, then LAPIC EOI.  The driver implements the entire
/// sequence; this stub exists purely to route the IDT vector.
extern "C" fn virtio_serial_interrupt() {
    // The virtio_serial driver module is only compiled with `--features qga`;
    // when absent, IDT[46] is still wired (idt.rs) so the stub stays present,
    // but it must not reference the missing module.  No-op in that build —
    // QEMU only fires this vector when a virtio-serial device is exposed,
    // which is itself gated by the host launching with `-device virtio-serial`
    // (QGA feature only).
    #[cfg(feature = "qga")]
    {
        crate::perf::record_interrupt(crate::drivers::virtio_serial::VIRTIO_SERIAL_IRQ_VECTOR);
        crate::drivers::virtio_serial::handle_irq();
    }
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
