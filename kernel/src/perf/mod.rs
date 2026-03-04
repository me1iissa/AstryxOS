//! Performance Metrics Subsystem
//!
//! Provides kernel-wide performance counters and monitoring.
//! Inspired by the Windows NT Performance Monitor (perfmon) and
//! Linux /proc/stat style instrumentation.
//!
//! # Tracked Metrics
//! - **Interrupts**: Per-vector counts (timer, keyboard, etc.)
//! - **Syscalls**: Per-call counters and total
//! - **Scheduler**: Context switches, idle ticks, run ticks
//! - **Memory**: Heap allocs/frees, page faults, peak usage
//! - **Network**: (delegates to net::stats for packets/bytes)
//! - **Uptime**: Precise tick-based uptime with breakdown

use core::sync::atomic::{AtomicU64, Ordering};

// ── Interrupt Counters ──────────────────────────────────────────────────────

/// Per-vector interrupt counters (vectors 0-255, but we mostly care about 32+).
static IRQ_COUNTS: [AtomicU64; 256] = {
    // const initializer for array of AtomicU64
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 256]
};

/// Record an interrupt on the given vector.
#[inline]
pub fn record_interrupt(vector: u8) {
    IRQ_COUNTS[vector as usize].fetch_add(1, Ordering::Relaxed);
}

/// Get the count for a specific interrupt vector.
pub fn interrupt_count(vector: u8) -> u64 {
    IRQ_COUNTS[vector as usize].load(Ordering::Relaxed)
}

/// Get total interrupt count across all vectors.
pub fn total_interrupts() -> u64 {
    let mut total = 0u64;
    for i in 0..256 {
        total += IRQ_COUNTS[i].load(Ordering::Relaxed);
    }
    total
}

// ── Syscall Counters ────────────────────────────────────────────────────────

/// Number of distinct syscall numbers we track (0..=15).
const MAX_SYSCALL_NR: usize = 16;

static SYSCALL_COUNTS: [AtomicU64; MAX_SYSCALL_NR] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; MAX_SYSCALL_NR]
};

static SYSCALL_TOTAL: AtomicU64 = AtomicU64::new(0);
static SYSCALL_UNKNOWN: AtomicU64 = AtomicU64::new(0);

/// Record a syscall invocation.
#[inline]
pub fn record_syscall(nr: u64) {
    SYSCALL_TOTAL.fetch_add(1, Ordering::Relaxed);
    if (nr as usize) < MAX_SYSCALL_NR {
        SYSCALL_COUNTS[nr as usize].fetch_add(1, Ordering::Relaxed);
    } else {
        SYSCALL_UNKNOWN.fetch_add(1, Ordering::Relaxed);
    }
}

/// Get count for a specific syscall number.
pub fn syscall_count(nr: u64) -> u64 {
    if (nr as usize) < MAX_SYSCALL_NR {
        SYSCALL_COUNTS[nr as usize].load(Ordering::Relaxed)
    } else {
        0
    }
}

/// Get total syscall count.
pub fn total_syscalls() -> u64 {
    SYSCALL_TOTAL.load(Ordering::Relaxed)
}

/// Get unknown syscall count.
pub fn unknown_syscalls() -> u64 {
    SYSCALL_UNKNOWN.load(Ordering::Relaxed)
}

// ── Scheduler Counters ──────────────────────────────────────────────────────

static CONTEXT_SWITCHES: AtomicU64 = AtomicU64::new(0);
static IDLE_TICKS: AtomicU64 = AtomicU64::new(0);

/// Record a context switch.
#[inline]
pub fn record_context_switch() {
    CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
}

/// Record an idle tick (CPU halted, no work).
#[inline]
pub fn record_idle_tick() {
    IDLE_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Get context switch count.
pub fn context_switches() -> u64 {
    CONTEXT_SWITCHES.load(Ordering::Relaxed)
}

/// Get idle tick count.
pub fn idle_ticks() -> u64 {
    IDLE_TICKS.load(Ordering::Relaxed)
}

// ── Memory Counters ─────────────────────────────────────────────────────────

static HEAP_ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static HEAP_FREE_COUNT: AtomicU64 = AtomicU64::new(0);
static HEAP_ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static HEAP_FREE_BYTES: AtomicU64 = AtomicU64::new(0);
static HEAP_PEAK_BYTES: AtomicU64 = AtomicU64::new(0);
static HEAP_CURRENT_BYTES: AtomicU64 = AtomicU64::new(0);
static PAGE_FAULTS: AtomicU64 = AtomicU64::new(0);

/// Record a heap allocation.
#[inline]
pub fn record_heap_alloc(bytes: usize) {
    HEAP_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    HEAP_ALLOC_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    let current = HEAP_CURRENT_BYTES.fetch_add(bytes as u64, Ordering::Relaxed) + bytes as u64;
    // Update peak — simple compare-and-swap loop
    let mut peak = HEAP_PEAK_BYTES.load(Ordering::Relaxed);
    while current > peak {
        match HEAP_PEAK_BYTES.compare_exchange_weak(peak, current, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => peak = actual,
        }
    }
}

/// Record a heap deallocation.
#[inline]
pub fn record_heap_free(bytes: usize) {
    HEAP_FREE_COUNT.fetch_add(1, Ordering::Relaxed);
    HEAP_FREE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    HEAP_CURRENT_BYTES.fetch_sub(bytes as u64, Ordering::Relaxed);
}

/// Record a page fault.
#[inline]
pub fn record_page_fault() {
    PAGE_FAULTS.fetch_add(1, Ordering::Relaxed);
}

/// Get heap allocation statistics.
pub fn heap_alloc_stats() -> (u64, u64, u64, u64, u64, u64) {
    (
        HEAP_ALLOC_COUNT.load(Ordering::Relaxed),
        HEAP_FREE_COUNT.load(Ordering::Relaxed),
        HEAP_ALLOC_BYTES.load(Ordering::Relaxed),
        HEAP_FREE_BYTES.load(Ordering::Relaxed),
        HEAP_CURRENT_BYTES.load(Ordering::Relaxed),
        HEAP_PEAK_BYTES.load(Ordering::Relaxed),
    )
}

/// Get page fault count.
pub fn page_faults() -> u64 {
    PAGE_FAULTS.load(Ordering::Relaxed)
}

// ── Snapshot / Summary ──────────────────────────────────────────────────────

/// A snapshot of all performance metrics at a point in time.
pub struct PerfSnapshot {
    pub uptime_ticks: u64,
    pub uptime_seconds: u64,
    pub total_interrupts: u64,
    pub timer_interrupts: u64,
    pub keyboard_interrupts: u64,
    pub total_syscalls: u64,
    pub unknown_syscalls: u64,
    pub context_switches: u64,
    pub idle_ticks: u64,
    pub cpu_idle_pct: u64,
    pub heap_allocs: u64,
    pub heap_frees: u64,
    pub heap_alloc_bytes: u64,
    pub heap_free_bytes: u64,
    pub heap_current_bytes: u64,
    pub heap_peak_bytes: u64,
    pub page_faults: u64,
    pub net_rx_packets: u64,
    pub net_tx_packets: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

/// Take a snapshot of all performance metrics.
pub fn snapshot() -> PerfSnapshot {
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let (net_rx_packets, net_tx_packets, net_rx_bytes, net_tx_bytes) = crate::net::stats();
    let idle = idle_ticks();

    let cpu_idle_pct = if ticks > 0 {
        (idle * 100) / ticks
    } else {
        0
    };

    let (allocs, frees, alloc_bytes, free_bytes, current_bytes, peak_bytes) = heap_alloc_stats();

    PerfSnapshot {
        uptime_ticks: ticks,
        uptime_seconds: ticks / 100, // 100 Hz timer
        total_interrupts: total_interrupts(),
        timer_interrupts: interrupt_count(32),  // IRQ0 = vector 32
        keyboard_interrupts: interrupt_count(33), // IRQ1 = vector 33
        total_syscalls: total_syscalls(),
        unknown_syscalls: unknown_syscalls(),
        context_switches: context_switches(),
        idle_ticks: idle,
        cpu_idle_pct,
        heap_allocs: allocs,
        heap_frees: frees,
        heap_alloc_bytes: alloc_bytes,
        heap_free_bytes: free_bytes,
        heap_current_bytes: current_bytes,
        heap_peak_bytes: peak_bytes,
        page_faults: page_faults(),
        net_rx_packets,
        net_tx_packets,
        net_rx_bytes,
        net_tx_bytes,
    }
}

/// Syscall name lookup for display purposes.
pub fn syscall_name(nr: u64) -> &'static str {
    match nr {
        0 => "exit",
        1 => "write",
        2 => "read",
        3 => "open",
        4 => "close",
        5 => "getpid",
        6 => "yield",
        7 => "fork",
        8 => "exec",
        9 => "waitpid",
        _ => "unknown",
    }
}
