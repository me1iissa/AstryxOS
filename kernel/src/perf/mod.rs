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

// ── Syscall trend ring (kdb-only) ───────────────────────────────────────────
//
// Fixed-capacity, single-producer-multiple-consumer ring of recent syscall
// events.  Each entry packs (tick: 32 bits | pid: 16 bits | nr: 16 bits) into
// a single u64 so insertion is a wait-free `fetch_add` on the head plus one
// relaxed store — no locks, no allocation, safe to call from any context
// (including the timer ISR's record_interrupt path).
//
// At 100 Hz the 32-bit tick wraps after ~497 days, far longer than any test
// run — wraparound handling in the consumer is therefore unnecessary.
//
// Capacity is sized to live comfortably in kernel BSS without crowding out
// the heap: 128 KiB of ring buffer (16384 entries × 8 B).  Under a busy
// Firefox process (~120k syscalls/sec) this is ~140 ms of history; under
// typical test workloads (≪ 10k syscalls/sec) it covers several seconds,
// which is the expected use case for `kdb syscall-trend`.  Increasing the
// ring further blew out the kernel BSS budget and triggered an early
// allocator panic during driver init — that boundary is empirical.

#[cfg(feature = "kdb")]
const SYSCALL_RING_CAP: usize = 1 << 14; // 16384 entries × 8 B = 128 KiB

#[cfg(feature = "kdb")]
static SYSCALL_RING: [AtomicU64; SYSCALL_RING_CAP] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; SYSCALL_RING_CAP]
};

#[cfg(feature = "kdb")]
static SYSCALL_RING_HEAD: AtomicU64 = AtomicU64::new(0);

/// Push a (pid, nr) syscall event into the kdb trend ring.
///
/// The current tick is read by the producer rather than by the caller so
/// that callers don't carry the dependency on `arch::x86_64::irq` and so
/// the timestamp reflects the actual emission time, not the dispatch entry.
#[cfg(feature = "kdb")]
#[inline]
pub fn record_syscall_event(pid: u64, nr: u64) {
    let tick = crate::arch::x86_64::irq::get_ticks();
    let packed = ((tick as u64 & 0xFFFF_FFFF) << 32)
        | ((pid & 0xFFFF) << 16)
        | (nr & 0xFFFF);
    let idx = SYSCALL_RING_HEAD.fetch_add(1, Ordering::Relaxed) as usize
        & (SYSCALL_RING_CAP - 1);
    SYSCALL_RING[idx].store(packed, Ordering::Relaxed);
}

/// Snapshot of one syscall ring entry.
#[cfg(feature = "kdb")]
#[derive(Clone, Copy)]
pub struct SyscallEvent {
    pub tick: u32,
    pub pid: u16,
    pub nr: u16,
}

/// Walk the syscall trend ring, calling `f` for every entry whose tick is
/// within `[since_tick, now_tick]` (inclusive).  Optionally filter by pid;
/// `pid_filter == 0` means all pids.
///
/// Lock-free: races with concurrent producers are tolerated — the worst
/// case is missing a write that lands in a slot already visited, or seeing
/// a torn entry that fails the tick-window test.  Both are acceptable for
/// a "what was this process doing" diagnostic.
#[cfg(feature = "kdb")]
pub fn syscall_ring_walk(since_tick: u64, pid_filter: u64, mut f: impl FnMut(SyscallEvent)) {
    // Read the head once, then walk the most recent SYSCALL_RING_CAP entries
    // backwards.  Stop at the first entry older than `since_tick`.
    let head = SYSCALL_RING_HEAD.load(Ordering::Relaxed);
    let count = head.min(SYSCALL_RING_CAP as u64);
    for i in 0..count {
        let raw_idx = head.wrapping_sub(1).wrapping_sub(i) as usize
            & (SYSCALL_RING_CAP - 1);
        let v = SYSCALL_RING[raw_idx].load(Ordering::Relaxed);
        if v == 0 { continue; } // never-written slot
        let ev = SyscallEvent {
            tick: (v >> 32) as u32,
            pid:  ((v >> 16) & 0xFFFF) as u16,
            nr:   (v & 0xFFFF) as u16,
        };
        if (ev.tick as u64) < since_tick { break; }
        if pid_filter != 0 && (ev.pid as u64) != pid_filter { continue; }
        f(ev);
    }
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

/// Syscall name lookup for display purposes (native Aether ABI).
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

/// Linux x86_64 syscall name lookup for display purposes.
///
/// Covers the syscalls observed during typical Firefox / glibc dispatch.
/// Returns "unknown" for numbers we have not catalogued — the caller can
/// fall back to printing the raw number.  Only the names matter; the kernel
/// still routes by number, so missing entries here are a documentation gap,
/// not a correctness concern.  Numbers per the public Linux kernel
/// `arch/x86/entry/syscalls/syscall_64.tbl` ABI.
pub fn linux_syscall_name(nr: u64) -> &'static str {
    match nr {
        0   => "read",
        1   => "write",
        2   => "open",
        3   => "close",
        4   => "stat",
        5   => "fstat",
        6   => "lstat",
        7   => "poll",
        8   => "lseek",
        9   => "mmap",
        10  => "mprotect",
        11  => "munmap",
        12  => "brk",
        13  => "rt_sigaction",
        14  => "rt_sigprocmask",
        16  => "ioctl",
        17  => "pread64",
        18  => "pwrite64",
        19  => "readv",
        20  => "writev",
        21  => "access",
        22  => "pipe",
        23  => "select",
        24  => "sched_yield",
        25  => "mremap",
        28  => "madvise",
        32  => "dup",
        33  => "dup2",
        35  => "nanosleep",
        39  => "getpid",
        41  => "socket",
        42  => "connect",
        43  => "accept",
        44  => "sendto",
        45  => "recvfrom",
        46  => "sendmsg",
        47  => "recvmsg",
        48  => "shutdown",
        49  => "bind",
        50  => "listen",
        56  => "clone",
        57  => "fork",
        58  => "vfork",
        59  => "execve",
        60  => "exit",
        61  => "wait4",
        62  => "kill",
        63  => "uname",
        72  => "fcntl",
        78  => "getdents",
        79  => "getcwd",
        80  => "chdir",
        83  => "mkdir",
        87  => "unlink",
        89  => "readlink",
        96  => "gettimeofday",
        97  => "getrlimit",
        102 => "getuid",
        104 => "getgid",
        107 => "geteuid",
        108 => "getegid",
        110 => "getppid",
        158 => "arch_prctl",
        186 => "gettid",
        202 => "futex",
        217 => "getdents64",
        218 => "set_tid_address",
        228 => "clock_gettime",
        230 => "clock_nanosleep",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        257 => "openat",
        262 => "newfstatat",
        263 => "unlinkat",
        270 => "pselect6",
        271 => "ppoll",
        272 => "unshare",
        273 => "set_robust_list",
        274 => "get_robust_list",
        281 => "epoll_pwait",
        288 => "accept4",
        291 => "epoll_create1",
        292 => "dup3",
        293 => "pipe2",
        302 => "prlimit64",
        318 => "getrandom",
        319 => "memfd_create",
        332 => "statx",
        435 => "clone3",
        439 => "faccessat2",
        449 => "futex_waitv",
        _   => "unknown",
    }
}
