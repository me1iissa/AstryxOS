//! Serial Port Driver (COM1)
//!
//! Provides debug output via the serial port (UART 16550A).
//! QEMU maps this to the host terminal, making it invaluable for debugging.
//!
//! # IRQ-window design
//!
//! The naïve approach holds interrupts off for the entire duration of a
//! `serial_println!` call.  At 115200 baud with no FIFO each byte takes
//! ~87 µs to shift out, so a modest 64-byte message adds a ~5.5 ms
//! blind window to every CPU that calls `serial_println!` — degrading
//! scheduler responsiveness and inflating interrupt latency.
//!
//! The previous iteration tried to fix this with a **per-byte** cli/sti
//! window.  Under KVM that pattern is pathological: every `cli`/`outb`/
//! `sti` triple traps to the hypervisor (VM-exit on cli, port I/O exit
//! on outb, VM-exit on sti), so a single 256-byte serial line consumes
//! ~768 VM-exits — orders of magnitude more wall time than the IRQ
//! latency we were trying to preserve.  Profiling under
//! `firefox-test,syscall-trace` showed 81–87 % of CPU 2 pinned in
//! `WriteAdapter::write_str` across three QEMU CPU models.
//!
//! The current design is two-pronged (NS16550A datasheet §8, OSDev Wiki
//! "Serial Ports"):
//!
//! 1. **16550A FIFO enabled at init** (FCR = 0xC7: FIFO_EN + both-reset +
//!    14-byte RX trigger).  The 16-byte TX FIFO accepts a burst of up to
//!    16 bytes in one polling round-trip; the chip then clocks them out
//!    independently while the CPU is unblocked.
//!
//! 2. **Chunked cli/sti in `_serial_print`** — interrupts are disabled
//!    once per 16-byte FIFO chunk, the LSR.THRE bit is polled exactly
//!    once per chunk (with a bounded spin so a wedged UART cannot hang
//!    the kernel), all 16 bytes are written to THR back-to-back, then
//!    the caller's RFLAGS.IF is restored.  Compared to the per-byte
//!    design this reduces VM-exits and cli/sti traps by ~16× while
//!    keeping the IRQ-off window bounded: at 115200 baud, 16 bytes
//!    take ~1.4 ms to physically shift out, but the FIFO write itself
//!    completes in a handful of port-I/O cycles (~µs scale), so the
//!    cli window per chunk is well under 100 µs in practice.
//!
//! # Reentrancy / SMP safety
//!
//! Two layered guards keep `_serial_print` safe under SMP + nested IRQs:
//!
//! 1. The `SERIAL` `spin::Mutex` prevents concurrent FIFO writers from
//!    two CPUs interleaving bytes.
//!
//! 2. The `PER_CPU_IN_SERIAL` atomic-flag array catches same-CPU
//!    re-entry.  Per-chunk cli bounds the IRQ-off window but the window
//!    re-opens between chunks, so the local timer ISR can fire on a CPU
//!    that already holds `SERIAL`.  If that ISR emits a
//!    `serial_println!` (e.g. the `[HB]` heartbeat), `_serial_print`
//!    detects the per-CPU flag is already set and drops the re-entrant
//!    line rather than spinning on a non-reentrant `spin::Mutex` it
//!    already owns.
//!
//! Together: one writer per CPU at a time, no same-CPU self-deadlock,
//! bounded IRQ blackout per chunk.  The trade-off is that re-entrant
//! diagnostic lines are dropped; emergency output never goes through
//! this path (see "Bugcheck / panic path" below).
//!
//! The 16550A FIFO is safe under SMP because only the one CPU holding the
//! `SERIAL` mutex ever writes to the UART at a time — no concurrent writers
//! race on the FIFO.
//!
//! # Bugcheck / panic path
//!
//! `ke::bugcheck` DOES NOT use this module.  It bypasses the `SERIAL`
//! mutex entirely via `util::no_alloc_fmt::bugcheck_serial_write_bytes`,
//! which polls LSR directly and never allocates.  That path is unchanged
//! by this module — see `kernel/src/ke/bugcheck.rs` and
//! `kernel/src/util/no_alloc_fmt.rs`.

use crate::hal;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// COM1 base I/O port.
///
/// `pub` so the fault-immune bugcheck path in
/// [`crate::util::no_alloc_fmt`] can reference the same constant — there
/// must be exactly one source of truth for the UART base address, or the
/// two paths can drift and one of them ends up talking to a different
/// (or no) device.  This is a plain compile-time `u16` literal: it has
/// no initialiser, no allocator dependency, and no `Mutex`-protected
/// state, so re-exporting it does not compromise the fault-immunity
/// contract documented in `kernel/src/ke/bugcheck.rs`.
pub const COM1: u16 = 0x3F8;

/// LSR register offset from base.
const LSR: u16 = 5;

/// LSR.THRE — transmit holding register empty; safe to write next byte to THR.
const LSR_THRE: u8 = 0x20;

/// LSR.TEMT — transmitter entirely empty (THR + shift register drained).
/// Used by `stop()` to wait for the last byte to physically leave the UART.
const LSR_TEMT: u8 = 0x40;

/// FCR value that enables the NS16550A 16-byte TX/RX FIFOs.
///
/// Bit layout (OSDev Wiki "Serial Ports", NS16550A datasheet §8):
///   bit 0    = FIFO_EN:  enable both TX and RX FIFOs
///   bit 1    = RCVR_RST: reset RX FIFO (clears stale bytes on init)
///   bit 2    = XMIT_RST: reset TX FIFO
///   bits 6-7 = ITL=0b11: RX interrupt trigger at 14 bytes (FIFO nearly full)
///
/// Setting ITL=14 matches the widely-used default for 16-byte FIFOs and
/// gives the CPU ample time to drain the FIFO before a stall.
/// Reference: OSDev Wiki "Serial Ports" — https://wiki.osdev.org/Serial_Ports
const FCR_FIFO_ENABLE: u8 = 0xC7;

/// Maximum spins waiting for THRE before giving up rather than hanging.
const THRE_SPIN_LIMIT: u32 = 100_000;

/// Depth of the NS16550A TX FIFO in bytes.  When LSR.THRE is set we may push
/// up to this many bytes back-to-back before re-polling.  Larger chunks
/// reduce per-byte VM-exit overhead under KVM at the cost of a slightly
/// longer cli window per chunk.  The 16550A datasheet §8 fixes this at 16.
const FIFO_DEPTH: usize = 16;

/// Global serial port instance.
static SERIAL: Mutex<SerialPort> = Mutex::new(SerialPort { base: COM1 });

/// Per-CPU "currently inside `_serial_print`" flag.
///
/// `spin::Mutex` is not reentrant.  PR #143's chunked design re-opens the
/// IRQ window between 16-byte FIFO chunks (cli → outb × N → restore IF →
/// cli for next chunk), so the local timer ISR can fire on the *same*
/// CPU while we still hold `SERIAL`.  If that ISR's handler emits a
/// `serial_println!` (e.g. the `[HB]` heartbeat), it would re-enter
/// `_serial_print` and spin forever trying to acquire a mutex the CPU
/// already owns.
///
/// The slot is indexed by `apic::cpu_index()` (lockless: read of
/// `IA32_TSC_AUX` via `rdmsr` — Intel SDM Vol 3 §10.4 / §17.17).  On
/// entry to `_serial_print` (after `cli`) we atomic-swap our slot to
/// `true`; if the prior value was already `true`, this is a same-CPU
/// re-entry from an ISR.  We route the message to
/// `write_fallback_direct`, which formats it into a stack buffer and
/// writes the bytes directly to the COM1 THR with a bounded-spin LSR
/// poll, bypassing the SERIAL mutex (Intel SDM Vol 3 §6.6 — interrupt
/// handlers must avoid blocking on resources held by interrupted code;
/// here we take the lock-free direct path instead).  Byte ordering
/// inside the inner line is preserved; cross-writer interleave with
/// the outer caller's chunk bursts is possible at FIFO_DEPTH boundaries
/// but is purely cosmetic.
///
/// The fault-immune bugcheck path (PR #127) does NOT use `_serial_print`
/// and is unaffected by this guard — it routes through
/// `util::no_alloc_fmt::bugcheck_serial_write_bytes`, which bypasses
/// `SERIAL` entirely.  So emergency panic output is never dropped by
/// this mechanism.
static PER_CPU_IN_SERIAL: [AtomicBool; crate::arch::x86_64::apic::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::apic::MAX_CPUS];

/// UART 16550 serial port driver.
pub struct SerialPort {
    base: u16,
}

impl SerialPort {
    /// Initialize the serial port.
    ///
    /// Enables the NS16550A TX/RX FIFO (FCR = 0xC7).  This is called once from
    /// `kernel_main` before SMP bring-up, so no concurrent writers exist yet.
    /// After init, normal-path writers always hold the `SERIAL` mutex, which
    /// prevents any concurrent CPU from touching the FIFO.
    fn init(&self) {
        // SAFETY: Standard NS16550A initialization sequence.  All port
        // addresses are in the reserved 0x3F8–0x3FF COM1 range on x86.
        unsafe {
            hal::outb(self.base + 1, 0x00);         // IER: disable all UART interrupts
            hal::outb(self.base + 3, 0x80);         // LCR: enable DLAB to program baud divisor
            hal::outb(self.base + 0, 0x01);         // DLL: divisor low  → 115200 baud
            hal::outb(self.base + 1, 0x00);         // DLH: divisor high → 115200 baud
            hal::outb(self.base + 3, 0x03);         // LCR: 8-N-1, clear DLAB
            hal::outb(self.base + 2, FCR_FIFO_ENABLE); // FCR: enable 16-byte TX/RX FIFO
            hal::outb(self.base + 4, 0x0B);         // MCR: OUT2 + RTS + DTR
        }
    }

    /// Write a single byte, polling LSR.THRE with a bounded spin.
    ///
    /// With the 16-byte TX FIFO enabled (FCR_FIFO_ENABLE), THRE is set as
    /// long as the FIFO has room (up to 16 bytes queued), so this almost
    /// always exits on the first LSR read.  The bounded spin prevents an
    /// infinite hang if the UART is wedged.
    #[inline]
    fn write_byte(&self, byte: u8) {
        // SAFETY: Port I/O on the COM1 (0x3F8–0x3FF) range.  Spin is bounded.
        unsafe {
            let mut n = 0u32;
            while hal::inb(self.base + LSR) & LSR_THRE == 0 {
                core::hint::spin_loop();
                n += 1;
                if n >= THRE_SPIN_LIMIT {
                    break; // Drop byte rather than hang forever
                }
            }
            hal::outb(self.base, byte);
        }
    }

    /// Push up to `FIFO_DEPTH` bytes into the TX FIFO with a single LSR poll.
    ///
    /// The caller must guarantee `bytes.len() <= FIFO_DEPTH` (the 16550A
    /// TX FIFO depth).  We poll LSR.THRE once: when set, the FIFO is empty,
    /// so all `bytes.len()` bytes fit without overrun.  The bounded spin
    /// drops the chunk rather than hanging if the UART is wedged.
    ///
    /// Under KVM this collapses what was ~3 VM-exits per byte (cli, outb,
    /// sti) into ~3 VM-exits per chunk (one LSR read, one cli/sti pair
    /// owned by the caller, and a burst of port-I/O exits that the
    /// hypervisor can coalesce into a tight outb sequence).  Net cost is
    /// ~one LSR read + N outb's per chunk instead of N × (LSR + outb).
    #[inline]
    fn write_chunk(&self, bytes: &[u8]) {
        debug_assert!(bytes.len() <= FIFO_DEPTH);
        // SAFETY: Port I/O on the COM1 (0x3F8–0x3FF) range.  Spin is
        // bounded.  Burst writes are safe because we polled THRE just
        // above and chunk size ≤ FIFO_DEPTH ≤ TX-FIFO capacity.
        unsafe {
            let mut n = 0u32;
            while hal::inb(self.base + LSR) & LSR_THRE == 0 {
                core::hint::spin_loop();
                n += 1;
                if n >= THRE_SPIN_LIMIT {
                    return; // UART wedged — drop the chunk rather than hang
                }
            }
            for &b in bytes {
                hal::outb(self.base, b);
            }
        }
    }

    /// Read a byte from the serial port (blocking).
    pub fn read_byte(&self) -> u8 {
        // SAFETY: Reading from the UART data register after DR is set in LSR.
        unsafe {
            while hal::inb(self.base + LSR) & 0x01 == 0 {
                core::hint::spin_loop();
            }
            hal::inb(self.base)
        }
    }

    /// Check if data is available to read.
    pub fn has_data(&self) -> bool {
        // SAFETY: LSR read is side-effect-free.
        unsafe { hal::inb(self.base + LSR) & 0x01 != 0 }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Initialize the serial port driver.
pub fn init() {
    SERIAL.lock().init();
    crate::serial_println!("[SERIAL] COM1 initialized at 115200 baud (16550A FIFO enabled)");
}

/// Try to read a byte from the serial port (non-blocking).
/// Returns `Some(byte)` if data is available, `None` otherwise.
pub fn try_read_byte() -> Option<u8> {
    let port = SERIAL.lock();
    if port.has_data() {
        Some(port.read_byte())
    } else {
        None
    }
}

/// Wait for the transmitter to fully drain, then release the port.
///
/// With the 16-byte TX FIFO enabled, THRE going high means the FIFO
/// accepted the write but the shift register may still be clocking.
/// We poll LSR.TEMT (transmitter entirely empty: THR + shift register)
/// so the last byte physically leaves the UART before the machine halts.
/// The same bounded-spin logic prevents an infinite hang if the UART
/// is wedged.
pub fn stop() {
    crate::serial_println!("[SERIAL] stop: flushing TX...");
    let port = SERIAL.lock();
    // SAFETY: LSR read is side-effect-free.
    unsafe {
        let mut n = 0u32;
        while crate::hal::inb(port.base + LSR) & LSR_TEMT == 0 {
            core::hint::spin_loop();
            n += 1;
            if n >= 100_000 { break; }
        }
    }
    // We intentionally do NOT print after this point — the caller
    // (po::shutdown) has already emitted a "stopping" banner before
    // invoking us.
}

/// Print to serial port (used by `serial_print!` macro).
///
/// # IRQ-window discipline
///
/// We snapshot RFLAGS.IF once on entry and restore it between FIFO chunks.
/// Each chunk is at most `FIFO_DEPTH` (16) bytes; the critical section per
/// chunk is:
///
///   cli → LSR.THRE poll (bounded spin) → outb × N (N ≤ 16) → restore IF
///
/// At 115200 baud with the 16-byte TX FIFO enabled, THRE is set whenever
/// the FIFO has room.  With the FIFO drained by the chip in the background,
/// successive chunks of a long string typically find THRE set on the first
/// LSR read.  Per-chunk cost on a KVM host is roughly one LSR read + N
/// outb's = ~17 port-I/O cycles, instead of the old per-byte design's
/// ~2 × N port-I/O cycles + 2 × N VM-exits for cli/sti.
///
/// Between chunks IF is restored, allowing the timer ISR, IPI delivery,
/// and LAPIC interrupts to fire at normal cadence.  The worst-case cli
/// window is bounded by the time to push 16 bytes back-to-back to the
/// THR (~µs scale on real hardware, ~16 port-I/O exits under KVM) plus
/// at most one LSR-poll busy-wait of `THRE_SPIN_LIMIT` iterations — the
/// same bound the original per-byte path used.
///
/// # Why cli at all?
///
/// The `SERIAL` `spin::Mutex` serialises concurrent CPUs.  Per-chunk cli
/// bounds the worst-case IRQ-off window during a long write — but it
/// does NOT prevent same-CPU re-entry, because the IRQ window re-opens
/// between chunks.  A timer ISR firing in that window and emitting a
/// `serial_println!` would re-enter and spin on the non-reentrant
/// `spin::Mutex` we already hold.  That case is handled by the
/// `PER_CPU_IN_SERIAL` guard installed at the top of this function:
/// re-entry on the same CPU is detected via an atomic swap and the
/// re-entrant line is dropped rather than deadlocking (Intel SDM Vol 3
/// §6.6 — interrupt handlers must not block on resources held by
/// interrupted code).
///
/// # Bugcheck path
///
/// `ke::bugcheck` never calls this function.  It bypasses `SERIAL`
/// entirely via `util::no_alloc_fmt::bugcheck_serial_write_bytes`, so
/// the recursion guard never drops emergency output.
#[doc(hidden)]
pub fn _serial_print(args: fmt::Arguments) {
    use fmt::Write;

    // Snapshot RFLAGS.IF once; restore it between chunks.
    // SAFETY: pushfq/pop is a pure register read with no memory side effects.
    let rflags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq; pop {rflags}",
            rflags = out(reg) rflags,
            options(nomem, nostack),
        );
    }
    let if_was_set = rflags & (1 << 9) != 0;

    // Disable IRQs before acquiring the mutex so that the timer ISR cannot
    // fire in the tiny window between "lock succeeded" and "first chunk
    // committed".  The IRQ window is re-opened per-chunk below.
    crate::hal::disable_interrupts();

    // Per-CPU re-entry guard.  IRQs are off here, so the read-modify-write
    // on our slot cannot race with another handler on the same CPU; the
    // atomic-swap is paranoia against the compiler reordering loads through
    // the cli (modelled as a side-effecting asm, but Acquire/Release matches
    // the discipline used by `PER_CPU_CURRENT_PID` in `proc/mod.rs`).
    //
    // The CPU index source is `apic::cpu_index()` — a lockless read of
    // IA32_TSC_AUX (Intel SDM Vol 3 §17.17), which holds the APIC ID written
    // at per-CPU init.  Before that init runs the slot is harmless: the
    // BSP returns index 0 deterministically and is the only CPU emitting.
    let cpu = crate::arch::x86_64::apic::cpu_index();
    if PER_CPU_IN_SERIAL[cpu].swap(true, Ordering::Acquire) {
        // Same-CPU re-entry detected (we hold SERIAL on this CPU; an ISR
        // fired in the inter-chunk IRQ window and ended up here).  The
        // re-entrant `spin::Mutex::lock()` would self-deadlock.  We MUST
        // NOT take the mutex — but we still want the diagnostic line to
        // reach the log: dropping it caused the W215 DR-arm diagnostic
        // to look silent for many trials (the post-hoc
        // `[W215/DR-ARM]` `serial_println!` from inside the timer ISR's
        // CRC walker fires while the BSP is mid-`_serial_print` from a
        // VFS-resolve trace, the guard rejects it, and the only sign of
        // the arm is `ARM_COUNT` advancing — not enough to identify
        // the writer).
        //
        // The fallback: format the args into a small stack buffer and
        // push the bytes DIRECTLY to the UART FIFO with a bounded-spin
        // LSR poll, **bypassing the SERIAL mutex**.  The outer caller is
        // mid-formatting and only writes to the FIFO in 16-byte chunks
        // between cli/sti pairs, so the two writers may interleave at
        // FIFO_DEPTH-byte boundaries — a cosmetic visual interleave in
        // the log but the inner line WILL appear, with all its bytes
        // intact (the NS16550A TX FIFO sequences port-I/O writes; per
        // datasheet §8 there is no data-race on outb to the THR).
        //
        // SAFETY of bypassing the mutex: SERIAL serialises chunk-burst
        // writers to keep multi-byte messages from cross-CPU interleave
        // *across whole lines*.  Within a single CPU, the OUTER writer
        // is in a non-IRQ path (otherwise the per-CPU guard would have
        // been set by it) and the INNER writer (here) is in an ISR or
        // bugcheck-adjacent path.  An interleaved line is strictly
        // better than a silently dropped line for any diagnostic use.
        //
        // We do NOT clear PER_CPU_IN_SERIAL[cpu] here — the OUTER
        // caller still owns it.  We restore IF and return.
        write_fallback_direct(args);
        if if_was_set {
            crate::hal::enable_interrupts();
        }
        return;
    }
    let mut port = SERIAL.lock();

    // WriteAdapter wraps SerialPort and implements a chunked IRQ-window
    // pattern: gather up to FIFO_DEPTH (16) bytes into a stack buffer,
    // expanding '\n' to "\r\n" inline, then push the buffer to the FIFO
    // under a single cli/sti.  The mutex is held for the full write,
    // preventing byte interleaving across CPUs.
    struct WriteAdapter<'a> {
        port: &'a mut SerialPort,
        if_was_set: bool,
    }

    impl<'a> WriteAdapter<'a> {
        /// Commit a fully-populated chunk: one cli/sti pair owns one LSR
        /// poll plus `chunk.len()` THR writes.
        #[inline]
        fn flush_chunk(&mut self, chunk: &[u8]) {
            if chunk.is_empty() {
                return;
            }
            crate::hal::disable_interrupts();
            self.port.write_chunk(chunk);
            // SAFETY: restoring IF to exactly what the caller had on entry.
            if self.if_was_set {
                crate::hal::enable_interrupts();
            }
        }
    }

    impl<'a> fmt::Write for WriteAdapter<'a> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            // Tee every line that reaches COM1 into the kernel log ring so
            // that userspace `syslog(2)`/`klogctl` and `/proc/kmsg` can read
            // the boot log without a serial console.  Best-effort: a failed
            // `try_lock` (concurrent reader or cross-CPU writer) drops the
            // chunk rather than block, which is safe inside this IRQ-disabled
            // critical section.  We tee the raw `s` (before the inline
            // "\r\n" expansion below) so the ring holds clean "\n"-terminated
            // lines.
            crate::util::dmesg::write_str(s);

            // Stack-allocated batching buffer.  Bytes accumulate here until
            // we hit FIFO_DEPTH or the input is exhausted; then we commit.
            // Newlines expand to "\r\n" inline, which means a single input
            // byte can append two output bytes — we therefore flush
            // whenever fewer than 2 slots remain to keep the chunk
            // size ≤ FIFO_DEPTH.
            let mut buf = [0u8; FIFO_DEPTH];
            let mut len: usize = 0;

            for byte in s.bytes() {
                if byte == b'\n' {
                    buf[len] = b'\r';
                    len += 1;
                }
                buf[len] = byte;
                len += 1;

                // Flush when no room for another \r\n pair guaranteed.
                if len >= FIFO_DEPTH - 1 {
                    self.flush_chunk(&buf[..len]);
                    len = 0;
                }
            }
            // Flush the partial trailing chunk.
            self.flush_chunk(&buf[..len]);
            Ok(())
        }
    }

    WriteAdapter { port: &mut *port, if_was_set }.write_fmt(args).ok();

    // Clear the per-CPU re-entry flag under cli, so the slot transitions
    // false→true→false strictly inside an IRQ-off window.  An ISR that
    // fires after `enable_interrupts()` below sees the slot already
    // cleared and is free to emit normally.  Release pairs with the
    // Acquire on entry: the bytes-pushed-to-FIFO writes happen-before
    // any future observer of `false`.
    //
    // Drop `port` first so we don't carry the mutex guard across the
    // store (the guard's Drop unlocks SERIAL while IRQs are still off,
    // which is the same ordering the previous code relied on).
    drop(port);
    crate::hal::disable_interrupts();
    PER_CPU_IN_SERIAL[cpu].store(false, Ordering::Release);

    // Ensure we always restore the caller's IF state on exit, even if
    // write_fmt returned an error or the format string was empty.
    if if_was_set {
        crate::hal::enable_interrupts();
    }
    // (If IF was off on entry it remains off here — correct behaviour.)
}

/// High-volume ("fast path") log entry.
///
/// Routes a formatted line to the near-zero-overhead guest-RAM ring
/// ([`crate::drivers::log_ring`]) when the ring sink is enabled, instead of
/// paying ~one VM-exit per byte on the COM1 16550 THR (Intel SDM Vol. 3C
/// §25.1.3 — port I/O traps to the hypervisor under KVM).  The ring write is a
/// single relaxed atomic reservation plus a bounded `memcpy`: no lock, no
/// `outb`, no exit.  The bytes are drained out of band by the harness
/// (`qemu-harness.py log-ring drain|flush`).
///
/// Falls back to the classic [`_serial_print`] COM1 path when the ring is
/// disabled (e.g. forced off for an A/B measurement, or before the ring is the
/// active sink).  This keeps every call site correct regardless of routing —
/// the firehose is cheap when the ring is on and still visible when it is off.
///
/// Callers that MUST always reach COM1 immediately (early boot, panic,
/// bugcheck, low-volume lifeline output) keep calling `serial_println!`
/// directly; only the high-frequency trace families use this entry.
#[doc(hidden)]
pub fn log_fast(args: fmt::Arguments) {
    use fmt::Write;
    if !crate::drivers::log_ring::enabled() {
        // Ring disabled: behave exactly like serial_println! so no output is
        // ever lost.
        _serial_print(args);
        return;
    }
    // Format into a bounded stack buffer (no heap), then commit to the ring in
    // one shot.  A line longer than the buffer is soft-truncated; the ring also
    // caps at MAX_RECORD, so this is belt-and-braces.
    const CAP: usize = crate::drivers::log_ring::MAX_RECORD;
    struct RingBuf {
        buf: [u8; CAP],
        len: usize,
    }
    impl fmt::Write for RingBuf {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            for &b in s.as_bytes() {
                if self.len >= self.buf.len() {
                    break;
                }
                self.buf[self.len] = b;
                self.len += 1;
            }
            Ok(())
        }
    }
    let mut rb = RingBuf { buf: [0u8; CAP], len: 0 };
    let _ = rb.write_fmt(args);
    crate::drivers::log_ring::record(&rb.buf[..rb.len]);
}

/// Burst a slice of already-formatted bytes to the COM1 16550 THR.
///
/// Used by the log-ring flush drain to re-emit buffered firehose lines to the
/// serial log in one controlled burst (paying the per-byte UART cost once, at
/// drain time, never in the hot path).  Takes the `SERIAL` mutex and reuses the
/// same chunked, IRQ-windowed FIFO writer as `_serial_print`, but does NOT
/// expand `'\n'` to `"\r\n"` — the payload already carries its own line
/// terminator, and the ring stores raw producer bytes.
pub fn write_bytes_com1(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let rflags: u64;
    // SAFETY: pushfq/pop is a pure register read with no memory side effects.
    unsafe {
        core::arch::asm!(
            "pushfq; pop {rflags}",
            rflags = out(reg) rflags,
            options(nomem, nostack),
        );
    }
    let if_was_set = rflags & (1 << 9) != 0;

    crate::hal::disable_interrupts();
    let cpu = crate::arch::x86_64::apic::cpu_index();
    if PER_CPU_IN_SERIAL[cpu].swap(true, Ordering::Acquire) {
        // Same-CPU re-entry: avoid self-deadlock on the non-reentrant mutex.
        // Drop the burst (the flush runs from the drain path, not an ISR, so
        // this is not expected to fire).
        if if_was_set {
            crate::hal::enable_interrupts();
        }
        return;
    }
    let mut port = SERIAL.lock();
    // Push FIFO_DEPTH-sized chunks under per-chunk cli, mirroring _serial_print
    // but without newline expansion.
    let mut off = 0usize;
    while off < bytes.len() {
        let end = core::cmp::min(off + FIFO_DEPTH, bytes.len());
        crate::hal::disable_interrupts();
        port.write_chunk(&bytes[off..end]);
        if if_was_set {
            crate::hal::enable_interrupts();
        }
        off = end;
    }
    drop(port);
    crate::hal::disable_interrupts();
    PER_CPU_IN_SERIAL[cpu].store(false, Ordering::Release);
    if if_was_set {
        crate::hal::enable_interrupts();
    }
}

/// Direct-to-UART fallback writer used when `_serial_print` detects
/// same-CPU re-entry (PER_CPU_IN_SERIAL[cpu] already set).  Bypasses the
/// SERIAL mutex; pushes bytes directly to the COM1 THR with a bounded
/// LSR.THRE poll per byte.
///
/// Buffer size: 384 bytes is the empirical ceiling for the longest W215
/// diagnostic line (`[W215/DR-WATCH-FIRE]` with full register dump),
/// rounded up for safety.  Excess bytes are truncated with a trailing
/// `…\n` marker to signal that the line was clipped — better a truncated
/// diagnostic than silent loss.
///
/// Newline expansion (LF → CRLF) is done inline so the buffer's logical
/// capacity is ~190 input bytes.  All current W215 diagnostic lines fit.
///
/// Per Intel SDM Vol. 3B §17.2.5 and NS16550A datasheet §8: outb to the
/// THR after polling LSR.THRE is the canonical single-byte send path,
/// safe under concurrent writers as long as each individual outb is
/// atomic (which it is — port I/O is single-instruction on x86).
fn write_fallback_direct(args: fmt::Arguments) {
    use fmt::Write;

    const FALLBACK_CAP: usize = 384;
    struct StackBuf {
        buf: [u8; FALLBACK_CAP],
        len: usize,
        truncated: bool,
    }
    impl fmt::Write for StackBuf {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            for byte in s.bytes() {
                // Account for the LF→CRLF expansion so we don't write
                // a half-pair at the buffer's tail.
                let needed = if byte == b'\n' { 2 } else { 1 };
                if self.len + needed > self.buf.len() {
                    self.truncated = true;
                    return Ok(()); // soft-truncate; let the trailer add `\n`
                }
                if byte == b'\n' {
                    self.buf[self.len] = b'\r';
                    self.len += 1;
                }
                self.buf[self.len] = byte;
                self.len += 1;
            }
            Ok(())
        }
    }
    let mut sbuf = StackBuf { buf: [0u8; FALLBACK_CAP], len: 0, truncated: false };
    let _ = sbuf.write_fmt(args);
    if sbuf.truncated {
        // Append a "…\n" trailer if there is room (3 bytes incl. CRLF).
        let trailer = b"...\r\n";
        let room = sbuf.buf.len().saturating_sub(sbuf.len);
        let n = core::cmp::min(room, trailer.len());
        sbuf.buf[sbuf.len..sbuf.len + n].copy_from_slice(&trailer[..n]);
        sbuf.len += n;
    }

    // Bounded-spin per-byte direct write to COM1 THR.
    // SAFETY: COM1 is in the reserved 0x3F8–0x3FF port range.  Per-byte
    // poll-then-outb sequence is the same as `SerialPort::write_byte`,
    // hoisted out of the struct so we don't need to acquire SERIAL.
    unsafe {
        for &b in &sbuf.buf[..sbuf.len] {
            let mut n = 0u32;
            while hal::inb(COM1 + LSR) & LSR_THRE == 0 {
                core::hint::spin_loop();
                n += 1;
                if n >= THRE_SPIN_LIMIT {
                    return; // UART wedged — drop the rest rather than hang
                }
            }
            hal::outb(COM1, b);
        }
    }
}

/// Test-only harness for the per-CPU re-entry guard.
///
/// Simulates a same-CPU re-entry by forcing `PER_CPU_IN_SERIAL[cpu]` to
/// `true` (as if `_serial_print` were already in flight on this CPU),
/// then invoking `serial_println!`.  Returns the elapsed TSC cycles of
/// the nested call: a guard-protected drop completes in ~tens of cycles;
/// a self-deadlock would spin until the bounded-spin limit on the inner
/// `SERIAL.lock()` (and almost certainly the watchdog catches it first).
///
/// The caller asserts the elapsed time is well under any reasonable
/// 1 ms ceiling.  IRQs are held off across the whole forced-reentry
/// window so the state transitions cannot race with the local timer
/// ISR (Intel SDM Vol 3 §6.6: nested handlers must not block on
/// resources held by interrupted code).
#[cfg(feature = "test-mode")]
pub fn _test_force_reentry_drop_returns_quickly() -> u64 {
    #[inline(always)]
    fn rdtsc() -> u64 {
        let lo: u32;
        let hi: u32;
        // SAFETY: rdtsc is a side-effect-free timestamp read; the lfence
        // prefix serialises the timing window (Intel SDM Vol 2B RDTSC).
        unsafe {
            core::arch::asm!("lfence; rdtsc",
                             out("eax") lo, out("edx") hi,
                             options(nomem, nostack));
        }
        ((hi as u64) << 32) | (lo as u64)
    }

    // Snapshot IF, then cli for the duration of the forced-reentry test.
    let rflags: u64;
    // SAFETY: pushfq/pop is a pure register read with no memory effects.
    unsafe {
        core::arch::asm!(
            "pushfq; pop {rflags}",
            rflags = out(reg) rflags,
            options(nomem, nostack),
        );
    }
    let if_was_set = rflags & (1 << 9) != 0;
    crate::hal::disable_interrupts();

    let cpu = crate::arch::x86_64::apic::cpu_index();
    PER_CPU_IN_SERIAL[cpu].store(true, Ordering::Release);

    let t0 = rdtsc();
    // The nested call must hit the guard and return without locking
    // SERIAL — if the guard is broken this self-deadlocks instead.
    crate::serial_println!("[SERIAL-REENTRY-TEST] this line is intentionally dropped");
    let t1 = rdtsc();

    PER_CPU_IN_SERIAL[cpu].store(false, Ordering::Release);
    if if_was_set {
        crate::hal::enable_interrupts();
    }
    t1.saturating_sub(t0)
}
