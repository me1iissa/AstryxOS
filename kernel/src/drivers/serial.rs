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
//! The `SERIAL` `spin::Mutex` prevents concurrent FIFO writers from two
//! CPUs interleaving bytes.  The per-chunk cli prevents the *same* CPU's
//! timer ISR from calling `serial_println!` while the mutex is already
//! held on that CPU (which would deadlock, since `spin::Mutex` is not
//! reentrant).  Together they give: one writer at a time, no deadlock,
//! bounded IRQ blackout per chunk.
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
/// The `SERIAL` `spin::Mutex` serialises concurrent CPUs.  But if a timer
/// ISR fires on the *same* CPU while we hold the mutex and calls
/// `serial_println!`, it would attempt to lock `SERIAL` again — deadlock,
/// because `spin::Mutex` is not reentrant.  The per-chunk cli prevents
/// that ISR from running between "mutex acquired" and "FIFO chunk
/// committed".  No ISR runs while a chunk is being written, but the IRQ
/// window re-opens between chunks so a 4 KiB write still admits hundreds
/// of timer/IPI events during its lifetime.
///
/// # Bugcheck path
///
/// `ke::bugcheck` never calls this function.  It bypasses `SERIAL`
/// entirely via `util::no_alloc_fmt::bugcheck_serial_write_bytes`.
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

    // Ensure we always restore the caller's IF state on exit, even if
    // write_fmt returned an error or the format string was empty.
    if if_was_set {
        crate::hal::enable_interrupts();
    }
    // (If IF was off on entry it remains off here — correct behaviour.)
}
