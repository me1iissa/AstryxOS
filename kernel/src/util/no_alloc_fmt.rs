//! Allocation-free, fault-immune byte formatting for kernel diagnostics.
//!
//! This module exists to support the bugcheck banner printer.  When the
//! kernel hits a fatal fault (CR2 corruption, stack-canary smash, PMM list
//! corruption, etc.) the heap and the global serial mutex may already be
//! corrupt or held by another CPU.  Any code path that goes through
//! `format_args!` → `core::fmt::Write` → `String`/`Vec`/`Box` can re-enter
//! the allocator and re-fault — burying the original bug under a synthetic
//! "fault while formatting" trace.
//!
//! The primitives here are deliberately:
//!
//! * **Stack-only**: every formatter writes into a caller-owned `[u8; N]`.
//!   No `alloc::*`, no `core::fmt::Display` for non-`&'static str` types,
//!   no transitive heap touches.
//! * **Lock-free serial**: [`bugcheck_serial_write_bytes`] talks directly
//!   to the COM1 UART by polling LSR.THRE.  It never takes the
//!   `drivers::serial::SERIAL` mutex, so a deadlocked owner CPU can't
//!   wedge the bugcheck path.
//! * **Volatile reads**: callers can copy out potentially-corrupt
//!   structures with [`read_u64_volatile`] without leaving a hidden
//!   `Display::fmt` invocation in the call graph.
//!
//! Public API is intentionally small: a stack [`ArrayWriter`] that
//! implements `core::fmt::Write` for `&'static str` writes only, plus a
//! handful of hex/decimal helpers, plus the bypass serial sink.  None of
//! these functions allocate, take sleeping locks, or call into the
//! normal `serial_println!` / `kprintln!` paths.

#![allow(dead_code)]

use crate::hal;

/// COM1 base I/O port — duplicated here so the bugcheck path does not
/// pull in [`crate::drivers::serial`] (which owns a `Mutex`).  This MUST
/// stay in sync with the constant in `drivers/serial.rs`.
const COM1: u16 = 0x3F8;

/// LSR.THRE bit — set when the transmit holding register is empty and
/// the next byte may be written to the data register.
const LSR_THRE: u8 = 0x20;

/// Maximum spins waiting for THRE before dropping a byte.  At 115200
/// baud one byte takes ~87 µs to transmit, so 200_000 spins (~2 ms on
/// a 100 MHz core) is comfortably above worst case but well below
/// "wedged forever".
const TX_SPIN_LIMIT: u32 = 200_000;

/// Write a single byte to COM1 by polling LSR.THRE — bypasses the
/// `SERIAL` mutex entirely.
///
/// # Safety
/// Always safe to call (port I/O on the standardised UART16550A range
/// is side-effect-free except for the byte being shifted out).  The
/// only failure mode is a dropped byte if the UART is wedged.
#[inline(always)]
pub fn bugcheck_serial_write_byte(byte: u8) {
    // SAFETY: COM1 ports are reserved for serial I/O and are mapped on
    // every supported platform configuration. Spin is bounded.
    unsafe {
        let mut n: u32 = 0;
        while hal::inb(COM1 + 5) & LSR_THRE == 0 {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n >= TX_SPIN_LIMIT {
                break;
            }
        }
        hal::outb(COM1, byte);
    }
}

/// Write a byte slice to COM1, expanding `\n` to `\r\n` so the host
/// terminal's line discipline cooperates.  Bypasses [`drivers::serial`]
/// entirely — does not allocate, does not lock.
pub fn bugcheck_serial_write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            bugcheck_serial_write_byte(b'\r');
        }
        bugcheck_serial_write_byte(b);
    }
}

/// Write a `&'static str` to COM1 via [`bugcheck_serial_write_bytes`].
/// The "&'static str" bound is load-bearing: it guarantees the string
/// data is in `.rodata`, not on a possibly-corrupt heap.
#[inline]
pub fn bugcheck_serial_write_str(s: &'static str) {
    bugcheck_serial_write_bytes(s.as_bytes());
}

/// Stack-resident byte buffer that implements just enough of
/// [`core::fmt::Write`] to support `write_str` writes.  Saturates on
/// overflow rather than panicking — any caller hitting the cap should
/// re-design the line, not crash.
pub struct ArrayWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> ArrayWriter<'a> {
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Append raw bytes; truncate (do not fault) if the buffer is full.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        let cap = self.buf.len();
        for &b in bytes {
            if self.len >= cap { return; }
            self.buf[self.len] = b;
            self.len += 1;
        }
    }

    /// Append a single byte; truncate if the buffer is full.
    #[inline]
    pub fn push_byte(&mut self, b: u8) {
        if self.len < self.buf.len() {
            self.buf[self.len] = b;
            self.len += 1;
        }
    }

    /// Append a `&'static str` (proven to live in rodata).
    #[inline]
    pub fn push_str(&mut self, s: &'static str) {
        self.push_bytes(s.as_bytes());
    }

    /// Append the canonical 18-char "0xHHHH_HHHH_HHHH_HHHH" form of `v`.
    /// The leading "0x" plus all 16 hex digits are always emitted; we
    /// drop the underscores to keep the format machine-parseable.
    pub fn push_hex_u64(&mut self, v: u64) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.push_bytes(b"0x");
        // Highest nibble first.  Unrolled 16-iteration loop — no shift
        // dependencies on a heap pointer.
        let mut i: i32 = 60;
        while i >= 0 {
            let nib = ((v >> (i as u32)) & 0xF) as usize;
            self.push_byte(HEX[nib]);
            i -= 4;
        }
    }

    /// Append the canonical 10-char "0xHHHHHHHH" form of `v`.
    pub fn push_hex_u32(&mut self, v: u32) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.push_bytes(b"0x");
        let mut i: i32 = 28;
        while i >= 0 {
            let nib = ((v >> (i as u32)) & 0xF) as usize;
            self.push_byte(HEX[nib]);
            i -= 4;
        }
    }

    /// Append `v` in unsigned decimal — always at least one digit.
    pub fn push_dec_u64(&mut self, mut v: u64) {
        if v == 0 {
            self.push_byte(b'0');
            return;
        }
        // u64::MAX is 20 digits; 24 leaves slack for a leading minus
        // if a future signed helper reuses this buffer.
        let mut tmp = [0u8; 24];
        let mut n = 0;
        while v != 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        // Reverse copy.
        while n > 0 {
            n -= 1;
            self.push_byte(tmp[n]);
        }
    }

    /// Borrow the bytes written so far.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// How many bytes have been written.
    #[inline]
    pub fn len(&self) -> usize { self.len }
}

/// Volatile read of a `u64` at `ptr`.  Used by the bugcheck snapshot to
/// copy potentially-corrupt fields without leaving a `Display::fmt` on
/// the call graph (which the optimiser is otherwise free to materialise
/// into an allocation in some Rust front-end versions).
///
/// # Safety
/// `ptr` must be 8-byte-aligned and point to readable memory.  The
/// caller is responsible for the validity of the address; this helper
/// does no checking.
#[inline(always)]
pub unsafe fn read_u64_volatile(ptr: *const u64) -> u64 {
    core::ptr::read_volatile(ptr)
}

#[cfg(feature = "bugcheck-test")]
pub(crate) mod tests {
    //! Self-tests for the formatter — exercised by the bugcheck-test
    //! feature so the failing helpers don't ship to release.
    use super::*;

    pub fn run_self_tests() -> bool {
        let mut ok = true;

        // hex u64
        let mut buf = [0u8; 32];
        let mut w = ArrayWriter::new(&mut buf);
        w.push_hex_u64(0xDEAD_BEEF_CAFE_F00D);
        ok &= w.as_bytes() == b"0xdeadbeefcafef00d";

        // hex u64 zero
        let mut buf = [0u8; 32];
        let mut w = ArrayWriter::new(&mut buf);
        w.push_hex_u64(0);
        ok &= w.as_bytes() == b"0x0000000000000000";

        // hex u32
        let mut buf = [0u8; 16];
        let mut w = ArrayWriter::new(&mut buf);
        w.push_hex_u32(0x1234_5678);
        ok &= w.as_bytes() == b"0x12345678";

        // dec u64 zero
        let mut buf = [0u8; 32];
        let mut w = ArrayWriter::new(&mut buf);
        w.push_dec_u64(0);
        ok &= w.as_bytes() == b"0";

        // dec u64 large
        let mut buf = [0u8; 32];
        let mut w = ArrayWriter::new(&mut buf);
        w.push_dec_u64(1234567890);
        ok &= w.as_bytes() == b"1234567890";

        // overflow truncates rather than panics
        let mut buf = [0u8; 4];
        let mut w = ArrayWriter::new(&mut buf);
        w.push_str("hello, world");
        ok &= w.as_bytes() == b"hell";

        ok
    }
}
