//! Serial Port Driver (COM1)
//!
//! Provides debug output via the serial port (UART 16550).
//! QEMU maps this to the host terminal, making it invaluable for debugging.

use crate::hal;
use core::fmt;
use spin::Mutex;

/// COM1 base I/O port.
const COM1: u16 = 0x3F8;

/// Global serial port instance.
static SERIAL: Mutex<SerialPort> = Mutex::new(SerialPort { base: COM1 });

/// UART 16550 serial port driver.
pub struct SerialPort {
    base: u16,
}

impl SerialPort {
    /// Initialize the serial port.
    fn init(&self) {
        // SAFETY: Standard UART 16550 initialization sequence.
        unsafe {
            hal::outb(self.base + 1, 0x00); // Disable all interrupts
            hal::outb(self.base + 3, 0x80); // Enable DLAB (set baud rate divisor)
            hal::outb(self.base + 0, 0x01); // Set divisor to 1 (115200 baud)
            hal::outb(self.base + 1, 0x00); //   (hi byte)
            hal::outb(self.base + 3, 0x03); // 8 bits, no parity, one stop bit
            hal::outb(self.base + 2, 0xC7); // Enable FIFO, clear them, 14-byte threshold
            hal::outb(self.base + 4, 0x0B); // IRQs enabled, RTS/DSR set
        }
    }

    /// Write a byte to the serial port.
    fn write_byte(&self, byte: u8) {
        // SAFETY: Writing to UART data register after checking transmit buffer is empty.
        unsafe {
            // Wait for transmit buffer to be empty
            while hal::inb(self.base + 5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            hal::outb(self.base, byte);
        }
    }

    /// Read a byte from the serial port (blocking).
    pub fn read_byte(&self) -> u8 {
        // SAFETY: Reading from UART data register after checking data is available.
        unsafe {
            while hal::inb(self.base + 5) & 0x01 == 0 {
                core::hint::spin_loop();
            }
            hal::inb(self.base)
        }
    }

    /// Check if data is available to read.
    pub fn has_data(&self) -> bool {
        // SAFETY: Reading the line status register is safe.
        unsafe { hal::inb(self.base + 5) & 0x01 != 0 }
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
    crate::serial_println!("[SERIAL] COM1 initialized at 115200 baud");
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

/// Print to serial port (used by serial_print! macro).
#[doc(hidden)]
pub fn _serial_print(args: fmt::Arguments) {
    use fmt::Write;
    SERIAL.lock().write_fmt(args).unwrap();
}
