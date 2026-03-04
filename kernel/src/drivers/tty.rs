//! TTY Subsystem
//!
//! Provides a proper TTY layer with configurable termios settings, line
//! discipline (canonical and raw modes), and signal generation. Sits between
//! the keyboard/console drivers and userspace syscalls.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

// ── termios flag constants (Linux-compatible values) ────────────────────────

// c_iflag bits
pub const IGNBRK: u32 = 0o000001;
pub const BRKINT: u32 = 0o000002;
pub const IGNPAR: u32 = 0o000004;
pub const PARMRK: u32 = 0o000010;
pub const INPCK: u32  = 0o000020;
pub const ISTRIP: u32 = 0o000040;
pub const INLCR: u32  = 0o000100;
pub const IGNCR: u32  = 0o000200;
pub const ICRNL: u32  = 0o000400;
pub const IXON: u32   = 0o002000;
pub const IXOFF: u32  = 0o010000;

// c_oflag bits
pub const OPOST: u32 = 0o000001;
pub const ONLCR: u32 = 0o000004;
pub const OCRNL: u32 = 0o000010;
pub const ONOCR: u32 = 0o000020;
pub const ONLRET: u32 = 0o000040;

// c_cflag bits
pub const CSIZE: u32  = 0o000060;
pub const CS5: u32    = 0o000000;
pub const CS6: u32    = 0o000020;
pub const CS7: u32    = 0o000040;
pub const CS8: u32    = 0o000060;
pub const CSTOPB: u32 = 0o000100;
pub const CREAD: u32  = 0o000200;
pub const PARENB: u32 = 0o000400;
pub const HUPCL: u32  = 0o002000;
pub const CLOCAL: u32 = 0o004000;

// c_lflag bits
pub const ISIG: u32   = 0o000001;
pub const ICANON: u32 = 0o000002;
pub const ECHO: u32   = 0o000010;
pub const ECHOE: u32  = 0o000020;
pub const ECHOK: u32  = 0o000040;
pub const ECHONL: u32 = 0o000100;
pub const NOFLSH: u32 = 0o000200;
pub const ECHOCTL: u32 = 0o001000;
pub const IEXTEN: u32 = 0o100000;

// c_cc indices
pub const VINTR: usize   = 0;
pub const VQUIT: usize   = 1;
pub const VERASE: usize  = 2;
pub const VKILL: usize   = 3;
pub const VEOF: usize    = 4;
pub const VTIME: usize   = 5;
pub const VMIN: usize    = 6;
pub const VSWTC: usize   = 7;
pub const VSTART: usize  = 8;
pub const VSTOP: usize   = 9;
pub const VSUSP: usize   = 10;
pub const VEOL: usize    = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize  = 15;
pub const VEOL2: usize   = 16;

/// Maximum canonical mode line buffer size.
const LINE_BUF_MAX: usize = 4096;

// ── ioctl request numbers ───────────────────────────────────────────────────

pub const TCGETS: u64    = 0x5401;
pub const TCSETS: u64    = 0x5402;
pub const TCSETSW: u64   = 0x5403;
pub const TCSETSF: u64   = 0x5404;
pub const TIOCGWINSZ: u64 = 0x5413;

// ── Structures ──────────────────────────────────────────────────────────────

/// Terminal I/O settings, matching the Linux `struct termios` layout.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Termios {
    /// Create a default cooked-mode termios (like a freshly-opened terminal).
    pub fn default_cooked() -> Self {
        let mut c_cc = [0u8; 32];
        c_cc[VINTR] = 3;      // ^C
        c_cc[VQUIT] = 28;     // ^\  
        c_cc[VERASE] = 127;   // DEL
        c_cc[VKILL] = 21;     // ^U
        c_cc[VEOF] = 4;       // ^D
        c_cc[VTIME] = 0;
        c_cc[VMIN] = 1;
        c_cc[VSTART] = 17;    // ^Q
        c_cc[VSTOP] = 19;     // ^S
        c_cc[VSUSP] = 26;     // ^Z
        c_cc[VEOL] = 0;
        c_cc[VREPRINT] = 18;  // ^R
        c_cc[VDISCARD] = 15;  // ^O
        c_cc[VWERASE] = 23;   // ^W
        c_cc[VLNEXT] = 22;    // ^V

        Termios {
            c_iflag: ICRNL,
            c_oflag: OPOST | ONLCR,
            c_cflag: CS8 | CREAD | CLOCAL,
            c_lflag: ECHO | ECHOE | ICANON | ISIG | IEXTEN,
            c_line: 0,
            c_cc,
            c_ispeed: 38400,
            c_ospeed: 38400,
        }
    }
}

/// Terminal window size (matches Linux `struct winsize`).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// TTY device state.
pub struct Tty {
    pub termios: Termios,
    /// Canonical-mode line buffer.
    pub input_buf: Vec<u8>,
    /// A complete line is available for reading.
    pub input_ready: bool,
    /// Cooked-mode output that has been committed (after newline/EOF).
    pub cooked_buf: Vec<u8>,
    /// Window size.
    pub winsize: Winsize,
    /// Foreground process group ID (for future signal delivery).
    pub fg_pgid: u32,
    /// Session ID (for future job control).
    pub session_id: u32,
}

/// Global TTY for the main console.
pub static TTY0: Mutex<Tty> = Mutex::new(Tty::const_new());

impl Tty {
    /// Const constructor for static initialization.
    const fn const_new() -> Self {
        let mut c_cc = [0u8; 32];
        c_cc[VINTR] = 3;
        c_cc[VQUIT] = 28;
        c_cc[VERASE] = 127;
        c_cc[VKILL] = 21;
        c_cc[VEOF] = 4;
        c_cc[VTIME] = 0;
        c_cc[VMIN] = 1;
        c_cc[VSTART] = 17;
        c_cc[VSTOP] = 19;
        c_cc[VSUSP] = 26;
        c_cc[VEOL] = 0;
        c_cc[VREPRINT] = 18;
        c_cc[VDISCARD] = 15;
        c_cc[VWERASE] = 23;
        c_cc[VLNEXT] = 22;

        Tty {
            termios: Termios {
                c_iflag: ICRNL,
                c_oflag: OPOST | ONLCR,
                c_cflag: CS8 | CREAD | CLOCAL,
                c_lflag: ECHO | ECHOE | ICANON | ISIG | IEXTEN,
                c_line: 0,
                c_cc,
                c_ispeed: 38400,
                c_ospeed: 38400,
            },
            input_buf: Vec::new(),
            input_ready: false,
            cooked_buf: Vec::new(),
            winsize: Winsize {
                ws_row: 25,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
            fg_pgid: 0,
            session_id: 0,
        }
    }

    /// Create a new TTY with default cooked-mode settings.
    pub fn new() -> Self {
        Tty {
            termios: Termios::default_cooked(),
            input_buf: Vec::new(),
            input_ready: false,
            cooked_buf: Vec::new(),
            winsize: Winsize {
                ws_row: 25,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
            fg_pgid: 0,
            session_id: 0,
        }
    }

    /// Process a single input byte from the keyboard through the line discipline.
    pub fn process_input(&mut self, ch: u8) {
        let lflag = self.termios.c_lflag;
        let iflag = self.termios.c_iflag;
        let c_cc = &self.termios.c_cc;

        // Input flag processing: CR/NL mapping
        let ch = if iflag & ICRNL != 0 && ch == b'\r' {
            b'\n'
        } else if iflag & INLCR != 0 && ch == b'\n' {
            b'\r'
        } else {
            ch
        };

        // Ignore CR if IGNCR is set
        if iflag & IGNCR != 0 && ch == b'\r' {
            return;
        }

        // Strip high bit if ISTRIP
        let ch = if iflag & ISTRIP != 0 { ch & 0x7F } else { ch };

        // Signal generation (ISIG)
        if lflag & ISIG != 0 {
            if ch == c_cc[VINTR] {
                // ^C — SIGINT
                crate::serial_println!("[TTY] SIGINT (^C) generated");
                if lflag & ECHO != 0 {
                    self.echo_bytes(b"^C\n");
                }
                // Flush input in canonical mode
                if lflag & ICANON != 0 {
                    self.input_buf.clear();
                    self.input_ready = false;
                }
                return;
            }
            if ch == c_cc[VQUIT] {
                // ^\ — SIGQUIT
                crate::serial_println!("[TTY] SIGQUIT (^\\) generated");
                if lflag & ECHO != 0 {
                    self.echo_bytes(b"^\\\n");
                }
                if lflag & ICANON != 0 {
                    self.input_buf.clear();
                    self.input_ready = false;
                }
                return;
            }
            if ch == c_cc[VSUSP] {
                // ^Z — SIGTSTP
                crate::serial_println!("[TTY] SIGTSTP (^Z) generated");
                if lflag & ECHO != 0 {
                    self.echo_bytes(b"^Z\n");
                }
                if lflag & ICANON != 0 {
                    self.input_buf.clear();
                    self.input_ready = false;
                }
                return;
            }
        }

        // Canonical mode (line editing)
        if lflag & ICANON != 0 {
            // VERASE — erase last character
            if ch == c_cc[VERASE] {
                if !self.input_buf.is_empty() {
                    self.input_buf.pop();
                    if lflag & ECHOE != 0 {
                        // Echo backspace-space-backspace
                        self.echo_bytes(b"\x08 \x08");
                    }
                }
                return;
            }

            // VKILL — erase entire line
            if ch == c_cc[VKILL] {
                let len = self.input_buf.len();
                self.input_buf.clear();
                if lflag & ECHO != 0 {
                    // Erase the line visually
                    for _ in 0..len {
                        self.echo_bytes(b"\x08 \x08");
                    }
                }
                return;
            }

            // VEOF — end of file (^D)
            if ch == c_cc[VEOF] {
                // Mark input as ready with current buffer contents (may be empty for EOF)
                self.input_ready = true;
                // Move input_buf contents to cooked_buf
                self.cooked_buf.clear();
                self.cooked_buf.append(&mut self.input_buf);
                return;
            }

            // Buffer the character
            if self.input_buf.len() < LINE_BUF_MAX {
                self.input_buf.push(ch);
            }

            // Echo the character
            if lflag & ECHO != 0 {
                self.echo_byte(ch);
            } else if lflag & ECHONL != 0 && ch == b'\n' {
                self.echo_byte(b'\n');
            }

            // Newline completes the line
            if ch == b'\n' {
                self.input_ready = true;
                self.cooked_buf.clear();
                self.cooked_buf.append(&mut self.input_buf);
            }
        } else {
            // Raw mode (non-canonical): character immediately available
            if self.input_buf.len() < LINE_BUF_MAX {
                self.input_buf.push(ch);
            }

            if lflag & ECHO != 0 {
                self.echo_byte(ch);
            }
        }
    }

    /// Read from the TTY into the provided buffer.
    ///
    /// Returns the number of bytes read. Returns 0 if no data is available
    /// yet (caller should yield and retry).
    pub fn read(&mut self, buf: &mut [u8], count: usize) -> usize {
        let n = count.min(buf.len());
        if n == 0 {
            return 0;
        }

        if self.termios.c_lflag & ICANON != 0 {
            // Canonical mode: wait for a complete line
            if !self.input_ready {
                return 0;
            }
            let avail = self.cooked_buf.len().min(n);
            buf[..avail].copy_from_slice(&self.cooked_buf[..avail]);
            self.cooked_buf.drain(..avail);
            if self.cooked_buf.is_empty() {
                self.input_ready = false;
            }
            avail
        } else {
            // Raw mode: return whatever is available (VMIN/VTIME simplified)
            let vmin = self.termios.c_cc[VMIN] as usize;
            let available = self.input_buf.len();
            if available < vmin.max(1) {
                return 0;
            }
            let to_read = available.min(n);
            buf[..to_read].copy_from_slice(&self.input_buf[..to_read]);
            self.input_buf.drain(..to_read);
            to_read
        }
    }

    /// Write data to the TTY output (to the console).
    ///
    /// Applies output processing (OPOST, ONLCR) before sending to console.
    pub fn write(&self, data: &[u8]) {
        let opost = self.termios.c_oflag & OPOST != 0;
        let onlcr = self.termios.c_oflag & ONLCR != 0;

        if opost && onlcr {
            // Convert \n to \r\n
            for &b in data {
                if b == b'\n' {
                    write_console_byte(b'\r');
                    write_console_byte(b'\n');
                } else {
                    write_console_byte(b);
                }
            }
        } else {
            for &b in data {
                write_console_byte(b);
            }
        }
    }

    /// Set termios (TCSETS).
    pub fn set_termios(&mut self, new: &Termios) {
        self.termios = *new;
    }

    /// Set termios and flush input (TCSETSF).
    pub fn set_termios_flush(&mut self, new: &Termios) {
        self.termios = *new;
        self.input_buf.clear();
        self.cooked_buf.clear();
        self.input_ready = false;
    }

    /// Get a copy of the current termios.
    pub fn get_termios(&self) -> Termios {
        self.termios
    }

    /// Get the window size.
    pub fn get_winsize(&self) -> Winsize {
        self.winsize
    }

    /// Update the window size (called from console init or resize).
    pub fn set_winsize(&mut self, rows: u16, cols: u16, xpixel: u16, ypixel: u16) {
        self.winsize.ws_row = rows;
        self.winsize.ws_col = cols;
        self.winsize.ws_xpixel = xpixel;
        self.winsize.ws_ypixel = ypixel;
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Echo a single byte to the console.
    fn echo_byte(&self, b: u8) {
        write_console_byte(b);
    }

    /// Echo a slice of bytes to the console.
    fn echo_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            write_console_byte(b);
        }
    }
}

/// Write a single byte to the framebuffer console.
///
/// This bypasses the TTY output processing (used for echo).
fn write_console_byte(b: u8) {
    if let Some(ref mut console) = *crate::drivers::console::CONSOLE.lock() {
        use core::fmt::Write;
        let _ = console.write_char(b as char);
    }
}

// ── Initialization ──────────────────────────────────────────────────────────

/// Initialize the TTY subsystem. Call after the console driver is initialized.
pub fn init() {
    // Grab real console dimensions and update TTY winsize
    if let Some(ref console) = *crate::drivers::console::CONSOLE.lock() {
        let (cols, rows) = console.dimensions();
        let mut tty = TTY0.lock();
        tty.set_winsize(
            rows as u16,
            cols as u16,
            (cols * 8) as u16,   // 8px per char
            (rows * 16) as u16,  // 16px per char
        );
        crate::serial_println!(
            "[TTY] Initialized TTY0 ({}x{}, cooked mode, echo on)",
            cols,
            rows
        );
    } else {
        crate::serial_println!("[TTY] Initialized TTY0 (no console, default 80x25)");
    }
}

// ── Keyboard → TTY bridge (on-demand pump for SYS_READ) ────────────────────

/// Pump pending keyboard scancodes into the TTY line discipline.
///
/// Called on-demand from the SYS_READ handler before reading from the TTY
/// buffer. This avoids holding locks during interrupt context.
pub fn pump_keyboard(tty: &mut Tty) {
    use crate::drivers::keyboard::{process_scancode, KeyEvent};

    // Drain all pending scancodes from the IRQ ring buffer
    while let Some(sc) = crate::arch::x86_64::irq::read_scancode() {
        let event = process_scancode(sc);
        if let Some(ev) = event {
            // Convert KeyEvent to byte(s) for the TTY
            match ev {
                KeyEvent::Char(ch) => {
                    tty.process_input(ch as u8);
                }
                KeyEvent::Enter => {
                    tty.process_input(b'\n');
                }
                KeyEvent::Backspace => {
                    // Send the VERASE character (usually DEL=127)
                    tty.process_input(tty.termios.c_cc[VERASE]);
                }
                KeyEvent::Tab => {
                    tty.process_input(b'\t');
                }
                KeyEvent::Ctrl(ch) => {
                    // Ctrl+letter → control character (e.g. ^C = 3)
                    let ctrl_byte = (ch as u8) - b'a' + 1;
                    tty.process_input(ctrl_byte);
                }
                KeyEvent::Escape => {
                    tty.process_input(0x1B);
                }
                KeyEvent::Delete => {
                    tty.process_input(0x7F);
                }
                // Arrow keys → VT100 escape sequences
                KeyEvent::ArrowUp => {
                    tty.process_input(0x1B);
                    tty.process_input(b'[');
                    tty.process_input(b'A');
                }
                KeyEvent::ArrowDown => {
                    tty.process_input(0x1B);
                    tty.process_input(b'[');
                    tty.process_input(b'B');
                }
                KeyEvent::ArrowRight => {
                    tty.process_input(0x1B);
                    tty.process_input(b'[');
                    tty.process_input(b'C');
                }
                KeyEvent::ArrowLeft => {
                    tty.process_input(0x1B);
                    tty.process_input(b'[');
                    tty.process_input(b'D');
                }
                KeyEvent::Home => {
                    tty.process_input(0x1B);
                    tty.process_input(b'[');
                    tty.process_input(b'H');
                }
                KeyEvent::End => {
                    tty.process_input(0x1B);
                    tty.process_input(b'[');
                    tty.process_input(b'F');
                }
                // Ignore other keys for now (function keys, Alt+, etc.)
                _ => {}
            }
        }
    }
}

// ── ioctl dispatch ──────────────────────────────────────────────────────────

/// Handle TTY ioctl requests. Returns 0 on success, negative errno on error.
pub fn tty_ioctl(request: u64, arg_ptr: *mut u8) -> i64 {
    match request {
        TCGETS => {
            if arg_ptr.is_null() {
                return -14; // EFAULT
            }
            let tty = TTY0.lock();
            let termios = tty.get_termios();
            let src = &termios as *const Termios as *const u8;
            let size = core::mem::size_of::<Termios>();
            unsafe {
                core::ptr::copy_nonoverlapping(src, arg_ptr, size);
            }
            0
        }
        TCSETS => {
            if arg_ptr.is_null() {
                return -14;
            }
            let mut termios = Termios::default_cooked();
            let dst = &mut termios as *mut Termios as *mut u8;
            let size = core::mem::size_of::<Termios>();
            unsafe {
                core::ptr::copy_nonoverlapping(arg_ptr as *const u8, dst, size);
            }
            let mut tty = TTY0.lock();
            tty.set_termios(&termios);
            0
        }
        TCSETSW => {
            // "Set after output drains" — for a virtual console there's nothing
            // to drain, so this is equivalent to TCSETS.
            if arg_ptr.is_null() {
                return -14;
            }
            let mut termios = Termios::default_cooked();
            let dst = &mut termios as *mut Termios as *mut u8;
            let size = core::mem::size_of::<Termios>();
            unsafe {
                core::ptr::copy_nonoverlapping(arg_ptr as *const u8, dst, size);
            }
            let mut tty = TTY0.lock();
            tty.set_termios(&termios);
            0
        }
        TCSETSF => {
            // "Set after output drains + flush input"
            if arg_ptr.is_null() {
                return -14;
            }
            let mut termios = Termios::default_cooked();
            let dst = &mut termios as *mut Termios as *mut u8;
            let size = core::mem::size_of::<Termios>();
            unsafe {
                core::ptr::copy_nonoverlapping(arg_ptr as *const u8, dst, size);
            }
            let mut tty = TTY0.lock();
            tty.set_termios_flush(&termios);
            0
        }
        TIOCGWINSZ => {
            if arg_ptr.is_null() {
                return -14;
            }
            let tty = TTY0.lock();
            let ws = tty.get_winsize();
            let src = &ws as *const Winsize as *const u8;
            let size = core::mem::size_of::<Winsize>();
            unsafe {
                core::ptr::copy_nonoverlapping(src, arg_ptr, size);
            }
            0
        }
        _ => -25, // ENOTTY
    }
}
