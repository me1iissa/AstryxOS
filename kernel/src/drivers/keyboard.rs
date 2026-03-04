//! PS/2 Keyboard Driver
//!
//! Converts PS/2 scancodes (Set 1) to key events with modifier tracking.
//! Supports Ctrl, Alt, Shift, CapsLock, and extended keys (arrows, Home, End, etc.).
//!
//! Initialises the i8042 PS/2 controller following the pattern used by the
//! ReactOS `i8042prt` driver: flush → read CCB → disable ports → self-test →
//! configure CCB (enable IRQ1, translation) → enable keyboard port → reset →
//! enable scanning.

// ── i8042 controller ports & constants ──────────────────────────────────────

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const COMMAND_PORT: u16 = 0x64;

// i8042 controller commands (sent to port 0x64)
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_KBD: u8 = 0xAD;
const CMD_ENABLE_KBD: u8 = 0xAE;
const CMD_SELF_TEST: u8 = 0xAA;

// Controller Configuration Byte (CCB) bits
const CCB_KBD_INT_ENAB: u8 = 0x01;  // Bit 0 — enable keyboard IRQ1
const CCB_MOUSE_INT_ENAB: u8 = 0x02; // Bit 1 — enable mouse IRQ12
const CCB_SYSTEM_FLAG: u8 = 0x04;   // Bit 2 — system flag (POST passed)
const CCB_KBD_DISAB: u8 = 0x10;     // Bit 4 — disable keyboard clock
const CCB_MOUSE_DISAB: u8 = 0x20;   // Bit 5 — disable mouse clock
const CCB_TRANSLATE: u8 = 0x40;     // Bit 6 — scancode translation (set 2→1)

// Keyboard commands (sent to port 0x60)
const KBD_CMD_RESET: u8 = 0xFF;
const KBD_CMD_ENABLE_SCAN: u8 = 0xF4;
const KBD_CMD_SET_LEDS: u8 = 0xED;

// Expected responses
const KBD_ACK: u8 = 0xFA;
const SELF_TEST_OK: u8 = 0x55;

/// Keyboard event — richer than just Option<char>.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyEvent {
    /// A printable ASCII character (with modifiers already applied).
    Char(char),
    /// Ctrl + a letter key (value is 'a'–'z', lowercase).
    Ctrl(char),
    /// Alt + a letter key (value is 'a'–'z', lowercase).
    Alt(char),
    /// Arrow keys.
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    /// Special navigation keys.
    Home,
    End,
    Delete,
    Insert,
    PageUp,
    PageDown,
    /// Enter key.
    Enter,
    /// Backspace key.
    Backspace,
    /// Tab key.
    Tab,
    /// Escape key.
    Escape,
    /// Function keys F1–F12.
    FKey(u8),
}

/// Modifier key state tracked across scancodes.
static mut SHIFT_PRESSED: bool = false;
static mut CTRL_PRESSED: bool = false;
static mut ALT_PRESSED: bool = false;
static mut CAPS_LOCK: bool = false;
/// Extended scancode prefix (0xE0) was received.
static mut EXTENDED_PREFIX: bool = false;

// ── i8042 low-level helpers ─────────────────────────────────────────────────

/// Wait until the i8042 input buffer is ready for a write (status bit 1 clear).
fn wait_input() {
    for _ in 0..100_000 {
        if unsafe { crate::hal::inb(STATUS_PORT) } & 0x02 == 0 {
            return;
        }
    }
}

/// Wait until the i8042 output buffer has data (status bit 0 set).
fn wait_output() -> bool {
    for _ in 0..100_000 {
        if unsafe { crate::hal::inb(STATUS_PORT) } & 0x01 != 0 {
            return true;
        }
    }
    false
}

/// Flush any stale bytes sitting in the i8042 output buffer.
fn flush_output_buffer() {
    for _ in 0..64 {
        if unsafe { crate::hal::inb(STATUS_PORT) } & 0x01 == 0 {
            break;
        }
        unsafe { crate::hal::inb(DATA_PORT); }
    }
}

/// Send a command byte to the i8042 controller (port 0x64).
fn controller_cmd(cmd: u8) {
    wait_input();
    unsafe { crate::hal::outb(COMMAND_PORT, cmd); }
}

/// Send a data byte to the keyboard via port 0x60, return the ACK status.
fn kbd_write(data: u8) -> bool {
    wait_input();
    unsafe { crate::hal::outb(DATA_PORT, data); }
    if wait_output() {
        unsafe { crate::hal::inb(DATA_PORT) == KBD_ACK }
    } else {
        false
    }
}

// ── Initialisation ──────────────────────────────────────────────────────────

/// Fully initialise the i8042 PS/2 controller and keyboard.
///
/// After UEFI `ExitBootServices()`, the controller state is undefined —
/// keyboard interrupts (IRQ1) may be disabled and the keyboard port may
/// be inhibited.  This routine mirrors the startup sequence used by the
/// ReactOS `i8042prt` driver:
///
/// 1. Flush stale data from the output buffer.
/// 2. Disable both PS/2 ports during setup.
/// 3. Read the Controller Configuration Byte (CCB).
/// 4. Set IRQ1 enable + scancode translation, clear keyboard-disable.
/// 5. Write back the CCB.
/// 6. Run the controller self-test (command 0xAA → expect 0x55).
/// 7. Re-enable the keyboard port (command 0xAE).
/// 8. Reset the keyboard (0xFF → ACK + 0xAA).
/// 9. Turn off LEDs and enable scanning (0xF4).
pub fn init() {
    // 1. Flush any stale bytes
    flush_output_buffer();

    // 2. Disable both ports while we reconfigure
    controller_cmd(CMD_DISABLE_KBD);     // 0xAD — disable first PS/2 port
    controller_cmd(0xA7);                // Disable second PS/2 port (mouse)

    // 3. Flush again (disabling ports may produce a byte)
    flush_output_buffer();

    // 4. Read the current Controller Configuration Byte
    controller_cmd(CMD_READ_CONFIG);     // 0x20
    let config = if wait_output() {
        unsafe { crate::hal::inb(DATA_PORT) }
    } else {
        // Default fallback: translation on, system flag set
        CCB_TRANSLATE | CCB_SYSTEM_FLAG
    };

    // 5. Build new CCB:
    //    - Set  bit 0 (keyboard IRQ1 enable)
    //    - Set  bit 2 (system flag — POST passed)
    //    - Set  bit 6 (scancode translation: set 2 → set 1)
    //    - Clear bit 4 (don't inhibit keyboard clock)
    //    Keep mouse bits as-is; mouse::init() will configure them later.
    let new_config = (config | CCB_KBD_INT_ENAB | CCB_SYSTEM_FLAG | CCB_TRANSLATE)
        & !CCB_KBD_DISAB;

    // 6. Write back the CCB
    controller_cmd(CMD_WRITE_CONFIG);    // 0x60
    wait_input();
    unsafe { crate::hal::outb(DATA_PORT, new_config); }

    // 7. Controller self-test (0xAA → expect 0x55)
    controller_cmd(CMD_SELF_TEST);       // 0xAA
    if wait_output() {
        let result = unsafe { crate::hal::inb(DATA_PORT) };
        if result != SELF_TEST_OK {
            crate::serial_println!(
                "[KEYBOARD] i8042 self-test failed (got 0x{:02x}, expected 0x55)",
                result
            );
            // Some controllers clobber the CCB after self-test — rewrite it.
            controller_cmd(CMD_WRITE_CONFIG);
            wait_input();
            unsafe { crate::hal::outb(DATA_PORT, new_config); }
        }
    } else {
        crate::serial_println!("[KEYBOARD] i8042 self-test: no response (continuing)");
    }

    // 8. Re-enable the keyboard port (clock line)
    controller_cmd(CMD_ENABLE_KBD);      // 0xAE

    // 9. Reset the keyboard device
    flush_output_buffer();
    if kbd_write(KBD_CMD_RESET) {        // 0xFF
        // After ACK, keyboard sends 0xAA (Basic Assurance Test passed)
        if wait_output() {
            let _bat = unsafe { crate::hal::inb(DATA_PORT) };
        }
    }

    // 10. Set LEDs off
    if kbd_write(KBD_CMD_SET_LEDS) {     // 0xED
        kbd_write(0x00);                 // All LEDs off
    }

    // 11. Enable scanning
    kbd_write(KBD_CMD_ENABLE_SCAN);      // 0xF4

    // 12. Final flush — discard any spurious bytes
    flush_output_buffer();

    crate::serial_println!("[KEYBOARD] PS/2 keyboard driver initialized (extended)");
    crate::serial_println!(
        "[KEYBOARD] i8042 CCB: 0x{:02x} → 0x{:02x} (IRQ1={}, translate={})",
        config,
        new_config,
        if new_config & CCB_KBD_INT_ENAB != 0 { "on" } else { "off" },
        if new_config & CCB_TRANSLATE != 0 { "on" } else { "off" },
    );
}

/// Convert a PS/2 Set 1 scancode to an ASCII character (legacy API).
///
/// Kept for backward compatibility. Delegates to `process_scancode()`.
pub fn scancode_to_ascii(scancode: u8) -> Option<char> {
    match process_scancode(scancode) {
        Some(KeyEvent::Char(ch)) => Some(ch),
        Some(KeyEvent::Enter) => Some('\n'),
        Some(KeyEvent::Backspace) => Some('\x08'),
        Some(KeyEvent::Tab) => Some('\t'),
        _ => None,
    }
}

/// Process a raw PS/2 Set 1 scancode and return a `KeyEvent`.
///
/// Handles extended prefix (0xE0), modifier tracking, and CapsLock toggle.
pub fn process_scancode(scancode: u8) -> Option<KeyEvent> {
    // SAFETY: Single-threaded keyboard handling (interrupts serialize access).
    unsafe {
        // Extended scancode prefix
        if scancode == 0xE0 {
            EXTENDED_PREFIX = true;
            return None;
        }

        let is_extended = EXTENDED_PREFIX;
        EXTENDED_PREFIX = false;

        // Key release (bit 7 set)
        if scancode & 0x80 != 0 {
            let released = scancode & 0x7F;
            if is_extended {
                match released {
                    0x38 => ALT_PRESSED = false,  // Right Alt release
                    0x1D => CTRL_PRESSED = false,  // Right Ctrl release
                    _ => {}
                }
            } else {
                match released {
                    0x2A | 0x36 => SHIFT_PRESSED = false,
                    0x1D => CTRL_PRESSED = false,
                    0x38 => ALT_PRESSED = false,
                    _ => {}
                }
            }
            return None;
        }

        // Extended key presses (preceded by 0xE0)
        if is_extended {
            return match scancode {
                0x48 => Some(KeyEvent::ArrowUp),
                0x50 => Some(KeyEvent::ArrowDown),
                0x4B => Some(KeyEvent::ArrowLeft),
                0x4D => Some(KeyEvent::ArrowRight),
                0x47 => Some(KeyEvent::Home),
                0x4F => Some(KeyEvent::End),
                0x53 => Some(KeyEvent::Delete),
                0x52 => Some(KeyEvent::Insert),
                0x49 => Some(KeyEvent::PageUp),
                0x51 => Some(KeyEvent::PageDown),
                0x1D => { CTRL_PRESSED = true; None }  // Right Ctrl
                0x38 => { ALT_PRESSED = true; None }   // Right Alt
                _ => None,
            };
        }

        // Modifier key presses
        match scancode {
            0x2A | 0x36 => { SHIFT_PRESSED = true; return None; }
            0x1D => { CTRL_PRESSED = true; return None; }
            0x38 => { ALT_PRESSED = true; return None; }
            0x3A => { CAPS_LOCK = !CAPS_LOCK; return None; }
            _ => {}
        }

        let shift = SHIFT_PRESSED;
        let ctrl = CTRL_PRESSED;
        let alt = ALT_PRESSED;
        let caps = CAPS_LOCK;

        // Special keys
        match scancode {
            0x01 => return Some(KeyEvent::Escape),
            0x0E => return Some(KeyEvent::Backspace),
            0x0F => return Some(KeyEvent::Tab),
            0x1C => return Some(KeyEvent::Enter),
            // Function keys F1-F12
            0x3B => return Some(KeyEvent::FKey(1)),
            0x3C => return Some(KeyEvent::FKey(2)),
            0x3D => return Some(KeyEvent::FKey(3)),
            0x3E => return Some(KeyEvent::FKey(4)),
            0x3F => return Some(KeyEvent::FKey(5)),
            0x40 => return Some(KeyEvent::FKey(6)),
            0x41 => return Some(KeyEvent::FKey(7)),
            0x42 => return Some(KeyEvent::FKey(8)),
            0x43 => return Some(KeyEvent::FKey(9)),
            0x44 => return Some(KeyEvent::FKey(10)),
            0x57 => return Some(KeyEvent::FKey(11)),
            0x58 => return Some(KeyEvent::FKey(12)),
            _ => {}
        }

        // Map scancode to base character
        let base_char = match scancode {
            0x39 => Some(' '),
            // Number row
            0x02 => Some(if shift { '!' } else { '1' }),
            0x03 => Some(if shift { '@' } else { '2' }),
            0x04 => Some(if shift { '#' } else { '3' }),
            0x05 => Some(if shift { '$' } else { '4' }),
            0x06 => Some(if shift { '%' } else { '5' }),
            0x07 => Some(if shift { '^' } else { '6' }),
            0x08 => Some(if shift { '&' } else { '7' }),
            0x09 => Some(if shift { '*' } else { '8' }),
            0x0A => Some(if shift { '(' } else { '9' }),
            0x0B => Some(if shift { ')' } else { '0' }),
            0x0C => Some(if shift { '_' } else { '-' }),
            0x0D => Some(if shift { '+' } else { '=' }),
            // QWERTY row
            0x10 => Some(letter('q', shift, caps)),
            0x11 => Some(letter('w', shift, caps)),
            0x12 => Some(letter('e', shift, caps)),
            0x13 => Some(letter('r', shift, caps)),
            0x14 => Some(letter('t', shift, caps)),
            0x15 => Some(letter('y', shift, caps)),
            0x16 => Some(letter('u', shift, caps)),
            0x17 => Some(letter('i', shift, caps)),
            0x18 => Some(letter('o', shift, caps)),
            0x19 => Some(letter('p', shift, caps)),
            0x1A => Some(if shift { '{' } else { '[' }),
            0x1B => Some(if shift { '}' } else { ']' }),
            // ASDF row
            0x1E => Some(letter('a', shift, caps)),
            0x1F => Some(letter('s', shift, caps)),
            0x20 => Some(letter('d', shift, caps)),
            0x21 => Some(letter('f', shift, caps)),
            0x22 => Some(letter('g', shift, caps)),
            0x23 => Some(letter('h', shift, caps)),
            0x24 => Some(letter('j', shift, caps)),
            0x25 => Some(letter('k', shift, caps)),
            0x26 => Some(letter('l', shift, caps)),
            0x27 => Some(if shift { ':' } else { ';' }),
            0x28 => Some(if shift { '"' } else { '\'' }),
            0x29 => Some(if shift { '~' } else { '`' }),
            // ZXCV row
            0x2B => Some(if shift { '|' } else { '\\' }),
            0x2C => Some(letter('z', shift, caps)),
            0x2D => Some(letter('x', shift, caps)),
            0x2E => Some(letter('c', shift, caps)),
            0x2F => Some(letter('v', shift, caps)),
            0x30 => Some(letter('b', shift, caps)),
            0x31 => Some(letter('n', shift, caps)),
            0x32 => Some(letter('m', shift, caps)),
            0x33 => Some(if shift { '<' } else { ',' }),
            0x34 => Some(if shift { '>' } else { '.' }),
            0x35 => Some(if shift { '?' } else { '/' }),
            _ => None,
        };

        if let Some(ch) = base_char {
            if ctrl && ch.is_ascii_alphabetic() {
                return Some(KeyEvent::Ctrl(ch.to_ascii_lowercase()));
            }
            if alt && ch.is_ascii_alphabetic() {
                return Some(KeyEvent::Alt(ch.to_ascii_lowercase()));
            }
            return Some(KeyEvent::Char(ch));
        }

        None
    }
}

/// Apply CapsLock + Shift to a letter character.
fn letter(base: char, shift: bool, caps: bool) -> char {
    let upper = shift ^ caps; // XOR: shift inverts caps state
    if upper { base.to_ascii_uppercase() } else { base }
}
