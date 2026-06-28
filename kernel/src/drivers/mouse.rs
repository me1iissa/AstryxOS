//! PS/2 Mouse Driver
//!
//! Initializes the PS/2 mouse controller through the keyboard controller (port 0x64/0x60),
//! handles IRQ12 (vector 44) for mouse data packets.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use spin::Mutex;

// PS/2 controller ports
const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const COMMAND_PORT: u16 = 0x64;

/// Mouse state.
static MOUSE_X: AtomicI32 = AtomicI32::new(0);
static MOUSE_Y: AtomicI32 = AtomicI32::new(0);
static MOUSE_BUTTONS: AtomicU8 = AtomicU8::new(0);
static MOUSE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Mouse packet assembly state.
static PACKET_BYTE: AtomicU8 = AtomicU8::new(0);
static PACKET_BUF: Mutex<[u8; 3]> = Mutex::new([0; 3]);

/// Screen dimensions for clamping.
static SCREEN_WIDTH: AtomicI32 = AtomicI32::new(1024);
static SCREEN_HEIGHT: AtomicI32 = AtomicI32::new(768);

/// Wait for the PS/2 controller input buffer to be ready.
fn wait_input() {
    for _ in 0..100_000 {
        if unsafe { crate::hal::inb(STATUS_PORT) } & 0x02 == 0 {
            return;
        }
    }
}

/// Wait for the PS/2 controller output buffer to have data.
fn wait_output() {
    for _ in 0..100_000 {
        if unsafe { crate::hal::inb(STATUS_PORT) } & 0x01 != 0 {
            return;
        }
    }
}

/// Send a command to the mouse (via the PS/2 controller).
fn mouse_write(data: u8) {
    wait_input();
    unsafe { crate::hal::outb(COMMAND_PORT, 0xD4); } // Tell controller: next byte goes to mouse
    wait_input();
    unsafe { crate::hal::outb(DATA_PORT, data); }
}

/// Read a byte from the mouse.
fn mouse_read() -> u8 {
    wait_output();
    unsafe { crate::hal::inb(DATA_PORT) }
}

/// Initialize the PS/2 mouse.
pub fn init(width: u32, height: u32) {
    SCREEN_WIDTH.store(width as i32, Ordering::Relaxed);
    SCREEN_HEIGHT.store(height as i32, Ordering::Relaxed);

    // Enable auxiliary device (mouse) on the PS/2 controller
    wait_input();
    unsafe { crate::hal::outb(COMMAND_PORT, 0xA8); } // Enable auxiliary device

    // Configure the controller command byte (CCB) for the mouse:
    //   * bit 1 (0x02) — enable the mouse/aux IRQ12.
    //   * bit 5 (0x20) — mouse-clock DISABLE: must be CLEARED or the controller
    //     gates the aux clock and the device never streams movement packets
    //     (so no IRQ12 ever fires).  The keyboard's CCB write leaves bit 5 set
    //     ("keep mouse bits as-is"), and although the `0xA8` enable-aux command
    //     is specified to clear it, we must not depend on that side effect —
    //     clear bit 5 explicitly here so the aux clock is unconditionally on.
    // Reference: IBM PS/2 / 8042 keyboard-controller command-byte definition;
    // PC/AT keyboard controller specification (command byte bits 1 and 5).
    wait_input();
    unsafe { crate::hal::outb(COMMAND_PORT, 0x20); } // Read controller config byte
    wait_output();
    let config = unsafe { crate::hal::inb(DATA_PORT) };
    let new_config = (config | 0x02) & !0x20; // enable IRQ12, clear mouse-clock-disable
    wait_input();
    unsafe { crate::hal::outb(COMMAND_PORT, 0x60); } // Write controller config byte
    wait_input();
    unsafe { crate::hal::outb(DATA_PORT, new_config); }

    // Reset mouse
    mouse_write(0xFF);
    let _ack = mouse_read(); // ACK (0xFA)
    let _id1 = mouse_read(); // Pass (0xAA)
    let _id2 = mouse_read(); // ID (0x00)

    // Set defaults
    mouse_write(0xF6);
    let _ack = mouse_read();

    // Enable data reporting
    mouse_write(0xF4);
    let _ack = mouse_read();

    // Set cursor to center
    MOUSE_X.store(width as i32 / 2, Ordering::Relaxed);
    MOUSE_Y.store(height as i32 / 2, Ordering::Relaxed);

    MOUSE_INITIALIZED.store(true, Ordering::Relaxed);
    crate::serial_println!("[MOUSE] PS/2 mouse initialized ({}x{})", width, height);
}

/// Handle IRQ12 mouse interrupt data byte.
/// Called from the ISR — must be quick.
pub fn handle_irq() {
    if !MOUSE_INITIALIZED.load(Ordering::Relaxed) { return; }

    let byte = unsafe { crate::hal::inb(DATA_PORT) };
    let idx = PACKET_BYTE.load(Ordering::Relaxed);

    let mut buf = PACKET_BUF.lock();
    buf[idx as usize] = byte;

    if idx == 0 {
        // First byte: validate — bit 3 must be set (always 1 in standard PS/2)
        if byte & 0x08 == 0 {
            // Out of sync — reset
            return;
        }
        PACKET_BYTE.store(1, Ordering::Relaxed);
    } else if idx == 1 {
        PACKET_BYTE.store(2, Ordering::Relaxed);
    } else {
        // Third byte received — process the complete packet
        PACKET_BYTE.store(0, Ordering::Relaxed);

        let buttons = buf[0] & 0x07;
        let mut dx = buf[1] as i32;
        let mut dy = buf[2] as i32;

        // Sign extend
        if buf[0] & 0x10 != 0 { dx -= 256; }
        if buf[0] & 0x20 != 0 { dy -= 256; }

        // WSL2 XWayland delivers relative mouse deltas with both axes already
        // inverted before QEMU sees them.  QEMU's PS/2 layer then negates Y
        // again (standard PS/2 spec), but not X.  Net result: X needs one
        // explicit negation here; Y comes out correct without any negation.
        dx = -dx;

        // Update position
        let max_x = SCREEN_WIDTH.load(Ordering::Relaxed) - 1;
        let max_y = SCREEN_HEIGHT.load(Ordering::Relaxed) - 1;

        let new_x = (MOUSE_X.load(Ordering::Relaxed) + dx).clamp(0, max_x);
        let new_y = (MOUSE_Y.load(Ordering::Relaxed) + dy).clamp(0, max_y);

        MOUSE_X.store(new_x, Ordering::Relaxed);
        MOUSE_Y.store(new_y, Ordering::Relaxed);
        MOUSE_BUTTONS.store(buttons, Ordering::Relaxed);
    }
}

/// Get current mouse position.
pub fn position() -> (i32, i32) {
    (MOUSE_X.load(Ordering::Relaxed), MOUSE_Y.load(Ordering::Relaxed))
}

/// Update the screen bounds used for clamping (e.g. after SVGA mode change).
pub fn set_bounds(width: u32, height: u32) {
    SCREEN_WIDTH.store(width as i32, Ordering::Relaxed);
    SCREEN_HEIGHT.store(height as i32, Ordering::Relaxed);
    // Re-center cursor
    MOUSE_X.store(width as i32 / 2, Ordering::Relaxed);
    MOUSE_Y.store(height as i32 / 2, Ordering::Relaxed);
    crate::serial_println!("[MOUSE] Bounds updated to {}x{}", width, height);
}

/// Get mouse buttons state (bit 0=left, bit 1=right, bit 2=middle).
pub fn buttons() -> u8 {
    MOUSE_BUTTONS.load(Ordering::Relaxed)
}

/// Warp the cursor to an absolute position (clamped to screen bounds).
pub fn warp(x: i32, y: i32) {
    let max_x = SCREEN_WIDTH.load(Ordering::Relaxed) - 1;
    let max_y = SCREEN_HEIGHT.load(Ordering::Relaxed) - 1;
    MOUSE_X.store(x.clamp(0, max_x), Ordering::Relaxed);
    MOUSE_Y.store(y.clamp(0, max_y), Ordering::Relaxed);
}

/// Check if mouse is initialized.
pub fn is_initialized() -> bool {
    MOUSE_INITIALIZED.load(Ordering::Relaxed)
}

/// Best-effort read of the live i8042 controller command byte (CCB), for the
/// `mouse-state` kdb diagnostic.
///
/// Issues the `0x20` (read-config) controller command and returns the byte.
/// Bit 1 (0x02) = mouse IRQ enabled; bit 5 (0x20) = mouse-clock disabled (must
/// be 0 for the mouse to stream).  Returns `None` if the controller already has
/// an unread output byte on entry (a device packet in flight): issuing `0x20`
/// then would read that data byte instead of the config and could desync the
/// packet assembler, so we decline rather than corrupt the stream.  Interrupts
/// are masked across the command/read so the IRQ12 handler cannot race the read.
/// Reference: PC/AT 8042 keyboard-controller command byte; status-register OBF
/// (bit 0) / AUX (bit 5) flags.
pub fn read_ccb() -> Option<u8> {
    let mut flags: u64;
    // Save RFLAGS then mask interrupts so the IRQ12 handler cannot consume the
    // output byte between our `0x20` command and the `0x60` read.  Restoring the
    // saved RFLAGS re-enables interrupts only if they were enabled on entry.
    unsafe { core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options(nomem)); }
    // Decline if an output byte is already pending (OBF, status bit 0): consuming
    // it would steal a device packet byte and report garbage.
    let ccb = if unsafe { crate::hal::inb(STATUS_PORT) } & 0x01 != 0 {
        None
    } else {
        wait_input();
        unsafe { crate::hal::outb(COMMAND_PORT, 0x20); }
        wait_output();
        Some(unsafe { crate::hal::inb(DATA_PORT) })
    };
    unsafe { core::arch::asm!("push {}; popfq", in(reg) flags, options(nomem)); }
    ccb
}
