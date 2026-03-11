//! X11 event packet builders.
//!
//! Each X11 event is exactly 32 bytes.  The helpers in this module
//! encode individual event types into that 32-byte buffer.

use crate::x11::proto;

// ── Generic pack helpers ──────────────────────────────────────────────────────

#[inline]
fn w16(buf: &mut [u8], off: usize, v: u16) {
    let b = v.to_le_bytes();
    buf[off] = b[0]; buf[off+1] = b[1];
}

#[inline]
fn w32(buf: &mut [u8], off: usize, v: u32) {
    let b = v.to_le_bytes();
    buf[off] = b[0]; buf[off+1] = b[1]; buf[off+2] = b[2]; buf[off+3] = b[3];
}

// ── Expose event (12) ─────────────────────────────────────────────────────────
//
//   [0]   12 (Expose)
//   [1]   0 (pad)
//   [2-3] sequence-number
//   [4-7] window
//   [8-9]  x  [10-11] y
//   [12-13] width  [14-15] height
//   [16-17] count (0 = last in series)
//   [18-31] pad

pub fn encode_expose(seq: u16, window: u32,
                     x: i16, y: i16, w: u16, h: u16) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_EXPOSE;
    w16(&mut b, 2, seq);
    w32(&mut b, 4, window);
    w16(&mut b, 8,  x as u16);
    w16(&mut b, 10, y as u16);
    w16(&mut b, 12, w);
    w16(&mut b, 14, h);
    // count = 0 (final expose in series)
    b
}

// ── ConfigureNotify event (22) ────────────────────────────────────────────────
//
//   [0]   22
//   [1]   0
//   [2-3] seq
//   [4-7] event-window
//   [8-11] window
//   [12-15] above-sibling (0=None)
//   [16-17] x  [18-19] y
//   [20-21] w  [22-23] h
//   [24-25] border-width
//   [26]  override-redirect
//   [27-31] pad

pub fn encode_configure_notify(seq: u16, window: u32,
                                x: i16, y: i16, w: u16, h: u16,
                                border: u16) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_CONFIGURE_NOTIFY;
    w16(&mut b, 2, seq);
    w32(&mut b, 4, window);   // event
    w32(&mut b, 8, window);   // window
    // above-sibling = 0
    w16(&mut b, 16, x as u16);
    w16(&mut b, 18, y as u16);
    w16(&mut b, 20, w);
    w16(&mut b, 22, h);
    w16(&mut b, 24, border);
    b
}

// ── MapNotify event (19) ──────────────────────────────────────────────────────
//
//   [0]   19
//   [1]   0
//   [2-3] seq
//   [4-7] event-window
//   [8-11] window
//   [12]  override-redirect
//   [13-31] pad

pub fn encode_map_notify(seq: u16, window: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_MAP_NOTIFY;
    w16(&mut b, 2, seq);
    w32(&mut b, 4, window);
    w32(&mut b, 8, window);
    b
}

// ── UnmapNotify event (18) ────────────────────────────────────────────────────

pub fn encode_unmap_notify(seq: u16, window: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_UNMAP_NOTIFY;
    w16(&mut b, 2, seq);
    w32(&mut b, 4, window);
    w32(&mut b, 8, window);
    b
}

// ── DestroyNotify event (17) ──────────────────────────────────────────────────

pub fn encode_destroy_notify(seq: u16, window: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_DESTROY_NOTIFY;
    w16(&mut b, 2, seq);
    w32(&mut b, 4, window);
    w32(&mut b, 8, window);
    b
}

// ── KeyPress / KeyRelease events (2/3) ───────────────────────────────────────
//
//   [0]   2 or 3
//   [1]   keycode
//   [2-3] seq
//   [4-7] time
//   [8-11] root
//   [12-15] event-window
//   [16-19] child (0)
//   [20-21] root-x  [22-23] root-y
//   [24-25] event-x  [26-27] event-y
//   [28-29] state (modifier mask)
//   [30]  same-screen
//   [31]  pad

pub fn encode_key_press(seq: u16, window: u32, keycode: u8, state: u16,
                        tick: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_KEY_PRESS;
    b[1] = keycode;
    w16(&mut b, 2, seq);
    w32(&mut b, 4, tick);
    w32(&mut b, 8, proto::ROOT_WINDOW_ID);
    w32(&mut b, 12, window);
    w16(&mut b, 28, state);
    b[30] = 1; // same-screen = true
    b
}

pub fn encode_key_release(seq: u16, window: u32, keycode: u8, state: u16,
                           tick: u32) -> [u8; 32] {
    let mut b = encode_key_press(seq, window, keycode, state, tick);
    b[0] = proto::EVENT_KEY_RELEASE;
    b
}

// ── ButtonPress / ButtonRelease events (4/5) ─────────────────────────────────

pub fn encode_button_press(seq: u16, window: u32, button: u8,
                            rx: i16, ry: i16, state: u16, tick: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_BUTTON_PRESS;
    b[1] = button;
    w16(&mut b, 2, seq);
    w32(&mut b, 4, tick);
    w32(&mut b, 8, proto::ROOT_WINDOW_ID);
    w32(&mut b, 12, window);
    w16(&mut b, 20, rx as u16);
    w16(&mut b, 22, ry as u16);
    w16(&mut b, 24, rx as u16);
    w16(&mut b, 26, ry as u16);
    w16(&mut b, 28, state);
    b[30] = 1;
    b
}

pub fn encode_button_release(seq: u16, window: u32, button: u8,
                               rx: i16, ry: i16, state: u16, tick: u32) -> [u8; 32] {
    let mut b = encode_button_press(seq, window, button, rx, ry, state, tick);
    b[0] = proto::EVENT_BUTTON_RELEASE;
    b
}

// ── MotionNotify event (6) ────────────────────────────────────────────────────

pub fn encode_motion_notify(seq: u16, window: u32,
                             rx: i16, ry: i16, state: u16, tick: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_MOTION_NOTIFY;
    b[1] = 0; // detail = Normal
    w16(&mut b, 2, seq);
    w32(&mut b, 4, tick);
    w32(&mut b, 8, proto::ROOT_WINDOW_ID);
    w32(&mut b, 12, window);
    w16(&mut b, 20, rx as u16);
    w16(&mut b, 22, ry as u16);
    w16(&mut b, 24, rx as u16);
    w16(&mut b, 26, ry as u16);
    w16(&mut b, 28, state);
    b[30] = 1;
    b
}

// ── ClientMessage event (33) ──────────────────────────────────────────────────

pub fn encode_client_message(seq: u16, window: u32,
                              type_: u32, data32: [u32; 5]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = proto::EVENT_CLIENT_MESSAGE;
    b[1] = 32; // format
    w16(&mut b, 2, seq);
    w32(&mut b, 4, window);
    w32(&mut b, 8, type_);
    for (i, &v) in data32.iter().enumerate() {
        w32(&mut b, 12 + i * 4, v);
    }
    b
}
