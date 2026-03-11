//! X11 wire protocol constants and byte-order helpers.
//!
//! All values use little-endian byte order (the only byte order AstryxOS
//! negotiates with clients; big-endian clients are refused at setup).

// ── Byte-order negotiation ────────────────────────────────────────────────────
pub const BYTE_ORDER_LSB: u8 = 0x6C; // 'l' — little-endian client

// ── Protocol versions ─────────────────────────────────────────────────────────
pub const PROTOCOL_MAJOR: u16 = 11;
pub const PROTOCOL_MINOR: u16 = 0;

// ── Display parameters ────────────────────────────────────────────────────────
pub const SCREEN_WIDTH:       u16 = 1920;
pub const SCREEN_HEIGHT:      u16 = 1080;
pub const SCREEN_WIDTH_MM:    u16 = 527; // ~27" at 96 dpi
pub const SCREEN_HEIGHT_MM:   u16 = 296;
pub const ROOT_DEPTH:         u8  = 24;
pub const ROOT_VISUAL:        u32 = 32;  // visual id for TrueColor 24bpp
pub const DEFAULT_COLORMAP:   u32 = 1;
pub const WHITE_PIXEL:        u32 = 0x00FFFFFF;
pub const BLACK_PIXEL:        u32 = 0x00000000;
pub const ROOT_WINDOW_ID:     u32 = 1;
pub const VENDOR_STRING:      &[u8] = b"Xastryx";

// ── Request opcodes ──────────────────────────────────────────────────────────
pub const OP_CREATE_WINDOW:          u8 = 1;
pub const OP_CHANGE_WINDOW_ATTRS:    u8 = 2;
pub const OP_GET_WINDOW_ATTRS:       u8 = 3;
pub const OP_DESTROY_WINDOW:         u8 = 4;
pub const OP_MAP_WINDOW:             u8 = 8;
pub const OP_UNMAP_WINDOW:           u8 = 10;
pub const OP_CONFIGURE_WINDOW:       u8 = 12;
pub const OP_GET_GEOMETRY:           u8 = 14;
pub const OP_QUERY_TREE:             u8 = 15;
pub const OP_INTERN_ATOM:            u8 = 16;
pub const OP_GET_ATOM_NAME:          u8 = 17;
pub const OP_CHANGE_PROPERTY:        u8 = 18;
pub const OP_DELETE_PROPERTY:        u8 = 19;
pub const OP_GET_PROPERTY:           u8 = 20;
pub const OP_LIST_PROPERTIES:        u8 = 21;
pub const OP_SELECT_INPUT:           u8 = 25;
pub const OP_GRAB_POINTER:           u8 = 26;
pub const OP_UNGRAB_POINTER:         u8 = 27;
pub const OP_GRAB_BUTTON:            u8 = 28;
pub const OP_UNGRAB_BUTTON:          u8 = 29;
pub const OP_GRAB_KEYBOARD:          u8 = 31;
pub const OP_UNGRAB_KEYBOARD:        u8 = 32;
pub const OP_WARP_POINTER:           u8 = 41;
pub const OP_SET_INPUT_FOCUS:        u8 = 42;
pub const OP_GET_INPUT_FOCUS:        u8 = 43;
pub const OP_QUERY_KEYMAP:           u8 = 44;
pub const OP_OPEN_FONT:              u8 = 45;
pub const OP_CLOSE_FONT:             u8 = 46;
pub const OP_QUERY_FONT:             u8 = 47;
pub const OP_LIST_FONTS:             u8 = 49;
pub const OP_CREATE_PIXMAP:          u8 = 53;
pub const OP_FREE_PIXMAP:            u8 = 54;
pub const OP_CREATE_GC:              u8 = 55;
pub const OP_CHANGE_GC:              u8 = 56;
pub const OP_COPY_GC:                u8 = 57;
pub const OP_FREE_GC:                u8 = 60;
pub const OP_CLEAR_AREA:             u8 = 61;
pub const OP_COPY_AREA:              u8 = 62;
pub const OP_POLY_FILL_RECTANGLE:    u8 = 70;
pub const OP_PUT_IMAGE:              u8 = 72;
pub const OP_IMAGE_TEXT8:            u8 = 76;
pub const OP_IMAGE_TEXT16:           u8 = 77;
pub const OP_CREATE_COLORMAP:        u8 = 78;
pub const OP_FREE_COLORMAP:          u8 = 79;
pub const OP_ALLOC_COLOR:            u8 = 84;
pub const OP_QUERY_COLORS:           u8 = 91;
pub const OP_QUERY_EXTENSION:        u8 = 98;
pub const OP_LIST_EXTENSIONS:        u8 = 99;
pub const OP_CHANGE_KEYBOARD_MAPPING:u8 = 100;
pub const OP_GET_KEYBOARD_MAPPING:   u8 = 101;
pub const OP_CHANGE_KEYBOARD_CONTROL:u8 = 102;
pub const OP_BELL:                   u8 = 104;
pub const OP_SET_POINTER_MAPPING:    u8 = 116;
pub const OP_GET_POINTER_MAPPING:    u8 = 117;
pub const OP_SET_MODIFIER_MAPPING:   u8 = 118;
pub const OP_GET_MODIFIER_MAPPING:   u8 = 119;
pub const OP_NO_OPERATION:           u8 = 127;

// ── Event types ───────────────────────────────────────────────────────────────
pub const EVENT_KEY_PRESS:         u8 = 2;
pub const EVENT_KEY_RELEASE:       u8 = 3;
pub const EVENT_BUTTON_PRESS:      u8 = 4;
pub const EVENT_BUTTON_RELEASE:    u8 = 5;
pub const EVENT_MOTION_NOTIFY:     u8 = 6;
pub const EVENT_ENTER_NOTIFY:      u8 = 7;
pub const EVENT_LEAVE_NOTIFY:      u8 = 8;
pub const EVENT_EXPOSE:            u8 = 12;
pub const EVENT_CONFIGURE_NOTIFY:  u8 = 22;
pub const EVENT_MAP_NOTIFY:        u8 = 19;
pub const EVENT_UNMAP_NOTIFY:      u8 = 18;
pub const EVENT_DESTROY_NOTIFY:    u8 = 17;
pub const EVENT_CLIENT_MESSAGE:    u8 = 33;

// ── Event masks ───────────────────────────────────────────────────────────────
pub const EVENT_MASK_KEY_PRESS:          u32 = 0x0001;
pub const EVENT_MASK_KEY_RELEASE:        u32 = 0x0002;
pub const EVENT_MASK_BUTTON_PRESS:       u32 = 0x0004;
pub const EVENT_MASK_BUTTON_RELEASE:     u32 = 0x0008;
pub const EVENT_MASK_POINTER_MOTION:     u32 = 0x0040;
pub const EVENT_MASK_EXPOSURE:           u32 = 0x8000;
pub const EVENT_MASK_STRUCTURE_NOTIFY:   u32 = 0x0002_0000;
pub const EVENT_MASK_SUBSTRUCTURE_NOTIFY:u32 = 0x0008_0000;

// ── CW value-list masks ───────────────────────────────────────────────────────
pub const CW_BACK_PIXMAP:       u32 = 0x0001;
pub const CW_BACK_PIXEL:        u32 = 0x0002;
pub const CW_BORDER_PIXMAP:     u32 = 0x0004;
pub const CW_BORDER_PIXEL:      u32 = 0x0008;
pub const CW_EVENT_MASK:        u32 = 0x0800;

// ── GC value-list masks ───────────────────────────────────────────────────────
pub const GC_FUNCTION:          u32 = 0x0001;
pub const GC_FOREGROUND:        u32 = 0x0004;
pub const GC_BACKGROUND:        u32 = 0x0008;
pub const GC_LINE_WIDTH:        u32 = 0x0010;
pub const GC_FONT:              u32 = 0x4000;

// ── ConfigureWindow value-list masks ─────────────────────────────────────────
pub const CW_X:      u16 = 0x0001;
pub const CW_Y:      u16 = 0x0002;
pub const CW_WIDTH:  u16 = 0x0004;
pub const CW_HEIGHT: u16 = 0x0008;

// ── PutImage formats ─────────────────────────────────────────────────────────
pub const IMAGE_FORMAT_XYPIXMAP: u8 = 1;
pub const IMAGE_FORMAT_ZPIXMAP:  u8 = 2;

// ── GetProperty return types ──────────────────────────────────────────────────
pub const ATOM_ANY: u32 = 0;

// ── Error codes ───────────────────────────────────────────────────────────────
pub const ERR_REQUEST:     u8 = 1;
pub const ERR_VALUE:       u8 = 2;
pub const ERR_WINDOW:      u8 = 3;
pub const ERR_PIXMAP:      u8 = 4;
pub const ERR_ATOM:        u8 = 5;
pub const ERR_CURSOR:      u8 = 6;
pub const ERR_FONT:        u8 = 7;
pub const ERR_MATCH:       u8 = 8;
pub const ERR_DRAWABLE:    u8 = 9;
pub const ERR_ACCESS:      u8 = 10;
pub const ERR_ALLOC:       u8 = 11;
pub const ERR_COLORMAP:    u8 = 12;
pub const ERR_GC:          u8 = 13;
pub const ERR_ID_CHOICE:   u8 = 14;
pub const ERR_NAME:        u8 = 15;
pub const ERR_LENGTH:      u8 = 16;
pub const ERR_IMPLEMENTATION: u8 = 17;

// ── Visual class ─────────────────────────────────────────────────────────────
pub const VISUAL_CLASS_TRUECOLOR: u8 = 4;

// ── Wire helpers ─────────────────────────────────────────────────────────────

/// Read a little-endian u16 from `buf[off..off+2]`.
#[inline]
pub fn read_u16le(buf: &[u8], off: usize) -> u16 {
    if off + 1 >= buf.len() { return 0; }
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Read a little-endian u32 from `buf[off..off+4]`.
#[inline]
pub fn read_u32le(buf: &[u8], off: usize) -> u32 {
    if off + 3 >= buf.len() { return 0; }
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Write a little-endian u16 into `buf[off..off+2]`.
#[inline]
pub fn write_u16le(buf: &mut [u8], off: usize, v: u16) {
    if off + 1 < buf.len() {
        let b = v.to_le_bytes();
        buf[off] = b[0]; buf[off + 1] = b[1];
    }
}

/// Write a little-endian u32 into `buf[off..off+4]`.
#[inline]
pub fn write_u32le(buf: &mut [u8], off: usize, v: u32) {
    if off + 3 < buf.len() {
        let b = v.to_le_bytes();
        buf[off] = b[0]; buf[off + 1] = b[1];
        buf[off + 2] = b[2]; buf[off + 3] = b[3];
    }
}

/// Pad `n` up to the next multiple of 4.
#[inline]
pub fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

// ── RENDER extension ──────────────────────────────────────────────────────────

/// Major opcode assigned to the RENDER extension by Xastryx.
pub const RENDER_MAJOR_OPCODE: u8 = 68;

// Minor opcodes
pub const RENDER_QUERY_VERSION:      u8 = 0;
pub const RENDER_QUERY_PICT_FORMATS: u8 = 1;
pub const RENDER_CREATE_PICTURE:     u8 = 4;
pub const RENDER_CHANGE_PICTURE:     u8 = 5;
pub const RENDER_FREE_PICTURE:       u8 = 7;
pub const RENDER_COMPOSITE:          u8 = 8;
pub const RENDER_FILL_RECTANGLES:    u8 = 22;

// Porter-Duff compositing operators
pub const RENDER_OP_CLEAR: u8 = 0;
pub const RENDER_OP_SRC:   u8 = 1;
pub const RENDER_OP_DST:   u8 = 2;
pub const RENDER_OP_OVER:  u8 = 3;

// Stable PictFormat IDs served by Xastryx.
// Clients discover these via QueryPictFormats and pass them to CreatePicture.
pub const PICT_FORMAT_ARGB32: u32 = 0x2000_0001; // depth=32, alpha/red/green/blue
pub const PICT_FORMAT_RGB24:  u32 = 0x2000_0002; // depth=24, no alpha
pub const PICT_FORMAT_A8:     u32 = 0x2000_0003; // depth=8,  alpha only
