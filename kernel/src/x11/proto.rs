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
pub const OP_DESTROY_SUBWINDOWS:     u8 = 5;
pub const OP_CHANGE_SAVE_SET:        u8 = 6;
pub const OP_REPARENT_WINDOW:        u8 = 7;
pub const OP_MAP_WINDOW:             u8 = 8;
pub const OP_MAP_SUBWINDOWS:         u8 = 9;
pub const OP_UNMAP_WINDOW:           u8 = 10;
pub const OP_UNMAP_SUBWINDOWS:       u8 = 11;
pub const OP_CIRCULATE_WINDOW:       u8 = 13;
pub const OP_TRANSLATE_COORDINATES:  u8 = 40;
pub const OP_ROTATE_PROPERTIES:      u8 = 114;
pub const OP_CONFIGURE_WINDOW:       u8 = 12;
pub const OP_GET_GEOMETRY:           u8 = 14;
pub const OP_QUERY_TREE:             u8 = 15;
pub const OP_INTERN_ATOM:            u8 = 16;
pub const OP_GET_ATOM_NAME:          u8 = 17;
pub const OP_CHANGE_PROPERTY:        u8 = 18;
pub const OP_DELETE_PROPERTY:        u8 = 19;
pub const OP_GET_PROPERTY:           u8 = 20;
pub const OP_LIST_PROPERTIES:        u8 = 21;
pub const OP_SET_SELECTION_OWNER:    u8 = 22;
pub const OP_GET_SELECTION_OWNER:    u8 = 23; // reply: owner window
pub const OP_CONVERT_SELECTION:      u8 = 24;
pub const OP_SEND_EVENT:             u8 = 25;
pub const OP_GRAB_POINTER:           u8 = 26;
pub const OP_UNGRAB_POINTER:         u8 = 27;
pub const OP_GRAB_BUTTON:            u8 = 28;
pub const OP_UNGRAB_BUTTON:          u8 = 29;
pub const OP_GRAB_KEYBOARD:          u8 = 31;
pub const OP_UNGRAB_KEYBOARD:        u8 = 32;
pub const OP_ALLOW_EVENTS:           u8 = 35;
pub const OP_GRAB_SERVER:            u8 = 36;
pub const OP_UNGRAB_SERVER:          u8 = 37;
pub const OP_QUERY_POINTER:          u8 = 38; // reply: pointer position
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
pub const OP_POLY_POINT:             u8 = 64;
pub const OP_POLY_LINE:              u8 = 65;
pub const OP_POLY_SEGMENT:           u8 = 66;
pub const OP_POLY_RECTANGLE:         u8 = 67;
pub const OP_POLY_ARC:               u8 = 68;
pub const OP_FILL_POLY:              u8 = 69;
pub const OP_POLY_FILL_RECTANGLE:    u8 = 70;
pub const OP_POLY_FILL_ARC:          u8 = 71;
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
pub const EVENT_FOCUS_IN:          u8 = 9;
pub const EVENT_FOCUS_OUT:         u8 = 10;
pub const EVENT_EXPOSE:            u8 = 12;
pub const EVENT_VISIBILITY_NOTIFY: u8 = 15;
pub const EVENT_CONFIGURE_NOTIFY:  u8 = 22;
pub const EVENT_MAP_NOTIFY:        u8 = 19;
pub const EVENT_UNMAP_NOTIFY:      u8 = 18;
pub const EVENT_DESTROY_NOTIFY:    u8 = 17;
pub const EVENT_PROPERTY_NOTIFY:   u8 = 28;
pub const EVENT_SELECTION_CLEAR:   u8 = 29;
pub const EVENT_SELECTION_REQUEST: u8 = 30;
pub const EVENT_SELECTION_NOTIFY:  u8 = 31;
pub const EVENT_CLIENT_MESSAGE:    u8 = 33;

// ── Event masks ───────────────────────────────────────────────────────────────
pub const EVENT_MASK_KEY_PRESS:          u32 = 0x0001;
pub const EVENT_MASK_KEY_RELEASE:        u32 = 0x0002;
pub const EVENT_MASK_BUTTON_PRESS:       u32 = 0x0004;
pub const EVENT_MASK_BUTTON_RELEASE:     u32 = 0x0008;
pub const EVENT_MASK_ENTER_WINDOW:       u32 = 0x0010;
pub const EVENT_MASK_POINTER_MOTION:     u32 = 0x0040;
pub const EVENT_MASK_EXPOSURE:           u32 = 0x8000;
pub const EVENT_MASK_VISIBILITY_CHANGE:  u32 = 0x0001_0000;
pub const EVENT_MASK_STRUCTURE_NOTIFY:   u32 = 0x0002_0000;
pub const EVENT_MASK_SUBSTRUCTURE_NOTIFY:u32 = 0x0008_0000;
pub const EVENT_MASK_FOCUS_CHANGE:       u32 = 0x0020_0000;
pub const EVENT_MASK_PROPERTY_CHANGE:    u32 = 0x0040_0000;

// ── CW value-list masks ───────────────────────────────────────────────────────
pub const CW_BACK_PIXMAP:       u32 = 0x0001;
pub const CW_BACK_PIXEL:        u32 = 0x0002;
pub const CW_BORDER_PIXMAP:     u32 = 0x0004;
pub const CW_BORDER_PIXEL:      u32 = 0x0008;
pub const CW_BIT_GRAVITY:       u32 = 0x0010;
pub const CW_WIN_GRAVITY:       u32 = 0x0020;
pub const CW_BACKING_STORE:     u32 = 0x0040;
pub const CW_BACKING_PLANES:    u32 = 0x0080;
pub const CW_BACKING_PIXEL:     u32 = 0x0100;
pub const CW_OVERRIDE_REDIRECT: u32 = 0x0200;
pub const CW_SAVE_UNDER:        u32 = 0x0400;
pub const CW_EVENT_MASK:        u32 = 0x0800;
pub const CW_DO_NOT_PROPAGATE:  u32 = 0x1000;
pub const CW_COLORMAP:          u32 = 0x2000;
pub const CW_CURSOR:            u32 = 0x4000;

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
/// Extension major opcodes are in the 128-255 range per X11 spec.
pub const RENDER_MAJOR_OPCODE: u8 = 139;

// Minor opcodes
pub const RENDER_QUERY_VERSION:      u8 = 0;
pub const RENDER_QUERY_PICT_FORMATS: u8 = 1;
pub const RENDER_CREATE_PICTURE:     u8 = 4;
pub const RENDER_CHANGE_PICTURE:     u8 = 5;
pub const RENDER_FREE_PICTURE:       u8 = 7;
pub const RENDER_COMPOSITE:          u8 = 8;
pub const RENDER_CREATE_GLYPH_SET:   u8 = 17;
pub const RENDER_FREE_GLYPH_SET:     u8 = 19;
pub const RENDER_ADD_GLYPHS:         u8 = 20;
pub const RENDER_FREE_GLYPHS:        u8 = 22;
pub const RENDER_COMPOSITE_GLYPHS8:  u8 = 23;
pub const RENDER_COMPOSITE_GLYPHS16: u8 = 24;
pub const RENDER_COMPOSITE_GLYPHS32: u8 = 25;
pub const RENDER_FILL_RECTANGLES:    u8 = 26; // was wrongly 22; FreeGlyphs=22, FillRects=26

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

// ── Extension major opcodes assigned by Xastryx ───────────────────────────────
// Each extension gets a unique major opcode (128-255 range for extensions).

// Extension major opcodes in 128-255 range (per X11 spec; core ops are 1-127).
pub const SHAPE_MAJOR_OPCODE:     u8 = 128; // SHAPE
pub const XTEST_MAJOR_OPCODE:     u8 = 132; // XTEST
pub const SYNC_MAJOR_OPCODE:      u8 = 134; // SYNC
pub const XKEYBOARD_MAJOR_OPCODE: u8 = 135; // XKEYBOARD
// RENDER = 139 (already defined above)
pub const XFIXES_MAJOR_OPCODE:    u8 = 140; // XFIXES
pub const DAMAGE_MAJOR_OPCODE:    u8 = 141; // DAMAGE
pub const COMPOSITE_MAJOR_OPCODE: u8 = 142; // COMPOSITE
pub const DPMS_MAJOR_OPCODE:      u8 = 145; // DPMS
pub const XINPUT_MAJOR_OPCODE:    u8 = 131; // XInputExtension (XI2)
pub const SHM_MAJOR_OPCODE:       u8 = 130; // MIT-SHM
pub const RANDR_MAJOR_OPCODE:     u8 = 143; // RANDR (RandR)
pub const GLX_MAJOR_OPCODE:       u8 = 146; // GLX

// QueryExtension event/error bases.  Per the X11 core protocol §QueryExtension,
// an extension that defines events reports its first_event (the event-code base
// from which the client offsets the extension's event numbers); one that defines
// errors reports its first_error.  Reporting 0 for an extension that DOES define
// events is a protocol violation: clients (libXi, libXext, libXrandr) build their
// incoming-event → extension dispatch maps keyed on first_event, and a 0 base
// makes them mis-route or drop the extension's events.  Real servers allocate
// these dynamically as extensions initialise; we use fixed, non-overlapping bases
// above the 64 core event codes, matching the per-extension event/error counts
// from each extension's published protocol (SHAPE: 1 event; XInput: events +
// 5 errors; XKEYBOARD: 1 event, 1 error; XFIXES: 1 event, 1 error; RANDR: 2
// events, 4 errors; DAMAGE: 1 event, 1 error; SYNC: 2 events, 2 errors; RENDER:
// 0 events, 5 errors).  Extensions with no events use first_event 0.
pub const SHAPE_FIRST_EVENT:     u8 = 64;  pub const SHAPE_FIRST_ERROR:     u8 = 0;
pub const XINPUT_FIRST_EVENT:    u8 = 66;  pub const XINPUT_FIRST_ERROR:    u8 = 129;
pub const XKEYBOARD_FIRST_EVENT: u8 = 85;  pub const XKEYBOARD_FIRST_ERROR: u8 = 137;
pub const XFIXES_FIRST_EVENT:    u8 = 87;  pub const XFIXES_FIRST_ERROR:    u8 = 140;
pub const RANDR_FIRST_EVENT:     u8 = 89;  pub const RANDR_FIRST_ERROR:     u8 = 147;
pub const DAMAGE_FIRST_EVENT:    u8 = 91;  pub const DAMAGE_FIRST_ERROR:    u8 = 152;
pub const SYNC_FIRST_EVENT:      u8 = 92;  pub const SYNC_FIRST_ERROR:      u8 = 153;
pub const RENDER_FIRST_EVENT:    u8 = 0;   pub const RENDER_FIRST_ERROR:    u8 = 142;
pub const SHM_FIRST_EVENT:       u8 = 65;  pub const SHM_FIRST_ERROR:       u8 = 128;
// GLX defines 14 errors (GLXBadContext..GLXBadProfileARB) and 0 events; per the
// GLX X-protocol encoding (OpenGL GLX extension §Protocol Encoding) first_event
// is 0 for an extension with no events.  We allocate the 14-error block at 156..
// (SYNC ends at 154, leaving 155 free; start at 156 for a one-code margin).
pub const GLX_FIRST_EVENT:       u8 = 0;   pub const GLX_FIRST_ERROR:       u8 = 156;

// ── MIT-SHM minor opcodes ──────────────────────────────────────────────────────
pub const SHM_QUERY_VERSION:  u8 = 0;
pub const SHM_ATTACH:         u8 = 1;
pub const SHM_DETACH:         u8 = 2;
pub const SHM_PUT_IMAGE:      u8 = 3;
pub const SHM_GET_IMAGE:      u8 = 4;
pub const SHM_CREATE_PIXMAP:  u8 = 5;

// ── XFIXES minor opcodes ───────────────────────────────────────────────────────
pub const XFIXES_QUERY_VERSION:       u8 = 0;
pub const XFIXES_CHANGE_SAVE_SET:     u8 = 1;
pub const XFIXES_SELECT_CURSOR_INPUT: u8 = 2;
pub const XFIXES_GET_CURSOR_IMAGE:    u8 = 3;
pub const XFIXES_CREATE_REGION:       u8 = 4; // and many more
pub const XFIXES_HIDE_CURSOR:         u8 = 29;
pub const XFIXES_SHOW_CURSOR:         u8 = 30;

// ── DAMAGE minor opcodes ───────────────────────────────────────────────────────
pub const DAMAGE_QUERY_VERSION:  u8 = 0;
pub const DAMAGE_CREATE:         u8 = 1;
pub const DAMAGE_DESTROY:        u8 = 2;
pub const DAMAGE_SUBTRACT:       u8 = 3;
pub const DAMAGE_ADD:            u8 = 4;

// ── XInputExtension minor opcodes ─────────────────────────────────────────────
// XI v1 (minors 1-39) and XI2 (minors 40-61) share the same XInputExtension
// major opcode (per X Input Extension Protocol §3).  libXi multiplexes
// based on the minor.  Public reference: X Input Extension Protocol
// Specification, XInput2 protocol XML.
//
// XI v1 — the subset commonly issued by toolkits during XOpenDevice / initial
// device discovery.  Each carries a reply.
pub const XI_V1_GET_EXTENSION_VERSION: u8 = 1;  // GetExtensionVersion
pub const XI_V1_LIST_INPUT_DEVICES:    u8 = 2;  // ListInputDevices
pub const XI_V1_OPEN_DEVICE:           u8 = 3;  // OpenDevice
pub const XI_V1_CLOSE_DEVICE:          u8 = 4;  // CloseDevice (no reply)
pub const XI_V1_GET_DEVICE_FOCUS:      u8 = 20; // GetDeviceFocus
pub const XI_V1_QUERY_DEVICE_STATE:    u8 = 30; // QueryDeviceState
//
// XI2.
pub const XI_QUERY_POINTER:        u8 = 40; // XIQueryPointer (reply)
pub const XI_GET_CLIENT_POINTER:   u8 = 45; // XIGetClientPointer (reply)
pub const XI_SELECT_EVENTS:        u8 = 46; // XISelectEvents (no reply)
pub const XI_QUERY_VERSION:        u8 = 47; // XIQueryVersion (reply)
pub const XI_QUERY_DEVICE:         u8 = 48; // XIQueryDevice (reply)
pub const XI_GET_FOCUS:            u8 = 50; // XIGetFocus (reply)
pub const XI_LIST_PROPERTIES:      u8 = 56; // XIListProperties (reply)
pub const XI_GET_PROPERTY:         u8 = 59; // XIGetProperty (reply)
pub const XI_GET_SELECTED_EVENTS:  u8 = 60; // XIGetSelectedEvents (reply)

// ── BIG-REQUESTS major opcode ─────────────────────────────────────────────────
// BIG-REQUESTS is a tiny protocol-negotiation extension: the client sends
// BigReqEnable (minor 0) and the server replies with the new maximum request
// length in 4-byte units.  We advertise 4 MiB (0x100_0000 bytes = 0x40_0000
// units).  No other opcodes are defined.
pub const BIGREQ_MAJOR_OPCODE: u8 = 133; // BIG-REQUESTS
pub const BIGREQ_ENABLE:       u8 = 0;   // BigReqEnable minor opcode

// New maximum request length in 4-byte units (4 MiB).
pub const BIGREQ_MAX_REQUEST_LEN: u32 = 0x0010_0000; // 4 MiB / 4

// ── COMPOSITE minor opcodes ───────────────────────────────────────────────────
pub const COMPOSITE_QUERY_VERSION:            u8 = 0;
pub const COMPOSITE_REDIRECT_WINDOW:          u8 = 1;
pub const COMPOSITE_UNREDIRECT_WINDOW:        u8 = 2;
pub const COMPOSITE_REDIRECT_SUBWINDOWS:      u8 = 3;
pub const COMPOSITE_UNREDIRECT_SUBWINDOWS:    u8 = 4;
pub const COMPOSITE_CREATE_REGION_FROM_BORDER_CLIP: u8 = 5;
pub const COMPOSITE_NAME_WINDOW_PIXMAP:       u8 = 6;
pub const COMPOSITE_GET_OVERLAY_WINDOW:       u8 = 7;
pub const COMPOSITE_RELEASE_OVERLAY_WINDOW:   u8 = 8;

// ── GLX extension (major opcode 146) ──────────────────────────────────────────
//
// Public reference: "OpenGL Graphics System: A Specification — GLX Extension"
// and the GLX Protocol Encoding.  The X server only performs the GLX *handshake*;
// with Mesa's software path the OpenGL rendering happens client-side in the
// application's own address space (direct rendering), so the server never sees a
// GL command stream — it only answers the metadata/bookkeeping requests below.
//
// GLX single-command request opcodes (the request's data[1] minor opcode).
pub const GLX_RENDER:                   u8 = 1;
pub const GLX_RENDER_LARGE:             u8 = 2;
pub const GLX_CREATE_CONTEXT:           u8 = 3;
pub const GLX_DESTROY_CONTEXT:          u8 = 4;
pub const GLX_MAKE_CURRENT:             u8 = 5;
pub const GLX_IS_DIRECT:                u8 = 6;
pub const GLX_QUERY_VERSION:            u8 = 7;
pub const GLX_WAIT_GL:                  u8 = 8;
pub const GLX_WAIT_X:                   u8 = 9;
pub const GLX_COPY_CONTEXT:             u8 = 10;
pub const GLX_SWAP_BUFFERS:             u8 = 11;
pub const GLX_USE_X_FONT:               u8 = 12;
pub const GLX_CREATE_GLX_PIXMAP:        u8 = 13;
pub const GLX_GET_VISUAL_CONFIGS:       u8 = 14;
pub const GLX_DESTROY_GLX_PIXMAP:       u8 = 15;
pub const GLX_VENDOR_PRIVATE:           u8 = 16;
pub const GLX_VENDOR_PRIVATE_WITH_REPLY:u8 = 17;
pub const GLX_QUERY_EXTENSIONS_STRING:  u8 = 18;
pub const GLX_QUERY_SERVER_STRING:      u8 = 19;
pub const GLX_CLIENT_INFO:              u8 = 20;
pub const GLX_GET_FB_CONFIGS:           u8 = 21;
pub const GLX_CREATE_PIXMAP:            u8 = 22;
pub const GLX_DESTROY_PIXMAP:           u8 = 23;
pub const GLX_CREATE_NEW_CONTEXT:       u8 = 24;
pub const GLX_QUERY_CONTEXT:            u8 = 25;
pub const GLX_MAKE_CONTEXT_CURRENT:     u8 = 26;
pub const GLX_CREATE_PBUFFER:           u8 = 27;
pub const GLX_DESTROY_PBUFFER:          u8 = 28;
pub const GLX_GET_DRAWABLE_ATTRIBUTES:  u8 = 29;
pub const GLX_CHANGE_DRAWABLE_ATTRIBUTES: u8 = 30;
pub const GLX_CREATE_WINDOW:            u8 = 31;
pub const GLX_DESTROY_WINDOW:           u8 = 32;
// GLX 1.4 ARB client-info variants (no reply): SetClientInfoARB=33,
// CreateContextAttribsARB=34, SetClientInfo2ARB=35.
pub const GLX_SET_CLIENT_INFO_ARB:           u8 = 33;
pub const GLX_CREATE_CONTEXT_ATTRIBS_ARB:    u8 = 34;
pub const GLX_SET_CLIENT_INFO_2ARB:          u8 = 35;

// GLX QueryServerString / QueryExtensionsString name tokens.
pub const GLX_STRING_VENDOR:     u32 = 1;
pub const GLX_STRING_VERSION:    u32 = 2;
pub const GLX_STRING_EXTENSIONS: u32 = 3;

// GLX config/visual attribute tokens (GLX Protocol Encoding, property arrays).
pub const GLX_TOK_USE_GL:         u32 = 1;
pub const GLX_TOK_BUFFER_SIZE:    u32 = 2;
pub const GLX_TOK_LEVEL:          u32 = 3;
pub const GLX_TOK_RGBA:           u32 = 4;
pub const GLX_TOK_DOUBLEBUFFER:   u32 = 5;
pub const GLX_TOK_STEREO:         u32 = 6;
pub const GLX_TOK_AUX_BUFFERS:    u32 = 7;
pub const GLX_TOK_RED_SIZE:       u32 = 8;
pub const GLX_TOK_GREEN_SIZE:     u32 = 9;
pub const GLX_TOK_BLUE_SIZE:      u32 = 10;
pub const GLX_TOK_ALPHA_SIZE:     u32 = 11;
pub const GLX_TOK_DEPTH_SIZE:     u32 = 12;
pub const GLX_TOK_STENCIL_SIZE:   u32 = 13;
pub const GLX_TOK_ACCUM_RED:      u32 = 14;
pub const GLX_TOK_ACCUM_GREEN:    u32 = 15;
pub const GLX_TOK_ACCUM_BLUE:     u32 = 16;
pub const GLX_TOK_ACCUM_ALPHA:    u32 = 17;
// FBConfig-only tokens (GLX 1.3).
pub const GLX_TOK_CONFIG_CAVEAT:  u32 = 0x20;
pub const GLX_TOK_X_VISUAL_TYPE:  u32 = 0x22;
pub const GLX_TOK_TRANSPARENT_TYPE: u32 = 0x23;
pub const GLX_TOK_VISUAL_ID:      u32 = 0x800B;
pub const GLX_TOK_DRAWABLE_TYPE:  u32 = 0x8010;
pub const GLX_TOK_RENDER_TYPE:    u32 = 0x8011;
pub const GLX_TOK_X_RENDERABLE:   u32 = 0x8012;
pub const GLX_TOK_FBCONFIG_ID:    u32 = 0x8013;
pub const GLX_TOK_MAX_PBUFFER_WIDTH:  u32 = 0x8016;
pub const GLX_TOK_MAX_PBUFFER_HEIGHT: u32 = 0x8017;
pub const GLX_TOK_MAX_PBUFFER_PIXELS: u32 = 0x8018;
// Token values.
pub const GLX_VAL_NONE:        u32 = 0x8000;
pub const GLX_VAL_TRUE_COLOR:  u32 = 0x8002;
pub const GLX_VAL_DIRECT_COLOR:u32 = 0x8003;
pub const GLX_VAL_RGBA_BIT:    u32 = 0x0000_0001;
pub const GLX_VAL_WINDOW_BIT:  u32 = 0x0000_0001;
pub const GLX_VAL_PIXMAP_BIT:  u32 = 0x0000_0002;
pub const GLX_VAL_PBUFFER_BIT: u32 = 0x0000_0004;
