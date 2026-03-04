//! Window message types and structures (NT-style constants).

// ── General window messages ────────────────────────────────────────────────
pub const WM_NULL: u32 = 0x0000;
pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_ACTIVATE: u32 = 0x0006;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_KILLFOCUS: u32 = 0x0008;
pub const WM_ENABLE: u32 = 0x000A;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_ERASEBKGND: u32 = 0x0014;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_TIMER: u32 = 0x0113;

// ── Keyboard messages ──────────────────────────────────────────────────────
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;

// ── Mouse messages ─────────────────────────────────────────────────────────
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;
pub const WM_MOUSEWHEEL: u32 = 0x020A;

// ── Non-client messages ────────────────────────────────────────────────────
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_NCMOUSEMOVE: u32 = 0x00A0;
pub const WM_NCLBUTTONDOWN: u32 = 0x00A1;
pub const WM_NCLBUTTONUP: u32 = 0x00A2;

// ── User-defined messages start here ───────────────────────────────────────
pub const WM_USER: u32 = 0x0400;

// ── Virtual key codes (subset) ─────────────────────────────────────────────
pub const VK_BACK: u64 = 0x08;
pub const VK_TAB: u64 = 0x09;
pub const VK_RETURN: u64 = 0x0D;
pub const VK_SHIFT: u64 = 0x10;
pub const VK_CONTROL: u64 = 0x11;
pub const VK_ALT: u64 = 0x12; // VK_MENU in Win32
pub const VK_ESCAPE: u64 = 0x1B;
pub const VK_SPACE: u64 = 0x20;
pub const VK_PAGEUP: u64 = 0x21;
pub const VK_PAGEDOWN: u64 = 0x22;
pub const VK_END: u64 = 0x23;
pub const VK_HOME: u64 = 0x24;
pub const VK_LEFT: u64 = 0x25;
pub const VK_UP: u64 = 0x26;
pub const VK_RIGHT: u64 = 0x27;
pub const VK_DOWN: u64 = 0x28;
pub const VK_DELETE: u64 = 0x2E;
pub const VK_F1: u64 = 0x70;
pub const VK_F2: u64 = 0x71;
pub const VK_F3: u64 = 0x72;
pub const VK_F4: u64 = 0x73;
pub const VK_F5: u64 = 0x74;
pub const VK_F6: u64 = 0x75;
pub const VK_F7: u64 = 0x76;
pub const VK_F8: u64 = 0x77;
pub const VK_F9: u64 = 0x78;
pub const VK_F10: u64 = 0x79;
pub const VK_F11: u64 = 0x7A;
pub const VK_F12: u64 = 0x7B;
// ASCII keys: 'A' = 0x41, '0' = 0x30, etc.

// ── OEM / punctuation virtual key codes (matches Win32) ────────────────────
pub const VK_OEM_1: u64 = 0xBA;      // ;:
pub const VK_OEM_PLUS: u64 = 0xBB;   // =+
pub const VK_OEM_COMMA: u64 = 0xBC;  // ,<
pub const VK_OEM_MINUS: u64 = 0xBD;  // -_
pub const VK_OEM_PERIOD: u64 = 0xBE; // .>
pub const VK_OEM_2: u64 = 0xBF;      // /?
pub const VK_OEM_3: u64 = 0xC0;      // `~
pub const VK_OEM_4: u64 = 0xDB;      // [{
pub const VK_OEM_5: u64 = 0xDC;      // \|
pub const VK_OEM_6: u64 = 0xDD;      // ]}
pub const VK_OEM_7: u64 = 0xDE;      // '"

// ── Mouse button flags for wparam ──────────────────────────────────────────
pub const MK_LBUTTON: u64 = 0x0001;
pub const MK_RBUTTON: u64 = 0x0002;
pub const MK_SHIFT: u64 = 0x0004;
pub const MK_CONTROL: u64 = 0x0008;
pub const MK_MBUTTON: u64 = 0x0010;

// ── Message struct ─────────────────────────────────────────────────────────

/// A window message.
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// Target window handle (0 = thread/system message).
    pub hwnd: u64,
    /// Message type (WM_*).
    pub msg: u32,
    /// First parameter (e.g. virtual key code).
    pub wparam: u64,
    /// Second parameter (e.g. packed mouse coordinates).
    pub lparam: u64,
    /// Tick count when message was posted.
    pub time: u64,
    /// Cursor X position when message was posted.
    pub pt_x: i32,
    /// Cursor Y position when message was posted.
    pub pt_y: i32,
}

impl Message {
    /// Create a new message with the given parameters. `time` and cursor
    /// position are zero-initialised; the posting layer fills them in.
    pub fn new(hwnd: u64, msg: u32, wparam: u64, lparam: u64) -> Self {
        Self {
            hwnd,
            msg,
            wparam,
            lparam,
            time: 0,
            pt_x: 0,
            pt_y: 0,
        }
    }

    /// Returns `true` if this is a mouse message (WM_MOUSEMOVE .. WM_MOUSEWHEEL).
    pub fn is_mouse_message(&self) -> bool {
        self.msg >= WM_MOUSEMOVE && self.msg <= WM_MOUSEWHEEL
    }

    /// Returns `true` if this is a keyboard message (WM_KEYDOWN .. WM_SYSKEYUP).
    pub fn is_keyboard_message(&self) -> bool {
        self.msg >= WM_KEYDOWN && self.msg <= WM_SYSKEYUP
    }
}

// ── Lparam helpers ─────────────────────────────────────────────────────────

/// Pack (x, y) into an lparam: low 32 bits = x, high 32 bits = y.
pub fn make_lparam(x: i32, y: i32) -> u64 {
    ((y as u32 as u64) << 32) | (x as u32 as u64)
}

/// Extract the X coordinate from a packed lparam.
pub fn get_x_lparam(lparam: u64) -> i32 {
    (lparam & 0xFFFF_FFFF) as i32
}

/// Extract the Y coordinate from a packed lparam.
pub fn get_y_lparam(lparam: u64) -> i32 {
    ((lparam >> 32) & 0xFFFF_FFFF) as i32
}
