//! X11 built-in and dynamic atom table.
//!
//! X11 predefined atoms 1..68 are hardcoded here (matching the standard Xlib
//! list). Clients that call `InternAtom` for a name from this list get back
//! the standard ID. New (dynamic) atoms start at 69 and are stored in a
//! simple fixed-size table.

extern crate alloc;
use alloc::string::String;
use spin::Mutex;

// ── Built-in atoms (X11 specification, atoms 1–68) ───────────────────────────

pub const ATOM_PRIMARY:             u32 = 1;
pub const ATOM_SECONDARY:           u32 = 2;
pub const ATOM_ARC:                 u32 = 3;
pub const ATOM_ATOM:                u32 = 4;
pub const ATOM_BITMAP:              u32 = 5;
pub const ATOM_CARDINAL:            u32 = 6;
pub const ATOM_COLORMAP:            u32 = 7;
pub const ATOM_CURSOR:              u32 = 8;
pub const ATOM_CUT_BUFFER0:         u32 = 9;
pub const ATOM_CUT_BUFFER1:         u32 = 10;
pub const ATOM_CUT_BUFFER2:         u32 = 11;
pub const ATOM_CUT_BUFFER3:         u32 = 12;
pub const ATOM_CUT_BUFFER4:         u32 = 13;
pub const ATOM_CUT_BUFFER5:         u32 = 14;
pub const ATOM_CUT_BUFFER6:         u32 = 15;
pub const ATOM_CUT_BUFFER7:         u32 = 16;
pub const ATOM_DRAWABLE:            u32 = 17;
pub const ATOM_FONT:                u32 = 18;
pub const ATOM_INTEGER:             u32 = 19;
pub const ATOM_PIXMAP:              u32 = 20;
pub const ATOM_POINT:               u32 = 21;
pub const ATOM_RECTANGLE:           u32 = 22;
pub const ATOM_RESOURCE_MANAGER:    u32 = 23;
pub const ATOM_RGB_COLOR_MAP:       u32 = 24;
pub const ATOM_RGB_BEST_MAP:        u32 = 25;
pub const ATOM_RGB_BLUE_MAP:        u32 = 26;
pub const ATOM_RGB_DEFAULT_MAP:     u32 = 27;
pub const ATOM_RGB_GRAY_MAP:        u32 = 28;
pub const ATOM_RGB_GREEN_MAP:       u32 = 29;
pub const ATOM_RGB_RED_MAP:         u32 = 30;
pub const ATOM_STRING:              u32 = 31;
pub const ATOM_VISUALID:            u32 = 32;
pub const ATOM_WINDOW:              u32 = 33;
pub const ATOM_WM_COMMAND:          u32 = 34;
pub const ATOM_WM_HINTS:            u32 = 35;
pub const ATOM_WM_CLIENT_MACHINE:   u32 = 36;
pub const ATOM_WM_ICON_NAME:        u32 = 37;
pub const ATOM_WM_ICON_SIZE:        u32 = 38;
pub const ATOM_WM_NAME:             u32 = 39;
pub const ATOM_WM_NORMAL_HINTS:     u32 = 40;
pub const ATOM_WM_SIZE_HINTS:       u32 = 41;
pub const ATOM_WM_ZOOM_HINTS:       u32 = 42;
pub const ATOM_MIN_SPACE:           u32 = 43;
pub const ATOM_NORM_SPACE:          u32 = 44;
pub const ATOM_MAX_SPACE:           u32 = 45;
pub const ATOM_END_SPACE:           u32 = 46;
pub const ATOM_SUPERSCRIPT_X:       u32 = 47;
pub const ATOM_SUPERSCRIPT_Y:       u32 = 48;
pub const ATOM_SUBSCRIPT_X:         u32 = 49;
pub const ATOM_SUBSCRIPT_Y:         u32 = 50;
pub const ATOM_UNDERLINE_POSITION:  u32 = 51;
pub const ATOM_UNDERLINE_THICKNESS: u32 = 52;
pub const ATOM_STRIKEOUT_ASCENT:    u32 = 53;
pub const ATOM_STRIKEOUT_DESCENT:   u32 = 54;
pub const ATOM_ITALIC_ANGLE:        u32 = 55;
pub const ATOM_X_HEIGHT:            u32 = 56;
pub const ATOM_QUAD_WIDTH:          u32 = 57;
pub const ATOM_WEIGHT:              u32 = 58;
pub const ATOM_POINT_SIZE:          u32 = 59;
pub const ATOM_RESOLUTION:          u32 = 60;
pub const ATOM_COPYRIGHT:           u32 = 61;
pub const ATOM_NOTICE:              u32 = 62;
pub const ATOM_FONT_NAME:           u32 = 63;
pub const ATOM_FAMILY_NAME:         u32 = 64;
pub const ATOM_FULL_NAME:           u32 = 65;
pub const ATOM_CAP_HEIGHT:          u32 = 66;
pub const ATOM_WM_CLASS:            u32 = 67;
pub const ATOM_WM_TRANSIENT_FOR:    u32 = 68;

const BUILTIN_NAMES: [(&str, u32); 68] = [
    ("PRIMARY",             1), ("SECONDARY",            2),
    ("ARC",                 3), ("ATOM",                 4),
    ("BITMAP",              5), ("CARDINAL",             6),
    ("COLORMAP",            7), ("CURSOR",               8),
    ("CUT_BUFFER0",         9), ("CUT_BUFFER1",         10),
    ("CUT_BUFFER2",        11), ("CUT_BUFFER3",         12),
    ("CUT_BUFFER4",        13), ("CUT_BUFFER5",         14),
    ("CUT_BUFFER6",        15), ("CUT_BUFFER7",         16),
    ("DRAWABLE",           17), ("FONT",                18),
    ("INTEGER",            19), ("PIXMAP",              20),
    ("POINT",              21), ("RECTANGLE",           22),
    ("RESOURCE_MANAGER",   23), ("RGB_COLOR_MAP",       24),
    ("RGB_BEST_MAP",       25), ("RGB_BLUE_MAP",        26),
    ("RGB_DEFAULT_MAP",    27), ("RGB_GRAY_MAP",        28),
    ("RGB_GREEN_MAP",      29), ("RGB_RED_MAP",         30),
    ("STRING",             31), ("VISUALID",            32),
    ("WINDOW",             33), ("WM_COMMAND",          34),
    ("WM_HINTS",           35), ("WM_CLIENT_MACHINE",   36),
    ("WM_ICON_NAME",       37), ("WM_ICON_SIZE",        38),
    ("WM_NAME",            39), ("WM_NORMAL_HINTS",     40),
    ("WM_SIZE_HINTS",      41), ("WM_ZOOM_HINTS",       42),
    ("MIN_SPACE",          43), ("NORM_SPACE",          44),
    ("MAX_SPACE",          45), ("END_SPACE",           46),
    ("SUPERSCRIPT_X",      47), ("SUPERSCRIPT_Y",       48),
    ("SUBSCRIPT_X",        49), ("SUBSCRIPT_Y",         50),
    ("UNDERLINE_POSITION", 51), ("UNDERLINE_THICKNESS", 52),
    ("STRIKEOUT_ASCENT",   53), ("STRIKEOUT_DESCENT",   54),
    ("ITALIC_ANGLE",       55), ("X_HEIGHT",            56),
    ("QUAD_WIDTH",         57), ("WEIGHT",              58),
    ("POINT_SIZE",         59), ("RESOLUTION",          60),
    ("COPYRIGHT",          61), ("NOTICE",              62),
    ("FONT_NAME",          63), ("FAMILY_NAME",         64),
    ("FULL_NAME",          65), ("CAP_HEIGHT",          66),
    ("WM_CLASS",           67), ("WM_TRANSIENT_FOR",    68),
];

// ── Dynamic atom storage ──────────────────────────────────────────────────────

const MAX_DYNAMIC_ATOMS: usize = 128;
const FIRST_DYNAMIC_ATOM: u32  = 69;

struct AtomEntry {
    id:   u32,
    name: String,
}

struct AtomTable {
    entries: [Option<AtomEntry>; MAX_DYNAMIC_ATOMS],
    next_id: u32,
}

impl AtomTable {
    const fn new() -> Self {
        AtomTable {
            entries:  [const { None }; MAX_DYNAMIC_ATOMS],
            // next_id starts at 0 so this struct is BSS-eligible (zero-initialized).
            // intern() lazily sets it to FIRST_DYNAMIC_ATOM on first use.
            next_id: 0,
        }
    }
}

// SAFETY: AtomTable holds only integers + Strings; no raw pointers.
unsafe impl Send for AtomTable {}

static ATOMS: Mutex<AtomTable> = Mutex::new(AtomTable::new());

// ── Public API ────────────────────────────────────────────────────────────────

/// Look up or create an atom by name.  Returns the atom ID.
pub fn intern(name: &str, only_if_exists: bool) -> u32 {
    // Check built-in atoms first.
    for &(n, id) in BUILTIN_NAMES.iter() {
        if n == name { return id; }
    }

    // Search dynamic table.
    let mut guard = ATOMS.lock();
    for slot in guard.entries.iter() {
        if let Some(e) = slot {
            if e.name == name { return e.id; }
        }
    }

    if only_if_exists { return 0; } // None

    // Insert new atom.  Lazily initialize next_id on first use.
    if guard.next_id == 0 {
        guard.next_id = FIRST_DYNAMIC_ATOM;
    }
    let id = guard.next_id;
    guard.next_id += 1;
    for slot in guard.entries.iter_mut() {
        if slot.is_none() {
            *slot = Some(AtomEntry { id, name: String::from(name) });
            return id;
        }
    }
    0 // table full
}

/// Return the name of an atom, or `None` if unknown.
pub fn get_name(id: u32) -> Option<String> {
    // Built-in
    for &(n, bid) in BUILTIN_NAMES.iter() {
        if bid == id { return Some(String::from(n)); }
    }
    // Dynamic
    let guard = ATOMS.lock();
    for slot in guard.entries.iter() {
        if let Some(e) = slot {
            if e.id == id { return Some(e.name.clone()); }
        }
    }
    None
}
