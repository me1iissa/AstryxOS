//! Window Class — Registration and lookup (like WNDCLASSEX)
//!
//! A window class defines a template that is referenced when creating windows.
//! The global class registry stores all registered classes.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::Mutex;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Standard cursor shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorType {
    Arrow,
    Hand,
    IBeam,
    SizeNS,
    SizeWE,
    SizeNWSE,
    SizeNESW,
    Wait,
}

/// Class-level style flags.
#[derive(Debug, Clone, Copy)]
pub struct ClassStyle {
    pub redraw_on_resize: bool,
    pub double_clicks: bool,
}

impl ClassStyle {
    /// Default class style.
    pub fn default_style() -> Self {
        Self {
            redraw_on_resize: true,
            double_clicks: false,
        }
    }
}

/// A window class defines the template for windows.
pub struct WindowClass {
    pub name: String,
    /// Default background colour for windows of this class (ARGB).
    pub bg_color: u32,
    pub cursor: CursorType,
    pub style: ClassStyle,
}

// ---------------------------------------------------------------------------
// Global class registry
// ---------------------------------------------------------------------------

static CLASS_REGISTRY: Mutex<BTreeMap<String, WindowClass>> = Mutex::new(BTreeMap::new());

/// Register a new window class.  Returns `true` on success, `false` if a class
/// with the same name is already registered.
pub fn register_class(class: WindowClass) -> bool {
    let mut registry = CLASS_REGISTRY.lock();
    if registry.contains_key(&class.name) {
        return false;
    }
    let name = class.name.clone();
    registry.insert(name, class);
    true
}

/// Look up a class by name and pass it to a closure.
pub fn with_class<F, R>(name: &str, f: F) -> Option<R>
where
    F: FnOnce(&WindowClass) -> R,
{
    let registry = CLASS_REGISTRY.lock();
    registry.get(name).map(f)
}

/// Unregister a window class by name.  Returns `true` if removed.
pub fn unregister_class(name: &str) -> bool {
    let mut registry = CLASS_REGISTRY.lock();
    registry.remove(name).is_some()
}

/// Find a class by name — returns `true` if it exists.
pub fn class_exists(name: &str) -> bool {
    let registry = CLASS_REGISTRY.lock();
    registry.contains_key(name)
}

// ---------------------------------------------------------------------------
// Built-in classes
// ---------------------------------------------------------------------------

/// Register the default built-in window classes.  Called once during WM init.
pub fn init_default_classes() {
    let defaults: &[(&str, u32, CursorType)] = &[
        ("Desktop", 0xFF000000, CursorType::Arrow),  // black desktop background
        ("Button",  0xFFCCCCCC, CursorType::Hand),    // light gray button
        ("Static",  0xFF1E1E1E, CursorType::Arrow),   // dark background
        ("Edit",    0xFF2D2D30, CursorType::IBeam),    // editor dark background
    ];

    for &(name, bg, cursor) in defaults {
        let cls = WindowClass {
            name: String::from(name),
            bg_color: bg,
            cursor,
            style: ClassStyle::default_style(),
        };
        register_class(cls);
    }

    crate::serial_println!("[WM] Registered {} default window classes", defaults.len());
}
