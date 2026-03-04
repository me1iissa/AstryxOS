//! Device Context — drawing state container (analogous to Windows HDC).

extern crate alloc;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Brush fill style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrushStyle {
    Solid,
    /// Null brush — no fill.
    Null,
}

/// Pen stroke style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenStyle {
    Solid,
    Dash,
    /// Null pen — no outline.
    Null,
}

/// A pen defines how lines and borders are drawn.
#[derive(Debug, Clone, Copy)]
pub struct Pen {
    pub style: PenStyle,
    pub width: u32,
    pub color: u32, // ARGB
}

/// A brush defines how areas are filled.
#[derive(Debug, Clone, Copy)]
pub struct Brush {
    pub style: BrushStyle,
    pub color: u32, // ARGB
}

/// ROP2 raster operations for drawing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rop2 {
    /// Draw with pen color (default).
    CopyPen,
    /// Invert destination.
    Not,
    /// XOR with background.
    Xor,
    /// Always black.
    Black,
    /// Always white.
    White,
}

/// Background mode for text / hatched brushes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgMode {
    Transparent,
    Opaque,
}

/// Axis-aligned rectangle (left/top inclusive, right/bottom exclusive — GDI convention).
#[derive(Debug, Clone, Copy)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub fn new(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Self { left, top, right, bottom }
    }

    pub fn width(&self) -> i32 {
        self.right - self.left
    }

    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }

    /// Returns `true` if `(x, y)` lies inside the rectangle (exclusive right/bottom).
    pub fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.left && x < self.right && y >= self.top && y < self.bottom
    }

    /// Compute the intersection of two rectangles. Returns `None` if they don't overlap.
    pub fn intersect(&self, other: &Rect) -> Option<Rect> {
        let left = self.left.max(other.left);
        let top = self.top.max(other.top);
        let right = self.right.min(other.right);
        let bottom = self.bottom.min(other.bottom);
        if left < right && top < bottom {
            Some(Rect { left, top, right, bottom })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceContext
// ---------------------------------------------------------------------------

/// Device Context — holds all drawing state for a logical rendering target.
pub struct DeviceContext {
    pub id: u64,
    pub pen: Pen,
    pub brush: Brush,
    pub text_color: u32,
    pub bg_color: u32,
    pub bg_mode: BgMode,
    pub rop2: Rop2,
    /// Optional clipping rectangle; `None` means no clipping.
    pub clip_rect: Option<Rect>,
    /// Coordinate-origin X offset.
    pub origin_x: i32,
    /// Coordinate-origin Y offset.
    pub origin_y: i32,
}

impl DeviceContext {
    /// Create a `DeviceContext` with sensible defaults.
    pub fn new(id: u64) -> Self {
        Self {
            id,
            pen: Pen {
                style: PenStyle::Solid,
                width: 1,
                color: 0xFF000000, // opaque black
            },
            brush: Brush {
                style: BrushStyle::Solid,
                color: 0xFFFFFFFF, // opaque white
            },
            text_color: 0xFF000000,
            bg_color: 0xFFFFFFFF,
            bg_mode: BgMode::Opaque,
            rop2: Rop2::CopyPen,
            clip_rect: None,
            origin_x: 0,
            origin_y: 0,
        }
    }

    /// Select a new pen and return the previous one.
    pub fn select_pen(&mut self, pen: Pen) -> Pen {
        let old = self.pen;
        self.pen = pen;
        old
    }

    /// Select a new brush and return the previous one.
    pub fn select_brush(&mut self, brush: Brush) -> Brush {
        let old = self.brush;
        self.brush = brush;
        old
    }

    /// Set text foreground color; returns previous value.
    pub fn set_text_color(&mut self, color: u32) -> u32 {
        let old = self.text_color;
        self.text_color = color;
        old
    }

    /// Set background color; returns previous value.
    pub fn set_bg_color(&mut self, color: u32) -> u32 {
        let old = self.bg_color;
        self.bg_color = color;
        old
    }

    /// Set background mode; returns previous value.
    pub fn set_bg_mode(&mut self, mode: BgMode) -> BgMode {
        let old = self.bg_mode;
        self.bg_mode = mode;
        old
    }

    /// Set the clipping rectangle (`None` = no clip).
    pub fn set_clip_rect(&mut self, rect: Option<Rect>) {
        self.clip_rect = rect;
    }

    /// Set the coordinate origin offset.
    pub fn set_origin(&mut self, x: i32, y: i32) {
        self.origin_x = x;
        self.origin_y = y;
    }
}

// ---------------------------------------------------------------------------
// Global DC registry
// ---------------------------------------------------------------------------

static DC_REGISTRY: Mutex<BTreeMap<u64, DeviceContext>> = Mutex::new(BTreeMap::new());
static NEXT_DC_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a new Device Context with default state. Returns the DC handle (id).
pub fn create_dc() -> u64 {
    let id = NEXT_DC_ID.fetch_add(1, Ordering::Relaxed);
    let dc = DeviceContext::new(id);
    DC_REGISTRY.lock().insert(id, dc);
    id
}

/// Delete (free) a Device Context by handle.
pub fn delete_dc(id: u64) {
    DC_REGISTRY.lock().remove(&id);
}

/// Borrow a DC immutably inside a closure. Returns `None` if the id is invalid.
pub fn with_dc<F, R>(id: u64, f: F) -> Option<R>
where
    F: FnOnce(&DeviceContext) -> R,
{
    let reg = DC_REGISTRY.lock();
    reg.get(&id).map(f)
}

/// Borrow a DC mutably inside a closure. Returns `None` if the id is invalid.
pub fn with_dc_mut<F, R>(id: u64, f: F) -> Option<R>
where
    F: FnOnce(&mut DeviceContext) -> R,
{
    let mut reg = DC_REGISTRY.lock();
    reg.get_mut(&id).map(f)
}
