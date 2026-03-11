//! X11 resource types — Window, Pixmap, GC, Colormap, Picture.
//!
//! Pixmaps carry a heap-allocated pixel buffer (`Vec<u8>`) that enables
//! off-screen rendering and RENDER-extension compositing.
//! Resources are identified by their X resource-id (`u32`).

extern crate alloc;
use alloc::vec::Vec;

// ── Property storage ──────────────────────────────────────────────────────────

pub const MAX_PROPERTIES:    usize = 16;
pub const MAX_PROPERTY_DATA: usize = 512;

#[derive(Clone)]
pub struct PropertyEntry {
    pub name:   u32,                         // atom id (XA_WM_NAME etc.)
    pub type_:  u32,                         // type atom (XA_STRING etc.)
    pub format: u8,                          // 8, 16, or 32 bits per unit
    pub data:   [u8; MAX_PROPERTY_DATA],     // raw bytes (truncated at MAX)
    pub len:    usize,                       // actual byte count stored
}

impl PropertyEntry {
    pub const fn empty() -> Self {
        PropertyEntry {
            name:   0,
            type_:  0,
            format: 8,
            data:   [0; MAX_PROPERTY_DATA],
            len:    0,
        }
    }
}

// ── Window ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WindowData {
    pub parent:          u32,
    pub x:               i16,
    pub y:               i16,
    pub width:           u16,
    pub height:          u16,
    pub depth:           u8,
    pub border_width:    u16,
    /// 1 = InputOutput, 2 = InputOnly
    pub class:           u16,
    pub visual:          u32,
    pub event_mask:      u32,
    pub background_pixel: u32,
    pub mapped:          bool,
    pub properties:      [Option<PropertyEntry>; MAX_PROPERTIES],
}

impl WindowData {
    pub fn new(parent: u32, x: i16, y: i16, w: u16, h: u16, depth: u8,
               border_width: u16, class: u16, visual: u32) -> Self {
        WindowData {
            parent, x, y, width: w, height: h, depth,
            border_width, class, visual,
            event_mask: 0,
            background_pixel: 0xFFFFFFFF,
            mapped: false,
            properties: [const { None }; MAX_PROPERTIES],
        }
    }

    /// Store or replace a property.
    pub fn set_property(&mut self, name: u32, type_: u32, format: u8,
                        data: &[u8], mode: u8) {
        // mode: 0=Replace, 1=Prepend, 2=Append
        // For simplicity we treat Prepend/Append as Replace if prop exists
        let copy_len = data.len().min(MAX_PROPERTY_DATA);
        // Find existing slot
        for slot in self.properties.iter_mut() {
            if let Some(p) = slot {
                if p.name == name {
                    match mode {
                        1 => { /* prepend: insert data before existing */
                            let old_len = p.len;
                            let new_len = (copy_len + old_len).min(MAX_PROPERTY_DATA);
                            // shift old data right
                            p.data.copy_within(0..old_len.min(MAX_PROPERTY_DATA - copy_len),
                                               copy_len);
                            p.data[..copy_len].copy_from_slice(&data[..copy_len]);
                            p.len = new_len;
                        }
                        2 => { /* append: insert data after existing */
                            let start = p.len;
                            let room  = MAX_PROPERTY_DATA.saturating_sub(start);
                            let add   = copy_len.min(room);
                            p.data[start..start + add].copy_from_slice(&data[..add]);
                            p.len = start + add;
                        }
                        _ => { /* replace */
                            p.type_  = type_;
                            p.format = format;
                            p.data[..copy_len].copy_from_slice(&data[..copy_len]);
                            // zero remainder
                            for b in p.data[copy_len..].iter_mut() { *b = 0; }
                            p.len = copy_len;
                        }
                    }
                    return;
                }
            }
        }
        // New property
        for slot in self.properties.iter_mut() {
            if slot.is_none() {
                let mut p = PropertyEntry::empty();
                p.name   = name;
                p.type_  = type_;
                p.format = format;
                p.data[..copy_len].copy_from_slice(&data[..copy_len]);
                p.len    = copy_len;
                *slot    = Some(p);
                return;
            }
        }
        // Table full — silent drop
    }

    pub fn get_property(&self, name: u32) -> Option<&PropertyEntry> {
        for slot in self.properties.iter() {
            if let Some(p) = slot {
                if p.name == name { return Some(p); }
            }
        }
        None
    }

    pub fn delete_property(&mut self, name: u32) {
        for slot in self.properties.iter_mut() {
            if let Some(p) = slot {
                if p.name == name { *slot = None; return; }
            }
        }
    }
}

// ── Pixmap ────────────────────────────────────────────────────────────────────

/// Per-pixmap pixel buffer.
///
/// Layout: row-major, 4 bytes per pixel, BGRA byte order (same as compositor
/// backbuffer), dimensions `width × height`.  Index of pixel (col, row) is
/// `(row * width + col) * 4`.
pub struct PixmapData {
    pub width:  u16,
    pub height: u16,
    pub depth:  u8,
    /// Pixel data: `width * height * 4` bytes, BGRA-ordered.
    pub pixels: Vec<u8>,
}

impl PixmapData {
    /// Allocate a zeroed pixel buffer for `width × height`.
    pub fn new(width: u16, height: u16, depth: u8) -> Self {
        let n = (width as usize) * (height as usize) * 4;
        PixmapData { width, height, depth, pixels: alloc::vec![0u8; n] }
    }

    /// Fill an axis-aligned rectangle with `color` (0xAARRGGBB).
    /// Clamps to pixmap bounds; silently ignores out-of-range areas.
    pub fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, color: u32) {
        let a = ((color >> 24) & 0xFF) as u8;
        let r = ((color >> 16) & 0xFF) as u8;
        let g = ((color >>  8) & 0xFF) as u8;
        let b = ( color        & 0xFF) as u8;
        let pw = self.width as i32;
        let ph = self.height as i32;
        let x0 = x.max(0); let y0 = y.max(0);
        let x1 = (x + w).min(pw); let y1 = (y + h).min(ph);
        if x0 >= x1 || y0 >= y1 { return; }
        for row in y0..y1 {
            for col in x0..x1 {
                let off = ((row * pw + col) * 4) as usize;
                self.pixels[off]     = b;
                self.pixels[off + 1] = g;
                self.pixels[off + 2] = r;
                self.pixels[off + 3] = a;
            }
        }
    }

    /// Copy a sub-rectangle from `src` into `self` at `(dst_x, dst_y)`.
    /// Both rects are clamped to their respective pixmap bounds.
    pub fn blit_from(&mut self, src: &PixmapData,
                     src_x: i32, src_y: i32,
                     dst_x: i32, dst_y: i32,
                     w: i32,     h: i32) {
        let sw = src.width  as i32;
        let sh = src.height as i32;
        let dw = self.width  as i32;
        let dh = self.height as i32;
        for row in 0..h {
            let sy = src_y + row;
            let dy = dst_y + row;
            if sy < 0 || sy >= sh || dy < 0 || dy >= dh { continue; }
            for col in 0..w {
                let sx = src_x + col;
                let dx = dst_x + col;
                if sx < 0 || sx >= sw || dx < 0 || dx >= dw { continue; }
                let so = ((sy * sw + sx) * 4) as usize;
                let do_ = ((dy * dw + dx) * 4) as usize;
                self.pixels[do_]     = src.pixels[so];
                self.pixels[do_ + 1] = src.pixels[so + 1];
                self.pixels[do_ + 2] = src.pixels[so + 2];
                self.pixels[do_ + 3] = src.pixels[so + 3];
            }
        }
    }

    /// Alpha-composite `src` over `self` at `(dst_x, dst_y)` (Porter-Duff Over).
    pub fn composite_over(&mut self, src: &PixmapData,
                          src_x: i32, src_y: i32,
                          dst_x: i32, dst_y: i32,
                          w: i32,     h: i32) {
        let sw = src.width  as i32;
        let sh = src.height as i32;
        let dw = self.width  as i32;
        let dh = self.height as i32;
        for row in 0..h {
            let sy = src_y + row;
            let dy = dst_y + row;
            if sy < 0 || sy >= sh || dy < 0 || dy >= dh { continue; }
            for col in 0..w {
                let sx = src_x + col;
                let dx = dst_x + col;
                if sx < 0 || sx >= sw || dx < 0 || dx >= dw { continue; }
                let so = ((sy * sw + sx) * 4) as usize;
                let do_ = ((dy * dw + dx) * 4) as usize;
                let sa = src.pixels[so + 3] as u32;
                if sa == 255 {
                    self.pixels[do_]     = src.pixels[so];
                    self.pixels[do_ + 1] = src.pixels[so + 1];
                    self.pixels[do_ + 2] = src.pixels[so + 2];
                    self.pixels[do_ + 3] = 255;
                } else if sa > 0 {
                    let ia = 255 - sa;
                    self.pixels[do_]     = ((src.pixels[so]     as u32 * sa + self.pixels[do_]     as u32 * ia) / 255) as u8;
                    self.pixels[do_ + 1] = ((src.pixels[so + 1] as u32 * sa + self.pixels[do_ + 1] as u32 * ia) / 255) as u8;
                    self.pixels[do_ + 2] = ((src.pixels[so + 2] as u32 * sa + self.pixels[do_ + 2] as u32 * ia) / 255) as u8;
                    self.pixels[do_ + 3] = (sa + self.pixels[do_ + 3] as u32 * ia / 255) as u8;
                }
            }
        }
    }
}

// ── Picture (RENDER extension) ────────────────────────────────────────────────

/// A RENDER extension Picture — wraps a Drawable (Window or Pixmap).
pub struct PictureData {
    /// The Window or Pixmap resource ID this picture is bound to.
    pub drawable: u32,
    /// PictFormat ID chosen at CreatePicture time.
    pub format:   u32,
}

// ── GC (Graphics Context) ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct GcData {
    /// GXcopy = 3 (default)
    pub function:   u8,
    pub foreground: u32,
    pub background: u32,
    pub line_width: u32,
    pub fill_style: u8,
    pub font:       u32,
}

impl GcData {
    pub fn default() -> Self {
        GcData { function: 3, foreground: 0, background: 0xFFFFFF, line_width: 0, fill_style: 0, font: 0 }
    }

    /// Apply a GC value-list mask + values (both are variable-length).
    pub fn apply_value_list(&mut self, mask: u32, values: &[u8]) {
        let mut idx = 0usize;
        let mut read_u32 = |data: &[u8], cursor: &mut usize| -> u32 {
            if *cursor + 3 < data.len() {
                let v = u32::from_le_bytes([data[*cursor], data[*cursor+1],
                                            data[*cursor+2], data[*cursor+3]]);
                *cursor += 4;
                v
            } else { *cursor += 4; 0 }
        };
        if mask & crate::x11::proto::GC_FUNCTION   != 0 { self.function   = read_u32(values, &mut idx) as u8; }
        if mask & crate::x11::proto::GC_FOREGROUND != 0 { self.foreground = read_u32(values, &mut idx); }
        if mask & crate::x11::proto::GC_BACKGROUND != 0 { self.background = read_u32(values, &mut idx); }
        if mask & crate::x11::proto::GC_LINE_WIDTH != 0 { self.line_width = read_u32(values, &mut idx); }
        if mask & crate::x11::proto::GC_FONT       != 0 { self.font       = read_u32(values, &mut idx); }
    }
}

// ── Resource enum ─────────────────────────────────────────────────────────────

pub enum ResourceBody {
    Window(WindowData),
    Pixmap(PixmapData),
    Gc(GcData),
    Picture(PictureData),
}

pub struct Resource {
    pub id:   u32,
    pub body: ResourceBody,
}

// ── Per-client resource table ─────────────────────────────────────────────────

pub const MAX_RESOURCES: usize = 256;

pub struct ResourceTable {
    pub entries: [Option<Resource>; MAX_RESOURCES],
}

impl ResourceTable {
    pub const fn new() -> Self {
        ResourceTable { entries: [const { None }; MAX_RESOURCES] }
    }

    pub fn insert(&mut self, id: u32, body: ResourceBody) -> bool {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(Resource { id, body });
                return true;
            }
        }
        false
    }

    pub fn remove(&mut self, id: u32) -> bool {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().map_or(false, |r| r.id == id) {
                *slot = None;
                return true;
            }
        }
        false
    }

    pub fn get_window_mut(&mut self, id: u32) -> Option<&mut WindowData> {
        for slot in self.entries.iter_mut() {
            if let Some(r) = slot {
                if r.id == id {
                    if let ResourceBody::Window(ref mut w) = r.body { return Some(w); }
                    return None;
                }
            }
        }
        None
    }

    pub fn get_gc_mut(&mut self, id: u32) -> Option<&mut GcData> {
        for slot in self.entries.iter_mut() {
            if let Some(r) = slot {
                if r.id == id {
                    if let ResourceBody::Gc(ref mut g) = r.body { return Some(g); }
                    return None;
                }
            }
        }
        None
    }

    pub fn get_pixmap_mut(&mut self, id: u32) -> Option<&mut PixmapData> {
        for slot in self.entries.iter_mut() {
            if let Some(r) = slot {
                if r.id == id {
                    if let ResourceBody::Pixmap(ref mut p) = r.body { return Some(p); }
                    return None;
                }
            }
        }
        None
    }

    pub fn get_pixmap(&self, id: u32) -> Option<&PixmapData> {
        for slot in self.entries.iter() {
            if let Some(r) = slot {
                if r.id == id {
                    if let ResourceBody::Pixmap(ref p) = r.body { return Some(p); }
                    return None;
                }
            }
        }
        None
    }

    pub fn get_picture_mut(&mut self, id: u32) -> Option<&mut PictureData> {
        for slot in self.entries.iter_mut() {
            if let Some(r) = slot {
                if r.id == id {
                    if let ResourceBody::Picture(ref mut p) = r.body { return Some(p); }
                    return None;
                }
            }
        }
        None
    }

    pub fn get_picture(&self, id: u32) -> Option<&PictureData> {
        for slot in self.entries.iter() {
            if let Some(r) = slot {
                if r.id == id {
                    if let ResourceBody::Picture(ref p) = r.body { return Some(p); }
                    return None;
                }
            }
        }
        None
    }

    /// Return the drawable (Window or Pixmap) that a Picture is bound to.
    pub fn picture_drawable(&self, pic_id: u32) -> Option<u32> {
        self.get_picture(pic_id).map(|p| p.drawable)
    }

    /// Returns (width, height, depth) for any Drawable (Window or Pixmap).
    pub fn get_drawable_geom(&self, id: u32) -> Option<(u16, u16, u8)> {
        for slot in self.entries.iter() {
            if let Some(r) = slot {
                if r.id == id {
                    return match &r.body {
                        ResourceBody::Window(w)  => Some((w.width, w.height, w.depth)),
                        ResourceBody::Pixmap(p)  => Some((p.width, p.height, p.depth)),
                        ResourceBody::Gc(_)      => None,
                        ResourceBody::Picture(_) => None,
                    };
                }
            }
        }
        None
    }

    pub fn has(&self, id: u32) -> bool {
        self.entries.iter().any(|s| s.as_ref().map_or(false, |r| r.id == id))
    }
}
