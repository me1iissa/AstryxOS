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
    pub override_redirect: bool,
    /// Background pixmap resource id (X core protocol `background-pixmap`).
    /// 0 = None, 1 = ParentRelative; any other value is a Pixmap id whose
    /// contents are tiled into the window on expose/clear (per CreateWindow
    /// / ChangeWindowAttributes / ClearArea semantics).
    pub background_pixmap: u32,
    pub properties:      [Option<PropertyEntry>; MAX_PROPERTIES],
    /// Pixel buffer (BGRA, width×height×4 bytes) for compositor blitting.
    /// Allocated on MapWindow with background_pixel fill.
    pub pixels:          alloc::vec::Vec<u8>,
    /// True once the window's persistent surface has had its background
    /// (background_pixel or background_pixmap) painted across its full extent.
    /// The X core protocol paints the background when a window first becomes
    /// viewable; subsequent draws (RENDER Composite, core arcs, PutImage) layer
    /// on top and must persist.  This flag makes the full-window background
    /// paint idempotent so a later MapWindow/ClearArea cannot clobber content
    /// already drawn into `pixels`.
    pub bg_painted:      bool,
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
            override_redirect: false,
            background_pixmap: 0,
            properties: [const { None }; MAX_PROPERTIES],
            pixels: alloc::vec::Vec::new(),
            bg_painted: false,
        }
    }

    /// Ensure pixel buffer is allocated (BGRA format, w×h×4 bytes).
    /// Called on MapWindow and before any drawing operation.
    ///
    /// On first allocation the surface is filled with the solid
    /// `background_pixel`.  For a window with a SOLID (or ParentRelative)
    /// background this IS the complete viewable-time background paint, so
    /// `bg_painted` is set — a later full-window `paint_window_background`
    /// (issued on MapWindow) then becomes a no-op and cannot clobber a client
    /// draw (e.g. a RENDER Composite) that landed in the surface first.  For a
    /// window with a real background-PIXMAP, the solid fill here is only a
    /// placeholder; the pixmap must still be tiled by `paint_window_background`,
    /// so `bg_painted` is left clear for that one-shot tiling paint to run.
    pub fn ensure_pixels(&mut self) {
        let needed = (self.width as usize) * (self.height as usize) * 4;
        if self.pixels.len() == needed { return; }
        self.pixels.resize(needed, 0);
        // Fill with background_pixel (convert RGB to BGRA)
        let bg = self.background_pixel;
        let r = ((bg >> 16) & 0xFF) as u8;
        let g = ((bg >> 8) & 0xFF) as u8;
        let b = (bg & 0xFF) as u8;
        for chunk in self.pixels.chunks_exact_mut(4) {
            chunk[0] = b; chunk[1] = g; chunk[2] = r; chunk[3] = 0xFF;
        }
        // background_pixmap: 0 = None, 1 = ParentRelative — both solid here.
        if self.background_pixmap <= 1 {
            self.bg_painted = true;
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

// ── Software rasteriser (core protocol geometry ops) ──────────────────────────
//
// Free functions operating on a flat BGRA pixel buffer (`width × height × 4`,
// little-endian B,G,R,A per pixel).  Both `WindowData::pixels` and
// `PixmapData::pixels` use this layout, so windows and pixmaps share these
// routines.  Coordinates are clipped to the buffer bounds; out-of-range writes
// are silently dropped.
//
// Colour input is the GC foreground as 0x00RRGGBB (X core protocol pixel for a
// 24-bit TrueColor visual); alpha is forced opaque so the compositor's OVER
// blend keeps the drawn pixels visible.
pub mod raster {
    /// Plot a single opaque pixel at `(x, y)` with colour `rgb` (0x00RRGGBB).
    #[inline]
    pub fn plot(px: &mut [u8], w: i32, h: i32, x: i32, y: i32, rgb: u32) {
        if x < 0 || y < 0 || x >= w || y >= h { return; }
        let off = ((y * w + x) * 4) as usize;
        if off + 3 >= px.len() { return; }
        px[off]     = ( rgb        & 0xFF) as u8; // B
        px[off + 1] = ((rgb >>  8) & 0xFF) as u8; // G
        px[off + 2] = ((rgb >> 16) & 0xFF) as u8; // R
        px[off + 3] = 0xFF;                        // A (opaque)
    }

    /// Fill a horizontal span `[x0, x1]` inclusive at row `y`.
    #[inline]
    fn span(px: &mut [u8], w: i32, h: i32, mut x0: i32, mut x1: i32, y: i32, rgb: u32) {
        if x0 > x1 { core::mem::swap(&mut x0, &mut x1); }
        for x in x0..=x1 { plot(px, w, h, x, y, rgb); }
    }

    /// Bresenham line from `(x0,y0)` to `(x1,y1)`.
    pub fn line(px: &mut [u8], w: i32, h: i32,
                mut x0: i32, mut y0: i32, x1: i32, y1: i32, rgb: u32) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;
        loop {
            plot(px, w, h, x0, y0, rgb);
            if x0 == x1 && y0 == y1 { break; }
            let e2 = 2 * err;
            if e2 >= dy { err += dy; x0 += sx; }
            if e2 <= dx { err += dx; y0 += sy; }
        }
    }

    /// Integer sqrt (floor) — Newton's method on u64.
    #[inline]
    fn isqrt(n: u64) -> u64 {
        if n == 0 { return 0; }
        let mut x = n;
        let mut y = (x + 1) / 2;
        while y < x { x = y; y = (x + n / x) / 2; }
        x
    }

    // X11 angles are in 1/64-degree units, measured CCW from the +x (3-o'clock)
    // direction.  A full ellipse is angle1=0, angle2=360*64=23040.  To test
    // membership without trig we map a point's (dx, dy) — in ellipse-normalised
    // space — into a 1/64-degree angle via a 256-entry integer atan table over
    // one octant, then mirror into the full circle.
    fn point_angle64(dx: i32, dy_up: i32) -> i32 {
        // dy_up is +up (mathematical orientation, already negated by caller).
        let (ax, ay) = (dx.unsigned_abs() as u64, dy_up.unsigned_abs() as u64);
        // angle within first octant [0,45°] = atan(min/max)
        let (lo, hi, swap) = if ay <= ax { (ay, ax, false) } else { (ax, ay, true) };
        let oct = if hi == 0 { 0 } else { ATAN_T[((lo * 256) / hi) as usize] as i32 };
        // oct ∈ [0, 45*64] = atan(lo/hi).  When ay>ax we measured atan(ax/ay),
        // which is the complement, so the in-quadrant angle is 90°-oct.
        let a = if swap { 90 * 64 - oct } else { oct };
        let q = match (dx >= 0, dy_up >= 0) {
            (true,  true)  => a,                 // Q1
            (false, true)  => 180 * 64 - a,      // Q2
            (false, false) => 180 * 64 + a,      // Q3
            (true,  false) => 360 * 64 - a,      // Q4
        };
        ((q % (360 * 64)) + 360 * 64) % (360 * 64)
    }

    #[inline]
    fn angle_in_sweep(a64: i32, angle1: i32, angle2: i32) -> bool {
        let full = 360 * 64;
        if angle2.abs() >= full { return true; }
        let start = ((angle1 % full) + full) % full;
        if angle2 >= 0 {
            let end = start + angle2;
            let a = if a64 < start { a64 + full } else { a64 };
            a >= start && a <= end
        } else {
            let end = start + angle2;
            let a = if a64 > start { a64 - full } else { a64 };
            a <= start && a >= end
        }
    }

    /// Fill the (portion of the) ellipse bounded by rect (x,y,bw,bh), sweeping
    /// from `angle1` for `angle2` (1/64-degree units), per X core PolyFillArc.
    /// For a full ellipse (|angle2| >= 360*64) the per-pixel angle test is
    /// skipped and whole scanline spans are filled.  Integer arithmetic only.
    pub fn fill_arc(px: &mut [u8], w: i32, h: i32,
                    x: i32, y: i32, bw: i32, bh: i32,
                    angle1: i32, angle2: i32, rgb: u32) {
        if bw <= 0 || bh <= 0 { return; }
        // Centre in doubled coordinates lands on an integer grid:
        //   2·cx = 2x+bw, 2·cy = 2y+bh.  Radii rx=bw/2, ry=bh/2.
        let cx2 = (2 * x + bw) as i64;    // 2·cx
        let cy2 = (2 * y + bh) as i64;    // 2·cy
        let bh2 = (bh as i64) * (bh as i64);
        let full = angle2.abs() >= 360 * 64;
        let y0 = y.max(0);
        let y1 = (y + bh).min(h);
        for py in y0..y1 {
            // dyn_ = 2·(py+0.5 - cy)
            let dyn_ = (2 * py + 1) as i64 - cy2;
            // half-width of the scanline span:
            //   half_real² = (bw²/4)·(bh² - dyn_²)/bh²
            let num = bh2 - dyn_ * dyn_;
            if num <= 0 { continue; }
            // i128 intermediate: bw²·num can exceed i64 for adversarial CARD16
            // dimensions (65535⁴ > i64::MAX); the result fits i64 after /(4·bh²).
            let half2 = ((bw as i128) * (bw as i128) * (num as i128)) / (4 * bh2 as i128);
            let half = isqrt(half2 as u64) as i32;
            let cx_real = (cx2 / 2) as i32;
            let xl = cx_real - half;
            let xr = cx_real + half;
            if full {
                span(px, w, h, xl, xr, py, rgb);
            } else {
                let dy_up = -dyn_ as i32; // +up
                for pxx in xl..=xr {
                    let dx = (2 * pxx + 1) as i32 - cx2 as i32; // 2·(px+0.5 - cx)
                    let a64 = point_angle64(dx, dy_up);
                    if angle_in_sweep(a64, angle1, angle2) {
                        plot(px, w, h, pxx, py, rgb);
                    }
                }
            }
        }
    }

    /// Stroke the outline of the ellipse bounded by rect (x,y,bw,bh) over the
    /// sweep [angle1, angle1+angle2), per X core PolyArc.  One pixel wide.
    /// Implemented as the boundary of the filled region: a pixel is on the
    /// outline if it is inside the ellipse but at least one 4-neighbour is not.
    pub fn stroke_arc(px: &mut [u8], w: i32, h: i32,
                      x: i32, y: i32, bw: i32, bh: i32,
                      angle1: i32, angle2: i32, rgb: u32) {
        if bw <= 0 || bh <= 0 { return; }
        let bh2 = (bh as i64) * (bh as i64);
        let bw2 = (bw as i64) * (bw as i64);
        let cx2 = (2 * x + bw) as i64;
        let cy2 = (2 * y + bh) as i64;
        let full = angle2.abs() >= 360 * 64;
        // inside-test in doubled coords: (dx²·bh² + dy²·bw²) <= bw²·bh².
        // i128 intermediates: the products can exceed i64 for adversarial
        // CARD16 dimensions (65535⁴ > i64::MAX).
        let inside = |pxx: i32, py: i32| -> bool {
            let dx = (2 * pxx + 1) as i128 - cx2 as i128;
            let dy = (2 * py + 1) as i128 - cy2 as i128;
            dx * dx * bh2 as i128 + dy * dy * bw2 as i128 <= bw2 as i128 * bh2 as i128
        };
        let y0 = (y - 1).max(0);
        let y1 = (y + bh + 1).min(h);
        let x0 = (x - 1).max(0);
        let x1 = (x + bw + 1).min(w);
        for py in y0..y1 {
            for pxx in x0..x1 {
                if !inside(pxx, py) { continue; }
                let edge = !inside(pxx - 1, py) || !inside(pxx + 1, py)
                        || !inside(pxx, py - 1) || !inside(pxx, py + 1);
                if !edge { continue; }
                if !full {
                    let dx = (2 * pxx + 1) as i32 - cx2 as i32;
                    let dy_up = -((2 * py + 1) as i32 - cy2 as i32);
                    if !angle_in_sweep(point_angle64(dx, dy_up), angle1, angle2) { continue; }
                }
                plot(px, w, h, pxx, py, rgb);
            }
        }
    }

    // 257-entry table: ATAN_T[i] = round(atan(i/256) in 1/64-degree units),
    // i.e. ∈ [0, 45*64].  Generated at compile time from the integer ratio.
    const ATAN_T: [u16; 257] = build_atan_table();

    const fn build_atan_table() -> [u16; 257] {
        // const fns can't use f64 trig; approximate atan(t) for t∈[0,1] with a
        // rational minimax good to <0.3° (adequate for xeyes — which only ever
        // draws full ellipses, so this table is a robustness margin, not a
        // correctness-critical path).  atan(t) ≈ t·(0.9956 - 0.2899·t²) [rad].
        // We scale to 1/64 degree: deg = rad·180/π, ×64.
        let mut t = [0u16; 257];
        let mut i = 0;
        while i <= 256 {
            // fixed-point: ratio = i/256 in Q16
            let r = (i as i64) * 65536 / 256;           // t in Q16
            let r2 = (r * r) >> 16;                      // t² in Q16
            // poly in Q16: 0.9956 = 65248, 0.2899 = 19000
            let p = (65248 - ((19000 * r2) >> 16)) as i64; // Q16
            let rad_q16 = (r * p) >> 16;                 // atan(t) [rad] Q16
            // deg64 = rad·(180/π)·64 ; 180/π·64 ≈ 3666.93 → Q16 const 240312832>>16
            let deg64 = (rad_q16 * 3667) >> 16;          // 1/64 degree
            t[i] = deg64 as u16;
            i += 1;
        }
        t
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

// ── GlyphSet (RENDER extension) ───────────────────────────────────────────────

/// Per-glyph metrics for RENDER glyph compositing.
#[derive(Clone, Copy, Default)]
pub struct GlyphInfo {
    pub width:  u16,
    pub height: u16,
    pub x_off:  i16,  // left bearing from pen x
    pub y_off:  i16,  // top bearing from pen y
    pub x_adv:  i16,  // x-advance after this glyph
    pub y_adv:  i16,  // y-advance after this glyph
}

/// A RENDER GlyphSet — stores a collection of glyphs with A8 alpha masks.
pub struct GlyphSet {
    pub format: u32,
    pub glyphs: Vec<(u32, GlyphInfo, Vec<u8>)>,  // (glyph_id, info, alpha_A8_pixels)
}

// ── Resource enum ─────────────────────────────────────────────────────────────

pub enum ResourceBody {
    Window(WindowData),
    Pixmap(PixmapData),
    Gc(GcData),
    Picture(PictureData),
    GlyphSet(alloc::boxed::Box<GlyphSet>),
}

pub struct Resource {
    pub id:   u32,
    pub body: ResourceBody,
}

// ── Per-client resource table ─────────────────────────────────────────────────

pub const MAX_RESOURCES: usize = 512;

pub struct ResourceTable {
    pub entries: [Option<Resource>; MAX_RESOURCES],
}

impl ResourceTable {
    pub const fn new() -> Self {
        ResourceTable { entries: [const { None }; MAX_RESOURCES] }
    }

    /// Iterate over all resources (id, body) pairs.
    pub fn iter_all(&self) -> impl Iterator<Item = (u32, &ResourceBody)> {
        self.entries.iter()
            .filter_map(|slot| slot.as_ref().map(|r| (r.id, &r.body)))
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

    pub fn get_glyphset_mut(&mut self, id: u32) -> Option<&mut GlyphSet> {
        for slot in self.entries.iter_mut() {
            if let Some(r) = slot {
                if r.id == id {
                    if let ResourceBody::GlyphSet(ref mut gs) = r.body { return Some(gs.as_mut()); }
                    return None;
                }
            }
        }
        None
    }

    pub fn get_glyphset(&self, id: u32) -> Option<&GlyphSet> {
        for slot in self.entries.iter() {
            if let Some(r) = slot {
                if r.id == id {
                    if let ResourceBody::GlyphSet(ref gs) = r.body { return Some(gs.as_ref()); }
                    return None;
                }
            }
        }
        None
    }

    /// Returns (width, height, depth) for any Drawable (Window or Pixmap).
    pub fn get_drawable_geom(&self, id: u32) -> Option<(u16, u16, u8)> {
        for slot in self.entries.iter() {
            if let Some(r) = slot {
                if r.id == id {
                    return match &r.body {
                        ResourceBody::Window(w)   => Some((w.width, w.height, w.depth)),
                        ResourceBody::Pixmap(p)   => Some((p.width, p.height, p.depth)),
                        ResourceBody::Gc(_)       => None,
                        ResourceBody::Picture(_)  => None,
                        ResourceBody::GlyphSet(_) => None,
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
