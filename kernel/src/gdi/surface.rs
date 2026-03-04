//! Surface — 32-bit ARGB pixel buffer abstraction.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

/// A 32-bit ARGB pixel buffer.
///
/// Pixel format: `0xAARRGGBB` — alpha in the high byte.
pub struct Surface {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
}

impl Surface {
    /// Create a new surface filled with transparent black (`0x00000000`).
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            pixels: vec![0u32; (width as usize) * (height as usize)],
        }
    }

    /// Create a new surface filled with the given color.
    pub fn new_with_color(width: u32, height: u32, color: u32) -> Self {
        Self {
            width,
            height,
            pixels: vec![color; (width as usize) * (height as usize)],
        }
    }

    /// Get the pixel at `(x, y)`. Returns 0 if out of bounds.
    pub fn get_pixel(&self, x: u32, y: u32) -> u32 {
        if x >= self.width || y >= self.height {
            return 0;
        }
        self.pixels[(y as usize) * (self.width as usize) + (x as usize)]
    }

    /// Set the pixel at `(x, y)`. Does nothing if out of bounds.
    pub fn set_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x < self.width && y < self.height {
            self.pixels[(y as usize) * (self.width as usize) + (x as usize)] = color;
        }
    }

    /// Fill the entire surface with a solid color.
    pub fn fill(&mut self, color: u32) {
        for p in self.pixels.iter_mut() {
            *p = color;
        }
    }

    /// Surface width accessor.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Surface height accessor.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Blit a rectangular region from `src` surface to this surface at `(dst_x, dst_y)`.
    ///
    /// Copies the rectangle `(src_x, src_y, w, h)` from `src` to `(dst_x, dst_y)` on self.
    /// Out-of-bounds pixels are clipped silently.
    pub fn blit_from(
        &mut self,
        src: &Surface,
        src_x: u32,
        src_y: u32,
        dst_x: u32,
        dst_y: u32,
        w: u32,
        h: u32,
    ) {
        for row in 0..h {
            let sy = src_y + row;
            let dy = dst_y + row;
            if sy >= src.height || dy >= self.height {
                continue;
            }
            for col in 0..w {
                let sx = src_x + col;
                let dx = dst_x + col;
                if sx >= src.width || dx >= self.width {
                    continue;
                }
                let pixel = src.pixels[(sy as usize) * (src.width as usize) + (sx as usize)];
                self.pixels[(dy as usize) * (self.width as usize) + (dx as usize)] = pixel;
            }
        }
    }

    /// Fill a rectangle with a solid color.
    ///
    /// `(x, y)` is the top-left corner; `w` and `h` are dimensions.
    /// Coordinates may be negative — the visible portion is clipped to the surface.
    pub fn fill_rect(&mut self, x: i32, y: i32, w: u32, h: u32, color: u32) {
        let x0 = x.max(0) as u32;
        let y0 = y.max(0) as u32;
        let x1 = ((x as i64 + w as i64).min(self.width as i64)) as u32;
        let y1 = ((y as i64 + h as i64).min(self.height as i64)) as u32;
        for row in y0..y1 {
            let base = (row as usize) * (self.width as usize);
            for col in x0..x1 {
                self.pixels[base + col as usize] = color;
            }
        }
    }

    /// Alpha-blend a pixel onto the surface at `(x, y)`: src over dst.
    ///
    /// Formula per channel: `result = (src_a * src_c + (255 - src_a) * dst_c) / 255`
    pub fn blend_pixel(&mut self, x: u32, y: u32, src_color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let sa = (src_color >> 24) & 0xFF;
        if sa == 0 {
            return; // fully transparent — nothing to do
        }
        if sa == 255 {
            self.set_pixel(x, y, src_color);
            return;
        }
        let dst_color = self.get_pixel(x, y);
        let inv_sa = 255 - sa;

        let sr = (src_color >> 16) & 0xFF;
        let sg = (src_color >> 8) & 0xFF;
        let sb = src_color & 0xFF;

        let dr = (dst_color >> 16) & 0xFF;
        let dg = (dst_color >> 8) & 0xFF;
        let db = dst_color & 0xFF;
        let da = (dst_color >> 24) & 0xFF;

        let r = (sa * sr + inv_sa * dr) / 255;
        let g = (sa * sg + inv_sa * dg) / 255;
        let b = (sa * sb + inv_sa * db) / 255;
        // Output alpha: src_a + dst_a * (1 - src_a) / 255
        let a = sa + (inv_sa * da) / 255;
        let a = a.min(255);

        self.set_pixel(x, y, (a << 24) | (r << 16) | (g << 8) | b);
    }
}
