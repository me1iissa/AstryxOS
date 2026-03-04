//! BitBlt — Bit Block Transfer operations.

use super::surface::Surface;

/// Raster operation codes for BitBlt / PatBlt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RasterOp {
    /// Straight copy.
    SrcCopy,
    /// OR: `dst | src`.
    SrcPaint,
    /// AND: `dst & src`.
    SrcAnd,
    /// XOR: `dst ^ src`.
    SrcInvert,
    /// NOT dst.
    DstInvert,
    /// Fill black.
    Blackness,
    /// Fill white.
    Whiteness,
    /// Alpha blend (per-pixel alpha).
    SrcAlpha,
}

/// Apply a raster operation to produce an output pixel.
#[inline]
fn apply_rop(rop: RasterOp, src: u32, dst: u32) -> u32 {
    match rop {
        RasterOp::SrcCopy => src,
        RasterOp::SrcPaint => dst | src,
        RasterOp::SrcAnd => dst & src,
        RasterOp::SrcInvert => dst ^ src,
        RasterOp::DstInvert => !dst | 0xFF000000,
        RasterOp::Blackness => 0xFF000000,
        RasterOp::Whiteness => 0xFFFFFFFF,
        RasterOp::SrcAlpha => alpha_blend_pixel(src, dst),
    }
}

/// Per-pixel alpha blend: `src` over `dst`.
///
/// Formula per channel: `out = (src_a * src_c + (255 - src_a) * dst_c) / 255`
#[inline]
fn alpha_blend_pixel(src: u32, dst: u32) -> u32 {
    let sa = (src >> 24) & 0xFF;
    if sa == 255 {
        return src;
    }
    if sa == 0 {
        return dst;
    }
    let inv_sa = 255 - sa;

    let sr = (src >> 16) & 0xFF;
    let sg = (src >> 8) & 0xFF;
    let sb = src & 0xFF;

    let dr = (dst >> 16) & 0xFF;
    let dg = (dst >> 8) & 0xFF;
    let db = dst & 0xFF;
    let da = (dst >> 24) & 0xFF;

    let r = (sa * sr + inv_sa * dr) / 255;
    let g = (sa * sg + inv_sa * dg) / 255;
    let b = (sa * sb + inv_sa * db) / 255;
    let a = (sa + (inv_sa * da) / 255).min(255);

    (a << 24) | (r << 16) | (g << 8) | b
}

/// BitBlt — copy a rectangular region from `src` to `dst` with a raster operation.
///
/// Coordinates may be negative; out-of-bounds pixels are clipped.
pub fn bit_blt(
    dst: &mut Surface,
    dst_x: i32,
    dst_y: i32,
    width: u32,
    height: u32,
    src: &Surface,
    src_x: i32,
    src_y: i32,
    rop: RasterOp,
) {
    for row in 0..height as i32 {
        let sy = src_y + row;
        let dy = dst_y + row;
        if sy < 0 || dy < 0 || sy as u32 >= src.height() || dy as u32 >= dst.height() {
            continue;
        }
        for col in 0..width as i32 {
            let sx = src_x + col;
            let dx = dst_x + col;
            if sx < 0 || dx < 0 || sx as u32 >= src.width() || dx as u32 >= dst.width() {
                continue;
            }
            let sp = src.get_pixel(sx as u32, sy as u32);
            let dp = dst.get_pixel(dx as u32, dy as u32);
            dst.set_pixel(dx as u32, dy as u32, apply_rop(rop, sp, dp));
        }
    }
}

/// StretchBlt — copy with scaling using nearest-neighbor interpolation.
pub fn stretch_blt(
    dst: &mut Surface,
    dst_x: i32,
    dst_y: i32,
    dst_w: u32,
    dst_h: u32,
    src: &Surface,
    src_x: i32,
    src_y: i32,
    src_w: u32,
    src_h: u32,
    rop: RasterOp,
) {
    if dst_w == 0 || dst_h == 0 || src_w == 0 || src_h == 0 {
        return;
    }
    for dy_off in 0..dst_h as i32 {
        let dy = dst_y + dy_off;
        if dy < 0 || dy as u32 >= dst.height() {
            continue;
        }
        // Map dst row → src row (nearest-neighbor).
        let sy = src_y + (dy_off as u64 * src_h as u64 / dst_h as u64) as i32;
        if sy < 0 || sy as u32 >= src.height() {
            continue;
        }
        for dx_off in 0..dst_w as i32 {
            let dx = dst_x + dx_off;
            if dx < 0 || dx as u32 >= dst.width() {
                continue;
            }
            let sx = src_x + (dx_off as u64 * src_w as u64 / dst_w as u64) as i32;
            if sx < 0 || sx as u32 >= src.width() {
                continue;
            }
            let sp = src.get_pixel(sx as u32, sy as u32);
            let dp = dst.get_pixel(dx as u32, dy as u32);
            dst.set_pixel(dx as u32, dy as u32, apply_rop(rop, sp, dp));
        }
    }
}

/// AlphaBlend — blend `src` onto `dst` using per-pixel alpha.
pub fn alpha_blend(
    dst: &mut Surface,
    dst_x: i32,
    dst_y: i32,
    src: &Surface,
    src_x: i32,
    src_y: i32,
    width: u32,
    height: u32,
) {
    for row in 0..height as i32 {
        let sy = src_y + row;
        let dy = dst_y + row;
        if sy < 0 || dy < 0 || sy as u32 >= src.height() || dy as u32 >= dst.height() {
            continue;
        }
        for col in 0..width as i32 {
            let sx = src_x + col;
            let dx = dst_x + col;
            if sx < 0 || dx < 0 || sx as u32 >= src.width() || dx as u32 >= dst.width() {
                continue;
            }
            let sp = src.get_pixel(sx as u32, sy as u32);
            dst.blend_pixel(dx as u32, dy as u32, sp);
        }
    }
}

/// PatBlt — fill a rectangle with a solid color and raster operation.
pub fn pat_blt(
    dst: &mut Surface,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    color: u32,
    rop: RasterOp,
) {
    for row in 0..height as i32 {
        let dy = y + row;
        if dy < 0 || dy as u32 >= dst.height() {
            continue;
        }
        for col in 0..width as i32 {
            let dx = x + col;
            if dx < 0 || dx as u32 >= dst.width() {
                continue;
            }
            let dp = dst.get_pixel(dx as u32, dy as u32);
            dst.set_pixel(dx as u32, dy as u32, apply_rop(rop, color, dp));
        }
    }
}
