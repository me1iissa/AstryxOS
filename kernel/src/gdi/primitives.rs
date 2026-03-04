//! Drawing primitives — rectangles, lines, ellipses, gradients.
//!
//! All functions respect the Device Context's clipping rectangle and origin offset.

use super::dc::{BrushStyle, DeviceContext, PenStyle, Rect, Rop2};
use super::surface::Surface;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the effective drawing area by intersecting the surface bounds,
/// the requested rectangle, and the DC clip rect (translated by origin).
fn effective_rect(
    surface: &Surface,
    dc: &DeviceContext,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> Option<Rect> {
    let surf_rect = Rect::new(0, 0, surface.width() as i32, surface.height() as i32);
    let draw_rect = Rect::new(
        left + dc.origin_x,
        top + dc.origin_y,
        right + dc.origin_x,
        bottom + dc.origin_y,
    );
    let clipped = surf_rect.intersect(&draw_rect)?;
    if let Some(ref cr) = dc.clip_rect {
        let cr_translated = Rect::new(
            cr.left + dc.origin_x,
            cr.top + dc.origin_y,
            cr.right + dc.origin_x,
            cr.bottom + dc.origin_y,
        );
        clipped.intersect(&cr_translated)
    } else {
        Some(clipped)
    }
}

/// Apply the DC's ROP2 to produce the final pixel color.
fn apply_rop2(dc: &DeviceContext, pen_color: u32, dst_color: u32) -> u32 {
    match dc.rop2 {
        Rop2::CopyPen => pen_color,
        Rop2::Not => !dst_color | 0xFF000000,
        Rop2::Xor => (dst_color ^ pen_color) | 0xFF000000,
        Rop2::Black => 0xFF000000,
        Rop2::White => 0xFFFFFFFF,
    }
}

/// Set a pixel on the surface, checking bounds.
#[inline]
fn safe_set(surface: &mut Surface, x: i32, y: i32, color: u32) {
    if x >= 0 && y >= 0 && (x as u32) < surface.width() && (y as u32) < surface.height() {
        surface.set_pixel(x as u32, y as u32, color);
    }
}

/// Check whether `(x, y)` is inside the optional clip rect (already origin-translated).
#[inline]
fn clip_ok(dc: &DeviceContext, x: i32, y: i32) -> bool {
    if let Some(ref cr) = dc.clip_rect {
        let cx = x - dc.origin_x;
        let cy = y - dc.origin_y;
        // clip_rect is in DC logical coords; x,y here are in surface (device) coords.
        // Since we already applied origin before calling, undo to compare with clip_rect.
        // Actually, we pass device coords to primitives, so let's keep it simple:
        // clip_rect is in logical coords, compare logical coords.
        cx >= cr.left && cx < cr.right && cy >= cr.top && cy < cr.bottom
    } else {
        true
    }
}

/// Set a pixel with DC clipping + ROP2 applied. `(px, py)` are in **logical** coords.
fn dc_set_pixel(surface: &mut Surface, dc: &DeviceContext, px: i32, py: i32, color: u32) {
    // clip
    if let Some(ref cr) = dc.clip_rect {
        if px < cr.left || px >= cr.right || py < cr.top || py >= cr.bottom {
            return;
        }
    }
    // translate to device coords
    let dx = px + dc.origin_x;
    let dy = py + dc.origin_y;
    if dx < 0 || dy < 0 || dx as u32 >= surface.width() || dy as u32 >= surface.height() {
        return;
    }
    let dst = surface.get_pixel(dx as u32, dy as u32);
    let out = apply_rop2(dc, color, dst);
    surface.set_pixel(dx as u32, dy as u32, out);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fill a rectangle on the surface using the DC's brush.
pub fn fill_rectangle(
    surface: &mut Surface,
    dc: &DeviceContext,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) {
    if dc.brush.style == BrushStyle::Null {
        return;
    }
    let color = dc.brush.color;
    for y in top..bottom {
        for x in left..right {
            dc_set_pixel(surface, dc, x, y, color);
        }
    }
}

/// Draw a rectangle: outline with DC's pen, fill interior with DC's brush.
pub fn rectangle(
    surface: &mut Surface,
    dc: &DeviceContext,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) {
    // Fill interior (excluding border)
    if dc.brush.style != BrushStyle::Null {
        let pen_w = if dc.pen.style != PenStyle::Null { dc.pen.width as i32 } else { 0 };
        let il = left + pen_w;
        let it = top + pen_w;
        let ir = right - pen_w;
        let ib = bottom - pen_w;
        if il < ir && it < ib {
            fill_rectangle(surface, dc, il, it, ir, ib);
        }
    }
    // Draw outline
    if dc.pen.style != PenStyle::Null {
        let color = dc.pen.color;
        let w = dc.pen.width as i32;
        // top edge
        for t in 0..w {
            for x in left..right {
                dc_set_pixel(surface, dc, x, top + t, color);
            }
        }
        // bottom edge
        for t in 0..w {
            for x in left..right {
                dc_set_pixel(surface, dc, x, bottom - 1 - t, color);
            }
        }
        // left edge
        for t in 0..w {
            for y in top..bottom {
                dc_set_pixel(surface, dc, left + t, y, color);
            }
        }
        // right edge
        for t in 0..w {
            for y in top..bottom {
                dc_set_pixel(surface, dc, right - 1 - t, y, color);
            }
        }
    }
}

/// Draw a horizontal line from `(x1, y)` to `(x2, y)` using DC's pen.
pub fn hline(surface: &mut Surface, dc: &DeviceContext, x1: i32, x2: i32, y: i32) {
    if dc.pen.style == PenStyle::Null {
        return;
    }
    let color = dc.pen.color;
    let (a, b) = if x1 <= x2 { (x1, x2) } else { (x2, x1) };
    for x in a..=b {
        dc_set_pixel(surface, dc, x, y, color);
    }
}

/// Draw a vertical line from `(x, y1)` to `(x, y2)` using DC's pen.
pub fn vline(surface: &mut Surface, dc: &DeviceContext, x: i32, y1: i32, y2: i32) {
    if dc.pen.style == PenStyle::Null {
        return;
    }
    let color = dc.pen.color;
    let (a, b) = if y1 <= y2 { (y1, y2) } else { (y2, y1) };
    for y in a..=b {
        dc_set_pixel(surface, dc, x, y, color);
    }
}

/// Draw a line using Bresenham's algorithm.
pub fn line(
    surface: &mut Surface,
    dc: &DeviceContext,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
) {
    if dc.pen.style == PenStyle::Null {
        return;
    }
    let color = dc.pen.color;

    let dx = (x2 - x1).abs();
    let dy = -(y2 - y1).abs();
    let sx: i32 = if x1 < x2 { 1 } else { -1 };
    let sy: i32 = if y1 < y2 { 1 } else { -1 };
    let mut err = dx + dy;
    let mut cx = x1;
    let mut cy = y1;

    loop {
        dc_set_pixel(surface, dc, cx, cy, color);
        if cx == x2 && cy == y2 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            if cx == x2 {
                break;
            }
            err += dy;
            cx += sx;
        }
        if e2 <= dx {
            if cy == y2 {
                break;
            }
            err += dx;
            cy += sy;
        }
    }
}

/// Draw a filled ellipse using the midpoint algorithm.
///
/// `(cx, cy)` = centre, `rx` / `ry` = radii.
pub fn fill_ellipse(
    surface: &mut Surface,
    dc: &DeviceContext,
    cx: i32,
    cy: i32,
    rx: i32,
    ry: i32,
) {
    if rx <= 0 || ry <= 0 {
        return;
    }
    let brush_color = if dc.brush.style != BrushStyle::Null {
        dc.brush.color
    } else {
        return;
    };

    // Scan-line fill: for each y from -ry to +ry determine the x span.
    let rx2 = (rx as i64) * (rx as i64);
    let ry2 = (ry as i64) * (ry as i64);
    for dy in -ry..=ry {
        // x^2 / rx^2 + y^2 / ry^2 <= 1  =>  x^2 <= rx^2 * (1 - y^2/ry^2)
        let dy2 = (dy as i64) * (dy as i64);
        let x_span_sq = rx2 * (ry2 - dy2);
        if x_span_sq < 0 {
            continue;
        }
        // integer sqrt
        let x_span = isqrt(x_span_sq / ry2);
        let py = cy + dy;
        for dxx in -(x_span as i32)..=(x_span as i32) {
            dc_set_pixel(surface, dc, cx + dxx, py, brush_color);
        }
    }

    // Outline with pen
    if dc.pen.style != PenStyle::Null {
        draw_ellipse_outline(surface, dc, cx, cy, rx, ry);
    }
}

/// Integer square root (floor).
fn isqrt(n: i64) -> i64 {
    if n < 0 {
        return 0;
    }
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Draw ellipse outline using midpoint algorithm.
fn draw_ellipse_outline(
    surface: &mut Surface,
    dc: &DeviceContext,
    cx: i32,
    cy: i32,
    rx: i32,
    ry: i32,
) {
    let color = dc.pen.color;
    let a2 = (rx as i64) * (rx as i64);
    let b2 = (ry as i64) * (ry as i64);
    let mut x: i64 = 0;
    let mut y: i64 = ry as i64;
    // Region 1
    let mut d1 = b2 - a2 * (ry as i64) + a2 / 4;
    let mut dx: i64 = 2 * b2 * x;
    let mut dy: i64 = 2 * a2 * y;

    while dx < dy {
        plot4(surface, dc, cx, cy, x as i32, y as i32, color);
        if d1 < 0 {
            x += 1;
            dx += 2 * b2;
            d1 += dx + b2;
        } else {
            x += 1;
            y -= 1;
            dx += 2 * b2;
            dy -= 2 * a2;
            d1 += dx - dy + b2;
        }
    }
    // Region 2
    let mut d2 = b2 * (2 * x + 1) * (2 * x + 1) / 4 + a2 * (y - 1) * (y - 1) - a2 * b2;
    while y >= 0 {
        plot4(surface, dc, cx, cy, x as i32, y as i32, color);
        if d2 > 0 {
            y -= 1;
            dy -= 2 * a2;
            d2 += a2 - dy;
        } else {
            x += 1;
            y -= 1;
            dx += 2 * b2;
            dy -= 2 * a2;
            d2 += dx - dy + a2;
        }
    }
}

/// Plot four symmetric points of an ellipse.
fn plot4(
    surface: &mut Surface,
    dc: &DeviceContext,
    cx: i32,
    cy: i32,
    x: i32,
    y: i32,
    color: u32,
) {
    dc_set_pixel(surface, dc, cx + x, cy + y, color);
    dc_set_pixel(surface, dc, cx - x, cy + y, color);
    dc_set_pixel(surface, dc, cx + x, cy - y, color);
    dc_set_pixel(surface, dc, cx - x, cy - y, color);
}

/// Draw a 1-pixel border (outline) rectangle with a given color (ignores DC).
pub fn frame_rect(
    surface: &mut Surface,
    color: u32,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) {
    let sw = surface.width() as i32;
    let sh = surface.height() as i32;
    // top
    for x in left..right {
        if x >= 0 && x < sw && top >= 0 && top < sh {
            surface.set_pixel(x as u32, top as u32, color);
        }
    }
    // bottom
    let by = bottom - 1;
    for x in left..right {
        if x >= 0 && x < sw && by >= 0 && by < sh {
            surface.set_pixel(x as u32, by as u32, color);
        }
    }
    // left
    for y in top..bottom {
        if left >= 0 && left < sw && y >= 0 && y < sh {
            surface.set_pixel(left as u32, y as u32, color);
        }
    }
    // right
    let rx = right - 1;
    for y in top..bottom {
        if rx >= 0 && rx < sw && y >= 0 && y < sh {
            surface.set_pixel(rx as u32, y as u32, color);
        }
    }
}

/// Draw a vertical gradient rectangle, interpolating from `top_color` to `bottom_color`.
pub fn gradient_fill_v(
    surface: &mut Surface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    top_color: u32,
    bottom_color: u32,
) {
    let height = bottom - top;
    if height <= 0 || right <= left {
        return;
    }
    let sw = surface.width() as i32;
    let sh = surface.height() as i32;

    let ta = ((top_color >> 24) & 0xFF) as i32;
    let tr = ((top_color >> 16) & 0xFF) as i32;
    let tg = ((top_color >> 8) & 0xFF) as i32;
    let tb = (top_color & 0xFF) as i32;

    let ba = ((bottom_color >> 24) & 0xFF) as i32;
    let br = ((bottom_color >> 16) & 0xFF) as i32;
    let bg = ((bottom_color >> 8) & 0xFF) as i32;
    let bb = (bottom_color & 0xFF) as i32;

    for row in 0..height {
        let y = top + row;
        if y < 0 || y >= sh {
            continue;
        }
        // Linear interpolation
        let a = (ta + (ba - ta) * row / height).clamp(0, 255) as u32;
        let r = (tr + (br - tr) * row / height).clamp(0, 255) as u32;
        let g = (tg + (bg - tg) * row / height).clamp(0, 255) as u32;
        let b = (tb + (bb - tb) * row / height).clamp(0, 255) as u32;
        let color = (a << 24) | (r << 16) | (g << 8) | b;
        for x in left..right {
            if x >= 0 && x < sw {
                surface.set_pixel(x as u32, y as u32, color);
            }
        }
    }
}

/// Draw a rounded rectangle: outline with DC's pen, fill with DC's brush.
///
/// `radius` is the corner circle radius.
pub fn round_rect(
    surface: &mut Surface,
    dc: &DeviceContext,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    radius: i32,
) {
    let w = right - left;
    let h = bottom - top;
    if w <= 0 || h <= 0 {
        return;
    }
    let r = radius.min(w / 2).min(h / 2).max(0);

    // --- Fill interior ---
    if dc.brush.style != BrushStyle::Null {
        let color = dc.brush.color;
        // Central rectangle (between corners vertically)
        for y in (top + r)..(bottom - r) {
            for x in left..right {
                dc_set_pixel(surface, dc, x, y, color);
            }
        }
        // Top and bottom bands with rounded corners
        for dy in 0..r {
            // Quarter-circle offset at this row
            let dx = r - isqrt(((r as i64) * (r as i64)) - ((r - dy) as i64) * ((r - dy) as i64)) as i32;
            // Top band
            let y_top = top + dy;
            for x in (left + dx)..(right - dx) {
                dc_set_pixel(surface, dc, x, y_top, color);
            }
            // Bottom band
            let y_bot = bottom - 1 - dy;
            for x in (left + dx)..(right - dx) {
                dc_set_pixel(surface, dc, x, y_bot, color);
            }
        }
    }

    // --- Draw outline ---
    if dc.pen.style != PenStyle::Null {
        let color = dc.pen.color;
        // Straight edges
        for x in (left + r)..(right - r) {
            dc_set_pixel(surface, dc, x, top, color);      // top
            dc_set_pixel(surface, dc, x, bottom - 1, color); // bottom
        }
        for y in (top + r)..(bottom - r) {
            dc_set_pixel(surface, dc, left, y, color);      // left
            dc_set_pixel(surface, dc, right - 1, y, color); // right
        }
        // Corner arcs (quarter circles)
        draw_quarter_circle(surface, dc, left + r, top + r, r, color, 1);     // top-left
        draw_quarter_circle(surface, dc, right - 1 - r, top + r, r, color, 0);  // top-right
        draw_quarter_circle(surface, dc, left + r, bottom - 1 - r, r, color, 2); // bottom-left
        draw_quarter_circle(surface, dc, right - 1 - r, bottom - 1 - r, r, color, 3); // bottom-right
    }
}

/// Draw a quarter circle arc using the midpoint circle algorithm.
/// `quadrant`: 0 = top-right, 1 = top-left, 2 = bottom-left, 3 = bottom-right.
fn draw_quarter_circle(
    surface: &mut Surface,
    dc: &DeviceContext,
    cx: i32,
    cy: i32,
    r: i32,
    color: u32,
    quadrant: u8,
) {
    let mut x = 0i32;
    let mut y = r;
    let mut d = 1 - r;
    while x <= y {
        match quadrant {
            0 => {
                dc_set_pixel(surface, dc, cx + y, cy - x, color);
                dc_set_pixel(surface, dc, cx + x, cy - y, color);
            }
            1 => {
                dc_set_pixel(surface, dc, cx - y, cy - x, color);
                dc_set_pixel(surface, dc, cx - x, cy - y, color);
            }
            2 => {
                dc_set_pixel(surface, dc, cx - y, cy + x, color);
                dc_set_pixel(surface, dc, cx - x, cy + y, color);
            }
            3 => {
                dc_set_pixel(surface, dc, cx + y, cy + x, color);
                dc_set_pixel(surface, dc, cx + x, cy + y, color);
            }
            _ => {}
        }
        if d < 0 {
            d += 2 * x + 3;
        } else {
            d += 2 * (x - y) + 5;
            y -= 1;
        }
        x += 1;
    }
}
