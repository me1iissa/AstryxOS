//! Clipping regions — simple rectangle-based clipping.

extern crate alloc;
use alloc::vec::Vec;
use super::dc::Rect;

/// A clipping region. Currently supports null, single-rect, and complex (union of rects).
#[derive(Debug, Clone)]
pub enum Region {
    /// Empty region — clips everything.
    Null,
    /// Single rectangle.
    Rect(Rect),
    /// Union of rectangles.
    Complex(Vec<Rect>),
}

impl Region {
    /// Create a region from a single rectangle.
    pub fn new_rect(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Region::Rect(Rect::new(left, top, right, bottom))
    }

    /// Create an empty (null) region that clips everything.
    pub fn new_null() -> Self {
        Region::Null
    }

    /// Returns `true` if `(x, y)` is contained in the region.
    pub fn contains_point(&self, x: i32, y: i32) -> bool {
        match self {
            Region::Null => false,
            Region::Rect(r) => r.contains(x, y),
            Region::Complex(rects) => rects.iter().any(|r| r.contains(x, y)),
        }
    }

    /// Compute the intersection of this region with a rectangle.
    pub fn intersect_rect(&self, rect: &Rect) -> Region {
        match self {
            Region::Null => Region::Null,
            Region::Rect(r) => match r.intersect(rect) {
                Some(ir) => Region::Rect(ir),
                None => Region::Null,
            },
            Region::Complex(rects) => {
                let mut result = Vec::new();
                for r in rects {
                    if let Some(ir) = r.intersect(rect) {
                        result.push(ir);
                    }
                }
                if result.is_empty() {
                    Region::Null
                } else if result.len() == 1 {
                    Region::Rect(result[0])
                } else {
                    Region::Complex(result)
                }
            }
        }
    }

    /// Compute the union of this region with a rectangle — adds the rect to the region.
    pub fn union_rect(&self, rect: &Rect) -> Region {
        match self {
            Region::Null => Region::Rect(*rect),
            Region::Rect(r) => {
                let mut v = Vec::with_capacity(2);
                v.push(*r);
                v.push(*rect);
                Region::Complex(v)
            }
            Region::Complex(rects) => {
                let mut v = rects.clone();
                v.push(*rect);
                Region::Complex(v)
            }
        }
    }

    /// Return the bounding rectangle of the entire region, or `None` if null.
    pub fn bounding_rect(&self) -> Option<Rect> {
        match self {
            Region::Null => None,
            Region::Rect(r) => Some(*r),
            Region::Complex(rects) => {
                if rects.is_empty() {
                    return None;
                }
                let mut left = i32::MAX;
                let mut top = i32::MAX;
                let mut right = i32::MIN;
                let mut bottom = i32::MIN;
                for r in rects {
                    left = left.min(r.left);
                    top = top.min(r.top);
                    right = right.max(r.right);
                    bottom = bottom.max(r.bottom);
                }
                Some(Rect::new(left, top, right, bottom))
            }
        }
    }

    /// Returns `true` if the region is empty (clips everything).
    pub fn is_empty(&self) -> bool {
        match self {
            Region::Null => true,
            Region::Rect(r) => r.width() <= 0 || r.height() <= 0,
            Region::Complex(rects) => rects.is_empty(),
        }
    }
}
