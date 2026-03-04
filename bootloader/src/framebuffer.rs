//! Framebuffer initialization via UEFI Graphics Output Protocol (GOP).

use astryx_shared::{FramebufferInfo, PixelFormat};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};

/// Query UEFI GOP for framebuffer information.
///
/// Returns framebuffer info struct with base address, dimensions, and pixel format.
/// Panics if GOP is not available (should not happen on UEFI systems with displays).
pub fn get_framebuffer_info() -> FramebufferInfo {
    let gop_handle = uefi::boot::get_handle_for_protocol::<GraphicsOutput>()
        .expect("GOP protocol not available");

    let mut gop = uefi::boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle)
        .expect("Failed to open GOP");

    // Try to find a good video mode (prefer 1024x768 or highest available)
    let desired_width = 1024;
    let desired_height = 768;

    let mut best_mode = None;
    let mut best_resolution = (0u32, 0u32);

    for mode in gop.modes() {
        let info = mode.info();
        let (w, h) = info.resolution();
        let (w, h) = (w as u32, h as u32);

        if w == desired_width && h == desired_height {
            best_mode = Some(mode);
            break;
        }

        if w * h > best_resolution.0 * best_resolution.1 && w <= 1920 && h <= 1080 {
            best_mode = Some(mode);
            best_resolution = (w, h);
        }
    }

    // Set the video mode if we found a good one
    if let Some(mode) = best_mode {
        let _ = gop.set_mode(&mode);
    }

    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();
    let stride = mode_info.stride() as u32;
    let pixel_format = match mode_info.pixel_format() {
        GopPixelFormat::Bgr => PixelFormat::Bgr,
        GopPixelFormat::Rgb => PixelFormat::Rgb,
        _ => PixelFormat::Unknown,
    };

    let fb_base = gop.frame_buffer().as_mut_ptr() as u64;

    FramebufferInfo {
        base_address: fb_base,
        width: width as u32,
        height: height as u32,
        stride,
        bytes_per_pixel: 4,
        pixel_format,
    }
}
