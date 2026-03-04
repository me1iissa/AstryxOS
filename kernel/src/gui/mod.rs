//! AstryxOS GUI Subsystem
//!
//! Top-level module organising the compositor, input pump, window interaction,
//! and demo desktop.  The public API (`init`, `compose`, `is_initialized`)
//! delegates to the unified compositor in `compositor.rs`.

pub mod compositor;
pub mod content;
pub mod desktop;
pub mod input;
pub mod interaction;
pub mod terminal;
pub mod editor;
pub mod calculator;

// ---------------------------------------------------------------------------
// Re-export thin wrappers that preserve the existing `gui::*` call-sites in
// main.rs and elsewhere.
// ---------------------------------------------------------------------------

/// Initialise the GUI compositor.
///
/// Must be called after the VMware SVGA framebuffer is set up.
pub fn init(fb_base: u64, width: u32, height: u32, stride: u32) {
    compositor::init(fb_base, width, height, stride);
}

/// Composite one frame (back-buffer draw + blit to hardware FB).
pub fn compose() {
    compositor::compose();
}

/// Returns `true` once the compositor has been initialised.
pub fn is_initialized() -> bool {
    compositor::is_initialized()
}
