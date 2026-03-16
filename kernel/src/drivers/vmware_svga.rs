//! VMware SVGA II Display Driver
//!
//! Supports the VMware SVGA II device (PCI vendor 0x15AD, device 0x0405),
//! emulated by QEMU with `-vga vmware`. Provides register-based mode setting,
//! FIFO-based 2D acceleration (fill, copy, update), and hardware cursor support.

use spin::Mutex;

// ── PCI Identification ──────────────────────────────────────────────────────

const VMWARE_VENDOR_ID: u16 = 0x15AD;
const VMWARE_SVGA_DEVICE_ID: u16 = 0x0405;

// ── SVGA Register Indices ───────────────────────────────────────────────────

const SVGA_REG_ID: u32 = 0;
const SVGA_REG_ENABLE: u32 = 1;
const SVGA_REG_WIDTH: u32 = 2;
const SVGA_REG_HEIGHT: u32 = 3;
const SVGA_REG_MAX_WIDTH: u32 = 4;
const SVGA_REG_MAX_HEIGHT: u32 = 5;
const SVGA_REG_DEPTH: u32 = 6;
const SVGA_REG_BPP: u32 = 7;
const SVGA_REG_BYTES_PER_LINE: u32 = 12;
const SVGA_REG_FB_START: u32 = 13;
const SVGA_REG_FB_OFFSET: u32 = 14;
const SVGA_REG_VRAM_SIZE: u32 = 15;
const SVGA_REG_FB_SIZE: u32 = 16;
const SVGA_REG_CAPABILITIES: u32 = 17;
const SVGA_REG_FIFO_START: u32 = 18;
const SVGA_REG_FIFO_SIZE: u32 = 19;
const SVGA_REG_CONFIG_DONE: u32 = 20;
const SVGA_REG_SYNC: u32 = 21;
const SVGA_REG_BUSY: u32 = 22;
const SVGA_REG_NUM_DISPLAYS: u32 = 27;

// ── I/O Port Offsets (relative to BAR0) ─────────────────────────────────────

const SVGA_INDEX_PORT_OFFSET: u16 = 0;
const SVGA_VALUE_PORT_OFFSET: u16 = 1;

// ── Version Negotiation ─────────────────────────────────────────────────────

const SVGA_ID_2: u32 = 0x900000 + 2; // SVGA_MAKE_ID(2)
const SVGA_ID_1: u32 = 0x900000 + 1;
const SVGA_ID_0: u32 = 0x900000 + 0;

// ── Capabilities ────────────────────────────────────────────────────────────

const SVGA_CAP_RECT_COPY: u32 = 0x0002;
const SVGA_CAP_RECT_FILL: u32 = 0x0004;
const SVGA_CAP_CURSOR: u32 = 0x0020;
const SVGA_CAP_CURSOR_BYPASS_2: u32 = 0x0080;
const SVGA_CAP_ALPHA_CURSOR: u32 = 0x0400;

// ── FIFO Commands ───────────────────────────────────────────────────────────

const SVGA_CMD_UPDATE: u32 = 1;
const SVGA_CMD_RECT_FILL: u32 = 2;
const SVGA_CMD_RECT_COPY: u32 = 3;
const SVGA_CMD_MOVE_CURSOR: u32 = 4;
const SVGA_CMD_DEFINE_CURSOR: u32 = 19;

// ── FIFO Register Offsets (indices into FIFO u32 array) ─────────────────────

const SVGA_FIFO_MIN: usize = 0;
const SVGA_FIFO_MAX: usize = 1;
const SVGA_FIFO_NEXT_CMD: usize = 2;
const SVGA_FIFO_STOP: usize = 3;
// Indices 4–8: CAPABILITIES, FLAGS, FENCE, 3D_HWVERSION, PITCHLOCK
// Cursor bypass-2 registers (SVGA2 spec §3.10, VMware SVGA Developer Kit):
const SVGA_FIFO_CURSOR_ON: usize = 9;   // 1 = cursor visible
const SVGA_FIFO_CURSOR_X: usize = 10;
const SVGA_FIFO_CURSOR_Y: usize = 11;

// ── SVGA Device State ───────────────────────────────────────────────────────

/// VMware SVGA II device state.
pub struct VmwareSvga {
    io_base: u16,
    fb_phys: u64,
    fb_size: u64,
    fifo_phys: u64,
    fifo_size: u64,
    fifo_virt: u64,
    width: u32,
    height: u32,
    bpp: u32,
    pitch: u32,
    capabilities: u32,
    enabled: bool,
}

/// Global SVGA state, protected by a spinlock.
static SVGA: Mutex<Option<VmwareSvga>> = Mutex::new(None);

// ── Low-level Register Access ───────────────────────────────────────────────

/// Write `index` to the SVGA index port, then read the value port.
fn read_reg(io_base: u16, index: u32) -> u32 {
    unsafe {
        crate::hal::outl(io_base + SVGA_INDEX_PORT_OFFSET, index);
        crate::hal::inl(io_base + SVGA_VALUE_PORT_OFFSET)
    }
}

/// Write `index` to the SVGA index port, then write `value` to the value port.
fn write_reg(io_base: u16, index: u32, value: u32) {
    unsafe {
        crate::hal::outl(io_base + SVGA_INDEX_PORT_OFFSET, index);
        crate::hal::outl(io_base + SVGA_VALUE_PORT_OFFSET, value);
    }
}

// ── FIFO Helpers ────────────────────────────────────────────────────────────

/// Initialise the FIFO command ring.
fn init_fifo(svga: &mut VmwareSvga) {
    if svga.fifo_virt == 0 || svga.fifo_size == 0 {
        crate::serial_println!("[SVGA] FIFO region not available, skipping FIFO init");
        return;
    }

    let fifo = svga.fifo_virt as *mut u32;
    let num_regs: u32 = 16; // reserve space for FIFO registers (min offset in bytes)
    let min_bytes = num_regs * 4;

    unsafe {
        // Min = start of command area (in bytes)
        fifo.add(SVGA_FIFO_MIN).write_volatile(min_bytes);
        // Max = end of FIFO (in bytes)
        fifo.add(SVGA_FIFO_MAX).write_volatile(svga.fifo_size as u32);
        // next_cmd and stop both point to min (empty ring)
        fifo.add(SVGA_FIFO_NEXT_CMD).write_volatile(min_bytes);
        fifo.add(SVGA_FIFO_STOP).write_volatile(min_bytes);
    }

    // Tell the device the FIFO is configured.
    write_reg(svga.io_base, SVGA_REG_CONFIG_DONE, 1);

    crate::serial_println!(
        "[SVGA] FIFO initialized: base=0x{:x} size=0x{:x}",
        svga.fifo_virt,
        svga.fifo_size
    );
}

/// Write a single `u32` into the FIFO ring, advancing next_cmd with wrapping.
fn fifo_write(svga: &VmwareSvga, val: u32) {
    let fifo = svga.fifo_virt as *mut u32;

    unsafe {
        let min = fifo.add(SVGA_FIFO_MIN).read_volatile();
        let max = fifo.add(SVGA_FIFO_MAX).read_volatile();
        let mut next_cmd = fifo.add(SVGA_FIFO_NEXT_CMD).read_volatile();

        // Write the value at the current next_cmd offset (byte offset → u32 index).
        let ptr = (svga.fifo_virt as *mut u8).add(next_cmd as usize) as *mut u32;
        ptr.write_volatile(val);

        // Advance next_cmd, wrapping around to min if we hit max.
        next_cmd += 4;
        if next_cmd >= max {
            next_cmd = min;
        }
        fifo.add(SVGA_FIFO_NEXT_CMD).write_volatile(next_cmd);
    }
}

/// Synchronise the FIFO: ask the device to process pending commands and
/// spin-wait until it reports idle.
pub fn fifo_sync() {
    let svga = SVGA.lock();
    let svga = match svga.as_ref() {
        Some(s) => s,
        None => return,
    };

    write_reg(svga.io_base, SVGA_REG_SYNC, 1);
    while read_reg(svga.io_base, SVGA_REG_BUSY) != 0 {
        core::hint::spin_loop();
    }
}

// ── Initialisation ──────────────────────────────────────────────────────────

/// Probe the PCI bus for a VMware SVGA II device. If found, negotiate the
/// protocol version, set 1920×1080×32 mode, and initialise the FIFO.
///
/// Returns `true` if the device was found and initialised.
pub fn init() -> bool {
    let dev = match crate::drivers::pci::find_by_id(VMWARE_VENDOR_ID, VMWARE_SVGA_DEVICE_ID) {
        Some(d) => d,
        None => {
            crate::serial_println!("[SVGA] VMware SVGA II device not found on PCI bus");
            return false;
        }
    };

    crate::serial_println!(
        "[SVGA] Found VMware SVGA II at PCI {:02x}:{:02x}.{}",
        dev.bus,
        dev.device,
        dev.function
    );

    // Enable I/O space, memory space, and bus mastering.
    crate::drivers::pci::enable_bus_master(dev.bus, dev.device, dev.function);

    // BAR0 — I/O ports (bit 0 set indicates I/O space).
    let io_base = (dev.bar[0] & !0x3) as u16;

    // BAR1 — Framebuffer MMIO (handled via SVGA_REG_FB_START).
    // BAR2 — FIFO MMIO base.
    let fifo_phys = (dev.bar[2] & !0xF) as u64;

    crate::serial_println!("[SVGA] I/O base = 0x{:x}, FIFO BAR = 0x{:x}", io_base, fifo_phys);

    // ── Version negotiation ─────────────────────────────────────────────
    write_reg(io_base, SVGA_REG_ID, SVGA_ID_2);
    let id = read_reg(io_base, SVGA_REG_ID);
    if id != SVGA_ID_2 {
        // Fall back to ID 1
        write_reg(io_base, SVGA_REG_ID, SVGA_ID_1);
        let id = read_reg(io_base, SVGA_REG_ID);
        if id != SVGA_ID_1 {
            write_reg(io_base, SVGA_REG_ID, SVGA_ID_0);
        }
        crate::serial_println!("[SVGA] Negotiated version ID: 0x{:x}", read_reg(io_base, SVGA_REG_ID));
    } else {
        crate::serial_println!("[SVGA] Using SVGA_ID_2 (0x{:x})", SVGA_ID_2);
    }

    let capabilities = read_reg(io_base, SVGA_REG_CAPABILITIES);
    let max_width = read_reg(io_base, SVGA_REG_MAX_WIDTH);
    let max_height = read_reg(io_base, SVGA_REG_MAX_HEIGHT);
    let vram_size = read_reg(io_base, SVGA_REG_VRAM_SIZE);

    crate::serial_println!(
        "[SVGA] Capabilities=0x{:08x} max={}x{} VRAM={}K",
        capabilities,
        max_width,
        max_height,
        vram_size / 1024
    );

    // ── Set display mode 1920×1080×32 ───────────────────────────────────
    let desired_w: u32 = 1920;
    let desired_h: u32 = 1080;
    let desired_bpp: u32 = 32;

    let width = if desired_w <= max_width { desired_w } else { max_width };
    let height = if desired_h <= max_height { desired_h } else { max_height };

    write_reg(io_base, SVGA_REG_WIDTH, width);
    write_reg(io_base, SVGA_REG_HEIGHT, height);
    write_reg(io_base, SVGA_REG_BPP, desired_bpp);
    write_reg(io_base, SVGA_REG_ENABLE, 1);

    // Read back actual values the device settled on.
    let actual_w = read_reg(io_base, SVGA_REG_WIDTH);
    let actual_h = read_reg(io_base, SVGA_REG_HEIGHT);
    let actual_bpp = read_reg(io_base, SVGA_REG_BPP);
    let pitch = read_reg(io_base, SVGA_REG_BYTES_PER_LINE);
    let fb_phys = read_reg(io_base, SVGA_REG_FB_START) as u64;
    let fb_size = read_reg(io_base, SVGA_REG_FB_SIZE) as u64;
    let fifo_size = read_reg(io_base, SVGA_REG_FIFO_SIZE) as u64;
    let fifo_start = read_reg(io_base, SVGA_REG_FIFO_START) as u64;

    crate::serial_println!(
        "[SVGA] Mode set: {}x{}x{} pitch={} fb=0x{:x} fb_size=0x{:x}",
        actual_w,
        actual_h,
        actual_bpp,
        pitch,
        fb_phys,
        fb_size
    );

    // Use FIFO start register (more reliable than BAR2 directly).
    let fifo_base = if fifo_start != 0 { fifo_start } else { fifo_phys };

    let mut svga = VmwareSvga {
        io_base,
        fb_phys,
        fb_size,
        fifo_phys: fifo_base,
        fifo_size,
        fifo_virt: fifo_base, // identity-mapped
        width: actual_w,
        height: actual_h,
        bpp: actual_bpp,
        pitch,
        capabilities,
        enabled: true,
    };

    init_fifo(&mut svga);

    *SVGA.lock() = Some(svga);

    crate::serial_println!("[SVGA] VMware SVGA II driver initialized");
    true
}

// ── Mode Setting ────────────────────────────────────────────────────────────

/// Change the display mode. Returns `true` on success.
pub fn set_mode(width: u32, height: u32, bpp: u32) -> bool {
    let mut guard = SVGA.lock();
    let svga = match guard.as_mut() {
        Some(s) => s,
        None => return false,
    };

    let max_w = read_reg(svga.io_base, SVGA_REG_MAX_WIDTH);
    let max_h = read_reg(svga.io_base, SVGA_REG_MAX_HEIGHT);
    if width > max_w || height > max_h {
        crate::serial_println!(
            "[SVGA] Requested {}x{} exceeds max {}x{}",
            width, height, max_w, max_h
        );
        return false;
    }

    write_reg(svga.io_base, SVGA_REG_WIDTH, width);
    write_reg(svga.io_base, SVGA_REG_HEIGHT, height);
    write_reg(svga.io_base, SVGA_REG_BPP, bpp);
    write_reg(svga.io_base, SVGA_REG_ENABLE, 1);

    svga.width = read_reg(svga.io_base, SVGA_REG_WIDTH);
    svga.height = read_reg(svga.io_base, SVGA_REG_HEIGHT);
    svga.bpp = read_reg(svga.io_base, SVGA_REG_BPP);
    svga.pitch = read_reg(svga.io_base, SVGA_REG_BYTES_PER_LINE);
    svga.fb_phys = read_reg(svga.io_base, SVGA_REG_FB_START) as u64;
    svga.fb_size = read_reg(svga.io_base, SVGA_REG_FB_SIZE) as u64;

    crate::serial_println!(
        "[SVGA] Mode changed: {}x{}x{} pitch={}",
        svga.width, svga.height, svga.bpp, svga.pitch
    );

    true
}

// ── Queries ─────────────────────────────────────────────────────────────────

/// Returns `(fb_phys, width, height, pitch_in_pixels)` if the SVGA device is
/// initialised.
pub fn get_framebuffer() -> Option<(u64, u32, u32, u32)> {
    let guard = SVGA.lock();
    let svga = guard.as_ref()?;
    let bytes_per_pixel = if svga.bpp > 0 { svga.bpp / 8 } else { 4 };
    let pitch_in_pixels = if bytes_per_pixel > 0 {
        svga.pitch / bytes_per_pixel
    } else {
        svga.pitch / 4
    };
    Some((svga.fb_phys, svga.width, svga.height, pitch_in_pixels))
}

/// Whether the VMware SVGA device has been successfully initialised.
pub fn is_available() -> bool {
    SVGA.lock().is_some()
}

/// Return the device capability bits.
pub fn get_capabilities() -> u32 {
    SVGA.lock().as_ref().map_or(0, |s| s.capabilities)
}

/// Returns `true` when the hardware cursor (SVGA_CAP_CURSOR) is supported.
///
/// When true the compositor can call [`define_cursor`] once at init and
/// [`move_cursor`] every frame instead of drawing a software cursor into the
/// backbuffer and re-blitting the entire screen.
pub fn has_cursor_support() -> bool {
    SVGA.lock()
        .as_ref()
        .map_or(false, |s| s.capabilities & SVGA_CAP_CURSOR != 0)
}

// ── 2-D Acceleration: FIFO Commands ────────────────────────────────────────

/// Notify the SVGA device that the entire visible screen has changed.
///
/// This is the primary method to trigger a display refresh after writing
/// directly to the framebuffer memory. Without this, the QEMU window will
/// only show stale content.
///
/// **Synchronous** — writes the update command and spin-waits for the
/// device to finish processing it. Use `display_notify()` for the
/// non-blocking variant.
pub fn update_screen() {
    let guard = SVGA.lock();
    let svga = match guard.as_ref() {
        Some(s) if s.enabled => s,
        _ => return,
    };

    fifo_write(svga, SVGA_CMD_UPDATE);
    fifo_write(svga, 0);
    fifo_write(svga, 0);
    fifo_write(svga, svga.width);
    fifo_write(svga, svga.height);

    drop(guard);
    fifo_sync();
}

/// Request a non-blocking display update.
///
/// Writes the same full-screen update command to the FIFO as
/// `update_screen()`, kicks the device with `SVGA_REG_SYNC`, but
/// returns immediately **without** waiting for the device to finish.
/// This is the fast-path used for interactive display updates (typing,
/// cursor blink, etc.) where the extra latency of `fifo_sync()` is
/// unacceptable.
pub fn display_notify() {
    let guard = SVGA.lock();
    let svga = match guard.as_ref() {
        Some(s) if s.enabled => s,
        _ => return,
    };

    fifo_write(svga, SVGA_CMD_UPDATE);
    fifo_write(svga, 0);
    fifo_write(svga, 0);
    fifo_write(svga, svga.width);
    fifo_write(svga, svga.height);

    // Kick the device but do NOT spin-wait for completion.
    write_reg(svga.io_base, SVGA_REG_SYNC, 1);
}

/// Mark a rectangular region as dirty (SVGA_CMD_UPDATE).
pub fn update_rect(x: u32, y: u32, w: u32, h: u32) {
    let guard = SVGA.lock();
    let svga = match guard.as_ref() {
        Some(s) if s.enabled => s,
        _ => return,
    };

    fifo_write(svga, SVGA_CMD_UPDATE);
    fifo_write(svga, x);
    fifo_write(svga, y);
    fifo_write(svga, w);
    fifo_write(svga, h);

    // Explicitly drop guard before sync (sync acquires the lock too).
    drop(guard);
    fifo_sync();
}

/// Fill a rectangle with `color` via the FIFO (SVGA_CMD_RECT_FILL).
///
/// Falls back to a software fill through the framebuffer if the device lacks
/// the `SVGA_CAP_RECT_FILL` capability.
pub fn fill_rect(color: u32, x: u32, y: u32, w: u32, h: u32) {
    let guard = SVGA.lock();
    let svga = match guard.as_ref() {
        Some(s) if s.enabled => s,
        _ => return,
    };

    if svga.capabilities & SVGA_CAP_RECT_FILL != 0 {
        fifo_write(svga, SVGA_CMD_RECT_FILL);
        fifo_write(svga, color);
        fifo_write(svga, x);
        fifo_write(svga, y);
        fifo_write(svga, w);
        fifo_write(svga, h);

        drop(guard);
        fifo_sync();
    } else {
        // Software fallback: write directly to the framebuffer.
        // fb_phys is a physical address; access it via the kernel's higher-half
        // (PHYS_OFF + phys) which is mapped for all physical addresses 0..4 GiB.
        const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
        let fb_virt = if svga.fb_phys < PHYS_OFF { svga.fb_phys + PHYS_OFF } else { svga.fb_phys };
        let fb = fb_virt as *mut u32;
        let pitch_pixels = svga.pitch / 4;
        for row in 0..h {
            for col in 0..w {
                let offset = ((y + row) * pitch_pixels + (x + col)) as usize;
                unsafe {
                    fb.add(offset).write_volatile(color);
                }
            }
        }

        // Issue an update so the device knows the region changed.
        fifo_write(svga, SVGA_CMD_UPDATE);
        fifo_write(svga, x);
        fifo_write(svga, y);
        fifo_write(svga, w);
        fifo_write(svga, h);

        drop(guard);
        fifo_sync();
    }
}

/// Copy a rectangle from (src_x, src_y) to (dst_x, dst_y) via FIFO
/// (SVGA_CMD_RECT_COPY). No-op if the device lacks `SVGA_CAP_RECT_COPY`.
pub fn copy_rect(src_x: u32, src_y: u32, dst_x: u32, dst_y: u32, w: u32, h: u32) {
    let guard = SVGA.lock();
    let svga = match guard.as_ref() {
        Some(s) if s.enabled => s,
        _ => return,
    };

    if svga.capabilities & SVGA_CAP_RECT_COPY == 0 {
        return;
    }

    fifo_write(svga, SVGA_CMD_RECT_COPY);
    fifo_write(svga, src_x);
    fifo_write(svga, src_y);
    fifo_write(svga, dst_x);
    fifo_write(svga, dst_y);
    fifo_write(svga, w);
    fifo_write(svga, h);

    drop(guard);
    fifo_sync();
}

/// Define a hardware cursor shape (SVGA_CMD_DEFINE_CURSOR).
///
/// `and_mask` and `xor_mask` are arrays of `u32` pixels making up the cursor
/// image (width × height each). No-op if the device lacks cursor support.
pub fn define_cursor(
    hotspot_x: u16,
    hotspot_y: u16,
    width: u16,
    height: u16,
    and_mask: &[u32],
    xor_mask: &[u32],
) {
    let guard = SVGA.lock();
    let svga = match guard.as_ref() {
        Some(s) if s.enabled => s,
        _ => return,
    };

    if svga.capabilities & SVGA_CAP_CURSOR == 0 {
        return;
    }

    fifo_write(svga, SVGA_CMD_DEFINE_CURSOR);
    fifo_write(svga, 0); // cursor id
    fifo_write(svga, hotspot_x as u32);
    fifo_write(svga, hotspot_y as u32);
    fifo_write(svga, width as u32);
    fifo_write(svga, height as u32);
    fifo_write(svga, 1); // AND depth (1 bpp)
    fifo_write(svga, 32); // XOR depth (32 bpp)

    for &word in and_mask {
        fifo_write(svga, word);
    }
    for &word in xor_mask {
        fifo_write(svga, word);
    }

    drop(guard);
    fifo_sync();
}

/// Move the hardware cursor to (x, y).
///
/// Uses FIFO cursor-bypass-2 registers when the device supports it, otherwise
/// falls back to the legacy SVGA_CMD_MOVE_CURSOR FIFO command.
pub fn move_cursor(x: u32, y: u32) {
    let guard = SVGA.lock();
    let svga = match guard.as_ref() {
        Some(s) if s.enabled => s,
        _ => return,
    };

    if svga.capabilities & SVGA_CAP_CURSOR_BYPASS_2 != 0 && svga.fifo_virt != 0 {
        // Cursor bypass 2: write directly to FIFO register area.
        let fifo = svga.fifo_virt as *mut u32;
        unsafe {
            fifo.add(SVGA_FIFO_CURSOR_ON).write_volatile(1);
            fifo.add(SVGA_FIFO_CURSOR_X).write_volatile(x);
            fifo.add(SVGA_FIFO_CURSOR_Y).write_volatile(y);
        }
    } else {
        // Legacy: issue a FIFO command.
        fifo_write(svga, SVGA_CMD_MOVE_CURSOR);
        fifo_write(svga, x);
        fifo_write(svga, y);
        drop(guard);
        fifo_sync();
    }
}
