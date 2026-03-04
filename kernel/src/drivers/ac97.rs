//! AC97 Audio Codec Driver
//!
//! Supports the Intel ICH AC97 audio controller (PCI vendor 0x8086, device 0x2415)
//! commonly emulated by QEMU (`-device AC97`).
//!
//! Architecture:
//!   - **Mixer** registers (via NAM — Native Audio Mixer, I/O BAR0)
//!   - **Bus Master** registers (via NABM — Native Audio Bus Master, I/O BAR1)
//!   - DMA-based playback via Buffer Descriptor List (BDL)
//!
//! Supports 16-bit stereo PCM at 48 kHz (AC97 default sample rate).

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

// ---------------------------------------------------------------------------
// PCI identification
// ---------------------------------------------------------------------------

const AC97_VENDOR_ID: u16 = 0x8086;
const AC97_DEVICE_ID: u16 = 0x2415;

// ---------------------------------------------------------------------------
// NAM (Native Audio Mixer) register offsets — I/O port BAR0
// ---------------------------------------------------------------------------

/// Master volume (left/right, 5-bit attenuation + mute bit 15)
const NAM_MASTER_VOL: u16 = 0x02;
/// PCM out volume
const NAM_PCM_VOL: u16 = 0x18;
/// Extended audio status/control
const NAM_EXT_AUDIO_CTRL: u16 = 0x2A;
/// Sample rate for front DAC
const NAM_FRONT_DAC_RATE: u16 = 0x2C;
/// Reset register
const NAM_RESET: u16 = 0x00;
/// Extended audio ID
const NAM_EXT_AUDIO_ID: u16 = 0x28;

// ---------------------------------------------------------------------------
// NABM (Native Audio Bus Master) register offsets — I/O port BAR1
// ---------------------------------------------------------------------------

// PCM Out (channel 1) registers, offset 0x10 from NABM base
const NABM_PCM_OUT_BDBAR: u16 = 0x10; // Buffer Descriptor List Base Address (32-bit)
const NABM_PCM_OUT_CIV: u16 = 0x14;   // Current Index Value (8-bit)
const NABM_PCM_OUT_LVI: u16 = 0x15;   // Last Valid Index (8-bit)
const NABM_PCM_OUT_SR: u16 = 0x16;    // Status Register (16-bit)
const NABM_PCM_OUT_PICB: u16 = 0x18;  // Position in Current Buffer (16-bit)
const NABM_PCM_OUT_CR: u16 = 0x1B;    // Control Register (8-bit)

// Global control register
const NABM_GLOB_CTRL: u16 = 0x2C;     // Global Control (32-bit)
const NABM_GLOB_STA: u16 = 0x30;      // Global Status (32-bit)

// Control register bits
const CR_RPBM: u8 = 0x01;   // Run/Pause Bus Master
const CR_RR: u8 = 0x02;     // Reset Registers
const CR_LVBIE: u8 = 0x04;  // Last Valid Buffer Interrupt Enable
const CR_IOCE: u8 = 0x08;   // Interrupt on Completion Enable

// Status register bits
const SR_DCH: u16 = 0x0001;   // DMA Controller Halted
const SR_CELV: u16 = 0x0002;  // Current Equals Last Valid
const SR_LVBCI: u16 = 0x0004; // Last Valid Buffer Completion Interrupt
const SR_BCIS: u16 = 0x0008;  // Buffer Completion Interrupt Status
const SR_FIFOE: u16 = 0x0010; // FIFO Error

// Global control bits
const GC_GIE: u32 = 0x01;    // Global Interrupt Enable
const GC_CR: u32 = 0x02;     // Cold Reset
const GC_WR: u32 = 0x04;     // Warm Reset

// ---------------------------------------------------------------------------
// Buffer Descriptor List entry (8 bytes each, up to 32 entries)
// ---------------------------------------------------------------------------

/// A single entry in the Buffer Descriptor List (BDL).
/// The hardware reads these to know where the DMA buffers are.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BdlEntry {
    /// Physical address of the audio buffer
    addr: u32,
    /// Number of samples (16-bit samples, so bytes / 2)
    /// Bit 31 = IOC (interrupt on completion)
    /// Bit 30 = BUP (buffer underrun policy: 0 = last sample, 1 = zero)
    samples_and_flags: u32,
}

const BDL_IOC: u32 = 1 << 31;
const BDL_BUP: u32 = 1 << 30;
const BDL_MAX_ENTRIES: usize = 32;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct Ac97State {
    /// I/O port base for NAM (mixer) registers
    nam_base: u16,
    /// I/O port base for NABM (bus master) registers
    nabm_base: u16,
    /// Physical address of the BDL (must be 8-byte aligned, below 4 GiB)
    bdl_phys: u32,
    /// Buffer Descriptor List address (stored as usize for Send safety, 32 entries)
    bdl_addr: usize,
    /// Physical addresses of DMA buffers (one per BDL entry)
    buf_phys: [u32; BDL_MAX_ENTRIES],
    /// Virtual pointers to DMA buffers (stored as usize for Send safety)
    buf_virt: [usize; BDL_MAX_ENTRIES],
    /// Size of each buffer in bytes
    buf_size: usize,
    /// Current write index (next BDL entry to fill)
    write_idx: usize,
    /// Sample rate (default 48000)
    sample_rate: u32,
    /// Master volume (0-31, 0 = max)
    master_volume: u8,
    /// Whether playback is running
    playing: bool,
    /// Whether the device is available
    available: bool,
}

static AC97: Mutex<Option<Ac97State>> = Mutex::new(None);

/// Per-buffer size: 4096 bytes = 2048 samples (16-bit) = 1024 stereo frames
/// At 48 kHz stereo 16-bit: ~21.3ms per buffer
const DMA_BUF_SIZE: usize = 4096;
/// Number of DMA buffers we actually use (ring of 8 for low latency)
const NUM_BUFFERS: usize = 8;

// ---------------------------------------------------------------------------
// I/O port helpers
// ---------------------------------------------------------------------------

unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    val
}

unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack));
    val
}

unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack));
    val
}

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

unsafe fn outw(port: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
}

unsafe fn outl(port: u16, val: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack));
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initialize the AC97 audio controller.
/// Returns `true` if the device was found and initialized.
pub fn init() -> bool {
    // Find the AC97 device on PCI
    let dev = match crate::drivers::pci::find_by_id(AC97_VENDOR_ID, AC97_DEVICE_ID) {
        Some(d) => d,
        None => {
            crate::serial_println!("[AC97] No AC97 device found on PCI bus");
            return false;
        }
    };

    crate::serial_println!(
        "[AC97] Found AC97 device: bus={}, dev={}, func={}, irq={}",
        dev.bus, dev.device, dev.function, dev.interrupt_line
    );

    // BAR0 = NAM (I/O space), BAR1 = NABM (I/O space)
    let nam_base = (dev.bar[0] & 0xFFFC) as u16;
    let nabm_base = (dev.bar[1] & 0xFFFC) as u16;

    crate::serial_println!("[AC97] NAM I/O base: 0x{:04X}, NABM I/O base: 0x{:04X}", nam_base, nabm_base);

    // Enable PCI bus mastering + I/O space
    crate::drivers::pci::enable_bus_master(dev.bus, dev.device, dev.function);
    // Also enable I/O space (bit 0)
    let cmd = crate::drivers::pci::pci_config_read32(dev.bus, dev.device, dev.function, 0x04);
    crate::drivers::pci::pci_config_write32(
        dev.bus, dev.device, dev.function, 0x04,
        cmd | 0x01,
    );

    // Cold reset the codec
    unsafe {
        outl(nabm_base + NABM_GLOB_CTRL, GC_CR);
        // Wait for codec to settle
        for _ in 0..100_000 { core::arch::asm!("pause"); }
        outl(nabm_base + NABM_GLOB_CTRL, GC_GIE | GC_CR);
    }

    // Wait for codec ready (check global status)
    let mut codec_ready = false;
    for _ in 0..1000 {
        unsafe { for _ in 0..10_000 { core::arch::asm!("pause"); } }
        let gsta = unsafe { inl(nabm_base + NABM_GLOB_STA) };
        if gsta & 0x100 != 0 {
            // Primary codec ready
            codec_ready = true;
            break;
        }
    }

    if !codec_ready {
        crate::serial_println!("[AC97] Codec not ready — giving up");
        return false;
    }

    // Reset the mixer
    unsafe { outw(nam_base + NAM_RESET, 0x00); }
    for _ in 0..100_000 { unsafe { core::arch::asm!("pause"); } }

    // Set master volume to max (0 = max attenuation off)
    unsafe { outw(nam_base + NAM_MASTER_VOL, 0x0000); }
    // Set PCM out volume to max
    unsafe { outw(nam_base + NAM_PCM_VOL, 0x0808); }

    // Check if variable rate audio is supported
    let ext_id = unsafe { inw(nam_base + NAM_EXT_AUDIO_ID) };
    if ext_id & 0x0001 != 0 {
        // Enable variable rate audio
        let ext_ctrl = unsafe { inw(nam_base + NAM_EXT_AUDIO_CTRL) };
        unsafe { outw(nam_base + NAM_EXT_AUDIO_CTRL, ext_ctrl | 0x0001); }
        // Set sample rate to 48000 Hz
        unsafe { outw(nam_base + NAM_FRONT_DAC_RATE, 48000); }
        crate::serial_println!("[AC97] Variable rate audio enabled, rate=48000 Hz");
    } else {
        crate::serial_println!("[AC97] Fixed rate codec (48000 Hz)");
    }

    // Allocate BDL (32 entries × 8 bytes = 256 bytes)
    // We need physical memory below 4 GiB for DMA.
    // Use a kernel page (identity-mapped in the first 4 GiB).
    let bdl_page = crate::mm::pmm::alloc_page().expect("[AC97] Failed to allocate BDL page");
    let bdl_phys = bdl_page as u32;
    let bdl_addr = bdl_page as usize;

    // Zero BDL
    unsafe {
        core::ptr::write_bytes(bdl_page as *mut u8, 0, BDL_MAX_ENTRIES * 8);
    }

    // Allocate DMA buffers (one page each = 4096 bytes)
    let mut buf_phys = [0u32; BDL_MAX_ENTRIES];
    let mut buf_virt = [0usize; BDL_MAX_ENTRIES];

    for i in 0..NUM_BUFFERS {
        let page = crate::mm::pmm::alloc_page().expect("[AC97] Failed to allocate DMA buffer");
        buf_phys[i] = page as u32;
        buf_virt[i] = page as usize;

        // Zero the buffer
        unsafe {
            core::ptr::write_bytes(page as *mut u8, 0, DMA_BUF_SIZE);
        }

        // Set up BDL entry
        unsafe {
            let entry = (bdl_addr + i * 8) as *mut BdlEntry;
            (*entry).addr = buf_phys[i];
            let samples = (DMA_BUF_SIZE / 2) as u32;
            (*entry).samples_and_flags = samples | BDL_IOC;
        }
    }

    // Reset PCM Out channel
    unsafe {
        outb(nabm_base + NABM_PCM_OUT_CR, CR_RR);
        for _ in 0..10_000 { core::arch::asm!("pause"); }
        outb(nabm_base + NABM_PCM_OUT_CR, 0);
    }

    // Set BDL base address
    unsafe {
        outl(nabm_base + NABM_PCM_OUT_BDBAR, bdl_phys);
    }

    // Set Last Valid Index to NUM_BUFFERS - 1
    unsafe {
        outb(nabm_base + NABM_PCM_OUT_LVI, (NUM_BUFFERS - 1) as u8);
    }

    // Clear status bits
    unsafe {
        outw(nabm_base + NABM_PCM_OUT_SR, SR_LVBCI | SR_BCIS | SR_FIFOE);
    }

    let state = Ac97State {
        nam_base,
        nabm_base,
        bdl_phys,
        bdl_addr,
        buf_phys,
        buf_virt,
        buf_size: DMA_BUF_SIZE,
        write_idx: 0,
        sample_rate: 48000,
        master_volume: 0,
        playing: false,
        available: true,
    };

    *AC97.lock() = Some(state);

    crate::serial_println!("[AC97] Audio controller initialized (48 kHz, 16-bit stereo)");
    true
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns true if the AC97 driver is initialized and available.
pub fn is_available() -> bool {
    AC97.lock().as_ref().map_or(false, |s| s.available)
}

/// Get the current sample rate.
pub fn sample_rate() -> u32 {
    AC97.lock().as_ref().map_or(0, |s| s.sample_rate)
}

/// Set master volume (0 = full volume, 63 = muted).
pub fn set_volume(left: u8, right: u8) {
    let mut guard = AC97.lock();
    if let Some(state) = guard.as_mut() {
        let l = (left & 0x3F) as u16;
        let r = (right & 0x3F) as u16;
        let val = (l << 8) | r;
        unsafe { outw(state.nam_base + NAM_MASTER_VOL, val); }
        state.master_volume = left;
    }
}

/// Get master volume (0 = full, 63 = mute).
pub fn get_volume() -> (u8, u8) {
    let guard = AC97.lock();
    if let Some(state) = guard.as_ref() {
        let val = unsafe { inw(state.nam_base + NAM_MASTER_VOL) };
        (((val >> 8) & 0x3F) as u8, (val & 0x3F) as u8)
    } else {
        (63, 63)
    }
}

/// Submit a buffer of 16-bit signed stereo PCM samples for playback.
/// `data` should contain interleaved left/right 16-bit samples.
/// Returns the number of bytes queued.
pub fn play_buffer(data: &[u8]) -> usize {
    let mut guard = AC97.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => return 0,
    };

    let chunk_size = state.buf_size;
    let mut written = 0;

    while written < data.len() {
        let idx = state.write_idx % NUM_BUFFERS;
        let remaining = data.len() - written;
        let copy_len = remaining.min(chunk_size);

        // Copy audio data to DMA buffer
        unsafe {
            let dst = state.buf_virt[idx] as *mut u8;
            core::ptr::copy_nonoverlapping(data[written..].as_ptr(), dst, copy_len);
            // Zero-fill remainder if partial buffer
            if copy_len < chunk_size {
                core::ptr::write_bytes(dst.add(copy_len), 0, chunk_size - copy_len);
            }
        }

        // Update BDL entry
        let samples = (chunk_size / 2) as u32;
        unsafe {
            let entry = (state.bdl_addr + idx * 8) as *mut BdlEntry;
            (*entry).addr = state.buf_phys[idx];
            (*entry).samples_and_flags = samples | BDL_IOC;
        }

        // Update Last Valid Index
        unsafe {
            outb(state.nabm_base + NABM_PCM_OUT_LVI, idx as u8);
        }

        state.write_idx += 1;
        written += copy_len;
    }

    // Start playback if not already running
    if !state.playing && written > 0 {
        unsafe {
            outb(state.nabm_base + NABM_PCM_OUT_CR, CR_RPBM | CR_LVBIE | CR_IOCE);
        }
        state.playing = true;
    }

    written
}

/// Stop audio playback.
pub fn stop() {
    let mut guard = AC97.lock();
    if let Some(state) = guard.as_mut() {
        unsafe {
            // Pause DMA
            outb(state.nabm_base + NABM_PCM_OUT_CR, 0);
            // Clear status
            outw(state.nabm_base + NABM_PCM_OUT_SR, SR_LVBCI | SR_BCIS | SR_FIFOE);
        }
        state.playing = false;
        state.write_idx = 0;
    }
}

/// Check if audio is currently playing.
pub fn is_playing() -> bool {
    AC97.lock().as_ref().map_or(false, |s| s.playing)
}

/// Get the playback status (CIV, LVI, PICB).
pub fn status() -> (u8, u8, u16) {
    let guard = AC97.lock();
    if let Some(state) = guard.as_ref() {
        unsafe {
            let civ = inb(state.nabm_base + NABM_PCM_OUT_CIV);
            let lvi = inb(state.nabm_base + NABM_PCM_OUT_LVI);
            let picb = inw(state.nabm_base + NABM_PCM_OUT_PICB);
            (civ, lvi, picb)
        }
    } else {
        (0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Tone generation helpers
// ---------------------------------------------------------------------------

/// Generate a sine wave tone and play it.
/// `freq_hz`: frequency in Hz (e.g. 440 for A4)
/// `duration_ms`: duration in milliseconds
/// `amplitude`: volume 0.0 to 1.0
pub fn play_tone(freq_hz: u32, duration_ms: u32, amplitude: f32) {
    if !is_available() { return; }

    let rate = 48000u32;
    let channels = 2u32; // stereo
    let total_frames = (rate * duration_ms) / 1000;
    let total_samples = total_frames * channels;
    let total_bytes = (total_samples * 2) as usize; // 16-bit

    let mut buf: Vec<u8> = vec![0u8; total_bytes];

    // Generate sine wave using integer approximation
    // We use a lookup table approach for no_std (no libm sin())
    for frame in 0..total_frames {
        let sample = sine_sample(frame, freq_hz, rate, amplitude);
        let s16 = (sample * 32767.0) as i16;
        let idx = (frame * channels * 2) as usize;
        // Left channel
        buf[idx] = (s16 & 0xFF) as u8;
        buf[idx + 1] = ((s16 >> 8) & 0xFF) as u8;
        // Right channel (same)
        buf[idx + 2] = (s16 & 0xFF) as u8;
        buf[idx + 3] = ((s16 >> 8) & 0xFF) as u8;
    }

    play_buffer(&buf);
}

/// Integer-friendly sine approximation using Bhaskara I's formula.
/// Returns a value in [-1.0, 1.0].
fn sine_sample(frame: u32, freq_hz: u32, rate: u32, amplitude: f32) -> f32 {
    // Phase in degrees: (frame * freq * 360) / rate
    let phase_deg = ((frame as u64 * freq_hz as u64 * 360) / rate as u64) % 360;
    let x = phase_deg as f32;

    // Bhaskara I's sine approximation: sin(x°) ≈ 4x(180-x) / (40500 - x(180-x))
    // For x in [0, 180], then negate for [180, 360]
    let (xx, sign) = if x <= 180.0 {
        (x, 1.0f32)
    } else {
        (x - 180.0, -1.0f32)
    };

    let numerator = 4.0 * xx * (180.0 - xx);
    let denominator = 40500.0 - xx * (180.0 - xx);

    if denominator.abs() < 0.001 {
        0.0
    } else {
        sign * (numerator / denominator) * amplitude
    }
}

/// Play a simple beep (440 Hz, 200ms).
pub fn beep() {
    play_tone(440, 200, 0.5);
}

/// Play a startup chime (three ascending tones).
pub fn startup_chime() {
    play_tone(523, 150, 0.4);  // C5
    play_tone(659, 150, 0.4);  // E5
    play_tone(784, 200, 0.4);  // G5
}
