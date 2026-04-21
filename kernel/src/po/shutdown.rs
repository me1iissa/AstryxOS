//! Shutdown / Reboot Coordination
//!
//! Implements the orderly shutdown and reboot sequences: notifying callbacks,
//! flushing caches, stopping drivers in dependency order, and finally
//! powering off or rebooting.
//!
//! # Driver Stop Order
//!
//! Higher-level consumers must stop before lower-level providers so in-flight
//! DMA or I/O is not abandoned mid-transfer:
//!
//!  1. `ac97`       — stop DMA audio (highest-level consumer of PCI bus master)
//!  2. `e1000`      — disable NIC TX/RX, mask interrupts
//!  3. `virtio_net` — reset virtio-net device
//!  4. `virtio_blk` — reset virtio-blk device (storage before disk drivers)
//!  5. `ahci`       — stop SATA DMA command engines
//!  6. `ata`        — drain ATA PIO BSY, clear device list
//!  7. `console`    — hide cursor, final framebuffer flush
//!  8. `serial`     — wait for TX FIFO to drain (last debug output)
//!
//! PCI, keyboard, mouse, RTC, TTY, PTY, and USB are not included because
//! they have no on-going DMA or buffered I/O to quiesce — they are reset
//! implicitly by the ACPI/firmware power-off path.

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

/// Phases of a shutdown sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    NotStarted,
    NotifyingCallbacks,
    FlushingCaches,
    StoppingDrivers,
    PoweringOff,
    Complete,
}

/// Current shutdown phase.
static SHUTDOWN_PHASE: Mutex<ShutdownPhase> = Mutex::new(ShutdownPhase::NotStarted);

// ── Driver stop tracking (for dry-run / test verification) ─────────────────
//
// Each bit in DRIVERS_STOPPED corresponds to one driver.  The sweep sets the
// bit atomically before calling `stop()` so the test can assert every driver
// was visited exactly once, without needing heap allocation or trait objects.

/// Bit 0 — ac97
pub const DRIVER_BIT_AC97:       u32 = 1 << 0;
/// Bit 1 — e1000
pub const DRIVER_BIT_E1000:      u32 = 1 << 1;
/// Bit 2 — virtio_net
pub const DRIVER_BIT_VIRTIO_NET: u32 = 1 << 2;
/// Bit 3 — virtio_blk
pub const DRIVER_BIT_VIRTIO_BLK: u32 = 1 << 3;
/// Bit 4 — ahci
pub const DRIVER_BIT_AHCI:       u32 = 1 << 4;
/// Bit 5 — ata
pub const DRIVER_BIT_ATA:        u32 = 1 << 5;
/// Bit 6 — console
pub const DRIVER_BIT_CONSOLE:    u32 = 1 << 6;
/// Bit 7 — serial
pub const DRIVER_BIT_SERIAL:     u32 = 1 << 7;

/// All expected driver bits OR-ed together.
pub const DRIVER_BITS_ALL: u32 = DRIVER_BIT_AC97
    | DRIVER_BIT_E1000
    | DRIVER_BIT_VIRTIO_NET
    | DRIVER_BIT_VIRTIO_BLK
    | DRIVER_BIT_AHCI
    | DRIVER_BIT_ATA
    | DRIVER_BIT_CONSOLE
    | DRIVER_BIT_SERIAL;

/// Bitmask that is OR-ed during `run_driver_stop_sweep()`.
/// Reset to 0 by `init_shutdown()` so dry-runs can be run repeatedly.
static DRIVERS_STOPPED: AtomicU32 = AtomicU32::new(0);

/// Initialize shutdown state.
pub fn init_shutdown() {
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::NotStarted;
    DRIVERS_STOPPED.store(0, Ordering::SeqCst);
}

/// Get the current shutdown phase.
pub fn get_shutdown_phase() -> ShutdownPhase {
    *SHUTDOWN_PHASE.lock()
}

/// Returns the bitmask of drivers that have been stopped in the most recent
/// sweep.  Each bit corresponds to a `DRIVER_BIT_*` constant.
pub fn drivers_stopped_mask() -> u32 {
    DRIVERS_STOPPED.load(Ordering::Acquire)
}

/// Perform a clean shutdown sequence.
pub fn initiate_shutdown() {
    crate::serial_println!("[Po] Initiating system shutdown...");

    // Phase 1: Notify power callbacks
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::NotifyingCallbacks;
    super::power::notify_power_callbacks(super::PowerAction::Shutdown);

    // Phase 2: Flush caches
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::FlushingCaches;
    flush_all_caches();

    // Phase 3: Stop drivers
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::StoppingDrivers;
    stop_all_drivers();

    // Phase 4: Power off
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::PoweringOff;
    super::acpi::acpi_shutdown();

    // If we somehow get here, mark complete
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::Complete;
}

/// Perform a clean reboot sequence.
pub fn initiate_reboot() {
    crate::serial_println!("[Po] Initiating system reboot...");

    // Phase 1: Notify power callbacks
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::NotifyingCallbacks;
    super::power::notify_power_callbacks(super::PowerAction::Reboot);

    // Phase 2: Flush caches
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::FlushingCaches;
    flush_all_caches();

    // Phase 3: Stop drivers
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::StoppingDrivers;
    stop_all_drivers();

    // Phase 4: Reboot
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::PoweringOff;
    super::acpi::system_reboot();

    // If we somehow get here, mark complete
    *SHUTDOWN_PHASE.lock() = ShutdownPhase::Complete;
}

/// Emergency shutdown — skip all cleanup, immediately power off.
pub fn emergency_shutdown() {
    crate::serial_println!("[Po] EMERGENCY SHUTDOWN — skipping cleanup!");
    super::acpi::acpi_shutdown();
}

/// Sync all mounted filesystems and flush the page cache.
pub fn flush_all_caches() {
    crate::serial_println!("[Po] Flushing all caches...");
    crate::vfs::sync_all();
    crate::serial_println!("[Po] All caches flushed");
}

/// Execute the ordered driver-stop sweep.
///
/// Every driver gets its `stop()` invoked once, in dependency order.
/// Each call is preceded by a log line (`[PO] stopping <name>...`) and the
/// corresponding `DRIVER_BIT_*` is OR-ed into `DRIVERS_STOPPED` before the
/// call so a panic inside `stop()` still records that the driver was reached.
///
/// The `#[inline(never)]` attribute keeps this function visible in
/// backtraces if a driver panics during shutdown.
#[inline(never)]
fn run_driver_stop_sweep() {
    macro_rules! do_stop {
        ($bit:expr, $name:expr, $call:expr) => {{
            crate::serial_println!("[Po] stopping {}...", $name);
            DRIVERS_STOPPED.fetch_or($bit, Ordering::AcqRel);
            $call;
        }};
    }

    // 1. AC97 — DMA audio (highest-level PCI bus-master consumer)
    do_stop!(DRIVER_BIT_AC97,       "ac97",       crate::drivers::ac97::stop());
    // 2. E1000 — disable NIC TX/RX engines, mask interrupts
    do_stop!(DRIVER_BIT_E1000,      "e1000",      crate::net::e1000::stop());
    // 3. virtio-net — reset virtio device
    do_stop!(DRIVER_BIT_VIRTIO_NET, "virtio_net", crate::net::virtio_net::stop());
    // 4. virtio-blk — reset virtio device (before AHCI so PCI bus is stable)
    do_stop!(DRIVER_BIT_VIRTIO_BLK, "virtio_blk", crate::drivers::virtio_blk::stop());
    // 5. AHCI — stop SATA DMA command engines
    do_stop!(DRIVER_BIT_AHCI,       "ahci",       crate::drivers::ahci::stop());
    // 6. ATA PIO — drain BSY, clear device list
    do_stop!(DRIVER_BIT_ATA,        "ata",        crate::drivers::ata::stop());
    // 7. Console — hide cursor, final framebuffer flush
    do_stop!(DRIVER_BIT_CONSOLE,    "console",    crate::drivers::console::stop());
    // 8. Serial — flush TX FIFO (last: we want debug output up to the end)
    do_stop!(DRIVER_BIT_SERIAL,     "serial",     crate::drivers::serial::stop());
}

/// Full driver stop sweep — called from `initiate_shutdown()` and
/// `initiate_reboot()`.
pub fn stop_all_drivers() {
    crate::serial_println!("[Po] Stopping all drivers...");
    DRIVERS_STOPPED.store(0, Ordering::SeqCst);
    run_driver_stop_sweep();
    crate::serial_println!("[Po] All drivers stopped");
}

/// Dry-run version of the shutdown sweep for headless testing.
///
/// Executes the complete driver-stop sequence (including real `stop()` calls
/// on each driver, which are safe to call even when the device is absent) but
/// does **not** call `hal::halt()`, invoke ACPI power-off, or alter the
/// `SHUTDOWN_PHASE` state machine.
///
/// Returns the bitmask of driver bits that were set, which must equal
/// `DRIVER_BITS_ALL` for the test to pass.
pub fn shutdown_dry_run() -> u32 {
    crate::serial_println!("[Po] Dry-run: driver stop sweep (no halt)");
    DRIVERS_STOPPED.store(0, Ordering::SeqCst);
    run_driver_stop_sweep();
    let mask = DRIVERS_STOPPED.load(Ordering::Acquire);
    crate::serial_println!("[Po] Dry-run: stopped mask = {:#010x}", mask);
    mask
}
