//! AHCI (Advanced Host Controller Interface) SATA Driver
//!
//! Discovers AHCI controllers via PCI, initializes ports with proper DMA
//! command structures, and provides block-level read/write for SATA disks
//! using FIS-based DMA transfers.
//!
//! # Architecture
//! Each SATA port gets dedicated physical memory for:
//! - **Command List** (1 KiB, 1024-byte aligned) — up to 32 command headers
//! - **FIS Receive Area** (256 bytes, 256-byte aligned) — incoming FIS from device
//! - **Command Table** (128-byte aligned) — CFIS + ACMD + PRDT entries
//! - **DMA Buffer** (4 KiB = 8 sectors) — staging area for data transfers
//!
//! All memory is allocated from the physical memory manager and is
//! identity-mapped below 4 GiB in this kernel.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

// ── PCI Class Codes ─────────────────────────────────────────────────────────

/// AHCI PCI class: Mass Storage (0x01), SATA (0x06), AHCI (prog_if 0x01)
const AHCI_CLASS: u8 = 0x01;
const AHCI_SUBCLASS: u8 = 0x06;

// ── HBA Global Registers (offset from ABAR) ────────────────────────────────

const HBA_CAP: usize = 0x00;
const HBA_GHC: usize = 0x04;
#[allow(dead_code)]
const HBA_IS: usize = 0x08;
const HBA_PI: usize = 0x0C;
const HBA_VS: usize = 0x10;

// ── Per-Port Register Offsets (from port base = ABAR + 0x100 + port*0x80) ──

const PORT_CLB: usize = 0x00;   // Command List Base Address (low 32)
const PORT_CLBU: usize = 0x04;  // Command List Base Address (high 32)
const PORT_FB: usize = 0x08;    // FIS Base Address (low 32)
const PORT_FBU: usize = 0x0C;   // FIS Base Address (high 32)
const PORT_IS: usize = 0x10;    // Interrupt Status
const PORT_IE: usize = 0x14;    // Interrupt Enable
const PORT_CMD: usize = 0x18;   // Command and Status
const PORT_TFD: usize = 0x20;   // Task File Data
const PORT_SIG: usize = 0x24;   // Signature
const PORT_SSTS: usize = 0x28;  // SATA Status (SCR0: SStatus)
const PORT_SERR: usize = 0x30;  // SATA Error  (SCR1: SError)
const PORT_CI: usize = 0x38;    // Command Issue

// ── Port Command Register Bits (PxCMD) ─────────────────────────────────────

const PORT_CMD_ST: u32 = 1 << 0;       // Start
const PORT_CMD_FRE: u32 = 1 << 4;      // FIS Receive Enable
const PORT_CMD_FR: u32 = 1 << 14;      // FIS Receive Running
const PORT_CMD_CR: u32 = 1 << 15;      // Command List Running

// ── Port Task File Data Bits (PxTFD) ───────────────────────────────────────

const PORT_TFD_ERR: u32 = 1 << 0;      // Error
const PORT_TFD_DRQ: u32 = 1 << 3;      // Data Request
const PORT_TFD_BSY: u32 = 1 << 7;      // Busy

// ── Port Interrupt Status Error Bits (PxIS) ─────────────────────────────────

const PORT_IS_IFS: u32 = 1 << 27;      // Interface Fatal Error
const PORT_IS_HBDS: u32 = 1 << 28;     // Host Bus Data Error
const PORT_IS_HBFS: u32 = 1 << 29;     // Host Bus Fatal Error
const PORT_IS_TFES: u32 = 1 << 30;     // Task File Error Status
/// Mask for any error bit in PxIS.
const PORT_IS_ERR_MASK: u32 = PORT_IS_TFES | PORT_IS_HBFS | PORT_IS_HBDS | PORT_IS_IFS;

// ── FIS Types ───────────────────────────────────────────────────────────────

/// Host to Device Register FIS.
const FIS_TYPE_REG_H2D: u8 = 0x27;

// ── ATA Commands ────────────────────────────────────────────────────────────

/// READ DMA EXT (48-bit LBA).
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// WRITE DMA EXT (48-bit LBA).
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;

// ── Constants ───────────────────────────────────────────────────────────────

/// Maximum sectors per single DMA command (1 page = 4096 bytes = 8 sectors).
const MAX_SECTORS_PER_CMD: u16 = 8;
/// Sector size in bytes.
const SECTOR_SIZE: usize = 512;
/// Physical page size.
const PAGE_SIZE: usize = 4096;
/// Port signature for SATA disk.
const SATA_SIG_ATA: u32 = 0x00000101;

// ── Per-Port DMA State ──────────────────────────────────────────────────────

/// Tracks the physical memory allocations for one AHCI port.
struct AhciPort {
    port_num: u8,
    clb_phys: u64,      // Command List Base physical address
    fb_phys: u64,       // FIS Base physical address
    ctbl_phys: u64,     // Command Table physical address (slot 0)
    dma_buf_phys: u64,  // DMA staging buffer (1 page = 8 sectors)
}

// ── Global State ────────────────────────────────────────────────────────────

/// ABAR (AHCI Base Address Register) from PCI BAR5.
static AHCI_BASE: Mutex<u64> = Mutex::new(0);
/// List of active SATA port numbers.
static AHCI_PORTS: Mutex<Vec<u8>> = Mutex::new(Vec::new());
/// Per-port DMA structures (populated during init).
static AHCI_PORT_STATE: Mutex<Vec<AhciPort>> = Mutex::new(Vec::new());

// ── MMIO Helpers ────────────────────────────────────────────────────────────

/// Read a 32-bit AHCI register via MMIO.
#[inline]
fn read_reg(base: u64, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
}

/// Write a 32-bit AHCI register via MMIO.
#[inline]
fn write_reg(base: u64, offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + offset as u64) as *mut u32, val); }
}

/// Compute a port's register base address.
#[inline]
fn port_base(abar: u64, port: u8) -> u64 {
    abar + 0x100 + (port as u64) * 0x80
}

// ── Port Engine Control ─────────────────────────────────────────────────────

/// Stop the command engine for a port (clear ST, wait CR; clear FRE, wait FR).
fn stop_port(pb: u64) {
    // Clear ST (Start)
    let cmd = read_reg(pb, PORT_CMD);
    if cmd & PORT_CMD_ST != 0 {
        write_reg(pb, PORT_CMD, cmd & !PORT_CMD_ST);
    }

    // Wait for CR (Command List Running) to clear
    for _ in 0..1_000_000u32 {
        if read_reg(pb, PORT_CMD) & PORT_CMD_CR == 0 {
            break;
        }
    }

    // Clear FRE (FIS Receive Enable)
    let cmd = read_reg(pb, PORT_CMD);
    if cmd & PORT_CMD_FRE != 0 {
        write_reg(pb, PORT_CMD, cmd & !PORT_CMD_FRE);
    }

    // Wait for FR (FIS Receive Running) to clear
    for _ in 0..1_000_000u32 {
        if read_reg(pb, PORT_CMD) & PORT_CMD_FR == 0 {
            break;
        }
    }
}

/// Start the command engine for a port (set FRE, then ST).
fn start_port(pb: u64) {
    // Wait until CR clears before starting
    for _ in 0..1_000_000u32 {
        if read_reg(pb, PORT_CMD) & PORT_CMD_CR == 0 {
            break;
        }
    }

    let cmd = read_reg(pb, PORT_CMD);
    // Set FRE first
    write_reg(pb, PORT_CMD, cmd | PORT_CMD_FRE);
    // Then set ST
    let cmd = read_reg(pb, PORT_CMD);
    write_reg(pb, PORT_CMD, cmd | PORT_CMD_ST);
}

// ── Port Initialization ────────────────────────────────────────────────────

/// Initialize a single port's DMA command structures.
///
/// Allocates physical memory for the command list, FIS receive area,
/// command table (slot 0), and a DMA staging buffer. Wires them together
/// and starts the port command engine.
fn init_port(abar: u64, port: u8) -> Option<AhciPort> {
    let pb = port_base(abar, port);

    // 1. Stop the command engine
    stop_port(pb);

    // 2. Allocate physical pages for DMA structures
    let clb_phys = crate::mm::pmm::alloc_page()?;
    let fb_phys = crate::mm::pmm::alloc_page()?;
    let ctbl_phys = crate::mm::pmm::alloc_page()?;
    let dma_buf_phys = crate::mm::pmm::alloc_page()?;

    // 3. Zero all allocated memory (identity-mapped — write directly)
    unsafe {
        core::ptr::write_bytes(clb_phys as *mut u8, 0, PAGE_SIZE);
        core::ptr::write_bytes(fb_phys as *mut u8, 0, PAGE_SIZE);
        core::ptr::write_bytes(ctbl_phys as *mut u8, 0, PAGE_SIZE);
        core::ptr::write_bytes(dma_buf_phys as *mut u8, 0, PAGE_SIZE);
    }

    // 4. Set PxCLB / PxCLBU — Command List Base
    write_reg(pb, PORT_CLB, clb_phys as u32);
    write_reg(pb, PORT_CLBU, (clb_phys >> 32) as u32);

    // 5. Set PxFB / PxFBU — FIS Receive Base
    write_reg(pb, PORT_FB, fb_phys as u32);
    write_reg(pb, PORT_FBU, (fb_phys >> 32) as u32);

    // 6. Set up command header slot 0 to point to the command table
    //    Command header layout (32 bytes per slot):
    //      DW0: flags (CFL, W, PRDTL, etc.)
    //      DW1: PRDBC (bytes transferred — filled by HBA)
    //      DW2: CTBA  (command table base address, low 32)
    //      DW3: CTBAU (command table base address, high 32)
    //      DW4–7: reserved
    unsafe {
        let hdr = clb_phys as *mut u32;
        core::ptr::write_volatile(hdr.add(2), ctbl_phys as u32);
        core::ptr::write_volatile(hdr.add(3), (ctbl_phys >> 32) as u32);
    }

    // 7. Clear pending interrupt status
    write_reg(pb, PORT_IS, 0xFFFF_FFFF);

    // Clear SATA error register
    write_reg(pb, PORT_SERR, 0xFFFF_FFFF);

    // 8. Disable interrupts (we use polling)
    write_reg(pb, PORT_IE, 0);

    // 9. Start the command engine
    start_port(pb);

    crate::serial_println!(
        "[AHCI] Port {} DMA init: CLB={:#x} FB={:#x} CT={:#x} BUF={:#x}",
        port, clb_phys, fb_phys, ctbl_phys, dma_buf_phys
    );

    Some(AhciPort {
        port_num: port,
        clb_phys,
        fb_phys: fb_phys,
        ctbl_phys,
        dma_buf_phys,
    })
}

// ── Command Building ────────────────────────────────────────────────────────

/// Build an H2D Register FIS for a 48-bit LBA DMA command.
///
/// Writes 20 bytes (5 DWORDs) into the CFIS area at the start of the
/// command table.
///
/// # Safety
/// `ctbl_phys` must point to a valid, zeroed, identity-mapped command table.
unsafe fn build_h2d_fis(ctbl_phys: u64, command: u8, lba: u64, count: u16) {
    let cfis = ctbl_phys as *mut u8;

    // Zero the 64-byte CFIS region
    core::ptr::write_bytes(cfis, 0, 64);

    // Byte 0 : FIS type = Register H2D
    core::ptr::write_volatile(cfis.add(0), FIS_TYPE_REG_H2D);
    // Byte 1 : C=1 (command, not control register update)
    core::ptr::write_volatile(cfis.add(1), 0x80);
    // Byte 2 : Command
    core::ptr::write_volatile(cfis.add(2), command);
    // Byte 3 : Features (low) — 0 for DMA read/write
    core::ptr::write_volatile(cfis.add(3), 0);

    // Byte 4 : LBA[7:0]
    core::ptr::write_volatile(cfis.add(4), (lba & 0xFF) as u8);
    // Byte 5 : LBA[15:8]
    core::ptr::write_volatile(cfis.add(5), ((lba >> 8) & 0xFF) as u8);
    // Byte 6 : LBA[23:16]
    core::ptr::write_volatile(cfis.add(6), ((lba >> 16) & 0xFF) as u8);
    // Byte 7 : Device — 0x40 = LBA mode
    core::ptr::write_volatile(cfis.add(7), 0x40);

    // Byte 8 : LBA[31:24]
    core::ptr::write_volatile(cfis.add(8), ((lba >> 24) & 0xFF) as u8);
    // Byte 9 : LBA[39:32]
    core::ptr::write_volatile(cfis.add(9), ((lba >> 32) & 0xFF) as u8);
    // Byte 10: LBA[47:40]
    core::ptr::write_volatile(cfis.add(10), ((lba >> 40) & 0xFF) as u8);
    // Byte 11: Features (high) — 0
    core::ptr::write_volatile(cfis.add(11), 0);

    // Byte 12: Sector count (low)
    core::ptr::write_volatile(cfis.add(12), (count & 0xFF) as u8);
    // Byte 13: Sector count (high)
    core::ptr::write_volatile(cfis.add(13), ((count >> 8) & 0xFF) as u8);
    // Byte 14: ICC — 0
    core::ptr::write_volatile(cfis.add(14), 0);
    // Byte 15: Control — 0
    core::ptr::write_volatile(cfis.add(15), 0);
}

/// Set up a single PRDT entry in the command table.
///
/// PRDT entries start at command table offset 0x80 (after 64-byte CFIS,
/// 16-byte ACMD, 48-byte reserved). Each PRDT entry is 16 bytes:
///   DW0: DBA  (data base address, low 32)
///   DW1: DBAU (data base address, high 32)
///   DW2: reserved
///   DW3: DBC  (byte count minus 1, bits 0–21) | I (interrupt, bit 31)
///
/// # Safety
/// `ctbl_phys` must point to a valid command table. `buf_phys` must be a
/// valid DMA-capable physical address.
unsafe fn setup_prdt(ctbl_phys: u64, buf_phys: u64, byte_count: u32) {
    let prdt = (ctbl_phys + 0x80) as *mut u32;

    // DW0: Data Base Address (low)
    core::ptr::write_volatile(prdt.add(0), buf_phys as u32);
    // DW1: Data Base Address (high)
    core::ptr::write_volatile(prdt.add(1), (buf_phys >> 32) as u32);
    // DW2: Reserved
    core::ptr::write_volatile(prdt.add(2), 0);
    // DW3: Byte count - 1 (bits 0–21). No interrupt-on-completion.
    core::ptr::write_volatile(prdt.add(3), (byte_count - 1) & 0x003F_FFFF);
}

/// Write the command header for slot 0.
///
/// # Safety
/// `clb_phys` must point to a valid, identity-mapped command list.
unsafe fn setup_cmd_header(clb_phys: u64, ctbl_phys: u64, write: bool, prdtl: u16) {
    let hdr = clb_phys as *mut u32;

    // DW0: CFL=5 (5 DWORDs for the H2D FIS), W bit, PRDTL
    let dw0: u32 = 5u32                                // CFL: FIS length in DWORDs
        | if write { 1u32 << 6 } else { 0 }            // W: direction (1=H2D write)
        | ((prdtl as u32) << 16);                       // PRDTL: # of PRDT entries
    core::ptr::write_volatile(hdr.add(0), dw0);

    // DW1: PRDBC = 0 (HBA will update this with bytes transferred)
    core::ptr::write_volatile(hdr.add(1), 0);

    // DW2–3: CTBA / CTBAU (refresh in case they were clobbered)
    core::ptr::write_volatile(hdr.add(2), ctbl_phys as u32);
    core::ptr::write_volatile(hdr.add(3), (ctbl_phys >> 32) as u32);
}

// ── Command Issue & Polling ─────────────────────────────────────────────────

/// Wait until the port's Task File Data register shows not-busy and not-DRQ.
fn wait_port_idle(pb: u64) -> Result<(), &'static str> {
    for _ in 0..1_000_000u32 {
        let tfd = read_reg(pb, PORT_TFD);
        if tfd & (PORT_TFD_BSY | PORT_TFD_DRQ) == 0 {
            return Ok(());
        }
    }
    Err("AHCI: timeout waiting for port idle")
}

/// Issue command slot 0 and poll until completion or error.
fn issue_command(pb: u64) -> Result<(), &'static str> {
    // Clear any pending interrupt status
    write_reg(pb, PORT_IS, 0xFFFF_FFFF);

    // Issue command on slot 0
    write_reg(pb, PORT_CI, 1);

    // Poll for completion (PxCI bit 0 clears when done)
    for _ in 0..10_000_000u32 {
        let ci = read_reg(pb, PORT_CI);
        if ci & 1 == 0 {
            // Check for residual TFD error
            let tfd = read_reg(pb, PORT_TFD);
            if tfd & PORT_TFD_ERR != 0 {
                crate::serial_println!("[AHCI] TFD error after completion: TFD={:#x}", tfd);
                return Err("AHCI: task file error");
            }
            return Ok(());
        }

        // Check for fatal error bits in PxIS
        let is = read_reg(pb, PORT_IS);
        if is & PORT_IS_ERR_MASK != 0 {
            let tfd = read_reg(pb, PORT_TFD);
            let serr = read_reg(pb, PORT_SERR);
            crate::serial_println!(
                "[AHCI] Command error: IS={:#x} TFD={:#x} SERR={:#x}",
                is, tfd, serr
            );
            // Clear error state
            write_reg(pb, PORT_IS, is);
            write_reg(pb, PORT_SERR, serr);
            return Err("AHCI: command failed");
        }
    }

    Err("AHCI: command timeout")
}

// ── Initialization ──────────────────────────────────────────────────────────

/// Initialize the AHCI controller: discover ports, set up DMA structures.
pub fn init() -> bool {
    let pci_dev = match super::pci::find_by_class(AHCI_CLASS, AHCI_SUBCLASS) {
        Some(d) => d,
        None => {
            crate::serial_println!("[AHCI] No AHCI controller found on PCI bus");
            return false;
        }
    };

    crate::serial_println!(
        "[AHCI] Found controller at PCI {:02x}:{:02x}.{} ({:04x}:{:04x})",
        pci_dev.bus, pci_dev.device, pci_dev.function,
        pci_dev.vendor_id, pci_dev.device_id
    );

    // Enable bus mastering and memory space access
    super::pci::enable_bus_master(pci_dev.bus, pci_dev.device, pci_dev.function);

    // BAR5 = ABAR (AHCI Base Memory Register)
    let abar = (pci_dev.bar[5] & 0xFFFF_FFF0) as u64;
    if abar == 0 {
        crate::serial_println!("[AHCI] BAR5 (ABAR) is zero — cannot initialize");
        return false;
    }

    crate::serial_println!("[AHCI] ABAR = {:#010x}", abar);
    *AHCI_BASE.lock() = abar;

    // Read HBA capabilities
    let cap = read_reg(abar, HBA_CAP);
    let num_ports = ((cap & 0x1F) + 1) as u8;
    let num_slots = (((cap >> 8) & 0x1F) + 1) as u8;
    let version = read_reg(abar, HBA_VS);
    crate::serial_println!(
        "[AHCI] Version {}.{}, {} ports, {} command slots",
        version >> 16, version & 0xFFFF, num_ports, num_slots
    );

    // Enable AHCI mode (set AE bit in GHC)
    let ghc = read_reg(abar, HBA_GHC);
    write_reg(abar, HBA_GHC, ghc | (1 << 31));

    // Scan implemented ports
    let pi = read_reg(abar, HBA_PI);
    let mut active_ports = Vec::new();
    let mut port_states = Vec::new();

    for port in 0..32u8 {
        if pi & (1 << port) == 0 {
            continue;
        }

        let pb = port_base(abar, port);
        let ssts = read_reg(pb, PORT_SSTS);
        let det = ssts & 0x0F;
        let ipm = (ssts >> 8) & 0x0F;

        if det != 3 || ipm != 1 {
            continue; // Device not present or not active
        }

        let sig = read_reg(pb, PORT_SIG);
        if sig == SATA_SIG_ATA {
            crate::serial_println!("[AHCI] Port {}: SATA disk detected (sig={:#010x})", port, sig);

            // Initialize port DMA structures
            match init_port(abar, port) {
                Some(ps) => {
                    port_states.push(ps);
                    active_ports.push(port);
                }
                None => {
                    crate::serial_println!("[AHCI] Port {}: failed to allocate DMA memory", port);
                }
            }
        } else {
            crate::serial_println!(
                "[AHCI] Port {}: device sig={:#010x} (not SATA disk)", port, sig
            );
        }
    }

    let _ = num_ports;
    let _ = num_slots;

    if active_ports.is_empty() {
        crate::serial_println!("[AHCI] No SATA disks found");
        return false;
    }

    *AHCI_PORTS.lock() = active_ports.clone();
    *AHCI_PORT_STATE.lock() = port_states;
    crate::serial_println!(
        "[AHCI] {} SATA disk(s) initialized with DMA",
        active_ports.len()
    );
    true
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Check if the AHCI controller has been initialized.
pub fn is_available() -> bool {
    *AHCI_BASE.lock() != 0
}

/// Get the list of active SATA port numbers.
pub fn active_ports() -> Vec<u8> {
    AHCI_PORTS.lock().clone()
}

/// Read sectors from a SATA disk using AHCI DMA.
///
/// Reads `count` sectors starting at `lba` from the specified AHCI port
/// into `buf`. Automatically splits large requests into 8-sector chunks.
///
/// # Arguments
/// * `port` — AHCI port number (from `active_ports()`)
/// * `lba`  — Starting logical block address (48-bit)
/// * `count` — Number of 512-byte sectors to read
/// * `buf`  — Destination buffer (must be >= `count * 512` bytes)
pub fn read_sectors(port: u8, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), &'static str> {
    let required = count as usize * SECTOR_SIZE;
    if buf.len() < required {
        return Err("AHCI read: buffer too small");
    }

    let abar = *AHCI_BASE.lock();
    if abar == 0 {
        return Err("AHCI not initialized");
    }

    let pb = port_base(abar, port);

    // Look up per-port DMA state
    let ports = AHCI_PORT_STATE.lock();
    let ps = ports.iter().find(|p| p.port_num == port)
        .ok_or("AHCI read: port not initialized")?;
    let clb_phys = ps.clb_phys;
    let ctbl_phys = ps.ctbl_phys;
    let dma_buf_phys = ps.dma_buf_phys;
    drop(ports); // Release lock before DMA operations

    let mut remaining = count;
    let mut current_lba = lba;
    let mut buf_offset = 0usize;

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, MAX_SECTORS_PER_CMD);
        let byte_count = chunk as u32 * SECTOR_SIZE as u32;

        // Wait for port to be idle
        wait_port_idle(pb)?;

        unsafe {
            // Build H2D Register FIS for READ DMA EXT
            build_h2d_fis(ctbl_phys, ATA_CMD_READ_DMA_EXT, current_lba, chunk);

            // Set up PRDT: one entry pointing to the DMA buffer
            setup_prdt(ctbl_phys, dma_buf_phys, byte_count);

            // Set up command header (slot 0, read direction)
            setup_cmd_header(clb_phys, ctbl_phys, false, 1);
        }

        // Issue the command and poll for completion
        issue_command(pb)?;

        // Copy data from DMA buffer to caller's buffer
        unsafe {
            core::ptr::copy_nonoverlapping(
                dma_buf_phys as *const u8,
                buf[buf_offset..].as_mut_ptr(),
                byte_count as usize,
            );
        }

        remaining -= chunk;
        current_lba += chunk as u64;
        buf_offset += byte_count as usize;
    }

    Ok(())
}

/// Write sectors to a SATA disk using AHCI DMA.
///
/// Writes `count` sectors starting at `lba` to the specified AHCI port
/// from `data`. Automatically splits large requests into 8-sector chunks.
///
/// # Arguments
/// * `port` — AHCI port number (from `active_ports()`)
/// * `lba`  — Starting logical block address (48-bit)
/// * `count` — Number of 512-byte sectors to write
/// * `data` — Source buffer (must be >= `count * 512` bytes)
pub fn write_sectors(port: u8, lba: u64, count: u16, data: &[u8]) -> Result<(), &'static str> {
    let required = count as usize * SECTOR_SIZE;
    if data.len() < required {
        return Err("AHCI write: data buffer too small");
    }

    let abar = *AHCI_BASE.lock();
    if abar == 0 {
        return Err("AHCI not initialized");
    }

    let pb = port_base(abar, port);

    // Look up per-port DMA state
    let ports = AHCI_PORT_STATE.lock();
    let ps = ports.iter().find(|p| p.port_num == port)
        .ok_or("AHCI write: port not initialized")?;
    let clb_phys = ps.clb_phys;
    let ctbl_phys = ps.ctbl_phys;
    let dma_buf_phys = ps.dma_buf_phys;
    drop(ports);

    let mut remaining = count;
    let mut current_lba = lba;
    let mut data_offset = 0usize;

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, MAX_SECTORS_PER_CMD);
        let byte_count = chunk as u32 * SECTOR_SIZE as u32;

        // Wait for port to be idle
        wait_port_idle(pb)?;

        // Copy source data into the DMA staging buffer
        unsafe {
            core::ptr::copy_nonoverlapping(
                data[data_offset..].as_ptr(),
                dma_buf_phys as *mut u8,
                byte_count as usize,
            );
        }

        unsafe {
            // Build H2D Register FIS for WRITE DMA EXT
            build_h2d_fis(ctbl_phys, ATA_CMD_WRITE_DMA_EXT, current_lba, chunk);

            // Set up PRDT: one entry pointing to the DMA buffer
            setup_prdt(ctbl_phys, dma_buf_phys, byte_count);

            // Set up command header (slot 0, write direction)
            setup_cmd_header(clb_phys, ctbl_phys, true, 1);
        }

        // Issue the command and poll for completion
        issue_command(pb)?;

        remaining -= chunk;
        current_lba += chunk as u64;
        data_offset += byte_count as usize;
    }

    Ok(())
}
