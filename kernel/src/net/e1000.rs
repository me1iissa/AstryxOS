//! Intel e1000 (82540EM) Ethernet Driver
//!
//! A minimal but functional driver for the QEMU-emulated Intel e1000 NIC.
//! Uses MMIO register access, descriptor rings for TX/RX, and polling.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// ── PCI constants ───────────────────────────────────────────────────────────

const E1000_VENDOR: u16 = 0x8086;
const E1000_DEVICE_82540EM: u16 = 0x100E;

// ── E1000 Register offsets (from BAR0 MMIO base) ───────────────────────────

const REG_CTRL: u32     = 0x0000; // Device Control
const REG_STATUS: u32   = 0x0008; // Device Status
const REG_EERD: u32     = 0x0014; // EEPROM Read
const REG_ICR: u32      = 0x00C0; // Interrupt Cause Read
const REG_IMC: u32      = 0x00D8; // Interrupt Mask Clear
const REG_RCTL: u32     = 0x0100; // Receive Control
const REG_TCTL: u32     = 0x0400; // Transmit Control
const REG_TIPG: u32     = 0x0410; // TX Inter-Packet Gap

const REG_RDBAL: u32    = 0x2800; // RX Descriptor Base Low
const REG_RDBAH: u32    = 0x2804; // RX Descriptor Base High
const REG_RDLEN: u32    = 0x2808; // RX Descriptor Length
const REG_RDH: u32      = 0x2810; // RX Descriptor Head
const REG_RDT: u32      = 0x2818; // RX Descriptor Tail

const REG_TDBAL: u32    = 0x3800; // TX Descriptor Base Low
const REG_TDBAH: u32    = 0x3804; // TX Descriptor Base High
const REG_TDLEN: u32    = 0x3808; // TX Descriptor Length
const REG_TDH: u32      = 0x3810; // TX Descriptor Head
const REG_TDT: u32      = 0x3818; // TX Descriptor Tail

const REG_RAL0: u32     = 0x5400; // Receive Address Low (MAC bytes 0-3)
const REG_RAH0: u32     = 0x5404; // Receive Address High (MAC bytes 4-5) + AV bit
const REG_MTA: u32      = 0x5200; // Multicast Table Array (128 entries)

// ── Control bits ────────────────────────────────────────────────────────────

const CTRL_ASDE: u32    = 1 << 5;  // Auto-Speed Detection Enable
const CTRL_SLU: u32     = 1 << 6;  // Set Link Up
const CTRL_RST: u32     = 1 << 26; // Device Reset

const RCTL_EN: u32      = 1 << 1;  // Receiver Enable
const RCTL_SBP: u32     = 1 << 2;  // Store Bad Packets
const RCTL_UPE: u32     = 1 << 3;  // Unicast Promiscuous Enable
const RCTL_MPE: u32     = 1 << 4;  // Multicast Promiscuous Enable
const RCTL_BAM: u32     = 1 << 15; // Broadcast Accept Mode
const RCTL_BSIZE_2048: u32 = 0 << 16; // Buffer Size 2048 (default)
const RCTL_SECRC: u32   = 1 << 26; // Strip Ethernet CRC

const TCTL_EN: u32      = 1 << 1;  // Transmit Enable
const TCTL_PSP: u32     = 1 << 3;  // Pad Short Packets
const TCTL_CT_SHIFT: u32 = 4;      // Collision Threshold shift
const TCTL_COLD_SHIFT: u32 = 12;   // Collision Distance shift

// ── TX Descriptor command/status bits ───────────────────────────────────────

const TDESC_CMD_EOP: u8  = 1 << 0; // End of Packet
const TDESC_CMD_IFCS: u8 = 1 << 1; // Insert FCS/CRC
const TDESC_CMD_RS: u8   = 1 << 3; // Report Status
const TDESC_STA_DD: u8   = 1 << 0; // Descriptor Done

// ── RX Descriptor status bits ───────────────────────────────────────────────

const RDESC_STA_DD: u8   = 1 << 0; // Descriptor Done
const RDESC_STA_EOP: u8  = 1 << 1; // End of Packet

// ── Descriptor ring sizes ───────────────────────────────────────────────────

const NUM_RX_DESC: usize = 32;
const NUM_TX_DESC: usize = 32;
const RX_BUF_SIZE: usize = 2048;

// ── Descriptor structures ───────────────────────────────────────────────────

/// Receive descriptor (hardware format, 16 bytes)
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct RxDesc {
    addr: u64,      // Buffer physical address
    length: u16,    // Length of received data
    checksum: u16,  // Packet checksum
    status: u8,     // Status bits
    errors: u8,     // Errors
    special: u16,   // VLAN tag
}

/// Transmit descriptor (hardware format, 16 bytes)
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct TxDesc {
    addr: u64,      // Buffer physical address
    length: u16,    // Data length
    cso: u8,        // Checksum offset
    cmd: u8,        // Command bits
    status: u8,     // Status bits
    css: u8,        // Checksum start
    special: u16,   // VLAN tag
}

// ── Static driver state ─────────────────────────────────────────────────────

/// MMIO base address for the e1000 registers.
static MMIO_BASE: Mutex<u64> = Mutex::new(0);

/// Whether the e1000 NIC has been initialized.
static AVAILABLE: AtomicBool = AtomicBool::new(false);

/// RX descriptor ring (page-aligned via alloc)
static RX_DESCS: Mutex<u64> = Mutex::new(0); // phys addr of desc ring
/// TX descriptor ring
static TX_DESCS: Mutex<u64> = Mutex::new(0); // phys addr of desc ring

/// RX buffers base address
static RX_BUFS: Mutex<u64> = Mutex::new(0);
/// TX buffer base address (single packet buffer)
static TX_BUFS: Mutex<u64> = Mutex::new(0);

/// Current TX tail index
static TX_TAIL: Mutex<u16> = Mutex::new(0);
/// Current RX tail (last index we gave to hardware)
static RX_CUR: Mutex<u16> = Mutex::new(0);

// ── MMIO helpers ────────────────────────────────────────────────────────────

/// Read a 32-bit register from MMIO space.
fn mmio_read(reg: u32) -> u32 {
    let base = *MMIO_BASE.lock();
    unsafe {
        let ptr = (base + reg as u64) as *const u32;
        core::ptr::read_volatile(ptr)
    }
}

/// Write a 32-bit register in MMIO space.
fn mmio_write(reg: u32, val: u32) {
    let base = *MMIO_BASE.lock();
    unsafe {
        let ptr = (base + reg as u64) as *mut u32;
        core::ptr::write_volatile(ptr, val);
    }
}

// ── PCI helpers ─────────────────────────────────────────────────────────────

fn pci_read(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        crate::hal::outl(0xCF8, addr);
        crate::hal::inl(0xCFC)
    }
}

fn pci_write(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr: u32 = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        crate::hal::outl(0xCF8, addr);
        crate::hal::outl(0xCFC, val);
    }
}

// ── Initialization ──────────────────────────────────────────────────────────

/// Scan PCI for e1000 and initialize it. Returns true on success.
pub fn init() -> bool {
    // Scan PCI for Intel e1000
    for bus in 0u8..=255 {
        for dev in 0u8..32 {
            let id = pci_read(bus, dev, 0, 0x00);
            if id == 0xFFFF_FFFF { continue; }

            let vendor = (id & 0xFFFF) as u16;
            let device = (id >> 16) as u16;

            if vendor == E1000_VENDOR && device == E1000_DEVICE_82540EM {
                crate::serial_println!("[E1000] Found device at PCI {}:{}.0", bus, dev);
                return init_device(bus, dev);
            }
        }
    }
    false
}

fn init_device(bus: u8, dev: u8) -> bool {
    // 1) Read BAR0 (MMIO base address)
    let bar0 = pci_read(bus, dev, 0, 0x10);
    let mmio_base = (bar0 & 0xFFFF_FFF0) as u64;

    // Read BAR0 high 32 bits for 64-bit BAR (Type 2 = prefetchable 64-bit)
    let bar_type = (bar0 >> 1) & 0x03;
    let mmio_base = if bar_type == 2 {
        let bar1 = pci_read(bus, dev, 0, 0x14);
        ((bar1 as u64) << 32) | mmio_base
    } else {
        mmio_base
    };

    *MMIO_BASE.lock() = mmio_base;
    crate::serial_println!("[E1000] MMIO base: {:#X}", mmio_base);

    // 2) Enable PCI bus mastering + memory space access
    let cmd = pci_read(bus, dev, 0, 0x04);
    pci_write(bus, dev, 0, 0x04, cmd | 0x06); // Bit 1 = Memory Space, Bit 2 = Bus Master
    crate::serial_println!("[E1000] PCI bus mastering enabled");

    // 3) Reset the device
    mmio_write(REG_CTRL, mmio_read(REG_CTRL) | CTRL_RST);
    // Wait for reset to complete (bit self-clears).
    // Use pause-spin — QEMU clears RST synchronously on re-read, and HLT is
    // unsafe here because IF may be 0 during early kernel init.
    for _ in 0..100_000 {
        unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
        if mmio_read(REG_CTRL) & CTRL_RST == 0 { break; }
    }

    // 3b) Re-enable PCI bus mastering + memory access (reset clears command register)
    let cmd_after = pci_read(bus, dev, 0, 0x04);
    pci_write(bus, dev, 0, 0x04, cmd_after | 0x06);
    crate::serial_println!("[E1000] PCI command after reset: {:#X} -> {:#X}",
        cmd_after, pci_read(bus, dev, 0, 0x04));

    // 4) Interrupt mask: handled after RX/TX ring setup (step 9).
    //    Read ICR now to drain any pending causes from reset.
    mmio_read(REG_ICR);

    // 5) Set link up + auto-speed detection, clear link-reset
    let ctrl = mmio_read(REG_CTRL);
    mmio_write(REG_CTRL, (ctrl & !(1u32 << 3)) | CTRL_SLU | CTRL_ASDE);

    // Wait up to ~200ms for link to come up (spin-wait).
    // QEMU's e1000 sets link-up immediately after SLU in software emulation;
    // with KVM it may take a handful of microseconds. Use a bounded spin so
    // we never block the init sequence if interrupts are still disabled.
    for _ in 0..1_000_000u32 {
        let s = mmio_read(REG_STATUS);
        if s & 0x02 != 0 { break; } // Link is UP
        unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
    }

    let status = mmio_read(REG_STATUS);
    crate::serial_println!("[E1000] Status: {:#X} (link {})",
        status, if status & 0x02 != 0 { "UP" } else { "DOWN" });

    // 6) Read MAC address from EEPROM/RAL
    let mac = read_mac();
    super::set_our_mac(mac);
    crate::serial_println!("[E1000] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // 6b) Explicitly program RAL0/RAH0 with the Address Valid (AV) bit.
    // After device reset, the AV bit may be cleared — without it the e1000
    // hardware filter rejects ALL unicast frames, so RX would be dead.
    {
        let ral_val = (mac[0] as u32)
            | ((mac[1] as u32) << 8)
            | ((mac[2] as u32) << 16)
            | ((mac[3] as u32) << 24);
        let rah_val = (mac[4] as u32)
            | ((mac[5] as u32) << 8)
            | (1u32 << 31); // AV (Address Valid) bit
        mmio_write(REG_RAL0, ral_val);
        mmio_write(REG_RAH0, rah_val);
    }

    // 7) Allocate and set up RX descriptor ring + buffers
    if !init_rx() {
        crate::serial_println!("[E1000] Failed to allocate RX resources");
        return false;
    }

    // 8) Allocate and set up TX descriptor ring + buffer
    if !init_tx() {
        crate::serial_println!("[E1000] Failed to allocate TX resources");
        return false;
    }

    // 9) Interrupt configuration.
    // We use polling, so disable all NIC interrupts and drain pending causes.
    mmio_write(REG_IMC, 0xFFFF_FFFF);
    mmio_read(REG_ICR);

    AVAILABLE.store(true, Ordering::Release);
    crate::serial_println!("[E1000] Driver initialized, ready for packets");
    true
}

/// Acknowledge a spurious e1000 interrupt.  Reads ICR (read-to-clear)
/// so the interrupt line is de-asserted.  We run with IMS=0 (polling),
/// but a stale PCI INTx could still fire once after reset.
pub fn acknowledge_irq() -> u32 {
    if !AVAILABLE.load(Ordering::Acquire) { return 0; }
    mmio_read(REG_ICR)
}

/// Read MAC address. Try EEPROM first, fall back to RAL/RAH.
fn read_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];

    // Try reading from RAL/RAH registers (QEMU fills these)
    let ral = mmio_read(REG_RAL0);
    let rah = mmio_read(REG_RAH0);

    mac[0] = (ral & 0xFF) as u8;
    mac[1] = ((ral >> 8) & 0xFF) as u8;
    mac[2] = ((ral >> 16) & 0xFF) as u8;
    mac[3] = ((ral >> 24) & 0xFF) as u8;
    mac[4] = (rah & 0xFF) as u8;
    mac[5] = ((rah >> 8) & 0xFF) as u8;

    // If RAL/RAH are zero, try EEPROM
    if mac == [0; 6] {
        for i in 0u32..3 {
            let val = eeprom_read(i as u8);
            mac[(i * 2) as usize] = (val & 0xFF) as u8;
            mac[(i * 2 + 1) as usize] = ((val >> 8) & 0xFF) as u8;
        }
    }

    mac
}

/// Read a word from the EEPROM.
fn eeprom_read(addr: u8) -> u16 {
    // Start EEPROM read
    mmio_write(REG_EERD, 1 | ((addr as u32) << 8));

    // Wait for completion (bit 4 = done)
    for _ in 0..10_000 {
        let val = mmio_read(REG_EERD);
        if val & (1 << 4) != 0 {
            return (val >> 16) as u16;
        }
        unsafe { core::arch::asm!("pause"); }
    }
    0
}

// ── RX setup ────────────────────────────────────────────────────────────────

fn init_rx() -> bool {
    // Allocate descriptor ring: NUM_RX_DESC * 16 bytes each, needs 128-byte alignment
    // We'll allocate a full page (4096) which is more than enough for 32 * 16 = 512 bytes
    let desc_phys = match crate::mm::pmm::alloc_page() {
        Some(p) => p,
        None => return false,
    };

    // Allocate buffer space: NUM_RX_DESC * RX_BUF_SIZE = 32 * 2048 = 64 KB = 16 pages
    let bufs_phys = match crate::mm::pmm::alloc_pages(NUM_RX_DESC * RX_BUF_SIZE / 4096) {
        Some(p) => p,
        None => return false,
    };

    // Zero out the descriptor ring
    unsafe {
        core::ptr::write_bytes(desc_phys as *mut u8, 0, 4096);
    }

    // Initialize each RX descriptor with a buffer address.
    // Use volatile writes — the hardware reads these via DMA and the compiler
    // must not reorder or elide them.
    for i in 0..NUM_RX_DESC {
        let desc_ptr = (desc_phys + (i as u64) * 16) as *mut RxDesc;
        let buf_addr = bufs_phys + (i as u64) * RX_BUF_SIZE as u64;
        unsafe {
            core::ptr::write_volatile(&mut (*desc_ptr).addr, buf_addr);
            core::ptr::write_volatile(&mut (*desc_ptr).status, 0);
        }
    }

    *RX_DESCS.lock() = desc_phys;
    *RX_BUFS.lock() = bufs_phys;
    *RX_CUR.lock() = 0;

    // Full fence: ensure all descriptor writes are globally visible before
    // we program the hardware registers that tell the NIC to start DMA.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    // Clear the Multicast Table Array (zero = accept none via hash)
    for i in 0..128u32 {
        mmio_write(REG_MTA + i * 4, 0);
    }

    // NOTE: We do NOT write RCTL=0 here.  QEMU's reset already sets RCTL=0
    // without going through `set_rx_control`, so no flush_queue_timer is armed.
    // An explicit RCTL=0 write would arm the timer for +1 000 ms during which
    // QEMU refuses all incoming packets — a problem for early networking.

    // Program the descriptor ring in hardware
    mmio_write(REG_RDBAL, (desc_phys & 0xFFFF_FFFF) as u32);
    mmio_write(REG_RDBAH, (desc_phys >> 32) as u32);
    mmio_write(REG_RDLEN, (NUM_RX_DESC * 16) as u32);
    mmio_write(REG_RDH, 0);
    mmio_write(REG_RDT, (NUM_RX_DESC - 1) as u32);

    // Enable receiver
    mmio_write(REG_RCTL,
        RCTL_EN
        | RCTL_UPE        // unicast promiscuous (accept all unicast)
        | RCTL_MPE        // multicast promiscuous
        | RCTL_BAM        // accept broadcast
        | RCTL_BSIZE_2048
        | RCTL_SECRC      // strip CRC
    );

    crate::serial_println!("[E1000] RX ring at {:#X}, {} descriptors, buffers at {:#X}",
        desc_phys, NUM_RX_DESC, bufs_phys);
    true
}

// ── TX setup ────────────────────────────────────────────────────────────────

fn init_tx() -> bool {
    // Allocate descriptor ring page
    let desc_phys = match crate::mm::pmm::alloc_page() {
        Some(p) => p,
        None => return false,
    };

    // Allocate TX buffer space: NUM_TX_DESC * 2048 = 64 KB = 16 pages
    let bufs_phys = match crate::mm::pmm::alloc_pages(NUM_TX_DESC * 2048 / 4096) {
        Some(p) => p,
        None => return false,
    };

    // Zero out the descriptor ring
    unsafe {
        core::ptr::write_bytes(desc_phys as *mut u8, 0, 4096);
    }

    // Init TX descriptors — mark all as done so first use works.
    // Volatile writes so the compiler cannot elide or reorder these DMA-visible stores.
    for i in 0..NUM_TX_DESC {
        let desc_ptr = (desc_phys + (i as u64) * 16) as *mut TxDesc;
        let buf_addr = bufs_phys + (i as u64) * 2048;
        unsafe {
            core::ptr::write_volatile(&mut (*desc_ptr).addr, buf_addr);
            core::ptr::write_volatile(&mut (*desc_ptr).status, TDESC_STA_DD);
            core::ptr::write_volatile(&mut (*desc_ptr).cmd, 0);
        }
    }

    *TX_DESCS.lock() = desc_phys;
    *TX_BUFS.lock() = bufs_phys;
    *TX_TAIL.lock() = 0;

    // Program the descriptor ring in hardware
    mmio_write(REG_TDBAL, (desc_phys & 0xFFFF_FFFF) as u32);
    mmio_write(REG_TDBAH, (desc_phys >> 32) as u32);
    mmio_write(REG_TDLEN, (NUM_TX_DESC * 16) as u32);
    mmio_write(REG_TDH, 0);
    mmio_write(REG_TDT, 0);

    // Set TX inter-packet gap for IEEE 802.3
    mmio_write(REG_TIPG, 10 | (10 << 10) | (10 << 20));

    // Enable transmitter
    mmio_write(REG_TCTL,
        TCTL_EN
        | TCTL_PSP
        | (15 << TCTL_CT_SHIFT)
        | (64 << TCTL_COLD_SHIFT)
    );

    crate::serial_println!("[E1000] TX ring at {:#X}, {} descriptors, buffers at {:#X}",
        desc_phys, NUM_TX_DESC, bufs_phys);
    true
}

// ── Packet TX ───────────────────────────────────────────────────────────────

/// Send a raw Ethernet frame.
pub fn send_packet(data: &[u8]) {
    if !AVAILABLE.load(Ordering::Acquire) { return; }
    if data.is_empty() || data.len() > 1518 { return; }

    let mut tail = TX_TAIL.lock();
    let desc_base = *TX_DESCS.lock();
    let idx = *tail as usize;

    let desc_ptr = (desc_base + (idx as u64) * 16) as *mut TxDesc;

    // Wait for this descriptor to be free (DD bit set by hardware)
    unsafe {
        for _ in 0..100_000 {
            if core::ptr::read_volatile(&(*desc_ptr).status) & TDESC_STA_DD != 0 {
                break;
            }
            core::arch::asm!("pause");
        }
    }

    // Copy data to the descriptor's buffer
    let buf_addr = *TX_BUFS.lock() + (idx as u64) * 2048;
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf_addr as *mut u8, data.len());
    }

    // Fill in the descriptor (volatile — DMA-visible to hardware)
    unsafe {
        core::ptr::write_volatile(&mut (*desc_ptr).addr, buf_addr);
        core::ptr::write_volatile(&mut (*desc_ptr).length, data.len() as u16);
        core::ptr::write_volatile(&mut (*desc_ptr).cmd,
            TDESC_CMD_EOP | TDESC_CMD_IFCS | TDESC_CMD_RS);
        core::ptr::write_volatile(&mut (*desc_ptr).status, 0);
    }

    // Advance tail
    let new_tail = ((idx + 1) % NUM_TX_DESC) as u16;
    *tail = new_tail;

    // Notify hardware — TDT (0x3818) is NOT coalesced, so this causes
    // an immediate VM exit.  Inside the handler, `start_xmit` calls
    // SLIRP's `slirp_input`; SLIRP processes the packet **synchronously**
    // and any reply (e.g. ARP) is queued by the `mem_reentrancy_guard`.
    mmio_write(REG_TDT, new_tail as u32);

    // Nudge RDT so that QEMU's `set_rdt` handler calls
    // `qemu_flush_queued_packets()`, delivering any reply that was just
    // queued by the reentrancy guard above.  RDT (0x2818) is in a
    // coalesced MMIO region — the write is buffered in KVM's ring and
    // only processed at the next VM exit (typically the HLT that
    // immediately follows in the caller's poll loop).  When `set_rdt`
    // runs and `flush_queue_timer` is not pending, it flushes the net
    // queue and DMA's the reply into the RX descriptor ring.
    {
        let cur = *RX_CUR.lock();
        let rdt_val = if cur == 0 { (NUM_RX_DESC - 1) as u32 } else { (cur as u32) - 1 };
        mmio_write(REG_RDT, rdt_val);
    }

    // Force the coalesced RDT write to be processed NOW by reading a
    // non-coalesced register.  The MMIO read causes an immediate VM exit;
    // KVM's kvm_arch_post_run() flushes the coalesced ring before the
    // read handler runs, which processes the RDT write → set_rdt() →
    // qemu_flush_queued_packets().
    let _ = mmio_read(REG_STATUS);
}

// ── Packet RX (polling) ─────────────────────────────────────────────────────

/// Poll for received packets. Calls the network stack's handle_rx_packet for each.
pub fn poll_rx() {
    if !AVAILABLE.load(Ordering::Acquire) { return; }

    let desc_base = *RX_DESCS.lock();
    let bufs_base = *RX_BUFS.lock();
    let mut cur = RX_CUR.lock();

    loop {
        let idx = *cur as usize;
        let desc_ptr = (desc_base + (idx as u64) * 16) as *const RxDesc;

        // Volatile reads — hardware writes these fields via DMA.
        let status = unsafe { core::ptr::read_volatile(&(*desc_ptr).status) };
        let length = unsafe { core::ptr::read_volatile(&(*desc_ptr).length) };

        // Check if this descriptor has been filled by hardware
        if status & RDESC_STA_DD == 0 {
            break; // No more packets
        }

        if status & RDESC_STA_EOP != 0 && length > 0 {
            let buf_addr = bufs_base + (idx as u64) * RX_BUF_SIZE as u64;
            let len = length as usize;

            // Safety: reading from the RX buffer that hardware wrote into
            let packet = unsafe {
                core::slice::from_raw_parts(buf_addr as *const u8, len)
            };

            // Hand to the network stack
            super::handle_rx_packet(packet);
        }

        // Volatile write: clear status so hardware can reuse this descriptor
        let desc_ptr_mut = desc_ptr as *mut RxDesc;
        unsafe {
            core::ptr::write_volatile(&mut (*desc_ptr_mut).status, 0);
        }

        // Advance and update tail
        let next = ((idx + 1) % NUM_RX_DESC) as u16;
        *cur = next;

        // Tell hardware it can use this descriptor again
        mmio_write(REG_RDT, idx as u32);
    }
}

/// Quiesce the e1000 NIC on shutdown.
///
/// Disables TX and RX engines via TCTL/RCTL, masks all interrupts (IMC),
/// and clears the AVAILABLE flag.  Does NOT perform a full device reset
/// (CTRL_RST) because that would nuke EEPROM state; a clean disable suffices
/// for a graceful power-off and is faster.
pub fn stop() {
    crate::serial_println!("[E1000] stop: disabling TX/RX");
    if !AVAILABLE.load(Ordering::Acquire) {
        crate::serial_println!("[E1000] stop: not initialized, skipping");
        return;
    }
    // Disable transmitter and receiver.
    mmio_write(REG_TCTL, 0);
    mmio_write(REG_RCTL, 0);
    // Mask all interrupts so no spurious IRQs fire during teardown.
    mmio_write(REG_IMC, 0xFFFF_FFFF);
    // Clear any pending interrupt causes.
    let _ = mmio_read(REG_ICR);
    AVAILABLE.store(false, Ordering::Release);
    crate::serial_println!("[E1000] stop: done");
}

/// Check if the e1000 NIC is available.
pub fn is_available() -> bool {
    AVAILABLE.load(Ordering::Acquire)
}

/// Read the device STATUS register (for diagnostics).
pub fn read_status() -> u32 {
    if !AVAILABLE.load(Ordering::Acquire) { return 0; }
    mmio_read(REG_STATUS)
}

/// Read TX/RX ring head/tail pointers (for diagnostics).
/// Returns (TDH, TDT, RDH, RDT).
pub fn read_ring_ptrs() -> (u32, u32, u32, u32) {
    if !AVAILABLE.load(Ordering::Acquire) { return (0, 0, 0, 0); }
    (
        mmio_read(REG_TDH),
        mmio_read(REG_TDT),
        mmio_read(REG_RDH),
        mmio_read(REG_RDT),
    )
}

/// Read TCTL and RCTL control registers (for diagnostics).
/// Returns (TCTL, RCTL).
pub fn read_ctrl_regs() -> (u32, u32) {
    if !AVAILABLE.load(Ordering::Acquire) { return (0, 0); }
    (mmio_read(REG_TCTL), mmio_read(REG_RCTL))
}

/// Read RAH0 for diagnostics (check AV bit).
pub fn read_rah0() -> u32 {
    if !AVAILABLE.load(Ordering::Acquire) { return 0; }
    mmio_read(REG_RAH0)
}


