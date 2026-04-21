//! Virtio-net PCI Ethernet Driver (Legacy Interface)
//!
//! Implements a virtio network device using the legacy (transitional) PCI
//! interface.  This serves as a fallback when the e1000 driver does not
//! find its device — enabling AstryxOS to run on hypervisors and container
//! runtimes that expose virtio-net rather than an emulated Intel NIC.
//!
//! # Protocol
//!
//! Uses two virtqueues:
//!   - Queue 0 (RX): pre-filled with receive buffers; device writes received
//!     frames (preceded by a `virtio_net_hdr`) into them.
//!   - Queue 1 (TX): caller enqueues a 2-descriptor chain: net_hdr + frame
//!     data; device DMA-reads them to transmit, then marks completion in the
//!     used ring.
//!
//! The control queue (q2) is skipped; all options that require it (MQ,
//! MAC filtering tables) are not negotiated.
//!
//! # Feature negotiation
//!
//! We negotiate only VIRTIO_NET_F_MAC (bit 5) and VIRTIO_NET_F_STATUS
//! (bit 16).  Checksum offload (F_CSUM=0), GSO (F_GSO=1), and mergeable
//! RX buffers (F_MRG_RXBUF=15) are intentionally NOT requested — this
//! keeps the descriptor format trivial and avoids parsing merged headers.
//!
//! # TX path
//!
//! 1. Copy frame into a driver-owned buffer (avoids caller lifetime issues).
//! 2. Prepend a zeroed `virtio_net_hdr` (no offloads, `gso_type = NONE`).
//! 3. Push a 2-descriptor chain (hdr | frame) onto queue 1's avail ring.
//! 4. Write queue-1 notify register.
//! 5. Spin-poll the used ring until completion is reported.
//! 6. Return (buffers remain owned by driver, reused on next TX).
//!
//! # RX path
//!
//! On init, queue 0 is pre-filled with `NUM_RX_DESC` receive buffers, each
//! large enough for a full Ethernet frame plus the `virtio_net_hdr` prefix.
//! `poll_rx()` drains the used ring, passes each completed frame (skipping
//! the 12-byte header) up to `super::handle_rx_packet()`, then re-posts the
//! buffer back into the available ring.
//!
//! # References
//! - Virtio 1.0 spec §5.1 (Network Device)
//! - Legacy interface: <https://docs.oasis-open.org/virtio/virtio/v1.0/cs04/>

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use crate::hal;
use crate::mm::pmm;

// ── Virtio PCI IDs ──────────────────────────────────────────────────────────

/// Red Hat / Virtio vendor ID.
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Legacy virtio-net device ID (transitional).
const VIRTIO_NET_DEVICE_LEGACY: u16 = 0x1000;
/// Virtio subsystem ID for network devices.
const VIRTIO_SUBSYS_NET: u16 = 1;

// ── Legacy Virtio Register Offsets (from BAR0 I/O base) ─────────────────────

const VIRTIO_REG_DEVICE_FEATURES: u16 = 0x00; // u32 RO
const VIRTIO_REG_GUEST_FEATURES:  u16 = 0x04; // u32 RW
const VIRTIO_REG_QUEUE_ADDRESS:   u16 = 0x08; // u32 RW  (PFN = phys >> 12)
const VIRTIO_REG_QUEUE_SIZE:      u16 = 0x0C; // u16 RO
const VIRTIO_REG_QUEUE_SELECT:    u16 = 0x0E; // u16 RW
const VIRTIO_REG_QUEUE_NOTIFY:    u16 = 0x10; // u16 WO
const VIRTIO_REG_DEVICE_STATUS:   u16 = 0x12; // u8  RW
const VIRTIO_REG_ISR_STATUS:      u16 = 0x13; // u8  RO  (clear-on-read)
// Device-specific config starts at +0x14 for legacy.
const VIRTIO_NET_REG_MAC:         u16 = 0x14; // 6 bytes
const VIRTIO_NET_REG_STATUS:      u16 = 0x1A; // u16 (VIRTIO_NET_F_STATUS)

// ── Virtio Device Status Bits ───────────────────────────────────────────────

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER:      u8 = 2;
const VIRTIO_STATUS_DRIVER_OK:   u8 = 4;

// ── Virtio Net Feature Bits ─────────────────────────────────────────────────

/// Device provides a MAC address in config space.
const VIRTIO_NET_F_MAC:    u32 = 1 << 5;
/// Device provides a link status register in config space.
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;

// ── Virtqueue Descriptor Flags ──────────────────────────────────────────────

const VRING_DESC_F_NEXT:  u16 = 1; // Descriptor is chained
const VRING_DESC_F_WRITE: u16 = 2; // Device may write to this buffer

// ── Virtqueue Indices ───────────────────────────────────────────────────────

const QUEUE_RX: u16 = 0;
const QUEUE_TX: u16 = 1;

// ── Buffer Geometry ─────────────────────────────────────────────────────────

/// Number of RX descriptors (must be power of two; device caps at queue_size).
const NUM_RX_DESC: usize = 32;
/// Number of TX descriptor *slots* — each TX uses 2 descriptors (hdr + data),
/// so this is the number of concurrent TX operations, each needing 2 desc slots.
const NUM_TX_SLOTS: usize = 16;

/// Size of each RX receive buffer: virtio_net_hdr (12 bytes) + max frame
/// (1514 bytes) + small padding → 2048 is a clean power-of-two page fraction.
const RX_BUF_SIZE: usize = 2048;

/// Size of the virtio_net_hdr prepended to every TX/RX frame.
const VIRTIO_NET_HDR_SIZE: usize = 12;

// ── Higher-Half Mapping ─────────────────────────────────────────────────────

const PHYS_OFFSET: u64 = astryx_shared::KERNEL_VIRT_BASE;

#[inline]
fn phys_to_virt<T>(phys: u64) -> *mut T {
    (PHYS_OFFSET + phys) as *mut T
}

// ── Virtqueue Layout (same formulae as virtio_blk) ─────────────────────────

#[inline]
fn avail_ring_offset(qs: u16) -> usize {
    (qs as usize) * 16
}

#[inline]
fn used_ring_offset(qs: u16) -> usize {
    let avail_end = avail_ring_offset(qs) + 4 + (qs as usize) * 2;
    (avail_end + 4095) & !4095
}

#[inline]
fn virtqueue_total_bytes(qs: u16) -> usize {
    let used_end = used_ring_offset(qs) + 4 + (qs as usize) * 8;
    (used_end + 4095) & !4095
}

// ── Driver State ────────────────────────────────────────────────────────────

struct VirtioNetDevice {
    /// BAR0 I/O port base.
    io_base: u16,
    /// RX virtqueue physical base.
    rxq_phys: u64,
    rxq_size: u16,
    /// TX virtqueue physical base.
    txq_phys: u64,
    txq_size: u16,
    /// Physical base of the RX buffer slab (NUM_RX_DESC * RX_BUF_SIZE bytes).
    rx_bufs_phys: u64,
    /// Physical base of the TX buffer slab for net headers + frame copies.
    /// Layout: NUM_TX_SLOTS slots, each RX_BUF_SIZE bytes.
    tx_bufs_phys: u64,
    /// Last seen used ring index for RX queue.
    rxq_last_used: u16,
    /// Last seen used ring index for TX queue.
    txq_last_used: u16,
    /// Next descriptor index to use for available ring in RX queue.
    rxq_avail_idx: u16,
    /// Next TX slot (wraps at NUM_TX_SLOTS).
    tx_slot: u16,
}

static VIRTIO_NET: Mutex<Option<VirtioNetDevice>> = Mutex::new(None);
static VIRTIO_NET_AVAILABLE: AtomicBool = AtomicBool::new(false);

// ── Initialization ──────────────────────────────────────────────────────────

/// Initialize the virtio-net driver. Scans PCI, negotiates features, allocates
/// virtqueues, and pre-fills the RX queue.  Returns true on success.
pub fn init() -> bool {
    let pci_dev = match find_virtio_net_pci() {
        Some(d) => d,
        None => {
            crate::serial_println!("[VIRTIO-NET] No virtio-net PCI device found");
            return false;
        }
    };

    crate::serial_println!(
        "[VIRTIO-NET] Found device at PCI {:02x}:{:02x}.{} (vendor={:04x} device={:04x})",
        pci_dev.bus, pci_dev.device, pci_dev.function,
        pci_dev.vendor_id, pci_dev.device_id
    );

    // BAR0 must be an I/O port BAR (bit 0 set).
    let bar0 = pci_dev.bar[0];
    if bar0 & 1 == 0 {
        crate::serial_println!("[VIRTIO-NET] BAR0 is not I/O space — aborting");
        return false;
    }
    let io_base = (bar0 & 0xFFFF_FFFC) as u16;
    crate::serial_println!("[VIRTIO-NET] I/O base = {:#06x}", io_base);

    // Enable bus mastering + I/O space access.
    crate::drivers::pci::enable_bus_master(pci_dev.bus, pci_dev.device, pci_dev.function);
    let cmd = crate::drivers::pci::pci_config_read32(
        pci_dev.bus, pci_dev.device, pci_dev.function, 0x04,
    );
    crate::drivers::pci::pci_config_write32(
        pci_dev.bus, pci_dev.device, pci_dev.function, 0x04, cmd | 0x01,
    );

    // SAFETY: Writing to I/O ports of the discovered virtio-net PCI device.
    // `io_base` was read from a valid BAR0; the device is a known virtio device.
    unsafe {
        // 1. Reset device — write 0 to status.
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);

        // 2. Acknowledge.
        hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. Declare ourselves a driver.
        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );

        // 4. Feature negotiation.
        // Read what the device offers; accept only F_MAC and F_STATUS.
        // We deliberately skip F_CSUM, F_GSO, F_MRG_RXBUF — keeping the
        // on-wire format trivial (fixed-size virtio_net_hdr, no coalescing).
        let device_features = hal::inl(io_base + VIRTIO_REG_DEVICE_FEATURES);
        let guest_features = device_features & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
        hal::outl(io_base + VIRTIO_REG_GUEST_FEATURES, guest_features);
        crate::serial_println!(
            "[VIRTIO-NET] Device features: {:#010x}, negotiated: {:#010x}",
            device_features, guest_features
        );

        // 5. Read MAC from config space (VIRTIO_NET_F_MAC guaranteed above).
        let mut mac = [0u8; 6];
        for i in 0u16..6 {
            mac[i as usize] = hal::inb(io_base + VIRTIO_NET_REG_MAC + i);
        }
        crate::serial_println!(
            "[VIRTIO-NET] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        if mac.iter().any(|&b| b != 0) {
            super::set_our_mac(mac);
        }

        // 6. Set up RX virtqueue (queue 0).
        hal::outw(io_base + VIRTIO_REG_QUEUE_SELECT, QUEUE_RX);
        let rxq_size = hal::inw(io_base + VIRTIO_REG_QUEUE_SIZE);
        if rxq_size == 0 {
            crate::serial_println!("[VIRTIO-NET] RX queue not available");
            hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
            return false;
        }
        let rx_use = core::cmp::min(rxq_size, NUM_RX_DESC as u16);
        crate::serial_println!("[VIRTIO-NET] RX queue size: {} (using {})", rxq_size, rx_use);

        let rxq_bytes = virtqueue_total_bytes(rx_use);
        let rxq_pages = (rxq_bytes + 4095) / 4096;
        let rxq_phys = match pmm::alloc_pages(rxq_pages) {
            Some(p) => p,
            None => {
                crate::serial_println!("[VIRTIO-NET] Failed to alloc RX virtqueue pages");
                hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
                return false;
            }
        };
        core::ptr::write_bytes(phys_to_virt::<u8>(rxq_phys), 0, rxq_bytes);
        hal::outl(io_base + VIRTIO_REG_QUEUE_ADDRESS, (rxq_phys >> 12) as u32);

        // Allocate RX buffer slab: rx_use * RX_BUF_SIZE bytes.
        let rx_buf_pages = (rx_use as usize * RX_BUF_SIZE + 4095) / 4096;
        let rx_bufs_phys = match pmm::alloc_pages(rx_buf_pages) {
            Some(p) => p,
            None => {
                crate::serial_println!("[VIRTIO-NET] Failed to alloc RX buffers");
                hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
                return false;
            }
        };

        // 7. Set up TX virtqueue (queue 1).
        hal::outw(io_base + VIRTIO_REG_QUEUE_SELECT, QUEUE_TX);
        let txq_size = hal::inw(io_base + VIRTIO_REG_QUEUE_SIZE);
        if txq_size == 0 {
            crate::serial_println!("[VIRTIO-NET] TX queue not available");
            hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
            return false;
        }
        // Each TX uses 2 descriptors (header + data), so cap TX slots at
        // txq_size/2 to ensure we always have a pair of free descriptors.
        let tx_slots = core::cmp::min(txq_size / 2, NUM_TX_SLOTS as u16);
        let tx_desc_count = tx_slots * 2; // descriptors actually used
        crate::serial_println!(
            "[VIRTIO-NET] TX queue size: {} (using {} slots = {} descs)",
            txq_size, tx_slots, tx_desc_count
        );

        let txq_bytes = virtqueue_total_bytes(txq_size);
        let txq_pages = (txq_bytes + 4095) / 4096;
        let txq_phys = match pmm::alloc_pages(txq_pages) {
            Some(p) => p,
            None => {
                crate::serial_println!("[VIRTIO-NET] Failed to alloc TX virtqueue pages");
                hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
                return false;
            }
        };
        core::ptr::write_bytes(phys_to_virt::<u8>(txq_phys), 0, txq_bytes);
        hal::outl(io_base + VIRTIO_REG_QUEUE_ADDRESS, (txq_phys >> 12) as u32);

        // Allocate TX buffer slab: tx_slots * RX_BUF_SIZE bytes.
        // Each slot holds VIRTIO_NET_HDR_SIZE + up to (RX_BUF_SIZE - HDR_SIZE)
        // bytes of frame data — a single allocation covers both.
        let tx_buf_pages = (tx_slots as usize * RX_BUF_SIZE + 4095) / 4096;
        let tx_bufs_phys = match pmm::alloc_pages(tx_buf_pages) {
            Some(p) => p,
            None => {
                crate::serial_println!("[VIRTIO-NET] Failed to alloc TX buffers");
                hal::outb(io_base + VIRTIO_REG_DEVICE_STATUS, 0);
                return false;
            }
        };

        // 8. Mark driver ready.
        hal::outb(
            io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
        );

        // 9. Pre-fill the RX available ring with all rx_use descriptors.
        // Each descriptor points at one receive buffer; the device will DMA
        // received frames (with virtio_net_hdr prefix) into them.
        let rxq_virt = phys_to_virt::<u8>(rxq_phys);
        let avail_base = rxq_virt.add(avail_ring_offset(rx_use));

        for i in 0..rx_use as u64 {
            let buf_phys = rx_bufs_phys + i * RX_BUF_SIZE as u64;

            // Fill descriptor i: writable (device writes RX data), no chain.
            let desc = rxq_virt.add((i as usize) * 16) as *mut u64;
            desc.write_volatile(buf_phys);                         // addr
            let desc_meta = rxq_virt.add((i as usize) * 16 + 8) as *mut u32;
            desc_meta.write_volatile(RX_BUF_SIZE as u32);          // len
            let desc_flags = rxq_virt.add((i as usize) * 16 + 12) as *mut u16;
            desc_flags.write_volatile(VRING_DESC_F_WRITE);          // device writes
            let desc_next = rxq_virt.add((i as usize) * 16 + 14) as *mut u16;
            desc_next.write_volatile(0);                            // no chain
        }

        // Populate the available ring: flags=0, idx=rx_use, ring=[0..rx_use-1].
        let avail_flags = avail_base as *mut u16;
        avail_flags.write_volatile(0);
        let avail_idx = avail_base.add(2) as *mut u16;
        avail_idx.write_volatile(0);
        for i in 0..rx_use {
            let slot = avail_base.add(4 + (i as usize) * 2) as *mut u16;
            slot.write_volatile(i);
        }

        // Memory fence before we advance avail->idx so the device sees
        // all descriptor and ring entries before the new index.
        core::sync::atomic::fence(Ordering::SeqCst);
        avail_idx.write_volatile(rx_use);

        // Notify the device that queue 0 (RX) has new buffers.
        hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, QUEUE_RX);

        crate::serial_println!(
            "[VIRTIO-NET] Initialized: io={:#06x}, rxq={:#x} ({} desc), \
             txq={:#x} ({} slots)",
            io_base, rxq_phys, rx_use, txq_phys, tx_slots
        );

        *VIRTIO_NET.lock() = Some(VirtioNetDevice {
            io_base,
            rxq_phys,
            rxq_size: rx_use,
            txq_phys,
            txq_size: txq_size,
            rx_bufs_phys,
            tx_bufs_phys,
            rxq_last_used: 0,
            txq_last_used: 0,
            rxq_avail_idx: rx_use, // we already posted rx_use descriptors
            tx_slot: 0,
        });
        VIRTIO_NET_AVAILABLE.store(true, Ordering::Release);
    }

    true
}

// ── PCI Discovery ───────────────────────────────────────────────────────────

fn find_virtio_net_pci() -> Option<crate::drivers::pci::PciDevice> {
    let devices = crate::drivers::pci::devices();
    for dev in &devices {
        if dev.vendor_id == VIRTIO_VENDOR {
            // Legacy net: device_id == 0x1000.
            if dev.device_id == VIRTIO_NET_DEVICE_LEGACY {
                return Some(*dev);
            }
            // Fallback: check subsystem ID (1 = network) for generic devices.
            let subsys = crate::drivers::pci::pci_config_read32(
                dev.bus, dev.device, dev.function, 0x2C,
            );
            let subsys_id = (subsys >> 16) as u16;
            if subsys_id == VIRTIO_SUBSYS_NET {
                return Some(*dev);
            }
        }
    }
    None
}

// ── TX ──────────────────────────────────────────────────────────────────────

/// Send a raw Ethernet frame via virtio-net.
///
/// The caller passes the raw frame (no virtio_net_hdr).  This function:
/// 1. Copies the frame into a driver-owned TX buffer slot.
/// 2. Prepends a zeroed virtio_net_hdr (no offloads).
/// 3. Posts a 2-descriptor chain (hdr + frame) onto the TX virtqueue.
/// 4. Kicks the notification register.
/// 5. Spin-polls the used ring for completion before returning.
pub fn send_packet(data: &[u8]) {
    if !VIRTIO_NET_AVAILABLE.load(Ordering::Acquire) { return; }
    if data.is_empty() || data.len() > (RX_BUF_SIZE - VIRTIO_NET_HDR_SIZE) { return; }

    let mut guard = VIRTIO_NET.lock();
    let dev = match guard.as_mut() {
        Some(d) => d,
        None => return,
    };

    let io_base    = dev.io_base;
    let qs         = dev.txq_size;
    let txq_base   = phys_to_virt::<u8>(dev.txq_phys);

    // Pick the next TX slot (wraps at NUM_TX_SLOTS).
    let slot = dev.tx_slot as usize;
    let tx_slots = core::cmp::min(qs / 2, NUM_TX_SLOTS as u16) as usize;
    dev.tx_slot = ((slot + 1) % tx_slots) as u16;

    // Each slot occupies RX_BUF_SIZE bytes: first VIRTIO_NET_HDR_SIZE bytes
    // are the header, remainder is the frame payload copy.
    let slot_phys  = dev.tx_bufs_phys + (slot * RX_BUF_SIZE) as u64;
    let hdr_phys   = slot_phys;
    let frame_phys = slot_phys + VIRTIO_NET_HDR_SIZE as u64;

    // SAFETY: The TX buffer slab was allocated from the PMM and is exclusively
    // owned by this driver.  Holding the mutex ensures single-threaded access.
    unsafe {
        // Zero the virtio_net_hdr (12 bytes): all fields 0 = no offloads,
        // gso_type = VIRTIO_NET_HDR_GSO_NONE (0).
        let hdr_virt = phys_to_virt::<u8>(hdr_phys);
        core::ptr::write_bytes(hdr_virt, 0, VIRTIO_NET_HDR_SIZE);

        // Copy frame into the buffer immediately after the header.
        let frame_virt = phys_to_virt::<u8>(frame_phys);
        core::ptr::copy_nonoverlapping(data.as_ptr(), frame_virt, data.len());
    }

    // Descriptor indices: use slot*2 for hdr, slot*2+1 for frame.
    // These stay within [0, qs) because tx_slots = qs/2.
    let d_hdr   = (slot * 2) as usize;
    let d_frame = (slot * 2 + 1) as usize;

    // SAFETY: Writing to the descriptor table within our allocated virtqueue pages.
    unsafe {
        // Descriptor 0 (slot*2): net header — device reads, has next.
        let d0 = txq_base.add(d_hdr * 16) as *mut u64;
        d0.write_volatile(hdr_phys);
        let d0_len   = txq_base.add(d_hdr * 16 + 8)  as *mut u32;
        let d0_flags = txq_base.add(d_hdr * 16 + 12) as *mut u16;
        let d0_next  = txq_base.add(d_hdr * 16 + 14) as *mut u16;
        d0_len.write_volatile(VIRTIO_NET_HDR_SIZE as u32);
        d0_flags.write_volatile(VRING_DESC_F_NEXT);
        d0_next.write_volatile(d_frame as u16);

        // Descriptor 1 (slot*2+1): frame data — device reads, end of chain.
        let d1 = txq_base.add(d_frame * 16) as *mut u64;
        d1.write_volatile(frame_phys);
        let d1_len   = txq_base.add(d_frame * 16 + 8)  as *mut u32;
        let d1_flags = txq_base.add(d_frame * 16 + 12) as *mut u16;
        let d1_next  = txq_base.add(d_frame * 16 + 14) as *mut u16;
        d1_len.write_volatile(data.len() as u32);
        d1_flags.write_volatile(0); // no WRITE, no NEXT
        d1_next.write_volatile(0);

        // Place the head descriptor index in the available ring.
        let avail_base = txq_base.add(avail_ring_offset(qs));
        let avail_idx_ptr = avail_base.add(2) as *mut u16;
        let avail_idx = avail_idx_ptr.read_volatile();
        let ring_slot = avail_base.add(4 + ((avail_idx % qs) as usize) * 2) as *mut u16;
        ring_slot.write_volatile(d_hdr as u16);

        // Fence: descriptor writes must be visible before the index advance.
        core::sync::atomic::fence(Ordering::SeqCst);

        avail_idx_ptr.write_volatile(avail_idx.wrapping_add(1));

        // Kick the device: writing queue 1 to QUEUE_NOTIFY triggers TX.
        hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, QUEUE_TX);

        // Spin-poll the used ring until the device marks completion.
        // The used ring layout: flags(u16), idx(u16), ring[qs]({id,len} each 8 bytes).
        let used_base = txq_base.add(used_ring_offset(qs));
        let used_idx_ptr = used_base.add(2) as *const u16;
        let expected = dev.txq_last_used.wrapping_add(1);

        let mut timeout = 5_000_000u32;
        loop {
            let current = used_idx_ptr.read_volatile();
            if current == expected { break; }
            timeout = match timeout.checked_sub(1) {
                Some(v) => v,
                None => {
                    crate::serial_println!("[VIRTIO-NET] TX timeout waiting for used ring");
                    break;
                }
            };
            core::hint::spin_loop();
        }
        dev.txq_last_used = expected;
    }
}

// ── RX ──────────────────────────────────────────────────────────────────────

/// Poll the RX virtqueue for completed receive buffers.
///
/// For each completed buffer the device wrote into:
/// - Skip the first `VIRTIO_NET_HDR_SIZE` bytes (virtio_net_hdr).
/// - Pass the remaining Ethernet frame to `super::handle_rx_packet()`.
/// - Re-post the descriptor back onto the available ring for reuse.
///
/// To avoid a lock-inversion hazard (the network stack may call back into
/// `send_packet`, which also takes VIRTIO_NET), we copy the received frame
/// into a stack buffer while holding the lock, then release the lock before
/// calling up to `handle_rx_packet`.
pub fn poll_rx() {
    if !VIRTIO_NET_AVAILABLE.load(Ordering::Acquire) { return; }

    // Process one completed RX descriptor per call.  If the caller wants to
    // drain the queue it should call poll_rx() in a loop.
    let mut frame_buf = [0u8; RX_BUF_SIZE];
    let mut frame_len = 0usize;
    let mut desc_id_to_repost: Option<u16> = None;

    {
        let mut guard = VIRTIO_NET.lock();
        let dev = match guard.as_mut() {
            Some(d) => d,
            None => return,
        };

        let io_base = dev.io_base;
        let qs      = dev.rxq_size;

        // SAFETY: All accesses below are to PMM-allocated memory we own.
        // The device owns only descriptors in the available ring; used-ring
        // entries are returned to us.
        unsafe {
            let rxq_virt  = phys_to_virt::<u8>(dev.rxq_phys);
            let used_base = rxq_virt.add(used_ring_offset(qs));
            let used_idx  = (used_base.add(2) as *const u16).read_volatile();

            if used_idx == dev.rxq_last_used {
                return; // nothing received
            }

            // Read the used-ring entry for our current position.
            let entry_off   = 4 + ((dev.rxq_last_used % qs) as usize) * 8;
            let desc_id     = (used_base.add(entry_off)     as *const u32).read_volatile() as usize;
            let total_len   = (used_base.add(entry_off + 4) as *const u32).read_volatile() as usize;

            dev.rxq_last_used = dev.rxq_last_used.wrapping_add(1);

            if total_len > VIRTIO_NET_HDR_SIZE && desc_id < qs as usize {
                let flen    = total_len - VIRTIO_NET_HDR_SIZE;
                let buf_phys = dev.rx_bufs_phys + (desc_id * RX_BUF_SIZE) as u64;
                let src     = phys_to_virt::<u8>(buf_phys + VIRTIO_NET_HDR_SIZE as u64);
                let copy_len = core::cmp::min(flen, RX_BUF_SIZE - VIRTIO_NET_HDR_SIZE);
                core::ptr::copy_nonoverlapping(src, frame_buf.as_mut_ptr(), copy_len);
                frame_len = copy_len;
            }

            // Re-post the descriptor regardless of frame validity so the
            // device never runs out of RX buffers.
            let rxq_virt_repost = phys_to_virt::<u8>(dev.rxq_phys);
            re_post_rx_desc(rxq_virt_repost, qs, dev, desc_id as u16, io_base);
            desc_id_to_repost = Some(desc_id as u16);
        }
    } // mutex released here

    // Now call up into the stack with no locks held.
    let _ = desc_id_to_repost; // already re-posted inside the lock
    if frame_len > 0 {
        super::handle_rx_packet(&frame_buf[..frame_len]);
    }
}

/// Post one RX descriptor back into the available ring and kick the device.
///
/// # Safety
/// Caller must hold the VIRTIO_NET mutex and `rxq_virt` must be the valid
/// virtual base of the RX virtqueue.
unsafe fn re_post_rx_desc(
    rxq_virt: *mut u8,
    qs: u16,
    dev: &mut VirtioNetDevice,
    desc_id: u16,
    io_base: u16,
) {
    let avail_base = rxq_virt.add(avail_ring_offset(qs));
    let avail_idx_ptr = avail_base.add(2) as *mut u16;
    let avail_idx = avail_idx_ptr.read_volatile();
    let ring_slot = avail_base.add(4 + ((avail_idx % qs) as usize) * 2) as *mut u16;
    ring_slot.write_volatile(desc_id);

    core::sync::atomic::fence(Ordering::SeqCst);
    avail_idx_ptr.write_volatile(avail_idx.wrapping_add(1));
    dev.rxq_avail_idx = avail_idx.wrapping_add(1);

    // Notify device of new RX buffer.
    hal::outw(io_base + VIRTIO_REG_QUEUE_NOTIFY, QUEUE_RX);
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Check if a virtio-net device is available.
pub fn is_available() -> bool {
    VIRTIO_NET_AVAILABLE.load(Ordering::Acquire)
}

/// Acknowledge a virtio-net IRQ by reading and clearing the ISR status register.
/// Returns the ISR value: bit 0 = queue interrupt, bit 1 = device config change.
/// Call this from the IRQ handler (same IRQ vector as e1000 or a dedicated one).
pub fn acknowledge_irq() -> u8 {
    if !VIRTIO_NET_AVAILABLE.load(Ordering::Acquire) { return 0; }
    let guard = VIRTIO_NET.lock();
    match guard.as_ref() {
        // SAFETY: Reading the ISR_STATUS port of the virtio-net device.
        // Reading this register atomically clears the interrupt assertion.
        Some(dev) => unsafe { hal::inb(dev.io_base + VIRTIO_REG_ISR_STATUS) },
        None => 0,
    }
}
