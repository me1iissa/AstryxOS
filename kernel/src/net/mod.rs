//! Network Subsystem
//!
//! Provides a minimal networking stack:
//! - Ethernet frame handling
//! - ARP (Address Resolution Protocol)
//! - IPv4 (Internet Protocol v4)
//! - ICMP (ping)
//! - UDP (User Datagram Protocol)
//! - TCP (Transmission Control Protocol) — basic connection state machine
//!
//! The network driver is an Intel e1000 (QEMU). Virtio-net is also available
//! but the e1000 driver provides simpler MMIO-based I/O that works in WSL2.

pub mod e1000;
pub mod virtio_net;
pub mod ethernet;
pub mod arp;
pub mod ipv4;
pub mod icmp;
pub mod ipv6;
pub mod icmpv6;
pub mod udp;
pub mod tcp;
pub mod socket;
pub mod dns;
pub mod dhcp;
pub mod unix;

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

/// MAC address type.
pub type MacAddress = [u8; 6];
/// IPv4 address type.
pub type Ipv4Address = [u8; 4];
/// IPv6 address type.
pub type Ipv6Address = [u8; 16];

/// Our MAC address (assigned by e1000 or default).
static OUR_MAC: Mutex<MacAddress> = Mutex::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
/// Our IPv4 address (QEMU user-mode NAT default: 10.0.2.15).
static OUR_IP: Mutex<Ipv4Address> = Mutex::new([10, 0, 2, 15]);
/// Gateway IP (QEMU SLIRP gateway: 10.0.2.2).
static GATEWAY_IP: Mutex<Ipv4Address> = Mutex::new([10, 0, 2, 2]);
/// Subnet mask.
static SUBNET_MASK: Mutex<Ipv4Address> = Mutex::new([255, 255, 255, 0]);

/// Our IPv6 address (QEMU SLIRP default: fec0::15).
static OUR_IPV6: Mutex<Ipv6Address> = Mutex::new([
    0xfe, 0xc0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x15,
]);
/// IPv6 gateway (QEMU SLIRP default: fec0::2).
static GATEWAY_IPV6: Mutex<Ipv6Address> = Mutex::new([
    0xfe, 0xc0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x02,
]);

pub fn our_mac() -> MacAddress { *OUR_MAC.lock() }
pub fn our_ip() -> Ipv4Address { *OUR_IP.lock() }
pub fn gateway_ip() -> Ipv4Address { *GATEWAY_IP.lock() }
pub fn subnet_mask() -> Ipv4Address { *SUBNET_MASK.lock() }
pub fn our_ipv6() -> Ipv6Address { *OUR_IPV6.lock() }
pub fn gateway_ipv6() -> Ipv6Address { *GATEWAY_IPV6.lock() }

pub fn set_our_mac(mac: MacAddress) { *OUR_MAC.lock() = mac; }
pub fn set_our_ip(ip: Ipv4Address) { *OUR_IP.lock() = ip; }
pub fn set_gateway_ip(ip: Ipv4Address) { *GATEWAY_IP.lock() = ip; }
pub fn set_subnet_mask(mask: Ipv4Address) { *SUBNET_MASK.lock() = mask; }
pub fn set_our_ipv6(ip: Ipv6Address) { *OUR_IPV6.lock() = ip; }
pub fn set_gateway_ipv6(ip: Ipv6Address) { *GATEWAY_IPV6.lock() = ip; }

/// Network interface statistics.
pub struct NetStats {
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
}

static STATS: Mutex<NetStats> = Mutex::new(NetStats {
    packets_rx: 0, packets_tx: 0, bytes_rx: 0, bytes_tx: 0,
});

pub fn stats() -> (u64, u64, u64, u64) {
    let s = STATS.lock();
    (s.packets_rx, s.packets_tx, s.bytes_rx, s.bytes_tx)
}

/// Initialize the network subsystem.
pub fn init() {
    // Try Intel e1000 first (preferred for QEMU + WSL2)
    if e1000::init() {
        crate::serial_println!("[NET] e1000 initialized, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            our_mac()[0], our_mac()[1], our_mac()[2],
            our_mac()[3], our_mac()[4], our_mac()[5]);
        crate::serial_println!("[NET] IPv4={}.{}.{}.{}", our_ip()[0], our_ip()[1], our_ip()[2], our_ip()[3]);
        crate::serial_println!("[NET] IPv6={}", format_ipv6(our_ipv6()));
    } else if virtio_net::init() {
        // Fallback to virtio-net
        crate::serial_println!("[NET] virtio-net initialized, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            our_mac()[0], our_mac()[1], our_mac()[2],
            our_mac()[3], our_mac()[4], our_mac()[5]);
        crate::serial_println!("[NET] IPv4={}.{}.{}.{}", our_ip()[0], our_ip()[1], our_ip()[2], our_ip()[3]);
        crate::serial_println!("[NET] IPv6={}", format_ipv6(our_ipv6()));
    } else {
        crate::serial_println!("[NET] No network device found (networking disabled)");
    }
}

/// Handle a received packet from the network device.
pub fn handle_rx_packet(data: &[u8]) {
    {
        let mut s = STATS.lock();
        s.packets_rx += 1;
        s.bytes_rx += data.len() as u64;
    }

    #[cfg(feature = "test-mode")]
    {
        crate::serial_println!("[NET RX] {} bytes | src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} type={:02x}{:02x}",
            data.len(),
            data[6], data[7], data[8], data[9], data[10], data[11],
            if data.len() >= 14 { data[12] } else { 0 },
            if data.len() >= 14 { data[13] } else { 0 });
    }

    ethernet::handle_frame(data);
}

/// Send a raw Ethernet frame.
pub fn send_frame(frame: &[u8]) {
    {
        let mut s = STATS.lock();
        s.packets_tx += 1;
        s.bytes_tx += frame.len() as u64;
    }

    #[cfg(feature = "test-mode")]
    {
        crate::serial_println!("[NET TX] {} bytes | dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} type={:02x}{:02x}",
            frame.len(),
            frame[0], frame[1], frame[2], frame[3], frame[4], frame[5],
            frame[12], frame[13]);
    }

    if e1000::is_available() {
        e1000::send_packet(frame);
    } else {
        virtio_net::send_packet(frame);
    }
}

/// Poll for incoming packets from the NIC.
pub fn poll() {
    if e1000::is_available() {
        e1000::poll_rx();
    } else {
        virtio_net::poll_rx();
    }
}

/// Format an IPv4 address as a string.
pub fn format_ip(ip: Ipv4Address) -> alloc::string::String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Format an IPv6 address as a string with `::` compression.
pub fn format_ipv6(addr: Ipv6Address) -> alloc::string::String {
    use core::fmt::Write;

    let groups: [u16; 8] = [
        u16::from_be_bytes([addr[0], addr[1]]),
        u16::from_be_bytes([addr[2], addr[3]]),
        u16::from_be_bytes([addr[4], addr[5]]),
        u16::from_be_bytes([addr[6], addr[7]]),
        u16::from_be_bytes([addr[8], addr[9]]),
        u16::from_be_bytes([addr[10], addr[11]]),
        u16::from_be_bytes([addr[12], addr[13]]),
        u16::from_be_bytes([addr[14], addr[15]]),
    ];

    // Find longest run of consecutive zero groups (for :: compression)
    let mut best_start = 8usize;
    let mut best_len = 0usize;
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;

    for i in 0..8 {
        if groups[i] == 0 {
            if cur_len == 0 { cur_start = i; }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }

    let mut s = alloc::string::String::new();
    let mut i = 0usize;
    while i < 8 {
        if i == best_start && best_len > 1 {
            if i == 0 { s.push(':'); }
            s.push(':');
            i += best_len;
            continue;
        }
        if i > 0 { s.push(':'); }
        let _ = write!(s, "{:x}", groups[i]);
        i += 1;
    }

    s
}
