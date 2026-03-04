//! UDP — User Datagram Protocol
//!
//! Connectionless datagram transport.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use super::{Ipv4Address, our_ip};
use super::ipv4;

/// A UDP header (parsed).
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 { return None; }
        Some(UdpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }
}

/// Received UDP datagram.
pub struct UdpDatagram {
    pub src_ip: Ipv4Address,
    pub src_port: u16,
    pub data: Vec<u8>,
}

/// Per-port receive buffer.
struct UdpBinding {
    port: u16,
    queue: Vec<UdpDatagram>,
}

/// Bound UDP ports.
static UDP_BINDINGS: Mutex<Vec<UdpBinding>> = Mutex::new(Vec::new());

/// Handle an incoming UDP packet.
pub fn handle_udp(src_ip: Ipv4Address, _dst_ip: Ipv4Address, data: &[u8]) {
    let header = match UdpHeader::parse(data) {
        Some(h) => h,
        None => return,
    };

    let payload = &data[8..];

    crate::serial_println!("[UDP] {}:{} -> port {} ({} bytes)",
        src_ip[0], src_ip[1],
        header.dst_port, payload.len());

    // Deliver to bound port.
    let mut bindings = UDP_BINDINGS.lock();
    if let Some(binding) = bindings.iter_mut().find(|b| b.port == header.dst_port) {
        binding.queue.push(UdpDatagram {
            src_ip,
            src_port: header.src_port,
            data: Vec::from(payload),
        });
    }
}

/// Bind a UDP port for receiving.
pub fn bind(port: u16) -> Result<(), &'static str> {
    let mut bindings = UDP_BINDINGS.lock();
    if bindings.iter().any(|b| b.port == port) {
        return Err("port already bound");
    }
    bindings.push(UdpBinding {
        port,
        queue: Vec::new(),
    });
    Ok(())
}

/// Receive a datagram from a bound port (non-blocking).
pub fn recv(port: u16) -> Option<UdpDatagram> {
    let mut bindings = UDP_BINDINGS.lock();
    if let Some(binding) = bindings.iter_mut().find(|b| b.port == port) {
        if !binding.queue.is_empty() {
            return Some(binding.queue.remove(0));
        }
    }
    None
}

/// Unbind a UDP port.
pub fn unbind(port: u16) {
    let mut bindings = UDP_BINDINGS.lock();
    bindings.retain(|b| b.port != port);
}

/// Send a UDP datagram.
pub fn send(dst_ip: Ipv4Address, src_port: u16, dst_port: u16, payload: &[u8]) {
    let udp_len = 8 + payload.len();
    let mut packet = Vec::with_capacity(udp_len);

    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    // Checksum (0 = disabled for UDP).
    packet.push(0);
    packet.push(0);
    packet.extend_from_slice(payload);

    // Compute UDP checksum over pseudo-header + UDP packet.
    let cksum = udp_checksum(our_ip(), dst_ip, &packet);
    packet[6] = (cksum >> 8) as u8;
    packet[7] = (cksum & 0xFF) as u8;

    ipv4::send_ipv4(dst_ip, ipv4::PROTO_UDP, &packet);
}

/// Send a UDP datagram with a custom source IP and destination MAC.
/// Used by DHCP (src 0.0.0.0, broadcast MAC ff:ff:ff:ff:ff:ff).
pub fn send_from(src_ip: Ipv4Address, dst_ip: Ipv4Address, dst_mac: super::MacAddress,
                 src_port: u16, dst_port: u16, payload: &[u8]) {
    let udp_len = 8 + payload.len();
    let mut packet = Vec::with_capacity(udp_len);

    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.push(0);
    packet.push(0);
    packet.extend_from_slice(payload);

    let cksum = udp_checksum(src_ip, dst_ip, &packet);
    packet[6] = (cksum >> 8) as u8;
    packet[7] = (cksum & 0xFF) as u8;

    ipv4::send_ipv4_from(src_ip, dst_ip, dst_mac, ipv4::PROTO_UDP, &packet);
}

/// UDP checksum with pseudo-header.
fn udp_checksum(src_ip: Ipv4Address, dst_ip: Ipv4Address, udp_data: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_data.len());
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(ipv4::PROTO_UDP);
    pseudo.extend_from_slice(&(udp_data.len() as u16).to_be_bytes());

    // Zero the checksum field in the copy for calculation.
    pseudo.extend_from_slice(udp_data);
    let cksum_offset = 12 + 6;
    if pseudo.len() > cksum_offset + 1 {
        pseudo[cksum_offset] = 0;
        pseudo[cksum_offset + 1] = 0;
    }

    ipv4::checksum(&pseudo)
}
