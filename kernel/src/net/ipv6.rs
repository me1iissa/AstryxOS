//! IPv6 — Internet Protocol version 6
//!
//! Handles IPv6 packet parsing, construction, and routing.
//! Uses QEMU SLIRP's IPv6 support (fec0::/64 prefix by default).

extern crate alloc;

use alloc::vec::Vec;
use super::{Ipv6Address, MacAddress, our_ipv6, send_frame};
use super::ethernet::{build_frame, ETHERTYPE_IPV6};

/// IPv6 Next Header values.
pub const PROTO_ICMPV6: u8 = 58;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// IPv6 header size (fixed, no options in base header).
pub const IPV6_HEADER_SIZE: usize = 40;

/// An IPv6 header (parsed).
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: Ipv6Address,
    pub dst_addr: Ipv6Address,
}

impl Ipv6Header {
    /// Parse an IPv6 header from raw bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < IPV6_HEADER_SIZE { return None; }

        let version = data[0] >> 4;
        if version != 6 { return None; }

        let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
        let flow_label = ((data[1] as u32 & 0x0F) << 16)
            | ((data[2] as u32) << 8)
            | (data[3] as u32);
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];

        let mut src_addr = [0u8; 16];
        let mut dst_addr = [0u8; 16];
        src_addr.copy_from_slice(&data[8..24]);
        dst_addr.copy_from_slice(&data[24..40]);

        Some(Ipv6Header {
            version, traffic_class, flow_label, payload_length,
            next_header, hop_limit, src_addr, dst_addr,
        })
    }
}

/// Handle an incoming IPv6 packet.
pub fn handle_ipv6(data: &[u8]) {
    let header = match Ipv6Header::parse(data) {
        Some(h) => h,
        None => return,
    };

    // Accept packets addressed to us, multicast (ff00::/8), or if we have no IPv6 yet
    let our = our_ipv6();
    let all_zeros = [0u8; 16];
    if header.dst_addr != our && header.dst_addr[0] != 0xFF && our != all_zeros {
        return;
    }

    let payload_start = IPV6_HEADER_SIZE;
    if data.len() < payload_start + header.payload_length as usize { return; }
    let payload = &data[payload_start..payload_start + header.payload_length as usize];

    match header.next_header {
        PROTO_ICMPV6 => super::icmpv6::handle_icmpv6(header.src_addr, header.dst_addr, payload),
        _ => {
            crate::serial_println!("[IPv6] Next header {} (ignored)", header.next_header);
        }
    }
}

/// Calculate checksum with IPv6 pseudo-header (RFC 2460 §8.1).
///
/// Pseudo-header: src_addr(16) + dst_addr(16) + upper_length(4) + zeros(3) + next_header(1)
pub fn ipv6_pseudo_checksum(src: &Ipv6Address, dst: &Ipv6Address, next_header: u8, data: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + data.len());
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    let upper_len = data.len() as u32;
    pseudo.extend_from_slice(&upper_len.to_be_bytes());
    pseudo.push(0);
    pseudo.push(0);
    pseudo.push(0);
    pseudo.push(next_header);
    pseudo.extend_from_slice(data);

    super::ipv4::checksum(&pseudo)
}

/// Build and send an IPv6 packet.
pub fn send_ipv6(dst_addr: Ipv6Address, next_header: u8, payload: &[u8]) {
    let src_addr = our_ipv6();

    let mut packet = Vec::with_capacity(IPV6_HEADER_SIZE + payload.len());

    // Version (6), Traffic Class (0), Flow Label (0)
    packet.push(0x60);
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x00);

    // Payload length
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    // Next header
    packet.push(next_header);
    // Hop limit
    packet.push(64);

    // Source address
    packet.extend_from_slice(&src_addr);
    // Destination address
    packet.extend_from_slice(&dst_addr);

    // Payload
    packet.extend_from_slice(payload);

    // Resolve destination MAC
    let dst_mac = resolve_ipv6_mac(dst_addr);

    let frame = build_frame(dst_mac, ETHERTYPE_IPV6, &packet);
    send_frame(&frame);
}

/// Resolve MAC address for an IPv6 destination.
///
/// For QEMU SLIRP, all traffic goes through the gateway, so we reuse
/// the ARP-cached MAC of the IPv4 gateway (same virtual NIC).
fn resolve_ipv6_mac(dst_addr: Ipv6Address) -> MacAddress {
    // IPv6 multicast → multicast MAC (33:33:xx:xx:xx:xx)
    if dst_addr[0] == 0xFF {
        return [0x33, 0x33, dst_addr[12], dst_addr[13], dst_addr[14], dst_addr[15]];
    }

    // Unicast: use the IPv4 gateway's MAC from ARP cache.
    // In QEMU SLIRP, the same virtual gateway handles both IPv4 and IPv6.
    let gw = super::gateway_ip();
    if let Some(mac) = super::arp::lookup(gw) {
        return mac;
    }

    // No ARP entry yet — send ARP request and use broadcast as fallback
    super::arp::send_request(gw);
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
}
