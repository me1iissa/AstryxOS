//! Ethernet Frame Handling
//!
//! Parses and constructs Ethernet II frames.

extern crate alloc;
use alloc::vec::Vec;
use super::{MacAddress, our_mac};

/// Ethernet frame header size.
pub const ETH_HEADER_SIZE: usize = 14;

/// EtherTypes.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Parse and dispatch an Ethernet frame.
pub fn handle_frame(data: &[u8]) {
    if data.len() < ETH_HEADER_SIZE {
        return;
    }

    let dst_mac: MacAddress = data[0..6].try_into().unwrap();
    let _src_mac: MacAddress = data[6..12].try_into().unwrap();
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // Only accept frames addressed to us, broadcast, or IPv6 multicast (33:33:xx).
    let broadcast: MacAddress = [0xFF; 6];
    let is_multicast = dst_mac[0] == 0x33 && dst_mac[1] == 0x33;
    if dst_mac != our_mac() && dst_mac != broadcast && !is_multicast {
        return;
    }

    let payload = &data[ETH_HEADER_SIZE..];

    match ethertype {
        ETHERTYPE_ARP => super::arp::handle_arp(payload),
        ETHERTYPE_IPV4 => super::ipv4::handle_ipv4(payload),
        ETHERTYPE_IPV6 => super::ipv6::handle_ipv6(payload),
        _ => {} // Ignore unknown ethertypes
    }
}

/// Build an Ethernet frame with the given destination, ethertype, and payload.
pub fn build_frame(dst: MacAddress, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETH_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&our_mac());
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    
    // Pad to minimum Ethernet frame size (64 bytes including CRC, but we don't add CRC).
    while frame.len() < 60 {
        frame.push(0);
    }
    
    frame
}
