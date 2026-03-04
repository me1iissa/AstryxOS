//! ARP — Address Resolution Protocol
//!
//! Maps IPv4 addresses to MAC addresses on the local network.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use super::{MacAddress, Ipv4Address, our_mac, our_ip};
use super::ethernet::{build_frame, ETHERTYPE_ARP};

/// ARP cache entry.
struct ArpEntry {
    ip: Ipv4Address,
    mac: MacAddress,
}

/// ARP cache.
static ARP_CACHE: Mutex<Vec<ArpEntry>> = Mutex::new(Vec::new());

/// ARP opcodes.
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

/// Handle an incoming ARP packet.
pub fn handle_arp(data: &[u8]) {
    if data.len() < 28 { return; }

    let opcode = u16::from_be_bytes([data[6], data[7]]);
    let sender_mac: MacAddress = data[8..14].try_into().unwrap();
    let sender_ip: Ipv4Address = data[14..18].try_into().unwrap();
    let target_ip: Ipv4Address = data[24..28].try_into().unwrap();

    // Update ARP cache with sender info.
    update_cache(sender_ip, sender_mac);

    match opcode {
        ARP_REQUEST => {
            // If they're asking for our IP, send a reply.
            if target_ip == our_ip() {
                send_reply(sender_mac, sender_ip);
            }
        }
        ARP_REPLY => {
            // Already cached above.
            crate::serial_println!("[ARP] Reply: {}.{}.{}.{} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
                sender_mac[0], sender_mac[1], sender_mac[2],
                sender_mac[3], sender_mac[4], sender_mac[5]);
        }
        _ => {}
    }
}

/// Send an ARP reply.
fn send_reply(target_mac: MacAddress, target_ip: Ipv4Address) {
    let mut arp = [0u8; 28];
    // Hardware type: Ethernet (1)
    arp[0..2].copy_from_slice(&1u16.to_be_bytes());
    // Protocol type: IPv4 (0x0800)
    arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    // Hardware size, Protocol size
    arp[4] = 6;
    arp[5] = 4;
    // Opcode: Reply (2)
    arp[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes());
    // Sender MAC + IP
    arp[8..14].copy_from_slice(&our_mac());
    arp[14..18].copy_from_slice(&our_ip());
    // Target MAC + IP
    arp[18..24].copy_from_slice(&target_mac);
    arp[24..28].copy_from_slice(&target_ip);

    let frame = build_frame(target_mac, ETHERTYPE_ARP, &arp);
    super::send_frame(&frame);
}

/// Update the ARP cache.
fn update_cache(ip: Ipv4Address, mac: MacAddress) {
    let mut cache = ARP_CACHE.lock();
    if let Some(entry) = cache.iter_mut().find(|e| e.ip == ip) {
        entry.mac = mac;
    } else {
        cache.push(ArpEntry { ip, mac });
    }
}

/// Look up a MAC address in the ARP cache.
pub fn lookup(ip: Ipv4Address) -> Option<MacAddress> {
    let cache = ARP_CACHE.lock();
    cache.iter().find(|e| e.ip == ip).map(|e| e.mac)
}

/// Dump the full ARP cache for diagnostics.
pub fn dump_cache() -> Vec<(Ipv4Address, MacAddress)> {
    let cache = ARP_CACHE.lock();
    cache.iter().map(|e| (e.ip, e.mac)).collect()
}

/// Send an ARP request for the given IP.
pub fn send_request(target_ip: Ipv4Address) {
    let mut arp = [0u8; 28];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes());
    arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    arp[8..14].copy_from_slice(&our_mac());
    arp[14..18].copy_from_slice(&our_ip());
    arp[18..24].copy_from_slice(&[0xFF; 6]); // Broadcast target MAC
    arp[24..28].copy_from_slice(&target_ip);

    let frame = build_frame([0xFF; 6], ETHERTYPE_ARP, &arp);
    super::send_frame(&frame);
}
