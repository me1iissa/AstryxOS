//! ICMPv6 — Internet Control Message Protocol for IPv6
//!
//! Handles ICMPv6 echo request/reply (ping6).
//! Checksum uses the IPv6 pseudo-header per RFC 2460 §8.1.

use super::Ipv6Address;
use super::ipv6;
use spin::Mutex;
use core::sync::atomic::{AtomicBool, Ordering};

/// ICMPv6 type numbers.
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Last received ICMPv6 echo reply.
pub struct Ping6Reply {
    pub src_addr: Ipv6Address,
    pub id: u16,
    pub seq: u16,
    pub data_len: usize,
}

static LAST_REPLY: Mutex<Option<Ping6Reply>> = Mutex::new(None);
static REPLY_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Take the last received ping6 reply (non-blocking).
pub fn take_reply() -> Option<Ping6Reply> {
    if REPLY_RECEIVED.swap(false, Ordering::AcqRel) {
        LAST_REPLY.lock().take()
    } else {
        None
    }
}

/// Handle an incoming ICMPv6 packet.
pub fn handle_icmpv6(src_addr: Ipv6Address, dst_addr: Ipv6Address, data: &[u8]) {
    if data.len() < 4 { return; }

    let icmp_type = data[0];
    let _icmp_code = data[1];
    // Checksum at data[2..4] — we trust the network stack for now.

    match icmp_type {
        ICMPV6_ECHO_REQUEST => {
            crate::serial_println!("[ICMPv6] Echo request from {:x?}", &src_addr[..]);
            send_echo_reply(src_addr, dst_addr, data);
        }
        ICMPV6_ECHO_REPLY => {
            if data.len() < 8 { return; }
            let id = u16::from_be_bytes([data[4], data[5]]);
            let seq = u16::from_be_bytes([data[6], data[7]]);
            crate::serial_println!("[ICMPv6] Echo reply from {:x?} id={} seq={}",
                &src_addr[..], id, seq);

            *LAST_REPLY.lock() = Some(Ping6Reply {
                src_addr,
                id,
                seq,
                data_len: data.len(),
            });
            REPLY_RECEIVED.store(true, Ordering::Release);
        }
        133..=137 => {
            // NDP messages: Router Solicitation (133), Router Advertisement (134),
            // Neighbor Solicitation (135), Neighbor Advertisement (136), Redirect (137)
            crate::serial_println!("[ICMPv6] NDP type {} (ignored)", icmp_type);
        }
        _ => {
            crate::serial_println!("[ICMPv6] Type {} (ignored)", icmp_type);
        }
    }
}

/// Send an ICMPv6 echo reply.
fn send_echo_reply(dst_addr: Ipv6Address, _original_dst: Ipv6Address, request: &[u8]) {
    extern crate alloc;
    use alloc::vec::Vec;

    let src_addr = super::our_ipv6();

    let mut reply = Vec::from(request);
    reply[0] = ICMPV6_ECHO_REPLY;
    reply[1] = 0; // Code

    // Zero checksum field before calculating
    reply[2] = 0;
    reply[3] = 0;

    let cksum = ipv6::ipv6_pseudo_checksum(&src_addr, &dst_addr, ipv6::PROTO_ICMPV6, &reply);
    reply[2] = (cksum >> 8) as u8;
    reply[3] = (cksum & 0xFF) as u8;

    ipv6::send_ipv6(dst_addr, ipv6::PROTO_ICMPV6, &reply);
}

/// Send an ICMPv6 echo request (ping6).
pub fn send_ping6(dst_addr: Ipv6Address, id: u16, seq: u16) {
    extern crate alloc;
    use alloc::vec::Vec;

    let src_addr = super::our_ipv6();

    let mut icmp = Vec::with_capacity(64);
    icmp.push(ICMPV6_ECHO_REQUEST);
    icmp.push(0); // Code
    icmp.push(0); // Checksum placeholder
    icmp.push(0);
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());

    // 56 bytes of payload (standard ping)
    for i in 0..56u8 {
        icmp.push(i);
    }

    // Calculate checksum with IPv6 pseudo-header
    let cksum = ipv6::ipv6_pseudo_checksum(&src_addr, &dst_addr, ipv6::PROTO_ICMPV6, &icmp);
    icmp[2] = (cksum >> 8) as u8;
    icmp[3] = (cksum & 0xFF) as u8;

    ipv6::send_ipv6(dst_addr, ipv6::PROTO_ICMPV6, &icmp);
}
