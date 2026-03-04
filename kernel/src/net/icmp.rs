//! ICMP — Internet Control Message Protocol
//!
//! Handles ICMP echo request/reply (ping).

use super::Ipv4Address;
use super::ipv4;
use spin::Mutex;
use core::sync::atomic::{AtomicBool, Ordering};

/// ICMP types.
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;

/// Last received ping reply info (for the shell to read).
pub struct PingReply {
    pub src_ip: Ipv4Address,
    pub id: u16,
    pub seq: u16,
    pub data_len: usize,
}

static LAST_REPLY: Mutex<Option<PingReply>> = Mutex::new(None);
static REPLY_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Check if a ping reply has been received and take it.
pub fn take_reply() -> Option<PingReply> {
    if REPLY_RECEIVED.swap(false, Ordering::AcqRel) {
        LAST_REPLY.lock().take()
    } else {
        None
    }
}

/// Handle an incoming ICMP packet.
pub fn handle_icmp(src_ip: Ipv4Address, data: &[u8]) {
    if data.len() < 8 { return; }

    let icmp_type = data[0];
    let _icmp_code = data[1];

    match icmp_type {
        ICMP_ECHO_REQUEST => {
            crate::serial_println!("[ICMP] Echo request from {}.{}.{}.{}",
                src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
            send_echo_reply(src_ip, data);
        }
        ICMP_ECHO_REPLY => {
            let id = u16::from_be_bytes([data[4], data[5]]);
            let seq = u16::from_be_bytes([data[6], data[7]]);
            crate::serial_println!("[ICMP] Echo reply from {}.{}.{}.{} id={} seq={}",
                src_ip[0], src_ip[1], src_ip[2], src_ip[3], id, seq);
            // Store for the shell ping command
            *LAST_REPLY.lock() = Some(PingReply {
                src_ip,
                id,
                seq,
                data_len: data.len(),
            });
            REPLY_RECEIVED.store(true, Ordering::Release);
        }
        _ => {
            crate::serial_println!("[ICMP] Type {} from {}.{}.{}.{}",
                icmp_type, src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        }
    }
}

/// Send an ICMP echo reply.
fn send_echo_reply(dst_ip: Ipv4Address, request: &[u8]) {
    extern crate alloc;
    use alloc::vec::Vec;

    let mut reply = Vec::from(request);
    reply[0] = ICMP_ECHO_REPLY;
    reply[1] = 0; // Code

    // Zero checksum field before calculating.
    reply[2] = 0;
    reply[3] = 0;
    let cksum = ipv4::checksum(&reply);
    reply[2] = (cksum >> 8) as u8;
    reply[3] = (cksum & 0xFF) as u8;

    ipv4::send_ipv4(dst_ip, ipv4::PROTO_ICMP, &reply);
}

/// Send an ICMP echo request (ping).
pub fn send_ping(dst_ip: Ipv4Address, id: u16, seq: u16) {
    extern crate alloc;
    use alloc::vec::Vec;

    let mut icmp = Vec::with_capacity(64);
    icmp.push(ICMP_ECHO_REQUEST);
    icmp.push(0); // Code
    icmp.push(0); // Checksum placeholder
    icmp.push(0);
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());

    // 56 bytes of payload (standard ping).
    for i in 0..56u8 {
        icmp.push(i);
    }

    // Calculate checksum.
    let cksum = ipv4::checksum(&icmp);
    icmp[2] = (cksum >> 8) as u8;
    icmp[3] = (cksum & 0xFF) as u8;

    ipv4::send_ipv4(dst_ip, ipv4::PROTO_ICMP, &icmp);
}
