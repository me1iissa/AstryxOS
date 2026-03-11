//! DNS — Domain Name System Resolver
//!
//! A stub DNS resolver over UDP. Builds DNS query packets, sends them to a
//! configurable nameserver, and parses A record responses.
//!
//! Default nameserver: 10.0.2.3 (QEMU SLIRP DNS forwarder).

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use super::Ipv4Address;

/// DNS server address (QEMU SLIRP default: 10.0.2.3).
static DNS_SERVER: Mutex<Ipv4Address> = Mutex::new([10, 0, 2, 3]);

/// DNS client port range.
static DNS_NEXT_PORT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(50000);

/// DNS record types.
const TYPE_A: u16 = 1;       // IPv4 address
const TYPE_CNAME: u16 = 5;   // Canonical name
const TYPE_AAAA: u16 = 28;   // IPv6 address

/// DNS classes.
const CLASS_IN: u16 = 1;     // Internet

/// Get current nameserver.
pub fn get_nameserver() -> Ipv4Address {
    *DNS_SERVER.lock()
}

/// Set the DNS nameserver.
pub fn set_nameserver(ip: Ipv4Address) {
    *DNS_SERVER.lock() = ip;
}

/// Resolve a hostname to an IPv4 address.
///
/// Returns `Some([a, b, c, d])` on success, `None` on failure (timeout/NXDOMAIN).
/// Uses UDP port 53, with a 3-second timeout and 2 retries.
pub fn resolve(hostname: &str) -> Option<Ipv4Address> {
    let dns_server = get_nameserver();
    let src_port = DNS_NEXT_PORT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Bind a local UDP port for the response
    if super::udp::bind(src_port).is_err() {
        crate::serial_println!("[DNS] Failed to bind port {}", src_port);
        return None;
    }

    // Build the DNS query
    let tx_id: u16 = (crate::arch::x86_64::irq::get_ticks() & 0xFFFF) as u16;
    let query = build_query(tx_id, hostname);

    let mut result = None;

    for attempt in 0..3 {
        crate::serial_println!("[DNS] Query #{} for '{}' via {}.{}.{}.{} (txid={:#06x})",
            attempt + 1, hostname,
            dns_server[0], dns_server[1], dns_server[2], dns_server[3], tx_id);

        // Send query
        super::udp::send(dns_server, src_port, 53, &query);

        // Wait for response (~3 seconds via bounded busy-spin, ~1M iterations at ~3ns each).
        // We avoid hal::halt() here because on the AP (CPU 1) the APIC timer may not
        // fire reliably, causing hlt to block indefinitely.
        for _ in 0..1_000_000u32 {
            crate::net::poll();

            if let Some(dgram) = super::udp::recv(src_port) {
                if let Some(ip) = parse_response(&dgram.data, tx_id) {
                    result = Some(ip);
                    break;
                }
            }

            for _ in 0..200u32 { core::hint::spin_loop(); }
        }

        if result.is_some() { break; }
    }

    super::udp::unbind(src_port);
    result
}

/// Build a DNS query packet for an A record.
fn build_query(tx_id: u16, hostname: &str) -> Vec<u8> {
    build_query_type(tx_id, hostname, TYPE_A)
}

/// Build a DNS query packet for a specific record type.
fn build_query_type(tx_id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // Header (12 bytes)
    pkt.extend_from_slice(&tx_id.to_be_bytes());   // Transaction ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query, recursion desired
    pkt.extend_from_slice(&1u16.to_be_bytes());     // QDCOUNT: 1 question
    pkt.extend_from_slice(&0u16.to_be_bytes());     // ANCOUNT: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());     // NSCOUNT: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());     // ARCOUNT: 0

    // Question section: encode hostname as DNS name
    for label in hostname.split('.') {
        let len = label.len().min(63) as u8;
        pkt.push(len);
        pkt.extend_from_slice(&label.as_bytes()[..len as usize]);
    }
    pkt.push(0); // Root label (end of name)

    // Type: specified record type
    pkt.extend_from_slice(&qtype.to_be_bytes());
    // Class: IN (Internet)
    pkt.extend_from_slice(&CLASS_IN.to_be_bytes());

    pkt
}

/// Parse a DNS response and extract the first A record.
fn parse_response(data: &[u8], expected_id: u16) -> Option<Ipv4Address> {
    if data.len() < 12 { return None; }

    // Verify transaction ID
    let tx_id = u16::from_be_bytes([data[0], data[1]]);
    if tx_id != expected_id { return None; }

    // Check flags: must be a response (bit 15), and RCODE == 0 (no error)
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 { return None; } // Not a response
    let rcode = flags & 0x000F;
    if rcode != 0 {
        crate::serial_println!("[DNS] Response error: RCODE={}", rcode);
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if ancount == 0 { return None; }

    // Skip question section
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset)?;
        offset += 4; // QTYPE + QCLASS
        if offset > data.len() { return None; }
    }

    // Parse answer section — look for first A record
    for _ in 0..ancount {
        if offset >= data.len() { break; }

        // Skip name (may be compressed pointer)
        offset = skip_dns_name(data, offset)?;

        if offset + 10 > data.len() { break; }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let _ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5],
                                       data[offset + 6], data[offset + 7]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if rtype == TYPE_A && rdlength == 4 && offset + 4 <= data.len() {
            let ip: Ipv4Address = [data[offset], data[offset + 1],
                                   data[offset + 2], data[offset + 3]];
            crate::serial_println!("[DNS] Resolved to {}.{}.{}.{}",
                ip[0], ip[1], ip[2], ip[3]);
            return Some(ip);
        }

        // Skip RDATA for non-A records (e.g., CNAME)
        offset += rdlength;
    }

    None
}

/// Skip a DNS name in the packet (handles compression pointers).
/// Returns the new offset after the name.
fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    let mut jumped = false;
    let mut result_offset = 0usize;

    loop {
        if offset >= data.len() { return None; }
        let len = data[offset] as usize;

        if len == 0 {
            offset += 1;
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes)
            if !jumped {
                result_offset = offset + 2;
            }
            if offset + 1 >= data.len() { return None; }
            let ptr = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            offset = ptr;
            jumped = true;
            continue;
        }

        offset += 1 + len;
    }

    Some(if jumped { result_offset } else { offset })
}

/// Resolve a hostname to an IPv6 address (AAAA record).
///
/// Sends the DNS query over IPv4 UDP (same DNS forwarder) but asks for
/// TYPE_AAAA.  Returns `Some([u8; 16])` on success, `None` on failure.
pub fn resolve_ipv6(hostname: &str) -> Option<super::Ipv6Address> {
    let dns_server = get_nameserver();
    let src_port = DNS_NEXT_PORT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    if super::udp::bind(src_port).is_err() {
        crate::serial_println!("[DNS] Failed to bind port {}", src_port);
        return None;
    }

    let tx_id: u16 = (crate::arch::x86_64::irq::get_ticks() & 0xFFFF) as u16;
    let query = build_query_type(tx_id, hostname, TYPE_AAAA);

    let mut result = None;

    for attempt in 0..3 {
        crate::serial_println!("[DNS] AAAA query #{} for '{}' via {}.{}.{}.{} (txid={:#06x})",
            attempt + 1, hostname,
            dns_server[0], dns_server[1], dns_server[2], dns_server[3], tx_id);

        super::udp::send(dns_server, src_port, 53, &query);

        for _ in 0..1_000_000u32 {
            crate::net::poll();

            if let Some(dgram) = super::udp::recv(src_port) {
                if let Some(ip6) = parse_response_aaaa(&dgram.data, tx_id) {
                    result = Some(ip6);
                    break;
                }
            }

            for _ in 0..200u32 { core::hint::spin_loop(); }
        }

        if result.is_some() { break; }
    }

    super::udp::unbind(src_port);
    result
}

/// Parse a DNS response and extract the first AAAA record (IPv6 address).
fn parse_response_aaaa(data: &[u8], expected_id: u16) -> Option<super::Ipv6Address> {
    if data.len() < 12 { return None; }

    let tx_id = u16::from_be_bytes([data[0], data[1]]);
    if tx_id != expected_id { return None; }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 { return None; }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        crate::serial_println!("[DNS] AAAA response error: RCODE={}", rcode);
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if ancount == 0 { return None; }

    // Skip question section
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset)?;
        offset += 4; // QTYPE + QCLASS
        if offset > data.len() { return None; }
    }

    // Parse answer section — look for first AAAA record
    for _ in 0..ancount {
        if offset >= data.len() { break; }

        offset = skip_dns_name(data, offset)?;

        if offset + 10 > data.len() { break; }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let _ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5],
                                       data[offset + 6], data[offset + 7]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if rtype == TYPE_AAAA && rdlength == 16 && offset + 16 <= data.len() {
            let mut ip6: super::Ipv6Address = [0u8; 16];
            ip6.copy_from_slice(&data[offset..offset + 16]);
            crate::serial_println!("[DNS] AAAA resolved to {}", crate::net::format_ipv6(ip6));
            return Some(ip6);
        }

        // Skip RDATA for non-AAAA records (e.g., CNAME)
        offset += rdlength;
    }

    None
}
