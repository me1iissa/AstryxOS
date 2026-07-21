//! IPv4 — Internet Protocol version 4
//!
//! Handles IPv4 packet parsing, construction, and routing.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use super::{MacAddress, Ipv4Address, our_ip, our_mac, gateway_ip, subnet_mask, send_frame};
use super::ethernet::{build_frame, ETHERTYPE_IPV4};

/// IPv4 protocol numbers.
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Count of IPv4 datagrams discarded on receive because the header
/// checksum failed verification, per RFC 791 §3.1: "If the header
/// checksum fails, the internet datagram is discarded at once by the
/// entity which detects the error."  Exposed for tests and the
/// `netstat`-style stats surface; loads/stores are Relaxed because the
/// counter has no synchronisation duty.
static IPV4_RX_BAD_CSUM: AtomicU64 = AtomicU64::new(0);

/// Read the running count of IPv4 RX header-checksum drops.
pub fn rx_bad_csum_count() -> u64 {
    IPV4_RX_BAD_CSUM.load(Ordering::Relaxed)
}

/// An IPv4 header (parsed).
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
}

impl Ipv4Header {
    /// Parse an IPv4 header from raw bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 { return None; }

        let version = data[0] >> 4;
        let ihl = data[0] & 0x0F;
        if version != 4 || ihl < 5 { return None; }

        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags = data[6] >> 5;
        let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
        let ttl = data[8];
        let protocol = data[9];
        let header_checksum = u16::from_be_bytes([data[10], data[11]]);
        let src_ip: Ipv4Address = data[12..16].try_into().unwrap();
        let dst_ip: Ipv4Address = data[16..20].try_into().unwrap();

        Some(Ipv4Header {
            version, ihl, total_length, identification, flags,
            fragment_offset, ttl, protocol, header_checksum,
            src_ip, dst_ip,
        })
    }

    /// Header length in bytes.
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }
}

/// Handle an incoming IPv4 packet.
pub fn handle_ipv4(data: &[u8]) {
    let header = match Ipv4Header::parse(data) {
        Some(h) => h,
        None => return,
    };

    // Per RFC 791 §3.1 ("Header Checksum") and RFC 1122 §3.2.1.2: the
    // 16-bit one's-complement checksum is computed over the IP header
    // only.  A receiver MUST verify and silently discard any datagram
    // whose header checksum is invalid.  The Internet-checksum identity
    // (RFC 1071 §1) lets us re-fold the header *with* the embedded
    // `header_checksum` field in place — a valid sum yields 0x0000.
    //
    // The header length is bounded by the IHL nibble (5..=15 32-bit
    // words = 20..=60 bytes); `Ipv4Header::parse` already enforced
    // ihl>=5 and a 20-byte minimum, but the full IHL-byte range may
    // extend past `data` for an attacker-truncated frame, so we clamp
    // before checksumming to avoid an out-of-bounds slice.
    let hlen = header.header_len();
    if data.len() < hlen {
        IPV4_RX_BAD_CSUM.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !verify_checksum(&data[..hlen]) {
        IPV4_RX_BAD_CSUM.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Only accept packets addressed to us, broadcast, when we have no IP
    // yet (DHCP), or destined for the loopback prefix 127.0.0.0/8 (RFC
    // 1122 §3.2.1.3 — every host implicitly owns the entire 127/8 range).
    let our = our_ip();
    if header.dst_ip != our
        && header.dst_ip != [255, 255, 255, 255]
        && our != [0, 0, 0, 0]
        && !super::loopback::is_loopback_addr(header.dst_ip)
    {
        return;
    }

    let payload_start = hlen;
    if data.len() < payload_start { return; }

    // RFC 791 §3.1: clamp the upper-layer payload to the IP datagram's
    // declared total_length so attacker-shaped Ethernet trailer bytes
    // cannot leak into ICMP / UDP / TCP parsers.  See
    // `clamp_payload_to_total_length` for the full rationale.
    let payload_end = clamp_payload_to_total_length(
        header.total_length as usize,
        payload_start,
        data.len(),
    );
    let payload = &data[payload_start..payload_end];

    match header.protocol {
        PROTO_ICMP => super::icmp::handle_icmp(header.src_ip, payload),
        PROTO_UDP => super::udp::handle_udp(header.src_ip, header.dst_ip, payload),
        PROTO_TCP => super::tcp::handle_tcp(header.src_ip, header.dst_ip, payload),
        _ => {
            crate::serial_println!("[IPv4] Unknown protocol: {}", header.protocol);
        }
    }
}

/// Compute the upper-layer payload end offset within the link-layer frame.
///
/// Per RFC 791 §3.1 ("Total Length"): "Total Length is the length of the
/// datagram, measured in octets, including internet header and data."
/// The Ethernet frame that delivered this datagram may be *larger* than
/// the IP datagram itself — Ethernet has a 46-byte minimum payload, so
/// an IP datagram smaller than 46 bytes arrives padded with arbitrary
/// trailer bytes.  Legitimately the NIC hardware zero-pads; under an
/// active on-path attacker the trailer bytes can be attacker-shaped.
///
/// Before this clamp, the payload slice handed to ICMP / UDP / TCP
/// included these trailer bytes.  ICMP and UDP did not re-clamp against
/// `total_length` themselves, so the trailer bytes were interpreted as
/// part of the datagram payload — an unbounded attacker-controlled
/// appendix to every accepted IPv4 packet, useful for fingerprinting
/// the host, smuggling bytes past length-aware checksum comparisons,
/// or fooling downstream parsers that scan past the documented end.
/// TCP's `handle_tcp` already uses `hdr.header_len().min(data.len())`
/// as a defence-in-depth clamp, so it was largely insulated; clamping
/// here ensures the upper layer sees identical bytes regardless of
/// protocol.
///
/// Returns the byte offset (within `data`) where the upper-layer
/// payload ends.  The slice `[payload_start..end]` is what should be
/// handed to the per-protocol handler.
///
/// Edge cases:
///  * `total_length < payload_start` (attacker-faked tiny total_length):
///    return `payload_start` (empty payload, no panic from wrapping
///    subtraction).
///  * `total_length > data.len()` (caller-truncated frame): return
///    `data.len()` (cannot read past the buffer end).
#[inline]
pub(crate) fn clamp_payload_to_total_length(
    total_length: usize,
    payload_start: usize,
    frame_len: usize,
) -> usize {
    // First clamp against the frame size — never read past the buffer.
    let end = total_length.min(frame_len);
    // Then clamp from below — never produce an end < payload_start that
    // would underflow the subsequent slice subtraction.
    if end < payload_start { payload_start } else { end }
}

/// Verify a buffer's embedded 16-bit Internet checksum (RFC 1071).
///
/// `data` must include the checksum field at the position the protocol
/// specifies (e.g. for an IPv4 header that is bytes 10..12).  Because
/// the checksum is the one's-complement of the one's-complement sum of
/// the buffer, re-summing the *whole* buffer (with the checksum field
/// in place) yields zero exactly when the embedded checksum is valid.
/// Returns `true` for "valid", `false` for "mismatch".
///
/// For UDP (RFC 768) and TCP (RFC 793 §3.1) this same helper is used
/// after the caller has prepended the IP pseudo-header.
#[inline]
pub fn verify_checksum(data: &[u8]) -> bool {
    checksum(data) == 0
}

/// Calculate the Internet Checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build and send an IPv4 packet with a custom source IP and destination MAC.
/// Used by DHCP (source 0.0.0.0, broadcast MAC).
pub fn send_ipv4_from(src_ip: Ipv4Address, dst_ip: Ipv4Address, dst_mac: MacAddress, protocol: u8, payload: &[u8]) {
    let total_length = 20 + payload.len();
    let mut packet = Vec::with_capacity(total_length);

    // Per RFC 1122 §3.2.1.3, the loopback prefix never reaches the link
    // layer — short-circuit it through the loopback pseudo-device even
    // when a caller has supplied an explicit source address.  A non-127
    // src_ip here would route the eventual reply out the physical NIC,
    // so reflect the loopback dst into the source field.
    let effective_src = if super::loopback::is_loopback_addr(dst_ip) { dst_ip } else { src_ip };

    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    static ID2: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0x8000);
    let id = ID2.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x4000u16.to_be_bytes());
    packet.push(64);
    packet.push(protocol);
    packet.push(0);
    packet.push(0);
    packet.extend_from_slice(&effective_src);
    packet.extend_from_slice(&dst_ip);

    let cksum = checksum(&packet[..20]);
    packet[10] = (cksum >> 8) as u8;
    packet[11] = (cksum & 0xFF) as u8;

    packet.extend_from_slice(payload);

    if super::loopback::is_loopback_addr(dst_ip) {
        super::loopback::enqueue(&packet);
        return;
    }

    let frame = build_frame(dst_mac, ETHERTYPE_IPV4, &packet);
    send_frame(&frame);
}

/// Build and send an IPv4 packet.
pub fn send_ipv4(dst_ip: Ipv4Address, protocol: u8, payload: &[u8]) {
    let total_length = 20 + payload.len();
    let mut packet = Vec::with_capacity(total_length);

    // Loopback short-circuit (RFC 1122 §3.2.1.3): packets destined for
    // 127.0.0.0/8 must never escape onto the link.  Reflect the dst into
    // the source field so the receiver's reply also addresses 127.x and
    // re-enters the loopback pseudo-device — without this rewrite the
    // peer would direct its reply to our globally-routable address and
    // the SYN-ACK / ACK / data segments would be lost.
    let src_ip = if super::loopback::is_loopback_addr(dst_ip) {
        dst_ip
    } else {
        our_ip()
    };

    // Version + IHL
    packet.push(0x45);
    // DSCP + ECN
    packet.push(0x00);
    // Total length
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    // Identification
    static ID: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(1);
    let id = ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    packet.extend_from_slice(&id.to_be_bytes());
    // Flags + Fragment offset (Don't Fragment)
    packet.extend_from_slice(&0x4000u16.to_be_bytes());
    // TTL
    packet.push(64);
    // Protocol
    packet.push(protocol);
    // Header checksum (placeholder)
    packet.push(0);
    packet.push(0);
    // Source IP
    packet.extend_from_slice(&src_ip);
    // Destination IP
    packet.extend_from_slice(&dst_ip);

    // Calculate header checksum.
    let cksum = checksum(&packet[..20]);
    packet[10] = (cksum >> 8) as u8;
    packet[11] = (cksum & 0xFF) as u8;

    // Payload
    packet.extend_from_slice(payload);

    if super::loopback::is_loopback_addr(dst_ip) {
        super::loopback::enqueue(&packet);
        return;
    }

    // Determine destination MAC.
    let dst_mac = resolve_mac(dst_ip);

    let frame = build_frame(dst_mac, ETHERTYPE_IPV4, &packet);
    send_frame(&frame);
}

/// Resolve a MAC address for a given IP. Uses ARP cache or gateway.
/// If not cached, sends an ARP request and polls for up to ~500ms.
fn resolve_mac(dst_ip: Ipv4Address) -> MacAddress {
    let mask = subnet_mask();
    let our = our_ip();

    // If same subnet, look up directly; else use gateway.
    let next_hop = if ip_and(dst_ip, mask) == ip_and(our, mask) {
        dst_ip
    } else {
        gateway_ip()
    };

    // Check ARP cache.
    if let Some(mac) = super::arp::lookup(next_hop) {
        return mac;
    }

    // Send ARP request and poll for a reply.
    for _attempt in 0..3 {
        super::arp::send_request(next_hop);

        // Poll for ~170 ms per attempt (17 ticks at 100 Hz)
        let start = crate::arch::x86_64::irq::get_ticks();
        let deadline = start + 17;
        loop {
            super::poll();

            if let Some(mac) = super::arp::lookup(next_hop) {
                return mac;
            }

            let now = crate::arch::x86_64::irq::get_ticks();
            if now >= deadline { break; }

            // Spin, not halt: the LAPIC periodic timer is this loop's only
            // no-reply wake and can stop under a wedged hypervisor (Intel SDM
            // Vol.3A Sec.10.5.4); TSC-floor `get_ticks()` keeps advancing
            // regardless, so spinning still re-checks `deadline` and exits.
            core::hint::spin_loop();
        }
    }

    // Fallback: broadcast (last resort)
    crate::serial_println!("[IPv4] ARP resolution failed for {}.{}.{}.{}, using broadcast",
        next_hop[0], next_hop[1], next_hop[2], next_hop[3]);
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
}

/// Bitwise AND of IP and mask.
fn ip_and(ip: Ipv4Address, mask: Ipv4Address) -> Ipv4Address {
    [ip[0] & mask[0], ip[1] & mask[1], ip[2] & mask[2], ip[3] & mask[3]]
}
