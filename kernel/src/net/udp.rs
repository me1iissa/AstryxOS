//! UDP — User Datagram Protocol
//!
//! Connectionless datagram transport.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use super::{Ipv4Address, our_ip};
use super::ipv4;

/// Count of UDP datagrams discarded on receive because the checksum
/// field was non-zero and did not validate, per RFC 1122 §4.1.3.4:
/// "If a UDP datagram is received with a checksum that is non-zero and
/// invalid, UDP MUST silently discard the datagram."  Exposed for
/// tests and the stats surface.  Loads/stores are Relaxed — the
/// counter has no synchronisation duty.
static UDP_RX_BAD_CSUM: AtomicU64 = AtomicU64::new(0);

/// Count of UDP datagrams discarded on receive because the bound port's
/// receive buffer was full.  UDP is an unreliable datagram service
/// (RFC 768) — when the application cannot drain fast enough, the
/// receiver sheds load by dropping rather than growing without bound.
/// The cap mirrors the POSIX `SO_RCVBUF` limit (`setsockopt(2)`); the
/// Linux `net.core.rmem_default` sysctl documents the conventional
/// default we adopt (see `DEFAULT_RCVBUF_BYTES`).  An unbounded queue
/// is a denial-of-service vector: a QUIC (RFC 9000) flood over UDP/443
/// would otherwise grow the kernel heap until OOM, or stall the drain.
/// Relaxed — the counter has no synchronisation duty.
static UDP_RX_OVERFLOW: AtomicU64 = AtomicU64::new(0);

/// Default per-binding receive-buffer byte cap, applied when no
/// `SO_RCVBUF` has been set on the owning socket.  212992 bytes matches
/// the conventional `net.core.rmem_default` value so resolvers and QUIC
/// stacks observe the same backpressure point they would on a stock
/// Unix host.  The cap accounts queued payload bytes only.
pub const DEFAULT_RCVBUF_BYTES: usize = 212_992;

/// Read the running count of UDP RX checksum drops.
pub fn rx_bad_csum_count() -> u64 {
    UDP_RX_BAD_CSUM.load(Ordering::Relaxed)
}

/// Read the running count of UDP RX drops caused by a full receive
/// buffer (`SO_RCVBUF` / `net.core.rmem_default` overflow).
pub fn rx_overflow_count() -> u64 {
    UDP_RX_OVERFLOW.load(Ordering::Relaxed)
}

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
///
/// `queue` is a `VecDeque` so the consumer drains from the front in O(1)
/// (`pop_front`) — a plain `Vec` with `remove(0)` is O(n) per dequeue,
/// which degrades to O(n²) drain under a sustained datagram flood and
/// lets the fill rate outrun the consumer.  `queued_bytes` tracks the
/// total payload bytes currently queued so the `rcvbuf_bytes` cap can be
/// enforced in O(1) on every `handle_udp` push, per RFC 768's
/// unreliable-delivery contract (tail-drop on overflow).
struct UdpBinding {
    port: u16,
    queue: VecDeque<UdpDatagram>,
    /// Sum of `data.len()` over all queued datagrams.
    queued_bytes: usize,
    /// Receive-buffer byte cap for this binding.  Set from the owning
    /// socket's `SO_RCVBUF` (`set_rcvbuf`); defaults to
    /// `DEFAULT_RCVBUF_BYTES`.
    rcvbuf_bytes: usize,
}

/// Bound UDP ports.
static UDP_BINDINGS: Mutex<Vec<UdpBinding>> = Mutex::new(Vec::new());

/// Handle an incoming UDP packet.
pub fn handle_udp(src_ip: Ipv4Address, dst_ip: Ipv4Address, data: &[u8]) {
    let header = match UdpHeader::parse(data) {
        Some(h) => h,
        None => return,
    };

    // RFC 768 §"Length": UDP header `Length` field counts the header
    // and payload combined.  Clamp the datagram to the declared length
    // so a frame whose IP `total_length` overshoots cannot leak trailer
    // bytes into our checksum or into the receive queue.  An undersized
    // declaration (length < 8) is an attacker-crafted header — drop.
    let udp_len = header.length as usize;
    if udp_len < 8 || udp_len > data.len() {
        UDP_RX_BAD_CSUM.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let datagram = &data[..udp_len];

    // RFC 768 + RFC 1122 §4.1.3.4: a transmitted checksum of 0x0000
    // means "checksum disabled by sender" — the receiver MUST NOT
    // validate.  A non-zero checksum that fails validation MUST cause
    // the datagram to be silently discarded.  The validation runs over
    // an IPv4 pseudo-header (src_ip || dst_ip || 0 || proto || udp_len)
    // followed by the UDP header and payload with the checksum field
    // in place, per the Internet-checksum identity (RFC 1071).
    if header.checksum != 0 && !verify_udp_checksum(src_ip, dst_ip, datagram) {
        UDP_RX_BAD_CSUM.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let payload = &datagram[8..];

    crate::serial_println!("[UDP] {}:{} -> port {} ({} bytes)",
        src_ip[0], src_ip[1],
        header.dst_port, payload.len());

    // Deliver to bound port.
    //
    // RFC 768 makes no delivery guarantee: when the bound port's receive
    // buffer is full we DROP the datagram rather than grow the queue
    // without bound.  We tail-drop (discard the just-arrived datagram,
    // the newest) because it is the cheapest RFC-768-faithful choice and
    // preserves the in-order datagrams already queued for the consumer.
    // A connectionless flood — e.g. a QUIC (RFC 9000) transfer over
    // UDP/443 whose congestion control will retransmit the lost
    // datagrams — must never be able to exhaust the kernel heap.  We
    // always admit at least one datagram into an empty queue so a
    // pathologically small `SO_RCVBUF` cannot wedge the socket entirely.
    let mut bindings = UDP_BINDINGS.lock();
    let delivered = if let Some(binding) = bindings.iter_mut().find(|b| b.port == header.dst_port) {
        let incoming = payload.len();
        let would_be = binding.queued_bytes.saturating_add(incoming);
        if would_be > binding.rcvbuf_bytes && !binding.queue.is_empty() {
            // Receive buffer full — shed load (tail-drop newest).
            UDP_RX_OVERFLOW.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            binding.queue.push_back(UdpDatagram {
                src_ip,
                src_port: header.src_port,
                data: Vec::from(payload),
            });
            binding.queued_bytes = would_be;
            true
        }
    } else {
        false
    };
    drop(bindings);

    // Wake any thread parked in `poll(2)` / `epoll_wait(2)` /
    // `select(2)` on a fd backed by this UDP socket.  Without this
    // ring, userspace pollers observe the new datagram only on the
    // 1 s resync floor in `wait_poll_event` — RFC 1035 §4.2.1 DNS
    // resolvers expect sub-second wake latency and otherwise report
    // ";; connection timed out; no servers could be reached" even
    // when the reply has already landed in the binding queue.
    if delivered {
        crate::ipc::waitlist::ring_poll_bell_for(
            crate::ipc::waitlist::PollBellSource::InetRx);
    }
}

/// Verify a UDP datagram's checksum using the IPv4 pseudo-header per
/// RFC 768 + RFC 1122 §4.1.3.4.  `datagram` is the UDP header followed
/// by the payload, exactly `header.length` bytes, with the embedded
/// checksum field still in place.  Returns true when valid.
fn verify_udp_checksum(src_ip: Ipv4Address, dst_ip: Ipv4Address, datagram: &[u8]) -> bool {
    let mut buf = Vec::with_capacity(12 + datagram.len());
    buf.extend_from_slice(&src_ip);
    buf.extend_from_slice(&dst_ip);
    buf.push(0);
    buf.push(ipv4::PROTO_UDP);
    buf.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
    buf.extend_from_slice(datagram);
    ipv4::verify_checksum(&buf)
}

/// Bind a UDP port for receiving.
pub fn bind(port: u16) -> Result<(), &'static str> {
    let mut bindings = UDP_BINDINGS.lock();
    if bindings.iter().any(|b| b.port == port) {
        return Err("port already bound");
    }
    bindings.push(UdpBinding {
        port,
        queue: VecDeque::new(),
        queued_bytes: 0,
        rcvbuf_bytes: DEFAULT_RCVBUF_BYTES,
    });
    Ok(())
}

/// Set the receive-buffer byte cap for a bound port from its owning
/// socket's `SO_RCVBUF` (`setsockopt(2)`).  A zero argument restores the
/// `net.core.rmem_default` baseline; the cap is clamped to at least one
/// MTU-sized datagram so a tiny request cannot make the socket undeliverable.
/// No-op when the port is not (yet) bound.
pub fn set_rcvbuf(port: u16, bytes: usize) {
    let effective = if bytes == 0 { DEFAULT_RCVBUF_BYTES } else { bytes };
    let effective = effective.max(2048);
    let mut bindings = UDP_BINDINGS.lock();
    if let Some(binding) = bindings.iter_mut().find(|b| b.port == port) {
        binding.rcvbuf_bytes = effective;
    }
}

/// Receive a datagram from a bound port (non-blocking).
pub fn recv(port: u16) -> Option<UdpDatagram> {
    let mut bindings = UDP_BINDINGS.lock();
    if let Some(binding) = bindings.iter_mut().find(|b| b.port == port) {
        if let Some(dg) = binding.queue.pop_front() {
            binding.queued_bytes = binding.queued_bytes.saturating_sub(dg.data.len());
            return Some(dg);
        }
    }
    None
}

/// Check if a UDP port has datagrams queued (non-destructive).
pub fn has_data(port: u16) -> bool {
    let bindings = UDP_BINDINGS.lock();
    bindings.iter().any(|b| b.port == port && !b.queue.is_empty())
}

/// Returns true if `port` already has a UDP binding.  Used by the
/// ephemeral-port allocator to probe for collisions.
pub fn is_bound(port: u16) -> bool {
    let bindings = UDP_BINDINGS.lock();
    bindings.iter().any(|b| b.port == port)
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

    // The UDP pseudo-header carries the IPv4 source address.  Match the
    // address the IPv4 layer will *actually* place in the outbound
    // header — `ipv4::send_ipv4` reflects loopback destinations into the
    // source field (RFC 1122 §3.2.1.3) so a packet sent to 127.x bears
    // src=127.x, not our globally-routable address.  Without this
    // mirroring the receive-side RFC 1122 §4.1.3.4 checksum check would
    // fail every loopback UDP datagram.
    let src_for_pseudo = if super::loopback::is_loopback_addr(dst_ip) {
        dst_ip
    } else {
        our_ip()
    };
    let cksum = udp_checksum(src_for_pseudo, dst_ip, &packet);
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
