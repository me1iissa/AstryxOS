//! Loopback interface — RFC 1122 §3.2.1.3
//!
//! The host MUST short-circuit traffic addressed to the 127.0.0.0/8 prefix
//! (and other addresses that resolve to a local interface) inside the
//! networking stack rather than emitting it on a physical link.  Without
//! this, services that bind to `127.0.0.1` (the X11 server, D-Bus session
//! bus, anything using `localhost` as a rendezvous address) are
//! unreachable from local clients because the SLIRP / e1000 path NATs
//! every transmitted frame and discards anything destined for `127.x`.
//!
//! ## Architecture
//!
//! The IPv4 transmit path detects packets whose destination falls in
//! 127.0.0.0/8 and hands the fully-formed IP datagram to
//! [`enqueue`] instead of building an Ethernet frame.  At each
//! [`crate::net::poll()`] tick, [`poll`] drains the deferred queue and
//! re-enters the IPv4 receive demux ([`crate::net::ipv4::handle_ipv4`])
//! so the existing TCP/UDP/ICMP delivery machinery handles the packet
//! exactly as it would for any inbound datagram.  Skipping the L2 layer
//! entirely is the canonical pattern for a loopback pseudo-device — there
//! is no peer to address, so an Ethernet header would be pure overhead.
//!
//! ## Source-address rewrite
//!
//! Outgoing loopback packets must carry a source IP that also resolves to
//! the local host, otherwise the listening peer's reply would be routed
//! out the physical interface and lost.  RFC 1122 §3.2.1.3 specifies that
//! `127.0.0.1` is always implicitly assigned to every host; we therefore
//! rewrite the source field of any IPv4 datagram bound for `127.x` to the
//! destination address itself (which trivially loops back).  This is
//! sufficient for end-to-end correctness because:
//!
//! - `Ipv4Header::parse` and the L4 demux paths do **not** validate the
//!   pseudo-header / IP / TCP / UDP checksum on inbound packets, so the
//!   stale checksum produced by the original sender is harmless;
//! - TCP/UDP 4-tuple matching keys on the rewritten address consistently
//!   on both ends, so SYN-ACK and other replies route back through the
//!   loopback enqueue path.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;
use super::Ipv4Address;

/// Maximum number of IP datagrams we will buffer in the deferred RX queue
/// before dropping new packets.  Loopback traffic is consumed at every
/// `net::poll()` tick (~10 ms in test mode), so this only matters under
/// pathological burst-then-no-poll patterns.  Sized to absorb a typical
/// X11 burst (XSetWMProperties + a few RENDER calls) without spilling.
const LOOPBACK_QUEUE_CAP: usize = 256;

static LOOPBACK_QUEUE: Mutex<VecDeque<Vec<u8>>> =
    Mutex::new(VecDeque::new());

/// Per-interface counters mirrored from RFC 1213 ifTable semantics.
struct LoopStats {
    pkts_in:  u64,
    pkts_out: u64,
    bytes_in:  u64,
    bytes_out: u64,
    drops:    u64,
}

static STATS: Mutex<LoopStats> = Mutex::new(LoopStats {
    pkts_in: 0, pkts_out: 0,
    bytes_in: 0, bytes_out: 0,
    drops: 0,
});

/// True if `addr` falls within the loopback prefix `127.0.0.0/8`.
///
/// Per RFC 1122 §3.2.1.3 (g): "Internet host implementations MUST treat
/// any address in the 127.x.x.x range as if it were the host itself."
#[inline]
pub fn is_loopback_addr(addr: Ipv4Address) -> bool {
    addr[0] == 127
}

/// Enqueue an outbound IPv4 datagram for loopback delivery.
///
/// `packet` is a full IPv4 datagram (header + payload) as it would be
/// transmitted on the wire — no Ethernet header.  The packet is delivered
/// to the local IPv4 demux on the next call to [`poll`].
pub fn enqueue(packet: &[u8]) {
    let mut q = LOOPBACK_QUEUE.lock();
    if q.len() >= LOOPBACK_QUEUE_CAP {
        STATS.lock().drops += 1;
        return;
    }
    {
        let mut s = STATS.lock();
        s.pkts_out += 1;
        s.bytes_out += packet.len() as u64;
    }
    q.push_back(packet.to_vec());
}

/// Drain pending loopback packets and feed them into the IPv4 receive
/// demux.  Called from `crate::net::poll()` once per tick.
///
/// We snapshot the queue under the lock and release it before invoking
/// `ipv4::handle_ipv4` to avoid re-entering the loopback enqueue path
/// while we hold the queue lock — `handle_ipv4` may transmit a reply
/// (SYN-ACK, ICMP echo reply, etc.) that itself targets 127.x and would
/// recurse into [`enqueue`].
pub fn poll() {
    let drained: Vec<Vec<u8>> = {
        let mut q = LOOPBACK_QUEUE.lock();
        if q.is_empty() {
            return;
        }
        q.drain(..).collect()
    };
    {
        let mut s = STATS.lock();
        s.pkts_in  += drained.len() as u64;
        for p in &drained {
            s.bytes_in += p.len() as u64;
        }
    }
    for pkt in drained {
        super::ipv4::handle_ipv4(&pkt);
    }
}

/// Read the loopback statistics tuple
/// `(pkts_in, pkts_out, bytes_in, bytes_out, drops)`.
///
/// Used by the `lo` test cases and any future ifTable / `/proc/net/dev`
/// surface.
#[allow(dead_code)]
pub fn stats() -> (u64, u64, u64, u64, u64) {
    let s = STATS.lock();
    (s.pkts_in, s.pkts_out, s.bytes_in, s.bytes_out, s.drops)
}

/// Test-only helper: return the current depth of the deferred RX queue.
/// Lets the test runner assert that loopback enqueues actually went
/// through the loopback path rather than escaping out the NIC.
#[cfg(feature = "kdb")]
pub fn queue_depth() -> usize {
    LOOPBACK_QUEUE.lock().len()
}
