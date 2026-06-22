//! ARP — Address Resolution Protocol
//!
//! Maps IPv4 addresses to MAC addresses on the local network.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use super::{MacAddress, Ipv4Address, our_mac, our_ip};
use super::ethernet::{build_frame, ETHERTYPE_ARP};

/// Maximum number of resolved IPv4→MAC mappings the cache will hold.
///
/// RFC 826 does not mandate a cache size; an unbounded cache lets a host that
/// emits ARP traffic from many distinct (e.g. spoofed) source addresses grow
/// the table without limit and exhaust kernel memory.  We therefore bound the
/// table: once it is full a new mapping evicts the *least recently refreshed*
/// entry, which is also the one most likely to already be stale.
const ARP_CACHE_MAX: usize = 256;

/// Time-to-live for a resolved entry, in timer ticks (~100 Hz → 10 ms/tick),
/// i.e. 60 seconds.  RFC 826 leaves expiry to the implementation; common
/// practice ages an entry out of the resolved (reachable) state on the order
/// of tens of seconds to a few minutes so that a stale mapping cannot keep
/// routing frames to a host that has since changed its NIC / MAC.  A lookup
/// that finds only an expired entry behaves as a miss, triggering a fresh
/// resolution.
const ARP_CACHE_TTL_TICKS: u64 = 6_000;

/// ARP cache entry.
struct ArpEntry {
    ip: Ipv4Address,
    mac: MacAddress,
    /// Monotonic tick at which this mapping was last learned or refreshed.
    last_seen: u64,
}

/// ARP cache.
static ARP_CACHE: Mutex<Vec<ArpEntry>> = Mutex::new(Vec::new());

/// Monotonic tick source used to stamp and age cache entries.
fn now_ticks() -> u64 {
    crate::arch::x86_64::irq::get_ticks()
}

/// True if `entry` is older than the TTL relative to `now`.
fn is_expired(entry: &ArpEntry, now: u64) -> bool {
    now.wrapping_sub(entry.last_seen) >= ARP_CACHE_TTL_TICKS
}

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

/// Update the ARP cache, stamping the entry with the current tick.
fn update_cache(ip: Ipv4Address, mac: MacAddress) {
    update_cache_at(ip, mac, now_ticks());
}

/// Insert or refresh `ip → mac`, stamping `last_seen = now`.
///
/// Refreshing an existing IP updates both the MAC and the timestamp.  When the
/// table is full and a *new* IP must be inserted, an expired entry is reclaimed
/// if one exists; otherwise the least-recently-refreshed entry is evicted so
/// the table never exceeds [`ARP_CACHE_MAX`] (bounds memory under a flood of
/// distinct source addresses).  `now` is taken as a parameter so the aging /
/// bounding logic is deterministically testable.
fn update_cache_at(ip: Ipv4Address, mac: MacAddress, now: u64) {
    let mut cache = ARP_CACHE.lock();

    if let Some(entry) = cache.iter_mut().find(|e| e.ip == ip) {
        entry.mac = mac;
        entry.last_seen = now;
        return;
    }

    if cache.len() >= ARP_CACHE_MAX {
        // Prefer reclaiming an already-expired slot; if none has expired, evict
        // the oldest (smallest last_seen) so the cap is always respected.
        let victim = cache
            .iter()
            .position(|e| is_expired(e, now))
            .or_else(|| {
                cache
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.last_seen)
                    .map(|(i, _)| i)
            });
        if let Some(i) = victim {
            cache.swap_remove(i);
        }
    }

    cache.push(ArpEntry { ip, mac, last_seen: now });
}

/// Look up a MAC address in the ARP cache.
pub fn lookup(ip: Ipv4Address) -> Option<MacAddress> {
    lookup_at(ip, now_ticks())
}

/// Look up `ip` as of tick `now`; an entry older than the TTL is treated as a
/// miss (returns `None`) so a stale mapping is never used.  `now` is a
/// parameter so the expiry behaviour is deterministically testable.
fn lookup_at(ip: Ipv4Address, now: u64) -> Option<MacAddress> {
    let cache = ARP_CACHE.lock();
    cache
        .iter()
        .find(|e| e.ip == ip && !is_expired(e, now))
        .map(|e| e.mac)
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

// ── Test-only hooks ─────────────────────────────────────────────────────────
// Exposed only under `test-mode` so the regression suite can exercise the
// bounding / aging logic deterministically by injecting an explicit `now`,
// without spinning on the real timer for the full TTL.

/// Capacity bound of the cache (for assertions).
#[cfg(feature = "test-mode")]
pub fn test_cache_max() -> usize { ARP_CACHE_MAX }

/// TTL in ticks (for assertions).
#[cfg(feature = "test-mode")]
pub fn test_cache_ttl_ticks() -> u64 { ARP_CACHE_TTL_TICKS }

/// Empty the cache so a test starts from a known state.
#[cfg(feature = "test-mode")]
pub fn test_clear_cache() {
    ARP_CACHE.lock().clear();
}

/// Current number of entries in the cache.
#[cfg(feature = "test-mode")]
pub fn test_cache_len() -> usize {
    ARP_CACHE.lock().len()
}

/// Insert/refresh `ip → mac` as if at tick `now` (drives the aging/bound path).
#[cfg(feature = "test-mode")]
pub fn test_update_at(ip: Ipv4Address, mac: MacAddress, now: u64) {
    update_cache_at(ip, mac, now);
}

/// Look up `ip` as of tick `now` (drives the expiry path).
#[cfg(feature = "test-mode")]
pub fn test_lookup_at(ip: Ipv4Address, now: u64) -> Option<MacAddress> {
    lookup_at(ip, now)
}
