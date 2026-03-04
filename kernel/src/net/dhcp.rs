//! DHCP — Dynamic Host Configuration Protocol Client
//!
//! Implements the DHCP 4-step handshake (DORA):
//!   1. DISCOVER — broadcast to find DHCP servers
//!   2. OFFER    — server offers an IP + lease
//!   3. REQUEST  — client requests the offered IP
//!   4. ACK      — server confirms the lease
//!
//! Configures IP, subnet mask, gateway, and DNS from server options.
//! QEMU SLIRP built-in DHCP server: 10.0.2.2 (port 67).

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use super::{Ipv4Address, MacAddress};

// ── DHCP Constants ──────────────────────────────────────────────────────────

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

const BOOTP_REQUEST: u8 = 1;
const BOOTP_REPLY: u8 = 2;

const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;

/// DHCP magic cookie (RFC 2131).
const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

// DHCP message types (option 53).
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_DECLINE: u8 = 4;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;
const DHCP_RELEASE: u8 = 7;

// DHCP options.
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_DOMAIN: u8 = 15;
const OPT_BROADCAST: u8 = 28;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_LIST: u8 = 55;
const OPT_END: u8 = 255;
const OPT_PAD: u8 = 0;

// ── DHCP Lease State ────────────────────────────────────────────────────────

/// Current lease information.
#[derive(Clone)]
pub struct DhcpLease {
    pub our_ip: Ipv4Address,
    pub server_ip: Ipv4Address,
    pub gateway: Ipv4Address,
    pub subnet_mask: Ipv4Address,
    pub dns_server: Ipv4Address,
    pub lease_time: u32,
    pub obtained_tick: u64,
    pub active: bool,
}

impl DhcpLease {
    const fn empty() -> Self {
        DhcpLease {
            our_ip: [0; 4],
            server_ip: [0; 4],
            gateway: [0; 4],
            subnet_mask: [0; 4],
            dns_server: [0; 4],
            lease_time: 0,
            obtained_tick: 0,
            active: false,
        }
    }
}

static CURRENT_LEASE: Mutex<DhcpLease> = Mutex::new(DhcpLease::empty());

/// Get a copy of the current DHCP lease.
pub fn get_lease() -> DhcpLease {
    CURRENT_LEASE.lock().clone()
}

/// Check if we have an active DHCP lease.
pub fn has_lease() -> bool {
    CURRENT_LEASE.lock().active
}

// ── DHCP Packet Builder ─────────────────────────────────────────────────────

/// Transaction ID for the current exchange.
static XID: Mutex<u32> = Mutex::new(0);

fn next_xid() -> u32 {
    let ticks = crate::arch::x86_64::irq::get_ticks() as u32;
    let xid = ticks ^ 0xDEAD_BEEF;
    *XID.lock() = xid;
    xid
}

fn current_xid() -> u32 {
    *XID.lock()
}

/// Build a base DHCP packet (BOOTP header + magic cookie).
/// Returns (packet, xid).
fn build_base_packet(msg_type: u8, xid: u32) -> Vec<u8> {
    let mac = super::our_mac();
    let mut pkt = Vec::with_capacity(576); // Minimum DHCP packet size

    // ── BOOTP header (236 bytes) ──
    pkt.push(BOOTP_REQUEST);         // op
    pkt.push(HTYPE_ETHERNET);       // htype
    pkt.push(HLEN_ETHERNET);        // hlen
    pkt.push(0);                     // hops

    pkt.extend_from_slice(&xid.to_be_bytes()); // xid

    pkt.extend_from_slice(&0u16.to_be_bytes()); // secs
    pkt.extend_from_slice(&0x8000u16.to_be_bytes()); // flags (broadcast)

    pkt.extend_from_slice(&[0; 4]); // ciaddr (client IP — 0 for DISCOVER)
    pkt.extend_from_slice(&[0; 4]); // yiaddr (your IP — filled by server)
    pkt.extend_from_slice(&[0; 4]); // siaddr (server IP)
    pkt.extend_from_slice(&[0; 4]); // giaddr (relay agent)

    // chaddr (16 bytes, MAC + padding)
    pkt.extend_from_slice(&mac);
    pkt.extend_from_slice(&[0; 10]); // Pad to 16 bytes

    // sname (64 bytes) + file (128 bytes) = 192 bytes of zeros
    pkt.extend_from_slice(&[0; 192]);

    // ── DHCP Magic Cookie ──
    pkt.extend_from_slice(&DHCP_MAGIC);

    // ── Option 53: DHCP Message Type ──
    pkt.push(OPT_MSG_TYPE);
    pkt.push(1);
    pkt.push(msg_type);

    pkt
}

/// Build a DHCP DISCOVER packet.
fn build_discover() -> (Vec<u8>, u32) {
    let xid = next_xid();
    let mut pkt = build_base_packet(DHCP_DISCOVER, xid);

    // Option 55: Parameter Request List
    pkt.push(OPT_PARAM_LIST);
    pkt.push(4);
    pkt.push(OPT_SUBNET_MASK);
    pkt.push(OPT_ROUTER);
    pkt.push(OPT_DNS);
    pkt.push(OPT_LEASE_TIME);

    // Option 12: Hostname
    let hostname = b"astryx";
    pkt.push(OPT_HOSTNAME);
    pkt.push(hostname.len() as u8);
    pkt.extend_from_slice(hostname);

    // End
    pkt.push(OPT_END);

    // Pad to minimum 300 bytes (BOOTP minimum)
    while pkt.len() < 300 {
        pkt.push(OPT_PAD);
    }

    (pkt, xid)
}

/// Build a DHCP REQUEST packet (requesting the offered IP).
fn build_request(offered_ip: Ipv4Address, server_ip: Ipv4Address, xid: u32) -> Vec<u8> {
    let mut pkt = build_base_packet(DHCP_REQUEST, xid);

    // Option 50: Requested IP Address
    pkt.push(OPT_REQUESTED_IP);
    pkt.push(4);
    pkt.extend_from_slice(&offered_ip);

    // Option 54: Server Identifier
    pkt.push(OPT_SERVER_ID);
    pkt.push(4);
    pkt.extend_from_slice(&server_ip);

    // Option 55: Parameter Request List
    pkt.push(OPT_PARAM_LIST);
    pkt.push(4);
    pkt.push(OPT_SUBNET_MASK);
    pkt.push(OPT_ROUTER);
    pkt.push(OPT_DNS);
    pkt.push(OPT_LEASE_TIME);

    // Option 12: Hostname
    let hostname = b"astryx";
    pkt.push(OPT_HOSTNAME);
    pkt.push(hostname.len() as u8);
    pkt.extend_from_slice(hostname);

    // End
    pkt.push(OPT_END);

    while pkt.len() < 300 {
        pkt.push(OPT_PAD);
    }

    pkt
}

/// Build a DHCP RELEASE packet.
fn build_release(our_ip: Ipv4Address, server_ip: Ipv4Address) -> Vec<u8> {
    let xid = next_xid();
    let mut pkt = build_base_packet(DHCP_RELEASE, xid);

    // Set ciaddr to our current IP
    pkt[12] = our_ip[0];
    pkt[13] = our_ip[1];
    pkt[14] = our_ip[2];
    pkt[15] = our_ip[3];

    // Option 54: Server Identifier
    pkt.push(OPT_SERVER_ID);
    pkt.push(4);
    pkt.extend_from_slice(&server_ip);

    pkt.push(OPT_END);

    while pkt.len() < 300 {
        pkt.push(OPT_PAD);
    }

    pkt
}

// ── DHCP Option Parser ──────────────────────────────────────────────────────

/// Parsed DHCP options from a server response.
struct DhcpOptions {
    msg_type: u8,
    server_id: Ipv4Address,
    your_ip: Ipv4Address,
    subnet_mask: Ipv4Address,
    router: Ipv4Address,
    dns: Ipv4Address,
    lease_time: u32,
}

/// Parse a DHCP response packet.
fn parse_response(data: &[u8], expected_xid: u32) -> Option<DhcpOptions> {
    // Minimum DHCP packet: 236 (BOOTP) + 4 (magic) = 240 bytes
    if data.len() < 240 {
        return None;
    }

    // Check op == BOOTREPLY
    if data[0] != BOOTP_REPLY {
        return None;
    }

    // Check xid
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if xid != expected_xid {
        return None;
    }

    // Check magic cookie at offset 236
    if data[236..240] != DHCP_MAGIC {
        return None;
    }

    // Extract yiaddr (your IP) from offset 16
    let your_ip: Ipv4Address = [data[16], data[17], data[18], data[19]];

    // Parse options starting at offset 240
    let mut opts = DhcpOptions {
        msg_type: 0,
        server_id: [0; 4],
        your_ip,
        subnet_mask: [255, 255, 255, 0],
        router: [0; 4],
        dns: [0; 4],
        lease_time: 0,
    };

    let mut i = 240;
    while i < data.len() {
        let opt = data[i];
        if opt == OPT_END { break; }
        if opt == OPT_PAD { i += 1; continue; }

        i += 1;
        if i >= data.len() { break; }
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() { break; }

        match opt {
            OPT_MSG_TYPE if len >= 1 => {
                opts.msg_type = data[i];
            }
            OPT_SUBNET_MASK if len >= 4 => {
                opts.subnet_mask = [data[i], data[i+1], data[i+2], data[i+3]];
            }
            OPT_ROUTER if len >= 4 => {
                opts.router = [data[i], data[i+1], data[i+2], data[i+3]];
            }
            OPT_DNS if len >= 4 => {
                opts.dns = [data[i], data[i+1], data[i+2], data[i+3]];
            }
            OPT_LEASE_TIME if len >= 4 => {
                opts.lease_time = u32::from_be_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
            }
            OPT_SERVER_ID if len >= 4 => {
                opts.server_id = [data[i], data[i+1], data[i+2], data[i+3]];
            }
            _ => {} // Ignore unknown options
        }

        i += len;
    }

    if opts.msg_type == 0 { return None; }

    Some(opts)
}

// ── DHCP Protocol Logic ─────────────────────────────────────────────────────

/// Perform a full DHCP handshake (DORA).
///
/// Returns `true` if successful, configuring IP/gateway/subnet/DNS.
/// Returns `false` on timeout or NAK.
pub fn discover() -> bool {
    crate::serial_println!("[DHCP] Starting DHCP discovery...");

    // Bind UDP port 68 for receiving responses
    if super::udp::bind(DHCP_CLIENT_PORT).is_err() {
        crate::serial_println!("[DHCP] Failed to bind port 68");
        return false;
    }

    let broadcast_mac: MacAddress = [0xFF; 6];
    let broadcast_ip: Ipv4Address = [255, 255, 255, 255];
    let zero_ip: Ipv4Address = [0, 0, 0, 0];

    // ── Step 1: DISCOVER ──
    let (discover_pkt, xid) = build_discover();
    crate::serial_println!("[DHCP] Sending DISCOVER (xid={:#010x})", xid);

    super::udp::send_from(zero_ip, broadcast_ip, broadcast_mac,
                          DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &discover_pkt);

    // Wait for OFFER (5 seconds = 500 ticks)
    let offer = match wait_for_response(xid, DHCP_OFFER, 500) {
        Some(o) => o,
        None => {
            crate::serial_println!("[DHCP] No OFFER received (timeout)");
            super::udp::unbind(DHCP_CLIENT_PORT);
            return false;
        }
    };

    crate::serial_println!("[DHCP] OFFER: IP={}.{}.{}.{} from server {}.{}.{}.{}",
        offer.your_ip[0], offer.your_ip[1], offer.your_ip[2], offer.your_ip[3],
        offer.server_id[0], offer.server_id[1], offer.server_id[2], offer.server_id[3]);
    crate::serial_println!("[DHCP]   Subnet: {}.{}.{}.{}  Gateway: {}.{}.{}.{}  DNS: {}.{}.{}.{}",
        offer.subnet_mask[0], offer.subnet_mask[1], offer.subnet_mask[2], offer.subnet_mask[3],
        offer.router[0], offer.router[1], offer.router[2], offer.router[3],
        offer.dns[0], offer.dns[1], offer.dns[2], offer.dns[3]);
    crate::serial_println!("[DHCP]   Lease: {} seconds", offer.lease_time);

    // ── Step 2: REQUEST ──
    let request_pkt = build_request(offer.your_ip, offer.server_id, xid);
    crate::serial_println!("[DHCP] Sending REQUEST for {}.{}.{}.{}",
        offer.your_ip[0], offer.your_ip[1], offer.your_ip[2], offer.your_ip[3]);

    super::udp::send_from(zero_ip, broadcast_ip, broadcast_mac,
                          DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &request_pkt);

    // Wait for ACK (5 seconds)
    let ack = match wait_for_response(xid, DHCP_ACK, 500) {
        Some(a) => a,
        None => {
            crate::serial_println!("[DHCP] No ACK received (timeout or NAK)");
            super::udp::unbind(DHCP_CLIENT_PORT);
            return false;
        }
    };

    crate::serial_println!("[DHCP] ACK received — lease confirmed");

    // ── Apply configuration ──
    apply_lease(&ack);

    super::udp::unbind(DHCP_CLIENT_PORT);

    crate::serial_println!("[DHCP] Configuration complete:");
    crate::serial_println!("[DHCP]   IP:      {}.{}.{}.{}",
        ack.your_ip[0], ack.your_ip[1], ack.your_ip[2], ack.your_ip[3]);
    crate::serial_println!("[DHCP]   Subnet:  {}.{}.{}.{}",
        ack.subnet_mask[0], ack.subnet_mask[1], ack.subnet_mask[2], ack.subnet_mask[3]);
    crate::serial_println!("[DHCP]   Gateway: {}.{}.{}.{}",
        ack.router[0], ack.router[1], ack.router[2], ack.router[3]);
    crate::serial_println!("[DHCP]   DNS:     {}.{}.{}.{}",
        ack.dns[0], ack.dns[1], ack.dns[2], ack.dns[3]);
    crate::serial_println!("[DHCP]   Lease:   {} seconds", ack.lease_time);

    true
}

/// Wait for a specific DHCP message type with the given xid.
fn wait_for_response(xid: u32, expected_type: u8, timeout_ticks: u64) -> Option<DhcpOptions> {
    let start = crate::arch::x86_64::irq::get_ticks();

    loop {
        let now = crate::arch::x86_64::irq::get_ticks();
        if now.wrapping_sub(start) >= timeout_ticks {
            return None;
        }

        crate::net::poll();

        if let Some(dgram) = super::udp::recv(DHCP_CLIENT_PORT) {
            if let Some(opts) = parse_response(&dgram.data, xid) {
                if opts.msg_type == expected_type {
                    return Some(opts);
                }
                if opts.msg_type == DHCP_NAK {
                    crate::serial_println!("[DHCP] Received NAK from server");
                    return None;
                }
            }
        }

        crate::hal::halt();
    }
}

/// Apply DHCP lease to the network stack.
fn apply_lease(opts: &DhcpOptions) {
    // Set IP
    super::set_our_ip(opts.your_ip);

    // Set subnet mask
    if opts.subnet_mask != [0; 4] {
        super::set_subnet_mask(opts.subnet_mask);
    }

    // Set gateway
    if opts.router != [0; 4] {
        super::set_gateway_ip(opts.router);
    }

    // Set DNS server
    if opts.dns != [0; 4] {
        super::dns::set_nameserver(opts.dns);
    }

    // Store lease info
    let mut lease = CURRENT_LEASE.lock();
    lease.our_ip = opts.your_ip;
    lease.server_ip = opts.server_id;
    lease.gateway = opts.router;
    lease.subnet_mask = opts.subnet_mask;
    lease.dns_server = opts.dns;
    lease.lease_time = opts.lease_time;
    lease.obtained_tick = crate::arch::x86_64::irq::get_ticks();
    lease.active = true;
}

/// Release the current DHCP lease.
pub fn release() -> bool {
    let lease = get_lease();
    if !lease.active {
        crate::serial_println!("[DHCP] No active lease to release");
        return false;
    }

    crate::serial_println!("[DHCP] Releasing lease for {}.{}.{}.{}",
        lease.our_ip[0], lease.our_ip[1], lease.our_ip[2], lease.our_ip[3]);

    let release_pkt = build_release(lease.our_ip, lease.server_ip);

    // Send release as unicast to the server
    super::udp::send(lease.server_ip, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &release_pkt);

    // Clear lease
    {
        let mut l = CURRENT_LEASE.lock();
        *l = DhcpLease::empty();
    }

    crate::serial_println!("[DHCP] Lease released");
    true
}

/// Renew the current DHCP lease (sends a new REQUEST).
pub fn renew() -> bool {
    let lease = get_lease();
    if !lease.active {
        crate::serial_println!("[DHCP] No active lease to renew");
        return false;
    }

    crate::serial_println!("[DHCP] Renewing lease for {}.{}.{}.{}",
        lease.our_ip[0], lease.our_ip[1], lease.our_ip[2], lease.our_ip[3]);

    if super::udp::bind(DHCP_CLIENT_PORT).is_err() {
        crate::serial_println!("[DHCP] Failed to bind port 68");
        return false;
    }

    let xid = next_xid();
    let request_pkt = build_request(lease.our_ip, lease.server_ip, xid);

    // Renew is unicast to the server
    super::udp::send(lease.server_ip, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &request_pkt);

    let result = match wait_for_response(xid, DHCP_ACK, 500) {
        Some(ack) => {
            crate::serial_println!("[DHCP] Lease renewed (new lease: {} seconds)", ack.lease_time);
            apply_lease(&ack);
            true
        }
        None => {
            crate::serial_println!("[DHCP] Renewal failed — no ACK");
            false
        }
    };

    super::udp::unbind(DHCP_CLIENT_PORT);
    result
}

/// Print the current DHCP lease status.
pub fn status() {
    let lease = get_lease();
    if !lease.active {
        crate::kprintln!("  DHCP: No active lease");
        crate::kprintln!("  Use 'dhcp discover' to obtain a lease");
        return;
    }

    let elapsed = crate::arch::x86_64::irq::get_ticks().wrapping_sub(lease.obtained_tick) / 100;
    let remaining = if lease.lease_time as u64 > elapsed {
        lease.lease_time as u64 - elapsed
    } else {
        0
    };

    crate::kprintln!("  DHCP Lease Status:");
    crate::kprintln!("    IP Address:  {}.{}.{}.{}",
        lease.our_ip[0], lease.our_ip[1], lease.our_ip[2], lease.our_ip[3]);
    crate::kprintln!("    Server:      {}.{}.{}.{}",
        lease.server_ip[0], lease.server_ip[1], lease.server_ip[2], lease.server_ip[3]);
    crate::kprintln!("    Gateway:     {}.{}.{}.{}",
        lease.gateway[0], lease.gateway[1], lease.gateway[2], lease.gateway[3]);
    crate::kprintln!("    Subnet Mask: {}.{}.{}.{}",
        lease.subnet_mask[0], lease.subnet_mask[1], lease.subnet_mask[2], lease.subnet_mask[3]);
    crate::kprintln!("    DNS Server:  {}.{}.{}.{}",
        lease.dns_server[0], lease.dns_server[1], lease.dns_server[2], lease.dns_server[3]);
    crate::kprintln!("    Lease Time:  {} seconds", lease.lease_time);
    crate::kprintln!("    Remaining:   {} seconds", remaining);
}
