//! TCP — Transmission Control Protocol
//!
//! Enhanced implementation with:
//! - rdtsc-based Initial Sequence Number (RFC 6528)
//! - Retransmit queue with exponential backoff (RFC 6298)
//! - Congestion control: slow start + congestion avoidance (RFC 5681)
//! - Proper window tracking and RST handling
//! - TimeWait expiry, LastAck → Closed transition

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;
use super::Ipv4Address;

// ── Constants ──────────────────────────────────────────────────────────────────

/// TCP flag bits.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// Maximum Segment Size (Ethernet 1500 − 20 IP − 20 TCP).
pub const MSS: u32 = 1460;

/// Initial RTO in PIT ticks (100 Hz → 200 = 2 s).
const RTO_INITIAL: u32 = 200;
/// Maximum RTO in ticks (64 s).
const RTO_MAX: u32 = 6400;
/// Maximum retransmit retries before RST.
const MAX_RETRIES: u8 = 5;
/// TIME_WAIT duration in ticks (2 s, simplified from 2×MSL).
const TIMEWAIT_TICKS: u64 = 200;

// ── Data structures ────────────────────────────────────────────────────────────

/// One unacknowledged segment sitting in the retransmit queue.
struct RetransmitEntry {
    seq:        u32,
    data:       Vec<u8>,
    sent_ticks: u64,
    rto:        u32,
    retries:    u8,
}

/// TCP connection state (per RFC 793).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

/// TCP Connection Control Block (TCB).
pub struct TcpConnection {
    // 4-tuple
    pub local_ip:    Ipv4Address,
    pub local_port:  u16,
    pub remote_ip:   Ipv4Address,
    pub remote_port: u16,
    pub state:       TcpState,

    // Sequence numbers
    pub send_next:  u32,  // SND.NXT
    pub send_unack: u32,  // SND.UNA
    pub recv_next:  u32,  // RCV.NXT

    // Data buffers
    pub recv_buffer: Vec<u8>,  // application receive queue
    pub send_buffer: Vec<u8>,  // data pending window space

    // Retransmit queue
    retransmit_queue: VecDeque<RetransmitEntry>,
    rto:  u32,   // current RTO in ticks
    srtt: u32,   // smoothed RTT

    // Congestion control (RFC 5681)
    pub cwnd:     u32,  // congestion window (bytes)
    pub ssthresh: u32,  // slow-start threshold
    dup_acks:     u8,   // dup-ACK counter

    // Flow control
    pub peer_window: u32,  // peer's advertised window

    // Socket options
    pub reuseaddr: bool,
    pub nodelay:   bool,
    pub rcvbuf:    u32,
    pub sndbuf:    u32,

    // TIME_WAIT expiry
    timewait_start: u64,
}

// ── ISN generation ─────────────────────────────────────────────────────────────

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
                         options(nostack, nomem, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Generate a pseudo-random ISN from the TSC.
pub fn new_isn() -> u32 {
    let tsc = rdtsc();
    let folded = (tsc ^ (tsc >> 32)) as u32;
    folded.wrapping_mul(1_000_003).wrapping_add(0xDEAD_BEEF)
}

// ── Global table ───────────────────────────────────────────────────────────────

static TCP_CONNECTIONS: Mutex<Vec<TcpConnection>> = Mutex::new(Vec::new());

// ── Helpers ───────────────────────────────────────────────────────────────────

/// TCP pseudo-header checksum.
fn tcp_checksum(src: Ipv4Address, dst: Ipv4Address, tcp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp.len());
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.push(0);
    buf.push(super::ipv4::PROTO_TCP);
    buf.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp);
    let off = 12 + 16;
    if buf.len() > off + 1 { buf[off] = 0; buf[off + 1] = 0; }
    super::ipv4::checksum(&buf)
}

/// Build a TCP segment (header + payload), checksum filled.
fn build_segment(
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8,
    src_ip: Ipv4Address, dst_ip: Ipv4Address,
    payload: &[u8],
) -> Vec<u8> {
    let mut s = Vec::with_capacity(20 + payload.len());
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.push(5 << 4);                          // data offset = 5 dwords
    s.push(flags);
    s.extend_from_slice(&65535u16.to_be_bytes()); // advertise full window
    s.push(0); s.push(0);                    // checksum placeholder
    s.push(0); s.push(0);                    // urgent pointer
    s.extend_from_slice(payload);
    let ck = tcp_checksum(src_ip, dst_ip, &s);
    s[16] = (ck >> 8) as u8;
    s[17] = (ck & 0xFF) as u8;
    s
}

/// Send a flag-only TCP segment.
fn send_flags(
    src_ip: Ipv4Address, src_port: u16,
    dst_ip: Ipv4Address, dst_port: u16,
    seq: u32, ack: u32, flags: u8,
) {
    let s = build_segment(src_port, dst_port, seq, ack, flags, src_ip, dst_ip, &[]);
    super::ipv4::send_ipv4(dst_ip, super::ipv4::PROTO_TCP, &s);
}

// ── Sequence-number arithmetic ────────────────────────────────────────────────

/// `a <= b` in sequence space (RFC 1982 serial-number arithmetic).
#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// `a > b` in sequence space.
#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) < 0
}

// ── ACK / congestion helpers ───────────────────────────────────────────────────

/// Remove retransmit-queue entries whose end sequence ≤ ack_num.
fn drain_retransmit(conn: &mut TcpConnection, ack_num: u32) {
    while let Some(e) = conn.retransmit_queue.front() {
        let end = e.seq.wrapping_add(e.data.len() as u32);
        if seq_le(end, ack_num) {
            conn.retransmit_queue.pop_front();
        } else {
            break;
        }
    }
}

/// Update cwnd after a new cumulative ACK (RFC 5681 §3.1).
fn update_cwnd(conn: &mut TcpConnection, acked: u32) {
    if conn.cwnd < conn.ssthresh {
        // Slow start: cwnd += min(ACKed, MSS)
        conn.cwnd = conn.cwnd.saturating_add(acked.min(MSS));
    } else {
        // Congestion avoidance: cwnd += MSS²/cwnd
        let inc = MSS * MSS / conn.cwnd.max(1);
        conn.cwnd = conn.cwnd.saturating_add(inc.max(1));
    }
}

/// Handle an incoming cumulative ACK on an existing connection.
fn handle_ack(conn: &mut TcpConnection, ack_num: u32) {
    if ack_num == conn.send_unack {
        // Duplicate ACK
        conn.dup_acks = conn.dup_acks.saturating_add(1);
        if conn.dup_acks >= 3 {
            // Fast retransmit trigger (RFC 5681 §3.2)
            conn.ssthresh = (conn.cwnd / 2).max(2 * MSS);
            conn.cwnd     = conn.ssthresh + 3 * MSS;
            conn.dup_acks = 0;
            if let Some(e) = conn.retransmit_queue.front_mut() {
                e.sent_ticks = 0; // force retransmit on next timer tick
            }
        }
        return;
    }
    if seq_gt(ack_num, conn.send_unack) {
        let acked = ack_num.wrapping_sub(conn.send_unack);
        conn.send_unack = ack_num;
        conn.dup_acks   = 0;
        conn.rto        = RTO_INITIAL; // reset after fresh ACK
        drain_retransmit(conn, ack_num);
        update_cwnd(conn, acked);
    }
}

// ── Receive path ──────────────────────────────────────────────────────────────

/// Parsed TCP header fields.
pub struct TcpHeader {
    pub src_port:    u16,
    pub dst_port:    u16,
    pub seq_num:     u32,
    pub ack_num:     u32,
    pub data_offset: u8,
    pub flags:       u8,
    pub window:      u16,
    pub checksum:    u16,
}

impl TcpHeader {
    pub fn parse(d: &[u8]) -> Option<Self> {
        if d.len() < 20 { return None; }
        Some(TcpHeader {
            src_port:    u16::from_be_bytes([d[0],  d[1]]),
            dst_port:    u16::from_be_bytes([d[2],  d[3]]),
            seq_num:     u32::from_be_bytes([d[4],  d[5],  d[6],  d[7]]),
            ack_num:     u32::from_be_bytes([d[8],  d[9],  d[10], d[11]]),
            data_offset: d[12] >> 4,
            flags:       d[13],
            window:      u16::from_be_bytes([d[14], d[15]]),
            checksum:    u16::from_be_bytes([d[16], d[17]]),
        })
    }
    pub fn header_len(&self) -> usize { (self.data_offset as usize) * 4 }
}

/// Handle an incoming TCP segment dispatched from the IPv4 layer.
pub fn handle_tcp(src_ip: Ipv4Address, dst_ip: Ipv4Address, data: &[u8]) {
    let hdr = match TcpHeader::parse(data) { Some(h) => h, None => return };
    let hlen = hdr.header_len().min(data.len());
    let payload = &data[hlen..];

    // RST: immediately close matching connection.
    if hdr.flags & RST != 0 {
        let mut conns = TCP_CONNECTIONS.lock();
        if let Some(c) = conns.iter_mut().find(|c|
            c.local_port == hdr.dst_port &&
            c.remote_ip  == src_ip &&
            c.remote_port == hdr.src_port
        ) {
            crate::serial_println!("[TCP] RST: closing port {}", c.local_port);
            c.state = TcpState::Closed;
            c.retransmit_queue.clear();
        }
        return;
    }

    let mut conns = TCP_CONNECTIONS.lock();

    // Existing connection?
    let idx = conns.iter().position(|c|
        c.local_port  == hdr.dst_port &&
        c.remote_ip   == src_ip &&
        c.remote_port == hdr.src_port
    );
    if let Some(i) = idx {
        process_segment(&mut conns[i], &hdr, payload);
        return;
    }

    // New SYN → find listener.
    if hdr.flags & SYN != 0 && hdr.flags & ACK == 0 {
        let listen_idx = conns.iter().position(|c|
            c.local_port == hdr.dst_port && c.state == TcpState::Listen
        );
        if let Some(li) = listen_idx {
            let isn     = new_isn();
            // Use the SYN's dst_ip as our local IP for the child TCB,
            // not the listener's stored `local_ip`.  The listener is
            // created at boot before DHCP runs, so its stored IP is
            // the hardcoded default (10.0.2.15).  After DHCP the real
            // IP differs; replying from the stale value makes the peer
            // drop the SYN-ACK as a martian source.  Using dst_ip is
            // also correct for multi-homed hosts — we reply on the
            // same address the peer reached us on.
            let lip     = dst_ip;
            let lport   = conns[li].local_port;
            let rcv_nxt = hdr.seq_num.wrapping_add(1);
            conns.push(TcpConnection {
                local_ip:    lip,
                local_port:  lport,
                remote_ip:   src_ip,
                remote_port: hdr.src_port,
                state:       TcpState::SynReceived,
                send_next:   isn.wrapping_add(1),
                send_unack:  isn,
                recv_next:   rcv_nxt,
                recv_buffer: Vec::new(),
                send_buffer: Vec::new(),
                retransmit_queue: VecDeque::new(),
                rto:         RTO_INITIAL,
                srtt:        RTO_INITIAL / 2,
                cwnd:        MSS,
                ssthresh:    65535,
                dup_acks:    0,
                peer_window: hdr.window as u32,
                reuseaddr:   false,
                nodelay:     false,
                rcvbuf:      87380,
                sndbuf:      131072,
                timewait_start: 0,
            });
            drop(conns);
            send_flags(lip, lport, src_ip, hdr.src_port, isn, rcv_nxt, SYN | ACK);
        } else {
            drop(conns);
            send_flags(dst_ip, hdr.dst_port, src_ip, hdr.src_port,
                       0, hdr.seq_num.wrapping_add(1), RST | ACK);
        }
    }
}

/// Process one segment on an existing connection (lock already held by caller).
fn process_segment(conn: &mut TcpConnection, hdr: &TcpHeader, payload: &[u8]) {
    conn.peer_window = hdr.window as u32;

    let lp = conn.local_port;
    let rp = conn.remote_port;
    let lip = conn.local_ip;
    let rip = conn.remote_ip;

    match conn.state {
        TcpState::SynSent => {
            if hdr.flags & (SYN | ACK) == (SYN | ACK) {
                conn.recv_next  = hdr.seq_num.wrapping_add(1);
                conn.send_unack = hdr.ack_num;
                drain_retransmit(conn, hdr.ack_num);
                conn.state = TcpState::Established;
                crate::serial_println!("[TCP] Established → {}:{}", rip[0], rp);
                let sn = conn.send_next;
                let rn = conn.recv_next;
                let s = build_segment(lp, rp, sn, rn, ACK, lip, rip, &[]);
                super::ipv4::send_ipv4(rip, super::ipv4::PROTO_TCP, &s);
            }
        }

        TcpState::SynReceived => {
            if hdr.flags & ACK != 0 {
                conn.send_unack = hdr.ack_num;
                drain_retransmit(conn, hdr.ack_num);
                conn.state = TcpState::Established;
                crate::serial_println!("[TCP] Accepted from {}:{}", rip[0], rp);
            }
        }

        TcpState::Established => {
            if hdr.flags & ACK != 0 {
                handle_ack(conn, hdr.ack_num);
            }
            // In-order data.
            if !payload.is_empty() && hdr.seq_num == conn.recv_next {
                conn.recv_buffer.extend_from_slice(payload);
                conn.recv_next = conn.recv_next.wrapping_add(payload.len() as u32);
                let sn = conn.send_next;
                let rn = conn.recv_next;
                let s = build_segment(lp, rp, sn, rn, ACK, lip, rip, &[]);
                super::ipv4::send_ipv4(rip, super::ipv4::PROTO_TCP, &s);
            }
            // FIN from peer.
            if hdr.flags & FIN != 0 {
                conn.recv_next = conn.recv_next.wrapping_add(1);
                conn.state = TcpState::CloseWait;
                let sn = conn.send_next;
                let rn = conn.recv_next;
                let s = build_segment(lp, rp, sn, rn, ACK, lip, rip, &[]);
                super::ipv4::send_ipv4(rip, super::ipv4::PROTO_TCP, &s);
            }
        }

        TcpState::FinWait1 => {
            if hdr.flags & ACK != 0 {
                handle_ack(conn, hdr.ack_num);
            }
            if hdr.flags & FIN != 0 {
                // Simultaneous close or ACK+FIN in same segment.
                conn.recv_next = conn.recv_next.wrapping_add(1);
                conn.state = TcpState::TimeWait;
                conn.timewait_start = crate::arch::x86_64::irq::get_ticks();
                let sn = conn.send_next;
                let rn = conn.recv_next;
                let s = build_segment(lp, rp, sn, rn, ACK, lip, rip, &[]);
                super::ipv4::send_ipv4(rip, super::ipv4::PROTO_TCP, &s);
            } else if hdr.flags & ACK != 0 {
                // Pure ACK (no FIN): move to FinWait2.
                conn.state = TcpState::FinWait2;
            }
        }

        TcpState::FinWait2 => {
            if hdr.flags & FIN != 0 {
                conn.recv_next = conn.recv_next.wrapping_add(1);
                conn.state = TcpState::TimeWait;
                conn.timewait_start = crate::arch::x86_64::irq::get_ticks();
                let sn = conn.send_next;
                let rn = conn.recv_next;
                let s = build_segment(lp, rp, sn, rn, ACK, lip, rip, &[]);
                super::ipv4::send_ipv4(rip, super::ipv4::PROTO_TCP, &s);
            }
        }

        TcpState::LastAck => {
            // Our FIN has been acknowledged → connection done.
            if hdr.flags & ACK != 0 {
                conn.state = TcpState::Closed;
                conn.retransmit_queue.clear();
                crate::serial_println!("[TCP] Closed (LastAck → Closed) port {}", lp);
            }
        }

        _ => {}
    }
}

// ── Send path ─────────────────────────────────────────────────────────────────

/// Send data on an established connection.
/// Respects congestion window; buffers excess in send_buffer.
pub fn send_data(port: u16, data: &[u8]) -> Result<usize, &'static str> {
    send_data_inner(port, None, data)
}

/// Send `data` on the connection identified by the full 4-tuple
/// `(local_port, remote_ip, remote_port)`.
///
/// Matches the connection strictly by tuple instead of by `local_port`
/// alone — required when several concurrent client sessions share a single
/// listening port (kdb on TCP/9999 in particular).
pub fn send_data_to(local_port: u16, remote_ip: Ipv4Address, remote_port: u16,
                     data: &[u8]) -> Result<usize, &'static str>
{
    send_data_inner(local_port, Some((remote_ip, remote_port)), data)
}

fn send_data_inner(port: u16, peer: Option<(Ipv4Address, u16)>, data: &[u8])
    -> Result<usize, &'static str>
{
    if data.is_empty() { return Ok(0); }

    struct PendingSend {
        remote_ip: Ipv4Address,
        seg:       Vec<u8>,
    }
    let mut to_send: Vec<PendingSend> = Vec::new();

    {
        let mut conns = TCP_CONNECTIONS.lock();
        let conn = conns.iter_mut()
            .find(|c| c.local_port == port && c.state == TcpState::Established
                    && peer.map_or(true, |(rip, rp)| c.remote_ip == rip && c.remote_port == rp))
            .ok_or("no established connection on port")?;

        let ticks = crate::arch::x86_64::irq::get_ticks();
        let in_flight   = conn.send_next.wrapping_sub(conn.send_unack);
        let eff_window  = conn.cwnd.min(conn.peer_window.max(MSS));
        let can_send    = if eff_window > in_flight { (eff_window - in_flight) as usize } else { 0 };

        let mut offset = 0usize;
        while offset < data.len() && offset < can_send {
            let end   = (offset + MSS as usize).min(data.len()).min(offset + can_send - offset);
            let chunk = &data[offset..end];
            let seq   = conn.send_next;
            let seg   = build_segment(
                conn.local_port, conn.remote_port,
                seq, conn.recv_next,
                PSH | ACK,
                conn.local_ip, conn.remote_ip,
                chunk,
            );
            conn.retransmit_queue.push_back(RetransmitEntry {
                seq,
                data:       chunk.to_vec(),
                sent_ticks: ticks,
                rto:        conn.rto,
                retries:    0,
            });
            conn.send_next = conn.send_next.wrapping_add(chunk.len() as u32);
            to_send.push(PendingSend { remote_ip: conn.remote_ip, seg });
            offset = end;
        }
        // Buffer data that didn't fit in the window.
        if offset < data.len() {
            conn.send_buffer.extend_from_slice(&data[offset..]);
        }
    }

    for ps in to_send {
        super::ipv4::send_ipv4(ps.remote_ip, super::ipv4::PROTO_TCP, &ps.seg);
    }
    Ok(data.len())
}

// ── Timer ─────────────────────────────────────────────────────────────────────

/// Called periodically from net::poll().
/// Handles retransmit timeouts and TIME_WAIT expiry.
pub fn tcp_timer_tick() {
    let now = crate::arch::x86_64::irq::get_ticks();

    struct SendJob {
        lip: Ipv4Address, lp: u16,
        rip: Ipv4Address, rp: u16,
        seq: u32, ack: u32, flags: u8,
        payload: Vec<u8>,
    }
    let mut jobs:     Vec<SendJob> = Vec::new();
    let mut aborted:  Vec<u16>    = Vec::new(); // local_ports that hit MAX_RETRIES

    {
        let mut conns = TCP_CONNECTIONS.lock();

        for conn in conns.iter_mut() {
            // TIME_WAIT expiry.
            if conn.state == TcpState::TimeWait {
                if now.wrapping_sub(conn.timewait_start) >= TIMEWAIT_TICKS {
                    conn.state = TcpState::Closed;
                }
                continue;
            }

            // Only check retransmit for states with pending unacked data.
            if !matches!(conn.state,
                TcpState::SynSent | TcpState::SynReceived |
                TcpState::Established | TcpState::FinWait1 | TcpState::LastAck
            ) { continue; }

            if let Some(e) = conn.retransmit_queue.front_mut() {
                let elapsed = now.wrapping_sub(e.sent_ticks);
                if elapsed >= e.rto as u64 {
                    if e.retries >= MAX_RETRIES {
                        aborted.push(conn.local_port);
                        jobs.push(SendJob {
                            lip: conn.local_ip, lp: conn.local_port,
                            rip: conn.remote_ip, rp: conn.remote_port,
                            seq: conn.send_next, ack: 0, flags: RST,
                            payload: Vec::new(),
                        });
                        conn.state = TcpState::Closed;
                        conn.retransmit_queue.clear();
                    } else {
                        e.retries   += 1;
                        e.rto        = (e.rto * 2).min(RTO_MAX);
                        e.sent_ticks = now;
                        conn.ssthresh = (conn.cwnd / 2).max(2 * MSS);
                        conn.cwnd     = MSS;
                        jobs.push(SendJob {
                            lip: conn.local_ip, lp: conn.local_port,
                            rip: conn.remote_ip, rp: conn.remote_port,
                            seq: e.seq, ack: conn.recv_next,
                            flags: PSH | ACK,
                            payload: e.data.clone(),
                        });
                    }
                }
            }

            // Drain send_buffer if window reopened.
            if conn.send_buffer.is_empty() { continue; }
            let in_flight  = conn.send_next.wrapping_sub(conn.send_unack);
            let eff_window = conn.cwnd.min(conn.peer_window.max(MSS));
            if eff_window <= in_flight { continue; }
            let can  = (eff_window - in_flight) as usize;
            let take = can.min(conn.send_buffer.len()).min(MSS as usize);
            let chunk: Vec<u8> = conn.send_buffer.drain(..take).collect();
            let seq = conn.send_next;
            conn.retransmit_queue.push_back(RetransmitEntry {
                seq,
                data:       chunk.clone(),
                sent_ticks: now,
                rto:        conn.rto,
                retries:    0,
            });
            conn.send_next = conn.send_next.wrapping_add(take as u32);
            jobs.push(SendJob {
                lip: conn.local_ip, lp: conn.local_port,
                rip: conn.remote_ip, rp: conn.remote_port,
                seq, ack: conn.recv_next, flags: PSH | ACK,
                payload: chunk,
            });
        }

        conns.retain(|c| !(c.state == TcpState::Closed && aborted.contains(&c.local_port)));
    }

    for job in jobs {
        let seg = build_segment(job.lp, job.rp, job.seq, job.ack,
                                job.flags, job.lip, job.rip, &job.payload);
        super::ipv4::send_ipv4(job.rip, super::ipv4::PROTO_TCP, &seg);
    }
}

// ── Public query API ──────────────────────────────────────────────────────────

/// Snapshot of a connection's 4-tuple + state.  Used by kdb for child-of-
/// listener discovery without exposing the full TCB struct.  Gated to
/// preserve byte-identical default builds — the struct would otherwise
/// alter LLVM's symbol mangling hashes of neighbouring statics.
#[cfg(feature = "kdb")]
#[derive(Clone, Copy)]
pub struct ConnSnap {
    pub local_port:  u16,
    pub remote_ip:   Ipv4Address,
    pub remote_port: u16,
    pub state:       TcpState,
}

/// Return a snapshot of every connection in the TCP table.  Caller-owned
/// copy — safe to use after the lock is dropped.
#[cfg(feature = "kdb")]
pub fn snapshot_connections() -> alloc::vec::Vec<ConnSnap> {
    TCP_CONNECTIONS.lock().iter().map(|c| ConnSnap {
        local_port:  c.local_port,
        remote_ip:   c.remote_ip,
        remote_port: c.remote_port,
        state:       c.state,
    }).collect()
}

/// Sum of bytes still in `send_buffer` (not yet on the wire) plus bytes
/// in the retransmit queue (on the wire but not yet ACKed) for the
/// given connection 4-tuple.  Returns 0 if no matching Established or
/// CloseWait connection exists.
///
/// Used by callers (kdb) that must defer FIN until the peer has actually
/// received their entire response.  Closing while either count is non-
/// zero discards the buffered tail because the FIN advances `send_next`
/// past data that has not yet been transmitted.
#[cfg(feature = "kdb")]
pub fn outbound_pending(local_port: u16, remote_ip: Ipv4Address, remote_port: u16) -> usize {
    TCP_CONNECTIONS.lock().iter()
        .find(|c| c.local_port == local_port
                  && c.remote_ip == remote_ip
                  && c.remote_port == remote_port
                  && matches!(c.state, TcpState::Established | TcpState::CloseWait))
        .map(|c| c.send_buffer.len()
                  + c.retransmit_queue.iter().map(|e| e.data.len()).sum::<usize>())
        .unwrap_or(0)
}

pub fn get_state(port: u16) -> Option<TcpState> {
    TCP_CONNECTIONS.lock().iter()
        .find(|c| c.local_port == port)
        .map(|c| c.state)
}

/// Returns true if any TCB on `port` is in the Listen state — used by
/// the socket-layer ephemeral-port allocator to probe for collisions.
pub fn is_listening(port: u16) -> bool {
    TCP_CONNECTIONS.lock().iter()
        .any(|c| c.local_port == port && c.state == TcpState::Listen)
}

/// Returns the bound `local_ip` recorded for a TCB on `port`, if any.
/// Prefers an Established connection (a connect()ed socket) over a
/// Listen entry, since the former carries the actual selected source
/// IP for the connection.  Returns `None` if no TCB matches.
///
/// Used by `getsockname(2)` to reconstruct the bound 4-tuple.
pub fn lookup_local_ip(port: u16) -> Option<Ipv4Address> {
    let conns = TCP_CONNECTIONS.lock();
    // Prefer Established (or any non-Listen) so getsockname on a
    // connected socket reflects the connection's source IP, not the
    // INADDR_ANY listener wildcard.
    if let Some(c) = conns.iter().find(|c|
        c.local_port == port && c.state != TcpState::Listen
    ) {
        return Some(c.local_ip);
    }
    conns.iter().find(|c| c.local_port == port).map(|c| c.local_ip)
}

pub fn retransmit_queue_len(port: u16) -> usize {
    TCP_CONNECTIONS.lock().iter()
        .find(|c| c.local_port == port)
        .map(|c| c.retransmit_queue.len())
        .unwrap_or(0)
}

pub fn get_cwnd(port: u16) -> u32 {
    TCP_CONNECTIONS.lock().iter()
        .find(|c| c.local_port == port)
        .map(|c| c.cwnd)
        .unwrap_or(0)
}

pub fn get_ssthresh(port: u16) -> u32 {
    TCP_CONNECTIONS.lock().iter()
        .find(|c| c.local_port == port)
        .map(|c| c.ssthresh)
        .unwrap_or(0)
}

pub fn get_send_next(port: u16) -> u32 {
    TCP_CONNECTIONS.lock().iter()
        .find(|c| c.local_port == port)
        .map(|c| c.send_next)
        .unwrap_or(0)
}

/// Inject a synthetic ACK directly into the connection (used by tests).
pub fn inject_ack(port: u16, ack_num: u32, window: u16) {
    let mut conns = TCP_CONNECTIONS.lock();
    if let Some(conn) = conns.iter_mut().find(|c| c.local_port == port) {
        conn.peer_window = window as u32;
        handle_ack(conn, ack_num);
    }
}

pub fn has_data(port: u16) -> bool {
    TCP_CONNECTIONS.lock().iter()
        .any(|c| c.local_port == port
                 && c.state == TcpState::Established
                 && !c.recv_buffer.is_empty())
}

pub fn read(port: u16) -> Vec<u8> {
    let mut conns = TCP_CONNECTIONS.lock();
    if let Some(conn) = conns.iter_mut()
        .find(|c| c.local_port == port && c.state == TcpState::Established)
    {
        let d = conn.recv_buffer.clone();
        conn.recv_buffer.clear();
        d
    } else {
        Vec::new()
    }
}

/// Test-only: synthesise an Established TCB with the given 4-tuple and a
/// pre-loaded receive buffer.  Bypasses the wire entirely so the test
/// runner can exercise drain/4-tuple-routing logic without paying the
/// e1000 + SLIRP round-trip (and its inevitable RST when the synthetic
/// peer doesn't actually exist on the host).
///
/// Behaviour mirrors a successful 3WHS finishing in `Established`: an
/// arbitrary ISN is chosen, retransmit queues are empty, congestion
/// windows are sane defaults.  Only the receive buffer is pre-populated
/// from `recv_data`.
///
/// Returns `Err` on duplicate 4-tuple.  Gated on `kdb` because that is
/// the only build profile that pulls in the test runner that needs it.
#[cfg(feature = "kdb")]
pub fn test_inject_established(local_port: u16, remote_ip: Ipv4Address,
                                remote_port: u16, recv_data: &[u8])
    -> Result<(), &'static str>
{
    let mut conns = TCP_CONNECTIONS.lock();
    if conns.iter().any(|c|
        c.local_port  == local_port
        && c.remote_ip   == remote_ip
        && c.remote_port == remote_port)
    {
        return Err("duplicate 4-tuple");
    }
    let isn = new_isn();
    conns.push(TcpConnection {
        local_ip:    super::our_ip(),
        local_port,
        remote_ip,
        remote_port,
        state:       TcpState::Established,
        send_next:   isn.wrapping_add(1),
        send_unack:  isn,
        recv_next:   1,
        recv_buffer: recv_data.to_vec(),
        send_buffer: Vec::new(),
        retransmit_queue: VecDeque::new(),
        rto:         RTO_INITIAL,
        srtt:        RTO_INITIAL / 2,
        cwnd:        MSS,
        ssthresh:    65535,
        dup_acks:    0,
        peer_window: 65535,
        reuseaddr:   false,
        nodelay:     false,
        rcvbuf:      87380,
        sndbuf:      131072,
        timewait_start: 0,
    });
    Ok(())
}

/// Drain the receive buffer of the established TCB identified by the full
/// 4-tuple `(local_port, remote_ip, remote_port)`.
///
/// Required when several concurrent client sessions share a single listening
/// port (kdb on TCP/9999 is the canonical case): `read(port)` returns bytes
/// from whichever Established TCB on `port` happens to match first, which
/// can attribute one client's request bytes to another.  The 4-tuple form
/// matches strictly so per-connection drains stay isolated.
///
/// Mirrors the shape of [`send_data_to`] / [`close_connection`].
pub fn read_from(local_port: u16, remote_ip: Ipv4Address, remote_port: u16) -> Vec<u8> {
    let mut conns = TCP_CONNECTIONS.lock();
    if let Some(conn) = conns.iter_mut().find(|c| {
        c.local_port  == local_port
            && c.remote_ip   == remote_ip
            && c.remote_port == remote_port
            && c.state       == TcpState::Established
    }) {
        let d = conn.recv_buffer.clone();
        conn.recv_buffer.clear();
        d
    } else {
        Vec::new()
    }
}

// ── Control operations ────────────────────────────────────────────────────────

pub fn listen(port: u16) -> Result<(), &'static str> {
    let mut conns = TCP_CONNECTIONS.lock();
    // Check for conflicting listener (unless reuseaddr allows it).
    if conns.iter().any(|c| c.local_port == port && c.state == TcpState::Listen) {
        return Err("port already listening");
    }
    let isn = new_isn();
    conns.push(TcpConnection {
        local_ip:    super::our_ip(),
        local_port:  port,
        remote_ip:   [0; 4],
        remote_port: 0,
        state:       TcpState::Listen,
        send_next:   isn,
        send_unack:  isn,
        recv_next:   0,
        recv_buffer: Vec::new(),
        send_buffer: Vec::new(),
        retransmit_queue: VecDeque::new(),
        rto:         RTO_INITIAL,
        srtt:        RTO_INITIAL / 2,
        cwnd:        MSS,
        ssthresh:    65535,
        dup_acks:    0,
        peer_window: 65535,
        reuseaddr:   false,
        nodelay:     false,
        rcvbuf:      87380,
        sndbuf:      131072,
        timewait_start: 0,
    });
    Ok(())
}

pub fn connect(remote_ip: Ipv4Address, remote_port: u16) -> Result<u16, &'static str> {
    static NEXT_EPHEMERAL: core::sync::atomic::AtomicU16 =
        core::sync::atomic::AtomicU16::new(49152);
    let local_port = NEXT_EPHEMERAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let local_ip   = super::our_ip();
    let isn        = new_isn();

    {
        let mut conns = TCP_CONNECTIONS.lock();
        conns.push(TcpConnection {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state:       TcpState::SynSent,
            send_next:   isn.wrapping_add(1),   // SYN consumed 1 byte
            send_unack:  isn,
            recv_next:   0,
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
            retransmit_queue: VecDeque::new(),
            rto:         RTO_INITIAL,
            srtt:        RTO_INITIAL / 2,
            cwnd:        MSS,
            ssthresh:    65535,
            dup_acks:    0,
            peer_window: 65535,
            reuseaddr:   false,
            nodelay:     false,
            rcvbuf:      87380,
            sndbuf:      131072,
            timewait_start: 0,
        });
    }
    send_flags(local_ip, local_port, remote_ip, remote_port, isn, 0, SYN);
    Ok(local_port)
}

/// Abort the connection on `port` by transmitting a RST segment to the
/// remote peer (if any) and marking the local TCB closed.
///
/// Unlike `close()`, which initiates a graceful four-way handshake and
/// leaves the peer in CLOSE_WAIT until it acks the FIN, `abort()` tears
/// the connection down unilaterally — necessary when the test harness
/// has finished with a scratch connection pointed at an unreachable
/// address and needs to release the corresponding state on the
/// emulator's SLIRP backend.
///
/// Returns `Ok(())` whether or not a matching connection was found so
/// call sites don't have to special-case missing entries.
pub fn abort(port: u16) -> Result<(), &'static str> {
    struct AbortInfo {
        lip: Ipv4Address, lp: u16,
        rip: Ipv4Address, rp: u16,
        sn: u32, rn: u32,
    }
    let info = {
        let mut conns = TCP_CONNECTIONS.lock();
        let conn = match conns.iter_mut().find(|c| c.local_port == port) {
            Some(c) => c,
            None    => return Ok(()),
        };
        // Send a RST to the peer whenever we know who it is, regardless
        // of our local state — callers use abort() precisely to tear
        // down a connection the remote side still considers live, such
        // as a SLIRP entry left over from a test that only cleaned up
        // the local TCB.  The one case where we suppress the RST is a
        // pure listener (remote_port == 0) which has no peer to notify.
        let info = if conn.remote_port != 0 && !matches!(conn.state, TcpState::Listen) {
            Some(AbortInfo {
                lip: conn.local_ip, lp: conn.local_port,
                rip: conn.remote_ip, rp: conn.remote_port,
                sn: conn.send_next, rn: conn.recv_next,
            })
        } else { None };
        conn.state = TcpState::Closed;
        conn.retransmit_queue.clear();
        info
    };
    if let Some(i) = info {
        send_flags(i.lip, i.lp, i.rip, i.rp, i.sn, i.rn, RST | ACK);
    }
    Ok(())
}

pub fn close(port: u16) -> Result<(), &'static str> {
    struct CloseInfo {
        lip: Ipv4Address, lp: u16,
        rip: Ipv4Address, rp: u16,
        sn: u32, rn: u32,
        was_close_wait: bool,
    }
    let info = {
        let mut conns = TCP_CONNECTIONS.lock();
        let conn = conns.iter_mut()
            .find(|c| c.local_port == port &&
                  matches!(c.state, TcpState::Established | TcpState::CloseWait))
            .ok_or("no connection to close")?;
        let was_cw = conn.state == TcpState::CloseWait;
        conn.state = if was_cw { TcpState::LastAck } else { TcpState::FinWait1 };
        CloseInfo { lip: conn.local_ip, lp: conn.local_port,
                    rip: conn.remote_ip, rp: conn.remote_port,
                    sn: conn.send_next, rn: conn.recv_next,
                    was_close_wait: was_cw }
    };
    send_flags(info.lip, info.lp, info.rip, info.rp, info.sn, info.rn, FIN | ACK);
    Ok(())
}

/// Close a specific connection identified by the full 4-tuple.
///
/// Used by services that share a single listening port across multiple
/// concurrent client sessions (e.g. kdb on TCP/9999): closing by `port`
/// alone matches the first established/close-wait TCB on that port and
/// would FIN the listener or a sibling session, not the responded one.
/// This variant matches strictly on `(local_port, remote_ip, remote_port)`
/// so the caller closes exactly the session it serviced.
pub fn close_connection(local_port: u16, remote_ip: Ipv4Address, remote_port: u16)
    -> Result<(), &'static str>
{
    struct CloseInfo {
        lip: Ipv4Address, lp: u16,
        rip: Ipv4Address, rp: u16,
        sn: u32, rn: u32,
    }
    let info = {
        let mut conns = TCP_CONNECTIONS.lock();
        let conn = conns.iter_mut()
            .find(|c| c.local_port == local_port
                   && c.remote_ip == remote_ip
                   && c.remote_port == remote_port
                   && matches!(c.state, TcpState::Established | TcpState::CloseWait))
            .ok_or("no connection to close")?;
        let was_cw = conn.state == TcpState::CloseWait;
        conn.state = if was_cw { TcpState::LastAck } else { TcpState::FinWait1 };
        CloseInfo { lip: conn.local_ip, lp: conn.local_port,
                    rip: conn.remote_ip, rp: conn.remote_port,
                    sn: conn.send_next, rn: conn.recv_next }
    };
    send_flags(info.lip, info.lp, info.rip, info.rp, info.sn, info.rn, FIN | ACK);
    Ok(())
}

/// Half-close the send side of an Established / CloseWait connection
/// identified by the full 4-tuple.  Drives the same RFC 793 §3.5 state
/// transition as a full close on the local TCB (Established → FinWait1
/// or CloseWait → LastAck) and emits a single FIN segment to the peer,
/// but is a no-op when the connection is in any other state — repeated
/// SHUT_WR calls or a SHUT_WR after our peer already FIN'd us must not
/// queue stray segments.
///
/// Distinct from [`close_connection`] only in intent: the socket layer
/// keeps the user-visible socket alive after this call so that pending
/// inbound data can still be read.  The underlying TCB lifecycle is
/// identical.
pub fn shutdown_write(local_port: u16, remote_ip: Ipv4Address, remote_port: u16)
    -> Result<(), &'static str>
{
    struct CloseInfo {
        lip: Ipv4Address, lp: u16,
        rip: Ipv4Address, rp: u16,
        sn: u32, rn: u32,
    }
    let info = {
        let mut conns = TCP_CONNECTIONS.lock();
        let conn = match conns.iter_mut()
            .find(|c| c.local_port == local_port
                   && c.remote_ip == remote_ip
                   && c.remote_port == remote_port
                   && matches!(c.state, TcpState::Established | TcpState::CloseWait))
        {
            Some(c) => c,
            None    => return Ok(()),
        };
        let was_cw = conn.state == TcpState::CloseWait;
        conn.state = if was_cw { TcpState::LastAck } else { TcpState::FinWait1 };
        CloseInfo { lip: conn.local_ip, lp: conn.local_port,
                    rip: conn.remote_ip, rp: conn.remote_port,
                    sn: conn.send_next, rn: conn.recv_next }
    };
    send_flags(info.lip, info.lp, info.rip, info.rp, info.sn, info.rn, FIN | ACK);
    Ok(())
}

/// Set a socket option on the TCP connection for a given port.
pub fn set_option(port: u16, reuseaddr: Option<bool>, nodelay: Option<bool>,
                   rcvbuf: Option<u32>, sndbuf: Option<u32>) {
    let mut conns = TCP_CONNECTIONS.lock();
    if let Some(c) = conns.iter_mut().find(|c| c.local_port == port) {
        if let Some(v) = reuseaddr { c.reuseaddr = v; }
        if let Some(v) = nodelay   { c.nodelay   = v; }
        if let Some(v) = rcvbuf    { c.rcvbuf    = v; }
        if let Some(v) = sndbuf    { c.sndbuf    = v; }
    }
}
