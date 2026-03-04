//! TCP — Transmission Control Protocol (stub)
//!
//! Minimal TCP state machine for basic connections.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use super::Ipv4Address;

/// TCP flags.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// TCP connection state.
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

/// A TCP connection control block.
pub struct TcpConnection {
    pub local_ip: Ipv4Address,
    pub local_port: u16,
    pub remote_ip: Ipv4Address,
    pub remote_port: u16,
    pub state: TcpState,
    pub send_next: u32,
    pub send_unack: u32,
    pub recv_next: u32,
    pub recv_buffer: Vec<u8>,
    pub send_buffer: Vec<u8>,
}

/// A parsed TCP header.
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
}

impl TcpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        Some(TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset: data[12] >> 4,
            flags: data[13],
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
        })
    }

    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }
}

/// Active TCP connections.
static TCP_CONNECTIONS: Mutex<Vec<TcpConnection>> = Mutex::new(Vec::new());

/// Handle an incoming TCP segment.
pub fn handle_tcp(src_ip: Ipv4Address, _dst_ip: Ipv4Address, data: &[u8]) {
    let header = match TcpHeader::parse(data) {
        Some(h) => h,
        None => return,
    };

    let payload_start = header.header_len();
    let payload = if data.len() > payload_start {
        &data[payload_start..]
    } else {
        &[]
    };

    let mut conns = TCP_CONNECTIONS.lock();

    // Find matching connection.
    if let Some(conn) = conns.iter_mut().find(|c| {
        c.local_port == header.dst_port &&
        c.remote_ip == src_ip &&
        c.remote_port == header.src_port
    }) {
        process_segment(conn, &header, payload);
    } else if header.flags & SYN != 0 {
        // Check for listening sockets.
        if let Some(listener) = conns.iter_mut().find(|c| {
            c.local_port == header.dst_port && c.state == TcpState::Listen
        }) {
            // Accept connection → send SYN-ACK.
            listener.remote_ip = src_ip;
            listener.remote_port = header.src_port;
            listener.recv_next = header.seq_num.wrapping_add(1);
            listener.state = TcpState::SynReceived;

            send_tcp_flags(
                listener.local_ip, listener.local_port,
                src_ip, header.src_port,
                listener.send_next, listener.recv_next,
                SYN | ACK,
            );
            listener.send_next = listener.send_next.wrapping_add(1);
        } else {
            // Send RST for unsolicited SYN.
            send_tcp_flags(
                _dst_ip, header.dst_port,
                src_ip, header.src_port,
                0, header.seq_num.wrapping_add(1),
                RST | ACK,
            );
        }
    }
}

/// Process a TCP segment for an existing connection.
fn process_segment(conn: &mut TcpConnection, header: &TcpHeader, payload: &[u8]) {
    match conn.state {
        TcpState::SynSent => {
            if header.flags & (SYN | ACK) == (SYN | ACK) {
                conn.recv_next = header.seq_num.wrapping_add(1);
                conn.send_unack = header.ack_num;
                conn.state = TcpState::Established;
                send_tcp_flags(
                    conn.local_ip, conn.local_port,
                    conn.remote_ip, conn.remote_port,
                    conn.send_next, conn.recv_next,
                    ACK,
                );
                crate::serial_println!("[TCP] Connection established to {}:{}",
                    conn.remote_ip[0], conn.remote_port);
            }
        }
        TcpState::SynReceived => {
            if header.flags & ACK != 0 {
                conn.state = TcpState::Established;
                crate::serial_println!("[TCP] Connection established from {}:{}",
                    conn.remote_ip[0], conn.remote_port);
            }
        }
        TcpState::Established => {
            if !payload.is_empty() {
                conn.recv_buffer.extend_from_slice(payload);
                conn.recv_next = conn.recv_next.wrapping_add(payload.len() as u32);
                send_tcp_flags(
                    conn.local_ip, conn.local_port,
                    conn.remote_ip, conn.remote_port,
                    conn.send_next, conn.recv_next,
                    ACK,
                );
            }
            if header.flags & FIN != 0 {
                conn.recv_next = conn.recv_next.wrapping_add(1);
                conn.state = TcpState::CloseWait;
                send_tcp_flags(
                    conn.local_ip, conn.local_port,
                    conn.remote_ip, conn.remote_port,
                    conn.send_next, conn.recv_next,
                    ACK,
                );
            }
        }
        TcpState::FinWait1 => {
            if header.flags & ACK != 0 {
                conn.state = TcpState::FinWait2;
            }
        }
        TcpState::FinWait2 => {
            if header.flags & FIN != 0 {
                conn.recv_next = conn.recv_next.wrapping_add(1);
                conn.state = TcpState::TimeWait;
                send_tcp_flags(
                    conn.local_ip, conn.local_port,
                    conn.remote_ip, conn.remote_port,
                    conn.send_next, conn.recv_next,
                    ACK,
                );
            }
        }
        _ => {}
    }
}

/// Send a TCP packet with given flags (no payload).
fn send_tcp_flags(
    src_ip: Ipv4Address, src_port: u16,
    dst_ip: Ipv4Address, dst_port: u16,
    seq: u32, ack: u32,
    flags: u8,
) {
    let mut segment = Vec::with_capacity(20);
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.push(5 << 4); // Data offset = 5 (20 bytes)
    segment.push(flags);
    segment.extend_from_slice(&8192u16.to_be_bytes()); // Window
    segment.push(0); // Checksum placeholder
    segment.push(0);
    segment.push(0); // Urgent pointer
    segment.push(0);

    // TCP checksum over pseudo-header.
    let cksum = tcp_checksum(src_ip, dst_ip, &segment);
    segment[16] = (cksum >> 8) as u8;
    segment[17] = (cksum & 0xFF) as u8;

    super::ipv4::send_ipv4(dst_ip, super::ipv4::PROTO_TCP, &segment);
}

/// TCP checksum with pseudo-header.
fn tcp_checksum(src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_data: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_data.len());
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(super::ipv4::PROTO_TCP);
    pseudo.extend_from_slice(&(tcp_data.len() as u16).to_be_bytes());

    pseudo.extend_from_slice(tcp_data);
    // Zero the checksum field.
    let cksum_offset = 12 + 16;
    if pseudo.len() > cksum_offset + 1 {
        pseudo[cksum_offset] = 0;
        pseudo[cksum_offset + 1] = 0;
    }

    super::ipv4::checksum(&pseudo)
}

/// Listen on a TCP port.
pub fn listen(port: u16) -> Result<(), &'static str> {
    let mut conns = TCP_CONNECTIONS.lock();
    if conns.iter().any(|c| c.local_port == port && c.state == TcpState::Listen) {
        return Err("port already listening");
    }
    conns.push(TcpConnection {
        local_ip: super::our_ip(),
        local_port: port,
        remote_ip: [0; 4],
        remote_port: 0,
        state: TcpState::Listen,
        send_next: 1000, // Initial sequence number
        send_unack: 0,
        recv_next: 0,
        recv_buffer: Vec::new(),
        send_buffer: Vec::new(),
    });
    Ok(())
}

/// Read data from a TCP connection.
pub fn read(port: u16) -> Vec<u8> {
    let mut conns = TCP_CONNECTIONS.lock();
    if let Some(conn) = conns.iter_mut().find(|c| c.local_port == port && c.state == TcpState::Established) {
        let data = conn.recv_buffer.clone();
        conn.recv_buffer.clear();
        data
    } else {
        Vec::new()
    }
}

/// Send data over an established TCP connection.
pub fn send_data(port: u16, data: &[u8]) -> Result<usize, &'static str> {
    let mut conns = TCP_CONNECTIONS.lock();
    let conn = conns.iter_mut()
        .find(|c| c.local_port == port && c.state == TcpState::Established)
        .ok_or("no established connection on this port")?;

    if data.is_empty() { return Ok(0); }

    // Build TCP segment with payload
    let mut segment = Vec::with_capacity(20 + data.len());
    segment.extend_from_slice(&conn.local_port.to_be_bytes());
    segment.extend_from_slice(&conn.remote_port.to_be_bytes());
    segment.extend_from_slice(&conn.send_next.to_be_bytes());
    segment.extend_from_slice(&conn.recv_next.to_be_bytes());
    segment.push(5 << 4); // Data offset = 5 (20 bytes header)
    segment.push(PSH | ACK); // flags
    segment.extend_from_slice(&8192u16.to_be_bytes()); // Window
    segment.push(0); // Checksum placeholder
    segment.push(0);
    segment.push(0); // Urgent pointer
    segment.push(0);
    segment.extend_from_slice(data);

    // Compute TCP checksum
    let cksum = tcp_checksum(conn.local_ip, conn.remote_ip, &segment);
    segment[16] = (cksum >> 8) as u8;
    segment[17] = (cksum & 0xFF) as u8;

    let remote_ip = conn.remote_ip;
    conn.send_next = conn.send_next.wrapping_add(data.len() as u32);

    // Drop the lock before sending
    drop(conns);
    super::ipv4::send_ipv4(remote_ip, super::ipv4::PROTO_TCP, &segment);

    Ok(data.len())
}

/// Initiate a TCP connection (active open).
pub fn connect(remote_ip: Ipv4Address, remote_port: u16) -> Result<u16, &'static str> {
    let mut conns = TCP_CONNECTIONS.lock();

    // Allocate an ephemeral local port (49152-65535)
    static NEXT_EPHEMERAL: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(49152);
    let local_port = NEXT_EPHEMERAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let local_ip = super::our_ip();
    conns.push(TcpConnection {
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        state: TcpState::SynSent,
        send_next: 1000,
        send_unack: 1000,
        recv_next: 0,
        recv_buffer: Vec::new(),
        send_buffer: Vec::new(),
    });

    // Send SYN
    drop(conns);
    send_tcp_flags(
        local_ip, local_port,
        remote_ip, remote_port,
        1000, 0,
        SYN,
    );

    Ok(local_port)
}

/// Close a TCP connection.
pub fn close(port: u16) -> Result<(), &'static str> {
    let mut conns = TCP_CONNECTIONS.lock();
    let conn = conns.iter_mut()
        .find(|c| c.local_port == port &&
              (c.state == TcpState::Established || c.state == TcpState::CloseWait))
        .ok_or("no connection to close")?;

    let local_ip = conn.local_ip;
    let local_port = conn.local_port;
    let remote_ip = conn.remote_ip;
    let remote_port = conn.remote_port;
    let send_next = conn.send_next;
    let recv_next = conn.recv_next;

    if conn.state == TcpState::Established {
        conn.state = TcpState::FinWait1;
    } else {
        // CloseWait → LastAck
        conn.state = TcpState::LastAck;
    }

    drop(conns);

    send_tcp_flags(
        local_ip, local_port,
        remote_ip, remote_port,
        send_next, recv_next,
        FIN | ACK,
    );

    Ok(())
}
