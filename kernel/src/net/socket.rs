//! Socket — User-facing network socket abstraction.
//!
//! Provides a unified API over UDP and TCP.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use super::Ipv4Address;

/// Socket type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocketType {
    Udp,
    Tcp,
}

/// A network socket.
pub struct Socket {
    pub id: u64,
    pub socket_type: SocketType,
    pub local_port: u16,
    pub remote_ip: Ipv4Address,
    pub remote_port: u16,
    pub bound: bool,
    pub connected: bool,
    // Socket options
    pub reuseaddr: bool,
    pub keepalive: bool,
    pub nodelay:   bool,
    pub rcvbuf:    u32,
    pub sndbuf:    u32,
    pub linger:    bool,
    pub so_error:  u32,
}

/// Socket table.
pub static SOCKETS: Mutex<Vec<Socket>> = Mutex::new(Vec::new());
static NEXT_SOCKET_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Create a new socket.
pub fn socket_create(socket_type: SocketType) -> u64 {
    let id = NEXT_SOCKET_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut sockets = SOCKETS.lock();
    sockets.push(Socket {
        id,
        socket_type,
        local_port:  0,
        remote_ip:   [0; 4],
        remote_port: 0,
        bound:       false,
        connected:   false,
        reuseaddr:   false,
        keepalive:   false,
        nodelay:     false,
        rcvbuf:      87380,
        sndbuf:      131072,
        linger:      false,
        so_error:    0,
    });
    id
}

// ── Socket option constants ───────────────────────────────────────────────────

const SOL_SOCKET:  u64 = 1;
const IPPROTO_TCP: u64 = 6;
const SO_ERROR:    u64 = 4;
const SO_TYPE:     u64 = 3;
const SO_REUSEADDR:u64 = 2;
const SO_KEEPALIVE:u64 = 9;
const SO_RCVBUF:   u64 = 8;
const SO_SNDBUF:   u64 = 7;
const SO_LINGER:   u64 = 13;
const TCP_NODELAY: u64 = 1;

/// Set a socket option.  Returns 0 on success, -errno on error.
pub fn socket_setsockopt(id: u64, level: u64, optname: u64, val: u32) -> i32 {
    let mut sockets = SOCKETS.lock();
    let sock = match sockets.iter_mut().find(|s| s.id == id) {
        Some(s) => s,
        None => return -9, // EBADF
    };
    match (level, optname) {
        (SOL_SOCKET,  SO_REUSEADDR) => { sock.reuseaddr = val != 0; }
        (SOL_SOCKET,  SO_KEEPALIVE) => { sock.keepalive = val != 0; }
        (SOL_SOCKET,  SO_RCVBUF)    => { sock.rcvbuf    = val; }
        (SOL_SOCKET,  SO_SNDBUF)    => { sock.sndbuf    = val; }
        (SOL_SOCKET,  SO_LINGER)    => { sock.linger    = val != 0; }
        (IPPROTO_TCP, TCP_NODELAY)  => { sock.nodelay   = val != 0; }
        _ => {} // ignore unknown options
    }
    0
}

/// Get a socket option value.
pub fn socket_getsockopt(id: u64, level: u64, optname: u64) -> u32 {
    let sockets = SOCKETS.lock();
    let sock = match sockets.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return 0,
    };
    match (level, optname) {
        (SOL_SOCKET,  SO_ERROR)     => sock.so_error,
        (SOL_SOCKET,  SO_TYPE)      => if sock.socket_type == SocketType::Tcp { 1 } else { 2 },
        (SOL_SOCKET,  SO_REUSEADDR) => sock.reuseaddr as u32,
        (SOL_SOCKET,  SO_KEEPALIVE) => sock.keepalive as u32,
        (SOL_SOCKET,  SO_RCVBUF)    => sock.rcvbuf,
        (SOL_SOCKET,  SO_SNDBUF)    => sock.sndbuf,
        (SOL_SOCKET,  SO_LINGER)    => sock.linger as u32,
        (IPPROTO_TCP, TCP_NODELAY)  => sock.nodelay as u32,
        _ => 0,
    }
}

/// Bind a socket to a local port.
///
/// If `port == 0`, an ephemeral port is allocated from the IANA dynamic
/// range (49152–65535) per RFC 6335 §6.  The caller can retrieve the
/// chosen port via [`socket_local_addr`] (per `getsockname(2)`).
pub fn socket_bind(id: u64, port: u16) -> Result<(), &'static str> {
    let mut sockets = SOCKETS.lock();
    let sock = sockets.iter_mut().find(|s| s.id == id)
        .ok_or("socket not found")?;

    if sock.bound {
        return Err("already bound");
    }

    let actual_port = if port == 0 {
        // Allocate an ephemeral port.  Try up to MAX_TRIES candidates
        // before giving up — covers the case where the dynamic range is
        // densely populated with bound sockets.
        const MAX_TRIES: u16 = 1024;
        let mut found: Option<u16> = None;
        for _ in 0..MAX_TRIES {
            let candidate = NEXT_EPHEMERAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            // Wrap from 65535 back to 49152.
            let candidate = if candidate < 49152 {
                NEXT_EPHEMERAL.store(49153, core::sync::atomic::Ordering::Relaxed);
                49152
            } else {
                candidate
            };
            // Probe: is this port already bound on this socket type?
            let collision = match sock.socket_type {
                SocketType::Udp => super::udp::is_bound(candidate),
                SocketType::Tcp => super::tcp::is_listening(candidate),
            };
            if !collision { found = Some(candidate); break; }
        }
        found.ok_or("no ephemeral port available")?
    } else {
        port
    };

    match sock.socket_type {
        SocketType::Udp => {
            // Bind will be done on first recv.
            super::udp::bind(actual_port)?;
        }
        SocketType::Tcp => {
            super::tcp::listen(actual_port)?;
        }
    }

    sock.local_port = actual_port;
    sock.bound = true;
    Ok(())
}

/// Ephemeral-port allocator for bind(port=0) — IANA dynamic range
/// 49152–65535 (RFC 6335 §6).  Wraps when exhausted.
static NEXT_EPHEMERAL: core::sync::atomic::AtomicU16 =
    core::sync::atomic::AtomicU16::new(49152);

/// Look up a socket's bound 4-tuple for `getsockname(2)`.
///
/// Returns `(local_ip, local_port)` when the socket is bound, else
/// returns `(0.0.0.0, 0)` — POSIX permits a zeroed reply for an
/// unbound or unspecified-address socket per IEEE 1003.1.
///
/// For TCP, the local IP is read from the underlying TCB (which records
/// the actual bound source IP at listen()/connect() time); for UDP we
/// fall back to the host's primary IPv4 address.  Listeners bound with
/// INADDR_ANY appear as `0.0.0.0:port`.
pub fn socket_local_addr(id: u64) -> (Ipv4Address, u16) {
    let sockets = SOCKETS.lock();
    let sock = match sockets.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return ([0; 4], 0),
    };
    if !sock.bound {
        return ([0; 4], 0);
    }
    let port = sock.local_port;
    let socket_type = sock.socket_type;
    drop(sockets);

    let ip = match socket_type {
        SocketType::Tcp => super::tcp::lookup_local_ip(port).unwrap_or([0; 4]),
        SocketType::Udp => super::our_ip(),
    };
    (ip, port)
}

/// Look up a socket's connected peer 4-tuple for `getpeername(2)`.
///
/// Returns `Some((remote_ip, remote_port))` only when the socket is
/// connected; otherwise returns `None` (the caller should report
/// `ENOTCONN` per IEEE 1003.1 §getpeername).
pub fn socket_peer_addr(id: u64) -> Option<(Ipv4Address, u16)> {
    let sockets = SOCKETS.lock();
    let sock = sockets.iter().find(|s| s.id == id)?;
    if !sock.connected {
        return None;
    }
    Some((sock.remote_ip, sock.remote_port))
}

/// Send data through a socket.
pub fn socket_send(id: u64, data: &[u8]) -> Result<usize, &'static str> {
    let sockets = SOCKETS.lock();
    let sock = sockets.iter().find(|s| s.id == id)
        .ok_or("socket not found")?;

    let socket_type = sock.socket_type;
    let remote_ip = sock.remote_ip;
    let local_port = sock.local_port;
    let remote_port = sock.remote_port;
    let bound = sock.bound;
    drop(sockets);

    match socket_type {
        SocketType::Udp => {
            if remote_ip == [0; 4] {
                return Err("no destination");
            }
            super::udp::send(remote_ip, local_port, remote_port, data);
            Ok(data.len())
        }
        SocketType::Tcp => {
            if !bound {
                return Err("not bound");
            }
            super::tcp::send_data(local_port, data)
        }
    }
}

/// Send data to a specific destination (UDP).
pub fn socket_sendto(
    id: u64,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
) -> Result<usize, &'static str> {
    let sockets = SOCKETS.lock();
    let sock = sockets.iter().find(|s| s.id == id)
        .ok_or("socket not found")?;

    if sock.socket_type != SocketType::Udp {
        return Err("sendto only for UDP");
    }

    super::udp::send(dst_ip, sock.local_port, dst_port, data);
    Ok(data.len())
}

/// Receive data from a socket (non-blocking).
pub fn socket_recv(id: u64) -> Result<Vec<u8>, &'static str> {
    let sockets = SOCKETS.lock();
    let sock = sockets.iter().find(|s| s.id == id)
        .ok_or("socket not found")?;

    match sock.socket_type {
        SocketType::Udp => {
            if !sock.bound {
                return Err("not bound");
            }
            if let Some(datagram) = super::udp::recv(sock.local_port) {
                Ok(datagram.data)
            } else {
                Ok(Vec::new())
            }
        }
        SocketType::Tcp => {
            if !sock.bound {
                return Err("not bound");
            }
            Ok(super::tcp::read(sock.local_port))
        }
    }
}

/// Receive data and the sender 4-tuple (for `recvfrom(2)`).
///
/// Per IEEE 1003.1 §recvfrom: when the caller supplies a non-NULL
/// `address` argument, the implementation writes the source address of
/// the returned message.  For unconnected datagram sockets this is the
/// sender of the dequeued datagram; for connection-mode sockets it is
/// the connected peer.
///
/// Returns `(payload, src_ip, src_port)`.  When no data is available
/// the payload is empty and the address is the zero 4-tuple — callers
/// must check the byte count before consulting the address (matches the
/// existing non-blocking semantics of [`socket_recv`]).
pub fn socket_recvfrom(id: u64) -> Result<(Vec<u8>, Ipv4Address, u16), &'static str> {
    let sockets = SOCKETS.lock();
    let sock = sockets.iter().find(|s| s.id == id)
        .ok_or("socket not found")?;

    match sock.socket_type {
        SocketType::Udp => {
            if !sock.bound {
                return Err("not bound");
            }
            let local_port = sock.local_port;
            drop(sockets);
            if let Some(datagram) = super::udp::recv(local_port) {
                let src_ip   = datagram.src_ip;
                let src_port = datagram.src_port;
                Ok((datagram.data, src_ip, src_port))
            } else {
                Ok((Vec::new(), [0; 4], 0))
            }
        }
        SocketType::Tcp => {
            if !sock.bound {
                return Err("not bound");
            }
            // For connection-mode sockets, `recvfrom`'s source address is
            // the connected peer (RFC 793 + IEEE 1003.1).  An unconnected
            // listener wouldn't have any in-band data to read here, so a
            // zero peer in that edge case is harmless.
            let peer_ip   = sock.remote_ip;
            let peer_port = sock.remote_port;
            let local_port = sock.local_port;
            drop(sockets);
            let data = super::tcp::read(local_port);
            Ok((data, peer_ip, peer_port))
        }
    }
}

/// Check if a socket has incoming data available (used by poll).
pub fn socket_has_data(id: u64) -> bool {
    let sockets = SOCKETS.lock();
    let sock = match sockets.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return false,
    };
    if !sock.bound { return false; }
    match sock.socket_type {
        SocketType::Udp => super::udp::has_data(sock.local_port),
        SocketType::Tcp => super::tcp::has_data(sock.local_port),
    }
}

/// Close a socket.
pub fn socket_close(id: u64) {
    let mut sockets = SOCKETS.lock();
    if let Some(idx) = sockets.iter().position(|s| s.id == id) {
        let sock = &sockets[idx];
        let socket_type = sock.socket_type;
        let local_port = sock.local_port;
        let bound = sock.bound;
        if bound {
            match socket_type {
                SocketType::Udp => super::udp::unbind(local_port),
                SocketType::Tcp => {
                    drop(sockets);
                    let _ = super::tcp::close(local_port);
                    // Re-lock to remove entry
                    let mut sockets = SOCKETS.lock();
                    if let Some(idx) = sockets.iter().position(|s| s.id == id) {
                        sockets.remove(idx);
                    }
                    return;
                }
            }
        }
        sockets.remove(idx);
    }
}

/// Set the remote endpoint for a socket and initiate TCP connection if applicable.
pub fn socket_connect(id: u64, remote_ip: Ipv4Address, remote_port: u16) -> Result<(), &'static str> {
    let mut sockets = SOCKETS.lock();
    let sock = sockets.iter_mut().find(|s| s.id == id)
        .ok_or("socket not found")?;

    sock.remote_ip = remote_ip;
    sock.remote_port = remote_port;
    sock.connected = true;

    if sock.socket_type == SocketType::Tcp {
        let local_port = super::tcp::connect(remote_ip, remote_port)?;
        sock.local_port = local_port;
        sock.bound = true;
    }
    Ok(())
}
