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
}

/// Socket table.
static SOCKETS: Mutex<Vec<Socket>> = Mutex::new(Vec::new());
static NEXT_SOCKET_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Create a new socket.
pub fn socket_create(socket_type: SocketType) -> u64 {
    let id = NEXT_SOCKET_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut sockets = SOCKETS.lock();
    sockets.push(Socket {
        id,
        socket_type,
        local_port: 0,
        remote_ip: [0; 4],
        remote_port: 0,
        bound: false,
        connected: false,
    });
    id
}

/// Bind a socket to a local port.
pub fn socket_bind(id: u64, port: u16) -> Result<(), &'static str> {
    let mut sockets = SOCKETS.lock();
    let sock = sockets.iter_mut().find(|s| s.id == id)
        .ok_or("socket not found")?;

    if sock.bound {
        return Err("already bound");
    }

    match sock.socket_type {
        SocketType::Udp => {
            // Bind will be done on first recv.
            super::udp::bind(port)?;
        }
        SocketType::Tcp => {
            super::tcp::listen(port)?;
        }
    }

    sock.local_port = port;
    sock.bound = true;
    Ok(())
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
