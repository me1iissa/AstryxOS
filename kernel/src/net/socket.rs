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
    // Half-close state per IEEE 1003.1 §shutdown.
    // `shut_rd` disables further receives (recv returns 0 / EOF).
    // `shut_wr` disables further sends (send returns -EPIPE) and, for
    // connection-mode sockets, signals end-of-stream to the peer (TCP FIN).
    pub shut_rd:   bool,
    pub shut_wr:   bool,
    // Open-file-description reference count.  One AF_INET `Socket` entry is the
    // shared "open file description" (POSIX.1-2017 §2.14) behind potentially
    // many fds — fork/vfork duplicates the fd table, dup(2) clones an fd, and
    // SCM_RIGHTS could pass one.  Each such duplicate adds a reference; the
    // socket (and its TCP/UDP TCB) is torn down only when the LAST reference is
    // closed.  Without this, the FIRST `close(2)` in any process destroys the
    // socket for every other holder — the bug that left a forked dropbear
    // session child's accepted-connection fd dangling (getpeername → ENOTCONN
    // → "Socket not connected" early exit).  Mirrors the AF_UNIX `ref_count`
    // model.  Initialised to 1 by every constructor (the fd that created it).
    pub ref_count: u32,
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
        shut_rd:     false,
        shut_wr:     false,
        ref_count:   1, // the fd returned by socket(2)
    });
    id
}

/// Create an accept-side TCP socket entry bound to an existing child
/// TCB identified by `(local_port, peer_ip, peer_port)`.
///
/// Used by `accept(2)` to materialise a user-visible socket fd over a
/// child TCB that was already brought up to `Established` by the
/// inbound SYN path in [`super::tcp::handle_tcp`].  The returned
/// socket id carries the full 4-tuple so subsequent `send`/`recv`
/// route via the per-connection [`super::tcp::send_data_to`] /
/// [`super::tcp::read_from`] primitives rather than the listener-port
/// fallback — required when several concurrent client sessions share
/// one listening port (RFC 793 §3.8 demultiplexing).
///
/// The new socket is marked `bound = true` (the underlying TCB is
/// already on the wire) and `connected = true` (the peer 4-tuple is
/// known), matching the state a `connect(2)`ed socket would be in
/// after its 3-way handshake completed.
pub fn socket_create_accepted(local_port: u16,
                              peer_ip:    Ipv4Address,
                              peer_port:  u16) -> u64 {
    let id = NEXT_SOCKET_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut sockets = SOCKETS.lock();
    sockets.push(Socket {
        id,
        socket_type: SocketType::Tcp,
        local_port,
        remote_ip:   peer_ip,
        remote_port: peer_port,
        bound:       true,
        connected:   true,
        reuseaddr:   false,
        keepalive:   false,
        nodelay:     false,
        rcvbuf:      87380,
        sndbuf:      131072,
        linger:      false,
        so_error:    0,
        shut_rd:     false,
        shut_wr:     false,
        ref_count:   1, // the fd returned by accept(2)
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
    // When SO_RCVBUF is set on a *bound* UDP socket we must propagate the
    // cap to the per-port UDP receive buffer (which enforces it in the RX
    // path, per `setsockopt(2)`).  TCP is analogous: the per-connection
    // `recv_buffer` cap lives on the TCB, so propagate to `tcp::set_option`.
    // Capture what's needed under the SOCKETS lock, then release it before
    // touching the protocol lock — lock order is socket → protocol, never
    // inverted.
    let mut udp_rcvbuf_update: Option<(u16, usize)> = None;
    let mut tcp_opt_update: Option<(u16, u32)> = None;
    match (level, optname) {
        (SOL_SOCKET,  SO_REUSEADDR) => { sock.reuseaddr = val != 0; }
        (SOL_SOCKET,  SO_KEEPALIVE) => { sock.keepalive = val != 0; }
        (SOL_SOCKET,  SO_RCVBUF)    => {
            sock.rcvbuf = val;
            if sock.socket_type == SocketType::Udp && sock.bound {
                udp_rcvbuf_update = Some((sock.local_port, val as usize));
            } else if sock.socket_type == SocketType::Tcp && sock.bound {
                tcp_opt_update = Some((sock.local_port, val));
            }
        }
        (SOL_SOCKET,  SO_SNDBUF)    => { sock.sndbuf    = val; }
        (SOL_SOCKET,  SO_LINGER)    => { sock.linger    = val != 0; }
        (IPPROTO_TCP, TCP_NODELAY)  => { sock.nodelay   = val != 0; }
        _ => {} // ignore unknown options
    }
    drop(sockets);
    if let Some((port, rcvbuf)) = udp_rcvbuf_update {
        super::udp::set_rcvbuf(port, rcvbuf);
    }
    if let Some((port, rcvbuf)) = tcp_opt_update {
        super::tcp::set_option(port, None, None, Some(rcvbuf), None);
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
        alloc_ephemeral_port(sock.socket_type)
            .ok_or("no ephemeral port available")?
    } else {
        port
    };

    // If the application set SO_RCVBUF before bind (the common pattern for
    // a high-throughput datagram consumer), carry that cap into the new
    // UDP binding.  The `Socket.rcvbuf` initial value (87380) marks "not
    // explicitly set"; only a different value is treated as an override,
    // so an untouched socket keeps the UDP `net.core.rmem_default` cap.
    let udp_rcvbuf_override = if sock.socket_type == SocketType::Udp
        && sock.rcvbuf != 87380 {
        Some(sock.rcvbuf as usize)
    } else {
        None
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
    drop(sockets);
    if let Some(rcvbuf) = udp_rcvbuf_override {
        super::udp::set_rcvbuf(actual_port, rcvbuf);
    }
    Ok(())
}

/// Allocate an ephemeral local port from the IANA dynamic range
/// (49152–65535, RFC 6335 §6).  Probes for collisions against the
/// per-protocol binding table so a freshly-allocated port is not
/// already in use by another socket.  Returns `None` only when the
/// entire dynamic range is contested by sockets the caller has not
/// torn down — `MAX_TRIES` (1024) is well above any realistic guest
/// workload.
///
/// Public-spec ref: RFC 6335 §6 (Service Name and Transport Protocol
/// Port Number Registry) — ephemeral allocations MUST come from the
/// 49152–65535 range and MUST avoid clashing with an in-use port.
fn alloc_ephemeral_port(socket_type: SocketType) -> Option<u16> {
    const MAX_TRIES: u16 = 1024;
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
        let collision = match socket_type {
            SocketType::Udp => super::udp::is_bound(candidate),
            SocketType::Tcp => super::tcp::is_listening(candidate),
        };
        if !collision { return Some(candidate); }
    }
    None
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

    // Per IEEE 1003.1 §shutdown: after SHUT_WR on the local end, send(2)
    // must fail with EPIPE.  The errno gets translated by the syscall
    // layer; here we surface it via a distinct error string that the
    // caller maps to -EPIPE.
    if sock.shut_wr {
        return Err("EPIPE");
    }

    let socket_type = sock.socket_type;
    let remote_ip = sock.remote_ip;
    let mut local_port = sock.local_port;
    let remote_port = sock.remote_port;
    let bound = sock.bound;
    let connected = sock.connected;
    drop(sockets);

    let r = match socket_type {
        SocketType::Udp => {
            if remote_ip == [0; 4] {
                return Err("no destination");
            }
            // Auto-bind to an ephemeral port if the caller never called
            // bind(2) — required so the reply has somewhere to land.
            // Mirrors `man 2 send`/`man 2 sendto`: "If the socket is a
            // SOCK_DGRAM socket [...] the socket need not be bound; the
            // protocol will assign a port automatically." (RFC 6335 §6.)
            if !bound {
                local_port = ensure_udp_local_port(id)?;
            }
            super::udp::send(remote_ip, local_port, remote_port, data);
            Ok(data.len())
        }
        SocketType::Tcp => {
            if !bound {
                return Err("not bound");
            }
            // When the socket carries a known peer 4-tuple (set by
            // `connect(2)` or `accept(2)` via socket_create_accepted),
            // route the segment to the matching TCB strictly by tuple
            // — otherwise `send_data(port)` would match the first
            // Established TCB on the listener's local port and mis-
            // address the bytes when multiple peers share that port
            // (RFC 793 §3.8 demultiplexing).
            if connected && remote_port != 0 {
                super::tcp::send_data_to(local_port, remote_ip, remote_port, data)
            } else {
                super::tcp::send_data(local_port, data)
            }
        }
    };
    // Attribute outbound bytes to the caller.  Counted on success only.
    if let Ok(n) = r.as_ref() {
        crate::proc::proc_metrics::bump_net_write(
            crate::proc::current_pid_lockless(), *n as u64);
    }
    r
}

/// Send data to a specific destination (UDP).
///
/// Per `man 2 sendto` / IEEE 1003.1 §sendto: a SOCK_DGRAM socket need not
/// be bound before the first send.  When the caller has not bound a local
/// port, lazily allocate an ephemeral one from the IANA dynamic range so
/// the eventual reply can be demultiplexed back to this socket.  Without
/// this lazy bind, the wire packet's source port is zero and the reply
/// from the peer matches no per-port UDP binding — the textbook DNS
/// "Operation timed out" symptom that triggered this fix.
pub fn socket_sendto(
    id: u64,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
) -> Result<usize, &'static str> {
    let (already_bound, mut local_port) = {
        let sockets = SOCKETS.lock();
        let sock = sockets.iter().find(|s| s.id == id)
            .ok_or("socket not found")?;

        if sock.shut_wr {
            return Err("EPIPE");
        }
        if sock.socket_type != SocketType::Udp {
            return Err("sendto only for UDP");
        }
        (sock.bound, sock.local_port)
    };

    if !already_bound {
        local_port = ensure_udp_local_port(id)?;
    }

    super::udp::send(dst_ip, local_port, dst_port, data);
    crate::proc::proc_metrics::bump_net_write(
        crate::proc::current_pid_lockless(), data.len() as u64);
    Ok(data.len())
}

/// Ensure a UDP socket has a bound local port; allocate an ephemeral one
/// from the IANA dynamic range (RFC 6335 §6) if not.  Returns the local
/// port the caller should stamp into the outgoing datagram's source-port
/// field so the reply demultiplexes back to this socket.
///
/// Racing callers (two concurrent sends on the same unbound socket) are
/// resolved by the SOCKETS-lock check: only the first observer of
/// `!sock.bound` performs the bind, the second sees `bound==true` and
/// reuses the already-allocated port.
fn ensure_udp_local_port(id: u64) -> Result<u16, &'static str> {
    // Allocate before re-acquiring the per-socket lock so the alloc
    // (which probes the udp::is_bound table) doesn't compose two locks.
    let port = alloc_ephemeral_port(SocketType::Udp)
        .ok_or("no ephemeral port available")?;
    super::udp::bind(port)?;

    let mut sockets = SOCKETS.lock();
    let sock = sockets.iter_mut().find(|s| s.id == id)
        .ok_or("socket not found")?;
    if sock.bound {
        // Lost the race; release the port we just reserved and use the
        // winner's port.  Without this branch we'd leak `port` in
        // UDP_BINDINGS until the socket closed.
        super::udp::unbind(port);
        return Ok(sock.local_port);
    }
    sock.local_port = port;
    sock.bound = true;
    Ok(port)
}

/// Outcome of a non-blocking socket receive, with the three states the
/// POSIX recv contract distinguishes:
///
///   * `Data(bytes)` — at least one byte (or one datagram) was dequeued.
///   * `Eof`         — orderly end-of-stream: the read direction was shut
///                     down (`shutdown(SHUT_RD)`) or, for a connection-mode
///                     socket, the peer has sent FIN and no buffered data
///                     remains.  `recv(2)` must report this as a 0-byte
///                     return (IEEE 1003.1 §recv: "a return value of 0
///                     indicates the peer has performed an orderly
///                     shutdown").
///   * `WouldBlock`  — no data is currently available but the endpoint is
///                     still live (a connectionless datagram socket with an
///                     empty queue, or a connection-mode socket whose peer
///                     has NOT closed).  On an `O_NONBLOCK` fd `recv(2)`
///                     must report this as `-1`/`EAGAIN`, NEVER as 0 — a 0
///                     return would falsely signal EOF and send an event
///                     loop into a busy re-read spin.
///
/// The distinction matters because [`socket_recv`] collapses `Eof` and
/// `WouldBlock` into the same empty `Ok(Vec::new())`, which left the
/// recvmsg/read syscall arms unable to choose between a 0 return (EOF) and
/// `-EAGAIN` (would-block).  See `recvmsg(2)`, `recv(2)`, POSIX.1-2017
/// §2.10.6 (Socket Receive Queue).
pub enum RecvOutcome {
    Data(Vec<u8>),
    Eof,
    WouldBlock,
}

/// Receive from a socket (non-blocking) with an explicit [`RecvOutcome`].
///
/// This is the EAGAIN-correct sibling of [`socket_recv`]: it tells the
/// caller whether an empty result is end-of-stream (`Eof` → 0 return) or a
/// transient empty queue (`WouldBlock` → `-EAGAIN`).  `recvmsg(2)` /
/// `recv(2)` on a non-blocking socket with no data pending must return
/// `EAGAIN` per IEEE 1003.1; returning 0 there is an EOF lie that drives a
/// polled reactor into a tight re-read loop.
///
/// `max` is the caller's buffer capacity.  For a STREAM (TCP) socket the
/// dequeue is bounded by it: per IEEE Std 1003.1-2017 §recv / recv(2), data
/// in excess of the supplied buffer SHALL remain in the receive queue for
/// subsequent receives.  An unbounded drain here silently destroyed the
/// surplus, which breaks any exact-length record reader (e.g. a TLS client
/// reading the 5-byte record header first: the header read consumed the
/// entire buffered server flight, and the handshake then waited forever for
/// bytes the kernel had discarded).  For a DATAGRAM (UDP) socket the whole
/// datagram is returned and the syscall layer truncates (excess datagram
/// bytes are discarded per §recvfrom — that is SOCK_DGRAM-only semantics).
pub fn socket_recv_status(id: u64, max: usize) -> Result<RecvOutcome, &'static str> {
    let sockets = SOCKETS.lock();
    let sock = sockets.iter().find(|s| s.id == id)
        .ok_or("socket not found")?;

    // shutdown(SHUT_RD): orderly EOF regardless of socket type.
    if sock.shut_rd {
        return Ok(RecvOutcome::Eof);
    }

    match sock.socket_type {
        SocketType::Udp => {
            if !sock.bound {
                return Err("not bound");
            }
            // UDP is connectionless: an empty receive queue is never EOF,
            // it is always "no datagram yet" — i.e. would-block.
            match super::udp::recv(sock.local_port) {
                Some(datagram) => {
                    crate::proc::proc_metrics::bump_net_read(
                        crate::proc::current_pid_lockless(),
                        datagram.data.len() as u64);
                    Ok(RecvOutcome::Data(datagram.data))
                }
                None => Ok(RecvOutcome::WouldBlock),
            }
        }
        SocketType::Tcp => {
            if !sock.bound {
                return Err("not bound");
            }
            let data = if sock.connected && sock.remote_port != 0 {
                super::tcp::read_from_n(sock.local_port, sock.remote_ip,
                                        sock.remote_port, max)
            } else {
                super::tcp::read_n(sock.local_port, max)
            };
            if !data.is_empty() {
                crate::proc::proc_metrics::bump_net_read(
                    crate::proc::current_pid_lockless(), data.len() as u64);
                return Ok(RecvOutcome::Data(data));
            }
            // Empty stream read: distinguish peer-FIN EOF from would-block.
            // A connection that has received the peer's FIN sits in
            // CloseWait (or has progressed to LastAck/Closed/TimeWait); with
            // no buffered data that is an orderly EOF (RFC 9293 §3.5).  An
            // Established (or still-handshaking) connection with an empty
            // buffer is would-block.
            //
            // Use the peer-aware (4-tuple) lookup when the connection's
            // remote endpoint is known, exactly as `read_from` (above) and
            // `socket_read_closed` do.  A port-only lookup returns whichever
            // TCB sits first in the table for this local port — which on a
            // socket sharing its port with a listener (or another session)
            // is the wrong TCB, so the EOF edge is read off a sibling and a
            // reader spins on WouldBlock instead of completing (RFC 9293
            // §3.6 demultiplexing).
            let state = if sock.connected && sock.remote_port != 0 {
                super::tcp::get_state_for(sock.local_port,
                                          sock.remote_ip, sock.remote_port)
            } else {
                super::tcp::get_state(sock.local_port)
            };
            let peer_closed = match state {
                Some(st) => matches!(st,
                    super::tcp::TcpState::CloseWait
                    | super::tcp::TcpState::LastAck
                    | super::tcp::TcpState::TimeWait
                    | super::tcp::TcpState::Closed),
                // No TCB found: the flow is gone — treat as EOF so a reader
                // drains to completion rather than spinning.
                None => true,
            };
            if peer_closed { Ok(RecvOutcome::Eof) } else { Ok(RecvOutcome::WouldBlock) }
        }
    }
}

/// Like [`socket_recv_status`] but also returns the source 4-tuple of the
/// data that was dequeued, for callers (recvmsg(2)) that must marshal
/// `msg_name`.
///
/// For UDP this is the true wire source of the datagram (`src_ip`/`src_port`
/// from the IP/UDP headers); a connection-mode resolver such as musl's
/// `__res_msend` validates this byte-for-byte against the nameserver it
/// queried and silently drops a reply whose source does not match (RFC 1035
/// §7.3, recvmsg(2)).  For TCP the source is the connected peer (RFC 793).
/// On a non-`Data` outcome the returned address is the connected peer (or a
/// zero 4-tuple for an unconnected datagram socket), which `recvmsg(2)`
/// leaves unused because `msg_namelen` is only written on a real message.
///
/// `max` bounds the stream dequeue exactly as in [`socket_recv_status`]
/// (IEEE Std 1003.1-2017 §recv: excess STREAM bytes remain queued; datagram
/// truncation stays at the syscall layer).
pub fn socket_recv_status_from(id: u64, max: usize)
    -> Result<(RecvOutcome, Ipv4Address, u16), &'static str>
{
    let sockets = SOCKETS.lock();
    let sock = sockets.iter().find(|s| s.id == id)
        .ok_or("socket not found")?;

    // shutdown(SHUT_RD): orderly EOF regardless of socket type.  Report the
    // connected peer as the (unused) source so the tuple is well-formed.
    if sock.shut_rd {
        return Ok((RecvOutcome::Eof, sock.remote_ip, sock.remote_port));
    }

    match sock.socket_type {
        SocketType::Udp => {
            if !sock.bound {
                return Err("not bound");
            }
            let local_port = sock.local_port;
            drop(sockets);
            match super::udp::recv(local_port) {
                Some(datagram) => {
                    crate::proc::proc_metrics::bump_net_read(
                        crate::proc::current_pid_lockless(),
                        datagram.data.len() as u64);
                    let src_ip   = datagram.src_ip;
                    let src_port = datagram.src_port;
                    Ok((RecvOutcome::Data(datagram.data), src_ip, src_port))
                }
                // UDP is connectionless: empty queue is would-block, never EOF.
                None => Ok((RecvOutcome::WouldBlock, [0; 4], 0)),
            }
        }
        SocketType::Tcp => {
            if !sock.bound {
                return Err("not bound");
            }
            let peer_ip   = sock.remote_ip;
            let peer_port = sock.remote_port;
            let data = if sock.connected && sock.remote_port != 0 {
                super::tcp::read_from_n(sock.local_port, sock.remote_ip,
                                        sock.remote_port, max)
            } else {
                super::tcp::read_n(sock.local_port, max)
            };
            if !data.is_empty() {
                crate::proc::proc_metrics::bump_net_read(
                    crate::proc::current_pid_lockless(), data.len() as u64);
                return Ok((RecvOutcome::Data(data), peer_ip, peer_port));
            }
            // Empty stream read: distinguish peer-FIN EOF from would-block
            // exactly as socket_recv_status does (RFC 9293 §3.5).  Peer-aware
            // (4-tuple) lookup when the remote endpoint is known, so the EOF
            // edge is read off THIS connection and not a sibling sharing the
            // local port (RFC 9293 §3.6).
            let state = if sock.connected && sock.remote_port != 0 {
                super::tcp::get_state_for(sock.local_port,
                                          sock.remote_ip, sock.remote_port)
            } else {
                super::tcp::get_state(sock.local_port)
            };
            let peer_closed = match state {
                Some(st) => matches!(st,
                    super::tcp::TcpState::CloseWait
                    | super::tcp::TcpState::LastAck
                    | super::tcp::TcpState::TimeWait
                    | super::tcp::TcpState::Closed),
                None => true,
            };
            if peer_closed {
                Ok((RecvOutcome::Eof, peer_ip, peer_port))
            } else {
                Ok((RecvOutcome::WouldBlock, peer_ip, peer_port))
            }
        }
    }
}

/// Receive data from a socket (non-blocking).
///
/// `max` bounds the stream dequeue — see [`socket_recv_status`]
/// (IEEE Std 1003.1-2017 §recv: excess STREAM bytes remain queued).
pub fn socket_recv(id: u64, max: usize) -> Result<Vec<u8>, &'static str> {
    let sockets = SOCKETS.lock();
    let sock = sockets.iter().find(|s| s.id == id)
        .ok_or("socket not found")?;

    // Per IEEE 1003.1 §shutdown: after SHUT_RD, subsequent recv(2)
    // returns 0 (orderly EOF) regardless of any data still queued.
    if sock.shut_rd {
        return Ok(Vec::new());
    }

    let r = match sock.socket_type {
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
            // Per-connection drain when a peer 4-tuple is known
            // (accept(2)-side child or connect(2)ed client) — matches
            // RFC 793 §3.8 demultiplexing.  Falls back to the
            // port-only drain only for the legacy single-peer case.
            if sock.connected && sock.remote_port != 0 {
                Ok(super::tcp::read_from_n(sock.local_port,
                                           sock.remote_ip,
                                           sock.remote_port, max))
            } else {
                Ok(super::tcp::read_n(sock.local_port, max))
            }
        }
    };
    if let Ok(d) = r.as_ref() {
        if !d.is_empty() {
            crate::proc::proc_metrics::bump_net_read(
                crate::proc::current_pid_lockless(), d.len() as u64);
        }
    }
    r
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

    if sock.shut_rd {
        // Connection-mode: peer 4-tuple is still meaningful.
        // Datagram (UDP unconnected): zero peer is benign.
        return Ok((Vec::new(), sock.remote_ip, sock.remote_port));
    }

    let r = match sock.socket_type {
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
    };
    if let Ok((d, _, _)) = r.as_ref() {
        if !d.is_empty() {
            crate::proc::proc_metrics::bump_net_read(
                crate::proc::current_pid_lockless(), d.len() as u64);
        }
    }
    r
}

/// Returns `true` when a connection-mode (TCP) socket has reached an
/// orderly end-of-stream that a subsequent `recv(2)` must report as EOF
/// (a 0-byte return): the peer's FIN has been received (the TCB is in
/// `CloseWait`/`LastAck`/`TimeWait`/`Closed` or has been reaped) *or* the
/// local end has `shutdown(SHUT_RD)`.  Buffered data still pending is NOT
/// EOF — the data must be drained first — so a non-empty receive queue
/// returns `false` here.
///
/// Read-only: this is a blocking-loop break predicate.  A blocking
/// `recvfrom(2)` that waits on [`socket_has_data`] alone never wakes on a
/// FIN-closed empty stream (there is no data and none will ever arrive),
/// so the loop must also break on this EOF condition and fall through to
/// the EOF-aware drain, returning 0 per RFC 9293 §3.5.  UDP is
/// connectionless and never reports EOF here.
pub fn socket_is_read_closed(id: u64) -> bool {
    let sockets = SOCKETS.lock();
    let sock = match sockets.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return false,
    };
    if sock.shut_rd { return true; }
    if sock.socket_type != SocketType::Tcp { return false; }
    if !sock.bound { return false; }
    let connected   = sock.connected;
    let remote_ip   = sock.remote_ip;
    let remote_port = sock.remote_port;
    let local_port  = sock.local_port;
    drop(sockets);
    // Any buffered bytes outrank EOF — drain first.
    let has_buffered = if connected && remote_port != 0 {
        super::tcp::has_data_for(local_port, remote_ip, remote_port)
    } else {
        super::tcp::has_data(local_port)
    };
    if has_buffered { return false; }
    match super::tcp::get_state(local_port) {
        Some(st) => matches!(st,
            super::tcp::TcpState::CloseWait
            | super::tcp::TcpState::LastAck
            | super::tcp::TcpState::TimeWait
            | super::tcp::TcpState::Closed),
        None => true,
    }
}

/// Returns `true` if the socket is a datagram (UDP / SOCK_DGRAM) socket.
///
/// Used by the recvmsg(2) AF_INET path to decide whether to marshal the
/// per-datagram source address into `msg_name`.  Connection-mode (TCP)
/// sockets do not need a per-message source — the source is the fixed
/// connected peer — and they carry an EOF/WouldBlock distinction that the
/// datagram path does not, so the two are handled separately.  Returns
/// `false` for an unknown id.
pub fn socket_is_udp(id: u64) -> bool {
    let sockets = SOCKETS.lock();
    sockets.iter().find(|s| s.id == id)
        .map(|s| s.socket_type == SocketType::Udp)
        .unwrap_or(false)
}

/// Check if a socket has incoming data available (used by poll).
///
/// For a TCP listener (bound but unconnected) the readability gate is
/// "accept(2) would not block" per IEEE Std 1003.1-2017 §poll, which
/// translates to "at least one pending child TCB on this local port".
/// For a connected TCP socket (accept-side child or connect(2)ed
/// client) the gate is per-connection: only this 4-tuple's recv
/// buffer must be non-empty.
pub fn socket_has_data(id: u64) -> bool {
    let sockets = SOCKETS.lock();
    let sock = match sockets.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return false,
    };
    if !sock.bound { return false; }
    match sock.socket_type {
        SocketType::Udp => super::udp::has_data(sock.local_port),
        SocketType::Tcp => {
            if sock.connected && sock.remote_port != 0 {
                // Per-connection: only count bytes routed to this 4-tuple.
                super::tcp::has_data_for(sock.local_port,
                                         sock.remote_ip,
                                         sock.remote_port)
            } else {
                // Listener: poll readable iff a child is accept-pending.
                super::tcp::has_data(sock.local_port)
                    || super::tcp::has_pending_accept(sock.local_port)
            }
        }
    }
}

/// True when the peer has closed its send direction (TCP FIN received)
/// so a subsequent `read(2)` / `recv(2)` will return data still buffered
/// and then 0 (orderly EOF).  This is the read-closed condition a
/// `poll(2)` / `epoll(7)` reader keys on to wake and issue the read that
/// observes EOF.
///
/// Mirrors the EOF discrimination in [`socket_recv_status`]: a connection
/// that has received the peer FIN sits in CloseWait (or has progressed to
/// LastAck / TimeWait / Closed) — RFC 9293 §3.5.  We do NOT include a
/// caller-side `shutdown(SHUT_RD)` here because that is the local read
/// half-close, already surfaced through the socket's own `shut_rd` flag
/// at the recv layer; this helper is specifically the *peer*-FIN edge
/// that no readiness arm currently reports.
///
/// Returns `false` for UDP (connectionless: no peer-FIN concept) and for
/// any socket with no matching TCB.
pub fn socket_read_closed(id: u64) -> bool {
    let sockets = SOCKETS.lock();
    let sock = match sockets.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return false,
    };
    if !sock.bound { return false; }
    match sock.socket_type {
        SocketType::Udp => false,
        SocketType::Tcp => {
            // Prefer a peer-aware lookup when the 4-tuple is known so the
            // edge fires for THIS connection, not a sibling sharing the
            // local port (RFC 9293 §3.6 demultiplexing).
            let state = if sock.connected && sock.remote_port != 0 {
                super::tcp::get_state_for(sock.local_port,
                                          sock.remote_ip,
                                          sock.remote_port)
            } else {
                super::tcp::get_state(sock.local_port)
            };
            match state {
                Some(st) => matches!(st,
                    super::tcp::TcpState::CloseWait
                    | super::tcp::TcpState::LastAck
                    | super::tcp::TcpState::TimeWait
                    | super::tcp::TcpState::Closed),
                // No TCB: the flow is gone — treat as read-closed so a
                // parked reader wakes and drains to a clean EOF rather
                // than parking on a connection that will never deliver.
                None => true,
            }
        }
    }
}

/// True when the connection is read-closed (peer FIN) **and** the receive
/// buffer is empty — i.e. the next `read(2)` returns 0 with nothing left
/// to drain.  This is the `poll(2)` `POLLHUP` / `epoll(7)` `EPOLLHUP`
/// condition: the read direction is fully hung up.
///
/// While a CloseWait tail is still buffered this returns `false` so the
/// readiness arm raises `POLLIN` (drain) but withholds `POLLHUP` until
/// the buffer empties — data-before-EOF ordering (RFC 9293 §3.5, POSIX
/// `poll(2)` which sets `POLLHUP` only once the channel is fully dead).
pub fn socket_fully_hung_up(id: u64) -> bool {
    if !socket_read_closed(id) {
        return false;
    }
    // Read-closed: hung up iff no buffered tail remains to drain.
    !socket_has_data(id)
}

/// Close a socket.
///
/// For TCP, the underlying close path depends on whether this socket
/// fd represents a listener or an accepted/connected child:
///
///   * A connected socket (peer 4-tuple set, accept-side child or
///     `connect(2)`ed client) calls [`super::tcp::close_connection`]
///     so the FIN targets exactly its own TCB and cannot trip a
///     sibling session sharing the listener's local port.
///   * A bound-but-unconnected listener has no peer; the listener
///     TCB is dropped quietly.  Children accepted from it carry
///     their own TCBs and are unaffected.
///   * A bound TCB with no peer in `Established`/`CloseWait` (a
///     dangling pre-handshake or already-closed socket) drops to the
///     legacy port-only `close()` which is a no-op in that state.
pub fn socket_close(id: u64) {
    let mut sockets = SOCKETS.lock();
    if let Some(idx) = sockets.iter().position(|s| s.id == id) {
        // Drop ONE open-file-description reference.  A socket inherited across
        // fork(2) / duplicated via dup(2) is one shared object held by several
        // fds; only the LAST close tears down the TCB and frees the entry.  An
        // earlier close just decrements so the surviving holder's fd keeps
        // resolving to a live, connected socket (POSIX.1-2017 §close: the open
        // file description is released only when the reference count reaches 0).
        if sockets[idx].ref_count > 1 {
            sockets[idx].ref_count -= 1;
            return;
        }
        let sock = &sockets[idx];
        let socket_type = sock.socket_type;
        let local_port = sock.local_port;
        let remote_ip = sock.remote_ip;
        let remote_port = sock.remote_port;
        let connected = sock.connected;
        let bound = sock.bound;
        if bound {
            match socket_type {
                SocketType::Udp => super::udp::unbind(local_port),
                SocketType::Tcp => {
                    drop(sockets);
                    if connected && remote_port != 0 {
                        let _ = super::tcp::close_connection(
                            local_port, remote_ip, remote_port);
                    } else {
                        // Listener socket: release the Listen-state
                        // TCB.  Children already accepted from this
                        // listener carry their own TCBs (independent
                        // 4-tuples) and survive — IEEE Std 1003.1-2017
                        // §close doesn't require accepted descendants
                        // to be torn down when their parent listener
                        // closes.
                        super::tcp::close_listener(local_port);
                    }
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

/// Add one open-file-description reference to AF_INET socket `id`.  Called when
/// an fd referring to this socket is duplicated — fork(2)/vfork(2) copying the
/// fd table, dup(2)/dup2(2), or an SCM_RIGHTS pass.  Balances a later
/// [`socket_close`].  No-op if `id` is not (or no longer) in the table — a
/// caller racing teardown simply finds nothing to bump (it had no live fd).
pub fn inc_ref(id: u64) {
    let mut sockets = SOCKETS.lock();
    if let Some(s) = sockets.iter_mut().find(|s| s.id == id) {
        s.ref_count = s.ref_count.saturating_add(1);
    }
}

/// `shutdown(2)` direction selector — RFC 793 §3.5 / IEEE 1003.1 §shutdown.
pub const SHUT_RD:   i32 = 0;
pub const SHUT_WR:   i32 = 1;
pub const SHUT_RDWR: i32 = 2;

/// Half-close a socket per IEEE 1003.1 §`shutdown` and RFC 793 §3.5.
///
/// `how` selects which directions are torn down:
///   * `SHUT_RD`   — disable further receives.  Subsequent `recv` returns
///     0 (orderly EOF).  No bytes are sent on the wire.
///   * `SHUT_WR`   — disable further sends.  For TCP, transmits a FIN to
///     the peer (Established → FinWait1, CloseWait → LastAck).  Subsequent
///     `send` returns -EPIPE.
///   * `SHUT_RDWR` — both of the above.
///
/// Returns 0 on success, -EBADF when the socket id is unknown, -ENOTCONN
/// when the connection-mode socket is not yet connected, or -EINVAL on
/// invalid `how`.  UDP (connectionless) sockets accept the call as a
/// pure local-flag update — the wire stays untouched.
pub fn socket_shutdown(id: u64, how: i32) -> i32 {
    if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
        return -22; // EINVAL
    }
    let want_rd = how == SHUT_RD   || how == SHUT_RDWR;
    let want_wr = how == SHUT_WR   || how == SHUT_RDWR;

    // Snapshot the bits we need under the lock, then release before
    // reaching into tcp:: (close_connection takes TCP_CONNECTIONS).
    struct Snap {
        socket_type: SocketType,
        connected:   bool,
        local_port:  u16,
        remote_ip:   Ipv4Address,
        remote_port: u16,
        already_wr:  bool,
    }

    let snap = {
        let mut sockets = SOCKETS.lock();
        let sock = match sockets.iter_mut().find(|s| s.id == id) {
            Some(s) => s,
            None    => return -9, // EBADF
        };
        if sock.socket_type == SocketType::Tcp && !sock.connected {
            // POSIX requires ENOTCONN for an unconnected stream socket.
            return -107;
        }
        let snap = Snap {
            socket_type: sock.socket_type,
            connected:   sock.connected,
            local_port:  sock.local_port,
            remote_ip:   sock.remote_ip,
            remote_port: sock.remote_port,
            already_wr:  sock.shut_wr,
        };
        // Apply the local flags now so a racing send/recv sees the new
        // state immediately even if we still have wire work to do below.
        if want_rd { sock.shut_rd = true; }
        if want_wr { sock.shut_wr = true; }
        snap
    };

    // For TCP, SHUT_WR signals end-of-stream to the peer by sending FIN.
    // Only do this on the first SHUT_WR — repeated calls are no-ops per
    // POSIX and would otherwise queue stray FINs.
    if want_wr && !snap.already_wr
        && snap.socket_type == SocketType::Tcp
        && snap.connected
    {
        let _ = super::tcp::shutdown_write(
            snap.local_port, snap.remote_ip, snap.remote_port,
        );
    }
    0
}

/// Set the remote endpoint for a socket and initiate TCP connection if applicable.
///
/// For UDP (SOCK_DGRAM), `connect(2)` does not generate any wire traffic —
/// IEEE 1003.1 §connect specifies that a connectionless socket merely records
/// the peer 4-tuple so subsequent `send(2)` calls implicitly target it and
/// `recv(2)` filters inbound datagrams against it.  The kernel still has to
/// allocate a local port for the reply demultiplexing path: without an
/// ephemeral bind, the source port on the wire is zero and the DNS server's
/// response would not match any port-keyed UDP binding (RFC 768 §"Source
/// Port", RFC 6335 §6).  We therefore lazily bind a 49152–65535 ephemeral
/// when the caller has not already called `bind(2)`.
///
/// For TCP, the existing connect path opens a TCB and drives the SYN; the
/// 3-way-handshake state-machine wait happens in the syscall stub (so we
/// can yield without holding the SOCKETS mutex), per RFC 793 §3.4.
pub fn socket_connect(id: u64, remote_ip: Ipv4Address, remote_port: u16) -> Result<(), &'static str> {
    let mut sockets = SOCKETS.lock();
    let sock = sockets.iter_mut().find(|s| s.id == id)
        .ok_or("socket not found")?;

    sock.remote_ip = remote_ip;
    sock.remote_port = remote_port;
    sock.connected = true;

    match sock.socket_type {
        SocketType::Tcp => {
            let local_port = super::tcp::connect(remote_ip, remote_port)?;
            sock.local_port = local_port;
            sock.bound = true;
        }
        SocketType::Udp => {
            // POSIX: connect(2) on a SOCK_DGRAM socket sets the peer but
            // sends nothing.  We still need a bound local port so the
            // reply lands somewhere — auto-bind when the caller has not.
            if !sock.bound {
                let socket_type = sock.socket_type;
                let port = alloc_ephemeral_port(socket_type)
                    .ok_or("no ephemeral port available")?;
                super::udp::bind(port)?;
                sock.local_port = port;
                sock.bound = true;
            }
        }
    }
    Ok(())
}
