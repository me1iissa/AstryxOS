//! AF_NETLINK / NETLINK_ROUTE (rtnetlink) — kernel-side socket family.
//!
//! Implements the minimum viable rtnetlink surface for interface, address,
//! and route *introspection* — enough for `ip addr`, `ip link`, `ip route`
//! and `ifconfig` (busybox / iproute2) to enumerate the host's network
//! configuration.  The wire format follows the published netlink and
//! rtnetlink UAPI (RFC 3549; `netlink(7)`, `rtnetlink(7)`, `sockaddr_nl(7)`):
//!
//!   * A netlink message is a fixed `nlmsghdr` (RFC 3549 §2.2) followed by a
//!     family-specific payload, all padded to a 4-byte (`NLMSG_ALIGNTO`)
//!     boundary.
//!   * A "dump" request carries `NLM_F_REQUEST | NLM_F_DUMP` and elicits a
//!     *multipart* reply: a run of `NLM_F_MULTI`-flagged messages, one per
//!     object, terminated by a single `NLMSG_DONE` message whose payload is
//!     the dump's terminating errno (0 = success) — RFC 3549 §2.3.2.
//!   * Attributes are nested TLVs (`struct rtattr`, RFC 3549 §2.3.3), each a
//!     `{ rta_len: u16, rta_type: u16 }` header followed by `rta_len -
//!     RTA_LENGTH(0)` payload bytes, padded to `RTA_ALIGNTO` (4).
//!
//! Only the introspection request types `RTM_GETLINK`, `RTM_GETADDR`, and
//! `RTM_GETROUTE` are serviced; everything else is acknowledged with an
//! `NLMSG_ERROR` carrying `EOPNOTSUPP` (a real Linux host answers an unknown
//! rtnetlink request the same way).  We never *write* config (no
//! `RTM_NEWLINK`/`RTM_DELADDR` handling) — this is a read-only view.
//!
//! Design mirrors the AF_UNIX (`net::unix`) model: a global socket table
//! keyed by a monotonic id, one entry per open file description, an
//! open-file-description reference count so fork(2)/dup(2) sharing tears the
//! socket down only on the last close, and a per-socket receive queue of
//! ready-to-read reply bytes the recv/poll path drains.  Each request is
//! processed synchronously on the sending thread (the dump is cheap — a
//! handful of interfaces) and the full reply is enqueued atomically, so the
//! socket is readable the instant `sendmsg`/`send` returns.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

use super::{Ipv4Address, MacAddress};

// ── netlink UAPI constants (RFC 3549; netlink(7), rtnetlink(7)) ───────────────

/// Routing/device netlink protocol — `NETLINK_ROUTE` (rtnetlink(7)).
pub const NETLINK_ROUTE: u32 = 0;

// nlmsghdr.nlmsg_flags bits (RFC 3549 §2.3.1).
const NLM_F_REQUEST: u16 = 0x01; // request message
const NLM_F_MULTI:   u16 = 0x02; // multipart, terminated by NLMSG_DONE
const NLM_F_ACK:     u16 = 0x04; // reply with ack (zero or error code)
const NLM_F_DUMP:    u16 = 0x100 | 0x200; // NLM_F_ROOT | NLM_F_MATCH

// Standard control message types (RFC 3549 §2.3.2).
const NLMSG_NOOP:  u16 = 0x1;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE:  u16 = 0x3;

// rtnetlink message types (rtnetlink(7); RTM_BASE = 16).
const RTM_NEWLINK:  u16 = 16;
const RTM_GETLINK:  u16 = 18;
const RTM_NEWADDR:  u16 = 20;
const RTM_GETADDR:  u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

// IFLA_* link attribute types (rtnetlink(7)).
const IFLA_ADDRESS:  u16 = 1;
const IFLA_IFNAME:   u16 = 3;
const IFLA_MTU:      u16 = 4;
const IFLA_TXQLEN:   u16 = 13;

// IFA_* address attribute types (rtnetlink(7)).
const IFA_ADDRESS:   u16 = 1;
const IFA_LOCAL:     u16 = 2;
const IFA_LABEL:     u16 = 3;

// RTA_* route attribute types (rtnetlink(7)).
const RTA_DST:       u16 = 1;
const RTA_OIF:       u16 = 4;
const RTA_GATEWAY:   u16 = 5;
const RTA_PREFSRC:   u16 = 7;
const RTA_TABLE:     u16 = 15;

// Address families.
const AF_INET: u8 = 2;

// Route table / scope / proto / type constants (rtnetlink(7)).
const RT_TABLE_MAIN:    u8 = 254;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK:    u8 = 253;
const RTPROT_BOOT:      u8 = 3;
const RTPROT_KERNEL:    u8 = 2;
const RTN_UNICAST:      u8 = 1;

// EOPNOTSUPP — returned (as a negative errno in NLMSG_ERROR) for any
// rtnetlink request we do not service.
const EOPNOTSUPP: i32 = 95;

/// Alignment for both nlmsghdr-framed messages and rtattr TLVs — both use a
/// 4-byte boundary (`NLMSG_ALIGNTO == RTA_ALIGNTO == 4`, RFC 3549).
const ALIGN: usize = 4;

#[inline]
const fn align4(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

/// `sizeof(struct nlmsghdr)` — 16 bytes (RFC 3549 §2.2).
const NLMSG_HDRLEN: usize = 16;

// ── socket table ─────────────────────────────────────────────────────────────

/// A single AF_NETLINK / NETLINK_ROUTE socket (one open file description).
struct NetlinkSocket {
    id: u64,
    /// Netlink protocol selector (`NETLINK_ROUTE` only, for now).
    #[allow(dead_code)]
    protocol: u32,
    /// Port id assigned to this socket (`nl_pid`).  Bound lazily on the first
    /// `bind(2)` or first send; the auto-bind value defaults to the caller's
    /// pid per netlink(7) ("If [nl_pid] is zero the kernel assigns one").
    nl_pid: u32,
    /// Whether `bind(2)` / first-send has assigned `nl_pid`.
    bound: bool,
    /// Ready-to-read reply bytes, one complete recvmsg's worth per entry.
    /// Each entry is a self-contained multipart reply (one or more
    /// nlmsghdr-framed messages, ending in NLMSG_DONE / NLMSG_ERROR).  recv
    /// returns at most one entry's bytes per call (datagram semantics —
    /// netlink is message-oriented, netlink(7)).
    rx: VecDeque<Vec<u8>>,
    /// Open-file-description reference count (fork/dup/SCM sharing).  Torn
    /// down on the last close.  POSIX.1-2017 §close.
    ref_count: u32,
}

static SOCKETS: Mutex<Vec<NetlinkSocket>> = Mutex::new(Vec::new());
static NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Monotonic source of kernel-assigned `nl_pid` port ids for the case where
/// neither the requested `nl_pid` nor the caller's pid yields a usable value
/// (netlink(7): a kernel-auto-assigned port id is always non-zero and unique).
/// Seeded high (0x8000_0000) so generated ids never collide with a real pid
/// used as a first-socket port id, mirroring the kernel's disambiguation of
/// multiple netlink sockets owned by one process.
static NEXT_AUTO_PID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0x8000_0000);

/// Resolve a port id for `bind`/auto-bind.  A non-zero requested `nl_pid` is
/// honoured verbatim; otherwise the caller's pid is used (the conventional
/// first-socket port id); if that is also 0 (e.g. a kernel-context caller) a
/// unique non-zero value is generated.  The result is never 0, per netlink(7)
/// ("If [nl_pid] is zero ... the kernel ... assigns ... a unique address").
fn resolve_pid(nl_pid: u32, default_pid: u32) -> u32 {
    if nl_pid != 0 {
        return nl_pid;
    }
    if default_pid != 0 {
        return default_pid;
    }
    NEXT_AUTO_PID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Create a new NETLINK_ROUTE socket.  Returns the socket id, or
/// `u64::MAX` on table exhaustion (mapped to EMFILE by the caller).
pub fn create(protocol: u32) -> u64 {
    let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut socks = SOCKETS.lock();
    socks.push(NetlinkSocket {
        id,
        protocol,
        nl_pid: 0,
        bound: false,
        rx: VecDeque::new(),
        ref_count: 1,
    });
    id
}

/// Bind the socket to a `sockaddr_nl`.  `nl_pid == 0` requests a
/// kernel-assigned port id (the conventional unicast nl_pid is the caller's
/// pid; a kernel-context caller with pid 0 gets a generated unique non-zero
/// value — a bound socket's port id is never 0, netlink(7)).  Any non-zero
/// `nl_pid` is accepted verbatim.  `groups` is accepted but ignored (we
/// deliver no multicast).  Returns 0 on success, -errno on a bad socket id
/// (netlink(7), sockaddr_nl(7)).
pub fn bind(id: u64, nl_pid: u32, _groups: u32, default_pid: u32) -> i32 {
    let mut socks = SOCKETS.lock();
    let s = match socks.iter_mut().find(|s| s.id == id) {
        Some(s) => s,
        None => return -9, // EBADF
    };
    s.nl_pid = resolve_pid(nl_pid, default_pid);
    s.bound = true;
    0
}

/// Ensure the socket has a port id, auto-binding to `default_pid` on first
/// use (netlink(7): an unbound socket is auto-bound on the first send).
/// Returns the resulting `nl_pid`.
fn ensure_bound(socks: &mut Vec<NetlinkSocket>, id: u64, default_pid: u32) -> u32 {
    if let Some(s) = socks.iter_mut().find(|s| s.id == id) {
        if !s.bound {
            s.nl_pid = resolve_pid(0, default_pid);
            s.bound = true;
        }
        s.nl_pid
    } else {
        0
    }
}

/// Return the socket's bound port id for `getsockname(2)` — a `sockaddr_nl`
/// whose `nl_pid` is the assigned port id (0 when never bound).  Returns
/// `None` for an unknown socket id.
pub fn local_pid(id: u64) -> Option<u32> {
    let socks = SOCKETS.lock();
    socks.iter().find(|s| s.id == id).map(|s| s.nl_pid)
}

/// Add one open-file-description reference (fork/dup/SCM).  No-op if the id
/// is gone.  Balances a later [`close`].
pub fn inc_ref(id: u64) {
    let mut socks = SOCKETS.lock();
    if let Some(s) = socks.iter_mut().find(|s| s.id == id) {
        s.ref_count = s.ref_count.saturating_add(1);
    }
}

/// Drop one reference; free the socket on the last close (POSIX.1-2017
/// §close: the open file description is released when the refcount hits 0).
pub fn close(id: u64) {
    let mut socks = SOCKETS.lock();
    if let Some(idx) = socks.iter().position(|s| s.id == id) {
        if socks[idx].ref_count > 1 {
            socks[idx].ref_count -= 1;
            return;
        }
        socks.remove(idx);
    }
}

/// True when a reply is queued — the `poll(2)` / `epoll(7)` POLLIN gate.
pub fn has_data(id: u64) -> bool {
    let socks = SOCKETS.lock();
    socks.iter().find(|s| s.id == id)
        .map(|s| !s.rx.is_empty())
        .unwrap_or(false)
}

/// A netlink socket is always writable (the send path is synchronous and
/// never blocks) — the POLLOUT gate.
pub fn writable(_id: u64) -> bool {
    true
}

// ── send / request processing ────────────────────────────────────────────────

/// Process one or more concatenated request messages sent by userspace.
///
/// `data` is the raw bytes of one `sendmsg`/`send`, which may pack several
/// nlmsghdr-framed requests back to back (RFC 3549 §2.2 permits it; iproute2
/// sends one per call but we tolerate batching).  Each request is parsed,
/// dispatched, and its reply appended to a single multipart reply buffer that
/// is enqueued atomically on the socket's receive queue.  Returns the number
/// of request bytes consumed (always `data.len()` on success, so the caller
/// reports a full write), or a negative errno.
///
/// `default_pid` is the caller's pid, used both to auto-bind an unbound
/// socket and as the `nlmsg_pid` echoed back on replies (netlink(7)).
pub fn send_request(id: u64, data: &[u8], default_pid: u32) -> i64 {
    // Auto-bind on first use, and confirm the socket exists.
    {
        let mut socks = SOCKETS.lock();
        if !socks.iter().any(|s| s.id == id) {
            return -9; // EBADF
        }
        ensure_bound(&mut socks, id, default_pid);
    }

    // Build the reply for every request packed into this send.
    let mut reply: Vec<u8> = Vec::new();
    let mut off = 0usize;
    while off + NLMSG_HDRLEN <= data.len() {
        let nlmsg_len = u32::from_ne_bytes([
            data[off], data[off + 1], data[off + 2], data[off + 3],
        ]) as usize;
        let nlmsg_type = u16::from_ne_bytes([data[off + 4], data[off + 5]]);
        let nlmsg_flags = u16::from_ne_bytes([data[off + 6], data[off + 7]]);
        let nlmsg_seq = u32::from_ne_bytes([
            data[off + 8], data[off + 9], data[off + 10], data[off + 11],
        ]);
        // A malformed length (shorter than the header, or running past the
        // buffer) terminates parsing — RFC 3549's NLMSG_OK guard.
        if nlmsg_len < NLMSG_HDRLEN || off + nlmsg_len > data.len() {
            break;
        }

        let is_dump = (nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
        match nlmsg_type {
            RTM_GETLINK => dump_links(&mut reply, nlmsg_seq, default_pid),
            RTM_GETADDR => dump_addrs(&mut reply, nlmsg_seq, default_pid),
            RTM_GETROUTE => dump_routes(&mut reply, nlmsg_seq, default_pid),
            _ => {
                // Any other request: a request that asked for an ACK, or any
                // unknown type, gets an NLMSG_ERROR.  An unknown type is
                // EOPNOTSUPP; an ACK-requested known-but-unhandled op would
                // be 0 — we only handle the GET dumps, so everything else is
                // EOPNOTSUPP (RFC 3549 §2.3.2.2 / netlink(7) NLMSG_ERROR).
                let _ = is_dump;
                push_error(&mut reply, nlmsg_seq, default_pid,
                           nlmsg_type, nlmsg_flags, -EOPNOTSUPP, data, off, nlmsg_len);
            }
        }

        // RTM_GET* dumps emit their own NLMSG_DONE terminator inside the
        // dump_* helpers.  For a non-dump RTM_GET (rare) the single reply +
        // DONE is still correct because the helpers always close with DONE.
        off += align4(nlmsg_len);
        if off <= data.len() && align4(nlmsg_len) == 0 {
            break; // defensive: never spin on a zero-advance
        }
    }

    // Enqueue the whole reply as one readable message.
    let mut socks = SOCKETS.lock();
    if let Some(s) = socks.iter_mut().find(|s| s.id == id) {
        if !reply.is_empty() {
            s.rx.push_back(reply);
        }
    }
    data.len() as i64
}

/// Dequeue at most one reply buffer into `buf`.  Netlink is message-oriented:
/// each recv returns one queued reply (which itself may contain several
/// nlmsghdr-framed messages).  Returns `(bytes_copied, truncated)`; on an
/// empty queue returns `(0, false)` which the syscall layer maps to -EAGAIN
/// for a non-blocking recv or parks for a blocking one.
pub fn recv(id: u64, buf: &mut [u8]) -> (usize, bool) {
    let mut socks = SOCKETS.lock();
    let s = match socks.iter_mut().find(|s| s.id == id) {
        Some(s) => s,
        None => return (0, false),
    };
    let msg = match s.rx.pop_front() {
        Some(m) => m,
        None => return (0, false),
    };
    let n = msg.len().min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    // A short user buffer truncates the message; per netlink(7) the excess is
    // discarded (the kernel sets MSG_TRUNC) — we drop the remainder.
    (n, n < msg.len())
}

// ── reply marshalling ────────────────────────────────────────────────────────

/// Append a `struct nlmsghdr` to `out`, recording its byte offset so the
/// length can be back-patched once the body and attrs are written.  Returns
/// the offset of this header within `out`.
fn put_nlmsghdr(out: &mut Vec<u8>, msg_type: u16, flags: u16, seq: u32, pid: u32) -> usize {
    let hdr_off = out.len();
    out.extend_from_slice(&0u32.to_ne_bytes());     // nlmsg_len (patched later)
    out.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
    out.extend_from_slice(&flags.to_ne_bytes());    // nlmsg_flags
    out.extend_from_slice(&seq.to_ne_bytes());      // nlmsg_seq
    out.extend_from_slice(&pid.to_ne_bytes());      // nlmsg_pid
    hdr_off
}

/// Back-patch `nlmsg_len` of the header at `hdr_off` to the true message
/// length (`out.len() - hdr_off`), then pad `out` to the next 4-byte
/// boundary so the following message starts aligned (RFC 3549 §2.2).
fn finish_nlmsg(out: &mut Vec<u8>, hdr_off: usize) {
    let len = (out.len() - hdr_off) as u32;
    out[hdr_off..hdr_off + 4].copy_from_slice(&len.to_ne_bytes());
    while out.len() % ALIGN != 0 {
        out.push(0);
    }
}

/// Append one `struct rtattr` TLV: `{ rta_len: u16, rta_type: u16 }` header
/// followed by `payload`, padded to the next 4-byte boundary (RFC 3549
/// §2.3.3).  `rta_len` excludes the trailing padding but includes the 4-byte
/// attribute header (`RTA_LENGTH(payload.len())`).
fn put_attr(out: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let rta_len = (4 + payload.len()) as u16;
    out.extend_from_slice(&rta_len.to_ne_bytes());
    out.extend_from_slice(&attr_type.to_ne_bytes());
    out.extend_from_slice(payload);
    while out.len() % ALIGN != 0 {
        out.push(0);
    }
}

/// Append the terminating `NLMSG_DONE` (RFC 3549 §2.3.2): a header of type
/// NLMSG_DONE carrying `NLM_F_MULTI`, with a 4-byte payload = the dump's
/// terminating errno (0 = success).
fn push_done(out: &mut Vec<u8>, seq: u32, pid: u32) {
    let hdr_off = put_nlmsghdr(out, NLMSG_DONE, NLM_F_MULTI, seq, pid);
    out.extend_from_slice(&0i32.to_ne_bytes()); // dump errno = 0
    finish_nlmsg(out, hdr_off);
}

/// Append an `NLMSG_ERROR` message (RFC 3549 §2.3.2.2): `{ error: i32 }`
/// followed by the original request header echoed back, per the UAPI
/// `struct nlmsgerr`.  `error == 0` is the conventional "ACK"; a negative
/// value reports a failure.
fn push_error(
    out: &mut Vec<u8>,
    seq: u32,
    pid: u32,
    _req_type: u16,
    _req_flags: u16,
    error: i32,
    req_data: &[u8],
    req_off: usize,
    req_len: usize,
) {
    let hdr_off = put_nlmsghdr(out, NLMSG_ERROR, 0, seq, pid);
    out.extend_from_slice(&error.to_ne_bytes()); // nlmsgerr.error
    // nlmsgerr.msg = the original request header (the first NLMSG_HDRLEN
    // bytes of the offending request), per struct nlmsgerr.  Echo exactly
    // NLMSG_HDRLEN bytes, zero-padding when the request was shorter than a
    // full header (defensive — a well-formed request is >= 16 bytes).
    let echo_end = (req_off + req_len.min(NLMSG_HDRLEN)).min(req_data.len());
    let echoed = if echo_end > req_off {
        out.extend_from_slice(&req_data[req_off..echo_end]);
        echo_end - req_off
    } else {
        0
    };
    for _ in echoed..NLMSG_HDRLEN {
        out.push(0);
    }
    finish_nlmsg(out, hdr_off);
}

// ── RTM_GETLINK → RTM_NEWLINK dump ───────────────────────────────────────────

/// Emit one `RTM_NEWLINK` message per interface, then `NLMSG_DONE`
/// (rtnetlink(7), RFC 3549 §2.3.2).  The link body is a `struct ifinfomsg`
/// followed by `IFLA_IFNAME`, `IFLA_ADDRESS` (MAC), `IFLA_MTU`, and
/// `IFLA_TXQLEN` attributes.
fn dump_links(out: &mut Vec<u8>, seq: u32, pid: u32) {
    for iface in super::list_ifaces() {
        let hdr_off = put_nlmsghdr(out, RTM_NEWLINK, NLM_F_MULTI, seq, pid);
        // struct ifinfomsg { u8 family; u8 pad; u16 type; i32 index; u32 flags; u32 change }
        out.push(0);                                        // ifi_family (AF_UNSPEC)
        out.push(0);                                        // __ifi_pad
        out.extend_from_slice(&iface.iftype.to_ne_bytes()); // ifi_type (ARPHRD_*)
        out.extend_from_slice(&(iface.ifindex as i32).to_ne_bytes()); // ifi_index
        out.extend_from_slice(&iface.flags.to_ne_bytes());  // ifi_flags (IFF_*)
        out.extend_from_slice(&0xffff_ffffu32.to_ne_bytes()); // ifi_change (all)

        // IFLA_IFNAME — NUL-terminated interface name.
        let mut name = iface.name.clone().into_bytes();
        name.push(0);
        put_attr(out, IFLA_IFNAME, &name);
        // IFLA_ADDRESS — hardware (MAC) address.  Loopback has all-zero,
        // which Linux still emits as a 6-byte zero IFLA_ADDRESS.
        put_attr(out, IFLA_ADDRESS, &iface.mac);
        // IFLA_MTU — u32.
        put_attr(out, IFLA_MTU, &iface.mtu.to_ne_bytes());
        // IFLA_TXQLEN — u32.  1000 is the conventional Ethernet default; 0 on
        // loopback (no real transmit queue).
        let txqlen: u32 = if iface.iftype == super::ARPHRD_LOOPBACK { 0 } else { 1000 };
        put_attr(out, IFLA_TXQLEN, &txqlen.to_ne_bytes());

        finish_nlmsg(out, hdr_off);
    }
    push_done(out, seq, pid);
}

// ── RTM_GETADDR → RTM_NEWADDR dump ───────────────────────────────────────────

/// Emit one `RTM_NEWADDR` message per (interface, IPv4 address) pair, then
/// `NLMSG_DONE`.  The body is a `struct ifaddrmsg` followed by `IFA_ADDRESS`,
/// `IFA_LOCAL`, and `IFA_LABEL` attributes (rtnetlink(7)).
fn dump_addrs(out: &mut Vec<u8>, seq: u32, pid: u32) {
    // Build (ifindex, name, addr, prefixlen, scope) tuples from the live
    // stack.  Loopback carries 127.0.0.1/8 (RFC 1122 §3.2.1.3); the hardware
    // NIC carries the host's primary IPv4 with the configured prefix length.
    let host_ip = super::our_ip();
    let prefixlen = mask_to_prefixlen(super::subnet_mask());

    for iface in super::list_ifaces() {
        let (addr, plen, scope): (Ipv4Address, u8, u8) =
            if iface.iftype == super::ARPHRD_LOOPBACK {
                ([127, 0, 0, 1], 8, RT_SCOPE_HOST)
            } else {
                (host_ip, prefixlen, RT_SCOPE_UNIVERSE)
            };
        // Skip an unconfigured NIC (all-zero address) — nothing to report.
        if iface.iftype != super::ARPHRD_LOOPBACK && addr == [0, 0, 0, 0] {
            continue;
        }

        let hdr_off = put_nlmsghdr(out, RTM_NEWADDR, NLM_F_MULTI, seq, pid);
        // struct ifaddrmsg { u8 family; u8 prefixlen; u8 flags; u8 scope; u32 index }
        out.push(AF_INET);               // ifa_family
        out.push(plen);                  // ifa_prefixlen
        out.push(IFA_F_PERMANENT);       // ifa_flags
        out.push(scope);                 // ifa_scope
        out.extend_from_slice(&iface.ifindex.to_ne_bytes()); // ifa_index

        // IFA_ADDRESS — the address of the prefix (== IFA_LOCAL for a normal,
        // non-point-to-point interface).  IFA_LOCAL — the local address.
        put_attr(out, IFA_ADDRESS, &addr);
        put_attr(out, IFA_LOCAL, &addr);
        // IFA_LABEL — the interface name (NUL-terminated), what `ip addr`
        // prints after the address.
        let mut label = iface.name.clone().into_bytes();
        label.push(0);
        put_attr(out, IFA_LABEL, &label);

        finish_nlmsg(out, hdr_off);
    }
    push_done(out, seq, pid);
}

const RT_SCOPE_HOST: u8 = 254;
const IFA_F_PERMANENT: u8 = 0x80;

// ── RTM_GETROUTE → RTM_NEWROUTE dump ─────────────────────────────────────────

/// Emit the IPv4 routing table — the on-link subnet route plus the default
/// route — then `NLMSG_DONE`.  Each route is a `struct rtmsg` followed by
/// `RTA_TABLE`, `RTA_DST`/`RTA_GATEWAY`, `RTA_PREFSRC`, and `RTA_OIF`
/// attributes (rtnetlink(7)).
fn dump_routes(out: &mut Vec<u8>, seq: u32, pid: u32) {
    let host_ip = super::our_ip();
    let gw = super::gateway_ip();
    let prefixlen = mask_to_prefixlen(super::subnet_mask());

    // The hardware NIC's ifindex (eth0 == 2 when present); routes are bound to
    // it via RTA_OIF.  If no NIC is up there is nothing to route, so we still
    // emit DONE (an empty table) rather than fabricating routes.
    let oif = super::list_ifaces().iter()
        .find(|i| i.iftype == super::ARPHRD_ETHER)
        .map(|i| i.ifindex);

    if let Some(oif) = oif {
        if host_ip != [0, 0, 0, 0] {
            // On-link subnet route: dst = host_ip & mask, dst_len = prefixlen,
            // scope LINK, proto KERNEL (the route the kernel installs for a
            // configured interface address).
            let subnet = [
                host_ip[0] & super::subnet_mask()[0],
                host_ip[1] & super::subnet_mask()[1],
                host_ip[2] & super::subnet_mask()[2],
                host_ip[3] & super::subnet_mask()[3],
            ];
            let hdr_off = put_nlmsghdr(out, RTM_NEWROUTE, NLM_F_MULTI, seq, pid);
            put_rtmsg(out, prefixlen, RT_SCOPE_LINK, RTPROT_KERNEL, RTN_UNICAST);
            put_attr(out, RTA_TABLE, &(RT_TABLE_MAIN as u32).to_ne_bytes());
            put_attr(out, RTA_DST, &subnet);
            put_attr(out, RTA_PREFSRC, &host_ip);
            put_attr(out, RTA_OIF, &oif.to_ne_bytes());
            finish_nlmsg(out, hdr_off);
        }

        if gw != [0, 0, 0, 0] {
            // Default route: dst_len = 0, via gw, scope UNIVERSE, proto BOOT.
            let hdr_off = put_nlmsghdr(out, RTM_NEWROUTE, NLM_F_MULTI, seq, pid);
            put_rtmsg(out, 0, RT_SCOPE_UNIVERSE, RTPROT_BOOT, RTN_UNICAST);
            put_attr(out, RTA_TABLE, &(RT_TABLE_MAIN as u32).to_ne_bytes());
            put_attr(out, RTA_GATEWAY, &gw);
            put_attr(out, RTA_OIF, &oif.to_ne_bytes());
            if host_ip != [0, 0, 0, 0] {
                put_attr(out, RTA_PREFSRC, &host_ip);
            }
            finish_nlmsg(out, hdr_off);
        }
    }
    push_done(out, seq, pid);
}

/// Append a `struct rtmsg` body (rtnetlink(7)): `rtm_family = AF_INET`,
/// `rtm_dst_len = dst_len`, table MAIN, the given scope/proto/type.
fn put_rtmsg(out: &mut Vec<u8>, dst_len: u8, scope: u8, proto: u8, rtype: u8) {
    out.push(AF_INET);        // rtm_family
    out.push(dst_len);        // rtm_dst_len
    out.push(0);              // rtm_src_len
    out.push(0);              // rtm_tos
    out.push(RT_TABLE_MAIN);  // rtm_table
    out.push(proto);          // rtm_protocol
    out.push(scope);          // rtm_scope
    out.push(rtype);          // rtm_type
    out.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
}

/// Convert a dotted IPv4 subnet mask to a CIDR prefix length (number of
/// leading 1 bits).  e.g. 255.255.255.0 → 24.
fn mask_to_prefixlen(mask: Ipv4Address) -> u8 {
    let m = u32::from_be_bytes(mask);
    m.count_ones() as u8
}

/// Format a MAC for the (compile-gated) trace logging.  Unused outside of
/// debug builds — kept minimal.
#[allow(dead_code)]
fn fmt_mac(mac: &MacAddress) -> alloc::string::String {
    alloc::format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
