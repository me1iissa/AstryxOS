//! AF_UNIX (UNIX domain) socket implementation.
//!
//! Provides local inter-process communication via named (path-based) and
//! unnamed (socketpair) UNIX sockets.
//!
//! Supports two socket types per `man 7 unix`:
//!   * `SOCK_STREAM`    — reliable byte-stream, no message boundaries.
//!   * `SOCK_SEQPACKET` — reliable, ordered, datagram-style messages with
//!     preserved boundaries.  A `read`/`recvmsg` returns at most one full
//!     sender-side message; if the receiver buffer is shorter than the
//!     message, the tail is discarded and `MSG_TRUNC` is set in the
//!     resulting `msghdr.msg_flags` (caller-side responsibility).
//!
//! # Concurrency
//! All state is protected by a single global Mutex.  Safe on AstryxOS's
//! single-CPU non-preemptive kernel model.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

// ── Limits ───────────────────────────────────────────────────────────────────

const MAX_UNIX_SOCKETS: usize = 64;
/// Maximum path length for AF_UNIX addresses (Linux: 108 bytes).
const UNIX_PATH_MAX: usize = 108;
/// Receive buffer per socket (bytes — ring buffer).
/// Sized at 32 KiB to support X11 PutImage payloads (small-medium windows).
const RECV_BUF_CAP: usize = 32768;
/// Maximum number of pending connections in a listen backlog.
const BACKLOG_CAP: usize = 8;
/// Maximum number of queued message-length records for a SOCK_SEQPACKET
/// socket.  Each `write` consumes one slot; each `read` releases one.
/// Sized for typical IPC bursts; a slow reader receiving more than this many
/// outstanding messages will see the writer get -EAGAIN.
const SEQ_QUEUE_CAP: usize = 64;

/// AF_UNIX socket type per `man 7 unix`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SockKind {
    /// `SOCK_STREAM` — reliable byte-stream, no message boundaries.
    Stream,
    /// `SOCK_SEQPACKET` — reliable, ordered datagrams with preserved
    /// message boundaries.  See `man 7 unix` §SOCK_SEQPACKET.
    SeqPacket,
}

// ── Socket state ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnixState {
    Free,
    Unbound,
    Bound,
    Listening,
    Connected,
}

// ── Socket entry ─────────────────────────────────────────────────────────────

struct UnixSocket {
    state:       UnixState,
    /// Socket type — `Stream` (byte-stream) or `SeqPacket` (boundary-preserving
    /// datagrams).  Set at creation (socket(2)/socketpair(2)) and inherited by
    /// peer sockets created by accept(2)/connect(2).
    kind:        SockKind,
    path:        [u8; UNIX_PATH_MAX],
    path_len:    usize,
    peer_id:     u64,
    recv_buf:    [u8; RECV_BUF_CAP],
    recv_head:   usize,
    recv_tail:   usize,
    /// Monotonic count of bytes ever *pushed* into `recv_buf` and ever
    /// *popped* out of it.  Unlike the wrapping `recv_head`/`recv_tail`
    /// indices, these never reset on read, so they form a stable absolute
    /// stream position for the live connection (`recv_pushed - recv_popped
    /// == recv_available()`).  Used to bind a queued `SCM_RIGHTS` control
    /// message to the exact stream offset at which it was sent, so an
    /// ancillary-only frame (`iov_len == 0`) is still a *readable message*
    /// per `recvmsg(2)` / `unix(7)` / POSIX.1-2017 SCM_RIGHTS, and so a
    /// reader draining an earlier data-only frame does not prematurely
    /// receive a later frame's fds.
    recv_pushed: u64,
    recv_popped: u64,
    /// SEQPACKET message-boundary queue: each entry records the length of
    /// one outstanding sender-side message in `recv_buf`.  Unused for STREAM.
    /// Implemented as a small ring; `seq_head` is dequeue, `seq_tail` is
    /// enqueue.  Number of queued messages = `(tail - head) mod CAP`.
    seq_lens:    [u32; SEQ_QUEUE_CAP],
    seq_head:    usize,
    seq_tail:    usize,
    backlog:     [u64; BACKLOG_CAP],
    backlog_len: usize,
    /// Per IEEE 1003.1 §shutdown.  `shut_rd` makes subsequent local reads
    /// return 0 (EOF).  `shut_wr` makes subsequent local writes fail with
    /// -EPIPE *and* causes the peer's reads to observe EOF — modelled by
    /// flipping the peer's `shut_rd`, since we have no FIN-equivalent on
    /// the in-memory pipe.
    shut_rd:     bool,
    shut_wr:     bool,
    /// "No more bytes will ever arrive" — set on this socket when its peer
    /// performs `shutdown(SHUT_WR)` or fully closes.  Distinct from the local
    /// `shut_rd` (SHUT_RD discards queued data and EOFs immediately per
    /// IEEE 1003.1 §shutdown): with `rx_eof` the reader first DRAINS any
    /// bytes already queued in `recv_buf` and only then observes the orderly
    /// EOF — the recv(2) contract for a peer that performed an orderly
    /// shutdown ("return 0 once all queued data is consumed").  Feeds the
    /// `POLLIN`/`POLLRDHUP` readiness edges via [`read_shutdown`].
    rx_eof:      bool,
    /// The peer endpoint has FULLY closed (last open file description gone).
    /// Set together with severing our `peer_id` back-pointer in [`close`], so
    /// no code path can ever dereference the freed — and possibly RECYCLED —
    /// peer slot through us.  Drives `POLLHUP` ([`fully_hung_up`]), the
    /// always-writable EPIPE fast-path ([`writable`]), and write(2) → -EPIPE.
    peer_closed: bool,
    /// Count of open file-description references to this socket slot.
    ///
    /// `socket(2)` / `socketpair(2)` initialise this to 1.  Every call that
    /// duplicates an open file description pointing at this slot — `dup(2)`,
    /// `dup2(2)`, `dup3(2)`, and the fd-table copy performed by `fork(2)` and
    /// `clone(2)` without `CLONE_FILES` — must call `inc_ref(id)` to bump this
    /// count.  `close(2)` decrements it; only when the count reaches zero is
    /// the slot actually recycled and the peer notified of the orderly close.
    /// This mirrors the POSIX requirement that "all file descriptors referring
    /// to the same open socket description" share a single underlying object
    /// (POSIX.1-2017 §2.14, `man 2 fork`: "file descriptors shall be
    /// duplicated", `man 2 dup`).
    ref_count:   u32,
    /// Credentials of the process that created (or, in the case of an
    /// accept-side socket, connected) this socket endpoint.  Captured at the
    /// moment the slot transitions out of `Free` so that subsequent
    /// `getsockopt(SO_PEERCRED)` calls on the peer can return the credentials
    /// of *this* endpoint's creator — per `unix(7)` SO_PEERCRED: "returns the
    /// credentials of the peer process connected to this socket … the
    /// credentials are those that were in effect at the time of the call to
    /// connect(2) or socketpair(2)."  Stored as PID/UID/GID; default values
    /// of (0, 0, 0) before initialisation are deliberately equivalent to
    /// "kernel-owned" and surface a structurally-detectable absence to
    /// authorisers that compare against a non-zero allowlist.
    creator_pid: u64,
    creator_uid: u32,
    creator_gid: u32,
    /// Monotonic generation of this slot index, bumped every time the slot is
    /// recycled ([`reset`]).  Because AF_UNIX socket ids are bare slot indices
    /// that are reused the instant a slot's last reference drops, any side
    /// table keyed on the bare index (notably the `SCM_RIGHTS` batch queue,
    /// `syscall::PENDING_SCM`) risks delivering a *previous* occupant's state
    /// to the *current* occupant.  Pairing the index with this incarnation
    /// makes such a stale entry structurally undeliverable: a queued batch
    /// records the incarnation at enqueue time, and delivery refuses any batch
    /// whose recorded incarnation differs from the slot's current one.  This
    /// closes the recycle race independently of the close→drain ordering
    /// window (see `close`).  `u64` never wraps in practice (one bump per
    /// socket teardown).
    incarnation: u64,
}

impl UnixSocket {
    const fn zeroed() -> Self {
        Self {
            state:       UnixState::Free,
            kind:        SockKind::Stream,
            path:        [0u8; UNIX_PATH_MAX],
            path_len:    0,
            peer_id:     u64::MAX,
            recv_buf:    [0u8; RECV_BUF_CAP],
            recv_head:   0,
            recv_tail:   0,
            recv_pushed: 0,
            recv_popped: 0,
            seq_lens:    [0u32; SEQ_QUEUE_CAP],
            seq_head:    0,
            seq_tail:    0,
            backlog:     [u64::MAX; BACKLOG_CAP],
            backlog_len: 0,
            shut_rd:     false,
            shut_wr:     false,
            rx_eof:      false,
            peer_closed: false,
            ref_count:   0,
            creator_pid: 0,
            creator_uid: 0,
            creator_gid: 0,
            incarnation: 0,
        }
    }

    fn reset(&mut self) {
        // Bump the slot generation FIRST so any SCM_RIGHTS batch still queued
        // against the OUTGOING incarnation can never be delivered to the next
        // occupant of this index (see the `incarnation` field doc and the
        // `syscall::PENDING_SCM` incarnation guard).
        self.incarnation = self.incarnation.wrapping_add(1);
        self.state       = UnixState::Free;
        self.kind        = SockKind::Stream;
        self.path_len    = 0;
        self.peer_id     = u64::MAX;
        self.recv_head   = 0;
        self.recv_tail   = 0;
        self.recv_pushed = 0;
        self.recv_popped = 0;
        self.seq_head    = 0;
        self.seq_tail    = 0;
        self.backlog_len = 0;
        self.shut_rd     = false;
        self.shut_wr     = false;
        self.rx_eof      = false;
        self.peer_closed = false;
        self.ref_count   = 0;
        self.creator_pid = 0;
        self.creator_uid = 0;
        self.creator_gid = 0;
    }

    fn recv_available(&self) -> usize {
        (self.recv_tail + RECV_BUF_CAP - self.recv_head) % RECV_BUF_CAP
    }

    fn recv_space(&self) -> usize {
        RECV_BUF_CAP - 1 - self.recv_available()
    }

    fn push(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.recv_space());
        // SMAP bracket — `data` is typically a user-VA slice forwarded
        // from the syscall layer (sys_write_linux / sendmsg / sendto).
        // The bounded loop runs under the TABLE lock with no schedule
        // points, so AC=1 cannot leak.  Collapses to a relaxed load on
        // CPUs without SMAP.
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        for &b in &data[..n] {
            self.recv_buf[self.recv_tail] = b;
            self.recv_tail = (self.recv_tail + 1) % RECV_BUF_CAP;
        }
        self.recv_pushed = self.recv_pushed.wrapping_add(n as u64);
        n
    }

    fn pop(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.recv_available());
        // SMAP bracket — `buf` is typically a user-VA slice.
        let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
        for byte in &mut buf[..n] {
            *byte = self.recv_buf[self.recv_head];
            self.recv_head = (self.recv_head + 1) % RECV_BUF_CAP;
        }
        self.recv_popped = self.recv_popped.wrapping_add(n as u64);
        n
    }

    /// Absolute stream position of the *next* byte that will be pushed —
    /// the offset to bind a queued `SCM_RIGHTS` batch to (see `recv_pushed`).
    fn enqueue_offset(&self) -> u64 {
        self.recv_pushed
    }
}

// ── Global socket table ───────────────────────────────────────────────────────

struct Table([UnixSocket; MAX_UNIX_SOCKETS]);
// SAFETY: UnixSocket contains only integer/array types — no heap pointers.
unsafe impl Send for Table {}

static TABLE: Mutex<Table> = Mutex::new(Table([UnixSocket::ZERO; MAX_UNIX_SOCKETS]));

impl UnixSocket { const ZERO: Self = Self::zeroed(); }

// ── Public API ────────────────────────────────────────────────────────────────

/// Credentials of the process opening / connecting / creating a socket end.
///
/// Captured at the moment the kernel allocates a socket slot on behalf of a
/// userland call (socket(2), connect(2), accept(2), socketpair(2)) so that a
/// later `getsockopt(SO_PEERCRED)` on the peer end can return the credentials
/// of the process that built this end — per `unix(7)` SO_PEERCRED, which
/// requires the *peer's* identity at connect/socketpair time, not the
/// caller's.  All authorisation flows that rely on SO_PEERCRED (D-Bus
/// authentication, the Mozilla content-process sandbox broker) depend on
/// this semantic.
#[derive(Clone, Copy, Debug)]
pub struct PeerCreds {
    pub pid: u64,
    pub uid: u32,
    pub gid: u32,
}

pub fn create(kind: SockKind, creds: PeerCreds) -> u64 {
    let mut t = TABLE.lock();
    for (i, s) in t.0.iter_mut().enumerate() {
        if s.state == UnixState::Free {
            s.reset();
            s.state       = UnixState::Unbound;
            s.kind        = kind;
            s.ref_count   = 1;
            s.creator_pid = creds.pid;
            s.creator_uid = creds.uid;
            s.creator_gid = creds.gid;
            return i as u64;
        }
    }
    u64::MAX
}

pub fn bind(id: u64, path: &[u8]) -> i64 {
    if id as usize >= MAX_UNIX_SOCKETS { return -9; }
    // Strip trailing NUL so paths stored by bind always match paths from connect.
    let raw_len = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    let plen = raw_len.min(UNIX_PATH_MAX);
    let new_path = &path[..plen];
    let mut t = TABLE.lock();
    for (i, s) in t.0.iter().enumerate() {
        if i as u64 == id { continue; }
        if (s.state == UnixState::Bound || s.state == UnixState::Listening)
            && &s.path[..s.path_len] == new_path
        {
            return -98; // EADDRINUSE
        }
    }
    let s = &mut t.0[id as usize];
    if s.state == UnixState::Free    { return -9;  }
    if s.state != UnixState::Unbound { return -22; }
    s.path[..plen].copy_from_slice(new_path);
    s.path_len = plen;
    s.state = UnixState::Bound;
    0
}

pub fn listen(id: u64) -> i64 {
    if id as usize >= MAX_UNIX_SOCKETS { return -9; }
    let mut t = TABLE.lock();
    let s = &mut t.0[id as usize];
    match s.state {
        UnixState::Bound | UnixState::Unbound => { s.state = UnixState::Listening; 0 }
        UnixState::Listening => 0,
        _ => -22,
    }
}

pub fn connect(id: u64, path: &[u8], _client_creds: PeerCreds) -> i64 {
    if id as usize >= MAX_UNIX_SOCKETS { return -9; }
    // Strip trailing NUL to match paths stored by bind.
    let raw_len = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    let plen = raw_len.min(UNIX_PATH_MAX);
    let search = &path[..plen];
    let mut t = TABLE.lock();

    let server_id = t.0.iter().enumerate()
        .find(|(_, s)| s.state == UnixState::Listening && &s.path[..s.path_len] == search)
        .map(|(i, _)| i as u64)
        .unwrap_or(u64::MAX);
    if server_id == u64::MAX { return -111; }

    // The accepted peer (server-side end of the new connection) inherits the
    // server's socket type per `man 7 unix` — a SEQPACKET listener must yield
    // SEQPACKET peers, never STREAM.
    let server_kind = t.0[server_id as usize].kind;
    let client_kind = t.0[id as usize].kind;
    // POSIX: connect on a wrong-type socket fails (Linux returns EPROTOTYPE).
    if client_kind != server_kind { return -91; } // EPROTOTYPE

    // Snapshot the server's creator credentials before the mutable borrow
    // below — we cannot hold a shared reference into `t.0[server_id]` while
    // simultaneously iterating `t.0` mutably.
    let server_creds = PeerCreds {
        pid: t.0[server_id as usize].creator_pid,
        uid: t.0[server_id as usize].creator_uid,
        gid: t.0[server_id as usize].creator_gid,
    };

    let peer_id = {
        let mut found = u64::MAX;
        for (i, s) in t.0.iter_mut().enumerate() {
            if i as u64 != id && s.state == UnixState::Free {
                s.reset();
                s.state       = UnixState::Connected;
                s.kind        = server_kind;
                s.peer_id     = id;
                s.ref_count   = 1; // one reference: the fd returned by accept(2)
                // Per unix(7) SO_PEERCRED: "Returns the credentials of the peer
                // process connected to this socket."  The peer of the CLIENT
                // socket is this accept-side slot, so peer_creds(client_fd) looks
                // up accept_side.creator_{pid,uid,gid}.  That must be the
                // SERVER's identity — not the client's.
                //
                // Conversely, peer_creds(server_accepted_fd) looks up
                // client_socket.creator_{pid,uid,gid}, which is set at create(2)
                // time and already holds the client's identity (correct).
                s.creator_pid = server_creds.pid;
                s.creator_uid = server_creds.uid;
                s.creator_gid = server_creds.gid;
                found = i as u64;
                break;
            }
        }
        found
    };
    if peer_id == u64::MAX { return -24; }

    t.0[id as usize].state   = UnixState::Connected;
    t.0[id as usize].peer_id = peer_id;
    // The client-side socket retains its own creator credentials (captured at
    // create(2) time).  peer_creds(server_accepted_fd) looks up THIS socket's
    // creator_* and returns the connecting client's identity — per unix(7).

    let srv = &mut t.0[server_id as usize];
    if srv.backlog_len < BACKLOG_CAP {
        srv.backlog[srv.backlog_len] = peer_id;
        srv.backlog_len += 1;
    }
    // Drop the table lock before ringing — a `poll`/`epoll_wait`
    // caller blocked on the listener fd for `POLLIN` (the
    // connection-pending readiness signal per `accept(2)`) re-checks
    // `has_pending()` on its rescan and proceeds to `accept` without
    // waiting for the resync floor.
    drop(t);
    crate::ipc::waitlist::ring_poll_bell_for(
        crate::ipc::waitlist::PollBellSource::UnixShutdown);
    0
}

pub fn accept(id: u64) -> i64 {
    if id as usize >= MAX_UNIX_SOCKETS { return -9; }
    let mut t = TABLE.lock();
    let s = &mut t.0[id as usize];
    if s.state != UnixState::Listening { return -22; }
    if s.backlog_len == 0 { return -11; } // EAGAIN
    let peer_id = s.backlog[0];
    for i in 0..s.backlog_len - 1 { s.backlog[i] = s.backlog[i + 1]; }
    s.backlog_len -= 1;
    drop(t);
    // The newly-accepted peer fd is immediately writable (and may
    // already have buffered data from a fast connect-write client).
    // Wake any pre-existing poller that registered the peer fd before
    // accept completed so it does not stall on the resync floor.
    crate::ipc::waitlist::ring_poll_bell_for(
        crate::ipc::waitlist::PollBellSource::UnixShutdown);
    peer_id as i64
}

pub fn socketpair(kind: SockKind, creds: PeerCreds) -> (u64, u64) {
    let mut t = TABLE.lock();
    let mut a = u64::MAX;
    let mut b = u64::MAX;
    for (i, s) in t.0.iter_mut().enumerate() {
        if s.state == UnixState::Free {
            if a == u64::MAX {
                s.reset();
                s.state       = UnixState::Connected;
                s.kind        = kind;
                s.ref_count   = 1; // one reference: fd[0] returned by socketpair(2)
                s.creator_pid = creds.pid;
                s.creator_uid = creds.uid;
                s.creator_gid = creds.gid;
                a = i as u64;
            } else {
                s.reset();
                s.state       = UnixState::Connected;
                s.kind        = kind;
                s.ref_count   = 1; // one reference: fd[1] returned by socketpair(2)
                s.creator_pid = creds.pid;
                s.creator_uid = creds.uid;
                s.creator_gid = creds.gid;
                b = i as u64;
                break;
            }
        }
    }
    if b == u64::MAX {
        if a != u64::MAX { t.0[a as usize].state = UnixState::Free; }
        return (u64::MAX, u64::MAX);
    }
    t.0[a as usize].peer_id = b;
    t.0[b as usize].peer_id = a;
    (a, b)
}

pub fn write(id: u64, data: &[u8]) -> i64 {
    if id as usize >= MAX_UNIX_SOCKETS { return -9; }
    let mut t = TABLE.lock();
    let (peer_id, kind) = {
        let s = &t.0[id as usize];
        if s.state != UnixState::Connected { return -32; }
        // SHUT_WR locally → -EPIPE per IEEE 1003.1 §shutdown.
        if s.shut_wr { return -32; }
        // Peer fully closed → -EPIPE per POSIX write(2)/send(2) on a
        // stream socket whose peer is gone.  (`peer_id` is severed to
        // u64::MAX at peer teardown, so the bounds check below also
        // catches this; the explicit flag keeps the intent readable.)
        if s.peer_closed { return -32; }
        (s.peer_id, s.kind)
    };
    if peer_id as usize >= MAX_UNIX_SOCKETS { return -32; }
    // Mutual-pairing gate: only deliver if the resolved peer slot still
    // points back at US.  The socket table recycles slot indices the moment
    // a slot's last reference is closed; a stale `peer_id` held across that
    // recycling would otherwise inject this stream's bytes into an UNRELATED
    // connection's receive ring (cross-channel corruption).  A connected
    // pair is mutual by construction (socketpair(2)/connect(2)), so a
    // mismatch can only mean "freed and possibly recycled" → the write must
    // observe -EPIPE, exactly as if the peer had closed (POSIX send(2)).
    {
        let peer = &t.0[peer_id as usize];
        if peer.state != UnixState::Connected || peer.peer_id != id {
            return -32;
        }
    }

    if kind == SockKind::SeqPacket {
        // SEQPACKET: an entire message must fit in the receiver's ring AND
        // a free slot must exist in the message-length queue.  Per POSIX
        // SOCK_SEQPACKET, a partial message is never delivered — either
        // the whole datagram lands or the call returns -EAGAIN.
        let peer = &mut t.0[peer_id as usize];
        let queued = (peer.seq_tail + SEQ_QUEUE_CAP - peer.seq_head) % SEQ_QUEUE_CAP;
        if queued >= SEQ_QUEUE_CAP - 1 { return -11; }   // EAGAIN — queue full
        if data.len() > peer.recv_space() { return -11; } // EAGAIN — buffer full
        let n = peer.push(data);
        // n == data.len() because we checked space above.
        peer.seq_lens[peer.seq_tail] = n as u32;
        peer.seq_tail = (peer.seq_tail + 1) % SEQ_QUEUE_CAP;
        // Drop the table lock before ringing the global poll bell so a
        // poller waking on the bell does not contend on TABLE on its
        // re-evaluation pass.
        drop(t);
        // Targeted by `peer_id` — the receiver's socket id, which is exactly
        // what a peer poller's fd resolves to via `get_unix_socket_id` — so only
        // pollers on that socket re-scan, not every AF_UNIX poller.
        crate::ipc::waitlist::ring_poll_bell_for_obj(
            crate::ipc::waitlist::PollBellSource::UnixWrite, peer_id);
        // Attribute SEQPACKET bytes to the writer.
        crate::proc::proc_metrics::bump_net_write(
            crate::proc::current_pid_lockless(), n as u64);
        return n as i64;
    }

    // STREAM: byte-stream, partial writes permitted.
    let n = t.0[peer_id as usize].push(data);
    drop(t);
    if n > 0 {
        // Wake any poll/epoll/select caller watching the peer fd.  The
        // pre-existing read path returns -EAGAIN when the buffer is empty,
        // so without this kick the caller would wait for the next resync
        // tick to discover the new bytes.  Targeted by `peer_id` (the
        // receiver's socket id = what the peer poller's fd resolves to).
        crate::ipc::waitlist::ring_poll_bell_for_obj(
            crate::ipc::waitlist::PollBellSource::UnixWrite, peer_id);
        // Attribute outbound AF_UNIX bytes to the writer.
        crate::proc::proc_metrics::bump_net_write(
            crate::proc::current_pid_lockless(), n as u64);
    }
    if n == 0 { -11 } else { n as i64 }
}

pub fn read(id: u64, buf: &mut [u8]) -> i64 {
    let (n, _truncated) = match read_msg(id, buf) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if n > 0 {
        crate::proc::proc_metrics::bump_net_read(
            crate::proc::current_pid_lockless(), n as u64);
    }
    n as i64
}

/// Read one message from the socket.
///
/// Returns `Ok((bytes_copied, truncated_extra))` on success:
///   * `bytes_copied`     — number of bytes actually placed in `buf`
///   * `truncated_extra`  — bytes discarded from a SEQPACKET message that
///     did not fit in `buf` (always 0 for STREAM, and 0 for SEQPACKET when
///     the buffer was large enough).  Callers (recvmsg) should set the
///     `MSG_TRUNC` flag when this is non-zero.
///
/// Returns `Err(errno)` for: -EBADF, -EAGAIN, and orderly EOF (0 from a
/// shut-rd socket is signalled as `Ok((0, 0))` to keep the existing read()
/// caller contract intact).
pub fn read_msg(id: u64, buf: &mut [u8]) -> Result<(usize, usize), i64> {
    if id as usize >= MAX_UNIX_SOCKETS { return Err(-9); }
    let mut t = TABLE.lock();
    let s = &mut t.0[id as usize];
    if s.state == UnixState::Free { return Err(-9); }
    // SHUT_RD locally → return 0 (orderly EOF) regardless of any data
    // still queued in our recv_buf.  Matches Linux AF_UNIX behaviour.
    if s.shut_rd { return Ok((0, 0)); }

    // The peer socket id — draining our recv ring makes the PEER's write side
    // newly POLLOUT-ready, so the UnixRead bell is targeted at `peer_id` (the
    // object a peer poller's fd resolves to via `get_unix_socket_id`).  Captured
    // here while the TABLE lock is held, before any drop.  A severed peer
    // (`u64::MAX`) yields a class-only ring below (harmless: no peer to wake).
    let peer_id = s.peer_id;

    // Number of bytes the drain frees from *our* recv ring.  Draining recv
    // space makes the *peer's* write side newly POLLOUT-ready, so once we
    // have dropped the TABLE lock we ring the write-side poll bell for any
    // peer parked in poll/epoll_wait waiting to become writable (`man 7
    // unix` recv-side write-space wake).  0 ⇒ nothing drained ⇒ no edge.
    let drained: usize;
    let result: Result<(usize, usize), i64>;

    if s.kind == SockKind::SeqPacket {
        // SEQPACKET: dequeue exactly one message, truncating any tail that
        // does not fit per `man 7 unix` §SOCK_SEQPACKET.
        if s.seq_head == s.seq_tail {
            // No queued message.  If the peer's write side is gone
            // (orderly shutdown or full close), report EOF — but only
            // AFTER the queue is empty: recv(2) requires queued data to
            // be returned before the 0-byte orderly-shutdown indication.
            if s.rx_eof { return Ok((0, 0)); }
            return Err(-11); // EAGAIN — no message
        }
        let msg_len = s.seq_lens[s.seq_head] as usize;
        s.seq_head = (s.seq_head + 1) % SEQ_QUEUE_CAP;

        let want    = buf.len().min(msg_len);
        let copied  = if want > 0 { s.pop(&mut buf[..want]) } else { 0 };
        let discard = msg_len - copied;
        // Drop the truncated tail from recv_buf so the next read sees the
        // start of the following message.  (We pop into a black-hole slot.)
        for _ in 0..discard {
            s.recv_head = (s.recv_head + 1) % RECV_BUF_CAP;
        }
        // Discarded bytes leave the ring too — keep the absolute stream
        // position (`recv_popped`) consistent with the wrapping head index.
        s.recv_popped = s.recv_popped.wrapping_add(discard as u64);
        // The whole message (copied + discarded tail) leaves the recv ring.
        drained = copied + discard;
        result  = Ok((copied, discard));
    } else {
        // STREAM: byte-stream — copy as many bytes as fit, no boundaries.
        if s.recv_available() == 0 {
            // Drain-then-EOF (recv(2)): once the ring is empty AND the peer
            // can never push more bytes (peer SHUT_WR or peer fully closed),
            // the read observes the orderly EOF.  Queued bytes always win.
            if s.rx_eof { return Ok((0, 0)); }
            return Err(-11);
        }
        let copied = s.pop(buf);
        drained = copied;
        result  = Ok((copied, 0));
    }

    // Drop the TABLE lock before ringing so a peer waking on the bell does
    // not contend on TABLE during its re-evaluation pass (same discipline
    // as `write()` / `shutdown()`).
    drop(t);
    if drained > 0 {
        // Targeted at the peer's socket id: only a poller on the peer fd (now
        // POLLOUT-ready) re-scans.  If the peer slot is severed, `peer_id` is
        // out of range and resolves to no parker — equivalent to a no-op.
        let obj = if (peer_id as usize) < MAX_UNIX_SOCKETS {
            peer_id
        } else {
            crate::ipc::waitlist::OBJECT_ID_NONE
        };
        crate::ipc::waitlist::ring_poll_bell_for_obj(
            crate::ipc::waitlist::PollBellSource::UnixRead, obj);
    }
    result
}

/// Half-close per IEEE 1003.1 §shutdown.  `shut_rd_flag` / `shut_wr_flag`
/// each, when true, mark the corresponding direction closed.
///
/// Because the AF_UNIX backend uses an in-memory ring, a SHUT_WR has no
/// FIN-equivalent on the wire; instead we propagate the semantic by
/// flipping the *peer's* `shut_rd`, so the peer's next `read` returns 0
/// (orderly EOF).  This mirrors Linux AF_UNIX where one half-closing
/// the write side surfaces as EOF on the peer's recv path.
///
/// Returns 0 on success, -EBADF for an invalid id, -ENOTCONN for an
/// unconnected stream socket (POSIX requirement).
pub fn shutdown(id: u64, shut_rd_flag: bool, shut_wr_flag: bool) -> i64 {
    if id as usize >= MAX_UNIX_SOCKETS { return -9; }
    let mut t = TABLE.lock();
    let s = &t.0[id as usize];
    if s.state == UnixState::Free { return -9; }
    if s.state != UnixState::Connected { return -107; } // ENOTCONN
    let peer_id = s.peer_id;
    let s = &mut t.0[id as usize];
    if shut_rd_flag { s.shut_rd = true; }
    if shut_wr_flag { s.shut_wr = true; }
    if shut_wr_flag && (peer_id as usize) < MAX_UNIX_SOCKETS {
        let p = &mut t.0[peer_id as usize];
        // Mutual-pairing gate (see `write`): never flip half-close state on
        // a slot that no longer points back at us — after slot recycling it
        // belongs to an UNRELATED connection, and a stale SHUT_WR here would
        // EOF-kill that innocent stream.  Also: the peer's read direction is
        // marked `rx_eof` (drain-then-EOF per recv(2)), NOT `shut_rd` —
        // bytes we pushed before half-closing must remain readable.
        if p.state == UnixState::Connected && p.peer_id == id {
            p.rx_eof = true;
        }
    }
    // Drop the table lock before ringing — per `man 2 shutdown` and
    // `man 7 unix`, a half-close surfaces on the peer as an orderly
    // EOF on subsequent `read()` and as `POLLIN | POLLRDHUP` /
    // `POLLHUP` on `poll`/`epoll_wait`.  Local listeners that watch
    // the peer fd would otherwise stall on the resync floor before
    // observing the new readiness — this is exactly the wedge the
    // Mozilla parent IPC bus tripped on, where the child's
    // `SHUT_RDWR` was invisible to the parent's `epoll_pwait2` until
    // the 1 s rescan.
    drop(t);
    // Lifecycle diagnostic (rare event — explicit shutdown(2) calls only).
    // Gate-1 instrumentation: a spurious EPOLLHUP/EPOLLRDHUP on a live IPC
    // channel implicates whoever flipped `shut_rd`; this names the caller.
    crate::serial_println!(
        "[UNIX/SHUT] id={} rd={} wr={} pid={} tid={}",
        id, shut_rd_flag, shut_wr_flag,
        crate::proc::current_pid_lockless(), crate::proc::current_tid());
    crate::ipc::waitlist::ring_poll_bell_for(
        crate::ipc::waitlist::PollBellSource::UnixShutdown);
    0
}

/// Increment the open-file-description reference count for socket `id`.
///
/// Must be called whenever an existing fd pointing at this socket slot is
/// duplicated — by `dup(2)`, `dup2(2)`, `dup3(2)`, or the fd-table copy
/// performed inside `fork(2)` / `clone(2)` (without `CLONE_FILES`).
/// Mirrors the `get_file()` increment in POSIX `dup_fd()`.  Per
/// POSIX.1-2017 §2.14 and `man 2 fork`: "open file descriptors shall be
/// duplicated"; the duplicated descriptors refer to the same open file
/// description and therefore the same underlying socket object.
pub fn inc_ref(id: u64) {
    if id as usize >= MAX_UNIX_SOCKETS { return; }
    let mut t = TABLE.lock();
    let s = &mut t.0[id as usize];
    if s.state != UnixState::Free {
        s.ref_count = s.ref_count.saturating_add(1);
    }
}

/// Tear down an AF_UNIX socket file description.
///
/// Decrements the open-file-description reference count.  The slot is only
/// recycled — and the peer notified of the orderly close — when the count
/// reaches zero, i.e. every fd that pointed at this socket across all
/// processes has been closed.  This satisfies POSIX.1-2017 §2.14:
/// "closing a file descriptor does not affect other file descriptors that
/// refer to the same open file description".
///
/// When the last reference is dropped we propagate the close as a
/// half-shutdown to the connected peer — flipping its `shut_rd` so any
/// subsequent local read on that peer returns 0 (orderly EOF) and any
/// epoll/poll waiter observes `EPOLLHUP` / `POLLHUP`.  We ring
/// `PollBellSource::UnixShutdown` so any thread currently parked in
/// `epoll_wait` / `poll` on the peer fd is woken in the same tick.
pub fn close(id: u64) {
    if id as usize >= MAX_UNIX_SOCKETS { return; }
    let mut t = TABLE.lock();
    let s = &mut t.0[id as usize];
    if s.state == UnixState::Free { return; }
    // Catch double-close or close-without-inc_ref in debug builds.
    // ref_count==0 here means a slot is being closed more times than it
    // was acquired, which is a kernel bookkeeping bug — not a user error.
    debug_assert!(s.ref_count > 0,
        "net::unix::close: id={} ref_count already 0 (double-close or \
         missing inc_ref on dup/fork)", id);
    // Release-mode visibility for the same bookkeeping bug the
    // debug_assert above catches: an underflow here means an extra
    // decrement (or missing fork/dup increment) is tearing a live
    // socket down early — the peer then observes a spurious hang-up.
    let underflow = s.ref_count == 0;
    // Decrement the reference count.  Only proceed with teardown when
    // the last open reference is released (count reaches zero).
    if s.ref_count > 1 {
        s.ref_count -= 1;
        return;
    }
    // ref_count == 1 (or 0 for legacy slots created before this field
    // was added — treat as "last reference").
    let peer_id = s.peer_id;
    s.reset();
    let mut ring = false;
    let mut peer_was_connected = false;
    if (peer_id as usize) < MAX_UNIX_SOCKETS {
        let peer = &mut t.0[peer_id as usize];
        // Mutual-pairing gate: only notify the peer if it still points back
        // at the slot we just freed.  Slot indices are recycled the moment a
        // slot's last reference drops; without this check, closing a STALE
        // survivor (one whose own peer died earlier) would flip half-close
        // state on whatever UNRELATED connection re-allocated the index.
        if peer.state == UnixState::Connected && peer.peer_id == id {
            // The peer survives us:
            //  * `rx_eof` — its reads drain any queued bytes, then observe
            //    the orderly EOF (recv(2): data first, then 0).
            //  * `peer_closed` — its writes fail -EPIPE, poll reports
            //    POLLHUP (full hang-up; POSIX poll(2)).
            //  * SEVER its back-pointer: our slot index is about to become
            //    recyclable, and any later dereference of it through the
            //    survivor (write/shutdown/close/SCM enqueue) would reach an
            //    unrelated connection.  u64::MAX fails every bounds check.
            peer.rx_eof      = true;
            peer.peer_closed = true;
            peer.peer_id     = u64::MAX;
            ring = true;
            peer_was_connected = true;
        }
    }
    drop(t);
    // Lifecycle diagnostic (rare event — final teardown only, never the
    // common ref_count-decrement path).  Gate-1 instrumentation: when a
    // live IPC channel collapses with a spurious hang-up, this line names
    // the tearing process and whether the peer was still connected.
    crate::serial_println!(
        "[UNIX/TEARDOWN] id={} peer={} peer_connected={} underflow={} pid={} tid={}",
        id, peer_id, peer_was_connected, underflow,
        crate::proc::current_pid_lockless(), crate::proc::current_tid());
    // This socket is now fully torn down.  Any `SCM_RIGHTS` ancillary fds that
    // were queued for it but never `recvmsg`'d are about to be lost — release
    // the references that the sender took at enqueue time so the passed
    // socket / pipe / file is not leaked and its peer observes the hang-up
    // (CWE-772; unix(7) / recvmsg(2) SCM_RIGHTS: undelivered fds in a destroyed
    // receive queue are dropped, mirroring close(2) of a delivered copy).
    // The TABLE lock is released here, so draining (PENDING_SCM lock) and the
    // per-fd drop (which may re-enter this function for a passed socket) cannot
    // deadlock against the lock we just held.
    let orphaned = crate::syscall::scm_drain_receiver(id);
    if !orphaned.is_empty() {
        crate::syscall::scm_drop_fds(orphaned);
    }
    if ring {
        crate::ipc::waitlist::ring_poll_bell_for(
            crate::ipc::waitlist::PollBellSource::UnixShutdown);
    }
}

pub fn has_data(id: u64) -> bool {
    if id as usize >= MAX_UNIX_SOCKETS { return false; }
    let t = TABLE.lock();
    let s = &t.0[id as usize];
    if s.kind == SockKind::SeqPacket {
        s.seq_head != s.seq_tail
    } else {
        s.recv_available() > 0
    }
}

/// Returns true if the local read direction is at EOF — the RCV_SHUTDOWN
/// equivalent.  This is set when the local side did `shutdown(SHUT_RD)`,
/// the peer did `shutdown(SHUT_WR)`, or the peer `close()`d (all of which
/// flip our `shut_rd`; see `shutdown()` / `close()` above).
///
/// This is a *read-direction half-close*: subsequent local `read()`s return
/// 0 (orderly EOF) but the connection is NOT torn down and the local write
/// direction stays valid.  Per `epoll(7)`, a read-side hang-up maps to
/// `EPOLLRDHUP` (and the read end becomes readable, so `EPOLLIN` too); per
/// `poll(2)` it maps to `POLLIN` / `POLLRDHUP`.  It does *not* by itself
/// imply `EPOLLHUP` / `POLLHUP`, which mean a *full* hang-up — see
/// [`fully_hung_up`].
pub fn read_shutdown(id: u64) -> bool {
    if id as usize >= MAX_UNIX_SOCKETS { return false; }
    let t = TABLE.lock();
    let s = &t.0[id as usize];
    if s.state == UnixState::Free { return true; }
    // `rx_eof` (peer SHUT_WR or peer close) raises the same POLLIN/POLLRDHUP
    // readiness edges as a local SHUT_RD: the read side can no longer block
    // (queued bytes are returned, then 0).  Edge TIMING is identical to the
    // pre-`rx_eof` behaviour, which flipped `shut_rd` directly.
    s.shut_rd || s.rx_eof
}

/// Returns true on a *full* hang-up — the SHUTDOWN_MASK / TCP_CLOSE
/// equivalent — where the connection is dead in both directions.  This is
/// the only condition under which `epoll(7)` reports `EPOLLHUP` and
/// `poll(2)` reports `POLLHUP` (both meaning "connection fully dead", as
/// opposed to `EPOLLRDHUP`'s "read EOF, write still valid").
///
/// It is true when:
///   * our slot is `Free` (fully closed locally — TCP_CLOSE), or
///   * the peer's slot is `Free` (peer fully closed — TCP_CLOSE), or
///   * both directions have been shut down locally
///     (`shut_rd && shut_wr`, i.e. `SHUT_RDWR` — SHUTDOWN_MASK).
///
/// A read-side-only half-close (peer `shutdown(SHUT_WR)`: our `shut_rd`
/// set but `shut_wr` clear, both slots still `Connected`) is deliberately
/// NOT a full hang-up — the write direction stays usable and only
/// [`read_shutdown`] fires.
pub fn fully_hung_up(id: u64) -> bool {
    if id as usize >= MAX_UNIX_SOCKETS { return false; }
    let t = TABLE.lock();
    let s = &t.0[id as usize];
    if s.state == UnixState::Free { return true; }
    if s.shut_rd && s.shut_wr { return true; }
    // Peer fully closed — recorded as a flag at teardown time (the peer's
    // slot index is severed/recyclable, so probing `t.0[peer].state` would
    // race with re-allocation and is no longer meaningful).
    if s.peer_closed { return true; }
    let peer = s.peer_id;
    if peer == u64::MAX { return false; }
    if (peer as usize) >= MAX_UNIX_SOCKETS { return false; }
    t.0[peer as usize].state == UnixState::Free
}

/// Returns true if a `write(2)` on socket `id` would make progress right now —
/// the AF_UNIX equivalent of the `POLLOUT` / `EPOLLOUT` writable predicate.
///
/// For our in-memory backend a STREAM `write()` pushes bytes directly into the
/// *peer's* `recv_buf`; the call returns `-EAGAIN` exactly when that ring has no
/// free space (`recv_space() == 0`).  A faithful `poll(2)` / `epoll_wait(2)`
/// must therefore gate `POLLOUT` / `EPOLLOUT` on the peer having recv-buffer
/// room, rather than advertising the socket writable unconditionally — an
/// always-writable report makes a producer blocked on a full socket busy-spin
/// `poll → write → EAGAIN`, the stuck-producer pattern `poll(2)` exists to
/// avoid (`man 7 unix`, `man 2 poll`).
///
/// Per the long-standing AF_UNIX rule — writable is also reported once the
/// write side can no longer block, so a blocked writer is released to observe
/// the terminal `-EPIPE` instead of hanging forever:
///   * not in `Connected` state (unbound / listening / disconnected) — a
///     `write()` returns immediately (`-ENOTCONN` / `-EPIPE`), never blocks;
///   * locally `shut_wr` — `write()` returns `-EPIPE` immediately;
///   * peer slot gone — `write()` returns `-EPIPE` immediately.
/// In all of those cases the call completes without blocking, so `POLLOUT`
/// is the correct, stuck-socket-avoiding answer.
pub fn writable(id: u64) -> bool {
    if id as usize >= MAX_UNIX_SOCKETS { return false; }
    let t = TABLE.lock();
    let s = &t.0[id as usize];
    if s.state == UnixState::Free { return true; }     // closed: write → EPIPE, no block
    if s.state != UnixState::Connected { return true; } // not connected: never blocks
    if s.shut_wr { return true; }                       // SHUT_WR: write → EPIPE, no block
    if s.peer_closed { return true; }                   // peer gone: write → EPIPE, no block
    let peer = s.peer_id;
    if peer == u64::MAX || (peer as usize) >= MAX_UNIX_SOCKETS { return true; }
    let peer = &t.0[peer as usize];
    if peer.state == UnixState::Free { return true; }   // peer gone: write → EPIPE, no block
    // Genuinely connected, write side open, peer alive: writable iff the peer's
    // recv ring has room for at least one byte — the exact condition under
    // which our STREAM/SEQPACKET `write()` returns >0 rather than -EAGAIN.
    peer.recv_space() > 0
}

pub fn bytes_available(id: u64) -> usize {
    if id as usize >= MAX_UNIX_SOCKETS { return 0; }
    let t = TABLE.lock();
    let s = &t.0[id as usize];
    if s.kind == SockKind::SeqPacket {
        // For SEQPACKET, ioctl(FIONREAD) and friends should report the size
        // of the *next* message, not the cumulative buffer fill.  Linux
        // returns 0 when no message is pending.
        if s.seq_head == s.seq_tail { 0 }
        else { s.seq_lens[s.seq_head] as usize }
    } else {
        s.recv_available()
    }
}

/// Absolute stream position (total bytes ever pushed into the recv ring) at
/// which a freshly-sent `SCM_RIGHTS` batch should attach.  An ancillary-only
/// frame (`iov_len == 0`) pushes no bytes, so its fds attach *after* every
/// byte already queued — i.e. at the current `recv_pushed`.  See
/// [`scm_deliverable_offset`] for the matching drain-side test.  Returns 0
/// for an out-of-range id.
pub fn enqueue_offset_for(id: u64) -> u64 {
    if id as usize >= MAX_UNIX_SOCKETS { return 0; }
    let t = TABLE.lock();
    t.0[id as usize].enqueue_offset()
}

/// Total bytes ever drained (popped, including SEQPACKET-truncated tails)
/// from the recv ring of socket `id` — the absolute read position.  A queued
/// `SCM_RIGHTS` batch bound to `byte_offset` becomes deliverable once this
/// reaches `byte_offset` (the reader has consumed every data byte that
/// preceded the ancillary message).  Returns 0 for an out-of-range id.
pub fn recv_consumed(id: u64) -> u64 {
    if id as usize >= MAX_UNIX_SOCKETS { return 0; }
    let t = TABLE.lock();
    t.0[id as usize].recv_popped
}

/// Current incarnation (recycle generation) of slot `id` — see the
/// `UnixSocket::incarnation` field.  An `SCM_RIGHTS` batch records this at
/// enqueue and delivery refuses a batch whose recorded incarnation differs,
/// so a stale batch can never reach a recycled slot's new occupant.  Returns
/// `u64::MAX` (a value no live slot can hold after a real recycle, and which
/// no batch records) for an out-of-range id so callers fail closed.
pub fn current_incarnation(id: u64) -> u64 {
    if id as usize >= MAX_UNIX_SOCKETS { return u64::MAX; }
    let t = TABLE.lock();
    t.0[id as usize].incarnation
}

/// Usable byte-stream capacity of one AF_UNIX socket end's recv ring — the
/// maximum number of bytes a `sendmsg(2)`/`write(2)` to the peer can have
/// outstanding (unread) before the transport returns -EAGAIN.  The ring stores
/// `RECV_BUF_CAP` slots but reserves one to disambiguate full-vs-empty (see
/// `recv_space`), so the usable capacity is `RECV_BUF_CAP - 1`.
///
/// Reported verbatim via `getsockopt(SO_SNDBUF)`/`SO_RCVBUF` so that a
/// length-prefixed IPC stream writer (which queries SO_SNDBUF to decide how
/// large a single `sendmsg(2)` to offer, per socket(7)) chunks at the real
/// transport boundary.  Advertising a larger SO_SNDBUF than the ring can hold
/// makes such a writer offer a >ring-sized frame in one call, which the
/// transport can only partially accept — forcing the partial-write resume path
/// on every large frame.
pub const fn buf_capacity() -> usize {
    RECV_BUF_CAP - 1
}

/// Return the socket type (`Stream` or `SeqPacket`) for an open socket id.
/// Returns `Stream` for an out-of-range id (matching the default).
pub fn kind(id: u64) -> SockKind {
    if id as usize >= MAX_UNIX_SOCKETS { return SockKind::Stream; }
    TABLE.lock().0[id as usize].kind
}

/// Test-only override of a socket endpoint's creator credentials.
///
/// Used by `kernel/src/test_runner.rs` Test 230 to simulate an
/// asymmetric `connect(2)`-established socket pair where the two ends
/// have distinct creator pids — driving the same `peer_creds()` lookup
/// the SO_PEERCRED syscall path would.  Not exposed to userland in any
/// build.
#[cfg(feature = "test-mode")]
pub fn test_only_set_creds(id: u64, creds: PeerCreds) {
    if id as usize >= MAX_UNIX_SOCKETS { return; }
    let mut t = TABLE.lock();
    let s = &mut t.0[id as usize];
    if s.state == UnixState::Free { return; }
    s.creator_pid = creds.pid;
    s.creator_uid = creds.uid;
    s.creator_gid = creds.gid;
}

/// Return the credentials of the **peer** of the socket referred to by `id`.
///
/// Implements the lookup required by `getsockopt(SO_PEERCRED)` per
/// `unix(7)` SO_PEERCRED and POSIX-style local-domain credential passing:
/// "the credentials of the peer process connected to this socket."  For a
/// `socketpair(2)` the peer is the other half of the pair; for a
/// `connect(2)`/`accept(2)` pair the peer is the process at the far end
/// of the established stream.
///
/// Returns `None` when the socket is invalid, free, or has no connected
/// peer.  Callers (the SO_PEERCRED implementation) should translate that
/// into the kernel-default ucred `{ pid: 0, uid: 0, gid: 0 }` so legacy
/// callers that ignore the return value still see a well-defined struct.
///
/// Cite POSIX.1-2017 §getsockopt; Linux `unix(7)` SO_PEERCRED.  CWE-287
/// (Improper Authentication) — finding H7 of the 2026-05-16 AstryxOS
/// security audit.
pub fn peer_creds(id: u64) -> Option<PeerCreds> {
    if id as usize >= MAX_UNIX_SOCKETS { return None; }
    let t = TABLE.lock();
    let s = &t.0[id as usize];
    if s.state == UnixState::Free { return None; }
    let peer = s.peer_id;
    if peer == u64::MAX || (peer as usize) >= MAX_UNIX_SOCKETS { return None; }
    let p = &t.0[peer as usize];
    if p.state == UnixState::Free { return None; }
    Some(PeerCreds {
        pid: p.creator_pid,
        uid: p.creator_uid,
        gid: p.creator_gid,
    })
}

pub fn has_pending(id: u64) -> bool {
    if id as usize >= MAX_UNIX_SOCKETS { return false; }
    TABLE.lock().0[id as usize].backlog_len > 0
}

/// Diagnostic-only one-socket snapshot for the kdb `unix-diag` op.
/// Reports the recv-ring read-readiness state of socket `id` so a live wedge
/// can be classified: `recv_avail` = unread bytes sitting in the ring (the
/// `has_data` input), `recv_pushed`/`recv_popped` = absolute stream positions
/// (the `enqueue_offset`/`recv_consumed` inputs to SCM delivery), plus the
/// half-close edges.  All values read under one TABLE lock.  Returns None for
/// an out-of-range or Free slot.
pub fn diag_for(id: u64) -> Option<UnixDiag> {
    if id as usize >= MAX_UNIX_SOCKETS { return None; }
    let t = TABLE.lock();
    let s = &t.0[id as usize];
    if s.state == UnixState::Free { return None; }
    Some(UnixDiag {
        id,
        state: s.state,
        kind: s.kind,
        peer_id: s.peer_id,
        recv_avail: s.recv_available(),
        recv_pushed: s.recv_pushed,
        recv_popped: s.recv_popped,
        read_shutdown: s.shut_rd,
        write_shutdown: s.shut_wr,
        rx_eof: s.rx_eof,
        peer_closed: s.peer_closed,
    })
}

/// Per-socket recv-readiness diagnostic (see [`diag_for`]).
pub struct UnixDiag {
    pub id: u64,
    pub state: UnixState,
    pub kind: SockKind,
    pub peer_id: u64,
    pub recv_avail: usize,
    pub recv_pushed: u64,
    pub recv_popped: u64,
    pub read_shutdown: bool,
    pub write_shutdown: bool,
    /// Peer write side gone (SHUT_WR or full close) — reads drain then EOF.
    pub rx_eof: bool,
    /// Peer endpoint fully closed; `peer_id` has been severed to u64::MAX.
    pub peer_closed: bool,
}

pub fn state(id: u64) -> UnixState {
    if id as usize >= MAX_UNIX_SOCKETS { return UnixState::Free; }
    TABLE.lock().0[id as usize].state
}

/// Return the peer socket id for a connected socket (u64::MAX if none).
pub fn get_peer(id: u64) -> u64 {
    if id as usize >= MAX_UNIX_SOCKETS { return u64::MAX; }
    TABLE.lock().0[id as usize].peer_id
}

/// Snapshot of one slot in the global unix socket TABLE.
/// Used by kdb `fd-map` to resolve socketpair peer relationships
/// without holding the TABLE lock across the entire traversal.
pub struct SocketSnap {
    pub id:       u64,
    pub state:    UnixState,
    pub kind:     SockKind,
    pub peer_id:  u64,
    pub recv_avail: usize,
    pub path:     [u8; UNIX_PATH_MAX],
    pub path_len: usize,
}

/// Snapshot all non-Free unix socket slots in one lock acquisition.
/// Returns at most `MAX_UNIX_SOCKETS` entries.
pub fn snapshot_all() -> Vec<SocketSnap> {
    let t = TABLE.lock();
    let mut out = Vec::new();
    for (i, s) in t.0.iter().enumerate() {
        if s.state == UnixState::Free { continue; }
        out.push(SocketSnap {
            id:          i as u64,
            state:       s.state,
            kind:        s.kind,
            peer_id:     s.peer_id,
            recv_avail:  s.recv_available(),
            path:        s.path,
            path_len:    s.path_len,
        });
    }
    out
}
