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
            seq_lens:    [0u32; SEQ_QUEUE_CAP],
            seq_head:    0,
            seq_tail:    0,
            backlog:     [u64::MAX; BACKLOG_CAP],
            backlog_len: 0,
            shut_rd:     false,
            shut_wr:     false,
        }
    }

    fn reset(&mut self) {
        self.state       = UnixState::Free;
        self.kind        = SockKind::Stream;
        self.path_len    = 0;
        self.peer_id     = u64::MAX;
        self.recv_head   = 0;
        self.recv_tail   = 0;
        self.seq_head    = 0;
        self.seq_tail    = 0;
        self.backlog_len = 0;
        self.shut_rd     = false;
        self.shut_wr     = false;
    }

    fn recv_available(&self) -> usize {
        (self.recv_tail + RECV_BUF_CAP - self.recv_head) % RECV_BUF_CAP
    }

    fn recv_space(&self) -> usize {
        RECV_BUF_CAP - 1 - self.recv_available()
    }

    fn push(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.recv_space());
        for &b in &data[..n] {
            self.recv_buf[self.recv_tail] = b;
            self.recv_tail = (self.recv_tail + 1) % RECV_BUF_CAP;
        }
        n
    }

    fn pop(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.recv_available());
        for byte in &mut buf[..n] {
            *byte = self.recv_buf[self.recv_head];
            self.recv_head = (self.recv_head + 1) % RECV_BUF_CAP;
        }
        n
    }
}

// ── Global socket table ───────────────────────────────────────────────────────

struct Table([UnixSocket; MAX_UNIX_SOCKETS]);
// SAFETY: UnixSocket contains only integer/array types — no heap pointers.
unsafe impl Send for Table {}

static TABLE: Mutex<Table> = Mutex::new(Table([UnixSocket::ZERO; MAX_UNIX_SOCKETS]));

impl UnixSocket { const ZERO: Self = Self::zeroed(); }

// ── Public API ────────────────────────────────────────────────────────────────

pub fn create(kind: SockKind) -> u64 {
    let mut t = TABLE.lock();
    for (i, s) in t.0.iter_mut().enumerate() {
        if s.state == UnixState::Free {
            s.reset();
            s.state = UnixState::Unbound;
            s.kind  = kind;
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

pub fn connect(id: u64, path: &[u8]) -> i64 {
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

    let peer_id = {
        let mut found = u64::MAX;
        for (i, s) in t.0.iter_mut().enumerate() {
            if i as u64 != id && s.state == UnixState::Free {
                s.reset();
                s.state   = UnixState::Connected;
                s.kind    = server_kind;
                s.peer_id = id;
                found = i as u64;
                break;
            }
        }
        found
    };
    if peer_id == u64::MAX { return -24; }

    t.0[id as usize].state   = UnixState::Connected;
    t.0[id as usize].peer_id = peer_id;

    let srv = &mut t.0[server_id as usize];
    if srv.backlog_len < BACKLOG_CAP {
        srv.backlog[srv.backlog_len] = peer_id;
        srv.backlog_len += 1;
    }
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
    peer_id as i64
}

pub fn socketpair(kind: SockKind) -> (u64, u64) {
    let mut t = TABLE.lock();
    let mut a = u64::MAX;
    let mut b = u64::MAX;
    for (i, s) in t.0.iter_mut().enumerate() {
        if s.state == UnixState::Free {
            if a == u64::MAX {
                s.reset();
                s.state = UnixState::Connected;
                s.kind  = kind;
                a = i as u64;
            } else {
                s.reset();
                s.state = UnixState::Connected;
                s.kind  = kind;
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
        (s.peer_id, s.kind)
    };
    if peer_id as usize >= MAX_UNIX_SOCKETS { return -32; }

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
        crate::ipc::waitlist::ring_poll_bell();
        return n as i64;
    }

    // STREAM: byte-stream, partial writes permitted.
    let n = t.0[peer_id as usize].push(data);
    drop(t);
    if n > 0 {
        // Wake any poll/epoll/select caller watching the peer fd.  The
        // pre-existing read path returns -EAGAIN when the buffer is empty,
        // so without this kick the caller would wait for the next 10 ms
        // tick to discover the new bytes.
        crate::ipc::waitlist::ring_poll_bell();
    }
    if n == 0 { -11 } else { n as i64 }
}

pub fn read(id: u64, buf: &mut [u8]) -> i64 {
    let (n, _truncated) = match read_msg(id, buf) {
        Ok(v) => v,
        Err(e) => return e,
    };
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

    if s.kind == SockKind::SeqPacket {
        // SEQPACKET: dequeue exactly one message, truncating any tail that
        // does not fit per `man 7 unix` §SOCK_SEQPACKET.
        if s.seq_head == s.seq_tail { return Err(-11); } // EAGAIN — no message
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
        return Ok((copied, discard));
    }

    // STREAM: byte-stream — copy as many bytes as fit, no boundaries.
    if s.recv_available() == 0 { return Err(-11); }
    Ok((s.pop(buf), 0))
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
        t.0[peer_id as usize].shut_rd = true;
    }
    0
}

pub fn close(id: u64) {
    if id as usize >= MAX_UNIX_SOCKETS { return; }
    TABLE.lock().0[id as usize].reset();
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

/// Return the socket type (`Stream` or `SeqPacket`) for an open socket id.
/// Returns `Stream` for an out-of-range id (matching the default).
pub fn kind(id: u64) -> SockKind {
    if id as usize >= MAX_UNIX_SOCKETS { return SockKind::Stream; }
    TABLE.lock().0[id as usize].kind
}

pub fn has_pending(id: u64) -> bool {
    if id as usize >= MAX_UNIX_SOCKETS { return false; }
    TABLE.lock().0[id as usize].backlog_len > 0
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
