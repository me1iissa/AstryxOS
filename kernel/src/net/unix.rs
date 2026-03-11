//! AF_UNIX (UNIX domain) socket implementation.
//!
//! Provides local inter-process communication via named (path-based) and
//! unnamed (socketpair) UNIX sockets.  Supports SOCK_STREAM only.
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
    path:        [u8; UNIX_PATH_MAX],
    path_len:    usize,
    peer_id:     u64,
    recv_buf:    [u8; RECV_BUF_CAP],
    recv_head:   usize,
    recv_tail:   usize,
    backlog:     [u64; BACKLOG_CAP],
    backlog_len: usize,
}

impl UnixSocket {
    const fn zeroed() -> Self {
        Self {
            state:       UnixState::Free,
            path:        [0u8; UNIX_PATH_MAX],
            path_len:    0,
            peer_id:     u64::MAX,
            recv_buf:    [0u8; RECV_BUF_CAP],
            recv_head:   0,
            recv_tail:   0,
            backlog:     [u64::MAX; BACKLOG_CAP],
            backlog_len: 0,
        }
    }

    fn reset(&mut self) {
        self.state       = UnixState::Free;
        self.path_len    = 0;
        self.peer_id     = u64::MAX;
        self.recv_head   = 0;
        self.recv_tail   = 0;
        self.backlog_len = 0;
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

pub fn create() -> u64 {
    let mut t = TABLE.lock();
    for (i, s) in t.0.iter_mut().enumerate() {
        if s.state == UnixState::Free {
            s.reset();
            s.state = UnixState::Unbound;
            return i as u64;
        }
    }
    u64::MAX
}

pub fn bind(id: u64, path: &[u8]) -> i64 {
    if id as usize >= MAX_UNIX_SOCKETS { return -9; }
    let plen = path.len().min(UNIX_PATH_MAX);
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
    let plen = path.len().min(UNIX_PATH_MAX);
    let search = &path[..plen];
    let mut t = TABLE.lock();

    let server_id = t.0.iter().enumerate()
        .find(|(_, s)| s.state == UnixState::Listening && &s.path[..s.path_len] == search)
        .map(|(i, _)| i as u64)
        .unwrap_or(u64::MAX);
    if server_id == u64::MAX { return -111; }

    let peer_id = {
        let mut found = u64::MAX;
        for (i, s) in t.0.iter_mut().enumerate() {
            if i as u64 != id && s.state == UnixState::Free {
                s.reset();
                s.state   = UnixState::Connected;
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

pub fn socketpair() -> (u64, u64) {
    let mut t = TABLE.lock();
    let mut a = u64::MAX;
    let mut b = u64::MAX;
    for (i, s) in t.0.iter_mut().enumerate() {
        if s.state == UnixState::Free {
            if a == u64::MAX { s.reset(); s.state = UnixState::Connected; a = i as u64; }
            else             { s.reset(); s.state = UnixState::Connected; b = i as u64; break; }
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
    let peer_id = {
        let s = &t.0[id as usize];
        if s.state != UnixState::Connected { return -32; }
        s.peer_id
    };
    if peer_id as usize >= MAX_UNIX_SOCKETS { return -32; }
    let n = t.0[peer_id as usize].push(data);
    if n == 0 { -11 } else { n as i64 }
}

pub fn read(id: u64, buf: &mut [u8]) -> i64 {
    if id as usize >= MAX_UNIX_SOCKETS { return -9; }
    let mut t = TABLE.lock();
    let s = &mut t.0[id as usize];
    if s.state == UnixState::Free { return -9; }
    if s.recv_available() == 0 { return -11; }
    s.pop(buf) as i64
}

pub fn close(id: u64) {
    if id as usize >= MAX_UNIX_SOCKETS { return; }
    TABLE.lock().0[id as usize].reset();
}

pub fn has_data(id: u64) -> bool {
    if id as usize >= MAX_UNIX_SOCKETS { return false; }
    TABLE.lock().0[id as usize].recv_available() > 0
}

pub fn has_pending(id: u64) -> bool {
    if id as usize >= MAX_UNIX_SOCKETS { return false; }
    TABLE.lock().0[id as usize].backlog_len > 0
}

pub fn state(id: u64) -> UnixState {
    if id as usize >= MAX_UNIX_SOCKETS { return UnixState::Free; }
    TABLE.lock().0[id as usize].state
}
