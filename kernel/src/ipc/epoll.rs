//! Per-process epoll data structures (level-triggered).
//!
//! Event polling logic lives in `syscall/mod.rs` which has access to the
//! `is_pipe_fd`/`get_pipe_id` helpers.  This module is purely data.

extern crate alloc;
use alloc::vec::Vec;

// ─── EPOLL_CTL operations ────────────────────────────────────────────────────
pub const EPOLL_CTL_ADD: u64 = 1;
pub const EPOLL_CTL_DEL: u64 = 2;
pub const EPOLL_CTL_MOD: u64 = 3;

// ─── Event flags ─────────────────────────────────────────────────────────────
pub const EPOLLIN:      u32 = 0x0001;
pub const EPOLLPRI:     u32 = 0x0002;
pub const EPOLLOUT:     u32 = 0x0004;
pub const EPOLLERR:     u32 = 0x0008;
pub const EPOLLHUP:     u32 = 0x0010;
pub const EPOLLRDHUP:   u32 = 0x2000;
pub const EPOLLET:      u32 = 1 << 31; // edge-triggered (accepted but not enforced)
pub const EPOLLONESHOT: u32 = 1 << 30;

/// Equivalent to Linux `struct epoll_event` (packed, 12 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EpollEvent {
    pub events: u32,
    pub data:   u64,
}

/// One watched fd entry inside an EpollInstance.
#[derive(Clone)]
pub struct EpollWatch {
    pub fd:     usize,
    pub events: u32,
    pub data:   u64,
}

/// One epoll instance — created by `epoll_create1`.
#[derive(Clone)]
pub struct EpollInstance {
    /// The fd in the process fd table that represents this epoll object.
    pub epfd:    usize,
    /// Registered watches.
    pub watches: Vec<EpollWatch>,
}

impl EpollInstance {
    pub fn new(epfd: usize) -> Self {
        Self { epfd, watches: Vec::new() }
    }

    /// EPOLL_CTL_ADD — returns `false` (caller should return -EEXIST) if already registered.
    pub fn add(&mut self, fd: usize, events: u32, data: u64) -> bool {
        if self.watches.iter().any(|w| w.fd == fd) { return false; }
        self.watches.push(EpollWatch { fd, events, data });
        true
    }

    /// EPOLL_CTL_DEL — returns `false` (ENOENT) if fd not registered.
    pub fn del(&mut self, fd: usize) -> bool {
        let before = self.watches.len();
        self.watches.retain(|w| w.fd != fd);
        self.watches.len() < before
    }

    /// EPOLL_CTL_MOD — returns `false` (ENOENT) if fd not registered.
    pub fn modify(&mut self, fd: usize, events: u32, data: u64) -> bool {
        if let Some(w) = self.watches.iter_mut().find(|w| w.fd == fd) {
            w.events = events;
            w.data   = data;
            true
        } else {
            false
        }
    }
}
