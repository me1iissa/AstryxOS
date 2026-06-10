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
pub const EPOLLET:      u32 = 1 << 31; // edge-triggered (enforced in sys_epoll_wait via per-watch et_seen)
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
    /// Edge-trigger baseline (`EPOLLET` only).  For a watch registered with
    /// `EPOLLET`, `epoll_wait(2)` must report a given readiness bit only on
    /// the rising edge — when the monitored fd transitions from not-having
    /// to having that condition — and NOT again until the condition is first
    /// cleared and then re-occurs (`epoll(7)`, "Level-triggered and
    /// edge-triggered").  `et_seen` records the subset of readiness bits that
    /// were already delivered on a prior `epoll_wait` and have stayed
    /// continuously asserted since: those bits are suppressed on subsequent
    /// calls.  A bit that drops to not-ready is cleared from `et_seen`, so a
    /// later re-rise fires a fresh edge.  Unused (always 0) for
    /// level-triggered watches.
    pub et_seen: u32,
    /// Per-source EPOLLIN rising-edge generation last delivered to this
    /// `EPOLLET` watch.  `et_seen` alone can only re-arm an edge when an
    /// `epoll_wait` happens to re-poll the fd while it is momentarily
    /// not-ready; a source that drops to not-ready and rises again entirely
    /// between two `epoll_wait` calls would otherwise be missed, because the
    /// readiness *bit* is identical across the two observations.  Sources
    /// that expose a monotonic rising-edge generation (e.g. eventfd) bump it
    /// on every not-ready→ready transition; storing the last-delivered value
    /// here lets `epoll_wait` recognise that a fresh edge occurred even when
    /// the bit looks unchanged, as `epoll(7)` requires.  Sources that do not
    /// expose a generation report 0, so this field stays 0 and the bit-based
    /// `et_seen` logic governs them unchanged.
    pub et_rise: u64,
}

/// Per-process monotonically increasing identifier for epoll instances.
///
/// Each `epoll_create1(2)` allocates a fresh `EpollInstance` and stamps a
/// unique 64-bit id into both the `EpollInstance.id` field AND the
/// owning `FileDescriptor.inode` slot.  The id is then the SHARED-state
/// key used by `sys_epoll_ctl` / `sys_epoll_wait` to locate the instance,
/// instead of the originally-allocated `epfd`.
///
/// Why per-process and not per-system?  The id only needs to disambiguate
/// among the epoll instances of *one* process — when a fd is dup'd via
/// `dup(2)` or `fcntl(F_DUPFD)`, the `FileDescriptor` is cloned (including
/// its `inode` field), so both fds end up with the SAME inode and thus the
/// SAME id.  Looking the instance up by id (not by epfd) means the watch
/// list is naturally shared between the original and the dup — which
/// matches POSIX/Linux semantics for shared open file descriptions
/// (POSIX.1-2017 §2.14; Linux epoll(7): "The set of file descriptors that
/// is being monitored is referred to as the interest list ... if the same
/// file descriptor is registered with multiple instances of epoll, ...").
///
/// We use a `static AtomicU64` rather than a per-process counter because:
///   (a) FileDescriptor.inode is a per-process field anyway — collisions
///       across processes don't matter, the lookup is always scoped to
///       the calling process's `epoll_sets`.
///   (b) A global counter is dead simple and cheap.
///   (c) Reserving 0 lets us keep the legacy `inode: 0` value as a
///       "uninitialised epoll" sentinel for any future callers.
///
/// Pre-PIVOT-I2 epoll_create1 left `inode = 0`.  The fix here uses a
/// non-zero id; any code path that still hard-codes `inode = 0` for an
/// epoll FileDescriptor (there should be none, but a forensic grep is
/// part of the dispatch) will start failing the by-id lookup explicitly
/// rather than silently aliasing to "the first epoll instance".
fn next_epoll_id() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// One epoll instance — created by `epoll_create1`.
#[derive(Clone)]
pub struct EpollInstance {
    /// Per-process unique identifier (see `next_epoll_id()` for rationale).
    /// Stored ALSO in the owning `FileDescriptor.inode` field, so any
    /// dup of the fd carries the id forward and resolves to the same
    /// instance via the by-id lookup helpers below.
    pub id:      u64,
    /// The fd in the process fd table that represents this epoll object.
    /// Recorded only for diagnostic / legacy-introspection use; the
    /// canonical lookup key is now `id`.  Kept as `usize::MAX` for
    /// instances created via the `new()` shorthand without a backing fd
    /// (e.g. in test fixtures); `new_with_fd` stamps a real value.
    pub epfd:    usize,
    /// Registered watches.
    pub watches: Vec<EpollWatch>,
}

impl EpollInstance {
    /// Legacy constructor — kept for callers that have not yet been
    /// migrated to the by-id model.  Allocates a fresh id but leaves
    /// `epfd` as the value passed (legacy callers know their epfd).
    /// New code should prefer `new_with_id()` and explicitly pair the
    /// id with the FileDescriptor.inode at creation time.
    pub fn new(epfd: usize) -> Self {
        Self { id: next_epoll_id(), epfd, watches: Vec::new() }
    }

    /// Allocate a fresh id and return it alongside the new instance.
    /// The caller MUST also stamp the same id into the matching
    /// `FileDescriptor.inode` slot so subsequent `sys_epoll_ctl`/wait
    /// lookups can find the instance through any dup'd fd.
    pub fn new_with_id(epfd: usize) -> (Self, u64) {
        let id = next_epoll_id();
        (Self { id, epfd, watches: Vec::new() }, id)
    }

    /// EPOLL_CTL_ADD — returns `false` (caller should return -EEXIST) if already registered.
    ///
    /// The stored mask is the caller's *raw* interest set, unmodified.  Per
    /// `epoll(7)`, `EPOLLERR` and `EPOLLHUP` are always reported and "it is
    /// not necessary to set [them] in `events`" — but rather than mutate the
    /// stored mask here (which would perturb the readiness/wake matching that
    /// every `sys_epoll_wait` re-check depends on), the always-on hang-up /
    /// error edge is force-added at the single `sys_epoll_wait` return site
    /// (`subscribed & (ready | EPOLLERR | EPOLLHUP)`).  Keeping the stored
    /// mask raw guarantees the wake path sees exactly the caller's interest
    /// and no spurious HUP/ERR readiness leaks into the parking decision.
    pub fn add(&mut self, fd: usize, events: u32, data: u64) -> bool {
        if self.watches.iter().any(|w| w.fd == fd) { return false; }
        self.watches.push(EpollWatch { fd, events, data, et_seen: 0, et_rise: 0 });
        true
    }

    /// EPOLL_CTL_DEL — returns `false` (ENOENT) if fd not registered.
    pub fn del(&mut self, fd: usize) -> bool {
        let before = self.watches.len();
        self.watches.retain(|w| w.fd != fd);
        self.watches.len() < before
    }

    /// EPOLL_CTL_MOD — returns `false` (ENOENT) if fd not registered.
    ///
    /// As in `add()`, the stored mask is the caller's raw interest set; the
    /// always-on `EPOLLERR | EPOLLHUP` edge is force-added at the
    /// `sys_epoll_wait` return site, not mutated into the stored mask.  A
    /// `MOD` that narrows the caller's interest therefore still surfaces
    /// ERR/HUP (added at delivery) without the stored mask diverging from
    /// what the caller requested.
    pub fn modify(&mut self, fd: usize, events: u32, data: u64) -> bool {
        if let Some(w) = self.watches.iter_mut().find(|w| w.fd == fd) {
            w.events = events;
            w.data   = data;
            // `EPOLL_CTL_MOD` re-arms the watch: per `epoll(7)`, changing the
            // interest mask of an `EPOLLET` watch makes any currently-asserted
            // condition count as a fresh edge on the next `epoll_wait`.  Reset
            // both edge baselines (the seen-bits AND the rising-edge
            // generation) so a level-ready fd is reported once more.
            w.et_seen = 0;
            w.et_rise = 0;
            true
        } else {
            false
        }
    }
}
