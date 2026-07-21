//! VFS-level path-component lookup cache (positive **and negative** dentries).
//!
//! # What this caches
//!
//! `resolve_path_opts` walks a pathname component by component (IEEE Std
//! 1003.1-2017 §4.13 *Pathname Resolution*), dispatching one `lookup` plus
//! one `stat` into the concrete filesystem per component.  On a disk-backed
//! filesystem each dispatch can cost block-device round-trips, and under
//! load every round-trip is amplified by scheduler deschedule gaps.  Repeat
//! resolutions of the same components — including repeat *failed* lookups of
//! names that do not exist (e.g. sqlite probing `<db>-journal` / `<db>-wal`
//! before every transaction, per the documented hot-journal detection in
//! sqlite's locking protocol) — pay that full cost every time.
//!
//! This module memoizes the per-component outcome:
//!
//! * **positive entry** — `(mount, dir_inode, name) → (child_inode,
//!   file_type)`: a subsequent walk skips both the `lookup` and the
//!   symlink-check `stat` dispatch.
//! * **negative entry** — `(mount, dir_inode, name) → ENOENT`: a subsequent
//!   walk fails immediately with `NotFound`, with **zero** FS dispatches.
//!
//! The cache is strictly a fast path in front of `resolve_path_opts`; on a
//! miss the resolver behaves byte-identically to the uncached walk (same
//! dispatch order, same error propagation, same mount-crossing and symlink
//! semantics, same no-progress deadline).
//!
//! # Correctness: invalidation rules (bracketed)
//!
//! A stale **negative** entry makes a newly created file invisible
//! (`stat(2)` keeps returning ENOENT after a successful `creat(2)` — a
//! direct POSIX violation and an instant sqlite breaker); a stale
//! **positive** entry resurrects an unlinked name — and, worst case, under
//! inode-number reuse resolves to a *different* file's data.  Every VFS
//! operation that can change a `(directory, name) → object` binding
//! therefore **brackets** the concrete-FS mutation: it invalidates the
//! affected key(s) **before** the mutation AND again **after** it:
//!
//! | Operation (vfs/mod.rs helper)     | Bracketed key(s)                    |
//! |-----------------------------------|-------------------------------------|
//! | `create_file` / `open(O_CREAT)`   | (mount, parent, name)               |
//! | `mkdir`                           | (mount, parent, name)               |
//! | `remove` (unlink / rmdir, both    | (mount, parent, name)               |
//! |   immediate and deferred-unlink)  |                                     |
//! | `rename`                          | BOTH (mount, old_parent, old_name)  |
//! |                                   | AND  (mount, new_parent, new_name)  |
//! | `symlink`                         | (mount, parent, name)               |
//! | `link`                            | **NOT CURRENTLY WIRED** (see below) |
//! | mount-table change (mount/umount) | full flush before + after (mount    |
//! |                                   | indices shift on umount; new mounts |
//! |                                   | shadow paths)                       |
//!
//! **`link` / `linkat` are not wired in this tree** — syscalls 86/265 return
//! ENOSYS and there is no `vfs::link` helper, so `FileSystemOps::link`
//! (implemented by ext2/ramfs) is reachable only from an in-kernel unit test,
//! never from a resolvable namespace path, and can stale no entry today.  A
//! future `vfs::link` + syscall wiring MUST bracket-invalidate
//! `(mount, new_parent, new_name)` exactly as `symlink` does.
//!
//! ## Why bracket (read-vs-mutate), not just post-invalidate
//!
//! A post-only invalidate leaves a window between the FS mutation landing and
//! the invalidate executing in which a *concurrent, unsynchronized* reader on
//! another CPU could hit the still-warm stale entry on the lock-free hit path
//! (which consults no generation).  The bracket closes it as tightly as a
//! lock-free dispatch allows:
//!
//! * the **pre**-invalidate removes the warm entry — so no reader can
//!   short-circuit on the stale binding during the mutation — and bumps the
//!   generation, so a reader that snapshotted before the bracket has its stale
//!   re-insert dropped by the guard below;
//! * the **post**-invalidate sweeps any entry a mid-window reader re-derived
//!   from pre-mutation FS state.
//!
//! **Guarantee:** once the mutating call returns to its caller, no stale entry
//! for the affected key survives, so any reader causally ordered after the
//! mutating syscall observes the new binding.  A *genuinely concurrent*
//! unsynchronized reader may still observe a transient pre-mutation outcome
//! during the bracket window — but POSIX does not order such a read against the
//! concurrent mutation, so this is a permitted race, not a stale-state bug.
//! (Holding a lock across the FS dispatch would eliminate even the transient,
//! but is deliberately avoided — the #82/#476 same-thread lock-recursion /
//! deadlock class.)
//!
//! # Correctness: the insert/mutate race (SMP)
//!
//! Lookup-miss inserts are *not* atomic with the FS dispatch they memoize:
//!
//! ```text
//!   CPU A: cache miss → fs.lookup("x") = ENOENT      (dispatch, no lock)
//!   CPU B: create("x") completes → invalidate("x")   (removes nothing)
//!   CPU A: insert negative "x"                       (STALE — never expires!)
//! ```
//!
//! Mature kernels close this by holding the parent directory lock across
//! both the FS operation and the cache update; this VFS dispatches lock-free
//! (never holds a lock across FS calls — see the #82/#476 deadlock class),
//! so instead every insert carries a **generation guard**: the resolver
//! snapshots the cache generation *before* the FS dispatch, and the insert
//! is dropped if *any* invalidation bumped the generation in between.  The
//! guard is deliberately global (coarse): invalidations are rare compared
//! to lookups, so the cost of a rejected insert is one extra future miss.
//! Either ordering of A's insert vs B's invalidate is now safe:
//! insert-then-invalidate → the entry is removed; invalidate-then-insert →
//! the generation mismatch drops the insert.
//!
//! # What is deliberately NOT cached
//!
//! * `".."` components — `rename(2)` of a directory rewires its parent
//!   linkage without touching the keys this cache could invalidate by name.
//!   (`"."` never reaches the cache; the resolver filters it.)
//! * Filesystems that do not opt in via `FileSystemOps::lookup_cacheable`.
//!   Pseudo-filesystems (procfs, sysfs) synthesize entries from live kernel
//!   state with no VFS-visible mutation events, and case-insensitive
//!   filesystems (FAT32, NTFS) would alias differently-cased keys that
//!   exact-string invalidation cannot cover.  Opt-in is the safe default
//!   for any future filesystem.
//!
//! # Bounds and eviction
//!
//! FIFO eviction over a fixed capacity ([`PATH_CACHE_CAP`] entries).  FIFO
//! keeps the hit path a single map probe under a leaf spinlock (no LRU
//! stamp maintenance) and is O(1) per eviction; the workloads this cache
//! targets (repeat probes of a small hot set during library load / database
//! open) have far fewer distinct hot keys than the capacity, so recency
//! tracking buys nothing measurable.  Memory is bounded by `2 ×
//! PATH_CACHE_CAP` keys (lazy FIFO deletion, see `compact`).
//!
//! # Lock discipline
//!
//! One global spinlock, strictly a **leaf** lock: every critical section is
//! a point operation on the in-memory maps (no FS dispatch, no `MOUNTS`, no
//! `PROCESS_TABLE`, no allocation-heavy work beyond the inserted key, never
//! held across `schedule()` or blocking I/O).

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::FileType;

/// Maximum number of cached entries (positive + negative combined).
///
/// Sizing: a Firefox-class userspace touches ~10⁵ files during startup, but
/// the *hot* resolution set (repeatedly probed names: shared-library search
/// paths, sqlite journal probes, config re-stats) is a few hundred keys.
/// 4096 entries ≈ a few hundred KiB worst-case heap (key strings dominate)
/// — bounded regardless of file churn.
const PATH_CACHE_CAP: usize = 4096;

/// A memoized per-component lookup outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cached {
    /// The name does not exist in the directory (`fs.lookup` → `NotFound`).
    Negative,
    /// The name resolved to `child` with file type `ftype` (the type is
    /// cached so the resolver can skip the symlink-check `stat` dispatch;
    /// an inode's type can only change if the name is unlinked and
    /// recreated, which invalidates the entry).
    Positive { child: u64, ftype: FileType },
}

struct Inner {
    /// (mount_idx, dir_inode) → name → outcome.  Nested so the hit path can
    /// probe with `&str` (no per-lookup `String` allocation).
    map: BTreeMap<(usize, u64), BTreeMap<String, Cached>>,
    /// Total entries across all inner maps.
    count: usize,
    /// Insertion order for FIFO eviction.  Lazily pruned: invalidated
    /// entries may leave stale keys here, popped harmlessly at eviction
    /// time and bounded by `compact`.
    fifo: VecDeque<(usize, u64, String)>,
    /// Invalidation generation.  Bumped (under this same lock) by every
    /// invalidate/flush; inserts snapshotted before the FS dispatch are
    /// dropped if it moved (see module docs, "the insert/mutate race").
    gen: u64,
}

impl Inner {
    const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            count: 0,
            fifo: VecDeque::new(),
            gen: 0,
        }
    }

    fn remove_key(&mut self, mount: usize, dir: u64, name: &str) -> bool {
        if let Some(inner) = self.map.get_mut(&(mount, dir)) {
            if inner.remove(name).is_some() {
                self.count -= 1;
                if inner.is_empty() {
                    self.map.remove(&(mount, dir));
                }
                return true;
            }
        }
        false
    }

    /// Evict FIFO-oldest entries until `count <= PATH_CACHE_CAP`, and bound
    /// the FIFO itself (stale keys from invalidations) at `2 × CAP`.
    fn compact(&mut self) {
        while self.count > PATH_CACHE_CAP || self.fifo.len() > 2 * PATH_CACHE_CAP {
            match self.fifo.pop_front() {
                Some((m, d, n)) => {
                    // May be a stale key (already invalidated) — remove_key
                    // is a no-op then, and the pop alone shrinks the FIFO.
                    self.remove_key(m, d, &n);
                }
                None => break,
            }
        }
    }
}

static CACHE: spin::Mutex<Inner> = spin::Mutex::new(Inner::new());

// ── Statistics (test + diagnostic surface; no correctness role) ────────────
static POS_HITS: AtomicUsize = AtomicUsize::new(0);
static NEG_HITS: AtomicUsize = AtomicUsize::new(0);
static MISSES: AtomicUsize = AtomicUsize::new(0);
static INSERTS: AtomicUsize = AtomicUsize::new(0);
static REJECTED_INSERTS: AtomicUsize = AtomicUsize::new(0);
static INVALIDATIONS: AtomicUsize = AtomicUsize::new(0);

/// Probe the cache for one path component.  `None` = miss (caller must
/// dispatch into the FS).  Hit-path cost: one leaf-spinlock acquire and two
/// `BTreeMap` probes; no allocation.
pub fn lookup(mount: usize, dir: u64, name: &str) -> Option<Cached> {
    let cache = CACHE.lock();
    let hit = cache
        .map
        .get(&(mount, dir))
        .and_then(|inner| inner.get(name).copied());
    drop(cache);
    match hit {
        Some(Cached::Positive { .. }) => { POS_HITS.fetch_add(1, Ordering::Relaxed); }
        Some(Cached::Negative) => { NEG_HITS.fetch_add(1, Ordering::Relaxed); }
        None => { MISSES.fetch_add(1, Ordering::Relaxed); }
    }
    hit
}

/// Snapshot the invalidation generation.  Call **before** the FS `lookup`
/// dispatch whose outcome will be inserted; pass the snapshot to [`insert`].
pub fn generation() -> u64 {
    CACHE.lock().gen
}

/// Insert a memoized outcome, unless any invalidation ran since
/// `gen_snapshot` was taken (in which case the outcome may be stale and is
/// dropped — the next walk simply misses and re-dispatches).
pub fn insert(gen_snapshot: u64, mount: usize, dir: u64, name: &str, value: Cached) {
    let mut cache = CACHE.lock();
    if cache.gen != gen_snapshot {
        drop(cache);
        REJECTED_INSERTS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let inner = cache.map.entry((mount, dir)).or_insert_with(BTreeMap::new);
    if inner.insert(String::from(name), value).is_none() {
        cache.count += 1;
        cache.fifo.push_back((mount, dir, String::from(name)));
        cache.compact();
    }
    drop(cache);
    INSERTS.fetch_add(1, Ordering::Relaxed);
}

/// Drop the entry for `(mount, dir, name)` and bump the generation.  Must be
/// called **after** the concrete-FS mutation that changes the binding has
/// completed (create / unlink / rmdir / rename(×2) / symlink / link).
pub fn invalidate(mount: usize, dir: u64, name: &str) {
    let mut cache = CACHE.lock();
    cache.gen += 1;
    cache.remove_key(mount, dir, name);
    drop(cache);
    INVALIDATIONS.fetch_add(1, Ordering::Relaxed);
}

/// Drop everything and bump the generation.  Required on any mount-table
/// change: `umount` shifts the mount indices that key this cache, and a new
/// mount may shadow paths under it.
pub fn flush() {
    let mut cache = CACHE.lock();
    cache.gen += 1;
    cache.map.clear();
    cache.fifo.clear();
    cache.count = 0;
    drop(cache);
    INVALIDATIONS.fetch_add(1, Ordering::Relaxed);
}

/// (pos_hits, neg_hits, misses, inserts, rejected_inserts, invalidations).
pub fn stats() -> (usize, usize, usize, usize, usize, usize) {
    (
        POS_HITS.load(Ordering::Relaxed),
        NEG_HITS.load(Ordering::Relaxed),
        MISSES.load(Ordering::Relaxed),
        INSERTS.load(Ordering::Relaxed),
        REJECTED_INSERTS.load(Ordering::Relaxed),
        INVALIDATIONS.load(Ordering::Relaxed),
    )
}

/// Test-only: empty the cache so a benchmark can measure the cold path.
#[doc(hidden)]
pub fn _test_flush() {
    flush();
}
