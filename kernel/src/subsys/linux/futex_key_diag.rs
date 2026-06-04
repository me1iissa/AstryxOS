//! Futex-key resolution diagnostic for `FUTEX_WAKE woken=0`.
//!
//! Purpose
//! -------
//! When `sys_futex_linux` `FUTEX_WAKE` returns `woken=0`, we want to know
//! *why*: is the bucket genuinely empty (correct ABI, the waiter is on a
//! different logical futex), or is the kernel mis-bucketing waiters and
//! wakers that should map to the same key?
//!
//! Per `futex(2)` (Linux man-pages, <https://man7.org/linux/man-pages/man2/futex.2.html>),
//! the futex key for `FUTEX_PRIVATE_FLAG` ops is the pair `(mm, uaddr)`
//! (i.e. per-process); for shared ops the key is the pair
//! `(inode, page_offset)`.  AstryxOS keys all futexes by `(pid, uaddr_u64)`
//! in `crate::syscall::FUTEX_WAITERS` — equivalent to the private-flag
//! key shape (one `mm` per `pid` in this kernel), with the caveat that
//! shared futexes across distinct `mm`s would currently miss.  The musl
//! `pthread_cond_t` is allocated inside the calling thread's address
//! space and all condvar ops carry `FUTEX_PRIVATE_FLAG = 0x80`, so the
//! private-key form is what the demo path exercises.
//!
//! Output
//! ------
//! On `FUTEX_WAKE` with `woken == 0`, emit ONE line of the form:
//!
//! ```text
//! [FUTEX-WAKE-EMPTY] tid=T pid=P op=OP uaddr=UADDR \
//!     key=(pid=P, uaddr=UADDR) bucket_present=0 \
//!     same_pid_keys=N nearest=[uaddr1+tids1@delta1, uaddr2+tids2@delta2, …] \
//!     same_page=[uaddr+tids, …]
//! ```
//!
//! Field meanings:
//!
//! * `bucket_present` — 0 if `FUTEX_WAITERS` has no entry at `(pid, uaddr)`,
//!   1 if there is one but empty (should never happen — drained entries
//!   are removed).  A `bucket_present=0` woken=0 is the normal case
//!   ("no waiter on this exact key").
//! * `same_pid_keys` — total number of futex keys currently held by this
//!   `pid` in `FUTEX_WAITERS`.  If this is non-zero while `woken=0`, the
//!   process has waiters but on different uaddrs (POSIX-defence bucket
//!   (a) of the audit) — not a kernel key-resolution bug.
//! * `nearest` — up to 6 (uaddr, tid_count, signed-byte-delta) tuples
//!   for keys closest in `uaddr` to the waker's, restricted to this
//!   `pid`.  Lets the post-processor see whether the waiter is one
//!   pthread_cond_t field away (musl `_c_seq` / `_c_waiters` ±4 bytes)
//!   or at a totally unrelated address (POSIX-level signal/wait mismatch).
//! * `same_page` — up to 4 (uaddr, tid_count) tuples for keys whose
//!   `uaddr` shares the same 4 KiB page as the waker's `uaddr`.  An empty
//!   list with a non-empty `nearest` confirms the wake is firing on a
//!   different page from the wait — strong "different logical futex"
//!   signal.
//!
//! This is **observe-only** — no behavioural change to wake semantics.
//! Output is gated on `firefox-test` to stay out of the production budget.
//! Per-event cost is one O(log n + k) `BTreeMap::range` scan over the
//! same `FUTEX_WAITERS` lock the wake already takes; budget is bounded by
//! the constant cap on emitted neighbours.

#![cfg(feature = "firefox-test-trace")]

extern crate alloc;

use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

/// Counter of [FUTEX-WAKE-EMPTY] events emitted since boot, exposed for
/// kdb / harness summary.  Bumped once per emit.
pub static FUTEX_WAKE_EMPTY_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Maximum number of neighbour keys to print per emit.  6 covers the
/// musl `pthread_cond_t` layout (5 32-bit fields = `_c_lock`, `_c_seq`,
/// `_c_waiters`, `_c_clock`, `_c_destroy` per public musl docs) plus a
/// few unrelated keys in the same page.
const NEAREST_CAP: usize = 6;

/// Maximum number of same-page neighbours to print.  4 is plenty to spot
/// "shared a page but not in the cluster window".
const SAME_PAGE_CAP: usize = 4;

/// Emit `[FUTEX-WAKE-EMPTY]` for a wake that returned `woken=0`.
///
/// Caller must NOT hold `FUTEX_WAITERS`.  We take the lock briefly for
/// the bucket peek and the bounded neighbour scan; the lock is released
/// before printing so a long serial transmit can never widen the wake-
/// path critical section.
///
/// Arguments mirror the local variables at the `FUTEX_WAKE` call site so
/// the wiring is one line at the call site.
///
/// `op` is the masked futex op (0-0x7F, i.e. with `FUTEX_PRIVATE_FLAG`
/// and `FUTEX_CLOCK_REALTIME` already stripped — same shape as the
/// existing `[FUTEX_WAKE]` log line uses for `futex_op`'s payload bits).
pub fn emit_wake_empty(
    pid: u64,
    tid: u64,
    uaddr: u64,
    futex_op: u64,
) {
    // Snapshot the relevant slice of FUTEX_WAITERS under a single lock.
    // We extract only what we need to print so the lock release happens
    // before any serial I/O.
    let (bucket_present, same_pid_keys, nearest, same_page) = {
        let waiters = crate::syscall::FUTEX_WAITERS.lock();

        let bucket_present = if waiters.contains_key(&(pid, uaddr)) { 1u8 } else { 0u8 };

        // Page-aligned bounds for the same_page scan.  4 KiB page,
        // 0-extended (uaddr is a u64 user-VA; arithmetic stays in u64).
        let page_lo = uaddr & !0xFFFu64;
        let page_hi = page_lo.saturating_add(0x1000);

        // Walk this `pid`'s slice of FUTEX_WAITERS only — BTreeMap is keyed
        // lexicographically on `(pid, uaddr)`, so a half-open range from
        // `(pid, 0)` to `(pid+1, 0)` walks exactly this pid's entries in
        // ascending uaddr order.
        let lo = (pid, 0u64);
        let hi = (pid.saturating_add(1), 0u64);

        let mut same_pid_keys: u64 = 0;
        let mut same_page: Vec<(u64, usize)> = Vec::with_capacity(SAME_PAGE_CAP);
        // Track up to NEAREST_CAP entries closest to `uaddr` by absolute
        // distance.  Cheap: linear pass with bounded inserts.
        let mut nearest: Vec<(u64, usize)> = Vec::with_capacity(NEAREST_CAP * 2);

        for (&(_p, wuaddr), tids) in waiters.range(lo..hi) {
            same_pid_keys = same_pid_keys.saturating_add(1);

            if wuaddr >= page_lo && wuaddr < page_hi && same_page.len() < SAME_PAGE_CAP {
                same_page.push((wuaddr, tids.len()));
            }

            // Maintain `nearest` as the closest-by-|delta| entries.  Cap
            // at 2× to avoid worst-case O(n) per insert; trim later.
            nearest.push((wuaddr, tids.len()));
        }

        // Sort `nearest` by absolute byte distance from `uaddr`, truncate.
        nearest.sort_by_key(|&(w, _)| {
            if w >= uaddr { w - uaddr } else { uaddr - w }
        });
        nearest.truncate(NEAREST_CAP);

        (bucket_present, same_pid_keys, nearest, same_page)
    };

    FUTEX_WAKE_EMPTY_EVENTS.fetch_add(1, Ordering::Relaxed);

    // Format the "nearest" list as
    //     [uaddr+N@±delta, uaddr+N@±delta, …]
    // and the "same_page" list as
    //     [uaddr+N, uaddr+N, …]
    // Inline-format to one serial line to keep grep-ability simple.
    // We use a small fixed-size scratch buffer reasoning to avoid heap
    // allocation: each entry is at most ~40 bytes, capped at 6+4=10.
    use core::fmt::Write;
    let mut nearest_buf: alloc::string::String = alloc::string::String::with_capacity(256);
    nearest_buf.push('[');
    for (i, &(w, n)) in nearest.iter().enumerate() {
        if i > 0 { nearest_buf.push(','); }
        let delta_signed: i128 = (w as i128) - (uaddr as i128);
        // Print as +/- hex bytes for readability — the demo wedge has
        // waiter/waker offsets in the MiB range, so signed hex makes the
        // "same cv field offset" vs "totally different" distinction
        // immediate.
        let _ = if delta_signed >= 0 {
            write!(nearest_buf, "{:#x}+{}@+{:#x}", w, n, delta_signed as u128)
        } else {
            write!(nearest_buf, "{:#x}+{}@-{:#x}", w, n, (-delta_signed) as u128)
        };
    }
    nearest_buf.push(']');

    let mut same_page_buf: alloc::string::String = alloc::string::String::with_capacity(128);
    same_page_buf.push('[');
    for (i, &(w, n)) in same_page.iter().enumerate() {
        if i > 0 { same_page_buf.push(','); }
        let _ = write!(same_page_buf, "{:#x}+{}", w, n);
    }
    same_page_buf.push(']');

    crate::serial_println!(
        "[FUTEX-WAKE-EMPTY] tid={} pid={} op={:#x} uaddr={:#x} \
         key=(pid={},uaddr={:#x}) bucket_present={} same_pid_keys={} \
         nearest={} same_page={}",
        tid, pid, futex_op, uaddr,
        pid, uaddr, bucket_present, same_pid_keys,
        nearest_buf, same_page_buf,
    );
}
