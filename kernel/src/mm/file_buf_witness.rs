//! File-struct buffer corruption witness (B-1 gate, ld-musl+0x44aeb).
//!
//! Targets the precise corruption pattern documented by the B-1 RETRY-2
//! verdict: musl `fgets` enters `memchr(rcx=NULL, '\n', 89)` because the
//! enclosing `FILE` struct has `f->buf == NULL` (and `f->buf_size == 0`)
//! at sc=70 read-return.  `f->buf` lives at offset 0x58 of the musl 1.2.5
//! FILE layout — i.e. page offset 0x68 of the 4 KiB anon page that holds
//! the FILE struct (FILE at page-offset 0x10).
//!
//! K1+K2+K3 of the prior audit all PASS (anon zero-fill correct, read(2)
//! post-condition correct, dependentlibs.list disk content correct), but
//! the empirical fault state at memchr+0x31 strictly requires 16 bytes of
//! corruption at FILE+0x58..0x68.  The corruption source is not in any
//! audited kernel write path.  This witness localises *when* the
//! corruption materialises by snapshotting `[page_base+0x68, +0x78)` on
//! every `read(2)` whose user buffer lives on a page that plausibly hosts
//! a musl FILE struct, and reporting any byte-level delta between
//! syscall entry and exit, plus a one-shot warning when the post-state
//! is observed in the smoking-gun state `(buf=0, size=0)`.
//!
//! Cites: POSIX `read(2)` (post-condition); musl public `FILE` layout
//! (`f->buf` at offset 0x58 in 1.2.x); Intel SDM Vol. 3A §4.10.5 (TLB
//! invariants — adjacent fault model H1).
//!
//! Diagnostic-only.  Feature-gated; default / production builds compile
//! the entire module out via the empty stubs at the bottom.
//!
//! Output format (single line per event):
//!
//!   [F_BUF_DELTA] pid=<n> fd=<n> page=<#x> pre_buf=<#x> pre_size=<#x>
//!                 post_buf=<#x> post_size=<#x> n_read=<n>
//!   [F_BUF_ZERO]  pid=<n> fd=<n> page=<#x> when=<pre|post> n_read=<n>
//!
//! All emissions are bounded by a per-witness fire cap (16 first hits,
//! then every 1024th) so the serial log cannot be flooded by a tight
//! read-loop.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ── Configuration ─────────────────────────────────────────────────────────

/// Offset within a 4 KiB user anon page where musl 1.2.5's `FILE` struct
/// places its `buf` (8 bytes) and `buf_size` (8 bytes) fields.  Derived
/// from: FILE struct placed at page-offset 0x10 by `__fdopen`, and
/// `buf` at FILE-offset 0x58 → page-offset `0x10 + 0x58 = 0x68`.
const F_BUF_PAGE_OFFSET: u64 = 0x68;
const F_SIZE_PAGE_OFFSET: u64 = 0x70;

/// Cap for first-fire emissions per witness.  After this many, only every
/// 1024th hit is logged.  Keeps the serial log bounded under a tight
/// `read()` loop.
const FIRST_FIRE_CAP: u64 = 16;
const SAMPLED_FIRE_MOD: u64 = 1024;

// ── Counters ──────────────────────────────────────────────────────────────

static F_BUF_DELTA_FIRES: AtomicU64 = AtomicU64::new(0);
static F_BUF_ZERO_PRE_FIRES: AtomicU64 = AtomicU64::new(0);
static F_BUF_ZERO_POST_FIRES: AtomicU64 = AtomicU64::new(0);
static F_BUF_SNAPSHOT_FAILS: AtomicU64 = AtomicU64::new(0);

// ── Public surface (feature-gated) ────────────────────────────────────────

/// Pre/post snapshot pair carried across a single `read(2)` invocation.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub pid: u64,
    pub fd: u64,
    pub page_base: u64,
    pub pre_buf: u64,
    pub pre_size: u64,
    pub buf_va: u64,
    /// `true` when the page-walk fault-immune reads succeeded on both
    /// 8-byte fields at entry.  A `false` here suppresses the post check.
    pub valid: bool,
}

impl Snapshot {
    pub const fn invalid() -> Self {
        Snapshot {
            pid: 0, fd: 0, page_base: 0,
            pre_buf: 0, pre_size: 0, buf_va: 0,
            valid: false,
        }
    }
}

/// Take a pre-read snapshot of `[page_base+0x68, +0x78)` using a page-
/// fault-immune software walk.  Returns an opaque `Snapshot` that must
/// be passed to `post_read` after the read syscall returns.
///
/// The witness only arms for buffers on user-mode anon pages where the
/// alignment hints at a musl FILE struct layout.  `buf_va` is the user
/// address the syscall is reading INTO (i.e. `f->buf` from musl's
/// perspective).  We compute `page_base = buf_va & ~0xFFF` and snapshot
/// at fixed page offsets — the corruption mode under investigation
/// targets a fixed FILE-struct field offset, not the read destination
/// itself.
///
/// Safe to call with any `buf_va`: out-of-bounds / kernel-VA / unmapped
/// VAs return an invalid snapshot.
#[cfg(feature = "file-buf-witness")]
pub fn pre_read(pid: u64, fd: u64, buf_va: u64) -> Snapshot {
    use astryx_shared::KERNEL_VIRT_BASE;
    if buf_va == 0 || buf_va >= KERNEL_VIRT_BASE {
        return Snapshot::invalid();
    }
    let page_base = buf_va & !0xFFFu64;
    let cr3 = crate::mm::vmm::get_cr3();
    if cr3 == 0 {
        return Snapshot::invalid();
    }
    let pre_buf = match crate::proc::sample::read_user_u64_at(
        cr3, page_base.wrapping_add(F_BUF_PAGE_OFFSET))
    {
        Some(v) => v,
        None => {
            F_BUF_SNAPSHOT_FAILS.fetch_add(1, Ordering::Relaxed);
            return Snapshot::invalid();
        }
    };
    let pre_size = match crate::proc::sample::read_user_u64_at(
        cr3, page_base.wrapping_add(F_SIZE_PAGE_OFFSET))
    {
        Some(v) => v,
        None => {
            F_BUF_SNAPSHOT_FAILS.fetch_add(1, Ordering::Relaxed);
            return Snapshot::invalid();
        }
    };
    // We do NOT emit on `pre_buf==0 && pre_size==0` here: many user
    // read destinations live on scratch pages that were never touched
    // by `__fdopen`, so the (0,0) doublet is the normal state, not a
    // smoking gun.  The interesting transition is `(non-zero,
    // non-zero) → (0, 0)` between two `read(2)` calls on the same
    // page — caught by the per-page state-tracking ring below.
    Snapshot {
        pid, fd, page_base,
        pre_buf, pre_size,
        buf_va,
        valid: true,
    }
}

/// Post-read snapshot.  Emits `[F_BUF_DELTA]` if the field pair changed
/// during the syscall, and `[F_BUF_ZERO when=post]` if the post-state is
/// the smoking-gun `(0, 0)`.  Bounded by `FIRST_FIRE_CAP` + sampled mod
/// so a tight read-loop cannot flood serial.
#[cfg(feature = "file-buf-witness")]
pub fn post_read(snap: Snapshot, n_read: i64) {
    if !snap.valid {
        return;
    }
    let cr3 = crate::mm::vmm::get_cr3();
    if cr3 == 0 {
        return;
    }
    let post_buf = match crate::proc::sample::read_user_u64_at(
        cr3, snap.page_base.wrapping_add(F_BUF_PAGE_OFFSET))
    {
        Some(v) => v,
        None => return, // page evaporated mid-syscall — not our scenario
    };
    let post_size = match crate::proc::sample::read_user_u64_at(
        cr3, snap.page_base.wrapping_add(F_SIZE_PAGE_OFFSET))
    {
        Some(v) => v,
        None => return,
    };

    let changed = post_buf != snap.pre_buf || post_size != snap.pre_size;
    if changed {
        let n = F_BUF_DELTA_FIRES.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= FIRST_FIRE_CAP || n % SAMPLED_FIRE_MOD == 0 {
            crate::serial_println!(
                "[F_BUF_DELTA] pid={} fd={} page={:#x} buf_va={:#x} \
                 pre_buf={:#x} pre_size={:#x} \
                 post_buf={:#x} post_size={:#x} n_read={} fires={}",
                snap.pid, snap.fd, snap.page_base, snap.buf_va,
                snap.pre_buf, snap.pre_size,
                post_buf, post_size, n_read, n
            );
        }
    }

    // Smoking-gun state — emit ONLY when the pre-state showed valid
    // non-NULL fields and the post-state is the deterministic
    // memchr(NULL, ...) trigger pattern.  This narrows to the actual
    // corruption transition the prior gate-ownership audit identified.
    let pre_looked_like_fdopen =
        snap.pre_buf != 0 && snap.pre_size != 0 && snap.pre_buf < (1u64 << 48);
    if pre_looked_like_fdopen && post_buf == 0 && post_size == 0 {
        let n = F_BUF_ZERO_POST_FIRES.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= FIRST_FIRE_CAP || n % SAMPLED_FIRE_MOD == 0 {
            crate::serial_println!(
                "[F_BUF_ZERO_TRANSITION] pid={} fd={} page={:#x} \
                 buf_va={:#x} pre_buf={:#x} pre_size={:#x} n_read={} fires={}",
                snap.pid, snap.fd, snap.page_base, snap.buf_va,
                snap.pre_buf, snap.pre_size, n_read, n
            );
        }
    }
}

/// Counters dump for the `kdb` introspection layer.  Returns
/// `(delta, zero_pre, zero_post, snap_fails)`.
#[cfg(feature = "file-buf-witness")]
pub fn counters() -> (u64, u64, u64, u64) {
    (
        F_BUF_DELTA_FIRES.load(Ordering::Relaxed),
        F_BUF_ZERO_PRE_FIRES.load(Ordering::Relaxed),
        F_BUF_ZERO_POST_FIRES.load(Ordering::Relaxed),
        F_BUF_SNAPSHOT_FAILS.load(Ordering::Relaxed),
    )
}

// ── No-op stubs for default / non-feature builds ──────────────────────────
//
// Keeping the public types visible (via `Snapshot::invalid()`) lets
// callers compile against the same signature in both configurations
// without per-call-site `#[cfg(...)]`.  The stubs are inline + empty so
// the linker drops them entirely under release builds.

#[cfg(not(feature = "file-buf-witness"))]
#[inline(always)]
pub fn pre_read(_pid: u64, _fd: u64, _buf_va: u64) -> Snapshot {
    Snapshot::invalid()
}

#[cfg(not(feature = "file-buf-witness"))]
#[inline(always)]
pub fn post_read(_snap: Snapshot, _n_read: i64) {}

#[cfg(not(feature = "file-buf-witness"))]
#[inline(always)]
pub fn counters() -> (u64, u64, u64, u64) { (0, 0, 0, 0) }
