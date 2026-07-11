//! W215 combined diagnostic instrumentation (firefox-test gated).
//!
//! ## Arms
//!
//! ### Arm 1 + 2 (PROV + PREINS — from W215 H2 diagnostic, PR #255)
//!
//! Two structurally-isolated diagnostics that disambiguate the remaining
//! candidate W215 corruption mechanisms after the dispositive soak
//! (2026-05-16) showed all six bookkeeping counters at zero while the
//! FAULT/PHYS bucket-A cluster fires 4/5.  This module contains NO
//! behavioural changes — only atomic counters, a small fixed-size event
//! ring, and a small fixed-size race-witness map.  Every public API is a
//! single function call that records into one of these structures.
//!
//! - **Arm 1 (PROV)**: per-phys event ring.  256-bucket hash table over
//!   `phys >> 12`, 16 entries per bucket.  Records ALLOC, INSERT, EVICT,
//!   REFINC, REFDEC, PHYS_OFF_WRITE_PRE_INSERT, and PFH_INSTALL events.
//!   On the FAULT/PHYS bucket-A signal site, the most recent entries for
//!   the fault's `rip_phys` are dumped as a `[FAULT/PHYS/PROV]` line.
//!
//! - **Arm 2 (PREINS)**: a 128-slot race-witness map keyed by phys, value
//!   is the in-flight pre-insert intent.  On every other cache operation
//!   that touches a phys present in the map, a `[PREINS/RACE]` line is
//!   emitted and `WINDOW_RACE` is incremented.  PFH install with a phys
//!   present in the map emits `[PREINS/INSTALL_RACE]` and increments
//!   `INSTALL_RACE`.
//!
//! ### Axis B — per-writer cache-residency probes (PR #256)
//!
//! Diagnostic-only instrumentation: identifies which kernel writer is the
//! W215 trigger by checking, before each candidate write, whether the
//! destination user buffer's physical page is currently resident in the
//! page cache.  A cache-resident frame being written through any path
//! other than the cache's own write-back machinery is the W215 bucket-A
//! corruption fingerprint (FAULT/PHYS classifier from PR #252).
//!
//! Decision matrix (see dispatch brief):
//!   - exactly one counter ticks  → that writer is the W215 trigger
//!   - multiple counters tick     → multi-writer class; need copy_to_user
//!                                  helper migration
//!   - none tick & W215 fires     → axis B is wrong; pivot to PHYS_OFF
//!                                  kernel-internal writers (cache.rs,
//!                                  elf.rs, vmm.rs zero-fill paths).
//!
//! ## Public spec citations
//!
//! - Intel SDM Vol. 3A §4.10.5 (paging-structure cache coherence) — the
//!   underlying invariant whose violation produces the observed cluster.
//! - POSIX 1003.1-2024 mmap(2) MAP_SHARED visibility semantics.
//!
//! ## ISR / lock-safety
//!
//! Every operation here uses `core::sync::atomic` only, with no Mutex,
//! no Once, no spinlock.  Safe from any context, including the PFH and
//! the bottom of the cache lock.  Hash collisions are tolerated: a slot
//! may be racily overwritten, in which case `PROV_RING_OVERFLOW` ticks
//! up.  The diagnostic favours simplicity over precision.

#![cfg(feature = "firefox-test-core")]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

// ── Event kinds for Arm-1 provenance ring ───────────────────────────────────

pub const KIND_ALLOC: u8                       = 1;
pub const KIND_INSERT: u8                      = 2;
pub const KIND_EVICT: u8                       = 3;
pub const KIND_REFINC: u8                      = 4;
pub const KIND_REFDEC: u8                      = 5;
pub const KIND_PHYS_OFF_WRITE_PRE_INSERT: u8   = 6;
pub const KIND_PFH_INSTALL: u8                 = 7;
/// Phase D (2026-05-20): the moment `pmm::free_page` returns a frame to the
/// allocator pool.  Carries the caller-RIP (low 48 bits) in `key_packed_48`
/// so a post-mortem dump can name the upstream unmap path that released
/// the frame.  Distinct from `KIND_REFDEC` (which records every refcount
/// decrement, including those that do not reach zero).  Used by the
/// `[FAULT/PHYS/PROV]` unconditional dump in the user-mode fatal-fault
/// path to localise W215-class anonymous-VMA recurrences.
pub const KIND_FREE: u8                        = 8;

// ── Writer site IDs for Arm-2 PREINS witness map ────────────────────────────

pub const SITE_CACHE_PREPOPULATE: u8 = 1;   // mm/cache.rs prepopulate path
pub const SITE_PFH_READAHEAD: u8     = 2;   // arch/x86_64/idt.rs readahead path
pub const SITE_PFH_SINGLEPAGE: u8    = 3;   // arch/x86_64/idt.rs single-page fallback

// ── Op identifiers for Arm-2 PREINS witness probes ──────────────────────────

pub const OP_LOOKUP: u8           = 1;
pub const OP_LOOKUP_ACQUIRE: u8   = 2;
pub const OP_IS_PHYS_IN_CACHE: u8 = 3;
pub const OP_EVICT: u8            = 4;
pub const OP_EVICT_IF_PHYS: u8    = 5;

// ── Arm-1: per-phys event ring ──────────────────────────────────────────────

const BUCKETS: usize = 256;
const ENTRIES_PER_BUCKET: usize = 16;

#[repr(C)]
struct ProvEntry {
    /// The phys that owns this slot (0 = empty).
    phys: AtomicU64,
    /// Tick at which this event was recorded.
    tick: AtomicU64,
    /// Packed event payload:
    ///   [63:16] key_packed_48 — caller-defined; for cache events we pack
    ///                           (inode_low24 << 24) | (file_offset_low24)
    ///   [15:8]  reserved (0)
    ///   [7:0]   kind          — KIND_* constants
    packed: AtomicU64,
}

impl ProvEntry {
    const fn new() -> Self {
        Self {
            phys: AtomicU64::new(0),
            tick: AtomicU64::new(0),
            packed: AtomicU64::new(0),
        }
    }
}

#[repr(C)]
struct ProvBucket {
    entries: [ProvEntry; ENTRIES_PER_BUCKET],
    /// Round-robin write cursor; not strictly correct under contention
    /// but the cost of a missed eviction is a single PROV_RING_OVERFLOW
    /// tick — acceptable for a diagnostic.
    cursor: AtomicUsize,
}

impl ProvBucket {
    const fn new() -> Self {
        // Hand-rolled because `[ProvEntry::new(); N]` is not const for atomics.
        const E: ProvEntry = ProvEntry::new();
        Self {
            entries: [E; ENTRIES_PER_BUCKET],
            cursor: AtomicUsize::new(0),
        }
    }
}

struct ProvTable {
    buckets: [ProvBucket; BUCKETS],
}

impl ProvTable {
    const fn new() -> Self {
        const B: ProvBucket = ProvBucket::new();
        Self { buckets: [B; BUCKETS] }
    }
}

static PROV_TABLE: ProvTable = ProvTable::new();

#[inline]
fn bucket_for(phys: u64) -> &'static ProvBucket {
    let pfn = (phys >> 12) as u64;
    let h = (pfn ^ (pfn >> 8) ^ (pfn >> 16)) as usize & (BUCKETS - 1);
    &PROV_TABLE.buckets[h]
}

/// Pack a cache key (inode, file_offset) into the 48-bit key payload.
#[inline]
pub fn pack_cache_key(inode: u64, file_offset: u64) -> u64 {
    let inode_low = inode & 0xFF_FFFF;            // 24 bits
    let off_low   = (file_offset >> 12) & 0xFF_FFFF; // 24-bit page index
    (inode_low << 24) | off_low
}

/// Record a provenance event for `phys`.
#[inline]
pub fn prov_record(phys: u64, kind: u8, key_packed_48: u64) {
    if phys == 0 { return; }
    let bucket = bucket_for(phys);
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);

    let payload = (key_packed_48 << 16) | (kind as u64);

    // Try to update an existing entry for this phys first (so consecutive
    // events for one hot frame don't immediately rotate out).
    for slot in bucket.entries.iter() {
        if slot.phys.load(Ordering::Relaxed) == phys {
            slot.tick.store(tick, Ordering::Relaxed);
            slot.packed.store(payload, Ordering::Relaxed);
            return;
        }
    }

    // No matching slot — write into the round-robin cursor position.  If
    // we evict a still-recent entry (< 200 ticks ≈ 2 s) count an overflow.
    let idx = bucket.cursor.fetch_add(1, Ordering::Relaxed)
        & (ENTRIES_PER_BUCKET - 1);
    let slot = &bucket.entries[idx];
    let prev_phys = slot.phys.load(Ordering::Relaxed);
    let prev_tick = slot.tick.load(Ordering::Relaxed);
    if prev_phys != 0 && tick.saturating_sub(prev_tick) < 200 {
        PROV_RING_OVERFLOW.fetch_add(1, Ordering::Relaxed);
    }
    slot.phys.store(phys, Ordering::Relaxed);
    slot.tick.store(tick, Ordering::Relaxed);
    slot.packed.store(payload, Ordering::Relaxed);
}

#[inline]
fn kind_str(k: u8) -> &'static str {
    match k {
        KIND_ALLOC => "ALLOC",
        KIND_INSERT => "INSERT",
        KIND_EVICT => "EVICT",
        KIND_REFINC => "REFINC",
        KIND_REFDEC => "REFDEC",
        KIND_PHYS_OFF_WRITE_PRE_INSERT => "PREINS_W",
        KIND_PFH_INSTALL => "PFH_INSTALL",
        KIND_FREE => "FREE",
        _ => "UNKNOWN",
    }
}

/// Convenience wrapper: record a `KIND_FREE` event for `phys` with the
/// caller's return address packed into the 48-bit key payload.  Used by
/// `pmm::free_page` after the residual-`pte_share_count` invariant check
/// passes — i.e. for every frame that actually returns to the allocator
/// pool.  Per Intel SDM Vol. 3A §4.10.5, the most-recent free of a frame
/// is the most-likely upstream of a W215-class use-after-recycle, so
/// recording it in the per-phys event ring lets the fault-site dump name
/// the unmap caller.  `caller_rip` is truncated to its low 48 bits when
/// packed; in practice the kernel image lives at `0xFFFF_8000_0010_0000`
/// (see arch::x86_64::layout), so the low 48 bits suffice to identify
/// the call-site within `addr2line`.
#[inline]
pub fn prov_record_free(phys: u64, caller_rip: u64) {
    if phys == 0 { return; }
    let key_low48 = caller_rip & 0x0000_FFFF_FFFF_FFFF;
    prov_record(phys, KIND_FREE, key_low48);
}

/// Emit the most-recent provenance entries for `phys` as a single
/// `[FAULT/PHYS/PROV]` serial line, ordered newest-first.
///
/// Called by the FAULT/PHYS bucket-A path in
/// `signal::emit_fault_phys_diagnostic`.  Bounded ~12 entries per line.
pub fn dump_prov_for_phys(phys: u64) {
    let bucket = bucket_for(phys);

    // Collect (tick, kind, key) for every slot matching `phys`.
    let mut matches: [(u64, u8, u64); ENTRIES_PER_BUCKET] =
        [(0, 0, 0); ENTRIES_PER_BUCKET];
    let mut n = 0usize;
    for slot in bucket.entries.iter() {
        if slot.phys.load(Ordering::Relaxed) == phys {
            let t = slot.tick.load(Ordering::Relaxed);
            let p = slot.packed.load(Ordering::Relaxed);
            let kind = (p & 0xFF) as u8;
            let key = p >> 16;
            matches[n] = (t, kind, key);
            n += 1;
            if n == ENTRIES_PER_BUCKET { break; }
        }
    }

    // Sort by tick descending (insertion sort, n ≤ 16).
    for i in 1..n {
        let cur = matches[i];
        let mut j = i;
        while j > 0 && matches[j - 1].0 < cur.0 {
            matches[j] = matches[j - 1];
            j -= 1;
        }
        matches[j] = cur;
    }

    if n == 0 {
        crate::serial_println!(
            "[FAULT/PHYS/PROV] phys={:#x} entries=[] (no prov data — bucket cold or evicted)",
            phys,
        );
        return;
    }

    // Emit one structured line.  Format chosen to be regex-grep-friendly
    // for the harness without requiring a JSON parser.
    let cap = core::cmp::min(n, 12);
    // Print head, then one entry per call (no allocation; serial_println
    // already routes through the per-CPU FIFO-batched writer).
    crate::serial_println!(
        "[FAULT/PHYS/PROV] phys={:#x} count={} entries_follow=1",
        phys, cap,
    );
    for i in 0..cap {
        let (t, kind, key) = matches[i];
        crate::serial_println!(
            "[FAULT/PHYS/PROV/E] phys={:#x} i={} tick={} kind={} key={:#x}",
            phys, i, t, kind_str(kind), key,
        );
    }
}

// ── Arm-2: pre-insert race witness map ──────────────────────────────────────

const PREINS_SLOTS: usize = 128;

#[repr(C)]
struct PreinsSlot {
    /// 0 = empty.
    phys: AtomicU64,
    tick_zerofill: AtomicU64,
    /// Packed metadata:
    ///   [63:32] file_offset_page_index_low32
    ///   [31:24] cpu
    ///   [23:16] writer_site_id
    ///   [15:0]  inode_low16
    meta: AtomicU64,
}

impl PreinsSlot {
    const fn new() -> Self {
        Self {
            phys: AtomicU64::new(0),
            tick_zerofill: AtomicU64::new(0),
            meta: AtomicU64::new(0),
        }
    }
}

struct PreinsMap {
    slots: [PreinsSlot; PREINS_SLOTS],
}

impl PreinsMap {
    const fn new() -> Self {
        const S: PreinsSlot = PreinsSlot::new();
        Self { slots: [S; PREINS_SLOTS] }
    }
}

static PREINS_MAP: PreinsMap = PreinsMap::new();

#[inline]
fn preins_slot_for(phys: u64) -> &'static PreinsSlot {
    let pfn = (phys >> 12) as u64;
    let h = (pfn ^ (pfn >> 7) ^ (pfn >> 13)) as usize & (PREINS_SLOTS - 1);
    &PREINS_MAP.slots[h]
}

#[inline]
fn pack_meta(site: u8, cpu: u8, inode_low16: u16, off_low32: u32) -> u64 {
    ((off_low32 as u64) << 32)
        | ((cpu as u64) << 24)
        | ((site as u64) << 16)
        | (inode_low16 as u64)
}

/// Register a pre-insert PHYS_OFF zero-write intent for `phys`.
pub fn preins_register(
    phys: u64,
    writer_site: u8,
    _mount_idx: usize,
    inode: u64,
    file_offset: u64,
) {
    if phys == 0 { return; }
    let slot = preins_slot_for(phys);
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let cpu = crate::arch::x86_64::apic::cpu_index() as u8;
    let meta = pack_meta(
        writer_site,
        cpu,
        (inode & 0xFFFF) as u16,
        ((file_offset >> 12) & 0xFFFF_FFFF) as u32,
    );
    // Re-zero of a recycled phys: legitimate, overwrite the witness.
    slot.phys.store(phys, Ordering::Relaxed);
    slot.tick_zerofill.store(tick, Ordering::Relaxed);
    slot.meta.store(meta, Ordering::Relaxed);
}

/// Clear the witness for `phys` after a successful cache::insert.
///
/// Returns true if the witness matched (normal happy path).
pub fn preins_clear_on_insert(phys: u64) -> bool {
    if phys == 0 { return false; }
    let slot = preins_slot_for(phys);
    let prev_phys = slot.phys.swap(0, Ordering::Relaxed);
    if prev_phys == phys {
        let zero_tick = slot.tick_zerofill.load(Ordering::Relaxed);
        let now = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
        let meta = slot.meta.load(Ordering::Relaxed);
        let site = ((meta >> 16) & 0xFF) as u8;
        // Sample to avoid serial flood.
        static PREINS_OK_N: AtomicU64 = AtomicU64::new(0);
        let n = PREINS_OK_N.fetch_add(1, Ordering::Relaxed);
        if n < 8 || n % 4096 == 0 {
            crate::serial_println!(
                "[PREINS/OK] phys={:#x} delta_ticks={} site={} n={}",
                phys, now.saturating_sub(zero_tick), site, n,
            );
        }
        true
    } else if prev_phys != 0 {
        // Slot was holding a different phys's witness — restore it.
        slot.phys.store(prev_phys, Ordering::Relaxed);
        false
    } else {
        false
    }
}

/// Witness probe for non-insert cache operations.
#[inline]
pub fn preins_check_op(phys: u64, op: u8, reader_key_low32: u32) {
    if phys == 0 { return; }
    let slot = preins_slot_for(phys);
    if slot.phys.load(Ordering::Relaxed) != phys { return; }
    let meta = slot.meta.load(Ordering::Relaxed);
    let site = ((meta >> 16) & 0xFF) as u8;
    let target_inode_low = (meta & 0xFFFF) as u16;
    let target_off_low32 = ((meta >> 32) & 0xFFFF_FFFF) as u32;
    WINDOW_RACE.fetch_add(1, Ordering::Relaxed);
    crate::serial_println!(
        "[PREINS/RACE] phys={:#x} op={} site={} target_inode_low16={:#x} \
         target_off_idx_low32={:#x} reader_key_low32={:#x}",
        phys, op_str(op), site, target_inode_low,
        target_off_low32, reader_key_low32,
    );
}

/// Witness probe for PFH install — the smoking-gun race.
#[inline]
pub fn preins_check_install(phys: u64, mount_idx: usize, inode: u64, file_offset: u64) {
    if phys == 0 { return; }
    let slot = preins_slot_for(phys);
    if slot.phys.load(Ordering::Relaxed) != phys { return; }
    let meta = slot.meta.load(Ordering::Relaxed);
    let site = ((meta >> 16) & 0xFF) as u8;
    let w_cpu = ((meta >> 24) & 0xFF) as u8;
    let w_inode_low16 = (meta & 0xFFFF) as u16;
    let w_off_low32 = ((meta >> 32) & 0xFFFF_FFFF) as u32;
    let w_tick = slot.tick_zerofill.load(Ordering::Relaxed);
    let now_tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let here_cpu = crate::arch::x86_64::apic::cpu_index() as u8;
    INSTALL_RACE.fetch_add(1, Ordering::Relaxed);
    crate::serial_println!(
        "[PREINS/INSTALL_RACE] phys={:#x} site={} \
         installer_key=({},{:#x},{:#x}) installer_cpu={} \
         witness_cpu={} witness_inode_low16={:#x} \
         witness_off_low32={:#x} witness_age_ticks={}",
        phys, site, mount_idx, inode, file_offset, here_cpu,
        w_cpu, w_inode_low16, w_off_low32,
        now_tick.saturating_sub(w_tick),
    );
}

#[inline]
fn op_str(o: u8) -> &'static str {
    match o {
        OP_LOOKUP => "lookup",
        OP_LOOKUP_ACQUIRE => "lookup_acquire",
        OP_IS_PHYS_IN_CACHE => "is_phys_in_cache",
        OP_EVICT => "evict",
        OP_EVICT_IF_PHYS => "evict_if_phys",
        _ => "?",
    }
}

// ── Counters readable via kdb (Arm-1/2) ────────────────────────────────────

static WINDOW_RACE: AtomicU64 = AtomicU64::new(0);
static INSTALL_RACE: AtomicU64 = AtomicU64::new(0);
static PROV_RING_OVERFLOW: AtomicU64 = AtomicU64::new(0);

pub fn window_race_count() -> u64 { WINDOW_RACE.load(Ordering::Relaxed) }
pub fn install_race_count() -> u64 { INSTALL_RACE.load(Ordering::Relaxed) }
pub fn prov_ring_overflow_count() -> u64 { PROV_RING_OVERFLOW.load(Ordering::Relaxed) }

/// Snapshot the top entries in the provenance table by occupancy.
/// Used by kdb's `w215-diag` op for sanity-checking the ring is alive.
pub fn top_traced_physes(out: &mut [(u64, u32)]) -> usize {
    let cap = out.len();
    if cap == 0 { return 0; }
    let mut filled = 0usize;
    for bucket in PROV_TABLE.buckets.iter() {
        for slot in bucket.entries.iter() {
            let phys = slot.phys.load(Ordering::Relaxed);
            if phys == 0 { continue; }
            // Find existing entry in `out`.
            let mut found = false;
            for i in 0..filled {
                if out[i].0 == phys {
                    out[i].1 = out[i].1.saturating_add(1);
                    found = true;
                    break;
                }
            }
            if found { continue; }
            if filled < cap {
                out[filled] = (phys, 1);
                filled += 1;
            } else {
                // Find the minimum-count slot and replace if this phys
                // would rank above it.  O(N²) — fine for cap ≤ 16.
                let mut min_i = 0;
                for i in 1..cap {
                    if out[i].1 < out[min_i].1 { min_i = i; }
                }
                if out[min_i].1 < 2 {
                    out[min_i] = (phys, 1);
                }
            }
        }
    }
    // Sort by count descending (insertion sort).
    for i in 1..filled {
        let cur = out[i];
        let mut j = i;
        while j > 0 && out[j - 1].1 < cur.1 {
            out[j] = out[j - 1];
            j -= 1;
        }
        out[j] = cur;
    }
    filled
}

// ── Axis B: per-writer cache-residency counters ─────────────────────────────

/// Counters — one per instrumented writer.  All `Relaxed`: read by kdb at
/// human pace, no ordering requirement against the corruption itself.
pub static DEVZERO_OVER_CACHE:    AtomicU64 = AtomicU64::new(0);
pub static STATX_OVER_CACHE:      AtomicU64 = AtomicU64::new(0);
pub static GETRANDOM_OVER_CACHE:  AtomicU64 = AtomicU64::new(0);
pub static GETRUSAGE_OVER_CACHE:  AtomicU64 = AtomicU64::new(0);
pub static SYSINFO_OVER_CACHE:    AtomicU64 = AtomicU64::new(0);
pub static TIMES_OVER_CACHE:      AtomicU64 = AtomicU64::new(0);
pub static MEMSET_OVER_CACHE:     AtomicU64 = AtomicU64::new(0);
pub static PREADV120_OVER_CACHE:  AtomicU64 = AtomicU64::new(0);
pub static CLEARTID_OVER_CACHE:   AtomicU64 = AtomicU64::new(0);
pub static SIGFRAME_OVER_CACHE:   AtomicU64 = AtomicU64::new(0);

/// One "first-hit serial line emitted" flag per writer, to avoid drowning
/// the serial log when a single corrupting path fires thousands of times.
/// The counters still tick on every hit; only the structured serial line is
/// rate-limited to one per writer per boot.
static FIRST_LINE_DEVZERO:   AtomicBool = AtomicBool::new(false);
static FIRST_LINE_STATX:     AtomicBool = AtomicBool::new(false);
static FIRST_LINE_GETRANDOM: AtomicBool = AtomicBool::new(false);
static FIRST_LINE_GETRUSAGE: AtomicBool = AtomicBool::new(false);
static FIRST_LINE_SYSINFO:   AtomicBool = AtomicBool::new(false);
static FIRST_LINE_TIMES:     AtomicBool = AtomicBool::new(false);
static FIRST_LINE_MEMSET:    AtomicBool = AtomicBool::new(false);
static FIRST_LINE_PREADV120: AtomicBool = AtomicBool::new(false);
static FIRST_LINE_CLEARTID:  AtomicBool = AtomicBool::new(false);
static FIRST_LINE_SIGFRAME:  AtomicBool = AtomicBool::new(false);

/// Identifies one of the ten instrumented writers.  The name is embedded
/// in the structured serial line so a downstream parser can attribute each
/// `[H_W/<name>]` event back to its source-of-truth callsite.
#[derive(Copy, Clone)]
pub enum Writer {
    DevZero,
    Statx,
    Getrandom,
    Getrusage,
    Sysinfo,
    Times,
    Memset,
    Preadv120,
    ClearTid,
    Sigframe,
}

impl Writer {
    fn name(self) -> &'static str {
        match self {
            Writer::DevZero   => "dev-zero",
            Writer::Statx     => "statx",
            Writer::Getrandom => "getrandom",
            Writer::Getrusage => "getrusage",
            Writer::Sysinfo   => "sysinfo",
            Writer::Times     => "times",
            Writer::Memset    => "memset",
            Writer::Preadv120 => "preadv120",
            Writer::ClearTid  => "clear-tid",
            Writer::Sigframe  => "sigframe",
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        match self {
            Writer::DevZero   => &DEVZERO_OVER_CACHE,
            Writer::Statx     => &STATX_OVER_CACHE,
            Writer::Getrandom => &GETRANDOM_OVER_CACHE,
            Writer::Getrusage => &GETRUSAGE_OVER_CACHE,
            Writer::Sysinfo   => &SYSINFO_OVER_CACHE,
            Writer::Times     => &TIMES_OVER_CACHE,
            Writer::Memset    => &MEMSET_OVER_CACHE,
            Writer::Preadv120 => &PREADV120_OVER_CACHE,
            Writer::ClearTid  => &CLEARTID_OVER_CACHE,
            Writer::Sigframe  => &SIGFRAME_OVER_CACHE,
        }
    }

    fn first_line(self) -> &'static AtomicBool {
        match self {
            Writer::DevZero   => &FIRST_LINE_DEVZERO,
            Writer::Statx     => &FIRST_LINE_STATX,
            Writer::Getrandom => &FIRST_LINE_GETRANDOM,
            Writer::Getrusage => &FIRST_LINE_GETRUSAGE,
            Writer::Sysinfo   => &FIRST_LINE_SYSINFO,
            Writer::Times     => &FIRST_LINE_TIMES,
            Writer::Memset    => &FIRST_LINE_MEMSET,
            Writer::Preadv120 => &FIRST_LINE_PREADV120,
            Writer::ClearTid  => &FIRST_LINE_CLEARTID,
            Writer::Sigframe  => &FIRST_LINE_SIGFRAME,
        }
    }
}

/// Resolve `buf` through the current CR3 to a physical page and ask the
/// cache whether that frame is currently resident.  Returns the first
/// (vaddr, phys, cache_key) tuple where the cache says "yes".
///
/// `len == 0` is treated as `len == 1` so a zero-length buffer is still
/// page-checked at `buf`.
///
/// Walks 4 KiB pages over `[buf, buf+len)` using the current process's
/// CR3.  Caller is responsible for the buffer being in user space; this
/// function only translates and looks up, it does not deref the buffer.
fn check_user_buf_over_cache(
    buf: *const u8,
    len: usize,
) -> Option<(u64, u64, (usize, u64, u64))> {
    if buf.is_null() { return None; }
    let len = if len == 0 { 1 } else { len };
    let start = buf as u64;
    let end   = start.checked_add(len as u64)?;
    let first_page = start & !0xFFFu64;
    let last_page  = (end - 1) & !0xFFFu64;

    // Use the current CR3 — the writer is in syscall context, so the
    // active CR3 is the calling process's PML4.
    let cr3 = crate::mm::vmm::get_cr3();

    let mut va = first_page;
    loop {
        if let Some(phys_with_offset) = crate::mm::vmm::virt_to_phys_in(cr3, va) {
            let phys = phys_with_offset & !0xFFFu64;
            if let Some(key) = crate::mm::cache::is_phys_in_cache(phys) {
                return Some((va, phys, key));
            }
        }
        if va == last_page { break; }
        va += 0x1000;
    }
    None
}

/// Probe `[buf, buf+len)`; if any page maps to a cache-resident phys
/// frame, bump the per-writer counter and (on the first hit per writer)
/// emit a structured `[H_W/<name>]` serial line.
///
/// Observation-only: returns no value, does not alter the write.
///
/// ISR-safe: uses the PAGE_CACHE Mutex (spin, no sleep) and a CR3 read
/// (asm).  Safe to call from syscall, exit-thread, and signal-delivery
/// contexts.
#[inline]
pub fn probe(writer: Writer, buf: *const u8, len: usize) {
    if let Some((vaddr, phys, (mount, inode, offset))) =
        check_user_buf_over_cache(buf, len)
    {
        writer.counter().fetch_add(1, Ordering::Relaxed);
        if !writer.first_line().swap(true, Ordering::Relaxed) {
            let pid = crate::proc::current_pid_lockless();
            crate::serial_println!(
                "[H_W/{}] pid={} vaddr={:#x} phys={:#x} key=({},{:#x},{:#x})",
                writer.name(), pid, vaddr, phys, mount, inode, offset,
            );
        }
    }
}

/// Read all ten counters; used by the `kdb w215-cache-residency` op.
pub fn counts() -> [(&'static str, u64); 10] {
    [
        ("dev-zero",  DEVZERO_OVER_CACHE.load(Ordering::Relaxed)),
        ("statx",     STATX_OVER_CACHE.load(Ordering::Relaxed)),
        ("getrandom", GETRANDOM_OVER_CACHE.load(Ordering::Relaxed)),
        ("getrusage", GETRUSAGE_OVER_CACHE.load(Ordering::Relaxed)),
        ("sysinfo",   SYSINFO_OVER_CACHE.load(Ordering::Relaxed)),
        ("times",     TIMES_OVER_CACHE.load(Ordering::Relaxed)),
        ("memset",    MEMSET_OVER_CACHE.load(Ordering::Relaxed)),
        ("preadv120", PREADV120_OVER_CACHE.load(Ordering::Relaxed)),
        ("clear-tid", CLEARTID_OVER_CACHE.load(Ordering::Relaxed)),
        ("sigframe",  SIGFRAME_OVER_CACHE.load(Ordering::Relaxed)),
    ]
}

// ── Phase D 2026-05-20: dedicated phys-FREE shadow ──────────────────────────
//
// The primary `PROV_TABLE` (above) hashes phys into 256 buckets of 16 slots
// each — adequate for the file-backed bucket-A workload that prior W215
// iterations targeted, but **too small** for the
// post-vfork-cleanup workload at sc≈1233 (Phase C trial set).  The Phase D
// first trial confirmed: the prov ring is EMPTY for the fault's `rip_phys`
// because every prior FREE / REFDEC / REFINC event for that bucket has been
// rotated out by ~16 other phys frames flowing through the same hash bucket.
//
// To capture the FREE→ALLOC→fault chain at the **specific frame** that
// faults, this shadow tracks ONLY `KIND_FREE` events, keyed directly by
// `pfn` (no hash collisions across phys → no eviction by unrelated frames).
// Sized at 64 Ki entries × 24 bytes = 1.5 MiB BSS — material only in
// `firefox-test` builds because the entire `w215_diag` module is gated.
//
// Direct addressing: `pfn % FREE_SHADOW_SIZE`.  On collision, the newer
// entry overwrites the older.  `FREE_SHADOW_DISPLACED` counts overwrites so
// a downstream operator can verify whether the shadow's verdict is reliable
// (zero displacements ⇒ exact per-pfn record).
//
// Per Intel SDM Vol. 3A §4.10.5, the most-recent free of a frame is the
// upstream of a use-after-recycle when the freed frame is then drawn by
// `alloc_page_locked` and re-installed in a PTE via a path that lacks the
// `page_ref_inc` discipline.  Naming the free's caller-RIP is the
// dispositive evidence.

/// Direct-mapped free-shadow size.  64 Ki entries covers `64 Ki × 4 KiB =
/// 256 MiB` of physical address space without collisions; with `pfn %
/// FREE_SHADOW_SIZE` direct addressing, frames spaced by a multiple of 256 MiB
/// alias into the same slot.
///
/// ## Why NOT widened to cover the whole guest (W215 task#23, 2026-07-10)
///
/// The obvious fix for the displacement-blind `hit=0` was to grow the table to
/// 2^19 (2 GiB coverage).  That is **infeasible in BSS**: the bootloader writes
/// the handoff `BootInfo` at a fixed `BOOT_INFO_PHYS_BASE` = 16 MiB
/// (`shared/src/lib.rs`), and the kernel image (loaded at 1 MiB, `.bss`
/// included) must end below it or `_start`'s BSS-zeroing clobbers the handoff
/// page (the exact hazard `w215_crc.rs` documents).  A 2^19 pair of shadows is
/// +22 MiB of BSS and overruns 16 MiB.
///
/// Instead the displacement-blindness is removed *per pfn* at read time, with
/// no size change: [`free_shadow_slot_state`] reports whether the faulting
/// frame's slot holds an EXACT record for that pfn (reliable hit), is EMPTY
/// (`phys == 0` — reliably "no free recorded for this pfn", since a free of
/// this pfn OR any aliasing pfn would have written it), or is ALIASED (holds a
/// *different* pfn — this pfn's record was displaced, so the verdict is
/// inconclusive for this fault and the operator waits for another).  Frees are
/// far rarer than allocs over a boot, so a code-page frame (which is demand-
/// faulted and never freed for the process lifetime) reads EMPTY reliably —
/// the common, decisive case.  Per Intel SDM Vol. 3A §4.10.5 the most-recent
/// free of a frame is the upstream of a use-after-recycle; naming it (or
/// proving it never happened) per-pfn is the dispositive evidence.
const FREE_SHADOW_SIZE: usize = 65536;

#[repr(C)]
struct FreeShadowEntry {
    /// Physical address of the most-recent free into this slot.  `0` means
    /// the slot has never been written.
    phys: AtomicU64,
    /// Tick at which the free fired.
    tick: AtomicU64,
    /// Caller-RIP of the `pmm::free_page` invocation that freed the frame.
    caller_rip: AtomicU64,
}

impl FreeShadowEntry {
    const fn new() -> Self {
        Self {
            phys: AtomicU64::new(0),
            tick: AtomicU64::new(0),
            caller_rip: AtomicU64::new(0),
        }
    }
}

struct FreeShadow {
    slots: [FreeShadowEntry; FREE_SHADOW_SIZE],
}

impl FreeShadow {
    const fn new() -> Self {
        const E: FreeShadowEntry = FreeShadowEntry::new();
        Self { slots: [E; FREE_SHADOW_SIZE] }
    }
}

static FREE_SHADOW: FreeShadow = FreeShadow::new();

/// Number of free events that displaced an unrelated previous entry in the
/// free-shadow (i.e. `slot.phys != 0 && slot.phys != new_phys`).  Zero means
/// every recorded FREE for the current run is observable by phys; non-zero
/// means at least one phys's free was overwritten by an aliasing pfn.
static FREE_SHADOW_DISPLACED: AtomicU64 = AtomicU64::new(0);

/// Total number of free events recorded into the shadow.
static FREE_SHADOW_RECORDED: AtomicU64 = AtomicU64::new(0);

#[inline]
fn free_shadow_slot(phys: u64) -> &'static FreeShadowEntry {
    let pfn = (phys >> 12) as usize;
    &FREE_SHADOW.slots[pfn & (FREE_SHADOW_SIZE - 1)]
}

/// Record a free event in the direct-addressed shadow.  Called by
/// `pmm::free_page` immediately after the residual-`pte_share_count`
/// invariant check passes.
#[inline]
pub fn free_shadow_record(phys: u64, caller_rip: u64) {
    if phys == 0 { return; }
    let slot = free_shadow_slot(phys);
    let prev_phys = slot.phys.load(Ordering::Relaxed);
    if prev_phys != 0 && prev_phys != phys {
        FREE_SHADOW_DISPLACED.fetch_add(1, Ordering::Relaxed);
    }
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    // Note: relaxed writes — diagnostic readers may observe a torn
    // (phys, tick, rip) tuple. Acceptable for a best-effort tracer; do
    // not promote to load-bearing.
    slot.phys.store(phys, Ordering::Relaxed);
    slot.tick.store(tick, Ordering::Relaxed);
    slot.caller_rip.store(caller_rip, Ordering::Relaxed);
    FREE_SHADOW_RECORDED.fetch_add(1, Ordering::Relaxed);
}

/// Look up the most-recent free recorded for `phys` in the shadow.  Returns
/// `(tick, caller_rip)` if an entry is present with matching phys, else
/// `None`.  Called from the fault-site dump to localise the unmap caller.
#[inline]
pub fn free_shadow_lookup(phys: u64) -> Option<(u64, u64)> {
    if phys == 0 { return None; }
    let slot = free_shadow_slot(phys);
    let p = slot.phys.load(Ordering::Relaxed);
    if p != phys { return None; }
    let tick = slot.tick.load(Ordering::Relaxed);
    let rip  = slot.caller_rip.load(Ordering::Relaxed);
    Some((tick, rip))
}

/// Diagnostic dump: emit the free-shadow entry for `phys` as a single
/// `[FAULT/PHYS/FREESHADOW]` serial line.  Format chosen for grep parsing
/// by the harness without requiring a JSON decoder.
pub fn dump_free_shadow_for_phys(phys: u64) {
    let now_tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let recorded = FREE_SHADOW_RECORDED.load(Ordering::Relaxed);
    let displaced = FREE_SHADOW_DISPLACED.load(Ordering::Relaxed);
    match free_shadow_lookup(phys) {
        Some((tick, rip)) => {
            let age_ticks = now_tick.saturating_sub(tick);
            crate::serial_println!(
                "[FAULT/PHYS/FREESHADOW] phys={:#x} hit=1 free_tick={} \
                 age_ticks={} caller_rip={:#x} totals=(recorded={},displaced={})",
                phys, tick, age_ticks, rip, recorded, displaced,
            );
        }
        None => {
            crate::serial_println!(
                "[FAULT/PHYS/FREESHADOW] phys={:#x} hit=0 totals=(recorded={},displaced={})",
                phys, recorded, displaced,
            );
        }
    }
}

/// Per-pfn trust state of a direct-addressed shadow slot.  This is what makes
/// a `hit=0` lookup interpretable despite the table aliasing 4-to-1 on a 1 GiB
/// guest: the *specific* faulting pfn either owns its slot, has a provably
/// untouched slot, or has been displaced by an aliasing pfn (in which case the
/// lookup for THIS pfn is inconclusive and must not be read as "never freed").
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SlotState {
    /// Slot holds a record for exactly this pfn — the (tick, rip) is reliable.
    Exact,
    /// Slot was never written (`phys == 0`).  Because a free/alloc of this pfn
    /// OR of any pfn aliasing to this slot would have stamped `phys`, an empty
    /// slot reliably proves this pfn's event never occurred.
    Empty,
    /// Slot holds a *different* pfn — this pfn's record (if any) was displaced.
    /// The lookup is inconclusive for this pfn.
    Aliased,
}

impl SlotState {
    pub fn as_str(self) -> &'static str {
        match self {
            SlotState::Exact => "EXACT",
            SlotState::Empty => "EMPTY",
            SlotState::Aliased => "ALIASED",
        }
    }
}

/// Classify the FREE-shadow slot occupancy for `phys` (see [`SlotState`]).
pub fn free_shadow_slot_state(phys: u64) -> SlotState {
    if phys == 0 {
        return SlotState::Aliased; // phys=0 is never a real frame; treat as noise
    }
    let slot = free_shadow_slot(phys);
    match slot.phys.load(Ordering::Relaxed) {
        0 => SlotState::Empty,
        p if p == phys => SlotState::Exact,
        _ => SlotState::Aliased,
    }
}

/// Read free-shadow counters for kdb introspection.
pub fn free_shadow_recorded_count() -> u64 {
    FREE_SHADOW_RECORDED.load(Ordering::Relaxed)
}
pub fn free_shadow_displaced_count() -> u64 {
    FREE_SHADOW_DISPLACED.load(Ordering::Relaxed)
}

// ── Track K (2026-05-20): ALLOC_SHADOW + USER-STACK PTE_CHANGE_RING ─────────
//
// Phase D landed `FREE_SHADOW` to name the upstream `pmm::free_page` caller
// for a given phys frame.  The symmetric ALLOC side lets a downstream
// diagnostic answer "was this phys allocated to *someone* between the
// libxul prologue and the SSP epilogue?" — the foundation for naming the
// page-table operation that aliased a stack-page VA to a different phys.
//
// `PTE_CHANGE_RING` is the per-VA companion: a direct-addressed ring keyed
// by `(va >> 12) % USER_STACK_PTE_RING_SIZE` that records every
// `map_page_in` / `unmap_page_in` / `write_pte` operation whose VA falls in
// the userspace high-stack window `[USER_STACK_RING_LO, USER_STACK_RING_HI)`.
// The window is chosen to cover the main-thread initial stack
// (`0x7fff_ffe0_0000 .. 0x8000_0000_0000`) PLUS any clone-spawned thread
// stacks placed by the kernel's `clone(CLONE_VM)` path in the same region.
//
// Per Intel SDM Vol. 3A §4.10.5 — a PTE change must be propagated to all
// processors before the underlying physical frame is returned to the
// allocator.  Naming the operator-of-record for each PTE change on the
// canary slot's VA is the dispositive evidence for Track K's F3
// hypothesis space (PTE-replace vs TLB-stale).
//
// All counters / rings are `firefox-test`-gated; default builds remain
// byte-identical.

/// Lower bound of the PTE-change ring window (D13 widening, 2026-05-22).
///
/// Originally `0x0000_7fff_ffe0_0000` — the top 2 MiB of canonical user space,
/// chosen to cover the main-thread initial stack + vfork helper stacks.  D12
/// (sc=201 glibc FILE._lock NULL-deref, 2026-05-22) demonstrated the
/// restriction was diagnostically fatal: the corrupted frame lived at
/// `0x7effd9a21020` (a glibc malloc-arena heap page well below the stack
/// window), so `pte_change_record` was a no-op for every PTE event on the
/// faulting page and the ring could not name the writer.
///
/// D13 widens the filter to the full canonical user VA range (skipping the
/// nullptr page at 0).  Per Intel SDM Vol. 3A §4.6 user VA covers
/// `[0, 0x0000_8000_0000_0000)`; we admit any user-VA PTE change.  The ring
/// SIZE is unchanged (1024 slots — see [`USER_STACK_PTE_RING_SIZE`] below)
/// to keep BSS bounded, so collisions are now expected and observable via
/// [`PTE_CHANGE_DISPLACED`].  Most-recent-write-wins per slot; for a saga
/// in flight the dispatcher cross-checks the ring's `tick` field against
/// the fault tick to confirm freshness.  This is a *diagnostic-only* tradeoff
/// gated under `firefox-test`; default builds remain byte-identical.
pub const USER_STACK_RING_LO: u64 = 0x0000_0000_0000_1000;

/// Upper (exclusive) bound — top of canonical lower-half user address space.
pub const USER_STACK_RING_HI: u64 = 0x0000_8000_0000_0000;

/// Number of entries in the PTE-change ring.  Direct addressing over
/// `(va >> 12)` mod the size.  Pre-D13 the window covered only 2 MiB (512
/// 4 KiB pages, so 1024 slots gave 2× headroom and effectively zero
/// collisions); post-D13 the window covers the full 128 TiB canonical user
/// VA, so collisions are unavoidable at this size — the ring is a
/// most-recent-write-wins cache rather than a complete record.  Bumping to
/// e.g. 64 Ki slots (3 MiB BSS) would not eliminate aliasing either
/// (`2^35 PFNs >> 2^16`), so we keep the small footprint and rely on the
/// `tick` freshness cross-check at dump time.  See module banner.
const USER_STACK_PTE_RING_SIZE: usize = 1024;

/// PTE-change kind codes.
pub const PTE_KIND_MAP: u8       = 1; // map_page_in installed a fresh PTE
pub const PTE_KIND_UNMAP: u8     = 2; // unmap_page_in cleared the PTE
pub const PTE_KIND_WRITE: u8     = 3; // write_pte rewrote PTE flags (CoW etc.)
pub const PTE_KIND_BULK_UNMAP: u8 = 4; // unmap_and_free_range_in cleared the PTE
pub const PTE_KIND_FORK_CLONE: u8 = 5; // clone_for_fork installed a CoW PTE

#[repr(C)]
struct PteChangeEntry {
    /// Virtual address (`va` masked to a 4 KiB-aligned page) of the changed
    /// PTE.  `0` means the slot has never been written.
    va: AtomicU64,
    /// Tick at which the change fired.
    tick: AtomicU64,
    /// New phys (post-change).  `0` for an unmap.
    new_phys: AtomicU64,
    /// Old phys (pre-change).  `0` if the slot was empty.
    old_phys: AtomicU64,
    /// Packed: [63:32] caller_rip_low32 (truncated; kernel low 32 bits suffice
    /// for `addr2line` against the kernel ELF), [31:16] cr3_low16,
    /// [15:8] cpu, [7:0] kind.  `tid` carried in a separate field below.
    packed: AtomicU64,
    /// Recording TID (mostly useful for cross-correlation with `[HB]` log).
    tid: AtomicU64,
}

impl PteChangeEntry {
    const fn new() -> Self {
        Self {
            va: AtomicU64::new(0),
            tick: AtomicU64::new(0),
            new_phys: AtomicU64::new(0),
            old_phys: AtomicU64::new(0),
            packed: AtomicU64::new(0),
            tid: AtomicU64::new(0),
        }
    }
}

struct PteChangeRing {
    slots: [PteChangeEntry; USER_STACK_PTE_RING_SIZE],
}

impl PteChangeRing {
    const fn new() -> Self {
        const E: PteChangeEntry = PteChangeEntry::new();
        Self { slots: [E; USER_STACK_PTE_RING_SIZE] }
    }
}

static PTE_CHANGE_RING: PteChangeRing = PteChangeRing::new();

/// Total PTE-change events recorded (every successful map / unmap / write
/// in-window).
static PTE_CHANGE_RECORDED: AtomicU64 = AtomicU64::new(0);

/// Number of events whose slot already held a different VA (slot collision —
/// the previous entry was overwritten).  Hash size is 8× the window so this
/// should remain ~0 in normal operation; non-zero is a yellow flag for the
/// dump's reliability.
static PTE_CHANGE_DISPLACED: AtomicU64 = AtomicU64::new(0);

#[inline]
fn pte_ring_slot(va: u64) -> Option<&'static PteChangeEntry> {
    if va < USER_STACK_RING_LO || va >= USER_STACK_RING_HI {
        return None;
    }
    let pfn = (va >> 12) as usize;
    Some(&PTE_CHANGE_RING.slots[pfn & (USER_STACK_PTE_RING_SIZE - 1)])
}

/// Record a PTE-change event.  No-op outside the user-stack window.
///
/// `va` is the changed user VA (will be page-aligned for storage).
/// `old_phys`/`new_phys` are the pre/post mappings (`0` for unmapped).
/// `kind` is one of `PTE_KIND_*`.  `caller_rip` is the kernel return
/// address into the caller of the page-table primitive — used to name
/// the upstream syscall handler (`addr2line` against the kernel ELF).
#[inline]
pub fn pte_change_record(
    va: u64,
    new_phys: u64,
    old_phys: u64,
    kind: u8,
    caller_rip: u64,
    cr3: u64,
) {
    let slot = match pte_ring_slot(va) {
        Some(s) => s,
        None => return,
    };
    let va_page = va & !0xFFFu64;
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let cpu = crate::arch::x86_64::apic::cpu_index() as u64;
    let tid = crate::proc::current_tid();
    let prev_va = slot.va.load(Ordering::Relaxed);
    // Note: displacement counter uses relaxed-order writes; concurrent
    // same-slot frees from different phys may undercount. Informational
    // only.
    if prev_va != 0 && prev_va != va_page {
        PTE_CHANGE_DISPLACED.fetch_add(1, Ordering::Relaxed);
    }
    let rip_low32 = caller_rip & 0xFFFF_FFFF;
    let cr3_low16 = (cr3 >> 12) & 0xFFFF;
    let packed = (rip_low32 << 32) | (cr3_low16 << 16) | (cpu << 8) | (kind as u64);
    slot.va.store(va_page, Ordering::Relaxed);
    slot.tick.store(tick, Ordering::Relaxed);
    slot.new_phys.store(new_phys & !0xFFFu64, Ordering::Relaxed);
    slot.old_phys.store(old_phys & !0xFFFu64, Ordering::Relaxed);
    slot.packed.store(packed, Ordering::Relaxed);
    slot.tid.store(tid as u64, Ordering::Relaxed);
    PTE_CHANGE_RECORDED.fetch_add(1, Ordering::Relaxed);
}

#[inline]
fn pte_kind_str(k: u8) -> &'static str {
    match k {
        PTE_KIND_MAP => "MAP",
        PTE_KIND_UNMAP => "UNMAP",
        PTE_KIND_WRITE => "WRITE",
        PTE_KIND_BULK_UNMAP => "BULK_UNMAP",
        PTE_KIND_FORK_CLONE => "FORK_CLONE",
        _ => "?",
    }
}

/// Emit the most-recent PTE-change entry for the (4 KiB-aligned) `va` as a
/// single `[FAULT/STACK-PTE]` serial line.  Used by the SSP-DIAG-PROV
/// extension and (later, optionally) by the FAULT/PHYS dump.  Returns the
/// recorded `old_phys` (pre-change PTE phys) so the caller can dump the
/// FREE_SHADOW / ALLOC_SHADOW entries for that prior frame.  Returns `0`
/// when the slot is empty or the lookup fell outside the user-stack window.
pub fn dump_pte_change_for_va(va: u64) -> u64 {
    let slot = match pte_ring_slot(va) {
        Some(s) => s,
        None => {
            crate::serial_println!(
                "[FAULT/STACK-PTE] va={:#x} hit=0 reason=out_of_window",
                va,
            );
            return 0;
        }
    };
    let va_page = va & !0xFFFu64;
    let stored_va = slot.va.load(Ordering::Relaxed);
    let recorded = PTE_CHANGE_RECORDED.load(Ordering::Relaxed);
    let displaced = PTE_CHANGE_DISPLACED.load(Ordering::Relaxed);
    if stored_va != va_page {
        crate::serial_println!(
            "[FAULT/STACK-PTE] va={:#x} hit=0 stored_va={:#x} \
             totals=(recorded={},displaced={})",
            va_page, stored_va, recorded, displaced,
        );
        return 0;
    }
    let tick = slot.tick.load(Ordering::Relaxed);
    let new_phys = slot.new_phys.load(Ordering::Relaxed);
    let old_phys = slot.old_phys.load(Ordering::Relaxed);
    let packed = slot.packed.load(Ordering::Relaxed);
    let tid = slot.tid.load(Ordering::Relaxed);
    let kind = (packed & 0xFF) as u8;
    let cpu = ((packed >> 8) & 0xFF) as u8;
    let cr3_low16 = (packed >> 16) & 0xFFFF;
    let rip_low32 = (packed >> 32) & 0xFFFF_FFFF;
    let now_tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let age_ticks = now_tick.saturating_sub(tick);
    crate::serial_println!(
        "[FAULT/STACK-PTE] va={:#x} hit=1 kind={} tick={} age_ticks={} \
         new_phys={:#x} old_phys={:#x} tid={} cpu={} \
         caller_rip_low32={:#x} cr3_low16={:#x} \
         totals=(recorded={},displaced={})",
        va_page, pte_kind_str(kind), tick, age_ticks,
        new_phys, old_phys, tid, cpu,
        rip_low32, cr3_low16,
        recorded, displaced,
    );
    old_phys
}

/// Read PTE-change-ring counters for kdb introspection.
pub fn pte_change_recorded_count() -> u64 {
    PTE_CHANGE_RECORDED.load(Ordering::Relaxed)
}
pub fn pte_change_displaced_count() -> u64 {
    PTE_CHANGE_DISPLACED.load(Ordering::Relaxed)
}

// ── ALLOC_SHADOW (symmetric to FREE_SHADOW) ─────────────────────────────────
//
// Direct-addressed by `pfn % ALLOC_SHADOW_SIZE`; records the most recent
// `pmm::alloc_page_locked` event for that pfn (caller-RIP, tick).  Combined
// with FREE_SHADOW (Phase D) this lets Track K reconstruct the "was this
// phys handed out between prologue and epilogue?" timeline for the foreign
// frame backing the canary slot at fault time.
//
// ## Sizing (Phase 10, 2026-05-22 widening)
//
// Pre-widening sizing was 4 Ki entries × 24 B = 96 KiB BSS.  Phase 10 of
// the F3 diagnostic (long demo trial, sc ≈ 1233) measured 97 % displacement
// saturation: `recorded = 38 394, displaced = 37 363`.  At that saturation
// the ring's attribution power for any specific phys is essentially zero —
// nearly every phys's `(caller_rip, tick)` has been overwritten by some
// later allocation that aliased the same slot.
//
// Widening to 64 Ki entries (× 24 B = 1.5 MiB BSS) brings ALLOC_SHADOW into
// symmetry with FREE_SHADOW (Phase D) and gives the same aliasing budget:
// `64 Ki × 4 KiB = 256 MiB` of physical address space hashed collision-free,
// degrading to ≤ 16-to-1 in a 4 GiB QEMU configuration.  This is the same
// rationale captured in the FREE_SHADOW banner above — direct addressing
// `pfn % SHADOW_SIZE` aliases pfn-multiples of 256 MiB, but the *most-recent*
// alloc working set on the firefox-test demo path is dominated by churn in
// the lower few hundred MiB (heap, anonymous mmap, kstacks), so aliasing
// frames are rare and `ALLOC_SHADOW_DISPLACED` should stay near zero.
//
// BSS impact: +1 440 KiB (gated on `firefox-test`).  Default builds remain
// byte-identical.  The 2026-05-21 dynamic-heap fix in
// `mm/heap.rs::compute_heap_layout()` (computes the heap base past
// `__kernel_end`) means BSS growth in diagnostic features no longer collides
// with the allocator arena — the earlier 96 KiB cap was a band-aid for the
// static-base heap, which has since been retired.
//
// Per Intel SDM Vol. 3A §4.10.5 (paging-structure cache coherence) and
// CWE-908 (Use of Uninitialized Resource), naming the upstream allocator
// of a frame that turns out to be use-after-recycle is the dispositive
// evidence for the W215 class of bug; the ring is the substrate for that
// attribution and must therefore have enough capacity to survive a multi-
// second demo trial without being overwritten end-to-end.

const ALLOC_SHADOW_SIZE: usize = 65536;

#[repr(C)]
struct AllocShadowEntry {
    phys: AtomicU64,
    tick: AtomicU64,
    caller_rip: AtomicU64,
}

impl AllocShadowEntry {
    const fn new() -> Self {
        Self {
            phys: AtomicU64::new(0),
            tick: AtomicU64::new(0),
            caller_rip: AtomicU64::new(0),
        }
    }
}

struct AllocShadow {
    slots: [AllocShadowEntry; ALLOC_SHADOW_SIZE],
}

impl AllocShadow {
    const fn new() -> Self {
        const E: AllocShadowEntry = AllocShadowEntry::new();
        Self { slots: [E; ALLOC_SHADOW_SIZE] }
    }
}

static ALLOC_SHADOW: AllocShadow = AllocShadow::new();

static ALLOC_SHADOW_RECORDED: AtomicU64 = AtomicU64::new(0);
static ALLOC_SHADOW_DISPLACED: AtomicU64 = AtomicU64::new(0);

#[inline]
fn alloc_shadow_slot(phys: u64) -> &'static AllocShadowEntry {
    let pfn = (phys >> 12) as usize;
    &ALLOC_SHADOW.slots[pfn & (ALLOC_SHADOW_SIZE - 1)]
}

/// Record an alloc event in the direct-addressed shadow.  Called by
/// `pmm::alloc_page_locked` immediately after `mark_page_used` succeeds.
///
/// To keep per-entry storage at 24 B (matching FREE_SHADOW) and BSS within
/// the heap-overlap budget (see comment block above), this function does
/// NOT record per-event TID or CPU.  The recording tick lets a downstream
/// operator cross-reference the `[HB]` heartbeat lines (which carry CPU
/// affinity) when needed.
#[inline]
pub fn alloc_shadow_record(phys: u64, caller_rip: u64) {
    if phys == 0 { return; }
    let slot = alloc_shadow_slot(phys);
    let prev_phys = slot.phys.load(Ordering::Relaxed);
    if prev_phys != 0 && prev_phys != phys {
        ALLOC_SHADOW_DISPLACED.fetch_add(1, Ordering::Relaxed);
    }
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    slot.phys.store(phys, Ordering::Relaxed);
    slot.tick.store(tick, Ordering::Relaxed);
    slot.caller_rip.store(caller_rip, Ordering::Relaxed);
    ALLOC_SHADOW_RECORDED.fetch_add(1, Ordering::Relaxed);
}

/// Look up the most-recent alloc recorded for `phys`.  Returns
/// `(tick, caller_rip)` if the entry's phys still matches.
#[inline]
pub fn alloc_shadow_lookup(phys: u64) -> Option<(u64, u64)> {
    if phys == 0 { return None; }
    let slot = alloc_shadow_slot(phys);
    let p = slot.phys.load(Ordering::Relaxed);
    if p != phys { return None; }
    let tick = slot.tick.load(Ordering::Relaxed);
    let rip = slot.caller_rip.load(Ordering::Relaxed);
    Some((tick, rip))
}

/// Diagnostic dump: emit the alloc-shadow entry for `phys` as a single
/// `[FAULT/PHYS/ALLOCSHADOW]` serial line.  Format mirrors FREESHADOW for
/// grep-symmetry.
pub fn dump_alloc_shadow_for_phys(phys: u64) {
    let now_tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let recorded = ALLOC_SHADOW_RECORDED.load(Ordering::Relaxed);
    let displaced = ALLOC_SHADOW_DISPLACED.load(Ordering::Relaxed);
    match alloc_shadow_lookup(phys) {
        Some((tick, rip)) => {
            let age_ticks = now_tick.saturating_sub(tick);
            crate::serial_println!(
                "[FAULT/PHYS/ALLOCSHADOW] phys={:#x} hit=1 alloc_tick={} \
                 age_ticks={} caller_rip={:#x} \
                 totals=(recorded={},displaced={})",
                phys, tick, age_ticks, rip,
                recorded, displaced,
            );
        }
        None => {
            crate::serial_println!(
                "[FAULT/PHYS/ALLOCSHADOW] phys={:#x} hit=0 \
                 totals=(recorded={},displaced={})",
                phys, recorded, displaced,
            );
        }
    }
}

/// Classify the ALLOC-shadow slot occupancy for `phys` (see [`SlotState`]).
pub fn alloc_shadow_slot_state(phys: u64) -> SlotState {
    if phys == 0 {
        return SlotState::Aliased;
    }
    let slot = alloc_shadow_slot(phys);
    match slot.phys.load(Ordering::Relaxed) {
        0 => SlotState::Empty,
        p if p == phys => SlotState::Exact,
        _ => SlotState::Aliased,
    }
}

/// Read alloc-shadow counters for kdb introspection.
pub fn alloc_shadow_recorded_count() -> u64 {
    ALLOC_SHADOW_RECORDED.load(Ordering::Relaxed)
}
pub fn alloc_shadow_displaced_count() -> u64 {
    ALLOC_SHADOW_DISPLACED.load(Ordering::Relaxed)
}

// ── [W215/VERDICT] combined free→recycle vs in-place-mutation classifier ─────
//
// The single disambiguator the W215 saga hinged on but never ran reliably.
// Given the physical frame that a fault resolved to (either the instruction
// page `rip_phys` or the data page `cr2`→phys), read the *per-pfn trust state*
// of the FREE/ALLOC shadow slots (see [`SlotState`] — this is what makes the
// verdict reliable despite the 256 MiB-aliasing table, without the +22 MiB BSS
// that whole-guest coverage would need and that would clobber the 16 MiB
// BootInfo handoff) plus the live refcount / pte_share, and emit a one-line
// verdict:
//
//   * `INPLACE_NEVERFREED` — FREE slot EMPTY (reliable): this frame was never
//                   freed since boot, so it cannot be a use-after-recycle — a
//                   wrong writer mutated a live, legitimately-owned frame in
//                   place.  The writer must then be caught with a hardware
//                   watchpoint on this frame's VA (classification, not writer
//                   RIP, is the output — that is what ends the two-camp
//                   ambiguity).  `alloc` names the owner-of-record if EXACT.
//   * `RECYCLE_DANGLING`  — FREE slot EXACT and `refcount == 0`: the frame was
//                   freed and is currently unowned, yet the victim still maps
//                   it ⇒ genuine dangling recycle.  `free.rip` names the
//                   `pmm::free_page` caller that released it under the mapping.
//   * `INPLACE_REALLOC`   — FREE slot EXACT but `refcount >= 1`: a free is
//                   recorded but the frame is live again (re-allocated after
//                   that free) ⇒ the recorded free is prior-life history; the
//                   current corruption is in-place on the live allocation.
//   * `INDETERMINATE_FREE_ALIASED` — FREE slot holds a different pfn (this
//                   pfn's record was displaced by an aliasing pfn) ⇒ the FREE
//                   verdict is inconclusive for this fault; wait for another.
//
// Per Intel SDM Vol. 3A §4.10.5 the most-recent free of a frame is the
// upstream of any use-after-recycle; proving per-pfn that it either happened
// (EXACT) or provably did not (EMPTY) is the dispositive evidence.  The line
// is grep-stable:
//   [W215/VERDICT] phys=<p> class=<...> free=(state,tick,rip) \
//     alloc=(state,tick,rip) rc=<n> sc=<n>
pub fn dump_w215_verdict_for_phys(phys: u64) {
    if phys == 0 {
        return;
    }
    let free_state = free_shadow_slot_state(phys);
    let alloc_state = alloc_shadow_slot_state(phys);
    let free = free_shadow_lookup(phys); // Option<(tick, rip)>, valid iff Exact
    let alloc = alloc_shadow_lookup(phys);
    let rc = crate::mm::refcount::page_ref_count(phys);
    let sc = crate::mm::refcount::pte_share_count(phys);

    // Classification anchored on the FREE-shadow *per-pfn* trust state plus the
    // live refcount.  The FREE side is the load-bearing signal: allocs are far
    // more frequent than frees, so the ALLOC slot is usually aliased, but the
    // FREE slot for a rarely-freed code/data frame is reliably readable.
    //
    //   * free EMPTY (reliable)          → this frame was NEVER freed since
    //                                        boot ⇒ it cannot be a recycle ⇒
    //                                        IN-PLACE mutation of a live frame.
    //   * free EXACT + refcount == 0     → freed AND currently unowned yet the
    //                                        victim still maps it ⇒ genuine
    //                                        dangling RECYCLE; `freer_rip` names
    //                                        the releaser.
    //   * free EXACT + refcount >= 1     → a free is recorded but the frame is
    //                                        live again (re-allocated after that
    //                                        free) ⇒ the recorded free is prior-
    //                                        life history; the current corruption
    //                                        is IN-PLACE on the live allocation.
    //   * free ALIASED                   → this pfn's free record was displaced
    //                                        by an aliasing pfn ⇒ INDETERMINATE
    //                                        for this fault; wait for another.
    let class = match free_state {
        SlotState::Empty => "INPLACE_NEVERFREED",
        SlotState::Exact if rc == 0 => "RECYCLE_DANGLING",
        SlotState::Exact => "INPLACE_REALLOC",
        SlotState::Aliased => "INDETERMINATE_FREE_ALIASED",
    };

    let (ftick, frip) = free.unwrap_or((0, 0));
    let (atick, arip) = alloc.unwrap_or((0, 0));
    crate::serial_println!(
        "[W215/VERDICT] phys={:#x} class={} \
         free=(state={},tick={},rip={:#x}) \
         alloc=(state={},tick={},rip={:#x}) rc={} sc={}",
        phys, class,
        free_state.as_str(), ftick, frip,
        alloc_state.as_str(), atick, arip,
        rc, sc,
    );
}

// ── FONT-RECYCLE catch (Wikipedia re/fonts blob slice-panic) ────────────────
//
// The targeted catch for the deterministic SMP=1 Wikipedia render crash: a
// Rust slice-range panic in WebRender's blob path whose garbage end-index
// 0x73746e6f662f6572 decodes to the ASCII bytes "re/fonts" — the trailing
// region of a moz2d blob buffer holding a stale font-path string instead of
// the blob's index offset.  The blob is produced and consumed in the SAME
// render process (BlobWriter::finish writes the trailing usize index offset;
// BlobReader::new reads &buf[index_offset..len-8]), so the corruption is a
// single-address-space hazard, not a cross-process one.
//
// Two sub-hypotheses, both catchable at frame-install time:
//   H_ZERO  — a frame whose previous content was a font path ("…/fonts/…")
//             is recycled into a writable user anonymous/heap mapping WITHOUT
//             zeroing, so the consumer reads stale font-path bytes.
//   H_ALIAS — the producer's write landed on a different frame than the
//             consumer reads (PTE updated, local TLB not invalidated).  On a
//             single CPU this requires a user-VA PTE swap with no following
//             local `invlpg`; the PTE_CHANGE_RING above already records every
//             such swap for correlation.
//
// `frame_content_is_fontpath` scans a freshly-selected physical frame for the
// "/fonts" byte run (covers "re/fonts", "share/fonts", a fontconfig cache
// path, etc.).  `fontpath_install_check` is called from each kernel arm that
// publishes a frame into a *writable user* mapping; it fires a loud
// `[W215/FONT-RECYCLE]` line iff the frame still carries that signature at
// the moment of install — i.e. the install path skipped zeroing.  A safe arm
// (one that zeroes before install) never trips it.
//
// Public spec citations: Intel SDM Vol. 3A §4.10.4 (TLB / paging caches);
// POSIX mmap(2) MAP_ANONYMOUS — anonymous mappings are zero-filled on first
// reference.

const PHYS_OFF_FONT: u64 = 0xFFFF_8000_0000_0000;

/// Number of frames that, at user-mapping install time, still carried a
/// font-path signature.  Non-zero ⇒ at least one recycled font-path frame was
/// published into a user mapping via a non-zeroing arm (H_ZERO red-handed).
static FONT_RECYCLE_HITS: AtomicU64 = AtomicU64::new(0);

/// Total number of install-time scans performed (denominator for the hit
/// rate).  Bounds confidence: a high scan count with zero hits is a strong
/// refutation of H_ZERO.
static FONT_RECYCLE_SCANS: AtomicU64 = AtomicU64::new(0);

/// Scan a 4 KiB physical frame for the byte run "/fonts".  Returns the offset
/// of the match (so the caller can report where in the frame the stale path
/// sits) or `None`.  Read-only access through the higher-half identity map;
/// safe from the PFH and any lock context.
#[inline]
pub fn frame_content_is_fontpath(phys: u64) -> Option<usize> {
    if phys == 0 { return None; }
    const NEEDLE: &[u8; 6] = b"/fonts";
    // SAFETY: `phys` is a frame the caller just obtained from the PMM; the
    // higher-half identity map covers all of physical RAM, so the 4 KiB read
    // is in-bounds.  Read-only.
    let base = (PHYS_OFF_FONT + phys) as *const u8;
    let page = unsafe { core::slice::from_raw_parts(base, 4096) };
    // Simple windowed scan; 4 KiB × 6-byte needle is cheap and only runs on
    // the (rare) recycle paths that opt in to the check.
    let n = page.len();
    let mut i = 0usize;
    while i + NEEDLE.len() <= n {
        if &page[i..i + NEEDLE.len()] == NEEDLE {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Site identifiers for `fontpath_install_check`, so a fire names the exact
/// kernel arm that published the un-zeroed frame.
pub const FONT_SITE_ANON_PREZERO: u8   = 1; // idt.rs anon arm, BEFORE zero-fill
pub const FONT_SITE_RAW_MAP_PAGE: u8   = 2; // a raw map_page_in user install

/// Called from a kernel arm that is about to publish `phys` into a writable
/// user mapping at `install_va`.  If the frame still carries a font-path
/// signature, emit `[W215/FONT-RECYCLE]` with the FREE→install chain.
///
/// `pre_zero` distinguishes the two call shapes:
///   - `pre_zero = true`  — called BEFORE the arm's own zero-fill (anon arm).
///     A hit here is *informational*: it proves a recycled font frame reached
///     the anon path, but the following zero-fill neutralises it.  Counts the
///     scan, emits a `kind=neutralised` line for the first few.
///   - `pre_zero = false` — called from a NON-zeroing install arm.  A hit here
///     is the H_ZERO smoking gun: the stale font bytes survive into the user
///     mapping.  Emits `kind=LIVE` loudly and bumps `FONT_RECYCLE_HITS`.
pub fn fontpath_install_check(phys: u64, install_va: u64, install_rip: u64, site: u8, pre_zero: bool) {
    FONT_RECYCLE_SCANS.fetch_add(1, Ordering::Relaxed);
    let off = match frame_content_is_fontpath(phys) {
        Some(o) => o,
        None => return,
    };
    let (free_tick, free_rip) = free_shadow_lookup(phys).unwrap_or((0, 0));
    if pre_zero {
        // Informational: neutralised by the arm's own zero-fill.
        let n = FONT_RECYCLE_SCANS.load(Ordering::Relaxed);
        if n <= 32 || n % 4096 == 0 {
            crate::serial_println!(
                "[W215/FONT-RECYCLE] kind=neutralised site={} phys={:#x} \
                 fontpath_off={:#x} install_va={:#x} install_rip={:#x} \
                 free_tick={} free_rip={:#x}",
                site, phys, off, install_va, install_rip,
                free_tick, free_rip,
            );
        }
    } else {
        let hits = FONT_RECYCLE_HITS.fetch_add(1, Ordering::Relaxed) + 1;
        crate::serial_println!(
            "[W215/FONT-RECYCLE] kind=LIVE site={} phys={:#x} \
             fontpath_off={:#x} install_va={:#x} install_rip={:#x} \
             free_tick={} free_rip={:#x} hits={}",
            site, phys, off, install_va, install_rip,
            free_tick, free_rip, hits,
        );
    }
}

/// Counters for kdb introspection / harness assertion.
pub fn font_recycle_hits() -> u64 { FONT_RECYCLE_HITS.load(Ordering::Relaxed) }
pub fn font_recycle_scans() -> u64 { FONT_RECYCLE_SCANS.load(Ordering::Relaxed) }
