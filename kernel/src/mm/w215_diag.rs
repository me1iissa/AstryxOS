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

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

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
/// 256 MiB` of physical address space without hash collisions; with the
/// `pfn % FREE_SHADOW_SIZE` direct addressing, frames spaced by a multiple
/// of 256 MiB will alias.  In a 4 GiB physical RAM configuration the
/// collision rate is ≤ 16-to-1 — adequate for a diagnostic.
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
    // H1 catch (2026-06-19): feed the anonymous-heap-band two-frame-alias
    // detector.  This is independent of the PTE-change ring window below — an
    // install/unmap in the band is recorded even though the band is a strict
    // subset of the ring window — so it is driven from the same callers (all
    // four leaf-PTE primitives) with no extra call-site edits.  MAP/WRITE
    // events that publish a present leaf PTE arm H1a + H1b; UNMAP/BULK_UNMAP
    // clear them.  WRITE here covers the CoW in-place bit-flip and NX fixup,
    // which keep the same frame, so the `prev_phys != new_phys` guard inside
    // `band_install_record` makes those a no-op (same frame ⇒ not an alias).
    if in_band(va) {
        match kind {
            // A MAP/WRITE/FORK_CLONE event with a ZERO new_phys is a PTE
            // *clear*, not an install (e.g. `write_pte(cr3, page, 0)` on the
            // madvise(MADV_DONTNEED) path) — it tears the mapping down.  Treat
            // it as an unmap so the slot is disarmed; otherwise the subsequent
            // re-fault re-install at the same VA would false-fire as a
            // double-install (the original frame having been legitimately
            // dropped in between).  Only a MAP/WRITE that publishes a non-zero
            // frame is a real install.
            PTE_KIND_MAP | PTE_KIND_WRITE | PTE_KIND_FORK_CLONE => {
                if new_phys & !0xFFFu64 == 0 {
                    band_unmap_record(va);
                } else {
                    band_install_record(va, new_phys, old_phys, caller_rip, cr3);
                }
            }
            PTE_KIND_UNMAP | PTE_KIND_BULK_UNMAP => {
                band_unmap_record(va);
            }
            _ => {}
        }
    }

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

/// Read alloc-shadow counters for kdb introspection.
pub fn alloc_shadow_recorded_count() -> u64 {
    ALLOC_SHADOW_RECORDED.load(Ordering::Relaxed)
}
pub fn alloc_shadow_displaced_count() -> u64 {
    ALLOC_SHADOW_DISPLACED.load(Ordering::Relaxed)
}

// ── H1 catch (2026-06-19): two-frame alias / freed-under-live-mapping ────────
//
// Pass-1 refuted the munmap-teardown reuse window (the find_free_range
// present-PTE catch fired 0× while corruption persisted).  The remaining
// strongest hypothesis (H1) is a two-frame alias: page tables and refcounts
// stay internally consistent, but a single anonymous-heap VA-page ends up
// associated with TWO distinct physical frames (concurrent double-install on a
// shared address space), and/or a CPU keeps a STALE TLB entry for a frame that
// has already been freed and reused as a mallocng heap group.  This is the same
// class as the prior W215 roots that were caught by physical-provenance autopsy
// (the shared-CR3 anonymous demand-fault double-install and the copy-on-write
// double-install), where the loser CPU's local invalidation fired before the
// winner overwrote the leaf PTE, leaving one VA backed by two frames.
//
// ## Why this catch is correct where the present-PTE catch was blind
//
// The present-PTE catch only saw a VMA-free range that still had a live PTE.
// It could not see a VA whose PTE is perfectly correct but was, for a window,
// pointed at a *different* frame by a racing installer, nor a frame freed while
// a VA-page record still names it as resident.  This catch observes the leaf
// PTE *history* per VA-page directly: every install and every unmap in the
// anonymous-heap band funnels through `pte_change_record` / the unmap recorders
// already wired into all four leaf-PTE primitives, so no call-site edits are
// needed.  Two structurally-distinct fires:
//
//   * **[W215/DOUBLE-INSTALL] (H1a)** — a band VA-page is (re)installed with a
//     *different non-zero* physical frame while the previous install is still
//     live (no intervening unmap recorded for that VA).  That is one VA, two
//     frames: the smoking gun for the concurrent double-install class.  Both
//     physical frames, both installer return-addresses, and both installing
//     CPUs are logged so the racing install paths can be named.
//
//   * **[W215/STALE-TLB] (H1b)** — `pmm::free_page` is about to return a frame
//     to the allocator while this catch still records that frame as the live
//     resident of a band VA-page with NO intervening unmap.  A remote CPU may
//     still hold the old translation, so reusing the frame as a heap group is a
//     use-after-free behind a stale TLB entry.  The VA, the installer
//     return-address, and the free return-address are logged.
//
// ## Structures (non-displacing, anonymous-heap band only)
//
// The existing alloc/free shadows are ~68 % displaced under the Firefox-musl
// anonymous-mmap churn, so their per-phys verdict is not authoritative.  This
// catch therefore uses TWO direct-addressed tables scoped to the band, each
// sized to the band's page count, with an explicit displacement counter so a
// non-zero alias rate is visible rather than silent:
//
//   * `BAND_VA_MAP[(va>>12) & MASK]` — keyed by band VA-page; answers
//     "what frame, installed by which RIP/CPU, is live at this VA?"  Drives
//     H1a (compare-on-install) and is set CLEARED on unmap.
//   * `BAND_PHYS_MAP[(phys>>12) & MASK]` — keyed by frame; answers in O(1) at
//     free time "is this frame still recorded as the live resident of a band
//     VA with no intervening unmap?"  Drives H1b.
//
// Per Intel SDM Vol. 3A §4.10.4.3 ("Optional Invalidation") and §4.10.5
// (paging-structure caches must be made coherent before a frame is repurposed),
// a single linear address must resolve to exactly one frame across all logical
// processors, and a frame must not be recycled while any processor can still
// translate a linear address to it.  Either fire is a direct violation.
//
// Atomic-only, no locks; safe from the page-fault handler, the syscall path,
// and the PMM free path.  Gated under `firefox-test-core`; default builds are
// byte-identical.

/// Anonymous-heap band lower bound (inclusive).  The Firefox-musl mallocng
/// group churn — and the repro's faulting heap chunk — live in this 16 GiB
/// window.  Chosen to exclude the higher shared-library code bands (which are
/// faithful refcounted code, not corruption loci) and the main-thread stack.
pub const BAND_LO: u64 = 0x0000_7eff_0000_0000;
/// Anonymous-heap band upper bound (exclusive).
pub const BAND_HI: u64 = 0x0000_7f00_0000_0000;

/// Direct-map size for both band tables.  The band spans
/// `(BAND_HI - BAND_LO) / 4 KiB = 16 GiB / 4 KiB = 4 Mi` pages, but the live
/// working set of distinct anonymous-heap pages at any instant is far smaller,
/// so a full 1:1 table is unnecessary and — more importantly — impossible: the
/// kernel image (`.text`+`.data`+`.bss`) must fit in `[0x10_0000, 0x100_0000)`
/// (the BootInfo struct lives at the 16 MiB physical mark, see
/// `main.rs::_start`), so a 10 MiB-per-table `.bss` would push `.bss` over the
/// BootInfo and zero its magic at load.
///
/// 32 Ki slots keeps each table at `32 Ki × 40 B = 1.25 MiB` (2.5 MiB total),
/// well within the budget.  Detection fidelity is preserved:
///   * H1a (double-install) is *exact* regardless of table size — the two
///     racing installs target the SAME VA, which always hashes to the SAME
///     slot, and the race window is microseconds, far too short for an
///     unrelated VA to evict the record between the two installs.
///   * H1b (freed-under-live-mapping) needs the phys record to survive from
///     install to free; 32 Ki slots cover `32 Ki × 4 KiB = 128 MiB` of
///     physical address space collision-free, and the FF anonymous working set
///     churns in the low few hundred MiB (≤ 4:1 aliasing in this config).
/// Both tables expose a displacement counter so any alias pressure is visible
/// rather than producing a false verdict.  Gated on `firefox-test-core` so
/// default builds are byte-identical.
const BAND_MAP_SIZE: usize = 32_768;
const BAND_MAP_MASK: usize = BAND_MAP_SIZE - 1;

/// Slot lifecycle state, stored in the low byte of `meta`.
const BAND_STATE_INSTALLED: u64 = 1;
const BAND_STATE_CLEARED: u64   = 2;

#[inline]
pub fn in_band(va: u64) -> bool {
    va >= BAND_LO && va < BAND_HI
}

// ── VA-keyed table (drives H1a) ─────────────────────────────────────────────

#[repr(C)]
struct BandVaEntry {
    /// Band VA-page (4 KiB-aligned).  `0` = never written.
    va: AtomicU64,
    /// Frame currently recorded live at this VA-page (`0` if cleared).
    phys: AtomicU64,
    /// Return-address of the install that recorded `phys`.
    install_rip: AtomicU64,
    /// Tick of the recorded install.
    tick: AtomicU64,
    /// Packed: [63:16] cr3 page-frame number (cr3 >> 12), [15:8] cpu,
    /// [7:0] state (BAND_STATE_*).  The cr3 is part of the slot identity: a
    /// double-install is only a real two-frame alias when BOTH installs are in
    /// the SAME address space.  Two different CR3s (e.g. a fork parent and
    /// child, or two unrelated processes) legitimately map the same VA to
    /// different frames; conflating them would be a false positive.
    meta: AtomicU64,
}

impl BandVaEntry {
    const fn new() -> Self {
        Self {
            va: AtomicU64::new(0),
            phys: AtomicU64::new(0),
            install_rip: AtomicU64::new(0),
            tick: AtomicU64::new(0),
            meta: AtomicU64::new(0),
        }
    }
}

struct BandVaMap {
    slots: [BandVaEntry; BAND_MAP_SIZE],
}

impl BandVaMap {
    const fn new() -> Self {
        const E: BandVaEntry = BandVaEntry::new();
        Self { slots: [E; BAND_MAP_SIZE] }
    }
}

static BAND_VA_MAP: BandVaMap = BandVaMap::new();

// ── phys-keyed table (drives H1b) ───────────────────────────────────────────

#[repr(C)]
struct BandPhysEntry {
    /// Frame (4 KiB-aligned).  `0` = never written.
    phys: AtomicU64,
    /// Band VA-page this frame was installed at.
    va: AtomicU64,
    /// Return-address of the install.
    install_rip: AtomicU64,
    /// Tick of the install.
    tick: AtomicU64,
    /// Packed: [15:8] cpu, [7:0] state (BAND_STATE_*).
    meta: AtomicU64,
}

impl BandPhysEntry {
    const fn new() -> Self {
        Self {
            phys: AtomicU64::new(0),
            va: AtomicU64::new(0),
            install_rip: AtomicU64::new(0),
            tick: AtomicU64::new(0),
            meta: AtomicU64::new(0),
        }
    }
}

struct BandPhysMap {
    slots: [BandPhysEntry; BAND_MAP_SIZE],
}

impl BandPhysMap {
    const fn new() -> Self {
        const E: BandPhysEntry = BandPhysEntry::new();
        Self { slots: [E; BAND_MAP_SIZE] }
    }
}

static BAND_PHYS_MAP: BandPhysMap = BandPhysMap::new();

// ── Counters (kdb-readable) ─────────────────────────────────────────────────

/// Number of [W215/DOUBLE-INSTALL] catches (H1a).  Non-zero = caught the
/// two-frame alias at install.
static BAND_DOUBLE_INSTALL: AtomicU64 = AtomicU64::new(0);
/// Number of [W215/STALE-TLB] catches (H1b).  Non-zero = caught a frame freed
/// while still recorded live at a band VA.
static BAND_STALE_TLB: AtomicU64 = AtomicU64::new(0);
/// Total band install events recorded.
static BAND_INSTALLS: AtomicU64 = AtomicU64::new(0);
/// Total band unmap events recorded.
static BAND_UNMAPS: AtomicU64 = AtomicU64::new(0);
/// VA-table slot displacements (a different VA-page aliased the same slot).
static BAND_VA_DISPLACED: AtomicU64 = AtomicU64::new(0);
/// phys-table slot displacements.
static BAND_PHYS_DISPLACED: AtomicU64 = AtomicU64::new(0);

#[inline]
fn band_va_slot(va: u64) -> &'static BandVaEntry {
    let pfn = (va >> 12) as usize;
    &BAND_VA_MAP.slots[pfn & BAND_MAP_MASK]
}

#[inline]
fn band_phys_slot(phys: u64) -> &'static BandPhysEntry {
    let pfn = (phys >> 12) as usize;
    &BAND_PHYS_MAP.slots[pfn & BAND_MAP_MASK]
}

#[inline]
fn pack_band_meta(cr3: u64, cpu: u8, state: u64) -> u64 {
    // [63:16] cr3 page-frame number (cr3 >> 12), [15:8] cpu, [7:0] state.
    ((cr3 >> 12) << 16) | ((cpu as u64) << 8) | (state & 0xFF)
}

#[inline]
fn meta_cr3_pfn(meta: u64) -> u64 {
    meta >> 16
}

/// Record a leaf-PTE install for a band VA-page.  Called from
/// `pte_change_record` for `PTE_KIND_MAP` / `PTE_KIND_WRITE` events whose VA is
/// in the anonymous-heap band.  `new_phys` is the just-installed frame;
/// `old_phys` is the frame the installer believed it was replacing (`0` if the
/// installer thought the slot was empty — the `map_page_in_if_absent` arm).
///
/// **H1a fire**: a genuine two-frame alias is when the VA-table slot already
/// holds THIS va_page with a DIFFERENT non-zero frame (state INSTALLED, same
/// CR3) AND the installer did NOT replace that recorded frame — i.e.
/// `old_phys != prev_phys`.  A legitimate in-place frame replacement (a CoW
/// break via `map_page_in_cow_if_unchanged`, or `map_page_in`/`write_pte` over
/// a known prior frame) always passes `old_phys == <the frame it replaced>`,
/// which equals the recorded `prev_phys` — that is a clean handoff (the old
/// frame's reference is dropped, one frame remains), NOT an alias, so it must
/// NOT fire.  The dangerous case is `old_phys == 0 && prev_phys != 0`: the
/// installer (the `map_page_in_if_absent` not-present arm) believed the page
/// was unmapped and installed a fresh frame while a different frame was still
/// live at that VA — one VA, two frames, the W215 smoking gun.
#[inline]
pub fn band_install_record(va: u64, new_phys: u64, old_phys: u64, install_rip: u64, cr3: u64) {
    if new_phys == 0 || !in_band(va) {
        return;
    }
    let va_page = va & !0xFFFu64;
    let new_phys = new_phys & !0xFFFu64;
    let old_phys = old_phys & !0xFFFu64;
    let cpu = crate::arch::x86_64::apic::cpu_index() as u8;
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    BAND_INSTALLS.fetch_add(1, Ordering::Relaxed);

    // ── VA table: H1a compare-on-install ────────────────────────────────────
    let vslot = band_va_slot(va_page);
    let prev_va = vslot.va.load(Ordering::Relaxed);
    if prev_va != 0 && prev_va != va_page {
        // A different VA aliases this slot — record displacement, then take it.
        BAND_VA_DISPLACED.fetch_add(1, Ordering::Relaxed);
    } else if prev_va == va_page {
        let prev_phys = vslot.phys.load(Ordering::Relaxed);
        let prev_meta = vslot.meta.load(Ordering::Relaxed);
        let prev_state = prev_meta & 0xFF;
        let prev_cr3_pfn = meta_cr3_pfn(prev_meta);
        if prev_phys != 0
            && prev_phys != new_phys
            && prev_state == BAND_STATE_INSTALLED
            // SAME address space only — a different CR3 mapping the same VA to a
            // different frame is legitimate (fork parent/child, two processes).
            && prev_cr3_pfn == (cr3 >> 12)
            // NOT an in-place replacement: a clean handoff replaces the exact
            // frame we recorded (old_phys == prev_phys).  Only an installer
            // that thought the slot was empty (old_phys == 0) while a different
            // frame was still live is a true two-frame alias.
            && old_phys != prev_phys
        {
            // SMOKING GUN: same CR3, same VA, two distinct frames, no
            // intervening unmap, and the second installer did NOT replace the
            // first frame.
            let n = BAND_DOUBLE_INSTALL.fetch_add(1, Ordering::Relaxed) + 1;
            let prev_rip = vslot.install_rip.load(Ordering::Relaxed);
            let prev_cpu = ((prev_meta >> 8) & 0xFF) as u8;
            let prev_tick = vslot.tick.load(Ordering::Relaxed);
            // Log first 64 then every 64th — the early fires are closest to the
            // first corruption.
            if n <= 64 || n % 64 == 0 {
                crate::serial_println!(
                    "[W215/DOUBLE-INSTALL] #{} va={:#x} cr3={:#x} \
                     frame_A=(phys={:#x} install_rip={:#x} cpu={} tick={}) \
                     frame_B=(phys={:#x} install_rip={:#x} cpu={} tick={} old_phys={:#x}) \
                     age_ticks={}",
                    n, va_page, cr3,
                    prev_phys, prev_rip, prev_cpu, prev_tick,
                    new_phys, install_rip, cpu, tick, old_phys,
                    tick.saturating_sub(prev_tick),
                );
                // Cross-reference the shadows for both frames so the alloc/free
                // provenance of each aliased frame is on the record.
                dump_band_frame_prov("A", prev_phys);
                dump_band_frame_prov("B", new_phys);
            }
        }
    }
    // Adopt the new frame as the live record for this VA.
    vslot.va.store(va_page, Ordering::Relaxed);
    vslot.phys.store(new_phys, Ordering::Relaxed);
    vslot.install_rip.store(install_rip, Ordering::Relaxed);
    vslot.tick.store(tick, Ordering::Relaxed);
    vslot.meta.store(pack_band_meta(cr3, cpu, BAND_STATE_INSTALLED), Ordering::Relaxed);

    // ── phys table: arm H1b ─────────────────────────────────────────────────
    let pslot = band_phys_slot(new_phys);
    let prev_pphys = pslot.phys.load(Ordering::Relaxed);
    if prev_pphys != 0 && prev_pphys != new_phys {
        BAND_PHYS_DISPLACED.fetch_add(1, Ordering::Relaxed);
    }
    pslot.phys.store(new_phys, Ordering::Relaxed);
    pslot.va.store(va_page, Ordering::Relaxed);
    pslot.install_rip.store(install_rip, Ordering::Relaxed);
    pslot.tick.store(tick, Ordering::Relaxed);
    pslot.meta.store(pack_band_meta(cr3, cpu, BAND_STATE_INSTALLED), Ordering::Relaxed);
}

/// Record a leaf-PTE unmap for a band VA-page.  Called from `pte_change_record`
/// for `PTE_KIND_UNMAP` / `PTE_KIND_BULK_UNMAP` events whose VA is in the band.
/// Sets both tables' state to CLEARED for the frame that was live at this VA, so
/// a legitimate unmap-then-remap is NOT flagged as a double-install and the
/// frame's subsequent free is NOT flagged as freed-under-live-mapping.
#[inline]
pub fn band_unmap_record(va: u64) {
    if !in_band(va) {
        return;
    }
    let va_page = va & !0xFFFu64;
    BAND_UNMAPS.fetch_add(1, Ordering::Relaxed);

    let vslot = band_va_slot(va_page);
    if vslot.va.load(Ordering::Relaxed) == va_page {
        let live_phys = vslot.phys.load(Ordering::Relaxed);
        // Preserve cr3/cpu, flip state → CLEARED.
        let m = vslot.meta.load(Ordering::Relaxed);
        vslot.meta.store((m & !0xFFu64) | BAND_STATE_CLEARED, Ordering::Relaxed);
        // Disarm H1b for the frame that was live here — its free is now legit.
        if live_phys != 0 {
            let pslot = band_phys_slot(live_phys);
            if pslot.phys.load(Ordering::Relaxed) == live_phys
                && pslot.va.load(Ordering::Relaxed) == va_page
            {
                let pm = pslot.meta.load(Ordering::Relaxed);
                pslot.meta.store((pm & !0xFFu64) | BAND_STATE_CLEARED, Ordering::Relaxed);
            }
        }
    }
}

/// H1b check: called from `pmm::free_page` immediately before the frame returns
/// to the allocator pool.  If `phys` is still recorded INSTALLED for a band VA
/// (no intervening unmap), the frame is being freed out from under a live
/// mapping — a remote CPU may still translate that VA to this frame through a
/// stale TLB entry.  Emit `[W215/STALE-TLB]`.
#[inline]
pub fn band_check_free(phys: u64, free_rip: u64) {
    let phys = phys & !0xFFFu64;
    if phys == 0 {
        return;
    }
    let pslot = band_phys_slot(phys);
    if pslot.phys.load(Ordering::Relaxed) != phys {
        return;
    }
    let state = pslot.meta.load(Ordering::Relaxed) & 0xFF;
    if state != BAND_STATE_INSTALLED {
        return;
    }
    // Confirm the VA-table still agrees this frame is the live resident — guards
    // against a phys-slot alias from a different frame that shared the slot.
    let va = pslot.va.load(Ordering::Relaxed);
    let vslot = band_va_slot(va);
    if vslot.va.load(Ordering::Relaxed) != va
        || vslot.phys.load(Ordering::Relaxed) != phys
        || (vslot.meta.load(Ordering::Relaxed) & 0xFF) != BAND_STATE_INSTALLED
    {
        return;
    }

    let n = BAND_STALE_TLB.fetch_add(1, Ordering::Relaxed) + 1;
    let install_rip = pslot.install_rip.load(Ordering::Relaxed);
    let install_tick = pslot.tick.load(Ordering::Relaxed);
    let install_cpu = ((pslot.meta.load(Ordering::Relaxed) >> 8) & 0xFF) as u8;
    let now = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let here_cpu = crate::arch::x86_64::apic::cpu_index() as u8;
    if n <= 64 || n % 64 == 0 {
        crate::serial_println!(
            "[W215/STALE-TLB] #{} freeing phys={:#x} STILL INSTALLED at va={:#x} \
             install_rip={:#x} install_cpu={} install_tick={} \
             free_rip={:#x} free_cpu={} age_ticks={}",
            n, phys, va, install_rip, install_cpu, install_tick,
            free_rip, here_cpu, now.saturating_sub(install_tick),
        );
        dump_band_frame_prov("freed", phys);
    }
    // Mark cleared so a re-free of the same frame in this run does not re-fire.
    let pm = pslot.meta.load(Ordering::Relaxed);
    pslot.meta.store((pm & !0xFFu64) | BAND_STATE_CLEARED, Ordering::Relaxed);
}

/// Emit the alloc/free shadow provenance for a band frame as a `[W215/BAND-PROV]`
/// line.  Best-effort: the shadows are ~68 % displaced under the FF workload, so
/// a `hit=0` is not authoritative, but a hit names the upstream alloc/free RIP.
fn dump_band_frame_prov(tag: &str, phys: u64) {
    match alloc_shadow_lookup(phys) {
        Some((t, rip)) => crate::serial_println!(
            "[W215/BAND-PROV] {} phys={:#x} last_alloc_tick={} alloc_rip={:#x}",
            tag, phys, t, rip,
        ),
        None => crate::serial_println!(
            "[W215/BAND-PROV] {} phys={:#x} last_alloc=none", tag, phys,
        ),
    }
    if let Some((t, rip)) = free_shadow_lookup(phys) {
        crate::serial_println!(
            "[W215/BAND-PROV] {} phys={:#x} last_free_tick={} free_rip={:#x}",
            tag, phys, t, rip,
        );
    }
}

/// Read H1-catch counters for kdb introspection.
pub fn band_counts() -> [(&'static str, u64); 6] {
    [
        ("double_install", BAND_DOUBLE_INSTALL.load(Ordering::Relaxed)),
        ("stale_tlb",      BAND_STALE_TLB.load(Ordering::Relaxed)),
        ("installs",       BAND_INSTALLS.load(Ordering::Relaxed)),
        ("unmaps",         BAND_UNMAPS.load(Ordering::Relaxed)),
        ("va_displaced",   BAND_VA_DISPLACED.load(Ordering::Relaxed)),
        ("phys_displaced", BAND_PHYS_DISPLACED.load(Ordering::Relaxed)),
    ]
}

pub fn band_double_install_count() -> u64 { BAND_DOUBLE_INSTALL.load(Ordering::Relaxed) }
pub fn band_stale_tlb_count() -> u64 { BAND_STALE_TLB.load(Ordering::Relaxed) }

// ── Cache-catch (2026-06-19): non-displacing per-phys page-cache provenance ──
//
// The retained anon catches (BAND_VA_MAP / BAND_PHYS_MAP above) cover the
// anonymous-heap locus.  This catch covers the STRUCTURALLY-ORTHOGONAL
// file-backed page-cache locus — the documented W215 bucket-A REFDEC class:
//
//   [FAULT/CACHE-KEY] bucket=A (same-key in-place corruption)
//     rip_phys=0x17801000 key=(mount=4,inode=0x129,off=0x25000)
//
// A cache frame whose 16-bit content changed while its (mount,inode,offset)
// key is UNCHANGED.  Two mechanisms produce that fingerprint:
//
//   * **same-key changed-content (CACHE-CLOBBER, H-cache-a)** — a writer
//     mutates a cache-resident frame in place after `cache::insert` validated
//     its content against the source-file bytes, while the frame is still the
//     live resident of the SAME (mount,inode,offset) key.  Under POSIX read(2)
//     + the install-path contract there is no legitimate kernel writer in that
//     window for a read-only code page; any change is the corruption.
//
//   * **freed-cache-frame reused-while-old-ref-writes (CACHE-REFDEC,
//     H-cache-b)** — the cache's own reference is dropped (REFDEC at evict /
//     truncate / collision), the frame's refcount reaches 0 and it is freed
//     and recycled for a NEW key (or a new anon allocation), yet a stale
//     reference still believes it owns the OLD key and writes the OLD content
//     into the now-foreign frame — or, symmetrically, a stale writer of the
//     OLD content lands on the frame after it was handed to a NEW cache key.
//
// ## Why a dedicated NON-DISPLACING table (not the existing shadows)
//
// The existing ALLOC_SHADOW / FREE_SHADOW are ~68 % displaced under the FF
// anonymous-mmap churn (`alloc_shadow_displaced_count`), so their per-phys
// verdict is NOT authoritative — a `hit=0` there means "overwritten by an
// aliasing pfn", not "no event".  This catch therefore keeps a DEDICATED
// direct-addressed table whose working set is the file-backed cache cluster
// (which churns far less than the anon heap), plus an explicit displacement
// counter so any alias pressure is visible rather than silent.  A future
// 0-fire while corruption reproduces is then a true REFUTATION of this
// mechanism, not a dead/overwritten catch — provided `CACHE_PROV_VALIDATED`
// is non-zero (the install/validate hook was reached on real cache traffic).
//
// ## Fingerprint
//
// Per-frame we record a 64-bit content fingerprint (FNV-1a over the first 256
// bytes of the frame, sampled through the kernel higher-half identity map at
// insert/validate time).  256 bytes covers the ELF entry stub + the first few
// code lines of a libxul page, which is where the observed bucket-A 16-bit
// flips landed; FNV-1a detects single-bit changes.  At fault bucket-A time the
// fingerprint is recomputed from the live frame and compared: a mismatch with
// the SAME key recorded is the smoking gun, and the recorded last-writer
// RIP/CPU/tick (captured by the per-write `cache_prov_write` hook) names the
// writer.
//
// Per Intel SDM Vol. 3A §4.10.5 (paging-structure / page-level coherence) and
// POSIX read(2) + mmap(2) MAP_SHARED visibility semantics, a read-only
// file-backed frame validated at insert must keep its content for as long as
// it is the live resident of its key across all logical processors.  Either
// fire is a direct violation.
//
// Atomic-only, no locks; safe from the page-fault handler, the syscall path,
// the cache lock interior, and the PMM free path.  Gated under
// `firefox-test-core`; default builds are byte-identical.

/// Slot count for the cache-provenance table.  `256 Ki slots × 48 B = 12 MiB`,
/// HEAP-allocated (not BSS — see [`cache_prov_init`]), gated on
/// `firefox-test-core`.
///
/// ## Band-scoped, NON-DISPLACING addressing (the displacement fix)
///
/// The previous revision indexed by `pfn & CACHE_PROV_MASK`, a single-way
/// global direct map.  That aliases frames spaced by `64 Ki × 4 KiB = 256 MiB`,
/// and the cold-boot libxul cache prepopulate touches frames across the whole
/// usable-RAM extent — so an unrelated install 256 MiB away from a corrupting
/// frame would EVICT that frame's recorded provenance (its `last_write_rip`)
/// before the bucket-A fault could probe it.  Measured displacement of the
/// corrupting cache band was ~62 %: the very slot that named the writer was
/// gone by fault time, forcing the `probe=miss` early-return.
///
/// The fix mirrors the working anonymous-heap `BAND_PHYS_MAP`: index by the
/// frame's offset WITHIN a phys band that the table covers 1:1, so no two
/// frames in the band ever alias the same slot.  `CACHE_PROV_SIZE = 256 Ki`
/// slots cover exactly `256 Ki × 4 KiB = 1024 MiB` of contiguous physical
/// address space collision-free (12 MiB heap table, `firefox-test-core`-gated),
/// addressed band-relatively.
///
/// The band `[CACHE_BAND_LO, CACHE_BAND_HI)` is positioned over the live
/// file-backed page-cache cluster where the corrupting rootfs (ext2 mount=4)
/// code/data frames land.  The corrupting frame's physical address drifts
/// per boot far more widely than first assumed: an early observation put it
/// near ~376 MiB, but a confirmed bucket-A reproduction landed the corrupting
/// `inode=0x12d off=0x186000` frame at phys 0x2c802000 (~712 MiB) — 200 MiB
/// ABOVE a 512 MiB ceiling, so the probe returned `out_of_band` and the
/// writer went unnamed.  The drift tracks the usable-RAM floor, so the band
/// must cover the whole region the buddy allocator hands file-backed
/// page-cache frames out of.
///
/// The band is therefore widened to `[256 MiB, 1280 MiB)` = 1024 MiB at 1:1
/// (`CACHE_PROV_SIZE = 256 Ki` slots, 12 MiB HEAP table — see
/// [`cache_prov_init`] for why it is not a BSS static — `firefox-test-core`-
/// gated), bracketing every corrupting frame observed so far (376 MiB and
/// 712 MiB) with >560 MiB of headroom above.  Per Intel SDM Vol. 3A §4.10.5
/// (page-level coherence) a validated read-only file-backed frame must keep
/// its content while it is the live resident of its key; a band-scoped 1:1
/// record lets us name the writer that violates this without alias eviction.
const CACHE_PROV_SIZE: usize = 262144; // 256 Ki slots × 48 B = 12 MiB heap table
const CACHE_PROV_MASK: usize = CACHE_PROV_SIZE - 1;

/// File-backed page-cache provenance band, lower bound (inclusive), 256 MiB.
/// `[CACHE_BAND_LO, CACHE_BAND_HI)` spans exactly `CACHE_PROV_SIZE` pages so a
/// band-relative index `(phys - CACHE_BAND_LO) >> 12` is collision-free across
/// the band.
pub const CACHE_BAND_LO: u64 = 0x1000_0000; // 256 MiB
/// File-backed page-cache provenance band, upper bound (exclusive), 1280 MiB.
pub const CACHE_BAND_HI: u64 = CACHE_BAND_LO + (CACHE_PROV_SIZE as u64) * 4096; // 1280 MiB


/// PHYS → kernel-higher-half identity-map offset.  Same constant as
/// `mm/pmm.rs` / `mm/cache.rs`; the fingerprint sampler reads cache frames
/// through this map.  Per Intel SDM Vol. 3A §4.10.5 the higher-half map covers
/// every PMM frame.
const CACHE_PROV_PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Slot lifecycle.  INSTALLED = a cache::insert validated this frame for its
/// key and the cache holds a reference.  RECLAIMED = the cache's reference was
/// dropped to zero and the frame was freed/recycled (REFDEC class arm).
const CACHE_STATE_EMPTY: u8     = 0;
const CACHE_STATE_INSTALLED: u8 = 1;
const CACHE_STATE_RECLAIMED: u8 = 2;

#[repr(C)]
struct CacheProvEntry {
    /// Frame (4 KiB-aligned).  `0` = never written.
    phys: AtomicU64,
    /// Cache key packed: `(mount_low8 << 56) | (inode_low24 << 32) |
    /// (file_page_index_low32)`.  Identifies the (mount,inode,offset) the
    /// frame was last INSTALLED for.
    key: AtomicU64,
    /// FNV-1a fingerprint of the first 256 bytes at insert/validate time.
    fp: AtomicU64,
    /// Last writer return-address recorded by `cache_prov_write` while the
    /// frame was INSTALLED for its key.  `0` if no in-window write recorded.
    last_write_rip: AtomicU64,
    /// Tick of the most recent install/validate.
    tick: AtomicU64,
    /// Packed: [31:24] state (CACHE_STATE_*), [23:16] install_cpu,
    /// [15:8] last_write_cpu, [7:0] reclaim generation (saturating).
    meta: AtomicU64,
}

impl CacheProvEntry {
    const fn new() -> Self {
        Self {
            phys: AtomicU64::new(0),
            key: AtomicU64::new(0),
            fp: AtomicU64::new(0),
            last_write_rip: AtomicU64::new(0),
            tick: AtomicU64::new(0),
            meta: AtomicU64::new(0),
        }
    }
}

/// Heap-backed slot array, installed once by [`cache_prov_init`] after the
/// kernel heap is up.
///
/// The table is NOT a `static [CacheProvEntry; CACHE_PROV_SIZE]` BSS array.
/// At `CACHE_PROV_SIZE = 256 Ki × 48 B` it would be a 12 MiB `.bss` block,
/// and the kernel image is loaded at physical 1 MiB while the bootloader
/// hands off `BootInfo` at `BOOT_INFO_PHYS_BASE = 16 MiB` (`shared/src/lib.rs`).
/// A 12 MiB `.bss` pushes the image end from ~14.6 MiB past 16 MiB, so `_start`
/// BSS zeroing wipes the BootInfo handoff page → `Invalid BootInfo magic`
/// panic at boot (observed empirically; see also `mm/w215_crc.rs`).  Per the
/// System V AMD64 ABI §3.4.1 the loader maps `.bss` immediately after `.data`
/// in the load segment, so a large static is a hard layout constraint.
///
/// Allocating the slots from the 128 MiB kernel heap (`mm/heap.rs`) after
/// `heap::init()` removes the constraint entirely: the image stays small and
/// the table lives in dynamic memory.  `Box::leak` gives a genuine `'static`
/// slice (the table lives for the lifetime of the kernel), so the hot-path
/// `cache_prov_slot` can still return `&'static CacheProvEntry`.
static CACHE_PROV_SLOTS: AtomicPtr<CacheProvEntry> = AtomicPtr::new(core::ptr::null_mut());

/// Number of slots actually installed (0 until [`cache_prov_init`] runs).
/// Read by the selftest/residency walks so they iterate only the live table.
static CACHE_PROV_INSTALLED_LEN: AtomicUsize = AtomicUsize::new(0);

/// Resolve the live heap-backed slot slice, or `None` before init.
#[inline]
fn cache_prov_slots() -> Option<&'static [CacheProvEntry]> {
    let p = CACHE_PROV_SLOTS.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    let len = CACHE_PROV_INSTALLED_LEN.load(Ordering::Acquire);
    if len == 0 {
        return None;
    }
    // SAFETY: `p` was produced by `Box::leak` of a `[CacheProvEntry; len]` in
    // `cache_prov_init` under an Acquire/Release handshake, is never freed, and
    // `len` is the matching element count.  The leaked allocation lives for the
    // lifetime of the kernel, so the `'static` lifetime is sound.
    Some(unsafe { core::slice::from_raw_parts(p, len) })
}

/// Allocate and zero-initialise the page-cache provenance table on the kernel
/// heap.  Idempotent; must be called once after `heap::init()` and before any
/// `cache_prov_install`/`cache_prov_slot` use (the install path no-ops on a
/// `None` slot until this runs).  `firefox-test-core`-gated build only.
pub fn cache_prov_init() {
    use alloc::vec::Vec;
    if !CACHE_PROV_SLOTS.load(Ordering::Acquire).is_null() {
        return; // already initialised
    }
    let mut v: Vec<CacheProvEntry> = Vec::new();
    v.reserve_exact(CACHE_PROV_SIZE);
    for _ in 0..CACHE_PROV_SIZE {
        v.push(CacheProvEntry::new());
    }
    let slice: &'static mut [CacheProvEntry] = Vec::leak(v);
    // Publish length first, then the pointer with Release so any reader that
    // observes a non-null pointer (Acquire) also observes the matching length.
    CACHE_PROV_INSTALLED_LEN.store(slice.len(), Ordering::Release);
    CACHE_PROV_SLOTS.store(slice.as_mut_ptr(), Ordering::Release);
    crate::serial_println!(
        "[W215/CACHE-CATCH] provenance table heap-allocated: {} slots \
         ({} MiB) band=[{:#x},{:#x})",
        CACHE_PROV_SIZE,
        (CACHE_PROV_SIZE * core::mem::size_of::<CacheProvEntry>()) / (1024 * 1024),
        CACHE_BAND_LO, CACHE_BAND_HI,
    );
}

// ── Cache-catch counters (kdb-readable) ─────────────────────────────────────

/// [W215/CACHE-CLOBBER] catches (H-cache-a): a same-key cache frame's content
/// fingerprint changed in place while still INSTALLED for its key.
static CACHE_CLOBBER: AtomicU64 = AtomicU64::new(0);
/// [W215/CACHE-REFDEC] catches (H-cache-b): a write or stale-ref landed on a
/// cache frame after it was reclaimed (refcount→0, freed/recycled) for a new
/// owner.
static CACHE_REFDEC_REUSE: AtomicU64 = AtomicU64::new(0);
/// Total insert/validate records (the LIVE-CATCH witness — a non-zero value
/// proves the install/validate hook is reached on real cache traffic, so a
/// future 0-fire is no-corruption, not a dead catch).
static CACHE_PROV_VALIDATED: AtomicU64 = AtomicU64::new(0);
/// Total in-window write records (the per-write last-writer hook fired).
static CACHE_PROV_WRITES: AtomicU64 = AtomicU64::new(0);
/// Total reclaim records (REFDEC→0 arm).
static CACHE_PROV_RECLAIMS: AtomicU64 = AtomicU64::new(0);
/// Slot displacements (a different frame aliased the same band-scoped slot).
/// With band-relative 1:1 addressing this MUST stay 0 for in-band frames — a
/// non-zero value would mean two distinct in-band frames collided, which is
/// impossible unless the band/size invariant is broken.  Retained as a
/// tripwire on that invariant.
static CACHE_PROV_DISPLACED: AtomicU64 = AtomicU64::new(0);
/// Cache traffic for frames OUTSIDE the provenance band (install/write/reclaim
/// attempts that the band-scoped table intentionally does not record).  These
/// are not the W215 cluster; the counter quantifies how much traffic is
/// out-of-band so a 0-fire in-band can be trusted (in-band `validated` is the
/// authoritative live-catch witness, not this).
static CACHE_PROV_OUT_OF_BAND: AtomicU64 = AtomicU64::new(0);
/// Fault-site bucket-A probes that found a recorded slot with MATCHING
/// fingerprint (no corruption on that frame — the negative control).
static CACHE_PROV_FP_MATCH: AtomicU64 = AtomicU64::new(0);

/// Resolve the band-scoped provenance slot for `phys`.
///
/// Returns `Some(slot)` for in-band frames, indexed by the frame's offset
/// WITHIN the band: `(phys - CACHE_BAND_LO) >> 12`.  Because the band spans
/// exactly `CACHE_PROV_SIZE` pages, two distinct in-band frames never share a
/// slot — the table is non-displacing for the band.  Returns `None` for
/// out-of-band frames so unrelated installs (the cold-boot prepopulate's
/// frames outside the cluster) cannot evict an in-band record.
#[inline]
fn cache_prov_slot(phys: u64) -> Option<&'static CacheProvEntry> {
    let p = phys & !0xFFFu64;
    if p < CACHE_BAND_LO || p >= CACHE_BAND_HI {
        return None;
    }
    let idx = ((p - CACHE_BAND_LO) >> 12) as usize;
    // `idx < CACHE_PROV_SIZE` is guaranteed by the band bounds, but mask for
    // defence in depth against any future band/size mismatch.
    let slots = cache_prov_slots()?;
    slots.get(idx & CACHE_PROV_MASK)
}

/// Pack a cache key (mount, inode, file_offset) into 64 bits.
#[inline]
fn pack_cache_prov_key(mount_idx: usize, inode: u64, file_offset: u64) -> u64 {
    let mount_low = (mount_idx as u64) & 0xFF;
    let inode_low = inode & 0xFF_FFFF;                 // 24 bits
    let page_idx  = (file_offset >> 12) & 0xFFFF_FFFF; // 32-bit page index
    (mount_low << 56) | (inode_low << 32) | page_idx
}

#[inline]
fn cache_prov_pack_meta(state: u8, install_cpu: u8, last_write_cpu: u8, generation: u8) -> u64 {
    ((state as u64) << 24)
        | ((install_cpu as u64) << 16)
        | ((last_write_cpu as u64) << 8)
        | (generation as u64)
}

#[inline]
fn cache_prov_state(meta: u64) -> u8 { ((meta >> 24) & 0xFF) as u8 }
#[inline]
fn cache_prov_generation(meta: u64) -> u8 { (meta & 0xFF) as u8 }

/// FNV-1a over the first `N` bytes of the frame at `PHYS_OFF + phys`.
///
/// SAFETY contract: `phys` must be a live PMM frame (the caller holds a cache
/// reference or is in the fault handler with the frame still mapped); the
/// kernel higher-half identity map covers every PMM frame per Intel SDM
/// Vol. 3A §4.10.5.  Volatile reads prevent the compiler from hoisting the
/// sample across a concurrent install.
#[inline]
fn cache_prov_fingerprint(phys: u64) -> u64 {
    const N: usize = 256;
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME:  u64 = 0x0000_0100_0000_01b3;
    let base = (CACHE_PROV_PHYS_OFF + (phys & !0xFFFu64)) as *const u8;
    let mut h = FNV_OFFSET;
    let mut i = 0usize;
    while i < N {
        let b = unsafe { core::ptr::read_volatile(base.add(i)) };
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    h
}

/// Record a cache install/validate for `phys` ↔ key.  Called from
/// `cache::insert_with_expected` AFTER the frame's content has been validated
/// against the source-file bytes (or the install completed) — i.e. the
/// fingerprint captured here is the AUTHORITATIVE post-install content.
///
/// This is the LIVE-CATCH witness hook: every steady-state cache::insert ticks
/// `CACHE_PROV_VALIDATED`, so `kdb w215-all` confirms the catch is reached on
/// real cache traffic.  A future 0-fire with a non-zero validated count is a
/// true refutation (no corruption), not a dead catch.
#[inline]
pub fn cache_prov_install(phys: u64, mount_idx: usize, inode: u64, file_offset: u64) {
    let phys = phys & !0xFFFu64;
    if phys == 0 { return; }
    let slot = match cache_prov_slot(phys) {
        Some(s) => s,
        None => {
            CACHE_PROV_OUT_OF_BAND.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let prev_phys = slot.phys.load(Ordering::Relaxed);
    if prev_phys != 0 && prev_phys != phys {
        // Band-relative 1:1 addressing makes this impossible for distinct
        // in-band frames; if it ever fires the band/size invariant is broken.
        CACHE_PROV_DISPLACED.fetch_add(1, Ordering::Relaxed);
    }
    let key = pack_cache_prov_key(mount_idx, inode, file_offset);
    let fp = cache_prov_fingerprint(phys);
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let cpu = crate::arch::x86_64::apic::cpu_index() as u8;
    // Preserve the reclaim generation if this is the same frame being
    // re-installed (it climbs across the REFDEC→reuse cycle); reset it to 0
    // for a fresh frame.
    let gen = if prev_phys == phys {
        cache_prov_generation(slot.meta.load(Ordering::Relaxed))
    } else {
        0
    };
    slot.phys.store(phys, Ordering::Relaxed);
    slot.key.store(key, Ordering::Relaxed);
    slot.fp.store(fp, Ordering::Relaxed);
    slot.last_write_rip.store(0, Ordering::Relaxed);
    slot.tick.store(tick, Ordering::Relaxed);
    slot.meta.store(
        cache_prov_pack_meta(CACHE_STATE_INSTALLED, cpu, 0, gen),
        Ordering::Relaxed,
    );
    CACHE_PROV_VALIDATED.fetch_add(1, Ordering::Relaxed);
}

/// Record a reclaim (the cache's reference reached 0 and the frame was
/// freed/recycled for a new owner).  Called from the cache REFDEC sites
/// (`insert` collision, `evict`, `truncate_range`) when `page_ref_dec`
/// returned 0 for a frame this table recorded INSTALLED.  Flips the slot to
/// RECLAIMED and bumps the reclaim generation so a subsequent stale-ref write
/// (`cache_prov_write`) fires H-cache-b.
#[inline]
pub fn cache_prov_reclaim(phys: u64) {
    let phys = phys & !0xFFFu64;
    if phys == 0 { return; }
    let slot = match cache_prov_slot(phys) {
        Some(s) => s,
        None => return,
    };
    if slot.phys.load(Ordering::Relaxed) != phys {
        return;
    }
    let meta = slot.meta.load(Ordering::Relaxed);
    if cache_prov_state(meta) != CACHE_STATE_INSTALLED {
        return;
    }
    let gen = cache_prov_generation(meta);
    let next_gen = if gen == 0xFF { 0xFF } else { gen + 1 };
    let install_cpu = ((meta >> 16) & 0xFF) as u8;
    slot.meta.store(
        cache_prov_pack_meta(CACHE_STATE_RECLAIMED, install_cpu, 0, next_gen),
        Ordering::Relaxed,
    );
    CACHE_PROV_RECLAIMS.fetch_add(1, Ordering::Relaxed);
}

/// Record an in-window write to a cache frame, naming the writer.  Called from
/// the cache write-through path (`cache::update_range`) for each touched
/// cache frame, and is the hook that captures the last-writer RIP for the
/// H-cache-a clobber dump.
///
/// **H-cache-b fire**: if the slot is RECLAIMED (the frame was already freed
/// out from under its old key and recycled), a write that still believes it
/// owns the old cache frame is landing on a foreign frame — the
/// freed-cache-frame-reused-while-old-ref-writes class.  Emit
/// `[W215/CACHE-REFDEC]` with the install/free generation and the writer RIP.
#[inline]
pub fn cache_prov_write(phys: u64, writer_rip: u64) {
    let phys = phys & !0xFFFu64;
    if phys == 0 { return; }
    let slot = match cache_prov_slot(phys) {
        Some(s) => s,
        None => {
            CACHE_PROV_OUT_OF_BAND.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    if slot.phys.load(Ordering::Relaxed) != phys {
        return;
    }
    CACHE_PROV_WRITES.fetch_add(1, Ordering::Relaxed);
    let meta = slot.meta.load(Ordering::Relaxed);
    let cpu = crate::arch::x86_64::apic::cpu_index() as u8;
    let state = cache_prov_state(meta);
    if state == CACHE_STATE_RECLAIMED {
        // The frame was reclaimed (refcount→0, freed/recycled) yet a writer
        // still references it through the old cache key — H-cache-b.
        let n = CACHE_REFDEC_REUSE.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 64 || n % 64 == 0 {
            let key = slot.key.load(Ordering::Relaxed);
            let gen = cache_prov_generation(meta);
            let install_tick = slot.tick.load(Ordering::Relaxed);
            let now = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
            crate::serial_println!(
                "[W215/CACHE-REFDEC] #{} writer landed on RECLAIMED frame \
                 phys={:#x} old_key=(mount={},inode={:#x},pageidx={:#x}) \
                 reclaim_gen={} writer_rip={:#x} writer_cpu={} \
                 age_since_install_ticks={}",
                n, phys,
                (key >> 56) & 0xFF, (key >> 32) & 0xFF_FFFF, key & 0xFFFF_FFFF,
                gen, writer_rip, cpu, now.saturating_sub(install_tick),
            );
            dump_band_frame_prov("cache-refdec", phys);
        }
        return;
    }
    // INSTALLED (or EMPTY) — record this as the last in-window writer so the
    // bucket-A clobber dump can name it.  Refresh the fingerprint so a
    // *legitimate* write-through (POSIX write(2) MAP_SHARED visibility) does
    // not later false-fire as a content change at fault time.
    let last_write_cpu = cpu;
    let install_cpu = ((meta >> 16) & 0xFF) as u8;
    let gen = cache_prov_generation(meta);
    slot.last_write_rip.store(writer_rip, Ordering::Relaxed);
    slot.fp.store(cache_prov_fingerprint(phys), Ordering::Relaxed);
    slot.meta.store(
        cache_prov_pack_meta(state, install_cpu, last_write_cpu, gen),
        Ordering::Relaxed,
    );
}

/// Arm the H-cache-a clobber check at the fault-site bucket-A classifier.
///
/// Called from `signal.rs` when `[FAULT/CACHE-KEY] bucket=A` fires — i.e. the
/// faulting frame is STILL the live resident of its (mount,inode,offset) key,
/// yet the faulting code observed wrong content.  This recomputes the live
/// fingerprint and compares it to the one recorded at insert/validate:
///
///   * fingerprint DIFFERS → the frame's content changed in place while its
///     key was unchanged — the W215 bucket-A clobber.  Emit
///     `[W215/CACHE-CLOBBER]` naming the recorded last-writer RIP/CPU and the
///     install→fault generation; cross-reference the alloc/free shadows.
///   * fingerprint MATCHES → the corruption is NOT in the first 256 bytes
///     this catch fingerprints (or the recorded slot was displaced); tick the
///     negative-control counter so the operator can tell "catch ran, no fp
///     change" from "catch never ran".
///
/// `expected_key` is the (mount,inode,offset) the fault classifier resolved;
/// it must match the slot's recorded key for the verdict to be authoritative.
pub fn cache_prov_fault_bucket_a(
    phys: u64,
    mount_idx: usize,
    inode: u64,
    file_offset: u64,
) {
    let phys = phys & !0xFFFu64;
    if phys == 0 { return; }
    let slot = match cache_prov_slot(phys) {
        Some(s) => s,
        None => {
            crate::serial_println!(
                "[W215/CACHE-CLOBBER] phys={:#x} probe=out_of_band \
                 (frame outside cache provenance band [{:#x},{:#x}) — not the \
                 instrumented W215 cluster; out_of_band_traffic={})",
                phys, CACHE_BAND_LO, CACHE_BAND_HI,
                CACHE_PROV_OUT_OF_BAND.load(Ordering::Relaxed),
            );
            return;
        }
    };
    if slot.phys.load(Ordering::Relaxed) != phys {
        // With band-relative 1:1 addressing a probe=miss now means the frame
        // was genuinely never recorded (no install ran for it) — NOT that an
        // aliasing install evicted it.  This is the displacement fix's payoff:
        // a miss is now diagnostic, not noise.
        crate::serial_println!(
            "[W215/CACHE-CLOBBER] phys={:#x} probe=miss (frame never recorded \
             an install in-band — band-1:1, NOT displaced; displaced_tripwire={})",
            phys, CACHE_PROV_DISPLACED.load(Ordering::Relaxed),
        );
        return;
    }
    let recorded_key = slot.key.load(Ordering::Relaxed);
    let expected_key = pack_cache_prov_key(mount_idx, inode, file_offset);
    let recorded_fp = slot.fp.load(Ordering::Relaxed);
    let live_fp = cache_prov_fingerprint(phys);
    let meta = slot.meta.load(Ordering::Relaxed);
    let key_matches = recorded_key == expected_key;
    if key_matches && live_fp != recorded_fp {
        let n = CACHE_CLOBBER.fetch_add(1, Ordering::Relaxed) + 1;
        let last_rip = slot.last_write_rip.load(Ordering::Relaxed);
        let last_write_cpu = ((meta >> 8) & 0xFF) as u8;
        let install_cpu = ((meta >> 16) & 0xFF) as u8;
        let gen = cache_prov_generation(meta);
        let install_tick = slot.tick.load(Ordering::Relaxed);
        let now = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
        crate::serial_println!(
            "[W215/CACHE-CLOBBER] #{} SAME-KEY CONTENT CHANGED \
             phys={:#x} key=(mount={},inode={:#x},pageidx={:#x}) \
             recorded_fp={:#x} live_fp={:#x} reclaim_gen={} \
             last_write_rip={:#x} last_write_cpu={} install_cpu={} \
             age_since_install_ticks={}",
            n, phys,
            mount_idx, inode, (file_offset >> 12),
            recorded_fp, live_fp, gen,
            last_rip, last_write_cpu, install_cpu,
            now.saturating_sub(install_tick),
        );
        dump_band_frame_prov("cache-clobber", phys);
    } else if key_matches {
        CACHE_PROV_FP_MATCH.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!(
            "[W215/CACHE-CLOBBER] phys={:#x} probe=fp_match \
             (key matched, first-256B fingerprint unchanged — corruption is \
             outside the fingerprint window or not in this frame) state={}",
            phys, cache_prov_state(meta),
        );
    } else {
        crate::serial_println!(
            "[W215/CACHE-CLOBBER] phys={:#x} probe=key_mismatch \
             recorded_key={:#x} expected_key={:#x} state={}",
            phys, recorded_key, expected_key, cache_prov_state(meta),
        );
    }
}

/// Read cache-catch counters for kdb introspection.
pub fn cache_prov_counts() -> [(&'static str, u64); 9] {
    [
        ("cache_clobber",     CACHE_CLOBBER.load(Ordering::Relaxed)),
        ("cache_refdec_reuse",CACHE_REFDEC_REUSE.load(Ordering::Relaxed)),
        ("validated",         CACHE_PROV_VALIDATED.load(Ordering::Relaxed)),
        ("writes",            CACHE_PROV_WRITES.load(Ordering::Relaxed)),
        ("reclaims",          CACHE_PROV_RECLAIMS.load(Ordering::Relaxed)),
        ("displaced",         CACHE_PROV_DISPLACED.load(Ordering::Relaxed)),
        ("fp_match_negctrl",  CACHE_PROV_FP_MATCH.load(Ordering::Relaxed)),
        ("out_of_band",       CACHE_PROV_OUT_OF_BAND.load(Ordering::Relaxed)),
        ("band_residents",    cache_band_resident_count()),
    ]
}

/// Self-test / verification probe: count how many band slots currently hold an
/// INSTALLED in-band frame provenance.  This is the displacement-fix verifier
/// — on a normal ff-gui boot, after the cold-boot libxul cache prepopulate,
/// this MUST be non-zero and stable (the band-scoped table is non-displacing,
/// so prepopulate installs in the band SURVIVE rather than evicting one
/// another).  Under the old single-way map a comparable readout would show
/// most band frames' provenance gone (displaced ~62 %).
///
/// O(CACHE_PROV_SIZE) — only invoked from the kdb self-test path, never on the
/// hot fault/install path.
pub fn cache_band_resident_count() -> u64 {
    let slots = match cache_prov_slots() {
        Some(s) => s,
        None => return 0,
    };
    let mut n = 0u64;
    for slot in slots.iter() {
        if slot.phys.load(Ordering::Relaxed) != 0
            && cache_prov_state(slot.meta.load(Ordering::Relaxed)) == CACHE_STATE_INSTALLED
        {
            n += 1;
        }
    }
    n
}

/// Self-test for the displacement fix: probe a band frame whose provenance was
/// recorded by an install, and confirm the slot still holds it (probe=hit)
/// rather than having been aliased out.  Returns `(probed, hit, miss)` over a
/// sample of the band's currently-recorded slots.
///
/// `kdb w215-cache-selftest` calls this on a live boot: a healthy result is
/// `probed > 0 && miss == 0` — every recorded in-band frame still resolves to
/// its own slot, proving the band-relative addressing did NOT displace it.
pub fn cache_prov_band_selftest() -> (u64, u64, u64) {
    let slots = match cache_prov_slots() {
        Some(s) => s,
        None => return (0, 0, 0),
    };
    let mut probed = 0u64;
    let mut hit = 0u64;
    let mut miss = 0u64;
    for slot in slots.iter() {
        let recorded = slot.phys.load(Ordering::Relaxed);
        if recorded == 0 {
            continue;
        }
        probed += 1;
        // Re-resolve the slot the SAME way a fault-time probe would, from the
        // recorded phys, and confirm it lands back on this exact entry.
        match cache_prov_slot(recorded) {
            Some(reslot) if core::ptr::eq(reslot, slot) => hit += 1,
            _ => miss += 1,
        }
    }
    (probed, hit, miss)
}

pub fn cache_prov_validated_count() -> u64 { CACHE_PROV_VALIDATED.load(Ordering::Relaxed) }
pub fn cache_clobber_count() -> u64 { CACHE_CLOBBER.load(Ordering::Relaxed) }
pub fn cache_refdec_reuse_count() -> u64 { CACHE_REFDEC_REUSE.load(Ordering::Relaxed) }
