//! W215 two-arm diagnostic instrumentation (firefox-test gated).
//!
//! ## Goal
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

#![cfg(feature = "firefox-test")]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// ── Event kinds for Arm-1 provenance ring ───────────────────────────────────

pub const KIND_ALLOC: u8                       = 1;
pub const KIND_INSERT: u8                      = 2;
pub const KIND_EVICT: u8                       = 3;
pub const KIND_REFINC: u8                      = 4;
pub const KIND_REFDEC: u8                      = 5;
pub const KIND_PHYS_OFF_WRITE_PRE_INSERT: u8   = 6;
pub const KIND_PFH_INSTALL: u8                 = 7;
// ── Forensic-ring kinds (cluster-filtered time-ordered ring) ────────────────
pub const KIND_FREE: u8                        = 8;
pub const KIND_QUARANTINE_FREE: u8             = 9;
pub const KIND_WRITE_DETECTED: u8              = 10;
pub const KIND_DUP_PHYS_AT_INSERT: u8          = 11;
pub const KIND_CACHE_DUP_FOUND: u8             = 12;
pub const KIND_COW_COPY_SRC: u8                = 13;
pub const KIND_COW_COPY_DST: u8                = 14;
pub const KIND_PT_ZERO: u8                     = 15;

// ── Forensic-ring writer-site IDs (for KIND_WRITE_DETECTED) ─────────────────
pub const W_SITE_PREPOPULATE_COPY: u8 = 1;  // mm/cache.rs prepopulate copy
pub const W_SITE_PFH_READAHEAD_ZERO: u8 = 2; // arch/x86_64/idt.rs readahead zero
pub const W_SITE_PFH_SINGLEPAGE_ZERO: u8 = 3; // arch/x86_64/idt.rs single-page zero
pub const W_SITE_COW_PHYSOFF_COPY: u8 = 4; // arch/x86_64/idt.rs CoW PHYS_OFF copy
pub const W_SITE_VMM_NEW_PT_ZERO: u8  = 5; // mm/vmm.rs new page-table zero

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
        _ => "UNKNOWN",
    }
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

// ── Forensic provenance ring (time-ordered, cluster-filtered) ───────────────
//
// A single global ring buffer that records every event touching a phys in
// the empirically-observed W215 cluster range.  Entries are written in
// monotonic head-index order; on overflow oldest entries are overwritten.
// Filtering on the cluster range keeps the ring noise-free across long
// runs (~100 K events) while still covering >95% of historical bucket-A
// hits (phys cluster 0x32ed*-0x330* across all five iterations of the
// W215 saga, per Intel SDM Vol. 3A §4.10.5 paging-structure coherence
// invariants).
//
// Lock-free: a single AtomicU64 head; per-slot stores are Relaxed.  A
// concurrent reader (dump_prov_ring_for_phys) walks the ring with a
// snapshot of head — it may observe partial writes on slots being
// updated, which is acceptable because:
//   (a) the filter range constrains writers to a small phys window, so
//       cross-slot interleaving is rare in practice;
//   (b) the dump is post-fault, by which time the ring is quiescent for
//       most physes;
//   (c) any torn entry is recognizable (phys=0 or impossible kind) and
//       skipped.

/// Lower bound of the W215 cluster phys filter (inclusive).  Observed
/// cluster: 0x32ed*-0x330* across all bucket-A hits in the W215 saga.
/// Widened to a round 1 MiB boundary on each side for safety.
const W215_CLUSTER_LO: u64 = 0x3280_0000;
const W215_CLUSTER_HI: u64 = 0x3380_0000;

#[inline]
fn in_cluster(phys: u64) -> bool {
    phys >= W215_CLUSTER_LO && phys < W215_CLUSTER_HI
}

/// One forensic-ring entry.  Sized 48 bytes (6 * u64) for cache-line
/// alignment friendliness.
#[repr(C, align(64))]
struct RingEntry {
    tsc_or_tick: AtomicU64,
    /// Bit layout:
    ///   [63:48] reserved (0)
    ///   [47:40] cpu
    ///   [39:32] kind
    ///   [31:0]  key_off_lo (low 32 bits of file_offset >> 12 page index)
    packed_a: AtomicU64,
    phys: AtomicU64,
    /// Bit layout:
    ///   [63:32] key_inode_lo32
    ///   [31:0]  key_mount_lo32
    packed_b: AtomicU64,
    rip: AtomicU64,
    cr3: AtomicU64,
}

impl RingEntry {
    const fn new() -> Self {
        Self {
            tsc_or_tick: AtomicU64::new(0),
            packed_a: AtomicU64::new(0),
            phys: AtomicU64::new(0),
            packed_b: AtomicU64::new(0),
            rip: AtomicU64::new(0),
            cr3: AtomicU64::new(0),
        }
    }
}

/// Ring capacity (power of two — index = head & (CAP-1)).
const RING_CAP: usize = 4096;

#[repr(C, align(64))]
struct Ring {
    entries: [RingEntry; RING_CAP],
}

impl Ring {
    const fn new() -> Self {
        const E: RingEntry = RingEntry::new();
        Self { entries: [E; RING_CAP] }
    }
}

static RING: Ring = Ring::new();

/// Monotonically-increasing head index.  Position in ring = head & (CAP-1).
static RING_HEAD: AtomicU64 = AtomicU64::new(0);

/// Total entries pushed (saturates if astronomically high).  Equal to
/// RING_HEAD post-saturation except in the no-overflow case.
static RING_PUSHES: AtomicU64 = AtomicU64::new(0);

/// Entries discarded by the cluster filter (out of range).
static RING_FILTERED: AtomicU64 = AtomicU64::new(0);

/// Wraps where a not-recently-touched slot was overwritten by the head.
static RING_WRAPS: AtomicU64 = AtomicU64::new(0);

/// Push one ring entry.  Caller provides the kind + phys + cache key + rip.
/// Filter: phys must be in the W215 cluster range — otherwise the call is
/// a no-op (filtered count incremented).
#[inline]
pub fn ring_push(
    kind: u8,
    phys: u64,
    mount_idx: usize,
    inode: u64,
    file_offset_bytes: u64,
    rip: u64,
) {
    if !in_cluster(phys) {
        RING_FILTERED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let head = RING_HEAD.fetch_add(1, Ordering::Relaxed);
    if head >= RING_CAP as u64 {
        RING_WRAPS.fetch_add(1, Ordering::Relaxed);
    }
    RING_PUSHES.fetch_add(1, Ordering::Relaxed);
    let slot = &RING.entries[(head as usize) & (RING_CAP - 1)];

    let cpu = crate::arch::x86_64::apic::cpu_index() as u64;
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let key_off_lo = ((file_offset_bytes >> 12) & 0xFFFF_FFFF) as u64;
    let packed_a = (cpu << 40) | ((kind as u64) << 32) | key_off_lo;
    let packed_b = ((inode & 0xFFFF_FFFF) << 32) | ((mount_idx as u64) & 0xFFFF_FFFF);
    let cr3 = crate::mm::vmm::get_cr3();

    slot.tsc_or_tick.store(tick, Ordering::Relaxed);
    slot.packed_a.store(packed_a, Ordering::Relaxed);
    slot.phys.store(phys, Ordering::Relaxed);
    slot.packed_b.store(packed_b, Ordering::Relaxed);
    slot.rip.store(rip, Ordering::Relaxed);
    slot.cr3.store(cr3, Ordering::Relaxed);
}

/// Push a ring entry without a cache key (alloc/free events).  rip optional.
#[inline]
pub fn ring_push_nokey(kind: u8, phys: u64, rip: u64) {
    ring_push(kind, phys, 0, 0, 0, rip);
}

#[inline]
fn kind_str_full(k: u8) -> &'static str {
    match k {
        KIND_ALLOC => "ALLOC",
        KIND_INSERT => "INSERT",
        KIND_EVICT => "EVICT",
        KIND_REFINC => "REFINC",
        KIND_REFDEC => "REFDEC",
        KIND_PHYS_OFF_WRITE_PRE_INSERT => "PREINS_W",
        KIND_PFH_INSTALL => "PFH_INSTALL",
        KIND_FREE => "FREE",
        KIND_QUARANTINE_FREE => "QUAR_FREE",
        KIND_WRITE_DETECTED => "WRITE_DETECTED",
        KIND_DUP_PHYS_AT_INSERT => "DUP_PHYS_AT_INSERT",
        KIND_CACHE_DUP_FOUND => "CACHE_DUP_FOUND",
        KIND_COW_COPY_SRC => "COW_COPY_SRC",
        KIND_COW_COPY_DST => "COW_COPY_DST",
        KIND_PT_ZERO => "PT_ZERO",
        _ => "?",
    }
}

/// Dump the last `max_entries` ring events matching `phys` to the serial
/// console.  Called from the FAULT/PHYS bucket-A path so the corrupting
/// writer's history is visible at the moment of fault.  Newest-first.
pub fn dump_prov_ring_for_phys(phys: u64) {
    if !in_cluster(phys) {
        crate::serial_println!(
            "[W215/PROV-RING] phys={:#x} entries=0 (out of cluster filter [{:#x},{:#x}))",
            phys, W215_CLUSTER_LO, W215_CLUSTER_HI,
        );
        return;
    }
    let head = RING_HEAD.load(Ordering::Relaxed);
    let pushes = RING_PUSHES.load(Ordering::Relaxed);
    // Walk backwards from head, emit up to MAX_DUMP entries matching phys.
    const MAX_DUMP: usize = 64;
    let scan_limit = core::cmp::min(head as usize, RING_CAP);
    let mut emitted: usize = 0;

    crate::serial_println!(
        "[W215/PROV-RING] phys={:#x} head={} pushes_total={} scan_limit={}",
        phys, head, pushes, scan_limit,
    );

    for back in 1..=scan_limit {
        if emitted >= MAX_DUMP { break; }
        let idx = ((head - back as u64) as usize) & (RING_CAP - 1);
        let slot = &RING.entries[idx];
        let p = slot.phys.load(Ordering::Relaxed);
        if p != phys { continue; }
        let tick = slot.tsc_or_tick.load(Ordering::Relaxed);
        let pa = slot.packed_a.load(Ordering::Relaxed);
        let pb = slot.packed_b.load(Ordering::Relaxed);
        let rip = slot.rip.load(Ordering::Relaxed);
        let cr3 = slot.cr3.load(Ordering::Relaxed);
        let cpu = ((pa >> 40) & 0xFF) as u8;
        let kind = ((pa >> 32) & 0xFF) as u8;
        let key_off_lo = (pa & 0xFFFF_FFFF) as u32;
        let key_mount = (pb & 0xFFFF_FFFF) as u32;
        let key_inode = ((pb >> 32) & 0xFFFF_FFFF) as u32;
        crate::serial_println!(
            "[W215/PROV-RING/E] i={} tick={} cpu={} op={} phys={:#x} \
             key=(m={},ino_lo={:#x},off_idx={:#x}) rip={:#x} cr3={:#x}",
            emitted, tick, cpu, kind_str_full(kind),
            p, key_mount, key_inode, key_off_lo, rip, cr3,
        );
        emitted += 1;
    }
    if emitted == 0 {
        crate::serial_println!(
            "[W215/PROV-RING/E] phys={:#x} (no matching entries in ring)",
            phys,
        );
    }
}

/// WRITE_DETECTED helper.  Call BEFORE a PHYS_OFF write at one of the five
/// instrumented sites.  Checks whether `phys` is currently cache-resident;
/// on hit, emits a structured `[W215/WRITE-DETECT]` serial line and pushes
/// a WRITE_DETECTED entry to the ring.  Does NOT modify the write.
///
/// `caller_rip` should be the return address of the calling instruction
/// — typical use is to pass `0` and let the compiler/optimizer omit RIP,
/// or capture via `core::intrinsics::caller_location()` upstream.
#[inline]
pub fn write_detect(site: u8, phys: u64, caller_rip: u64) {
    if !in_cluster(phys) {
        return;
    }
    // Capture cache key if any.  is_phys_in_cache is O(n) over the cache
    // (≤40 K entries) but only fires in-cluster — bounded total impact.
    if let Some((m, ino, off)) = crate::mm::cache::is_phys_in_cache(phys) {
        let n = WRITE_DETECT_TOTAL.fetch_add(1, Ordering::Relaxed);
        // Sample serial line to avoid flood.  Always push to ring.
        if n < 16 || n % 256 == 0 {
            crate::serial_println!(
                "[W215/WRITE-DETECT] site={} phys={:#x} \
                 cache_key=(m={},ino={:#x},off={:#x}) rip={:#x} n={}",
                w_site_str(site), phys, m, ino, off, caller_rip, n,
            );
        }
        ring_push(KIND_WRITE_DETECTED, phys, m, ino, off, caller_rip);
        match site {
            W_SITE_PREPOPULATE_COPY     => WRITE_DETECT_PREPOP.fetch_add(1, Ordering::Relaxed),
            W_SITE_PFH_READAHEAD_ZERO   => WRITE_DETECT_PFH_RA.fetch_add(1, Ordering::Relaxed),
            W_SITE_PFH_SINGLEPAGE_ZERO  => WRITE_DETECT_PFH_SP.fetch_add(1, Ordering::Relaxed),
            W_SITE_COW_PHYSOFF_COPY     => WRITE_DETECT_COW.fetch_add(1, Ordering::Relaxed),
            W_SITE_VMM_NEW_PT_ZERO      => WRITE_DETECT_PTZ.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }
}

#[inline]
fn w_site_str(s: u8) -> &'static str {
    match s {
        W_SITE_PREPOPULATE_COPY    => "prepop_copy",
        W_SITE_PFH_READAHEAD_ZERO  => "pfh_readahead_zero",
        W_SITE_PFH_SINGLEPAGE_ZERO => "pfh_singlepage_zero",
        W_SITE_COW_PHYSOFF_COPY    => "cow_physoff_copy",
        W_SITE_VMM_NEW_PT_ZERO     => "vmm_new_pt_zero",
        _ => "?",
    }
}

// ── Cache duplicate-phys audit (axis-C double-bind detector) ────────────────
//
// Every CACHE_DUP_AUDIT_EVERY cache::insert calls, scan the cache for any
// two distinct keys pointing at the same phys.  A hit is structural axis-C
// evidence: `is_phys_in_cache` returns the FIRST match it encounters, so a
// double-bind silently presents as a "consistent cache key" to the bucket
// classifier while the actual PTE may have been installed via the other
// binding.

const CACHE_DUP_AUDIT_EVERY: u64 = 1000;
static INSERT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Called from cache::insert after the lock is dropped.  Schedules an audit
/// every CACHE_DUP_AUDIT_EVERY inserts.  This bound keeps the cumulative
/// O(n²) cost manageable: ~40 inserts/s × 40 K cache entries = ~1.6 M ops/s
/// at peak, scaled to one full audit per 25 s — negligible.
#[inline]
pub fn maybe_audit_cache_dup() {
    let n = INSERT_COUNTER.fetch_add(1, Ordering::Relaxed);
    if n % CACHE_DUP_AUDIT_EVERY != 0 {
        return;
    }
    if let Some((phys, key1, key2)) = crate::mm::cache::audit_duplicate_phys() {
        CACHE_DUP_HITS.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!(
            "[W215/CACHE-DUP] phys={:#x} key1=(m={},ino={:#x},off={:#x}) \
             key2=(m={},ino={:#x},off={:#x})",
            phys,
            key1.0, key1.1, key1.2,
            key2.0, key2.1, key2.2,
        );
        ring_push(KIND_CACHE_DUP_FOUND, phys,
                  key1.0, key1.1, key1.2, 0);
    }
}

/// Probe at insert time: if `phys` is already bound to a DIFFERENT cache key
/// at the moment of insert, that's a DUP_PHYS_AT_INSERT event.  Call this
/// from cache::insert before the actual map.insert occurs.
#[inline]
pub fn check_dup_phys_at_insert(
    incoming_mount: usize,
    incoming_inode: u64,
    incoming_off: u64,
    phys: u64,
) {
    if let Some((m, ino, off)) = crate::mm::cache::is_phys_in_cache(phys) {
        if m != incoming_mount || ino != incoming_inode || off != incoming_off {
            DUP_PHYS_AT_INSERT_HITS.fetch_add(1, Ordering::Relaxed);
            crate::serial_println!(
                "[W215/DUP-PHYS-AT-INSERT] phys={:#x} \
                 existing_key=(m={},ino={:#x},off={:#x}) \
                 incoming_key=(m={},ino={:#x},off={:#x})",
                phys, m, ino, off,
                incoming_mount, incoming_inode, incoming_off,
            );
            ring_push(KIND_DUP_PHYS_AT_INSERT, phys,
                      incoming_mount, incoming_inode, incoming_off, 0);
        }
    }
}

// ── Counters readable via kdb ───────────────────────────────────────────────

static WINDOW_RACE: AtomicU64 = AtomicU64::new(0);
static INSTALL_RACE: AtomicU64 = AtomicU64::new(0);
static PROV_RING_OVERFLOW: AtomicU64 = AtomicU64::new(0);
// Forensic-ring counters
static WRITE_DETECT_TOTAL: AtomicU64 = AtomicU64::new(0);
static WRITE_DETECT_PREPOP: AtomicU64 = AtomicU64::new(0);
static WRITE_DETECT_PFH_RA: AtomicU64 = AtomicU64::new(0);
static WRITE_DETECT_PFH_SP: AtomicU64 = AtomicU64::new(0);
static WRITE_DETECT_COW: AtomicU64 = AtomicU64::new(0);
static WRITE_DETECT_PTZ: AtomicU64 = AtomicU64::new(0);
static DUP_PHYS_AT_INSERT_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_DUP_HITS: AtomicU64 = AtomicU64::new(0);

pub fn window_race_count() -> u64 { WINDOW_RACE.load(Ordering::Relaxed) }
pub fn install_race_count() -> u64 { INSTALL_RACE.load(Ordering::Relaxed) }
pub fn prov_ring_overflow_count() -> u64 { PROV_RING_OVERFLOW.load(Ordering::Relaxed) }

/// Forensic-ring counter readout for kdb `w215-prov-ring` op.
///
/// Order: (head, pushes, filtered, wraps, write_detect_total,
///         wd_prepop, wd_pfh_ra, wd_pfh_sp, wd_cow, wd_ptz,
///         dup_phys_at_insert, cache_dup_hits)
pub fn forensic_ring_counters() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        RING_HEAD.load(Ordering::Relaxed),
        RING_PUSHES.load(Ordering::Relaxed),
        RING_FILTERED.load(Ordering::Relaxed),
        RING_WRAPS.load(Ordering::Relaxed),
        WRITE_DETECT_TOTAL.load(Ordering::Relaxed),
        WRITE_DETECT_PREPOP.load(Ordering::Relaxed),
        WRITE_DETECT_PFH_RA.load(Ordering::Relaxed),
        WRITE_DETECT_PFH_SP.load(Ordering::Relaxed),
        WRITE_DETECT_COW.load(Ordering::Relaxed),
        WRITE_DETECT_PTZ.load(Ordering::Relaxed),
        DUP_PHYS_AT_INSERT_HITS.load(Ordering::Relaxed),
        CACHE_DUP_HITS.load(Ordering::Relaxed),
    )
}

/// Dump the most-recent `max_entries` ring entries (any phys) to serial.
/// Used by kdb's `w215-prov-ring` op.
pub fn dump_prov_ring_tail(max_entries: usize) {
    let head = RING_HEAD.load(Ordering::Relaxed);
    let pushes = RING_PUSHES.load(Ordering::Relaxed);
    let scan_limit = core::cmp::min(head as usize, RING_CAP);
    let cap = core::cmp::min(max_entries, scan_limit);
    crate::serial_println!(
        "[W215/PROV-RING] tail dump head={} pushes_total={} emit={}",
        head, pushes, cap,
    );
    for back in 1..=cap {
        let idx = ((head - back as u64) as usize) & (RING_CAP - 1);
        let slot = &RING.entries[idx];
        let p = slot.phys.load(Ordering::Relaxed);
        if p == 0 { continue; }
        let tick = slot.tsc_or_tick.load(Ordering::Relaxed);
        let pa = slot.packed_a.load(Ordering::Relaxed);
        let pb = slot.packed_b.load(Ordering::Relaxed);
        let rip = slot.rip.load(Ordering::Relaxed);
        let cpu = ((pa >> 40) & 0xFF) as u8;
        let kind = ((pa >> 32) & 0xFF) as u8;
        let key_off_lo = (pa & 0xFFFF_FFFF) as u32;
        let key_mount = (pb & 0xFFFF_FFFF) as u32;
        let key_inode = ((pb >> 32) & 0xFFFF_FFFF) as u32;
        crate::serial_println!(
            "[W215/PROV-RING/T] i={} tick={} cpu={} op={} phys={:#x} \
             key=(m={},ino_lo={:#x},off_idx={:#x}) rip={:#x}",
            back - 1, tick, cpu, kind_str_full(kind),
            p, key_mount, key_inode, key_off_lo, rip,
        );
    }
}

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
