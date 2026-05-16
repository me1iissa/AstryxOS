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

#![cfg(feature = "firefox-test")]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

// ── Event kinds for Arm-1 provenance ring ───────────────────────────────────

pub const KIND_ALLOC: u8                       = 1;
pub const KIND_INSERT: u8                      = 2;
pub const KIND_EVICT: u8                       = 3;
pub const KIND_REFINC: u8                      = 4;
pub const KIND_REFDEC: u8                      = 5;
pub const KIND_PHYS_OFF_WRITE_PRE_INSERT: u8   = 6;
pub const KIND_PFH_INSTALL: u8                 = 7;

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
