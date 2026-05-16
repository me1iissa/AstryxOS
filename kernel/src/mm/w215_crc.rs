//! W215 Arm-1 diagnostic — page-cache CRC walker.
//!
//! Records a CRC32 of each cache-resident page at insert time and walks the
//! cache from the periodic timer ISR re-CRCing live entries.  Any mismatch
//! arms a single-slot hardware write-watchpoint via
//! `crate::arch::x86_64::debug_reg::arm_write_watchpoint`, so the next CPU
//! to write to the corrupted frame traps to `#DB` with its RIP captured.
//!
//! Rate-limited to `WALK_BUDGET_PER_TICK` checks per timer tick across the
//! whole system, with per-CPU round-robin slicing.  At `TICK_HZ = 100` and
//! the default 4096 budget, a 4 M-entry cache walks in ~10 s; in practice
//! AstryxOS sees ≤ 50 K cache entries during the Firefox demo, so the
//! whole cache walks in well under one second.
//!
//! Citations:
//!   - Intel SDM Vol. 3A §4.10.5 (page-level coherence requirements).
//!   - Intel SDM Vol. 3B §17.2.4 (Debug Address Registers DR0–DR3).
//!   - ISO/IEC 8802-3 §3.2.8 CRC32 (the IEEE 802.3 polynomial used here).
//!
//! Diagnostic-only.  No fix-it logic.

#![cfg(feature = "w215-diag")]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// PHYS → kernel-higher-half offset.  Identical to the constant used in
/// `mm/cache.rs` and `mm/pmm.rs`; duplicated here to keep this module
/// self-contained.
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// 4 KiB cache page size; CRC walks one full page at a time.
const PAGE_BYTES: usize = 4096;

/// Maximum number of cache entries we can snapshot for the walker's
/// recompute pass.  Sized for the libxul demand-paging working set
/// (~38 K pages) plus headroom; larger caches just need more memory.
const SNAPSHOT_CAP: usize = 65_536;

/// Walk budget per timer tick, summed across all CPUs.  Each CPU
/// claims `WALK_BUDGET_PER_TICK / cpu_count` entries on its tick.
const WALK_BUDGET_PER_TICK: usize = 4096;

/// One entry in the shadow CRC table.  `phys == 0` means "free slot"
/// (PMM never hands out phys=0 on AstryxOS — see `pmm::init`).
#[derive(Copy, Clone)]
struct CrcEntry {
    phys: u64,
    crc32: u32,
    /// Cache-key fingerprint: `inode << 32 | (offset >> 12)` truncated to
    /// 64 bits.  Diagnostic only; the writer-discrimination evidence is
    /// the kernel RIP, not the key.
    key_packed: u64,
    /// Generation stamp incremented every time the CRC is re-recorded.
    /// Used as a coarse staleness signal in the report.
    generation: u32,
}

impl CrcEntry {
    const fn empty() -> Self {
        Self { phys: 0, crc32: 0, key_packed: 0, generation: 0 }
    }
}

/// Shadow CRC table, indexed by a stable hash of `(inode, offset)`.
/// Linear-probed; on collision we evict the oldest generation.
struct CrcTable {
    entries: [CrcEntry; SNAPSHOT_CAP],
}

impl CrcTable {
    const fn new() -> Self {
        Self { entries: [CrcEntry::empty(); SNAPSHOT_CAP] }
    }
}

/// Single mutex-protected shadow table.  Updates from `cache::insert`
/// take this lock briefly; the walker takes it briefly per slot.
static CRC_TABLE: spin::Mutex<CrcTable> = spin::Mutex::new(CrcTable::new());

/// Number of live (phys != 0) entries.
static LIVE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Round-robin walk cursor — the next slot index any CPU should examine.
/// Each CPU `fetch_add`s its slice and walks from the returned index.
static WALK_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// Stats published in the final report line.
static STAT_INSERTS: AtomicU64 = AtomicU64::new(0);
static STAT_WALKS: AtomicU64 = AtomicU64::new(0);
static STAT_MISMATCH: AtomicU64 = AtomicU64::new(0);
static STAT_FALSE_POSITIVE: AtomicU64 = AtomicU64::new(0);
static STAT_OVERFLOW_DROP: AtomicU64 = AtomicU64::new(0);

/// Compute the IEEE-802.3 CRC32 of a 4 KiB byte slice.
///
/// Reflected polynomial 0xEDB88320 (the reversed form of 0x04C11DB7),
/// initial seed 0xFFFF_FFFF, final XOR 0xFFFF_FFFF — the standard
/// zlib / IEEE 802.3 conventions.  Implemented inline to avoid pulling
/// a CRC crate into `no_std` kernel space; the table fits in 1 KiB.
fn crc32(buf: &[u8]) -> u32 {
    // Compile-time CRC32 table (Sarwate / table-driven, 256 entries).
    static CRC_TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0u32;
        while i < 256 {
            let mut c = i;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i as usize] = c;
            i += 1;
        }
        t
    };

    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[idx];
    }
    crc ^ 0xFFFF_FFFF
}

/// Hash `(inode, offset)` to a slot index in the shadow table.  We do
/// not need a cryptographic hash; a multiply-then-fold suffices.
fn key_to_slot(inode: u64, offset: u64) -> usize {
    // Splittable PRNG-style mixer (xoshiro-class).  Cheap and fairly
    // uniform across the libxul page-offset distribution.
    let mut k = inode.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    k ^= offset.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    k ^= k >> 27;
    k = k.wrapping_mul(0x94D0_49BB_1331_11EB);
    (k as usize) & (SNAPSHOT_CAP - 1)
}

/// Read 4 KiB at `PHYS_OFF + phys` and return its CRC32.  Safe to call
/// from any context that may also be writing to the frame — the worst
/// case is a torn read producing a "mismatch" that the verifier (a
/// second CRC computed by the walker on its next pass) will resolve.
///
/// SAFETY: the kernel higher-half identity-mapping (PHYS_OFF) covers
/// every physical frame that PMM has handed out, so the read is always
/// well-defined.
unsafe fn crc_of_phys(phys: u64) -> u32 {
    let p = (PHYS_OFF + phys) as *const u8;
    let slice = core::slice::from_raw_parts(p, PAGE_BYTES);
    crc32(slice)
}

/// Called from `cache::insert` after the new entry is published.
/// Records (or updates) the CRC of `phys` keyed by `(inode, file_offset)`.
/// Linear-probe within 8 slots; on collision overflow we drop the record
/// (incrementing `STAT_OVERFLOW_DROP`) — the cache is bigger than the
/// shadow table, but the libxul working set is well under capacity.
pub fn record_insert(phys: u64, inode: u64, file_offset: u64) {
    if phys == 0 {
        return;
    }
    let key_packed = (inode << 16) | ((file_offset >> 12) & 0xFFFF);
    let crc = unsafe { crc_of_phys(phys) };

    let start = key_to_slot(inode, file_offset);
    let mut table = CRC_TABLE.lock();
    for probe in 0..8usize {
        let idx = (start + probe) & (SNAPSHOT_CAP - 1);
        let e = &mut table.entries[idx];
        if e.phys == 0 {
            *e = CrcEntry {
                phys,
                crc32: crc,
                key_packed,
                generation: 1,
            };
            LIVE_COUNT.fetch_add(1, Ordering::Relaxed);
            STAT_INSERTS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if e.phys == phys && e.key_packed == key_packed {
            // Refresh in place — same key, same phys.
            e.crc32 = crc;
            e.generation = e.generation.wrapping_add(1);
            STAT_INSERTS.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    STAT_OVERFLOW_DROP.fetch_add(1, Ordering::Relaxed);
}

/// Called from `cache::evict` and other paths that remove a (phys, key)
/// pair.  Removes the shadow entry matching `phys` so a future PMM recycle
/// to a new tenant does not produce a phantom mismatch against stale CRC.
pub fn record_evict(phys: u64) {
    if phys == 0 {
        return;
    }
    let mut table = CRC_TABLE.lock();
    for e in table.entries.iter_mut() {
        if e.phys == phys {
            *e = CrcEntry::empty();
            LIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Per-CPU walk slice.  Called from `arch::x86_64::irq::timer_tick` once
/// per CPU per tick.  Picks up `per_cpu_budget` slots from the global
/// round-robin cursor and re-CRCs each live entry.  On mismatch:
///
///   - Re-CRC immediately to filter torn-read false positives.  If the
///     second CRC matches the stored one, classify as false positive and
///     continue.  Otherwise:
///   - Emit `[W215/CRC-MISMATCH] ...`.
///   - If no W215 watchpoint is currently armed, arm DR0 W-only on the
///     8-byte qword at `PHYS_OFF + phys` (offset 0) — the first qword of
///     the frame is as good a witness as any; whatever writer is mutating
///     the page is overwhelmingly likely to write at least one qword.
///
/// Cheap-path: when the cache is empty or the walker has no slots to
/// examine on this tick, returns immediately without taking the table
/// lock.
pub fn crc_walk_tick(_cpu: u32) {
    let live = LIVE_COUNT.load(Ordering::Relaxed);
    if live == 0 {
        return;
    }

    // Determine this tick's slice.  Each CPU advances the cursor by
    // ceil(WALK_BUDGET_PER_TICK / cpus); a missing CPU just means the
    // remaining CPUs cover the budget faster.
    let cpus = crate::arch::x86_64::apic::cpu_count() as usize;
    let cpus = cpus.max(1);
    let per_cpu_budget = (WALK_BUDGET_PER_TICK + cpus - 1) / cpus;
    let start = WALK_CURSOR.fetch_add(per_cpu_budget, Ordering::Relaxed) & (SNAPSHOT_CAP - 1);

    // Snapshot up to `per_cpu_budget` (phys, expected_crc, key_packed)
    // tuples under the lock, then drop it before re-CRCing — the CRC
    // computation is ~4 KiB of memory load per entry and we do not want
    // to hold the shadow-table mutex across all of that.
    //
    // Use `try_lock`: the walker runs from the timer ISR (IF=0), and if
    // the lock is held by a `record_insert` / `record_evict` mid-flight
    // on a thread context that this ISR interrupted, a blocking
    // `lock()` would self-deadlock because the holder cannot release it
    // until the ISR returns.  Skipping a slice when contended is
    // harmless — the next tick will pick up where we left off.
    let mut buf: [(u64, u32, u64); 64] = [(0u64, 0u32, 0u64); 64];
    let slice_n = per_cpu_budget.min(buf.len());
    let mut n = 0usize;
    match CRC_TABLE.try_lock() {
        Some(table) => {
            for i in 0..slice_n {
                let idx = (start + i) & (SNAPSHOT_CAP - 1);
                // Snapshot the entry into a stack local ONCE so the
                // subsequent validity check and the value we copy into
                // `buf[n]` agree byte-for-byte.  Reading `e.phys` for
                // the filter and then reading it again for the buf
                // copy admits a torn read: a concurrent `record_insert`
                // (which holds the mutex, so we cannot collide here)
                // is not the threat, but a memcpy / static-data writer
                // racing the walker through `PHYS_OFF` is — that race
                // produced the historical ~60-per-trial `phys=0x201`
                // noise floor, where the filter saw a stable 4 KiB-aligned
                // value but the latched copy disagreed (low-32-bit
                // tear on the 64-bit `phys` field).  A single read into
                // a stack local removes the second load entirely.
                let snap: CrcEntry = table.entries[idx];
                // Skip slots with bogus phys values.  PMM never hands out
                // sub-MiB frames (kernel ELF + BIOS + identity-mapped
                // bootloader page tables occupy that region per
                // `pmm::init`), so a phys < 0x10_0000 in the shadow table
                // is either a still-being-initialised slot (torn read of
                // a concurrently writing `record_insert`) or a stale 4 KiB
                // field of a CrcEntry struct.  Either way, do not CRC it
                // against expected.
                //
                // Filters on phys:
                //   (a) ≥ 0x10_0000 — PMM never hands out sub-MiB frames.
                //   (b) ≤ 0x4_0000_0000 (16 GiB) — far above any realistic
                //       AstryxOS RAM ceiling; an over-large `phys` is
                //       almost certainly a torn write that has only
                //       latched the low 32 bits and left high 32 as
                //       garbage.  Without this bound a phys whose top
                //       bit is set would push `PHYS_OFF + phys` past the
                //       canonical range and #GPF the walker.
                //   (c) 4 KiB-aligned (low 12 bits zero) — PMM invariant.
                if snap.phys >= 0x10_0000
                    && snap.phys <= 0x4_0000_0000
                    && (snap.phys & 0xFFF) == 0
                {
                    buf[n] = (snap.phys, snap.crc32, snap.key_packed);
                    n += 1;
                }
            }
        }
        None => return,
    }
    if n == 0 {
        return;
    }
    STAT_WALKS.fetch_add(n as u64, Ordering::Relaxed);

    for i in 0..n {
        let (phys, expected, key_packed) = buf[i];
        let actual = unsafe { crc_of_phys(phys) };
        if actual == expected {
            continue;
        }
        // Re-CRC once for false-positive filter (torn-read window).
        let actual2 = unsafe { crc_of_phys(phys) };
        if actual2 == expected {
            STAT_FALSE_POSITIVE.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
        let inode = key_packed >> 16;
        let offset_page = key_packed & 0xFFFF;
        crate::serial_println!(
            "[W215/CRC-MISMATCH] phys={:#x} key=(_,{},{:#x}) expected={:#010x} \
             actual={:#010x} actual2={:#010x} tick={}",
            phys, inode, offset_page << 12, expected, actual, actual2, tick,
        );
        STAT_MISMATCH.fetch_add(1, Ordering::Relaxed);

        // Arm DR0 W-only on the 8-byte qword at PHYS_OFF+phys+0 unless
        // an arm is already in flight.  `arm_write_watchpoint` is
        // idempotent — only the first call wins.
        if !crate::arch::x86_64::debug_reg::is_armed() {
            let linear_addr = PHYS_OFF + phys;
            let armed = crate::arch::x86_64::debug_reg::arm_write_watchpoint(
                linear_addr, 8, phys, inode, offset_page << 12,
            );
            if armed {
                // Refresh the stored CRC to the new (corrupt) value so a
                // repeat walk does not re-emit a mismatch for the same
                // frame on every tick.  The DR0 trap is the dispositive
                // signal from this point forward.  `try_lock` for the
                // same self-deadlock reason as above; on contention we
                // simply pick this up on the next tick.
                if let Some(mut table) = CRC_TABLE.try_lock() {
                    for e in table.entries.iter_mut() {
                        if e.phys == phys {
                            e.crc32 = actual2;
                            e.generation = e.generation.wrapping_add(1);
                        }
                    }
                }
            }
        }
    }
}

/// Final report line — invoked from the test runner or shell when an
/// investigator wants to see the diagnostic's accumulated counts.
pub fn dump_stats() {
    let (arm_count, fire_count) = crate::arch::x86_64::debug_reg::stats();
    let per_slot = crate::arch::x86_64::debug_reg::per_slot_fires();
    crate::serial_println!(
        "[W215/ARM1/STATS] inserts={} walks={} mismatches={} false_pos={} \
         overflow_drop={} live={} dr_arms={} dr_fires={} \
         per_slot=[dr0={},dr1={},dr2={},dr3={}]",
        STAT_INSERTS.load(Ordering::Relaxed),
        STAT_WALKS.load(Ordering::Relaxed),
        STAT_MISMATCH.load(Ordering::Relaxed),
        STAT_FALSE_POSITIVE.load(Ordering::Relaxed),
        STAT_OVERFLOW_DROP.load(Ordering::Relaxed),
        LIVE_COUNT.load(Ordering::Relaxed),
        arm_count, fire_count,
        per_slot[0], per_slot[1], per_slot[2], per_slot[3],
    );
}
