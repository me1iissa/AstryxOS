//! W215 write-protect page-fault trap (diagnostic, `w215-wptrap`-gated).
//!
//! ## Purpose
//!
//! The residual W215 corruption is an **in-place store** into a live,
//! reference-held page-cache frame that holds verified-correct library code
//! (libxul / satellite `.text`).  No allocator, free, or page-table event is
//! hooked at the moment of that store, so the passive per-phys provenance
//! shadows (`w215_diag` FREE_SHADOW / ALLOC_SHADOW / PROV) can classify the
//! frame's lifecycle but can never name the *writer's* RIP.
//!
//! This module names the writer directly by **trapping the store**: at cache
//! insert of a hot cluster frame, after the frame's contents are verified to
//! match the source bytes, the frame is made read-only on its canonical
//! higher-half direct-map alias (`PHYS_OFF + phys`).  A verified code page has
//! no legitimate kernel writer for the remainder of its cache residency, so
//! the *next* supervisor write to it — the W215 clobber — raises a
//! protection-violation `#PF` (error code P=1, W=1, U=0).  The page-fault
//! handler recognises the fault as a WP-trap, records the interrupted RIP,
//! CR2, tid/pid, refcount and tick, then bugchecks to freeze the machine for a
//! GDB autopsy of the offending instruction.
//!
//! ## Coverage and limitations (see the PR body)
//!
//! * The write-protect is on the higher-half direct-map alias only.  This is
//!   the alias every kernel `memset` / `copy_nonoverlapping` / zero-fill path
//!   uses (`PHYS_OFF + phys`), which is the suspected in-place writer class.
//!   A writer that reaches the frame through some *other* kernel mapping would
//!   not trap; user `.text` aliases are already read-only (`r-x`) so they are
//!   not the writer.
//! * Device DMA writes bypass CPU paging and cannot raise a `#PF`; the W215
//!   class under investigation is a CPU-side in-place store (the DMA-recycle
//!   class was addressed separately).
//! * Arming is bounded to a small pool and restricted to the historical
//!   cluster window, so the perturbation to the running system is minimal.
//!
//! ## Safety of the direct-map mutation
//!
//! The 2 MiB huge page that covers the target frame in the higher-half map is
//! split into 512 × 4 KiB entries by the existing, boot-proven
//! `vmm::get_or_create_entry` split path (invoked through `vmm::map_page`).
//! That split fills every sub-entry with the *same* physical base + flags the
//! huge page carried, so neighbouring frames keep their exact mapping and
//! writability; only the single target PTE has its writable bit cleared.  A
//! local `invlpg` plus a cross-CPU shootdown retires any stale writable TLB
//! entry before the trap can be relied upon.
//!
//! ## Public spec citations
//!
//! * Intel SDM Vol. 3A §4.6 (access rights / the R/W and U/S bits), §4.10.4
//!   (invalidation of TLBs and paging-structure caches — `INVLPG`), §4.10.5
//!   (propagating paging-structure changes across processors).
//! * POSIX 1003.1-2024 mmap(2) — `MAP_PRIVATE`/`PROT_EXEC` file mappings serve
//!   the file's bytes; a served code page must equal the on-disk bytes.
//!
//! ## ISR / lock safety
//!
//! `is_protected` and `report_and_freeze` are called from the page-fault
//! handler (IF=0) and use only atomics — no locks.  `arm` / `disarm` call
//! `vmm::map_page` (which takes `VMM_LOCK`) and `tlb::shootdown_page`; they run
//! from the cache-insert path with **no other lock held** (the cache lock has
//! already been released at the arm/disarm sites).

#![cfg(feature = "w215-wptrap")]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::vmm::{self, PHYS_OFF, PAGE_PRESENT, PAGE_WRITABLE};

/// Number of frames that can be write-protected concurrently.  Matches the
/// order of magnitude of the DR pre-arm pool; a handful of hot cluster code
/// pages is enough to catch the flaky clobber while keeping the perturbation
/// (and the per-fault scan cost) small.
const PROT_SLOTS: usize = 64;

/// Cluster window matching `cache.rs`'s `W215_PREARM_PHYS_{LO,HI}` — the
/// historical libxul fingerprint cluster.  Frames outside this window are
/// never armed (keeps the trap targeted at the code pages under suspicion).
const CLUSTER_PHYS_LO: u64 = 0x1000_0000; // 256 MiB
const CLUSTER_PHYS_HI: u64 = 0x4000_0000; // 1 GiB

/// One protected-frame record.  `phys == 0` means the slot is free.
#[repr(C)]
struct ProtEntry {
    /// Page-aligned physical address of the protected frame (0 = empty).
    phys: AtomicU64,
    /// Cache key inode (for the fire line) — best-effort.
    inode: AtomicU64,
    /// Cache key page offset (for the fire line) — best-effort.
    offset: AtomicU64,
}

impl ProtEntry {
    const fn new() -> Self {
        Self {
            phys: AtomicU64::new(0),
            inode: AtomicU64::new(0),
            offset: AtomicU64::new(0),
        }
    }
}

struct ProtTable {
    slots: [ProtEntry; PROT_SLOTS],
}

impl ProtTable {
    const fn new() -> Self {
        const E: ProtEntry = ProtEntry::new();
        Self { slots: [E; PROT_SLOTS] }
    }
}

static PROT: ProtTable = ProtTable::new();

// ── Counters (kdb-readable) ─────────────────────────────────────────────────
static ARMED: AtomicU64 = AtomicU64::new(0);
static DISARMED: AtomicU64 = AtomicU64::new(0);
static ARM_TABLE_FULL: AtomicU64 = AtomicU64::new(0);
static SHOOTDOWN_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static FIRES: AtomicU64 = AtomicU64::new(0);

pub fn armed_count() -> u64 { ARMED.load(Ordering::Relaxed) }
pub fn disarmed_count() -> u64 { DISARMED.load(Ordering::Relaxed) }
pub fn arm_table_full_count() -> u64 { ARM_TABLE_FULL.load(Ordering::Relaxed) }
pub fn shootdown_timeout_count() -> u64 { SHOOTDOWN_TIMEOUTS.load(Ordering::Relaxed) }
pub fn fire_count() -> u64 { FIRES.load(Ordering::Relaxed) }

/// Number of slots currently occupied (kdb introspection).
pub fn protected_count() -> usize {
    PROT.slots
        .iter()
        .filter(|s| s.phys.load(Ordering::Relaxed) != 0)
        .count()
}

/// Is `phys` (page-aligned) currently write-protected by this module?
///
/// Called from the page-fault handler on every supervisor write-present fault
/// to a higher-half direct-map address.  A linear scan of `PROT_SLOTS`
/// atomics; cheap because such faults are rare.
#[inline]
pub fn is_protected(phys: u64) -> bool {
    let p = phys & !0xFFFu64;
    if p == 0 {
        return false;
    }
    PROT.slots
        .iter()
        .any(|s| s.phys.load(Ordering::Acquire) == p)
}

/// Write-protect `phys` on its higher-half direct-map alias and register it.
///
/// No-op when `phys` is outside the cluster window, already protected, or the
/// table is full.  Must be called with no lock held (takes `VMM_LOCK` via
/// `map_page`).
pub fn arm(phys: u64, inode: u64, offset: u64) {
    let p = phys & !0xFFFu64;
    if p < CLUSTER_PHYS_LO || p >= CLUSTER_PHYS_HI {
        return;
    }
    // Already protected? (idempotent)
    if is_protected(p) {
        return;
    }
    // Claim a free slot.
    let mut slot_idx = None;
    for (i, s) in PROT.slots.iter().enumerate() {
        // Claim atomically: only take a slot whose phys is still 0.
        if s.phys
            .compare_exchange(0, p, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            s.inode.store(inode, Ordering::Relaxed);
            s.offset.store(offset, Ordering::Relaxed);
            slot_idx = Some(i);
            break;
        }
    }
    if slot_idx.is_none() {
        ARM_TABLE_FULL.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Write-protect the higher-half direct-map alias: present, supervisor,
    // read-only.  `map_page` splits the covering 2 MiB huge page as needed;
    // neighbouring sub-pages keep their (writable) mapping — see module doc.
    let va = PHYS_OFF + p;
    let ok = vmm::map_page(va, p, PAGE_PRESENT); // no PAGE_WRITABLE ⇒ read-only
    if !ok {
        // Roll the slot back so we don't claim a frame we failed to protect.
        for s in PROT.slots.iter() {
            if s.phys.load(Ordering::Relaxed) == p {
                s.phys.store(0, Ordering::Release);
                break;
            }
        }
        return;
    }
    vmm::invlpg(va);
    if !crate::mm::tlb::shootdown_page(vmm::get_cr3(), va) {
        SHOOTDOWN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    }
    let n = ARMED.fetch_add(1, Ordering::Relaxed);
    if n < 16 || n % 256 == 0 {
        crate::serial_println!(
            "[W215/WP-ARM] phys={:#x} va={:#x} inode={:#x} offset={:#x} n={}",
            p, va, inode, offset, n,
        );
    }
}

/// Restore write access to `phys` and free its slot, if it is protected.
///
/// Called when the frame leaves the cache (eviction) so a recycled frame is
/// never left read-only.  No-op when `phys` is not protected.  Takes
/// `VMM_LOCK` via `map_page`; must be called with no lock held.
pub fn disarm(phys: u64) {
    let p = phys & !0xFFFu64;
    if p == 0 {
        return;
    }
    let mut found = false;
    for s in PROT.slots.iter() {
        if s.phys
            .compare_exchange(p, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            found = true;
            break;
        }
    }
    if !found {
        return;
    }
    // Restore present + writable + supervisor on the direct-map alias.
    let va = PHYS_OFF + p;
    let _ = vmm::map_page(va, p, PAGE_WRITABLE);
    vmm::invlpg(va);
    if !crate::mm::tlb::shootdown_page(vmm::get_cr3(), va) {
        SHOOTDOWN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    }
    DISARMED.fetch_add(1, Ordering::Relaxed);
}

/// The page-fault handler caught a supervisor write to a protected frame — the
/// W215 clobber writer, red-handed.  Record everything and bugcheck to freeze
/// the machine at the offending store for a GDB autopsy.
///
/// `phys` is the protected frame, `cr2` the faulting linear address (the
/// direct-map alias written), `frame` the interrupt frame (its `rip` is the
/// writer).  Does not return.
#[inline(never)]
pub fn report_and_freeze(
    phys: u64,
    cr2: u64,
    frame: &crate::arch::x86_64::idt::InterruptFrame,
) -> ! {
    FIRES.fetch_add(1, Ordering::Relaxed);
    let p = phys & !0xFFFu64;
    let rip = frame.rip;
    let tid = crate::proc::current_tid();
    let pid = crate::proc::current_pid_lockless();
    let rc = crate::mm::refcount::page_ref_count(p);
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);

    // Recover the cache key recorded at arm time.
    let mut inode = 0u64;
    let mut offset = 0u64;
    for s in PROT.slots.iter() {
        if s.phys.load(Ordering::Relaxed) == p {
            inode = s.inode.load(Ordering::Relaxed);
            offset = s.offset.load(Ordering::Relaxed);
            break;
        }
    }

    // Sample the current (pre-store) frame bytes.  The frame is present + RO,
    // so this read is safe.  The store's operand value is not in the frame yet
    // — decode it from the frozen instruction at `rip` under GDB.
    let src = (PHYS_OFF + p) as *const u8;
    let mut b = [0u8; 16];
    for i in 0..16 {
        b[i] = unsafe { core::ptr::read_volatile(src.add(i)) };
    }

    crate::serial_println!(
        "[W215/WP-TRAP] writer_rip={:#x} cr2={:#x} phys={:#x} rc={} tid={} pid={} \
         inode={:#x} offset={:#x} tick={} cur_bytes={:02x}{:02x}{:02x}{:02x}\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        rip, cr2, p, rc, tid, pid, inode, offset, tick,
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    );
    crate::serial_println!(
        "[W215/WP-TRAP] the interrupted RIP is the in-place clobber writer — \
         autopsy the store operand at that RIP; phys is a verified cluster code page"
    );

    crate::ke::bugcheck::ke_bugcheck(
        crate::ke::bugcheck::BUGCHECK_W215_WP_TRAP,
        rip,
        cr2,
        p,
        rc as u64,
    );
}

/// The cluster phys window (`[lo, hi)`) this trap arms within.  Exposed for
/// tests and kdb.
pub fn cluster_window() -> (u64, u64) {
    (CLUSTER_PHYS_LO, CLUSTER_PHYS_HI)
}

/// Self-test of the load-bearing correctness property: write-protecting one
/// frame on the higher-half direct map splits the covering 2 MiB huge page
/// **without** disturbing its neighbours.
///
/// Drives the real `vmm::map_page` protect/restore primitive on `phys` (the
/// caller supplies a scratch frame it owns) and its `+4 KiB` neighbour, and
/// returns `(protected_ro_ok, neighbour_safe, restored_ok)`:
///   * `protected_ro_ok` — after protect, `PHYS_OFF+phys` is present,
///     **read-only**, and still maps to `phys`.
///   * `neighbour_safe`  — after protect, `PHYS_OFF+phys+0x1000` is present,
///     **writable**, and still maps to `phys+0x1000` (the split preserved it).
///   * `restored_ok`     — after restore, `PHYS_OFF+phys` is present,
///     **writable**, and still maps to `phys`.
///
/// The scratch frame is left writable (restored) on return; the caller frees
/// it.  Bypasses the cluster-window filter and the `PROT` table on purpose —
/// this exercises only the page-table split/protect/restore primitive.
pub fn selftest(phys: u64) -> (bool, bool, bool) {
    let p = phys & !0xFFFu64;
    let neigh = p + 0x1000;
    let va = PHYS_OFF + p;
    let nva = PHYS_OFF + neigh;

    // Helper: (present, writable, phys) for a leaf VA in the kernel map.
    let probe = |virt: u64, expect_phys: u64| -> (bool, bool, bool) {
        match vmm::lookup_pte_in(vmm::get_cr3(), virt) {
            Some(pte) => {
                let present = pte & PAGE_PRESENT != 0;
                let writable = pte & PAGE_WRITABLE != 0;
                let phys_ok = (pte & crate::mm::vmm::ADDR_MASK) == expect_phys;
                (present, writable, phys_ok)
            }
            // None ⇒ still a huge page or non-present: neither present-leaf.
            None => (false, false, false),
        }
    };

    // Protect the target frame read-only (splits the huge page).
    let _ = vmm::map_page(va, p, PAGE_PRESENT);
    vmm::invlpg(va);
    vmm::invlpg(nva);

    let (t_present, t_writable, t_phys) = probe(va, p);
    let protected_ro_ok = t_present && !t_writable && t_phys;

    let (n_present, n_writable, n_phys) = probe(nva, neigh);
    let neighbour_safe = n_present && n_writable && n_phys;

    // Restore write access to the target frame.
    let _ = vmm::map_page(va, p, PAGE_WRITABLE);
    vmm::invlpg(va);

    let (r_present, r_writable, r_phys) = probe(va, p);
    let restored_ok = r_present && r_writable && r_phys;

    (protected_ro_ok, neighbour_safe, restored_ok)
}
