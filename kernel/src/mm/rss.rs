//! Per-address-space resident-set accounting.
//!
//! # What this counts
//!
//! For each user address space (keyed by its CR3, the physical address of its
//! PML4), the number of **user-space leaf page-table entries that are
//! currently present** — i.e. the frames the process can touch right now
//! without taking a fault.  A frame shared between address spaces (a
//! fork-CoW page, a `MAP_SHARED` file page, a SysV SHM segment) counts once in
//! *each* space that maps it, which is the standard meaning of resident set
//! size: it answers "how much memory does killing this process release
//! pressure on", not "who owns the frame".
//!
//! It deliberately does **not** count:
//!
//! * address space that has been reserved but never faulted in — that is the
//!   *virtual* size, and conflating the two is exactly the defect this module
//!   exists to fix;
//! * page-table pages themselves.  They are proportional to the resident count
//!   (at most one PT per 512 resident frames) so including them cannot reorder
//!   two candidates that differ materially, and every additional accounting
//!   chokepoint is a fresh opportunity for the counter to drift.
//!
//! # Why a lock-free table rather than a field on `VmSpace`
//!
//! The hot maintenance sites are leaf-PTE writes inside `mm::vmm`, which run
//! under `VMM_LOCK` — and, on the demand-fault path, with interrupts disabled
//! on an interrupt gate (Intel SDM Vol. 3A §6.8.1).  They hold a `cr3`, not a
//! `&VmSpace`.  Reaching a counter through a `Mutex<BTreeMap<..>>` registry
//! from there would both invert the documented `mm_sem → VMM_LOCK` ordering
//! and add a blocking acquire to an IF=0 path.  A fixed-size open-addressed
//! table of atomics has no lock to order and no acquire to block on, so it is
//! safe to update from directly beside the PTE write — which is also the only
//! place where the old and new entry are known to be consistent with each
//! other.
//!
//! # Failure model
//!
//! Best-effort, and asymmetric on purpose.  A saturated table (more concurrent
//! address spaces than [`RSS_SLOTS`]) means a space has no counter; it reads
//! back as `None`, and the OOM killer scores it 0 — so the failure mode is
//! "this process is not selected as a victim", never "an innocent process is
//! selected because its count was inflated".  [`attach_failures`] makes the
//! condition visible rather than silent.

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Concurrently-tracked address spaces.  Comfortably above the number of
/// processes any workload here runs (a full windowed browser session is a few
/// dozen), and slots are recycled on process exit.
const RSS_SLOTS: usize = 256;

/// Slot key meaning "never used" — a lookup may stop here.
const KEY_EMPTY: u64 = 0;
/// Slot key meaning "used and then released" — a lookup must probe *past* it.
///
/// Without this, releasing a slot that sits earlier in another entry's probe
/// chain would make that entry unreachable until it was re-attached, silently
/// zeroing a live process's resident count.  A real CR3 is a page-aligned
/// physical address and can never collide with this value.
const KEY_TOMBSTONE: u64 = u64::MAX;
/// Slot key meaning "claimed by an [`attach`] that has not published its CR3
/// yet" — a lookup must probe *past* it, exactly like a tombstone.
///
/// This is what makes the claim safe against a concurrent `attach`: the count
/// is reset only after the slot has been won and while it is still unreachable
/// by `find`, so no losing racer can zero a slot another address space has
/// already begun counting into, and no `account` can slip in between the reset
/// and the publish.  A real CR3 is a page-aligned physical address and can
/// never collide with this value.
const KEY_CLAIMING: u64 = u64::MAX - 1;

/// CR3 of the address space occupying each slot.
static RSS_KEYS: [AtomicU64; RSS_SLOTS] = [const { AtomicU64::new(KEY_EMPTY) }; RSS_SLOTS];

/// Resident pages for the address space in the matching [`RSS_KEYS`] slot.
///
/// Signed so that an accounting bug shows up as a negative value that
/// [`underflow_count`] reports, instead of being hidden by a saturating
/// subtraction at zero.
static RSS_PAGES: [AtomicI64; RSS_SLOTS] = [const { AtomicI64::new(0) }; RSS_SLOTS];

/// Number of [`attach`] calls that found no free slot.
static RSS_ATTACH_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Number of [`account`] calls that drove a counter below zero.
static RSS_UNDERFLOWS: AtomicU64 = AtomicU64::new(0);

/// CR3 is page-aligned; fold the frame number with a multiplicative hash so
/// consecutively-allocated PML4 frames do not pile into adjacent slots.
#[inline]
fn slot_for(cr3: u64) -> usize {
    (((cr3 >> 12).wrapping_mul(2654435761)) as usize) % RSS_SLOTS
}

/// Find the slot holding `cr3`, or `None`.
///
/// Probes past every non-matching key — another CR3, a tombstone, or a slot
/// mid-claim — and stops only at the first never-used slot: an entry that
/// exists is always reachable from its hash position through an unbroken chain
/// of non-empty slots.
#[inline]
fn find(cr3: u64) -> Option<usize> {
    let start = slot_for(cr3);
    for i in 0..RSS_SLOTS {
        let idx = (start + i) % RSS_SLOTS;
        match RSS_KEYS[idx].load(Ordering::Acquire) {
            KEY_EMPTY => return None,
            k if k == cr3 => return Some(idx),
            // KEY_TOMBSTONE, KEY_CLAIMING, or a different CR3 — keep probing.
            _ => continue,
        }
    }
    None
}

/// Begin tracking `cr3`, with a resident count of zero.
///
/// Idempotent: re-attaching an already-tracked CR3 leaves its count alone, so
/// a caller that cannot easily tell whether a space is new (the vfork sibling
/// sharing its parent's CR3) may call it unconditionally.
///
/// Returns `false` if the table is full, in which case the space is untracked
/// and [`resident_pages`] will report `None` for it.
pub fn attach(cr3: u64) -> bool {
    if cr3 == 0 {
        return false;
    }
    let start = slot_for(cr3);
    // Pass 1: an existing entry for this CR3 wins over claiming a new slot,
    // otherwise two attaches could leave two slots for one space and a later
    // `find` would see only the first.
    if find(cr3).is_some() {
        return true;
    }
    // Pass 2: claim the first empty-or-tombstoned slot, in two steps.
    //
    // Win the slot FIRST (CAS to `KEY_CLAIMING`), then reset the count, then
    // publish the CR3.  Resetting before the CAS would be a live-data bug: on
    // a lost race the slot already belongs to another address space, and this
    // call would have wiped a count that space had begun accumulating.  While
    // the key reads `KEY_CLAIMING` the slot is invisible to `find`, so the
    // reset also cannot race an `account` for the CR3 about to be published.
    for i in 0..RSS_SLOTS {
        let idx = (start + i) % RSS_SLOTS;
        let cur = RSS_KEYS[idx].load(Ordering::Relaxed);
        if cur != KEY_EMPTY && cur != KEY_TOMBSTONE {
            continue;
        }
        if RSS_KEYS[idx]
            .compare_exchange(cur, KEY_CLAIMING, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            RSS_PAGES[idx].store(0, Ordering::Relaxed);
            // Release: the zeroed count happens-before any `find` that
            // acquires this key and starts accounting into the slot.
            RSS_KEYS[idx].store(cr3, Ordering::Release);
            return true;
        }
        // Lost the race for this slot; keep probing.  Nothing was written.
    }
    RSS_ATTACH_FAILURES.fetch_add(1, Ordering::Relaxed);
    false
}

/// Stop tracking `cr3` and release its slot.
///
/// Must run before the CR3's PML4 frame can be recycled into a new address
/// space, or a late accounting call from the dying space could land on the new
/// occupant of the same physical frame.
pub fn detach(cr3: u64) {
    if cr3 == 0 {
        return;
    }
    if let Some(idx) = find(cr3) {
        RSS_PAGES[idx].store(0, Ordering::Relaxed);
        RSS_KEYS[idx].store(KEY_TOMBSTONE, Ordering::Release);
    }
}

/// Adjust the resident count of `cr3` by `delta` pages.
///
/// No-op for an untracked CR3 (kernel address spaces, the bootstrap CR3, a
/// space that lost the attach race).  Callers inside a per-page loop should
/// accumulate and call this once rather than per page.
#[inline]
pub fn account(cr3: u64, delta: i64) {
    if cr3 == 0 || delta == 0 {
        return;
    }
    if let Some(idx) = find(cr3) {
        let prev = RSS_PAGES[idx].fetch_add(delta, Ordering::Relaxed);
        if prev + delta < 0 {
            RSS_UNDERFLOWS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Resident pages currently mapped by `cr3`, or `None` if it is not tracked.
///
/// Lock-free and allocation-free: safe to call from the OOM path, which runs
/// when the machine is already distressed and must not take a lock it may not
/// get (see `mm::oom::invoke_oom_killer`).
pub fn resident_pages(cr3: u64) -> Option<u64> {
    let idx = find(cr3)?;
    let v = RSS_PAGES[idx].load(Ordering::Relaxed);
    Some(if v > 0 { v as u64 } else { 0 })
}

/// Count of address spaces that could not be tracked because the table was
/// full.  Non-zero means [`RSS_SLOTS`] is too small for the workload and some
/// processes are invisible to resident-set-based decisions.
pub fn attach_failures() -> u64 {
    RSS_ATTACH_FAILURES.load(Ordering::Relaxed)
}

/// Count of accounting calls that drove a counter below zero — i.e. a PTE was
/// reported cleared more often than it was reported installed.  Any non-zero
/// value is an accounting defect in the maintenance sites.
pub fn underflow_count() -> u64 {
    RSS_UNDERFLOWS.load(Ordering::Relaxed)
}

/// Number of tracked address spaces.  Diagnostic only.
pub fn tracked_count() -> usize {
    let mut n = 0;
    for slot in RSS_KEYS.iter() {
        let k = slot.load(Ordering::Relaxed);
        if k != KEY_EMPTY && k != KEY_TOMBSTONE && k != KEY_CLAIMING {
            n += 1;
        }
    }
    n
}

/// Count present user leaf PTEs in `cr3` by walking its page tables.
///
/// This is the ground truth [`resident_pages`] is required to match.  It only
/// descends tables that exist, so its cost is proportional to what is actually
/// mapped rather than to the size of the address space — but it still reads up
/// to 512 entries per present table with no lock held, so it is for tests and
/// diagnostics, never for the OOM path (which is why the counter exists).
///
/// A huge leaf counts as the number of 4 KiB frames it covers, matching how
/// the maintenance sites account for one.
///
/// Kernel identity-map leaves (`phys == va` inside the identity window) are
/// **excluded**, matching the exclusion in `VmSpace::clone_for_fork`.  They
/// appear in PML4[0] only on the kernel's own CR3 — which the in-kernel test
/// runner can fork — and are aliases of kernel memory that no process teardown
/// frees.  Counting them would put up to 2^20 phantom pages into a score whose
/// entire purpose is to predict how much memory killing the process returns.
pub fn walk_resident_pages(cr3: u64) -> u64 {
    /// Higher-half physical map base — matches `mm::vmm::PHYS_OFF`.
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    const PAGE_PRESENT: u64 = 1 << 0;
    const PAGE_HUGE: u64 = 1 << 7;
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    if cr3 == 0 {
        return 0;
    }
    let mut resident = 0u64;
    // SAFETY: `cr3` names a live PML4 frame; the higher-half map covers all
    // physical memory, and every dereference below is guarded by a
    // present-bit check on the level above it.  Read-only throughout.
    unsafe {
        let pml4 = (PHYS_OFF + cr3) as *const u64;
        // User space is PML4[0..256]; PML4[256..512] is the shared kernel half.
        for pml4_idx in 0..256usize {
            let pml4e = *pml4.add(pml4_idx);
            if pml4e & PAGE_PRESENT == 0 {
                continue;
            }
            let pdpt = (PHYS_OFF + (pml4e & ADDR_MASK)) as *const u64;
            for pdpt_idx in 0..512usize {
                let pdpte = *pdpt.add(pdpt_idx);
                if pdpte & PAGE_PRESENT == 0 {
                    continue;
                }
                let va_1g = ((pml4_idx as u64) << 39) | ((pdpt_idx as u64) << 30);
                if pdpte & PAGE_HUGE != 0 {
                    let phys_1g = pdpte & !0x3FFF_FFFFu64;
                    if !crate::mm::vmm::is_identity_map_phys(va_1g, phys_1g) {
                        resident += 512 * 512; // one 1 GiB leaf
                    }
                    continue;
                }
                let pd = (PHYS_OFF + (pdpte & ADDR_MASK)) as *const u64;
                for pd_idx in 0..512usize {
                    let pde = *pd.add(pd_idx);
                    if pde & PAGE_PRESENT == 0 {
                        continue;
                    }
                    let va_2m = va_1g | ((pd_idx as u64) << 21);
                    if pde & PAGE_HUGE != 0 {
                        let phys_2m = pde & 0x000F_FFFF_FFE0_0000u64;
                        if !crate::mm::vmm::is_identity_map_phys(va_2m, phys_2m) {
                            resident += 512; // one 2 MiB leaf
                        }
                        continue;
                    }
                    let pt = (PHYS_OFF + (pde & ADDR_MASK)) as *const u64;
                    for pt_idx in 0..512usize {
                        let pte = *pt.add(pt_idx);
                        if pte & PAGE_PRESENT == 0 {
                            continue;
                        }
                        let va = va_2m | ((pt_idx as u64) << 12);
                        if !crate::mm::vmm::is_identity_map_phys(va, pte & ADDR_MASK) {
                            resident += 1;
                        }
                    }
                }
            }
        }
    }
    resident
}
