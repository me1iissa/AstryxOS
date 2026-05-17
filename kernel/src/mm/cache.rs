//! Global Buffer / Page Cache
//!
//! Caches file-backed pages keyed by (mount_index, inode, page_offset_in_file).
//! Prevents redundant disk reads and allows pages to be shared between
//! multiple mappings of the same file region.

extern crate alloc;

use alloc::collections::BTreeMap;
#[cfg(feature = "w215-diag")]
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// True while `prepopulate_file` is actively bulk-loading pages.  The
/// W215 pre-arm hook in `insert` consults this flag and skips arming
/// during the bulk-load phase so the boot-time prepopulate (which
/// inserts ~50 K libxul pages back-to-back) is not perturbed by the
/// DR programming side-effects.  Set by `prepopulate_file` around its
/// inner loop; cleared on exit (and on early return / break).
#[cfg(feature = "w215-diag")]
static PREPOPULATE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Cache key: (mount_index, inode_number, page_aligned_file_offset).
type CacheKey = (usize, u64, u64);

/// A cached physical page.
struct PageCacheEntry {
    /// Physical address of the cached page.
    phys: u64,
    /// Whether the page has been written to (for future writeback).
    dirty: bool,
}

/// Global page cache.
static PAGE_CACHE: Mutex<BTreeMap<CacheKey, PageCacheEntry>> = Mutex::new(BTreeMap::new());

/// W215 pre-arm policy: the `(mount, inode)` tuples that identify the
/// libxul-cluster cache keys in the Firefox demo run.  Any cache::insert
/// whose key matches one of these will attempt to arm a hardware
/// DR1/DR2/DR3 watch on the inserted phys at insert time, so the
/// upstream writer that mutates the cache-resident frame is caught the
/// moment its store retires.
///
/// The exact `(mount, inode)` values are tuned for the current Firefox
/// build: 0x9b is libxul main; 265 / 283 / 289 are the satellite
/// libraries (libpng / libcairo-class) loaded through the libxul dlopen
/// chain that have shown post-hoc CRC mismatches in earlier diagnostic
/// trials.  An empty slice falls back to "match every insert" — only
/// viable for early-boot debug because the DR pool is just 3 slots.
#[cfg(feature = "w215-diag")]
const W215_PREARM_KEYS: &[(usize, u64)] = &[
    (4, 0x9b),   // libxul main
    (4, 265),    // satellite library — CRC mismatch in PR #265 trial
    (4, 283),    // satellite library — CRC mismatch in PR #265 trial
    (4, 289),    // satellite library — CRC mismatch in PR #265 trial
];

/// W215 pre-arm cluster-range filter on phys.  Inserts with phys outside
/// this range are not interesting — the historical fingerprint cluster
/// spans phys roughly 0x32E*–0x39F* (850 MiB – 920 MiB).  We use a
/// generous [256 MiB, 1 GiB) window so the diagnostic is robust to small
/// per-boot layout drift while still excluding the bulk of cold-start
/// prepopulate inserts (which cluster well below 256 MiB).
#[cfg(feature = "w215-diag")]
const W215_PREARM_PHYS_LO: u64 = 0x1000_0000;   // 256 MiB
#[cfg(feature = "w215-diag")]
const W215_PREARM_PHYS_HI: u64 = 0x4000_0000;   // 1 GiB

/// PHYS → kernel-higher-half offset.  Same constant as `mm/pmm.rs` /
/// `mm/w215_crc.rs`; duplicated here to keep this file self-contained.
#[cfg(feature = "w215-diag")]
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Best-effort caller-RIP capture.  Walks one frame up using `rbp`; if
/// the prologue did not save RBP (LTO / `-fomit-frame-pointer`) this
/// returns 0 — the line is still useful from the (mount, inode, phys)
/// triple alone.  Diagnostic-only.
#[cfg(feature = "w215-diag")]
#[inline(never)]
fn caller_rip() -> u64 {
    let rbp: u64;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags));
    }
    if rbp == 0 || (rbp & 7) != 0 || rbp < 0xFFFF_8000_0000_0000 {
        return 0;
    }
    // [rbp+8] = saved return address into `cache::insert`'s caller.
    let ret = unsafe { core::ptr::read_volatile((rbp + 8) as *const u64) };
    ret
}

/// Look up a cached page.  Returns the physical address if found.
pub fn lookup(mount_idx: usize, inode: u64, page_offset: u64) -> Option<u64> {
    PAGE_CACHE
        .lock()
        .get(&(mount_idx, inode, page_offset))
        .map(|e| e.phys)
}

/// Look up a cached page and atomically acquire a guard reference on it.
///
/// The reference count is incremented while the cache lock is still held, so
/// the caller's view of the returned physical address is guaranteed to be alive
/// until a matching `page_ref_dec` is issued.  Without this atomicity, a bare
/// `lookup` + later `page_ref_inc` pair admits a window in which:
///
///   1. A concurrent `cache::insert` collision evicts the old entry and drops
///      the cache's own reference (`page_ref_dec` in `insert`).
///   2. A sibling process's `munmap` / `execve` teardown drops the last PTE
///      reference, driving the refcount to zero.
///   3. `pmm::alloc_page` on a third CPU recycles the frame into a different
///      VMA before the faulting CPU reaches its own `page_ref_inc`.
///
/// The faulting CPU would then install a stale PTE pointing at a recycled
/// frame, aliasing two unrelated virtual address spaces against the same
/// physical frame.  Holding the cache lock across the refcount increment
/// collapses the race window to zero: no concurrent insert can evict the entry,
/// and therefore no munmap can drive the refcount to zero, while this function
/// executes.
///
/// Per Intel SDM Vol. 3A §4.10.5 (page-level coherence requirements) and
/// POSIX mmap(2) MAP_SHARED visibility semantics, every path that installs
/// a PTE must ensure the target frame is alive at the moment of install and
/// remains so until the PTE is removed.  This function satisfies that
/// requirement for the cache-hit path.
///
/// # Caller contract
///
/// The caller MUST release the acquired reference via `page_ref_dec` once it
/// has either:
///   (a) installed a PTE whose own refcount now covers the frame — the acquired
///       guard ref is then redundant and must be dropped; or
///   (b) aborted before PTE installation (OOM, error, etc.) — the acquired
///       guard ref is the last reference and dropping it may free the frame.
///
/// In the alias arm (MAP_SHARED or PROT_READ), the guard ref IS the PTE ref
/// (no separate `page_ref_inc` before `map_page_in` is needed or correct).
/// In the private-copy arm the guard ref is purely protective: after the
/// `copy_nonoverlapping` completes, drop the guard via `page_ref_dec` because
/// the installed PTE refers to `private_phys`, not `cached_phys`.
pub fn lookup_and_acquire(mount_idx: usize, inode: u64, page_offset: u64) -> Option<u64> {
    let cache = PAGE_CACHE.lock();
    let phys = cache.get(&(mount_idx, inode, page_offset))?.phys;
    // Bump the refcount while the cache lock is still held.  This prevents any
    // concurrent `cache::insert` (which holds the same lock before its own
    // `page_ref_dec` on eviction) from driving the count to zero between our
    // lookup and the caller's eventual PTE install.
    crate::mm::refcount::page_ref_inc(phys);
    // W215 diagnostic Arm-2: a lookup_acquire reaching a phys that has an
    // in-flight pre-insert witness implies a sibling-CPU reader has obtained
    // a handle to bytes that the original installer has not yet copied in.
    #[cfg(feature = "firefox-test")]
    crate::mm::w215_diag::preins_check_op(
        phys,
        crate::mm::w215_diag::OP_LOOKUP_ACQUIRE,
        ((page_offset >> 12) & 0xFFFF_FFFF) as u32,
    );
    Some(phys)
}

/// Insert a page into the cache.
///
/// Convenience wrapper for [`insert_with_expected`] that supplies no
/// reference bytes for the post-install source-content diagnostic.
/// Callers that have just read the source bytes from the filesystem
/// SHOULD prefer `insert_with_expected` so the W215 wrong-content guard
/// can fire on a concurrent writer.  Paths that have no source bytes to
/// hand (eviction-then-reinsert, future writeback paths) keep using
/// this entry point.
pub fn insert(mount_idx: usize, inode: u64, page_offset: u64, phys: u64) {
    insert_with_expected(mount_idx, inode, page_offset, phys, None)
}

/// Insert a page into the cache, optionally verifying that the frame's
/// contents match the source-file bytes the caller just read.
///
/// Increments the page's reference count to represent the cache's own
/// reference.  If the key already exists the old entry is replaced and
/// its cache reference is released.
///
/// When the evicted entry's reference count reaches zero, the physical
/// frame is routed through [`crate::mm::tlb::quarantine_free`] rather
/// than freed immediately.  A TLB entry for the evicted frame's virtual
/// address may still be live on a sibling CPU (the cache does not track
/// which CPUs have mapped each frame), so the quarantine grace period —
/// at least one timer ISR on every online CPU — is necessary to
/// guarantee that the stale TLB entry is retired before the frame is
/// recycled.  Per Intel SDM Vol. 3A §4.10.5, paging-structure changes
/// must be propagated to all processors before the physical frame is
/// repurposed.
///
/// ## `expected` — W215 wrong-content guard
///
/// When `Some(reference)`, the diagnostic samples the first 64 bytes of
/// the just-inserted frame and compares them against `reference`.  A
/// mismatch indicates a writer mutated the frame between the caller's
/// successful filesystem read and the cache install — under POSIX
/// read(2) and the install-path contract there is no legitimate kernel
/// writer in that window, so any divergence is a smoking-gun aliasing
/// race (the residual W215 class).  The diagnostic emits a structured
/// `[W215/INSERT-WRONG-CONTENT]` line and bugchecks via
/// [`crate::ke::bugcheck::BUGCHECK_W215_INSERT_WRONG_CONTENT`] so the
/// trial captures full register state at the moment of corruption.
///
/// The check is gated behind `cfg(feature = "w215-diag")` (implies
/// `firefox-test`) and is skipped while `PREPOPULATE_ACTIVE` is set —
/// the bulk-prepopulate phase legitimately overwrites every libxul
/// page once at boot and its own pre-zero + memcpy sequence is the
/// source of truth there, not an `fs.read` reference snapshot.
///
/// Genuinely all-zero source bytes (e.g. sparse-file holes, zero-filled
/// `.bss` segments past the file's true end) are tolerated: if the
/// supplied reference is entirely zero AND the page bytes are entirely
/// zero, the check is skipped to avoid false fires on legitimate
/// zero-content pages.
pub fn insert_with_expected(
    mount_idx: usize,
    inode: u64,
    page_offset: u64,
    phys: u64,
    expected: Option<&[u8; 64]>,
) {
    // Reference parameter is read only inside the `w215-diag` block; mark
    // it used on non-diag builds so the cfg-out does not provoke a warn.
    #[cfg(not(feature = "w215-diag"))]
    let _ = expected;

    // W215 structural-invariant guard: a cache::insert MUST NOT install a
    // frame whose physical address lies inside the kernel image
    // (.text/.rodata/.data/.bss).  The page cache is for filesystem-backed
    // pages; a kernel-static frame as cache contents would mean the kernel
    // is about to be overwritten by a memset/zero-fill in the page-fault
    // install path the moment a userspace mapping demand-faults on the
    // aliased VMA.  This was the observed symptom in the W215
    // `Console::scroll_region_up` corruption (PR #260 trial: Console.fb
    // overwritten because its phys was aliased into a libxul cache key).
    // Emit a single line with full provenance and refuse the insert —
    // diagnostic-only, the caller will then take the cold-path that does
    // not alias kernel static data.
    #[cfg(feature = "w215-diag")]
    {
        if crate::mm::pmm::is_kernel_static_phys(phys) {
            let (kbase, kend) = crate::mm::pmm::kernel_image_phys_range();
            // Best-effort RIP capture: read the caller's return address
            // through the saved frame pointer.  This is a one-shot
            // diagnostic; if RBP is clobbered we just log 0.
            let rip = caller_rip();
            crate::serial_println!(
                "[W215/INSERT-OF-KERNEL-STATIC] phys={:#x} mount={} inode={} \
                 offset={:#x} kernel_phys=[{:#x},{:#x}) caller_rip={:#x}",
                phys, mount_idx, inode, page_offset, kbase, kend, rip,
            );
            // Bail out — do NOT insert.  The page cache must not own a
            // kernel-static phys.
            return;
        }
    }

    // Capture the evicted frame (if any) before releasing the lock so
    // we can call quarantine_free without holding the cache mutex, which
    // would create a lock-order cycle (cache → TLB quarantine → PMM).
    let evicted_zero_rc: Option<u64>;

    {
        let mut cache = PAGE_CACHE.lock();
        let old = cache.insert(
            (mount_idx, inode, page_offset),
            PageCacheEntry { phys, dirty: false },
        );
        // The cache now holds a reference to the new page.
        crate::mm::refcount::page_ref_inc(phys);

        if let Some(old_entry) = old {
            // Drop the cache's own reference to the evicted page.
            // If rc reaches zero, the frame has no remaining references
            // (no live PTEs, no other cache users) and must be freed.
            let new_rc = crate::mm::refcount::page_ref_dec(old_entry.phys);
            evicted_zero_rc = if new_rc == 0 { Some(old_entry.phys) } else { None };
            #[cfg(feature = "firefox-test")]
            {
                crate::mm::w215_diag::prov_record(
                    old_entry.phys,
                    crate::mm::w215_diag::KIND_EVICT,
                    crate::mm::w215_diag::pack_cache_key(inode, page_offset),
                );
                #[cfg(feature = "w215-diag")]
                crate::mm::w215_crc::record_evict(old_entry.phys);
            }
        } else {
            evicted_zero_rc = None;
        }
    } // release cache lock

    // W215 diagnostic Arm-1: record the INSERT event for `phys`.  Arm-2:
    // clear the pre-insert witness, if any — the happy path.
    #[cfg(feature = "firefox-test")]
    {
        crate::mm::w215_diag::prov_record(
            phys,
            crate::mm::w215_diag::KIND_INSERT,
            crate::mm::w215_diag::pack_cache_key(inode, page_offset),
        );
        let _ = crate::mm::w215_diag::preins_clear_on_insert(phys);
        // Arm-1 CRC walker shadow-table snapshot.  Done AFTER the cache
        // lock is released so we do not hold two locks at once; the
        // shadow-table mutex is the only lock involved.  Gated behind
        // `w215-diag` so the demo path does not perform the per-insert
        // 4 KiB CRC scan that touches the ~2 MiB shadow table.
        #[cfg(feature = "w215-diag")]
        crate::mm::w215_crc::record_insert(phys, inode, page_offset);

        // W215 Arm-1.5 pre-arm: for cache-keys that fall in the libxul
        // cluster (configured via `W215_PREARM_KEY`), arm a hardware
        // DR1/DR2/DR3 write-watchpoint on the just-inserted frame.  The
        // DR pool is shared between concurrent pre-arms — most inserts
        // are no-ops because the pool is already saturated; that's fine,
        // the goal is to catch the *next* corruption while a victim is
        // armed.  See `arch/x86_64/debug_reg.rs::arm_preinsert_watchpoint`
        // for the slot-allocation policy.
        //
        // BOOT-PHASE GUARD: the prepopulate path inserts ~50 K libxul
        // pages through this code path during boot.  We only want to
        // arm during the *steady-state* fault-driven cache::insert path
        // (the one where the W215 fingerprint reproduces), NOT during
        // the bulk-prepopulate phase where every page goes through here.
        // The prepopulate hook signals it is active via
        // `crate::mm::cache::PREPOPULATE_ACTIVE`; if that's set, skip the
        // arm.  This bounds the arm activity to ~3 IPI-free DR programmings
        // per fire-and-recycle cycle in steady state.
        #[cfg(feature = "w215-diag")]
        if !PREPOPULATE_ACTIVE.load(Ordering::Acquire) {
            let want_prearm = if W215_PREARM_KEYS.is_empty() {
                true
            } else {
                W215_PREARM_KEYS
                    .iter()
                    .any(|&(m, i)| mount_idx == m && inode == i)
            };
            if want_prearm
                && phys >= W215_PREARM_PHYS_LO
                && phys < W215_PREARM_PHYS_HI
                && (phys & 0xFFF) == 0
            {
                let linear = PHYS_OFF + phys;
                // 8-byte W-only — matches the post-hoc DR0 width so the same
                // dispatcher path can interpret the fire.  The first qword
                // of the frame is as good a witness as any: any writer that
                // mutates the page is overwhelmingly likely to write at
                // least one qword starting at the page base (memset, memcpy,
                // struct store).
                let _ = crate::arch::x86_64::debug_reg::arm_preinsert_watchpoint(
                    linear, 8, phys, inode, page_offset,
                );
            }
        }
    }

    // ── W215 post-insert source-content guard ──────────────────────────────
    //
    // After the cache record is installed (and the existing diagnostic
    // hooks have run), sample the first 64 bytes of the just-inserted
    // frame and compare them against the reference snapshot the caller
    // captured immediately after its `fs.read` returned.  Per POSIX
    // read(2) the install path holds the only kernel-side handle to the
    // freshly-allocated PMM frame from `pmm::alloc_page` through
    // `cache::insert`; the bytes at the moment of insert MUST equal the
    // bytes the FS driver wrote.  Any divergence implies a sibling-CPU
    // writer with a still-live PTE to the recycled frame — the W215
    // aliasing class under investigation.
    //
    // The check is skipped:
    //   - while `PREPOPULATE_ACTIVE` is set (bulk-loader has its own
    //     pre-zero + memcpy as the source of truth);
    //   - when no reference snapshot was supplied (legacy `insert`
    //     callers — eviction-then-reinsert, future writeback);
    //   - when both reference and page contents are entirely zero
    //     (sparse-file holes, zero-filled tails past EOF).
    //
    // On mismatch: emit a structured `[W215/INSERT-WRONG-CONTENT]` line
    // with full provenance, then bugcheck via
    // `BUGCHECK_W215_INSERT_WRONG_CONTENT` so the trial captures
    // register state at the moment of the divergence.  Per Intel SDM
    // Vol. 3A §4.10.5 the writer must have observed the PMM frame
    // before the cache lock was acquired — a tractable invariant to
    // hunt with the bugcheck stack.
    #[cfg(feature = "w215-diag")]
    if let Some(reference) = expected {
        if !PREPOPULATE_ACTIVE.load(Ordering::Acquire) {
            // SAFETY: the higher-half identity map covers every PMM
            // frame, and the just-inserted frame is alive (cache holds
            // a ref from `page_ref_inc` above).  We read 64 bytes
            // through a volatile slice copy to avoid the compiler
            // re-ordering the read past the install.
            let mut sample = [0u8; 64];
            let src = (PHYS_OFF + phys) as *const u8;
            for i in 0..64 {
                sample[i] = unsafe { core::ptr::read_volatile(src.add(i)) };
            }
            // Allow legitimate all-zero source pages (sparse file hole,
            // .bss-extended tail).  If both sides are zero the install
            // path is correct by definition.
            let ref_all_zero = reference.iter().all(|&b| b == 0);
            let sample_all_zero = sample.iter().all(|&b| b == 0);
            let trivial_zero_match = ref_all_zero && sample_all_zero;
            if !trivial_zero_match && sample[..] != reference[..] {
                let rip = caller_rip();
                // Emit hex pairs for ref/observed.  Use a fixed-format
                // line so `qemu-harness.py wait` can match the prefix.
                crate::serial_println!(
                    "[W215/INSERT-WRONG-CONTENT] phys={:#x} mount={} inode={} \
                     offset={:#x} caller_rip={:#x}",
                    phys, mount_idx, inode, page_offset, rip,
                );
                crate::serial_println!(
                    "[W215/INSERT-WRONG-CONTENT/REF]  {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x}",
                    reference[0],  reference[1],  reference[2],  reference[3],
                    reference[4],  reference[5],  reference[6],  reference[7],
                    reference[8],  reference[9],  reference[10], reference[11],
                    reference[12], reference[13], reference[14], reference[15],
                    reference[16], reference[17], reference[18], reference[19],
                    reference[20], reference[21], reference[22], reference[23],
                    reference[24], reference[25], reference[26], reference[27],
                    reference[28], reference[29], reference[30], reference[31],
                );
                crate::serial_println!(
                    "[W215/INSERT-WRONG-CONTENT/REF2] {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x}",
                    reference[32], reference[33], reference[34], reference[35],
                    reference[36], reference[37], reference[38], reference[39],
                    reference[40], reference[41], reference[42], reference[43],
                    reference[44], reference[45], reference[46], reference[47],
                    reference[48], reference[49], reference[50], reference[51],
                    reference[52], reference[53], reference[54], reference[55],
                    reference[56], reference[57], reference[58], reference[59],
                    reference[60], reference[61], reference[62], reference[63],
                );
                crate::serial_println!(
                    "[W215/INSERT-WRONG-CONTENT/OBS]  {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x}",
                    sample[0],  sample[1],  sample[2],  sample[3],
                    sample[4],  sample[5],  sample[6],  sample[7],
                    sample[8],  sample[9],  sample[10], sample[11],
                    sample[12], sample[13], sample[14], sample[15],
                    sample[16], sample[17], sample[18], sample[19],
                    sample[20], sample[21], sample[22], sample[23],
                    sample[24], sample[25], sample[26], sample[27],
                    sample[28], sample[29], sample[30], sample[31],
                );
                crate::serial_println!(
                    "[W215/INSERT-WRONG-CONTENT/OBS2] {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} \
                     {:02x}{:02x}{:02x}{:02x}",
                    sample[32], sample[33], sample[34], sample[35],
                    sample[36], sample[37], sample[38], sample[39],
                    sample[40], sample[41], sample[42], sample[43],
                    sample[44], sample[45], sample[46], sample[47],
                    sample[48], sample[49], sample[50], sample[51],
                    sample[52], sample[53], sample[54], sample[55],
                    sample[56], sample[57], sample[58], sample[59],
                    sample[60], sample[61], sample[62], sample[63],
                );
                crate::ke::bugcheck::ke_bugcheck(
                    crate::ke::bugcheck::BUGCHECK_W215_INSERT_WRONG_CONTENT,
                    phys,
                    mount_idx as u64,
                    inode,
                    page_offset,
                );
            }
        }
    }

    if let Some(old_phys) = evicted_zero_rc {
        // Defer PMM release through the quarantine to ensure any stale
        // TLB entry on a sibling CPU is retired before the frame is
        // recycled.  See module-level doc for the quiescent-state
        // guarantee.
        crate::mm::tlb::quarantine_free(old_phys);
    }
}

/// Mark a cached page as dirty (written to).
pub fn mark_dirty(mount_idx: usize, inode: u64, page_offset: u64) {
    if let Some(entry) = PAGE_CACHE.lock().get_mut(&(mount_idx, inode, page_offset)) {
        entry.dirty = true;
    }
}

/// Evict a page from the cache, releasing the cache's reference.
/// Returns the physical address of the evicted page, if any.
pub fn evict(mount_idx: usize, inode: u64, page_offset: u64) -> Option<u64> {
    let mut cache = PAGE_CACHE.lock();
    if let Some(entry) = cache.remove(&(mount_idx, inode, page_offset)) {
        // Caller takes ownership of the phys frame; freeing it (with proper
        // shootdown) is the caller's responsibility.  Here we only release
        // the cache's reference.
        let _ = crate::mm::refcount::page_ref_dec(entry.phys);
        // W215 diagnostic Arm-1 / Arm-2.
        #[cfg(feature = "firefox-test")]
        {
            crate::mm::w215_diag::prov_record(
                entry.phys,
                crate::mm::w215_diag::KIND_EVICT,
                crate::mm::w215_diag::pack_cache_key(inode, page_offset),
            );
            crate::mm::w215_diag::preins_check_op(
                entry.phys,
                crate::mm::w215_diag::OP_EVICT,
                ((page_offset >> 12) & 0xFFFF_FFFF) as u32,
            );
            #[cfg(feature = "w215-diag")]
            crate::mm::w215_crc::record_evict(entry.phys);
        }
        Some(entry.phys)
    } else {
        None
    }
}

/// Mark all dirty pages for a given inode as clean.
/// (Actual writeback through VFS would be added in a future milestone.)
pub fn sync_inode(mount_idx: usize, inode: u64) {
    let mut cache = PAGE_CACHE.lock();
    for ((m, i, _), entry) in cache.iter_mut() {
        if *m == mount_idx && *i == inode {
            entry.dirty = false;
        }
    }
}

/// Pre-populate the page cache for an entire file.
///
/// Reads every 4KB page of the file from disk into PMM-allocated pages
/// and inserts them into the page cache.  Subsequent demand-page faults
/// for this file will hit the cache (instant) instead of reading from
/// disk (slow ATA PIO on WSL2/KVM).
///
/// Reads are issued in multi-megabyte bursts so each `Filesystem::read` call
/// amortises its inode lookup, cluster-chain walk, and lock acquisitions over
/// many pages — and the underlying block driver coalesces sequential clusters
/// into a small number of large multi-sector requests instead of one per
/// page.  After the burst arrives, we copy each page into a freshly allocated
/// PMM frame so the page cache continues to own per-page physical frames as
/// the rest of the VM expects.
///
/// Returns the number of pages cached.
pub fn prepopulate_file(path: &str) -> usize {
    use crate::vfs;

    let (mount_idx, inode) = match vfs::resolve_path(path) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    // Snapshot the FS handle and drop MOUNTS before any FS dispatch:
    // stat/read here could fault on the chunk buffer's kernel pages and
    // re-enter the PF handler, which itself needs MOUNTS (#82).
    let fs: alloc::sync::Arc<dyn vfs::FileSystemOps> = {
        let mounts = vfs::MOUNTS.lock();
        match mounts.get(mount_idx) {
            Some(m) => m.fs.clone(),
            None => return 0,
        }
    };
    let file_size = match fs.stat(inode) {
        Ok(s) => s.size,
        Err(_) => return 0,
    };

    let page_size = crate::mm::pmm::PAGE_SIZE as u64;
    let mut cached = 0usize;
    let phys_off: u64 = 0xFFFF_8000_0000_0000;

    // W215 pre-arm guard: suppress the cache::insert pre-arm hook for
    // the duration of this bulk-prepopulate.  The hook is intended to
    // fire on steady-state fault-driven inserts (the path where the
    // W215 fingerprint reproduces), not on this back-to-back load that
    // touches every libxul page once at boot.
    #[cfg(feature = "w215-diag")]
    PREPOPULATE_ACTIVE.store(true, Ordering::Release);
    // Restore-on-exit pattern via a small RAII guard.
    #[cfg(feature = "w215-diag")]
    struct PrepGuard;
    #[cfg(feature = "w215-diag")]
    impl Drop for PrepGuard {
        fn drop(&mut self) {
            PREPOPULATE_ACTIVE.store(false, Ordering::Release);
        }
    }
    #[cfg(feature = "w215-diag")]
    let _prep_guard = PrepGuard;

    // Read in 2 MiB bursts.  Sized to match the BlockDevice multi-sector
    // batch window so each `read` translates into a small number of
    // underlying multi-sector requests (the block driver caps each request
    // at 1 MiB to keep the contiguous-buffer requirement modest, so a
    // 2 MiB burst becomes two adjacent virtio requests).  This amortises
    // the per-request KVM/MMIO round-trip cost (typical 3-5 ms per virtio
    // request) over many pages — the 38k-page libxul prepopulate compresses
    // into ~75 bursts (~150 underlying requests) instead of the original
    // 38k page-by-page reads.
    const CHUNK_PAGES: usize = 512;
    const CHUNK_BYTES: usize = CHUNK_PAGES * 4096;
    let mut chunk_buf: alloc::vec::Vec<u8> = alloc::vec![0u8; CHUNK_BYTES];

    let mut offset: u64 = 0;
    while offset < file_size {
        // Stop if PMM is running low — keep 20K pages (80MB) free for kernel ops.
        if crate::mm::pmm::free_page_count() < 20_000 {
            crate::serial_println!("[CACHE] prepopulate stopping: PMM low ({} free pages)",
                crate::mm::pmm::free_page_count());
            break;
        }

        let chunk_start = offset & !(CHUNK_BYTES as u64 - 1); // CHUNK-aligned
        let chunk_remaining = file_size.saturating_sub(chunk_start);
        let this_chunk = core::cmp::min(chunk_remaining as usize, CHUNK_BYTES);

        // If every page in this chunk is already cached, skip the disk read.
        let mut all_cached = true;
        for page_idx in 0..((this_chunk + 4095) / 4096) {
            let page_off = chunk_start + (page_idx as u64) * page_size;
            if lookup(mount_idx, inode, page_off).is_none() {
                all_cached = false;
                break;
            }
        }
        if all_cached {
            offset = chunk_start + this_chunk as u64;
            continue;
        }

        // Issue one filesystem read for the entire chunk.  The FAT32 driver
        // detects the contiguous cluster run, computes the matching disk
        // sector range, and issues large multi-sector block-device calls —
        // one virtio request per up-to-1 MiB-aligned segment of the burst.
        // (`fs` was snapshotted above; MOUNTS is not held during the read.)
        //
        // Per POSIX read(2), a successful read may return fewer bytes than
        // requested (short read).  We MUST honour the returned length —
        // bytes beyond it in chunk_buf are stale heap content from prior
        // iterations and must not be installed into the page cache.
        let read_buf = &mut chunk_buf[..this_chunk];
        let bytes_read = match fs.read(inode, chunk_start, read_buf) {
            Ok(n) => n,
            Err(_) => break,
        };
        if bytes_read == 0 {
            // EOF or transient zero-return: skip this chunk and advance so
            // the outer loop does not spin forever.
            offset = chunk_start + this_chunk as u64;
            continue;
        }
        // Zero-fill the unread tail of chunk_buf so subsequent page-slicing
        // below never copies stale heap bytes into the page cache.
        if bytes_read < this_chunk {
            // SAFETY: read_buf covers [0..this_chunk]; bytes_read <= this_chunk.
            unsafe {
                core::ptr::write_bytes(
                    read_buf.as_mut_ptr().add(bytes_read),
                    0,
                    this_chunk - bytes_read,
                );
            }
        }

        // Split the chunk into 4 KiB pages, allocating a PMM frame for each
        // and inserting it into the page cache.
        let mut page_off_in_chunk = 0usize;
        while page_off_in_chunk < this_chunk {
            let page_off = chunk_start + page_off_in_chunk as u64;
            if lookup(mount_idx, inode, page_off).is_some() {
                page_off_in_chunk += page_size as usize;
                continue;
            }
            if let Some(phys) = crate::mm::pmm::alloc_page() {
                let copy_len = core::cmp::min(
                    page_size as usize,
                    this_chunk - page_off_in_chunk,
                );
                let dst = (phys_off + phys) as *mut u8;
                // W215 diagnostic Arm-1+2: record the PHYS_OFF pre-insert
                // write intent.  preins_register opens the race window;
                // the matching cache::insert below will close it.
                #[cfg(feature = "firefox-test")]
                {
                    crate::mm::w215_diag::prov_record(
                        phys,
                        crate::mm::w215_diag::KIND_PHYS_OFF_WRITE_PRE_INSERT,
                        crate::mm::w215_diag::pack_cache_key(inode, page_off),
                    );
                    crate::mm::w215_diag::preins_register(
                        phys,
                        crate::mm::w215_diag::SITE_CACHE_PREPOPULATE,
                        mount_idx, inode, page_off,
                    );
                }
                // SAFETY: PMM hands out an exclusive 4 KiB physical frame.
                // The higher-half identity map covers it, and the page cache
                // is the sole owner once we insert.
                //
                // Always zero the destination frame before copying.  PMM does
                // not guarantee zeroed pages on alloc (Intel SDM Vol. 3A,
                // §4.10.5 describes no such invariant), so any partial copy
                // — whether from a short fs.read or a tail-of-file page —
                // would expose PMM-recycled content to user-space if we only
                // zero when copy_len < page_size.  The unconditional bzero is
                // inexpensive relative to the prior disk I/O and eliminates
                // the class of stale-content faults entirely.
                unsafe {
                    core::ptr::write_bytes(dst, 0, page_size as usize);
                    core::ptr::copy_nonoverlapping(
                        chunk_buf.as_ptr().add(page_off_in_chunk),
                        dst,
                        copy_len,
                    );
                }
                insert(mount_idx, inode, page_off, phys);
                cached += 1;
            } else {
                // OOM — bail out of the inner loop; outer loop will hit the
                // free-page guard and exit on the next iteration.
                break;
            }
            page_off_in_chunk += page_size as usize;

            // Log progress every 4000 pages (~16MB).
            if cached > 0 && cached % 4000 == 0 {
                crate::serial_println!("[CACHE] prepopulate {}: {} pages ({} MB)",
                    path, cached, cached * 4 / 1024);
            }
        }

        offset = chunk_start + this_chunk as u64;
    }
    cached
}

/// Conditionally evict a cache entry, but only if the stored physical address
/// matches `expected_phys`.
///
/// This is used by the demand-paging path to reclaim a redundant frame when a
/// concurrent `cache::insert` on the same (mount, inode, offset) key has
/// already replaced the entry with a different physical address.  A plain
/// `evict` would incorrectly discard the winner's entry and leak a reference.
///
/// Returns `true` if the entry was found, matched, and removed.
pub fn evict_if_phys(
    mount_idx: usize,
    inode: u64,
    page_offset: u64,
    expected_phys: u64,
) -> bool {
    let key = (mount_idx, inode, page_offset);
    // W215 diagnostic Arm-2: an evict_if_phys call against a phys with an
    // in-flight pre-insert witness is a race candidate.
    #[cfg(feature = "firefox-test")]
    crate::mm::w215_diag::preins_check_op(
        expected_phys,
        crate::mm::w215_diag::OP_EVICT_IF_PHYS,
        ((page_offset >> 12) & 0xFFFF_FFFF) as u32,
    );
    let mut cache = PAGE_CACHE.lock();
    // Peek before removing so we don't evict a different winner's entry.
    let matches = cache
        .get(&key)
        .map(|e| e.phys == expected_phys)
        .unwrap_or(false);
    if matches {
        cache.remove(&key);
        // Release the cache's reference to the evicted frame.
        let _ = crate::mm::refcount::page_ref_dec(expected_phys);
        #[cfg(feature = "firefox-test")]
        {
            crate::mm::w215_diag::prov_record(
                expected_phys,
                crate::mm::w215_diag::KIND_EVICT,
                crate::mm::w215_diag::pack_cache_key(inode, page_offset),
            );
            #[cfg(feature = "w215-diag")]
            crate::mm::w215_crc::record_evict(expected_phys);
        }
        true
    } else {
        false
    }
}

/// Return cache statistics: (total_entries, dirty_entries).
pub fn stats() -> (usize, usize) {
    let cache = PAGE_CACHE.lock();
    let total = cache.len();
    let dirty = cache.values().filter(|e| e.dirty).count();
    (total, dirty)
}

/// Walk the page cache and return the cache key for a given physical frame.
///
/// Returns `Some((mount_idx, inode, page_offset))` if any live cache entry holds
/// `phys` as its backing physical frame; `None` otherwise.  An O(n) walk is
/// acceptable here: this predicate is only reachable from `#[cfg(feature =
/// "firefox-test")]` PFH instrumentation where `n` ≈ 40 K (libxul) and the
/// call happens at most once per writable PTE install.
///
/// Per-entry `phys` comparison is exact — the cache holds one physical frame per
/// key and frames are 4 KiB-aligned, so a u64 equality test is sufficient.
#[cfg(feature = "firefox-test")]
pub fn is_phys_in_cache(phys: u64) -> Option<(usize, u64, u64)> {
    // W215 diagnostic Arm-2: probe BEFORE taking the cache lock so the
    // witness check is not serialised against insert.  A racing pre-insert
    // window straddles the cache-lock boundary at the insert site.
    crate::mm::w215_diag::preins_check_op(
        phys, crate::mm::w215_diag::OP_IS_PHYS_IN_CACHE, 0,
    );
    let cache = PAGE_CACHE.lock();
    for ((mount_idx, inode, page_offset), entry) in cache.iter() {
        if entry.phys == phys {
            return Some((*mount_idx, *inode, *page_offset));
        }
    }
    None
}

/// Audit the page cache for H1 invariant violations: any cached entry whose
/// physical frame has a reference count of zero.
///
/// A zero-refcount entry indicates the cache holds a pointer to a physical
/// frame that has no live PTE covering it.  If the PMM later recycles that
/// frame via `alloc_page`, the next cache-hit demand fault installs a PTE to
/// the wrong physical page — the aliasing class under investigation (W215).
///
/// This is a purely read-only walk; it never modifies cache or refcount state.
/// The serial output format is structured for `qemu-harness.py grep` / `wait`:
///
///   `[CACHE/AUDIT] total_entries=N orphan_count=M`
///   `[CACHE/AUDIT/ORPHAN] key=(mount,inode,0xOFFSET) phys=0xPHYS rc=0`
///
/// At most 16 orphan lines are emitted per call to avoid serial flood.
///
/// Returns `(total_entries, orphan_count)`.
#[cfg(any(feature = "firefox-test", feature = "test-mode"))]
pub fn audit_invariant() -> (usize, usize) {
    use crate::mm::refcount::page_ref_count;
    use core::fmt::Write as _;

    let cache = PAGE_CACHE.lock();
    let total = cache.len();
    let mut orphan_count = 0usize;
    let mut logged = 0usize;

    for ((mount_idx, inode, page_offset), entry) in cache.iter() {
        let rc = page_ref_count(entry.phys);
        if rc == 0 {
            orphan_count += 1;
            if logged < 16 {
                let mut buf = alloc::string::String::with_capacity(128);
                let _ = write!(
                    buf,
                    "[CACHE/AUDIT/ORPHAN] key=({},{},{:#x}) phys={:#x} rc=0",
                    mount_idx, inode, page_offset, entry.phys,
                );
                crate::serial_println!("{}", buf);
                logged += 1;
            }
        }
    }

    crate::serial_println!(
        "[CACHE/AUDIT] total_entries={} orphan_count={}",
        total, orphan_count,
    );
    (total, orphan_count)
}
