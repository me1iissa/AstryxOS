//! Stack-page write provenance ring — F3 BUCKET writer attribution.
//!
//! ## Problem
//!
//! BUCKET F3 (per `[[ssp_mode_a_vs_b_dispositive_2026_05_20]]` and Phase 4
//! `[[phase_4_post_aslr_fs_base_trace_2026_05_21]]`): the libxul function's
//! SSP-instrumented prologue stores its master canary at user VA
//! `saved_slot = [caller_rsp + 0x50] = 0x3f5e7c5850` for the trapping TID 7.
//! Between that prologue store and the matching epilogue compare, *some*
//! kernel code path writes a heap-pointer-shaped value (e.g.
//! `0x3feef73910`) into the slot, the epilogue's `cmp 0x50(%rsp), %rax`
//! disagrees with the live `*fs:0x28`, musl's `__stack_chk_fail` runs
//! (`hlt; ret` at user RIP `0x7f000001c7f9`), and a CPL-3 `#GP` fires.
//!
//! K2b ([[k2b-f3-user-writer-2026-05-20]]) ruled out the *user-VA-DR*
//! channel: 32/32 watchpoint fires were CPL=3.  But DR watchpoints only
//! catch writes that go through the *linear* address (Intel SDM Vol. 3B
//! §17.2.4) — they miss writes through the kernel direct map
//! (`PHYS_OFF + phys`) that the kernel uses for *every* kernel→user-page
//! write today (signal-frame builder, vfork helper-stack seed,
//! `setup_user_stack`, clone-child TLS bootstrap, ...).  This ring closes
//! that blind spot.
//!
//! The Phase 4 `[FAULT/PHYS/ALLOCSHADOW]` already names the kernel
//! `pmm::alloc_page_locked` site that handed out the frame backing
//! `saved_slot` (172/174 ticks before the trap).  This ring names *what
//! kernel-mode code wrote a heap-pointer into it after that allocation*.
//!
//! ## Design
//!
//! Two indexes over the same set of records:
//!
//! - **By-phys ring** (256 entries, direct-addressed by `pfn & MASK`):
//!   answers "what were the last writes to this phys frame?".  Read at
//!   `[SSP-DIAG-STACK-PROV]` time keyed on `saved_slot_phys`.  The 256-entry
//!   table covers `256 × 4 KiB = 1 MiB` of physical address space without
//!   aliasing; with `pfn % 256` direct addressing, frames spaced by 1 MiB
//!   alias.  In practice the canary's backing frame is in the recently-
//!   allocated set (~1 MiB-spread per the PMM's free-list policy) so
//!   collision rate is bounded.
//!
//! - **Append-only sequence ring** (also 256 entries): every record is
//!   stamped with a monotonic `seq` counter.  Allows post-mortem ordering
//!   of writes against `[SSP-DIAG] sc=…` when the by-phys index aliases.
//!
//! Hot path emits no serial output — all logging happens at trap time when
//! `dump_for_phys` is called.  Each `record_write` call costs ≤ 8 atomic
//! stores; safe to invoke from any kernel context that holds (or doesn't
//! need) the relevant locks.
//!
//! Window gate: writes whose target user VA is OUTSIDE the documented
//! thread-stack range `[STACK_PROV_VA_LO, STACK_PROV_VA_HI)` are dropped.
//! Per Phase 4's VMA-DUMP, TID 7's stack VMA sits at `0x3f5e_785000` —
//! comfortably inside `[0x3f00_0000_0000, 0x4000_0000_0000)`.  Other
//! callers (e.g. `setup_user_stack` for the main thread at
//! `USER_STACK_TOP=0x7fff_…`) fall outside the window and are dropped.
//!
//! ## Output format
//!
//! Three line shapes, all gated by the existing `SSP_DIAG_MAX` cap so the
//! serial-log volume stays bounded:
//!
//! ```text
//! [SSP-DIAG-STACK-PROV] phys=<#x> entries=<n> recorded=<n> displaced=<n>
//! [SSP-DIAG-STACK-PROV-W] seq=<n> idx=<n> phys=<#x> va=<#x> val=<#x>
//!                         pid=<n> tid=<n> rip=<#x> sc=<n> tick=<n>
//!                         cpu=<n> site=<tag>
//! [SSP-DIAG-STACK-PROV-END] phys=<#x> emitted=<n>
//! ```
//!
//! `site=<tag>` is a short ASCII label naming the writer site (one of
//! `VFORK_STACK_SEED`, `VFORK_TLS_INIT`, `ELF_AUXV`, `ELF_AUXV_BYTES`,
//! `EXEC_TRAMP`, `EXEC_TEB`).  Each call to `record_write` carries a
//! const tag so the post-mortem can identify the call site without
//! addr2line on a stripped kernel ELF.
//!
//! ## What it cannot catch
//!
//! - Writes through the user VA itself (caught by `f3-watch` DR0–DR3, per
//!   `[[track-k-f3-provenance-2026-05-20]]`).
//! - Writes from another process's CR3 — the ring records `cr3_low16` so
//!   cross-CR3 writes are still distinguishable in the dump.
//! - Writes the *PMM* makes during page-zeroing (uncommon path; zero-fill
//!   produces zeroes, not heap pointers — out of scope).
//!
//! ## Refs
//!
//! - Intel SDM Vol. 3A §4.6 (SMAP / user-VA writes); Vol. 3B §17.2.4
//!   (debug registers — linear-VA only).
//! - POSIX `vfork(2)` / `clone(2)`; ELF gABI §6 (auxiliary vector).
//! - Saga discipline: `[[w215-saga-antipattern-2026-05-16]]` — diagnostics
//!   first, no fix in this dispatch.

#![cfg(feature = "stack-prov")]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ── Window gate ───────────────────────────────────────────────────────────

/// Lower bound of the thread-stack VA window watched by this ring.  Picked
/// to enclose the AstryxOS mmap-allocator's 0x3f-range thread-stack
/// allocations per Phase 4 §6.a (VMA-DUMP shows TID 7's stack VMA at
/// `0x3f5e_785000`).  Generous: covers `0x3f00_…` through `0x3fff_…`.
pub const STACK_PROV_VA_LO: u64 = 0x0000_3f00_0000_0000;

/// Upper (exclusive) bound — `0x4000_0000_0000`.  Anything at or above
/// this is left to the existing `[USER_STACK_RING_LO, USER_STACK_RING_HI)`
/// PTE-change ring (which covers `0x7fff_…` per `mm::w215_diag`).
pub const STACK_PROV_VA_HI: u64 = 0x0000_4000_0000_0000;

#[inline]
fn in_window(va: u64) -> bool {
    va >= STACK_PROV_VA_LO && va < STACK_PROV_VA_HI
}

// ── Site tags ─────────────────────────────────────────────────────────────
//
// Each `record_write` site passes a const tag.  Keep these enumerated
// here (and as a single source of truth for `site_str`) so post-mortem
// log analysis can name the writer without addr2line.

pub const SITE_VFORK_STACK_SEED: u8 = 1; // alloc_vfork_child_stack: write arg_word at top-8
pub const SITE_VFORK_TLS_INIT:   u8 = 2; // alloc_vfork_child_tls: self-ptr + cancel-state
pub const SITE_ELF_AUXV:         u8 = 3; // setup_user_stack u64 writes (argc/envp/auxv)
pub const SITE_ELF_AUXV_BYTES:   u8 = 4; // setup_user_stack byte-slice writes (argv strings)
pub const SITE_EXEC_TRAMP:       u8 = 5; // proc/usermode build_stub_trampoline_page
pub const SITE_EXEC_TEB:         u8 = 6; // proc/usermode TEB zero+init
pub const SITE_GENERIC:          u8 = 7; // any future caller without a dedicated tag

fn site_str(tag: u8) -> &'static str {
    match tag {
        SITE_VFORK_STACK_SEED => "VFORK_STACK_SEED",
        SITE_VFORK_TLS_INIT   => "VFORK_TLS_INIT",
        SITE_ELF_AUXV         => "ELF_AUXV",
        SITE_ELF_AUXV_BYTES   => "ELF_AUXV_BYTES",
        SITE_EXEC_TRAMP       => "EXEC_TRAMP",
        SITE_EXEC_TEB         => "EXEC_TEB",
        SITE_GENERIC          => "GENERIC",
        _                     => "?",
    }
}

// ── Ring storage ──────────────────────────────────────────────────────────

const RING_SIZE: usize = 256;
const RING_MASK: u64 = (RING_SIZE - 1) as u64;

/// One slot in the by-phys ring.  All fields are stored atomically with
/// `Relaxed` ordering — the diagnostic reader tolerates torn tuples in
/// the rare case of concurrent record/read.
#[repr(C)]
struct Entry {
    /// Phys page (4 KiB-aligned) the write landed on.  `0` = slot empty.
    phys: AtomicU64,
    /// User VA that the write resolved to.
    va: AtomicU64,
    /// Value the writer stored (truncated to 64 bits; useful for
    /// matching against `saved_canary` shape).
    val: AtomicU64,
    /// Sequence counter at record time.
    seq: AtomicU64,
    /// Recording TID (lower 32 bits) packed with PID (upper 32 bits).
    pid_tid: AtomicU64,
    /// Caller-RIP (kernel) so addr2line names the writer site.
    rip: AtomicU64,
    /// Packed metadata: [63:32]=syscall_count_low32, [31:16]=tick_low16,
    /// [15:8]=cpu, [7:0]=site_tag.  Truncated values are fine — these
    /// are diagnostic anchors, not authoritative.
    packed: AtomicU64,
    /// CR3 low 16 bits (PML4 phys >> 12 & 0xFFFF), so cross-AS writes are
    /// distinguishable from same-AS writes in the dump.
    cr3_lo16: AtomicU64,
}

impl Entry {
    const fn new() -> Self {
        Self {
            phys: AtomicU64::new(0),
            va: AtomicU64::new(0),
            val: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            pid_tid: AtomicU64::new(0),
            rip: AtomicU64::new(0),
            packed: AtomicU64::new(0),
            cr3_lo16: AtomicU64::new(0),
        }
    }
}

struct Ring {
    slots: [Entry; RING_SIZE],
}

impl Ring {
    const fn new() -> Self {
        const E: Entry = Entry::new();
        Self { slots: [E; RING_SIZE] }
    }
}

static BY_PHYS: Ring = Ring::new();
static SEQUENCE: Ring = Ring::new();

/// Monotonic write-sequence counter.  Wraps after 2^64; in practice the
/// observation window is ≤ 1 boot so no wrap is observed.
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

/// Total `record_write` invocations whose VA passed the window gate.
static RECORDED: AtomicU64 = AtomicU64::new(0);

/// `record_write` calls that displaced an unrelated previous BY_PHYS entry
/// (different phys, same slot — direct-address hash collision).  Non-zero
/// is informational only.
static DISPLACED: AtomicU64 = AtomicU64::new(0);

/// `record_write` calls dropped by the window gate (VA outside the
/// `[STACK_PROV_VA_LO, STACK_PROV_VA_HI)` window).  Reported in the dump
/// header so reviewers can sanity-check window coverage.
static DROPPED_OUT_OF_WINDOW: AtomicU64 = AtomicU64::new(0);

// ── Public API ────────────────────────────────────────────────────────────

/// Record a kernel-mode write whose physical-address target is reached
/// via `(PHYS_OFF + phys)` and corresponds to user VA `va`.  Callers
/// that perform multi-byte writes should call this once per fundamental
/// store (e.g. once per u64 write); per-byte tracking would be too
/// expensive for the `stack_write_bytes` path.
///
/// No-op outside `[STACK_PROV_VA_LO, STACK_PROV_VA_HI)`.
///
/// Cost: 8 atomic stores under a window hit, ≤ 1 cmp+branch otherwise.
#[inline]
pub fn record_write(va: u64, val: u64, site_tag: u8) {
    if !in_window(va) {
        DROPPED_OUT_OF_WINDOW.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Resolve the phys backing this VA.  `virt_to_phys_in` is the
    // fault-immune software walker used by every direct-map writer.  If
    // the walker fails (e.g. the PTE is mid-install) we still record the
    // event with `phys=0` so the seq ring keeps temporal ordering — but
    // it won't appear in a phys-keyed dump.
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = match crate::mm::vmm::virt_to_phys_in(cr3, va) {
        Some(p) => p & !0xFFFu64,
        None => 0,
    };

    let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = crate::proc::current_pid_lockless() as u64;
    let tid = crate::proc::current_tid() as u64;
    let pid_tid = (pid << 32) | (tid & 0xFFFF_FFFF);
    // Caller-RIP: take return address (one frame up) so addr2line
    // names the caller of `record_write`, not the inlined record body.
    // Best-effort; if frame pointers were omitted at this site, returns
    // 0 — still useful per-call-site via the const `site_tag` field.
    let rip: u64;
    unsafe {
        let mut rbp: u64;
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack));
        // [rbp + 8] = caller's return address (System V AMD64 ABI §3.2.2).
        // Validated to lie in the kernel half before storing.
        if rbp >= 0xFFFF_8000_0000_0000 {
            let ra_ptr = (rbp + 8) as *const u64;
            rip = core::ptr::read_volatile(ra_ptr);
        } else {
            rip = 0;
        }
    }
    let sc = crate::syscall::FIREFOX_SYSCALL_COUNT.load(Ordering::Relaxed);
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let cpu = crate::arch::x86_64::apic::cpu_index() as u64;
    let packed = (sc & 0xFFFF_FFFF) << 32
        | (tick & 0xFFFF) << 16
        | (cpu & 0xFF) << 8
        | (site_tag as u64);
    let cr3_lo = (cr3 >> 12) & 0xFFFF;

    // Slot 1: by-phys (direct-addressed).
    if phys != 0 {
        let bp_idx = ((phys >> 12) & RING_MASK) as usize;
        let bp = &BY_PHYS.slots[bp_idx];
        let prev_phys = bp.phys.load(Ordering::Relaxed);
        if prev_phys != 0 && prev_phys != phys {
            DISPLACED.fetch_add(1, Ordering::Relaxed);
        }
        bp.phys.store(phys, Ordering::Relaxed);
        bp.va.store(va, Ordering::Relaxed);
        bp.val.store(val, Ordering::Relaxed);
        bp.seq.store(seq, Ordering::Relaxed);
        bp.pid_tid.store(pid_tid, Ordering::Relaxed);
        bp.rip.store(rip, Ordering::Relaxed);
        bp.packed.store(packed, Ordering::Relaxed);
        bp.cr3_lo16.store(cr3_lo, Ordering::Relaxed);
    }

    // Slot 2: append-only sequence (always recorded).
    let sq_idx = (seq & RING_MASK) as usize;
    let sq = &SEQUENCE.slots[sq_idx];
    sq.phys.store(phys, Ordering::Relaxed);
    sq.va.store(va, Ordering::Relaxed);
    sq.val.store(val, Ordering::Relaxed);
    sq.seq.store(seq, Ordering::Relaxed);
    sq.pid_tid.store(pid_tid, Ordering::Relaxed);
    sq.rip.store(rip, Ordering::Relaxed);
    sq.packed.store(packed, Ordering::Relaxed);
    sq.cr3_lo16.store(cr3_lo, Ordering::Relaxed);

    RECORDED.fetch_add(1, Ordering::Relaxed);
}

/// Cap on `[SSP-DIAG-STACK-PROV-W]` lines emitted per `dump_for_phys`
/// invocation.  Bounded so a colliding-bucket dump cannot flood the log.
const DUMP_PER_INVOC_CAP: usize = 16;

/// Dump every ring entry matching `phys_page` (page-aligned).  Walks both
/// the BY_PHYS ring (1 direct hit per call) and the SEQUENCE ring
/// (RING_SIZE candidates) so colliding sites are still visible.
///
/// Output volume: 1 header line + up to `DUMP_PER_INVOC_CAP` per-write
/// lines + 1 footer line.  Header always emitted; footer always emitted
/// (even when zero matches) so a verifier can grep for the END marker.
///
/// Caller is responsible for the outer rate-limit (the caller in
/// `ssp_diag.rs` already gates on `SSP_DIAG_MAX`).
pub fn dump_for_phys(phys_page: u64) {
    let phys_page = phys_page & !0xFFFu64;
    let recorded = RECORDED.load(Ordering::Relaxed);
    let displaced = DISPLACED.load(Ordering::Relaxed);
    let dropped = DROPPED_OUT_OF_WINDOW.load(Ordering::Relaxed);

    // Pre-count matches across the SEQUENCE ring so the header carries
    // an accurate `entries=` field before any per-line emission.
    let mut matches: usize = 0;
    for slot in SEQUENCE.slots.iter() {
        if slot.phys.load(Ordering::Relaxed) == phys_page {
            matches += 1;
        }
    }
    crate::serial_println!(
        "[SSP-DIAG-STACK-PROV] phys={:#x} entries={} recorded={} displaced={} \
         dropped_out_of_window={}",
        phys_page, matches, recorded, displaced, dropped,
    );

    let mut emitted: usize = 0;
    // BY_PHYS direct lookup first (most likely the most-recent writer).
    {
        let idx = ((phys_page >> 12) & RING_MASK) as usize;
        let slot = &BY_PHYS.slots[idx];
        if slot.phys.load(Ordering::Relaxed) == phys_page
            && emitted < DUMP_PER_INVOC_CAP
        {
            emit_entry(slot, "by_phys");
            emitted += 1;
        }
    }
    // Then walk the SEQUENCE ring for all matches.
    for slot in SEQUENCE.slots.iter() {
        if emitted >= DUMP_PER_INVOC_CAP { break; }
        if slot.phys.load(Ordering::Relaxed) == phys_page {
            emit_entry(slot, "seq");
            emitted += 1;
        }
    }
    crate::serial_println!(
        "[SSP-DIAG-STACK-PROV-END] phys={:#x} emitted={}",
        phys_page, emitted,
    );
}

/// Emit one entry as a single `[SSP-DIAG-STACK-PROV-W]` line.  Reads each
/// field once with `Relaxed` ordering; concurrent updates may produce a
/// torn tuple — informational only, the SSP-DIAG cap bounds the dump
/// window so this should be infrequent.
fn emit_entry(slot: &Entry, source: &'static str) {
    let phys     = slot.phys.load(Ordering::Relaxed);
    let va       = slot.va.load(Ordering::Relaxed);
    let val      = slot.val.load(Ordering::Relaxed);
    let seq      = slot.seq.load(Ordering::Relaxed);
    let pid_tid  = slot.pid_tid.load(Ordering::Relaxed);
    let rip      = slot.rip.load(Ordering::Relaxed);
    let packed   = slot.packed.load(Ordering::Relaxed);
    let cr3_lo   = slot.cr3_lo16.load(Ordering::Relaxed);
    let pid = (pid_tid >> 32) & 0xFFFF_FFFF;
    let tid = pid_tid & 0xFFFF_FFFF;
    let sc       = (packed >> 32) & 0xFFFF_FFFF;
    let tick16   = (packed >> 16) & 0xFFFF;
    let cpu      = (packed >> 8) & 0xFF;
    let site_tag = (packed & 0xFF) as u8;
    crate::serial_println!(
        "[SSP-DIAG-STACK-PROV-W] src={} seq={} phys={:#x} va={:#x} val={:#x} \
         pid={} tid={} rip={:#x} sc={} tick_lo16={} cpu={} cr3_lo16={:#x} \
         site={}",
        source, seq, phys, va, val,
        pid, tid, rip, sc, tick16, cpu, cr3_lo,
        site_str(site_tag),
    );
}

/// Read-only counter accessors for kdb introspection.
pub fn recorded_count() -> u64 { RECORDED.load(Ordering::Relaxed) }
pub fn displaced_count() -> u64 { DISPLACED.load(Ordering::Relaxed) }
pub fn dropped_count() -> u64 { DROPPED_OUT_OF_WINDOW.load(Ordering::Relaxed) }
