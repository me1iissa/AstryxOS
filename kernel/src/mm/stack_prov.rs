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
//! Window gate: writes whose target user VA is OUTSIDE the two documented
//! windows are dropped:
//!
//!   1. **Thread-stack window** `[STACK_PROV_VA_LO, STACK_PROV_VA_HI)` =
//!      `[0x3f00_…, 0x4000_…)`.  Per Phase 4's VMA-DUMP, TID 7's stack VMA
//!      sits at `0x3f5e_785000` — comfortably inside.  This is the original
//!      W215/F3 canary-slot window; left UNCHANGED.
//!   2. **Main-stack TOP window** `[STACK_PROV_TOP_LO, STACK_PROV_TOP_HI)` =
//!      `[USER_STACK_TOP - 64*4KiB, USER_STACK_TOP)` =
//!      `[0x7fff_fffc_0000, 0x7fff_ffff_0000)`.  Added 2026-05-30 to close
//!      the GATE-A blind spot: `setup_user_stack` lays down the
//!      argc/argv/envp/auxv block in the top ~few KiB of the main user
//!      stack (e.g. the `argv[1]` pointer slot at `0x7fff_fffe_fa38`), and
//!      that block must then be IMMUTABLE until the process reads it in
//!      `nsCommandLine::Init`.  Any *subsequent* kernel-mode store into
//!      this window — in particular a value-zeroing store that clears a
//!      previously-non-zero pointer slot — is the out-of-band writer we
//!      have never captured (`argc=4, argv[1]=0` is unconstructable at
//!      build time, so it must be written AFTER the build path).  The
//!      window is deliberately a small top region, NOT the whole main
//!      stack: every userspace `call`/`push` touches the bulk of the stack
//!      and instrumenting it would be pure noise/cost; argv/envp/auxv sit
//!      just below `USER_STACK_TOP`.
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
//! `EXEC_TRAMP`, `EXEC_TEB`, `CLEARTID`, `ARGV_BUILD`).  Each call to
//! `record_write` carries a const tag so the post-mortem can identify the
//! call site without addr2line on a stripped kernel ELF.
//!
//! ## ARGV-WRITER capture (GATE-A, 2026-05-30)
//!
//! For the main-stack TOP window the interesting event is a *value-zeroing*
//! store: a kernel-mode write that overwrites a previously-non-zero
//! (pointer-shaped) slot with `0`.  `record_top_window_write` reads the
//! current 8 bytes at the target VA *before* the store, flags the record
//! `zeroing=1` when `old != 0 && new == 0`, and stores both `old` and `new`
//! so the SIGSEGV-time dump can print a definitive
//! `[STACK-PROV/ARGV-WRITER] rip=… tid=… va=… old=… new=0` line naming the
//! writer.  The pre-read is cheap (a single software page-table walk that the
//! direct-map writer already performs) and is gated behind the top-window
//! check, so the hot path of unrelated writers is untouched.
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

/// Top of the main user stack — must match `proc::elf::USER_STACK_TOP`.
/// `setup_user_stack` grows the initial stack DOWN from here, placing the
/// argc/argv/envp/auxv block in the first few KiB below this address.
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;

/// Number of 4 KiB pages below `USER_STACK_TOP` covered by the main-stack
/// TOP window.  64 pages = 256 KiB is ample: the entire initial-stack block
/// (16 random bytes + env/argv strings + auxv + the pointer arrays + argc)
/// for a Firefox-class command line is a few KiB at most, so 256 KiB leaves
/// generous headroom while staying far away from the deep call frames the
/// running program churns through (those sit ≥ hundreds of KiB lower).
pub const STACK_PROV_TOP_PAGES: u64 = 64;

/// Lower (inclusive) bound of the main-stack TOP window =
/// `USER_STACK_TOP - 64*4KiB` = `0x7fff_fffc_0000`.
pub const STACK_PROV_TOP_LO: u64 = USER_STACK_TOP - STACK_PROV_TOP_PAGES * 0x1000;

/// Upper (exclusive) bound of the main-stack TOP window = `USER_STACK_TOP`.
pub const STACK_PROV_TOP_HI: u64 = USER_STACK_TOP;

/// Original 0x3f thread-stack window (W215/F3 canary slot).  Unchanged.
#[inline]
fn in_window(va: u64) -> bool {
    va >= STACK_PROV_VA_LO && va < STACK_PROV_VA_HI
}

/// Main-stack TOP window (GATE-A argv/envp/auxv block).
#[inline]
pub fn in_top_window(va: u64) -> bool {
    va >= STACK_PROV_TOP_LO && va < STACK_PROV_TOP_HI
}

/// True if `va` falls in EITHER instrumented window.
#[inline]
fn in_any_window(va: u64) -> bool {
    in_window(va) || in_top_window(va)
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
pub const SITE_CLEARTID:         u8 = 8; // syscall::write_u32_to_user (CLONE_CHILD_{CLEAR,SET}TID)
pub const SITE_ARGV_BUILD:       u8 = 9; // setup_user_stack TOP-window build write (baseline)

fn site_str(tag: u8) -> &'static str {
    match tag {
        SITE_VFORK_STACK_SEED => "VFORK_STACK_SEED",
        SITE_VFORK_TLS_INIT   => "VFORK_TLS_INIT",
        SITE_ELF_AUXV         => "ELF_AUXV",
        SITE_ELF_AUXV_BYTES   => "ELF_AUXV_BYTES",
        SITE_EXEC_TRAMP       => "EXEC_TRAMP",
        SITE_EXEC_TEB         => "EXEC_TEB",
        SITE_GENERIC          => "GENERIC",
        SITE_CLEARTID         => "CLEARTID",
        SITE_ARGV_BUILD       => "ARGV_BUILD",
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
    /// distinguishable from same-AS writes in the dump.  Bit 63 is reused as
    /// the `zeroing` flag (set when `old != 0 && new == 0` — a value-zeroing
    /// store, the GATE-A signature).  Bit 62 marks a TOP-window record.
    cr3_lo16: AtomicU64,
    /// The 8 bytes present at the target VA *before* this store, captured by
    /// `record_top_window_write` (TOP-window records only; `0` for the 0x3f
    /// thread-stack `record_write` path which does not pre-read).  Lets the
    /// SIGSEGV dump print `old=<#x> new=<#x>` and prove a non-zero pointer
    /// slot was cleared.
    old_val: AtomicU64,
}

/// `cr3_lo16` bit 63: this record is a value-zeroing store.
const FLAG_ZEROING: u64 = 1u64 << 63;
/// `cr3_lo16` bit 62: this record landed in the main-stack TOP window.
const FLAG_TOP_WINDOW: u64 = 1u64 << 62;

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
            old_val: AtomicU64::new(0),
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

/// Value-zeroing stores recorded in the main-stack TOP window (`old != 0 &&
/// new == 0`).  This is the GATE-A signal: a non-zero count after a Firefox
/// boot means the out-of-band argv-zeroing writer has been captured at least
/// once.  Surfaced in `kdb` via `argv_zeroing_count()`.
static ARGV_ZEROING_WRITES: AtomicU64 = AtomicU64::new(0);

/// Total TOP-window records (zeroing or not), for sanity-checking coverage.
static TOP_WINDOW_RECORDS: AtomicU64 = AtomicU64::new(0);

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
    // The original 0x3f thread-stack window only.  TOP-window writes go
    // through `record_top_window_write` (which captures the pre-store old
    // value for zeroing-store detection).  Keeping the gate unchanged here
    // preserves the exact W215/F3 behaviour.
    if !in_window(va) {
        DROPPED_OUT_OF_WINDOW.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let rip = caller_rip();
    store_record(va, /*old_val*/ 0, /*new_val*/ val, site_tag, rip, false);
}

/// Record a kernel-mode write into the **main-stack TOP window**
/// (`[STACK_PROV_TOP_LO, STACK_PROV_TOP_HI)`), capturing the 8 bytes present
/// at `va` *before* the store so a value-zeroing store can be recognised.
///
/// This is the GATE-A capture path.  Call it at every kernel direct-map
/// writer that can target a user stack address, passing the value about to be
/// stored as `new_val`.  Outside the TOP window the function is a no-op (≤ 1
/// cmp+branch) so unrelated writers (CLEARTID into a libc `.bss` word, etc.)
/// pay almost nothing; the pre-read page-table walk only runs on a TOP-window
/// hit.
///
/// `new_val` should be the full intended value where known (e.g. a u64
/// store).  For a sub-word store (u32 CLEARTID), pass the new u32 zero-extended
/// to u64; the recorded `old`/`new` still demonstrate whether a previously
/// non-zero pointer slot was cleared, which is all the GATE-A diagnosis needs.
#[inline]
pub fn record_top_window_write(va: u64, new_val: u64, site_tag: u8) {
    if !in_top_window(va) {
        return;
    }
    // Pre-read the current 8 bytes at `va` via the fault-immune direct-map
    // path so we can flag a value-zeroing store.  Read once, before the
    // caller's store mutates the slot — callers MUST invoke this BEFORE their
    // store.  A failed walk yields old=0 (no zeroing flag); still recorded.
    let old_val = read_user_qword_via_cr3(va).unwrap_or(0);
    let rip = caller_rip();
    store_record(va, old_val, new_val, site_tag, rip, true);
}

/// TOP-window record variant for a writer that targets an EXPLICIT CR3 (e.g.
/// `syscall::write_u32_to_user`, which is handed the dying thread's `cr3` on
/// the CLONE_CHILD_CLEARTID exit path and may run while `get_cr3()` is the
/// idle/another address space).  Pre-reads the old 8 bytes against `cr3` so a
/// value-zeroing store into the argv block is flagged with the correct frame.
///
/// MUST be called BEFORE the caller's store mutates the slot.
#[inline]
pub fn record_top_window_write_cr3(va: u64, new_val: u64, cr3: u64, site_tag: u8) {
    if !in_top_window(va) {
        return;
    }
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let (phys, old_val) = match crate::mm::vmm::virt_to_phys_in(cr3, va) {
        Some(p) => {
            // `p` carries the page offset; read the 8 bytes at `va` so a
            // CLEARTID u32 store (which may clear only the low half of an
            // 8-byte pointer slot) still shows a previously-non-zero `old`.
            let frame = p & !0xFFFu64;
            let old = if (va & 0xFFF) <= 0xFF8 {
                unsafe { core::ptr::read_unaligned((PHYS_OFF + p) as *const u64) }
            } else {
                0
            };
            (frame, old)
        }
        None => (0, 0),
    };
    let rip = caller_rip();
    store_record_with_phys(va, old_val, new_val, phys, site_tag, rip, true);
}

/// TOP-window record variant for callers that already hold the target
/// physical frame (e.g. `setup_user_stack`, which writes through a known
/// `(vaddr, phys)` pair while running in the *creating* context's CR3, not
/// the target process's).  Skips the `get_cr3()`-relative page-table walk and
/// the pre-read (passes `old_val = 0`, so it never flags a zeroing store) —
/// this path only seeds a BASELINE record of the legitimate build write so a
/// later out-of-band zeroing store on the same frame has a phys-keyed anchor.
#[inline]
pub fn record_top_window_write_phys(va: u64, new_val: u64, phys: u64, site_tag: u8) {
    if !in_top_window(va) {
        return;
    }
    let rip = caller_rip();
    store_record_with_phys(va, 0, new_val, phys & !0xFFFu64, site_tag, rip, true);
}

/// Resolve the caller's return address (one frame up) so addr2line names the
/// writer site, not the inlined record body.  Best-effort; returns 0 if frame
/// pointers were omitted at the call site (still useful via `site_tag`).
#[inline(always)]
fn caller_rip() -> u64 {
    unsafe {
        let mut rbp: u64;
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack));
        // [rbp + 8] = caller's return address (System V AMD64 ABI §3.2.2).
        if rbp >= 0xFFFF_8000_0000_0000 {
            core::ptr::read_volatile((rbp + 8) as *const u64)
        } else {
            0
        }
    }
}

/// Fault-immune read of the 8 bytes at user `va` through the current CR3's
/// direct map.  Returns `None` if the VA does not resolve.
#[inline]
fn read_user_qword_via_cr3(va: u64) -> Option<u64> {
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = crate::mm::vmm::virt_to_phys_in(cr3, va)?;
    // Reads can cross a page boundary only if `va` is within 7 bytes of a page
    // end; argv slots are 8-aligned so this does not occur in practice, but be
    // safe and only read when the whole qword is on one resolved frame.
    if (va & 0xFFF) <= 0xFF8 {
        Some(unsafe { core::ptr::read_unaligned((PHYS_OFF + phys) as *const u64) })
    } else {
        None
    }
}

/// Shared ring-store body for both the 0x3f `record_write` path and the
/// TOP-window `record_top_window_write` path.  Writes the by-phys and
/// sequence rings and bumps the global counters.  `is_top` selects the
/// TOP-window flag / counters and the zeroing-store detection.
#[inline]
fn store_record(va: u64, old_val: u64, new_val: u64, site_tag: u8, rip: u64, is_top: bool) {
    // Resolve the phys backing this VA.  `virt_to_phys_in` is the
    // fault-immune software walker used by every direct-map writer.  If the
    // walker fails the event is still recorded with `phys=0` so the seq ring
    // keeps temporal ordering — but it won't appear in a phys-keyed dump.
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = match crate::mm::vmm::virt_to_phys_in(cr3, va) {
        Some(p) => p & !0xFFFu64,
        None => 0,
    };
    store_record_with_phys(va, old_val, new_val, phys, site_tag, rip, is_top);
}

/// Ring-store body with a caller-supplied (already page-table-resolved)
/// physical frame.  Used directly by `record_top_window_write_phys` and as
/// the tail of `store_record`.
#[inline]
fn store_record_with_phys(
    va: u64, old_val: u64, new_val: u64, phys: u64, site_tag: u8, rip: u64, is_top: bool,
) {
    let phys = phys & !0xFFFu64;
    let cr3 = crate::mm::vmm::get_cr3();
    let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = crate::proc::current_pid_lockless() as u64;
    let tid = crate::proc::current_tid() as u64;
    let pid_tid = (pid << 32) | (tid & 0xFFFF_FFFF);
    let sc = crate::syscall::FIREFOX_SYSCALL_COUNT.load(Ordering::Relaxed);
    let tick = crate::arch::x86_64::irq::TICK_COUNT.load(Ordering::Relaxed);
    let cpu = crate::arch::x86_64::apic::cpu_index() as u64;
    let packed = (sc & 0xFFFF_FFFF) << 32
        | (tick & 0xFFFF) << 16
        | (cpu & 0xFF) << 8
        | (site_tag as u64);

    // Zeroing store: a previously-non-zero slot overwritten with 0.  Only
    // meaningful for the TOP-window path (which pre-reads `old_val`).
    let zeroing = is_top && old_val != 0 && new_val == 0;
    let mut cr3_lo = (cr3 >> 12) & 0xFFFF;
    if zeroing { cr3_lo |= FLAG_ZEROING; }
    if is_top  { cr3_lo |= FLAG_TOP_WINDOW; }

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
        bp.val.store(new_val, Ordering::Relaxed);
        bp.seq.store(seq, Ordering::Relaxed);
        bp.pid_tid.store(pid_tid, Ordering::Relaxed);
        bp.rip.store(rip, Ordering::Relaxed);
        bp.packed.store(packed, Ordering::Relaxed);
        bp.cr3_lo16.store(cr3_lo, Ordering::Relaxed);
        bp.old_val.store(old_val, Ordering::Relaxed);
    }

    // Slot 2: append-only sequence (always recorded).
    let sq_idx = (seq & RING_MASK) as usize;
    let sq = &SEQUENCE.slots[sq_idx];
    sq.phys.store(phys, Ordering::Relaxed);
    sq.va.store(va, Ordering::Relaxed);
    sq.val.store(new_val, Ordering::Relaxed);
    sq.seq.store(seq, Ordering::Relaxed);
    sq.pid_tid.store(pid_tid, Ordering::Relaxed);
    sq.rip.store(rip, Ordering::Relaxed);
    sq.packed.store(packed, Ordering::Relaxed);
    sq.cr3_lo16.store(cr3_lo, Ordering::Relaxed);
    sq.old_val.store(old_val, Ordering::Relaxed);

    RECORDED.fetch_add(1, Ordering::Relaxed);
    if is_top {
        TOP_WINDOW_RECORDS.fetch_add(1, Ordering::Relaxed);
    }
    if zeroing {
        ARGV_ZEROING_WRITES.fetch_add(1, Ordering::Relaxed);
        // Emit the definitive writer-naming line IMMEDIATELY at capture time.
        // Unlike the trap-time `dump_for_phys` (which can be displaced out of
        // the ring by the time the SIGSEGV fires), this fires synchronously at
        // the exact store, so the writer-RIP is always named for the FIRST
        // zeroing store into the argv block.  Bounded by `ZEROING_LOG_CAP` so
        // a pathological loop cannot flood the serial log.
        let n = ARGV_ZEROING_WRITES.load(Ordering::Relaxed);
        if n <= ZEROING_LOG_CAP {
            crate::serial_println!(
                "[STACK-PROV/ARGV-WRITER] rip={:#x} pid={} tid={} cpu={} sc={} \
                 va={:#x} phys={:#x} old={:#x} new={:#x} site={} src=capture seq={}",
                rip, pid, tid, cpu, sc, va, phys, old_val, new_val,
                site_str(site_tag), seq,
            );
        }
    }
}

/// Cap on capture-time `[STACK-PROV/ARGV-WRITER]` lines (the synchronous
/// zeroing-store emit in `store_record`).  Bounded so a runaway loop cannot
/// flood serial; the first few captures are what name the GATE-A writer.
const ZEROING_LOG_CAP: u64 = 8;

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
    let old_val  = slot.old_val.load(Ordering::Relaxed);
    let seq      = slot.seq.load(Ordering::Relaxed);
    let pid_tid  = slot.pid_tid.load(Ordering::Relaxed);
    let rip      = slot.rip.load(Ordering::Relaxed);
    let packed   = slot.packed.load(Ordering::Relaxed);
    let cr3_raw  = slot.cr3_lo16.load(Ordering::Relaxed);
    let cr3_lo   = cr3_raw & 0xFFFF;
    let zeroing  = (cr3_raw & FLAG_ZEROING) != 0;
    let is_top   = (cr3_raw & FLAG_TOP_WINDOW) != 0;
    let pid = (pid_tid >> 32) & 0xFFFF_FFFF;
    let tid = pid_tid & 0xFFFF_FFFF;
    let sc       = (packed >> 32) & 0xFFFF_FFFF;
    let tick16   = (packed >> 16) & 0xFFFF;
    let cpu      = (packed >> 8) & 0xFF;
    let site_tag = (packed & 0xFF) as u8;
    crate::serial_println!(
        "[SSP-DIAG-STACK-PROV-W] src={} seq={} phys={:#x} va={:#x} val={:#x} \
         old={:#x} pid={} tid={} rip={:#x} sc={} tick_lo16={} cpu={} \
         cr3_lo16={:#x} site={} top={} zeroing={}",
        source, seq, phys, va, val, old_val,
        pid, tid, rip, sc, tick16, cpu, cr3_lo,
        site_str(site_tag), is_top as u8, zeroing as u8,
    );
}

/// SIGSEGV-time companion to `dump_for_phys`, specialised for the GATE-A
/// argv-zeroing investigation.  Given the **data page** physical address of
/// the faulting CR2 (computed by the signal-delivery path), scan the rings
/// for any TOP-window record on that frame and emit one
/// `[STACK-PROV/ARGV-WRITER] …` line per match naming the writer-RIP.
///
/// This is the trap-time mirror of the synchronous capture-time emit in
/// `store_record`: if the zeroing store's ring entry survived (not displaced),
/// the writer is named again here, keyed on the exact CR2 data frame, so the
/// post-mortem deterministically links `cr2=0x7fff…fa38` to its writer.
///
/// Always emits a header + footer so a verifier can grep for the END marker
/// even on zero matches.  Bounded by `DUMP_PER_INVOC_CAP`.
pub fn dump_argv_writer_for_phys(phys_page: u64) {
    let phys_page = phys_page & !0xFFFu64;
    let zeroing_total = ARGV_ZEROING_WRITES.load(Ordering::Relaxed);
    let top_total = TOP_WINDOW_RECORDS.load(Ordering::Relaxed);
    crate::serial_println!(
        "[STACK-PROV/ARGV-WRITER-SCAN] phys={:#x} top_window_records={} \
         zeroing_writes_total={}",
        phys_page, top_total, zeroing_total,
    );

    let mut emitted: usize = 0;
    for slot in SEQUENCE.slots.iter() {
        if emitted >= DUMP_PER_INVOC_CAP { break; }
        if slot.phys.load(Ordering::Relaxed) != phys_page { continue; }
        let cr3_raw = slot.cr3_lo16.load(Ordering::Relaxed);
        if (cr3_raw & FLAG_TOP_WINDOW) == 0 { continue; }
        let va       = slot.va.load(Ordering::Relaxed);
        let val      = slot.val.load(Ordering::Relaxed);
        let old_val  = slot.old_val.load(Ordering::Relaxed);
        let seq      = slot.seq.load(Ordering::Relaxed);
        let pid_tid  = slot.pid_tid.load(Ordering::Relaxed);
        let rip      = slot.rip.load(Ordering::Relaxed);
        let packed   = slot.packed.load(Ordering::Relaxed);
        let pid = (pid_tid >> 32) & 0xFFFF_FFFF;
        let tid = pid_tid & 0xFFFF_FFFF;
        let sc       = (packed >> 32) & 0xFFFF_FFFF;
        let cpu      = (packed >> 8) & 0xFF;
        let site_tag = (packed & 0xFF) as u8;
        let zeroing  = (cr3_raw & FLAG_ZEROING) != 0;
        crate::serial_println!(
            "[STACK-PROV/ARGV-WRITER] rip={:#x} pid={} tid={} cpu={} sc={} \
             va={:#x} phys={:#x} old={:#x} new={:#x} site={} src=trap-scan \
             seq={} zeroing={}",
            rip, pid, tid, cpu, sc, va, phys_page, old_val, val,
            site_str(site_tag), seq, zeroing as u8,
        );
        emitted += 1;
    }
    crate::serial_println!(
        "[STACK-PROV/ARGV-WRITER-END] phys={:#x} emitted={}",
        phys_page, emitted,
    );
}

/// Read-only counter accessors for kdb introspection.
pub fn recorded_count() -> u64 { RECORDED.load(Ordering::Relaxed) }
pub fn displaced_count() -> u64 { DISPLACED.load(Ordering::Relaxed) }
pub fn dropped_count() -> u64 { DROPPED_OUT_OF_WINDOW.load(Ordering::Relaxed) }
/// Count of value-zeroing stores captured in the main-stack TOP window
/// (GATE-A argv-writer signal).
pub fn argv_zeroing_count() -> u64 { ARGV_ZEROING_WRITES.load(Ordering::Relaxed) }
/// Count of all TOP-window records (zeroing or not).
pub fn top_window_count() -> u64 { TOP_WINDOW_RECORDS.load(Ordering::Relaxed) }

// ── Test-only helpers ──────────────────────────────────────────────────────
//
// Exposed for `test_runner::test_283_stack_prov_argv_writer_capture` so the
// test can drive the recording path against a synthetic TOP-window VA without
// a real direct-map write, and read back the captured writer-RIP for that VA.

/// Inject a synthetic TOP-window record directly into the rings (bypassing
/// the page-table walk and pre-read), as if a writer with `rip` had stored
/// `new_val` over `old_val` at `va`.  Used by the self-test to confirm the
/// blind spot is closed without needing a mapped user frame.
#[cfg(feature = "stack-prov")]
pub fn test_inject_top_window_record(
    va: u64, old_val: u64, new_val: u64, rip: u64, phys: u64, site_tag: u8,
) {
    let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
    let zeroing = old_val != 0 && new_val == 0;
    let mut cr3_lo: u64 = 0;
    if zeroing { cr3_lo |= FLAG_ZEROING; }
    cr3_lo |= FLAG_TOP_WINDOW;
    let packed = (site_tag as u64) | (0 << 8);
    let phys_aligned = phys & !0xFFFu64;
    // by-phys ring
    if phys_aligned != 0 {
        let bp = &BY_PHYS.slots[((phys_aligned >> 12) & RING_MASK) as usize];
        bp.phys.store(phys_aligned, Ordering::Relaxed);
        bp.va.store(va, Ordering::Relaxed);
        bp.val.store(new_val, Ordering::Relaxed);
        bp.old_val.store(old_val, Ordering::Relaxed);
        bp.seq.store(seq, Ordering::Relaxed);
        bp.pid_tid.store(0, Ordering::Relaxed);
        bp.rip.store(rip, Ordering::Relaxed);
        bp.packed.store(packed, Ordering::Relaxed);
        bp.cr3_lo16.store(cr3_lo, Ordering::Relaxed);
    }
    // sequence ring
    let sq = &SEQUENCE.slots[(seq & RING_MASK) as usize];
    sq.phys.store(phys_aligned, Ordering::Relaxed);
    sq.va.store(va, Ordering::Relaxed);
    sq.val.store(new_val, Ordering::Relaxed);
    sq.old_val.store(old_val, Ordering::Relaxed);
    sq.seq.store(seq, Ordering::Relaxed);
    sq.pid_tid.store(0, Ordering::Relaxed);
    sq.rip.store(rip, Ordering::Relaxed);
    sq.packed.store(packed, Ordering::Relaxed);
    sq.cr3_lo16.store(cr3_lo, Ordering::Relaxed);
    TOP_WINDOW_RECORDS.fetch_add(1, Ordering::Relaxed);
    if zeroing { ARGV_ZEROING_WRITES.fetch_add(1, Ordering::Relaxed); }
}

/// Look up the most-recent recorded writer-RIP for a TOP-window `va` by
/// scanning the SEQUENCE ring.  Returns `(rip, old_val, new_val)` for the
/// highest-seq matching record, or `None`.  Test-only retrieval path.
#[cfg(feature = "stack-prov")]
pub fn test_lookup_writer_for_va(va: u64) -> Option<(u64, u64, u64)> {
    let mut best_seq = 0u64;
    let mut found: Option<(u64, u64, u64)> = None;
    for slot in SEQUENCE.slots.iter() {
        if slot.va.load(Ordering::Relaxed) != va { continue; }
        if (slot.cr3_lo16.load(Ordering::Relaxed) & FLAG_TOP_WINDOW) == 0 { continue; }
        let seq = slot.seq.load(Ordering::Relaxed);
        if seq >= best_seq {
            best_seq = seq;
            found = Some((
                slot.rip.load(Ordering::Relaxed),
                slot.old_val.load(Ordering::Relaxed),
                slot.val.load(Ordering::Relaxed),
            ));
        }
    }
    found
}
