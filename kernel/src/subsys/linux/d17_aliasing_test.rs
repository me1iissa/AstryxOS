//! D17 read-side aliasing test for the SSP-canary slot.
//!
//! ## What this catches
//!
//! D16 ([[kernel/src/subsys/linux/d16_canary_watch.rs]]) arms two hardware
//! watchpoints on the canary slot — one on the user VA `0x7ffffffee4c0`
//! (firefox-bin CR3) and one on the kernel direct-map mirror at
//! `PHYS_OFF + 0x127114c0`.  The D16 fire log named 32 writes, all from
//! CPL=3 user code (the libxul / musl SSP prologue), with zero CPL=0
//! kernel-mode fires on the PHYS_OFF channel.  Read superficially, that
//! falsifies "kernel direct-map writer corrupts the slot between the
//! prologue and the epilogue".
//!
//! But there is a remaining hypothesis the D16 channels alone cannot
//! distinguish.  The PHYS_OFF arm targets the **observed** deterministic
//! phys `0x127114c0`.  If between the prologue write and the epilogue
//! read the page-table mapping for the canary VA was re-pointed (PTE
//! replaced, or a TLB stale on a peer CPU causes the read CPU to resolve
//! the same VA to a *different* phys than the writer CPU did), then:
//!
//!   * The prologue's write retired against phys `X` (the correct
//!     canary value), trapped on D16's user-VA channel (CS=0x23).
//!   * The PHYS_OFF arm at `PHYS_OFF + 0x127114c0` (`= phys X` per D16's
//!     `[D16/ARM]` capture) would also fire on that prologue write.
//!   * The epilogue's read resolves the same VA to phys `Y` (`!= X`),
//!     reads a stale or foreign byte sequence including the observed
//!     `0x30`, and trips `__stack_chk_fail`.
//!
//! In that mode, **D16 sees the writer but the writer wrote the right
//! value to the right phys**.  The bug is on the *read* path — a page-
//! table or TLB aliasing hazard, the same class as W215 (PR #270,
//! [[project_w215_saga_CLOSED_v2_2026_05_21]]) and the post-W215
//! `pte_share_count` invariant, but on a different VA.
//!
//! D17 directly distinguishes the two modes with a single observable:
//! the canary slot's backing physical frame at write-time vs at
//! fault-time.  If they differ, the kernel has a residual aliasing
//! issue on the stack canary path.
//!
//! ## Mechanism
//!
//! D17 hooks two existing diagnostic moments without adding any new
//! hardware machinery:
//!
//!   * **Write-time** — called from `arch::x86_64::debug_reg::
//!     handle_db_exception` when the firing slot has
//!     `kind_tag == WATCH_KIND_D16_CANARY`.  We capture the write event's
//!     `(rip, va = CANARY_SLOT_VA, phys = virt_to_phys_in(cr3, va),
//!     value = direct_map_read_qword(phys))` and push the tuple onto a
//!     small ring (`D17_RING`, 16 slots).  `cr3` is the current CR3 at
//!     fire time; `phys` is the live page-table-walk result the writer
//!     CPU would have observed.  Per Intel SDM Vol. 3B §17.3.1.1 the
//!     `#DB` is taken *after* the writer's store retires, so the qword
//!     value we read through the direct map reflects what the writer
//!     just stored.
//!   * **Read-time** — called from `subsys::linux::ssp_diag::
//!     probe_gp_at_ssp_fail` on the CPL-3 `#GP` at musl
//!     `__stack_chk_fail`.  We re-resolve `virt_to_phys_in(cr3,
//!     CANARY_SLOT_VA)` at fault time, read the qword through the direct
//!     map, scan `D17_RING` for the most-recent matching VA entry, and
//!     emit a verdict line: `D17-PHYS-DIFFER` (write-phys ≠ read-phys —
//!     READ-SIDE ALIASING CONFIRMED), `D17-PHYS-MATCH` (same phys but
//!     the value differs — D16 missed a writer, or it's a fundamentally
//!     different corruption mode), or `D17-NO-WRITE-CAPTURED` (D16 did
//!     not fire — different code path; inconclusive).
//!
//! Per the AstryxOS PHYS_OFF identity-map invariant (Intel SDM Vol. 3A
//! §4.10 — every installed RAM frame is linearly mapped at `PHYS_OFF +
//! phys`), both the write-time and read-time `direct_map_read_qword`
//! calls observe the same physical byte sequence as the writer/reader
//! would through their user-VA paging chain, modulo cache coherence
//! (Intel SDM Vol. 3A §11.4 — the snoop protocol keeps all aliased
//! virtual mappings of a single frame coherent at qword granularity for
//! WB-cached memory, which the AstryxOS PMM exclusively allocates).
//!
//! ## Expected signatures
//!
//!   * **`[D17/VERDICT] D17-PHYS-DIFFER ...`** — write-phys ≠ read-phys.
//!     Read-side aliasing is **confirmed**.  Names a kernel page-table
//!     or TLB issue specific to the canary VA.  Resolution: phys-
//!     provenance dump (FREE_SHADOW / ALLOC_SHADOW per PR #354 /
//!     Track K) for the read-time phys to name the freer/allocator
//!     that re-pointed the mapping; cross-walk against the
//!     `pte_share_count` invariant.
//!   * **`[D17/VERDICT] D17-PHYS-MATCH ...`** — write-phys ==
//!     read-phys but the value at fault time != value at write time.
//!     D16's coverage missed a writer (e.g. the writer wrote via a
//!     CR3 other than firefox-bin's *and* via a VA other than the
//!     direct-map mirror of `0x127114c0` — vanishingly unlikely given
//!     D16's two-channel coverage) OR the corruption is a different
//!     class entirely (cache incoherence on a non-WB region — would
//!     contradict the PMM's WB allocation invariant).
//!   * **`[D17/VERDICT] D17-NO-WRITE-CAPTURED ...`** — `D17_RING` has
//!     no entry for `CANARY_SLOT_VA`.  D16 did not fire on this trial;
//!     the fault arrived on a code path D16 does not see.
//!     Inconclusive — collect another trial.
//!
//! ## No-fix discipline
//!
//! Per saga-discipline rules 1 (phys-provenance FIRST) and 4 (framing
//! IS the bug), this module is read-only diagnostic.  It does NOT
//! mutate page tables, allocate frames, change lock order, or alter
//! syscall behaviour.  The ring is a per-boot fixed BSS allocation
//! (16 × 32 B = 512 B); the hot path on each D16 fire is one
//! `virt_to_phys_in` + one `read_volatile` + one atomic ring index
//! increment.
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3A §4.6 (page-table walk, linear → phys).
//!   * Intel SDM Vol. 3A §4.10 (TLB management; PHYS_OFF coherence).
//!   * Intel SDM Vol. 3A §11.4 (cache coherence protocol; aliased VAs).
//!   * Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7 layout).
//!   * Intel SDM Vol. 3B §17.3.1.1 (data-breakpoint trap timing —
//!     trap-after-retire).
//!   * System V AMD64 ABI §3.4.1 (SSP / `__stack_chk_guard` model).
//!   * POSIX `execve(2)` (process-image-replacement semantics).
//!   * CWE-787 (out-of-bounds write — page-table-aliasing reads
//!     adjacent / stale data).
//!   * ELF gABI (the libxul SSP-instrumented function layout).

#![cfg(feature = "d17-aliasing-test")]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Canary slot user VA (mirrors `d16_canary_watch::CANARY_SLOT_VA`).
/// Duplicated here to keep D17 freestanding when D16 is disabled (the
/// feature deps prevent that today, but the constant is local for
/// clarity).
const CANARY_SLOT_VA: u64 = 0x0000_7fff_fffe_e4c0;

/// Kernel direct-map base (mirrors `d16_canary_watch::PHYS_OFF` /
/// `ssp_diag::PHYS_OFF`).  Per the AstryxOS bootloader invariant
/// (Intel SDM Vol. 3A §4.10), every installed RAM frame is mapped
/// here at `PHYS_OFF + phys`.
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Ring capacity — 16 slots covers the F3_FIRE_CAP=32 D16 ceiling with
/// a 2× headroom for wrap-around of stale entries.  Per the D16 fire
/// model the prologue typically emits 1–3 writes per frame; 16 slots
/// keep the entire recent-history window addressable.
const RING_CAP: usize = 16;

/// One captured write event.  All u64 fields are atomically loaded /
/// stored individually; the `seq` field stamps a monotonic sequence
/// number so a reader can detect torn writes between fields.  Even
/// `seq` = published; odd `seq` = in-progress (seqlock pattern, per
/// the Linux kernel's `seqcount_t` model used freely without citing
/// any specific implementation).
#[derive(Default)]
struct WriteEvent {
    seq: AtomicU64,
    rip: AtomicU64,
    va: AtomicU64,
    phys: AtomicU64,
    value: AtomicU64,
    cpu: AtomicU32,
    /// 0 for CPL-3 user-mode writers; 8 for CPL-0 kernel-mode writers.
    /// Stored as u32 because `AtomicU8` isn't `const Default`-friendly
    /// in the same shape as the rest of the struct.
    cs: AtomicU32,
}

impl WriteEvent {
    const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            rip: AtomicU64::new(0),
            va: AtomicU64::new(0),
            phys: AtomicU64::new(0),
            value: AtomicU64::new(0),
            cpu: AtomicU32::new(0),
            cs: AtomicU32::new(0),
        }
    }
}

/// Per-boot ring of D16 fire events.  Indexed by `D17_RING_NEXT %
/// RING_CAP`; oldest entries are overwritten on wrap.
static D17_RING: [WriteEvent; RING_CAP] = [const { WriteEvent::new() }; RING_CAP];

/// Monotonic ring-write index.  Increments on every successful push.
static D17_RING_NEXT: AtomicU64 = AtomicU64::new(0);

/// Latch used to bound `[D17/VERDICT]` emissions to one per fault
/// (cheaply, without coordinating with `ssp_diag::SSP_DIAG_MAX`).  Per
/// the F3 saga discipline, one definitive verdict is all this
/// dispatch needs.
static D17_VERDICT_EMITTED: AtomicBool = AtomicBool::new(false);

/// Fault-immune direct-map qword read.  Returns `None` if the linear
/// `PHYS_OFF + phys` is plausibly outside installed RAM (defensive;
/// real callers feed valid `phys` from `virt_to_phys_in`).  Per Intel
/// SDM Vol. 3A §4.10 every PMM-allocated frame is in the direct map.
///
/// SAFETY: the caller is responsible for `phys` being a valid PMM
/// frame's qword offset.  All D17 callers obtain `phys` from
/// `virt_to_phys_in` immediately prior, which validates the walk.
fn read_phys_qword(phys: u64) -> u64 {
    unsafe { core::ptr::read_volatile((PHYS_OFF + phys) as *const u64) }
}

/// Resolve `va` through `cr3` and read the qword at its backing phys.
/// Returns `Some((phys, value))` on a successful walk, `None` if the
/// VA is unmapped or straddles a page boundary.  Per Intel SDM Vol.
/// 3A §4.6 a qword straddles only when `addr & 0xFFF > 0x1000 - 8`;
/// `CANARY_SLOT_VA` (`...e4c0`) is qword-aligned so this is the
/// not-taken arm at the call sites here.
fn walk_va(cr3: u64, va: u64) -> Option<(u64, u64)> {
    if (va & 0xFFF) > 0x1000 - 8 {
        return None;
    }
    let phys = crate::mm::vmm::virt_to_phys_in(cr3, va)?;
    Some((phys, read_phys_qword(phys)))
}

/// Push a write event onto the ring.  Called from the D16 fire path
/// in `handle_db_exception` when the firing slot is tagged
/// `WATCH_KIND_D16_CANARY`.  `rip` is the post-retire RIP (one
/// instruction past the writer per Intel SDM Vol. 3B §17.3.1.1).
///
/// The recording is best-effort: under heavy fire we may wrap, but
/// the read-side scan walks the most-recent N entries so wrap is
/// harmless until N > RING_CAP.
pub fn record_d16_fire(rip: u64, cs: u64, cr3: u64) {
    let (phys, value) = match walk_va(cr3, CANARY_SLOT_VA) {
        Some(t) => t,
        None    => (0, 0), // VA unmapped at fire time — still record the rip/cs
    };
    let cpu = crate::arch::x86_64::apic::cpu_index() as u32;

    let idx = D17_RING_NEXT.fetch_add(1, Ordering::Relaxed) as usize % RING_CAP;
    let slot = &D17_RING[idx];

    // Seqlock-style publish: bump to odd (write-in-progress), write
    // fields, bump to even (published).  A read-side that observes an
    // odd seq retries.  Per Linux's `seqcount_t` model — public idiom
    // available without citing a specific implementation.
    let s = slot.seq.load(Ordering::Relaxed);
    slot.seq.store(s.wrapping_add(1), Ordering::Release);
    slot.rip.store(rip, Ordering::Relaxed);
    slot.va.store(CANARY_SLOT_VA, Ordering::Relaxed);
    slot.phys.store(phys, Ordering::Relaxed);
    slot.value.store(value, Ordering::Relaxed);
    slot.cpu.store(cpu, Ordering::Relaxed);
    slot.cs.store(cs as u32, Ordering::Relaxed);
    slot.seq.store(s.wrapping_add(2), Ordering::Release);

    crate::serial_println!(
        "[D17/WRITE-PHYS] idx={} write_rip={:#x} cs={:#x} cpu={} cr3={:#x} \
         va={:#x} phys={:#x} value={:#018x}",
        idx, rip, cs, cpu, cr3, CANARY_SLOT_VA, phys, value,
    );
}

/// Read a `WriteEvent` slot under the seqlock protocol.  Returns
/// `None` if the slot is empty (seq == 0) or if a concurrent writer
/// keeps tearing the read.  At fault time `#GP` is taken at CPL 3 so
/// no concurrent D16 fire can race us on the same CPU, but a peer
/// CPU's fire could land between our field loads.
fn snapshot_slot(slot: &WriteEvent) -> Option<(u64, u64, u64, u64, u64, u32, u32)> {
    for _ in 0..4 {
        let s1 = slot.seq.load(Ordering::Acquire);
        if s1 == 0 { return None; }
        if s1 & 1 != 0 { continue; } // write in progress, retry
        let rip   = slot.rip  .load(Ordering::Relaxed);
        let va    = slot.va   .load(Ordering::Relaxed);
        let phys  = slot.phys .load(Ordering::Relaxed);
        let value = slot.value.load(Ordering::Relaxed);
        let cpu   = slot.cpu  .load(Ordering::Relaxed);
        let cs    = slot.cs   .load(Ordering::Relaxed);
        let s2 = slot.seq.load(Ordering::Acquire);
        if s1 == s2 {
            return Some((s1, rip, va, phys, value, cpu, cs));
        }
    }
    None
}

/// Emit the read-time verdict.  Called from `ssp_diag::
/// probe_gp_at_ssp_fail` on a CPL-3 `#GP` at musl `__stack_chk_fail`.
/// Re-resolves the canary VA → phys, scans the ring for the
/// most-recent matching VA entry, and prints `[D17/READ-PHYS]`
/// followed by a `[D17/VERDICT]` line.
///
/// Bounded to one emission per boot via `D17_VERDICT_EMITTED`.  Per
/// the dispatch brief, a single definitive verdict is the desired
/// output.
pub fn emit_fault_verdict(read_rip: u64) {
    // Latch — once-per-boot.
    if D17_VERDICT_EMITTED.swap(true, Ordering::AcqRel) {
        return;
    }

    let cr3 = crate::mm::vmm::get_cr3();
    let (read_phys, read_value) = match walk_va(cr3, CANARY_SLOT_VA) {
        Some(t) => t,
        None => {
            crate::serial_println!(
                "[D17/READ-PHYS] read_rip={:#x} cr3={:#x} va={:#x} phys=unmapped",
                read_rip, cr3, CANARY_SLOT_VA,
            );
            crate::serial_println!(
                "[D17/VERDICT] D17-READ-UNMAPPED read_rip={:#x} va={:#x}",
                read_rip, CANARY_SLOT_VA,
            );
            return;
        }
    };

    crate::serial_println!(
        "[D17/READ-PHYS] read_rip={:#x} cr3={:#x} va={:#x} phys={:#x} value={:#018x}",
        read_rip, cr3, CANARY_SLOT_VA, read_phys, read_value,
    );

    // Walk the ring most-recent-first looking for a matching VA.  The
    // monotonic next-index minus 1 modulo CAP is the youngest entry.
    let total = D17_RING_NEXT.load(Ordering::Relaxed);
    if total == 0 {
        crate::serial_println!(
            "[D17/VERDICT] D17-NO-WRITE-CAPTURED read_rip={:#x} read_phys={:#x} \
             read_value={:#018x} ring_total=0",
            read_rip, read_phys, read_value,
        );
        return;
    }
    let n_to_scan = if total < RING_CAP as u64 { total as usize } else { RING_CAP };
    let mut best: Option<(u64, u64, u64, u64, u32, u32)> = None;
    for k in 0..n_to_scan {
        let logical = total.wrapping_sub(1).wrapping_sub(k as u64);
        let idx = (logical as usize) % RING_CAP;
        if let Some((_, rip, va, phys, value, cpu, cs)) = snapshot_slot(&D17_RING[idx]) {
            if va == CANARY_SLOT_VA {
                best = Some((rip, phys, value, logical, cpu, cs));
                break;
            }
        }
    }

    let (write_rip, write_phys, write_value, write_seq, write_cpu, write_cs) = match best {
        Some(t) => t,
        None => {
            crate::serial_println!(
                "[D17/VERDICT] D17-NO-WRITE-CAPTURED read_rip={:#x} read_phys={:#x} \
                 read_value={:#018x} ring_total={} scan_window={}",
                read_rip, read_phys, read_value, total, n_to_scan,
            );
            return;
        }
    };

    let verdict = if write_phys != read_phys {
        "D17-PHYS-DIFFER"
    } else if write_value != read_value {
        "D17-PHYS-MATCH-VALUE-DIVERGED"
    } else {
        "D17-PHYS-MATCH-VALUE-MATCH"
    };

    crate::serial_println!(
        "[D17/VERDICT] {} read_rip={:#x} read_phys={:#x} read_value={:#018x} \
         write_rip={:#x} write_phys={:#x} write_value={:#018x} \
         write_seq={} write_cpu={} write_cs={:#x} ring_total={} scan_window={}",
        verdict, read_rip, read_phys, read_value,
        write_rip, write_phys, write_value,
        write_seq, write_cpu, write_cs,
        total, n_to_scan,
    );
}
