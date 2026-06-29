//! #655 alias-discriminating probe (`kstack-pte-scan`, DIAGNOSTIC ONLY).
//!
//! # What this discriminates
//!
//! The #655 SMP>1 kernel-stack corruptor has been localised to a **physical
//! kernel-stack alias**: two threads execute concurrently on ONE physical
//! kstack frame (seen via the higher-half direct map at
//! [`KERNEL_VIRT_OFFSET`] + phys), corrupting each other's saved
//! `switch_context` frames in place.  The victim (PID1's main thread) stays
//! ALIVE — no free, no recycle, no use-after-free.  Two candidate geneses of
//! the alias remain, with identical crash signatures:
//!
//! * **Candidate A — a kstack alias that escapes the alloc-side guard.** The
//!   guard ([`crate::proc::kstack_candidate_aliases_live`]) only overlap-checks
//!   the LIVE `THREAD_TABLE` `[base,+size)` spans.  It is blind to stacks that
//!   are NOT in the table — the bootstrap stack, the AP-idle stacks, and the
//!   static IST / interrupt stacks ([`crate::arch::x86_64::gdt`]).  A candidate
//!   overlapping one of those (or a partner whose recorded span differs from
//!   its true span at the check instant) is handed out and two threads end up
//!   on one frame.
//!
//! * **Candidate B — a stale `TSS.rsp0` foreign interrupt frame** (Intel SDM
//!   Vol. 3A §6.14 "Interrupt and Exception Handling": the stack switch on
//!   interrupt delivery uses the TSS RSP for the target privilege level).  The
//!   idle-switch path zeroes only the SYSCALL `kernel_rsp` and leaves
//!   `TSS.rsp0` pointing at a previous (now foreign) thread's stack; an
//!   interrupt arriving on that CPU lands its frame on the foreign live stack.
//!
//! # The probe
//!
//! Each CPU publishes, into [`PER_CPU_EXEC_FRAME`]:
//!
//! * `OwnStack` — the physical span of the kstack the CPU is currently
//!   executing on, published at [`note_own_stack_for_current`] (called from
//!   `sched::note_switch_completed`, i.e. AFTER the stack flip), and
//! * `Rsp0` — the physical frame its `TSS.rsp0` names, published at
//!   [`note_rsp0`] (called from `gdt::update_tss_rsp0`).
//!
//! At [`alias_scan`] (called at `mirror_maintain` entry — runs on every
//! `schedule()`, `THREAD_TABLE` held, lock-free reads only), the running CPU
//! maps its own RSP to a physical frame and scans every OTHER online CPU:
//!
//! * my running stack overlaps another CPU's `OwnStack` ⇒ **Candidate A**
//!   (kstack double-use): two CPUs on one physical kstack.  The genesis of the
//!   aliased frame is reported — which alloc path served it (cache / pmm /
//!   emergency, via [`record_kstack_genesis`]), the RIP that last freed that
//!   frame (`free_shadow_lookup`), and whether the frame overlaps a registered
//!   static / idle / IST stack (via [`register_static_stack`]).
//! * another CPU's `Rsp0` aims into my live running stack (and that CPU is not
//!   itself running on my stack) ⇒ **Candidate B** (stale `TSS.rsp0`).
//!
//! # Cost / perturbation
//!
//! The scan is O(online-CPUs) lock-free atomic loads plus one RSP read — far
//! lighter than the round-2 per-allocation full-PML4 reverse scan, which
//! slowed the boot ~5× and could itself widen the race.  Off-feature the whole
//! module is absent and every call site compiles to nothing.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::arch::x86_64::apic::{cpu_count, cpu_index, MAX_CPUS};
use crate::proc::KERNEL_VIRT_OFFSET;

const PAGE: u64 = 0x1000;
const PAGE_MASK: u64 = !(PAGE - 1);

/// Read the current stack pointer.
#[inline(always)]
fn read_rsp() -> u64 {
    let rsp: u64;
    // SAFETY: reads RSP into a register; no memory, no clobbers, flags preserved.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    rsp
}

/// Translate a kernel virtual address to its physical address.  Kernel stacks,
/// the static IST/interrupt stacks and the heap all map via the higher-half
/// direct map (VA = `KERNEL_VIRT_OFFSET` + phys); the BSP-idle bootstrap stack
/// is identity-mapped low (VA == phys).  Both are covered.
#[inline(always)]
fn va_to_phys(va: u64) -> u64 {
    if va >= KERNEL_VIRT_OFFSET {
        va - KERNEL_VIRT_OFFSET
    } else {
        va
    }
}

// ─── PER_CPU_EXEC_FRAME ─────────────────────────────────────────────────────

/// Per-CPU published execution-frame view.  Updated only by the owning CPU
/// (writers never race each other on one slot — a CPU is single-threaded);
/// read by every other CPU.  A small `gen` seqlock guards a consistent
/// snapshot so a reader never mixes a fresh `own_base` with a stale `own_end`.
#[repr(align(64))]
struct ExecFrame {
    /// Even = stable, odd = mid-update (seqlock generation).
    gen: AtomicU64,
    /// Physical base of the kstack this CPU runs on (0 = unset).
    own_base: AtomicU64,
    /// Physical end (exclusive) of that kstack.
    own_end: AtomicU64,
    /// Tid of the thread running on that kstack.
    own_tid: AtomicU64,
    /// Physical address of `TSS.rsp0` (the top the interrupt frame lands below);
    /// 0 = unset.
    rsp0_phys: AtomicU64,
    /// Tid for which `TSS.rsp0` was last set.
    rsp0_tid: AtomicU64,
}

impl ExecFrame {
    const fn new() -> Self {
        ExecFrame {
            gen: AtomicU64::new(0),
            own_base: AtomicU64::new(0),
            own_end: AtomicU64::new(0),
            own_tid: AtomicU64::new(0),
            rsp0_phys: AtomicU64::new(0),
            rsp0_tid: AtomicU64::new(0),
        }
    }
}

static PER_CPU_EXEC_FRAME: [ExecFrame; MAX_CPUS] = [const { ExecFrame::new() }; MAX_CPUS];

/// Begin a seqlock write window on `cpu`'s slot (sets gen odd).
#[inline]
fn frame_write_begin(cpu: usize) {
    PER_CPU_EXEC_FRAME[cpu].gen.fetch_add(1, Ordering::Release);
}

/// End a seqlock write window on `cpu`'s slot (sets gen even).
#[inline]
fn frame_write_end(cpu: usize) {
    PER_CPU_EXEC_FRAME[cpu].gen.fetch_add(1, Ordering::Release);
}

/// Consistent snapshot of `cpu`'s slot, or `None` if a writer was mid-update
/// across a bounded number of retries (the slot is simply skipped this pass).
#[inline]
fn frame_snapshot(cpu: usize) -> Option<(u64, u64, u64, u64, u64)> {
    let f = &PER_CPU_EXEC_FRAME[cpu];
    for _ in 0..8 {
        let g1 = f.gen.load(Ordering::Acquire);
        if g1 & 1 != 0 {
            continue; // mid-update
        }
        let own_base = f.own_base.load(Ordering::Relaxed);
        let own_end = f.own_end.load(Ordering::Relaxed);
        let own_tid = f.own_tid.load(Ordering::Relaxed);
        let rsp0_phys = f.rsp0_phys.load(Ordering::Relaxed);
        let rsp0_tid = f.rsp0_tid.load(Ordering::Relaxed);
        let g2 = f.gen.load(Ordering::Acquire);
        if g1 == g2 {
            return Some((own_base, own_end, own_tid, rsp0_phys, rsp0_tid));
        }
    }
    None
}

/// Publish the OwnStack span (physical) for the current CPU's running thread.
///
/// Called from `sched::note_switch_completed` (after the stack flip) and the
/// first-run path; resolves the incoming thread's kstack span from
/// `THREAD_TABLE` (`try_lock`, never blocks — this runs with interrupts
/// disabled right after `switch_context`).  Idle / no-dedicated-stack threads
/// (`kernel_stack_base == 0`) fall back to the current RSP's single page so the
/// CPU's actual execution frame is still represented.
pub fn note_own_stack_for_current() {
    let cpu = cpu_index();
    if cpu >= MAX_CPUS {
        return;
    }
    let tid = crate::proc::current_tid();
    let (mut pb, mut pe) = (0u64, 0u64);
    if let Some(threads) = crate::proc::THREAD_TABLE.try_lock() {
        if let Some(t) = threads.iter().find(|t| t.tid == tid) {
            let base = t.kernel_stack_base;
            let size = t.kernel_stack_size;
            if base != 0 && size != 0 {
                let phys = va_to_phys(base);
                pb = phys;
                pe = phys + size;
            }
        }
    }
    if pb == 0 {
        // Idle / bootstrap / no recorded kstack: record the current RSP page.
        let phys = va_to_phys(read_rsp()) & PAGE_MASK;
        pb = phys;
        pe = phys + PAGE;
    }
    frame_write_begin(cpu);
    PER_CPU_EXEC_FRAME[cpu].own_base.store(pb, Ordering::Relaxed);
    PER_CPU_EXEC_FRAME[cpu].own_end.store(pe, Ordering::Relaxed);
    PER_CPU_EXEC_FRAME[cpu].own_tid.store(tid as u64, Ordering::Relaxed);
    frame_write_end(cpu);
}

/// Publish the `TSS.rsp0` physical frame for the current CPU.
///
/// Called from `gdt::update_tss_rsp0`.  `stack_top` is the higher-half VA the
/// hardware loads as RSP on a Ring 3 → Ring 0 transition (Intel SDM Vol. 3A
/// §6.14); the interrupt frame is pushed just below it, so the page recorded is
/// the one containing `stack_top - 1`.  The idle-switch path does NOT call
/// `update_tss_rsp0`, so a stale value persists here — exactly the Candidate-B
/// condition the scan detects.
pub fn note_rsp0(stack_top: u64) {
    let cpu = cpu_index();
    if cpu >= MAX_CPUS {
        return;
    }
    let phys = if stack_top == 0 { 0 } else { va_to_phys(stack_top) };
    let tid = crate::proc::current_tid() as u64;
    frame_write_begin(cpu);
    PER_CPU_EXEC_FRAME[cpu].rsp0_phys.store(phys, Ordering::Relaxed);
    PER_CPU_EXEC_FRAME[cpu].rsp0_tid.store(tid, Ordering::Relaxed);
    frame_write_end(cpu);
}

// ─── kstack alloc genesis ring ──────────────────────────────────────────────

/// Number of recent kstack allocations whose provenance is retained.  FF spawns
/// ~120 threads but heavily recycles; 512 covers a wide recent window.
const GENESIS_RING: usize = 512;
const SRC_CACHE: u64 = 1;
const SRC_PMM: u64 = 2;
const SRC_EMERGENCY: u64 = 3;

static GEN_BASE: [AtomicU64; GENESIS_RING] = [const { AtomicU64::new(0) }; GENESIS_RING];
static GEN_END: [AtomicU64; GENESIS_RING] = [const { AtomicU64::new(0) }; GENESIS_RING];
/// Packs `src` (low 8 bits) and the allocation sequence number (>> 8).
static GEN_TAG: [AtomicU64; GENESIS_RING] = [const { AtomicU64::new(0) }; GENESIS_RING];
static GEN_HEAD: AtomicUsize = AtomicUsize::new(0);
static GEN_SEQ: AtomicU64 = AtomicU64::new(1);

/// Record a kstack allocation's physical provenance.  `src` is "cache",
/// "pmm" or "emergency"; `base`/`size` are the kstack VA span.  Lock-free
/// (a torn ring slot is benign for a diagnostic).
pub fn record_kstack_genesis(base: u64, size: u64, src: &str) {
    if base < KERNEL_VIRT_OFFSET || size == 0 {
        return;
    }
    let src_tag = match src {
        "cache" => SRC_CACHE,
        "pmm" => SRC_PMM,
        _ => SRC_EMERGENCY,
    };
    let seq = GEN_SEQ.fetch_add(1, Ordering::Relaxed);
    let i = GEN_HEAD.fetch_add(1, Ordering::Relaxed) % GENESIS_RING;
    let phys = base - KERNEL_VIRT_OFFSET;
    GEN_BASE[i].store(phys, Ordering::Relaxed);
    GEN_END[i].store(phys + size, Ordering::Relaxed);
    GEN_TAG[i].store((seq << 8) | src_tag, Ordering::Relaxed);
}

/// Find the most-recent genesis ring entry whose physical span contains
/// `phys`.  Returns `(src_name, alloc_seq)` or `None`.
fn genesis_lookup(phys: u64) -> Option<(&'static str, u64)> {
    let mut best: Option<(u64, u64)> = None; // (seq, tag)
    for i in 0..GENESIS_RING {
        let b = GEN_BASE[i].load(Ordering::Relaxed);
        let e = GEN_END[i].load(Ordering::Relaxed);
        if b == 0 || e <= b {
            continue;
        }
        if phys >= b && phys < e {
            let tag = GEN_TAG[i].load(Ordering::Relaxed);
            let seq = tag >> 8;
            if best.map_or(true, |(bseq, _)| seq > bseq) {
                best = Some((seq, tag));
            }
        }
    }
    best.map(|(seq, tag)| {
        let name = match tag & 0xff {
            SRC_CACHE => "cache",
            SRC_PMM => "pmm",
            SRC_EMERGENCY => "emergency",
            _ => "?",
        };
        (name, seq)
    })
}

// ─── static / idle / IST stack registry ─────────────────────────────────────

/// Kinds of stacks NOT visible to the THREAD_TABLE-based alloc guard.
const STATIC_REG: usize = 64;
static STAT_BASE: [AtomicU64; STATIC_REG] = [const { AtomicU64::new(0) }; STATIC_REG];
static STAT_END: [AtomicU64; STATIC_REG] = [const { AtomicU64::new(0) }; STATIC_REG];
/// Index into [`STAT_KINDS`].
static STAT_KIND: [AtomicU64; STATIC_REG] = [const { AtomicU64::new(0) }; STATIC_REG];
static STAT_COUNT: AtomicUsize = AtomicUsize::new(0);

static STAT_KINDS: [&str; 5] = [
    "?",
    "bsp-interrupt",
    "bsp-double-fault",
    "ap-interrupt",
    "ap-double-fault",
];

/// Register a static / idle / IST stack physical span the alloc guard cannot
/// see.  `kind` 1..=4 indexes [`STAT_KINDS`].  Called once from `gdt::init`.
pub fn register_static_stack(va_base: u64, span: u64, kind: u64) {
    if span == 0 {
        return;
    }
    let phys = va_to_phys(va_base);
    let i = STAT_COUNT.fetch_add(1, Ordering::Relaxed);
    if i >= STATIC_REG {
        return;
    }
    STAT_BASE[i].store(phys, Ordering::Relaxed);
    STAT_END[i].store(phys + span, Ordering::Relaxed);
    STAT_KIND[i].store(kind, Ordering::Relaxed);
}

/// Name the registered static span containing `phys`, or "none".
fn static_lookup(phys: u64) -> &'static str {
    let n = STAT_COUNT.load(Ordering::Relaxed).min(STATIC_REG);
    for i in 0..n {
        let b = STAT_BASE[i].load(Ordering::Relaxed);
        let e = STAT_END[i].load(Ordering::Relaxed);
        if b != 0 && e > b && phys >= b && phys < e {
            let k = STAT_KIND[i].load(Ordering::Relaxed) as usize;
            return STAT_KINDS.get(k).copied().unwrap_or("?");
        }
    }
    "none"
}

// ─── the discriminating scan ────────────────────────────────────────────────

/// Total `[655/ALIAS]` lines emitted this boot; bounds serial output so a hit
/// storm cannot saturate COM1 and starve the guest (the round-2 lesson).
static ALIAS_HITS: AtomicU64 = AtomicU64::new(0);
const ALIAS_HIT_CAP: u64 = 24;

/// Scan, at `mirror_maintain` entry, for a physical kstack alias between the
/// running CPU and any other online CPU, and classify it A vs B.  Lock-free.
pub fn alias_scan() {
    let a = cpu_index();
    if a >= MAX_CPUS {
        return;
    }
    let ncpus = (cpu_count().min(MAX_CPUS as u32)) as usize;
    if ncpus <= 1 {
        return; // SMP=1 is immune by construction (no peer CPU).
    }

    // My running stack span (prefer the recorded OwnStack; fall back to the
    // current RSP page if not yet published).
    let my_rsp = read_rsp();
    let my_phys = va_to_phys(my_rsp);
    let my_page = my_phys & PAGE_MASK;
    let (a_base, a_end) = match frame_snapshot(a) {
        Some((b, e, _, _, _)) if b != 0 && e > b => (b, e),
        _ => (my_page, my_page + PAGE),
    };
    let my_tid = crate::proc::current_tid();
    let my_cr3 = crate::mm::vmm::get_cr3();

    for b in 0..ncpus {
        if b == a {
            continue;
        }

        // ── DOUBLE-DISPATCH (authoritative, latency-free) ───────────────────
        // The per-CPU CURRENT_TID is published with Release at every pick
        // (`set_current_tid`), so it is the authoritative "who is this CPU
        // running" signal — unlike the OwnStack snapshot it has no publish lag.
        // If another online CPU's CURRENT_TID equals mine for a real (non-idle)
        // user thread, ONE thread is concurrently dispatched on TWO CPUs: both
        // execute on its single kernel stack and cross-corrupt the saved frame
        // in place (the in-place foreign writer the #655 saga converged on).
        // This is neither Candidate A (alloc/static kstack alias between two
        // DISTINCT threads) nor Candidate B (stale TSS.rsp0) — it is a
        // scheduler pick/resume mutual-exclusion hole.
        let b_cur = crate::proc::current_tid_on_cpu(b);
        if my_tid != 0 && my_tid < 0x1000 && b_cur == my_tid {
            if ALIAS_HITS.fetch_add(1, Ordering::Relaxed) < ALIAS_HIT_CAP {
                let span_name = static_lookup(my_phys & PAGE_MASK);
                crate::serial_println!(
                    "[655/ALIAS] class=DD cpu={} tid={} cr3={:#x} rsp={:#x} my_phys={:#x} \
                     my_stack=[{:#x},{:#x}) | cpu={} CURRENT_TID={} (SAME) \
                     — one thread dispatched on two CPUs (scheduler pick/resume race) \
                     static_span={}",
                    a, my_tid, my_cr3, my_rsp, my_phys, a_base, a_end,
                    b, b_cur, span_name,
                );
            }
            continue;
        }

        let Some((bb, be, b_tid, b_rsp0, b_rsp0_tid)) = frame_snapshot(b) else {
            continue;
        };

        // ── Candidate A: two CPUs' running kstacks overlap ──────────────────
        let b_valid = bb != 0 && be > bb;
        if b_valid && a_base < be && bb < a_end {
            if ALIAS_HITS.fetch_add(1, Ordering::Relaxed) < ALIAS_HIT_CAP {
                let overlap_phys = if a_base > bb { a_base } else { bb };
                let (free_tick, free_rip) =
                    crate::mm::w215_diag::free_shadow_lookup(overlap_phys).unwrap_or((0, 0));
                let (gsrc, gseq) = genesis_lookup(overlap_phys).unwrap_or(("unknown", 0));
                let span_name = static_lookup(overlap_phys);
                crate::serial_println!(
                    "[655/ALIAS] class=A cpu={} tid={} cr3={:#x} rsp={:#x} my_phys={:#x} \
                     my_stack=[{:#x},{:#x}) IN cpu={} tid={} OwnStack=[{:#x},{:#x}) \
                     overlap_phys={:#x} | GENESIS alloc_path={} alloc_seq={} \
                     last_free_tick={} last_free_rip={:#x} static_span={}",
                    a, my_tid, my_cr3, my_rsp, my_phys, a_base, a_end,
                    b, b_tid, bb, be, overlap_phys,
                    gsrc, gseq, free_tick, free_rip, span_name,
                );
            }
            continue;
        }

        // ── Candidate B: B's stale TSS.rsp0 aims into my live running stack ──
        // (and B is NOT itself running on my stack — that would be class A,
        // already handled above).
        if b_rsp0 != 0 {
            // The page an interrupt frame would land in (just below rsp0 top).
            let b_rsp0_page = b_rsp0.saturating_sub(1) & PAGE_MASK;
            // B legitimately owns rsp0 when it names B's own running stack.
            let b_owns_rsp0 = b_valid && b_rsp0 > bb && b_rsp0 <= be;
            // Spec literal: my RSP's page == B's rsp0 frame page.
            let my_in_rsp0 = my_page == b_rsp0_page;
            // More sensitive: B's rsp0 top falls inside my running stack span.
            let rsp0_in_my_stack = b_rsp0 > a_base && b_rsp0 <= a_end;
            if !b_owns_rsp0 && (my_in_rsp0 || rsp0_in_my_stack) {
                if ALIAS_HITS.fetch_add(1, Ordering::Relaxed) < ALIAS_HIT_CAP {
                    let span_name = static_lookup(b_rsp0_page);
                    let test = if my_in_rsp0 { "rsp-in-rsp0-page" } else { "rsp0-in-my-stack" };
                    crate::serial_println!(
                        "[655/ALIAS] class=B cpu={} tid={} cr3={:#x} rsp={:#x} my_phys={:#x} \
                         my_stack=[{:#x},{:#x}) | cpu={} stale_rsp0_phys={:#x} rsp0_tid={} \
                         rsp0_page={:#x} test={} static_span={}",
                        a, my_tid, my_cr3, my_rsp, my_phys, a_base, a_end,
                        b, b_rsp0, b_rsp0_tid, b_rsp0_page, test, span_name,
                    );
                }
            }
        }
    }
}
