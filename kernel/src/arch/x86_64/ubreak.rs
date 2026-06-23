//! Userspace execution breakpoints (CoW-private int3).
//!
//! A debug-only facility for breaking on a *userspace* virtual address in one
//! specific process without disturbing any other process that shares the same
//! code page.  It exists because the two ordinary ways to break on a user VA
//! are both unusable on this target:
//!
//!   * A QEMU/GDB hardware execution breakpoint (Intel SDM Vol. 3B §17.2,
//!     DR0–DR3 + DR7) is silently overwritten — the kernel re-programs its own
//!     debug registers on every IRQ entry for an unrelated diagnostic, so a
//!     hardware breakpoint armed by the external stub never survives to fire.
//!   * A plain software breakpoint (`int3` / `0xCC`, Intel SDM Vol. 2A) written
//!     into a shared, copy-on-write library code page corrupts *every* process
//!     mapping that frame — including processes the debugger is not targeting —
//!     which wedges the system.
//!
//! The fix is to give the target process a **private copy** of the single code
//! page before planting the `0xCC`:
//!
//!   1. Walk the target CR3 to the leaf PTE for the page (Intel SDM Vol. 3A
//!      §4.5, 4-level paging).
//!   2. Allocate a fresh frame, copy the page's bytes into it.
//!   3. Re-point the leaf PTE at the private frame (preserving the original
//!      USER / NX / present bits), invalidate the TLB entry (`invlpg`).
//!   4. Save the original byte at the target offset and overwrite it with
//!      `0xCC`.
//!
//! The shared library frame is now untouched for every other process; only the
//! target sees the breakpoint.
//!
//! When the planted `int3` executes from Ring 3 the CPU raises #BP (vector 3,
//! IDT entry DPL=3).  The vector-3 path in `idt.rs` calls
//! [`on_breakpoint`], which matches the faulting `(CR3, RIP-1)` against the
//! registry, snapshots the general-purpose registers plus a small set of
//! register-relative memory windows into a ring, then restores the original
//! byte, rewinds `RIP`, and lets execution continue (one-shot).  The snapshots
//! are drained out-of-band over the KDB protocol (`ubreak dump`).
//!
//! One-shot is the default: the primary use is breaking on a *panic branch* that
//! executes exactly once before the process aborts.
//!
//! ## Re-arm mode (TF single-step)
//!
//! A breakpoint may instead be armed **re-armable** so it fires every time the
//! VA executes (e.g. a copy loop that runs once per message until a *corrupt*
//! one appears).  Re-arm uses the trap flag, not a second `0xCC`:
//!
//!   1. On the `#BP` hit the original byte is restored and `RIP` rewound, but the
//!      slot is NOT disarmed.  Instead `RFLAGS.TF` (Intel SDM Vol. 3B §17.3.1.1,
//!      single-step) is set in the saved interrupt frame and the slot is recorded
//!      as "pending re-arm".
//!   2. The CPU re-executes the original instruction and then raises `#DB`
//!      (vector 1) — the single-step trap.  The vector-1 hook re-plants the
//!      `0xCC` at the (now-stepped-past) VA, clears `TF`, and returns.
//!
//! There is a one-instruction window where the byte is absent.  On a
//! single-process, SMP=1 target that window is safe: no other thread can fetch
//! that VA in the gap.  Re-arm is therefore restricted to that configuration and
//! to the `kdb` build (which does NOT enable `w215-diag`, so vector 1 / `#DB` is
//! otherwise unused — Intel SDM Vol. 3B §17.2 debug registers are untouched by
//! TF single-step).
//!
//! A re-armable breakpoint may carry a **capture gate** (`gate_len`): the
//! snapshot is only recorded when `RDX == gate_len` at the hit (the copy length
//! at the consumer copy-site), so a hot loop only banks the message size of
//! interest and the 16-deep ring keeps the most recent matching hits.
//!
//! Feature-gated behind `kdb`; absent from production builds.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::mm::vmm::{self, PHYS_OFF};

/// Maximum simultaneously-armed userspace breakpoints.
pub const MAX_UBREAKS: usize = 8;
/// Captured-snapshot ring depth.
pub const SNAP_RING: usize = 16;
/// Memory windows captured per snapshot (register + offset → bytes).
pub const MEM_WINDOWS: usize = 3;
/// Bytes captured per memory window.
pub const MEM_WINDOW_LEN: usize = 64;

/// One armed breakpoint slot.
struct UBreak {
    active: AtomicBool,
    cr3: AtomicU64,
    va: AtomicU64,
    orig_byte: AtomicU64, // low 8 bits hold the saved byte
    private_phys: AtomicU64,
    hits: AtomicU64,
    // Index into AUTO_ARM_OFFSETS/CONSUMED, or usize::MAX for a manually-armed
    // (kdb `ubreak set`) breakpoint with no auto-arm offset.
    auto_idx: AtomicUsize,
    // Re-armable: on a hit, single-step (TF) and re-plant the int3 instead of
    // disarming one-shot.  See the module docs (re-arm mode).
    rearm: AtomicBool,
    // Capture gate for re-armable breakpoints: snapshot only when RDX == gate_len
    // at the hit.  0 = always capture.
    gate_len: AtomicU64,
}

impl UBreak {
    const fn new() -> Self {
        UBreak {
            active: AtomicBool::new(false),
            cr3: AtomicU64::new(0),
            va: AtomicU64::new(0),
            orig_byte: AtomicU64::new(0),
            private_phys: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            auto_idx: AtomicUsize::new(usize::MAX),
            rearm: AtomicBool::new(false),
            gate_len: AtomicU64::new(0),
        }
    }
}

/// A captured register + memory snapshot taken at a breakpoint hit.
#[derive(Clone, Copy)]
pub struct Snapshot {
    pub valid: bool,
    pub cr3: u64,
    pub rip: u64,
    pub rsp: u64,
    pub tid: u64,
    pub pid: u64,
    // GPRs in the canonical order used by the #UD dump in idt.rs.
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// (base_va, len) of each captured window; len==0 = unused.
    pub win_va: [u64; MEM_WINDOWS],
    pub win_len: [u32; MEM_WINDOWS],
    pub win_bytes: [[u8; MEM_WINDOW_LEN]; MEM_WINDOWS],
}

impl Snapshot {
    const fn empty() -> Self {
        Snapshot {
            valid: false,
            cr3: 0, rip: 0, rsp: 0, tid: 0, pid: 0,
            rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rbp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
            win_va: [0; MEM_WINDOWS],
            win_len: [0; MEM_WINDOWS],
            win_bytes: [[0; MEM_WINDOW_LEN]; MEM_WINDOWS],
        }
    }
}

// Registry of armed breakpoints.
static BREAKS: [UBreak; MAX_UBREAKS] = [
    UBreak::new(), UBreak::new(), UBreak::new(), UBreak::new(),
    UBreak::new(), UBreak::new(), UBreak::new(), UBreak::new(),
];

// Snapshot ring.  Single-producer (the #BP ISR is non-reentrant w.r.t. itself
// because the byte is restored one-shot), single-drainer (KDB).  A spin::Mutex
// is unsuitable inside the exception path, so the ring uses a monotonic head
// and a SeqCst publish flag per slot.
static SNAPS: spin::Mutex<[Snapshot; SNAP_RING]> =
    spin::Mutex::new([Snapshot::empty(); SNAP_RING]);
static SNAP_HEAD: AtomicUsize = AtomicUsize::new(0);
static SNAP_COUNT: AtomicU64 = AtomicU64::new(0);

const PAGE_SIZE: u64 = 0x1000;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ── Auto-arm (boot-flag driven, kdb-independent) ───────────────────────────────
//
// When set (via the `astryx.ubreak=<elf_offset>` boot token), the kernel
// auto-arms a one-shot breakpoint at `load_base + AUTO_ARM_OFFSET` for any
// process the moment it demand-faults the page containing that offset.  This
// removes the host-side timing race and works under KDB starvation.  The
// crash in the moz2d blob path fires VERY early and in a content process, so a
// host poll cannot reliably plant in time.  Sentinel 0 = disabled.
// Up to 4 auto-arm offsets (e.g. add-entry + the panic branches + the crash
// thunk).  Sentinel 0 in a slot = unused.  Each offset carries a 4-byte
// instruction SIGNATURE (the first 4 code bytes expected at that ELF offset);
// the auto-arm only fires when the target page's bytes match, which rejects a
// wrong load base computed from a NON-libxul VMA (ld-musl, libc, etc.) that
// happens to make the target page present.
const MAX_AUTO_ARM: usize = 4;
static AUTO_ARM_OFFSETS: [AtomicU64; MAX_AUTO_ARM] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static AUTO_ARM_SIGS: [AtomicU64; MAX_AUTO_ARM] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
// Per-offset re-arm flag: true = re-armable (TF single-step re-plant), false =
// one-shot.  A re-armable offset is NEVER marked consumed on a hit, so the scan
// keeps it armed for the whole run.
static AUTO_ARM_REARM: [AtomicBool; MAX_AUTO_ARM] = [
    AtomicBool::new(false), AtomicBool::new(false),
    AtomicBool::new(false), AtomicBool::new(false),
];
// Per-offset capture gate length (0 = always capture; else only when RDX==len).
static AUTO_ARM_GATELEN: [AtomicU64; MAX_AUTO_ARM] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
// Per-offset "consumed" flags.  A one-shot breakpoint disarms its slot on the
// first hit and restores the original byte.  Without this flag the per-fault
// `maybe_auto_arm_scan` would immediately RE-arm the freed slot (re-planting
// the int3) — opening a window where the int3 is planted but no slot matches it
// (slot freed, scan not yet re-run), so a #BP between disarm and re-arm hits the
// generic handler, is not rewound, and SIGSEGVs.  Marking the offset consumed
// makes the scan skip it forever, so each offset fires exactly once.
static AUTO_ARM_CONSUMED: [AtomicBool; MAX_AUTO_ARM] = [
    AtomicBool::new(false), AtomicBool::new(false),
    AtomicBool::new(false), AtomicBool::new(false),
];
// Fast-path early-out flag: non-zero iff at least one auto-arm offset is set.
// (De-dup of already-armed (cr3, va) pairs is handled by `is_armed`.)
static AUTO_ARM_OFFSET: AtomicU64 = AtomicU64::new(0);

// ── Pending re-arm (TF single-step re-plant) ────────────────────────────────────
//
// When a re-armable breakpoint hits, its original byte is restored and the slot
// is recorded here so the vector-1 (#DB) single-step trap can re-plant the int3
// after the original instruction re-executes.  SMP=1 + single debugged process
// means exactly one re-arm can be pending at a time; the sentinel is
// `usize::MAX`.  These are written by the #BP path and read/cleared by the #DB
// path on the SAME CPU (TF single-step traps on the next instruction of the same
// thread), so a plain atomic is sufficient.
static PENDING_REARM_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static PENDING_REARM_CR3: AtomicU64 = AtomicU64::new(0);
static PENDING_REARM_VA: AtomicU64 = AtomicU64::new(0);

/// Enable auto-arm at the given libxul-relative ELF offset with a 4-byte
/// instruction signature, an optional re-arm flag, and an optional capture-gate
/// length.
///
/// * `sig`==0 disables the signature check for that offset.
/// * `rearm`==true makes the breakpoint re-armable (TF single-step re-plant)
///   instead of one-shot.
/// * `gate_len`!=0 limits captures of a re-armable breakpoint to hits where
///   `RDX == gate_len` (the copy length at the consumer copy-site).
///
/// (0 offset disables the slot.)
pub fn set_auto_arm_full(off: u64, sig: u32, rearm: bool, gate_len: u64) {
    if off == 0 {
        return;
    }
    AUTO_ARM_OFFSET.store(off, Ordering::Release);
    for idx in 0..MAX_AUTO_ARM {
        if AUTO_ARM_OFFSETS[idx].load(Ordering::Acquire) == 0 {
            AUTO_ARM_SIGS[idx].store(sig as u64, Ordering::Release);
            AUTO_ARM_REARM[idx].store(rearm, Ordering::Release);
            AUTO_ARM_GATELEN[idx].store(gate_len, Ordering::Release);
            // Publish the offset LAST so a concurrent scan never sees an offset
            // before its sig/rearm/gate metadata.
            AUTO_ARM_OFFSETS[idx].store(off, Ordering::Release);
            return;
        }
    }
}

/// Enable auto-arm with a signature check (one-shot, no gate).
pub fn set_auto_arm_offset_sig(off: u64, sig: u32) {
    set_auto_arm_full(off, sig, false, 0);
}

/// Back-compat: enable auto-arm with no signature check (legacy single-offset).
pub fn set_auto_arm_offset(off: u64) {
    set_auto_arm_full(off, 0, false, 0);
}

/// Read the first 4 bytes at `va` in `cr3` as a little-endian u32 (0 if any
/// byte is unmapped).
fn read_sig4(cr3: u64, va: u64) -> u32 {
    let mut buf = [0u8; MEM_WINDOW_LEN];
    let n = read_user(cr3, va, &mut buf);
    if n < 4 {
        return 0;
    }
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Page-fault-install hook.  Called after a Linux process demand-faults a
/// file-backed executable page.  `load_base` is the libxul ELF load base
/// (faulting_addr - vaddr_in_elf), `faulted_page` is the page-aligned VA just
/// installed.  If auto-arm is enabled and the requested offset's page == the
/// faulted page (and this CR3 hasn't been armed yet), plant the breakpoint.
///
/// Cheap fast-path: a single relaxed atomic load returns immediately when
/// auto-arm is disabled (the production / non-debug case).
pub fn maybe_auto_arm(cr3: u64, load_base: u64, faulted_page: u64) {
    // Fast-path early-out: nothing to do unless at least one offset is set.
    if AUTO_ARM_OFFSET.load(Ordering::Acquire) == 0 {
        return;
    }
    for idx in 0..MAX_AUTO_ARM {
        let off = AUTO_ARM_OFFSETS[idx].load(Ordering::Acquire);
        if off == 0 {
            continue;
        }
        if AUTO_ARM_CONSUMED[idx].load(Ordering::Acquire) {
            continue;
        }
        let target_va = load_base.wrapping_add(off);
        if (target_va & !(PAGE_SIZE - 1)) != faulted_page {
            continue;
        }
        // De-dup: skip if THIS (cr3, target_va) is already armed.
        if is_armed(cr3, target_va) {
            continue;
        }
        // Signature gate (reject a wrong non-libxul load base).
        let sig = AUTO_ARM_SIGS[idx].load(Ordering::Acquire) as u32;
        if sig != 0 && read_sig4(cr3, target_va) != sig {
            continue;
        }
        let rearm = AUTO_ARM_REARM[idx].load(Ordering::Acquire);
        let gate_len = AUTO_ARM_GATELEN[idx].load(Ordering::Acquire);
        if arm_at_cr3_idx(cr3, target_va, idx, rearm, gate_len).is_ok() {
            crate::serial_println!(
                "[UBREAK] auto-armed cr3={:#x} load_base={:#x} target={:#x} (off={:#x} rearm={} gate={})",
                cr3, load_base, target_va, off, rearm, gate_len
            );
        }
    }
}

/// True if a breakpoint at `(cr3, va)` is currently armed.
fn is_armed(cr3: u64, va: u64) -> bool {
    for slot in BREAKS.iter() {
        if slot.active.load(Ordering::Acquire)
            && slot.cr3.load(Ordering::Acquire) == cr3
            && slot.va.load(Ordering::Acquire) == va
        {
            return true;
        }
    }
    false
}

/// Per-fault auto-arm scan.  Called from the page-fault handler on every fault
/// (cheap early-out when disabled).  Unlike `maybe_auto_arm` (which only fires
/// when the freshly-installed page IS a target — and so misses targets that
/// were demand-faulted before the offset was set, or brought in via readahead,
/// or are in a hot pre-faulted page), this walks the faulting process's VMAs to
/// find libxul (the large r-x file-backed mapping), computes its ELF load base,
/// and arms any target page that is already present.  Faults happen frequently
/// during Firefox startup, so a target page becomes armed shortly after libxul
/// maps — well before the moz2d blob code executes.
///
/// `find_libxul` returns (load_base) for the current process or None.
pub fn maybe_auto_arm_scan(load_base: u64, cr3: u64) {
    if AUTO_ARM_OFFSET.load(Ordering::Acquire) == 0 {
        return;
    }
    if load_base == 0 {
        return;
    }
    for idx in 0..MAX_AUTO_ARM {
        let off = AUTO_ARM_OFFSETS[idx].load(Ordering::Acquire);
        if off == 0 {
            continue;
        }
        // Skip offsets that have already fired once (one-shot): re-arming them
        // would re-open the plant-without-active-slot window (see
        // AUTO_ARM_CONSUMED docs).
        if AUTO_ARM_CONSUMED[idx].load(Ordering::Acquire) {
            continue;
        }
        let target_va = load_base.wrapping_add(off);
        if is_armed(cr3, target_va) {
            continue;
        }
        // Only arm if the target page is already present in this CR3.
        let page = target_va & !(PAGE_SIZE - 1);
        if vmm::read_pte(cr3, page) & vmm::PAGE_PRESENT == 0 {
            continue;
        }
        // Signature gate: reject a wrong load base (from a non-libxul VMA) by
        // requiring the target's first 4 code bytes to match the expected
        // instruction signature.  sig==0 disables the check.
        let sig = AUTO_ARM_SIGS[idx].load(Ordering::Acquire) as u32;
        if sig != 0 && read_sig4(cr3, target_va) != sig {
            continue;
        }
        let rearm = AUTO_ARM_REARM[idx].load(Ordering::Acquire);
        let gate_len = AUTO_ARM_GATELEN[idx].load(Ordering::Acquire);
        if arm_at_cr3_idx(cr3, target_va, idx, rearm, gate_len).is_ok() {
            crate::serial_println!(
                "[UBREAK] auto-armed (scan) cr3={:#x} load_base={:#x} target={:#x} (off={:#x} rearm={} gate={})",
                cr3, load_base, target_va, off, rearm, gate_len
            );
        }
    }
}

/// Arm a one-shot breakpoint at `va` in an explicit `cr3` (used by the auto-arm
/// PF hook, which already knows the CR3).  Same mechanism as [`arm`] minus the
/// pid→cr3 resolution.  Page must be present (it just faulted in).
#[allow(dead_code)]
fn arm_at_cr3(cr3: u64, va: u64) -> Result<(), &'static str> {
    arm_at_cr3_idx(cr3, va, usize::MAX, false, 0)
}

fn arm_at_cr3_idx(
    cr3: u64,
    va: u64,
    auto_idx: usize,
    rearm: bool,
    gate_len: u64,
) -> Result<(), &'static str> {
    let page = va & !(PAGE_SIZE - 1);
    let old_pte = vmm::read_pte(cr3, page);
    if old_pte & vmm::PAGE_PRESENT == 0 {
        return Err("page not present");
    }
    if old_pte & vmm::PAGE_HUGE != 0 {
        return Err("huge page");
    }
    let old_phys = old_pte & ADDR_MASK;
    // Idempotence guard: if the target byte is ALREADY 0xCC, this (cr3, va) is
    // already armed (by a prior install-hook OR scan-hook call that this one
    // raced).  Re-CoW-privating would mint a SECOND private frame, leaving the
    // PTE on the new frame's int3 while the registered slot's recorded
    // private_phys (and thus restore_byte) points at the OLD frame — so the
    // one-shot restore would fail to remove the live int3, turning a later #BP
    // into an unhandled SIGSEGV.  Bail out (the existing slot owns this va).
    {
        let cur = unsafe {
            core::ptr::read_volatile((PHYS_OFF + old_phys + (va & (PAGE_SIZE - 1))) as *const u8)
        };
        if cur == 0xCC {
            return Err("already armed (0xCC present)");
        }
    }
    let flags = old_pte & !ADDR_MASK;
    let new_phys = crate::mm::pmm::alloc_page().ok_or("alloc_page failed")?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            (PHYS_OFF + old_phys) as *const u8,
            (PHYS_OFF + new_phys) as *mut u8,
            PAGE_SIZE as usize,
        );
    }
    let new_pte = new_phys | flags | vmm::PAGE_WRITABLE;
    vmm::write_pte(cr3, page, new_pte);
    vmm::invlpg(page);
    // Refcount bookkeeping: the PTE now references `new_phys` (set its ref to 1,
    // mirroring the demand-paging private-copy install) and no longer references
    // `old_phys` (release the mapping ref we displaced).  Without this the old
    // shared/cache frame leaks and `new_phys` underflows its refcount at process
    // teardown (still freed correctly, but it bumps the underflow diagnostic).
    crate::mm::refcount::page_ref_set(new_phys, 1);
    let _ = crate::mm::refcount::page_ref_dec(old_phys);
    let off = (va & (PAGE_SIZE - 1)) as usize;
    let byte_ptr = (PHYS_OFF + new_phys + off as u64) as *mut u8;
    let orig = unsafe { core::ptr::read_volatile(byte_ptr) };
    unsafe { core::ptr::write_volatile(byte_ptr, 0xCC); }
    for slot in BREAKS.iter() {
        if slot
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.cr3.store(cr3, Ordering::Release);
            slot.va.store(va, Ordering::Release);
            slot.orig_byte.store(orig as u64, Ordering::Release);
            slot.private_phys.store(new_phys, Ordering::Release);
            slot.hits.store(0, Ordering::Release);
            slot.auto_idx.store(auto_idx, Ordering::Release);
            slot.rearm.store(rearm, Ordering::Release);
            slot.gate_len.store(gate_len, Ordering::Release);
            return Ok(());
        }
    }
    unsafe { core::ptr::write_volatile(byte_ptr, orig); }
    Err("no free slot")
}

/// Resolve a PID to its CR3 under a brief PROCESS_TABLE lock.
fn cr3_for_pid(pid: u64) -> Option<u64> {
    let pt = crate::proc::PROCESS_TABLE.try_lock()?;
    let c = pt.iter().find(|p| p.pid == pid).map(|p| p.cr3);
    c
}

/// Best-effort resolution of the file-backing (inode, file_offset) for a VA in
/// `cr3`.  Returns `(0, 0)` if the VA is anonymous, has no VMA, or the
/// PROCESS_TABLE lock is contended (ISR-safe: never blocks).  For a memfd
/// MAP_SHARED segment this gives the (inode, file_offset) the producer wrote to
/// / the consumer reads from, so a same-inode/same-offset pair with DIFFERENT
/// physical frames is an aliasing bug (one memfd offset mapped to two frames),
/// while a different inode/offset means the two sites reference distinct memfd
/// segments (a gecko-level segment-ref mismatch).
fn memfd_backing_of(cr3: u64, va: u64) -> (u64, u64) {
    let pt = match crate::proc::PROCESS_TABLE.try_lock() {
        Some(g) => g,
        None => return (0, 0),
    };
    for p in pt.iter() {
        if p.cr3 != cr3 {
            continue;
        }
        let vms = match &p.vm_space {
            Some(v) => v,
            None => return (0, 0),
        };
        if let Some(vma) = vms.find_vma(va) {
            if let crate::mm::vma::VmBacking::File { inode, offset, .. } = vma.backing {
                let foff = offset.wrapping_add(va.wrapping_sub(vma.base));
                return (inode, foff);
            }
        }
        return (0, 0);
    }
    (0, 0)
}

/// Arm a one-shot userspace breakpoint at `va` in process `pid`.
///
/// CoW-privates the page (so the shared library frame is untouched), saves the
/// original byte, and plants `0xCC`.  Returns Ok((cr3, private_phys, orig_byte))
/// on success.
pub fn arm(pid: u64, va: u64) -> Result<(u64, u64, u8), &'static str> {
    let cr3 = cr3_for_pid(pid).ok_or("pid not found / table busy")?;
    let page = va & !(PAGE_SIZE - 1);

    // Existing leaf PTE — must be present and a 4 KiB leaf (no huge-page code).
    let old_pte = vmm::read_pte(cr3, page);
    if old_pte & vmm::PAGE_PRESENT == 0 {
        return Err("target page not present");
    }
    if old_pte & vmm::PAGE_HUGE != 0 {
        return Err("target is a huge page");
    }
    let old_phys = old_pte & ADDR_MASK;
    let flags = old_pte & !ADDR_MASK; // preserve USER / NX / etc.

    // Allocate a private frame and copy the original page into it.
    let new_phys = crate::mm::pmm::alloc_page().ok_or("alloc_page failed")?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            (PHYS_OFF + old_phys) as *const u8,
            (PHYS_OFF + new_phys) as *mut u8,
            PAGE_SIZE as usize,
        );
    }

    // Re-point the leaf PTE at the private frame.  Keep it WRITABLE so the
    // kernel can plant/restore the byte; user code only ever fetches (RX) it,
    // and the page is process-private now so a stray user write would only
    // corrupt this one process (which is already being debugged).
    let new_pte = new_phys | flags | vmm::PAGE_WRITABLE;
    vmm::write_pte(cr3, page, new_pte);
    vmm::invlpg(page);
    // Refcount bookkeeping: the PTE now references `new_phys` (set its ref to 1,
    // mirroring the demand-paging private-copy install) and no longer references
    // `old_phys` (release the mapping ref we displaced).  Without this the old
    // shared/cache frame leaks and `new_phys` underflows its refcount at process
    // teardown (still freed correctly, but it bumps the underflow diagnostic).
    crate::mm::refcount::page_ref_set(new_phys, 1);
    let _ = crate::mm::refcount::page_ref_dec(old_phys);

    // Plant the int3.
    let off = (va & (PAGE_SIZE - 1)) as usize;
    let byte_ptr = (PHYS_OFF + new_phys + off as u64) as *mut u8;
    let orig = unsafe { core::ptr::read_volatile(byte_ptr) };
    unsafe { core::ptr::write_volatile(byte_ptr, 0xCC); }

    // Register the slot.
    for slot in BREAKS.iter() {
        if slot
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.cr3.store(cr3, Ordering::Release);
            slot.va.store(va, Ordering::Release);
            slot.orig_byte.store(orig as u64, Ordering::Release);
            slot.private_phys.store(new_phys, Ordering::Release);
            slot.hits.store(0, Ordering::Release);
            slot.auto_idx.store(usize::MAX, Ordering::Release);
            slot.rearm.store(false, Ordering::Release);
            slot.gate_len.store(0, Ordering::Release);
            return Ok((cr3, new_phys, orig));
        }
    }

    // No free slot — undo the int3 (leave the private page; harmless) and fail.
    unsafe { core::ptr::write_volatile(byte_ptr, orig); }
    Err("no free breakpoint slot")
}

/// Disarm a breakpoint (restore the original byte).  Leaves the page private
/// (cheap; a private copy of one shared code page is harmless).
pub fn disarm(cr3: u64, va: u64) -> bool {
    for slot in BREAKS.iter() {
        if !slot.active.load(Ordering::Acquire) {
            continue;
        }
        if slot.cr3.load(Ordering::Acquire) == cr3 && slot.va.load(Ordering::Acquire) == va {
            restore_byte(slot);
            slot.active.store(false, Ordering::Release);
            return true;
        }
    }
    false
}

/// Disarm all breakpoints.  Returns the count cleared.
pub fn disarm_all() -> usize {
    let mut n = 0;
    for slot in BREAKS.iter() {
        if slot.active.load(Ordering::Acquire) {
            restore_byte(slot);
            slot.active.store(false, Ordering::Release);
            n += 1;
        }
    }
    n
}

fn restore_byte(slot: &UBreak) {
    let va = slot.va.load(Ordering::Acquire);
    let orig = slot.orig_byte.load(Ordering::Acquire) as u8;
    let off = (va & (PAGE_SIZE - 1)) as usize;
    let page = va & !(PAGE_SIZE - 1);
    // Restore through the LIVE PTE frame, not the frame recorded at arm time.
    // If the page was re-installed (re-faulted into a fresh frame) between arm
    // and the hit, the recorded private_phys is stale and writing there would
    // leave the int3 live in the actual mapped frame.  Prefer the current leaf
    // PTE's frame; fall back to the recorded private_phys if the walk fails.
    let cr3 = slot.cr3.load(Ordering::Acquire);
    let live_pte = vmm::read_pte(cr3, page);
    let phys = if live_pte & vmm::PAGE_PRESENT != 0 {
        live_pte & ADDR_MASK
    } else {
        slot.private_phys.load(Ordering::Acquire)
    };
    let byte_ptr = (PHYS_OFF + phys + off as u64) as *mut u8;
    unsafe { core::ptr::write_volatile(byte_ptr, orig); }
    vmm::invlpg(page);
}

/// Result of [`on_breakpoint`]: tells the vector-3 caller what to do.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BpAction {
    /// Not one of our breakpoints — fall through to generic handling.
    NotOurs,
    /// Ours, one-shot: byte already restored, RIP rewound; just return.
    Handled,
    /// Ours, re-armable: byte restored, RIP rewound; the caller MUST set
    /// `RFLAGS.TF` so the single-step trap re-plants the int3.
    HandledRearm,
}

/// #BP handler hook.  Called from the vector-3 path in idt.rs for Ring-3
/// breakpoints.  `gpr` is the 15-element GPR array as laid out by the ISR stub
/// (see [`read_gprs_from_frame`]).
///
/// `frame_rip` is the RIP *after* the int3 (points one byte past the 0xCC).
/// On a match we capture (subject to the per-slot gate), restore the byte, and
/// rewind `*rip_out` by one so the original instruction re-executes.  For a
/// one-shot slot we disarm; for a re-armable slot we record a pending re-arm and
/// return [`BpAction::HandledRearm`] so the caller sets TF.
pub fn on_breakpoint(
    cr3: u64,
    frame_rip: u64,
    frame_rsp: u64,
    gpr: &Gprs,
    rip_out: &mut u64,
) -> BpAction {
    let bp_va = frame_rip.wrapping_sub(1);
    for (slot_idx, slot) in BREAKS.iter().enumerate() {
        if !slot.active.load(Ordering::Acquire) {
            continue;
        }
        if slot.cr3.load(Ordering::Acquire) != cr3 {
            continue;
        }
        if slot.va.load(Ordering::Acquire) != bp_va {
            continue;
        }
        slot.hits.fetch_add(1, Ordering::AcqRel);

        let rearm = slot.rearm.load(Ordering::Acquire);
        // Capture gate: a re-armable slot with a non-zero gate_len only banks
        // hits whose copy length (RDX) matches — so a hot copy loop records only
        // the message size of interest.
        let gate = slot.gate_len.load(Ordering::Acquire);
        if gate == 0 || gpr.rdx == gate {
            capture(cr3, bp_va, frame_rsp, gpr);
        }

        // Restore the original byte and rewind so the instruction re-executes.
        restore_byte(slot);
        *rip_out = bp_va;

        if rearm {
            // Re-armable: keep the slot active and record a pending re-arm so
            // the single-step (#DB) trap re-plants the int3 after the original
            // instruction executes.  Do NOT mark the offset consumed.
            PENDING_REARM_SLOT.store(slot_idx, Ordering::Release);
            PENDING_REARM_CR3.store(cr3, Ordering::Release);
            PENDING_REARM_VA.store(bp_va, Ordering::Release);
            return BpAction::HandledRearm;
        }

        // One-shot: disarm the slot (we keep the private page) and mark the
        // offset CONSUMED so the per-fault scan never re-arms it — re-arming
        // would re-open the plant-without-active-slot window that turns a later
        // #BP into an unhandled SIGSEGV.
        let idx = slot.auto_idx.load(Ordering::Acquire);
        if idx < MAX_AUTO_ARM {
            AUTO_ARM_CONSUMED[idx].store(true, Ordering::Release);
        }
        slot.active.store(false, Ordering::Release);
        return BpAction::Handled;
    }
    BpAction::NotOurs
}

/// #DB (vector 1) single-step hook for re-arm.  Called from the vector-1 path in
/// idt.rs for a Ring-3 single-step trap.  If a re-arm is pending (the prior #BP
/// set TF for this CR3), re-plant the int3 at the recorded VA, clear the pending
/// state, and return true so the caller clears TF and returns.  Returns false if
/// there is no pending re-arm (some other source of #DB).
pub fn on_debug_trap(cr3: u64) -> bool {
    let slot_idx = PENDING_REARM_SLOT.load(Ordering::Acquire);
    if slot_idx >= MAX_UBREAKS {
        return false;
    }
    if PENDING_REARM_CR3.load(Ordering::Acquire) != cr3 {
        // The single-step trap belongs to a different address space (should not
        // happen on SMP=1 single-process, but be conservative).
        return false;
    }
    let va = PENDING_REARM_VA.load(Ordering::Acquire);
    let slot = &BREAKS[slot_idx];
    // Re-plant the int3 only if the slot is still the same armed (cr3, va) and
    // the original byte is currently in place (it was restored by the #BP path).
    if slot.active.load(Ordering::Acquire)
        && slot.cr3.load(Ordering::Acquire) == cr3
        && slot.va.load(Ordering::Acquire) == va
    {
        replant_byte(slot);
    }
    PENDING_REARM_SLOT.store(usize::MAX, Ordering::Release);
    true
}

/// Re-plant the `0xCC` at a slot's VA through the LIVE PTE frame (mirrors
/// [`restore_byte`]'s live-PTE discipline so a re-faulted page is handled).
fn replant_byte(slot: &UBreak) {
    let va = slot.va.load(Ordering::Acquire);
    let off = (va & (PAGE_SIZE - 1)) as usize;
    let page = va & !(PAGE_SIZE - 1);
    let cr3 = slot.cr3.load(Ordering::Acquire);
    let live_pte = vmm::read_pte(cr3, page);
    let phys = if live_pte & vmm::PAGE_PRESENT != 0 {
        live_pte & ADDR_MASK
    } else {
        slot.private_phys.load(Ordering::Acquire)
    };
    let byte_ptr = (PHYS_OFF + phys + off as u64) as *mut u8;
    unsafe { core::ptr::write_volatile(byte_ptr, 0xCC); }
    vmm::invlpg(page);
}

/// GPR snapshot passed from the ISR stub.
#[derive(Clone, Copy)]
pub struct Gprs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Decode the 15 GPRs from the ISR stack frame, mirroring the layout the
/// `isr_no_error!` macro pushes (see idt.rs).  `frame_base` is the pointer
/// passed as `frame` to `exception_handler` (the InterruptFrame).
///
/// # Safety
/// `frame_base` must be the live InterruptFrame pointer; the saved GPRs live at
/// the negative offsets the macro pushed them to.
pub unsafe fn read_gprs_from_frame(frame_base: *const u64) -> Gprs {
    unsafe {
        Gprs {
            rax: *frame_base.sub(2),
            rcx: *frame_base.sub(3),
            rdx: *frame_base.sub(4),
            rsi: *frame_base.sub(5),
            rdi: *frame_base.sub(6),
            r8: *frame_base.sub(7),
            r9: *frame_base.sub(8),
            r10: *frame_base.sub(9),
            r11: *frame_base.sub(10),
            rbx: *frame_base.sub(11),
            rbp: *frame_base.sub(12),
            r12: *frame_base.sub(13),
            r13: *frame_base.sub(14),
            r14: *frame_base.sub(15),
            r15: *frame_base.sub(16),
        }
    }
}

/// Read up to MEM_WINDOW_LEN bytes from a userspace VA in `cr3`, page-walking
/// the target address space.  Returns the count read (0 on unmapped).
fn read_user(cr3: u64, va: u64, buf: &mut [u8; MEM_WINDOW_LEN]) -> u32 {
    let mut got: u32 = 0;
    let mut i: u64 = 0;
    while (i as usize) < buf.len() {
        let cur = va.wrapping_add(i);
        let page = cur & !(PAGE_SIZE - 1);
        let phys = match vmm::virt_to_phys_in(cr3, page) {
            Some(p) => p,
            None => break,
        };
        let off = cur & (PAGE_SIZE - 1);
        let avail = PAGE_SIZE - off;
        let take = core::cmp::min(avail, buf.len() as u64 - i);
        for b in 0..take {
            let byte = unsafe {
                core::ptr::read_volatile((PHYS_OFF + phys + off + b) as *const u8)
            };
            buf[(i + b) as usize] = byte;
            got += 1;
        }
        i += take;
    }
    got
}

/// Capture a snapshot.  Auto-derives the memory windows useful for the moz2d
/// blob gate: many libxul Rust call sites pass a fat slice / Arc<Vec<u8>>, so
/// we capture (a) the 64 bytes around RSP, (b) the 64 bytes at the object R15
/// points to (the common "this"/data register at these sites), and (c) the
/// blob payload — for an Arc<Vec<u8>> the Vec header sits at obj+0x10 as
/// {ptr@+0x18, cap, len@+0x20}; we read the ptr and capture the first bytes of
/// the buffer.  Generic callers can ignore the auto-windows and read the GPRs.
fn capture(cr3: u64, bp_va: u64, frame_rsp: u64, gpr: &Gprs) {
    let mut snap = Snapshot::empty();
    snap.valid = true;
    snap.cr3 = cr3;
    snap.rip = bp_va;
    snap.rsp = frame_rsp;
    snap.tid = crate::proc::current_tid() as u64;
    snap.pid = crate::proc::current_pid_lockless();
    snap.rax = gpr.rax; snap.rbx = gpr.rbx; snap.rcx = gpr.rcx; snap.rdx = gpr.rdx;
    snap.rsi = gpr.rsi; snap.rdi = gpr.rdi; snap.rbp = gpr.rbp;
    snap.r8 = gpr.r8; snap.r9 = gpr.r9; snap.r10 = gpr.r10; snap.r11 = gpr.r11;
    snap.r12 = gpr.r12; snap.r13 = gpr.r13; snap.r14 = gpr.r14; snap.r15 = gpr.r15;

    // Window 0: stack around RSP.
    {
        let mut buf = [0u8; MEM_WINDOW_LEN];
        let n = read_user(cr3, frame_rsp, &mut buf);
        snap.win_va[0] = frame_rsp;
        snap.win_len[0] = n;
        snap.win_bytes[0] = buf;
    }

    // Window 1: the blob `data` Arc<Vec<u8>> header.  At the moz2d
    // Moz2dBlobImageHandler::add ENTRY (off 0x6e36c70) the `data` arg is in RDX
    // (SysV ABI 3rd integer arg; confirmed by the prologue `mov 0x20(%rdx),%rsi`
    // = Vec.len, `mov 0x18(%rdx),%rax` = Vec.ptr).  Capture 64 bytes at RDX so
    // the Vec{ptr@+0x18, len@+0x20} header is preserved at capture time
    // (reading it later races the Arc being freed).
    let blob_ptr;
    let blob_len;
    {
        let mut buf = [0u8; MEM_WINDOW_LEN];
        let n = read_user(cr3, gpr.rdx, &mut buf);
        snap.win_va[1] = gpr.rdx;
        snap.win_len[1] = n;
        snap.win_bytes[1] = buf;
        blob_ptr = if n >= 0x20 {
            u64::from_le_bytes([buf[0x18], buf[0x19], buf[0x1a], buf[0x1b],
                                buf[0x1c], buf[0x1d], buf[0x1e], buf[0x1f]])
        } else { 0 };
        blob_len = if n >= 0x28 {
            u64::from_le_bytes([buf[0x20], buf[0x21], buf[0x22], buf[0x23],
                                buf[0x24], buf[0x25], buf[0x26], buf[0x27]])
        } else { 0 };
    }

    // Window 2: the FIRST 64 bytes of the blob buffer (Vec.ptr).  This is the
    // dispositive read for b1 vs b2: a degenerate blob (b2) is short / all-zero;
    // a font-region blob (b1) is ASCII font-path + zeros; a valid moz2d
    // recording starts with the 0xc001feed kMagicInt.  Also capture the blob
    // length (snap.r8 is reused to carry blob_len in the dump; see dump_json).
    {
        let mut buf = [0u8; MEM_WINDOW_LEN];
        let n = if blob_ptr != 0 { read_user(cr3, blob_ptr, &mut buf) } else { 0 };
        snap.win_va[2] = blob_ptr;
        snap.win_len[2] = n;
        snap.win_bytes[2] = buf;
    }
    // The decoded blob length is logged to serial (window 2's va already carries
    // the blob ptr); this keeps the blob ptr+len visible even when the KDB pump
    // is starved under heavy Firefox load and `ubreak dump` cannot be reached.
    if blob_len != 0 {
        crate::serial_println!(
            "[UBREAK] capture blob: rip={:#x} data(rdx)={:#x} blob_ptr={:#x} blob_len={}",
            bp_va, gpr.rdx, blob_ptr, blob_len);
    }

    // Dispositive consumer-read emit.  At the consumer copy-site (off 0x25b005f,
    // `call <memcpy>` with RSI=shmem source ptr, RDX=copy length) RSI points
    // INTO the recycled MAP_SHARED memfd segment that the render thread is about
    // to read.  Resolve RSI's *physical frame* in this thread's address space and
    // capture the first 16 bytes so a CORRUPT hit (font-path '/usr/share/fonts',
    // first u32 = 0x2f757372) is distinguishable from a CLEAN one (kMagicInt,
    // first u32 = 0xc001feed), and the source PHYS can be compared against the
    // producer's write-dest phys.  Emitted to serial directly so it survives KDB
    // starvation under heavy Firefox load.  RSI here is also valid at the moz2d
    // add site, where the line is harmless extra context.
    {
        let src_va = gpr.rsi;
        let src_page = src_va & !(PAGE_SIZE - 1);
        let src_phys = vmm::virt_to_phys_in(cr3, src_page)
            .map(|p| p | (src_va & (PAGE_SIZE - 1)))
            .unwrap_or(0);
        let mut srcbuf = [0u8; MEM_WINDOW_LEN];
        let sn = read_user(cr3, src_va, &mut srcbuf);
        let magic = if sn >= 4 {
            u32::from_le_bytes([srcbuf[0], srcbuf[1], srcbuf[2], srcbuf[3]])
        } else { 0 };
        // Classify: kMagicInt = CLEAN; the font-path ASCII '/usr' = CORRUPT.
        let verdict = match magic {
            0xc001feed => "CLEAN(kMagicInt)",
            0x2f757372 => "CORRUPT(font-path)",
            _ => "OTHER",
        };
        // Resolve the memfd file-offset for the consumer source VA (best-effort,
        // try-locked).  same (inode,offset) as the producer DEST but a different
        // phys ⇒ our kernel aliasing (one memfd offset, two frames); a different
        // (inode,offset) ⇒ gecko shipped a different segment ref.
        let (src_inode, src_foff) = memfd_backing_of(cr3, src_va);
        crate::serial_println!(
            "[UBREAK] capture read: rip={:#x} pid={} tid={} cr3={:#x} src_va={:#x} src_phys={:#x} inode={} foff={:#x} len(rdx)={} first_u32={:#010x} verdict={}",
            bp_va, snap.pid, snap.tid, cr3, src_va, src_phys, src_inode, src_foff, gpr.rdx, magic, verdict);
    }

    // Producer write-dest emit.  At the producer memcpy-into-shmem (off
    // 0x25af556: `mov r13,rsi`=blob source, `mov r12,rdx`=len, RDI=shmem DEST)
    // RDI points INTO the recycled MAP_SHARED memfd segment the writer is about
    // to fill.  Resolve RDI's physical frame so the producer DEST phys can be
    // compared against the consumer SOURCE phys captured above: same phys +
    // consumer-stale ⇒ store-visibility-under-recycle (our kernel); different
    // phys ⇒ aliasing/remap (our W215) or gecko shipped a different segment.
    {
        let dst_va = gpr.rdi;
        let dst_page = dst_va & !(PAGE_SIZE - 1);
        let dst_phys = vmm::virt_to_phys_in(cr3, dst_page)
            .map(|p| p | (dst_va & (PAGE_SIZE - 1)))
            .unwrap_or(0);
        let (dst_inode, dst_foff) = memfd_backing_of(cr3, dst_va);
        crate::serial_println!(
            "[UBREAK] capture write-dest: rip={:#x} pid={} tid={} cr3={:#x} dst_va={:#x} dst_phys={:#x} inode={} foff={:#x} len(rdx)={}",
            bp_va, snap.pid, snap.tid, cr3, dst_va, dst_phys, dst_inode, dst_foff, gpr.rdx);
    }

    // Publish into the ring.
    let idx = SNAP_HEAD.fetch_add(1, Ordering::AcqRel) % SNAP_RING;
    if let Some(mut ring) = SNAPS.try_lock() {
        ring[idx] = snap;
        SNAP_COUNT.fetch_add(1, Ordering::AcqRel);
    }
}

/// Drain captured snapshots into a JSON string (for KDB `ubreak dump`).
pub fn dump_json(out: &mut alloc::string::String) {
    use core::fmt::Write;
    let ring = match SNAPS.try_lock() {
        Some(g) => g,
        None => {
            out.push_str(r#"{"busy":"snapshot ring held"}"#);
            return;
        }
    };
    let total = SNAP_COUNT.load(Ordering::Acquire);
    let _ = write!(out, r#"{{"captured_total":{},"snapshots":["#, total);
    let mut first = true;
    for s in ring.iter() {
        if !s.valid {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            r#"{{"pid":{},"tid":{},"cr3":"{:#x}","rip":"{:#x}","rsp":"{:#x}","#,
            s.pid, s.tid, s.cr3, s.rip, s.rsp
        );
        let _ = write!(
            out,
            r#""rax":"{:#x}","rbx":"{:#x}","rcx":"{:#x}","rdx":"{:#x}","rsi":"{:#x}","rdi":"{:#x}","rbp":"{:#x}","#,
            s.rax, s.rbx, s.rcx, s.rdx, s.rsi, s.rdi, s.rbp
        );
        let _ = write!(
            out,
            r#""r8":"{:#x}","r9":"{:#x}","r10":"{:#x}","r11":"{:#x}","r12":"{:#x}","r13":"{:#x}","r14":"{:#x}","r15":"{:#x}","#,
            s.r8, s.r9, s.r10, s.r11, s.r12, s.r13, s.r14, s.r15
        );
        out.push_str(r#""windows":["#);
        for w in 0..MEM_WINDOWS {
            if w > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                r#"{{"va":"{:#x}","len":{},"bytes":""#,
                s.win_va[w], s.win_len[w]
            );
            for b in 0..(s.win_len[w] as usize).min(MEM_WINDOW_LEN) {
                let _ = write!(out, "{:02x}", s.win_bytes[w][b]);
            }
            out.push_str(r#""}"#);
        }
        out.push_str("]}");
    }
    out.push_str("]}");
}

/// Serial dump of armed slots (debug helper for the #BP-miss diagnostic).
pub fn list_serial() {
    for (i, slot) in BREAKS.iter().enumerate() {
        if slot.active.load(Ordering::Acquire) {
            crate::serial_println!(
                "[UBREAK/slot] {} active cr3={:#x} va={:#x} hits={}",
                i,
                slot.cr3.load(Ordering::Acquire),
                slot.va.load(Ordering::Acquire),
                slot.hits.load(Ordering::Acquire),
            );
        }
    }
}

/// List armed breakpoints + hit counts as JSON (for KDB `ubreak list`).
pub fn list_json(out: &mut alloc::string::String) {
    use core::fmt::Write;
    out.push_str(r#"{"breakpoints":["#);
    let mut first = true;
    for slot in BREAKS.iter() {
        if !slot.active.load(Ordering::Acquire) {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            r#"{{"cr3":"{:#x}","va":"{:#x}","orig_byte":"{:#x}","private_phys":"{:#x}","hits":{}}}"#,
            slot.cr3.load(Ordering::Acquire),
            slot.va.load(Ordering::Acquire),
            slot.orig_byte.load(Ordering::Acquire) & 0xff,
            slot.private_phys.load(Ordering::Acquire),
            slot.hits.load(Ordering::Acquire),
        );
    }
    out.push_str("]}");
}
