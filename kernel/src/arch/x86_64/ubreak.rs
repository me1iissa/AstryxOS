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
//! One-shot is deliberate: the primary use is breaking on a *panic branch* that
//! executes exactly once before the process aborts, so no single-step/re-arm
//! machinery (which would collide with the kernel's own #DB usage) is needed.
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

/// Enable auto-arm at the given libxul-relative ELF offset with a 4-byte
/// instruction signature (the first 4 code bytes expected at that offset, as a
/// little-endian u32 — i.e. byte[0] in bits 0..7).  `sig`==0 disables the check
/// for that offset.  (0 offset disables the slot.)
pub fn set_auto_arm_offset_sig(off: u64, sig: u32) {
    if off == 0 {
        return;
    }
    AUTO_ARM_OFFSET.store(off, Ordering::Release);
    for (s, sg) in AUTO_ARM_OFFSETS.iter().zip(AUTO_ARM_SIGS.iter()) {
        if s.load(Ordering::Acquire) == 0 {
            sg.store(sig as u64, Ordering::Release);
            s.store(off, Ordering::Release);
            return;
        }
    }
}

/// Back-compat: enable auto-arm with no signature check (legacy single-offset).
pub fn set_auto_arm_offset(off: u64) {
    set_auto_arm_offset_sig(off, 0);
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
        if arm_at_cr3_idx(cr3, target_va, idx).is_ok() {
            crate::serial_println!(
                "[UBREAK] auto-armed cr3={:#x} load_base={:#x} target={:#x} (off={:#x})",
                cr3, load_base, target_va, off
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
        if arm_at_cr3_idx(cr3, target_va, idx).is_ok() {
            crate::serial_println!(
                "[UBREAK] auto-armed (scan) cr3={:#x} load_base={:#x} target={:#x} (off={:#x})",
                cr3, load_base, target_va, off
            );
        }
    }
}

/// Arm a one-shot breakpoint at `va` in an explicit `cr3` (used by the auto-arm
/// PF hook, which already knows the CR3).  Same mechanism as [`arm`] minus the
/// pid→cr3 resolution.  Page must be present (it just faulted in).
fn arm_at_cr3(cr3: u64, va: u64) -> Result<(), &'static str> {
    arm_at_cr3_idx(cr3, va, usize::MAX)
}

fn arm_at_cr3_idx(cr3: u64, va: u64, auto_idx: usize) -> Result<(), &'static str> {
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

/// #BP handler hook.  Called from the vector-3 path in idt.rs for Ring-3
/// breakpoints.  `gpr` is the 15-element GPR array as laid out by the ISR stub
/// (see [`read_gprs_from_frame`]).  Returns true if this #BP belonged to a
/// registered userspace breakpoint (so the caller skips the generic handling
/// and returns to the rewound RIP).
///
/// `frame_rip` is the RIP *after* the int3 (points one byte past the 0xCC).
/// On a match we capture, restore the byte (one-shot), and rewind `*rip_out` by
/// one so the original instruction re-executes.
pub fn on_breakpoint(
    cr3: u64,
    frame_rip: u64,
    frame_rsp: u64,
    gpr: &Gprs,
    rip_out: &mut u64,
) -> bool {
    let bp_va = frame_rip.wrapping_sub(1);
    for slot in BREAKS.iter() {
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

        capture(cr3, bp_va, frame_rsp, gpr);

        // One-shot: restore the original byte and rewind so the instruction
        // re-executes normally.  Disarm the slot (we keep the private page).
        // Mark this offset CONSUMED so the per-fault scan never re-arms it —
        // re-arming would re-open the plant-without-active-slot window that
        // turns a later #BP into an unhandled SIGSEGV.
        let idx = slot.auto_idx.load(Ordering::Acquire);
        if idx < MAX_AUTO_ARM {
            AUTO_ARM_CONSUMED[idx].store(true, Ordering::Release);
        }
        restore_byte(slot);
        slot.active.store(false, Ordering::Release);
        *rip_out = bp_va;
        return true;
    }
    false
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
