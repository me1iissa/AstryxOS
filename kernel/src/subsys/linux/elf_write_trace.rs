//! ELF write-trace diagnostic.
//!
//! Investigative tool for the W215-aliasing axis-N case where a kernel-mode
//! store corrupts a fixed slot of the dynamic linker's `.data.rel.ro` page
//! during the `CLONE_VM | CLONE_VFORK` parent-block window.  In the demo
//! trial captured before this diagnostic was added, the parent (PID 1, TID
//! 2) returned from `schedule()` after the child's `exit_group(0)`, ran six
//! cleanup syscalls (close/read/close/sigprocmask/close/close), then took a
//! `#GP` from a stack-protector-fail trap (`hlt;ret` at the musl `a_crash`
//! glue), because the function-pointer slot at user VA `0x7f0000037e18`
//! had transitioned from a valid interpreter-text address to garbage.
//!
//! Per project memory `project_w215_saga_antipattern_2026_05_16`, five
//! prior iterations of the W215 saga ("right theory, wrong write site")
//! landed real fixes for real writers that did not close the bug.  The
//! discipline that breaks the cycle is *diagnostic-first* — pinpoint the
//! kernel RIP at the moment of the store, before designing any fix.
//!
//! # Strategy
//!
//! Around the parent's `CLONE_VM | CLONE_VFORK` schedule-yield, this
//! module:
//!
//!   1. Resolves the suspect user VA (`0x7f0000037e18`, the slot the
//!      `[GPF-DBG]` diagnostic reports as corrupted) to a physical frame
//!      via the parent's CR3, using `mm::vmm::virt_to_phys_in`.
//!   2. Arms a hardware write-only watchpoint on `PHYS_OFF + phys` via the
//!      existing four-slot W215 DR0–DR3 plumbing (`arch::x86_64::debug_reg`).
//!      Programs the local CPU; peer CPUs pick up the arm on their next
//!      timer ISR via the lazy-gen-polled `apply_pending_if_stale` path
//!      (Intel SDM Vol. 3B §17.2.4 / §17.2.5).
//!   3. Snapshots the first 64 bytes of the suspect page (and the canary
//!      qword at the slot) at enter time, again at exit time, and emits a
//!      diff line so a corruption that occurred without the DR firing
//!      (e.g. a peer-CPU write that slipped through the one-tick
//!      sync-gen window, or a write via a different linear address that
//!      aliases the same phys frame) is still observable.
//!
//! Any kernel-mode write to the watched 8-byte window fires `#DB` (Intel
//! SDM Vol. 3A §6.15 vector 1) and is reported by
//! `arch::x86_64::debug_reg::handle_db_exception` with `[W215/DR-WATCH-FIRE]
//! slot=… cpu=… rip=… cs=… rflags=… cr3=… phys=… linear=… …` — that line
//! is the diagnostic's primary output.  The `[ELF-WRITE-TRACE/ENTER]` and
//! `[ELF-WRITE-TRACE/EXIT]` lines from this module bracket the window and
//! give the before/after content cross-check.
//!
//! # Why this VA
//!
//! The ELF dynamic linker (`/lib/ld-musl-x86_64.so.1`) maps its
//! `.data.rel.ro` segment at the fixed interpreter base
//! `INTERP_BASE = 0x7F00_0000_0000`.  The slot at offset `0x37e18` is the
//! function-pointer the parent dereferences shortly after returning from
//! the vfork-wake.  Per System V AMD64 ABI §6.4 (stack protector) a fault
//! in this slot manifests as a `#GP` at `a_crash` because the indirect
//! call enters the `hlt;ret` epilogue.  See `arch::x86_64::idt.rs`
//! `[GPF-DBG] ldlinux[0x37e18]=…` for the existing on-fault snapshot.
//!
//! The suspect slot is a property of the trial under investigation —
//! `WATCH_LINEAR_BASE` is a `const` that the next iteration can re-point
//! to a different VA without rebuilding any infrastructure here.
//!
//! # Gating
//!
//! The whole module compiles to nothing unless `elf-write-trace` is in
//! the feature set.  The feature pulls in `w215-diag` (for the DR0–DR3
//! infrastructure) and `firefox-test` (for the shared serial-trace
//! formatters and the syscall-ring context).  No other code path
//! depends on this module; master builds are byte-identical without it.
//!
//! # References
//!
//!   - Intel SDM Vol. 3B §17.2.4 (Debug Address Registers DR0–DR3)
//!   - Intel SDM Vol. 3B §17.2.5 (Debug Status / Control Registers DR6/DR7)
//!   - Intel SDM Vol. 3A §6.15 (vector 1, `#DB`)
//!   - POSIX vfork(2): pubs.opengroup.org/onlinepubs/9699919799/functions/vfork.html
//!   - POSIX clone(2)
//!   - System V AMD64 ABI §6.4 (stack-protector)
//!   - musl libc (https://musl.libc.org/) — dynamic linker layout

#![cfg(feature = "elf-write-trace")]

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Default suspect user VA — the function-pointer slot in the dynamic
/// linker's `.data.rel.ro` page that the existing `[GPF-DBG]` diagnostic
/// (`arch/x86_64/idt.rs`) reports as corrupted at `#GP` time.
///
/// `INTERP_BASE = 0x7F00_0000_0000` + `0x37e18` per the diagnostic
/// constant in `idt.rs`.  Held as a `pub const` so future iterations can
/// re-point the watch at a different slot without touching the rest of
/// the module.
pub const WATCH_LINEAR_BASE: u64 = 0x7F00_0003_7e18;

/// Width of the hardware watchpoint, in bytes.  Per Intel SDM Vol. 3B
/// §17.2.4 Table 17-2, valid widths are 1 / 2 / 4 / 8; an 8-byte window
/// captures a single u64 store at the suspect slot.
const WATCH_LEN: u8 = 8;

/// Half-window of bytes we snapshot around `WATCH_LINEAR_BASE` for the
/// before/after cross-check.  Centered on the slot; total snapshot is
/// `2 * SNAPSHOT_HALF` bytes.  Sized to keep the [ELF-WRITE-TRACE] lines
/// inside one serial chunk (the FIFO-batched driver is 16-byte aligned;
/// 64 hex bytes fit comfortably).
const SNAPSHOT_HALF: usize = 32;

/// `true` while a vfork window is active and our watchpoint is armed.
/// Used to gate the cleanup path so an `exit_window` without a matching
/// `enter_window` is a cheap atomic-load no-op.
static WINDOW_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Stored physical address that we armed at enter time.  Zero when not
/// armed.  Used by `exit_window` to re-read the same frame even if the
/// parent's CR3 (or the page-table mapping for the suspect VA) has been
/// torn down by the cleanup syscalls that run after `schedule()` returns
/// but before `exit_window` is called.
static ARMED_PHYS: AtomicU64 = AtomicU64::new(0);

/// The 8-byte qword we read at the suspect slot at enter time.  Logged
/// again at exit time so the diff is visible even without the DR firing.
static ENTER_QWORD: AtomicU64 = AtomicU64::new(0);

/// Snapshot of `2 * SNAPSHOT_HALF` bytes centered on `WATCH_LINEAR_BASE`,
/// read at enter time.  Reread at exit; any differing byte is logged.
static ENTER_SNAPSHOT: spin::Mutex<[u8; 2 * SNAPSHOT_HALF]> =
    spin::Mutex::new([0u8; 2 * SNAPSHOT_HALF]);

/// Physical-address half of `PHYS_OFF` — the kernel's identity map of
/// physical RAM starts here (W215 conventions / mm modules).
const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Snapshot start address: half the snapshot window below the watch base.
#[inline]
const fn snapshot_start() -> u64 {
    WATCH_LINEAR_BASE - (SNAPSHOT_HALF as u64)
}

/// Read 8 bytes at `linear` through the kernel's PHYS_OFF identity map.
/// Returns `None` if the linear address resolves to a phys outside the
/// installed RAM window.  Safe to call from any context: only touches the
/// PHYS_OFF map (no PTE writes, no locks).
///
/// `pml4_phys` is the CR3 to use for the walk — the parent's CR3 captured
/// at enter time.  We deliberately avoid calling `get_cr3()` here so that
/// `exit_window` running on a CPU that has switched to a different
/// process (the parent woke, returned to userspace, then issued more
/// syscalls — but we are still pinned by the syscall handler) still sees
/// the same translation it saw at enter time.
fn read_qword_via(pml4_phys: u64, linear: u64) -> Option<u64> {
    let phys = crate::mm::vmm::virt_to_phys_in(pml4_phys, linear)?;
    // SAFETY: PHYS_OFF + phys is the kernel's identity map of installed
    // RAM.  An unaligned read at `linear & 7 != 0` is permitted under the
    // x86_64 ISA (single-byte memory model); we use read_unaligned for
    // safety against future relocations of WATCH_LINEAR_BASE that may
    // straddle a u64 boundary.
    let kva = (PHYS_OFF + phys) as *const u64;
    Some(unsafe { core::ptr::read_unaligned(kva) })
}

/// Read `len` bytes at `linear` into `dst` via the PHYS_OFF map.  Handles
/// 4 KiB page boundaries: if the snapshot window straddles a page, both
/// halves are looked up independently.  Bytes that resolve to UNMAPPED
/// are filled with `0xAA` so the post-processor can tell unmapped from
/// "actually 0x00".
fn read_bytes_via(pml4_phys: u64, linear: u64, dst: &mut [u8]) {
    for (i, b) in dst.iter_mut().enumerate() {
        let va = linear.wrapping_add(i as u64);
        let v = match crate::mm::vmm::virt_to_phys_in(pml4_phys, va) {
            Some(phys) => {
                let p = (PHYS_OFF + phys) as *const u8;
                unsafe { core::ptr::read_volatile(p) }
            }
            None => 0xAAu8,
        };
        *b = v;
    }
}

/// Hex-format an `&[u8]` slice into a stack buffer.  Returns the populated
/// length (`2 * src.len()`).  Used for the [ELF-WRITE-TRACE/SNAP] lines so
/// we don't allocate during the diagnostic emit (the alloc crate is
/// available, but a stack buffer keeps the path safe to call from any
/// context).
fn hex_into(src: &[u8], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut n = 0;
    for &b in src {
        if n + 2 > out.len() { break; }
        out[n]     = HEX[(b >> 4) as usize];
        out[n + 1] = HEX[(b & 0x0F) as usize];
        n += 2;
    }
    n
}

/// Enter the diagnostic window: resolve `WATCH_LINEAR_BASE` to a phys via
/// `parent_cr3`, arm a write-only DR slot on `PHYS_OFF + phys`, and snap
/// the page content.  Idempotent — a second call with the window already
/// active emits a `[ELF-WRITE-TRACE/REENTRY]` line and returns without
/// re-arming.
///
/// `parent_cr3` is the CR3 of the parent at the moment it about to call
/// `schedule()` — i.e. before any vfork-isolated stack/TLS allocation
/// runs.  Captured by the caller because once the parent yields, the
/// per-CPU `get_cr3()` may belong to whichever process the scheduler
/// dispatched next.
pub fn enter_window(parent_pid: u64, parent_tid: u64, parent_cr3: u64) {
    if WINDOW_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::serial_println!(
            "[ELF-WRITE-TRACE/REENTRY] pid={} tid={} cr3={:#x} \
             watch_va={:#x} state=already_armed",
            parent_pid, parent_tid, parent_cr3, WATCH_LINEAR_BASE
        );
        return;
    }

    // Resolve VA → phys via the parent's CR3.  If unmapped, the watch
    // can't be armed; log and leave WINDOW_ACTIVE=true so exit_window
    // still runs symmetrically (and can detect a lazy mapping that
    // appears during the window).
    let phys_opt = crate::mm::vmm::virt_to_phys_in(parent_cr3, WATCH_LINEAR_BASE);
    let phys = match phys_opt {
        Some(p) => p,
        None => {
            crate::serial_println!(
                "[ELF-WRITE-TRACE/ENTER] pid={} tid={} cr3={:#x} \
                 watch_va={:#x} state=unmapped",
                parent_pid, parent_tid, parent_cr3, WATCH_LINEAR_BASE
            );
            ARMED_PHYS.store(0, Ordering::Release);
            return;
        }
    };

    // Snapshot the qword at the slot (pre-corruption value).
    let pre_val = read_qword_via(parent_cr3, WATCH_LINEAR_BASE).unwrap_or(0);
    ENTER_QWORD.store(pre_val, Ordering::Release);

    // Snapshot the surrounding bytes.
    {
        let mut snap = ENTER_SNAPSHOT.lock();
        read_bytes_via(parent_cr3, snapshot_start(), &mut snap[..]);
    }

    // Arm the watchpoint precisely on the suspect slot inside the
    // resolved 4 KiB frame.  `arm_phys_slot_watchpoint` validates the
    // (phys, off, len) triple per Intel SDM Vol. 3B §17.2.4 Table 17-2
    // and stores the watch in DR1–DR3 (preferring the pre-insert pool
    // over DR0 to avoid clobbering the post-hoc cache CRC walker's
    // slot).  A naturally-aligned 8-byte watch at `phys & ~7` catches
    // any kernel store that touches the 8 bytes containing the slot.
    let frame_base = phys & !0xFFF;
    let off_in_frame = phys & 0xFFF;
    // The slot is naturally u64-aligned by construction (WATCH_LINEAR_BASE
    // ends in 0x18 → off mod 8 == 0); the alignment check inside
    // `arm_phys_slot_watchpoint` catches any future relocation that
    // violates this.
    let arm_off = off_in_frame & !0x7;
    let arm_result = crate::arch::x86_64::debug_reg::arm_phys_slot_watchpoint(
        frame_base, arm_off, WATCH_LEN,
    );
    let arm_str: alloc::string::String = match arm_result {
        crate::arch::x86_64::debug_reg::ArmPhysResult::Armed(slot) => {
            ARMED_PHYS.store(phys, Ordering::Release);
            alloc::format!("armed_slot={}", slot)
        }
        crate::arch::x86_64::debug_reg::ArmPhysResult::NotAligned => {
            ARMED_PHYS.store(0, Ordering::Release);
            alloc::string::String::from("err=not_aligned")
        }
        crate::arch::x86_64::debug_reg::ArmPhysResult::OutOfRange => {
            ARMED_PHYS.store(0, Ordering::Release);
            alloc::string::String::from("err=out_of_range")
        }
        crate::arch::x86_64::debug_reg::ArmPhysResult::PoolExhausted => {
            ARMED_PHYS.store(0, Ordering::Release);
            alloc::string::String::from("err=pool_exhausted")
        }
    };

    // Stack-format the snapshot bytes as a single hex string for the
    // [ELF-WRITE-TRACE/ENTER-SNAP] line.
    let mut hex = [0u8; 2 * 2 * SNAPSHOT_HALF];
    let hex_len = {
        let snap = ENTER_SNAPSHOT.lock();
        hex_into(&snap[..], &mut hex[..])
    };

    crate::serial_println!(
        "[ELF-WRITE-TRACE/ENTER] pid={} tid={} cr3={:#x} \
         watch_va={:#x} watch_phys={:#x} pre_val={:#018x} {}",
        parent_pid, parent_tid, parent_cr3,
        WATCH_LINEAR_BASE, phys, pre_val, arm_str
    );
    // SAFETY: hex_into only writes ASCII, so this slice is valid UTF-8.
    let hex_str = unsafe { core::str::from_utf8_unchecked(&hex[..hex_len]) };
    crate::serial_println!(
        "[ELF-WRITE-TRACE/ENTER-SNAP] pid={} tid={} \
         snap_va={:#x} len={} bytes={}",
        parent_pid, parent_tid, snapshot_start(), 2 * SNAPSHOT_HALF, hex_str
    );
}

/// Exit the diagnostic window: re-read the page content, log diffs, and
/// drop the active flag.  The DR slot disarms one-shot when the watch
/// fires (see `debug_reg::handle_db_exception`); we don't explicitly
/// disarm here because (a) the slot is already free if the watch fired,
/// and (b) a still-armed slot will harmlessly fire once more if any
/// post-window store hits the page — the resulting `[W215/DR-WATCH-FIRE]`
/// line carries the RIP and is a bonus data point.
pub fn exit_window(parent_pid: u64, parent_tid: u64, parent_cr3: u64) {
    if !WINDOW_ACTIVE.load(Ordering::Acquire) {
        // No matching enter; cheap return.
        return;
    }
    // Drop the flag first so a re-entry from a re-vforking parent on the
    // same CPU re-arms cleanly.  AcqRel pairs with the Acquire in
    // enter_window's CAS.
    WINDOW_ACTIVE.store(false, Ordering::Release);

    let phys = ARMED_PHYS.load(Ordering::Acquire);
    let post_val = read_qword_via(parent_cr3, WATCH_LINEAR_BASE);
    let pre_val = ENTER_QWORD.load(Ordering::Acquire);

    let post_str = match post_val {
        Some(v) => alloc::format!("{:#018x}", v),
        None    => alloc::string::String::from("unmapped"),
    };

    let changed = match post_val {
        Some(v) => v != pre_val,
        None    => true,
    };

    crate::serial_println!(
        "[ELF-WRITE-TRACE/EXIT] pid={} tid={} cr3={:#x} \
         watch_va={:#x} watch_phys={:#x} pre_val={:#018x} \
         post_val={} changed={}",
        parent_pid, parent_tid, parent_cr3,
        WATCH_LINEAR_BASE, phys, pre_val, post_str, changed
    );

    // Re-snapshot the surrounding bytes and diff against ENTER_SNAPSHOT.
    // Only emit per-offset lines for offsets whose byte differs; bound
    // the output at 16 lines to keep serial volume sane even in a wide
    // overwrite scenario.
    let mut post_snap = [0u8; 2 * SNAPSHOT_HALF];
    read_bytes_via(parent_cr3, snapshot_start(), &mut post_snap[..]);

    let enter_snap = ENTER_SNAPSHOT.lock();
    let mut diffs = 0usize;
    const MAX_DIFF_LINES: usize = 16;
    for i in 0..(2 * SNAPSHOT_HALF) {
        if enter_snap[i] == post_snap[i] {
            continue;
        }
        if diffs >= MAX_DIFF_LINES {
            crate::serial_println!(
                "[ELF-WRITE-TRACE/EXIT-DIFF] pid={} tid={} cap={} ...truncated",
                parent_pid, parent_tid, MAX_DIFF_LINES
            );
            break;
        }
        let off = i as i64 - SNAPSHOT_HALF as i64;
        let va = snapshot_start().wrapping_add(i as u64);
        crate::serial_println!(
            "[ELF-WRITE-TRACE/EXIT-DIFF] pid={} tid={} \
             va={:#x} slot_off={} pre={:#04x} post={:#04x}",
            parent_pid, parent_tid, va, off, enter_snap[i], post_snap[i]
        );
        diffs += 1;
    }
    drop(enter_snap);

    if diffs == 0 && !changed {
        // Common no-corruption case: emit a single [CLEAN] line so the
        // post-processor can tell "diagnostic ran, nothing fired" from
        // "diagnostic never ran".
        crate::serial_println!(
            "[ELF-WRITE-TRACE/CLEAN] pid={} tid={} watch_va={:#x}",
            parent_pid, parent_tid, WATCH_LINEAR_BASE
        );
    }

    // Clear the stored phys so a subsequent enter starts from a known
    // state.  No barrier needed: the next enter does its own CAS.
    ARMED_PHYS.store(0, Ordering::Relaxed);
    ENTER_QWORD.store(0, Ordering::Relaxed);
}

/// Public test hook: returns `true` if the window is currently armed.
/// Used by the kernel test runner to assert the gating doesn't leak past
/// a vfork window completion.
#[allow(dead_code)]
pub fn is_window_active() -> bool {
    WINDOW_ACTIVE.load(Ordering::Acquire)
}
