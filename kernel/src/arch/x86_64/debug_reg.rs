//! W215 diagnostic — DR0–DR3 write-only watchpoints.
//!
//! Per Intel SDM Vol. 3B §17.2.4 (Debug Address Registers DR0–DR3) and
//! §17.2.5 (Debug Status Register DR6 / Debug Control Register DR7), each
//! CPU has four hardware breakpoint slots whose linear address, size, and
//! access-type are programmed via DR0–DR3 and DR7.  A write-only data
//! breakpoint on a kernel linear address triggers `#DB` (vector 1) on the
//! CPU that performs a write whose data spans the watched range; the
//! instruction pointer captured in the interrupt frame is the RIP of the
//! offending instruction.
//!
//! This module exposes a four-slot watchpoint scheme used by the W215
//! page-cache CRC walker (`mm/w215_crc.rs`) and the cache::insert
//! pre-arming hook (`mm/cache.rs`) to identify the kernel code path that
//! mutates a cache-resident frame.  Slot assignment convention:
//!
//!   - DR0 — reserved for **post-hoc** arming by the CRC walker after a
//!     mismatch is detected (the historical Arm-1 single-slot behaviour).
//!   - DR1, DR2, DR3 — used **at insert time** as a pre-arming pool over
//!     suspect cache keys (libxul cluster), round-robin.  Earlier capture
//!     than DR0 because the watch fires the moment the upstream writer
//!     stores, before any cache-evict / memset chain can play out.
//!
//! ## Cross-CPU synchronisation
//!
//! DR0–DR7 are per-CPU registers (Intel SDM Vol. 3B §17.2).  To watch a
//! set of linear addresses on every CPU we publish the desired per-slot
//! `(addr, ctrl)` pairs to static atomic arrays and broadcast a
//! lightweight IPI on vector `W215_DR_SYNC_VECTOR`.  Each receiver loads
//! the published values and programs its own DR0–DR3 + DR7 from them.
//!
//! The sync protocol is one-shot per arm: the sender does not block on an
//! ack, because a missed IPI on a quiescent CPU is harmless — the next
//! timer interrupt on that CPU is followed by the same publish-and-load
//! pattern in `handle_w215_dr_sync_ipi`.
//!
//! ## Public surface
//!
//! - `arm_write_watchpoint(linear_addr, len, phys, inode, file_offset)` —
//!     post-hoc arm on DR0; returns `true` if DR0 was available.
//! - `arm_preinsert_watchpoint(linear_addr, len, phys, inode, file_offset)` —
//!     insert-time arm on DR1/DR2/DR3 round-robin; returns `Some(slot)`
//!     if a slot was free, `None` if all three were busy.
//! - `handle_w215_dr_sync_ipi()` — IPI handler.
//! - `handle_db_exception(...)` — `#DB` dispatcher; returns `true` if the
//!   trap belonged to W215 and was consumed.
//! - `apply_pending_to_this_cpu()` — called from `ap_rust_entry` so a CPU
//!   that comes online after arm picks up the watchpoints.
//! - `is_armed()` — back-compat: true if DR0 is armed.
//! - `stats()` — `(arm_count, fire_count)` summary.
//!
//! No fix-it logic lives here; the module is diagnostic-only.

#![cfg(feature = "w215-diag")]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering};

/// LAPIC vector used to broadcast a DR update to other CPUs.
///
/// Chosen to sit immediately above the TLB shootdown vector (`0xF0`,
/// see `mm/tlb.rs`) and below the spurious-interrupt vector (`0xFF`).
/// No other AstryxOS handler installs here.
pub const W215_DR_SYNC_VECTOR: u8 = 0xF1;

/// Number of hardware breakpoint slots (DR0–DR3).  Per Intel SDM Vol. 3B
/// §17.2.4, x86_64 always exposes exactly four.
pub const N_DR_SLOTS: usize = 4;

/// Per-slot armed flag.
static ARMED: [AtomicBool; N_DR_SLOTS] = [
    AtomicBool::new(false), AtomicBool::new(false),
    AtomicBool::new(false), AtomicBool::new(false),
];
/// Per-slot watched linear address (`PHYS_OFF + phys`).
static ARMED_ADDR: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Per-slot DR7-shaped local control bits, in the canonical positions for
/// that slot.  See `slot_dr7_bits` for the layout.
static ARMED_CTRL: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Per-slot phys / cache-key snapshot for the fire-line.
static ARMED_PHYS: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static ARMED_KEY_INODE: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static ARMED_KEY_OFFSET: [AtomicU64; N_DR_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

/// Per-slot fire count.  Final report sums to the legacy single counter.
static DR_FIRE_COUNT: [AtomicU32; N_DR_SLOTS] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

/// Number of arm broadcasts issued since boot (sum across slots).
static ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Round-robin cursor over the pre-insert pool {DR1, DR2, DR3}.  Lives
/// outside the per-slot atomic array because the policy is "pick first
/// free starting from cursor, then advance".
static PREINS_CURSOR: AtomicU32 = AtomicU32::new(0);

/// Per-slot DR7 R/W and LEN field positions.
///
/// Per Intel SDM Vol. 3B §17.2.4 Table 17-2 (DR7 layout):
///   - L{i} = bit 2*i           (local enable)
///   - G{i} = bit 2*i + 1       (global enable)
///   - R/W{i} = bits 16+4*i .. 17+4*i
///   - LEN{i} = bits 18+4*i .. 19+4*i
///   - LE   = bit 8, GE = bit 9 (exact-data-match — recommended)
///   - bit 10 reserved, must be 1
fn dr7_bits_for_slot(slot: usize, len: u8) -> u64 {
    debug_assert!(slot < N_DR_SLOTS);
    let rw: u64 = 0b01;        // write-only
    let len_field: u64 = match len {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        8 => 0b10,             // 8-byte form is valid on x86_64 per §17.2.5
        _ => 0b11,
    };
    let li = 2 * slot as u64;
    let gi = li + 1;
    let rw_pos = 16 + (4 * slot as u64);
    let len_pos = rw_pos + 2;
    let mut ctrl: u64 = 0;
    ctrl |= 1 << li;           // L{slot}
    ctrl |= 1 << gi;           // G{slot}
    ctrl |= rw << rw_pos;
    ctrl |= len_field << len_pos;
    ctrl
}

/// Read DR7.
#[inline(always)]
fn read_dr7() -> u64 {
    let dr7: u64;
    unsafe {
        core::arch::asm!("mov {}, dr7", out(reg) dr7, options(nomem, nostack, preserves_flags));
    }
    dr7
}

#[inline(always)]
fn write_dr7(val: u64) {
    unsafe {
        core::arch::asm!("mov dr7, {}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
fn write_dr_n(slot: usize, addr: u64) {
    // DR0–DR3 are not addressable by index in the `mov drN, reg` syntax —
    // the operand encodes the register number.  Use a match.
    unsafe {
        match slot {
            0 => core::arch::asm!("mov dr0, {}", in(reg) addr, options(nomem, nostack, preserves_flags)),
            1 => core::arch::asm!("mov dr1, {}", in(reg) addr, options(nomem, nostack, preserves_flags)),
            2 => core::arch::asm!("mov dr2, {}", in(reg) addr, options(nomem, nostack, preserves_flags)),
            3 => core::arch::asm!("mov dr3, {}", in(reg) addr, options(nomem, nostack, preserves_flags)),
            _ => {}
        }
    }
}

/// Program DR0–DR3 + DR7 on the current CPU from the published per-slot
/// atomics.  No-op when no slot is armed.
///
/// Always sets bit 10 (reserved-1) and clears LE/GE — exact-data-match is
/// optional on modern silicon and our R/W=write-only filter does not need
/// it, while LE/GE introduces an extra latency requirement on some CPUs.
///
/// Safe to call from interrupt context: only touches debug registers and
/// the atomics, never holds a lock.
#[inline(never)]
fn program_local_drs() {
    // Re-build DR7 from per-slot enables.  When a slot has been disarmed
    // we *must* explicitly clear its enable bits in DR7, otherwise a
    // formerly-watched address that the kernel writes again (typical:
    // disarm because Arm-1 captured the writer, then a follow-on write
    // happens through the same address before our IPI propagates) will
    // re-trip the trap and bugcheck.  This is the fix for PR #260 Issue 1.
    let mut dr7: u64 = 1 << 10; // reserved bit
    let mut any_armed = false;
    for slot in 0..N_DR_SLOTS {
        if !ARMED[slot].load(Ordering::Acquire) {
            // Slot is disarmed.  Leave DR{slot} value as-is (writing 0
            // would be safe, but is unnecessary because L{slot}=G{slot}=0
            // suppresses the breakpoint regardless of DR{slot} contents).
            continue;
        }
        let addr = ARMED_ADDR[slot].load(Ordering::Relaxed);
        if addr == 0 {
            // Defensive: a zero addr with ARMED=true means a publish-tear;
            // skip this slot rather than catch every kernel-page-zero read.
            continue;
        }
        let ctrl = ARMED_CTRL[slot].load(Ordering::Relaxed);
        write_dr_n(slot, addr);
        dr7 |= ctrl;
        any_armed = true;
    }
    // Always commit DR7 — even when `any_armed == false` we want to clear
    // any stale enable bits that may remain from a previous arm.  This is
    // the explicit-clear path that closes PR #260 Issue 1.
    let _ = any_armed; // retained for readability
    unsafe {
        // Clear DR6 before re-programming DR7 to avoid an immediate
        // spurious `#DB` from a stale B0..B3.  Per Intel SDM Vol. 3B
        // §17.2.5 the B bits are sticky until cleared by software.
        core::arch::asm!("mov dr6, {}", in(reg) 0u64, options(nomem, nostack, preserves_flags));
    }
    write_dr7(dr7);
}

/// Apply the currently armed watchpoints to this CPU.  Called from
/// `apic::ap_rust_entry` so a CPU that comes online after Arm-1 fires
/// picks up the watchpoint, and from the IPI handler.
pub fn apply_pending_to_this_cpu() {
    program_local_drs();
}

/// Internal: attempt to claim slot `slot`, returning `true` on success.
/// Publishes the slot's address/control/key atomics on success.
fn try_arm_slot(
    slot: usize,
    linear_addr: u64,
    len: u8,
    phys: u64,
    inode: u64,
    file_offset: u64,
) -> bool {
    if ARMED[slot]
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    let ctrl = dr7_bits_for_slot(slot, len);
    ARMED_ADDR[slot].store(linear_addr, Ordering::Relaxed);
    ARMED_CTRL[slot].store(ctrl, Ordering::Relaxed);
    ARMED_PHYS[slot].store(phys, Ordering::Relaxed);
    ARMED_KEY_INODE[slot].store(inode, Ordering::Relaxed);
    ARMED_KEY_OFFSET[slot].store(file_offset, Ordering::Relaxed);
    true
}

/// Post-hoc arm on DR0 (the CRC walker's slot).  Returns `true` if DR0
/// was free and got armed.  Back-compat name with PR #260.
pub fn arm_write_watchpoint(
    linear_addr: u64,
    len: u8,
    phys: u64,
    inode: u64,
    file_offset: u64,
) -> bool {
    if !try_arm_slot(0, linear_addr, len, phys, inode, file_offset) {
        return false;
    }
    program_local_drs();
    broadcast_dr_sync();
    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::serial_println!(
        "[W215/DR-ARM] slot=0 linear={:#x} phys={:#x} inode={} offset={:#x}",
        linear_addr, phys, inode, file_offset,
    );
    true
}

/// Pre-insert arm: try DR1, then DR2, then DR3, advancing the round-robin
/// cursor.  Returns `Some(slot)` if a slot was free, `None` otherwise.
///
/// Called from `cache::insert` for entries whose `(mount, inode)` falls in
/// the W215 libxul cluster.  Diagnostic-only.
pub fn arm_preinsert_watchpoint(
    linear_addr: u64,
    len: u8,
    phys: u64,
    inode: u64,
    file_offset: u64,
) -> Option<u8> {
    // Start at PREINS_CURSOR mod 3, scan {DR1, DR2, DR3} once.
    let start = (PREINS_CURSOR.fetch_add(1, Ordering::Relaxed) as usize) % 3;
    for off in 0..3usize {
        let slot = 1 + ((start + off) % 3);
        if try_arm_slot(slot, linear_addr, len, phys, inode, file_offset) {
            // Program this CPU's DRs.  We DO NOT broadcast a sync IPI
            // from the cache::insert hot path — the cost is meaningful
            // during prepopulate, and remote CPUs pick up the new arm
            // lazily via `apply_pending_to_this_cpu` on the next path
            // through the IDT (timer ISR, TLB shootdown IPI, etc.).
            // For the cache-aliasing writer we want to catch, the
            // writer is overwhelmingly likely to be on the same CPU
            // that committed the insert (CoW / memset paths run in
            // thread context on the faulting CPU), so the local DR
            // programming is exactly what matters.
            program_local_drs();
            ARM_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::serial_println!(
                "[W215/DR-ARM] slot={} linear={:#x} phys={:#x} inode={} offset={:#x} kind=preinsert",
                slot, linear_addr, phys, inode, file_offset,
            );
            return Some(slot as u8);
        }
    }
    None
}

/// Broadcast the pending DR update to all other online CPUs via
/// `W215_DR_SYNC_VECTOR`.  Best-effort.
fn broadcast_dr_sync() {
    let me = super::apic::cpu_index() as u8;
    let total = super::apic::cpu_count() as usize;
    let max = total.min(super::apic::MAX_CPUS);
    for cpu in 0..max {
        if cpu as u8 == me {
            continue;
        }
        super::apic::send_ipi(cpu as u8, W215_DR_SYNC_VECTOR);
    }
}

/// IPI handler for `W215_DR_SYNC_VECTOR`.  Programs this CPU's DR0–DR3 +
/// DR7 from the published atomics and EOIs the LAPIC.
pub extern "C" fn handle_w215_dr_sync_ipi() {
    program_local_drs();
    super::apic::lapic_eoi();
}

/// Read DR6.
#[inline(always)]
fn read_dr6() -> u64 {
    let dr6: u64;
    unsafe {
        core::arch::asm!("mov {}, dr6", out(reg) dr6, options(nomem, nostack, preserves_flags));
    }
    dr6
}

#[inline(always)]
fn write_dr6(val: u64) {
    unsafe {
        core::arch::asm!("mov dr6, {}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

/// Read CR3.
#[inline(always)]
fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Inspect DR6 to see whether this `#DB` is a W215 watchpoint firing.
///
/// On a hit:
///   - Disarms the slot globally (one-shot capture per slot).
///   - Emits `[W215/DR-WATCH-FIRE] slot=N ...` with RIP, CR3, phys, key.
///   - Dumps 8 qwords at and below RSP.
///   - Clears B0..B3 in DR6.
///   - Re-broadcasts the DR sync so other CPUs disarm their copy of the
///     just-fired slot.
///   - Returns `true` to tell the dispatcher this trap is consumed.
///
/// If multiple slots fire on the same `#DB` (rare but legal — Intel SDM
/// Vol. 3B §17.2.5 says all hit bits are reported in DR6), each is logged
/// and disarmed.
///
/// Returns `false` if the trap is not a W215 watchpoint.
pub fn handle_db_exception(
    rip: u64,
    rsp: u64,
    rflags: u64,
    cs: u64,
) -> bool {
    let dr6 = read_dr6();
    let hit_mask = dr6 & 0xF;
    if hit_mask == 0 {
        return false;
    }
    // Check that at least one of the hit slots is one we armed.
    let mut consumed = false;
    let cpu = super::apic::cpu_index();
    let cr3 = read_cr3();
    for slot in 0..N_DR_SLOTS {
        if (hit_mask & (1u64 << slot)) == 0 {
            continue;
        }
        if !ARMED[slot].load(Ordering::Acquire) {
            // Stale sticky bit for a slot we never armed.  Clear it and
            // skip; do NOT treat as consumed — the trap may belong to
            // someone else (e.g. an INT1 instruction).
            continue;
        }
        let phys = ARMED_PHYS[slot].load(Ordering::Relaxed);
        let inode = ARMED_KEY_INODE[slot].load(Ordering::Relaxed);
        let offset = ARMED_KEY_OFFSET[slot].load(Ordering::Relaxed);
        let addr = ARMED_ADDR[slot].load(Ordering::Relaxed);
        // One-shot disarm of this slot.
        ARMED[slot].store(false, Ordering::Release);
        ARMED_ADDR[slot].store(0, Ordering::Relaxed);
        ARMED_CTRL[slot].store(0, Ordering::Relaxed);

        let fire_idx = DR_FIRE_COUNT[slot].fetch_add(1, Ordering::Relaxed);
        crate::serial_println!(
            "[W215/DR-WATCH-FIRE] slot={} fire_idx={} cpu={} rip={:#x} cs={:#x} \
             rflags={:#x} cr3={:#x} phys={:#x} linear={:#x} key=(_,{},{:#x}) dr6={:#x}",
            slot, fire_idx, cpu, rip, cs, rflags, cr3, phys, addr, inode, offset, dr6,
        );
        crate::serial_println!(
            "[W215/DR-WATCH-FIRE/STACK] slot={} cpu={} rip={:#x} rsp={:#x}",
            slot, cpu, rip, rsp,
        );
        for i in 0..8usize {
            let p = rsp.wrapping_add((i * 8) as u64);
            if p >= 0xFFFF_8000_0000_0000 {
                let v = unsafe { core::ptr::read_volatile(p as *const u64) };
                crate::serial_println!(
                    "[W215/DR-WATCH-FIRE/STACK]   [rsp+{:#04x}] {:#018x} = {:#018x}",
                    i * 8, p, v,
                );
            } else {
                crate::serial_println!(
                    "[W215/DR-WATCH-FIRE/STACK]   [rsp+{:#04x}] {:#018x} = (user)",
                    i * 8, p,
                );
            }
        }
        consumed = true;
    }

    // Clear sticky B0..B3 regardless — leaving them set would re-trigger
    // the trap on next #DB even if the underlying slot is now disarmed.
    write_dr6(dr6 & !0xF);

    if consumed {
        // Re-program local DRs (this also clears DR7 enable bits for the
        // disarmed slots — the explicit-DR7-clear fix from PR #260 Issue 1).
        program_local_drs();
        // Re-broadcast to peer CPUs so they disarm too.
        broadcast_dr_sync();
        true
    } else {
        // Hit bits set but no W215 slot owns them — let the generic
        // dispatcher handle the trap.
        false
    }
}

/// Return `(arm_count, fire_count)` summary for the final report.
/// `fire_count` is the sum across all four slots.
pub fn stats() -> (u32, u32) {
    let mut fires = 0u32;
    for slot in 0..N_DR_SLOTS {
        fires = fires.wrapping_add(DR_FIRE_COUNT[slot].load(Ordering::Relaxed));
    }
    (ARM_COUNT.load(Ordering::Relaxed), fires)
}

/// Per-slot fire counts, for the `[W215/ARM1/STATS]` line.
pub fn per_slot_fires() -> [u32; N_DR_SLOTS] {
    [
        DR_FIRE_COUNT[0].load(Ordering::Relaxed),
        DR_FIRE_COUNT[1].load(Ordering::Relaxed),
        DR_FIRE_COUNT[2].load(Ordering::Relaxed),
        DR_FIRE_COUNT[3].load(Ordering::Relaxed),
    ]
}

/// Back-compat: returns true if DR0 (post-hoc walker slot) is armed.
/// Used by the CRC walker to avoid re-arming over its own active capture.
pub fn is_armed() -> bool {
    ARMED[0].load(Ordering::Acquire)
}
