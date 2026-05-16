//! W215 Arm-1 diagnostic — DR0 write-only watchpoint plumbing.
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
//! This module exposes a single-slot, one-shot W-only watchpoint used by
//! the W215 cache CRC walker (`mm/w215_crc.rs`) to identify the kernel
//! code path that mutates a cache-resident frame outside the normal
//! cache::insert / cache::evict bookkeeping.
//!
//! ## Cross-CPU synchronisation
//!
//! DR0–DR7 are per-CPU registers (Intel SDM Vol. 3B §17.2).  To watch a
//! single linear address on every CPU we publish the desired
//! `(addr, ctrl)` pair to a pair of static atomics and broadcast a
//! lightweight IPI on vector `W215_DR_SYNC_VECTOR`.  Each receiver loads
//! the published values and programs its own DR0/DR7 from them.  The
//! published values are read by APs on first arm (so a CPU that was idle
//! during arm picks the watchpoint up on its next IPI).
//!
//! The sync protocol is one-shot per arm: the sender does not block on an
//! ack, because a missed IPI on a quiescent CPU is harmless — the next
//! timer interrupt on that CPU is followed by the same publish-and-load
//! pattern in `handle_w215_dr_sync_ipi`.  In practice the diagnostic only
//! needs the IPI to reach the CPU that is about to issue the corrupting
//! write; if it does not, a subsequent CRC mismatch on the same frame
//! will re-arm and re-broadcast.
//!
//! ## Public surface
//!
//! - `arm_write_watchpoint(linear_addr, len)` — publish + broadcast.
//! - `handle_w215_dr_sync_ipi()`             — IPI handler.
//! - `handle_db_exception(frame, saved_gpr)` — `#DB` dispatcher; returns
//!   `true` if the trap belonged to W215 and was consumed.
//! - `apply_pending_to_this_cpu()`           — called from `ap_rust_entry`
//!   so a CPU that comes online after arm picks up the watchpoint.
//!
//! No fix-it logic lives here; the module is diagnostic-only.  See
//! `docs/W215_DISPOSITIVE_SOAK_2026-05-16.md` for the soak context that
//! motivates this approach.

#![cfg(feature = "firefox-test")]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering};

/// LAPIC vector used to broadcast a DR0 update to other CPUs.
///
/// Chosen to sit immediately above the TLB shootdown vector (`0xF0`,
/// see `mm/tlb.rs`) and below the spurious-interrupt vector (`0xFF`).
/// No other AstryxOS handler installs here.
pub const W215_DR_SYNC_VECTOR: u8 = 0xF1;

/// Published linear address (`PHYS_OFF + phys`) and DR7 control word.
///
/// `ARMED.load == true` is the trigger for the IPI handler / late-arrival
/// helper to program DR0/DR7.  A zero `ARMED_ADDR` is treated as unarmed
/// regardless of `ARMED` for safety: writing 0 into DR0 with G0/L0 set
/// would catch every kernel-page-zero read.
static ARMED: AtomicBool = AtomicBool::new(false);
static ARMED_ADDR: AtomicU64 = AtomicU64::new(0);
static ARMED_CTRL: AtomicU64 = AtomicU64::new(0);
static ARMED_PHYS: AtomicU64 = AtomicU64::new(0);
static ARMED_KEY_INODE: AtomicU64 = AtomicU64::new(0);
static ARMED_KEY_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Number of `#DB` events captured by Arm-1 since boot.
static DR_FIRE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of arm broadcasts issued since boot.
static ARM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Build a DR7 control word for a single W-only watchpoint on DR0.
///
/// Per Intel SDM Vol. 3B §17.2.4 (DR7 layout, Table 17-2):
///   - L0  = bit 0  : local enable for DR0
///   - G0  = bit 1  : global enable for DR0 (survives task switch)
///   - LE  = bit 8  : local exact-data-match (recommended, even on P6+)
///   - GE  = bit 9  : global exact-data-match (recommended)
///   - R/W0 = bits 16-17 : 0b01 = data write only
///   - LEN0 = bits 18-19 : 0b00 = 1 byte, 0b01 = 2, 0b11 = 4, *0b10 = 8*
///     (8-byte form requires CPUID DE / IA-32 mode; valid on x86_64 per §17.2.5)
///
/// All other DRn slots are left disabled (Ln=Gn=0).  Reserved bit 10
/// (set on first read of an architectural DR7) is preserved by the
/// caller's read-modify-write in `program_local_dr0`.
fn dr7_for_write_watchpoint(len: u8) -> u64 {
    let rw: u64 = 0b01;        // write-only
    let len_field: u64 = match len {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        8 => 0b10,
        _ => 0b11,             // 4-byte default for unsupported sizes
    };
    let mut ctrl: u64 = 0;
    ctrl |= 1 << 0;            // L0
    ctrl |= 1 << 1;            // G0
    ctrl |= 1 << 8;            // LE
    ctrl |= 1 << 9;            // GE
    ctrl |= rw << 16;
    ctrl |= len_field << 18;
    // Bit 10 is documented as "reserved, must be 1" on most CPUs (Intel SDM
    // Vol. 3B §17.2.4).  Setting it unconditionally keeps DR7 well-formed.
    ctrl |= 1 << 10;
    ctrl
}

/// Program DR0 + DR7 on the current CPU with the published `(addr, ctrl)`
/// pair, leaving DR1–DR3 disabled.  No-op when unarmed.
///
/// Safe to call from interrupt context: only touches debug registers and
/// the atomics, never holds a lock.
#[inline(never)]
fn program_local_dr0() {
    if !ARMED.load(Ordering::Acquire) {
        return;
    }
    let addr = ARMED_ADDR.load(Ordering::Relaxed);
    let ctrl = ARMED_CTRL.load(Ordering::Relaxed);
    if addr == 0 {
        return;
    }
    unsafe {
        // Per Intel SDM Vol. 3B §17.2.6: clear DR6 status bits before
        // arming to avoid an immediate spurious `#DB` from a stale B0..B3.
        // BD/BS/BT are sticky and harmless if left set; we clear the lot
        // for cleanliness.
        let dr6_clear: u64 = 0;
        core::arch::asm!(
            "mov dr0, {addr}",
            "mov dr6, {dr6}",
            "mov dr7, {ctrl}",
            addr = in(reg) addr,
            dr6  = in(reg) dr6_clear,
            ctrl = in(reg) ctrl,
            options(nostack, preserves_flags),
        );
    }
}

/// Apply the currently armed watchpoint to this CPU.  Called from
/// `apic::ap_rust_entry` so a CPU that comes online after Arm-1 fires
/// picks up the watchpoint, and from the IPI handler.
pub fn apply_pending_to_this_cpu() {
    program_local_dr0();
}

/// Arm a W-only watchpoint at `linear_addr` of width `len` bytes.
///
/// Records the corrupted `phys` and cache key for the eventual `#DB`
/// fire-line so an investigator can correlate the kernel RIP with the
/// frame that tripped the CRC walker.
///
/// Idempotent on subsequent calls — only the first call within a boot
/// arms (rationale: the diagnostic is single-slot one-shot; an inflight
/// `#DB` would otherwise re-trip on every nearby kernel write before the
/// first hit is logged).  Returns `false` if already armed.
pub fn arm_write_watchpoint(
    linear_addr: u64,
    len: u8,
    phys: u64,
    inode: u64,
    file_offset: u64,
) -> bool {
    // First-armer wins.  AcqRel pairs with the IPI handler's Acquire on
    // ARMED.
    if ARMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    let ctrl = dr7_for_write_watchpoint(len);
    ARMED_ADDR.store(linear_addr, Ordering::Relaxed);
    ARMED_CTRL.store(ctrl, Ordering::Relaxed);
    ARMED_PHYS.store(phys, Ordering::Relaxed);
    ARMED_KEY_INODE.store(inode, Ordering::Relaxed);
    ARMED_KEY_OFFSET.store(file_offset, Ordering::Relaxed);

    // Program this CPU first; the IPI broadcast covers the rest.
    program_local_dr0();
    broadcast_dr_sync();

    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::serial_println!(
        "[W215/DR-ARM] linear={:#x} ctrl={:#x} phys={:#x} inode={} offset={:#x}",
        linear_addr, ctrl, phys, inode, file_offset,
    );
    true
}

/// Broadcast the pending DR0 update to all other online CPUs via
/// `W215_DR_SYNC_VECTOR`.  Best-effort: a CPU that is in SMM, holds
/// IF=0, or has not yet wired its IDT will pick up the update lazily
/// via `apply_pending_to_this_cpu` on its next entry path.
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

/// IPI handler for `W215_DR_SYNC_VECTOR`.  Programs this CPU's DR0/DR7
/// from the published atomics and EOIs the LAPIC.
pub extern "C" fn handle_w215_dr_sync_ipi() {
    program_local_dr0();
    super::apic::lapic_eoi();
}

/// Read DR6 (debug status register).  Per Intel SDM Vol. 3B §17.2.5,
/// reading DR6 returns sticky bits B0..B3 (one per breakpoint that
/// triggered), BD, BS, BT.  AstryxOS only inspects B0 for the W215
/// single-slot watchpoint.
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

/// Read CR3 (active page-table root).  Cheap; used only to tag the
/// `#DB` fire-line so an investigator can correlate the trap with the
/// active process.
#[inline(always)]
fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Inspect DR6 to see whether this `#DB` is the W215 watchpoint firing.
///
/// On a hit:
///   - Disarms the watchpoint globally (one-shot capture).
///   - Emits `[W215/DR-WATCH-FIRE] ...` with RIP, CR3, phys, key, and
///     up to 8 stack qwords below RSP.
///   - Clears B0..B3 in DR6 (write 0 to clear sticky bits per
///     Intel SDM Vol. 3B §17.2.5).
///   - Returns `true` to tell the dispatcher this trap is consumed.
///
/// Returns `false` if the trap is not the W215 watchpoint.
pub fn handle_db_exception(
    rip: u64,
    rsp: u64,
    rflags: u64,
    cs: u64,
) -> bool {
    let dr6 = read_dr6();
    // B0 = bit 0 of DR6 indicates DR0 triggered (Intel SDM Vol. 3B Table 17-1).
    let b0_hit = (dr6 & 0x1) != 0;
    if !b0_hit {
        return false;
    }
    if !ARMED.load(Ordering::Acquire) {
        // Spurious B0 (stale sticky bit) with no W215 arm active — clear and
        // let the trap fall through to the generic handler.
        write_dr6(dr6 & !0xF);
        return false;
    }

    // One-shot capture: disarm globally before logging so a flood of
    // follow-on writes does not re-trip the handler reentrantly.
    let phys = ARMED_PHYS.load(Ordering::Relaxed);
    let inode = ARMED_KEY_INODE.load(Ordering::Relaxed);
    let offset = ARMED_KEY_OFFSET.load(Ordering::Relaxed);
    let addr = ARMED_ADDR.load(Ordering::Relaxed);
    ARMED.store(false, Ordering::Release);
    ARMED_ADDR.store(0, Ordering::Relaxed);
    ARMED_CTRL.store(0, Ordering::Relaxed);
    // Clear DR7 on this CPU; the other CPUs still hold the watchpoint
    // until their next sync IPI, which we broadcast below to flush them.
    unsafe {
        core::arch::asm!(
            "xor rax, rax",
            "mov dr7, rax",
            "mov dr0, rax",
            out("rax") _,
            options(nostack, preserves_flags),
        );
    }
    // Clear the sticky B0..B3 bits we observed.
    write_dr6(dr6 & !0xF);

    let cpu = super::apic::cpu_index();
    let cr3 = read_cr3();
    let fire_idx = DR_FIRE_COUNT.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!(
        "[W215/DR-WATCH-FIRE] fire_idx={} cpu={} rip={:#x} cs={:#x} \
         rflags={:#x} cr3={:#x} phys={:#x} linear={:#x} key=(_,{},{:#x}) dr6={:#x}",
        fire_idx, cpu, rip, cs, rflags, cr3, phys, addr, inode, offset, dr6,
    );

    // Dump 8 qwords at and below RSP.  These are the top of the kernel
    // stack at trap time, so the qword at RSP is typically the return
    // address of the function that issued the write — that's the
    // information we actually want.  No locks, no page-fault recovery:
    // if RSP straddles an unmapped page the kernel page-fault handler
    // will catch it and log #PF; we won't hide that.
    crate::serial_println!(
        "[W215/DR-WATCH-FIRE/STACK] cpu={} rip={:#x} rsp={:#x}",
        cpu, rip, rsp,
    );
    for i in 0..8usize {
        let p = rsp.wrapping_add((i * 8) as u64);
        // Only dereference if the qword lies inside the kernel higher-half;
        // userspace RSPs are not meaningful for a kernel-side trap and a
        // stray dereference could itself fault.
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

    // Re-broadcast the (now-cleared) DR sync so the other CPUs disarm
    // their DR0/DR7 too.  This is a best-effort broadcast; a CPU that
    // misses it will continue to fire `#DB` on writes to the watched
    // address until its next sync IPI — the handler above will log
    // those as duplicate fires, which is informative rather than wrong.
    broadcast_dr_sync();
    true
}

/// Return `(arm_count, fire_count)` for the final reporting line.
pub fn stats() -> (u32, u32) {
    (
        ARM_COUNT.load(Ordering::Relaxed),
        DR_FIRE_COUNT.load(Ordering::Relaxed),
    )
}

/// True if the W215 watchpoint is currently armed.
pub fn is_armed() -> bool {
    ARMED.load(Ordering::Acquire)
}
