//! IRQL — Interrupt Request Level Model
//!
//! Software interrupt request levels modeled after NT but adapted for AstryxOS.
//! Controls preemptability: code running at a higher IRQL cannot be preempted by
//! activity at a lower IRQL.

use core::sync::atomic::{AtomicU8, Ordering};

/// Interrupt Request Level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Irql {
    Passive  = 0, // Normal thread execution
    Apc      = 1, // APC delivery level
    Dispatch = 2, // DPC delivery / scheduler level
    Device   = 3, // Device interrupt level (placeholder for multiple)
    High     = 4, // Highest — masks all interrupts
}

impl Irql {
    /// Convert from raw u8.  Returns `None` for out-of-range values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Irql::Passive),
            1 => Some(Irql::Apc),
            2 => Some(Irql::Dispatch),
            3 => Some(Irql::Device),
            4 => Some(Irql::High),
            _ => None,
        }
    }
}

/// Per-CPU current IRQL (single CPU for now).
static CURRENT_IRQL: AtomicU8 = AtomicU8::new(Irql::High as u8);

/// Initialize the IRQL subsystem.  Sets the initial IRQL to `Passive`.
pub fn init() {
    CURRENT_IRQL.store(Irql::Passive as u8, Ordering::SeqCst);
    sync_hw_interrupts(Irql::Passive);
    crate::serial_println!("[Ke/IRQL] Initialized — current IRQL = Passive");
}

/// Returns the current IRQL.
#[inline]
pub fn current_irql() -> Irql {
    Irql::from_u8(CURRENT_IRQL.load(Ordering::SeqCst))
        .unwrap_or(Irql::High)
}

/// Raise the IRQL to `new`.  Returns the previous IRQL.
///
/// # Panics
/// Panics if `new` is lower than the current IRQL (use `lower_irql` instead).
pub fn raise_irql(new: Irql) -> Irql {
    let prev_raw = CURRENT_IRQL.load(Ordering::SeqCst);
    let prev = Irql::from_u8(prev_raw).unwrap_or(Irql::High);
    assert!(
        new >= prev,
        "raise_irql: new ({:?}) < current ({:?}) — use lower_irql to lower",
        new,
        prev,
    );
    CURRENT_IRQL.store(new as u8, Ordering::SeqCst);
    sync_hw_interrupts(new);
    prev
}

/// Lower the IRQL to `old` (the value previously returned by `raise_irql`).
///
/// If the transition crosses below `Dispatch`, the DPC queue is drained.
/// If the transition crosses below `Apc`, pending APCs are delivered.
pub fn lower_irql(old: Irql) {
    CURRENT_IRQL.store(old as u8, Ordering::SeqCst);
    sync_hw_interrupts(old);

    // When dropping below Dispatch, drain the DPC queue.
    if old < Irql::Dispatch {
        super::dpc::drain_dpc_queue();
    }

    // When dropping below Apc, deliver pending APCs for current thread.
    if old < Irql::Apc {
        // Use thread_id 0 as the "current" thread placeholder.
        super::apc::deliver_apcs(0);
    }
}

/// Raw IRQL lower — sets the level and syncs HW flags but does **not**
/// trigger DPC drain or APC delivery.  Used internally by the DPC/APC
/// subsystems to avoid recursion.
pub fn lower_irql_raw(old: Irql) {
    CURRENT_IRQL.store(old as u8, Ordering::SeqCst);
    sync_hw_interrupts(old);
}

/// Synchronize hardware interrupt flag with the given IRQL.
/// At Dispatch and above → CLI (hardware interrupts disabled).
/// At Passive / APC      → STI (hardware interrupts enabled).
#[inline]
fn sync_hw_interrupts(level: Irql) {
    if level >= Irql::Dispatch {
        unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)); }
    } else {
        unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)); }
    }
}
