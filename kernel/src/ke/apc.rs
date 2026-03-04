//! APC — Asynchronous Procedure Calls
//!
//! Per-thread callbacks that execute when the IRQL drops to the appropriate
//! level.  Kernel APCs fire when IRQL < APC; user APCs fire on alertable waits
//! or when returning to user mode.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

/// Kernel-mode APC routine signature.
pub type KernelApcRoutine = fn(apc: &Apc);

/// User-mode APC routine signature (placeholder — not yet dispatched).
pub type UserApcRoutine = fn(context: u64);

/// APC mode — kernel or user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcMode {
    Kernel,
    User,
}

/// An Asynchronous Procedure Call object.
pub struct Apc {
    pub mode: ApcMode,
    pub kernel_routine: Option<KernelApcRoutine>,
    pub context: u64,
    pub thread_id: u64,
    pub inserted: bool,
}

/// Per-thread APC queues (kernel + user).
struct ApcQueue {
    kernel: Vec<Apc>,
    user: Vec<Apc>,
}

impl ApcQueue {
    const fn new() -> Self {
        Self {
            kernel: Vec::new(),
            user: Vec::new(),
        }
    }
}

/// Global map of thread-id → APC queues.
static APC_QUEUES: Mutex<BTreeMap<u64, ApcQueue>> = Mutex::new(BTreeMap::new());

/// Initialize the APC subsystem.
pub fn init() {
    crate::serial_println!("[Ke/APC] Initialized");
}

/// Initialize an APC object.
pub fn init_apc(
    apc: &mut Apc,
    thread_id: u64,
    mode: ApcMode,
    routine: KernelApcRoutine,
) {
    apc.thread_id = thread_id;
    apc.mode = mode;
    apc.kernel_routine = Some(routine);
    apc.context = 0;
    apc.inserted = false;
}

/// Queue an APC to the target thread's APC queue.
pub fn queue_apc(mut apc: Apc) {
    apc.inserted = true;
    let tid = apc.thread_id;
    let mode = apc.mode;
    let mut map = APC_QUEUES.lock();
    let entry = map.entry(tid).or_insert_with(ApcQueue::new);
    match mode {
        ApcMode::Kernel => entry.kernel.push(apc),
        ApcMode::User => entry.user.push(apc),
    }
}

/// Deliver all pending APCs for the given thread.
///
/// Kernel APCs are delivered first, then user APCs.
/// Called automatically when IRQL drops to Passive.
pub fn deliver_apcs(thread_id: u64) {
    deliver_kernel_apcs_inner(thread_id);
    deliver_user_apcs_inner(thread_id);
}

/// Deliver only kernel-mode APCs for the given thread.
pub fn drain_kernel_apcs(thread_id: u64) {
    deliver_kernel_apcs_inner(thread_id);
}

/// Return the number of queued APCs for the given thread and mode.
pub fn apc_queue_length(thread_id: u64, mode: ApcMode) -> usize {
    let map = APC_QUEUES.lock();
    match map.get(&thread_id) {
        Some(q) => match mode {
            ApcMode::Kernel => q.kernel.len(),
            ApcMode::User => q.user.len(),
        },
        None => 0,
    }
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn deliver_kernel_apcs_inner(thread_id: u64) {
    let batch: Vec<Apc> = {
        let mut map = APC_QUEUES.lock();
        match map.get_mut(&thread_id) {
            Some(q) => {
                let v = core::mem::replace(&mut q.kernel, Vec::new());
                v
            }
            None => return,
        }
    };

    for apc in &batch {
        if let Some(routine) = apc.kernel_routine {
            routine(apc);
        }
    }
}

fn deliver_user_apcs_inner(thread_id: u64) {
    let batch: Vec<Apc> = {
        let mut map = APC_QUEUES.lock();
        match map.get_mut(&thread_id) {
            Some(q) => core::mem::replace(&mut q.user, Vec::new()),
            None => return,
        }
    };

    // User APCs would be dispatched to userspace; for now just invoke the
    // kernel_routine if present (placeholder).
    for apc in &batch {
        if let Some(routine) = apc.kernel_routine {
            routine(apc);
        }
    }
}
