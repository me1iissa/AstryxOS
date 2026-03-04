//! Dispatcher Objects — Base infrastructure for waitable kernel objects
//!
//! Every waitable object (event, mutant, semaphore, timer) contains a
//! DispatcherHeader that tracks its type, signal state, and wait list.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::event::KeEvent;
use super::mutant::KeMutant;
use super::semaphore::KeSemaphore;
use super::timer::KeTimer;

// ── Dispatcher Object Types ─────────────────────────────────────────────────

/// The type of a dispatcher (waitable) object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatcherObjectType {
    Event,
    Mutant,
    Semaphore,
    Timer,
}

/// Signal state for readability (signal_state field is an i32 count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalState {
    NonSignaled,
    Signaled,
}

// ── WaitBlock ───────────────────────────────────────────────────────────────

/// Represents a thread waiting on a dispatcher object.
#[derive(Debug, Clone)]
pub struct WaitBlock {
    pub thread_id: u64,
    pub wait_type: WaitType,
    pub wait_key: u32, // index in WaitForMultiple array
    pub satisfied: bool,
}

/// Wait type for multi-object waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitType {
    WaitAll,
    WaitAny,
}

// ── DispatcherHeader ────────────────────────────────────────────────────────

/// Every waitable object contains a dispatcher header.
pub struct DispatcherHeader {
    pub object_type: DispatcherObjectType,
    pub signal_state: i32, // >0 means signaled (count for semaphore)
    pub wait_list: Vec<WaitBlock>,
}

impl DispatcherHeader {
    /// Create a new dispatcher header.
    pub fn new(object_type: DispatcherObjectType, initial_signal: i32) -> Self {
        Self {
            object_type,
            signal_state: initial_signal,
            wait_list: Vec::new(),
        }
    }

    /// Check if the object is currently signaled.
    pub fn is_signaled(&self) -> bool {
        self.signal_state > 0
    }
}

// ── Global Dispatcher Object Registry ───────────────────────────────────────

/// Global ID counter for dispatcher objects.
static NEXT_DISPATCHER_ID: AtomicU64 = AtomicU64::new(1);

/// A registered dispatcher object.
pub enum DispatcherEntry {
    Event(KeEvent),
    Mutant(KeMutant),
    Semaphore(KeSemaphore),
    Timer(KeTimer),
}

/// Global registry of all dispatcher objects, keyed by ID.
pub static DISPATCHER_REGISTRY: Mutex<Option<BTreeMap<u64, DispatcherEntry>>> = Mutex::new(None);

/// Initialize the dispatcher registry.
pub fn init() {
    let mut reg = DISPATCHER_REGISTRY.lock();
    *reg = Some(BTreeMap::new());
    crate::serial_println!("[Ke/Dispatcher] Initialized");
}

/// Allocate a new unique dispatcher object ID.
fn alloc_id() -> u64 {
    NEXT_DISPATCHER_ID.fetch_add(1, Ordering::SeqCst)
}

// ── Factory Functions ───────────────────────────────────────────────────────

/// Create an event and register it. Returns the object ID.
pub fn create_event(event_type: super::event::EventType) -> u64 {
    let id = alloc_id();
    let event = KeEvent::new(event_type);
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        map.insert(id, DispatcherEntry::Event(event));
    }
    id
}

/// Create a mutant and register it. Returns the object ID.
pub fn create_mutant() -> u64 {
    let id = alloc_id();
    let mutant = KeMutant::new();
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        map.insert(id, DispatcherEntry::Mutant(mutant));
    }
    id
}

/// Create a semaphore and register it. Returns the object ID.
pub fn create_semaphore(initial_count: i32, limit: i32) -> u64 {
    let id = alloc_id();
    let sem = KeSemaphore::new(initial_count, limit);
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        map.insert(id, DispatcherEntry::Semaphore(sem));
    }
    id
}

/// Create a timer and register it. Returns the object ID.
pub fn create_timer() -> u64 {
    let id = alloc_id();
    let timer = KeTimer::new();
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        map.insert(id, DispatcherEntry::Timer(timer));
    }
    id
}

/// Destroy/remove a dispatcher object from the registry.
pub fn destroy_object(id: u64) {
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        map.remove(&id);
    }
}

// ── With-object helpers ─────────────────────────────────────────────────────

/// Execute a closure with a mutable reference to the event at `id`.
/// Returns `None` if the object doesn't exist or is not an event.
pub fn with_event<F, R>(id: u64, f: F) -> Option<R>
where
    F: FnOnce(&mut KeEvent) -> R,
{
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        if let Some(DispatcherEntry::Event(ev)) = map.get_mut(&id) {
            return Some(f(ev));
        }
    }
    None
}

/// Execute a closure with a mutable reference to the mutant at `id`.
pub fn with_mutant<F, R>(id: u64, f: F) -> Option<R>
where
    F: FnOnce(&mut KeMutant) -> R,
{
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        if let Some(DispatcherEntry::Mutant(m)) = map.get_mut(&id) {
            return Some(f(m));
        }
    }
    None
}

/// Execute a closure with a mutable reference to the semaphore at `id`.
pub fn with_semaphore<F, R>(id: u64, f: F) -> Option<R>
where
    F: FnOnce(&mut KeSemaphore) -> R,
{
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        if let Some(DispatcherEntry::Semaphore(s)) = map.get_mut(&id) {
            return Some(f(s));
        }
    }
    None
}

/// Execute a closure with a mutable reference to the timer at `id`.
pub fn with_timer<F, R>(id: u64, f: F) -> Option<R>
where
    F: FnOnce(&mut KeTimer) -> R,
{
    let mut reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_mut() {
        if let Some(DispatcherEntry::Timer(t)) = map.get_mut(&id) {
            return Some(f(t));
        }
    }
    None
}

/// Read the signal state of any dispatcher object by ID.
pub fn read_signal_state(id: u64) -> Option<i32> {
    let reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_ref() {
        match map.get(&id) {
            Some(DispatcherEntry::Event(e)) => Some(e.header.signal_state),
            Some(DispatcherEntry::Mutant(m)) => Some(m.header.signal_state),
            Some(DispatcherEntry::Semaphore(s)) => Some(s.header.signal_state),
            Some(DispatcherEntry::Timer(t)) => Some(t.header.signal_state),
            None => None,
        }
    } else {
        None
    }
}

/// Get the object type for a given ID.
pub fn object_type(id: u64) -> Option<DispatcherObjectType> {
    let reg = DISPATCHER_REGISTRY.lock();
    if let Some(map) = reg.as_ref() {
        match map.get(&id) {
            Some(DispatcherEntry::Event(_)) => Some(DispatcherObjectType::Event),
            Some(DispatcherEntry::Mutant(_)) => Some(DispatcherObjectType::Mutant),
            Some(DispatcherEntry::Semaphore(_)) => Some(DispatcherObjectType::Semaphore),
            Some(DispatcherEntry::Timer(_)) => Some(DispatcherObjectType::Timer),
            None => None,
        }
    } else {
        None
    }
}

// ── True Blocking Wait Support ──────────────────────────────────────────────

/// Get a mutable reference to the DispatcherHeader from a DispatcherEntry.
pub fn dispatcher_header_mut(entry: &mut DispatcherEntry) -> &mut DispatcherHeader {
    match entry {
        DispatcherEntry::Event(e) => &mut e.header,
        DispatcherEntry::Mutant(m) => &mut m.header,
        DispatcherEntry::Semaphore(s) => &mut s.header,
        DispatcherEntry::Timer(t) => &mut t.header,
    }
}

/// Wake threads blocked on a dispatcher object whose WaitBlocks are marked satisfied.
///
/// This function is called by signal operations (set_event, release_mutant, etc.)
/// while the caller holds a mutable reference to the object (via DISPATCHER_REGISTRY).
/// It acquires THREAD_TABLE internally.
///
/// Lock ordering: DISPATCHER_REGISTRY → THREAD_TABLE (never reverse).
///
/// Woken threads receive a priority boost to improve responsiveness.
pub fn wake_blocked_waiters(header: &mut DispatcherHeader) {
    use crate::proc::{THREAD_TABLE, ThreadState, PRIORITY_BOOST_WAIT, PRIORITY_MAX};

    let mut threads = THREAD_TABLE.lock();
    for wb in header.wait_list.iter().filter(|wb| wb.satisfied) {
        if let Some(t) = threads.iter_mut().find(|t| t.tid == wb.thread_id) {
            if t.state == ThreadState::Blocked {
                t.state = ThreadState::Ready;
                // Apply priority boost (capped at MAX).
                t.priority = (t.priority + PRIORITY_BOOST_WAIT).min(PRIORITY_MAX);
            }
        }
    }
}
