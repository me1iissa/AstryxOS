//! Ke — Kernel Executive
//!
//! NT-inspired kernel services: IRQL, DPC, APC, Dispatcher Objects, Wait.

pub mod bugcheck;
pub mod irql;
pub mod dpc;
pub mod apc;
pub mod dispatcher;
pub mod event;
pub mod mutant;
pub mod semaphore;
pub mod timer;
pub mod wait;

pub use irql::{Irql, raise_irql, lower_irql, current_irql};
pub use dpc::{Dpc, DpcImportance, DpcRoutine, init_dpc, queue_dpc, drain_dpc_queue};
pub use apc::{Apc, ApcMode, queue_apc, deliver_apcs};
pub use dispatcher::{
    DispatcherObjectType, SignalState, DispatcherHeader, WaitBlock, WaitType,
    create_event, create_mutant, create_semaphore, create_timer,
    destroy_object, with_event, with_mutant, with_semaphore, with_timer,
    read_signal_state,
};
pub use event::EventType;
pub use wait::{WaitStatus, wait_for_single_object, wait_for_multiple_objects};

/// Initialize all Ke subsystems.
pub fn init() {
    irql::init();
    dpc::init();
    apc::init();
    dispatcher::init();
    timer::init();
    crate::serial_println!("[Ke] Kernel executive initialized (IRQL+DPC+APC+Dispatcher+Timer)");
}
