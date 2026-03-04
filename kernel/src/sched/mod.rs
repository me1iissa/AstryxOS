//! CoreSched — The AstryxOS Scheduler
//!
//! Implements a round-robin cooperative/preemptive scheduler.
//! The timer interrupt calls `timer_tick_schedule()` which triggers
//! context switches at the end of each time quantum.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::proc::{self, ThreadState, THREAD_TABLE};
use crate::arch::x86_64::apic::MAX_CPUS;

/// Whether the scheduler is active.
static SCHEDULER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Time slice in ticks before preemption.
const TIME_SLICE: u64 = 5; // ~50 ms at 100 Hz

/// Per-CPU ticks remaining for current time slice.
static TICKS_REMAINING: [AtomicU64; MAX_CPUS] =
    [const { AtomicU64::new(TIME_SLICE) }; MAX_CPUS];

/// Counter for periodic dead-thread reaping.
static REAP_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Reap dead threads every N ticks (~1 second at 100 Hz).
const REAP_INTERVAL: u64 = 100;

/// Per-CPU reschedule flag: set by timer ISR, checked after interrupt return.
static NEED_RESCHEDULE: [AtomicBool; MAX_CPUS] =
    [const { AtomicBool::new(false) }; MAX_CPUS];

/// Get the current CPU index (APIC ID).
#[inline(always)]
fn cpu_index() -> usize {
    crate::arch::x86_64::apic::current_apic_id() as usize
}

/// Initialize CoreSched.
pub fn init() {
    SCHEDULER_ACTIVE.store(false, Ordering::Relaxed);
    for i in 0..MAX_CPUS {
        TICKS_REMAINING[i].store(TIME_SLICE, Ordering::Relaxed);
        NEED_RESCHEDULE[i].store(false, Ordering::Relaxed);
    }
    crate::serial_println!("[CoreSched] Scheduler initialized (per-CPU round-robin, quantum={} ticks)", TIME_SLICE);
}

/// Enable the scheduler.
pub fn enable() {
    SCHEDULER_ACTIVE.store(true, Ordering::Relaxed);
    crate::serial_println!("[CoreSched] Scheduler enabled");
}

/// Disable the scheduler.
pub fn disable() {
    SCHEDULER_ACTIVE.store(false, Ordering::Relaxed);
}

/// Check if the scheduler is active.
pub fn is_active() -> bool {
    SCHEDULER_ACTIVE.load(Ordering::Relaxed)
}

/// Called from the timer interrupt handler.
/// Decrements the time slice counter and sets the reschedule flag when expired.
/// Also decays boosted thread priorities towards their base values.
pub fn timer_tick_schedule() {
    if !is_active() {
        return;
    }

    // Wake sleeping threads and handle blocked timeouts.
    // Use try_lock to avoid deadlock: if THREAD_TABLE is held by
    // the interrupted code path, skip this tick.
    wake_sleeping_threads();

    // Periodically reap dead threads to free resources.
    // reap_dead_threads() locks THREAD_TABLE internally; since we're in
    // interrupt context, only do this if we can be reasonably sure the lock
    // is free.  The actual reap uses .lock() — if it deadlocks we skip via
    // the try_lock pattern inside reap_dead_threads_safe().
    let reap_count = REAP_COUNTER.fetch_add(1, Ordering::Relaxed);
    if reap_count % REAP_INTERVAL == 0 {
        reap_dead_threads_isr_safe();
    }

    // Decay priority boost on the current running thread.
    // Use try_lock to avoid deadlock with interrupted code holding THREAD_TABLE.
    {
        let tid = proc::current_tid();
        if let Some(mut threads) = THREAD_TABLE.try_lock() {
            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                if t.priority > t.base_priority {
                    t.priority -= 1;
                }
            }
        }
    }

    let cpu = cpu_index();
    let remaining = TICKS_REMAINING[cpu].load(Ordering::Relaxed);
    if remaining <= 1 {
        NEED_RESCHEDULE[cpu].store(true, Ordering::Relaxed);
        TICKS_REMAINING[cpu].store(TIME_SLICE, Ordering::Relaxed);
    } else {
        TICKS_REMAINING[cpu].store(remaining - 1, Ordering::Relaxed);
    }
}

/// Wake any threads whose sleep time has elapsed.
/// Also wakes blocked threads whose wait timeout has expired.
/// Uses try_lock since this is called from interrupt context —
/// if THREAD_TABLE is already held, skip this tick (wakeups will
/// be caught on the next timer tick).
fn wake_sleeping_threads() {
    let now = crate::arch::x86_64::irq::get_ticks();
    let mut threads = match THREAD_TABLE.try_lock() {
        Some(guard) => guard,
        None => return, // Lock held — skip this tick.
    };
    for t in threads.iter_mut() {
        if t.state == ThreadState::Sleeping && now >= t.wake_tick {
            t.state = ThreadState::Ready;
        }
        // Wake blocked threads whose timeout has expired.
        // The thread will resume in wait_for_single_object / wait_for_multiple_objects,
        // discover that its WaitBlock was NOT satisfied, and return Timeout.
        if t.state == ThreadState::Blocked && t.wake_tick != u64::MAX && now >= t.wake_tick {
            t.state = ThreadState::Ready;
        }
    }
}

/// ISR-safe variant of dead thread reaping.
/// Uses try_lock to avoid deadlock when called from interrupt context.
fn reap_dead_threads_isr_safe() {
    let mut threads = match THREAD_TABLE.try_lock() {
        Some(guard) => guard,
        None => return,
    };

    let dead_indices: alloc::vec::Vec<usize> = threads.iter().enumerate()
        .filter(|(_, t)| {
            t.state == ThreadState::Dead
                && t.tid != 0
                && t.tid < 0x1000
        })
        .map(|(i, _)| i)
        .collect();

    if dead_indices.is_empty() {
        return;
    }

    let mut reaped = 0usize;
    for &idx in dead_indices.iter().rev() {
        let t = &threads[idx];
        let stack_base = t.kernel_stack_base;
        let stack_pages = if t.kernel_stack_size > 0 {
            (t.kernel_stack_size as usize + 4095) / 4096
        } else {
            0
        };

        threads.swap_remove(idx);
        reaped += 1;

        if stack_base > 0 && stack_pages > 0 {
            for p in 0..stack_pages {
                crate::mm::pmm::free_page(stack_base + (p * 4096) as u64);
            }
        }
    }

    if reaped > 0 {
        drop(threads); // Release lock before serial output
        crate::serial_println!("[CoreSched] Reaped {} dead thread(s)", reaped);
    }
}

/// Check if a reschedule is pending (called after returning from interrupt).
pub fn check_reschedule() {
    let cpu = cpu_index();
    if NEED_RESCHEDULE[cpu].swap(false, Ordering::Relaxed) {
        schedule();
    }
}

/// Schedule the next thread to run.
///
/// This is the core scheduling function. It:
/// 1. Finds the highest-priority Ready thread (round-robin among equals).
/// 2. Saves context of the current thread.
/// 3. Switches to the new thread via switch_context.
pub fn schedule() {
    if !is_active() {
        return;
    }

    // ── Disable interrupts to prevent deadlock ──────────────────────
    // timer_tick_schedule() runs in the timer ISR and acquires THREAD_TABLE.
    // If we hold THREAD_TABLE when a timer interrupt fires on this CPU,
    // the ISR spins on the same lock → deadlock.  CLI prevents that.
    // Interrupts are re-enabled at each early-return and after the context
    // switch completes.
    crate::hal::disable_interrupts();

    let current_tid = proc::current_tid();
    let cpu = cpu_index() as u8;

    // Find the next ready thread — highest priority wins, round-robin among equals.
    // Prefer threads with matching cpu_affinity, then threads whose last_cpu
    // matches the current CPU (cache locality), then any Ready thread.
    let (next_tid, next_rsp, next_pid) = {
        let mut threads = THREAD_TABLE.lock();
        let len = threads.len();
        if len <= 1 {
            drop(threads);
            crate::hal::enable_interrupts();
            return; // Only idle thread, nothing to switch to.
        }

        // Find current thread's index.
        let current_idx = threads.iter()
            .position(|t| t.tid == current_tid)
            .unwrap_or(0);

        // Find the highest-priority Ready thread with affinity awareness.
        // Scoring: priority * 4 + affinity_bonus (0-2)
        //   - affinity match (pinned to this cpu): +2
        //   - last_cpu match (cache-warm): +1
        //   - no match: +0
        let mut best_idx: Option<usize> = None;
        let mut best_score: u16 = 0;

        for i in 1..len {
            let idx = (current_idx + i) % len;
            let t = &threads[idx];
            if t.state != ThreadState::Ready {
                continue;
            }
            // Skip threads pinned to a different CPU.
            if let Some(aff) = t.cpu_affinity {
                if aff != cpu {
                    continue;
                }
            }

            let mut score = (t.priority as u16) * 4;
            if t.cpu_affinity == Some(cpu) {
                score += 2; // Pinned to us — strong preference.
            } else if t.last_cpu == cpu {
                score += 1; // Ran here last — cache-warm preference.
            }

            if score > best_score || best_idx.is_none() {
                best_idx = Some(idx);
                best_score = score;
            }
        }

        match best_idx {
            Some(idx) => {
                // Mark current thread as Ready (unless it's Dead/Blocked/Sleeping).
                if let Some(cur) = threads.iter_mut().find(|t| t.tid == current_tid) {
                    if cur.state == ThreadState::Running {
                        cur.state = ThreadState::Ready;
                    }
                }

                // Mark next thread as Running and record which CPU it's on.
                threads[idx].state = ThreadState::Running;
                threads[idx].last_cpu = cpu;
                let tid = threads[idx].tid;
                let rsp = threads[idx].context.rsp;
                let pid = threads[idx].pid;
                (tid, rsp, pid)
            }
            None => {
                // No ready threads — stay on current (or idle).
                drop(threads);
                crate::hal::enable_interrupts();
                crate::perf::record_idle_tick();
                return;
            }
        }
    };

    if next_tid == current_tid {
        crate::hal::enable_interrupts();
        return; // No switch needed.
    }

    // Record performance metric
    crate::perf::record_context_switch();

    // Perform context switch.
    proc::set_current_tid(next_tid);
    TICKS_REMAINING[cpu as usize].store(TIME_SLICE, Ordering::Relaxed);

    // Get a raw pointer to the current thread's RSP field.
    // We need to hold the lock briefly to get the pointer, then release
    // before calling switch_context (which won't return until we're
    // scheduled back).
    let old_rsp_ptr = {
        let mut threads = THREAD_TABLE.lock();
        let cur = threads.iter_mut()
            .find(|t| t.tid == current_tid)
            .expect("current thread not in table");
        &mut cur.context.rsp as *mut u64
    };

    // Update TSS.rsp[0] and SYSCALL_KERNEL_RSP for the next thread.
    // This ensures that interrupts and SYSCALL from Ring 3 land on the
    // correct kernel stack for the newly-scheduled thread.
    {
        let threads = THREAD_TABLE.lock();
        if let Some(t) = threads.iter().find(|t| t.tid == next_tid) {
            if t.kernel_stack_base > 0 {
                let kstack_top = t.kernel_stack_base + t.kernel_stack_size;
                unsafe {
                    crate::arch::x86_64::gdt::update_tss_rsp0(kstack_top);
                    crate::syscall::set_kernel_rsp(kstack_top);
                }
            }
        }
    }

    // ── Per-process address space switch ─────────────────────────────
    // If the next thread belongs to a different process with a different CR3,
    // switch the page table before switching context.
    {
        let procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter().find(|p| p.pid == next_pid) {
            let new_cr3 = p.cr3;
            let current_cr3 = crate::mm::vmm::get_cr3();
            if new_cr3 != 0 && new_cr3 != current_cr3 {
                unsafe { crate::mm::vmm::switch_cr3(new_cr3); }
            }
        }
    }

    // ── FPU/SSE state save for outgoing thread ───────────────────────
    // Save FPU state lazily: only allocate the 512-byte buffer on first save.
    {
        let mut threads = THREAD_TABLE.lock();
        if let Some(cur) = threads.iter_mut().find(|t| t.tid == current_tid) {
            if cur.fpu_state.is_none() {
                cur.fpu_state = Some(alloc::boxed::Box::new(proc::FpuState::new_zeroed()));
            }
            if let Some(ref mut fpu) = cur.fpu_state {
                unsafe {
                    core::arch::asm!(
                        "fxsave [{}]",
                        in(reg) fpu.data.as_mut_ptr(),
                        options(nostack, preserves_flags),
                    );
                }
            }
        }
    }

    // SAFETY: old_rsp_ptr and new_rsp are valid. switch_context saves/restores
    // all callee-saved registers and switches stacks.
    // Note: interrupts are disabled (CLI). The switched-to thread will either:
    //   - IRETQ to Ring 3 with IF=1 (new user thread)
    //   - Return here and re-enable below (resumed kernel thread)
    unsafe {
        proc::thread::switch_context(old_rsp_ptr, next_rsp);
    }

    // ── Resumed after being rescheduled back onto this thread ───────
    // Interrupts are still disabled (CLI was set by whoever rescheduled us).

    // ── FPU/SSE state restore for incoming thread ───────────────────
    {
        let current_tid_now = proc::current_tid();
        let threads = THREAD_TABLE.lock();
        if let Some(cur) = threads.iter().find(|t| t.tid == current_tid_now) {
            if let Some(ref fpu) = cur.fpu_state {
                unsafe {
                    core::arch::asm!(
                        "fxrstor [{}]",
                        in(reg) fpu.data.as_ptr(),
                        options(nostack, preserves_flags),
                    );
                }
            }
        }
    }

    // ── TLS: restore FS base for incoming thread ────────────────────
    proc::restore_tls_for_current();

    // Re-enable interrupts now that all locks are released.
    crate::hal::enable_interrupts();
}

/// Yield the current thread's time slice voluntarily.
pub fn yield_cpu() {
    schedule();
}

/// Get scheduler statistics.
pub fn stats() -> (u64, u64) {
    let threads = THREAD_TABLE.lock();
    let ready = threads.iter().filter(|t| t.state == ThreadState::Ready).count() as u64;
    let total = threads.len() as u64;
    (ready, total)
}

/// Get the total number of timer ticks since boot.
pub fn total_ticks() -> u64 {
    crate::arch::x86_64::irq::get_ticks()
}
