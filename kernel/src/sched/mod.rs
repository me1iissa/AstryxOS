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


/// Per-CPU reschedule flag: set by timer ISR, checked after interrupt return.
static NEED_RESCHEDULE: [AtomicBool; MAX_CPUS] =
    [const { AtomicBool::new(false) }; MAX_CPUS];

use crate::arch::x86_64::apic::cpu_index;

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

    // NOTE: Dead-thread reaping (freeing kernel stacks via pmm::free_page)
    // is intentionally NOT done here.  pmm::free_page acquires PMM_LOCK.
    // If the interrupted code already holds PMM_LOCK (e.g. free_process_memory),
    // the ISR would spin on PMM_LOCK forever — a same-CPU re-entrant deadlock.
    // Reaping is instead done at the start of schedule() where interrupts are
    // already disabled and no ISR can fire to cause this race.

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


/// Check if a reschedule is pending (called after returning from interrupt).
///
/// Returns immediately if the scheduler is not yet active — this avoids
/// calling `cpu_index()` (which reads `IA32_TSC_AUX` via `rdmsr`) before
/// `syscall::init()` has initialised that MSR on the BSP.
pub fn check_reschedule() {
    if !is_active() {
        return;
    }
    let cpu = cpu_index();
    if NEED_RESCHEDULE[cpu].swap(false, Ordering::Relaxed) {
        schedule();
    }
}

/// Reap dead threads and free their kernel stacks.
///
/// MUST be called with interrupts already disabled so that pmm::free_page()
/// cannot deadlock with a concurrent timer ISR that also acquires PMM_LOCK.
/// Called at the start of schedule() which guarantees IF=0 via disable_interrupts().
fn reap_dead_threads_sched() {
    use crate::proc::KERNEL_VIRT_OFFSET;

    // IMPORTANT: Never reap the CURRENT thread. The caller is still running on
    // its kernel stack — freeing the stack while executing on it is a UAF.
    // The current thread will be reaped the next time a DIFFERENT thread calls
    // schedule() and runs this function (with a different current_tid).
    let current_tid = crate::proc::current_tid();

    // Collect (stack_base, stack_pages) for each reapable thread, removing
    // them from THREAD_TABLE in the same pass.
    let stacks: alloc::vec::Vec<(u64, usize)> = {
        let mut threads = THREAD_TABLE.lock();
        // A Dead thread is safe to reap only when ctx_rsp_valid == true, which
        // switch_context_asm sets AFTER saving the thread's RSP (meaning the CPU
        // has left or is about to leave the thread's kernel stack).  Exit paths
        // (exit_thread/exit_group) set ctx_rsp_valid=false before calling schedule(),
        // preventing the AP from freeing the stack while the BSP is still on it.
        let dead_indices: alloc::vec::Vec<usize> = threads.iter().enumerate()
            .filter(|(_, t)| {
                t.is_reapable()
                    && t.tid != current_tid
                    && t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire)
            })
            .map(|(i, _)| i)
            .collect();
        if dead_indices.is_empty() {
            return;
        }
        let mut out = alloc::vec::Vec::with_capacity(dead_indices.len());
        for &idx in dead_indices.iter().rev() {
            let t = &threads[idx];
            let base = t.kernel_stack_base;
            let pages = if t.kernel_stack_size > 0 {
                (t.kernel_stack_size as usize + 4095) / 4096
            } else { 0 };
            threads.swap_remove(idx);
            if base > 0 && pages > 0 {
                out.push((base, pages));
            }
        }
        out
    }; // THREAD_TABLE released before any PMM operations

    // Free kernel stacks with no locks held (interrupts still disabled → safe).
    for (stack_base, stack_pages) in stacks {
        let phys_base = if stack_base >= KERNEL_VIRT_OFFSET {
            stack_base - KERNEL_VIRT_OFFSET
        } else {
            stack_base
        };
        for p in 0..stack_pages {
            crate::mm::pmm::free_page(phys_base + (p as u64) * 0x1000);
        }
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

    // Reap dead threads here (interrupts disabled → PMM_LOCK safe, no ISR deadlock).
    reap_dead_threads_sched();

    let current_tid = proc::current_tid();
    let cpu = cpu_index() as u8;

    // Find the next ready thread — highest priority wins, round-robin among equals.
    // Prefer threads with matching cpu_affinity, then threads whose last_cpu
    // matches the current CPU (cache locality), then any Ready thread.
    let (next_tid, next_rsp, next_pid, next_kstack_top, next_first_run) = {
        let mut threads = THREAD_TABLE.lock();
        let len = threads.len();
        if len <= 1 {
            // Check if we're a dead thread before bailing — if so we need to spin.
            let current_is_done = threads
                .iter()
                .find(|t| t.tid == current_tid)
                .map(|t| !matches!(t.state, ThreadState::Running))
                .unwrap_or(true);
            drop(threads);
            crate::hal::enable_interrupts();
            if current_is_done {
                loop { core::hint::spin_loop(); } // nothing else can ever exist
            }
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
            // Skip threads whose kernel RSP is not yet valid — another CPU is
            // mid-way through switching them out and hasn't saved the new RSP
            // yet.  Picking up such a thread would resume it from a stale RSP.
            if !t.ctx_rsp_valid.load(core::sync::atomic::Ordering::Acquire) {
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
                // IMPORTANT: Clear ctx_rsp_valid BEFORE marking Ready.  This prevents
                // other CPUs from picking up the thread with a stale kernel RSP (SMP
                // context-switch race guard).  switch_context_asm will set it back to
                // true atomically right after saving the new RSP.
                if let Some(cur) = threads.iter_mut().find(|t| t.tid == current_tid) {
                    if cur.state == ThreadState::Running {
                        cur.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
                        cur.state = ThreadState::Ready;
                    }
                    // Decay priority boost here (outgoing thread, lock already held)
                    // rather than in the timer ISR to avoid 100 Hz try_lock overhead.
                    if cur.priority > cur.base_priority {
                        cur.priority -= 1;
                    }
                }

                // Mark next thread as Running and record which CPU it's on.
                threads[idx].state = ThreadState::Running;
                threads[idx].last_cpu = cpu;
                let tid = threads[idx].tid;
                let rsp = threads[idx].context.rsp;
                let pid = threads[idx].pid;
                let kstack_top = if threads[idx].kernel_stack_base > 0 {
                    threads[idx].kernel_stack_base + threads[idx].kernel_stack_size
                } else { 0 };
                let first_run = threads[idx].first_run;
                (tid, rsp, pid, kstack_top, first_run)
            }
            None => {
                // No ready threads on this CPU right now.
                // If the current thread is dead/blocked/sleeping (e.g. called from
                // exit_group or exit_thread) we MUST NOT return to it — doing so
                // would sysretq back into dead user-space code.  Spin with interrupts
                // enabled so timer ticks can wake/schedule another thread, then retry.
                let current_is_done = threads
                    .iter()
                    .find(|t| t.tid == current_tid)
                    .map(|t| !matches!(t.state, ThreadState::Running))
                    .unwrap_or(true); // thread already reaped = treat as done
                drop(threads);
                crate::hal::enable_interrupts();
                if current_is_done {
                    loop {
                        core::hint::spin_loop();
                        // Check if a thread runnable on this CPU has become Ready.
                        let any_ready = THREAD_TABLE.try_lock().map(|t| {
                            t.iter().any(|th| {
                                th.state == ThreadState::Ready
                                    && th.cpu_affinity.map_or(true, |aff| aff == cpu)
                            })
                        }).unwrap_or(false);
                        if any_ready { break; }
                    }
                    // Re-enter schedule() to perform the actual context switch.
                    // The dead/blocked thread will be replaced and never return here.
                    return schedule();
                }
                crate::perf::record_idle_tick();
                return  // no semicolon — arm type is !, coerces to tuple type
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

    // Update TSS.rsp[0] and SYSCALL_KERNEL_RSP for the next thread.
    // This ensures that interrupts and SYSCALL from Ring 3 land on the
    // correct kernel stack for the newly-scheduled thread.
    // next_kstack_top was extracted from the main scheduling lock above.
    unsafe {
        if next_kstack_top > 0 {
            crate::arch::x86_64::gdt::update_tss_rsp0(next_kstack_top);
            crate::syscall::set_kernel_rsp(next_kstack_top);
        } else {
            // Switching to idle/kernel thread with no dedicated stack.
            // Invalidate kernel_rsp so recover_current_tid() slow-path
            // does not misidentify this thread as the previous user thread.
            crate::syscall::set_kernel_rsp(0);
        }
    }

    // ── Per-process address space switch ─────────────────────────────
    // If the next thread belongs to a different process with a different CR3,
    // switch the page table before switching context.
    //
    // EXCEPTION: first-run threads (first_run == true) must NOT have their
    // CR3 switched here.  Their kernel stack was allocated after the user
    // page table was created, so the user PML4 does not yet contain the
    // kernel-stack mapping.  Switching to the user CR3 before switch_context
    // would cause a triple-fault the moment switch_context touches the stack.
    // user_mode_bootstrap() clears first_run and switches CR3 itself, after
    // running on the current kernel page table where the stack IS mapped.
    // next_first_run was extracted from the main scheduling lock above.
    // KERNEL THREAD CR3 RESTORE: when the next thread is a kernel/idle thread
    // (p.cr3 == 0), switch back to the kernel's primary page table.  Without
    // this, a CPU that previously ran a user thread (via user_mode_bootstrap)
    // retains the user CR3 after that process exits.  free_process_memory then
    // frees/reallocates those physical pages, corrupting the CPU's page table.
    if !next_first_run {
        let next_cr3 = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == next_pid).map(|p| p.cr3).unwrap_or(0)
        };
        let effective_cr3 = if next_cr3 != 0 {
            next_cr3
        } else {
            crate::mm::vmm::get_kernel_cr3()
        };
        let current_cr3 = crate::mm::vmm::get_cr3();
        if effective_cr3 != 0 && effective_cr3 != current_cr3 {
            unsafe { crate::mm::vmm::switch_cr3(effective_cr3); }
        }
    }

    // Get raw pointers to the current thread's RSP and ctx_rsp_valid fields,
    // and save FPU state, all in a single lock acquisition.  The lock must be
    // released before switch_context (which won't return until rescheduled).
    let (old_rsp_ptr, ctx_valid_ptr) = {
        let mut threads = THREAD_TABLE.lock();
        let cur = threads.iter_mut()
            .find(|t| t.tid == current_tid)
            .expect("current thread not in table");
        // ── FPU/SSE state save for outgoing thread ───────────────────────
        // Save FPU state lazily: only allocate the 512-byte buffer on first save.
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
        (
            &mut cur.context.rsp as *mut u64,
            cur.ctx_rsp_valid.as_ptr() as *mut u8,
        )
    };

    // SAFETY: old_rsp_ptr and new_rsp are valid. switch_context saves/restores
    // all callee-saved registers and switches stacks.
    // Note: interrupts are disabled (CLI). The switched-to thread will either:
    //   - IRETQ to Ring 3 with IF=1 (new user thread)
    //   - Return here and re-enable below (resumed kernel thread)
    // ctx_valid_ptr: switch_context_asm sets *ctx_valid_ptr = 1 after saving
    // old_rsp, preventing other CPUs from using a stale RSP (SMP race guard).
    unsafe {
        proc::thread::switch_context(old_rsp_ptr, next_rsp, ctx_valid_ptr);
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
