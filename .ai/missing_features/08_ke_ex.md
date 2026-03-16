# Kernel Executive (KE / EX) Gaps

> Reference: Windows XP `base/ntos/ke/` (127 C files, 40 ASM), `base/ntos/ex/` (48 C files)
>             Linux `kernel/irq/`, `kernel/timer/`, `kernel/locking/`
> AstryxOS: `ke/mod.rs`, `ke/timer.rs`, `ke/wait.rs`, `ke/apc.rs`, `ke/dpc.rs`,
>            `ke/dispatcher.rs`, `ke/irql.rs`, `ex/mod.rs`, `ex/work_queue.rs`,
>            `ex/push_lock.rs`, `ex/fast_mutex.rs`, `ex/resource.rs`

---

## What We Have

- IRQL enum defined: PASSIVE_LEVEL(0), APC_LEVEL(1), DISPATCH_LEVEL(2), DIRQL base
- DPC struct + `queue_dpc()` + DPC work queue — **stub, queue is never drained**
- APC struct + `queue_user_apc()` — **stub, never delivered**
- `KernelTimer` with periodic + one-shot via PIT tick counter
- `WaitBlock` and `wait_for_single_object()` / `wait_for_multiple_objects()` with timeout
- Dispatcher objects: `KernelEvent`, `KernelMutant`, `KernelSemaphore` — Signal/Wait
- Executive work queue struct (`WorkQueue`, `WorkItem`) — **stub, items never executed**
- Push-lock (reader-writer spinlock) — read_lock / write_lock / try_read / try_write
- Fast mutex (spinlock-based) — acquire / release / try_acquire
- ERESOURCE (shared/exclusive lock) — defined but **exclusive/shared acquisition not enforced**

---

## Missing (Critical)

### Actual IRQL Enforcement
**What**: IRQL (Interrupt Request Level) is the NT mechanism for interrupt masking. At PASSIVE
(0), all interrupts are allowed. At DISPATCH (2), the CPU is in DPC context — no blocking.
At DIRQL (≥3), a specific hardware IRQ is masked. Raising IRQL to DISPATCH must disable the
scheduler; lowering it re-enables it.

**Current state**: IRQL enum exists but `raise_irql()` / `lower_irql()` in `ke/irql.rs` likely
just store the level without actually masking CPU interrupts. There is no enforcement preventing
blocking at DISPATCH_LEVEL (which would be a deadlock on a real kernel).

**Why critical**: Without IRQL enforcement, DPC code can sleep (taking a mutex that is held by
code waiting for an interrupt) → deadlock. This is a class of bug that silently causes random
hangs in drivers.

**Reference**: `XP/base/ntos/ke/i386/amd64s.asm` (`KfRaiseIrql`, `KfLowerIrql`);
`reactos/ntoskrnl/ke/i386/irq.c`

---

### DPC Queue Draining
**What**: DPCs (Deferred Procedure Calls) are queued by ISRs (can't do much work in ISR context)
and run at DISPATCH_LEVEL after the ISR completes. The scheduler tick, network packet processing,
and timer callbacks all use DPCs.

**Current state**: `queue_dpc()` exists and pushes to a `VecDeque`, but nothing ever calls
the drain function. DPCs are never executed.

**Why critical**: Network packet receive (e1000 RX interrupt) queues a DPC to process the packet.
Without DPC drain, received packets are silently discarded.

**Implementation**: Add DPC drain call to:
1. End of interrupt handler (after EOI to APIC)
2. End of `schedule()` (after all locks released)
3. AP idle loop between `hlt` instructions

**Reference**: `XP/base/ntos/ke/dpcsup.c` (`KiExecuteDpc`);
`reactos/ntoskrnl/ke/dpc.c`

---

### APC Delivery to User Mode
**What**: APCs (Asynchronous Procedure Calls) queued for user threads are delivered when the
thread returns to user mode from a syscall/interrupt (at PASSIVE_LEVEL). The kernel:
1. Checks APC queue on every return-to-user path
2. If APCs pending and thread is alertable: set up APC frame on user stack, call APC in user mode
3. On APC return: resume original user context

**Current state**: APC struct + queue exist but are never checked on syscall/interrupt return.

**Why needed**: Windows NT uses APCs for: async I/O completion, thread termination,
`QueueUserAPC()`. Direct equivalent in Linux is signal delivery (already done) but APC delivery
enables the NT subsystem compatibility layer.

**Reference**: `XP/base/ntos/ke/apc.c` (`KiDeliverApc`);
`XP/base/ntos/ke/i386/apcuser.asm`

---

## Missing (High)

### Per-CPU IRQL State
**What**: Each CPU maintains its own current IRQL. Raising IRQL on CPU 0 doesn't affect CPU 1.
Currently there is a single global interrupt enable/disable via `sti`/`cli`.

**Why high**: SMP requires per-CPU IRQL. An ISR on CPU 1 should not be blocked by CPU 0
lowering its IRQL.

**Reference**: `XP/base/ntos/ke/i386/` (`amd64prc.asm`); per-CPU GDT slot for IRQL

---

### ERESOURCE (Shared/Exclusive Reader-Writer Lock)
**What**: NT's ERESOURCE allows multiple concurrent readers OR one exclusive writer, with
recursive acquisition. Used throughout the NT kernel for: registry hive access, memory
manager tree locks, file system metadata.

**Current state**: `ex/resource.rs` has the struct but `acquire_shared`/`acquire_exclusive`
likely don't implement proper reader-writer semantics with waiters.

**Reference**: `XP/base/ntos/ex/resource.c` (`ExAcquireResourceSharedLite`);
`reactos/ntoskrnl/ex/resource.c`

---

### Executive Work Queue Execution
**What**: Work items queued to the executive work queue run on a pool of kernel worker threads.
These are the NT equivalent of Linux kernel work queues (`workqueue_struct`).

**Current state**: `queue_work_item()` exists, items stored in queue, but no worker threads
are ever spawned and no drain happens.

**Reference**: `XP/base/ntos/ex/worker.c` (`ExpWorkerThread`);
`linux/kernel/workqueue.c` (`process_one_work`)

---

### One-Shot vs Periodic Timer Distinction
**What**: Currently `KernelTimer` fires periodically at 100 Hz. NT timers can be:
- **Periodic**: resetting automatically (NotificationTimer that's re-armed)
- **One-shot**: fire once after N milliseconds, then disarm

Many kernel subsystems need one-shot timers: TCP retransmit, ARP retry, DHCP lease renewal.

**Reference**: `XP/base/ntos/ke/timer.c` (`KeSetTimer`, `KeSetTimerEx`);
`linux/kernel/hrtimer.c`

---

## Missing (Medium)

| Feature | Description | Reference |
|---------|-------------|-----------|
| High-resolution timers | Sub-tick precision (HPET or TSC) | `linux/kernel/hrtimer.c` |
| Soft-lockup / hard-lockup detection | Detect hung CPU via NMI watchdog | `linux/kernel/watchdog.c` |
| CPU stall detection | Panic if CPU is stuck in interrupt | `linux/kernel/rcu/tree_stall.h` |
| Spin count for mutexes | Try spin before blocking (NUMA perf) | `XP/base/ntos/ex/pushlock.c` |
| Timer coalescing | Group nearby timers to reduce wakeups | `linux/kernel/timer.c` |
| APC cancellation | Cancel queued APC before delivery | `XP/base/ntos/ke/apc.c` |

---

## Missing (Low)

| Feature | Description |
|---------|-------------|
| I/O priority levels | Separate RT / normal / idle I/O classes |
| Interrupt priority (IRQL per-interrupt) | Different hardware IRQs at different IRQLs |
| Dispatcher object performance counters | Count acquires/contention for profiling |
| Lock verification (Driver Verifier equivalent) | Check for IRQL violations at runtime |

---

## Implementation Order

1. **DPC drain** — add `ke::drain_dpcs()` call at end of each interrupt handler + end of `schedule()`
2. **One-shot timers** — add `is_periodic: bool` + `fire_count: u32` to `KernelTimer`; disarm after first fire if one-shot
3. **IRQL enforcement** — in `raise_irql(DISPATCH_LEVEL)` call `cli`; in `lower_irql(PASSIVE_LEVEL)` call `sti`; store in per-CPU `gs:`-relative slot
4. **Executive work queue drain** — spawn N kernel worker threads in `ex::init()`; each spins on work queue
5. **ERESOURCE reader-writer** — replace spin with semaphore + reader count + waitqueue
6. **APC delivery** — in syscall return path, before `sysret`, check `current_thread.apc_queue`, set up APC frame if alertable
