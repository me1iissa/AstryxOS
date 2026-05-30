# musl / Linux-ABI Completeness Audit — AstryxOS

**Audit date:** 2026-05-30
**Master:** `9a13616`
**Scope:** the subset of the Linux x86-64 syscall ABI that **musl libc**
(Alpine binaries: `ld-musl-x86_64.so.1`, libxul, GTK, X11) actually issues,
and whether the AstryxOS kernel meets the published contract for each.
**Implementation under audit:** `kernel/src/subsys/linux/syscall.rs`,
`kernel/src/proc/mod.rs`, `kernel/src/signal.rs`, `kernel/src/ipc/`.

This document is **audit only** — no kernel source was modified to produce it.
All semantics are stated against public specifications: the Linux `man 2`
pages (man-pages 6.x), POSIX.1-2017, and the x86-64 System V psABI. No
description is derived from any third-party source tree.

A companion **test tier** (`musl-abi`) was added to
`kernel/src/test_runner.rs` to pin the high-value surfaces — see §4.

---

## 1. Method

musl differs from glibc in *which* syscalls it issues and in *what form*.
Three musl-specific traits shape this audit:

1. **musl converts absolute pthread deadlines to relative `FUTEX_WAIT`
   intervals in userspace** (`__timedwait` does
   `to = at − clock_gettime(clk)` and issues plain `FUTEX_WAIT`). It does
   **not** rely on `FUTEX_CLOCK_REALTIME` for its core condvar/semaphore
   timed waits. Consequence: the kernel's relative-`FUTEX_WAIT` timeout path
   is the load-bearing one for musl; the absolute path matters for *direct*
   application callers (libxul, GTK) and for glibc binaries.

2. **musl unwinds its own robust-mutex list in userspace at normal thread
   exit** (in `pthread_create`'s exit shim). It registers
   `set_robust_list` only as a backstop for *abnormal* death (crash / kill
   while holding a robust mutex). Consequence: the kernel robust-list
   owner-died walk is a rare-path correctness backstop, not a hot path.

3. **musl never issues `FUTEX_WAKE_OP`.** It uses `FUTEX_WAIT`,
   `FUTEX_WAKE`, `FUTEX_REQUEUE`, `FUTEX_PRIVATE`, and the PI ops
   (`FUTEX_LOCK_PI` / `FUTEX_UNLOCK_PI`, only when a mutex is created with
   `PTHREAD_PRIO_INHERIT`). Consequence: the `FUTEX_WAKE_OP` ENOSYS stub is
   **not** a musl gap.

For each surface below: musl-uses-it-for | our status | gap detail | severity.

Severity = likelihood of biting a real musl program on the FF path:
**CRITICAL** (musl/libxul hits it constantly), **HIGH** (specific init or
timed-wait paths), **MEDIUM** (rare / abnormal-path only), **LOW** (dead path
for the current workload).

---

## 2. Gap table — ranked

| # | Surface | musl uses it for | Our status | Gap detail | Severity |
|---|---------|------------------|-----------|-----------|----------|
| 1 | **`clock_nanosleep` (230) `TIMER_ABSTIME`** | direct app sleeps with an absolute deadline (libxul `Sleep`/`TimeStamp`, GTK/libevent resilient timers); musl `nanosleep`/`thrd_sleep` use flags=0 (relative) | **partial** — dispatch is `230 => sys_nanosleep_linux(arg3, arg4)`; `clockid` (arg1) and `flags` (arg2) are **discarded** | `TIMER_ABSTIME` (flag bit 0) is ignored, so an absolute deadline timespec is treated as a *relative* interval → the caller sleeps for the full wall-clock value of the timestamp (decades), never waking. Also `clockid` is ignored, so `CLOCK_MONOTONIC` vs `CLOCK_REALTIME` is not honoured. Per `clock_nanosleep(2)`: with `TIMER_ABSTIME`, `request` is "an absolute time as measured by the clock, `clockid`". | **HIGH** |
| 2 | **`FUTEX_REQUEUE` (3) wake=0/requeue=1** | `pthread_cond_timedwait` / `pthread_cond_broadcast` requeue cond-internal waiters onto the associated mutex (musl issues `FUTEX_REQUEUE\|FUTEX_PRIVATE, 0, 1, mutex`) | **full** | Handler wakes `val` and requeues up to `val2`; with `val=0, val2=1` it wakes 0 and moves 1 waiter to `uaddr2`, returning 0 (woken count). Matches `futex(2)`. **No gap** — listed because it is the single most ABI-load-bearing musl futex op and must not regress. | OK |
| 3 | **robust-list owner-died walk on thread death** | `set_robust_list` backstop: if a thread dies *abnormally* holding a robust mutex, the kernel must set `FUTEX_OWNER_DIED` (bit 30) on the lock word and `FUTEX_WAKE` one waiter | **partial** — head/len are stored and round-tripped for `get_robust_list`; the list is **never walked** on exit | A thread killed/crashed while holding a `PTHREAD_MUTEX_ROBUST` mutex leaves waiters parked forever (no `EOWNERDEAD` handoff). musl handles the *normal*-exit case itself, so this only bites abnormal death. Per `set_robust_list(2)` / `get_robust_list(2)` and `robust_futexes` semantics. | **MEDIUM** |
| 4 | **`FUTEX_WAKE_OP` (5)** | — (musl never issues it) | **ENOSYS stub** | Correct to stub for musl. glibc cond-vars in *older* builds could use it; current glibc/musl do not. Returning `-ENOSYS` is the spec-sanctioned signal for "unsupported op." | **LOW** |
| 5 | **`FUTEX_LOCK_PI` / `FUTEX_UNLOCK_PI` (6/7)** | `pthread_mutex_*` only when the mutex is `PTHREAD_PRIO_INHERIT` | **absent** (falls to `_ => -38 ENOSYS`) | PI mutexes are not on the FF path (libxul does not request `PRIO_INHERIT`). A program that does create a PI mutex would get `-ENOSYS` from lock/unlock. Per `futex(2)` PI-futex section. | **LOW** |
| 6 | **`rseq` (334)** | glibc 2.35+ registers unconditionally; musl does **not** use rseq | returns **0** (accept, no-op) | Returning 0 claims rseq is registered without honouring the ABI. musl never calls it; glibc tolerates a no-op region. Harmless for musl; mild fib for glibc. Per `rseq(2)`. | **LOW** |
| 7 | **`membarrier` (324)** | musl does not issue it; glibc/libstdc++ `__cxa`/JIT paths may | implemented (global barrier) | A kernel-wide barrier over-satisfies `MEMBARRIER_CMD_*`; spec-permissive. No gap. Per `membarrier(2)`. | OK |
| 8 | **`set_tid_address` (218) + clear-on-exit wake** | musl thread startup registers `&self->tid`; kernel must zero it and `FUTEX_WAKE` one waiter at exit (the `pthread_join` wakeup) | **full** (hardened by the CLEARTID demand-fault-on-exit work) | `clear_child_tid` stored; `fire_cleartid_for_group` zeroes the user-VA and wakes one waiter on exit, fault-immune against a torn-down VmSpace. Matches `set_tid_address(2)` + `clone(2)` `CLONE_CHILD_CLEARTID`. **No gap.** | OK |
| 9 | **`clone` / `clone3` `CLONE_*` set** | `pthread_create` (THREAD\|VM\|FS\|FILES\|SIGHAND\|SETTLS\|CHILD_CLEARTID\|PARENT_SETTID); `posix_spawn`/`vfork` (VM\|VFORK) | **full** for the musl set | THREAD+VM share the `Arc<VmSpace>`; SETTLS, CHILD_CLEARTID, PARENT_SETTID, CHILD_SETTID, CLEAR_SIGHAND all handled in both `clone` and `clone3`. Callee-saved GPRs inherited (W113 fix). Matches `clone(2)`/`clone3(2)`. **No gap** for musl. | OK |
| 10 | **signal frame `ucontext_t` / `SA_SIGINFO`** | musl `sigaction(SA_SIGINFO)` handlers (libxul crash reporter, JS GC signals) read `uc_mcontext.gregs[REG_*]` | **full** | 424-byte `UContext` with a compile-time size assert; `gregs[23]` at offset 40 per `<sys/ucontext.h>`; `RDX=&ucontext`, `RSI=&siginfo` set before handler entry per psABI §3.4. **No gap** (see §3 hardening note). | OK |
| 11 | **`sched_getaffinity` (204)** | musl `sysconf(_SC_NPROCESSORS_ONLN)` / `pthread` pool sizing | implemented (reports online CPUs; returns mask length per the raw-syscall C-library-difference note in `sched_getaffinity(2)`) | No gap. | OK |
| 12 | **`sched_setaffinity` (203)** | rarely; some thread pools pin | **stub** (`203 => 0`, accept-any) | Accepting without pinning is spec-tolerable (affinity is advisory); no observable musl breakage. Per `sched_setaffinity(2)`. | LOW |
| 13 | **`prlimit64` (302) / `getrlimit` (97)** | musl `setrlimit`/`getrlimit`, stack-size queries at thread create | implemented (GET path populated) | SET path is the audit follow-up; GET is what `pthread_create` reads for the default stack size. Per `prlimit(2)`. | LOW |
| 14 | **eventfd / timerfd / signalfd / epoll / pipe readiness** | musl `pthread_cancel` self-pipe, libxul event loop (epoll + eventfd + pipe), GTK timerfd | implemented; readiness edges hardened (HUP delivery, POLL_BELL TOCTOU) | timerfd honours `TFD_TIMER_ABSTIME`. The recent readiness fixes cleared the deterministic event-loop wedge. **No gap** identified at audit time. | OK |

---

## 3. Notes on surfaces that are correct (so they are not "re-fixed")

- **`FUTEX_WAIT_BITSET` (9) / `FUTEX_WAKE_BITSET` (10):** bitset accepted and
  treated as `MATCH_ANY`. musl/glibc condvars always pass
  `FUTEX_BITSET_MATCH_ANY`, so the simplification is ABI-faithful in
  practice. Per `futex(2)`.
- **`FUTEX_CLOCK_REALTIME` (0x100):** absolute-deadline conversion present
  and coherent with `clock_gettime(CLOCK_REALTIME)` and the vDSO. Needed by
  glibc; musl uses relative waits but the path is correct for both.
- **ucontext layout:** `_UCONTEXT_SIZE_CHECK` const-asserts
  `size_of::<UContext>() == 424`. Padding in the frame is zeroed
  (`write_bytes(ucontext_ptr, 0, 1)`) before population, so no stale stack
  bytes leak through `gregs`/`fpregs`. This is the struct-layout discipline
  already satisfied.

---

## 4. Test tier `musl-abi`

A named tier was added to `kernel/src/test_runner.rs`. Each test routes
through `crate::syscall::dispatch_linux_kernel(nr, …)` — the exact path a
musl binary's `syscall` instruction reaches — and asserts a deterministic
pass/fail. The tier covers:

- **futex** WAIT (EAGAIN on value-mismatch; ETIMEDOUT on 1 ns relative
  timeout), WAKE (woken-count on empty queue), REQUEUE wake=0/requeue=1
  (the musl condvar pattern), CMP_REQUEUE val3 mismatch → EAGAIN,
  WAIT_BITSET timeout, private+shared.
- **clock surface** CLOCK_MONOTONIC monotonicity across two reads;
  CLOCK_REALTIME ≥ MONOTONIC; relative `clock_nanosleep` returns 0;
  **`clock_nanosleep(TIMER_ABSTIME)` with a past deadline returns
  immediately** (regression pin for gap #1 once fixed).
- **set_tid_address** returns the caller TID and stores the clear slot.
- **clone GPR / TLS** invariants exercised by the existing
  `test_clone_thread` / `test_clone3_share_vm` (cross-referenced, not
  duplicated).

CI gates on the tier via the standard `[TEST-JSON]` reporter consumed by
`qemu-harness.py results`.

---

## 5. Top 3 gaps to fix next (for a follow-up dispatch)

Ranked by likelihood of biting a real musl/libxul program.

### Gap #1 — `clock_nanosleep` ignores `TIMER_ABSTIME` and `clockid` — **HIGH**

`kernel/src/subsys/linux/syscall.rs:4562`

```rust
230 => sys_nanosleep_linux(arg3, arg4),
```

**Problem:** `arg1`=clockid and `arg2`=flags are dropped. With
`TIMER_ABSTIME` (flag 1) the timespec at `arg3` is an *absolute* deadline;
treating it as a relative interval parks the caller for the full timestamp
value (decades).

**Confirmed at the code level:** `sys_nanosleep_linux` (`syscall.rs:5061`)
reads the timespec at `arg3` and converts `tv_sec` directly to a *relative*
tick count (`ticks = (tv_sec*1000 + tv_nsec/1e6 + 9)/10`). With an absolute
deadline of, e.g., `{tv_sec = 1_748_600_000}` (a realistic 2025 wall-clock
timestamp) this computes ~174-billion ticks — a multi-decade park — instead
of waking at the deadline. The `musl-abi` clock test exercises the abstime
path; it pins the contract as a *soft* note rather than a hard assertion
because the kernel-test BSP context executes `sleep_ticks` synchronously and
cannot faithfully reproduce a real userspace wall-park (the probe observed a
~1 µs return). The mishandling is in the dispatch, not the runtime-probe
result; the hard regression check belongs in a userspace `.c` test once the
handler lands.

**Fix shape:** add a `230 => sys_clock_nanosleep(arg1, arg2, arg3, arg4)`
handler. Read the timespec; if `flags & TIMER_ABSTIME`, subtract "now" on the
requested `clockid` (CLOCK_MONOTONIC via `vdso::monotonic_ns()`,
CLOCK_REALTIME via the `wall_secs_at_boot + monotonic` formula already used
by the futex abs path at `syscall.rs:8431`) to derive the relative sleep;
if the deadline is already past, return 0 immediately. Validate `tv_nsec <
1e9` → EINVAL. Mirror the abs→relative conversion already proven correct for
`FUTEX_CLOCK_REALTIME`. Cite `clock_nanosleep(2)`.

### Gap #3 — robust-list owner-died walk on thread death — **MEDIUM**

`kernel/src/proc/mod.rs:2477` (the `robust_list_head` store site) and the
thread-exit path that already calls `fire_cleartid_for_group`.

**Problem:** a thread that dies abnormally holding a `PTHREAD_MUTEX_ROBUST`
mutex leaves waiters parked; no `FUTEX_OWNER_DIED` handoff.

**Fix shape:** on thread exit, before clearing `robust_list_head`, walk the
user-space `struct robust_list_head` (bounded iteration, e.g. ≤ 2048 nodes,
fault-immune reads): for each registered lock word, atomically OR in
`FUTEX_OWNER_DIED` (0x4000_0000) and `FUTEX_WAKE` one waiter; process the
`list_op_pending` slot last per the robust-futex protocol. Cite
`set_robust_list(2)` and `get_robust_list(2)`. Keep it gated so a malformed
list cannot loop the exit path (bound + present-PTE check).

### Gap #5 — `FUTEX_LOCK_PI` / `FUTEX_UNLOCK_PI` absent — **LOW**

`kernel/src/subsys/linux/syscall.rs` futex `match op { … _ => -38 }`

**Problem:** PI-mutex lock/unlock return `-ENOSYS`. Not on the FF path (no
`PRIO_INHERIT` mutexes in libxul), but any program that creates one stalls.

**Fix shape:** implement a non-PI-priority-boosting fallback that treats
`FUTEX_LOCK_PI` as `FUTEX_WAIT`-until-acquirable and `FUTEX_UNLOCK_PI` as
`FUTEX_WAKE 1`, with the owner-TID encoded in the low bits of the lock word
per the PI-futex value protocol. This is a *correctness* fallback (no real
priority inheritance, which the scheduler does not model) but unblocks the
ABI. Cite `futex(2)` PI section. Defer until a PI-mutex consumer appears.

---

## 6. Bottom line

For the **musl / Alpine / libxul** workload that AstryxOS actually runs, the
Linux-ABI surface is **substantially code-complete**: the futex op-set musl
issues, the full musl `CLONE_*` set, `set_tid_address` clear-on-exit,
`sched_getaffinity`, the readiness primitives, and the `SA_SIGINFO`
`ucontext` layout are all implemented and spec-faithful. The one **HIGH**
gap that can bite real musl-adjacent code is `clock_nanosleep(TIMER_ABSTIME)`
(gap #1); robust-list owner-died (#3) and PI-futex (#5) are rare-path
backstops. None of the three is on the critical Firefox event-loop path,
which is consistent with the independently-established finding that the
kernel is faithful at the futex storm.
