# FUTEX_WAKE_EXIT — AstryxOS-vs-Linux ABI compare cycle

**Date**: 2026-05-23
**Author**: abi-compatibility-engineer
**Status**: Compare-cycle output. No kernel code changes recommended in this
pass — see "Recommended next step" below.
**Trigger**: New demo gate after PR #400 (STACK_CANARY closure, commit
`c9ca911`). `qa-engineer` retry verdict flagged `[FUTEX_WAKE_EXIT]` as the new
plateau marker on musl Firefox at sc≈826.

## TL;DR

`[FUTEX_WAKE_EXIT]` is **not** a Linux syscall, an op-code, or a fault — it is
an AstryxOS-internal serial diagnostic emitted by
`kernel/src/syscall/mod.rs::futex_wake_for_exit` (lines 1870-1919) immediately
after the kernel finishes the CLEARTID-time FUTEX_WAKE that
`set_tid_address(2)` makes mandatory at thread exit. The line records the
*outcome* of that wake (key present?, threads woken, remaining keys for this
PID). Live capture on the master tip confirms the implementation is
spec-conformant: the post-`[FUTEX_WAKE_EXIT]` execution proceeds normally and
the wedge is downstream.

| | AstryxOS | Linux |
|---|---|---|
| `set_tid_address(2)` exit-time write | implemented (`proc::exit_thread`, lines 1258-1287) | spec |
| Exit-time `FUTEX_WAKE` with `nr_wake=1` | implemented (`futex_wake_for_exit`) | spec |
| Wake errors ignored (per `set_tid_address(2)`) | yes — `key_present=false` is a no-op | spec |
| `[FUTEX_WAKE_EXIT]` serial diagnostic | yes (firefox-test feature only) | no analogue |
| Robust-list walk on thread exit | **NOT implemented** — see below | walks list, OR-in `FUTEX_OWNER_DIED`, FUTEX_WAKE held mutexes |

The single **real ABI gap** named in this cycle is the robust-list walk. It is
known and self-documented in `kernel/src/syscall/mod.rs:2828-2832`. There is
no evidence it is the post-#400 plateau cause.

## 1. What FUTEX_WAKE_EXIT means on AstryxOS

### Source-of-truth callsite

```
kernel/src/syscall/mod.rs
  1870   /// Wake futex waiters from the exit path (CLONE_CHILD_CLEARTID).
  1871   /// This is called from proc::exit_thread when a thread with
  1872   /// clear_child_tid exits.
  1873   pub fn futex_wake_for_exit(pid: u64, uaddr: u64, max_wake: u64) {
  ...
  1905       crate::serial_println!(
  1906           "[FUTEX_WAKE_EXIT] pid={} uaddr={:#x} key_present={} \
                                    woken={:?} remaining_pid_keys={:?}",
  1907           pid, uaddr, key_present, tids_to_wake, other_keys
  1908       );
```

### Producer site

`futex_wake_for_exit` has exactly two producers, both at thread/process death:

| Site | Source | Purpose |
|---|---|---|
| Per-thread CLEARTID | `kernel/src/proc/mod.rs:1258-1287` (`exit_thread`) | Thread exits, `clear_child_tid != 0`. Honour the per-thread CLEARTID protocol. |
| Process-wide CLEARTID-on-group-exit | `kernel/src/proc/mod.rs:2191-2308` (`exit_group_cleartid_all_threads`) | Whole process exits via SIGKILL/exit_group; every thread still owes its individual CLEARTID write+wake. |

Both producers are spec-mandated by POSIX `clone(2)` ("`CLONE_CHILD_CLEARTID`")
and `set_tid_address(2)`. The diagnostic line is feature-gated under
`firefox-test` and prints **once per exit-time wake** (per thread), so it
amplifies along with thread-exit storms during Firefox's content-process
spawn flurries.

### Field semantics

`pid`           — the dying thread's PID (process ID).
`uaddr`         — the user VA registered via `set_tid_address(2)` or
                  `CLONE_CHILD_CLEARTID`. Glibc/musl set this to the TCB
                  `tid` slot so `pthread_join` can `FUTEX_WAIT` on it.
`key_present`   — was there a registered futex waiter on `(pid, uaddr)`?
                  Both `true` and `false` are legal outcomes — see §2.
`woken`         — list of TIDs woken (≤ `max_wake = 1` in this caller).
`remaining_pid_keys` — other `(pid, _)` keys still parked in
                  `FUTEX_WAITERS`. Used to diagnose stale entries.

### Captured outcome on master tip (`c9ca911`, post-#400)

```
[CLEARTID] tid=3 pid=1 clear_addr=0x7fb56229af90
[CLEARTID] tid=3 cr3=0x12119000
[FUTEX_WAKE_EXIT] pid=1 uaddr=0x7fb56229af90 \
                  key_present=false woken=[] remaining_pid_keys=[]
[SC-RET] pid=1 tid=2 nr=11 ret=0x0   ← execution continues
...                                    sc climbs 31 → 807, plateaus
```

`key_present=false` means: tid=3 exited holding a registered
`clear_child_tid`, but no other thread was parked in `FUTEX_WAIT` on that
address. So the kernel correctly performed the `nr_wake=1` futex op as a
no-op, ignored the "no waiter" outcome, and continued teardown. This is the
spec-conformant path (see §2).

## 2. What Linux does at the equivalent point

### `set_tid_address(2)` — public spec text

From `man 2 set_tid_address` (Linux man-pages 6.10):

> When a thread whose `clear_child_tid` is not NULL terminates, then, if the
> thread is sharing memory with other threads, then 0 is written at the
> address specified in `clear_child_tid`, and the kernel performs the
> following operation:
>
>     futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
>
> The effect of this operation is to wake a single thread that is performing
> a futex wait on the memory location. **Errors from the futex wake operation
> are ignored.**

(Emphasis added — this is exactly the path `[FUTEX_WAKE_EXIT]` reports on.)

### `clone(2)` — CLONE_CHILD_CLEARTID

From `man 2 clone` (Linux man-pages 6.10):

> `CLONE_CHILD_CLEARTID` (since Linux 2.5.49)
>     Clear (zero) the child thread ID at the location pointed to by
>     `child_tid` (`clone()`) or `cl_args.child_tid` (`clone3()`) in child
>     memory when the child exits, and do a wakeup on the futex at that
>     address. The address involved may be changed by the
>     `set_tid_address(2)` system call. **This is used by threading libraries.**

### Conclusion for §2

AstryxOS's `futex_wake_for_exit` performs exactly the operation `set_tid_address(2)` mandates:

```
futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
```

— with the same "errors are ignored" behaviour (the `key_present=false` arm
returns immediately without setting an error code in the caller). **No
divergence on the CLEARTID + FUTEX_WAKE-on-exit pair.**

## 3. The one real ABI gap: robust-list walk at thread exit

This is **not** what `[FUTEX_WAKE_EXIT]` reports on, but it is the only
adjacent area where AstryxOS diverges from Linux exit-time futex semantics,
and any abi-compat audit triggered by an exit-path gate must name it.

### Public spec — `set_robust_list(2)` + futex(2)

From `man 2 set_robust_list` (Linux man-pages 6.10):

> If a thread accidentally fails to unlock a futex before terminating or
> calling `execve(2)`, another thread that is waiting on that futex is
> notified that the former owner of the futex has died. The notification
> consists of two pieces: the `FUTEX_OWNER_DIED` bit is set in the futex
> word, and a `FUTEX_WAKE` operation is performed on one waiting thread.

From kernel.org `Documentation/robust-futex-ABI.txt`:

> On exit, the kernel will consider the address stored in `list_op_pending`
> and the address of each `lock word` found by walking the list starting at
> `head`. For each such address, if the bottom 30 bits of the `lock word` at
> offset `offset` from that address equals the exiting thread's TID, then
> the kernel will do two things: 1) if bit 31 (`0x80000000`) is set in that
> word, then attempt a futex wakeup on that address ... and 2) atomically
> set bit 30 (`0x40000000`) in the `lock word`.

The walk must silently stop on three error conditions (invalid head pointer,
invalid lock-word address, more than 1 million entries).

### AstryxOS state

```
kernel/src/subsys/linux/syscall.rs
  2828   // 273: set_robust_list(head, len)
  2829   // Store head pointer + length in the calling thread for later
  2830   // retrieval.  The kernel only uses this during thread death (to
  2831   // mark locked mutexes as abandoned), which we don't implement, but
  2832   // we must store it so that get_robust_list returns the same values
  2833   // (glibc consistency check).
```

And:

```
kernel/src/proc/mod.rs
  2218   /// stores `robust_list_head` as an opaque user pointer and never
  2219   /// walks it in normal operation (the slot is round-tripped for
  2220   /// `get_robust_list(2)` only).  We simply zero the slot at exit
```

`set_robust_list(2)` / `get_robust_list(2)` (syscalls 273/274) store and
round-trip the head pointer but the kernel does **not**:

1. Walk `robust_list_head` at thread exit.
2. Walk `list_op_pending` at thread exit.
3. Set the `FUTEX_OWNER_DIED` bit (`0x40000000`) on lock-words owned by the
   exiting TID.
4. Perform `FUTEX_WAKE` on lock-words with bit 31 (`0x80000000`) set.

### Symptom signature when this matters

A waiter parked in PTHREAD_MUTEX_ROBUST mode whose owner thread died without
unlocking will block **forever** on AstryxOS. On Linux the waiter receives
`EOWNERDEAD` from `pthread_mutex_lock()` (per `pthread_mutexattr_setrobust(3)`
- POSIX 2017 §2.9.6) and can call `pthread_mutex_consistent()` to recover.

### Diagnostic distinguisher from `[FUTEX_WAKE_EXIT]`

`[FUTEX_WAKE_EXIT]` is the single CLEARTID-target wake (one user VA, one TID
slot). A robust-list walk would be many wakes across an arbitrary list of
lock-words, each accompanied by an OR-in of `0x40000000`. The two paths do
not overlap in observable serial output.

## 4. Recommended next step

### Do NOT change `futex_wake_for_exit` in this cycle

The captured behaviour is spec-conformant. Adding "fix the FUTEX_WAKE_EXIT
wedge" work would be tilting at the diagnostic line, not the wedge. The
`sc=807` plateau on master tip is downstream — a tight mmap (nr=9) / munmap
(nr=11) / futex (nr=202) loop on tid=2 after tid=3's exit. That is the
correct next-cycle target.

### Cheap diagnostic-quality wins (≤ 30 LOC, optional)

1. **Add a `key_resolved` counter** to the `[FUTEX_WAKE_EXIT]` line that
   distinguishes "no waiters at all" from "waiters exist on this PID but
   not on this uaddr" (i.e. show `remaining_pid_keys.len()` always, not
   just when empty). The current line already does this via
   `remaining_pid_keys` — verify there isn't a redaction step that drops
   it on long lists.
2. **`[ROBUST_LIST]` non-emission marker** — when a thread exits with
   `robust_list_head != 0`, emit a one-line warning naming the unwalked
   head address. This costs nothing on default builds (feature-gated to
   `firefox-test`) and makes any future robust-mutex-EOWNERDEAD wedge
   immediately searchable.

### Real ABI work (defer to a dedicated cycle)

Implementing the robust-list walk is well-bounded but non-trivial: ~80-150
LOC in a new `proc::robust_list_exit_walk(thread)` helper, called from both
`exit_thread` (per-thread) and `exit_group_cleartid_all_threads` (process
death). Citations: `Documentation/robust-futex-ABI.txt`, `set_robust_list(2)`,
POSIX 2017 §2.9.6 (`pthread_mutexattr_setrobust`). Walk-safety constraints:

- All user reads must be `read_u64_from_user` (validate per-step against
  the VMA list — the head can be an arbitrary user pointer).
- Cap iterations at 1,048,576 per kernel.org spec.
- Silently stop on any fault — do **not** raise EFAULT or kill the process;
  the spec says stop scanning.
- Use the same write-via-CR3 helper as the CLEARTID path
  (`syscall::write_u32_to_user`) so the `FUTEX_OWNER_DIED` OR is performed
  through the dying thread's CR3 even after schedule-out.

There is no evidence this is the current demo blocker. Stage it as an
opportunistic ABI-conformance improvement, not a wedge fix.

## Citations (public-spec only)

- `set_tid_address(2)` — Linux man-pages 6.10 — <https://man7.org/linux/man-pages/man2/set_tid_address.2.html>
- `clone(2)` — Linux man-pages 6.10 — <https://man7.org/linux/man-pages/man2/clone.2.html> §CLONE_CHILD_CLEARTID
- `set_robust_list(2)` / `get_robust_list(2)` — Linux man-pages 6.10 — <https://man7.org/linux/man-pages/man2/set_robust_list.2.html>
- `futex(2)` — Linux man-pages 6.10 — <https://man7.org/linux/man-pages/man2/futex.2.html>
- Linux kernel docs — `Documentation/robust-futex-ABI.txt` — <https://www.kernel.org/doc/Documentation/robust-futex-ABI.txt>
- POSIX.1-2017 — `pthread_mutexattr_setrobust` — <https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_mutexattr_setrobust.html>
