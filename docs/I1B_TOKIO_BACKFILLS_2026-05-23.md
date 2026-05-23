# I1b — tokio syscall backfills (2026-05-23)

Status: implemented; test 271 PASS on `--features test-mode` KVM boot.

## Dispatch context

I1b is the second half of a two-phase TLS-substrate enablement.  I1a (in
flight) handles the userspace side (libssl/libcrypto/ca-certs/openssl CLI);
I1b covers the kernel-side syscall residuals that the tokio runtime exercises
during start-up.

The INFRASVC oracle audit (commit `5b54613`) measured the tokio syscall
surface against current AstryxOS state and concluded ~95% plumbed post
PR #298 (musl ABI), PR #305 (musl FF), PR #320 (Linux ABI sysinfo/getrusage/
procfs status).  I1b's job was to **measure the residual 5%**, implement the
named gaps, and stop.

## Phase 1 — measured residual

Static audit of `kernel/src/subsys/linux/syscall.rs` against the audit's
named tokio-relevant syscall list:

| sc  | name                | status pre-I1b                    |
|-----|---------------------|-----------------------------------|
| 24  | `sched_yield`       | present                           |
| 157 | `prctl`             | present (`PR_SET_*` / `PR_GET_*` mostly covered) |
| 230 | `clock_nanosleep`   | present (delegates to `sys_nanosleep_linux`) |
| 232 | `epoll_wait`        | present (wake-on-readiness via poll bell) |
| 233 | `epoll_ctl`         | present                           |
| 281 | `epoll_pwait`       | present (sigmask accepted-and-ignored) |
| **282** | `signalfd` (legacy) | **MISSING** — falls through to `_ => -38` |
| 283 | `timerfd_create`    | present                           |
| 284 | `eventfd` (legacy)  | present                           |
| 286 | `timerfd_settime`   | present                           |
| 287 | `timerfd_gettime`   | present                           |
| 289 | `signalfd4`         | present                           |
| 290 | `eventfd2`          | present                           |
| 291 | `epoll_create1`     | present                           |
| 297 | `rt_tgsigqueueinfo` | present                           |
| 302 | `prlimit64`         | present (self only — fine for tokio) |
| 318 | `getrandom`         | present (GRND_NONBLOCK / GRND_RANDOM / GRND_INSECURE) |
| 324 | `membarrier`        | present (all 7 cmd bits) |
| **424** | `pidfd_send_signal` | returns `-38` already (explicit) |
| **434** | `pidfd_open`        | **MISSING** — falls through to `_ => -38` |
| **441** | `epoll_pwait2`      | **MISSING** — falls through to `_ => -38` |

Two of the three "missing" entries fell through to the catch-all
`Unknown Linux syscall: {}` log line at line 4643, which is functionally
ENOSYS but flags as a serial-log surprise on every call (tokio's reactor
issues `epoll_pwait2` on every poll cycle on Linux 5.11+ kernels — that
would have flooded the log).  Making them explicit silences the surprise
log and either gives the right answer (sc 282, 441) or returns the
documented-pre-Linux-5.3 ENOSYS that tokio's pidfd-feature-probe path
already handles (sc 434).

Audit was also vague on one ABI hardening item I noticed in passing:

| arm                  | status pre-I1b                                |
|----------------------|-----------------------------------------------|
| `prctl(PR_GET_NAME)` | Wrote 7 bytes (`"astryx\0"`) without range-checking the user pointer.  Same CWE-822/CWE-823 shape called out on the `PR_GET_CHILD_SUBREAPER` / `PR_GET_PDEATHSIG` arms that already use `validate_user_ptr`. |

I included the fix because the per-process audit pattern was already
established on adjacent arms and matching it costs ~10 LOC.

## Phase 2 — additions

`kernel/src/subsys/linux/syscall.rs` (+78 production LOC):

1. **`282 signalfd(fd, *mask, sizemask)`** — wraps `sys_signalfd4(fd, mask,
   sizemask, 0)`.  Per signalfd(2): "signalfd() was added to Linux in
   kernel 2.6.22; signalfd4() supports a flags argument."  Functionally
   identical to signalfd4 with flags=0.

2. **`441 epoll_pwait2(epfd, events, maxevents, *timespec, *sigmask,
   sigsetsize)`** — bounds-checks the user-supplied `struct timespec *`,
   converts to whole milliseconds rounded up (matching our 100 Hz tick
   resolution), and delegates to `sys_epoll_wait`.  Sigmask accepted-and-
   ignored as on sc 281.  Per epoll_pwait2(2) (Linux 5.11+): "Compared to
   epoll_pwait, ... it allows for sub-millisecond precision via a struct
   timespec timeout."

3. **`434 pidfd_open(pid, flags)`** — explicit ENOSYS log line.  Per
   pidfd_open(2) NOTES: callers must handle ENOSYS on pre-5.3 kernels;
   tokio's `tokio::process::Child::wait` and `signal::ctrl_c` reactors
   take the kill(2) + waitpid(2) + signalfd fallback path on ENOSYS,
   all of which are plumbed.

4. **`424 pidfd_send_signal`** — already returned `-38`, added a comment
   block explaining the tokio fallback.

5. **`prctl(PR_GET_NAME)`** — now validates `arg2` with `validate_user_ptr(arg2, 16)`,
   returns `-EFAULT` on NULL or unmapped, writes exactly 16 NUL-padded
   bytes per prctl(2) ("The buffer should allow space for up to 16 bytes;
   the returned string will be null-terminated").

## Phase 3 — validation

Added `test_271_tokio_syscall_backfills` (`kernel/src/test_runner.rs`,
+213 LOC), gated on `test-mode` or `firefox-test`.  Four sub-cases:

- 271-A: `signalfd(-1, &mask, 8)` returns a valid fd; `signalfd(-1, &mask, 4)` returns -EINVAL.
- 271-B: `epoll_pwait2(epfd, ts={0,0})` returns 0 on empty set; negative `tv_nsec` returns -EINVAL.
- 271-C: `pidfd_open(1, 0)` returns -38.
- 271-D: `PR_GET_NAME(NULL)` returns -EFAULT; `PR_GET_NAME(buf16)` writes `"astryx\0"` + 9 NUL pad.

### KVM result (test-mode)

```
[PASS] tokio I1b backfills: signalfd / epoll_pwait2 / pidfd_open
[TEST-JSON] {"name":"tokio I1b backfills: signalfd / epoll_pwait2 / pidfd_open","result":"pass","elapsed_ticks":8}
Test Results: 288/296 passed
```

The 8 failures are pre-existing (Musl hello / TCC compile / sigchld /
ascension / glibc_hello — all `Cannot read /disk/bin/<X>: NotFound`,
i.e. data.img staging gaps; plus execve_leak and monotonic-rate, both
known-flaky on KVM per the `--allow-fail` list at
`scripts/qemu-harness.py:1741`).  Test 271 itself is a clean PASS.

## Outcome vs. audit prediction

Audit predicted ~50-150 LOC residual.  Actual: 78 production LOC.
Audit prediction was accurate — within band.

## What's NOT done (out of scope)

- **Real pidfd object**.  Implementing pidfd_open + pidfd_send_signal +
  waitid(P_PIDFD) properly requires a new VFS file-type and lifetime
  binding to the process slot.  Tokio takes the documented kill(2) +
  waitpid(2) fallback on ENOSYS, so this is not blocking.  Defer until
  a userland actually needs pidfd semantics (e.g. systemd's
  `PidfdsAreUsable` probe).
- **rseq**.  Tokio reads `auxv[AT_HWCAP]` and rseq-related entries; per
  the audit (line 134) the existing stub-returns-0 behaviour is fine.
- **Multi-PID `prlimit64`**.  Tokio queries `RLIMIT_NOFILE` / `RLIMIT_STACK`
  on self only.  Other-PID prlimit64 is not used and would require a
  ptrace-style cross-process credential check; deferred.

## Refs

- POSIX-1.2017 `<signal.h>`, `<sys/epoll.h>`, `<sys/prctl.h>`
- `signalfd(2)`, `signalfd4(2)`, `epoll_pwait2(2)`, `pidfd_open(2)`,
  `pidfd_send_signal(2)`, `prctl(2)`
- kernel.org/Documentation/admin-guide/syscalls.html
- Intel SDM Vol. 3A §4.6.1 (SMAP), CWE-822/CWE-823 (untrusted-pointer
  deref / out-of-range pointer offset)
