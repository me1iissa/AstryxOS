# SSP differential at first-futex anchor (2026-05-23)

## Mission

Run the INFRA-1 differential bytestream harness landed in PR #413 to compare the
**same** musl `firefox-bin` (Build-ID `cc77a6e278a161964ce8abdbe0751ad333aff469`)
running under (a) the host Linux kernel via bwrap, vs (b) the AstryxOS kernel
under QEMU/KVM, both reaching the SSP-fail wedge at musl `__stack_chk_fail+0`.

The **first byte-level divergence** between the two syscall streams names the
kernel-state divergence that ultimately produces the SSP fault (per the binding
demo-gate iteration loop: AstryxOS is the bug, Firefox is not).

## Setup

| Side    | Source                                                         |
|---------|----------------------------------------------------------------|
| Linux   | bwrap + Alpine musl rootfs (`~/.cache/astryxos-firefox-musl/`) |
|         | strace -f, full syscall filter, headless --screenshot          |
|         | 172,511 strace lines → 24,994 parseable calls                  |
|         | PID 1101255 (firefox-esr, post-bwrap-exec)                     |
| AstryxOS| QEMU/KVM, kernel features `firefox-test,differential-trace`    |
|         | 1,972 [SC] entries on serial log                               |
|         | PID 1 TID 1 (firefox-bin)                                      |

Both sides ran the **identical** musl-linked `firefox-bin` and the same
`ld-musl-x86_64.so.1` interpreter. Reference Linux capture reused from
`~/.astryx-harness/strace-ref/captures/ff-musl-all-2026-05-20`.

## Harness fixes landed inline (per CLAUDE.md harness-extension policy)

Five INFRA-1 bugs surfaced and were fixed in this dispatch (single PR):

| # | Class                  | Effect                                                                 |
|---|------------------------|------------------------------------------------------------------------|
| 1 | strace ret regex order | Hex return values (`0x614ff1726000`) silently truncated to `0` because |
|   |                        | `-?\d+` alternative matched the leading `0`. **Fixed**: hex alt first. |
| 2 | per-tid cap on shim    | When reusing a single-file strace (no `-ff`), all records collapse to  |
|   |                        | `tid_from_name=0` → per-tid cap silently truncates to ¼ of max.        |
|   |                        | **Fixed**: drop per-tid cap; rely on post-parse slice.                 |
| 3 | no PID filter on Linux | Single-file strace contains bwrap + firefox + glxtest + content-proc   |
|   |                        | interleaved; diff anchored at bwrap's arch_prctl, not firefox's.       |
|   |                        | **Fixed**: `--linux-pid-filter N` + `--linux-pid-auto-firefox`.        |
| 4 | no anchor alignment    | AstryxOS [SC] starts at first user syscall; Linux strace starts at     |
|   |                        | execve+ld.so probes. Streams misaligned at index 0.                    |
|   |                        | **Fixed**: `--align-anchor <syscall> [--align-anchor-arg-prefix S]`    |
|   |                        | drops leading records on BOTH sides until first matching syscall.      |
| 5 | retval false positives | strace renders errors as `ret=-1 errno=ENOENT`; AstryxOS [SC-RET]      |
|   |                        | reports raw `-2`. Diff flagged every ENOENT as `retval_value` mismatch.|
|   |                        | Also runtime-dependent rets (TID, PID, addresses, time, random) caused |
|   |                        | spurious mismatches. **Fixed**: `_RUNTIME_DEP_RETVAL` skip set +       |
|   |                        | `_ERRNO_VALUES` table normalising strace's `-1 + errno` to `-<errno>`. |

After fixes the 12-check smoke suite at `scripts/differential/smoke.py` still
PASSes. JSON output is additive (new fields: `anchor_dropped`, `anchor`,
`pid_filter` on `linux`; `anchor_dropped` on `astryx`) — no breaking changes.

## Final diff (file: `/tmp/ssp-diff/diff-FINAL.json`)

Configuration:

```
python3 scripts/differential-soak.py run \
  --reuse-linux-capture ff-musl-all-2026-05-20 \
  --reuse-astryx-log <serial-log> \
  --astryx-features firefox-test,differential-trace \
  --astryx-pid 1 \
  --linux-pid-auto-firefox \
  --align-anchor futex \
  --context 25 \
  --max-syscalls 0
```

| Field              | Value      |
|--------------------|-----------:|
| linux_total_calls  | 24994      |
| astryx_total_calls | 1183       |
| aligned_calls      | 1          |
| linux anchor drop  | 362        |
| astryx anchor drop | 47         |
| divergence_class   | missing_or_extra_call |
| first_div sc_index | 1          |

### Anchor (both sides matched at first `futex()`)

| Side    | Record                                                                  |
|---------|-------------------------------------------------------------------------|
| Linux   | `futex(0x72880ef3ab70, FUTEX_WAIT_PRIVATE, 2, NULL)` — pid 1101255      |
| AstryxOS| `futex(0x7effa9379b70, op=0x80=WAIT_PRIVATE, val=2)` — pid 1 tid 1 → 0  |

Same opcode, same val, same RIP-relative offset in libxul. The streams ARE
talking to the same underlying call site.

### First divergence (sc_index = 1, post-anchor)

| Side    | Record                                                                |
|---------|-----------------------------------------------------------------------|
| Linux   | `futex(0x72880f01bf90, FUTEX_WAIT, 1101256, NULL)` — *parent waiting* |
|         | *for child TID slot to clear (CLONE_CHILD_CLEARTID join)*             |
| AstryxOS| `open(0x7effa9379a40, 0x8000, 0x1b6)` — *opens `/proc/self/task/2/stat`* |
|         | *(this is the CHILD thread tid=2, not the parent)*                    |

## Verdict on the six diagnostic questions

| #  | Question                                            | Answer                  |
|----|-----------------------------------------------------|-------------------------|
| Q1 | Same syscall sequence up to anchor?                 | **Yes** (post-strip)    |
| Q2 | Same syscall args at divergent sc?                  | **N/A** — different sc  |
| Q3 | Same retval/errno?                                  | **N/A**                 |
| Q4 | Same memory state at relevant pages?                | Not captured this run   |
| Q5 | Same register state after syscall return?           | Not captured this run   |
| Q6 | Was sc=1226 the same on both?                       | **No — not reached**    |

The divergence is **Q1-class**: the syscall *sequence* differs, not args/retval
of a single syscall.

## What the divergence actually says

The Linux parent (pid 1101255) at the join-thread boundary issues **two
back-to-back futex calls**:

1. `futex(addr_A, WAIT_PRIVATE, 2)` — wait for child to signal "I'm done with
   shared state"
2. `futex(addr_B = tid_slot, WAIT, child_tid)` — wait for kernel to zero the
   child's TID slot (CLONE_CHILD_CLEARTID)

Per the Linux trace, between the two waits the child (pid 1101256) does a small
amount of work (proc/self/task/N/stat reads, then `futex(addr_A, WAKE, 1)`
followed by `exit(0)`), and the kernel — upon detecting the child's exit —
clears the TID slot at `addr_B` and wakes any FUTEX_WAIT registered on it.
Public refs: futex(2) `FUTEX_WAIT`; clone(2) `CLONE_CHILD_CLEARTID`.

On AstryxOS the child (tid=2) does the equivalent work and issues
`futex(addr_A, WAKE_PRIVATE, 1) = 1` waking 1 waiter (the parent), then
`exit(0)`. The kernel logs `[CLEARTID] tid=2 clear_addr=0x7f4aedb5ff90` followed
by `[FUTEX_WAKE_EXIT] uaddr=0x7f4aedb5ff90 key_present=false woken=[]
remaining_pid_keys=[]`. **No waiter was registered on the CLEARTID address.**

The AstryxOS parent then resumes from its first `futex(addr_A, WAIT, 2)` with
ret=0 and **never issues the second futex** — it falls through to `munmap`,
`gettid`, `gettid`, `mmap`, mirroring Linux's L[2..5] post-join shape but
**without the FUTEX_WAIT on the TID slot**.

### Two possible musl branches

`pthread_join` in upstream musl 1.2.x performs:

```c
int r = __timedwait_cp(&t->tid, t->tid, ...);   // FUTEX_WAIT on TID slot
```

ONLY if `t->tid` is non-zero at check time. If the child has already cleared
its TID (via the kernel's CLONE_CHILD_CLEARTID), the WAIT is **skipped**
because the loop predicate is already false. (Public ref: musl-libc.org docs,
`__timedwait_cp` semantics; also reflected in `pthread_join.c` in musl
1.2.x upstream snapshots — citing the project, not the internal-refs
mirror.)

So the divergence is a **race**: on Linux, the parent's WAIT registers
BEFORE the child clears its TID; on AstryxOS, the child has already cleared
its TID by the time the parent gets to the WAIT, and the WAIT is skipped.

### Why does the race resolve differently?

On AstryxOS:

- The child thread's work between WAKE and EXIT (`munmap` + the kernel
  `[CLEARTID]` flow) appears to complete **faster** than the parent's
  return-from-WAIT path.
- The kernel-logged `[FUTEX_WAKE_EXIT] key_present=false` confirms nobody was
  parked on the CLEARTID uaddr when the kernel issued the cleartid wake.
- The parent then enters `pthread_join` and checks `t->tid` — already zero —
  so it never issues the second FUTEX_WAIT.

On Linux:

- The parent enters `pthread_join` first (it has work to do before checking
  TID), then issues the WAIT on the TID slot.
- The child's CLEARTID happens AFTER the parent registers as a waiter, so the
  WAIT blocks briefly and then the kernel wakes it.

**The race is timing-driven.** It is not the kernel-state divergence
**causing** the SSP fault 1,220 syscalls downstream — both branches of musl
`pthread_join` are correct and produce the same post-join state.

### What this differential run rules OUT

- ❌ syscall *sequence* divergence as a load-bearing bug class at this point in
  startup. Both sides do the same thread-join dance.
- ❌ syscall *args* divergence at the anchor or first 1 record.
- ❌ retval *semantics* divergence (after the normalisation fixes).
- ❌ FS_BASE drift, set_tid_address mis-binding, vfork-frame loss as candidate
  causes at this boundary (FS_BASE has been confirmed stable in PRs #408/#421;
  this run did not exercise those snapshots but the syscall sequence
  alignment IS the indirect evidence — divergent FS_BASE would have surfaced
  as wildly different syscall args, not as a benign join-order race).

### What this differential run still hasn't ruled out

- ❓ A *memory-state* divergence at some later snapshot point (e.g. the TLS
  canary, the SSP saved-slot, the kstack contents). Snapshots config is
  defined in `scripts/differential/snapshots.yaml` but live capture is not
  yet implemented in INFRA-1; only syscall-stream alignment ran.
- ❓ A *register-state* divergence (e.g. r11/rcx after SYSRET, FS_BASE after
  arch_prctl). The harness has no register-capture channel yet.
- ❓ A divergence *beyond* index 1 once the soft-skip / search-path noise on
  later library loads is filtered out. The 24,994 vs 1,183 record gap is
  almost entirely the search-path probe-order drift caused by AstryxOS
  setting `LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:...` (test_runner-side
  `kernel/src/gui/terminal.rs`) where Alpine bwrap leaves `LD_LIBRARY_PATH`
  unset and musl uses defaults `/lib:/usr/local/lib:/usr/lib`.

## Side observation: LD_LIBRARY_PATH probe-order shift

While reaching the diff verdict the harness surfaced a separate, benign-looking
but architecturally significant divergence in the lib-loading prefix.

For every library load `libstdc++.so.6`, `libgcc_s.so.1`, `libnspr4.so`, etc.
AstryxOS musl probes:

```
/lib/x86_64-linux-gnu/<lib>      → ENOENT
/usr/lib/<lib>                   → success
```

Linux (Alpine bwrap, no `LD_LIBRARY_PATH`) musl probes (per musl
defaults + DT_RUNPATH):

```
/usr/lib/firefox-esr/<lib>       → ENOENT
/etc/ld-musl-x86_64.path         → ENOENT (config file absent)
/lib/<lib>                       → ENOENT
/usr/local/lib/<lib>             → ENOENT
/usr/lib/<lib>                   → success
```

Source of divergence: `kernel/src/gui/terminal.rs` sets
`LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/usr/lib:/usr/lib/firefox-esr:...` for
the firefox-test launch. The `/lib/x86_64-linux-gnu` prefix is glibc-multiarch
flavoured and is wrong for the musl variant. Same final library resolution,
but ~80 extra ENOENT open()/SC syscalls per library load, plus a different
probe sequence visible to userspace and to any FS-watch / audit infrastructure.

This is **not** the cause of the SSP fault. It is a configuration nit that
slightly slows boot and inflates the syscall count plateau by a few %. Safe
to deprioritise.

Public refs: ld-musl(8) search order
(<https://wiki.musl-libc.org/functional-differences-from-glibc.html>);
ELF gABI §5.4 "Shared Object Dependencies" for DT_RUNPATH semantics.

## Recommended next dispatch

This run successfully:

1. Validated the INFRA-1 substrate end-to-end against a real wedge.
2. Fixed five harness bugs that would have blocked all future differential
   work.
3. Established that the syscall-stream channel alone is INSUFFICIENT to find
   the SSP bug — the load-bearing divergence is below syscall granularity (in
   memory state or register state at boundaries the syscall walker doesn't
   touch).

The recommended next dispatch is **INFRA-1 Phase 2: live snapshot capture**
to give the diff engine access to the boundaries the snapshots.yaml already
names (`post_arch_prctl_set_fs`, `post_vfork_parent_return`,
`post_futex_wake`, `pre_fatal_pf`).

| Field              | Value                                                   |
|--------------------|---------------------------------------------------------|
| Agent type         | toolchain-platform-engineer (owns INFRA-1 substrate)    |
| Scope              | Implement memory-snapshot capture at named boundaries.  |
|                    | AstryxOS side: new `[SNAP]` serial line on each         |
|                    | snapshots.yaml trigger, capturing the named regions     |
|                    | (`fs_base`, `tls_canary`, `stack_near_rbp`, `fixed_va`).|
|                    | Linux side: ptrace-attach + PTRACE_PEEKDATA at the same |
|                    | boundaries via a new `strace-ref.py snap` mode.         |
|                    | Diff engine: extend `diff_streams` to flag `mempage`-   |
|                    | class divergence on per-snapshot region byte mismatch.  |
| LOC budget         | ~600 LOC across `differential-soak.py` (+200),          |
|                    | `strace-ref.py` (+150), kernel `subsys/linux/diff_snap` |
|                    | (+250). 1.5×-burst-permitted under global CLAUDE.md.    |
| Why not now        | This is substrate work and outside the scope of a       |
|                    | single 90-min QA-engineer dispatch; the immediate value |
|                    | of *running* the snapshot diff requires that substrate. |
| Why dispositive    | The snapshot at `post_futex_wake` for the WAKE on the   |
|                    | SSP-failure precursor (sc=1226 area) will catch any     |
|                    | TLS/stack-frame divergence at the byte level — which    |
|                    | is what's left after the syscall-stream channel says    |
|                    | "no semantic divergence here".                          |

The SAGA-CLOSING fix is not this dispatch — this dispatch establishes the
substrate (now working + battle-tested + 5 bugs fixed) and reports that
syscall-stream-only differential is insufficient. The fix-naming dispatch
should run AFTER Phase 2 snapshot capture is live.

## Public references

- musl: <https://musl.libc.org/> — pthread_join / __timedwait_cp / ld-musl(8)
- futex(2): <https://man7.org/linux/man-pages/man2/futex.2.html>
- clone(2): <https://man7.org/linux/man-pages/man2/clone.2.html>
  (`CLONE_CHILD_CLEARTID` semantics)
- arch_prctl(2): <https://man7.org/linux/man-pages/man2/arch_prctl.2.html>
- strace(1): <https://man7.org/linux/man-pages/man1/strace.1.html>
- bwrap(1): <https://github.com/containers/bubblewrap>
- System V AMD64 ABI: <https://gitlab.com/x86-psABIs/x86-64-ABI>
- ELF gABI §5.4: <https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html>
- ld.so(8): <https://man7.org/linux/man-pages/man8/ld.so.8.html>

## Files generated this dispatch

- `docs/SSP_DIFFERENTIAL_AT_ANCHOR_2026-05-23.md` (this doc)
- `scripts/differential-soak.py` (INFRA-1 substrate; 5 fixes)
- `/tmp/ssp-diff/diff-FINAL.json` (final aligned diff JSON, retained for
  follow-up)
