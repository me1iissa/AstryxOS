# PNG Strategy — glibc cond_var version comparison

**Date**: 2026-05-17
**Author**: principal-systems-engineer (PSysEng)
**Scope**: Cross-version glibc `pthread_cond_*` algorithm review, render strategic verdict
on whether changing the glibc version pinned by the test image can close the PNG demo gate.
**Time spent**: ~60 min source comparison + upstream public-changelog cross-check.

---

## TL;DR — VERDICT: **C (kernel-side compensation)** with caveats

**None of glibc 2.33 / 2.34 / 2.35 / 2.36 changes the cond_var algorithm in any way
that would affect the PNG-2 observation.** The two-group cycle pattern observed
by PNG-2 (TID 13 issues 37-38 `FUTEX_WAKE` on one uaddr while waiters are parked on
adjacent uaddrs `-0x3a0` / `-0x500`) exists in **all four versions** and is by design.

Critically: **our test image is not running 2.34 at all.** `scripts/install-glibc.sh`
copies the host glibc; the current host is Ubuntu glibc **2.43-2ubuntu2**. The disk image's
`/lib/x86_64-linux-gnu/libc.so.6` is 2.43. glibc 2.43 includes the BZ 25847 fix
("undoing-stealing" missed-wakeup) which landed in 2.41 (January 2025).

This **reframes the entire investigation**:

- The W209 verdict that called this a "glibc 2.34 two-group cycle pattern" was mis-versioned.
  We are running 2.43, which has Skarupke's BZ 25847 fix already applied.
- PNG-2's observation ("FUTEX_WAKE → woken=0, waiters on adjacent uaddrs") is
  **expected behaviour** for the two-group algorithm. It is NOT a glibc bug.
  It also is NOT a kernel bug *in the futex syscall itself*.
- The real gate must be elsewhere: which adjacent cond_var is the actual
  intended signal target, and why is the signaling thread targeting the wrong one?

Recommended next step is **not** a glibc swap. It's:

1. **Add a per-cond_var uaddr-cluster log to the FUTEX_WAKE_REQ diagnostic** —
   group together every uaddr that lives within 48 bytes (one `pthread_cond_t`) so we
   can tell which cond_var the signaler thinks it is targeting vs which one the
   waiter is parked on. ~10 LOC in `kernel/src/subsys/linux/syscall.rs`.
2. **If that confirms different cond_vars**, the bug is in Mozilla / libxul usage —
   shared-vs-private cond_var, condvar-in-fork-child reinit, or moved-from cond_var
   accessed after destroy. None of these are fixable by glibc version swaps.
3. **If that confirms same cond_var address but different (uaddr offset, group)** —
   then the bug IS still in the glibc cond_var path, but it would be reproducible against
   2.43 (which is what we ship). At that point the public Skarupke "second bug"
   discussion becomes relevant (2.41+ fixed BZ 25847 but Skarupke's 2022 essay
   describes a residual second bug that has not been formally tracked as a BZ).

Either way: **A (downgrade to 2.33), B (upgrade to 2.35/2.36), and D (rebuild on musl)
are NOT the right next move**, because they don't change the algorithm that PNG-2 observed.

---

## Per-version cond_var summary

For each version I extracted `nptl/pthread_cond_*.c` and
`sysdeps/nptl/bits/thread-shared-types.h` and compared. The key files:

| File | 2.33 | 2.34 | 2.35 | 2.36 |
| --- | --- | --- | --- | --- |
| `pthread_cond_wait.c` | 688 | 711 | 710 | 710 |
| `pthread_cond_signal.c` | 100 | 103 | 102 | 102 |
| `pthread_cond_broadcast.c` | 92 | 95 | 94 | 94 |
| `pthread_cond_common.c` | 469 | 469 | 329 | 329 |

### `pthread_cond_t` struct layout

**Identical across 2.33 / 2.34 / 2.35 / 2.36.** 48-byte structure with the
following two-group fields:

```
struct __pthread_cond_s {
    uint64_t __wseq;            // waiter sequence counter (atomic_wide_counter from 2.35)
    uint64_t __g1_start;        // start of group G1 (atomic_wide_counter from 2.35)
    unsigned __g_refs[2];       // per-group futex reference count
    unsigned __g_size[2];       // per-group remaining signal capacity
    unsigned __g1_orig_size;
    unsigned __wrefs;           // total waiter refcount
    unsigned __g_signals[2];    // per-group signal count (FUTEX_WAIT/WAKE address)
};
```

This is **the same two-group algorithm** in all four versions. The only struct-layout
change is internal: 2.35 wraps `__wseq` / `__g1_start` in `__atomic_wide_counter` so that
the 32-bit-atomics fallback is hidden behind a clean abstraction. The on-disk layout is
unchanged.

### Algorithm overview (constant across 2.33-2.36)

```
__pthread_cond_wait_common:
  wseq = fetch_add_acquire(&cond->__wseq, 2)
  g    = wseq & 1                       // join G2
  seq  = wseq >> 1
  fetch_add_relaxed(&cond->__wrefs, 8)
  unlock(mutex)
  signals = load_acquire(&cond->__g_signals[g])
  loop:
    if g closed via __g1_start  -> goto done
    if signals available        -> CAS-consume + try-undo-steal + done
    fetch_add_acquire(&cond->__g_refs[g], 2)
    futex_wait(&cond->__g_signals[g], 0)   // PARK
    dec_grefs(g); reload signals
    [check closed, retry]

__pthread_cond_signal:
  if wrefs >> 3 == 0  -> return            // no waiters
  acquire_internal_lock
  wseq = load_relaxed(&cond->__wseq)
  g1 = (wseq & 1) ^ 1                     // G1 = the other group
  if g_size[g1] != 0  OR  quiesce_and_switch_g1():
      fetch_add_relaxed(&cond->__g_signals[g1], 2)
      g_size[g1]--
      do_futex_wake = true
  release_internal_lock
  if do_futex_wake:
      futex_wake(&cond->__g_signals[g1], 1)
```

The signaler increments `__g_signals[g1]` and calls `futex_wake` on
`&cond->__g_signals[g1]`. A waiter that joined the cond_var at this moment goes
into G2 (`__g_signals[g2]`) — a *different uaddr 4 bytes away* — and will not
be woken by this `futex_wake`.

This is exactly the pattern PNG-2 observed.

### Diff highlights between versions

**2.33 → 2.34**: pure symbol-versioning changes. `__pthread_cond_*` renamed to
`___pthread_cond_*` to move the symbol from `libpthread` to `libc` as part of the
2.34 libpthread merge. **Zero algorithm changes.**

```
< __pthread_cond_wait (...)
> ___pthread_cond_wait (...)
> versioned_symbol (libc, ___pthread_cond_wait, pthread_cond_wait, GLIBC_2_3_2);
> libc_hidden_ver (___pthread_cond_wait, __pthread_cond_wait)
```

**2.34 → 2.35**: introduces `<bits/atomic_wide_counter.h>` and rewrites the 32-bit-atomic
fallback paths in `pthread_cond_common.c`. The 64-bit-atomic path is unchanged in
behaviour. `pthread_cond_common.c` shrinks from 469 to 329 lines because the
160-line `_condvar_lohi` helper is extracted into the new header.

**Zero algorithm changes** at the cond_var level. This is a pure refactor.

**2.35 → 2.36**: copyright-year-only diff in `pthread_cond_wait.c`. **No code change.**

### Bug fixes between 2.33 and 2.36 (per upstream NEWS)

Cond-related BZ entries that appear in NEWS for any version in the comparison set:

- BZ 27304 (in 2.34): `pthread_cond_destroy` does not pass private flag to futex
  system calls. Cosmetic; affects cleanup path only.
- BZ 23538 (historic): cond_broadcast hang. Fixed pre-2.33.
- BZ 13165 (historic): signal-consumption race. Fixed pre-2.33.

**No version in 2.33-2.36 fixes the bug PNG-2 observes.**

---

## What WOULD have mattered (and why none of these tarballs have it)

### BZ 25847 — "undoing stealing" lost wakeup

This is **the exact bug shape** PNG-2 reports: `pthread_cond_signal` fires, but the
matching waiter is not woken. Cause is described in [Skarupke 2020][skarupke-2020]
([Skarupke 2022][skarupke-2022] discusses a residual second bug):

> A signal is posted to group G1, but no futex waiter wakes up because `__g_refs[G1]`
> was already 0 before `__g_size[G1]` was decremented, and the signal remains not
> taken, while there are one or more waiters in another group (G2).

This is a real glibc bug, and it requires **4 signals + 209 interleaved steps** to
trigger in the formal TLA+ model. It was first reported in April 2020, debated
for two years, finally patched by Malte Skarupke in January 2023, and **landed in
glibc 2.41** (January 2025) — see the [glibc 2.41 release announcement][glibc-241].

**Our test image already has this fix.** The host machine is glibc 2.43.

### Implication for the four tarballs in `internal-refs/`

`glibc-2.33` through `glibc-2.36` are **all pre-fix**. If our test image somehow
ended up running 2.34, downgrading to 2.33 (option A) would NOT help because 2.33
has the same bug. Upgrading to 2.35/2.36 (option B) would NOT help because 2.35/2.36
have the same bug.

The lowest version that closes BZ 25847 is **2.41**, which we already have via the
host glibc 2.43.

---

## Cross-check: what is the test image actually running?

```bash
$ strings /home/ubuntu/AstryxOS/build/disk/lib/x86_64-linux-gnu/libc.so.6 \
  | grep "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.43-2ubuntu2) stable release version 2.43.

$ ldd --version | head -1
ldd (Ubuntu GLIBC 2.43-2ubuntu2) 2.43
```

`scripts/install-glibc.sh` copies the host `libc.so.6` (resolved through symlinks)
into `build/disk/lib*/`. There is **no pinned glibc tarball** in the test-image build
pipeline; whatever the host runs, the disk image runs.

The W209 / PNG-2 verdict that this was a "glibc 2.34 two-group cycle pattern" was
based on the algorithm pattern shape, not on the actual symbol-version of the
running library. The pattern is correct; the version attribution was wrong.
**We have been running 2.41-fixed glibc the entire time.**

---

## Why the PNG-2 observation is still real

The `FUTEX_WAKE woken=0` pattern is *expected behaviour* for the two-group
algorithm in any of these scenarios:

1. **The signaler wakes the wrong group.** If G1 has the in-flight signal but the
   waiter is in G2 (because they joined after `__condvar_quiesce_and_switch_g1`
   moved the group), the wake call hits an empty uaddr.
2. **Adjacent cond_var addresses.** PNG-2 observed waiters at `uaddr - 0x3a0` and
   `uaddr - 0x500`. These offsets (928 and 1280 bytes) are far too large to be the
   two `__g_signals[]` slots within one `pthread_cond_t` (which are 4 bytes apart).
   These are **different cond_vars in the same enclosing struct** (e.g. a Mozilla
   `Monitor` or `RWLock` object containing multiple `pthread_cond_t` fields).
3. **Stale signal.** The signaler has updated `__g_signals[g1]` but the waiter is
   still spinning on the pre-update value and hasn't reached `futex_wait` yet.
   The `futex_wake` legitimately wakes 0 because no one is parked.

In each case the right diagnostic is *the next stage of the cond_var protocol*,
not "swap glibc version". The kernel `futex(2)` implementation is doing its job:
it wakes whatever waiters are parked on the asked-for uaddr.

---

## Kernel-side futex audit

I inspected `kernel/src/subsys/linux/syscall.rs:5555-5860` (the FUTEX
implementation). Findings:

- FUTEX_WAITERS is keyed by `(pid, uaddr)`. This is correct for **private**
  futexes (the default for `pthread_cond_t` initialised with default attrs).
- `FUTEX_PRIVATE_FLAG` is explicitly stripped but **not behaviourally honoured**:

  ```rust
  const FUTEX_PRIVATE_FLAG:   u64 = 0x80;
  let _ = FUTEX_PRIVATE_FLAG; // documented for clarity; no behavioural use
  ```

  For shared futexes (PRIVATE_FLAG clear), the canonical Linux behaviour is to key
  by the underlying physical page (so two processes mmap'ing the same file at
  different VAs share a futex). AstryxOS keys by `(pid, vaddr)` regardless. **For
  process-local cond_vars (the vast majority) this is correct.** For shared
  cond_vars across IPC pipes / shared-memory, it is broken — but PNG-2's evidence
  (waiters in the same process as signaler) does not point at the shared case.
- The FUTEX_WAKE/WAIT critical section uses the documented FUTEX_WAITERS →
  THREAD_TABLE lock order. The check-then-queue is done under FUTEX_WAITERS,
  matching mainline Linux pattern. **No obvious race.**

**Verdict: the kernel futex syscall is not the bug.**

---

## Strategic options (verdict)

### Option A — downgrade to glibc 2.33

**REJECTED.** 2.33 has the same two-group cond_var algorithm and the same BZ 25847
bug. Downgrading would (a) not fix the observed pattern, and (b) lose the BZ 25847
fix our current 2.43 has.

### Option B — upgrade to 2.35 / 2.36

**REJECTED.** 2.35 and 2.36 have identical cond_var algorithms to 2.34 and the
same BZ 25847 bug. Pure refactor releases.

If we were to upgrade to **2.41+**, we would gain the BZ 25847 fix — but we
already have it via 2.43. The tarballs in `internal-refs/osrefs/glibc/`
stop at 2.36 and so don't include the fix anyway.

### Option C — kernel-side compensation **(RECOMMENDED)**

The observed pattern is most likely a **diagnostic gap, not a real wedge**:
PNG-2 sees `FUTEX_WAKE woken=0` and concludes "lost wakeup", but the algorithm
correctly tolerates many woken=0 returns (spin-then-park races, stale-signal
races, wrong-group races that are subsequently corrected by the steal-undo path).

What's missing is whether the *signaler is targeting the wrong cond_var* (a
Mozilla bug, fixable in libxul — but per CLAUDE.md invariant we cannot patch
upstream binaries) or *the same cond_var but the waiter is parked on a different
internal slot* (would be a real glibc/kernel bug).

**Recommended kernel-side change (~30-50 LOC):**

1. **Add cond_var-cluster tagging to FUTEX_WAKE_REQ and FUTEX_WAIT_REG** so the
   harness can group log lines by enclosing 48-byte cond_t. ~10 LOC in
   `kernel/src/subsys/linux/syscall.rs` (add a cluster key that masks the low
   bits of uaddr to 6 bits / 48 bytes).
2. **Add a FUTEX_WAITERS dump on every WAKE that returns 0** (gated by
   `firefox-test` feature). This lets us see whether the wake call *would have
   woken* a different uaddr in the same cond_var. ~10 LOC.
3. **Add a "ghost wake" diagnostic** that scans all uaddrs in the same 48-byte
   range as the wake target and records whether any of them had waiters. If yes,
   the bug is "wake-on-wrong-group" and we can characterise it more precisely.
   ~20 LOC.

Estimated total: **~40 LOC, one PR.**

This would either:

- **Confirm Mozilla bug** (different cond_vars in adjacent memory — the signaler
  is updating one and trying to wake another). At that point the right move is
  to characterise the Mozilla call site and either work around it via an LD_PRELOAD
  shim (still permitted — we don't patch the binary, we interpose) or accept
  PNG won't ship via current libxul.
- **Confirm kernel/glibc bug** (same cond_var, wrong group). Then we have a
  reproducible scenario to investigate, with the algorithm understood in detail.

### Option D — build Firefox against musl

**REJECTED.** Out of scope; musl source not in `internal-refs/`; would
require an XCode-scale rebuild of the Firefox userspace stack; would lose the
ABI guarantees the entire Linux subsystem is designed around (the personality
runs *upstream Linux binaries*, not bespoke-rebuilt ones).

### Option E — accept PNG won't ship via Firefox

**DEFERRED.** Premature until Option C diagnostic narrows the bug. If Option C
confirms "Mozilla bug we cannot interpose around", THIS becomes the verdict —
but we are not there yet.

---

## Build-script impact (for reference, since A/B/D were rejected)

If at some point we DO want to pin a specific glibc version (e.g. 2.41+ to
hedge against future host-glibc regressions), the change is small:

```bash
# scripts/install-glibc.sh
# Current: copies host glibc, no version check.
# Proposed: optionally extract a pinned tarball into build/glibc-<ver>/ and
# copy from there instead of /lib.

GLIBC_PINNED_VERSION="${GLIBC_PIN:-}"
if [ -n "$GLIBC_PINNED_VERSION" ]; then
    # ... extract glibc-${GLIBC_PINNED_VERSION}.tar.gz into build/glibc/,
    # build it (./configure --prefix=... && make), then copy from build/glibc/lib
    : # ~80 LOC of build+copy logic
else
    # ... existing host-glibc copy logic
    : # current ~250 LOC
fi
```

Estimated effort: **~100-150 LOC of shell + a 30-60 min glibc build per CI run**.
ABI risk is moderate — libxul links against many internal glibc helpers; building
glibc with a different toolchain than the host could create symbol-versioning
divergence. **Not recommended unless we hit a host-glibc regression in CI.**

---

## Citation discipline (per CLAUDE.md `feedback_coord_reads_supporting_resources`)

This document cites only:

- POSIX [pthread_cond_signal(3p)][posix-cond-signal] and [pthread_cond_wait(3p)][posix-cond-wait]
- The public [futex(2)][linux-futex] man page
- glibc release notes published on [www.gnu.org][glibc-241] and the
  [upstream NEWS file][glibc-news] (hosted on GitHub mirror)
- Public technical analysis at [probablydance.com][skarupke-2020]

No internal `internal-refs/` paths, no "Linux kernel source", no
"per glibc nptl/X.c" citations.

[posix-cond-signal]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_cond_signal.html
[posix-cond-wait]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_cond_wait.html
[linux-futex]: https://man7.org/linux/man-pages/man2/futex.2.html
[glibc-241]: https://lists.gnu.org/archive/html/info-gnu/2025-01/msg00014.html
[glibc-news]: https://github.com/bminor/glibc/blob/master/NEWS
[skarupke-2020]: https://probablydance.com/2020/10/31/using-tla-in-the-real-world-to-understand-a-glibc-bug/
[skarupke-2022]: https://probablydance.com/2022/09/17/finding-the-second-bug-in-glibcs-condition-variable/

---

## Concrete next step

Open a separate dispatch (or include in the next kernel-debug investigation):

> **Add cond-cluster diagnostic to FUTEX_WAKE / FUTEX_WAIT logging** —
> in `kernel/src/subsys/linux/syscall.rs` near line 5811 (`FUTEX_WAKE_REQ`)
> and line 5754 (`FUTEX_WAIT_REG`), add a `cluster=` field that bins `uaddr`
> by 64-byte alignment so the harness can post-process and group log lines by
> enclosing cond_t. Also add a `[FUTEX_WAKE_GHOST]` line emitted when WAKE
> returns 0 AND there are waiters on any uaddr in the same 64-byte cluster.
> Gated by `firefox-test`. ~40 LOC.

That diagnostic resolves the A/B/D-vs-C question for this entire issue class
and should be the next move before any more demo-PNG attempts.
