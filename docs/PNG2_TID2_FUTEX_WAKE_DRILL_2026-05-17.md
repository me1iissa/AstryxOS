# PNG-2 — TID-2 FUTEX_WAKE drill — post-W215 plateau classification

**Date**: 2026-05-17
**Status**: H1_STATIC verdict, but the producer is **TID 13**, not TID 2 as PNG-1 hypothesised
**Branch**: `png-2-tid2-futex-wake-drill`
**Prior**: PR #272 (PNG-1 thread-park-audit) — post-W215 plateau characterised at sc=3534/3538/3532

## Headline

The post-W215 plateau (sc≈3559 per global heartbeat; pid=1 sc=2907) is an
**H1 STATIC FUTEX_WAKE deadlock**, but the producer is not who PNG-1
initially identified.

The new `futex-wake-drill` subcommand (added in this PR) parses
`[FUTEX_WAKE]` and `[FUTEX_WAKE_REQ]` lines from the serial log, buckets
them temporally, and computes Jaccard similarity of per-bucket wake-uaddr
sets:

| TID | wakes | woken/wakes | Jaccard(first,last) | verdict |
|-----|------:|------------:|--------------------:|---------|
| 2   |     9 |       8 / 9 |               0.00  | H2_CHURNING (normal main-thread activity, not stuck) |
| 13  |    37 |       0 / 37|               1.00  | **H1_STATIC** (single uaddr 0x7effff4f1ea0, 6/6 buckets) |
| 16  |     2 |       1 / 2 |                  —  | minor |
| 15  |     1 |       0 / 1 |                  —  | minor |

**TID 13** issues 37 FUTEX_WAKE calls — all on the same address
`0x7effff4f1ea0`, all returning `woken=0`. The wakes are in a tight loop
with FUTEX_WAIT(`0x7eff6d19f9ec`) → ETIMEDOUT → FUTEX_WAKE(`0x7effff4f1ea0`)
→ woken=0 → repeat. Same RIP pair on every iteration:

- wait RIP `0x7effffa84ae2`
- wake RIP `0x7effffa78c67`

## Why PNG-1's "TID 2 producer" framing was incomplete

`thread-park-audit` in PR #272 correctly identified TID 2 (Mozilla main)
issuing FUTEX_WAKE calls. But the audit reports state at a single moment;
it cannot weight producers by frequency. Once we bucket the
`[FUTEX_WAKE]` event stream temporally:

- TID 2 = 9 wakes (8/9 woken, completely churning across buckets — main is
  fine, this is the natural rate of nsThread event-loop coordination)
- TID 13 = 37 wakes (0/37 woken, single uaddr in every bucket — STATIC)

So PNG-1's hypothesis "main thread is waking the worker pool but never
progresses" was directionally right (something is waking, nobody is
progressing) but mis-attributed: the wedge isn't on main, it's on **worker
TID 13**.

## Live `thread-park-audit` cross-reference

At the plateau (sc=3559, tick=80364) the live FUTEX_WAITERS view shows:

| tid | thread | state    | parked-on uaddr      |
|-----|--------|----------|----------------------|
|   2 | main   | ready    | 0x7effff4c8290 (futex-other) |
|   9 | clone-child | blocked | 0x7effff4f1b00 |
|  10 | clone-child | ready   | 0x7effff43b098 |
|  11 | clone-child | blocked | 0x7effff4f19a0 |
|  13 | clone-child | ready   | **0x7eff6d19f9ec** (the WAIT side) |
|  15 | clone-child | ready   | 0x7effff47af1c |
|  16 | clone-child | blocked | 0x7effff43cf50 |

**No thread is parked on `0x7effff4f1ea0`** (TID 13's wake target). The
two closest parked uaddrs (TID 9 at `0x7effff4f1b00`, TID 11 at
`0x7effff4f19a0`) are 0x500 / 0x3a0 bytes away — same library page region
but distinct objects.

This is consistent with the W209 (2026-05-15) finding: glibc 2.34
`pthread_cond_t` has two internal sequence counters (G1/G2) that cycle by
design. If the producer signals the wrong group's futex, no waiter is
unblocked.

## Verdict

**H1 STATIC deadlock**, located on **TID 13** (clone-child worker), waking
`0x7effff4f1ea0` with no waiter parked on that address. Jaccard
first-vs-last = **1.00**; single uaddr in every one of 6 buckets; 0/37
wakes successful.

Wake/wait pattern matches the glibc 2.34 pthread_cond_t two-group cycle
documented in W209 — this is library-level cond-var coordination, not a
kernel futex bug. The kernel correctly delivers the wake to address
`0x7effff4f1ea0`; no waiter is on the queue for that address because the
waiters parked themselves on adjacent counter addresses.

## Recommended next dispatch

The next move is **NOT** a kernel fix — W209 already rejected all 6 kernel
hypotheses for this Branch-A pattern. The correct next dispatch is one of:

1. **Worker-thread call-graph reconstruction** (cheap): use the existing
   `[FUTEX_WAIT_REG]` / `[FUTEX_WAIT_STACK]` rbp-chain + the
   `[FFTEST/mmap-so]` load-base table to resolve TID 13's wait RIP
   `0x7effffa84ae2` and wake RIP `0x7effffa78c67` to library:symbol pairs.
   The wedge is in the userspace code that decides to wake
   `0x7effff4f1ea0` while waiters parked themselves on
   `0x7effff4f1b00` / `0x7effff4f19a0`.

2. **Cond-var-address audit on the kernel side** (medium): instrument
   `sys_futex_linux`'s WAKE path with an "alias scan" — for each
   `woken=0` FUTEX_WAKE, log any waiters in `FUTEX_WAITERS` within ±0x100
   of the target uaddr. This makes the kernel surface the suspected
   cond-var-relocation pattern automatically rather than requiring
   post-hoc analysis. Diff budget: ~20-40 LOC.

3. **Drop in glibc 2.34 vs 2.35 strace-diff** (large): the W209
   investigation concluded the two-group cycle is by-design. If the
   pattern's *frequency* is anomalous compared to native Linux, a
   trace-diff would surface what triggered TID 13's spin (usually a
   missing source of forward progress: an IPC byte, a file completion, an
   epoll wake elsewhere).

(2) is the highest-ROI follow-up — it makes future dispatches diagnostic-
ready rather than re-deriving this each time. Suggest dispatching as
PNG-3 with diff cap ≤ 100 LOC.

## Methodology — `futex-wake-drill` algorithm

```
1. Read serial log for the session.
2. Filter [FUTEX_WAKE] / [FUTEX_WAKE_REQ] lines by --tid (default 2).
3. Bucket into K equal-row-count temporal slices (--bucket-count K, def 2).
4. Per bucket: aggregate uaddr → (wakes, woken_total, max_woken, wake_reqs).
5. Compute Jaccard(set(bucket[0].uaddrs), set(bucket[-1].uaddrs)).
6. Classify:
     J ≥ 0.80  →  H1_STATIC   (same set across whole window)
     J ≤ 0.20  →  H2_CHURNING (set rotated — progress made)
     else      →  HYBRID
7. Optional --cross-park: live kdb thread-park-audit; per-uaddr in last
   bucket, attach "parked waiters" list to confirm/refute deadlock.
```

References:
- POSIX `futex(2)` — FUTEX_WAKE semantics
- Intel SDM Vol 3A §8.2.3 — total-store-order properties used by the
  kernel sample slot ordering
- `glibc/nptl/pthread_cond_wait.c` (publicly published source on
  sourceware.org) — two-group cycle algorithm rationale

## What this PR ships

1. `scripts/qemu-harness.py` — new subcommand `futex-wake-drill`
   (~280 LOC including the new helpers `_lo_idx`/`_hi_idx`,
   `_futex_drill_jaccard`, and `cmd_futex_wake_drill`).
2. `docs/PNG2_TID2_FUTEX_WAKE_DRILL_2026-05-17.md` — this writeup.

No kernel-side changes — the existing `[FUTEX_WAKE]` and
`[FUTEX_WAKE_REQ]` instrumentation already provides every signal needed.

## Reproducing

```
python3 scripts/qemu-harness.py start --features firefox-test,kdb,syscall-trace,w215-diag
# wait for plateau (~3-4 min)
python3 scripts/qemu-harness.py wait <sid> 'HB.*sc=35[5-9][0-9]' --ms 240000
# drill on any TID
python3 scripts/qemu-harness.py futex-wake-drill <sid> --tid 13 --bucket-count 4
# cross-park (requires --features kdb)
python3 scripts/qemu-harness.py futex-wake-drill <sid> --tid 13 --cross-park
```

## Cross-link

- PR #270 — W215 saga close (pte_share_count invariant)
- PR #272 — PNG-1 thread-park-audit (this drill is its temporal-bucketing complement)
- Per-conversation memory: `project_w209_sem_wait_branch_a_rootcause_2026_05_15`
  documents the glibc 2.34 cond_t two-group cycle pattern this drill confirms
