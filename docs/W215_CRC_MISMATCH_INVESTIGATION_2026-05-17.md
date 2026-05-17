# W215 residual CRC-MISMATCH investigation — 2026-05-17

Author: Aether kernel engineer (branch `w215-crc-mismatch-investigation`).

## Premise

PR #270 (b1`1b1059e0`) closed the W215 cache-evict-vs-PTE race with a
per-frame `pte_share_count` invariant + `pmm::free_page` assertion.  The
5-trial closure soak reported **5/5 clean across four evidence channels**:

| Channel                       | Trial 1..5 |
|-------------------------------|-----------:|
| `[FAULT/PHYS]`                | 0          |
| `[PMM/PTE-REFS]`              | 0          |
| `pmm_alloc_nonzero_rc`        | 0          |
| `window_race + install_race`  | 0          |

The H7 (PR #274) follow-up soak observed 21-50 `[W215/CRC-MISMATCH]` lines
per trial.  Because **CRC-MISMATCH was not among PR #270's four verified
channels**, the closure verdict was — strictly — incomplete by one
channel.  This investigation closes that gap.

The core question: does PR #270 actually close the W215 mechanism (frame
recycle while user PTEs live), or does it merely suppress the user-visible
FAULT manifestation while a separate corruption mechanism (write to a
cache-resident frame from an unaccounted-for writer) continues?

## TL;DR

**`[W215/CRC-MISMATCH]` post-PR-#270 is H_legit_write: a legitimate write
to a cache-resident frame via a MAP_SHARED+PROT_WRITE PTE that aliases
that frame.  It is not a residual of the W215 frame-recycle race.**

PR #270's closure is complete for the bug it was designed to fix.  The
CRC walker (`kernel/src/mm/w215_crc.rs`) was instrumented in PR #260
under the working hypothesis that a stale PTE was clobbering a still-
cache-resident frame; with that mechanism now closed by `pte_share_count`,
the remaining MISMATCH fires are the *legitimate* writers the walker
cannot distinguish from corruption.

The right action is **not** another kernel fix — it is to teach the
walker (or its consumer) to filter MAP_SHARED+PROT_WRITE-aliased frames
out of the alarm.  Estimated fix size: ~30 LOC, diagnostic-only.

## Step 1 — single-trial soak on master tip `936f330` (post-PR-#274)

Built `firefox-test,w215-diag,kdb` and ran one trial under KVM.  Counts
at the post-libpng16 plateau (sc dropped off after `libpng16.so.16`
appears in `[FF/write]`; allowed to run until quiescent for a long
window to maximise CRC walker passes):

| Channel                                  | Count    |
|------------------------------------------|---------:|
| `[FAULT/PHYS]`                           | 0        |
| `[PMM/PTE-REFS]`                         | 0        |
| `pmm_alloc_nonzero_rc`                   | 0        |
| `refcount_set_over_nonzero`              | 0        |
| `pmm_free_residual_refs`                 | 0        |
| `[W215/INSERT-WRONG-CONTENT]`            | 0        |
| `[W215/DR-WATCH-FIRE]`                   | 0        |
| `[W215/DR-ARM]`                          | 1        |
| **`[W215/CRC-MISMATCH]`** (unique tuples)| **4**    |
| `[W215/CRC-MISMATCH]` (total emissions)  | 8 443    |
| `cache.total_entries`                    | 42 016   |
| `cache.orphan_count`                     | 0        |

The 8 443 total emissions are 4 unique `(phys, key)` tuples re-emitting
on every walker pass — the walker re-CRCs the same frame each tick, and
because no DR slot is available to suppress the re-fire (DR pool was
already saturated and the post-fire CRC-refresh step in
`crc_walk_tick` only runs if a watchpoint was actually armed), the same
mismatch reprints.  Distinct tuples:

```
phys=0x29ee9000 key=(_,265,0x33000)  expected=0xc71c0011 actual=0xac156679
phys=0x2ffc1000 key=(_,287,0x3000)   expected=0xc71c0011 actual=0xf9e19326
phys=0x2ffd1000 key=(_,287,0x5000)   expected=0xc71c0011 actual=0xbdde8132
phys=0x2fd99000 key=(_,283,0x0)      expected=0xc71c0011 actual=0x8dace453
```

The first `[W215/CRC-MISMATCH]` line in the trial was an *earlier*
phys for the same inode-265 cluster:

```
phys=0x29d99000 key=(_,265,0x9000)   expected=0xc71c0011 actual=0x55c06af7  tick=14322
```

That phys received the single `[W215/DR-ARM]` (slot=0).  No
`[W215/DR-WATCH-FIRE]` followed — the writer either had already finished
before the arm, or wrote at a byte offset outside the 8-byte watchpoint
window at the frame base (the walker arms only `linear_addr = PHYS_OFF +
phys + 0`).

### Critical numerical anchor: `expected = 0xc71c0011`

All four steady-state tuples report `expected = 0xc71c0011`.  This is
not a coincidence — it is **the IEEE 802.3 CRC32 of a 4 KiB all-zero
page**:

```
$ python3 -c "import zlib; print(hex(zlib.crc32(b'\\x00'*4096) & 0xFFFFFFFF))"
0xc71c0011
```

That means at the moment `cache::insert_with_expected` called
`w215_crc::record_insert(phys, ...)`, the physical frame at
`PHYS_OFF + phys` held **all zeros**.  The `actual` value is a stable,
distinct CRC per phys — the frame later acquired stable non-zero
content that has not changed across hundreds of subsequent walker
passes.

This is the exact signature of a **legitimate one-shot write to the
cache page after insert, then quiescence** — not the
write-by-stale-PTE-then-recycle signature W215 was tracking.

## Step 2 — what the CRC walker means after PR #270

`mm/w215_crc.rs` semantics (read at HEAD `936f330`):

1. `record_insert(phys, inode, file_offset)` runs at the tail of
   `cache::insert_with_expected` (`mm/cache.rs:311`), after the cache
   lock is released.  It reads 4 KiB at `PHYS_OFF + phys`, computes
   CRC32, stores `(phys, key, crc, generation)` in a 64 K-slot shadow
   table keyed by `hash(inode, offset)`.
2. `crc_walk_tick(cpu)` runs from the timer ISR at `TICK_HZ = 100`,
   per CPU.  It re-CRCs up to `WALK_BUDGET_PER_TICK` (4096) entries
   per system tick, divided across online CPUs.
3. On mismatch: re-CRC once (to filter torn reads), and if still
   different, emit `[W215/CRC-MISMATCH]`, then attempt to arm DR0
   write-watchpoint on `(PHYS_OFF + phys, len=8)`.  If a DR slot is
   available, refresh the stored CRC to `actual2` so the same frame
   does not re-fire on every tick.  If the DR pool is saturated, the
   stored CRC is **not** refreshed and the frame re-fires every walker
   pass — the source of the 8 443 emissions across 4 tuples.

A `[W215/CRC-MISMATCH]` line means exactly: *the contents of physical
frame X at walker time differ from the contents recorded when
`cache::insert` published frame X for cache-key K*.

This is broader than the W215 hypothesis it was designed to test.
Specifically, it does **not** distinguish between:

- a stale user PTE (or kernel reference) writing into a frame the cache
  is no longer supposed to be holding (the W215 mechanism — closed by
  PR #270), and
- a *live* writer through a *correctly-aliased* user PTE updating a
  frame that the cache is *currently* holding — the H_legit_write case.

## Step 3 — classifying the observed tuples

The cache keys map back to inodes via `[H3a/mmap] SHARED+WRITE`
diagnostic lines (PR #248), which log every
`mmap(MAP_SHARED|PROT_WRITE, fd≥0)` call:

| Inode (dec) | Inode (hex) | Source file                        | mmap len   | mmap off |
|-------------|-------------|------------------------------------|-----------:|---------:|
| 265         | 0x109       | `/tmp/ff-profile/cookies.sqlite`   | 0x3b000    | 0x0      |
| 283         | 0x11b       | (SQLite WAL/journal via fd=32)     | 0x1000     | 0x0      |
| 287         | 0x11f       | (SQLite WAL/journal via fd=36)     | 0x10000    | 0x0      |

(fd=32 / fd=36 are `/proc/self/fd/31` and `/proc/self/fd/35`
respectively, both opened on SQLite cookie-database satellite files;
the underlying inodes 283 and 287 are part of the same cookies.sqlite
family.)

**All four CRC-MISMATCH cache keys are inside MAP_SHARED+PROT_WRITE
file-backed mappings.**

The total `sys_mmap_shared_write_filebacked` counter for the trial is
15 — Mozilla creates several such mappings for SQLite cookie/places
databases, font metadata caches, and the OS shared memory pool.

### The MAP_SHARED+PROT_WRITE alias arm

`arch/x86_64/idt.rs` page-fault install path treats
MAP_SHARED+PROT_WRITE specifically (see lines 1714-1731, 1859-1860,
1899-1900, 2193-2196 for the three install arms — readahead, cache-hit
COW evaluator, single-page fallback).  All three honour the same
contract:

> MAP_SHARED + writable: ALIAS the cache page so that writes are
> visible to other mappers of the same `(mount, inode, offset)`.
> Required by mmap(2)'s MAP_SHARED contract.

The aliased PTE has `PAGE_WRITABLE` set and points at the same
physical frame the cache holds.  A user-space store through that PTE
writes directly into the cache frame — *by design*, per POSIX mmap(2):

> *The MAP_SHARED flag... requires that updates to the mapping are
> visible to other processes that map this file.*

The cache page IS the shared backing.

### Why `expected = CRC(zeros)`

The cookies.sqlite trajectory in the serial log (line numbers from the
single-trial log):

```
L10888  [H3a/mmap] SHARED+WRITE filebacked mount=0 inode=0x109 fd=26 len=0x3b000 off=0x0 pid=1
L11178  [FF/open-ret] pid=1 path=/tmp/ff-profile/cookies.sqlite ret=-2           ← initial ENOENT
L11199  [FF/open-ret] pid=1 path=/tmp/ff-profile/cookies.sqlite ret=26           ← open O_CREAT, fd=26
L14322  [W215/CRC-MISMATCH] phys=0x29d99000 key=(_,265,0x9000) expected=0xc71c0011 ...
```

Mozilla `open(O_CREAT)` created `cookies.sqlite`, then immediately
`mmap(SHARED|WRITE, fd=26, len=0x3b000)` over a file that initially
held 0 bytes of content (just-created via O_CREAT).  The mmap is
larger than the file; subsequent ftruncate / write extends the file in
4 KiB increments.

When the user-space SQLite later faults on the mmap'd VMA at file
offset 0x33000 (a region of the mapping that lies *beyond* the file's
EOF at the moment of fault), the install path:

1. Allocates a fresh PMM frame.
2. Zero-fills `PHYS_OFF_FILE + phys` (`idt.rs:1565`).
3. Calls `fs.read(inode, 0x33000, buf)` — which returns short or zero
   because the file has not yet been extended to that offset (POSIX
   `read(2)` past EOF semantics: "zero indicates end of file" — see
   `man 2 read`).  The zero-fill from step 2 stands.
4. Inserts the zero-filled frame into the cache via
   `cache::insert_with_expected(...)` — `expected=Some(reference[64])`
   where the reference snapshot is also zeros (consistent with the
   frame).  PR #269's wrong-content guard sees ref-zero AND
   sample-zero → `trivial_zero_match=true` → guard skipped.
5. `w215_crc::record_insert(phys, ...)` snapshots CRC32 of 4 KiB of
   zeros → **expected = 0xc71c0011**.
6. Installs the user PTE aliasing `phys` (MAP_SHARED + writable arm at
   `idt.rs:1929`).

Later — possibly milliseconds later — userspace ftruncate's the file
to its full size and writes the real SQLite content (header, b-tree
pages) via *the mmap'd PTE*.  The writes go directly into `phys`.

At the next walker pass, the frame contents differ from the recorded
CRC → `[W215/CRC-MISMATCH]` fires.  The new content is stable (SQLite
does not re-write these pages on every tick), so `actual` and
`actual2` agree (no torn read), and the line keeps reprinting because
the DR pool is saturated and the stored CRC is not refreshed.

### Why this is NOT H_residual / H_different_bug

The five hypotheses the dispatch listed, evaluated against the
evidence:

| H              | Verdict                                                                  | Evidence                                                                                                                                                  |
|----------------|--------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| H_benign       | **REJECTED**                                                             | "Benign" here would mean a torn-read between insert and walker.  But `actual == actual2` always (re-CRC after the mismatch agrees), and PR #269's post-insert source-CRC compare (which would catch a torn insert) reported 0 wrong-content lines. |
| H_residual     | **REJECTED**                                                             | Would require a stale PTE writing into a cache-resident frame.  PR #270 closes the only known stale-PTE mechanism (`pte_share_count` assertion).  Confirmation: `[PMM/PTE-REFS] = 0`, `pmm_free_residual_refs = 0`.  No frame was freed with live PTEs. |
| H_legit_write  | **CONFIRMED**                                                            | All 4 unique cache keys are inside MAP_SHARED+PROT_WRITE mappings (per `[H3a/mmap]`).  The mmap install path aliases the cache page (`idt.rs:1929`).  Writes via the user PTE legitimately modify the frame.  `expected=CRC(zeros)` matches the "mmap'd before file extended" trajectory.  `actual` is stable per phys — consistent with one-shot or rare userspace writes to the SQLite page. |
| H_different_bug| **REJECTED for the CRC-MISMATCH manifestation itself**                   | A separate latent bug *is* visible adjacent to this evidence (`fs.write` does not invalidate/refresh the page cache — write(2) syscall bypass), but this surfaces as a *cache-coherency* gap between the write(2) path and the mmap path, not as an additional CRC-MISMATCH source.  See "Adjacent finding" below. |

The dispositive evidence is the conjunction of:

1. `expected = CRC32(zeros)` for every unique tuple (writer wrote
   AFTER insert recorded a zero frame).
2. `actual` is stable per phys, NOT changing across walker passes
   (consistent with rare userspace writes, not with churn-class
   corruption).
3. Every unique cache key is inside a MAP_SHARED+PROT_WRITE mapping
   (per `[H3a/mmap]` lines).
4. `[W215/INSERT-WRONG-CONTENT] = 0` (PR #269 post-insert guard did
   not fire — the frame contents at insert WERE correct given the
   file's state at that moment).
5. Every PR #270 channel (`FAULT/PHYS`, `PMM/PTE-REFS`,
   `pmm_alloc_nonzero_rc`, `pmm_free_residual_refs`) is zero.

## Step 4 — verdict and recommendation

### Verdict on PR #270's closure

**PR #270's W215 closure is complete for the W215 frame-recycle
mechanism it was designed to fix.**  The CRC-MISMATCH events are not
residuals of that mechanism; they are diagnostic over-sensitivity to
legitimate MAP_SHARED+PROT_WRITE writers — a class the CRC walker
cannot distinguish from corruption at its current resolution.

The saga-close memory `project_w215_saga_CLOSED_2026_05_17` should be
updated to record that the four verified channels remain zero, AND
that the CRC walker's 4 stable-tuple emissions are H_legit_write
artefacts now characterised in this document.

### Recommendation: diagnostic-only refinement (NOT a kernel fix)

The CRC walker is a diagnostic; the right response is to make it
quieter on writers it cannot meaningfully distinguish from a bug.
Three options, in increasing order of effort:

1. **Allow-list MAP_SHARED+PROT_WRITE cache-keys (preferred, ~30 LOC).**
   `mm/cache.rs::insert_with_expected` already knows the cache key.
   The mmap path (`subsys/linux/syscall.rs::sys_mmap`) already tracks
   `sys_mmap_shared_write_filebacked` per (inode).  Wire a
   `(mount_idx, inode)` "expected legitimate writer" set into
   `mm/w215_crc.rs`, and have `record_insert` mark such entries as
   `allow_writer=true`.  In `crc_walk_tick`, when an `allow_writer`
   entry mismatches, classify as `STAT_LEGIT_WRITE` and refresh the
   stored CRC silently instead of emitting `[W215/CRC-MISMATCH]`.

2. **One-shot per-key emission (≤ 15 LOC).**  Track a `silenced`
   flag per shadow-table entry.  On first mismatch, emit one
   `[W215/CRC-MISMATCH/FIRST]` line carrying the key + actual, set
   `silenced=true`, refresh CRC.  Subsequent walks compare against the
   new CRC; further mismatches re-emit `[W215/CRC-MISMATCH/AGAIN]` at
   most once per (key, generation) pair.  Loses the
   tight-stream signal but keeps coverage.

3. **Tear down the walker entirely (≤ 5 LOC, gated behind
   `w215-diag`).**  PR #270 has closed the diagnostic's hypothesis;
   the walker is no longer producing actionable signal in steady
   state.  Mark `w215_crc.rs` dormant unless re-enabled via a
   `w215-crc-walker` opt-in feature flag.

Option 1 preserves the walker's value (it would still catch a fresh
class-of-bug that wrote to a *non*-MAP_SHARED frame), while
eliminating the H_legit_write noise floor.  Recommended.

### Adjacent finding (out of scope, worth a follow-up)

The trial log shows extensive `[FF/write] fd=26 bytes=32768` traffic
on the SQLite databases.  `kernel/src/vfs/mod.rs::sys_write` (line
~2062) calls `fs.write(inode, offset, data)` directly and does **not**
invalidate or refresh the page cache for the modified `(mount, inode,
offset)` range.  Any subsequent fault on a MAP_SHARED mapping of the
same inode that hits a still-cached pre-write page would observe
stale content; conversely, a `write(2)` immediately after an mmap
update could under-write if the cache page got faulted in between the
two.

This is a real cache-coherency gap between the write(2) syscall path
and the mmap read/write path, distinct from W215.  It does not
manifest as `[FAULT/PHYS]` because the frame is not recycled, only
stale.  Worth a dedicated audit; not a CRC-MISMATCH driver in this
trial.

Recommended follow-up dispatch: `vfs-engineer` (or equivalent) to
audit `sys_write` → `cache::evict` / `cache::mark_dirty` / writeback
plumbing.  Cite POSIX `write(2)` and mmap(2) coherency requirements.

## Citations

- POSIX `mmap(2)` MAP_SHARED contract: "Updates to the mapping are
  visible to other processes that map this file, and are carried
  through to the underlying file."  (Single Unix Specification v4 /
  IEEE Std 1003.1-2017.)
- POSIX `read(2)`: "If the starting position is at or after the
  end-of-file, 0 shall be returned."
- POSIX `write(2)` / `mmap(2)` consistency requirement: implementation
  may treat the two as cache-coherent; AstryxOS currently does not.
- Intel SDM Vol. 3A §4.10.5 (page-level coherence requirements).
- ISO/IEC 8802-3 CRC32 polynomial (used by
  `kernel/src/mm/w215_crc.rs::crc32`).

## Headline

**H_legit_write confirmed.**  PR #270's W215 closure is complete.  The
CRC-MISMATCH events are MAP_SHARED+PROT_WRITE writers visiting their
own cache-aliased frames.  Recommended next dispatch: ~30 LOC
diagnostic refinement (allow-list MAP_SHARED+PROT_WRITE cache keys
inside the CRC walker), with an optional follow-up audit of
`sys_write` → page-cache coherency for the adjacent (non-W215) gap.
