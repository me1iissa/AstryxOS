# W215 cache::insert source-of-bytes audit — 2026-05-17

Author: Aether kernel engineer (worktree `w215-insert-wrong-content-diag`).

## Premise

W215 is currently understood as a **one-shot drive-by corruption** of a
page-cache frame: the bad value is stamped exactly once and a hardware
watchpoint set after the fact never re-fires.  The candidate writers are:

  1. `cache::insert` itself (or its source-fill step in the install path).
  2. The MAP_PRIVATE writable cache-hit CoW arm (`copy_nonoverlapping` from
     `cached_phys` into `private_phys`).
  3. An OOM-fallback or short-read path that hands a frame to `cache::insert`
     without first overwriting it with the correct file bytes.

This audit enumerates every code path that fills a physical frame and
then hands it to `cache::insert`, evaluates whether each could insert a
frame whose contents do NOT match the source file bytes, and flags
findings worth a focused fix.

The two production callers of `cache::insert` are at:

  - `kernel/src/arch/x86_64/idt.rs:1783` (readahead install loop).
  - `kernel/src/arch/x86_64/idt.rs:2072` (single-page fallback).

Plus the boot-time `cache::prepopulate_file` path in
`kernel/src/mm/cache.rs:553`, which is gated behind `PREPOPULATE_ACTIVE`
and is OUT OF SCOPE for the steady-state diagnostic.

## Method

For each path that ends at a `cache::insert` call, I walked the code from
PMM allocation through the source-bytes write through to insert, and asked
four questions:

  1. **Short-read tail handling.** If `fs.read` returns N < requested bytes,
     are bytes `[N, 4096)` zero-filled before insert?
  2. **OOM-fallback hand-back.** Does any retry or fallback hand a partially
     filled (or fully uninitialised) frame to `cache::insert`?
  3. **Memset-zero-then-forget.** Does any path `write_bytes(..., 0, 0x1000)`
     and then call `cache::insert` without overwriting with file contents?
  4. **CoW MAP_PRIVATE writable file-backed.** When the cache-hit arm
     allocates a private copy, is the source frame guaranteed to be the
     correct file bytes at the moment of `copy_nonoverlapping`?

## Findings — per call path

### F1. `idt.rs:1554-1601` — readahead install path

```
pmm::alloc_page() → frame
write_bytes((PHYS_OFF_FILE + phys) as *mut u8, 0, 0x1000)   // explicit pre-zero
fs.read(inode, foff, buf)                                    // buf IS (PHYS_OFF + phys)..+0x1000
                                                             // success: drop into pages_to_map[]
                                                             // failure: pmm::free_page(phys), break
[ later, after revalidate ]
cache::insert(mount_idx, inode, foff, phys)                  // line 1783
```

- Short-read tail (Q1): the entire 4 KiB buffer was zero-filled before
  `fs.read`, and the FAT32 driver writes `[0, bytes_read)` into the
  destination buffer.  Bytes `[bytes_read, 4096)` therefore remain zero —
  **correct**.
- OOM-fallback (Q2): on `fs.read` failure or `alloc_page` failure the path
  returns the frame to the PMM (line 1592) and breaks — no `cache::insert`
  with a stale frame.  **Correct.**
- Memset-zero-then-forget (Q3): no — `fs.read` immediately follows the
  zero-fill.  **Correct.**
- CoW (Q4): N/A — this is the install path, not the cache-hit path.

**Time window between `fs.read` return and `cache::insert`**: lines 1601
(push into `pages_to_map`) through 1783 (insert).  The intervening work is:

  - the second `fs.read` loop iterations for adjacent pages (each operating
    on its own distinct frame);
  - VMA revalidation (PROCESS_TABLE lock, no frame writes);
  - the generation re-check loop (atomic load only).

There is no kernel-side writer to the just-read frame in that window.
**If the frame contents differ at the time of `cache::insert`, the writer
is concurrent (user-mode or sibling-CPU IPC).**

**Verdict**: PATH-CORRECT.  This is the right callsite for the Part-B
post-insert diagnostic — bytes captured immediately after `fs.read` are
the authoritative reference.

### F2. `idt.rs:1918-2072` — single-page fallback install path

Identical shape to F1:

```
pmm::alloc_page() → frame
write_bytes((PHYS_OFF_FILE + phys) as *mut u8, 0, 0x1000)
fs.read(inode, file_page_offset, buf)
  → on err: pmm::free_page(phys); return false
  → on ok:  proceed
[ revalidate / gen-check ]
cache::insert(mount_idx, inode, file_page_offset, phys)      // line 2072
```

- Q1: same pre-zero pattern — **correct**.
- Q2: failure paths free and return — **correct**.
- Q3: zero-fill immediately followed by `fs.read` — **correct**.
- Q4: N/A.

The MOUNTS spin-then-None branch also frees the frame (line 1997) before
returning false — no insert.

**Verdict**: PATH-CORRECT.  Suitable for the Part-B diagnostic.

### F3. `cache.rs:383-572` — `prepopulate_file` (bulk boot loader)

```
loop:
  fs.read(inode, chunk_start, &mut chunk_buf[..this_chunk])
  if bytes_read < this_chunk:
    write_bytes(chunk_buf[bytes_read..this_chunk], 0)        // zero-fill tail
  per-page:
    pmm::alloc_page()
    write_bytes(dst, 0, 0x1000)                              // pre-zero frame
    copy_nonoverlapping(chunk_buf + page_off, dst, copy_len) // copy file bytes
    cache::insert(...)
```

- Q1: short-read tail is zero-filled in two places — once in the source
  buffer (line 491-499) and once in the destination frame
  (`write_bytes(dst, 0, 0x1000)`, line 546).  **Correct, defence-in-depth.**
- Q2: on PMM exhaustion the inner loop breaks out and the outer loop
  trips the `free_page_count() < 20_000` guard.  No insert of a stale
  frame.  **Correct.**
- Q3: each `write_bytes(dst, 0, 0x1000)` is immediately followed by
  `copy_nonoverlapping` from the read buffer — **correct**.
- Q4: N/A.

**Verdict**: PATH-CORRECT.  Gated behind `PREPOPULATE_ACTIVE` and excluded
from the Part-B diagnostic per task spec.

### F4. `idt.rs:1313-1369` — cache-hit MAP_PRIVATE writable CoW arm

This is NOT a `cache::insert` callsite — the private copy is mapped
directly into the user PTE without going through the page cache.  But the
task brief flags it as a candidate W215 writer and it is worth auditing
for completeness.

```
lookup_and_acquire(mount_idx, inode, file_page_offset) → cached_phys (guard ref held)
revalidate VMA
if needs_private_copy:
    alloc_page() → private_phys
    copy_nonoverlapping((COW_OFF + cached_phys), (COW_OFF + private_phys), 4096)
    gen-re-check
    page_ref_set(private_phys, 1)
    map_page_in(cr3, page_addr, private_phys, page_flags)
    page_ref_dec(cached_phys)   // drop guard
```

- **Guard ref**: `lookup_and_acquire` holds the cache lock while doing the
  ref bump (cache.rs:142).  After the guard is in hand, the cache's own
  ref + the guard ref keep `cached_phys` alive across the copy.  A
  concurrent `cache::insert` collision can drop the cache's ref, but the
  guard ref prevents the rc from reaching zero.
- **Possible source mutation between cache-lock-release and copy**: if a
  sibling CPU obtains a MAP_SHARED writable PTE to `cached_phys` (via the
  cache-hit alias arm at line 1456 or the install-time alias arm at line
  1838/1894), and writes through that PTE between
  `lookup_and_acquire` returning and our `copy_nonoverlapping` running,
  we would copy *post-write* bytes into the private frame.

  This is **semantically permitted** by POSIX mmap(2): the contents of
  `cached_phys` are mutable through any MAP_SHARED writable mapping, and
  a MAP_PRIVATE reader is permitted to observe any prior state.  But the
  observed W215 fingerprint (CRC mismatch where the page contents do NOT
  match the file bytes) is consistent with: cache-resident frame mutated
  by a MAP_SHARED writer, then a MAP_PRIVATE CoW copies the mutated
  bytes into a private frame, which is then mapped at a libxul VA that
  expected unrelocated file bytes.

  However, this would mean the CRC walker observes the mismatch on the
  *cache* frame — not on the private copy.  Our Arm-1 CRC walker
  (`mm/w215_crc.rs`) records the cache frame's hash at insert time and
  re-walks the cache.  A MAP_SHARED writer mutating the cache frame
  would indeed show up there.  This argues for keeping the existing
  CRC walker; the Part-B diagnostic adds an INDEPENDENT check.

- **Generation re-check after copy**: present (line 1345).  Catches VMA
  replacement between revalidate and install.  Does NOT catch a sibling
  MAP_SHARED write through the same cache frame.

**Verdict**: PATH-CORRECT *for what it promises* (MAP_PRIVATE CoW from a
live cache frame).  Possible W215 contribution if a MAP_SHARED writer
ever obtains a writable PTE on a libxul cache frame — but the install
paths' `needs_private_copy_vma` gating (line 1709) already forces every
write-mapped libxul VMA through a private copy, so MAP_SHARED writers of
libxul cache frames should not exist in the steady state.

**Worth a defensive check**: the audit ring (`w215_diag::prov_record`)
should already capture KIND_INSERT for any cache::insert that re-keys a
phys.  We could additionally assert in the cache-hit CoW arm that
`cached_phys` is not concurrently held under a different cache key
(`is_phys_in_cache` returns a key that does not match `(mount_idx,
inode, file_page_offset)`).  This is the H3a probe in the install arms
(line 1444) — extending it to the CoW arm pre-copy would be a sub-100-LOC
addition.  **DEFERRED** — out of scope for this PR; the Part-B
post-insert check should expose the writer first.

### F5. `idt.rs:1828-1842` and `idt.rs:2100-2115` — install OOM-fallback CoW

These are CoW copies from a freshly-inserted cache frame into a private
copy frame, in the install arm (not the cache-hit arm).  Sequence:

```
fs.read → frame
cache::insert(mount_idx, inode, foff, phys)   // line 1783 / 2072
[ post-insert work ]
if needs_private_copy_vma:
    alloc_page() → private_phys
    copy_nonoverlapping((COW + phys), (COW + private_phys), 4096)
    map_page_in(cr3, vaddr, private_phys, page_flags)
    page_ref_dec(phys)
```

Window between `cache::insert` and `copy_nonoverlapping`: at this point
the frame is reachable via the cache, so a sibling CPU's
`lookup_and_acquire` for the same key could find it and (if MAP_SHARED
writable) map it directly.  But again, the install-arm gating forces
every writable file-backed install through a private copy on EVERY CPU —
no concurrent MAP_SHARED writer should ever appear.

**Verdict**: PATH-CORRECT under the install-arm gating contract.

### F6. Other `cache::insert` callers

A repo-wide `grep -n 'cache::insert\b'` confirms only the three callsites
above in production code.  Test paths under `kernel/src/test_runner.rs`
are not built in the firefox-test binary.

## Cross-cutting structural invariants checked

### S1. Frame pre-zero before file fill — UNIFORM

Every install path that does an `fs.read` first zeroes the destination
frame with `write_bytes(..., 0, 0x1000)`.  Short-read tails therefore
contain deterministic zero bytes, not PMM-recycled stale content.  Per
Intel SDM Vol. 3A §4.10.5 cache coherence is irrelevant here — the
write is performed through the higher-half identity map and the only
later reader is the user-mode PTE installed after invlpg.

### S2. Frame lifecycle — UNIFORM

Every `fs.read` failure path returns the frame to the PMM and aborts
without calling `cache::insert`.  No path inserts a frame that the
caller has not just filled with file bytes.

### S3. Cache eviction → TLB quarantine — IN PLACE

`cache::insert` evictions route through `tlb::quarantine_free` (line
314) — a sibling-CPU PTE pointing at the evicted phys is guaranteed to
be invalidated before the frame is recycled.  This closes one class of
W215-shaped aliasing.

## Conclusions — Part A

1. The three known `cache::insert` paths are individually correct under
   their stated contracts.  No short-read, OOM-fallback, or
   memset-zero-then-forget hand-back was found.

2. The narrowed W215 fingerprint ("one-shot drive-by, exactly one stamp
   per corruption") is **not explained by any structural bug in the
   install paths above**.  Two residual suspects remain:

   a. A **concurrent writer between `fs.read` and `cache::insert`** —
      a sibling CPU has a writable PTE to the just-allocated PMM frame
      (recycling-without-shootdown) and writes to it before the cache
      install completes.  This is the residual aliasing class.

   b. A **cache-resident frame mutated by a sibling MAP_SHARED writer**
      whose existence violates the install-arm CoW gating.  Possible if
      a code path missed the `needs_private_copy_vma` check or if
      `is_shared` is mis-computed for a libxul VMA.

3. The Part-B post-insert source-CRC compare directly tests hypothesis
   (a): if the frame contents at the moment of cache install do NOT
   match the bytes returned by `fs.read`, the writer is concurrent and
   has run between the `fs.read` return and the cache install.

   Hypothesis (b) is OUT OF SCOPE for the Part-B diagnostic — that
   would require a check at the CoW copy site, deferred per F4 above.

4. No Part-C fix is warranted from the audit alone.  The Part-B
   diagnostic must fire first to identify the writer.

## Future audit candidates (NOT FOR THIS PR)

- `vfs::*` paths that hand buffers to FS drivers — could a syscall
  `read(2)` into a user buffer end up writing into a PMM frame that the
  PFH then hands to `cache::insert`?  The user buffer goes through
  `copy_to_user` which uses its own kernel-mode lookup; this should not
  reach a cache-managed frame.  Worth a focused walk.

- `syscall::mmap` MAP_FIXED Phase 2b: when unmapping the old VMA, does
  the unmap path correctly issue the shootdown BEFORE returning the
  frame to the PMM?  PR #225 (TLB quarantine) closed one variant; PR
  #226 (post-I/O revalidate) closed another.  If any remaining
  Phase-2b path returns a frame to the PMM with a live PTE on a
  sibling CPU, the PMM may re-issue that frame to the install loop
  here — and the sibling writer can mutate it before our `fs.read`
  arrives.  This matches hypothesis (a) above.

## Public references cited in commits / comments

- POSIX mmap(2) — file-backed mapping semantics and SIGSEGV on demand-page
  failure.
- POSIX read(2) — short-read return semantics; bytes past the returned
  length are unspecified.
- Intel SDM Vol. 3A §4.10.5 — paging-structure coherence requirements for
  multi-processor systems.
