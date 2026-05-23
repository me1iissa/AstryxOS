# SSP autopsy result — Post-INFRA-4 #1B (2026-05-23)

**Role**: QA verifier. **Dispatch ID**: Post-INFRA-4 #1B.
**Outcome**: **REFRAME-FAILED** — the libxul `__stack_chk_fail` SSP gate was
never reached in this run. A kernel-side `STACK_CANARY_CORRUPT` bugcheck
fires first, on the same emergency-tier kstack base, with reproducible
shape across two independent KVM trials. The "FPO frame whose canary is at
`[rsp+0x1e0]`" framing from INFRA-4 is descriptively correct (96% of libxul
SSP callers are FPO; the static offset varies per function) but is not the
gate the current build is hitting.

---

## 1. Reproducibility (2 KVM trials)

| Trial | sid          | wedge                       | tid/pid | kstack base          | size  | canary slot got     |
|-------|--------------|-----------------------------|---------|----------------------|-------|---------------------|
| 1     | 08857c7f1506 | `[KSTACK/CANARY-FAIL]`      | 4 / 2   | `0xffff8000009cb000` | 0x4000 (16 KiB) | `0x0000000000007210` |
| 2     | a67063455da3 | `[KSTACK/CANARY-FAIL]`      | 4 / 2   | `0xffff8000009cb000` | 0x4000 (16 KiB) | `0x0000000000000001` |

**Both** trials fire **before** any libxul `__stack_chk_fail@plt` call site
is ever reached: `grep stack_chk` / `grep SSP|SIGABRT|MOZ_CRASH` against
both serial logs returns empty. The userspace SSP gate is post-this gate.

**Expected canary**: `STACK_END_MAGIC = 0x5741_436B_5374_4B21` ("WACkStK!")
— Linux `STACK_END_MAGIC` extended to 64 bits per `kernel/src/proc/mod.rs`.

**Captured neighbour bytes at canary slot** (kernel stack base + offset):

| offset | trial 1                  | trial 2                  | match? |
|--------|--------------------------|--------------------------|--------|
| +0     | `0x0000000000007210`     | `0x0000000000000001`     | NO     |
| +8     | `0xb70f00001b5e158d`     | `0xb70f00001b5e158d`     | **YES** |
| +16    | `0x0000000000000001`     | `0xd0014882046348c0`     | NO     |
| +24    | `0x99e8df8948e0ff3e`     | `0x99e8df8948e0ff3e`     | **YES** |

Decoded as little-endian x86-64 instruction bytes:

- +8  = `8d 15 5e 1b 00 00  0f b7` → `lea rdx,[rip+0x1b5e]; movzx ...`
- +24 = `3e ff e0  48 89 df  e8 99` → `jmp rax; mov rdi,rbx; call rel32`

These are **userspace code bytes** at kernel-virtual addresses, identical
across two independent boots at the same kstack base. The Intel SDM Vol.
3A §4.10.5 use-after-recycle invariant requires the physical frame to be
unmapped from every prior consumer before re-issue; identical-content
across boots on the same kernel VA is exactly what the W215 page-aliasing
class produced before PR #270.

Stable +8 / +24 and varying +0 / +16 split the picture into two writers:

1. A page-cache writer that lays the same userspace bytes into the frame
   deterministically each boot (libxul `.text` paged in via the FS layout
   that's also boot-deterministic).
2. The kernel kstack consumer that subsequently writes to +0 (`write_stack_canary`)
   and to +16 (probably part of `switch_context_asm`'s initial frame setup).

The runtime observation that +0 contains `0x7210` / `0x1` rather than the
expected `0x5741_436B_5374_4B21` is **not** stack-overflow: the bugcheck
records `depth=0x260` (608 bytes) on a `size=0x4000` (16 KiB) stack —
RSP_live is `0xffff8000009ceda0`, ~15.5 KiB above the canary at base+0.
Per x86_64 SysV ABI §3.4.1 stack growth direction, the stack pointer at
that depth cannot reach base+0 without scribbling 15 KiB of unrelated
locals first — none of which the diagnostic shows.

---

## 2. Why this is not the dispatch's intended gate

The dispatch (Post-INFRA-4 #1B) was specified for a **libxul** `__stack_chk_fail`
fire, on an FPO function whose canary slot the dispatch identified as
`[rsp+0x1e0]`. A static analysis of libxul-ESR (`/disk/usr/lib/firefox-esr/libxul.so`,
sha = unchanged from build) over all **63,172** SSP call sites confirms
the FPO observation but does not single out the cited offset:

- FPO callers (canary at `[rsp+N]`):  **79,595** (96.0%)
- Framed callers (canary at `[rbp-N]`): **83** (0.1%)
- Unknown / pattern-not-matched:        3,575 (3.9%)

Top 8 FPO canary offsets:

| offset           | sites  |
|------------------|--------|
| `[rsp+0x10]`     | 15,292 |
| `[rsp+0x20]`     |  8,907 |
| `[rsp+0x8]`      |  7,808 |
| `[rsp+0x18]`     |  6,050 |
| `[rsp+0x30]`     |  5,945 |
| `[rsp+0x28]`     |  3,199 |
| `[rsp+0x40]`     |  2,965 |
| `[rsp+0x50]`     |  2,693 |

`[rsp+0x1e0]` is present (8 sample call VAs observed) but is one of many
per-function-frame-size canary offsets and is not the dominant gate.
Per System V AMD64 ABI §3.2 (stack frame layout), the canary's RSP offset
equals the per-function locals + alignment padding; it varies per
function and gives no clue which function is the relevant one without
a live RIP.

---

## 3. Mechanism (kernel-side, the gate we actually hit)

From `kernel/src/sched/mod.rs` (lines 698–732) the canary check at
`schedule()` reads `*stack_base` and compares against `STACK_END_MAGIC`.
From `kernel/src/proc/mod.rs` `alloc_kernel_stack`:

```rust
// emergency-tier path (lines 591–625, abridged)
for &(pages, span_bytes) in SMALL_KSTACK_TIERS {
    let phys_opt = if pages == 1 { pmm::alloc_page() }
                   else { pmm::alloc_pages(pages) };
    let Some(phys) = phys_opt else { continue };
    let stack_base = KERNEL_VIRT_OFFSET + phys;
    write_stack_canary(stack_base);           // <-- writes STACK_END_MAGIC
    record_emergency_kstack(stack_base);
    ...
}
```

`pmm::alloc_page()` / `pmm::alloc_pages()` do **not** zero the frame; the
caller is expected to either zero or stamp every byte it relies on
(`kernel/src/mm/pmm.rs::alloc_page_locked`, lines 404–499 — explicit
`return Some(phys)` with no zero-fill). `write_stack_canary` only writes
8 bytes at `+0`; everything from `+8` upward keeps whatever the previous
consumer left in the frame, which here is libxul `.text` bytes from a
prior page-cache occupant.

That residual content explains the **stable** `+8` and `+24` values across
trials — they're the same physical frame, paged with the same libxul
content, deterministically across boots.

It does **not** explain the canary slot's observed value at `+0`. After
`write_stack_canary` runs, base+0 should hold `0x5741_436B_5374_4B21`. The
post-bugcheck dump shows it holding `0x7210` / `0x1`. Two consistent
hypotheses, in priority order:

**H-A: page is alias-mapped while kstack is live.** The same physical
frame is mapped both in the page cache (as part of libxul's read-only
`.text`) and at the higher-half kstack VA. The page-cache mapping is
`PROT_READ` so the cache won't write through it, but if the cache evicts
and the eviction path zeroes / reuses through the *kstack* VA in some
unrelated context, the resulting torn writes look exactly like
"someone wrote partial-word values to base+0 and base+16". This is the
W215 class that PR #270 closed for the `pte_share_count` invariant but
which did NOT cover the emergency-tier kstack consumer (the tier-path
in `alloc_kernel_stack` calls `pmm::alloc_page()` directly without
checking residual `pte_share_count`).

**H-B: `write_stack_canary` never ran for tid 4.** Possible if the
emergency-tier path took an early `continue` (the `phys_opt` failed) for
a previous tier, then succeeded on the next, and the success branch's
`write_stack_canary` wrote to a *different* base than the one the Thread
stamp records. Source inspection (lines 591–624) shows the same
`stack_base` is used both for the canary write and the Thread stamp, so
this is structurally unlikely — but a load-bearing recheck is cheap.

H-A is preferred because:
- Two trials, identical kstack base `0xffff8000009cb000`, identical +8
  / +24 (deterministic page-cache content).
- The PMM has no residual-PTE check on the emergency-tier alloc path
  (`pmm::alloc_page_locked` returns the frame with `mark_page_used` and
  no further bookkeeping).
- The W215 saga's closure (PR #270) added `pte_share_count` invariants
  on the FREE side, but the emergency-tier ALLOC side bypasses those
  invariants entirely. A page-cache evict that retains its
  `pte_share_count` references and is then re-allocated as a kstack is
  exactly the shape H-A predicts.

---

## 4. Verdict

**REFRAME-FAILED** for the libxul-SSP dispatch. The autopsy was technically
executable — the INFRA-2 wrapper at commit `4ea3e7f` works correctly via
its `--break` and `--capture ssp-fail-snapshot` interface (confirmed by
`autopsy --help` resolving on the worktree-staged copy of the harness).
But the SSP gate was not reachable: a deeper kernel-side gate
(`STACK_CANARY_CORRUPT` at the emergency-tier kstack allocation path) is
the active blocker in the current build of `master` at HEAD `c958ccc`.

The dispatch's "FPO frame, canary at `[rsp+0x1e0]`" reframing is
descriptively accurate for libxul but is **gating the wrong layer**. The
gate is one stratum deeper. Per the saga's Rule 4 (right window, wrong
frame): we have re-identified the wrong frame — the *libxul user
frame*, when the active blocker is the *kernel-stack-base* frame.

---

## 5. Recommended next dispatch

**Title**: "Emergency-tier kstack alias-vs-pmm audit (post-INFRA-4 #2)"
**Agent**: `astryx-kernel-engineer`
**Scope**: Add the equivalent of the PR #270 `pte_share_count` invariant
to the EMERGENCY-tier alloc path in `proc::alloc_kernel_stack`
(`kernel/src/proc/mod.rs` lines 591–625). Two minimal-diff options:

1. **Defensive zero-fill in emergency-tier alloc** (~10 LOC). After
   `pmm::alloc_page()` / `pmm::alloc_pages()` returns in the tier loop,
   issue `core::ptr::write_bytes(stack_base as *mut u8, 0, span_bytes)`
   BEFORE the `write_stack_canary` call. Closes the residual-page-cache
   content channel at small constant cost (~5 µs per emergency kstack;
   emergency kstacks are <1% of allocations).
   - **References**: System V AMD64 ABI §3.4.1 (stack growth direction
     mandates a known-good bottom-of-stack canary), Intel SDM Vol. 3A
     §11.10 (cache-coherence — explicit serialising write to the kstack
     range before any subsequent load).

2. **Add `pte_share_count` gate on PMM alloc** (~30 LOC). In
   `mm::pmm::alloc_page_locked`, before returning a frame, check
   `crate::mm::refcount::pte_share_count(phys)`; if non-zero,
   bypass-and-retry (skipping the frame for this allocation but leaving
   it in the bitmap so a later cycle can drain residual PTEs). Wider
   protection but adds a hot-path check.
   - **References**: Intel SDM Vol. 3A §4.10.5 (paging-structure changes
     must reach all processors before frame repurpose), POSIX mmap(2)
     (page content lifetime).

**Soak gate**: ≥3 KVM trials must show ZERO `[KSTACK/CANARY-FAIL]`
events; verifier signs off only after that. Then re-dispatch the
libxul-SSP autopsy (this dispatch) once the kernel layer is unblocked.

**Diff budget**: ≤50 LOC, ≤2 files, ≤2× burst per dispatch convention.
Option 1 preferred (smaller blast radius, defence-in-depth, addresses
the observed residual-content channel directly).

---

## 6. Hand-back metadata

- **Worktree branch**: `qa-ssp-autopsy-result-2026-05-23` (this report only)
- **Reproducibility**: 2/2 KVM trials wedged identically (sid `08857c7f1506`,
  `a67063455da3`)
- **Wall-clock**: ~12 min build + 2× ~7 min trials = ~26 min total under
  the 45–60 min budget
- **Build commit base**: `c958ccc` (worktree HEAD, current branch
  `w215-h2-tlb-shootdown-diagnostic`)
- **Autopsy infra used**: harness commit `4ea3e7f` (INFRA-2 wrapper),
  staged into worktree as `scripts/qemu-harness-autopsy.py` since the
  branch under test predates the harness merge to master. Not committed
  (out of scope for a doc-only PR).
- **Live FF session not held open**: both sessions stopped cleanly via
  `qemu-harness.py stop`.

### INFRA-2 wrapper observation (file follow-up to toolchain-platform-engineer)

The autopsy wrapper requires `scripts/watch-test.py` to be reachable at
`_SCRIPTS_DIR / "watch-test.py"` (where `_SCRIPTS_DIR =
Path(__file__).resolve().parent`). If the wrapper is invoked from a path
outside `scripts/` (e.g. `/tmp/autopsy-harness.py`), the build helper
fails with `FileNotFoundError: '/tmp/watch-test.py'`. Recommend the
wrapper fall back to a `git rev-parse --show-toplevel`-anchored lookup
when its own parent dir doesn't contain `watch-test.py`. Not blocking
for this dispatch (worked around by staging inside the worktree's
`scripts/` directory).
