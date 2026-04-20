# Memory Management Gaps

> Reference: Windows XP `base/ntos/mm/` (81 C files), Linux `mm/` (202 C files)
> AstryxOS: `mm/vma.rs`, `mm/vmm.rs`, `mm/pmm.rs`, `mm/heap.rs`, `mm/refcount.rs`, `mm/cache.rs`

---

## What We Have

- Physical page bitmap allocator (4 KiB pages, up to 4 GiB tracking)
- 4-level x86_64 page table walker (map/unmap/query)
- Virtual Memory Area (VMA) struct: base, length, flags, backing (anon/file/device)
- VMA insertion/search/removal via sorted Vec in VmSpace
- Page protection flags: PROT_READ/WRITE/EXEC, PAGE_USER/WRITABLE/NO_EXECUTE
- Kernel heap at virtual 0xFFFF_8000_0080_0000, 128 MiB
- Per-process CR3 with shallow kernel PML4 half-copy (PML4[256-511])
- Page refcount table in `refcount.rs` (per-physical-frame u16 counters)
- PMM `alloc_pages(n)` / `free_page(phys)` with Option<u64> return

---

## Missing (Critical)

### CoW Page Faults
**What**: When a process forks with `MAP_PRIVATE`, both parent and child share the same physical
pages read-only. On first write, the #PF handler must allocate a new frame, copy the content, remap,
and decrement the old refcount.

**Why critical**: Without CoW, `fork()` is either a full page copy (expensive, breaks under memory
pressure) or sharing (parent/child corrupt each other). musl/libc `fork()` requires CoW.

**Reference**: `linux/mm/memory.c` (`do_wp_page`, `wp_page_copy`);
Windows NT copy-on-write (`MiCopyOnWrite`) — see ReactOS `ntoskrnl/mm/ARM3/pagfault.c` or NT Internals docs

---

### Demand Paging (Lazy Allocation)
**What**: `mmap(MAP_ANONYMOUS)` should not allocate physical pages at call time — only on first
access (page fault). Current code pre-allocates pages at mmap time.

**Why critical**: Large processes (Firefox ~200 MB RSS) with pre-allocation would exhaust physical
RAM immediately. Lazy alloc is the only viable model.

**Reference**: `linux/mm/memory.c` (`do_anonymous_page`);
Windows NT demand-zero fault handling (`MiResolveDemandZeroFault`) — see ReactOS `ntoskrnl/mm/ARM3/pagfault.c`

---

### Stack Growth (Guard Pages)
**What**: User stacks start small and grow downward on demand. A guard page below the current stack
triggers a fault; the kernel extends the stack VMA and allocates the new page.

**Why critical**: musl default stack is 8 MiB but only the top few pages are touched initially.
Without guard-page growth, any function with deep recursion or large stack frames will fault and die.

**Reference**: `linux/mm/mmap.c` (`expand_stack`);
Windows NT user-stack overflow handling (`MiCheckForUserStackOverflow`) — see ReactOS `ntoskrnl/mm/ARM3/pagfault.c`

---

### Proper `mprotect()` Implementation
**What**: `mprotect(addr, len, prot)` must walk the VMA list, split VMAs at boundaries, and update
actual PTE flags for every mapped page in the range. Currently it just updates the VMA struct flags
without updating the hardware PTEs.

**Why critical**: JIT compilers (Firefox SpiderMonkey) use `mprotect(PROT_NONE)` → write → `mprotect(PROT_EXEC)`
to create executable code. Without hardware PTE updates, the code stays writable or non-executable.

**Reference**: `linux/mm/mprotect.c` (`mprotect_fixup`, `change_pte_range`);
`reactos/ntoskrnl/mm/ARM3/virtual.c` (NtProtectVirtualMemory)

---

## Missing (High)

### Page Cache (File-backed Pages)
**What**: A global radix-tree/XArray mapping (inode, offset) → physical page. File reads populate
the cache; subsequent reads return cached pages. Writes mark pages dirty for writeback.

**Why high**: Without a page cache, every `read()` copies from disk; `mmap()` of file-backed regions
can't share pages between processes that map the same file. Firefox reads shared libraries repeatedly.

**Reference**: `linux/mm/filemap.c` (2,500 LOC); `reactos/ntoskrnl/cc/` (`CcMapData`, `CcPinRead`)

---

### TLB Shootdown (SMP Safety)
**What**: When any CPU unmaps or changes a page, all CPUs holding that address in their TLB cache
must be notified via IPI (Inter-Processor Interrupt) to flush it.

**Why high**: On SMP (-smp 2), a `munmap()` on CPU 0 leaves the stale mapping in CPU 1's TLB.
CPU 1 can access freed memory, causing silent data corruption or use-after-free.

**Reference**: `linux/arch/x86/mm/tlb.c` (`flush_tlb_others`);
Windows NT TLB-flush architecture (`MiFlushTbAndCapture`) — see ReactOS `ntoskrnl/mm/` or NT Internals docs

---

### Huge Pages (2 MiB / 1 GiB)
**What**: Map large contiguous regions using 2 MiB PDE entries instead of 4 KiB PTEs. Reduces
TLB pressure dramatically for large allocations (kernel heap, shared libraries, framebuffer).

**Reference**: `linux/mm/huge_memory.c`; `linux/arch/x86/mm/hugetlbpage.c`

---

### Memory Pressure & Reclaim
**What**: When physical RAM is low, the kernel must evict clean pages (discard), write dirty
anonymous pages to swap, or kill a low-priority process (OOM killer). Without this, the kernel
panics or hangs when RAM is exhausted.

**Reference**: `linux/mm/vmscan.c` (`shrink_node`, `reclaim_clean_pages`);
Windows NT working-set trimming — see ReactOS `ntoskrnl/mm/` or NT Internals docs

---

### `madvise()` — Advisory Hints
**What**: Programs tell the kernel how they'll use a region (MADV_SEQUENTIAL, MADV_WILLNEED,
MADV_DONTNEED, MADV_FREE, MADV_HUGEPAGE). Firefox uses MADV_DONTNEED to release memory.

**Reference**: `linux/mm/madvise.c`; syscall 28 / `madvise(2)`

---

### `mremap()` — Remap Mapping
**What**: Resize or move an existing mmap region atomically. musl `realloc()` for large allocations
can use mremap to avoid copy. Firefox heap management uses this.

**Reference**: `linux/mm/mremap.c` (`sys_mremap`); syscall 25

---

## Missing (Medium)

| Feature | Description | Reference |
|---------|-------------|-----------|
| `mincore()` | Query which pages are resident in RAM | `linux/mm/mincore.c` |
| `mlock()` / `munlock()` | Pin pages in RAM, prevent eviction | `linux/mm/mlock.c` |
| `msync()` | Flush dirty mmap pages to backing file | `linux/mm/msync.c` |
| Memory-mapped files | True mmap of file contents, not just anon | `linux/mm/filemap.c` |
| ASLR | Randomize stack/heap/mmap base | `linux/mm/mmap.c` (`arch_mmap_rnd`) |

---

## Missing (Low)

| Feature | Description |
|---------|-------------|
| Swap (page out to disk) | `linux/mm/swap.c`, `linux/mm/swapfile.c` |
| Memory cgroups | Per-group limit enforcement |
| KSM (Kernel Samepage Merging) | Dedup identical anonymous pages |
| Huge page transparent (THP) | Auto-promote pages to 2 MiB |
| NUMA | Multi-node affinity, interleave policy |

---

## Implementation Notes

The hardest change is the **page fault handler rewrite**. Currently `mm/vmm.rs` has a trivial
`#[no_mangle] pub extern "C" fn page_fault_handler` stub. The full handler needs to:
1. Check if fault address is in any VMA (if not → SIGSEGV)
2. If CoW fault: allocate new frame, copy, remap writable, decrement shared refcount
3. If demand zero: allocate zeroed frame, map at fault address
4. If stack growth: extend stack VMA downward (up to RLIMIT_STACK)
5. If file-backed: bring page in from page cache (or disk if cold)

The refcount table in `mm/refcount.rs` is already in place — build CoW on top of that.
