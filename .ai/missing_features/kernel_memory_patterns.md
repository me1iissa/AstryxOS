# Kernel Memory Management Patterns — Linux vs NT vs AstryxOS

## Reference Sources
- `SupportingResources/linux/kernel/fork.c` — thread stack allocation
- `SupportingResources/linux/Documentation/arch/x86/x86_64/mm.rst` — VA layout
- `SupportingResources/linux/arch/x86/mm/tlb.c` — CR3 switching
- `SupportingResources/linux/kernel/sched/core.c` — context_switch()
- `SupportingResources/reactos/ntoskrnl/mm/ARM3/procsup.c` — MmCreateKernelStack
- `SupportingResources/Microsoft-Windows-XP-Source-Kit/base/ntos/ke/i386/ctxswap.asm` — SwapContext
- `SupportingResources/Microsoft-Windows-XP-Source-Kit/base/ntos/mm/i386/mi386.h` — VA layout

---

## 1. Virtual Address Layout Comparison

### Linux x86_64 (4-level)
```
0000000000000000 – 00007fffffffefff  (~128 TB)  user space (per-process)
ffff888000000000 – ffffc87fffffffff  (64 TB)    direct mapping of ALL phys RAM (PAGE_OFFSET)
ffffc90000000000 – ffffe8ffffffffff  (32 TB)    vmalloc/ioremap (kernel stacks here)
ffffffff80000000 – ffffffff9fffffff  (512 MB)   kernel text (__START_KERNEL_map)
```

### NT/Windows XP x86
```
00000000 – 7FFEFFFF  user space (per-process)
80000000 – BFFFFFFF  kernel code + data (shared)
C0000000 – C03FFFFF  self-mapped page tables
E1000000 – FBFFFFFF  system PTE area (kernel stacks, MDLs)
```

### AstryxOS x86_64
```
0000000000000000 – 00007fffffffffff  user space (per-process, PML4[0])
FFFF800000000000 – FFFF800000100000  (kernel virt base → +1MiB)
FFFF800000100000 – ...               kernel text + data (KERNEL_VIRT_OFFSET + KERNEL_PHYS_BASE)
FFFF800000800000 – ...               kernel heap (128 MiB)
```

**Gap vs Linux**: AstryxOS keeps an identity map in PML4[0] alongside user mappings. Linux discards the identity map after boot. This caused the Session 37 double-fault (UEFI bootstrap stack in identity-mapped PML4[0] became unmapped when CR3 switched to user page table).

---

## 2. Kernel Stack Management

### Linux
- **vmalloc-backed**: `alloc_thread_stack_node()` uses `__vmalloc_node_range()` in the vmalloc region (0xffffc90000000000)
- **Size**: THREAD_SIZE = 16 KiB (4 pages) on x86_64
- **Guard**: No explicit guard page in the vmalloc allocation; VMAP_STACK config enables vmalloc-based stacks with implicit guard
- **Caching**: Dead stacks cached per-CPU via `cached_stacks[]` and reused via RCU
- **Canary**: `STACK_END_MAGIC` (0x57AC6E9D) written at bottom of each stack
- **Key invariant**: ALL kernel stacks are in vmalloc space (higher-half). Never identity-mapped.

### NT/Windows
- **System PTE area**: Stacks allocated from system PTE region (0xE1000000+)
- **Size**: 12 KiB committed (3 pages), up to 64 KiB reserved for GUI threads
- **Guard page**: Explicit guard page between committed and reserved (auto-expand on fault)
- **Dead stack pool**: `MmDeadStackSListHead` — interlocked S-LIST, up to 5 cached stacks
- **Lazy commit**: Only commits first 12 KiB; `MmGrowKernelStackEx()` expands on demand
- **Stack switch**: `KiSwitchKernelStack()` copies old stack to new, updates TSS.RSP0 + PCR.RspBase
- **Key invariant**: ALL kernel stacks are in kernel VA space (≥0x80000000). Never user-accessible.

### AstryxOS (current)
- **PMM-allocated + KERNEL_VIRT_OFFSET**: `phys_stack = pmm::alloc_pages(16)`, `stack_base = KERNEL_VIRT_OFFSET + phys`
- **Size**: 64 KiB (16 pages) — larger than both Linux (16K) and NT (12K committed)
- **Guard**: None for kernel stacks (user stacks have PROT_NONE guard since Session 36)
- **Caching**: Dead stacks freed immediately by `reap_dead_threads_sched()` via PMM
- **Canary**: None
- **Key fix (Session 37)**: TID 0 now gets a PMM-allocated higher-half stack + two-phase CR3 switch

---

## 3. CR3 Switching Patterns

### Linux (`context_switch` in kernel/sched/core.c)
```c
// Order: MM switch THEN register switch
if (!next->mm) {
    enter_lazy_tlb(prev->active_mm, next);  // kernel thread: keep old CR3
} else {
    switch_mm_irqs_off(NULL, next->mm, tsk);  // user thread: switch CR3
}
switch_to(prev, next, prev);  // register/stack switch
```
- CR3 switch happens BEFORE stack switch
- Safe because all kernel stacks are in vmalloc (higher-half, shared across all page tables)
- Kernel threads use "lazy TLB" — they reuse the previous user process's CR3

### NT (`SwapContext` in ke/i386/ctxswap.asm)
```asm
; Inside SwapContext — AFTER saving old regs, BEFORE loading new stack
mov eax, [edi]+PrDirectoryTableBase  ; new process CR3
mov [ebp]+TssCR3, eax                ; sync TSS
mov cr3, eax                         ; switch address space
; ... then load new thread's kernel stack
```
- CR3 switch happens INSIDE SwapContext (between save and restore)
- Safe because kernel stacks are in system PTE area (always kernel-accessible)

### AstryxOS (Session 37 fix)
```
Phase 1 (before switch_context): switch to kernel_cr3  ← ensures identity map present
Phase 2 (after switch_context):  switch to incoming thread's process CR3
```
- Two-phase approach needed because TID 0's bootstrap stack is identity-mapped
- Performance cost: 2 CR3 switches (2 TLB flushes) vs Linux/NT's 1
- **Future optimization**: migrate TID 0 to a proper higher-half stack, then revert to single-phase

---

## 4. Recommended Hardening for AstryxOS

### Priority A (should do now)
1. **Stack canary** — Write `0x57AC6E9D` at bottom of each kernel stack in `create_*_thread`. Check in schedule() or exit_thread() for overflow detection.
2. **Page table walks via KERNEL_VIRT_OFFSET** — Change `virt_to_phys_in()` to use `(KERNEL_VIRT_OFFSET + phys) as *const u64` instead of `phys as *const u64`. Eliminates dependency on identity map.

### Priority B (should do soon)
3. **Dead stack caching** — Maintain per-CPU `Vec<u64>` of freed kernel stack physical pages. Reuse on next `create_thread` instead of hitting PMM.
4. **Lazy TLB for kernel threads** — When incoming thread is pid=0 (kernel/idle), skip CR3 switch entirely. Matches Linux pattern.
5. **Single-phase CR3 switch** — Migrate TID 0 to a proper higher-half stack (via trampoline in kernel_main), then revert schedule() to single CR3 switch before switch_context.

### Priority C (long-term)
6. **Remove identity map** — After boot setup, unmap PML4[0] from kernel page table. Forces all kernel code to use KERNEL_VIRT_OFFSET addresses. Any accidental physical-address access would immediately fault instead of silently succeeding.
7. **vmalloc-backed kernel stacks** — Allocate kernel stacks from a dedicated virtual region (like Linux's vmalloc area) with per-stack guard pages. Catches stack overflow via #PF instead of silent corruption.
