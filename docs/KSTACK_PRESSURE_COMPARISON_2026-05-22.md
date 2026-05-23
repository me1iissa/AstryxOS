# brk-path kernel-stack pressure — AstryxOS vs the reference Unix model

Investigation timestamp: 2026-05-22.  Scope: narrow PR #394 §B
hypothesis **H1** ("the `brk` syscall path overflows the 4 KiB emergency
kernel stack when a thread is unlucky enough to run on the PMM-fragmented
fallback") by *quantifying* how much kernel stack the `brk`-extending
path consumes in AstryxOS, and comparing that consumption against a
mature reference Unix that handles the same syscall on the same x86_64
ABI but with a different VMA representation and lock primitive.

## TL;DR

H1 is **strongly supported**: AstryxOS's `brk`-shrink path is *itself*
larger than the 4 KiB emergency kernel stack, before any caller frame is
counted.  A single stack-resident array inside
`mm::vmm::unmap_and_free_range_in` (`let mut to_free = [0u64; 1024];`,
**8192 bytes**) is more than twice the entire emergency span.  Even the
`brk`-extend path, which avoids the unmap loop, lands at roughly the
same total depth as the reference path — but with no headroom: any
4 KiB-only thread that ends up taking the shrink arm of `sys_brk` is
guaranteed to push the bottom-of-stack canary off the page.

The reference path of comparable shape, in contrast, uses a single
fixed-size embedded munmap descriptor on the stack and pushes all bulk
work into heap-allocated maple-tree nodes.  Its worst case is ~3 KiB
total kernel-stack consumption, leaving a comfortable margin under the
typical 16 KiB thread-stack budget on x86_64 — and still fitting *twice*
into a hypothetical 4 KiB emergency span.

## Method

### What is counted

For each frame we counted, in order of contribution:

1. **Static frame size from explicit local arrays**, e.g.
   `[u64; 1024]` = 8192 bytes.  These are the dominant contribution to
   any stack-frame measurement and are read directly from the Rust /
   C source.
2. **Saved-register and locals area**, estimated at 64 bytes per Rust
   function that takes a handful of u64/usize locals plus a few pointer
   spills, 32 bytes for a leaf or single-local Rust function, and
   16 bytes for the System V AMD64 return-address + saved-rbp pair.
   These figures are conservative upper bounds; LLVM may inline or
   merge slots in practice.
3. **Guard objects** held across the frame, e.g. `SpinMutexGuard`
   (16 bytes: two pointers per the `spin` 0.9.8 layout) or
   `RwLock` read-guards of similar shape.
4. **Syscall-entry assembly frame**: at the `syscall` instruction
   AstryxOS pushes 13 registers (rdi, rsi, rdx, r8, r9, r10, r15, r14,
   r13, r12, rbx, rbp, r11) followed by user-RIP and user-RSP, plus an
   8-byte alignment slot and a 7th-arg stack slot for `dispatch()` —
   **112 bytes** of fixed frame before any Rust handler runs.

### What is NOT counted

* Interrupt frames pushed by the CPU prior to syscall entry (the
  `syscall` instruction itself does not push a frame; SWAPGS-style
  entry stashes saved RSP/RIP into the per-CPU area, not the stack).
* TLB-shootdown-handler frames on *target* CPUs: those run on each
  target's own kernel stack, not the syscall caller's stack.
* The brief stack consumed by `core::hint::spin_loop()` inside the
  shootdown ACK spin — it is a single `pause` instruction, no frame.

### Confidence

Frame-size numbers are read from source (arrays) and estimated
(saved-register area).  They are not derived from `objdump --disassemble`
because the relevant cargo profile flags (`opt-level = 3`,
`overflow-checks = on`, `debug-assertions = off` for release) match
production builds but may inline aggressively; the +/- on each frame
estimate is roughly **±32 bytes** from inlining decisions LLVM makes
during real builds.  The dominant `[u64; 1024]` slot is exact.

## AstryxOS `sys_brk` frame chain

Source files (all under `kernel/src/`):

* `syscall/mod.rs` — `sys_brk` (line 2776)
* `mm/vma.rs` — `VmSpace::adjust_brk` (line 1158), `insert_vma`
  (line 937)
* `mm/vmm.rs` — `unmap_and_free_range_in` (line 680), `unmap_page_in`
  (line 599)
* `mm/tlb.rs` — `shootdown_range` (line 450),
  `shootdown_range_inner` (line 475)
* `proc/mod.rs` — `alloc_kernel_stack` (line 545) — the emergency
  fallback that returns a 4 KiB span

### Extend path (`new_brk > self.brk`)

| Frame | Locals / arrays | Guards | Est. bytes |
|---|---|---|---|
| syscall asm entry stub | 13 saved regs + alignment + arg6 slot | — | **112** |
| `dispatch` | num + 6 args spill, jump-table residue | — | 64 |
| `dispatch_linux` → `dispatch_body` arm 12 | tail-call shape | — | 32 |
| `sys_brk` | `pid`, `procs` guard, `proc` ref, `space` ref | `SpinMutexGuard<PROCESS_TABLE>` (16) | 96 |
| `VmSpace::adjust_brk` | aligned `new_brk`, `heap_vma` iter cursor | — | 48 |
| `VmSpace::insert_vma` | `pos` cursor, overlap-check iter | — | 48 |
| **Extend-path total** | | | **~400 B** |

The `PROCESS_TABLE` Mutex guard is held across the whole `adjust_brk`
invocation; the contained `proc` reference borrows from it.  No other
guards are held across the chain.  No stack arrays of any size appear
on the extend path.

### Shrink path (`new_brk < self.brk`) — the H1 candidate

| Frame | Locals / arrays | Guards | Est. bytes |
|---|---|---|---|
| syscall asm entry stub | as above | — | **112** |
| `dispatch` / `dispatch_linux` / `dispatch_body` | as above | — | **96** |
| `sys_brk` | as above | `SpinMutexGuard<PROCESS_TABLE>` (16) | 96 |
| `VmSpace::adjust_brk` | `old_brk`, `heap_vma` iter | — | 48 |
| `mm::vmm::unmap_and_free_range_in` | **`to_free: [u64; 1024]` (8192)**, `freed`, `pg`, `end`, `batch_start`, `n`, `_mm_guard`, `_mm_read` | `Option<Arc<RwLock<()>>>` + `Option<RwLockReadGuard<()>>` ≈ 32 | **8272** |
| `mm::vmm::unmap_page_in` (per page, leaf) | 4 page-walk indices, optional `old_phys_for_ring` | `SpinMutexGuard<VMM_LOCK>` (16) + `RwLock` read-guard pair (~32) | 96 |
| `mm::tlb::shootdown_range_inner` | `self_cpu`, `self_mask`, `targets`, `remaining`, `iters`, `t`, `r`, `bit`, `still`, optional `late_cpus: [u8; 8]` (firefox-test only, +8) | — | 80 |
| `mm::tlb::local_invlpg_range` | `lo`, `hi`, `pages`, `p` | — | 48 |
| **Shrink-path total (firefox-test off)** | | | **~8 848 B** |
| **Shrink-path total (firefox-test on)** | adds `[u8; 8]` in shootdown + diag in unmap_page_in | | **~8 880 B** |

The shrink path's stack footprint is dominated by the 8 KiB `to_free`
array inside `unmap_and_free_range_in`.  The remaining frames
collectively account for ~600 bytes.  Even if the entire 8 KiB array
were optimised away (it cannot be — it is read across the
shootdown/free pass split), the remaining frames still consume
~700–800 bytes, leaving ~3 KiB of headroom in a 4 KiB stack — about the
same headroom as the reference path's worst case.

### Locking — `spin::Mutex` versus a sleeping rwsem

The `spin` 0.9.8 `SpinMutex::lock()` is a `compare_exchange_weak` loop
with `core::hint::spin_loop()` on contention; the returned
`SpinMutexGuard` is two pointers (16 bytes).  No stack-allocated
waiter, no callbacks, no per-CPU scratch — `lock()` itself runs entirely
in registers on the fast path.  This is good for stack but bad for
latency under contention; the brk path takes `PROCESS_TABLE` (global)
and `VMM_LOCK` (global, per-page in the inner loop), so a contended
shrink spins on the lock while still holding 8 KiB of stack live.

The `RwLock` used by `mm_sem_for_cr3` is the `spin` crate's `RwLock`,
same family — `read()` returns a `RwLockReadGuard` of similar size
(pointer + atomic count clone).  Three guards may be live
simultaneously inside the shrink loop:

* The `PROCESS_TABLE` Mutex guard (from `sys_brk`),
* The optional `Arc<RwLock<()>>` + its read guard from
  `unmap_and_free_range_in` (the per-cr3 `mm_sem`),
* The inner `Arc<RwLock<()>>` + its read guard re-acquired in
  `unmap_page_in` for each page.

The inner-loop guard is allocated once per `unmap_page_in` call, so it
churns through the stack rather than accumulating; total live guard
footprint stays under 100 bytes.

## Reference path frame chain (for comparison)

The mature reference Unix implementation of `brk(2)` on x86_64 follows
a recognisably similar shape but with two structural differences that
dominate the stack accounting:

1. **The unmap descriptor is a single embedded struct on the stack**
   (one `vma_munmap_struct`, a few `unsigned long`s, and an on-stack
   tree-iterator struct — together well under 256 bytes).
   Bulk per-page work happens *behind a heap-allocated tree*, not in
   a stack-resident batch buffer.
2. **The address-space lock is a sleeping rwsem** whose write fast
   path is a single `atomic_long_try_cmpxchg_acquire`, no stack-frame
   growth at all — the slow path moves to a wait queue rather than
   spinning.

### Extend path

| Frame | Locals / arrays | Est. bytes |
|---|---|---|
| syscall entry + dispatch_64 | per-arch entry stub + saved regs | ~256 |
| `__do_sys_brk` | `newbrk`, `oldbrk`, `origbrk`, `min_brk`, `populate`, `uf` list head, `vmi` iterator struct, `next`, `brkvma` | ~256 |
| `mmap_write_lock_killable` → `down_write_killable` → `__down_write_common` fast path | leaf CAS, no locals | 16 |
| `do_brk_flags` | `vm_flags`, `vmg` (VMG_STATE on stack — a tagged struct), `vma` ref | ~256 |
| `vma_merge_new_range` / `vm_area_alloc` (heap alloc, no stack array) | small | 96 |
| **Extend-path total** | | **~880 B** |

### Shrink path

| Frame | Locals / arrays | Est. bytes |
|---|---|---|
| syscall entry + dispatch_64 | as above | ~256 |
| `__do_sys_brk` | as above | ~256 |
| `mmap_write_lock_killable` fast path | leaf CAS | 16 |
| `do_vmi_align_munmap` | `mt_detach` (maple-tree root on stack), `mas_detach` state, `vms`, `error` | ~512 |
| `vms_gather_munmap_vmas` (iterator-driven, descends into per-VMA work via heap nodes) | small per-frame | ~256 |
| `vms_complete_munmap_vmas` | per-batch TLB tracking (per-CPU work, not on syscall stack), few locals | ~256 |
| **Shrink-path total** | | **~1 552 B** |

Worst-case real-world depth (the heaviest path is the shrink path with
a contended VMA tree split): roughly **3 KiB** including the deepest
helper.  That is well under half of a 4 KiB emergency stack, and is
the design target — the reference path deliberately keeps the embedded
state small and offloads any unbounded work into heap-resident
structures.

## Per-system measurement table

| System / path | Frame chain | Max single frame | Total est. bytes |
|---|---|---|---|
| AstryxOS `sys_brk` **extend** | asm-entry → dispatch → dispatch_linux → dispatch_body → sys_brk → adjust_brk → insert_vma | 112 (asm entry) | **~400** |
| AstryxOS `sys_brk` **shrink** | asm-entry → dispatch → dispatch_linux → dispatch_body → sys_brk → adjust_brk → unmap_and_free_range_in → {unmap_page_in, shootdown_range_inner} | **8 272 (unmap_and_free_range_in, holds `[u64; 1024]`)** | **~8 848** |
| Reference Unix `brk` **extend** | syscall-entry → __do_sys_brk → mmap_write_lock_killable (CAS) → do_brk_flags → vma_merge_new_range | ~256 (do_brk_flags + VMG_STATE) | ~880 |
| Reference Unix `brk` **shrink** | syscall-entry → __do_sys_brk → mmap_write_lock_killable (CAS) → do_vmi_align_munmap → vms_gather/vms_complete (heap-driven) | ~512 (do_vmi_align_munmap with on-stack `mt_detach`) | ~1 552 |

## Implication for hypothesis H1

H1 from PR #394 §B asks: "could the `brk` syscall handler, when run on
a 4 KiB emergency kernel stack, plausibly overflow that stack and
corrupt the bottom-of-stack canary?"

The shrink path's static frame for `unmap_and_free_range_in` alone is
**8 192 bytes** for the `to_free` array, plus locals and guards.  Even
without counting any caller frame, that is **2.0× the entire 4 KiB
emergency stack**.

Even the *extend* path, which never reaches `unmap_and_free_range_in`,
sits at ~400 bytes total before any sub-helper allocates anything.  An
extend that triggers `insert_vma` and then takes an unrelated reschedule
inside the `PROCESS_TABLE` guard — pushing a scheduler frame — would
not overflow 4 KiB by itself, but the shrink-path overflow is an
unconditional architectural guarantee, not a probabilistic event.

The PMM-fragmented emergency-fallback thread therefore cannot safely
execute any `sys_brk` shrink request.  Two follow-on observations:

1. The diagnostic at `proc::mod.rs:568-575`
   (`[KSTACK/EMERGENCY] base=… size=4K`) correctly identifies threads
   running on the 4 KiB span, and the `[KSTACK/EMERGENCY-THREAD]`
   companion line tags subsequent syscall traces, so an
   `unmap_and_free_range_in` invocation from such a thread is
   recognisable in the serial log.
2. The 8 KiB `[u64; 1024]` batch buffer is deliberately stack-resident
   (per the comment at `mm/vmm.rs:681-684`) to avoid allocator
   dependence in the unmap path — the allocator may itself need to
   unmap memory.  The pre-existing design assumption is that
   `KERNEL_STACK_SIZE` (the contiguous-allocation success path) leaves
   ample headroom; the emergency-fallback path silently violates that
   assumption.

## Recommended next steps (orthogonal — not part of this doc)

* A reasonable narrowing of H1 is to gate the emergency-fallback
  thread against any syscall that calls into `unmap_and_free_range_in`
  (`munmap`, `mremap`, `brk`-shrink, `exit_mm`).  This could be a
  per-thread "thin kernel stack" flag that, when set, causes those
  syscalls to return `-ENOMEM` rather than risk an overflow.
* A more permanent fix is to shrink the `BATCH` constant in
  `mm/vmm.rs` from `1024` (8 KiB) down to e.g. `128` (1 KiB),
  trading 8× more shootdown IPIs in the unmap loop for a frame size
  that fits a 4 KiB stack.  The performance impact is one shootdown
  per 128 pages = ~512 KiB of unmap — still cheap relative to the
  syscall round-trip cost.
* Long-term, a vmalloc-style virtual mapping for kernel stacks would
  eliminate the PMM-fragmentation failure mode entirely and remove the
  need for an emergency-fallback path — already noted as future work
  at `proc::mod.rs:566-567`.

These suggestions are scope notes only; they are not implemented as
part of this comparison document.

## Citations

* `brk(2)` man page —
  https://man7.org/linux/man-pages/man2/brk.2.html
* POSIX.1-2017 (IEEE Std 1003.1-2017), `<unistd.h>` brk/sbrk rationale —
  https://pubs.opengroup.org/onlinepubs/9699919799/functions/brk.html
* Intel® 64 and IA-32 Architectures Software Developer's Manual,
  Vol. 3A, §4.10.4 ("Invalidation of TLBs and Paging-Structure
  Caches") and §4.10.5 ("Propagation of Paging-Structure Changes to
  Multiple Processors") — for the TLB-shootdown ordering invariant
  that motivates the 8 KiB batch buffer in
  `unmap_and_free_range_in`.
* System V Application Binary Interface, AMD64 Architecture Processor
  Supplement (1.0+), §3.2.2 ("The Stack Frame") and §3.4 ("Process
  Initialization") — for the saved-register-area conventions used in
  the frame-size estimates above.
