//! Virtual Memory Area (VMA) Management
//!
//! Tracks virtual memory regions for each process's address space.
//! Each VMA describes a contiguous range of virtual pages with uniform
//! protection and backing.
//!
//! # Design
//! - `VmArea` — A single contiguous virtual memory region.
//! - `VmSpace` — Per-process virtual address space (owns a CR3 + VMA list).
//! - Operations: find, insert, remove, split, merge, page fault handling.
//!
//! VMAs are kept sorted by base address in a `Vec<VmArea>`. For the small
//! VMA counts typical of early OS use (<100), linear search is acceptable.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock, RwLockReadGuard};

/// VMA protection flags (mmap-compatible).
pub type VmProt = u32;
/// Page is readable.
pub const PROT_READ: VmProt = 1 << 0;
/// Page is writable.
pub const PROT_WRITE: VmProt = 1 << 1;
/// Page is executable.
pub const PROT_EXEC: VmProt = 1 << 2;
/// No access (guard page).
pub const PROT_NONE: VmProt = 0;

/// VMA mapping flags (mmap-compatible).
pub type VmFlags = u32;
/// Mapping is shared (writes visible to other mappers).
pub const MAP_SHARED: VmFlags = 1 << 0;
/// Mapping is private (copy-on-write).
pub const MAP_PRIVATE: VmFlags = 1 << 1;
/// Map at a fixed address (don't auto-pick).
pub const MAP_FIXED: VmFlags = 1 << 4;
/// Anonymous mapping (not file-backed).
pub const MAP_ANONYMOUS: VmFlags = 1 << 5;
/// Stack region (grows downward).
pub const MAP_STACK: VmFlags = 1 << 17;

/// What backs a VMA's pages.
#[derive(Debug, Clone)]
pub enum VmBacking {
    /// Anonymous memory (zero-filled on first access).
    Anonymous,
    /// File-backed mapping (inode + mount index + file offset).
    ///
    /// `elf_load_delta` encodes the difference between the ELF segment's
    /// page-aligned virtual address (`p_vaddr & !0xfff`) and its page-aligned
    /// file offset (`p_offset & !0xfff`), i.e.:
    ///
    ///   `elf_load_delta = (p_vaddr & !0xfff) - (p_offset & !0xfff)`
    ///
    /// This constant is zero for non-ELF mappings (anonymous mmap, heap, etc.)
    /// and for ELF segments where `p_vaddr == p_offset` (rare but valid).
    ///
    /// Given a runtime virtual address `va` inside this VMA:
    ///
    ///   `offset_in_file = backing.offset + (va - vma.base)`
    ///   `vaddr_in_elf   = offset_in_file + elf_load_delta`
    ///
    /// The `vaddr_in_elf` value is what addr2line and nm expect — it is the
    /// link-time virtual address, independent of load-time ASLR bias.
    ///
    /// See ELF-64 Object File Format §3 (Program Loading) for the relationship
    /// between `p_vaddr`, `p_offset`, and the runtime load address.
    File {
        mount_idx: usize,
        inode: u64,
        /// Page-aligned file offset of the first byte mapped by this VMA.
        offset: u64,
        /// `(p_vaddr_page - p_offset_page)` for ELF PT_LOAD segments; 0 otherwise.
        elf_load_delta: u64,
    },
    /// Device memory (framebuffer, MMIO) — never swapped, identity-mapped.
    Device {
        phys_base: u64,
    },
}

/// A Virtual Memory Area — one contiguous region in a process's address space.
#[derive(Clone)]
pub struct VmArea {
    /// Start virtual address (page-aligned).
    pub base: u64,
    /// Length in bytes (page-aligned).
    pub length: u64,
    /// Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC).
    pub prot: VmProt,
    /// Mapping flags (MAP_PRIVATE, MAP_SHARED, MAP_ANONYMOUS, etc.).
    pub flags: VmFlags,
    /// What backs this VMA.
    pub backing: VmBacking,
    /// Human-readable label for debugging (e.g., "[heap]", "[stack]", "libc.so").
    pub name: &'static str,
}

impl VmArea {
    /// End address (exclusive).
    pub fn end(&self) -> u64 {
        self.base + self.length
    }

    /// Check if a virtual address falls within this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Check if this VMA overlaps with a given range [base, base+length).
    pub fn overlaps(&self, base: u64, length: u64) -> bool {
        self.base < base + length && base < self.end()
    }

    /// Convert VMA protection flags to x86_64 page table flags.
    pub fn to_page_flags(&self) -> u64 {
        use crate::mm::vmm;
        let mut flags = vmm::PAGE_PRESENT;
        if self.prot & PROT_WRITE != 0 {
            flags |= vmm::PAGE_WRITABLE;
        }
        if self.prot & PROT_EXEC == 0 {
            flags |= vmm::PAGE_NO_EXECUTE;
        }
        // User-space VMAs get PAGE_USER
        if self.base < 0x0000_8000_0000_0000 {
            flags |= vmm::PAGE_USER;
        }
        flags
    }
}

/// Classification of a page-fault access, decoded from the x86 error code.
///
/// The three variants partition the access into at most one of
/// {instruction-fetch, write, read}.  Instruction-fetch takes priority so that
/// an `ifetch` fault is never misinterpreted as a read even on CPUs that leave
/// the R/W bit ambiguous for those faults.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FaultAccess {
    InstructionFetch,
    Write,
    Read,
}

impl FaultAccess {
    /// Decode from the x86_64 page-fault error code:
    ///   bit 1 (R/W):  1 = write
    ///   bit 4 (I/D):  1 = instruction fetch
    pub fn from_error_code(err: u64) -> Self {
        if err & 0x10 != 0 {
            FaultAccess::InstructionFetch
        } else if err & 0x02 != 0 {
            FaultAccess::Write
        } else {
            FaultAccess::Read
        }
    }
}

/// Decide whether a page fault of a given access class is compatible with a
/// VMA's declared protection bits.
///
/// Returns `true` when demand-paging may proceed, `false` when the fault is a
/// permission violation that should surface as SIGSEGV to user space.
///
/// Rules (matches POSIX `mmap`/`mprotect` semantics and Linux `do_user_addr_fault`):
///   * `PROT_NONE`           — rejects every access (guard pages).
///   * `InstructionFetch`    — requires `PROT_EXEC`.
///   * `Write`               — requires `PROT_WRITE`.
///   * `Read`                — requires any of `PROT_READ | PROT_WRITE | PROT_EXEC`
///     (x86_64 execute-only pages are implicitly readable, matching Linux).
///
/// This helper is the single source of truth used by both the x86 page-fault
/// handler and the unit tests, so the "which accesses are allowed?" policy is
/// decided in exactly one place.
pub fn fault_access_permitted(prot: VmProt, access: FaultAccess) -> bool {
    if prot == PROT_NONE {
        return false;
    }
    match access {
        FaultAccess::InstructionFetch => prot & PROT_EXEC != 0,
        FaultAccess::Write            => prot & PROT_WRITE != 0,
        FaultAccess::Read             => prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0,
    }
}

impl fmt::Debug for VmArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prot_str = [
            if self.prot & PROT_READ != 0 { 'r' } else { '-' },
            if self.prot & PROT_WRITE != 0 { 'w' } else { '-' },
            if self.prot & PROT_EXEC != 0 { 'x' } else { '-' },
        ];
        write!(
            f,
            "VMA {:#018x}-{:#018x} {}{}{} {}",
            self.base,
            self.end(),
            prot_str[0],
            prot_str[1],
            prot_str[2],
            self.name,
        )
    }
}

// ============================================================================
// VmSpace — Per-Process Virtual Address Space
// ============================================================================

/// A process's virtual address space: a CR3 + collection of VMAs.
///
/// # `mm_sem` — per-VmSpace address-space lock (W216 fix)
///
/// `mm_sem` is a per-process `RwLock` mirroring the POSIX equivalent of
/// Linux's `mmap_lock` (formerly `mmap_sem`).  It serialises page-table
/// edits against bulk address-space rewrites such as `clone_for_fork`
/// and process teardown.  Without it, a sibling CPU running
/// `clone_for_fork` while another CPU is mid-`unmap_and_free_range_in`
/// can resurrect a page-table entry pointing at a physical frame that is
/// about to be returned to the PMM, producing the systemic page-aliasing
/// race documented as W215 / W216.
///
/// ## Acquisition rules
///
/// * **Write lock** — held while mutating PTEs in bulk across the
///   address space.  Required by `clone_for_fork`, `free_process_memory`,
///   `free_vm_space`, and any future address-space rewrite (e.g. exec).
/// * **Read lock** — held while mutating a small number of PTEs (one
///   page-fault arm, one syscall such as `mmap`, `munmap`, `mprotect`,
///   `madvise`, `brk`).  Multiple readers can proceed concurrently — the
///   write lock only excludes when the bulk-rewrite path is active.
///
/// ## Lock ordering invariant
///
/// `PROCESS_TABLE` (top) → `VmSpace::mm_sem` (per-process)
/// → `MM_REGISTRY` (leaf, brief lookup) → `VMM_LOCK` (leaf)
/// → `PMM_LOCK` (leaf) → `PAGE_CACHE` (leaf, sibling).
///
/// Per-process `mm_sem`s are independent across processes — no cycle is
/// possible across them.  Within one process only read OR write is held
/// at a time per `RwLock` semantics.
///
/// ## Construction
///
/// `mm_sem` is an `Arc<RwLock<()>>`.  Constructors that create a new address
/// space (`new_kernel`, `new_user`, `clone_for_fork`) allocate a fresh lock.
/// `from_existing_cr3` SHARES the caller-supplied Arc (the parent's lock) so
/// that vfork-child and parent share the same `mm_sem`; the Drop impl guards
/// registry removal with `Arc::strong_count == 2` (only self + registry) so
/// the parent's entry survives the child's drop.  Test helpers in `kernel/src/test_runner.rs`
/// that build `VmSpace` via struct-literal syntax call
/// `make_mm_sem_for_test()`.  The child of a `clone_for_fork` gets its OWN
/// lock — the parent and child are independent address spaces post-fork.
pub struct VmSpace {
    /// Physical address of the PML4 page table root.
    pub cr3: u64,
    /// Sorted list of VMAs (by base address, non-overlapping).
    pub areas: Vec<VmArea>,
    /// Next hint address for mmap auto-placement.
    pub mmap_hint: u64,
    /// Per-process upper bound for `MAP_STACK` allocations.  Drawn fresh from
    /// `[STACK_ASLR_MIN, STACK_ASLR_MAX)` in `new_user()`; remains constant
    /// for the life of the address space.  Consumed by `find_free_stack_range`
    /// as the seed for per-call jitter — see the `STACK_ASLR_MIN` docs for
    /// the layout rationale and `find_free_stack_range` for the search.
    pub stack_aslr_base: u64,
    /// Program break (end of the heap segment).
    pub brk: u64,
    /// Start of the heap segment.
    pub brk_start: u64,
    /// Per-VmSpace address-space lock — see struct-level docs for usage.
    ///
    /// Reference-counted so that `MM_REGISTRY` and the owning `VmSpace`
    /// can both hold a handle; the registry deregisters when the
    /// `VmSpace` is dropped and the last `Arc` ref vanishes.
    pub mm_sem: Arc<RwLock<()>>,
    /// Monotonic counter bumped on every VMA-list mutation (W216 H_5j-B,
    /// 5th systemic aliasing path).  The page-fault handler in
    /// `arch/x86_64/idt.rs` samples this counter immediately after the
    /// PR #226 / #230 post-I/O VMA re-validation succeeds, then re-loads
    /// it before each `cache::insert + map_page_in` install iteration in
    /// the readahead and single-page fallback arms.  A mismatch indicates
    /// that a sibling CPU mutated the address space between revalidate
    /// and the current iteration; the install loop aborts and the user
    /// re-faults against the new VMA, mirroring the abort-and-retry
    /// pattern used elsewhere in the PFH for stale snapshots.
    ///
    /// The counter is shared (`Arc<AtomicU64>`) so that low-level helpers
    /// like `unmap_and_free_range_in` — which only have a `cr3`, not a
    /// `&VmSpace` — can bump the generation via `bump_generation_for_cr3`.
    /// Acquire/Release ordering is per Intel SDM Vol. 3A §8.2.3 (memory-
    /// ordering guarantees of LOCK-prefixed atomics on x86-64): a
    /// release-store on the mutator side happens-before an acquire-load
    /// on the PFH side, so any VMA-list write that preceded the bump is
    /// visible to a PFH iteration that observes the new generation.
    pub generation: Arc<AtomicU64>,
}

/// Default user-space mmap starting address.  `find_free_range` walks
/// downward from `mmap_hint`, so this is the *upper* bound from which
/// the first anonymous mmap is allocated.
const MMAP_BASE: u64 = 0x0000_7F00_0000_0000;

/// Entropy bits applied to each `VmSpace`'s starting `mmap_hint` so that
/// the first anonymous-mmap address — and every subsequent allocation
/// that derives from it via the top-down walk — varies per process and
/// per boot.  20 bits of page-granular entropy gives a `2^20 * 4 KiB =
/// 4 GiB` jitter window which is large enough to defeat fixed-VA
/// exploits while leaving the bulk of the mmap region (`MMAP_BASE`
/// downward) intact for normal allocation.
///
/// References:
/// - mmap(2) — kernel-chosen VA when `addr == NULL`
/// - System V AMD64 ABI §3.3.3 (Address Space Layout)
const MMAP_ASLR_BITS: u32 = 20;

/// Return a per-process randomised `mmap_hint` starting value.
///
/// The hint is `MMAP_BASE - random_4 KiB_offset`, so subsequent
/// `find_free_range` calls walk downward from a slightly different
/// upper bound each time a new address space is created.  Combined
/// with interpreter ASLR (`proc::elf::interp_aslr_base()`), this means
/// every shared library that the dynamic linker maps via `mmap()`
/// lands at a different VA per `exec()`.
#[inline]
fn randomised_mmap_hint() -> u64 {
    let offset = crate::security::rand::aslr_page_offset(MMAP_ASLR_BITS);
    // Subtract so the hint stays at or below `MMAP_BASE`; the allocator
    // walks downward from this hint, never upward, so a subtractive
    // jitter is the correct direction.  Saturating sub is paranoia —
    // `MMAP_BASE - 4 GiB` is still well inside user space.
    MMAP_BASE.saturating_sub(offset)
}

/// Pick a fresh per-process upper bound for `MAP_STACK` allocations.  Uniform
/// over `[STACK_ASLR_MIN, STACK_ASLR_MAX)`, 4 KiB-aligned.  Each VmSpace
/// constructed by `new_user()` calls this once at construction time; the
/// per-call jitter is applied separately by `find_free_stack_range`.
///
/// Refs: mmap(2), System V AMD64 ABI §3.3.3, CWE-330.
#[inline]
fn randomised_stack_aslr_base() -> u64 {
    const WINDOW: u64 = STACK_ASLR_MAX - STACK_ASLR_MIN;
    debug_assert!(WINDOW >= (1u64 << 30), "stack ASLR window too small for useful entropy");
    // The window is `2^38` bytes (256 GiB), i.e. `2^26` 4 KiB pages — pick a
    // 26-bit page-aligned offset.  `aslr_page_offset` rejects entropy > 40
    // bits via its `debug_assert!`, so 26 is well within bounds.
    let page_offset = crate::security::rand::aslr_page_offset(26);
    // Saturating add: even at the maximum 26-bit offset of `2^26 * 4 KiB =
    // 256 GiB - 4 KiB`, `STACK_ASLR_MIN + 256 GiB = STACK_ASLR_MAX`, so the
    // result fits in `[STACK_ASLR_MIN, STACK_ASLR_MAX]`.  The saturating
    // form is defence-in-depth against future window-resize edits.
    STACK_ASLR_MIN.saturating_add(page_offset).min(STACK_ASLR_MAX - 0x1000)
}

/// Default user-space heap start.
const HEAP_BASE: u64 = 0x0000_0040_0000_0000;

/// Dedicated VA window for `MAP_STACK | MAP_ANONYMOUS` thread-stack allocations
/// chosen by the kernel (i.e. when the caller passes no fixed address).  The
/// window sits ABOVE the general `mmap_hint` ceiling so that `find_free_range`
/// — which only walks downward from `mmap_hint ≤ MMAP_BASE` — never touches it,
/// and BELOW the interpreter PIE ASLR window (`INTERP_ASLR_MIN = 0x7F40...`),
/// so the interpreter loader and stack allocator do not compete for the same
/// VAs.  256 GiB is far more than any pthread implementation will ever need:
/// `__SC_THREAD_STACK_MIN` ≥ 16 KiB and a generous default of 8 MiB per stack
/// gives `2^15` simultaneous threads worth of room.
///
/// # Why this exists (independent of `mmap_hint` jitter)
///
/// PR #365's `randomised_mmap_hint()` jitters the *starting* `mmap_hint` by 20
/// bits but every successful `mmap` lowers `mmap_hint` toward the chosen base
/// (`syscall::sys_mmap` end-of-function).  After the dynamic linker has
/// finished mapping libxul + ld-musl + dependent libraries the hint has
/// marched many GiB downward through a sequence whose total span is
/// dominated by deterministic library sizes; the 4 GiB of starting jitter is
/// drowned out and a pthread `MAP_STACK` allocation that follows lands at a
/// nearly byte-identical VA across boots.  Routing `MAP_STACK` through a
/// dedicated window with per-call fresh entropy decouples thread-stack VAs
/// from prior mmap state.
///
/// Refs: mmap(2) (MAP_STACK semantics + kernel-chosen address when
/// `addr == NULL`), pthread_create(3), System V AMD64 ABI §3.3.3 (Address
/// Space Layout), CWE-330 (use of insufficiently random values).
const STACK_ASLR_MIN: u64 = MMAP_BASE;                        // 0x0000_7F00_0000_0000
const STACK_ASLR_MAX: u64 = 0x0000_7F40_0000_0000;             // == INTERP_ASLR_MIN

/// Entropy bits applied to each `MAP_STACK` allocation's chosen base.  16 bits
/// at 4 KiB granularity covers a 256 MiB span — well within the 256 GiB
/// window and far more positions than any realistic exploit could enumerate
/// against a non-fixed thread-stack allocation.  We compose this with the
/// per-VmSpace `stack_aslr_base` jitter so the per-process *and* per-call
/// entropy combine: per-process gives ~22 bits inside the window (window /
/// max-stack-size), per-call gives 16 more bits of small jitter on top.
///
/// Combined effective entropy for the chosen base across boots:
///   `min(22 + 16, log2(WINDOW / 4 KiB)) = min(38, 26) = 26 bits`
/// (since the window is `2^26` pages wide).  That is far above the 20-bit
/// threshold the kernel uses elsewhere for ASLR (`MMAP_ASLR_BITS`,
/// `aslr_page_offset` callers) and 2^26 ≈ 6.7e7 distinct VAs.
const STACK_ASLR_BITS: u32 = 16;

// ============================================================================
// MM registry — maps cr3 → VmSpace::mm_sem so PTE-mutating helpers in
// `mm/vmm.rs` can acquire the right per-process lock without changing their
// signatures.  See the `VmSpace::mm_sem` docs for the lock-ordering rules.
// ============================================================================

/// Per-`cr3` lookup table for the address-space `mm_sem` lock.
///
/// `register_mm_sem` inserts on `VmSpace` construction; `unregister_mm_sem`
/// removes on `VmSpace` drop.  Look-ups (`mm_sem_for_cr3`) take the registry
/// lock only long enough to clone the `Arc` out of the map.
static MM_REGISTRY: Mutex<BTreeMap<u64, Arc<RwLock<()>>>> = Mutex::new(BTreeMap::new());

/// Insert (cr3 → mm_sem) into the registry.
///
/// Idempotent: if a different sem is already registered under this cr3 (e.g.
/// because exec swapped the VmSpace but the old one has not yet been dropped),
/// the new entry replaces the old.  The old `Arc` survives in any reader that
/// already grabbed it — `RwLock` correctness is preserved.
pub(crate) fn register_mm_sem(cr3: u64, sem: Arc<RwLock<()>>) {
    if cr3 == 0 {
        return; // Sentinel for "no VmSpace yet" or kernel-only.
    }
    let mut reg = MM_REGISTRY.lock();
    reg.insert(cr3, sem);
}

/// Remove a registry entry (no-op if absent).
pub(crate) fn unregister_mm_sem(cr3: u64) {
    if cr3 == 0 {
        return;
    }
    let mut reg = MM_REGISTRY.lock();
    reg.remove(&cr3);
}

/// Look up the mm_sem associated with `cr3`, returning `None` for unknown CR3s
/// (kernel threads, idle, AP bootstrap).
pub fn mm_sem_for_cr3(cr3: u64) -> Option<Arc<RwLock<()>>> {
    if cr3 == 0 {
        return None;
    }
    let reg = MM_REGISTRY.lock();
    reg.get(&cr3).cloned()
}

/// Acquire `sem.read()` for a `#PF`-fast-path caller, servicing this CPU's
/// own incoming TLB-shootdown slot on every contended spin iteration instead
/// of blocking outright.
///
/// # The `mm_sem`/shootdown reentrancy deadlock this closes
///
/// `free_process_memory`, `free_vm_space`, and `clone_for_fork` hold
/// `mm_sem.write()` across a `mm::tlb::shootdown_*` call.  That ordering is
/// load-bearing per the W216 exclusion invariant documented on
/// [`VmSpace::mm_sem`] above — no concurrent faulter may install a mapping
/// while teardown/fork is walking page tables and returning frames to the
/// PMM — so, unlike the `PROCESS_TABLE`-vs-shootdown deadlock fixed by
/// dropping `PROCESS_TABLE` before its shootdown (PR #703), `mm_sem.write()`
/// cannot simply be released before the shootdown here.  The writer must keep
/// the lock.
///
/// A `#PF` is delivered on an interrupt gate (IF=0 for the duration of the
/// handler; Intel SDM Vol. 3A §6.8.1/§6.12.1), so a peer CPU concurrently
/// installing a PTE via `map_page_in_if_absent`, `map_page_in_cow_if_unchanged`,
/// or the fault-path callers of `map_page_in` / `write_pte` takes `mm_sem`
/// in read mode with interrupts disabled.  If that reader spins on a plain
/// `RwLock::read()` because a writer already holds `mm_sem.write()`, and the
/// writer's own `shootdown_full_user` / `shootdown_range` call is
/// simultaneously spinning on the ACK from that exact reader CPU, the two
/// sides deadlock: the writer never receives its ACK, because IF=0 leaves the
/// shootdown IPI vector pending in the reader CPU's LAPIC IRR (unserviceable
/// until the reader returns from the page-fault handler and re-enables
/// interrupts, per Intel SDM Vol. 3A §10.6.1), and the reader never acquires
/// `mm_sem`, because the writer never reaches the point where it drops it.
/// This is the same deadlock CLASS fixed for `PROCESS_TABLE` vs. the
/// write-fault-path shootdown — a lock held across a TLB shootdown whose
/// target is itself blocked acquiring that lock — applied to `mm_sem`.
///
/// # The fix
///
/// Mirrors the reentrancy already used to break the analogous livelock
/// between two shootdown *initiators* (the ACK-spin in
/// `mm::tlb::shootdown_range_inner`, which services incoming shootdowns on
/// every iteration): instead of blocking, a contended reader here services
/// its OWN incoming shootdown slot via
/// [`crate::mm::tlb::drain_incoming_shootdown_if_smp`] on every iteration.
/// That routine is lock-free and EOI-free, so it is safe to call with
/// interrupts disabled while `mm_sem` / `VMM_LOCK` are NOT held by this CPU
/// (they are not: this CPU is still spinning to acquire `mm_sem`, and
/// `VMM_LOCK` is taken only after `mm_sem`).  The W216 mutual exclusion is
/// preserved exactly — the reader still cannot proceed until the writer is
/// done — this only stops the reader from presenting as IF=0 dead weight to
/// the writer's shootdown while it waits.
///
/// # Cost
///
/// The common case (a live fault racing a teardown/fork writer is rare) is
/// `try_read()` succeeding immediately — identical cost to a plain
/// `RwLock::read()`.  Only on contention does the loop run, and each iteration
/// costs one relaxed atomic load (`drain_incoming_shootdown_if_smp`'s
/// `SMP_ACTIVE` check) plus, only when SMP is active AND a shootdown is
/// actually incoming, one lock-free compare-exchange + `invlpg`.  On SMP=1 the
/// drain is a single relaxed load per iteration and never sends or receives an
/// IPI.
///
/// # Scope — why this is not just `RwLock::read()` everywhere
///
/// This wrapper is used ONLY by the acquisitions that can run with IF=0:
/// `map_page_in_if_absent`, `map_page_in_cow_if_unchanged`, and the
/// `_fault_path` wrappers of `map_page_in` / `write_pte` (see
/// `kernel/src/mm/vmm.rs`).  Every other `mm_sem_for_cr3(...).read()` site —
/// ELF/PE loading, the non-fault-path `map_page_in` / `write_pte` callers
/// (`sysv_shm`, `signal.rs`'s trampoline setup, `ptrace` POKETEXT/POKEDATA,
/// process/PE bring-up, the `vdso`/`usermode` setup helpers,
/// `unmap_and_free_range_in`'s own inner read acquisition) — runs with
/// interrupts enabled, where a plain blocking `RwLock::read()` cannot produce
/// this deadlock: the shootdown IPI targeting that CPU is still serviceable by
/// the ordinary ISR while it spins.  Leaving those on the plain acquire keeps
/// this change scoped to the actual IF=0 hazard.
pub(crate) fn mm_sem_read_draining(sem: &RwLock<()>) -> RwLockReadGuard<'_, ()> {
    if let Some(guard) = sem.try_read() {
        return guard;
    }
    loop {
        crate::mm::tlb::drain_incoming_shootdown_if_smp();
        if let Some(guard) = sem.try_read() {
            return guard;
        }
        core::hint::spin_loop();
    }
}

// ============================================================================
// MM generation registry — parallel to MM_REGISTRY, keyed by cr3.
// Allows low-level helpers (unmap_and_free_range_in, MADV_DONTNEED bulk
// teardown) that only have a cr3 to bump the owning VmSpace's generation
// without threading a `&VmSpace` reference through the call graph.
// See `VmSpace::generation` doc-comment for the use case.
// ============================================================================

static MM_GEN_REGISTRY: Mutex<BTreeMap<u64, Arc<AtomicU64>>> = Mutex::new(BTreeMap::new());

/// Insert (cr3 → generation counter) into the parallel registry.  Idempotent
/// (replaces any prior entry) for the same reasons described in
/// `register_mm_sem`.
pub(crate) fn register_mm_generation(cr3: u64, gen_arc: Arc<AtomicU64>) {
    if cr3 == 0 {
        return;
    }
    let mut reg = MM_GEN_REGISTRY.lock();
    reg.insert(cr3, gen_arc);
}

/// Remove the generation counter entry for `cr3` (no-op if absent).
#[allow(dead_code)]
pub(crate) fn unregister_mm_generation(cr3: u64) {
    if cr3 == 0 {
        return;
    }
    let mut reg = MM_GEN_REGISTRY.lock();
    reg.remove(&cr3);
}

/// Bump the VmSpace generation counter associated with `cr3`.  Called by
/// PTE-mutating helpers that only have a `cr3` (see `mm/vmm.rs`).  Cheap
/// (registry lookup + one atomic fetch_add); no-op for unknown CR3s.
///
/// The fetch_add uses Release ordering so that VMA-list / PTE writes that
/// precede the bump on the same CPU are observable to any other CPU that
/// subsequently performs an Acquire load of the counter (Intel SDM
/// Vol. 3A §8.2.3).
pub fn bump_generation_for_cr3(cr3: u64) {
    if cr3 == 0 {
        return;
    }
    let arc = {
        let reg = MM_GEN_REGISTRY.lock();
        reg.get(&cr3).cloned()
    };
    if let Some(g) = arc {
        g.fetch_add(1, Ordering::Release);
    }
}

/// Allocate a fresh `mm_sem` handle for use in test struct-literal
/// `VmSpace { ... }` construction.  Production code paths should construct
/// `VmSpace` via `new_kernel`, `new_user`, `from_existing_cr3`, or
/// `clone_for_fork`; those constructors install the registry entry.  The
/// test helper does NOT register because most tests use cr3=0 (synthetic).
pub fn make_mm_sem_for_test() -> Arc<RwLock<()>> {
    Arc::new(RwLock::new(()))
}

/// Allocate a fresh generation counter for use in test struct-literal
/// `VmSpace { ... }` construction.  Mirrors `make_mm_sem_for_test`.
pub fn make_generation_for_test() -> Arc<AtomicU64> {
    Arc::new(AtomicU64::new(0))
}

/// Count of fresh user address spaces minted via [`VmSpace::new_user`].
///
/// `new_user()` is the genesis of every user process: a `clone_for_fork`
/// child necessarily descends from a `new_user()`'d ancestor, so a zero here
/// means no user address space (and therefore no user CR3) exists at all.
/// The BSP stack-pivot in `main.rs` asserts this is still zero at pivot time —
/// see [`user_address_spaces_created`].
static USER_ADDRESS_SPACES_CREATED: AtomicU64 = AtomicU64::new(0);

/// Number of user address spaces minted via [`VmSpace::new_user`] so far.
/// Used by the BSP stack-pivot to enforce "the pivot precedes the first user
/// CR3" as a runtime invariant rather than a verified-today fact.
pub fn user_address_spaces_created() -> u64 {
    USER_ADDRESS_SPACES_CREATED.load(Ordering::Acquire)
}

impl VmSpace {
    /// Create a new empty address space for a kernel process (shares kernel CR3).
    pub fn new_kernel() -> Self {
        let cr3 = crate::mm::vmm::get_cr3();
        let mm_sem = Arc::new(RwLock::new(()));
        register_mm_sem(cr3, mm_sem.clone());
        let generation = Arc::new(AtomicU64::new(0));
        register_mm_generation(cr3, generation.clone());
        Self {
            cr3,
            areas: Vec::new(),
            mmap_hint: MMAP_BASE,
            // Kernel processes never allocate user stacks; pick a neutral
            // default inside the configured window so any accidental call
            // from a kernel-mode context still produces a well-formed VA.
            stack_aslr_base: STACK_ASLR_MIN,
            brk: HEAP_BASE,
            brk_start: HEAP_BASE,
            mm_sem,
            generation,
        }
    }

    /// Create a VmSpace that uses an existing CR3 (e.g., for vfork children
    /// that share the parent's page tables but need their own VMA tracking).
    ///
    /// `parent_mm_sem` must be the `Arc<RwLock<()>>` already registered under
    /// `cr3` in `MM_REGISTRY` — typically `parent_vm_space.mm_sem.clone()`.
    /// The child VmSpace shares this same Arc so that:
    ///
    ///   * Both parent and child calls to `mm_sem_for_cr3(cr3)` return the
    ///     SAME lock object, serialising concurrent PTE mutations against any
    ///     `clone_for_fork` / `free_vm_space` write-lock acquisition.
    ///   * The registry entry is only removed when the LAST owner drops —
    ///     see the `Drop` impl which guards removal with `Arc::strong_count`.
    ///
    /// Allocating a fresh Arc here (as the pre-fix code did) would overwrite
    /// the registry slot with a new lock object, so the parent's subsequent
    /// `mm_sem_for_cr3` lookups return a different (child-owned) lock.  When
    /// the child later drops its VmSpace the registry slot is removed, and
    /// every subsequent PTE-mutating call on the parent silently skips the
    /// lock acquisition — re-opening the W215 race.
    pub fn from_existing_cr3(cr3: u64, parent_mm_sem: Arc<RwLock<()>>) -> Self {
        // The Arc clone bumps the strong count; the registry entry is already
        // present (the parent's VmSpace registered it at construction).  No
        // re-registration is needed — `mm_sem_for_cr3(cr3)` already returns
        // this Arc.
        //
        // Generation counter: shares the parent's counter so any mutation made
        // by either share-CR3 sibling is observed by both at the PFH check.
        // Falls back to a fresh counter if the parent is no longer registered
        // (defensive — should not occur in practice).
        let generation = {
            let reg = MM_GEN_REGISTRY.lock();
            reg.get(&cr3).cloned()
        }
        .unwrap_or_else(|| {
            let g = Arc::new(AtomicU64::new(0));
            register_mm_generation(cr3, g.clone());
            g
        });
        Self {
            cr3,
            areas: Vec::new(),
            mmap_hint: MMAP_BASE,
            // vfork children share the parent's address space until execve(2);
            // their MAP_STACK allocations (if any) should not collide with the
            // parent's pthread stacks, so seed with a fresh per-vfork base.
            stack_aslr_base: randomised_stack_aslr_base(),
            brk: HEAP_BASE,
            brk_start: HEAP_BASE,
            mm_sem: parent_mm_sem,
            generation,
        }
    }

    /// Create a new user address space with its own PML4.
    ///
    /// The new PML4 clones the kernel-half (entries 256-511) from the current CR3,
    /// ensuring the kernel is always mapped. It also deep-clones PML4 entry 0
    /// (the identity map of the first 4 GiB) so that kernel code, kernel stacks,
    /// and page-table data remain accessible when CR3 is switched to this table.
    /// The deep clone creates private copies of the PDPT and PD levels so that
    /// per-process modifications (e.g., splitting a 2 MiB huge page to overlay
    /// user ELF segments) don't affect the kernel's own page tables.
    pub fn new_user() -> Option<Self> {
        // Higher-half physical-to-virtual offset — same as vmm::PHYS_OFF.
        // We use this instead of raw physical pointers so that accesses go
        // through the stable kernel higher-half mapping (PML4[256-511]) rather
        // than the identity map (PML4[0]), which can be split/modified by user
        // mmap() calls after a process has been running for a while.
        const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

        let new_pml4 = crate::mm::pmm::alloc_page()?;

        // Zero the entire PML4 via the higher-half mapping.
        unsafe {
            core::ptr::write_bytes((PHYS_OFF + new_pml4) as *mut u8, 0, crate::mm::pmm::PAGE_SIZE);
        }

        // Clone kernel-half entries (256-511) from the current PML4.
        // These are shallow copies and share the same underlying page tables
        // (kernel mappings are identical across all processes).
        let current_cr3 = crate::mm::vmm::get_cr3();
        unsafe {
            let src = (PHYS_OFF + current_cr3) as *const u64;
            let dst = (PHYS_OFF + new_pml4) as *mut u64;
            for i in 256..512 {
                *dst.add(i) = *src.add(i);
            }
        }

        // PML4[0] (user virtual address space, 0x0 – 0x7FFF_FFFF_FFFF) starts
        // completely empty.  map_page_in() will allocate PDPT/PD/PT pages as
        // needed when user ELF segments and anonymous regions are mapped.
        //
        // NOTE: do NOT copy the kernel's PML4[0] identity map here.  The kernel
        // identity map includes the first 4 GiB (physical == virtual for 0..4 GiB),
        // which means address 0x0 would be present in every user process.  That
        // allows a NULL function-pointer call to execute code from physical address
        // 0x0 (BIOS area) instead of faulting cleanly.
        //
        // The kernel always uses PHYS_OFF (0xFFFF_8000_0000_0000 + phys) for its
        // own memory accesses, so PML4[0] is not needed by any kernel subsystem
        // after the higher-half switch.

        let mm_sem = Arc::new(RwLock::new(()));
        register_mm_sem(new_pml4, mm_sem.clone());
        let generation = Arc::new(AtomicU64::new(0));
        register_mm_generation(new_pml4, generation.clone());
        // Record that a user address space (and thus a user CR3) now exists.
        // The BSP stack-pivot in `main.rs` asserts this is zero before it runs,
        // so a boot-phase reorder that spawns a user process before the pivot
        // trips loudly instead of silently reopening the bootstrap-stack hole.
        USER_ADDRESS_SPACES_CREATED.fetch_add(1, Ordering::Release);
        Some(Self {
            cr3: new_pml4,
            areas: Vec::new(),
            // Per-process mmap-hint ASLR: subsequent anonymous mmaps via
            // `find_free_range` walk downward from this hint, so jittering
            // the starting value forces every shared-library VA chosen by
            // ld-musl to differ between processes and between boots.  See
            // `randomised_mmap_hint()` for the entropy rationale.
            mmap_hint: randomised_mmap_hint(),
            // Per-process MAP_STACK ASLR: `MAP_STACK` mmap allocations use a
            // dedicated window (above `MMAP_BASE`, below `INTERP_ASLR_MIN`)
            // with per-call jitter on top of this per-process base.  This
            // decouples thread-stack VAs from the deterministic-after-libxul
            // `mmap_hint` walk.  See `STACK_ASLR_MIN` docs and
            // `find_free_stack_range` for the layout rationale.
            stack_aslr_base: randomised_stack_aslr_base(),
            brk: HEAP_BASE,
            brk_start: HEAP_BASE,
            mm_sem,
            generation,
        })
    }

    /// Clone this address space for fork (copy-on-write).
    ///
    /// `actual_cr3` must be the process's real running CR3 (from `proc.cr3` in
    /// the process table).  `self.cr3` may be stale if `proc.cr3` was updated
    /// (e.g. by exec) without a corresponding update to the VmSpace.
    ///
    /// Walks `actual_cr3`'s page tables directly (PML4[0..256] → PDPT → PD → PT),
    /// allocating fresh PT structures for the child at each level.  Every present
    /// 4 KB PTE is write-protected in the parent and mirrored read-only in the
    /// child; the page fault handler performs the actual physical copy on write.
    ///
    /// Also syncs `self.cr3 = actual_cr3` so subsequent VmSpace operations
    /// (demand-paging, CoW handling) use the correct page tables.
    pub fn clone_for_fork(&mut self, actual_cr3: u64) -> Option<Self> {
        use crate::mm::vmm::{PAGE_PRESENT, PAGE_WRITABLE, PAGE_HUGE, ADDR_MASK,
                             get_kernel_cr3, is_identity_map_phys};
        use crate::mm::pmm;
        use crate::mm::refcount::page_ref_inc;

        const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

        // === W216 fix: serialise against concurrent PTE-mutating syscalls ====
        //
        // Acquire the parent's mm_sem in write mode for the entire walk.  Any
        // sibling thread on another CPU that is currently inside
        // `unmap_and_free_range_in`, `map_page_in`, `sys_madvise(MADV_DONTNEED)`,
        // `sys_mprotect`, or `sys_brk` for this same address space is holding
        // the read side of the same `mm_sem`; the write acquisition below
        // blocks until they all complete.  Once we hold the write lock no new
        // reader can start until we release it after the walk.
        //
        // Without this, the timeline in W216 fires:
        //   CPU A — clone_for_fork: reads parent_pt[X] = F | RW | PRESENT
        //   CPU B — unmap_and_free_range_in: clears PTE_Y referencing F,
        //           refcount goes to 0, F is queued for free
        //   CPU A — writes parent_pt[X] = F | RO  (resurrects the PTE!)
        //   CPU A — writes child_pt[X]  = F | RO  (+ page_ref_inc to 1)
        //   CPU B — shootdown completes for Y but NOT for X
        //   CPU B — pmm::free_page(F) — F returns to the free pool
        //   CPU B — third allocator hands F to a kernel page-table page
        //   CPU A — child or parent demand-loads from X → reads stale F.
        //
        // Holding mm_sem write across the entire PML4→PT walk closes the
        // window: CPU B's `_lock = read_lock(mm_sem)` at the head of
        // `unmap_and_free_range_in` cannot run while this write is held.
        let _mm_guard = self.mm_sem.write();

        let hw_cr3: u64;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) hw_cr3, options(nomem, nostack)); }

        // Sync self.cr3 to actual_cr3 so future VmSpace ops are consistent.
        // Log if there was a discrepancy (helps diagnose root cause).
        if self.cr3 != actual_cr3 {
            crate::serial_println!(
                "[FORK-COW] WARN: vm_space.cr3={:#x} != actual_cr3={:#x} (hw_cr3={:#x}); syncing",
                self.cr3, actual_cr3, hw_cr3
            );
            self.cr3 = actual_cr3;
        }

        // task#4 identity-map guard.  A fork whose page tables ARE the kernel's
        // own (`actual_cr3 == kernel_cr3`) is only ever the in-kernel test
        // runner (a `vm_space == None` process runs on `kernel_cr3`).  For such
        // a fork the CoW write-protect pass below would clear `PAGE_WRITABLE`
        // on the kernel's 1:1 identity map (PML4[0]); the running kernel writes
        // through that map (e.g. the BSP bootstrap stack), so the next kernel
        // store to a now-read-only identity page faults — a #PF that re-pushes
        // onto the same read-only stack and escalates to #DF, or a getrandom /
        // sysinfo kernel-context write that fault-loops.  When this flag is set
        // the leaf loops below leave identity leaves (`phys == va`, low VA)
        // writable and CoW every other (non-identity, high-VA) leaf normally.
        // A real user address space never satisfies `actual_cr3 == kernel_cr3`
        // — its PML4[0] is built empty and never shares a page-table page with
        // the kernel identity map — so this is inert for every real fork(2).
        let kernel_cr3 = get_kernel_cr3();
        let fork_on_kernel_cr3 = kernel_cr3 != 0 && actual_cr3 == kernel_cr3;

        // Per-fork [FORK-COW] dump (START line + one line per VMA, ~100 VMAs
        // per Firefox process).  ALWAYS-ON historically — this taxed every
        // fork(2) in EVERY build, including stock production.  Pure diagnostic:
        // gate it behind the off-by-default `fork-cow-trace` feature.  The
        // cr3-mismatch WARN above and the OOM line below stay UNCONDITIONAL —
        // those are rare, real error signals, not hot-path chatter.
        #[cfg(feature = "fork-cow-trace")]
        {
            crate::serial_println!("[FORK-COW] clone_for_fork START cr3={:#x} hw_cr3={:#x} vmas={}", actual_cr3, hw_cr3, self.areas.len());
            for vma in &self.areas {
                crate::serial_println!("[FORK-COW]   VMA [{:#x}..{:#x}) prot={:#x} flags={:#x} {:?}", vma.base, vma.base + vma.length, vma.prot, vma.flags, vma.backing);
            }
        }

        // Allocate a fresh, zeroed PML4 for the child.
        let child_pml4_phys = match pmm::alloc_page() {
            Some(p) => p,
            None => { crate::serial_println!("[FORK-COW] alloc_page failed for child PML4 (OOM)"); return None; }
        };
        unsafe {
            core::ptr::write_bytes((PHYS_OFF + child_pml4_phys) as *mut u8, 0, 4096);
        }

        // Copy kernel-half (PML4 entries 256-511) from actual_cr3 — these are
        // shallow shared entries identical across all processes.
        unsafe {
            let src = (PHYS_OFF + actual_cr3) as *const u64;
            let dst = (PHYS_OFF + child_pml4_phys) as *mut u64;
            for i in 256..512usize {
                *dst.add(i) = *src.add(i);
            }
        }

        // Walk parent's user page tables (PML4[0..256]).
        // At each level allocate a fresh table for the child so the child's
        // PD/PT pages are never shared with the parent's.
        let mut total_pages_cow: u64 = 0;
        unsafe {
            let parent_pml4 = (PHYS_OFF + actual_cr3) as *mut u64;
            let child_pml4  = (PHYS_OFF + child_pml4_phys) as *mut u64;

            for pml4_idx in 0..256usize {
                let pml4e = *parent_pml4.add(pml4_idx);
                if pml4e & PAGE_PRESENT == 0 { continue; }
                #[cfg(feature = "fork-cow-trace")]
                crate::serial_println!("[FORK-COW] PML4[{}] present (phys={:#x})", pml4_idx, pml4e & ADDR_MASK);

                let parent_pdpt_phys = pml4e & ADDR_MASK;

                // Fresh PDPT for child.
                let child_pdpt_phys = pmm::alloc_page()?;
                core::ptr::write_bytes((PHYS_OFF + child_pdpt_phys) as *mut u8, 0, 4096);
                *child_pml4.add(pml4_idx) = child_pdpt_phys | (pml4e & !ADDR_MASK);

                let parent_pdpt = (PHYS_OFF + parent_pdpt_phys) as *mut u64;
                let child_pdpt  = (PHYS_OFF + child_pdpt_phys)  as *mut u64;

                for pdpt_idx in 0..512usize {
                    let pdpte = *parent_pdpt.add(pdpt_idx);
                    if pdpte & PAGE_PRESENT == 0 { continue; }

                    // 1 GB huge page — write-protect in both, no CoW split.
                    if pdpte & PAGE_HUGE != 0 {
                        let phys_1g  = pdpte & !0x3FFF_FFFFu64;
                        let va_1g    = ((pml4_idx as u64) << 39) | ((pdpt_idx as u64) << 30);
                        if fork_on_kernel_cr3 && is_identity_map_phys(va_1g, phys_1g) {
                            // Kernel identity 1 GiB page: keep it writable in
                            // both parent and child (copy the PDPTE verbatim).
                            *parent_pdpt.add(pdpt_idx) = pdpte;
                            *child_pdpt .add(pdpt_idx) = pdpte;
                            continue;
                        }
                        let flags_ro = (pdpte & !ADDR_MASK) & !PAGE_WRITABLE;
                        *parent_pdpt.add(pdpt_idx) = phys_1g | flags_ro;
                        *child_pdpt .add(pdpt_idx) = phys_1g | flags_ro;
                        continue;
                    }

                    let parent_pd_phys = pdpte & ADDR_MASK;

                    // Fresh PD for child.
                    let child_pd_phys = pmm::alloc_page()?;
                    core::ptr::write_bytes((PHYS_OFF + child_pd_phys) as *mut u8, 0, 4096);
                    *child_pdpt.add(pdpt_idx) = child_pd_phys | (pdpte & !ADDR_MASK);

                    let parent_pd = (PHYS_OFF + parent_pd_phys) as *mut u64;
                    let child_pd  = (PHYS_OFF + child_pd_phys)  as *mut u64;

                    for pd_idx in 0..512usize {
                        let pde = *parent_pd.add(pd_idx);
                        if pde & PAGE_PRESENT == 0 { continue; }

                        // 2 MB huge page — write-protect in both and ref-count sub-pages.
                        if pde & PAGE_HUGE != 0 {
                            let phys_2m     = pde & 0x000F_FFFF_FFE0_0000u64;
                            let va_2m       = ((pml4_idx as u64) << 39)
                                            | ((pdpt_idx as u64) << 30)
                                            | ((pd_idx as u64) << 21);
                            let (parent_pde, child_pde) =
                                if fork_on_kernel_cr3 && is_identity_map_phys(va_2m, phys_2m) {
                                    // Kernel identity 2 MiB page: keep writable
                                    // in both (copy the PDE verbatim).  The
                                    // sub-page ref-count accounting is unchanged
                                    // from the normal path so teardown stays
                                    // balanced — only the writable bit differs.
                                    (pde, pde)
                                } else {
                                    let flags_ro = (pde & !ADDR_MASK) & !PAGE_WRITABLE;
                                    (phys_2m | flags_ro, phys_2m | flags_ro)
                                };
                            *parent_pd.add(pd_idx) = parent_pde;
                            *child_pd .add(pd_idx) = child_pde;
                            for sub in 0..512u64 {
                                page_ref_inc(phys_2m + sub * 0x1000);
                            }
                            continue;
                        }

                        let parent_pt_phys = pde & ADDR_MASK;

                        // Fresh PT for child.
                        let child_pt_phys = pmm::alloc_page()?;
                        core::ptr::write_bytes((PHYS_OFF + child_pt_phys) as *mut u8, 0, 4096);
                        *child_pd.add(pd_idx) = child_pt_phys | (pde & !ADDR_MASK);

                        let parent_pt = (PHYS_OFF + parent_pt_phys) as *mut u64;
                        let child_pt  = (PHYS_OFF + child_pt_phys)  as *mut u64;

                        for pt_idx in 0..512usize {
                            let pte = *parent_pt.add(pt_idx);
                            if pte & PAGE_PRESENT == 0 { continue; }

                            let phys       = pte & ADDR_MASK;
                            let va         = ((pml4_idx as u64) << 39)
                                           | ((pdpt_idx as u64) << 30)
                                           | ((pd_idx as u64) << 21)
                                           | ((pt_idx as u64) << 12);

                            // Kernel identity leaf under kernel_cr3: keep the
                            // parent (and child) PTE writable — never CoW the
                            // kernel's own 1:1 map.  Otherwise write-protect in
                            // place as usual.
                            let entry = if fork_on_kernel_cr3 && is_identity_map_phys(va, phys) {
                                pte
                            } else {
                                phys | ((pte & !ADDR_MASK) & !PAGE_WRITABLE)
                            };

                            // Parent PTE in place; child PTE: same physical page.
                            *parent_pt.add(pt_idx) = entry;
                            *child_pt.add(pt_idx)  = entry;

                            // Keep page alive until both mappings are gone.
                            page_ref_inc(phys);
                            total_pages_cow += 1;
                        }
                    }
                }
            }
        }

        // Flush TLB: parent PTEs were write-protected so stale entries must
        // be evicted on every CPU that has the parent's CR3 loaded — without
        // a cross-CPU shootdown, a sibling thread on another core would keep
        // writing through its cached writable translation and silently
        // corrupt the page the new CoW child also sees.  We pass the full
        // user-VA range (0..2^47) so the local handler falls through to
        // a CR3 reload, which drops every TLB entry tagged with this CR3
        // in a single operation.  Senders that have switched CPUs since
        // the original mapping are still covered because the per-CR3
        // active-CPU mask is consulted at shootdown time.
        crate::mm::tlb::shootdown_full_user(self.cr3);
        #[cfg(feature = "fork-cow-trace")]
        crate::serial_println!("[FORK-COW] total {} 4KB pages CoW'd into child CR3={:#x}", total_pages_cow, child_pml4_phys);
        // `total_pages_cow` is only read by the trace line above; bind it when
        // the trace is compiled out so the running tally does not warn.
        #[cfg(not(feature = "fork-cow-trace"))]
        let _ = total_pages_cow;

        // Copy VMA list to child.
        let mut child_areas = Vec::with_capacity(self.areas.len());
        for vma in &self.areas {
            // The child independently maps every VMA the parent had, so a
            // MAP_SHARED file-backed mapping inherited by the child holds its
            // OWN inode pin.  This balances the unpin the child's teardown
            // (free_process_memory / free_vm_space) will perform over its
            // areas; without it the child's exit would underflow the parent's
            // pin and free a still-mapped shm inode.  This direct push bypasses
            // insert_vma, so pin here.  See vfs::vma_pin_if_shared_file.
            crate::vfs::vma_pin_if_shared_file(vma.flags, &vma.backing);
            child_areas.push(vma.clone());
        }

        // Child gets a fresh, independent `mm_sem`.  Parent and child are now
        // separate address spaces; their PTE-mutating sites must not contend
        // on a single shared lock.  The `register_mm_sem` call associates
        // the new lock with the child's freshly-allocated PML4.
        let child_mm_sem = Arc::new(RwLock::new(()));
        register_mm_sem(child_pml4_phys, child_mm_sem.clone());
        let child_generation = Arc::new(AtomicU64::new(0));
        register_mm_generation(child_pml4_phys, child_generation.clone());

        // Bump the parent's generation: the CoW write-protect pass above
        // mutated parent PTEs (clear PAGE_WRITABLE), which the PFH treats
        // analogously to a VMA-list mutation for race-detection purposes.
        self.generation.fetch_add(1, Ordering::Release);

        Some(VmSpace {
            cr3: child_pml4_phys,
            areas: child_areas,
            mmap_hint: self.mmap_hint,
            // Inherit the parent's stack ASLR base.  The child gets its own
            // PML4 (fresh VMA list) but inheriting the base keeps existing
            // thread-stack VMAs that were copied above pointing at the same
            // VAs in the child — required for thread-aware libc state (e.g.
            // `pthread_attr_getstack(3)`) to remain consistent across fork.
            // Per-call jitter on subsequent MAP_STACK allocations still
            // diverges parent and child paths.
            stack_aslr_base: self.stack_aslr_base,
            brk: self.brk,
            brk_start: self.brk_start,
            mm_sem: child_mm_sem,
            generation: child_generation,
        })
    }

    /// Find the VMA containing the given virtual address.
    pub fn find_vma(&self, addr: u64) -> Option<&VmArea> {
        // Binary search would be better for large VMA counts, but linear is
        // fine for < 100 VMAs.
        self.areas.iter().find(|vma| vma.contains(addr))
    }

    /// Find the VMA containing the given virtual address (mutable).
    pub fn find_vma_mut(&mut self, addr: u64) -> Option<&mut VmArea> {
        self.areas.iter_mut().find(|vma| vma.contains(addr))
    }

    /// Lower `mmap_hint` to `base` only when this placement participates in
    /// the NULL-hint downward-walk regime — i.e. neither MAP_FIXED nor a
    /// MAP_STACK kernel-chosen allocation.  Skipping MAP_FIXED preserves the
    /// per-process entropy seeded by `randomised_mmap_hint()`: a dynamic
    /// linker that MAP_FIXED-loads shared libraries at a PIE-biased base
    /// would otherwise drag the hint down to that base, destroying entropy
    /// before any later NULL-hint allocation (notably `pthread_create`'s
    /// stack fallback path) is ever issued.
    ///
    /// References: POSIX mmap(2), pthread_create(3), CWE-330.
    #[inline]
    pub fn note_mmap_placement(&mut self, base: u64, is_fixed: bool, is_stack_alloc: bool) {
        if !is_fixed && !is_stack_alloc && base < self.mmap_hint {
            self.mmap_hint = base;
        }
    }

    /// Insert a new VMA, maintaining sorted order by base address.
    /// Returns an error if the new VMA overlaps with any existing one.
    pub fn insert_vma(&mut self, vma: VmArea) -> Result<(), VmaError> {
        // Check for overlaps
        for existing in &self.areas {
            if existing.overlaps(vma.base, vma.length) {
                return Err(VmaError::Overlap);
            }
        }

        // Find insertion point (sorted by base)
        let pos = self.areas.iter().position(|v| v.base > vma.base)
            .unwrap_or(self.areas.len());
        // A MAP_SHARED file-backed VMA entering the address space holds one
        // kernel pin on its inode for the duration of its membership in this
        // list (POSIX mmap(2)'s independent open-file reference).  Pin before
        // moving `vma` into the Vec so we can read its flags/backing.  See
        // vfs::vma_pin_if_shared_file.  Balanced in remove_range / on whole-
        // VmSpace teardown (proc::free_process_memory).
        crate::vfs::vma_pin_if_shared_file(vma.flags, &vma.backing);
        self.areas.insert(pos, vma);
        // W216 H_5j-B: notify the PFH install loop that the VMA list changed.
        self.generation.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Remove all VMAs that overlap with the range [base, base+length).
    /// Partially overlapping VMAs are split or shrunk.
    ///
    /// For file-backed VMAs, split pieces have their backing offset adjusted so
    /// that each piece still maps the correct portion of the file.  Without this
    /// adjustment, glibc's ld-linux (which uses an initial PROT_READ file-backed
    /// reservation to reserve the full library span, then overwrites individual
    /// segments with MAP_FIXED) would read stale/wrong file data from the
    /// remnant reservation pages, corrupting its internal load-address
    /// structures and producing garbage mprotect/relocation addresses.
    pub fn remove_range(&mut self, base: u64, length: u64) -> Result<(), VmaError> {
        // W216 H_5j-B: notify the PFH install loop that the VMA list is about
        // to change.  Bumped before the mutation so any PFH iteration that
        // observes the new generation will also (via the lock acquisition in
        // `unmap_and_free_range_in`) see the post-mutation areas list.
        self.generation.fetch_add(1, Ordering::Release);
        let end = base + length;
        let mut i = 0;

        while i < self.areas.len() {
            let vma = &self.areas[i];

            if !vma.overlaps(base, length) {
                // No overlap — keep as-is
                i += 1;
                continue;
            }

            if vma.base >= base && vma.end() <= end {
                // Completely contained — remove.  This VMA leaves the address
                // space entirely, so drop the MAP_SHARED-file pin it held (if
                // any).  This is the munmap / MAP_FIXED-replacement path that
                // tears down a shm mapping; when it is the last reference the
                // pinned, deferred-deleted inode is freed here.
                let removed = self.areas.remove(i);
                crate::vfs::vma_unpin_if_shared_file(removed.flags, &removed.backing);
                continue;
            }

            if vma.base < base && vma.end() > end {
                // Range punches a hole in the middle — split into two pieces.
                // The right piece starts at `end`, which is `end - vma.base`
                // bytes into the original VMA.  For file-backed VMAs the
                // backing offset of the right piece must be advanced by that
                // same delta so page faults still read from the correct file
                // position.
                let right_delta = end - vma.base;
                let left = VmArea {
                    base: vma.base,
                    length: base - vma.base,
                    prot: vma.prot,
                    flags: vma.flags,
                    backing: vma.backing.clone(),   // left piece: offset unchanged
                    name: vma.name,
                };
                let right_backing = match &vma.backing {
                    VmBacking::File { mount_idx, inode, offset, elf_load_delta } => VmBacking::File {
                        mount_idx: *mount_idx,
                        inode: *inode,
                        offset: offset + right_delta,
                        // delta is a segment-level constant; unchanged by split
                        elf_load_delta: *elf_load_delta,
                    },
                    other => other.clone(),
                };
                let right = VmArea {
                    base: end,
                    length: vma.end() - end,
                    prot: vma.prot,
                    flags: vma.flags,
                    backing: right_backing,
                    name: vma.name,
                };
                // One MAP_SHARED-file VMA becomes two: drop the original's pin
                // and place one pin per surviving piece so the inode stays
                // pinned exactly once per live mapping.  The inserts below
                // bypass insert_vma, so pin them directly here.
                let removed = self.areas.remove(i);
                crate::vfs::vma_unpin_if_shared_file(removed.flags, &removed.backing);
                crate::vfs::vma_pin_if_shared_file(right.flags, &right.backing);
                crate::vfs::vma_pin_if_shared_file(left.flags, &left.backing);
                self.areas.insert(i, right);
                self.areas.insert(i, left);
                i += 2;
                continue;
            }

            if vma.base < base {
                // Overlap on the right side — shrink (left portion kept).
                // The kept portion starts at vma.base with unchanged offset.
                let mut vma = self.areas.remove(i);
                vma.length = base - vma.base;
                self.areas.insert(i, vma);
                i += 1;
                continue;
            }

            // Overlap on the left side — shrink from left.
            // The kept portion starts at `end`, which is `end - old_base`
            // bytes into the original VMA.  Advance the file offset accordingly.
            let mut vma = self.areas.remove(i);
            let old_base = vma.base;
            let left_delta = end - old_base;
            if let VmBacking::File { offset, .. } = &mut vma.backing {
                *offset += left_delta;
            }
            vma.base = end;
            vma.length -= left_delta;
            self.areas.insert(i, vma);
            i += 1;
        }

        Ok(())
    }

    /// Find a free virtual address range for a `MAP_STACK` allocation inside
    /// the dedicated stack-ASLR window `[STACK_ASLR_MIN, STACK_ASLR_MAX)`.
    ///
    /// The base is chosen by combining the per-process `stack_aslr_base`
    /// (sampled once at `new_user()` time) with `STACK_ASLR_BITS` of fresh
    /// per-call entropy.  This decouples thread-stack VAs from the
    /// deterministic-after-libxul downward walk of `find_free_range` /
    /// `mmap_hint`: each pthread_create's MAP_STACK lands at a different VA
    /// across boots and across threads, independent of the order in which
    /// the dynamic linker has mapped shared libraries beforehand.
    ///
    /// On overlap (rare — the window is 256 GiB and stacks are at most a few
    /// MiB), retries with fresh entropy up to a small bounded number of
    /// times.  If every attempt overlaps (which would require the window to
    /// be substantially full), falls back to `find_free_range` for the
    /// general mmap region so the caller still receives a valid VA — albeit
    /// without the dedicated entropy.  This fallback preserves correctness
    /// when the window is unavailable (e.g. exhausted by a pathological
    /// caller); the deterministic-VA risk is the same as the legacy path.
    ///
    /// # References
    /// - mmap(2) — MAP_STACK and kernel-chosen VA semantics
    /// - pthread_create(3) — typical caller of MAP_STACK
    /// - System V AMD64 ABI §3.3.3 — Address Space Layout
    /// - Intel SDM Vol. 3A §4.6 — User/Supervisor address-space boundaries
    pub fn find_free_stack_range(&self, size: u64) -> Option<u64> {
        let size = page_align_up(size);
        if size == 0 || size > (STACK_ASLR_MAX - STACK_ASLR_MIN) {
            return None;
        }

        // Number of retries before falling through.  16 attempts at 16-bit
        // jitter over a 256 GiB window with a few MiB stack-per-slot keeps
        // the failure probability negligible (collision per attempt ≪ 1%
        // until the window is dense).
        const STACK_PLACE_RETRIES: u32 = 16;

        for _ in 0..STACK_PLACE_RETRIES {
            // Per-call jitter, page-aligned, within `2^STACK_ASLR_BITS` pages.
            let jitter = crate::security::rand::aslr_page_offset(STACK_ASLR_BITS);
            // Candidate base: anchor on `stack_aslr_base`, then nudge by
            // `jitter` while keeping the whole `[base, base+size)` inside
            // `[STACK_ASLR_MIN, STACK_ASLR_MAX)`.
            let raw = self.stack_aslr_base.saturating_add(jitter);
            // Clamp so `base + size <= STACK_ASLR_MAX`.  If clamping pushes
            // us below `STACK_ASLR_MIN`, the window is smaller than `size`
            // and we already returned `None` above; otherwise the clamp
            // keeps the candidate within the window.
            let max_base = STACK_ASLR_MAX.saturating_sub(size);
            let candidate = raw.min(max_base).max(STACK_ASLR_MIN);

            let overlaps = self.areas.iter().any(|vma| vma.overlaps(candidate, size));
            if !overlaps {
                return Some(candidate);
            }
        }

        // Window full or otherwise unwilling — fall through so the caller
        // still gets a VA from the general allocator.  Callers may treat
        // this as a "best-effort, weaker entropy" outcome and proceed.
        self.find_free_range(size)
    }

    /// Find a free virtual address range of the given size.
    /// Searches from `mmap_hint` downward (top-down allocation like Linux).
    pub fn find_free_range(&self, size: u64) -> Option<u64> {
        let size = page_align_up(size);

        // Top-down search for the highest free gap >= size, starting from the
        // fixed MMAP_BASE ceiling (NOT the running `mmap_hint`).
        //
        // `mmap_hint` is lowered monotonically as mappings are placed below it
        // (see insert_vma) and is never raised on munmap.  Starting the walk at
        // `mmap_hint` therefore only ever searched the shrinking window *below*
        // the lowest mapping ever made, so address space freed by munmap (which
        // sits above the lowered hint) was never reused.  Under heavy
        // mmap/munmap churn — e.g. a malloc that grows via mremap(MREMAP_MAYMOVE)
        // (mmap a new region, copy, munmap the old) — the window below the hint
        // eventually exhausts while plenty of freed space remains above it, so
        // mmap(NULL,...) returns None and mremap fails with -ENOMEM in a retry
        // storm.  Searching top-down from the fixed ceiling reuses freed gaps,
        // matching the top-down unmapped-area search every POSIX mmap relies on
        // (man 2 mmap / man 2 mremap MREMAP_MAYMOVE).
        // Lowest legal mmap base (page 0 is reserved as the NULL guard page).
        const FLOOR: u64 = 0x1000;

        // Single descending sweep of the address-sorted VMA list — O(n), not the
        // former O(n²) (a per-candidate `areas.iter().any(overlaps)` re-scan plus
        // a per-step `areas.iter().rev().find(...)`).  Under a browser's mmap
        // churn the VMA list grows into the thousands; the quadratic walk then
        // ran for millions of `overlaps()` calls per mmap, and because mmap runs
        // non-preemptibly in Ring 0 (the timer ISR does not preempt kernel mode)
        // a single such call could monopolise the CPU for seconds, starving the
        // compositor / poll threads and wedging interactive progress.  The
        // sorted list lets us find the highest free gap in one pass.
        //
        // `self.areas` is maintained sorted ascending by `base` (see insert_vma),
        // so iterating in reverse visits VMAs from highest to lowest.  `ceiling`
        // tracks the top of the currently-considered free window, descending from
        // the fixed MMAP_BASE ceiling past each mapping.  The first (highest) gap
        // of at least `size` wins — the standard top-down unmapped-area search
        // (man 2 mmap kernel-chosen VA semantics; matches the e1aa90d1 intent of
        // reusing space freed by munmap, which sits above the running hint).
        //
        // VMAs at or above MMAP_BASE (e.g. thread stacks in the dedicated stack
        // ASLR window, which starts at STACK_ASLR_MIN == MMAP_BASE) lie outside
        // the search window and are simply skipped — `ceiling` is already capped
        // at MMAP_BASE so they never constrain a candidate.
        let mut ceiling = MMAP_BASE;
        for vma in self.areas.iter().rev() {
            // Skip mappings entirely above the ceiling (stack-window VMAs, or any
            // VMA already above the descended ceiling): they cannot bound a gap
            // inside [FLOOR, ceiling).
            if vma.base >= ceiling {
                continue;
            }
            // Gap between this VMA's top and the current ceiling.  Clamp the
            // VMA end into the window so a mapping that straddles MMAP_BASE does
            // not produce a phantom gap above the ceiling.
            let gap_top = ceiling;
            let gap_bot = vma.end().min(ceiling).max(FLOOR);
            if gap_top >= gap_bot && gap_top - gap_bot >= size {
                // Highest fitting gap: place the allocation at its top.
                return Some(gap_top - size);
            }
            // Descend the ceiling below this VMA and continue.
            ceiling = vma.base.min(ceiling);
        }

        // Final gap: everything below the lowest VMA, down to the NULL guard.
        if ceiling > FLOOR && ceiling - FLOOR >= size {
            return Some(ceiling - size);
        }

        None // Ran out of address space
    }

    /// Adjust the program break (brk syscall).
    ///
    /// If `new_brk` > current brk, expand the heap VMA (or create one).
    /// If `new_brk` < current brk, shrink/unmap pages.
    /// Returns the new brk value.
    pub fn adjust_brk(&mut self, new_brk: u64) -> u64 {
        let new_brk = page_align_up(new_brk);

        if new_brk < self.brk_start {
            return self.brk; // Can't shrink below heap start
        }

        if new_brk == self.brk {
            return self.brk;
        }

        // W216 H_5j-B: heap VMA grow/shrink mutates the area list; notify the
        // PFH install loop.  insert_vma below also bumps on the create-heap
        // path; double-bump is harmless (counter is monotonic).
        self.generation.fetch_add(1, Ordering::Release);

        if new_brk > self.brk {
            // Expanding: ensure we have a heap VMA
            if let Some(heap_vma) = self.areas.iter_mut().find(|v| v.name == "[heap]") {
                heap_vma.length = new_brk - heap_vma.base;
            } else {
                // Create the heap VMA
                let heap_vma = VmArea {
                    base: self.brk_start,
                    length: new_brk - self.brk_start,
                    prot: PROT_READ | PROT_WRITE,
                    flags: MAP_PRIVATE | MAP_ANONYMOUS,
                    backing: VmBacking::Anonymous,
                    name: "[heap]",
                };
                let _ = self.insert_vma(heap_vma);
            }
        } else {
            // Shrinking: save old brk before modifying, then unmap freed pages
            let old_brk = self.brk;

            if let Some(heap_vma) = self.areas.iter_mut().find(|v| v.name == "[heap]") {
                if new_brk <= self.brk_start {
                    // Remove the heap VMA entirely
                    self.areas.retain(|v| v.name != "[heap]");
                } else {
                    heap_vma.length = new_brk - heap_vma.base;
                }
            }

            // Unmap pages in [new_brk, old_brk) and return their frames to the
            // PMM.  `unmap_and_free_range_in` clears each PTE, decrements the
            // page refcount, performs a cross-CPU TLB shootdown, and frees any
            // frame whose refcount reaches zero (or routes through quarantine if
            // the shootdown timed out).  This replaces the former
            // unmap_page_in + shootdown_range pair, which cleared PTEs and
            // issued the TLB shootdown but never called page_ref_dec or
            // pmm::free_page — leaking every shrunk heap page permanently into
            // the PMM until process exit (W216 audit brk-shrink finding).
            if new_brk < old_brk {
                crate::mm::vmm::unmap_and_free_range_in(self.cr3, new_brk, old_brk - new_brk);
            }
        }

        self.brk = new_brk;
        self.brk
    }

    /// Dump all VMAs for debugging.
    pub fn dump(&self) {
        crate::serial_println!("  VmSpace CR3={:#x}, {} VMAs, brk={:#x}:", self.cr3, self.areas.len(), self.brk);
        for vma in &self.areas {
            crate::serial_println!("    {:?}", vma);
        }
    }
}

/// Deregister this VmSpace's `mm_sem` from the cr3 registry when the
/// `VmSpace` is dropped.  The `Arc<RwLock<()>>` itself remains alive for
/// any reader that already obtained a clone via `mm_sem_for_cr3` — the
/// `RwLock` outlives the map entry by exactly the time it takes the last
/// in-flight reader/writer to release its guard.
///
/// ## vfork-style shared mm_sem
///
/// When a vfork child's VmSpace is built via `from_existing_cr3`, it shares
/// the parent's `Arc<RwLock<()>>`.  The registry slot must NOT be removed
/// when the child drops — the parent still needs the entry.
///
/// While the registry Mutex is held during `drop`, `Arc::strong_count`
/// counts:
///   * `self.mm_sem` — the VmSpace being dropped (+1), and
///   * `reg[self.cr3]` — the registry's own stored Arc (+1).
///
/// A count of exactly 2 means only self and the registry hold refs → safe
/// to evict.  A count > 2 means at least one other VmSpace (the vfork parent
/// while the child is dropping) still holds a clone; in that case we leave
/// the registry entry intact.
///
/// External callers that obtained a clone via `mm_sem_for_cr3` (short-lived
/// PTE-mutation guards) always drop their clone before the VmSpace drops, so
/// they never inflate the count at `VmSpace::drop` time.
impl Drop for VmSpace {
    fn drop(&mut self) {
        // Sentinel: cr3=0 is used by test fixtures and kernel threads without
        // a registered VmSpace.
        if self.cr3 == 0 {
            return;
        }
        let mut reg = MM_REGISTRY.lock();
        if let Some(slot) = reg.get(&self.cr3) {
            // Only remove if:
            //   1. The slot still names our Arc (not a replacement from exec
            //      or a PMM-recycled cr3 reuse), AND
            //   2. No other VmSpace also holds a clone of this Arc.
            //
            // While the registry Mutex is held, strong_count accounts for:
            //   * `self.mm_sem`    — this VmSpace being dropped (+1)
            //   * `reg[self.cr3]` — the registry's own stored Arc (+1)
            //   * Any other VmSpace that shares this Arc (vfork child/parent)
            //
            // If strong_count == 2 only self and the registry hold refs →
            // safe to evict.  A count > 2 means at least one other VmSpace
            // (e.g. the vfork parent while the child is dropping, or vice
            // versa) still holds a clone — leave the registry entry intact.
            if Arc::ptr_eq(slot, &self.mm_sem) && Arc::strong_count(&self.mm_sem) == 2 {
                reg.remove(&self.cr3);
                // Generation registry tracks the same lifecycle (per-cr3,
                // shared with from_existing_cr3 vfork siblings).  Remove the
                // entry only when the sem entry was also removed so the two
                // registries stay coherent.
                drop(reg);
                let mut greg = MM_GEN_REGISTRY.lock();
                if let Some(gslot) = greg.get(&self.cr3) {
                    if Arc::ptr_eq(gslot, &self.generation)
                        && Arc::strong_count(&self.generation) == 2
                    {
                        greg.remove(&self.cr3);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// VMA operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaError {
    /// The requested range overlaps with an existing VMA.
    Overlap,
    /// Out of virtual address space.
    NoSpace,
    /// Out of physical memory.
    OutOfMemory,
    /// Invalid arguments.
    InvalidArg,
    /// Permission denied.
    PermissionDenied,
}

/// Disposition of a write-protection fault on a present, writable-VMA page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFaultAction {
    /// MAP_SHARED writable mapping: mark the existing frame writable in place
    /// and write through it.  The store MUST be visible to every other mapping
    /// of the same region (POSIX mmap(2) MAP_SHARED) — copy-on-write would
    /// strand the store in a private frame no other mapper can see.
    WriteThrough,
    /// MAP_PRIVATE (or VMA-less orphan) writable mapping: copy-on-write — give
    /// the writer a private frame so the store stays private to this mapping.
    CopyOnWrite,
}

/// Decide how a write-protection fault on a present page must be resolved,
/// given the VMA flags (`MAP_SHARED` / `MAP_PRIVATE`) of the faulting mapping.
///
/// This is the single source of truth shared by the page-fault handler and
/// its unit test.  Per POSIX mmap(2): stores through a MAP_SHARED mapping are
/// visible to all mappings of the region (write-through); stores through a
/// MAP_PRIVATE mapping are private (copy-on-write).
pub fn write_fault_action(vma_flags: VmFlags) -> WriteFaultAction {
    if vma_flags & MAP_SHARED != 0 {
        WriteFaultAction::WriteThrough
    } else {
        WriteFaultAction::CopyOnWrite
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Align an address up to the next page boundary.
pub fn page_align_up(addr: u64) -> u64 {
    (addr + 0xFFF) & !0xFFF
}

/// Align an address down to the page boundary.
pub fn page_align_down(addr: u64) -> u64 {
    addr & !0xFFF
}
