//! SysV Shared Memory — shmget / shmat / shmdt / shmctl
//!
//! Implements kernel-side shared memory segments.  Each segment has a key,
//! a size (rounded up to page granularity), and a physically contiguous
//! backing region.  `shmat` maps the physical pages into the calling
//! process's VmSpace as a Device-backed VMA; `shmdt` removes that VMA.
//!
//! Maximum 64 concurrent segments (sufficient for Firefox/compositor use).

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};

/// IPC_PRIVATE — create a new (non-keyed) segment.
pub const IPC_PRIVATE: i32 = 0;
/// IPC_CREAT — create segment if it doesn't exist.
pub const IPC_CREAT: i32 = 0o1000;
/// IPC_EXCL — fail if segment exists (used with IPC_CREAT).
pub const IPC_EXCL: i32 = 0o2000;
/// IPC_RMID — remove the segment.
pub const IPC_RMID: i32 = 0;
/// IPC_STAT — copy info to shmid_ds.
pub const IPC_STAT: i32 = 2;

const MAX_SEGMENTS: usize = 64;
const PAGE_SIZE: u64 = 4096;

#[derive(Clone)]
pub struct ShmSegment {
    pub id:         u32,   // shmid (== slot index for simplicity)
    pub key:        i32,
    pub size:       u64,   // in bytes (page-aligned)
    pub phys_base:  u64,   // physical base of backing pages
    pub refcount:   u32,   // number of active shmat mappings
    pub in_use:     bool,
}

impl ShmSegment {
    const fn empty() -> Self {
        Self { id: 0, key: 0, size: 0, phys_base: 0, refcount: 0, in_use: false }
    }
}

static SEGMENTS: Mutex<[ShmSegment; MAX_SEGMENTS]> =
    Mutex::new([const { ShmSegment::empty() }; MAX_SEGMENTS]);

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

fn pages_for(size: u64) -> u64 {
    (size + PAGE_SIZE - 1) / PAGE_SIZE
}

/// `shmget(key, size, shmflg)` — get or create a shared memory segment.
/// Returns shmid (≥ 0) on success, negative errno on error.
pub fn shmget(key: i32, size: u64, flags: i32) -> i64 {
    if size == 0 {
        return -22; // EINVAL
    }
    let size_aligned = pages_for(size) * PAGE_SIZE;
    let mut segs = SEGMENTS.lock();

    if key != IPC_PRIVATE {
        // Look for existing segment with this key
        if let Some(seg) = segs.iter().find(|s| s.in_use && s.key == key) {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return -17; // EEXIST
            }
            return seg.id as i64;
        }
        // Not found — require IPC_CREAT
        if flags & IPC_CREAT == 0 {
            return -2; // ENOENT
        }
    }

    // Allocate a new segment
    let slot = match segs.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return -28, // ENOSPC
    };

    // Allocate physical pages
    let n_pages = pages_for(size_aligned);
    let phys_base = match crate::mm::pmm::alloc_pages(n_pages as usize) {
        Some(p) => p,
        None => return -12, // ENOMEM
    };

    // Zero the backing memory through the higher-half physical map.
    //
    // `alloc_pages` returns a *physical* base.  The CPU must reach it through
    // a mapped virtual address: the kernel's higher-half direct map at
    // `PHYS_OFF + phys` covers every physical frame (0 .. 4 GiB), whereas the
    // low identity map (virtual == physical) only covers the first 1 GiB of
    // RAM.  Dereferencing the bare physical address therefore faults the
    // instant `alloc_pages` hands back a frame above 1 GiB — exactly what a
    // large MIT-SHM segment triggers on a >1 GiB guest.  See Intel SDM Vol. 3A
    // §4.5 (4-level paging): a linear address is translated only if every
    // paging-structure entry on its walk is present; the identity range past
    // 1 GiB has no such entries, so the access is a not-present #PF.
    unsafe {
        core::ptr::write_bytes(phys_to_kvirt(phys_base), 0, size_aligned as usize);
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    segs[slot] = ShmSegment {
        id,
        key,
        size: size_aligned,
        phys_base,
        refcount: 0,
        in_use: true,
    };

    crate::serial_println!(
        "[SHM] shmget key={} size={} → id={} phys={:#x}",
        key, size_aligned, id, phys_base
    );

    id as i64
}

/// `shmat(shmid, shmaddr, shmflg)` — attach a shared memory segment.
/// Returns the virtual address where the segment was mapped, or -errno.
pub fn shmat(shmid: u32, shmaddr: u64, _shmflg: i32) -> i64 {
    let pid = crate::proc::current_pid();
    let (size, phys_base) = {
        let mut segs = SEGMENTS.lock();
        let seg = match segs.iter_mut().find(|s| s.in_use && s.id == shmid) {
            Some(s) => s,
            None => return -22, // EINVAL (bad shmid)
        };
        seg.refcount += 1;
        (seg.size, seg.phys_base)
    };

    // Pick a virtual address for the mapping.  If shmaddr == 0, let the VMM
    // choose a free region; otherwise honour the hint (page-aligned).
    let map_vaddr = if shmaddr != 0 {
        shmaddr & !(PAGE_SIZE - 1)
    } else {
        // Find a free region in user space above 0x6000_0000
        pick_vaddr(pid, size)
    };

    if map_vaddr == 0 {
        // Decrement refcount on failure
        let mut segs = SEGMENTS.lock();
        if let Some(seg) = segs.iter_mut().find(|s| s.in_use && s.id == shmid) {
            if seg.refcount > 0 { seg.refcount -= 1; }
        }
        return -12; // ENOMEM
    }

    // Map pages into the process's page tables.
    let n_pages = size / PAGE_SIZE;
    use crate::mm::vmm::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};
    let flags = PAGE_PRESENT | PAGE_USER | PAGE_WRITABLE;
    for i in 0..n_pages {
        let vaddr = map_vaddr + i * PAGE_SIZE;
        let phys  = phys_base + i * PAGE_SIZE;
        crate::mm::vmm::map_page_in(
            get_cr3(pid),
            vaddr,
            phys,
            flags,
        );
    }

    // Register a Device-backed VMA so munmap/shmdt can find it.
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(vs) = proc.vm_space.as_mut() {
                let shm_vma = crate::mm::vma::VmArea {
                    base:    map_vaddr,
                    length:  size,
                    prot:    crate::mm::vma::PROT_READ | crate::mm::vma::PROT_WRITE,
                    flags:   crate::mm::vma::MAP_SHARED,
                    backing: crate::mm::vma::VmBacking::Device { phys_base },
                    name:    "[shm]",
                };
                // Insert at the sorted position rather than a raw push.  The
                // areas list is maintained strictly ascending by base, and
                // VmSpace::find_free_range performs a single DESCENDING pass
                // (areas.iter().rev()) that relies on that ordering.  shmat
                // typically attaches low in the address space (pick_vaddr ~
                // 0x6000_0000) while the list already holds much higher VMAs
                // (libraries, thread stacks near the top of the mmap window);
                // a raw push left that low-base VMA at the END of the Vec, so
                // the descending pass visited it FIRST, computed a phantom
                // free gap spanning the whole window, and returned a base that
                // was actually occupied — making later kernel-chosen mmap()s
                // fail spuriously with ENOMEM (insert_vma's order-independent
                // overlap scan then rejected the bogus placement).
                let pos = vs.areas.iter().position(|v| v.base > shm_vma.base)
                    .unwrap_or(vs.areas.len());
                vs.areas.insert(pos, shm_vma);
                // W216 H_5j-B: notify the PFH install loop of the VMA-list
                // mutation (this site bypasses insert_vma).
                vs.generation.fetch_add(1, core::sync::atomic::Ordering::Release);
            }
        }
    }

    crate::serial_println!(
        "[SHM] shmat id={} → vaddr={:#x} (pid={})",
        shmid, map_vaddr, pid
    );

    map_vaddr as i64
}

/// `shmdt(shmaddr)` — detach a shared memory segment at `shmaddr`.
pub fn shmdt(shmaddr: u64) -> i64 {
    let pid = crate::proc::current_pid();

    // Find the VMA with this base address
    let (phys_base, size) = {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -22,
        };
        let vs = match proc.vm_space.as_mut() {
            Some(v) => v,
            None => return -22,
        };
        let idx = vs.areas.iter().position(|a| {
            a.base == shmaddr
                && matches!(a.backing, crate::mm::vma::VmBacking::Device { .. })
        });
        match idx {
            Some(i) => {
                let vma = vs.areas.remove(i);
                // W216 H_5j-B: notify the PFH install loop of the VMA-list
                // mutation (this site bypasses remove_range).
                vs.generation.fetch_add(1, core::sync::atomic::Ordering::Release);
                match vma.backing {
                    crate::mm::vma::VmBacking::Device { phys_base } => (phys_base, vma.length),
                    _ => unreachable!(),
                }
            }
            None => return -22, // EINVAL — not an shm mapping
        }
    };

    // Unmap page table entries
    let cr3 = get_cr3(pid);
    let n_pages = size / PAGE_SIZE;
    for i in 0..n_pages {
        let vaddr = shmaddr + i * PAGE_SIZE;
        crate::mm::vmm::unmap_page_in(cr3, vaddr);
    }
    // Coalesced TLB shootdown over the SHM range — other CPUs that had
    // attached the same segment must drop their cached translations
    // before the kernel hands the physical frames back to the next
    // user of the segment.
    if n_pages > 0 {
        crate::mm::tlb::shootdown_range(cr3, shmaddr, shmaddr + n_pages * PAGE_SIZE);
    }

    // Decrement refcount on the segment
    {
        let mut segs = SEGMENTS.lock();
        if let Some(seg) = segs.iter_mut().find(|s| s.in_use && s.phys_base == phys_base) {
            if seg.refcount > 0 {
                seg.refcount -= 1;
            }
        }
    }

    crate::serial_println!("[SHM] shmdt vaddr={:#x} (pid={})", shmaddr, pid);
    0
}

/// `shmctl(shmid, cmd, buf)` — control shared memory.
pub fn shmctl(shmid: u32, cmd: i32, buf: u64) -> i64 {
    match cmd {
        IPC_RMID => {
            let mut segs = SEGMENTS.lock();
            if let Some(seg) = segs.iter_mut().find(|s| s.in_use && s.id == shmid) {
                if seg.refcount == 0 {
                    // Free physical pages
                    let n_pages = (seg.size / PAGE_SIZE) as usize;
                    for i in 0..n_pages {
                        crate::mm::pmm::free_page(seg.phys_base + i as u64 * PAGE_SIZE);
                    }
                    *seg = ShmSegment::empty();
                    crate::serial_println!("[SHM] shmctl IPC_RMID id={}", shmid);
                }
                // If refcount > 0, mark for deferred deletion (we just return 0)
                0
            } else {
                -22 // EINVAL
            }
        }
        IPC_STAT => {
            // Write minimal shmid_ds to buf (all zeros — sizes only)
            if buf != 0 {
                let segs = SEGMENTS.lock();
                if let Some(seg) = segs.iter().find(|s| s.in_use && s.id == shmid) {
                    // shmid_ds.shm_segsz at offset 48 on x86_64 Linux
                    unsafe {
                        core::ptr::write_bytes(buf as *mut u8, 0, 112); // sizeof(shmid_ds)
                        *(buf as *mut u64) = seg.size;                   // shm_segsz approx
                    }
                }
            }
            0
        }
        _ => 0, // Ignore unknown cmds
    }
}

/// Look up a segment by its shmid and return its raw `(phys_base, size)`.
///
/// The backing pages are physically contiguous.  The returned value is a
/// *physical* address — suitable for installing a page-table entry, but NOT
/// for direct CPU dereference (the low identity map only covers the first
/// 1 GiB of RAM).  Callers that need to read or write the segment bytes from
/// kernel mode must use [`segment_kvirt`], which returns a higher-half virtual
/// base valid for any frame.  Returns `None` if no in-use segment has that id.
pub fn segment_phys(shmid: u32) -> Option<(u64, u64)> {
    let segs = SEGMENTS.lock();
    segs.iter()
        .find(|s| s.in_use && s.id == shmid)
        .map(|s| (s.phys_base, s.size))
}

/// Look up a segment by its shmid and return its kernel-readable
/// `(virt_base, size)`.
///
/// `virt_base` is the segment's physical base mapped through the kernel's
/// higher-half direct map (`PHYS_OFF + phys`), so it is dereferenceable from
/// kernel mode regardless of where the frame lives in physical memory.  Used
/// by the in-kernel X server's MIT-SHM `ShmPutImage` / `CopyArea` paths to read
/// client pixel data straight from the segment without a per-frame copy.
/// Returns `None` if no in-use segment has that id.
///
/// Per Intel SDM Vol. 3A §4.5, the higher-half direct map is the only mapping
/// guaranteed present for physical addresses above the 1 GiB identity range, so
/// the raw `phys_base` must never be dereferenced directly.
pub fn segment_kvirt(shmid: u32) -> Option<(u64, u64)> {
    let segs = SEGMENTS.lock();
    segs.iter()
        .find(|s| s.in_use && s.id == shmid)
        .map(|s| (phys_to_kvirt(s.phys_base) as u64, s.size))
}

/// Convert a physical frame base into a kernel-dereferenceable pointer via the
/// higher-half direct map.  The map covers physical 0 .. 4 GiB (`PHYS_OFF`),
/// unlike the low identity map which stops at 1 GiB.
#[inline]
fn phys_to_kvirt(phys: u64) -> *mut u8 {
    (crate::mm::vmm::PHYS_OFF + phys) as *mut u8
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_cr3(pid: u64) -> u64 {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter()
        .find(|p| p.pid == pid)
        .and_then(|p| p.vm_space.as_ref())
        .map(|vs| vs.cr3)
        .unwrap_or(0)
}

/// Find a free virtual address region of `size` bytes for `pid`.
fn pick_vaddr(pid: u64, size: u64) -> u64 {
    let hint_base = 0x6000_0000u64;
    let hint_end  = 0x7000_0000u64;

    let procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return 0,
    };
    let vs = match proc.vm_space.as_ref() {
        Some(v) => v,
        None => return 0,
    };

    // Scan candidate addresses
    let mut candidate = hint_base;
    while candidate + size < hint_end {
        let conflict = vs.areas.iter().any(|a| {
            candidate < a.base + a.length && candidate + size > a.base
        });
        if !conflict {
            return candidate;
        }
        candidate += size;
    }
    0
}
