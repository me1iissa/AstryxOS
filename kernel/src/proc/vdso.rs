//! vDSO — virtual Dynamic Shared Object.
//!
//! Maps a small position-independent shared object plus a kernel-managed
//! "vvar" page into every user process address space so glibc / musl can
//! call `clock_gettime`, `gettimeofday`, `time`, and `getcpu` without
//! entering the kernel.
//!
//! # Per-process layout
//!
//! ```text
//!   VDSO_WINDOW_BASE + 0x0000   vvar page  (R, kernel-writable, no-X)
//!   VDSO_WINDOW_BASE + 0x1000   vDSO ELF   (R + X, no-W)
//! ```
//!
//! `AT_SYSINFO_EHDR` is set to `VDSO_WINDOW_BASE + 0x1000` — the ELF
//! header of the vDSO image.  glibc / musl probe this address, parse the
//! .dynsym, resolve `__vdso_clock_gettime` (etc.) under version "LINUX_2.6"
//! and call the resolved function pointer for every subsequent clock read.
//!
//! The vDSO ELF itself is built once at compile time by `kernel/build.rs`
//! and embedded into the kernel image via `include_bytes!`.  See
//! `kernel/vdso/vdso.S` for the assembly source and `vdso.lds` for the
//! linker script that anchors the vvar fields at fixed negative virtual
//! addresses (so RIP-relative addressing in .text reaches the kernel-
//! supplied vvar page wherever the kernel chose to map it).
//!
//! # vvar page
//!
//! A single 4 KiB page holding:
//!
//! ```text
//!   offset  type   field        writer            reader
//!   0x00    u32    seq          PIT timer ISR     vDSO (loop while odd)
//!   0x04    u32    tick_hz      boot init         (informational)
//!   0x08    u64    ticks        PIT timer ISR     vDSO clock_*/time()
//!   0x10    u64    wall_secs    boot init         vDSO realtime path
//! ```
//!
//! Atomicity is provided by a classic seqlock: the writer increments
//! `seq` to an odd value before each multi-field update and back to
//! the next even value after.  Readers retry while `seq` is odd and
//! whenever the value changes between pre-read and post-read snapshots.
//!
//! Only the global PIT tick counter and the wall-clock-at-boot offset
//! need to live in the vvar page.  Per-CPU getcpu uses RDTSCP entirely
//! in userspace (the kernel writes `IA32_TSC_AUX = cpu_index` on every
//! AP at startup) — no vvar field needed.
//!
//! # Lifetime
//!
//! - The vvar page is **shared by all user processes** (one global
//!   physical page mapped into each process's PML4 at the same virtual
//!   address).  We allocate it once in [`init_global_vvar`] called from
//!   the kernel boot path, then map the same physical address into each
//!   process at execve time.  The mapping is read-only for the user.
//!
//! - The vDSO ELF page(s) are likewise mapped from a globally-allocated
//!   physical region.  This reduces both physical memory footprint and
//!   cache pollution: every process executes the same physical bytes.
//!
//! - On process exit we DO NOT free the global vvar / vDSO pages;
//!   `unmap_user_vmas()` decrements per-PT refcounts but the global
//!   refcount stays well above zero because every process holds one.
//!
//! Public references:
//!   vdso(7)         — AT_SYSINFO_EHDR, symbol versioning, fast-path layout
//!   clock_gettime(2)— clk_id semantics
//!   ELF-64 spec     — PT_LOAD, p_vaddr, p_filesz semantics

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::mm::pmm::{self, PAGE_SIZE};
use crate::mm::vma::{VmArea, VmBacking, MAP_PRIVATE, PROT_EXEC, PROT_READ};
use crate::mm::{refcount, vmm};

/// Embedded vDSO ELF image, produced at build time by `kernel/build.rs`.
static VDSO_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vdso.so"));

/// Virtual base of the vDSO + vvar window in every user process.
///
/// Located 16 MiB below the interpreter base (`INTERP_BASE = 0x7F00_0000_0000`)
/// so neither the interpreter's BSS expansion nor any stack growth can
/// collide with it.
pub const VDSO_WINDOW_BASE: u64 = 0x7EFF_F000_0000;

/// Fixed sub-offset within the window: vvar page first, vDSO ELF second.
/// The vDSO ELF source uses RIP-relative addressing with a hard-coded
/// `-0x1000` offset to reach vvar fields, so this layout is part of the
/// kernel/vDSO ABI contract — see `kernel/vdso/vdso.lds`.
pub const VVAR_PAGE_OFFSET: u64 = 0x0000;
pub const VDSO_ELF_OFFSET:  u64 = 0x1000;

/// Runtime address of the vDSO ELF header in user space (= AT_SYSINFO_EHDR).
pub const VDSO_ELF_BASE: u64 = VDSO_WINDOW_BASE + VDSO_ELF_OFFSET;
pub const VVAR_BASE:     u64 = VDSO_WINDOW_BASE + VVAR_PAGE_OFFSET;

/// AT_SYSINFO_EHDR auxv type constant (= 33 per Linux UAPI, vdso(7)).
pub const AT_SYSINFO_EHDR: u64 = 33;

/// vvar field offsets (must match the absolute symbol values produced
/// by `kernel/vdso/vdso.lds`).
const VVAR_OFF_SEQ:        usize = 0x00; // u32
const VVAR_OFF_TICK_HZ:    usize = 0x04; // u32
const VVAR_OFF_TICKS:      usize = 0x08; // u64
const VVAR_OFF_WALL_SECS:  usize = 0x10; // u64

/// Physical address of the kernel-allocated, globally-shared vvar page.
/// Set once by [`init`].
static VVAR_PHYS: AtomicU64 = AtomicU64::new(0);

/// Physical base address of the kernel-allocated, globally-shared vDSO
/// ELF region (contiguous; spans `vdso_n_pages()` 4 KiB pages).  Set once
/// by [`init`].
static VDSO_PHYS: AtomicU64 = AtomicU64::new(0);

/// Number of pages occupied by the embedded vDSO ELF image (rounded up).
/// The vdso.S / vdso.lds layout places .text at vaddr 0x1000 within the
/// vDSO ELF and vvar at vaddr -0x1000; this works for any ELF size
/// because the kernel simply maps consecutive pages of the ELF image at
/// VDSO_ELF_BASE, VDSO_ELF_BASE + 0x1000, ... — the rip-relative offsets
/// never reference pages other than [VDSO_ELF_BASE, VDSO_ELF_BASE + size)
/// for code and VVAR_BASE for data.
fn vdso_n_pages() -> usize {
    (VDSO_IMAGE.len() + PAGE_SIZE - 1) / PAGE_SIZE
}

/// Initialise the global vvar + vDSO physical pages.
///
/// Allocates one physical page for vvar, populates it with the boot-time
/// constants (`tick_hz`, `wall_secs`), and copies the embedded vDSO ELF
/// bytes into a freshly-allocated physical page (or pages).
///
/// Must be called once during kernel boot, AFTER the PMM and refcount
/// subsystems are up but before any user process is loaded.
///
/// Safe to call from CPU 0 only at boot — there is no synchronisation
/// because no APs are running yet.
pub fn init() {
    if VVAR_PHYS.load(Ordering::Relaxed) != 0 {
        return; // already initialised
    }

    // ── Allocate and populate the vvar page ─────────────────────────
    let vvar_phys = pmm::alloc_page().expect("[vDSO] PMM exhausted at vvar init");
    unsafe {
        let p = phys_to_virt(vvar_phys);
        core::ptr::write_bytes(p, 0, PAGE_SIZE);

        // tick_hz constant — informational; vDSO code uses a hard-coded 100.
        write_u32(p, VVAR_OFF_TICK_HZ, 100);

        // Capture wall-clock seconds at boot; the vDSO reconstructs the
        // current wall-clock time as `wall_secs + ticks / tick_hz`.
        let wall = crate::drivers::rtc::read_unix_time();
        write_u64(p, VVAR_OFF_WALL_SECS, wall);

        // seq starts at 0 (even = stable).
        write_u32(p, VVAR_OFF_SEQ, 0);

        // Initial ticks snapshot (will be overwritten on the next timer ISR).
        let initial_ticks = crate::arch::x86_64::irq::TICK_COUNT
            .load(core::sync::atomic::Ordering::Relaxed);
        write_u64(p, VVAR_OFF_TICKS, initial_ticks);
    }
    // Pin the page (refcount = 1) so per-process map/unmap doesn't free it.
    refcount::page_ref_set(vvar_phys, 1);
    VVAR_PHYS.store(vvar_phys, Ordering::Relaxed);

    // ── Allocate and populate the vDSO ELF page(s) ──────────────────
    // We allocate a contiguous run of N physical pages so the per-process
    // mapping loop can map them sequentially at VDSO_ELF_BASE +
    // i*PAGE_SIZE.  Each page is then refcount-pinned so per-process
    // map/unmap sequences cannot accidentally free the global region.
    let n_pages = vdso_n_pages();
    let vdso_phys = pmm::alloc_pages(n_pages)
        .expect("[vDSO] PMM exhausted at vDSO init");
    unsafe {
        let p = phys_to_virt(vdso_phys);
        core::ptr::write_bytes(p, 0, n_pages * PAGE_SIZE);
        let dst = core::slice::from_raw_parts_mut(p, VDSO_IMAGE.len());
        dst.copy_from_slice(VDSO_IMAGE);
    }
    for i in 0..n_pages {
        refcount::page_ref_set(vdso_phys + (i * PAGE_SIZE) as u64, 1);
    }
    VDSO_PHYS.store(vdso_phys, Ordering::Relaxed);

    crate::serial_println!(
        "[vDSO] init: vvar_phys={:#x} vdso_phys={:#x} elf={} bytes wall_secs={}",
        vvar_phys, vdso_phys, VDSO_IMAGE.len(),
        unsafe { read_u64(phys_to_virt(vvar_phys), VVAR_OFF_WALL_SECS) },
    );
}

/// Map the global vvar + vDSO pages into the address space rooted at `cr3`.
///
/// Both pages are mapped read-only-for-user (the vvar page would also
/// be writable if we wanted CoW behaviour, but we want a single shared
/// physical page for all processes — so user-side writes must trap).
///
/// The kernel still writes the vvar page directly via the kernel direct
/// map (`phys_to_virt`), bypassing the user PTE — that's why no W bit
/// is required on the user side.
///
/// On success, returns `VDSO_ELF_BASE` (the runtime AT_SYSINFO_EHDR value).
/// On failure (PMM-OOM in page-table allocation), returns `None`; callers
/// are expected to treat a failed vDSO mapping as non-fatal — the process
/// just goes through the syscall path for clock reads.
///
/// `vmas` is appended with one VMA describing the [vdso] mapping so
/// `/proc/self/maps` can show it.
pub fn map_vdso(cr3: u64, vmas: &mut Vec<VmArea>) -> Option<u64> {
    let vvar_phys = VVAR_PHYS.load(Ordering::Relaxed);
    let vdso_phys = VDSO_PHYS.load(Ordering::Relaxed);
    if vvar_phys == 0 || vdso_phys == 0 {
        return None; // init() not called yet — fall back to syscall path
    }

    // ── vvar page: R + U, no-W, no-X (NX set) ──────────────────────
    // (PAGE_NO_EXECUTE is implied by absence of EXEC in the prot we'd
    // emit via VMA flags; we set it explicitly here to be safe.)
    let vvar_flags =
        vmm::PAGE_PRESENT | vmm::PAGE_USER | vmm::PAGE_NO_EXECUTE;
    if !vmm::map_page_in(cr3, VVAR_BASE, vvar_phys, vvar_flags) {
        return None;
    }
    refcount::page_ref_inc(vvar_phys);

    // ── vDSO ELF page(s): R + U + X, no-W ──────────────────────────
    let vdso_flags = vmm::PAGE_PRESENT | vmm::PAGE_USER;
    let n = vdso_n_pages();
    for i in 0..n {
        let va = VDSO_ELF_BASE + (i * PAGE_SIZE) as u64;
        let pa = vdso_phys + (i * PAGE_SIZE) as u64;
        if !vmm::map_page_in(cr3, va, pa, vdso_flags) {
            // Roll back the vvar + any prior vDSO mappings on failure.
            // (Not strictly necessary — the process will be killed if
            // its VmSpace can't be built — but keeps refcounts accurate.)
            refcount::page_ref_dec(vvar_phys);
            for j in 0..i {
                refcount::page_ref_dec(vdso_phys + (j * PAGE_SIZE) as u64);
            }
            return None;
        }
        refcount::page_ref_inc(pa);
    }

    // ── Register a single VMA for the whole [vdso] window ──────────
    // (Linux exposes "[vvar]" and "[vdso]" as separate entries; we
    // collapse them for now since AstryxOS's /proc/self/maps doesn't
    // expose VMAs to userspace yet.  Splitting is a no-op refactor
    // when /proc/self/maps lands.)
    vmas.push(VmArea {
        base:    VDSO_WINDOW_BASE,
        length:  (VDSO_ELF_OFFSET + (vdso_n_pages() as u64) * PAGE_SIZE as u64) as u64,
        prot:    PROT_READ | PROT_EXEC,
        flags:   MAP_PRIVATE,
        backing: VmBacking::Anonymous,
        name:    "[vdso]",
    });

    Some(VDSO_ELF_BASE)
}

/// Update the vvar `ticks` field.  Called from the PIT timer ISR on every
/// tick.  Uses the seqlock pattern: bump seq odd → write fields → bump
/// seq even.  Readers in user space retry whenever they see an odd seq
/// or a seq mismatch between pre- and post-read snapshots.
///
/// # Safety
/// Must only be called from the timer ISR path or comparable single-
/// writer context.  Concurrent writers would corrupt the seqlock.
#[inline(always)]
pub fn vvar_tick(ticks: u64) {
    let phys = VVAR_PHYS.load(Ordering::Relaxed);
    if phys == 0 {
        return; // pre-init: timer ISR may fire before init() completes
    }

    // Cast through AtomicU32/AtomicU64 to get the right ordering primitives.
    // SAFETY: VVAR_PHYS is a kernel-allocated page; the direct map is valid.
    unsafe {
        let p = phys_to_virt(phys);
        let seq = &*(p.add(VVAR_OFF_SEQ) as *const AtomicU32);
        let tk  = &*(p.add(VVAR_OFF_TICKS) as *const AtomicU64);

        // Acquire writer lock: increment seq from even to odd.
        let cur = seq.load(Ordering::Relaxed);
        seq.store(cur.wrapping_add(1), Ordering::Release); // odd
        tk.store(ticks, Ordering::Release);
        seq.store(cur.wrapping_add(2), Ordering::Release); // even
    }
}

/// Embedded vDSO image size (for tests / introspection).
pub fn vdso_image_size() -> usize {
    VDSO_IMAGE.len()
}

/// Read the current vvar `ticks` field (for tests / introspection).
pub fn vvar_ticks_for_test() -> u64 {
    let phys = VVAR_PHYS.load(Ordering::Relaxed);
    if phys == 0 {
        return 0;
    }
    unsafe { read_u64(phys_to_virt(phys), VVAR_OFF_TICKS) }
}

/// Read the current vvar `wall_secs` field (for tests / introspection).
pub fn vvar_wall_secs_for_test() -> u64 {
    let phys = VVAR_PHYS.load(Ordering::Relaxed);
    if phys == 0 {
        return 0;
    }
    unsafe { read_u64(phys_to_virt(phys), VVAR_OFF_WALL_SECS) }
}

/// Physical address of the global vvar page (or 0 if init not run).
pub fn vvar_phys_for_test() -> u64 {
    VVAR_PHYS.load(Ordering::Relaxed)
}

// ── Internal helpers ───────────────────────────────────────────────

#[inline(always)]
fn phys_to_virt(phys: u64) -> *mut u8 {
    (0xFFFF_8000_0000_0000u64 + phys) as *mut u8
}

#[inline(always)]
unsafe fn write_u32(p: *mut u8, off: usize, v: u32) {
    core::ptr::write(p.add(off) as *mut u32, v);
}

#[inline(always)]
unsafe fn write_u64(p: *mut u8, off: usize, v: u64) {
    core::ptr::write(p.add(off) as *mut u64, v);
}

#[inline(always)]
unsafe fn read_u64(p: *mut u8, off: usize) -> u64 {
    core::ptr::read(p.add(off) as *const u64)
}
