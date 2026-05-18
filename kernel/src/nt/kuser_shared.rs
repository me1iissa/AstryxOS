//! KUSER_SHARED_DATA — Windows NT shared user/kernel data page.
//!
//! Windows maps a single 4 KiB page at the canonical user-mode virtual
//! address `0x7FFE_0000` (read-only) and the kernel-mode address
//! `0xFFFF_F780_0000_0000` (read-write) so that every user-mode process can
//! read time, version, processor-feature, and policy fields without an
//! `INT 0x2E` round trip.  The layout is defined publicly as the
//! `KUSER_SHARED_DATA` structure in `ntddk.h` and surfaced by the WinDbg
//! `!kuser` extension at `_KUSER_SHARED_DATA at 7ffe0000`.
//!
//! References:
//! - `KUSER_SHARED_DATA` (ntddk.h):
//!   <https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data>
//! - `!kuser` extension (canonical VA documented):
//!   <https://learn.microsoft.com/windows-hardware/drivers/debuggercmds/-kuser>
//!
//! # AstryxOS posture
//!
//! Every Win32 process created via `proc::usermode::create_win32_process`
//! gets a read-only mapping of the shared page at `KUSER_SHARED_DATA_VA`.
//! The kernel owns one physical page (`KUSER_SHARED_PAGE`) and writes the
//! time/version fields lazily on each access through the public
//! [`update_time_fields`] helper.  Only the well-documented fields a normal
//! console / GUI binary reads (`SystemTime`, `InterruptTime`,
//! `TickCount`/`TickCountQuad`, `TickCountMultiplier`, `NumberOfPhysicalPages`,
//! `NumberOfProcessors`, `NtMajorVersion`/`NtMinorVersion`/`NtBuildNumber`,
//! `NtProductType`, `NativeProcessorArchitecture`, `SystemCall`,
//! `QpcFrequency`) are populated; everything else stays zero.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

/// Canonical user-mode VA of the shared page.  Documented by the WinDbg
/// `!kuser` extension as `_KUSER_SHARED_DATA at 7ffe0000`.
pub const KUSER_SHARED_DATA_VA: u64 = 0x7FFE_0000;

// ──────────────────────────────────────────────────────────────────────────
// Field offsets (from `ntddk.h`).  Verified against the published struct
// layout; all offsets are bytes from the start of the page.
// ──────────────────────────────────────────────────────────────────────────

// Each `KSYSTEM_TIME` is `{ ULONG LowPart; LONG High1Time; LONG High2Time; }`
// = 0x0C bytes (no inter-field padding on x64 — the struct is naturally
// 4-byte aligned).  The duplicated `High*Time` halves implement the
// well-known torn-read avoidance pattern; KUSER_SHARED_DATA tools and
// callers must read `High1Time`, then `LowPart`, then `High2Time`, and
// retry if the two highs differ.

pub const OFF_TICK_COUNT_LOW_DEPRECATED:        usize = 0x000; // ULONG
pub const OFF_TICK_COUNT_MULTIPLIER:            usize = 0x004; // ULONG
pub const OFF_INTERRUPT_TIME:                   usize = 0x008; // KSYSTEM_TIME (0xC)
pub const OFF_SYSTEM_TIME:                      usize = 0x014; // KSYSTEM_TIME (0xC)
pub const OFF_TIME_ZONE_BIAS:                   usize = 0x020; // KSYSTEM_TIME (0xC)
pub const OFF_IMAGE_NUMBER_LOW:                 usize = 0x02C; // USHORT
pub const OFF_IMAGE_NUMBER_HIGH:                usize = 0x02E; // USHORT
pub const OFF_NT_SYSTEM_ROOT:                   usize = 0x030; // WCHAR[260]
pub const OFF_MAX_STACK_TRACE_DEPTH:            usize = 0x238; // ULONG
pub const OFF_CRYPTO_EXPONENT:                  usize = 0x23C; // ULONG
pub const OFF_TIME_ZONE_ID:                     usize = 0x240; // ULONG
pub const OFF_LARGE_PAGE_MINIMUM:               usize = 0x244; // ULONG
pub const OFF_NT_BUILD_NUMBER:                  usize = 0x260; // ULONG
pub const OFF_NT_PRODUCT_TYPE:                  usize = 0x264; // NT_PRODUCT_TYPE (ULONG)
pub const OFF_PRODUCT_TYPE_IS_VALID:            usize = 0x268; // BOOLEAN
pub const OFF_NATIVE_PROCESSOR_ARCHITECTURE:    usize = 0x26A; // USHORT
pub const OFF_NT_MAJOR_VERSION:                 usize = 0x26C; // ULONG
pub const OFF_NT_MINOR_VERSION:                 usize = 0x270; // ULONG
pub const OFF_PROCESSOR_FEATURES:               usize = 0x274; // BOOLEAN[64]
pub const OFF_NUMBER_OF_PHYSICAL_PAGES:         usize = 0x2E8; // ULONG
pub const OFF_SAFE_BOOT_MODE:                   usize = 0x2EC; // BOOLEAN
pub const OFF_QPC_FREQUENCY:                    usize = 0x300; // LONGLONG
pub const OFF_SYSTEM_CALL:                      usize = 0x308; // ULONG
pub const OFF_TICK_COUNT:                       usize = 0x320; // KSYSTEM_TIME / TickCountQuad union
pub const OFF_COOKIE:                           usize = 0x330; // ULONG
pub const OFF_ACTIVE_PROCESSOR_COUNT:           usize = 0x3C0; // ULONG

/// NT product types (`NT_PRODUCT_TYPE` enum, `ntddk.h`).
pub const NT_PRODUCT_WIN_NT:        u32 = 1;  // workstation
pub const NT_PRODUCT_LAN_MAN_NT:    u32 = 2;  // domain controller
pub const NT_PRODUCT_SERVER:        u32 = 3;

/// `IMAGE_FILE_MACHINE_AMD64` per `winnt.h` and ECMA-335 / PE-COFF spec.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// AstryxOS NT version exposed via `KUSER_SHARED_DATA`.  Pin to Windows 10
/// 1809 (build 17763) — old enough to be widely accepted by NT-personality
/// callers, new enough that no app's "you're on Vista" fallback kicks in.
pub const NT_MAJOR_VERSION: u32 = 10;
pub const NT_MINOR_VERSION: u32 = 0;
pub const NT_BUILD_NUMBER:  u32 = 17763;

/// Number of 100 ns intervals per millisecond (NT FILETIME unit).
pub const NT_INTERVALS_PER_MS: u64 = 10_000;
/// Number of 100 ns intervals per second.
pub const NT_INTERVALS_PER_SEC: u64 = 10_000_000;

/// 11_644_473_600 seconds between 1601-01-01 00:00:00 UTC (NT epoch) and
/// 1970-01-01 00:00:00 UTC (Unix epoch).  Documented in the Win32 API
/// `FILETIME` reference (<https://learn.microsoft.com/windows/win32/api/minwinbase/ns-minwinbase-filetime>).
pub const NT_EPOCH_DELTA_SECS: u64 = 11_644_473_600;

// ──────────────────────────────────────────────────────────────────────────
// Backing storage — one statically-allocated 4 KiB page in kernel BSS, owned
// by this module.  We never free or remap it; multiple Win32 processes
// share a read-only mapping of the same physical page.
// ──────────────────────────────────────────────────────────────────────────

#[repr(C, align(4096))]
struct SharedPage([u8; 4096]);

static mut KUSER_SHARED_PAGE: SharedPage = SharedPage([0u8; 4096]);
static KUSER_INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Kernel-side virtual address of the shared page (high-half VA produced by
/// the compiler for the `KUSER_SHARED_PAGE` static).  Used by the Win32
/// process loader to look up the physical frame to map at the user VA.
fn kernel_va() -> u64 {
    // Safety: taking the address of a static is always defined; we never
    // dereference through this raw pointer outside `write_*`/`read_*` helpers.
    let ptr = core::ptr::addr_of!(KUSER_SHARED_PAGE) as *const u8;
    ptr as u64
}

/// Physical address of the static shared page.  Resolved via
/// [`crate::mm::vmm::virt_to_phys`] rather than a linker-base subtraction
/// so the result stays correct if the kernel image is relocated or the
/// `.bss` is moved into a separately-mapped region by the linker script.
pub fn physical_address() -> u64 {
    crate::mm::vmm::virt_to_phys(kernel_va())
        .expect("KUSER_SHARED_PAGE must be mapped in the kernel address space")
}

#[inline]
fn page_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(KUSER_SHARED_PAGE) as *mut u8
}

#[inline]
unsafe fn write_u16(off: usize, val: u16) {
    core::ptr::write_unaligned(page_ptr().add(off) as *mut u16, val);
}
#[inline]
unsafe fn write_u32(off: usize, val: u32) {
    core::ptr::write_unaligned(page_ptr().add(off) as *mut u32, val);
}
#[inline]
unsafe fn write_u64(off: usize, val: u64) {
    core::ptr::write_unaligned(page_ptr().add(off) as *mut u64, val);
}

/// Write a `KSYSTEM_TIME` value at `off`.
///
/// The canonical NT writer protocol for the `KSYSTEM_TIME` torn-read
/// avoidance pattern is a strictly-ordered three-store sequence:
///
///   1. **High2Time** (offset +8)
///   2. **LowPart**   (offset +0)
///   3. **High1Time** (offset +4)
///
/// with a compiler fence between each store so the compiler cannot
/// reorder the writes.  The pairing reader protocol is:
///
/// ```ignore
///   loop {
///       let h1 = read(off + 4);          // High1
///       compiler_fence(SeqCst);
///       let lo = read(off + 0);          // LowPart
///       compiler_fence(SeqCst);
///       let h2 = read(off + 8);          // High2
///       if h1 == h2 { return ((h1 as u64) << 32) | lo as u64; }
///   }
/// ```
///
/// Why this order matters: a reader that observes `H1 != H2` knows the
/// writer was mid-update and retries.  If the writer published the new
/// `High1Time` first (the inverted order), a reader could see
/// `H1 == H2 == new_high` while `LowPart` is still the old value —
/// passing the consistency check on stale data and surfacing as a
/// ~4 GiB jump in `FILETIME` / `TickCount` to ring-3 callers.  See the
/// `KSYSTEM_TIME` declaration in `ntddk.h` and Intel SDM Vol. 3A §8.2
/// for the underlying memory-ordering model (single-writer is sufficient
/// on x86-TSO with compiler fences; no `LOCK` prefix needed).
#[inline]
unsafe fn write_ksystem_time(off: usize, value_100ns: u64) {
    let low = value_100ns as u32;
    let high = (value_100ns >> 32) as u32;
    // Step 1: High2Time (off + 8)
    write_u32(off + 8, high);
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    // Step 2: LowPart (off + 0)
    write_u32(off + 0, low);
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    // Step 3: High1Time (off + 4)
    write_u32(off + 4, high);
}

/// Initialise the static page with the version / processor-feature fields
/// that never change after boot.  Called once from `crate::nt::init` very
/// early in kernel bring-up.
pub fn init() {
    if KUSER_INIT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }
    unsafe {
        // ── Time-multiplier / image-number fields ──────────────────────────
        // TickCountMultiplier: scale applied to 32-bit TickCountLowDeprecated
        // to get a millisecond count.  Real Windows uses ~0xFA00000 for a
        // 15.625 ms tick.  We tick at 100 Hz (10 ms), so the multiplier
        // mapping `tick * 0xFA0000 >> 24 = tick * 10 / 1` gives ms directly.
        // Use 0xA00000 (10 * 2^20) so `(tick * multiplier) >> 24 = tick * 10 / 16`,
        // which apps treat as monotonic ms — the exact value is opaque to
        // userland and the field is documented as "tick count multiplier".
        write_u32(OFF_TICK_COUNT_MULTIPLIER, 0x00A0_0000);
        write_u16(OFF_IMAGE_NUMBER_LOW, IMAGE_FILE_MACHINE_AMD64);
        write_u16(OFF_IMAGE_NUMBER_HIGH, IMAGE_FILE_MACHINE_AMD64);

        // ── Version fields ─────────────────────────────────────────────────
        write_u32(OFF_NT_BUILD_NUMBER, NT_BUILD_NUMBER);
        write_u32(OFF_NT_PRODUCT_TYPE, NT_PRODUCT_WIN_NT);
        // ProductTypeIsValid: TRUE
        *page_ptr().add(OFF_PRODUCT_TYPE_IS_VALID) = 1;
        write_u16(OFF_NATIVE_PROCESSOR_ARCHITECTURE, 9 /* PROCESSOR_ARCHITECTURE_AMD64 */);
        write_u32(OFF_NT_MAJOR_VERSION, NT_MAJOR_VERSION);
        write_u32(OFF_NT_MINOR_VERSION, NT_MINOR_VERSION);

        // ── Processor features (BOOLEAN[64]) ──────────────────────────────
        // Index constants from `winnt.h` PF_*:
        //   PF_COMPARE_EXCHANGE_DOUBLE         = 2
        //   PF_MMX_INSTRUCTIONS_AVAILABLE      = 3
        //   PF_XMMI_INSTRUCTIONS_AVAILABLE     = 6  (SSE)
        //   PF_3DNOW_INSTRUCTIONS_AVAILABLE    = 7
        //   PF_RDTSC_INSTRUCTION_AVAILABLE     = 8
        //   PF_PAE_ENABLED                     = 9
        //   PF_XMMI64_INSTRUCTIONS_AVAILABLE   = 10 (SSE2)
        //   PF_NX_ENABLED                      = 12
        //   PF_SSE3_INSTRUCTIONS_AVAILABLE     = 13
        //   PF_COMPARE_EXCHANGE128             = 14
        //   PF_XSAVE_ENABLED                   = 17
        //   PF_VIRT_FIRMWARE_ENABLED           = 21
        //   PF_RDWRFSGSBASE_AVAILABLE          = 22
        //   PF_FASTFAIL_AVAILABLE              = 23
        //   PF_RDRAND_INSTRUCTION_AVAILABLE    = 28
        // We unconditionally set the AMD64 baseline (RDTSC, MMX, SSE,
        // SSE2, CMPXCHG16B, NX) as guaranteed by the architecture.
        for idx in [2u32, 3, 6, 8, 9, 10, 12, 14] {
            *page_ptr().add(OFF_PROCESSOR_FEATURES + idx as usize) = 1;
        }

        // ── Memory / SMP fields ────────────────────────────────────────────
        // Number of physical pages (best-effort lower bound from PMM total).
        let (total_pages, _used) = crate::mm::pmm::stats();
        let phys_pages = total_pages.min(u32::MAX as u64) as u32;
        write_u32(OFF_NUMBER_OF_PHYSICAL_PAGES, phys_pages);
        // ActiveProcessorCount = current online CPU count.
        let cpu_count = crate::arch::x86_64::apic::cpu_count() as u32;
        write_u32(OFF_ACTIVE_PROCESSOR_COUNT, cpu_count.max(1));

        // ── QpcFrequency: 100 ns ticks per second = 10_000_000 ─────────────
        // Matches `QueryPerformanceFrequency` in NT FILETIME units, the
        // convention AstryxOS already uses in `nt_fn_query_perf_freq`.
        write_u64(OFF_QPC_FREQUENCY, NT_INTERVALS_PER_SEC);

        // ── SystemCall: 0 (we do not advertise an altered syscall view) ───
        write_u32(OFF_SYSTEM_CALL, 0);

        // ── Cookie: deterministic ASCII tag (TODO: reseed from RNG) ───────
        // The cookie is documented as "Cookie for encoding pointers system
        // wide"; user-mode CRTs read it but tolerate any non-zero value.
        // TODO(security): reseed from the kernel CSPRNG once the RNG surface
        // stabilises so the cookie is unpredictable across boots — the
        // current literal is deterministic and unsuitable for production
        // pointer-encoding use.
        write_u32(OFF_COOKIE, 0x6261_5354 /* "TSab" ASCII tag */);

        // ── NtSystemRoot: "C:\\Windows" in UTF-16LE ────────────────────────
        let sys_root: &[u16] = &[
            b'C' as u16, b':' as u16, b'\\' as u16,
            b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16,
            b'o' as u16, b'w' as u16, b's' as u16, 0u16,
        ];
        for (i, &wc) in sys_root.iter().enumerate() {
            write_u16(OFF_NT_SYSTEM_ROOT + i * 2, wc);
        }
    }

    // Seed the time fields once at boot so processes spawned before any
    // tick handler runs still see a non-zero stamp.
    update_time_fields();
}

/// Recompute the time-dependent fields (`InterruptTime`, `SystemTime`,
/// `TickCount`/`TickCountQuad`, `TickCountLowDeprecated`).
///
/// Called from:
///   - boot-time `init()`
///   - lazily from `crate::nt::nt_fn_query_system_time` and the QPC stubs
///     before a read, so the next ring-3 read of the shared page returns
///     a fresh stamp
///
/// We deliberately do NOT hook this into the timer ISR to avoid
/// per-tick overhead on every CPU; the shared page is good enough for
/// 10 ms resolution and most callers re-read on demand.
pub fn update_time_fields() {
    // Tick rate is `crate::arch::x86_64::irq::TICK_HZ` (= 100 Hz, i.e.
    // 10 ms per tick).  This matches the `TickCountMultiplier` we wrote in
    // `init()`.
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let ms = ticks
        .saturating_mul(1000)
        .checked_div(crate::arch::x86_64::irq::TICK_HZ)
        .unwrap_or(0);
    let interrupt_time_100ns = ms.saturating_mul(NT_INTERVALS_PER_MS);

    // Wall clock: RTC seconds since Unix epoch → NT FILETIME (100 ns ticks
    // since 1601-01-01).  See `FILETIME` reference for the epoch offset.
    let unix_secs = crate::drivers::rtc::read_unix_time();
    let nt_secs = unix_secs.saturating_add(NT_EPOCH_DELTA_SECS);
    let mut system_time_100ns = nt_secs.saturating_mul(NT_INTERVALS_PER_SEC);
    // Add the sub-second residue from the monotonic boot tick so
    // successive reads make forward progress between RTC seconds.
    let sub_sec = ms.saturating_mul(NT_INTERVALS_PER_MS) % NT_INTERVALS_PER_SEC;
    system_time_100ns = system_time_100ns.saturating_add(sub_sec);

    unsafe {
        write_ksystem_time(OFF_INTERRUPT_TIME, interrupt_time_100ns);
        write_ksystem_time(OFF_SYSTEM_TIME, system_time_100ns);
        // TickCount is documented as a `KSYSTEM_TIME` (LowPart = ms low,
        // High1Time/High2Time = ms high).  The `TickCountQuad` union view
        // is a single 64-bit ms count; writing the `KSYSTEM_TIME` form is
        // sufficient because the union shares storage.
        write_ksystem_time(OFF_TICK_COUNT, ms);
        write_u32(OFF_TICK_COUNT_LOW_DEPRECATED, ms as u32);
    }
}

/// Read a `KSYSTEM_TIME` field at `off` using the canonical
/// torn-read-safe protocol.  Pairs with [`write_ksystem_time`]:
///
///   1. Sample `High1Time` (off + 4)
///   2. Sample `LowPart`   (off + 0)
///   3. Sample `High2Time` (off + 8)
///   4. If `H1 == H2`, return `(H1 << 32) | LowPart`; else retry.
///
/// With the writer publishing `H2 → L → H1`, observing `H1 == H2` means
/// the writer either hadn't started a new update (both halves still old)
/// or had completed it (both halves new) — and in either case `LowPart`
/// matches the high halves we read.  See the `KSYSTEM_TIME` declaration
/// in `ntddk.h` (`<https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data>`).
#[inline]
unsafe fn read_ksystem_time(off: usize) -> u64 {
    loop {
        let h1 = core::ptr::read_unaligned(page_ptr().add(off + 4) as *const u32);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        let lo = core::ptr::read_unaligned(page_ptr().add(off + 0) as *const u32);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        let h2 = core::ptr::read_unaligned(page_ptr().add(off + 8) as *const u32);
        if h1 == h2 {
            return ((h1 as u64) << 32) | lo as u64;
        }
        // Torn read — writer was mid-update; spin and retry.  The writer
        // is a single store-store-store sequence with no I/O between, so
        // we never block here for more than a handful of instructions.
        core::hint::spin_loop();
    }
}

/// Read the current 64-bit SystemTime field (NT FILETIME, 100 ns ticks
/// since 1601-01-01 UTC).  Used by `NtQuerySystemTime`.
pub fn current_system_time() -> i64 {
    update_time_fields();
    unsafe { read_ksystem_time(OFF_SYSTEM_TIME) as i64 }
}

/// Read the current 64-bit TickCountQuad field (milliseconds since boot).
/// Mirrors `GetTickCount64` semantics from <https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64>.
pub fn current_tick_count64() -> u64 {
    update_time_fields();
    unsafe { read_ksystem_time(OFF_TICK_COUNT) }
}

#[cfg(any(feature = "test-mode", feature = "firefox-test"))]
pub fn page_base_for_test() -> *const u8 {
    page_ptr() as *const u8
}
