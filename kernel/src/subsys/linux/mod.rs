//! Linux Compatibility Subsystem
//!
//! Translates Linux x86_64 syscalls to their Aether equivalents.
//! Processes with `SubsystemType::Linux` use this personality.
//!
//! # Translation Model
//! Linux binaries (musl, glibc) issue `SYSCALL` with Linux-number in RAX.
//! The kernel's `dispatch()` detects `SubsystemType::Linux` and routes here.
//! Each syscall is translated: Linux number → Aether handler or stub.
//! No Linux kernel code is re-implemented; we only translate the interface.
//!
//! # Current State
//! ~90 Linux syscall numbers mapped in `kernel/src/syscall/mod.rs::dispatch_linux()`.
//! Full coverage target: ~385 Linux x86_64 native syscalls.
//!
//! # Phase 0.2 Plan
//! Extract `dispatch_linux()` from `syscall/mod.rs` into `linux/syscall.rs` here.
//! Then add helper modules: translate.rs, errno.rs, signal.rs, elf.rs.
//!
//! # Implementation Phases
//! - Phase 1: ~90 syscalls → static musl hello, ls, cat (done)
//! - Phase 2: ~150 syscalls → coreutils, bash
//! - Phase 3: ~250 syscalls → GCC + dynamic linking (in progress)
//! - Phase 4: ~350 syscalls → X11 client protocol
//!
//! See `.ai/subsystem/LINUX.md` for full design and syscall translation table.

// ─── Submodules ──────────────────────────────────────────────────────────────

/// Linux errno constants and VfsError / NtStatus conversion helpers.
pub mod errno;

/// Linux x86_64 syscall dispatch and Linux-specific helpers.
/// Extracted from `kernel/src/syscall/mod.rs` in Phase 0.2.
pub mod syscall;

/// Vfork canary snapshot-pair + sibling-syscall tagger diagnostic.  See
/// the module docstring (`vfork_diag.rs`) for the three channels and the
/// reference set (POSIX vfork(2) / clone(2), Intel SDM Vol. 3A §6.8,
/// System V AMD64 ABI §3.4.5.2).  Gated entirely behind `vfork-canary-diag`
/// so master builds are byte-identical.
#[cfg(feature = "vfork-canary-diag")]
pub mod vfork_diag;

/// ELF write-trace diagnostic for the W215-aliasing axis-N investigation:
/// arms a hardware write-only watchpoint on the ld-musl `.data.rel.ro`
/// slot at `0x7F00_0003_7e18` for the duration of the `CLONE_VM|CLONE_VFORK`
/// parent-block window and snapshots the page content before/after.
/// Per Intel SDM Vol. 3B §17.2.4 / §17.2.5.  Gated behind `elf-write-trace`
/// (which also pulls in `w215-diag` for the DR0–DR3 plumbing) so master
/// builds are byte-identical without it.
#[cfg(feature = "elf-write-trace")]
pub mod elf_write_trace;

/// Live `__clone` pthread-args smoking-gun diagnostic — W215 axis-N
/// continuation per tech-lead cross-walk verdict 2026-05-20.  Captures the
/// pthread-args struct's `start_routine` and `arg` fields at successful
/// clone(2)/clone3(2) syscall exit into a 16-entry ring keyed by (pid,
/// tid); on a later CPL-3 `#GP` looks up the trapping child and emits
/// `[CLONE-CHECK]` (framing-falsifier, fires for every matched trap) and
/// `[CLONE-SMOKING-GUN]` (fires when captured `start_routine == rip`).
/// Disambiguates F1 (pre-clone corruption) from F2 (mid-flight kernel
/// aliasing — W215 axis-N) via phys-frame variance.  See POSIX
/// pthread_create(3) / clone(2) / clone3(2), AMD64 SysV ABI §3.4, Intel
/// SDM Vol. 3A §6.15 (`#GP`).  Gated behind `clone-args-diag` so master
/// builds remain byte-identical.
#[cfg(feature = "clone-args-diag")]
pub mod clone_args_diag;

/// SSP-canary divergence diagnostic.  Fires once per `#GP` taken from CPL 3
/// at the publicly-exported musl `__stack_chk_fail` two-byte `hlt;ret` stub
/// (ld-musl-x86_64.so.1 + 0x1c7f9, per the musl ldso `.dynsym`).  The hook
/// emits the live `IA32_FS_BASE` MSR, the master canary at `*(fs_base+0x28)`,
/// and the saved-canary qword the SSP epilogue was about to read.  Mode A
/// (saved-canary mutated) and Mode B (FS_BASE shifted mid-function) are
/// distinguishable from the emitted lines.  Bounded to a small number of
/// events per boot.  See POSIX sigaction(2), Intel SDM Vol. 3A §3.4.4.1
/// (IA32_FS_BASE), §6.15 (#GP), System V AMD64 ABI §6.4.  Gated behind
/// `ssp-canary-diag` so master builds remain byte-identical.
#[cfg(feature = "ssp-canary-diag")]
pub mod ssp_diag;

/// K2b F3 foreign-frame writer trap — hardware-watchpoint-based diagnostic
/// for the canary slot at the libxul `FireGLXTestProcess` `[rbp-8]` VA.
/// Arms write-only DR slots on BOTH the user-VA and `PHYS_OFF + backing
/// phys` channels at firefox-bin execve completion; the existing
/// `[W215/DR-WATCH-FIRE]` line names the writer RIP on every hit.  The
/// F3 hypothesis space (kernel `clone_for_fork` direct PTE writes vs
/// stack-VMA grow path replacing PTEs without `map_page_in` vs sibling-
/// CPU TLB-stale read) is distinguished by the writer RIP — see the
/// module docstring for the per-mode signature.  See Intel SDM Vol. 3B
/// §17.2 (DR0–DR3, DR7), Intel SDM Vol. 3A §4.10 (TLB management),
/// System V AMD64 ABI §6.4 (SSP / `__stack_chk_guard`).  Diagnostic-only;
/// gated behind `f3-watch` so master builds remain byte-identical.
#[cfg(feature = "f3-watch")]
pub mod f3_watch;

/// FS_BASE preserve-across-execution probe.  Records every kernel-side
/// `WRMSR(IA32_FS_BASE)` into a per-boot ring; on a CPL-3 SSP-canary `#GP`
/// the trapping TID's recent event history is dumped alongside the
/// `[SSP-DIAG]` block.  Distinguishes the "FS.base shifted between
/// prologue and epilogue" hypothesis from the "FS.base preserved; canary
/// fail is on the stack slot" hypothesis — neither of which is falsified
/// by `ax_eq_fs28=1` alone.  See module docstring for sites instrumented
/// and Intel SDM Vol. 3A §3.4.4.1 (`IA32_FS_BASE`).  Gated behind
/// `fs-base-trace` so master builds remain byte-identical.
#[cfg(feature = "fs-base-trace")]
pub mod fs_base_trace;

/// D7 PT_TLS BSS-slot writer trap.  Arms a write-only hardware
/// watchpoint on the linear address `fs_base - 0x18` of the firefox-bin
/// init thread (pid=1, tid=1) at the first `proc::write_fs_base()`
/// transition from zero to non-zero.  The watched qword is part of the
/// firefox-bin PT_TLS BSS tail (`memsz=0x20, filesz=0`), which ELF
/// gABI §5.2 requires to be zero on first access; Mozilla's
/// `GetThreadRegistrationTime` reads it and on zero takes an
/// early-return path (Linux behaviour), on non-zero takes a slow path
/// to a NULL deref (the deterministic AstryxOS fault at
/// `firefox-bin + 0x207dc`).  Each `#DB` fire emits a
/// `[W215/DR-WATCH-FIRE] kind_tag=3 …` line naming the writer RIP, CS
/// and CR3 — `CS=0x23` (CPL-3) implicates upstream, `CS=0x08` (CPL-0)
/// implicates the kernel.  See Intel SDM Vol. 3B §17.2.4 (DR0–DR3,
/// DR7); ELF gABI §5.2.  Diagnostic-only; gated behind `d7-bss-watch`
/// so master builds remain byte-identical.
#[cfg(feature = "d7-bss-watch")]
pub mod d7_bss_watch;

/// D8 fault-time TLS-slot dump + phys-frame provenance.  Distinguishes
/// the surviving PSE Z1 hypothesis (anon-mmap returned a recycled
/// physical frame without ELF gABI §5.2 zero-fill) from a re-framing
/// (slot is zero at fault time; `r14` came from elsewhere) by
/// inspecting `[fs:-0x18]` at the very instant of the deterministic
/// pid=1 firefox-bin NULL-deref fault.  Content-gated on
/// `cr2 == 0x20`, the `49 8b 5e 20` opcode prefix of
/// `mov 0x20(%r14), %rbx`, and `pid == 1`.  Re-uses the existing
/// FREE_SHADOW / ALLOC_SHADOW phys-provenance rings (PR #354 / Track K)
/// to name the most recent `pmm::free_page` / `pmm::alloc_page` caller
/// RIPs for the backing frame.  See Intel SDM Vol. 3A §3.4.4 (TLS via
/// `IA32_FS_BASE`); ELF gABI §5.2 (PT_TLS BSS zero-fill); POSIX
/// `mmap(2)` (anonymous-mapping zero contract); CWE-908 (Use of
/// Uninitialized Resource).  Diagnostic-only; gated behind
/// `d8-tls-fault-dump` so master builds remain byte-identical.
#[cfg(feature = "d8-tls-fault-dump")]
pub mod d8_fault_tls_dump;

/// D15 `RegisteredThread::mThreadInfo` slot writer trap.  Arms a write-
/// only hardware watchpoint on the heap qword at `*(fs:-0x18) + 0x38`
/// — the inner-field that Mozilla's `GetThreadRegistrationTime` reads
/// into `r14` before the sc=1171 fault deref at `[r14+0x20]`.  Because
/// the outer heap-object VA is non-deterministic across boots (mallocng
/// arenas jitter under F3-v2 PR #368 entropy), the arm is dispatched
/// from the Linux syscall entry hook: each call from pid=1 / tid=1
/// (firefox-bin init thread per PSE Phase 1) reads `[fs:-0x18]` through
/// the kernel direct map and arms on the inner field the first time the
/// outer pointer is non-zero.  Catches Mozilla / sibling-thread writers
/// to `mThreadInfo` between the TLS publish and the sc=1171 fault.
/// Diagnostic-only; gated behind `d15-mthread-watch` so master builds
/// remain byte-identical.  Refs: Intel SDM Vol. 3B §17.2.4 (DR0–DR3,
/// DR7), §17.3.1.1; Intel SDM Vol. 3A §3.4.4.1 (`IA32_FS_BASE`);
/// Mozilla searchfox `mozglue/baseprofiler/core/RegisteredThread.cpp`;
/// System V AMD64 ABI §3.4.4; POSIX `mmap(2)`.
#[cfg(feature = "d15-mthread-watch")]
pub mod d15_mthread_watch;

/// D16 SSP-canary saved-slot writer trap.  Post-F3-saga-closure (PR
/// #368) the sc plateau moved to musl `__stack_chk_fail` at
/// ld-musl+0x87f9 (sc=1230-1232 deterministic, byte-identical 3/3).
/// The saved canary qword reads `0x30` in the low byte — the F3 SSP
/// fingerprint returning at a different RIP.  Critical anchor: the
/// canary slot backing phys `0x127114c0` is **deterministic across
/// all 3 trials**, letting D16 arm a PHYS_OFF-channel DR at execve
/// time without waiting for the user stack page to be demand-paged.
/// A complementary user-VA DR is late-armed from the syscall-entry
/// hook (same shape as D15).  Each fire emits `[W215/DR-WATCH-FIRE]
/// kind_tag=5 …` naming the writer RIP / CS / CR3.  Diagnostic-only;
/// gated behind `d16-canary-watch` so master builds remain byte-
/// identical.  Refs: Intel SDM Vol. 3B §17.2.4 (DR0–DR3, DR7),
/// §17.3.1.1 (data-breakpoint trap timing); Intel SDM Vol. 3A
/// §3.4.4.1 (`IA32_FS_BASE`); System V AMD64 ABI §3.4.1 (SSP);
/// POSIX execve(2); CWE-121, CWE-587.
#[cfg(feature = "d16-canary-watch")]
pub mod d16_canary_watch;

/// D17 read-side aliasing test for the SSP-canary slot.  D16
/// established that all 32 fires on the canary slot were CPL-3 user
/// writers (no kernel direct-map writer), superficially falsifying
/// "kernel writer corrupts the slot".  D17 closes the remaining
/// hypothesis: the writer wrote correct data to the correct phys,
/// but a residual page-table or TLB aliasing (W215-class on the stack
/// canary VA) means the epilogue's read resolves the same VA to a
/// *different* phys at fault time.  D17 records (rip, va, phys, value)
/// at each D16 fire, re-resolves the canary VA at SSP-fail `#GP` time,
/// and emits a verdict line: `D17-PHYS-DIFFER` (read-side aliasing
/// confirmed), `D17-PHYS-MATCH-VALUE-DIVERGED` (D16 missed a writer),
/// `D17-PHYS-MATCH-VALUE-MATCH` (no kernel-side anomaly — points to
/// the read instruction itself), or `D17-NO-WRITE-CAPTURED` (D16 did
/// not fire — inconclusive).  Diagnostic-only; gated behind
/// `d17-aliasing-test` so master builds remain byte-identical.  Refs:
/// Intel SDM Vol. 3A §4.6 (page-table walk), §4.10 (TLB management,
/// PHYS_OFF coherence), §11.4 (cache coherence on aliased VAs);
/// Intel SDM Vol. 3B §17.2.4 (DR0–DR3), §17.3.1.1 (trap-after-retire);
/// System V AMD64 ABI §3.4.1 (SSP); POSIX `execve(2)`; CWE-787.
#[cfg(feature = "d17-aliasing-test")]
pub mod d17_aliasing_test;

/// D20 — write-only DR watchpoint on the kernel-stack canary slot of the
/// post-#396/#397 STACK_CANARY_CORRUPT bugcheck victim (PID 2 TID 5).  PRs
/// #396 (multi-tier emergency kstack fallback) and #397 (`mm/vmm.rs`
/// `BATCH` 1024→128) merged with the demo gate UNMOVED (3/3 trials still
/// bugcheck at sc=1230..1232).  ZERO `[KSTACK/TIER]` and ZERO
/// `[KSTACK/CANARY-FAIL]` records in the same trials prove the writer is
/// not in either of the brk(2) / munmap(2) paths PR #395's stack-pressure
/// analysis named.  D20 arms a DR write-only watchpoint on
/// `[kernel_stack_base, kernel_stack_base + 8)` for the first N PID-2
/// thread creations and lets `handle_db_exception` emit a
/// `[W215/DR-WATCH-FIRE] kind_tag=6 …` line on the writing CPU — the RIP
/// in that line directly names the writer (Intel SDM Vol. 3B §17.3.1.1).
/// Gated behind `d20-kstack-canary-watch` so master builds remain
/// byte-identical.
#[cfg(feature = "d20-kstack-canary-watch")]
pub mod d20_kstack_canary_watch;

/// Bounded broadcast-within-cluster compensation for FUTEX_WAKE.  Mitigates
/// the older-glibc `pthread_cond_signal` race
/// (<https://sourceware.org/bugzilla/show_bug.cgi?id=25847>) by
/// optionally waking nearby waiters when a `FUTEX_WAKE(uaddr, n)` would
/// otherwise leave a recently-parked sibling stranded.  See
/// `futex_cluster.rs` for the safety harness.
#[cfg(any(feature = "firefox-test", feature = "test-mode"))]
pub mod futex_cluster;

/// Futex-key resolution diagnostic for `FUTEX_WAKE woken=0`.
///
/// Emits `[FUTEX-WAKE-EMPTY]` lines describing the bucket landscape when
/// a wake returns zero, so the harness can decide whether the kernel
/// key-resolution is correct (waiter on different uaddr → userspace
/// POSIX defence) or wrong (waiter and waker hash to different keys for
/// the same logical futex).  Per `futex(2)`
/// (<https://man7.org/linux/man-pages/man2/futex.2.html>) the
/// `FUTEX_PRIVATE_FLAG` key is `(mm, uaddr)`; AstryxOS uses `(pid, uaddr)`
/// equivalent.  See `futex_key_diag.rs` for the audit framing.
#[cfg(feature = "firefox-test")]
pub mod futex_key_diag;

/// Firefox-test diagnostic ring helpers — tiny shim that holds the "current
/// syscall's ring-entry index" so sys_read_linux / sys_open_linux can attach
/// path / read-content context without threading it through every signature.
#[cfg(feature = "firefox-test")]
pub mod syscall_ring {
    use core::sync::atomic::{AtomicI64, Ordering};
    use crate::arch::x86_64::apic::MAX_CPUS;

    /// Per-CPU "current syscall ring entry".  -1 means "no entry".
    /// A u64 would wrap harmlessly; i64 lets us store -1 as a sentinel.
    static CUR: [AtomicI64; MAX_CPUS] = [const { AtomicI64::new(-1) }; MAX_CPUS];

    #[inline]
    fn cpu() -> usize { crate::arch::x86_64::apic::cpu_index() }

    #[inline]
    pub fn set_current_entry(idx: Option<usize>) {
        CUR[cpu()].store(idx.map(|v| v as i64).unwrap_or(-1), Ordering::Relaxed);
    }

    #[inline]
    pub fn clear_current_entry() {
        CUR[cpu()].store(-1, Ordering::Relaxed);
    }

    #[inline]
    pub fn current_entry() -> Option<usize> {
        let v = CUR[cpu()].load(Ordering::Relaxed);
        if v < 0 { None } else { Some(v as usize) }
    }
}

// Re-export the two most-used helpers at the subsystem level so submodules
// can write `use crate::subsys::linux::{vfs_err, EINVAL};`.
pub use errno::{vfs_err, EINVAL, ENOENT, EBADF, ENOMEM, EFAULT, ENOSYS,
                EAGAIN, ENFILE, EMFILE, EINTR, EACCES, EPERM, EEXIST, ENOTDIR,
                EISDIR, ENOTEMPTY, ENOSPC, EROFS, EPIPE, ESPIPE, EBUSY,
                ENODEV, ENOTTY, E2BIG, ENOEXEC, ELOOP, ECHILD, EIO};

// ============================================================================
// Subsystem dispatch entry point
// ============================================================================
//
// `dispatch_linux()` lives in `kernel/src/syscall/mod.rs` during Phase 0.
// It will migrate to `linux/syscall.rs` in Phase 0.2.  This wrapper provides
// the stable public API surface now.
//   crate::subsys::linux → crate::syscall  (one-way, no circular dep)

/// Linux compatibility syscall entry point.
///
/// Delegates directly to `self::syscall::dispatch`.  External code should use
/// this rather than calling `syscall::dispatch_linux` directly.
#[inline]
pub fn dispatch(
    num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, arg6: u64,
) -> i64 {
    self::syscall::dispatch(num, arg1, arg2, arg3, arg4, arg5, arg6)
}
