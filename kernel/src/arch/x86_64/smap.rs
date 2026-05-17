//! Supervisor Mode Access Prevention (SMAP) — STAC/CLAC plumbing.
//!
//! SMAP (CR4 bit 21) causes the CPU to raise #PF on any supervisor-mode
//! access to a user-mapped page (PTE.U/S=1) unless EFLAGS.AC (bit 18) is
//! set.  The STAC instruction sets AC; CLAC clears it.  Per Intel SDM
//! Vol. 3A §4.6 and Vol. 2A (CLAC/STAC entries).
//!
//! # Threat model
//!
//! Without SMAP, a kernel bug that dereferences an attacker-controlled
//! user pointer (e.g. a confused-deputy write through a corrupted
//! function pointer the attacker steered at a user address) executes
//! silently, giving the attacker an arbitrary-kernel-write primitive
//! mediated by their own user pages.  With SMAP enabled, any such
//! unguarded access faults immediately and the page-fault handler can
//! cleanly terminate the offending process — converting an arbitrary-
//! write primitive into a fail-stop.  See CVE-2014-9322 (BadIRET) and
//! CWE-269 / CWE-119 / CWE-823 for the bug-class catalogue.
//!
//! Crucially, SMAP is *additive* to validation: every legitimate
//! kernel→user dereference must still range-check via
//! [`crate::syscall::validate_user_ptr`] to reject kernel-VA pointers
//! (which SMAP does NOT cover — those pages have PTE.U=0) and to bound
//! the access length.  STAC/CLAC merely enable the *intentional* access
//! once the pointer has been validated.
//!
//! # Runtime gating
//!
//! Older CPUs (and TCG without `-cpu Haswell-v4` or newer) do not
//! advertise SMAP.  The [`SMAP_ENABLED`] atomic is set by
//! [`crate::arch::x86_64::enable_cpu_security_features`] only when the
//! CPUID probe succeeds AND CR4.SMAP is actually set.  The gated
//! [`stac_if_smap`] / [`clac_if_smap`] wrappers (and the [`UserGuard`]
//! RAII) check this flag, so on a non-SMAP CPU the bracketing collapses
//! to a single relaxed load + branch — no #UD from issuing STAC on
//! hardware that does not implement it.
//!
//! Once `SMAP_ENABLED` is set, it never clears — there is no legitimate
//! reason to disable SMAP at runtime, and a one-way transition lets
//! the compiler hoist the check out of tight loops once the BSP has
//! finished bring-up.

use core::sync::atomic::{AtomicBool, Ordering};

/// Set by [`crate::arch::x86_64::enable_cpu_security_features`] after
/// CR4.SMAP is asserted.  Cleared at boot.  One-way transition (never
/// re-cleared) so callers can treat it as monotonic.
///
/// Tests / kernel paths that drive a syscall handler with a kernel-VA
/// buffer must NOT set this flag — those accesses do not target user
/// pages and SMAP is silent for them.  The flag is set exactly once,
/// from BSP and from every AP, after the CPU has actually committed
/// CR4.SMAP.
pub static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Raw STAC — set EFLAGS.AC.  Allows subsequent supervisor accesses
/// to user-mapped pages without a #PF.  Must be paired with a
/// matching [`clac()`] on every exit path including faults.
///
/// # Safety
///
/// Unconditional on the underlying CPU supporting SMAP.  Issuing STAC
/// on a non-SMAP CPU raises #UD per Intel SDM Vol. 2A (STAC).  Callers
/// should prefer [`stac_if_smap`] / [`UserGuard`] instead.
///
/// IMPORTANT: we deliberately omit `nomem` here.  The default (memory
/// clobber) tells LLVM that any memory access could happen as a side
/// effect of this asm block, which prevents the optimiser from hoisting
/// user-memory reads (e.g. inlined `copy_nonoverlapping` word loads)
/// past the STAC instruction.  Without the memory clobber, LLVM
/// previously rewrote `let _g = UserGuard::new(); copy_nonoverlapping(p, buf, 32); use buf`
/// into direct reads from `p` AFTER the CLAC fired — faulting with
/// AC=0.  Same rationale applies to CLAC below.
#[inline(always)]
pub unsafe fn stac() {
    core::arch::asm!("stac", options(nostack));
}

/// Raw CLAC — clear EFLAGS.AC.  Re-arms SMAP enforcement for any
/// subsequent supervisor access to user-mapped pages.  Must be
/// executed before returning from any STAC scope.
///
/// # Safety
///
/// See [`stac`] — same #UD hazard on non-SMAP CPUs.  Prefer
/// [`clac_if_smap`] / [`UserGuard`].  See `stac` for the
/// memory-clobber rationale.
#[inline(always)]
pub unsafe fn clac() {
    core::arch::asm!("clac", options(nostack));
}

/// Issue STAC iff SMAP has been enabled on this CPU.  Safe to call from
/// any kernel context; collapses to a single relaxed load + branch when
/// SMAP is not advertised (e.g. early boot before
/// [`crate::arch::x86_64::enable_cpu_security_features`], or on TCG
/// without `+smap`).
///
/// # Safety
///
/// Caller must pair this with [`clac_if_smap`] (or use [`UserGuard`]
/// which does that on drop).  Holding AC=1 across an unrelated kernel
/// codepath would silently bypass SMAP for any user-pointer deref that
/// path performs.
#[inline(always)]
pub unsafe fn stac_if_smap() {
    if SMAP_ENABLED.load(Ordering::Relaxed) {
        stac();
    }
}

/// Issue CLAC iff SMAP has been enabled on this CPU.  Pair with
/// [`stac_if_smap`].
///
/// # Safety
///
/// Idempotent: clearing an already-clear AC is a no-op.  The danger
/// runs the other way — failing to call this after [`stac_if_smap`]
/// leaves SMAP disabled for the remainder of the kernel path.
#[inline(always)]
pub unsafe fn clac_if_smap() {
    if SMAP_ENABLED.load(Ordering::Relaxed) {
        clac();
    }
}

/// RAII bracket for a user-pointer access region.  Sets AC on
/// construction (when SMAP is active) and clears it on drop, including
/// on a panic / fault unwind exit path.
///
/// # Usage
///
/// ```ignore
/// // Pointer must already have been range-validated.
/// let val = unsafe {
///     let _g = UserGuard::new();
///     core::ptr::read_volatile(user_ptr)
/// }; // CLAC fires on `_g` drop here.
/// ```
///
/// # Safety
///
/// Constructing a `UserGuard` is unsafe because it lifts SMAP
/// enforcement for the current CPU until drop.  The caller must:
///
/// 1. Have range-validated the pointer (`validate_user_ptr`) so a
///    kernel-VA cannot slip through this guard.
/// 2. Confine the guard's scope to the minimum needed for the user
///    access — anything else risks an unintended bypass.
/// 3. NOT recurse into a kernel-only path while holding the guard, for
///    the same reason.
pub struct UserGuard {
    /// `true` if construction actually issued STAC.  Drop only issues
    /// the matching CLAC in that case, so a nested guard on a non-SMAP
    /// CPU collapses to two relaxed loads.
    armed: bool,
}

impl UserGuard {
    /// # Safety
    ///
    /// See type-level docs.  The caller assumes responsibility for
    /// ensuring the about-to-be-dereferenced pointer is a validated
    /// user-VA, not a kernel-VA.
    #[inline(always)]
    pub unsafe fn new() -> Self {
        let armed = SMAP_ENABLED.load(Ordering::Relaxed);
        if armed {
            stac();
        }
        // SeqCst compiler fence: prevents LLVM from reordering
        // user-memory accesses across this point.  Without this fence
        // the optimiser can hoist `copy_nonoverlapping`'s individual
        // word loads PAST the UserGuard scope (a literal observed
        // failure mode: `let _g = UserGuard::new(); copy_nonoverlapping(p, buf, 32); ... use buf` was
        // rewritten by LLVM to read directly from `p` AFTER `_g`
        // dropped, faulting with AC=0).  The fence forces the
        // user-memory access ordering to match source order.
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        UserGuard { armed }
    }
}

impl Drop for UserGuard {
    #[inline(always)]
    fn drop(&mut self) {
        // Matching fence to seal the AC=1 region before CLAC.  Same
        // rationale as the constructor fence — LLVM must not move
        // user-memory accesses past the drop boundary.
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        if self.armed {
            // Safety: paired with the STAC issued in `new`.
            unsafe { clac() };
        }
    }
}
