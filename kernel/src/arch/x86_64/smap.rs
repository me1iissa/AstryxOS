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

/// EFLAGS.AC — bit 18 per Intel SDM Vol. 1 §3.4.3 / Vol. 3A §2.5.
/// Used by `UserGuard::new` to detect whether the current kernel
/// codepath is already inside a STAC bracket (AC=1) so the new guard
/// can nest as a passenger instead of issuing its own STAC/CLAC pair.
const RFLAGS_AC: u64 = 1 << 18;

/// Read the current RFLAGS via `pushfq` / `pop`.  Lifted out of
/// `UserGuard::new` to keep that hot path branch-predictable.
#[inline(always)]
unsafe fn rflags() -> u64 {
    let f: u64;
    core::arch::asm!(
        "pushfq",
        "pop {0}",
        out(reg) f,
        options(nomem, preserves_flags),
    );
    f
}

/// RAII bracket for a user-pointer access region.  Sets AC on
/// construction (when SMAP is active **and AC was not already set**)
/// and clears it on drop, including on a panic / fault unwind exit
/// path.
///
/// # Nesting (nest-safe behaviour)
///
/// Per Intel SDM Vol. 3A §4.6.1 and Vol. 2A (CLAC/STAC entries), AC is
/// a single global EFLAGS bit on the executing CPU — there is no
/// hardware "nest count".  Naively pairing every guard's `new` with a
/// `Drop` that issues CLAC produces a real correctness bug whenever
/// the inner callee constructs its own guard: when the inner guard
/// drops it clears AC, but the **outer** caller still expects AC=1
/// for the remainder of its scope, and a subsequent user-pointer
/// dereference under the (logically still open) outer bracket faults
/// with `[SMAP/FAULT] code=0x2 cr2=<user-VA> rflags AC=0`.
///
/// Concrete observed failure mode (post-PR #286, KVM
/// `firefox-test,kdb,syscall-trace`):
///
/// ```text
///   recvmsg arm:        let _g_outer = UserGuard::new();   // STAC → AC=1
///                       read_msg(unix_id, buf)             // inner call:
///                         unix::pop():
///                           let _g_inner = UserGuard::new(); // already AC=1
///                           memcpy(...);
///                         } // _g_inner drops → CLAC → AC=0  ← bug
///                       write user msg_flags;              // ← faults
///                     } // _g_outer drops → CLAC (already clear)
/// ```
///
/// Fix: on construction, sample EFLAGS.AC.  If AC was already 1, this
/// guard is a **passenger** — it issues neither STAC nor CLAC, and
/// `Drop` is a no-op.  Only the **outermost** guard (the one that
/// flipped AC from 0 to 1) issues the matching CLAC at drop.  This
/// matches the established Linux-kernel `user_access_begin` /
/// `user_access_end` semantics where nesting is documented as
/// expected behaviour rather than UB.
///
/// # Usage
///
/// ```ignore
/// // Pointer must already have been range-validated.
/// let val = unsafe {
///     let _g = UserGuard::new();
///     core::ptr::read_volatile(user_ptr)
/// }; // CLAC fires on `_g` drop here (if this is the outermost guard).
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
/// 3. Avoid recursing into a kernel-only path that itself performs
///    unrelated user-pointer dereferences (those should be confined
///    to their own bracket; this is a correctness-of-scope concern,
///    not a soundness concern, since AC is preserved across nesting).
pub struct UserGuard {
    /// `true` if construction actually issued STAC and therefore owns
    /// the matching CLAC.  `false` for two cases:
    ///   1. SMAP is disabled on this CPU.
    ///   2. AC was already set on entry (this guard is nested inside
    ///      another open bracket).
    /// In both cases `Drop` is a no-op for STAC/CLAC and the guard
    /// collapses to a pair of compiler fences.
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
        // Sample SMAP gate + current AC.  We arm (issue STAC) only
        // when SMAP is enabled AND AC is currently clear — i.e. when
        // this guard is the *outermost* bracket on the current CPU.
        // A nested construction (AC already 1) is a no-op so the
        // inner guard's Drop does NOT clear AC out from under the
        // outer caller.  See type-level doc for the recvmsg bug
        // class this prevents (Intel SDM Vol. 3A §4.6.1).
        let smap_on = SMAP_ENABLED.load(Ordering::Relaxed);
        let already_ac = smap_on && (rflags() & RFLAGS_AC) != 0;
        let armed = smap_on && !already_ac;
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
            // Safety: paired with the STAC issued in `new`.  Only the
            // outermost guard sets `armed`; nested guards are
            // passengers and do not touch AC here.
            unsafe { clac() };
        }
    }
}
