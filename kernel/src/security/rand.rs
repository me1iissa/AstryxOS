//! Minimal kernel RNG for ASLR and other security-sensitive randomisation.
//!
//! Uses RDRAND when the CPU supports it (CPUID.01H:ECX bit 30).  Falls back
//! to a xorshift64 PRNG seeded from RDTSC + LAPIC timer tick counter so we
//! always return a non-zero value even on emulators that don't implement RDRAND.
//!
//! This is NOT a cryptographic RNG; it is suitable only for ASLR bias
//! selection where even a weak PRN prevents deterministic exploitation.

/// Return a 64-bit pseudo-random value.
///
/// Panics only if inline-asm constraints fail — which is impossible on x86_64.
/// Caller must be prepared for identical values on successive calls with
/// probability 1/2^64 (or 1/2^28 after masking for ASLR).
#[inline]
pub fn rand_u64() -> u64 {
    // Try RDRAND (Intel Ivy Bridge+, AMD Ryzen+).  CPUID.01H:ECX[30] = RDRAND.
    let has_rdrand: bool = unsafe {
        let ecx: u32;
        core::arch::asm!(
            "push rbx",   // rbx is reserved by LLVM
            "cpuid",
            "pop rbx",
            in("eax") 1u32,
            lateout("ecx") ecx,
            out("edx") _,
        );
        ecx & (1 << 30) != 0
    };

    if has_rdrand {
        // Retry loop: RDRAND can return CF=0 on entropy-pool depletion (rare).
        // Intel recommends up to 10 retries.
        for _ in 0..10 {
            let val: u64;
            let ok: u8;
            unsafe {
                core::arch::asm!(
                    "rdrand {val}",
                    "setc   {ok}",
                    val = out(reg) val,
                    ok  = out(reg_byte) ok,
                );
            }
            if ok != 0 {
                return val;
            }
        }
        // RDRAND failed 10 times — fall through to TSC fallback below.
    }

    // Fallback: xorshift64 seeded from RDTSC mixed with LAPIC tick counter.
    // The LAPIC counter gives jitter even when RDTSC is deterministic in KVM.
    let tsc: u64 = unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi);
        ((hi as u64) << 32) | lo as u64
    };
    let tick = crate::arch::x86_64::irq::TICK_COUNT
        .load(core::sync::atomic::Ordering::Relaxed);

    // Mix tsc and tick into an initial state; ensure non-zero.
    let mut state: u64 = tsc
        .wrapping_mul(0x9E3779B97F4A7C15) // Fibonacci hashing constant
        .wrapping_add(tick.wrapping_mul(0x6C62272E07BB0142));
    if state == 0 {
        state = 0xDEAD_BEEF_CAFE_BABE;
    }

    // Three rounds of xorshift64 to thoroughly mix the bits.
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;

    state
}

/// Return a random offset for ASLR, aligned to `PAGE_SIZE` (4 KiB).
///
/// The offset is uniformly distributed over a window of `2^entropy_bits`
/// pages.  For 28 bits of entropy the window is 2^28 * 4096 = 1 TiB, which
/// fits comfortably in the user lower-half (0..0x0000_7FFF_FFFF_FFFF).
///
/// `entropy_bits` should be at most 28 for 64-bit user space.
#[inline]
pub fn aslr_page_offset(entropy_bits: u32) -> u64 {
    debug_assert!(entropy_bits <= 40, "entropy_bits too large for user address space");
    let mask: u64 = ((1u64 << entropy_bits) - 1) << 12; // aligned to 4 KiB
    rand_u64() & mask
}
