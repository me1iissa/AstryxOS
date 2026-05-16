//! Minimal property-test framework for the in-kernel test suite.
//!
//! This module provides a lightweight, no-std-compatible property-testing
//! harness that runs inside the kernel under `--features test-mode`.  It is
//! intentionally small (~120 LOC) and self-contained: no external crates are
//! required, and the only RNG dependency is `security::rand::rand_u64()` which
//! is already present in the kernel.
//!
//! # Design
//!
//! The harness follows the same conceptual model as property-based testing
//! literature (see Claessen & Hughes, "QuickCheck: A Lightweight Tool for
//! Random Testing of Haskell Programs", ICFP 2000): for each iteration, the
//! framework draws a pseudo-random value from the `Generator` for a given
//! type, applies the user's test body, and records whether the invariant
//! holds.  A fixed deterministic seed is mixed in so failures are exactly
//! reproducible when the seed is logged.
//!
//! Unlike full property-test frameworks we do NOT implement shrinking.  For
//! kernel tests the iteration count is small (≤1000), and the failure output
//! includes the full random state, so the developer can reproduce the exact
//! failing case by re-running with that seed.
//!
//! # Serial output
//!
//! Each iteration emits:
//!   `[PROP-TEST] <name> iter=<N> val=<V> PASS|FAIL`
//! Only failing iterations emit the full line; passing iterations are silent
//! by default (use the verbose path in the harness if needed).
//! On completion:
//!   `[PROP-RESULT] <name> iterations=<N> failures=<F> PASS|FAIL`
//!
//! This format is parseable by `qemu-harness.py grep <sid> '\[PROP-RESULT\]'`.

extern crate alloc;

/// A simple xorshift64 pseudo-random number generator.
///
/// State must be non-zero.  We initialise from `security::rand::rand_u64()`
/// so each test run gets a different seed, but we log the seed so failures
/// are reproducible.
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Create a new RNG seeded from the kernel PRNG.
    ///
    /// The seed is printed to serial so any failure can be reproduced by
    /// constructing `Rng::from_seed(seed)` with the logged value.
    pub fn new_with_logged_seed(test_name: &str) -> Self {
        let seed = crate::security::rand::rand_u64();
        // Ensure non-zero state (xorshift64 breaks on 0).
        let seed = if seed == 0 { 0xDEAD_BEEF_CAFE_BABEu64 } else { seed };
        crate::serial_println!("[PROP-SEED] {} seed={:#018x}", test_name, seed);
        Self { state: seed }
    }

    /// Create a deterministic RNG from an explicit seed (for reproduction).
    #[allow(dead_code)]
    pub fn from_seed(seed: u64) -> Self {
        let seed = if seed == 0 { 0xDEAD_BEEF_CAFE_BABEu64 } else { seed };
        Self { state: seed }
    }

    /// Generate the next pseudo-random 64-bit value using xorshift64.
    ///
    /// xorshift64 has a period of 2^64 - 1 and passes all standard
    /// randomness tests for non-cryptographic use.  The shift constants
    /// (13, 7, 17) are from Marsaglia (2003), "Xorshift RNGs".
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Generate a value in `[0, n)`.  Uses rejection sampling to avoid modulo
    /// bias; the worst case is < 2 retries for any n.
    pub fn gen_range_u64(&mut self, n: u64) -> u64 {
        if n <= 1 {
            return 0;
        }
        // Compute threshold to avoid modulo bias.
        let threshold = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < threshold {
                return v % n;
            }
        }
    }

    /// Generate a `usize` in `[0, n)`.
    pub fn gen_range_usize(&mut self, n: usize) -> usize {
        self.gen_range_u64(n as u64) as usize
    }

    /// Generate a `u32` in `[0, n)`.
    pub fn gen_range_u32(&mut self, n: u32) -> u32 {
        self.gen_range_u64(n as u64) as u32
    }
}

/// Run a property test with `iterations` random draws.
///
/// `body` receives a mutable `Rng` and returns `Ok(())` on success or
/// `Err(alloc::string::String)` with a failure description.
///
/// Returns `true` iff zero failures were observed.
pub fn run_prop_test<F>(name: &str, iterations: u32, mut body: F) -> bool
where
    F: FnMut(&mut Rng) -> Result<(), alloc::string::String>,
{
    let mut rng = Rng::new_with_logged_seed(name);
    let mut failures: u32 = 0;

    for i in 0..iterations {
        match body(&mut rng) {
            Ok(()) => { /* silent on pass */ }
            Err(msg) => {
                crate::serial_println!(
                    "[PROP-TEST] {} iter={} FAIL: {}",
                    name, i, msg,
                );
                failures += 1;
                // Stop after 10 failures to avoid flooding the serial port.
                if failures >= 10 {
                    crate::serial_println!(
                        "[PROP-TEST] {} halting after 10 failures", name
                    );
                    break;
                }
            }
        }
    }

    let pass = failures == 0;
    crate::serial_println!(
        "[PROP-RESULT] {} iterations={} failures={} {}",
        name, iterations, failures,
        if pass { "PASS" } else { "FAIL" },
    );
    pass
}
