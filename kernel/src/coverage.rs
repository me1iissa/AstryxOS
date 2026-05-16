//! LLVM source-based code-coverage runtime (kernel `coverage` feature).
//!
//! Implements the post-test flush path described in the test-coverage
//! audit (`docs/TEST_COVERAGE_AUDIT_2026-05-16.md` Phase 4 Option A).
//!
//! When the kernel is built with `--features coverage` PLUS the matching
//! `-C instrument-coverage` rustflag (the harness's `--features coverage`
//! path sets both), LLVM emits five linker-delimited sections into the
//! kernel image:
//!
//!   * `__llvm_prf_cnts`  — per-region 64-bit execution counters (mutable,
//!                          incremented at runtime).
//!   * `__llvm_prf_data`  — static profile metadata records that pair each
//!                          counter array with the function it instruments.
//!   * `__llvm_prf_names` — the (possibly compressed) function-name table.
//!   * `__llvm_covmap`    — coverage mapping header + filename list.
//!   * `__llvm_covfun`    — per-function coverage map records (file IDs,
//!                          source range encoding, counter expressions).
//!
//! The `_cnts` section is the only one that mutates at runtime; the rest
//! are static metadata baked into the ELF.  A fully-compliant `.profraw`
//! file requires bytes from all of (cnts + data + names) plus a small
//! version-dependent header — see `llvm/include/llvm/ProfileData/.../InstrProfData.inc`.
//! Producing that header in-kernel is brittle (it changes per LLVM minor
//! version and depends on toolchain-internal constants).  We therefore
//! adopt the audit's recommended hybrid approach:
//!
//!   1. Dump the raw bytes of all five sections as hex `[COV-CHUNK]`
//!      serial lines so a host-side tool with the matching `llvm-tools`
//!      version can synthesise a valid `.profraw` after the fact.
//!   2. Compute a region-level "non-zero counters" summary on-device and
//!      emit it as a single `[COV-SUMMARY]` JSON line — this gives an
//!      immediately useful per-PR coverage metric without any host
//!      post-processing and is the value the planned CI coverage gate
//!      (task #315) will threshold against.
//!
//! Output discipline:
//!   * Every chunk line is `[COV-CHUNK] sec=<name> off=<N> hex=<XX...>`
//!     where chunks are bounded to 256 bytes (512 hex chars + header)
//!     to keep individual serial writes well under any reasonable FIFO
//!     batch limit.
//!   * Section bounds are advertised once each via `[COV-SECTION]`.
//!   * Final summary line is structured JSON parseable by
//!     `scripts/qemu-harness.py coverage --collect`.
//!
//! The walker tolerates `start == stop` for every section, so if the
//! kernel is built with `--features coverage` but rustc was NOT invoked
//! with `-C instrument-coverage`, `dump_profile()` simply emits an empty
//! summary instead of panicking.

use core::sync::atomic::{AtomicBool, Ordering};

// ── Minimal stub profiler runtime ──────────────────────────────────────────
//
// `-C instrument-coverage` makes rustc emit a `__llvm_profile_runtime`
// reference into every instrumented object so the linker pulls in the
// real compiler-rt profile runtime (libclang_rt.profile-*.a).  That
// runtime expects libc (open/write/atexit/getenv/...) which we do not
// have in a no_std kernel.
//
// We sidestep the dependency entirely by providing our own stub symbol:
// the counter array is updated by LLVM's inline atomic increments, so
// the only thing the runtime needs to do is exist.  We do not register
// an atexit handler — the test runner explicitly invokes
// `dump_profile()` before `qemu_exit`, which serves the same role.
//
// The stub avoids the `profiler_builtins` crate (which tries to build
// compiler-rt from C source — see `library/profiler_builtins/build.rs`
// in the rust source tree) and thus removes the cargo `-Z
// build-std=...,profiler_builtins` requirement.  Build with just
// `--features coverage` plus `-C instrument-coverage` in RUSTFLAGS;
// the harness's `_build` helper sets the rustflag automatically.
#[no_mangle]
#[used]
pub static __llvm_profile_runtime: u32 = 0;

extern "C" {
    // Linker-generated bounds (see kernel/linker.ld).  The linker emits
    // these as zero-length symbols at the start/end of each named
    // section, regardless of whether any input objects contributed
    // bytes — so dereferencing the bounds is safe even when the
    // section is empty.
    //
    // We dump only the three allocated sections (`prf_cnts`, `prf_data`,
    // `prf_names`).  The static `__llvm_covmap` / `__llvm_covfun`
    // sections are marked non-allocated by LLVM and live only inside
    // the ELF — the host-side post-processor reads them directly from
    // `target/x86_64-astryx/release/astryx-kernel` when synthesising a
    // `.profraw` file.  Dumping them via serial would be a 1 MiB+
    // waste of telemetry bandwidth.
    static __start___llvm_prf_cnts: u8;
    static __stop___llvm_prf_cnts: u8;
    static __start___llvm_prf_data: u8;
    static __stop___llvm_prf_data: u8;
    static __start___llvm_prf_names: u8;
    static __stop___llvm_prf_names: u8;
}

/// Idempotency guard.  `dump_profile()` is safe to call multiple times
/// but the kdb-triggered flush and the test-runner exit hook can both
/// race; the first caller wins and subsequent callers no-op.
static DUMPED: AtomicBool = AtomicBool::new(false);

/// Reset the idempotency latch so a subsequent `dump_profile()` will
/// re-emit the chunks.  Intended for the kdb `coverage-flush` op which
/// may be called interactively between suite phases for partial
/// snapshots.
pub fn reset() {
    DUMPED.store(false, Ordering::Release);
}

/// Walk every LLVM coverage section, dump it to serial as hex chunks,
/// and emit a single `[COV-SUMMARY]` line with the region-level
/// non-zero-counter percentage.  Returns `(covered_regions,
/// total_regions, bytes_dumped)`; callers may log this but the
/// authoritative output is the serial stream.
pub fn dump_profile() -> (usize, usize, usize) {
    if DUMPED.swap(true, Ordering::AcqRel) {
        // Already emitted in this boot; preserve idempotency.
        return (0, 0, 0);
    }

    crate::serial_println!("[COV-BEGIN] llvm-source-based coverage flush");

    // Dump each section as named hex chunks.  Counter arrays are u64
    // little-endian; the dumper treats them as opaque bytes so the
    // host post-processor handles endianness.
    let mut total_bytes = 0usize;
    total_bytes += dump_section("cnts",  unsafe { &__start___llvm_prf_cnts },  unsafe { &__stop___llvm_prf_cnts });
    total_bytes += dump_section("data",  unsafe { &__start___llvm_prf_data },  unsafe { &__stop___llvm_prf_data });
    total_bytes += dump_section("names", unsafe { &__start___llvm_prf_names }, unsafe { &__stop___llvm_prf_names });

    // Region-level coverage summary.  The `cnts` section is a packed
    // array of u64 counters, one per coverage region.  A non-zero
    // counter means the region executed at least once during the
    // current boot.  This is the metric the CI coverage gate (task
    // #315) will threshold against.
    let (covered, total) = count_regions();
    let pct_x100 = if total == 0 { 0 } else { (covered as u64 * 10_000) / total as u64 };
    let pct_whole = pct_x100 / 100;
    let pct_frac = pct_x100 % 100;
    crate::serial_println!(
        "[COV-SUMMARY] {{\"regions_covered\":{},\"regions_total\":{},\"pct\":\"{}.{}{}\",\"bytes_dumped\":{}}}",
        covered, total, pct_whole,
        if pct_frac < 10 { "0" } else { "" }, pct_frac, total_bytes,
    );
    // Single-line summary that the CI coverage gate can grep directly.
    // Format matches the audit's "per-PR-friendly summary line" spec.
    crate::serial_println!(
        "[COVERAGE] kernel={}.{}{}% regions={}/{} bytes={}",
        pct_whole,
        if pct_frac < 10 { "0" } else { "" }, pct_frac,
        covered, total, total_bytes,
    );
    crate::serial_println!("[COV-END]");

    (covered, total, total_bytes)
}

/// Emit one section's bytes as `[COV-CHUNK]` serial lines plus a
/// `[COV-SECTION]` envelope.  Returns the byte count.
fn dump_section(name: &str, start: &u8, stop: &u8) -> usize {
    let start_ptr = start as *const u8;
    let stop_ptr  = stop  as *const u8;
    let len = (stop_ptr as usize).saturating_sub(start_ptr as usize);
    crate::serial_println!("[COV-SECTION] name={} addr={:p} len={}", name, start_ptr, len);
    if len == 0 {
        return 0;
    }

    // Safety: linker-defined bounds are valid for `len` bytes by
    // construction.  The buffer is rodata for everything except the
    // mutable counter array, and we only read it.
    let bytes = unsafe { core::slice::from_raw_parts(start_ptr, len) };

    // 256 bytes per chunk → 512 hex chars + header fits comfortably
    // inside the 4 KiB serial FIFO without straddling any reasonable
    // host-side line buffer.
    const CHUNK: usize = 256;
    let mut off = 0usize;
    while off < bytes.len() {
        let end = core::cmp::min(off + CHUNK, bytes.len());
        emit_chunk(name, off, &bytes[off..end]);
        off = end;
    }
    len
}

/// Format a single `[COV-CHUNK]` line with inline hex encoding.  We
/// avoid `format!` to keep allocator pressure bounded and to match the
/// fault-immunity discipline of nearby serial-print sites.
fn emit_chunk(sec: &str, off: usize, bytes: &[u8]) {
    use core::fmt::Write;
    // Reusable scratch buffer (sized for CHUNK=256 plus header overhead).
    let mut buf = heapless_hex::HexBuf::new();
    let _ = write!(&mut buf, "[COV-CHUNK] sec={} off={} hex=", sec, off);
    for b in bytes {
        let _ = buf.write_byte_hex(*b);
    }
    crate::serial_println!("{}", buf.as_str());
}

/// Count non-zero entries in the counter array.  Each entry is a
/// little-endian u64 — we read it as `read_unaligned` so we don't
/// depend on the linker giving us an 8-byte-aligned bound (the
/// `ALIGN(8)` in the script makes this redundant in practice but the
/// extra safety costs nothing).
fn count_regions() -> (usize, usize) {
    let start = unsafe { &__start___llvm_prf_cnts as *const u8 };
    let stop  = unsafe { &__stop___llvm_prf_cnts  as *const u8 };
    let len = (stop as usize).saturating_sub(start as usize);
    if len < 8 {
        return (0, 0);
    }
    let total = len / 8;
    let mut covered = 0usize;
    for i in 0..total {
        let p = unsafe { start.add(i * 8) } as *const u64;
        let v = unsafe { core::ptr::read_unaligned(p) };
        if v != 0 {
            covered += 1;
        }
    }
    (covered, total)
}

// ── Tiny no-alloc hex formatter ─────────────────────────────────────────
//
// Sized for one `[COV-CHUNK]` line: header (~48 chars) + 2 * 256 hex
// digits = 560 bytes.  Using a stack buffer instead of `String` keeps
// the dump path inert under low-memory conditions and matches the
// fault-immune-formatter pattern used elsewhere in the kernel.
mod heapless_hex {
    use core::fmt;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    const CAP: usize = 640;

    pub struct HexBuf {
        buf: [u8; CAP],
        len: usize,
    }

    impl HexBuf {
        pub fn new() -> Self {
            Self { buf: [0; CAP], len: 0 }
        }
        pub fn as_str(&self) -> &str {
            // Safety: every push goes through `fmt::Write` which only
            // appends UTF-8, or through `write_byte_hex` which appends
            // ASCII hex digits.
            unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
        }
        pub fn write_byte_hex(&mut self, b: u8) -> fmt::Result {
            if self.len + 2 > CAP { return Err(fmt::Error); }
            self.buf[self.len]     = HEX[(b >> 4) as usize];
            self.buf[self.len + 1] = HEX[(b & 0x0f) as usize];
            self.len += 2;
            Ok(())
        }
    }

    impl fmt::Write for HexBuf {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let b = s.as_bytes();
            if self.len + b.len() > CAP { return Err(fmt::Error); }
            self.buf[self.len..self.len + b.len()].copy_from_slice(b);
            self.len += b.len();
            Ok(())
        }
    }
}
