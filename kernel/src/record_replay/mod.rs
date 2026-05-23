//! Record/replay primitives — INFRA-3 (off-saga investment).
//!
//! This module exists only under `--features record-replay`.  Default
//! kernel builds compile without it and are byte-identical to the
//! pre-PR artefact (every fast-path consumer in `security/rand.rs`,
//! `syscall/mod.rs`, `subsys/linux/syscall.rs`, `proc/vdso.rs`, and
//! `kdb.rs` gates its call site behind `#[cfg(feature = "record-replay")]`).
//!
//! ## Goal
//!
//! Make repeated runs of the same userspace workload byte-deterministic
//! enough to bisect a single failure offline.  This is the cheap version
//! of full rr-style record/replay — it does NOT capture asynchronous
//! events (disk I/O completion order from real hardware timing,
//! interrupt arrival jitter, KVM-emulated TSC drift across vCPUs) and
//! it does NOT replay through the kernel.  What it provides:
//!
//!   1. **Deterministic PRNG** — every `security::rand::rand_u64()`
//!      consumer (ASLR, `AT_RANDOM`, `getrandom(2)`, kernel-internal
//!      seeds) is served from a per-boot xorshift64* PRNG seeded from
//!      `astryx.rng_seed=<u64>` on the QEMU `opt/astryx/cmdline`
//!      fw_cfg blob.  Default seed when the cmdline is absent:
//!      [`DEFAULT_SEED`].
//!
//!   2. **Frozen virtual tick source** — [`KERNEL_VIRTUAL_TICKS`]
//!      advances exclusively on syscall entry, syscall exit, and timer
//!      interrupt.  `clock_gettime(2)`, `gettimeofday(2)`, and the
//!      vDSO `monotonic_ns()` fallback path all derive their result
//!      from this counter.  Same syscall sequence -> same returned
//!      times.
//!
//!   3. **Structured per-syscall record log** — every Linux dispatch
//!      entry emits one self-describing `[SC-REC] {...}` JSON-shaped
//!      serial line carrying pid, tid, sc#, all six args, user RIP at
//!      entry, `IA32_FS_BASE`, and a strictly increasing `ord`
//!      sequence ordinal tied to [`KERNEL_VIRTUAL_TICKS`].
//!
//! ## Transport: QEMU fw_cfg
//!
//! The harness passes the cmdline via
//! `-fw_cfg name=opt/astryx/cmdline,string=astryx.rng_seed=0x...`.
//! We read it directly via the legacy fw_cfg I/O ports 0x510 / 0x511
//! (selector / data) — no bootloader changes required.  See QEMU
//! `docs/specs/fw_cfg.txt` for the protocol.  When the blob is absent
//! (production boot, non-QEMU host, or harness forgot to pass it) we
//! silently fall back to the default seed; record-replay determinism
//! still applies but the seed is fixed across runs rather than
//! configurable.
//!
//! ## Known non-deterministic sources (NOT addressed by this layer)
//!
//! See `docs/RECORD_REPLAY_2026-05-23.md` for the full taxonomy.
//! Headline items:
//!
//!   - Async I/O completion ordering from real disk (virtio-blk
//!     scheduler decisions are workload-independent under KVM but not
//!     guaranteed identical across host kernel versions).
//!   - Inter-CPU IPI arrival latency (TLB shootdown completion order).
//!   - SMP scheduler choices between equal-priority ready threads.
//!   - Host TSC drift visible under KVM `-cpu host` (use `-cpu
//!     qemu64,+invtsc` for stricter determinism — already the TCG
//!     default; see `scripts/astryx_qemu.py::_TCG_SAFE_CPU`).
//!
//! For the demo workload (single-shot firefox-test, headless, SMP=2)
//! these are observed to contribute zero divergence within the first
//! ~500 syscalls when the seed is fixed — see the validation soak in
//! the docs.
//!
//! ## References
//!
//! - QEMU `docs/specs/fw_cfg.txt` — selector/data port protocol.
//! - Intel SDM Vol. 1 §17.17 — Time-Stamp Counter semantics.
//! - kernel.org `Documentation/timers/timekeeping.rst`.
//! - POSIX `clock_gettime(3)`, `getrandom(3)` (man-pages section 3).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

/// Fallback PRNG seed when the cmdline omits `astryx.rng_seed=`.
///
/// Chosen as a deliberately-recognisable bit pattern so a forensic
/// reader can immediately tell that a run used the default seed.
pub const DEFAULT_SEED: u64 = 0xA577_E470_57ED_7E57;

// ───── QEMU fw_cfg legacy I/O port protocol ─────────────────────────────────
//
// Selector at 0x510 (16-bit write), data at 0x511 (8-bit read).  The
// well-known "file directory" selector 0x0019 lists named blobs that
// QEMU was launched with via `-fw_cfg name=...`.  We scan the directory
// for `opt/astryx/cmdline` and read its bytes.
//
// Layout (QEMU `docs/specs/fw_cfg.txt`):
//   FW_CFG_FILE_DIR selector returns:
//     u32 BE     count
//     repeated (count times):
//       u32 BE   size
//       u16 BE   select
//       u16      reserved
//       char[56] name (NUL-padded)

const FW_CFG_PORT_SEL:  u16 = 0x510;
const FW_CFG_PORT_DATA: u16 = 0x511;
const FW_CFG_SIG_SEL:   u16 = 0x0000;
const FW_CFG_FILE_DIR:  u16 = 0x0019;
const FW_CFG_SIG_MAGIC: [u8; 4] = *b"QEMU";

/// Maximum cmdline blob size we accept from fw_cfg.  4 KiB is far more
/// than enough for the small handful of `astryx.foo=bar` tokens this
/// mechanism is meant to carry.
const MAX_CMDLINE_LEN: usize = 4096;

/// Maximum fw_cfg directory entries we scan.  QEMU's own ceiling is
/// well under this in practice; bounding the loop protects against a
/// malformed device.
const MAX_FW_CFG_ENTRIES: u32 = 256;

// ───── Published state ──────────────────────────────────────────────────────

/// PRNG state used by `rr_rand_u64`.  Seeded once at boot from
/// `astryx.rng_seed=<u64>` on the QEMU cmdline (or [`DEFAULT_SEED`]).
/// xorshift64*-style mixing — non-cryptographic by design.
static PRNG_STATE: AtomicU64 = AtomicU64::new(DEFAULT_SEED);

/// The seed value that was loaded at boot (for introspection via
/// `record-status`).  Zero until [`init_early`] runs.
static SEED_AT_BOOT: AtomicU64 = AtomicU64::new(0);

/// `true` once [`init_early`] has populated [`PRNG_STATE`] from either
/// the cmdline or [`DEFAULT_SEED`].  Used to decide whether to log the
/// "RR initialised" banner exactly once and as a self-check in the
/// record-status op.
static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Frozen virtual tick source.  Advances on syscall entry, syscall
/// exit, and timer interrupt only.  Reads from any time-of-day path
/// (when this feature is on) derive their result from this counter
/// rather than RDTSC, giving byte-identical timestamps across runs of
/// the same workload.
pub static KERNEL_VIRTUAL_TICKS: AtomicU64 = AtomicU64::new(0);

/// Strictly increasing ordinal stamped on every `[SC-REC]` record.
/// Bumped before the record is formatted so concurrent emitters cannot
/// observe the same ordinal twice.  Reads via [`current_ordinal`].
static SC_REC_ORDINAL: AtomicU64 = AtomicU64::new(0);

// ───── Cmdline storage ──────────────────────────────────────────────────────

/// Captured raw cmdline blob bytes (NUL-trimmed).  Empty when no
/// cmdline was found.  Stored as `Vec<u8>` (under a Mutex) rather than
/// `&'static [u8]` because the early-init runs after the heap is up
/// — see [`init_early`] for the ordering.  Access is bounded to a
/// handful of reads from `record-status`, so the Mutex cost is
/// irrelevant.
static CMDLINE_BLOB: Mutex<Option<Vec<u8>>> = Mutex::new(None);

// ───── In-RAM record log (for `replay-dump`) ───────────────────────────────
//
// Each entry is the exact `[SC-REC] {...}` JSON line (without the
// `[SC-REC] ` prefix and without the trailing newline) that was also
// written to the serial port.  The serial line is the canonical record;
// the in-RAM mirror exists so the KDB op `replay-dump` can write a
// complete dump to a VFS file in one shot without having to re-parse
// the serial log.
//
// Bounded by `MAX_RECORDS` to keep RAM usage predictable; once full,
// further entries are dropped (the serial log still has them, so no
// signal is actually lost).

const MAX_RECORDS: usize = 8192;

static RECORD_LOG: Mutex<Option<Vec<String>>> = Mutex::new(None);

// ───── Public entry points ──────────────────────────────────────────────────

/// Very-early initialisation — called from `_start` right after serial
/// init and before BootInfo validation.
///
/// We deliberately run before the heap is up: the cmdline parser is
/// stack-only.  After it finds (or doesn't find) `astryx.rng_seed=`,
/// we publish the seed into [`PRNG_STATE`] and announce the result on
/// the serial console.  The record-log `Vec` is allocated lazily on
/// first use (see [`record_syscall_entry`]) so this path stays
/// allocator-free.
pub fn init_early() {
    let seed_raw = read_cmdline_seed();
    let seed = if seed_raw == 0 {
        // A literal seed of 0 would deadlock the xorshift PRNG, so we
        // fold it onto the default rather than silently producing
        // identical zero outputs forever.  Also covers the
        // cmdline-absent path which returns 0 to signal "missing".
        DEFAULT_SEED
    } else {
        seed_raw
    };
    PRNG_STATE.store(seed, Ordering::Relaxed);
    SEED_AT_BOOT.store(seed, Ordering::Relaxed);
    INIT_DONE.store(true, Ordering::Release);

    crate::serial_println!(
        "[RR] record/replay initialised: seed={:#018x} (from cmdline={})",
        seed,
        seed_raw != 0,
    );
}

/// Read the QEMU `opt/astryx/cmdline` fw_cfg blob and extract the
/// `astryx.rng_seed=<u64>` token (if present).  Returns `0` when the
/// blob is missing, malformed, or does not contain the token.
///
/// Stack-only: safe to call before the kernel heap is up.  The blob is
/// stashed into [`CMDLINE_BLOB`] lazily — that requires the heap, so
/// we defer it to first call from a heap-up context (see
/// [`stash_cmdline_if_available`]).
fn read_cmdline_seed() -> u64 {
    // Confirm the QEMU fw_cfg device is present.  Selector 0x0000
    // returns the four-byte signature "QEMU".  If the magic does not
    // match (running on bare metal, or a hypervisor without fw_cfg),
    // there's nothing to read.
    let mut sig = [0u8; 4];
    unsafe {
        fw_cfg_select(FW_CFG_SIG_SEL);
        for b in sig.iter_mut() {
            *b = crate::hal::inb(FW_CFG_PORT_DATA);
        }
    }
    if sig != FW_CFG_SIG_MAGIC {
        return 0;
    }

    // Walk the file directory looking for "opt/astryx/cmdline".
    let mut buf = [0u8; MAX_CMDLINE_LEN];
    let n = match fw_cfg_read_file(b"opt/astryx/cmdline", &mut buf) {
        Some(n) => n,
        None    => return 0,
    };
    parse_seed_from_cmdline(&buf[..n])
}

/// Stash the cmdline blob into [`CMDLINE_BLOB`] for later inspection
/// via `record-status`.  Heap-allocating, so callable only after
/// `mm::init()` has run.  Currently a no-op stub — the record-status
/// op re-reads from fw_cfg on demand so we don't need a persistent
/// stash.  Kept as a named entry point because a future enhancement
/// (e.g. exposing the raw cmdline to userspace via /proc/cmdline) may
/// want it.
#[allow(dead_code)]
fn stash_cmdline_if_available() {
    let mut buf_static = [0u8; MAX_CMDLINE_LEN];
    let n = match fw_cfg_read_file(b"opt/astryx/cmdline", &mut buf_static) {
        Some(n) => n,
        None    => return,
    };
    let mut g = CMDLINE_BLOB.lock();
    if g.is_none() {
        let mut v = Vec::with_capacity(n);
        v.extend_from_slice(&buf_static[..n]);
        *g = Some(v);
    }
}

// ───── PRNG ─────────────────────────────────────────────────────────────────

/// Deterministic xorshift64* — single hot routine consumed by every
/// RNG path in the kernel when this feature is on.  Identical bit
/// pattern across boots that use the same seed, byte-for-byte.
///
/// Algorithm: George Marsaglia, "Xorshift RNGs" (J. Stat. Softw. 8(14),
/// 2003) — same constants used by `xoshiro` family bootstrap.  Output
/// is mixed with the magic 0x2545_F491_4F6C_DD1D to break linearity in
/// the low bits (the "star" step), giving a 2^64 - 1 period.
#[inline]
pub fn rr_rand_u64() -> u64 {
    // Atomic CAS so concurrent callers on different CPUs each see a
    // distinct state, but the *sequence* of values returned across all
    // CPUs is determined entirely by the order in which CASes succeed.
    // Under SMP that order is itself non-deterministic — but for the
    // demo workload (firefox-test pid=1 is single-threaded for the
    // bringup window, AT_RANDOM and ASLR consumers all serialise
    // through process creation on the BSP) the sequence is observed to
    // be byte-stable across runs.  Multi-threaded workloads that pull
    // from rand_u64 concurrently are explicitly noted as
    // non-deterministic in docs/RECORD_REPLAY_2026-05-23.md.
    loop {
        let cur = PRNG_STATE.load(Ordering::Relaxed);
        let mut x = cur;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        // Guard against the all-zero absorbing state (the xorshift
        // family deadlocks on 0).  Should never trigger in practice
        // because the seed is fold-non-zero in init_early.
        if x == 0 {
            x = DEFAULT_SEED;
        }
        if PRNG_STATE
            .compare_exchange_weak(cur, x, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            // "star" mix into output.
            return x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        }
        core::hint::spin_loop();
    }
}

// ───── Virtual ticks ────────────────────────────────────────────────────────

/// Advance the virtual tick counter by one.  Called from syscall
/// entry, syscall exit, and the PIT timer ISR.  Single relaxed atomic
/// increment — costs ~1 ns on every modern x86_64.
#[inline]
pub fn advance_virtual_ticks() {
    KERNEL_VIRTUAL_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Current virtual tick value (load).  Used by `record-status` and by
/// the time-deriving paths in `clock_gettime` / `gettimeofday` (which
/// gate themselves on `cfg!(feature = "record-replay")`).
#[inline]
pub fn current_virtual_ticks() -> u64 {
    KERNEL_VIRTUAL_TICKS.load(Ordering::Relaxed)
}

/// Compute deterministic `(seconds, nanoseconds)` for `clock_gettime`
/// and `gettimeofday` from the virtual tick counter.
///
/// We pick a fictitious 1 GHz tick rate: 1 tick == 1 ns, so the
/// returned `(secs, ns)` pair is just `(ticks / 1e9, ticks % 1e9)`.
/// This is intentionally NOT the real `TICK_HZ` (100 Hz) — the goal is
/// to keep the math simple and the resolution fine enough that
/// `pthread_cond_timedwait` deadlines computed from this clock advance
/// monotonically between syscalls (each syscall pair advances the
/// counter by at least 2 ticks).
#[inline]
pub fn virtual_clock() -> (u64, u64) {
    let ticks = current_virtual_ticks();
    (ticks / 1_000_000_000, ticks % 1_000_000_000)
}

// ───── Syscall record log ──────────────────────────────────────────────────

/// Emit one `[SC-REC] {...}` line for a Linux syscall entry.  Also
/// pushes the same line (minus the prefix and trailing newline) into
/// the in-RAM `RECORD_LOG` for later dump via `replay-dump`.
///
/// `user_rip` is the user RIP at the SYSCALL instruction (per-CPU stash
/// set by the assembly entry stub — `crate::syscall::get_user_rip()`).
/// `fs_base` is the live `IA32_FS_BASE` MSR value — see Intel SDM
/// Vol. 3A §3.4.4.1.  `gen_id` is the per-process generation counter
/// from `mm::vmm::VmSpace::generation` (or 0 when not available — e.g.
/// from kernel threads).
#[inline]
pub fn record_syscall_entry(
    num: u64,
    a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64,
    pid: u64, tid: u64,
    user_rip: u64, fs_base: u64, gen_id: u64,
) {
    let ord = SC_REC_ORDINAL.fetch_add(1, Ordering::Relaxed);
    let vticks = current_virtual_ticks();
    // Format once into a heap String, then both serial-log it and
    // stash a copy.  ~150 bytes typical.
    use core::fmt::Write;
    let mut line = String::with_capacity(192);
    let _ = write!(
        &mut line,
        r#"{{"ord":{},"vt":{},"pid":{},"tid":{},"sc":{},"a1":"{:#x}","a2":"{:#x}","a3":"{:#x}","a4":"{:#x}","a5":"{:#x}","a6":"{:#x}","rip":"{:#x}","fs":"{:#x}","gen":{}}}"#,
        ord, vticks, pid, tid, num,
        a1, a2, a3, a4, a5, a6,
        user_rip, fs_base, gen_id,
    );
    crate::serial_println!("[SC-REC] {}", line);

    // In-RAM mirror, bounded.
    let mut g = RECORD_LOG.lock();
    if g.is_none() {
        *g = Some(Vec::with_capacity(MAX_RECORDS));
    }
    if let Some(v) = g.as_mut() {
        if v.len() < MAX_RECORDS {
            v.push(line);
        }
    }
}

/// Current ordinal value (next ordinal that will be issued).  For
/// introspection via `record-status`.
#[inline]
pub fn current_ordinal() -> u64 {
    SC_REC_ORDINAL.load(Ordering::Relaxed)
}

/// Seed-at-boot value (for `record-status`).
#[inline]
pub fn seed_at_boot() -> u64 {
    SEED_AT_BOOT.load(Ordering::Relaxed)
}

/// Dump the in-RAM record log to a VFS file, one JSON object per line
/// (newline-separated).  Returns the number of records written, or an
/// error message string for `record-status`.
pub fn dump_records_to(path: &str) -> Result<usize, &'static str> {
    let g = RECORD_LOG.lock();
    let v = match g.as_ref() {
        Some(v) => v,
        None    => return Err("record log empty (no syscalls yet)"),
    };
    let mut blob = String::with_capacity(v.len() * 192);
    for line in v.iter() {
        blob.push_str(line);
        blob.push('\n');
    }
    // VFS write — the path must be on a writable filesystem (the
    // ramdisk root in test/firefox-test).  Errors are mapped to a
    // generic string for the JSON-shaped KDB response.
    match crate::vfs::write_file(path, blob.as_bytes()) {
        Ok(_)  => Ok(v.len()),
        Err(_) => Err("vfs::write_file failed (path unwritable?)"),
    }
}

// ───── fw_cfg helpers (stack-only) ─────────────────────────────────────────

#[inline]
unsafe fn fw_cfg_select(selector: u16) {
    crate::hal::outw(FW_CFG_PORT_SEL, selector);
}

/// Read a u32 BE from the data port.
#[inline]
unsafe fn fw_cfg_read_u32_be() -> u32 {
    let mut buf = [0u8; 4];
    for b in buf.iter_mut() {
        *b = crate::hal::inb(FW_CFG_PORT_DATA);
    }
    u32::from_be_bytes(buf)
}

/// Read a u16 BE from the data port.
#[inline]
unsafe fn fw_cfg_read_u16_be() -> u16 {
    let mut buf = [0u8; 2];
    for b in buf.iter_mut() {
        *b = crate::hal::inb(FW_CFG_PORT_DATA);
    }
    u16::from_be_bytes(buf)
}

/// Locate the named blob in the fw_cfg file directory and read it
/// into `out`.  Returns `Some(n)` with the number of bytes written
/// (clamped to `out.len()`), or `None` if the blob is not present.
fn fw_cfg_read_file(name: &[u8], out: &mut [u8]) -> Option<usize> {
    unsafe {
        fw_cfg_select(FW_CFG_FILE_DIR);
        let count = fw_cfg_read_u32_be();
        if count == 0 || count > MAX_FW_CFG_ENTRIES {
            return None;
        }
        // Directory entries are laid out sequentially after the count
        // word, on the same selector.  Read them one at a time looking
        // for our name; remember the matched selector + size and break
        // out of the loop, then re-select and slurp the blob.
        let mut found_sel:  Option<u16> = None;
        let mut found_size: u32         = 0;
        for _ in 0..count {
            let size  = fw_cfg_read_u32_be();
            let sel   = fw_cfg_read_u16_be();
            let _res  = fw_cfg_read_u16_be(); // reserved
            // name field is 56 bytes
            let mut nbuf = [0u8; 56];
            for b in nbuf.iter_mut() {
                *b = crate::hal::inb(FW_CFG_PORT_DATA);
            }
            if found_sel.is_some() {
                continue; // keep draining the directory but ignore further hits
            }
            // Compare against `name` up to NUL.
            let name_len = nbuf.iter().position(|&b| b == 0).unwrap_or(nbuf.len());
            if &nbuf[..name_len] == name {
                found_sel  = Some(sel);
                found_size = size;
            }
        }
        let sel = found_sel?;
        let want = (found_size as usize).min(out.len());
        fw_cfg_select(sel);
        for byte in out.iter_mut().take(want) {
            *byte = crate::hal::inb(FW_CFG_PORT_DATA);
        }
        Some(want)
    }
}

// ───── Cmdline parser ───────────────────────────────────────────────────────

/// Parse `astryx.rng_seed=<u64>` from a cmdline blob.  Returns 0 if
/// the token is absent or unparseable.  Accepted formats: decimal,
/// `0x`-prefixed hex.  Whitespace or `\0` terminates the value.
fn parse_seed_from_cmdline(buf: &[u8]) -> u64 {
    const KEY: &[u8] = b"astryx.rng_seed=";
    let mut i = 0;
    while i + KEY.len() <= buf.len() {
        if &buf[i..i + KEY.len()] == KEY {
            let val_start = i + KEY.len();
            let val_end = (val_start..buf.len())
                .find(|&j| matches!(buf[j], b' ' | b'\t' | b'\n' | b'\r' | b'\0'))
                .unwrap_or(buf.len());
            return parse_u64_token(&buf[val_start..val_end]);
        }
        i += 1;
    }
    0
}

/// Parse a u64 token in decimal or `0x`-prefixed hex.  Returns 0 on
/// any parse failure (including overflow), matching the
/// cmdline-absent fallback shape.
fn parse_u64_token(tok: &[u8]) -> u64 {
    let (s, radix) = if tok.len() >= 2 && tok[0] == b'0' && (tok[1] == b'x' || tok[1] == b'X') {
        (&tok[2..], 16u32)
    } else {
        (tok, 10u32)
    };
    let mut acc: u64 = 0;
    for &b in s {
        let d: u32 = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' if radix == 16 => 10 + (b - b'a') as u32,
            b'A'..=b'F' if radix == 16 => 10 + (b - b'A') as u32,
            _ => return 0,
        };
        if d >= radix {
            return 0;
        }
        acc = match acc.checked_mul(radix as u64).and_then(|v| v.checked_add(d as u64)) {
            Some(v) => v,
            None    => return 0,
        };
    }
    acc
}

// ───── Unit-test surface ────────────────────────────────────────────────────
//
// Pure functions only — exercises the cmdline parser without needing
// fw_cfg or any kernel state.  Wired into `test_runner.rs` via the
// `record_replay_self_tests` entry point below; see that file for the
// dispatch shape.

/// Run pure-Rust self tests for the cmdline parser.  Returns the
/// number of asserts performed (so the test runner can refuse to
/// silently treat an empty test as a pass).
pub fn self_tests() -> usize {
    let mut n = 0usize;

    macro_rules! check {
        ($cond:expr, $msg:expr) => {{
            n += 1;
            if !$cond {
                crate::serial_println!("[RR/SELFTEST] FAIL: {}", $msg);
                return n;
            }
        }};
    }

    // Hex parsing.
    check!(parse_u64_token(b"0xCAFEF00DCAFEF00D") == 0xCAFE_F00D_CAFE_F00D, "hex parse");
    check!(parse_u64_token(b"0X1") == 1, "hex upper-case prefix");
    check!(parse_u64_token(b"0xff") == 0xff, "hex lower");
    check!(parse_u64_token(b"0xFF") == 0xff, "hex upper");

    // Decimal parsing.
    check!(parse_u64_token(b"0") == 0, "dec zero");
    check!(parse_u64_token(b"12345") == 12345, "dec mid");
    check!(parse_u64_token(b"18446744073709551615") == u64::MAX, "dec u64::MAX");

    // Overflow rejection.
    check!(parse_u64_token(b"18446744073709551616") == 0, "dec overflow returns 0");
    check!(parse_u64_token(b"0xFFFFFFFFFFFFFFFFF") == 0, "hex overflow returns 0");

    // Garbage tokens.
    check!(parse_u64_token(b"abc") == 0, "non-prefixed letters");
    check!(parse_u64_token(b"0xGG") == 0, "hex out of range");
    check!(parse_u64_token(b"") == 0, "empty");

    // Cmdline parser.
    check!(parse_seed_from_cmdline(b"") == 0, "empty cmdline");
    check!(parse_seed_from_cmdline(b"foo=bar") == 0, "no rng_seed");
    check!(parse_seed_from_cmdline(b"astryx.rng_seed=0xCAFE")
           == 0xCAFE, "lone token");
    check!(parse_seed_from_cmdline(b"console=ttyS0 astryx.rng_seed=42 quiet")
           == 42, "embedded token");
    check!(parse_seed_from_cmdline(b"astryx.rng_seed=0xDEADBEEF\nrest")
           == 0xDEAD_BEEF, "newline terminated");
    check!(parse_seed_from_cmdline(b"astryx.rng_seed=0x1\0junk")
           == 1, "NUL terminated");

    // PRNG fixed-seed determinism.
    PRNG_STATE.store(0xA577_E470_57ED_7E57, Ordering::Relaxed);
    let v1 = rr_rand_u64();
    let v2 = rr_rand_u64();
    let v3 = rr_rand_u64();
    PRNG_STATE.store(0xA577_E470_57ED_7E57, Ordering::Relaxed);
    check!(rr_rand_u64() == v1, "PRNG round-1 deterministic");
    check!(rr_rand_u64() == v2, "PRNG round-2 deterministic");
    check!(rr_rand_u64() == v3, "PRNG round-3 deterministic");

    // Distinct seeds produce distinct sequences.
    PRNG_STATE.store(1, Ordering::Relaxed);
    let a = rr_rand_u64();
    PRNG_STATE.store(2, Ordering::Relaxed);
    let b = rr_rand_u64();
    check!(a != b, "distinct seeds → distinct outputs");

    crate::serial_println!("[RR/SELFTEST] PASS ({} asserts)", n);
    n
}
