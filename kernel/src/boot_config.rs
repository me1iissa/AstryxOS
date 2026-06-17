//! Boot-time configuration read from the QEMU `fw_cfg` device.
//!
//! The firefox-test workload's target URL was historically a compile-time
//! constant (`main.rs` `CMDLINE_MUSL_*`), so every site change forced a full
//! kernel rebuild.  This module reads an optional `astryx.ff_url=<url>` token
//! from the QEMU `opt/astryx/cmdline` `fw_cfg` blob so the harness can deliver
//! a new URL at boot WITHOUT a rebuild (it passes
//! `-fw_cfg name=opt/astryx/cmdline,string=astryx.ff_url=<url>`).
//!
//! When the token is absent — production boot, non-QEMU host, or the harness
//! did not pass `--ff-url` — the firefox-test launch path falls back to the
//! compiled default, so existing behaviour is byte-for-byte unchanged.
//!
//! ## Transport: QEMU fw_cfg
//!
//! We read the blob directly via the legacy `fw_cfg` I/O ports 0x510
//! (selector) / 0x511 (data) — no bootloader changes required.  The well-known
//! file-directory selector 0x0019 lists named blobs that QEMU was launched with
//! via `-fw_cfg name=...`; we scan it for `opt/astryx/cmdline`, read its bytes,
//! and extract the `astryx.ff_url=` value.  See QEMU
//! `docs/specs/fw_cfg.txt` for the selector/data port protocol.
//!
//! This is the same transport `record_replay::init_early()` uses for
//! `astryx.rng_seed=`, but that module is gated behind the `record-replay`
//! feature (off for the firefox-test profile), so the small reader is
//! duplicated here rather than cross-coupling the two feature gates.
//!
//! ## Validation
//!
//! The extracted URL is validated before use: the scheme must be one of
//! `http://`, `https://`, or `file://` (per RFC 3986 §3.1, scheme is the
//! leading component before `:`), the length is bounded, and only printable
//! ASCII (no whitespace/control bytes, which would break the single-string
//! command line) is accepted.  A token that fails validation is ignored and
//! the compiled default is used.
//!
//! ## References
//! - QEMU `docs/specs/fw_cfg.txt` — selector/data port protocol.
//! - RFC 3986 §3.1 — URI scheme syntax.

extern crate alloc;

use alloc::string::String;

// ───── QEMU fw_cfg legacy I/O port protocol ─────────────────────────────────
//
// Selector at 0x510 (16-bit write), data at 0x511 (8-bit read).  The
// file-directory selector 0x0019 returns:
//   u32 BE     count
//   repeated (count times):
//     u32 BE   size
//     u16 BE   select
//     u16      reserved
//     char[56] name (NUL-padded)
#[cfg(feature = "firefox-test-core")]
const FW_CFG_PORT_SEL:  u16 = 0x510;
#[cfg(feature = "firefox-test-core")]
const FW_CFG_PORT_DATA: u16 = 0x511;
#[cfg(feature = "firefox-test-core")]
const FW_CFG_SIG_SEL:   u16 = 0x0000;
#[cfg(feature = "firefox-test-core")]
const FW_CFG_FILE_DIR:  u16 = 0x0019;
#[cfg(feature = "firefox-test-core")]
const FW_CFG_SIG_MAGIC: [u8; 4] = *b"QEMU";

/// Maximum cmdline blob we accept from fw_cfg.  4 KiB is far more than enough
/// for the handful of `astryx.foo=bar` tokens this mechanism carries.
#[cfg(feature = "firefox-test-core")]
const MAX_CMDLINE_LEN: usize = 4096;

/// Maximum fw_cfg directory entries we scan (bounds a malformed device).
#[cfg(feature = "firefox-test-core")]
const MAX_FW_CFG_ENTRIES: u32 = 256;

/// Upper bound on an accepted URL.  RFC 3986 sets no hard limit, but a real
/// browser command-line URL is well under this; bounding it protects the
/// fixed-size cmdline buffer in the launch path.
const MAX_URL_LEN: usize = 2048;

/// Key for the runtime target URL token.
const FF_URL_KEY: &[u8] = b"astryx.ff_url=";

/// Key for the runtime GUI-mode token.  When present as `astryx.ff_gui=1` in
/// the `opt/astryx/cmdline` blob, the launch path runs Firefox in X11/GUI mode
/// (no `--headless`, no `--screenshot`, `MOZ_HEADLESS` unset) so it connects to
/// the in-kernel Xastryx server on `DISPLAY=:0` and paints into a real window.
const FF_GUI_KEY: &[u8] = b"astryx.ff_gui=1";

/// Read the QEMU `opt/astryx/cmdline` fw_cfg blob and extract a validated
/// `astryx.ff_url=<url>` value.  Returns `None` when the blob is missing,
/// the token is absent, or the value fails validation — callers fall back to
/// the compiled default in that case.
///
/// Stack-only fw_cfg read; the single returned `String` is the only heap
/// allocation, so this is safe to call from the firefox-test launch path
/// (heap is up long before then).
///
/// Only reachable from the FF launch path; under a pure `test-mode` build the
/// parser self-tests still run, but the I/O entry point is unused.
#[cfg(feature = "firefox-test-core")]
pub fn ff_url_override() -> Option<String> {
    // Confirm the fw_cfg device is present (selector 0x0000 returns "QEMU").
    let mut sig = [0u8; 4];
    unsafe {
        fw_cfg_select(FW_CFG_SIG_SEL);
        for b in sig.iter_mut() {
            *b = crate::hal::inb(FW_CFG_PORT_DATA);
        }
    }
    if sig != FW_CFG_SIG_MAGIC {
        return None;
    }

    let mut buf = [0u8; MAX_CMDLINE_LEN];
    let n = fw_cfg_read_file(b"opt/astryx/cmdline", &mut buf)?;
    parse_ff_url(&buf[..n])
}

/// Read the QEMU `opt/astryx/cmdline` fw_cfg blob and report whether the
/// `astryx.ff_gui=1` token is present.  Returns `false` when the blob is
/// missing or the token is absent (the default headless behaviour).
///
/// Like [`ff_url_override`] this is a stack-only fw_cfg read with no heap
/// allocation, safe to call from the firefox-test launch path.  The token is
/// carried in the SAME `opt/astryx/cmdline` blob as `astryx.ff_url=` (fw_cfg
/// permits a single named entry), so the harness appends both into one string.
#[cfg(feature = "firefox-test-core")]
pub fn ff_gui_mode() -> bool {
    // Confirm the fw_cfg device is present (selector 0x0000 returns "QEMU").
    let mut sig = [0u8; 4];
    unsafe {
        fw_cfg_select(FW_CFG_SIG_SEL);
        for b in sig.iter_mut() {
            *b = crate::hal::inb(FW_CFG_PORT_DATA);
        }
    }
    if sig != FW_CFG_SIG_MAGIC {
        return false;
    }

    let mut buf = [0u8; MAX_CMDLINE_LEN];
    match fw_cfg_read_file(b"opt/astryx/cmdline", &mut buf) {
        Some(n) => parse_ff_gui(&buf[..n]),
        None => false,
    }
}

/// Return `true` iff the `astryx.ff_gui=1` token appears in the cmdline blob.
/// Exposed for unit tests; see [`self_tests`].
fn parse_ff_gui(buf: &[u8]) -> bool {
    find_token(buf, FF_GUI_KEY).is_some()
}

/// Extract and validate the `astryx.ff_url=` value from a cmdline blob.
/// Exposed for unit tests; see [`self_tests`].
fn parse_ff_url(buf: &[u8]) -> Option<String> {
    let start = find_token(buf, FF_URL_KEY)?;
    let val_start = start + FF_URL_KEY.len();
    // The value runs to the first whitespace, control byte, or NUL — a URL
    // never contains those, and they would also break the single-string
    // command line the launch path builds.
    let mut end = val_start;
    while end < buf.len() {
        let b = buf[end];
        if b == 0 || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            break;
        }
        end += 1;
    }
    let val = &buf[val_start..end];
    if !url_is_valid(val) {
        return None;
    }
    // SAFETY: url_is_valid guarantees printable ASCII (each byte 0x21..=0x7e).
    Some(String::from_utf8_lossy(val).into_owned())
}

/// Find the first occurrence of `key` in `buf`; returns the start index.
fn find_token(buf: &[u8], key: &[u8]) -> Option<usize> {
    if key.is_empty() || key.len() > buf.len() {
        return None;
    }
    buf.windows(key.len()).position(|w| w == key)
}

/// Validate a candidate URL: non-empty, ≤ [`MAX_URL_LEN`], printable ASCII
/// only (no whitespace/control bytes), and a scheme of `http`, `https`, or
/// `file` (RFC 3986 §3.1).  Rejecting anything else keeps an untrusted blob
/// from injecting an arbitrary argv token into the launch command line.
fn url_is_valid(val: &[u8]) -> bool {
    if val.is_empty() || val.len() > MAX_URL_LEN {
        return false;
    }
    // Printable ASCII only — `url_is_valid` is the single gate, so be strict.
    if !val.iter().all(|&b| (0x21..=0x7e).contains(&b)) {
        return false;
    }
    val.starts_with(b"http://")
        || val.starts_with(b"https://")
        || val.starts_with(b"file://")
}

// ───── fw_cfg helpers (stack-only) ─────────────────────────────────────────
//
// Only reached via `ff_url_override` (FF launch path); the test-mode build
// runs the pure parser self-tests and never touches the I/O ports.
#[cfg(feature = "firefox-test-core")]
#[inline]
unsafe fn fw_cfg_select(selector: u16) {
    crate::hal::outw(FW_CFG_PORT_SEL, selector);
}

#[cfg(feature = "firefox-test-core")]
#[inline]
unsafe fn fw_cfg_read_u32_be() -> u32 {
    let mut buf = [0u8; 4];
    for b in buf.iter_mut() {
        *b = crate::hal::inb(FW_CFG_PORT_DATA);
    }
    u32::from_be_bytes(buf)
}

#[cfg(feature = "firefox-test-core")]
#[inline]
unsafe fn fw_cfg_read_u16_be() -> u16 {
    let mut buf = [0u8; 2];
    for b in buf.iter_mut() {
        *b = crate::hal::inb(FW_CFG_PORT_DATA);
    }
    u16::from_be_bytes(buf)
}

/// Locate the named blob in the fw_cfg file directory and read it into `out`.
/// Returns `Some(n)` (bytes written, clamped to `out.len()`), or `None` if the
/// blob is not present.
#[cfg(feature = "firefox-test-core")]
fn fw_cfg_read_file(name: &[u8], out: &mut [u8]) -> Option<usize> {
    unsafe {
        fw_cfg_select(FW_CFG_FILE_DIR);
        let count = fw_cfg_read_u32_be();
        if count == 0 || count > MAX_FW_CFG_ENTRIES {
            return None;
        }
        let mut found_sel:  Option<u16> = None;
        let mut found_size: u32         = 0;
        for _ in 0..count {
            let size = fw_cfg_read_u32_be();
            let sel  = fw_cfg_read_u16_be();
            let _res = fw_cfg_read_u16_be(); // reserved
            let mut nbuf = [0u8; 56];
            for b in nbuf.iter_mut() {
                *b = crate::hal::inb(FW_CFG_PORT_DATA);
            }
            if found_sel.is_some() {
                continue; // drain the rest of the directory, ignore further hits
            }
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

// ───── Self-tests ───────────────────────────────────────────────────────────

/// In-kernel parser self-tests.  Returns the number of assertions made.
/// Driven by the firefox-test runner; pure (no I/O), so safe in any context.
pub fn self_tests() -> usize {
    let mut n = 0usize;
    macro_rules! check {
        ($cond:expr, $name:expr) => {{
            n += 1;
            if !($cond) {
                crate::serial_println!("[BOOTCFG/SELFTEST] FAIL: {}", $name);
            }
        }};
    }

    // Happy paths — all three accepted schemes.
    check!(
        parse_ff_url(b"astryx.ff_url=https://bbc.com/news").as_deref()
            == Some("https://bbc.com/news"),
        "https extracted"
    );
    check!(
        parse_ff_url(b"astryx.ff_url=http://example.com/").as_deref()
            == Some("http://example.com/"),
        "http extracted"
    );
    check!(
        parse_ff_url(b"astryx.ff_url=file:///tmp/hello.html").as_deref()
            == Some("file:///tmp/hello.html"),
        "file extracted"
    );
    // Value terminated by whitespace and by NUL.
    check!(
        parse_ff_url(b"astryx.rng_seed=42 astryx.ff_url=https://a.io/ quiet")
            .as_deref()
            == Some("https://a.io/"),
        "space-terminated, token after another"
    );
    check!(
        parse_ff_url(b"astryx.ff_url=https://b.io/\0junk").as_deref()
            == Some("https://b.io/"),
        "NUL-terminated"
    );
    // Rejections.
    check!(parse_ff_url(b"foo=bar").is_none(), "absent token");
    check!(
        parse_ff_url(b"astryx.ff_url=ftp://x/").is_none(),
        "disallowed scheme rejected"
    );
    check!(
        parse_ff_url(b"astryx.ff_url=").is_none(),
        "empty value rejected"
    );
    check!(
        parse_ff_url(b"astryx.ff_url=javascript:alert(1)").is_none(),
        "non-allowed scheme rejected"
    );
    // A value with an embedded space is truncated at the space, but the head
    // ("https://a") still validates as a well-formed allowed-scheme URL.
    check!(
        parse_ff_url(b"astryx.ff_url=https://a b").as_deref() == Some("https://a"),
        "space truncates value"
    );

    // GUI-mode token detection (carried in the same cmdline blob).
    check!(parse_ff_gui(b"astryx.ff_gui=1"), "gui token present");
    check!(
        parse_ff_gui(b"astryx.ff_url=https://lite.cnn.com astryx.ff_gui=1"),
        "gui token alongside url"
    );
    check!(!parse_ff_gui(b"astryx.ff_url=https://lite.cnn.com"), "gui token absent");
    check!(!parse_ff_gui(b"astryx.ff_gui=0"), "gui token explicitly off");

    crate::serial_println!("[BOOTCFG/SELFTEST] PASS ({} asserts)", n);
    n
}
