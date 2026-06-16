//! Firefox headless-screenshot extraction over the serial port.
//!
//! After the firefox-test boot drives the headless Firefox `--screenshot`
//! pipeline, the rendered PNG lands at the guest path `/tmp/out.png` (a VFS
//! ramdisk file — see `kernel/src/main.rs` firefox-test path). The QEMU VGA
//! framebuffer at that point still shows the AstryxOS boot splash, so the
//! existing `[SCREENSHOT-B64:…]` stream (which carries the framebuffer) does
//! NOT carry Firefox's rendered output. This module reads `/tmp/out.png` back
//! through the kernel VFS and reports it over serial.
//!
//! # Default: a single summary marker, no byte stream
//!
//! Every firefox-test boot emits exactly one summary line the moment the PNG is
//! a structurally complete file:
//!
//! ```text
//! [FF-OUT-PNG:path=/tmp/out.png size=<N> sig_ok=<bool> complete=<bool>]
//! ```
//!
//! That single line tells the host the PNG is written, its byte size, and that
//! it has a valid signature + `IEND` trailer — enough for the harness to switch
//! to a live VFS read (`qemu-harness.py kdb-read-png`), which is NOT baud-bound
//! and returns a 2 MB PNG in seconds.  The rendered bytes stay in the guest VFS
//! ramdisk; serial carries only the one-line marker.
//!
//! # Opt-in: the full base64 byte stream (`ff-png-serial-emit`)
//!
//! When the kernel is built with `--features ff-png-serial-emit`, the same call
//! ALSO streams the byte-exact PNG over COM1 as a DISTINCT base64 marker stream
//! so a host with no kdb channel can still reconstruct the file:
//!
//! ```text
//! [FF-OUT-PNG:path=/tmp/out.png size=<N> sig_ok=<bool> complete=<bool>]
//! [FF-OUT-PNG-B64:0/M] <up to 76 base64 chars>
//! [FF-OUT-PNG-B64:1/M] ...
//! ...
//! [FF-OUT-PNG-END]
//! ```
//!
//! This stream is OFF by default: it is one synchronous `serial_println!` per
//! 57 input bytes (RFC 2045 §6.8 MIME line), i.e. ~36 800 UART writes for a
//! 2 MB PNG; at ~88 µs per port-I/O VM-exit (Intel SDM Vol. 3C §25
//! I/O-instruction VM-exits) that is several minutes of CPU0 emit time, during
//! which it starves the kdb pump thread the live read depends on.  Enable it
//! only when serial is the sole extraction channel.
//!
//! The encoding is standard base64 (RFC 4648 §4) with `=` padding; each data
//! line carries 57 input bytes → 76 output characters (the MIME line length,
//! RFC 2045 §6.8). The PNG signature is the 8-byte magic of W3C/ISO 15948 PNG
//! (89 50 4E 47 0D 0A 1A 0A).
//!
//! The host-side decoders are `scripts/qemu-harness.py kdb-read-png` (live VFS
//! read — the default, fast path) and `read-ff-png` (the serial-stream decoder,
//! used only when `ff-png-serial-emit` is enabled).  Both are kept entirely
//! separate from `read-png` (the framebuffer decoder) so the extraction paths
//! never collide.
//!
//! This module is compiled only under the `firefox-test-core` feature; it is
//! inert (and absent) in every other build, so it cannot affect other tests.

extern crate alloc;
use alloc::vec::Vec;
use crate::serial_println;

/// 8-byte PNG file signature (W3C PNG §5.2 / ISO 15948).
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Trailing 8 bytes of every well-formed PNG: the zero-length `IEND` chunk —
/// length(0)=`00 00 00 00`, type `IEND`=`49 45 4E 44`, CRC=`AE 42 60 82`
/// (W3C PNG §5.6 / §11.2.5; the IEND CRC is constant). Used to confirm the
/// file Firefox is writing is COMPLETE before we stream it, so a probe that
/// catches the write mid-flight does not emit a truncated PNG.
const PNG_IEND_TRAILER: [u8; 8] =
    [0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, ];

/// Whether `bytes` is a structurally complete PNG: 8-byte signature at the
/// front AND the 12-byte IEND chunk at the back (we match the first 8 of those
/// 12; the final 4 are the constant CRC). A minimum length of 8+12 = 20 bytes
/// is required for both windows to exist.
fn is_complete_png(bytes: &[u8]) -> bool {
    if bytes.len() < 20 {
        return false;
    }
    if bytes[..8] != PNG_SIGNATURE {
        return false;
    }
    // IEND chunk is the last 12 bytes: 4 len + 4 type + 4 CRC. Match the
    // 8-byte len+type window at offset len-12.
    let iend_at = bytes.len() - 12;
    bytes[iend_at..iend_at + 8] == PNG_IEND_TRAILER
}

/// Standard base64 alphabet (RFC 4648 §4, Table 1). Used only by the opt-in
/// serial byte stream; absent in the default build.
#[cfg(feature = "ff-png-serial-emit")]
const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Input bytes per emitted line: 57 → exactly 76 base64 characters
/// (RFC 2045 §6.8 MIME line length).
#[cfg(feature = "ff-png-serial-emit")]
const CHUNK_BYTES: usize = 57;

/// Maximum encoded bytes for one `CHUNK_BYTES` group: ceil(57/3)*4 = 76.
#[cfg(feature = "ff-png-serial-emit")]
const MAX_ENC_LEN: usize = 76;

/// Base64-encode one input group (≤ `CHUNK_BYTES` bytes) into `out`, returning
/// the number of bytes written. `out` must be at least `MAX_ENC_LEN` long.
///
/// Pure function (no I/O, no allocation) so the encoding is unit-testable and
/// identical in shape to the `[SCREENSHOT-B64]` encoder in `test_runner.rs`.
/// Compiled only under the opt-in serial byte stream.
#[cfg(feature = "ff-png-serial-emit")]
fn b64_encode_group(src: &[u8], out: &mut [u8; MAX_ENC_LEN]) -> usize {
    let mut enc_len = 0usize;
    let mut i = 0usize;

    // Full 3-byte groups → 4 output chars.
    while i + 2 < src.len() {
        let b0 = src[i] as usize;
        let b1 = src[i + 1] as usize;
        let b2 = src[i + 2] as usize;
        out[enc_len]     = B64_ALPHABET[b0 >> 2];
        out[enc_len + 1] = B64_ALPHABET[((b0 & 0x3) << 4) | (b1 >> 4)];
        out[enc_len + 2] = B64_ALPHABET[((b1 & 0xf) << 2) | (b2 >> 6)];
        out[enc_len + 3] = B64_ALPHABET[b2 & 0x3f];
        enc_len += 4;
        i += 3;
    }

    // Trailing 1 or 2 bytes + `=` padding.
    if i < src.len() {
        let b0 = src[i] as usize;
        let b1 = if i + 1 < src.len() { src[i + 1] as usize } else { 0 };
        out[enc_len]     = B64_ALPHABET[b0 >> 2];
        out[enc_len + 1] = B64_ALPHABET[((b0 & 0x3) << 4) | (b1 >> 4)];
        out[enc_len + 2] = if i + 1 < src.len() {
            B64_ALPHABET[(b1 & 0xf) << 2]
        } else {
            b'='
        };
        out[enc_len + 3] = b'=';
        enc_len += 4;
    }

    enc_len
}

/// Read `/tmp/out.png` back from the VFS and report it over serial. Returns
/// `true` iff the file is a COMPLETE PNG (valid signature + IEND trailer).
///
/// Default behaviour (any firefox-test build): emit exactly the one-line
/// `[FF-OUT-PNG:path=… size=… sig_ok=… complete=…]` summary marker. The
/// rendered bytes stay in the guest VFS for the host to pull live via
/// `qemu-harness.py kdb-read-png` (not baud-bound). NO byte stream is emitted,
/// so the call cannot starve the kdb pump thread or add minutes of UART time.
///
/// Opt-in (`--features ff-png-serial-emit`): a COMPLETE PNG is ADDITIONALLY
/// streamed as the `[FF-OUT-PNG-B64:…]` / `[FF-OUT-PNG-END]` marker stream for a
/// host with no kdb channel. See the module docs for the cost rationale.
///
/// Best-effort and side-effect-free with respect to the boot: any failure
/// (file absent, read error, empty, bad signature) is reported on the single
/// `[FF-OUT-PNG:…]` line and the function returns `false` — it never panics and
/// never blocks the shutdown path. Firefox having failed to write a screenshot
/// is a normal, expected outcome that must not wedge the boot.
///
/// When called speculatively from the poll loop (file may still be mid-write),
/// the `complete=false` return lets the caller probe again next tick rather
/// than treat a truncated image as final.
pub fn emit_out_png() -> bool {
    const PNG_PATH: &str = "/tmp/out.png";

    // Read the guest-written PNG back through the same VFS Firefox wrote to.
    // `/tmp` is a kernel VFS ramdisk shared between the kernel and the Linux
    // personality, so this is the byte-exact file Firefox produced.
    let bytes: Vec<u8> = match crate::vfs::read_file(PNG_PATH) {
        Ok(b) => b,
        Err(e) => {
            serial_println!(
                "[FF-OUT-PNG:path={} size=0 sig_ok=false complete=false read_error={:?}]",
                PNG_PATH, e
            );
            return false;
        }
    };

    let size = bytes.len();
    let sig_ok = size >= 8 && bytes[..8] == PNG_SIGNATURE;
    let complete = is_complete_png(&bytes);

    // The summary marker is ALWAYS emitted — it is one line regardless of PNG
    // size, so it carries no baud-rate cost. The harness keys on this line to
    // learn the PNG is written and complete, then reads the bytes live via the
    // kdb VFS path (`qemu-harness.py kdb-read-png`).
    serial_println!(
        "[FF-OUT-PNG:path={} size={} sig_ok={} complete={}]",
        PNG_PATH, size, sig_ok, complete
    );

    if size == 0 || !complete {
        // Empty, mid-write, or corrupt: nothing to stream and not yet final.
        // The summary line above already reported the state; let the caller
        // retry on the next probe (complete=false) rather than act on a
        // partial image.
        return false;
    }

    // A complete PNG is present. Stream the byte-exact base64 marker stream ONLY
    // under the opt-in feature — it is the multi-minute, kdb-starving path that
    // is redundant whenever the live kdb VFS read is available (the default).
    #[cfg(feature = "ff-png-serial-emit")]
    emit_b64_stream(&bytes, size);

    true
}

/// Emit the byte-exact `[FF-OUT-PNG-B64:…]` chunk stream + `[FF-OUT-PNG-END]`
/// terminator for `bytes` (a verified-complete PNG of length `size`). Compiled
/// only under `ff-png-serial-emit`; absent and zero-cost otherwise.
#[cfg(feature = "ff-png-serial-emit")]
fn emit_b64_stream(bytes: &[u8], size: usize) {
    // Ceiling division for the chunk count (matches the existing
    // `[SCREENSHOT-B64]` encoder); the summary line already told the host the
    // byte size for a sanity cross-check.
    let total_chunks = (size + CHUNK_BYTES - 1) / CHUNK_BYTES;

    for chunk_idx in 0..total_chunks {
        let start = chunk_idx * CHUNK_BYTES;
        let end = (start + CHUNK_BYTES).min(size);
        let src = &bytes[start..end];

        let mut enc = [0u8; MAX_ENC_LEN];
        let enc_len = b64_encode_group(src, &mut enc);

        // SAFETY: `enc[..enc_len]` contains only ASCII bytes drawn from
        // `B64_ALPHABET` or `b'='`, all valid UTF-8.
        let enc_str =
            core::str::from_utf8(&enc[..enc_len]).unwrap_or("(b64-encode-error)");

        serial_println!("[FF-OUT-PNG-B64:{}/{}] {}", chunk_idx, total_chunks, enc_str);
    }

    serial_println!("[FF-OUT-PNG-END]");
}
