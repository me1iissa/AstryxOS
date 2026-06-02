//! Firefox headless-screenshot extraction over the serial port.
//!
//! After the firefox-test boot drives the headless Firefox `--screenshot`
//! pipeline, the rendered PNG lands at the guest path `/tmp/out.png` (a VFS
//! ramdisk file — see `kernel/src/main.rs` firefox-test path). The QEMU VGA
//! framebuffer at that point still shows the AstryxOS boot splash, so the
//! existing `[SCREENSHOT-B64:…]` stream (which carries the framebuffer) does
//! NOT carry Firefox's rendered output. This module reads `/tmp/out.png` back
//! through the kernel VFS and emits it over serial as a DISTINCT base64 marker
//! stream so the host can reconstruct the byte-exact file:
//!
//! ```text
//! [FF-OUT-PNG:path=/tmp/out.png size=<N> sig_ok=<bool>]
//! [FF-OUT-PNG-B64:0/M] <up to 76 base64 chars>
//! [FF-OUT-PNG-B64:1/M] ...
//! ...
//! [FF-OUT-PNG-END]
//! ```
//!
//! The encoding is standard base64 (RFC 4648 §4) with `=` padding; each data
//! line carries 57 input bytes → 76 output characters (the MIME line length,
//! RFC 2045 §6.8). The PNG signature is the 8-byte magic of W3C/ISO 15948 PNG
//! (89 50 4E 47 0D 0A 1A 0A).
//!
//! The host-side decoder is `scripts/qemu-harness.py read-ff-png`, which is
//! kept entirely separate from `read-png` (the framebuffer decoder) so the two
//! extraction paths never collide.
//!
//! This module is compiled only under the `firefox-test` feature; it is inert
//! (and absent) in every other build, so it cannot affect other tests.

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

/// Standard base64 alphabet (RFC 4648 §4, Table 1).
const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Input bytes per emitted line: 57 → exactly 76 base64 characters
/// (RFC 2045 §6.8 MIME line length).
const CHUNK_BYTES: usize = 57;

/// Maximum encoded bytes for one `CHUNK_BYTES` group: ceil(57/3)*4 = 76.
const MAX_ENC_LEN: usize = 76;

/// Base64-encode one input group (≤ `CHUNK_BYTES` bytes) into `out`, returning
/// the number of bytes written. `out` must be at least `MAX_ENC_LEN` long.
///
/// Pure function (no I/O, no allocation) so the encoding is unit-testable and
/// identical in shape to the `[SCREENSHOT-B64]` encoder in `test_runner.rs`.
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

/// Read `/tmp/out.png` back from the VFS and emit it over serial as the
/// `[FF-OUT-PNG-B64:…]` marker stream for host extraction. Returns `true` iff a
/// COMPLETE PNG (valid signature + IEND trailer) was streamed.
///
/// Best-effort and side-effect-free with respect to the boot: any failure
/// (file absent, read error, empty, bad signature) is reported on a single
/// `[FF-OUT-PNG:…]` line and the function returns `false` without emitting a
/// data stream — it never panics and never blocks the shutdown path. Firefox
/// having failed to write a screenshot is a normal, expected outcome that must
/// not wedge the boot.
///
/// When called speculatively from the poll loop (file may still be mid-write),
/// the `complete=false` early return lets the caller probe again next tick
/// rather than stream a truncated image.
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

    serial_println!(
        "[FF-OUT-PNG:path={} size={} sig_ok={} complete={}]",
        PNG_PATH, size, sig_ok, complete
    );

    if size == 0 {
        // Nothing to stream — header line already reported the empty file.
        serial_println!("[FF-OUT-PNG-END]");
        return false;
    }

    if !complete {
        // File present but not yet a complete PNG (still mid-write, or
        // corrupt). Do NOT stream a partial image; report and let the caller
        // retry on the next probe.
        serial_println!("[FF-OUT-PNG-END]");
        return false;
    }

    // Ceiling division for the chunk count (matches the existing
    // `[SCREENSHOT-B64]` encoder); the header line above already told the host
    // the byte size for a sanity cross-check.
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
    true
}
