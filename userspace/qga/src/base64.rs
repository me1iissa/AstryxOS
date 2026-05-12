//! Minimal RFC 4648 §4 base64 encoder.
//!
//! Output is the standard alphabet `A–Z`, `a–z`, `0–9`, `+`, `/` with `=`
//! padding.  No URL-safe variant, no line breaks.  Encoding writes into a
//! caller-provided buffer and returns the number of bytes written, so the
//! daemon's hot path is allocation-free.

/// Standard alphabet from RFC 4648 §4 (table 1).
const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Number of base64 output bytes required to encode `input_len` raw bytes.
pub const fn encoded_len(input_len: usize) -> usize {
    // Ceiling division by 3 then *4 — matches RFC 4648 §4 (always padded).
    ((input_len + 2) / 3) * 4
}

/// Encode `input` into `out` using the standard alphabet with `=` padding.
///
/// Returns `Some(n)` where `n` is the number of bytes written, or `None` if
/// `out` is too small.
pub fn encode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let need = encoded_len(input.len());
    if out.len() < need {
        return None;
    }
    let mut o = 0;
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let b2 = input[i + 2] as u32;
        let v = (b0 << 16) | (b1 << 8) | b2;
        out[o]     = ALPHA[((v >> 18) & 0x3F) as usize];
        out[o + 1] = ALPHA[((v >> 12) & 0x3F) as usize];
        out[o + 2] = ALPHA[((v >>  6) & 0x3F) as usize];
        out[o + 3] = ALPHA[( v        & 0x3F) as usize];
        i += 3;
        o += 4;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let b0 = input[i] as u32;
        let v = b0 << 16;
        out[o]     = ALPHA[((v >> 18) & 0x3F) as usize];
        out[o + 1] = ALPHA[((v >> 12) & 0x3F) as usize];
        out[o + 2] = b'=';
        out[o + 3] = b'=';
        o += 4;
    } else if rem == 2 {
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let v = (b0 << 16) | (b1 << 8);
        out[o]     = ALPHA[((v >> 18) & 0x3F) as usize];
        out[o + 1] = ALPHA[((v >> 12) & 0x3F) as usize];
        out[o + 2] = ALPHA[((v >>  6) & 0x3F) as usize];
        out[o + 3] = b'=';
        o += 4;
    }
    Some(o)
}
