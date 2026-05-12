//! Minimal PNG encoder for AstryxOS GDI surfaces.
//!
//! Encodes a [`Surface`] (32-bpp ARGB pixel buffer) into a valid PNG byte stream.
//!
//! ## Format overview
//!
//! Per the PNG specification (W3C PNG Third Edition, ISO/IEC 15948:2024):
//! - 8-byte PNG signature
//! - IHDR chunk  (13 bytes of image metadata)
//! - IDAT chunk  (compressed image data)
//! - IEND chunk  (zero-length end marker)
//!
//! ## Compression
//!
//! The image data is compressed using zlib format (RFC 1950) with a deflate
//! (RFC 1951) payload composed entirely of stored (non-compressed) blocks.
//! Stored blocks are valid per RFC 1951 §3.2.4 and are accepted by every
//! standards-conforming PNG decoder. This avoids a Huffman / LZ77 implementation
//! while keeping the output a spec-valid, widely-readable PNG file.
//!
//! ## Pixel format conversion
//!
//! The surface stores pixels as 32-bit `0xAARRGGBB`. The encoder converts each
//! pixel to an 8-bit RGBA byte tuple (R, G, B, A) and prepends each scanline
//! with a PNG filter byte of 0 (None). Alpha is preserved.

extern crate alloc;
use alloc::vec::Vec;
use super::surface::Surface;

// ── CRC-32 ──────────────────────────────────────────────────────────────────

/// Generate the standard CRC-32 table (ISO 3309 polynomial 0xEDB88320).
///
/// CRC-32 is used for PNG chunk integrity as required by the PNG specification.
fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for n in 0..256usize {
        let mut c = n as u32;
        for _ in 0..8 {
            if c & 1 != 0 {
                c = 0xEDB88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        table[n] = c;
    }
    table
}

/// Compute CRC-32 over `data`, seeded with `crc` (pass `0xFFFF_FFFF` initially,
/// XOR the final result with `0xFFFF_FFFF`).
fn update_crc(table: &[u32; 256], mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// Compute the complete CRC-32 for a block of data.
fn crc32(table: &[u32; 256], data: &[u8]) -> u32 {
    update_crc(table, 0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

// ── Chunk helpers ────────────────────────────────────────────────────────────

/// Append a big-endian u32 to `buf`.
#[inline]
fn push_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.push((v >> 24) as u8);
    buf.push((v >> 16) as u8);
    buf.push((v >>  8) as u8);
    buf.push( v        as u8);
}

/// Write a PNG chunk: `length(4) + type(4) + data(length) + crc32(4)`.
///
/// `chunk_type` must be exactly 4 ASCII bytes.
fn write_chunk(buf: &mut Vec<u8>, table: &[u32; 256], chunk_type: &[u8; 4], data: &[u8]) {
    push_u32_be(buf, data.len() as u32);
    buf.extend_from_slice(chunk_type);
    buf.extend_from_slice(data);
    // CRC covers chunk-type + chunk-data (not the length field).
    let mut crc_input = [0u8; 4];
    crc_input.copy_from_slice(chunk_type);
    let crc = update_crc(table, 0xFFFF_FFFF, &crc_input);
    let crc = update_crc(table, crc, data) ^ 0xFFFF_FFFF;
    push_u32_be(buf, crc);
}

// ── Stored-block deflate / zlib ──────────────────────────────────────────────

/// Wrap `raw_data` in a zlib envelope (RFC 1950) containing stored deflate blocks
/// (RFC 1951 §3.2.4, BTYPE=00).
///
/// Structure:
/// ```text
/// zlib header  (2 bytes):  CMF=0x78 (deflate, window=32K), FLG (computed for FCHECK)
/// for each stored block:
///   BFINAL (1 bit) | BTYPE=00 (2 bits) | padding (5 bits)  -> 1 byte
///   LEN   (2 bytes, little-endian)
///   NLEN  (2 bytes, one's complement of LEN, little-endian)
///   data  (LEN bytes)
/// Adler-32 checksum (4 bytes, big-endian)
/// ```
///
/// Maximum stored block payload is 65535 bytes. Long inputs are split.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    // Capacity estimate: header(2) + ceil(len/65535)*(5+65535) + trailer(4)
    let n_blocks = if data.is_empty() { 1 } else { (data.len() + 65534) / 65535 };
    let mut out = Vec::with_capacity(2 + n_blocks * 5 + data.len() + 4);

    // zlib header: CMF = 0x78 (CM=8 deflate, CINFO=7 -> 32K window)
    // FLG must make (CMF*256 + FLG) divisible by 31.
    // 0x78 * 256 = 0x7800 = 30720.  30720 % 31 = 30720 - 991*31 = 30720-30721 < 0 → try 1
    // 30720 + FLG ≡ 0 (mod 31) → FLG ≡ -30720 (mod 31) ≡ -(30720 % 31) (mod 31)
    // 30720 / 31 = 991 rem 30720 - 991*31 = 30720 - 30721 … let's just compute.
    // 30721 % 31 = 30721 - 991*31 = 30721 - 30721 = 0.  So CMF=0x78, FLG=0x01.
    // Verify: (0x78<<8 | 0x01) = 0x7801 = 30721. 30721 / 31 = 991. ✓
    out.push(0x78); // CMF
    out.push(0x01); // FLG  (no dict, FCHECK=1)

    // Adler-32 running state (RFC 1950 §2.2).
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;

    let mut offset = 0usize;
    while offset < data.len() || data.is_empty() {
        let end = (offset + 65535).min(data.len());
        let block = &data[offset..end];
        let bfinal: u8 = if end == data.len() { 1 } else { 0 };

        // BFINAL + BTYPE=00 (stored).  The remaining 5 bits of the byte are 0.
        out.push(bfinal); // BFINAL=bfinal, BTYPE=00

        let len = block.len() as u16;
        let nlen = !len;
        out.push( len        as u8);
        out.push((len >> 8)  as u8);
        out.push( nlen       as u8);
        out.push((nlen >> 8) as u8);

        out.extend_from_slice(block);

        // Update Adler-32 (mod 65521).
        for &b in block {
            s1 = (s1 + b as u32) % 65521;
            s2 = (s2 + s1)       % 65521;
        }

        if data.is_empty() {
            break;
        }
        offset = end;
        if offset >= data.len() {
            break;
        }
    }

    // Handle truly empty input: one zero-length stored block was written above.
    // Adler-32 of empty string = (s2<<16)|s1 = (0<<16)|1 = 1.

    // Adler-32 trailer — big-endian.
    let adler = (s2 << 16) | s1;
    push_u32_be(&mut out, adler);

    out
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Encode a [`Surface`] as a PNG byte stream.
///
/// The surface's pixels (32-bpp `0xAARRGGBB`) are converted to 8-bit RGBA
/// tuples. Each scanline is preceded by a filter byte of 0 (None) as required
/// by the PNG specification. The IDAT payload is zlib-wrapped with stored
/// deflate blocks.
///
/// Returns the complete PNG file as a `Vec<u8>`.
pub fn encode_surface_to_png(surface: &Surface) -> Vec<u8> {
    let w = surface.width;
    let h = surface.height;

    let crc_table = make_crc_table();

    // ── Build raw IDAT payload: filter(1) + RGBA(4) per pixel, per row ──────
    // Each scanline: 1 filter byte + 4 bytes per pixel.
    let row_stride = 1 + (w as usize) * 4;
    let mut raw = Vec::with_capacity(row_stride * h as usize);

    for y in 0..h {
        raw.push(0u8); // PNG filter type 0 (None)
        for x in 0..w {
            let argb = surface.pixels[(y as usize) * (w as usize) + (x as usize)];
            let r = ((argb >> 16) & 0xFF) as u8;
            let g = ((argb >>  8) & 0xFF) as u8;
            let b = ( argb        & 0xFF) as u8;
            let a = ((argb >> 24) & 0xFF) as u8;
            raw.push(r);
            raw.push(g);
            raw.push(b);
            raw.push(a);
        }
    }

    // ── Compress with stored deflate / zlib ──────────────────────────────────
    let idat_data = zlib_stored(&raw);

    // ── Assemble PNG ─────────────────────────────────────────────────────────
    // Capacity estimate: sig(8) + IHDR(25) + IDAT(12+len) + IEND(12)
    let mut png = Vec::with_capacity(8 + 25 + 12 + idat_data.len() + 12);

    // PNG signature (fixed 8-byte magic, per PNG spec §5.2).
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR chunk (13 bytes of data):
    //   width(4) height(4) bit_depth(1) color_type(1) compression(1) filter(1) interlace(1)
    // color_type=6: RGBA (truecolour with alpha).
    let mut ihdr = [0u8; 13];
    ihdr[0] = (w >> 24) as u8;
    ihdr[1] = (w >> 16) as u8;
    ihdr[2] = (w >>  8) as u8;
    ihdr[3] =  w        as u8;
    ihdr[4] = (h >> 24) as u8;
    ihdr[5] = (h >> 16) as u8;
    ihdr[6] = (h >>  8) as u8;
    ihdr[7] =  h        as u8;
    ihdr[8]  = 8;  // bit depth
    ihdr[9]  = 6;  // color type: RGBA
    ihdr[10] = 0;  // compression method: deflate (only defined value)
    ihdr[11] = 0;  // filter method: adaptive (only defined value)
    ihdr[12] = 0;  // interlace method: none
    write_chunk(&mut png, &crc_table, b"IHDR", &ihdr);

    // IDAT chunk
    write_chunk(&mut png, &crc_table, b"IDAT", &idat_data);

    // IEND chunk (zero-length)
    write_chunk(&mut png, &crc_table, b"IEND", &[]);

    png
}

/// The 8-byte PNG signature that every valid PNG file begins with (PNG spec §5.2).
pub const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
