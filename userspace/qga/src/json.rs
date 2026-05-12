//! Minimal no_std JSON parser + builder tailored to the QGA frame shape.
//!
//! The QGA wire format is well-defined and tiny — each request is a single
//! JSON object on one line with at most four top-level keys (`execute`,
//! `arguments`, `id`, `return`).  We don't need a full RFC 8259 parser; a
//! permissive recursive-descent scanner over ASCII suffices.  The parser
//! handles:
//!   * Strings (with backslash escapes \" \\ \/ \n \r \t \b \f \uXXXX).
//!   * Integers (decimal, signed).
//!   * Booleans + null.
//!   * Objects and arrays (skipped via balanced-brace scan when we just need
//!     to step over them).
//!   * Optional whitespace anywhere.
//!
//! The builder emits the same subset back into a caller-supplied byte buffer.

/// Strongly-typed lookup result for a string value.  Storing only borrowed
/// slices keeps the parser allocation-free.
pub struct JsonStr<'a> {
    /// Raw bytes (between the outer quotes) — caller decodes escapes via
    /// `copy_string`.
    pub raw: &'a [u8],
}

/// Skip ASCII whitespace forward from `pos` and return the new index.
fn skip_ws(buf: &[u8], mut pos: usize) -> usize {
    while pos < buf.len() {
        match buf[pos] {
            b' ' | b'\t' | b'\n' | b'\r' => pos += 1,
            _ => break,
        }
    }
    pos
}

/// Try to match an unquoted ASCII literal (`true`, `false`, `null`,
/// `<digits>`); return its byte range.
fn scan_literal(buf: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut end = start;
    while end < buf.len() {
        let c = buf[end];
        let alpha = (c >= b'a' && c <= b'z')
            || (c >= b'A' && c <= b'Z')
            || (c >= b'0' && c <= b'9')
            || c == b'-' || c == b'+' || c == b'.';
        if !alpha {
            break;
        }
        end += 1;
    }
    if end > start {
        Some((start, end))
    } else {
        None
    }
}

/// Parse a quoted string starting at `pos` (which must be a `"`).  Returns
/// `(JsonStr, next_pos_after_closing_quote)`.  Backslash escapes are NOT
/// expanded here — `copy_string` does that into a caller-supplied buffer.
fn scan_string(buf: &[u8], pos: usize) -> Option<(JsonStr<'_>, usize)> {
    if pos >= buf.len() || buf[pos] != b'"' {
        return None;
    }
    let start = pos + 1;
    let mut i = start;
    while i < buf.len() {
        match buf[i] {
            b'\\' => i += 2,
            b'"' => return Some((JsonStr { raw: &buf[start..i] }, i + 1)),
            _ => i += 1,
        }
    }
    None
}

/// Skip past a JSON value starting at `pos`, returning the index just after.
/// Supports objects/arrays via brace-depth scanning, strings via the proper
/// escape-aware scanner, and bare literals.
fn skip_value(buf: &[u8], pos: usize) -> Option<usize> {
    let pos = skip_ws(buf, pos);
    if pos >= buf.len() { return None; }
    match buf[pos] {
        b'"' => scan_string(buf, pos).map(|(_, p)| p),
        b'{' | b'[' => {
            let open = buf[pos];
            let close = if open == b'{' { b'}' } else { b']' };
            let mut i = pos + 1;
            let mut depth = 1i32;
            while i < buf.len() && depth > 0 {
                match buf[i] {
                    b'"' => {
                        let (_, end) = scan_string(buf, i)?;
                        i = end;
                        continue;
                    }
                    c if c == open => depth += 1,
                    c if c == close => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            if depth == 0 { Some(i) } else { None }
        }
        _ => scan_literal(buf, pos).map(|(_, e)| e),
    }
}

/// Top-level object cursor: scans key/value pairs of an object whose opening
/// `{` starts at `pos`.  This is the workhorse of the request parser.
pub struct ObjCursor<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> ObjCursor<'a> {
    /// Build a cursor over the outermost object in `buf`.  Returns `None` if
    /// the buffer does not start with a `{`.
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        let start = skip_ws(buf, 0);
        if start >= buf.len() || buf[start] != b'{' {
            return None;
        }
        // Find the matching close so iteration knows where to stop.
        let end = skip_value(buf, start)?;
        Some(Self {
            buf,
            pos: start + 1,
            end,
        })
    }

    /// Look up a string-valued field by ASCII key.  Returns the raw bytes
    /// (between the quotes — caller invokes `copy_string` to expand escapes).
    pub fn get_str(&self, key: &str) -> Option<JsonStr<'a>> {
        self.find_key(key).and_then(|p| {
            let p = skip_ws(self.buf, p);
            scan_string(self.buf, p).map(|(s, _)| s)
        })
    }

    /// Look up an integer-valued field by ASCII key.  Returns the parsed i64.
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.find_key(key).and_then(|p| {
            let p = skip_ws(self.buf, p);
            let (s, e) = scan_literal(self.buf, p)?;
            parse_i64(&self.buf[s..e])
        })
    }

    /// Recursively look up a key inside a nested `{...}` value of the
    /// current object (e.g. the QGA `arguments` sub-object).
    pub fn get_subobject(&self, key: &str) -> Option<ObjCursor<'a>> {
        let p = self.find_key(key)?;
        let p = skip_ws(self.buf, p);
        if p >= self.buf.len() || self.buf[p] != b'{' {
            return None;
        }
        let sub_end = skip_value(self.buf, p)?;
        Some(ObjCursor { buf: self.buf, pos: p + 1, end: sub_end })
    }

    /// Lower-level: find the position immediately after the `:` separator for
    /// the named key, or `None` if no such key exists in this object.  Used
    /// by the typed getters above.
    fn find_key(&self, key: &str) -> Option<usize> {
        let mut i = self.pos;
        while i < self.end {
            i = skip_ws(self.buf, i);
            if i >= self.end || self.buf[i] == b'}' {
                break;
            }
            // Key.
            let (k, after_key) = scan_string(self.buf, i)?;
            let mut p = skip_ws(self.buf, after_key);
            if p >= self.end || self.buf[p] != b':' {
                return None;
            }
            p = skip_ws(self.buf, p + 1);
            // Compare key (no escape expansion: QGA keys are ASCII literals).
            if k.raw == key.as_bytes() {
                return Some(p);
            }
            // Otherwise skip the value and the optional comma.
            let after_val = skip_value(self.buf, p)?;
            i = skip_ws(self.buf, after_val);
            if i < self.end && self.buf[i] == b',' {
                i += 1;
            }
        }
        None
    }
}

/// Copy a raw (escape-bearing) JSON string slice into a UTF-8 byte buffer,
/// expanding the standard escapes.  Returns the number of bytes written, or
/// `None` if `out` is too small or an escape was malformed.  Used by
/// `guest-file-open` to materialise the path string.
pub fn copy_string(src: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut o = 0;
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if c != b'\\' {
            if o >= out.len() { return None; }
            out[o] = c;
            o += 1;
            i += 1;
            continue;
        }
        // Escape sequence.
        if i + 1 >= src.len() { return None; }
        let n = src[i + 1];
        let byte = match n {
            b'"' => b'"',
            b'\\' => b'\\',
            b'/' => b'/',
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'b' => 0x08,
            b'f' => 0x0C,
            // \uXXXX — we accept only ASCII codepoints.  Anything else is
            // a malformed QGA path and rejected outright.
            b'u' => {
                if i + 5 >= src.len() { return None; }
                let mut v: u32 = 0;
                for k in 0..4 {
                    let d = src[i + 2 + k];
                    let nib = match d {
                        b'0'..=b'9' => d - b'0',
                        b'a'..=b'f' => d - b'a' + 10,
                        b'A'..=b'F' => d - b'A' + 10,
                        _ => return None,
                    };
                    v = (v << 4) | nib as u32;
                }
                if v > 0x7F { return None; }
                i += 6;
                if o >= out.len() { return None; }
                out[o] = v as u8;
                o += 1;
                continue;
            }
            _ => return None,
        };
        if o >= out.len() { return None; }
        out[o] = byte;
        o += 1;
        i += 2;
    }
    Some(o)
}

/// Parse a signed decimal integer.
pub fn parse_i64(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() { return None; }
    let (neg, start) = if bytes[0] == b'-' {
        (true, 1)
    } else if bytes[0] == b'+' {
        (false, 1)
    } else {
        (false, 0)
    };
    if start >= bytes.len() { return None; }
    let mut v: i64 = 0;
    for &b in &bytes[start..] {
        if !(b'0'..=b'9').contains(&b) {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as i64)?;
    }
    Some(if neg { -v } else { v })
}

// ── Builder ─────────────────────────────────────────────────────────────────

/// Stack-allocated JSON writer that appends to a caller-owned byte slice.
/// Each `write_*` method returns whether it succeeded — once a write fails
/// (buffer full), subsequent writes are no-ops and `len()` is clamped.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    failed: bool,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0, failed: false }
    }

    pub fn len(&self) -> usize {
        if self.failed { 0 } else { self.pos }
    }

    pub fn failed(&self) -> bool { self.failed }

    pub fn raw(&mut self, bytes: &[u8]) {
        if self.failed { return; }
        if self.pos + bytes.len() > self.buf.len() {
            self.failed = true;
            return;
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    pub fn byte(&mut self, b: u8) {
        if self.failed { return; }
        if self.pos >= self.buf.len() {
            self.failed = true;
            return;
        }
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    /// Emit a JSON string literal — backslash-escapes `"` and `\` and
    /// control characters; everything else passes through (QGA replies are
    /// ASCII / UTF-8).
    pub fn string(&mut self, s: &[u8]) {
        self.byte(b'"');
        for &c in s {
            match c {
                b'"' => self.raw(b"\\\""),
                b'\\' => self.raw(b"\\\\"),
                b'\n' => self.raw(b"\\n"),
                b'\r' => self.raw(b"\\r"),
                b'\t' => self.raw(b"\\t"),
                0..=0x1F => {
                    let hex = b"0123456789abcdef";
                    self.raw(b"\\u00");
                    self.byte(hex[(c >> 4) as usize]);
                    self.byte(hex[(c & 0x0F) as usize]);
                }
                _ => self.byte(c),
            }
        }
        self.byte(b'"');
    }

    /// Emit a signed decimal integer.
    pub fn i64(&mut self, v: i64) {
        let mut tmp = [0u8; 24];
        let mut n = 0;
        let (neg, mut u) = if v < 0 {
            (true, (v as i128).unsigned_abs() as u64)
        } else {
            (false, v as u64)
        };
        if u == 0 {
            self.byte(b'0');
            return;
        }
        while u > 0 {
            tmp[n] = b'0' + (u % 10) as u8;
            u /= 10;
            n += 1;
        }
        if neg { self.byte(b'-'); }
        while n > 0 {
            n -= 1;
            self.byte(tmp[n]);
        }
    }
}
