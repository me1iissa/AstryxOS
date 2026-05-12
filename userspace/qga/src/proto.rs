//! QGA command dispatcher.
//!
//! Receives a single newline-stripped request frame and emits a single
//! newline-terminated reply into `out`.  Returns the number of bytes
//! written; a zero-length response means the request was an empty frame
//! and should be silently dropped.
//!
//! Errors are encoded as `{"error":{"class":"GenericError","desc":"…"}}`
//! per the QGA reference (https://www.qemu.org/docs/master/interop/qemu-ga-ref.html).

extern crate astryx_libsys as sys;

use crate::handles::HandleTable;
use crate::json::{copy_string, ObjCursor, Writer};
use crate::base64;

/// Largest path the daemon will accept on `guest-file-open`.  Linux's PATH_MAX
/// is 4 KiB; we cap considerably below to keep the path stack buffer tight.
const MAX_PATH: usize = 512;

/// Per-read chunk size for `guest-file-read` — matches the virtio-serial
/// scratch buffer in PR #150 so the encoded reply fits in MAX_REPLY (8 KiB
/// after base64 expansion of 4 KiB).
const MAX_READ_CHUNK: usize = 4096;

pub fn handle_request(req: &[u8], out: &mut [u8], handles: &mut HandleTable) -> usize {
    if req.is_empty() {
        return 0;
    }

    let mut w = Writer::new(out);

    // Try to parse the frame.  Any failure becomes a generic error reply
    // with no `id` (we couldn't read one anyway).
    let obj = match ObjCursor::new(req) {
        Some(o) => o,
        None => {
            emit_error(&mut w, None, b"invalid JSON frame");
            return finalise(w);
        }
    };

    let id = obj.get_i64("id"); // optional
    let cmd = match obj.get_str("execute") {
        Some(s) => s,
        None => {
            emit_error(&mut w, id, b"missing 'execute' field");
            return finalise(w);
        }
    };

    match cmd.raw {
        b"guest-sync" => cmd_guest_sync(&mut w, &obj, id),
        b"guest-ping" => cmd_guest_ping(&mut w, id),
        b"guest-info" => cmd_guest_info(&mut w, id),
        b"guest-file-open" => cmd_guest_file_open(&mut w, &obj, id, handles),
        b"guest-file-read" => cmd_guest_file_read(&mut w, &obj, id, handles),
        b"guest-file-close" => cmd_guest_file_close(&mut w, &obj, id, handles),
        _ => emit_error(&mut w, id, b"command not supported"),
    }

    finalise(w)
}

fn finalise(mut w: Writer<'_>) -> usize {
    // Append the framing newline.  If the writer overflowed mid-payload we
    // would emit a malformed half-frame; return 0 instead so the host times
    // out cleanly rather than parsing partial JSON.  In the MVS the reply
    // buffer (MAX_REPLY = 8 KiB) is sized to fit every command response,
    // so this branch is defensive and not exercised by the implemented
    // command set.
    if w.failed() {
        return 0;
    }
    w.byte(b'\n');
    w.len()
}

fn emit_error(w: &mut Writer<'_>, id: Option<i64>, desc: &[u8]) {
    w.raw(b"{\"error\":{\"class\":\"GenericError\",\"desc\":");
    w.string(desc);
    w.raw(b"}");
    if let Some(v) = id {
        w.raw(b",\"id\":");
        w.i64(v);
    }
    w.byte(b'}');
}

// ── Commands ────────────────────────────────────────────────────────────────

fn cmd_guest_sync(w: &mut Writer<'_>, obj: &ObjCursor<'_>, id: Option<i64>) {
    // QGA spec: arguments = {"id": <i64>}.  Reply with that same id as the
    // top-level return value (NOT inside a sub-object) — see qga-ref §
    // guest-sync.
    let sync_id = obj
        .get_subobject("arguments")
        .and_then(|a| a.get_i64("id"));
    match sync_id {
        Some(v) => {
            w.raw(b"{\"return\":");
            w.i64(v);
            if let Some(rid) = id {
                w.raw(b",\"id\":");
                w.i64(rid);
            }
            w.byte(b'}');
        }
        None => emit_error(w, id, b"missing arguments.id for guest-sync"),
    }
}

fn cmd_guest_ping(w: &mut Writer<'_>, id: Option<i64>) {
    w.raw(b"{\"return\":{}");
    if let Some(rid) = id {
        w.raw(b",\"id\":");
        w.i64(rid);
    }
    w.byte(b'}');
}

fn cmd_guest_info(w: &mut Writer<'_>, id: Option<i64>) {
    // The supported_commands list is the MVS subset.  Future phases will
    // extend this in lockstep with new dispatch arms.
    w.raw(b"{\"return\":{\"version\":\"0.1\",\"supported_commands\":[");
    let cmds: &[&[u8]] = &[
        b"guest-sync",
        b"guest-ping",
        b"guest-info",
        b"guest-file-open",
        b"guest-file-read",
        b"guest-file-close",
    ];
    for (i, c) in cmds.iter().enumerate() {
        if i > 0 { w.byte(b','); }
        w.string(c);
    }
    w.raw(b"]}");
    if let Some(rid) = id {
        w.raw(b",\"id\":");
        w.i64(rid);
    }
    w.byte(b'}');
}

fn cmd_guest_file_open(
    w: &mut Writer<'_>,
    obj: &ObjCursor<'_>,
    id: Option<i64>,
    handles: &mut HandleTable,
) {
    let args = match obj.get_subobject("arguments") {
        Some(a) => a,
        None => return emit_error(w, id, b"missing arguments object"),
    };
    let path_str = match args.get_str("path") {
        Some(s) => s,
        None => return emit_error(w, id, b"missing arguments.path"),
    };
    // We don't enforce the mode beyond "must be present and start with r" —
    // QGA accepts "r", "rb"; anything else we reject so callers can't
    // accidentally request writes (deferred to QGA-4).
    if let Some(mode) = args.get_str("mode") {
        if mode.raw.is_empty() || mode.raw[0] != b'r' {
            return emit_error(w, id, b"only read modes supported in QGA-2");
        }
    }

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match copy_string(path_str.raw, &mut path_buf) {
        Some(n) => n,
        None => return emit_error(w, id, b"path too long or malformed"),
    };

    // Aether native open: open(path_ptr, path_len, flags=0 → O_RDONLY).
    let fd = sys::open(path_buf.as_ptr(), path_len as u64, 0);
    if (fd as i64) < 0 {
        return emit_error(w, id, b"file not found or open failed");
    }
    let handle = match handles.insert(fd) {
        Some(h) => h,
        None => {
            // Table full — close the just-opened fd and bail.
            let _ = sys::close(fd);
            return emit_error(w, id, b"handle table exhausted");
        }
    };

    w.raw(b"{\"return\":");
    w.i64(handle);
    if let Some(rid) = id {
        w.raw(b",\"id\":");
        w.i64(rid);
    }
    w.byte(b'}');
}

fn cmd_guest_file_read(
    w: &mut Writer<'_>,
    obj: &ObjCursor<'_>,
    id: Option<i64>,
    handles: &mut HandleTable,
) {
    let args = match obj.get_subobject("arguments") {
        Some(a) => a,
        None => return emit_error(w, id, b"missing arguments object"),
    };
    let handle = match args.get_i64("handle") {
        Some(h) => h,
        None => return emit_error(w, id, b"missing arguments.handle"),
    };
    // `count` is optional; default cap matches MAX_READ_CHUNK.
    let req_count = args.get_i64("count").unwrap_or(MAX_READ_CHUNK as i64);
    let count = req_count.clamp(0, MAX_READ_CHUNK as i64) as usize;

    let fd = match handles.lookup(handle) {
        Some(fd) => fd,
        None => return emit_error(w, id, b"unknown handle"),
    };

    let mut data = [0u8; MAX_READ_CHUNK];
    let n_raw = sys::read(fd, data.as_mut_ptr(), count as u64) as i64;
    if n_raw < 0 {
        return emit_error(w, id, b"read failed");
    }
    let n = n_raw as usize;

    // Base64-encode the (possibly empty) chunk into the JSON reply.  We do
    // this through a small scratch buffer rather than encoding inline so the
    // emitted JSON has clean separation between framing and payload.
    let mut b64 = [0u8; base64::encoded_len(MAX_READ_CHUNK)];
    let b64_len = match base64::encode(&data[..n], &mut b64) {
        Some(l) => l,
        None => return emit_error(w, id, b"base64 buffer too small"),
    };

    w.raw(b"{\"return\":{\"count\":");
    w.i64(n as i64);
    w.raw(b",\"buf-b64\":\"");
    w.raw(&b64[..b64_len]);
    w.raw(b"\"}");
    if let Some(rid) = id {
        w.raw(b",\"id\":");
        w.i64(rid);
    }
    w.byte(b'}');
}

fn cmd_guest_file_close(
    w: &mut Writer<'_>,
    obj: &ObjCursor<'_>,
    id: Option<i64>,
    handles: &mut HandleTable,
) {
    let args = match obj.get_subobject("arguments") {
        Some(a) => a,
        None => return emit_error(w, id, b"missing arguments object"),
    };
    let handle = match args.get_i64("handle") {
        Some(h) => h,
        None => return emit_error(w, id, b"missing arguments.handle"),
    };
    let fd = match handles.remove(handle) {
        Some(fd) => fd,
        None => return emit_error(w, id, b"unknown handle"),
    };
    let _ = sys::close(fd);

    w.raw(b"{\"return\":{}");
    if let Some(rid) = id {
        w.raw(b",\"id\":");
        w.i64(rid);
    }
    w.byte(b'}');
}
