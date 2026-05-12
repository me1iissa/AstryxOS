//! AstryxOS QEMU Guest Agent (QGA) daemon — Phase QGA-2.
//!
//! Opens `/dev/vport0p0` (the virtio-serial port wired up to the host's
//! `org.qemu.guest_agent.0` chardev in QGA-1) and runs a tiny JSON-RPC loop
//! over a newline-delimited subset of the QEMU Guest Agent protocol.
//!
//! References:
//! * <https://www.qemu.org/docs/master/interop/qemu-ga-ref.html>
//! * RFC 4648 — The Base16, Base32, and Base64 Data Encodings.
//!
//! Commands implemented (the MVS):
//!   * `guest-sync`        — handshake; echoes the caller's `id`.
//!   * `guest-ping`        — returns `{}`.
//!   * `guest-info`        — returns version + supported_commands list.
//!   * `guest-file-open`   — open a path read-only; returns daemon handle.
//!   * `guest-file-read`   — base64-encoded read of N bytes from a handle.
//!   * `guest-file-close`  — closes a handle.
//!
//! Anything else returns `{"error":{"class":"GenericError",...}}` with the
//! request `id` echoed back when present.  Protocol errors do not crash the
//! daemon — bad JSON / unknown commands are turned into error replies and
//! the read loop continues.

#![no_std]
#![no_main]

extern crate astryx_libsys as sys;

mod base64;
mod handles;
mod json;
mod proto;

use core::panic::PanicInfo;

/// Path of the virtio-serial device node (created by `vfs::init` when the
/// kernel is built with `--features qga`; see PR #150).
const VPORT_PATH: &[u8] = b"/dev/vport0p0";

/// Maximum size of an incoming QGA frame in bytes.  The MVS requests stay
/// well under 1 KiB; we leave headroom for argument paths and future fields.
const MAX_FRAME: usize = 4096;

/// Maximum size of an outgoing reply (base64 of a 4 KiB read fits in ~5.5 KiB).
const MAX_REPLY: usize = 8192;

/// Single-shot input scratch (consumed by the line reader).
const RX_CHUNK: usize = 512;

/// Spin / yield budget between empty reads before we ask the scheduler to
/// pick someone else.  The virtio-serial driver returns 0 from `read()` when
/// no data is pending; we busy-poll a small number of times before yielding
/// so latency stays low on cadenced host requests.
const POLL_BEFORE_YIELD: u32 = 64;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    main_loop()
}

fn main_loop() -> ! {
    // Open the QGA transport.  If the kernel was built without `--features qga`
    // or the host QEMU did not present a virtio-serial-pci device, this will
    // fail and there is nothing useful for us to do — exit quietly so we do
    // not log-spam every boot.
    let fd = match open_vport() {
        Some(fd) => fd,
        None => sys::exit(0),
    };

    // Greet so the harness can confirm the daemon reached its main loop.
    let _ = sys::write(1, b"qga: daemon ready\n".as_ptr(), 18);

    let mut frame_buf = [0u8; MAX_FRAME];
    let mut frame_len: usize = 0;
    let mut rx_chunk = [0u8; RX_CHUNK];
    let mut reply_buf = [0u8; MAX_REPLY];
    let mut handles = handles::HandleTable::new();
    let mut idle_polls: u32 = 0;

    loop {
        let n = sys::read(fd, rx_chunk.as_mut_ptr(), rx_chunk.len() as u64) as i64;
        if n <= 0 {
            // EAGAIN / EOF / transient error — back off cooperatively.
            idle_polls = idle_polls.saturating_add(1);
            if idle_polls >= POLL_BEFORE_YIELD {
                sys::yield_cpu();
                idle_polls = 0;
            }
            continue;
        }
        idle_polls = 0;

        let n = n as usize;
        for i in 0..n {
            let byte = rx_chunk[i];
            if byte == b'\n' {
                // Complete frame — dispatch.
                let req = &frame_buf[..frame_len];
                let reply_len = proto::handle_request(req, &mut reply_buf, &mut handles);
                if reply_len > 0 {
                    write_all(fd, &reply_buf[..reply_len]);
                }
                frame_len = 0;
            } else if byte == b'\r' {
                // ignore — tolerant of CRLF line endings if any host sends them
            } else if frame_len < frame_buf.len() {
                frame_buf[frame_len] = byte;
                frame_len += 1;
            } else {
                // Frame too long — drop the oversize byte; the next '\n'
                // will close out a truncated frame and the parser will
                // reject it cleanly.
                frame_len = frame_buf.len();
            }
        }
    }
}

fn open_vport() -> Option<u64> {
    // Native AstryxOS open ABI: open(path_ptr, path_len, flags).  Flags=0
    // means O_RDONLY in the kernel's Aether VFS; the device supports both
    // read and write regardless.
    let ret = sys::open(VPORT_PATH.as_ptr(), VPORT_PATH.len() as u64, 0);
    // Negative-as-u64 means error (kernel returns -errno).
    if (ret as i64) < 0 {
        None
    } else {
        Some(ret)
    }
}

fn write_all(fd: u64, data: &[u8]) {
    let mut written = 0;
    while written < data.len() {
        let n = sys::write(
            fd,
            unsafe { data.as_ptr().add(written) },
            (data.len() - written) as u64,
        ) as i64;
        if n <= 0 {
            // Bail — the host side may have torn down the socket.
            return;
        }
        written += n as usize;
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    // No serial access from a freestanding userspace panic; just exit so the
    // kernel reaps us and the test driver notices.
    sys::exit(1);
}
