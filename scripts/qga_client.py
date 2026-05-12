"""
qga_client.py — Minimal one-shot client for the AstryxOS QGA daemon.

Talks to the in-guest QEMU Guest Agent daemon through QEMU's UNIX-domain
chardev socket (the host side of the virtio-serial port wired into the
guest as `/dev/vport0p0`). Wire format is qemu-guest-agent compatible —
each line is one JSON request, the daemon replies with one JSON line.

See https://wiki.qemu.org/Features/GuestAgent and
https://www.qemu.org/docs/master/interop/qemu-ga-ref.html for the protocol.

## Design

Strictly one-shot per call: every public helper opens the socket, writes
one request, reads one response, closes, returns. This matches the
agent-friendly contract enforced by `qemu-harness.py` itself — no REPL,
no kept-open connections, no stdin pipes. Multiple parallel callers are
safe because the chardev socket is session-scoped (one socket per
QEMU process).

## guest-sync-delimited robustness

The published QGA framing has a stale-data quirk: after a guest reboot,
the host side of the chardev may still have bytes from the previous
guest's reply lingering in its receive buffer. The recommended cure is
`guest-sync-delimited`, which prefixes its reply with a literal `0xff`
byte that the client uses to skip the stale prefix. A plain `guest-sync`
emits no `0xff`. Both forms are valid JSON-line replies.

We accept either: when reading the response we strip a single leading
`0xff` if present before JSON parsing. This keeps the client compatible
with the current AstryxOS daemon (which never emits `0xff`) and with a
future upgrade path to delimited sync.
"""

from __future__ import annotations

import json
import os
import random
import socket
import time
from typing import Any, Optional


# ── Public API ───────────────────────────────────────────────────────────────


def qga_request(
    sock_path: str,
    request: dict,
    *,
    timeout: float = 5.0,
) -> dict:
    """
    Send one QGA request, return one parsed response.

    Returns a dict of the form:
      - success: ``{"ok": True, "response": <parsed JSON>, "latency_ms": N}``
      - failure: ``{"ok": False, "error": "<short reason>", "latency_ms": N}``

    Never raises. All failure modes (missing socket, connect refused,
    short read, bad JSON, server-side error reply) are surfaced through
    the ``ok=False`` shape so callers can render structured stdout
    without try/except boilerplate.

    The ``latency_ms`` field is the wall-clock duration of the call,
    rounded down to whole milliseconds.

    Args:
        sock_path:  Filesystem path of the host-side QGA chardev socket
                    (``~/.astryx-harness/<sid>.qga.sock``).
        request:    Dict that JSON-encodes to one QGA request line.
                    Must include an ``execute`` key per QGA spec.
        timeout:    Total wall-clock budget for connect + send + recv,
                    in seconds. Default 5s (matches the smoke-test
                    expectation of "fresh boot → ping in well under 1s").

    Errors returned:
      - ``"socket missing"`` — sock_path doesn't exist (QGA daemon never
        ran, or session not started with `--features qga`)
      - ``"connect failed: ..."`` — socket exists but QEMU refused
      - ``"timeout"`` — no response line within ``timeout``
      - ``"short read"`` — peer closed before delivering a complete line
      - ``"bad JSON: ..."`` — response was not valid JSON
      - ``"server error: ..."`` — response was a well-formed QGA error
    """
    t0 = time.monotonic()

    def _latency() -> int:
        return int((time.monotonic() - t0) * 1000)

    if not os.path.exists(sock_path):
        return {"ok": False, "error": "socket missing", "latency_ms": _latency()}

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect(sock_path)
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            return {
                "ok": False,
                "error": f"connect failed: {e}",
                "latency_ms": _latency(),
            }

        payload = (json.dumps(request, separators=(",", ":")) + "\n").encode()
        try:
            s.sendall(payload)
        except OSError as e:
            return {
                "ok": False,
                "error": f"send failed: {e}",
                "latency_ms": _latency(),
            }

        # Read until newline or deadline. The daemon emits exactly one
        # newline-terminated reply per request — anything past it is a
        # framing error.
        deadline = t0 + timeout
        buf = bytearray()
        while b"\n" not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {
                    "ok": False,
                    "error": "timeout",
                    "latency_ms": _latency(),
                }
            try:
                s.settimeout(remaining)
                chunk = s.recv(65536)
            except socket.timeout:
                return {
                    "ok": False,
                    "error": "timeout",
                    "latency_ms": _latency(),
                }
            except OSError as e:
                return {
                    "ok": False,
                    "error": f"recv failed: {e}",
                    "latency_ms": _latency(),
                }
            if not chunk:
                return {
                    "ok": False,
                    "error": "short read",
                    "latency_ms": _latency(),
                }
            buf.extend(chunk)
            # Cap buffer to keep a runaway server from blowing the host.
            if len(buf) > 1024 * 1024:
                return {
                    "ok": False,
                    "error": "reply too large",
                    "latency_ms": _latency(),
                }
    finally:
        try:
            s.close()
        except OSError:
            pass

    # Carve out exactly the first line.
    line, _, _ = bytes(buf).partition(b"\n")

    # Strip a single leading 0xff if present (guest-sync-delimited path —
    # see module docstring). Anything else is treated as opaque JSON bytes.
    if line.startswith(b"\xff"):
        line = line[1:]

    try:
        obj = json.loads(line.decode("utf-8", errors="replace"))
    except (ValueError, json.JSONDecodeError) as e:
        return {
            "ok": False,
            "error": f"bad JSON: {e}",
            "raw": line.decode("utf-8", errors="replace"),
            "latency_ms": _latency(),
        }

    if isinstance(obj, dict) and "error" in obj:
        err = obj.get("error")
        # QGA error class is `{"error":{"class":"GenericError","desc":"..."}}`
        desc = ""
        if isinstance(err, dict):
            desc = str(err.get("desc") or err)
        else:
            desc = str(err)
        return {
            "ok": False,
            "error": f"server error: {desc}",
            "response": obj,
            "latency_ms": _latency(),
        }

    return {"ok": True, "response": obj, "latency_ms": _latency()}


def qga_sync(sock_path: str, *, timeout: float = 5.0,
             sync_id: Optional[int] = None) -> dict:
    """
    Issue a `guest-sync` request and verify the echoed id matches.

    Returns the same shape as `qga_request` plus a ``"id"`` field
    holding the id that was sent. On a successful sync the response
    object will have ``response["return"]`` equal to ``sync_id``.

    If `sync_id` is omitted, a fresh random 31-bit positive integer is
    generated so concurrent callers do not collide.
    """
    if sync_id is None:
        sync_id = random.randint(1, 0x7FFF_FFFF)
    req = {"execute": "guest-sync", "arguments": {"id": sync_id}}
    out = qga_request(sock_path, req, timeout=timeout)
    out["id"] = sync_id
    if out.get("ok") and isinstance(out.get("response"), dict):
        ret = out["response"].get("return")
        if ret != sync_id:
            out["ok"] = False
            out["error"] = f"sync id mismatch: sent {sync_id}, got {ret!r}"
    return out


def qga_ping(sock_path: str, *, timeout: float = 5.0) -> dict:
    """
    Issue a `guest-ping`. Returns the qga_request shape; on success
    `response["return"]` is the empty object `{}`.
    """
    return qga_request(sock_path, {"execute": "guest-ping"}, timeout=timeout)


def qga_info(sock_path: str, *, timeout: float = 5.0) -> dict:
    """Issue a `guest-info`. Returns the qga_request shape."""
    return qga_request(sock_path, {"execute": "guest-info"}, timeout=timeout)


def qga_file_open(sock_path: str, path: str, mode: str = "r",
                  *, timeout: float = 5.0) -> dict:
    """
    Issue a `guest-file-open`. On success `response["return"]` is the
    integer file handle the daemon allocated.
    """
    return qga_request(
        sock_path,
        {"execute": "guest-file-open",
         "arguments": {"path": path, "mode": mode}},
        timeout=timeout,
    )


def qga_file_read(sock_path: str, handle: int, count: int,
                  *, timeout: float = 5.0) -> dict:
    """
    Issue a `guest-file-read`. On success `response["return"]` is an
    object `{"count": N, "buf-b64": "<base64>"}`.
    """
    return qga_request(
        sock_path,
        {"execute": "guest-file-read",
         "arguments": {"handle": handle, "count": count}},
        timeout=timeout,
    )


def qga_file_close(sock_path: str, handle: int,
                   *, timeout: float = 5.0) -> dict:
    """Issue a `guest-file-close`. On success `response["return"]` is `{}`."""
    return qga_request(
        sock_path,
        {"execute": "guest-file-close", "arguments": {"handle": handle}},
        timeout=timeout,
    )


__all__ = [
    "qga_request",
    "qga_sync",
    "qga_ping",
    "qga_info",
    "qga_file_open",
    "qga_file_read",
    "qga_file_close",
]
