#!/usr/bin/env python3
"""
oracle-stub-conflux.py — Host-side stub Conflux endpoint for the Oracle
daemon-mode demo (PIVOT-I2 Phase D, 2026-05-23).
================================================================================

What this is
------------
A minimum-viable Conflux replacement that runs on the AstryxOS host machine,
binds to 127.0.0.1:<port>, speaks plain HTTP/1.1, and accepts JSON heartbeat
POSTs from a guest-side oracle.  Logs every received heartbeat to a structured
JSONL file and prints a one-line summary to stderr.  Exits cleanly on SIGINT
or SIGTERM and writes a summary line to stderr listing total heartbeats and
distinct hostnames seen.

This is the host counterpart of `kernel/src/oracle_demo.rs::run_oracle_daemon`.
Together they implement §7 of `docs/INFRASVC_ORACLE_AUDIT_2026-05-23.md`
("Minimum viable demo — defer I1 path"): swap WS+TLS for plain HTTP, prove
the substrate end-to-end, defer the full TLS substrate to I1.

Wire shape
----------
This release of oracle (infrasvc git 7b03aa65, the pinned tag in
`scripts/install-oracle.sh`) uses `infrasvc::sync::HttpSync` — NOT
WebSocket-over-TLS as the legacy audit described.  HttpSync sends:

    POST /heartbeat HTTP/1.1
    Host: <server-from-INFRASVC_SYNC_URL>
    Content-Type: application/json
    Content-Length: N

    {"hostname": ..., "agent_version": ..., "timestamp": ..., ...}

and expects 2xx for "accepted" or 4xx/5xx for "rejected".  See the symbols
`<infrasvc::sync::HttpSync as infrasvc::sync::SyncBackend>::send_heartbeat`
and the "Conflux rejected heartbeat: " / "Heartbeat sent for" log strings
shipping in the oracle binary.  We therefore implement the *minimum subset*:

  - `GET /healthz` → 200 OK `{"ok":true}` (smoke ping, optional)
  - `POST /heartbeat` → 200 OK `{"accepted":true,"protocol_version":2}`
  - Anything else → 404 Not Found

This is intentionally TLS-free (defers the I1 ca-certificates / OpenSSL soak)
and intentionally non-keep-alive (one request per connection — simplifies the
stub and matches reqwest's default for short-lived clients without breaking
oracle).

How it interacts with the harness
---------------------------------
The QEMU SLIRP gateway aliases `10.0.2.2` (guest-visible) ↔ `127.0.0.1` (host
loopback) — same alias used by the busybox-test wget probe and the tls-test
s_client demo.  When the guest oracle has `INFRASVC_SYNC_URL=http://10.0.2.2:<port>`
the POST routes through SLIRP NAT, hits this stub on host loopback, and the
heartbeat JSON appears in the stub's stdout + JSONL log.

The companion harness wrapper (`qemu-harness.py --oracle-stub-conflux PORT`
on `start`) launches this script in the background before QEMU boots and
sends SIGTERM after the QEMU session stops.  Both can also be driven by hand:

    # terminal 1 — start stub
    python3 scripts/oracle-stub-conflux.py --port 8088 --log /tmp/oracle.jsonl

    # terminal 2 — start guest with the URL env-var hint
    python3 scripts/qemu-harness.py start --features oracle-daemon-test ...

    # observe heartbeats in /tmp/oracle.jsonl and the stub stderr

References (public)
-------------------
  - RFC 9110 (HTTP semantics) — § 9.3.3 POST, § 15.3 2xx status codes.
  - RFC 9112 (HTTP/1.1 message syntax) — request/response framing.
  - QEMU SLIRP networking: https://www.qemu.org/docs/master/system/devices/net.html#network-options
  - Python http.server: https://docs.python.org/3/library/http.server.html
"""

import argparse
import json
import os
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional


HEARTBEATS_TOTAL = 0
HOSTNAMES_SEEN: set[str] = set()
LOG_FILE: Optional[str] = None
LOG_LOCK = threading.Lock()


def _stderr(msg: str) -> None:
    """Single-line stderr write; avoids interleaving when multiple threads
    accept simultaneously.  No trailing colon — keeps grep-friendly."""
    sys.stderr.write(msg.rstrip("\n") + "\n")
    sys.stderr.flush()


def _append_jsonl(record: dict) -> None:
    """Atomic append of one JSON object as a single line in the JSONL log."""
    if not LOG_FILE:
        return
    line = json.dumps(record, separators=(",", ":")) + "\n"
    with LOG_LOCK:
        with open(LOG_FILE, "a") as f:
            f.write(line)


class ConfluxStubHandler(BaseHTTPRequestHandler):
    """Threading HTTP handler for the stub Conflux endpoints.  Each request
    is independent; no shared state beyond the HEARTBEATS_TOTAL counter and
    HOSTNAMES_SEEN set (both guarded implicitly by the GIL — atomic ops here)."""

    # Silence the default per-request access log; we emit our own structured
    # one-liner.  Without this the stub spams stderr with one line per request
    # which dilutes the heartbeat-summary signal.
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _ok_json(self, body: dict, status: int = 200) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _not_found(self) -> None:
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "10")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"not found\n")

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        # Lightweight health probe.  Lets the harness validate the stub is
        # listening before launching QEMU (avoids racing oracle's first
        # heartbeat against stub bring-up).
        if self.path == "/healthz" or self.path == "/":
            self._ok_json({"ok": True, "service": "oracle-stub-conflux"})
            return
        self._not_found()

    def do_POST(self) -> None:  # noqa: N802
        global HEARTBEATS_TOTAL  # noqa: PLW0603

        if self.path != "/heartbeat":
            self._not_found()
            return

        # Per RFC 9110 § 8.6 Content-Length is REQUIRED when the body has
        # length; oracle's reqwest client always sets it.  If absent or
        # malformed we reject with 400 rather than block on read().
        cl_raw = self.headers.get("Content-Length", "")
        try:
            cl = int(cl_raw)
        except ValueError:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        if cl < 0 or cl > 4 * 1024 * 1024:
            # Sanity cap — a heartbeat that big means something's wrong on
            # the guest side; refuse to allocate.
            self.send_response(413)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return

        body = self.rfile.read(cl) if cl > 0 else b""

        # Parse defensively — even malformed JSON should still count as
        # "the guest oracle reached us" (the substrate worked).  Record
        # the parse failure in the JSONL log so we know oracle is alive
        # but its payload schema drifted.
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
            parse_ok = True
            hostname = (
                payload.get("hostname")
                or payload.get("instance_id")
                or payload.get("host_id")
                or "<unknown>"
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            parse_ok = False
            hostname = f"<parse-error: {type(e).__name__}>"
            payload = {"_raw_b64": body[:512].hex(), "_parse_error": str(e)}

        # Atomic increment + set add.  Python lists/sets/ints are GIL-safe
        # for single ops; no explicit lock needed.
        HEARTBEATS_TOTAL += 1
        HOSTNAMES_SEEN.add(hostname)
        seq = HEARTBEATS_TOTAL

        record = {
            "ts": time.time(),
            "seq": seq,
            "hostname": hostname,
            "client": f"{self.client_address[0]}:{self.client_address[1]}",
            "content_length": cl,
            "parse_ok": parse_ok,
            "payload": payload,
        }
        _append_jsonl(record)

        _stderr(
            f"[STUB-CONFLUX] heartbeat #{seq} hostname={hostname} "
            f"client={self.client_address[0]}:{self.client_address[1]} "
            f"bytes={cl} parse_ok={parse_ok}"
        )

        # Reply shape mirrors what reqwest's send_heartbeat happy-path
        # logic in `infrasvc::sync::HttpSync` accepts: 2xx + non-empty body
        # is enough to log "Heartbeat sent for <hostname>" on the guest.
        self._ok_json({"accepted": True, "protocol_version": 2, "seq": seq})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--port", type=int, default=8088,
        help="TCP port to bind on 127.0.0.1 (default 8088). "
             "Guest-side oracle should target http://10.0.2.2:<port>/heartbeat."
    )
    parser.add_argument(
        "--bind", default="127.0.0.1",
        help="Host address to bind to (default 127.0.0.1). "
             "Use 0.0.0.0 for non-loopback access (e.g. external smoke test)."
    )
    parser.add_argument(
        "--log", default=None,
        help="Path to a JSONL file where every received heartbeat is "
             "appended one-JSON-per-line.  Default: no file log (stderr only)."
    )
    parser.add_argument(
        "--ready-file", default=None,
        help="If set, the stub writes a single byte to this path after "
             "successfully binding the listening socket.  The QEMU harness "
             "polls this file to know the stub is ready before launching guest."
    )
    parser.add_argument(
        "--max-runtime-sec", type=int, default=0,
        help="If > 0, exit cleanly after this many seconds of uptime.  "
             "0 = run until SIGINT/SIGTERM.  Useful as a soak deadline."
    )
    args = parser.parse_args()

    global LOG_FILE  # noqa: PLW0603
    LOG_FILE = args.log
    if LOG_FILE:
        # Truncate any previous log so each test run starts clean; the
        # JSONL nature means appending across runs is technically valid
        # but operator-confusing.
        with open(LOG_FILE, "w") as _f:
            pass
        _stderr(f"[STUB-CONFLUX] heartbeat log: {LOG_FILE}")

    # Build the server *before* the ready-file write so any bind error
    # (EADDRINUSE most commonly) surfaces before downstream waiters see
    # a green light.
    try:
        server = ThreadingHTTPServer((args.bind, args.port), ConfluxStubHandler)
    except OSError as e:
        _stderr(f"[STUB-CONFLUX] FATAL: bind({args.bind}:{args.port}) failed: {e}")
        return 2

    _stderr(
        f"[STUB-CONFLUX] listening on http://{args.bind}:{args.port}/ "
        f"(POST /heartbeat, GET /healthz)"
    )

    if args.ready_file:
        try:
            with open(args.ready_file, "w") as f:
                f.write("ready\n")
            _stderr(f"[STUB-CONFLUX] wrote ready-file: {args.ready_file}")
        except OSError as e:
            _stderr(f"[STUB-CONFLUX] WARN: ready-file write failed: {e}")

    # Stop flag + shutdown coordination.  Using a threading.Event keeps the
    # signal handler trivial (Event.set is async-signal-safe in CPython
    # because of the GIL) and lets the deadline thread share the same exit
    # path.
    stop_evt = threading.Event()

    def _shutdown(*_args):
        if stop_evt.is_set():
            return
        stop_evt.set()
        # ThreadingHTTPServer.shutdown() blocks until serve_forever returns,
        # so call it from a worker thread to keep the signal handler short.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if args.max_runtime_sec > 0:
        def _deadline():
            stop_evt.wait(args.max_runtime_sec)
            if not stop_evt.is_set():
                _stderr(
                    f"[STUB-CONFLUX] max-runtime-sec={args.max_runtime_sec} "
                    f"reached; shutting down"
                )
                _shutdown()
        threading.Thread(target=_deadline, daemon=True).start()

    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        _stderr(
            f"[STUB-CONFLUX] === SUMMARY === heartbeats_total={HEARTBEATS_TOTAL} "
            f"distinct_hostnames={len(HOSTNAMES_SEEN)} "
            f"hostnames={sorted(HOSTNAMES_SEEN)}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
