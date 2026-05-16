#!/usr/bin/env python3
"""
test_kdb_recv_retry.py — Unit test for `_kdb_recv` retry/backoff behaviour.

Verifies that the harness-side kdb client recovers from transient TCP
failures within the overall deadline (the failure mode that previously
made `kdb counters` time out during heavy guest CPU load).

Scenarios:
  1. Connection refused for the first ~500 ms, then a server appears
     and serves one request — must succeed.
  2. Server accepts but closes the connection without writing a newline
     for the first attempt; then on retry serves a full response.
  3. Deadline exceeded — never serves a response; harness must raise
     within the deadline (with at most 1 attempt's slack).

Not wired into qemu-harness-smoke.py because it doesn't need a kernel boot.
Run directly:

    python3 scripts/test_kdb_recv_retry.py
"""
import importlib.util
import json
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qemu_harness",
                                              HERE / "qemu-harness.py")
qh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qh)

PASS = "PASS"
FAIL = "FAIL"
failures: list[str] = []


def _check(name: str, cond: bool, detail: str = ""):
    tag = PASS if cond else FAIL
    print(f"[{tag}] {name}" + (f"  ({detail})" if detail else ""))
    if not cond:
        failures.append(name)


def _bind_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve_one(port: int, response: bytes,
               start_delay: float = 0.0,
               half_close: bool = False) -> threading.Thread:
    """Listen on `port`, accept one connection, optionally write `response`,
    then close.  If `half_close`, close without writing a newline."""
    def run():
        time.sleep(start_delay)
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", port))
        ls.listen(1)
        ls.settimeout(10.0)
        try:
            c, _ = ls.accept()
            try:
                # Drain the request line.
                buf = b""
                c.settimeout(2.0)
                while not buf.endswith(b"\n"):
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                if not half_close:
                    c.sendall(response)
            finally:
                c.close()
        finally:
            ls.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def test_retry_through_connection_refused():
    port = _bind_free_port()
    t = _serve_one(port, b'{"ok":true}\n', start_delay=0.6)
    t0 = time.monotonic()
    try:
        raw = qh._kdb_recv(port, {"op": "ping"}, timeout=5.0)
        dt = time.monotonic() - t0
        try:
            obj = json.loads(raw.decode())
        except Exception:
            obj = None
        _check("retry survives 0.6s ConnectionRefused",
               obj == {"ok": True} and dt < 4.0,
               f"dt={dt:.2f}s, obj={obj}")
    except Exception as e:
        dt = time.monotonic() - t0
        _check("retry survives 0.6s ConnectionRefused", False,
               f"raised {type(e).__name__}: {e} after {dt:.2f}s")
    t.join(timeout=5.0)


def test_retry_through_half_close():
    """First attempt: peer closes without newline.  Then a second listener
    serves the full response."""
    port = _bind_free_port()
    # Server #1: half-close immediately.
    t1 = _serve_one(port, b'', start_delay=0.0, half_close=True)
    # Server #2: real response, after #1 finishes.
    t2 = _serve_one(port, b'{"retry":true}\n', start_delay=0.8)
    t0 = time.monotonic()
    try:
        raw = qh._kdb_recv(port, {"op": "ping"}, timeout=5.0)
        dt = time.monotonic() - t0
        try:
            obj = json.loads(raw.decode())
        except Exception:
            obj = None
        _check("retry survives half-close",
               obj == {"retry": True} and dt < 4.0,
               f"dt={dt:.2f}s, obj={obj}")
    except Exception as e:
        dt = time.monotonic() - t0
        _check("retry survives half-close", False,
               f"raised {type(e).__name__}: {e} after {dt:.2f}s")
    t1.join(timeout=2.0)
    t2.join(timeout=5.0)


def test_deadline_exceeded():
    port = _bind_free_port()
    # No server.  Deadline ~1.5s; expect failure within ~2.5s wall.
    t0 = time.monotonic()
    raised = False
    try:
        qh._kdb_recv(port, {"op": "ping"}, timeout=1.5)
    except (socket.timeout, ConnectionRefusedError,
            ConnectionResetError, OSError):
        raised = True
    dt = time.monotonic() - t0
    _check("deadline exceeded raises within ~2× deadline",
           raised and dt < 4.0,
           f"raised={raised}, dt={dt:.2f}s")


def test_fast_path_no_wasted_time():
    """Confirm the new retry wrapper doesn't add latency to the happy path."""
    port = _bind_free_port()
    t = _serve_one(port, b'{"fast":true}\n', start_delay=0.0)
    t0 = time.monotonic()
    raw = qh._kdb_recv(port, {"op": "ping"}, timeout=5.0)
    dt = time.monotonic() - t0
    obj = json.loads(raw.decode())
    _check("happy path no added latency",
           obj == {"fast": True} and dt < 0.5,
           f"dt={dt:.3f}s, obj={obj}")
    t.join(timeout=2.0)


def main():
    print("== _kdb_recv retry/backoff unit tests ==")
    test_fast_path_no_wasted_time()
    test_retry_through_connection_refused()
    test_retry_through_half_close()
    test_deadline_exceeded()
    if failures:
        print(f"\n{len(failures)} FAILED: {failures}")
        sys.exit(1)
    print("\nAll passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
