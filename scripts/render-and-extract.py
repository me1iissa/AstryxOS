#!/usr/bin/env python3
"""
render-and-extract — drive one headless-Firefox render and pull the PNG out fast.

A thin, non-interactive orchestrator over ``scripts/qemu-harness.py``: it starts
a firefox-test render, waits for the kernel's one-line
``[FF-OUT-PNG:path=… size=… sig_ok=… complete=…]`` summary marker, then extracts
the rendered ``/tmp/out.png`` to the host — preferring the live VFS read
(``kdb-read-png``), which is NOT baud-bound, and falling back to the serial
byte-stream decoder (``read-ff-png``) only when the slow opt-in
``ff-png-serial-emit`` build streamed the bytes.

Why kdb-first
-------------
The render profile (``firefox-test-core,kdb``) does NOT stream the PNG over
serial by default (the kernel ``ff-png-serial-emit`` feature is off). It emits
only the one-line summary marker and leaves the bytes in the guest VFS ramdisk.
``kdb-read-png`` reads them live in seconds; the old ``read-ff-png`` serial path
had to drain ~36 800 base64 lines over COM1 (~8 min for a 2 MB PNG) and starved
the kdb pump while it ran. kdb-first makes a 2 MB extraction <60 s instead.

Agent-friendly contract (project invariant)
-------------------------------------------
One-shot argv invocation, structured JSON on stdout, no REPL/prompt. Every QEMU
step goes through ``scripts/qemu-harness.py`` — this script never shells out to a
banned wrapper. It is safe to drive from claude-code, a human shell, or CI.

Examples
--------
    # Full render + fast extract (default: starts a fresh session, stops it).
    python3 scripts/render-and-extract.py \\
        --url https://en.wikipedia.org/wiki/Firefox \\
        --features firefox-test-core,kdb --smp 4 \\
        --out /tmp/out.png

    # Extract only, against an already-running session (no start/stop).
    python3 scripts/render-and-extract.py --sid <sid> --extract-only \\
        --out /tmp/out.png

JSON output (additive — fields are only ever added, never renamed)::

    {
      "ok": true,
      "sid": "<sid>",
      "url": "...",
      "marker": {"size": 2097152, "sig_ok": true, "complete": true},
      "extract": {"method": "kdb-read-png", "bytes": 2097152, "is_png": true,
                  "size_match": true, "wall_ms": 4210, "fallback_used": false},
      "out": "/abs/path/out.png",
      "render_wait_ms": 281000,
      "stopped": true
    }

Public refs: W3C/ISO 15948 PNG signature (89 50 4E 47 0D 0A 1A 0A); base64
RFC 4648 §4.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE / "qemu-harness.py"

# The kernel summary marker (kernel/src/ff_out_png.rs). complete= was added when
# the byte stream was gated off; sig_ok/size are the historical fields. We grep
# for the path token so a partial early probe line still matches.
_MARKER_RE = r"\[FF-OUT-PNG:path=/tmp/out\.png "


def _run_harness(args, timeout=None):
    """
    Run `qemu-harness.py <args...>` and return (rc, parsed_json_or_None, raw).
    The harness prints a single JSON object on stdout for the subcommands this
    script uses; we parse the last JSON-looking line defensively.
    """
    cmd = [sys.executable, str(HARNESS)] + list(args)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return (124, None, f"timeout after {timeout}s running: {' '.join(args)}")
    raw = (proc.stdout or "") + (proc.stderr or "")
    obj = None
    # Scan from the end for the last line that parses as a JSON object.
    for line in reversed((proc.stdout or "").splitlines()):
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
            break
        except (json.JSONDecodeError, ValueError):
            continue
    return (proc.returncode, obj, raw)


def _err(payload, code=1):
    print(json.dumps(payload))
    sys.exit(code)


def _parse_marker(grep_obj):
    """
    Pull size / sig_ok / complete out of the matched [FF-OUT-PNG:…] line(s).
    The harness `grep` returns matched serial lines; we parse the LAST one (the
    final, complete-state report) for the size/sig_ok/complete tokens.
    """
    import re
    lines = []
    if isinstance(grep_obj, dict):
        lines = grep_obj.get("matches") or grep_obj.get("lines") or []
    if isinstance(grep_obj, list):
        lines = grep_obj
    last = None
    for ln in lines:
        if isinstance(ln, dict):
            ln = ln.get("line") or ln.get("text") or ""
        if "[FF-OUT-PNG:path=" in ln:
            last = ln
    if last is None:
        return None
    m = {}
    sz = re.search(r"size=(\d+)", last)
    sg = re.search(r"sig_ok=(true|false)", last)
    cp = re.search(r"complete=(true|false)", last)
    if sz:
        m["size"] = int(sz.group(1))
    if sg:
        m["sig_ok"] = (sg.group(1) == "true")
    if cp:
        m["complete"] = (cp.group(1) == "true")
    m["raw"] = last.strip()
    return m


def _extract(sid, out_path, prefer_serial, timeout_ms):
    """
    Extract /tmp/out.png. kdb-read-png first (fast, live VFS), read-ff-png as
    fallback. When prefer_serial=True (caller knows the slow byte stream was
    enabled) the order is reversed. Returns the extract-result dict.
    """
    kdb_first = not prefer_serial

    def try_kdb():
        t0 = time.monotonic()
        rc, obj, raw = _run_harness(
            ["kdb-read-png", sid, str(out_path), "--timeout-ms", str(timeout_ms)],
            timeout=(timeout_ms / 1000.0) + 30.0,
        )
        wall_ms = int((time.monotonic() - t0) * 1000)
        if obj and obj.get("ok"):
            return {"method": "kdb-read-png", "wall_ms": wall_ms,
                    "bytes": obj.get("bytes"), "is_png": obj.get("is_png"),
                    "size_match": obj.get("size_match"),
                    "guest_size": obj.get("guest_size")}
        return {"method": "kdb-read-png", "wall_ms": wall_ms, "ok": False,
                "error": (obj or {}).get("error") if obj else raw[:300]}

    def try_serial():
        t0 = time.monotonic()
        rc, obj, raw = _run_harness(
            ["read-ff-png", sid, str(out_path), "--timeout-ms", str(timeout_ms)],
            timeout=(timeout_ms / 1000.0) + 30.0,
        )
        wall_ms = int((time.monotonic() - t0) * 1000)
        if obj and obj.get("ok"):
            return {"method": "read-ff-png", "wall_ms": wall_ms,
                    "bytes": obj.get("bytes"), "is_png": True,
                    "size_match": obj.get("size_match"),
                    "chunks": obj.get("chunks")}
        return {"method": "read-ff-png", "wall_ms": wall_ms, "ok": False,
                "error": (obj or {}).get("error") if obj else raw[:300]}

    order = [try_kdb, try_serial] if kdb_first else [try_serial, try_kdb]
    first = order[0]()
    if first.get("is_png") and first.get("size_match"):
        first["ok"] = True
        first["fallback_used"] = False
        return first
    # First method failed/partial — fall back to the other.
    second = order[1]()
    second["fallback_used"] = True
    second["primary_failure"] = {"method": first.get("method"),
                                 "error": first.get("error")}
    second["ok"] = bool(second.get("is_png") and second.get("size_match"))
    return second


def main():
    ap = argparse.ArgumentParser(
        description="Render headless Firefox and extract /tmp/out.png fast "
                    "(kdb-first, serial fallback). All QEMU steps go through "
                    "scripts/qemu-harness.py.")
    ap.add_argument("--url", help="Page to render (passed to start --ff-url).")
    ap.add_argument("--out", default="/tmp/out.png",
                    help="Host destination path for the extracted PNG.")
    ap.add_argument("--features", default="firefox-test-core,kdb",
                    help="Kernel feature flags (must include 'kdb' for the "
                         "fast live read). Default: firefox-test-core,kdb.")
    ap.add_argument("--smp", type=int, default=4, help="vCPU count for start.")
    ap.add_argument("--no-build", action="store_true",
                    help="Reuse the existing kernel.bin (skip cargo build).")
    ap.add_argument("--sid", help="Attach to an existing session instead of "
                                  "starting a new one.")
    ap.add_argument("--extract-only", action="store_true",
                    help="Skip start/render-wait; just extract from --sid.")
    ap.add_argument("--render-timeout-ms", type=int, default=600000,
                    help="Max ms to wait for the [FF-OUT-PNG:…] marker.")
    ap.add_argument("--extract-timeout-ms", type=int, default=60000,
                    help="Per-method extraction timeout (ms).")
    ap.add_argument("--keep", action="store_true",
                    help="Do not stop the session this script started.")
    ap.add_argument("--prefer-serial", action="store_true",
                    help="Try read-ff-png before kdb-read-png (only useful for "
                         "an ff-png-serial-emit build with no kdb channel).")
    args = ap.parse_args()

    result = {"ok": False, "url": args.url, "out": None}
    started_here = False
    sid = args.sid

    # ── start (unless attaching) ──────────────────────────────────────────────
    if not args.extract_only:
        if sid is None:
            if "kdb" not in args.features.split(",") and not args.prefer_serial:
                _err({"ok": False,
                      "error": "features must include 'kdb' for the fast live "
                               "read; pass --prefer-serial for a serial-only "
                               "build", "features": args.features})
            start_argv = ["start", "--features", args.features,
                          "--smp", str(args.smp)]
            if args.no_build:
                start_argv.append("--no-build")
            if args.url:
                start_argv += ["--ff-url", args.url]
            rc, obj, raw = _run_harness(start_argv, timeout=1200)
            if not obj or not obj.get("sid"):
                _err({"ok": False, "error": "start failed",
                      "rc": rc, "raw": raw[-600:]})
            sid = obj["sid"]
            started_here = True
        result["sid"] = sid

        # ── wait for the one-line summary marker ──────────────────────────────
        t0 = time.monotonic()
        rc, obj, raw = _run_harness(
            ["wait", sid, _MARKER_RE, "--ms", str(args.render_timeout_ms)],
            timeout=(args.render_timeout_ms / 1000.0) + 60.0,
        )
        result["render_wait_ms"] = int((time.monotonic() - t0) * 1000)
        marker_hit = bool(obj and (obj.get("matched") or obj.get("found")
                                   or obj.get("ok")))
        if not marker_hit:
            _maybe_stop(sid, started_here and not args.keep, result)
            _err({**result, "ok": False,
                  "error": "render did not produce the [FF-OUT-PNG:…] marker "
                           "before --render-timeout-ms", "raw": raw[-400:]})

    result["sid"] = sid

    # ── read back the final marker state (size / sig_ok / complete) ───────────
    rc, gobj, raw = _run_harness(["grep", sid, _MARKER_RE, "--tail", "4"],
                                 timeout=30)
    marker = _parse_marker(gobj)
    result["marker"] = marker
    if marker and marker.get("complete") is False:
        # File present but not a complete PNG — surface it but still try extract
        # (kdb read will report size_match=false, caller decides).
        result["warning"] = "marker reports complete=false (PNG may be mid-write)"

    # ── extract ───────────────────────────────────────────────────────────────
    ext = _extract(sid, Path(args.out), args.prefer_serial, args.extract_timeout_ms)
    result["extract"] = ext
    result["out"] = str(Path(args.out).resolve()) if ext.get("ok") else None
    result["ok"] = bool(ext.get("ok"))

    # ── stop the session we started ──────────────────────────────────────────
    _maybe_stop(sid, started_here and not args.keep, result)

    print(json.dumps(result))
    sys.exit(0 if result["ok"] else 2)


def _maybe_stop(sid, do_stop, result):
    if not do_stop:
        result["stopped"] = False
        return
    rc, obj, raw = _run_harness(["stop", sid], timeout=60)
    result["stopped"] = (rc == 0)


if __name__ == "__main__":
    main()
