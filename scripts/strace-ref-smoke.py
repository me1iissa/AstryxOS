#!/usr/bin/env python3
"""
strace-ref-smoke.py — Host-side smoke test for strace-ref.py

Exercises the strace-ref subcommands end-to-end:
  - setup     (verify Alpine rootfs detection)
  - capture   (firefox-esr --version under bwrap+strace)
  - list      (capture appears in listing)
  - diff      (against the capture itself, comparing self-vs-self)
  - clean     (cleanup the smoke capture)

Run directly (does not interact with QEMU or a kernel build):

    python3 scripts/strace-ref-smoke.py

Exit codes:
    0  — all checks passed
    1  — one or more checks failed
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parent / "strace-ref.py"
PY = sys.executable

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"


def run(args: list[str]) -> tuple[int, dict[str, Any], str]:
    """Run strace-ref.py with args; return (rc, parsed-json-or-{}, raw)."""
    res = subprocess.run(
        [PY, str(SCRIPT)] + args,
        capture_output=True, text=True, timeout=120,
    )
    raw = res.stdout
    try:
        data = json.loads(raw)
    except Exception:
        data = {}
    return res.returncode, data, raw


def check(label: str, ok: bool, detail: str = "") -> bool:
    tag = PASS if ok else FAIL
    line = f"  {tag}  {label}"
    if detail:
        line += f"  ({detail})"
    print(line)
    return ok


def main() -> int:
    failures = 0
    print(f"{INFO}  strace-ref smoke — using {SCRIPT}")

    # 1. setup
    rc, data, raw = run(["setup"])
    if not check("setup returns ok=true", rc == 0 and data.get("ok")):
        print(f"    raw: {raw[:400]}")
        failures += 1
    if not check("setup reports musl rootfs", data.get("is_musl") is True,
                 detail=f"rootfs={data.get('rootfs')!r}"):
        failures += 1
    if not check("setup reports firefox version 115.x",
                 (data.get("firefox_version") or "").startswith("115."),
                 detail=f"version={data.get('firefox_version')!r}"):
        failures += 1

    # 2. capture (smoke: --version)
    rc, data, raw = run([
        "capture",
        "--label", "smoke-test",
        "--binary-args=--version",
        "--timeout", "30",
    ])
    if not check("capture returns ok=true", rc == 0 and data.get("ok")):
        print(f"    raw: {raw[:400]}")
        failures += 1
    trace_path = data.get("trace_path")
    stats = data.get("stats", {})
    if not check("capture produced a non-empty trace",
                 stats.get("size_bytes", 0) > 0,
                 detail=f"size={stats.get('size_bytes')}"):
        failures += 1
    if not check("capture matched at least one FUTEX entry",
                 sum(stats.get("by_op", {}).values()) >= 1,
                 detail=f"by_op={stats.get('by_op')}"):
        failures += 1

    # 3. list (smoke capture must appear)
    rc, data, raw = run(["list"])
    labels = [c.get("label") for c in data.get("captures", [])]
    if not check("list shows the smoke capture",
                 "smoke-test" in labels,
                 detail=f"labels={labels}"):
        failures += 1

    # 4. diff (linux trace vs itself — sanity, ratios should be 1.0)
    if trace_path:
        rc, data, raw = run([
            "diff",
            "--linux-trace", trace_path,
            "--astryx-log", trace_path,   # NOT a real astryx log; tests
                                          # the diff path doesn't crash
        ])
        # The astryx parser will find 0 [FUTEX_*] tags in a strace trace,
        # so astryx.stats.matched should be 0; this is the expected shape.
        if not check("diff runs without error", rc == 0 and data.get("ok"),
                     detail=f"keys={list(data.keys())}"):
            print(f"    raw: {raw[:400]}")
            failures += 1
        astryx_matched = data.get("astryx", {}).get("stats", {}).get("matched", -1)
        if not check("diff astryx.matched == 0 for non-astryx input",
                     astryx_matched == 0,
                     detail=f"matched={astryx_matched}"):
            failures += 1

    # 5. clean
    rc, data, raw = run(["clean", "--label", "smoke-test"])
    if not check("clean returns ok=true", rc == 0 and data.get("ok")):
        failures += 1
    removed = data.get("removed", [])
    if not check("clean removed >=1 file",
                 len(removed) >= 1,
                 detail=f"removed={removed}"):
        failures += 1

    print()
    if failures:
        print(f"{FAIL}  {failures} check(s) failed")
        return 1
    print(f"{PASS}  all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
