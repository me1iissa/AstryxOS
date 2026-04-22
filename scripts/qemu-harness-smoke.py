#!/usr/bin/env python3
"""
qemu-harness-smoke.py — Host-side smoke test for qemu-harness.py

Exercises all Tier 1 and Tier 3 subcommands against a real kernel boot.
Not part of the kernel test suite (test_runner.rs) — run directly:

    python3 scripts/qemu-harness-smoke.py

Exit codes:
    0  — all checks passed
    1  — one or more checks failed
"""

import json
import subprocess
import sys
import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "qemu-harness.py"
PYTHON  = sys.executable

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"

failures = []


def _h(*args_extra):
    """Run a harness subcommand, return (parsed_json, raw_stdout, returncode)."""
    cmd = [PYTHON, str(HARNESS)] + list(args_extra)
    r = subprocess.run(cmd, capture_output=True, text=True)
    raw = r.stdout.strip()
    try:
        obj = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        obj = None
    return obj, raw, r.returncode


def check(name: str, cond: bool, detail: str = ""):
    tag = PASS if cond else FAIL
    extra = f"  ({detail})" if detail else ""
    print(f"  [{tag}] {name}{extra}")
    if not cond:
        failures.append(name)


def main():
    print(f"[{INFO}] AstryxOS qemu-harness smoke test")
    print(f"[{INFO}] Harness: {HARNESS}")
    print()

    # ── Step 1: start ─────────────────────────────────────────────────────────
    print("Step 1: start (build + launch QEMU)")
    obj, raw, rc = _h("start")
    check("start returns JSON",       obj is not None,           raw[:120])
    check("start.sid present",        bool(obj and obj.get("sid")), str(obj))
    check("start.pid > 0",            bool(obj and obj.get("pid", 0) > 0), str(obj))
    check("start returncode 0",       rc == 0,                   f"rc={rc}")

    if not obj or not obj.get("sid"):
        print(f"\n[{FAIL}] Cannot proceed without a valid sid — aborting.")
        sys.exit(1)

    sid = obj["sid"]
    print(f"  [INFO] sid={sid}  pid={obj['pid']}")
    print()

    # ── Step 2: wait for boot message ────────────────────────────────────────
    print("Step 2: wait for 'kernel initialization complete' (60 s)")
    # The AstryxOS boot prints various phase markers; "Phase" appears early.
    # We also accept the test-runner start banner as proof of life.
    obj2, raw2, rc2 = _h("wait", sid,
                          r"(kernel initialization complete|Phase \d|AstryxOS|PASS|FAIL)",
                          "--ms", "60000")
    check("wait returns JSON",   obj2 is not None,               raw2[:120])
    check("wait.matched=true",   bool(obj2 and obj2.get("matched")), str(obj2))
    if obj2 and obj2.get("matched"):
        print(f"  [INFO] Matched at line {obj2.get('line_no')}: {obj2.get('line','')[:80]}")
    print()

    # ── Step 3: tail ──────────────────────────────────────────────────────────
    print("Step 3: tail --bytes 2000")
    obj3, raw3, rc3 = _h("tail", sid, "--bytes", "2000")
    check("tail returns JSON",      obj3 is not None,            raw3[:120])
    check("tail.lines is list",     isinstance(obj3.get("lines") if obj3 else None, list))
    check("tail has content",       bool(obj3 and len(obj3.get("lines", [])) > 0),
          f"lines={len(obj3.get('lines', [])) if obj3 else 0}")
    print()

    # ── Step 4: status ────────────────────────────────────────────────────────
    print("Step 4: status")
    obj4, raw4, rc4 = _h("status", sid)
    check("status returns JSON",    obj4 is not None,            raw4[:120])
    check("status.running=true",    bool(obj4 and obj4.get("running")), str(obj4))
    check("status.pid > 0",         bool(obj4 and obj4.get("pid", 0) > 0))
    check("status.uptime_s > 0",    bool(obj4 and obj4.get("uptime_s", 0) > 0))
    print()

    # ── Step 5: grep ──────────────────────────────────────────────────────────
    print("Step 5: grep 'Phase' --tail 10")
    # Wait a little longer so more boot output is available
    _h("wait", sid, r"Phase [0-9]", "--ms", "30000")
    obj5, raw5, rc5 = _h("grep", sid, r"Phase [0-9]", "--tail", "10")
    check("grep returns JSON list",  isinstance(obj5, list),     raw5[:120])
    # Phase markers appear in test-mode boot; tolerate absence in edge cases
    has_phase = isinstance(obj5, list) and len(obj5) > 0
    check("grep has Phase lines",    has_phase,
          f"count={len(obj5) if isinstance(obj5, list) else 0}")
    print()

    # ── Step 6: events ───────────────────────────────────────────────────────
    print("Step 6: events (may be empty, that is fine)")
    obj6, raw6, rc6 = _h("events", sid)
    check("events returns JSON list", isinstance(obj6, list),    raw6[:120])
    print(f"  [INFO] {len(obj6) if isinstance(obj6, list) else '?'} events recorded")
    print()

    # ── Step 7: stop ─────────────────────────────────────────────────────────
    print("Step 7: stop")
    obj7, raw7, rc7 = _h("stop", sid)
    check("stop returns JSON",  obj7 is not None,                raw7[:120])
    check("stop.ok=true",       bool(obj7 and obj7.get("ok")),   str(obj7))
    check("stop returncode 0",  rc7 == 0,                        f"rc={rc7}")
    print()

    # ── Step 8: list ─────────────────────────────────────────────────────────
    print("Step 8: list (sid should be absent)")
    # Allow a moment for process cleanup
    time.sleep(0.5)
    obj8, raw8, rc8 = _h("list")
    check("list returns JSON array",  isinstance(obj8, list),    raw8[:120])
    sid_present = any(s.get("sid") == sid for s in (obj8 or []))
    check("sid absent from list",     not sid_present,
          f"sessions={[s.get('sid') for s in (obj8 or [])]}")
    print()

    # ── Stop idempotency ──────────────────────────────────────────────────────
    print("Bonus: stop idempotency (stop already-stopped session)")
    obj9, raw9, rc9 = _h("stop", sid)
    check("second stop returns ok",   bool(obj9 and obj9.get("ok")), str(obj9))
    print()

    # ── Summary ───────────────────────────────────────────────────────────────
    total  = 0
    passed = 0
    # Count by scanning failures list vs total checks emitted
    # (we track failures explicitly)
    n_fail = len(failures)

    if n_fail == 0:
        print(f"\033[32m\nAll smoke-test checks passed.\033[0m")
        sys.exit(0)
    else:
        print(f"\033[31m\n{n_fail} check(s) FAILED:\033[0m")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
