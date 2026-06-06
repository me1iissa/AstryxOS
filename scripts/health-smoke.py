#!/usr/bin/env python3
"""
health-smoke.py — fast, boot-free smoke test for the `health` subcommand.

The `health` classifier is the coordinator's circle/spin/stall detector: it is
run every turn, so a regression in it cascades into every dispatch (it could
silently reap a healthy boot, or fail to reap a wedged one).  This smoke test
locks the classification down with two layers:

  1. Pure-function tests of `_health_classify` over fixture sample-pairs that
     reproduce every verdict class (HEALTHY, SLOW-ALIVE, SPINNING, STALLED,
     WEDGED-PRE-BUGCHECK, DEAD/BUGCHECKED) — including the load-bearing
     "firehose-throttled boot must read SLOW-ALIVE, never STALLED/SPINNING"
     invariant.

  2. End-to-end argv tests of `health <sid>` and `health --all
     --reap-circles` against synthetic serial logs written into a throwaway
     ASTRYX_HARNESS_DIR — proving the structured-JSON contract, that the
     declared fields are all present, and that --reap-circles stops + LOGS
     (never silently) exactly the circle classes.

No QEMU, no kernel build — runs in well under a second.  Suitable for CI.

    python3 scripts/health-smoke.py

Exit codes: 0 all passed, 1 one or more failed.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "qemu-harness.py"
PYTHON = sys.executable

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

failures = []


def check(name, cond, detail=""):
    tag = PASS if cond else FAIL
    extra = f"  ({detail})" if detail else ""
    print(f"  [{tag}] {name}{extra}")
    if not cond:
        failures.append(name)


# ── Layer 1: pure-function classifier tests ───────────────────────────────────
#
# We import the harness module directly to reach _health_classify.  The harness
# has no top-level side effects beyond creating HARNESS_DIR, so importing it is
# safe; point it at a temp dir first so we don't touch the real session store.

def _load_harness_module(tmp_harness_dir):
    os.environ["ASTRYX_HARNESS_DIR"] = str(tmp_harness_dir)
    import importlib.util
    spec = importlib.util.spec_from_file_location("qemu_harness_mod", str(HARNESS))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sample(tick, sc_sum, gate_ordinal, deepest_gate, stuck=0, stuck_nr=None,
            proc_sc=None):
    return {
        "latest_tick": tick,
        "proc_sc": proc_sc or {},
        "sc_sum": sc_sum,
        "deepest_gate": deepest_gate,
        "gate_ordinal": gate_ordinal,
        "max_stuck_ticks": stuck,
        "stuck_nr": stuck_nr,
    }


def run_classifier_tests(mod):
    print("Layer 1: pure _health_classify decision logic")
    cl = mod._health_classify
    DT = 4.0  # the default sample gap

    # HEALTHY: gate advanced between samples.
    s0 = _sample(1000, 5000, 3, "content-procs")
    s1 = _sample(1400, 5800, 4, "screenshot-actors")
    v, _ = cl(s0, s1, {"cpu_pct": 99.0}, DT, "[SC]", 20.0, False, False, False, True)
    check("gate advance -> HEALTHY", v == "HEALTHY", v)

    # HEALTHY: fresh kdb autopsy artefact, even if momentarily frozen.
    s0 = _sample(1000, 5000, 3, "content-procs")
    s1 = _sample(1000, 5000, 3, "content-procs")
    v, _ = cl(s0, s1, {"cpu_pct": 99.0}, DT, "[FUTEX_TIMEDOUT]", 90.0, True,
              True, False, True)
    check("fresh kdb autopsy -> HEALTHY (not reaped)", v == "HEALTHY", v)

    # SPINNING: sc rockets, no gate advance.
    s0 = _sample(1000, 5000, 3, "content-procs")
    s1 = _sample(1010, 5000 + int(6000 * DT), 3, "content-procs")  # ~6000 sc/s
    v, _ = cl(s0, s1, {"cpu_pct": 99.0}, DT, "[SC]", 30.0, False, False, False, True)
    check("fast sc + no gate -> SPINNING", v == "SPINNING", v)

    # SPINNING: single tag dominates the tail at high CPU.
    s0 = _sample(1000, 5000, 3, "content-procs")
    s1 = _sample(1010, 5005, 3, "content-procs")  # sc barely moves
    v, _ = cl(s0, s1, {"cpu_pct": 99.0}, DT, "[FUTEX_WAKE]", 85.0, False, False,
              False, True)
    check("dominant tag @ high CPU -> SPINNING", v == "SPINNING", v)

    # STALLED: sc frozen + gate frozen at meaningful CPU + futex churn (the
    # content-handshake wedge — exactly the ea3da73280e2 fingerprint).
    s0 = _sample(118000, 96000, 5, "content-procs", stuck=40000, stuck_nr=7)
    s1 = _sample(119000, 96000, 5, "content-procs", stuck=40500, stuck_nr=7)
    v, r = cl(s0, s1, {"cpu_pct": 80.0}, DT, "[FUTEX_TIMEDOUT]", 60.0, True,
              False, False, True)
    check("frozen sc + futex churn -> STALLED", v == "STALLED", v)
    check("STALLED reason names futex churn", "FUTEX" in r or "churn" in r, r)

    # WEDGED-PRE-BUGCHECK: a thread stuck in one syscall near the 60k watchdog.
    s0 = _sample(118000, 59786, 5, "content-procs", stuck=55000, stuck_nr=7)
    s1 = _sample(119000, 59786, 5, "content-procs", stuck=55769, stuck_nr=7)
    v, _ = cl(s0, s1, {"cpu_pct": 80.0}, DT, "[FUTEX_TIMEDOUT]", 50.0, True,
              False, False, True)
    check("stuck ~55k ticks -> WEDGED-PRE-BUGCHECK", v == "WEDGED-PRE-BUGCHECK", v)

    # DEAD/BUGCHECKED: process gone.
    s0 = _sample(1000, 5000, 3, "content-procs")
    v, _ = cl(s0, s0, {}, DT, None, 0.0, False, False, False, False)
    check("process gone -> DEAD/BUGCHECKED", v == "DEAD/BUGCHECKED", v)

    # DEAD/BUGCHECKED: bugcheck marker in serial even though pid still alive.
    v, _ = cl(s0, s0, {"cpu_pct": 5.0}, DT, None, 0.0, False, False, True, True)
    check("bugcheck marker -> DEAD/BUGCHECKED", v == "DEAD/BUGCHECKED", v)

    # SLOW-ALIVE: the load-bearing invariant — a firehose-throttled boot whose
    # sc is creeping up (below the spin rate) with no gate advance must NOT read
    # STALLED or SPINNING.  Here sc advances ~50/s at high CPU.
    s0 = _sample(118000, 60000, 5, "content-procs")
    s1 = _sample(118500, 60000 + int(50 * DT), 5, "content-procs")  # ~50 sc/s
    v, r = cl(s0, s1, {"cpu_pct": 95.0}, DT, "[SC]", 40.0, False, False, False, True)
    check("firehose creeping sc @ high CPU -> SLOW-ALIVE (never reaped)",
          v == "SLOW-ALIVE", v)
    check("SLOW-ALIVE is NOT a reap class",
          "SLOW-ALIVE" not in mod.HEALTH_REAP_CLASSES, "guard")

    # SLOW-ALIVE: tick advancing at low CPU (idle-ish, not a circle).
    s0 = _sample(1000, 5000, 3, "content-procs")
    s1 = _sample(1100, 5001, 3, "content-procs")
    v, _ = cl(s0, s1, {"cpu_pct": 8.0}, DT, "[POLL_RET]", 30.0, False, False,
              False, True)
    check("tick advancing @ low CPU -> SLOW-ALIVE", v == "SLOW-ALIVE", v)

    # Enum + reap-class contract.
    check("HEALTH_CLASSES has all 6 verdicts",
          set(mod.HEALTH_CLASSES) == {
              "HEALTHY", "SLOW-ALIVE", "SPINNING", "STALLED",
              "WEDGED-PRE-BUGCHECK", "DEAD/BUGCHECKED"},
          ",".join(mod.HEALTH_CLASSES))
    check("reap classes are exactly the 4 circle classes",
          mod.HEALTH_REAP_CLASSES == {
              "SPINNING", "STALLED", "WEDGED-PRE-BUGCHECK", "DEAD/BUGCHECKED"},
          ",".join(sorted(mod.HEALTH_REAP_CLASSES)))


# ── Layer 2: end-to-end argv tests over synthetic serial logs ─────────────────

# Required output fields per the subcommand contract.
REQUIRED_FIELDS = [
    "sid", "qemu_pid", "etimes", "cpu_pct", "deepest_gate", "gate_advancing",
    "sc_now", "sc_rate_per_s", "serial_growth_kbps", "dominant_tail_tag",
    "dominant_tag_pct", "futex_timeout_churn", "kdb_autopsy_fresh",
    "bugchecked", "ticks_since_progress", "verdict", "reason",
]


def _write_stalled_serial(path):
    """Reproduce the ea3da73280e2 STALLED fingerprint: [GATE] markers reached,
    then a frozen run of PROC-METRICS with FUTEX_TIMEDOUT churn + a thread
    STUCK_IN_NR=7 for ~68k ticks while the global tick advances but sc/gate do
    not (in a fresh, processless log the pid is dead -> DEAD/BUGCHECKED; this
    fixture is for the serial-parsing assertions)."""
    lines = ["[GATE] libxul", "[GATE] content-procs"]
    for t in range(118000, 119500, 500):
        lines.append(f"[HB] tick={t} cpu=1 pf=89944 sc=97075")
        lines.append(
            f"[PROC-METRICS] tick={t} pid=1 name=/disk/usr/lib/firefox-esr/firefox-bin "
            f"sc=59786 (sync=37519) pf=49100 cur_nr=202@2t")
        lines.append(
            f"[PROC-METRICS] tick={t} pid=3 name=/disk/usr/lib/firefox-esr/firefox-bin "
            f"sc=1864 (sync=65) pf=8982 STUCK_IN_NR=7@67975t")
        for _ in range(20):
            lines.append("[FUTEX_TIMEDOUT] tid=62 pid=1 uaddr=0x7efe9dba4a34 op=0x80")
    Path(path).write_text("\n".join(lines) + "\n")


def run_e2e_tests(tmp_dir):
    print("Layer 2: end-to-end argv contract over synthetic serial logs")
    env = dict(os.environ)
    env["ASTRYX_HARNESS_DIR"] = str(tmp_dir)

    def h(*a):
        r = subprocess.run([PYTHON, str(HARNESS), *a],
                           capture_output=True, text=True, env=env)
        try:
            return json.loads(r.stdout.strip()) if r.stdout.strip() else None, r
        except json.JSONDecodeError:
            return None, r

    # Fixture A: a processless STALLED-fingerprint serial log (no <sid>.json,
    # pid gone) — single-sid path must still parse all serial signals and emit
    # the full contract.
    sid = "deadbeef0001"
    _write_stalled_serial(tmp_dir / f"{sid}.serial.log")
    obj, r = h("health", sid, "--gap", "0")
    check("health <sid> returns a JSON object", isinstance(obj, dict),
          (r.stdout or r.stderr)[:200])
    if isinstance(obj, dict):
        missing = [f for f in REQUIRED_FIELDS if f not in obj]
        check("all contract fields present", not missing, f"missing={missing}")
        check("deepest_gate parsed from whole-file scan",
              obj.get("deepest_gate") == "content-procs", obj.get("deepest_gate"))
        check("sc_now = sum of per-proc sc (59786+1864)",
              obj.get("sc_now") == 59786 + 1864, obj.get("sc_now"))
        check("ticks_since_progress = STUCK_IN_NR tick count",
              obj.get("ticks_since_progress") == 67975,
              obj.get("ticks_since_progress"))
        check("dominant_tail_tag = [FUTEX_TIMEDOUT]",
              obj.get("dominant_tail_tag") == "[FUTEX_TIMEDOUT]",
              obj.get("dominant_tail_tag"))
        check("futex_timeout_churn flagged",
              obj.get("futex_timeout_churn") is True,
              obj.get("futex_timeout_churn"))
        check("processless session -> DEAD/BUGCHECKED",
              obj.get("verdict") == "DEAD/BUGCHECKED", obj.get("verdict"))

    # Fixture B: a bugchecked serial log — bugchecked flag must be True.
    sid_bc = "deadbeef0002"
    (tmp_dir / f"{sid_bc}.serial.log").write_text(
        "[GATE] libxul\n[HB] tick=500 sc=10\nAETHER KERNEL BUGCHECK 0x1234\n")
    obj, r = h("health", sid_bc, "--gap", "0")
    check("bugcheck log -> bugchecked True",
          isinstance(obj, dict) and obj.get("bugchecked") is True,
          obj.get("bugchecked") if isinstance(obj, dict) else r.stdout[:120])
    check("bugcheck log -> DEAD/BUGCHECKED",
          isinstance(obj, dict) and obj.get("verdict") == "DEAD/BUGCHECKED",
          obj.get("verdict") if isinstance(obj, dict) else "")

    # Fixture C: --all sweep + --reap-circles.  Build two LIVE sessions (a
    # self-backgrounded `sleep` stands in for qemu so the pid is alive): one
    # whose serial log is a frozen STALLED fingerprint (must be reaped) and one
    # that is HEALTHY (gate advancing — must NOT be reaped).  We hand-write the
    # <sid>.json so --all picks them up.
    import signal as _sig
    live_a = subprocess.Popen(["sleep", "30"])
    live_b = subprocess.Popen(["sleep", "30"])
    try:
        # STALLED session: frozen sc, frozen gate, futex churn, high "cpu" is
        # irrelevant here (sleep is idle) so we lean on the frozen-sc rule via a
        # STUCK thread near the wedge threshold => WEDGED-PRE-BUGCHECK actually,
        # which is also a reap class.  Either reap class satisfies the test.
        sid_s = "11110000aaaa"
        _write_stalled_serial(tmp_dir / f"{sid_s}.serial.log")
        (tmp_dir / f"{sid_s}.json").write_text(json.dumps({
            "sid": sid_s, "pid": live_a.pid,
            "serial_log": str(tmp_dir / f"{sid_s}.serial.log"),
            "features": "firefox-test", "started_at": time.time() - 600,
        }))
        # HEALTHY session: two serial snapshots would show a gate advance, but
        # --all takes the two samples itself.  To make the gate advance appear
        # *between* samples we can't easily time-inject; instead we make it
        # plainly HEALTHY by a fast-but-present gate set with sc climbing every
        # poll.  Simplest robust signal: a non-frozen, slowly-advancing log =>
        # SLOW-ALIVE, which is ALSO a never-reap class.  The invariant under
        # test is "not reaped", which SLOW-ALIVE satisfies identically.
        sid_h = "22220000bbbb"
        healthy_lines = ["[GATE] libxul", "[GATE] content-procs"]
        base = 70000
        for i, t in enumerate(range(50000, 51000, 250)):
            healthy_lines.append(f"[HB] tick={t} sc={base + i * 500}")
            healthy_lines.append(
                f"[PROC-METRICS] tick={t} pid=1 name=ff sc={base + i * 500} cur_nr=1@1t")
        (tmp_dir / f"{sid_h}.serial.log").write_text("\n".join(healthy_lines) + "\n")
        (tmp_dir / f"{sid_h}.json").write_text(json.dumps({
            "sid": sid_h, "pid": live_b.pid,
            "serial_log": str(tmp_dir / f"{sid_h}.serial.log"),
            "features": "firefox-test", "started_at": time.time() - 600,
        }))

        obj, r = h("health", "--all", "--reap-circles", "--gap", "0")
        check("--all returns the envelope dict",
              isinstance(obj, dict) and "sessions" in obj and "reaped" in obj,
              (r.stdout or r.stderr)[:200])
        if isinstance(obj, dict):
            verdicts = {s["sid"]: s["verdict"] for s in obj["sessions"]}
            reaped_sids = {x["sid"] for x in obj["reaped"]}
            check("reap_enabled echoed True", obj.get("reap_enabled") is True,
                  obj.get("reap_enabled"))
            check("STALLED/WEDGED session was reaped",
                  sid_s in reaped_sids, f"verdict={verdicts.get(sid_s)}")
            check("non-circle session NOT reaped",
                  sid_h not in reaped_sids, f"verdict={verdicts.get(sid_h)}")
            # Every reaped sid carries a non-empty reason (never a silent kill).
            check("every reap has a reason",
                  all(x.get("reason") for x in obj["reaped"]),
                  json.dumps(obj["reaped"])[:200])
            # The reap must be LOGGED to the per-session event stream.
            ev = tmp_dir / f"{sid_s}.events.jsonl"
            logged = False
            if ev.exists():
                logged = any('"health_reap"' in ln for ln in ev.read_text().splitlines())
            check("reap logged to events.jsonl (no silent kill)", logged,
                  "missing health_reap event")
            # The reaped session's <sid>.json must be gone (stop() ran).
            check("reaped session's <sid>.json removed",
                  not (tmp_dir / f"{sid_s}.json").exists(), "json still present")
    finally:
        for p in (live_a, live_b):
            if p.poll() is None:
                p.send_signal(_sig.SIGKILL)


def main():
    print("=== health-smoke: boot-free classifier + contract tests ===")
    with tempfile.TemporaryDirectory(prefix="health-smoke-") as td:
        tmp = Path(td)
        mod = _load_harness_module(tmp)
        run_classifier_tests(mod)
        run_e2e_tests(tmp)

    print()
    if failures:
        print(f"FAILED ({len(failures)}): {', '.join(failures)}")
        sys.exit(1)
    print("ALL HEALTH SMOKE CHECKS PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
