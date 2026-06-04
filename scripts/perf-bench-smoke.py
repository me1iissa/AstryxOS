#!/usr/bin/env python3
"""
perf-bench-smoke.py — Host-side smoke test for perf-bench.py + perf_markers.py

Exercises the measurement foundation end-to-end against a SYNTHETIC serial log
(no QEMU, no kernel build, no real boot):

  - perf_markers: forward-ordered phase-boundary scan + tick->ms derivation
  - perf_markers: vendored-vs-serial-web marker source resolves
  - perf-bench import-logs: synthetic log -> a sane time-series record
  - perf-bench list / export-json: store round-trips
  - perf-bench run --build-only: boot stays gated off
  - perf-bench baseline-linux: stub shape is pinned

Run directly:

    python3 scripts/perf-bench-smoke.py

Exit codes:
    0  — all checks passed
    1  — one or more checks failed
"""

import os
import sys
import json
import time
import tempfile
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
BENCH = SCRIPTS / "perf-bench.py"
PY = sys.executable

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"

# A compact synthetic FF-headless serial log that hits every taxonomy anchor in
# order, with kernel [HB] tick lines so the tick axis is exercised. Ticks chosen
# so phase deltas are easy to assert (10 ms/tick at 100 Hz).
#
# This mirrors the REAL marker shapes the import path keys on (verified against
# the historical FF-boot logs):
#   * libpng16.so is a STARTUP load (during LIBXUL-INIT, before screenshot) — it
#     must NOT anchor the render pipeline (the historical bug).
#   * a CHILD process emits `exit_group(` long before the launcher — the real
#     end-of-run is `[PROC] PID 1 exit_group`.
#   * the real draw/encode boundary is `[FF/open] pid=1 path=/tmp/out.png`, and
#     the PNG is the `89504e47` magic in a `[FF/write-fd]` payload.
SYNTHETIC_LOG = """\
BdsDxe: loading Boot0002 "UEFI QEMU HARDDISK"
BdsDxe: starting Boot0002 "UEFI QEMU HARDDISK"
        Aether Kernel v0.1 - Booting...
[AstryxBoot] Initializing UEFI bootloader...
[Aether] Phase 1: HAL OK
[Aether] Phase 5b: APIC init...
[APIC] Local APIC initialized: BSP ID=0
[Aether] Phase 7: device probe
[VFS] Probing virtio-blk device (4194304 sectors) for partitions...
[VFS] Virtio-blk disk is not FAT32, trying ext2
[X11] Xastryx ready on /tmp/.X11-unix/X0 (fd=0)
[FFTEST] X11 server ready
[FFTEST] Launching /disk/usr/lib/firefox-esr/firefox-bin ...
[HB] tick=100 cpu=0 pf=10 sc=50
[FF/open] pid=1 path=/disk/usr/lib/firefox-esr/libxul.so
[HB] tick=150 cpu=0 pf=15 sc=70
[FF/open] pid=1 path=/usr/lib/libpng16.so.16
[HB] tick=200 cpu=0 pf=20 sc=100
[KDB] listening on 0.0.0.0:9999
[TCP] Accepted from 10:52152
[HB] tick=400 cpu=1 pf=40 sc=300
[SYSCALL/Linux] exit_group(0)
[PROC] PID 2 exit_group(0) caller_tid=5
[HB] tick=500 cpu=1 pf=50 sc=400
[FF/write] pid=1 fd=62 bytes=10 body="getDimensions ScreenshotParent"
[HB] tick=600 cpu=1 pf=60 sc=500
[FF/open] pid=1 path=/tmp/out.png
[HB] tick=900 cpu=0 pf=90 sc=800
[FF/write-fd] pid=1 fd=72 len=30186 bytes=89504e470d0a1a0a0000000d49484452
[HB] tick=1000 cpu=0 pf=100 sc=900
[SYSCALL/Linux] exit_group(0)
[PROC] PID 1 exit_group(0) caller_tid=2
[PROC-METRICS] tick=1000 pid=1 name=firefox-bin sc=900 (vm=1) pf=100 disk=R0/W0 rreq=0 net=R0/W0
"""


def run(args, env=None):
    res = subprocess.run([PY, str(BENCH)] + args,
                         capture_output=True, text=True, timeout=120, env=env)
    try:
        out = json.loads(res.stdout)
    except Exception:
        out = {}
    return res.returncode, out, res.stdout + res.stderr


def main():
    fails = 0

    def check(name, ok, detail=""):
        nonlocal fails
        mark = PASS if ok else FAIL
        print(f"  [{mark}] {name}" + (f"  — {detail}" if detail else ""))
        if not ok:
            fails += 1

    print(f"[{INFO}] perf-bench smoke test (host-only, no QEMU)")

    # ── perf_markers direct ──────────────────────────────────────────────────
    sys.path.insert(0, str(SCRIPTS))
    import perf_markers as pm
    print(f"[{INFO}] markers source: {pm.MARKERS_SOURCE} ({pm.MARKERS_PATH})")
    check("ticks_to_ms(100)==1000.0", pm.ticks_to_ms(100) == 1000.0)
    check("AND-anchor accepts [FF/write]+getDimensions",
          pm._match("[FF/write] x getDimensions", (("[FF/write]", "getDimensions"),)))
    check("AND-anchor rejects bare getDimensions (cached JS)",
          not pm._match("cached getDimensions", (("[FF/write]", "getDimensions"),)))
    check("13 phases defined", len(pm.PHASE_NAMES) == 13,
          f"{len(pm.PHASE_NAMES)} phases")

    with tempfile.TemporaryDirectory() as td:
        harness_dir = Path(td) / "harness"
        perf_dir = Path(td) / "perf"
        harness_dir.mkdir()
        log = harness_dir / "smoke00000001.serial.log"
        log.write_text(SYNTHETIC_LOG)
        # ensure a sane mtime for revision attribution
        os.utime(log, (time.time(), time.time()))

        env = dict(os.environ)
        env["ASTRYX_HARNESS_DIR"] = str(harness_dir)
        env["ASTRYX_PERF_DIR"] = str(perf_dir)
        # isolate from the committed .perf/baseline.json so `list`/`export-json`
        # counts are deterministic (empty baseline for this temp store).
        empty_baseline = Path(td) / "baseline.json"
        empty_baseline.write_text('{"schema_v":1,"records":[]}')
        env["ASTRYX_PERF_BASELINE"] = str(empty_baseline)

        # marker scan against the synthetic log
        scan = pm.scan_phase_boundaries(str(log))
        check("synthetic: deepest anchor == exit_group",
              scan["deepest_anchor"] == "exit_group", scan["deepest_anchor"])
        check("synthetic: no panic", scan["panic"] is False)
        # png_seen is GLOBAL (PNG magic anywhere), independent of the chain
        check("synthetic: png_seen True (global)", scan["png_seen"] is True)
        a = scan["anchors"]
        # exit_group anchored on `[PROC] PID 1 exit_group`, NOT the earlier
        # child `[PROC] PID 2 exit_group` / bare `exit_group(` (precision fix).
        check("exit_group anchors on PID 1 (not child)",
              a.get("exit_group", {}).get("line") is not None and
              a["exit_group"]["tick"] == 1000, str(a.get("exit_group")))
        # out_png_open anchored on /tmp/out.png (not libpng16.so load).
        check("out_png_open anchored on /tmp/out.png",
              a.get("out_png_open", {}).get("tick") == 600,
              str(a.get("out_png_open")))
        d = pm.phase_durations(scan)
        # libxul anchor lands after [HB] tick=100; tcp anchor after [HB] tick=200
        # => LIBXUL-INIT = (200-100) ticks = 1000 ms.
        check("LIBXUL-INIT tick_ms == 1000.0",
              d["LIBXUL-INIT"]["tick_ms"] == 1000.0,
              str(d["LIBXUL-INIT"]["tick_ms"]))
        # tcp tick=200 -> screenshot anchor after [HB] tick=500 => 3000 ms.
        check("NETWORK/TLS tick_ms == 3000.0",
              d["NETWORK/TLS"]["tick_ms"] == 3000.0,
              str(d["NETWORK/TLS"]["tick_ms"]))
        # MECE: RENDER-SETUP (screenshot tick=500 -> out_png_open tick=600) and
        # ENCODE (out_png_open tick=600 -> png_written tick=900) and TEARDOWN
        # (png_written tick=900 -> exit_group tick=1000) are DISJOINT — no two
        # phases span the same interval (the old RENDER==ENCODE==libpng->png bug).
        check("RENDER-SETUP tick_ms == 1000.0",
              d["RENDER-SETUP"]["tick_ms"] == 1000.0,
              str(d["RENDER-SETUP"]["tick_ms"]))
        check("ENCODE tick_ms == 3000.0 (out_png_open->png)",
              d["ENCODE"]["tick_ms"] == 3000.0, str(d["ENCODE"]["tick_ms"]))
        check("TEARDOWN tick_ms == 1000.0 (png->exit)",
              d["TEARDOWN"]["tick_ms"] == 1000.0, str(d["TEARDOWN"]["tick_ms"]))
        # MECE assertion: no two timed render-pipeline phases share an interval.
        spans = {p: (d[p]["from_line"], d[p]["to_line"])
                 for p in ("RENDER-SETUP", "RENDER", "ENCODE", "TEARDOWN")
                 if d[p]["tick_ms"] is not None}
        check("render pipeline MECE (no shared span)",
              len(set(spans.values())) == len(spans), str(spans))
        check("TEARDOWN reached", d["TEARDOWN"]["reached"] is True)

        # ── optional-anchor skip: a no-TCP (file://) render still reaches PNG ──
        # Drop the [TCP] line; the screenshot/out_png/png anchors must still fire
        # (the old mandatory-tcp-intermediate design stalled the chain here).
        no_tcp = SYNTHETIC_LOG.replace("[TCP] Accepted from 10:52152\n", "")
        notcp_log = harness_dir / "smoke0000notcp.serial.log"
        notcp_log.write_text(no_tcp)
        scan2 = pm.scan_phase_boundaries(str(notcp_log))
        check("no-TCP render still png_seen", scan2["png_seen"] is True)
        check("no-TCP render reaches exit_group anchor",
              scan2["deepest_anchor"] == "exit_group", scan2["deepest_anchor"])
        check("no-TCP render: tcp anchor absent",
              "tcp" not in scan2["anchors"])
        notcp_log.unlink()

        # ── events.jsonl host-anchoring: true launch ts + kvm_effective ───────
        # The session json is absent (historical case). The first events.jsonl
        # line (cpu_model) carries the true started_at + kvm_effective; the import
        # must use it for iso_ts/kvm instead of the run-END log mtime.
        ev = harness_dir / "smoke00000001.events.jsonl"
        launch_ts = 1780000000.0
        ev.write_text(json.dumps({"kind": "cpu_model", "kvm_effective": True,
                                  "ts": launch_ts}) + "\n")
        # push log mtime far past the launch (simulating the ~28-min run)
        os.utime(log, (launch_ts + 1700, launch_ts + 1700))
        ts2, kvm2 = pm.event_anchor("smoke00000001", str(harness_dir))
        check("event_anchor recovers launch ts", ts2 == launch_ts, str(ts2))
        check("event_anchor recovers kvm_effective", kvm2 is True)
        la_ts, la_src = pm.launch_anchor("smoke00000001", str(log), str(harness_dir))
        check("launch_anchor prefers events.jsonl over mtime",
              la_src == "events.jsonl" and la_ts == launch_ts,
              f"{la_src} {la_ts}")

        # ── import-logs ──────────────────────────────────────────────────────
        rc, out, raw = run(["import-logs"], env=env)
        check("import-logs rc==0", rc == 0, raw[-200:] if rc else "")
        check("import-logs parsed 1", out.get("parsed") == 1, str(out.get("parsed")))
        check("import-logs reached_png 1", out.get("reached_png") == 1)
        check("import-logs deepest TEARDOWN present",
              "TEARDOWN" in (out.get("deepest_phase_dist") or {}))
        # the imported record's iso_ts must reflect the events.jsonl launch ts,
        # kvm recovered from events.jsonl, launch_src == events.jsonl.
        ex = (out.get("example_records") or [{}])[-1]
        check("import record launch_src == events.jsonl",
              ex.get("launch_src") == "events.jsonl", str(ex.get("launch_src")))
        check("import record kvm recovered True", ex.get("kvm") is True,
              str(ex.get("kvm")))
        check("import record iso_ts == launch (not run-end)",
              (ex.get("iso_ts") or "").startswith("2026-"),
              str(ex.get("iso_ts")))

        # ── list ─────────────────────────────────────────────────────────────
        rc, out, raw = run(["list", "--limit", "5"], env=env)
        check("list rc==0", rc == 0)
        check("list returns 1 record", out.get("n") == 1, str(out.get("n")))
        if out.get("records"):
            r0 = out["records"][0]
            check("list record reached_png", r0.get("reached_png") is True)
            check("list record deepest TEARDOWN",
                  r0.get("deepest_phase") == "TEARDOWN", str(r0.get("deepest_phase")))

        # ── export-json ──────────────────────────────────────────────────────
        rc, out, raw = run(["export-json"], env=env)
        check("export-json rc==0", rc == 0)
        check("export-json schema_v==1", out.get("schema_v") == 1)
        check("export-json timeseries_count==1", out.get("timeseries_count") == 1)

        # ── run build-only gate (no build, no boot) ──────────────────────────
        rc, out, raw = run(["run", "--no-build", "--build-only", "--dry-run"],
                           env=env)
        check("run rc==0", rc == 0)
        check("run mode == build-only", out.get("mode") == "build-only",
              str(out.get("mode")))

        # ── run boot stays gated even with unlock flag, no env var ────────────
        env_no_boot = dict(env)
        env_no_boot.pop("ASTRYX_PERF_ALLOW_BOOT", None)
        rc, out, raw = run(["run", "--no-build", "--i-understand-this-boots",
                            "--dry-run"], env=env_no_boot)
        check("run boot stays gated without ASTRYX_PERF_ALLOW_BOOT",
              out.get("mode") == "build-only", str(out.get("mode")))

        # ── baseline-linux stub shape ────────────────────────────────────────
        rc, out, raw = run(["baseline-linux", "--distro", "alpine-3.20"], env=env)
        check("baseline-linux rc==0", rc == 0)
        check("baseline-linux is stub", out.get("stub") is True)
        check("baseline-linux record_shape has 13 phases",
              len((out.get("record_shape") or {}).get("phase_ms") or {}) == 13)

    print()
    if fails:
        print(f"[{FAIL}] {fails} check(s) failed")
        return 1
    print(f"[{PASS}] all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
