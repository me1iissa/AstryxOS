#!/usr/bin/env python3
"""
serial-web-smoke.py — Host-side smoke test for scripts/serial-web.py.

Validates every dashboard backend parser/endpoint against synthetic serial-log
fixtures, with NO kernel boot and NO QEMU. Imports serial-web.py's pure
functions directly and also exercises the HTTP layer end-to-end on an ephemeral
port. Fast (<2s), deterministic, and CI-safe.

    python3 scripts/serial-web-smoke.py

Exit codes:
    0  — all checks passed
    1  — one or more checks failed

Covers (matches the operator-requested feature set):
  * /api/sessions  — launch-time fields (started_at/elapsed/started_src) from
                     <sid>.json, plus the log-mtime fallback when json is absent.
  * /api/milestones — forward-ordered first-hit timeline (line numbers).
  * /api/context    — N±ctx window slice around a gate line.
  * /api/metrics    — latest [PROC-METRICS] per pid + [HB], aggregates,
                      breakdown, both STUCK_IN_NR= and cur_nr= variants.
  * /api/blkmap     — [BLK] histogram bucketing across the 4194304-sector device,
                      has_trace=False when no [BLK] lines are present.
  * /api/milestones per-gate TIMING — host elapsed (+Ns) + per-gate delta (Δ+Ns)
                      from the marks sidecar (EXACT live stamps) and from
                      kernel-tick derivation (APPROX historical), incl. the
                      monotone/forward-ordered delta invariant.
"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
failures = []


def check(name, cond, detail=""):
    print(f"  [{PASS if cond else FAIL}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def load_module(harness_dir):
    """Import serial-web.py with HARNESS_DIR pointed at our fixture dir."""
    spec = importlib.util.spec_from_file_location("sw", os.path.join(HERE, "serial-web.py"))
    sw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sw)
    sw.HARNESS_DIR = harness_dir
    return sw


# ── synthetic fixtures ────────────────────────────────────────────────────────
SERIAL = """\
[BOOT] AstryxOS kernel starting
[HEAP GUARD] Guard pages installed
[ACPI] Phase 5b: APIC init
[SMP] scheduler online, AP online (Phase 6)
[DRIVERS] Phase 7: probing virtio devices
[VIRTIO-BLK] Initialized: io=0xc000, capacity=4194304 sectors, queue_size=256
[VFS] ext2 mounted rootfs
[INIT] PID 1 spawn /sbin/init
[BLK] op=R lba=0 len=1 pid=0
[BLK] op=R lba=2 len=8 pid=0
[BLK] op=R lba=131072 len=2048 pid=1
[BLK] op=W lba=4000000 len=8 pid=2
[FFTEST] X11 server ready
[EXEC] /disk/usr/lib/firefox-esr/firefox-bin
[HB] tick=10000 cpu=0 pf=500 sc=1200
[PROC-METRICS] tick=10000 pid=1 name=/disk/usr/lib/firefox-esr/firefox-bin sc=800 (vm=400 file=300 net=10 sync=20 proc=30 sig=20 other=20) pf=300 disk=R262144/W0 rreq=300 net=R0/W100 STUCK_IN_NR=7@9000t
[PROC-METRICS] tick=10000 pid=2 name=/disk/usr/lib/firefox-esr/firefox-bin sc=200 (vm=100 file=80 net=0 sync=5 proc=8 sig=4 other=3) pf=120 disk=R4096/W4096 rreq=20 net=R0/W0 cur_nr=2@100t
[HB] tick=10500 cpu=1 pf=520 sc=1500
[PROC-METRICS] tick=10500 pid=1 name=/disk/usr/lib/firefox-esr/firefox-bin sc=900 (vm=450 file=320 net=12 sync=22 proc=32 sig=22 other=20) pf=320 disk=R524288/W0 rreq=400 net=R0/W200 cur_nr=5@25t
"""


# Full forward-ordered ladder with interleaved kernel ticks. Each gate line is
# preceded by an [HB] tick= so the tick-derivation can stamp it. Ticks: kernel
# entry @0, APIC @100 (=1.0s), drivers @300 (=3.0s), VFS @400 (=4.0s),
# X11 @900 (=9.0s), firefox @950 (=9.5s) — at the published 100 Hz (10ms/tick).
TIMED_SERIAL = """\
[HB] tick=0 cpu=0 pf=0 sc=0
[BOOT] AstryxOS kernel kernel_main Booting
[HEAP GUARD] Guard pages installed
[HB] tick=100 cpu=0 pf=1 sc=1
[ACPI] Phase 5b APIC init
[SMP] scheduler online AP online Phase 6
[HB] tick=300 cpu=0 pf=1 sc=1
[DRIVERS] virtio Phase 7
[HB] tick=400 cpu=0 pf=1 sc=1
[VFS] ext2 mounted rootfs
[INIT] PID 1 spawn
[HB] tick=900 cpu=0 pf=1 sc=1
[FFTEST] X11 server ready
[HB] tick=950 cpu=0 pf=1 sc=1
[EXEC] firefox-bin
"""


def _gate_timing_checks(sw, tmp):
    """Per-gate timing: EXACT (marks sidecar) + APPROX (tick-derived), and the
    forward-ordered/monotone delta invariant. Independently hand-computed values."""
    import gate_marks as gm

    # ---- APPROX path: no marks sidecar, derive from kernel ticks ----
    sidA = "timedapprox01"
    logA = os.path.join(tmp, sidA + ".serial.log")
    with open(logA, "w") as f:
        f.write(TIMED_SERIAL)
    with open(os.path.join(tmp, sidA + ".json"), "w") as f:
        json.dump({"sid": sidA, "started_at": time.time() - 60,
                   "features": "firefox-test,kdb", "running": False}, f)
    tA = {x["label"]: x for x in sw.scan_milestones_timed(sidA, logA)}
    # tick 100 -> 1.0s, 300 -> 3.0s, 400 -> 4.0s, 900 -> 9.0s, 950 -> 9.5s
    check("approx APIC elapsed +1.0s",
          tA["APIC init"]["host_elapsed"] == 1.0, tA["APIC init"]["host_elapsed"])
    check("approx APIC is approx (tick-derived)", tA["APIC init"]["approx"] is True)
    check("approx drivers elapsed +3.0s",
          tA["drivers"]["host_elapsed"] == 3.0, tA["drivers"]["host_elapsed"])
    # per-gate DELTA: drivers since APIC = 3.0-1.0 = 2.0s (the key compare signal)
    check("approx drivers delta = +2.0s (vs APIC)",
          tA["drivers"]["host_delta"] == 2.0, tA["drivers"]["host_delta"])
    check("approx VFS delta = +1.0s (4.0-3.0)",
          tA["VFS / mount"]["host_delta"] == 1.0, tA["VFS / mount"]["host_delta"])
    check("approx X11 delta = +5.0s (9.0-4.0)",
          tA["X11 ready"]["host_delta"] == 5.0, tA["X11 ready"]["host_delta"])
    # monotone: every hit gate's elapsed is non-decreasing in ladder order
    seq = [x["host_elapsed"] for x in sw.scan_milestones_timed(sidA, logA)
           if x["hit"] and x["host_elapsed"] is not None]
    check("approx elapsed monotone non-decreasing",
          all(seq[i] <= seq[i + 1] for i in range(len(seq) - 1)), seq)

    # ---- EXACT path: marks sidecar with known host stamps ----
    sidE = "timedexact01"
    logE = os.path.join(tmp, sidE + ".serial.log")
    with open(logE, "w") as f:
        f.write(TIMED_SERIAL)
    started = 5000.0
    with open(os.path.join(tmp, sidE + ".json"), "w") as f:
        json.dump({"sid": sidE, "started_at": started,
                   "features": "firefox-test,kdb", "running": True}, f)
    # watcher would stamp these; here we write them directly via the shared helper
    stamps = [("kernel entry", 5000.2), ("heap guard", 5000.4),
              ("APIC init", 5002.0), ("SMP / scheduler", 5003.0),
              ("drivers", 5005.0), ("VFS / mount", 5009.0),
              ("init / userspace", 5010.0), ("X11 ready", 5023.0),
              ("firefox exec", 5024.0)]
    for lab, ts in stamps:
        gm.append_gate_mark(sidE, tmp, lab, host_ts=ts, tick=None, line=1)
    tE = {x["label"]: x for x in sw.scan_milestones_timed(sidE, logE)}
    # X11 arrived at 5023.0, launch 5000.0 -> elapsed 23.0s exact (NOT approx)
    check("exact X11 elapsed +23.0s",
          tE["X11 ready"]["host_elapsed"] == 23.0, tE["X11 ready"]["host_elapsed"])
    check("exact X11 NOT approx", tE["X11 ready"]["approx"] is False)
    check("exact X11 has absolute host_ts",
          tE["X11 ready"]["host_ts"] == 5023.0, tE["X11 ready"]["host_ts"])
    # X11 delta from previous HIT gate (init/userspace @5010) = 23.0-10.0 = 13.0s
    check("exact X11 delta = +13.0s (vs init/userspace)",
          tE["X11 ready"]["host_delta"] == 13.0, tE["X11 ready"]["host_delta"])
    check("exact drivers delta = +2.0s (5005-5003)",
          tE["drivers"]["host_delta"] == 2.0, tE["drivers"]["host_delta"])

    # ---- the shared gate<->phase mapping is internally consistent ----
    mlabels = {l for l, _ in gm.MILESTONES}
    check("GATE_TO_PHASE covers every milestone",
          set(gm.GATE_TO_PHASE) == mlabels,
          set(gm.GATE_TO_PHASE) ^ mlabels)

    # ---- HTTP: /api/milestones surfaces the timing fields ----
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), sw.H)
    srv.daemon_threads = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/milestones?sid={sidE}",
                timeout=5) as r:
            body = r.read()
        check("/api/milestones has host_elapsed", b"host_elapsed" in body)
        check("/api/milestones has host_delta", b"host_delta" in body)
    finally:
        srv.shutdown()


def main():
    tmp = tempfile.mkdtemp(prefix="serialweb-smoke-")
    sid = "smoketest1234"
    log = os.path.join(tmp, sid + ".serial.log")
    with open(log, "w") as f:
        f.write(SERIAL)
    started = time.time() - 119          # 1m59s ago
    with open(os.path.join(tmp, sid + ".json"), "w") as f:
        json.dump({"sid": sid, "pid": 4242, "started_at": started,
                   "features": "firefox-test,kdb,blk-trace", "running": True}, f)
    # a second session with NO json — exercises the log-mtime fallback
    sid2 = "nojson5678"
    log2 = os.path.join(tmp, sid2 + ".serial.log")
    with open(log2, "w") as f:
        f.write("[BOOT] AstryxOS kernel\n")

    sw = load_module(tmp)

    print("── pure parsers ──")
    # sessions / launch info
    sessions = {s["sid"]: s for s in sw.list_sessions()}
    s1 = sessions.get(sid, {})
    check("sessions includes fixture", sid in sessions)
    check("started_at from json", abs((s1.get("started_at") or 0) - started) < 1, s1.get("started_at"))
    check("started_src == json", s1.get("started_src") == "json", s1.get("started_src"))
    check("elapsed ~119s", s1.get("elapsed") is not None and 115 <= s1["elapsed"] <= 125, s1.get("elapsed"))
    check("pid surfaced", s1.get("pid") == 4242, s1.get("pid"))
    s2 = sessions.get(sid2, {})
    check("no-json fallback started_src", s2.get("started_src") == "log-ctime", s2.get("started_src"))
    check("no-json fallback has started_at", s2.get("started_at") is not None)

    # milestones — forward-ordered first hits
    ms = {m["label"]: m for m in sw.scan_milestones(log)}
    check("milestone kernel-entry hit", ms["kernel entry"]["hit"])
    check("milestone X11 hit with line", ms["X11 ready"]["hit"] and ms["X11 ready"]["line"] > 0)
    check("milestone firefox-exec hit", ms["firefox exec"]["hit"])
    check("milestone PNG not hit", not ms["PNG write"]["hit"])
    # forward ordering: X11 line < firefox-exec line
    check("milestones forward-ordered", ms["X11 ready"]["line"] < ms["firefox exec"]["line"])

    # context window around a gate line
    x11_line = ms["X11 ready"]["line"]
    ctx = sw.read_context(log, x11_line, 3)
    check("context start<=line<=end", ctx["start"] <= x11_line <= ctx["end"])
    check("context returns lines", len(ctx["lines"]) > 0)
    check("context target line present",
          any(l["n"] == x11_line and "X11 server ready" in l["t"] for l in ctx["lines"]))

    # metrics — both STUCK_IN_NR and cur_nr variants parse
    size = os.path.getsize(log)
    mt = sw.scan_metrics(log, size)
    check("metrics hb parsed", mt.get("hb") and mt["hb"]["sc"] == 1500, mt.get("hb"))
    pids = {p["pid"]: p for p in mt.get("pids", [])}
    check("metrics pid1 latest sc", pids.get(1, {}).get("sc") == 900, pids.get(1, {}).get("sc"))
    check("metrics pid1 cur_nr stuck", pids.get(1, {}).get("stuck_nr") == 5, pids.get(1, {}).get("stuck_nr"))
    check("metrics pid2 STUCK fallback parse", 2 in pids)
    check("metrics breakdown parsed", pids.get(1, {}).get("bd", {}).get("file") == 320)
    check("metrics aggregate sc", mt["agg"]["sc"] == 900 + 200, mt["agg"]["sc"])
    check("metrics ram_total 2GiB", mt["ram_total"] == 2 * 1024 * 1024 * 1024)

    # blkmap — histogram across the device
    bk = sw.scan_blkmap(log, size, 256)
    check("blkmap has_trace True", bk["has_trace"])
    check("blkmap n_req == 4", bk["n_req"] == 4, bk["n_req"])
    check("blkmap device sectors", bk["sectors"] == 4194304)
    tr = sum(b["r"] for b in bk["buckets"])
    tw = sum(b["w"] for b in bk["buckets"])
    check("blkmap read sectors == 1+8+2048", tr == 1 + 8 + 2048, tr)
    check("blkmap write sectors == 8", tw == 8, tw)
    # write request at lba 4000000 -> high bucket
    spb = bk["sectors_per_bucket"]
    wbucket = 4000000 // spb
    check("blkmap write in high bucket", bk["buckets"][wbucket]["w"] == 8, bk["buckets"][wbucket])
    # no-trace log reports has_trace False
    bk2 = sw.scan_blkmap(log2, os.path.getsize(log2), 256)
    check("blkmap no-trace -> has_trace False", not bk2["has_trace"])

    # ── per-gate TIMING: elapsed-since-launch + per-gate delta ──
    print("── per-gate timing ──")
    _gate_timing_checks(sw, tmp)

    # ── HTTP layer end-to-end on an ephemeral port ──
    print("── HTTP endpoints ──")
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), sw.H)
    srv.daemon_threads = True
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"

    def get(path):
        with urllib.request.urlopen(base + path, timeout=5) as r:
            return r.status, r.read()

    try:
        st, body = get("/api/sessions")
        check("GET /api/sessions 200", st == 200)
        check("GET /api/sessions has started_at", b"started_at" in body)
        st, body = get(f"/api/milestones?sid={sid}")
        check("GET /api/milestones 200", st == 200 and b'"hit"' in body)
        st, body = get(f"/api/context?sid={sid}&line={x11_line}&ctx=3")
        check("GET /api/context 200", st == 200 and b'"lines"' in body)
        st, body = get(f"/api/metrics?sid={sid}")
        check("GET /api/metrics 200", st == 200 and b'"agg"' in body)
        st, body = get(f"/api/blkmap?sid={sid}&grid=128")
        check("GET /api/blkmap 200", st == 200 and b'"buckets"' in body)
        st, body = get("/")
        check("GET / dashboard 200", st == 200 and b"AstryxOS" in body)
        # path-traversal / bad sid rejected
        try:
            get("/api/metrics?sid=../../etc/passwd")
            rejected = False
        except urllib.error.HTTPError as e:
            rejected = e.code in (400, 404)
        check("path traversal rejected", rejected)
    finally:
        srv.shutdown()

    # cleanup
    for f in os.listdir(tmp):
        os.unlink(os.path.join(tmp, f))
    os.rmdir(tmp)

    print()
    if failures:
        print(f"\033[31m{len(failures)} check(s) FAILED:\033[0m " + ", ".join(failures))
        return 1
    print("\033[32mAll serial-web smoke checks passed.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
