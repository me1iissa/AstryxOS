#!/usr/bin/env python3
"""serial-web.py — a tiny, dependency-free live dashboard for AstryxOS QEMU
serial logs (read-only; safe alongside live boots).

  GET /                       dashboard (session list + live log viewer)
  GET /api/sessions           JSON: every session + gate/sc/tick + launch time
  GET /api/stream?sid=<sid>   SSE: tail then every newly-appended line
  GET /api/milestones?sid=    JSON: forward-ordered milestone timeline
  GET /api/context?sid=&line=N&ctx=400
                              JSON: the ~N±ctx serial lines around `line`
                              (for the clickable gate rail — jump to a gate)
  GET /api/metrics?sid=       JSON: latest [PROC-METRICS]/[HB] sample — CPU/mem
                              proxy/IO bytes+IOPS/net, plus per-pid breakdown
  GET /api/blkmap?sid=&grid=N JSON: data.img block-map histogram built from
                              feature-gated [BLK] op/lba/len trace lines

  python3 scripts/serial-web.py [--port 8088] [--host 0.0.0.0]

All endpoints are read-only and one-shot (the harness convention): each request
reads the on-disk serial log / session json, computes, and returns. No state is
kept server-side; the client keeps the rolling sparkline buffers.
"""
import os, sys, json, time, glob, argparse, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Shared gate-timing helper (marks sidecar + gate<->phase mapping). Imported so
# the milestone rail can show per-gate host elapsed/delta from the SAME source
# the harness watcher stamps and perf-bench ingests. Optional: if it is not on
# this checkout, the dashboard degrades to the original hit/line/tick view.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import gate_marks as _gate_marks  # noqa: E402
except Exception:
    _gate_marks = None

HARNESS_DIR = os.path.expanduser("~/.astryx-harness")
SID_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
TAIL_BYTES = 96 * 1024
GATE_SCAN_BYTES = 256 * 1024
GATE_SCAN_MAX_AGE = 3600         # compute gate/sc for sessions <1h old; result is
                                 # cached by (mtime,size) so frozen logs scan once,
                                 # live logs re-scan each poll (only the 2-3 active ones)
METRICS_SCAN_BYTES = 512 * 1024  # tail window for the latest PROC-METRICS/HB sample
BLK_SCAN_BYTES = 8 * 1024 * 1024 # tail window for the [BLK] block-map histogram
GUEST_RAM_BYTES = 2 * 1024 * 1024 * 1024   # 2 GiB guest RAM (from the qemu cmdline)
DISK_SECTORS = 4194304           # virtio-blk capacity=4194304 sectors (data.img)
SECTOR_BYTES = 512

# render ladder, deepest first (idx, label, substring markers). Each render gate
# accepts BOTH the low-frequency kernel-emitted `[GATE] <label>` milestone marker
# (default-ON on the fast firefox-test-core profile) AND the historical
# diagnostic/JS strings (present on a full-trace boot) — so a gate is detected
# whichever serial source is enabled. This is a tail-window substring scan (no
# AND-anchoring), so the `[GATE]` markers carry the load on the fast profile.
GATES = [
    (8, "PNG",               ("[FF-OUT-PNG:path=/tmp/out.png size=",
                              "/tmp/out.png present", "89504e47", "out.png written",
                              "kdb-read-png")),
    (7, "drawSnapshot",      ("[GATE] drawSnapshot", "drawSnapshot",
                              "CrossProcessPaint", "libpng16")),
    (6, "screenshot-actors", ("[GATE] screenshot-actors", "ScreenshotParent",
                              "getDimensions")),
    (5, "content-proc",      ("[GATE] content-procs", "isForBrowser")),
    (4, "network",           ("] Established", "Established →", "[TCP]")),
    (3, "ff-launch",         ("firefox-bin",)),
    (2, "x11",               ("X11 server ready", "Xastryx")),
    (1, "lib-load",          ("[GATE] libxul", "libxul")),
]
GATE_MAX = 8
_SC_RE = re.compile(r"pid=1[^\n]*?sc=(\d+)")
_TICK_RE = re.compile(r"tick=(\d+)")
_PANIC_RE = re.compile(r"PANIC|HEAP GUARD\] overflow|SCHEDULER_DEADLOCK|ke_bugcheck")


def scan_gate(path, size):
    try:
        with open(path, "rb") as f:
            f.seek(max(0, size - GATE_SCAN_BYTES))
            text = f.read().decode("latin-1", "replace")
    except OSError:
        return {}
    gi, gl = 0, "boot"
    for idx, label, marks in GATES:
        if any(m in text for m in marks):
            gi, gl = idx, label
            break
    sc = tick = None
    m = list(_SC_RE.finditer(text))
    if m:
        sc = int(m[-1].group(1))
    t = list(_TICK_RE.finditer(text))
    if t:
        tick = int(t[-1].group(1))
    return {"gate": gl, "gate_idx": gi, "gate_max": GATE_MAX,
            "sc": sc, "tick": tick, "panic": bool(_PANIC_RE.search(text))}


# Ordered bring-up + render milestones. Each: (label, markers). A marker is a
# substring (str) OR a tuple-of-substrings (ALL must be on the SAME line) — the
# AND form anchors render-stage markers to the real kernel [FF/write] IPDL line
# so they don't false-positive on the same strings inside FF's serialized JS
# source / startup cache. Easily extended — add an entry, it shows everywhere.
MILESTONES = [
    ("kernel entry",      ("AstryxOS kernel", "kernel_main", "Booting")),
    ("heap guard",        ("[HEAP GUARD] Guard pages installed",)),
    ("APIC init",         ("Phase 5b", "APIC init")),
    ("SMP / scheduler",   ("scheduler online", "SMP", "AP online", "Phase 6")),
    ("drivers",           ("virtio", "e1000", "ahci", "vmware_svga", "Phase 7")),
    ("VFS / mount",       ("mounted", "ext2", "fat32", "rootfs")),
    ("init / userspace",  ("init started", "PID 1", "spawn")),
    ("X11 ready",         ("X11 server ready", "Xastryx")),
    ("firefox exec",      ("firefox-bin",)),
    ("TLS / network",     ("[TCP] Established", "] Established →")),
    # content-process spawn. `[GATE] content-procs` is the kernel-emitted
    # milestone marker (default-ON on firefox-test-core, fires once); the
    # `[EXEC] …-isForBrowser …` argv line is the functional default-on fallback
    # (the bare `isForBrowser` substring also lives in FF's cached JS, so we
    # anchor it to the kernel `[EXEC]` line). On a full-trace boot all fire.
    ("content procs",     ("[GATE] content-procs", ("[EXEC]", "isForBrowser"))),
    # render stages. On the FAST `firefox-test-core` profile the per-write
    # `[FF/write]` IPDL mirror is OFF, so these match the low-frequency
    # kernel-emitted `[GATE] <label>` markers instead. The `[FF/write]`-anchored
    # tuples are kept for full-trace boots (firefox-test / *-trace), where they
    # also fire — both detect the same gate, whichever serial source is on.
    ("screenshot-actors", ("[GATE] screenshot-actors",
                           ("[FF/write]", "getDimensions"),
                           ("[FF/write]", "ScreenshotParent"),
                           ("[FF/write]", "sendQuery"))),
    ("drawSnapshot",      ("[GATE] drawSnapshot", "libpng16.so")),
    # PNG write. The FINAL screenshot PNG is NOT detected by a raw [GATE]/magic
    # marker (Firefox writes many internal PNGs — favicons, theme assets — that
    # would false-positive). The authoritative, single-per-run signal is the FF
    # supervisor's functional `[FFTEST] /tmp/out.png present` /
    # `[FF-OUT-PNG:… sig_ok=true …]` lines (default-on on firefox-test-core); the
    # `89504e47` magic / `out.png written` are kept for full-trace boots.
    ("PNG write",         (("[FF-OUT-PNG:", "sig_ok=true"),
                           "/tmp/out.png present", "89504e47", "out.png written")),
    ("exit_group",        ("exit_group(",)),
]

# OPTIONAL milestones: gates that can be absent OR arrive out-of-order on a
# successful run, and so must never STALL the strictly-monotone ladder below.
# When a DEEPER milestone matches the current line but an in-between optional
# gate was not yet seen, the scan advances past the optional gate (same
# discipline as perf_markers.ANCHOR_OPTIONAL). Two members:
#   * "TLS / network" — the headless demo renders a local file:// page with no
#     network I/O, so the TCP gate legitimately never fires, yet content-process
#     spawn + the render gates DO.
#   * "init / userspace" — the FF supervisor emits "X11 server ready" BEFORE the
#     "[PROC] … PID 1" line this gate keys on, so on a strict in-order scan the
#     ladder would dead-end here (X11-ready can't fire while the cursor waits on
#     PID 1) and EVERY deeper gate — firefox exec, [GATE] libxul/content-procs,
#     the render gates — would show as un-hit. Marking it optional lets the
#     ladder advance to the gates the boot actually reached. (Pre-existing
#     ordering quirk, surfaced once the deep [GATE] markers made the deeper
#     gates reachable on the fast profile.)
OPTIONAL_MILESTONES = {"TLS / network", "init / userspace"}

# Only the kernel's own tick lines, not arbitrary "tick=" in FF/JS output.
_TICK_KERNEL = re.compile(r"(?:\[HB\]|PROC-METRICS\]) tick=(\d+)")


def _match(line, marks):
    """True if `line` satisfies any marker in `marks`. A marker is a substring,
    or a tuple of substrings ALL of which must appear on the line (AND)."""
    for mk in marks:
        if isinstance(mk, tuple):
            if all(s in line for s in mk):
                return True
        elif mk in line:
            return True
    return False


# Cache: path -> (mtime, size, result). ONE forward-ordered scan per session,
# reused until the log changes — so the left badge and the right timeline ALWAYS
# agree (both read this), and stopped logs are free.
_prog_cache = {}


def scan_progress(path):
    """FORWARD-ORDERED scan -> {timeline, gate (deepest hit label), gate_idx,
    gate_max, sc (latest pid=1), tick (latest kernel), panic}. The single source
    of truth for BOTH the session-list gate badge and the milestone rail, so they
    can never disagree. Milestone N+1 only matches at/after milestone N's line,
    which (with the AND-anchored render markers) filters the cached-JS-source
    false positives."""
    try:
        st = os.stat(path)
    except OSError:
        return {}
    c = _prog_cache.get(path)
    if c and c[0] == st.st_mtime and c[1] == st.st_size:
        return c[2]
    found = {}
    idx = 0
    cur_tick = sc = None
    first_tick = None
    panic = False
    n = 0
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                n += 1
                tk = _TICK_KERNEL.search(line)
                if tk:
                    cur_tick = int(tk.group(1))
                    if first_tick is None:
                        first_tick = cur_tick
                scm = _SC_RE.search(line)
                if scm:
                    sc = int(scm.group(1))
                if not panic and _PANIC_RE.search(line):
                    panic = True
                while idx < len(MILESTONES):
                    if _match(line, MILESTONES[idx][1]):
                        found[MILESTONES[idx][0]] = (n, cur_tick)
                        idx += 1
                        continue
                    # Current milestone didn't match. If it is OPTIONAL and a
                    # DEEPER milestone matches this line, skip the optional gate
                    # so it can't stall the ladder (e.g. a file:// render emits
                    # no TCP line, but `[GATE] content-procs` / render markers do).
                    if MILESTONES[idx][0] in OPTIONAL_MILESTONES and any(
                        _match(line, MILESTONES[j][1])
                        for j in range(idx + 1, len(MILESTONES))
                    ):
                        idx += 1
                        continue
                    break
                # don't early-break: keep scanning so the latest sc/tick (current
                # state) stays fresh even after the deepest milestone is hit.
    except OSError:
        pass
    timeline, prev, deep_idx, deep_lab = [], None, -1, None
    for i, (lab, _m) in enumerate(MILESTONES):
        h = found.get(lab)
        delta = (h[1] - prev) if (h and h[1] is not None and prev is not None) else None
        if h and h[1] is not None:
            prev = h[1]
        if h:
            deep_idx, deep_lab = i, lab
        timeline.append({"label": lab, "hit": h is not None,
                         "line": h[0] if h else None,
                         "tick": h[1] if h else None, "dtick": delta})
    res = {"timeline": timeline, "gate": deep_lab or "boot",
           "gate_idx": max(deep_idx, 0), "gate_max": len(MILESTONES),
           "sc": sc, "tick": cur_tick, "first_tick": first_tick, "panic": panic}
    _prog_cache[path] = (st.st_mtime, st.st_size, res)
    return res


def scan_milestones(path):
    """Back-compat wrapper for /api/milestones — the timeline from scan_progress.

    Returns the bare timeline (hit/line/tick/dtick). For the per-gate host
    elapsed/delta view use scan_milestones_timed(sid, path)."""
    return scan_progress(path).get("timeline", [])


def scan_milestones_timed(sid, path):
    """Timeline ENRICHED with per-gate host elapsed/delta (the 'compare
    performance' signal). Each hit gate gains, ADDITIVELY (existing keys
    untouched):
        host_elapsed  float|None  seconds since launch at the gate's arrival
        host_delta    float|None  seconds since the PREVIOUS hit gate
        host_ts       float|None  absolute host epoch (exact live marks only)
        approx        bool        True when tick-derived (no exact watcher mark)

    Source priority per gate: the exact host stamp the harness watcher wrote to
    <sid>.marks.jsonl > a kernel-tick derivation (approx). Falls back to the bare
    timeline when the shared gate_marks helper is unavailable."""
    prog = scan_progress(path)
    timeline = prog.get("timeline", [])
    if _gate_marks is None:
        return timeline
    started_at, _src = _launch_info(sid, path,
                                    os.stat(path) if os.path.exists(path) else None)
    marks = _gate_marks.read_gate_marks(sid, HARNESS_DIR)
    return _gate_marks.gate_timeline(
        timeline, marks, started_at, first_tick=prog.get("first_tick") or 0)


def read_context(path, line, ctx):
    """Return the window of serial lines [line-ctx, line+ctx] (1-based line nums)
    so the UI can jump the log view to a gate's exact line. Reads the file once
    and slices — read-only, bounded by `ctx` so an absurd ctx can't OOM us."""
    ctx = max(1, min(int(ctx), 5000))
    line = max(1, int(line))
    lo = max(1, line - ctx)
    hi = line + ctx
    out = []
    n = 0
    try:
        with open(path, "r", errors="replace") as f:
            for raw in f:
                n += 1
                if n < lo:
                    continue
                if n > hi:
                    break
                out.append({"n": n, "t": raw.rstrip("\n")})
    except OSError:
        pass
    return {"line": line, "start": lo, "end": min(hi, n), "total": n, "lines": out}


# ── Guest metrics: latest [PROC-METRICS] per pid + global [HB] ────────────────
# [PROC-METRICS] tick=306000 pid=5 name=… sc=2184 (vm=1254 file=690 net=7 sync=38
#   proc=70 sig=40 other=85) pf=10076 disk=R1801216/W0 rreq=2174 net=R0/W100
#   STUCK_IN_NR=7@190912t      (older logs) / cur_nr=5@25t (newer)
_PM_RE = re.compile(
    r"\[PROC-METRICS\] tick=(?P<tick>\d+) pid=(?P<pid>\d+) name=(?P<name>\S+) "
    r"sc=(?P<sc>\d+) \((?P<bd>[^)]*)\) pf=(?P<pf>\d+) "
    r"disk=R(?P<dr>\d+)/W(?P<dw>\d+) rreq=(?P<rreq>\d+) "
    r"net=R(?P<nr>\d+)/W(?P<nw>\d+)"
    r"(?:.*?(?:STUCK_IN_NR|cur_nr)=(?P<stuck>\d+)@(?P<stuckt>\d+)t)?"
)
_HB_RE = re.compile(r"\[HB\] tick=(\d+) cpu=(\d+) pf=(\d+) sc=(\d+)")


def scan_metrics(path, size):
    """Latest guest-metrics sample: the most-recent [PROC-METRICS] line for each
    pid (within the tail window) + the most-recent [HB] global heartbeat. Returns
    raw counters; the client derives rates from successive polls (it keeps the
    rolling buffer). 'mem' is a pf-pressure PROXY against 2 GiB — there is no
    exact used-bytes counter in the serial log."""
    try:
        with open(path, "rb") as f:
            f.seek(max(0, size - METRICS_SCAN_BYTES))
            text = f.read().decode("latin-1", "replace")
    except OSError:
        return {}
    # latest HB
    hb = None
    for m in _HB_RE.finditer(text):
        hb = {"tick": int(m.group(1)), "cpu": int(m.group(2)),
              "pf": int(m.group(3)), "sc": int(m.group(4))}
    # latest PROC-METRICS per pid (keep order of last-seen tick)
    pids = {}
    for m in _PM_RE.finditer(text):
        pid = int(m.group("pid"))
        bd = {}
        for part in m.group("bd").split():
            if "=" in part:
                k, v = part.split("=", 1)
                try:
                    bd[k] = int(v)
                except ValueError:
                    pass
        pids[pid] = {
            "pid": pid,
            "tick": int(m.group("tick")),
            "name": m.group("name").rsplit("/", 1)[-1][:28],
            "sc": int(m.group("sc")),
            "bd": bd,
            "pf": int(m.group("pf")),
            "disk_r": int(m.group("dr")),
            "disk_w": int(m.group("dw")),
            "rreq": int(m.group("rreq")),
            "net_r": int(m.group("nr")),
            "net_w": int(m.group("nw")),
            "stuck_nr": int(m.group("stuck")) if m.group("stuck") else None,
        }
    plist = sorted(pids.values(), key=lambda p: p["pid"])
    # aggregate totals across pids (for the top-line IO/IOPS gauges)
    agg = {"sc": 0, "pf": 0, "disk_r": 0, "disk_w": 0,
           "rreq": 0, "net_r": 0, "net_w": 0}
    for p in plist:
        for k in agg:
            agg[k] += p[k]
    return {
        "hb": hb,
        "tick": (hb["tick"] if hb else (plist[-1]["tick"] if plist else None)),
        "pids": plist,
        "agg": agg,
        "ram_total": GUEST_RAM_BYTES,
        "mem_proxy_note": "pf-pressure proxy; no exact used-bytes in serial",
    }


# ── data.img block-map: histogram of [BLK] op/lba/len over the device ─────────
_BLK_RE = re.compile(r"\[BLK\] op=(?P<op>[RW]) lba=(?P<lba>\d+) len=(?P<len>\d+)")


def scan_blkmap(path, size, grid):
    """Bucket every [BLK] request into a `grid`-cell histogram across the
    4194304-sector device. Returns per-bucket read-sector and write-sector
    totals so the UI can colour read vs write intensity. Returns has_trace=False
    when no [BLK] lines are present (kernel not built with --features blk-trace),
    so the UI can show a 'enable blk-trace' hint instead of an empty grid."""
    grid = max(16, min(int(grid), 2048))
    try:
        with open(path, "rb") as f:
            f.seek(max(0, size - BLK_SCAN_BYTES))
            text = f.read().decode("latin-1", "replace")
    except OSError:
        return {"has_trace": False, "grid": grid, "buckets": []}
    reads = [0] * grid
    writes = [0] * grid
    n_req = 0
    max_lba = 0
    sectors_per_bucket = DISK_SECTORS / grid
    for m in _BLK_RE.finditer(text):
        lba = int(m.group("lba"))
        ln = int(m.group("len"))
        n_req += 1
        if lba + ln > max_lba:
            max_lba = lba + ln
        # spread the request's sectors across the bucket(s) it spans
        b0 = int(lba / sectors_per_bucket)
        b1 = int((lba + ln - 1) / sectors_per_bucket)
        if b0 == b1:
            arr = reads if m.group("op") == "R" else writes
            if 0 <= b0 < grid:
                arr[b0] += ln
        else:
            arr = reads if m.group("op") == "R" else writes
            for b in range(max(0, b0), min(grid, b1 + 1)):
                lo = b * sectors_per_bucket
                hi = (b + 1) * sectors_per_bucket
                ov = min(hi, lba + ln) - max(lo, lba)
                if ov > 0:
                    arr[b] += int(ov)
    buckets = [{"r": reads[i], "w": writes[i]} for i in range(grid)]
    return {
        "has_trace": n_req > 0,
        "grid": grid,
        "n_req": n_req,
        "sectors": DISK_SECTORS,
        "sectors_per_bucket": int(sectors_per_bucket),
        "max_lba": max_lba,
        "buckets": buckets,
    }


# ── launch-time / session listing ─────────────────────────────────────────────
def _launch_info(sid, log_path, log_stat):
    """Absolute + relative launch time, anchored to the host clock. Reads
    started_at from <sid>.json; falls back to the serial log's first-mtime
    (best available proxy) when the json is missing."""
    started = None
    src = "json"
    meta = os.path.join(HARNESS_DIR, sid + ".json")
    if os.path.exists(meta):
        try:
            m = json.load(open(meta))
            if isinstance(m.get("started_at"), (int, float)):
                started = float(m["started_at"])
        except Exception:
            pass
    if started is None:
        # fallback: earliest known timestamp for the log (ctime ~ creation)
        try:
            started = log_stat.st_ctime
            src = "log-ctime"
        except Exception:
            started = None
    return started, src


def list_sessions():
    out = []
    logs = glob.glob(os.path.join(HARNESS_DIR, "*.serial.log"))
    logs.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
    now = time.time()
    for log in logs:
        sid = os.path.basename(log)[:-len(".serial.log")]
        try:
            st = os.stat(log)
        except OSError:
            continue
        age = int(now - st.st_mtime)
        feats, running, pid = "", None, None
        started_at, started_src = _launch_info(sid, log, st)
        meta = os.path.join(HARNESS_DIR, sid + ".json")
        if os.path.exists(meta):
            try:
                m = json.load(open(meta))
                feats = m.get("features", "") or ""
                running = m.get("running")
                pid = m.get("pid")
            except Exception:
                pass
        elapsed = (now - started_at) if started_at else None
        s = {"sid": sid, "features": feats, "size": st.st_size,
             "age": age, "active": age < 20, "running": running, "pid": pid,
             "started_at": started_at, "started_src": started_src,
             "elapsed": int(elapsed) if elapsed is not None else None,
             "mtime": st.st_mtime}
        if age < GATE_SCAN_MAX_AGE:
            p = scan_progress(log)   # SAME source as the milestone rail
            s.update({"gate": p.get("gate"), "gate_idx": p.get("gate_idx"),
                      "gate_max": p.get("gate_max"), "sc": p.get("sc"),
                      "tick": p.get("tick"), "panic": p.get("panic")})
        out.append(s)
    return out


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>AstryxOS · serial monitor</title>
<style>
 :root{--bg:#0b0e14;--panel:#11151f;--edge:#1e2533;--fg:#c9d1d9;--dim:#5c6675;--accent:#39d353}
 *{box-sizing:border-box} html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);
   font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
 #app{display:flex;height:100vh}
 #side{width:340px;min-width:340px;border-right:1px solid var(--edge);overflow:auto;background:var(--panel)}
 #shead{padding:10px 12px;border-bottom:1px solid var(--edge);position:sticky;top:0;background:var(--panel);z-index:2}
 #shead h1{font-size:13px;margin:0 0 8px;letter-spacing:.5px} #shead h1 small{color:var(--dim);font-weight:400}
 input,button{background:#0b0e14;border:1px solid var(--edge);color:var(--fg);border-radius:5px;padding:5px 8px;font:inherit}
 button{cursor:pointer} button:hover{border-color:var(--accent)}
 #q{width:100%} #shead label{color:var(--dim);font-size:11px;cursor:pointer;display:inline-block;margin-top:6px}
 .s{padding:9px 12px;border-bottom:1px solid var(--edge);cursor:pointer}
 .s:hover{background:#161b27} .s.sel{background:#1b2230;border-left:3px solid var(--accent);padding-left:9px}
 .s .sid{font-weight:600} .s .meta{color:var(--dim);font-size:11px;margin-top:2px}
 .s .launch{color:#56b6c2;font-size:10px;margin-top:2px}
 .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:#37404f;vertical-align:middle}
 .dot.on{background:var(--accent);box-shadow:0 0 6px var(--accent)} .dot.panic{background:#ff7b72;box-shadow:0 0 6px #ff7b72}
 .gate{margin-top:5px;height:5px;background:#1b2230;border-radius:3px;overflow:hidden}
 .gate>i{display:block;height:100%;background:var(--accent)} .gate.gp>i{background:#d2a8ff} .gate.ge>i{background:#ff7b72}
 .glab{font-size:10px;color:var(--dim);margin-top:3px} .glab b{color:#7ee787}
 #main{flex:1;display:flex;flex-direction:column;min-width:0}
 #bar{padding:7px 12px;border-bottom:1px solid var(--edge);background:var(--panel);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
 #bar .t{font-weight:600} #bar .badge{font-size:11px;color:#7ee787;border:1px solid var(--edge);padding:2px 7px;border-radius:10px}
 #bar .x{color:var(--dim);font-size:11px} #bar label{color:var(--dim);cursor:pointer;font-size:11px}
 #bar button{font-size:11px;padding:3px 8px}
 #flt{width:150px}
 #logwrap{flex:1;display:flex;min-height:0}
 #log{flex:1;overflow:auto;padding:8px 12px;white-space:pre-wrap;word-break:break-all}
 #log .l{display:block} #log .l:hover{background:#11151f} #log .l.hide{display:none}
 #log .l.gatehit{background:#1b2230;border-left:3px solid var(--accent);padding-left:6px;font-weight:600}
 mark{background:#7c5cff;color:#fff;border-radius:2px}
 .ff{color:#7ee787} .err{color:#ff7b72;font-weight:600} .warn{color:#f0c674}
 .met{color:#56b6c2} .futex{color:#6b7686} .png{color:#d2a8ff;font-weight:600}
 #empty{color:var(--dim);padding:24px}
 #miles{display:flex;flex-wrap:wrap;gap:6px;padding:8px 12px;border-bottom:1px solid var(--edge);background:#0d111a}
 #miles:empty{display:none}
 .mile{font-size:11px;padding:3px 9px;border-radius:12px;border:1px solid var(--edge);color:var(--dim);background:#11151f;white-space:nowrap}
 .mile.hit{color:#7ee787;border-color:#214a2c;background:#0e1c14;cursor:pointer}
 .mile.hit:hover{box-shadow:0 0 6px rgba(126,231,135,.5)}
 .mile.hit.last{border-color:var(--accent);box-shadow:0 0 6px rgba(57,211,83,.4)}
 .mile.png{color:#d2a8ff;border-color:#3a2a52;background:#160e22} .mile b{color:#56b6c2;font-weight:600}
 .mile .dlt,.rstep .dlt{color:#f0c674;font-weight:600} .rstep .rel{color:#56b6c2}
 /* right-hand progression rail overlay */
 #rail{width:0;transition:width .15s;overflow:hidden;border-left:1px solid var(--edge);background:#0d111a}
 #rail.open{width:210px;min-width:210px;overflow:auto}
 #rail h3{font-size:11px;color:var(--dim);margin:10px 12px 4px;letter-spacing:.5px;text-transform:uppercase}
 .rstep{display:flex;align-items:flex-start;gap:8px;padding:5px 12px;font-size:11px;position:relative}
 .rstep .ic{width:14px;flex:none;text-align:center;color:#37404f}
 .rstep.hit .ic{color:var(--accent)} .rep .lab{color:var(--dim)}
 .rstep.hit{cursor:pointer} .rstep.hit:hover{background:#161b27}
 .rstep.hit .lab{color:#7ee787} .rstep.last{background:#1b2230;border-left:3px solid var(--accent)}
 .rstep .lab small{display:block;color:var(--dim);font-size:10px}
 .rstep::before{content:'';position:absolute;left:18px;top:18px;bottom:-5px;width:1px;background:var(--edge)}
 .rstep:last-child::before{display:none}
 /* banner */
 #banner{display:none;padding:6px 12px;font-size:12px;font-weight:600;color:#0b0e14;background:#ff7b72}
 #banner.warn{background:#f0c674} #banner.stall{background:#d2a8ff}
 /* metrics panel */
 #metrics{display:none;border-bottom:1px solid var(--edge);background:#0d111a;padding:7px 12px;gap:14px;flex-wrap:wrap;align-items:stretch}
 #metrics.show{display:flex}
 .gm{min-width:118px} .gm .k{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
 .gm .v{font-size:15px;font-weight:600;color:#7ee787} .gm .v small{font-size:10px;color:var(--dim);font-weight:400}
 .gm canvas{display:block;margin-top:2px}
 .gm.mem .bar{height:6px;background:#1b2230;border-radius:3px;margin-top:4px;overflow:hidden}
 .gm.mem .bar>i{display:block;height:100%;background:#d2a8ff}
 #pids{display:none;border-bottom:1px solid var(--edge);background:#0b0e14;padding:5px 12px;font-size:11px;overflow-x:auto;white-space:nowrap}
 #pids.show{display:block} #pids .p{display:inline-block;margin-right:14px;color:var(--dim)}
 #pids .p b{color:#56b6c2} #pids .p .sc{color:#7ee787}
 /* block map */
 #blk{display:none;border-bottom:1px solid var(--edge);background:#0d111a;padding:7px 12px}
 #blk.show{display:block} #blk .hd{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
 #blk .hd b{color:#56b6c2} #blkcanvas{display:block;width:100%;height:34px;image-rendering:pixelated;border:1px solid var(--edge);border-radius:3px}
 #blk .hint{color:var(--dim);font-size:11px} #blk .lg{font-size:10px;color:var(--dim);margin-top:3px}
 #blk .lg i{display:inline-block;width:9px;height:9px;border-radius:2px;vertical-align:middle;margin:0 3px 0 9px}
 .toggles{display:flex;gap:6px} .toggles button.on{border-color:var(--accent);color:#7ee787}
</style></head><body><div id=app>
 <div id=side>
   <div id=shead><h1>AstryxOS serial <small id=cnt></small></h1>
     <input id=q placeholder="filter sessions (sid / features)…">
     <label><input type=checkbox id=onlyactive checked> active &amp; recent only</label>
     &nbsp;<label><input type=checkbox id=autolive> auto-follow live</label></div>
   <div id=list></div></div>
 <div id=main>
   <div id=bar><span class=t id=title>— select a session —</span>
     <span class=badge id=gate style=display:none></span>
     <span class=x id=sc></span><span class=x id=rate></span>
     <span class=x id=launch></span>
     <span style=flex:1></span>
     <span class=toggles>
       <button id=tMetrics class=on title="guest metrics + sparklines">metrics</button>
       <button id=tBlk title="data.img block map (needs blk-trace)">blkmap</button>
       <button id=tRail class=on title="gate progression rail">rail</button>
     </span>
     <input id=flt placeholder="filter lines…"><label><input type=checkbox id=follow checked> follow</label>
     <button id=jumpLive style=display:none>↧ live</button>
     <button id=jumpGate title="jump to last gate / PNG / panic">⤓ last</button>
   </div>
   <div id=banner></div>
   <div id=metrics class=show></div>
   <div id=pids></div>
   <div id=blk></div>
   <div id=miles></div>
   <div id=logwrap>
     <div id=log><div id=empty>Pick a session on the left to stream its serial output.</div></div>
     <div id=rail class=open></div>
   </div>
 </div></div>
<script>
let cur=null,es=null,sessions=[],rate={n:0,t:Date.now()};
let miles=[],frozen=false,metaCur=null;
let mPrev=null,mTime=0;                       // last metrics sample (for rate deltas)
const buf={sc:[],pf:[],dio:[],iops:[],net:[]}; // rolling sparkline buffers
const BUFMAX=60;
const list=document.getElementById('list'),log=document.getElementById('log');
const $=id=>document.getElementById(id);
const fmt=s=>s==null?'':s<60?s+'s':s<3600?(s/60|0)+'m':Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m';
const human=n=>n==null?'':n>=1e9?(n/1e9).toFixed(1)+'G':n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':(''+Math.round(n));
const bytes=n=>n==null?'':n>=1e9?(n/1073741824).toFixed(1)+'GB':n>=1e6?(n/1048576).toFixed(1)+'MB':n>=1e3?(n/1024).toFixed(1)+'KB':n+'B';
function utc(ts){if(!ts)return '';const d=new Date(ts*1000);return d.toISOString().slice(11,19)+' UTC';}
function classify(t){
  if(/PANIC|HEAP GUARD|SCHEDULER_DEADLOCK|bugcheck|\\bFAIL\\b|#PF|#GP|#UD|channel error/.test(t))return'err';
  if(/89504e47|drawSnapshot|out\\.png|libpng|CrossProcessPaint|kdb-read-png/.test(t))return'png';
  if(/^\\[FF\\/|ScreenshotParent|getDimensions|isForBrowser|Established/.test(t))return'ff';
  if(/WARN|WARNING/.test(t))return'warn';
  if(/PROC-METRICS|\\[HB\\] tick|\\[BLK\\] /.test(t))return'met';
  if(/FUTEX|CLEARTID|UNIXPOLL/.test(t))return'futex';
  return'';}
function gateClass(s){return s.panic?'gate ge':s.gate_idx>=((s.gate_max||15)-3)?'gate gp':'gate';}
function render(){
  const q=$('q').value.toLowerCase(),onlyA=$('onlyactive').checked;
  let r=sessions.filter(s=>(!onlyA||s.active||s.age<600)&&(!q||s.sid.includes(q)||(s.features||'').toLowerCase().includes(q)));
  $('cnt').textContent='('+r.length+'/'+sessions.length+')';
  list.innerHTML=r.map(s=>{
    const pct=s.gate_idx!=null?Math.round(s.gate_idx/(s.gate_max||15)*100):0;
    const gl=s.gate?`<div class=glab>gate <b>${s.gate}</b> ${s.gate_idx}/${s.gate_max||15}${s.sc!=null?' · sc '+human(s.sc):''}${s.panic?' · ⚠ panic':''}</div>`:'';
    const gb=s.gate_idx!=null?`<div class="${gateClass(s)}"><i style=width:${pct}%></i></div>${gl}`:'';
    const lt=s.started_at?`<div class=launch>▸ ${utc(s.started_at)} · ${fmt(s.elapsed)} ago${s.started_src!=='json'?' (≈)':''}</div>`:'';
    return `<div class="s${s.sid===cur?' sel':''}" data-sid="${s.sid}">
     <div class=sid><span class="dot ${s.panic?'panic':s.active?'on':''}"></span>${s.sid}</div>
     <div class=meta>${(s.features||'—').slice(0,40)} · ${(s.size/1024|0)}KB · ${fmt(s.age)} ago${s.active?' · live':''}</div>${lt}${gb}</div>`;
  }).join('')||'<div id=empty>No matching sessions.</div>';
  list.querySelectorAll('.s').forEach(e=>e.onclick=()=>openS(e.dataset.sid));
}
async function refresh(){
  try{sessions=await(await fetch('/api/sessions')).json()}catch(e){return}
  if($('autolive').checked){const live=sessions.find(s=>s.active);if(live&&live.sid!==cur)openS(live.sid);}
  const c=sessions.find(s=>s.sid===cur); metaCur=c||metaCur;
  if(c){const g=$('gate');if(c.gate){g.style.display='';g.textContent='gate '+c.gate+' '+c.gate_idx+'/'+(c.gate_max||15);g.style.color=c.panic?'#ff7b72':c.gate_idx>=((c.gate_max||15)-3)?'#d2a8ff':'#7ee787';}
        $('sc').textContent=c.sc!=null?'sc '+human(c.sc):'';
        $('launch').textContent=c.started_at?('⏱ '+utc(c.started_at)+' · up '+fmt(c.elapsed)):'';
        banner(c);}
  render();
}
function banner(c){
  const b=$('banner');
  if(c.panic){b.className='';b.style.display='block';b.textContent='⚠ KERNEL FAULT — panic / heap-guard / deadlock / bugcheck detected in tail';return;}
  // stall alert: active session whose lines/sec has gone to ~0
  if(c.active&&rate.last!=null&&rate.last<1&&c.gate_idx<((c.gate_max||15)-1)){b.className='stall';b.style.display='block';b.textContent='◷ STALL — serial output ~0 lines/s on a live session (gate '+(c.gate||'?')+')';return;}
  b.style.display='none';
}
function openS(sid){
  cur=sid; document.getElementById('title').textContent=sid; log.innerHTML=''; frozen=false;
  if(es)es.close(); rate={n:0,t:Date.now(),last:null}; mPrev=null;
  for(const k in buf)buf[k]=[];
  $('jumpLive').style.display='none';
  startStream(sid);
  render(); loadMiles(sid); pollMetrics(); pollBlk();
}
function startStream(sid){
  if(es)es.close();
  es=new EventSource('/api/stream?sid='+encodeURIComponent(sid));
  es.onmessage=ev=>{
    if(frozen)return;            // viewing a gate context region — don't append live
    rate.n++;
    appendLine(ev.data);
    if(log.childElementCount>6000)for(let i=0;i<1500;i++)log.removeChild(log.firstChild);
    if($('follow').checked&&!log.lastChild.classList.contains('hide'))log.scrollTop=log.scrollHeight;
  };
}
function appendLine(text,nNum,isGate){
  const d=document.createElement('span'); d.className='l '+classify(text)+(isGate?' gatehit':'');
  d.dataset.t=text.toLowerCase(); if(nNum)d.dataset.n=nNum; d.textContent=text;
  applyFlt(d); log.appendChild(d); return d;
}
// elapsed/delta seconds -> "+2m14s" / "Δ +18s". `approx` (tick-derived, no exact
// watcher mark) gets a leading '~' so it's never confused with a live stamp.
function dur(s){if(s==null)return '';s=Math.round(s);if(s<60)return s+'s';
  const m=Math.floor(s/60),r=s%60;return m<60?m+'m'+(r?r+'s':''):Math.floor(m/60)+'h'+(m%60)+'m';}
function elapStr(x){if(x.host_elapsed==null)return '';return (x.approx?'~+':'+')+dur(x.host_elapsed);}
function deltaStr(x){if(x.host_delta==null)return '';return 'Δ '+(x.approx?'~+':'+')+dur(x.host_delta);}
async function loadMiles(sid){
  let m; try{m=await(await fetch('/api/milestones?sid='+encodeURIComponent(sid))).json()}catch(e){return}
  if(sid!==cur)return; miles=m;
  let lastHit=-1; m.forEach((x,i)=>{if(x.hit)lastHit=i;});
  // top milestone chips: label + elapsed-since-launch + per-gate Δ (the compare
  // signal). Absolute wall time + line/tick provenance live in the tooltip.
  $('miles').innerHTML=m.map((x,i)=>{
    const cls='mile'+(x.hit?' hit':'')+(i===lastHit?' last':'')+(/PNG|drawSnapshot/.test(x.label)?' png':'');
    const el=x.hit?elapStr(x):'', dl=x.hit?deltaStr(x):'';
    const timing=(el||dl)?(' <b>'+el+'</b>'+(dl?' <span class=dlt>'+dl+'</span>':'')):'';
    const wall=x.host_ts!=null?(' · '+utc(x.host_ts)):'';
    const ti=x.hit?('line '+x.line+(x.tick!=null?' · tick '+x.tick:'')+(x.dtick!=null?' · +'+x.dtick+' ticks':'')+(x.host_elapsed!=null?' · '+(x.approx?'≈':'')+'+'+dur(x.host_elapsed)+' since launch'+(x.host_delta!=null?', Δ+'+dur(x.host_delta)+' vs prev gate':''):'')+wall+(x.approx?' (tick-derived approx)':'')+' — click to jump'):'not reached';
    return '<span class="'+cls+'" data-line="'+(x.line||'')+'" data-label="'+x.label+'" title="'+ti+'">'+(x.hit?'✓':'○')+' '+x.label+timing+'</span>';
  }).join('');
  $('miles').querySelectorAll('.mile.hit').forEach(e=>{if(e.dataset.line)e.onclick=()=>jumpToLine(+e.dataset.line,e.dataset.label);});
  // right-hand progression rail: same per-gate elapsed + Δ, stacked.
  $('rail').innerHTML='<h3>progression</h3>'+m.map((x,i)=>{
    const cls='rstep'+(x.hit?' hit':'')+(i===lastHit?' last':'');
    const el=x.hit?elapStr(x):'', dl=x.hit?deltaStr(x):'';
    const tline='line '+x.line+(x.tick!=null?' · @'+human(x.tick):'');
    const sub=x.hit?((el?'<span class=rel>'+el+(dl?' · <span class=dlt>'+dl+'</span>':'')+'</span>':'')+tline):'not yet';
    return '<div class="'+cls+'" data-line="'+(x.line||'')+'" data-label="'+x.label+'"><span class=ic>'+(x.hit?'✓':'○')+'</span>'
      +'<span class=lab>'+x.label+'<small>'+sub+'</small></span></div>';
  }).join('');
  $('rail').querySelectorAll('.rstep.hit').forEach(e=>{if(e.dataset.line)e.onclick=()=>jumpToLine(+e.dataset.line,e.dataset.label);});
}
// jump the log view to a gate's serial line: disable follow, freeze the live
// stream, fetch the ±ctx context window, render it with the gate line marked.
async function jumpToLine(line,label){
  if(!line||!cur)return;
  $('follow').checked=false; frozen=true; $('jumpLive').style.display='';
  let d; try{d=await(await fetch('/api/context?sid='+encodeURIComponent(cur)+'&line='+line+'&ctx=400')).json()}catch(e){return}
  log.innerHTML=''; let target=null;
  d.lines.forEach(ln=>{const el=appendLine(ln.t,ln.n,ln.n===line);if(ln.n===line)target=el;});
  const hdr=document.createElement('div');hdr.style.cssText='color:#39d353;padding:2px 0 6px;font-weight:600';
  hdr.textContent='▸ context around '+(label||('line '+line))+' (lines '+d.start+'–'+d.end+'). Click ↧ live to resume.';
  log.insertBefore(hdr,log.firstChild);
  if(target)target.scrollIntoView({block:'center'});
}
function jumpLive(){frozen=false;$('follow').checked=true;$('jumpLive').style.display='none';log.innerHTML='';startStream(cur);}
// jump-to-interesting: scan loaded log for PNG / panic / last gate, scroll to it
function jumpGate(){
  const els=[...log.querySelectorAll('.l')];
  let t=els.reverse().find(e=>/89504e47|out\\.png|PANIC|HEAP GUARD|SCHEDULER_DEADLOCK|bugcheck|ScreenshotParent/.test(e.textContent));
  if(t){t.scrollIntoView({block:'center'});t.style.outline='2px solid #d2a8ff';setTimeout(()=>t.style.outline='',1500);}
  else if(miles.length){const lh=[...miles].reverse().find(x=>x.hit);if(lh&&lh.line)jumpToLine(lh.line,lh.label);}
}
function applyFlt(el){const f=$('flt').value.toLowerCase();if(!f){el.classList.remove('hide');return;}el.classList.toggle('hide',!el.dataset.t.includes(f));}
$('flt').oninput=()=>{const f=$('flt').value.toLowerCase();log.querySelectorAll('.l').forEach(applyFlt);};
$('q').oninput=render; $('onlyactive').onchange=render; $('autolive').onchange=refresh;
$('jumpLive').onclick=jumpLive; $('jumpGate').onclick=jumpGate;

// ── sparklines ────────────────────────────────────────────────────────────
function spark(id,data,color,unit){
  const c=$(id);if(!c)return;const w=c.width=110,h=c.height=26,x=c.getContext('2d');
  x.clearRect(0,0,w,h);if(!data.length)return;
  const mx=Math.max(...data,1e-9);x.strokeStyle=color;x.lineWidth=1;x.beginPath();
  data.forEach((v,i)=>{const px=i/(BUFMAX-1)*w,py=h-2-(v/mx)*(h-4);i?x.lineTo(px,py):x.moveTo(px,py);});
  x.stroke();x.globalAlpha=.13;x.lineTo((data.length-1)/(BUFMAX-1)*w,h);x.lineTo(0,h);x.closePath();x.fillStyle=color;x.fill();x.globalAlpha=1;
}
function push(k,v){buf[k].push(v);if(buf[k].length>BUFMAX)buf[k].shift();}
async function pollMetrics(){
  if(!cur||!$('tMetrics').classList.contains('on'))return;
  let m;try{m=await(await fetch('/api/metrics?sid='+encodeURIComponent(cur))).json()}catch(e){return}
  if(!m||!m.agg){$('metrics').classList.remove('show');return;}
  $('metrics').classList.add('show');
  const now=Date.now()/1000,dt=mPrev?Math.max(now-mTime,.5):0;
  let scR=0,pfR=0,dioR=0,iopsR=0,netR=0;
  if(mPrev&&dt>0){
    scR=Math.max(0,(m.agg.sc-mPrev.sc)/dt);
    pfR=Math.max(0,(m.agg.pf-mPrev.pf)/dt);
    dioR=Math.max(0,((m.agg.disk_r+m.agg.disk_w)-(mPrev.disk_r+mPrev.disk_w))/dt);
    iopsR=Math.max(0,(m.agg.rreq-mPrev.rreq)/dt);
    netR=Math.max(0,((m.agg.net_r+m.agg.net_w)-(mPrev.net_r+mPrev.net_w))/dt);
    push('sc',scR);push('pf',pfR);push('dio',dioR);push('iops',iopsR);push('net',netR);
  }
  mPrev={...m.agg}; mTime=now;
  const memPct=Math.min(100,(m.agg.pf*4096/m.ram_total)*100); // pf*4K vs 2GiB — PROXY
  const cpu=m.hb?('cpu'+m.hb.cpu):'';
  $('metrics').innerHTML=
    gm('sc/s (CPU≈)',human(scR)+' <small>'+cpu+'</small>','sp_sc')+
    gm('pf/s',human(pfR),'sp_pf')+
    memGm(memPct,m.agg.pf)+
    gm('disk B/s',bytes(dioR),'sp_dio')+
    gm('IOPS',human(iopsR)+' <small>rreq</small>','sp_iops')+
    gm('net B/s',bytes(netR),'sp_net');
  spark('sp_sc',buf.sc,'#7ee787');spark('sp_pf',buf.pf,'#f0c674');
  spark('sp_dio',buf.dio,'#56b6c2');spark('sp_iops',buf.iops,'#d2a8ff');spark('sp_net',buf.net,'#ff7b72');
  // per-pid breakdown (top syscall-counts)
  const top=[...m.pids].sort((a,b)=>b.sc-a.sc).slice(0,6);
  $('pids').className='show';
  $('pids').innerHTML='<span style="color:#5c6675">pids:</span> '+top.map(p=>
    `<span class=p><b>${p.pid}</b> ${p.name} <span class=sc>sc ${human(p.sc)}</span> pf ${human(p.pf)} dR ${bytes(p.disk_r)}${p.stuck_nr?' <span style="color:#ff7b72">⊘nr'+p.stuck_nr+'</span>':''}</span>`).join('')||'—';
}
function gm(k,v,cid){return `<div class=gm><div class=k>${k}</div><div class=v>${v}</div><canvas id=${cid}></canvas></div>`;}
function memGm(pct,pf){return `<div class="gm mem"><div class=k>mem proxy</div><div class=v>${pct.toFixed(1)}<small>% · pf×4K/2GiB</small></div><div class=bar><i style=width:${pct}%></i></div></div>`;}

// ── data.img block map ────────────────────────────────────────────────────
let blkGrid=256;
async function pollBlk(){
  if(!cur||!$('tBlk').classList.contains('on'))return;
  let m;try{m=await(await fetch('/api/blkmap?sid='+encodeURIComponent(cur)+'&grid='+blkGrid)).json()}catch(e){return}
  $('blk').className='show';
  if(!m||!m.has_trace){
    $('blk').innerHTML='<div class=hd>data.img block map</div><div class=hint>No <b>[BLK]</b> trace lines in this log. Boot with <b>--features firefox-test,kdb,blk-trace</b> to populate the per-sector heatmap (default builds emit no [BLK] line and pay zero overhead).</div>';
    return;}
  $('blk').innerHTML='<div class=hd>data.img block map · <b>'+human(m.n_req)+'</b> reqs · '+m.grid+' buckets × '+human(m.sectors_per_bucket)+' sectors · max lba '+human(m.max_lba)+'/'+human(m.sectors)+'</div>'
    +'<canvas id=blkcanvas></canvas><div class=lg><i style=background:#39d353></i>read <i style=background:#ff7b72></i>write <i style="background:linear-gradient(90deg,#39d353,#f0c674,#ff7b72)"></i>mixed · brighter = busier</div>';
  drawBlk(m.buckets);
}
function drawBlk(bk){
  const c=$('blkcanvas');if(!c)return;const w=c.width=bk.length,h=c.height=1,x=c.getContext('2d');
  let mr=1,mw=1;bk.forEach(b=>{if(b.r>mr)mr=b.r;if(b.w>mw)mw=b.w;});
  const img=x.createImageData(w,1);
  bk.forEach((b,i)=>{
    const r=b.r/mr,wv=b.w/mw,a=i*4;
    if(b.r===0&&b.w===0){img.data[a]=17;img.data[a+1]=21;img.data[a+2]=31;}
    else{img.data[a]=Math.round(40+wv*215);img.data[a+1]=Math.round(40+r*171);img.data[a+2]=Math.round(40+(r+wv)*30);}
    img.data[a+3]=255;
  });
  x.putImageData(img,0,0);
}

// toggles
function tog(btn,after){btn.onclick=()=>{btn.classList.toggle('on');
  if(btn===$('tRail'))$('rail').classList.toggle('open',btn.classList.contains('on'));
  if(btn===$('tMetrics')&&!btn.classList.contains('on')){$('metrics').classList.remove('show');$('pids').classList.remove('show');}
  if(btn===$('tBlk')&&!btn.classList.contains('on'))$('blk').classList.remove('show');
  if(after&&btn.classList.contains('on'))after();};}
tog($('tMetrics'),pollMetrics);tog($('tBlk'),pollBlk);tog($('tRail'),null);
$('tRail').onclick=()=>{$('tRail').classList.toggle('on');$('rail').classList.toggle('open',$('tRail').classList.contains('on'));};

setInterval(()=>{const now=Date.now(),dt=(now-rate.t)/1000;if(dt>=2){const r=rate.n/dt;rate.last=r;$('rate').textContent=cur?r.toFixed(0)+' ln/s':'';rate={n:0,t:now,last:r};}},1000);
refresh(); setInterval(refresh,3000);
setInterval(()=>{if(cur)loadMiles(cur);},5000);
setInterval(pollMetrics,2000);
setInterval(pollBlk,3000);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _hdr(self, code=200, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()

    def _log_path(self, sid):
        """Validate sid and resolve its serial log inside HARNESS_DIR, or None."""
        if not SID_RE.match(sid):
            return None
        path = os.path.join(HARNESS_DIR, sid + ".serial.log")
        if not os.path.realpath(path).startswith(os.path.realpath(HARNESS_DIR)):
            return None
        return path if os.path.exists(path) else None

    def _json(self, obj):
        self._hdr(ctype="application/json")
        self.wfile.write(json.dumps(obj).encode())

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            self._hdr(); self.wfile.write(PAGE.encode())
        elif u.path == "/api/sessions":
            self._json(list_sessions())
        elif u.path == "/api/milestones":
            sid = q.get("sid", [""])[0]
            p = self._log_path(sid)
            if not p:
                self._hdr(404, "text/plain"); self.wfile.write(b"no log"); return
            self._json(scan_milestones_timed(sid, p))
        elif u.path == "/api/context":
            p = self._log_path(q.get("sid", [""])[0])
            if not p:
                self._hdr(404, "text/plain"); self.wfile.write(b"no log"); return
            try:
                line = int(q.get("line", ["1"])[0])
                ctx = int(q.get("ctx", ["400"])[0])
            except ValueError:
                self._hdr(400, "text/plain"); self.wfile.write(b"bad args"); return
            self._json(read_context(p, line, ctx))
        elif u.path == "/api/metrics":
            p = self._log_path(q.get("sid", [""])[0])
            if not p:
                self._hdr(404, "text/plain"); self.wfile.write(b"no log"); return
            try:
                size = os.path.getsize(p)
            except OSError:
                size = 0
            self._json(scan_metrics(p, size))
        elif u.path == "/api/blkmap":
            p = self._log_path(q.get("sid", [""])[0])
            if not p:
                self._hdr(404, "text/plain"); self.wfile.write(b"no log"); return
            try:
                size = os.path.getsize(p)
                grid = int(q.get("grid", ["256"])[0])
            except (OSError, ValueError):
                size, grid = 0, 256
            self._json(scan_blkmap(p, size, grid))
        elif u.path == "/api/stream":
            self._stream(q.get("sid", [""])[0])
        else:
            self._hdr(404, "text/plain"); self.wfile.write(b"404")

    def _stream(self, sid):
        path = self._log_path(sid)
        if not path:
            self._hdr(400 if not SID_RE.match(sid) else 404, "text/plain")
            self.wfile.write(b"bad sid" if not SID_RE.match(sid) else b"no log")
            return
        self._hdr(ctype="text/event-stream", extra={
            "Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - TAIL_BYTES))
                if size > TAIL_BYTES:
                    f.readline()
                buf = b""
                idle = 0
                while True:
                    chunk = f.read(65536)
                    if chunk:
                        idle = 0
                        buf += chunk
                        *lines, buf = buf.split(b"\n")
                        for ln in lines:
                            self.wfile.write(b"data: " + ln.replace(b"\r", b"") + b"\n\n")
                        self.wfile.flush()
                    else:
                        idle += 1
                        if idle % 30 == 0:
                            self.wfile.write(b": ka\n\n"); self.wfile.flush()
                        time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("SERIAL_WEB_PORT", 8088)))
    ap.add_argument("--host", default=os.environ.get("SERIAL_WEB_HOST", "0.0.0.0"))
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), H)
    srv.daemon_threads = True
    print(f"[serial-web] serving {HARNESS_DIR} on http://{a.host}:{a.port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
