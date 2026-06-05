#!/usr/bin/env python3
"""perf-bench.py — non-interactive, structured-JSON performance-measurement
driver for the AstryxOS Firefox-headless test.

The Firefox-headless screenshot test currently takes 30+ minutes to produce a
usable PNG. This tool measures that test END-TO-END, broken into a 14-phase
taxonomy (BUILD .. TEARDOWN), so a per-revision time-series makes slow-compile
or slow-boot regressions visible over time, and lets the run be compared against
a typical Linux distro baseline under KVM.

Every subcommand is ONE-SHOT argv -> structured JSON -> exit. No REPL, no
prompt, no persistent stdin. State lives on disk:

  STORE (two-tier, per design):
    .perf/baseline.json                  committed, in-repo — a small curated set
                                         of golden reference records (current HEAD
                                         + the Linux baseline) that travels with
                                         the branch and is reviewed in PRs.
    ~/.astryx-perf/timeseries.jsonl      rolling, host-local — one JSON record per
                                         line, append-only, additive fields only.
                                         This is the full per-run history; it is
                                         NOT committed (it is machine-local and
                                         grows without bound).

SUBCOMMANDS
  run [--rev SHA] [--features F] [--url U] [--build-only] [--no-build]
      [--check-only] [--dry-run]
        Measure a revision end-to-end: time the build (host wall-clock around the
        REAL `harness build` = codegen + link + ESP stage, so a slow-codegen or
        slow-link regression is visible; --check-only uses the faster type-check
        `harness check` probe instead), boot via the harness, extract per-phase
        durations from the serial markers, append a record to the time-series.
        With --rev it checks out + builds that past revision first. In THIS
        workflow `run` is gated to BUILD-ONLY (no boot) unless explicitly unlocked.
  import-logs [--limit N] [--glob G] [--out -]
        Retroactively parse existing ~/.astryx-harness/*.serial.log into
        time-series records using the phase taxonomy + host-anchoring. The true
        host launch time + kvm_effective are recovered from the first
        <sid>.events.jsonl line (the cpu_model event the harness writes AT launch)
        when the session <sid>.json is gone — so iso_ts is the real launch, NOT
        the run-END log mtime. Revisions are attributed by mtime ordering (no
        per-revision boot banner exists yet).
  baseline-linux ...
        Stub — the linux-baseline component fills this in. Emits a placeholder
        record shape so the schema is pinned.
  list [--limit N] [--rev SHA] [--source S]
        Read the store and print records (newest first).
  export-json [--out FILE]
        Dump the merged store (baseline.json + timeseries.jsonl) as one JSON array.

RECORD SCHEMA (one JSON object per line in timeseries.jsonl; additive-only —
never rename a field, downstream tolerates extra keys but breaks on renames):
  revision        str   git short sha of the kernel under test (going-forward
                        boot banner, or mtime-bisect for historical)
  short_desc      str   commit subject (`git show -s --format=%s <sha>`)
  iso_ts          str   ISO-8601 UTC of the run = host started_at
  host            str   hostname (Arrythmia/Quackie — runs are 2-host-race-sensitive)
  kvm             bool  kvm_effective from session json (None if unknown)
  smp             int   vCPU count (None if unknown)
  features        str   the --features flag string (authoritative, from json)
  features_inferred [str] features inferred from serial markers (historical logs)
  phase_ms        obj   {phase_name: ms|null} — per-phase duration, tick axis on
                        import, host axis on a live run
  phase_axis      obj   {phase_name: "tick"|"host"} — which axis phase_ms is on
  phase_lines     obj   {phase_name: {from,to}} — serial line numbers (provenance)
  total_ms        int|null  host(QEMU-exit) - started_at for a live run; null on
                        import (no host anchor survives), where total_tick_ms is
                        the recoverable proxy
  total_tick_ms   float|null  (max_tick - first_tick) * 10ms — kernel-tick total
  max_sc          int   deepest pid=1 syscall count
  deepest_phase   str   deepest taxonomy phase reached
  reached_png     bool  did the run produce a PNG (89504e47 / out.png)
  panic           bool  kernel fault detected in the log
  build_ms        int|null  host wall-clock of the cargo build (null on import)
  source          str   "run" | "import" | "baseline-linux"
  sid             str   harness session id (provenance back to the serial log)
  schema_v        int   record schema version (1)

Public-spec note: the 100 Hz timer figure used for tick->ms is the kernel's
published PIT/APIC rate; 1 tick = 10 ms.
"""

import os
import sys
import json
import time
import glob
import socket
import argparse
import datetime
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import perf_markers as pm   # noqa: E402
import gate_marks as gmk    # noqa: E402  (gate<->phase mapping + marks sidecar)

SCHEMA_V = 1
HARNESS_DIR = os.path.expanduser(os.environ.get("ASTRYX_HARNESS_DIR",
                                                "~/.astryx-harness"))
HARNESS_DIR = os.path.expanduser(HARNESS_DIR)
PERF_DIR = os.path.expanduser(os.environ.get("ASTRYX_PERF_DIR", "~/.astryx-perf"))
TIMESERIES = os.path.join(PERF_DIR, "timeseries.jsonl")


def _repo_root():
    """Repo root of THIS script's checkout (the worktree)."""
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], cwd=here, text=True,
            stderr=subprocess.DEVNULL).strip()
        return out
    except Exception:
        return os.path.dirname(here)


REPO_ROOT = _repo_root()
# Committed reference store. Overridable via ASTRYX_PERF_BASELINE so a test (or a
# caller pointing at a different branch's reference) can isolate from the in-repo
# .perf/baseline.json. Default = the committed file that travels with the branch.
BASELINE_JSON = os.environ.get("ASTRYX_PERF_BASELINE",
                               os.path.join(REPO_ROOT, ".perf", "baseline.json"))


# ── git helpers ──────────────────────────────────────────────────────────────
def _git(args, cwd=REPO_ROOT):
    try:
        return subprocess.check_output(["git"] + args, cwd=cwd, text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def _short_sha(rev="HEAD"):
    return _git(["rev-parse", "--short", rev]) or "unknown"


def _commit_subject(rev="HEAD"):
    return _git(["show", "-s", "--format=%s", rev]) or ""


def _iso_utc(epoch=None):
    if epoch is None:
        epoch = time.time()
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc).isoformat(timespec="seconds")


# ── store I/O ────────────────────────────────────────────────────────────────
def _append_timeseries(record):
    os.makedirs(PERF_DIR, exist_ok=True)
    with open(TIMESERIES, "a") as f:
        f.write(json.dumps(record) + "\n")


def _read_timeseries():
    out = []
    if os.path.exists(TIMESERIES):
        with open(TIMESERIES, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def _read_baseline():
    if os.path.exists(BASELINE_JSON):
        try:
            d = json.load(open(BASELINE_JSON))
            if isinstance(d, dict) and isinstance(d.get("records"), list):
                return d["records"]
            if isinstance(d, list):
                return d
        except Exception:
            pass
    return []


# ── core: build one record from a serial log ─────────────────────────────────
def _record_from_log(log_path, sid, revision, short_desc, host, source,
                      started_at=None, build_ms=None, total_ms=None,
                      features_auth=None, kvm=None, smp=None):
    """Construct a time-series record from a single serial log + metadata.

    Tick-axis phase durations come straight from the marker scan; the host axis
    (total_ms, build_ms) is only supplied for a live `run`."""
    scan = pm.scan_phase_boundaries(log_path)
    durations = pm.phase_durations(scan)

    phase_ms = {}
    phase_axis = {}
    phase_lines = {}
    for name in pm.PHASE_NAMES:
        d = durations[name]
        # On import, the recoverable measurement is the tick axis. Host-axis
        # phases (early boot) have no per-line host stamp on a historical log,
        # so their phase_ms is null but their provenance lines are recorded.
        phase_ms[name] = d["tick_ms"]
        # `phase_axis` reports the axis the value ACTUALLY came from: "tick" when
        # a kernel-tick delta was recovered, else the design's intended axis
        # ("host") with a null value. This keeps a consumer from mistaking a
        # real tick measurement for a host-clock one. The design's intended axis
        # is preserved separately in pm.PHASE_AXIS for reference.
        phase_axis[name] = ("tick" if d["tick_ms"] is not None
                            else d["axis"])
        phase_lines[name] = {"from": d["from_line"], "to": d["to_line"]}

    anchors = scan.get("anchors", {})
    # first kernel tick anywhere (for total_tick_ms): smallest tick stamped on
    # any anchor that has one, else None.
    first_tick = None
    for a in anchors.values():
        t = a.get("tick")
        if t is not None and (first_tick is None or t < first_tick):
            first_tick = t
    total_tick_ms = None
    if first_tick is not None and scan.get("max_tick") is not None \
            and scan["max_tick"] >= first_tick:
        total_tick_ms = pm.ticks_to_ms(scan["max_tick"] - first_tick)

    deepest_phase = _deepest_phase(durations)
    # reached_png is a GLOBAL test: did the PNG magic (89504e47) appear ANYWHERE
    # in the log. The previous gate (anchors.get("png_written")) under-reported
    # success because png_written sits behind the monotone anchor chain, which
    # stalls on a no-network (file://) render or the old libpng startup-marker
    # bug — so genuine PNG runs were recorded as failures. For a render-to-PNG
    # benchmark, success must be detected honestly regardless of the chain.
    reached_png = bool(scan.get("png_seen"))

    rec = {
        "schema_v": SCHEMA_V,
        "revision": revision,
        "short_desc": short_desc,
        "iso_ts": _iso_utc(started_at) if started_at else _iso_utc(
            os.path.getmtime(log_path) if os.path.exists(log_path) else None),
        "host": host,
        "kvm": kvm,
        "smp": smp,
        "features": features_auth if features_auth is not None else "",
        "features_inferred": pm.infer_features(log_path),
        "phase_ms": phase_ms,
        "phase_axis": phase_axis,
        "phase_lines": phase_lines,
        "total_ms": total_ms,
        "total_tick_ms": total_tick_ms,
        "max_sc": scan.get("max_sc"),
        "deepest_phase": deepest_phase,
        "reached_png": reached_png,
        "panic": scan.get("panic", False),
        "build_ms": build_ms,
        "source": source,
        "sid": sid,
        "markers_source": pm.MARKERS_SOURCE,
        # provenance: which serial line proved the PNG, and the deepest anchor in
        # the (optional-tolerant) monotone chain. Lets a consumer see that a PNG
        # was detected globally even when the in-order chain stalled earlier.
        "png_line": (anchors.get("png_written") or {}).get("line"),
        "deepest_anchor": scan.get("deepest_anchor"),
    }
    return rec


def _deepest_phase(durations):
    """Deepest phase whose `from` boundary was reached, in taxonomy order."""
    deepest = None
    for name in pm.PHASE_NAMES:
        d = durations[name]
        if d["from_line"] is not None or d["to_line"] is not None:
            deepest = name
    return deepest


# ── gate-marks -> phase_ms (the serial-monitor <-> perf-dashboard bridge) ─────
def _scan_progress_timeline(log_path):
    """Forward-ordered milestone timeline (label/hit/line/tick) for a log, using
    serial-web.py's scan_progress when available (single source of truth), else a
    minimal re-scan with the shared MILESTONES ladder. Returns (timeline, first_tick)."""
    sw = pm._sw  # the serial-web module perf_markers already imported (or None)
    if sw is not None and hasattr(sw, "scan_progress"):
        prog = sw.scan_progress(log_path)
        return prog.get("timeline", []), (prog.get("first_tick") or 0)
    # Fallback: vendored re-scan (mirrors scan_progress' first-hit + dtick logic).
    found, idx, cur_tick, first_tick, n = {}, 0, None, None, 0
    try:
        with open(log_path, "r", errors="replace") as f:
            for line in f:
                n += 1
                tk = pm._TICK_KERNEL.search(line)
                if tk:
                    cur_tick = int(tk.group(1))
                    if first_tick is None:
                        first_tick = cur_tick
                while idx < len(gmk.MILESTONES) and gmk.match(line, gmk.MILESTONES[idx][1]):
                    found[gmk.MILESTONES[idx][0]] = (n, cur_tick)
                    idx += 1
    except OSError:
        pass
    timeline = []
    prev = None
    for lab, _m in gmk.MILESTONES:
        h = found.get(lab)
        dtick = (h[1] - prev) if (h and h[1] is not None and prev is not None) else None
        if h and h[1] is not None:
            prev = h[1]
        timeline.append({"label": lab, "hit": h is not None,
                         "line": h[0] if h else None,
                         "tick": h[1] if h else None, "dtick": dtick})
    return timeline, (first_tick or 0)


def _marks_to_phase_ms(sid, log_path, started_at):
    """Turn a session's gate marks (or tick-derived timeline) into a perf-style
    {phase_name: ms} dict via the shared GATE_TO_PHASE mapping.

    Each gate that ENDS a perf phase (GATE_TO_PHASE[label] is not None) contributes
    its per-gate host_delta (seconds-since-previous-gate) as that phase's ms. The
    delta is the SAME 'compare performance' signal the serial monitor shows, so the
    two dashboards agree by construction.

    Returns (phase_ms, phase_axis, phase_lines, reached_marker, approx_any,
             total_marks_ms, n_marks). `approx_any` is True when ANY contributing
    gate was tick-derived (no exact watcher mark)."""
    timeline, first_tick = _scan_progress_timeline(log_path)
    marks = gmk.read_gate_marks(sid, HARNESS_DIR)
    timed = gmk.gate_timeline(timeline, marks, started_at, first_tick=first_tick)

    phase_ms = {}
    phase_axis = {}
    phase_lines = {}
    approx_any = False
    deepest_label = None
    n_marks = 0
    last_elapsed = None
    for step in timed:
        lab = step.get("label")
        if not step.get("hit"):
            continue
        deepest_label = lab
        if step.get("host_elapsed") is not None:
            last_elapsed = step["host_elapsed"]
            n_marks += 1
        phase = gmk.GATE_TO_PHASE.get(lab)
        if phase is None:
            continue
        d = step.get("host_delta")
        if d is not None:
            phase_ms[phase] = round(d * 1000.0)         # seconds -> ms
            phase_axis[phase] = "host" if not step.get("approx") else "tick"
            phase_lines[phase] = {"to": step.get("line")}
            if step.get("approx"):
                approx_any = True
    total_marks_ms = round(last_elapsed * 1000.0) if last_elapsed is not None else None
    return (phase_ms, phase_axis, phase_lines, deepest_label, approx_any,
            total_marks_ms, n_marks)


# ── subcommand: ingest-marks ─────────────────────────────────────────────────
def cmd_ingest_marks(args):
    """Turn a single session's gate marks into a time-series record so a boot
    watched in the SERIAL MONITOR (:8088) shows up on the PERF dashboard (:8099).

    Builds the base record exactly like `import-logs` (same revision attribution,
    host/kvm/features/png detection, schema), then OVERLAYS the gate-marks-derived
    phase_ms onto it. Additive: every existing field is preserved; new keys are
    `phase_ms_source`, `marks_approx`, `total_marks_ms`, `n_gate_marks`.
    """
    sid = args.sid
    log_path = os.path.join(HARNESS_DIR, sid + ".serial.log")
    if not os.path.exists(log_path):
        print(json.dumps({"ok": False, "error": "no_serial_log",
                          "sid": sid, "path": log_path}))
        return 1

    host = socket.gethostname()
    # revision attribution + launch anchor + session meta — same as import-logs
    commit_timeline = _build_commit_timeline()
    try:
        mtime = os.path.getmtime(log_path)
    except OSError:
        mtime = time.time()
    rev, subj = _attribute_revision(mtime, commit_timeline)
    started_at, launch_src = pm.launch_anchor(sid, log_path, HARNESS_DIR)
    features_auth, kvm, smp = _session_meta(sid)

    # base record (tick-axis phase_ms, png, max_sc, etc. — the import path)
    rec = _record_from_log(
        log_path, sid, rev, subj, host, source="ingest-marks",
        started_at=started_at, features_auth=features_auth, kvm=kvm, smp=smp)
    rec["rev_attribution"] = "mtime-bisect" if rev != "unknown" else "none"
    rec["launch_src"] = launch_src

    # overlay the gate-marks-derived phase durations (host axis when exact)
    (gphase_ms, gphase_axis, gphase_lines, deepest_label, approx_any,
     total_marks_ms, n_marks) = _marks_to_phase_ms(sid, log_path, started_at)

    if n_marks == 0:
        print(json.dumps({
            "ok": False, "error": "no_gate_marks_or_ticks", "sid": sid,
            "note": ("No <sid>.marks.jsonl sidecar AND no recoverable kernel "
                     "ticks at gate lines — nothing to ingest. A LIVE session "
                     "watched through the harness gets a marks sidecar "
                     "automatically; a historical log needs [HB]/PROC-METRICS "
                     "tick lines for the approximate derivation."),
        }, indent=2))
        return 1

    # merge: gate-marks phase_ms takes precedence for the phases it covers; the
    # tick-axis values from _record_from_log fill the rest. Additive-only.
    merged_phase_ms = dict(rec.get("phase_ms") or {})
    merged_phase_axis = dict(rec.get("phase_axis") or {})
    merged_phase_lines = dict(rec.get("phase_lines") or {})
    merged_phase_ms.update(gphase_ms)
    merged_phase_axis.update(gphase_axis)
    for k, v in gphase_lines.items():
        cur = dict(merged_phase_lines.get(k) or {})
        cur.update(v)
        merged_phase_lines[k] = cur
    rec["phase_ms"] = merged_phase_ms
    rec["phase_axis"] = merged_phase_axis
    rec["phase_lines"] = merged_phase_lines

    # additive provenance keys (downstream tolerates extra keys)
    rec["phase_ms_source"] = "gate-marks"
    rec["marks_approx"] = approx_any
    rec["total_marks_ms"] = total_marks_ms
    rec["n_gate_marks"] = n_marks
    rec["deepest_gate"] = deepest_label
    rec["gate_phase_ms"] = gphase_ms   # the gate-only slice, for transparency
    # total_ms: prefer the marks-derived end-to-last-gate when it's exact and the
    # import path left total_ms null (historical anchor lost). Keep additive.
    if rec.get("total_ms") is None and not approx_any and total_marks_ms is not None:
        rec["total_ms"] = total_marks_ms

    if not args.dry_run:
        _append_timeseries(rec)

    print(json.dumps({
        "ok": True,
        "sid": sid,
        "revision": rev,
        "host": host,
        "kvm": kvm,
        "deepest_gate": deepest_label,
        "n_gate_marks": n_marks,
        "marks_approx": approx_any,
        "gate_phase_ms": gphase_ms,
        "total_marks_ms": total_marks_ms,
        "reached_png": rec.get("reached_png"),
        "wrote_to": None if args.dry_run else TIMESERIES,
        "record": rec if args.full else None,
    }, indent=2))
    return 0


# ── subcommand: import-logs ──────────────────────────────────────────────────
def cmd_import_logs(args):
    pattern = args.glob or os.path.join(HARNESS_DIR, "*.serial.log")
    logs = sorted(glob.glob(pattern),
                  key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
    if args.limit:
        logs = logs[-args.limit:]

    # Revision attribution: no per-revision boot banner exists yet (the kernel
    # prints a fixed "Aether Kernel v0.1" line, NO git sha). Per the design we
    # attribute by MTIME ORDERING — map each log's mtime onto the git history of
    # this branch by wall-clock, so logs cluster under the revision that was HEAD
    # at the time they were produced. Best-effort: we read the commit timeline
    # and bisect each log's mtime against commit author-dates.
    commit_timeline = _build_commit_timeline()

    records = []
    parsed = 0
    skipped = 0
    host = socket.gethostname()
    for log in logs:
        sid = os.path.basename(log)[:-len(".serial.log")]
        try:
            mtime = os.path.getmtime(log)
        except OSError:
            skipped += 1
            continue
        rev, subj = _attribute_revision(mtime, commit_timeline)
        # session json is gone for historical logs -> features/smp unknown, BUT
        # the true launch ts + kvm_effective are recoverable from the first
        # <sid>.events.jsonl line (the cpu_model event the harness writes AT
        # launch). launch_anchor + _session_meta both consult it.
        started_at, src = pm.launch_anchor(sid, log, HARNESS_DIR)
        features_auth, kvm, smp = _session_meta(sid)
        rec = _record_from_log(
            log, sid, rev, subj, host, source="import",
            started_at=started_at, features_auth=features_auth,
            kvm=kvm, smp=smp)
        rec["rev_attribution"] = "mtime-bisect" if rev != "unknown" else "none"
        rec["launch_src"] = src               # json | events.jsonl | log-mtime
        rec["kvm_source"] = ("events.jsonl" if kvm is not None
                             and not os.path.exists(
                                 os.path.join(HARNESS_DIR, sid + ".json"))
                             else "json" if kvm is not None else None)
        records.append(rec)
        parsed += 1

    # write to the rolling store unless dry-run / stdout
    if args.out == "-":
        print(json.dumps({"parsed": parsed, "skipped": skipped,
                          "records": records}, indent=2))
        return 0

    if not args.dry_run:
        for r in records:
            _append_timeseries(r)

    summary = _import_summary(records)
    summary.update({"parsed": parsed, "skipped": skipped,
                    "wrote_to": (None if args.dry_run else TIMESERIES),
                    "markers_source": pm.MARKERS_SOURCE,
                    "markers_path": pm.MARKERS_PATH})
    print(json.dumps(summary, indent=2))
    return 0


def _build_commit_timeline():
    """List of (epoch_author_date, short_sha, subject) newest-first for HEAD's
    history, used to attribute a log's mtime to the revision that was current
    when it ran."""
    raw = _git(["log", "--format=%ct\t%h\t%s", "-n", "400"])
    out = []
    if raw:
        for line in raw.splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3:
                try:
                    out.append((int(parts[0]), parts[1], parts[2]))
                except ValueError:
                    continue
    return out


def _attribute_revision(log_mtime, timeline):
    """Pick the newest commit whose author-date <= the log's mtime — i.e. the
    revision that was HEAD when the log was produced. Returns (short_sha, subj).
    Falls back to ('unknown','') when the log predates all commits in range."""
    for ct, sha, subj in timeline:   # newest-first
        if ct <= log_mtime:
            return sha, subj
    return "unknown", ""


def _session_meta(sid):
    """Authoritative features/kvm/smp for `sid`. Priority:
        1. <sid>.json                         (live-run session state, if it
           survives — features + kvm_effective + smp all authoritative)
        2. <sid>.events.jsonl first line      (recoverable kvm_effective when the
           json is gone, which it is for ~all historical logs)
    Returns (features|None, kvm|None, smp|None). features/smp are only in the json
    so stay None on a historical import; kvm is recovered from the event stream so
    it is NO LONGER always-null on import (was the bug: <sid>.json is 0/614
    present, so kvm was unconditionally None)."""
    meta = os.path.join(HARNESS_DIR, sid + ".json")
    if os.path.exists(meta):
        try:
            m = json.load(open(meta))
            return (m.get("features"), m.get("kvm_effective"), m.get("smp"))
        except Exception:
            pass
    _ts, kvm = pm.event_anchor(sid, HARNESS_DIR)
    return (None, kvm, None)


def _import_summary(records):
    """Distribution stats for an import: how many reached each phase, total-time
    distribution (tick axis), feature mix — for the validation report."""
    n = len(records)
    by_deepest = {}
    totals = []
    png = 0
    panics = 0
    feat_mix = {}
    for r in records:
        dp = r.get("deepest_phase") or "none"
        by_deepest[dp] = by_deepest.get(dp, 0) + 1
        if r.get("total_tick_ms") is not None:
            totals.append(r["total_tick_ms"])
        if r.get("reached_png"):
            png += 1
        if r.get("panic"):
            panics += 1
        for f in r.get("features_inferred", []):
            feat_mix[f] = feat_mix.get(f, 0) + 1
    totals.sort()

    def pctl(p):
        if not totals:
            return None
        k = int(round((p / 100.0) * (len(totals) - 1)))
        return round(totals[k], 1)

    return {
        "n_records": n,
        "reached_png": png,
        "panics": panics,
        "deepest_phase_dist": dict(sorted(by_deepest.items(),
                                          key=lambda kv: -kv[1])),
        "total_tick_ms": {
            "n_with_tick_total": len(totals),
            "min": round(totals[0], 1) if totals else None,
            "p50": pctl(50), "p90": pctl(90),
            "max": round(totals[-1], 1) if totals else None,
        },
        "features_inferred_mix": dict(sorted(feat_mix.items(),
                                             key=lambda kv: -kv[1])),
        "example_records": records[-2:] if len(records) >= 2 else records,
    }


# ── subcommand: run ──────────────────────────────────────────────────────────
def cmd_run(args):
    """Measure the CURRENT (or --rev) revision end-to-end. In THIS workflow it is
    HARD-GATED to build-only: it will NOT boot QEMU unless explicitly unlocked
    with --i-understand-this-boots (and not in --build-only). Boot timing is a
    later phase against a quiet host."""
    harness = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "qemu-harness.py")
    host = socket.gethostname()

    # optional checkout of a past revision (orchestration only; build-only gate)
    orig_head = None
    if args.rev:
        orig_head = _git(["rev-parse", "--abbrev-ref", "HEAD"]) or _git(
            ["rev-parse", "HEAD"])
        co = subprocess.run(["git", "checkout", "--detach", args.rev],
                            cwd=REPO_ROOT, capture_output=True, text=True)
        if co.returncode != 0:
            print(json.dumps({"ok": False, "error": "checkout_failed",
                              "rev": args.rev, "stderr": co.stderr[-2000:]}))
            return 1

    revision = _short_sha("HEAD")
    short_desc = _commit_subject("HEAD")

    # ── BUILD phase: host wall-clock around the kernel build ─────────────────
    build_ms = None
    build_ok = None
    if not args.no_build:
        features = args.features or "firefox-test,kdb"
        # Probe selection — what magnitude the BUILD phase captures:
        #   default (`build`) -> `harness build`: the REAL build (cargo build of
        #     astryx-boot + astryx-kernel, objcopy to kernel.bin, ESP staging) =
        #     codegen + link + stage. This is the magnitude a build-time benchmark
        #     EXISTS to catch (slow-codegen / slow-link regressions). `cargo check`
        #     would type-check only and miss exactly those.
        #   --check-only      -> `harness check`: a fast type-check probe for a
        #     busy host where a full link is undesirable; it does NOT surface
        #     codegen/link regressions and is labelled as such (build_probe).
        # We never compose a raw `cargo +nightly build` ourselves (harness-only
        # rule) — both probes go through scripts/qemu-harness.py.
        probe = "check" if args.check_only else "build"
        t0 = time.time()
        bp = subprocess.run(
            [sys.executable, harness, probe, "--features", features],
            cwd=REPO_ROOT, capture_output=True, text=True)
        build_ms = int((time.time() - t0) * 1000)
        build_ok = (bp.returncode == 0)
        build_probe = probe
        build_tail = (bp.stdout or "")[-1500:] + (bp.stderr or "")[-1500:]
    else:
        features = args.features or ""
        build_tail = ""
        build_probe = None

    # restore original HEAD if we detached for --rev
    if orig_head:
        subprocess.run(["git", "checkout", orig_head], cwd=REPO_ROOT,
                       capture_output=True, text=True)

    # ── BOOT gate: refuse to boot in this workflow ───────────────────────────
    boot_unlocked = (args.i_understand_this_boots
                     and not args.build_only
                     and os.environ.get("ASTRYX_PERF_ALLOW_BOOT") == "1")
    if not boot_unlocked:
        out = {
            "ok": bool(build_ok) if build_ok is not None else True,
            "mode": "build-only",
            "revision": revision,
            "short_desc": short_desc,
            "host": host,
            "features": features,
            "build_ms": build_ms,
            "build_ok": build_ok,
            "build_probe": build_probe,
            "note": ("BOOT GATED OFF in this workflow. Build was timed and "
                     "recorded. To actually boot+measure on a quiet host, pass "
                     "--i-understand-this-boots and set ASTRYX_PERF_ALLOW_BOOT=1."),
        }
        if build_ok is False:
            out["build_tail"] = build_tail
        # record a build-only datapoint so slow-compile regressions are tracked
        if build_ms is not None and not args.dry_run:
            rec = {
                "schema_v": SCHEMA_V, "revision": revision,
                "short_desc": short_desc, "iso_ts": _iso_utc(),
                "host": host, "kvm": None, "smp": None,
                "features": features, "features_inferred": [],
                "phase_ms": {"BUILD": build_ms}, "phase_axis": {"BUILD": "host"},
                "phase_lines": {}, "total_ms": None, "total_tick_ms": None,
                "max_sc": None, "deepest_phase": "BUILD",
                "reached_png": False, "panic": False, "build_ms": build_ms,
                "source": "run-build-only", "sid": None,
                "markers_source": pm.MARKERS_SOURCE,
                # which magnitude BUILD captured: "build" (real codegen+link+stage)
                # or "check" (type-check only — does NOT surface link/codegen regr).
                "build_probe": build_probe,
            }
            _append_timeseries(rec)
            out["recorded"] = TIMESERIES
        print(json.dumps(out, indent=2))
        return 0 if build_ok is not False else 1

    # ── (unlocked) full boot+measure path ────────────────────────────────────
    # Intentionally reached only when explicitly unlocked. Boots via the harness,
    # waits for a terminal marker, then builds a record from the serial log.
    return _run_full_boot(harness, revision, short_desc, host, features, args)


def _run_full_boot(harness, revision, short_desc, host, features, args):
    """Full boot+measure (only when explicitly unlocked). Anchors the host clock
    around the QEMU lifetime, then derives phases from the serial log."""
    url = args.url or "about:blank"
    started_at = time.time()
    sp = subprocess.run(
        [sys.executable, harness, "start", "--features", features, "--no-build"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    try:
        start_out = json.loads(sp.stdout)
    except Exception:
        print(json.dumps({"ok": False, "error": "start_parse_failed",
                          "stdout": sp.stdout[-2000:]}))
        return 1
    sid = start_out.get("sid")
    if not sid:
        print(json.dumps({"ok": False, "error": "no_sid", "start": start_out}))
        return 1
    # wait for a terminal marker (PNG / exit_group / panic), bounded
    subprocess.run(
        [sys.executable, harness, "wait", sid,
         r"89504e47|out\.png written|exit_group\(|PANIC|SCHEDULER_DEADLOCK",
         "--ms", str(args.timeout_ms)],
        cwd=REPO_ROOT, capture_output=True, text=True)
    total_ms = int((time.time() - started_at) * 1000)
    subprocess.run([sys.executable, harness, "stop", sid],
                   cwd=REPO_ROOT, capture_output=True, text=True)

    log_path = os.path.join(HARNESS_DIR, sid + ".serial.log")
    features_auth, kvm, smp = _session_meta(sid)
    rec = _record_from_log(
        log_path, sid, revision, short_desc, host, source="run",
        started_at=started_at, build_ms=None, total_ms=total_ms,
        features_auth=features_auth or features, kvm=kvm, smp=smp)
    if not args.dry_run:
        _append_timeseries(rec)
    print(json.dumps({"ok": True, "record": rec,
                      "wrote_to": None if args.dry_run else TIMESERIES},
                     indent=2))
    return 0


# ── subcommand: baseline-linux (stub) ────────────────────────────────────────
def cmd_baseline_linux(args):
    """Stub filled by the linux-baseline component. Emits the record SHAPE so the
    schema is pinned and `list`/`export-json` can already merge it. A real Linux
    baseline run boots a typical distro under KVM, times the equivalent
    boot->firefox-headless->PNG path on the host clock, and writes a record with
    source='baseline-linux' and a distro tag."""
    rec = {
        "schema_v": SCHEMA_V,
        "revision": args.distro or "linux-baseline",
        "short_desc": "Linux distro KVM baseline (stub — fill via linux-baseline)",
        "iso_ts": _iso_utc(),
        "host": socket.gethostname(),
        "kvm": True,
        "smp": args.smp,
        "features": "",
        "features_inferred": [],
        "phase_ms": {n: None for n in pm.PHASE_NAMES},
        "phase_axis": {n: "host" for n in pm.PHASE_NAMES},
        "phase_lines": {},
        "total_ms": None,
        "total_tick_ms": None,
        "max_sc": None,
        "deepest_phase": None,
        "reached_png": False,
        "panic": False,
        "build_ms": None,
        "source": "baseline-linux",
        "sid": None,
        "distro": args.distro,
        "stub": True,
        "markers_source": pm.MARKERS_SOURCE,
    }
    if args.emit and not args.dry_run:
        _append_timeseries(rec)
    print(json.dumps({"ok": True, "stub": True, "record_shape": rec,
                      "note": "baseline-linux is a stub; the linux-baseline "
                              "component fills the timing fields."}, indent=2))
    return 0


# ── subcommand: list ─────────────────────────────────────────────────────────
def cmd_list(args):
    recs = _read_baseline() + _read_timeseries()
    if args.rev:
        recs = [r for r in recs if r.get("revision") == args.rev]
    if args.source:
        recs = [r for r in recs if r.get("source") == args.source]
    recs.sort(key=lambda r: r.get("iso_ts") or "", reverse=True)
    if args.limit:
        recs = recs[:args.limit]
    # compact projection for listing
    rows = [{
        "iso_ts": r.get("iso_ts"), "revision": r.get("revision"),
        "host": r.get("host"), "source": r.get("source"),
        "deepest_phase": r.get("deepest_phase"),
        "total_tick_ms": r.get("total_tick_ms"), "total_ms": r.get("total_ms"),
        "build_ms": r.get("build_ms"), "reached_png": r.get("reached_png"),
        "panic": r.get("panic"), "sid": r.get("sid"),
        "short_desc": (r.get("short_desc") or "")[:60],
    } for r in recs]
    print(json.dumps({"n": len(rows), "records": rows}, indent=2))
    return 0


# ── subcommand: export-json ──────────────────────────────────────────────────
def cmd_export(args):
    recs = _read_baseline() + _read_timeseries()
    recs.sort(key=lambda r: r.get("iso_ts") or "")
    payload = {
        "schema_v": SCHEMA_V,
        "exported_at": _iso_utc(),
        "baseline_count": len(_read_baseline()),
        "timeseries_count": len(_read_timeseries()),
        "records": recs,
    }
    if args.out and args.out != "-":
        with open(args.out, "w") as f:
            json.dump(payload, f, indent=2)
        print(json.dumps({"ok": True, "wrote": args.out, "n": len(recs)}))
    else:
        print(json.dumps(payload, indent=2))
    return 0


# ── argv ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        prog="perf-bench.py",
        description="AstryxOS FF-headless performance measurement driver "
                    "(non-interactive, JSON output).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="measure current/--rev revision end-to-end "
                                    "(BUILD-ONLY in this workflow)")
    r.add_argument("--rev", help="checkout + build this past revision first")
    r.add_argument("--features", help="cargo --features string "
                                      "(default firefox-test,kdb)")
    r.add_argument("--url", help="target URL (default about:blank)")
    r.add_argument("--no-build", action="store_true",
                   help="skip the build (assume already staged)")
    r.add_argument("--build-only", action="store_true",
                   help="time the build, do not boot (default in this workflow)")
    r.add_argument("--check-only", action="store_true",
                   help="use `cargo check` instead of `build` for a fast probe")
    r.add_argument("--i-understand-this-boots", action="store_true",
                   help="UNLOCK the boot path (also needs ASTRYX_PERF_ALLOW_BOOT=1)")
    r.add_argument("--timeout-ms", type=int, default=2400000,
                   help="boot wait timeout (default 40 min)")
    r.add_argument("--dry-run", action="store_true",
                   help="do not write to the store")
    r.set_defaults(func=cmd_run)

    im = sub.add_parser("ingest-marks",
                        help="turn ONE session's gate marks into a time-series "
                             "record (serial-monitor -> perf-dashboard bridge)")
    im.add_argument("sid", help="harness session id (reads "
                                "~/.astryx-harness/<sid>.serial.log + .marks.jsonl)")
    im.add_argument("--dry-run", action="store_true",
                    help="compute + print but do not write the store")
    im.add_argument("--full", action="store_true",
                    help="include the full record object in the output")
    im.set_defaults(func=cmd_ingest_marks)

    il = sub.add_parser("import-logs",
                        help="parse existing serial logs into time-series records")
    il.add_argument("--limit", type=int, help="only the newest N logs")
    il.add_argument("--glob", help="override the log glob")
    il.add_argument("--out", default="store",
                    help="'store' (append to timeseries.jsonl, default), "
                         "or '-' for stdout-only")
    il.add_argument("--dry-run", action="store_true",
                    help="parse + summarise but do not write the store")
    il.set_defaults(func=cmd_import_logs)

    bl = sub.add_parser("baseline-linux",
                        help="stub for the Linux KVM baseline (schema pin)")
    bl.add_argument("--distro", help="distro tag, e.g. alpine-3.20")
    bl.add_argument("--smp", type=int, default=2)
    bl.add_argument("--emit", action="store_true",
                    help="append the stub record to the store")
    bl.add_argument("--dry-run", action="store_true")
    bl.set_defaults(func=cmd_baseline_linux)

    ls = sub.add_parser("list", help="list stored records (newest first)")
    ls.add_argument("--limit", type=int, default=20)
    ls.add_argument("--rev", help="filter by revision short sha")
    ls.add_argument("--source", help="filter by source (run/import/baseline-linux)")
    ls.set_defaults(func=cmd_list)

    ej = sub.add_parser("export-json", help="dump the merged store as JSON")
    ej.add_argument("--out", help="output file (default stdout)")
    ej.set_defaults(func=cmd_export)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
