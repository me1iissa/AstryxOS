#!/usr/bin/env python3
"""perf-web.py — read-only dashboard over the AstryxOS FF-headless perf store.

A cheap, Python-stdlib-only HTTP server that visualises the per-revision
benchmark time-series produced by ``perf-bench.py``. It is NON-INTERACTIVE and
read-only: it only ever READS the on-disk store, so any number of callers
(claude-code, a human browser, CI) can point at it without side effects.

DATA SOURCES (read exactly the same paths perf-bench.py writes):

    .perf/baseline.json                  committed, curated golden + Linux KVM
                                         baseline records  (in-repo)
    ~/.astryx-perf/timeseries.jsonl      rolling, host-local per-run history
                                         (one JSON record per line)

The record schema is owned by ``scripts/perf-bench.py`` (``schema_v=1``,
additive-only — never rename a field). This server tolerates extra/unknown
keys and degrades gracefully on missing ones.

ENDPOINTS

    GET  /                 the dashboard (self-contained HTML; inline SVG charts)
    GET  /api/series       the per-revision aggregated time-series + raw runs
    GET  /api/revisions    revision -> {subject, date, ...} from git log
    GET  /api/raw          the full merged store (debug / completeness)
    GET  /healthz          {"ok": true, ...} liveness probe

Charts are hand-rolled inline SVG so the page is fully OFFLINE-FRIENDLY — no
CDN, no vendored JS, no pip deps. Theme matches scripts/serial-web.py.

USAGE (one-shot argv; structured where it matters):

    python3 scripts/perf-web.py [--port 8099] [--host 0.0.0.0]
    PERF_WEB_PORT=8099 python3 scripts/perf-web.py

    # validation / scripting without a browser:
    curl -s localhost:8099/api/series | python3 -m json.tool

Aggregation note: FF-headless runs are noisy and 2-host-race-sensitive, so the
trend line plots the per-revision MEDIAN of the recoverable total (host
``total_ms`` when present, else the ``total_tick_ms`` tick-axis proxy), with the
run count and min/max carried alongside so a single outlier is visible, not
silently averaged away.
"""

import argparse
import datetime
import glob
import html
import json
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── store locations (mirror perf-bench.py exactly; resolved independently) ────
PERF_DIR = os.path.expanduser(os.environ.get("ASTRYX_PERF_DIR", "~/.astryx-perf"))
TIMESERIES = os.path.join(PERF_DIR, "timeseries.jsonl")


def _repo_root():
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], cwd=here, text=True,
            stderr=subprocess.DEVNULL).strip()
    except Exception:
        return os.path.dirname(here)


REPO_ROOT = _repo_root()
# Committed reference store. Overridable via ASTRYX_PERF_BASELINE (mirrors
# perf-bench.py) so a caller can point the dashboard at an alternate baseline.
BASELINE_JSON = os.environ.get("ASTRYX_PERF_BASELINE",
                               os.path.join(REPO_ROOT, ".perf", "baseline.json"))

SHA_RE = re.compile(r"^[0-9a-f]{4,40}$")

# Canonical phase order (owned by perf_markers.PHASE_NAMES; vendored here so the
# dashboard never imports the marker module — it only reads stored records).
PHASE_NAMES = [
    "BUILD", "FIRMWARE/OVMF", "KERNEL-EARLY", "DRIVERS", "VFS-MOUNT", "INIT",
    "FF-STARTUP", "LIBXUL-INIT", "NETWORK/TLS", "RENDER-SETUP", "RENDER",
    "ENCODE", "TEARDOWN",
]

# Coarse groups for the stacked phase-breakdown bars (BUILD/BOOT/FF-INIT/
# NETWORK/RENDER/ENCODE) and the colour ramp used in the SVG legend.
#
# MECE: every taxonomy phase belongs to exactly ONE group, and no phase is
# counted twice. The render pipeline is now disjoint in perf_markers
# (RENDER-SETUP=screenshot->draw, RENDER=draw->encode-open, ENCODE=encode-open->
# png-written, TEARDOWN=png-written->exit), so the RENDER group (RENDER-SETUP +
# RENDER = the whole draw interval) and the ENCODE group (ENCODE + TEARDOWN =
# encode + exit) no longer paint the same span. Previously RENDER and ENCODE both
# spanned [libpng->png_written] and the stacked bar double-painted it.
PHASE_GROUPS = [
    ("BUILD",   ["BUILD"],                                          "#56b6c2"),
    ("BOOT",    ["FIRMWARE/OVMF", "KERNEL-EARLY", "DRIVERS",
                 "VFS-MOUNT", "INIT"],                              "#7ee787"),
    ("FF-INIT", ["FF-STARTUP", "LIBXUL-INIT"],                      "#39d353"),
    ("NETWORK", ["NETWORK/TLS"],                                    "#f0c674"),
    ("RENDER",  ["RENDER-SETUP", "RENDER"],                         "#d2a8ff"),
    ("ENCODE",  ["ENCODE", "TEARDOWN"],                             "#ff7b72"),
]


# ── store I/O (read-only) ─────────────────────────────────────────────────────
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


def _merged():
    """All records, baseline first then rolling, sorted by iso_ts ascending."""
    recs = _read_baseline() + _read_timeseries()
    recs.sort(key=lambda r: (r.get("iso_ts") or ""))
    return recs


# ── git revision metadata (best-effort; never fatal) ─────────────────────────
def _git(args):
    try:
        return subprocess.check_output(
            ["git"] + args, cwd=REPO_ROOT, text=True,
            stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def revision_meta(revisions):
    """Map each revision sha -> {subject, date, author} via a single git log walk.

    Best-effort: a sha that isn't in this checkout (rebased away, or a synthetic
    'linux-*' baseline id) just gets an empty subject."""
    meta = {}
    for rev in revisions:
        if not rev or not SHA_RE.match(str(rev)):
            meta[rev] = {"subject": "", "date": None, "author": None,
                         "in_tree": False}
            continue
        info = _git(["show", "-s", "--format=%s\x1f%cI\x1f%an", rev])
        if info and "\x1f" in info:
            subj, date, author = (info.split("\x1f") + ["", "", ""])[:3]
            meta[rev] = {"subject": subj, "date": date, "author": author,
                         "in_tree": True}
        else:
            meta[rev] = {"subject": "", "date": None, "author": None,
                         "in_tree": False}
    return meta


# ── aggregation: build the per-revision series ───────────────────────────────
def _run_total_ms(rec):
    """Recoverable per-run total: prefer host total_ms, else the tick proxy."""
    v = rec.get("total_ms")
    if isinstance(v, (int, float)) and v > 0:
        return float(v), "host"
    v = rec.get("total_tick_ms")
    if isinstance(v, (int, float)) and v > 0:
        return float(v), "tick"
    return None, None


def _median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return None
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _group_phase_ms(phase_ms):
    """Collapse the 13-phase phase_ms dict into the coarse PHASE_GROUPS totals.

    Returns {group_name: ms_or_None}. A group is None only if EVERY constituent
    phase is null (so we don't paint a zero where a phase was simply unmeasured
    on the tick axis); otherwise null constituents count as 0."""
    out = {}
    pm = phase_ms or {}
    for gname, members, _color in PHASE_GROUPS:
        vals = [pm.get(m) for m in members]
        present = [v for v in vals if isinstance(v, (int, float))]
        out[gname] = float(sum(present)) if present else None
    return out


def build_series():
    """Aggregate the merged store into a per-revision, date-ordered series.

    Each entry carries: revision, subject, date, run count, median/min/max of the
    recoverable total, how many runs reached PNG / panicked, the median grouped
    phase breakdown, and which axis the total came from.

    Baseline-sourced records (Linux KVM reference, curated golden refs in
    .perf/baseline.json) are NOT folded into the per-revision trend/delta
    sequence — they are surfaced separately as a reference band. Only the
    rolling per-run history drives the AstryxOS revision series."""
    rolling = _read_timeseries()

    by_rev = {}
    for r in rolling:
        rev = r.get("revision") or "unknown"
        by_rev.setdefault(rev, []).append(r)

    meta = revision_meta(list(by_rev.keys()))

    series = []
    for rev, runs in by_rev.items():
        totals = []
        axes = set()
        for r in runs:
            t, axis = _run_total_ms(r)
            if t is not None:
                totals.append(t)
                axes.add(axis)

        # Median grouped phase breakdown across runs that have ANY phase data.
        group_runs = {g[0]: [] for g in PHASE_GROUPS}
        for r in runs:
            grp = _group_phase_ms(r.get("phase_ms"))
            for gname, v in grp.items():
                if v is not None:
                    group_runs[gname].append(v)
        phase_breakdown = {
            g: (_median(vs) if vs else None) for g, vs in group_runs.items()
        }

        m = meta.get(rev, {})
        # Sort key: author-date when known, else earliest iso_ts of its runs.
        first_ts = min((r.get("iso_ts") or "" for r in runs), default="")
        date_key = m.get("date") or first_ts

        series.append({
            "revision": rev,
            "subject": m.get("subject", ""),
            "date": m.get("date"),
            "in_tree": m.get("in_tree", False),
            "first_run_iso": first_ts or None,
            "_date_key": date_key,
            "runs": len(runs),
            "runs_with_total": len(totals),
            "median_total_ms": _median(totals),
            "min_total_ms": min(totals) if totals else None,
            "max_total_ms": max(totals) if totals else None,
            "total_axis": ("host" if "host" in axes
                           else "tick" if "tick" in axes else None),
            "reached_png": sum(1 for r in runs if r.get("reached_png")),
            "panics": sum(1 for r in runs if r.get("panic")),
            "phase_breakdown": phase_breakdown,
        })

    series.sort(key=lambda e: (e["_date_key"], e["revision"]))
    for e in series:
        e.pop("_date_key", None)

    # Linux KVM baseline reference line: any baseline record whose revision /
    # host marks it as the Linux reference. We surface ALL baseline-sourced
    # totals so the dashboard can draw the reference band.
    baseline = []
    for r in _read_baseline():
        t, axis = _run_total_ms(r)
        if t is None:
            continue
        baseline.append({
            "label": r.get("short_desc") or r.get("revision") or "baseline",
            "revision": r.get("revision"),
            "host": r.get("host"),
            "total_ms": t,
            "axis": axis,
            "is_linux": _looks_like_linux(r),
        })

    return {"series": series, "baseline": baseline}


def _looks_like_linux(rec):
    blob = " ".join(str(rec.get(k, "")) for k in
                    ("revision", "short_desc", "host", "source")).lower()
    return "linux" in blob or "kvm-baseline" in blob or "baseline-linux" in blob


# ── /api/series payload ──────────────────────────────────────────────────────
def api_series():
    data = build_series()
    series = data["series"]
    baseline = data["baseline"]

    linux_totals = [b["total_ms"] for b in baseline if b["is_linux"]]
    linux_ref = _median(linux_totals) if linux_totals else None

    # Consecutive-revision delta on the median total (only across revisions that
    # both have a recoverable median, preserving chronological order).
    timed = [e for e in series if e["median_total_ms"] is not None]
    deltas = []
    for prev, cur in zip(timed, timed[1:]):
        d = cur["median_total_ms"] - prev["median_total_ms"]
        deltas.append({
            "from": prev["revision"], "to": cur["revision"],
            "subject": cur["subject"],
            "delta_ms": d,
            "pct": (d / prev["median_total_ms"] * 100.0)
                   if prev["median_total_ms"] else None,
            "direction": "slower" if d > 0 else "faster" if d < 0 else "flat",
        })

    return {
        "schema_v": 1,
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec="seconds"),
        "store": {
            "timeseries_path": TIMESERIES,
            "baseline_path": BASELINE_JSON,
            "timeseries_exists": os.path.exists(TIMESERIES),
        },
        "phase_groups": [{"name": g, "members": m, "color": c}
                         for (g, m, c) in PHASE_GROUPS],
        "linux_baseline_ms": linux_ref,
        "baseline_records": baseline,
        "n_revisions": len(series),
        "n_revisions_timed": len(timed),
        "series": series,
        "deltas": deltas,
    }


def api_revisions():
    recs = _merged()
    revs = []
    seen = set()
    for r in recs:
        rev = r.get("revision")
        if rev and rev not in seen:
            seen.add(rev)
            revs.append(rev)
    meta = revision_meta(revs)
    return {
        "schema_v": 1,
        "n": len(revs),
        "revisions": [
            {"revision": rev, **meta.get(rev, {})} for rev in revs
        ],
    }


# ── SVG chart helpers (hand-rolled; fully offline) ───────────────────────────
def _fmt_dur(ms):
    if ms is None:
        return "—"
    s = ms / 1000.0
    if s < 90:
        return f"{s:.1f}s"
    m = s / 60.0
    return f"{m:.1f}m"


def _esc(s):
    return html.escape(str(s), quote=True)


def render_page():
    """Self-contained dashboard HTML. All charts are server-rendered inline SVG;
    a tiny client script only handles hover-tooltips + the axis toggle, so the
    page works with JS disabled (charts still render) and needs no network."""
    payload = api_series()
    series = payload["series"]
    deltas = payload["deltas"]
    linux_ref = payload["linux_baseline_ms"]

    timed = [e for e in series if e["median_total_ms"] is not None]

    trend_svg = _svg_trend(timed, linux_ref)
    stacked_svg = _svg_stacked(timed)
    delta_svg = _svg_delta(deltas)

    # Embed the series JSON for the client tooltip layer (read-only).
    embed = json.dumps({"series": series, "deltas": deltas,
                        "linux_baseline_ms": linux_ref})

    n_runs = sum(e["runs"] for e in series)
    n_png = sum(e["reached_png"] for e in series)
    n_panic = sum(e["panics"] for e in series)

    return PAGE_TMPL.format(
        embed=embed,
        n_rev=len(series),
        n_rev_timed=len(timed),
        n_runs=n_runs,
        n_png=n_png,
        n_panic=n_panic,
        linux_ref=_fmt_dur(linux_ref),
        ts_path=_esc(TIMESERIES),
        base_path=_esc(BASELINE_JSON),
        gen=_esc(payload["generated_at"]),
        trend_svg=trend_svg,
        stacked_svg=stacked_svg,
        delta_svg=delta_svg,
        legend=_legend_html(),
    )


def _legend_html():
    out = []
    for gname, _members, color in PHASE_GROUPS:
        out.append(
            f'<span class="lg"><i style="background:{color}"></i>{_esc(gname)}</span>')
    return "".join(out)


def _nice_max(v):
    if v <= 0:
        return 1.0
    import math
    mag = 10 ** math.floor(math.log10(v))
    for step in (1, 1.5, 2, 2.5, 5, 10):
        if step * mag >= v:
            return step * mag
    return 10 * mag


def _svg_trend(entries, linux_ref):
    """Per-revision MEDIAN total trend line + min/max whiskers + Linux ref line."""
    W, H = 1080, 320
    padL, padR, padT, padB = 64, 20, 18, 74
    if not entries:
        return _empty_svg(W, H, "no timed revisions yet")
    plotW = W - padL - padR
    plotH = H - padT - padB
    maxv = max([e["max_total_ms"] or e["median_total_ms"] for e in entries]
               + ([linux_ref] if linux_ref else []))
    ymax = _nice_max(maxv)
    n = len(entries)
    step = plotW / max(1, n - 1) if n > 1 else 0

    def x(i):
        return padL + (i * step if n > 1 else plotW / 2)

    def y(v):
        return padT + plotH * (1 - (v / ymax))

    parts = [f'<svg viewBox="0 0 {W} {H}" class="chart" '
             f'preserveAspectRatio="xMidYMid meet">']
    # gridlines + y labels
    for g in range(5):
        gv = ymax * g / 4
        gy = y(gv)
        parts.append(f'<line x1="{padL}" y1="{gy:.1f}" x2="{W-padR}" '
                     f'y2="{gy:.1f}" class="grid"/>')
        parts.append(f'<text x="{padL-8}" y="{gy+4:.1f}" '
                     f'class="ylab">{_fmt_dur(gv)}</text>')
    # Linux baseline reference line
    if linux_ref:
        ly = y(linux_ref)
        parts.append(f'<line x1="{padL}" y1="{ly:.1f}" x2="{W-padR}" '
                     f'y2="{ly:.1f}" class="refline"/>')
        parts.append(f'<text x="{W-padR}" y="{ly-5:.1f}" class="reflab" '
                     f'text-anchor="end">Linux KVM {_fmt_dur(linux_ref)}</text>')
    # whiskers (min..max)
    for i, e in enumerate(entries):
        lo, hi = e["min_total_ms"], e["max_total_ms"]
        if lo is not None and hi is not None and hi > lo:
            parts.append(f'<line x1="{x(i):.1f}" y1="{y(lo):.1f}" '
                         f'x2="{x(i):.1f}" y2="{y(hi):.1f}" class="whisk"/>')
    # the median line
    pts = " ".join(f"{x(i):.1f},{y(e['median_total_ms']):.1f}"
                   for i, e in enumerate(entries))
    parts.append(f'<polyline points="{pts}" class="trend"/>')
    # points (hoverable)
    for i, e in enumerate(entries):
        cx, cy = x(i), y(e["median_total_ms"])
        cls = "pt png" if e["reached_png"] else "pt"
        title = (f'{e["revision"]} — {e["subject"][:60]}\\n'
                 f'median {_fmt_dur(e["median_total_ms"])} '
                 f'({e["runs_with_total"]} runs, axis={e["total_axis"]})')
        parts.append(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="4" class="{cls}" '
            f'data-i="{i}" tabindex="0"><title>{_esc(title)}</title></circle>')
    # x labels (rotated short shas, every ~Nth to avoid overlap)
    every = max(1, n // 22)
    for i, e in enumerate(entries):
        if i % every:
            continue
        parts.append(
            f'<text x="{x(i):.1f}" y="{H-padB+14}" class="xlab" '
            f'transform="rotate(45 {x(i):.1f} {H-padB+14})">{_esc(e["revision"])}</text>')
    parts.append(f'<text x="{padL}" y="14" class="axtitle">'
                 f'per-revision median total (lower = faster)</text>')
    parts.append("</svg>")
    return "".join(parts)


def _svg_stacked(entries):
    """Stacked phase-group bars per revision (BUILD/BOOT/FF-INIT/NET/RENDER/ENC)."""
    if not entries:
        return _empty_svg(1080, 300, "no phase data yet")
    # Only revisions that have ANY phase breakdown.
    rows = [e for e in entries
            if any(v is not None for v in e["phase_breakdown"].values())]
    if not rows:
        return _empty_svg(1080, 300, "no phase breakdown recovered yet")
    W = 1080
    padL, padR, padT, padB = 64, 20, 18, 74
    barH = 26
    H = padT + padB + barH * len(rows) + 4 * len(rows)
    plotW = W - padL - padR
    maxv = 0.0
    for e in rows:
        tot = sum(v for v in e["phase_breakdown"].values() if v)
        maxv = max(maxv, tot)
    xmax = _nice_max(maxv) if maxv > 0 else 1.0
    colors = {g: c for (g, _m, c) in PHASE_GROUPS}

    parts = [f'<svg viewBox="0 0 {W} {H}" class="chart" '
             f'preserveAspectRatio="xMidYMid meet">']
    # x gridlines
    for g in range(5):
        gv = xmax * g / 4
        gx = padL + plotW * (gv / xmax)
        parts.append(f'<line x1="{gx:.1f}" y1="{padT}" x2="{gx:.1f}" '
                     f'y2="{H-padB}" class="grid"/>')
        parts.append(f'<text x="{gx:.1f}" y="{H-padB+16}" class="xlab" '
                     f'text-anchor="middle">{_fmt_dur(gv)}</text>')
    y = padT
    for e in rows:
        xacc = padL
        for gname, _members, _c in PHASE_GROUPS:
            v = e["phase_breakdown"].get(gname)
            if not v:
                continue
            w = plotW * (v / xmax)
            title = f'{e["revision"]} {gname}: {_fmt_dur(v)}'
            parts.append(
                f'<rect x="{xacc:.1f}" y="{y}" width="{max(0.5,w):.1f}" '
                f'height="{barH}" fill="{colors[gname]}" class="seg">'
                f'<title>{_esc(title)}</title></rect>')
            xacc += w
        parts.append(f'<text x="{padL-8}" y="{y+barH-8}" class="ylab" '
                     f'text-anchor="end">{_esc(e["revision"])}</text>')
        y += barH + 4
    parts.append(f'<text x="{padL}" y="14" class="axtitle">'
                 f'phase breakdown (median per revision)</text>')
    parts.append("</svg>")
    return "".join(parts)


def _svg_delta(deltas):
    """Consecutive-revision delta bars: green=faster (down), red=slower (up)."""
    if not deltas:
        return _empty_svg(1080, 240, "need >=2 timed revisions for deltas")
    W, H = 1080, 240
    padL, padR, padT, padB = 64, 20, 28, 70
    plotW = W - padL - padR
    plotH = H - padT - padB
    mx = max((abs(d["delta_ms"]) for d in deltas), default=1.0) or 1.0
    n = len(deltas)
    bw = plotW / max(1, n)
    midy = padT + plotH / 2

    parts = [f'<svg viewBox="0 0 {W} {H}" class="chart" '
             f'preserveAspectRatio="xMidYMid meet">']
    parts.append(f'<line x1="{padL}" y1="{midy:.1f}" x2="{W-padR}" '
                 f'y2="{midy:.1f}" class="grid0"/>')
    for i, d in enumerate(deltas):
        h = (plotH / 2) * (abs(d["delta_ms"]) / mx)
        cx = padL + i * bw
        slower = d["delta_ms"] > 0
        color = "#ff7b72" if slower else "#3fb950" if d["delta_ms"] < 0 else "#5c6675"
        if slower:
            ry, rh = midy - h, h
        else:
            ry, rh = midy, h
        pct = "" if d["pct"] is None else f' ({d["pct"]:+.0f}%)'
        title = (f'{d["from"]} -> {d["to"]}: '
                 f'{"+"if slower else ""}{_fmt_dur(abs(d["delta_ms"]))}{pct} '
                 f'{d["direction"]}\\n{d["subject"][:60]}')
        parts.append(
            f'<rect x="{cx+1:.1f}" y="{ry:.1f}" width="{max(1,bw-2):.1f}" '
            f'height="{max(0.5,rh):.1f}" fill="{color}" class="seg">'
            f'<title>{_esc(title)}</title></rect>')
    parts.append(f'<text x="{padL}" y="14" class="axtitle">'
                 f'consecutive-revision delta '
                 f'(green = faster, red = slower)</text>')
    parts.append(f'<text x="{padL-8}" y="{padT+6}" class="ylab" '
                 f'text-anchor="end">slower</text>')
    parts.append(f'<text x="{padL-8}" y="{H-padB+2}" class="ylab" '
                 f'text-anchor="end">faster</text>')
    parts.append("</svg>")
    return "".join(parts)


def _empty_svg(w, h, msg):
    return (f'<svg viewBox="0 0 {w} {h}" class="chart">'
            f'<text x="{w//2}" y="{h//2}" class="empty" '
            f'text-anchor="middle">{_esc(msg)}</text></svg>')


# ── page template (serial-web.py dark theme) ─────────────────────────────────
PAGE_TMPL = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AstryxOS — FF-headless perf benchmark</title>
<style>
 :root{{--bg:#0b0e14;--panel:#11151f;--edge:#1e2533;--fg:#c9d1d9;--dim:#5c6675;--accent:#39d353}}
 *{{box-sizing:border-box}} html,body{{margin:0;background:var(--bg);color:var(--fg);
   font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
 header{{padding:12px 18px;border-bottom:1px solid var(--edge);background:var(--panel);
   position:sticky;top:0;z-index:3;display:flex;gap:18px;align-items:center;flex-wrap:wrap}}
 header h1{{font-size:14px;margin:0;letter-spacing:.5px}}
 header h1 small{{color:var(--dim);font-weight:400}}
 .badge{{font-size:11px;color:#7ee787;border:1px solid var(--edge);padding:2px 8px;
   border-radius:10px}} .badge.r{{color:#ff7b72}} .badge.p{{color:#d2a8ff}}
 .badge.b{{color:#56b6c2}}
 main{{padding:18px;max-width:1140px;margin:0 auto}}
 section{{background:var(--panel);border:1px solid var(--edge);border-radius:8px;
   padding:14px 16px;margin-bottom:18px}}
 section h2{{font-size:12px;margin:0 0 10px;color:var(--dim);text-transform:uppercase;
   letter-spacing:.6px}}
 svg.chart{{width:100%;height:auto;display:block}}
 .grid{{stroke:#1b2230;stroke-width:1}} .grid0{{stroke:#2a3344;stroke-width:1}}
 .ylab,.xlab{{fill:var(--dim);font-size:10px}}
 .axtitle{{fill:#7ee787;font-size:11px;font-weight:600}}
 .trend{{fill:none;stroke:var(--accent);stroke-width:2}}
 .whisk{{stroke:#37404f;stroke-width:1}}
 .pt{{fill:var(--accent);stroke:#0b0e14;stroke-width:1;cursor:pointer}}
 .pt.png{{fill:#d2a8ff;r:5}}
 .refline{{stroke:#f0c674;stroke-width:1.5;stroke-dasharray:6 4}}
 .reflab{{fill:#f0c674;font-size:10px}}
 .seg{{cursor:pointer}} .seg:hover{{opacity:.82}}
 .empty{{fill:var(--dim);font-size:13px}}
 .legend{{display:flex;gap:14px;flex-wrap:wrap;margin:6px 0 0}}
 .lg{{font-size:11px;color:var(--dim);display:inline-flex;align-items:center;gap:5px}}
 .lg i{{width:10px;height:10px;border-radius:2px;display:inline-block}}
 table{{width:100%;border-collapse:collapse;font-size:11.5px}}
 th,td{{text-align:left;padding:4px 8px;border-bottom:1px solid var(--edge);
   white-space:nowrap}}
 th{{color:var(--dim);font-weight:600;text-transform:uppercase;font-size:10px;
   letter-spacing:.5px}}
 td.r{{text-align:right}} tr:hover{{background:#161b27}}
 .mono{{color:#56b6c2}} .sub{{color:var(--dim);white-space:normal}}
 .pngrow{{color:#d2a8ff}} .down{{color:#3fb950}} .up{{color:#ff7b72}}
 footer{{padding:10px 18px;color:var(--dim);font-size:10.5px;border-top:1px solid var(--edge)}}
 footer code{{color:#56b6c2}}
</style></head><body>
<header>
 <h1>AstryxOS · FF-headless perf <small>render-a-website-to-PNG benchmark</small></h1>
 <span class="badge">{n_rev} revisions</span>
 <span class="badge b">{n_rev_timed} timed</span>
 <span class="badge">{n_runs} runs</span>
 <span class="badge p">{n_png} reached PNG</span>
 <span class="badge r">{n_panic} panics</span>
 <span class="badge">Linux KVM ref: {linux_ref}</span>
</header>
<main>
 <section>
  <h2>Total time per revision (trend)</h2>
  {trend_svg}
 </section>
 <section>
  <h2>Phase breakdown (stacked)</h2>
  {stacked_svg}
  <div class="legend">{legend}</div>
 </section>
 <section>
  <h2>Consecutive-revision delta</h2>
  {delta_svg}
 </section>
 <section>
  <h2>Revisions</h2>
  <table id="tbl"><thead><tr>
   <th>rev</th><th>date</th><th class="r">runs</th><th class="r">median</th>
   <th class="r">min</th><th class="r">max</th><th>axis</th>
   <th class="r">png</th><th class="r">panic</th><th>subject</th>
  </tr></thead><tbody id="tb"></tbody></table>
 </section>
</main>
<footer>
 read-only · stores: <code>{ts_path}</code> + <code>{base_path}</code> ·
 generated {gen} · charts are inline SVG (offline) · refresh to re-read the store
</footer>
<script>
const D = {embed};
function dur(ms){{ if(ms==null) return '—'; const s=ms/1000;
  return s<90 ? s.toFixed(1)+'s' : (s/60).toFixed(1)+'m'; }}
const tb = document.getElementById('tb');
for(const e of D.series){{
  const tr=document.createElement('tr');
  if(e.reached_png) tr.className='pngrow';
  const cells=[
    `<td class="mono">${{e.revision}}</td>`,
    `<td>${{(e.date||e.first_run_iso||'').slice(0,10)}}</td>`,
    `<td class="r">${{e.runs}}</td>`,
    `<td class="r">${{dur(e.median_total_ms)}}</td>`,
    `<td class="r">${{dur(e.min_total_ms)}}</td>`,
    `<td class="r">${{dur(e.max_total_ms)}}</td>`,
    `<td>${{e.total_axis||'—'}}</td>`,
    `<td class="r">${{e.reached_png||''}}</td>`,
    `<td class="r">${{e.panics||''}}</td>`,
    `<td class="sub">${{(e.subject||'').replace(/[<>&]/g,'')}}</td>`,
  ];
  tr.innerHTML=cells.join(''); tb.appendChild(tr);
}}
</script>
</body></html>"""


# ── HTTP server ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "perf-web/1.0"

    def _send(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, "application/json; charset=utf-8",
                   json.dumps(obj, indent=2))

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        try:
            if path == "/" or path == "/index.html":
                self._send(200, "text/html; charset=utf-8", render_page())
            elif path == "/api/series":
                self._json(api_series())
            elif path == "/api/revisions":
                self._json(api_revisions())
            elif path == "/api/raw":
                recs = _merged()
                self._json({"schema_v": 1, "n": len(recs), "records": recs})
            elif path == "/healthz":
                self._json({"ok": True,
                            "timeseries_exists": os.path.exists(TIMESERIES),
                            "baseline_exists": os.path.exists(BASELINE_JSON)})
            else:
                self._send(404, "text/plain; charset=utf-8", "404")
        except Exception as exc:  # never crash the server on a bad record
            self._json({"error": str(exc),
                        "where": path}, code=500)

    def log_message(self, fmt, *args):  # quiet by default
        if os.environ.get("PERF_WEB_VERBOSE"):
            super().log_message(fmt, *args)


def main():
    ap = argparse.ArgumentParser(
        description="Read-only dashboard over the AstryxOS FF-headless perf store.")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("PERF_WEB_PORT", 8099)))
    ap.add_argument("--host", default=os.environ.get("PERF_WEB_HOST", "0.0.0.0"))
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.daemon_threads = True
    print(f"[perf-web] serving {BASELINE_JSON} + {TIMESERIES} "
          f"on http://{a.host}:{a.port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
