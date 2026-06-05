#!/usr/bin/env python3
"""gate_marks.py — shared gate-timing helpers for the AstryxOS dev dashboards.

SINGLE SOURCE OF TRUTH for "when did this boot reach each gate, in host time?"
The serial monitor (serial-web.py, :8088) and the perf dashboard
(perf-bench.py -> perf-web.py, :8099) must never disagree on a gate's time, so
the gate definitions and the gate->time methodology live here, in ONE module
that both import.

  * The GATE LADDER itself is still owned by serial-web.py's MILESTONES (the
    canonical bring-up + render ladder). This module re-exports it via
    perf_markers (which imports serial-web's MILESTONES), so there is exactly one
    place a gate is defined.
  * The GATE<->PERF-PHASE MAPPING (GATE_TO_PHASE) is the bridge between the two
    dashboards: each gate that ENDS a perf phase names that phase, so a per-gate
    delta in the serial monitor IS the phase_ms value perf-bench records. The
    mapping is documented in ONE place (here) so the dashboards never diverge.

MARKS SIDECAR — the exact-host-time source for LIVE sessions
------------------------------------------------------------
The harness watcher (qemu-harness.py _watcher_thread) streams the serial log with
the host clock and, the instant it first sees a milestone marker, appends a
record to ``~/.astryx-harness/<sid>.marks.jsonl``::

    {"kind": "gate", "label": "<milestone>", "host_ts": <epoch>, "tick": <int|null>,
     "line": <int>, "ts": <epoch>}

One line per gate, first-arrival only, append-only, additive fields only. This is
the robust exact-host-time source: the watcher always runs for a live session, so
serial-web can read the marks and show the true wall-clock arrival of each gate
without re-deriving it from kernel ticks.

For HISTORICAL logs (no watcher ran, no marks sidecar, no per-line host stamp)
the arrival time is derived from the kernel-tick axis (launch started_at + the
[HB]/PROC-METRICS tick at the gate line, at the published 100 Hz timer = 10
ms/tick). Tick-derived times are flagged ``approx=True`` so a consumer never
confuses them with an exact live stamp.

Public-spec note: the 100 Hz timer figure (1 tick = 10 ms) is the kernel's
published PIT/APIC rate.
"""

import os
import json

# Reuse the canonical ladder + tick rate from perf_markers (which itself imports
# serial-web.py's MILESTONES — so the gate ladder is single-sourced).
import perf_markers as pm

# Re-export so callers can `from gate_marks import MILESTONES` without caring
# whether it came from serial-web or the vendored fallback.
MILESTONES = pm.MILESTONES
MS_PER_TICK = pm.MS_PER_TICK
# The AND-anchored marker-match rule (substring | tuple-of-substrings-all-on-line)
# from serial-web/perf_markers — re-exported so the harness watcher uses the SAME
# matcher as the dashboards (no divergent fork of the gate-detection logic).
match = pm._match


# ── gate <-> perf-phase mapping (the bridge between the two dashboards) ────────
# Each gate that ENDS a perf phase names that phase. The per-gate delta in the
# serial monitor (time since the PREVIOUS gate) is therefore exactly the duration
# of the named phase, and perf-bench ingest-marks writes it straight into
# phase_ms[<phase>]. Gates that do not close a distinct perf phase map to None
# (they still get an elapsed/delta shown in the serial monitor; they just don't
# feed a phase_ms slot). This is the ONE place the two taxonomies are reconciled.
#
# serial-web MILESTONE        ->  perf-bench PHASE it closes (or None)
GATE_TO_PHASE = {
    "kernel entry":      None,            # phase opener; no prior gate to delta from
    "heap guard":        None,            # within KERNEL-EARLY; no distinct phase
    "APIC init":         "KERNEL-EARLY",  # bootloader -> apic
    "SMP / scheduler":   None,            # within DRIVERS bring-up
    "drivers":           "DRIVERS",       # apic -> drivers/blk
    "VFS / mount":       "VFS-MOUNT",     # drivers -> vfs mount
    "init / userspace":  None,            # within INIT
    "X11 ready":         "INIT",          # vfs/init -> X11 ready (INIT end anchor)
    "firefox exec":      "FF-STARTUP",    # X11 -> firefox-bin exec
    "TLS / network":     "LIBXUL-INIT",   # ff exec/libxul -> first TCP
    "content procs":     None,            # within NETWORK/TLS handshake
    "screenshot-actors": "NETWORK/TLS",   # tcp -> screenshot IPDL
    "drawSnapshot":      "RENDER-SETUP",  # screenshot -> composite/draw
    "PNG write":         "ENCODE",        # draw -> PNG magic written
    "exit_group":        "TEARDOWN",      # PNG -> pid1 exit_group
}


def marks_path(sid, harness_dir):
    """Path to the per-session gate-marks sidecar."""
    return os.path.join(harness_dir, sid + ".marks.jsonl")


def append_gate_mark(sid, harness_dir, label, host_ts, tick, line):
    """Append a single first-arrival gate mark (called by the harness watcher).

    Best-effort and append-only: a write failure is swallowed so the watcher's
    panic/idle duties are never disrupted by marks I/O."""
    rec = {"kind": "gate", "label": label, "host_ts": host_ts,
           "tick": tick, "line": line, "ts": host_ts}
    try:
        with open(marks_path(sid, harness_dir), "a") as f:
            f.write(json.dumps(rec) + "\n")
        return True
    except OSError:
        return False


def read_gate_marks(sid, harness_dir):
    """Read the marks sidecar -> {label: {host_ts, tick, line}} (first-arrival).

    Returns {} when no sidecar exists (historical logs). Only the FIRST record
    for a label is kept (the watcher only writes first-arrival, but be defensive
    against a re-attached watcher writing a duplicate)."""
    out = {}
    p = marks_path(sid, harness_dir)
    if not os.path.exists(p):
        return out
    try:
        with open(p, "r", errors="replace") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    d = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if d.get("kind") != "gate":
                    continue
                lab = d.get("label")
                if lab and lab not in out:
                    out[lab] = {"host_ts": d.get("host_ts"),
                                "tick": d.get("tick"),
                                "line": d.get("line")}
    except OSError:
        pass
    return out


def tick_to_elapsed_s(tick, started_at, first_tick=0):
    """Approximate host-elapsed-since-launch (seconds) for a gate at kernel
    `tick`, derived from the published 100 Hz timer. `started_at` is unused for
    the elapsed value (elapsed is a pure tick delta from first_tick) but is kept
    in the signature so a caller that wants absolute host time can add it. Returns
    None when `tick` is unknown."""
    if tick is None:
        return None
    base = first_tick if first_tick is not None else 0
    if tick < base:
        return None
    return (tick - base) * MS_PER_TICK / 1000.0


def gate_timeline(timeline, marks, started_at, first_tick=0):
    """Attach per-gate host timing to a serial-web `scan_progress` timeline.

    `timeline` is the list of {label, hit, line, tick, dtick} dicts.
    `marks`     is read_gate_marks() output (exact host stamps), or {} historical.
    `started_at` is the session launch epoch (from <sid>.json), or None.
    `first_tick` is the earliest kernel tick on this log (for the tick-derived
                 approximate axis baseline).

    For each HIT gate, adds (additive — never renames existing keys):
      host_elapsed  float|None  seconds since launch at this gate's arrival
      host_delta    float|None  seconds since the PREVIOUS hit gate (the "compare
                                performance" signal)
      approx        bool        True when the time is tick-derived (no exact mark)
      host_ts       float|None  absolute host epoch of arrival (exact marks only)

    Priority per gate: exact host mark (marks sidecar) > tick-derived approx.
    The delta is computed on whichever axis the gate's elapsed is on, falling back
    consistently so the ladder stays monotone."""
    out = []
    prev_elapsed = None
    for step in timeline:
        s = dict(step)  # copy; additive
        lab = s.get("label")
        host_elapsed = None
        host_ts = None
        approx = False
        if s.get("hit"):
            mk = marks.get(lab)
            if mk and mk.get("host_ts") is not None and started_at:
                # exact: watcher stamped the host arrival time
                host_ts = mk["host_ts"]
                host_elapsed = max(0.0, host_ts - started_at)
                approx = False
            else:
                # approximate: derive from the kernel tick at this gate line
                te = tick_to_elapsed_s(s.get("tick"), started_at, first_tick)
                if te is not None:
                    host_elapsed = te
                    approx = True
        host_delta = None
        if host_elapsed is not None and prev_elapsed is not None:
            host_delta = max(0.0, host_elapsed - prev_elapsed)
        if host_elapsed is not None:
            prev_elapsed = host_elapsed
        # round to 1 ms to keep the JSON clean (float-subtraction noise otherwise)
        s["host_elapsed"] = round(host_elapsed, 3) if host_elapsed is not None else None
        s["host_delta"] = round(host_delta, 3) if host_delta is not None else None
        s["host_ts"] = host_ts
        s["approx"] = approx
        out.append(s)
    return out
