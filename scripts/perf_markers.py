#!/usr/bin/env python3
"""perf_markers.py — shared serial-marker + host-anchoring helpers for the
AstryxOS performance-benchmarking tooling (perf-bench.py and any future
dashboard).

DESIGN INTENT — single source of truth for markers
--------------------------------------------------
The live dashboard ``scripts/serial-web.py`` already defines the canonical
bring-up + render MILESTONES ladder, the AND-anchored ``_match`` rule (a marker
may be a substring, or a tuple of substrings that must ALL appear on the same
line — this anchors render markers to the real kernel ``[FF/write]`` IPDL line
so they don't false-positive on the same strings inside Firefox's serialized JS
source / startup cache), the kernel-only tick regex, the pid=1 syscall-count
regex, and the panic regex.

To avoid a divergent fork, this module **imports those definitions straight from
serial-web.py when it is present on the same branch** (``_load_serial_web``).
When serial-web.py is not checked out (e.g. a worktree branched off an older
master that predates it), this module falls back to a VENDORED copy of those
exact definitions, tagged ``MARKERS_SOURCE == "vendored"`` so a caller can tell
which path was taken. The vendored copy MUST stay byte-identical in meaning to
serial-web.py's; if you edit the ladder in one place, mirror it.

PHASE TAXONOMY — the measurement layer
--------------------------------------
On top of the raw MILESTONES, this module defines the 14-phase performance
taxonomy (BUILD .. TEARDOWN). Each phase is delimited by a *from* marker and a
*to* marker expressed in the same marker grammar (substring or AND-tuple). The
forward-ordered, monotone scan (``scan_phase_boundaries``) walks the log once
and records, for the FIRST line that satisfies each phase boundary marker: the
1-based line number, the latest kernel tick seen at/before that line, and the
latest pid=1 sc seen. Phase durations are then derived on TWO axes:

  * kernel-tick axis  — tick delta between adjacent boundaries, converted to ms
    at the 100 Hz timer (``TICKS_PER_SEC``); the *only* axis recoverable from a
    historical log, and valid only once the heartbeat thread is emitting ticks
    (pre-scheduler phases share tick=0 and yield a null tick duration).
  * host-wall-clock   — only available for a LIVE capture that anchors phases to
    ``time.time()`` (perf-bench ``run``); historical logs carry no per-line host
    timestamp, so the host axis is null on import.

Public spec note: the 100 Hz figure is the kernel's published PIT/APIC timer
rate ("timer at ~100 Hz" in the boot log); 1 tick = 10 ms.
"""

import os
import re
import importlib.util


# ── locate + import serial-web.py's canonical marker definitions ─────────────
def _load_serial_web():
    """Return the imported serial-web module, or None if not found.

    Search order: same dir as this file, then the repo's scripts/ dir, then the
    main checkout's scripts/ dir (covers the worktree-branched-off-old-master
    case where serial-web.py lives in the primary checkout but not this branch).
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "serial-web.py"),
        os.path.join(here, "..", "scripts", "serial-web.py"),
    ]
    # main checkout fallback: walk up from here looking for AstryxOS/scripts
    p = here
    for _ in range(6):
        cand = os.path.join(p, "scripts", "serial-web.py")
        if os.path.exists(cand):
            candidates.append(cand)
        p = os.path.dirname(p)
    # absolute last-ditch: the conventional primary checkout location
    candidates.append(os.path.expanduser("~/AstryxOS/scripts/serial-web.py"))
    for c in candidates:
        c = os.path.normpath(c)
        if os.path.exists(c):
            try:
                spec = importlib.util.spec_from_file_location("_serial_web_markers", c)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                # sanity: it must expose the ladder we depend on
                if hasattr(mod, "MILESTONES") and hasattr(mod, "_match"):
                    return mod, c
            except Exception:
                continue
    return None, None


_sw, _SW_PATH = _load_serial_web()

if _sw is not None:
    MILESTONES = _sw.MILESTONES
    _match = _sw._match
    _TICK_KERNEL = _sw._TICK_KERNEL
    _SC_RE = _sw._SC_RE
    _PANIC_RE = _sw._PANIC_RE
    MARKERS_SOURCE = "serial-web"
    MARKERS_PATH = _SW_PATH
else:
    # ── VENDORED fallback (keep in lock-step with serial-web.py) ─────────────
    # Ordered bring-up + render milestones. A marker is a substring OR a tuple
    # of substrings that must ALL be on the same line (AND-anchored). Mirror of
    # serial-web.py's MILESTONES.
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
        ("content procs",     ("isForBrowser",)),
        ("screenshot-actors", (("[FF/write]", "getDimensions"),
                               ("[FF/write]", "ScreenshotParent"),
                               ("[FF/write]", "sendQuery"))),
        ("drawSnapshot",      ("libpng16.so",)),
        ("PNG write",         ("89504e47", "out.png written")),
        ("exit_group",        ("exit_group(",)),
    ]
    _TICK_KERNEL = re.compile(r"(?:\[HB\]|PROC-METRICS\]) tick=(\d+)")
    # pid=1 syscall-count. The serial-web vendored copy is r"pid=1[^\n]*?sc=(\d+)"
    # which lacks a word boundary and will read pid=10/pid=11/pid=19 lines as if
    # they were pid=1 (the multi-digit pids that appear once Firefox spawns
    # content processes). Anchor the "1" with a non-digit lookahead so only the
    # genuine pid=1 (the Firefox launcher process) is counted.
    _SC_RE = re.compile(r"pid=1(?![0-9])[^\n]*?sc=(\d+)")
    _PANIC_RE = re.compile(r"PANIC|HEAP GUARD\] overflow|SCHEDULER_DEADLOCK|ke_bugcheck")

    def _match(line, marks):
        """True if `line` satisfies any marker in `marks`. A marker is a
        substring, or a tuple of substrings ALL of which must appear (AND)."""
        for mk in marks:
            if isinstance(mk, tuple):
                if all(s in line for s in mk):
                    return True
            elif mk in line:
                return True
        return False

    MARKERS_SOURCE = "vendored"
    MARKERS_PATH = __file__


# ── robust pid=1 syscall-count regex (override regardless of source) ──────────
# serial-web's MILESTONES ladder is the canonical bring-up ladder and we reuse it
# verbatim for the milestone chips. But its pid=1 sc regex has no word boundary
# (it reads pid=10/pid=11/pid=19 lines as pid=1). The phase taxonomy stamps each
# anchor with the pid=1 sc at that point, and the per-record max_sc, so a stray
# multi-digit pid line would corrupt those numbers. We therefore ALWAYS use a
# boundary-anchored regex for the measurement layer, independent of whether the
# ladder came from serial-web or the vendored copy. This is additive: callers
# that imported serial-web still get its MILESTONES; only the sc scan is hardened.
_SC_RE = re.compile(r"pid=1(?![0-9])[^\n]*?sc=(\d+)")


# ── timer rate (public boot-log figure: "timer at ~100 Hz") ──────────────────
TICKS_PER_SEC = 100
MS_PER_TICK = 1000.0 / TICKS_PER_SEC   # 10 ms


def ticks_to_ms(dticks):
    """Convert a kernel-tick delta to milliseconds at the 100 Hz timer."""
    if dticks is None:
        return None
    return round(dticks * MS_PER_TICK, 1)


# ── PHASE TAXONOMY ───────────────────────────────────────────────────────────
# Each phase: (name, from_markers, to_markers, axis_hint). The from/to markers
# use the same grammar as MILESTONES (substring | AND-tuple). `axis_hint` says
# which axis the design considers recoverable for this phase on a HISTORICAL log
# ("host" = host-wall-clock only / not recoverable on import; "tick" = kernel
# tick is dense here so the duration is recoverable on import).
#
# The scan is forward-ordered and monotone: phase N+1's `from` marker is only
# matched at/after phase N's marker line, which (with the AND-anchored render
# markers) filters the cached-JS-source false positives — identical discipline
# to serial-web.py's scan_progress.
#
# BUILD and FIRMWARE/OVMF have no in-serial `from` marker (BUILD is pure host
# wall-clock around cargo; FIRMWARE starts at the host QEMU-launch instant); on
# import they are recorded as present-but-untimed. Their boundaries below are the
# first serial line that BOUNDS the far (to) end.
#
# RENDER / ENCODE draw-time signals (corrected). The historical taxonomy used the
# `libpng16.so` *library-load* line (~line 1185, during LIBXUL-INIT) as the
# RENDER/ENCODE boundary — but that fires at startup, long BEFORE the screenshot
# handshake, so a monotone scan positioned past `screenshot` could never reach it
# and RENDER/ENCODE were permanently null (and on the rare run where libpng16.so
# is re-touched late by an mmap, it matched only by accident). The real draw +
# encode boundary in these builds is the test harness opening the output file and
# writing the PNG:
#   * draw / encode-start = `[FF/open] pid=1 path=/tmp/out.png` (the screenshot
#     has been composited and the encoder is about to write the file)
#   * PNG written          = `89504e47` (the PNG magic in the `[FF/write-fd]`
#     payload — exactly one per successful run, never a false positive)
# RENDER and ENCODE are now DISJOINT (MECE): RENDER = screenshot -> out_png_open
# (composite/draw), ENCODE = out_png_open -> png_written (libpng encode + write).
PHASES = [
    # name                 from_markers                                   to_markers                                                axis
    ("BUILD",             None,                                           ("[AstryxBoot] Initializing UEFI bootloader",),            "host"),
    ("FIRMWARE/OVMF",     ("BdsDxe: starting Boot0002", "BdsDxe: loading Boot0002"),
                          ("[AstryxBoot] Initializing UEFI bootloader",),                                                            "host"),
    ("KERNEL-EARLY",      ("[AstryxBoot] Initializing UEFI bootloader",), (("Phase 5b", "APIC init"),),                              "host"),
    ("DRIVERS",           (("Phase 5b", "APIC init"),),                   ("[VFS] Probing virtio-blk",),                             "host"),
    ("VFS-MOUNT",         ("[VFS] Probing virtio-blk",),                  ("X11 server ready", "Xastryx ready"),                     "host"),
    ("INIT",              ("X11 server ready", "Xastryx ready"),          ("[FFTEST] Launching", "[EXEC] pid=1"),                    "host"),
    ("FF-STARTUP",        ("[FFTEST] Launching", "[EXEC] pid=1"),         (("[FF/open]", "libxul.so"),),                             "host"),
    ("LIBXUL-INIT",       (("[FF/open]", "libxul.so"),),                  ("[TCP] Established", "[TCP] Accepted", "] Established →"), "tick"),
    ("NETWORK/TLS",       ("[TCP] Established", "[TCP] Accepted",
                           "] Established →"),                            (("[FF/write]", "getDimensions"),
                                                                           ("[FF/write]", "ScreenshotParent")),                      "tick"),
    ("RENDER-SETUP",      (("[FF/write]", "getDimensions"),
                           ("[FF/write]", "ScreenshotParent")),          (("[FF/open]", "/tmp/out.png"),),                          "tick"),
    ("RENDER",            (("[FF/write]", "getDimensions"),
                           ("[FF/write]", "ScreenshotParent")),          (("[FF/open]", "/tmp/out.png"),),                          "tick"),
    ("ENCODE",            (("[FF/open]", "/tmp/out.png"),),               ("89504e47",),                                             "tick"),
    ("TEARDOWN",          ("89504e47",),                                  (("[PROC]", "PID 1 exit_group"),),                         "host"),
]

# The ordered list of phase boundary *marker sets* that the monotone scan walks.
# A boundary fires once; the scan never goes backwards. We collapse the from/to
# pairs into a single ordered sequence of named anchor points so each anchor is
# matched at most once in file order. The phases then read adjacent anchors.
#
# Anchor sequence (each entry: (anchor_name, markers)). Phase[i] spans
# anchor[from_name] -> anchor[to_name]. BUILD/FIRMWARE host-only anchors that
# have no distinct serial line collapse onto the next real anchor.
#
# OPTIONAL anchors (`tcp`, `screenshot`, `render_start`, `out_png_open`) are
# anchors that can LEGITIMATELY be absent on a successful run — a file:// render
# emits no TCP line; some builds emit no distinct CrossProcessPaint line. The
# scan (scan_phase_boundaries) treats them as non-blocking: a missing optional
# anchor does NOT stall the deeper required anchors behind it (see the scan's
# "advance past optionals" rule). Without this, a no-network render would stall
# the whole chain at `libxul` and `png_written` would never be reached even
# though the run produced a real PNG.
ANCHOR_OPTIONAL = {"tcp", "screenshot", "render_start", "out_png_open"}

ANCHORS = [
    ("firmware_start", ("BdsDxe: starting Boot0002", "BdsDxe: loading Boot0002")),
    ("bootloader",     ("[AstryxBoot] Initializing UEFI bootloader",)),
    ("apic",           (("Phase 5b", "APIC init"),)),
    ("blk_probe",      ("[VFS] Probing virtio-blk",)),
    ("x11_ready",      ("X11 server ready", "Xastryx ready")),
    ("ff_launch",      ("[FFTEST] Launching", "[EXEC] pid=1")),
    # libxul: anchor on the FF runtime OPENING libxul.so (`[FF/open] ... libxul.so`)
    # rather than the bare `libxul.so` token, which also matches the much-earlier
    # `[VFS/resolve] component=libxul.so` line that can precede ff_launch and so
    # mis-anchor FF-STARTUP to ~zero. The AND-tuple ties the anchor to the FF
    # open path, a deterministic post-launch boundary.
    ("libxul",         (("[FF/open]", "libxul.so"),)),
    ("tcp",            ("[TCP] Established", "[TCP] Accepted", "] Established →")),
    ("screenshot",     (("[FF/write]", "getDimensions"),
                        ("[FF/write]", "ScreenshotParent"))),
    # render_start: a DISTINCT composite/draw line, when the build emits one.
    # Optional — absent on these builds, in which case RENDER collapses to null
    # and RENDER-SETUP carries the whole screenshot->encode-open interval (MECE).
    ("render_start",   ("CrossProcessPaint", "drawSnapshot")),
    # out_png_open: the test harness opens the output PNG file — the real draw->
    # encode boundary (replaces the structurally-wrong libpng16.so load marker).
    ("out_png_open",   (("[FF/open]", "/tmp/out.png"),)),
    # png_written: PNG magic in the write payload. Exactly one per success run.
    ("png_written",    ("89504e47",)),
    # exit_group: the pid=1 (Firefox launcher) teardown specifically. The bare
    # `exit_group(` token matches EVERY child process exit (PID 2/4/5/6 emit it
    # long before the launcher), so anchor on the `[PROC] PID 1 exit_group` form
    # which fires exactly once at the real end-of-run.
    ("exit_group",     (("[PROC]", "PID 1 exit_group"),)),
]

# Phase -> (from_anchor, to_anchor). The render pipeline is now MECE:
#   RENDER-SETUP : screenshot -> render_start (composite handshake), OR
#                  screenshot -> out_png_open when no distinct render_start line
#                  exists on this build (the common case) — i.e. it carries the
#                  whole post-screenshot draw interval and RENDER is null.
#   RENDER       : render_start -> out_png_open (the actual draw), null when the
#                  build emits no render_start line (so RENDER and RENDER-SETUP
#                  never both count the same interval — no double-count).
#   ENCODE       : out_png_open -> png_written (libpng encode + file write).
# This removes the historical RENDER==ENCODE==[libpng->png_written] overlap.
PHASE_SPAN = {
    "BUILD":         (None, "bootloader"),          # host-only; bounded by first serial line
    "FIRMWARE/OVMF": ("firmware_start", "bootloader"),
    "KERNEL-EARLY":  ("bootloader", "apic"),
    "DRIVERS":       ("apic", "blk_probe"),
    "VFS-MOUNT":     ("blk_probe", "x11_ready"),
    "INIT":          ("x11_ready", "ff_launch"),
    "FF-STARTUP":    ("ff_launch", "libxul"),
    "LIBXUL-INIT":   ("libxul", "tcp"),
    "NETWORK/TLS":   ("tcp", "screenshot"),
    "RENDER-SETUP":  ("screenshot", "render_start_or_out_png"),
    "RENDER":        ("render_start", "out_png_open"),
    "ENCODE":        ("out_png_open", "png_written"),
    "TEARDOWN":      ("png_written", "exit_group"),
}

PHASE_NAMES = [p[0] for p in PHASES]
PHASE_AXIS = {p[0]: p[3] for p in PHASES}


def anchor_index(name):
    """Index of a named anchor in the ANCHORS sequence, or 0 if not found."""
    for i, (nm, _m) in enumerate(ANCHORS):
        if nm == name:
            return i
    return 0


def scan_phase_boundaries(path, start_index=0):
    """FORWARD-ORDERED monotone scan of a serial log -> dict of anchor hits.

    `start_index` lets a caller begin the monotone walk PAST the early anchors —
    used by the Linux baseline (which lacks the AstryxOS firmware/kernel-early/
    VFS/X11 markers): pass anchor_index('ff_launch') so the pre-FF anchors stay
    unmatched (their phases null) while the FF-onward chain maps. Default 0 = the
    full AstryxOS scan.

    Returns:
      {
        "anchors": { anchor_name: {"line": int, "tick": int|None, "sc": int|None} },
        "deepest_anchor": str | None,
        "max_tick": int | None,        # last kernel tick seen anywhere
        "max_sc": int | None,          # last pid=1 sc seen anywhere
        "panic": bool,
        "n_lines": int,
        "png_seen": bool,              # PNG magic seen ANYWHERE (global, ungated)
        "render_start": {...} | None,  # CrossProcessPaint/drawSnapshot if present
      }

    Anchor matching is monotone (anchor N+1 only matches at/after the deepest
    anchor already fired) so the AND-anchored render markers don't false-positive
    on Firefox's serialized-JS startup cache. BUT optional anchors (ANCHOR_OPTIONAL
    — tcp / screenshot / render_start / out_png_open) are NON-BLOCKING: when the
    cursor is sitting on an optional anchor that this run never emits (e.g. a
    file:// render emits no [TCP] line), the scan skips it (lookahead of exactly
    1) so the chain doesn't dead-end before png_written. A genuine PNG is
    therefore detected even on a no-network run.

    `png_seen` is a GLOBAL check (does the PNG magic appear anywhere) used for the
    honest reached_png flag, independent of whether the monotone chain reached the
    png_written anchor in order.
    """
    anchors = {}
    idx = start_index
    cur_tick = None
    cur_sc = None
    panic = False
    n = 0
    png_seen = False
    render_start = None
    render_markers = ("CrossProcessPaint", "drawSnapshot")
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                n += 1
                tk = _TICK_KERNEL.search(line)
                if tk:
                    cur_tick = int(tk.group(1))
                scm = _SC_RE.search(line)
                if scm:
                    cur_sc = int(scm.group(1))
                if not panic and _PANIC_RE.search(line):
                    panic = True
                if not png_seen and "89504e47" in line:
                    png_seen = True
                if render_start is None and any(m in line for m in render_markers):
                    render_start = {"line": n, "tick": cur_tick, "sc": cur_sc}
                # monotone anchor matching, with non-blocking optional anchors.
                # A single line can satisfy several anchors in sequence; advance
                # the cursor while the current anchor matches, OR while the current
                # anchor is optional-and-unmatched but the IMMEDIATELY-NEXT anchor
                # matches this line (skip just the one optional so the next anchor
                # can fire — lookahead of exactly 1, NOT skip-to-any-downstream).
                #
                # The lookahead-of-1 discipline is load-bearing: a "skip to any
                # deeper required anchor" rule would let a stray early line that
                # happens to contain a deep marker (e.g. a CHILD process emitting
                # `exit_group(`, or a `89504e47` echo) skip the whole render
                # section at once. Stepping one optional at a time means an
                # optional is only ever skipped when its true successor is present
                # on the same line, so a real screenshot/out_png_open line later in
                # the log still gets matched.
                while idx < len(ANCHORS):
                    name, marks = ANCHORS[idx]
                    if _match(line, marks):
                        anchors[name] = {"line": n, "tick": cur_tick, "sc": cur_sc}
                        idx += 1
                        continue
                    # current anchor didn't match. If it's optional AND the very
                    # next anchor matches this line, skip just this optional and
                    # let the loop fire the next anchor. Otherwise stop (the
                    # current anchor blocks until its own line arrives).
                    if (name in ANCHOR_OPTIONAL and idx + 1 < len(ANCHORS)
                            and _match(line, ANCHORS[idx + 1][1])):
                        idx += 1   # skip this optional; re-loop fires the next
                        continue
                    break
    except OSError:
        pass
    deepest = ANCHORS[idx - 1][0] if idx > start_index else None
    return {
        "anchors": anchors,
        "deepest_anchor": deepest,
        "max_tick": cur_tick,
        "max_sc": cur_sc,
        "panic": panic,
        "n_lines": n,
        "png_seen": png_seen,
        "render_start": render_start,
    }


def phase_durations(scan, host_anchor_ms=None):
    """Derive per-phase tick-axis durations from a scan_phase_boundaries result.

    Returns a dict mapping phase name -> {
        "reached": bool,            # was the `to` anchor hit?
        "from_line", "to_line": int|None,
        "from_tick", "to_tick": int|None,
        "tick_ms": float|None,      # (to_tick - from_tick) * 10ms, when both ticks known
        "axis": "tick"|"host",      # design's recoverable axis for this phase
    }

    `host_anchor_ms` is reserved for a LIVE run where the caller passes a parallel
    list of host-time stamps per anchor; on a historical import it is None and the
    host axis stays null. (perf-bench `run` populates host timing separately.)
    """
    anchors = scan.get("anchors", {})
    # render_start: prefer the anchor the monotone scan recorded (kept in order),
    # falling back to the free-standing first-occurrence record for robustness.
    render_start = anchors.get("render_start") or scan.get("render_start")
    out = {}

    def _resolve(anchor_key):
        """Resolve a PHASE_SPAN anchor name to a hit dict (or None). Handles the
        synthetic `render_start_or_out_png` boundary for RENDER-SETUP."""
        if anchor_key is None:
            return None
        if anchor_key == "render_start":
            return render_start
        if anchor_key == "render_start_or_out_png":
            # RENDER-SETUP ends at render_start when the build emits one, else at
            # out_png_open. This keeps RENDER-SETUP and RENDER disjoint: if
            # render_start exists, RENDER-SETUP=screenshot->render_start and
            # RENDER=render_start->out_png_open; if not, RENDER-SETUP carries the
            # whole screenshot->out_png_open interval and RENDER is null.
            return render_start or anchors.get("out_png_open")
        return anchors.get(anchor_key)

    for name in PHASE_NAMES:
        frm, to = PHASE_SPAN[name]
        a_from = _resolve(frm)
        a_to = _resolve(to)
        ft = a_from.get("tick") if a_from else None
        tt = a_to.get("tick") if a_to else None
        tick_ms = None
        if ft is not None and tt is not None and tt >= ft:
            tick_ms = ticks_to_ms(tt - ft)
        out[name] = {
            "reached": a_to is not None,
            "from_line": a_from.get("line") if a_from else None,
            "to_line": a_to.get("line") if a_to else None,
            "from_tick": ft,
            "to_tick": tt,
            "tick_ms": tick_ms,
            "axis": PHASE_AXIS[name],
        }
    return out


# ── feature inference (historical logs carry no session json) ────────────────
# When the session .json is gone, infer which build features were on from serial
# markers. Additive-only: callers store this as `features_inferred`, distinct
# from the authoritative `features` field a live run reads from the session json.
_FEATURE_MARKERS = {
    "kdb":            ("[KDB] listening", "kdb introspection server"),
    "firefox-test":   ("[FFTEST]", "firefox-bin"),
    "syscall-trace":  ("[SC] ", "[SYSCALL] "),
    "blk-trace":      ("[BLK] op=",),
    "differential-trace": ("[DIFF]", "differential-trace"),
    "smp":            ("AP online", "per-CPU TSSes for BSP"),
}


def infer_features(path, scan_bytes=512 * 1024):
    """Best-effort feature set inferred from the head+tail of a serial log."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(min(scan_bytes, size))
            tail = b""
            if size > scan_bytes:
                f.seek(max(0, size - scan_bytes))
                tail = f.read(scan_bytes)
        text = (head + tail).decode("latin-1", "replace")
    except OSError:
        return []
    found = []
    for feat, marks in _FEATURE_MARKERS.items():
        if any(m in text for m in marks):
            found.append(feat)
    return sorted(found)


def event_anchor(sid, harness_dir):
    """Recover the TRUE host launch time + effective-KVM flag from the per-session
    event stream <sid>.events.jsonl. The harness writes a `cpu_model` event as the
    FIRST line of that file at QEMU-launch time, carrying:
        ts             host epoch seconds at launch (= the real started_at)
        kvm_effective  whether KVM was actually used for this run
    This is the recoverable ground truth when the session <sid>.json is gone (the
    historical logs have 0 surviving .json files). Returns
    (ts|None, kvm_effective|None). Reads only the first line — O(1)."""
    ev = os.path.join(harness_dir, sid + ".events.jsonl")
    if not os.path.exists(ev):
        return None, None
    try:
        import json
        with open(ev, "r", errors="replace") as f:
            first = f.readline()
        d = json.loads(first)
        ts = d.get("ts")
        kvm = d.get("kvm_effective")
        ts = float(ts) if isinstance(ts, (int, float)) else None
        return ts, (kvm if isinstance(kvm, bool) else None)
    except Exception:
        return None, None


def launch_anchor(sid, log_path, harness_dir):
    """Host launch time for `sid`, in priority order:
        1. started_at from <sid>.json            (authoritative live-run anchor)
        2. ts from the first <sid>.events.jsonl line (recoverable true launch —
           the cpu_model event the harness writes AT launch); see event_anchor
        3. log mtime                             (coarse proxy = run-END, ~minutes
           to hours LATE vs the true launch — last resort only)
    Returns (epoch_seconds | None, source_str). The mtime fallback is explicitly
    the run-END time and must not be trusted as a launch anchor when events.jsonl
    is present (which it is for ~all historical logs)."""
    meta = os.path.join(harness_dir, sid + ".json")
    if os.path.exists(meta):
        try:
            import json
            m = json.load(open(meta))
            if isinstance(m.get("started_at"), (int, float)):
                return float(m["started_at"]), "json"
        except Exception:
            pass
    ev_ts, _ = event_anchor(sid, harness_dir)
    if ev_ts is not None:
        return ev_ts, "events.jsonl"
    try:
        return os.path.getmtime(log_path), "log-mtime"
    except OSError:
        return None, "none"
