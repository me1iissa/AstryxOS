#!/usr/bin/env python3
"""
differential-soak.py — INFRA-1 differential bytestream harness.

End-to-end orchestrator that runs the same musl `firefox-bin` under
**both** a Linux reference kernel and the AstryxOS QEMU kernel, then
aligns the two syscall bytestreams and reports the FIRST divergence.

Designed to replace the saga-style "guess-a-hypothesis-then-soak" loop
with continuous differential observation: every divergence is a named
ABI gap that an engineering agent can pick up directly.

## Architecture

  ┌───────────────────────────────────────────────────────────────────┐
  │                      differential-soak                            │
  │                                                                   │
  │  ┌──────────────────────┐         ┌───────────────────────────┐  │
  │  │  Linux reference     │         │  AstryxOS QEMU            │  │
  │  │  (host kernel via    │         │  (qemu-harness start +    │  │
  │  │   bwrap + strace)    │         │   --features              │  │
  │  │   strace-ref.py      │         │   firefox-test,           │  │
  │  │                      │         │   syscall-trace)          │  │
  │  └──────────┬───────────┘         └──────────────┬────────────┘  │
  │             │                                    │               │
  │             │  trace.<tid> (strace -ff)          │  [SC]/[SC-RET]│
  │             │                                    │  serial log   │
  │             ▼                                    ▼               │
  │  ┌────────────────────────────────────────────────────────────┐  │
  │  │             differential diff engine                       │  │
  │  │  • parse both streams into unified call records            │  │
  │  │  • align by (sc_name, ordinal) per pid/tid                 │  │
  │  │  • snapshot config (scripts/differential/snapshots.yaml)   │  │
  │  │  • emit first_divergence + summary                         │  │
  │  └────────────────────────────────────────────────────────────┘  │
  │                              │                                    │
  │                              ▼                                    │
  │                       {first_divergence: ..., summary: ...}       │
  └───────────────────────────────────────────────────────────────────┘

## Linux side: bwrap + host kernel

Per `strace-ref.py`, we run the SAME `firefox-bin` AstryxOS ships in
its data.img, under the HOST Linux kernel, inside a bubblewrap sandbox.
This shares the host kernel directly — no virtualisation overhead, and
the kernel under test on the Linux side is a real upstream Linux
kernel exactly as a user would have it.  Alpine LXC was the original
option but bwrap is faster (~50 ms entry) and uses the same musl
firefox-esr binary already in the cache.

## AstryxOS side: qemu-harness.py start

We launch QEMU via the standard `start` subcommand with
`--features firefox-test,differential-trace`.  The `differential-trace`
feature is a meta-feature that pulls in `firefox-test` + `syscall-trace`,
so every Linux syscall emits a `[SC]` line + paired `[SC-RET]` line on
the serial log.

The harness then waits up to --boot-timeout-ms for the kernel
"FIREFOX_BOOT_SETUP_END" banner before collecting traces.

## Diff engine

  1. Parse Linux strace into a list of `Call` records (one per syscall,
     keyed by `(pid, tid, ordinal)`).
  2. Parse AstryxOS serial log [SC] + [SC-RET] into the same shape.
  3. Walk both streams in lock-step.  For each step:
     - If `sc_nr` (canonical) differs → `kind=missing` divergence.
     - If args differ on a structured arg position → `kind=arg`.
     - If retval differs (sign or magnitude) → `kind=retval`.
     - If a configured snapshot point fires here, compare the
       memory snapshot regions → `kind=mempage` divergence.
  4. Emit first divergence with context window.

## Subcommand contract

  python3 scripts/qemu-harness.py differential-soak \\
      --baseline-lxc <ignored, kept for forward compat> \\
      --astryx-features firefox-test,differential-trace \\
      [--max-syscalls N] \\
      [--boot-timeout-ms MS] \\
      [--linux-timeout-s SEC] \\
      [--snapshots PATH] \\
      [--reuse-linux-capture LABEL] \\
      [--reuse-astryx-log PATH] \\
      [--output /tmp/diff.json] \\
      [--no-build] [--no-kvm]

The subcommand prints exactly one JSON object to stdout on completion;
also writes the full diff to --output if supplied.  Agent-friendly:
one-shot argv, no REPL, no interactive prompts.  Per AstryxOS invariant
in `CLAUDE.md`.

## Public references (cited per CLAUDE.md no-private-corpus rule)

  - strace(1):           https://man7.org/linux/man-pages/man1/strace.1.html
  - bwrap(1):            https://github.com/containers/bubblewrap
  - System V AMD64 ABI:  https://gitlab.com/x86-psABIs/x86-64-ABI
  - Linux syscall table: kernel.org Documentation/admin-guide/syscalls/
  - Intel SDM Vol. 3:    §3.4.4 FS/GS segment register
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

# Optional YAML — fall back to JSON snapshot config if PyYAML is missing.
try:
    import yaml  # type: ignore
    _HAVE_YAML = True
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore
    _HAVE_YAML = False


# ── Paths ──────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
HARNESS_PY = SCRIPT_DIR / "qemu-harness.py"
STRACE_REF_PY = SCRIPT_DIR / "strace-ref.py"
SNAPSHOTS_DEFAULT = SCRIPT_DIR / "differential" / "snapshots.yaml"
HARNESS_DIR = Path.home() / ".astryx-harness"
DIFF_DIR = HARNESS_DIR / "differential"
DIFF_DIR.mkdir(parents=True, exist_ok=True)


# ── JSON I/O ───────────────────────────────────────────────────────────────────

def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, default=str))
    sys.stdout.flush()


def _die(reason: str, **extra: Any) -> int:
    out = {"ok": False, "error": reason}
    out.update(extra)
    print(json.dumps(out, indent=2, default=str))
    sys.stdout.flush()
    return 1


# ── Snapshot config loader ─────────────────────────────────────────────────────

def load_snapshot_config(path: Path) -> dict[str, Any]:
    """Load snapshots.yaml (or .json fallback).  Never raises — returns
    an empty config on parse error so the diff still runs.
    """
    if not path.exists():
        return {"version": 0, "snapshots": [], "_warning": f"missing: {path}"}
    raw = path.read_text()
    parsed: Any = None
    if path.suffix.lower() in (".yaml", ".yml") and _HAVE_YAML:
        try:
            parsed = yaml.safe_load(raw)
        except Exception as exc:
            return {"version": 0, "snapshots": [], "_warning": f"yaml parse: {exc}"}
    else:
        try:
            parsed = json.loads(raw)
        except Exception as exc:
            return {"version": 0, "snapshots": [], "_warning": f"json parse: {exc}"}
    if not isinstance(parsed, dict):
        return {"version": 0, "snapshots": [], "_warning": "config not a dict"}
    parsed.setdefault("snapshots", [])
    if not isinstance(parsed["snapshots"], list):
        parsed["snapshots"] = []
        parsed["_warning"] = "snapshots: not a list"
    return parsed


# ── Syscall name table ─────────────────────────────────────────────────────────
#
# We delegate to syscall-diff.py's loader because it already handles the
# unistd_64.h fallback for the full Firefox-startup set.  Imported lazily
# to keep this module standalone for unit tests.

def _load_syscall_table() -> tuple[dict[int, str], dict[str, int]]:
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "syscall_diff", SCRIPT_DIR / "syscall-diff.py"
        )
        if spec is None or spec.loader is None:
            raise ImportError("could not load syscall-diff.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.load_syscall_table()  # type: ignore[attr-defined]
    finally:
        if str(SCRIPT_DIR) in sys.path:
            sys.path.remove(str(SCRIPT_DIR))


# ── Linux strace parsing ───────────────────────────────────────────────────────
#
# strace -f -e trace=all -ttt -y -s256 firefox-bin --headless --screenshot ...
#
# Sample (with -f -ttt):
#   2415  1747991234.123456 execve("/usr/lib/firefox-esr/firefox-esr", [...], ...) = 0
#   2415  1747991234.124001 brk(NULL)               = 0x55c4b9a5d000
#   2415  1747991234.124102 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
#
# We parse a (pid, ts, name, args[], ret, errno) tuple per line.

_RE_STRACE_LINE = re.compile(
    r"""
    ^(?:(?P<pid>\d+)\s+)?               # optional pid (with -f)
    (?:(?P<ts>\d+\.\d+)\s+)?            # optional epoch timestamp
    (?P<name>[a-z_][a-z0-9_]*)          # syscall name
    \((?P<args>.*)\)\s*=\s*             # arg list + " = "
    (?P<ret>-?\d+|0x[0-9a-fA-F]+|\?)    # return value
    (?:\s+(?P<errno>[A-Z_][A-Z0-9_]+))? # optional errno
    """,
    re.VERBOSE,
)

_RE_STRACE_UNFIN = re.compile(
    r"""
    ^(?:(?P<pid>\d+)\s+)?
    (?:(?P<ts>\d+\.\d+)\s+)?
    (?P<name>[a-z_][a-z0-9_]*)
    \((?P<args>.*?)
    \s*<unfinished
    """,
    re.VERBOSE,
)

_RE_STRACE_IGNORE = re.compile(r"^\+\+\+|^---")


def _split_strace_args(s: str, max_args: int = 6) -> list[str]:
    """Top-level comma split honouring nested braces/brackets/strings."""
    out: list[str] = []
    depth = 0
    in_str = False
    escape = False
    cur: list[str] = []
    for i, c in enumerate(s):
        if in_str:
            cur.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            if len(out) >= max_args:
                rest = s[i + 1:].strip()
                if rest:
                    out.append(rest)
                return out
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur).strip())
    return out


def parse_linux_trace_dir(trace_dir: Path,
                          name_to_nr: dict[str, int],
                          max_per_tid: int = 0,
                          ) -> list[dict[str, Any]]:
    """Parse a directory of strace -ff `trace.<tid>` files into a single
    flat list of call records, ordered by epoch timestamp (cross-thread).
    """
    records: list[dict[str, Any]] = []
    if not trace_dir.is_dir():
        return records
    for p in sorted(trace_dir.glob("trace.*")):
        # Filename is `trace.<tid>`.
        try:
            tid_from_name = int(p.name.split(".", 1)[1])
        except (IndexError, ValueError):
            tid_from_name = 0
        per_tid_count = 0
        with p.open("r", errors="replace") as fh:
            for line in fh:
                if _RE_STRACE_IGNORE.match(line):
                    continue
                m = _RE_STRACE_LINE.match(line.rstrip())
                if m:
                    name = m.group("name")
                    nr = name_to_nr.get(name, -1)
                    ret = m.group("ret")
                    try:
                        ret_val = int(ret, 0) if ret != "?" else None
                    except ValueError:
                        ret_val = None
                    pid = int(m.group("pid")) if m.group("pid") else tid_from_name
                    rec = {
                        "src":   "linux",
                        "pid":   pid,
                        "tid":   tid_from_name,
                        "ts":    float(m.group("ts")) if m.group("ts") else None,
                        "name":  name,
                        "nr":    nr,
                        "args":  _split_strace_args(m.group("args"))[:6],
                        "ret":   ret_val,
                        "errno": m.group("errno"),
                    }
                    records.append(rec)
                    per_tid_count += 1
                    if max_per_tid and per_tid_count >= max_per_tid:
                        break
                    continue
                mu = _RE_STRACE_UNFIN.match(line.rstrip())
                if mu:
                    name = mu.group("name")
                    pid = int(mu.group("pid")) if mu.group("pid") else tid_from_name
                    rec = {
                        "src":   "linux",
                        "pid":   pid,
                        "tid":   tid_from_name,
                        "ts":    float(mu.group("ts")) if mu.group("ts") else None,
                        "name":  name,
                        "nr":    name_to_nr.get(name, -1),
                        "args":  _split_strace_args(mu.group("args"))[:6],
                        "ret":   None,
                        "errno": None,
                        "unfinished": True,
                    }
                    records.append(rec)
                    per_tid_count += 1
                    if max_per_tid and per_tid_count >= max_per_tid:
                        break
    # Order across files by timestamp so the diff reflects wall-clock
    # interleaving — but keep records without ts at their file-natural
    # position (sort is stable in Python).
    records.sort(key=lambda r: (r.get("ts") or 0.0))
    return records


# ── AstryxOS [SC] + [SC-RET] parsing ───────────────────────────────────────────

_RE_SC = re.compile(
    r"""
    ^\[SC\]\s+
    pid=(?P<pid>\d+)\s+
    tid=(?P<tid>\d+)\s+
    nr=(?P<nr>\d+)\s+
    rip=(?P<rip>0x[0-9a-fA-F]+)\s+
    cr=(?P<cr>0x[0-9a-fA-F]+)\s+
    a1=(?P<a1>0x[0-9a-fA-F]+)\s+
    a2=(?P<a2>0x[0-9a-fA-F]+)\s+
    a3=(?P<a3>0x[0-9a-fA-F]+)\s+
    a4=(?P<a4>0x[0-9a-fA-F]+)\s+
    a5=(?P<a5>0x[0-9a-fA-F]+)\s+
    a6=(?P<a6>0x[0-9a-fA-F]+)
    """,
    re.VERBOSE,
)
_RE_SC_RET = re.compile(
    r"""
    ^\[SC-RET\]\s+
    pid=(?P<pid>\d+)\s+
    tid=(?P<tid>\d+)\s+
    nr=(?P<nr>\d+)\s+
    ret=(?P<ret>0x[0-9a-fA-F]+)
    """,
    re.VERBOSE,
)


def parse_astryx_serial(path: Path,
                        nr_to_name: dict[int, str],
                        pid_filter: int | None = None,
                        max_records: int = 0,
                        ) -> list[dict[str, Any]]:
    """Walk an AstryxOS serial log and emit a list of call records.

    Pairs [SC] entry lines with their matching [SC-RET] line (matched by
    (pid, tid, nr) — kernel guarantees these are serial per-thread).
    Unmatched entries get ret=None (kernel crashed mid-syscall — still
    a useful diff signal).
    """
    records: list[dict[str, Any]] = []
    pending: dict[tuple[int, int, int], int] = {}  # (pid,tid,nr) -> records idx
    if not path.exists():
        return records
    with path.open("r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()
            m = _RE_SC.match(line)
            if m:
                pid = int(m.group("pid"))
                if pid_filter is not None and pid != pid_filter:
                    continue
                tid = int(m.group("tid"))
                nr = int(m.group("nr"))
                rec = {
                    "src":   "astryx",
                    "pid":   pid,
                    "tid":   tid,
                    "ts":    None,                    # serial line has no ts
                    "name":  nr_to_name.get(nr, f"syscall_{nr}"),
                    "nr":    nr,
                    "args":  [
                        m.group("a1"), m.group("a2"), m.group("a3"),
                        m.group("a4"), m.group("a5"), m.group("a6"),
                    ],
                    "rip":   m.group("rip"),
                    "cr":    m.group("cr"),
                    "ret":   None,
                    "errno": None,
                }
                records.append(rec)
                pending[(pid, tid, nr)] = len(records) - 1
                if max_records and len(records) >= max_records:
                    break
                continue
            r = _RE_SC_RET.match(line)
            if r:
                key = (int(r.group("pid")), int(r.group("tid")), int(r.group("nr")))
                ret_u64 = int(r.group("ret"), 16)
                # Sign-extend: ret is u64; if high bit set it's a Linux -errno.
                ret_s64 = ret_u64 - (1 << 64) if ret_u64 & (1 << 63) else ret_u64
                idx = pending.pop(key, None)
                if idx is not None:
                    records[idx]["ret"] = ret_s64
    return records


# ── Alignment + diff engine ────────────────────────────────────────────────────

# ABI-divergent prefix that the dynamic linker emits before the streams
# converge.  These calls reflect host-vs-AstryxOS layout differences
# (ld.so cache location, hwcaps subdirs, env-var-driven probes) and are
# uninformative for ABI-correctness work.
_LD_PROBE_NAMES = {"openat", "newfstatat", "access", "stat", "fstat", "lstat"}


def _strip_linux_prefix_noise(linux: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Drop the initial execve (AstryxOS doesn't surface it in [SC])
    plus any leading ENOENT linker probes.  Returns (rest, dropped).
    """
    out: list[dict[str, Any]] = []
    dropped = 0
    saw_execve = False
    in_prefix = True
    for c in linux:
        if in_prefix and not saw_execve and c["name"] == "execve":
            saw_execve = True
            dropped += 1
            continue
        if in_prefix and c["name"] in _LD_PROBE_NAMES and c.get("errno") == "ENOENT":
            dropped += 1
            continue
        in_prefix = False
        out.append(c)
    return out, dropped


def _arg_match_strace(args: list[str], wanted: str) -> bool:
    """Is `wanted` a substring of any positional arg's strace rendering?"""
    return any(wanted in a for a in args)


def _classify(linux_rec: dict[str, Any] | None,
              astryx_rec: dict[str, Any] | None) -> str:
    if linux_rec is None:
        return "linux_truncated"
    if astryx_rec is None:
        return "astryx_truncated"
    if linux_rec["nr"] != astryx_rec["nr"]:
        return "missing_or_extra_call"
    # Same syscall.  Check retval shape (only if Linux has one).
    lret = linux_rec.get("ret")
    aret = astryx_rec.get("ret")
    if lret is not None and aret is not None:
        if (lret < 0) != (aret < 0):
            return "retval_sign"
        if lret != aret:
            return "retval_value"
    # Same nr, retval matches (or astryx ret missing) — flag arg shape.
    return "args_or_seq"


def _summarise_record(r: dict[str, Any] | None) -> dict[str, Any] | None:
    if r is None:
        return None
    return {
        "pid":   r["pid"],
        "tid":   r["tid"],
        "ts":    r.get("ts"),
        "name":  r["name"],
        "nr":    r["nr"],
        "args":  r["args"][:6],
        "ret":   r.get("ret"),
        "errno": r.get("errno"),
        "rip":   r.get("rip"),
    }


def diff_streams(linux: list[dict[str, Any]],
                 astryx: list[dict[str, Any]],
                 snapshot_cfg: dict[str, Any],
                 context: int = 5,
                 ) -> dict[str, Any]:
    """Lock-step walk; first index where (nr, ret) disagrees is the verdict.
    Snapshot points are advisory — they augment the diff with named
    region comparisons but do not by themselves trigger a divergence
    (snapshot data isn't currently captured live; this is the hook for
    future per-syscall page-dump emission).
    """
    snap_points = {s["name"]: s for s in snapshot_cfg.get("snapshots", [])
                   if isinstance(s, dict) and s.get("name")}
    snap_by_syscall: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in snap_points.values():
        sc = s.get("syscall")
        if sc:
            snap_by_syscall[sc].append(s)

    n = min(len(linux), len(astryx))
    aligned = 0
    first_idx: int | None = None
    snapshot_hits: list[dict[str, Any]] = []
    for i in range(n):
        L, A = linux[i], astryx[i]
        # Record any configured snapshot point fired here — useful for
        # post-diagnosis even when no divergence is found.
        for s in snap_by_syscall.get(L["name"], []):
            am = s.get("arg_match")
            if am and not _arg_match_strace(L["args"], am):
                continue
            snapshot_hits.append({
                "index":    i,
                "syscall":  L["name"],
                "snapshot": s["name"],
                "when":     s.get("when"),
                "regions":  s.get("regions", []),
                "linux":    _summarise_record(L),
                "astryx":   _summarise_record(A),
            })
        if L["nr"] != A["nr"]:
            first_idx = i
            break
        # Same nr — check retval divergence (both sides known).
        lret, aret = L.get("ret"), A.get("ret")
        if lret is not None and aret is not None and lret != aret:
            first_idx = i
            break
        aligned += 1

    summary: dict[str, Any] = {
        "linux_total_calls":   len(linux),
        "astryx_total_calls":  len(astryx),
        "aligned_calls":       aligned,
        "snapshot_hits_count": len(snapshot_hits),
    }

    if first_idx is None:
        if len(linux) != len(astryx):
            tail_idx = min(len(linux), len(astryx))
            summary["divergence_class"] = (
                "linux_truncated" if len(linux) < len(astryx) else "astryx_truncated"
            )
            return {
                "summary": summary,
                "first_divergence": {
                    "sc_index": tail_idx,
                    "kind":     summary["divergence_class"],
                    "linux":    _summarise_record(linux[tail_idx])
                                if tail_idx < len(linux) else None,
                    "astryx":   _summarise_record(astryx[tail_idx])
                                if tail_idx < len(astryx) else None,
                },
                "context_lines":  _context_window(linux, astryx, tail_idx, context),
                "snapshot_hits":  snapshot_hits[:32],
            }
        summary["divergence_class"] = "no_divergence"
        return {
            "summary": summary,
            "first_divergence": None,
            "context_lines": [],
            "snapshot_hits": snapshot_hits[:32],
        }

    L, A = linux[first_idx], astryx[first_idx]
    summary["divergence_class"] = _classify(L, A)
    return {
        "summary": summary,
        "first_divergence": {
            "sc_index": first_idx,
            "kind":     summary["divergence_class"],
            "linux":    _summarise_record(L),
            "astryx":   _summarise_record(A),
        },
        "context_lines":  _context_window(linux, astryx, first_idx, context),
        "snapshot_hits":  snapshot_hits[:32],
    }


def _context_window(linux: list[dict[str, Any]],
                    astryx: list[dict[str, Any]],
                    i: int, n: int) -> dict[str, Any]:
    lo = max(0, i - n)
    return {
        "window_start": lo,
        "linux":  [_summarise_record(c) for c in linux[lo:i + n + 1]],
        "astryx": [_summarise_record(c) for c in astryx[lo:i + n + 1]],
    }


# ── Linux side: capture (or reuse) via strace-ref.py ───────────────────────────

def capture_linux(label: str,
                  binary_args: str,
                  timeout_s: int,
                  reuse: str | None,
                  ) -> dict[str, Any]:
    """Either reuse a previously captured trace, or run strace-ref.py.

    The trace lives under ~/.astryx-harness/strace-ref/captures/.  In
    --reuse mode we skip the run and just resolve the path.
    """
    cap_dir = HARNESS_DIR / "strace-ref" / "captures"
    cap_dir.mkdir(parents=True, exist_ok=True)
    if reuse:
        # Two acceptable forms: a label or an absolute path.
        p = Path(reuse)
        if not p.exists():
            p = cap_dir / f"{reuse}.trace"
        if not p.exists():
            return {"ok": False, "error": f"reuse trace not found: {reuse}"}
        return {"ok": True, "trace_path": str(p), "reused": True}

    if not STRACE_REF_PY.exists():
        return {"ok": False, "error": f"missing helper: {STRACE_REF_PY}"}

    cmd = [
        sys.executable, str(STRACE_REF_PY), "capture",
        "--label",          label,
        "--binary-args",    binary_args,
        "--syscall-filter", "all",       # full stream for differential diff
        "--timeout",        str(timeout_s),
        "--string-size",    "256",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "strace-ref.py capture failed",
            "stdout_tail": (proc.stdout or "")[-2000:],
            "stderr_tail": (proc.stderr or "")[-2000:],
        }
    try:
        meta = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "error": "strace-ref.py emitted non-JSON",
            "stdout_tail": (proc.stdout or "")[-2000:],
        }
    return {
        "ok":          True,
        "trace_path":  meta.get("trace_path"),
        "elapsed_s":   meta.get("elapsed_s"),
        "timed_out":   meta.get("timed_out"),
        "stats":       meta.get("stats"),
        "reused":      False,
    }


def _linux_trace_dir(trace_path: Path) -> Path:
    """strace-ref.py captures into a single file (-o <out>).  If the
    user passed `strace -ff -o DIR/prefix` they get a directory of
    `prefix.<tid>` files instead.  Auto-detect both shapes.
    """
    if trace_path.is_dir():
        return trace_path
    # Single-file shape.  Wrap in a synthetic dir-of-one for the parser.
    parent = trace_path.parent
    # Create a sibling layout `<file>.dir/trace.<pid>` symlinking the
    # single file so parse_linux_trace_dir's glob works.  Only do this
    # on first sight to avoid littering on reruns.
    shim = parent / f"{trace_path.stem}.dir"
    shim.mkdir(parents=True, exist_ok=True)
    link = shim / "trace.0"
    if not link.exists():
        try:
            link.symlink_to(trace_path)
        except OSError:
            # Fall back to a copy if symlink isn't permitted.
            link.write_bytes(trace_path.read_bytes())
    return shim


# ── AstryxOS side: launch + wait + collect via qemu-harness.py ─────────────────

def _harness_json(*argv: str) -> dict[str, Any]:
    cmd = [sys.executable, str(HARNESS_PY)] + list(argv)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout:
        return {"ok": False, "error": "harness failed",
                "argv": argv, "rc": proc.returncode,
                "stderr_tail": (proc.stderr or "")[-2000:]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": "harness emitted non-JSON",
                "argv": argv, "rc": proc.returncode,
                "stdout_tail": (proc.stdout or "")[-2000:]}


def launch_astryx(features: str,
                  no_build: bool,
                  no_kvm: bool,
                  boot_timeout_ms: int,
                  reuse_log: str | None,
                  ) -> dict[str, Any]:
    """Start a QEMU session (or reuse an existing serial log) and return
    {"sid": ..., "serial_log": ...} on success.
    """
    if reuse_log:
        p = Path(reuse_log)
        if not p.exists():
            return {"ok": False, "error": f"reuse log not found: {reuse_log}"}
        return {"ok": True, "sid": None, "serial_log": str(p), "reused": True}

    argv = ["start", "--features", features]
    if no_build:
        argv.append("--no-build")
    if no_kvm:
        argv.append("--no-kvm")
    r = _harness_json(*argv)
    if not r.get("ok") and r.get("sid") is None:
        return {"ok": False, "error": "harness start failed", "harness": r}
    sid = r.get("sid")
    if not sid:
        return {"ok": False, "error": "no sid in start response", "harness": r}
    # Wait for the firefox-test boot completion marker.  If that pattern
    # never appears (early panic), the wait times out and we still
    # collect whatever serial data was captured — partial diffs are
    # better than no diff for early-crash analysis.
    wait_r = _harness_json("wait", sid, r"FIREFOX_BOOT_SETUP_END|firefox-test ready|\[SC\] ",
                           "--ms", str(boot_timeout_ms))
    return {
        "ok":         True,
        "sid":        sid,
        "serial_log": r.get("serial_log") or str(HARNESS_DIR / f"{sid}.serial.log"),
        "wait":       wait_r,
        "reused":     False,
        "start":      r,
    }


def stop_astryx(sid: str) -> dict[str, Any]:
    return _harness_json("stop", sid)


# ── Orchestrator ───────────────────────────────────────────────────────────────

def cmd_run(args: argparse.Namespace) -> int:
    t0 = time.time()
    snapshots_path = Path(args.snapshots) if args.snapshots else SNAPSHOTS_DEFAULT
    snapshot_cfg = load_snapshot_config(snapshots_path)

    # ── Step 1: Linux baseline capture (or reuse) ──────────────────────
    linux_label = args.linux_label or time.strftime("diff-%Y%m%d-%H%M%S")
    linux_step = capture_linux(
        label=linux_label,
        binary_args=args.linux_binary_args,
        timeout_s=args.linux_timeout_s,
        reuse=args.reuse_linux_capture,
    )
    if not linux_step.get("ok"):
        return _die("linux capture failed", linux=linux_step,
                    snapshot_cfg_warning=snapshot_cfg.get("_warning"))

    # ── Step 2: AstryxOS QEMU launch (or reuse log) ────────────────────
    sid_to_stop: str | None = None
    if args.reuse_astryx_log:
        astryx_step = launch_astryx(args.astryx_features, args.no_build,
                                    args.no_kvm, args.boot_timeout_ms,
                                    reuse_log=args.reuse_astryx_log)
    else:
        astryx_step = launch_astryx(args.astryx_features, args.no_build,
                                    args.no_kvm, args.boot_timeout_ms,
                                    reuse_log=None)
        if astryx_step.get("ok") and astryx_step.get("sid"):
            sid_to_stop = astryx_step["sid"]
    if not astryx_step.get("ok"):
        return _die("astryx launch failed", astryx=astryx_step,
                    linux=linux_step)

    try:
        # Give the kernel a moment to emit some [SC] lines after boot.
        if not args.reuse_astryx_log and args.post_boot_settle_ms > 0:
            time.sleep(args.post_boot_settle_ms / 1000.0)

        # ── Step 3: parse both streams ────────────────────────────────
        nr_to_name, name_to_nr = _load_syscall_table()

        linux_trace_path = Path(linux_step["trace_path"])
        linux_dir = _linux_trace_dir(linux_trace_path)
        linux_calls = parse_linux_trace_dir(
            linux_dir, name_to_nr,
            max_per_tid=args.max_syscalls // 4 if args.max_syscalls else 0,
        )
        if args.max_syscalls:
            linux_calls = linux_calls[:args.max_syscalls]

        astryx_serial = Path(astryx_step["serial_log"])
        astryx_calls = parse_astryx_serial(
            astryx_serial, nr_to_name,
            pid_filter=args.astryx_pid,
            max_records=args.max_syscalls,
        )

        # Strip the host-vs-guest linker noise from the Linux side.
        if args.strip_linux_prefix:
            linux_calls, dropped = _strip_linux_prefix_noise(linux_calls)
        else:
            dropped = 0

        # ── Step 4: diff ──────────────────────────────────────────────
        diff = diff_streams(linux_calls, astryx_calls,
                            snapshot_cfg, context=args.context)
    finally:
        # ── Step 5: stop QEMU (always, even on parser exception) ──────
        if sid_to_stop and not args.keep_session:
            stop_astryx(sid_to_stop)

    elapsed = round(time.time() - t0, 3)
    out = {
        "ok":               True,
        "subcommand":       "differential-soak",
        "elapsed_s":        elapsed,
        "snapshots":        {
            "path":     str(snapshots_path),
            "version":  snapshot_cfg.get("version"),
            "warning":  snapshot_cfg.get("_warning"),
            "count":    len(snapshot_cfg.get("snapshots", [])),
        },
        "linux": {
            "trace_path":      linux_step.get("trace_path"),
            "elapsed_s":       linux_step.get("elapsed_s"),
            "timed_out":       linux_step.get("timed_out"),
            "reused":          linux_step.get("reused"),
            "calls_parsed":    len(linux_calls),
            "prefix_dropped":  dropped,
        },
        "astryx": {
            "sid":             astryx_step.get("sid"),
            "serial_log":      astryx_step.get("serial_log"),
            "reused":          astryx_step.get("reused"),
            "wait":            astryx_step.get("wait"),
            "calls_parsed":    len(astryx_calls),
        },
        "first_divergence": diff["first_divergence"],
        "summary":          diff["summary"],
        "context_lines":    diff["context_lines"],
        "snapshot_hits":    diff["snapshot_hits"],
    }
    if args.output:
        try:
            Path(args.output).write_text(json.dumps(out, indent=2, default=str))
        except OSError as exc:
            out["_output_write_error"] = str(exc)
    _emit(out)
    return 0


# ── argparse ───────────────────────────────────────────────────────────────────

def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="differential-soak.py",
        description="Differential bytestream harness (Linux ↔ AstryxOS).",
    )
    sub = p.add_subparsers(dest="cmd", required=False)

    p_run = sub.add_parser(
        "run",
        help="End-to-end run: Linux capture (or reuse) + AstryxOS QEMU "
             "launch (or reuse) + diff.  Default subcommand when invoked "
             "with no subcommand.",
    )
    p_list = sub.add_parser(
        "list",
        help="List prior differential runs cached under "
             "~/.astryx-harness/differential/.",
    )
    p_list.set_defaults(_op="list")
    p_run.set_defaults(_op="run")

    # The dispatch was specified with --baseline-lxc; we accept it but
    # ignore the value (bwrap+host-kernel is the actual reference path).
    p_run.add_argument("--baseline-lxc", default=None,
                       help="[ignored — reference is bwrap+host-kernel via "
                            "strace-ref.py.  Accepted for forward compat.]")
    p_run.add_argument("--astryx-features",
                       default="firefox-test,differential-trace",
                       help="Kernel features for the AstryxOS run.  "
                            "Must include syscall-trace (directly or via "
                            "the meta-feature differential-trace).  "
                            "Default: firefox-test,differential-trace.")
    p_run.add_argument("--max-syscalls", type=int, default=0,
                       help="Truncate each stream to N records before "
                            "diffing.  0 = no truncation.  Useful to "
                            "isolate a window around a known divergence.")
    p_run.add_argument("--boot-timeout-ms", type=int, default=180000,
                       help="ms to wait for AstryxOS boot completion banner "
                            "(default 180000 = 3 min).")
    p_run.add_argument("--post-boot-settle-ms", type=int, default=2000,
                       help="ms to sleep after boot completes, letting "
                            "some [SC] lines accumulate before parsing "
                            "(default 2000).")
    p_run.add_argument("--linux-timeout-s", type=int, default=30,
                       help="strace wall-clock budget for the Linux run "
                            "(default 30).")
    p_run.add_argument("--linux-binary-args",
                       default="--headless --screenshot=/tmp/diff-shot.png "
                               "http://example.com",
                       help="argv tail for firefox-bin on the Linux side.")
    p_run.add_argument("--linux-label", default=None,
                       help="Label for the Linux strace capture "
                            "(default: diff-YYYYMMDD-HHMMSS).")
    p_run.add_argument("--snapshots", default=None,
                       help=f"Snapshot config path (default: {SNAPSHOTS_DEFAULT}).")
    p_run.add_argument("--astryx-pid", type=int, default=None,
                       help="If set, restrict AstryxOS [SC] parsing to "
                            "this PID.  Default: no filter (every "
                            "Linux-personality pid).")
    p_run.add_argument("--reuse-linux-capture", default=None,
                       help="Reuse an existing Linux strace capture by "
                            "label or absolute path.  Skips the strace step.")
    p_run.add_argument("--reuse-astryx-log", default=None,
                       help="Reuse an existing AstryxOS serial log "
                            "(absolute path).  Skips the QEMU launch step.")
    p_run.add_argument("--no-build", action="store_true",
                       help="Pass --no-build to qemu-harness start.")
    p_run.add_argument("--no-kvm", action="store_true",
                       help="Force-disable KVM (debug-only; significantly slower).")
    p_run.add_argument("--keep-session", action="store_true",
                       help="Don't stop the AstryxOS QEMU session after "
                            "diffing.  Useful for follow-up kdb / grep queries.")
    p_run.add_argument("--strip-linux-prefix", action="store_true",
                       default=True,
                       help="Drop initial execve + leading ENOENT linker "
                            "probes from the Linux side (default on).")
    p_run.add_argument("--no-strip-linux-prefix", dest="strip_linux_prefix",
                       action="store_false",
                       help="Disable the prefix-noise strip.")
    p_run.add_argument("--context", type=int, default=5,
                       help="Records of context on each side around the "
                            "first-divergence row (default 5).")
    p_run.add_argument("--output", default=None,
                       help="Write full JSON diff to this path (in "
                            "addition to stdout).")
    return p


def cmd_list(args: argparse.Namespace) -> int:
    """List previously written differential-soak result files."""
    items: list[dict[str, Any]] = []
    if DIFF_DIR.exists():
        for p in sorted(DIFF_DIR.glob("*.json")):
            try:
                blob = json.loads(p.read_text())
                items.append({
                    "path":              str(p),
                    "elapsed_s":         blob.get("elapsed_s"),
                    "summary":           blob.get("summary"),
                    "first_divergence":  blob.get("first_divergence"),
                })
            except Exception as exc:  # pragma: no cover
                items.append({"path": str(p), "error": str(exc)})
    _emit({"ok": True, "subcommand": "list",
           "results_dir": str(DIFF_DIR), "results": items})
    return 0


def main() -> int:
    argv = sys.argv[1:]
    # Backwards-compat: if user passes flags directly (no subcommand),
    # treat as implicit `run`.  This keeps the dispatch-spec invocation
    # `differential-soak --reuse-linux-capture ...` working.
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["run"] + argv
    args = make_parser().parse_args(argv)
    op = getattr(args, "_op", "run")
    if op == "list":
        return cmd_list(args)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
