#!/usr/bin/env python3
"""
strace-ref.py — Linux reference strace captures for ABI conformance work.

Runs the **same musl-linked firefox-esr binary** that AstryxOS ships, but
under a real Linux kernel (the host kernel), and records the syscall trace
that abi-compatibility-engineer can diff against AstryxOS serial logs.

Use case:
  AstryxOS shows a futex / signal / clone wedge that may be either an
  AstryxOS-kernel ABI bug OR a quirk of Mozilla's userspace.  Capturing
  the reference Linux trace lets us distinguish "Linux does it this way
  too" from "AstryxOS diverges here".

## Architecture

  +----------------------------+
  |  HOST  (Ubuntu 26.04)      |
  |                            |
  |  strace -f -e trace=...    |    captures syscalls of …
  |   |                        |
  |   v                        |
  |  bwrap --ro-bind rootfs /  |    … this bubblewrap sandbox, which …
  |   |                        |
  |   v                        |
  |  Alpine 3.20 musl rootfs   |    … runs the SAME firefox-esr-115.24.0
  |  firefox-esr-115.24.0esr   |    binary that AstryxOS pre-caches.
  |                            |
  +----------------------------+

No virtualisation, no LXC overhead: bwrap is a kernel-namespace sandbox
that takes ~50 ms to enter and shares the host kernel.  The "reference"
is the host's real Linux kernel — exactly what we want.

## Subcommands

  setup           Idempotent: prepare the Alpine rootfs (uses
                  ~/.cache/astryxos-firefox-musl/rootfs/ if present, else
                  bootstraps via apk-static).
  capture         Run firefox-esr under strace inside the rootfs, write
                  the trace to disk.  Structured JSON status on stdout.
  diff            Compare a captured Linux trace against an AstryxOS
                  serial log (extracting [FUTEX_*] / [SC_*] lines).
                  JSON output.
  list            List previously captured traces.
  clean           Remove cached traces.

All subcommands print one JSON object to stdout on completion.  No REPL,
no prompts, no persistent stdin — agent-friendly per AstryxOS invariant.

## Hard rules

- Reference rootfs lives in ~/.astryx-harness/strace-ref/ (or reuses
  the pre-existing ~/.cache/astryxos-firefox-musl/rootfs/ — same Alpine
  3.20 / firefox-esr-115.24.0esr that AstryxOS ships).
- Captures live in ~/.astryx-harness/strace-ref/captures/.
- Read access only into the rootfs; trace output writes go to host /tmp.
- Per ELF gABI and ld-musl(8), Mozilla DSOs are dlopen'd via the
  DT_RUNPATH baked into libxul (/usr/lib/firefox-esr/); the bwrap mount
  preserves that layout.

References (public):
- strace(1) man page: https://man7.org/linux/man-pages/man1/strace.1.html
- bwrap(1) man page: https://github.com/containers/bubblewrap
- futex(2):           https://man7.org/linux/man-pages/man2/futex.2.html
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

HARNESS_DIR = Path.home() / ".astryx-harness"
REF_ROOT = HARNESS_DIR / "strace-ref"
REF_CAPTURES = REF_ROOT / "captures"
REF_ROOTFS_LOCAL = REF_ROOT / "rootfs"

# The AstryxOS firefox-esr build pipeline already produces an Alpine 3.20
# rootfs with musl firefox-esr 115.24.0 in it.  Reuse it if present — it's
# bit-for-bit the same binary that ships in build/disk/.
ASTRYX_ROOTFS_CACHE = Path.home() / ".cache" / "astryxos-firefox-musl" / "rootfs"

# Default firefox-esr launcher path inside the rootfs.
FF_LAUNCHER_REL = "usr/lib/firefox-esr/firefox-esr"


# ---------------------------------------------------------------------------
# JSON output helpers
# ---------------------------------------------------------------------------

def emit(payload: dict[str, Any]) -> None:
    """Print one JSON object to stdout, flush, exit normally."""
    print(json.dumps(payload, indent=2, default=str))
    sys.stdout.flush()


def die(reason: str, **extra: Any) -> None:
    out = {"ok": False, "error": reason}
    out.update(extra)
    print(json.dumps(out, indent=2, default=str))
    sys.stdout.flush()
    sys.exit(1)


# ---------------------------------------------------------------------------
# Rootfs resolution
# ---------------------------------------------------------------------------

def find_rootfs(explicit: Path | None = None) -> tuple[Path, str]:
    """
    Resolve which Alpine rootfs to use, in priority order:
      1. --rootfs explicit override
      2. ~/.astryx-harness/strace-ref/rootfs/ (if previously set up by us)
      3. ~/.cache/astryxos-firefox-musl/rootfs/ (the AstryxOS build cache)

    Returns (path, source-label).  Raises on failure.
    """
    candidates: list[tuple[Path, str]] = []
    if explicit is not None:
        candidates.append((explicit, "explicit"))
    candidates.append((REF_ROOTFS_LOCAL, "strace-ref-local"))
    candidates.append((ASTRYX_ROOTFS_CACHE, "astryxos-firefox-musl-cache"))

    for path, label in candidates:
        if (path / FF_LAUNCHER_REL).exists():
            return path, label
    raise FileNotFoundError(
        "No usable Alpine rootfs found.  Tried: "
        + ", ".join(str(p) for p, _ in candidates)
        + ".  Hint: run `scripts/install-firefox-musl.sh` to populate "
        "the AstryxOS firefox-esr cache first."
    )


def prepare_rootfs_writable_dirs(rootfs: Path) -> None:
    """
    The Alpine rootfs from apk-add --no-scripts lacks /home /run /root /sys.
    bwrap needs them as mount points (even with --tmpfs / --ro-bind).  We
    create empty dirs in the rootfs once; this is the only mutation we ever
    do to the shared cache and it's harmless.
    """
    for d in ("home", "root", "run", "sys"):
        (rootfs / d).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------

def cmd_setup(args: argparse.Namespace) -> int:
    """
    Prepare the reference rootfs.  Mostly a verification step — the heavy
    lifting (Alpine bootstrap + apk add firefox-esr) is done by
    install-firefox-musl.sh as part of the regular AstryxOS build.

    If --bootstrap is passed and no rootfs exists, we delegate to that
    script.  Otherwise we just verify.
    """
    REF_ROOT.mkdir(parents=True, exist_ok=True)
    REF_CAPTURES.mkdir(parents=True, exist_ok=True)

    try:
        rootfs, label = find_rootfs(
            Path(args.rootfs) if args.rootfs else None
        )
    except FileNotFoundError as exc:
        if not args.bootstrap:
            die(str(exc), hint="rerun with --bootstrap to invoke "
                "scripts/install-firefox-musl.sh")
            return 1
        # Bootstrap path — call the existing AstryxOS installer.
        install_script = Path(__file__).resolve().parent / "install-firefox-musl.sh"
        if not install_script.exists():
            die(f"bootstrap requested but {install_script} missing")
            return 1
        proc = subprocess.run(
            [str(install_script)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            die("install-firefox-musl.sh failed",
                stdout_tail=proc.stdout[-2000:],
                stderr_tail=proc.stderr[-2000:])
            return 1
        rootfs, label = find_rootfs()

    prepare_rootfs_writable_dirs(rootfs)

    # Sanity: the launcher must be a musl-linked PIE ELF.
    launcher = rootfs / FF_LAUNCHER_REL
    file_proc = subprocess.run(
        ["file", str(launcher)],
        capture_output=True, text=True,
    )
    is_musl = "ld-musl" in file_proc.stdout

    # Read firefox-esr version from application.ini
    appini = rootfs / "usr" / "lib" / "firefox-esr" / "application.ini"
    version = "unknown"
    if appini.exists():
        for line in appini.read_text().splitlines():
            if line.startswith("Version="):
                version = line.split("=", 1)[1].strip()
                break

    emit({
        "ok": True,
        "subcommand": "setup",
        "rootfs": str(rootfs),
        "rootfs_source": label,
        "firefox_launcher": str(launcher),
        "firefox_version": version,
        "is_musl": is_musl,
        "host_kernel": os.uname().release,
        "captures_dir": str(REF_CAPTURES),
    })
    return 0


# ---------------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------------

def cmd_capture(args: argparse.Namespace) -> int:
    """
    Run firefox-esr under strace inside bwrap.  Write a parseable trace
    to ~/.astryx-harness/strace-ref/captures/<label>.trace.

    The wrapping pattern is:
        strace -f -e trace=<filter> -o <out> --
            bwrap --ro-bind <rootfs> / --proc /proc --dev /dev
                  --ro-bind /sys /sys --tmpfs /tmp ... --
                <ff-launcher> [ff-args...]
    """
    REF_ROOT.mkdir(parents=True, exist_ok=True)
    REF_CAPTURES.mkdir(parents=True, exist_ok=True)

    try:
        rootfs, label = find_rootfs(
            Path(args.rootfs) if args.rootfs else None
        )
    except FileNotFoundError as exc:
        die(str(exc), hint="run `strace-ref.py setup --bootstrap`")
        return 1

    prepare_rootfs_writable_dirs(rootfs)

    launcher = rootfs / FF_LAUNCHER_REL
    if not launcher.exists():
        die(f"firefox launcher missing: {launcher}")
        return 1

    # Resolve output paths.
    label_clean = re.sub(r"[^\w\.\-]+", "_", args.label or
                         time.strftime("ref-%Y%m%d-%H%M%S"))
    out_trace = Path(args.output) if args.output else (
        REF_CAPTURES / f"{label_clean}.trace"
    )
    out_trace.parent.mkdir(parents=True, exist_ok=True)

    # Build strace argv.  We use --absolute-timestamps for diffing.
    strace_argv = ["strace"]
    if args.follow_forks:
        strace_argv.append("-f")
    # syscall filter
    syscalls = args.syscall_filter or "futex"
    strace_argv += ["-e", f"trace={syscalls}"]
    if args.timestamps:
        # -ttt: epoch microseconds prefix, easy to parse / diff.
        strace_argv += ["-ttt"]
    if args.string_size:
        strace_argv += ["-s", str(args.string_size)]
    strace_argv += ["-o", str(out_trace)]
    strace_argv.append("--")

    # bwrap argv — mirror the path layout AstryxOS uses.
    bwrap_argv = [
        "bwrap",
        "--ro-bind", str(rootfs), "/",
        "--proc", "/proc",
        "--dev", "/dev",
        "--ro-bind", "/sys", "/sys",
        "--tmpfs", "/tmp",
        "--tmpfs", "/var",
        "--tmpfs", "/home",
        "--tmpfs", "/root",
        "--tmpfs", "/run",
        "--setenv", "HOME", "/root",
        "--setenv", "PATH", "/usr/lib/firefox-esr:/usr/bin:/bin",
        "--setenv", "MOZ_HEADLESS", "1",
        "--die-with-parent",
    ]
    # Optional extra env from caller
    for kv in args.env or []:
        if "=" not in kv:
            die(f"--env entry must be KEY=VALUE: {kv!r}")
            return 1
        k, v = kv.split("=", 1)
        bwrap_argv += ["--setenv", k, v]

    # Inner argv — the firefox-esr launch.
    inner = [f"/{FF_LAUNCHER_REL}"]
    if args.binary_args:
        # Tokenise via shlex to honour quoting.
        import shlex as _shlex
        inner += _shlex.split(args.binary_args)

    argv = strace_argv + bwrap_argv + inner

    # Popen + communicate(timeout=...) so we still capture stdout/stderr
    # and the strace output file even if firefox-esr hangs past the
    # wall-clock budget (we kill on timeout, then collect partial output).
    started = time.time()
    p = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = p.communicate(
            timeout=args.timeout if args.timeout > 0 else None
        )
        timed_out = False
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            stdout, stderr = p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        timed_out = True
    elapsed = time.time() - started

    # Parse stats from the trace.
    stats = summarise_strace_trace(out_trace) if out_trace.exists() else {
        "lines": 0,
        "by_op": {},
        "tids": [],
        "size_bytes": 0,
    }

    # Persist a small JSON sidecar with metadata.
    meta = {
        "label": label_clean,
        "trace_path": str(out_trace),
        "host_kernel": os.uname().release,
        "rootfs": str(rootfs),
        "rootfs_source": label,
        "firefox_launcher": f"/{FF_LAUNCHER_REL}",
        "binary_args": args.binary_args,
        "syscall_filter": syscalls,
        "elapsed_s": round(elapsed, 3),
        "timed_out": timed_out,
        "captured_at": int(time.time()),
        "stats": stats,
        "stderr_tail": (stderr or "")[-2000:],
    }
    meta_path = out_trace.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2))

    emit({
        "ok": True,
        "subcommand": "capture",
        "trace_path": str(out_trace),
        "meta_path": str(meta_path),
        "label": label_clean,
        "elapsed_s": round(elapsed, 3),
        "timed_out": timed_out,
        "syscall_filter": syscalls,
        "stats": stats,
    })
    return 0


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

FUTEX_OP_BITS = {
    "WAIT":            0,
    "WAKE":            1,
    "REQUEUE":         3,
    "CMP_REQUEUE":     4,
    "WAKE_OP":         5,
    "LOCK_PI":         6,
    "UNLOCK_PI":       7,
    "WAIT_BITSET":     9,
    "WAKE_BITSET":    10,
}


# strace line formats (with -f -ttt -e trace=futex):
#   complete:    PID time futex(0xADDR, FUTEX_WAIT_PRIVATE, val, NULL) = rc
#   unfinished:  PID time futex(0xADDR, FUTEX_WAIT_PRIVATE, val, NULL <unfinished ...>
# We accept both — the "unfinished" case lacks a closing `)`/`=`, so the
# pattern stops at the first comma after `op` and is tolerant of either
# `)` or `<unfinished` terminating the call.
RE_STRACE_FUTEX = re.compile(
    r"""
    ^(?:(?P<tid>\d+)\s+)?           # optional tid (with -f)
    (?:(?P<ts>\d+\.\d+)\s+)?        # optional epoch timestamp
    futex\(
        \s*(?P<uaddr>0x[0-9a-fA-F]+|\d+)
        \s*,\s*(?P<op>FUTEX_[A-Z_]+)
        (?:\s*,\s*(?P<val>\S+?))?   # val (may be absent for some ops)
    """,
    re.VERBOSE,
)
# Separate pattern for the return-code tail when present.
RE_STRACE_FUTEX_RC = re.compile(r"\)\s*=\s*(?P<rc>-?\d+|\?)")


# AstryxOS serial log format:
#   [FUTEX_WAIT_REG] tid=2 pid=1 uaddr=0x... val=2 op=0x109 rip=... rsp=... rbp=...
#   [FUTEX_WAKE]     tid=2 pid=1 uaddr=0x... woken=0 max=... op=0x81
#   [FUTEX_WAKE_REQ] tid=2 pid=1 uaddr=0x... max=...     op=0x81 rip=... ...
RE_ASTRYX_FUTEX = re.compile(
    r"""
    ^\[(?P<tag>FUTEX_[A-Z_]+)\]\s+
    .*?tid=(?P<tid>\d+).*?
    uaddr=(?P<uaddr>0x[0-9a-fA-F]+)
    (?:.*?op=(?P<op>0x[0-9a-fA-F]+))?
    (?:.*?val=(?P<val>0x[0-9a-fA-F]+|\d+))?
    (?:.*?max=(?P<max>0x[0-9a-fA-F]+|\d+|\d+))?
    (?:.*?woken=(?P<woken>\d+))?
    """,
    re.VERBOSE,
)


def linux_op_class(op_str: str) -> str:
    """
    Reduce a Linux strace op symbol (FUTEX_WAIT_BITSET_PRIVATE) to a
    canonical class (WAIT_BITSET) so we can compare with AstryxOS, which
    only emits the numeric op (the _PRIVATE / _CLOCK_REALTIME bits live
    in the raw op constant on the AstryxOS side).
    """
    s = op_str
    if s.startswith("FUTEX_"):
        s = s[6:]
    # strip _PRIVATE / _CLOCK_REALTIME suffix
    for suf in ("_PRIVATE", "_CLOCK_REALTIME"):
        if s.endswith(suf):
            s = s[:-len(suf)]
    return s


def astryx_op_class(op_hex: str | None) -> str:
    """
    Decode an AstryxOS futex op hex (e.g. 0x109) into the canonical class
    label.  Bits:
        - low 7 = op number (futex.h)
        - bit 7 (0x80) = FUTEX_PRIVATE_FLAG
        - bit 8 (0x100) = FUTEX_CLOCK_REALTIME
    """
    if op_hex is None:
        return "?"
    try:
        n = int(op_hex, 16)
    except ValueError:
        return "?"
    code = n & 0x7F
    for name, num in FUTEX_OP_BITS.items():
        if num == code:
            return name
    return f"op{code}"


def parse_linux_trace(path: Path, max_lines: int = 0) -> dict[str, Any]:
    """
    Parse a strace -e trace=futex output file into a list of event dicts
    and aggregate stats.
    """
    events: list[dict[str, Any]] = []
    by_op = Counter()
    by_tid = Counter()
    uaddrs = set()
    line_count = 0
    with path.open("r", errors="replace") as f:
        for line in f:
            line_count += 1
            if max_lines and len(events) >= max_lines:
                break
            m = RE_STRACE_FUTEX.search(line)
            if not m:
                continue
            op = m.group("op") or ""
            cls = linux_op_class(op)
            uaddr = m.group("uaddr") or ""
            tid = m.group("tid") or ""
            rc_m = RE_STRACE_FUTEX_RC.search(line)
            ev = {
                "src": "linux",
                "ts": float(m.group("ts")) if m.group("ts") else None,
                "tid": int(tid) if tid.isdigit() else None,
                "uaddr": uaddr,
                "op_raw": op,
                "op_class": cls,
                "rc": rc_m.group("rc") if rc_m else None,
            }
            events.append(ev)
            by_op[cls] += 1
            if ev["tid"] is not None:
                by_tid[ev["tid"]] += 1
            uaddrs.add(uaddr)
    return {
        "events": events,
        "stats": {
            "lines": line_count,
            "matched": len(events),
            "by_op": dict(by_op.most_common()),
            "tids": sorted(by_tid),
            "by_tid": dict(by_tid.most_common(16)),
            "unique_uaddrs": len(uaddrs),
            "size_bytes": path.stat().st_size if path.exists() else 0,
        },
    }


# AstryxOS tags that represent *syscall entries* (one tag = one futex()
# syscall, directly comparable to one Linux strace line).
#
# Note: AstryxOS emits *two* lines per WAKE syscall — [FUTEX_WAKE_REQ]
# at entry and [FUTEX_WAKE] reporting the outcome.  Counting both would
# double the WAKE count relative to Linux.  We canonicalise on the entry
# tag (_REQ for WAKE, _REG for WAIT) so the histogram is 1:1 with Linux.
ASTRYX_SYSCALL_TAGS = {
    "FUTEX_WAIT_REG",   # waiter parked  (analogue: FUTEX_WAIT* entry)
    "FUTEX_WAKE_REQ",   # waker invoked  (analogue: FUTEX_WAKE* entry)
}


def parse_astryx_serial(path: Path) -> dict[str, Any]:
    """Parse an AstryxOS serial log for [FUTEX_*] lines.

    AstryxOS emits two kinds of [FUTEX_*] tags:
      - syscall-entry analogues (FUTEX_WAIT_REG, FUTEX_WAKE_REQ, FUTEX_WAKE):
        these correspond to actual Linux `futex()` calls.
      - kernel diagnostic events (FUTEX_WAIT_STACK, FUTEX_WAKE_EXIT,
        FUTEX_TIMEDOUT, FUTEX_WAKE_GHOST, FUTEX_CLUSTER_WAKE, ...):
        emitted for wedge analysis; no Linux counterpart.

    The by_op histogram is restricted to syscall-entry tags so it is
    directly comparable to a Linux strace run.  The by_tag histogram
    reports the full breakdown so diagnostic events remain visible.
    """
    events: list[dict[str, Any]] = []
    by_op = Counter()           # restricted to ASTRYX_SYSCALL_TAGS
    by_tid = Counter()
    by_tag = Counter()
    uaddrs = set()
    line_count = 0
    with path.open("r", errors="replace") as f:
        for line in f:
            line_count += 1
            m = RE_ASTRYX_FUTEX.search(line)
            if not m:
                continue
            tag = m.group("tag")
            op_hex = m.group("op")
            cls = astryx_op_class(op_hex)
            # FUTEX_WAIT_REG/FUTEX_WAKE_REQ emit the op explicitly; their
            # cls is meaningful.  FUTEX_WAKE re-emits the same op too.
            # Other tags have no op field; we don't count them in by_op.
            uaddr = m.group("uaddr") or ""
            tid = m.group("tid") or ""
            is_syscall_entry = tag in ASTRYX_SYSCALL_TAGS
            ev = {
                "src": "astryx",
                "tid": int(tid) if tid.isdigit() else None,
                "uaddr": uaddr,
                "op_raw": op_hex,
                "op_class": cls,
                "tag": tag,
                "syscall_entry": is_syscall_entry,
                "val": m.group("val"),
                "max": m.group("max"),
                "woken": m.group("woken"),
            }
            events.append(ev)
            if is_syscall_entry and cls != "?":
                by_op[cls] += 1
            by_tag[tag] += 1
            if ev["tid"] is not None:
                by_tid[ev["tid"]] += 1
            uaddrs.add(uaddr)
    return {
        "events": events,
        "stats": {
            "lines": line_count,
            "matched": len(events),
            "by_op": dict(by_op.most_common()),
            "by_tag": dict(by_tag.most_common()),
            "tids": sorted(by_tid),
            "by_tid": dict(by_tid.most_common(16)),
            "unique_uaddrs": len(uaddrs),
        },
    }


def summarise_strace_trace(path: Path) -> dict[str, Any]:
    """Lightweight summary for capture stats (no full event list)."""
    if not path.exists():
        return {"lines": 0, "by_op": {}, "tids": [], "size_bytes": 0}
    by_op = Counter()
    tids = set()
    line_count = 0
    with path.open("r", errors="replace") as f:
        for line in f:
            line_count += 1
            m = RE_STRACE_FUTEX.search(line)
            if m:
                cls = linux_op_class(m.group("op") or "")
                by_op[cls] += 1
                tid = m.group("tid")
                if tid and tid.isdigit():
                    tids.add(int(tid))
    return {
        "lines": line_count,
        "by_op": dict(by_op.most_common()),
        "tids": sorted(tids),
        "n_tids": len(tids),
        "size_bytes": path.stat().st_size,
    }


def cmd_diff(args: argparse.Namespace) -> int:
    """
    Compare a Linux strace futex trace against an AstryxOS serial log.

    Output schema (JSON):
      {
        "ok": true,
        "linux":  {"stats": {...}},
        "astryx": {"stats": {...}},
        "comparison": {
            "by_op":          [{"op":..., "linux":N, "astryx":M, "delta":...}, ...],
            "only_in_linux":  ["OP1", ...],   # ops Linux had that astryx didn't
            "only_in_astryx": ["OP1", ...],   # vice versa
            "ratio":          {"OP": <linux/astryx>, ...}
        },
        "notes": [...optional callouts...]
      }
    """
    linux_path = Path(args.linux_trace)
    if not linux_path.exists():
        die(f"linux trace not found: {linux_path}")
        return 1
    astryx_path = Path(args.astryx_log)
    if not astryx_path.exists():
        die(f"astryx log not found: {astryx_path}")
        return 1

    linux_parsed = parse_linux_trace(linux_path)
    astryx_parsed = parse_astryx_serial(astryx_path)

    # Build comparison.
    linux_ops = linux_parsed["stats"]["by_op"]
    astryx_ops = astryx_parsed["stats"]["by_op"]
    all_ops = set(linux_ops) | set(astryx_ops)
    by_op_compare = []
    for op in sorted(all_ops):
        l = linux_ops.get(op, 0)
        a = astryx_ops.get(op, 0)
        by_op_compare.append({
            "op": op,
            "linux": l,
            "astryx": a,
            "delta": a - l,
            "ratio": (a / l) if l else None,
        })

    only_linux = sorted(set(linux_ops) - set(astryx_ops))
    only_astryx = sorted(set(astryx_ops) - set(linux_ops))

    notes: list[str] = []
    if only_astryx:
        notes.append(
            f"AstryxOS emitted {len(only_astryx)} op class(es) absent from "
            f"Linux: {only_astryx}.  Likely AstryxOS-specific or a missing "
            "Linux subset."
        )
    if only_linux:
        notes.append(
            f"Linux emitted {len(only_linux)} op class(es) absent from "
            f"AstryxOS: {only_linux}.  Possible ABI-coverage gap."
        )

    # Detect WAKE/WAIT imbalance hint (cv-wedge signature).
    a_wait = astryx_ops.get("WAIT_BITSET", 0) + astryx_ops.get("WAIT", 0)
    a_wake = astryx_ops.get("WAKE", 0) + astryx_ops.get("WAKE_BITSET", 0)
    l_wait = linux_ops.get("WAIT_BITSET", 0) + linux_ops.get("WAIT", 0)
    l_wake = linux_ops.get("WAKE", 0) + linux_ops.get("WAKE_BITSET", 0)
    if a_wait > 0 and a_wake / max(a_wait, 1) < 0.5 and l_wake / max(l_wait, 1) >= 0.7:
        notes.append(
            "AstryxOS WAKE/WAIT ratio is low compared to Linux reference. "
            "Consistent with a cv-wedge: waiters parking but wakers not "
            "firing (e.g. wrong uaddr key, FUTEX_WAKE_GHOST class)."
        )

    # Volume-ratio note: if AstryxOS produces << Linux events, that's the
    # plateau signature (kernel stops handling syscalls because userspace
    # is stuck spinning).
    l_total = sum(linux_ops.values())
    a_total = sum(astryx_ops.values())
    if l_total > 0 and a_total / l_total < 0.20:
        notes.append(
            f"AstryxOS futex volume is {a_total} vs Linux {l_total} "
            f"({100*a_total/l_total:.1f}%).  Consistent with a userspace "
            "plateau (libxul stuck, kernel rarely entered)."
        )

    # Diagnostic-tag callouts — these only live on AstryxOS so they're
    # the highest-signal items for abi-compat.
    diag_tags = {
        "FUTEX_TIMEDOUT":      "FUTEX_WAIT_BITSET returned -ETIMEDOUT",
        "FUTEX_WAKE_GHOST":    "FUTEX_WAKE delivered to a uaddr with NO "
                               "registered waiter (W101 ghost class)",
        "FUTEX_WAKE_GHOST_HIST": "history-based ghost-uaddr offset histogram "
                                 "(PR #288 diagnostic)",
        "FUTEX_CLUSTER_WAKE":  "bounded-broadcast compensation for ghost "
                               "wakes (PR #287)",
    }
    astryx_tags = astryx_parsed["stats"].get("by_tag", {})
    for tag, desc in diag_tags.items():
        n = astryx_tags.get(tag, 0)
        if n > 0:
            notes.append(
                f"AstryxOS emitted [{tag}] x{n} — {desc}.  No Linux analogue."
            )

    out: dict[str, Any] = {
        "ok": True,
        "subcommand": "diff",
        "linux": {
            "path": str(linux_path),
            "stats": linux_parsed["stats"],
        },
        "astryx": {
            "path": str(astryx_path),
            "stats": astryx_parsed["stats"],
        },
        "comparison": {
            "by_op": by_op_compare,
            "only_in_linux": only_linux,
            "only_in_astryx": only_astryx,
        },
        "notes": notes,
    }
    if args.verbose:
        out["linux"]["events_head"] = linux_parsed["events"][:50]
        out["astryx"]["events_head"] = astryx_parsed["events"][:50]
    emit(out)
    return 0


# ---------------------------------------------------------------------------
# list / clean
# ---------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> int:
    REF_CAPTURES.mkdir(parents=True, exist_ok=True)
    items = []
    for meta_path in sorted(REF_CAPTURES.glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text())
            items.append({
                "label": meta.get("label"),
                "captured_at": meta.get("captured_at"),
                "trace_path": meta.get("trace_path"),
                "elapsed_s": meta.get("elapsed_s"),
                "timed_out": meta.get("timed_out"),
                "stats": meta.get("stats", {}),
                "host_kernel": meta.get("host_kernel"),
            })
        except Exception as e:
            items.append({"meta_path": str(meta_path), "error": str(e)})
    emit({
        "ok": True,
        "subcommand": "list",
        "captures_dir": str(REF_CAPTURES),
        "captures": items,
    })
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    removed: list[str] = []
    if REF_CAPTURES.exists():
        for p in list(REF_CAPTURES.iterdir()):
            if args.label and args.label not in p.name:
                continue
            removed.append(str(p))
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
    emit({
        "ok": True,
        "subcommand": "clean",
        "removed": removed,
    })
    return 0


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="strace-ref.py",
        description="Linux reference strace captures for AstryxOS ABI work.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # setup
    p_setup = sub.add_parser(
        "setup",
        help="Verify (and optionally bootstrap) the Alpine reference rootfs.",
    )
    p_setup.add_argument("--rootfs", default=None,
                         help="Explicit path to an Alpine rootfs to use.")
    p_setup.add_argument("--bootstrap", action="store_true",
                         help="If no rootfs is found, invoke "
                              "scripts/install-firefox-musl.sh to create one.")
    p_setup.set_defaults(func=cmd_setup)

    # capture
    p_capture = sub.add_parser(
        "capture",
        help="Run firefox-esr under strace inside bwrap; emit a trace file.",
    )
    p_capture.add_argument("--label", default=None,
                           help="Short label for this capture (default: "
                                "ref-YYYYMMDD-HHMMSS).")
    p_capture.add_argument("--output", default=None,
                           help="Override trace output path "
                                "(default: ~/.astryx-harness/strace-ref/"
                                "captures/<label>.trace).")
    p_capture.add_argument("--binary", default=None,
                           help="Override firefox launcher path inside the "
                                "rootfs (default: /usr/lib/firefox-esr/firefox-esr).")
    p_capture.add_argument("--binary-args", default="--version",
                           help="Args passed to the binary.  Quote-supported "
                                "via shlex.  Default: --version (smoke).  "
                                "For ABI-comparison runs use e.g. "
                                "'--headless --screenshot=/root/out.png about:blank'.")
    p_capture.add_argument("--syscall-filter", default="futex",
                           help="strace -e trace= filter (default: futex).  "
                                "Can be a comma list: "
                                "'futex,clone,rt_sigaction,mmap'.")
    p_capture.add_argument("--timeout", type=int, default=60,
                           help="Wall-clock timeout in seconds (default: 60). "
                                "0 disables.")
    p_capture.add_argument("--rootfs", default=None,
                           help="Override Alpine rootfs path.")
    p_capture.add_argument("--no-follow-forks", dest="follow_forks",
                           action="store_false", default=True,
                           help="Don't pass -f to strace.")
    p_capture.add_argument("--no-timestamps", dest="timestamps",
                           action="store_false", default=True,
                           help="Don't pass -ttt to strace.")
    p_capture.add_argument("--string-size", type=int, default=256,
                           help="strace -s argument (string truncation).")
    p_capture.add_argument("--env", action="append", default=[],
                           metavar="KEY=VALUE",
                           help="Extra env vars for the binary (repeatable).")
    p_capture.set_defaults(func=cmd_capture)

    # diff
    p_diff = sub.add_parser(
        "diff",
        help="Compare a Linux strace trace against an AstryxOS serial log.",
    )
    p_diff.add_argument("--linux-trace", required=True,
                        help="Path to a strace futex trace (from `capture`).")
    p_diff.add_argument("--astryx-log", required=True,
                        help="Path to an AstryxOS serial log "
                             "(~/.astryx-harness/<sid>.serial.log).")
    p_diff.add_argument("--verbose", action="store_true",
                        help="Include up to 50 head events from each side.")
    p_diff.set_defaults(func=cmd_diff)

    # list / clean
    p_list = sub.add_parser("list", help="List captured traces.")
    p_list.set_defaults(func=cmd_list)
    p_clean = sub.add_parser("clean", help="Remove captures (optionally filtered).")
    p_clean.add_argument("--label", default=None,
                         help="Only remove captures whose path contains this "
                              "substring.")
    p_clean.set_defaults(func=cmd_clean)

    return p


def main() -> None:
    parser = make_parser()
    args = parser.parse_args()
    rc = args.func(args)
    if isinstance(rc, int):
        sys.exit(rc)


if __name__ == "__main__":
    main()
