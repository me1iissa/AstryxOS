#!/usr/bin/env python3
"""
smoke.py — minimal unit test for the differential-soak diff engine.

Exercises the parsers and the alignment logic against synthetic inputs
so a regression in `scripts/differential-soak.py` is caught without
needing a full Linux capture + AstryxOS QEMU boot.

Usage (one-shot):
    python3 scripts/differential/smoke.py

Exit codes:
    0  — all checks passed
    1  — one or more failures
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ds", ROOT / "differential-soak.py")
assert spec and spec.loader
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)


def _check(name: str, cond: bool, detail: str = "") -> bool:
    tag = "PASS" if cond else "FAIL"
    extra = f"  ({detail})" if detail else ""
    print(f"  [{tag}] {name}{extra}")
    return cond


def main() -> int:
    failures: list[str] = []

    # ── snapshot config loader ─────────────────────────────────────────
    cfg = ds.load_snapshot_config(ds.SNAPSHOTS_DEFAULT)
    if not _check("snapshot config loads", cfg.get("version") == 1,
                  f"got={cfg.get('version')}"):
        failures.append("snapshot config version != 1")
    if not _check("snapshot config has entries",
                  len(cfg.get("snapshots", [])) >= 5,
                  f"count={len(cfg.get('snapshots', []))}"):
        failures.append("fewer than 5 snapshot entries")

    # ── astryx [SC]/[SC-RET] parser ────────────────────────────────────
    sample = (
        "[BOOT] init OK\n"
        "[SC] pid=12 tid=12 nr=12 rip=0x1 cr=0x2 a1=0x0 a2=0x10 "
        "a3=0x0 a4=0x0 a5=0x0 a6=0x0\n"
        "[SC-RET] pid=12 tid=12 nr=12 ret=0x7f1234567000\n"
        "[SC] pid=12 tid=12 nr=257 rip=0x3 cr=0x4 a1=0xffffff9c "
        "a2=0x10 a3=0x0 a4=0x0 a5=0x0 a6=0x0\n"
        "[SC-RET] pid=12 tid=12 nr=257 ret=0xfffffffffffffffe\n"
    )
    tf = tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w")
    tf.write(sample); tf.close()
    n2n = {12: "brk", 257: "openat"}
    recs = ds.parse_astryx_serial(Path(tf.name), n2n)
    if not _check("parses 2 [SC] records",
                  len(recs) == 2, f"got={len(recs)}"):
        failures.append("[SC] parser count")
    if not _check("brk return is positive",
                  recs[0].get("ret") == 0x7f1234567000,
                  f"got={recs[0].get('ret')}"):
        failures.append("brk ret")
    if not _check("openat ENOENT sign-extended",
                  recs[1].get("ret") == -2,
                  f"got={recs[1].get('ret')}"):
        failures.append("openat -ENOENT sign")

    # ── diff engine: matching streams → no_divergence ──────────────────
    same = [
        {"src": "linux", "pid": 1, "tid": 1, "name": "brk", "nr": 12,
         "args": ["NULL"], "ret": 0x100, "errno": None},
        {"src": "linux", "pid": 1, "tid": 1, "name": "mmap", "nr": 9,
         "args": ["NULL", "4096"], "ret": 0x200, "errno": None},
    ]
    astryx_same = [
        {"src": "astryx", "pid": 1, "tid": 1, "name": "brk", "nr": 12,
         "args": ["0x0"], "ret": 0x100},
        {"src": "astryx", "pid": 1, "tid": 1, "name": "mmap", "nr": 9,
         "args": ["0x0", "0x1000"], "ret": 0x200},
    ]
    diff = ds.diff_streams(same, astryx_same, {"snapshots": []})
    if not _check("aligned streams → no_divergence",
                  diff["summary"]["divergence_class"] == "no_divergence",
                  f"got={diff['summary']['divergence_class']}"):
        failures.append("clean match misclassified")
    if not _check("first_divergence is None when aligned",
                  diff["first_divergence"] is None):
        failures.append("first_divergence not None")

    # ── diff engine: retval sign divergence ────────────────────────────
    linux = same + [{"src": "linux", "pid": 1, "tid": 1, "name": "read",
                     "nr": 0, "args": ["3", "...", "4096"], "ret": 50,
                     "errno": None}]
    astryx = astryx_same + [{"src": "astryx", "pid": 1, "tid": 1,
                             "name": "read", "nr": 0,
                             "args": ["0x3", "...", "0x1000"], "ret": -22}]
    diff = ds.diff_streams(linux, astryx, {"snapshots": []})
    if not _check("retval sign flip detected",
                  diff["summary"]["divergence_class"] == "retval_sign"):
        failures.append("retval sign flip")
    if not _check("divergence at index 2",
                  diff["first_divergence"]["sc_index"] == 2):
        failures.append("divergence sc_index")

    # ── diff engine: missing call ──────────────────────────────────────
    astryx_skip = astryx_same + [{"src": "astryx", "pid": 1, "tid": 1,
                                   "name": "write", "nr": 1,
                                   "args": ["0x1"], "ret": 5}]
    diff = ds.diff_streams(linux, astryx_skip, {"snapshots": []})
    if not _check("nr mismatch → missing_or_extra_call",
                  diff["summary"]["divergence_class"] == "missing_or_extra_call"):
        failures.append("nr mismatch class")

    # ── diff engine: snapshot hits recorded ────────────────────────────
    snap_cfg = {"snapshots": [
        {"name": "post_brk", "syscall": "brk", "when": "after",
         "regions": [{"kind": "fs_base"}]},
    ]}
    diff = ds.diff_streams(same, astryx_same, snap_cfg)
    if not _check("snapshot trigger fires on brk",
                  len(diff["snapshot_hits"]) >= 1,
                  f"got={len(diff['snapshot_hits'])}"):
        failures.append("snapshot hits empty")

    # ── prefix-noise strip drops execve + ENOENT linker probes ─────────
    noisy = [
        {"name": "execve", "nr": 59, "args": [], "ret": 0, "errno": None},
        {"name": "openat", "nr": 257, "args": [], "ret": -1,
         "errno": "ENOENT"},
        {"name": "access", "nr": 21, "args": [], "ret": -1,
         "errno": "ENOENT"},
        {"name": "brk", "nr": 12, "args": [], "ret": 0x1000, "errno": None},
    ]
    stripped, dropped = ds._strip_linux_prefix_noise(noisy)
    if not _check("prefix strip removes execve + ENOENT probes",
                  dropped == 3 and len(stripped) == 1 and stripped[0]["name"] == "brk",
                  f"dropped={dropped} remaining={[s['name'] for s in stripped]}"):
        failures.append("prefix strip behaviour")

    print()
    if failures:
        print(f"FAILED ({len(failures)}): {', '.join(failures)}")
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
