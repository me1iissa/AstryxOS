#!/usr/bin/env python3
"""
perf-baseline-linux-smoke.py — Host-side smoke test for perf-baseline-linux.py

Exercises the Linux KVM baseline runner end-to-end WITHOUT booting a VM (no
download, no QEMU, no network). All checks are one-shot argv -> JSON, run
against a SYNTHETIC baseline serial log and the runner's own dry-run plumbing:

  - acquire-image: prints reproducible download+build steps, never downloads,
    pins Alpine/apk-tools versions, detects cached-rootfs reuse vs fresh apk
    bootstrap per requested firefox package
  - run (dry-run): image-present check + exact qemu argv (KVM -cpu host, 2 vCPU,
    2048 MiB matching firefox-test) + rendered guest init (valid POSIX sh) +
    the record it WOULD emit (timing null, dry_run=True)
  - scan_baseline_log: starts the monotone scan at ff_launch so a Linux log
    (no AstryxOS pre-FF markers) still lights up FF-STARTUP..TEARDOWN + reaches
    PNG, while pre-FF phases stay null
  - parse-log: a synthetic baseline log -> a record with the comparable
    ff_exec_to_png_ms window, written to an isolated store
  - record schema is compatible with perf-bench (source=baseline-linux merges)
  - status: image-present + store summary

Run directly:

    python3 scripts/perf-baseline-linux-smoke.py

Exit codes:
    0  — all checks passed
    1  — one or more checks failed
"""

import os
import sys
import json
import tempfile
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
RUNNER = SCRIPTS / "perf-baseline-linux.py"
PY = sys.executable

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"

# A synthetic Linux baseline serial log: a healthy Alpine FF screenshot that
# completes in ~9.25 s. It deliberately carries NONE of the AstryxOS pre-FF
# markers (no [AstryxBoot]/Phase 5b/[VFS] Probing/X11), exactly like a real
# stock-Linux boot would. It DOES carry the FF-onward markers + the advisory
# guest [BASELINE] ff_exec_epoch / png_epoch lines the runner emits.
SYNTHETIC_BASELINE_LOG = """\
[    0.000000] Linux version 6.6.30-0-virt (Alpine 6.6.30)
[    0.412331] Run /sbin/init as init process
[BASELINE] alpine init up; launching upstream Firefox
[BASELINE] ff_exec_epoch=1717531200.100000
[FFTEST] Launching /usr/lib/firefox-esr/firefox-bin ...
[FF/open] pid=1 path=/usr/lib/firefox-esr/libxul.so
[TCP] Established (loopback)
[FF/write] pid=1 getDimensions ScreenshotParent sendQuery
[BASELINE] png_epoch=1717531209.350000
[FF/open] pid=1 path=/tmp/out.png
[FF-OUT-PNG:path=/tmp/out.png size=18342 sig_ok=true] out.png written
[FF/write-fd] pid=1 fd=9 len=18342 bytes=89504e470d0a1a0a PNG magic confirmed
[BASELINE] firefox exit_group(0)
[PROC] PID 1 exit_group(0) caller_tid=1
"""


def run(args, env=None):
    res = subprocess.run([PY, str(RUNNER)] + args,
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

    print(f"[{INFO}] perf-baseline-linux smoke test (host-only, no QEMU/network)")

    # ── import the runner module directly for scan_baseline_log unit checks ───
    sys.path.insert(0, str(SCRIPTS))
    import importlib.util
    spec = importlib.util.spec_from_file_location("pbl", str(RUNNER))
    pbl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pbl)
    import perf_markers as pm
    print(f"[{INFO}] markers source: {pm.MARKERS_SOURCE}")

    with tempfile.TemporaryDirectory() as td:
        perf_dir = Path(td) / "perf"
        log = Path(td) / "baseline.serial.log"
        log.write_text(SYNTHETIC_BASELINE_LOG)

        env = dict(os.environ)
        env["ASTRYX_PERF_DIR"] = str(perf_dir)
        # isolate from the committed .perf/baseline.json so the `perf-bench list`
        # cross-check counts only the record this smoke writes to the temp store.
        empty_baseline = Path(td) / "baseline.json"
        empty_baseline.write_text('{"schema_v":1,"records":[]}')
        env["ASTRYX_PERF_BASELINE"] = str(empty_baseline)
        # Do NOT let an unlock env var leak in from the parent shell.
        env.pop("ASTRYX_PERF_ALLOW_BOOT", None)

        # ── scan_baseline_log: FF-onward anchors fire; pre-FF stay null ───────
        scan = pbl.scan_baseline_log(str(log))
        check("scan_baseline_log: scan_kind tagged",
              scan.get("scan_kind") == "baseline-ff-onward",
              str(scan.get("scan_kind")))
        check("scan_baseline_log: ff_launch anchor fires",
              "ff_launch" in scan["anchors"])
        check("scan_baseline_log: png_written anchor fires",
              "png_written" in scan["anchors"])
        check("scan_baseline_log: deepest == exit_group",
              scan["deepest_anchor"] == "exit_group", str(scan["deepest_anchor"]))
        check("scan_baseline_log: pre-FF anchors NOT spuriously matched",
              "firmware_start" not in scan["anchors"]
              and "x11_ready" not in scan["anchors"])
        check("scan_baseline_log: no panic", scan["panic"] is False)

        d = pm.phase_durations(scan)
        # FF-onward phases reached; pre-FF phases have no `from` boundary.
        check("FF-STARTUP reached on baseline log", d["FF-STARTUP"]["reached"])
        check("TEARDOWN reached on baseline log", d["TEARDOWN"]["reached"])
        check("KERNEL-EARLY null on baseline log (Linux has no analogue)",
              d["KERNEL-EARLY"]["from_line"] is None
              and d["KERNEL-EARLY"]["to_line"] is None)

        # ── acquire-image: prints steps, never downloads ─────────────────────
        rc, out, raw = run(["acquire-image"], env=env)
        check("acquire-image rc==0", rc == 0, raw[-200:] if rc else "")
        check("acquire-image did NOT execute", out.get("executed") is False)
        check("acquire-image pins alpine v3.20",
              out.get("alpine_version") == "v3.20", str(out.get("alpine_version")))
        check("acquire-image firefox-esr default",
              out.get("firefox_package") == "firefox-esr")
        steps = out.get("steps") or []
        labels = [s["label"] for s in steps]
        check("acquire-image has kernel/initramfs download steps",
              "download-kernel" in labels and "download-initramfs" in labels,
              str(labels))
        check("acquire-image steps reference only the public Alpine CDN",
              all("dl-cdn.alpinelinux.org" in s["cmd"]
                  for s in steps if s["label"].startswith("download")))

        # firefox-132 cannot reuse the firefox-esr cache -> fresh apk bootstrap
        rc, out, raw = run(["acquire-image", "--firefox-package", "firefox"],
                           env=env)
        check("acquire-image firefox-132 does not reuse esr cache",
              out.get("reuse_cached_rootfs") is False,
              str(out.get("reuse_cached_rootfs")))
        labels132 = [s["label"] for s in (out.get("steps") or [])]
        check("acquire-image firefox-132 falls back to apk bootstrap",
              any("bootstrap" in l for l in labels132), str(labels132))

        # ── run (dry-run, default): plumbing without a boot ──────────────────
        rc, out, raw = run(["run"], env=env)
        check("run rc==0", rc == 0, raw[-200:] if rc else "")
        check("run mode == dry-run", out.get("mode") == "dry-run",
              str(out.get("mode")))
        argv = out.get("qemu_argv") or []
        check("run qemu argv carries -kernel + -initrd",
              "-kernel" in argv and "-initrd" in argv)
        check("run qemu argv 2 vCPU / 2048 MiB (firefox-test geometry)",
              "-smp" in argv and argv[argv.index("-smp") + 1] == "2"
              and "-m" in argv and argv[argv.index("-m") + 1] == "2048M")
        check("run qemu argv headless (-nographic + serial file)",
              "-nographic" in argv
              and any(a.startswith("file:") for a in argv))
        rec = out.get("would_emit_record") or {}
        check("run would_emit source == baseline-linux",
              rec.get("source") == "baseline-linux", str(rec.get("source")))
        check("run would_emit baseline tag",
              rec.get("baseline") == "linux-alpine-3.20", str(rec.get("baseline")))
        check("run would_emit dry_run True + null timing",
              rec.get("dry_run") is True and rec.get("total_ms") is None
              and rec.get("ff_exec_to_png_ms") is None)
        check("run would_emit full 13-phase shape",
              len(rec.get("phase_ms") or {}) == 13,
              str(len(rec.get("phase_ms") or {})))

        # rendered guest init is valid POSIX sh
        init_sh = out.get("guest_init_preview") or ""
        init_path = Path(td) / "guest-init.sh"
        init_path.write_text(init_sh)
        shrc = subprocess.run(["sh", "-n", str(init_path)],
                              capture_output=True, text=True)
        check("run guest init is valid POSIX sh", shrc.returncode == 0,
              shrc.stderr[-200:])
        check("run guest init launches FF with the canonical argv",
              "--headless --no-remote --profile /tmp/ff-profile" in init_sh
              and "--screenshot /tmp/out.png" in init_sh)

        # ── parse-log: synthetic baseline log -> a real store record ─────────
        rc, out, raw = run(["parse-log", "--log", str(log), "--kvm"], env=env)
        check("parse-log rc==0", rc == 0, raw[-200:] if rc else "")
        prec = out.get("record") or {}
        check("parse-log reached_png True", prec.get("reached_png") is True)
        check("parse-log deepest TEARDOWN",
              prec.get("deepest_phase") == "TEARDOWN",
              str(prec.get("deepest_phase")))
        # ff_exec_epoch=...200.1 -> png_epoch=...209.35 => 9250 ms window
        check("parse-log ff_exec_to_png_ms == 9250 (the comparable window)",
              prec.get("ff_exec_to_png_ms") == 9250,
              str(prec.get("ff_exec_to_png_ms")))
        check("parse-log ff_exit_rc == 0", prec.get("ff_exit_rc") == 0)
        check("parse-log wrote the store",
              out.get("wrote_timeseries") is not None)

        # ── perf-bench list merges the baseline record (schema compatibility) ─
        bench = SCRIPTS / "perf-bench.py"
        lr = subprocess.run([PY, str(bench), "list", "--source", "baseline-linux"],
                            capture_output=True, text=True, env=env, timeout=60)
        try:
            lout = json.loads(lr.stdout)
        except Exception:
            lout = {}
        check("perf-bench list sees the baseline record",
              lout.get("n") == 1
              and lout["records"][0].get("revision") == "alpine-3.20",
              json.dumps(lout)[-200:])

        # ── status ───────────────────────────────────────────────────────────
        rc, out, raw = run(["status"], env=env)
        check("status rc==0", rc == 0)
        check("status reports baseline record count >= 1",
              (out.get("baseline_records_in_store") or 0) >= 1,
              str(out.get("baseline_records_in_store")))

    print()
    if fails:
        print(f"[{FAIL}] {fails} check(s) failed")
        return 1
    print(f"[{PASS}] all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
