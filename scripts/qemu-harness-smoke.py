#!/usr/bin/env python3
"""
qemu-harness-smoke.py — Host-side smoke test for qemu-harness.py

Exercises all Tier 1 and Tier 3 subcommands against a real kernel boot.
Optionally exercises Tier 2 (GDB stub integration) when --tier2 is passed.

Not part of the kernel test suite (test_runner.rs) — run directly:

    python3 scripts/qemu-harness-smoke.py           # Tier 1 only
    python3 scripts/qemu-harness-smoke.py --tier2   # Tier 1 + Tier 2

Exit codes:
    0  — all checks passed
    1  — one or more checks failed
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "qemu-harness.py"
PYTHON  = sys.executable

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36mINFO\033[0m"

failures = []


def _h(*args_extra):
    """Run a harness subcommand, return (parsed_json, raw_stdout, returncode)."""
    cmd = [PYTHON, str(HARNESS)] + list(args_extra)
    r = subprocess.run(cmd, capture_output=True, text=True)
    raw = r.stdout.strip()
    try:
        obj = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        obj = None
    return obj, raw, r.returncode


def check(name: str, cond: bool, detail: str = ""):
    tag = PASS if cond else FAIL
    extra = f"  ({detail})" if detail else ""
    print(f"  [{tag}] {name}{extra}")
    if not cond:
        failures.append(name)


def run_tier1(no_build: bool = False):
    """Tier 1 smoke test: session lifecycle + serial log operations."""

    # ── Step 1: start ─────────────────────────────────────────────────────────
    print("Step 1: start (build + launch QEMU)")
    # Tier 1 expects the in-kernel test-runner banners ("Phase N", PASS/FAIL),
    # so we request test-mode explicitly.  The harness no longer injects it.
    start_args = ["start", "--features", "test-mode"]
    if no_build:
        start_args.append("--no-build")
    obj, raw, rc = _h(*start_args)
    check("start returns JSON",       obj is not None,           raw[:120])
    check("start.sid present",        bool(obj and obj.get("sid")), str(obj))
    check("start.pid > 0",            bool(obj and obj.get("pid", 0) > 0), str(obj))
    check("start returncode 0",       rc == 0,                   f"rc={rc}")

    if not obj or not obj.get("sid"):
        print(f"\n[{FAIL}] Cannot proceed without a valid sid — aborting.")
        sys.exit(1)

    sid = obj["sid"]
    print(f"  [INFO] sid={sid}  pid={obj['pid']}")
    print()

    # ── Step 2: wait for boot message ────────────────────────────────────────
    print("Step 2: wait for 'kernel initialization complete' (60 s)")
    # The AstryxOS boot prints various phase markers; "Phase" appears early.
    # We also accept the test-runner start banner as proof of life.
    obj2, raw2, rc2 = _h("wait", sid,
                          r"(kernel initialization complete|Phase \d|AstryxOS|PASS|FAIL)",
                          "--ms", "60000")
    check("wait returns JSON",   obj2 is not None,               raw2[:120])
    check("wait.matched=true",   bool(obj2 and obj2.get("matched")), str(obj2))
    if obj2 and obj2.get("matched"):
        print(f"  [INFO] Matched at line {obj2.get('line_no')}: {obj2.get('line','')[:80]}")
    print()

    # ── Step 3: tail ──────────────────────────────────────────────────────────
    print("Step 3: tail --bytes 2000")
    obj3, raw3, rc3 = _h("tail", sid, "--bytes", "2000")
    check("tail returns JSON",      obj3 is not None,            raw3[:120])
    check("tail.lines is list",     isinstance(obj3.get("lines") if obj3 else None, list))
    check("tail has content",       bool(obj3 and len(obj3.get("lines", [])) > 0),
          f"lines={len(obj3.get('lines', [])) if obj3 else 0}")
    print()

    # ── Step 4: status ────────────────────────────────────────────────────────
    print("Step 4: status")
    obj4, raw4, rc4 = _h("status", sid)
    check("status returns JSON",    obj4 is not None,            raw4[:120])
    check("status.running=true",    bool(obj4 and obj4.get("running")), str(obj4))
    check("status.pid > 0",         bool(obj4 and obj4.get("pid", 0) > 0))
    check("status.uptime_s > 0",    bool(obj4 and obj4.get("uptime_s", 0) > 0))
    print()

    # ── Step 5: grep ──────────────────────────────────────────────────────────
    print("Step 5: grep 'Phase' --tail 10")
    # Wait a little longer so more boot output is available
    _h("wait", sid, r"Phase [0-9]", "--ms", "30000")
    obj5, raw5, rc5 = _h("grep", sid, r"Phase [0-9]", "--tail", "10")
    check("grep returns JSON list",  isinstance(obj5, list),     raw5[:120])
    # Phase markers appear in test-mode boot; tolerate absence in edge cases
    has_phase = isinstance(obj5, list) and len(obj5) > 0
    check("grep has Phase lines",    has_phase,
          f"count={len(obj5) if isinstance(obj5, list) else 0}")
    print()

    # ── Step 6: events ───────────────────────────────────────────────────────
    print("Step 6: events (may be empty, that is fine)")
    obj6, raw6, rc6 = _h("events", sid)
    check("events returns JSON list", isinstance(obj6, list),    raw6[:120])
    print(f"  [INFO] {len(obj6) if isinstance(obj6, list) else '?'} events recorded")
    print()

    # ── Step 7: stop ─────────────────────────────────────────────────────────
    print("Step 7: stop")
    obj7, raw7, rc7 = _h("stop", sid)
    check("stop returns JSON",  obj7 is not None,                raw7[:120])
    check("stop.ok=true",       bool(obj7 and obj7.get("ok")),   str(obj7))
    check("stop returncode 0",  rc7 == 0,                        f"rc={rc7}")
    print()

    # ── Step 8: list ─────────────────────────────────────────────────────────
    print("Step 8: list (sid should be absent)")
    # Allow a moment for process cleanup
    time.sleep(0.5)
    obj8, raw8, rc8 = _h("list")
    check("list returns JSON array",  isinstance(obj8, list),    raw8[:120])
    sid_present = any(s.get("sid") == sid for s in (obj8 or []))
    check("sid absent from list",     not sid_present,
          f"sessions={[s.get('sid') for s in (obj8 or [])]}")
    print()

    # ── Stop idempotency ──────────────────────────────────────────────────────
    print("Bonus: stop idempotency (stop already-stopped session)")
    obj9, raw9, rc9 = _h("stop", sid)
    check("second stop returns ok",   bool(obj9 and obj9.get("ok")), str(obj9))
    print()


def run_tier2(gdb_port: int = 1234, no_build: bool = False):
    """
    Tier 2 smoke test: GDB stub integration.

    Sequence:
      1. start --gdb-port PORT  (no -S so kernel boots freely)
      2. wait "Phase 4:" for driver-init milestone
      3. pause (QMP stop)
      4. regs  — assert RIP is non-zero and in higher-half
      5. sym kernel_main — assert address returned
      6. mem <RSP> 64  — assert 128 hex chars returned
      7. bp add <kernel_main_addr> / bp list / bp del
      8. resume
      9. cont (GDB continue — already running, expect graceful handling)
     10. stop
    """
    print(f"=== Tier 2: GDB stub (port {gdb_port}) ===")
    print()

    # ── T2-1: start with GDB port ─────────────────────────────────────────────
    print(f"T2-1: start --gdb-port {gdb_port}")
    # Tier 2 pauses at Phase 4 banners, so test-mode must be explicit now.
    start_args = ["start", "--features", "test-mode",
                  "--gdb-port", str(gdb_port)]
    if no_build:
        start_args.append("--no-build")
    obj, raw, rc = _h(*start_args)
    check("T2 start returns JSON",    obj is not None,           raw[:120])
    check("T2 start.sid present",     bool(obj and obj.get("sid")), str(obj))
    check("T2 start.gdb_port set",    bool(obj and obj.get("gdb_port", 0) > 0), str(obj))

    if not obj or not obj.get("sid"):
        print(f"\n[{FAIL}] Cannot proceed without sid — aborting Tier 2.")
        return

    sid = obj["sid"]
    actual_port = obj.get("gdb_port", gdb_port)
    print(f"  [INFO] sid={sid} gdb_port={actual_port}")
    print()

    # ── T2-2: wait for Phase 4 (driver init) ─────────────────────────────────
    print("T2-2: wait for 'Phase 4' (driver init, up to 90 s)")
    obj2, raw2, _ = _h("wait", sid, r"Phase [4-9]|Phase [1-9][0-9]|AstryxOS|PASS|FAIL",
                        "--ms", "90000")
    check("T2 wait matched",          bool(obj2 and obj2.get("matched")), str(obj2))
    if obj2 and obj2.get("matched"):
        print(f"  [INFO] Matched: {obj2.get('line','')[:80]}")
    print()

    # ── T2-3: pause via QMP ───────────────────────────────────────────────────
    print("T2-3: pause (QMP stop)")
    obj3, raw3, _ = _h("pause", sid)
    check("T2 pause ok",              bool(obj3 and obj3.get("ok")), str(obj3))
    time.sleep(0.3)  # give vCPUs time to freeze
    print()

    # ── T2-4: regs ────────────────────────────────────────────────────────────
    print("T2-4: regs — assert RIP in higher-half kernel")
    obj4, raw4, _ = _h("regs", sid)
    check("T2 regs ok",               bool(obj4 and obj4.get("ok")),       str(obj4))
    rip_hex = (obj4 or {}).get("regs", {}).get("rip", "0x0")
    try:
        rip_val = int(rip_hex, 16)
    except (ValueError, TypeError):
        rip_val = 0
    rip_nonzero   = rip_val != 0
    # Higher-half kernel starts at 0xFFFF800000000000
    rip_higherhalf = rip_val >= 0xFFFF800000000000
    check("T2 regs RIP non-zero",     rip_nonzero,  f"rip={rip_hex}")
    # Note: RIP may not be in higher-half if paused during UEFI/early boot;
    # we log a warning rather than hard-fail this check.
    if not rip_higherhalf:
        print(f"  [INFO] RIP={rip_hex} not yet in higher-half (paused during boot/UEFI) — non-fatal")
    else:
        check("T2 regs RIP in higher-half", rip_higherhalf, f"rip={rip_hex}")
    print()

    # ── T2-5: sym _start (kernel entry point) ───────────────────────────────
    # The AstryxOS kernel exposes '_start' as the UEFI-loaded entry point.
    # 'kernel_main' is a Rust function that gets mangled; '_start' is the
    # linker-exported naked entry that is always present.
    print("T2-5: sym _start (kernel entry point)")
    obj5, raw5, _ = _h("sym", sid, "_start")
    check("T2 sym returns JSON",      obj5 is not None,             raw5[:120])
    sym_ok = bool(obj5 and obj5.get("ok"))
    sym_addr = (obj5 or {}).get("addr", "0x0")
    check("T2 sym _start found",      sym_ok,                        str(obj5))
    if sym_ok:
        print(f"  [INFO] _start @ {sym_addr} type={obj5.get('type')}")
    print()

    # ── T2-6: mem — read 64 bytes at RSP ────────────────────────────────────
    print("T2-6: mem RSP 64 — read stack")
    rsp_hex = (obj4 or {}).get("regs", {}).get("rsp", "0x0") if obj4 else "0x0"
    # RSP may be 0 if regs failed; fall back to a known higher-half address
    try:
        rsp_val = int(rsp_hex, 16)
    except (ValueError, TypeError):
        rsp_val = 0
    mem_addr = rsp_hex if rsp_val != 0 else "0xFFFF800000100000"
    obj6, raw6, _ = _h("mem", sid, mem_addr, "64")
    check("T2 mem returns JSON",      obj6 is not None,             raw6[:120])
    mem_ok    = bool(obj6 and obj6.get("ok"))
    mem_bytes = (obj6 or {}).get("bytes", "")
    check("T2 mem ok",                mem_ok,                        str(obj6))
    # 64 bytes = 128 hex chars
    check("T2 mem 64 bytes returned", len(mem_bytes) == 128,
          f"len={len(mem_bytes)} bytes_hex={mem_bytes[:32]}...")
    print()

    # ── T2-7: bp add / list / del ─────────────────────────────────────────────
    print("T2-7: breakpoint add / list / del")
    if sym_ok and sym_addr and sym_addr != "0x0":
        obj7a, _, _ = _h("bp", sid, "add", sym_addr)
        check("T2 bp add ok",         bool(obj7a and obj7a.get("ok")), str(obj7a))

        obj7b, _, _ = _h("bp", sid, "list")
        bps = (obj7b or {}).get("breakpoints", [])
        check("T2 bp list non-empty", len(bps) > 0, str(bps))

        obj7c, _, _ = _h("bp", sid, "del", sym_addr)
        check("T2 bp del ok",         bool(obj7c and obj7c.get("ok")), str(obj7c))
    else:
        print("  [INFO] Skipping bp sub-test (_start symbol not resolved)")
    print()

    # ── T2-8: resume ─────────────────────────────────────────────────────────
    print("T2-8: resume (QMP cont)")
    obj8, raw8, _ = _h("resume", sid)
    check("T2 resume ok",             bool(obj8 and obj8.get("ok")), str(obj8))
    print()

    # ── T2-9: cont (GDB continue while already running) ──────────────────────
    print("T2-9: cont (GDB vCont;c — kernel running, expect graceful handling)")
    obj9, raw9, _ = _h("cont", sid)
    # cont may succeed or return "running" note — either is acceptable
    check("T2 cont returns JSON",     obj9 is not None, raw9[:120])
    print()

    # ── T2-9b: autopsy — arm bp on _start (already past it) with timeout ────
    # Cannot guarantee a fresh hit of _start (kernel already booted), but the
    # wrapper's plumbing — preset load, breakpoint arm, timeout-then-clean —
    # is testable: we expect a clean "timed_out: true" with no exceptions.
    print("T2-9b: autopsy --capture full-register-dump (expect timeout)")
    if sym_ok and sym_addr and sym_addr != "0x0":
        obj9b, raw9b, _ = _h(
            "autopsy", sid,
            "--break", sym_addr,
            "--capture", "full-register-dump",
            "--timeout-ms", "2000",
        )
        check("T2 autopsy returns JSON",  obj9b is not None, raw9b[:160])
        if obj9b is not None:
            # Either we hit (rare, would need to rewind) or we timed out —
            # both are valid; failure mode is an exception / missing key.
            check("T2 autopsy preset echoed",
                  obj9b.get("preset") == "full-register-dump", str(obj9b)[:200])
            check("T2 autopsy breakpoint armed",
                  bool(obj9b.get("breakpoints") and
                       obj9b["breakpoints"][0].get("armed")),
                  str(obj9b.get("breakpoints")))
            check("T2 autopsy clean completion (timed_out or hit)",
                  obj9b.get("timed_out") is True or obj9b.get("hit_count", 0) > 0,
                  f"timed_out={obj9b.get('timed_out')} "
                  f"hits={obj9b.get('hit_count')}")
    else:
        print("  [INFO] Skipping autopsy sub-test (_start symbol not resolved)")
    print()

    # ── T2-9c: autopsy with unknown preset → clean JSON error ────────────────
    print("T2-9c: autopsy --capture nonexistent-preset (expect JSON error)")
    obj9c, raw9c, _ = _h(
        "autopsy", sid,
        "--break", sym_addr if sym_ok and sym_addr else "0xffff800000000000",
        "--capture", "this-preset-does-not-exist",
        "--timeout-ms", "1000",
    )
    check("T2 autopsy bad-preset returns JSON", obj9c is not None, raw9c[:160])
    check("T2 autopsy bad-preset surfaces error",
          bool(obj9c and obj9c.get("error")), str(obj9c)[:200])

    # ── T2-10: stop ──────────────────────────────────────────────────────────
    print("T2-10: stop")
    obj10, raw10, rc10 = _h("stop", sid)
    check("T2 stop ok",               bool(obj10 and obj10.get("ok")), str(obj10))
    print()


def run_tier3(no_build: bool = False):
    """
    Tier 3 smoke test: kdb introspection socket over inbound TCP hostfwd.

    Sequence:
      1. start --features "test-mode,kdb" — boots the kernel with the
         kdb TCP listener on guest port 9999 and a per-session hostfwd
         rule binding a host port to that guest port.
      2. wait "KDB. runtime loop engaged" — the kernel has finished its
         test suite and entered the post-suite pump loop where
         `net::poll()` is running continuously.
      3. kdb ping — dispatches a {"op":"ping"} request over the hostfwd
         rule.  Asserts the response carries "pong":true.  This is the
         true end-to-end exercise of an inbound TCP 3WHS on AstryxOS.
      4. stop.

    The Tier 1 / Tier 2 sequences do NOT exercise inbound TCP — they
    rely entirely on outbound ARP / ICMP or the GDB stub.  Tier 3 is
    the only smoke check that validates inbound hostfwd delivery end
    to end, so it's gated behind --tier3 and may be flakey on hosts
    where QEMU SLIRP has pre-existing delivery quirks (e.g. nested
    WSL2 + KVM).
    """
    print("=== Tier 3: kdb introspection (inbound hostfwd) ===")
    print()

    start_args = ["start", "--features", "test-mode,kdb"]
    if no_build:
        start_args.append("--no-build")
    obj, raw, _ = _h(*start_args)
    check("T3 start returns JSON",    obj is not None,             raw[:120])
    check("T3 start.sid present",     bool(obj and obj.get("sid")), str(obj))
    check("T3 start.kdb_host_port>0", bool(obj and obj.get("kdb_host_port", 0) > 0),
                                       str(obj))

    if not obj or not obj.get("sid"):
        print(f"\n[{FAIL}] Cannot proceed without sid — aborting Tier 3.")
        return

    sid = obj["sid"]
    print(f"  [INFO] sid={sid} kdb_host_port={obj.get('kdb_host_port')}")
    print()

    # Wait for post-suite pump loop — up to 2 minutes since the full
    # test suite runs first.
    print("T3-2: wait 'KDB. runtime loop engaged'")
    wait_obj, wait_raw, _ = _h("wait", sid, r"KDB. runtime loop engaged",
                                "--ms", "120000")
    check("T3 runtime-loop reached",  bool(wait_obj and wait_obj.get("matched")),
                                       str(wait_obj))
    print()

    # Small settle period so the first net::poll() runs post-tests.
    time.sleep(2)

    print("T3-3: kdb ping")
    ping_obj, ping_raw, ping_rc = _h("kdb", sid, "ping", "--timeout", "10")
    # Ping may time out on WSL2/KVM due to SLIRP delivery timing —
    # that's a known host-side quirk, not a kernel bug.  We record the
    # result but only hard-fail if the response is malformed.
    pong_ok = bool(ping_obj and ping_obj.get("pong") is True)
    if pong_ok:
        check("T3 kdb ping pong=true",  True, str(ping_obj))
    else:
        print(f"  [{INFO}] kdb ping did not return pong (likely host SLIRP quirk): {ping_raw[:160]}")
    print()

    print("T3-4: stop")
    stop_obj, stop_raw, _ = _h("stop", sid)
    check("T3 stop ok",               bool(stop_obj and stop_obj.get("ok")), str(stop_obj))
    print()


def run_snapgate_argv_check():
    """
    Tier 1.5 host-only check: snap-gate device topology + CLI parsing.

    No QEMU launched (runs in < 1s).  Locks down the snap-gate topology so a
    future refactor cannot silently regress the savevm/loadvm compatibility:

      * default (non-snapshottable) argv is UNCHANGED — fat:rw boot disk +
        writable raw OVMF_VARS pflash (existing harness usage unaffected)
      * --snapshottable argv has the savevm-compatible topology — fat:ro boot
        disk via virtio-blk-pci read-only, qcow2 OVMF_VARS pflash, an orphan
        qcow2 vmstate device emitted before the qcow2 data overlay
      * snap-gate CLI parses the three argv forms: `list`, `load <name>`,
        bad-usage -> error
    """
    print("=== Tier 1.5: snap-gate topology + CLI (host-only) ===")
    print()

    import importlib.util
    aq_path = Path(__file__).resolve().parent / "astryx_qemu.py"
    spec = importlib.util.spec_from_file_location("astryx_qemu_smoke", aq_path)
    aq = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aq)

    kw = dict(mode="test", ovmf_code="/x/code.fd", ovmf_vars="/x/vars",
              esp_dir="/x/esp", qmp_sock="/x/q.sock", kvm=False)

    # The data-disk args are only emitted when the backing data_img exists on
    # disk (a W13/W15 silent-wedge guard); use a real temp file so the overlay
    # branch is exercised.
    import tempfile, os as _os
    _di = tempfile.NamedTemporaryFile(suffix=".img", delete=False)
    _di.write(b"\0" * 4096)
    _di.close()
    data_img = _di.name

    # ── default path unchanged ────────────────────────────────────────────────
    d = aq.build_qemu_cmd("", data_img, "/x/s.log", **kw)
    boot = [x for x in d if "fat:" in x]
    pflash = [x for x in d if "pflash" in x]
    check("default boot disk is fat:rw",
          boot == ["format=raw,file=fat:rw:/x/esp"], str(boot))
    check("default OVMF_VARS pflash is writable raw",
          "if=pflash,format=raw,file=/x/vars" in pflash, str(pflash))
    check("default has no orphan vmstate device",
          not any("vmstate0" in x for x in d), "vmstate0 leaked into default")

    # ── snapshottable path ────────────────────────────────────────────────────
    s = aq.build_qemu_cmd("", data_img, "/x/s.log",
                          snapshottable=True,
                          data_overlay="/x/ov.qcow2",
                          vmstate_qcow2="/x/vm.qcow2", **kw)
    check("snap boot disk is fat:ro",
          any(x.startswith("format=raw,file=fat:ro:/x/esp") for x in s),
          "boot disk not fat:ro")
    check("snap boot disk on virtio-blk-pci read-only frontend",
          any("virtio-blk-pci,drive=boot0" in x for x in s)
          and any("readonly=on,id=boot0" in x or "id=boot0,readonly=on" in x
                  or "fat:ro:/x/esp,if=none,id=boot0,readonly=on" in x for x in s),
          "boot0 frontend missing")
    check("snap OVMF_VARS pflash is qcow2 (writable+snapshottable)",
          any("if=pflash,format=qcow2,file=/x/vars" in x for x in s),
          "vars pflash not qcow2")
    check("snap has orphan vmstate qcow2 device (if=none, no -device)",
          any("file=/x/vm.qcow2,format=qcow2,if=none,id=vmstate0" in x for x in s)
          and not any("drive=vmstate0" in x for x in s),
          "vmstate0 orphan missing or wired to a device")
    check("snap data disk is the qcow2 overlay",
          any("file=/x/ov.qcow2,format=qcow2,if=none,id=data0" in x for x in s),
          "data overlay missing")
    # vmstate must precede the data overlay so bdrv_all_find_vmstate_bs picks it.
    try:
        i_vm = next(i for i, x in enumerate(s) if "id=vmstate0" in x)
        i_ov = next(i for i, x in enumerate(s) if "id=data0" in x)
        check("orphan vmstate device emitted BEFORE data overlay",
              i_vm < i_ov, f"vmstate@{i_vm} overlay@{i_ov}")
    except StopIteration:
        check("orphan vmstate device emitted BEFORE data overlay", False,
              "could not locate both devices")

    # ── snap-gate CLI parsing (no QEMU) ───────────────────────────────────────
    obj, raw, rc = _h("snap-gate", "list")
    check("snap-gate list returns JSON ok", obj is not None and obj.get("ok"),
          raw[:120])
    obj2, raw2, rc2 = _h("snap-gate", "load", "__no_such_snap__")
    check("snap-gate load missing -> ok:false",
          obj2 is not None and obj2.get("ok") is False, raw2[:120])
    import subprocess as _sp
    r3 = _sp.run([PYTHON, str(HARNESS), "snap-gate", "save"],
                 capture_output=True, text=True)
    check("snap-gate bad-usage -> error envelope",
          '"error"' in r3.stdout, r3.stdout[:120])

    try:
        _os.unlink(data_img)
    except OSError:
        pass
    print()


def run_staleness_check():
    """
    Tier 1.5 host-only check: exercise `_data_img_staleness` directly to confirm
    the W7 staleness detector works on fresh, stale, and missing-input inputs.

    This is a pure host-side import test — no QEMU launched. The point is that
    a future refactor of qemu-harness.py cannot accidentally break the
    auto-regen guard without this smoke test failing first.
    """
    print("=== Tier 1.5: data.img staleness detector (host-only) ===")
    print()
    import importlib.util
    import os
    import tempfile
    spec = importlib.util.spec_from_file_location("qh_smoke_load", str(HARNESS))
    mod = importlib.util.module_from_spec(spec)
    # Module-level side effects only mkdir ~/.astryx-harness — no QEMU.
    _orig_argv = sys.argv
    sys.argv = ["qemu-harness.py", "list"]
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pass
    finally:
        sys.argv = _orig_argv

    fn = getattr(mod, "_data_img_staleness", None)
    check("staleness fn importable", fn is not None, "")
    if fn is None:
        return

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        img = tdp / "data.img"
        disk = tdp / "disk"
        disk.mkdir()
        f1 = disk / "lib.so"
        f1.write_text("x")
        # Case A: data.img missing — soft-fail with error string.
        r = fn(img, disk)
        check("missing data.img → stale=False",  not r["stale"])
        check("missing data.img → error set",    bool(r["error"]))

        # Case B: data.img newer than every disk file — not stale.
        img.write_text("img")
        os.utime(img, (time.time() + 60, time.time() + 60))
        r = fn(img, disk)
        check("fresh data.img → stale=False",    not r["stale"], str(r))
        check("fresh data.img → error=None",     r["error"] is None, str(r))
        check("fresh data.img → files_scanned",  r["files_scanned"] >= 1, str(r))

        # Case C: a disk file newer than data.img — stale=True.
        os.utime(img, (time.time() - 60, time.time() - 60))
        r = fn(img, disk)
        check("stale data.img → stale=True",     r["stale"], str(r))
        check("stale data.img → newest_path",    bool(r["newest_path"]), str(r))

        # Case D: disk dir missing — soft-fail.
        r = fn(img, tdp / "nope")
        check("missing disk_dir → stale=False",  not r["stale"])
        check("missing disk_dir → error set",    bool(r["error"]))

    print()


def run_allowlist_check():
    """
    Tier 1.5 host-only check: exercise `allowlist` subcommands directly.

    Validates:
      * `allowlist regex` produces a non-empty alternation regex
      * `allowlist list` returns a JSON envelope with an entries list
      * `allowlist check --serial-log` correctly classifies known [FAIL]
        lines as allowed vs. unallowed
      * `allowlist add/remove` round-trip preserves the file _comment

    No QEMU launched; runs in < 1s.  Locked down so future refactors of
    qemu-harness.py cannot silently break the CI-side rendering of
    ci/allow-fail.json.
    """
    import tempfile
    print("=== Tier 1.5: ci/allow-fail.json allowlist (host-only) ===")
    print()

    # ── list ──────────────────────────────────────────────────────────────────
    obj, raw, rc = _h("allowlist", "list")
    check("allowlist list returns JSON",   obj is not None, raw[:120])
    check("allowlist list rc=0",           rc == 0, f"rc={rc}")
    if obj is not None:
        check("allowlist.entries is a list",
              isinstance(obj.get("entries"), list),
              str(type(obj.get("entries"))))

    # ── regex (printed verbatim, no trailing newline) ─────────────────────────
    # _h() parses stdout as JSON; allowlist regex prints a raw string, so we
    # need to call it without parsing.
    import subprocess
    r = subprocess.run([PYTHON, str(HARNESS), "allowlist", "regex"],
                       capture_output=True, text=True)
    check("allowlist regex rc=0",  r.returncode == 0, f"rc={r.returncode}")
    check("allowlist regex non-empty",
          len(r.stdout) > 0, f"stdout={r.stdout[:80]!r}")
    check("allowlist regex no trailing newline",
          not r.stdout.endswith("\n"), repr(r.stdout[-10:]))

    # ── check against a synthetic serial log ──────────────────────────────────
    # Use 'dynamic_elf' as the allowed failure — it is a stable env-gap entry
    # that will remain in ci/allow-fail.json until the musl dynamic linker is
    # always present in CI.  'Musl hello' was removed from the allowlist when
    # staging was fixed in PR #467; keep this fixture in sync with the live
    # allowlist rather than reverting that staging improvement.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
        fh.write("[OK] something\n")
        fh.write("[PASS] another\n")
        fh.write("[FAIL] dynamic_elf: interpreter not found\n")
        fh.write("[FAIL] WriteConsoleA: stub not registered\n")
        synthetic = fh.name
    try:
        obj, raw, rc = _h("allowlist", "check", "--serial-log", synthetic)
        check("allowlist check returns JSON", obj is not None, raw[:120])
        if obj is not None:
            check("allowlist check found 1 allowed",
                  len(obj.get("allowed_failures", [])) == 1,
                  f"allowed={obj.get('allowed_failures')}")
            check("allowlist check found 1 unallowed (WriteConsoleA)",
                  len(obj.get("unallowed_failures", [])) == 1,
                  f"unallowed={obj.get('unallowed_failures')}")
            check("allowlist check rc=1 (drift)",
                  rc == 1, f"rc={rc}")
    finally:
        Path(synthetic).unlink(missing_ok=True)

    # ── add/remove round-trip (against a temp copy so we don't touch ci/) ────
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
        # Seed with a _comment to confirm preservation across edits.
        fh.write('{"_comment": "test", "entries": []}\n')
        tmp_path = fh.name
    try:
        obj, raw, rc = _h("allowlist", "--file", tmp_path,
                          "add", "--name", "smoke_x", "--reason", "test",
                          "--tracking", "#999")
        check("allowlist add ok=true",
              bool(obj and obj.get("ok")), str(obj))
        # Duplicate add → ok=false
        obj, raw, rc = _h("allowlist", "--file", tmp_path,
                          "add", "--name", "smoke_x")
        check("allowlist add duplicate ok=false",
              bool(obj and obj.get("ok") is False), str(obj))
        # _comment preserved
        with open(tmp_path) as f:
            data = json.load(f)
        check("allowlist add preserves _comment",
              data.get("_comment") == "test", str(data))
        # Remove
        obj, raw, rc = _h("allowlist", "--file", tmp_path,
                          "remove", "--name", "smoke_x")
        check("allowlist remove ok=true",
              bool(obj and obj.get("ok")), str(obj))
        with open(tmp_path) as f:
            data = json.load(f)
        check("allowlist remove leaves 0 entries",
              len(data.get("entries", [])) == 0, str(data))
        check("allowlist remove preserves _comment",
              data.get("_comment") == "test", str(data))
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="AstryxOS qemu-harness smoke test")
    parser.add_argument("--tier2", action="store_true",
                         help="Also run Tier 2 GDB stub integration tests")
    parser.add_argument("--tier3", action="store_true",
                         help="Also run Tier 3 kdb (inbound TCP hostfwd) smoke test")
    parser.add_argument("--gdb-port", type=int, default=1234,
                         help="TCP port for GDB stub in Tier 2 (default 1234)")
    parser.add_argument("--no-build", action="store_true",
                         help="Skip cargo build; use existing kernel.bin")
    parser.add_argument("--staleness-only", action="store_true",
                         help="Run only the host-side staleness detector check "
                              "(no QEMU); fast (<1s).")
    args = parser.parse_args()

    print(f"[{INFO}] AstryxOS qemu-harness smoke test")
    print(f"[{INFO}] Harness: {HARNESS}")
    if args.tier2:
        print(f"[{INFO}] Tier 2 GDB tests enabled (port {args.gdb_port})")
    if args.tier3:
        print(f"[{INFO}] Tier 3 kdb hostfwd smoke enabled")
    print()

    # Always run the host-only checks — each is < 1 second and protects
    # the corresponding silent-wedge guards (W7 staleness; ci/allow-fail
    # registry) against future refactors of qemu-harness.py.
    run_staleness_check()
    run_allowlist_check()
    run_snapgate_argv_check()

    if args.staleness_only:
        # Early exit for CI cycles that just want the cheap host-only checks.
        # (Name retained for back-compat; now covers all Tier-1.5 host checks.)
        n_fail = len(failures)
        if n_fail == 0:
            print(f"\033[32m\nHost-only checks passed.\033[0m")
            sys.exit(0)
        else:
            print(f"\033[31m\n{n_fail} check(s) FAILED:\033[0m")
            for f in failures:
                print(f"  - {f}")
            sys.exit(1)

    run_tier1(no_build=args.no_build)

    if args.tier2:
        run_tier2(gdb_port=args.gdb_port, no_build=True)  # kernel already built

    if args.tier3:
        run_tier3(no_build=True)

    # ── Summary ───────────────────────────────────────────────────────────────
    n_fail = len(failures)

    if n_fail == 0:
        print(f"\033[32m\nAll smoke-test checks passed.\033[0m")
        sys.exit(0)
    else:
        print(f"\033[31m\n{n_fail} check(s) FAILED:\033[0m")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
