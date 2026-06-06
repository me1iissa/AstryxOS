#!/usr/bin/env python3
"""
serial-web-smoke.py — Host-side smoke test for scripts/serial-web.py.

Validates every dashboard backend parser/endpoint against synthetic serial-log
fixtures, with NO kernel boot and NO QEMU. Imports serial-web.py's pure
functions directly and also exercises the HTTP layer end-to-end on an ephemeral
port. Fast (<2s), deterministic, and CI-safe.

    python3 scripts/serial-web-smoke.py

Exit codes:
    0  — all checks passed
    1  — one or more checks failed

Covers (matches the operator-requested feature set):
  * /api/sessions  — launch-time fields (started_at/elapsed/started_src) from
                     <sid>.json, plus the log-mtime fallback when json is absent.
  * /api/milestones — forward-ordered first-hit timeline (line numbers).
  * /api/context    — N±ctx window slice around a gate line.
  * /api/metrics    — latest [PROC-METRICS] per pid + [HB], aggregates,
                      breakdown, both STUCK_IN_NR= and cur_nr= variants.
  * /api/blkmap     — [BLK] histogram bucketing across the 4194304-sector device,
                      has_trace=False when no [BLK] lines are present.
  * /api/milestones per-gate TIMING — host elapsed (+Ns) + per-gate delta (Δ+Ns)
                      from the marks sidecar (EXACT live stamps) and from
                      kernel-tick derivation (APPROX historical), incl. the
                      monotone/forward-ordered delta invariant.
"""
import base64
import importlib.util
import json
import os
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
failures = []


def check(name, cond, detail=""):
    print(f"  [{PASS if cond else FAIL}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def load_module(harness_dir):
    """Import serial-web.py with HARNESS_DIR pointed at our fixture dir."""
    spec = importlib.util.spec_from_file_location("sw", os.path.join(HERE, "serial-web.py"))
    sw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sw)
    sw.HARNESS_DIR = harness_dir
    return sw


def _build_pcap_fixture():
    """Return bytes of a tiny but spec-faithful libpcap capture for the wire
    endpoints. Reuses pcap_decode's own frame builders (the same ones its
    --selftest exercises) so the fixture is a real Ethernet/IPv4/UDP DNS query
    plus a TCP+TLS ClientHello carrying an SNI — i.e. /api/wire must decode a
    DNS question and a TLS SNI out of it. Imported lazily so a checkout missing
    pcap_decode.py degrades to the decode_available=False path instead of
    erroring the whole smoke run."""
    pd_spec = importlib.util.spec_from_file_location(
        "pcap_decode_fixture", os.path.join(HERE, "pcap_decode.py"))
    pd = importlib.util.module_from_spec(pd_spec)
    pd_spec.loader.exec_module(pd)
    dns = pd._build_eth_ipv4("10.0.2.15", "10.0.2.3", pd.IPPROTO_UDP,
                             pd._build_udp(50000, 53, pd._build_dns_query("example.com")))
    ch = pd._build_eth_ipv4("10.0.2.15", "93.184.216.34", pd.IPPROTO_TCP,
                            pd._build_tcp(50001, 443, 1, 0, 0x02))  # SYN
    hello = pd._build_eth_ipv4("10.0.2.15", "93.184.216.34", pd.IPPROTO_TCP,
                               pd._build_tcp(50001, 443, 2, 1, 0x18,
                                             pd._build_client_hello("example.com")))
    return pd._write_pcap([(1, 0, dns), (1, 1000, ch), (1, 2000, hello)])


# ── synthetic fixtures ────────────────────────────────────────────────────────
SERIAL = """\
[BOOT] AstryxOS kernel starting
[HEAP GUARD] Guard pages installed
[ACPI] Phase 5b: APIC init
[SMP] scheduler online, AP online (Phase 6)
[DRIVERS] Phase 7: probing virtio devices
[VIRTIO-BLK] Initialized: io=0xc000, capacity=4194304 sectors, queue_size=256
[VFS] ext2 mounted rootfs
[INIT] PID 1 spawn /sbin/init
[BLK] op=R lba=0 len=1 pid=0
[BLK] op=R lba=2 len=8 pid=0
[BLK] op=R lba=131072 len=2048 pid=1
[BLK] op=W lba=4000000 len=8 pid=2
[FFTEST] X11 server ready
[EXEC] /disk/usr/lib/firefox-esr/firefox-bin
[HB] tick=10000 cpu=0 pf=500 sc=1200
[PROC-METRICS] tick=10000 pid=1 name=/disk/usr/lib/firefox-esr/firefox-bin sc=800 (vm=400 file=300 net=10 sync=20 proc=30 sig=20 other=20) pf=300 disk=R262144/W0 rreq=300 net=R0/W100 STUCK_IN_NR=7@9000t
[PROC-METRICS] tick=10000 pid=2 name=/disk/usr/lib/firefox-esr/firefox-bin sc=200 (vm=100 file=80 net=0 sync=5 proc=8 sig=4 other=3) pf=120 disk=R4096/W4096 rreq=20 net=R0/W0 cur_nr=2@100t
[HB] tick=10500 cpu=1 pf=520 sc=1500
[PROC-METRICS] tick=10500 pid=1 name=/disk/usr/lib/firefox-esr/firefox-bin sc=900 (vm=450 file=320 net=12 sync=22 proc=32 sig=22 other=20) pf=320 disk=R524288/W0 rreq=400 net=R0/W200 cur_nr=5@25t
"""


# Full forward-ordered ladder with interleaved kernel ticks. Each gate line is
# preceded by an [HB] tick= so the tick-derivation can stamp it. Ticks: kernel
# entry @0, APIC @100 (=1.0s), drivers @300 (=3.0s), VFS @400 (=4.0s),
# X11 @900 (=9.0s), firefox @950 (=9.5s) — at the published 100 Hz (10ms/tick).
TIMED_SERIAL = """\
[HB] tick=0 cpu=0 pf=0 sc=0
[BOOT] AstryxOS kernel kernel_main Booting
[HEAP GUARD] Guard pages installed
[HB] tick=100 cpu=0 pf=1 sc=1
[ACPI] Phase 5b APIC init
[SMP] scheduler online AP online Phase 6
[HB] tick=300 cpu=0 pf=1 sc=1
[DRIVERS] virtio Phase 7
[HB] tick=400 cpu=0 pf=1 sc=1
[VFS] ext2 mounted rootfs
[INIT] PID 1 spawn
[HB] tick=900 cpu=0 pf=1 sc=1
[FFTEST] X11 server ready
[HB] tick=950 cpu=0 pf=1 sc=1
[EXEC] firefox-bin
"""


def _gate_timing_checks(sw, tmp):
    """Per-gate timing: EXACT (marks sidecar) + APPROX (tick-derived), and the
    forward-ordered/monotone delta invariant. Independently hand-computed values."""
    import gate_marks as gm

    # ---- APPROX path: no marks sidecar, derive from kernel ticks ----
    sidA = "timedapprox01"
    logA = os.path.join(tmp, sidA + ".serial.log")
    with open(logA, "w") as f:
        f.write(TIMED_SERIAL)
    with open(os.path.join(tmp, sidA + ".json"), "w") as f:
        json.dump({"sid": sidA, "started_at": time.time() - 60,
                   "features": "firefox-test,kdb", "running": False}, f)
    tA = {x["label"]: x for x in sw.scan_milestones_timed(sidA, logA)}
    # tick 100 -> 1.0s, 300 -> 3.0s, 400 -> 4.0s, 900 -> 9.0s, 950 -> 9.5s
    check("approx APIC elapsed +1.0s",
          tA["APIC init"]["host_elapsed"] == 1.0, tA["APIC init"]["host_elapsed"])
    check("approx APIC is approx (tick-derived)", tA["APIC init"]["approx"] is True)
    check("approx drivers elapsed +3.0s",
          tA["drivers"]["host_elapsed"] == 3.0, tA["drivers"]["host_elapsed"])
    # per-gate DELTA: drivers since APIC = 3.0-1.0 = 2.0s (the key compare signal)
    check("approx drivers delta = +2.0s (vs APIC)",
          tA["drivers"]["host_delta"] == 2.0, tA["drivers"]["host_delta"])
    check("approx VFS delta = +1.0s (4.0-3.0)",
          tA["VFS / mount"]["host_delta"] == 1.0, tA["VFS / mount"]["host_delta"])
    check("approx X11 delta = +5.0s (9.0-4.0)",
          tA["X11 ready"]["host_delta"] == 5.0, tA["X11 ready"]["host_delta"])
    # monotone: every hit gate's elapsed is non-decreasing in ladder order
    seq = [x["host_elapsed"] for x in sw.scan_milestones_timed(sidA, logA)
           if x["hit"] and x["host_elapsed"] is not None]
    check("approx elapsed monotone non-decreasing",
          all(seq[i] <= seq[i + 1] for i in range(len(seq) - 1)), seq)

    # ---- EXACT path: marks sidecar with known host stamps ----
    sidE = "timedexact01"
    logE = os.path.join(tmp, sidE + ".serial.log")
    with open(logE, "w") as f:
        f.write(TIMED_SERIAL)
    started = 5000.0
    with open(os.path.join(tmp, sidE + ".json"), "w") as f:
        json.dump({"sid": sidE, "started_at": started,
                   "features": "firefox-test,kdb", "running": True}, f)
    # watcher would stamp these; here we write them directly via the shared helper
    stamps = [("kernel entry", 5000.2), ("heap guard", 5000.4),
              ("APIC init", 5002.0), ("SMP / scheduler", 5003.0),
              ("drivers", 5005.0), ("VFS / mount", 5009.0),
              ("init / userspace", 5010.0), ("X11 ready", 5023.0),
              ("firefox exec", 5024.0)]
    for lab, ts in stamps:
        gm.append_gate_mark(sidE, tmp, lab, host_ts=ts, tick=None, line=1)
    tE = {x["label"]: x for x in sw.scan_milestones_timed(sidE, logE)}
    # X11 arrived at 5023.0, launch 5000.0 -> elapsed 23.0s exact (NOT approx)
    check("exact X11 elapsed +23.0s",
          tE["X11 ready"]["host_elapsed"] == 23.0, tE["X11 ready"]["host_elapsed"])
    check("exact X11 NOT approx", tE["X11 ready"]["approx"] is False)
    check("exact X11 has absolute host_ts",
          tE["X11 ready"]["host_ts"] == 5023.0, tE["X11 ready"]["host_ts"])
    # X11 delta from previous HIT gate (init/userspace @5010) = 23.0-10.0 = 13.0s
    check("exact X11 delta = +13.0s (vs init/userspace)",
          tE["X11 ready"]["host_delta"] == 13.0, tE["X11 ready"]["host_delta"])
    check("exact drivers delta = +2.0s (5005-5003)",
          tE["drivers"]["host_delta"] == 2.0, tE["drivers"]["host_delta"])

    # ---- the shared gate<->phase mapping is internally consistent ----
    mlabels = {l for l, _ in gm.MILESTONES}
    check("GATE_TO_PHASE covers every milestone",
          set(gm.GATE_TO_PHASE) == mlabels,
          set(gm.GATE_TO_PHASE) ^ mlabels)

    # ---- HTTP: /api/milestones surfaces the timing fields ----
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), sw.H)
    srv.daemon_threads = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/milestones?sid={sidE}",
                timeout=5) as r:
            body = r.read()
        check("/api/milestones has host_elapsed", b"host_elapsed" in body)
        check("/api/milestones has host_delta", b"host_delta" in body)
    finally:
        srv.shutdown()


# A `firefox-test-core` (fast default) boot: the per-write `[FF/write]`/
# `[FF/stderr]`/`[FF/open]` diagnostic firehose is OFF, so the ONLY render-gate
# signal is the low-frequency kernel-emitted `[GATE] <label>` milestone markers
# (plus the functional `[EXEC] …-isForBrowser` argv line). The headless demo
# renders a local file:// page, so there is NO TCP line (TLS / network is
# legitimately absent). This is exactly the case PR #518's serial split created
# a blind spot for — before the milestone markers the monitor showed "firefox
# exec" as the deepest gate even though FF reached content-proc spawn + the
# render handshake. This fixture proves the ladder now advances past it.
CORE_PROFILE_SERIAL = """\
[BOOT] AstryxOS kernel kernel_main Booting
[HEAP GUARD] Guard pages installed
[ACPI] Phase 5b APIC init
[SMP] scheduler online AP online Phase 6
[DRIVERS] virtio Phase 7
[VFS] ext2 mounted rootfs
[X11] Xastryx ready on /tmp/.X11-unix/X0 (fd=0)
[FFTEST] X11 server ready
[PROC] Created kernel process firefox-bin PID 1 TID 1
[EXEC] pid=1 tid=1 argv="firefox-bin" "--headless" (2 of 14 args shown)
[HB] tick=200 cpu=0 pid=1 sc=120000
[GATE] libxul
[HB] tick=400 cpu=0 pid=1 sc=300000
[EXEC] pid=1 tid=9 argv="firefox-bin" "-contentproc" "-isForBrowser" (3 of 16 args shown)
[GATE] content-procs
[HB] tick=800 cpu=0 pid=1 sc=1600000
[GATE] screenshot-actors
[HB] tick=1200 cpu=0 pid=1 sc=2000000
[GATE] drawSnapshot
[FFTEST] /tmp/out.png present (12345 bytes) — streaming
[FF-OUT-PNG:path=/tmp/out.png size=12345 sig_ok=true complete=true]
[PROC] PID 1 exit_group(0)
"""


def _core_profile_gate_checks(sw, tmp):
    """firefox-test-core (firehose OFF): the `[GATE]` milestone markers + the
    functional FF-supervisor PNG line must advance the ladder PAST 'firefox
    exec' to the deep render gates. Also exercises the OPTIONAL-skip rule: the
    no-network file:// render emits no TCP line ('TLS / network' absent) AND the
    fixture emits 'X11 server ready' BEFORE the 'PID 1' line ('init / userspace'
    out of order) — neither may stall the strictly-monotone ladder."""
    sid = "coreprofile01"
    log = os.path.join(tmp, sid + ".serial.log")
    with open(log, "w") as f:
        f.write(CORE_PROFILE_SERIAL)
    prog = sw.scan_progress(log)
    hit = {s["label"] for s in prog["timeline"] if s["hit"]}
    # The blind-spot fix: deepest gate is NOT stuck at 'firefox exec' (or before).
    check("core: deepest gate past 'firefox exec'",
          prog["gate"] not in ("firefox exec", "init / userspace", "boot"),
          prog["gate"])
    # PNG write is detected via the functional FF-supervisor line, the rest via
    # the kernel `[GATE]` markers — all default-on on firefox-test-core.
    for g in ("content procs", "screenshot-actors", "drawSnapshot", "PNG write"):
        check(f"core: '{g}' reached on fast profile (firehose off)", g in hit,
              sorted(hit))
    # firefox exec must still be hit (the gate we advance PAST).
    check("core: 'firefox exec' hit (then surpassed)", "firefox exec" in hit)
    # Optional gates: absent/out-of-order, but the ladder still reaches PNG.
    check("core: 'TLS / network' optional (absent on file://, not stalling)",
          "TLS / network" not in hit and "PNG write" in hit)
    check("core: 'init / userspace' optional-skip (X11-before-PID1, not stalling)",
          "X11 ready" in hit and "firefox exec" in hit)
    # Prove the firehose really is off in this fixture (no per-write mirror).
    fire = (CORE_PROFILE_SERIAL.count("[FF/write]")
            + CORE_PROFILE_SERIAL.count("[FF/stderr]")
            + CORE_PROFILE_SERIAL.count("[FF/write-fd]")
            + CORE_PROFILE_SERIAL.count("[FF/open]"))
    check("core: firehose stayed off (0 [FF/write]/[FF/stderr]/[FF/open])",
          fire == 0, fire)


# ── screenshot streams: base64 PNG decode (VGA framebuffer + Firefox render) ──
PNG_SIG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


def _make_png(w, h):
    """A real, valid PNG built with stdlib zlib only (NO Pillow). 8-bit RGBA,
    one IDAT, one IEND. Its IHDR carries w/h so the dimension parse is exercised."""
    def chunk(typ, data):
        c = typ + data
        return struct.pack(">I", len(data)) + c + struct.pack(
            ">I", zlib.crc32(c) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)   # 8-bit, colour-type 6
    # filter byte 0 + RGBA scanlines (a flat colour compresses small/fast)
    raw = b"".join(b"\x00" + b"\x39\xd3\x53\xff" * w for _ in range(h))
    return (PNG_SIG + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def _emit_stream(png, kind, drop_tail=0, end=True):
    """Render `png` as the chunked base64 serial stream for `kind` (vga|ff). When
    drop_tail>0, omit the last `drop_tail` chunks (and the END marker) to model
    an in-progress/partial stream. Mirrors the kernel's 76-char chunk width."""
    b64 = base64.b64encode(png).decode()
    parts = [b64[i:i + 76] for i in range(0, len(b64), 76)]
    M = len(parts)
    keep = M - drop_tail
    lines = []
    if kind == "ff":
        lines.append(f"[FF-OUT-PNG:path=/tmp/out.png size={len(png)} sig_ok=true]")
        tag = "FF-OUT-PNG-B64"
        endtag = "[FF-OUT-PNG-END]"
    else:
        tag = "SCREENSHOT-B64"
        endtag = "[SCREENSHOT-B64-END]"
    for i in range(keep):
        lines.append(f"[{tag}:{i}/{M}] {parts[i]}")
    if end and drop_tail == 0:
        lines.append(endtag)
    return "\n".join(lines) + "\n", M, keep


def _screenshot_checks(sw, tmp):
    """The screenshot decode endpoint: complete + partial streams for BOTH the
    VGA framebuffer (kind=vga) and the Firefox render (kind=ff). Validates the
    decoded PNG signature/dimensions, completeness flags, partial-pct, the
    metadata endpoint, and graceful degradation (no 500 on a torn stream; a
    clean JSON 404 when absent). All synthetic — CI-safe, no real logs needed."""
    # ---- complete VGA + complete FF in one log ----
    png_vga = _make_png(800, 450)        # matches the real fixture dimensions
    png_ff = _make_png(64, 48)
    sid = "shots01"
    log = os.path.join(tmp, sid + ".serial.log")
    vga_txt, vgaM, _ = _emit_stream(png_vga, "vga")
    ff_txt, ffM, _ = _emit_stream(png_ff, "ff")
    with open(log, "w") as f:
        f.write("[BOOT] AstryxOS kernel\n" + vga_txt + ff_txt)

    dv = sw._decode_shot(log, "vga")
    check("shots vga decodes to valid PNG", dv["sig_ok"] and dv["png"][:8] == PNG_SIG)
    check("shots vga complete", dv["complete"] is True, dv["complete"])
    check("shots vga dims 800x450", dv["w"] == 800 and dv["h"] == 450, (dv["w"], dv["h"]))
    check("shots vga byte-exact", dv["bytes"] == len(png_vga), (dv["bytes"], len(png_vga)))
    check("shots vga chunks==total", dv["chunks"] == vgaM and dv["total"] == vgaM)

    df = sw._decode_shot(log, "ff")
    check("shots ff decodes to valid PNG", df["sig_ok"] and df["png"][:8] == PNG_SIG)
    check("shots ff complete", df["complete"] is True, df["complete"])
    check("shots ff dims 64x48", df["w"] == 64 and df["h"] == 48, (df["w"], df["h"]))
    check("shots ff byte-exact + guest_size cross-check",
          df["bytes"] == len(png_ff) == df["guest_size"],
          (df["bytes"], len(png_ff), df["guest_size"]))

    # ---- metadata endpoint: both present, no png bytes shipped ----
    md = sw.scan_screenshots(log)
    check("scan_screenshots vga present+complete",
          md["vga"]["present"] and md["vga"]["complete"])
    check("scan_screenshots ff present+complete",
          md["ff"]["present"] and md["ff"]["complete"])
    check("scan_screenshots strips png bytes (metadata only)",
          "png" not in md["vga"] and "png" not in md["ff"])
    check("scan_screenshots consistent schema (both branches have end_seen/received)",
          all(k in md["vga"] for k in ("end_seen", "received", "first_gap", "partial_pct")))

    # ---- PARTIAL VGA: drop ~33% of the tail + the END marker ----
    sidp = "shotspart01"
    logp = os.path.join(tmp, sidp + ".serial.log")
    drop = vgaM // 3
    vpart, _, vkeep = _emit_stream(png_vga, "vga", drop_tail=drop)
    with open(logp, "w") as f:
        f.write(vpart)
    dp = sw._decode_shot(logp, "vga")
    check("shots PARTIAL does not error (graceful)", dp["error"] is None, dp["error"])
    check("shots PARTIAL present but not complete",
          dp["present"] and dp["complete"] is False, (dp["present"], dp["complete"]))
    check("shots PARTIAL still a valid PNG prefix (IHDR present)",
          dp["sig_ok"] and dp["png"][:8] == PNG_SIG)
    check("shots PARTIAL keeps IHDR dims (800x450)",
          dp["w"] == 800 and dp["h"] == 450, (dp["w"], dp["h"]))
    check("shots PARTIAL pct == int(100*keep/total)",
          dp["partial_pct"] == int(100 * vkeep / vgaM),
          (dp["partial_pct"], vkeep, vgaM))
    check("shots PARTIAL end_seen False (no END marker)", dp["end_seen"] is False)

    # ---- absent stream: clean 'present:false', no crash ----
    sidn = "shotsnone01"
    logn = os.path.join(tmp, sidn + ".serial.log")
    with open(logn, "w") as f:
        f.write("[BOOT] AstryxOS kernel\n[FFTEST] no screenshot here\n")
    dn = sw._decode_shot(logn, "vga")
    check("shots absent -> present False, no error", not dn["present"] and dn["error"] is None)

    # ---- HTTP layer: serve PNG bytes, headers, JSON 404 on absent ----
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), sw.H)
    srv.daemon_threads = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # complete VGA -> 200 image/png, PNG magic, complete header
        req = urllib.request.urlopen(
            f"http://127.0.0.1:{port}/api/screenshot?sid={sid}&kind=vga", timeout=5)
        body = req.read()
        check("GET /api/screenshot vga 200 image/png",
              req.status == 200 and req.headers.get("Content-Type") == "image/png")
        check("GET /api/screenshot vga returns PNG bytes", body[:8] == PNG_SIG)
        check("GET /api/screenshot vga X-Screenshot-Complete true",
              req.headers.get("X-Screenshot-Complete") == "true")
        check("GET /api/screenshot vga X-Screenshot-Dimensions 800x450",
              req.headers.get("X-Screenshot-Dimensions") == "800x450")
        # complete FF -> 200 image/png
        reqf = urllib.request.urlopen(
            f"http://127.0.0.1:{port}/api/screenshot?sid={sid}&kind=ff", timeout=5)
        bodyf = reqf.read()
        check("GET /api/screenshot ff 200 PNG bytes",
              reqf.status == 200 and bodyf[:8] == PNG_SIG)
        # partial VGA -> 200 but Complete:false (degrades, not 500)
        reqp = urllib.request.urlopen(
            f"http://127.0.0.1:{port}/api/screenshot?sid={sidp}&kind=vga", timeout=5)
        bodyp = reqp.read()
        check("GET /api/screenshot PARTIAL 200 (not 500) + PNG bytes",
              reqp.status == 200 and bodyp[:8] == PNG_SIG)
        check("GET /api/screenshot PARTIAL Complete header false",
              reqp.headers.get("X-Screenshot-Complete") == "false")
        # absent FF on a vga-only log -> JSON 404
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/screenshot?sid={sidp}&kind=ff", timeout=5)
            absent404 = False
        except urllib.error.HTTPError as e:
            absent404 = (e.code == 404
                         and e.headers.get("Content-Type") == "application/json")
        check("GET /api/screenshot absent -> JSON 404 (no 500)", absent404)
        # bad kind -> 400 JSON
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/screenshot?sid={sid}&kind=bogus", timeout=5)
            bad400 = False
        except urllib.error.HTTPError as e:
            bad400 = e.code == 400
        check("GET /api/screenshot bad kind -> 400", bad400)
        # metadata endpoint
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/screenshots?sid={sid}", timeout=5) as r:
            mbody = json.loads(r.read())
        check("GET /api/screenshots both kinds + no png bytes",
              mbody["vga"]["complete"] and mbody["ff"]["complete"]
              and "png" not in mbody["vga"])
        # the dashboard HTML wires up the screenshots panel + endpoint
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            page = r.read()
        check("dashboard HTML references screenshots panel",
              b"id=shots" in page and b"/api/screenshot?" in page
              and b"VGA framebuffer" in page and b"Firefox render" in page)
    finally:
        srv.shutdown()


def _real_fixture_checks(sw):
    """Opportunistic check against the REAL operator fixtures, only when this
    host has them (skipped silently in CI, which has no ~/.astryx-harness logs).
    fcc3cb95d128 = a COMPLETE [SCREENSHOT-B64] (25275/25275 -> 800x450 PNG);
    137d5d460cc0 = a PARTIAL one (16990/25275)."""
    hd = os.path.expanduser("~/.astryx-harness")
    comp = os.path.join(hd, "fcc3cb95d128.serial.log")
    part = os.path.join(hd, "137d5d460cc0.serial.log")
    if not (os.path.exists(comp) and os.path.exists(part)):
        print("  (real fixtures absent — host-fixture checks skipped)")
        return
    old = sw.HARNESS_DIR
    sw.HARNESS_DIR = hd
    try:
        dc = sw._decode_shot(comp, "vga")
        check("REAL complete fixture -> valid 800x450 PNG",
              dc["complete"] and dc["sig_ok"] and dc["w"] == 800 and dc["h"] == 450,
              (dc["complete"], dc["w"], dc["h"]))
        check("REAL complete fixture 25275 chunks",
              dc["total"] == 25275 and dc["chunks"] == 25275, (dc["chunks"], dc["total"]))
        dp = sw._decode_shot(part, "vga")
        check("REAL partial fixture decodes gracefully (no error, valid prefix)",
              dp["error"] is None and dp["sig_ok"] and dp["present"], dp["error"])
        check("REAL partial fixture not complete + pct ~67",
              dp["complete"] is False and dp["partial_pct"] == 67, dp["partial_pct"])
    finally:
        sw.HARNESS_DIR = old


def main():
    tmp = tempfile.mkdtemp(prefix="serialweb-smoke-")
    sid = "smoketest1234"
    log = os.path.join(tmp, sid + ".serial.log")
    with open(log, "w") as f:
        f.write(SERIAL)
    started = time.time() - 119          # 1m59s ago
    with open(os.path.join(tmp, sid + ".json"), "w") as f:
        json.dump({"sid": sid, "pid": 4242, "started_at": started,
                   "features": "firefox-test,kdb,blk-trace", "running": True}, f)
    # a second session with NO json — exercises the log-mtime fallback
    sid2 = "nojson5678"
    log2 = os.path.join(tmp, sid2 + ".serial.log")
    with open(log2, "w") as f:
        f.write("[BOOT] AstryxOS kernel\n")
    # a third session WITH a --pcap capture — exercises /api/pcap (raw libpcap
    # download) + /api/wire (decoded DNS/TCP/TLS/HTTP summary). The fixture pcap
    # is built spec-faithfully via pcap_decode's own frame builders (DNS query +
    # TLS ClientHello with SNI), so the wire summary must surface them.
    sid3 = "pcapsess9012"
    log3 = os.path.join(tmp, sid3 + ".serial.log")
    with open(log3, "w") as f:
        f.write("[BOOT] AstryxOS kernel (pcap session)\n")
    pcap_fixture = _build_pcap_fixture()
    pcap_path = os.path.join(tmp, sid3 + ".pcap")
    with open(pcap_path, "wb") as f:
        f.write(pcap_fixture)
    with open(os.path.join(tmp, sid3 + ".json"), "w") as f:
        json.dump({"sid": sid3, "pid": 5252, "started_at": time.time() - 30,
                   "features": "firefox-test,kdb", "running": True,
                   "pcap_path": pcap_path}, f)

    sw = load_module(tmp)

    print("── pure parsers ──")
    # sessions / launch info
    sessions = {s["sid"]: s for s in sw.list_sessions()}
    s1 = sessions.get(sid, {})
    check("sessions includes fixture", sid in sessions)
    check("started_at from json", abs((s1.get("started_at") or 0) - started) < 1, s1.get("started_at"))
    check("started_src == json", s1.get("started_src") == "json", s1.get("started_src"))
    check("elapsed ~119s", s1.get("elapsed") is not None and 115 <= s1["elapsed"] <= 125, s1.get("elapsed"))
    check("pid surfaced", s1.get("pid") == 4242, s1.get("pid"))
    s2 = sessions.get(sid2, {})
    check("no-json fallback started_src", s2.get("started_src") == "log-ctime", s2.get("started_src"))
    check("no-json fallback has started_at", s2.get("started_at") is not None)

    # milestones — forward-ordered first hits
    ms = {m["label"]: m for m in sw.scan_milestones(log)}
    check("milestone kernel-entry hit", ms["kernel entry"]["hit"])
    check("milestone X11 hit with line", ms["X11 ready"]["hit"] and ms["X11 ready"]["line"] > 0)
    check("milestone firefox-exec hit", ms["firefox exec"]["hit"])
    check("milestone PNG not hit", not ms["PNG write"]["hit"])
    # forward ordering: X11 line < firefox-exec line
    check("milestones forward-ordered", ms["X11 ready"]["line"] < ms["firefox exec"]["line"])

    # context window around a gate line
    x11_line = ms["X11 ready"]["line"]
    ctx = sw.read_context(log, x11_line, 3)
    check("context start<=line<=end", ctx["start"] <= x11_line <= ctx["end"])
    check("context returns lines", len(ctx["lines"]) > 0)
    check("context target line present",
          any(l["n"] == x11_line and "X11 server ready" in l["t"] for l in ctx["lines"]))

    # metrics — both STUCK_IN_NR and cur_nr variants parse
    size = os.path.getsize(log)
    mt = sw.scan_metrics(log, size)
    check("metrics hb parsed", mt.get("hb") and mt["hb"]["sc"] == 1500, mt.get("hb"))
    pids = {p["pid"]: p for p in mt.get("pids", [])}
    check("metrics pid1 latest sc", pids.get(1, {}).get("sc") == 900, pids.get(1, {}).get("sc"))
    check("metrics pid1 cur_nr stuck", pids.get(1, {}).get("stuck_nr") == 5, pids.get(1, {}).get("stuck_nr"))
    check("metrics pid2 STUCK fallback parse", 2 in pids)
    check("metrics breakdown parsed", pids.get(1, {}).get("bd", {}).get("file") == 320)
    check("metrics aggregate sc", mt["agg"]["sc"] == 900 + 200, mt["agg"]["sc"])
    check("metrics ram_total 2GiB", mt["ram_total"] == 2 * 1024 * 1024 * 1024)

    # blkmap — histogram across the device
    bk = sw.scan_blkmap(log, size, 256)
    check("blkmap has_trace True", bk["has_trace"])
    check("blkmap n_req == 4", bk["n_req"] == 4, bk["n_req"])
    check("blkmap device sectors", bk["sectors"] == 4194304)
    tr = sum(b["r"] for b in bk["buckets"])
    tw = sum(b["w"] for b in bk["buckets"])
    check("blkmap read sectors == 1+8+2048", tr == 1 + 8 + 2048, tr)
    check("blkmap write sectors == 8", tw == 8, tw)
    # write request at lba 4000000 -> high bucket
    spb = bk["sectors_per_bucket"]
    wbucket = 4000000 // spb
    check("blkmap write in high bucket", bk["buckets"][wbucket]["w"] == 8, bk["buckets"][wbucket])
    # no-trace log reports has_trace False
    bk2 = sw.scan_blkmap(log2, os.path.getsize(log2), 256)
    check("blkmap no-trace -> has_trace False", not bk2["has_trace"])

    # ── per-gate TIMING: elapsed-since-launch + per-gate delta ──
    print("── per-gate timing ──")
    _gate_timing_checks(sw, tmp)

    # ── firefox-test-core (fast profile, firehose OFF) gate visibility ──
    print("── core-profile gate visibility ──")
    _core_profile_gate_checks(sw, tmp)

    # ── screenshot streams: base64 PNG decode (VGA framebuffer + FF render) ──
    print("── screenshot decode (VGA framebuffer + Firefox render) ──")
    _screenshot_checks(sw, tmp)
    _real_fixture_checks(sw)

    # ── HTTP layer end-to-end on an ephemeral port ──
    print("── HTTP endpoints ──")
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), sw.H)
    srv.daemon_threads = True
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"

    def get(path):
        with urllib.request.urlopen(base + path, timeout=5) as r:
            return r.status, r.read()

    try:
        st, body = get("/api/sessions")
        check("GET /api/sessions 200", st == 200)
        check("GET /api/sessions has started_at", b"started_at" in body)
        st, body = get(f"/api/milestones?sid={sid}")
        check("GET /api/milestones 200", st == 200 and b'"hit"' in body)
        st, body = get(f"/api/context?sid={sid}&line={x11_line}&ctx=3")
        check("GET /api/context 200", st == 200 and b'"lines"' in body)
        st, body = get(f"/api/metrics?sid={sid}")
        check("GET /api/metrics 200", st == 200 and b'"agg"' in body)
        st, body = get(f"/api/blkmap?sid={sid}&grid=128")
        check("GET /api/blkmap 200", st == 200 and b'"buckets"' in body)
        st, body = get("/")
        check("GET / dashboard 200", st == 200 and b"AstryxOS" in body)
        # the dashboard HTML wires up the wire/network panel + endpoints
        check("dashboard HTML references wire panel",
              b"id=wire" in body and b"/api/pcap?" in body
              and b"/api/wire?" in body)

        # ── /api/pcap (raw libpcap download) ──────────────────────────────
        reqc = urllib.request.urlopen(base + f"/api/pcap?sid={sid3}", timeout=5)
        bodyc = reqc.read()
        check("GET /api/pcap 200 + libpcap content-type",
              reqc.status == 200
              and reqc.headers.get("Content-Type") == "application/vnd.tcpdump.pcap")
        check("GET /api/pcap Content-Disposition attachment",
              "attachment" in (reqc.headers.get("Content-Disposition") or ""))
        check("GET /api/pcap returns the exact capture bytes",
              bodyc == pcap_fixture)
        # absent capture (session not run with --pcap) -> JSON 404, never 500
        try:
            urllib.request.urlopen(base + f"/api/pcap?sid={sid}", timeout=5)
            pcap404 = False
        except urllib.error.HTTPError as e:
            pcap404 = (e.code == 404
                       and e.headers.get("Content-Type") == "application/json")
        check("GET /api/pcap absent -> JSON 404 (no 500)", pcap404)

        # ── /api/wire (decoded DNS/TCP/TLS/HTTP summary) ──────────────────
        st, body = get(f"/api/wire?sid={sid3}")
        wire = json.loads(body)
        check("GET /api/wire 200 envelope", st == 200 and "decode_available" in wire)
        if wire.get("decode_available"):
            # decoder present: the fixture's DNS question + TLS SNI must surface
            check("GET /api/wire decoded ok", wire.get("ok") is True)
            check("GET /api/wire carries pcap_url",
                  wire.get("pcap_url") == f"/api/pcap?sid={sid3}")
            check("GET /api/wire surfaces DNS example.com",
                  any((d.get("name") == "example.com") for d in wire.get("dns", [])))
            check("GET /api/wire surfaces TLS SNI example.com",
                  any((t.get("sni") == "example.com") for t in wire.get("tls", [])))
            check("GET /api/wire packet count >= 3", (wire.get("packets") or 0) >= 3)
        else:
            # checkout without pcap_decode.py: must still return raw-download hint
            check("GET /api/wire degrades to decode_available=false",
                  wire.get("ok") is False and wire.get("pcap_url"))
        # absent capture -> JSON 404 with decode_available flag, never 500
        try:
            urllib.request.urlopen(base + f"/api/wire?sid={sid}", timeout=5)
            wire404 = False
        except urllib.error.HTTPError as e:
            wire404 = e.code == 404
        check("GET /api/wire absent -> JSON 404 (no 500)", wire404)
        # bad sid -> 400, never 500
        try:
            urllib.request.urlopen(base + "/api/wire?sid=../../etc/passwd", timeout=5)
            wirebad = False
        except urllib.error.HTTPError as e:
            wirebad = e.code in (400, 404)
        check("GET /api/wire bad sid rejected", wirebad)

        # path-traversal / bad sid rejected
        try:
            get("/api/metrics?sid=../../etc/passwd")
            rejected = False
        except urllib.error.HTTPError as e:
            rejected = e.code in (400, 404)
        check("path traversal rejected", rejected)
    finally:
        srv.shutdown()

    # cleanup
    for f in os.listdir(tmp):
        os.unlink(os.path.join(tmp, f))
    os.rmdir(tmp)

    print()
    if failures:
        print(f"\033[31m{len(failures)} check(s) FAILED:\033[0m " + ", ".join(failures))
        return 1
    print("\033[32mAll serial-web smoke checks passed.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
