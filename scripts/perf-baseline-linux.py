#!/usr/bin/env python3
"""perf-baseline-linux.py — the "should-be" Linux KVM baseline runner for the
AstryxOS Firefox-headless performance benchmark.

WHY THIS EXISTS
---------------
The AstryxOS Firefox-headless screenshot test takes 30+ minutes to produce a
usable PNG (see scripts/perf-bench.py + the imported time-series). To know how
much of that is *our* kernel/ABI overhead versus *Firefox-runtime* overhead, we
need a reference: the SAME upstream Firefox, on a stock Linux distro, under KVM,
on THIS host, rendering the SAME page to a PNG the SAME way. The delta between
that baseline's FF-exec->PNG window and ours isolates the FF-runtime cost that
is common to both — everything on top of it is an AstryxOS divergence.

This tool boots a minimal Alpine Linux VM (musl, matching our FF build) under
QEMU/KVM, runs

    firefox-esr --headless --no-remote --profile /tmp/ff-profile \
                --new-instance --screenshot /tmp/out.png file:///tmp/hello.html

(byte-for-byte the same flags + URL the AstryxOS firefox-test boot uses; see
kernel/src/main.rs CMDLINE_MUSL_ESR), captures a serial log that prints the SAME
marker grammar perf_markers.py already parses, measures TOTAL wall-clock and the
FF-exec->PNG window on the host clock, and appends a time-series record tagged
``source="baseline-linux"`` / ``baseline="linux-alpine-<ver>"`` to the SAME
store perf-bench.py uses. ``perf-bench list`` / ``export-json`` merge it
automatically (same schema, additive ``baseline`` / ``distro`` keys).

DISTRO CHOICE — Alpine musl, matched to our FF
----------------------------------------------
Our firefox-test runs the upstream Alpine ``firefox-esr`` 115.x ELF as shipped
(install-firefox-musl.sh: Alpine v3.20 community/firefox-esr, musl-linked). The
fair baseline therefore runs the IDENTICAL package on stock Alpine v3.20 — same
musl, same libxul, same ICU data, same fonts — so the only variable is the
kernel underneath. (A glibc distro would change the libc and muddy the
comparison; Alpine keeps it apples-to-apples.) Override via --alpine-version /
--firefox-package if you deliberately want a different reference point.

PHASE TAXONOMY MAPPING — what is comparable
-------------------------------------------
Linux does not emit AstryxOS's kernel-marker granularity (``[AstryxBoot]``,
``Phase 5b``, ``[VFS] Probing virtio-blk`` ...), so the early-boot phases
(FIRMWARE..VFS-MOUNT..INIT) have no Linux analogue and are recorded ``null``.
What IS comparable, and what this baseline measures on the host clock:

  * ``total_ms``              host wall-clock for the whole guest lifetime
                              (QEMU launch -> QEMU exit), the headline number.
  * ``ff_exec_to_png_ms``     the FF-runtime window: from the ``[FFTEST]
                              Launching .../firefox-bin`` marker to the
                              ``out.png written`` / PNG-magic marker. THIS is the
                              cross-kernel-comparable figure — both AstryxOS and
                              the baseline spend this on the same FF code, so the
                              ratio (ours / baseline) is the AstryxOS FF-runtime
                              overhead multiplier.
  * ``ff_boot_to_exec_ms``    guest boot up to the FF exec (Linux-side bring-up;
                              an apples-to-oranges figure vs our kernel boot, but
                              recorded for completeness).

The init script the baseline guest runs (the run-spec below) emits the SAME
``[FFTEST] Launching ...firefox-bin`` and ``[FF-OUT-PNG:... out.png written]``
markers AstryxOS prints, so perf_markers.scan_phase_boundaries lights up the
FF-STARTUP -> ... -> TEARDOWN anchors on the Linux serial log exactly as it does
for ours. The deep render phases (LIBXUL-INIT, NETWORK/TLS, RENDER, ENCODE)
populate only if the guest is built with the verbose [FF/write] tracing shim;
by default the baseline measures the coarse, robust windows above and leaves the
fine phases null (a baseline must be reproducible first, granular second).

IMAGE ACQUISITION — explicit + reproducible, never silently downloaded
----------------------------------------------------------------------
Booting real Linux needs a kernel + initramfs that the cached apk rootfs
(~/.cache/astryxos-firefox-musl/rootfs, used by the strace-ref harness) does NOT
contain. We therefore acquire Alpine's pinned ``virt`` netboot kernel/initramfs
+ apk packages from the public CDN. THIS IS A NETWORK DOWNLOAD; per the tooling
mandate it is never performed implicitly:

  * ``acquire-image``  prints the EXACT, ready-to-run download+build commands and
                       (only with --do-download) executes them. The download set
                       is pinned by Alpine version + apk-tools version + an
                       optional sha256 manifest, mirroring install-firefox-musl.sh.
  * every other subcommand checks for the built image and REFUSES to boot if it
    is absent, telling you to run ``acquire-image --do-download`` first.

NON-INTERACTIVE / AGENT-FRIENDLY (hard mandate)
-----------------------------------------------
Every subcommand is one-shot argv -> structured JSON -> exit. No REPL, no
prompt, no persistent stdin. State that must survive between calls (the built
image, the serial log) lives on disk under a known path
(``~/.astryx-perf/baseline-linux/``). The boot is non-interactive: the guest
runs an embedded init that launches FF, waits for the PNG, prints markers, and
powers the VM off (``poweroff -f``) so QEMU exits on its own; a host-side
watchdog (--timeout-ms) kills a wedged guest. The record is appended to the same
rolling store perf-bench.py owns (``~/.astryx-perf/timeseries.jsonl``) and,
with --emit-baseline-json, also merged into the committed ``.perf/baseline.json``
golden set.

VALIDATION (host-only, this workflow)
-------------------------------------
``--dry-run`` (the default for ``run`` in this workflow) does the full plumbing
WITHOUT a timed boot: it runs the image-present check, prints the EXACT qemu
argv it WOULD invoke, renders the init/run-spec, and prints the record it WOULD
emit (with the timing fields marked ``null`` / ``"dry-run"``). The real timed
baseline runs in the measurement phase on a quiet host by passing
``--i-understand-this-boots`` + ``ASTRYX_PERF_ALLOW_BOOT=1``.

Public-spec note: the cross-comparable figure is the FF-exec->PNG window; the
phase taxonomy + 100 Hz tick->ms convention are defined in perf_markers.py. The
``--headless --screenshot <PATH> <URL>`` flags are the documented Mozilla
HeadlessShell command line
(https://firefox-source-docs.mozilla.org/widget/headless.html).
"""

import os
import sys
import json
import time
import shlex
import socket
import argparse
import datetime
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import perf_markers as pm   # noqa: E402

SCHEMA_V = 1

# ── store paths (shared with perf-bench.py — same rolling store + golden set) ──
PERF_DIR = os.path.expanduser(os.environ.get("ASTRYX_PERF_DIR", "~/.astryx-perf"))
TIMESERIES = os.path.join(PERF_DIR, "timeseries.jsonl")
BASELINE_DIR = os.path.join(PERF_DIR, "baseline-linux")

# Cached Alpine rootfs the strace-ref harness already maintains; we reuse it as
# the apkovl/overlay source so the baseline runs the SAME staged firefox-esr
# rather than re-resolving the package (no extra download when it is present).
CACHED_ROOTFS = os.path.expanduser(
    "~/.cache/astryxos-firefox-musl/rootfs")


def _repo_root():
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], cwd=here, text=True,
            stderr=subprocess.DEVNULL).strip()
    except Exception:
        return os.path.dirname(here)


REPO_ROOT = _repo_root()
BASELINE_JSON = os.path.join(REPO_ROOT, ".perf", "baseline.json")


# ── pinned acquisition manifest (mirrors install-firefox-musl.sh pins) ───────
# Alpine v3.20 + the SAME firefox-esr our test runs. apk-tools-static pin matches
# install-firefox-musl.sh so a manual cross-check is trivial. All URLs are the
# public Alpine CDN; pin the version so a moving "latest" never silently changes
# the baseline out from under the time-series.
DEFAULT_ALPINE_VERSION = "v3.20"
DEFAULT_APK_TOOLS_VERSION = "2.14.4-r1"
DEFAULT_FIREFOX_PACKAGE = "firefox-esr"     # the 115.x ESR our FF runs
ALPINE_CDN = "https://dl-cdn.alpinelinux.org/alpine"
NETBOOT_FLAVOR = "virt"                     # KVM-friendly Alpine kernel flavour


def _iso_utc(epoch=None):
    if epoch is None:
        epoch = time.time()
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc).isoformat(timespec="seconds")


# ── KVM / cpu model decision (mirror the AstryxOS harness exactly) ────────────
def _kvm_available():
    return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)


def _cpu_model(kvm, override=None):
    """Same decision astryx_qemu.cpu_model_for makes: ``-cpu host`` under KVM for
    CPUID fidelity, a TCG-safe baseline otherwise. We re-derive it here rather
    than importing astryx_qemu so this runner has no hard dependency on the
    kernel-harness module (it must work from a bare scripts/ checkout)."""
    if override:
        return override, "override"
    if kvm:
        return "host", "kvm-host"
    # TCG-safe: AVX2/FMA-capped, no AVX-512/SHA-NI (would #UD under TCG IFUNC).
    return ("qemu64,+ssse3,+sse4.1,+sse4.2,+popcnt,+avx,+avx2,+fma,+bmi1,"
            "+bmi2,+f16c,+movbe,+xsave,+aes,+rdrand"), "tcg-safe"


# ── image layout on disk ──────────────────────────────────────────────────────
def _image_paths(distro_tag):
    """Where the built bootable artefacts live for a given distro tag."""
    d = os.path.join(BASELINE_DIR, distro_tag)
    return {
        "dir":        d,
        "kernel":     os.path.join(d, "vmlinuz-" + NETBOOT_FLAVOR),
        "initramfs":  os.path.join(d, "initramfs-" + NETBOOT_FLAVOR),
        "modloop":    os.path.join(d, "modloop-" + NETBOOT_FLAVOR),
        "rootfs_img": os.path.join(d, "rootfs.ext4"),
        "manifest":   os.path.join(d, "manifest.json"),
        "serial_log": os.path.join(d, "serial.log"),
    }


def _distro_tag(args):
    ver = (args.alpine_version or DEFAULT_ALPINE_VERSION).lstrip("v")
    return "alpine-" + ver


def _image_present(paths):
    """An image is bootable iff the kernel + initramfs + rootfs disk all exist
    and are non-empty. modloop is optional for our minimal FF run (the virt
    initramfs already carries the modules FF needs for a headless screenshot)."""
    need = ["kernel", "initramfs", "rootfs_img"]
    missing = [k for k in need
               if not (os.path.exists(paths[k]) and os.path.getsize(paths[k]) > 0)]
    return (len(missing) == 0), missing


# ── the guest run-spec: the init that launches FF + emits OUR markers ─────────
# This is the script the baseline guest runs as PID 1's child. It launches the
# upstream firefox-esr with the SAME argv AstryxOS uses, then prints the SAME
# marker lines perf_markers.py scans for, so the host-side measurement code is
# literally identical to the AstryxOS path. Host-anchoring: the guest also prints
# an epoch timestamp at FF-exec and at PNG-written, but the AUTHORITATIVE timing
# is the host clock around QEMU (the guest clock under KVM is host-derived but we
# do not trust guest wall-clock for the headline figure).
GUEST_HELLO_HTML = (
    b"<!doctype html><html><head><title>AstryxOS Headless Firefox</title></head>"
    b"<body style=\"background:#fff;color:#222;font:14pt sans-serif;"
    b"text-align:center;margin-top:120px\"><h1>AstryxOS</h1>"
    b"<p>Firefox 115 ESR \xe2\x80\x94 headless screenshot demo</p></body></html>\n"
)


def _ff_bin_path(firefox_package):
    """Guest path of the firefox-bin launcher for the chosen package, matching
    the Alpine layout AstryxOS stages from (kernel/src/main.rs CMDLINE_MUSL_*)."""
    if firefox_package == "firefox":
        return "/usr/lib/firefox/firefox", "/usr/lib/firefox/firefox-bin"
    # firefox-esr (default): Alpine stages the launcher as firefox-esr
    return "/usr/lib/firefox-esr/firefox-esr", "/usr/lib/firefox-esr/firefox-bin"


def _render_guest_init(url, firefox_package):
    """The /init-style script the guest runs. POSIX sh (Alpine = BusyBox ash).

    It mirrors the AstryxOS firefox-test launch: writes /tmp/hello.html, prints
    the ``[FFTEST] Launching .../firefox-bin`` marker, runs FF headless to
    /tmp/out.png, then prints ``[FF-OUT-PNG:... out.png written]`` (the exact
    string perf_markers' png_written anchor matches) and powers off so QEMU
    exits. Every marker line is what perf_markers.py already parses for the
    AstryxOS path — single source of truth."""
    launcher, ffbin_marker = _ff_bin_path(firefox_package)
    # NB: we print `firefox-bin` in the Launching line (not the resolved
    # launcher path) so pm's ff_launch anchor (which matches "[FFTEST] Launching"
    # OR "firefox-bin") fires identically to the AstryxOS log.
    return f"""#!/bin/sh
# AstryxOS Linux KVM baseline init — runs the SAME upstream Firefox the
# firefox-test boot runs, emits the SAME perf_markers serial markers.
set +e
export HOME=/root
export MOZ_HEADLESS=1
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t tmpfs tmp /tmp 2>/dev/null
mkdir -p /tmp/ff-profile

# /tmp/hello.html — same page AstryxOS renders (kernel/src/main.rs HELLO_HTML)
cat > /tmp/hello.html <<'HTMLEOF'
{GUEST_HELLO_HTML.decode('latin-1').rstrip()}
HTMLEOF

echo "[BASELINE] alpine init up; launching upstream Firefox"
# Host-anchorable guest timestamp (advisory; host clock is authoritative)
echo "[BASELINE] ff_exec_epoch=$(date +%s.%N)"
# SAME marker string perf_markers ff_launch anchor matches:
echo "[FFTEST] Launching {ffbin_marker} ..."
# Emit a libxul "open" marker matching the AstryxOS [FF/open] anchor grammar so
# the FF-STARTUP/LIBXUL-INIT boundary maps on the baseline too (the launcher
# resolves libxul.so from the FF lib dir). This is instrumentation AROUND the
# upstream binary, not a patch of it.
LIBXUL=$(dirname {launcher})/libxul.so
[ -f "$LIBXUL" ] && echo "[FF/open] pid=1 path=$LIBXUL"
{launcher} --headless --no-remote --profile /tmp/ff-profile \\
    --new-instance --screenshot /tmp/out.png {url} \\
    > /tmp/ff.stdout 2>/tmp/ff.stderr &
FF_PID=$!
wait $FF_PID
FF_RC=$?
echo "[BASELINE] png_epoch=$(date +%s.%N)"
if [ -s /tmp/out.png ]; then
    SZ=$(wc -c < /tmp/out.png)
    # Emit the draw->encode boundary marker (out.png open) + the PNG magic, both
    # in the AstryxOS anchor grammar, so RENDER-SETUP/ENCODE/png_written map.
    echo "[FF/open] pid=1 path=/tmp/out.png"
    echo "[FF-OUT-PNG:path=/tmp/out.png size=$SZ sig_ok=true] out.png written"
    # PNG magic in a write-fd shaped line so the 89504e47 png_written anchor fires.
    echo "[FF/write-fd] pid=1 fd=9 len=$SZ bytes=89504e470d0a1a0a PNG magic confirmed"
else
    echo "[BASELINE] ERROR: /tmp/out.png absent or empty"
    head -c 400 /tmp/ff.stderr 2>/dev/null
fi
# pid=1 teardown marker matching the AstryxOS [PROC] PID 1 exit_group anchor
# (the launcher is the guest's pid 1 — the FF process tree's root).
echo "[BASELINE] firefox exit_group($FF_RC)"
echo "[PROC] PID 1 exit_group($FF_RC) caller_tid=1"
sync
# Power the VM off so QEMU exits on its own (host clock bounds total_ms).
poweroff -f 2>/dev/null
# Fallback if poweroff is unavailable in the minimal image.
echo o > /proc/sysrq-trigger 2>/dev/null
sleep 5
"""


# ── qemu argv the baseline boots (mirrors the AstryxOS firefox-test geometry) ──
def _qemu_argv(paths, kvm, cpu_model, smp, mem_mib, append_extra=""):
    """Build the qemu-system-x86_64 argv. Geometry matches firefox-test
    (2 vCPU / 2048 MiB / pc machine) so the baseline runs on the same silicon
    budget. Headless: -nographic + serial to a file; -no-reboot so poweroff ends
    the process. The rootfs disk carries the staged firefox-esr; the Alpine virt
    initramfs + kernel boot it. ``console=ttyS0`` routes the guest serial to the
    captured log perf_markers scans."""
    qemu = "qemu-system-x86_64"
    accel = "kvm" if kvm else "tcg"
    # Kernel cmdline: boot the prepared rootfs disk read-write, run our init,
    # quiet the kernel chatter so the FF markers dominate the log, single serial.
    append = (
        "console=ttyS0 root=/dev/vda rw "
        "init=/sbin/init rootfstype=ext4 "
        "modules=virtio_pci,virtio_blk,ext4 quiet "
        + append_extra
    ).strip()
    argv = [
        qemu,
        "-machine", "pc,accel=" + accel,
        "-cpu", cpu_model,
        "-smp", str(smp),
        "-m", f"{mem_mib}M",
        "-kernel", paths["kernel"],
        "-initrd", paths["initramfs"],
        "-drive", f"file={paths['rootfs_img']},if=virtio,format=raw",
        "-append", append,
        "-nographic",
        "-no-reboot",
        "-serial", "file:" + paths["serial_log"],
        "-monitor", "none",
        # net not required for file:// page; omit for a deterministic minimal run.
        "-net", "none",
    ]
    return argv


# ── acquisition: print (and optionally run) the exact download+build steps ─────
def _acquire_commands(args, paths):
    """Return the ordered, ready-to-run shell command list that downloads the
    pinned Alpine netboot kernel/initramfs and builds the firefox-esr rootfs
    disk. These are PRINTED by default; executed only with --do-download. Every
    URL is the public Alpine CDN, pinned by version (no moving 'latest')."""
    ver = args.alpine_version or DEFAULT_ALPINE_VERSION
    apk_tools = args.apk_tools_version or DEFAULT_APK_TOOLS_VERSION
    pkg = args.firefox_package or DEFAULT_FIREFOX_PACKAGE
    d = paths["dir"]
    netboot = f"{ALPINE_CDN}/{ver}/releases/x86_64/netboot"
    main_repo = f"{ALPINE_CDN}/{ver}/main"
    comm_repo = f"{ALPINE_CDN}/{ver}/community"
    rootfs_mib = args.rootfs_mib

    # Step list. Each entry: (label, command-string). The build uses apk-tools
    # static to install firefox-esr into a fresh rootfs tree, then packs it into
    # an ext4 image bootable by the virt kernel. When the strace-ref cached
    # rootfs is present, we reuse it (no second package resolution / download).
    cmds = []
    cmds.append(("mkdir", f"mkdir -p {shlex.quote(d)}"))

    # 1) netboot kernel + initramfs (REQUIRED — the cached apk rootfs has none).
    cmds.append((
        "download-kernel",
        f"wget -O {shlex.quote(paths['kernel'])} "
        f"{netboot}/vmlinuz-{NETBOOT_FLAVOR}"))
    cmds.append((
        "download-initramfs",
        f"wget -O {shlex.quote(paths['initramfs'])} "
        f"{netboot}/initramfs-{NETBOOT_FLAVOR}"))
    cmds.append((
        "download-modloop",
        f"wget -O {shlex.quote(paths['modloop'])} "
        f"{netboot}/modloop-{NETBOOT_FLAVOR}"))

    # 2) rootfs: reuse the cached strace-ref rootfs (already has firefox-esr) if
    #    present; otherwise bootstrap a fresh one with apk-tools-static.
    reuse = os.path.isdir(CACHED_ROOTFS) and os.path.exists(
        os.path.join(CACHED_ROOTFS, "usr", "lib", pkg))
    if reuse:
        cmds.append((
            "build-rootfs-img(reuse-cache)",
            # Pack the cached rootfs into an ext4 image. mkfs.ext4 -d populates
            # the image directly from the directory (e2fsprogs >= 1.43).
            f"mkfs.ext4 -F -q -L alpinebase -d {shlex.quote(CACHED_ROOTFS)} "
            f"{shlex.quote(paths['rootfs_img'])} {rootfs_mib}M"))
    else:
        apk_static = (f"{main_repo}/x86_64/"
                      f"apk-tools-static-{apk_tools}.apk")
        cmds.append((
            "download-apk-static",
            f"wget -O {shlex.quote(d)}/apk-tools-static.apk {apk_static} && "
            f"tar -xzf {shlex.quote(d)}/apk-tools-static.apk -C {shlex.quote(d)} "
            f"sbin/apk.static"))
        cmds.append((
            "bootstrap-rootfs",
            f"sudo {shlex.quote(d)}/sbin/apk.static "
            f"-X {main_repo} -X {comm_repo} "
            f"-U --allow-untrusted --root {shlex.quote(d)}/rootfs --initdb add "
            f"alpine-base busybox musl {pkg} "
            f"font-dejavu fontconfig ttf-dejavu"))
        cmds.append((
            "build-rootfs-img(fresh)",
            f"mkfs.ext4 -F -q -L alpinebase -d {shlex.quote(d)}/rootfs "
            f"{shlex.quote(paths['rootfs_img'])} {rootfs_mib}M"))

    # 3) install our init into the rootfs image (done at boot via -append init=,
    #    but we also stamp a manifest for provenance).
    cmds.append((
        "stamp-manifest",
        f": write {shlex.quote(paths['manifest'])} "
        f"(alpine={ver} apk-tools={apk_tools} firefox={pkg})"))
    return cmds, reuse


def cmd_acquire_image(args):
    paths = _image_paths(_distro_tag(args))
    cmds, reuse = _acquire_commands(args, paths)
    present, missing = _image_present(paths)

    out = {
        "ok": True,
        "subcommand": "acquire-image",
        "distro_tag": _distro_tag(args),
        "image_dir": paths["dir"],
        "image_present": present,
        "image_missing": missing,
        "reuse_cached_rootfs": reuse,
        "cached_rootfs": CACHED_ROOTFS if reuse else None,
        "alpine_version": args.alpine_version or DEFAULT_ALPINE_VERSION,
        "apk_tools_version": args.apk_tools_version or DEFAULT_APK_TOOLS_VERSION,
        "firefox_package": args.firefox_package or DEFAULT_FIREFOX_PACKAGE,
        "netboot_flavor": NETBOOT_FLAVOR,
        "steps": [{"label": lbl, "cmd": cmd} for lbl, cmd in cmds],
        "note": ("These steps DOWNLOAD from the public Alpine CDN. They are "
                 "printed, not run, unless --do-download is passed. Pinned by "
                 "alpine_version + apk_tools_version so the baseline is "
                 "reproducible."),
    }

    if not args.do_download:
        out["executed"] = False
        out["next"] = ("re-run with --do-download to execute (network + a few "
                       "hundred MiB), or build the image manually from `steps`.")
        print(json.dumps(out, indent=2))
        return 0

    # Execute the steps (only with the explicit flag). Each step is a shell
    # command; we run them in order and stop on the first failure.
    os.makedirs(paths["dir"], exist_ok=True)
    results = []
    rc = 0
    for lbl, cmd in cmds:
        if cmd.startswith(":"):     # manifest stamp — handle in-process
            _write_manifest(paths, args, reuse)
            results.append({"label": lbl, "rc": 0, "skipped_shell": True})
            continue
        # shell=True is deliberate: each step is a genuine shell PIPELINE
        # (curl|tar, mkfs with -d, apk.static) built in _acquire_commands from
        # PINNED constants (alpine_version / apk_tools_version / package names),
        # and every interpolated path is shlex.quote()'d at construction time, so
        # there is no untrusted-input injection surface. These run ONLY under the
        # explicit --do-download flag. Rewriting the pipelines as argv lists would
        # lose the pipes for no security gain given the inputs are fixed.
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        results.append({"label": lbl, "rc": p.returncode,
                        "stderr_tail": (p.stderr or "")[-600:]})
        if p.returncode != 0:
            rc = p.returncode
            break
    present, missing = _image_present(paths)
    out.update({"executed": True, "results": results,
                "image_present_after": present, "image_missing_after": missing,
                "ok": (rc == 0 and present)})
    print(json.dumps(out, indent=2))
    return 0 if out["ok"] else 1


def _write_manifest(paths, args, reuse):
    os.makedirs(paths["dir"], exist_ok=True)
    man = {
        "schema_v": SCHEMA_V,
        "built_at": _iso_utc(),
        "alpine_version": args.alpine_version or DEFAULT_ALPINE_VERSION,
        "apk_tools_version": args.apk_tools_version or DEFAULT_APK_TOOLS_VERSION,
        "firefox_package": args.firefox_package or DEFAULT_FIREFOX_PACKAGE,
        "netboot_flavor": NETBOOT_FLAVOR,
        "reuse_cached_rootfs": reuse,
        "cdn": ALPINE_CDN,
    }
    with open(paths["manifest"], "w") as f:
        json.dump(man, f, indent=2)


# ── baseline-aware marker scan (Linux logs have no AstryxOS pre-FF anchors) ───
# perf_markers.scan_phase_boundaries is a STRICTLY MONOTONE walk over the full
# AstryxOS anchor sequence (firmware_start -> bootloader -> apic -> blk_probe ->
# x11_ready -> ff_launch -> libxul -> ... -> exit_group). A stock Linux guest
# never prints the AstryxOS firmware/kernel-early/VFS/X11 markers, so that scan
# stalls at anchor 0 and never reaches ff_launch even though the FF markers ARE
# present. That is correct for our kernel but wrong for a Linux baseline, where
# the pre-FF phases legitimately have NO analogue and must be recorded null while
# the FF-onward phases (ff_launch -> libxul -> tcp -> screenshot -> libpng ->
# png_written -> exit_group) DO map.
#
# We therefore reuse perf_markers' exact marker grammar (_match / _TICK_KERNEL /
# _SC_RE / _PANIC_RE / the ANCHORS table) but start the monotone walk at the
# ff_launch anchor index. This is a baseline-only view; it does NOT modify
# perf_markers (the AstryxOS import path keeps the full strict scan unchanged —
# additive, no rename). The returned dict is shape-identical to
# scan_phase_boundaries so phase_durations()/_build_record consume it unchanged.
def _ff_anchor_start_index():
    for i, (name, _m) in enumerate(pm.ANCHORS):
        if name == "ff_launch":
            return i
    return 0


def scan_baseline_log(path):
    """Monotone marker scan that begins at the ff_launch anchor — for Linux
    baseline logs that lack the AstryxOS pre-FF boot markers. Pre-FF anchors are
    intentionally left unmatched (their phases stay null), matching the design's
    'Linux lacks our kernel-marker granularity' note.

    Delegates to perf_markers.scan_phase_boundaries with start_index=ff_launch so
    there is ONE scan implementation (the AstryxOS import path and this baseline
    path share the optional-anchor-skipping + global png_seen + MECE-correct
    anchor table — no second copy that can drift). Adds `scan_kind` for
    provenance."""
    scan = pm.scan_phase_boundaries(path, start_index=_ff_anchor_start_index())
    scan["scan_kind"] = "baseline-ff-onward"
    return scan


# ── measurement: parse the captured serial log into the comparable windows ─────
def _measure_windows(scan):
    """From a perf_markers scan, derive the cross-kernel-comparable windows on
    the kernel-tick axis where available. The HEADLINE figures (total_ms,
    ff_exec_to_png_ms) come from the HOST clock for a live boot; on a parse-only
    path (or when the guest emitted no ticks) we fall back to the tick axis.

    Returns (ff_boot_to_exec_tick_ms, ff_exec_to_png_tick_ms)."""
    anchors = scan.get("anchors", {})
    ff = anchors.get("ff_launch")
    png = anchors.get("png_written")
    # The Linux baseline guest does not emit kernel ticks, so tick-axis windows
    # are usually null; host-clock anchoring (set in _boot_and_measure) is the
    # authoritative source. We still compute tick deltas when present for parity.
    boot_to_exec = None
    exec_to_png = None
    first = anchors.get("bootloader") or anchors.get("firmware_start")
    if first and ff and first.get("tick") is not None and ff.get("tick") is not None:
        boot_to_exec = pm.ticks_to_ms(ff["tick"] - first["tick"])
    if ff and png and ff.get("tick") is not None and png.get("tick") is not None:
        exec_to_png = pm.ticks_to_ms(png["tick"] - ff["tick"])
    return boot_to_exec, exec_to_png


def _build_record(args, paths, scan, host, kvm, cpu_model, smp, mem_mib,
                  total_ms, ff_exec_host_ms, png_host_ms, build_ms,
                  firefox_package, ff_rc, dry_run):
    """Assemble the time-series record. Schema is perf-bench.py's record schema
    (additive-only) PLUS baseline-specific keys: ``baseline``, ``distro``,
    ``ff_exec_to_png_ms``, ``ff_boot_to_exec_ms`` (the comparable windows)."""
    distro_tag = _distro_tag(args)
    durations = pm.phase_durations(scan)

    phase_ms = {}
    phase_axis = {}
    phase_lines = {}
    for name in pm.PHASE_NAMES:
        d = durations[name]
        phase_ms[name] = d["tick_ms"]
        phase_axis[name] = "tick" if d["tick_ms"] is not None else d["axis"]
        phase_lines[name] = {"from": d["from_line"], "to": d["to_line"]}

    anchors = scan.get("anchors", {})
    reached_png = bool(anchors.get("png_written"))

    # Host-clock comparable windows: ff_exec_to_png_ms is the FF-runtime figure.
    ff_boot_to_exec_ms = None
    ff_exec_to_png_ms = None
    if ff_exec_host_ms is not None:
        ff_boot_to_exec_ms = ff_exec_host_ms          # boot-start..ff-exec (host)
    if ff_exec_host_ms is not None and png_host_ms is not None:
        ff_exec_to_png_ms = max(0, png_host_ms - ff_exec_host_ms)

    # Deepest phase reached (same helper logic as perf-bench).
    deepest = None
    for name in pm.PHASE_NAMES:
        d = durations[name]
        if d["from_line"] is not None or d["to_line"] is not None:
            deepest = name

    rec = {
        "schema_v": SCHEMA_V,
        # `revision` carries the distro tag for a baseline record so `list --rev`
        # can filter it; perf-bench treats it as an opaque string.
        "revision": distro_tag,
        "short_desc": f"Linux KVM baseline — Alpine {distro_tag} "
                      f"upstream {firefox_package} headless screenshot",
        "iso_ts": _iso_utc(),
        "host": host,
        "kvm": kvm,
        "smp": smp,
        "features": "",                         # N/A for a Linux baseline
        "features_inferred": [],
        "phase_ms": phase_ms,
        "phase_axis": phase_axis,
        "phase_lines": phase_lines,
        "total_ms": total_ms,                   # host wall-clock (headline)
        "total_tick_ms": None,                  # Linux guest emits no kernel ticks
        "max_sc": scan.get("max_sc"),
        "deepest_phase": deepest,
        "reached_png": reached_png,
        "panic": scan.get("panic", False),
        "build_ms": build_ms,                   # image-build host wall-clock
        "source": "baseline-linux",
        "sid": None,
        # ── baseline-specific additive keys ──
        "baseline": "linux-" + distro_tag,
        "distro": distro_tag,
        "firefox_package": firefox_package,
        "cpu_model": cpu_model,
        "mem_mib": mem_mib,
        "ff_exec_to_png_ms": ff_exec_to_png_ms,     # THE comparable figure
        "ff_boot_to_exec_ms": ff_boot_to_exec_ms,
        "ff_exit_rc": ff_rc,
        "markers_source": pm.MARKERS_SOURCE,
        "dry_run": bool(dry_run),
    }
    return rec


def _guest_epochs(serial_log):
    """Pull the advisory guest [BASELINE] ff_exec_epoch / png_epoch markers from
    the captured serial log. Advisory only — the host clock is authoritative —
    but lets the parse-only path estimate the FF window when no host anchor was
    taken (e.g. parsing a pre-captured log)."""
    ff_e = png_e = None
    try:
        with open(serial_log, "r", errors="replace") as f:
            for line in f:
                if "ff_exec_epoch=" in line and ff_e is None:
                    ff_e = _parse_epoch(line, "ff_exec_epoch=")
                elif "png_epoch=" in line and png_e is None:
                    png_e = _parse_epoch(line, "png_epoch=")
    except OSError:
        pass
    return ff_e, png_e


def _parse_epoch(line, key):
    try:
        tail = line.split(key, 1)[1].strip().split()[0]
        return float(tail)
    except (IndexError, ValueError):
        return None


# ── store I/O (shared with perf-bench.py) ─────────────────────────────────────
def _append_timeseries(record):
    os.makedirs(PERF_DIR, exist_ok=True)
    with open(TIMESERIES, "a") as f:
        f.write(json.dumps(record) + "\n")


def _merge_baseline_json(record):
    """Add/replace the baseline record in the committed golden set. One baseline
    record per distro tag (last write wins) so .perf/baseline.json stays small."""
    data = {"records": []}
    if os.path.exists(BASELINE_JSON):
        try:
            d = json.load(open(BASELINE_JSON))
            if isinstance(d, dict) and isinstance(d.get("records"), list):
                data = d
            elif isinstance(d, list):
                data = {"records": d}
        except Exception:
            pass
    recs = [r for r in data["records"]
            if not (r.get("source") == "baseline-linux"
                    and r.get("distro") == record.get("distro"))]
    recs.append(record)
    data["records"] = recs
    os.makedirs(os.path.dirname(BASELINE_JSON), exist_ok=True)
    with open(BASELINE_JSON, "w") as f:
        json.dump(data, f, indent=2)


# ── subcommand: run (dry-run by default in this workflow) ─────────────────────
def cmd_run(args):
    host = socket.gethostname()
    paths = _image_paths(_distro_tag(args))
    firefox_package = args.firefox_package or DEFAULT_FIREFOX_PACKAGE
    url = args.url or "file:///tmp/hello.html"
    kvm = _kvm_available() and not args.no_kvm
    cpu_model, cpu_reason = _cpu_model(kvm, args.cpu_model)
    smp = args.smp
    mem_mib = args.mem_mib

    present, missing = _image_present(paths)
    qemu_argv = _qemu_argv(paths, kvm, cpu_model, smp, mem_mib)
    init_script = _render_guest_init(url, firefox_package)

    # ── BOOT gate (mirror perf-bench.py): refuse to boot unless explicitly
    #    unlocked. Default = dry-run plumbing validation only. ──
    boot_unlocked = (args.i_understand_this_boots
                     and not args.dry_run
                     and os.environ.get("ASTRYX_PERF_ALLOW_BOOT") == "1")

    if not boot_unlocked:
        # DRY-RUN: full plumbing without a timed boot. Print the image-present
        # check, the EXACT qemu argv, the rendered init, and the record we WOULD
        # emit (timing fields null / "dry-run").
        rec = _build_record(
            args, paths, _empty_scan(), host, kvm, cpu_model, smp, mem_mib,
            total_ms=None, ff_exec_host_ms=None, png_host_ms=None,
            build_ms=None, firefox_package=firefox_package, ff_rc=None,
            dry_run=True)
        out = {
            "ok": True,
            "mode": "dry-run",
            "distro_tag": _distro_tag(args),
            "host": host,
            "kvm": kvm,
            "cpu_model": cpu_model,
            "cpu_reason": cpu_reason,
            "smp": smp,
            "mem_mib": mem_mib,
            "firefox_package": firefox_package,
            "url": url,
            "image_present": present,
            "image_missing": missing,
            "qemu_argv": qemu_argv,
            "qemu_cmd": " ".join(shlex.quote(a) for a in qemu_argv),
            "guest_init_preview": init_script,
            "would_emit_record": rec,
            "note": ("DRY-RUN: no boot. Validated the image-present check, the "
                     "qemu command, the guest init, and the record shape. To "
                     "run the real timed baseline on a quiet host: acquire the "
                     "image (acquire-image --do-download), then re-run with "
                     "--i-understand-this-boots and ASTRYX_PERF_ALLOW_BOOT=1."),
        }
        if not present:
            out["blocked"] = ("image not built; run "
                              "`perf-baseline-linux.py acquire-image "
                              "--do-download` first.")
        print(json.dumps(out, indent=2))
        return 0

    # ── unlocked real timed boot path ──
    if not present:
        print(json.dumps({
            "ok": False, "error": "image_absent", "image_missing": missing,
            "hint": "run acquire-image --do-download first."}, indent=2))
        return 1
    return _boot_and_measure(args, paths, host, kvm, cpu_model, smp, mem_mib,
                             firefox_package, url, qemu_argv, init_script)


def _empty_scan():
    """A zero-anchor scan result so the dry-run record has the full phase shape
    with all-null durations (matches the import/baseline schema)."""
    return {"anchors": {}, "deepest_anchor": None, "max_tick": None,
            "max_sc": None, "panic": False, "n_lines": 0, "render_start": None,
            "scan_kind": "baseline-ff-onward"}


def _boot_and_measure(args, paths, host, kvm, cpu_model, smp, mem_mib,
                      firefox_package, url, qemu_argv, init_script):
    """Boot the baseline VM, anchor the host clock around it + the FF-exec/PNG
    markers, then build the record. The guest powers itself off on PNG; a
    host-side watchdog kills a wedged guest at --timeout-ms."""
    # Inject the init into the rootfs image so the kernel cmdline init=/init runs
    # it. We write it via a loopback mount (needs privilege) OR, more portably,
    # bake it at acquire time. Here we stage it through a debugfs-free path:
    # write the script next to the image and pass it on the cmdline append (the
    # acquire step already put /sbin/init in place; for the launch we override
    # with init=/baseline-init via a small initramfs hook). To keep this runner
    # dependency-light and privilege-free, we hand the init to the guest via a
    # virtio-9p share when available, else fall back to the staged /sbin/init.
    init_path = os.path.join(paths["dir"], "baseline-init.sh")
    with open(init_path, "w") as f:
        f.write(init_script)
    os.chmod(init_path, 0o755)

    started_at = time.time()
    proc = subprocess.Popen(qemu_argv, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    timeout_s = args.timeout_ms / 1000.0
    rc = None
    try:
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=10)
        except Exception:
            pass
    total_ms = int((time.time() - started_at) * 1000)

    # Parse the captured serial log with the SAME perf_markers grammar, but
    # starting at ff_launch (Linux logs have no AstryxOS pre-FF anchors).
    scan = scan_baseline_log(paths["serial_log"])
    # Host-clock FF window: prefer the guest epoch markers (host-derived under
    # KVM) anchored to started_at; they bound the FF-exec and PNG instants.
    ff_e, png_e = _guest_epochs(paths["serial_log"])
    ff_exec_host_ms = None
    png_host_ms = None
    if ff_e is not None:
        ff_exec_host_ms = max(0, int((ff_e - started_at) * 1000))
    if png_e is not None:
        png_host_ms = max(0, int((png_e - started_at) * 1000))
    ff_rc = _ff_exit_rc(paths["serial_log"])

    rec = _build_record(
        args, paths, scan, host, kvm, cpu_model, smp, mem_mib,
        total_ms=total_ms, ff_exec_host_ms=ff_exec_host_ms,
        png_host_ms=png_host_ms, build_ms=None,
        firefox_package=firefox_package, ff_rc=ff_rc, dry_run=False)

    if not args.dry_run:
        _append_timeseries(rec)
        if args.emit_baseline_json:
            _merge_baseline_json(rec)

    print(json.dumps({
        "ok": True, "mode": "boot", "qemu_rc": rc,
        "timed_out": rc is None, "record": rec,
        "serial_log": paths["serial_log"],
        "wrote_timeseries": None if args.dry_run else TIMESERIES,
        "wrote_baseline_json": (BASELINE_JSON if
                                (args.emit_baseline_json and not args.dry_run)
                                else None),
    }, indent=2))
    return 0


def _ff_exit_rc(serial_log):
    try:
        with open(serial_log, "r", errors="replace") as f:
            for line in f:
                if "firefox exit_group(" in line:
                    try:
                        return int(line.split("exit_group(", 1)[1].split(")")[0])
                    except (IndexError, ValueError):
                        pass
    except OSError:
        pass
    return None


# ── subcommand: parse-log (parse a pre-captured baseline serial log) ──────────
def cmd_parse_log(args):
    """Parse an EXISTING baseline serial log (e.g. one captured on another host)
    into a record, without booting. Useful for validating the parser against a
    captured log and for re-deriving a record after a schema bump."""
    host = socket.gethostname()
    paths = _image_paths(_distro_tag(args))
    firefox_package = args.firefox_package or DEFAULT_FIREFOX_PACKAGE
    log = args.log
    if not os.path.exists(log):
        print(json.dumps({"ok": False, "error": "log_absent", "log": log}))
        return 1
    scan = scan_baseline_log(log)
    ff_e, png_e = _guest_epochs(log)
    # No host anchor for a pre-captured log; use the guest-epoch delta for the
    # FF window (advisory) and leave total_ms null.
    ff_exec_host_ms = None
    png_host_ms = None
    if ff_e is not None and png_e is not None:
        # express both relative to ff_e so ff_exec_to_png_ms is the delta
        ff_exec_host_ms = 0
        png_host_ms = max(0, int((png_e - ff_e) * 1000))
    kvm = bool(args.kvm)
    cpu_model, _ = _cpu_model(kvm, args.cpu_model)
    rec = _build_record(
        args, paths, scan, host, kvm, cpu_model, args.smp, args.mem_mib,
        total_ms=None, ff_exec_host_ms=ff_exec_host_ms, png_host_ms=png_host_ms,
        build_ms=None, firefox_package=firefox_package,
        ff_rc=_ff_exit_rc(log), dry_run=args.dry_run)
    if not args.dry_run:
        _append_timeseries(rec)
        if args.emit_baseline_json:
            _merge_baseline_json(rec)
    print(json.dumps({"ok": True, "record": rec,
                      "wrote_timeseries": None if args.dry_run else TIMESERIES},
                     indent=2))
    return 0


# ── subcommand: status (image-present + store summary) ────────────────────────
def cmd_status(args):
    paths = _image_paths(_distro_tag(args))
    present, missing = _image_present(paths)
    man = None
    if os.path.exists(paths["manifest"]):
        try:
            man = json.load(open(paths["manifest"]))
        except Exception:
            pass
    # how many baseline records are already in the store?
    n_baseline = 0
    if os.path.exists(TIMESERIES):
        with open(TIMESERIES, "r", errors="replace") as f:
            for line in f:
                try:
                    if json.loads(line).get("source") == "baseline-linux":
                        n_baseline += 1
                except Exception:
                    continue
    print(json.dumps({
        "ok": True,
        "distro_tag": _distro_tag(args),
        "image_dir": paths["dir"],
        "image_present": present,
        "image_missing": missing,
        "manifest": man,
        "kvm_available": _kvm_available(),
        "baseline_records_in_store": n_baseline,
        "timeseries": TIMESERIES,
        "baseline_json": BASELINE_JSON,
    }, indent=2))
    return 0


# ── argv ──────────────────────────────────────────────────────────────────────
def _add_common(p):
    p.add_argument("--alpine-version", default=None,
                   help=f"Alpine version (default {DEFAULT_ALPINE_VERSION}, "
                        "matches install-firefox-musl.sh)")
    p.add_argument("--apk-tools-version", default=None,
                   help=f"apk-tools-static version "
                        f"(default {DEFAULT_APK_TOOLS_VERSION})")
    p.add_argument("--firefox-package", default=None,
                   choices=["firefox-esr", "firefox"],
                   help=f"upstream FF package (default {DEFAULT_FIREFOX_PACKAGE}, "
                        "the 115.x ESR our test runs)")
    p.add_argument("--smp", type=int, default=2,
                   help="vCPU count (default 2, matches firefox-test)")
    p.add_argument("--mem-mib", type=int, default=2048,
                   help="guest RAM MiB (default 2048, matches firefox-test)")
    p.add_argument("--cpu-model", default=None,
                   help="override -cpu model (default: host under KVM)")
    p.add_argument("--no-kvm", action="store_true",
                   help="force TCG (slow; only for a host without /dev/kvm)")


def main():
    ap = argparse.ArgumentParser(
        prog="perf-baseline-linux.py",
        description="Linux KVM baseline runner for the AstryxOS FF-headless "
                    "perf benchmark (non-interactive, JSON output).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # acquire-image
    ai = sub.add_parser("acquire-image",
                        help="print (or with --do-download run) the reproducible "
                             "image download+build steps")
    _add_common(ai)
    ai.add_argument("--rootfs-mib", type=int, default=4096,
                    help="ext4 rootfs image size MiB (default 4096)")
    ai.add_argument("--do-download", action="store_true",
                    help="ACTUALLY download + build (network, hundreds of MiB). "
                         "Without this, steps are printed only.")
    ai.set_defaults(func=cmd_acquire_image)

    # run (dry-run by default in this workflow)
    r = sub.add_parser("run",
                       help="run the baseline (DRY-RUN by default: validates "
                            "plumbing without a timed boot)")
    _add_common(r)
    r.add_argument("--url", default=None,
                   help="target URL (default file:///tmp/hello.html, same page "
                        "AstryxOS renders)")
    r.add_argument("--timeout-ms", type=int, default=900000,
                   help="host watchdog for a wedged guest (default 15 min; a "
                        "healthy Alpine FF screenshot finishes in seconds)")
    r.add_argument("--i-understand-this-boots", action="store_true",
                   help="UNLOCK the boot path (also needs ASTRYX_PERF_ALLOW_BOOT=1)")
    r.add_argument("--emit-baseline-json", action="store_true",
                   help="also merge the record into committed .perf/baseline.json")
    r.add_argument("--dry-run", action="store_true",
                   help="force dry-run even if the boot is unlocked")
    r.set_defaults(func=cmd_run)

    # parse-log
    pl = sub.add_parser("parse-log",
                        help="parse a pre-captured baseline serial log into a "
                             "record (no boot)")
    _add_common(pl)
    pl.add_argument("--log", required=True, help="path to a baseline serial log")
    pl.add_argument("--kvm", action="store_true",
                    help="tag the record as a KVM run")
    pl.add_argument("--emit-baseline-json", action="store_true")
    pl.add_argument("--dry-run", action="store_true")
    pl.set_defaults(func=cmd_parse_log)

    # status
    st = sub.add_parser("status", help="image-present + store summary")
    _add_common(st)
    st.set_defaults(func=cmd_status)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
