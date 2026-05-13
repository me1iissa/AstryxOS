#!/usr/bin/env python3
"""
astryx_qemu.py — Canonical QEMU command-line builder for AstryxOS.

Single source of truth for the `qemu-system-x86_64` argv used by every
AstryxOS launcher (`run-test.sh`, `run-firefox-test.sh`, `run-gui-test.sh`,
`watch-test.py`, `qemu-harness.py`). Consolidating the definition here
kills the silent config drift that audit MED-2/3/5 flagged: e.g. one
launcher using `ide-hd` for the data disk while two others used
`virtio-blk-pci`, or Firefox mode using `-cpu host` while the unit-test
mode used `-cpu qemu64,+rdtscp`.

## Design

`build_qemu_cmd()` assembles the final argv from named building blocks
(`_cpu_args`, `_memory_args`, `_serial_args`, `_firmware_args`,
`_drives_args`, `_display_args`, `_net_args`). Each block is a small
helper whose output depends on `mode` ("test" | "firefox-test" |
"gui-test") plus a handful of explicit kwargs. The per-mode
differences are therefore visible in one file.

## Canonical choices

1. **Data disk bus — virtio-blk-pci** everywhere.

   Rationale: three of the four existing launchers already used
   virtio-blk-pci. The recent shutdown-reset fix (f0e1835) moved our
   regression coverage onto this path, and test 13 (ATA PIO) exercises
   the primary/secondary IDE *controllers* via raw I/O ports, not an
   attached drive — QEMU `-machine pc` always exposes the IDE
   controllers, so the ATA probe sees hardware regardless of where
   the data.img is attached.

2. **CPU — `host` under KVM, a TCG-safe baseline under TCG.**

   Rationale: under KVM, `host` matches what a physical boot would
   encounter on the developer's workstation (the target surface
   Firefox actually hits). Under TCG, we must NOT advertise host
   CPUID — glibc's IFUNC resolver reads CPUID and selects
   AVX-512/AVX10/SHA-NI variants of `memcpy`/`strcmp`/etc that TCG
   cannot decode at runtime, triggering #UD and looking like a
   userspace crash. The TCG baseline (`qemu64` + safe extensions
   through AVX2/FMA, no AVX-512, no AVX10, no SHA-NI) gives glibc
   enough ISA to pick fast SSE/AVX2 variants while staying inside
   TCG's emulated instruction set. See QEMU `docs/system/i386/cpu.rst`
   for the per-feature decode status.

3. **Memory — 1 GiB default, 2 GiB for firefox mode.**

4. **SMP — 2 vCPUs everywhere.** Our scheduler is dual-core stable.

## Non-interactive contract

Every output of this module is the argv list for a one-shot
`qemu-system-x86_64` invocation. It never spawns QEMU itself, never
reads stdin, never holds state. Callers persist session state on
disk (see `qemu-harness.py`).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional


# ── Canonical constants ──────────────────────────────────────────────────────

#: Memory in MiB keyed by mode.
_MEM_MIB = {
    "test":         1024,
    "gui-test":     1024,
    "firefox-test": 2048,
}

#: SMP vCPU count — dual-core is the stable configuration.
#: Override via env: ASTRYX_SMP=1 for single-CPU debugging (works around
#: SMP scheduling bugs and makes QEMU gdbstub more reliable).
_SMP = int(os.environ.get("ASTRYX_SMP", "2"))

#: ISA debug-exit device — kernel writes 0 → QEMU exit(1)=pass,
#: 1 → QEMU exit(3)=fail. Shared with run-test.sh semantics.
_ISA_DEBUG_EXIT = ["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]

#: TCG-safe CPU baseline. `qemu64` is the QEMU-defined model whose
#: feature set TCG fully decodes; the `+` extensions below are all
#: TCG-decoded in QEMU >= 7 and give glibc's IFUNC resolver enough
#: ISA surface to pick a fast (SSE4.2 / AVX2 / FMA) variant of
#: `memcpy`, `strcmp`, etc. Critically we do NOT advertise:
#:   • AVX-512* (any flavour) — TCG decodes a subset only; many
#:     vector ops trap as #UD at runtime
#:   • AVX10 (Intel) — not in TCG
#:   • SHA-NI (Intel SHA extension) — Mozilla NSS picks this when
#:     present; TCG decodes only a subset and the resolver falls
#:     into a path that issues an unsupported opcode
#: When KVM is in use we want `-cpu host` instead so guest CPUID
#: matches hardware exactly.
_TCG_SAFE_CPU = (
    "qemu64"
    ",+ssse3,+sse4_1,+sse4_2"   # SSE family — palignr, pcmpistri
    ",+avx,+avx2,+fma"           # AVX2 + FMA for memcpy/memmove
    ",+rdtscp"                   # vDSO-style timing path
    ",+popcnt"                   # std::popcount IFUNC
    ",+aes,+pclmulqdq"           # NSS AES-NI / CRC32C
    ",+cmov"                     # universally assumed since P6
)


# ── Host feature detection ────────────────────────────────────────────────────

def _detect_kvm() -> bool:
    """True iff /dev/kvm is present and readable."""
    return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK)


# ── Block assemblers ──────────────────────────────────────────────────────────

def cpu_model_for(mode: str, kvm: bool,
                  cpu_override: Optional[str] = None) -> tuple[str, str]:
    """
    Return ``(cpu_model, reason)`` for the given mode + KVM state.

    ``reason`` is a short tag suitable for structured logging:
      * ``"override"``  — caller passed ``cpu_override`` verbatim
      * ``"kvm-host"``  — KVM available, using ``-cpu host`` for fidelity
      * ``"tcg-safe"``  — TCG path, using the AVX2/FMA-capped baseline
                          to avoid AVX-512/AVX10/SHA-NI IFUNC traps

    The "firefox-test forces host" special case (formerly here) has
    been removed: under TCG it would advertise host CPUID, glibc's
    IFUNC resolver would pick AVX-512 ``memcpy`` variants, and TCG
    would fault on the first unsupported vector op. Firefox-test under
    TCG is slow regardless; correctness wins.
    """
    if cpu_override:
        return cpu_override, "override"
    if kvm:
        return "host", "kvm-host"
    return _TCG_SAFE_CPU, "tcg-safe"


def _cpu_args(mode: str, kvm: bool, cpu_override: Optional[str] = None) -> list[str]:
    """
    QEMU ``-cpu`` argv fragment. Delegates the model choice to
    :func:`cpu_model_for`; this wrapper exists so callers that only
    want the argv (most of them) need not unpack the reason tag.
    """
    model, _reason = cpu_model_for(mode, kvm, cpu_override)
    return ["-cpu", model]


def _memory_args(mode: str) -> list[str]:
    mib = _MEM_MIB.get(mode, 1024)
    # Use M suffix so QEMU shows the value in MiB in its own logs
    return ["-m", f"{mib}M"]


def _smp_args() -> list[str]:
    return ["-smp", str(_SMP)]


def _machine_args() -> list[str]:
    # `pc` is the legacy i440FX-based machine that AstryxOS targets.
    # `q35` would give us PCIe natively but we haven't validated all
    # drivers against it — keep `pc` pending a separate port.
    return ["-machine", "pc"]


def _serial_args(serial_path: str) -> list[str]:
    """
    File-backed serial chardev named `ser0`. The chardev id is
    important: `qemu-harness.py send` targets it via QMP `chardev-write`.
    """
    return [
        "-chardev", f"file,id=ser0,path={serial_path},append=off",
        "-serial", "chardev:ser0",
        "-no-reboot", "-no-shutdown",
    ]


def _firmware_args(ovmf_code: str, ovmf_vars: str) -> list[str]:
    """UEFI firmware pflash pair."""
    return [
        "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive", f"if=pflash,format=raw,file={ovmf_vars}",
    ]


def _boot_disk_args(esp_dir: str) -> list[str]:
    """Boot disk: FAT-formatted ESP directory exposed as a raw image."""
    return ["-drive", f"format=raw,file=fat:rw:{esp_dir}"]


def _data_disk_args(data_img: str, warn_on_missing: bool = False) -> list[str]:
    """
    Canonical data-disk attachment: virtio-blk-pci with snapshot=on.

    Returns an empty list if `data_img` is missing — callers that
    require the data disk (e.g. firefox-test mode) must check for its
    presence themselves and error out before calling this function.

    NOTE (W13/W15 incident): when `data_img` is absent, this function
    silently returns [] and QEMU boots without /disk. In firefox-test
    mode the guest then wedges at sc=0/pf=0 with no diagnostic output.
    The root cause is agent worktrees omitting the .gitignored
    build/data.img. `qemu-harness.py::cmd_start` now emits a banner
    WARNING and attempts an auto-symlink when data_img is missing; set
    `warn_on_missing=True` (as cmd_start does) to also print to stderr
    here.
    """
    import sys as _sys
    if not data_img or not Path(data_img).exists():
        if warn_on_missing:
            print(
                f"[astryx_qemu] WARNING: data disk image not found: {data_img}",
                file=_sys.stderr,
            )
        return []
    return [
        "-drive", f"file={data_img},format=raw,if=none,id=data0,snapshot=on",
        "-device", "virtio-blk-pci,drive=data0",
    ]


def _display_args(mode: str, show_window: bool) -> list[str]:
    """
    Display subsystem.

    - Headless (default): `-display none` + (for gui-test/firefox-test)
      a vmware VGA attached to VRAM so QMP `screendump` still works.
    - Windowed: shows the QEMU display for manual inspection.
    """
    if show_window:
        # Always pick vmware VGA in windowed mode so the GUI compositor
        # has a framebuffer it understands.
        return ["-vga", "vmware"]
    if mode in ("gui-test", "firefox-test"):
        return ["-vga", "vmware", "-display", "none"]
    return ["-display", "none"]


def _net_args() -> list[str]:
    """
    e1000 + SLIRP user-mode NAT. No TAP, no bridge, no sudo. The
    guest gets 10.0.2.15 and reaches the host network via the
    SLIRP gateway at 10.0.2.2.
    """
    return [
        "-device", "e1000,netdev=net0",
        "-netdev", "user,id=net0",
    ]


def _qmp_args(qmp_sock: Optional[str]) -> list[str]:
    if not qmp_sock:
        return []
    # server=on,wait=off: socket created immediately, QEMU does not
    # block waiting for a client. This matches qemu-harness.py's
    # assumption.
    return ["-qmp", f"unix:{qmp_sock},server=on,wait=off"]


def _gdb_args(gdb_port: Optional[int], gdb_wait: bool) -> list[str]:
    if not gdb_port or gdb_port <= 0:
        return []
    args = ["-gdb", f"tcp::{gdb_port}"]
    if gdb_wait:
        args.append("-S")
    return args


def _qga_args(qga_sock: Optional[str]) -> list[str]:
    """
    QEMU CLI fragment exposing a virtio-serial port for the QEMU Guest Agent
    (QGA) transport.  Three pieces:

      -chardev socket,id=qga0,path=...,server=on,wait=off
      -device virtio-serial-pci,id=vio-serial0
      -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0

    The named-port string is the QGA well-known name; QEMU routes the
    Unix-socket chardev to that port in the multiport virtio-console
    handshake.  See virtio 1.2 §5.3.  Returns [] when `qga_sock` is None.
    """
    if not qga_sock:
        return []
    return [
        "-chardev", f"socket,id=qga0,path={qga_sock},server=on,wait=off",
        "-device", "virtio-serial-pci,id=vio-serial0",
        "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
    ]


# ── Public API ────────────────────────────────────────────────────────────────

def build_qemu_cmd(
    kernel_path: str,
    data_img: str,
    serial_path: str,
    *,
    mode: str = "test",
    ovmf_code: str,
    ovmf_vars: str,
    esp_dir: Optional[str] = None,
    qmp_sock: Optional[str] = None,
    qga_sock: Optional[str] = None,
    gdb_port: Optional[int] = None,
    gdb_wait: bool = False,
    kvm: Optional[bool] = None,
    show_window: bool = False,
    extra_args: Optional[list[str]] = None,
    cpu_override: Optional[str] = None,
    warn_on_missing_data_img: bool = False,
) -> list[str]:
    """
    Return the full argv for `qemu-system-x86_64` for an AstryxOS test run.

    Args:
      kernel_path: Unused at argv-build time (the kernel is already
        staged into `esp_dir/EFI/astryx/kernel.bin` by the caller).
        Accepted so the signature matches the audit spec.
      data_img:    Path to the raw data-disk image. If it does not
        exist, the data drive is omitted.
      serial_path: File-backed serial chardev target.
      mode:        "test" | "firefox-test" | "gui-test".
      ovmf_code:   OVMF_CODE pflash image (read-only).
      ovmf_vars:   OVMF_VARS pflash image (read-write, per-session copy).
      esp_dir:     Boot-disk ESP directory. Defaults to `<ROOT>/build/esp`
        when unset (derived from the location of this file).
      qmp_sock:    Unix socket path for a QMP monitor. `None` disables.
      gdb_port:    TCP port for QEMU's built-in GDB stub. `None`/0 disables.
      gdb_wait:    If `True` with `gdb_port`, pass `-S` (start frozen).
      kvm:         Tri-state: `True` forces `-enable-kvm`, `False`
        disables it, `None` autodetects via `/dev/kvm`.
      show_window: If `True`, show the QEMU display window instead of
        running headless.
      extra_args:  Appended verbatim to the final argv — an escape
        hatch for per-launcher quirks. Prefer a new kwarg.
      warn_on_missing_data_img: If True, print a stderr warning when
        `data_img` does not exist. Set by `qemu-harness.py` which also
        emits a full banner and attempts an auto-symlink.

    The returned list is safe to pass to `subprocess.Popen` without
    shell quoting.
    """
    if mode not in _MEM_MIB:
        raise ValueError(f"Unknown mode {mode!r}; expected one of {list(_MEM_MIB)}")

    if esp_dir is None:
        # Default to the in-tree ESP dir. Callers almost always want
        # this; the parameter exists mainly so per-session launchers
        # can point at a session-scoped copy.
        esp_dir = str(Path(__file__).resolve().parent.parent / "build" / "esp")

    if kvm is None:
        kvm = _detect_kvm()

    cmd: list[str] = ["qemu-system-x86_64"]
    cmd += _machine_args()
    cmd += _cpu_args(mode, kvm, cpu_override)
    cmd += _memory_args(mode)
    cmd += _smp_args()
    cmd += _serial_args(serial_path)
    cmd += _ISA_DEBUG_EXIT
    cmd += _qmp_args(qmp_sock)
    cmd += _qga_args(qga_sock)
    cmd += _display_args(mode, show_window)
    cmd += _firmware_args(ovmf_code, ovmf_vars)
    cmd += _boot_disk_args(esp_dir)
    cmd += _data_disk_args(data_img, warn_on_missing=warn_on_missing_data_img)
    cmd += _net_args()
    cmd += _gdb_args(gdb_port, gdb_wait)

    if kvm:
        cmd += ["-enable-kvm"]

    if extra_args:
        cmd += list(extra_args)

    return cmd


# ── CLI: print argv as a shell-safe string ───────────────────────────────────
#
# Bash wrappers can source our canonical argv by invoking:
#
#     readarray -t QEMU_CMD < <(python3 scripts/astryx_qemu.py build \
#         --mode test --serial-path BUILD/serial.log ...)
#
# Each argv token is printed on its own line, so `readarray` (or any
# equivalent line-oriented reader) reconstructs the array exactly,
# including tokens that contain spaces. No shell quoting is involved.

def qmp_screendump(sock_path: str, out_path: str, timeout: float = 5.0) -> bool:
    """
    One-shot QMP client that saves the guest framebuffer to `out_path`
    as a PPM via the `screendump` command. Returns True on success.

    Extracted from the inline heredoc that used to live in
    `run-gui-test.sh` (audit LOW-5). Keeping the QMP handshake in one
    place means we don't have two slightly different implementations
    drifting apart.
    """
    import json
    import socket
    import time

    deadline = time.monotonic() + timeout
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(sock_path)
        # Greeting
        greet = b""
        while b"\n" not in greet:
            chunk = s.recv(4096)
            if not chunk:
                return False
            greet += chunk
        # Capabilities
        s.sendall(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\n")
        # Drain return
        resp = b""
        while b"\n" not in resp:
            if time.monotonic() >= deadline:
                return False
            chunk = s.recv(4096)
            if not chunk:
                return False
            resp += chunk
        # screendump
        s.sendall(
            json.dumps({"execute": "screendump",
                        "arguments": {"filename": out_path}}).encode() + b"\n"
        )
        # Read until we see a "return" or "error"
        buf = b""
        while time.monotonic() < deadline:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            for line in buf.split(b"\n"):
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    if "return" in obj:
                        return True
                    if "error" in obj:
                        return False
                except json.JSONDecodeError:
                    continue
        return False
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _main() -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Canonical QEMU helper for AstryxOS.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("build", help="Print QEMU argv, one token per line")
    p.add_argument("--mode", default="test",
                   choices=sorted(_MEM_MIB.keys()))
    p.add_argument("--serial-path", required=True)
    p.add_argument("--data-img",    required=True)
    p.add_argument("--kernel-path", default="")
    p.add_argument("--ovmf-code",   required=True)
    p.add_argument("--ovmf-vars",   required=True)
    p.add_argument("--esp-dir",     default=None)
    p.add_argument("--qmp-sock",    default=None)
    p.add_argument("--gdb-port",    type=int, default=0)
    p.add_argument("--gdb-wait",    action="store_true")
    p.add_argument("--kvm",   dest="kvm", action="store_true",  default=None)
    p.add_argument("--no-kvm",dest="kvm", action="store_false")
    p.add_argument("--window",      action="store_true")
    p.add_argument("--extra",       action="append", default=[],
                   help="Extra verbatim QEMU arg (may repeat)")

    # screendump — one-shot QMP screenshot (LOW-5: replaces
    # run-gui-test.sh's inline Python heredoc).
    sd = sub.add_parser("screendump", help="Save guest framebuffer to PPM via QMP")
    sd.add_argument("--qmp-sock", required=True)
    sd.add_argument("--out",      required=True)
    sd.add_argument("--timeout",  type=float, default=5.0)

    args = ap.parse_args()

    if args.cmd == "build":
        cmd = build_qemu_cmd(
            kernel_path=args.kernel_path,
            data_img=args.data_img,
            serial_path=args.serial_path,
            mode=args.mode,
            ovmf_code=args.ovmf_code,
            ovmf_vars=args.ovmf_vars,
            esp_dir=args.esp_dir,
            qmp_sock=args.qmp_sock,
            gdb_port=args.gdb_port or None,
            gdb_wait=args.gdb_wait,
            kvm=args.kvm,
            show_window=args.window,
            extra_args=args.extra or None,
        )
        for token in cmd:
            print(token)
        return 0

    if args.cmd == "screendump":
        ok = qmp_screendump(args.qmp_sock, args.out, timeout=args.timeout)
        print(f"[GUITEST] Screenshot saved to {args.out}" if ok
              else f"[GUITEST] Screendump failed for {args.out}")
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(_main())
