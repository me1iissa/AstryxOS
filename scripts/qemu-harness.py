#!/usr/bin/env python3
"""
qemu-harness.py — Agentic QEMU session manager for AstryxOS kernel debugging.

Provides a persistent, structured JSON interface for driving QEMU sessions
from agent scripts or CI. Every subcommand prints JSON to stdout.

Session state is stored in ~/.astryx-harness/<sid>.json.
Events are written to ~/.astryx-harness/<sid>.events.jsonl.
QMP socket: ~/.astryx-harness/<sid>.qmp.sock

Usage:
    python3 scripts/qemu-harness.py start [--features FLAGS] [--no-build]
    python3 scripts/qemu-harness.py stop <sid>
    python3 scripts/qemu-harness.py list
    python3 scripts/qemu-harness.py wait <sid> <regex> [--ms MS]
    python3 scripts/qemu-harness.py grep <sid> <regex> [--tail N]
    python3 scripts/qemu-harness.py send <sid> <text>
    python3 scripts/qemu-harness.py tail <sid> [--bytes B] [--since LINE]
    python3 scripts/qemu-harness.py status <sid>
    python3 scripts/qemu-harness.py events <sid> [--tail N] [--follow]
    python3 scripts/qemu-harness.py snap <sid> save|load <name>
"""

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

# ── Shared build helpers (re-used from watch-test.py logic) ──────────────────
# Import build_kernel and path constants from the sibling module without
# executing its main(). We add the scripts/ dir to sys.path.

_SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPTS_DIR))

# Lazy import: only load watch_test symbols we actually need.
def _get_watch_test():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "watch_test", _SCRIPTS_DIR / "watch-test.py"
    )
    mod = importlib.util.module_from_spec(spec)
    # Prevent watch-test's main() from running on import
    _orig = sys.argv
    sys.argv = ["watch-test.py", "--no-build"]  # suppress argparse side-effects
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = _orig
    return mod

# ── Session directory ─────────────────────────────────────────────────────────

HARNESS_DIR = Path.home() / ".astryx-harness"
HARNESS_DIR.mkdir(parents=True, exist_ok=True)

# ── ANSI (TTY only) ───────────────────────────────────────────────────────────

_TTY = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"{code}{text}\033[0m" if _TTY else text

def _out(obj):
    """Print a JSON object to stdout."""
    print(json.dumps(obj, default=str))

def _err(msg: str, code: int = 1):
    _out({"error": msg})
    sys.exit(code)

# ── QMP helpers ───────────────────────────────────────────────────────────────

class QMP:
    """Minimal synchronous QMP client over a Unix socket."""

    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self._s: Optional[socket.socket] = None

    def connect(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.sock_path)
                # Read greeting
                greeting = b""
                s.settimeout(3.0)
                while b"\n" not in greeting:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    greeting += chunk
                # Send capabilities negotiation
                s.sendall(b'{"execute": "qmp_capabilities"}\n')
                resp = b""
                while b"\n" not in resp:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                self._s = s
                return True
            except (ConnectionRefusedError, FileNotFoundError, OSError):
                time.sleep(0.2)
        return False

    def execute(self, cmd: str, args: Optional[dict] = None) -> dict:
        if self._s is None:
            raise RuntimeError("QMP not connected")
        req = {"execute": cmd}
        if args:
            req["arguments"] = args
        self._s.sendall((json.dumps(req) + "\n").encode())
        # Read until we get a return or error
        buf = b""
        self._s.settimeout(10.0)
        while True:
            chunk = self._s.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Try each newline-delimited message
            lines = buf.split(b"\n")
            for line in lines[:-1]:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "return" in obj or "error" in obj:
                        return obj
                except json.JSONDecodeError:
                    pass
            buf = lines[-1]
        return {"return": {}}

    def close(self):
        if self._s:
            try:
                self._s.close()
            except OSError:
                pass
            self._s = None


def _qmp_command(sock_path: str, cmd: str, args: Optional[dict] = None,
                  connect_timeout: float = 3.0) -> dict:
    """One-shot QMP command. Returns the full response dict."""
    qmp = QMP(sock_path)
    if not qmp.connect(timeout=connect_timeout):
        return {"error": "QMP socket not available"}
    try:
        return qmp.execute(cmd, args)
    finally:
        qmp.close()


# ── Session file I/O ──────────────────────────────────────────────────────────

def _session_path(sid: str) -> Path:
    return HARNESS_DIR / f"{sid}.json"

def _events_path(sid: str) -> Path:
    return HARNESS_DIR / f"{sid}.events.jsonl"

def _load_session(sid: str) -> dict:
    p = _session_path(sid)
    if not p.exists():
        _err(f"Unknown session: {sid}")
    with p.open() as f:
        return json.load(f)

def _save_session(data: dict):
    p = _session_path(data["sid"])
    with p.open("w") as f:
        json.dump(data, f)

def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False

def _emit_event(sid: str, event: dict):
    event["ts"] = time.time()
    with _events_path(sid).open("a") as f:
        f.write(json.dumps(event) + "\n")


# ── Background watcher thread ─────────────────────────────────────────────────

_PANIC_RE = re.compile(
    r"kernel panic|double fault|page fault|PANIC",
    re.IGNORECASE,
)
_IDLE_SECONDS = 30

def _watcher_thread(sid: str, serial_log: str, qmp_sock: str, pid: int):
    """
    Monitors the serial log for panic patterns and idle periods.
    Runs as a daemon thread started by `start`.
    """
    last_size = 0
    last_activity = time.monotonic()
    idle_event_sent = False
    log_path = Path(serial_log)

    while _pid_alive(pid):
        try:
            size = log_path.stat().st_size if log_path.exists() else 0
        except OSError:
            size = 0

        if size > last_size:
            # Read new content
            try:
                with log_path.open("rb") as f:
                    f.seek(last_size)
                    new_data = f.read(size - last_size)
                new_text = new_data.decode("utf-8", errors="replace")
                for line in new_text.splitlines():
                    m = _PANIC_RE.search(line)
                    if m:
                        snap_name = f"{sid}-panic"
                        snap_ok = False
                        try:
                            resp = _qmp_command(qmp_sock,
                                                "human-monitor-command",
                                                {"command-line": f"savevm {snap_name}"},
                                                connect_timeout=2.0)
                            snap_ok = "error" not in resp
                        except Exception:
                            pass
                        _emit_event(sid, {
                            "event": "panic",
                            "pattern": m.group(0),
                            "line": line,
                            "snapshot": snap_name if snap_ok else None,
                        })
                last_size = size
                last_activity = time.monotonic()
                idle_event_sent = False
            except OSError:
                pass
        else:
            # Check idle
            idle = time.monotonic() - last_activity
            if idle >= _IDLE_SECONDS and not idle_event_sent:
                _emit_event(sid, {
                    "event": "idle",
                    "idle_seconds": idle,
                    "line": None,
                    "snapshot": None,
                })
                idle_event_sent = True

        time.sleep(1.0)


# ── Build helper (shared with watch-test.py) ──────────────────────────────────

def _build(features: str) -> bool:
    """Build the kernel using the same logic as watch-test.py."""
    wt = _get_watch_test()
    # watch-test's build_kernel always uses 'test-mode'.
    # If caller passes extra features we need to do the build ourselves.
    if features and features != "test-mode":
        # features is a comma-separated string; build directly
        ROOT = wt.ROOT
        KERNEL_TARGET = wt.KERNEL_TARGET
        BOOT_EFI_SRC = wt.BOOT_EFI_SRC
        BOOT_EFI_DST = wt.BOOT_EFI_DST
        KERNEL_ELF   = wt.KERNEL_ELF
        KERNEL_BIN   = wt.KERNEL_BIN

        r1 = subprocess.run(
            ["cargo", "+nightly", "build",
             "--package", "astryx-boot",
             "--target", "x86_64-unknown-uefi",
             "--profile", "release"],
            cwd=ROOT
        )
        if r1.returncode != 0:
            return False

        feature_list = features if "test-mode" in features else f"test-mode,{features}"
        r2 = subprocess.run(
            ["cargo", "+nightly", "build",
             "--package", "astryx-kernel",
             f"--target={KERNEL_TARGET}",
             "--profile", "release",
             "--features", feature_list,
             "-Zbuild-std=core,alloc",
             "-Zbuild-std-features=compiler-builtins-mem",
             "-Zjson-target-spec"],
            cwd=ROOT
        )
        if r2.returncode != 0:
            return False

        BOOT_EFI_DST.parent.mkdir(parents=True, exist_ok=True)
        KERNEL_BIN.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(BOOT_EFI_SRC, BOOT_EFI_DST)

        sysroot = subprocess.check_output(
            ["rustc", "+nightly", "--print", "sysroot"],
            text=True, cwd=ROOT
        ).strip()
        objcopy = next(Path(sysroot).rglob("llvm-objcopy"), None) or shutil.which("llvm-objcopy")
        if not objcopy:
            return False
        r3 = subprocess.run([str(objcopy), "-O", "binary",
                             str(KERNEL_ELF), str(KERNEL_BIN)], cwd=ROOT)
        return r3.returncode == 0

    # Default path: delegate to watch-test's build_kernel()
    return wt.build_kernel()


# ── QEMU launch (harness variant) ────────────────────────────────────────────

def _launch_qemu_harness(sid: str, serial_log: str, qmp_sock: str,
                          ovmf_vars_dst: str) -> subprocess.Popen:
    """Launch QEMU with a per-session serial log and QMP socket."""
    wt = _get_watch_test()
    ROOT     = wt.ROOT
    ESP_DIR  = wt.ESP_DIR
    DATA_IMG = wt.DATA_IMG
    OVMF_CODE     = wt.OVMF_CODE
    OVMF_VARS_SRC = wt.OVMF_VARS_SRC

    if not OVMF_CODE.exists():
        raise FileNotFoundError(f"OVMF not found at {OVMF_CODE}")
    shutil.copy(OVMF_VARS_SRC, ovmf_vars_dst)

    # Truncate per-session serial log
    Path(serial_log).parent.mkdir(parents=True, exist_ok=True)
    Path(serial_log).write_text("")

    cmd = [
        "qemu-system-x86_64",
        "-machine", "pc",
        "-cpu", "qemu64,+rdtscp",
        "-m", "1G",
        "-smp", "2",
        # Serial: per-session log file + a pty for send command
        "-chardev", f"file,id=ser0,path={serial_log},append=off",
        "-serial", "chardev:ser0",
        "-no-reboot", "-no-shutdown",
        "-display", "none",
        # ISA debug-exit (same as run-test.sh)
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        # QMP socket for agent control
        "-qmp", f"unix:{qmp_sock},server,nowait",
        # UEFI firmware
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={ovmf_vars_dst}",
        # Boot disk
        "-drive", f"format=raw,file=fat:rw:{ESP_DIR}",
        # Network
        "-device", "e1000,netdev=net0",
        "-netdev", "user,id=net0",
    ]

    if DATA_IMG.exists():
        cmd += [
            "-drive", f"file={DATA_IMG},format=raw,if=none,id=data0,snapshot=on",
            "-device", "virtio-blk-pci,drive=data0",
        ]

    if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK):
        cmd += ["-enable-kvm"]

    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


# ══════════════════════════════════════════════════════════════════════════════
# Subcommand implementations
# ══════════════════════════════════════════════════════════════════════════════

def cmd_start(args):
    sid = uuid.uuid4().hex[:12]
    serial_log  = str(HARNESS_DIR / f"{sid}.serial.log")
    qmp_sock    = str(HARNESS_DIR / f"{sid}.qmp.sock")
    ovmf_vars   = str(HARNESS_DIR / f"{sid}.OVMF_VARS.fd")

    # Build unless --no-build.
    # Redirect all build output to stderr so stdout stays JSON-only.
    if not args.no_build:
        _orig_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            ok = _build(args.features or "")
        finally:
            sys.stdout = _orig_stdout
        if not ok:
            _err("Build failed")

    proc = _launch_qemu_harness(sid, serial_log, qmp_sock, ovmf_vars)

    session = {
        "sid":        sid,
        "pid":        proc.pid,
        "serial_log": serial_log,
        "qmp_sock":   qmp_sock,
        "ovmf_vars":  ovmf_vars,
        "started_at": time.time(),
        "features":   args.features or "test-mode",
    }
    _save_session(session)

    # Start background watcher as a detached subprocess.
    # It re-invokes this script with the private _watch subcommand so that
    # the watcher survives after `start` exits.
    watcher_proc = subprocess.Popen(
        [sys.executable, __file__, "_watch", sid],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,  # detach from caller's process group
    )
    session["watcher_pid"] = watcher_proc.pid
    _save_session(session)

    _out({"sid": sid, "pid": proc.pid, "serial_log": serial_log})


def cmd_stop(args):
    sid = args.sid
    p = _session_path(sid)
    if not p.exists():
        # Idempotent: already gone
        _out({"ok": True, "note": "session not found (already stopped?)"})
        return

    sess = _load_session(sid)
    pid = sess.get("pid", 0)
    if pid and _pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
            # Give it 3s to exit gracefully
            for _ in range(30):
                if not _pid_alive(pid):
                    break
                time.sleep(0.1)
            if _pid_alive(pid):
                os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    # Clean up session file (leave serial log + events for post-mortem)
    p.unlink(missing_ok=True)
    # Clean up QMP socket
    qmp_sock = sess.get("qmp_sock", "")
    if qmp_sock and Path(qmp_sock).exists():
        try:
            Path(qmp_sock).unlink()
        except OSError:
            pass

    _out({"ok": True})


def cmd_list(args):
    sessions = []
    for p in sorted(HARNESS_DIR.glob("*.json")):
        try:
            with p.open() as f:
                sess = json.load(f)
            pid = sess.get("pid", 0)
            alive = _pid_alive(pid) if pid else False
            if not alive:
                # Prune dead session
                p.unlink(missing_ok=True)
                continue
            sessions.append({
                "sid":        sess["sid"],
                "pid":        pid,
                "started_at": sess.get("started_at"),
                "features":   sess.get("features"),
                "running":    alive,
            })
        except (json.JSONDecodeError, KeyError):
            pass
    _out(sessions)


def cmd_wait(args):
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]
    pattern    = re.compile(args.regex)
    timeout_ms = args.ms
    deadline   = time.monotonic() + timeout_ms / 1000.0

    # Scan from the beginning so lines produced before wait() was called
    # are not missed (important when calling wait immediately after start).
    file_pos = 0
    line_no  = 0

    while time.monotonic() < deadline:
        pid = sess.get("pid", 0)

        try:
            with Path(serial_log).open("r", errors="replace") as fh:
                fh.seek(file_pos)
                chunk = fh.read(65536)
                if chunk:
                    for ln in chunk.splitlines(keepends=True):
                        line_no += 1
                        if pattern.search(ln):
                            _out({"matched": True,
                                  "line": ln.rstrip("\n"),
                                  "line_no": line_no})
                            return
                    file_pos += len(chunk.encode("utf-8", errors="replace"))
        except OSError:
            pass

        if pid and not _pid_alive(pid):
            # QEMU exited — do one final drain
            try:
                with Path(serial_log).open("r", errors="replace") as fh:
                    fh.seek(file_pos)
                    for ln in fh.readlines():
                        line_no += 1
                        if pattern.search(ln):
                            _out({"matched": True,
                                  "line": ln.rstrip("\n"),
                                  "line_no": line_no})
                            return
            except OSError:
                pass
            break

        time.sleep(0.1)

    _out({"matched": False, "reason": "timeout"})


def cmd_grep(args):
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]
    pattern    = re.compile(args.regex)
    tail_n     = args.tail

    matches = []
    try:
        with Path(serial_log).open("r", errors="replace") as fh:
            for ln in fh:
                if pattern.search(ln):
                    matches.append(ln.rstrip("\n"))
    except OSError:
        pass

    _out(matches[-tail_n:])


def cmd_send(args):
    sess   = _load_session(args.sid)
    qmp_sock = sess["qmp_sock"]
    text   = args.text

    # Use QMP human-monitor-command to send text to the serial console.
    # QEMU's human monitor `sendkey` sends single keystrokes; for arbitrary
    # text we use `chardev-write` on the backend if available, otherwise
    # fall back to the `cont` / `sendkey` approach.
    #
    # The most reliable approach for serial input is to write via a second
    # chardev pty.  Here we use `human-monitor-command` with a
    # `chardev-write` HMP command as a best-effort mechanism.
    result = _qmp_command(
        qmp_sock,
        "human-monitor-command",
        {"command-line": f"chardev-send-break ser0"},
        connect_timeout=3.0,
    )
    # Actually write using the chardev-write QMP command (QEMU >= 7.0)
    import base64
    payload = base64.b64encode((text + "\n").encode()).decode()
    result = _qmp_command(
        qmp_sock,
        "chardev-write",
        {"id": "ser0", "data": payload},
        connect_timeout=3.0,
    )
    if "error" in result:
        # chardev-write may not be available on older QEMU; note it
        _out({"ok": False, "qmp_error": result["error"]})
        return
    _out({"ok": True})


def cmd_tail(args):
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]
    max_bytes  = args.bytes
    since_line = args.since

    try:
        with Path(serial_log).open("r", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        _out({"lines": [], "total_lines": 0})
        return

    total = len(lines)

    if since_line is not None:
        lines = lines[since_line:]

    # Apply byte cap
    result = []
    acc = 0
    for ln in reversed(lines):
        enc = ln.encode("utf-8", errors="replace")
        if acc + len(enc) > max_bytes:
            break
        result.append(ln.rstrip("\n"))
        acc += len(enc)
    result.reverse()

    _out({
        "lines":      result,
        "total_lines": total,
        "returned":   len(result),
    })


def cmd_status(args):
    sid = args.sid
    p   = _session_path(sid)
    if not p.exists():
        _out({"running": False, "sid": sid})
        return
    sess = _load_session(sid)
    pid  = sess.get("pid", 0)
    alive = _pid_alive(pid) if pid else False

    serial_size = 0
    try:
        serial_size = Path(sess["serial_log"]).stat().st_size
    except OSError:
        pass

    uptime = 0.0
    if sess.get("started_at"):
        uptime = time.time() - sess["started_at"]

    _out({
        "running":         alive,
        "sid":             sid,
        "pid":             pid,
        "serial_log_size": serial_size,
        "uptime_s":        round(uptime, 1),
        "features":        sess.get("features"),
    })


def cmd_events(args):
    sess  = _load_session(args.sid)
    ep    = _events_path(args.sid)
    tail_n = args.tail

    if not ep.exists():
        if args.follow:
            # Follow mode: wait for events
            _follow_events(ep)
        else:
            _out([])
        return

    if args.follow:
        _follow_events(ep)
        return

    events = []
    try:
        with ep.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass

    _out(events[-tail_n:] if tail_n else events)


def _follow_events(ep: Path):
    """Tail an events file indefinitely, printing each new line as JSON."""
    pos = ep.stat().st_size if ep.exists() else 0
    try:
        while True:
            try:
                sz = ep.stat().st_size if ep.exists() else 0
            except OSError:
                sz = pos
            if sz > pos:
                with ep.open() as f:
                    f.seek(pos)
                    for line in f:
                        line = line.strip()
                        if line:
                            print(line, flush=True)
                pos = sz
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass


def cmd_snap(args):
    sess     = _load_session(args.sid)
    qmp_sock = sess["qmp_sock"]
    op       = args.op          # "save" or "load"
    name     = args.name

    if op == "save":
        hmp_cmd = f"savevm {name}"
    elif op == "load":
        hmp_cmd = f"loadvm {name}"
    else:
        _err(f"Unknown snap op: {op}")

    result = _qmp_command(
        qmp_sock,
        "human-monitor-command",
        {"command-line": hmp_cmd},
        connect_timeout=5.0,
    )
    if "error" in result:
        _out({"ok": False, "qmp_error": result["error"]})
    else:
        _out({"ok": True, "name": name, "op": op})


def cmd_run_watcher(args):
    """
    Private subcommand: run the background watcher loop for a session.
    Called by `start` as a detached subprocess; runs until QEMU dies.
    Output goes to /dev/null (caller redirects stdout/stderr to DEVNULL).
    """
    sid = args.sid
    p   = _session_path(sid)
    if not p.exists():
        sys.exit(0)
    with p.open() as f:
        sess = json.load(f)

    _watcher_thread(
        sid        = sid,
        serial_log = sess["serial_log"],
        qmp_sock   = sess["qmp_sock"],
        pid        = sess["pid"],
    )
    sys.exit(0)


# ── Argument parsing ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="qemu-harness.py",
        description="Agentic QEMU session manager for AstryxOS (JSON protocol)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # start
    p_start = sub.add_parser("start", help="Launch a new QEMU session")
    p_start.add_argument("--features", default="", metavar="FLAGS",
                          help="Extra kernel features (comma-separated, test-mode always added)")
    p_start.add_argument("--no-build", action="store_true",
                          help="Skip cargo build; use existing kernel.bin")

    # stop
    p_stop = sub.add_parser("stop", help="Kill a QEMU session")
    p_stop.add_argument("sid")

    # list
    sub.add_parser("list", help="List active sessions")

    # wait
    p_wait = sub.add_parser("wait", help="Block until regex matches in serial log")
    p_wait.add_argument("sid")
    p_wait.add_argument("regex")
    p_wait.add_argument("--ms", type=int, default=30000,
                         help="Timeout in milliseconds (default 30000)")

    # grep
    p_grep = sub.add_parser("grep", help="Search serial log for regex")
    p_grep.add_argument("sid")
    p_grep.add_argument("regex")
    p_grep.add_argument("--tail", type=int, default=50,
                         help="Return last N matching lines (default 50)")

    # send
    p_send = sub.add_parser("send", help="Write text to QEMU serial input")
    p_send.add_argument("sid")
    p_send.add_argument("text")

    # tail
    p_tail = sub.add_parser("tail", help="Return last N bytes of serial log")
    p_tail.add_argument("sid")
    p_tail.add_argument("--bytes", type=int, default=4096, dest="bytes",
                         help="Max bytes to return (default 4096)")
    p_tail.add_argument("--since", type=int, default=None,
                         help="Return everything from this line number onwards")

    # status
    p_status = sub.add_parser("status", help="Return session status")
    p_status.add_argument("sid")

    # events
    p_events = sub.add_parser("events", help="Show event log (panics, idles)")
    p_events.add_argument("sid")
    p_events.add_argument("--tail", type=int, default=0,
                           help="Return last N events (0 = all)")
    p_events.add_argument("--follow", action="store_true",
                           help="Stream new events as they arrive (Monitor-tool-friendly)")

    # snap
    p_snap = sub.add_parser("snap", help="Save or load a QEMU VM snapshot")
    p_snap.add_argument("sid")
    p_snap.add_argument("op", choices=["save", "load"])
    p_snap.add_argument("name")

    # _watch: private subcommand used internally by `start` to run the
    # background watcher in a detached process. Not shown in help.
    p_watch = sub.add_parser("_watch")
    p_watch.add_argument("sid")

    args = parser.parse_args()

    dispatch = {
        "start":  cmd_start,
        "stop":   cmd_stop,
        "list":   cmd_list,
        "wait":   cmd_wait,
        "grep":   cmd_grep,
        "send":   cmd_send,
        "tail":   cmd_tail,
        "status": cmd_status,
        "events": cmd_events,
        "snap":   cmd_snap,
        "_watch": cmd_run_watcher,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
