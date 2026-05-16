#!/usr/bin/env python3
"""
qemu-harness.py — Agentic QEMU session manager for AstryxOS kernel debugging.

Provides a persistent, structured JSON interface for driving QEMU sessions
from agent scripts or CI. Every subcommand prints JSON to stdout.

Session state is stored in ~/.astryx-harness/<sid>.json.
Events are written to ~/.astryx-harness/<sid>.events.jsonl.
QMP socket: ~/.astryx-harness/<sid>.qmp.sock

## KVM default (W139 recommendation)

When /dev/kvm is available the harness uses KVM automatically — no flag
required. A 10-trial soak (W139, 2026-05-13) showed KVM consistently reaches
deeper than TCG on this host:

  * Mean syscall count:        +58 % (4 893 TCG vs 7 751 KVM)
  * quit-application-granted:   0/5 TCG vs 3/5 KVM
  * W127-cluster SIGSEGV rate: 80 % TCG vs 40 % KVM

W109 confirmed that the KVM serial-port recursion deadlock (W107) is closed
by PR #156 on master, so KVM is safe for all current firefox-test runs.

Do NOT pass --no-kvm unless you are explicitly reproducing a TCG-only
environment or testing on a host without /dev/kvm. The harness will emit a
WARNING to stderr when --no-kvm is used and /dev/kvm is available.

Tier 1 — session management:
    python3 scripts/qemu-harness.py start [--features FLAGS] [--no-build]
                                          [--gdb-port PORT] [--gdb-wait]
    python3 scripts/qemu-harness.py stop <sid>
    python3 scripts/qemu-harness.py list
    python3 scripts/qemu-harness.py wait <sid> <regex> [--ms MS]
    python3 scripts/qemu-harness.py grep <sid> <regex> [--tail N]
    python3 scripts/qemu-harness.py send <sid> <text>
    python3 scripts/qemu-harness.py tail <sid> [--bytes B] [--since LINE]
    python3 scripts/qemu-harness.py status <sid>
    python3 scripts/qemu-harness.py events <sid> [--tail N] [--follow]
    python3 scripts/qemu-harness.py snap <sid> save|load <name>
    python3 scripts/qemu-harness.py prune [--ttl DAYS]
    python3 scripts/qemu-harness.py results <sid>
    python3 scripts/qemu-harness.py read-png <sid> <dst.png> [--timeout-ms MS]

Tier 2 — GDB stub integration (requires --gdb-port on start):
    python3 scripts/qemu-harness.py regs <sid>
    python3 scripts/qemu-harness.py mem <sid> <addr> <len>
    python3 scripts/qemu-harness.py sym <sid> <name>
    python3 scripts/qemu-harness.py bp <sid> add|del|list <addr>
    python3 scripts/qemu-harness.py step <sid>
    python3 scripts/qemu-harness.py cont <sid>
    python3 scripts/qemu-harness.py pause <sid>
    python3 scripts/qemu-harness.py resume <sid>

QGA bridge (requires --features qga on start):
    python3 scripts/qemu-harness.py qga-ping <sid> [--timeout S]
    python3 scripts/qemu-harness.py qga-info <sid> [--timeout S]
    python3 scripts/qemu-harness.py qga-sync <sid> [--id N] [--timeout S]
    python3 scripts/qemu-harness.py qga-file-read <sid> --path <P> [--max-bytes N]
"""

import argparse
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

# Canonical QEMU argv builder — one source of truth across all launchers.
# astryx_qemu.py lives next to this file; make it importable whether we're
# invoked from the scripts/ dir or elsewhere.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import astryx_qemu  # noqa: E402

# ── Tier 2: GDB Remote Serial Protocol client ────────────────────────────────
#
# Implements a minimal RSP client sufficient for register reads, memory reads,
# breakpoint management, and single-step/continue.
#
# Wire format:  $<payload>#<checksum_hex2>
# Ack:          + (acknowledged) / - (nak, retransmit)
# The GDB stub inside QEMU speaks this protocol over TCP.
#
# Port conflict policy: if connect fails on the requested port, we back off
# and retry on port+1 (up to 5 attempts) to avoid "address already in use"
# when a previous test left a stale stub open.

class GdbClient:
    """Minimal RSP client for QEMU's GDB stub."""

    # x86_64 g-packet register order (GDB remote protocol):
    # rax rbx rcx rdx rsi rdi rbp rsp r8..r15 rip eflags
    # cs ss ds es fs gs (segment regs, 32-bit each in the packet)
    # Offsets in the 'g' response (little-endian 64-bit each for GPRs/RIP):
    _GPR_NAMES = [
        "rax", "rbx", "rcx", "rdx",
        "rsi", "rdi", "rbp", "rsp",
        "r8",  "r9",  "r10", "r11",
        "r12", "r13", "r14", "r15",
        "rip",
    ]
    # After the 17 64-bit GPRs comes eflags (32-bit), then segment regs (32-bit each).
    _SEG_NAMES = ["cs", "ss", "ds", "es", "fs", "gs"]

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self._s: Optional[socket.socket] = None
        self._ack_mode = True  # QEMU stub defaults to ack mode

    # ── connection ────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """
        Connect to GDB stub. Retries on port+1 .. port+4 if port is busy.
        Returns True on success.
        """
        for attempt in range(5):
            port = self.port + attempt
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.host, port))
                self._s = s
                if attempt > 0:
                    # record the actual port we used
                    self.port = port
                return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        return False

    def close(self):
        if self._s:
            try:
                self._s.sendall(b"$D#44")  # detach
            except OSError:
                pass
            try:
                self._s.close()
            except OSError:
                pass
            self._s = None

    # ── low-level packet I/O ──────────────────────────────────────────────────

    @staticmethod
    def _checksum(payload: bytes) -> int:
        return sum(payload) & 0xFF

    def _send_pkt(self, payload: str):
        """Frame and send an RSP packet, wait for + ack."""
        raw = payload.encode("ascii")
        cs  = self._checksum(raw)
        pkt = f"${payload}#{cs:02x}".encode("ascii")
        # Retry up to 3 times if we get a - nak
        for _ in range(3):
            self._s.sendall(pkt)
            if not self._ack_mode:
                return
            ack = self._recv_bytes(1)
            if ack == b"+":
                return
            # nak: fall through and retransmit

    def _recv_bytes(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("GDB stub closed connection")
            buf += chunk
        return buf

    def _recv_pkt(self) -> str:
        """
        Receive one RSP packet.  Skips any leading ack bytes (+/-) and
        consumes the trailing checksum.  Sends + ack back.
        """
        # Skip leading +/- ack bytes (response to our previous send)
        while True:
            b = self._recv_bytes(1)
            if b == b"$":
                break
            # b is + or - or other noise — skip

        payload = b""
        while True:
            c = self._recv_bytes(1)
            if c == b"#":
                break
            payload += c

        # Read the two-hex checksum
        _cs_bytes = self._recv_bytes(2)

        if self._ack_mode:
            self._s.sendall(b"+")

        return payload.decode("ascii", errors="replace")

    def send(self, payload: str) -> str:
        """Send a packet and return the response payload."""
        self._send_pkt(payload)
        return self._recv_pkt()

    # ── high-level commands ───────────────────────────────────────────────────

    def read_regs(self) -> dict:
        """Issue 'g' packet; decode and return register dict."""
        raw = self.send("g")
        if raw.startswith("E"):
            raise RuntimeError(f"GDB 'g' error: {raw}")

        # Each register is 8 bytes = 16 hex chars (little-endian)
        def le64(off):
            chunk = raw[off*16 : off*16+16]
            if len(chunk) < 16:
                return 0
            return struct.unpack_from("<Q", bytes.fromhex(chunk))[0]

        def le32(off_bytes):
            # off_bytes is byte offset into the hex string
            chunk = raw[off_bytes*2 : off_bytes*2+8]
            if len(chunk) < 8:
                return 0
            return struct.unpack_from("<I", bytes.fromhex(chunk))[0]

        result = {}
        for i, name in enumerate(self._GPR_NAMES):
            result[name] = le64(i)

        # eflags is at offset 17 (17 * 8 = 136 bytes = after 17 GPRs)
        result["eflags"] = le32(17 * 8)

        # segment regs at offsets 18..23 (each 4 bytes in the g-packet)
        seg_base = 17 * 8 + 4  # 17 GPRs + eflags
        for i, name in enumerate(self._SEG_NAMES):
            result[name] = le32(seg_base + i * 4)

        # Format as hex strings for readability
        return {k: hex(v) for k, v in result.items()}

    def read_mem(self, addr: int, length: int) -> bytes:
        """Issue 'm addr,len' packet; return raw bytes."""
        resp = self.send(f"m{addr:x},{length:x}")
        if resp.startswith("E"):
            raise RuntimeError(f"GDB mem read error: {resp}")
        return bytes.fromhex(resp)

    def set_bp(self, addr: int) -> bool:
        """Set software breakpoint via Z0 packet."""
        resp = self.send(f"Z0,{addr:x},1")
        return resp == "OK"

    def del_bp(self, addr: int) -> bool:
        """Remove software breakpoint via z0 packet."""
        resp = self.send(f"z0,{addr:x},1")
        return resp == "OK"

    def vcont_step(self) -> str:
        """Single-step via vCont;s. Returns stop-reply payload."""
        # First check vCont is supported
        support = self.send("vCont?")
        if "s" in support:
            return self.send("vCont;s")
        # Fallback to 's' packet
        return self.send("s")

    def vcont_cont(self) -> str:
        """
        Continue via vCont;c.  Sends the packet and returns immediately.

        The stop-reply will only arrive when the guest hits a breakpoint or
        is interrupted.  We set a very short recv timeout so we don't block
        indefinitely; a timeout here simply means the kernel is running, which
        is the expected state.
        """
        support = self.send("vCont?")
        pkt = "vCont;c" if "c" in support else "c"
        # Send the continue packet
        raw = pkt.encode("ascii")
        cs  = self._checksum(raw)
        frame = f"${pkt}#{cs:02x}".encode("ascii")
        self._s.sendall(frame)
        if self._ack_mode:
            # Drain the '+' ack (may arrive quickly)
            self._s.settimeout(0.5)
            try:
                self._recv_bytes(1)  # consume '+'
            except (socket.timeout, ConnectionError):
                pass
            finally:
                self._s.settimeout(self.timeout)
        # Do NOT wait for a stop-reply — the kernel is now running.
        return f"<sent: {pkt}>"

    # ── thread enumeration / selection (each QEMU vCPU is a "thread") ─────────

    def list_threads(self) -> list[int]:
        """Enumerate vCPU thread IDs via qfThreadInfo / qsThreadInfo.

        Returns a list of integer thread IDs (typically [1, 2, ...] for SMP).
        Empty list if the stub doesn't advertise threads.
        """
        ids: list[int] = []
        try:
            resp = self.send("qfThreadInfo")
        except Exception:
            return ids
        # Loop: "m<id>,<id>,..." then "qsThreadInfo" to get next batch; "l" terminator.
        while resp and resp != "l":
            if not resp.startswith("m"):
                break
            for tok in resp[1:].split(","):
                tok = tok.strip()
                if not tok:
                    continue
                try:
                    ids.append(int(tok, 16))
                except ValueError:
                    pass
            try:
                resp = self.send("qsThreadInfo")
            except Exception:
                break
        return ids

    def select_thread(self, tid: int) -> bool:
        """Select thread for subsequent g/G/m/M operations via Hg packet."""
        try:
            resp = self.send(f"Hg{tid:x}")
            return resp == "OK"
        except Exception:
            return False


# ── Tier 2: ELF symbol resolver ──────────────────────────────────────────────
#
# Resolves symbol names from the kernel ELF without spawning a GDB process.
# Uses pyelftools if available; falls back to a hand-rolled ELF64 parser.

def _resolve_symbol(elf_path: Path, name: str) -> Optional[dict]:
    """
    Return {"addr": "0x...", "size": N, "type": "func|obj|other"} or None.
    Tries pyelftools first; falls back to struct-based parser.
    """
    if not elf_path.exists():
        return None

    # ── pyelftools path ───────────────────────────────────────────────────────
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        with elf_path.open("rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                for sym in sec.iter_symbols():
                    if sym.name == name:
                        addr  = sym["st_value"]
                        size  = sym["st_size"]
                        stype = sym["st_info"]["type"]
                        type_str = {
                            "STT_FUNC":   "func",
                            "STT_OBJECT": "obj",
                        }.get(stype, "other")
                        return {
                            "addr":  hex(addr),
                            "size":  size,
                            "type":  type_str,
                        }
        return None
    except ImportError:
        pass  # fall through to manual parser

    # ── Manual ELF64 parser ───────────────────────────────────────────────────
    # ELF64 header: magic(4)+class(1)+data(1)+version(1)+osabi(1)+pad(8)
    #              +e_type(2)+e_machine(2)+e_version(4)+e_entry(8)
    #              +e_phoff(8)+e_shoff(8)+e_flags(4)+e_ehsize(2)
    #              +e_phentsize(2)+e_phnum(2)+e_shentsize(2)+e_shnum(2)
    #              +e_shstrndx(2)  = 64 bytes total
    ELF_HDR = struct.Struct("<4sBBBBxxxxxxxx HHIQQQIHHHHHH")

    with elf_path.open("rb") as f:
        raw = f.read()

    if raw[:4] != b"\x7fELF":
        return None

    (magic, ei_class, ei_data, ei_ver, ei_osabi,
     e_type, e_machine, e_version, e_entry,
     e_phoff, e_shoff, e_flags, e_ehsize,
     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = ELF_HDR.unpack_from(raw)

    # Section header entry: sh_name(4)+sh_type(4)+sh_flags(8)+sh_addr(8)
    #                       +sh_offset(8)+sh_size(8)+sh_link(4)+sh_info(4)
    #                       +sh_addralign(8)+sh_entsize(8) = 64 bytes
    SH_HDR = struct.Struct("<IIQQQQIIQQ")
    SHT_SYMTAB = 2
    SHT_DYNSYM = 11

    # Symbol entry: st_name(4)+st_info(1)+st_other(1)+st_shndx(2)
    #               +st_value(8)+st_size(8) = 24 bytes
    SYM = struct.Struct("<IBBHQQ")
    STT_FUNC   = 2
    STT_OBJECT = 1

    def read_strtab(offset, size):
        return raw[offset:offset+size]

    for i in range(e_shnum):
        sh_off = e_shoff + i * 64
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
         sh_size, sh_link, sh_info, sh_addralign, sh_entsize) = SH_HDR.unpack_from(raw, sh_off)

        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if sh_entsize == 0:
            continue

        # Load string table for this symbol table
        str_sh_off = e_shoff + sh_link * 64
        (_, _, _, _, str_offset, str_size, *_) = SH_HDR.unpack_from(raw, str_sh_off)
        strtab = read_strtab(str_offset, str_size)

        # Iterate symbols
        n_syms = sh_size // sh_entsize
        for j in range(n_syms):
            sym_off = sh_offset + j * 24
            (st_name, st_info, st_other, st_shndx,
             st_value, st_size) = SYM.unpack_from(raw, sym_off)

            # Extract name from string table
            end = strtab.find(b"\x00", st_name)
            sym_name = strtab[st_name:end].decode("ascii", errors="replace")

            if sym_name != name:
                continue

            stype = st_info & 0xF
            type_str = {STT_FUNC: "func", STT_OBJECT: "obj"}.get(stype, "other")
            return {
                "addr":  hex(st_value),
                "size":  st_size,
                "type":  type_str,
            }

    return None


def _get_gdb_port(sess: dict) -> int:
    port = sess.get("gdb_port", 0)
    if not port:
        _err("Session was not started with --gdb-port; GDB stub unavailable")
    return port


def _get_kernel_elf() -> Path:
    """
    Locate the kernel ELF.  In a git worktree the `target/` directory lives
    in the main worktree root, not the per-worktree checkout.  We walk up
    from the script's directory looking for the ELF so that both normal and
    worktree layouts work correctly.
    """
    wt  = _get_watch_test()
    elf = wt.KERNEL_ELF  # usually ROOT/target/x86_64-astryx/release/astryx-kernel

    if elf.exists():
        return elf

    # Fallback: git worktrees share the object store.  The common dir is the
    # main worktree's .git/; walk up from __file__ until we find a target/ dir.
    here = _SCRIPTS_DIR
    for _ in range(6):  # at most 6 levels up
        candidate = here / "target" / "x86_64-astryx" / "release" / "astryx-kernel"
        if candidate.exists():
            return candidate
        here = here.parent

    # Return the computed path even if it doesn't exist yet — callers check.
    return elf


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
    """
    Build the kernel, passing `features` to cargo VERBATIM.

    Empty string → no --features flag (default desktop kernel).
    Nothing is injected silently — callers that want the test-runner
    path must pass "test-mode" themselves.
    """
    wt = _get_watch_test()
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

    kernel_cmd = ["cargo", "+nightly", "build",
                  "--package", "astryx-kernel",
                  f"--target={KERNEL_TARGET}",
                  "--profile", "release"]
    if features:
        kernel_cmd += ["--features", features]
    kernel_cmd += ["-Zbuild-std=core,alloc",
                   "-Zbuild-std-features=compiler-builtins-mem",
                   "-Zjson-target-spec"]
    r2 = subprocess.run(kernel_cmd, cwd=ROOT)
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


def _check(features: str) -> tuple[int, str]:
    """
    Run `cargo +nightly check` against the kernel package for `features`.

    Returns (rc, stderr_tail) — rc==0 on success.  Stderr is forwarded
    truncated to the last 4 KB so callers can surface the failing diagnostic
    without flooding the JSON envelope.

    `features` is passed VERBATIM (comma-separated, e.g. "test-mode,kdb").
    Empty string → no `--features` flag (default desktop kernel).
    """
    wt = _get_watch_test()
    ROOT = wt.ROOT
    KERNEL_TARGET = wt.KERNEL_TARGET

    cmd = ["cargo", "+nightly", "check",
           "--package", "astryx-kernel",
           f"--target={KERNEL_TARGET}",
           "--profile", "release"]
    if features:
        cmd += ["--features", features]
    cmd += ["-Zbuild-std=core,alloc,compiler_builtins",
            "-Zbuild-std-features=compiler-builtins-mem",
            "-Zjson-target-spec"]

    proc = subprocess.run(cmd, cwd=ROOT,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          text=True)
    tail = (proc.stderr or "")[-4096:]
    return proc.returncode, tail


# ── Session-scoped ESP (concurrent-rebuild clobber fix) ──────────────────────
#
# Bug: QEMU opens the ESP directory via its `vvfat` driver, which re-reads
# host files on guest access. If another concurrent build (or the same agent
# running `cargo build` directly) rewrites `target/.../kernel.bin` or the
# staged `ESP/EFI/astryx/kernel.bin` while the session is running, the guest
# can pick up the NEW binary mid-boot, *and* any later `--no-build` restart
# silently picks up the new on-disk version — invalidating reproducibility.
#
# Fix: at session start, snapshot the ESP directory into
# `~/.astryx-harness/<sid>.esp/` and point QEMU there. Subsequent rebuilds
# from other sessions touch the in-tree `build/esp/...` but the session's
# frozen copy is untouched.
#
# Note: the data disk is already protected via `-drive snapshot=on` (host
# writes to data.img are not seen by the guest mid-run), and OVMF_VARS is
# already per-session. Only the ESP was missing this protection.

_SESSION_ESP_REL_KERNEL   = ("EFI", "astryx", "kernel.bin")
_SESSION_ESP_REL_BOOT_EFI = ("EFI", "BOOT",   "BOOTX64.EFI")


def _session_esp_dir(sid: str) -> Path:
    return HARNESS_DIR / f"{sid}.esp"


def _freeze_session_esp(sid: str, src_esp_dir: Path) -> dict:
    """
    Copy the in-tree ESP into a per-session directory so concurrent rebuilds
    from other workspaces cannot clobber this session's kernel binary.

    Returns a dict with the resolved paths, suitable for merging into the
    session-state JSON: {session_esp_dir, session_kernel_path,
    session_boot_efi_path}.

    Raises FileNotFoundError if either expected file is missing from the
    in-tree ESP — callers must run `_build()` first, or use `--no-build` on
    a tree that has previously been built.
    """
    dst_esp = _session_esp_dir(sid)
    # Clean any stale directory left from a previous session reusing the sid
    # (uuid collisions are vanishingly rare, but defensive).
    if dst_esp.exists():
        shutil.rmtree(dst_esp, ignore_errors=True)

    src_kernel   = src_esp_dir.joinpath(*_SESSION_ESP_REL_KERNEL)
    src_boot_efi = src_esp_dir.joinpath(*_SESSION_ESP_REL_BOOT_EFI)
    if not src_kernel.exists():
        raise FileNotFoundError(
            f"kernel.bin missing at {src_kernel} — run a build first")
    if not src_boot_efi.exists():
        raise FileNotFoundError(
            f"BOOTX64.EFI missing at {src_boot_efi} — run a build first")

    dst_kernel   = dst_esp.joinpath(*_SESSION_ESP_REL_KERNEL)
    dst_boot_efi = dst_esp.joinpath(*_SESSION_ESP_REL_BOOT_EFI)
    dst_kernel.parent.mkdir(parents=True, exist_ok=True)
    dst_boot_efi.parent.mkdir(parents=True, exist_ok=True)
    # copy2 preserves mtime — useful when humans diff sessions.
    shutil.copy2(src_kernel,   dst_kernel)
    shutil.copy2(src_boot_efi, dst_boot_efi)

    return {
        "session_esp_dir":       str(dst_esp),
        "session_kernel_path":   str(dst_kernel),
        "session_boot_efi_path": str(dst_boot_efi),
    }


# ── QEMU launch (harness variant) ────────────────────────────────────────────

def _launch_qemu_harness(sid: str, serial_log: str, qmp_sock: str,
                          ovmf_vars_dst: str,
                          gdb_port: int = 0,
                          gdb_wait: bool = False,
                          kdb_host_port: int = 0,
                          kvm: Optional[bool] = None,
                          smp: int = 2,
                          cpu_model: Optional[str] = None,
                          esp_dir_override: Optional[str] = None,
                          qga_sock: str = "",
                          ) -> subprocess.Popen:
    """
    Launch QEMU with a per-session serial log and QMP socket.

    gdb_port: if > 0, adds -gdb tcp::PORT to the QEMU command line.
    gdb_wait: if True and gdb_port > 0, adds -S (start frozen, wait for GDB).
    kdb_host_port: if > 0, adds a hostfwd rule forwarding host-port to
        guest 10.0.2.15:9999 for the kdb introspection server.
    kvm: tri-state. None = autodetect; True = force-enable; False = force-disable
        (matches CI which has no /dev/kvm — useful for reproducing CI hangs locally).
    esp_dir_override: if set, use this ESP directory instead of the in-tree
        `build/esp`. Used by cmd_start to point at the session-scoped frozen
        copy under `~/.astryx-harness/<sid>.esp/`, isolating the running QEMU
        from concurrent rebuilds in the in-tree ESP.
    """
    wt = _get_watch_test()
    ROOT     = wt.ROOT
    ESP_DIR  = Path(esp_dir_override) if esp_dir_override else wt.ESP_DIR
    DATA_IMG = wt.DATA_IMG
    OVMF_CODE     = wt.OVMF_CODE
    OVMF_VARS_SRC = wt.OVMF_VARS_SRC

    if not OVMF_CODE.exists():
        raise FileNotFoundError(f"OVMF not found at {OVMF_CODE}")
    shutil.copy(OVMF_VARS_SRC, ovmf_vars_dst)

    # Truncate per-session serial log
    Path(serial_log).parent.mkdir(parents=True, exist_ok=True)
    Path(serial_log).write_text("")

    # Canonical argv — see scripts/astryx_qemu.py for the single source of
    # truth. We ask for the `test` mode (1 GiB, CPU model chosen by host
    # KVM availability, virtio-blk-pci data disk) plus a QMP socket and
    # optional GDB stub. All launchers must go through this builder so
    # divergence like audit MED-2/3 cannot recreep back in.
    cmd = astryx_qemu.build_qemu_cmd(
        kernel_path="",
        data_img=str(DATA_IMG),
        serial_path=str(serial_log),
        mode="test",
        ovmf_code=str(OVMF_CODE),
        ovmf_vars=str(ovmf_vars_dst),
        esp_dir=str(ESP_DIR),
        qmp_sock=str(qmp_sock),
        qga_sock=str(qga_sock) if qga_sock else None,
        gdb_port=gdb_port if gdb_port and gdb_port > 0 else None,
        gdb_wait=gdb_wait,
        kvm=kvm,
        cpu_override=cpu_model,
        warn_on_missing_data_img=True,
    )

    # Override -smp count if caller asked for non-default. astryx_qemu.py
    # honours ASTRYX_SMP env on its own; here we patch the pre-built argv
    # so we don't have to mutate process env. Plan-C experiments use --smp 16
    # to stress-test Mozilla nsThreadPool sizing keyed off _SC_NPROCESSORS_ONLN.
    if smp != 2:
        for i, arg in enumerate(cmd):
            if arg == "-smp" and i + 1 < len(cmd):
                cmd[i + 1] = str(smp)
                break

    # Inject the kdb hostfwd rule by patching the `-netdev user,id=net0`
    # entry in-place.  Done here (rather than in `astryx_qemu.py`) to keep
    # the kdb feature self-contained — `build_qemu_cmd` stays unchanged.
    if kdb_host_port and kdb_host_port > 0:
        for i, arg in enumerate(cmd):
            if arg == "-netdev" and i + 1 < len(cmd) and cmd[i + 1].startswith("user,id=net0"):
                cmd[i + 1] = cmd[i + 1] + f",hostfwd=tcp:127.0.0.1:{kdb_host_port}-:9999"
                break

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
#
# Data-disk staleness detection (W7 silent-wedge guard)
#
# Pattern: agents stage updated runtime libraries / stubs under build/disk/
# (e.g. install-firefox-stubs.sh writes libglib-2.0.so.0 there) but forget
# to re-pack them into build/data.img via create-data-disk.sh --force.
# QEMU then boots with the OLD data.img — the guest sees the OLD libraries
# regardless of what's on the host. The failure mode is silent: no warning,
# tests behave as if the fix never landed, and verifiers mis-attribute the
# stall to whichever PR is currently under test.
#
# The check is timestamp-based: if any regular file under build/disk/ has an
# mtime newer than build/data.img, the image is stale and must be repacked.
# We bound the scan (max files / time budget) so a giant /opt/firefox tree
# can never wedge `start`.

# Soft cap on files scanned per staleness check. The full build/disk tree
# during firefox-test work has ~3000-5000 files; we don't need to look at
# every byte to detect staleness — finding *any* file newer than data.img
# is sufficient. We early-exit on the first newer file.
_STALENESS_SCAN_FILE_BUDGET = 20000
_STALENESS_SCAN_TIME_BUDGET_S = 4.0


def _data_img_staleness(data_img: Path, disk_dir: Path,
                         extra_src_dirs: "list[Path] | None" = None) -> dict:
    """
    Check whether `data_img` is older than any regular file under `disk_dir`
    OR under any directory in `extra_src_dirs`.

    `extra_src_dirs` is used to cover source files that compile into disk_dir
    artifacts (e.g. userspace/libfontconfig-interposer/interposer.c compiles
    to build/disk/lib64/libfontconfig-interposer.so). Without it, a source
    update that hasn't yet triggered a `make` produces a stale .so inside
    build/disk/ — older than data.img — so the mtime check falsely reports
    "not stale" and the old binary ships in the next boot image.

    Returns a dict with:
      stale: bool                 — True iff a newer file was found
      newest_path: Optional[str]  — first newer file (early-exit; not the global newest)
      newest_mtime: Optional[float]
      data_img_mtime: Optional[float]
      files_scanned: int
      scan_seconds: float
      error: Optional[str]        — set when the check could not run (soft-fail)

    The check is best-effort: any I/O error returns `stale=False` with `error`
    populated. Callers should treat `error` as "could not determine" — boot
    proceeds either way.
    """
    out = {
        "stale": False,
        "newest_path": None,
        "newest_mtime": None,
        "data_img_mtime": None,
        "files_scanned": 0,
        "scan_seconds": 0.0,
        "error": None,
    }
    try:
        if not data_img.exists():
            out["error"] = "data_img missing"
            return out
        if not disk_dir.exists() or not disk_dir.is_dir():
            out["error"] = f"disk_dir not present: {disk_dir}"
            return out
        di_mtime = data_img.stat().st_mtime
        out["data_img_mtime"] = di_mtime
        deadline = time.monotonic() + _STALENESS_SCAN_TIME_BUDGET_S
        scanned = 0
        t0 = time.monotonic()
        # os.scandir-based walk is meaningfully faster than Path.rglob on
        # the large /opt/firefox subtree (~3000 files). Stop scanning on
        # first hit — even one newer file is sufficient evidence.
        # Seed the stack with disk_dir first, then any extra source dirs.
        stack = [disk_dir]
        for d in (extra_src_dirs or []):
            if d.exists() and d.is_dir():
                stack.append(d)
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        # Budget guards: bail out cleanly if we've spent too
                        # much time or seen too many files. We prefer a
                        # false-negative (boot the stale image) over delaying
                        # the harness start by seconds.
                        if scanned >= _STALENESS_SCAN_FILE_BUDGET:
                            out["error"] = (
                                f"file-budget exhausted ({scanned} files)"
                            )
                            out["files_scanned"] = scanned
                            out["scan_seconds"] = time.monotonic() - t0
                            return out
                        if time.monotonic() > deadline:
                            out["error"] = (
                                f"time-budget exhausted "
                                f"({_STALENESS_SCAN_TIME_BUDGET_S:.1f}s)"
                            )
                            out["files_scanned"] = scanned
                            out["scan_seconds"] = time.monotonic() - t0
                            return out
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(Path(entry.path))
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            scanned += 1
                            st = entry.stat(follow_symlinks=False)
                            if st.st_mtime > di_mtime:
                                out["stale"] = True
                                out["newest_path"] = entry.path
                                out["newest_mtime"] = st.st_mtime
                                out["files_scanned"] = scanned
                                out["scan_seconds"] = time.monotonic() - t0
                                return out
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue
        out["files_scanned"] = scanned
        out["scan_seconds"] = time.monotonic() - t0
        return out
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out


def _regen_data_img(root_dir: Path) -> dict:
    """
    Invoke `scripts/create-data-disk.sh --force` and capture its outcome.

    Returns:
      ok: bool        — True iff the script exited 0
      rc: int
      duration_s: float
      tail: str       — last ~1500 chars of stderr (so a failure surfaces)

    The script logs to stdout (mixed with stderr by some sub-scripts); we
    fold both streams together and keep the tail for diagnostics.
    """
    script = root_dir / "scripts" / "create-data-disk.sh"
    out = {"ok": False, "rc": -1, "duration_s": 0.0, "tail": ""}
    if not script.exists():
        out["tail"] = f"create-data-disk.sh not found at {script}"
        return out
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            ["bash", str(script), "--force"],
            cwd=str(root_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=900,  # 15 min — generous; full Firefox copy is ~3 min
        )
        out["rc"] = proc.returncode
        out["ok"] = proc.returncode == 0
        merged = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        out["tail"] = merged[-1500:]
    except subprocess.TimeoutExpired as e:
        out["rc"] = -2
        out["tail"] = f"timeout after {e.timeout}s"
    except Exception as e:
        out["rc"] = -3
        out["tail"] = f"{type(e).__name__}: {e}"
    out["duration_s"] = time.monotonic() - t0
    return out


# ══════════════════════════════════════════════════════════════════════════════

def cmd_context(args):
    """
    Front-end for scripts/agent-context.py — shared session-context management.

    Delegates directly to agent-context.py with the supplied sub-subcommand and
    arguments.  Agents that already know to use qemu-harness.py can access the
    context layer through this single entry point without needing to remember a
    separate script path.

    Usage:
      python3 scripts/qemu-harness.py context read-current [--section S] [--json]
      python3 scripts/qemu-harness.py context summary
      python3 scripts/qemu-harness.py context register-dispatch --agent-id ID \\
                                                                 --role ROLE \\
                                                                 --task TASK
      python3 scripts/qemu-harness.py context register-completion --agent-id ID \\
                                                                   --outcome TEXT \\
                                                                   [--commits SHAs]\\
                                                                   [--pr #NNN]
      python3 scripts/qemu-harness.py context append-event KIND \\
                                                             --agent-id ID \\
                                                             --payload JSON
      python3 scripts/qemu-harness.py context digest-since TIMESTAMP
      python3 scripts/qemu-harness.py context prune-current [--max-lines N]
    """
    import subprocess as _sp
    agent_ctx = Path(__file__).parent / "agent-context.py"
    if not agent_ctx.exists():
        _out({"ok": False, "error": f"agent-context.py not found at {agent_ctx}"})
        return 1
    # Pass everything after "context" directly to the helper script.
    cmd = [sys.executable, str(agent_ctx)] + (args.context_args or [])
    result = _sp.run(cmd)
    return result.returncode


# ══════════════════════════════════════════════════════════════════════════════

def cmd_check(args):
    """
    Run `cargo +nightly check` against the kernel package and emit a JSON
    verdict.  No QEMU is launched.  Useful for sweeping feature-flag matrices
    after a code change.
    """
    rc, tail = _check(args.features or "")
    out = {
        "ok": rc == 0,
        "features": args.features or "",
        "rc": rc,
    }
    if rc != 0:
        out["stderr_tail"] = tail
    print(json.dumps(out, indent=2))
    return rc


def cmd_start(args):
    sid = uuid.uuid4().hex[:12]
    serial_log  = str(HARNESS_DIR / f"{sid}.serial.log")
    qmp_sock    = str(HARNESS_DIR / f"{sid}.qmp.sock")
    ovmf_vars   = str(HARNESS_DIR / f"{sid}.OVMF_VARS.fd")

    gdb_port = getattr(args, "gdb_port", 0) or 0
    gdb_wait = getattr(args, "gdb_wait", False)

    # Derive a per-session kdb host port when --features includes `kdb`.
    # We hash the sid into the 9990..10989 range — 1000 slots, collision
    # resolved by a linear-probe in the derivation itself (not bindable
    # ports are just forwarded; only the SLIRP side binds inside QEMU).
    features_str = (args.features or "")
    feats = [f.strip() for f in features_str.split(",")]
    kdb_host_port = 0
    if "kdb" in feats:
        # Derive deterministically from sid so reruns are stable and two
        # concurrent sessions almost certainly land on distinct ports.
        kdb_host_port = 9990 + (int(sid, 16) % 1000)

    # QGA transport (Phase QGA-1): when the kernel was built with the `qga`
    # feature, expose a virtio-serial port + matching host Unix socket so
    # the future userspace daemon (Phase QGA-2) has a path out to the host.
    qga_sock = ""
    if "qga" in feats:
        qga_sock = str(HARNESS_DIR / f"{sid}.qga.sock")

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

    # Snapshot the in-tree ESP into a session-scoped directory so concurrent
    # rebuilds from other workspaces cannot clobber the kernel binary this
    # session is running. See _freeze_session_esp() docstring for the bug
    # this fixes (W3 trials 4-5 / 2026-05-12 and W6 session 622bbe4ed14b).
    #
    # `--no-build` semantics: we freeze whatever is currently staged at the
    # in-tree ESP. If the user passed --no-build expecting to reuse a prior
    # session's exact binary, they should pass --reuse-esp <sid> in a future
    # extension; for now, --no-build + freeze means "use whatever the in-tree
    # ESP holds right now, then isolate it from further changes". This is
    # strictly safer than the prior behaviour (always race-prone).
    wt = _get_watch_test()
    try:
        esp_paths = _freeze_session_esp(sid, wt.ESP_DIR)
    except FileNotFoundError as e:
        _err(f"Cannot freeze ESP: {e}")

    # ── data.img presence check (W13/W15 silent-wedge guard) ─────────────────
    # Agent worktrees omit build/data.img (.gitignored). Without it, QEMU boots
    # without a /disk drive: firefox-test wedges at sc=0/pf=0 with no output,
    # causing verifiers to mis-attribute the stall to the PR under review.
    # Fix: (1) auto-symlink from the source-of-truth if reachable, (2) emit a
    # visible banner regardless so the operator always knows the state.
    _data_img_path = Path(wt.DATA_IMG)
    _data_img_missing = not _data_img_path.exists()
    if _data_img_missing:
        _CANONICAL_DATA_IMG = Path("/home/ubuntu/AstryxOS/build/data.img")
        if _CANONICAL_DATA_IMG.exists():
            _data_img_path.parent.mkdir(parents=True, exist_ok=True)
            _data_img_path.symlink_to(_CANONICAL_DATA_IMG)
            _data_img_missing = False
            print(
                "╔══════════════════════════════════════════════════════════════╗\n"
                "║  WARNING: data disk image auto-symlinked                     ║\n"
                f"║  {str(_data_img_path)[:60]:<60}  ║\n"
                f"║  -> {str(_CANONICAL_DATA_IMG)[:57]:<57}  ║\n"
                "║  (worktree lacked data.img; symlinked from repo build/)      ║\n"
                "╚══════════════════════════════════════════════════════════════╝",
                file=sys.stderr,
            )
        else:
            print(
                "╔══════════════════════════════════════════════════════════════╗\n"
                "║  WARNING: data disk image not found                          ║\n"
                f"║  expected: {str(_data_img_path)[:51]:<51}  ║\n"
                "║  firefox-test paths will fail; /disk will not mount.         ║\n"
                "║  Symlink from /home/ubuntu/AstryxOS/build/data.img to fix.   ║\n"
                "╚══════════════════════════════════════════════════════════════╝",
                file=sys.stderr,
            )

    # ── data.img staleness check (W7 silent-wedge guard) ─────────────────────
    # Pattern: `install-firefox-stubs.sh` (and other build helpers) writes
    # updated runtime libraries into build/disk/ but does NOT repack
    # build/data.img. Subsequent firefox-test runs boot the OLD image and
    # silently exercise the OLD stubs/libraries. The trap is invisible at
    # boot — symptoms only show up deep in the test run (e.g. glxtest
    # spinning on an unopened pipe fd, or an exec'd helper running the
    # last-decade version of libxul).
    #
    # We detect this by mtime: if any file under build/disk/ is newer than
    # data.img, the image is stale. Default action: auto-regenerate via
    # `scripts/create-data-disk.sh --force`. The user can opt out with
    # --no-regen-data-img, in which case we still emit a loud WARNING so
    # the next "why doesn't my fix work?" is one harness invocation away.
    #
    # Soft-fail throughout: any I/O or scan error → boot proceeds without
    # the auto-regen. We surface the situation through stderr + session
    # state, never through a hard exit.
    _data_img_stale = False
    _data_img_regenerated = False
    _data_img_staleness_info: dict = {}
    _data_img_regen_info: dict = {}
    _no_regen = bool(getattr(args, "no_regen_data_img", False))
    if not _data_img_missing:
        _disk_dir = Path(wt.ROOT) / "build" / "disk"
        # Extra source directories whose compiled outputs land in build/disk/.
        # A source file newer than its compiled artifact inside build/disk/ will
        # make the artifact appear older than data.img — the normal disk_dir scan
        # then falsely reports "not stale" even though a rebuild is needed.
        # Adding the source dirs here means ANY updated source file is enough to
        # trigger a create-data-disk.sh --force, which recompiles and repacks.
        _extra_src_dirs = [
            # interposer.c compiles to build/disk/lib64/libfontconfig-interposer.so
            Path(wt.ROOT) / "userspace" / "libfontconfig-interposer",
        ]
        _data_img_staleness_info = _data_img_staleness(
            _data_img_path, _disk_dir, extra_src_dirs=_extra_src_dirs)
        _data_img_stale = bool(_data_img_staleness_info.get("stale"))
    if _data_img_stale:
        _newest = _data_img_staleness_info.get("newest_path") or "?"
        _di_mt  = _data_img_staleness_info.get("data_img_mtime")
        _new_mt = _data_img_staleness_info.get("newest_mtime")
        try:
            _di_age = time.strftime("%Y-%m-%d %H:%M",
                                    time.localtime(_di_mt)) if _di_mt else "?"
            _ne_age = time.strftime("%Y-%m-%d %H:%M",
                                    time.localtime(_new_mt)) if _new_mt else "?"
        except Exception:
            _di_age, _ne_age = "?", "?"
        # `_newest` may be a long path — keep a short tail for the banner.
        _newest_short = _newest
        if len(_newest_short) > 56:
            _newest_short = "..." + _newest_short[-53:]
        print(
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║  WARNING: data disk image is STALE                           ║\n"
            f"║  data.img  mtime: {_di_age:<43}║\n"
            f"║  newer file:      {_newest_short:<43}║\n"
            f"║  newer mtime:     {_ne_age:<43}║\n"
            "║  (build/disk/ has updates not yet packed into data.img)      ║\n"
            "╚══════════════════════════════════════════════════════════════╝",
            file=sys.stderr,
        )
        if _no_regen:
            print(
                "║  --no-regen-data-img set; booting stale image as requested.  ║",
                file=sys.stderr,
            )
        else:
            print(
                "║  Auto-regenerating via scripts/create-data-disk.sh --force … ║",
                file=sys.stderr,
            )
            _data_img_regen_info = _regen_data_img(Path(wt.ROOT))
            _data_img_regenerated = bool(_data_img_regen_info.get("ok"))
            if _data_img_regenerated:
                # Re-scan; the regen should have updated data.img mtime so the
                # follow-up check is informational only.
                try:
                    _data_img_staleness_info = _data_img_staleness(
                        _data_img_path, _disk_dir,
                        extra_src_dirs=_extra_src_dirs)
                    _data_img_stale = bool(_data_img_staleness_info.get("stale"))
                except Exception:
                    pass
                _dur = _data_img_regen_info.get("duration_s", 0.0)
                print(
                    f"║  data.img regenerated in {_dur:.1f}s.                          ║",
                    file=sys.stderr,
                )
            else:
                _tail = (_data_img_regen_info.get("tail") or "")[-400:]
                print(
                    "║  REGEN FAILED — booting stale image; check stderr above.    ║\n"
                    f"║  rc={_data_img_regen_info.get('rc')}, tail: {_tail!r:<48}",
                    file=sys.stderr,
                )

    kvm_arg: Optional[bool]
    no_kvm_flag = bool(getattr(args, "no_kvm", False))
    force_kvm_flag = bool(getattr(args, "force_kvm", False))
    if no_kvm_flag:
        kvm_arg = False
        # W139 deprecation warning: --no-kvm degrades firefox-test fidelity.
        # Emit when /dev/kvm is present so agents and humans see the cost
        # of opting out. Suppressed on hosts without KVM (where TCG is the
        # only option and the flag is a no-op).
        if astryx_qemu._detect_kvm():
            print(
                "WARNING: --no-kvm passed but /dev/kvm is available. "
                "KVM disabled — firefox-test progresses 58% further under KVM "
                "per W139 soak (2026-05-13): sc +58%, quit-application-granted "
                "3/5 KVM vs 0/5 TCG. Remove --no-kvm unless reproducing a "
                "TCG-specific regression.",
                file=sys.stderr,
            )
    elif force_kvm_flag:
        kvm_arg = True
    else:
        kvm_arg = None  # autodetect
    smp = int(getattr(args, "smp", 2) or 2)
    cpu_model = getattr(args, "cpu_model", None)

    # Resolve effective KVM state + CPU model up-front so we can log the
    # decision (W106: catches "TCG run with -cpu host advertising AVX-512
    # → glibc IFUNC trap → spurious #UD" misconfiguration before launch).
    kvm_effective = (
        kvm_arg if kvm_arg is not None else astryx_qemu._detect_kvm()
    )
    cpu_model_resolved, cpu_model_reason = astryx_qemu.cpu_model_for(
        mode="test", kvm=kvm_effective, cpu_override=cpu_model,
    )
    kvm_available = astryx_qemu._detect_kvm()
    print(
        f"[harness] cpu_model={cpu_model_resolved} reason={cpu_model_reason} "
        f"(kvm_available={kvm_available}, no_kvm_flag={no_kvm_flag}, "
        f"force_kvm_flag={force_kvm_flag})",
        file=sys.stderr,
    )

    proc = _launch_qemu_harness(sid, serial_log, qmp_sock, ovmf_vars,
                                 gdb_port=gdb_port, gdb_wait=gdb_wait,
                                 kdb_host_port=kdb_host_port,
                                 kvm=kvm_arg,
                                 smp=smp,
                                 cpu_model=cpu_model,
                                 esp_dir_override=esp_paths["session_esp_dir"],
                                 qga_sock=qga_sock)

    session = {
        "sid":        sid,
        "pid":        proc.pid,
        "serial_log": serial_log,
        "qmp_sock":   qmp_sock,
        "qga_sock":   qga_sock,
        "ovmf_vars":  ovmf_vars,
        "started_at": time.time(),
        "features":   args.features or "",
        "gdb_port":   gdb_port,
        "gdb_wait":   gdb_wait,
        "kdb_host_port": kdb_host_port,
        "smp":         smp,
        "cpu_model":   cpu_model or "default",
        # W106: capture the resolved CPU model + reason so post-hoc
        # investigations can tell whether a run was on `-cpu host` (KVM
        # fidelity path) or the TCG-safe baseline. Additive — never
        # rename these keys without updating downstream agents.
        "cpu_model_resolved": cpu_model_resolved,
        "cpu_model_reason":   cpu_model_reason,
        "kvm_available":      kvm_available,
        "kvm_effective":      bool(kvm_effective),
        "no_kvm_flag":        no_kvm_flag,
        "force_kvm_flag":     force_kvm_flag,
        "breakpoints": [],
        # True when data.img was absent at session start (after any auto-symlink
        # attempt). Agents inspecting this field can immediately distinguish a
        # firefox-test wedge caused by missing /disk from a real regression.
        "data_img_missing": _data_img_missing,
        # True iff a file under build/disk/ was newer than data.img at session
        # start. When `data_img_regenerated` is also True, the image was
        # rebuilt before launch and the stale flag describes the pre-launch
        # state. When `data_img_regenerated` is False, the boot ran against
        # the stale image (either --no-regen-data-img was set or the regen
        # script failed — see `data_img_regen_tail`).
        "data_img_stale": _data_img_stale,
        "data_img_regenerated": _data_img_regenerated,
        "data_img_staleness_info": _data_img_staleness_info,
        "data_img_regen_info": _data_img_regen_info,
        # Session-scoped kernel binary (concurrent-rebuild clobber fix).
        # NOTE: snapshot files saved via `qemu-harness.py snap save` are tied
        # to the kernel binary loaded at the time. Loading a snapshot in a
        # *different* session that froze a different kernel will fail or
        # misbehave — snapshots are kernel-version-specific.
        **esp_paths,
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

    # W106: record the CPU-model decision in the event stream so a single
    # `events <sid>` invocation reveals whether the run was on KVM fidelity
    # or the TCG-safe baseline. Investigations of "spurious #UD" / SIGSEGV
    # clusters check this first.
    _emit_event(sid, {
        "kind": "cpu_model",
        "model": cpu_model_resolved,
        "reason": cpu_model_reason,
        "kvm_available": kvm_available,
        "kvm_effective": bool(kvm_effective),
        "no_kvm_flag": no_kvm_flag,
        "force_kvm_flag": force_kvm_flag,
        "cpu_override": cpu_model,
    })

    _out({"sid": sid, "pid": proc.pid, "serial_log": serial_log,
          "gdb_port": gdb_port, "kdb_host_port": kdb_host_port,
          # W106: structured CPU-model fields. `cpu_model_resolved` is
          # the literal string passed to QEMU `-cpu`; `cpu_model_reason`
          # is one of "override" | "kvm-host" | "tcg-safe".
          "cpu_model_resolved": cpu_model_resolved,
          "cpu_model_reason":   cpu_model_reason,
          "kvm_available":      kvm_available,
          "kvm_effective":      bool(kvm_effective),
          # True when data.img was absent (even after auto-symlink attempt).
          # Agents should treat this as a hard warning for firefox-test runs.
          "data_img_missing": _data_img_missing,
          # True iff build/disk/ had files newer than data.img at session
          # start. False after a successful auto-regen (the post-regen value
          # is stored — pre-regen state is in `data_img_staleness_info`).
          "data_img_stale": _data_img_stale,
          # True iff the harness auto-ran create-data-disk.sh --force this
          # session. False when not needed, when --no-regen-data-img was set,
          # or when the regen script failed (check `data_img_regen_info`).
          "data_img_regenerated": _data_img_regenerated,
          # Per-session QGA UNIX chardev socket path. Empty string when the
          # session was started without --features qga; non-empty paths may
          # not yet exist on disk if QEMU hasn't bound the socket yet
          # (the qga-* subcommands report `socket missing` until then).
          "qga_sock_path": qga_sock,
          # Session-scoped kernel binary path (additive field — agents that
          # want to verify the running binary's SHA against a known-good
          # reference can read this directly).
          "session_kernel_path": esp_paths["session_kernel_path"]})


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
    # Clean up QGA socket (Phase QGA-1)
    qga_sock = sess.get("qga_sock", "")
    if qga_sock and Path(qga_sock).exists():
        try:
            Path(qga_sock).unlink()
        except OSError:
            pass

    # Clean up session-scoped ESP directory (10-20 MB per session). Tolerant
    # of legacy sessions that pre-date the freeze feature and have no
    # `session_esp_dir` field.
    sess_esp = sess.get("session_esp_dir", "")
    if sess_esp and Path(sess_esp).exists():
        shutil.rmtree(sess_esp, ignore_errors=True)

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
    """
    Return the last N bytes of the serial log without materialising the full
    file. Serial logs can grow into the multi-MB range during a long run; a
    naive `readlines()` then slice allocates the whole file. Instead we seek
    to `max(0, size - window)` (the window is `max_bytes` with a small
    multiplier so `--since LINE` has enough context to bite) and stream
    forward, splitting on `\n` as we go.
    """
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]
    max_bytes  = args.bytes
    since_line = args.since

    path = Path(serial_log)
    try:
        total_size = path.stat().st_size
    except OSError:
        _out({"lines": [], "total_lines": 0, "returned": 0})
        return

    # If `--since LINE` is set, we need to count lines from the start of
    # the file (there is no cheap way to map a line number to a byte
    # offset without a persistent index). We stream the file in 64 KiB
    # chunks and split on newlines, keeping only a rolling window of the
    # most recent lines — bounded by both the line count (post-`since`)
    # and the byte budget.
    result_lines = []
    total_lines  = 0
    # Byte budget for the "keep the tail" window. When `--since` is set
    # we may need to keep many lines, so we don't cap by bytes in that
    # branch; without `--since`, the byte cap bounds memory directly.
    CHUNK = 64 * 1024

    try:
        if since_line is None:
            # Pure tail path — seek backwards to an offset that is
            # guaranteed to cover `max_bytes` worth of data, then
            # forward-stream from there. This avoids reading byte 0.
            seek_to = max(0, total_size - max_bytes * 2 - CHUNK)
            with path.open("rb") as fh:
                # Count total newlines with a forward scan that never
                # holds more than CHUNK bytes in memory. We do this in
                # a single streaming pass from byte 0 to EOF.
                fh.seek(0)
                while True:
                    chunk = fh.read(CHUNK)
                    if not chunk:
                        break
                    total_lines += chunk.count(b"\n")
                # Now stream from seek_to onwards for the actual tail window.
                fh.seek(seek_to)
                remainder = fh.read()  # bounded by max_bytes * 2 + CHUNK
                # If we seeked past byte 0, the first (possibly partial)
                # line is incomplete. Drop it so we only emit whole lines.
                if seek_to > 0:
                    nl = remainder.find(b"\n")
                    if nl >= 0:
                        remainder = remainder[nl+1:]
            text_lines = remainder.decode("utf-8", errors="replace").splitlines()
        else:
            # --since LINE: stream the whole file once, keep lines >= since_line.
            text_lines = []
            with path.open("rb") as fh:
                buf = b""
                while True:
                    chunk = fh.read(CHUNK)
                    if not chunk:
                        if buf:
                            total_lines += 1
                            if total_lines - 1 >= since_line:
                                text_lines.append(buf.decode("utf-8", errors="replace"))
                        break
                    buf += chunk
                    while True:
                        nl = buf.find(b"\n")
                        if nl < 0:
                            break
                        line = buf[:nl]
                        buf = buf[nl+1:]
                        total_lines += 1
                        if total_lines - 1 >= since_line:
                            text_lines.append(line.decode("utf-8", errors="replace"))
    except OSError:
        _out({"lines": [], "total_lines": 0, "returned": 0})
        return

    # Apply the byte cap from the back.
    result = []
    acc = 0
    for ln in reversed(text_lines):
        enc_len = len(ln.encode("utf-8", errors="replace")) + 1  # + newline
        if acc + enc_len > max_bytes:
            break
        result.append(ln)
        acc += enc_len
    result.reverse()

    _out({
        "lines":       result,
        "total_lines": total_lines,
        "returned":    len(result),
    })


def _classify_exit_cause(serial_log: str, running: bool) -> str:
    """
    Walk the serial log tail and classify why (or whether) QEMU stopped.

    Priority — first match wins:
      1. `BUGCHECK 0xNNNN` → `bugcheck:0xNNNN`
      2. `SCHEDULER_DEADLOCK` → `scheduler_deadlock`
      3. `PANIC:` / `panicked at` → `panic`
      4. `[FFTEST] DONE` → `firefox_exited_clean`
      5. `[FFTEST] Firefox exited after N ticks` → `firefox_exited:ticks=N`
      6. Still running (process alive) → `running`
      7. Nothing of the above → `unknown_exit`

    We read only the last ~256 KiB of the log; the causal marker is always
    near the end. Reading from the tail keeps latency O(1) regardless of
    log size.
    """
    if running:
        return "running"
    try:
        with Path(serial_log).open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 256 * 1024), 0)
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return "unknown_exit"

    m = re.search(r"BUGCHECK\s+0x([0-9a-fA-F]+)", tail)
    if m:
        return f"bugcheck:0x{m.group(1).lower()}"
    if re.search(r"SCHEDULER_DEADLOCK", tail):
        return "scheduler_deadlock"
    if re.search(r"PANIC:|panicked at", tail):
        return "panic"
    if re.search(r"\[FFTEST\]\s+DONE", tail):
        return "firefox_exited_clean"
    m = re.search(r"\[FFTEST\]\s+Firefox exited after\s+(\d+)\s+ticks", tail)
    if m:
        return f"firefox_exited:ticks={m.group(1)}"
    return "unknown_exit"


def cmd_status(args):
    sid = args.sid
    p   = _session_path(sid)
    if not p.exists():
        _out({"running": False, "sid": sid, "exit_cause": "no_session"})
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

    exit_cause = _classify_exit_cause(sess["serial_log"], alive)

    _out({
        "running":         alive,
        "sid":             sid,
        "pid":             pid,
        "serial_log_size": serial_size,
        "uptime_s":        round(uptime, 1),
        "features":        sess.get("features"),
        "exit_cause":      exit_cause,
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
    """
    Tail an events file indefinitely, printing each new line as JSON.

    Uses `select.select` on the underlying file descriptor for zero-latency
    wake-up when new data arrives, with a 5-second periodic fallback so we
    still notice rotations or unlinks. The previous implementation used a
    500 ms poll which delayed event delivery for agent callers.
    """
    import select

    # Wait briefly for the file to appear if it doesn't yet exist.
    for _ in range(50):
        if ep.exists():
            break
        time.sleep(0.1)
    if not ep.exists():
        return

    try:
        fh = ep.open("r")
    except OSError:
        return

    # Start at EOF so we only emit *new* events.
    fh.seek(0, 2)  # SEEK_END

    try:
        while True:
            # select() on a regular file always returns immediately "readable".
            # That's fine — the loop below will read any available new data
            # and fall through to select() again. When no new data is ready,
            # readline() returns "" and we block on select() with the 5 s
            # periodic fallback.
            line = fh.readline()
            if line:
                stripped = line.strip()
                if stripped:
                    print(stripped, flush=True)
                continue

            # No new data — wait up to 5 s for more, honouring KeyboardInterrupt.
            try:
                select.select([fh], [], [], 5.0)
            except (OSError, ValueError):
                # fd closed under us; exit cleanly.
                return
    except KeyboardInterrupt:
        pass
    finally:
        try:
            fh.close()
        except OSError:
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


# ══════════════════════════════════════════════════════════════════════════════
# Tier 2 subcommand implementations
# ══════════════════════════════════════════════════════════════════════════════

def cmd_regs(args):
    """Connect to GDB stub, read all GPRs, return as JSON dict."""
    sess = _load_session(args.sid)
    port = _get_gdb_port(sess)

    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        _err(f"Cannot connect to GDB stub on port {port} (tried {port}..{port+4})")
    try:
        regs = gdb.read_regs()
    except Exception as e:
        _err(f"GDB regs error: {e}")
    finally:
        gdb.close()

    _out({"ok": True, "regs": regs})


def cmd_mem(args):
    """Read memory via GDB 'm addr,len' packet; cap at 4096 bytes."""
    sess = _load_session(args.sid)
    port = _get_gdb_port(sess)

    try:
        addr = int(args.addr, 0)
    except ValueError:
        _err(f"Invalid address: {args.addr}")

    length = min(args.length, 4096)  # protect agent context

    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        _err(f"Cannot connect to GDB stub on port {port} (tried {port}..{port+4})")
    try:
        data = gdb.read_mem(addr, length)
    except Exception as e:
        _err(f"GDB mem error: {e}")
    finally:
        gdb.close()

    _out({
        "ok":    True,
        "addr":  hex(addr),
        "bytes": data.hex(),
        "len":   len(data),
    })


def cmd_sym(args):
    """Resolve a kernel symbol name from the ELF; no GDB needed."""
    elf = _get_kernel_elf()
    result = _resolve_symbol(elf, args.name)
    if result is None:
        _out({"ok": False, "error": f"Symbol '{args.name}' not found in {elf}"})
    else:
        result["ok"] = True
        result["name"] = args.name
        _out(result)


def cmd_bp(args):
    """Breakpoint management: add / del / list."""
    sess = _load_session(args.sid)
    op   = args.op

    if op == "list":
        bps = sess.get("breakpoints", [])
        _out({"ok": True, "breakpoints": bps})
        return

    port = _get_gdb_port(sess)

    try:
        addr = int(args.addr, 0)
    except (ValueError, TypeError):
        _err(f"Invalid address: {getattr(args, 'addr', None)}")

    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        _err(f"Cannot connect to GDB stub on port {port} (tried {port}..{port+4})")
    try:
        if op == "add":
            ok = gdb.set_bp(addr)
            if ok:
                bps = sess.get("breakpoints", [])
                hex_addr = hex(addr)
                if hex_addr not in bps:
                    bps.append(hex_addr)
                sess["breakpoints"] = bps
                _save_session(sess)
        elif op == "del":
            ok = gdb.del_bp(addr)
            if ok:
                bps = sess.get("breakpoints", [])
                hex_addr = hex(addr)
                sess["breakpoints"] = [b for b in bps if b != hex_addr]
                _save_session(sess)
        else:
            _err(f"Unknown bp op: {op}")
    except Exception as e:
        _err(f"GDB bp error: {e}")
    finally:
        gdb.close()

    _out({"ok": ok, "op": op, "addr": hex(addr)})


def cmd_step(args):
    """Single-step via GDB vCont;s. Returns new RIP."""
    sess = _load_session(args.sid)
    port = _get_gdb_port(sess)

    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        _err(f"Cannot connect to GDB stub on port {port} (tried {port}..{port+4})")
    try:
        stop_reply = gdb.vcont_step()
        # After stepping, read new RIP
        regs = gdb.read_regs()
        rip  = regs.get("rip", "0x0")
    except Exception as e:
        _err(f"GDB step error: {e}")
    finally:
        gdb.close()

    _out({"ok": True, "stop_reply": stop_reply, "rip": rip})


def cmd_cont(args):
    """Continue execution via GDB vCont;c. Returns immediately."""
    sess = _load_session(args.sid)
    port = _get_gdb_port(sess)

    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        _err(f"Cannot connect to GDB stub on port {port} (tried {port}..{port+4})")
    try:
        resp = gdb.vcont_cont()
    except Exception as e:
        # vCont;c sends the packet but the reply may not arrive immediately
        # (the kernel is running). Treat a timeout/connection-reset as normal.
        resp = f"<running: {e}>"
    finally:
        gdb.close()

    _out({"ok": True, "note": "kernel running", "reply": resp})


def cmd_pause(args):
    """Pause QEMU via QMP 'stop'. Freezes all vCPUs."""
    sess     = _load_session(args.sid)
    qmp_sock = sess["qmp_sock"]

    result = _qmp_command(qmp_sock, "stop", connect_timeout=3.0)
    if "error" in result:
        _out({"ok": False, "qmp_error": result["error"]})
    else:
        _out({"ok": True, "note": "QEMU paused"})


def cmd_resume(args):
    """Resume QEMU via QMP 'cont'. Unfreezes all vCPUs."""
    sess     = _load_session(args.sid)
    qmp_sock = sess["qmp_sock"]

    result = _qmp_command(qmp_sock, "cont", connect_timeout=3.0)
    if "error" in result:
        _out({"ok": False, "qmp_error": result["error"]})
    else:
        _out({"ok": True, "note": "QEMU resumed"})


# ══════════════════════════════════════════════════════════════════════════════
# Tier 1: kdb — one-shot JSON introspection TCP client
# ══════════════════════════════════════════════════════════════════════════════
#
# Non-interactive contract: open → send one JSON request → read one JSON
# response → close.  Session-side state mirrored to
# ~/.astryx-harness/<sid>.kdb.json so repeat callers see the last
# response per op without another round-trip.

def _kdb_build_request(op: str, rest: list[str]) -> dict:
    """CLI args → request dict.  Each op has its own arg shape.

    Argparse claims `--foo` tokens for itself so optional flags here are
    accepted *positionally* (after `--`) only:
      proc-tree     [<root_pid>]                       (default 1)
      fd-table      <pid>
      syscall-trend [<seconds> [<pid>]]                (defaults: 5 0)

    Examples:
        qemu-harness.py kdb <sid> proc-tree 0
        qemu-harness.py kdb <sid> fd-table 6
        qemu-harness.py kdb <sid> syscall-trend 10 4
    """
    if op in ("ping", "proc-list", "vfs-mounts", "trace-status", "bell-stats"):
        return {"op": op}
    if op == "proc":
        if not rest: raise ValueError("proc requires <pid>")
        return {"op": "proc", "pid": int(rest[0], 0)}
    if op == "proc-tree":
        pid = int(rest[0], 0) if rest else 1
        return {"op": "proc-tree", "pid": pid}
    if op == "fd-table":
        if not rest: raise ValueError("fd-table requires <pid>")
        return {"op": "fd-table", "pid": int(rest[0], 0)}
    if op == "fd-map":
        pid = int(rest[0], 0) if rest else 0  # 0 = all processes
        req: dict = {"op": "fd-map"}
        if pid != 0:
            req["pid"] = pid
        return req
    if op == "syscall-trend":
        seconds = int(rest[0], 0) if len(rest) >= 1 else 5
        pid     = int(rest[1], 0) if len(rest) >= 2 else 0
        return {"op": "syscall-trend", "seconds": seconds, "pid": pid}
    if op == "dmesg":
        return {"op": "dmesg", "tail": int(rest[0]) if rest else 100}
    if op == "syms":
        if not rest: raise ValueError("syms requires <name> or 0x<addr>")
        key = "addr" if rest[0].lower().startswith("0x") else "name"
        return {"op": "syms", key: rest[0]}
    if op == "mem":
        if len(rest) < 2: raise ValueError("mem requires <addr> <len>")
        return {"op": "mem", "addr": rest[0], "len": int(rest[1], 0)}
    if op == "tframe":
        if len(rest) < 2: raise ValueError("tframe requires <pid> <tid>")
        return {"op": "tframe", "pid": int(rest[0], 0), "tid": int(rest[1], 0)}
    if op == "user-mem":
        if len(rest) < 3: raise ValueError("user-mem requires <pid> <addr> <len>")
        return {"op": "user-mem", "pid": int(rest[0], 0),
                "addr": rest[1], "len": int(rest[2], 0)}
    raise ValueError(f"unknown kdb op: {op}")


def _kdb_recv(port: int, req: dict, timeout: float = 5.0) -> bytes:
    """Send one JSON kdb request, return the raw response bytes."""
    payload = (json.dumps(req) + "\n").encode("utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(payload)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk: break
            buf += chunk
            if len(buf) > 128 * 1024: break
    finally:
        s.close()
    return buf


def _kdb_call(port: int, req: dict, timeout: float = 5.0) -> dict:
    """One-shot kdb call.  Connects, sends one JSON line, reads one line back,
    closes.  Returns the parsed response.  For diagnostic access to the raw
    bytes (e.g. to surface them in a malformed-response error), use
    `_kdb_recv` and `json.loads` separately."""
    return json.loads(_kdb_recv(port, req, timeout).strip().decode("utf-8", errors="replace"))


def cmd_kdb(args):
    """One-shot kdb client: connect, send, receive one line, close."""
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)
    try:
        req = _kdb_build_request(args.op, list(args.args or []))
    except ValueError as e:
        _out({"error": str(e)}); sys.exit(1)

    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    try:
        raw = _kdb_recv(port, req, timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        _out({"error": f"kdb connect/io failed on 127.0.0.1:{port}: {e}"})
        sys.exit(1)
    try:
        resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError) as e:
        _out({"error": f"malformed response: {e}",
              "raw": raw.decode(errors="replace")})
        sys.exit(1)

    # Mirror to ~/.astryx-harness/<sid>.kdb.json (best-effort).
    cache = HARNESS_DIR / f"{args.sid}.kdb.json"
    state = {"operations_called": 0, "last_response": {}}
    if cache.exists():
        try: state = json.loads(cache.read_text())
        except Exception: pass
    state["port"] = port
    state["last_ping_unix"] = int(time.time())
    state["operations_called"] = int(state.get("operations_called", 0)) + 1
    state.setdefault("last_response", {})[args.op] = resp
    try: cache.write_text(json.dumps(state))
    except OSError: pass

    _out(resp)


# ══════════════════════════════════════════════════════════════════════════════
# fd-map — cross-process FD map with socketpair peer resolution (W216)
# ══════════════════════════════════════════════════════════════════════════════
#
# Wraps `kdb fd-map` with two additional capabilities:
#   --save <name>  Persist the snapshot to ~/.astryx-harness/<sid>.fdmap.<name>.json
#   --diff <name>  Compare the current snapshot with a previously saved one and
#                  print the diff as JSON.  Useful for differentiating:
#     Hypothesis A (FD routing bug): PID-1 fd=70 peer resolves to a DIFFERENT
#                  (pid, fd) than the one PID-4 writes its fd=27 to.
#     Hypothesis B (kernel wake bug): peer is correct but poll never fires.

def cmd_fd_map(args):
    """Cross-process FD map with socketpair/pipe peer resolution.

    Calls kdb op 'fd-map' and returns structured JSON.  Each entry is:
      { pid, fd, kind, socket_id, peer_socket_id, peer_pid, peer_fd }   (socket)
      { pid, fd, kind, pipe_id, pipe_end, peer_pid, peer_fd }           (pipe)

    Optionally saves or diffs snapshots to differentiate IPC routing bugs.
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)

    pid = getattr(args, "pid", 0) or 0
    req: dict = {"op": "fd-map"}
    if pid:
        req["pid"] = pid

    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    try:
        raw = _kdb_recv(port, req, timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        _out({"error": f"kdb connect failed on 127.0.0.1:{port}: {e}"})
        sys.exit(1)
    try:
        resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError) as e:
        _out({"error": f"malformed kdb response: {e}",
              "raw": raw.decode(errors="replace")})
        sys.exit(1)

    snap_name = getattr(args, "save", None)
    diff_name = getattr(args, "diff", None)

    if snap_name:
        path = HARNESS_DIR / f"{args.sid}.fdmap.{snap_name}.json"
        try:
            path.write_text(json.dumps(resp))
            resp["_saved"] = str(path)
        except OSError as e:
            resp["_save_error"] = str(e)

    if diff_name:
        path = HARNESS_DIR / f"{args.sid}.fdmap.{diff_name}.json"
        if not path.exists():
            _out({"error": f"no saved snapshot '{diff_name}' at {path}"})
            sys.exit(1)
        try:
            prev = json.loads(path.read_text())
        except Exception as e:
            _out({"error": f"could not load snapshot '{diff_name}': {e}"})
            sys.exit(1)

        def _entry_key(e: dict) -> str:
            return f"{e.get('pid')}/{e.get('fd')}"

        prev_map = {_entry_key(e): e for e in prev.get("entries", [])}
        curr_map = {_entry_key(e): e for e in resp.get("entries", [])}

        added   = [curr_map[k] for k in curr_map if k not in prev_map]
        removed = [prev_map[k] for k in prev_map if k not in curr_map]
        changed = []
        for k in curr_map:
            if k in prev_map and curr_map[k] != prev_map[k]:
                changed.append({"key": k, "before": prev_map[k], "after": curr_map[k]})

        resp = {
            "diff_against": diff_name,
            "added":   added,
            "removed": removed,
            "changed": changed,
            "snapshot": resp,
        }

    _out(resp)


# ══════════════════════════════════════════════════════════════════════════════
# QGA (QEMU Guest Agent) subcommands — one-shot calls into the in-guest daemon
# ══════════════════════════════════════════════════════════════════════════════
#
# These commands speak qemu-guest-agent-compatible NDJSON over the UNIX-domain
# chardev socket QEMU exposes on the host side of the virtio-serial port. The
# socket path is per-session: ~/.astryx-harness/<sid>.qga.sock, recorded as
# `qga_sock` in the session JSON. Each invocation here opens the socket, sends
# one request, reads one reply, closes. See `scripts/qga_client.py` for the
# wire helper that takes care of framing, timeouts, and the `0xff` stale-data
# delimiter quirk (sync-delimited path; documented at
# https://wiki.qemu.org/Features/GuestAgent).
#
# The session must have been started with `--features qga` (or a feature set
# that pulls it in) for the daemon to spawn and the host socket to bind. When
# the socket is absent, the wrappers return a structured `connect failed`
# error rather than raising.

# qga_client lives next to this file — already imported above via the sys.path
# manipulation that pulled in astryx_qemu.
import qga_client  # noqa: E402


def _qga_sock_or_err(sess: dict) -> str:
    """
    Resolve the QGA socket path from a session dict.

    Returns the path string; if the session was not started with QGA
    enabled, prints a structured error and exits non-zero. Callers can
    therefore treat the return value as a guaranteed non-empty path.
    """
    sock = (sess.get("qga_sock") or "").strip()
    if not sock:
        _out({
            "ok": False,
            "error": "session was not started with --features qga "
                     "(no qga_sock in session JSON)",
        })
        sys.exit(2)
    return sock


def cmd_qga_ping(args):
    """guest-ping — round-trip latency probe."""
    sess = _load_session(args.sid)
    sock = _qga_sock_or_err(sess)
    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    res = qga_client.qga_ping(sock, timeout=timeout)
    # Project the qga_client structured result onto the harness contract:
    #   {"ok": bool, "latency_ms": int, "error"?: str, "response"?: ...}
    out = {"ok": bool(res.get("ok")), "latency_ms": int(res.get("latency_ms", 0))}
    if not res.get("ok"):
        out["error"] = res.get("error", "unknown error")
        if "raw" in res:
            out["raw"] = res["raw"]
    else:
        out["response"] = res.get("response")
    _out(out)
    sys.exit(0 if out["ok"] else 2)


def cmd_qga_info(args):
    """guest-info — daemon version + supported-commands list."""
    sess = _load_session(args.sid)
    sock = _qga_sock_or_err(sess)
    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    res = qga_client.qga_info(sock, timeout=timeout)
    out = {"ok": bool(res.get("ok")), "latency_ms": int(res.get("latency_ms", 0))}
    if not res.get("ok"):
        out["error"] = res.get("error", "unknown error")
        if "raw" in res:
            out["raw"] = res["raw"]
    else:
        # Surface the daemon's `return` payload at the top level so agents
        # can read `version` / `supported_commands` without descending into
        # the QGA envelope.
        resp = res.get("response") or {}
        ret = resp.get("return") if isinstance(resp, dict) else None
        out["response"] = resp
        if isinstance(ret, dict):
            out["return"] = ret
    _out(out)
    sys.exit(0 if out["ok"] else 2)


def cmd_qga_sync(args):
    """guest-sync — verify the daemon round-trip ID matches.

    Useful as a liveness probe before any other QGA call; the daemon
    echoes the supplied integer, so a mismatch flags a stale or mis-
    framed reply (e.g. a crash-restart between calls). Default id is
    a random 31-bit positive integer to keep concurrent callers
    independent; pass --id to pin a specific value (handy in tests
    that compare on exact JSON output).
    """
    sess = _load_session(args.sid)
    sock = _qga_sock_or_err(sess)
    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    sync_id = getattr(args, "id", None)
    res = qga_client.qga_sync(sock, timeout=timeout, sync_id=sync_id)
    out = {
        "ok": bool(res.get("ok")),
        "latency_ms": int(res.get("latency_ms", 0)),
        "id": res.get("id"),
    }
    if not res.get("ok"):
        out["error"] = res.get("error", "unknown error")
        if "raw" in res:
            out["raw"] = res["raw"]
    else:
        out["response"] = res.get("response")
    _out(out)
    sys.exit(0 if out["ok"] else 2)


def cmd_qga_file_read(args):
    """guest-file-open → guest-file-read → guest-file-close in one call.

    Returns:
        On success: {"ok":true,"bytes_b64":"...","len":N,"path":...}
        On any failure: {"ok":false,"error":"...","stage":"open|read|close"}

    The `stage` field identifies which underlying QGA call failed, so a
    caller can distinguish "file not found" (open) from "guest read
    error" (read). The close step is best-effort: if open+read both
    succeeded but close failed, we still return ok=true and surface the
    close diagnostic under `close_error`.
    """
    sess = _load_session(args.sid)
    sock = _qga_sock_or_err(sess)
    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    path = args.path
    # Cap at 4 KiB by default — matches the daemon's MAX_READ_CHUNK so a
    # caller asking for more wouldn't get more anyway. Larger reads would
    # need iterated guest-file-read calls (out of scope for QGA-3).
    max_bytes = int(getattr(args, "max_bytes", 4096) or 4096)
    if max_bytes <= 0:
        _out({"ok": False, "error": "max-bytes must be positive", "stage": "args"})
        sys.exit(2)
    if max_bytes > 4096:
        max_bytes = 4096

    # ── open ────────────────────────────────────────────────────────────────
    open_res = qga_client.qga_file_open(sock, path, mode="r", timeout=timeout)
    if not open_res.get("ok"):
        out = {
            "ok": False,
            "stage": "open",
            "error": open_res.get("error", "open failed"),
            "path": path,
            "latency_ms": int(open_res.get("latency_ms", 0)),
        }
        if "raw" in open_res:
            out["raw"] = open_res["raw"]
        _out(out)
        sys.exit(2)

    handle_raw = (open_res.get("response") or {}).get("return")
    try:
        handle = int(handle_raw)
    except (TypeError, ValueError):
        _out({
            "ok": False,
            "stage": "open",
            "error": f"daemon returned non-integer handle: {handle_raw!r}",
            "path": path,
        })
        sys.exit(2)

    # ── read ────────────────────────────────────────────────────────────────
    read_res = qga_client.qga_file_read(sock, handle, max_bytes, timeout=timeout)
    if not read_res.get("ok"):
        # Best-effort close, then report the read failure.
        qga_client.qga_file_close(sock, handle, timeout=timeout)
        out = {
            "ok": False,
            "stage": "read",
            "error": read_res.get("error", "read failed"),
            "path": path,
            "handle": handle,
            "latency_ms": int(read_res.get("latency_ms", 0)),
        }
        if "raw" in read_res:
            out["raw"] = read_res["raw"]
        _out(out)
        sys.exit(2)

    ret = (read_res.get("response") or {}).get("return") or {}
    bytes_b64 = ret.get("buf-b64") or ""
    length = int(ret.get("count") or 0)

    # ── close ───────────────────────────────────────────────────────────────
    close_res = qga_client.qga_file_close(sock, handle, timeout=timeout)

    out = {
        "ok": True,
        "path": path,
        "handle": handle,
        "bytes_b64": bytes_b64,
        "len": length,
        "latency_ms": int(read_res.get("latency_ms", 0)),
    }
    if not close_res.get("ok"):
        out["close_error"] = close_res.get("error", "close failed")
    _out(out)
    sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# QMP-based register / memory introspection (does not require kdb hostfwd)
# ══════════════════════════════════════════════════════════════════════════════
#
# These subcommands drive QEMU's QMP `human-monitor-command` to capture the
# current architectural state of every vCPU and read guest memory through the
# active CR3 page table. They are the fallback when kdb's slirp hostfwd is
# unreliable (a recurring WSL2 + slirp issue) and they work even when no GDB
# stub has been configured.

_RE_QMP_RIP = re.compile(r"^RIP=([0-9a-fA-F]+)\s+RFL=", re.MULTILINE)
_RE_QMP_RAX = re.compile(r"^RAX=([0-9a-fA-F]+)\s+RBX=([0-9a-fA-F]+)\s+RCX=([0-9a-fA-F]+)\s+RDX=([0-9a-fA-F]+)", re.MULTILINE)
_RE_QMP_RSI = re.compile(r"^RSI=([0-9a-fA-F]+)\s+RDI=([0-9a-fA-F]+)\s+RBP=([0-9a-fA-F]+)\s+RSP=([0-9a-fA-F]+)", re.MULTILINE)
_RE_QMP_R8  = re.compile(r"^R8 =([0-9a-fA-F]+)\s+R9 =([0-9a-fA-F]+)\s+R10=([0-9a-fA-F]+)\s+R11=([0-9a-fA-F]+)", re.MULTILINE)
_RE_QMP_R12 = re.compile(r"^R12=([0-9a-fA-F]+)\s+R13=([0-9a-fA-F]+)\s+R14=([0-9a-fA-F]+)\s+R15=([0-9a-fA-F]+)", re.MULTILINE)
_RE_QMP_CR3 = re.compile(r"\bCR3=([0-9a-fA-F]+)")
_RE_QMP_CPU_HEADER = re.compile(r"^(?:CPU#\s*)?(\d+):\s*$|^CPU#?\s*(\d+)\s*", re.MULTILINE)


def _parse_info_registers(text: str) -> list:
    """Parse QEMU's `info registers -a` text into a list of per-CPU dicts.

    QEMU emits a header like `CPU#0` or `CPU#0:` at the start of each block,
    followed by RAX/RBX/.../RIP/CR3/etc. lines. We tokenise on the headers and
    extract the fields we care about for the futex/mutex investigation.
    """
    blocks = re.split(r"^(?:CPU#?\s*\d+:?)\s*$", text, flags=re.MULTILINE)
    headers = re.findall(r"^CPU#?\s*(\d+):?\s*$", text, flags=re.MULTILINE)
    cpus = []
    for cpu_idx_str, body in zip(headers, blocks[1:]):
        cpu = {"cpu": int(cpu_idx_str)}
        for name, regex, keys in [
            ("rip", _RE_QMP_RIP, ["rip"]),
            ("rax", _RE_QMP_RAX, ["rax", "rbx", "rcx", "rdx"]),
            ("rsi", _RE_QMP_RSI, ["rsi", "rdi", "rbp", "rsp"]),
            ("r8",  _RE_QMP_R8,  ["r8", "r9", "r10", "r11"]),
            ("r12", _RE_QMP_R12, ["r12", "r13", "r14", "r15"]),
        ]:
            m = regex.search(body)
            if m:
                for k, v in zip(keys, m.groups()):
                    cpu[k] = int(v, 16)
        m = _RE_QMP_CR3.search(body)
        if m:
            cpu["cr3"] = int(m.group(1), 16)
        cpus.append(cpu)
    return cpus


def cmd_qmp_regs(args):
    """Pause via QMP, read `info registers -a`, parse, resume.  No GDB needed."""
    sess = _load_session(args.sid)
    qmp_sock = sess.get("qmp_sock") or str(HARNESS_DIR / f"{args.sid}.qmp.sock")
    if not args.no_pause:
        _qmp_command(qmp_sock, "stop")
    try:
        resp = _qmp_command(qmp_sock, "human-monitor-command",
                             {"command-line": "info registers -a"})
        text = resp.get("return", "") if isinstance(resp, dict) else ""
        cpus = _parse_info_registers(text)
        out = {"cpus": cpus}
        if args.raw:
            out["raw"] = text
        _out(out)
    finally:
        if not args.no_pause:
            _qmp_command(qmp_sock, "cont")


def cmd_qmp_xp(args):
    """Read guest physical memory via QMP `xp`. Useful for page-table walks."""
    sess = _load_session(args.sid)
    qmp_sock = sess.get("qmp_sock") or str(HARNESS_DIR / f"{args.sid}.qmp.sock")
    addr = int(args.addr, 0)
    nbytes = int(args.bytes, 0)
    # `xp /Nb 0xADDR` dumps N bytes as hex.  Use /b (byte) so the layout is
    # unambiguous; we then re-pack to a plain hex string.
    cmdline = f"xp /{nbytes}bx 0x{addr:x}"
    resp = _qmp_command(qmp_sock, "human-monitor-command",
                         {"command-line": cmdline})
    text = resp.get("return", "") if isinstance(resp, dict) else ""
    # Lines look like: `0000000007fc0000: 0x12 0x34 ...`
    hex_bytes = []
    for ln in text.splitlines():
        toks = ln.split(":", 1)
        if len(toks) != 2: continue
        for t in toks[1].split():
            t = t.strip()
            if t.startswith("0x") and len(t) <= 4:
                hex_bytes.append(t[2:].zfill(2))
    _out({"addr": f"0x{addr:x}", "bytes": nbytes, "hex": "".join(hex_bytes), "raw": text if args.raw else None})


def cmd_qmp_xv(args):
    """Read guest *virtual* memory via QMP `x` (uses current CR3)."""
    sess = _load_session(args.sid)
    qmp_sock = sess.get("qmp_sock") or str(HARNESS_DIR / f"{args.sid}.qmp.sock")
    addr = int(args.addr, 0)
    nbytes = int(args.bytes, 0)
    cpu = int(args.cpu)
    # `x` uses the current CPU's translation; we select the CPU first so the
    # walker uses tid=1's CR3 (CPU 0 if tid=1 is on CPU 0).
    _qmp_command(qmp_sock, "human-monitor-command",
                  {"command-line": f"cpu {cpu}"})
    cmdline = f"x /{nbytes}bx 0x{addr:x}"
    resp = _qmp_command(qmp_sock, "human-monitor-command",
                         {"command-line": cmdline})
    text = resp.get("return", "") if isinstance(resp, dict) else ""
    hex_bytes = []
    for ln in text.splitlines():
        toks = ln.split(":", 1)
        if len(toks) != 2: continue
        for t in toks[1].split():
            t = t.strip()
            if t.startswith("0x") and len(t) <= 4:
                hex_bytes.append(t[2:].zfill(2))
    _out({"cpu": cpu, "addr": f"0x{addr:x}", "bytes": nbytes,
          "hex": "".join(hex_bytes), "raw": text if args.raw else None})


# ══════════════════════════════════════════════════════════════════════════════
# rip-walk — pause at a serial-log marker; walk user RBP chain via QMP
# ══════════════════════════════════════════════════════════════════════════════
#
# Phase 18 demand: at a chosen syscall ordinal (the upstream branching choice
# in libxul/NSPR/GTK that picks "fork glxtest" vs "thread-spawn-only"),
# capture the user-space RBP chain so we can identify the gating Mozilla
# function on the stack at that exact moment.
#
# The kernel already publishes the saved user RBP via per-CPU storage
# (`PER_CPU_SYSCALL[cpu].frame_rsp`, populated by syscall_entry).  At any
# moment a CPU is executing a Linux syscall, frame_rsp[11] is the user RBP
# and frame_rsp[14] is the user RSP (see kernel/src/syscall/mod.rs).  We
# read those via QMP `xv` (kernel addresses translate through the active
# CR3 because the kernel is mapped in higher half of every user CR3),
# then walk the user RBP chain entirely via QMP `xv` reads against the
# user CR3.  No kernel rebuild required, no GDB stub required.
#
# Output schema (stable for downstream tools):
# {
#   "ok": true,
#   "marker": <regex>, "matched_line": <str>, "match_index": <int>,
#   "cpu": <int>, "kernel_rip": <hex>, "cr3": <hex>,
#   "frame_rsp": <hex>,  // kernel pointer to saved user regs
#   "user_rsp": <hex>, "user_rbp": <hex>,
#   "frames": [
#     {"i": 0, "kind": "user_rip", "rip": hex,
#      "library": str|null, "offset": hex|null, "symbol": str|null},
#     {"i": 1, "kind": "rbp",     "rip": hex, ...},
#     ...
#   ]
# }

# Slot offset of `rbp` and `user_rsp` in the syscall_entry frame (8-byte
# words from `frame_rsp`).  Must match the layout in
# kernel/src/syscall/mod.rs: get_user_rsp_rbp() reads p.add(11) for rbp
# and p.add(14) for user_rsp.
_SC_FRAME_RBP_SLOT      = 11
_SC_FRAME_USER_RSP_SLOT = 14


def _kernel_symbol_addr(elf_path: Path, name: str) -> Optional[int]:
    """Resolve a STT_OBJECT or STT_FUNC symbol's address from the kernel ELF.
    Returns the integer virtual address or None."""
    info = _resolve_symbol(elf_path, name)
    if info is None:
        return None
    try:
        return int(info["addr"], 16)
    except (KeyError, ValueError, TypeError):
        return None


def _qmp_xp_bytes(qmp: "QMP", paddr: int, nbytes: int) -> Optional[bytes]:
    """Read N bytes of guest *physical* memory via QMP `xp`.  Used for the
    manual page-table walk in `_translate_va_via_cr3`."""
    resp = qmp.execute("human-monitor-command",
                        {"command-line": f"xp /{nbytes}bx 0x{paddr:x}"})
    text = resp.get("return", "") if isinstance(resp, dict) else ""
    if "Cannot access memory" in text:
        return None
    out = bytearray()
    for ln in text.splitlines():
        if ":" not in ln:
            continue
        _, rhs = ln.split(":", 1)
        for tok in rhs.split():
            tok = tok.strip()
            if tok.startswith("0x") and len(tok) <= 4:
                try:
                    out.append(int(tok, 16))
                except ValueError:
                    return None
    if len(out) == 0:
        return None
    return bytes(out[:nbytes])


def _translate_va_via_cr3(qmp: "QMP", cr3: int, vaddr: int) -> Optional[int]:
    """Translate a 4-level x86_64 virtual address to a physical address by
    manually walking the page tables rooted at CR3.  Returns the physical
    address (with 12-bit offset preserved) or None if any level is not
    present.

    This is the fallback when QMP's HMP `cpu N`/`x` cannot reach a CR3
    (e.g. tid=1 was on Firefox's CR3 when the syscall fired but every
    paused vCPU is now on the kernel's CR3 — between Firefox bursts).
    """
    cr3_pa = cr3 & ~0xFFF
    levels = [
        (39, "PML4"),
        (30, "PDPT"),
        (21, "PD"),
        (12, "PT"),
    ]
    table_pa = cr3_pa
    for shift, _name in levels:
        idx = (vaddr >> shift) & 0x1FF
        entry_pa = table_pa + idx * 8
        raw = _qmp_xp_bytes(qmp, entry_pa, 8)
        if raw is None or len(raw) < 8:
            return None
        entry = struct.unpack_from("<Q", raw)[0]
        if (entry & 0x1) == 0:  # not present
            return None
        # Bit 7 = PS (huge page): PDPT→1G, PD→2M.  Mask the next-level
        # index bits below shift and OR in the current va offset.
        if shift in (30, 21) and (entry & (1 << 7)):
            base = entry & 0x000F_FFFF_FFFF_F000
            mask = (1 << shift) - 1
            return (base & ~mask) | (vaddr & mask)
        table_pa = entry & 0x000F_FFFF_FFFF_F000
    # Final PT entry maps a 4 KiB page.
    return table_pa | (vaddr & 0xFFF)


def _qmp_xv_via_cr3(qmp: "QMP", cr3: int, vaddr: int, nbytes: int) -> Optional[bytes]:
    """Read N bytes of guest virtual memory through an *explicit* CR3 via
    a manual page-table walk + `xp` reads.  Use when no paused vCPU has
    the desired user CR3 loaded (the common case mid-walk on this kernel —
    syscall returned, scheduler switched to kernel CR3, then we paused).

    This walks one page boundary at a time so a multi-page read whose
    middle page is unmapped still returns the prefix.
    """
    out = bytearray()
    remaining = nbytes
    cur = vaddr
    while remaining > 0:
        page_off = cur & 0xFFF
        chunk = min(0x1000 - page_off, remaining)
        pa = _translate_va_via_cr3(qmp, cr3, cur)
        if pa is None:
            break
        raw = _qmp_xp_bytes(qmp, pa, chunk)
        if raw is None:
            break
        out.extend(raw)
        if len(raw) < chunk:
            break
        cur += chunk
        remaining -= chunk
    return bytes(out) if out else None


def _qmp_xv_u64_via_cr3(qmp: "QMP", cr3: int, vaddr: int) -> Optional[int]:
    """Read one little-endian u64 at a guest virtual address via an
    explicit CR3."""
    raw = _qmp_xv_via_cr3(qmp, cr3, vaddr, 8)
    if raw is None or len(raw) < 8:
        return None
    return struct.unpack_from("<Q", raw)[0]


def _qmp_xv_via_qmp(qmp: "QMP", cpu: int, vaddr: int, nbytes: int) -> Optional[bytes]:
    """Read N bytes of guest *virtual* memory through CPU `cpu`'s active
    CR3, using a CALLER-SUPPLIED open QMP connection.

    The HMP `cpu N` selection lasts only as long as the QMP connection
    stays open — issuing `cpu N` then a `x` on a *new* connection fails
    silently (the second connection's HMP context still defaults to CPU 0,
    whose CR3 lacks user-space mappings on this kernel).  Take a persistent
    connection from the caller so all reads against one CPU share the
    selection, and so we amortise connection setup over a stack walk.

    Returns the raw bytes (best-effort, may be shorter than `nbytes` if
    only part of the range was readable), or None if the address is
    entirely unmapped from CPU `cpu`'s CR3.
    """
    qmp.execute("human-monitor-command", {"command-line": f"cpu {cpu}"})
    resp = qmp.execute("human-monitor-command",
                        {"command-line": f"x /{nbytes}bx 0x{vaddr:x}"})
    text = resp.get("return", "") if isinstance(resp, dict) else ""
    if "Cannot access memory" in text:
        return None
    out = bytearray()
    for ln in text.splitlines():
        if ":" not in ln:
            continue
        _, rhs = ln.split(":", 1)
        for tok in rhs.split():
            tok = tok.strip()
            if tok.startswith("0x") and len(tok) <= 4:
                try:
                    out.append(int(tok, 16))
                except ValueError:
                    return None
    if len(out) == 0:
        return None
    return bytes(out[:nbytes])


def _qmp_xv_u64(qmp: "QMP", cpu: int, vaddr: int) -> Optional[int]:
    """Read one little-endian u64 at a guest virtual address through `cpu`'s
    CR3, using a caller-supplied open QMP connection."""
    raw = _qmp_xv_via_qmp(qmp, cpu, vaddr, 8)
    if raw is None or len(raw) < 8:
        return None
    return struct.unpack_from("<Q", raw)[0]


def _wait_for_marker(serial_log: str, regex: re.Pattern, timeout_ms: int,
                      start_offset: int = 0,
                      occurrence: int = 1) -> Optional[tuple]:
    """Tail `serial_log` from `start_offset` until `regex` matches `occurrence`
    times or `timeout_ms` elapses.  Returns (match_text, byte_offset_after,
    occurrence_count) on success, None on timeout.

    Re-opens the file each poll so growth is observed even on log-rotation.
    """
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    matches_seen = 0
    last_match: Optional[tuple] = None
    pos = start_offset
    while time.monotonic() < deadline:
        try:
            with open(serial_log, "rb") as f:
                f.seek(pos)
                chunk = f.read()
        except OSError:
            time.sleep(0.05)
            continue
        if chunk:
            text = chunk.decode("utf-8", errors="replace")
            for m in regex.finditer(text):
                matches_seen += 1
                end_off = pos + m.end()
                if matches_seen >= occurrence:
                    return (m.group(0), end_off, matches_seen)
                last_match = (m.group(0), pos + m.end(), matches_seen)
            pos += len(chunk)
        time.sleep(0.05)
    return None


def cmd_rip_walk(args):
    """Pause QEMU at a serial-log marker, walk the user RBP chain, symbolise.

    Required: --marker <regex>.  Optional: --frames N (default 32),
              --occurrence K (default 1, K-th match wins),
              --timeout-ms M (default 60000),
              --disk-root DIR (host disk-staging root for symbol lookup).

    Implementation flow:
      1. Tail the session's serial log waiting for `--marker`.
      2. On match, QMP `stop` immediately (atomic across all vCPUs).
      3. QMP `info registers -a` → find tid=1's CPU (the syscall is on
         the CPU whose RIP is in higher-half AND whose CR3 matches the
         active user process).  We default to CPU 0 unless --cpu is set
         (Firefox tid=1 lives on CPU 0 in every observed run).
      4. Read PER_CPU_SYSCALL[cpu].frame_rsp via QMP xv on the kernel
         address (`PER_CPU_SYSCALL_addr + cpu * sizeof(slot) + 24`).
      5. From frame_rsp, read user_rbp (slot 11) and user_rsp (slot 14).
      6. Walk RBP chain: each frame has [rbp, return_rip] at [rbp, rbp+8].
      7. Resolve every RIP against the [FFTEST/mmap-so] load-base map +
         pyelftools symtab cache (same machinery as `ustack`/`rip-sample`).
      8. QMP `cont` (always — never leave the guest paused on error).
    """
    sess     = _load_session(args.sid)
    qmp_sock = sess.get("qmp_sock") or str(HARNESS_DIR / f"{args.sid}.qmp.sock")
    serial_log = sess["serial_log"]

    pattern    = re.compile(args.marker)
    frames_n   = max(1, int(args.frames))
    occurrence = max(1, int(args.occurrence))
    timeout_ms = max(0, int(args.timeout_ms))
    disk_root  = getattr(args, "disk_root", None)
    target_cpu = int(args.cpu) if args.cpu is not None else None
    user_cr3   = int(args.user_cr3, 0) if args.user_cr3 is not None else None

    # Establish a starting offset so we don't match historical lines.
    start_off = 0
    try:
        start_off = Path(serial_log).stat().st_size
    except OSError:
        pass

    # ── 1. Wait for the marker line ───────────────────────────────────────
    match = _wait_for_marker(serial_log, pattern, timeout_ms, start_off,
                              occurrence=occurrence)
    if match is None:
        # NB: serial log may simply not have grown yet — caller can retry.
        _out({
            "ok": False,
            "error": "marker not seen",
            "marker": args.marker,
            "timeout_ms": timeout_ms,
            "start_offset": start_off,
        })
        return

    matched_line, match_off, occ = match

    # ── 2. Pause guest atomically ─────────────────────────────────────────
    # We hold a SINGLE persistent QMP connection across the whole walk.
    # The HMP `cpu N` selection only persists within one connection, so
    # opening a fresh connection per memory read (the previous design)
    # would silently fall back to CPU 0's CR3 — which on this kernel
    # has no user-space mappings, making every user_rsp / rbp read
    # report "Cannot access memory".
    qmp = QMP(qmp_sock)
    if not qmp.connect(timeout=2.0):
        _err("QMP socket not available")
    stop_resp = qmp.execute("stop")
    if "error" in stop_resp:
        _err(f"QMP stop failed: {stop_resp.get('error')}")

    out: dict = {
        "ok": False,
        "marker": args.marker,
        "matched_line": matched_line.rstrip(),
        "match_index": occ,
        "frames": [],
    }

    try:
        # ── 3. Read per-CPU register file ────────────────────────────────
        regs_resp = qmp.execute("human-monitor-command",
                                 {"command-line": "info registers -a"})
        regs_text = regs_resp.get("return", "") if isinstance(regs_resp, dict) else ""
        cpus = _parse_info_registers(regs_text)
        if not cpus:
            out["error"] = "no CPUs in info registers"
            _out(out)
            return

        # ── Pick the target CPU ──────────────────────────────────────────
        # The right choice is the CPU whose per-CPU syscall slot was last
        # populated by a SYSCALL — that's the CPU currently servicing (or
        # most recently serviced) tid=1's syscall.  We probe slots[0..N]
        # for non-zero `frame_rsp`; if multiple are populated we prefer
        # one whose RIP is currently in higher-half kernel space (matches
        # the marker we paused on).  Falling back to "first CPU with
        # frame_rsp != 0" handles the common case where tid=1 has already
        # SYSRET'd back to user-space by the time we observe the marker.
        kernel_elf = _get_kernel_elf()
        base = _kernel_symbol_addr(kernel_elf, "PER_CPU_SYSCALL")
        if base is None:
            out["error"] = ("PER_CPU_SYSCALL symbol not in kernel ELF — "
                            "cannot read user RBP without it")
            _out(out)
            return
        # PerCpuSyscallData is repr(C, align(64)): 4 u64 fields = 32 bytes,
        # padded to 64 bytes by alignment.  Slot stride is therefore 64.
        slot_stride = 64
        # Probe each CPU's frame_rsp and rank by liveness.
        slot_state: list[dict] = []
        for c in cpus:
            ci = c["cpu"]
            slot = base + ci * slot_stride
            fr   = _qmp_xv_u64(qmp, ci, slot + 24) or 0
            slot_state.append({
                "cpu":       ci,
                "rip":       c.get("rip", 0),
                "rsp":       c.get("rsp", 0),
                "rbp":       c.get("rbp", 0),
                "cr3":       c.get("cr3", 0),
                "frame_rsp": fr,
                "in_kernel": (c.get("rip", 0) or 0) >= _KERNEL_VMA_BASE,
            })

        chosen = None
        if target_cpu is not None:
            for s in slot_state:
                if s["cpu"] == target_cpu:
                    chosen = s
                    break
        # Best: kernel-mode CPU with populated frame_rsp.
        if chosen is None:
            for s in slot_state:
                if s["frame_rsp"] != 0 and s["in_kernel"]:
                    chosen = s
                    break
        # Next best: any CPU with populated frame_rsp (user-mode, post-SYSRET).
        if chosen is None:
            for s in slot_state:
                if s["frame_rsp"] != 0:
                    chosen = s
                    break
        # Last resort: first CPU.
        if chosen is None:
            chosen = slot_state[0]

        cpu_idx = chosen["cpu"]
        kernel_rip = chosen["rip"]
        cr3 = chosen["cr3"]
        out["cpu"]        = cpu_idx
        out["kernel_rip"] = f"{kernel_rip:#x}"
        out["cr3"]        = f"{cr3:#x}"
        out["all_cpus"]   = [
            {"cpu": c["cpu"],
             "rip": f"{(c.get('rip') or 0):#x}",
             "rsp": f"{(c.get('rsp') or 0):#x}",
             "rbp": f"{(c.get('rbp') or 0):#x}",
             "cr3": f"{(c.get('cr3') or 0):#x}"}
            for c in cpus
        ]

        # ── 4. Resolve PER_CPU_SYSCALL slot for the chosen CPU ──────────
        # We already probed all slots above to make the CPU choice;
        # `chosen["frame_rsp"]` is the live value from the active CR3.
        slot_addr      = base + cpu_idx * slot_stride
        frame_rsp_addr = slot_addr + 24
        out["per_cpu_syscall_base"] = f"{base:#x}"
        out["frame_rsp_addr"]       = f"{frame_rsp_addr:#x}"
        out["per_cpu_slots"]        = [
            {"cpu": s["cpu"], "frame_rsp": f"{s['frame_rsp']:#x}",
             "in_kernel": s["in_kernel"]}
            for s in slot_state
        ]

        frame_rsp = chosen["frame_rsp"]
        if not frame_rsp:
            out["error"] = ("no CPU has a populated PER_CPU_SYSCALL slot — "
                            "tid=1 may not have entered a syscall yet, or the "
                            "marker fired during early boot")
            _out(out)
            return
        out["frame_rsp"] = f"{frame_rsp:#x}"

        # ── 5. Read saved user RBP and user RSP from kernel stack ────────
        # frame_rsp is a kernel-half address (the kernel stack window the
        # syscall_entry stub pushed user GPRs onto).  Reads here go through
        # the *current* CPU's CR3 — the higher-half mapping is identical
        # across all CR3s in this kernel, so any populated CR3 works.
        user_rbp = _qmp_xv_u64(qmp, cpu_idx,
                                  frame_rsp + _SC_FRAME_RBP_SLOT * 8)
        user_rsp = _qmp_xv_u64(qmp, cpu_idx,
                                  frame_rsp + _SC_FRAME_USER_RSP_SLOT * 8)
        out["user_rbp"] = f"{(user_rbp or 0):#x}"
        out["user_rsp"] = f"{(user_rsp or 0):#x}"

        # ── 5a. Decide which CR3 to use for user-space reads ─────────────
        # If --user-cr3 was supplied, use it verbatim.  Otherwise:
        #   (a) prefer a paused CPU whose CR3 has user-space mappings
        #       (PML4[0..255] populated) — that's still on the user
        #       process's CR3.
        #   (b) fall back to scanning the serial log for the most-recent
        #       Firefox/user-process CR3 marker.
        eff_user_cr3 = None
        if user_cr3 is not None:
            eff_user_cr3 = user_cr3
            out["user_cr3_source"] = "explicit"
        else:
            # (a) Probe each CPU's CR3 for a *Firefox-style* PML4 layout:
            # the bootloader's kernel CR3 has PML4[0..3] populated for the
            # 4 GiB identity map + PML4[256..] for the higher half, but
            # NOTHING in PML4[4..255].  A Firefox-side CR3 has PML4[253]
            # (≈0x7eff_… libxul/heap/thread-stack range) and/or PML4[255]
            # (≈0x7fff_… main stack) populated — i.e. some entry in [4..255].
            # We probe that span directly, skipping the [0..3] identity
            # entries that the kernel CR3 also has.
            for s in slot_state:
                cr3_val = s["cr3"]
                if not cr3_val:
                    continue
                pml4_lo = _qmp_xp_bytes(qmp, cr3_val & ~0xFFF, 256 * 8)
                if not pml4_lo or len(pml4_lo) < 256 * 8:
                    continue
                has_user = False
                for i in range(4, 256):
                    e = struct.unpack_from("<Q", pml4_lo, i * 8)[0]
                    if e & 1:
                        has_user = True
                        break
                if has_user:
                    eff_user_cr3 = cr3_val
                    out["user_cr3_source"] = f"cpu{s['cpu']}"
                    break
            # (b) If no paused CPU is on a user CR3, parse the serial log
            # for the most recent CR3 marker — Firefox bringup logs lines
            # like [USER] Bootstrap tid=N: ... CR3=0xNNN.
            if eff_user_cr3 is None:
                cr3_re = re.compile(r"CR3=0x([0-9a-fA-F]+)")
                try:
                    log_text = Path(serial_log).read_text(errors="replace")
                except OSError:
                    log_text = ""
                # Tally CR3 occurrences: the most-frequently-cited
                # non-boot CR3 in the log is the user process's.
                counts: dict[int, int] = {}
                for m in cr3_re.finditer(log_text):
                    val = int(m.group(1), 16)
                    if val and val != 0x3dcd3000 and val < 0x4_0000_0000:
                        counts[val] = counts.get(val, 0) + 1
                if counts:
                    # Pick the highest-count CR3 (a Firefox process's CR3
                    # is referenced once per syscall trace and once per
                    # bootstrap, so it dominates).
                    eff_user_cr3 = max(counts.items(), key=lambda kv: kv[1])[0]
                    out["user_cr3_source"] = "serial-log"
        out["user_cr3"] = f"{(eff_user_cr3 or 0):#x}"

        # ── 5b. The leaf user caller RIP at *(user_rsp) ──────────────────
        # Try the chosen CPU's CR3 first; if that fails (CPU is on kernel
        # CR3), fall back to manual page-table walk via eff_user_cr3.
        leaf_rip = None
        if user_rsp and user_rsp >= 0x1000 and user_rsp < _KERNEL_VMA_BASE:
            leaf_rip = _qmp_xv_u64(qmp, cpu_idx, user_rsp)
            if leaf_rip is None and eff_user_cr3:
                leaf_rip = _qmp_xv_u64_via_cr3(qmp, eff_user_cr3, user_rsp)

        # ── 6. Build symbol resolution context (load-base + cache) ───────
        try:
            log_lines = Path(serial_log).read_text(errors="replace").splitlines()
        except OSError:
            log_lines = []
        libs = _build_load_base_map(log_lines)
        libs.sort(key=lambda L: L["base"])

        def _resolve(rip: int) -> dict:
            entry = {"rip": f"{rip:#x}", "library": None,
                     "offset": None, "symbol": None}
            if rip == 0:
                return entry
            ur = _resolve_user_rip(rip, libs, disk_root)
            if ur is not None:
                entry.update({
                    "library": ur["library"],
                    "offset":  ur["offset"],
                    "symbol":  ur["symbol"],
                })
            return entry

        frames: list[dict] = []

        # Frame 0: the leaf — caller of the libc syscall wrapper.
        if leaf_rip:
            f0 = _resolve(leaf_rip)
            f0.update({"i": 0, "kind": "user_caller"})
            frames.append(f0)

        # ── 7. Walk RBP chain via QMP xv (live CPU) + CR3 walk fallback ──
        def _ureadu64(va: int) -> Optional[int]:
            """User-virtual u64 read with CPU-CR3 then explicit-CR3 fallback."""
            v = _qmp_xv_u64(qmp, cpu_idx, va)
            if v is None and eff_user_cr3:
                v = _qmp_xv_u64_via_cr3(qmp, eff_user_cr3, va)
            return v

        cur = user_rbp or 0
        prev = 0
        for i in range(frames_n):
            if cur == 0 or cur >= _KERNEL_VMA_BASE or cur < 0x1000:
                break
            if (cur & 0x7) != 0:
                break
            # Sanity: rbp should march up the stack.  A frame whose saved-rbp
            # is <= the current rbp indicates a corrupted chain (or the
            # standard libc/_start sentinel saved-rbp=0).  Stop in either
            # case rather than risk emitting garbage.
            if prev != 0 and cur <= prev:
                break
            saved_rbp = _ureadu64(cur)
            saved_rip = _ureadu64(cur + 8)
            if saved_rip is None:
                break
            frame = _resolve(saved_rip)
            frame.update({"i": len(frames), "kind": "rbp",
                          "rbp_at": f"{cur:#x}"})
            frames.append(frame)
            if saved_rbp is None or saved_rbp == 0:
                break
            prev = cur
            cur  = saved_rbp

        # ── 7b. RBP-chain absent or short — scan up the user RSP for any
        # word that resolves to a known mapped library.  This is the same
        # "raw stack scan" trick the [SC-USTACK]/parked-stacks tools use
        # for FPO-compiled callers (libc/libxul leaf functions don't set
        # up frame pointers).  Scan up to 256 words of stack.
        if user_rsp and user_rsp >= 0x1000 and user_rsp < _KERNEL_VMA_BASE:
            scan_words = 256
            scan_buf = _qmp_xv_via_qmp(qmp, cpu_idx, user_rsp, scan_words * 8)
            if (scan_buf is None or len(scan_buf) < 64) and eff_user_cr3:
                scan_buf = _qmp_xv_via_cr3(qmp, eff_user_cr3, user_rsp,
                                            scan_words * 8)
            if scan_buf:
                seen_libs: set[str] = set()
                for off in range(0, len(scan_buf) - 8, 8):
                    word = struct.unpack_from("<Q", scan_buf, off)[0]
                    if word == 0 or word >= _KERNEL_VMA_BASE:
                        continue
                    lib, lib_off = _resolve_frame_to_lib(word, libs)
                    if lib is None:
                        continue
                    # One scan-frame per library — keeps the output compact
                    # and surfaces the call chain (libc → libxul → libc).
                    if lib in seen_libs:
                        continue
                    seen_libs.add(lib)
                    fr = _resolve(word)
                    fr.update({"i": len(frames), "kind": "scan",
                               "rsp_off": off})
                    frames.append(fr)

        out["frames"] = frames
        out["frame_count"] = len(frames)

        # Compact "stack signature" = the lowest non-libc library:symbol
        # tuple — that is the function name the caller is hunting.
        gate_lib = None
        gate_sym = None
        for fr in frames:
            lib = fr.get("library") or ""
            sym = fr.get("symbol")
            # Skip libc/ld/pthread frames — the gate is the first
            # *non-libc* frame above the syscall.
            if lib and not any(s in lib for s in (
                "libc.so", "libpthread", "ld-musl", "ld-linux",
                "libdl.so", "libm.so",
            )):
                gate_lib, gate_sym = lib, sym
                break
        out["gate_library"] = gate_lib
        out["gate_symbol"]  = gate_sym
        out["ok"] = True
    finally:
        # Always resume — never leave the guest paused on error.
        try:
            qmp.execute("cont")
        except Exception:
            # Last-resort: spin a fresh one-shot connection in case the
            # persistent one wedged.  Guest-paused-forever is the worst
            # outcome we can have here, so always fire `cont`.
            _qmp_command(qmp_sock, "cont", connect_timeout=2.0)
        finally:
            qmp.close()

    _out(out)


# ══════════════════════════════════════════════════════════════════════════════
# Housekeeping / reporting subcommands
# ══════════════════════════════════════════════════════════════════════════════

def cmd_prune(args):
    """
    Remove per-session artefacts for dead sessions older than --ttl days.

    Walks HARNESS_DIR, groups files by sid (derived from `<sid>.json` or from
    the filename stem of orphaned `<sid>.serial.log` / `<sid>.events.jsonl` /
    `<sid>.OVMF_VARS.fd`). A sid is considered prunable when:
      - its .json either doesn't exist, OR its recorded pid is not alive; AND
      - the newest mtime across all its files is older than TTL days.

    Orphan files without any matching `.json` are always eligible if older
    than TTL.

    Per-file permission/OS errors are swallowed so one bad file doesn't abort
    the whole sweep.
    """
    ttl_days = max(0.0, float(args.ttl))
    ttl_seconds = ttl_days * 86400.0
    now = time.time()

    # Group files by sid stem. We recognise the well-known suffix set:
    # .json, .serial.log, .events.jsonl, .qmp.sock, .OVMF_VARS.fd, .esp (dir)
    known_suffixes = (
        ".json",
        ".serial.log",
        ".events.jsonl",
        ".qmp.sock",
        ".OVMF_VARS.fd",
        ".esp",          # session-scoped ESP directory (10-20 MB)
        ".kdb.json",     # kdb introspection cache (see cmd_kdb)
        ".gdb.lock",     # gdb-stub mutex file (see cmd_rip_sample)
    )

    groups: dict = {}  # sid -> list[Path]
    try:
        entries = list(HARNESS_DIR.iterdir())
    except OSError:
        _out({"pruned": [], "kept": 0, "freed_bytes": 0})
        return

    for p in entries:
        # Accept both files and directories (the `.esp` entry is a directory
        # tree containing the session-scoped kernel.bin + BOOTX64.EFI).
        if not (p.is_file() or p.is_dir()):
            continue
        name = p.name
        sid = None
        for suf in known_suffixes:
            if name.endswith(suf):
                sid = name[: -len(suf)]
                break
        if not sid:
            continue
        groups.setdefault(sid, []).append(p)

    pruned = []
    kept = 0
    freed_bytes = 0

    for sid, files in groups.items():
        # Determine liveness via the .json file, if present.
        alive = False
        sess_pid = 0
        json_path = HARNESS_DIR / f"{sid}.json"
        if json_path.exists():
            try:
                with json_path.open() as f:
                    sess = json.load(f)
                sess_pid = int(sess.get("pid", 0) or 0)
                if sess_pid:
                    alive = _pid_alive(sess_pid)
            except (json.JSONDecodeError, OSError, ValueError):
                # Corrupt JSON — treat as dead (orphan).
                alive = False

        if alive:
            kept += 1
            continue

        # Newest mtime across all grouped files.
        newest = 0.0
        for fp in files:
            try:
                st = fp.stat()
                if st.st_mtime > newest:
                    newest = st.st_mtime
            except OSError:
                continue

        age = now - newest if newest > 0 else float("inf")
        if age < ttl_seconds:
            kept += 1
            continue

        # Prune: delete every file/dir in the group. Directories (e.g. the
        # `<sid>.esp` session-scoped ESP tree) get rmtree'd; files get
        # unlinked. Permission/race errors are swallowed so one bad entry
        # doesn't abort the whole sweep.
        for fp in files:
            try:
                if fp.is_dir():
                    # Sum sizes recursively before deleting.
                    sz = 0
                    for child in fp.rglob("*"):
                        try:
                            if child.is_file():
                                sz += child.stat().st_size
                        except OSError:
                            continue
                    shutil.rmtree(fp, ignore_errors=True)
                    freed_bytes += sz
                else:
                    sz = fp.stat().st_size
                    fp.unlink()
                    freed_bytes += sz
            except OSError:
                continue
        pruned.append(sid)

    _out({
        "pruned":      sorted(pruned),
        "kept":        kept,
        "freed_bytes": freed_bytes,
    })


_TEST_JSON_RE   = re.compile(r"^\[TEST-JSON\]\s+(\{.*\})\s*$")
_FF_OPEN_RET_RE = re.compile(r"^\[FF/open-ret\]\s+pid=(\d+)\s+path=(\S+)\s+ret=(-?\d+)")
_SC_ENTRY_RE    = re.compile(
    r"^\[SC\]\s+pid=(\d+)\s+tid=(\d+)\s+nr=(\d+)\s+rip=(0x[0-9a-fA-F]+)"
    r"\s+a1=(0x[0-9a-fA-F]+)\s+a2=(0x[0-9a-fA-F]+)\s+a3=(0x[0-9a-fA-F]+)")
_FF_EXIT_CLEAN_RE = re.compile(r"\[FFTEST\]\s+DONE")
_FF_EXIT_TICKS_RE = re.compile(r"\[FFTEST\]\s+Firefox exited after\s+(\d+)\s+ticks")
_FF_EXIT_CODE_RE  = re.compile(r"\[FFTEST\]\s+Firefox exit code[:= ]+(-?\d+)")
_TICK_RE          = re.compile(r"tick[=:\s]+(\d+)")

# [SC] full-line regex — includes cr= a4= a5= a6= which _SC_ENTRY_RE omits.
_SC_FULL_RE = re.compile(
    r"\[SC\]\s+pid=(\d+)\s+tid=(\d+)\s+nr=(\d+)\s+rip=(0x[0-9a-fA-F]+)"
)
# [SC-RET] regex
_SC_RET_FULL_RE = re.compile(
    r"\[SC-RET\]\s+pid=(\d+)\s+tid=(\d+)\s+nr=(\d+)\s+ret=(-?\d+|0x[0-9a-fA-F]+)"
)

# Linux syscall number → name table (x86_64, abbreviated to the set Firefox uses).
_NR_NAME = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect",
    11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
    15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 21: "access", 22: "pipe", 23: "select",
    24: "sched_yield", 25: "mremap", 26: "msync", 28: "madvise",
    29: "shmget", 30: "shmat", 31: "shmctl", 32: "dup", 33: "dup2",
    34: "pause", 35: "nanosleep", 36: "getitimer", 37: "alarm",
    38: "setitimer", 39: "getpid", 41: "socket", 42: "connect",
    43: "accept", 44: "sendto", 45: "recvfrom", 46: "sendmsg",
    47: "recvmsg", 48: "shutdown", 49: "bind", 50: "listen",
    51: "getsockname", 52: "getpeername", 53: "socketpair",
    54: "setsockopt", 55: "getsockopt", 56: "clone",
    57: "fork", 58: "vfork", 59: "execve", 60: "exit",
    61: "wait4", 62: "kill", 63: "uname", 72: "fcntl", 73: "flock",
    74: "fsync", 75: "fdatasync", 76: "truncate", 77: "ftruncate",
    78: "getdents", 79: "getcwd", 80: "chdir", 81: "fchdir",
    83: "mkdir", 84: "rmdir", 85: "creat", 86: "link", 87: "unlink",
    88: "symlink", 89: "readlink", 90: "chmod", 91: "fchmod",
    97: "getrlimit", 98: "getrusage", 99: "sysinfo", 100: "times",
    102: "getuid", 104: "getgid", 105: "setuid", 106: "setgid",
    107: "geteuid", 108: "getegid", 110: "getppid", 111: "getpgrp",
    112: "setsid", 158: "arch_prctl", 160: "setrlimit",
    186: "gettid", 201: "time", 202: "futex",
    218: "set_tid_address", 228: "clock_gettime", 229: "clock_getres",
    230: "clock_nanosleep", 231: "exit_group", 232: "epoll_wait",
    233: "epoll_ctl", 234: "tgkill", 257: "openat", 262: "newfstatat",
    273: "set_robust_list", 302: "prlimit64", 318: "getrandom",
    319: "memfd_create", 334: "rseq", 435: "clone3",
}


def _nr_to_name(nr: int) -> str:
    return _NR_NAME.get(nr, f"nr{nr}")


def cmd_sc_histogram(args):
    """Scan [SC] trace lines from the serial log; produce a per-tid syscall
    count histogram plus a global top-N sorted by call frequency.

    Also scans [SC-RET] lines to identify syscalls that return errors
    (negative return values) which may indicate ABI divergence from Linux.

    Output schema:
      {
        "total_sc_lines": <int>,
        "tids_seen": [<tid>, ...],
        "global_top": [{"name": str, "nr": int, "count": int}, ...],
        "per_tid": {
          "<tid>": {
            "total": <int>,
            "top": [{"name": str, "nr": int, "count": int}, ...]
          }
        },
        "error_returns": [{"name": str, "nr": int, "ret": str, "count": int}, ...],
      }
    """
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]
    filter_tid = args.tid
    top_n = max(1, int(args.top))
    since_line = args.since_line

    # Per-tid: {tid: {nr: count}}
    per_tid: dict[int, dict[int, int]] = {}
    # Global: {nr: count}
    global_hist: dict[int, int] = {}
    # Error returns: {(tid, nr): {ret_str: count}}
    error_hist: dict[tuple, dict[str, int]] = {}

    total_sc = 0
    line_no = 0

    try:
        with Path(serial_log).open("r", errors="replace") as fh:
            for ln in fh:
                line_no += 1
                if since_line is not None and line_no < since_line:
                    continue
                # [SC] entry lines
                m = _SC_FULL_RE.search(ln)
                if m:
                    tid = int(m.group(2))
                    nr  = int(m.group(3))
                    if filter_tid is not None and tid != filter_tid:
                        continue
                    total_sc += 1
                    per_tid.setdefault(tid, {})
                    per_tid[tid][nr] = per_tid[tid].get(nr, 0) + 1
                    global_hist[nr] = global_hist.get(nr, 0) + 1
                    continue
                # [SC-RET] lines — track negative returns as errors
                m = _SC_RET_FULL_RE.search(ln)
                if m:
                    tid = int(m.group(2))
                    nr  = int(m.group(3))
                    if filter_tid is not None and tid != filter_tid:
                        continue
                    ret_s = m.group(4)
                    try:
                        ret_v = int(ret_s, 0)
                    except ValueError:
                        continue
                    # Only track negative returns (errors) or interesting values
                    if ret_v < 0 or (nr == 202 and ret_v == 11):  # 202=futex, EAGAIN=11
                        key = (tid, nr)
                        error_hist.setdefault(key, {})
                        error_hist[key][ret_s] = error_hist[key].get(ret_s, 0) + 1
    except OSError as e:
        _err(f"Cannot read serial log: {e}")

    # Build global top-N
    global_top = sorted(
        [{"name": _nr_to_name(nr), "nr": nr, "count": c}
         for nr, c in global_hist.items()],
        key=lambda x: -x["count"]
    )[:top_n]

    # Build per-tid top-N
    per_tid_out = {}
    for tid, hist in sorted(per_tid.items()):
        top = sorted(
            [{"name": _nr_to_name(nr), "nr": nr, "count": c}
             for nr, c in hist.items()],
            key=lambda x: -x["count"]
        )[:top_n]
        per_tid_out[str(tid)] = {"total": sum(hist.values()), "top": top}

    # Flatten error histogram
    error_list = []
    for (tid, nr), ret_counts in sorted(error_hist.items()):
        for ret_s, count in sorted(ret_counts.items(), key=lambda kv: -kv[1]):
            error_list.append({
                "tid": tid, "name": _nr_to_name(nr), "nr": nr,
                "ret": ret_s, "count": count
            })
    error_list.sort(key=lambda x: -x["count"])

    _out({
        "total_sc_lines": total_sc,
        "tids_seen": sorted(per_tid.keys()),
        "global_top": global_top,
        "per_tid": per_tid_out,
        "error_returns": error_list[:50],
    })


def cmd_results(args):
    """
    Scan the session's serial log and summarise test-runner + Firefox state.

    The kernel test_runner emits one `[TEST-JSON] {...}` line per
    test_pass! / test_fail!. When `firefox-test` / `syscall-trace` features
    are enabled, additional `[FF/*]` and `[SC]` / `[SC-RET]` markers are
    rolled up into the `firefox` sub-object. Missing lines (session still
    running, or a crash before emission) result in a partial report — we
    never fail.
    """
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]

    tests: list = []
    libs_loaded: list = []
    failed_opens: list = []
    last_syscall: Optional[dict] = None
    ff_exit_code: Optional[int] = None
    ff_exit_ticks: Optional[int] = None
    ff_clean_exit = False
    total_ticks = 0
    ff_trace_seen = False

    try:
        with Path(serial_log).open("rb") as fh:
            buf = b""
            while True:
                chunk = fh.read(64 * 1024)
                if not chunk:
                    if buf:
                        _scan_line(buf, tests, libs_loaded, failed_opens)
                    break
                buf += chunk
                while True:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        break
                    line_b = buf[:nl]
                    buf = buf[nl+1:]
                    line = line_b.decode("utf-8", errors="replace").rstrip("\r")
                    _scan_line(line_b, tests, libs_loaded, failed_opens)
                    # Last-syscall (entry) for Firefox diagnostics.
                    m = _SC_ENTRY_RE.match(line)
                    if m:
                        ff_trace_seen = True
                        last_syscall = {
                            "pid":  int(m.group(1)),
                            "tid":  int(m.group(2)),
                            "nr":   int(m.group(3)),
                            "rip":  m.group(4),
                            "args": [m.group(5), m.group(6), m.group(7)],
                        }
                    # Firefox lifecycle markers.
                    if _FF_EXIT_CLEAN_RE.search(line):
                        ff_clean_exit = True
                    m = _FF_EXIT_TICKS_RE.search(line)
                    if m:
                        ff_exit_ticks = int(m.group(1))
                    m = _FF_EXIT_CODE_RE.search(line)
                    if m:
                        ff_exit_code = int(m.group(1))
                    # Track highest tick we've seen for total_ticks.
                    m = _TICK_RE.search(line)
                    if m:
                        t = int(m.group(1))
                        if t > total_ticks:
                            total_ticks = t
    except OSError as e:
        _err(f"Cannot read serial log: {e}")

    passed = sum(1 for t in tests if t.get("result") == "pass")
    failed = sum(1 for t in tests if t.get("result") == "fail")
    duration = sum(int(t.get("elapsed_ticks") or 0) for t in tests)

    # Determine exit cause from same heuristics as `status`.
    pid = sess.get("pid", 0)
    alive = _pid_alive(pid) if pid else False
    exit_cause = _classify_exit_cause(serial_log, alive)

    firefox = None
    if ff_trace_seen or libs_loaded or failed_opens:
        firefox = {
            "libs_loaded":   libs_loaded,
            "failed_opens":  failed_opens,
            "last_syscall":  last_syscall,
            "exit_code":     ff_exit_code,
            "exit_ticks":    ff_exit_ticks,
            "clean_exit":    ff_clean_exit,
        }

    _out({
        "exit_cause":     exit_cause,
        "total_ticks":    total_ticks,
        "test_results": {
            "total":          len(tests),
            "passed":         passed,
            "failed":         failed,
            "duration_ticks": duration,
            "tests":          tests,
        },
        "firefox":        firefox,
    })


def _scan_line(line_bytes: bytes, tests: list, libs_loaded: list,
               failed_opens: list) -> None:
    """
    Called for every serial log line. Extracts TEST-JSON, FF/open-ret.
    Multi-purpose so we only pay one decode per line.
    """
    try:
        line = line_bytes.decode("utf-8", errors="replace").rstrip("\r")
    except Exception:
        return
    # Test-runner JSON lines
    m = _TEST_JSON_RE.match(line)
    if m:
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict) and "name" in obj and "result" in obj:
                tests.append(obj)
        except json.JSONDecodeError:
            pass
        return
    # Firefox open() return-value lines
    m = _FF_OPEN_RET_RE.match(line)
    if m:
        ret = int(m.group(3))
        path = m.group(2)
        if ret >= 0:
            # Extract library name from common paths like
            # /lib/x86_64-linux-gnu/libnspr4.so.0.
            base = path.rsplit("/", 1)[-1]
            lib = base.split(".so", 1)[0] if ".so" in base else base
            if lib and lib not in libs_loaded:
                libs_loaded.append(lib)
        else:
            failed_opens.append({"path": path, "errno": ret})


# ── scrings: parse per-process syscall ring-buffer dumps ─────────────────────
#
# The kernel (with the firefox-test feature) emits ring-buffer traces on any
# `exit_group(code)` where `code != 0`.  Format, from kernel/src/syscall/ring.rs:
#
#   [SC-RING-BEGIN] pid=<N> exit_code=<N> entries=<N>
#   [SC-RING] i=NNN t=<tick> <name>/<nr> rip=0x.. a1=0x.. a2=0x.. a3=0x.. \
#             a4=0x.. a5=0x.. a6=0x.. ret=<i64>
#   [SC-RING-PATH] i=NNN path="..."                    (for open/openat only)
#   [SC-RING-BYTES] i=NNN len=<N> hex=<hex-ascii>      (for captured reads)
#   [SC-RING-END] pid=<N>
#
# `scrings` finds every dump in the serial log and returns a JSON array — one
# object per dump — each containing pid, exit_code, and a chronological list
# of parsed entries.  The path / bytes lines are attached to their parent
# [SC-RING] entry by matching `i=NNN`.

_SC_RING_BEGIN = re.compile(
    r"\[SC-RING-BEGIN\] pid=(\d+) exit_code=(-?\d+) entries=(\d+)"
)
_SC_RING_LINE = re.compile(
    r"\[SC-RING\] i=(\d+) t=(\d+) (\S+) rip=(0x[0-9a-fA-F]+) "
    r"a1=(0x[0-9a-fA-F]+) a2=(0x[0-9a-fA-F]+) a3=(0x[0-9a-fA-F]+) "
    r"a4=(0x[0-9a-fA-F]+) a5=(0x[0-9a-fA-F]+) a6=(0x[0-9a-fA-F]+) "
    r"ret=(-?\d+)"
)
_SC_RING_PATH = re.compile(r'\[SC-RING-PATH\] i=(\d+) path="([^"]*)"')
_SC_RING_BYTES = re.compile(r'\[SC-RING-BYTES\] i=(\d+) len=(\d+) hex=([0-9a-fA-F]+)')
_SC_RING_END = re.compile(r"\[SC-RING-END\] pid=(\d+)")


def _parse_ring_dump(lines):
    """Given an iterable of serial-log lines, yield one parsed dump per
    [SC-RING-BEGIN]...[SC-RING-END] block."""
    cur = None
    entries_by_idx = {}
    for ln in lines:
        m = _SC_RING_BEGIN.search(ln)
        if m:
            cur = {
                "pid":         int(m.group(1)),
                "exit_code":   int(m.group(2)),
                "entry_count": int(m.group(3)),
                "entries":     [],
            }
            entries_by_idx = {}
            continue
        if cur is None:
            continue
        m = _SC_RING_LINE.search(ln)
        if m:
            e = {
                "i":    int(m.group(1)),
                "tick": int(m.group(2)),
                "name": m.group(3),
                "rip":  int(m.group(4), 16),
                "a1":   int(m.group(5), 16),
                "a2":   int(m.group(6), 16),
                "a3":   int(m.group(7), 16),
                "a4":   int(m.group(8), 16),
                "a5":   int(m.group(9), 16),
                "a6":   int(m.group(10), 16),
                "ret":  int(m.group(11)),
                "path": None,
                "bytes_hex": None,
                "bytes_len": 0,
            }
            cur["entries"].append(e)
            entries_by_idx[e["i"]] = e
            continue
        m = _SC_RING_PATH.search(ln)
        if m:
            e = entries_by_idx.get(int(m.group(1)))
            if e is not None:
                e["path"] = m.group(2)
            continue
        m = _SC_RING_BYTES.search(ln)
        if m:
            e = entries_by_idx.get(int(m.group(1)))
            if e is not None:
                e["bytes_hex"] = m.group(3)
                e["bytes_len"] = int(m.group(2))
            continue
        m = _SC_RING_END.search(ln)
        if m:
            yield cur
            cur = None
            entries_by_idx = {}
    # If the log ended mid-dump (e.g. kernel panic), yield what we have.
    if cur is not None:
        yield cur


def cmd_scrings(args):
    """Parse syscall ring-buffer dumps from the serial log and emit JSON."""
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]

    dumps = []
    try:
        with Path(serial_log).open("r", errors="replace") as fh:
            for d in _parse_ring_dump(fh):
                dumps.append(d)
    except OSError as e:
        _err(f"could not read serial log: {e}")

    # Optional pid filter.
    pid = getattr(args, "pid", None)
    if pid is not None:
        dumps = [d for d in dumps if d["pid"] == pid]

    # Optional entry-count cap per dump.
    last = getattr(args, "last", None)
    if last is not None and last > 0:
        for d in dumps:
            d["entries"] = d["entries"][-last:]

    _out({"dumps": dumps, "dump_count": len(dumps)})


# ── stack: parse exit-time userspace stack snapshots ─────────────────────────
#
# On non-zero exit the kernel (firefox-test feature) emits:
#
#   [SC-RING-STACK] pid=<N> rsp=<hex> rbp=<hex>
#   [SC-RING-STACK] stack_top=<up-to-256-hex-chars>
#   [SC-RING-STACK] frame[N] rbp=<hex> rip=<hex>
#   ...
#   [SC-RING-STACK-END]
#
# `stack` collects every such block in the serial log and returns a JSON
# array — one object per block — containing pid, rsp, rbp, stack_top_hex,
# and the list of parsed frames.  Frames order matches the kernel's emission
# order (frame[0] = deepest / immediate caller of exit_group).

_STACK_HEADER = re.compile(
    r"\[SC-RING-STACK\] pid=(\d+) rsp=(0x[0-9a-fA-F]+) rbp=(0x[0-9a-fA-F]+)"
)
_STACK_TOP = re.compile(r"\[SC-RING-STACK\] stack_top=([0-9a-fA-F]*)")
_STACK_FRAME = re.compile(
    r"\[SC-RING-STACK\] frame\[(\d+)\] rbp=(0x[0-9a-fA-F]+) rip=(0x[0-9a-fA-F]+)"
)
_STACK_END = re.compile(r"\[SC-RING-STACK-END\]")


def _parse_stack_dumps(lines):
    cur = None
    for ln in lines:
        m = _STACK_HEADER.search(ln)
        if m:
            # Start a fresh block whenever we see a pid/rsp/rbp header.  The
            # stack_top line follows immediately; frames come after.
            cur = {
                "pid":  int(m.group(1)),
                "rsp":  int(m.group(2), 16),
                "rbp":  int(m.group(3), 16),
                "stack_top_hex": None,
                "frames": [],
            }
            continue
        if cur is None:
            continue
        m = _STACK_TOP.search(ln)
        if m:
            cur["stack_top_hex"] = m.group(1)
            continue
        m = _STACK_FRAME.search(ln)
        if m:
            cur["frames"].append({
                "i":   int(m.group(1)),
                "rbp": int(m.group(2), 16),
                "rip": int(m.group(3), 16),
            })
            continue
        if _STACK_END.search(ln):
            yield cur
            cur = None
    if cur is not None:
        yield cur


def cmd_stack(args):
    """Parse exit-time userspace stack snapshots and emit JSON."""
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]
    snapshots = []
    try:
        with Path(serial_log).open("r", errors="replace") as fh:
            for s in _parse_stack_dumps(fh):
                snapshots.append(s)
    except OSError as e:
        _err(f"could not read serial log: {e}")
    pid = getattr(args, "pid", None)
    if pid is not None:
        snapshots = [s for s in snapshots if s["pid"] == pid]
    _out({"snapshots": snapshots, "snapshot_count": len(snapshots)})


# ── ustack: parse periodic [SC-USTACK] snapshots + resolve frames ─────────────
#
# When the kernel is built with `firefox-test`, every Nth `clock_gettime` /
# `gettimeofday` syscall on tid=1 emits one line of the form:
#
#   [SC-USTACK] tid=1 nr=<num> n=<idx> rsp=0x... rbp=0x... leaf=0x... f1=... f2=...
#
# `ustack` collects every such line plus the `[FFTEST/mmap-so]` library-load
# table that precedes it, and resolves each frame address to
# `<library>+<offset>` using simple range arithmetic.  Optional symbol
# resolution via `nm` / `addr2line` (when present on $PATH and the library
# binary is reachable on the host) returns `<symbol>+<offset>` for each frame.
#
# Output: { "load_bases":[...], "snapshots":[ {nr, n, rsp, rbp, leaf, frames:[
#   {rip, library, offset, symbol, file_offset} ]} ] }

_USTACK_LINE = re.compile(
    r"\[SC-USTACK\] pid=(\d+) tid=(\d+) nr=(\d+) n=(\d+) rsp=(0x[0-9a-fA-F]+) "
    r"rbp=(0x[0-9a-fA-F]+) leaf=(0x[0-9a-fA-F]+)(.*)$"
)
_USTACK_FRAME = re.compile(r" f(\d+)=(0x[0-9a-fA-F]+)")
_USTACK_SCAN  = re.compile(r" s(\d+)=(0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+)")
_MMAP_SO = re.compile(
    r"\[FFTEST/mmap-so\] pid=(\d+) base=(0x[0-9a-fA-F]+) "
    r"len=(0x[0-9a-fA-F]+) off=(0x[0-9a-fA-F]+) prot=(0x[0-9a-fA-F]+) "
    r"fd=(\d+) path=(\S+)"
)


def _build_load_base_map(lines):
    """Walk the serial log and collect every library mmap, returning a list of
    {pid, base, end, off, path} ranges.  Multiple LOADs per .so accumulate;
    we use the lowest `base` for each path as the load base."""
    by_path = {}
    for ln in lines:
        m = _MMAP_SO.search(ln)
        if not m: continue
        pid  = int(m.group(1))
        base = int(m.group(2), 16)
        leng = int(m.group(3), 16)
        off  = int(m.group(4), 16)
        path = m.group(7)
        end  = base + leng
        rec  = by_path.setdefault(path, {
            "pid": pid, "path": path, "base": base, "end": end, "off": off,
        })
        if base < rec["base"]: rec["base"] = base
        if end  > rec["end"]:  rec["end"]  = end
    return list(by_path.values())


def _resolve_frame_to_lib(rip, libs):
    """Return (library, offset_from_load_base) or (None, None)."""
    for L in libs:
        if L["base"] <= rip < L["end"]:
            return (L["path"], rip - L["base"])
    return (None, None)


def _try_symbolise(host_path, file_offset):
    """Best-effort: run `nm -D` on host_path, return nearest `<sym>+<delta>`
    where the symbol's file-offset (lowest virt addr in the .so) is <= the
    target offset.  Returns None if `nm` fails or no host file is present."""
    if not host_path or not Path(host_path).exists(): return None
    import subprocess
    try:
        out = subprocess.check_output(
            ["nm", "--defined-only", "-D", "--no-demangle", host_path],
            stderr=subprocess.DEVNULL, timeout=10,
        ).decode("utf-8", errors="replace")
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    best_sym, best_addr = None, -1
    for line in out.splitlines():
        # Format: "0000000000123abc T some_symbol"
        parts = line.split(maxsplit=2)
        if len(parts) < 3: continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        if addr <= file_offset and addr > best_addr:
            best_addr, best_sym = addr, parts[2]
    if best_sym is None: return None
    return f"{best_sym}+{file_offset - best_addr:#x}"


def _resolve_path_on_host(guest_path, disk_root=None):
    """Map a guest path like /opt/firefox/libxul.so to a host path under
    `disk_root` (default: ./build/disk and ./build).  Returns the first match
    that exists on the host, or None.

    Passing an explicit `disk_root` makes resolution independent of the
    process's current working directory — useful when the harness is being
    driven from outside the repo root, or when several disk staging
    directories coexist (e.g. firefox-test vs the default test-mode disk).
    """
    candidates = []
    rel = guest_path.lstrip("/")
    if disk_root:
        root = Path(disk_root)
        candidates.append(root / rel)
        # Permit `--disk-root build/disk` to resolve `/opt/x` to
        # `build/disk/opt/x` AND `--disk-root build` to resolve `/disk/opt/x`
        # to `build/disk/opt/x`; either flag spelling works.
        candidates.append(root / "disk" / rel)
    candidates.extend([
        Path("build/disk") / rel,
        Path("build") / rel,
        Path(guest_path),
    ])
    for c in candidates:
        if c.exists(): return str(c)
    return None


def cmd_ustack(args):
    """Parse [SC-USTACK] snapshots and resolve frames against [FFTEST/mmap-so]."""
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]

    try:
        text = Path(serial_log).read_text(errors="replace")
    except OSError as e:
        _err(f"could not read serial log: {e}")
        return
    lines = text.splitlines()

    libs = _build_load_base_map(lines)
    libs.sort(key=lambda L: L["base"])
    do_syms = bool(getattr(args, "symbolise", False))
    disk_root = getattr(args, "disk_root", None)

    snapshots = []
    for ln in lines:
        m = _USTACK_LINE.search(ln)
        if not m: continue
        pid  = int(m.group(1))
        tid  = int(m.group(2))
        nr   = int(m.group(3))
        n    = int(m.group(4))
        rsp  = int(m.group(5), 16)
        rbp  = int(m.group(6), 16)
        leaf = int(m.group(7), 16)
        frame_text = m.group(8) or ""
        frames = [(0, leaf, "leaf")]
        for fm in _USTACK_FRAME.finditer(frame_text):
            frames.append((int(fm.group(1)), int(fm.group(2), 16), "rbp"))
        # Scan candidates: only keep words that resolve to a known mapped
        # library — drops random user-data words that happen to look like
        # code addresses but aren't return addresses.
        for sm in _USTACK_SCAN.finditer(frame_text):
            soff = int(sm.group(2), 16)
            sval = int(sm.group(3), 16)
            lib, off = _resolve_frame_to_lib(sval, libs)
            if lib is not None:
                # Index the scan slot using its stack offset (in 8-byte words)
                # so multiple snapshots are comparable across runs.
                frames.append((soff // 8, sval, "scan"))

        resolved = []
        for (idx, rip, kind) in frames:
            lib, off = _resolve_frame_to_lib(rip, libs)
            entry = {
                "i": idx, "kind": kind, "rip": f"{rip:#x}",
                "library": lib, "offset": (f"{off:#x}" if off is not None else None),
                "symbol": None,
            }
            if do_syms and lib is not None:
                host = _resolve_path_on_host(lib, disk_root=disk_root)
                sym = _try_symbolise(host, off) if host else None
                entry["symbol"] = sym
                entry["host_path"] = host
            resolved.append(entry)

        snapshots.append({
            "pid": pid, "tid": tid, "nr": nr, "n": n,
            "rsp": f"{rsp:#x}", "rbp": f"{rbp:#x}",
            "frames": resolved,
        })

    if getattr(args, "pid", None) is not None:
        snapshots = [s for s in snapshots if s["pid"] == args.pid]
    if getattr(args, "tid", None) is not None:
        snapshots = [s for s in snapshots if s["tid"] == args.tid]
    if getattr(args, "nr", None) is not None:
        snapshots = [s for s in snapshots if s["nr"] == args.nr]

    _out({
        "load_bases": [
            {"path": L["path"], "base": f"{L['base']:#x}", "end": f"{L['end']:#x}"}
            for L in libs
        ],
        "snapshots": snapshots,
        "snapshot_count": len(snapshots),
    })


# ══════════════════════════════════════════════════════════════════════════════
# rip-sample — sampling profiler for kernel + user RIP via QMP stop / GDB g
# ══════════════════════════════════════════════════════════════════════════════
#
# Pause QEMU via QMP, read RIP/RSP from each vCPU via the GDB stub, resume,
# repeat.  Symbolises kernel RIPs against the kernel ELF and user RIPs against
# the [FFTEST/mmap-so] load-base table parsed from the serial log.  Output is
# a fully-resolved sample list plus a by_symbol histogram so the dominant
# spin function falls out for free.

# Lower bound of the higher-half kernel virtual address space.  Anything
# >= this is treated as a kernel RIP for symbolisation.
_KERNEL_VMA_BASE = 0xFFFF_8000_0000_0000


def _build_kernel_symtab(elf_path: Path) -> list[tuple[int, int, str]]:
    """Extract (addr, size, name) for STT_FUNC symbols from the kernel ELF.
    Sorted by address so a binary search finds the enclosing function."""
    syms: list[tuple[int, int, str]] = []
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        return syms
    if not elf_path.exists():
        return syms
    with elf_path.open("rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC":
                    continue
                addr = sym["st_value"]
                size = sym["st_size"]
                if addr == 0:
                    continue
                syms.append((addr, size, sym.name))
    syms.sort(key=lambda t: t[0])
    return syms


_USER_SYMTAB_CACHE: dict[str, list[tuple[int, int, str]]] = {}


def _resolve_kernel_rip(rip: int, syms: list[tuple[int, int, str]]) -> Optional[str]:
    """Bisect into the sorted symbol list; return 'name+0xN' or None."""
    if not syms:
        return None
    import bisect
    idx = bisect.bisect_right([s[0] for s in syms], rip) - 1
    if idx < 0:
        return None
    addr, size, name = syms[idx]
    delta = rip - addr
    # Tolerate symbols with size==0 (some asm symbols) up to a 4 KiB window.
    upper = size if size > 0 else 0x1000
    if delta >= upper:
        return None
    return f"{name}+{delta:#x}"


def _user_lib_symtab(host_path: str) -> list[tuple[int, int, str]]:
    """Extract STT_FUNC (and STT_NOTYPE) dynamic symbols from a userspace
    .so / executable.  Cached per-host_path via _USER_SYMTAB_CACHE."""
    cache = _USER_SYMTAB_CACHE
    if host_path in cache:
        return cache[host_path]
    syms: list[tuple[int, int, str]] = []
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        with open(host_path, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                for sym in sec.iter_symbols():
                    addr = sym["st_value"]
                    if addr == 0:
                        continue
                    syms.append((addr, sym["st_size"], sym.name))
    except Exception:
        syms = []
    syms.sort(key=lambda t: t[0])
    cache[host_path] = syms
    return syms


def _resolve_user_rip(rip: int, libs: list, disk_root: Optional[str]) -> Optional[dict]:
    """Resolve a userspace RIP against the [FFTEST/mmap-so] load-base table.
    Returns {library, offset, symbol} or None if outside any mapping."""
    lib_path, off = _resolve_frame_to_lib(rip, libs)
    if lib_path is None:
        return None
    host = _resolve_path_on_host(lib_path, disk_root=disk_root)
    sym = None
    if host:
        # First try the cached pyelftools symtab (handles static + dynamic).
        elf_syms = _user_lib_symtab(host)
        if elf_syms:
            import bisect
            idx = bisect.bisect_right([s[0] for s in elf_syms], off) - 1
            if idx >= 0:
                a, sz, name = elf_syms[idx]
                delta = off - a
                upper = sz if sz > 0 else 0x10000
                if delta < upper:
                    sym = f"{name}+{delta:#x}"
        # Fall back to nm on the host file (covers stripped binaries' .dynsym).
        if sym is None:
            sym = _try_symbolise(host, off)
    return {
        "library": lib_path,
        "offset":  f"{off:#x}",
        "symbol":  sym,
    }


def cmd_rip_sample(args):
    """Pause/resume QEMU N times; read RIP per vCPU each time; symbolise.

    Output schema:
      {
        "sample_count": <N * vcpu_count>,
        "vcpu_count":   <int>,
        "interval_ms":  <int>,
        "samples":      [{"i":i, "cpu":n, "rip":hex, "rsp":hex,
                          "domain":"kernel|user|unknown",
                          "symbol":str|null, "library":str|null}, ...],
        "by_symbol":    {"<name>": <count>, ...},  # top-level histogram
        "by_domain":    {"kernel":N, "user":N, "unknown":N},
      }
    """
    sess     = _load_session(args.sid)
    qmp_sock = sess["qmp_sock"]
    port     = _get_gdb_port(sess)

    count       = max(1, int(args.count))
    interval_ms = max(0, int(args.interval_ms))
    disk_root   = getattr(args, "disk_root", None)

    # The GDB stub keeps server-side selected-thread state across packets
    # (Hg<tid>), so two concurrent invocations against the same sid would
    # race.  Take an advisory file lock across the GDB-stub session — the
    # kdb subcommand uses the same stub, so other consumers will block
    # while sampling is in progress instead of corrupting thread state.
    import fcntl
    lock_path = HARNESS_DIR / f"{args.sid}.gdb.lock"
    lock_fd = open(lock_path, "w")
    try:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_fd.close()
        _err(f"GDB stub for sid {args.sid} is busy (held by another "
             f"qemu-harness.py process). Retry once it exits.")

    # Build symbolisation tables once up-front.
    kernel_elf = _get_kernel_elf()
    kernel_syms = _build_kernel_symtab(kernel_elf)

    serial_log = sess["serial_log"]
    try:
        log_lines = Path(serial_log).read_text(errors="replace").splitlines()
    except OSError:
        log_lines = []
    libs = _build_load_base_map(log_lines)

    # One persistent GDB connection across all iterations — handshake is
    # expensive (the stub re-queries supported features on each connect).
    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        _err(f"Cannot connect to GDB stub on port {port} (tried {port}..{port+4})")

    samples: list[dict] = []
    by_symbol: dict[str, int] = {}
    by_domain = {"kernel": 0, "user": 0, "unknown": 0}

    try:
        threads = gdb.list_threads()
        if not threads:
            # Stub doesn't enumerate threads — sample the current CPU only.
            threads = [0]
        for i in range(count):
            # QMP stop is the canonical way to freeze all vCPUs atomically.
            stop_resp = _qmp_command(qmp_sock, "stop", connect_timeout=2.0)
            if "error" in stop_resp:
                _err(f"QMP stop failed: {stop_resp['error']}")
            try:
                for tid in threads:
                    if tid:
                        gdb.select_thread(tid)
                    try:
                        regs = gdb.read_regs()
                    except Exception as e:
                        regs = {"rip": "0x0", "rsp": "0x0", "_err": str(e)}
                    rip = int(regs.get("rip", "0x0"), 16)
                    rsp = int(regs.get("rsp", "0x0"), 16)
                    domain = "unknown"
                    library = None
                    symbol  = None
                    if rip >= _KERNEL_VMA_BASE:
                        domain = "kernel"
                        symbol = _resolve_kernel_rip(rip, kernel_syms)
                    elif rip != 0:
                        ur = _resolve_user_rip(rip, libs, disk_root)
                        if ur is not None:
                            domain  = "user"
                            library = ur["library"]
                            symbol  = ur["symbol"]
                    by_domain[domain] += 1
                    key = symbol or f"<unresolved {domain} {rip:#x}>"
                    by_symbol[key] = by_symbol.get(key, 0) + 1
                    samples.append({
                        "i":      i,
                        "cpu":    tid,
                        "rip":    f"{rip:#x}",
                        "rsp":    f"{rsp:#x}",
                        "domain": domain,
                        "symbol": symbol,
                        "library": library,
                    })
            finally:
                # Always resume — never leave the guest paused on error.
                _qmp_command(qmp_sock, "cont", connect_timeout=2.0)
            if i + 1 < count and interval_ms > 0:
                time.sleep(interval_ms / 1000.0)
    finally:
        gdb.close()
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
        finally:
            lock_fd.close()

    # Sorted top-K histogram for a compact agent-readable summary.
    top_k = sorted(by_symbol.items(), key=lambda kv: -kv[1])[:20]

    _out({
        "ok":           True,
        "sample_count": len(samples),
        "vcpu_count":   len(threads),
        "interval_ms":  interval_ms,
        "by_domain":    by_domain,
        "by_symbol":    dict(top_k),
        "samples":      samples,
    })

# ══════════════════════════════════════════════════════════════════════════════
# parked-tids — characterise threads parked in futex_wait via serial-log scan
# ══════════════════════════════════════════════════════════════════════════════
#
# Phase-12 fallback for environments where the kdb hostfwd is unreliable
# (WSL2 + slirp + e1000: inbound TCP can stall behind QEMU's flush_queue_timer
# coalescer).  Reads `[FUTEX_WAIT_REG] tid=… uaddr=… rip=… rsp=… rbp=…`
# lines from the serial log, keeps the most-recent registration per tid, and
# resolves each rip against the `[FFTEST/mmap-so]` load-base table.
#
# To classify a tid as "still parked" we cross-check `[FUTEX_WAKE]`: any wake
# directed at the tid's last-registered uaddr that woke ≥1 waiter is taken as
# evidence that the tid likely re-entered the run-queue (best-effort — a wake
# may have hit a different waiter on the same uaddr).
#
# Output: { "tids":[{tid, uaddr, op, rip, library, symbol, parked}],
#           "by_signature":{<library:symbol>: [tids…]} }
_FUTEX_WAIT_REG_RICH = re.compile(
    r"\[FUTEX_WAIT_REG\] tid=(\d+) pid=(\d+) uaddr=(0x[0-9a-fA-F]+) "
    r"val=\d+ op=(0x[0-9a-fA-F]+) rip=(0x[0-9a-fA-F]+) "
    r"rsp=(0x[0-9a-fA-F]+) rbp=(0x[0-9a-fA-F]+)"
)
_FUTEX_WAKE_RE = re.compile(
    r"\[FUTEX_WAKE\] tid=\d+ pid=\d+ uaddr=(0x[0-9a-fA-F]+) woken=(\d+)"
)
# Phase-17 stack-walk markers — emitted by the kernel at futex_wait entry
# alongside FUTEX_WAIT_REG.  WAIT_STACK is the rbp-chain walk (up to 7
# frames); WAIT_SCAN is the raw u64 stack window for cases where the chain
# dies inside libc/libxul (callees built with -fomit-frame-pointer).
_FUTEX_WAIT_STACK_RE = re.compile(
    r"\[FUTEX_WAIT_STACK\] tid=(\d+) pid=\d+ uaddr=0x[0-9a-fA-F]+ "
    r"leaf=(0x[0-9a-fA-F]+)(.*)"
)
_FUTEX_WAIT_SCAN_RE = re.compile(
    r"\[FUTEX_WAIT_SCAN\] tid=(\d+) pid=\d+ rsp=(0x[0-9a-fA-F]+)(.*)"
)
_FRAME_RE = re.compile(r" f(\d+)=(0x[0-9a-fA-F]+)")
_SCAN_WORD_RE = re.compile(r" w(\d+)=(0x[0-9a-fA-F]+)")

def cmd_parked_stacks(args):
    """Phase-17 deep stack walk for parked tids.

    Combines the latest [FUTEX_WAIT_REG] (uaddr/op/rip), [FUTEX_WAIT_STACK]
    (rbp-chain frames f1..f7) and [FUTEX_WAIT_SCAN] (128 u64 stack words)
    records per tid and resolves every frame against the [FFTEST/mmap-so]
    load-base table plus the host-side .so symbol tables.  The scan-word
    pass is critical because Mozilla libraries are built with
    -fomit-frame-pointer — the rbp chain dies after 1-3 frames inside
    libc, but the actual libxul/libnspr return addresses live on the stack
    and can be recovered by treating any u64 that lands in a known mapped
    .text segment as a candidate return address.

    Output schema:
      { "tids":[{tid, pid, uaddr, op, leaf, rbp_chain:[{rip, library,
        offset, symbol}], scan_hits:[{idx, rip, library, offset, symbol}]
        }], "tid_count": N, "parked_count": M }

    The post-processor in this subcommand only reports SCAN words that
    resolve to a non-libc, non-libpthread library — those are the
    user-code return addresses that identify the wedge's call chain.
    """
    sess = _load_session(args.sid)
    try:
        lines = Path(sess["serial_log"]).read_text(errors="replace").splitlines()
    except OSError as e:
        _err(f"could not read serial log: {e}")
    libs = _build_load_base_map(lines)
    disk_root = getattr(args, "disk_root", None)
    # Reuse the parked-tids state-machine for "is this tid currently parked?"
    last_reg: dict[int, dict] = {}
    last_stack: dict[int, dict] = {}
    last_scan: dict[int, dict] = {}
    waked_uaddrs: set[str] = set()
    for ln in lines:
        m = _FUTEX_WAIT_REG_RICH.search(ln)
        if m:
            tid = int(m.group(1))
            last_reg[tid] = {
                "tid": tid, "pid": int(m.group(2)), "uaddr": m.group(3),
                "op": m.group(4),
                "rip": int(m.group(5), 16), "rsp": int(m.group(6), 16),
                "rbp": int(m.group(7), 16),
            }
            continue
        m = _FUTEX_WAIT_STACK_RE.search(ln)
        if m:
            tid = int(m.group(1)); leaf = int(m.group(2), 16)
            frames = [(int(i), int(v, 16)) for i, v in
                      _FRAME_RE.findall(m.group(3))]
            last_stack[tid] = {"leaf": leaf, "frames": frames}
            continue
        m = _FUTEX_WAIT_SCAN_RE.search(ln)
        if m:
            tid = int(m.group(1)); rsp = int(m.group(2), 16)
            words = [(int(i), int(v, 16)) for i, v in
                     _SCAN_WORD_RE.findall(m.group(3))]
            last_scan[tid] = {"rsp": rsp, "words": words}
            continue
        w = _FUTEX_WAKE_RE.search(ln)
        if w and int(w.group(2)) > 0:
            waked_uaddrs.add(w.group(1))

    rows: list[dict] = []
    for tid in sorted(last_reg):
        r = last_reg[tid]
        parked = r["uaddr"] not in waked_uaddrs
        # rbp-chain frames
        rbp_chain = []
        if tid in last_stack:
            for i, rip in last_stack[tid]["frames"]:
                ur = _resolve_user_rip(rip, libs, disk_root)
                rbp_chain.append({
                    "i": i, "rip": f"{rip:#x}",
                    "library": (ur or {}).get("library"),
                    "offset":  (ur or {}).get("offset"),
                    "symbol":  (ur or {}).get("symbol"),
                })
        # Scan-word hits filtered to non-libc libraries
        scan_hits = []
        if tid in last_scan:
            for idx, rip in last_scan[tid]["words"]:
                ur = _resolve_user_rip(rip, libs, disk_root)
                if not ur: continue
                lib = ur["library"] or ""
                # Filter out libc/libpthread/ld — the caller is interested
                # in libxul/libnspr/libmoz*/libnss* return addresses.
                bn = Path(lib).name if lib else ""
                if bn.startswith("libc.") or bn.startswith("libpthread.") \
                   or bn.startswith("ld-") or bn.startswith("libstdc++"):
                    continue
                scan_hits.append({
                    "idx": idx, "rip": f"{rip:#x}",
                    "library": lib, "offset": ur.get("offset"),
                    "symbol":  ur.get("symbol"),
                })
        leaf = last_stack.get(tid, {}).get("leaf")
        rows.append({
            "tid": tid, "pid": r["pid"], "uaddr": r["uaddr"],
            "op": r["op"], "parked": parked,
            "leaf": (f"{leaf:#x}" if leaf else None),
            "rbp_chain": rbp_chain,
            "scan_hits": scan_hits,
        })

    _out({
        "ok": True,
        "tid_count": len(rows),
        "parked_count": sum(1 for r in rows if r["parked"]),
        "tids": rows,
    })


def cmd_parked_tids(args):
    sess = _load_session(args.sid)
    try:
        lines = Path(sess["serial_log"]).read_text(errors="replace").splitlines()
    except OSError as e:
        _err(f"could not read serial log: {e}")
    libs = _build_load_base_map(lines)
    disk_root = getattr(args, "disk_root", None)

    # Latest registration per tid (parked tids re-enter futex_wait several
    # times before the system reaches steady state; the last entry tells us
    # where the tid has *currently* settled).
    last_reg: dict[int, dict] = {}
    waked_uaddrs: set[str] = set()
    for ln in lines:
        m = _FUTEX_WAIT_REG_RICH.search(ln)
        if m:
            tid = int(m.group(1))
            last_reg[tid] = {
                "tid":   tid,
                "pid":   int(m.group(2)),
                "uaddr": m.group(3),
                "op":    m.group(4),
                "rip":   int(m.group(5), 16),
                "rsp":   int(m.group(6), 16),
                "rbp":   int(m.group(7), 16),
            }
            continue
        w = _FUTEX_WAKE_RE.search(ln)
        if w and int(w.group(2)) > 0:
            waked_uaddrs.add(w.group(1))

    rows: list[dict] = []
    by_signature: dict[str, list[int]] = {}
    for tid in sorted(last_reg):
        r = last_reg[tid]
        ur = _resolve_user_rip(r["rip"], libs, disk_root) if r["rip"] else None
        sig_lib = (ur or {}).get("library") or "<unresolved>"
        sig_sym = (ur or {}).get("symbol")  or f"<rip {r['rip']:#x}>"
        sig = f"{Path(sig_lib).name}:{sig_sym}"
        # Heuristic: a tid is "likely parked" if its last-registered uaddr
        # never appears with woken≥1.  Imperfect (wakes may target a sibling
        # waiter on the same uaddr) but matches the Phase-11 methodology.
        parked = r["uaddr"] not in waked_uaddrs
        rows.append({
            "tid":      tid,
            "pid":      r["pid"],
            "uaddr":    r["uaddr"],
            "op":       r["op"],
            "rip":      f"{r['rip']:#x}",
            "rsp":      f"{r['rsp']:#x}",
            "rbp":      f"{r['rbp']:#x}",
            "library":  (ur or {}).get("library"),
            "offset":   (ur or {}).get("offset"),
            "symbol":   (ur or {}).get("symbol"),
            "parked":   parked,
        })
        if parked:
            by_signature.setdefault(sig, []).append(tid)

    _out({
        "ok":           True,
        "tid_count":    len(rows),
        "parked_count": sum(1 for r in rows if r["parked"]),
        "tids":         rows,
        "by_signature": by_signature,
    })


# ══════════════════════════════════════════════════════════════════════════════
# wake-attempts — diff attempted-wake uaddrs against still-parked uaddrs
# ══════════════════════════════════════════════════════════════════════════════
#
# Reads `[FUTEX_WAKE_REQ]` (every WAKE attempt at handler entry, regardless of
# match) and `[FUTEX_WAIT_REG]` (every futex_wait registration) and classifies
# the missing-wakeup mode:
#
#   parked_only          uaddr appears in WAIT_REG (latest per tid) but never in
#                        WAKE_REQ → Branch A: wake call site never reached.
#   attempted_and_matched uaddr in BOTH → wake handler ran but waiter wasn't
#                        queued (race) or the kernel match logic differs.
#   attempted_only       uaddr in WAKE_REQ only → diagnostic noise (already-
#                        woken or pre-wait wake).
#   near_misses          for each parked_only uaddr, attempted uaddrs within
#                        ±0x100 → Branch B: cond-var struct relocated.
#
# Branch classification (downstream automation should rely on these exact
# rules — the prose summary in any commit/PR text may be looser):
#
#   "A"     n_parked > 0 AND n_matched == 0 AND no near_misses
#           — no wake ever reaches a parked uaddr or any neighbour
#   "B"     near_misses present AND n_matched == 0
#           — wakes go to addresses adjacent to parked uaddrs but never
#             directly hit them; cond-var-relocation pattern
#   "none"  n_parked == 0
#           — nothing parked; this snapshot doesn't show a missing-wake bug
#   "mixed" otherwise (any combination not covered above; in particular
#           any non-empty matched_set falls here)
#
# Output: `{branch:"A"|"B"|"none"|"mixed", parked_only:[...],
#           attempted_and_matched:[...], near_misses:[...]}`
_FUTEX_WAKE_REQ_RE = re.compile(
    r"\[FUTEX_WAKE_REQ\] tid=(\d+) pid=(\d+) uaddr=(0x[0-9a-fA-F]+) "
    r"max=\d+ op=(0x[0-9a-fA-F]+) rip=(0x[0-9a-fA-F]+)"
)

def cmd_wake_attempts(args):
    sess = _load_session(args.sid)
    try:
        lines = Path(sess["serial_log"]).read_text(errors="replace").splitlines()
    except OSError as e:
        _err(f"could not read serial log: {e}")
    libs = _build_load_base_map(lines)
    disk_root = getattr(args, "disk_root", None)

    # Replicate parked-tids logic to derive the still-parked uaddr set.
    last_reg: dict[int, dict] = {}
    waked_uaddrs: set[str] = set()
    attempted: dict[str, dict] = {}  # uaddr -> first-seen attempt sample
    attempted_count: dict[str, int] = {}
    for ln in lines:
        m = _FUTEX_WAIT_REG_RICH.search(ln)
        if m:
            last_reg[int(m.group(1))] = {
                "tid":   int(m.group(1)),
                "uaddr": m.group(3),
                "rip":   int(m.group(5), 16),
            }
            continue
        w = _FUTEX_WAKE_RE.search(ln)
        if w and int(w.group(2)) > 0:
            waked_uaddrs.add(w.group(1))
            continue
        a = _FUTEX_WAKE_REQ_RE.search(ln)
        if a:
            ua = a.group(3)
            attempted_count[ua] = attempted_count.get(ua, 0) + 1
            if ua not in attempted:
                attempted[ua] = {
                    "uaddr": ua,
                    "tid":   int(a.group(1)),
                    "op":    a.group(4),
                    "rip":   int(a.group(5), 16),
                }

    parked_uaddrs: dict[str, list[int]] = {}
    for tid, r in last_reg.items():
        if r["uaddr"] not in waked_uaddrs:
            parked_uaddrs.setdefault(r["uaddr"], []).append(tid)

    parked_set = set(parked_uaddrs.keys())
    attempted_set = set(attempted.keys())

    parked_only_set = parked_set - attempted_set
    matched_set = parked_set & attempted_set
    attempted_only_set = attempted_set - parked_set

    def _att_row(ua: str) -> dict:
        a = attempted[ua]
        ur = _resolve_user_rip(a["rip"], libs, disk_root) if a["rip"] else None
        return {
            "uaddr":   ua,
            "count":   attempted_count[ua],
            "op":      a["op"],
            "tid":     a["tid"],
            "rip":     f"{a['rip']:#x}",
            "library": (ur or {}).get("library"),
            "symbol":  (ur or {}).get("symbol"),
            "offset":  (ur or {}).get("offset"),
        }

    def _parked_row(ua: str) -> dict:
        tids = parked_uaddrs[ua]
        sample_tid = tids[0]
        rip = last_reg[sample_tid]["rip"]
        ur = _resolve_user_rip(rip, libs, disk_root) if rip else None
        return {
            "uaddr":   ua,
            "tids":    sorted(tids),
            "rip":     f"{rip:#x}",
            "library": (ur or {}).get("library"),
            "symbol":  (ur or {}).get("symbol"),
            "offset":  (ur or {}).get("offset"),
        }

    # Branch B near-miss heuristic: glibc's __pthread_cond_broadcast may target
    # a uaddr offset by a few bytes from the cond-var's wait-uaddr (cond-var
    # struct layout — the seq counter sits adjacent to the futex word).  Scan
    # ±0x100 for visual alignment with that pattern.
    near_misses: list[dict] = []
    parked_ints = {ua: int(ua, 16) for ua in parked_only_set}
    attempted_ints = {ua: int(ua, 16) for ua in attempted_set}
    for pua, pi in parked_ints.items():
        nearby = []
        for aua, ai in attempted_ints.items():
            d = ai - pi
            if -0x100 <= d <= 0x100 and d != 0:
                nearby.append({"attempted_uaddr": aua, "delta": d,
                               "count": attempted_count[aua]})
        if nearby:
            nearby.sort(key=lambda r: abs(r["delta"]))
            near_misses.append({
                "parked_uaddr": pua,
                "parked_tids":  sorted(parked_uaddrs[pua]),
                "nearby":       nearby[:8],
            })

    parked_only = sorted(
        (_parked_row(ua) for ua in parked_only_set),
        key=lambda r: -len(r["tids"]),
    )
    attempted_and_matched = sorted(
        (_att_row(ua) for ua in matched_set),
        key=lambda r: -r["count"],
    )
    attempted_only = sorted(
        (_att_row(ua) for ua in attempted_only_set),
        key=lambda r: -r["count"],
    )

    n_parked = len(parked_only_set)
    n_matched = len(matched_set)
    if n_parked > 0 and n_matched == 0 and not near_misses:
        branch = "A"   # No wake ever reaches a parked uaddr or any neighbour.
    elif near_misses and not matched_set:
        branch = "B"   # Wakes go to addresses adjacent to parked uaddrs.
    elif n_parked == 0:
        branch = "none"  # Nothing parked → no missing-wake bug here.
    else:
        branch = "mixed"

    _out({
        "ok":                       True,
        "branch":                   branch,
        "summary": {
            "parked_uaddr_count":    len(parked_set),
            "attempted_uaddr_count": len(attempted_set),
            "parked_only":           n_parked,
            "attempted_and_matched": n_matched,
            "attempted_only":        len(attempted_only_set),
            "near_miss_count":       len(near_misses),
            "wake_req_total":        sum(attempted_count.values()),
        },
        "parked_only":           parked_only,
        "attempted_and_matched": attempted_and_matched,
        "attempted_only":        attempted_only[:32],
        "near_misses":           near_misses,
    })


# ══════════════════════════════════════════════════════════════════════════════
# read-png — extract a PNG screenshot from the guest via serial base64
# ══════════════════════════════════════════════════════════════════════════════
#
# Protocol emitted by the kernel's test_gdi_png_screenshot (Test 198):
#
#   [SCREENSHOT-B64:N/M] <76-char base64 chunk>   (N = 0-based index, M = total)
#   [SCREENSHOT-B64-END]
#
# This subcommand:
#   1. Waits for the first [SCREENSHOT-B64:0/M] line (up to --timeout-ms).
#   2. Scans the serial log for all M chunks (0..M-1) in order.
#   3. Validates the chunk count matches M.
#   4. Decodes the concatenated base64 (RFC 4648 §4) and writes to <dst>.
#   5. Verifies the PNG signature (8-byte magic, W3C PNG §5.2).
#   6. Prints JSON: {"ok": true, "path": dst, "bytes": N, "chunks": M}
#      or {"ok": false, "error": "...", ...} on failure.
#
# Output is additive to the existing [SCREENSHOT] summary line — Test 198
# continues to PASS regardless of whether read-png was waiting.

_B64_FIRST_RE = re.compile(
    r"\[SCREENSHOT-B64:0/(\d+)\]\s+([A-Za-z0-9+/=]+)"
)
_B64_CHUNK_RE = re.compile(
    r"\[SCREENSHOT-B64:(\d+)/(\d+)\]\s+([A-Za-z0-9+/=]+)"
)
_B64_END_RE = re.compile(r"\[SCREENSHOT-B64-END\]")

_PNG_SIGNATURE = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


def cmd_read_png(args):
    """
    Collect base64-encoded PNG chunks from the serial log and write to <dst>.

    Waits for the first [SCREENSHOT-B64:0/M] line, then scans for all M chunks,
    decodes, verifies the PNG signature, and writes to args.dst.
    """
    import base64

    sess       = _load_session(args.sid)
    serial_log = sess["serial_log"]
    dst        = args.dst
    timeout_ms = args.timeout_ms

    # ── 1. Wait for the first chunk (index 0) ─────────────────────────────────
    deadline = time.monotonic() + timeout_ms / 1000.0
    total_chunks: Optional[int] = None
    first_chunk: Optional[str]  = None
    file_pos = 0

    while time.monotonic() < deadline:
        try:
            with open(serial_log, "r", errors="replace") as fh:
                fh.seek(file_pos)
                chunk = fh.read(131072)
        except OSError:
            time.sleep(0.1)
            continue

        if chunk:
            for ln in chunk.splitlines():
                m = _B64_FIRST_RE.search(ln)
                if m:
                    total_chunks = int(m.group(1))
                    first_chunk  = m.group(2)
                    break
            file_pos += len(chunk.encode("utf-8", errors="replace"))

        if first_chunk is not None:
            break

        # Check if QEMU has already exited (no point waiting further).
        pid = sess.get("pid", 0)
        if pid and not _pid_alive(pid):
            break

        time.sleep(0.1)

    if first_chunk is None or total_chunks is None:
        _err(f"read-png: timed out waiting for [SCREENSHOT-B64:0/M] "
             f"(waited {timeout_ms} ms). Is the session running test-mode?")

    # ── 2. Collect all M chunks from the serial log ───────────────────────────
    # We have chunk 0 already. Scan the full log for chunks 0..M-1 in case
    # some arrived before we started (serial log is append-only; we can always
    # re-scan from the beginning).
    chunks: dict[int, str] = {0: first_chunk}

    # Allow extra time for the remaining chunks (the PNG is ~77 KB → ~1370 lines
    # at 115200 baud ≈ 10 s; we give 2× margin).
    collect_deadline = time.monotonic() + 30.0

    while len(chunks) < total_chunks and time.monotonic() < collect_deadline:
        try:
            with open(serial_log, "r", errors="replace") as fh:
                for ln in fh:
                    m = _B64_CHUNK_RE.search(ln)
                    if m:
                        idx = int(m.group(1))
                        tot = int(m.group(2))
                        b64 = m.group(3)
                        if tot == total_chunks and idx < total_chunks:
                            chunks[idx] = b64
        except OSError:
            pass

        if len(chunks) < total_chunks:
            # Still missing some chunks — wait briefly and rescan.
            pid = sess.get("pid", 0)
            if pid and not _pid_alive(pid):
                # QEMU exited; do one final rescan below.
                break
            time.sleep(0.2)

    # Final rescan after QEMU may have exited.
    if len(chunks) < total_chunks:
        try:
            with open(serial_log, "r", errors="replace") as fh:
                for ln in fh:
                    m = _B64_CHUNK_RE.search(ln)
                    if m:
                        idx = int(m.group(1))
                        tot = int(m.group(2))
                        b64 = m.group(3)
                        if tot == total_chunks and idx < total_chunks:
                            chunks[idx] = b64
        except OSError:
            pass

    # ── 3. Validate chunk count ────────────────────────────────────────────────
    missing = [i for i in range(total_chunks) if i not in chunks]
    if missing:
        _out({
            "ok":          False,
            "error":       "missing_chunks",
            "total":       total_chunks,
            "received":    len(chunks),
            "missing":     missing[:20],
        })
        sys.exit(1)

    # ── 4. Decode base64 ─────────────────────────────────────────────────────
    b64_concat = "".join(chunks[i] for i in range(total_chunks))
    try:
        png_bytes = base64.b64decode(b64_concat, validate=True)
    except Exception as exc:
        _out({
            "ok":    False,
            "error": f"base64_decode_failed: {exc}",
            "chunks": total_chunks,
        })
        sys.exit(1)

    # ── 5. Verify PNG signature ────────────────────────────────────────────────
    if len(png_bytes) < 8 or png_bytes[:8] != _PNG_SIGNATURE:
        got = png_bytes[:8].hex() if len(png_bytes) >= 8 else png_bytes.hex()
        _out({
            "ok":    False,
            "error": "png_signature_mismatch",
            "got":   got,
            "expected": _PNG_SIGNATURE.hex(),
            "chunks": total_chunks,
            "bytes":  len(png_bytes),
        })
        sys.exit(1)

    # ── 6. Write to dst ───────────────────────────────────────────────────────
    dst_path = Path(dst)
    try:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        dst_path.write_bytes(png_bytes)
    except OSError as exc:
        _out({
            "ok":    False,
            "error": f"write_failed: {exc}",
            "path":  dst,
        })
        sys.exit(1)

    _out({
        "ok":     True,
        "path":   str(dst_path.resolve()),
        "bytes":  len(png_bytes),
        "chunks": total_chunks,
    })


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
                          help="Kernel feature flags passed VERBATIM to cargo "
                               "(comma-separated, e.g. 'test-mode,kdb'). "
                               "Empty string → default desktop kernel. "
                               "Nothing is injected silently.")
    p_start.add_argument("--no-build", action="store_true",
                          help="Skip cargo build; use existing kernel.bin")
    p_start.add_argument("--gdb-port", type=int, default=0, metavar="PORT",
                          help="Enable GDB stub on TCP PORT (0=off). "
                               "GdbClient will back off to PORT+1..PORT+4 on conflict.")
    p_start.add_argument("--gdb-wait", action="store_true",
                          help="Start QEMU frozen (-S); debugger must 'cont' to unfreeze")
    p_start.add_argument("--no-kvm", dest="no_kvm", action="store_true",
                          help="[DEPRECATED] Force-disable KVM acceleration. "
                               "Use only to reproduce a TCG-only environment or "
                               "on hosts without /dev/kvm. A 10-trial soak "
                               "(W139, 2026-05-13) showed KVM reaches 58%% more "
                               "syscalls and hit quit-application-granted 3/5 vs "
                               "0/5 for TCG — avoid this flag for firefox-test "
                               "unless you have a specific TCG regression to chase.")
    p_start.add_argument("--kvm", dest="force_kvm", action="store_true",
                          help="Force-enable KVM acceleration. Errors out if "
                               "/dev/kvm is unavailable.")
    p_start.add_argument("--smp", type=int, default=2, metavar="N",
                          help="Number of QEMU vCPUs (default 2). Plan-C "
                               "experiment uses 16 to test Mozilla "
                               "nsThreadPool sizing under wider _SC_NPROCESSORS_ONLN.")
    p_start.add_argument("--cpu", dest="cpu_model", default=None, metavar="MODEL",
                          help="Override QEMU -cpu model verbatim (e.g. 'host', "
                               "'max', 'Cascadelake-Server', 'EPYC-Genoa-v1', "
                               "'qemu64'). When unset, astryx_qemu.py picks: "
                               "'host' under KVM, otherwise the TCG-safe "
                               "qemu64+SSE4.2/AVX2/FMA baseline (no AVX-512, "
                               "no AVX10, no SHA-NI — see astryx_qemu._TCG_SAFE_CPU). "
                               "Used by perf sweeps to vary VMEXIT surface.")
    p_start.add_argument("--no-regen-data-img", action="store_true",
                          dest="no_regen_data_img",
                          help="Skip the auto-regen of build/data.img when "
                               "build/disk/ has files newer than the image "
                               "(W7 silent-wedge guard). The staleness banner "
                               "still prints to stderr so the situation is "
                               "never hidden. Use when reproducing a bug that "
                               "depends on the existing data.img contents.")

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

    # ── Tier 2: GDB stub subcommands ──────────────────────────────────────────
    # All require that `start` was called with --gdb-port PORT.

    # regs
    p_regs = sub.add_parser("regs", help="[Tier2] Read x86_64 registers via GDB stub")
    p_regs.add_argument("sid")

    # mem
    p_mem = sub.add_parser("mem", help="[Tier2] Read guest memory via GDB stub")
    p_mem.add_argument("sid")
    p_mem.add_argument("addr", help="Guest virtual address (hex or decimal)")
    p_mem.add_argument("length", type=int, help="Byte count (capped at 4096)")

    # sym
    p_sym = sub.add_parser("sym", help="[Tier2] Resolve kernel symbol to address (ELF parse, no GDB)")
    p_sym.add_argument("sid")
    p_sym.add_argument("name", help="Symbol name (e.g. kernel_main)")

    # bp
    p_bp = sub.add_parser("bp", help="[Tier2] Manage breakpoints via GDB stub")
    p_bp.add_argument("sid")
    p_bp.add_argument("op", choices=["add", "del", "list"],
                       help="add <addr> / del <addr> / list")
    p_bp.add_argument("addr", nargs="?", default=None,
                       help="Address for add/del (hex or decimal)")

    # step
    p_step = sub.add_parser("step", help="[Tier2] Single-step via GDB vCont;s")
    p_step.add_argument("sid")

    # cont
    p_cont = sub.add_parser("cont", help="[Tier2] Continue execution via GDB vCont;c")
    p_cont.add_argument("sid")

    # pause
    p_pause = sub.add_parser("pause", help="[Tier2] Pause QEMU via QMP stop")
    p_pause.add_argument("sid")

    # resume
    p_resume = sub.add_parser("resume", help="[Tier2] Resume QEMU via QMP cont")
    p_resume.add_argument("sid")

    # kdb — Tier 1 kernel debugger JSON socket
    p_kdb = sub.add_parser(
        "kdb",
        help="[Tier1] One-shot JSON request against the in-kernel debugger "
             "(requires --features kdb at start)")
    p_kdb.add_argument("sid")
    p_kdb.add_argument("op", choices=[
        "ping", "proc-list", "proc", "proc-tree", "fd-table", "fd-map",
        "syscall-trend", "vfs-mounts",
        "dmesg", "syms", "mem", "tframe", "user-mem", "trace-status",
        "bell-stats",
    ])
    p_kdb.add_argument("args", nargs="*",
                        help="Op-specific positional args: "
                             "proc <pid>, proc-tree [<root_pid>] (def 1), "
                             "fd-table <pid>, "
                             "fd-map [<pid>] (0 or omit = all processes), "
                             "syscall-trend [<seconds> [<pid>]] (def 5 0), "
                             "dmesg [tail], syms <name|0xaddr>, "
                             "mem <addr> <len>")
    p_kdb.add_argument("--timeout", type=float, default=5.0,
                        help="Socket timeout in seconds (default 5.0)")

    # fd-map — dedicated top-level subcommand with snapshot/diff support
    p_fdmap = sub.add_parser(
        "fd-map",
        help="[Tier1] Cross-process FD map: resolves socketpair/pipe peer "
             "(pid,fd) pairs. Wraps kdb fd-map with --save/--diff for "
             "two-snapshot Hypothesis A vs B diagnosis (W216 IPC forensic).")
    p_fdmap.add_argument("sid")
    p_fdmap.add_argument("--pid", type=lambda x: int(x, 0), default=0,
                          help="Filter to one PID (0 or omit = all processes)")
    p_fdmap.add_argument("--save", metavar="NAME", default=None,
                          help="Save snapshot to ~/.astryx-harness/<sid>.fdmap.<NAME>.json")
    p_fdmap.add_argument("--diff", metavar="NAME", default=None,
                          help="Diff current snapshot against a previously --save'd NAME")
    p_fdmap.add_argument("--timeout", type=float, default=5.0,
                          help="kdb socket timeout in seconds (default 5.0)")

    # qga-ping / qga-info / qga-sync / qga-file-read — QEMU Guest Agent
    # bridge.  Requires --features qga at start; talks NDJSON over the
    # per-session UNIX chardev socket at ~/.astryx-harness/<sid>.qga.sock.
    p_qga_ping = sub.add_parser(
        "qga-ping",
        help="QGA: round-trip ping the in-guest QEMU Guest Agent daemon")
    p_qga_ping.add_argument("sid")
    p_qga_ping.add_argument("--timeout", type=float, default=5.0,
                             help="Socket timeout in seconds (default 5.0)")

    p_qga_info = sub.add_parser(
        "qga-info",
        help="QGA: fetch daemon version + supported-commands list")
    p_qga_info.add_argument("sid")
    p_qga_info.add_argument("--timeout", type=float, default=5.0,
                             help="Socket timeout in seconds (default 5.0)")

    p_qga_sync = sub.add_parser(
        "qga-sync",
        help="QGA: send guest-sync, verify the daemon echoes the same id "
             "(liveness probe before other QGA calls)")
    p_qga_sync.add_argument("sid")
    p_qga_sync.add_argument("--id", dest="id", type=int, default=None,
                             help="Sync id (default: random 31-bit positive int)")
    p_qga_sync.add_argument("--timeout", type=float, default=5.0,
                             help="Socket timeout in seconds (default 5.0)")

    p_qga_fread = sub.add_parser(
        "qga-file-read",
        help="QGA: open + read + close a guest file in one call. "
             "Returns base64-encoded bytes (capped at 4 KiB per QGA-2)")
    p_qga_fread.add_argument("sid")
    p_qga_fread.add_argument("--path", required=True,
                              help="Absolute guest path (e.g. /disk/opt/firefox/firefox-bin)")
    p_qga_fread.add_argument("--max-bytes", dest="max_bytes",
                              type=int, default=4096,
                              help="Max bytes to read (1..4096, default 4096)")
    p_qga_fread.add_argument("--timeout", type=float, default=5.0,
                              help="Socket timeout in seconds (default 5.0)")

    # prune — housekeeping for ~/.astryx-harness/
    p_prune = sub.add_parser("prune",
        help="Delete state/log files for dead sessions older than --ttl days")
    p_prune.add_argument("--ttl", type=float, default=7.0,
                          help="Age threshold in days (default 7)")

    # results — summarise [TEST-JSON] lines from a session's serial log
    p_results = sub.add_parser("results",
        help="Parse per-test JSONL results from the session's serial log")
    p_results.add_argument("sid")

    # scrings — parse firefox-test syscall ring-buffer dumps from serial log.
    p_scrings = sub.add_parser(
        "scrings",
        help="Parse syscall ring-buffer dumps (firefox-test feature)"
    )
    p_scrings.add_argument("sid")
    p_scrings.add_argument("--pid", type=int, default=None,
                            help="Only return dumps for this PID")
    p_scrings.add_argument("--last", type=int, default=None,
                            help="Truncate each dump's entries[] to last N")

    # stack — parse [SC-RING-STACK] exit-time userspace stack snapshots.
    p_stack = sub.add_parser(
        "stack",
        help="Parse exit-time userspace stack snapshots (firefox-test feature)"
    )
    p_stack.add_argument("sid")
    p_stack.add_argument("--pid", type=int, default=None,
                          help="Only return snapshots for this PID")

    # ustack — parse periodic [SC-USTACK] tid=1 snapshots + resolve frames
    # against the [FFTEST/mmap-so] load-base table.  Use --symbolise to also
    # run `nm` on the host-side library binary for symbol names.
    p_ustack = sub.add_parser(
        "ustack",
        help="Parse periodic tid=1 user-stack snapshots + resolve frames"
    )
    p_ustack.add_argument("sid")
    p_ustack.add_argument("--symbolise", action="store_true",
                          help="Also resolve each frame to <symbol>+<delta> "
                               "via `nm` on the host-side .so file")
    p_ustack.add_argument("--pid", type=int, default=None,
                          help="Only return snapshots for this PID")
    p_ustack.add_argument("--tid", type=int, default=None,
                          help="Only return snapshots for this TID")
    p_ustack.add_argument("--nr", type=int, default=None,
                          help="Only return snapshots for this syscall number")
    p_ustack.add_argument("--disk-root", default=None, metavar="DIR",
                          help="Root directory containing the staged guest disk "
                               "(used to resolve guest paths to host files for "
                               "symbol lookup).  Defaults to ./build/disk and "
                               "./build relative to CWD.")

    # rip-sample — sampling profiler (QMP stop + GDB g).  Requires --gdb-port.
    p_rip = sub.add_parser(
        "rip-sample",
        help="[Tier2] Sample RIP/RSP per vCPU N times via QMP stop + GDB stub; "
             "symbolise against kernel ELF + [FFTEST/mmap-so] load-base table",
    )
    p_rip.add_argument("sid")
    p_rip.add_argument("--count", type=int, default=100,
                       help="Number of sampling iterations (default 100)")
    p_rip.add_argument("--interval-ms", type=int, default=100,
                       dest="interval_ms",
                       help="Sleep between iterations in ms (default 100)")
    p_rip.add_argument("--disk-root", default=None, metavar="DIR",
                       help="Disk staging root for userspace .so symbol lookup "
                            "(see `ustack --disk-root`)")

    # parked-tids — passive serial-log scan of FUTEX_WAIT_REG → leaf rip + sig.
    p_parked = sub.add_parser(
        "parked-tids",
        help="Resolve futex_wait leaf RIP per tid from serial log; group by "
             "library:symbol signature.  Works without kdb (firefox-test)."
    )
    p_parked.add_argument("sid")
    p_parked.add_argument("--disk-root", default=None, metavar="DIR",
                          help="Disk staging root for symbol lookup")

    # parked-stacks — Phase-17 deep stack walk: rbp-chain frames + raw stack
    # word scan, resolved against [FFTEST/mmap-so] + host-side .so symbols.
    p_pstacks = sub.add_parser(
        "parked-stacks",
        help="Phase-17 deep stack walk for parked tids: combines "
             "[FUTEX_WAIT_STACK] rbp-chain frames with [FUTEX_WAIT_SCAN] "
             "raw stack words, filtered to non-libc libraries.  Reveals "
             "the libxul/libnspr return addresses where the rbp chain "
             "dies inside libc.")
    p_pstacks.add_argument("sid")
    p_pstacks.add_argument("--disk-root", default=None, metavar="DIR",
                           help="Disk staging root for symbol lookup")

    # wake-attempts — diff WAKE_REQ vs still-parked uaddrs (Branch A/B verdict).
    p_wake = sub.add_parser(
        "wake-attempts",
        help="Diff [FUTEX_WAKE_REQ] uaddrs against still-parked uaddrs to "
             "decide Branch A (wake never called) vs Branch B (wrong uaddr)."
    )
    p_wake.add_argument("sid")
    p_wake.add_argument("--disk-root", default=None, metavar="DIR",
                        help="Disk staging root for symbol lookup")

    # qmp-regs / qmp-xv / qmp-xp — QEMU monitor introspection (no GDB needed)
    p_qmp_regs = sub.add_parser(
        "qmp-regs",
        help="Read all CPU registers via QMP `info registers -a` (pauses VM)")
    p_qmp_regs.add_argument("sid")
    p_qmp_regs.add_argument("--no-pause", action="store_true",
                              help="Do not stop/cont the VM around the read")
    p_qmp_regs.add_argument("--raw", action="store_true",
                              help="Include raw monitor text in the response")

    p_qmp_xv = sub.add_parser(
        "qmp-xv",
        help="Read guest *virtual* memory through the active CR3 via QMP `x`")
    p_qmp_xv.add_argument("sid")
    p_qmp_xv.add_argument("addr", help="Virtual address (0x... or decimal)")
    p_qmp_xv.add_argument("bytes", help="Number of bytes to read")
    p_qmp_xv.add_argument("--cpu", default="0",
                            help="vCPU index whose CR3 to use (default 0)")
    p_qmp_xv.add_argument("--raw", action="store_true")

    p_qmp_xp = sub.add_parser(
        "qmp-xp",
        help="Read guest *physical* memory via QMP `xp`")
    p_qmp_xp.add_argument("sid")
    p_qmp_xp.add_argument("addr", help="Physical address (0x... or decimal)")
    p_qmp_xp.add_argument("bytes", help="Number of bytes to read")
    p_qmp_xp.add_argument("--raw", action="store_true")

    # rip-walk — pause at a serial-log marker, walk user RBP chain.
    p_rwalk = sub.add_parser(
        "rip-walk",
        help="Pause at a serial-log marker and walk the user RBP chain via "
             "QMP; resolve every frame against the [FFTEST/mmap-so] map.  "
             "Use to identify the user-space gate function at a chosen "
             "syscall ordinal (e.g. --marker '\\[LINUX-SYS\\] #742 ').")
    p_rwalk.add_argument("sid")
    p_rwalk.add_argument("--marker", required=True,
                          help="Regex matched against incoming serial-log "
                               "lines; QEMU is paused on first match.")
    p_rwalk.add_argument("--frames", type=int, default=32,
                          help="Maximum RBP-chain frames to walk (default 32)")
    p_rwalk.add_argument("--occurrence", type=int, default=1,
                          help="K-th match wins (default 1)")
    p_rwalk.add_argument("--timeout-ms", type=int, default=60000,
                          dest="timeout_ms",
                          help="Marker-wait timeout in ms (default 60000)")
    p_rwalk.add_argument("--cpu", default=None,
                          help="Force vCPU index (default: first kernel-RIP CPU)")
    p_rwalk.add_argument("--user-cr3", default=None, dest="user_cr3",
                          help="Explicit user-process CR3 to use for the "
                               "user-space stack walk.  Required if every "
                               "paused vCPU is on the kernel CR3 at pause "
                               "time (the common case between Firefox "
                               "syscall bursts).  Default: auto-detect from "
                               "[FFTEST/...] / [PROC] log lines.")
    p_rwalk.add_argument("--disk-root", default=None, metavar="DIR",
                          help="Disk staging root for symbol lookup "
                               "(see `ustack --disk-root`)")

    # sc-histogram — syscall count histogram from [SC] trace lines
    p_schist = sub.add_parser(
        "sc-histogram",
        help="Parse [SC] trace lines from serial log; produce per-tid syscall "
             "count histogram and total call counts sorted by frequency. "
             "Requires --features syscall-trace at start."
    )
    p_schist.add_argument("sid")
    p_schist.add_argument("--tid", type=int, default=None,
                          help="Restrict to a single TID (default: all tids)")
    p_schist.add_argument("--top", type=int, default=20,
                          help="Report the top N syscalls by count (default 20)")
    p_schist.add_argument("--since-line", type=int, default=None, dest="since_line",
                          help="Skip serial log lines before this line number "
                               "(useful to restrict to post-plateau window)")

    # read-png — extract the guest PNG screenshot to a host-side file
    p_read_png = sub.add_parser(
        "read-png",
        help="Collect base64-encoded PNG from the serial log (Test 198 emits "
             "[SCREENSHOT-B64:N/M] lines) and write to <dst.png>.  "
             "Verifies the PNG signature before writing.  "
             "Example: read-png <sid> /tmp/extracted.png"
    )
    p_read_png.add_argument("sid")
    p_read_png.add_argument("dst", help="Host-side destination path for the PNG file")
    p_read_png.add_argument(
        "--timeout-ms", type=int, default=120000, dest="timeout_ms",
        help="Milliseconds to wait for the first [SCREENSHOT-B64:0/M] line "
             "(default 120000 = 2 min, covers build + boot + test run)"
    )

    # check: run `cargo check` against a feature-flag combination without
    # spinning up QEMU.  Used by hotfix verification sweeps that need to
    # confirm a regression is closed across N feature combos before
    # committing to a full boot.
    p_check = sub.add_parser("check",
                              help="Run `cargo +nightly check` for given --features")
    p_check.add_argument("--features", default="", metavar="FLAGS",
                          help="Feature flags passed VERBATIM to cargo. "
                               "Empty string → default desktop kernel.")

    # context — shared session-context management (delegates to agent-context.py)
    p_ctx = sub.add_parser(
        "context",
        help="Shared session-context management: read CURRENT.md, register "
             "dispatch/completion events, append arbitrary events, summarise. "
             "All subcommands are forwarded verbatim to scripts/agent-context.py. "
             "Example: context read-current --section Goal",
    )
    p_ctx.add_argument(
        "context_args", nargs=argparse.REMAINDER,
        help="Subcommand + arguments forwarded to agent-context.py",
    )

    # _watch: private subcommand used internally by `start` to run the
    # background watcher in a detached process. Not shown in help.
    p_watch = sub.add_parser("_watch")
    p_watch.add_argument("sid")

    args = parser.parse_args()

    dispatch = {
        "check":  cmd_check,
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
        # Tier 2
        "regs":   cmd_regs,
        "mem":    cmd_mem,
        "sym":    cmd_sym,
        "bp":     cmd_bp,
        "step":   cmd_step,
        "cont":   cmd_cont,
        "pause":  cmd_pause,
        "resume": cmd_resume,
        # Tier 1
        "kdb":    cmd_kdb,
        "fd-map": cmd_fd_map,
        # QGA bridge
        "qga-ping":      cmd_qga_ping,
        "qga-info":      cmd_qga_info,
        "qga-sync":      cmd_qga_sync,
        "qga-file-read": cmd_qga_file_read,
        # Housekeeping / reporting
        "prune":   cmd_prune,
        "results": cmd_results,
        "scrings": cmd_scrings,
        "stack":   cmd_stack,
        "ustack":  cmd_ustack,
        "parked-tids": cmd_parked_tids,
        "parked-stacks": cmd_parked_stacks,
        "wake-attempts": cmd_wake_attempts,
        "sc-histogram": cmd_sc_histogram,
        "rip-sample": cmd_rip_sample,
        "qmp-regs": cmd_qmp_regs,
        "qmp-xv":   cmd_qmp_xv,
        "qmp-xp":   cmd_qmp_xp,
        "rip-walk": cmd_rip_walk,
        "read-png": cmd_read_png,
        # Shared session context
        "context": cmd_context,
        "_watch":  cmd_run_watcher,
    }
    rc = dispatch[args.cmd](args)
    if isinstance(rc, int) and rc != 0:
        sys.exit(rc)


if __name__ == "__main__":
    main()
