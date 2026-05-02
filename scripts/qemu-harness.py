#!/usr/bin/env python3
"""
qemu-harness.py — Agentic QEMU session manager for AstryxOS kernel debugging.

Provides a persistent, structured JSON interface for driving QEMU sessions
from agent scripts or CI. Every subcommand prints JSON to stdout.

Session state is stored in ~/.astryx-harness/<sid>.json.
Events are written to ~/.astryx-harness/<sid>.events.jsonl.
QMP socket: ~/.astryx-harness/<sid>.qmp.sock

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

Tier 2 — GDB stub integration (requires --gdb-port on start):
    python3 scripts/qemu-harness.py regs <sid>
    python3 scripts/qemu-harness.py mem <sid> <addr> <len>
    python3 scripts/qemu-harness.py sym <sid> <name>
    python3 scripts/qemu-harness.py bp <sid> add|del|list <addr>
    python3 scripts/qemu-harness.py step <sid>
    python3 scripts/qemu-harness.py cont <sid>
    python3 scripts/qemu-harness.py pause <sid>
    python3 scripts/qemu-harness.py resume <sid>
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


# ── QEMU launch (harness variant) ────────────────────────────────────────────

def _launch_qemu_harness(sid: str, serial_log: str, qmp_sock: str,
                          ovmf_vars_dst: str,
                          gdb_port: int = 0,
                          gdb_wait: bool = False,
                          kdb_host_port: int = 0,
                          kvm: Optional[bool] = None) -> subprocess.Popen:
    """
    Launch QEMU with a per-session serial log and QMP socket.

    gdb_port: if > 0, adds -gdb tcp::PORT to the QEMU command line.
    gdb_wait: if True and gdb_port > 0, adds -S (start frozen, wait for GDB).
    kdb_host_port: if > 0, adds a hostfwd rule forwarding host-port to
        guest 10.0.2.15:9999 for the kdb introspection server.
    kvm: tri-state. None = autodetect; True = force-enable; False = force-disable
        (matches CI which has no /dev/kvm — useful for reproducing CI hangs locally).
    """
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
        gdb_port=gdb_port if gdb_port and gdb_port > 0 else None,
        gdb_wait=gdb_wait,
        kvm=kvm,
    )

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
    kdb_host_port = 0
    if "kdb" in [f.strip() for f in features_str.split(",")]:
        # Derive deterministically from sid so reruns are stable and two
        # concurrent sessions almost certainly land on distinct ports.
        kdb_host_port = 9990 + (int(sid, 16) % 1000)

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

    kvm_arg: Optional[bool]
    if getattr(args, "no_kvm", False):
        kvm_arg = False
    elif getattr(args, "force_kvm", False):
        kvm_arg = True
    else:
        kvm_arg = None  # autodetect
    proc = _launch_qemu_harness(sid, serial_log, qmp_sock, ovmf_vars,
                                 gdb_port=gdb_port, gdb_wait=gdb_wait,
                                 kdb_host_port=kdb_host_port,
                                 kvm=kvm_arg)

    session = {
        "sid":        sid,
        "pid":        proc.pid,
        "serial_log": serial_log,
        "qmp_sock":   qmp_sock,
        "ovmf_vars":  ovmf_vars,
        "started_at": time.time(),
        "features":   args.features or "",
        "gdb_port":   gdb_port,
        "gdb_wait":   gdb_wait,
        "kdb_host_port": kdb_host_port,
        "breakpoints": [],
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

    _out({"sid": sid, "pid": proc.pid, "serial_log": serial_log,
          "gdb_port": gdb_port, "kdb_host_port": kdb_host_port})


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
    if op in ("ping", "proc-list", "vfs-mounts", "trace-status"):
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
    # .json, .serial.log, .events.jsonl, .qmp.sock, .OVMF_VARS.fd
    known_suffixes = (
        ".json",
        ".serial.log",
        ".events.jsonl",
        ".qmp.sock",
        ".OVMF_VARS.fd",
    )

    groups: dict = {}  # sid -> list[Path]
    try:
        entries = list(HARNESS_DIR.iterdir())
    except OSError:
        _out({"pruned": [], "kept": 0, "freed_bytes": 0})
        return

    for p in entries:
        if not p.is_file():
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

        # Prune: delete every file in the group.
        for fp in files:
            try:
                sz = fp.stat().st_size
            except OSError:
                sz = 0
            try:
                fp.unlink()
                freed_bytes += sz
            except OSError:
                # Permission denied or race with another pruner — skip.
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
                          help="Force-disable KVM acceleration. Reproduces CI's "
                               "TCG-only environment (qemu64 CPU model). Useful "
                               "when a test hangs only without KVM.")
    p_start.add_argument("--kvm", dest="force_kvm", action="store_true",
                          help="Force-enable KVM acceleration. Errors out if "
                               "/dev/kvm is unavailable.")

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
        "ping", "proc-list", "proc", "proc-tree", "fd-table",
        "syscall-trend", "vfs-mounts",
        "dmesg", "syms", "mem", "tframe", "user-mem", "trace-status",
    ])
    p_kdb.add_argument("args", nargs="*",
                        help="Op-specific positional args: "
                             "proc <pid>, proc-tree [<root_pid>] (def 1), "
                             "fd-table <pid>, "
                             "syscall-trend [<seconds> [<pid>]] (def 5 0), "
                             "dmesg [tail], syms <name|0xaddr>, "
                             "mem <addr> <len>")
    p_kdb.add_argument("--timeout", type=float, default=5.0,
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

    # wake-attempts — diff WAKE_REQ vs still-parked uaddrs (Branch A/B verdict).
    p_wake = sub.add_parser(
        "wake-attempts",
        help="Diff [FUTEX_WAKE_REQ] uaddrs against still-parked uaddrs to "
             "decide Branch A (wake never called) vs Branch B (wrong uaddr)."
    )
    p_wake.add_argument("sid")
    p_wake.add_argument("--disk-root", default=None, metavar="DIR",
                        help="Disk staging root for symbol lookup")

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
        # Housekeeping / reporting
        "prune":   cmd_prune,
        "results": cmd_results,
        "scrings": cmd_scrings,
        "stack":   cmd_stack,
        "ustack":  cmd_ustack,
        "parked-tids": cmd_parked_tids,
        "wake-attempts": cmd_wake_attempts,
        "rip-sample": cmd_rip_sample,
        "_watch":  cmd_run_watcher,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
