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
                          ovmf_vars_dst: str,
                          gdb_port: int = 0,
                          gdb_wait: bool = False) -> subprocess.Popen:
    """
    Launch QEMU with a per-session serial log and QMP socket.

    gdb_port: if > 0, adds -gdb tcp::PORT to the QEMU command line.
    gdb_wait: if True and gdb_port > 0, adds -S (start frozen, wait for GDB).
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

    # GDB stub (Tier 2) — attach QEMU's built-in GDB server on a TCP port.
    # Port conflict policy: if the caller's port is busy, GdbClient.connect()
    # will back off to port+1 .. port+4 automatically.
    if gdb_port > 0:
        cmd += ["-gdb", f"tcp::{gdb_port}"]
        if gdb_wait:
            # Start frozen; the debugger must `continue` to unfreeze.
            cmd += ["-S"]

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

    proc = _launch_qemu_harness(sid, serial_log, qmp_sock, ovmf_vars,
                                 gdb_port=gdb_port, gdb_wait=gdb_wait)

    session = {
        "sid":        sid,
        "pid":        proc.pid,
        "serial_log": serial_log,
        "qmp_sock":   qmp_sock,
        "ovmf_vars":  ovmf_vars,
        "started_at": time.time(),
        "features":   args.features or "test-mode",
        "gdb_port":   gdb_port,
        "gdb_wait":   gdb_wait,
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
          "gdb_port": gdb_port})


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
    p_start.add_argument("--gdb-port", type=int, default=0, metavar="PORT",
                          help="Enable GDB stub on TCP PORT (0=off). "
                               "GdbClient will back off to PORT+1..PORT+4 on conflict.")
    p_start.add_argument("--gdb-wait", action="store_true",
                          help="Start QEMU frozen (-S); debugger must 'cont' to unfreeze")

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
        "_watch": cmd_run_watcher,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
