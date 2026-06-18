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

Firefox serial profiles (perf vs trace):
    The Firefox kernel ships two profiles that share identical FUNCTIONAL
    behaviour and differ only in diagnostic serial volume:

      PERF / RENDER / CI (fast, default):
          start --features firefox-test-core[,kdb,...]
          High-frequency diagnostic emitters ([FF/stderr]/[FF/write],
          [POLL_RET], per-component [VFS/resolve], [FUTEX_*]) are compiled OUT.
          A boot emits <2 MB serial instead of ~45 MB; since each serial byte is
          one PIO VM-exit under KVM (Intel SDM Vol. 3C §25 / NS16550A THR-write
          model), the synchronous transcription cost that dominated wall-clock
          (~56 min) collapses to minutes.  Firefox still runs IDENTICALLY.

      DEBUG / TRACE (full serial, opt-in):
          start --features firefox-test-core --trace        (preferred)
          start --features firefox-test                     (back-compat alias)
          Adds firefox-test-trace → the full per-syscall serial transcript.
          --trace appends the trace feature and prints the expansion to stderr
          (never injected silently).  Do NOT add futex-wait-scan or
          firefox-trace-verbose to a perf boot — both add large PT-walk + serial
          cost and stay explicit opt-ins outside both profiles.

Tier 1 — session management:
    python3 scripts/qemu-harness.py start [--features FLAGS] [--trace] [--no-build]
                                          [--gdb-port PORT] [--gdb-wait]
                                          [--firefox-variant musl|glibc]
                                          [--snapshottable]
                                          [--pcap] [--no-pcap]
                                          [--livelock-reap-sc N]
                                          [--livelock-reap-secs SECS]
                                          [--no-livelock-reap]
        Host-side packet capture (default ON for FF-render boots): every
        Firefox-render boot (features firefox-test / firefox-test-core /
        firefox-test-trace) automatically captures its VM<->internet traffic to
        ~/.astryx-harness/<sid>.pcap via a host-side QEMU `-object filter-dump`
        (ZERO guest VM-exits — only a host fwrite per frame).  serial-web serves
        it at /api/pcap?sid=<sid> and a decoded wire summary at
        /api/wire?sid=<sid>.  Non-FF boots (test-mode, default desktop) have no
        network worth capturing, so capture stays OFF for them.  --pcap
        force-enables capture on ANY boot (incl. non-FF); --no-pcap disables it
        even on an FF boot (for a clean perf-timing run).  Precedence: --no-pcap
        > --pcap > FF-default > off.  The effective path + decision land in the
        session JSON and `start`/`status` output as pcap_path (source of truth,
        "" when disabled), pcap_enabled, and pcap_reason.
        Livelock auto-reap (default ON): a spinning FF render boot — pid 1
        busy-looping (waitpid/futex) while the deepest gate is frozen — drives
        the pid=1 syscall count into the hundreds-of-millions/billions at ~100%
        host CPU with NO forward progress.  The watcher auto-stops such a boot
        so it stops pinning a core and skewing concurrent timing runs.  The
        rule: once the pid=1 syscall count churns by > --livelock-reap-sc
        (default 50,000,000) WHILE the deepest FF gate stays frozen for longer
        than --livelock-reap-secs (default 180s), the session is cleanly stopped
        (same path as `stop`), marked terminal_cause="livelock-autoreap" in the
        session JSON + events.jsonl, and a "[HARNESS] livelock auto-reap: …"
        line is logged.  BEFORE a reap, `status`/`list`/the serial monitor show
        a live `livelock_suspected: true` flag.  Pass --no-livelock-reap (or set
        either threshold to 0) to keep a spinning session alive for inspection
        (debugging/autopsy holds).
    python3 scripts/qemu-harness.py stop <sid>
    python3 scripts/qemu-harness.py list
    python3 scripts/qemu-harness.py wait <sid> <regex> [--ms MS]
    python3 scripts/qemu-harness.py grep <sid> <regex> [--tail N]
    python3 scripts/qemu-harness.py send <sid> <text>
    python3 scripts/qemu-harness.py tail <sid> [--bytes B] [--since LINE]
    python3 scripts/qemu-harness.py status <sid>
    python3 scripts/qemu-harness.py events <sid> [--tail N] [--follow]
    python3 scripts/qemu-harness.py snap <sid> save|load <name>
    python3 scripts/qemu-harness.py snap-gate <sid> save <name>
    python3 scripts/qemu-harness.py snap-gate load <name>
    python3 scripts/qemu-harness.py snap-gate list
        Live VM snapshot/restore that PRESERVES a running guest (e.g. a deep
        Firefox boot) across save/load — collapses a 30-50min FF-boot-to-gate
        into a sub-second loadvm. Requires `start --snapshottable` (the
        savevm-compatible device topology: read-only fat:ro vvfat boot disk on
        a virtio-blk-pci frontend, qcow2 OVMF_VARS pflash, an orphan qcow2
        vmstate device + a persistent qcow2 data overlay backed read-only by
        the shared data.img). `save` does QMP stop->savevm->cont and records a
        manifest entry (name -> {sid, gate, max_sc, features, ts, qcow2 paths})
        under ~/.astryx-harness/snapshots/. `load` spawns a NEW session with
        the same topology + loadvm and prints its sid, so grep/wait/kdb/
        ff-progress work against the restored VM. Stop the origin session
        before `load` (load reuses the saved qcow2 files in place). The default
        `snap` subcommand (above) cannot preserve FF state — the writable
        vvfat boot disk blocks savevm; snap-gate is the FF-capable replacement.
    python3 scripts/qemu-harness.py prune [--ttl DAYS]
    python3 scripts/qemu-harness.py results <sid>
    python3 scripts/qemu-harness.py ff-progress <sid>
        FF headless-screenshot gate ladder + DEEPEST gate reached (pure
        serial-log scan; no kdb). Ladder in scripts/ff_gates.yaml (additive).
        Reports lib-load -> x11-ready -> compositor-init -> ff-launch ->
        content-proc -> screenshot-actors -> draw-snapshot -> png-write,
        plus max_sc, reached_png, and terminal_cause. The authoritative
        "how deep did this boot get + is it the screenshot wedge?" oracle.
    python3 scripts/qemu-harness.py kdb <sid> cond-autopsy <pid> <cond_va> [<half>]
        One-shot musl pthread_cond/mutex wake-target-vs-wait-addr report:
        live struct dump + parked waiters in [va-half,va+half] (with delta to
        the query) + recent FUTEX_WAKE targets + inferred lock holder +
        verdict_hint (wake-address-mismatch | held-lock-deadlock |
        owner-starved | true-lost-wakeup | benign-empty) + a one-line summary.
        The decisive condvar-livelock probe in one argv call (half def 128).
    python3 scripts/qemu-harness.py read-png <sid> <dst.png> [--timeout-ms MS]
        Decode the VGA framebuffer ([SCREENSHOT-B64:…], Test 198) to a host PNG.
    python3 scripts/qemu-harness.py read-ff-png <sid> <dst.png> [--timeout-ms MS]
        Decode Firefox's RENDERED /tmp/out.png from the DISTINCT
        [FF-OUT-PNG-B64:…] stream the firefox-test boot emits after FF exits.
        This is the actual loaded page, not the boot-splash framebuffer.
    python3 scripts/qemu-harness.py kdb-read-png <sid> <dst.png> [--path P]
        Pull a guest VFS file (default /tmp/out.png) LIVE via the kdb
        read-file op (chunked base64). Works the instant the file exists,
        independent of the boot's serial emit. Requires --features kdb.
    python3 scripts/qemu-harness.py futex-wake-drill <sid> [--tid N]
                                            [--bucket-count K] [--window-lines L]
                                            [--cross-park]
    python3 scripts/qemu-harness.py rip-trace-resolve <sid> <tid> [<ms>]
                                            [--disk-root DIR]

Tier 2 — GDB stub integration (requires --gdb-port on start):
    python3 scripts/qemu-harness.py regs <sid>
    python3 scripts/qemu-harness.py mem <sid> <addr> <len>
    python3 scripts/qemu-harness.py sym <sid> <name>
    python3 scripts/qemu-harness.py bp <sid> add|del|list <addr>
    python3 scripts/qemu-harness.py step <sid>
    python3 scripts/qemu-harness.py cont <sid>
    python3 scripts/qemu-harness.py pause <sid>
    python3 scripts/qemu-harness.py resume <sid>
    python3 scripts/qemu-harness.py autopsy <sid> --break <sym|addr> \\
                                            --capture <preset> \\
                                            [--once N] [--continue-after] \\
                                            [--timeout-ms MS] \\
                                            [--leave-paused] \\
                                            [--output PATH]

Autopsy is the MANDATORY FIRST PROBE for any fault investigation.
Presets live at scripts/autopsy/presets.yaml; current set includes
full-register-dump, stack-walk-bt-full, ssp-fail-snapshot, vfork-window,
gp-fault-context, bugcheck-entry.  Adding a new printk-style ring buffer
without first running an autopsy is dispatch-counted-against-you — the
GDB stub already produces structured machine-readable output that
beats every ad-hoc serial-log probe.

QGA bridge (requires --features qga on start):
    python3 scripts/qemu-harness.py qga-ping <sid> [--timeout S]
    python3 scripts/qemu-harness.py qga-info <sid> [--timeout S]
    python3 scripts/qemu-harness.py qga-sync <sid> [--id N] [--timeout S]
    python3 scripts/qemu-harness.py qga-file-read <sid> --path <P> [--max-bytes N]

CI / multi-trial aggregation:
    python3 scripts/qemu-harness.py ci-run [--features F] [--timeout-ms MS]
                                           [--allow-fail REGEX] [--no-kvm]
    python3 scripts/qemu-harness.py soak --trials N [--features F]
                                           [--use-allowlist] [--allow-fail R]
                                           [--timeout-ms MS] [--no-kvm]
    python3 scripts/qemu-harness.py allowlist list
    python3 scripts/qemu-harness.py allowlist regex
    python3 scripts/qemu-harness.py allowlist add --name N --reason R
                                                    [--tracking T] [--regex]
    python3 scripts/qemu-harness.py allowlist remove --name N
    python3 scripts/qemu-harness.py allowlist check --serial-log PATH

ABI-conformance reference (delegates to scripts/strace-ref.py):
    python3 scripts/qemu-harness.py strace-ref setup [--bootstrap]
    python3 scripts/qemu-harness.py strace-ref capture [--label N]
                                                       [--binary-args ARGS]
                                                       [--syscall-filter F]
                                                       [--timeout SEC]
    python3 scripts/qemu-harness.py strace-ref diff --linux-trace P
                                                    --astryx-log P [--verbose]
    python3 scripts/qemu-harness.py strace-ref list
    python3 scripts/qemu-harness.py strace-ref clean [--label STR]
"""

import argparse
import datetime
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

    def set_bp(self, addr: int, hw: bool = False) -> bool:
        """Set a breakpoint.  Z0 = software (INT3 patch), Z1 = hardware
        (x86 debug register DR0..DR3).  Under KVM the software (Z0) INT3
        patch is sometimes silently dropped for kernel .text addresses
        (the stub acks 'OK' but the guest never traps), so a hardware
        breakpoint (Z1, which programs DR7) is the reliable choice for
        catching a kernel symbol.  See Intel SDM Vol. 3B §17.2 (DR0-DR3,
        DR7) and the GDB Remote Serial Protocol Z/z packet spec."""
        ztype = 1 if hw else 0
        resp = self.send(f"Z{ztype},{addr:x},1")
        return resp == "OK"

    def del_bp(self, addr: int, hw: bool = False) -> bool:
        """Remove a software (z0) or hardware (z1) breakpoint."""
        ztype = 1 if hw else 0
        resp = self.send(f"z{ztype},{addr:x},1")
        return resp == "OK"

    # ── hardware watchpoints (Z2/Z3/Z4 packets) ──────────────────────────────
    #
    # GDB remote-protocol watchpoint kinds (see the GDB Remote Serial Protocol
    # "Z/z packets" spec): Z2 = write watchpoint, Z3 = read watchpoint,
    # Z4 = access (read|write) watchpoint.  QEMU's gdbstub maps these onto the
    # x86 debug registers (DR0..DR3 + DR7) so they fire on the EXACT store that
    # touches the watched bytes — this is what lets us name an out-of-band
    # writer without polluting the kernel with a probe.

    def set_watch(self, addr: int, length: int = 8, kind: str = "write") -> bool:
        """Arm a hardware watchpoint via Z2/Z3/Z4.  Returns True on stub ack."""
        z = {"write": "Z2", "read": "Z3", "access": "Z4"}.get(kind, "Z2")
        resp = self.send(f"{z},{addr:x},{length:x}")
        return resp == "OK"

    def del_watch(self, addr: int, length: int = 8, kind: str = "write") -> bool:
        """Remove a hardware watchpoint via z2/z3/z4."""
        z = {"write": "z2", "read": "z3", "access": "z4"}.get(kind, "z2")
        resp = self.send(f"{z},{addr:x},{length:x}")
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

    # ── continue + wait-for-stop (used by `autopsy`) ──────────────────────────

    def cont_no_wait(self) -> None:
        """
        Send `vCont;c` (or `c` if vCont unsupported) WITHOUT consuming the
        eventual stop-reply.  The caller is responsible for invoking
        `wait_for_stop()` later to drain the stop packet.

        This split exists so `cmd_autopsy` can arm a breakpoint, resume the
        guest, poll with a timeout, and time-bound the wait — the
        `vcont_cont` convenience helper drops the stop-reply on the floor
        which we cannot tolerate when we need it.
        """
        support = ""
        try:
            support = self.send("vCont?")
        except Exception:
            pass
        pkt = "vCont;c" if "c" in support else "c"
        # Hand-build the frame so we don't recurse into _send_pkt's ack loop.
        raw = pkt.encode("ascii")
        cs  = self._checksum(raw)
        frame = f"${pkt}#{cs:02x}".encode("ascii")
        self._s.sendall(frame)
        if self._ack_mode:
            # Drain the immediate '+' ack to the continue packet.
            self._s.settimeout(1.0)
            try:
                self._recv_bytes(1)  # consume '+'
            except (socket.timeout, ConnectionError):
                pass
            finally:
                self._s.settimeout(self.timeout)

    def wait_for_stop(self, timeout_s: float) -> Optional[str]:
        """
        Block up to `timeout_s` seconds for the next stop-reply packet
        ($T..#cs or $S..#cs).  Returns the payload (e.g. "T05swbreak:;...")
        on success, or None on timeout.

        We use select() on the underlying socket so we can honour a
        deadline without holding the connection timeout permanently low
        (which would break subsequent packet exchanges).
        """
        import select
        deadline = time.monotonic() + timeout_s
        # Skip leading +/- ack bytes (response to our previous send) and
        # wait for the '$' that begins a stop packet.
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([self._s], [], [], remaining)
            if not ready:
                return None
            try:
                b = self._s.recv(1)
            except (socket.timeout, ConnectionError):
                return None
            if not b:
                return None
            if b == b"$":
                break
            # else: stray + or - or noise — keep going.

        # Read until '#'; the body of the stop packet is small (< 64 bytes
        # in practice) so we don't need an inner select loop.
        old_to = self._s.gettimeout()
        try:
            self._s.settimeout(max(1.0, deadline - time.monotonic()))
            payload = b""
            while True:
                c = self._s.recv(1)
                if not c:
                    return None
                if c == b"#":
                    break
                payload += c
            _cs_bytes = self._s.recv(2)
            if self._ack_mode:
                self._s.sendall(b"+")
            return payload.decode("ascii", errors="replace")
        except (socket.timeout, ConnectionError):
            return None
        finally:
            self._s.settimeout(old_to)


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

# The session directory may be overridden via ASTRYX_HARNESS_DIR.  This lets
# two agents (or a soak loop and an interactive debug session) run concurrently
# on the same host without their session-state files colliding — notably so
# one agent's leaked-session cleanup ("any *.json appearing during the trial is
# presumed ours → stop it") cannot reap the other agent's live QEMU.  Default
# is the shared ~/.astryx-harness when the env var is unset.
HARNESS_DIR = Path(os.environ.get("ASTRYX_HARNESS_DIR", str(Path.home() / ".astryx-harness")))
HARNESS_DIR.mkdir(parents=True, exist_ok=True)

# snap-gate: dedicated qcow2 vmstate / data-overlay files + the named-snapshot
# manifest live here.  Separate from per-session files so they survive `stop`
# (a snapshot must outlive the session that created it).
SNAP_DIR = HARNESS_DIR / "snapshots"
SNAP_DIR.mkdir(parents=True, exist_ok=True)
SNAP_MANIFEST = SNAP_DIR / "manifest.json"

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

# Kernel-tick regex for stamping each gate mark with the latest tick (so a
# historical re-derivation cross-checks against the exact host stamp). Same
# kernel-only form serial-web/perf_markers use ([HB]/PROC-METRICS tick=).
_WATCH_TICK_RE = re.compile(r"(?:\[HB\]|PROC-METRICS\]) tick=(\d+)")

# ── Livelock auto-reap ────────────────────────────────────────────────────────
#
# A spinning FF render boot (the livelock variant of the screenshot-IPC stall —
# e.g. pid 1 busy-looping on waitpid/futex while the deepest gate is frozen)
# drives the pid=1 syscall counter into the hundreds-of-millions / billions at
# ~100% host CPU while making NO forward progress.  Left alone it pins a core
# until the wall-clock timeout, skewing concurrent timing boots.  The watcher
# already tails the serial log; the detector below turns "huge syscall churn,
# zero gate progress" into a clean auto-stop.
#
# The authoritative live pid=1 syscall count comes from the per-process metrics
# line the kernel emits every ~500 ticks:
#
#   [PROC-METRICS] tick=420514 pid=1 name=/disk/.../firefox-bin sc=758998 (...)
#
# That line can be prefixed by another marker on the same physical line (the
# serial mux interleaves emitters), so the regex anchors on the `PROC-METRICS]`
# token rather than start-of-line.  Only pid=1 is tracked (the dispatching
# process whose runaway churn is the symptom).
_PROC_METRICS_PID1_SC_RE = re.compile(rb"PROC-METRICS\] .*?\bpid=1\b.*?\bsc=(\d+)")

# Defaults: ON.  A boot must churn > 50M pid=1 syscalls with the deepest gate
# frozen for > 180 s of wall-clock before it is reaped.  Both are tunable per
# session via `start --livelock-reap-sc N --livelock-reap-secs N`, and the whole
# guard is disabled with `start --no-livelock-reap`.
LIVELOCK_REAP_SC_DEFAULT   = 50_000_000
LIVELOCK_REAP_SECS_DEFAULT = 180.0

# Feature flags that mark a boot as a "Firefox-render" boot (the profiles that
# exercise the network: a real HTTPS page load over the e1000/SLIRP netdev).
# `firefox-test` is the back-compat super-feature; `firefox-test-core` is the
# perf/render profile; `firefox-test-trace` is the dense-trace add-on. When the
# resolved feature set intersects this set, host-side pcap capture defaults ON
# (see `_resolve_pcap_decision`) — every FF boot's VM↔internet traffic is
# captured automatically. Non-FF boots (test-mode, default desktop) have no
# network worth capturing, so capture stays OFF for them by default.
FF_RENDER_FEATURES = frozenset({
    "firefox-test",
    "firefox-test-core",
    "firefox-test-trace",
})


def _resolve_pcap_decision(feats, pcap_flag, no_pcap_flag):
    """Decide whether host-side pcap capture is enabled for this boot.

    Pure (no I/O) so the smoke suite can exercise every branch without a boot.

    Precedence (highest first):
      1. ``--no-pcap``  → OFF unconditionally (wins over everything; lets a
         clean perf-timing FF run suppress even the host fwrite).
      2. ``--pcap``     → ON unconditionally (force-on for ANY boot, incl. the
         non-FF / no-network ones).
      3. FF-render feature set present → ON (the new default: every Firefox
         boot captures its VM↔internet traffic automatically).
      4. otherwise      → OFF (non-FF boots have no network worth capturing).

    `feats` is the fully-resolved feature list (post `--trace` expansion).
    Returns ``(enabled: bool, reason: str)`` where reason is one of
    ``"no-pcap-optout" | "pcap-forced" | "ff-default" | "non-ff-default"``.
    """
    if no_pcap_flag:
        return False, "no-pcap-optout"
    if pcap_flag:
        return True, "pcap-forced"
    if any(f in FF_RENDER_FEATURES for f in feats):
        return True, "ff-default"
    return False, "non-ff-default"


class LivelockDetector:
    """Pure (no-I/O) "syscall-churn-without-gate-progress" detector.

    The watcher feeds it observations as the serial log advances:

        det = LivelockDetector(reap_sc=50_000_000, reap_secs=180.0)
        det.observe(sc=12_345, gate_idx=3, now=t)   # repeatedly
        if det.suspected: ...                       # live "coming" flag
        if det.should_reap(now=t): reap()           # terminal verdict

    State is a single moving anchor: the (sc, time) captured the last time the
    *deepest gate index* advanced.  Livelock is declared when, relative to that
    anchor, the syscall counter has advanced by more than `reap_sc` AND the gate
    has stayed put for more than `reap_secs` of wall-clock.  Any gate advance
    re-anchors and clears suspicion, so a boot that is churning syscalls *and*
    making progress is never flagged.

    `suspected` is the early-warning flag (both conditions partially met — churn
    over threshold, gate frozen, but the time window not yet elapsed) so a
    dashboard can badge a spinning session *before* it is reaped.  `should_reap`
    is the strict terminal predicate.

    `success_gate_idx` (the last/png-write gate index) makes the detector REFUSE
    to suspect or reap once the success gate is reached — a boot that rendered
    the screenshot is done, not livelocked, even if it keeps churning syscalls
    afterwards.  Pass -1 (the default) to disable this guard.

    Disabled (`enabled=False`, set when reap_sc<=0 or reap_secs<=0, or
    --no-livelock-reap) the detector observes but never suspects or reaps.
    """

    def __init__(self, reap_sc: int, reap_secs: float, enabled: bool = True,
                 success_gate_idx: int = -1):
        self.reap_sc = int(reap_sc)
        self.reap_secs = float(reap_secs)
        # A non-positive threshold (either axis) disables the guard outright —
        # callers can pass 0 to mean "off" without a separate flag.
        self.enabled = bool(enabled) and self.reap_sc > 0 and self.reap_secs > 0
        # The success/terminal gate index (png-write).  Once the boot reaches
        # it the detector goes inert — a rendered screenshot is success, never
        # a livelock.  -1 = no success gate (detector always armed).
        self.success_gate_idx = int(success_gate_idx)
        self.anchor_sc = 0          # pid=1 sc at the last gate advance
        self.anchor_time = None     # wall-clock at the last gate advance
        self.deepest_gate_idx = -1  # deepest FF gate index seen so far
        self.last_sc = 0            # most recent pid=1 sc observed
        self.last_gate_idx = -1
        # Frozen at reap time so the event/JSON report the exact numbers that
        # tripped the guard.
        self.reaped = False
        self.reap_sc_at = None
        self.reap_frozen_secs = None

    def observe(self, sc, gate_idx, now):
        """Record one observation.  `sc` is the latest pid=1 syscall count (or
        None if this line carried no pid=1 metrics), `gate_idx` the deepest FF
        gate index reached so far (-1 = none), `now` a monotonic timestamp."""
        if self.anchor_time is None:
            # First observation establishes the baseline anchor.
            self.anchor_time = now
            self.anchor_sc = sc if sc is not None else 0
        if sc is not None:
            self.last_sc = sc
        if gate_idx is not None and gate_idx > self.deepest_gate_idx:
            # Forward progress — re-anchor (clears any accumulated suspicion).
            self.deepest_gate_idx = gate_idx
            self.anchor_sc = self.last_sc
            self.anchor_time = now
        self.last_gate_idx = self.deepest_gate_idx

    @property
    def sc_delta(self) -> int:
        return self.last_sc - self.anchor_sc

    def frozen_secs(self, now) -> float:
        if self.anchor_time is None:
            return 0.0
        return now - self.anchor_time

    @property
    def _reached_success(self) -> bool:
        """True once the deepest gate is at/past the success (png-write) gate —
        the boot rendered the screenshot, so it is success, never a livelock."""
        return (self.success_gate_idx >= 0
                and self.deepest_gate_idx >= self.success_gate_idx)

    @property
    def suspected(self) -> bool:
        """Live early-warning: churn over threshold while the gate is frozen.

        Intentionally does NOT require the time window — it is the "this is
        heading for a reap" badge a human/agent sees on the dashboard before
        the terminal verdict fires.  False when disabled or once the success
        gate (png-write) has been reached."""
        if not self.enabled or self._reached_success:
            return False
        return self.sc_delta > self.reap_sc

    def should_reap(self, now) -> bool:
        """Strict terminal predicate: churn over threshold AND gate frozen for
        longer than the configured wall-clock window.  False when disabled,
        already reaped, or once the success gate (png-write) has been reached."""
        if not self.enabled or self.reaped or self._reached_success:
            return False
        if self.sc_delta <= self.reap_sc:
            return False
        if self.frozen_secs(now) <= self.reap_secs:
            return False
        # Latch the tripping numbers for the report.
        self.reaped = True
        self.reap_sc_at = self.last_sc
        self.reap_frozen_secs = self.frozen_secs(now)
        return True


def _ll_persist_suspected(sid: str, suspected: bool, det: "LivelockDetector",
                          gate_id):
    """Stamp the live `livelock_suspected` early-warning flag (and the current
    churn/frozen numbers) into the session JSON so `status`, `list`, and the
    serial-monitor can badge a spinning session BEFORE it is reaped.  Additive
    fields — never present on sessions started before this landed.  Best-effort:
    a transient read/write race must not disturb the watcher."""
    try:
        sess = _load_session(sid)
    except SystemExit:
        return
    sess["livelock_suspected"] = bool(suspected)
    sess["livelock_info"] = {
        "suspected":   bool(suspected),
        "sc_delta":    det.sc_delta,
        "frozen_gate": gate_id,
        "reap_sc":     det.reap_sc,
        "reap_secs":   det.reap_secs,
        "enabled":     det.enabled,
    }
    try:
        _save_session(sess)
    except OSError:
        pass


def _ll_reap_session(sid: str, qmp_sock: str, pid: int,
                     det: "LivelockDetector", gate_id):
    """Clean-stop a livelocked session: record `terminal_cause` in the session
    JSON + events, log a clear [HARNESS] line, then take QEMU down via the same
    SIGTERM→SIGKILL path `stop` uses.  The session JSON is updated (NOT deleted)
    so a post-mortem `status <sid>` still shows terminal_cause=livelock-autoreap;
    a later explicit `stop <sid>` cleans the file up."""
    frozen = det.reap_frozen_secs if det.reap_frozen_secs is not None else 0.0
    sc_at = det.reap_sc_at if det.reap_sc_at is not None else det.last_sc
    # Record on the session JSON first (so the verdict survives even if the
    # kill below races a manual stop).
    try:
        sess = _load_session(sid)
        sess["terminal_cause"] = "livelock-autoreap"
        sess["livelock_suspected"] = True
        sess["livelock_reap_result"] = {
            "frozen_gate":  gate_id,
            "sc_at_reap":   sc_at,
            "sc_delta":     det.sc_delta,
            "frozen_secs":  round(frozen, 1),
            "reap_sc":      det.reap_sc,
            "reap_secs":    det.reap_secs,
            "reaped_at":    time.time(),
        }
        _save_session(sess)
    except SystemExit:
        pass
    except OSError:
        pass
    _emit_event(sid, {
        "event":        "livelock_autoreap",
        "terminal_cause": "livelock-autoreap",
        "frozen_gate":  gate_id,
        "sc_at_reap":   sc_at,
        "sc_delta":     det.sc_delta,
        "frozen_secs":  round(frozen, 1),
        "reap_sc":      det.reap_sc,
        "reap_secs":    det.reap_secs,
    })
    # Clear, greppable host-side log line (goes to the detached watcher's stderr,
    # which is /dev/null in production — the durable record is the event above).
    sys.stderr.write(
        f"[HARNESS] livelock auto-reap: sid={sid} gate={gate_id} "
        f"sc={sc_at} sc_delta={det.sc_delta} "
        f"(no gate progress for {round(frozen, 1)}s)\n")
    # Take QEMU down — same SIGTERM→(3s)→SIGKILL escalation as cmd_stop.
    if pid and _pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(30):
                if not _pid_alive(pid):
                    break
                time.sleep(0.1)
            if _pid_alive(pid):
                os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _load_gate_marks():
    """Lazy-import the shared gate-marks helper. Returns the module, or None when
    it is not on this branch (an older master that predates the dashboards) — in
    which case the watcher simply skips gate stamping and keeps its panic/idle
    duties. Additive: never fails the watcher."""
    try:
        import gate_marks  # noqa: PLC0415
        return gate_marks
    except Exception:
        return None


def _watcher_thread(sid: str, serial_log: str, qmp_sock: str, pid: int):
    """
    Monitors the serial log for panic patterns and idle periods, and stamps the
    host arrival time of each bring-up/render gate to <sid>.marks.jsonl (the
    exact-host-time source the serial monitor reads). Gate detection is
    forward-ordered (milestone N+1 only fires at/after N) — identical discipline
    to serial-web's scan_progress — so render markers don't false-positive on
    Firefox's serialized-JS startup cache.

    Runs as a daemon thread started by `start`.
    """
    last_size = 0
    last_activity = time.monotonic()
    idle_event_sent = False
    log_path = Path(serial_log)

    # Gate stamping state (forward-ordered, append first-arrival only).
    _gm = _load_gate_marks()
    _gate_idx = 0
    _cur_tick = None
    _line_no = 0

    # ── Livelock auto-reap setup ──────────────────────────────────────────────
    # Read the per-session config (thresholds + opt-out) the `start` command
    # stamped into the session JSON.  Tolerant of legacy sessions that predate
    # this field — fall back to the built-in defaults (guard ON).
    try:
        _sess0 = _load_session(sid)
    except SystemExit:
        _sess0 = {}
    _ll_cfg = (_sess0.get("livelock_reap") or {}) if isinstance(_sess0, dict) else {}
    # FF gate ladder (same source as `ff-progress`) — forward-ordered deepest
    # gate the boot has reached.  Best-effort: a missing ladder just leaves the
    # detector observing sc-only (gate index never advances → it can still reap
    # a boot that churns without ANY gate, which is the right behaviour).
    try:
        _ff_gates = _load_ff_gates()
    except Exception:
        _ff_gates = []
    # The success gate is the last ladder entry (png-write).  Once reached the
    # detector goes inert — a rendered screenshot is success, not a livelock.
    _ll_success_idx = (len(_ff_gates) - 1) if _ff_gates else -1
    _ll_det = LivelockDetector(
        reap_sc   = _ll_cfg.get("reap_sc", LIVELOCK_REAP_SC_DEFAULT),
        reap_secs = _ll_cfg.get("reap_secs", LIVELOCK_REAP_SECS_DEFAULT),
        enabled   = _ll_cfg.get("enabled", True),
        success_gate_idx = _ll_success_idx,
    )
    _ff_gate_idx = -1                # deepest FF gate index reached (-1 = none)
    _ff_gate_id = None               # its stable id (for the reap report)
    _ll_last_suspected = None        # last value pushed to the session JSON
    _ll_last_persist = 0.0           # throttle session-JSON writes

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
                    _line_no += 1
                    # Track latest kernel tick so each gate mark carries the tick
                    # at its arrival (lets a historical re-derivation cross-check).
                    # The whole gate block is best-effort: any failure here must
                    # NOT disrupt the watcher's panic/idle duties (the harness is
                    # critical infra), so it is wrapped defensively.
                    if _gm is not None:
                        try:
                            _tk = _WATCH_TICK_RE.search(line)
                            if _tk:
                                _cur_tick = int(_tk.group(1))
                            # Forward-ordered milestone stamping: the instant we
                            # first see milestone N's marker (and only at/after
                            # N-1), record its host arrival time. One line can
                            # satisfy several milestones in sequence (while-advance).
                            while (_gate_idx < len(_gm.MILESTONES)
                                   and _gm.match(line, _gm.MILESTONES[_gate_idx][1])):
                                _label = _gm.MILESTONES[_gate_idx][0]
                                _gm.append_gate_mark(
                                    sid, str(HARNESS_DIR), _label,
                                    host_ts=time.time(), tick=_cur_tick,
                                    line=_line_no)
                                _emit_event(sid, {
                                    "event": "gate",
                                    "label": _label,
                                    "tick": _cur_tick,
                                    "line": _line_no,
                                })
                                _gate_idx += 1
                        except Exception:
                            # disable gate stamping for the rest of this run; keep
                            # the watcher alive for panics/idles.
                            _gm = None
                    m = _PANIC_RE.search(line)
                    if m:
                        snap_name = f"{sid}-panic"
                        snap_ok = False
                        snap_err = None
                        try:
                            resp = _qmp_command(qmp_sock,
                                                "human-monitor-command",
                                                {"command-line": f"savevm {snap_name}"},
                                                connect_timeout=2.0)
                            # An HMP savevm failure rides in the `return`
                            # string, not an `error` key — parse it so the
                            # panic event reports a TRUE snapshot, not a
                            # phantom one (same bug class as cmd_snap).
                            snap_err = _hmp_error(resp)
                            snap_ok = snap_err is None
                        except Exception:
                            pass
                        _emit_event(sid, {
                            "event": "panic",
                            "pattern": m.group(0),
                            "line": line,
                            "snapshot": snap_name if snap_ok else None,
                            "snapshot_error": snap_err,
                        })

                    # ── Livelock auto-reap: advance the FF gate index + feed
                    # the detector the live pid=1 syscall count. Entirely
                    # best-effort — wrapped so a malformed line can never take
                    # the watcher's panic/idle duties down.
                    try:
                        _rawline = line.encode("utf-8", errors="replace")
                        # Forward-ordered FF gate advance (same discipline as
                        # ff-progress): one line may satisfy several gates.
                        _is_ipc = bool(_FF_IPC_WRITE_RE.search(_rawline))
                        while (_ff_gate_idx + 1) < len(_ff_gates):
                            _g = _ff_gates[_ff_gate_idx + 1]
                            if _g["kind"] == "ipc-body" and not _is_ipc:
                                if not _g["regex"].search(_rawline):
                                    break
                            if not _g["regex"].search(_rawline):
                                break
                            _ff_gate_idx += 1
                            _ff_gate_id = _g["id"]
                        # Live pid=1 syscall count (None when this line carried
                        # no pid=1 PROC-METRICS).
                        _scm = _PROC_METRICS_PID1_SC_RE.search(_rawline)
                        _sc_val = int(_scm.group(1)) if _scm else None
                        _now = time.monotonic()
                        _ll_det.observe(sc=_sc_val, gate_idx=_ff_gate_idx, now=_now)
                        # Push the early-warning flag to the session JSON for
                        # status/list/serial-web — but only when it CHANGES, and
                        # at most every ~5 s, so we never thrash the JSON file.
                        _susp = _ll_det.suspected
                        if (_susp != _ll_last_suspected
                                and (_now - _ll_last_persist) >= 5.0):
                            _ll_persist_suspected(sid, _susp, _ll_det, _ff_gate_id)
                            _ll_last_suspected = _susp
                            _ll_last_persist = _now
                        # Terminal verdict: churn over threshold AND gate frozen
                        # for the configured wall-clock window → clean reap.
                        if _ll_det.should_reap(now=_now):
                            _ll_reap_session(sid, qmp_sock, pid, _ll_det,
                                             _ff_gate_id)
                            return
                    except Exception:
                        pass
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

    # `--features coverage` (test-coverage audit session 5) requires three
    # build-time adjustments that we keep entirely out of the default
    # build path so non-coverage artefacts remain byte-identical to the
    # pre-coverage kernel:
    #
    #   1. Include `profiler_builtins` in `-Zbuild-std` so rustc finds a
    #      crate with the `#![profiler_runtime]` attribute (the only way
    #      to satisfy the E0463 check that `-C instrument-coverage`
    #      triggers).  We point its build script at an empty stub
    #      `libclang_rt.profile-x86_64.a` via `LLVM_PROFILER_RT_LIB` so
    #      the std build does not try to compile compiler-rt from C
    #      source (which would need LLVM compiler-rt source on the host).
    #      The kernel never CALLS into the profile runtime — the counter
    #      increments LLVM emits are inline, and `dump_profile()` walks
    #      the sections directly — so a content-free `.a` is sufficient.
    #
    #   2. Apply `-C instrument-coverage` to ONLY the astryx-kernel crate
    #      via per-package `profile.release.package."astryx-kernel".rustflags`
    #      (requires the `profile-rustflags` cargo feature, which we
    #      opt into at the workspace root).  If we set the flag globally
    #      `profiler_builtins` itself recurses on E0463.  Scoping to one
    #      crate keeps `core` / `alloc` un-instrumented, which is fine —
    #      kernel test coverage is the audit's only goal.
    #
    #   3. Ensure the empty stub archive exists on disk before invoking
    #      cargo.  Cached across calls under HARNESS_DIR.
    coverage_extra: list = []
    env = None
    if features and "coverage" in [f.strip() for f in features.split(",")]:
        stub_lib = HARNESS_DIR / "libclang_rt.profile-x86_64.a"
        if not stub_lib.exists():
            # `ar`-format empty archive header (8-byte magic + nothing else).
            stub_lib.write_bytes(b"!<arch>\n")
        # Inject build flags + LLVM_PROFILER_RT_LIB into a copy of the env.
        env = dict(os.environ)
        env["LLVM_PROFILER_RT_LIB"] = str(stub_lib)
        coverage_extra = [
            "--config",
            'profile.release.package."astryx-kernel".rustflags = '
            '["-C","instrument-coverage"]',
        ]
        kernel_cmd += ["-Zbuild-std=core,alloc,profiler_builtins"]
    else:
        kernel_cmd += ["-Zbuild-std=core,alloc"]
    kernel_cmd += ["-Zbuild-std-features=compiler-builtins-mem",
                   "-Zjson-target-spec"]
    kernel_cmd += coverage_extra

    r2 = subprocess.run(kernel_cmd, cwd=ROOT, env=env)
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
    # Surface enough trailing stderr to capture the actual rustc error
    # diagnostic when the build fails — 4 KB was below the rustc warning
    # noise floor for large diffs and only showed warnings, hiding the
    # real error.  16 KB clears typical multi-error tails without
    # exploding the JSON envelope.
    tail = (proc.stderr or "")[-16384:]
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
                          http_host_port: int = 0,
                          ssh_host_port: int = 0,
                          kvm: Optional[bool] = None,
                          smp: int = 2,
                          cpu_model: Optional[str] = None,
                          esp_dir_override: Optional[str] = None,
                          qga_sock: str = "",
                          extra_qemu_args: Optional[list[str]] = None,
                          snapshottable: bool = False,
                          data_overlay: Optional[str] = None,
                          vmstate_qcow2: Optional[str] = None,
                          ) -> subprocess.Popen:
    """
    Launch QEMU with a per-session serial log and QMP socket.

    gdb_port: if > 0, adds -gdb tcp::PORT to the QEMU command line.
    gdb_wait: if True and gdb_port > 0, adds -S (start frozen, wait for GDB).
    kdb_host_port: if > 0, adds a hostfwd rule forwarding host-port to
        guest 10.0.2.15:9999 for the kdb introspection server.
    http_host_port: if > 0, adds a hostfwd rule forwarding host-port to
        guest 10.0.2.15:8080 for the httpd-test in-kernel HTTP responder.
        Used by --features httpd-test (PIVOT-C, 2026-05-23) so a host
        `curl http://127.0.0.1:<port>/` reaches the kernel HTTP server.
    ssh_host_port: if > 0, adds a hostfwd rule forwarding host-port to
        guest 10.0.2.15:22 for the sshd-test userspace dropbear daemon.
        Used by --features sshd-test (PIVOT-D, 2026-05-23) so a host
        `ssh -p <port> root@127.0.0.1` reaches the guest dropbear.
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
    # OVMF_VARS varstore. Under --snapshottable it must be a writable qcow2
    # (writable so EDK2 boots, qcow2 so it participates in savevm) — convert
    # the raw template to qcow2. Otherwise a plain raw copy (unchanged).
    if snapshottable:
        qi = shutil.which("qemu-img") or "qemu-img"
        # If a qcow2 varstore already exists at this path (snap-gate load
        # relaunch reuses the path), keep it so firmware vars persist; else
        # convert the raw template.
        if not Path(ovmf_vars_dst).exists():
            subprocess.run([qi, "convert", "-f", "raw", "-O", "qcow2",
                            str(OVMF_VARS_SRC), str(ovmf_vars_dst)],
                           check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE)
    else:
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
        extra_args=list(extra_qemu_args) if extra_qemu_args else None,
        warn_on_missing_data_img=True,
        snapshottable=snapshottable,
        data_overlay=data_overlay,
        vmstate_qcow2=vmstate_qcow2,
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
    #
    # Multiple `hostfwd=` clauses can be appended to a single -netdev arg
    # (comma-separated) per QEMU SLIRP docs, so kdb + http hostfwd rules
    # can coexist on the same NIC.
    if kdb_host_port and kdb_host_port > 0:
        for i, arg in enumerate(cmd):
            if arg == "-netdev" and i + 1 < len(cmd) and cmd[i + 1].startswith("user,id=net0"):
                cmd[i + 1] = cmd[i + 1] + f",hostfwd=tcp:127.0.0.1:{kdb_host_port}-:9999"
                break
    if http_host_port and http_host_port > 0:
        for i, arg in enumerate(cmd):
            if arg == "-netdev" and i + 1 < len(cmd) and cmd[i + 1].startswith("user,id=net0"):
                cmd[i + 1] = cmd[i + 1] + f",hostfwd=tcp:127.0.0.1:{http_host_port}-:8080"
                break
    if ssh_host_port and ssh_host_port > 0:
        for i, arg in enumerate(cmd):
            if arg == "-netdev" and i + 1 < len(cmd) and cmd[i + 1].startswith("user,id=net0"):
                cmd[i + 1] = cmd[i + 1] + f",hostfwd=tcp:127.0.0.1:{ssh_host_port}-:22"
                break

    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # Detach QEMU into its own session/process-group so it survives the
        # teardown of the (possibly short-lived) shell that invoked `start`.
        # Without this, an agent that runs `start` as a backgrounded one-shot
        # has QEMU reaped (SIGKILL) the moment that wrapper process tree is
        # cleaned up — even though the session JSON/serial-log persist on disk,
        # leaving a "no_session"/defunct-qemu mismatch.  setsid is the standard
        # POSIX way to orphan a long-lived child from its launcher.
        start_new_session=True,
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


def _regen_data_img(root_dir: Path,
                    firefox_variant: "str | None" = None,
                    extra_flags: "list[str] | None" = None,
                    extra_env: "dict[str, str] | None" = None) -> dict:
    """
    Invoke `scripts/create-data-disk.sh --force` and capture its outcome.

    Returns:
      ok: bool        — True iff the script exited 0
      rc: int
      duration_s: float
      tail: str       — last ~1500 chars of stderr (so a failure surfaces)
      argv: list[str] — full argv handed to the child (for debuggability)
      env_overrides: dict[str, str] — env vars layered on top of os.environ

    `firefox_variant`, when set, is exported to the child shell as
    ASTRYXOS_FIREFOX_VARIANT so the data-disk builder stages the requested
    libc/Firefox combination (see create-data-disk.sh: glibc | musl).  When
    None, the script's default applies (currently glibc; controlled by the
    script, not the harness).

    `extra_flags` are appended verbatim to the create-data-disk.sh argv
    after `--force`.  Used to forward demo-binary opt-ins
    (e.g. `--oracle`, `--sshd`, `--tls`) so an auto-restage triggered by
    the variant-pin guard does not silently drop staging the user
    previously opted into.

    `extra_env` is layered on top of os.environ (and after the
    ASTRYXOS_FIREFOX_VARIANT injection).  Mirrors the env-var equivalents
    of the demo-binary flags (ASTRYXOS_ORACLE, ASTRYXOS_SSHD, ASTRYXOS_TLS)
    for callers that prefer env to argv.

    The script logs to stdout (mixed with stderr by some sub-scripts); we
    fold both streams together and keep the tail for diagnostics.
    """
    script = root_dir / "scripts" / "create-data-disk.sh"
    flags = list(extra_flags or [])
    env_overrides = dict(extra_env or {})
    argv = ["bash", str(script), "--force", *flags]
    out = {"ok": False, "rc": -1, "duration_s": 0.0, "tail": "",
           "firefox_variant": firefox_variant,
           "argv": argv,
           "env_overrides": env_overrides}
    if not script.exists():
        out["tail"] = f"create-data-disk.sh not found at {script}"
        return out
    env = os.environ.copy()
    if firefox_variant:
        env["ASTRYXOS_FIREFOX_VARIANT"] = firefox_variant
    for k, v in env_overrides.items():
        env[k] = v
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(root_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=900,  # 15 min — generous; full Firefox copy is ~3 min
            env=env,
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


# ── Demo-binary flag preservation (auto-restage path) ─────────────────────────
#
# When the variant-pin guard re-invokes scripts/create-data-disk.sh to swap
# between the musl and glibc Firefox layouts, the auto-restage runs with a
# bare `--force` — none of the user's prior demo-binary opt-ins (--oracle,
# --sshd, --tls / ASTRYXOS_ORACLE=1, ASTRYXOS_SSHD=1, ASTRYXOS_TLS=1) carry
# across.  Result: the previously-staged demo binaries vanish from data.img
# and the kernel fails at first-boot probe with `[ORACLE] FATAL: cannot
# read /disk/usr/bin/oracle: NotFound` (or the SSHD / TLS equivalents).
#
# `_resolve_demo_binary_flags` reconstructs the user's intent from two
# additive sources and folds them into one (flags, env) pair that the
# restage call can replay verbatim:
#
#   1. Explicit env vars in os.environ (ASTRYXOS_ORACLE / _SSHD / _TLS) —
#      the canonical way users opt in to demo binaries from the shell.
#      Truthy when the value is one of "1" / "true" / "yes" / "on" (case
#      insensitive).  These take precedence: if the env says ORACLE=1 we
#      stage oracle even when the cargo feature list does not include
#      oracle-test (e.g. an investigation where oracle is staged on disk
#      but the kernel is built without the runtime-launch hook).
#
#   2. Cargo feature names in the harness's `--features` comma list:
#      `oracle-test` → ORACLE=1, `sshd-test` → SSHD=1, `tls-test` → TLS=1.
#      This catches the common case where the user passed
#      `--features oracle-test` and expects the staging to follow without
#      having to also export ASTRYXOS_ORACLE=1.
#
# Both flag and env forms are emitted: create-data-disk.sh accepts either,
# but emitting both is harmless (the script ORs them) and means a future
# refactor in either layer keeps working.  Additive output — agents
# parsing `firefox_variant_info.restage_extra_flags` see the resolved
# argv tail and can audit it.
_DEMO_BIN_SPEC = [
    # (cargo-feature, create-data-disk-flag, env-var-name)
    ("oracle-test",        "--oracle", "ASTRYXOS_ORACLE"),
    # oracle-daemon-test reuses the same staged binary as oracle-test
    # (same /usr/bin/oracle + glibc + libssl3 DT_NEEDED closure); the
    # only divergence is the kernel-side launcher (--once vs daemon-mode
    # + INFRASVC_SYNC_URL override).  Mapping both features to the same
    # staging flag keeps the data.img stage cost amortised — agents that
    # toggle between the two feature builds don't re-stage.
    ("oracle-daemon-test", "--oracle", "ASTRYXOS_ORACLE"),
    ("sshd-test",          "--sshd",   "ASTRYXOS_SSHD"),
    ("tls-test",           "--tls",    "ASTRYXOS_TLS"),
    # pivot-e-test (PIVOT-E, 2026-05-24) — Tier B core utilities
    # (curl/jq/tar) plus DT_NEEDED closure walker, on top of the Tier A
    # busybox surface.  --pivot-e in create-data-disk.sh auto-enables
    # --busybox and --tls (declared at the script level as implicit
    # prerequisites), so a single feature flag triggers the full stage.
    ("pivot-e-test",       "--pivot-e","ASTRYXOS_PIVOT_E"),
    # pivot-e-tui-test (PIVOT-E Tier C, 2026-05-24) — TUI utilities
    # (nano/vim/htop/tmux) on top of the PR #450 per-pair PTY substrate.
    # --pivot-e-tui in create-data-disk.sh auto-enables --pivot-e (which
    # in turn auto-enables --busybox and --tls), so a single feature flag
    # triggers the full Tier A + B + C staging closure.
    ("pivot-e-tui-test",   "--pivot-e-tui","ASTRYXOS_PIVOT_E_TUI"),
    # pivot-e-git-test (PIVOT-E Tier D, 2026-05-24) — git on top of the
    # Tier B DT_NEEDED substrate (libcurl/libssl/libz/libcrypto) plus
    # libpcre2 + libexpat staged by install-pivot-e-git.sh.  --pivot-e-git
    # in create-data-disk.sh auto-enables --pivot-e (which in turn
    # auto-enables --busybox and --tls), so a single feature flag triggers
    # the full Tier A + B + D staging closure.
    ("pivot-e-git-test",   "--pivot-e-git","ASTRYXOS_PIVOT_E_GIT"),
]


def _resolve_demo_binary_flags(features: "list[str]",
                                env: "dict[str, str] | None" = None
                                ) -> dict:
    """
    Compute the (--flag, ENV=1) set to forward into an auto-restage call.

    `features` — comma-split harness `--features` list (already trimmed).
    `env`      — env mapping to inspect (defaults to os.environ).

    Returns a dict:
      flags:        list[str]  — argv-tail e.g. ["--oracle", "--tls"]
      env:          dict[str,str]  — env additions e.g. {"ASTRYXOS_ORACLE":"1"}
      sources:      dict[str,str]  — per-flag, "env" | "feature" | None,
                                     for debuggability
    """
    if env is None:
        env = os.environ
    truthy = {"1", "true", "yes", "on"}
    flags: list = []
    env_out: dict = {}
    sources: dict = {}
    for feat_name, flag, env_var in _DEMO_BIN_SPEC:
        env_val = (env.get(env_var) or "").strip().lower()
        if env_val in truthy:
            flags.append(flag)
            env_out[env_var] = "1"
            sources[flag] = "env"
        elif feat_name in features:
            flags.append(flag)
            env_out[env_var] = "1"
            sources[flag] = "feature"
        else:
            sources[flag] = None
    return {"flags": flags, "env": env_out, "sources": sources}


# ── Firefox variant pin (D10 staging-gap guard) ───────────────────────────────
#
# Two userspace Firefox layouts can be staged into build/disk/ + build/data.img:
#
#   musl   — Alpine packages installed into  /usr/lib/firefox/firefox-bin
#                                            /usr/lib/firefox-esr/firefox-bin
#   glibc  — Mozilla-official tarball at     /opt/firefox/firefox-bin
#
# The kernel's main.rs probe selects, in order: musl-132 → musl-esr → glibc
# (first existing wins).  If the user is mid-investigation on musl but
# build/data.img was last staged for glibc, the kernel silently picks glibc
# and the run diverges from the saga.  We catch this BEFORE QEMU boots.
#
# We inspect the staged tree (build/disk/) — not the packed image — because:
#   * inspecting the FAT32 image needs mtools/mcopy, more brittle
#   * the data-disk builder always writes build/disk/ before mcopy'ing
#   * staleness logic already trips a regen if disk/ is newer than data.img
# Per-binary "firefox-bin" presence under each prefix is a sufficient signal.

# Canonical install prefixes (mirror create-data-disk.sh + kernel/main.rs probe).
# Each entry: (variant-tag, on-disk relative path of firefox-bin).
_FF_VARIANT_PROBE_PATHS = [
    ("musl-132", "usr/lib/firefox/firefox-bin"),
    ("musl-esr", "usr/lib/firefox-esr/firefox-bin"),
    ("glibc",    "opt/firefox/firefox-bin"),
]


def _detect_staged_ff_variant(disk_dir: Path) -> dict:
    """
    Inspect build/disk/ for which Firefox layouts are present and predict
    which one the kernel's [FFTEST] probe will select on boot.

    Returns:
      present: dict[tag, bool]  — one entry per (musl-132, musl-esr, glibc)
      predicted_kernel_choice: "musl-132" | "musl-esr" | "glibc" | None
      family: "musl" | "glibc" | None — coarse grouping of the predicted choice

    No I/O failure modes; missing entries surface as `present[tag] = False`.
    The kernel rule (musl-132 → musl-esr → glibc) is mirrored exactly here.
    """
    out = {"present": {}, "predicted_kernel_choice": None, "family": None}
    for tag, rel in _FF_VARIANT_PROBE_PATHS:
        try:
            out["present"][tag] = (disk_dir / rel).is_file()
        except OSError:
            out["present"][tag] = False
    for tag, _rel in _FF_VARIANT_PROBE_PATHS:
        if out["present"].get(tag):
            out["predicted_kernel_choice"] = tag
            out["family"] = "musl" if tag.startswith("musl") else "glibc"
            break
    return out


# Canonical (main-checkout) build/disk/ — used as a fallback for variant
# detection when an agent worktree has no local build/disk/ but its
# build/data.img is a symlink to the canonical build/data.img.  Mirrors
# the same path used by the data.img auto-symlink in cmd_start.
_CANONICAL_DISK_DIR = Path("/home/ubuntu/AstryxOS/build/disk")


def _data_img_symlink_info(data_img: Path, wt_root: Path) -> dict:
    """
    Classify how `build/data.img` is materialised in this worktree.

    Returns:
      is_symlink: bool — os.path.islink(data_img)
      target:    str|None — symlink target as written (may be relative)
      resolved:  str|None — fully resolved real path (after symlinks)
      target_outside_wt: bool — True when the resolved target lives outside
        `wt_root` (i.e. mutating it would clobber a different worktree's or
        the main checkout's data.img).  Conservative default False when we
        cannot resolve.

    Per POSIX symlink(7), st_mode on the link itself reports S_IFLNK; we
    use os.path.islink for that classification and os.path.realpath to
    follow the chain.  Symlink-to-symlink chains resolve to the terminal
    target.  Hardlinks are not detected here because there is no portable
    way to enumerate "files outside this worktree that share the same
    inode" — agents that hardlink data.img into a worktree are on their
    own; the symlink path is the documented one (see cmd_start banner).
    """
    out = {"is_symlink": False, "target": None, "resolved": None,
           "target_outside_wt": False}
    try:
        out["is_symlink"] = os.path.islink(str(data_img))
    except OSError:
        return out
    if out["is_symlink"]:
        try:
            out["target"] = os.readlink(str(data_img))
        except OSError:
            out["target"] = None
    try:
        out["resolved"] = os.path.realpath(str(data_img))
    except OSError:
        out["resolved"] = None
    if out["resolved"]:
        try:
            wt_real = os.path.realpath(str(wt_root))
            # commonpath raises ValueError on cross-drive paths (Windows);
            # on Linux that path never trips for our absolute paths.
            common = os.path.commonpath([out["resolved"], wt_real])
            out["target_outside_wt"] = (common != wt_real)
        except (ValueError, OSError):
            out["target_outside_wt"] = False
    return out


def _resolve_effective_disk_dir(wt_root: Path, data_img: Path) -> Path:
    """
    Return the disk_dir that should be inspected for the FF-variant probe.

    Prefer the worktree's own `build/disk/` when it exists.  When it does
    not (typical for agent worktrees, which are .gitignored for the whole
    `build/` tree) and `build/data.img` is a symlink to the canonical
    image, fall back to the canonical `build/disk/` so the variant pin
    can still observe the staged layout.  Otherwise return the worktree
    path unchanged so callers' `.exists()` check fails the soft way.
    """
    local = wt_root / "build" / "disk"
    if local.exists():
        return local
    sym = _data_img_symlink_info(data_img, wt_root)
    if sym["is_symlink"] and sym["resolved"]:
        # If the symlink target is inside the canonical AstryxOS build/, use
        # the canonical disk_dir for probe inspection.  We never mutate it —
        # the variant-pin regen path refuses to clobber shared targets.
        canonical_data_img = "/home/ubuntu/AstryxOS/build/data.img"
        try:
            if os.path.realpath(canonical_data_img) == sym["resolved"]:
                return _CANONICAL_DISK_DIR
        except OSError:
            pass
    return local


# Regex for the kernel's post-boot variant probe line.  Each "Ok(<size>)" /
# "Err(<errcode>)" group reflects whether vfs::stat() succeeded for that path.
# Example: "[FFTEST] FF binary probe: musl-132=Ok(795616) musl-esr=Err(NotFound) glibc=Err(NotFound)"
_FF_PROBE_RE = re.compile(
    r"\[FFTEST\] FF binary probe: "
    r"musl-132=(?P<m132>Ok\([^)]*\)|Err\([^)]*\))\s+"
    r"musl-esr=(?P<mesr>Ok\([^)]*\)|Err\([^)]*\))\s+"
    r"glibc=(?P<g>Ok\([^)]*\)|Err\([^)]*\))"
)


def _parse_kernel_ff_probe(line: str) -> "dict | None":
    """
    Parse a serial-log line emitted by kernel main.rs and report which
    Firefox binary the kernel actually selected.  Mirrors the rule in
    main.rs: musl-132 wins, else musl-esr, else glibc.

    Returns None if the line does not match the [FFTEST] FF binary probe
    format; otherwise a dict with `chosen` ∈ {"musl-132", "musl-esr",
    "glibc", None} and `family` ∈ {"musl", "glibc", None}.
    """
    m = _FF_PROBE_RE.search(line)
    if not m:
        return None
    def _ok(s: str) -> bool:
        return s.startswith("Ok(")
    m132_ok = _ok(m.group("m132"))
    mesr_ok = _ok(m.group("mesr"))
    g_ok    = _ok(m.group("g"))
    if m132_ok:
        chosen = "musl-132"
    elif mesr_ok:
        chosen = "musl-esr"
    elif g_ok:
        chosen = "glibc"
    else:
        chosen = None
    family = ("musl" if chosen and chosen.startswith("musl")
              else ("glibc" if chosen == "glibc" else None))
    return {
        "chosen": chosen,
        "family": family,
        "musl_132_present": m132_ok,
        "musl_esr_present": mesr_ok,
        "glibc_present":    g_ok,
    }


def _scan_serial_for_ff_probe(serial_log: str,
                              deadline_s: float) -> "dict | None":
    """
    Tail the serial log until either the [FFTEST] FF binary probe line is
    seen or `deadline_s` (wall-clock seconds) is reached.  Returns the
    parsed probe dict on hit; None on timeout.

    Best-effort: returns None on any I/O error.  Caller decides what to do
    with a timeout (typically: log a warning and move on).
    """
    p = Path(serial_log)
    end = time.monotonic() + deadline_s
    last_pos = 0
    while time.monotonic() < end:
        try:
            if not p.exists():
                time.sleep(0.1)
                continue
            with p.open("rb") as fh:
                fh.seek(last_pos)
                chunk = fh.read()
                last_pos += len(chunk)
            for line in chunk.decode("utf-8", errors="replace").splitlines():
                parsed = _parse_kernel_ff_probe(line)
                if parsed is not None:
                    return parsed
        except OSError:
            return None
        time.sleep(0.1)
    return None


# ══════════════════════════════════════════════════════════════════════════════

def cmd_strace_ref(args):
    """
    Front-end for scripts/strace-ref.py — Linux reference strace captures.

    Runs the AstryxOS-shipped musl firefox-esr binary under a real Linux
    kernel (the host) inside a bubblewrap sandbox, captures strace output,
    and compares against AstryxOS serial logs.  Use for ABI-conformance
    diffing when an AstryxOS wedge could be either a kernel ABI bug or a
    quirk of Mozilla's userspace.

    Subcommands (forwarded to strace-ref.py):
      setup [--bootstrap]
        Verify (or bootstrap) the Alpine reference rootfs.

      capture [--label NAME] [--binary-args ARGS] [--syscall-filter FILT]
              [--timeout SEC] [--output PATH]
        Run firefox-esr under strace; trace saved to
        ~/.astryx-harness/strace-ref/captures/<label>.trace.

      diff --linux-trace PATH --astryx-log PATH [--verbose]
        Compare a captured Linux trace against an AstryxOS serial log;
        JSON summary with by-op histogram and wedge-class notes.

      list                 Show captured traces.
      clean [--label STR]  Remove captures.

    See the strace-ref.py docstring for full details.
    """
    import subprocess as _sp
    helper = Path(__file__).parent / "strace-ref.py"
    if not helper.exists():
        _out({"ok": False, "error": f"strace-ref.py not found at {helper}"})
        return 1
    cmd = [sys.executable, str(helper)] + (args.strace_ref_args or [])
    result = _sp.run(cmd)
    return result.returncode


def cmd_differential_soak(args):
    """
    Front-end for scripts/differential-soak.py — INFRA-1 differential
    bytestream harness.

    Runs the AstryxOS-shipped musl firefox-bin under BOTH the host Linux
    kernel (via strace-ref.py + bwrap) and the AstryxOS QEMU kernel, then
    diffs the two syscall bytestreams and reports the FIRST divergence
    in a structured JSON object.

    Replaces the "guess-a-hypothesis-then-soak" saga loop with continuous
    differential observation.  Every divergence is a named ABI gap that
    an engineering agent can pick up directly.

    Subcommand arguments (forwarded to differential-soak.py):
      --baseline-lxc NAME              [accepted for forward compat; ignored]
      --astryx-features FLAGS          (default: firefox-test,differential-trace)
      --max-syscalls N                 truncate each stream to N records
      --boot-timeout-ms MS             ms to wait for boot banner (180000)
      --linux-timeout-s SEC            strace wall-clock budget (30)
      --linux-binary-args ARGS         firefox-bin argv tail
      --snapshots PATH                 override snapshot config
                                       (default: scripts/differential/snapshots.yaml)
      --reuse-linux-capture LABEL      reuse prior strace trace
      --reuse-astryx-log PATH          reuse prior serial log
      --output PATH                    also write full JSON to PATH
      --no-build                       skip cargo rebuild
      --no-kvm                         debug-only TCG run
      --keep-session                   leave AstryxOS QEMU running

    Output (stdout, one JSON object):
      {
        "ok": true,
        "subcommand": "differential-soak",
        "linux":  {...},
        "astryx": {...},
        "first_divergence": {"sc_index": N, "kind": ..., "linux": ..., "astryx": ...},
        "summary": {...},
        "snapshot_hits": [...]
      }

    See scripts/differential-soak.py docstring for full details.
    """
    import subprocess as _sp
    helper = Path(__file__).parent / "differential-soak.py"
    if not helper.exists():
        _out({"ok": False,
              "error": f"differential-soak.py not found at {helper}"})
        return 1
    cmd = [sys.executable, str(helper)] + (args.differential_args or [])
    return _sp.run(cmd).returncode


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


def cmd_ci_run(args):
    """
    ci-run: Build, boot, and run the full kernel test suite in one command.

    Intended for CI use (replaces the banned watch-test.py wrapper):
      - Builds the kernel with --features (default: test-mode)
      - Launches QEMU and waits for the test suite to complete
      - Parses [TEST-JSON] lines from the serial log
      - Applies --allow-fail regex to downgrade listed failures
      - Exits 0 on pass (or when all failures are allow-listed), 1 on failure

    Example (CI):
      python3 scripts/qemu-harness.py ci-run \\
        --features test-mode \\
        --timeout-ms 900000 \\
        --allow-fail 'Musl hello|dynamic_elf|pie_elf|TCC compile|busybox basic|sigchld|ascension|firefox_oracle|unix socketpair EPOLLIN gating'

    Output (to stdout, JSON):
      {"ok": true/false, "passed": N, "failed": N, "allowed_failures": [...],
       "real_failures": [...], "sid": "...", "exit_cause": "..."}
    """
    import types

    features = args.features or "test-mode"
    timeout_ms = args.timeout_ms
    allow_fail_pat = args.allow_fail or ""
    no_build = getattr(args, "no_build", False)
    no_kvm = getattr(args, "no_kvm", False)

    # Compile the allow-fail regex once so a bad pattern is caught up front.
    allow_re = None
    if allow_fail_pat:
        try:
            allow_re = re.compile(allow_fail_pat)
        except re.error as e:
            _err(f"--allow-fail is not a valid regex: {e}")

    # --- Step 1: build ---
    if not no_build:
        print("[ci-run] building kernel ...", file=sys.stderr)
        ok = _build(features)
        if not ok:
            result = {"ok": False, "error": "build_failed", "features": features}
            print(json.dumps(result, indent=2))
            return 1

    # --- Step 2: start QEMU ---
    # Synthesise a minimal args namespace that cmd_start expects.
    start_args = types.SimpleNamespace(
        features=features,
        no_build=True,          # build already done above
        gdb_port=0,
        gdb_wait=False,
        no_kvm=no_kvm,
        force_kvm=False,
        smp=2,
        cpu_model=None,
        no_regen_data_img=False,
    )
    # cmd_start prints a JSON start record to stdout.  Redirect stdout to
    # stderr during the call so it doesn't pollute our final JSON output.
    before_sids = {p.stem for p in HARNESS_DIR.glob("*.json")}

    print("[ci-run] launching QEMU ...", file=sys.stderr)
    _orig_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        cmd_start(start_args)  # may call sys.exit() on hard error
    finally:
        sys.stdout = _orig_stdout

    after_sids = {p.stem for p in HARNESS_DIR.glob("*.json")}
    new_sids = after_sids - before_sids
    if not new_sids:
        result = {"ok": False, "error": "session_not_created"}
        print(json.dumps(result, indent=2))
        return 1
    sid = sorted(new_sids)[-1]
    print(f"[ci-run] session sid={sid}", file=sys.stderr)

    # --- Step 3: wait for test suite completion marker ---
    # The kernel prints either:
    #   [TEST SUITE] ✓ ALL TESTS PASSED
    #   [TEST SUITE] ✗ N TESTS FAILED
    # Both end the test run; we scan for the common prefix.
    suite_done_re = r"\[TEST SUITE\]"
    print(f"[ci-run] waiting up to {timeout_ms // 1000}s for [TEST SUITE] ...",
          file=sys.stderr)

    # Inline wait loop (mirrors cmd_wait logic but doesn't need a separate
    # args namespace — avoids calling cmd_wait which prints JSON to stdout).
    sess = _load_session(sid)
    serial_log = sess["serial_log"]
    pattern = re.compile(suite_done_re)
    deadline = time.monotonic() + timeout_ms / 1000.0
    file_pos = 0
    suite_found = False
    while time.monotonic() < deadline:
        pid = sess.get("pid", 0)
        try:
            with Path(serial_log).open("r", errors="replace") as fh:
                fh.seek(file_pos)
                chunk = fh.read(65536)
                if chunk:
                    for ln in chunk.splitlines(keepends=True):
                        if pattern.search(ln):
                            suite_found = True
                            break
                    file_pos += len(chunk.encode("utf-8", errors="replace"))
        except OSError:
            pass
        if suite_found:
            break
        if pid and not _pid_alive(pid):
            # QEMU exited — do a final drain
            try:
                with Path(serial_log).open("r", errors="replace") as fh:
                    fh.seek(file_pos)
                    for ln in fh.readlines():
                        if pattern.search(ln):
                            suite_found = True
                            break
            except OSError:
                pass
            break
        time.sleep(0.5)

    # --- Step 4: stop the session ---
    # Redirect stdout during stop so cmd_stop's JSON doesn't pollute ours.
    try:
        stop_args = types.SimpleNamespace(sid=sid)
        _s = sys.stdout
        sys.stdout = sys.stderr
        try:
            cmd_stop(stop_args)
        finally:
            sys.stdout = _s
    except Exception:
        pass

    if not suite_found:
        # QEMU died or timed out before printing the suite banner.
        exit_cause = _classify_exit_cause(serial_log, False)
        result = {
            "ok": False,
            "error": "suite_not_completed",
            "sid": sid,
            "exit_cause": exit_cause,
            "timeout_ms": timeout_ms,
        }
        print(json.dumps(result, indent=2))
        return 1

    # --- Step 5: parse test results from serial log ---
    tests: list = []
    libs_loaded: list = []
    failed_opens: list = []
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
                    buf = buf[nl + 1:]
                    _scan_line(line_b, tests, libs_loaded, failed_opens)
    except OSError as e:
        _err(f"Cannot read serial log {serial_log}: {e}")

    # --- Step 6: apply --allow-fail filtering ---
    passed_tests = [t for t in tests if t.get("result") == "pass"]
    failed_tests = [t for t in tests if t.get("result") == "fail"]

    allowed_failures = []
    real_failures = []
    for t in failed_tests:
        name = t.get("name", "")
        if allow_re and allow_re.search(name):
            allowed_failures.append(name)
        else:
            real_failures.append(name)

    exit_cause = _classify_exit_cause(serial_log, False)
    overall_ok = len(real_failures) == 0

    result = {
        "ok": overall_ok,
        "sid": sid,
        "exit_cause": exit_cause,
        "features": features,
        "passed": len(passed_tests),
        "failed": len(failed_tests),
        "allowed_failures": allowed_failures,
        "real_failures": real_failures,
        "total_tests": len(tests),
    }
    print(json.dumps(result, indent=2))

    if not overall_ok:
        print(
            f"[ci-run] FAILED — {len(real_failures)} unallowed failure(s): "
            f"{real_failures}",
            file=sys.stderr,
        )
    else:
        print(
            f"[ci-run] PASSED — {len(passed_tests)} pass, "
            f"{len(allowed_failures)} allowed-fail, "
            f"{len(real_failures)} real-fail",
            file=sys.stderr,
        )

    return 0 if overall_ok else 1


# ══════════════════════════════════════════════════════════════════════════════
# allowlist — manage ci/allow-fail.json (structured CI expected-fail registry)
# ══════════════════════════════════════════════════════════════════════════════
#
# Replaces a hand-edited regex string baked into .github/workflows/build.yml
# with a structured JSON file at ci/allow-fail.json.  Agents and CI can
# query / edit entries through one-shot argv calls (no manual YAML editing
# in the workflow when a test like WriteConsoleA legitimately flips to
# expected-fail mode while a fix lands).
#
# File schema:
#   {
#     "entries": [
#       {"name": "<test name substring>",
#        "reason": "<one-liner>",
#        "tracking": "<issue / PR ref>" | null,
#        "regex": false}              # optional; if true, name is a regex
#     ]
#   }
#
# The workflow renders this into the regex that `ci-run --allow-fail`
# consumes by invoking `qemu-harness.py allowlist regex`.

_ALLOWLIST_PATH_DEFAULT = "ci/allow-fail.json"


def _allowlist_path(args) -> Path:
    """Resolve the allowlist file path.

    Order of precedence:
      1. --file argument
      2. ASTRYX_ALLOWLIST environment variable
      3. <repo root>/ci/allow-fail.json   (repo root inferred from this script)
    """
    p = getattr(args, "file", None)
    if p:
        return Path(p).expanduser().resolve()
    env = os.environ.get("ASTRYX_ALLOWLIST")
    if env:
        return Path(env).expanduser().resolve()
    # Two levels up from scripts/qemu-harness.py → repo root.
    return (Path(__file__).resolve().parent.parent / _ALLOWLIST_PATH_DEFAULT).resolve()


def _allowlist_load(path: Path) -> dict:
    """Load and minimally validate the allowlist JSON file.

    Duplicate entries (same name + same regex-flag) are silently dropped,
    keeping the first occurrence and emitting a warning to stderr per
    dropped duplicate.  Without dedup the rendered regex would contain
    repeated alternatives (``x|x``); harmless to the matcher but a sign
    the file has been edited concurrently or by hand-merge.  Warn-and-
    keep-first chosen over hard-reject so a live CI run is not blocked by
    a typo a human can fix at leisure.
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {"entries": []}
    except (OSError, json.JSONDecodeError) as e:
        _err(f"cannot read allowlist {path}: {e}")
    if not isinstance(data, dict):
        _err(f"allowlist {path} is not a JSON object")
    entries = data.get("entries", [])
    if not isinstance(entries, list):
        _err(f"allowlist {path}: 'entries' is not a list")
    # De-duplicate, keeping first occurrence.  Key on (name, regex-flag)
    # so a literal-name entry and a regex-name entry that happen to share
    # the same string are not collapsed (they target different patterns).
    seen: set = set()
    deduped: list = []
    for e in entries:
        if not isinstance(e, dict):
            # Preserve odd entries so the validation path stays loud
            # downstream rather than silently dropping malformed data.
            deduped.append(e)
            continue
        key = (e.get("name", ""), bool(e.get("regex")))
        if key in seen:
            print(f"[allowlist] {path}: dropping duplicate entry "
                  f"name={key[0]!r} regex={key[1]} (keeping first)",
                  file=sys.stderr)
            continue
        seen.add(key)
        deduped.append(e)
    # Drop any inline _comment field for consumers; tolerate extras.
    return {"entries": deduped}


def _allowlist_save(path: Path, data: dict, preserve_comment: bool = True) -> None:
    """Save the allowlist back to disk.

    Preserves any top-level "_comment" field that may already be present in
    the file (the schema is described in a "_comment" array at the head of
    ci/allow-fail.json — we don't want one-off edits to wipe it).
    """
    existing_comment = None
    if preserve_comment and path.exists():
        try:
            with path.open("r", encoding="utf-8") as fh:
                old = json.load(fh)
            if isinstance(old, dict) and "_comment" in old:
                existing_comment = old["_comment"]
        except (OSError, json.JSONDecodeError):
            pass
    out: dict = {}
    if existing_comment is not None:
        out["_comment"] = existing_comment
    out["entries"] = data.get("entries", [])
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(out, indent=2) + "\n")
    tmp.replace(path)


_ALLOWLIST_NEVER_MATCH_SENTINEL = "(?!)"
"""Sentinel regex returned when the allowlist renders to no usable entries.

`(?!)` is a negative lookahead with an empty inner pattern; the empty
pattern always matches, so the negative lookahead can never succeed.
Spliced into the workflow's `--allow-fail "\\[FAIL\\] (...)"` template it
yields a pattern that matches nothing — the only safe default when the
allowlist is empty.

Using a sentinel (rather than the empty string) closes a silent-CI-green
hole: bash splicing `""` into `(...)` produces `()`, an empty group which
matches every `[FAIL]` line.  See workflow comment in build.yml.
"""


def _allowlist_to_regex(entries: list) -> str:
    """Render entries → an alternation regex suitable for ci-run --allow-fail.

    Each entry's "name" is escaped (re.escape) unless "regex": true is set,
    in which case it is taken verbatim.

    When there are no usable entries we return a never-match sentinel
    (``(?!)``) rather than an empty string — splicing ``""`` into the
    workflow's ``\\[FAIL\\] (REGEX)`` template would produce ``()``, an
    empty group that matches every ``[FAIL]`` line and silently turns a
    wiped allowlist into a green CI build.  The sentinel matches nothing,
    preserving the intended "tolerate no failures" semantics.
    """
    parts = []
    for e in entries:
        name = e.get("name", "")
        if not name:
            continue
        if e.get("regex"):
            parts.append(f"(?:{name})")
        else:
            parts.append(re.escape(name))
    if not parts:
        return _ALLOWLIST_NEVER_MATCH_SENTINEL
    return "|".join(parts)


def cmd_allowlist(args):
    """
    Manage ci/allow-fail.json (the structured CI expected-fail registry).

    Subcommands:
      list                     — print all entries as JSON
      regex                    — print the rendered allow-fail regex string
                                 (stdout has NO trailing newline; suitable
                                 for `$(... allowlist regex)` in shell).
      add --name N [--reason R] [--tracking T] [--regex]
                               — append a new entry; refuses duplicates
      remove --name N          — remove the first matching entry
      check --serial-log P     — scan a serial log and report which [FAIL]
                                 lines are matched by the allowlist, which
                                 are not, and any entries that did NOT match
                                 anything (potential drift).

    All forms accept --file PATH to override the default ci/allow-fail.json.
    """
    sub = getattr(args, "alsub", None)
    path = _allowlist_path(args)
    data = _allowlist_load(path)
    entries = data["entries"]

    if sub == "list":
        _out({"path": str(path), "entries": entries})
        return 0

    if sub == "regex":
        # Print verbatim (no trailing newline) so callers can splice into
        # other commands without trimming.  Also expose a JSON form on
        # stderr so the call is debuggable.
        rx = _allowlist_to_regex(entries)
        sys.stdout.write(rx)
        sys.stdout.flush()
        print(f"[allowlist] {len(entries)} entry/entries, regex len={len(rx)}",
              file=sys.stderr)
        return 0

    if sub == "add":
        name = getattr(args, "name", "") or ""
        if not name:
            _err("allowlist add: --name is required")
        for e in entries:
            if e.get("name") == name and bool(e.get("regex")) == bool(getattr(args, "regex_flag", False)):
                _out({"ok": False, "error": "duplicate", "entry": e,
                      "path": str(path)})
                return 1
        new_entry: dict = {
            "name": name,
            "reason": getattr(args, "reason", "") or "",
            "tracking": getattr(args, "tracking", None),
        }
        if getattr(args, "regex_flag", False):
            new_entry["regex"] = True
        entries.append(new_entry)
        _allowlist_save(path, {"entries": entries})
        _out({"ok": True, "added": new_entry, "total": len(entries),
              "path": str(path)})
        return 0

    if sub == "remove":
        name = getattr(args, "name", "") or ""
        if not name:
            _err("allowlist remove: --name is required")
        for i, e in enumerate(entries):
            if e.get("name") == name:
                removed = entries.pop(i)
                _allowlist_save(path, {"entries": entries})
                _out({"ok": True, "removed": removed,
                      "remaining": len(entries), "path": str(path)})
                return 0
        _out({"ok": False, "error": "not_found", "name": name,
              "path": str(path)})
        return 1

    if sub == "check":
        serial = getattr(args, "serial_log", "") or ""
        if not serial:
            _err("allowlist check: --serial-log is required")
        if not Path(serial).exists():
            _err(f"allowlist check: serial log {serial} does not exist")
        # Compile per-entry regexes so we can attribute matches back to the
        # specific allowlist line.
        compiled: list = []
        for e in entries:
            pat = e.get("name", "")
            if not pat:
                continue
            if not e.get("regex"):
                pat = re.escape(pat)
            try:
                compiled.append((re.compile(pat), e))
            except re.error as ex:
                _err(f"allowlist check: bad regex for {e!r}: {ex}")
        fail_re = re.compile(r"\[FAIL\]\s*(.+?)\s*$")
        matched_entries: set = set()
        allowed: list = []
        unallowed: list = []
        try:
            with open(serial, "r", errors="replace") as fh:
                for ln in fh:
                    m = fail_re.search(ln)
                    if not m:
                        continue
                    name = m.group(1)
                    hit = None
                    for (rx, e) in compiled:
                        if rx.search(name):
                            hit = e
                            break
                    if hit is not None:
                        matched_entries.add(hit.get("name", ""))
                        allowed.append({"name": name, "by": hit.get("name", "")})
                    else:
                        unallowed.append({"name": name})
        except OSError as ex:
            _err(f"allowlist check: cannot read {serial}: {ex}")
        unused = [e for e in entries
                  if e.get("name", "") and e.get("name") not in matched_entries]
        _out({
            "ok": len(unallowed) == 0,
            "serial_log": serial,
            "allowed_failures": allowed,
            "unallowed_failures": unallowed,
            "unused_entries": unused,
            "total_entries": len(entries),
        })
        return 0 if len(unallowed) == 0 else 1

    _err(f"allowlist: unknown subcommand {sub!r}")
    return 1


# ══════════════════════════════════════════════════════════════════════════════
# soak — run N trials of ci-run and aggregate results
# ══════════════════════════════════════════════════════════════════════════════
#
# Cross-walk diagnostics repeatedly need 3–5 sequential ci-run invocations
# with the results aggregated.  Doing this by hand wastes dispatch time and
# the resulting per-trial JSON has to be glued together manually.
#
# `soak` does it once, structurally:
#   * runs N trials of ci-run with the same features + allow-fail
#   * builds the kernel ONCE up front (--no-build for the trials themselves)
#   * collects per-trial pass / fail / real_failures + exit_cause
#   * computes a flake report: tests that pass in some trials and fail in
#     others (the most actionable signal for race investigations)
#
# Output schema (additive — extra keys are fine for callers):
#   {
#     "ok":              bool,                  # all N trials had ok=true
#     "trials":          int,                   # N
#     "trials_ok":       int,                   # how many had ok=true
#     "features":        str,
#     "per_trial":       [{"trial": i, "ok": ..., "passed": ..., ...}, ...],
#     "flaky_tests":     [{"name": "...", "pass": k, "fail": N-k}, ...],
#     "consistent_fail": [{"name": "...", "trials": N}, ...],
#     "exit_causes":     {"clean": k, "panic": j, ...}
#   }

def cmd_soak(args):
    """
    Run ci-run N times and aggregate results.

    Example:
      python3 scripts/qemu-harness.py soak \\
          --trials 3 \\
          --features test-mode \\
          --timeout-ms 900000 \\
          --use-allowlist
    """
    import types
    import io

    trials = max(1, int(getattr(args, "trials", 3) or 3))
    features = args.features or "test-mode"
    timeout_ms = int(getattr(args, "timeout_ms", 900000) or 900000)
    no_kvm = bool(getattr(args, "no_kvm", False))

    # Resolve allow-fail: either explicit --allow-fail, or render from the
    # allowlist file if --use-allowlist was passed.  An explicit --allow-fail
    # always wins.
    allow_fail = getattr(args, "allow_fail", "") or ""
    if not allow_fail and getattr(args, "use_allowlist", False):
        path = _allowlist_path(args)
        data = _allowlist_load(path)
        allow_fail = _allowlist_to_regex(data["entries"])
        print(f"[soak] using allowlist {path} → {len(data['entries'])} entries",
              file=sys.stderr)

    # Single up-front build (mirrors what ci-run would do on trial 1) so the
    # trials only differ in QEMU launch.  --no-build is force-passed to the
    # per-trial ci-run calls.
    no_build_outer = bool(getattr(args, "no_build", False))
    if not no_build_outer:
        print(f"[soak] building kernel once for {trials} trials ...",
              file=sys.stderr)
        ok = _build(features)
        if not ok:
            result = {"ok": False, "error": "build_failed",
                      "features": features, "trials": trials}
            print(json.dumps(result, indent=2))
            return 1

    per_trial: list = []
    exit_causes: dict = {}
    # Per-test fail counts across trials, indexed by test name.
    fail_counts: dict = {}

    for i in range(1, trials + 1):
        print(f"[soak] === trial {i}/{trials} ===", file=sys.stderr)
        ci_args = types.SimpleNamespace(
            features=features,
            no_build=True,            # always reuse the up-front build
            timeout_ms=timeout_ms,
            allow_fail=allow_fail,
            no_kvm=no_kvm,
        )
        # Capture ci-run's stdout JSON (the function prints the JSON itself).
        # Redirect stdout to a buffer, then parse it back.
        #
        # cmd_ci_run delegates to cmd_start, which calls _err() / sys.exit()
        # on hard errors (QEMU spawn failure, missing data.img, frozen-ESP
        # FileNotFoundError, etc.).  Without the outer try/except the first
        # such failure would abort the entire soak before any aggregation —
        # the worst possible outcome for a cross-walk diagnostic where the
        # whole point is repeat sampling.  Catch SystemExit (and any other
        # BaseException short of KeyboardInterrupt) and synthesise a
        # trial_aborted record so the remaining trials still run.
        _orig_stdout = sys.stdout
        captured = io.StringIO()
        sys.stdout = captured
        # Snapshot sessions before the trial so we can best-effort clean up
        # a session that the failing cmd_start may have left behind.
        sids_before = {p.stem for p in HARNESS_DIR.glob("*.json")}
        rc: int = 0
        aborted_cause: str = ""
        try:
            try:
                rc = cmd_ci_run(ci_args)
            finally:
                sys.stdout = _orig_stdout
        except SystemExit as ex:
            rc = int(ex.code) if isinstance(ex.code, int) else 1
            aborted_cause = f"system_exit code={ex.code!r}"
        except KeyboardInterrupt:
            # Honour Ctrl-C immediately — don't bury it as a trial abort.
            sys.stdout = _orig_stdout
            raise
        except BaseException as ex:  # noqa: BLE001 — intentional broad catch
            rc = 1
            aborted_cause = f"{type(ex).__name__}: {ex}"
        raw = captured.getvalue().strip()
        if aborted_cause:
            # Best-effort: tear down any QEMU session the failing trial
            # leaked so we don't accumulate zombies across trials.  Any
            # new session file appearing during the trial is presumed
            # ours (concurrent dispatch on this host is rare and the
            # alternative is a leak).
            sids_after = {p.stem for p in HARNESS_DIR.glob("*.json")}
            for leaked_sid in sids_after - sids_before:
                try:
                    cmd_stop(types.SimpleNamespace(sid=leaked_sid))
                except BaseException as cleanup_ex:  # noqa: BLE001
                    print(f"[soak] cleanup of leaked sid={leaked_sid} "
                          f"failed: {cleanup_ex}", file=sys.stderr)
            obj = {
                "ok": False,
                "error": "trial_aborted",
                "exit_cause": "trial_aborted",
                "abort_cause": aborted_cause,
                "stdout_tail": raw[:400],
            }
            print(f"[soak] trial {i} aborted: {aborted_cause}",
                  file=sys.stderr)
        else:
            try:
                obj = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                obj = {"_unparsable_stdout": raw[:400]}
        obj["trial"] = i
        obj["rc"] = rc
        per_trial.append(obj)

        cause = obj.get("exit_cause", "unknown")
        exit_causes[cause] = exit_causes.get(cause, 0) + 1

        for name in obj.get("real_failures", []) or []:
            fail_counts[name] = fail_counts.get(name, 0) + 1

    # Flake report: tests that failed in some but not all trials.
    flaky: list = []
    consistent_fail: list = []
    for name, fc in fail_counts.items():
        if fc == trials:
            consistent_fail.append({"name": name, "trials": fc})
        else:
            flaky.append({"name": name, "fail": fc, "pass": trials - fc})

    trials_ok = sum(1 for t in per_trial if t.get("ok") is True)
    overall_ok = trials_ok == trials

    result = {
        "ok": overall_ok,
        "trials": trials,
        "trials_ok": trials_ok,
        "features": features,
        "allow_fail": allow_fail,
        "per_trial": per_trial,
        "flaky_tests": sorted(flaky, key=lambda x: (-x["fail"], x["name"])),
        "consistent_fail": consistent_fail,
        "exit_causes": exit_causes,
    }
    print(json.dumps(result, indent=2))

    if not overall_ok:
        print(f"[soak] FAILED — {trials_ok}/{trials} trials ok; "
              f"flaky={len(flaky)} consistent_fail={len(consistent_fail)}",
              file=sys.stderr)
    else:
        print(f"[soak] PASSED — {trials_ok}/{trials} trials ok",
              file=sys.stderr)

    return 0 if overall_ok else 1


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


def cmd_build(args):
    """
    Run the REAL kernel build (`cargo +nightly build` for astryx-boot +
    astryx-kernel, then objcopy to the flat kernel.bin and stage the boot EFI) —
    i.e. codegen + link + ESP staging — and emit a JSON verdict with the host
    wall-clock build time.  No QEMU is launched.

    This exists so the perf-benchmark BUILD phase can time a genuine build (the
    magnitude that surfaces a slow-codegen or slow-link regression) rather than a
    type-check-only `cargo check`.  `start` already builds internally; this is the
    standalone, no-boot build for measurement.  Output is additive structured
    JSON (build_ms, ok, features) so any caller can resume.
    """
    features = args.features or ""
    t0 = time.time()
    ok = _build(features)
    build_ms = int((time.time() - t0) * 1000)
    out = {
        "ok": bool(ok),
        "features": features,
        "build_ms": build_ms,
        "probe": "build",   # vs `check` — names the magnitude captured
    }
    print(json.dumps(out, indent=2))
    return 0 if ok else 1


def _qemu_img() -> str:
    """Resolve the qemu-img binary (snap-gate creates qcow2 overlays)."""
    return shutil.which("qemu-img") or "qemu-img"


def _make_snap_topology(sid: str, data_img: str) -> dict:
    """Create the per-session snap-gate qcow2 files (vmstate + data overlay).

    Returns a dict with `vmstate_qcow2`, `data_overlay`, and `data_img`
    (the raw backing path).  Files live under SNAP_DIR keyed by sid so they
    survive `stop` — a saved snapshot must outlive its originating session.

      * vmstate qcow2  — orphan device that holds the savevm RAM/CPU blob.
        Sized generously (4 GiB virtual; qcow2 is sparse so on-disk cost is
        only the RAM actually written, ~1 GiB guest RAM + overhead).
      * data overlay   — qcow2 backed read-only by the shared raw data.img,
        so guest writes never mutate the shared image and the per-device
        data snapshot persists across stop.
    """
    vmstate = str(SNAP_DIR / f"{sid}.vmstate.qcow2")
    overlay = str(SNAP_DIR / f"{sid}.data-overlay.qcow2")
    qi = _qemu_img()
    # Orphan vmstate device. 4G virtual is ample headroom for the RAM blob.
    subprocess.run([qi, "create", "-f", "qcow2", vmstate, "4G"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    # Data overlay backed by the raw data.img (backing format must be raw).
    subprocess.run([qi, "create", "-f", "qcow2",
                    "-b", str(data_img), "-F", "raw", overlay],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return {"vmstate_qcow2": vmstate, "data_overlay": overlay,
            "data_img": str(data_img)}


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

    # ── --ff-url: validate EARLY (before the expensive build) ────────────────
    # A bad URL must fail fast, not after a multi-minute kernel rebuild.  The
    # fw_cfg argv token is appended later (where extra_qemu_args is composed);
    # here we only reject malformed input.  Validation mirrors the kernel-side
    # boot_config::url_is_valid gate (defence in depth): scheme http/https/file
    # (RFC 3986 §3.1), printable ASCII only, ≤2048 chars, and no comma (the
    # `-fw_cfg ...,string=...` argument is comma-delimited).
    ff_url = getattr(args, "ff_url", None)
    if ff_url:
        if not ff_url.startswith(("http://", "https://", "file://")):
            _err(f"--ff-url: scheme must be http/https/file (got {ff_url!r})")
        if not all(0x21 <= ord(c) <= 0x7e for c in ff_url) or len(ff_url) > 2048:
            _err(f"--ff-url: must be printable ASCII, no whitespace, <=2048 "
                 f"chars (got {ff_url!r})")
        if "," in ff_url:
            _err("--ff-url: a comma in the URL is not supported (it delimits "
                 "the -fw_cfg argument); percent-encode it as %2C")

    # ── Firefox serial profile (perf vs trace) ───────────────────────────────
    # Two profiles share the same functional kernel:
    #
    #   PERF / RENDER / CI (default):  --features firefox-test-core
    #       Functional Firefox bring-up with the high-frequency diagnostic
    #       serial emitters compiled OUT.  A boot emits <2 MB of serial instead
    #       of ~45 MB; since each emitted byte is one PIO VM-exit under KVM
    #       (Intel SDM Vol. 3C §25), this collapses the synchronous transcription
    #       cost that otherwise dominated wall-clock (~56 min → minutes).
    #
    #   DEBUG / TRACE (opt-in):  --features firefox-test-core --trace
    #       (or the back-compat super-feature  --features firefox-test)
    #       Adds firefox-test-trace → the full per-syscall mirror
    #       ([FF/stderr]/[FF/write]), [POLL_RET], per-component [VFS/resolve],
    #       and [FUTEX_*] traces, for debugging boots that want the dense log.
    #
    # --trace appends firefox-test-trace only when the core/full feature is
    # present, and prints the expansion to stderr (never injected silently —
    # the harness's standing rule).  NEVER auto-add futex-wait-scan or
    # firefox-trace-verbose; those carry extra PT-walk + serial cost and stay
    # explicit opt-ins outside both profiles.
    if getattr(args, "ff_trace", False):
        has_ff = ("firefox-test-core" in feats) or ("firefox-test" in feats)
        if has_ff and "firefox-test-trace" not in feats and "firefox-test" not in feats:
            feats.append("firefox-test-trace")
            features_str = ",".join(f for f in feats if f)
            # Write the expansion back onto args so the downstream build
            # (_build(args.features) at session start) and the recorded session
            # state both see the trace feature.  feats/features_str are kept in
            # sync for the per-feature presence checks below.
            args.features = features_str
            sys.stderr.write(
                "[harness] --trace: appended 'firefox-test-trace' → features="
                f"{features_str}\n"
            )
        elif not has_ff:
            sys.stderr.write(
                "[harness] --trace ignored: feature set has neither "
                "'firefox-test-core' nor 'firefox-test'\n"
            )

    kdb_host_port = 0
    if "kdb" in feats:
        # Derive deterministically from sid so reruns are stable and two
        # concurrent sessions almost certainly land on distinct ports.
        kdb_host_port = 9990 + (int(sid, 16) % 1000)

    # PIVOT-C (2026-05-23): when `httpd-test` is in the feature set the
    # kernel binds an in-kernel HTTP responder on TCP/8080; expose a host
    # port via SLIRP hostfwd so a host-side `curl http://127.0.0.1:<port>/`
    # reaches it.  Derived deterministically from the sid (range
    # 8800..9799) so reruns are stable and concurrent sessions almost
    # certainly land on distinct ports.  Override with --http-host-port N.
    http_host_port = int(getattr(args, "http_host_port", 0) or 0)
    if http_host_port == 0 and "httpd-test" in feats:
        http_host_port = 8800 + (int(sid, 16) % 1000)

    # PIVOT-D (2026-05-23): when `sshd-test` is in the feature set the
    # guest runs dropbear listening on TCP/22; expose a host port via SLIRP
    # hostfwd so a host-side `ssh -p <port> root@127.0.0.1` reaches it.
    # Derived deterministically from the sid (range 2200..2299) so reruns
    # are stable and concurrent sessions almost certainly land on distinct
    # ports.  Override with --ssh-host-port N.
    ssh_host_port = int(getattr(args, "ssh_host_port", 0) or 0)
    if ssh_host_port == 0 and "sshd-test" in feats:
        ssh_host_port = 2200 + (int(sid, 16) % 100)

    # QGA transport (Phase QGA-1): when the kernel was built with the `qga`
    # feature, expose a virtio-serial port + matching host Unix socket so
    # the future userspace daemon (Phase QGA-2) has a path out to the host.
    qga_sock = ""
    if "qga" in feats:
        qga_sock = str(HARNESS_DIR / f"{sid}.qga.sock")

    # PIVOT-I2 Phase D (2026-05-23): when --oracle-stub-conflux is passed
    # AND the feature set includes oracle-daemon-test, launch the host-side
    # Python stub Conflux responder on 127.0.0.1:<port>.  Records its pid
    # in the session state so cmd_stop can SIGTERM it on session teardown.
    # Heartbeats land in `<sid>.oracle-stub.jsonl` (one JSON per line).
    #
    # Defensive: if --oracle-stub-conflux is set WITHOUT oracle-daemon-test
    # in the feature list we still launch — operator may be doing a manual
    # workflow.  Print a warning to stderr so the unusual case is visible.
    oracle_stub_port = int(getattr(args, "oracle_stub_conflux", 0) or 0)
    oracle_stub_pid  = 0
    oracle_stub_log  = ""
    oracle_stub_ready_file = ""
    if oracle_stub_port > 0:
        if "oracle-daemon-test" not in feats:
            print(
                f"[harness] WARNING: --oracle-stub-conflux={oracle_stub_port} "
                f"set but oracle-daemon-test not in --features; launching "
                f"stub anyway (manual / advanced workflow).",
                file=sys.stderr,
            )
        oracle_stub_log = str(HARNESS_DIR / f"{sid}.oracle-stub.jsonl")
        oracle_stub_ready_file = str(HARNESS_DIR / f"{sid}.oracle-stub.ready")
        # Truncate any prior ready file so the post-launch wait loop
        # doesn't false-positive on a previous session's leftover.
        try:
            Path(oracle_stub_ready_file).unlink(missing_ok=True)
        except OSError:
            pass
        # Stub lives alongside this script (scripts/).  Use __file__-relative
        # path so it works whether the harness was launched via a wrapper,
        # an agent worktree, or directly.
        stub_script = Path(__file__).resolve().parent / "oracle-stub-conflux.py"
        stub_stderr_path = HARNESS_DIR / f"{sid}.oracle-stub.stderr.log"
        # Run unbuffered so stderr lines appear in the log immediately —
        # the agent tails this file looking for "[STUB-CONFLUX] heartbeat"
        # lines and we don't want python's default block-buffering hiding them.
        try:
            stub_stderr_fh = open(stub_stderr_path, "w")
            stub_proc = subprocess.Popen(
                [
                    sys.executable, "-u", str(stub_script),
                    "--port", str(oracle_stub_port),
                    "--bind", "127.0.0.1",
                    "--log", oracle_stub_log,
                    "--ready-file", oracle_stub_ready_file,
                ],
                stdin=subprocess.DEVNULL,
                stdout=stub_stderr_fh,
                stderr=stub_stderr_fh,
                start_new_session=True,
            )
            oracle_stub_pid = stub_proc.pid
            # Wait up to 5 s for the stub to bind + write its ready file.
            # If it never appears we leave the stub running (cmd_stop will
            # still SIGTERM it via the pid) but warn loudly — most likely
            # cause is EADDRINUSE which is operator-fixable.
            ready_seen = False
            for _ in range(50):
                if Path(oracle_stub_ready_file).exists():
                    ready_seen = True
                    break
                time.sleep(0.1)
            if ready_seen:
                print(
                    f"[harness] oracle-stub-conflux listening on "
                    f"127.0.0.1:{oracle_stub_port} (pid={oracle_stub_pid}, "
                    f"log={oracle_stub_log})",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[harness] WARNING: oracle-stub-conflux did not signal "
                    f"ready within 5 s; check {stub_stderr_path} for bind "
                    f"errors (EADDRINUSE most likely).  Continuing anyway.",
                    file=sys.stderr,
                )
        except OSError as e:
            print(
                f"[harness] WARNING: failed to spawn oracle-stub-conflux: {e}",
                file=sys.stderr,
            )
            oracle_stub_pid = 0
            oracle_stub_log = ""

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

    # --build-only: compile + stage the in-tree ESP, then exit WITHOUT booting
    # QEMU. The just-built kernel.bin/BOOTX64.EFI now sit at the in-tree ESP, so
    # a later `start --no-build` reuses this exact binary. Lets a host run the
    # (CPU-bound) compile while a concurrent KVM boot is in flight, then boot in
    # a quiet window — keeping cycle-accurate timing free of host-core
    # contention. Additive flag; absent → existing behaviour is unchanged.
    if getattr(args, "build_only", False):
        _out({
            "ok": True,
            "build_only": True,
            "features": args.features or "",
            "kernel_bin": str(_get_watch_test().KERNEL_BIN),
            "note": "kernel staged at in-tree ESP; boot later with "
                    "`start --no-build`",
        })
        return

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

    # --data-img OVERRIDE: point the worktree's build/data.img at an explicit
    # prebuilt image (e.g. /home/ubuntu/gui-complete.img) by replacing the
    # worktree symlink target.  A prebuilt complete image is authoritative — we
    # do NOT want the staleness check to regenerate it from build/disk/, so this
    # implies --no-regen-data-img.  Additive: when --data-img is absent the
    # behaviour is byte-identical to before.
    _data_img_override = getattr(args, "data_img_override", None)
    if _data_img_override:
        _ovr = Path(_data_img_override)
        if not _ovr.exists():
            print(json.dumps({"ok": False, "error": f"--data-img not found: {_ovr}"}))
            sys.exit(2)
        # Force no-regen for an explicit prebuilt image.
        try:
            setattr(args, "no_regen_data_img", True)
        except Exception:
            pass
        # Replace the worktree symlink/file so all downstream machinery
        # (build_qemu_cmd, snap topology) uses the override transparently.
        _data_img_path.parent.mkdir(parents=True, exist_ok=True)
        if _data_img_path.is_symlink() or _data_img_path.exists():
            try:
                _data_img_path.unlink()
            except Exception:
                pass
        _data_img_path.symlink_to(_ovr.resolve())
        print(
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║  --data-img OVERRIDE (no-regen forced)                       ║\n"
            f"║  {str(_data_img_path)[:60]:<60}  ║\n"
            f"║  -> {str(_ovr.resolve())[:57]:<57}  ║\n"
            "╚══════════════════════════════════════════════════════════════╝",
            file=sys.stderr,
        )

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
    # ── Firefox variant pin (D10 staging-gap guard) ──────────────────────────
    # `--firefox-variant` requests a specific libc + Firefox layout.  Default
    # is "musl" because that is the primary demo target as of 2026-05; agents
    # explicitly investigating the glibc plateau must pass `--firefox-variant
    # glibc`.  When the requested variant does not match what is currently
    # staged in build/disk/ we trigger an `ASTRYXOS_FIREFOX_VARIANT=<v>
    # scripts/create-data-disk.sh --force` to re-stage the disk before boot.
    _requested_variant = getattr(args, "firefox_variant", None) or "musl"
    # Resolve the demo-binary flag set ONCE so both regen sites (staleness
    # and variant mismatch) forward the same staging intent.  Without this,
    # an auto-restage runs `create-data-disk.sh --force` bare and silently
    # drops the user's prior `--oracle` / `--sshd` / `--tls` opt-ins,
    # producing `[ORACLE] FATAL: cannot read /disk/usr/bin/oracle: NotFound`
    # (or the SSHD/TLS analogue) on the next boot.  See
    # `_resolve_demo_binary_flags` for the env-vs-feature precedence rule.
    _demo_bin = _resolve_demo_binary_flags(feats)
    _ff_variant_info: dict = {
        "requested": _requested_variant,
        "staged_predicted": None,   # filled in after probe
        "regen_triggered": False,
        "regen_ok": None,
        "regen_reason": None,
        # D10 fix-it (PR #378 follow-up): when build/data.img is a symlink to
        # a path outside this worktree, an in-place create-data-disk.sh --force
        # would clobber the shared target (mkfs.fat overwrites the inode the
        # symlink points to).  We refuse that and record the reason here so
        # `events <sid>` / `status <sid>` make the inaction visible.  None
        # when no refusal happened.
        "regen_refused_reason": None,
        "data_img_symlink": None,   # populated below when relevant
        "kernel_chosen": None,      # filled in by post-boot probe verifier
        "match": None,              # final verdict, when known
        # Demo-binary flag preservation (2026-05-23): the resolved
        # (--oracle / --sshd / --tls) tail that the auto-restage path will
        # forward into create-data-disk.sh, plus the per-flag source
        # ("env" | "feature" | None) for debuggability.  Additive — never
        # rename without updating downstream agents.
        "restage_extra_flags": list(_demo_bin["flags"]),
        "restage_extra_env":   dict(_demo_bin["env"]),
        "restage_flag_sources": dict(_demo_bin["sources"]),
    }
    # D10 fix-it: in worktrees the local build/disk/ is typically absent;
    # if build/data.img is a symlink into the canonical tree, inspect that
    # tree instead so the variant probe still resolves a family.  Read-only
    # inspection — the regen path below has its own anti-clobber guard.
    _disk_dir = _resolve_effective_disk_dir(Path(wt.ROOT), _data_img_path)
    _data_img_symlink = _data_img_symlink_info(_data_img_path, Path(wt.ROOT))
    _ff_variant_info["data_img_symlink"] = _data_img_symlink
    if not _data_img_missing:
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
            _data_img_regen_info = _regen_data_img(
                Path(wt.ROOT), firefox_variant=_requested_variant,
                extra_flags=_demo_bin["flags"],
                extra_env=_demo_bin["env"])
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

    # ── Firefox variant-mismatch guard (D10) ────────────────────────────────
    # Even when data.img is fresh, the *layout* staged on it may not match
    # the variant the agent requested.  Compare the kernel's predicted
    # selection (mirrors main.rs probe rule) against `_requested_variant`;
    # re-stage with ASTRYXOS_FIREFOX_VARIANT exported when they disagree.
    # Soft-fail: if the inspection or regen can't run, we still launch — the
    # post-boot kernel-probe verifier (below) emits the final verdict either
    # way.  Re-using the staleness regen is intentional: if staleness already
    # ran the script for the right variant, the staged tree now matches and
    # we don't loop.
    _variant_info = {}
    if _disk_dir.exists():
        _variant_info = _detect_staged_ff_variant(_disk_dir)
    _ff_variant_info["staged_predicted"] = _variant_info.get(
        "predicted_kernel_choice")
    _staged_family = _variant_info.get("family")
    _need_variant_regen = (
        not _data_img_missing
        and not _data_img_regenerated  # avoid back-to-back regens
        and _staged_family is not None
        and _staged_family != _requested_variant
    )
    if _need_variant_regen:
        _ff_variant_info["regen_reason"] = (
            f"staged-family={_staged_family} != requested={_requested_variant}"
        )
        # D10 fix-it: detect the "shared symlink" scenario before doing
        # anything destructive.  scripts/create-data-disk.sh resolves
        # ${BUILD_DIR}/data.img relative to ROOT_DIR=<script>/..; in an
        # agent worktree that is <worktree>/build/data.img.  When that path
        # is a symlink to /home/ubuntu/AstryxOS/build/data.img (or any
        # target outside the worktree), `mkfs.fat -F 32 "${DATA_IMG}"`
        # writes through the link and clobbers the shared image — taking
        # every sibling agent's session down with it.  Refuse politely
        # and tell the caller exactly what to do.
        _shared_symlink = (
            _data_img_symlink.get("is_symlink")
            and _data_img_symlink.get("target_outside_wt")
        )
        if _shared_symlink and not _no_regen:
            _target_disp = (_data_img_symlink.get("resolved")
                            or _data_img_symlink.get("target") or "<unknown>")
            _ff_variant_info["regen_refused_reason"] = (
                f"data.img is a symlink to a shared target ({_target_disp}); "
                "refusing to clobber via create-data-disk.sh --force. "
                "Pass --no-regen-data-img to boot the staged variant as-is, "
                "or run scripts/create-data-disk.sh in the canonical tree."
            )
            print(
                "╔══════════════════════════════════════════════════════════════╗\n"
                "║  Firefox variant mismatch — REFUSING auto re-stage           ║\n"
                f"║  staged: {_staged_family:<10} requested: {_requested_variant:<28}║\n"
                "║  build/data.img is a symlink to a shared target; an          ║\n"
                "║  in-place re-stage would clobber sibling worktrees.          ║\n"
                f"║  target: {_target_disp[:50]:<50}    ║\n"
                "║  Either --no-regen-data-img (boot mismatched), or            ║\n"
                "║  re-stage in the canonical tree before retrying.             ║\n"
                "╚══════════════════════════════════════════════════════════════╝",
                file=sys.stderr,
            )
            print(
                f"[VARIANT-PIN] requested={_requested_variant} "
                f"staged={_staged_family} action=refused-shared-symlink",
                file=sys.stderr,
            )
        elif _no_regen:
            print(
                "╔══════════════════════════════════════════════════════════════╗\n"
                f"║  WARNING: staged FF variant ({_staged_family}) != requested ({_requested_variant})  ║\n"
                "║  --no-regen-data-img set; booting mismatched image as-is.    ║\n"
                "╚══════════════════════════════════════════════════════════════╝",
                file=sys.stderr,
            )
            print(
                f"[VARIANT-PIN] requested={_requested_variant} "
                f"staged={_staged_family} action=no-regen-warned",
                file=sys.stderr,
            )
        else:
            # 2026-05-23: surface the demo-binary flag preservation in the
            # re-stage banner so it is obvious in stderr that the auto-
            # restage is honouring the user's prior `--oracle` / `--sshd` /
            # `--tls` opt-ins (the missing-flag bug that produced
            # "[ORACLE] FATAL: cannot read /disk/usr/bin/oracle: NotFound"
            # on first-boot verification of the oracle-test track).
            _df_disp = (" ".join(_demo_bin["flags"])
                        if _demo_bin["flags"] else "<none>")
            print(
                "╔══════════════════════════════════════════════════════════════╗\n"
                "║  Firefox variant mismatch — re-staging data.img              ║\n"
                f"║  staged: {_staged_family:<10} requested: {_requested_variant:<28}║\n"
                "║  Running scripts/create-data-disk.sh --force with            ║\n"
                f"║  ASTRYXOS_FIREFOX_VARIANT={_requested_variant:<35} ║\n"
                f"║  preserved demo flags:    {_df_disp:<35} ║\n"
                "╚══════════════════════════════════════════════════════════════╝",
                file=sys.stderr,
            )
            _variant_regen = _regen_data_img(
                Path(wt.ROOT), firefox_variant=_requested_variant,
                extra_flags=_demo_bin["flags"],
                extra_env=_demo_bin["env"])
            _ff_variant_info["regen_triggered"] = True
            _ff_variant_info["regen_ok"] = bool(_variant_regen.get("ok"))
            # Fold into the existing regen-info slot so a single field carries
            # the latest invocation outcome; the older staleness regen (if any)
            # already set _data_img_regenerated above.
            _data_img_regen_info = _variant_regen
            if _variant_regen.get("ok"):
                _data_img_regenerated = True
                _variant_info = _detect_staged_ff_variant(_disk_dir)
                _ff_variant_info["staged_predicted"] = _variant_info.get(
                    "predicted_kernel_choice")
                _dur = _variant_regen.get("duration_s", 0.0)
                print(
                    f"║  variant re-stage OK in {_dur:.1f}s "
                    f"(now {_ff_variant_info['staged_predicted']}).",
                    file=sys.stderr,
                )
                print(
                    f"[VARIANT-PIN] requested={_requested_variant} "
                    f"staged={_staged_family} action=restaged-ok",
                    file=sys.stderr,
                )
            else:
                _tail = (_variant_regen.get("tail") or "")[-400:]
                print(
                    "║  variant re-stage FAILED — booting with wrong variant.   ║\n"
                    f"║  rc={_variant_regen.get('rc')}, tail: {_tail!r:<48}",
                    file=sys.stderr,
                )
                print(
                    f"[VARIANT-PIN] requested={_requested_variant} "
                    f"staged={_staged_family} action=restage-failed",
                    file=sys.stderr,
                )
    else:
        # Match case: no mismatch detected.  Still emit one line so agents
        # parsing the harness output always see the pin's decision (matches
        # cleanly to grep '\[VARIANT-PIN\]').  Skipped when the staged
        # family couldn't be determined (worktree without build/disk/ and
        # no usable symlink fallback) to avoid asserting a match we can't
        # justify — `staged_predicted: null` in the JSON tells that story.
        if _staged_family is not None:
            print(
                f"[VARIANT-PIN] requested={_requested_variant} "
                f"staged={_staged_family} action=match-no-op",
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

    extra_qemu_args = list(getattr(args, "extra_qemu_args", None) or [])

    # ── --ff-url: append the fw_cfg argv token (validated early above) ───────
    # Delivers the URL through the QEMU `opt/astryx/cmdline` fw_cfg blob the
    # kernel reads at boot (boot_config.rs reads `astryx.ff_url=<url>`), so a
    # site change needs no rebuild.  `ff_url` was already validated (scheme /
    # length / printable / no-comma) near the top of cmd_start.
    # Both the URL override and the GUI-mode flag ride in the SAME
    # opt/astryx/cmdline fw_cfg blob (fw_cfg permits one entry per name), so
    # assemble a single space-separated token string and emit one -fw_cfg.
    ff_gui = bool(getattr(args, "ff_gui", False))
    cmdline_tokens = []
    if ff_url:
        cmdline_tokens.append(f"astryx.ff_url={ff_url}")
    if ff_gui:
        cmdline_tokens.append("astryx.ff_gui=1")
    if cmdline_tokens:
        blob = " ".join(cmdline_tokens)
        extra_qemu_args += [
            "-fw_cfg",
            f"name=opt/astryx/cmdline,string={blob}",
        ]
        if ff_url:
            print(f"[HARNESS] ff-url override: {ff_url}", file=sys.stderr)
        if ff_gui:
            print("[HARNESS] ff-gui mode: ON (Firefox X11/windowed)", file=sys.stderr)

    # When `xeyes-test` is in the feature set, the kernel boots an Alpine
    # X11 binary that needs a real framebuffer for any visible window to
    # show up.  `_launch_qemu_harness` is hard-wired to mode="test", which
    # emits `-display none` without a VGA card, so QMP `screendump` returns
    # an empty frame.  Inject `-vga vmware` (matches gui-test/firefox-test
    # via astryx_qemu._display_args) so the kernel framebuffer compositor
    # has somewhere to write and QMP can pull the image.  Idempotent guard
    # so an explicit caller-supplied `-vga` is not duplicated.
    if ("xeyes-test" in feats or ff_gui) and not any(a == "-vga" for a in extra_qemu_args):
        # The windowed (--ff-gui) Firefox path drives the in-kernel Xastryx
        # server, whose compositor blits into the VMware SVGA II framebuffer
        # (kernel/src/gui/compositor.rs).  Without a VGA card QEMU comes up
        # with `-display none` and no framebuffer, so the X11 present has
        # nowhere to land and QMP `screendump` returns an empty frame.  Inject
        # the same `-vga vmware` device the gui-test / firefox-test paths use
        # so the chrome the browser paints is visible to a screendump.
        extra_qemu_args += ["-vga", "vmware"]

    # Host-side packet capture on the e1000/SLIRP netdev (net0).
    #
    # `-object filter-dump,id=netdump,netdev=net0,file=<sid>.pcap` taps the
    # netdev frontend on the HOST side (QEMU networking docs: filter-dump
    # records every packet on the named netdev to a libpcap file, RFC-less
    # classic pcap format).  Because the tap lives in the host QEMU process
    # — not the guest — the guest takes ZERO extra VM-exits; the only cost
    # is a host fwrite per frame, bounded by traffic volume (~MB per page
    # load).  This is fundamentally cheaper than the serial firehose, where
    # every emitted byte was a synchronous PIO VM-exit (Intel SDM Vol. 3C
    # §25).  The `-object` is appended via extra_qemu_args; it references
    # the netdev by id (`net0`) so the in-place hostfwd patching in
    # `_launch_qemu_harness` (which mutates the `-netdev` arg, not its id)
    # leaves the filter-dump binding intact.
    #
    # Capture defaults ON for Firefox-render boots (the FF profiles exercise a
    # real network load), so every FF boot's VM↔internet traffic is captured
    # automatically with no opt-in.  `--pcap` force-enables it for ANY boot
    # (incl. non-FF); `--no-pcap` disables it even on FF boots (for a clean
    # perf-timing run).  Precedence and the decision live in
    # `_resolve_pcap_decision`; `pcap_reason` records which rule fired.
    pcap_enabled, pcap_reason = _resolve_pcap_decision(
        feats,
        bool(getattr(args, "pcap", False)),
        bool(getattr(args, "no_pcap", False)),
    )
    pcap_path = ""
    if pcap_enabled:
        pcap_path = str(HARNESS_DIR / f"{sid}.pcap")
        extra_qemu_args += [
            "-object",
            f"filter-dump,id=netdump,netdev=net0,file={pcap_path}",
        ]
        print(f"[HARNESS] pcap capture: {pcap_path}", file=sys.stderr)
    else:
        print(f"[HARNESS] pcap capture: disabled ({pcap_reason})",
              file=sys.stderr)

    # snap-gate (--snapshottable): build the savevm/loadvm-compatible device
    # topology so the running guest can be snapshotted live.  The default
    # firefox-test boot disk (writable vvfat) + writable OVMF_VARS pflash
    # both abort `savevm` with "Device '...' is writable but does not support
    # snapshots"; --snapshottable makes them read-only and adds a dedicated
    # orphan qcow2 vmstate device + a persistent qcow2 data overlay.  Gated
    # behind the flag so all existing (non-snapshottable) harness usage is
    # byte-for-byte unaffected.
    snapshottable = bool(getattr(args, "snapshottable", False))
    snap_topology = None
    if snapshottable:
        wt_for_di = _get_watch_test()
        snap_topology = _make_snap_topology(sid, str(wt_for_di.DATA_IMG))

    proc = _launch_qemu_harness(sid, serial_log, qmp_sock, ovmf_vars,
                                 gdb_port=gdb_port, gdb_wait=gdb_wait,
                                 kdb_host_port=kdb_host_port,
                                 http_host_port=http_host_port,
                                 ssh_host_port=ssh_host_port,
                                 kvm=kvm_arg,
                                 smp=smp,
                                 cpu_model=cpu_model,
                                 esp_dir_override=esp_paths["session_esp_dir"],
                                 qga_sock=qga_sock,
                                 extra_qemu_args=extra_qemu_args,
                                 snapshottable=snapshottable,
                                 data_overlay=(snap_topology or {}).get("data_overlay"),
                                 vmstate_qcow2=(snap_topology or {}).get("vmstate_qcow2"))

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
        "http_host_port": http_host_port,
        "ssh_host_port": ssh_host_port,
        # Host-side network capture.  `pcap_path` is the source of truth —
        # the libpcap file QEMU's filter-dump object writes every guest netdev
        # frame to, or "" when capture is disabled.  serial-web serves it at
        # /api/pcap?sid=<sid> and decodes it at /api/wire?sid=<sid>.  Defaults
        # ON for FF-render boots, OFF otherwise; `--pcap` force-on, `--no-pcap`
        # force-off (precedence in `_resolve_pcap_decision`).  `pcap_enabled`
        # mirrors `bool(pcap_path)`; `pcap_reason` records which rule decided.
        # All additive — never present on sessions started before they landed.
        "pcap_path":    pcap_path,
        "pcap_enabled": pcap_enabled,
        "pcap_reason":  pcap_reason,
        # Runtime firefox-test target URL (--ff-url), delivered via fw_cfg.
        # "" / absent when the compiled CMDLINE_* default is used.  Additive.
        "ff_url":       ff_url or "",
        # Runtime firefox-test GUI/X11 windowed mode (--ff-gui), delivered via
        # the same fw_cfg cmdline blob.  False = headless (compiled default).
        "ff_gui":       bool(getattr(args, "ff_gui", False)),
        # PIVOT-I2 Phase D — host stub Conflux for oracle-daemon-test.
        # If oracle_stub_pid is 0 the stub wasn't launched (default).
        "oracle_stub_port": oracle_stub_port,
        "oracle_stub_pid":  oracle_stub_pid,
        "oracle_stub_log":  oracle_stub_log,
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
        # Livelock auto-reap config (read by the detached watcher). `enabled`
        # is False when --no-livelock-reap was passed or either threshold was
        # set to 0.  Additive — never present on sessions started before this
        # landed; the watcher falls back to the built-in defaults (guard ON).
        "livelock_reap": {
            "enabled": (not getattr(args, "no_livelock_reap", False)
                        and getattr(args, "livelock_reap_sc",
                                    LIVELOCK_REAP_SC_DEFAULT) > 0
                        and getattr(args, "livelock_reap_secs",
                                    LIVELOCK_REAP_SECS_DEFAULT) > 0),
            "reap_sc":   getattr(args, "livelock_reap_sc",
                                 LIVELOCK_REAP_SC_DEFAULT),
            "reap_secs": getattr(args, "livelock_reap_secs",
                                 LIVELOCK_REAP_SECS_DEFAULT),
        },
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
        # Firefox variant pin (D10 staging-gap guard).  `requested` is what
        # the caller asked for; `staged_predicted` is what kernel main.rs's
        # selection rule will pick from the current build/disk/ tree.  The
        # `kernel_chosen` field is updated by the post-boot verifier after
        # the kernel's "[FFTEST] FF binary probe" line is observed.
        "firefox_variant_info": _ff_variant_info,
        # snap-gate topology.  `snapshottable` records whether this session
        # was launched with the savevm/loadvm-compatible device layout;
        # `snap_vmstate_qcow2` / `snap_data_overlay` / `snap_data_img` are
        # the qcow2 files that hold the VM state + data overlay (None on
        # non-snapshottable sessions).  Additive — never present on sessions
        # started before snap-gate landed; `snap-gate load` reads these back
        # to relaunch QEMU with an identical topology.
        "snapshottable":       snapshottable,
        "snap_vmstate_qcow2":  (snap_topology or {}).get("vmstate_qcow2"),
        "snap_data_overlay":   (snap_topology or {}).get("data_overlay"),
        "snap_data_img":       (snap_topology or {}).get("data_img"),
        # Re-launch parameters captured so `snap-gate load` can spawn a fresh
        # QEMU with the same accel/cpu/smp as the saved session.
        "snap_launch": {
            "features":   args.features or "",
            "smp":        smp,
            "cpu_model":  cpu_model,
            "kvm_arg":    kvm_arg,
            "gdb_port":   gdb_port,
            "kdb_host_port": kdb_host_port,
        } if snapshottable else None,
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

    # D10: record the requested Firefox variant + staged-predicted choice up
    # front so a single `events <sid>` shows whether the pre-boot guard caught
    # a mismatch.  A follow-up `firefox_variant_probe` event is emitted by the
    # detached verifier when the kernel's [FFTEST] probe line is parsed.
    _emit_event(sid, {
        "kind": "firefox_variant_requested",
        "requested": _requested_variant,
        "staged_predicted": _ff_variant_info.get("staged_predicted"),
        "regen_triggered": _ff_variant_info.get("regen_triggered", False),
        "regen_ok": _ff_variant_info.get("regen_ok"),
        "regen_reason": _ff_variant_info.get("regen_reason"),
        # D10 fix-it (additive): None on the success path, populated when
        # variant-pin refused to clobber a shared data.img symlink target.
        "regen_refused_reason": _ff_variant_info.get("regen_refused_reason"),
        # 2026-05-23 demo-binary flag preservation: the (--oracle / --sshd /
        # --tls) tail the auto-restage forwarded into create-data-disk.sh
        # plus the per-flag source so a single `events <sid>` answers
        # "why did oracle disappear after my variant swap?".
        "restage_extra_flags":  _ff_variant_info.get("restage_extra_flags"),
        "restage_extra_env":    _ff_variant_info.get("restage_extra_env"),
        "restage_flag_sources": _ff_variant_info.get("restage_flag_sources"),
    })
    # Spawn a detached verifier that tails the serial log for the kernel's
    # "[FFTEST] FF binary probe:" line, parses the chosen variant, updates
    # the session JSON, and emits a `firefox_variant_probe` event.  Detached
    # so `start` exits promptly; the verifier's 120 s deadline is generous
    # for normal boots (kernel emits the probe within ~5–15 s).
    subprocess.Popen(
        [sys.executable, __file__, "_ff_variant_verify", sid],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    _out({"sid": sid, "pid": proc.pid, "serial_log": serial_log,
          "gdb_port": gdb_port, "kdb_host_port": kdb_host_port,
          "http_host_port": http_host_port,
          "ssh_host_port": ssh_host_port,
          # Host-side capture: path ("" when disabled) is the source of truth;
          # `pcap_enabled` mirrors bool(path); `pcap_reason` is the rule that
          # fired ("ff-default" | "pcap-forced" | "no-pcap-optout" |
          # "non-ff-default").  Additive.
          "pcap_path":    pcap_path,
          "pcap_enabled": pcap_enabled,
          "pcap_reason":  pcap_reason,
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
          # D10: Firefox variant pin.  `firefox_variant_info` reflects the
          # state at session-start time: `requested` (caller's pin), and
          # `staged_predicted` (which binary the kernel's probe rule will
          # select from the current build/disk/ tree).  The `kernel_chosen`
          # field is populated asynchronously by the post-boot verifier;
          # read it from `events <sid>` or `status <sid>` after wait().
          "firefox_variant_info": _ff_variant_info,
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

    # PIVOT-I2 Phase D (2026-05-23): tear down the host-side stub Conflux
    # responder if cmd_start launched one.  SIGTERM gets the stub's clean
    # SUMMARY line into the stderr log; if it doesn't exit in 2 s we
    # SIGKILL so we don't leak the python process across runs.
    oracle_stub_pid = sess.get("oracle_stub_pid", 0)
    if oracle_stub_pid and _pid_alive(oracle_stub_pid):
        try:
            os.kill(oracle_stub_pid, signal.SIGTERM)
            for _ in range(20):
                if not _pid_alive(oracle_stub_pid):
                    break
                time.sleep(0.1)
            if _pid_alive(oracle_stub_pid):
                os.kill(oracle_stub_pid, signal.SIGKILL)
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
            stored_terminal = sess.get("terminal_cause")
            if not alive and not stored_terminal:
                # Prune dead session.  EXCEPTION: a session the watcher reaped
                # for livelock carries a stored `terminal_cause` — keep it
                # listed (with running=False) so the dashboard/agent sees the
                # `livelock-autoreap` verdict.  An explicit `stop <sid>` removes
                # the file when the operator is done with it.
                p.unlink(missing_ok=True)
                continue
            sessions.append({
                "sid":        sess["sid"],
                "pid":        pid,
                "started_at": sess.get("started_at"),
                "features":   sess.get("features"),
                "running":    alive,
                # Additive: authoritative terminal cause (livelock-autoreap when
                # the watcher reaped a spinning boot) + the live early-warning
                # flag for boots heading toward a reap.
                "terminal_cause":     stored_terminal,
                "livelock_suspected": bool(sess.get("livelock_suspected", False)),
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
      4. `[GATE] ff-exit-clean code=C` → `firefox_exited_clean:code=C`
         (authoritative kernel marker on the pid-1 group exit; fires on the
         fast `firefox-test-core` profile, where the prose lines below may be
         compiled out)
      5. `[FFTEST] DONE` → `firefox_exited_clean`
      6. `[FFTEST] Firefox exited after N ticks` → `firefox_exited:ticks=N`
      7. Still running (process alive) → `running`
      8. Nothing of the above → `unknown_exit`

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
    m = re.search(r"\[GATE\]\s+ff-exit-clean\s+code=(-?\d+)", tail)
    if m:
        return f"firefox_exited_clean:code={m.group(1)}"
    if re.search(r"\[FFTEST\]\s+DONE", tail):
        return "firefox_exited_clean"
    m = re.search(r"\[FFTEST\]\s+Firefox exited after\s+(\d+)\s+ticks", tail)
    if m:
        return f"firefox_exited:ticks={m.group(1)}"
    return "unknown_exit"


_FF_GATES_PATH = _SCRIPTS_DIR / "ff_gates.yaml"

# sc= appears on most [SC]/trace lines; capture the running counter so we can
# tag each gate with the syscall count at which it was first reached and
# report the deepest live sc.
_FF_SC_RE = re.compile(rb"sc=(\d+)")
# An [FF/write] IPC line carries its payload in body="...".  The screenshot
# actor names live INSIDE that escaped payload, so ipc-body gates substring-
# scan the whole line rather than anchoring.
_FF_IPC_WRITE_RE = re.compile(rb"\[FF/write\]")


def _load_ff_gates() -> list[dict]:
    """Load the ordered FF gate ladder from scripts/ff_gates.yaml.

    Returns a list of {id, marker_regex (compiled bytes), kind, desc} in
    ladder order.  Falls back to a built-in minimal ladder if PyYAML is
    missing or the file is absent so ff-progress always produces output.
    """
    fallback = [
        {"id": "lib-load",          "marker_regex": rb"\[FFTEST\]\s+Cached\s+\S*libxul\.so\s+\((?!0 pages)", "kind": "line"},
        {"id": "x11-ready",         "marker_regex": rb"\[FFTEST\]\s+X11 server ready", "kind": "line"},
        {"id": "compositor-init",   "marker_regex": rb"\[GUI\]\s+Compositor initialized", "kind": "line"},
        {"id": "ff-launch",         "marker_regex": rb"\[FFTEST\]\s+Launching\s+\S*firefox", "kind": "line"},
        {"id": "content-proc",      "marker_regex": rb"\[FF/write\]\s+pid=2\b", "kind": "line"},
        {"id": "screenshot-actors", "marker_regex": rb"ScreenshotParent|getDimensions|sendQuery", "kind": "ipc-body"},
        {"id": "draw-snapshot",     "marker_regex": rb"drawSnapshot", "kind": "ipc-body"},
        {"id": "png-write",         "marker_regex": rb"\[GATE\]\s+png-write\b|\[FF-OUT-PNG:path=|/tmp/out\.png present|Screenshot saved", "kind": "line"},
        {"id": "ff-exit-clean",     "marker_regex": rb"\[GATE\]\s+ff-exit-clean\b", "kind": "line"},
    ]
    raw = None
    if _FF_GATES_PATH.exists():
        try:
            import yaml
            with _FF_GATES_PATH.open() as f:
                doc = yaml.safe_load(f) or {}
            raw = doc.get("gates")
        except Exception:
            raw = None
    src = raw if raw else fallback
    out: list[dict] = []
    for g in src:
        try:
            rx = g["marker_regex"]
            if isinstance(rx, str):
                rx = rx.encode("utf-8", errors="replace")
            out.append({
                "id":    g["id"],
                "regex": re.compile(rx),
                "kind":  g.get("kind", "line"),
                "desc":  g.get("desc", ""),
            })
        except (KeyError, re.error):
            continue
    return out


def cmd_ff_progress(args):
    """One-shot FF gate-ladder + deepest-reached detector.

    Pure read-only serial-log scan; no kernel/kdb interaction.  Reports which
    canonical Firefox-headless-screenshot gates the session reached, the
    deepest one, the live syscall count at each, and the terminal cause —
    automating the recurring "how deep did this boot get + is it the
    screenshot wedge?" question.  The ladder is read from
    scripts/ff_gates.yaml (additive; extend it to add gates)."""
    sess = _load_session(args.sid)
    serial_log = sess.get("serial_log", "")
    if not serial_log or not Path(serial_log).exists():
        _out({"error": f"no serial log for session {args.sid}"})
        sys.exit(1)

    gates = _load_ff_gates()
    # Per-gate first-seen state.
    seen: dict[str, dict] = {}      # id -> {first_line_no, first_sc}
    line_no = 0
    cur_sc = 0
    max_sc = 0

    try:
        with Path(serial_log).open("rb") as fh:
            for raw_line in fh:
                line_no += 1
                # Track the running syscall counter so each gate gets the sc
                # at which it was first reached, and we can report deepest sc.
                m = _FF_SC_RE.search(raw_line)
                if m:
                    try:
                        cur_sc = int(m.group(1))
                        if cur_sc > max_sc:
                            max_sc = cur_sc
                    except ValueError:
                        pass
                is_ipc = bool(_FF_IPC_WRITE_RE.search(raw_line))
                for g in gates:
                    if g["id"] in seen:
                        continue
                    if g["kind"] == "ipc-body" and not is_ipc:
                        # ipc-body gates only match inside an [FF/write] body,
                        # but still allow a bare line match as a fallback (some
                        # markers also appear in plain log lines).
                        if not g["regex"].search(raw_line):
                            continue
                    if g["regex"].search(raw_line):
                        seen[g["id"]] = {
                            "first_line_no": line_no,
                            "first_sc": max_sc,
                        }
    except OSError as e:
        _out({"error": f"cannot read serial log: {e}"})
        sys.exit(1)

    # Build the ordered gate report; deepest = last gate in ladder order that
    # was reached.
    gate_rows = []
    deepest_gate = None
    deepest_index = -1
    for i, g in enumerate(gates):
        s = seen.get(g["id"])
        reached = s is not None
        gate_rows.append({
            "id":            g["id"],
            "reached":       reached,
            "first_sc":      (s["first_sc"] if reached else None),
            "first_line_no": (s["first_line_no"] if reached else None),
            "desc":          g["desc"],
        })
        if reached:
            deepest_gate = g["id"]
            deepest_index = i

    pid = sess.get("pid", 0)
    alive = _pid_alive(pid) if pid else False
    terminal_cause = _classify_exit_cause(serial_log, alive)
    reached_png = "png-write" in seen
    # `[GATE] ff-exit-clean` — the kernel's authoritative clean-exit marker
    # on the pid-1 group exit (fires on the fast firefox-test-core profile).
    reached_exit_clean = "ff-exit-clean" in seen

    _out({
        "sid":            args.sid,
        "running":        alive,
        "deepest_gate":   deepest_gate,
        "deepest_index":  deepest_index,
        "max_sc":         max_sc,
        "reached_png":    reached_png,
        "reached_exit_clean": reached_exit_clean,
        "terminal_cause": terminal_cause,
        "total_lines":    line_no,
        "gates":          gate_rows,
    })


# ── health: active circle / spin / stall detector ─────────────────────────────
#
# `health` classifies a boot's *liveness* from the harness session files alone
# (serial log + ps + the optional kdb proc-list) — NO new guest-side cost.  The
# coordinator runs it every turn so a wedged FF boot burning a core for nothing
# is reaped automatically instead of being spotted by a human.
#
# The classifier takes TWO samples a few seconds apart so it can tell a busy
# loop (sc rockets, no gate advance) from a boot that is genuinely advancing
# (gate / sc climbing) from a stall (sc frozen, a thread still burning cycles).
# A single shot cannot distinguish SPINNING from progressing — rates need a
# delta.  Verdict enum (see HEALTH_CLASSES):
#
#   HEALTHY              deepest [GATE] advanced, or per-proc sc climbing at a
#                        healthy rate, or a fresh kdb/autopsy artefact shows an
#                        agent is actively investigating it.
#   SLOW-ALIVE           progressing but slowly — sc/gate advance, but slowly;
#                        the firefox-test serial firehose throttles forward
#                        progress and explains the high CPU.  NEVER reaped.
#   SPINNING             a busy loop — per-proc sc climbs very fast (> ~5000/s)
#                        with NO gate advance for the window, OR a single
#                        syscall-nr / a single [FUTEX_*]/[POLL_*] tag dominates
#                        the recent tail (> ~70 %) at ~100 % CPU.
#   STALLED              sc FROZEN (delta ~0) AND deepest [GATE] frozen, at
#                        meaningful CPU — e.g. the content-handshake wedge where
#                        pid threads churn FUTEX_WAIT -> FUTEX_TIMEDOUT on the
#                        same uaddr while the gate counter is frozen.
#   WEDGED-PRE-BUGCHECK  STALLED and approaching the no-forward-progress
#                        watchdog (a thread STUCK_IN_NR for close to the
#                        ~60000-tick SCHEDULER_DEADLOCK budget) — about to halt.
#   DEAD/BUGCHECKED      serial contains AETHER KERNEL BUGCHECK / a panic /
#                        SCHEDULER_DEADLOCK, or the qemu pid is gone.
#
# Signals (all free — derived from files the harness already writes):
#   - <sid>.serial.log : [GATE] markers, [HB]/[PROC-METRICS] tick=, per-proc
#                        sc=, STUCK_IN_NR=nr@Tt, and the [FUTEX_*]/[POLL_*]/nr=
#                        tags in the tail.
#   - ps              : qemu %CPU, etimes, liveness.
#   - serial-log size : growth rate (kB/s) between the two samples.
#   - <sid>.kdb.json mtime : is an agent autopsying this boot right now?
#   - kdb proc-list   : used OPPORTUNISTICALLY when the kdb feature is on and the
#                        boot still answers (short timeout, failure tolerated);
#                        the verdict never DEPENDS on kdb — serial + ps suffice.

HEALTH_CLASSES = [
    "HEALTHY",
    "SLOW-ALIVE",
    "SPINNING",
    "STALLED",
    "WEDGED-PRE-BUGCHECK",
    "DEAD/BUGCHECKED",
]

# Classes the --reap-circles flag will stop().  HEALTHY and SLOW-ALIVE are
# NEVER reaped — a firehose-throttled boot that is slowly advancing its [GATE]
# must survive.
HEALTH_REAP_CLASSES = {
    "SPINNING",
    "STALLED",
    "WEDGED-PRE-BUGCHECK",
    "DEAD/BUGCHECKED",
}

# Thresholds (tunable; chosen from the ea3da73280e2 wedge autopsy + healthy
# boots).  Tick rate is ~100 Hz (10 ms/tick), so 1 s ~= 100 ticks.
_HEALTH_SPIN_SC_RATE = 5000.0      # sc/s above this with no gate advance = SPINNING
_HEALTH_SLOW_SC_RATE = 5.0         # sc/s below this (but > ~0) = slow-but-alive floor
_HEALTH_FROZEN_SC_DELTA = 3        # |sc delta| <= this over the window = "frozen"
_HEALTH_DOMINANT_TAG_PCT = 70.0    # one tag >= this % of the tail = dominated
_HEALTH_TAIL_LINES = 400           # how many trailing serial lines to bucket
_HEALTH_WEDGE_TICKS = 50000        # STUCK_IN_NR@T at/above this => pre-bugcheck
_HEALTH_KDB_FRESH_S = 90.0         # kdb.json touched within this = active autopsy
_HEALTH_SAMPLE_GAP_S = 4.0         # default delay between the two rate samples

# A leading "[TAG]" token at the start of a serial line.  We bucket the tail by
# this to find a dominant-tag busy loop (e.g. [FUTEX_TIMEDOUT] churn).
_HEALTH_TAG_RE = re.compile(rb"\[([A-Z][A-Z0-9_]+)\]")
# Global kernel tick (heartbeat / proc-metrics).  Authoritative "kernel time".
_HEALTH_TICK_RE = re.compile(rb"(?:\[HB\]|\[PROC-METRICS\])\s+tick=(\d+)")
# Per-process syscall counter line.
_HEALTH_PROC_SC_RE = re.compile(rb"\[PROC-METRICS\][^\n]*?\bpid=(\d+)[^\n]*?\bsc=(\d+)")
# STUCK_IN_NR=<nr>@<ticks>t — a thread parked in one syscall for <ticks> ticks.
_HEALTH_STUCK_RE = re.compile(rb"STUCK_IN_NR=(\d+)@(\d+)t")
# A bare [GATE] <name> marker (serial milestone).  Deepest = last distinct one.
_HEALTH_GATE_RE = re.compile(rb"\[GATE\]\s+(\S+)")
# nr=<n> appears on raw [SC] trace lines; used to detect single-syscall spin.
_HEALTH_NR_RE = re.compile(rb"\bnr=(\d+)\b")
_HEALTH_BUGCHECK_RE = re.compile(
    rb"AETHER KERNEL BUGCHECK|BUGCHECK\s+0x[0-9a-fA-F]+|SCHEDULER_DEADLOCK|"
    rb"PANIC:|panicked at"
)


def _health_tail_bytes(path: Path, nbytes: int) -> bytes:
    """Return the last `nbytes` of a file (or the whole file if smaller).

    O(1) regardless of log size — the wedge signal is always near the end."""
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - nbytes), 0)
            return fh.read()
    except OSError:
        return b""


def _health_scan_gates(serial_log: str) -> list[str]:
    """Distinct serial [GATE] markers in first-seen order across the WHOLE log.

    [GATE] markers are rare (a handful per boot) and never regress, so scanning
    the whole file just for them is cheap even on a multi-GiB log — we stream in
    1 MiB chunks and only keep the gate names.  The trailing-window scan in
    `_health_scan_serial` can miss an early gate once a long boot scrolls it out
    of the 4 MiB tail; this dedicated pass keeps the *deepest reached* gate
    correct regardless of log size."""
    gate_order: list[str] = []
    seen: set[str] = set()
    try:
        with Path(serial_log).open("rb") as fh:
            carry = b""
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                buf = carry + chunk
                # Keep the last partial line to avoid splitting a [GATE] marker
                # across a chunk boundary.
                nl = buf.rfind(b"\n")
                if nl >= 0:
                    scan, carry = buf[:nl], buf[nl + 1:]
                else:
                    scan, carry = b"", buf
                for m in _HEALTH_GATE_RE.finditer(scan):
                    g = m.group(1).decode("ascii", "replace")
                    if g not in seen:
                        seen.add(g)
                        gate_order.append(g)
            for m in _HEALTH_GATE_RE.finditer(carry):
                g = m.group(1).decode("ascii", "replace")
                if g not in seen:
                    seen.add(g)
                    gate_order.append(g)
    except OSError:
        pass
    return gate_order


def _health_scan_serial(serial_log: str) -> dict:
    """One pass over the END of the serial log -> the per-sample progress
    fingerprint: latest global tick, per-proc sc map (pid -> sc), the deepest
    [GATE] marker + its ordinal, and the max STUCK_IN_NR tick count.

    Reads only the trailing window (4 MiB) for the tick/sc/stuck signals so it
    stays cheap on multi-GiB logs — the most recent PROC-METRICS sweep for every
    live proc (printed every ~500 ticks) always sits in that window.  The
    deepest-[GATE] signal is taken from a dedicated whole-file gate pass
    (`_health_scan_gates`) since an early gate can scroll out of the tail on a
    long boot, and gates never regress."""
    path = Path(serial_log)
    tail = _health_tail_bytes(path, 4 * 1024 * 1024)

    latest_tick = None
    for m in _HEALTH_TICK_RE.finditer(tail):
        latest_tick = int(m.group(1))

    # Per-proc latest sc.  PROC-METRICS sweeps every proc every ~500 ticks, so
    # the last occurrence of each pid in the window is its current sc.
    proc_sc: dict[int, int] = {}
    for m in _HEALTH_PROC_SC_RE.finditer(tail):
        proc_sc[int(m.group(1))] = int(m.group(2))

    # Deepest serial [GATE] from the whole-file gate pass (ordinal = number of
    # distinct gates reached).  Never regresses, so it is a monotone progress
    # axis: an advance between the two samples is unambiguous forward progress.
    gate_order = _health_scan_gates(serial_log)
    deepest_gate = gate_order[-1] if gate_order else None

    # Max STUCK_IN_NR tick count across procs (best-effort no-progress signal).
    max_stuck_ticks = 0
    stuck_nr = None
    for m in _HEALTH_STUCK_RE.finditer(tail):
        t = int(m.group(2))
        if t > max_stuck_ticks:
            max_stuck_ticks = t
            stuck_nr = int(m.group(1))

    return {
        "latest_tick":     latest_tick,
        "proc_sc":         proc_sc,
        "sc_sum":          sum(proc_sc.values()),
        "deepest_gate":    deepest_gate,
        "gate_ordinal":    len(gate_order),
        "max_stuck_ticks": max_stuck_ticks,
        "stuck_nr":        stuck_nr,
    }


def _health_dominant_tail_tag(serial_log: str, n_lines: int) -> tuple[Optional[str], float, int]:
    """Bucket the last `n_lines` serial lines by leading [TAG] (falling back to
    a `nr=<n>` syscall bucket when a line carries no tag) and return
    (dominant_label, pct_of_tagged_lines, tagged_line_count).

    A single dominant tag at ~100 % CPU is the SPINNING fingerprint (e.g.
    [FUTEX_TIMEDOUT] churn, or one syscall nr looping)."""
    # ~200 bytes/line average; grab generously so we have >= n_lines.
    tail = _health_tail_bytes(Path(serial_log), max(n_lines * 300, 256 * 1024))
    lines = tail.split(b"\n")
    if len(lines) > n_lines:
        lines = lines[-n_lines:]
    counts: dict[str, int] = {}
    tagged = 0
    for ln in lines:
        if not ln.strip():
            continue
        mt = _HEALTH_TAG_RE.match(ln.lstrip())
        if mt:
            label = "[" + mt.group(1).decode("ascii", "replace") + "]"
        else:
            mn = _HEALTH_NR_RE.search(ln)
            if mn:
                label = "nr=" + mn.group(1).decode("ascii", "replace")
            else:
                continue
        counts[label] = counts.get(label, 0) + 1
        tagged += 1
    if not counts or tagged == 0:
        return None, 0.0, 0
    top_label, top_count = max(counts.items(), key=lambda kv: kv[1])
    pct = 100.0 * top_count / tagged
    return top_label, round(pct, 1), tagged


def _health_ps(pid: int) -> dict:
    """ps snapshot for a qemu pid: %CPU (instantaneous) + etimes (seconds).
    Returns {} when the pid is gone or ps is unavailable."""
    if not pid:
        return {}
    try:
        out = subprocess.run(
            ["ps", "-o", "pcpu=,etimes=", "-p", str(pid)],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return {}
    if not out:
        return {}
    parts = out.split()
    try:
        return {"cpu_pct": float(parts[0]), "etimes": int(parts[1])}
    except (ValueError, IndexError):
        return {}


def _health_kdb_autopsy_fresh(sid: str) -> bool:
    """True when <sid>.kdb.json was written within _HEALTH_KDB_FRESH_S — i.e.
    an agent is actively autopsying this boot right now (so it is being worked,
    not abandoned in a circle).  Best-effort; missing file -> False."""
    p = HARNESS_DIR / f"{sid}.kdb.json"
    try:
        return (time.time() - p.stat().st_mtime) <= _HEALTH_KDB_FRESH_S
    except OSError:
        return False


def _health_kdb_proclist(sess: dict, timeout: float = 2.0) -> Optional[dict]:
    """OPPORTUNISTIC kdb proc-list, wrapped in a short deadline.  Returns the
    parsed response (with syscall_count_total + per-proc thread states) when the
    boot was started with --features kdb AND still answers; None otherwise.

    The verdict NEVER depends on this — it only enriches the JSON when cheap."""
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        return None
    try:
        return _kdb_call(port, {"op": "proc-list"}, timeout=timeout)
    except Exception:
        return None


def _health_classify(s0: dict, s1: dict, ps: dict, dt: float,
                     dominant_tag: Optional[str], dominant_pct: float,
                     futex_churn: bool, kdb_fresh: bool,
                     bugchecked: bool, alive: bool) -> tuple[str, str]:
    """Pure classification from the two samples + ps + tail signals.

    Returns (verdict, one-line reason).  Order matters — first decisive rule
    wins, mirroring the precedence in the class docstring."""
    # 1. Dead / bugchecked — process gone, or a halt marker in the serial tail.
    if not alive:
        return "DEAD/BUGCHECKED", "qemu process is gone"
    if bugchecked:
        return "DEAD/BUGCHECKED", "serial shows BUGCHECK/panic/SCHEDULER_DEADLOCK"

    cpu = ps.get("cpu_pct", 0.0)
    gate_advanced = (
        s1["gate_ordinal"] > s0["gate_ordinal"]
        or (s1["deepest_gate"] != s0["deepest_gate"]
            and s1["deepest_gate"] is not None)
    )
    sc_delta = s1["sc_sum"] - s0["sc_sum"]
    sc_rate = (sc_delta / dt) if dt > 0 else 0.0
    tick_advanced = (
        s0["latest_tick"] is not None and s1["latest_tick"] is not None
        and s1["latest_tick"] > s0["latest_tick"]
    )
    stuck_ticks = max(s0["max_stuck_ticks"], s1["max_stuck_ticks"])

    # 2. Active autopsy -> being worked, not a circle.  (Still HEALTHY even if
    #    momentarily frozen — an agent paused it at a breakpoint, etc.)
    if kdb_fresh:
        return "HEALTHY", "fresh kdb/autopsy artefact — under active investigation"

    # 3. Gate advanced in the window -> unambiguously making forward progress.
    if gate_advanced:
        return "HEALTHY", (
            f"[GATE] advanced {s0['deepest_gate']!r}->{s1['deepest_gate']!r} "
            f"(sc rate {sc_rate:.0f}/s)"
        )

    # 4. WEDGED-PRE-BUGCHECK — a thread has been stuck in one syscall for close
    #    to the no-forward-progress watchdog budget, with no gate advance.
    if stuck_ticks >= _HEALTH_WEDGE_TICKS:
        return "WEDGED-PRE-BUGCHECK", (
            f"thread STUCK_IN_NR={s1.get('stuck_nr')} for {stuck_ticks} ticks "
            f"(approaching ~60000-tick deadlock watchdog), no [GATE] advance"
        )

    # 5. SPINNING — busy loop.  Either sc rockets with no gate advance, or one
    #    tag/syscall dominates the tail at high CPU.
    if sc_rate >= _HEALTH_SPIN_SC_RATE:
        return "SPINNING", (
            f"sc climbing {sc_rate:.0f}/s with no [GATE] advance — busy loop"
        )
    if (dominant_tag is not None
            and dominant_pct >= _HEALTH_DOMINANT_TAG_PCT
            and cpu >= 50.0):
        return "SPINNING", (
            f"{dominant_tag} dominates {dominant_pct:.0f}% of the tail at "
            f"{cpu:.0f}% CPU — single-tag busy loop"
        )

    # 6. Frozen sc + frozen gate at meaningful CPU -> STALLED.  The FUTEX churn
    #    case (content-handshake wedge) reads here when sc isn't climbing fast.
    frozen = abs(sc_delta) <= _HEALTH_FROZEN_SC_DELTA
    if frozen and cpu >= 20.0:
        why = "sc frozen + [GATE] frozen at meaningful CPU"
        if futex_churn:
            why += " (FUTEX_WAIT->FUTEX_TIMEDOUT churn on the same uaddr)"
        return "STALLED", why

    # 7. Genuinely slow but advancing -> SLOW-ALIVE.  Either sc is creeping up,
    #    or the tick is advancing while the firehose throttles forward progress.
    #    This MUST win over a STALLED misread for a firehose boot.
    if sc_rate > _HEALTH_SLOW_SC_RATE or (sc_delta > _HEALTH_FROZEN_SC_DELTA):
        return "SLOW-ALIVE", (
            f"sc creeping {sc_rate:.0f}/s (firehose-throttled), no gate advance"
        )
    if tick_advanced and not frozen:
        return "SLOW-ALIVE", "kernel tick advancing, sc creeping — slow but alive"

    # 8. Fallback.  A frozen log is only STALLED when a thread is actually
    #    burning cycles — STALLED is defined as "no progress AT MEANINGFUL CPU".
    #    A frozen log at low/idle CPU is quiesced (blocked in the scheduler,
    #    nothing to do), NOT a circle, so it must read SLOW-ALIVE and never be
    #    reaped.  (Rule 6 already caught the frozen + >=20% CPU case; this only
    #    reaches frozen sessions below that CPU floor or with CPU unknown.)
    if frozen:
        if cpu >= 20.0:
            return "STALLED", "sc + [GATE] frozen across samples at meaningful CPU"
        return "SLOW-ALIVE", "sc flat at low/idle CPU — quiesced, not a circle"
    if tick_advanced:
        return "SLOW-ALIVE", "tick advancing — slow but alive"
    return "SLOW-ALIVE", "no decisive spin/stall signal — assume alive"


def _health_one(sid: str, sample_gap_s: float, do_sample2: bool = True) -> dict:
    """Compute the full health record for one session.

    Reads the serial log directly so it also works on a STOPPED session whose
    <sid>.json was already pruned (post-mortem) — the single-sid `health <sid>`
    path is intentionally lenient so an agent can classify a historical wedge."""
    sess: dict = {}
    p = _session_path(sid)
    if p.exists():
        try:
            sess = _load_session(sid)
        except SystemExit:
            sess = {}
    serial_log = sess.get("serial_log") or str(HARNESS_DIR / f"{sid}.serial.log")
    pid = int(sess.get("pid") or 0)
    alive = _pid_alive(pid) if pid else False

    if not Path(serial_log).exists():
        return {
            "sid": sid, "qemu_pid": pid or None, "alive": alive,
            "verdict": "DEAD/BUGCHECKED",
            "reason": "no serial log on disk (session gone)",
            "etimes": None, "cpu_pct": None,
            "deepest_gate": None, "gate_advancing": False,
            "sc_now": None, "sc_rate_per_s": None, "serial_growth_kbps": None,
            "dominant_tail_tag": None, "dominant_tag_pct": None,
            "futex_timeout_churn": False, "kdb_autopsy_fresh": False,
            "bugchecked": False, "ticks_since_progress": None,
        }

    # Sample 0.
    t0 = time.monotonic()
    size0 = Path(serial_log).stat().st_size if Path(serial_log).exists() else 0
    s0 = _health_scan_serial(serial_log)

    # Bugcheck/panic in the tail short-circuits the gap wait — no point sampling
    # a halted kernel for a rate.
    tail_for_bc = _health_tail_bytes(Path(serial_log), 256 * 1024)
    bugchecked = bool(_HEALTH_BUGCHECK_RE.search(tail_for_bc))

    if do_sample2 and alive and not bugchecked:
        # Sleep the rate window, then resample.
        remaining = sample_gap_s
        # Don't block forever if the file vanished.
        time.sleep(max(0.0, remaining))
    dt = time.monotonic() - t0

    size1 = Path(serial_log).stat().st_size if Path(serial_log).exists() else size0
    s1 = _health_scan_serial(serial_log) if (do_sample2 and alive and not bugchecked) else s0
    if not (do_sample2 and alive and not bugchecked):
        dt = max(dt, 1e-6)

    # ps + opportunistic kdb.
    ps = _health_ps(pid) if alive else {}
    kdb_fresh = _health_kdb_autopsy_fresh(sid)
    kdb_proclist = _health_kdb_proclist(sess) if (alive and sess) else None

    # Tail-tag dominance + futex churn.
    dominant_tag, dominant_pct, tagged_n = _health_dominant_tail_tag(
        serial_log, _HEALTH_TAIL_LINES)
    futex_churn = (
        dominant_tag == "[FUTEX_TIMEDOUT]"
        and dominant_pct >= 40.0
    )

    # Rates.
    sc_delta = s1["sc_sum"] - s0["sc_sum"]
    sc_rate = (sc_delta / dt) if dt > 0 else 0.0
    growth_kbps = ((size1 - size0) / 1024.0 / dt) if dt > 0 else 0.0

    gate_advanced = (
        s1["gate_ordinal"] > s0["gate_ordinal"]
        or (s1["deepest_gate"] != s0["deepest_gate"]
            and s1["deepest_gate"] is not None)
    )
    ticks_since_progress = max(s0["max_stuck_ticks"], s1["max_stuck_ticks"]) or None

    verdict, reason = _health_classify(
        s0, s1, ps, dt, dominant_tag, dominant_pct, futex_churn,
        kdb_fresh, bugchecked, alive,
    )

    rec = {
        "sid":                 sid,
        "qemu_pid":            pid or None,
        "alive":               alive,
        "etimes":              ps.get("etimes"),
        "cpu_pct":             ps.get("cpu_pct"),
        "deepest_gate":        s1["deepest_gate"],
        "gate_advancing":      gate_advanced,
        "sc_now":              s1["sc_sum"],
        "sc_rate_per_s":       round(sc_rate, 1),
        "serial_growth_kbps":  round(growth_kbps, 2),
        "dominant_tail_tag":   dominant_tag,
        "dominant_tag_pct":    dominant_pct,
        "futex_timeout_churn": futex_churn,
        "kdb_autopsy_fresh":   kdb_fresh,
        "bugchecked":          bugchecked,
        "ticks_since_progress": ticks_since_progress,
        "verdict":             verdict,
        "reason":              reason,
        # Additive context — handy for an agent without changing the contract.
        "sample_gap_s":        round(dt, 2),
        "per_proc_sc":         s1["proc_sc"],
        "latest_tick":         s1["latest_tick"],
        "stuck_nr":            s1["stuck_nr"],
        "tagged_tail_lines":   tagged_n,
        "features":            sess.get("features"),
        # Cross-reference the in-process watcher's own early-warning flag (the
        # LivelockDetector stamped into the session JSON by `start`).  Additive,
        # and only present on sessions started after that landed — health does
        # NOT depend on it, but surfacing it lets an agent see both the
        # out-of-band classifier verdict and the in-process watcher's view at a
        # glance.
        "watcher_livelock_suspected": bool(sess.get("livelock_suspected", False)),
        "watcher_terminal_cause":     sess.get("terminal_cause"),
    }
    if kdb_proclist is not None:
        rec["kdb_proc_list"] = kdb_proclist
    return rec


def cmd_health(args):
    """Active circle/spin/stall detector — see HEALTH_CLASSES.

    `health <sid>`                  one session -> JSON record.
    `health --all`                  every live session -> JSON array.
    `health --all --reap-circles`   additionally stop() SPINNING / STALLED /
                                    WEDGED-PRE-BUGCHECK / DEAD sessions and
                                    report reaped:[...] with a per-sid reason.
                                    HEALTHY and SLOW-ALIVE are NEVER reaped.

    Takes two samples `--gap` seconds apart (default 4) for the rate signals."""
    gap = float(getattr(args, "gap", _HEALTH_SAMPLE_GAP_S) or _HEALTH_SAMPLE_GAP_S)

    if not args.all:
        if not args.sid:
            _out({"error": "health <sid> requires a session id, or use --all"})
            sys.exit(1)
        _out(_health_one(args.sid, gap))
        return

    # --all: classify every live session.  Only a canonical <sid>.json counts —
    # NOT the auxiliary `<sid>.kdb.json` / `<sid>.fdmap.*.json` /
    # `<sid>.thread-park.*.json` caches, which share the `*.json` glob but carry
    # no top-level "sid" key.  Filtering on a dict-with-"sid" matches cmd_list's
    # implicit contract and avoids classifying a phantom "<sid>.kdb" session.
    sids = []
    for p in sorted(HARNESS_DIR.glob("*.json")):
        try:
            with p.open() as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(doc, dict) and doc.get("sid") == p.stem:
            sids.append(p.stem)
    records = []
    reaped = []
    for sid in sids:
        try:
            rec = _health_one(sid, gap)
        except Exception as e:  # never let one bad session sink the sweep
            rec = {"sid": sid, "verdict": "DEAD/BUGCHECKED",
                   "reason": f"health probe error: {e}",
                   "alive": False}
        records.append(rec)

    if args.reap_circles:
        for rec in records:
            verdict = rec.get("verdict")
            if verdict in HEALTH_REAP_CLASSES:
                sid = rec["sid"]
                reason = rec.get("reason", "")
                # NEVER a silent kill — log the reap to the per-session event
                # stream AND echo it in the output with the deciding reason.
                try:
                    _emit_event(sid, {
                        "kind": "health_reap",
                        "verdict": verdict,
                        "reason": reason,
                        "cpu_pct": rec.get("cpu_pct"),
                        "sc_rate_per_s": rec.get("sc_rate_per_s"),
                        "ticks_since_progress": rec.get("ticks_since_progress"),
                    })
                except Exception:
                    pass
                # stop() is idempotent and prints its own JSON; suppress that so
                # our single health envelope stays the one structured result.
                _reap_stop_quiet(sid)
                reaped.append({"sid": sid, "verdict": verdict, "reason": reason})
                rec["reaped"] = True

    _out({
        "sessions": records,
        "reaped":   reaped,
        "reap_enabled": bool(args.reap_circles),
        "classes":  HEALTH_CLASSES,
    })


def _reap_stop_quiet(sid: str):
    """stop() a session without letting its `_out` JSON leak into health's
    single structured envelope.  Reuses cmd_stop so the teardown (SIGTERM ->
    SIGKILL, socket/ESP cleanup) is identical to a manual stop."""
    import io  # noqa: PLC0415 — local to keep the helper self-contained
    class _A:  # minimal args shim for cmd_stop
        pass
    a = _A()
    a.sid = sid
    buf = io.StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        cmd_stop(a)
    except SystemExit:
        pass
    finally:
        sys.stdout = old


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

    # Livelock auto-reap: a stored `terminal_cause` (set by the watcher when it
    # reaped this session) is authoritative over the live-classified exit_cause.
    stored_terminal = sess.get("terminal_cause")
    terminal_cause = stored_terminal or (None if alive else exit_cause)

    # Host-side capture.  Report path + whether QEMU has started writing frames
    # (file present + byte size), plus the decision metadata.  pcap_path is ""
    # when capture was disabled for this session (and absent entirely on
    # sessions that predate the feature).  `pcap_reason` records which rule
    # enabled/disabled it; older sessions fall back to deriving it from path.
    pcap_path = sess.get("pcap_path") or ""
    pcap_enabled = bool(sess.get("pcap_enabled", bool(pcap_path)))
    # None on sessions that predate the field (decision rule unknown).
    pcap_reason = sess.get("pcap_reason")
    pcap_size = 0
    if pcap_path:
        try:
            pcap_size = Path(pcap_path).stat().st_size
        except OSError:
            pass

    _out({
        "running":         alive,
        "sid":             sid,
        "pid":             pid,
        "serial_log_size": serial_size,
        "uptime_s":        round(uptime, 1),
        "features":        sess.get("features"),
        "exit_cause":      exit_cause,
        # Authoritative terminal cause: `livelock-autoreap` when the watcher
        # reaped a spinning boot, else the classified exit cause once dead,
        # else None while still running.  Additive — never renames exit_cause.
        "terminal_cause":  terminal_cause,
        # Live early-warning flag: True when the boot is churning pid=1
        # syscalls past the reap threshold with the deepest gate frozen, but
        # the wall-clock window has not yet elapsed (a reap is "coming").
        "livelock_suspected": bool(sess.get("livelock_suspected", False)),
        "livelock_info":      sess.get("livelock_info"),
        "livelock_reap_result": sess.get("livelock_reap_result"),
        # D10: Firefox variant pin.  Additive — never present on sessions
        # started before this field landed.  `kernel_chosen`/`match` are
        # filled in by the post-boot verifier once the [FFTEST] probe line
        # is parsed; until then they remain None.
        "firefox_variant_info": sess.get("firefox_variant_info"),
        # Host-side capture.  `pcap_path` is "" when capture was disabled;
        # `pcap_size` > 0 confirms QEMU's filter-dump is writing frames.
        # `pcap_enabled` mirrors bool(path); `pcap_reason` is the rule that
        # decided ("ff-default" | "pcap-forced" | "no-pcap-optout" |
        # "non-ff-default"), or None on pre-feature sessions.  Additive.
        "pcap_path":       pcap_path,
        "pcap_size":       pcap_size,
        "pcap_enabled":    pcap_enabled,
        "pcap_reason":     pcap_reason,
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


def _hmp_error(result: dict) -> Optional[str]:
    """Extract a failure string from a `human-monitor-command` reply.

    QMP `human-monitor-command` succeeds at the QMP layer even when the HMP
    command itself fails — the HMP error text is delivered in the `return`
    STRING, not in a top-level `error` key.  `savevm`/`loadvm` failures (no
    snapshottable device, snapshot not found, image read-only) therefore look
    like success to a naive `"error" in result` check, which is how phantom
    snapshots were silently reported `ok:true`.

    Returns the error text if the command failed, else None.  Checks both the
    QMP-transport `error` key AND the HMP `return` text for the leading
    `Error:` / `Error ` marker QEMU's monitor prints on failure.
    """
    if not isinstance(result, dict):
        return f"unexpected QMP reply type: {type(result).__name__}"
    if "error" in result:
        return f"qmp: {result['error']}"
    ret = result.get("return", "")
    if isinstance(ret, str):
        text = ret.strip()
        # HMP prints "Error: <msg>" (and historically "Error <msg>") to the
        # monitor on savevm/loadvm failure.  An empty return is success.
        low = text.lower()
        if low.startswith("error:") or low.startswith("error ") or \
           "device has no snapshot" in low or "no block device can store" in low or \
           "is not found" in low:
            return text
    return None


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
    err = _hmp_error(result)
    if err is not None:
        # Surface the HMP error AND a remediation hint — full VM-state
        # savevm needs a writable qcow2 device to hold the RAM blob; the
        # default firefox-test boot disk (vvfat/raw) cannot store one.
        _out({
            "ok": False,
            "hmp_error": err,
            "name": name,
            "op": op,
            "remediation": (
                "savevm/loadvm requires a writable qcow2 device to hold the "
                "VM state. The default firefox-test data/boot disks are "
                "raw/vvfat and cannot store a snapshot. Attach a qcow2 "
                "scratch device at start (see snap-gate spec) before saving."
            ),
        })
    else:
        _out({"ok": True, "name": name, "op": op,
              "hmp_return": result.get("return", "") if isinstance(result, dict) else ""})


# ── snap-gate: live VM snapshot/restore over the savevm/loadvm topology ───────

def _snap_manifest_load() -> dict:
    """Load the snapshot manifest ({name: {meta...}}). Empty dict if absent."""
    if not SNAP_MANIFEST.exists():
        return {}
    try:
        with SNAP_MANIFEST.open() as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _snap_manifest_save(manifest: dict):
    tmp = SNAP_MANIFEST.with_suffix(".json.tmp")
    with tmp.open("w") as f:
        json.dump(manifest, f, indent=2)
    tmp.replace(SNAP_MANIFEST)


def _hmp(qmp_sock: str, hmp_cmd: str, connect_timeout: float = 5.0) -> dict:
    """Run one HMP command via QMP human-monitor-command. Returns the reply."""
    return _qmp_command(qmp_sock, "human-monitor-command",
                        {"command-line": hmp_cmd}, connect_timeout=connect_timeout)


def _ff_gate_label(sid: str) -> dict:
    """Best-effort gate/sc summary for the manifest. Tolerant of any failure."""
    info = {"gate": None, "max_sc": None}
    try:
        sess = _load_session(sid)
        serial = sess.get("serial_log", "")
        if serial and Path(serial).exists():
            txt = Path(serial).read_text(errors="replace")
            # Highest "sc=<N>" seen — cheap progress proxy used elsewhere.
            scs = [int(m) for m in re.findall(r"\bsc=(\d+)", txt)]
            if scs:
                info["max_sc"] = max(scs)
            # Cheap gate hints (matches ff-progress vocabulary, additive).
            for label, pat in (
                ("png-write",      r"\[GATE\]\s+png-write\b|\[FF-OUT-PNG:path=|/tmp/out\.png present|Screenshot saved"),
                ("draw-snapshot",  r"drawSnapshot|DrawSnapshot"),
                ("content-proc",   r"content process|contentproc|HeadlessShell"),
                ("compositor",     r"Compositor"),
                ("lib-load",       r"libxul"),
            ):
                if re.search(pat, txt):
                    info["gate"] = label
                    break
    except Exception:
        pass
    return info


def cmd_snap_gate(args):
    """snap-gate: save/load/list live VM snapshots of a --snapshottable session.

    save: QMP `stop` -> HMP `savevm <name>` -> `cont`, then record a manifest
          entry (name -> {sid, gate, max_sc, features, ts, qcow2 paths, esp}).
          A copy of the session ESP is frozen under SNAP_DIR so a later `load`
          can relaunch QEMU with the matching kernel even after the originating
          session is stopped and its session-ESP is reaped.
    load: spawn a fresh QEMU with the SAME snapshottable topology pointing at
          the saved vmstate/overlay qcow2 files, issue HMP `loadvm <name>`, and
          write a NEW session JSON so subsequent grep/wait/kdb/ff-progress run
          against the restored VM. Prints the new sid.
    list: print the manifest.

    argv forms (resolved from the free-form positionals):
      snap-gate <sid> save <name>
      snap-gate load <name>
      snap-gate list
    """
    rest = list(getattr(args, "rest", []) or [])
    # Resolve op + sid + name from the positionals.
    sid = None
    name = None
    if rest and rest[0] == "list":
        op = "list"
    elif rest and rest[0] == "load":
        op = "load"
        name = rest[1] if len(rest) > 1 else None
    elif len(rest) >= 2 and rest[1] == "save":
        op = "save"
        sid = rest[0]
        name = rest[2] if len(rest) > 2 else None
    else:
        _err("usage: snap-gate <sid> save <name> | snap-gate load <name> | "
             "snap-gate list")
        return

    if op == "list":
        manifest = _snap_manifest_load()
        _out({"ok": True, "snapshots": manifest})
        return

    if not name:
        _err("snap-gate save/load requires a <name>")

    # ── save ──────────────────────────────────────────────────────────────
    if op == "save":
        sess = _load_session(sid)
        if not sess.get("snapshottable"):
            _out({
                "ok": False,
                "error": "session is not snapshottable",
                "remediation": (
                    "Start the session with `--snapshottable` so savevm has a "
                    "qcow2 vmstate device and read-only vvfat/pflash. The "
                    "default firefox-test topology cannot store a live "
                    "snapshot (writable vvfat boot disk blocks savevm)."
                ),
            })
            return

        qmp_sock = sess["qmp_sock"]
        # stop -> savevm -> cont. `stop` quiesces the vCPUs so the RAM blob is
        # consistent; savevm writes the named snapshot into the vmstate orphan
        # qcow2 + the data overlay; cont resumes.
        _hmp(qmp_sock, "stop")
        save_res = _hmp(qmp_sock, f"savevm {name}")
        _hmp(qmp_sock, "cont")
        err = _hmp_error(save_res)
        if err is not None:
            _out({"ok": False, "op": "save", "name": name, "hmp_error": err})
            return

        # Freeze a copy of the session ESP so `load` can relaunch with the same
        # kernel even after the originating session is stopped.
        snap_esp = SNAP_DIR / f"snap-{name}.esp"
        src_esp = sess.get("session_esp_dir", "")
        if src_esp and Path(src_esp).exists():
            if snap_esp.exists():
                shutil.rmtree(snap_esp, ignore_errors=True)
            shutil.copytree(src_esp, snap_esp)

        # Freeze the OVMF_VARS qcow2 too.  Under --snapshottable it is a
        # writable snapshottable pflash, so `savevm` wrote the named snapshot
        # INTO it; `loadvm` requires that snapshot present.  A fresh `load`
        # session uses a new ovmf_vars path, so we must hand it this exact
        # post-save varstore (the raw template lacks the snapshot).
        snap_vars = str(SNAP_DIR / f"snap-{name}.OVMF_VARS.qcow2")
        src_vars = sess.get("ovmf_vars", "")
        if src_vars and Path(src_vars).exists():
            shutil.copy2(src_vars, snap_vars)
        else:
            snap_vars = None

        gate = _ff_gate_label(sid)
        manifest = _snap_manifest_load()
        manifest[name] = {
            "name":            name,
            "origin_sid":      sid,
            "features":        sess.get("features", ""),
            "gate":            gate.get("gate"),
            "max_sc":          gate.get("max_sc"),
            "saved_at":        time.time(),
            "saved_at_iso":    datetime.datetime.now().isoformat(timespec="seconds"),
            "vmstate_qcow2":   sess.get("snap_vmstate_qcow2"),
            "data_overlay":    sess.get("snap_data_overlay"),
            "data_img":        sess.get("snap_data_img"),
            "snap_esp_dir":    str(snap_esp) if snap_esp.exists() else None,
            "snap_ovmf_vars":  snap_vars,
            "snap_launch":     sess.get("snap_launch") or {},
        }
        _snap_manifest_save(manifest)
        _out({
            "ok": True, "op": "save", "name": name,
            "gate": gate.get("gate"), "max_sc": gate.get("max_sc"),
            "vmstate_qcow2": sess.get("snap_vmstate_qcow2"),
            "data_overlay": sess.get("snap_data_overlay"),
        })
        return

    # ── load ──────────────────────────────────────────────────────────────
    if op == "load":
        manifest = _snap_manifest_load()
        entry = manifest.get(name)
        if entry is None:
            _out({"ok": False, "op": "load", "name": name,
                  "error": f"no snapshot named {name!r}",
                  "available": sorted(manifest.keys())})
            return

        vmstate = entry.get("vmstate_qcow2")
        overlay = entry.get("data_overlay")
        snap_esp = entry.get("snap_esp_dir")
        snap_vars = entry.get("snap_ovmf_vars")
        for label, p in (("vmstate", vmstate), ("data_overlay", overlay),
                         ("snap_esp_dir", snap_esp), ("snap_ovmf_vars", snap_vars)):
            if not p or not Path(p).exists():
                _out({"ok": False, "op": "load", "name": name,
                      "error": f"snapshot {label} missing on disk: {p}"})
                return

        launch = entry.get("snap_launch") or {}
        # New session: fresh sid, fresh serial/qmp, but the SAME vmstate +
        # data overlay so `loadvm` finds the named snapshot in both devices.
        # NOTE: this reuses the saved overlay/vmstate qcow2 files in place, so
        # the ORIGIN session must be `stop`ped before loading (a still-running
        # origin would race on the same qcow2 files). The named snapshot is
        # preserved by loadvm, so the same snapshot can be loaded repeatedly.
        new_sid = uuid.uuid4().hex[:12]
        serial_log = str(HARNESS_DIR / f"{new_sid}.serial.log")
        qmp_sock = str(HARNESS_DIR / f"{new_sid}.qmp.sock")
        ovmf_vars = str(HARNESS_DIR / f"{new_sid}.OVMF_VARS.fd")
        # Hand the new session the saved post-save varstore qcow2 (it carries
        # the named snapshot that loadvm requires in the pflash device).
        shutil.copy2(snap_vars, ovmf_vars)
        # Give the restored session its OWN copy of the frozen ESP so that
        # `stop`ping it (cmd_stop reaps session_esp_dir) does not delete the
        # snapshot's master ESP — the snapshot stays loadable repeatedly.
        sess_esp = _session_esp_dir(new_sid)
        if sess_esp.exists():
            shutil.rmtree(sess_esp, ignore_errors=True)
        shutil.copytree(snap_esp, sess_esp)

        feats = [f.strip() for f in (launch.get("features") or "").split(",")]
        kdb_host_port = launch.get("kdb_host_port") or 0
        if "kdb" in feats and not kdb_host_port:
            kdb_host_port = 9990 + (int(new_sid, 16) % 1000)

        proc = _launch_qemu_harness(
            new_sid, serial_log, qmp_sock, ovmf_vars,
            gdb_port=launch.get("gdb_port") or 0,
            kdb_host_port=kdb_host_port,
            kvm=launch.get("kvm_arg"),
            smp=launch.get("smp") or 2,
            cpu_model=launch.get("cpu_model"),
            esp_dir_override=str(sess_esp),
            snapshottable=True,
            data_overlay=overlay,
            vmstate_qcow2=vmstate,
        )

        # Wait for QMP to actually ACCEPT a connection (the socket file can
        # appear before QEMU is listening, and under host load QEMU can take
        # tens of seconds to reach the monitor). Probe with a real `query-status`
        # until it answers, up to a generous deadline. Then loadvm: QEMU starts
        # the (orphan) VM running from firmware; `loadvm` discards that and
        # restores the saved RAM/CPU/disk state. `stop` first for determinism,
        # `cont` to resume the restored VM.
        load_err = None
        load_ret = ""
        ok = False
        qmp_ready = False
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            if Path(qmp_sock).exists():
                probe = _qmp_command(qmp_sock, "query-status", connect_timeout=2.0)
                if isinstance(probe, dict) and "return" in probe:
                    qmp_ready = True
                    break
            time.sleep(0.3)
        if not qmp_ready:
            load_err = "qmp: monitor never became ready within 90s"
        else:
            _hmp(qmp_sock, "stop", connect_timeout=15.0)
            load_res = _hmp(qmp_sock, f"loadvm {name}", connect_timeout=15.0)
            _hmp(qmp_sock, "cont", connect_timeout=15.0)
            load_err = _hmp_error(load_res)
            ok = load_err is None
            load_ret = load_res.get("return", "") if isinstance(load_res, dict) else ""

        # Write the restored session JSON so grep/wait/kdb/ff-progress work.
        session = {
            "sid":            new_sid,
            "pid":            proc.pid,
            "serial_log":     serial_log,
            "qmp_sock":       qmp_sock,
            "qga_sock":       "",
            "ovmf_vars":      ovmf_vars,
            "started_at":     time.time(),
            "features":       launch.get("features") or "",
            "gdb_port":       launch.get("gdb_port") or 0,
            "gdb_wait":       False,
            "kdb_host_port":  kdb_host_port,
            "http_host_port": 0,
            "ssh_host_port":  0,
            "oracle_stub_port": 0, "oracle_stub_pid": 0, "oracle_stub_log": "",
            "smp":            launch.get("smp") or 2,
            "cpu_model":      launch.get("cpu_model") or "default",
            "breakpoints":    [],
            "snapshottable":  True,
            "snap_vmstate_qcow2": vmstate,
            "snap_data_overlay":  overlay,
            "snap_data_img":      entry.get("data_img"),
            "snap_launch":        launch,
            # Provenance: this session was hydrated from a snapshot.
            "restored_from_snapshot": name,
            "session_esp_dir":       str(sess_esp),
        }
        _save_session(session)

        # Background watcher so panics/idles still get recorded post-restore.
        try:
            subprocess.Popen(
                [sys.executable, __file__, "_watch", new_sid],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
        except Exception:
            pass

        _out({
            "ok": ok, "op": "load", "name": name, "sid": new_sid,
            "pid": proc.pid, "serial_log": serial_log, "qmp_sock": qmp_sock,
            "restored_gate": entry.get("gate"), "restored_max_sc": entry.get("max_sc"),
            "hmp_error": load_err, "hmp_return": load_ret,
            "hint": (f"use `grep {new_sid} ...`, `wait {new_sid} ...`, "
                     f"`ff-progress {new_sid}`, `kdb {new_sid} ...` against the "
                     f"restored VM" if ok else None),
        })
        return

    _err(f"Unknown snap-gate op: {op}")


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


def cmd_ff_variant_verify(args):
    """
    Private subcommand: tail the serial log for the kernel's "[FFTEST] FF
    binary probe:" line, parse the selected variant, and (a) emit a
    `firefox_variant_probe` event, (b) update `firefox_variant_info` in the
    session JSON.  Detached process spawned by `start`.  Best-effort: any
    error path exits 0 silently — the agent can fall back to `grep <sid>
    '\\[FFTEST\\] FF binary probe'`.

    Deadline is 120 s wall-clock — kernel emits the probe within the first
    few seconds of test_runner.  We loop until either the probe line is
    parsed or the deadline is reached.
    """
    sid = args.sid
    try:
        sess = _load_session(sid)
    except SystemExit:
        sys.exit(0)
    serial_log = sess.get("serial_log")
    if not serial_log:
        sys.exit(0)
    parsed = _scan_serial_for_ff_probe(serial_log, deadline_s=120.0)
    # Refresh session under the assumption it may have been updated by other
    # callers (e.g. snapshot save); merge our verdict in.
    try:
        sess = _load_session(sid)
    except SystemExit:
        sys.exit(0)
    fvi = dict(sess.get("firefox_variant_info") or {})
    if parsed is None:
        fvi["kernel_chosen"] = None
        fvi["match"] = None
        fvi["probe_timeout"] = True
        sess["firefox_variant_info"] = fvi
        _save_session(sess)
        _emit_event(sid, {
            "kind": "firefox_variant_probe",
            "ok": False,
            "reason": "timeout-waiting-for-[FFTEST]-probe-line",
            "requested": fvi.get("requested"),
        })
        sys.exit(0)
    chosen = parsed.get("chosen")
    family = parsed.get("family")
    requested = fvi.get("requested")
    match = (family == requested) if (family and requested) else None
    fvi["kernel_chosen"] = chosen
    fvi["kernel_chosen_family"] = family
    fvi["match"] = match
    fvi["probe_timeout"] = False
    sess["firefox_variant_info"] = fvi
    _save_session(sess)
    _emit_event(sid, {
        "kind": "firefox_variant_probe",
        "ok": True,
        "requested": requested,
        "kernel_chosen": chosen,
        "kernel_chosen_family": family,
        "match": match,
        "musl_132_present": parsed.get("musl_132_present"),
        "musl_esr_present": parsed.get("musl_esr_present"),
        "glibc_present":    parsed.get("glibc_present"),
    })
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


def cmd_dual_regs(args):
    """Enumerate every QEMU vCPU thread, read RIP/CS/RSP/RBP for each, and
    symbolize the kernel-space RIP.

    Purpose: SMP spin-lock deadlock autopsy.  When the whole machine freezes
    on a held-across-dispatch spin::Mutex, one core strands the lock while the
    other busy-spins in a non-preemptible Ring-0 loop.  This command names the
    RIP each vCPU is parked at so the busy-spinner core (the one looping in a
    lock-acquire path) and the holder core can be identified in one shot.

    Output per-cpu: thread id, RIP (hex), symbolized RIP, CS (ring via low 2
    bits), RSP, RBP.  No guest mutation — pure read via the GDB stub.
    """
    sess = _load_session(args.sid)
    port = _get_gdb_port(sess)

    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        _err(f"Cannot connect to GDB stub on port {port} (tried {port}..{port+4})")
    cpus = []
    try:
        tids = gdb.list_threads()
        if not tids:
            tids = [1]  # single-vCPU stub that doesn't advertise threads
        for tid in tids:
            gdb.select_thread(tid)
            regs = gdb.read_regs()
            rip = int(regs.get("rip", "0x0"), 16)
            cs = int(regs.get("cs", "0x0"), 16)
            sym = _autopsy_resolve_kernel_rip(rip)
            cpus.append({
                "tid":  tid,
                "rip":  hex(rip),
                "sym":  sym,
                "cs":   hex(cs),
                "ring": cs & 0x3,
                "rsp":  regs.get("rsp"),
                "rbp":  regs.get("rbp"),
                "rax":  regs.get("rax"),
                "rdi":  regs.get("rdi"),
                "rsi":  regs.get("rsi"),
            })
    except Exception as e:
        _err(f"GDB dual-regs error: {e}")
    finally:
        gdb.close()

    _out({"ok": True, "n_cpus": len(cpus), "cpus": cpus})


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


def cmd_watch(args):
    """
    Arm a HARDWARE write watchpoint on a guest VA, resume, and capture the
    EXACT store that writes to it — naming the writer RIP + register context
    and classifying it kernel-mode vs user-mode.

    This is the "name the out-of-band writer" tool: the legitimate kernel
    argv-build store happens before the watch is armed (we arm at a chosen
    break-point, after the stack is built), so the FIRST fire after arming is
    the offending later store.  Use --skip N to let the first N fires pass
    (e.g. if a legitimate write to the slot precedes the corrupting one).

    Contract: session started with --gdb-port.  One-shot JSON on stdout.
    """
    sess = _load_session(args.sid)
    port = _get_gdb_port(sess)

    try:
        addr = int(args.addr, 0)
    except ValueError:
        _err(f"Invalid watch address: {args.addr}")

    length = args.length
    kind   = args.kind
    skip   = max(0, args.skip)
    timeout_s = args.timeout_ms / 1000.0

    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        _err(f"Cannot connect to GDB stub on port {port} (tried {port}..{port+4})")

    fires = []
    armed = False
    try:
        # If the caller wants us to break at a symbol/addr first (so the watch
        # is armed only after the stack region is mapped), honour --break.
        if getattr(args, "brk", None):
            try:
                brk_addr = int(args.brk, 0)
            except ValueError:
                # Try resolving as a kernel symbol.
                r = _resolve_symbol(_get_kernel_elf(), args.brk)
                brk_addr = int(r["address"], 0) if r and r.get("address") else None
            if brk_addr is not None:
                gdb.set_bp(brk_addr)
                gdb.cont_no_wait()
                gdb.wait_for_stop(timeout_s)
                gdb.del_bp(brk_addr)

        armed = gdb.set_watch(addr, length, kind)
        if not armed:
            _out({"ok": False, "error": f"stub rejected watchpoint Z@{hex(addr)} "
                                        f"(len={length},kind={kind}) — DRs exhausted?"})
            return

        hit_count = 0
        # We allow (skip + 1) fires total; the (skip+1)-th is the one we report.
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            gdb.cont_no_wait()
            stop = gdb.wait_for_stop(max(1.0, deadline - time.monotonic()))
            if stop is None:
                break  # timed out with no fire
            hit_count += 1
            try:
                regs = gdb.read_regs()
            except Exception:
                regs = {}
            rip = int(regs.get("rip", "0x0"), 0)
            # x86-64 canonical kernel half-space: high bit set (0xffff8.. and up).
            is_kernel = rip >= 0xFFFF_8000_0000_0000
            # Read the watched slot's current value + the instruction bytes at RIP.
            try:
                slot_val = gdb.read_mem(addr, length).hex()
            except Exception:
                slot_val = None
            try:
                code = gdb.read_mem(rip, 16).hex()
            except Exception:
                code = None
            fire = {
                "fire_index": hit_count,
                "rip":        hex(rip),
                "mode":       "kernel" if is_kernel else "user",
                "slot_now":   slot_val,
                "code_at_rip": code,
                "regs":       regs,
            }
            fires.append(fire)
            if hit_count > skip:
                break  # this is the fire we care about

        # Disarm before returning so we don't leave a DR busy for the next run.
        try:
            gdb.del_watch(addr, length, kind)
        except Exception:
            pass
    except Exception as e:
        _err(f"GDB watch error: {e}")
    finally:
        gdb.close()

    reported = fires[skip] if len(fires) > skip else (fires[-1] if fires else None)
    _out({
        "ok":        True,
        "watch_addr": hex(addr),
        "length":    length,
        "kind":      kind,
        "skip":      skip,
        "armed":     armed,
        "fire_count": len(fires),
        "writer":    reported,
        "all_fires": fires,
    })


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
# Tier 2: GDB-autopsy wrapper (cmd_autopsy)
# ══════════════════════════════════════════════════════════════════════════════
#
# Replaces the "add another printk" debugging anti-pattern with a one-shot
# argv invocation that arms one or more breakpoints on the live GDB stub,
# waits for them to hit, and captures a STRUCTURED snapshot per hit
# (registers, named memory windows, FSBASE-relative reads) driven by a
# YAML-defined preset library at scripts/autopsy/presets.yaml.
#
# Contract:
#   - The session MUST have been started with --gdb-port PORT.  Without it
#     we exit with a JSON error pointing at the correct start command.
#   - Output is a single JSON document on stdout.  Optionally also written
#     to --output PATH for archival.
#   - Hits are returned as an ordered array; agents iterate with no further
#     parsing required.
#   - All memory reads are capped per-step (default 4 KiB per window).
#   - If a breakpoint never hits within --timeout-ms we return what we
#     captured plus `{"timed_out": true}` — silent timeouts are forbidden.
#
# Public spec references:
#   - GDB Remote Serial Protocol (Z0/z0 packets, vCont, stop replies)
#   - Intel SDM Vol. 1 §3.4 (GPR set)
#   - Intel SDM Vol. 3A §3.4.4 (FSBASE/GSBASE MSRs, segment base)
#   - sysV AMD64 ABI §3.2 (stack frame layout)

_AUTOPSY_PRESETS_PATH = _SCRIPTS_DIR / "autopsy" / "presets.yaml"

_KERNEL_NM_CACHE: list[tuple[int, str]] = []


def _kernel_nm_suffix_lookup(suffix: str) -> list[tuple[int, str]]:
    """Use `nm --defined-only -C` against the kernel ELF to find symbols
    whose demangled name equals `suffix` OR ends in `::<suffix>`.

    Used by autopsy's --break resolution as a fallback when pyelftools
    isn't installed (and `_build_kernel_symtab` therefore returns []).
    Caches the parsed nm output for the lifetime of the process.

    Returns a list of (addr, fullname) tuples.  Empty if nm can't run.
    """
    global _KERNEL_NM_CACHE
    if not _KERNEL_NM_CACHE:
        elf = _get_kernel_elf()
        if not elf.exists():
            return []
        try:
            out = subprocess.check_output(
                ["nm", "--defined-only", "-C", str(elf)],
                stderr=subprocess.DEVNULL, timeout=20,
            ).decode("utf-8", errors="replace")
        except (FileNotFoundError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired):
            return []
        parsed: list[tuple[int, str]] = []
        for line in out.splitlines():
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if addr == 0:
                continue
            parsed.append((addr, parts[2]))
        _KERNEL_NM_CACHE = parsed
    suffix_qualified = f"::{suffix}"
    return [(a, n) for (a, n) in _KERNEL_NM_CACHE
            if n == suffix or n.endswith(suffix_qualified)]


def _load_autopsy_presets() -> dict:
    """Read scripts/autopsy/presets.yaml; return the parsed dict.

    Falls back to an empty preset bank if PyYAML is missing or the file
    doesn't exist — the autopsy command can still run with ad-hoc captures
    via --capture-step (future extension) but the canonical path uses
    the preset library.
    """
    if not _AUTOPSY_PRESETS_PATH.exists():
        return {"presets": {}}
    try:
        import yaml
    except ImportError:
        return {"presets": {}, "_warning": "PyYAML missing; presets unavailable"}
    try:
        with _AUTOPSY_PRESETS_PATH.open() as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        return {"presets": {}, "_warning": f"presets.yaml parse error: {e}"}
    if "presets" not in data:
        return {"presets": {}}
    return data


_AUTOPSY_RE_FS_LINE = re.compile(
    r"^FS\s*=([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+", re.MULTILINE
)
_AUTOPSY_RE_GS_LINE = re.compile(
    r"^GS\s*=([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+", re.MULTILINE
)


def _autopsy_query_seg_base(qmp_sock: str, seg: str) -> Optional[int]:
    """Return the segment base (FS/GS) of CPU 0 via QMP info registers.

    On x86_64, FSBASE is stored in the FS_BASE MSR (IA32_FS_BASE) and is
    independent of the FS segment selector; QEMU's `info registers` text
    surfaces it as the 64-bit field immediately after the segment
    selector on the corresponding line.  We don't pause/resume QEMU here
    — caller is responsible for state since autopsy runs while paused at
    a breakpoint.
    """
    resp = _qmp_command(qmp_sock, "human-monitor-command",
                         {"command-line": "info registers"},
                         connect_timeout=2.0)
    text = resp.get("return", "") if isinstance(resp, dict) else ""
    if not text:
        return None
    rx = _AUTOPSY_RE_FS_LINE if seg == "fs" else _AUTOPSY_RE_GS_LINE
    m = rx.search(text)
    if not m:
        return None
    try:
        return int(m.group(2), 16)
    except ValueError:
        return None


def _autopsy_resolve_kernel_rip(rip: int) -> Optional[str]:
    """Best-effort symbol resolution for a kernel-space RIP.  Returns
    'symbol+offset' string or None.

    Tries pyelftools-backed symtab first (fast, demangled).  Falls back
    to the cached nm output when pyelftools is missing so the autopsy
    still names the RIP on minimal Python installs.
    """
    if rip < _KERNEL_VMA_BASE:
        return None
    try:
        elf = _get_kernel_elf()
        if not elf.exists():
            return None
        syms = _build_kernel_symtab(elf)
        if syms:
            named = _resolve_kernel_rip(rip, syms)
            if named:
                return named
    except Exception:
        pass

    # nm fallback: prime the cache via a no-op lookup, then bisect.
    _kernel_nm_suffix_lookup("__AUTOPSY_PRIME_NM_CACHE__")
    if not _KERNEL_NM_CACHE:
        return None
    import bisect
    sorted_pairs = sorted(_KERNEL_NM_CACHE, key=lambda t: t[0])
    addrs = [a for (a, _n) in sorted_pairs]
    idx = bisect.bisect_right(addrs, rip) - 1
    if idx < 0:
        return None
    base, name = sorted_pairs[idx]
    delta = rip - base
    if delta > 0x10000:  # too far from any known symbol — likely junk
        return None
    return f"{name}+{delta:#x}"


def _autopsy_run_step(gdb: GdbClient, regs: dict, step: dict,
                       qmp_sock: str, seg_base_cache: dict,
                       per_step_cap: int) -> dict:
    """Execute one capture step; return its JSON record.

    Errors are FOLDED INTO the record (`"error": "..."`) rather than
    raised — a single failing step must not invalidate the whole hit.
    """
    kind = step.get("kind", "")
    name = step.get("name", "")
    try:
        if kind == "regs":
            return {"kind": "regs", "regs": regs}

        if kind == "mem":
            addr = int(step["addr"]) if not isinstance(step["addr"], str) \
                   else int(step["addr"], 0)
            length = min(int(step["len"]), per_step_cap)
            data = gdb.read_mem(addr, length)
            return {
                "kind": "mem", "addr": hex(addr), "len": len(data),
                "bytes": data.hex(),
            }

        if kind in ("mem_at", "mem_via_reg"):
            reg = step["reg"].lower()
            if reg not in regs:
                return {"kind": kind, "error": f"unknown register {reg!r}"}
            base = int(regs[reg], 16) if isinstance(regs[reg], str) \
                   else int(regs[reg])
            offset = int(step.get("offset", 0))
            length = min(int(step["len"]), per_step_cap)
            addr = (base + offset) & 0xFFFF_FFFF_FFFF_FFFF
            try:
                data = gdb.read_mem(addr, length)
                return {
                    "kind": kind, "reg": reg, "offset": offset,
                    "addr": hex(addr), "len": len(data), "bytes": data.hex(),
                }
            except Exception as e:
                return {
                    "kind": kind, "reg": reg, "offset": offset,
                    "addr": hex(addr), "error": str(e),
                }

        if kind == "mem_via_seg":
            seg = step["seg"].lower()
            if seg not in ("fs", "gs"):
                return {"kind": kind, "error": f"unsupported seg {seg!r}"}
            base = seg_base_cache.get(seg)
            if base is None:
                base = _autopsy_query_seg_base(qmp_sock, seg)
                seg_base_cache[seg] = base
            if base is None:
                return {"kind": kind, "seg": seg,
                        "error": "segment base unavailable from QMP"}
            offset = int(step.get("offset", 0))
            length = min(int(step["len"]), per_step_cap)
            addr = (base + offset) & 0xFFFF_FFFF_FFFF_FFFF
            try:
                data = gdb.read_mem(addr, length)
                return {
                    "kind": kind, "seg": seg, "seg_base": hex(base),
                    "offset": offset, "addr": hex(addr), "len": len(data),
                    "bytes": data.hex(),
                }
            except Exception as e:
                return {
                    "kind": kind, "seg": seg, "seg_base": hex(base),
                    "offset": offset, "addr": hex(addr), "error": str(e),
                }

        if kind == "sym_window":
            sym_name = step["sym"]
            elf = _get_kernel_elf()
            info = _resolve_symbol(elf, sym_name)
            if info is None:
                return {"kind": kind, "sym": sym_name,
                        "error": "symbol not found in kernel ELF"}
            base = int(info["addr"], 16)
            offset = int(step.get("offset", 0))
            length = min(int(step["len"]), per_step_cap)
            addr = (base + offset) & 0xFFFF_FFFF_FFFF_FFFF
            try:
                data = gdb.read_mem(addr, length)
                return {
                    "kind": kind, "sym": sym_name, "sym_addr": info["addr"],
                    "offset": offset, "addr": hex(addr), "len": len(data),
                    "bytes": data.hex(),
                }
            except Exception as e:
                return {"kind": kind, "sym": sym_name, "addr": hex(addr),
                        "error": str(e)}

        if kind == "note":
            return {"kind": "note", "text": str(step.get("text", ""))}

        return {"kind": kind, "error": f"unknown step kind {kind!r}"}
    except KeyError as e:
        return {"kind": kind, "name": name, "error": f"missing field {e}"}
    except Exception as e:
        return {"kind": kind, "name": name, "error": str(e)}


def _autopsy_resolve_break_target(target: str) -> tuple[Optional[int], Optional[str]]:
    """Resolve a --break argument into (address, label).

    Accepts:
      - "0xffff..."   raw hex address
      - "12345"       decimal address
      - "ke_bugcheck" symbol name (looked up in kernel ELF)
      - "ke_bugcheck+0x10" symbol with offset

    Returns (None, "<error msg>") on failure.
    """
    if target.startswith("0x") or target.startswith("0X"):
        try:
            return (int(target, 16), target)
        except ValueError:
            return (None, f"invalid hex address {target!r}")
    if target[:1].isdigit() and "+" not in target:
        try:
            return (int(target, 0), target)
        except ValueError:
            pass

    # Symbol or symbol+offset
    sym = target
    delta = 0
    if "+" in target:
        sym, off_s = target.split("+", 1)
        try:
            delta = int(off_s, 0)
        except ValueError:
            return (None, f"invalid offset {off_s!r} in {target!r}")

    elf = _get_kernel_elf()
    if not elf.exists():
        return (None, f"kernel ELF not found at {elf}")
    info = _resolve_symbol(elf, sym)
    if info is None:
        # Rust mangles kernel symbols (e.g. ke_bugcheck →
        # astryx_kernel::ke::bugcheck::ke_bugcheck), so fall back to a
        # suffix-match across the kernel symtab.  The user-friendly
        # "break ke_bugcheck" then resolves the canonical mangled name.
        # Try pyelftools first (covers both global and local symbols);
        # if pyelftools is missing the symtab is empty and we fall through
        # to an `nm -C` based lookup.
        candidates: list[tuple[int, str]] = []
        try:
            syms = _build_kernel_symtab(elf)
        except Exception:
            syms = []
        suffix = f"::{sym}"
        candidates = [(a, n) for (a, _sz, n) in syms
                      if n == sym or n.endswith(suffix)]
        if not candidates:
            candidates = _kernel_nm_suffix_lookup(sym)
        if len(candidates) == 1:
            addr, fullname = candidates[0]
            return (addr + delta,
                    f"{target} ({fullname})")
        if len(candidates) > 1:
            sample = [c[1] for c in candidates[:5]]
            return (None, f"symbol {sym!r} ambiguous "
                          f"({len(candidates)} matches, e.g. {sample}); "
                          f"pass the fully-qualified name or a hex address")
        return (None, f"symbol {sym!r} not found in {elf.name}")
    try:
        addr = int(info["addr"], 16) + delta
    except (TypeError, ValueError) as e:
        return (None, f"symbol resolution returned non-hex: {e}")
    return (addr, target)


def cmd_autopsy(args):
    """
    GDB-autopsy wrapper.

    Arms one or more breakpoints on the live GDB stub, resumes the
    guest, and on each hit runs a YAML-defined capture preset that
    produces STRUCTURED JSON (registers, named memory windows,
    FSBASE-relative reads) instead of forcing the agent to grep raw
    GDB output.

    Usage (canonical):
      qemu-harness.py autopsy <sid> \\
          --break ke_bugcheck \\
          --capture ssp-fail-snapshot \\
          --once \\
          --timeout-ms 60000 \\
          --output /tmp/ssp.json

    Mandatory first probe before ANY new printk-style ring buffer.
    """
    sess = _load_session(args.sid)
    port = _get_gdb_port(sess)
    qmp_sock = sess["qmp_sock"]

    # ── Preset resolution ────────────────────────────────────────────────────
    bank = _load_autopsy_presets()
    preset_name = args.capture
    presets = bank.get("presets") or {}
    if preset_name not in presets:
        _err(f"Unknown preset {preset_name!r}. "
             f"Available: {sorted(presets.keys())}. "
             f"Edit {_AUTOPSY_PRESETS_PATH} to add a new one.")
    preset = presets[preset_name]
    steps = preset.get("steps") or []
    if not steps:
        _err(f"Preset {preset_name!r} has no steps")

    # ── Breakpoint resolution ────────────────────────────────────────────────
    breaks: list[dict] = []
    for tgt in args.brk:
        addr, label = _autopsy_resolve_break_target(tgt)
        if addr is None:
            _err(f"Could not resolve --break {tgt!r}: {label}")
        breaks.append({"addr": addr, "label": tgt})

    # ── Stub lock (one autopsy at a time) ────────────────────────────────────
    import fcntl
    lock_path = HARNESS_DIR / f"{args.sid}.gdb.lock"
    lock_fd = open(lock_path, "w")
    try:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_fd.close()
        _err(f"GDB stub for sid {args.sid} is busy (another autopsy / "
             f"rip-sample / kdb invocation holds the lock). Retry once it "
             f"exits.")

    # ── Pause guest, connect, arm breakpoints, capture ───────────────────────
    # We pause via QMP first so the breakpoints land on a frozen guest;
    # this avoids a race where the guest runs past the desired symbol
    # between the connect and the Z0 packet.
    was_paused = False
    paused_resp = _qmp_command(qmp_sock, "stop", connect_timeout=3.0)
    if "error" in paused_resp:
        # QMP stop on an already-stopped guest can return runstate-mismatch;
        # treat it as a benign "already stopped" condition.
        was_paused = True

    hits: list[dict] = []
    timed_out = False
    captured_error: Optional[str] = None
    started_at = time.time()

    gdb = GdbClient("127.0.0.1", port)
    if not gdb.connect():
        # Make sure we don't leave the guest paused on connect failure.
        if not was_paused:
            _qmp_command(qmp_sock, "cont", connect_timeout=3.0)
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
        finally:
            lock_fd.close()
        _err(f"Cannot connect to GDB stub on port {port} (tried "
             f"{port}..{port+4}). Was the session started with --gdb-port?")

    armed_addrs: list[int] = []
    try:
        # Arm all requested breakpoints.
        for b in breaks:
            ok = gdb.set_bp(b["addr"], hw=bool(getattr(args, "hw_break", False)))
            b["armed"] = bool(ok)
            if ok:
                armed_addrs.append(b["addr"])
        if not armed_addrs:
            captured_error = "no breakpoints could be armed (check addresses)"
        else:
            per_step_cap = max(64, min(int(args.max_bytes_per_step), 4096))
            once_n = max(1, int(args.once_n))
            timeout_ms = max(100, int(args.timeout_ms))
            wait_budget = timeout_ms / 1000.0

            # ── Parse --match-reg filters (NAME=HEXVAL, AND semantics) ──
            match_filters: list[tuple[str, int]] = []
            for spec in (args.match_reg or []):
                if "=" not in spec:
                    captured_error = f"bad --match-reg {spec!r} (want NAME=HEXVAL)"
                    break
                rn, rv = spec.split("=", 1)
                try:
                    match_filters.append((rn.strip().lower(), int(rv, 0)))
                except ValueError:
                    captured_error = f"bad --match-reg value in {spec!r}"
                    break
            match_scan_max = max(1, int(getattr(args, "match_scan_max", 200000)))
            scanned_nonmatch = 0  # diagnostic: how many fires we skipped

            def _regs_match(regs_dict: dict) -> bool:
                for rn, rv in match_filters:
                    try:
                        cur = int(regs_dict.get(rn, "0x0"), 16)
                    except Exception:
                        return False
                    if cur != rv:
                        return False
                return True

            # The breakpoint loop: resume → wait → snapshot → repeat.
            for hit_index in range(once_n):
                # Resume.  QMP cont is the canonical "let it run" command;
                # we then poll the GDB stub's stop-reply channel.
                cont_resp = _qmp_command(qmp_sock, "cont",
                                          connect_timeout=2.0)
                if "error" in cont_resp:
                    # Already running is benign.
                    pass

                # Tell the GDB stub to continue too (so vCont state is
                # cleared) — QMP cont already resumes the vCPUs but
                # without a matching vCont;c the next stop-reply may
                # have stale state.  We still need to drain via
                # wait_for_stop.
                try:
                    gdb.cont_no_wait()
                except Exception as e:
                    captured_error = f"gdb continue failed: {e}"
                    break

                stop_reply = gdb.wait_for_stop(wait_budget)
                if stop_reply is None:
                    timed_out = True
                    # Pause back so the cleanup path can disarm cleanly.
                    _qmp_command(qmp_sock, "stop", connect_timeout=2.0)
                    break

                # The guest is now halted at the breakpoint; snapshot it.
                try:
                    regs = gdb.read_regs()
                except Exception as e:
                    regs = {}
                    captured_error = f"read_regs failed: {e}"

                # ── --match-reg filter: skip benign fires ──
                # On a high-frequency handler (handle_page_fault), keep
                # resuming until the registers match the requested filter
                # (e.g. rdi==0xd0 to isolate one CR2).  Skipped fires do
                # NOT count against --once N.
                if match_filters and regs and not _regs_match(regs):
                    skipped = False
                    while scanned_nonmatch < match_scan_max:
                        scanned_nonmatch += 1
                        # renew budget; bail out if exhausted
                        elapsed = time.time() - started_at
                        if elapsed >= timeout_ms / 1000.0:
                            timed_out = True
                            _qmp_command(qmp_sock, "stop", connect_timeout=2.0)
                            skipped = True
                            break
                        try:
                            gdb.cont_no_wait()
                        except Exception as e:
                            captured_error = f"gdb continue (match-scan) failed: {e}"
                            skipped = True
                            break
                        sr = gdb.wait_for_stop(
                            max(0.1, timeout_ms / 1000.0 - elapsed))
                        if sr is None:
                            timed_out = True
                            _qmp_command(qmp_sock, "stop", connect_timeout=2.0)
                            skipped = True
                            break
                        try:
                            regs = gdb.read_regs()
                        except Exception as e:
                            regs = {}
                            captured_error = f"read_regs (match-scan) failed: {e}"
                            skipped = True
                            break
                        stop_reply = sr
                        if _regs_match(regs):
                            skipped = False
                            break
                    else:
                        # ran out of scan budget without a match
                        captured_error = (
                            f"--match-reg unmatched after "
                            f"{scanned_nonmatch} fires")
                        timed_out = True
                    if skipped or (match_filters and not _regs_match(regs)):
                        # Could not isolate a matching fire — stop the loop.
                        break

                rip = 0
                try:
                    rip = int(regs.get("rip", "0x0"), 16)
                except Exception:
                    pass

                # Match this hit to one of our armed breakpoints (by RIP).
                matched = None
                for b in breaks:
                    if b.get("armed") and b["addr"] == rip:
                        matched = b
                        break
                bp_record = {
                    "addr": hex(rip),
                    "label": matched["label"] if matched else None,
                    "symbol": _autopsy_resolve_kernel_rip(rip),
                }

                # Run the preset's capture steps.
                seg_base_cache: dict = {}
                captures: dict = {}
                for step in steps:
                    step_name = step.get("name") or step.get("kind", "?")
                    captures[step_name] = _autopsy_run_step(
                        gdb, regs, step, qmp_sock,
                        seg_base_cache, per_step_cap,
                    )

                hits.append({
                    "hit_index": hit_index,
                    "breakpoint": bp_record,
                    "stop_reply": stop_reply,
                    "captures": captures,
                })

                # Budget renewal for the next hit (subtract elapsed).
                wait_budget = max(
                    0.1,
                    timeout_ms / 1000.0 - (time.time() - started_at),
                )
                if wait_budget <= 0:
                    timed_out = True
                    break

                # If continue-after is OFF (single shot per arm), break.
                if not args.continue_after:
                    break
    finally:
        # When the caller asked to leave the guest paused, freeze it via QMP
        # FIRST — before detaching GDB.  QEMU's gdbstub RESUMES the guest on
        # detach ($D packet sent by gdb.close()), which would race the fault
        # context out of existence (the faulting CR3 gets torn down as the
        # process exits).  A QMP `stop` issued while still at the breakpoint
        # keeps the vCPUs halted across the detach so a follow-up physical /
        # page-table read sees the exact faulting address space.
        if args.leave_paused:
            _qmp_command(qmp_sock, "stop", connect_timeout=3.0)
        # Always disarm the breakpoints we set; leaving them armed would
        # surprise the next agent who attaches via `step`/`cont`.
        for addr in armed_addrs:
            try:
                gdb.del_bp(addr, hw=bool(getattr(args, "hw_break", False)))
            except Exception:
                pass
        try:
            gdb.close()
        except Exception:
            pass

        # Resume the guest UNLESS the caller asked to leave it paused.
        if not args.leave_paused:
            _qmp_command(qmp_sock, "cont", connect_timeout=3.0)

        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
        finally:
            lock_fd.close()

    # ── Emit ─────────────────────────────────────────────────────────────────
    result = {
        "ok":          len(hits) > 0 or not timed_out,
        "sid":         args.sid,
        "preset":      preset_name,
        "preset_desc": preset.get("description", "").strip(),
        "breakpoints": [
            {"label": b["label"], "addr": hex(b["addr"]),
             "armed": b.get("armed", False)}
            for b in breaks
        ],
        "hit_count":   len(hits),
        "timed_out":   timed_out,
        "elapsed_s":   round(time.time() - started_at, 3),
        "hits":        hits,
    }
    try:
        if args.match_reg:
            result["match_reg"] = args.match_reg
            result["scanned_nonmatch"] = scanned_nonmatch
    except NameError:
        pass
    if captured_error:
        result["error"] = captured_error
    if "_warning" in bank:
        result["preset_warning"] = bank["_warning"]

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2, default=str)
            result["output_path"] = args.output
        except OSError as e:
            result["output_error"] = str(e)

    _out(result)


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
    if op in ("ping", "proc-list", "vfs-mounts", "trace-status",
              "bell-stats", "cache-audit", "cache-aliasing",
              "fault-cache-keys", "w215-cache-residency",
              "tlb-stats", "heap-stats", "w215-diag",
              "coverage-flush", "proc-metrics",
              "futex-stats",
              # blk-trace: out-of-band drain of the virtio-blk LBA ring.
              "blk-trace", "blk-trace-flush",
              # log-ring: out-of-band drain / burst-flush of the cheap log ring.
              "log-ring", "log-ring-flush",
              # virtio-blk wait-amplification: drain the per-round-trip wait
              # histogram / zero the ring.  See drivers::virtio_blk +
              # op_virtio_wait_hist.
              "virtio-wait-hist", "virtio-wait-reset",
              # INFRA-3 record/replay: zero-arg introspection.
              "record-status"):
        return {"op": op}
    if op == "virtio-wait-mode":
        # Flip the wait strategy at runtime: adaptive (poll + peer-aware yield) |
        # legacy (unconditional schedule()-yield).  Absent → query-only.  Carried
        # as {"mode": ...} to match the kernel op's extract_field("mode") parse.
        if not rest:
            return {"op": "virtio-wait-mode"}
        val = rest[0].strip().lower()
        if val not in ("adaptive", "legacy", "true", "false", "1", "0"):
            raise ValueError(
                f"virtio-wait-mode: unrecognised value '{rest[0]}' "
                "(expected adaptive|legacy)"
            )
        return {"op": "virtio-wait-mode", "mode": val}
    if op == "virtio-wait-spin":
        # Set the adaptive-spin budget (iterations) before blocking.
        if not rest:
            raise ValueError("virtio-wait-spin requires an integer iteration count")
        try:
            n = int(rest[0])
        except ValueError:
            raise ValueError(f"virtio-wait-spin: '{rest[0]}' is not an integer")
        return {"op": "virtio-wait-spin", "n": str(n)}
    if op == "log-ring-enable":
        # Toggle the fast-path ring sink (A/B control). Optional on/off; absent
        # → query-only. Carried as {"on": "on"|"off"} to match the kernel op's
        # extract_field("on") parse (mirrors futex-set-cluster-wake).
        if not rest:
            return {"op": "log-ring-enable"}
        val = rest[0].strip().lower()
        if val not in ("on", "off", "true", "false", "1", "0"):
            raise ValueError(
                f"log-ring-enable: unrecognised value '{rest[0]}' "
                "(expected on|off)"
            )
        return {"op": "log-ring-enable", "on": val}
    if op == "replay-dump":
        # INFRA-3: dump the in-RAM record log to a VFS file.  Single
        # required positional `path=<abs>` arg (or just `<abs>`).
        if not rest:
            raise ValueError("replay-dump requires <path> (absolute VFS path)")
        # Accept either `path=/foo` or bare `/foo`.
        tok = rest[0]
        path = tok.split("=", 1)[1] if tok.startswith("path=") else tok
        return {"op": "replay-dump", "path": path}
    if op == "futex-set-cluster-wake":
        # Accepts:
        #   futex-set-cluster-wake on
        #   futex-set-cluster-wake off
        #   futex-set-cluster-wake true|false|1|0
        # Default queried via futex-stats (no toggle here).
        if not rest:
            raise ValueError("futex-set-cluster-wake requires on|off")
        val = rest[0].strip().lower()
        if val not in ("on", "off", "true", "false", "1", "0"):
            raise ValueError(
                f"futex-set-cluster-wake: unrecognised value '{rest[0]}' "
                "(expected on|off|true|false|1|0)"
            )
        return {"op": "futex-set-cluster-wake", "on": val}
    if op == "proc":
        if not rest: raise ValueError("proc requires <pid>")
        return {"op": "proc", "pid": int(rest[0], 0)}
    if op == "procmaps":
        # Terse file-backed VMA map for ASLR-base / addr2line symbolication.
        # Emits one JSON object per VMA with first_page_phys via PML4 walk.
        if not rest: raise ValueError("procmaps requires <pid>")
        return {"op": "procmaps", "pid": int(rest[0], 0)}
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
    if op == "arm-phys":
        # Manually arm a write-only DR watchpoint on a specific physical
        # address (bypasses cache::insert pre-arm key filter).  Phys is
        # passed verbatim as a string so the kernel-side parse_u64 sees
        # the "0x..." prefix.  Requires the kernel built with
        # --features w215-diag.
        if not rest: raise ValueError("arm-phys requires <phys>")
        # Validate parseability host-side and round-trip as canonical hex
        # so a caller's "0X..." / "29d91000" forms both reach the kernel
        # as "0x29d91000".
        phys = int(rest[0], 0)
        return {"op": "arm-phys", "phys": f"0x{phys:x}"}
    if op == "user-mem":
        if len(rest) < 3: raise ValueError("user-mem requires <pid> <addr> <len>")
        return {"op": "user-mem", "pid": int(rest[0], 0),
                "addr": rest[1], "len": int(rest[2], 0)}
    if op == "rip-trace":
        # Periodic userspace RIP sampler for one TID over a fixed
        # wall-clock window.  Used to characterise userspace plateaux
        # where kernel-side metrics (sc/clone3/futex counts) plateau
        # but the target thread is alive and looping in libxul (the
        # post-PR-#287/#288/#289 JIT plateau pattern; see the W101
        # firefox plateau memory for the same shape in May).
        if not rest:
            raise ValueError("rip-trace requires <tid> [<ms>] (default ms=1000)")
        tid = int(rest[0], 0)
        ms  = int(rest[1], 0) if len(rest) >= 2 else 1000
        return {"op": "rip-trace", "tid": tid, "ms": ms}
    if op == "futex-ghost-hist":
        # History-based FUTEX_WAKE_GHOST diagnostic.  Optional positional
        # token controls the kernel-side toggle / counter reset:
        #   kdb <sid> futex-ghost-hist                  → snapshot
        #   kdb <sid> futex-ghost-hist on               → enable + snapshot
        #   kdb <sid> futex-ghost-hist off              → disable + snapshot
        #   kdb <sid> futex-ghost-hist reset            → reset + snapshot
        # Snapshot is always returned in the response.  The kernel
        # additionally mirrors a [GHOST_HIST_SUMMARY] block to serial
        # on every invocation so the harness has a structured side
        # channel.  Requires --features firefox-test or test-mode.
        req: dict = {"op": "futex-ghost-hist"}
        if rest:
            tok = rest[0].lower()
            if tok in ("on", "enable", "true", "1"):
                req["enable"] = "true"
            elif tok in ("off", "disable", "false", "0"):
                req["enable"] = "false"
            elif tok in ("reset", "clear"):
                req["reset"] = "true"
            else:
                raise ValueError(
                    f"futex-ghost-hist: unknown sub-arg {rest[0]!r} "
                    "(expected on|off|reset or none)"
                )
        return req
    if op == "cond-autopsy":
        # One-shot musl pthread_cond/mutex wake-target-vs-wait-addr report.
        #   kdb <sid> cond-autopsy <pid> <cond_va> [<half>]   (half default 128)
        # Composes the live struct dump + parked waiters (FUTEX_WAITERS in
        # [va-half, va+half]) + recent FUTEX_WAKE targets + inferred lock
        # holder into ONE JSON object with a verdict_hint.  The cond_va is
        # canonicalised to 0x-prefixed hex so the kernel parse_u64 sees the
        # prefix (matching the arm-phys branch).  Requires --features kdb;
        # the recent_wakes section additionally needs firefox-test/test-mode.
        if len(rest) < 2:
            raise ValueError(
                "cond-autopsy requires <pid> <cond_va> [<half>]")
        half = int(rest[2], 0) if len(rest) >= 3 else 128
        return {"op": "cond-autopsy",
                "pid": int(rest[0], 0),
                "addr": f"0x{int(rest[1], 0):x}",
                "half": half}
    if op == "read-file":
        # Read a slice of a VFS file, returned base64.  Robust extraction
        # primitive — works on any live kdb session regardless of process
        # state.  Args: <path> [<offset> [<len>]].  The host-side
        # `read-ff-png --via-kdb` wrapper loops offset+=n until eof.
        if not rest:
            raise ValueError("read-file requires <path> [<offset> [<len>]]")
        req: dict = {"op": "read-file", "path": rest[0]}
        if len(rest) >= 2:
            req["offset"] = int(rest[1], 0)
        if len(rest) >= 3:
            req["len"] = int(rest[2], 0)
        return req
    if op == "net-ipver":
        # Read or toggle the runtime IPv4/IPv6 address-family enable flags.
        #   kdb <sid> net-ipver               → report {ipv4,ipv6} state
        #   kdb <sid> net-ipver 6 off         → disable IPv6, report state
        #   kdb <sid> net-ipver 4 on          → enable IPv4, report state
        # Mirrors the `net-ipver` top-level subcommand below.
        req: dict = {"op": "net-ipver"}
        if rest:
            fam = rest[0].strip()
            if fam not in ("4", "6"):
                raise ValueError(
                    f"net-ipver: family must be 4 or 6 (got {rest[0]!r})")
            req["family"] = fam
            if len(rest) >= 2:
                st = rest[1].strip().lower()
                if st not in ("on", "off", "1", "0", "true", "false",
                              "enable", "disable"):
                    raise ValueError(
                        f"net-ipver: state must be on|off (got {rest[1]!r})")
                req["state"] = st
            else:
                raise ValueError("net-ipver <family> requires a state (on|off)")
        return req
    raise ValueError(f"unknown kdb op: {op}")


def _kdb_recv(port: int, req: dict, timeout: float = 30.0) -> bytes:
    """Send one JSON kdb request, return the raw response bytes.

    `timeout` is the OVERALL DEADLINE (not per-attempt).  The harness retries
    connect/send/read on `ConnectionRefused` / `socket.timeout` /
    `ConnectionReset` / empty-read with exponential backoff until the
    deadline is reached.  This tolerates transient BSP starvation under
    heavy guest load without forcing every caller to wrap a retry loop.
    The connection is closed on every attempt — kdb is one-request-per-
    connection, so a partial response cannot be resumed.
    """
    payload = (json.dumps(req) + "\n").encode("utf-8")
    deadline = time.monotonic() + max(timeout, 0.1)
    backoff = 0.1
    last_err: Exception | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise last_err or socket.timeout(f"kdb deadline {timeout}s exceeded")
        # Per-attempt socket timeout.  For connect-refused / RST we want
        # to retry quickly, but once the connection IS established a
        # large response (multiple MSS) drains over several TCP round-
        # trips and `recv` may legitimately block longer than 3 s for a
        # single chunk.  Use the FULL remaining deadline as the socket
        # timeout — connect-refused still fires fast (kernel returns
        # ECONNREFUSED immediately, no need to wait), but a slow drain
        # gets its fair share of the deadline.  The earlier 3 s cap was
        # specifically a problem for ops that emit >1460 B (one MSS):
        # the kdb server is one-response-per-connection, so a retry on
        # the original short timeout reopens a fresh socket whose new
        # 4-tuple the server has already marked responded=true.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(max(0.5, remaining))
        try:
            s.connect(("127.0.0.1", port))
            s.sendall(payload)
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 128 * 1024:
                    break
            if buf.endswith(b"\n"):
                return buf
            last_err = ConnectionResetError(
                "kdb peer closed before newline (incomplete response)")
        except (socket.timeout, ConnectionRefusedError,
                ConnectionResetError, BrokenPipeError, OSError) as e:
            last_err = e
        finally:
            s.close()
        sleep_for = min(backoff, max(0.0, deadline - time.monotonic()))
        if sleep_for > 0:
            time.sleep(sleep_for)
        backoff = min(backoff * 2.0, 1.0)


def _kdb_call(port: int, req: dict, timeout: float = 30.0) -> dict:
    """One-shot kdb call.  Connects, sends one JSON line, reads one line back,
    closes.  Returns the parsed response.  `timeout` is the overall deadline;
    `_kdb_recv` will retry under transient TCP/poll-cycle stalls.

    For diagnostic access to the raw bytes (e.g. to surface them in a
    malformed-response error), use `_kdb_recv` and `json.loads` separately."""
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

    # cond-autopsy: derive a one-line human summary so the recurring manual
    # interpretation ("waiter at +delta, holder runnable?") is a glance.
    # Purely additive — the machine-readable verdict_hint stays the source of
    # truth; `summary` is a derived convenience key.
    if args.op == "cond-autopsy" and isinstance(resp, dict) and "verdict_hint" in resp:
        try:
            resp["summary"] = _cond_autopsy_summary(resp)
        except Exception:
            pass

    try: cache.write_text(json.dumps(state))
    except OSError: pass

    _out(resp)


def cmd_blk_trace(args):
    """Drain the virtio-blk LBA trace ring (out-of-band; replaces the old
    per-op `[BLK]` serial write).

    Forms:
      blk-trace drain <sid>   -> kdb `blk-trace` op: live ring as JSON
                                 ({feature, total, resident, dropped, emitted,
                                  cap, events:[{op,lba,len,pid}...]}).
      blk-trace flush <sid>   -> kdb `blk-trace-flush` op: re-emit the classic
                                 `[BLK]` serial lines in one burst (legacy
                                 heatmap ingestion), returns {emitted}.

    Thin wrapper over `cmd_kdb`; requires the session to have been started with
    `--features ...,kdb,blk-trace`. `drain` against a non-blk-trace build returns
    `{"feature":"off",...}` rather than an error, so the protocol surface is
    stable across builds.
    """
    sub = getattr(args, "blk_action", None)
    op = {"drain": "blk-trace", "flush": "blk-trace-flush"}.get(sub)
    if op is None:
        _out({"error": f"blk-trace: unknown action {sub!r} "
                       "(expected 'drain' or 'flush')"})
        sys.exit(1)
    # Reuse the kdb one-shot path verbatim (port resolution, recv, JSON, cache).
    args.op = op
    args.args = []
    cmd_kdb(args)


def cmd_log_ring(args):
    """Drain / flush / toggle the near-zero-overhead guest-RAM log ring.

    The cheap high-volume log transport (drivers::log_ring) collects the
    firehose trace families (serial_fast_println!, e.g. `[SC]`) into a lock-free
    ring in guest RAM with ZERO VM-exits, replacing the per-byte COM1 16550 PIO
    path. This wrapper drains it out of band.

    Forms:
      log-ring drain <sid> [--out-file PATH]
          -> kdb `log-ring` op: live ring as JSON
             {feature, cap, total_bytes, resident_bytes, dropped_bytes,
              records, oversize_drops, text, emitted_records}.
             `text` is the recovered, newline-delimited log content. With
             --out-file the decoded bytes are also written there (so the same
             firehose lands in a file a human/agent/serial-web.py can read).
      log-ring flush <sid>
          -> kdb `log-ring-flush` op: re-emit buffered lines to COM1 in one
             burst (serial-log consumers see the firehose), returns {emitted}.
      log-ring enable <sid> [on|off]
          -> kdb `log-ring-enable` op: set the fast-path ring sink on/off (the
             A/B control — `off` forces the slow per-byte COM1 path). Omit the
             state to query. Returns {prev, enabled}.

    Thin wrapper over `cmd_kdb`. Requires the session to have been started with
    `--features ...,kdb`.
    """
    sub = getattr(args, "log_action", None)
    op = {"drain": "log-ring",
          "flush": "log-ring-flush",
          "enable": "log-ring-enable"}.get(sub)
    if op is None:
        _out({"error": f"log-ring: unknown action {sub!r} "
                       "(expected 'drain', 'flush', or 'enable')"})
        sys.exit(1)

    # `enable` carries an optional on/off positional we forward to the kernel op.
    extra_args = []
    if sub == "enable":
        st = getattr(args, "state", None)
        if st:
            extra_args = [st]

    # For drain with --out-file we need the parsed JSON back, so call the kdb
    # one-shot path directly instead of cmd_kdb (which prints and exits).
    out_file = getattr(args, "out_file", None)
    if sub == "drain" and out_file:
        sess = _load_session(args.sid)
        port = int(sess.get("kdb_host_port") or 0)
        if port <= 0:
            _out({"error": "session was not started with --features kdb"})
            sys.exit(1)
        timeout = float(getattr(args, "timeout", 30.0) or 30.0)
        try:
            raw = _kdb_recv(port, {"op": op}, timeout=timeout)
            resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            _out({"error": f"kdb connect/io failed on 127.0.0.1:{port}: {e}"})
            sys.exit(1)
        except (json.JSONDecodeError, ValueError) as e:
            _out({"error": f"malformed response: {e}"})
            sys.exit(1)
        text = resp.get("text", "")
        try:
            with open(out_file, "w", errors="replace") as fh:
                fh.write(text)
            resp["out_file"] = out_file
            resp["out_file_bytes"] = len(text)
        except OSError as e:
            resp["out_file_error"] = str(e)
        # Drop the (potentially huge) text from the printed JSON; it's on disk.
        resp_print = dict(resp)
        resp_print["text"] = f"<{len(text)} bytes written to {out_file}>"
        _out(resp_print)
        return

    # Reuse the kdb one-shot path verbatim (port resolution, recv, JSON, cache).
    args.op = op
    args.args = extra_args
    cmd_kdb(args)


def cmd_net_ipver(args):
    """Read or toggle the runtime IPv4/IPv6 address-family flags via kdb.

    Thin wrapper over the kdb `net-ipver` op.  Prints the structured JSON
    state ({applied?, error?, ipv4_enabled, ipv6_enabled}) emitted by the
    kernel.  See net::ipver + kdb::op_net_ipver.
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)
    if args.family is not None and args.state is None:
        _out({"error": "net-ipver <family> requires a state (on|off)"})
        sys.exit(1)
    req: dict = {"op": "net-ipver"}
    if args.family is not None:
        req["family"] = args.family
        req["state"] = str(args.state).strip().lower()
    timeout = float(getattr(args, "timeout", 10.0) or 10.0)
    try:
        raw = _kdb_recv(port, req, timeout=timeout)
        resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        _out({"error": f"kdb connect/io failed on 127.0.0.1:{port}: {e}"})
        sys.exit(1)
    except (json.JSONDecodeError, ValueError) as e:
        _out({"error": f"malformed response: {e}"})
        sys.exit(1)
    _out(resp)


def _cond_autopsy_summary(resp: dict) -> str:
    """One-line gloss of a cond-autopsy response.

    e.g. `VERDICT=wake-address-mismatch waiters=3@{+0x50,+0x54} holder=tid14`
    `(blocked,runs=false) recent_wakes=2@{+0x50}`.
    """
    verdict = resp.get("verdict_hint", "?")
    waiters = resp.get("waiters", []) or []
    wakes   = resp.get("recent_wakes", []) or []
    holder  = resp.get("holder", {}) or {}

    def _deltas(rows):
        seen = []
        for r in rows:
            try:
                d = int(r.get("delta", 0))
            except (TypeError, ValueError):
                continue
            tag = f"+0x{d:x}" if d >= 0 else f"-0x{-d:x}"
            if tag not in seen:
                seen.append(tag)
        return ("{" + ",".join(seen[:6]) + "}") if seen else "{}"

    w_part = f"waiters={len(waiters)}@{_deltas(waiters)}"
    k_part = f"recent_wakes={len(wakes)}@{_deltas(wakes)}"
    ot = holder.get("owner_tid", 0)
    if ot and str(ot) != "0":
        h_part = (f"holder=tid{ot}({holder.get('owner_state','?')},"
                  f"runs={str(holder.get('owner_runs', False)).lower()})")
    else:
        h_part = "holder=none"
    return f"VERDICT={verdict} {w_part} {h_part} {k_part}"


# ══════════════════════════════════════════════════════════════════════════════
# rip-trace-resolve — kdb rip-trace + host-side .symtab resolution
# ══════════════════════════════════════════════════════════════════════════════
#
# Combines kdb rip-trace (userspace RIP sampler) with host-side symbol lookup
# using the .symtab injected into libxul.so by scripts/inject-libxul-symtab.py.
#
# Workflow:
#   1. Call kdb rip-trace <tid> <ms> to obtain the raw RIP histogram and
#      RBP-chain prefixes.
#   2. Parse [FFTEST/mmap-so] load-base table from the session serial log to
#      find each library's runtime base address.
#   3. For each sampled RIP, subtract the library's load base to get the
#      ELF-relative VMA, then binary-search the host-side .symtab to resolve
#      to <function>+<delta>.
#
# Output (additive superset of kdb rip-trace response):
#   { ...rip-trace fields...,
#     "resolved_rips": [
#       { "rip": "0x...", "count": N, "library": str, "offset": "0x...",
#         "symbol": str|null },
#       ...
#     ],
#     "resolve_stats": { "total": N, "resolved": N, "pct": float },
#   }

_RIP_SYMTAB_CACHE: dict[str, list[tuple[int, int, str]]] = {}


def _load_symtab_from_nm(host_path: str) -> list[tuple[int, int, str]]:
    """Load defined symbols from a host-side .so file using nm.

    Returns a sorted list of (vma, size, name) triples.  Parses nm output
    directly — does not use pyelftools — so that the new .symtab injected by
    inject-libxul-symtab.py is always used regardless of pyelftools' symbol-
    section preference.

    Result is cached per host_path for the process lifetime.
    """
    if host_path in _RIP_SYMTAB_CACHE:
        return _RIP_SYMTAB_CACHE[host_path]
    import bisect as _bisect
    import subprocess as _sp
    syms: list[tuple[int, int, str]] = []
    try:
        out = _sp.check_output(
            ["nm", "--defined-only", host_path],
            stderr=_sp.DEVNULL, timeout=60,
        ).decode("utf-8", errors="replace")
    except (_sp.CalledProcessError, FileNotFoundError, _sp.TimeoutExpired):
        _RIP_SYMTAB_CACHE[host_path] = syms
        return syms
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        syms.append((addr, 0, parts[2]))  # size unknown from nm; use 0
    syms.sort(key=lambda t: t[0])
    _RIP_SYMTAB_CACHE[host_path] = syms
    return syms


def _resolve_rip_with_symtab(rip: int, libs: list, disk_root: Optional[str]) -> dict:
    """Resolve a single RIP to a library + function name.

    Mirrors _resolve_user_rip but uses nm --defined-only (which reads .symtab)
    instead of nm -D (which reads only .dynsym).  Falls back to _resolve_user_rip
    if the library is not found on the host or has no .symtab entries.
    """
    import bisect
    lib_path, off = _resolve_frame_to_lib(rip, libs)
    result: dict = {
        "rip": f"{rip:#x}",
        "library": lib_path,
        "offset": f"{off:#x}" if off is not None else None,
        "symbol": None,
    }
    if lib_path is None:
        return result
    host = _resolve_path_on_host(lib_path, disk_root=disk_root)
    if host and Path(host).exists():
        syms = _load_symtab_from_nm(host)
        if syms:
            addrs = [s[0] for s in syms]
            idx = bisect.bisect_right(addrs, off) - 1
            if idx >= 0:
                addr, _, name = syms[idx]
                delta = off - addr
                result["symbol"] = f"{name}+{delta:#x}"
    if result["symbol"] is None:
        # Fall back to dynsym-only resolution for libraries without .symtab.
        sym = _try_symbolise(host, off) if host else None
        result["symbol"] = sym
    return result


def cmd_rip_trace_resolve(args):
    """Run kdb rip-trace and resolve all sampled RIPs to named functions.

    Calls kdb rip-trace <tid> <ms> to collect a RIP histogram, then resolves
    each top-RIP entry against the host-side .symtab of the owning library
    (libxul.so, libc, etc.).  Requires --features kdb at session start.

    The libxul.so in build/disk/opt/firefox/ must have .symtab populated
    (via scripts/inject-libxul-symtab.py) for libxul symbols to resolve.

    Output schema:
      {
        "tid": N, "pid": N, "ms_requested": N, "samples": N,
        "errors": { ... },        -- from kdb rip-trace
        "top_rips": [...],        -- raw RIP histogram from kdb rip-trace
        "top_rbp_chains": [...],  -- raw chain histogram from kdb rip-trace
        "resolved_rips": [
          { "rip": "0x...", "count": N, "library": str|null,
            "offset": "0x...|null", "symbol": str|null },
          ...
        ],
        "resolve_stats": {
          "total": N,    -- number of top_rips entries
          "resolved": N, -- entries where symbol != null
          "pct": float,  -- resolved / total * 100
        },
      }
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)

    tid = int(args.tid)
    ms  = int(args.ms)
    disk_root = getattr(args, "disk_root", None)
    timeout_val = getattr(args, "timeout", None)
    timeout = float(timeout_val) if timeout_val is not None else (ms / 1000.0 + 10.0)

    # ── 1. Run kdb rip-trace ─────────────────────────────────────────────────
    try:
        raw = _kdb_recv(port, {"op": "rip-trace", "tid": tid, "ms": ms},
                        timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        _out({"error": f"kdb connect/io failed: {e}"}); sys.exit(1)
    try:
        resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError) as e:
        _out({"error": f"malformed kdb response: {e}",
              "raw": raw.decode(errors="replace")}); sys.exit(1)

    if "error" in resp:
        _out(resp); sys.exit(1)

    # ── 2. Build load-base map from serial log ───────────────────────────────
    serial_log = sess.get("serial_log", "")
    try:
        log_lines = Path(serial_log).read_text(errors="replace").splitlines()
    except OSError:
        log_lines = []
    libs = _build_load_base_map(log_lines)

    # ── 3. Resolve each sampled RIP ──────────────────────────────────────────
    top_rips = resp.get("top_rips", [])
    resolved_rips = []
    resolved_count = 0
    for entry in top_rips:
        rip_str = entry.get("rip", "0x0")
        try:
            rip = int(rip_str, 16)
        except (ValueError, TypeError):
            rip = 0
        count = entry.get("count", 0)
        r = _resolve_rip_with_symtab(rip, libs, disk_root)
        r["count"] = count
        resolved_rips.append(r)
        if r["symbol"] is not None:
            resolved_count += 1

    total = len(resolved_rips)
    pct = (resolved_count / total * 100.0) if total > 0 else 0.0

    # ── 4. Emit enriched response (additive superset of rip-trace) ──────────
    out = dict(resp)
    out["resolved_rips"] = resolved_rips
    out["resolve_stats"] = {
        "total": total,
        "resolved": resolved_count,
        "pct": round(pct, 1),
    }
    _out(out)


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

def cmd_tlb_stats(args):
    """One-shot TLB shootdown + PMM recent-free diagnostic readout.

    Calls kdb op 'tlb-stats' and returns a flat JSON object containing:

    TLB transport counters (always present):
      shootdowns_sent, ipis_sent, ack_timeouts, shootdowns_handled,
      quarantine_deferred, quarantine_released, quarantine_depth

    H2 diagnostic counters (firefox-test feature; zero in other builds):
      shootdown_clean_ack_late  -- shootdowns declared clean before handler done
      shootdown_unclean_total   -- shootdowns routed to quarantine (baseline rate)
      pmm_alloc_recent_free     -- frames recycled faster than quarantine window

    W215 H2 verdict gate (for the 5-trial soak):
      PROCEED-TO-FIX  : shootdown_clean_ack_late > 0 OR pmm_alloc_recent_free > 0
      ABORT-ESCALATE  : all counters zero AND W215 cluster reproduces
      NULL            : W215 does not reproduce
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)
    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    try:
        raw = _kdb_recv(port, {"op": "tlb-stats"}, timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        _out({"error": f"kdb connect/io failed on 127.0.0.1:{port}: {e}"})
        sys.exit(1)
    try:
        result = json.loads(raw.strip().decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        _out({"error": f"malformed kdb response: {e}",
              "raw": raw[:256].decode("utf-8", errors="replace")})
        sys.exit(1)
    _out(result)

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
# thread-park-audit — PNG-1 plateau characterisation
# ══════════════════════════════════════════════════════════════════════════════
#
# Wraps kdb op 'thread-park-audit' (requires --features firefox-test,kdb).
# Returns the structured per-thread view documented in kernel/src/kdb.rs;
# adds --save/--diff support for cross-snapshot characterisation so the
# PNG-1 dispatch can confirm determinism across 3 trials.
#
# Output shape (one entry per non-Dead thread):
#   {
#     "tick": N, "sc_total": M, "pid_filter": F,
#     "threads": [
#       { "tid", "pid", "proc_name", "thread_name", "state",
#         "rip", "rsp", "wake_tick", "blocked_for_ticks",
#         "syscall": {"nr","name","arg0"} | null,
#         "wait": { "kind": "futex"|"poll-bell"|"fd-blocked"|"sleep"
#                   |"vfork-complete"|"futex-other"|"unknown", ... }
#       }, ...
#     ]
#   }
#
# Useful invocations:
#   thread-park-audit <sid>                       — full snapshot
#   thread-park-audit <sid> --pid 1               — Mozilla parent only
#   thread-park-audit <sid> --save plateau-1      — save for later diff
#   thread-park-audit <sid> --diff plateau-1      — diff current vs saved

# Regex for the per-thread serial-mirror lines emitted by op_thread_park_audit.
# Captured groups feed _thread_park_from_serial's record reconstruction.
_THREAD_PARK_LINE_RE = re.compile(
    r"\[THREAD-PARK\] id=(\d+) tid=(\d+) pid=(\d+) pname=(\S+) tname=(\S+) "
    r"state=(\S+) rip=(0x[0-9a-fA-F]+) rsp=(0x[0-9a-fA-F]+) "
    r"wake_tick=(\d+) blocked_for=(\d+) sc_nr=(-?\d+) sc_arg0=(0x[0-9a-fA-F]+) "
    r"wait=(\S+)$"
)
_THREAD_PARK_BEGIN_RE = re.compile(
    r"\[THREAD-PARK\] BEGIN audit_id=(\d+) tick=(\d+) sc_total=(\d+) "
    r"pid_filter=(\d+) threads=(\d+)"
)
_THREAD_PARK_END_RE = re.compile(
    r"\[THREAD-PARK\] END audit_id=(\d+) emitted_json=(\d+) threads_total=(\d+)"
)


def _thread_park_parse_wait(wait_suffix: str) -> dict:
    """Parse the compact `wait=KIND[,kv]*` suffix into the JSON-shape dict."""
    parts = wait_suffix.split(",")
    kind = parts[0]
    if "=" in kind:
        # No leading kind — empty wait field; treat as unknown.
        return {"kind": "unknown"}
    out: dict = {"kind": kind}
    for p in parts[1:]:
        if "=" not in p: continue
        k, v = p.split("=", 1)
        if v.startswith("0x"):
            out[k] = v
        else:
            try: out[k] = int(v)
            except ValueError: out[k] = v
    return out


def _thread_park_from_serial(sess: dict, sid: str, pid_filter: int) -> dict:
    """Reconstruct the thread-park-audit response from serial-log lines.

    Reads the session's serial log, finds the MOST RECENT BEGIN/END pair,
    and synthesises a dict shaped like the kdb JSON.  Returns
    `{"threads": []}` if no markers found.
    """
    serial_path = sess.get("serial_log")
    if not serial_path:
        return {"threads": []}
    try:
        lines = Path(serial_path).read_text(errors="replace").splitlines()
    except OSError:
        return {"threads": []}

    # Walk backwards: find the most recent END, then the matching BEGIN.
    end_idx: int | None = None
    end_audit_id: int | None = None
    for i in range(len(lines) - 1, -1, -1):
        m = _THREAD_PARK_END_RE.search(lines[i])
        if m:
            end_idx = i
            end_audit_id = int(m.group(1))
            break
    if end_idx is None or end_audit_id is None:
        return {"threads": []}
    begin_idx: int | None = None
    begin_meta: dict = {}
    for i in range(end_idx - 1, -1, -1):
        m = _THREAD_PARK_BEGIN_RE.search(lines[i])
        if m and int(m.group(1)) == end_audit_id:
            begin_idx = i
            begin_meta = {
                "tick":       int(m.group(2)),
                "sc_total":   int(m.group(3)),
                "pid_filter": int(m.group(4)),
            }
            break
    if begin_idx is None:
        return {"threads": []}

    threads: list[dict] = []
    for ln in lines[begin_idx + 1: end_idx]:
        m = _THREAD_PARK_LINE_RE.search(ln)
        if not m: continue
        if int(m.group(1)) != end_audit_id: continue
        tid = int(m.group(2)); pid = int(m.group(3))
        if pid_filter and pid != pid_filter: continue
        sc_nr   = int(m.group(11))
        sc_arg0 = m.group(12)
        syscall = None
        if sc_nr >= 0:
            syscall = {
                "nr":   sc_nr,
                "name": _syscall_name_lite(sc_nr),
                "arg0": sc_arg0,
            }
        threads.append({
            "tid":               tid,
            "pid":               pid,
            "proc_name":         m.group(4),
            "thread_name":       m.group(5),
            "state":             m.group(6),
            "rip":               m.group(7),
            "rsp":               m.group(8),
            "wake_tick":         int(m.group(9)),
            "blocked_for_ticks": int(m.group(10)),
            "syscall":           syscall,
            "wait":              _thread_park_parse_wait(m.group(13)),
        })
    return {
        **begin_meta,
        "threads": threads,
    }


def _syscall_name_lite(nr: int) -> str:
    """Tiny name table for the syscalls the audit classifier cares about.

    Mirrors kernel/src/perf.linux_syscall_name for the subset that turns
    up in `wait=` classifiers; unknown numbers render as `nr=N`.
    """
    table = {
        0: "read", 7: "poll", 17: "pread64", 23: "select",
        35: "nanosleep", 43: "accept", 45: "recvfrom", 46: "sendmsg",
        47: "recvmsg", 202: "futex", 230: "clock_nanosleep",
        232: "epoll_wait", 270: "pselect6", 271: "ppoll",
        281: "epoll_pwait", 288: "accept4", 295: "preadv",
    }
    return table.get(nr, f"nr={nr}")


def cmd_thread_park_audit(args):
    """PNG-1 plateau characterisation: per-thread wait-object classifier.

    For every thread not in state=Dead, classifies what kernel object the
    thread is parked on (futex/poll-bell/fd-blocked/sleep/vfork-complete)
    using the FUTEX_WAITERS reverse-lookup table, the per-TID last-syscall
    sample, and the process FD tables.  See kernel/src/kdb.rs for the full
    `wait.kind` taxonomy.

    Requires the session to have been started with --features firefox-test,kdb.
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)

    pid = getattr(args, "pid", 0) or 0
    req: dict = {"op": "thread-park-audit"}
    if pid:
        req["pid"] = pid

    timeout = float(getattr(args, "timeout", 30.0) or 30.0)
    # We trigger the op via kdb (so the kernel emits BOTH the JSON
    # response AND the per-thread serial mirror), then fall back to
    # parsing the serial log when the kdb response is unparseable or
    # truncated.  The kernel TCP stack is observed to drain large
    # responses over multiple pump ticks; for pid=1 (Mozilla, 19+
    # threads) the host's recv deadline may expire before the full
    # JSON arrives.  The serial mirror is unconditionally complete.
    kdb_err: str | None = None
    resp: dict
    try:
        raw = _kdb_recv(port, req, timeout=timeout)
        try:
            resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, ValueError) as e:
            kdb_err = f"malformed kdb response (likely TCP-stalled): {e}"
            resp = _thread_park_from_serial(sess, args.sid, pid)
            if not resp.get("threads"):
                _out({"error": kdb_err,
                      "raw": raw.decode(errors="replace")})
                sys.exit(1)
            resp["_kdb_fallback"] = kdb_err
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        kdb_err = f"kdb connect failed on 127.0.0.1:{port}: {e}"
        # Even on socket timeout the kernel may have emitted the serial
        # mirror — try the fallback before giving up.
        resp = _thread_park_from_serial(sess, args.sid, pid)
        if not resp.get("threads"):
            _out({"error": kdb_err})
            sys.exit(1)
        resp["_kdb_fallback"] = kdb_err

    # Optional summary: counts per wait.kind, helpful at-a-glance triage.
    if isinstance(resp, dict) and isinstance(resp.get("threads"), list):
        kinds: dict[str, int] = {}
        for t in resp["threads"]:
            w = (t.get("wait") or {})
            k = w.get("kind", "unknown")
            kinds[k] = kinds.get(k, 0) + 1
        resp["_summary"] = {
            "thread_count": len(resp["threads"]),
            "by_kind": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
        }

    snap_name = getattr(args, "save", None)
    diff_name = getattr(args, "diff", None)

    if snap_name:
        path = HARNESS_DIR / f"{args.sid}.thread-park.{snap_name}.json"
        try:
            path.write_text(json.dumps(resp))
            resp["_saved"] = str(path)
        except OSError as e:
            resp["_save_error"] = str(e)

    if diff_name:
        path = HARNESS_DIR / f"{args.sid}.thread-park.{diff_name}.json"
        if not path.exists():
            _out({"error": f"no saved snapshot '{diff_name}' at {path}"})
            sys.exit(1)
        try:
            prev = json.loads(path.read_text())
        except Exception as e:
            _out({"error": f"could not load snapshot '{diff_name}': {e}"})
            sys.exit(1)

        def _entry_key(e: dict) -> str:
            return f"{e.get('pid')}/{e.get('tid')}"
        # For per-thread diffs we care primarily about the wait.kind
        # transitions: a thread that flipped from futex→poll-bell between
        # snapshots is much more interesting than one that just advanced
        # blocked_for_ticks.  We emit both raw added/removed/changed and
        # a "kind_changed" subset for fast triage.
        prev_map = {_entry_key(e): e for e in prev.get("threads", [])}
        curr_map = {_entry_key(e): e for e in resp.get("threads", [])}
        added    = [curr_map[k] for k in curr_map if k not in prev_map]
        removed  = [prev_map[k] for k in prev_map if k not in curr_map]
        kind_changed = []
        for k in curr_map:
            if k not in prev_map: continue
            old_kind = (prev_map[k].get("wait") or {}).get("kind")
            new_kind = (curr_map[k].get("wait") or {}).get("kind")
            if old_kind != new_kind:
                kind_changed.append({
                    "key": k, "from": old_kind, "to": new_kind,
                    "before": prev_map[k], "after": curr_map[k],
                })
        resp = {
            "diff_against": diff_name,
            "added":         added,
            "removed":       removed,
            "kind_changed":  kind_changed,
            "snapshot":      resp,
        }

    _out(resp)


# ══════════════════════════════════════════════════════════════════════════════
# futex-wake-drill — PNG-2 post-W215 plateau: TID-2 FUTEX_WAKE pattern classifier
# ══════════════════════════════════════════════════════════════════════════════
#
# Post-W215 (PR #270) the demo plateau settled at sc≈2886 with no contentproc
# spawn.  PNG-1 (PR #272 thread-park-audit) identified TID 2 (Mozilla main
# thread) as the FUTEX_WAKE producer — issuing wakes on a worker pool but
# never advancing past the plateau.  Two competing hypotheses:
#
#   H1 STATIC deadlock: TID 2 wakes the SAME futex addresses over and over;
#                       a worker consumes the wakes but never makes forward
#                       progress.  Wake-set is small + stable across time.
#
#   H2 CHURNING/overhead: TID 2's wake addresses CHANGE between time windows
#                         (workers ARE progressing, just slowly).  Plateau is
#                         init/overhead, not deadlock.
#
# This subcommand reads the existing `[FUTEX_WAKE]` and `[FUTEX_WAKE_REQ]`
# diagnostic lines from the serial log (both already emitted unconditionally
# under firefox-test), filters by the producer TID (default 2), splits the
# matched lines into N temporal buckets, and computes Jaccard set-similarity
# of the per-bucket uaddr sets.
#
# Classification rules (matching the PNG-2 dispatch spec):
#   |J(b_last, b_first)| ≥ 0.80  → STATIC (H1)
#   |J(b_last, b_first)| ≤ 0.20  → CHURNING (H2)
#   else                          → HYBRID (mixed)
#
# Output schema:
#   {
#     "ok": true,
#     "tid_filter": N, "bucket_count": K, "window_lines": L,
#     "total_wakes": M, "total_wake_reqs": M',
#     "bucket_summary": [
#       { "i": 0, "lines": [a,b], "wake_count": N, "wake_req_count": N',
#         "unique_uaddrs": K, "top_uaddrs": [
#             { "uaddr": "0x...", "wakes": n, "woken_total": w, "max_woken": m,
#               "wake_reqs": r }
#         ] }, ... ],
#     "jaccard": {
#       "first_vs_last":  0.xx,         # primary classifier
#       "adjacent":      [0.xx, ...],   # bucket[i] vs bucket[i+1]
#     },
#     "verdict": "H1_STATIC" | "H2_CHURNING" | "HYBRID",
#     "verdict_reason": "...",
#     "static_uaddrs": [             # uaddrs present in ALL buckets (H1 evidence)
#         { "uaddr": "0x...", "wakes_per_bucket": [...], "buckets_present": K }
#     ],
#     "churn_metrics": {
#       "uaddrs_in_first_only":  K_a,
#       "uaddrs_in_last_only":   K_b,
#       "uaddrs_in_both":        K_c,
#     }
#   }
#
# References:
#   - POSIX `futex(2)` — FUTEX_WAKE semantics
#   - Intel SDM Vol 3A §8.2.3 (total store order — relied on by sample slots)
#   - Mozilla CondVarPOSIX: https://searchfox.org/mozilla-central/source/mozglue/misc/PlatformConditionVariable.h

_FUTEX_WAKE_FULL_RE = re.compile(
    r"\[FUTEX_WAKE\] tid=(\d+) pid=(\d+) uaddr=(0x[0-9a-fA-F]+) "
    r"woken=(\d+) max=(\d+|MAX)"
)
_FUTEX_WAKE_REQ_FULL_RE = re.compile(
    r"\[FUTEX_WAKE_REQ\] tid=(\d+) pid=(\d+) uaddr=(0x[0-9a-fA-F]+) max=(\d+|MAX)"
)


def _futex_drill_jaccard(a: set, b: set) -> float:
    """Jaccard similarity coefficient of two sets (|A∩B| / |A∪B|).

    Returns 1.0 when both sets are empty (treated as "no change"), and 0.0
    when one is empty and the other is not.  Used to classify wake-set
    drift across temporal buckets.
    """
    if not a and not b: return 1.0
    union = a | b
    if not union: return 1.0
    return len(a & b) / len(union)


def cmd_futex_wake_drill(args):
    """PNG-2 TID-2 FUTEX_WAKE drill: STATIC deadlock vs CHURNING overhead.

    Reads `[FUTEX_WAKE]` and `[FUTEX_WAKE_REQ]` lines from the serial log,
    filters by `--tid` (default 2 = Mozilla parent main), splits the matched
    lines into `--bucket-count` (default 2) equal temporal buckets, and
    classifies the wake-set drift via Jaccard similarity.

    With `--cross-park` the live kdb thread-park-audit is queried alongside
    and uaddr-set is joined against still-parked futex waiters — for each
    uaddr TID is waking, the joined table shows whether any thread is parked
    on it (deadlock-confirming) or no parked waiter exists (consumed wake).
    """
    sess = _load_session(args.sid)
    serial_log = sess.get("serial_log")
    if not serial_log:
        _out({"error": "session has no serial log"})
        sys.exit(1)

    tid_filter   = int(getattr(args, "tid", 2) or 2)
    bucket_count = max(2, int(getattr(args, "bucket_count", 2) or 2))
    window_lines = int(getattr(args, "window_lines", 0) or 0)
    cross_park   = bool(getattr(args, "cross_park", False))

    try:
        lines = Path(serial_log).read_text(errors="replace").splitlines()
    except OSError as e:
        _out({"error": f"cannot read serial log: {e}"})
        sys.exit(1)

    # Collect every matching WAKE / WAKE_REQ line for our tid.  We keep
    # (line_idx, kind, uaddr, woken, max) tuples in chronological order so
    # the bucket split below is deterministic and reproducible.
    wake_rows: list[tuple] = []
    req_rows:  list[tuple] = []
    for i, ln in enumerate(lines):
        m = _FUTEX_WAKE_FULL_RE.search(ln)
        if m and int(m.group(1)) == tid_filter:
            wake_rows.append((i, m.group(3),
                              int(m.group(4)),
                              m.group(5)))
            continue
        m = _FUTEX_WAKE_REQ_FULL_RE.search(ln)
        if m and int(m.group(1)) == tid_filter:
            req_rows.append((i, m.group(3), m.group(4)))

    # Optionally restrict to the most-recent N lines (post-plateau window
    # so early init noise doesn't dominate the classification).
    if window_lines > 0 and lines:
        first_keep = max(0, len(lines) - window_lines)
        wake_rows = [r for r in wake_rows if r[0] >= first_keep]
        req_rows  = [r for r in req_rows  if r[0] >= first_keep]

    if not wake_rows and not req_rows:
        _out({
            "ok": False,
            "tid_filter": tid_filter,
            "error": "no [FUTEX_WAKE] or [FUTEX_WAKE_REQ] lines found "
                     "for this tid; was the kernel built with "
                     "--features firefox-test?",
            "lines_scanned": len(lines),
        })
        return

    # Bucket split: divide WAKE rows into K equal-count slices.  We split
    # on WAKE rather than WAKE_REQ because WAKE is the act-on-real-state
    # signal (REQ logs an attempt regardless of whether any waiter matched).
    # If no WAKE rows exist (only REQ), fall back to REQ-based bucketing
    # so the diagnostic remains useful even when every wake is a no-op.
    rows_for_bucket = wake_rows if wake_rows else req_rows
    n = len(rows_for_bucket)
    bucket_count_eff = min(bucket_count, n) if n > 0 else 0
    if bucket_count_eff < 2:
        _out({
            "ok": False,
            "tid_filter": tid_filter,
            "error": f"too few wake/wake_req rows ({n}) for bucket_count={bucket_count}",
            "wake_count": len(wake_rows),
            "wake_req_count": len(req_rows),
        })
        return

    # Compute bucket boundaries by row-index (chronological), not by line
    # number — guarantees roughly equal sample sizes per bucket even when
    # the wake-rate varies wildly across the run.
    edges_row: list[int] = []
    for b in range(bucket_count_eff + 1):
        edges_row.append((b * n) // bucket_count_eff)
    # Translate row-edges back into serial-line ranges for human readability.
    line_edges: list[tuple] = []
    for b in range(bucket_count_eff):
        lo_row = edges_row[b]; hi_row = edges_row[b + 1]
        if hi_row > lo_row:
            lo_line = rows_for_bucket[lo_row][0]
            hi_line = rows_for_bucket[hi_row - 1][0]
        else:
            lo_line = hi_line = 0
        line_edges.append((lo_line, hi_line))

    # Per-bucket aggregation.  uaddr → (wake_count, woken_total, max_woken,
    # wake_req_count).
    buckets: list[dict] = []
    for b in range(bucket_count_eff):
        lo_row = edges_row[b]; hi_row = edges_row[b + 1]
        # Translate to a (lo_line, hi_line) inclusive range for slicing
        # the OTHER row-list (WAKE_REQ) — important so wake/wake_req counts
        # in the same bucket cover the same serial-log window.
        lo_line, hi_line = line_edges[b]
        agg: dict[str, dict] = {}
        for (_, uaddr, woken, mx) in wake_rows[
                _lo_idx(wake_rows, lo_line):
                _hi_idx(wake_rows, hi_line)]:
            row = agg.setdefault(uaddr, {
                "uaddr": uaddr, "wakes": 0, "woken_total": 0,
                "max_woken": 0, "wake_reqs": 0,
            })
            row["wakes"] += 1
            row["woken_total"] += woken
            if woken > row["max_woken"]:
                row["max_woken"] = woken
        for (_, uaddr, _mx) in req_rows[
                _lo_idx(req_rows, lo_line):
                _hi_idx(req_rows, hi_line)]:
            row = agg.setdefault(uaddr, {
                "uaddr": uaddr, "wakes": 0, "woken_total": 0,
                "max_woken": 0, "wake_reqs": 0,
            })
            row["wake_reqs"] += 1
        # Top-N for human triage.
        top = sorted(agg.values(),
                     key=lambda r: (-r["wakes"], -r["wake_reqs"]))[:10]
        buckets.append({
            "i": b,
            "lines": [lo_line, hi_line],
            "row_range": [lo_row, hi_row],
            "wake_count":     sum(r["wakes"]     for r in agg.values()),
            "wake_req_count": sum(r["wake_reqs"] for r in agg.values()),
            "unique_uaddrs":  len(agg),
            "top_uaddrs":     top,
            "_uaddr_set":     set(agg.keys()),
        })

    # Jaccard similarity classification.
    first_set = buckets[0]["_uaddr_set"]
    last_set  = buckets[-1]["_uaddr_set"]
    j_first_last = _futex_drill_jaccard(first_set, last_set)
    j_adjacent = [
        _futex_drill_jaccard(buckets[i]["_uaddr_set"],
                              buckets[i + 1]["_uaddr_set"])
        for i in range(len(buckets) - 1)
    ]

    if j_first_last >= 0.80:
        verdict = "H1_STATIC"
        reason  = (f"first-vs-last Jaccard={j_first_last:.2f} ≥ 0.80: "
                   f"TID {tid_filter} is waking the same uaddr set across "
                   f"the entire {bucket_count_eff}-bucket window — STATIC "
                   f"deadlock pattern.")
    elif j_first_last <= 0.20:
        verdict = "H2_CHURNING"
        reason  = (f"first-vs-last Jaccard={j_first_last:.2f} ≤ 0.20: "
                   f"TID {tid_filter}'s wake set has rotated over time — "
                   f"workers ARE making progress, plateau is overhead/cost.")
    else:
        verdict = "HYBRID"
        reason  = (f"first-vs-last Jaccard={j_first_last:.2f} in (0.20, 0.80): "
                   f"partial overlap — some uaddrs persist across the window "
                   f"(potential deadlock subset) while others rotate.")

    # Static-uaddrs (present in EVERY bucket) — the H1 evidence list.
    common: set[str] = set(buckets[0]["_uaddr_set"])
    for b in buckets[1:]:
        common &= b["_uaddr_set"]
    static_uaddrs = []
    for ua in sorted(common):
        per_bucket = [
            next((r["wakes"] for r in b["top_uaddrs"] if r["uaddr"] == ua), 0)
            for b in buckets
        ]
        static_uaddrs.append({
            "uaddr": ua,
            "wakes_per_bucket": per_bucket,
            "buckets_present":  len(buckets),
        })

    churn_metrics = {
        "uaddrs_in_first_only": len(first_set - last_set),
        "uaddrs_in_last_only":  len(last_set  - first_set),
        "uaddrs_in_both":       len(first_set & last_set),
    }

    # Drop the internal _uaddr_set field before JSON-serialising.
    for b in buckets:
        b.pop("_uaddr_set", None)

    resp: dict = {
        "ok":              True,
        "tid_filter":      tid_filter,
        "bucket_count":    bucket_count_eff,
        "window_lines":    window_lines,
        "lines_scanned":   len(lines),
        "total_wakes":     len(wake_rows),
        "total_wake_reqs": len(req_rows),
        "bucket_summary":  buckets,
        "jaccard": {
            "first_vs_last": round(j_first_last, 4),
            "adjacent":      [round(j, 4) for j in j_adjacent],
        },
        "verdict":         verdict,
        "verdict_reason":  reason,
        "static_uaddrs":   static_uaddrs,
        "churn_metrics":   churn_metrics,
    }

    # Optional: cross-reference live FUTEX_WAITERS via thread-park-audit.
    # If --cross-park, we issue the live kdb query and join the WAKING uaddr
    # set against the still-PARKED uaddr set.  For each waking uaddr we list
    # any tids currently blocked on it — these are the worker(s) supposed to
    # consume each wake.  Absence of parked waiters for a heavily-waked uaddr
    # is strong evidence of either lost-wakeup or post-consume re-park.
    if cross_park:
        port = int(sess.get("kdb_host_port") or 0)
        if port <= 0:
            resp["cross_park_error"] = "session not started with --features kdb"
        else:
            try:
                raw = _kdb_recv(port, {"op": "thread-park-audit"},
                                timeout=float(getattr(args, "timeout", 30.0)))
                park = json.loads(raw.strip().decode("utf-8", errors="replace"))
                parked_by_uaddr: dict[str, list[dict]] = {}
                for t in park.get("threads", []):
                    w = t.get("wait") or {}
                    if w.get("kind") != "futex": continue
                    ua = w.get("uaddr")
                    if not ua: continue
                    parked_by_uaddr.setdefault(ua, []).append({
                        "tid":         t.get("tid"),
                        "pid":         t.get("pid"),
                        "thread_name": t.get("thread_name"),
                        "blocked_for_ticks": t.get("blocked_for_ticks"),
                    })
                # Join: for each TOP uaddr in the LAST bucket, attach parked
                # waiters list.  Last bucket because that's the live state
                # the cross-park snapshot is concurrent with.
                joined = []
                for row in buckets[-1].get("top_uaddrs", []):
                    ua = row["uaddr"]
                    waiters = parked_by_uaddr.get(ua, [])
                    joined.append({
                        **row,
                        "parked_waiters_count": len(waiters),
                        "parked_waiters":       waiters,
                    })
                resp["cross_park"] = {
                    "live_parked_futex_uaddrs": len(parked_by_uaddr),
                    "join_last_bucket":          joined,
                }
            except (socket.timeout, ConnectionRefusedError, OSError,
                    json.JSONDecodeError, ValueError) as e:
                resp["cross_park_error"] = f"kdb thread-park-audit failed: {e}"

    _out(resp)


def _lo_idx(rows: list[tuple], lo_line: int) -> int:
    """Binary-search index of the first row with line_idx ≥ lo_line.

    Assumes rows are sorted by line_idx ascending (always true: they were
    accumulated in serial-log order).  O(log N) per call; the per-bucket
    aggregation in cmd_futex_wake_drill calls this twice per bucket.
    """
    import bisect
    keys = [r[0] for r in rows]
    return bisect.bisect_left(keys, lo_line)


def _hi_idx(rows: list[tuple], hi_line: int) -> int:
    """Binary-search index one-past the last row with line_idx ≤ hi_line."""
    import bisect
    keys = [r[0] for r in rows]
    return bisect.bisect_right(keys, hi_line)


# ══════════════════════════════════════════════════════════════════════════════
# cache-audit — W215 H1 diagnostic: page-cache refcount invariant walker
# ══════════════════════════════════════════════════════════════════════════════
#
# Wraps kdb op 'cache-audit' (firefox-test kernel builds only) and pretty-
# prints the result.  The response carries:
#   total_entries           — number of entries currently in PAGE_CACHE
#   orphan_count            — entries with page_ref_count == 0 (H1 smoke gun)
#   pmm_alloc_nonzero_rc    — times alloc_page returned a frame with rc > 0
#   refcount_set_over_nonzero — times page_ref_set decreased a non-zero rc
#
# PROCEED-TO-FIX (per PM verdict) iff any of the three counters are non-zero.

def cmd_cache_audit(args):
    """W215 H1 diagnostic: audit page-cache vs refcount table invariants.

    Sends kdb op 'cache-audit' and returns structured JSON with orphan_count,
    pmm_alloc_nonzero_rc, and refcount_set_over_nonzero counters.

    Requires the session to have been started with --features firefox-test,kdb.
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)

    req: dict = {"op": "cache-audit"}
    timeout = float(getattr(args, "timeout", 10.0) or 10.0)
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

    # Annotate with a human-readable verdict for the PM's classification rules.
    orphans    = resp.get("orphan_count", -1)
    pmm_nz     = resp.get("pmm_alloc_nonzero_rc", -1)
    rc_set_ov  = resp.get("refcount_set_over_nonzero", -1)
    if any(v > 0 for v in [orphans, pmm_nz, rc_set_ov] if isinstance(v, int)):
        resp["_verdict"] = "PROCEED-TO-FIX: at least one H1 counter non-zero"
    elif all(v == 0 for v in [orphans, pmm_nz, rc_set_ov] if isinstance(v, int)):
        resp["_verdict"] = "ABORT-OR-NULL: all H1 counters zero"
    else:
        resp["_verdict"] = "UNKNOWN: check for error field"

    _out(resp)


# ══════════════════════════════════════════════════════════════════════════════
# cache-aliasing — W215 H3a diagnostic: writable alias + SHARED+WRITE mmap counters
# ══════════════════════════════════════════════════════════════════════════════
#
# Wraps kdb op 'cache-aliasing' (firefox-test kernel builds only).
# The response carries:
#   pfh_writable_alias_cache           — writable installs that aliased a cache frame
#                                        under a different (mount,inode,offset) key
#   sys_mmap_shared_write_filebacked   — MAP_SHARED|PROT_WRITE mmap calls on file fds
#
# Disambiguation table (per docs/W215_H3_CACHE_HIT_COW_2026-05-16.md §188-196):
#   sys_mmap_shared_write_filebacked > 0   → H3a confirmed (mmap path); check inode in log
#   pfh_writable_alias_cache > 0           → H3a confirmed (PFH path)
#   both == 0 AND W215 still fires         → H3a dead; escalate to H3b (kalloc recycled frame)

def cmd_cache_aliasing(args):
    """W215 H3a diagnostic: writable cache-frame alias + SHARED+WRITE mmap counters.

    Sends kdb op 'cache-aliasing' and returns structured JSON with
    pfh_writable_alias_cache and sys_mmap_shared_write_filebacked counters.

    Requires the session to have been started with --features firefox-test,kdb.
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)

    req: dict = {"op": "cache-aliasing"}
    timeout = float(getattr(args, "timeout", 10.0) or 10.0)
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

    # Annotate with a verdict per the H3a disambiguation table.
    pfh_alias = resp.get("pfh_writable_alias_cache", -1)
    mmap_sw   = resp.get("sys_mmap_shared_write_filebacked", -1)
    if isinstance(pfh_alias, int) and pfh_alias > 0:
        resp["_verdict"] = "PROCEED-TO-FIX (H3a via PFH path): pfh_writable_alias_cache > 0"
    elif isinstance(mmap_sw, int) and mmap_sw > 0:
        resp["_verdict"] = ("PROCEED-TO-FIX (H3a via mmap path): sys_mmap_shared_write_filebacked > 0 "
                            "— check [H3a/mmap] lines in serial log for inode match")
    elif isinstance(pfh_alias, int) and isinstance(mmap_sw, int) and pfh_alias == 0 and mmap_sw == 0:
        resp["_verdict"] = "ABORT-AND-ESCALATE: both H3a counters zero — escalate to H3b"
    else:
        resp["_verdict"] = "UNKNOWN: check for error field"

    _out(resp)


# ══════════════════════════════════════════════════════════════════════════════
# fault-cache-keys — W215 action-(C) diagnostic: 3-bucket cache-key classifier
# ══════════════════════════════════════════════════════════════════════════════
#
# Wraps kdb op 'fault-cache-keys' (firefox-test kernel builds only).
# The response carries three counters, one per exhaustive bucket:
#
#   bucket_a_same_key_inplace      — FAULT/PHYS frame still in cache under
#                                    the correct (mount,inode,page_offset) key.
#                                    Content corrupted in-place by a physmap or
#                                    MAP_SHARED+RW writer.
#
#   bucket_b_cross_key_aliased     — FAULT/PHYS frame in cache under a DIFFERENT
#                                    key.  Cache aliasing between two file pages.
#
#   bucket_c_post_evict_stale_pte  — FAULT/PHYS frame NOT in cache at all.
#                                    PTE outlived the cache entry (stale PTE after
#                                    eviction, no shootdown).
#
# Verdict annotations (per tech-lead cross-walk):
#   A dominates → writer-into-cache-frame instrumentation (physmap or SHARED+RW audit)
#   B dominates → cache::insert/lookup_and_acquire phys-collision audit
#   C dominates → VMA-shootdown-on-evict audit
#   All zero    → INCONCLUSIVE (W215 cluster has not fired yet; re-run)

def cmd_fault_cache_keys(args):
    """W215 action-(C) diagnostic: FAULT/PHYS 3-bucket cache-key classifier.

    Sends kdb op 'fault-cache-keys' and returns structured JSON with three
    counters (bucket_a/b/c) plus a _verdict field annotating the dominant bucket
    and the recommended next dispatch.

    Requires the session to have been started with --features firefox-test,kdb.
    Counters read as zero before any W215-cluster fault fires (idle state is
    'INCONCLUSIVE').
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        sys.exit(1)

    req: dict = {"op": "fault-cache-keys"}
    timeout = float(getattr(args, "timeout", 10.0) or 10.0)
    try:
        raw = _kdb_recv(port, req, timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        _out({"error": f"kdb connect/io failed on 127.0.0.1:{port}: {e}"})
        sys.exit(1)
    try:
        resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError) as e:
        _out({"error": f"malformed kdb response: {e}",
              "raw": raw.decode(errors="replace")})
        sys.exit(1)

    a = resp.get("bucket_a_same_key_inplace", -1)
    b = resp.get("bucket_b_cross_key_aliased", -1)
    c = resp.get("bucket_c_post_evict_stale_pte", -1)

    if not all(isinstance(v, int) for v in [a, b, c]):
        resp["_verdict"] = "UNKNOWN: missing or malformed counter fields — check for error field"
    elif a == 0 and b == 0 and c == 0:
        resp["_verdict"] = (
            "INCONCLUSIVE — W215 cluster has not fired yet; re-run after a fault occurs"
        )
    else:
        dom = max((a, "A"), (b, "B"), (c, "C"), key=lambda t: t[0])
        if dom[1] == "A":
            resp["_verdict"] = (
                f"BUCKET-A dominates (count={a}) — in-place corruption of cache frame "
                "under the same key — next dispatch: writer-into-cache-frame "
                "instrumentation (kernel direct-physmap audit OR same-inode "
                "SHARED+RW user-PTE audit)"
            )
        elif dom[1] == "B":
            resp["_verdict"] = (
                f"BUCKET-B dominates (count={b}) — cross-key cache aliasing — "
                "next dispatch: cache::insert / cache::lookup_and_acquire "
                "phys-collision audit"
            )
        else:
            resp["_verdict"] = (
                f"BUCKET-C dominates (count={c}) — post-evict stale PTE — "
                "next dispatch: VMA-shootdown-on-evict audit"
            )

    _out(resp)


# ══════════════════════════════════════════════════════════════════════════════
# coverage — LLVM source-based coverage collection + reporting
# ══════════════════════════════════════════════════════════════════════════════
#
# Backs `scripts/qemu-harness.py coverage`.  Workflow:
#
#   1. Start a kernel session with `--features coverage,test-mode,kdb` (the
#      `_build` helper injects `-C instrument-coverage` automatically when
#      `coverage` is in the feature set).
#   2. After the test suite emits `[COVERAGE] kernel=...` (or anytime via
#      kdb op `coverage-flush`), run:
#         coverage --collect <sid>
#      The collector tails the session's serial log, reassembles every
#      [COV-CHUNK] line into per-section raw bytes, writes them to
#      ~/.astryx-harness/<sid>.coverage/<section>.bin, and snapshots the
#      [COV-SUMMARY] JSON to ~/.astryx-harness/<sid>.coverage/summary.json.
#   3. `coverage --report` then reads the summary(ies) and emits structured
#      JSON for downstream consumers (CI gate, claudemon, PR comment bot).
#
# Per-PR-friendly summary line (parseable by the future task #315 gate):
#   [COVERAGE] kernel=X.YZ% regions=A/B files=C/D
# Where files=C/D is derived from the static __llvm_covmap dump.  The
# region-level number is the authoritative metric for the gate; the
# files-level number is informational.
#
# The collected raw bytes are NOT a complete .profraw file — they are the
# section payloads.  A host-side post-processor with the matching LLVM
# toolchain version can synthesise the header and run `llvm-profdata
# merge` against them.  That step lives outside this harness for now;
# only the audit's "structured per-region summary" deliverable is
# implemented in-tree to keep the CI gate hook self-contained.

def _coverage_dir(sid: str) -> Path:
    p = HARNESS_DIR / f"{sid}.coverage"
    p.mkdir(parents=True, exist_ok=True)
    return p


def cmd_coverage(args):
    """LLVM source-based coverage collection + reporting.

    With `--collect <sid>` (default): triggers an in-kernel flush via the
    kdb `coverage-flush` op (if the session is kdb-enabled), then scans
    the session's serial log for `[COV-CHUNK]` / `[COV-SUMMARY]` lines
    and writes per-section raw bytes + a summary JSON to
    `~/.astryx-harness/<sid>.coverage/`.

    With `--report` (optionally combined with `--collect`): reads every
    `~/.astryx-harness/*.coverage/summary.json` (or just the one named
    via `--sid`) and emits a unified structured report.
    """
    do_collect = bool(getattr(args, "collect", None))
    do_report  = bool(getattr(args, "report", False))
    if not (do_collect or do_report):
        _out({"error": "coverage: pass --collect <sid> or --report (or both)"})
        sys.exit(2)

    out: dict = {}

    if do_collect:
        sid = args.collect
        sess_path = HARNESS_DIR / f"{sid}.json"
        if not sess_path.exists():
            _out({"error": f"no session {sid} at {sess_path}"})
            sys.exit(1)
        sess = _load_session(sid)

        # Best-effort: trigger an explicit flush via kdb so we never
        # collect a stale snapshot.  Silently skipped on non-kdb builds —
        # the test-runner's pre-exit hook still emits chunks.
        kdb_port = int(sess.get("kdb_host_port") or 0)
        flush_resp = None
        if kdb_port > 0:
            try:
                raw = _kdb_recv(kdb_port, {"op": "coverage-flush"}, timeout=15.0)
                flush_resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
            except (socket.timeout, ConnectionRefusedError, OSError, ValueError):
                flush_resp = {"warning": "kdb coverage-flush failed; using log as-is"}

        # Read the serial log and reassemble chunks per section.
        serial_log = HARNESS_DIR / f"{sid}.serial.log"
        if not serial_log.exists():
            _out({"error": f"no serial log at {serial_log}"})
            sys.exit(1)
        text = serial_log.read_text(errors="replace")

        sections: dict = {}  # name -> list of (offset, hexbytes)
        summary: Optional[dict] = None
        chunk_re = re.compile(
            r"^\[COV-CHUNK\] sec=(?P<sec>[a-z]+) off=(?P<off>\d+) hex=(?P<hex>[0-9a-f]+)\s*$",
            re.MULTILINE,
        )
        for m in chunk_re.finditer(text):
            sec = m.group("sec")
            off = int(m.group("off"))
            hx  = m.group("hex")
            sections.setdefault(sec, []).append((off, hx))
        sum_re = re.compile(r"^\[COV-SUMMARY\] (\{.*\})\s*$", re.MULTILINE)
        sm = list(sum_re.finditer(text))
        if sm:
            # Take the LAST summary — multiple flushes are possible.
            try:
                summary = json.loads(sm[-1].group(1))
            except json.JSONDecodeError:
                summary = None

        cov_dir = _coverage_dir(sid)
        wrote: dict = {}
        for sec, parts in sections.items():
            parts.sort(key=lambda t: t[0])
            buf = bytearray()
            for off, hx in parts:
                # Tolerate gaps by zero-padding; in practice chunks are
                # contiguous from offset 0 because the kernel emits in
                # 256-byte increments.
                if off > len(buf):
                    buf.extend(b"\x00" * (off - len(buf)))
                buf.extend(bytes.fromhex(hx))
            dest = cov_dir / f"{sec}.bin"
            dest.write_bytes(bytes(buf))
            wrote[sec] = {"path": str(dest), "bytes": len(buf)}

        if summary is None:
            summary = {"regions_covered": 0, "regions_total": 0, "pct": "0.00", "bytes_dumped": 0}
        summary_path = cov_dir / "summary.json"
        merged = dict(summary)
        merged["sections"]    = wrote
        merged["serial_log"]  = str(serial_log)
        merged["flush_resp"]  = flush_resp
        summary_path.write_text(json.dumps(merged, indent=2))

        out["collect"] = {
            "sid": sid,
            "summary_path": str(summary_path),
            "sections":     wrote,
            "summary":      summary,
            "flush_resp":   flush_resp,
        }

    if do_report:
        # Pick which summaries to include.
        sid = getattr(args, "sid", None) or getattr(args, "collect", None)
        if sid:
            candidates = [HARNESS_DIR / f"{sid}.coverage" / "summary.json"]
        else:
            candidates = sorted(HARNESS_DIR.glob("*.coverage/summary.json"))

        per_session = []
        agg_covered = 0
        agg_total   = 0
        agg_bytes   = 0
        for path in candidates:
            if not path.exists():
                continue
            try:
                s = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            rc = int(s.get("regions_covered", 0))
            rt = int(s.get("regions_total",   0))
            agg_covered += rc
            agg_total   += rt
            agg_bytes   += int(s.get("bytes_dumped", 0))
            per_session.append({"path": str(path), **s})

        pct_x100 = (agg_covered * 10000 // agg_total) if agg_total else 0
        pct = f"{pct_x100 // 100}.{pct_x100 % 100:02d}"
        # Files-level placeholder — full file-mapping requires parsing
        # the __llvm_covmap section, which is downstream of the
        # collected `.bin` files.  Surface a 0/0 placeholder so the
        # per-PR summary line shape is stable for the CI gate.
        files_total = 0
        files_covered = 0

        # Structured report for programmatic consumers.
        report = {
            "regions_covered": agg_covered,
            "regions_total":   agg_total,
            "pct":             pct,
            "files_covered":   files_covered,
            "files_total":     files_total,
            "bytes_dumped":    agg_bytes,
            "sessions":        per_session,
            # The single line a CI gate / PR comment bot can grep for.
            # Matches the [COVERAGE] format the kernel itself emits so
            # the gate parser can use a single regex against either
            # source of truth.
            "summary_line": (
                f"[COVERAGE] kernel={pct}% "
                f"regions={agg_covered}/{agg_total} "
                f"files={files_covered}/{files_total}"
            ),
        }
        out["report"] = report

    _out(out)


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


# ─── W215 axis-N+1 stack-provenance verdict bucket parser ─────────────────────
#
# Inputs (per session serial log):
#   [STACK-CANARY-WALK]    {PRE|POST} pid=… tid=… frame_idx=N rbp=… \
#                          saved_rbp_at_rbp=… saved_rip_at_rbp+8=… canary_at_rbp-8=…
#   [STACK-CANARY-FINEGRAIN] {pre|post} pid=… tid=… chunk_idx=N crc=… range=…
#   [STACK-PAGE-PROV]      when={pre|post} pid=… tid=… page_va=… page_pa=… \
#                          refcount=N present=B writable=B
#   [VFORK-FS28-WATCH]     state=… fs_base=… fs28_addr=… phys=… linear=…
#   [W215/DR-WATCH-FIRE]   slot=… cpu=… rip=… …  (from the master-canary DR0
#                          watch — names the kernel writer if `fs:0x28` is
#                          stored to during the vfork window).
#
# Verdict buckets (per dispatch's three branches):
#   (a) "pre_existing_zero"      — all chunks identical AND canary_at_rbp-8 == 0
#                                  in BOTH PRE and POST snapshots.  Corruption
#                                  is pre-vfork.  Next dispatch: trace SSP
#                                  prologue writes (DR watchpoint on the slot
#                                  at the moment the prologue stores it).
#   (b) "during_vfork_chunk_delta" — some FINEGRAIN chunk CRC differs pre/post.
#                                  Corruption is during-vfork.  Localised to
#                                  the changed chunk's 256 B band.
#   (c) "page_aliasing"           — for some page_va, page_pa changed across
#                                  the wait (same VA → different physical
#                                  frame) or refcount mismatched.  W215-class
#                                  aliasing on the user-stack VMA.  Dispatch
#                                  aether-kernel-engineer with the failing
#                                  (page_va, refcount-history) tuple.
#   "no_signal"                  — none of the above; the snapshot pair is
#                                  perfectly identical AND no SSP-instrumented
#                                  frame had a zero canary.  Likely the run
#                                  didn't reach the vfork window.
#
# Plus per-trial fields:
#   pre_snapshot_seen / post_snapshot_seen / chunks_pre / chunks_post …

_SPP_WALK_RE = re.compile(
    r"\[STACK-CANARY-WALK\]\s+(?P<label>\S+)\s+pid=(?P<pid>\d+)\s+tid=(?P<tid>\d+)\s+"
    r"frame_idx=(?P<idx>\d+)\s+rbp=(?P<rbp>0x[0-9a-fA-F]+)\s+"
    r"saved_rbp_at_rbp=(?P<srbp>0x[0-9a-fA-F]+)\s+"
    r"saved_rip_at_rbp\+8=(?P<srip>0x[0-9a-fA-F]+)\s+"
    r"canary_at_rbp-8=(?P<canary>\S+)"
)
_SPP_FINE_RE = re.compile(
    r"\[STACK-CANARY-FINEGRAIN\]\s+(?P<label>\S+)\s+pid=(?P<pid>\d+)\s+tid=(?P<tid>\d+)\s+"
    r"chunk_idx=(?P<idx>\d+)\s+crc=(?P<crc>0x[0-9a-fA-F]+)\s+"
    r"range=(?P<lo>0x[0-9a-fA-F]+)\.\.(?P<hi>0x[0-9a-fA-F]+)"
)
_SPP_PAGE_RE = re.compile(
    r"\[STACK-PAGE-PROV\]\s+when=(?P<when>\S+)\s+pid=(?P<pid>\d+)\s+tid=(?P<tid>\d+)\s+"
    r"page_va=(?P<va>0x[0-9a-fA-F]+)\s+page_pa=(?P<pa>\S+)\s+"
    r"refcount=(?P<rc>\d+)\s+present=(?P<pres>\S+)\s+writable=(?P<wr>\S+)"
)
_SPP_WATCH_RE = re.compile(
    r"\[VFORK-FS28-WATCH\]\s+state=(?P<state>\S+)"
)
_SPP_FIRE_RE = re.compile(
    r"\[W215/DR-WATCH-FIRE\]\s+slot=(?P<slot>\d+)\s+fire_idx=\d+\s+cpu=\d+\s+"
    r"rip=(?P<rip>0x[0-9a-fA-F]+)"
)


def _parse_canary_str(s: str):
    """Decode the canary_at_rbp-8 field, which is either a hex literal
    (`0x…`) or a `?` sentinel for unmapped/unreadable slots.  Returns
    `int | None`.  Used to detect zero canaries (verdict bucket (a))."""
    if s == "?" or s.startswith("?"):
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def cmd_stack_prov_summary(args):
    """Parse W215 axis-N+1 stack-provenance lines from the serial log and
    emit a verdict bucket per the tech-lead cross-walk:

      a) "pre_existing_zero"  — saved-`[rbp-8]` was already 0 BEFORE vfork
                                AND no kernel write hit the window;
      b) "during_vfork_chunk_delta" — some 256 B FINEGRAIN chunk CRC
                                differs across the vfork window;
      c) "page_aliasing"      — some user-stack page's `page_pa` changed
                                (or refcount mismatched) across the wait.

    Output (one JSON object):
      {
        "verdict": "a"|"b"|"c"|"no_signal",
        "pre_walk_frames": [{frame_idx, rbp, saved_rbp, saved_rip, canary}, …],
        "post_walk_frames": [...],
        "zero_canary_frames_pre":  [<frame_idx>, …],
        "zero_canary_frames_post": [<frame_idx>, …],
        "finegrain_pre":  {<chunk_idx>: crc, …},
        "finegrain_post": {<chunk_idx>: crc, …},
        "finegrain_changed_chunks": [<chunk_idx>, …],
        "page_prov_pre":  [{page_va, page_pa, refcount, present, writable}, …],
        "page_prov_post": [...],
        "page_prov_pa_swaps":    [{page_va, pa_pre, pa_post}, …],
        "page_prov_rc_mismatch": [{page_va, rc_pre, rc_post}, …],
        "fs28_watch_state":      "armed"|"dr0_busy"|"fs28_unmapped"|null,
        "fs28_watch_fires":      [{slot, rip}, …],
      }
    """
    sess = _load_session(args.sid)
    serial_log = sess["serial_log"]

    pre_walk = []
    post_walk = []
    fine_pre: dict[int, str] = {}
    fine_post: dict[int, str] = {}
    page_pre = []
    page_post = []
    fs28_state = None
    watch_fires = []

    try:
        with Path(serial_log).open("r", errors="replace") as fh:
            for ln in fh:
                m = _SPP_WALK_RE.search(ln)
                if m:
                    rec = {
                        "frame_idx": int(m.group("idx")),
                        "rbp":       m.group("rbp"),
                        "saved_rbp": m.group("srbp"),
                        "saved_rip": m.group("srip"),
                        "canary":    m.group("canary"),
                    }
                    if m.group("label") == "PRE":
                        pre_walk.append(rec)
                    else:
                        post_walk.append(rec)
                    continue
                m = _SPP_FINE_RE.search(ln)
                if m:
                    if m.group("label") == "pre":
                        fine_pre[int(m.group("idx"))] = m.group("crc")
                    else:
                        fine_post[int(m.group("idx"))] = m.group("crc")
                    continue
                m = _SPP_PAGE_RE.search(ln)
                if m:
                    rec = {
                        "page_va":   m.group("va"),
                        "page_pa":   m.group("pa"),
                        "refcount":  int(m.group("rc")),
                        "present":   m.group("pres"),
                        "writable":  m.group("wr"),
                    }
                    if m.group("when") == "pre":
                        page_pre.append(rec)
                    else:
                        page_post.append(rec)
                    continue
                m = _SPP_WATCH_RE.search(ln)
                if m:
                    fs28_state = m.group("state")
                    continue
                m = _SPP_FIRE_RE.search(ln)
                if m:
                    watch_fires.append({
                        "slot": int(m.group("slot")),
                        "rip":  m.group("rip"),
                    })
    except OSError as e:
        _err(f"Cannot read serial log: {e}")

    # FINEGRAIN delta detection.
    changed_chunks = sorted(
        idx for idx in set(fine_pre) | set(fine_post)
        if fine_pre.get(idx) != fine_post.get(idx)
    )

    # PAGE-PROV pa-swap + refcount-mismatch detection (match by page_va).
    pre_by_va  = {p["page_va"]: p for p in page_pre}
    post_by_va = {p["page_va"]: p for p in page_post}
    pa_swaps = []
    rc_mismatches = []
    for va in sorted(set(pre_by_va) & set(post_by_va)):
        a, b = pre_by_va[va], post_by_va[va]
        if a["page_pa"] != b["page_pa"]:
            pa_swaps.append({
                "page_va": va, "pa_pre": a["page_pa"], "pa_post": b["page_pa"],
            })
        if a["refcount"] != b["refcount"]:
            rc_mismatches.append({
                "page_va": va, "rc_pre": a["refcount"], "rc_post": b["refcount"],
            })

    # Zero-canary frame detection (per-pre / per-post).
    def _zero_idxs(frames):
        out = []
        for f in frames:
            v = _parse_canary_str(f["canary"])
            if v == 0:
                out.append(f["frame_idx"])
        return out
    zero_pre  = _zero_idxs(pre_walk)
    zero_post = _zero_idxs(post_walk)

    # Verdict bucket.  Branch (c) takes precedence over (b) which takes
    # precedence over (a) — a pa-swap is the most actionable signal
    # (W215-class kernel bug), a finegrain delta is next (in-window
    # write), pre-existing-zero is last (corruption pre-vfork).
    if pa_swaps or rc_mismatches:
        verdict = "c"
    elif changed_chunks:
        verdict = "b"
    elif (zero_pre and zero_post) or (zero_pre == zero_post and zero_pre):
        verdict = "a"
    else:
        verdict = "no_signal"

    _out({
        "verdict": verdict,
        "pre_walk_frames":  pre_walk,
        "post_walk_frames": post_walk,
        "zero_canary_frames_pre":  zero_pre,
        "zero_canary_frames_post": zero_post,
        "finegrain_pre":  {str(k): v for k, v in sorted(fine_pre.items())},
        "finegrain_post": {str(k): v for k, v in sorted(fine_post.items())},
        "finegrain_changed_chunks": changed_chunks,
        "page_prov_pre":  page_pre,
        "page_prov_post": page_post,
        "page_prov_pa_swaps":    pa_swaps,
        "page_prov_rc_mismatch": rc_mismatches,
        "fs28_watch_state":      fs28_state,
        "fs28_watch_fires":      watch_fires,
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
    {pid, base, end, off, path} ranges.  Multiple LOADs of the same .so by
    the same PID accumulate into one range (lowest base, highest end).  The
    key is (pid, path) — a child process (PID 2+) re-mapping the SAME path
    at a DIFFERENT base does NOT merge with the parent; it produces a
    separate record.  Without this distinction, cross-process load-base
    aggregation would create artificial multi-GiB ranges that swallow every
    RIP between PID 1's and PID 2's base for the same library."""
    by_key = {}
    for ln in lines:
        m = _MMAP_SO.search(ln)
        if not m: continue
        pid  = int(m.group(1))
        base = int(m.group(2), 16)
        leng = int(m.group(3), 16)
        off  = int(m.group(4), 16)
        path = m.group(7)
        end  = base + leng
        key  = (pid, path)
        rec  = by_key.setdefault(key, {
            "pid": pid, "path": path, "base": base, "end": end, "off": off,
        })
        if base < rec["base"]: rec["base"] = base
        if end  > rec["end"]:  rec["end"]  = end
    return list(by_key.values())


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


def cmd_rip_trace_sym(args):
    """Run kdb rip-trace then symbolicate every address in the response.

    Each of top_rips / top_rbp_chains / top_rsp_scan is augmented with a
    `library` (guest path, e.g. /disk/opt/firefox/libxul.so) and a
    `symbol` (nearest exported symbol + offset).  Addresses that don't
    fall inside any [FFTEST/mmap-so]-traced VMA stay as raw hex with
    `library: null` — handy hint that the kernel sampled inside the
    vDSO, anonymous JIT/stack memory, or a library whose load base
    wasn't traced.

    This is the symbolisation companion to `kdb rip-trace`; the latter
    returns bare addresses, the former turns them into readable names.
    Used by the W101 saga-closer to identify the Mozilla event-loop
    function spinning at the post-plateau wedge.
    """
    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"error": "session was not started with --features kdb"})
        return 1

    # ── 1. Issue the kdb rip-trace request directly ─────────────────────
    req = {"op": "rip-trace", "tid": args.tid, "ms": args.ms}
    timeout = float(getattr(args, "timeout", 30.0) or 30.0)
    try:
        raw = _kdb_recv(port, req, timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        _out({"error": f"kdb connect/io failed on 127.0.0.1:{port}: {e}"})
        return 1
    try:
        resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError) as e:
        _out({"error": f"malformed kdb response: {e}",
              "raw": raw.decode(errors="replace")})
        return 1
    if "error" in resp:
        _out(resp); return 1

    # ── 2. Build load-base map from serial log ──────────────────────────
    try:
        log_lines = Path(sess["serial_log"]).read_text(errors="replace").splitlines()
    except OSError as e:
        _out({"error": f"could not read serial log: {e}"})
        return 1
    libs = _build_load_base_map(log_lines)
    # Filter to PID 1 (the target Firefox process) — the cross-process map
    # merges all PIDs' load bases and would have e.g. libXi.so.6 spanning
    # from PID 1's base to PID 2's base (~3 GiB), trapping every RIP in
    # between as "libXi.so.6+0x…".  Use the response's pid to filter.
    target_pid = int(resp.get("pid") or 0)
    if target_pid > 0:
        libs = [L for L in libs if L.get("pid") == target_pid]
    libs.sort(key=lambda L: L["base"])

    # Cache nm -D output per host file (one subprocess per .so).
    sym_cache: dict[str, list[tuple[int, str]]] = {}
    disk_root = getattr(args, "disk_root", None)

    def _sym_for(lib_path: str, offset: int):
        # Lookup nearest exported symbol at or below offset.  Returns
        # f"{symbol}+{delta:#x}" or None.
        if lib_path not in sym_cache:
            host = _resolve_path_on_host(lib_path, disk_root=disk_root)
            if not host or not Path(host).exists():
                sym_cache[lib_path] = []
                return None
            entries: list[tuple[int, str]] = []
            try:
                import subprocess as _sp
                out = _sp.check_output(
                    ["nm", "--defined-only", "-D", "--no-demangle", host],
                    stderr=_sp.DEVNULL, timeout=10,
                ).decode("utf-8", errors="replace")
                for line in out.splitlines():
                    parts = line.split(maxsplit=2)
                    if len(parts) < 3: continue
                    try: addr = int(parts[0], 16)
                    except ValueError: continue
                    if parts[1] not in ("T", "t", "W", "w"): continue
                    entries.append((addr, parts[2]))
                entries.sort(key=lambda e: e[0])
            except (FileNotFoundError, _sp.CalledProcessError, _sp.TimeoutExpired):
                pass
            sym_cache[lib_path] = entries
        entries = sym_cache[lib_path]
        if not entries: return None
        # Binary search for the largest addr <= offset.
        import bisect
        idx = bisect.bisect_right(entries, (offset, "\x7f")) - 1
        if idx < 0: return None
        addr, sym = entries[idx]
        # Demangle on demand (best effort).
        try:
            import subprocess as _sp
            d = _sp.check_output(["c++filt", "--no-strip-underscore"],
                                 input=sym, text=True, timeout=2).strip()
            sym = d if d else sym
        except (FileNotFoundError, _sp.CalledProcessError, _sp.TimeoutExpired):
            pass
        return f"{sym}+{offset - addr:#x}"

    def _resolve(addr_hex: str) -> dict:
        rip = int(addr_hex, 16)
        lib, off = _resolve_frame_to_lib(rip, libs)
        return {
            "addr": addr_hex,
            "library": lib,
            "offset": (f"{off:#x}" if off is not None else None),
            "symbol": (_sym_for(lib, off) if lib is not None else None),
        }

    # ── 3. Decorate every address in the response ───────────────────────
    out_top_rips = []
    for entry in resp.get("top_rips", []):
        d = _resolve(entry["rip"])
        d["count"] = entry["count"]
        d["page"]  = entry.get("page")
        out_top_rips.append(d)

    out_chains = []
    for ch in resp.get("top_rbp_chains", []):
        frames = [_resolve(a) for a in ch.get("chain", [])]
        out_chains.append({
            "chain": frames,
            "count": ch["count"],
        })

    out_rsp_scan = []
    for entry in resp.get("top_rsp_scan", []):
        d = _resolve(entry["addr"])
        d["count"] = entry["count"]
        d["page"]  = entry.get("page")
        out_rsp_scan.append(d)

    result = {
        "tid": resp.get("tid"),
        "pid": resp.get("pid"),
        "ms_requested":  resp.get("ms_requested"),
        "ticks_polled":  resp.get("ticks_polled"),
        "samples":       resp.get("samples"),
        "errors":        resp.get("errors"),
        "load_bases":    [
            {"path": L["path"], "base": f"{L['base']:#x}", "end": f"{L['end']:#x}"}
            for L in libs
        ],
        "top_rips":         out_top_rips,
        "top_rbp_chains":   out_chains,
        "top_rsp_scan":     out_rsp_scan,
    }
    _out(result)
    return 0


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


# ══════════════════════════════════════════════════════════════════════════════
# read-ff-png — extract Firefox's rendered /tmp/out.png from the guest via serial
# ══════════════════════════════════════════════════════════════════════════════
#
# DISTINCT from read-png above.  read-png decodes the [SCREENSHOT-B64:…] stream,
# which carries the QEMU VGA framebuffer (the AstryxOS boot splash in headless
# mode) — NOT Firefox's off-screen render.  Firefox writes its real screenshot
# to the guest path /tmp/out.png; the firefox-test boot reads that file back out
# of the VFS ramdisk and emits it over serial as a SEPARATE marker stream
# (kernel/src/ff_out_png.rs):
#
#   [FF-OUT-PNG:path=/tmp/out.png size=<N> sig_ok=<bool>]
#   [FF-OUT-PNG-B64:0/M] <up to 76 base64 chars>   (N = 0-based chunk index)
#   [FF-OUT-PNG-B64:1/M] ...
#   ...
#   [FF-OUT-PNG-END]
#
# This subcommand:
#   1. Waits for the [FF-OUT-PNG:…] header line (up to --timeout-ms), which
#      carries the guest-side byte size for a cross-check.
#   2. Scans the serial log for all M chunks (0..M-1) in order.
#   3. Decodes the concatenated base64 (RFC 4648 §4) and writes to <dst>.
#   4. Verifies the PNG signature (8-byte magic, W3C PNG §5.2 / ISO 15948),
#      and that the decoded byte count matches the guest-reported size.
#   5. Prints JSON: {"ok": true, "path": dst, "bytes": N, "chunks": M,
#                    "guest_size": G, "size_match": bool}
#      or {"ok": false, "error": "...", ...} on failure.
#
# Fully additive — does not touch read-png or its [SCREENSHOT-B64] regexes.

_FFPNG_HEADER_RE = re.compile(
    r"\[FF-OUT-PNG:path=(\S+)\s+size=(\d+)\s+sig_ok=(true|false)"
)
_FFPNG_CHUNK_RE = re.compile(
    r"\[FF-OUT-PNG-B64:(\d+)/(\d+)\]\s+([A-Za-z0-9+/=]+)"
)
_FFPNG_END_RE = re.compile(r"\[FF-OUT-PNG-END\]")


def cmd_read_ff_png(args):
    """
    Collect base64-encoded /tmp/out.png chunks from the [FF-OUT-PNG-B64:…]
    serial stream and write to <dst>.

    Waits for the [FF-OUT-PNG:…] header line, scans for all M chunks, decodes,
    verifies the PNG signature, cross-checks the guest-reported size, and writes
    to args.dst.  Distinct from read-png (which decodes the VGA framebuffer
    stream).
    """
    import base64

    sess       = _load_session(args.sid)
    serial_log = sess["serial_log"]
    dst        = args.dst
    timeout_ms = args.timeout_ms

    # ── 1. Wait for the [FF-OUT-PNG:…] header line ────────────────────────────
    deadline = time.monotonic() + timeout_ms / 1000.0
    guest_size: Optional[int] = None
    guest_sig_ok: Optional[bool] = None

    while time.monotonic() < deadline:
        try:
            with open(serial_log, "r", errors="replace") as fh:
                for ln in fh:
                    m = _FFPNG_HEADER_RE.search(ln)
                    if m:
                        guest_size   = int(m.group(2))
                        guest_sig_ok = (m.group(3) == "true")
        except OSError:
            time.sleep(0.1)
            continue

        if guest_size is not None:
            break

        # If QEMU has already exited, do one final scan then give up.
        pid = sess.get("pid", 0)
        if pid and not _pid_alive(pid):
            try:
                with open(serial_log, "r", errors="replace") as fh:
                    for ln in fh:
                        m = _FFPNG_HEADER_RE.search(ln)
                        if m:
                            guest_size   = int(m.group(2))
                            guest_sig_ok = (m.group(3) == "true")
            except OSError:
                pass
            break

        time.sleep(0.1)

    if guest_size is None:
        _err(f"read-ff-png: timed out waiting for [FF-OUT-PNG:…] header "
             f"(waited {timeout_ms} ms). Did firefox-test reach [FFTEST] DONE "
             f"and did Firefox write /tmp/out.png?")

    if guest_size == 0:
        _out({
            "ok":         False,
            "error":      "guest_out_png_empty",
            "guest_size": guest_size,
            "guest_sig_ok": guest_sig_ok,
            "hint":       "Firefox did not write a non-empty /tmp/out.png "
                          "(reached png-write gate but produced 0 bytes).",
        })
        sys.exit(1)

    # ── 2. Collect all chunks ─────────────────────────────────────────────────
    # M is announced per chunk line (idx/M); we collect until we have a complete
    # 0..M-1 set or the collect deadline elapses.  The PNG is ~30-80 KB → up to
    # ~1400 lines; at 115200 baud that is ~10 s.  Give a 30 s collect window.
    chunks: dict[int, str] = {}
    total_chunks: Optional[int] = None
    collect_deadline = time.monotonic() + 30.0

    def _scan_chunks():
        nonlocal total_chunks
        try:
            with open(serial_log, "r", errors="replace") as fh:
                for ln in fh:
                    m = _FFPNG_CHUNK_RE.search(ln)
                    if m:
                        idx = int(m.group(1))
                        tot = int(m.group(2))
                        b64 = m.group(3)
                        if total_chunks is None:
                            total_chunks = tot
                        if tot == total_chunks and idx < tot:
                            chunks[idx] = b64
        except OSError:
            pass

    while time.monotonic() < collect_deadline:
        _scan_chunks()
        if total_chunks is not None and len(chunks) >= total_chunks:
            break
        pid = sess.get("pid", 0)
        if pid and not _pid_alive(pid):
            # QEMU exited; one final scan then stop.
            _scan_chunks()
            break
        time.sleep(0.2)

    if total_chunks is None:
        _out({
            "ok":         False,
            "error":      "no_ffpng_chunks",
            "guest_size": guest_size,
            "hint":       "Saw the [FF-OUT-PNG:…] header but no "
                          "[FF-OUT-PNG-B64:…] data lines.",
        })
        sys.exit(1)

    # ── 3. Validate chunk count ───────────────────────────────────────────────
    missing = [i for i in range(total_chunks) if i not in chunks]
    if missing:
        _out({
            "ok":         False,
            "error":      "missing_chunks",
            "total":      total_chunks,
            "received":   len(chunks),
            "missing":    missing[:20],
            "guest_size": guest_size,
        })
        sys.exit(1)

    # ── 4. Decode base64 ──────────────────────────────────────────────────────
    b64_concat = "".join(chunks[i] for i in range(total_chunks))
    try:
        png_bytes = base64.b64decode(b64_concat, validate=True)
    except Exception as exc:
        _out({
            "ok":     False,
            "error":  f"base64_decode_failed: {exc}",
            "chunks": total_chunks,
        })
        sys.exit(1)

    # ── 5. Verify PNG signature + size cross-check ────────────────────────────
    if len(png_bytes) < 8 or png_bytes[:8] != _PNG_SIGNATURE:
        got = png_bytes[:8].hex() if len(png_bytes) >= 8 else png_bytes.hex()
        _out({
            "ok":       False,
            "error":    "png_signature_mismatch",
            "got":      got,
            "expected": _PNG_SIGNATURE.hex(),
            "chunks":   total_chunks,
            "bytes":    len(png_bytes),
            "guest_size": guest_size,
        })
        sys.exit(1)

    size_match = (len(png_bytes) == guest_size)

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
        "ok":           True,
        "path":         str(dst_path.resolve()),
        "bytes":        len(png_bytes),
        "chunks":       total_chunks,
        "guest_size":   guest_size,
        "size_match":   size_match,
        "guest_sig_ok": guest_sig_ok,
    })


# ══════════════════════════════════════════════════════════════════════════════
# kdb-read-png — pull a guest VFS file (e.g. /tmp/out.png) via the kdb read-file
# op, regardless of the firefox-test boot's own detect-and-emit serial path.
# ══════════════════════════════════════════════════════════════════════════════
#
# Robust live extraction: the kdb `read-file` op (kernel/src/kdb.rs) reads a VFS
# file slice and returns it base64 (RFC 4648 §4).  This wrapper loops the op
# with increasing offset until eof, concatenates, decodes, verifies the PNG
# signature (W3C PNG §5.2 / ISO 15948), and writes to <dst>.  Unlike read-ff-png
# (which decodes the [FF-OUT-PNG-B64] serial stream emitted at FF-exit), this
# works against a LIVE session the instant the file exists on the guest — even
# while Firefox is still a draining zombie and the serial emit has not fired.
# Requires the session started with --features kdb.

def cmd_kdb_read_png(args):
    import base64

    sess = _load_session(args.sid)
    port = int(sess.get("kdb_host_port") or 0)
    if port <= 0:
        _out({"ok": False, "error": "session was not started with --features kdb"})
        sys.exit(1)

    path       = args.path
    dst        = args.dst
    timeout    = float(getattr(args, "timeout", 10.0) or 10.0)
    max_chunks = 4096  # generous ceiling; a 16 KiB chunk × 4096 = 64 MiB cap

    chunks: list[bytes] = []
    offset = 0
    file_size: Optional[int] = None
    sig_png: Optional[bool] = None

    for _ in range(max_chunks):
        req = {"op": "read-file", "path": path, "offset": offset, "len": 16384}
        try:
            raw = _kdb_recv(port, req, timeout=timeout)
            resp = json.loads(raw.strip().decode("utf-8", errors="replace"))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            _out({"ok": False, "error": f"kdb io failed on 127.0.0.1:{port}: {e}",
                  "offset": offset})
            sys.exit(1)
        except (json.JSONDecodeError, ValueError) as e:
            _out({"ok": False, "error": f"malformed kdb response: {e}",
                  "offset": offset, "raw": raw.decode(errors="replace")[:200]})
            sys.exit(1)

        if "error" in resp:
            _out({"ok": False, "error": f"kdb read-file: {resp['error']}",
                  "path": path, "offset": offset})
            sys.exit(1)

        if file_size is None:
            file_size = int(resp.get("file_size", 0))
            sig_png = bool(resp.get("sig_png", False))
            if file_size == 0:
                _out({"ok": False, "error": "guest_file_empty", "path": path})
                sys.exit(1)

        b64 = resp.get("b64", "")
        try:
            chunks.append(base64.b64decode(b64, validate=True))
        except Exception as e:
            _out({"ok": False, "error": f"base64_decode_failed: {e}",
                  "offset": offset})
            sys.exit(1)

        n = int(resp.get("n", 0))
        offset += n
        if bool(resp.get("eof", False)) or n == 0:
            break

    data = b"".join(chunks)

    sig = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    is_png = len(data) >= 8 and data[:8] == sig
    size_match = (file_size is not None and len(data) == file_size)

    dst_path = Path(dst)
    try:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        dst_path.write_bytes(data)
    except OSError as exc:
        _out({"ok": False, "error": f"write_failed: {exc}", "path": dst})
        sys.exit(1)

    _out({
        "ok":          is_png and size_match,
        "path":        str(dst_path.resolve()),
        "bytes":       len(data),
        "guest_size":  file_size,
        "size_match":  size_match,
        "is_png":      is_png,
        "guest_sig_png": sig_png,
        "via":         "kdb-read-file",
    })


# ══════════════════════════════════════════════════════════════════════════════
# screendump — capture the QEMU framebuffer via QMP and write a PNG
# ══════════════════════════════════════════════════════════════════════════════
#
# Uses QEMU's `screendump` QMP command (returns PPM at a server-side path).
# Convert PPM (P6, ASCII header + binary RGB) to PNG using only the Python
# stdlib (struct + zlib) — no PIL/netpbm dependency.
#
# QMP screendump payload (see qemu/docs/interop/qmp-spec.txt and the
# `screendump` command at https://www.qemu.org/docs/master/interop/qemu-qmp-
# ref.html):
#
#   { "execute": "screendump", "arguments": { "filename": "<host-path>" } }
#
# The resulting PPM is a P6 file: ASCII header `P6\n<W> <H>\n<MAXVAL>\n`,
# then W*H pixels of 3 bytes each (R, G, B). PNG output follows W3C PNG §5.

def _ppm_to_png_bytes(ppm: bytes) -> bytes:
    """
    Convert a P6 PPM image to PNG bytes.  Pure stdlib; uses zlib for IDAT
    deflate (W3C PNG §11.2.4) and struct for chunk framing (§5).
    """
    import struct
    import zlib

    if not ppm.startswith(b"P6"):
        raise ValueError(f"not a P6 PPM (got magic {ppm[:2]!r})")

    # Parse ASCII header: P6\n<W> <H>\n<MAXVAL>\n  (comments with # allowed)
    pos = 2
    tokens: list[bytes] = []
    while len(tokens) < 3:
        # skip whitespace + comments
        while pos < len(ppm) and ppm[pos:pos+1] in (b" ", b"\t", b"\n", b"\r"):
            pos += 1
        if pos < len(ppm) and ppm[pos:pos+1] == b"#":
            while pos < len(ppm) and ppm[pos:pos+1] != b"\n":
                pos += 1
            continue
        start = pos
        while pos < len(ppm) and ppm[pos:pos+1] not in (b" ", b"\t", b"\n", b"\r"):
            pos += 1
        if start == pos:
            raise ValueError("PPM header truncated")
        tokens.append(ppm[start:pos])
    # one whitespace byte after MAXVAL per PPM spec
    if pos < len(ppm) and ppm[pos:pos+1] in (b" ", b"\t", b"\n", b"\r"):
        pos += 1
    w = int(tokens[0]); h = int(tokens[1]); maxval = int(tokens[2])
    if maxval != 255:
        raise ValueError(f"PPM maxval={maxval} unsupported (only 255)")
    pixels = ppm[pos:pos + w * h * 3]
    if len(pixels) != w * h * 3:
        raise ValueError(
            f"PPM pixel count mismatch: header says {w}x{h}*3={w*h*3}, "
            f"got {len(pixels)} bytes")

    # Build PNG: signature + IHDR + IDAT + IEND (W3C PNG §11.2).
    sig = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    # IHDR: width(4), height(4), bitdepth(1), colortype(1=2 RGB),
    # compression(1=0), filter(1=0), interlace(1=0)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)

    # Raw image data: each scanline prefixed with filter type 0 (None).
    raw = bytearray()
    stride = w * 3
    for y in range(h):
        raw.append(0)
        raw.extend(pixels[y*stride:(y+1)*stride])
    idat = zlib.compress(bytes(raw), level=6)

    return sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def cmd_screendump(args):
    """
    Capture the QEMU framebuffer via QMP `screendump` and write a PNG to <dst>.

    Requires the session to have been started with a VGA card (xeyes-test
    feature auto-injects `-vga vmware`; gui-test / firefox-test enable it
    via astryx_qemu._display_args).  Returns JSON describing the capture.
    """
    import tempfile

    sess     = _load_session(args.sid)
    qmp_sock = sess["qmp_sock"]
    dst      = args.dst

    # QMP writes the PPM at a server-visible path.  Use a host temp file —
    # QEMU shares the host's filesystem (no isolation).
    with tempfile.NamedTemporaryFile(suffix=".ppm", delete=False) as tmp:
        ppm_path = tmp.name
    try:
        resp = _qmp_command(qmp_sock, "screendump", {"filename": ppm_path})
        if "error" in resp:
            _out({"ok": False, "error": "qmp_error",
                  "qmp_response": resp})
            sys.exit(1)
        # screendump may return before the file is fully flushed on some QEMU
        # builds; poll briefly for non-zero size to avoid a torn read.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                if Path(ppm_path).stat().st_size > 0:
                    break
            except OSError:
                pass
            time.sleep(0.05)
        ppm_bytes = Path(ppm_path).read_bytes()
        if not ppm_bytes:
            _out({"ok": False, "error": "ppm_empty",
                  "hint": "VGA card not attached?  xeyes-test injects "
                          "-vga vmware; check the session's -vga args."})
            sys.exit(1)
        try:
            png_bytes = _ppm_to_png_bytes(ppm_bytes)
        except Exception as exc:
            _out({"ok": False, "error": f"ppm_to_png_failed: {exc}",
                  "ppm_bytes": len(ppm_bytes)})
            sys.exit(1)
        dst_path = Path(dst)
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        dst_path.write_bytes(png_bytes)
        _out({
            "ok":         True,
            "path":       str(dst_path.resolve()),
            "png_bytes":  len(png_bytes),
            "ppm_bytes":  len(ppm_bytes),
        })
    finally:
        try:
            Path(ppm_path).unlink()
        except OSError:
            pass


# ── Argument parsing ──────────────────────────────────────────────────────────

def main():
    # ── Early-exit forwarding for delegate subcommands ───────────────────────
    # `argparse.REMAINDER` is famously broken when the first remaining token
    # starts with `-` — it tries to interpret it as an unknown parent-parser
    # flag.  For pure-forwarding subcommands (strace-ref, differential-soak,
    # context) the cleanest workaround is to detect them at argv[1] and
    # shell out directly, before argparse even runs.
    _DELEGATE_SCRIPTS = {
        "differential-soak": "differential-soak.py",
        # Note: strace-ref and context still flow through argparse because
        # they're always invoked with a positional subcommand first, which
        # REMAINDER handles correctly.
    }
    if len(sys.argv) >= 2 and sys.argv[1] in _DELEGATE_SCRIPTS:
        if "--help" in sys.argv[2:3] or "-h" in sys.argv[2:3]:
            # Let argparse render `qemu-harness differential-soak --help`
            # for discoverability — only intercept real invocations.
            pass
        else:
            import subprocess as _sp
            helper = Path(__file__).parent / _DELEGATE_SCRIPTS[sys.argv[1]]
            if not helper.exists():
                _out({"ok": False,
                      "error": f"delegate script missing: {helper}"})
                sys.exit(1)
            cmd = [sys.executable, str(helper)] + list(sys.argv[2:])
            sys.exit(_sp.run(cmd).returncode)

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
                               "Nothing is injected silently.  Special case: "
                               "'coverage' (test-coverage audit session 5) "
                               "additionally injects -C instrument-coverage "
                               "into RUSTFLAGS so LLVM emits the __llvm_prf_* "
                               "and __llvm_cov* sections; the test runner's "
                               "pre-exit hook then dumps them as [COV-CHUNK] "
                               "serial lines for `coverage --collect`.")
    p_start.add_argument("--trace", action="store_true", dest="ff_trace",
                          help="Diagnostic-serial profile: append "
                               "'firefox-test-trace' to the feature list when it "
                               "contains 'firefox-test-core' (or 'firefox-test'). "
                               "This turns ON the high-frequency per-syscall/"
                               "per-poll/per-resolve serial emitters ([FF/stderr], "
                               "[POLL_RET], [VFS/resolve], [FUTEX_*]) for a "
                               "debugging boot.  WITHOUT --trace, a "
                               "'firefox-test-core' boot is the FAST perf/render "
                               "profile (<2 MB serial vs ~45 MB).  The expansion "
                               "is printed to stderr, never silent.")
    p_start.add_argument("--no-build", action="store_true",
                          help="Skip cargo build; use existing kernel.bin")
    p_start.add_argument("--build-only", action="store_true", dest="build_only",
                          help="Build the kernel for --features then exit (no "
                               "QEMU boot). Stages the in-tree ESP so a later "
                               "`start --no-build` reuses this exact binary. "
                               "Lets a host run the (CPU-bound) compile while a "
                               "concurrent KVM boot is in flight, then boot in a "
                               "quiet window — keeps cycle-accurate perf timing "
                               "free of host-core contention.")
    p_start.add_argument("--snapshottable", action="store_true",
                          dest="snapshottable",
                          help="snap-gate: launch with the QEMU savevm/loadvm-"
                               "compatible device topology so the live guest "
                               "can be snapshotted. Makes the vvfat boot disk "
                               "read-only (fat:ro:) and the OVMF_VARS pflash "
                               "read-only (both block savevm otherwise), and "
                               "attaches a dedicated orphan qcow2 vmstate "
                               "device + a persistent qcow2 data overlay (under "
                               "~/.astryx-harness/snapshots/) backed read-only "
                               "by the shared data.img. Required for the "
                               "`snap-gate save/load` subcommands. Default OFF "
                               "— existing harness usage is byte-for-byte "
                               "unaffected.")
    p_start.add_argument("--gdb-port", type=int, default=0, metavar="PORT",
                          help="Enable GDB stub on TCP PORT (0=off). "
                               "GdbClient will back off to PORT+1..PORT+4 on conflict.")
    p_start.add_argument("--http-host-port", dest="http_host_port", type=int,
                          default=0, metavar="PORT",
                          help="When --features includes 'httpd-test' (PIVOT-C, "
                               "2026-05-23), forward host TCP PORT to guest "
                               "10.0.2.15:8080 via SLIRP hostfwd so a host "
                               "`curl http://127.0.0.1:PORT/` reaches the "
                               "in-kernel HTTP responder. 0 = derive "
                               "deterministically from sid in 8800..9799.")
    p_start.add_argument("--ssh-host-port", dest="ssh_host_port", type=int,
                          default=0, metavar="PORT",
                          help="When --features includes 'sshd-test' (PIVOT-D, "
                               "2026-05-23), forward host TCP PORT to guest "
                               "10.0.2.15:22 via SLIRP hostfwd so a host "
                               "`ssh -p PORT root@127.0.0.1` reaches the "
                               "guest dropbear daemon.  0 = derive "
                               "deterministically from sid in 2200..2299.")
    p_start.add_argument("--oracle-stub-conflux", dest="oracle_stub_conflux",
                          type=int, default=0, metavar="PORT",
                          help="When --features includes 'oracle-daemon-test' "
                               "(PIVOT-I2 Phase D, 2026-05-23), launch the "
                               "host-side `scripts/oracle-stub-conflux.py` "
                               "responder on 127.0.0.1:PORT before QEMU boots "
                               "and tear it down on `stop`. Guest oracle "
                               "reaches it via the QEMU SLIRP gateway alias at "
                               "http://10.0.2.2:PORT/heartbeat (matches the "
                               "kernel-side run_oracle_daemon() default URL). "
                               "Heartbeat JSON is appended to "
                               "~/.astryx-harness/<sid>.oracle-stub.jsonl. "
                               "0 = do not auto-launch (operator can run the "
                               "stub by hand at any port).  Pass 8088 to match "
                               "the kernel-side default URL.")
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
    p_start.add_argument("--extra-arg", dest="extra_qemu_args", action="append",
                          default=None, metavar="ARG",
                          help="Repeatable: append a verbatim argv token to the "
                               "QEMU command line. For multi-token flags like "
                               "'-overcommit cpu-pm=off', pass --extra-arg twice: "
                               "--extra-arg -overcommit --extra-arg cpu-pm=off. "
                               "Used by CPU-model sweeps to vary VMEXIT surface "
                               "knobs that are not covered by --cpu.")
    p_start.add_argument("--no-regen-data-img", action="store_true",
                          dest="no_regen_data_img",
                          help="Skip the auto-regen of build/data.img when "
                               "build/disk/ has files newer than the image "
                               "(W7 silent-wedge guard). The staleness banner "
                               "still prints to stderr so the situation is "
                               "never hidden. Use when reproducing a bug that "
                               "depends on the existing data.img contents.")
    p_start.add_argument("--data-img", dest="data_img_override", default=None,
                          metavar="PATH",
                          help="Boot against an explicit prebuilt data image "
                               "(e.g. /home/ubuntu/gui-complete.img) by "
                               "repointing the worktree build/data.img symlink. "
                               "Implies --no-regen-data-img (a prebuilt complete "
                               "image is authoritative and must not be "
                               "regenerated). Additive; absent => unchanged.")
    p_start.add_argument("--firefox-variant", dest="firefox_variant",
                          choices=("musl", "glibc"), default="musl",
                          help="Pin which Firefox userspace layout the data "
                               "disk must carry: 'musl' (Alpine packages at "
                               "/usr/lib/firefox*) or 'glibc' (Mozilla tarball "
                               "at /opt/firefox).  Default 'musl' — the "
                               "primary demo target.  When the staged tree "
                               "doesn't match, the harness re-runs "
                               "scripts/create-data-disk.sh with "
                               "ASTRYXOS_FIREFOX_VARIANT exported so the boot "
                               "image carries the requested binaries.  After "
                               "boot the kernel's [FFTEST] FF binary probe "
                               "line is parsed and a `firefox_variant_probe` "
                               "event records the actual selection (read it "
                               "via `events <sid>` or `status <sid>`). "
                               "Suppress the auto-restage with "
                               "--no-regen-data-img — the mismatch is still "
                               "warned about on stderr.")
    # Livelock auto-reap (default ON).  A spinning FF render boot (pid 1
    # busy-looping while the deepest gate is frozen) drives the pid=1 syscall
    # counter into the hundreds-of-millions/billions at ~100% host CPU with no
    # forward progress; the watcher auto-stops it so it stops pinning a core
    # and skewing concurrent timing boots.
    p_start.add_argument("--livelock-reap-sc", dest="livelock_reap_sc",
                          type=int, default=LIVELOCK_REAP_SC_DEFAULT,
                          metavar="N",
                          help="Auto-reap a boot once its pid=1 syscall count "
                               f"churns by > N (default {LIVELOCK_REAP_SC_DEFAULT:_}) "
                               "WHILE the deepest FF gate stays frozen for longer "
                               "than --livelock-reap-secs. Set to 0 to disable.")
    p_start.add_argument("--livelock-reap-secs", dest="livelock_reap_secs",
                          type=float, default=LIVELOCK_REAP_SECS_DEFAULT,
                          metavar="SECS",
                          help="Wall-clock window (default "
                               f"{int(LIVELOCK_REAP_SECS_DEFAULT)}s) of zero "
                               "deepest-gate progress that — combined with "
                               "--livelock-reap-sc syscall churn — declares a "
                               "livelock. Set to 0 to disable.")
    p_start.add_argument("--no-livelock-reap", dest="no_livelock_reap",
                          action="store_true",
                          help="Disable the livelock auto-reap guard for this "
                               "session entirely. Use for a debugging/autopsy "
                               "hold you WANT to keep spinning for inspection.")
    p_start.add_argument("--ff-url", dest="ff_url", default=None, metavar="URL",
                          help="firefox-test target URL delivered to the kernel "
                               "at boot WITHOUT a rebuild.  The harness appends "
                               "`-fw_cfg name=opt/astryx/cmdline,"
                               "string=astryx.ff_url=<URL>` so the kernel's "
                               "firefox-test launch path (boot_config.rs) reads "
                               "and substitutes it into the Firefox command "
                               "line, falling back to the compiled default when "
                               "absent.  The scheme must be http/https/file "
                               "(RFC 3986 3.1) and the value is validated "
                               "kernel-side; an invalid value is ignored.  "
                               "Example: --ff-url file:///tmp/hello.html for a "
                               "fast local-render win, or --ff-url "
                               "https://bbc.com/news.  Additive: omit to keep "
                               "the compiled CMDLINE_* default.")
    p_start.add_argument("--ff-gui", action="store_true", dest="ff_gui",
                          help="Run Firefox in X11/GUI (windowed) mode instead "
                               "of headless.  The harness appends "
                               "`astryx.ff_gui=1` to the SAME opt/astryx/cmdline "
                               "fw_cfg blob (combined with --ff-url), and the "
                               "kernel (boot_config::ff_gui_mode) drops "
                               "`--headless`/`--screenshot` from the Firefox "
                               "command line and omits MOZ_HEADLESS so libxul "
                               "calls XOpenDisplay() and paints into a real "
                               "window on the in-kernel Xastryx server "
                               "(DISPLAY=:0).  Capture the composited desktop "
                               "with `screendump <sid> <out.png>`.  No rebuild "
                               "needed (same firefox-test-core build serves "
                               "both modes).")
    p_start.add_argument("--pcap", action="store_true", dest="pcap",
                          help="FORCE host-side packet capture ON for this "
                               "boot, even a non-FF one.  Captures ALL guest "
                               "network traffic on the e1000/SLIRP netdev "
                               "(net0) to a libpcap file at "
                               "~/.astryx-harness/<sid>.pcap via a HOST-SIDE "
                               "QEMU `-object filter-dump`.  Capture already "
                               "DEFAULTS ON for Firefox-render boots (features "
                               "firefox-test / firefox-test-core / "
                               "firefox-test-trace) — this flag is only needed "
                               "to force it on a non-FF boot.  The tap lives on "
                               "the host side — the guest is unaware, so there "
                               "are ZERO guest VM-exits and negligible guest "
                               "perf cost (only host disk writes bounded by "
                               "traffic volume, a few MB for a page load).  "
                               "Unlike the serial firehose (per-byte PIO "
                               "VM-exits), this is free on the guest path.  The "
                               "pcap opens in Wireshark; serial-web serves it "
                               "at /api/pcap?sid=<sid> and a decoded wire "
                               "summary at /api/wire?sid=<sid>.")
    p_start.add_argument("--no-pcap", action="store_true", dest="no_pcap",
                          help="Disable host-side packet capture for this boot "
                               "even when it would otherwise default ON (an "
                               "FF-render boot).  Use for a clean perf-timing "
                               "run where even the per-frame host fwrite is "
                               "unwanted.  Wins over both the FF-default and an "
                               "explicit --pcap.")

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

    # snap-gate: live VM snapshot/restore that actually preserves a running
    # Firefox process across save/load (requires `start --snapshottable`).
    p_snapgate = sub.add_parser(
        "snap-gate",
        help="Live VM snapshot/restore preserving the running guest. "
             "Forms: `snap-gate <sid> save <name>`, `snap-gate load <name>`, "
             "`snap-gate list`. Requires `start --snapshottable`. Collapses a "
             "30-50min FF-boot-to-gate into a sub-second loadvm.")
    # Free-form positionals resolved in cmd_snap_gate so the three argv forms
    # above all parse without ambiguity:
    #   save: <sid> save <name>   (3 tokens)
    #   load: load <name>         (2 tokens; no sid — a NEW session is spawned)
    #   list: list                (1 token)
    p_snapgate.add_argument("rest", nargs="*",
                            help="See the forms in --help.")

    # ── Tier 2: GDB stub subcommands ──────────────────────────────────────────
    # All require that `start` was called with --gdb-port PORT.

    # regs
    p_regs = sub.add_parser("regs", help="[Tier2] Read x86_64 registers via GDB stub")
    p_regs.add_argument("sid")

    # dual-regs — read RIP/CS/RSP for EVERY vCPU + symbolize (SMP deadlock autopsy)
    p_dual_regs = sub.add_parser(
        "dual-regs",
        help="[Tier2] Read RIP/CS/RSP/RBP for every vCPU and symbolize the kernel RIP")
    p_dual_regs.add_argument("sid")

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

    # watch — hardware write watchpoint; names the out-of-band writer
    p_watch = sub.add_parser(
        "watch",
        help="[Tier2] Arm a HW write watchpoint on a VA, resume, and capture "
             "the exact store that writes it (writer RIP + kernel/user mode "
             "+ register context). Names out-of-band stack-slot writers.")
    p_watch.add_argument("sid")
    p_watch.add_argument("addr", help="Guest VA to watch (hex or decimal)")
    p_watch.add_argument("--length", type=int, default=8,
                          help="Watch width in bytes (default 8)")
    p_watch.add_argument("--kind", choices=["write", "read", "access"],
                          default="write", help="Watchpoint kind (default write)")
    p_watch.add_argument("--skip", type=int, default=0,
                          help="Let the first N fires pass before reporting "
                               "(e.g. skip the legitimate argv-build store)")
    p_watch.add_argument("--break", dest="brk", default=None,
                          help="Break at this symbol/addr FIRST (so the watch "
                               "is armed only after the stack is mapped)")
    p_watch.add_argument("--timeout-ms", type=int, default=120000,
                          help="Overall budget for catching the writer")

    # pause
    p_pause = sub.add_parser("pause", help="[Tier2] Pause QEMU via QMP stop")
    p_pause.add_argument("sid")

    # resume
    p_resume = sub.add_parser("resume", help="[Tier2] Resume QEMU via QMP cont")
    p_resume.add_argument("sid")

    # autopsy — GDB breakpoint + structured capture wrapper
    p_autopsy = sub.add_parser(
        "autopsy",
        help="[Tier2] GDB-autopsy: arm breakpoint(s), wait for hit, "
             "capture structured snapshot driven by a preset. "
             "Required first probe before any new printk-style ring buffer.",
    )
    p_autopsy.add_argument("sid")
    p_autopsy.add_argument(
        "--break", dest="brk", action="append", required=True, metavar="TARGET",
        help="Breakpoint target. Accepts hex address (0xffff...), "
             "decimal address, kernel symbol name (e.g. ke_bugcheck), "
             "or symbol+offset (e.g. ke_bugcheck+0x10). May be "
             "repeated to arm multiple sites simultaneously.",
    )
    p_autopsy.add_argument(
        "--capture", required=True, metavar="PRESET",
        help="Preset name from scripts/autopsy/presets.yaml. Examples: "
             "full-register-dump, stack-walk-bt-full, ssp-fail-snapshot, "
             "vfork-window, gp-fault-context, bugcheck-entry. Run with "
             "an unknown preset to see the available list.",
    )
    p_autopsy.add_argument(
        "--once", dest="once_n", type=int, default=1, metavar="N",
        help="Cap the number of hits captured (default 1). Use higher "
             "values together with --continue-after to record repeated "
             "fires of the same breakpoint.",
    )
    p_autopsy.add_argument(
        "--continue-after", action="store_true", dest="continue_after",
        help="After capturing a hit, resume the guest and wait for the "
             "next one (up to --once N). Default: stop after the first hit.",
    )
    p_autopsy.add_argument(
        "--timeout-ms", type=int, default=60000, metavar="MS",
        help="Total wall-clock budget across all hits (default 60000 ms). "
             "On timeout the captured hits so far are returned with "
             "timed_out=true — never silent.",
    )
    p_autopsy.add_argument(
        "--max-bytes-per-step", type=int, default=512, metavar="N",
        help="Cap per-memory-window read size (default 512, max 4096) to "
             "protect agent context length.",
    )
    p_autopsy.add_argument(
        "--match-reg", dest="match_reg", action="append", default=None,
        metavar="NAME=HEXVAL",
        help="Filter hits: only capture a breakpoint fire when register "
             "NAME == HEXVAL (e.g. --match-reg rdi=0xd0). May be repeated "
             "(AND semantics). Non-matching fires are silently resumed and "
             "do NOT count against --once N. Requires the guest to keep "
             "hitting the breakpoint; combine with a generous --timeout-ms. "
             "Use this to isolate one fault (e.g. a specific CR2) on a "
             "high-frequency handler like handle_page_fault, whose 1st arg "
             "rdi==faulting_addr and 2nd arg rsi==error_code per SysV ABI.",
    )
    p_autopsy.add_argument(
        "--hw-break", dest="hw_break", action="store_true",
        help="Use a HARDWARE execution breakpoint (x86 DR0-DR3 via the Z1 "
             "RSP packet) instead of a software INT3 patch (Z0). Required "
             "under KVM for kernel .text symbols where the INT3 patch is "
             "silently dropped (stub acks OK but the guest never traps). "
             "Limited to 4 simultaneous breakpoints (the debug-register "
             "count).",
    )
    p_autopsy.add_argument(
        "--match-scan-max", dest="match_scan_max", type=int, default=200000,
        metavar="N",
        help="With --match-reg, cap the number of non-matching fires "
             "scanned before giving up (default 200000). Protects against "
             "an infinite stream of benign faults.",
    )
    p_autopsy.add_argument(
        "--leave-paused", action="store_true",
        help="On exit, leave the guest paused (so a follow-up `step`/`mem` "
             "session can pick up state). Default: resume the guest.",
    )
    p_autopsy.add_argument(
        "--output", default=None, metavar="PATH",
        help="Optional: also write the structured JSON to PATH "
             "(in addition to stdout) for archival in a doc / commit message.",
    )

    # kdb — Tier 1 kernel debugger JSON socket
    p_kdb = sub.add_parser(
        "kdb",
        help="[Tier1] One-shot JSON request against the in-kernel debugger "
             "(requires --features kdb at start)")
    p_kdb.add_argument("sid")
    p_kdb.add_argument("op", choices=[
        "ping", "proc-list", "proc", "proc-tree", "fd-table", "fd-map",
        "syscall-trend", "vfs-mounts",
        "dmesg", "syms", "mem", "read-file", "tframe", "user-mem", "trace-status",
        "bell-stats", "cache-audit", "cache-aliasing", "fault-cache-keys",
        "w215-cache-residency", "tlb-stats", "heap-stats", "w215-diag",
        "arm-phys",
        # blk-trace: drain the virtio-blk LBA ring (JSON) / re-emit `[BLK]`
        # serial lines for the heatmap. Also exposed as the `blk-trace`
        # top-level subcommand below (drain|flush).
        "blk-trace", "blk-trace-flush",
        "coverage-flush", "proc-metrics", "thread-park-audit",
        "rip-trace",
        "futex-ghost-hist",
        # One-shot musl pthread_cond/mutex wake-target-vs-wait-addr report:
        # struct dump + parked waiters + recent wakes + holder + verdict.
        # See subsys/linux/futex_cluster.rs::recent_wakes_near + op_cond_autopsy.
        "cond-autopsy",
        # Terse file-backed VMA map; one entry per VMA with first_page_phys.
        "procmaps",
        # FUTEX_WAKE cluster-wake compensation (firefox-test/test-mode only).
        # See subsys/linux/futex_cluster.rs.
        "futex-stats", "futex-set-cluster-wake",
        # INFRA-3 record/replay introspection (record-replay feature).
        # `record-status` returns seed + virtual ticks + ordinal; safe to
        # query under any build (returns enabled:false when the feature
        # is off).  `replay-dump path=<abs>` writes the in-RAM record
        # log to a VFS file; takes one `path=...` arg.  See
        # docs/RECORD_REPLAY_2026-05-23.md.
        "record-status", "replay-dump",
        # net-ipver: read or toggle runtime IPv4/IPv6 address-family flags.
        # See net::ipver + op_net_ipver.  Also exposed as the `net-ipver`
        # top-level subcommand below.
        "net-ipver",
        # virtio-blk wait-amplification telemetry + runtime A/B controls.
        # `virtio-wait-hist` drains the per-round-trip wait histogram (µs
        # buckets × mean run-queue depth, median/p99); `virtio-wait-mode
        # block|yield` flips the wait strategy on a live build (no rebuild);
        # `virtio-wait-spin <n>` tunes the adaptive-spin budget;
        # `virtio-wait-reset` zeroes the ring for a clean A/B window.
        # See drivers::virtio_blk + op_virtio_wait_*.
        "virtio-wait-hist", "virtio-wait-mode", "virtio-wait-spin",
        "virtio-wait-reset",
    ])
    p_kdb.add_argument("args", nargs="*",
                        help="Op-specific positional args: "
                             "proc <pid>, proc-tree [<root_pid>] (def 1), "
                             "fd-table <pid>, "
                             "fd-map [<pid>] (0 or omit = all processes), "
                             "syscall-trend [<seconds> [<pid>]] (def 5 0), "
                             "dmesg [tail], syms <name|0xaddr>, "
                             "mem <addr> <len>, "
                             "rip-trace <tid> [<ms>] (def ms=1000), "
                             "cond-autopsy <pid> <cond_va> [<half>] (def half=128)")
    p_kdb.add_argument("--timeout", type=float, default=30.0,
                        help="Overall deadline in seconds (default 30.0). "
                             "Wraps retry/backoff for BSP starvation tolerance.")

    # blk-trace — out-of-band drain of the virtio-blk LBA trace ring.
    # Replaces the old per-op `[BLK]` COM1 write (a KVM VM-exit storm) with a
    # lock-free ring drained on demand. Requires --features ...,kdb,blk-trace.
    p_blktrace = sub.add_parser(
        "blk-trace",
        help="[Tier1] Drain the virtio-blk LBA trace ring. "
             "`drain` -> live ring as JSON; `flush` -> re-emit classic `[BLK]` "
             "serial lines for the data.img heatmap. "
             "Requires --features ...,kdb,blk-trace at start.")
    p_blktrace.add_argument(
        "blk_action", choices=["drain", "flush"],
        help="drain: dump ring as JSON (events:[{op,lba,len,pid}...]). "
             "flush: emit `[BLK]` serial lines on demand (heatmap compat).")
    p_blktrace.add_argument("sid")
    p_blktrace.add_argument("--timeout", type=float, default=30.0,
                             help="kdb overall deadline (default 30.0s).")

    # log-ring — out-of-band drain of the near-zero-overhead guest-RAM log ring.
    # The cheap high-volume log transport: the firehose trace families
    # (serial_fast_println!, e.g. the `[SC]` syscall trace) write to a lock-free
    # ring in guest RAM with ZERO VM-exits instead of the per-byte COM1 16550
    # PIO path. `drain` serialises the ring over the kdb channel (no UART cost);
    # `flush` re-emits the buffered lines to COM1 for serial-log consumers;
    # `enable on|off` toggles the slow COM1 fallback for an A/B measurement.
    # Requires --features ...,kdb at start.
    p_logring = sub.add_parser(
        "log-ring",
        help="[Tier1] Drain the guest-RAM log ring (cheap high-volume log "
             "transport). `drain` -> live ring as JSON {text, counters}; "
             "`flush` -> re-emit buffered lines to COM1 (serial-log compat); "
             "`enable on|off` -> toggle the slow COM1 fallback. "
             "Requires --features ...,kdb at start.")
    p_logring.add_argument(
        "log_action", choices=["drain", "flush", "enable"],
        help="drain: dump ring as JSON. flush: emit lines to COM1 on demand. "
             "enable: set the fast-path ring sink on/off (A/B control).")
    p_logring.add_argument("sid")
    p_logring.add_argument("state", nargs="?", choices=["on", "off"],
                           help="for `enable`: on|off (omit to query).")
    p_logring.add_argument("--out-file", default=None,
                           help="for `drain`: write the recovered log text to "
                                "this file (raw bytes) in addition to JSON.")
    p_logring.add_argument("--timeout", type=float, default=30.0,
                           help="kdb overall deadline (default 30.0s).")

    # tlb-stats — dedicated top-level subcommand for W215 H2 TLB diagnostic
    p_tlb_stats = sub.add_parser(
        "tlb-stats",
        help="[Tier1] TLB shootdown + PMM recent-free H2 diagnostic snapshot "
             "(requires --features kdb+firefox-test at start).")
    p_tlb_stats.add_argument("sid")
    p_tlb_stats.add_argument("--timeout", type=float, default=30.0,
                              help="kdb overall deadline (default 30.0s); retried internally.")

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
    p_fdmap.add_argument("--timeout", type=float, default=30.0,
                          help="kdb overall deadline (default 30.0s); retried internally.")

    # thread-park-audit — PNG-1 plateau characterisation
    p_tpa = sub.add_parser(
        "thread-park-audit",
        help="[PNG-1] Per-thread wait-object classifier (futex/poll-bell/"
             "fd-blocked/sleep/vfork-complete/unknown). Cross-references "
             "FUTEX_WAITERS, per-TID last-syscall sample, and FD tables. "
             "Requires --features firefox-test,kdb.")
    p_tpa.add_argument("sid")
    p_tpa.add_argument("--pid", type=lambda x: int(x, 0), default=0,
                        help="Filter to one PID (0 or omit = all processes)")
    p_tpa.add_argument("--save", metavar="NAME", default=None,
                        help="Save snapshot to "
                             "~/.astryx-harness/<sid>.thread-park.<NAME>.json")
    p_tpa.add_argument("--diff", metavar="NAME", default=None,
                        help="Diff current snapshot against a previously --save'd NAME; "
                             "emits added/removed/kind_changed for fast triage")
    p_tpa.add_argument("--timeout", type=float, default=30.0,
                        help="kdb overall deadline (default 30.0s); retried internally.")

    # futex-wake-drill — PNG-2 TID-2 FUTEX_WAKE pattern classifier
    p_fwd = sub.add_parser(
        "futex-wake-drill",
        help="[PNG-2] TID-2 FUTEX_WAKE drill: classify post-W215 plateau as "
             "H1 STATIC deadlock vs H2 CHURNING overhead via Jaccard "
             "similarity of per-bucket wake-uaddr sets. Parses "
             "[FUTEX_WAKE]/[FUTEX_WAKE_REQ] from serial log; needs "
             "--features firefox-test at start. With --cross-park, joins "
             "against live FUTEX_WAITERS via thread-park-audit.")
    p_fwd.add_argument("sid")
    p_fwd.add_argument("--tid", type=int, default=2,
                        help="TID filter (default 2 = Mozilla parent main)")
    p_fwd.add_argument("--bucket-count", type=int, default=2,
                        dest="bucket_count",
                        help="Number of temporal buckets (default 2)")
    p_fwd.add_argument("--window-lines", type=int, default=0,
                        dest="window_lines",
                        help="Restrict to most-recent N serial-log lines "
                             "(0 = whole log; default 0)")
    p_fwd.add_argument("--cross-park", action="store_true",
                        dest="cross_park",
                        help="Cross-reference live FUTEX_WAITERS via kdb "
                             "thread-park-audit (requires --features kdb)")
    p_fwd.add_argument("--timeout", type=float, default=30.0,
                        help="kdb cross-park deadline (default 30s)")

    # cache-audit — W215 H1 diagnostic: walk the page cache checking for
    # zero-refcount entries.  Requires --features firefox-test,kdb at start.
    p_cacheaudit = sub.add_parser(
        "cache-audit",
        help="[W215 diag] Audit page-cache refcount invariants via kdb op "
             "cache-audit (requires --features firefox-test,kdb). Reports "
             "total_entries, orphan_count (rc=0 entries), and the cumulative "
             "PMM_ALLOC_NONZERO_RC and REFCOUNT_SET_OVER_NONZERO counters.")
    p_cacheaudit.add_argument("sid")
    p_cacheaudit.add_argument("--timeout", type=float, default=30.0,
                               help="kdb overall deadline (default 30.0s); retried internally.")

    # cache-aliasing — W215 H3a diagnostic: writable cache-frame alias + filebacked SHARED+WRITE mmap
    p_cache_aliasing = sub.add_parser(
        "cache-aliasing",
        help="[W215 H3a diag] Dump PFH_WRITABLE_ALIAS_CACHE and "
             "SYS_MMAP_SHARED_WRITE_FILEBACKED counters "
             "(requires --features firefox-test,kdb). "
             "Non-zero pfh_writable_alias_cache or sys_mmap_shared_write_filebacked "
             "confirms H3a (MAP_SHARED+PROT_WRITE file-backed mapping aliases cache frame).")
    p_cache_aliasing.add_argument("sid")
    p_cache_aliasing.add_argument("--timeout", type=float, default=30.0,
                                   help="kdb overall deadline (default 30.0s); retried internally.")

    # fault-cache-keys — W215 action-(C) diagnostic: 3-bucket cache-key classifier
    p_fault_cache_keys = sub.add_parser(
        "fault-cache-keys",
        help="[W215 action-(C) diag] Dump FAULT/PHYS 3-bucket cache-key classifier: "
             "bucket_a (same-key in-place corruption), bucket_b (cross-key aliased), "
             "bucket_c (post-evict stale PTE).  Reads as zero before any W215-cluster "
             "fault fires.  Requires --features firefox-test,kdb.")
    p_fault_cache_keys.add_argument("sid")
    p_fault_cache_keys.add_argument("--timeout", type=float, default=30.0,
                                    help="kdb overall deadline (default 30.0s); retried internally.")

    # coverage — LLVM source-based coverage collection + reporting.
    # Requires the session was started with --features coverage,test-mode
    # (and ideally kdb, for the on-demand flush op).  See _build()'s
    # CARGO_ENCODED_RUSTFLAGS hook that pairs the feature flag with
    # -C instrument-coverage so LLVM actually emits the section payloads.
    p_cov = sub.add_parser(
        "coverage",
        help="LLVM source-based coverage: --collect <sid> reassembles the "
             "in-kernel [COV-CHUNK] dump from a session's serial log into "
             "per-section binary blobs + summary.json; --report aggregates "
             "previously collected summaries and emits a CI-gate-friendly "
             "[COVERAGE] kernel=X% regions=Y/Z files=A/B line.  Hooks for "
             "task #315 (CI coverage gate) are left in the report shape.")
    p_cov.add_argument("--collect", metavar="SID", default=None,
                        help="Session id whose serial log to scan and whose "
                             "kdb endpoint to flush before collection.")
    p_cov.add_argument("--report", action="store_true",
                        help="Aggregate every ~/.astryx-harness/*.coverage/"
                             "summary.json (or just --sid's) and emit a "
                             "unified structured report.")
    p_cov.add_argument("--sid", default=None,
                        help="When --report is passed without --collect, "
                             "limit the aggregation to this one session id.")

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

    # ff-progress — structured FF gate-ladder + deepest-reached detector.
    p_ffprog = sub.add_parser(
        "ff-progress",
        help="[Tier0] FF headless-screenshot gate ladder + deepest gate "
             "reached (pure serial-log scan; no kdb). Ladder is read from "
             "scripts/ff_gates.yaml (additive). Reports lib-load -> x11-ready "
             "-> compositor-init -> ff-launch -> content-proc -> "
             "screenshot-actors -> draw-snapshot -> png-write, plus max_sc "
             "and terminal_cause.")
    p_ffprog.add_argument("sid")

    # health — active circle / spin / stall detector (see HEALTH_CLASSES).
    p_health = sub.add_parser(
        "health",
        help="[Tier0] Classify a boot's liveness from serial+ps (+opportunistic "
             "kdb): HEALTHY / SLOW-ALIVE / SPINNING / STALLED / "
             "WEDGED-PRE-BUGCHECK / DEAD-BUGCHECKED. Takes two samples a few "
             "seconds apart for the rate signals. `--all` sweeps every live "
             "session; add `--reap-circles` to stop() (and LOG) the wedged "
             "ones (SPINNING/STALLED/WEDGED-PRE-BUGCHECK/DEAD). HEALTHY and "
             "SLOW-ALIVE are never reaped.")
    p_health.add_argument("sid", nargs="?", default=None,
                          help="session id (omit with --all)")
    p_health.add_argument("--all", action="store_true",
                          help="classify every live session in the harness dir")
    p_health.add_argument("--reap-circles", dest="reap_circles",
                          action="store_true",
                          help="with --all: stop() and log SPINNING/STALLED/"
                               "WEDGED-PRE-BUGCHECK/DEAD sessions")
    p_health.add_argument("--gap", type=float, default=_HEALTH_SAMPLE_GAP_S,
                          help="seconds between the two rate samples "
                               f"(default {_HEALTH_SAMPLE_GAP_S})")

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

    # rip-trace-resolve — kdb rip-trace + host-side .symtab resolution.
    # The combined subcommand eliminates the manual two-step (rip-trace then
    # addr2line) for W101-class userspace plateau investigations.
    p_rtr = sub.add_parser(
        "rip-trace-resolve",
        help="[W101] kdb rip-trace + host-side .symtab resolution. "
             "Samples TID <tid> for <ms> ms, then resolves every top-RIP "
             "entry against the host-side libxul.so .symtab (requires "
             "--features kdb at start and a .symtab-bearing libxul.so in "
             "build/disk/opt/firefox/ — see scripts/inject-libxul-symtab.py)."
    )
    p_rtr.add_argument("sid")
    p_rtr.add_argument("tid", help="TID to sample (e.g. 2)")
    p_rtr.add_argument("ms", nargs="?", default="1000",
                       help="Sampling window in milliseconds (default 1000)")
    p_rtr.add_argument("--disk-root", default=None, metavar="DIR",
                       help="Disk staging root for .so symbol lookup "
                            "(default: ./build/disk)")
    p_rtr.add_argument("--timeout", type=float, default=None,
                       help="kdb deadline in seconds (default: ms/1000 + 10)")

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

    # rip-trace-sym — symbolicated wrapper around kdb rip-trace.  Runs the
    # in-kernel sampler, then resolves every RIP / chain-frame / RSP-scan
    # candidate against [FFTEST/mmap-so]-derived load bases and per-library
    # nm exports.  This is the saga-closer companion for the W101 demo
    # wedge: rip-trace alone reports addresses; rip-trace-sym names the
    # function.
    p_rt_sym = sub.add_parser(
        "rip-trace-sym",
        help="[Tier1] Symbolicated rip-trace: run kdb rip-trace then map "
             "every RIP, RBP-chain frame, and RSP-scan candidate to "
             "<library>:<symbol+offset> via [FFTEST/mmap-so] + nm.",
    )
    p_rt_sym.add_argument("sid")
    p_rt_sym.add_argument("tid", type=lambda x: int(x, 0),
                          help="Target TID (must be in PID 1's tree)")
    p_rt_sym.add_argument("--ms", type=int, default=2000,
                          help="Sampling window in ms (default 2000, max 5000)")
    p_rt_sym.add_argument("--disk-root", default=None, metavar="DIR",
                          help="Disk staging root for userspace .so symbol lookup")
    p_rt_sym.add_argument("--timeout", type=float, default=30.0,
                          help="kdb overall deadline in seconds (default 30.0)")

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

    # stack-prov-summary — parse W215 axis-N+1 stack-provenance lines
    # and emit a verdict bucket (a/b/c/no_signal).  Pairs with the
    # `vfork-canary-diag` kernel build (vfork_diag.rs).
    p_spp = sub.add_parser(
        "stack-prov-summary",
        help="Parse [STACK-CANARY-WALK], [STACK-CANARY-FINEGRAIN], "
             "[STACK-PAGE-PROV], [VFORK-FS28-WATCH], and "
             "[W215/DR-WATCH-FIRE] lines from the serial log; emit "
             "a per-trial verdict bucket (a=pre_existing_zero, "
             "b=during_vfork_chunk_delta, c=page_aliasing).  "
             "Requires --features vfork-canary-diag at start."
    )
    p_spp.add_argument("sid")

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

    # read-ff-png — extract Firefox's rendered /tmp/out.png (DISTINCT stream)
    p_read_ff_png = sub.add_parser(
        "read-ff-png",
        help="Collect Firefox's rendered /tmp/out.png from the "
             "[FF-OUT-PNG-B64:N/M] serial stream (firefox-test boot emits it "
             "after [FFTEST] DONE) and write to <dst.png>.  DISTINCT from "
             "read-png, which decodes the VGA framebuffer ([SCREENSHOT-B64]) — "
             "the boot splash, not Firefox's render.  Verifies the PNG "
             "signature and cross-checks the guest-reported byte size.  "
             "Example: read-ff-png <sid> /tmp/firefox-out.png"
    )
    p_read_ff_png.add_argument("sid")
    p_read_ff_png.add_argument("dst", help="Host-side destination path for the PNG file")
    p_read_ff_png.add_argument(
        "--timeout-ms", type=int, default=120000, dest="timeout_ms",
        help="Milliseconds to wait for the [FF-OUT-PNG:…] header line "
             "(default 120000 = 2 min)"
    )

    # kdb-read-png — pull a guest VFS file live via the kdb read-file op
    p_kdb_read_png = sub.add_parser(
        "kdb-read-png",
        help="Pull a guest VFS file (default /tmp/out.png) to <dst.png> via the "
             "kdb read-file op (chunked base64).  Works on a LIVE session the "
             "instant the file exists — independent of the firefox-test boot's "
             "own serial emit.  Requires --features kdb.  "
             "Example: kdb-read-png <sid> /tmp/firefox-out.png"
    )
    p_kdb_read_png.add_argument("sid")
    p_kdb_read_png.add_argument("dst", help="Host-side destination path for the PNG file")
    p_kdb_read_png.add_argument(
        "--path", default="/tmp/out.png",
        help="Guest VFS path to read (default /tmp/out.png)"
    )
    p_kdb_read_png.add_argument(
        "--timeout", type=float, default=10.0,
        help="Per-chunk kdb request timeout in seconds (default 10)"
    )

    # net-ipver — convenience wrapper over the kdb `net-ipver` op.  Read or
    # toggle the runtime IPv4/IPv6 address-family enable flags (net::ipver).
    p_net_ipver = sub.add_parser(
        "net-ipver",
        help="Read or toggle the runtime IPv4/IPv6 address-family flags "
             "(requires --features kdb).  No args = report state.  "
             "Examples: net-ipver <sid>  |  net-ipver <sid> 6 off  |  "
             "net-ipver <sid> 4 on"
    )
    p_net_ipver.add_argument("sid")
    p_net_ipver.add_argument(
        "family", nargs="?", choices=["4", "6"], default=None,
        help="Address family to toggle (4 or 6).  Omit to just read state.")
    p_net_ipver.add_argument(
        "state", nargs="?", default=None,
        help="on|off — required when a family is given.")
    p_net_ipver.add_argument(
        "--timeout", type=float, default=10.0,
        help="kdb request timeout in seconds (default 10)")

    # screendump — capture the framebuffer via QMP screendump + PPM->PNG
    p_screendump = sub.add_parser(
        "screendump",
        help="Capture the QEMU framebuffer via QMP `screendump` and convert "
             "the resulting PPM to PNG.  Requires the session to have a VGA "
             "card (xeyes-test auto-injects -vga vmware; gui-test/firefox-test "
             "always do).  Example: screendump <sid> /tmp/xeyes.png"
    )
    p_screendump.add_argument("sid")
    p_screendump.add_argument("dst", help="Host-side destination path for the PNG")

    # ci-run: one-shot build+boot+test+report for CI.  Replaces the banned
    # watch-test.py wrapper.  All filtering (--allow-fail) is applied here
    # rather than at the CI YAML level, keeping the logic in one place.
    p_ci = sub.add_parser(
        "ci-run",
        help="Build, boot, run the full test suite, and report pass/fail "
             "(CI replacement for the banned watch-test.py wrapper). "
             "Exits 0 on pass or when all failures match --allow-fail.",
    )
    p_ci.add_argument("--features", default="test-mode", metavar="FLAGS",
                      help="Kernel feature flags (default: test-mode)")
    p_ci.add_argument("--no-build", action="store_true", dest="no_build",
                      help="Skip cargo build; use existing kernel.bin")
    p_ci.add_argument("--timeout-ms", type=int, default=900000,
                      dest="timeout_ms",
                      help="Total budget in ms for suite to complete "
                           "(default 900000 = 15 min)")
    p_ci.add_argument("--allow-fail", default="", metavar="REGEX",
                      dest="allow_fail",
                      help="Regex of test names to tolerate failing. "
                           "Matched failures are reported but do not set "
                           "exit code 1. Example: 'Musl hello|pie_elf'")
    p_ci.add_argument("--no-kvm", dest="no_kvm", action="store_true",
                      help="Disable KVM (GitHub runners have no /dev/kvm)")

    # allowlist — manage ci/allow-fail.json (structured CI expected-fail list)
    p_al = sub.add_parser(
        "allowlist",
        help="Manage ci/allow-fail.json (the structured CI expected-fail "
             "registry). Render to regex, add/remove entries, audit a serial "
             "log for drift. Replaces hand-edited regex in workflow files.",
    )
    p_al.add_argument("--file", default=None,
                       help="Override allowlist path (default: ci/allow-fail.json)")
    al_sub = p_al.add_subparsers(dest="alsub", required=True)
    al_sub.add_parser("list", help="Print all entries as JSON")
    al_sub.add_parser("regex", help="Render entries → alternation regex on stdout")
    p_al_add = al_sub.add_parser("add", help="Append a new entry")
    p_al_add.add_argument("--name", required=True,
                          help="Test name (or regex if --regex)")
    p_al_add.add_argument("--reason", default="",
                          help="Short reason for tolerating the failure")
    p_al_add.add_argument("--tracking", default=None,
                          help="Issue or PR reference (e.g. #41)")
    p_al_add.add_argument("--regex", dest="regex_flag", action="store_true",
                          help="Treat --name as a regex, not a literal substring")
    p_al_rm = al_sub.add_parser("remove", help="Remove the first matching entry")
    p_al_rm.add_argument("--name", required=True,
                         help="Test name to remove (exact match against 'name' field)")
    p_al_chk = al_sub.add_parser(
        "check",
        help="Audit a serial log: which [FAIL] lines are/aren't covered, "
             "and which allowlist entries did NOT match anything (drift).",
    )
    p_al_chk.add_argument("--serial-log", dest="serial_log", required=True,
                          help="Path to a serial log to scan")

    # soak — run N trials of ci-run and aggregate results (flake report)
    p_soak = sub.add_parser(
        "soak",
        help="Run ci-run N times, aggregate pass/fail counts, detect "
             "flaky tests (pass in some trials and fail in others). "
             "Builds the kernel once up front; trials reuse the build.",
    )
    p_soak.add_argument("--trials", type=int, default=3,
                         help="Number of ci-run trials to execute (default: 3)")
    p_soak.add_argument("--features", default="test-mode", metavar="FLAGS",
                         help="Kernel feature flags (default: test-mode)")
    p_soak.add_argument("--no-build", action="store_true", dest="no_build",
                         help="Skip the up-front build; reuse existing kernel.bin")
    p_soak.add_argument("--timeout-ms", type=int, default=900000,
                         dest="timeout_ms",
                         help="Per-trial budget in ms (default 900000 = 15 min)")
    p_soak.add_argument("--allow-fail", default="", metavar="REGEX",
                         dest="allow_fail",
                         help="Explicit allow-fail regex (overrides --use-allowlist)")
    p_soak.add_argument("--use-allowlist", action="store_true",
                         dest="use_allowlist",
                         help="Render ci/allow-fail.json into the allow-fail regex")
    p_soak.add_argument("--file", default=None,
                         help="Override allowlist path (used with --use-allowlist)")
    p_soak.add_argument("--no-kvm", dest="no_kvm", action="store_true",
                         help="Disable KVM (GitHub runners have no /dev/kvm)")

    # check: run `cargo check` against a feature-flag combination without
    # spinning up QEMU.  Used by hotfix verification sweeps that need to
    # confirm a regression is closed across N feature combos before
    # committing to a full boot.
    p_check = sub.add_parser("check",
                              help="Run `cargo +nightly check` for given --features")
    p_check.add_argument("--features", default="", metavar="FLAGS",
                          help="Feature flags passed VERBATIM to cargo. "
                               "Empty string → default desktop kernel.")

    p_build = sub.add_parser("build",
                              help="Run the REAL kernel build (codegen+link+ESP "
                                   "stage) for given --features and report "
                                   "build_ms. No boot. Use for the BUILD-phase "
                                   "perf measurement (not `check`).")
    p_build.add_argument("--features", default="", metavar="FLAGS",
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

    # differential-soak — end-to-end Linux↔AstryxOS bytestream diff (INFRA-1)
    p_diff = sub.add_parser(
        "differential-soak",
        help="End-to-end differential bytestream harness: run firefox-bin "
             "under both the host Linux kernel (bwrap + strace) and "
             "AstryxOS QEMU; align the two syscall streams; report the "
             "FIRST divergence with structured JSON.  Snapshot trigger "
             "points configurable via scripts/differential/snapshots.yaml.  "
             "All arguments forwarded to scripts/differential-soak.py.",
    )
    p_diff.add_argument(
        "differential_args", nargs=argparse.REMAINDER,
        help="Arguments forwarded to differential-soak.py "
             "(see --help on that script for the full list)",
    )

    # strace-ref — Linux reference strace captures (delegates to strace-ref.py)
    p_sref = sub.add_parser(
        "strace-ref",
        help="Linux reference strace captures for ABI conformance.  Runs the "
             "same musl firefox-esr binary under the host Linux kernel inside "
             "bwrap; captures strace, diffs against AstryxOS serial logs.  "
             "Subcommands: setup | capture | diff | list | clean.  All "
             "arguments are forwarded verbatim to scripts/strace-ref.py.",
    )
    p_sref.add_argument(
        "strace_ref_args", nargs=argparse.REMAINDER,
        help="Subcommand + arguments forwarded to strace-ref.py",
    )

    # _watch: private subcommand used internally by `start` to run the
    # background watcher in a detached process. Not shown in help.
    p_watch = sub.add_parser("_watch")
    p_watch.add_argument("sid")

    # _ff_variant_verify: private subcommand used internally by `start` to
    # tail the serial log for the kernel's [FFTEST] FF binary probe line
    # and record the actual variant selection.  Not shown in help.
    p_ffv = sub.add_parser("_ff_variant_verify")
    p_ffv.add_argument("sid")

    args = parser.parse_args()

    dispatch = {
        "ci-run":    cmd_ci_run,
        "allowlist": cmd_allowlist,
        "soak":      cmd_soak,
        "check":     cmd_check,
        "build":     cmd_build,
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
        "snap-gate": cmd_snap_gate,
        # Tier 2
        "regs":   cmd_regs,
        "dual-regs": cmd_dual_regs,
        "mem":    cmd_mem,
        "sym":    cmd_sym,
        "bp":     cmd_bp,
        "step":   cmd_step,
        "cont":   cmd_cont,
        "watch":  cmd_watch,
        "pause":  cmd_pause,
        "resume": cmd_resume,
        "autopsy": cmd_autopsy,
        # Tier 1
        "kdb":         cmd_kdb,
        "blk-trace":   cmd_blk_trace,
        "log-ring":    cmd_log_ring,
        "net-ipver":   cmd_net_ipver,
        "tlb-stats":   cmd_tlb_stats,
        "fd-map":      cmd_fd_map,
        "thread-park-audit": cmd_thread_park_audit,
        "futex-wake-drill":  cmd_futex_wake_drill,
        "cache-audit":       cmd_cache_audit,
        "cache-aliasing":    cmd_cache_aliasing,
        "fault-cache-keys":  cmd_fault_cache_keys,
        "coverage":          cmd_coverage,
        # QGA bridge
        "qga-ping":      cmd_qga_ping,
        "qga-info":      cmd_qga_info,
        "qga-sync":      cmd_qga_sync,
        "qga-file-read": cmd_qga_file_read,
        # Housekeeping / reporting
        "prune":   cmd_prune,
        "results": cmd_results,
        "ff-progress": cmd_ff_progress,
        "health":      cmd_health,
        "scrings": cmd_scrings,
        "stack":   cmd_stack,
        "ustack":  cmd_ustack,
        "parked-tids": cmd_parked_tids,
        "parked-stacks": cmd_parked_stacks,
        "wake-attempts": cmd_wake_attempts,
        "sc-histogram": cmd_sc_histogram,
        "stack-prov-summary": cmd_stack_prov_summary,
        "rip-sample": cmd_rip_sample,
        "rip-trace-sym": cmd_rip_trace_sym,
        "qmp-regs": cmd_qmp_regs,
        "qmp-xv":   cmd_qmp_xv,
        "qmp-xp":   cmd_qmp_xp,
        "rip-walk": cmd_rip_walk,
        "rip-trace-resolve": cmd_rip_trace_resolve,
        "read-png": cmd_read_png,
        "read-ff-png": cmd_read_ff_png,
        "kdb-read-png": cmd_kdb_read_png,
        "screendump": cmd_screendump,
        # Shared session context
        "context": cmd_context,
        # Linux reference strace (ABI conformance)
        "strace-ref": cmd_strace_ref,
        # INFRA-1 differential bytestream harness (end-to-end)
        "differential-soak": cmd_differential_soak,
        "_watch":  cmd_run_watcher,
        "_ff_variant_verify": cmd_ff_variant_verify,
    }
    rc = dispatch[args.cmd](args)
    if isinstance(rc, int) and rc != 0:
        sys.exit(rc)


if __name__ == "__main__":
    main()
