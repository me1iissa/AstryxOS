#!/usr/bin/env python3
"""
QEMU Watchdog — Fast hang detection for AstryxOS test runs.

Monitors QEMU serial output for test progress, detects hangs within 15-30 seconds
(vs the old 1200s bash timeout), and optionally auto-captures GDB backtraces.

Dual-mode: Human CLI (default) or MCP server (--mcp) for AI agent integration.

Usage (human):
    python3 tools/qemu-watchdog.py                           # build + run + watch
    python3 tools/qemu-watchdog.py --no-build                # skip build
    python3 tools/qemu-watchdog.py --gdb-on-hang             # auto-GDB on hang
    python3 tools/qemu-watchdog.py --monitor --pid PID --log FILE  # attach to existing QEMU

Usage (AI via MCP):
    python3 tools/qemu-watchdog.py --mcp                     # start MCP server

Exit codes:
    0 = all tests passed
    1 = tests failed
    2 = hang detected
    3 = hard timeout
    4 = kernel crash / QEMU crash
    5 = build failure
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from collections import deque
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

ROOT_DIR = Path(__file__).resolve().parent.parent
SERIAL_LOG = ROOT_DIR / "build" / "test-serial.log"
KERNEL_ELF = ROOT_DIR / "target" / "x86_64-astryx" / "release" / "astryx-kernel"

# Serial output patterns
RE_TEST_HEADER = re.compile(r"^\s*TEST:\s*(.+)$", re.MULTILINE)
RE_PASS = re.compile(r"^\[PASS\] (.+)$")
RE_FAIL = re.compile(r"^\[FAIL\] (.+)$")
RE_RESULT = re.compile(r"Test Results:\s*(\d+)/(\d+)\s+passed")
RE_SUITE_PASS = re.compile(r"\[TEST SUITE\].*ALL TESTS PASSED")
RE_SUITE_FAIL = re.compile(r"\[TEST SUITE\].*TESTS FAILED")
RE_PANIC = re.compile(r"panicked at |AETHER KERNEL BUGCHECK|!!! Exception #8: Double Fault|triple fault")
RE_HEARTBEAT = re.compile(r"^\[HB\]\s+tick=(\d+)\s+cpu=(\d+)", re.MULTILINE)

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_HANG = 2
EXIT_HARD_TIMEOUT = 3
EXIT_CRASH = 4
EXIT_BUILD_FAIL = 5

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ── Data Classes ──────────────────────────────────────────────────────────────

class TestState:
    """Tracks a single running test."""
    def __init__(self, name: str, index: int):
        self.name = name
        self.index = index
        self.started_at = time.monotonic()


class WatchdogState:
    """Aggregate state for the entire watch session."""
    def __init__(self):
        self.current_test: TestState | None = None
        self.pass_count = 0
        self.fail_count = 0
        self.test_index = 0
        self.last_output_time = time.monotonic()
        self.last_heartbeat_time = 0.0  # 0 = no heartbeat seen yet
        self.last_heartbeat_tick = 0
        self.last_lines: deque = deque(maxlen=40)
        self.start_time = time.monotonic()
        self.had_panic = False
        self.panic_time = 0.0
        self.suite_done = False
        self.file_pos = 0
        self.result_line = ""
        self.failed_tests: list[str] = []


# ── QEMU Watchdog ─────────────────────────────────────────────────────────────

class QemuWatchdog:
    """Main watchdog controller."""

    def __init__(self, args):
        self.args = args
        self.state = WatchdogState()
        self.qemu_proc: subprocess.Popen | None = None
        self.qemu_pid: int | None = None

    def run(self) -> int:
        """Top-level: build → launch QEMU → watch → cleanup."""
        if not self.args.no_build and not self.args.monitor:
            if not self._build_kernel():
                return EXIT_BUILD_FAIL

        if self.args.monitor:
            self.qemu_pid = self.args.pid
        else:
            self.qemu_proc = self._launch_qemu()
            self.qemu_pid = self.qemu_proc.pid

        try:
            return self._watch_loop()
        finally:
            self._cleanup()

    def _build_kernel(self) -> bool:
        """Build kernel in the appropriate mode."""
        feature = "firefox-test" if self.args.firefox else "test-mode"
        self._print(f"{CYAN}Building kernel ({feature})...{RESET}")
        result = subprocess.run(
            ["cargo", "+nightly", "build",
             "--package", "astryx-kernel",
             "--target", "kernel/x86_64-astryx.json",
             "--profile", "release",
             "--features", feature,
             "-Zbuild-std=core,alloc",
             "-Zbuild-std-features=compiler-builtins-mem",
             "-Zjson-target-spec"],
            cwd=str(ROOT_DIR),
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            self._print(f"{RED}Build failed:{RESET}")
            self._print(result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr)
            return False

        # objcopy to binary
        subprocess.run(
            ["llvm-objcopy", "-O", "binary",
             str(KERNEL_ELF),
             str(ROOT_DIR / "build" / "esp" / "EFI" / "astryx" / "kernel.bin")],
            cwd=str(ROOT_DIR), check=True
        )
        self._print(f"{GREEN}Build OK{RESET}")
        return True

    def _launch_qemu(self) -> subprocess.Popen:
        """Launch QEMU with standard test flags."""
        # Clear old serial log
        SERIAL_LOG.parent.mkdir(parents=True, exist_ok=True)
        SERIAL_LOG.write_text("")

        # Find OVMF firmware
        ovmf_code = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
        if not ovmf_code.exists():
            ovmf_code = Path("/usr/share/ovmf/OVMF.fd")

        ovmf_vars_src = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
        ovmf_vars = ROOT_DIR / "build" / "OVMF_VARS_TEST.fd"
        if ovmf_vars_src.exists():
            subprocess.run(["cp", str(ovmf_vars_src), str(ovmf_vars)], check=True)

        # Use QEMU's virtual FAT from the esp/ directory (same as run-test.sh)
        # NOT astryx-os.img which can be stale.
        esp_dir = ROOT_DIR / "build" / "esp"
        data_img = ROOT_DIR / "build" / "data.img"

        cmd = [
            "qemu-system-x86_64",
            "-machine", "pc",
            "-cpu", "qemu64,+rdtscp",
            "-m", "1G",
            "-smp", "2",
            "-monitor", "none",
            "-serial", f"file:{SERIAL_LOG}",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-nic", "user,model=e1000,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,"
                    "hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:80",
        ]

        # Display: --video shows the QEMU window (works in WSL2 via WSLg)
        if self.args.video:
            cmd.extend(["-display", "gtk"])
            print(f"\033[96mVideo mode: QEMU GTK window will appear\033[0m",
                  file=sys.stderr)
        else:
            cmd.extend(["-display", "none"])

        # KVM if available
        if os.path.exists("/dev/kvm"):
            cmd.extend(["-enable-kvm"])

        # Firmware
        if ovmf_code.exists() and ovmf_vars.exists():
            cmd.extend([
                "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
                "-drive", f"if=pflash,format=raw,file={ovmf_vars}",
            ])

        # Boot disk (virtual FAT from esp/ directory, same as run-test.sh)
        if esp_dir.exists():
            cmd.extend(["-drive", f"format=raw,file=fat:rw:{esp_dir}"])

        # Data disk
        if data_img.exists():
            cmd.extend(["-drive", f"format=raw,file={data_img},if=none,id=data,snapshot=on",
                        "-device", "ide-hd,drive=data,bus=ide.1"])

        # GDB stub if requested
        if self.args.gdb_on_hang:
            cmd.extend(["-gdb", "tcp::1234"])

        self._print(f"{CYAN}Launching QEMU (PID will follow)...{RESET}")
        proc = subprocess.Popen(cmd, cwd=str(ROOT_DIR))
        self._print(f"{CYAN}QEMU PID: {proc.pid}{RESET}")
        return proc

    def _watch_loop(self) -> int:
        """Core monitoring loop. Returns exit code."""
        poll_interval = 0.25
        last_progress_print = 0.0

        while True:
            now = time.monotonic()
            elapsed = now - self.state.start_time

            # ── Check QEMU exit ───────────────────────────────────────
            if self.qemu_proc and self.qemu_proc.poll() is not None:
                exit_code = self.qemu_proc.returncode
                # Read remaining serial output
                time.sleep(0.5)
                self._read_new_lines()
                return self._interpret_exit(exit_code)

            # ── Read new serial lines ─────────────────────────────────
            new_lines = self._read_new_lines()
            if new_lines:
                self.state.last_output_time = now

            # ── Check for panic (give 5s for trace dump) ──────────────
            if self.state.had_panic:
                if now - self.state.panic_time > 5.0:
                    self._on_crash("Kernel panic/bugcheck detected")
                    return EXIT_CRASH

            # ── Check suite completion ────────────────────────────────
            if self.state.suite_done:
                # Wait up to 5s for QEMU to exit via debug-exit
                if now - self.state.last_output_time > 5.0:
                    self._print(f"{YELLOW}Suite done but QEMU didn't exit — killing{RESET}")
                    self._kill_qemu()
                    return EXIT_PASS if self.state.fail_count == 0 else EXIT_FAIL

            # ── Hard timeout ──────────────────────────────────────────
            if elapsed > self.args.hard_timeout:
                self._on_hang(f"Hard timeout ({self.args.hard_timeout}s)")
                return EXIT_HARD_TIMEOUT

            # ── Idle timeout (no serial output) ───────────────────────
            idle = now - self.state.last_output_time
            if idle > self.args.idle_timeout and not self.state.suite_done:
                self._on_hang(f"No serial output for {idle:.0f}s")
                return EXIT_HANG

            # ── Heartbeat timeout ─────────────────────────────────────
            if self.state.last_heartbeat_time > 0:
                hb_silence = now - self.state.last_heartbeat_time
                if hb_silence > self.args.heartbeat_timeout and not self.state.suite_done:
                    self._on_hang(f"No heartbeat for {hb_silence:.0f}s (timer ISR dead?)")
                    return EXIT_HANG

            # ── Per-test timeout ──────────────────────────────────────
            if self.state.current_test:
                test_elapsed = now - self.state.current_test.started_at
                if test_elapsed > self.args.test_timeout:
                    self._on_hang(
                        f"Test '{self.state.current_test.name}' stuck for {test_elapsed:.0f}s"
                    )
                    return EXIT_HANG

            # ── Progress display (every 5s) ───────────────────────────
            if now - last_progress_print > 5.0:
                self._print_progress()
                last_progress_print = now

            time.sleep(poll_interval)

    def _read_new_lines(self) -> list[str]:
        """Read new content from serial log, parse, return lines."""
        try:
            with open(SERIAL_LOG, "rb") as f:
                f.seek(self.state.file_pos)
                raw = f.read()
                self.state.file_pos = f.tell()
        except (FileNotFoundError, IOError):
            return []

        if not raw:
            return []

        # Decode with error replacement (binary garbage from UEFI)
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()

        for line in lines:
            self._process_line(line)
            self.state.last_lines.append(line)

        return lines

    def _process_line(self, line: str):
        """Parse a serial line and update state."""
        # Test header
        m = RE_TEST_HEADER.search(line)
        if m:
            self.state.test_index += 1
            self.state.current_test = TestState(m.group(1).strip(), self.state.test_index)
            return

        # Pass
        m = RE_PASS.search(line)
        if m:
            self.state.pass_count += 1
            self.state.current_test = None
            return

        # Fail
        m = RE_FAIL.search(line)
        if m:
            self.state.fail_count += 1
            self.state.failed_tests.append(m.group(1).strip())
            self.state.current_test = None
            return

        # Suite result
        if RE_RESULT.search(line):
            self.state.result_line = line.strip()
        if RE_SUITE_PASS.search(line) or RE_SUITE_FAIL.search(line):
            self.state.suite_done = True
            return

        # Heartbeat
        m = RE_HEARTBEAT.search(line)
        if m:
            self.state.last_heartbeat_time = time.monotonic()
            self.state.last_heartbeat_tick = int(m.group(1))
            return

        # Firefox-specific: FFTEST markers and FF/stderr errors
        if "[FFTEST] DONE" in line:
            self.state.suite_done = True
            return
        if "[FFTEST]" in line:
            # FFTEST heartbeat — treat as progress (prevents idle timeout)
            return
        if "[FF/stderr]" in line:
            # Firefox stderr output — print it prominently
            self._print(f"{YELLOW}[FF/STDERR]{RESET} {line.strip()}", file=sys.stderr)
            return
        if "[FF/open]" in line:
            # Library loading — update progress display
            return

        # Panic/crash
        if RE_PANIC.search(line):
            if not self.state.had_panic:
                self.state.had_panic = True
                self.state.panic_time = time.monotonic()

    def _interpret_exit(self, exit_code: int) -> int:
        """Interpret QEMU exit code."""
        elapsed = time.monotonic() - self.state.start_time
        if exit_code == 1:  # isa-debug-exit with value 0 → (0*2)+1=1
            self._print(
                f"\n{GREEN}{BOLD}ALL TESTS PASSED{RESET} "
                f"({self.state.pass_count}/{self.state.pass_count + self.state.fail_count}) "
                f"in {elapsed:.1f}s"
            )
            return EXIT_PASS
        elif exit_code == 3:  # isa-debug-exit with value 1 → (1*2)+1=3
            self._print(
                f"\n{RED}{BOLD}TESTS FAILED{RESET} "
                f"({self.state.pass_count}/{self.state.pass_count + self.state.fail_count}) "
                f"in {elapsed:.1f}s"
            )
            if self.state.failed_tests:
                self._print(f"{RED}Failed tests:{RESET}")
                for t in self.state.failed_tests:
                    self._print(f"  - {t}")
            return EXIT_FAIL
        elif exit_code == 124:
            self._on_hang("bash timeout (1200s)")
            return EXIT_HARD_TIMEOUT
        else:
            self._on_crash(f"QEMU exited with unexpected code {exit_code}")
            return EXIT_CRASH

    def _on_hang(self, reason: str):
        """Handle detected hang."""
        elapsed = time.monotonic() - self.state.start_time
        self._print(f"\n{RED}{BOLD}HANG DETECTED{RESET} after {elapsed:.1f}s: {reason}")

        if self.state.current_test:
            self._print(f"  Stuck on: {self.state.current_test.name} "
                        f"(test #{self.state.current_test.index})")

        self._print(f"  Progress: {self.state.pass_count} passed, {self.state.fail_count} failed")
        self._print(f"\n{YELLOW}Last serial output:{RESET}")
        for line in list(self.state.last_lines)[-20:]:
            printable = line.encode("ascii", errors="replace").decode("ascii")
            self._print(f"  | {printable}")

        # GDB capture
        if self.args.gdb_on_hang:
            self._gdb_capture()

        self._kill_qemu()

    def _on_crash(self, reason: str):
        """Handle detected crash."""
        elapsed = time.monotonic() - self.state.start_time
        self._print(f"\n{RED}{BOLD}CRASH{RESET} after {elapsed:.1f}s: {reason}")
        self._print(f"\n{YELLOW}Last serial output:{RESET}")
        for line in list(self.state.last_lines)[-30:]:
            printable = line.encode("ascii", errors="replace").decode("ascii")
            self._print(f"  | {printable}")
        self._kill_qemu()

    def _gdb_capture(self) -> str | None:
        """Connect to QEMU GDB stub, capture backtrace + registers."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", 1234))
            s.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            self._print(f"{YELLOW}GDB port 1234 not available — skipping backtrace{RESET}")
            return None

        self._print(f"\n{CYAN}Capturing GDB backtrace...{RESET}")
        gdb_script = (
            "set architecture i386:x86-64\n"
            "set pagination off\n"
            f"file {KERNEL_ELF}\n"
            "target remote :1234\n"
            "info threads\n"
            "thread apply all bt 20\n"
            "thread apply all info registers rip rsp rbp rflags\n"
            "detach\n"
            "quit\n"
        )
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
                f.write(gdb_script)
                gdb_file = f.name

            result = subprocess.run(
                ["gdb", "--batch", "-x", gdb_file],
                capture_output=True, text=True, timeout=15
            )
            os.unlink(gdb_file)

            output = result.stdout
            if output:
                self._print(f"\n{CYAN}GDB backtrace:{RESET}")
                for line in output.splitlines():
                    self._print(f"  {line}")
            return output
        except Exception as e:
            self._print(f"{YELLOW}GDB capture failed: {e}{RESET}")
            return None

    def _kill_qemu(self):
        """Kill QEMU process."""
        if self.qemu_proc:
            try:
                self.qemu_proc.terminate()
                self.qemu_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.qemu_proc.kill()
                self.qemu_proc.wait(timeout=2)
        elif self.qemu_pid:
            try:
                os.kill(self.qemu_pid, signal.SIGTERM)
                time.sleep(1)
                os.kill(self.qemu_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _print_progress(self):
        """Print a single-line progress summary."""
        elapsed = time.monotonic() - self.state.start_time
        idle = time.monotonic() - self.state.last_output_time
        test_info = ""
        if self.state.current_test:
            test_info = f" | Test {self.state.current_test.index}: {self.state.current_test.name}"
        hb = ""
        if self.state.last_heartbeat_tick > 0:
            hb = f" | HB={self.state.last_heartbeat_tick}"
        self._print(
            f"{CYAN}[WATCHDOG]{RESET} {elapsed:.0f}s{test_info}"
            f" | PASS={self.state.pass_count} FAIL={self.state.fail_count}"
            f" | idle={idle:.1f}s{hb}",
            file=sys.stderr
        )

    def _print(self, msg: str, file=None):
        """Print to stderr (stdout reserved for MCP)."""
        print(msg, file=file or sys.stderr, flush=True)

    def _cleanup(self):
        """Final cleanup."""
        pass

    # ── MCP tool functions ────────────────────────────────────────────

    def mcp_test_run(self, idle_timeout: int = 30, test_timeout: int = 60,
                     gdb_on_hang: bool = False) -> str:
        """Run a full test suite with watchdog monitoring."""
        self.args.idle_timeout = idle_timeout
        self.args.test_timeout = test_timeout
        self.args.gdb_on_hang = gdb_on_hang
        code = self.run()
        return json.dumps({
            "exit_code": code,
            "passed": self.state.pass_count,
            "failed": self.state.fail_count,
            "failed_tests": self.state.failed_tests,
            "elapsed": time.monotonic() - self.state.start_time,
            "result": self.state.result_line,
        })

    def mcp_test_status(self) -> str:
        """Get current test progress."""
        return json.dumps({
            "current_test": self.state.current_test.name if self.state.current_test else None,
            "test_index": self.state.test_index,
            "passed": self.state.pass_count,
            "failed": self.state.fail_count,
            "elapsed": time.monotonic() - self.state.start_time,
            "idle": time.monotonic() - self.state.last_output_time,
            "last_heartbeat_tick": self.state.last_heartbeat_tick,
        })

    def mcp_test_serial_tail(self, lines: int = 30) -> str:
        """Get last N lines of serial output."""
        return "\n".join(list(self.state.last_lines)[-lines:])

    def mcp_test_kill(self) -> str:
        """Kill the running QEMU instance."""
        self._kill_qemu()
        return "QEMU killed"


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="QEMU Watchdog — fast hang detection for AstryxOS tests"
    )
    parser.add_argument("--no-build", action="store_true",
                        help="Skip kernel build (use existing binary)")
    parser.add_argument("--monitor", action="store_true",
                        help="Attach to existing QEMU (requires --pid and --log)")
    parser.add_argument("--pid", type=int, default=0,
                        help="PID of existing QEMU process (with --monitor)")
    parser.add_argument("--log", type=str, default=str(SERIAL_LOG),
                        help="Path to serial log file")
    parser.add_argument("--idle-timeout", type=float, default=30.0,
                        help="Seconds of serial silence before declaring hang (default: 30)")
    parser.add_argument("--test-timeout", type=float, default=60.0,
                        help="Max seconds for a single test (default: 60)")
    parser.add_argument("--heartbeat-timeout", type=float, default=15.0,
                        help="Seconds without [HB] before declaring hang (default: 15)")
    parser.add_argument("--hard-timeout", type=float, default=300.0,
                        help="Absolute max seconds for entire run (default: 300)")
    parser.add_argument("--gdb-on-hang", action="store_true",
                        help="Auto-attach GDB and capture backtrace on hang")
    parser.add_argument("--firefox", action="store_true",
                        help="Firefox test mode: builds with --features firefox-test, "
                             "longer timeouts, watches for FF/stderr and FFTEST markers")
    parser.add_argument("--video", action="store_true",
                        help="Show QEMU display (removes -display none, uses SDL/GTK)")
    parser.add_argument("--mcp", action="store_true",
                        help="Run as MCP server (JSON-RPC over stdio)")
    args = parser.parse_args()
    # Firefox mode: adjust defaults for slow ATA PIO + long library loading
    if args.firefox:
        if args.idle_timeout == 30.0:
            args.idle_timeout = 60.0
        if args.test_timeout == 60.0:
            args.test_timeout = 300.0
        if args.hard_timeout == 300.0:
            args.hard_timeout = 600.0
        if args.heartbeat_timeout == 15.0:
            args.heartbeat_timeout = 45.0
    return args


def run_mcp_server():
    """Run as an MCP server for AI agent integration."""
    sys.path.insert(0, str(Path(__file__).parent))
    from mcp_server import McpServer

    server = McpServer("astryx-watchdog", "1.0.0")
    watchdog = QemuWatchdog(parse_args())

    @server.tool("test_run", "Run the AstryxOS test suite with watchdog monitoring", {
        "type": "object",
        "properties": {
            "idle_timeout": {"type": "integer", "description": "Serial silence timeout (seconds)", "default": 30},
            "test_timeout": {"type": "integer", "description": "Per-test timeout (seconds)", "default": 60},
            "gdb_on_hang": {"type": "boolean", "description": "Auto-capture GDB backtrace on hang", "default": False},
        },
    })
    def test_run(idle_timeout: int = 30, test_timeout: int = 60, gdb_on_hang: bool = False) -> str:
        return watchdog.mcp_test_run(idle_timeout, test_timeout, gdb_on_hang)

    @server.tool("test_status", "Get current test progress", {
        "type": "object", "properties": {},
    })
    def test_status() -> str:
        return watchdog.mcp_test_status()

    @server.tool("test_serial_tail", "Get last N lines of serial output", {
        "type": "object",
        "properties": {
            "lines": {"type": "integer", "description": "Number of lines", "default": 30},
        },
    })
    def test_serial_tail(lines: int = 30) -> str:
        return watchdog.mcp_test_serial_tail(lines)

    @server.tool("test_kill", "Kill the running QEMU instance", {
        "type": "object", "properties": {},
    })
    def test_kill() -> str:
        return watchdog.mcp_test_kill()

    server.run()


def main():
    args = parse_args()

    if args.mcp:
        run_mcp_server()
        return

    global SERIAL_LOG
    if args.log:
        SERIAL_LOG = Path(args.log)

    watchdog = QemuWatchdog(args)
    sys.exit(watchdog.run())


if __name__ == "__main__":
    main()
