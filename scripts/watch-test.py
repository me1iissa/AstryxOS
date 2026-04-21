#!/usr/bin/env python3
"""
AstryxOS Test Watchdog
======================
Monitors the QEMU serial log and the QEMU process simultaneously.
Detects hangs (no new output), hard timeouts, crashes, and clean exits.

Usage (launch-and-watch):
    python3 scripts/watch-test.py

Usage (watch an already-running QEMU):
    python3 scripts/watch-test.py --no-build --qemu-pid 12345

Exit codes:
    0  — all tests passed  (QEMU isa-debug-exit code 1 → exit(1))
    1  — some tests failed (QEMU isa-debug-exit code 3 → exit(3))
    2  — process hung      (idle timeout with no new serial output)
    3  — hard timeout      (total runtime exceeded)
    4  — QEMU crashed      (unexpected exit code)
    5  — build failed
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# ── ANSI colours ──────────────────────────────────────────────────────────────

RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[0;33m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
NC     = "\033[0m"

def _c(code: str, text: str) -> str:
    return f"{code}{text}{NC}" if sys.stdout.isatty() else text

# ── Defaults ──────────────────────────────────────────────────────────────────

ROOT          = Path(__file__).resolve().parent.parent
SERIAL_LOG    = ROOT / "build" / "test-serial.log"
OVMF_CODE     = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
OVMF_VARS_SRC = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
OVMF_VARS_DST = ROOT / "build" / "OVMF_VARS_TEST.fd"
DATA_IMG      = ROOT / "build" / "data.img"
ESP_DIR       = ROOT / "build" / "esp"
KERNEL_ELF    = ROOT / "target" / "x86_64-astryx" / "release" / "astryx-kernel"
KERNEL_BIN    = ESP_DIR / "EFI" / "astryx" / "kernel.bin"
BOOT_EFI_SRC  = ROOT / "target" / "x86_64-unknown-uefi" / "release" / "astryx-boot.efi"
BOOT_EFI_DST  = ESP_DIR / "EFI" / "BOOT" / "BOOTX64.EFI"
KERNEL_TARGET = ROOT / "kernel" / "x86_64-astryx.json"

IDLE_TIMEOUT_DEFAULT  = 30    # seconds with no new serial output → hung
HARD_TIMEOUT_DEFAULT  = 600   # seconds total runtime → timeout
POLL_INTERVAL         = 0.25  # seconds between log polls

# ── Build ─────────────────────────────────────────────────────────────────────

def build_kernel() -> bool:
    print(_c(CYAN, "[WATCH] Building kernel (test-mode)..."))
    try:
        # Boot loader
        r = subprocess.run(
            ["cargo", "+nightly", "build",
             "--package", "astryx-boot",
             "--target", "x86_64-unknown-uefi",
             "--profile", "release"],
            cwd=ROOT, capture_output=False
        )
        if r.returncode != 0:
            print(_c(RED, "[WATCH] Boot build failed."))
            return False

        # Kernel
        r = subprocess.run(
            ["cargo", "+nightly", "build",
             "--package", "astryx-kernel",
             f"--target={KERNEL_TARGET}",
             "--profile", "release",
             "--features", "test-mode",
             "-Zbuild-std=core,alloc",
             "-Zbuild-std-features=compiler-builtins-mem",
             "-Zjson-target-spec"],
            cwd=ROOT, capture_output=False
        )
        if r.returncode != 0:
            print(_c(RED, "[WATCH] Kernel build failed."))
            return False

        # Prepare ESP
        BOOT_EFI_DST.parent.mkdir(parents=True, exist_ok=True)
        KERNEL_BIN.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(BOOT_EFI_SRC, BOOT_EFI_DST)

        # llvm-objcopy: ELF → flat binary
        sysroot = subprocess.check_output(
            ["rustc", "+nightly", "--print", "sysroot"],
            text=True, cwd=ROOT
        ).strip()
        objcopy = next(
            Path(sysroot).rglob("llvm-objcopy"), None
        ) or shutil.which("llvm-objcopy")
        if not objcopy:
            print(_c(RED, "[WATCH] llvm-objcopy not found."))
            return False
        r = subprocess.run([str(objcopy), "-O", "binary",
                            str(KERNEL_ELF), str(KERNEL_BIN)], cwd=ROOT)
        if r.returncode != 0:
            print(_c(RED, "[WATCH] objcopy failed."))
            return False

        print(_c(GREEN, "[WATCH] Build complete."))
        return True

    except Exception as e:
        print(_c(RED, f"[WATCH] Build exception: {e}"))
        return False


# ── QEMU launch ───────────────────────────────────────────────────────────────

def launch_qemu(gdb_port: Optional[int] = None, freeze: bool = False) -> subprocess.Popen:
    if not OVMF_CODE.exists():
        raise FileNotFoundError(f"OVMF not found at {OVMF_CODE}")
    shutil.copy(OVMF_VARS_SRC, OVMF_VARS_DST)

    # Truncate serial log
    SERIAL_LOG.parent.mkdir(parents=True, exist_ok=True)
    SERIAL_LOG.write_text("")

    cmd = [
        "qemu-system-x86_64",
        "-machine", "pc",
        "-cpu", "qemu64,+rdtscp",
        "-m", "1G",
        "-smp", "2",
        "-serial", f"file:{SERIAL_LOG}",
        "-no-reboot", "-no-shutdown",
        "-monitor", "none",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-display", "none",
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={OVMF_VARS_DST}",
        "-drive", f"format=raw,file=fat:rw:{ESP_DIR}",
        "-device", "e1000,netdev=net0",
        "-netdev", "user,id=net0",
    ]

    if DATA_IMG.exists():
        cmd += [
            "-drive", f"file={DATA_IMG},format=raw,if=none,id=data0,snapshot=on",
            "-device", "ide-hd,drive=data0,bus=ide.1",
        ]

    if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK):
        cmd += ["-enable-kvm"]

    if gdb_port:
        cmd += ["-gdb", f"tcp::{gdb_port}"]
    if freeze:
        cmd += ["-S"]

    print(_c(CYAN, f"[WATCH] Launching QEMU: {' '.join(cmd[:6])} ..."))
    proc = subprocess.Popen(cmd, cwd=ROOT)
    print(_c(GREEN, f"[WATCH] QEMU PID {proc.pid}"))
    return proc


# ── Log watcher ───────────────────────────────────────────────────────────────

_PASS_PATTERN = re.compile(r"\[PASS\]|All tests passed|ALL TESTS PASSED", re.I)
_FAIL_PATTERN = re.compile(r"\[FAIL\]|SOME TESTS FAILED",                 re.I)
_PANIC_PATTERN = re.compile(r"PANIC|panicked at|kernel panic|double fault|page fault", re.I)
_HANG_HINTS   = re.compile(r"Waiting for|yield #\d+|idle.*spin", re.I)


def watch(
    qemu: subprocess.Popen,
    idle_timeout: int,
    hard_timeout: int,
    show_all: bool,
    quiet: bool,
) -> int:
    """
    Tail the serial log, monitor the QEMU process.

    Returns an exit code (0=pass, 1=fail, 2=hung, 3=hard-timeout, 4=crash).
    """
    start_time  = time.monotonic()
    last_output = time.monotonic()
    file_pos    = 0
    last_lines: list[str] = []  # rolling window for context on hang
    pass_count  = 0
    fail_count  = 0
    had_panic   = False

    print(_c(CYAN, f"[WATCH] Monitoring {SERIAL_LOG}"))
    print(_c(DIM,  f"[WATCH] idle-timeout={idle_timeout}s  hard-timeout={hard_timeout}s"))
    print()

    def _elapsed() -> str:
        return f"{time.monotonic() - start_time:6.1f}s"

    def _print_line(line: str):
        nonlocal pass_count, fail_count, had_panic
        stripped = line.rstrip("\n")
        if _PASS_PATTERN.search(stripped):
            pass_count += 1
            if not quiet:
                print(_c(GREEN, f"  {stripped}"))
        elif _FAIL_PATTERN.search(stripped):
            fail_count += 1
            if not quiet:
                print(_c(RED, f"  {stripped}"))
        elif _PANIC_PATTERN.search(stripped):
            had_panic = True
            print(_c(RED + BOLD, f"  {stripped}"))
        else:
            if not quiet or show_all:
                print(f"  {stripped}")

    while True:
        elapsed = time.monotonic() - start_time

        # ── Hard timeout ──────────────────────────────────────────────────────
        if elapsed >= hard_timeout:
            print()
            print(_c(RED + BOLD, f"[WATCH] ✗ HARD TIMEOUT after {elapsed:.1f}s"))
            _dump_context(last_lines)
            _kill(qemu)
            return 3

        # ── Idle timeout ──────────────────────────────────────────────────────
        idle = time.monotonic() - last_output
        if idle >= idle_timeout:
            print()
            print(_c(RED + BOLD,
                     f"[WATCH] ✗ HUNG — no new serial output for {idle:.1f}s "
                     f"(elapsed {elapsed:.1f}s)"))
            _dump_context(last_lines)
            _kill(qemu)
            return 2

        # ── Read new log lines ────────────────────────────────────────────────
        try:
            with open(SERIAL_LOG, "r", errors="replace") as fh:
                fh.seek(file_pos)
                chunk = fh.read()
                if chunk:
                    last_output = time.monotonic()
                    lines = chunk.splitlines(keepends=True)
                    for ln in lines:
                        _print_line(ln)
                        last_lines.append(ln.rstrip("\n"))
                        if len(last_lines) > 40:
                            last_lines.pop(0)
                    file_pos = fh.tell()
        except FileNotFoundError:
            pass  # log not created yet; QEMU just started

        # ── Check if QEMU exited ──────────────────────────────────────────────
        rc = qemu.poll()
        if rc is not None:
            # Drain any remaining log output
            try:
                with open(SERIAL_LOG, "r", errors="replace") as fh:
                    fh.seek(file_pos)
                    for ln in fh:
                        _print_line(ln)
                        last_lines.append(ln.rstrip("\n"))
                        if len(last_lines) > 40:
                            last_lines.pop(0)
            except FileNotFoundError:
                pass

            print()
            # QEMU isa-debug-exit: pass → kernel writes 0 → (0*2)+1=1, fail → 1 → 3
            if rc == 1:
                print(_c(GREEN + BOLD,
                         f"[WATCH] ✓ ALL TESTS PASSED  "
                         f"({pass_count} PASS, elapsed {elapsed:.1f}s)"))
                return 0
            elif rc == 3:
                print(_c(RED + BOLD,
                         f"[WATCH] ✗ SOME TESTS FAILED  "
                         f"({fail_count} FAIL, elapsed {elapsed:.1f}s)"))
                return 1
            else:
                print(_c(RED + BOLD,
                         f"[WATCH] ✗ QEMU exited unexpectedly (code={rc}, "
                         f"elapsed {elapsed:.1f}s)"))
                _dump_context(last_lines)
                return 4

        # Print periodic heartbeat so we know it's still running
        if not quiet and int(elapsed) % 30 == 0 and int(elapsed) > 0:
            idle_str = f"idle={idle:.0f}s" if idle > 5 else ""
            print(_c(DIM, f"[WATCH] {_elapsed()} running  PASS={pass_count} FAIL={fail_count} {idle_str}"),
                  end="\r", flush=True)

        time.sleep(POLL_INTERVAL)


def _dump_context(last_lines: list[str]):
    """Print the last N serial lines for context when hung/crashed."""
    if not last_lines:
        print(_c(YELLOW, "[WATCH] No serial output captured."))
        return
    count = min(20, len(last_lines))
    print(_c(YELLOW, f"\n[WATCH] Last {count} serial lines:"))
    for line in last_lines[-count:]:
        print(_c(DIM, f"  │ {line}"))
    print()


def _kill(proc: subprocess.Popen):
    if proc.poll() is None:
        print(_c(YELLOW, f"[WATCH] Killing QEMU PID {proc.pid}"))
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    global SERIAL_LOG   # must be declared before any use of SERIAL_LOG in this scope

    parser = argparse.ArgumentParser(
        description="AstryxOS QEMU test watchdog",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--no-build",    action="store_true",
                        help="Skip cargo build; use existing kernel.bin")
    parser.add_argument("--qemu-pid",    type=int, default=None,
                        help="Attach to an already-running QEMU PID instead of launching")
    parser.add_argument("--idle-timeout", type=int, default=IDLE_TIMEOUT_DEFAULT,
                        help=f"Seconds of no serial output before declaring hung (default {IDLE_TIMEOUT_DEFAULT})")
    parser.add_argument("--hard-timeout", type=int, default=HARD_TIMEOUT_DEFAULT,
                        help=f"Total max runtime in seconds (default {HARD_TIMEOUT_DEFAULT})")
    parser.add_argument("--gdb",          type=int, default=None, metavar="PORT",
                        help="Expose QEMU GDB stub on this port (e.g. 1234)")
    parser.add_argument("--freeze",       action="store_true",
                        help="Pass -S to QEMU (freeze at boot, wait for GDB connect)")
    parser.add_argument("--quiet",        action="store_true",
                        help="Only print PASS/FAIL/PANIC lines plus summary")
    parser.add_argument("--show-all",     action="store_true",
                        help="Show every serial line even in quiet mode")
    parser.add_argument("--log",          default=str(SERIAL_LOG),
                        help=f"Path to serial log file (default: {SERIAL_LOG})")
    args = parser.parse_args()

    # ── Build ─────────────────────────────────────────────────────────────────
    SERIAL_LOG = Path(args.log)

    if not args.no_build and args.qemu_pid is None:
        if not build_kernel():
            sys.exit(5)

    # ── Attach or launch QEMU ─────────────────────────────────────────────────
    if args.qemu_pid is not None:
        # Wrap an already-running process
        try:
            qemu = subprocess.Popen.__new__(subprocess.Popen)
            import os as _os
            # Use psutil-free approach: open /proc/<pid>/status
            qemu = _attach_pid(args.qemu_pid)
        except Exception as e:
            print(_c(RED, f"[WATCH] Cannot attach to PID {args.qemu_pid}: {e}"))
            sys.exit(4)
    else:
        try:
            qemu = launch_qemu(gdb_port=args.gdb, freeze=args.freeze)
        except Exception as e:
            print(_c(RED, f"[WATCH] Failed to launch QEMU: {e}"))
            sys.exit(4)

    # ── Handle Ctrl-C gracefully ──────────────────────────────────────────────
    def _sigint(sig, frame):
        print(_c(YELLOW, "\n[WATCH] Interrupted — killing QEMU"))
        _kill(qemu)
        sys.exit(130)
    signal.signal(signal.SIGINT, _sigint)

    # ── Watch ─────────────────────────────────────────────────────────────────
    exit_code = watch(
        qemu        = qemu,
        idle_timeout= args.idle_timeout,
        hard_timeout= args.hard_timeout,
        show_all    = args.show_all,
        quiet       = args.quiet,
    )

    # Map to human label for quick reading
    labels = {0: "PASS", 1: "FAIL", 2: "HUNG", 3: "TIMEOUT", 4: "CRASH", 5: "BUILD_FAIL"}
    print(_c(CYAN, f"[WATCH] Exit: {labels.get(exit_code, '?')} (code {exit_code})"))
    sys.exit(exit_code)


def _attach_pid(pid: int) -> subprocess.Popen:
    """Create a minimal Popen-like wrapper around an existing PID."""
    class ExistingProcess:
        def __init__(self, pid):
            self.pid = pid
        def poll(self):
            try:
                os.kill(self.pid, 0)
                # Check if zombie
                with open(f"/proc/{self.pid}/status") as f:
                    for line in f:
                        if line.startswith("State:") and "Z" in line:
                            return self._wait_exit()
                return None
            except (ProcessLookupError, FileNotFoundError):
                return self._wait_exit()
        def _wait_exit(self):
            try:
                _, status = os.waitpid(self.pid, os.WNOHANG)
                if os.WIFEXITED(status):
                    return os.WEXITSTATUS(status)
                return -1
            except ChildProcessError:
                return -1
        def terminate(self):
            try: os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError: pass
        def kill(self):
            try: os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        def wait(self, timeout=None):
            deadline = time.monotonic() + (timeout or 999999)
            while time.monotonic() < deadline:
                try:
                    os.kill(self.pid, 0)
                    time.sleep(0.1)
                except ProcessLookupError:
                    return
            raise subprocess.TimeoutExpired([], timeout)
    return ExistingProcess(pid)


if __name__ == "__main__":
    main()
