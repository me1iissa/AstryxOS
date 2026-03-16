#!/usr/bin/env python3
"""
kdebug — Interactive kernel debugger for AstryxOS.

Wraps GDB connected to QEMU's gdbstub, with kernel-specific commands:
symbol resolution, stack canary checks, per-CPU register dumps, etc.

Dual-mode: Human REPL (default) or MCP server (--mcp) for AI agents.

Usage (human):
    # Start QEMU with GDB stub first:
    bash scripts/run-test-gdb.sh &
    # Then connect:
    python3 tools/kdebug.py
    kdebug> bt
    kdebug> regs
    kdebug> mem 0xffff800000100000 32
    kdebug> sym 0xffff80000022e44d
    kdebug> stack-canary 0xffff800003fe80000

Usage (AI via MCP):
    python3 tools/kdebug.py --mcp
"""

import argparse
import bisect
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
KERNEL_ELF = ROOT_DIR / "target" / "x86_64-astryx" / "release" / "astryx-kernel"

# Stack canary magic value (must match kernel/src/proc/mod.rs STACK_END_MAGIC)
STACK_END_MAGIC = 0x5741_436B_5374_4B21  # "WACkStK!"


# ── Symbol Table ──────────────────────────────────────────────────────────────

class SymbolTable:
    """Parses kernel ELF symbol table for address-to-function mapping."""

    def __init__(self, kernel_elf: str):
        self.addrs: list[int] = []
        self.names: list[str] = []
        self._load(kernel_elf)

    def _load(self, path: str):
        """Run nm --demangle and parse output."""
        try:
            result = subprocess.run(
                ["nm", "--demangle", "-n", path],
                capture_output=True, text=True, timeout=10
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"Warning: could not load symbols from {path}", file=sys.stderr)
            return

        for line in result.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            addr_str, sym_type, name = parts
            if sym_type.lower() not in ("t", "w", "d", "b", "r"):
                continue
            try:
                addr = int(addr_str, 16)
            except ValueError:
                continue
            self.addrs.append(addr)
            self.names.append(name)

        print(f"Loaded {len(self.addrs)} symbols from {path}", file=sys.stderr)

    def resolve(self, addr: int) -> str:
        """Resolve address to 'function+0xOFFSET' or hex if unknown."""
        if not self.addrs:
            return f"{addr:#018x}"
        idx = bisect.bisect_right(self.addrs, addr) - 1
        if idx < 0:
            return f"{addr:#018x}"
        offset = addr - self.addrs[idx]
        if offset > 0x10000:  # too far from any symbol
            return f"{addr:#018x}"
        if offset == 0:
            return self.names[idx]
        return f"{self.names[idx]}+{offset:#x}"

    def lookup(self, fragment: str) -> list[tuple[int, str]]:
        """Find symbols matching a substring."""
        results = []
        frag_lower = fragment.lower()
        for addr, name in zip(self.addrs, self.names):
            if frag_lower in name.lower():
                results.append((addr, name))
                if len(results) >= 20:
                    break
        return results


# ── GDB Session ───────────────────────────────────────────────────────────────

class GdbSession:
    """Manages an interactive GDB subprocess via stdin/stdout pipes."""

    def __init__(self, kernel_elf: str, gdb_port: int = 1234):
        self.proc = subprocess.Popen(
            ["gdb", "-q", "-nx", "--interpreter=mi2"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        # Initial setup
        self._send_raw(f"file {kernel_elf}")
        self._send_raw("set architecture i386:x86-64")
        self._send_raw("set pagination off")
        self._send_raw("set print pretty off")
        self._send_raw(f"target remote :{gdb_port}")

    def send(self, cmd: str, timeout: float = 10.0) -> str:
        """Send a GDB/MI command and collect console output."""
        return self._send_raw(cmd, timeout)

    def _send_raw(self, cmd: str, timeout: float = 10.0) -> str:
        """Send command, read until (gdb) prompt or done marker."""
        if not self.proc or self.proc.poll() is not None:
            return "[GDB process dead]"

        try:
            self.proc.stdin.write(f"-interpreter-exec console \"{cmd}\"\n")
            self.proc.stdin.flush()
        except BrokenPipeError:
            return "[GDB pipe broken]"

        output_lines = []
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            line = self.proc.stdout.readline()
            if not line:
                break
            line = line.rstrip("\n")
            # GDB/MI console output starts with ~"..."
            if line.startswith("~\""):
                # Unescape the MI string
                text = line[2:-1].replace("\\n", "\n").replace("\\t", "\t").replace("\\\"", "\"")
                output_lines.append(text)
            elif line.startswith("^done") or line.startswith("^error"):
                break
            elif line.startswith("^"):
                break

        return "".join(output_lines).rstrip()

    def close(self):
        """Detach and quit."""
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.write("quit\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()


# ── Kernel Debugger ───────────────────────────────────────────────────────────

class KernelDebugger:
    """Interactive kernel debugger with kernel-specific commands."""

    def __init__(self, kernel_elf: str, gdb_port: int = 1234):
        self.symbols = SymbolTable(kernel_elf)
        print(f"Connecting to QEMU GDB stub at localhost:{gdb_port}...", file=sys.stderr)
        self.gdb = GdbSession(kernel_elf, gdb_port)
        print("Connected.", file=sys.stderr)

    def run_repl(self):
        """Interactive REPL."""
        try:
            import readline
            readline.parse_and_bind("tab: complete")
            readline.set_completer(self._completer)
        except ImportError:
            pass

        print("kdebug — AstryxOS kernel debugger. Type 'help' for commands.", file=sys.stderr)
        while True:
            try:
                line = input("kdebug> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nBye.", file=sys.stderr)
                break
            if not line:
                continue
            self._dispatch(line)

        self.gdb.close()

    def _dispatch(self, line: str):
        """Parse and dispatch command."""
        parts = line.split()
        cmd = parts[0]
        args = parts[1:]

        handlers = {
            "bt": self.cmd_bt,
            "regs": self.cmd_regs,
            "threads": self.cmd_threads,
            "mem": self.cmd_mem,
            "sym": self.cmd_sym,
            "lookup": self.cmd_lookup,
            "break": self.cmd_break,
            "cont": self.cmd_cont,
            "step": self.cmd_step,
            "stack-canary": self.cmd_stack_canary,
            "help": self.cmd_help,
            "quit": self.cmd_quit,
            "q": self.cmd_quit,
        }

        handler = handlers.get(cmd)
        if handler:
            try:
                result = handler(args)
                if result:
                    print(result)
            except Exception as e:
                print(f"Error: {e}")
        else:
            # Pass through to GDB
            result = self.gdb.send(line)
            if result:
                print(result)

    def _completer(self, text, state):
        commands = ["bt", "regs", "threads", "mem", "sym", "lookup",
                    "break", "cont", "step", "stack-canary", "help", "quit"]
        matches = [c for c in commands if c.startswith(text)]
        return matches[state] if state < len(matches) else None

    # ── Commands ──────────────────────────────────────────────────────

    def cmd_bt(self, args) -> str:
        """Backtrace all CPUs."""
        return self.gdb.send("thread apply all bt 20")

    def cmd_regs(self, args) -> str:
        """Dump registers."""
        raw = self.gdb.send("info registers rip rsp rbp rflags cr3")
        # Enhance with symbol resolution for RIP
        for line in raw.splitlines():
            if "rip" in line:
                m = re.search(r"0x([0-9a-f]+)", line)
                if m:
                    addr = int(m.group(1), 16)
                    sym = self.symbols.resolve(addr)
                    raw += f"\n  RIP → {sym}"
        return raw

    def cmd_threads(self, args) -> str:
        """List vCPU threads."""
        return self.gdb.send("info threads")

    def cmd_mem(self, args) -> str:
        """Read memory: mem <addr> [len]"""
        if not args:
            return "Usage: mem <address> [length]"
        addr = args[0]
        length = int(args[1], 0) if len(args) > 1 else 64
        n_words = max(1, length // 8)
        return self.gdb.send(f"x/{n_words}gx {addr}")

    def cmd_sym(self, args) -> str:
        """Resolve address to symbol."""
        if not args:
            return "Usage: sym <address>"
        addr = int(args[0], 0)
        return f"{addr:#018x} → {self.symbols.resolve(addr)}"

    def cmd_lookup(self, args) -> str:
        """Find symbols matching substring."""
        if not args:
            return "Usage: lookup <fragment>"
        results = self.symbols.lookup(args[0])
        if not results:
            return "No symbols found"
        lines = [f"  {addr:#018x}  {name}" for addr, name in results]
        return "\n".join(lines)

    def cmd_break(self, args) -> str:
        """Set breakpoint."""
        if not args:
            return "Usage: break <address-or-symbol>"
        target = args[0]
        # If it's a hex number, prefix with *
        try:
            int(target, 0)
            target = f"*{target}"
        except ValueError:
            pass
        return self.gdb.send(f"break {target}")

    def cmd_cont(self, args) -> str:
        """Continue execution."""
        return self.gdb.send("continue")

    def cmd_step(self, args) -> str:
        """Single-step."""
        return self.gdb.send("stepi")

    def cmd_stack_canary(self, args) -> str:
        """Check stack canary at given kernel stack base."""
        if not args:
            return "Usage: stack-canary <stack_base_address>"
        addr = args[0]
        raw = self.gdb.send(f"x/1gx {addr}")
        # Parse the value
        m = re.search(r"0x([0-9a-f]+)", raw.split(":")[-1] if ":" in raw else raw)
        if m:
            value = int(m.group(1), 16)
            if value == STACK_END_MAGIC:
                return f"{raw}\n  Canary: INTACT ({value:#018x} == STACK_END_MAGIC)"
            else:
                return f"{raw}\n  Canary: CORRUPTED! ({value:#018x} != {STACK_END_MAGIC:#018x})"
        return raw

    def cmd_help(self, args) -> str:
        """Print help."""
        return """Commands:
  bt                  Backtrace all CPUs
  regs                Dump RIP, RSP, RBP, CR3, RFLAGS (with symbol resolution)
  threads             List vCPU threads
  mem <addr> [len]    Hex dump memory (default 64 bytes)
  sym <addr>          Resolve address to kernel symbol+offset
  lookup <fragment>   Find symbols matching substring
  break <addr|sym>    Set breakpoint
  cont                Continue execution
  step                Single-step one instruction
  stack-canary <addr> Check STACK_END_MAGIC at kernel stack base
  help                This help
  quit                Detach and exit
  <anything else>     Passed directly to GDB"""

    def cmd_quit(self, args):
        self.gdb.close()
        raise SystemExit(0)

    # ── MCP tool functions ────────────────────────────────────────────

    def mcp_kernel_backtrace(self) -> str:
        return self.cmd_bt([])

    def mcp_kernel_registers(self) -> str:
        return self.cmd_regs([])

    def mcp_kernel_threads(self) -> str:
        return self.cmd_threads([])

    def mcp_kernel_memory_read(self, address: str, length: int = 64) -> str:
        return self.cmd_mem([address, str(length)])

    def mcp_kernel_symbol_resolve(self, address: str) -> str:
        return self.cmd_sym([address])

    def mcp_kernel_stack_canary(self, stack_base: str) -> str:
        return self.cmd_stack_canary([stack_base])

    def mcp_kernel_gdb_raw(self, command: str) -> str:
        return self.gdb.send(command)


# ── CLI + MCP ─────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="kdebug — AstryxOS kernel debugger")
    parser.add_argument("--port", type=int, default=1234,
                        help="GDB port (default: 1234)")
    parser.add_argument("--elf", type=str, default=str(KERNEL_ELF),
                        help="Path to kernel ELF binary")
    parser.add_argument("--mcp", action="store_true",
                        help="Run as MCP server (JSON-RPC over stdio)")
    return parser.parse_args()


def run_mcp_server(args):
    """Run as MCP server for AI agents."""
    sys.path.insert(0, str(Path(__file__).parent))
    from mcp_server import McpServer

    server = McpServer("astryx-kdebug", "1.0.0")
    debugger = KernelDebugger(args.elf, args.port)

    @server.tool("kernel_backtrace", "Get backtrace of all CPUs", {
        "type": "object", "properties": {},
    })
    def kernel_backtrace() -> str:
        return debugger.mcp_kernel_backtrace()

    @server.tool("kernel_registers", "Dump CPU registers (RIP, RSP, CR3, RFLAGS) with symbol resolution", {
        "type": "object", "properties": {},
    })
    def kernel_registers() -> str:
        return debugger.mcp_kernel_registers()

    @server.tool("kernel_threads", "List all vCPU threads with their state", {
        "type": "object", "properties": {},
    })
    def kernel_threads() -> str:
        return debugger.mcp_kernel_threads()

    @server.tool("kernel_memory_read", "Read and hex-dump kernel memory", {
        "type": "object",
        "properties": {
            "address": {"type": "string", "description": "Memory address (hex, e.g. '0xffff800000100000')"},
            "length": {"type": "integer", "description": "Bytes to read (default 64)", "default": 64},
        },
        "required": ["address"],
    })
    def kernel_memory_read(address: str, length: int = 64) -> str:
        return debugger.mcp_kernel_memory_read(address, length)

    @server.tool("kernel_symbol_resolve", "Resolve a kernel address to function name + offset", {
        "type": "object",
        "properties": {
            "address": {"type": "string", "description": "Address to resolve (hex)"},
        },
        "required": ["address"],
    })
    def kernel_symbol_resolve(address: str) -> str:
        return debugger.mcp_kernel_symbol_resolve(address)

    @server.tool("kernel_stack_canary", "Check if a kernel stack's canary (overflow guard) is intact", {
        "type": "object",
        "properties": {
            "stack_base": {"type": "string", "description": "Kernel stack base address (hex)"},
        },
        "required": ["stack_base"],
    })
    def kernel_stack_canary(stack_base: str) -> str:
        return debugger.mcp_kernel_stack_canary(stack_base)

    @server.tool("kernel_gdb_raw", "Send a raw GDB command and return output", {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "GDB command to execute"},
        },
        "required": ["command"],
    })
    def kernel_gdb_raw(command: str) -> str:
        return debugger.mcp_kernel_gdb_raw(command)

    server.run()


def main():
    args = parse_args()

    if args.mcp:
        run_mcp_server(args)
        return

    debugger = KernelDebugger(args.elf, args.port)
    debugger.run_repl()


if __name__ == "__main__":
    main()
