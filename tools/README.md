# AstryxOS Developer Tools

## qemu-watchdog.py — Fast Hang Detection

Monitors QEMU test runs and detects hangs within 15-30 seconds (vs 20-minute bash timeout).

### Human Usage

```bash
# Full build + test + watch (recommended)
python3 tools/qemu-watchdog.py

# Skip build (use existing kernel binary)
python3 tools/qemu-watchdog.py --no-build

# Auto-capture GDB backtrace when hang detected
python3 tools/qemu-watchdog.py --gdb-on-hang

# Attach to existing QEMU
python3 tools/qemu-watchdog.py --monitor --pid <PID> --log build/test-serial.log

# Custom timeouts
python3 tools/qemu-watchdog.py --idle-timeout 20 --test-timeout 45 --hard-timeout 120
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | Tests failed |
| 2 | Hang detected |
| 3 | Hard timeout |
| 4 | Kernel crash / QEMU crash |
| 5 | Build failure |

### Detection Mechanisms

| Method | Default Timeout | What It Catches |
|--------|----------------|-----------------|
| Heartbeat silence | 15s | Timer ISR deadlock, triple fault |
| Serial idle | 30s | Any hang that doesn't crash serial |
| Per-test timeout | 60s | Test-internal infinite loop |
| Hard timeout | 300s | Absolute safety net |

---

## kdebug.py — Interactive Kernel Debugger

Wraps GDB with kernel-specific commands: symbol resolution, stack canary checks, etc.

### Human Usage

```bash
# Start QEMU with GDB stub
bash scripts/run-test-gdb.sh &

# Connect debugger
python3 tools/kdebug.py

kdebug> bt                          # backtrace all CPUs
kdebug> regs                        # dump registers with symbol resolution
kdebug> threads                     # list vCPU threads
kdebug> mem 0xffff800000100000 64   # hex dump 64 bytes
kdebug> sym 0xffff80000022e44d      # resolve address to function
kdebug> lookup schedule             # find symbols matching "schedule"
kdebug> stack-canary 0xffff800003fe80000  # check stack overflow guard
kdebug> cont                        # continue execution
kdebug> step                        # single-step
```

---

## AI Agent Integration (MCP)

Both tools support [Model Context Protocol](https://modelcontextprotocol.io/) for AI agent use.

### Setup

Add to `.claude/settings.local.json`:

```json
{
  "mcpServers": {
    "astryx-kdebug": {
      "type": "stdio",
      "command": "python3",
      "args": ["tools/kdebug.py", "--mcp"]
    },
    "astryx-watchdog": {
      "type": "stdio",
      "command": "python3",
      "args": ["tools/qemu-watchdog.py", "--mcp"]
    }
  }
}
```

### Available MCP Tools

**Watchdog:**
- `test_run(idle_timeout?, test_timeout?, gdb_on_hang?)` — run test suite
- `test_status()` — get current progress
- `test_serial_tail(lines?)` — last N lines of serial output
- `test_kill()` — kill QEMU

**Debugger:**
- `kernel_backtrace()` — backtrace all CPUs
- `kernel_registers()` — register dump with symbol resolution
- `kernel_threads()` — list vCPU threads
- `kernel_memory_read(address, length?)` — hex dump memory
- `kernel_symbol_resolve(address)` — resolve address to function
- `kernel_stack_canary(stack_base)` — check stack overflow guard
- `kernel_gdb_raw(command)` — raw GDB command

### Requirements

- Python 3.8+ (stdlib only — no pip install needed)
- GDB (for kdebug and --gdb-on-hang)
- QEMU with isa-debug-exit device
