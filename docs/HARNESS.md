# qemu-harness.py — Reference

## Overview

`scripts/qemu-harness.py` is a persistent, structured QEMU session manager
for AstryxOS. It solves a specific problem: the test watchdog (`watch-test.py`)
is excellent at CI-style pass/fail runs but gives no way to inspect a live
kernel, set breakpoints, or capture a crash snapshot programmatically.

The harness fills that gap. It wraps QEMU in a long-lived session, exposes
every interaction as a subcommand that prints JSON to stdout, and provides a
second tier of GDB Remote Serial Protocol integration for register reads,
memory inspection, breakpoints, and single-stepping. Every output is
machine-parseable, which makes it suitable for agentic debuggers as well as
human use.

Session state is stored under `~/.astryx-harness/<sid>.json`. Events (panics,
idle notices) are appended to `~/.astryx-harness/<sid>.events.jsonl`. A
background watcher process monitors the serial log for panic keywords and
auto-saves a QEMU snapshot on the first panic it detects.

The harness does not replace `watch-test.py` for CI. Use `watch-test.py` for
any automated pass/fail check; use the harness when you need to interact with a
running kernel.

---

## Tier 1 — Session management

These subcommands work on any session, with or without a GDB port.

### `start`

Launch a new QEMU session. Builds the kernel unless `--no-build` is given.
Returns a JSON object with the session ID (`sid`), QEMU PID, path to the serial
log, and the GDB port (0 if not requested).

```bash
python3 scripts/qemu-harness.py start
# {"sid": "abc123def456", "pid": 98765, "serial_log": "/home/user/.astryx-harness/abc123def456.serial.log", "gdb_port": 0}
```

Options:

- `--no-build` — skip cargo build; use the existing `kernel.bin` from a
  previous build.
- `--features FLAGS` — pass additional comma-separated kernel feature flags
  (e.g. `virtio-test`). `test-mode` is always added automatically.
- `--gdb-port PORT` — attach QEMU's built-in GDB stub to TCP port PORT.
  Required to use any Tier 2 subcommand.
- `--gdb-wait` — start QEMU frozen (`-S`); the kernel will not execute until a
  debugger sends `continue`. Implies `--gdb-port`.

### `stop`

Terminate a session by SID. Sends SIGTERM, waits 3 seconds, then sends
SIGKILL if necessary. The serial log and events file are preserved for
post-mortem analysis. Idempotent — safe to call even if the session is
already dead.

```bash
python3 scripts/qemu-harness.py stop abc123def456
# {"ok": true}
```

### `list`

List all active sessions. Dead sessions are pruned from the state directory.

```bash
python3 scripts/qemu-harness.py list
# [{"sid": "abc123def456", "pid": 98765, "started_at": 1745000000.0, "features": "test-mode", "running": true}]
```

### `status`

Return status for one session: running state, serial log size in bytes, uptime
in seconds.

```bash
python3 scripts/qemu-harness.py status abc123def456
# {"running": true, "sid": "abc123def456", "pid": 98765, "serial_log_size": 14720, "uptime_s": 12.4, "features": "test-mode"}
```

### `wait`

Block until a regular expression matches a line in the session's serial log,
or until a timeout expires. Scans from the beginning of the log, so lines
produced before `wait` was called are not missed.

```bash
python3 scripts/qemu-harness.py wait abc123def456 "kernel ready" --ms 15000
# {"matched": true, "line": "[BOOT] kernel ready", "line_no": 47}
```

On timeout: `{"matched": false, "reason": "timeout"}`.

`--ms N` sets the timeout in milliseconds (default 30000).

### `grep`

Search the entire serial log for all lines matching a regex. Returns the last
N matches (default 50, configurable with `--tail N`).

```bash
python3 scripts/qemu-harness.py grep abc123def456 "PANIC|page fault"
# ["[KERNEL] page fault at 0x0000000000000008 rip=0xffff800001234567"]
```

### `tail`

Return the last N bytes of the serial log as a list of lines. Useful for a
quick look at what the kernel printed recently. `--since LINE` starts from
a specific line number (useful for incremental polling).

```bash
python3 scripts/qemu-harness.py tail abc123def456 --bytes 2048
# {"lines": ["[TEST] test_fat32_write ... PASS", ...], "total_lines": 312, "returned": 18}
```

### `send`

Write text to the QEMU serial input via QMP `chardev-write`. Requires QEMU
7.0 or later; returns `{"ok": false}` on older versions.

```bash
python3 scripts/qemu-harness.py send abc123def456 "ls /"
```

### `events`

Show the structured event log for a session. Events include panic detections
(with auto-snapshot names) and idle notifications. `--follow` streams new
events as they arrive.

```bash
python3 scripts/qemu-harness.py events abc123def456
# [{"event": "panic", "pattern": "page fault", "line": "...", "snapshot": "abc123def456-panic", "ts": 1745000012.3}]
```

### `snap`

Save or restore a QEMU VM snapshot via QMP.

```bash
# Save
python3 scripts/qemu-harness.py snap abc123def456 save before-execve
# {"ok": true, "name": "before-execve", "op": "save"}

# Restore
python3 scripts/qemu-harness.py snap abc123def456 load before-execve
# {"ok": true, "name": "before-execve", "op": "load"}
```

---

## Tier 2 — GDB stub integration

Tier 2 subcommands require that the session was started with `--gdb-port PORT`.
They connect directly to QEMU's built-in GDB Remote Serial Protocol stub over
TCP without spawning a separate `gdb` process.

### `regs`

Read all x86_64 general-purpose registers plus EFLAGS and segment selectors
from the guest at its current execution point. Returns a JSON dict keyed by
register name, values formatted as hex strings.

```bash
python3 scripts/qemu-harness.py regs abc123def456
# {"ok": true, "regs": {"rax": "0x0", "rbx": "0xffff800001a3c000", ..., "rip": "0xffff800001234abc", "eflags": "0x246"}}
```

If the session is not paused, registers reflect the last vcpu state seen by
the GDB stub. Use `pause` first for a consistent snapshot.

### `mem`

Read up to 4096 bytes of guest memory starting at the given address. The
address may be a hex literal (`0xffff800001234000`) or decimal. Returns raw
bytes as a hex string.

```bash
python3 scripts/qemu-harness.py mem abc123def456 0xffff800001234000 64
# {"ok": true, "addr": "0xffff800001234000", "bytes": "4d5a...", "len": 64}
```

### `sym`

Resolve a kernel symbol name to its address and type by parsing the kernel ELF
directly. Does not require a live GDB connection.

```bash
python3 scripts/qemu-harness.py sym abc123def456 kernel_main
# {"ok": true, "name": "kernel_main", "addr": "0xffff800000100000", "size": 2048, "type": "func"}
```

### `bp`

Manage software breakpoints via GDB Z0/z0 packets. Breakpoint addresses are
persisted in the session JSON so `list` always reflects current state.

```bash
# Add a breakpoint at a hex address
python3 scripts/qemu-harness.py bp abc123def456 add 0xffff800001234abc
# {"ok": true, "op": "add", "addr": "0xffff800001234abc"}

# Remove it
python3 scripts/qemu-harness.py bp abc123def456 del 0xffff800001234abc

# List current breakpoints
python3 scripts/qemu-harness.py bp abc123def456 list
# {"ok": true, "breakpoints": []}
```

### `step`

Single-step one instruction via GDB `vCont;s`. Returns the stop-reply and the
new RIP after the step.

```bash
python3 scripts/qemu-harness.py step abc123def456
# {"ok": true, "stop_reply": "S05", "rip": "0xffff800001234abf"}
```

### `cont`

Continue execution via GDB `vCont;c`. Returns immediately — the kernel is now
running. Use `wait` to detect when it stops again (e.g. at a breakpoint).

```bash
python3 scripts/qemu-harness.py cont abc123def456
# {"ok": true, "note": "kernel running", "reply": "<sent: vCont;c>"}
```

### `pause`

Freeze all vCPUs via QMP `stop`. Required before reading registers for a
consistent snapshot.

```bash
python3 scripts/qemu-harness.py pause abc123def456
# {"ok": true, "note": "QEMU paused"}
```

### `resume`

Unfreeze all vCPUs via QMP `cont`. The mirror of `pause`.

```bash
python3 scripts/qemu-harness.py resume abc123def456
# {"ok": true, "note": "QEMU resumed"}
```

---

## Use cases

### Debugging a kernel hang

The kernel stops printing output but QEMU is still running. The watchdog would
report an idle timeout; the harness lets you inspect the live state.

```bash
# Start with GDB port
python3 scripts/qemu-harness.py start --gdb-port 1234
# Let it run until it hangs, then:
python3 scripts/qemu-harness.py pause $SID
python3 scripts/qemu-harness.py regs $SID
# Check RIP — is it in a spin-lock? Read memory around that address:
python3 scripts/qemu-harness.py mem $SID $RIP 128
# Save snapshot for later analysis
python3 scripts/qemu-harness.py snap $SID save hang-snapshot
python3 scripts/qemu-harness.py stop $SID
```

### Investigating a Ring-3 segfault

A user-space process faults. The kernel prints a `SIGSEGV` or `page fault`
line. You want to know the exact register state at the fault.

```bash
python3 scripts/qemu-harness.py start --gdb-port 1234
python3 scripts/qemu-harness.py wait $SID "page fault" --ms 30000
# Kernel printed the fault; pause and read registers
python3 scripts/qemu-harness.py pause $SID
python3 scripts/qemu-harness.py regs $SID
# Check the faulting address in rcr2 (kernel prints it in the fault message)
python3 scripts/qemu-harness.py grep $SID "fault"
```

### Single-stepping a new syscall

You added a syscall and want to trace the first few instructions.

```bash
python3 scripts/qemu-harness.py start --gdb-port 1234 --gdb-wait
# QEMU starts frozen. Resolve the syscall handler symbol:
python3 scripts/qemu-harness.py sym $SID sys_new_call
# {"addr": "0xffff800001abc000", ...}
python3 scripts/qemu-harness.py bp $SID add 0xffff800001abc000
python3 scripts/qemu-harness.py cont $SID
# Wait for the breakpoint to trigger
python3 scripts/qemu-harness.py wait $SID "S05" --ms 10000
# Step through
python3 scripts/qemu-harness.py step $SID
python3 scripts/qemu-harness.py regs $SID
```
