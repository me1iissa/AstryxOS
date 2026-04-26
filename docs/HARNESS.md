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

## Canonical machine definition

Every AstryxOS launcher — `run-test.sh`, `run-firefox-test.sh`,
`run-gui-test.sh`, `watch-test.py`, and this harness — composes its
`qemu-system-x86_64` argv through a single builder in
`scripts/astryx_qemu.py`. Previously each launcher assembled its own
command, which drifted: one used `ide-hd` for the data disk while two
others used `virtio-blk-pci`, and Firefox mode used `-cpu host` while
unit tests used `-cpu qemu64,+rdtscp`. Tests that depended on those
differences produced silently different results from one launcher to
the next.

`astryx_qemu.build_qemu_cmd()` takes a `mode` (`"test"` | `"firefox-test"`
| `"gui-test"`) plus explicit kwargs and returns the full argv as a
list. The per-mode differences (memory, CPU model, display) are all
visible in that one file.

Canonical choices:

- **Data disk bus**: `virtio-blk-pci` in every mode. Test 13 (ATA PIO)
  probes the IDE controller via raw I/O ports, which QEMU `-machine pc`
  exposes regardless of where the data image is attached — so moving
  the data disk off IDE does not regress it.
- **CPU**: `-cpu host` when `/dev/kvm` is present and for Firefox mode
  (which needs real-hardware CPUID). `-cpu qemu64,+rdtscp,+sse4_2`
  under TCG — the minimum feature set the kernel relies on.
- **Memory**: 1 GiB for `test` and `gui-test`, 2 GiB for `firefox-test`.
- **SMP**: 2 vCPUs everywhere (the stable configuration).

To extend the machine definition, edit `astryx_qemu.py`. Do not
re-introduce an inline QEMU argv in any launcher.

Bash wrappers invoke the builder via its CLI front-end:

```bash
readarray -t QEMU_CMD < <(python3 scripts/astryx_qemu.py build \
    --mode test --serial-path BUILD/serial.log \
    --data-img BUILD/data.img --ovmf-code OVMF_CODE.fd \
    --ovmf-vars OVMF_VARS.fd --esp-dir BUILD/esp)
```

Each argv token prints on its own line, so `readarray` reconstructs
the array exactly — including any token that contains spaces.

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

**`--features` is pass-through.**  Whatever string you supply is handed
to `cargo build --features` verbatim; nothing is injected silently.
Three canonical invocations cover the common cases:

```bash
# Default desktop kernel (no tests, no tracing)
python3 scripts/qemu-harness.py start

# In-kernel test-runner with kdb introspection
python3 scripts/qemu-harness.py start --features "test-mode,kdb"

# Firefox launch with live kdb + syscall/PF tracing
python3 scripts/qemu-harness.py start \
    --features "firefox-test,kdb,syscall-trace,pf-trace"
```

Options:

- `--no-build` — skip cargo build; use the existing `kernel.bin` from a
  previous build.
- `--features FLAGS` — comma-separated kernel feature flags passed
  verbatim to cargo.  Empty string (the default) builds the default
  desktop kernel with no `--features` flag.
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
# {"running": true, "sid": "abc123def456", "pid": 98765, "serial_log_size": 14720, "uptime_s": 12.4, "features": "test-mode", "exit_cause": "running"}
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

### `prune`

Delete all per-session state files (`<sid>.json`, `<sid>.serial.log`,
`<sid>.events.jsonl`, `<sid>.qmp.sock`, `<sid>.OVMF_VARS.fd`) for sessions
whose process is no longer alive AND whose most recent artefact is older
than `--ttl` days (default 7). Orphan files that have no matching
`<sid>.json` are included in the sweep. Per-file I/O or permission errors
are silently ignored so one bad file does not abort the whole run.

Returns a JSON object with the sids that were pruned, the count of
sessions kept (live or within TTL), and the total bytes freed.

```bash
python3 scripts/qemu-harness.py prune --ttl 7
# {"pruned": ["dead1", "dead2"], "kept": 3, "freed_bytes": 15482103}

# Aggressive sweep (everything dead, regardless of age)
python3 scripts/qemu-harness.py prune --ttl 0
```

### `results`

Summarise per-test pass/fail outcomes and Firefox diagnostics from the
session's serial log. The kernel test runner emits one
`[TEST-JSON] {...}` line per `test_pass!` / `test_fail!` invocation;
Firefox-mode runs additionally emit `[FF/open]`, `[FF/open-ret]`, `[SC]`,
`[SC-RET]`, and `[FFTEST] ...` markers that feed a `firefox` sub-object.

Output shape:

```json
{
  "exit_cause": "firefox_exited_clean",
  "total_ticks": 10761,
  "test_results": {
    "total": 175,
    "passed": 173,
    "failed": 2,
    "duration_ticks": 4521,
    "tests": [
      {"name": "Musl hello", "result": "pass", "elapsed_ticks": 1234},
      {"name": "FAT32 write", "result": "fail", "elapsed_ticks": 500}
    ]
  },
  "firefox": {
    "libs_loaded":  ["libnspr4", "libplc4", "libc"],
    "failed_opens": [{"path": "/etc/firefox.conf", "errno": -2}],
    "last_syscall": {"pid": 1, "tid": 1, "nr": 231, "rip": "0x7eff...",
                     "args": ["0x1", "0x0", "0x0"]},
    "exit_code":  1,
    "exit_ticks": 10761,
    "clean_exit": true
  }
}
```

`libs_loaded` is deduped by ELF soname stem (everything up to `.so`).
`failed_opens` surfaces every `[FF/open-ret]` with `ret < 0` so you can
trace which paths the loader couldn't resolve — the common case is
`errno=-2` (ENOENT) for missing library search paths. `firefox` is
`null` on non-firefox-test runs. `exit_cause` is computed with the same
heuristic as `status` (see below).

`elapsed_ticks` per test is the APIC tick delta between consecutive
reports. `duration_ticks` is the sum across all recorded tests. Tests
that ran but produced no `[TEST-JSON]` emission (pre-macros or output
lost before a crash) do not appear.

```bash
python3 scripts/qemu-harness.py results abc123def456 \
  | python3 -c 'import sys,json; o=json.load(sys.stdin); \
                tr=o["test_results"]; \
                print(f"{tr[\"passed\"]}/{tr[\"total\"]} passed")'
# 173/175 passed
```

---

## Diagnostics — syscall traces and exit classification

Three correlated signals make kernel-side application debugging
(especially Firefox porting) tractable without spelunking through the
serial log by hand.

**`[SC]` / `[SC-RET]` — paired syscall traces.** With the
`syscall-trace` feature enabled the Linux subsystem emits one
self-contained line at dispatch entry and another at dispatch exit:

```
[SC] pid=28 tid=28 nr=2 rip=0x7ffe12340120 a1=0x7fff... a2=0x0 a3=0x0
[SC-RET] pid=28 tid=28 nr=2 ret=0x3
```

`ret` is hex-formatted so negative errno values (e.g. `-2` → 
`0xfffffffffffffffe`) remain grep-friendly. The trace reflects the
actual value the caller observes in RAX; it is emitted after the
handler runs but before the register frame is written. A handful of
syscall handlers take non-expression `return` paths inside their match
arm block; those do not fire `[SC-RET]`, which is why the entry/exit
pair is not 1:1 in every direction.

**`[FF/open-ret]` — paired `open(2)` traces for Firefox.** When the
`firefox-test` or `test-mode` feature is enabled and the caller is PID
1 or 28, each `open()` emits both `[FF/open] pid=P path=PATH` before
resolution and `[FF/open-ret] pid=P path=PATH ret=N` after. `ret` is
decimal for readability (`-2` = ENOENT, `-13` = EACCES, non-negative =
fd). Pair these with `[SC-RET]` to distinguish "kernel returned an
error" from "libc translated it".

**`status.exit_cause` / `results.exit_cause`.** Both subcommands now
classify the session's terminal state from a 256 KiB tail of the
serial log, in this priority order:

| Cause | Trigger |
|---|---|
| `bugcheck:0xNNNN`        | `BUGCHECK 0xNNNN` |
| `scheduler_deadlock`     | `SCHEDULER_DEADLOCK` |
| `panic`                  | `PANIC:` or `panicked at` |
| `firefox_exited_clean`   | `[FFTEST] DONE` |
| `firefox_exited:ticks=N` | `[FFTEST] Firefox exited after N ticks` |
| `running`                | QEMU process still alive |
| `unknown_exit`           | none of the above, process gone |

Common invocations:

```bash
# Full syscall trace with returns, last 50 lines:
python3 scripts/qemu-harness.py grep <sid> '^\[SC(-RET)?\]' --tail 50

# What did Firefox's last failing open look like?
python3 scripts/qemu-harness.py results <sid> | jq '.firefox.failed_opens[-1]'

# Which shared libraries did Firefox successfully load?
python3 scripts/qemu-harness.py results <sid> | jq '.firefox.libs_loaded'

# Why did QEMU exit?
python3 scripts/qemu-harness.py status <sid> | jq '.exit_cause'
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

---

## Kernel feature flags used by the test suite

- **`test-mode`** — replaces the interactive shell with the automated test
  runner.  Always enabled for any CI or `watch-test.py` run.
- **`network-tests`** *(opt-in)* — re-enables the four soft-pass external
  network tests (Test 5 ping `8.8.8.8`, Test 6 DNS, Test 32 IPv6 DNS,
  Test 33 IPv6 ping).  These are off by default because QEMU's SLIRP
  backend drops external ICMP without `CAP_NET_ADMIN` on the host and the
  tests used to silently return `true` in that case.  Build with
  `--features "test-mode network-tests"` when validating the live
  network stack on a host that has `net.ipv4.ping_group_range`
  configured permissively.
- **`gui-test`**, **`firefox-test`** — see the respective launcher scripts.
- **`syscall-trace`** *(opt-in, Tier 0)* — emits one self-contained line per
  Linux syscall entry on the serial console.  Line format (stable,
  regex-parseable in one pass):

  ```
  [SC] pid=<n> tid=<n> nr=<n> rip=<0x…> a1=<0x…> a2=<0x…> a3=<0x…>
  ```

  `nr` is the Linux syscall number (RAX on entry), `rip` is the user-mode
  RIP of the `syscall` instruction (captured by the per-CPU `syscall_entry`
  stash), `a1`/`a2`/`a3` are the first three argument registers
  (RDI/RSI/RDX).  Arg count stops at 3 to keep volume manageable;
  correlate with `docs/LINUX_SYSCALL_COVERAGE.md` when you need a4–a6.
- **`pf-trace`** *(opt-in, Tier 0)* — emits one self-contained line per page
  fault (before VMA resolution, so every fault is visible, not only the
  unresolved ones).  Line format:

  ```
  [PF] cr2=<0x…> rip=<0x…> code=<0x…> pid=<n> tid=<n>
  ```

  `code` is the x86_64 PF error code (bit 0=present, 1=write, 2=user,
  4=ifetch).  `pid` is resolved via a *try-lock* on THREAD_TABLE; if the
  lock is contended (e.g. the fault raced with thread-table edits on
  another CPU) the trace emits `pid=0` rather than block — the trace is
  diagnostic-only.
- Enable both together for Firefox/user-mode debugging:

  ```sh
  python3 scripts/qemu-harness.py start \
      --features "firefox-test,syscall-trace,pf-trace"
  # all openat(2) calls
  python3 scripts/qemu-harness.py grep <sid> '^\[SC\] .*nr=257'
  # every user-mode #PF with its faulting RIP
  python3 scripts/qemu-harness.py grep <sid> '^\[PF\] '
  ```

  Both traces are off in the default and `test-mode` builds; enabling them
  adds no cost when disabled (cfg-gated emissions).

## kdb — in-kernel JSON introspection server (Tier 1)

Read-only kernel debugger listening on TCP port 9999 inside the guest.
One JSON request per connection, one JSON response, close — no REPL, no
keep-alive.  Enable with `--features kdb` alongside `test-mode`; every
code path is `#[cfg(feature = "kdb")]` so default builds are byte-
identical to the pre-kdb artefact.

```sh
python3 scripts/qemu-harness.py start --features "test-mode,kdb"
# → {"sid":"...","kdb_host_port":9990+(sid_hash%1000), ...}
```

SID hash → host port in 9990..10989, forwarded via SLIRP hostfwd to
guest `10.0.2.15:9999`.

| op             | args                   | returns                                               |
|----------------|------------------------|-------------------------------------------------------|
| `ping`         | —                      | `{"pong":true,"uptime_ticks":N}`                      |
| `proc-list`    | —                      | `{"procs":[{pid,ppid,state,name,rip,threads,…}]}`     |
| `proc`         | `<pid>`                | `{pid,state,threads:[…],vmas:[…],open_fds:{…}}`       |
| `vfs-mounts`   | —                      | `{"mounts":[{mountpoint,fstype,root_inode}]}`         |
| `dmesg`        | `[tail=100]`           | `{"lines":[…]}` — tail of the 64 KiB ring             |
| `syms`         | `<name>` or `0x<addr>` | `{name,addr,…}` — small kernel-resident table         |
| `mem`          | `<addr> <len≤4096>`    | `{addr,len,hex}` — kernel higher-half only            |
| `trace-status` | —                      | `{syscall_trace:bool,pf_trace:bool,build:"kdb"}`      |

```sh
SID=<sid-from-start>
python3 scripts/qemu-harness.py kdb $SID ping
python3 scripts/qemu-harness.py kdb $SID proc-list
python3 scripts/qemu-harness.py kdb $SID proc 1
python3 scripts/qemu-harness.py kdb $SID mem 0xffff800000100000 64
```

**Read-only guarantees.**  Memory/CPU mutation, pausing, single-step,
and breakpoint management live in Tier 2 (`--gdb-port`).  `mem` refuses
user-space addresses (we can't pick the right CR3), walks every 4 KiB
page through `virt_to_phys` so an unmapped region returns
`{"error":"unmapped page at …"}` rather than faulting in ring 0, and
caps length at 4096 B per call.

**Session mirror.**  `~/.astryx-harness/<sid>.kdb.json` caches the last
response per op + a call counter so repeat callers can see the last
observed state without another round-trip.

