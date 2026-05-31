---
title: Contributing & Dev Tooling
nav_order: 5
---

# Contributing & Dev Tooling

AstryxOS is built and debugged through a small set of purpose-built,
**non-interactive, structured-output** tools. This page covers the harness you
will use to boot and debug the kernel, the GDB-autopsy-first discipline for
investigating faults, and the contribution workflow.

{: .note }
AstryxOS is also an experiment in agentic development: most of the codebase was
written by AI agents working in parallel worktrees, with human review at merge
time. The tooling reflects that — every command is a one-shot invocation that
prints machine-readable JSON, so a human, a script, or an agent can drive it
identically.

---

## The QEMU harness

`scripts/qemu-harness.py` is the canonical way to build, boot, and debug the
kernel. Every subcommand prints JSON to stdout; session state persists on disk
under `~/.astryx-harness/`, so any number of one-shot queries can run against a
single live boot.

```bash
# start a session — prints {"sid": "...", "pid": ..., "serial_log": "..."}
python3 scripts/qemu-harness.py start [--features FLAGS] [--no-build] \
                                      [--gdb-port PORT] [--gdb-wait]

python3 scripts/qemu-harness.py wait <sid> <regex> [--ms MS]   # blocking wait on a marker
python3 scripts/qemu-harness.py grep <sid> <regex> [--tail N]  # search the serial log
python3 scripts/qemu-harness.py tail <sid>                     # recent serial output
python3 scripts/qemu-harness.py status <sid>                   # session status JSON
python3 scripts/qemu-harness.py list                           # all sessions
python3 scripts/qemu-harness.py stop <sid>                     # tear down
```

KVM is used automatically when `/dev/kvm` is present (recommended — it reaches
deeper into long boots and is much faster). Pass `--no-kvm` only to force a TCG
run.

A typical debug loop runs the QEMU session in the background and issues
foreground queries against it:

```bash
# 1. boot in the background
python3 scripts/qemu-harness.py start --features firefox-test    # backgrounded
# 2. block until a marker appears
python3 scripts/qemu-harness.py wait <sid> 'Compositor' --ms 120000
# 3. query live state as many times as needed (each returns immediately)
python3 scripts/qemu-harness.py grep <sid> 'content proc|Screenshot' --tail 20
python3 scripts/qemu-harness.py ff-progress <sid>
# 4. stop
python3 scripts/qemu-harness.py stop <sid>
```

The full subcommand reference is in [docs/HARNESS.md](HARNESS.md).

{: .warning }
For kernel and Firefox-port work, use the harness — **not** the shell wrappers
(`run-test.sh`, `run-firefox-test.sh`, etc.). The harness is the supported path:
it carries session state, an event stream, and the GDB stub. If it is missing a
subcommand you need, extend the harness rather than working around it.

### Firefox bring-up helpers

The harness ships oracles for the Firefox push:

- **`ff-progress <sid>`** — a pure serial-log scan reporting the headless
  screenshot **gate ladder** and the deepest gate reached: lib-load → x11-ready →
  compositor-init → ff-launch → content-proc → screenshot-actors →
  draw-snapshot → png-write, plus the max syscall count, whether a PNG was
  written, and the terminal cause. This is the authoritative "how deep did this
  boot get?" answer. The ladder lives in `scripts/ff_gates.yaml` and is
  additive.
- **`kdb <sid> cond-autopsy <pid> <cond_va> [<half>]`** — a one-shot
  pthread-condition-variable / mutex autopsy: it dumps the live struct, lists
  every parked waiter near the address (with the delta to the query), shows
  recent `FUTEX_WAKE` targets, infers the lock holder and whether it ever runs,
  and emits a `verdict_hint` (`wake-address-mismatch` | `held-lock-deadlock` |
  `owner-starved` | `true-lost-wakeup` | `benign-empty`). This is the decisive
  probe for the condvar-livelock gate.

---

## GDB autopsy first

AstryxOS has a GDB stub wired directly into the harness (`start --gdb-port N`).
The binding rule for fault investigation is:

> **Before adding any new printk-style probe** — a ring buffer, a counter, a
> diagnostic log line — to investigate a fault, first run a structured GDB
> autopsy and report what it says.

The autopsy subcommand breaks at a symbol or address, captures a named set of
registers and memory windows, and prints JSON:

```bash
python3 scripts/qemu-harness.py start --features <flags> --gdb-port 1234
python3 scripts/qemu-harness.py wait <sid> '<fault-marker-regex>'
python3 scripts/qemu-harness.py autopsy <sid> \
    --break <symbol-or-addr> \
    --capture <preset> \
    [--once N] [--continue-after] [--timeout-ms MS] [--output /tmp/autopsy.json]
```

Presets live in `scripts/autopsy/presets.yaml` and are additive (append a YAML
entry; no code change). The current set:

| Preset | Use when |
|---|---|
| `full-register-dump` | Minimal first probe — GPRs + segments + RFLAGS |
| `stack-walk-bt-full` | Need to walk frames; captures RSP/RBP windows |
| `ssp-fail-snapshot` | Stack-canary / `__stack_chk_fail`; canary slot + `fs:0x28` |
| `vfork-window` | `vfork(2)` gate; pre-clone frame identity |
| `gp-fault-context` | `#GP` at IRET/SYSRET; IRET frame + code around RIP |
| `sigsegv-user-gprs` | `SIGSEGV` delivery; the faulting user GPR context |
| `bugcheck-entry` | `ke_bugcheck` entry; decodes the bugcheck code + parameters |

A technique worth calling out, because it has cracked several gates: **live-RIP
on the correct build.** Break at the kernel syscall or futex handler and read
the *saved user RIP* — that names the exact upstream instruction that is stuck,
which the in-kernel debugger's process view alone may not reveal.

The GDB stub also exposes the lower-level primitives directly: `regs`, `mem`,
`sym`, `bp add|del|list`, `step`, `cont`, `pause`, `resume`.

The only faults GDB literally cannot reach — concurrent-write races where the
writer no longer holds the faulting page, freed-frame writers, fire-and-forget
corruption that completes before the symptom fires — are the documented
exceptions where a targeted probe is justified. Everything else (page faults,
`#GP`, `#UD`, canary corruption, bugchecks, kernel asserts) gets an autopsy
first.

---

## The in-kernel debugger (kdb)

`kdb` is a non-interactive in-kernel debugger surfaced through the harness as
one-shot argv commands — process listing, per-process detail, memory reads, and
the `cond-autopsy` probe above. Like everything else, each invocation is a
single request/response that prints structured output and exits; there is no
REPL to type into.

---

## Snapshots

The harness supports save/restore so a known-good boot state can be captured and
restored without redoing the boot:

```bash
python3 scripts/qemu-harness.py snap <sid> save <name>
python3 scripts/qemu-harness.py snap <sid> load <name>
```

This is the force-multiplier for deep gates: reach a hard-to-hit state once,
snapshot it, and restore it instead of waiting through a long reboot.

---

## Contribution workflow

Process rules that apply to **everyone**, human or agent:

1. **One change per branch.** No drive-by refactors inside a feature branch.
2. **Kernel changes land via pull request with green CI** — never direct to
   `master`.
3. **Tests are required.** Every new syscall or feature ships with at least one
   headless test in `kernel/src/test_runner.rs`.
4. **The test suite must pass before merging** — run
   `python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300` and
   confirm the expected pass count.
5. **Never patch an upstream binary.** If an upstream binary misbehaves, fix the
   kernel or the ABI layer — see
   [Running Upstream Binaries](running-upstream-binaries.md).
6. **Cite public specifications only.** In commits, comments, PRs, and docs,
   cite POSIX, the Linux man-pages, RFCs, the Intel SDM, and the ELF/psABI
   standards — never a private or proprietary source tree.

Routing:

- **Human contributors** — [HUMAN_CONTRIBUTING.md](https://github.com/me1iissa/AstryxOS/blob/master/HUMAN_CONTRIBUTING.md):
  environment, branch naming, commit format, PR workflow, style, filing bugs.
- **AI agents** — [AI_CONTRIBUTING.md](https://github.com/me1iissa/AstryxOS/blob/master/AI_CONTRIBUTING.md):
  worktree isolation, the canonical test command, known pitfalls, and how to
  extend the test suite autonomously.
- Vulnerability reports — [SECURITY.md](https://github.com/me1iissa/AstryxOS/blob/master/SECURITY.md).

---

## Tooling principles

Every debug/test tool in AstryxOS follows the same contract, which is what makes
the workflow scriptable end-to-end:

- **Non-interactive.** Each operation is one argv invocation that reads its
  arguments, does the work, prints structured output (preferably JSON), and
  exits. No REPLs, no "press any key", no required persistent stdin.
- **State lives on disk.** If state must survive between calls (a running QEMU
  session, a GDB attachment), it is written under a known path so any future
  caller can resume it.
- **Additive output.** New JSON fields are fine; field renames break downstream
  callers, so breaking changes are called out explicitly.

---

## See also

- [Getting Started](getting-started.md) — build and run the test suite first.
- [Architecture](architecture.md) — what you are debugging.
- [Running Upstream Binaries](running-upstream-binaries.md) — the find-the-
  divergence, fix-the-kernel method the harness exists to support.
