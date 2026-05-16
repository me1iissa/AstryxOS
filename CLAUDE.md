# AstryxOS — project instructions for Claude Code agents

## Live session context (read on entry, update on exit)

**Before doing any non-trivial work, read `.claude/session/CURRENT.md`** for the
current goal, active investigations, recent decisions, and known gates.

```
python3 scripts/agent-context.py read-current
# Or through the harness front-end:
python3 scripts/qemu-harness.py context read-current
```

On completion, register your outcome so downstream agents start informed:

```
python3 scripts/agent-context.py register-completion \
    --agent-id <YOUR-AGENT-ID> \
    --outcome "<one-liner summary>" \
    --commits <sha1,sha2>       \   # omit if no commits
    --pr "#NNN"                      # omit if no PR
```

If dispatching sub-agents, register their launch too:

```
python3 scripts/agent-context.py register-dispatch \
    --agent-id <CHILD-AGENT-ID> \
    --role <role> \
    --task "<what it's doing>" \
    --parent <YOUR-AGENT-ID>
```

### Context helper subcommands

| Subcommand | Purpose |
|---|---|
| `read-current [--section S] [--json]` | Print CURRENT.md or one section |
| `summary` | One-paragraph session state |
| `digest-since <ISO-ts>` | Events since timestamp |
| `register-dispatch ...` | Record launch + update Active investigations |
| `register-completion ...` | Record finish + move to Recent findings |
| `append-event <kind> ...` | Append arbitrary event to EVENTS.jsonl |
| `prune-current [--max-lines N]` | Trim CURRENT.md to ≤N lines |

All subcommands are also accessible as `python3 scripts/qemu-harness.py context <subcommand>`.

---

## Test harness

For **all** kernel / Firefox-port testing use `scripts/qemu-harness.py` — NOT
the shell wrappers (`run-test.sh`, `run-firefox-test.sh`, etc.).

```
python3 scripts/qemu-harness.py start [--features FLAGS] [--no-build]
python3 scripts/qemu-harness.py wait <sid> <regex> [--ms MS]
python3 scripts/qemu-harness.py grep <sid> <regex>
python3 scripts/qemu-harness.py stop <sid>
```

KVM is used by default when `/dev/kvm` is available (recommended — see W139
soak results in harness docstring). Pass `--no-kvm` only for explicit TCG runs.

GDB stub: add `--gdb-port N` to `start`, then use `regs`, `mem`, `bp`, `step`.

Snapshot/restore: `snap <sid> save <name>` / `snap <sid> load <name>`.

### Hard-banned tools (for kernel testing)

- `scripts/run-test.sh`
- `scripts/run-firefox-test.sh`
- `scripts/run-qemu.sh`
- `scripts/run-test-gdb.sh`
- `scripts/run-gui-test.sh`
- Direct `scripts/watch-test.py` invocation
- Manually composed `cargo +nightly build` for testing

Every step goes through `scripts/qemu-harness.py`. If a subcommand is missing,
**extend the harness** — don't fall back to shell scripts.

---

## Architectural invariants

- **Never edit upstream binaries.** The Linux personality layer runs upstream
  Linux binaries (libxul, glibc, GTK, X11) as shipped. Build scripts wrap
  upstream — they do not patch it. If a wrap requires patching, fix the
  kernel/ABI instead.
- **All tools must be non-interactive and agent-friendly.** One-shot argv
  invocations, structured JSON output, no REPLs, no interactive prompts. If
  state must persist between calls, write it to disk.
- **Harness changes are additive.** New JSON fields are fine; field renames
  break downstream dispatches. Call out breaking changes in commit messages.

---

## Session files

| File | Purpose |
|---|---|
| `.claude/session/CURRENT.md` | Live state of the world (coordinator-maintained) |
| `.claude/session/EVENTS.jsonl` | Append-only event stream (one JSON per line) |
| `~/.astryx-harness/<sid>.json` | Per-QEMU-session state |
| `~/.astryx-harness/<sid>.events.jsonl` | Per-QEMU-session event stream |
| `~/.astryx-harness/<sid>.serial.log` | Serial log for grep/wait/tail |
