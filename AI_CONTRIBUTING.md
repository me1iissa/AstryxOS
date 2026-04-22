# AI Agent Contributor Guide

This guide is for AI agents (Claude, GPT, Gemini, or any other LLM agent)
contributing to AstryxOS. Human contributors should read
[HUMAN_CONTRIBUTING.md](HUMAN_CONTRIBUTING.md) instead.

---

## Contents

1. [AI contributions are welcome](#ai-contributions-are-welcome)
2. [Canonical task prompt template](#canonical-task-prompt-template)
3. [Use the watchdog — not run-test.sh](#use-the-watchdog)
4. [Worktree isolation](#worktree-isolation)
5. [Conflict resolution pitfall](#conflict-resolution-pitfall)
6. [No proprietary source citations](#no-proprietary-source-citations)
7. [win32-pe-test must stay off](#win32-pe-test-must-stay-off)
8. [Commit identity](#commit-identity)
9. [Co-Authored-By lines](#co-authored-by-lines)
10. [Wave structure and parallel agents](#wave-structure-and-parallel-agents)
11. [How to extend the test suite](#how-to-extend-the-test-suite)
12. [How to use the harness for autonomous debugging](#how-to-use-the-harness-for-autonomous-debugging)

---

## AI contributions are welcome

AstryxOS is developed heavily with AI agents working in parallel git worktrees.
Each agent is assigned a task, given its own worktree and branch, works
autonomously until the task is complete, and then the branch is merged by a
human reviewer. If you are an AI agent reading this file, you are operating
in a supported and expected mode.

---

## Canonical task prompt template

Prompts that work well with this repository follow this shape:

```
Role: You are a kernel engineer working on AstryxOS (Rust, x86_64, UEFI).

Task: <one clear sentence describing what to implement or fix>

Affected files: <list the specific files or subsystems>

Required tests: Every new feature or syscall must include at least one
headless regression test in kernel/src/test_runner.rs.

Exit criteria:
- python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300
  exits with code 0 and reports 139/140 (or more) tests passing.
- No new warnings introduced in the kernel build.

Constraints:
- Do NOT enable the win32-pe-test feature — it hangs the suite.
- Commit to branch <branch-name> (already checked out in this worktree).
- Co-Authored-By line must include your model name.
- Do not change git config.
```

Adapt as needed, but keep the exit criteria and constraints sections explicit.
Vague prompts produce agents that guess at done-ness criteria and may loop.

---

## Use the watchdog

The canonical test command is:

```bash
python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300
```

This is the only reliable way to verify the test suite. It:

1. Rebuilds the kernel with the `test-mode` Cargo feature enabled.
2. Launches QEMU headless.
3. Watches the serial log for pass/fail markers.
4. Handles hangs and panics automatically.
5. Exits with a structured code (0 = pass, 1 = fail, 2 = hung, 3 = hard
   timeout, 4 = QEMU crash, 5 = build failure).

**Do not use `bash scripts/run-test.sh` with `--no-build`.** That script does
not activate the `test-mode` feature. Past agents lost multiple hours running
tests that silently skipped the entire test dispatch loop because `test-mode`
was absent. The kernel builds and QEMU runs, but no tests execute.

`watch-test.py --no-build` is safe (it skips the cargo step but was previously
built with `test-mode`), but only use `--no-build` if you have verified the
existing binary was built with `test-mode` in the current session.

---

## Worktree isolation

Each agent works in its own git worktree. The harness infrastructure creates
these automatically. The worktree's branch belongs exclusively to that agent's
task.

Rules:
- Do not commit to another agent's worktree or branch.
- Do not commit to `master` directly from a worktree. All changes land via
  merge by the human reviewer.
- The harness protects against some of these accidentally, but the policy
  exists regardless.

If you discover a bug in code that is being modified by another active agent,
file a note in the task description or raise it in the output — do not reach
into the other branch.

---

## Conflict resolution pitfall

When resolving merge conflicts in `test_runner.rs` (the most common conflict
site, since every agent adds tests), use the `Edit` tool to apply precise
changes. Do not use shell pipelines with `awk`, `sed`, or `grep` to strip or
rewrite conflict markers.

**Why:** Past agents used `awk` to strip `<<<<<<`, `======`, and `>>>>>>>`
markers from around function bodies. Because awk operates line-by-line, it
silently dropped closing braces (`}`) that happened to appear adjacent to
conflict markers. The resulting file compiled in some configurations but had
subtly wrong control flow that caused multi-hour debugging sessions before
the missing brace was found.

**How to apply:** When you see a conflict in `test_runner.rs`:
1. Read the file section with the conflict markers.
2. Understand what both sides added.
3. Use the `Edit` tool to produce the correct merged content with both sets
   of tests present.
4. Verify the file has balanced braces before committing.

---

## No proprietary source citations

Do not include comments, documentation, or commit message text that cites or
paraphrases leaked Microsoft Windows source code. This includes:
- Windows NT 4.0 source kit
- Windows XP source kit
- Any other leaked or improperly disclosed Microsoft source tree

ReactOS is MIT-licensed and is explicitly safe to reference. Linux is GPL and
is also safe to reference. If you are uncertain whether something came from a
leaked source, do not include it.

---

## win32-pe-test must stay off

The `win32-pe-test` Cargo feature gates a test that requires proprietary PE
binaries not included in the repository. When this feature is enabled, the
test suite hangs indefinitely waiting for binaries that will never arrive.

Never pass `--features win32-pe-test` to any build command. Never add it to
`watch-test.py` or any CI script. The expected test count `139/140` reflects
this feature being off: the one gated test is excluded from the denominator
of passing tests.

---

## Commit identity

The repository's git config already has the correct user identity:

```
user.name  = Melissa
user.email = 184648288+me1iissa@users.noreply.github.com
```

Do not run `git config user.name` or `git config user.email` — the values are
already correct and changing them would affect the worktree for subsequent
agents. If git complains about identity when committing, check
`.git/config` in the worktree; do not set global config.

---

## Co-Authored-By lines

Include a `Co-Authored-By` trailer in every commit:

```
Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
```

Substitute your actual model name. For GPT-based agents:

```
Co-Authored-By: GPT-4o <noreply@openai.com>
```

The Co-Authored-By line goes after a blank line at the end of the commit
message body. Look at recent commits (`git log --oneline -10`) to see the
current convention.

---

## Wave structure and parallel agents

Development is organized into waves of 3–5 parallel agents. Each wave:

1. A human designs 3–5 non-overlapping tasks. Non-overlapping means the tasks
   touch different files and subsystems, so agents do not conflict.
2. Each agent is launched in its own worktree on its own branch.
3. Agents work in parallel until their tasks are complete.
4. The human merges branches sequentially, resolving any `test_runner.rs`
   conflicts manually using `Edit` (not awk).

If you are an agent in a wave, your branch is non-overlapping by design. If
you find yourself needing to touch a file that another active branch also
touches, stop and report this to the human reviewer rather than proceeding
and creating a hard conflict.

Wave-level conflicts in `test_runner.rs` are expected and normal. They are
resolved at merge time, not by agents during their task.

---

## How to extend the test suite

Adding a new test to `kernel/src/test_runner.rs`:

### Step 1: Write the test function

```rust
fn test_your_feature() {
    // Exercise the feature using syscalls or kernel APIs
    // Use the existing assert_eq!/assert! macros available in test_runner.rs
    // Print a pass marker if successful
    kprint!("[PASS test_your_feature]\n");
}
```

Look at existing test functions for patterns. Tests run in kernel mode inside
QEMU and have access to all kernel subsystems.

### Step 2: Register the test

Find the `run_all_tests()` function and add a call:

```rust
run_test("test_your_feature", test_your_feature);
```

The `run_test` wrapper catches panics and marks the test failed if it panics,
so your test function does not need to be defensive against its own panics.

### Step 3: Verify

```bash
python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300
```

The total count will increase by 1. The passing count should also increase
by 1 if your test passes.

### Step 4: Commit

Include the test name in your commit message body:

```
feat: add sys_ftruncate

Implements ftruncate(2) for ramfs and FAT32. Truncation to a larger size
extends the file with zero bytes. Adds test_ftruncate to test_runner.rs.
```

---

## How to use the harness for autonomous debugging

When a test fails or the kernel panics and you need to investigate
interactively, use `qemu-harness.py`.

### Start a session

```bash
python3 scripts/qemu-harness.py start --gdb-port 1234
```

Returns JSON:

```json
{"sid": "abc123def456", "pid": 98765, "serial_log": "/home/user/.astryx-harness/abc123def456.serial.log", "gdb_port": 1234}
```

Save the `sid` value.

### Wait for a known log line

```bash
python3 scripts/qemu-harness.py wait abc123def456 "kernel ready" --ms 15000
```

Blocks until the string appears in the serial log, or returns an error after
15 seconds.

### Inspect registers

```bash
python3 scripts/qemu-harness.py pause abc123def456
python3 scripts/qemu-harness.py regs abc123def456
```

Returns all x86_64 general-purpose and control registers as JSON.

### Read memory

```bash
python3 scripts/qemu-harness.py mem abc123def456 0xFFFF800000100000 64
```

Reads 64 bytes from the given virtual address.

### Resolve a symbol

```bash
python3 scripts/qemu-harness.py sym abc123def456 sys_mmap
```

Returns the virtual address of the symbol.

### Set a breakpoint and continue

```bash
python3 scripts/qemu-harness.py bp abc123def456 0xFFFF800001234560
python3 scripts/qemu-harness.py cont abc123def456
# ... wait for the bp to fire, then inspect
python3 scripts/qemu-harness.py regs abc123def456
```

### Capture an event log

```bash
python3 scripts/qemu-harness.py events abc123def456
```

Returns the JSONL event stream, which includes auto-captured panic snapshots.

### Fix and restart

Once you have identified the issue:

1. Stop the session: `python3 scripts/qemu-harness.py stop abc123def456`
2. Edit the kernel source.
3. Start a new session (it will rebuild automatically).

Do not try to hot-patch a running QEMU kernel. The rebuild cycle is fast
(incremental Rust compilation + QEMU start is typically under 30 seconds with
KVM).

### Tear down

```bash
python3 scripts/qemu-harness.py stop abc123def456
```

Always stop sessions when done. Orphaned QEMU processes consume memory and
may interfere with port bindings for subsequent sessions.

See [docs/HARNESS.md](docs/HARNESS.md) for the complete subcommand reference.
