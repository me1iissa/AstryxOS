# Human Contributor Guide

This guide is for human contributors to AstryxOS. AI agents should read
[AI_CONTRIBUTING.md](AI_CONTRIBUTING.md) instead.

---

## Contents

1. [Environment setup](#environment-setup)
2. [Branch naming](#branch-naming)
3. [Commit message format](#commit-message-format)
4. [PR workflow](#pr-workflow)
5. [Running tests](#running-tests)
6. [Using the debug harness](#using-the-debug-harness)
7. [Style guide](#style-guide)
8. [Testing requirements](#testing-requirements)
9. [Filing bugs](#filing-bugs)
10. [Code of conduct](#code-of-conduct)

---

## Environment setup

Tested on Ubuntu 22.04 LTS and WSL2 running Ubuntu 22.04. Other recent
Debian-based distributions should work.

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the complete step-by-step
guide, including OVMF path variations, KVM setup, and common build failures.

Quick summary of required packages:

```bash
sudo apt-get install -y \
    build-essential gcc musl-tools mtools \
    qemu-system-x86 ovmf git curl python3
```

Rust nightly is required. The exact version is pinned in `rust-toolchain.toml`
and Cargo will download it automatically once rustup is installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

First build:

```bash
./build.sh release
bash scripts/create-data-disk.sh
```

---

## Branch naming

Use the following prefixes:

| Prefix | When to use |
|--------|-------------|
| `feat/` | New user-visible capability, driver, or syscall |
| `fix/` | Correctness fix for a known bug |
| `refactor/` | Code restructuring without behaviour change |
| `docs/` | Documentation-only changes |
| `test/` | New or updated headless tests only |
| `infra/` | Build system, CI scripts, tooling changes |

Examples:

```
feat/fat32-hard-links
fix/execve-vmspace-leak
refactor/syscall-split
docs/oss-style-refresh
test/x11-extension-audit
infra/watch-test-exit-codes
```

Keep branch names short and lowercase with hyphens. One branch per logical
change.

---

## Commit message format

Follow the conventional-commit style with a mandatory body paragraph.

```
<prefix>: <short imperative summary (50 chars or less)>

<Body paragraph: one or two sentences explaining the motivation —
WHY the change was made, which subsystems are affected, and what
tests cover the new behaviour. One blank line between subject and
body.>

Co-Authored-By: Your Name <your@email.example>
```

Accepted prefixes match the branch prefix table above (`feat:`, `fix:`,
`refactor:`, `docs:`, `test:`, `infra:`, `merge:`).

Rules:
- Subject line is imperative mood ("add", "fix", "remove" — not "added" or "fixes").
- Subject line does not end with a period.
- Body is required for feat/fix/refactor commits. It may be omitted for
  trivial docs or typo fixes.
- Merge commits must reference the feature branch name.

Good example:

```
fix: tgkill uses tgid not tid for signal delivery

tgkill(tgid, tid, sig) must validate against arg1 (the thread-group ID),
not arg2 (the thread ID). The wrong argument was being checked, causing
signals sent to a process from another process to be silently dropped.
Adds test_tgkill_cross_process to test_runner.rs.
```

---

## PR workflow

### GitHub

1. Fork or push a branch to the main repository.
2. Open a pull request targeting `master`.
3. Fill in the PR template (title matches the commit subject; body describes
   the change and which tests cover it).
4. A passing test run (`139/140` or better) is required before merge.
5. At least one reviewer approval is required.

### Internal GitLab (if applicable)

Same conventions. The GitLab mirror carries the original SHAs. GitHub carries
the rewritten-author SHAs. Do not force-push `master` on either remote without
explicit agreement.

---

## Running tests

**Always use the watchdog.** Do not invoke QEMU directly for automated runs.

```bash
python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300
```

The watchdog rebuilds the kernel with the `test-mode` feature enabled, launches
QEMU headless, streams the serial log with colour annotations, and exits with
a structured exit code:

| Exit code | Meaning |
|-----------|---------|
| 0 | All tests passed |
| 1 | Some tests failed |
| 2 | Hung (idle timeout) |
| 3 | Hard timeout |
| 4 | QEMU crashed |
| 5 | Build failed |

To re-run without rebuilding (useful during rapid iteration):

```bash
python3 scripts/watch-test.py --no-build --idle-timeout 60 --hard-timeout 300
```

A passing run ends with output similar to:

```
[PASS] 139/140 tests passed
[WATCHDOG] QEMU exited cleanly
```

Do not use `bash scripts/run-test.sh` directly unless you know what you are
doing. That script does not activate the `test-mode` feature and will produce
misleading results.

---

## Using the debug harness

`scripts/qemu-harness.py` is the interactive QEMU session manager for debugging
specific failures. It exposes every interaction as a JSON-printing subcommand,
suitable for both human use and scripting.

Minimal workflow:

```bash
# Start a session with GDB stub
python3 scripts/qemu-harness.py start --gdb-port 1234
# prints: {"sid": "abc123def456", "pid": 98765, ...}

# Wait for kernel ready signal (up to 15 s)
python3 scripts/qemu-harness.py wait abc123def456 "kernel ready" --ms 15000

# Inspect registers
python3 scripts/qemu-harness.py pause abc123def456
python3 scripts/qemu-harness.py regs abc123def456

# Tear down
python3 scripts/qemu-harness.py stop abc123def456
```

See [docs/HARNESS.md](docs/HARNESS.md) for the full subcommand reference
(tail, events, mem, sym, bp, step, cont, snapshot, restore).

---

## Style guide

### Rust conventions

- Use `Option`/`Result` properly. Avoid `.unwrap()` in kernel paths — use
  `?` or explicit error handling.
- Comments explain WHY, not WHAT. Hardware workarounds must have a SAFETY or
  NOTE comment referencing the specific register/quirk.
- Unsafe blocks must have a `// SAFETY:` comment explaining the invariant.
- Constants over magic numbers. Shared constants go in `shared/src/lib.rs` or
  the relevant module's constants block.
- Functions should generally stay under ~100 lines. Extract helpers for
  complex logic.

### Source references

- ReactOS (MIT-licensed) and Linux (GPL) references are welcome in comments
  and documentation.
- Do not cite or paraphrase leaked Microsoft Windows source code (NT 4.0 source
  kit, XP source kit, or similar). If you are uncertain whether a reference is
  from a leaked source, do not include it.

### Focus

Keep commits focused. A commit that fixes a bug should not also refactor an
unrelated module. If you notice something broken while working on something
else, file it as a separate issue or branch.

---

## Testing requirements

Every new feature or syscall implementation must ship with at least one
regression test in `kernel/src/test_runner.rs`.

Pattern for adding a test:

1. Add a `fn test_your_feature()` function in `test_runner.rs`.
2. Add a dispatch call in the `run_all_tests()` function in the same file.
3. Make sure the test passes: `python3 scripts/watch-test.py --idle-timeout 60
   --hard-timeout 300`.
4. Include the test name in your commit message body.

Tests run headless inside QEMU with no display. They use the kernel's own
syscall interface and print `[PASS test_name]` or `[FAIL test_name reason]`
to the serial port. The watchdog parses this output.

---

## Filing bugs

Open a GitHub issue. Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).

Always include:

1. Full output of `python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300`.
2. The serial log at `build/test-serial.log` if available.
3. Host OS and QEMU version (`qemu-system-x86_64 --version`).

For panics and triple-faults, attach the output of:

```bash
python3 scripts/qemu-harness.py events <sid>
```

which may contain an auto-captured QEMU snapshot name that allows the crash
to be replayed.

---

## Code of conduct

Be kind. Discriminatory language is not tolerated. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
