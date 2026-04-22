# Contributing to AstryxOS

AstryxOS is a research kernel. Contributions that improve stability, API
completeness, or test coverage are welcome. Read this document before opening a
pull request.

---

## How to build

Use `./build.sh release` for a standard manual build. This compiles the UEFI
bootloader and the Aether kernel and places the ESP image under `build/esp/`.

```bash
./build.sh release
```

For a debug build (no optimizations, more debug assertions):

```bash
./build.sh dev
```

The kernel target JSON is `kernel/x86_64-astryx.json`. The build requires Rust
nightly. See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full toolchain
setup.

---

## How to run the test suite

Always use the watchdog script — never launch QEMU directly for CI or automated
test runs.

```bash
python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300
```

The watchdog builds the kernel with `test-mode` enabled, launches QEMU headless,
watches the serial log for a pass/fail marker, and exits with a structured exit
code. It handles hangs, panics, and hard timeouts automatically.

`watch-test.py` also accepts `--no-build` if you want to re-run without
recompiling:

```bash
python3 scripts/watch-test.py --no-build --idle-timeout 60 --hard-timeout 300
```

Expected output when all tests pass ends with a line like:

```
[PASS] 139/140 tests passed
```

(One test is gated behind the `win32-pe-test` feature flag and is excluded from
the default run.)

---

## How to debug with the harness

`scripts/qemu-harness.py` is the agentic QEMU session manager. Every subcommand
prints JSON to stdout. See [docs/HARNESS.md](docs/HARNESS.md) for the full
reference.

Minimal workflow (start, wait for boot, inspect registers, stop):

```bash
# 1. Start a session with GDB stub on port 1234
python3 scripts/qemu-harness.py start --gdb-port 1234
# prints: {"sid": "abc123def456", "pid": 98765, ...}

# 2. Wait up to 15 s for the kernel to announce it is ready
python3 scripts/qemu-harness.py wait abc123def456 "kernel ready" --ms 15000

# 3. Pause and read registers
python3 scripts/qemu-harness.py pause abc123def456
python3 scripts/qemu-harness.py regs abc123def456

# 4. Tear down
python3 scripts/qemu-harness.py stop abc123def456
```

Replace `abc123def456` with the `sid` value returned by `start`.

---

## Commit message conventions

We use a conventional-commit prefix followed by a mandatory body paragraph
explaining the *why*, not just the *what*.

```
<prefix>: <short imperative summary>

<Body paragraph: motivation, affected subsystems, test coverage added.
One blank line separates the subject from the body.>

Co-Authored-By: ...
```

Accepted prefixes:

| Prefix | When to use |
|--------|-------------|
| `feat:` | New user-visible capability or syscall |
| `fix:` | Correctness fix for a known bug |
| `refactor:` | Code restructuring without behaviour change |
| `merge:` | Merge commit integrating a feature branch |
| `docs:` | Documentation-only changes |
| `test:` | New or updated headless tests only |
| `infra:` | Build system, CI scripts, tooling |

Merge commits should reference the feature branch name and include the same
body paragraph convention.

---

## Branch and PR rules

- **One change per branch.** No drive-by refactors inside a feature branch.
- **Tests are required for features.** Every new syscall or subsystem must
  include at least one headless test in `kernel/src/test_runner.rs`.
- **The test suite must pass before merging.** Run `watch-test.py` and
  confirm 139/140 (or better) before requesting review.
- **Target `master`.** All merges land on `master` directly.

---

## No-go zones

- **Do not cite or paraphrase leaked Microsoft source code** in comments,
  commit messages, or documentation. ReactOS (MIT-licensed) and Linux
  (GPL) references are fine.
- **Do not enable `win32-pe-test`** in CI or default builds. This feature
  flag gates a test that requires proprietary PE binaries not included in
  the repository.
- **Always use `watch-test.py` for automated test runs.** Do not launch
  QEMU directly from CI scripts; the watchdog handles timeout and cleanup.
- **Do not push `--force` to `master`** without explicit team agreement.

---

## Filing bugs

Open a GitHub issue. Include:

1. The full output of `python3 scripts/watch-test.py --idle-timeout 60 --hard-timeout 300`.
2. The serial log (`build/test-serial.log`) if available.
3. Host OS and QEMU version (`qemu-system-x86_64 --version`).

For panics and triple-faults, attach the output of
`python3 scripts/qemu-harness.py events <sid>` which may contain an
auto-captured QEMU snapshot name.
