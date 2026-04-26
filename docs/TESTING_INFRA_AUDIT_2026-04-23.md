# Testing Infra Audit — 2026-04-23

Read-only audit by agent `ac4dbc31`. Tool profile: `feature-dev:code-reviewer`.

## Executive summary

AstryxOS has an unusually sophisticated testing infrastructure for a research OS. `test_runner.rs` is 10,000+ lines covering ~175 numbered tests across virtually every kernel subsystem, with strong post-condition checking and detailed serial telemetry. `scripts/qemu-harness.py` is a standout: persistent sessions, structured JSON output, built-in GDB RSP integration, QMP VM snapshots, and an in-process ELF symbol resolver — all documented in `docs/HARNESS.md`. What's missing is almost entirely at the **CI layer**: GitHub Actions doesn't boot a kernel, making the entire test suite invisible to the merge gate. Secondary liabilities: unbounded artefact growth in `~/.astryx-harness/`, "soft-pass" tests that silently tolerate network regressions, and a 1515-line Python hot-path that re-reads the serial log from byte zero on every `wait` poll cycle.

**Totals: 4 CRIT · 5 HIGH · 7 MED · 5 LOW**

## Wins

- Structured JSON protocol throughout `qemu-harness.py` — every subcommand emits one JSON object/array
- GDB RSP client in pure Python, no subprocess — `GdbClient` implements the wire protocol in ~200 lines
- Per-session isolation: each `start` creates independent serial log, QMP socket, OVMF_VARS copy
- Panic auto-snapshot: background watcher detects panic keywords and calls QMP `savevm` before the session dies
- 175 numbered kernel-side tests — no framework overhead, no parallel scheduling hazard
- FAT32 regression suite (110–115, 170–175) — precise bug-regression tests with before/after cluster counts
- GUI pixel telemetry via compositor backbuffer sampling (ground truth from inside the thing being tested)
- `docs/HARNESS.md` exists, is accurate, describes every subcommand with examples
- Runtime KVM detection: tests run identically with or without `-enable-kvm`
- `watch-test.py` idle/hang detection with rolling 40-line context dump

## CRIT

### CRIT-1 — CI never boots a kernel

`build.yml` has `cargo-check` and `kernel-build` jobs only. Neither installs QEMU or runs `watch-test.py`. A kernel that compiles but panics at boot can merge undetected. README badge "tests: 167/171" comes from manual runs; CI cannot confirm.

### CRIT-2 — "Soft pass" tests always return true regardless of network state

Tests 5 (ping Google DNS), 6 (DNS resolution), 32 (IPv6 DNS), 33 (IPv6 ping) all `return true` with `"SLIRP limitation — soft pass"` when operations fail. `test_dns_resolution()` at line 1244 passes even when `resolve()` returns `None` — DNS stack could stop sending packets entirely and this test still passes. Inflates pass count, hides regressions.

### CRIT-3 — `test_registry()` has no round-trip verification

Sets a key, deletes it, passes — never calls `registry_get()`. Comment at line 1398 acknowledges: "A more thorough test would need a registry_get() API." Test passes if `registry_set` is a no-op.

### CRIT-4 — `test_object_manager()` lacks namespace query

Inserts an object, trusts the `true` return, passes without `lookup_object()`. Broken namespace insert that returns `true` without actually registering would pass.

## HIGH

### HIGH-1 — `cmd_wait` re-reads serial log from byte zero on every 100 ms poll

`qemu-harness.py:936`. File-pos maintained across iterations but every poll re-opens and seeks. 1.2 MB seeks every 100 ms after a 2-minute run.

### HIGH-2 — `cmd_tail` reads entire serial log into memory

`cmd_tail` line 1031 calls `fh.readlines()` unconditionally before filtering. Multi-MB logs are fully materialised per call.

### HIGH-3 — No CI kernel-boot job exists

Compounds CRIT-1 on an agent-heavy project. Daily friction, no automatic regression signal.

### HIGH-4 — `run-test.sh` 1200 s hard timeout with no intermediate signal

Without KVM, full run can approach 20 min. No progress heartbeat; CI would see nothing for up to 20 min.

### HIGH-5 — `create-data-disk.sh` silently skips missing test binaries

Tests 43, 45, 63, 64–69, 141 depend on prebuilt binaries. Fresh clone running `run-test.sh` fails with `cannot read /disk/bin/tcc`. No prerequisite check.

## MED

- **MED-1** — Artefact accumulation in `~/.astryx-harness/` is unbounded; `cmd_stop` preserves serial log + events + OVMF_VARS. No prune command, no TTL.
- **MED-2** — `run-test.sh` and `watch-test.py` use different QEMU configs (virtio-blk-pci vs ide-hd for the data disk).
- **MED-3** — `qemu-harness.py` is the third QEMU invocation divergence.
- **MED-4** — `_get_watch_test()` hacks `sys.argv` to suppress argparse — fragile across refactors.
- **MED-5** — `run-firefox-test.sh` uses `-cpu host`, unit tests use `-cpu qemu64,+rdtscp` — undocumented inconsistency.
- **MED-6** — `qemu-harness-smoke.py` not invoked by CI or any wrapper — silently rots.
- **MED-7** — Numbered collisions: tests 63 and 63b both appear as "Test 63" in serial output.

## LOW

- **LOW-1** — `run-test.sh` attempts `sysctl` unconditionally; warns in CI.
- **LOW-2** — `_follow_events` polls every 500 ms instead of using `select`/`inotify`.
- **LOW-3** — `send` fires unconditional `chardev-send-break` before every write.
- **LOW-4** — `analyze-gui.py` screenshot validation is advisory, never fails the test.
- **LOW-5** — `run-gui-test.sh` embeds an inline Python QMP client (duplicates `qemu-harness.py`).

## Answers to specific questions

1. **`run-test.sh` end-to-end**: ~8–12 min with KVM, up to 20 min without.
2. **`run-firefox-test.sh` end-to-end**: ~4–8 min with KVM, risks 600 s timeout without.
3. **Tests in `test_runner.rs`**: 175+ numbered (178 effective with sub-tests). Avg 55–60 LOC per test.
4. **Tests that pass when the feature is broken**: `test_registry`, `test_object_manager`, `test_dns_resolution` (v4 + v6), soft-pass `test_ping`, `test_po_shutdown_sweep`.
5. **Parallel sessions**: Yes. Each `start` creates UUID-based `sid` with independent state. Only shared resource is the kernel binary.
6. **Artefact growth**: `build/*.log` truncated on run (no accumulation). `~/.astryx-harness/` accumulates unbounded.
7. **CI boots kernel?**: No. Just `cargo check` + disk image build.
8. **Flake detection**: Currently requires serial log grep. No structured per-test result artefact, no JUnit XML.

## Recommendations (ordered by bang-for-buck)

1. **Add a CI kernel-boot job** — install QEMU + OVMF, run `watch-test.py`, gate on exit code. ~20-line YAML + apt install.
2. **Harden soft-pass tests** or gate behind `#[cfg(feature = "network-tests")]`. Distinguish "packet sent but no reply" (soft) from "stack produced no packet" (hard fail). ~50 lines.
3. **Add round-trip verification** to `test_registry()` + `test_object_manager()` — 1–4 lines each.
4. **Add `prune` subcommand** to `qemu-harness.py` — TTL-based cleanup of orphaned sessions. ~30 lines of Python.
5. **Extract canonical QEMU machine definition** — one source for all three launchers. Refactor, ~100 lines.
6. **Emit per-test results as JSONL** on a dedicated serial port + `results <sid>` subcommand. ~80 lines total.
7. **Run `qemu-harness-smoke.py` in CI** — validates the harness itself isn't broken. 5-line CI step.
8. **Replace 500 ms poll with `select`/`inotify`** — zero-latency event delivery. ~10 lines.

## Rewrite candidates

- **`cmd_tail` hot path** → streaming `os.pread`/`mmap` in Python (no language change needed).
- **Serial log ingestion for `wait`/`grep`** → Rust sidecar with `inotify` + in-memory line store, Unix socket for queries. **Only worth it at scale** (dozens of parallel sessions); premature for current workflow.
- **`qemu-harness-smoke.py`** → fold into `qemu-harness.py` as a `selftest` subcommand.

## Coverage gaps

- **MM**: no OOM-killer + recover end-to-end test.
- **SMP**: no stress tests, no priority-inversion test.
- **Scheduler**: no test verifies CPU time distribution across vCPUs.
- **ext2 / NTFS**: feature-table claim, no tests.
- **Bootloader**: compile-checked only, no runtime verification.
- **Interrupt latency / APIC timer calibration**: no measurement tests.
- **TCP under packet loss**: no test injects reordering/loss via QEMU.
- **Win32 PE32+ (test 82)**: disabled behind feature flag due to scheduler hang.
- **Firefox full launch (test 56)**: disabled; firefox-test is a separate script, not in the 175-test suite.

---

*Full original audit in agent transcript `ac4dbc31`.*
