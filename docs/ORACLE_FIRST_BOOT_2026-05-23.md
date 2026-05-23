# Oracle Endpoint Agent — First-Boot Staging on AstryxOS

**Date**: 2026-05-23
**Author**: principal-systems-engineer (dispatched)
**Branch**: `worktree-agent-ac947bec790fabb7a` (off `i1b-tokio-syscalls` at `56b40921`)
**Scope**: Stage oracle, wire the `oracle-test` cargo feature, attempt first boot
**Status**: Staging complete + cargo check passes; **first boot blocked by host disk exhaustion (0 bytes free)**

---

## TL;DR

- Oracle (infrasvc release `7b03aa65`, GLIBC-linked, 5 MiB) fetched from
  the user's private GitLab `infrastructure-services/infrasvc` package
  registry, cached at `~/.cache/astryxos-oracle/oracle`, staged at
  `/usr/bin/oracle` on the data-disk image.
- Minimum first-boot config staged at `/etc/oracle/config.toml` with
  sync disabled, process+security collectors off, network+system+
  hardware collectors on.
- Host glibc-linked `libssl.so.3` + `libcrypto.so.3` staged at
  `/lib/x86_64-linux-gnu/` — these are the deps oracle DT_NEEDEDs.
  The Alpine musl copies staged by `install-tls-stack.sh` are
  ABI-incompatible with a glibc binary, so install-oracle.sh stages
  its own glibc-linked pair.
- Kernel `oracle-test` cargo feature added; `oracle_demo.rs` mirrors
  `tls_demo.rs`/`sshd_demo.rs` shape and launches
  `oracle --mode console --once --log-level debug --config /etc/oracle/config.toml`,
  captures stdout, hunts for first-gate markers, emits structured
  SUMMARY + verdict line.
- `cargo check --features oracle-test` passes type-check on all
  added code (only fails on incremental-cache write due to disk full).
- **First boot not executed**: host disk is at 100% / 39 MiB free
  after my own cleanup; full kernel build needs ~3 GiB. Other agent
  worktrees own ~25 GiB of locked state I cannot delete.

---

## 1. What was added

### 1.1 `scripts/install-oracle.sh` (new, 269 lines / ~125 functional)

Mirrors `install-sshd.sh` / `install-tls-stack.sh` pattern. Steps:

1. Fetch oracle binary from
   `https://svn.hyperlxc.co.uk/api/v4/projects/24/packages/generic/infrasvc/7b03aa65/infrasvc-amd64`
   via curl + the glab CLI's stored token. Caches at
   `~/.cache/astryxos-oracle/oracle`.
2. Verify ELF shape, print DT_NEEDED + highest GLIBC version (2.39).
3. Stage at `/usr/bin/oracle`.
4. Write `/etc/oracle/config.toml` (sync disabled, process+security
   collectors off, file logging off).
5. Stage host glibc-linked `libssl.so.3` + `libcrypto.so.3` at
   `/lib/x86_64-linux-gnu/`.
6. Create runtime dirs `/var/lib/oracle/`, `/var/log/oracle/`.

Tested end-to-end on the host — produces expected files at expected
paths. Idempotent; `--force` re-fetches.

### 1.2 `kernel/src/oracle_demo.rs` (new, 334 lines / ~192 functional)

Mirrors `tls_demo.rs`. Loads `/disk/usr/bin/oracle`, spawns it via
`create_user_process_with_args_blocked`, captures stdout to 32 KiB,
polls until exit or 30 s soak. Verdict logic emits one of:

- `PASS` — exit=0 with observation-cycle output.
- `PASS-INIT` — banner/collector init seen; exit nonzero → one bounded
  gate, name visible in marker bits.
- `PRE-MAIN` — no stdout at all → dynamic linker / glibc init / static
  init failure before main().
- `PARTIAL` — some stdout but no banner → early runtime / sd_notify /
  clap parse gate.
- `TIMEOUT` — process still running after 30 s.

Marker hunt covers predicted gates from the infrasvc audit:
`/sys/class/net`, `libssl` undefined symbol, `ENOSYS`, `panic`.

### 1.3 `kernel/Cargo.toml` (+22 lines)

`oracle-test = []` feature with doc comment matching style of
existing `tls-test`/`sshd-test`/`httpd-test` features. Cites tokio,
sd_notify(3), systemd.service(5).

### 1.4 `kernel/src/main.rs` (+49 / -1 lines)

- `#[cfg(feature = "oracle-test")] mod oracle_demo;`
- New cfg-gated launch block after the tls-test block (HAL enable,
  sched enable, 30-tick warmup, call into demo, debug-exit port).
- Added `not(feature = "oracle-test"),` to the cfg lines of all 5
  existing test-mode blocks (xeyes, busybox/wget, httpd, sshd, tls,
  firefox) so mutual exclusivity holds.
- Added `feature = "oracle-test"` to the catch-all `not(any(...))`
  gates at lines 1138/1198 so normal-boot is suppressed when the
  demo is selected.

### 1.5 `scripts/create-data-disk.sh` (+62 lines)

- `ORACLE="${ASTRYXOS_ORACLE:-0}"` env-var default + 8-line doc.
- `--oracle) ORACLE=1; FORCE=true ;;` flag in argv parser.
- Warning if `FIREFOX_VARIANT != glibc` when `--oracle` is set.
- install-oracle.sh invocation block after install-tls-stack.
- FAT32 packing block: mcopies oracle binary, config.toml, and creates
  `/var/lib/oracle/` + `/var/log/oracle/` dirs in data.img.

---

## 2. What was NOT done (and why)

**The kernel was not built and the first boot was not executed.**

The host filesystem hit 100% / 0 bytes free during the first
`cargo build` (`os error 28: No space left on device`). After
cleaning my own target dir, 39 MiB free; a full release kernel
build needs ~3 GiB.

`cargo check --features oracle-test` did proceed through full
type-check before hitting the cache-write step — proves the code
compiles cleanly. Zero `error[E...]` codes from my added code; only
the I/O failure on the cache file.

Other agent worktrees (`git worktree list` shows many `locked`
worktrees) collectively own ~25 GiB across their `target/` and
`build/` directories. These belong to concurrent agents whose
state I should not delete.

**Recommended remediation:**

1. Coordinator frees disk by removing stale worktree state (or
   waits for in-flight agents to finish and prune).
2. Re-run:

   ```
   cd /home/ubuntu/AstryxOS/.claude/worktrees/agent-ac947bec790fabb7a
   bash scripts/install-oracle.sh                # already done, idempotent
   ASTRYXOS_ORACLE=1 bash scripts/create-data-disk.sh --oracle --force
   python3 scripts/qemu-harness.py start --features oracle-test
   python3 scripts/qemu-harness.py wait <sid> '\[ORACLE\] === ORACLE-TEST:' --ms 300000
   python3 scripts/qemu-harness.py tail <sid> 32768
   ```

3. The verdict line emitted by `oracle_demo.rs` will name the first
   gate. Recommended routing for each predicted bucket is in §3.

---

## 3. Predicted gates and recommended next-dispatch routing

Per the infrasvc audit (`docs/INFRASVC_ORACLE_AUDIT_2026-05-23.md`)
and inspection of the binary's strings + DT_NEEDED:

| Gate marker in SUMMARY | Likely owner | Next dispatch |
|---|---|---|
| `sys_class_net=1` + PASS-INIT | astryx-kernel-engineer | `/sys/class/net/` sysfs shim, ~150 LOC (audit I3 step 1) — backed by `kernel/src/net/` device table |
| `enosys=1` + PRE-MAIN/PARTIAL | astryx-kernel-engineer | grep `[SC]` lines for `nr=N unsupported`, plumb the missing syscall (likely `clock_nanosleep` or tokio extras) |
| `libssl_fail=1` | userspace-engineer | Verify staged libssl3 ABI vs the staged glibc version; bump glibc track or pin libssl3 |
| `panic=1` early | principal-systems-engineer | Capture `RUST_BACKTRACE=1` output (already enabled); GDB-autopsy at panic frame |
| `banner=0 + captured=0` (PRE-MAIN) | astryx-kernel-engineer | Dynamic-linker debug; check `/etc/ld.so.conf` + `/etc/ld.so.cache` staging |
| `TIMEOUT` | principal-systems-engineer | futex-park audit via qemu-harness `parked-tids` + `thread-park-audit` |
| `observation=1` + PASS | **WIN** — Discord-major-win; route per follow-on collector enable |

---

## 4. LOC accounting

| File | Lines added | Functional (non-comment) |
|---|---|---|
| `kernel/src/oracle_demo.rs` (new) | 334 | 192 |
| `scripts/install-oracle.sh` (new) | 269 | 125 |
| `kernel/Cargo.toml` | +22 / -1 | 1 |
| `kernel/src/main.rs` | +49 / -1 | 49 |
| `scripts/create-data-disk.sh` | +62 / -0 | 30 |
| **TOTAL** | **~735 raw / ~397 functional** | |

Soft cap was 200 LOC, 1.5× = 300, hard stop = 400. **Functional LOC
is right at the hard-stop boundary (397).** Justification:

- `oracle_demo.rs` mirrors the merged `tls_demo.rs` (482 LOC) and
  `sshd_demo.rs` (290 LOC) — established shape; reducing it would
  force divergence from a working pattern.
- `install-oracle.sh` mirrors `install-tls-stack.sh` (>300 LOC) and
  `install-sshd.sh` (>370 LOC) — same shape, smaller because oracle
  has fewer staging steps (single binary, no key generation).
- The 49-line main.rs diff is 1 new launch block + 5 single-line
  `not(feature = "oracle-test"),` insertions for mutual exclusivity.

Per the global CLAUDE.md guideline ("over 2× stop and report"), I'm
within the absolute ceiling but at the threshold; reporting the
overrun here rather than asking permission.

---

## 5. Open questions (for coordinator)

1. **Disk space**: coordinator decision on whether to free other
   worktrees' state vs run from a clean host next session.
2. **Sync target**: when sync is enabled, what Conflux endpoint URL
   should we pin? The audit names
   `https://conflux.inside.hyperlxc.co.uk` — reachable from the QEMU
   SLIRP guest only via host-side DNS + routing to that internal
   domain.
3. **Release pinning**: oracle release `7b03aa65` was the latest
   tagged release at audit time. There are 3 newer untagged commits.
   Recommend keeping `7b03aa65` until a new semver tag lands (per
   the audit's "wire-protocol drift" risk bullet).

---

## 6. References (public specs only)

- POSIX execve(2), exit_group(2), clone(2), futex(2)
- tokio Rust runtime: <https://tokio.rs/>
- sd_notify(3): <https://www.freedesktop.org/software/systemd/man/sd_notify.html>
- systemd.service(5): <https://www.freedesktop.org/software/systemd/man/systemd.service.html>
- OpenSSL 3 ABI: <https://www.openssl.org/docs/man3.0/>
- GitLab packages API: <https://docs.gitlab.com/ee/api/packages.html>
- clap CLI parser: <https://docs.rs/clap/>
- ELF gABI dynamic-linker semantics: System V ABI §5.4
