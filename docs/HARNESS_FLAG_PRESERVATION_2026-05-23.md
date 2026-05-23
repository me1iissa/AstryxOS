# Harness variant-pin restage drops user demo-binary flags (2026-05-23)

## The wart

The Firefox variant-pin guard added in PR #378 auto-invokes
`scripts/create-data-disk.sh --force` when the data disk's staged Firefox
layout (musl vs glibc) does not match the variant requested by the
harness `--firefox-variant` option.  The auto-invocation only forwards
the `ASTRYXOS_FIREFOX_VARIANT` environment variable; it does not
forward any other staging opt-in.

PR #439 (oracle staging) introduced the first such opt-in that bites:
`--oracle` / `ASTRYXOS_ORACLE=1`.  When the agent ran:

```
ASTRYXOS_ORACLE=1 bash scripts/create-data-disk.sh --oracle --force   # baseline
python3 scripts/qemu-harness.py start --features oracle-test \
    --firefox-variant glibc
```

…the harness detected a variant mismatch (existing data.img was musl),
spawned `ASTRYXOS_FIREFOX_VARIANT=glibc bash scripts/create-data-disk.sh
--force`, and the data-disk builder re-created the image **without** the
`--oracle` opt-in.  Oracle and its glibc-linked TLS libs vanished, and
the kernel's `oracle-test` first-boot path reported

```
[ORACLE] FATAL: cannot read /disk/usr/bin/oracle: NotFound
```

on the next boot — a staging failure mis-attributed to a kernel bug.

The same gap exists for `--sshd` / `ASTRYXOS_SSHD=1` (PR #434) and
`--tls` / `ASTRYXOS_TLS=1` (PR #438).  Without this fix, any future
opt-in repeats the wart.

## The fix

### `scripts/qemu-harness.py`

1. `_regen_data_img` accepts two new optional parameters,
   `extra_flags: list[str]` and `extra_env: dict[str, str]`, appended
   to the create-data-disk.sh argv (after `--force`) and layered onto
   the child env respectively.  The function also returns `argv` and
   `env_overrides` in its result dict for debuggability.

2. A new helper, `_resolve_demo_binary_flags(features, env)`, derives
   the (--flag, ENV=1) set from two additive sources:

   | Source | Precedence | Example |
   |---|---|---|
   | `ASTRYXOS_ORACLE` / `_SSHD` / `_TLS` env vars | 1 (winning) | `ASTRYXOS_ORACLE=1` → `--oracle` |
   | Cargo features `oracle-test` / `sshd-test` / `tls-test` | 2 (fallback) | `--features oracle-test` → `--oracle` |

   Truthy env values are `1`, `true`, `yes`, `on` (case-insensitive).
   Per-flag source (`"env"` / `"feature"` / `None`) is recorded so the
   resolution is auditable from `events <sid>` JSON.

3. `cmd_start` computes the resolved flag set once via
   `_resolve_demo_binary_flags(feats)` and passes the result into both
   `_regen_data_img` call sites (staleness-driven regen + variant-
   mismatch regen) so neither path can silently drop staging intent.

4. The pre-restage banner now shows `preserved demo flags: <list>` so
   the propagation is visible in stderr; the result is also recorded
   in `firefox_variant_info.restage_extra_flags`,
   `.restage_extra_env`, and `.restage_flag_sources`, and folded into
   the `firefox_variant_requested` event.

All harness output changes are **additive** — new keys appear on
existing JSON objects; no field renames; no semantic shifts in
existing keys.  Downstream agents tolerating extra keys (the harness
contract) continue to work unchanged.

### `scripts/create-data-disk.sh`

Independently caught while reproducing the oracle staging failure:
the `openssl.cnf` mtools copy at the TLS-stack staging step did not
ensure its parent FAT32 directory existed before `mcopy`.  When a
preceding step (the CA-bundle copy) did not run — for instance when
the bundle was not staged or when the staged bundles took different
paths — `mcopy ... ::etc/ssl/openssl.cnf` failed with
`no match for target`.

Fixed by adding idempotent `mmd -i "${DATA_IMG}" "::etc"` and
`mmd -i "${DATA_IMG}" "::etc/ssl"` calls (each with the standard
`2>/dev/null || true` guard for the "already exists" case) before the
`mcopy` line.  An audit of every other `mcopy` call writing to a
multi-level FAT32 path showed all other sites already had matching
`mmd` guards.

Reference: mtools(1) `mcopy` does NOT auto-create parent directories
(unlike GNU `cp --parents`), and `mmd -p` is not portable across
mtools versions; explicit chained `mmd` calls are the documented
pattern (see `mtools(1)` and `mtools.conf(5)`).

## Verification

End-to-end run against the worktree's harness with oracle pre-staged:

```
ASTRYXOS_ORACLE=1 bash scripts/create-data-disk.sh --oracle --force
ASTRYXOS_ORACLE=1 python3 scripts/qemu-harness.py start \
    --features oracle-test --firefox-variant glibc
```

Harness output (stderr) excerpt:

```
║  Firefox variant mismatch — re-staging data.img              ║
║  staged: musl       requested: glibc                       ║
║  Running scripts/create-data-disk.sh --force with            ║
║  ASTRYXOS_FIREFOX_VARIANT=glibc                              ║
║  preserved demo flags:    --oracle                           ║
╚══════════════════════════════════════════════════════════════╝
║  variant re-stage OK in 51.0s (now musl-esr).
[VARIANT-PIN] requested=glibc staged=musl action=restaged-ok
```

Post-restage data.img audit (`mdir -i build/data.img ::/usr/bin |
grep oracle`):

```
oracle         5042136 2026-05-23  22:08
```

Oracle SURVIVED the auto-restage.

Kernel first-boot oracle-test serial excerpt:

```
[ORACLE] oracle-test starting (PIVOT-I2, 2026-05-23)
[ORACLE] Loaded /disk/usr/bin/oracle (5042136 bytes)
[ORACLE] Spawning oracle with argv=["oracle", "--mode", "console",
         "--once", "--log-level", "debug", "--config",
         "/etc/oracle/config.toml"]
[ORACLE] oracle spawned: pid=1
[ORACLE] oracle | oracle: error while loading shared libraries:
         libzstd.so.1: cannot open shared object file:
         No such file or directory
[ORACLE] === SUMMARY === banner=0 collector_init=0 observation=0 ...
         exit=127 state=Zombie captured_bytes=118 timed_out=0
[ORACLE] === ORACLE-TEST: PARTIAL (some stdout but no banner;
         exit=127; first bytes may name the loader gate) ===
[ORACLE] DONE
```

## New oracle first-gate

The previous failure (`FATAL: cannot read /disk/usr/bin/oracle:
NotFound`) is no longer observed — the harness-side flag-preservation
fix removes it.  The new first-gate, surfaced now that oracle can
actually load, is:

> **`libzstd.so.1: cannot open shared object file`** — exit 127 from
> the glibc ELF loader.

This is a staging gap in `scripts/install-oracle.sh` /
`scripts/install-glibc.sh`: the oracle binary's `DT_NEEDED`
transitively pulls in `libzstd.so.1` (via `libssl3` or `libcrypto3`
on some host-glibc distributions), but neither installer copies the
host's `/lib/x86_64-linux-gnu/libzstd.so.1` into
`build/disk/lib/x86_64-linux-gnu/`.

Fixing it is the next dispatch — out of scope for this harness fix.

## Suggested next work

- Stage `libzstd.so.1` (and any other oracle DT_NEEDED transitives
  the host's glibc-linked oracle expects) into the data disk via
  `scripts/install-oracle.sh` or a new helper.  Re-run the soak —
  the kernel-side `oracle-test` path should then either reach
  `[ORACLE] === ORACLE-TEST: PASS ===` or surface the next legitimate
  runtime gate (sysfs probe failure, /proc not yet mounted, etc.).

## References

- Public spec: mtools(1) — mcopy parent-directory semantics
- Public spec: ELF gABI (System V ABI §5.4) — DT_NEEDED resolution
