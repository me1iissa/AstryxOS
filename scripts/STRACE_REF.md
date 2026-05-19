# strace-ref — Linux reference captures for ABI conformance

A small toolchain that runs the **exact musl-linked `firefox-esr` binary AstryxOS
ships** under the host's real Linux kernel, captures `strace` output, and diffs
it against AstryxOS serial logs.  It exists so abi-compatibility work has a
ground-truth baseline: when AstryxOS shows a wedge or unexpected syscall
pattern, you can answer "does Linux behave the same way against this binary?"
in seconds.

## Why not LXC / KVM?

We use `bwrap` (bubblewrap) into an Alpine 3.20 rootfs that the AstryxOS build
already produces under `~/.cache/astryxos-firefox-musl/rootfs/`.  Reasons:

- **Identical binary**: same `firefox-esr-115.24.0esr` (musl), bit-for-bit, as
  the one staged into `build/disk/usr/lib/firefox-esr/`.
- **Real Linux kernel**: bwrap is a kernel-namespace sandbox, not a VM.  Every
  syscall the binary makes goes to the host's real Linux kernel — exactly the
  reference behaviour we want.
- **Sub-second entry**: ~50 ms cold start vs ~5-10 s for a KVM/Alpine VM boot.
- **No extra disk**: we reuse the rootfs the AstryxOS build already produced,
  no second copy.

LXC / a full Alpine VM remain available as a fallback if you need PID/network
isolation we don't get from bwrap; the harness ships only the bwrap path for
now because it's enough for futex/clone/signal/mmap tracing.

## Subcommands

All commands print a single JSON object to stdout and exit.

### setup

Verify the Alpine reference rootfs.  Reports the firefox-esr version, whether
the launcher is musl-linked, and the captures directory.

```
python3 scripts/qemu-harness.py strace-ref setup
# or:
python3 scripts/strace-ref.py setup
```

If no rootfs is found, pass `--bootstrap` to invoke
`scripts/install-firefox-musl.sh` (which downloads Alpine + apk-installs
firefox-esr).

### capture

Run firefox-esr under `strace -f -e trace=futex` inside a bwrap sandbox.

```
python3 scripts/qemu-harness.py strace-ref capture \
    --label ref-about-blank \
    --binary-args="--headless --screenshot=/root/out.png about:blank" \
    --timeout 30
```

Output trace lives at `~/.astryx-harness/strace-ref/captures/<label>.trace`.

Useful flags:

| flag | default | meaning |
|------|---------|---------|
| `--label` | `ref-YYYYMMDD-HHMMSS` | Capture label / filename stem |
| `--binary-args` | `--version` | Args passed to firefox-esr (shlex-split) |
| `--syscall-filter` | `futex` | strace `-e trace=` filter; comma-list ok |
| `--timeout` | `60` | Wall-clock cap in seconds |
| `--env KEY=VAL` | — | Extra env var (repeatable) |
| `--output` | (under captures dir) | Override trace output path |
| `--no-follow-forks` | (follow) | Drop strace `-f` |
| `--no-timestamps` | (with timestamps) | Drop strace `-ttt` |

The stats block on stdout summarises the trace:

```json
{
  "stats": {
    "lines": 21355,
    "by_op": {"WAKE": 5935, "WAIT": 5359, "WAIT_BITSET": 129, "REQUEUE": 2},
    "tids": [879932, 879933, ...],
    "n_tids": 64,
    "size_bytes": 1937412
  }
}
```

### diff

Compare a captured Linux trace against an AstryxOS serial log.

```
python3 scripts/qemu-harness.py strace-ref diff \
    --linux-trace ~/.astryx-harness/strace-ref/captures/ref-about-blank.trace \
    --astryx-log  ~/.astryx-harness/9eb335f19366.serial.log
```

Output schema:

```json
{
  "ok": true,
  "linux":  {"path": "...", "stats": {...}},
  "astryx": {"path": "...", "stats": {...}},
  "comparison": {
    "by_op": [
      {"op": "WAKE", "linux": 5935, "astryx": 389, "delta": -5546, "ratio": 0.065},
      ...
    ],
    "only_in_linux":  ["REQUEUE"],
    "only_in_astryx": []
  },
  "notes": [
    "Linux emitted 1 op class(es) absent from AstryxOS: ['REQUEUE']. Possible ABI-coverage gap.",
    "AstryxOS futex volume is 706 vs Linux 11425 (6.2%). Consistent with a userspace plateau ...",
    "AstryxOS emitted [FUTEX_WAKE_GHOST] x11 — FUTEX_WAKE delivered to a uaddr with NO registered waiter ..."
  ]
}
```

The `notes` field is the human-actionable summary: ABI gaps, volume plateaus,
ghost-wake / timeout signatures.

### list / clean

```
python3 scripts/qemu-harness.py strace-ref list
python3 scripts/qemu-harness.py strace-ref clean --label smoke-test
```

## How AstryxOS [FUTEX_*] tags map to Linux strace ops

AstryxOS emits more granular logging than Linux strace:

| AstryxOS tag | Linux analogue | Notes |
|---|---|---|
| `[FUTEX_WAIT_REG]`  | `futex(..., FUTEX_WAIT*)` entry  | Counted in `by_op` |
| `[FUTEX_WAKE_REQ]`  | `futex(..., FUTEX_WAKE*)` entry  | Counted in `by_op` |
| `[FUTEX_WAKE]`      | `futex(..., FUTEX_WAKE*)` return | Skipped (would double-count `_REQ`) |
| `[FUTEX_WAIT_STACK]` | (no analogue) | Kernel diagnostic: waiter backtrace |
| `[FUTEX_TIMEDOUT]`   | (no analogue) | Diagnostic: `FUTEX_WAIT_*` returned `-ETIMEDOUT` |
| `[FUTEX_WAKE_GHOST]` | (no analogue) | Diagnostic: WAKE delivered with no registered waiter |
| `[FUTEX_CLUSTER_WAKE]` | (no analogue) | Diagnostic: bounded-broadcast compensation |
| `[FUTEX_WAKE_EXIT]` | (no analogue) | Diagnostic: WAKE outcome list |

The diff tool surfaces non-zero diagnostic-tag counts as `notes` because they
are precisely the AstryxOS wedge signatures abi-compat investigations care
about.

The `op_class` mapping handles the standard Linux futex op constants:

| op (low 7 bits) | class |
|---|---|
| 0  | `WAIT` |
| 1  | `WAKE` |
| 3  | `REQUEUE` |
| 4  | `CMP_REQUEUE` |
| 5  | `WAKE_OP` |
| 6  | `LOCK_PI` |
| 7  | `UNLOCK_PI` |
| 9  | `WAIT_BITSET` |
| 10 | `WAKE_BITSET` |

`FUTEX_PRIVATE_FLAG` (0x80) and `FUTEX_CLOCK_REALTIME` (0x100) are stripped
before classification on both sides.

## One-liner for abi-compat

```
python3 scripts/qemu-harness.py strace-ref capture --label abi-ref-$(date +%Y%m%d) \
    --binary-args="--headless --screenshot=/root/out.png about:blank" --timeout 60 && \
python3 scripts/qemu-harness.py strace-ref diff \
    --linux-trace ~/.astryx-harness/strace-ref/captures/abi-ref-$(date +%Y%m%d).trace \
    --astryx-log  ~/.astryx-harness/<sid>.serial.log
```

For a different syscall surface (e.g. clone/signal investigations), swap
`--syscall-filter=futex` to `--syscall-filter="clone,rt_sigaction,rt_sigreturn"`
or any strace `-e trace=` selector.

## Smoke test

```
python3 scripts/strace-ref-smoke.py
```

Exits 0 if all 11 checks pass; 1 otherwise.

## Disk usage

| path | size |
|------|------|
| `~/.cache/astryxos-firefox-musl/rootfs/` | ~360 MB (shared with AstryxOS build) |
| `~/.astryx-harness/strace-ref/captures/` | ~1-2 MB per minute of strace |

Run `strace-ref clean --label <substring>` periodically.

## References

- `strace(1)`:  <https://man7.org/linux/man-pages/man1/strace.1.html>
- `bwrap(1)`:   <https://github.com/containers/bubblewrap>
- `futex(2)`:   <https://man7.org/linux/man-pages/man2/futex.2.html>
- Alpine 3.20: <https://www.alpinelinux.org/posts/Alpine-3.20.0-released.html>
- musl libc:   <https://musl.libc.org/>
