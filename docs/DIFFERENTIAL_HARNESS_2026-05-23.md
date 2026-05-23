# Differential bytestream harness (INFRA-1)

Status: landed 2026-05-23.

## Why

The Firefox demo has stalled in a local minimum: dozens of falsified
"saga" hypotheses, growing diagnostic infrastructure, but no continuous
*differential* observation between a reference Linux kernel and AstryxOS
running the same musl `firefox-bin`.  Each saga starts from a guess
("maybe it's TLS canary corruption", "maybe it's vfork stack drift")
rather than from a named ABI divergence.

INFRA-1 is the missing tool: a single argv invocation that produces a
structured JSON object naming the FIRST place the two kernels' syscall
streams diverge.

## What it does

`differential-soak` orchestrates three steps:

1. **Linux reference run** — `scripts/strace-ref.py capture` runs the
   exact same musl `firefox-esr` shipped in AstryxOS's data.img under
   the **host kernel** via `bwrap` (no virtualisation), capturing
   `strace -f -e trace=all -ttt -y -s256`.

2. **AstryxOS QEMU run** — `scripts/qemu-harness.py start --features
   firefox-test,differential-trace` boots AstryxOS, which emits
   `[SC] pid=… tid=… nr=… rip=… cr=… a1=…a6=…` and paired
   `[SC-RET] pid=… tid=… nr=… ret=…` lines per Linux syscall
   (gated on `syscall-trace`, pre-existing).

3. **Diff engine** — Both streams parse into a unified record shape
   `{pid, tid, name, nr, args[], ret, errno, rip?}`, are aligned by
   ordinal position, and walked in lock-step.  The first record where
   `nr`, `ret` (sign or value) differs is the verdict.

The output is a single JSON object printed to stdout (and optionally to
`--output PATH`):

```json
{
  "ok": true,
  "subcommand": "differential-soak",
  "linux":  {"trace_path": "...", "calls_parsed": 1234, ...},
  "astryx": {"sid": "...",  "calls_parsed": 567,  ...},
  "first_divergence": {
    "sc_index": 12,
    "kind": "retval_value",
    "linux":  {"name": "futex",       "nr": 202, "ret":  0, ...},
    "astryx": {"name": "futex",       "nr": 202, "ret": -38, ...}
  },
  "summary": {
    "linux_total_calls":   1234,
    "astryx_total_calls":   567,
    "aligned_calls":         11,
    "divergence_class": "retval_value"
  },
  "context_lines": {"window_start": 6, "linux": [...], "astryx": [...]},
  "snapshot_hits": [...]
}
```

`kind` is one of:
- `missing_or_extra_call` — different syscall number at the same ordinal.
- `retval_sign` — same nr, but Linux returned `>=0` and AstryxOS `<0`
  (or vice versa) — the textbook ABI gap.
- `retval_value` — same nr, same sign, different magnitude.
- `linux_truncated` / `astryx_truncated` — one stream ended early.
- `no_divergence` — streams matched out to whichever ran shorter.

## Usage

End-to-end (fresh run on both sides):

```
python3 scripts/qemu-harness.py differential-soak \
    --astryx-features firefox-test,differential-trace \
    --max-syscalls 200 \
    --output /tmp/diff.json
```

Iterate quickly using a previously captured Linux trace and a known-good
AstryxOS serial log:

```
python3 scripts/qemu-harness.py differential-soak \
    --reuse-linux-capture diff-20260523-153000 \
    --reuse-astryx-log    ~/.astryx-harness/abc123.serial.log \
    --output /tmp/diff.json
```

Run only the Linux side once a day, reuse for many AstryxOS iterations:

```
# Capture once.
python3 scripts/qemu-harness.py strace-ref capture --label daily \
    --binary-args "--headless --screenshot=/tmp/x.png http://example.com" \
    --syscall-filter all --timeout 30

# Iterate.
python3 scripts/qemu-harness.py differential-soak \
    --reuse-linux-capture daily \
    --output /tmp/diff.json
```

## Snapshot configuration

Per-syscall memory snapshot trigger points live in
`scripts/differential/snapshots.yaml`.  Each entry names a syscall
boundary (`post_execve`, `post_arch_prctl_set_fs`,
`post_vfork_parent_return`, `post_clone_child`, `post_futex_wake`,
`pre_fatal_pf`) and a list of memory regions to capture
(`fs_base`, `stack_near_rbp`, `tls_canary`, `fixed_va`, `elf_aux`).

In the current build the snapshot config is **advisory**: the diff
output's `snapshot_hits[]` list records every time a configured trigger
fires, with the matching syscall records on both sides.  When a future
kernel-side hook emits explicit `[SNAP/<name>]` lines with hex region
contents, the engine will lift the comparison into the first-divergence
verdict directly.  The hook is in place — extending the kernel side is
a separate, additive change.

Add new snapshot points by appending YAML entries; no Python edit
needed.

## Architectural invariants honoured

- **Never edits upstream binaries.**  The Linux side runs the same
  musl `firefox-esr` shipped in `data.img`, unmodified, under
  `bwrap`.  The AstryxOS side runs the same binary.  Any divergence
  reported is necessarily an AstryxOS-kernel ABI gap.
- **Agent-friendly.**  One-shot `argv`, structured JSON output, no
  REPL, no interactive prompts.  All state lives on disk
  (`~/.astryx-harness/strace-ref/captures/`,
  `~/.astryx-harness/<sid>.serial.log`,
  `~/.astryx-harness/differential/`).
- **Additive harness change.**  New subcommand and new JSON fields;
  no existing field renamed; no behaviour change to existing
  subcommands.
- **Kernel build feature is additive.**  `differential-trace` is a
  meta-feature aliasing `firefox-test + syscall-trace` (both
  pre-existing).  No new code paths.

## Public references

- strace(1) — https://man7.org/linux/man-pages/man1/strace.1.html
- bwrap(1) — https://github.com/containers/bubblewrap
- ptrace(2) — https://man7.org/linux/man-pages/man2/ptrace.2.html
- System V AMD64 ABI — https://gitlab.com/x86-psABIs/x86-64-ABI
- Linux syscall table — kernel.org Documentation/admin-guide/syscalls/
- POSIX-2017 — https://pubs.opengroup.org/onlinepubs/9699919799/
