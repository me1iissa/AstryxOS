# INFRA-3 — Crude Record/Replay Primitives (2026-05-23)

## Why

The Firefox SSP-canary saga (and several preceding investigations) has
been blocked by the fact that the same userspace workload, on the same
boot, produces slightly different syscall sequences and slightly
different RIPs across runs.  Without a deterministic reproducer there
is no way to walk *backwards* in time from a single observed failure —
every bisect requires N fresh runs and a probabilistic guess at where
the divergence occurred.

INFRA-3 buys ~80% of the value of a full rr-style record/replay
infrastructure (which is a multi-month build) at ~5% of the cost.  It
does NOT replay execution back through the kernel.  It simply pins
down the three biggest sources of run-to-run divergence:

1. **The kernel PRNG** (ASLR, `AT_RANDOM`, `getrandom(2)`).
2. **The kernel clock** (`clock_gettime`, `gettimeofday`, vDSO fallback).
3. **The per-syscall trace ordering** (now carries a strictly
   increasing ordinal tied to a frozen virtual tick counter).

With those pinned, two runs of the same workload (same binary, same
data disk, same QEMU CPU model, same SMP count, same RNG seed) emit
byte-identical `[SC-REC]` streams for the first several hundred
syscalls.  Divergence after that point names its own cause via the
ordinal: the first `[SC-REC]` line that differs between two runs is
the divergence point, and the contents of the line (sc number, args,
RIP, FS_BASE, vfork generation) is enough information to walk
backwards through the serial logs and figure out *why* one run took
the other branch.

## Cargo feature

Everything is gated behind `record-replay` in `kernel/Cargo.toml`.
Off by default; default kernel builds are byte-identical to the
pre-PR artefact.  Enable with:

```
python3 scripts/qemu-harness.py start --features "firefox-test,record-replay"
```

Combine with `kdb` to access the new `record-status` and
`replay-dump` introspection ops, and with `syscall-trace` to also
get the legacy `[SC]` / `[SC-RET]` pair side-by-side with `[SC-REC]`.

## Cmdline transport: QEMU fw_cfg

The harness passes the PRNG seed via QEMU `-fw_cfg`:

```
python3 scripts/qemu-harness.py start \
    --features "firefox-test,record-replay,kdb,syscall-trace" \
    --extra-arg '-fw_cfg' \
    --extra-arg 'name=opt/astryx/cmdline,string=astryx.rng_seed=0xCAFEF00DCAFEF00D'
```

The kernel reads the `opt/astryx/cmdline` blob via the legacy fw_cfg
I/O ports 0x510 (selector) / 0x511 (data) — see QEMU
`docs/specs/fw_cfg.txt` for the protocol.  Tokens recognised on the
cmdline:

| Token | Type | Meaning |
|---|---|---|
| `astryx.rng_seed=<u64>` | dec or `0x`-hex | PRNG seed; default `0xA577_E470_57ED_7E57` when absent |

When the fw_cfg device is absent (bare metal, non-QEMU hypervisors),
the kernel falls back to the default seed and continues to be
deterministic across runs on that host.

## What this layer guarantees

1. **Same seed → same `rand_u64` sequence.**  Every consumer of
   `crate::security::rand::rand_u64()` is routed through the
   deterministic xorshift64* PRNG.  This includes:
   - mmap ASLR (`crate::mm::vma::aslr_*`)
   - interpreter / executable ASLR (`crate::proc::elf::aslr_*`)
   - PE-loader ASLR (`crate::proc::pe`)
   - stack ASLR jitter (`crate::mm::vma::STACK_ASLR_BITS`)
   - `AT_RANDOM` aux-vector entry (16 bytes; SSP canary seed)
   - `getrandom(2)` (Linux syscall 318) — bypasses RDRAND entirely

2. **Same syscall sequence → same `clock_gettime` returns.**
   `KERNEL_VIRTUAL_TICKS` advances on:
   - syscall entry (+1)
   - syscall exit  (+1)
   - timer ISR's publishing CPU (+1 per real wall-clock tick)
   `clock_gettime(2)` (all clock-ids, both HRES and COARSE),
   `gettimeofday(2)`, and any in-kernel time-of-day consumer that
   goes through these paths derive `(secs, nsecs)` from
   `KERNEL_VIRTUAL_TICKS` interpreted at 1 GHz (1 tick = 1 ns).
   The wall-clock epoch is pinned to `1_700_000_000`
   (2023-11-14T22:13:20Z) so CLOCK_REALTIME is reproducible without
   relying on the CMOS RTC.

3. **Same workload → same `[SC-REC]` stream.**  Every Linux dispatch
   entry emits one self-describing JSON-shaped serial line:
   ```
   [SC-REC] {"ord":123,"vt":246,"pid":1,"tid":1,"sc":56,"a1":"0x...","a2":"0x...","a3":"0x...","a4":"0x...","a5":"0x...","a6":"0x...","rip":"0x...","fs":"0x...","gen":0}
   ```
   Fields:
   - `ord`  — strictly increasing sequence ordinal (total order across
              all CPUs).
   - `vt`   — `KERNEL_VIRTUAL_TICKS` value at entry.
   - `pid`/`tid` — current process / thread.
   - `sc`   — Linux syscall number.
   - `a1..a6` — full six-argument register frame.
   - `rip`  — user RIP at the `SYSCALL` instruction.
   - `fs`   — live `IA32_FS_BASE` MSR (Intel SDM Vol. 3A §3.4.4.1).
   - `gen`  — per-process VmSpace generation counter (0 when the
              process table couldn't be locked non-contentiously).

   The line is also pushed into an in-RAM bounded log (cap 8192 entries)
   which the `replay-dump` KDB op can write to a VFS path in one shot
   for offline diff.

## KDB ops

```
$ python3 scripts/qemu-harness.py kdb <sid> record-status
{"enabled":true,"seed":"0xcafef00dcafef00d","virtual_ticks":1248,"ordinal":624}

$ python3 scripts/qemu-harness.py kdb <sid> replay-dump path=/tmp/rec1.jsonl
{"ok":true,"records":624,"path":"/tmp/rec1.jsonl"}
```

When the `record-replay` feature is OFF, both ops return a stable
"feature off" JSON so harnesses that always query them don't error
out:

```
{"enabled":false}
{"ok":false,"error":"record-replay feature off"}
```

## Known non-deterministic sources (NOT addressed by this layer)

These are explicitly out of scope for the cheap version.  Document
them here so a future investigator knows where to look when their
two `[SC-REC]` streams diverge before the workload's bug fires.

| Source | Effect on `[SC-REC]` | Mitigation |
|---|---|---|
| Async disk I/O completion order (virtio-blk) | Reorders post-I/O syscalls when two threads issue concurrent reads | Run with `--smp 1` or serialise I/O at the userspace test driver |
| Inter-CPU IPI arrival latency (TLB shootdown) | Threads on different CPUs may observe slightly different schedule-resume orderings | Same |
| SMP scheduler choices between equal-priority ready threads | Two ready threads → arbitrary pick | Same |
| Host TSC drift under KVM `-cpu host` across vCPUs | Visible only via vDSO direct reads, which bypass our virtual-tick override | Use `--cpu qemu64,+invtsc` (already TCG default) |
| KVM-emulated `RDTSC` reordering vs the deterministic virtual tick | Userspace that reads TSC directly will see real-time noise | Out of scope — kernel can't intercept user-mode RDTSC without trap-on-RDTSC (Intel SDM Vol. 3A §25.6.5), which costs ~50 ns per read |
| `rand_u64` concurrent CAS contention | The *sequence* of values is deterministic but the *assignment* of values to CPUs is not | For single-threaded workloads (Firefox bringup window) this is observed not to matter; for multi-threaded workloads, instrument each call site to read sequentially |

## Validation protocol

The PR is validated by running `firefox-test` twice with the same
seed and diffing the resulting `[SC-REC]` streams.

```
# Trial 1
python3 scripts/qemu-harness.py start --features "firefox-test,record-replay,kdb,syscall-trace" \
    --extra-arg '-fw_cfg' --extra-arg 'name=opt/astryx/cmdline,string=astryx.rng_seed=0xCAFEF00DCAFEF00D'
# (capture serial log)
python3 scripts/qemu-harness.py stop <sid>

# Trial 2 (same flags)
# ...

# Diff
grep '^\[SC-REC\]' trial1.log | head -500 > trial1.recs
grep '^\[SC-REC\]' trial2.log | head -500 > trial2.recs
diff trial1.recs trial2.recs
```

The target is **zero diff for the first 500 records**.  Reality may
diverge earlier — when it does, the first diverging record names
its own cause (`sc`, `pid`, `tid`, `gen`).  Update the "Known
non-deterministic sources" table above when a new divergence cause
is identified and explain whether it's been addressed, deferred, or
declared out of scope.

## References (public specs only)

- QEMU `docs/specs/fw_cfg.txt` — firmware config I/O port protocol.
- Intel SDM Vol. 1 §17.17 — Time-Stamp Counter semantics.
- Intel SDM Vol. 3A §3.4.4.1 — `IA32_FS_BASE` MSR.
- Intel SDM Vol. 3A §25.6.5 — RDTSC exiting (VMX control).
- kernel.org `Documentation/timers/timekeeping.rst`.
- POSIX `clock_gettime(3)`, `gettimeofday(3)`, `getrandom(3)`.
- George Marsaglia, "Xorshift RNGs" — J. Stat. Softw. 8(14), 2003.
