# GDB-autopsy wrapper — `qemu-harness.py autopsy`

**Status**: shipped 2026-05-23. INFRA-2 of the post-saga tooling investment.
**Scope**: replace the "add another printk" anti-pattern with structured GDB
captures. Mandatory first probe for any fault investigation.

---

## Why this exists

Across the last six weeks of Firefox-port saga work, the dominant debugging
pattern has been:

1. Fault fires (`STACK_CANARY_CORRUPT`, `#GP`, `#UD`, hang at `__stack_chk_fail`).
2. Agent looks at the serial log, guesses at a cause.
3. Agent adds a diagnostic ring buffer (`STACK_PROV`, `PTE_CHANGE_RING`,
   `ALLOC_SHADOW`, `FREE_SHADOW`, `K2b DR-watchpoint`, `D7 BSS-watch`,
   `D8 fault-time TLS dump`, ...).
4. Rebuild, re-soak, read the ring buffer, propose a fix, re-soak.
5. Fix is falsified by the next 3-trial soak; back to step 1.

14+ hypotheses on `STACK_CANARY_CORRUPT` alone have been falsified this way,
and the underlying reason is that **the GDB stub was right there the whole
time**, but using it required:

- A multi-step interactive GDB session against a moving QEMU target.
- Hand-parsing scrollback (`info registers`, `bt full`, `x/64gx ...`).
- Re-typing the same 8–10 commands on every hit.
- Manually correlating ASLR-biased RIPs to library offsets.

So agents reached for a fresh printk every time. The autopsy wrapper closes
that gap.

## What it is

`qemu-harness.py autopsy` is a one-shot argv invocation that:

1. Arms one or more breakpoints on the live GDB stub.
2. Resumes the guest, waits for any breakpoint to hit (bounded by
   `--timeout-ms`).
3. On each hit, runs a YAML-declared **capture preset** that produces
   structured JSON: registers, named memory windows, FSBASE-relative reads,
   symbol-resolved RIP.
4. Returns the result as one JSON document on stdout (and optionally to a
   file for archival).

It honours the agent-friendly tool contract: no REPL, no interactive prompt,
no required persistent stdin. Session state lives on disk
(`~/.astryx-harness/<sid>.json`) so multiple agents / shells can interleave
invocations without stepping on each other (the wrapper takes the
existing `gdb.lock` file lock used by `rip-sample`).

## Quick usage

```bash
# Start a session with the GDB stub on TCP port 1234.
python3 scripts/qemu-harness.py start --features firefox-test --gdb-port 1234
# → {"sid": "abc123...", ...}

# Wait for the SSP fail marker to appear in the serial log.
python3 scripts/qemu-harness.py wait abc123 'STACK_CANARY_CORRUPT' --ms 180000

# Autopsy the kernel bugcheck entry.  --once is the default; the wrapper
# breaks on the first hit, snapshots state, releases the guest, exits.
python3 scripts/qemu-harness.py autopsy abc123 \
    --break ke_bugcheck \
    --capture ssp-fail-snapshot \
    --output /tmp/ssp.json
```

The JSON document on stdout has:

```jsonc
{
  "ok": true,
  "sid": "abc123",
  "preset": "ssp-fail-snapshot",
  "preset_desc": "...",
  "breakpoints": [{"label": "ke_bugcheck", "addr": "0xffff...", "armed": true}],
  "hit_count": 1,
  "timed_out": false,
  "elapsed_s": 2.341,
  "hits": [
    {
      "hit_index": 0,
      "breakpoint": {"addr": "0xffff...", "label": "ke_bugcheck", "symbol": "ke_bugcheck+0x0"},
      "stop_reply": "T05swbreak:;",
      "captures": {
        "regs":         {"kind": "regs", "regs": {"rax": "0x..", "rbx": "0x..", ..., "rip": "0x..", "fs": "0x.."}},
        "canary_slot":  {"kind": "mem_via_reg", "reg": "rbp", "offset": -16, "addr": "0x..", "bytes": "..."},
        "frame_window": {"kind": "mem_via_reg", "reg": "rbp", "offset": -128, "addr": "0x..", "bytes": "..."},
        "stack_top":    {"kind": "mem_via_reg", "reg": "rsp", "offset": 0, "addr": "0x..", "bytes": "..."},
        "tls_guard":    {"kind": "mem_via_seg", "seg": "fs", "seg_base": "0x..", "offset": 40, "addr": "0x..", "bytes": "..."},
        "arg_window":   {"kind": "mem_via_reg", "reg": "rsp", "offset": -64, "addr": "0x..", "bytes": "..."}
      }
    }
  ]
}
```

## Preset library

Presets live at `scripts/autopsy/presets.yaml`. Each preset is a named list
of capture steps; steps are one of `regs`, `mem`, `mem_at`, `mem_via_reg`,
`mem_via_seg`, `sym_window`, `note`. See the YAML header for the full schema.

Current library:

| Preset | Use when |
|---|---|
| `full-register-dump` | Minimal first probe; GPRs + segs + RFLAGS only |
| `stack-walk-bt-full` | Walk frames; registers + stack window + RBP window |
| `ssp-fail-snapshot` | SSP fail / `STACK_CANARY_CORRUPT`; canary slot at `[rbp-8]` + `fs:0x28` per sysV AMD64 ABI §11.4 TLS Variant II |
| `vfork-window` | vfork(2) gate; pre-clone frame identity capture |
| `gp-fault-context` | `#GP` at IRET/SYSRET; IRET frame + code-around-RIP |
| `bugcheck-entry` | `ke_bugcheck` entry; decodes EDI=code, RSI..R8=p1..p4 per sysV AMD64 ABI §3.2.3 |

### Adding a preset

```yaml
my-new-preset:
  description: |
    What this preset is for; when to reach for it.
  steps:
    - name: regs
      kind: regs
    - name: my_window
      kind: mem_via_reg
      reg: rbp
      offset: -64
      len: 128
```

New presets are **additive**: append the entry, no harness code change
required. Agents are encouraged to ship a preset with any non-trivial
investigation so the next agent picking up the same axis gets the
playbook for free.

## Breakpoint target syntax

`--break` accepts:

- Raw hex: `0xffffffff80123456`
- Decimal: `18446744071562068054`
- Kernel symbol: `ke_bugcheck`, `__stack_chk_fail` (if exported)
- Symbol + offset: `ke_bugcheck+0x10`

User-space symbols are not resolved through the wrapper today — for
user-space breakpoints, look up the address via `kdb procmaps` or the
ASLR-biased `[mmap-so]` line in the serial log, then pass the literal
hex address.

## Multi-hit captures

```bash
# Capture the first 3 entries into ke_bugcheck back-to-back.
python3 scripts/qemu-harness.py autopsy <sid> \
    --break ke_bugcheck \
    --capture full-register-dump \
    --once 3 --continue-after \
    --timeout-ms 30000
```

`--once N` caps the captured array length; `--continue-after` makes the
wrapper resume the guest after each hit instead of stopping at the first.
A budget of 30 s applies across **all** hits combined.

## When NOT to use autopsy

GDB breakpoints + register dumps are perfect for: anything that hits a
well-defined symbol (`ke_bugcheck`, `__stack_chk_fail`, `do_page_fault`,
`general_protection_handler`, `ud_handler`, ...).

They are **not** the right tool for:

- Concurrent-write races where the writer doesn't hold the page when the
  symptom fires. The autopsy snapshots state at the symptom site; the
  writer is already gone.
- Freed-frame writers (the W215 PTE_CHANGE_RING axis). Same reason —
  by the time the bugcheck fires, the writer is unreachable.
- Frequency / histogram questions ("how often does X happen, what does
  the distribution of Y look like"). A counter / histogram in the kernel
  is genuinely the right answer here.

For everything else — and that is the vast majority of fault investigations
— autopsy first.

## References (public specs only)

- GDB Remote Serial Protocol: <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html>
- Intel SDM Vol. 1 §3.4 (general-purpose registers)
- Intel SDM Vol. 3A §3.4.4 (FSBASE / GSBASE MSRs)
- sysV AMD64 ABI: <https://gitlab.com/x86-psABIs/x86-64-ABI>
  - §3.2 (stack frame layout, function calling convention)
  - §11.4 (TLS Variant II; `fs:0x28` per-thread stack guard)
- musl `__stack_chk_fail`: <https://git.musl-libc.org/cgit/musl/tree/src/env/__stack_chk_fail.c>
