# AstryxOS FF-headless performance benchmarking

True, durable, per-revision performance benchmarking of the Firefox-headless
screenshot test (which currently takes 30+ minutes to render a PNG) versus a
typical Linux distribution under KVM. The per-revision time-series makes
regressions and improvements visible over time.

All tools are **non-interactive and agent-friendly**: every operation is a
one-shot `argv` invocation that prints structured JSON and exits. No REPLs, no
prompts, no required persistent stdin. State lives on disk so any caller resumes.

## Components

| File | Role |
|---|---|
| `perf_markers.py` | Shared serial-marker + host-anchoring helpers. The single source of truth for the 14-phase taxonomy, the anchor table, the monotone scan, and tick→ms conversion. Reuses `serial-web.py`'s `MILESTONES` ladder when present (vendored copy otherwise, byte-identical). |
| `perf-bench.py` | The measurement driver: `run` (build/boot a revision), `import-logs` (seed from existing serial logs), `list`, `export-json`, `baseline-linux` (schema stub). Owns the record schema. |
| `perf-baseline-linux.py` | The Linux KVM "should-be" reference runner: boots stock Alpine 3.20 + the SAME upstream `firefox-esr` with the SAME launch line/URL, times the equivalent render-to-PNG path, emits a `source=baseline-linux` record. |
| `perf-web.py` | Read-only stdlib HTTP dashboard over the store. Hand-rolled inline-SVG charts, fully offline (no CDN, no pip deps). |
| `perf-bench-smoke.py`, `perf-baseline-linux-smoke.py` | Host-only smoke tests (no QEMU, no network). |

## Store layout

Two tiers (mirrored, resolved independently, by all four tools):

| Path | Committed? | Contents |
|---|---|---|
| `.perf/baseline.json` | **yes** (in-repo) | Curated **reference targets** — the AstryxOS render-to-PNG reference band and the Linux KVM baseline. Surfaced as a reference band; the rolling series is compared against it. |
| `~/.astryx-perf/timeseries.jsonl` | no (host-local) | Rolling per-run history, one JSON record per line, append-only. The full benchmark history; grows without bound, machine-local. |

Override with `ASTRYX_PERF_DIR` (timeseries) and `ASTRYX_HARNESS_DIR` (serial logs).

## Record schema (`schema_v=1`, additive-only — never rename a field)

Documented in full in `perf-bench.py`'s module docstring. Key fields:

- `revision`, `short_desc` — kernel git short-sha + subject (mtime-bisect attributed on import).
- `iso_ts` — ISO-8601 UTC of the run = the **true** host launch time.
- `host`, `kvm`, `smp`, `features`, `features_inferred`.
- `phase_ms` `{phase: ms|null}` — per-phase duration; tick axis on import, host axis on a live run.
- `phase_axis` `{phase: "tick"|"host"}` — which axis the value actually came from.
- `total_ms` (host) / `total_tick_ms` (kernel-tick proxy), `max_sc`, `deepest_phase`, `reached_png`, `panic`, `build_ms`, `source`, `sid`.

### How the recoverable truth is anchored (historical logs)

The session `<sid>.json` files do **not** survive for the historical logs, but the
recoverable truth lives in the per-session event stream:

- **`<sid>.events.jsonl` first line** (`kind: cpu_model`) carries the host `ts`
  (the true `started_at`) and `kvm_effective`. `perf_markers.event_anchor` /
  `launch_anchor` read it, so `iso_ts` is the real launch time and `kvm` is
  recovered — **not** the log mtime (which is the run-END, minutes-to-hours late).
- When even the event stream is gone, `launch_anchor` falls back to log mtime
  and labels it `launch_src="log-mtime"` so the imprecision is visible.

## The 14-phase taxonomy (MECE)

`BUILD · FIRMWARE/OVMF · KERNEL-EARLY · DRIVERS · VFS-MOUNT · INIT · FF-STARTUP ·
LIBXUL-INIT · NETWORK/TLS · RENDER-SETUP · RENDER · ENCODE · TEARDOWN`

Two axes per phase:
- **kernel-tick** (10 ms/tick at the published ~100 Hz timer) — the only axis
  recoverable from a historical log.
- **host wall-clock** — only for a live `perf-bench run`.

The render pipeline is **MECE** (no phase double-counts an interval):
`RENDER-SETUP` = screenshot→draw, `RENDER` = draw→encode-open (null when the
build emits no distinct `CrossProcessPaint`/`drawSnapshot` line), `ENCODE` =
out.png-open→PNG-magic, `TEARDOWN` = PNG-magic→pid-1-exit. The draw/encode
boundary is the real `[FF/open] /tmp/out.png` open + the `89504e47` PNG magic —
**not** the `libpng16.so` library *load* (a startup marker that fires far too
early). `reached_png` is a **global** test (PNG magic anywhere), so a successful
render is never reported as a failure even on a no-network (`file://`) run.

## Dashboard

```
python3 scripts/perf-web.py --port 8099        # then open http://localhost:8099
PERF_WEB_PORT=8099 python3 scripts/perf-web.py  # env form

# scripting without a browser:
curl -s localhost:8099/api/series    | python3 -m json.tool
curl -s localhost:8099/api/revisions | python3 -m json.tool
curl -s localhost:8099/healthz
```

The trend plots the per-revision **median** total (host `total_ms` when present,
else the `total_tick_ms` proxy) with min/max whiskers, the Linux KVM baseline as
a reference line, and a MECE stacked phase breakdown. Baseline records are a
reference band — they are **not** folded into the per-revision trend/delta series.

---

## MEASUREMENT RUNBOOK (run on a QUIET host)

This phase was pure tooling + validation against existing logs. The REAL clean
measurement below should run only when the host is idle (FF boots are
2-host-race-sensitive and ~30 min each).

### 0. Seed the time-series from existing logs (already done; re-runnable)

```
python3 scripts/perf-bench.py import-logs           # -> ~/.astryx-perf/timeseries.jsonl
python3 scripts/perf-bench.py import-logs --dry-run  # summary only, no write
```

### 1. Current-rev AstryxOS full phase breakdown (one clean boot)

```
# Build timing (REAL build: codegen + link + ESP stage — not cargo check):
python3 scripts/perf-bench.py run --build-only --features firefox-test,kdb

# Full boot + render-to-PNG, host-clock anchored (UNLOCK required):
ASTRYX_PERF_ALLOW_BOOT=1 python3 scripts/perf-bench.py run \
    --features firefox-test,kdb \
    --url file:///tmp/hello.html \
    --i-understand-this-boots --timeout-ms 2400000
```

### 2. Linux KVM baseline (the "should-be" reference)

```
# One-time: fetch the pinned Alpine 3.20 image + upstream firefox-esr (network):
python3 scripts/perf-baseline-linux.py acquire-image --do-download

# Boot the baseline and time the equivalent render-to-PNG path:
python3 scripts/perf-baseline-linux.py run --i-understand-this-boots
# (writes a source=baseline-linux record; ff_exec_to_png_ms is THE comparable figure)
```

### 3. Replay N key past revisions (the NDE render-ladder commits)

Replay the revisions that each broke a render gate, so the trend shows the
render-to-PNG total improving as the ladder landed:

```
for REV in 6757eb2 2275f61 b21a7a3 eda765f 7b4aecf 652d4cd 0e1bd71; do
  ASTRYX_PERF_ALLOW_BOOT=1 python3 scripts/perf-bench.py run \
      --rev "$REV" --features firefox-test,kdb \
      --url file:///tmp/hello.html \
      --i-understand-this-boots --timeout-ms 2400000
done
```

(`6757eb2`→`0e1bd71` are the NDE-10→NDE-17 render-ladder commits; substitute the
current ladder if it has moved. Each `--rev` checks out + builds that revision,
boots, records, then restores HEAD.)

### 4. View

```
python3 scripts/perf-web.py --port 8099    # http://localhost:8099
```

Then promote the clean current-HEAD + Linux records into `.perf/baseline.json`
(replacing the import-derived reference targets) and commit.
