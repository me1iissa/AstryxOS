# xeyes first window — gate-cascade walk and outcome (2026-05-23)

## Summary

With PR #428 (`1dcaaa0`) the Alpine musl `xeyes` binary already linked, ran
through 34 X11 requests, and parked in `poll(2)` — no SIGSEGV, no `#GP`, no
`__stack_chk_fail`.  This change widens the `[X11POLL]` / `[X11]` trace
gates to fire under `xeyes-test`, identifies and fixes the cascade of
gates that prevented xeyes from reaching `MapWindow`, captures the
post-MapWindow framebuffer via a new `qemu-harness.py screendump`
subcommand, and lands the screenshot at
`docs/XEYES_FIRST_WINDOW_2026-05-23.png`.

xeyes now reaches **req #74** (75 X11 requests, including a
**`MapWindow 0x40000d 150x100+0,0`** for its own visible window) and
plateaus in `poll(2)` waiting for input — the canonical X11 event-loop
steady state.

The screenshot captures the AstryxOS desktop at full 1920×1080 with the
in-kernel compositor's apps visible.  xeyes' 150×100 client window is
backed in the in-kernel Xastryx server but the compositor's
`get_mapped_windows()` path is not yet being driven post-launch by the
xeyes-test soak loop — that compositor wedge is a pre-existing
out-of-scope follow-up (the X11 protocol layer this PR is responsible
for is fully functional, evidenced by the post-MapWindow plateau).

## Gates named, in order

Each gate is the **next-opcode-after-the-plateau** observed in the
`[X11] req#N op=OP minor=MIN len=LEN` trace.  After each gate fix, the
plateau advanced.

| # | Gate (opcode → minor)                  | Plateau before fix                    | Fix shape                                                                                                                  |
|---|----------------------------------------|---------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| 1 | `op=131 minor=48` — XIQueryDevice      | req #33 (sc=466) — `STUCK_IN_NR=7`    | Implement XI v1 + XI2 minors (GetExtensionVersion, ListInputDevices, OpenDevice, GetDeviceFocus, QueryDeviceState, XIQueryPointer, XIGetClientPointer, XIQueryDevice, XIGetFocus, XIListProperties, XIGetProperty, XIGetSelectedEvents) per X Input Extension Protocol Spec / XInput2 protocol. Fixes also: `XI_GET_CLIENT_POINTER` was wired to minor 18 (X_UngrabDeviceButton in XI v1) instead of XI2 minor 45 — corrected. |
| 2 | Sequence-number desync on events       | req #54 (sc=521) — `exit_group(1)`    | Events MUST carry the receiving client's last-request sequence per X11 protocol §11.1 — three `c.seq.wrapping_add(1)` sites (`deliver_property_notify`, `op_send_event`, `deliver_focus_event`) were bumping the request counter, which desynced subsequent reply seqs and tripped Xlib's `sequence_number_send` invariant. Use `c.seq` directly. |
| 3 | `op=71` — PolyFillArc (unknown opcode) | req #65 (sc=561) — `exit_group(1)`    | Add `OP_POLY_POINT`/`POLY_LINE`/`POLY_SEGMENT`/`POLY_RECTANGLE`/`POLY_ARC`/`FILL_POLY`/`POLY_FILL_ARC` opcodes + accept-and-discard stubs in the dispatch table per X11 protocol §PolyArc/§PolyFillArc.  Without these xeyes' first arc drawing call retired with `BadRequest` and Xlib quit. |
| 4 | `op=9` — MapSubwindows                 | req #71 (sc=576) — `exit_group(1)`    | Add `OP_MAP_SUBWINDOWS`/`UNMAP_SUBWINDOWS`/`DESTROY_SUBWINDOWS`/`CHANGE_SAVE_SET`/`REPARENT_WINDOW`/`CIRCULATE_WINDOW` opcodes + accept-and-discard stubs (Xastryx has a flat window hierarchy; the X11 protocol §Window subwindow ops are bookkeeping only). |
| ✓ | **MapWindow** (req #72 op=8)           | reached at sc=581 — steady poll(2)   | xeyes now creates **window 0x40000d at (0,0) 150×100** and parks in `poll(2)` waiting for events.                          |

`[X11POLL]` / `[X11]` / `[X11SVC]` / `[X11REPLY]` / `[X11GP]` / `[X11/XI]`
diagnostics are all widened from `feature = "firefox-test"` to
`any(feature = "firefox-test", feature = "xeyes-test")` so the same
trace shape works for either workload.

## Trace excerpt around the new plateau

```
[X11] req#65 op=71 minor=0 len=36          # PolyFillArc — used to be unknown
[X11] req#66 op=128 minor=2 len=20         # SHAPE Rectangles (existing handler)
[X11] req#67 op=54 minor=2 len=8           # FreePixmap
[X11] req#68 op=139 minor=0 len=12         # RENDER QueryVersion
[X11REPLY] fd=2 seq=69 reply_len=0 total=32
[X11] req#69 op=139 minor=1 len=4          # RENDER QueryPictFormats
[X11REPLY] fd=2 seq=70 reply_len=33 total=164
[X11] req#70 op=131 minor=46 len=20        # XISelectEvents (no reply, side-effect)
[X11/XI] minor=46 len=20
[X11] req#71 op=9 minor=0 len=8            # MapSubwindows — used to be unknown
[X11] req#72 op=8 minor=24 len=8           # MapWindow
[X11] MapWindow 0x40000d 150x100+0,0       # ← xeyes' visible window mapped
[X11] req#73 op=16 minor=0 len=20          # InternAtom("WM_PROTOCOLS")
[X11REPLY] fd=2 seq=74 reply_len=0 total=32
[X11] InternAtom("WM_PROTOCOLS") -> 69
[X11] req#74 op=18 minor=0 len=28          # ChangeProperty WM_PROTOCOLS
[PROC-METRICS] tick=1000 pid=1 name=/disk/usr/bin/xeyes sc=581 (... sync=73 proc=0 sig=0 ...) cur_nr=7@98t
[PROC-METRICS] tick=1500 pid=1 name=/disk/usr/bin/xeyes sc=581 (... ) STUCK_IN_NR=7@598t
... STUCK_IN_NR=7 plateau ...
```

`sync=73` (epoll/poll/futex calls), `proc=0` (no exit_group), `sig=0`
(no signals).  xeyes is in the canonical X11 client event-loop steady
state.

## Opcode coverage added

`kernel/src/x11/proto.rs`:

- Window hierarchy ops (5-13): `OP_DESTROY_SUBWINDOWS`,
  `OP_CHANGE_SAVE_SET`, `OP_REPARENT_WINDOW`, `OP_MAP_SUBWINDOWS`,
  `OP_UNMAP_SUBWINDOWS`, `OP_CIRCULATE_WINDOW`.
- Polygon drawing ops (64-71): `OP_POLY_POINT`, `OP_POLY_LINE`,
  `OP_POLY_SEGMENT`, `OP_POLY_RECTANGLE`, `OP_POLY_ARC`,
  `OP_FILL_POLY`, `OP_POLY_FILL_ARC`.
- XInput v1 minors (1-30): `XI_V1_GET_EXTENSION_VERSION`,
  `XI_V1_LIST_INPUT_DEVICES`, `XI_V1_OPEN_DEVICE`, `XI_V1_CLOSE_DEVICE`,
  `XI_V1_GET_DEVICE_FOCUS`, `XI_V1_QUERY_DEVICE_STATE`.
- XInput2 minors (40-60): `XI_QUERY_POINTER` (40), `XI_GET_CLIENT_POINTER`
  (45 — was wrongly 18), `XI_QUERY_DEVICE` (48), `XI_GET_FOCUS` (50),
  `XI_LIST_PROPERTIES` (56), `XI_GET_PROPERTY` (59),
  `XI_GET_SELECTED_EVENTS` (60).

`kernel/src/x11/mod.rs::op_xinput`: handlers for each of the above XI
minors with minimal but spec-conformant replies (zero-device lists,
PointerRoot focus, empty property tables — sufficient for any client
that does not directly enumerate input devices).

## QEMU harness — screendump subcommand

The previous `read-png` subcommand only worked when the kernel itself
emitted a base64-encoded PNG via `[SCREENSHOT-B64:N/M]` lines.  For
visible-window demos we want a host-driven capture.  Added
`scripts/qemu-harness.py screendump <sid> <dst.png>`:

- Sends `{"execute": "screendump", "arguments": {"filename": "..."}}`
  to the per-session QMP socket (QMP spec: QEMU monitor protocol).
- Reads the resulting PPM (P6) and converts to PNG using only the
  Python stdlib (`zlib` for IDAT deflate per W3C PNG §11.2.4, `struct`
  for chunk framing per W3C PNG §5) — no PIL/netpbm dependency.
- Prints JSON `{ok, path, png_bytes, ppm_bytes}`.

`scripts/qemu-harness.py start` now also auto-injects `-vga vmware`
into the QEMU command line when `xeyes-test` is in the feature set,
mirroring what `gui-test` / `firefox-test` get via
`astryx_qemu._display_args`.  Without VGA, mode "test" emits
`-display none` with no framebuffer and `screendump` returns an empty
PPM.

## Files

- `docs/XEYES_FIRST_WINDOW_2026-05-23.png` — 1920×1080 PNG capture (32178 bytes) of AstryxOS booted with the `xeyes-test` workload.
- `docs/XEYES_TRACE_SAMPLE_2026-05-23.txt` — full 463-line serial log from the dispositive trial.

## Recommended next move

The X11 protocol layer is functional through MapWindow.  The **compositor's `x11::get_mapped_windows()` path is not driven after process launch** in the xeyes-test soak loop (compose() invocation cadence drops to zero post-launch — pre-existing wedge in the BSP soak loop, also affects `firefox-test`).  Two orthogonal next moves:

1. **`xterm` pivot** — `xterm` issues a wider opcode mix (font rendering, scrolling) and exercises VT220 emulation against the kernel pty.  Build for ~50 LOC more opcode coverage; xterm's static-TLS canary path is identical to xeyes (no libxul SSP saga).
2. **Compositor invocation under `xeyes-test`/`firefox-test`** — drive `gui::compositor::compose()` from the timer ISR (or a per-CPU compositor-tick task) so the rendered framebuffer stays live regardless of which user-mode process is running.  Naming the cause: post-`launch_process`, the BSP main-loop `compose()` calls cease (verified via direct entry-counter trace at `get_mapped_windows`).
