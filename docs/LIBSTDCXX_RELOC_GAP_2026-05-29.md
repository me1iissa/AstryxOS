# libstdc++ relocation-error gap — triage (2026-05-29)

**Mission**: capture the relocation-error symbols emitted at the Firefox-demo
natural exit (sc=121, `exit_group(127)`), categorise them, and produce a
go/no-go recommendation. **Triage only — no interposer designed or built**
(per PM verdict 2026-05-28, Option C with 90-min cap).

Produced via a dynamic workflow (6 agents: categorise → per-bucket
analyse + adversarial refute → synthesize) over a deterministic capture from
QEMU session `6dcb11196084` (Alpine-musl variant, KVM).

---

## 1. Capture

Run: `qemu-harness.py start --features firefox-test --firefox-variant musl`.
Natural exit reached at `[SYSCALL/Linux] exit_group(127)` (serial line 649),
process `/disk/usr/lib/firefox-esr/firefox-bin`, sc=118 at last metrics tick.

**24 distinct relocation errors**, all against libraries on the **glibc
multiarch path** `/lib/x86_64-linux-gnu/` (plus one in the LD_PRELOAD
interposer itself):

| Library | n | Symbols |
|---|---|---|
| `libstdc++.so.6` (→ 6.0.35) | 18 | `__cxa_thread_atexit_impl`, `__fprintf_chk`, `__isoc23_strtoul`, `__libc_single_threaded`, `__mbsrtowcs_chk`, `__memcpy_chk`, `__memmove_chk`, `__memset_chk`, `__openat_2`, `__read_chk`, `__sprintf_chk`, `__strcpy_chk`, `__strftime_l`, `__wmemcpy_chk`, `__wmemset_chk`, `arc4random`, `strfromf128`, `strtof128` |
| `libgcc_s.so.1` | 4 | `__cpu_indicator_init`, `__cpu_model`, `__memset_chk`, `_dl_find_object` |
| `ld-linux-x86-64.so.2` | 1 | `unsupported relocation type 37` (R_X86_64_IRELATIVE / ifunc) |
| `libfontconfig-interposer.so` | 1 | `dlvsym` |

Every libstdc++/libgcc symbol is a **glibc** symbol — fortify `_chk`
intrinsics, `__isoc23_*` (glibc 2.38+), `strtof128`/`strfromf128` (`_Float128`),
`__libc_single_threaded` (glibc 2.32+), `_dl_find_object` (glibc 2.35+),
`__cpu_model`/`__cpu_indicator_init` (ifunc resolver state). None are CXXABI/
GLIBCXX version tags; none are private (`GLIBC_PRIVATE`) symbols.

---

## 2. Root cause (convergent, cross-checked)

**A glibc-built `libstdc++.so.6.0.35` is being loaded into the musl Firefox
process because `LD_LIBRARY_PATH` lists the glibc multiarch tree before the
musl tree.**

- The running binary is the **Alpine musl** Firefox: `firefox-bin` has
  `PT_INTERP /lib/ld-musl-x86_64.so.1`; `libxul` `DT_NEEDED`s
  `libc.musl-x86_64.so.1` + `libstdc++.so.6` + `libgcc_s.so.1`.
- `kernel/src/gui/terminal.rs:891` sets a **single shared** env for both
  variants:
  `LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/usr/lib:/usr/lib/firefox-esr:/opt/firefox:/disk/lib/firefox`.
  The **glibc** dir `/lib/x86_64-linux-gnu` precedes the **musl/Alpine** dir
  `/usr/lib`.
- ld-musl searches `LD_LIBRARY_PATH` left-to-right and resolves the soname
  `libstdc++.so.6` to the **glibc** `6.0.35` object in `/lib/x86_64-linux-gnu`
  — *before* it reaches the correct musl `6.0.32` in `/usr/lib`.
- The glibc `libstdc++ 6.0.35` imports glibc-versioned symbols
  (`__cxa_thread_atexit_impl@GLIBC_2.18`, `__libc_single_threaded@GLIBC_2.32`,
  `_dl_find_object@GLIBC_2.35`, the `_chk` fortify family) that
  `libc.musl-x86_64.so.1` does not export → unresolvable relocations →
  ld-musl prints "Error relocating … symbol not found" and abandons →
  `exit_group(127)`.
- The correct Alpine musl `libstdc++.so.6.0.32` (in `build/disk/usr/lib/`)
  defines these locally / does not import them, and resolves cleanly against
  musl. It is simply shadowed by the glibc copy on the search path.

The disk image is intentionally **mixed-ABI** (a glibc Firefox tree under
`/lib/x86_64-linux-gnu` + `/lib64`, and a musl Alpine tree under `/usr/lib`),
so both libstdc++ copies belong on disk. The defect is the **search-order**
in the shared env, not the presence of either library.

### Adversarial cross-check (why this is the real cause, not the obvious one)

The first analysis pass proposed "the wrong (host glibc) libstdc++ leaked into
the musl image — drop it / Alpine-native rebuild." A refuting agent **falsified
that framing** via byte-level ELF inspection: both libstdc++ copies are on disk
*by design* (one per ABI), the glibc `libc.so.6` 2.43 on disk *does* export
all three "missing" symbols, and removing the glibc copy would break the
*glibc* Firefox variant. The surviving, evidence-backed diagnosis is the
**LD_LIBRARY_PATH ordering** above — a search-scope bug, not a staging-leak bug
and not a genuine kernel ABI gap.

---

## 3. Category histogram

```
cxxabi_glibcxx_version = 0
std_cxx_runtime        = 0
libgcc_unwinder        = 1   (analysis REFUTED — wrong causal framing)
private_linker         = 2   (_dl_find_object, __libc_single_threaded — NOT refuted)
other                  = 21  (glibc fortify _chk + glibc-versioned libc symbols)
total                  = 24  (< 25 symbol escalation threshold)
```

Note: the 4-bucket scheme from the PM brief fit poorly — most symbols are
glibc fortify/versioned-libc symbols that are neither CXXABI/GLIBCXX version
tags nor `_ZN*` mangled C++ names, so they fell to `other`. The *cause* is
uniform regardless of bucket.

---

## 4. GO / NO-GO

**NO-GO on an interposer. GO on a single-ABI search-scope fix** (PM Option A
family, but far cheaper than a full Alpine-native rebuild).

- **Interposer is the wrong remedy** and is correctly out of scope here:
  `__libc_single_threaded` is a load-bearing slot that glibc *writes* on
  `pthread_create` so libstdc++ knows to re-enable atomics. A static shim byte
  is never updated by the threading layer, so once Firefox goes multi-threaded
  libstdc++ would silently elide locking → data races that masquerade as
  kernel faults and poison the demo signal. `_dl_find_object` backs C++
  exception unwinding; a wrong stub corrupts unwinding.
- The PM fallback rule ("any private_linker symbol present → escalate to
  Option A") fires (`_dl_find_object`, `__libc_single_threaded`). But the
  evidence narrows Option A from "rebuild Firefox on Alpine" to **"make the
  musl variant resolve its C++ runtime only from the musl tree"** — a
  candidate **one-line kernel env fix**.

### Recommended next step (NOT done in this triage)

Make `LD_LIBRARY_PATH` variant-aware in `kernel/src/gui/terminal.rs` (~line
891): for the **musl** variant, place `/usr/lib` *before*
`/lib/x86_64-linux-gnu` (or omit the glibc multiarch dir entirely); leave the
glibc variant as-is. Then re-run `--firefox-variant musl` and confirm the
relocation errors clear and sc advances past 121.

Cheap confirmation before the fix: re-run with `LD_DEBUG=libs` (envp already
sets `LD_DEBUG=files` for this session) and read which
`libstdc++ / libgcc_s / libc` triple binds when the error fires — pins whether
reordering alone suffices or the glibc C++ runtime must be fully removed from
the musl process's scope.

**This is a kernel-side change → PR flow, CI green, user decision on dispatch.
Triage stops here per the PM verdict.**

---

## 5. Grounding (public-spec citations only)

- ELF gABI §5.4 "Shared Object Dependencies" (search order); `ld-musl(8)` /
  `man 8 ld.so` (`LD_LIBRARY_PATH` precedes `DT_RUNPATH`; left-to-right scan).
- Itanium C++ ABI (`__cxa_thread_atexit_impl` signature; TLS dtor semantics).
- `psABI` x86-64 (`R_X86_64_IRELATIVE` = 37; ifunc relative relocation).
- Files: `kernel/src/gui/terminal.rs:891` (envp), `build/disk/usr/lib/libstdc++.so.6.0.32`
  (correct musl runtime), `build/disk/lib/x86_64-linux-gnu/libstdc++.so.6.0.35`
  (glibc runtime that shadows it for the musl variant).
