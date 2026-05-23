# Mozilla Bugzilla + musl/Alpine deep-mine: prior art for `__stack_chk_fail` in vfork/posix_spawn paths

**Date**: 2026-05-23
**Investigator**: INFRA-5 research dispatch
**Scope**: Catalogue every public source we could find that describes Firefox /
libxul crashing in `__stack_chk_fail` on alt-libc (specifically musl) with a
vfork / posix_spawn / clone-VM angle. The goal is to determine whether our
current gate (SSP mismatch at `ld-musl+0x1c7f9`, fired from a libxul
posix_spawn-style path) is an upstream pattern that has prior art and a known
fix, or whether it is novel to AstryxOS and therefore points at a
kernel/ABI defect on our side.

---

## TL;DR — the single most-likely candidate

After mining bugzilla.mozilla.org, the musl mailing list, GLib's GitLab, the
GCC bug tracker, and Alpine / Void packaging:

**There is NO publicly documented bug where mainline Firefox crashes inside
`__stack_chk_fail` in a vfork/posix_spawn child or parent on Alpine/Void with
musl.** All the "Firefox + musl + SSP" hits in the public record are one of:

1. *Build-time* link failures resolving `__stack_chk_fail` (libssp packaging,
   bug 1533133).
2. *Genuine* stack overflows from oversized stack-allocated buffers (bug
   1274732 — brotli 128 KiB on a musl 80 KiB thread stack; bug 1643474 —
   `nsLookAndFeel::EnsureInit` reading malformed gconf input).
3. Unrelated musl-vs-glibc seccomp/ptrace/header gaps (bugs 1376653, 1881979,
   1041962, 1714564).

The closest *runtime* prior art is musl's own 2017 mailing-list thread (Rich
Felker et al., [openwall 2017-09-14/15]) about the 1 KiB child stack in
`posix_spawn` being too small for `execvpe` when `PATH` is large. That was
fixed in musl by enlarging the child stack to `1024+PATH_MAX` — but the
failure mode it describes is a *child-side* generic stack corruption, not the
specific `__stack_chk_fail` epilogue mismatch we observe.

**Conclusion (HIGH confidence)**: because mainstream Linux + musl + Firefox
combinations on Alpine/Void run this exact `posix_spawn`/`vfork` path
millions of times daily without SSP aborts, the failure we see is *almost
certainly* an AstryxOS kernel-side defect along one of these axes:

- **TLS / `FS_BASE` not restored byte-identical across the vfork-return**
  (parent epilogue reads canary from `fs:0x28`; if our kernel rewrites
  `MSR_FS_BASE` on the vfork-child's behalf and fails to restore the
  parent's value when `CLONE_VFORK` unblocks the parent, the epilogue
  loads a *different* TLS slot's canary and aborts);
- **the page backing `__pthread_self()->canary` in the parent gets COW'd,
  zeroed, or wrong-frame-mapped** during the vfork window (W215-family
  aliasing residual);
- **the child's writes to its 1 KiB stack escape the buffer and trample
  the parent's stack frame**, which in a normal Linux kernel is detected as
  ordinary stack corruption (no SSP involvement) but in our kernel may
  succeed silently and re-corrupt the canary slot;
- **musl's `__init_ssp` runs unexpectedly in the vfork child after
  execve-failure**, re-seeding `__stack_chk_guard` to a value different
  from the parent's, and the parent then fails its epilogue check.

The first axis is the most testable and the most consistent with our
observed signature (epilogue-time fault at `ld-musl+0x1c7f9` after a vfork
return). Recommend a 1-hour kernel-side audit of vfork-return `FS_BASE`
restoration before any further kernel changes.

---

## Mechanism background (cited from public sources)

### 1. musl's stack-canary storage (`__stack_chk_fail.c`)

From musl's [`src/env/__stack_chk_fail.c`](https://git.musl-libc.org/cgit/musl/tree/src/env/__stack_chk_fail.c):

```c
uintptr_t __stack_chk_guard;        // global

void __init_ssp(void *entropy) {
    if (entropy) memcpy(&__stack_chk_guard, entropy, sizeof(uintptr_t));
    else __stack_chk_guard = (uintptr_t)&__stack_chk_guard * 1103515245;
    ...
    __pthread_self()->canary = __stack_chk_guard;   // also in TLS
}

void __stack_chk_fail(void) { a_crash(); }
```

So musl stores the canary in **two** places: the global `__stack_chk_guard`
*and* `__pthread_self()->canary`. On x86-64, the compiler emits the SSP
epilogue check against `fs:0x28`, which resolves to the *TLS* copy
(`__pthread_self()->canary`). The global is initialised once at
`__libc_start_main` time from `AT_RANDOM` in the ELF auxiliary vector
(see musl's `__libc_start_main.c`, multiple mirrors).

### 2. musl's `posix_spawn` uses `CLONE_VM|CLONE_VFORK` without `CLONE_SETTLS`

From musl's current [`src/process/posix_spawn.c`](https://git.musl-libc.org/cgit/musl/tree/src/process/posix_spawn.c):

```c
char stack[1024+PATH_MAX];       // child stack on parent's stack frame
...
pid = __clone(child, stack+sizeof stack,
              CLONE_VM|CLONE_VFORK|SIGCHLD, &args);
```

**Crucial properties** (confirmed by reading the public source):

- The child gets a **fixed 1 KiB+PATH_MAX stack carved out of the parent's stack frame**.
- `CLONE_SETTLS` is **not** passed, no `tls` argument is supplied, and the
  child therefore **inherits the parent's `FS_BASE`** — it sees the same
  `__pthread_self()` slot, including the same `->canary` field.
- `CLONE_VM` means writes by the child are visible in the parent. The
  child's PT_TLS / per-thread state is the parent's.
- `CLONE_VFORK` suspends the parent until the child execve's or _exits;
  the kernel must then restore the parent's `RIP/RSP/RBP/FS_BASE/registers`
  byte-identical to the state at the clone instruction.

### 3. Mozilla's own launcher path does NOT use `CLONE_VM`

From `security/sandbox/linux/launch/SandboxLaunch.cpp`
([searchfox](https://searchfox.org/mozilla-central/source/security/sandbox/linux/launch/SandboxLaunch.cpp)):

> *Don't allow flags that would share the address space* ...
> `MOZ_RELEASE_ASSERT((aFlags & CLONE_VM) == 0)`

Mozilla deliberately forbids `CLONE_VM` in its own `ForkWithFlags()` wrapper
for sandbox launches. So the SSP-on-vfork path *inside libxul itself* does
not exist on the **content-process spawn** path. The path through which our
gate gets hit must therefore be one of:

- **The fork-server child process** (bug 1470591) using ordinary `fork()`,
  i.e. a separate address space — no vfork shared-AS issue;
- **Indirect `posix_spawn()` through GLib's `g_spawn_async_with_pipes`**,
  which since GLib's [MR !95](https://gitlab.gnome.org/GNOME/glib/-/merge_requests/95) prefers a `posix_spawn` codepath (= musl
  vfork + CLONE_VM) on Linux for performance;
- **libstdc++ / launcher helpers** that call `posix_spawn` directly (e.g.
  `breakpad` minidump uploader, sub-launcher invocations);
- **One of Mozilla's launched helper binaries** (glxtest, snap helpers,
  pkexec invocations) using libc's posix_spawn.

If our gate fires on a `vfork` return inside libxul + musl, the most likely
caller is **GLib's g_spawn → musl posix_spawn**, since Firefox uses GTK on
Linux for chrome and uses GLib spawning extensively.

---

## Findings catalogue

### HIGH confidence — directly related to our pattern

#### F1: musl posix_spawn child stack is fixed-size on the parent's stack frame
- **Source**: [openwall musl ML 2017-09-14 thread start](https://www.openwall.com/lists/musl/2017/09/14/1)
  and [2017-09-15 Rich Felker reply](https://www.openwall.com/lists/musl/2017/09/15/1)
- **Summary**: Bison crashed invoking m4 via posix_spawnp because musl's
  fixed-size 1 KiB child stack was overflowed by `execvpe`'s `PATH` search
  buffers. Fix landed in musl as the 2017-10-19 commit "use larger stack to
  cover worst-case in execvpe" — enlarged to `1024 + PATH_MAX`.
- **Mapping to our gate**: This is the same *mechanism class* but a
  different *failure mode*. The 2017 bug was a genuine stack overflow
  inside the child writing past the 1 KiB buffer into the parent's stack
  frame. **It would NOT manifest as a parent-side `__stack_chk_fail` at
  the vfork-return; it would either crash the child during exec or
  corrupt parent state visible after the parent resumes.** That said,
  *if* our kernel reports a different `PATH_MAX` than musl was compiled
  for, or if Mozilla's pre-execve work in the child writes more than
  expected, we could be triggering a contemporary recurrence.
- **Action**: Check the `PATH_MAX` musl in our build was compiled with
  vs. what the child does. Check what the launcher caller's PATH is set
  to. (Likely not the issue, since this would corrupt random data not
  the canary specifically, but worth a 5-minute glance.)

#### F2: musl `__init_ssp` re-runs in vfork child if dynamic loader pulled in late
- **Source**: musl's [`__libc_start_main.c`](https://git.musl-libc.org/cgit/musl/tree/src/env/__libc_start_main.c) (multiple mirrors); musl
  [`__stack_chk_fail.c`](https://git.musl-libc.org/cgit/musl/tree/src/env/__stack_chk_fail.c)
- **Summary**: `__init_ssp` is called from `__libc_start_main` for the
  primary thread. It re-seeds `__stack_chk_guard` and writes
  `__pthread_self()->canary`. In a `posix_spawn` child this code path
  should *not* re-run: musl's `__posix_spawnx` child function does not
  call `__libc_start_main`, only `__execvpe` / `_exit`. **However**, if
  for any reason the dynamic loader does additional work in the child
  (e.g. PT_TLS re-initialisation, a TLS slot bzero), `__pthread_self()->canary`
  could be clobbered, which the *parent* would then see on resume.
- **Mapping to our gate**: HIGH-relevance mechanism. Because the child
  shares the parent's address space, *any* write the child does to
  `__pthread_self()->canary` is a write to the parent's TLS canary. When
  the parent resumes and runs its SSP epilogue, the on-stack saved
  canary (from the prologue, before the vfork) is compared to the now-clobbered
  TLS slot. They differ -> abort at `ld-musl+0x1c7f9`.
- **Action**: This is the **top hypothesis to verify**. The
  D22-PHYS_OFF telemetry should be able to confirm whether the canary slot
  in the parent's TLS page is rewritten between vfork-call and
  vfork-return. The cross-walk to user-RBP-identity in PR #408/#409 is
  already on this scent — but the data should be analysed specifically for
  *writes to the canary slot* during the vfork window, not just RBP / stack
  identity.

#### F3: `CLONE_VFORK` semantics require byte-identical `FS_BASE` restore on parent resume
- **Source**: [clone(2) Linux man page](https://www.man7.org/linux/man-pages/man2/clone.2.html); musl source as cited above
- **Summary**: The Linux kernel's `CLONE_VFORK` implementation must
  suspend the parent thread, run the child to completion of execve/_exit,
  and then resume the parent with all CPU state restored byte-identical
  to the state at the clone instruction — including segment bases.
  Because musl does NOT pass `CLONE_SETTLS`, the child inherits the parent's
  `FS_BASE` and never modifies it.
- **Mapping to our gate**: HIGH. If AstryxOS's vfork return path
  inadvertently re-writes `MSR_FS_BASE` from a stale per-CPU cache, or
  reloads it from a `Task::fs_base` field that has drifted, the parent
  resumes with `fs` pointing to the *wrong* TLS page and the epilogue
  compares the saved canary against an unrelated qword.
- **Action**: Audit the vfork-return path in our kernel for any
  `wrmsr(MSR_FS_BASE, ...)` or `arch_prctl(ARCH_SET_FS, ...)` between
  vfork-suspend and parent-resume. The expected behaviour is that
  `FS_BASE` is part of the parent's save-area and is restored verbatim
  with the rest of the GPRs.

### MED confidence — adjacent and informative

#### F4: gcc bug 58245 — SSP epilogue eliminated when caller invokes a `noreturn` function
- **Source**: [gcc bugzilla 58245](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=58245) (and the secondary
  fix work at [llvm D147975](https://reviews.llvm.org/D147975))
- **Summary**: Functions that call `noreturn` functions (e.g. `abort`,
  `execve` after it returns 0 in `posix_spawn`'s child path is conceptually
  noreturn) have their SSP epilogue check **optimised away** by gcc. The
  caller's stack might be smashed and the check never runs.
- **Mapping to our gate**: MED. If the libxul caller of `posix_spawn`
  is itself compiled with `-fstack-protector-strong`, the function's
  epilogue *should* run after `posix_spawn` returns. The bug 58245
  pattern eliminates this check only when the call is `noreturn` — but
  `posix_spawn` is NOT noreturn (it returns a status). So this is
  unlikely to explain the *absence* of a check in normal cases. However,
  it does explain why some functions appear "stack-protected" yet fire
  `__stack_chk_fail` from a *different* function later — the corruption
  happens deep in the call chain but is detected at an outer caller.
- **Action**: If we have a libxul function in the call chain compiled
  *without* `-fstack-protector-strong` (some perf-critical mozglue files
  exclude it), corruption from a deeper frame would propagate undetected
  until a checked outer frame runs its epilogue. The crash site
  (`ld-musl+0x1c7f9`) is *inside `__stack_chk_fail`* itself in musl, so
  the failing check is at whatever libxul frame called it — useful
  to symbolicate that exact frame and check its compile flags.

#### F5: bug 1274732 — Firefox brotli 128KiB stack buffer overflows musl's 80KiB default thread stack
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1274732](https://bugzilla.mozilla.org/show_bug.cgi?id=1274732)
- **Summary**: Crash in `WriteRingBuffer` on Alpine because brotli
  allocated a 128 KiB buffer on stack and musl threads get only 80 KiB by
  default. **Genuine stack overflow, NOT an SSP-detected one.** Fix:
  move to heap with `mozilla::UniquePtr`.
- **Mapping to our gate**: MED — establishes that "Firefox on musl
  hits stack-size assumptions" is a documented pattern. Our gate is *not*
  this exact bug (it would manifest as SIGSEGV on the guard page, not
  as `__stack_chk_fail`), but the same family of stack-size mismatch is
  worth checking: does our musl build use the standard 128 KiB default,
  or a smaller value that would trip libxul code paths that work on
  glibc?

#### F6: bug 1376653 — Firefox seccomp-bpf sandbox broken on musl (clone flag whitelist)
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1376653](https://bugzilla.mozilla.org/show_bug.cgi?id=1376653)
- **Summary**: musl's pthread_create passes `CLONE_DETACHED` which
  glibc does not. Firefox's seccomp whitelist rejected it, killing
  pthread_create early in startup. **The crash signature was a NULL
  deref in `ProcessHangMonitor::CreateHangMonitorChild` when `mThread`
  was NULL.**
- **Mapping to our gate**: MED. Establishes musl-vs-glibc clone-flag
  differences cause real Firefox crashes. Our scenario is the inverse:
  our kernel needs to *accept* musl's full set of clone flags identically
  to Linux. If our `sys_clone` rejects `CLONE_VFORK` or `CLONE_VM` with a
  silent fallback (e.g. treating it as plain fork), the child would NOT
  share the parent's address space and the SSP slot in the parent would
  remain pristine — so this would not produce our exact gate. But if we
  accept `CLONE_VFORK` semantics partially (e.g. share AS but not
  properly suspend the parent thread, leading to a race), we could see
  the canary slot get written by the child *while the parent is also
  running* and reach its epilogue. **Worth a 10-minute look at our
  vfork suspend logic.**

#### F7: bug 1533133 — Firefox build-time `__stack_chk_fail` link failure on Solaris
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1533133](https://bugzilla.mozilla.org/show_bug.cgi?id=1533133)
- **Summary**: `--enable-hardening` set `-fstack-protector-strong` but the
  linker couldn't resolve `__stack_chk_fail` because the JS engine was
  excluded from SSP and Solaris needed `libssp.so.0` explicitly. Fix: add
  `-fstack-protector-strong` to ldflags consistently.
- **Mapping to our gate**: LOW-MED. Tells us libxul *is* normally
  built with `-fstack-protector-strong` (the Mozilla `--enable-hardening`
  flag enables it; Alpine's `firefox-esr` APKBUILD removes
  `-fstack-clash-protection` but does *not* remove `-fstack-protector*`).
  So libxul's SSP epilogues are real and active on Alpine builds.

### LOW confidence — adjacent only

#### F8: bug 1643474 — `nsLookAndFeel::EnsureInit` `__stack_chk_fail` from bad gconf input
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1643474](https://bugzilla.mozilla.org/show_bug.cgi?id=1643474)
- **Summary**: Genuine SSP catch in a Mozilla function reading
  unvalidated-length gconf strings into a stack buffer.
- **Mapping to our gate**: LOW. Different code path, different
  caller, no vfork/posix_spawn involvement. Useful only as evidence
  that libxul's SSP epilogues are correctly armed on Linux.

#### F9: bug 1881979 — Crash reporter ptrace type mismatch on musl
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1881979](https://bugzilla.mozilla.org/show_bug.cgi?id=1881979)
- **Summary**: Rust type mismatch (`u32` vs `i32`) for `PTRACE_ATTACH`
  on musl. Build-time only.
- **Mapping**: LOW. Documents musl-vs-glibc Linux header drift; no
  SSP/vfork connection.

#### F10: bug 1041962 — build fails with musl: `basename` not declared
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1041962](https://bugzilla.mozilla.org/show_bug.cgi?id=1041962)
- **Mapping**: LOW. Build-time only.

#### F11: bug 1714564 — Firefox 89 rendering broken on musl + Intel Xe
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1714564](https://bugzilla.mozilla.org/show_bug.cgi?id=1714564)
- **Mapping**: LOW. GPU-driver path, no SSP.

#### F12: void-linux/void-packages#31933 — Intermittent Firefox 88+ freeze on musl
- **Source**: [github.com/void-linux/void-packages/issues/31933](https://github.com/void-linux/void-packages/issues/31933)
- **Summary**: Firefox 88+ intermittently freezes when bringing up
  context menus on Void musl. No crash signature. Marked stale, never
  resolved.
- **Mapping**: LOW-MED. Adjacency: a *menu* spawn would go through
  GLib's `g_spawn → posix_spawn → vfork`. If this freeze is the
  vfork-parent never resuming because the child crashed silently inside
  shared-AS work, that would *almost* match our gate — except no SSP
  abort was reported. Worth keeping in mind: if our gate ever stops
  reporting and becomes a silent hang, this is the upstream prior art.

#### F13: musl wiki — known third-party assumptions: large thread stacks, stack base arithmetic
- **Source**: [wiki.musl-libc.org/bugs-found-by-musl.html](https://wiki.musl-libc.org/bugs-found-by-musl.html)
- **Summary**: Documents that "various projects (firefox, libgc, ...)
  assume large thread stack size without setting it up" and "query the
  base pointer of the stack to do pointer arithmetics with it."
- **Mapping**: LOW-MED. Establishes that Mozilla code has historically
  made fragile assumptions about stack layout on glibc. If our musl
  setup passes a smaller-than-expected stack but the libxul caller of
  `posix_spawn` does fragile arithmetic, the SSP epilogue might be
  reading the canary from a fraction-of-a-page-off location.

#### F14: bug 1511073 — Enable stack-protector on mingw-clang builds (Windows)
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1511073](https://bugzilla.mozilla.org/show_bug.cgi?id=1511073)
- **Mapping**: LOW. Windows-only, but documents SSP enablement in libxul.

#### F15: bug 1588710 — Enable stack-clash protection on supported OS/arch
- **Source**: [bugzilla.mozilla.org/show_bug.cgi?id=1588710](https://bugzilla.mozilla.org/show_bug.cgi?id=1588710)
- **Mapping**: LOW. Adjacent hardening flag.

### Negative results (questions answered "NO" in the public record)

#### N1: Has Mozilla disabled `vfork()` in `posix_spawn` for musl builds?
- **Answer**: No public evidence Mozilla disables vfork in posix_spawn
  for musl. Mozilla doesn't call `posix_spawn` directly for its launcher
  (it uses its own `ForkWithFlags()` clone wrapper that explicitly
  *forbids* `CLONE_VM`). Indirect callers (GLib, system libraries) go
  through musl's stock `posix_spawn` which DOES use `CLONE_VM|CLONE_VFORK`.
  See SandboxLaunch.cpp source cited above.

#### N2: Is there a documented requirement that `__stack_chk_guard` must be re-seeded between vfork-return and SSP epilogue?
- **Answer**: No. Linux kernel `CLONE_VFORK` semantics require
  byte-identical register restoration. Userspace (musl) does NOT
  re-initialise the canary across vfork-return. Both the global
  `__stack_chk_guard` and `__pthread_self()->canary` should remain
  unchanged from the parent's perspective.

#### N3: Is Alpine Linux's `firefox-esr` package built with `--disable-stack-protector`?
- **Answer**: No. Alpine's [firefox-esr APKBUILD](https://github.com/alpinelinux/aports/blob/master/community/firefox-esr/APKBUILD)
  only removes `-fstack-clash-protection`. It does *not* disable
  `-fstack-protector-strong`. So libxul on Alpine has live SSP epilogues
  in essentially every function.

#### N4: Has anyone hit `__stack_chk_fail` in a vfork child/parent on alt-libc with Firefox?
- **Answer**: No public hit found in bugzilla.mozilla.org, GitHub
  cross-repo search, the musl mailing list, Alpine bug tracker, or
  Void packages issues. **This strongly suggests the failure mode is
  AstryxOS-specific, not a Mozilla/musl bug we are reproducing.**

---

## Top-5 most actionable findings (ranked)

1. **F3 (HIGH)**: `CLONE_VFORK` semantics + musl's lack of `CLONE_SETTLS` mean
   parent's `FS_BASE` must be byte-identical on vfork-return. **Audit our
   vfork-return path for any `wrmsr(MSR_FS_BASE)` or partial register
   restore.** This is the single most-likely candidate and the cheapest to
   verify (~1 hour of kernel-side reading).

2. **F2 (HIGH)**: Because `CLONE_VM` makes child writes visible in the
   parent, *any* write the child makes to `__pthread_self()->canary` (e.g.
   spurious `__init_ssp` re-run, dynamic loader TLS bzero) corrupts the
   parent's canary slot. **Extend the D22-PHYS_OFF watchpoint to
   specifically trap writes to the parent's `fs:0x28` qword during the
   vfork window.** That gives a fire-or-no-fire answer on whether the
   canary slot is being touched.

3. **F6 (MED)**: Verify our `sys_clone`/`sys_vfork` correctly implements
   `CLONE_VFORK` parent-suspend semantics — specifically that the parent
   thread does NOT execute *any* instructions between the clone return-to-user
   and the child's execve/_exit. If we have a partial-suspend race where the
   parent runs briefly while the child is still in shared-AS mode, the
   child could be writing to TLS while the parent reads it.

4. **F4 (MED)**: Symbolicate the exact libxul function whose SSP epilogue
   fires `__stack_chk_fail`. Check whether it's compiled with
   `-fstack-protector-strong` or not. If the calling function is *unprotected*
   and a deeper protected callee survived, this is a "shifted-detection"
   pattern (corruption-deep-in-callee, detected-shallow-in-caller).

5. **F1 (MED)**: Cross-check our build's musl `PATH_MAX` value vs the
   value musl was compiled against. If they differ, the 1 KiB+PATH_MAX
   child stack could overflow.

---

## Verification plan (concrete, in priority order)

1. **(1 hr)** Read `kernel/src/syscalls/clone.rs` (or wherever) and
   trace the vfork-return path: does it restore `FS_BASE` from the
   parent's task save-area, or from a per-CPU `current->fs_base` field
   that might have been updated by the child? If the latter, fix.

2. **(2 hr)** Extend `[VFORK/CANARY]` telemetry (already in PR #410)
   to also log `MSR_FS_BASE` at vfork-call and at vfork-return. Run
   a 3-trial KVM Firefox demo and compare bytes.

3. **(2 hr)** Add a kernel-side D22-PHYS_OFF-style watchpoint that
   traps any *write* to the parent's `fs:0x28` qword between vfork-call
   and vfork-return. Fire-once-then-disarm to avoid log floods.

4. **(1 hr)** Pull the apk-cached `libxul.so` from our Alpine root
   filesystem and disassemble around the symbol that contains
   `ld-musl+0x1c7f9`'s caller frame. Confirm what libxul function is
   the callee, what its SSP-prologue store address is, and whether
   that exact qword has been written between prologue and epilogue.

5. **(post-verification)** If F3/F2 are both negative, escalate to a
   tech-lead cross-walk on whether musl's `__libc_start_main` /
   `__init_ssp` could plausibly run twice (suggesting our ELF loader
   re-runs init for some reason).

---

## Sources (canonical URLs only)

- musl source: [`__stack_chk_fail.c`](https://git.musl-libc.org/cgit/musl/tree/src/env/__stack_chk_fail.c), [`posix_spawn.c`](https://git.musl-libc.org/cgit/musl/tree/src/process/posix_spawn.c), [`__libc_start_main.c`](https://git.musl-libc.org/cgit/musl/tree/src/env/__libc_start_main.c), [posix_spawn.c log](https://git.musl-libc.org/cgit/musl/log/src/process/posix_spawn.c)
- musl mailing list: [openwall posix_spawnp stack overflow 2017-09-14](https://www.openwall.com/lists/musl/2017/09/14/1), [Rich Felker reply 2017-09-15](https://www.openwall.com/lists/musl/2017/09/15/1)
- musl wiki: [bugs found by musl](https://wiki.musl-libc.org/bugs-found-by-musl.html)
- Mozilla searchfox: [SandboxLaunch.cpp](https://searchfox.org/mozilla-central/source/security/sandbox/linux/launch/SandboxLaunch.cpp), [GeckoChildProcessHost.cpp](https://searchfox.org/mozilla-central/source/ipc/glue/GeckoChildProcessHost.cpp), [ProcessUtils_linux.cpp](https://searchfox.org/mozilla-central/source/ipc/glue/ProcessUtils_linux.cpp)
- Mozilla bugzilla: [272138](https://bugzilla.mozilla.org/show_bug.cgi?id=272138), [1041962](https://bugzilla.mozilla.org/show_bug.cgi?id=1041962), [1274732](https://bugzilla.mozilla.org/show_bug.cgi?id=1274732), [1376653](https://bugzilla.mozilla.org/show_bug.cgi?id=1376653), [1401062](https://bugzilla.mozilla.org/show_bug.cgi?id=1401062), [1470591](https://bugzilla.mozilla.org/show_bug.cgi?id=1470591), [1511073](https://bugzilla.mozilla.org/show_bug.cgi?id=1511073), [1533133](https://bugzilla.mozilla.org/show_bug.cgi?id=1533133), [1588710](https://bugzilla.mozilla.org/show_bug.cgi?id=1588710), [1643474](https://bugzilla.mozilla.org/show_bug.cgi?id=1643474), [1714564](https://bugzilla.mozilla.org/show_bug.cgi?id=1714564), [1881979](https://bugzilla.mozilla.org/show_bug.cgi?id=1881979)
- Alpine packaging: [firefox-esr APKBUILD](https://github.com/alpinelinux/aports/blob/master/community/firefox-esr/APKBUILD)
- Void packages: [issue 31933](https://github.com/void-linux/void-packages/issues/31933)
- GLib: [posix_spawn merge !95](https://gitlab.gnome.org/GNOME/glib/-/merge_requests/95)
- GCC: [bug 58245](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=58245)
- LLVM: [D147975](https://reviews.llvm.org/D147975)
- POSIX / man pages: [vfork(2)](https://www.man7.org/linux/man-pages/man2/vfork.2.html), [clone(2)](https://www.man7.org/linux/man-pages/man2/clone.2.html), [clone3(2)](https://man.archlinux.org/man/clone3.2.en), [posix_spawn(3)](https://man7.org/linux/man-pages/man3/posix_spawn.3.html)
- Background: [EWONTFIX — vfork considered dangerous](https://ewontfix.com/7/), [Launching Processes on Linux (Adhemerval Zanella)](https://zatrazz.github.io/Launching-Process/), [LSB __stack_chk_fail](http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/libc---stack-chk-fail-1.html)
