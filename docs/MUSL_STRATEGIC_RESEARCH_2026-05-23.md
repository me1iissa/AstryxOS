# Strategic research — musl drop-in vs 1:1 from-scratch for AstryxOS native userspace

Date: 2026-05-23
Status: Strategy doc — no code changes
Scope: AstryxOS-native userspace only. The Linux personality (`kernel/src/subsys/linux/`) is *not* the subject of this doc; it already runs upstream musl-linked binaries (Alpine `firefox-bin`, Alpine `libc.musl-x86_64.so.1`) unmodified and must continue to.

---

## TL;DR

**Recommended: Option D — adopt upstream musl as the AstryxOS-native libc, vendored under `external/musl/` as a verbatim copy, building two separate musl artefacts in the tree (a "native" musl linked against AstryxOS-native syscall numbers, and the Alpine-shipped binary used unmodified by the Linux personality). Reject Option B (1:1 from-scratch) outright; reject Option A (single shared musl) on litmus-test grounds; treat Option C (status quo) as the fallback if D's build-system work is not yet justified.**

One paragraph: musl is ~88–110 KLOC of dense systems code (mallocng, ldso, NPTL-equivalent threading, locale, math, network). Re-implementing 1:1 is the kind of multi-engineer-year project that produces inferior code by drift; AstryxOS gains nothing by owning a copy. The right move is to vendor musl, build it twice with a small `arch/astryx/` overlay (~300–600 LOC) for AstryxOS-native syscall numbers, and keep the Alpine-shipped binary entirely untouched on the Linux-personality side. This preserves the litmus-test invariant ("FF runs unmodified upstream") absolutely, gives AstryxOS-native binaries (`ascension`, `orbit`, future `aterm`, `acompositor`, etc.) a real, POSIX-2008-conformant libc for free, and bounds maintenance to "rebase the overlay onto each musl release."

---

## Current state

### `userspace/libsys/` is not a libc

`userspace/libsys/` is **1,435 lines of Rust** providing raw syscall wrappers, a `Timespec`/`Timeval`/`ClockId` shim layer, an `errno` translation helper, and `auxv` parsing. It exports 37 public functions across `lib.rs` (28) and `posix.rs` (9). It is `#![no_std]`, has no allocator, no stdio, no locale, no math, no threading primitives, no dynamic-linker support code, no signal-handler trampoline machinery, no DNS resolver, no time-zone database. It is — correctly, for its scope — a thin shim over `syscall` for the few AstryxOS-native programs that currently exist (`ascension` 56 LOC, `orbit` 59 LOC, plus C test programs).

It is roughly **0.4 %** of musl by line count, and that ratio under-states the functional gap: the missing pieces (allocator, stdio FILE\*, pthread/mutex/cond/rwlock, signal trampoline, dlopen/dlsym, locale, math, regex, network resolver, getopt, qsort/bsearch, the entire `<string.h>` family) are exactly the parts where re-implementation drift produces subtle, hard-to-debug bugs.

### What AstryxOS-native programs need

Today: `ascension` (init) opens files, forks, execs, sleeps, prints to fd 1. `orbit` (shell) reads a line, parses it, forks/execs. Neither needs more than libsys provides.

Tomorrow (sketched in `docs/FIREFOX_PORT_ROADMAP.md` and `docs/DEVELOPMENT_PLAN.md`): a real `aterm` (terminal emulator), `acompositor` (Wayland-shaped compositor), `aupdate` (package manager). These need: dynamic linking, threads, mutexes, condition variables, `malloc`, `printf`-family, `fopen`-family, `dlopen` plugins, network sockets with name resolution, optional X11 transport. That is the libc / runtime surface, not the syscall surface.

### What the kernel already supports

The Linux-personality syscall dispatcher in `kernel/src/subsys/linux/syscall.rs` is **9,571 lines** and handles 70+ Linux syscalls (verified by the recent strace-ref differential gate — see `docs/PR395_LINUX_GROUND_TRUTH_FF.md` per session memory). It implements `FS_BASE` MSR handling, `set_tid_address`, `clone(CLONE_THREAD|CLONE_VM|CLONE_SETTLS|...)`, `rt_sigaction`, `futex(WAIT/WAKE/REQUEUE)`, `mprotect`, `mmap` (anon + file-backed + MAP_STACK), `getrandom`, vDSO via `AT_SYSINFO_EHDR`. **musl's kernel requirements are already met.** The only AstryxOS-native delta is the syscall number table — `libsys/src/lib.rs` already documents both spaces side-by-side (`SYS_EXIT=0` native vs `SYS_EXIT=60` Linux).

### What is already vendored

`build/disk/lib/ld-musl-x86_64.so.1` and `build/disk/lib/libc.musl-x86_64.so.1` are the **unmodified Alpine** musl artefacts. The Firefox test image consumes them via PT_INTERP. **Touching these is prohibited** by `feedback_no_upstream_binary_edits.md`. Option D depends on this remaining true.

---

## Option A — Drop-in single musl

**Shape**: vendor upstream musl, build it once, use it for both AstryxOS-native binaries and the Linux personality.

**Why it looks attractive**: one source of truth, one ABI to test, one rebase cadence.

**Why it fails the litmus test**: the Linux personality runs **Alpine's** musl binary. Alpine ships a specific build (Alpine's CFLAGS, Alpine's ldso path `/lib/ld-musl-x86_64.so.1`, Alpine's TLS layout, Alpine's `ldconfig` and `ld-musl-x86_64.path`). The instant we substitute our own build — even a byte-identical rebuild from the same source — we no longer satisfy "runs upstream-as-shipped artefacts." Per `feedback_no_upstream_binary_edits.md` "even rebuilding upstream binaries with our own flags counts as 'editing'." This option contradicts the architectural invariant.

**Additional cost**: AstryxOS-native binaries don't naturally fit `/lib/ld-musl-x86_64.so.1` semantics — they may want a different INTERP path (`/lib/ld-astryx-x86_64.so.1`) so that the loader's resolv.conf paths, nsswitch paths, etc. don't collide with the Linux personality's filesystem layout (Alpine's musl looks at `/etc/resolv.conf`; native AstryxOS may want `/astryx/etc/resolv.conf`).

**Verdict: rejected.** The litmus test is non-negotiable.

---

## Option B — 1:1 from-scratch musl-shaped libc

**Shape**: implement a new C library in Rust (or C) that exposes the same public ABI as musl, function-by-function, structurally compatible enough that a `gcc -lc` link against the new libc produces a binary indistinguishable in behaviour from musl-linked.

**KLOC estimate**: musl is approximately **88,000–110,000 lines** of C and asm by published measurements (compared with glibc's ~2 million). The interesting subsystems and their approximate musl line counts (recovered by reading the public `git.musl-libc.org/cgit/musl/tree/src/` directory listing — see Sources):

| Subsystem | Indicative LOC | Hardness |
|---|---|---|
| `src/malloc/` (mallocng) | ~3,500 | Hard. Re-implementing a correct, fast, fragmentation-resistant allocator is a project unto itself. |
| `src/thread/` (NPTL-equivalent) | ~8,500 | Very hard. Cancellation, robust mutexes, condvars, rwlocks, TLS dtors, futex-correctness. |
| `src/network/` (DNS, getaddrinfo) | ~4,200 | Hard. Parallel UDP DNS, RFC 5395 edge cases, IDN handling. |
| `src/stdio/` (FILE\*) | ~3,800 | Medium. Buffering, lock semantics, `__stdio_exit` orderings. |
| `src/locale/`, `src/regex/`, `src/time/` | ~5,000 each | Medium. Tedious but mechanical. |
| `src/math/` | ~12,000 | Medium. Math correctness is a standards burden, not an algorithmic puzzle, but musl's tests are extensive. |
| `ldso/` (dynamic linker) | ~3,500 | Very hard. PT_TLS, lazy bind, DT_RELR, IFUNC, symbol versioning. |
| `arch/x86_64/` (asm, atomic primitives, syscall trampolines) | ~2,500 | Medium. |
| Headers, `compat/`, misc | ~10,000 | Mechanical. |

**Effort**: at AstryxOS's current rate (1–2 engineers, mixed kernel + userspace) this is a **2–3 engineer-year** project before reaching musl behavioural parity, and that estimate is generous — it does not account for the test infrastructure to *prove* parity (musl's external test suites: libc-test, posixtest, the Open POSIX Test Suite). Industry data points: writing a libc from scratch to musl-grade correctness has bitten projects like Dietlibc (still incomplete after 20+ years), klibc (intentionally tiny), the various BSD libcs (decades of polish), and the Apple-internal libSystem (huge team, decades).

**Where 1:1 drift happens**: the bugs you avoid by *using* musl are by definition the ones you re-introduce when re-implementing — race-free pthread cancellation, robust mutex recovery on `EOWNERDEAD`, `pthread_cond_t.__g_refs` two-group cycling, DT_RELR double-bias, `clock_gettime` vDSO selection, `getaddrinfo` parallel-query timing. The recent W-series investigations recovered several of these in *kernel* code; the *userspace* surface is at least equally subtle.

**Strategic argument against**: every hour spent on a from-scratch libc is an hour not spent on the demo gate (FF headless screenshot) or on legitimate AstryxOS differentiators (orbit/ascension/acompositor). The work is high-cost, low-novelty, and produces a libc that — by intent — behaves the same as musl. There is no surface area where AstryxOS would benefit from a *different* libc implementation; the differentiation lives in the kernel, the compositor, and the package model, not in `strtol`.

**Verdict: rejected.** This option is not credibly affordable and produces no architectural value.

---

## Option C — Status quo hybrid (libsys + Alpine musl in personality)

**Shape**: leave things as they are. `libsys` for native binaries; unmodified Alpine musl for the Linux personality.

**What we lose**: AstryxOS-native binaries are stuck at libsys's scope forever. Want `printf`? Write it. Want threads? Write the futex layer, the mutex layer, the cond layer, TLS dtors. Want dlopen? Write a dynamic linker. Each one is a multi-week project that ends with code we maintain forever — and that, predictably, is a worse libc than musl. Worse, ambitious native programs (a compositor, a package manager, a real shell) will either drift into duplicating musl in `libsys/` or will be deferred indefinitely.

**What we keep**: zero new build-system surface. Zero risk to the Linux-personality litmus test.

**Verdict: viable as fallback.** If Option D's build-system cost (estimated below) is not yet affordable, stay here and re-evaluate after the FF demo lands.

---

## Option D — Refined drop-in: two musls, cleanly separated

**Shape**:

1. Vendor upstream musl under `external/musl/` as a verbatim tarball extraction (current latest: 1.2.5). Treat `external/musl/` exactly the way the kernel treats third-party Rust crates pulled by Cargo: pin a version, never edit in-place, document the upgrade procedure.
2. Add a small AstryxOS overlay at `external/musl/arch/astryx-x86_64/` — **NOT** as a patch to upstream files but as an *additional* architecture per musl's own multi-arch model. musl already supports adding new arches via `arch/<name>/` (see musl's distribution guidelines: "musl supports full multiarch with separate include and lib paths"). The overlay defines:
   - `bits/syscall.h.in` — the AstryxOS-native syscall numbers (`SYS_EXIT=0`, etc., per `libsys/src/lib.rs`).
   - `syscall_arch.h` — the `__syscall*` inline-asm template (the same `syscall` instruction shape musl uses on x86_64, just dispatching to AstryxOS-native numbers).
   - `crt_arch.h` — `_start` entry, stack layout, auxv handling.
   - A small `pthread_arch.h` / TLS variant if AstryxOS-native ABI differs (it shouldn't — Variant II Linux-style is fine).
   - Total overlay: estimated **300–600 LOC** of musl-style C and asm.
3. Build musl twice:
   - **`build/musl-native/`**: musl built against the `astryx-x86_64` overlay, with `--prefix=/astryx/usr`, `ldso` install name `/lib/ld-astryx-x86_64.so.1`. Used by `ascension`, `orbit`, `aterm`, future native binaries. PT_INTERP points at the AstryxOS-native ldso.
   - **`build/musl-alpine/`**: the **untouched** Alpine binary, copied into `build/disk/lib/` exactly as Alpine shipped it. Used by the Linux personality for FF, glibc-test, etc. PT_INTERP points at `/lib/ld-musl-x86_64.so.1`.
4. `libsys/` stays as the **low-level Rust crate** — it does not go away. Native Rust binaries that want `#![no_std]` keep using libsys. Native C/C++ binaries link against `build/musl-native/`. A future native-Rust-with-`std` story can sit `std` on top of musl-native via a small `astryx-sys` shim.

**Litmus-test invariance**: Alpine's musl is never rebuilt, never relinked, never patched. It is bit-for-bit the file Alpine produced. The AstryxOS-native musl is a *separate artefact* that never enters the Linux-personality sysroot. The two musls cannot be confused because their `PT_INTERP` strings differ and they install into different prefixes.

**Patch surface against upstream musl**: zero in-tree edits to `external/musl/src/`, `external/musl/include/`, or `external/musl/ldso/`. The overlay lives entirely under `external/musl/arch/astryx-x86_64/`, which is the directory musl's own build system reserves for downstream-defined architectures. Compare against the way Alpine maintains its musl: Alpine carries ~15 patches against upstream, all addressed back to mailing list, never structural. AstryxOS would carry zero structural patches and ~500 LOC of additive arch code.

**Build-system cost**: estimated **2–3 weeks** for one engineer to:
- Vendor `external/musl/` (1 day).
- Write `arch/astryx-x86_64/` overlay (1 week).
- Wire `configure` invocation into `scripts/build-musl-native.sh` (2 days) — pattern matches existing `scripts/build-firefox.sh`.
- Relink `ascension` and `orbit` against musl-native as proof, validate that current behaviour is preserved (3 days).
- CI integration via `scripts/qemu-harness.py` (2 days).

**License**: MIT (musl since 2012). Compatible with everything AstryxOS does. No copyleft contamination, no attribution burden beyond preserving `external/musl/COPYRIGHT` verbatim.

**Maintenance**: musl releases on average every 6–9 months. Each upgrade is "drop in the new tarball under `external/musl/`, re-run the overlay diff, run the test image." This is the same cadence Alpine maintains and is well-understood.

**Verdict: recommended.** Bounded cost, no litmus-test risk, gives AstryxOS-native programs a real libc forever, and the overlay is small enough to audit in one sitting.

---

## Litmus-test implications

The litmus test (`feedback_litmus_test_run_mainstream_apps_natively.md` per session memory) is: upstream Linux binaries — Alpine `firefox-bin`, the shipped `libc.musl-x86_64.so.1`, the shipped `libxul.so` — must run unmodified.

| Option | Litmus-test status |
|---|---|
| A — single shared musl | **Violates.** Substituting our build for Alpine's counts as editing. |
| B — from-scratch 1:1 | **Does not violate** (Linux personality unchanged) but is rejected on cost. |
| C — status quo | **Does not violate.** |
| **D — two musls** | **Does not violate.** Alpine binary is bit-for-bit preserved; native musl is a separate artefact in a different prefix with a different INTERP path. |

Option D is explicitly designed so that the two libcs cannot be confused at runtime — they have different INTERP strings, different install prefixes, and different soname (`libc.musl-x86_64.so.1` for Alpine, `libc.astryx-x86_64.so.1` for native). A program's loader path is fixed at link time and cannot accidentally cross over.

---

## Recommendation and concrete next steps

**Adopt Option D.** Phase it as follows:

**Phase 1 — Vendor + build (week 1–2)**
- Add `external/musl/` containing upstream musl 1.2.5 verbatim. Document the upgrade procedure in `external/musl/README.AstryxOS`.
- Write `external/musl/arch/astryx-x86_64/` overlay. Total ≤600 LOC of additive arch code, zero edits under `external/musl/src/`.
- Add `scripts/build-musl-native.sh` modelled on `scripts/build-firefox.sh`. Produces `build/musl-native/` with ldso, libc, headers, crt files.

**Phase 2 — Proof-of-life (week 3)**
- Relink one tiny native C program (e.g. `hello.c`) against `build/musl-native/`. Confirm it runs under AstryxOS-native dispatch (not the Linux personality).
- Use `scripts/qemu-harness.py ci-run` to validate that the Linux-personality FF test path is unaffected — bit-equal `libc.musl-x86_64.so.1` checksum before/after.

**Phase 3 — Migrate native Rust (week 4+)**
- Keep `libsys` as the no_std Rust syscall shim. Do not delete it.
- For native Rust binaries that want `std`, design `astryx-sys` to sit on `build/musl-native/`. This is its own multi-week project and can be deferred.

**Top-3 concrete actions for the next sprint**
1. Decide on musl release pin (recommend 1.2.5, the current stable as of session knowledge — verify on `musl.libc.org/releases.html` before committing).
2. Author the `arch/astryx-x86_64/` overlay as a standalone PR (≤600 LOC; reviewable in one sitting). Land before any build-system changes.
3. Treat the *Alpine musl binary* as a checksummed test fixture in `scripts/qemu-harness.py`: every CI run validates `build/disk/lib/libc.musl-x86_64.so.1` is bit-equal to the pinned Alpine artefact. This is the long-term litmus-test enforcement mechanism.

---

## Sources

- POSIX.1-2008 (Issue 7), `pubs.opengroup.org/onlinepubs/9699919799/` — the actual conformance target for any libc, including musl.
- musl.libc.org "About musl", `musl.libc.org/about.html` — design goals and minimalism claims.
- musl.libc.org Functional differences from glibc, `wiki.musl-libc.org/functional-differences-from-glibc.html` — concrete behavioural gaps relevant to running unmodified Linux binaries.
- musl.libc.org Design Concepts, `wiki.musl-libc.org/design-concepts.html` — unified-library architecture, dynamic linker rationale, thread cancellation model.
- musl.libc.org Guidelines for Distributions, `wiki.musl-libc.org/guidelines-for-distributions.html` — what counts as a compatible musl, multiarch model used here for `arch/astryx-x86_64/`.
- musl public git tree, `git.musl-libc.org/cgit/musl/tree/` — directory structure (`src/`, `arch/`, `include/`, `ldso/`, `crt/`) referenced for Option D's overlay design.
- musl FAQ, `musl.libc.org/faq.html` — kernel requirements, supported architectures.
- musl Coding Style, `wiki.musl-libc.org/coding-style` — what overlay code must follow if it lives under `external/musl/arch/astryx-x86_64/`.
- Linux man-pages (sections 2 and 3) for every syscall and libc entry point referenced.
- ELF gABI (System V ABI x86_64), `gitlab.com/x86-psABIs/x86-64-ABI` — PT_TLS, PT_INTERP, dynamic relocation order.
