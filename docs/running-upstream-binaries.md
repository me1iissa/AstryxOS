---
title: Running Upstream Binaries
nav_order: 4
---

# Running Upstream Binaries

> The whole point of AstryxOS is in this sentence: **you take a binary that was
> built for another operating system, you do not touch it, and it runs.**

AstryxOS is a UEFI-native x86-64 hybrid kernel written in Rust (codename
*Aether*). Its architecture borrows the NT subsystem model — a small executive
at the centre, a Hardware Abstraction Layer beneath it, and **personality
subsystems** layered above that each present one operating system's native
Application Binary Interface (ABI). A program does not know it is running on
AstryxOS. A glibc- or musl-linked Linux ELF makes Linux `syscall`s and gets
Linux semantics back; a Windows PE32+ image makes NT calls through the
`INT 0x2E` gate and gets NT semantics back. Same kernel, two faces.

This page explains the multi-personality model, the single invariant that
keeps it honest, and the flagship stress test that drives the whole project:
bringing **upstream, unmodified, musl-linked Firefox** to a headless
`--screenshot`.

{: .note }
This is an honest progress document. Where a thing works, we say so. Where a
thing is in progress — and the Firefox screenshot pipeline is very much in
progress — we say that too, and we say exactly where it stops.

---

## The multi-personality model

A personality subsystem is the thin translation layer that turns one OS's ABI
into AstryxOS executive primitives. Each personality owns a syscall entry
surface and a binary loader; everything below the personality (memory manager,
scheduler, VFS, IPC, networking, drivers) is shared.

| Personality | Entry surface | Binaries | Maturity |
|---|---|---|---|
| **Linux x86-64** | the `syscall` instruction (per the x86-64 psABI / `SYSCALL` in the Intel SDM Vol. 2) | static ELF, PIE (`ET_DYN`), and fully dynamic ELF via the system's `ld.so` | Real upstream glibc- and musl-linked binaries run end-to-end |
| **NT / Win32** | software interrupt `INT 0x2E` (the classic NT syscall gate) | PE32+ images | Loader + `KUSER_SHARED_DATA`-style stub subsystem |
| **Native Aether** | software interrupt `INT 0x2E` (Aether dispatch) | AstryxOS-native programs | First-party calls for the shell, demos, and tooling |

The Linux personality is the most developed because it is the one Firefox
needs. It dispatches **193+ Linux syscalls** (see
[`docs/LINUX_SYSCALL_COVERAGE.md`](LINUX_SYSCALL_COVERAGE.md)) through
`kernel/src/subsys/linux/syscall.rs`, alongside **50+ native Aether calls** for
first-party programs.

### What "run upstream binaries unmodified" means in practice

It means the loader consumes exactly what the upstream toolchain emitted:

- **The ELF program is loaded as shipped.** Static, PIE, and dynamically linked
  layouts are all honoured: `PT_LOAD` segments, `PT_INTERP` (the path to the
  upstream dynamic linker), `PT_TLS` (thread-local storage), `PT_GNU_RELRO`,
  and the relocation tables — including the compact `DT_RELR` form and
  `DT_GNU_HASH` symbol lookup — are processed in-kernel so the upstream
  `ld-musl-x86_64.so.1` (or glibc's `ld-linux-x86-64.so.2`) runs as the program
  interpreter.
- **The upstream libc runs unmodified.** AstryxOS ships *no* patched libc. The
  exact musl and glibc binaries that ship on a normal Linux distribution
  execute against the kernel's syscall surface. When something doesn't work,
  that is information about an AstryxOS ABI gap, never an excuse to recompile
  the library.
- **PE32+ images are parsed natively** by the NT loader, which sets up the
  Win32 environment block and a `KUSER_SHARED_DATA`-style shared page so the
  image's CRT can initialise.

---

## The invariant: never patch the upstream binary — fix the kernel

This is the single rule the entire project is organised around:

> **If an upstream binary misbehaves on AstryxOS, the bug is in AstryxOS, not in
> the binary. The fix goes in the kernel or the ABI layer — never in the
> binary, never in the libc, never in a "shim" that rewrites what the program
> does.**

The justification is simple and is the philosophical core of the Firefox work:
**the same musl + libxul Firefox runs for millions of people on real Linux.**
If it runs there and stalls here, then AstryxOS has diverged from the
documented ABI somewhere — a syscall returning the wrong errno, a wakeup that
never fires, a page served with the wrong contents. The job is to find that
divergence and close it. "It's an upstream bug" is, in this project, almost
always the wrong answer.

This invariant has teeth: it forbids the easy outs (recompiling the library
with a workaround, LD_PRELOAD-ing a shim, editing the data disk's copy of a
`.so`) and forces every fix to be a real, generally-correct ABI fix that any
conformant binary benefits from.

---

## The Firefox bring-up story (flagship)

Firefox is the forcing function. It is not a synthetic benchmark — it is a
~100-million-line real-world application (Gecko, SpiderMonkey, WebRender, NSS,
ICU, Cairo/Skia, the GTK/X11 stack, and the libxul mega-library) that exercises
nearly every corner of a POSIX kernel: threads and futexes, demand paging and
`mremap`, epoll/poll readiness, Unix-socket IPC between processes, signal
delivery, the whole VFS. If AstryxOS can drive upstream Firefox to render a
page, the Linux personality is real.

**The concrete goal:** run the upstream binary as

```
firefox --headless --screenshot /tmp/out.png https://…/hello.html
```

and have it write a non-empty PNG.

### The engineering method

The Firefox push is not guesswork; it is a disciplined, repeatable loop.

1. **Golden reference on a real kernel.** The *same* musl Firefox build is run
   on a stock Linux host, where it produces `/tmp/out.png` in roughly nine
   seconds. That run is captured as a full `strace` (the "golden strace"). This
   is the ground truth: it proves the demo is achievable with this exact binary
   and gives a syscall-by-syscall reference to diff against.

2. **Run it on AstryxOS under the harness.** Everything goes through
   [`scripts/qemu-harness.py`](HARNESS.md) — a non-interactive, structured-JSON
   QEMU session manager. It boots the kernel with the `firefox-test` feature,
   waits on serial markers, greps the log, and exposes a GDB stub. Sessions
   persist on disk so any number of one-shot queries can run against a live
   boot.

3. **Diff against golden, find the first divergence.** Firefox advances
   "gate by gate": it gets a little further, then stalls at the first place
   AstryxOS behaves differently from the golden run. The harness reports how
   far it got (a syscall count and a named gate), and the divergence is the
   thing to root-cause.

4. **GDB autopsy first — not a printk.** When something faults or hangs, the
   first diagnostic is a structured GDB autopsy
   (`qemu-harness.py autopsy …`, presets in
   [`scripts/autopsy/presets.yaml`](../scripts/autopsy/presets.yaml):
   `full-register-dump`, `gp-fault-context`, `sigsegv-user-gprs`,
   `ssp-fail-snapshot`, `vfork-window`, `bugcheck-entry`,
   `stack-walk-bt-full`), plus the in-kernel debugger `kdb` for live process and
   memory state. A key technique that broke several gates is *live-RIP on the
   correct build*: break at the kernel syscall/futex handler and read the saved
   **user** RIP, which names the exact upstream instruction that is stuck.

5. **Fix the kernel/ABI, re-run, confirm.** Each fix lands as a reviewed PR
   with green CI, citing only public specifications (POSIX, the relevant
   man-pages, RFCs, the Intel SDM, the ELF/psABI standards). Then the harness
   re-runs Firefox and confirms it advances past the gate.

### The real ABI bugs found and fixed

The honesty of the project is in this list: every gate was a genuine, distinct
kernel/ABI bug that *any* conformant binary could have hit, not a Firefox
special-case. Each one is described here at a public-specification level.

| # | Symptom in Firefox | The real bug (public-spec framing) |
|---|---|---|
| **A. 32-bit `FUTEX_WAIT` value compare** | A contended musl mutex spun forever; the main thread never parked and "stormed" billions of syscalls. Misdiagnosed for *months* as a userspace problem. | `futex(2)` `FUTEX_WAIT` compares the 32-bit word at `uaddr` against the supplied `val`. The kernel was comparing the full 64-bit register. A musl `int` futex value with the high bit set (e.g. `0x80000010`) sign-extended, so the compare never matched, the wait always returned `EAGAIN`, and the waiter never slept. Fixed by comparing as a 32-bit value, per the `futex(2)` contract. This single fix retired the long-running "futex storm" saga. |
| **B. `mremap` clobbered the argv page** | Process started, then took a `SIGSEGV` because `argv[1]` had become `NULL` — the command line was corrupted before `main` ran. | An in-place `mremap(2)` grow was implemented with a destructive `MAP_FIXED`-style mapping that could overwrite an *adjacent* existing mapping (here, the page holding the process's argument vector). `mremap` must not clobber unrelated mappings; the grow path was corrected so adjacent pages are preserved. |
| **C. ext2 read-error treated as EOF** | A code page of `libxul` would intermittently read back as all-zeros, yielding `Exec format error` / spurious `ENOENT` and a corrupt main loop. | A device-level read error is **not** end-of-file. The page cache was zero-filling a *failed* covering read and installing it as valid data, silently corrupting file contents. A failed read now propagates an error and never installs a zero page, so file-backed memory matches the disk. |
| **D. Scheduler starved Ready threads** | A content-process child was created but **never scheduled** — it sat Ready forever while other threads ran, so the multi-process startup deadlocked. | A fair run queue must not let a runnable thread starve indefinitely behind higher-priority work. The scheduler gained anti-starvation aging: a thread's effective priority rises with its time spent waiting in the Ready queue, guaranteeing forward progress. |
| **E. Timer due-wake dropped under contention** | Timed waits (`FUTEX_WAIT` with timeout, `poll` timeouts) occasionally never woke, so threads slept past their deadline. | A scheduler timer that comes due must wake its sleeper. The due-wake was being silently dropped when a `try_lock` on the thread table lost a race; it now never drops a due wake on lock contention. |
| **F. Dynamic-linker search path** | The upstream dynamic linker couldn't find Firefox's bundled `.so` files, failing to resolve `libxul` and friends. | The exec environment now builds a variant-aware `LD_LIBRARY_PATH` derived from the binary's `PT_INTERP`, so the upstream `ld.so` searches the same directories it would on a normal install and resolves the bundled libraries (dozens of them) from `/usr/lib`. |

(These six sit on top of a longer tail of earlier ABI fixes from the same push:
the `pipe(2)` buffer ABI, `PT_TLS` page refcounting, `epoll`/`poll` `HUP`
delivery on peer close, `CLONE_CHILD_CLEARTID` exit semantics, AF_UNIX
readiness/`POLLOUT` gating, a VFS mount-lock SMP deadlock, ext2 directory and
read-coalescing correctness, and futex requeue/wake-op handling.)

### Honest current state

With those fixes in place, upstream Firefox no longer wedges early. It now:

- boots through the dynamic linker, resolves `libxul` and the full bundled
  library set, and initialises;
- reaches **Compositor initialisation**;
- spawns **two content processes**;
- loads the **HeadlessShell screenshot actors** (the IPC machinery that, on a
  working run, captures the page and encodes the PNG);
- and runs into the hundreds of thousands of syscalls deep into the
  screenshot pipeline.

**Where it stops, honestly:** the run currently stalls at a **screenshot-IPC
condition-variable lost-wakeup**. Deep in startup, a thread parks on a musl
condition variable (a `futex(2)` `FUTEX_WAIT`) waiting for the screenshot IPC to
hand it work; the wake that should release it either never arrives or targets a
`uaddr` offset from where the waiter is parked, so the thread only ever escapes
via timeout and the run livelocks instead of proceeding to `drawSnapshot` and
writing the PNG.

**So: there is no rendered `out.png` yet.** Firefox is *running the headless
screenshot pipeline* — Compositor up, content processes up, screenshot actors
loaded — and is blocked on this one condvar-wakeup gate. That gate is the next
thing to root-cause, and the standing discipline is to characterise it with the
`cond-autopsy` tool (which dumps the condition variable's struct, every parked
waiter, recent wake targets, the inferred lock-holder, and a verdict hint)
*before* writing any speculative fix — exactly the same find-the-divergence,
fix-the-kernel method that carried Firefox this far.

---

## Try it yourself

The full setup is in [Getting Started](getting-started.md); the short version,
once the data disk is staged with the Firefox payload, is:

```bash
# boot the kernel with the Firefox bring-up feature and watch it advance
python3 scripts/qemu-harness.py start --features firefox-test
python3 scripts/qemu-harness.py ff-progress <sid>     # report the gate ladder reached
python3 scripts/qemu-harness.py grep <sid> 'Compositor|content proc|Screenshot'
python3 scripts/qemu-harness.py stop  <sid>
```

For other upstream Linux programs that *do* complete today — busybox and its
400+ applets, `wget`/`curl`, an `httpd`, `dropbear` sshd, `git`, an OpenSSL
TLS handshake, and X11 clients against the in-kernel X server — see
[Running Linux utilities on AstryxOS](RUNNING_LINUX_UTILITIES.md).

---

## See also

- [Architecture](architecture.md) — the executive / HAL / personality model
  (Linux vs NT vs Win32) and the dual syscall entry surface.
- [Getting Started](getting-started.md) — build the kernel, run the test suite,
  and boot the Firefox bring-up under the harness.
- [Contributing & Dev Tooling](dev-tooling.md) — `qemu-harness.py`, the
  `ff-progress` gate ladder, `cond-autopsy`, GDB autopsy, `kdb`, and the
  contribution flow.
