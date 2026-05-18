# Session 2026-05-18 — musl Firefox track, 9 PRs

## Headline

Most substantive kernel-engineering day in the AstryxOS Firefox-demo arc.
**Nine PRs landed** (`#296` through `#305`) covering the Alpine musl
Firefox swap, three real kernel-ABI gaps glibc didn't trigger, the
W216-class pipe-refcount-on-fork gap, and a hardened SMAP boundary that
caught and closed a HIGH-severity bypass primitive under threat-model
review.

The musl Firefox content-process **spawned and executed cleanly** for
the first time. sc plateau advanced **32 → 1976** over the day. Every
PR moved a named gate; saga discipline held throughout (no false
closures, no rapid-fix cycles).

## PRs landed

| PR | Commit | Subject |
|---|---|---|
| `#296` | `15094d5` | `build/data.img`: swap glibc Firefox for Alpine musl Firefox (W101 endpoint pivot) |
| `#297` | `e5b13ca` | `scripts/qemu-harness`: handle `--timeout None` safely in `rip-trace-resolve` |
| `#298` | `24c1f1d` | `kernel/proc/elf+usermode+syscall`: musl libc ABI compatibility (3 gaps fixed) |
| `#299` | `4cf9154` | `scripts/install-firefox-musl`: stage Alpine `/lib/` base libs (libz, libcrypto, libssl, libblkid, libmount) |
| `#300` | `c6c0282` | `kernel/vfs`: add `/opt → /disk/opt` boot symlink for musl FF DT_NEEDED chain |
| `#301` | `23a32a8` | `build/musl-runpath`: stage Mozilla tree at DT_RUNPATH (`/usr/lib/firefox-esr`) |
| `#302` | `c9a6d68` | `kernel/arch`: make `UserGuard` nest-safe (recvmsg SMAP fault fix) + FMASK AC + IDT-entry CLAC (CWE-269/693) |
| `#304` | `bc28cc5` | `kernel/arch/x86_64/irq`: clear `EFLAGS.AC` at hardware IRQ entry (SMAP gate, CWE-693) |
| `#305` | `9a40399` | `kernel/ipc/pipe+vfs+syscall`: drop pipe refcount on close/exec/dup |

## sc forward-progress ladder

Every PR moved a measurable gate. No PR was speculative; each had a
dispositive evidence signal:

| Stage | sc plateau | Gate closed |
|---|---|---|
| Pre-musl baseline | 32 | (initial musl crash at RIP `0xeb9fe26ce0`) |
| `+#298` musl ABI | 548 | DT_RELR double-bias / R9 clone / futex timespec |
| `+#299` `/lib/` stage | 871 | Alpine /lib/* base libs missing from data.img |
| `+#300` `/opt` symlink | 1777 | DT_NEEDED canonical-path resolution |
| `+#302+#304` SMAP nest-safe | 1959 | recvmsg `msg_controllen` SMAP fault + downstream HIGH-sev bypass |
| `+#305` pipe refcount | **1976/1976/1976** (3-trial deterministic) | musl `posix_spawn` cancel-pipe parent never EOF'd |

3-trial soak confirmed sc=1976 is deterministic (σ≈0.47, range=1).

## Kernel architecture deltas

### Linux personality ABI completeness

**PR #298 — three independent musl ABI gaps named & fixed:**

1. **`DT_RELR` double-bias on dynamic-PIE main binaries** — kernel was
   applying `DT_RELR` to firefox-bin's PT_LOAD pages; ld-musl then
   applied them again. Slots ended up at `2 × pie_bias + lva`. Fix
   gates kernel-side `DT_RELR` on `interp_path.is_none()` (ELF gABI
   §5.1 PT_INTERP semantics). Glibc Firefox ESR 115 has no `DT_RELR`,
   so this gap was masked by binary choice.
2. **`R9` clobber in `clone(CLONE_THREAD)`** — musl's `__clone.s`
   stashes the thread entry function in R9 across the syscall, then
   `call *%r9` in the child. AstryxOS's `xor r9d, r9d` clobbered it.
   Fix captures parent's R9 in `ForkUserRegs.r9`, propagates across
   CoW + share-VM fork paths, restores in `jump_to_user_mode`. Glibc's
   `clone3` uses RDX/R8 (both already preserved), so this gap was
   masked.
3. **`futex(2)` timespec unconditional deref** — kernel called
   `user_read_timespec(timeout_ptr)` for all `futex_op` values. musl's
   `pthread_cond_signal` issues `futex(uaddr, FUTEX_WAKE|FUTEX_PRIVATE,
   count=1, 0x8, …)` where arg-4 is a count, not a pointer. Kernel
   `#PF` `CR2=0x8`. Fix gates the deref on `op ∈ {0, 6, 9, 11, 12}`
   (`FUTEX_WAIT`, `FUTEX_LOCK_PI`, `FUTEX_WAIT_BITSET`,
   `FUTEX_WAIT_REQUEUE_PI`, `FUTEX_LOCK_PI2`) — matches the `futex(2)`
   man-page TIMEOUTS table verbatim.

### VFS path-resolution completeness

**PR #300 (1 LOC) + PR #301 (defence-in-depth)** — Mozilla's Alpine
binaries have `DT_RUNPATH = /usr/lib/firefox-esr` baked in. Two
complementary fixes:

- `PR #300`: complete the existing `/lib`, `/lib64`, `/usr` → `/disk/*`
  boot-symlink pattern at `kernel/src/vfs/mod.rs:368-371` by adding
  `/opt → /disk/opt`. Mozilla artefacts staged under `/opt/firefox/`
  now reachable via canonical-path lookup.
- `PR #301`: stage the Mozilla tree at the canonical `/usr/lib/firefox-esr/`
  path. Closes Mozilla launcher-relative resource lookups
  (`dependentlibs.list`, `omni.ja`, etc.) that use
  `readlink("/proc/self/exe") + dirname`. ELF gABI §5.4 spec-correct.

### SMAP hardening (security-engineer-driven)

**PR #302** — Surfaced from a verifier-named gate (RIP `0xffff800000127fd1`
in `subsys::linux::syscall::dispatch_body` writing `msg_controllen` to
user with `RFLAGS.AC = 0`). Aether named the underlying bug as
`UserGuard` not being nest-safe: when an inner guard's `Drop` ran
`CLAC`, the outer scope retained `AC = 0` even though the bracket
intent was for `AC = 1`.

Fix made `UserGuard` nest-safe (outer owns `STAC`/`CLAC`; inner are
passengers via runtime `EFLAGS.AC` sampling).

**Security-engineer /review caught a HIGH-severity SMAP-bypass
primitive (CWE-269/CWE-693)** in the nest-safe heuristic: unprivileged
userland could prime `EFLAGS.AC = 1` via `pushfq;or 0x40000;popfq`
before `syscall`, making the first kernel-side `UserGuard` a passenger
and leaking `AC = 1` across the entire kernel window — neutralising
SMAP for any latent unbracketed user-deref bug.

Remediation bundled into PR #302 in the same /review cycle:

- `IA32_FMASK = 0x40700` masks `AC` on `SYSCALL` entry (Intel SDM Vol
  3A §6.8.8).
- SMAP-gated `CLAC` prologue at every ring-3-callable IDT entry
  (`isr_no_error!` + `isr_with_error!` macros + `isr_syscall_int80` +
  `isr_syscall_int2e`).
- Test 220c Scenario E added covering the inherited-AC attacker
  pattern.

**PR #304** extends the same prologue to hardware IRQ entry stubs
(timer, keyboard, e1000, mouse, virtio-blk, virtio-serial,
TLB-shootdown, w215-diag-IPI). CWE-693 forward-compat hardening.

### IPC refcount completeness

**PR #305** — musl `posix_spawn(3)` cancel-pipe pattern parked the
parent's `read(read_end, 4)` forever after the child's `execve`. Three
independent close paths failed to decrement the pipe's
`writers` / `readers` counts:

- `vfs::close` cleared the fd slot without dropping pipe refcount
- `execve`'s `FD_CLOEXEC` purge did `*fd_slot = None` without dropping
- `dup`/`dup2` family missed both bump (new ref) and drop
  (`dup2`-displaced fd)

Plus `fork` / `clone3` without `CLONE_FILES` was missing the symmetric
**bump** — pipe ends duplicated into the child fd table with no count
increase. This mirrored the W216 H_A gap closed for AF_UNIX sockets by
PR #233, but `inc_socket_refs_for_fork` gated only on
`FileType::Socket && UNIX_SOCKET_FLAG`. PR #305 adds
`inc_pipe_refs_for_fork` wired into all three fork sites symmetric to
PR #233's pattern.

Engineering-historian caught the original verifier's "VFORK path
unpatched" framing as wrong (PR #233 already wired vfork for sockets);
real gap was `FileType::Pipe` across all fork paths. Tech-lead
cross-walk confirmed convergence before /review.

## Saga-discipline events worth recording

1. **W101 endpoint acknowledged**. Glibc Firefox plateau at sc=2902
   was empirically dispositive (30-min soak, kernel exonerated, 14
   falsified hypotheses). User picked Option 3 (different FF), which
   exposed three real kernel-ABI gaps. Both verdicts coherent: glibc
   path is algorithmic, musl path exposes new kernel surface.
2. **Multi-source cross-walk worked**. PR #305 was integrated from
   three parallel sources: qa-engineer (verifier — syscall-trace
   lens), engineering-historian (git + code-static-audit lens), aether
   (implementation lens). Verifier's framing was partially wrong; the
   historian caught it; tech-lead validated the convergence; security-
   engineer audited the merged result. No single agent's output was
   accepted on its own.
3. **Security-engineer caught what other reviewers wouldn't**. PR
   #302's threat-model lens surfaced a HIGH-severity SMAP-bypass
   primitive that a general-purpose /review wouldn't have caught. This
   is the case for using `security-engineer` on any PR touching
   security primitives.
4. **Independently-arrived-at framings.** Aether independently
   converged on the `FileType::Pipe` framing without seeing the
   historian's correction — strong evidence the framing is correct.

## Outstanding work / next session

**Next gate (deterministic, in scope for next dispatch)**:

Userspace `#GP` at RIP `0x7f000001c7f9`, CS=0x23, RSP=0x7ffffffee478.
Bytes at fault = `f4 c3` = `HLT;RET`. Same anon-VMA file=`<anon>`
offset_in_vma=0x87f9 across all 3 trials of the post-#305 soak.

Verifier interpretation: indirect call landing on a bad fptr post
posix_spawn return. Most likely candidates: kernel-published value the
musl posix_spawn return path indirect-calls through (auxv / vDSO /
sigframe / wait4 status), or genuinely uninitialised heap that happens
to encode `f4 c3`. PM verdict on session-end: bounded probe (90 min
hard cap) before declaring session-complete.

**Other open follow-ups (not blocking)**:

- Test 0bc2 / PR #305 follow-up: add `FileDescriptor`-shaped round-trip
  test for the predicate gating (`flags & 0x80000000`). Security-
  engineer flagged as MEDIUM.
- IDT[0xFF] LAPIC spurious vector: install a handler so the
  SMAP-gated-CLAC invariant holds even on spurious interrupts. PR #304
  reviewer flagged as a pre-existing latent gap.
- PNG-3: W215 `pte_share_count` overhead audit (deferred from May
  17 — Task #53).
- PR #303 (dependabot `spin 0.11.0`) waiting for sweep.
- 8 stale W215-era branches in worktrees can be cleaned up.

## Citations used in this session's commits

- Intel SDM Vol 1 §6.4 (interrupt RFLAGS), Vol 2A (CLAC/STAC
  encoding + #UD-on-non-SMAP), Vol 3A §4.6.1 (SMAP), §6.8.8 (SYSCALL
  flag masking), §3.4.3 (RFLAGS layout)
- POSIX `pipe(2)`, `close(2)`, `read(2)`, `write(2)`, `dup(2)`,
  `dup2(2)`, `execve(2)`, `fork(2)`, `clone(2)`, `vfork(2)`,
  `futex(2)`, `dlopen(3)`, `recvmsg(2)`, `clock_gettime(2)`
- ELF gABI §5.1 (PT_INTERP), §5.4 (`DT_RUNPATH` search order)
- glibc public source on sourceware.org; musl public source on
  git.musl-libc.org; Mozilla gecko-dev on github
- CWE-190, CWE-191, CWE-269, CWE-415, CWE-416, CWE-693
- Alpine wiki (apk package layout, FAT32-friendly long-name semantics)
- Breakpad public symbol-format documentation

Citations are public-specs-only across all commits.
