# libxul SSP frame-shape audit — post-INFRA-4 hypothesis test (2026-05-23)

## Binary under analysis

`/disk/usr/lib/firefox-esr/libxul.so` — ELF64 DYN PIE, BuildID `a5376fe04c6356fa322d30858e9e36a468f9a897`, stripped (no DWARF companion staged). This is the libxul that the FFTEST harness has loaded across every D-series run referenced in the saga record (`[FFTEST/mmap-so] path=/disk/usr/lib/firefox-esr/libxul.so`), including the Wave-13 D22 trials (PR #408 commit `4cfa0f7`).

ASLR-bias anchor for the trial whose serial log carries the convergent RIP `0x7effb60bc591`: libxul `PT_LOAD#1` mapped at `0x7effb1a4c000` (R-X segment, file off `0x1a2432c`, vaddr `0x1a2532c`). Binary-relative VA = `0x7effb60bc591 − 0x7effb1a4c000 = 0x4670591`.

## INFRA-4 hypothesis under test

**"SSP frame-shape skew in the failing libxul function"** — the prologue stores the canary at `[rbp − N]` while the epilogue's XOR load reads `[rbp − M]` with `N ≠ M`, OR the same `[rbp − 8]` is materialised against two different RBP values (different functions, e.g. nested inlined SSP frames). Either shape would explain the 0x68-byte VA delta observed in PR #408 D22 between the prologue store-site VA (`0x7ffffffee458`, watched by D22) and the epilogue load-site VA (`0x7ffffffee4c0`, captured by `ssp_diag::probe_gp_at_ssp_fail`) on a byte-for-byte identical physical frame.

## Methodology

1. Recovered the function bracket around binary offset `0x4670591` by scanning `objdump -d -M intel` for the nearest preceding entry whose prologue matches the SysV AMD64 SSP pattern (System V AMD64 ABI §3.2.2 frame layout, §3.4.5.2 stack-protector convention; GCC manual `-fstack-protector*`).
2. Enumerated every canary-related instruction in `[0x4670270, 0x46706c0)` — the discovered function bracket — by greping for `fs:0x28` (the `__stack_chk_guard` TLS slot per the SSP-x86-64 ABI), every `[rbp±N]` reference, and every `[rsp+N]` reference.
3. Cross-checked the function's stack discipline (frame-pointer present vs FPO) by inspecting the first six prologue instructions and walking the addressing mode of every `mov`/`lea` that touches a local slot.
4. Cross-checked the kernel-side D21/D22 arm site (`kernel/src/subsys/linux/d22_user_canary_phys.rs` and `d21_user_canary_watch.rs`) for the assumption it bakes about how the canary VA relates to `user_rsp` at vfork pre-block.

## Findings

### 1. Function identity (content-gated)

The enclosing function spans `[0x4670270, 0x4670670)`. Stripped libxul has no exported symbol for it; the nearest preceding dynsym (`_ZNSt8_Rb_tree…_M_get_insert_hint_unique_pos@@xul115`) is a misnomer carried forward from D19's analysis of the same offset. Content identification:

- Calls `__stack_chk_fail@plt` at `0x467066b`.
- Calls `pipe@plt` at `0x46702d0` and `close@plt` at `0x4670610`.
- Calls `_ZNSt6localeD1Ev`, `_ZNSt8ios_baseD2Ev` — a `std::ostringstream` is constructed and torn down on stack.
- Stores `gMozCrashReason = "MOZ_RELEASE_ASSERT((!elements && extentSize == 0) || (elements && extentSize != dynamic_extent))"` (the `mozilla::Span` invariant, [searchfox.org/mozilla-central/source/mfbt/Span.h](https://searchfox.org/mozilla-central/source/mfbt/Span.h)).
- Builds the integer→decimal loop at `0x4670520` (`imul $0x51eb851f; shr $0x25` = `÷100`, two-digit ASCII table at `0x510c00`).
- Concatenates `"-f"` (rodata `0x20b4c2`) and feature-failure rodata strings (`FEATURE_FAILURE_WEBRENDER_COMPOSITOR_DISABLED`).

Content identity: **GPU/WebRender `gfxConfig` feature-failure diagnostic string builder**, formatting an `unsigned int` ID through `ostringstream` plus a pipe/close pair (FD plumbing for the `FireGLXTestProcess` IPC channel). D19 reached the same identification on this BuildID at the same offset.

### 2. SSP prologue at `0x4670270` (binary-relative)

```
4670270:  push   rbp
4670271:  push   r15
4670273:  push   r14
4670275:  push   r13
4670277:  push   r12
4670279:  push   rbx                     ; 6× callee-saved push = 48 B
467027a:  sub    rsp, 0x1e8              ; 0x1e8 (488 B) local frame
4670281:  mov    rax, QWORD PTR fs:0x28  ; load __stack_chk_guard
467028a:  mov    QWORD PTR [rsp+0x1e0], rax   ; *** STORE canary at [rsp+0x1e0] ***
```

### 3. SSP epilogue at `0x467029d` (binary-relative)

```
467029d:  mov    rax, QWORD PTR fs:0x28
46702a6:  cmp    rax, QWORD PTR [rsp+0x1e0]   ; *** LOAD canary from [rsp+0x1e0] ***
46702ae:  jne    467066b                       ; → tail call __stack_chk_fail@plt
46702b4:  mov    eax, ebx
46702b6:  add    rsp, 0x1e8                    ; matching tear-down
46702bd:  pop    rbx
46702be:  pop    r12
46702c0:  pop    r13
46702c2:  pop    r14
46702c4:  pop    r15
46702c6:  pop    rbp
46702c7:  ret
```

### 4. Frame-pointer mode

Scanning `[0x4670270, 0x4670700)` for every addressing mode that touches a local:

- `[rbp ± N]`: **zero occurrences** in the entire function.
- `[rsp + N]`: 30+ occurrences, all RSP-relative, with the canary slot the deepest local (`+0x1e0`) and string-builder buffers at `[rsp+0x40 .. rsp+0xd0]`, IO state at `[rsp+0x90 .. rsp+0xc0]` (the `ostringstream`), and the pipe FD pair at `[rsp+0x1d8] / [rsp+0x1dc]`.

The `push rbp` at `0x4670270` is purely **callee-saved register preservation per System V AMD64 ABI §3.2.1 Table 3.4** — RBP is not repurposed as a frame pointer. `mov ebp, r12d` at `0x46706f7` and `cmp ebp, 0x64` at `0x46704ff` (in the integer-format loop) confirm `rbp` is in use as a **general-purpose register** holding the integer argument being formatted. This function is compiled with **`-fomit-frame-pointer`** (the GCC default at `-O2`, per the GCC manual §3.20 / `-fomit-frame-pointer`).

### 5. Canary addressing inside this function: N = M

The prologue store at `0x467028a` and the epilogue load at `0x46702a6` both address the canary at **`[rsp + 0x1e0]`** — the SAME offset relative to the same RSP value (RSP is unchanged across the function body because no further `sub rsp, …` or `push` instructions appear after the prologue's `sub rsp, 0x1e8` until the epilogue's matching `add rsp, 0x1e8`).

**There is no intra-function SSP frame-shape skew.** INFRA-4's "N ≠ M" sub-shape is **REJECTED** for this function: the prologue and epilogue use a single addressing mode (`[rsp+0x1e0]`) and a single base register (RSP), and RSP holds the same value at both sites.

## Where the 0x68 delta actually comes from

The 0x68-byte delta between PR #408 D22's `write_va = 0x7ffffffee458` and the epilogue's `read_va = 0x7ffffffee4c0` is **not** an intra-function effect of any single libxul frame. It is the delta between **two different functions' canary slots**:

- The kernel's D21/D22 arm site is computed as `canary_va = user_rsp + SAVED_RBP_OFFSET_FROM_RSP − 8 = user_rsp + 0x1d58 − 8 = user_rsp + 0x1d50` (see `kernel/src/subsys/linux/d22_user_canary_phys.rs:189,421`). With the recorded `user_rsp = 0x7ffffffec708` this evaluates to `0x7ffffffee458` — exactly the D22-armed VA. The `0x1d58` constant is a **raw empirical offset** from the prior `[VFORK/CANARY] s_1d58` probe, not derived from the actual callee's SSP layout.
- The libxul function whose SSP epilogue actually fires (the one whose `[rsp+0x1e0]` canary mismatches `fs:0x28`) sits in the call chain **above** the vfork wrapper. Its frame's `[rsp+0x1e0]` lands at `0x7ffffffee4c0`. If this is the function at `0x4670270`, that places its `rsp` at `0x7ffffffee2e0` — 6 936 B (`0x1bd8`) above the vfork wrapper's `user_rsp` of `0x7ffffffec708`. Consistent with a deep call chain (XPCOM event loop → `posix_spawn` → musl `vfork` wrapper).

D22's arm site and the SSP epilogue's load site are **in different frames**. The D22 watch sees the WebRender string-builder function's transient write into its own stack-local string buffer (`mov BYTE PTR [rax], cl` at `0x467058f`, where `rax = [rsp+0x40] + r12` — exactly the destination ASCII buffer per D19's analysis). That write coincidentally lands at the VA that an earlier (now-popped) deeper frame had used for its canary slot, and that VA is what D21/D22's `+0x1d50` heuristic picked.

This is the saga's **Rule 4 ("right window, wrong frame") pattern** — exactly the diagnostic-frame-misidentification that closed D19 (`docs/SC1230_D19_DISASM_2026-05-22.md`), now re-occurring at a different point in the call chain.

## Verdict

**REFRAMED.** INFRA-4's specific SSP frame-shape skew (N ≠ M within one function) is **REJECTED** — the libxul function at `0x4670270` is FPO with a single RSP-relative canary slot at `[rsp+0x1e0]`, addressed identically by prologue and epilogue. The 0x68 VA delta observed in PR #408 D22 is an **inter-frame misidentification**: the kernel's D21/D22 arm-site formula `user_rsp + 0x1d50` does not land on the canary slot of the SSP-instrumented function whose epilogue runs after vfork returns; it lands on a transient byte inside the WebRender-feature-failure string builder's stack-local buffer.

INFRA-4's broader "nested-inlined SSP frames" sub-shape is also rejected for the function at `0x4670270` — there are no nested SSP prologues within the bracket `[0x4670270, 0x4670670)` (no inner `fs:0x28` load between the prologue at `0x4670281` and the epilogue at `0x467029d`).

## Recommended next dispatch

**Replace D21/D22's offset-derived arm site with a per-frame canary identity.** The arm site must be derived from the **actual SSP-instrumented function's RSP at its own prologue**, not from a fixed offset above the vfork wrapper's `user_rsp`. Two viable mechanisms, both bounded:

### Option A — RIP-walk to find the canary slot (preferred, ~120 LOC)

At vfork pre-block, walk the parent's user stack frames using the return-address chain (saved RIPs are at `[rsp + 8N]` for the appropriate N at each frame boundary, derived from `add rsp, K` sizes recovered by reading the prologue of each return target). For each frame whose return RIP lands inside libxul:

1. Symbolise the return RIP back to the calling function's prologue.
2. If the prologue contains the SSP pattern (`mov rax, fs:0x28; mov [rsp+OFF], rax`), extract `OFF` by disassembling on the fly (≤ 32 B from the prologue start is sufficient).
3. Arm the linear DR slot at `frame_rsp + OFF` for that specific frame.

This requires a tiny in-kernel disassembler shim (we can use a hand-coded matcher for the 9-byte SSP-store sequence — no general decoder needed). Citation surface: System V AMD64 ABI §3.2.2, GCC manual §3.20 (`-fstack-protector*`), Intel SDM Vol. 3B §17.2.4 / Table 17-2.

### Option B — Co-opt `__stack_chk_fail@plt` as the breakpoint (~40 LOC)

Set a code DR slot (`R/W = 0`, `LEN = 0`) on the `__stack_chk_fail@plt` entry point in libxul (binary offset `0x774e010`, runtime VA computed from `[FFTEST/mmap-so]` libxul base + `0x774e010 − 0x1000`). When the breakpoint fires, the failing function's RSP is in `regs.rsp`, RIP is the `call` site (one past), and the canary VA can be recovered by:

1. Reading the prologue back from the function start (walk down from the `call __stack_chk_fail` site to the nearest `push rbp / push r15 / push r14 …` sequence — bounded by ~64 B in practice).
2. Computing the canary slot from the discovered `[rsp+OFF]` immediate.
3. Re-walking the parent stack to compare what value was there vs `fs:0x28`.

This sidesteps the entire "arm before block, fire after wake" race and gives a **post-hoc** dispositive answer in a single fire. Loses one dimension (we can no longer observe the prior writer) but the writer hypothesis is what D22 already falsified.

### Dispatch recommendation

`aether-kernel-engineer` for Option A or `abi-compatibility-engineer` for Option B. Option B is cheaper to land and gives an immediate dispositive result; Option A is the durable infrastructure. Suggest **Option B first** as a one-PR cliff-walker, then Option A if B confirms the misframe and we need to identify the writer.

The kernel-side fix shape, once the real canary slot is identified, will most likely fall into one of two buckets — these are INFRA-4's next-highest-prior hypotheses on the residual list:

- **fs:0x28 differs between prologue and epilogue.** A TLS-base or guard-value drift between the two calls to `mov rax, fs:0x28` (the prologue at `0x4670281` and the epilogue at `0x467029d`). Plausible mechanisms: vfork wake restoring stale FS_BASE, signal-frame trampoline clobbering TLS, or scheduler thread-switch leaving stale `__stack_chk_guard` in another thread's TCB after `clone(CLONE_VM)`. This was Wave 15 R-B's parked axis (memory `project_d22_wave13_falsification_2026_05_23.md`).
- **Out-of-band writer to the actual `[rsp+0x1e0]` slot.** Once the right VA is identified by Option A/B, a clean linear DR-watch on it will name the writer. Candidate: signal frame construction on the vfork parent, kernel-side stack zeroing past the legitimate extent, or kstack reuse leaking past the user-stack boundary.

Both buckets are kernel-side and have public-spec citation surfaces (POSIX vfork(3p), Intel SDM Vol. 3A §3.4.4 segment-base behaviour on syscall/sysret, System V AMD64 ABI §3.2.2).

## References

- [System V AMD64 Application Binary Interface §3.2.2 (Stack Frame), §3.4.5.2 (Stack Protector)](https://gitlab.com/x86-psABIs/x86-64-ABI)
- [GCC manual §3.20 — `-fomit-frame-pointer`, `-fstack-protector*`](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- [Intel® 64 and IA-32 Architectures Software Developer's Manual Vol. 3B §17.2.4 (Debug Address Registers DR0–DR3) and §17.3.1.1 (Data-Breakpoint Trap Semantics)](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [POSIX `vfork(3p)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/vfork.html)
- [`mozilla::Span` invariant string — searchfox.org/mozilla-central/source/mfbt/Span.h](https://searchfox.org/mozilla-central/source/mfbt/Span.h)
- PR #404 (D21 linear-VA arm at `user_rsp + 0x1d50`)
- PR #408 (D22 PHYS_OFF channel — dispositive falsification of Mechanism D)
- PR #409 (D22 falsification cross-walk to user-RBP-identity)
- `docs/SC1230_D19_DISASM_2026-05-22.md` (prior content-gated identification of the same function at the same offset)
