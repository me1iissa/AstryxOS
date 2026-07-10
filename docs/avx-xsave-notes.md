# AVX / XSAVE / FPU-state notes (AstryxOS)

Reference for the FPU/SSE/AVX state-management path enabled by PR #711
(XSAVE + AVX, full FPU state preserved across context switches **and**
signals). Written to be cited by teammates who touch anything involving the
vector register file, the context switch, signal delivery, or `sigreturn`.

All citations are to **public** specifications: Intel® 64 and IA-32
Architectures Software Developer's Manual (SDM), AMD64 Architecture
Programmer's Manual (APM), the x86-64 System V psABI, POSIX.1-2017, and the
published glibc manual. Verify volume/section against your local SDM revision;
section numbering drifts slightly between editions.

---

## 0. TL;DR for a teammate in a hurry

- The kernel now enables **XSAVE + AVX** (`CR4.OSXSAVE`, `XCR0 = x87|SSE|AVX`)
  on the BSP and every AP, and preserves the **full** FPU/SSE/AVX register file
  across context switches (`XSAVE`/`XRSTOR`) and across signal delivery
  (`fpstate` in the signal frame).
- `XSAVE_AREA_SIZE = 1024` bytes, 64-byte aligned, **standard (non-compacted)**
  XSAVE form. On a CPU without AVX (e.g. TCG) it transparently falls back to
  `FXSAVE`/`FXRSTOR` (x87 + SSE only).
- The security-critical function is
  `arch::x86_64::fpu_restore_from_user(user_va)` on the `sigreturn` path — it
  takes a **fully untrusted** user XSAVE image and must never let `XRSTOR`
  fault in ring 0. It (1) range-checks the pointer is user-space,
  (2) copies through the fault-immune direct map, (3) validates the XSAVE
  header + MXCSR, then (4) `XRSTOR`s from a kernel buffer.
- Two known follow-ups: the MXCSR check uses a **fixed** reserved mask
  (`0xFFFF_0000`) rather than the CPU's real `MXCSR_MASK`; and the area is
  sized for x87|SSE|AVX only (no AVX-512). Both are documented below.
- **Operational gotcha:** enabling AVX *amplified* the parked W215
  content-corruption flake (AVX-enabled glibc uses vector ops pervasively, so
  any live-frame corruption is hit far more often). This is expected fallout of
  turning AVX on, not a new bug in the XSAVE path — see §10.

---

## 1. Why #711 was needed: two coupled failures

Before #711 the kernel enabled legacy SSE only (`CR4.OSFXSR`, `CR0.EM=0`,
`CR0.MP=1`) and saved FPU state with `FXSAVE`/`FXRSTOR`. That covers x87, MXCSR,
and the low 128 bits (XMM0–15) of the vector registers — **not** the AVX upper
128 bits (YMM_Hi128). With AVX advertised by CPUID (host-passthrough) but
`XCR0`/`OSXSAVE` left disabled, two problems followed:

1. **Userspace #UD.** A glibc/musl IFUNC resolver selects an AVX code path on
   the CPUID feature bit alone; the resulting VEX-encoded instruction faults
   `#UD` because `CR4.OSXSAVE`/`XCR0.AVX` were never set. See §4 — the OS *must*
   opt in for AVX to be legally executable, and a correct resolver checks
   `OSXSAVE`+`XGETBV`, but not all code paths are that careful and the CPUID AVX
   bit being set without OS support is itself the misconfiguration.
2. **Silent YMM loss across preemption.** `FXSAVE` does not save YMM upper
   halves, so any AVX state in a preempted thread was dropped on every context
   switch — silent value corruption in AVX-using code.

There was a **third, latent** bug that enabling AVX turned fatal: signal
delivery preserved the interrupted GPRs (#710) but not the FPU register file.
A signal can interrupt user code mid-SIMD, and glibc/musl use AVX pervasively
(memcpy/memset/strlen via IFUNC), so the handler's own FPU use clobbered the
interrupted YMM/XMM/x87 state with no restore on return. #711 closes all three.

---

## 2. XSAVE area layout (standard / non-compacted form)

Intel SDM Vol. 1 §13.4 (XSAVE area). An XSAVE area has three parts:

```
offset   size   region
0        512    LEGACY REGION   (identical layout to FXSAVE)
512      64     XSAVE HEADER
576      ...    EXTENDED REGION  (one block per enabled non-legacy component)
```

### Legacy region (bytes 0–511) — SDM Vol. 1 §10.5.1 (FXSAVE area)

| offset | field |
|--------|-------|
| 0      | FCW / FSW / FTW / FOP / FIP / FDP (x87 control/status) |
| 24     | **MXCSR** (SSE control/status) |
| 28     | **MXCSR_MASK** (valid-bit mask; written by FXSAVE) |
| 32–159 | ST0–ST7 / MM0–MM7 (x87/MMX), 16 bytes each |
| 160–415| XMM0–XMM15, 16 bytes each |
| 416–511| reserved / available |

### XSAVE header (bytes 512–575) — SDM Vol. 1 §13.4.2

| offset | size | field |
|--------|------|-------|
| 512    | 8    | **XSTATE_BV** — state-component bitmap: which components are present in the area |
| 520    | 8    | **XCOMP_BV** — compaction bitmap; **bit 63 = 1 ⇒ compacted form**, bit 63 = 0 ⇒ standard form |
| 528    | 48   | reserved (must be 0) |

### Extended region (from byte 576) — standard form

Each enabled non-legacy component occupies a fixed offset given by
`CPUID.(EAX=0Dh, ECX=n).EBX`. For **AVX (component bit 2 = YMM_Hi128)** the
block is at offset 576, size 256 bytes (the upper 128 bits of YMM0–15).

Total standard-form size for `x87|SSE|AVX` = 512 + 64 + 256 = **832 bytes**.
That is why `XSAVE_AREA_SIZE = 1024` (1 KiB) is safely larger, asserted against
`CPUID.(EAX=0Dh,ECX=0).EBX` at boot (see §4).

### Standard vs compacted form

- **Standard form** (XCOMP_BV[63]=0): components sit at their CPUID-defined
  fixed offsets; a component absent from XSTATE_BV still leaves a gap. Written
  by `XSAVE`/`XSAVEOPT`.
- **Compacted form** (XCOMP_BV[63]=1): components are packed with no gaps in
  XCOMP_BV order (optional 64-byte alignment per component). Written by
  `XSAVEC`/`XSAVES`. **AstryxOS uses standard form only** — `XSAVE` writes it
  and `fpu_restore_from_user` *requires* `XCOMP_BV == 0`, rejecting any
  compacted image.

### Init and modified optimizations — SDM Vol. 1 §13.6

- `XSAVE` **clears** an XSTATE_BV bit for any component that is in its init
  state (and may skip writing it). A **freshly zeroed area is a valid initial
  state** for `XRSTOR` (XSTATE_BV=0 ⇒ every component restored to init). This is
  why `FpuState::new_zeroed()` is a legitimate starting FPU context.
- `XRSTOR` with an XSTATE_BV bit **clear** restores that component to its
  **init** state — it is *not* left unchanged. (Consequence: a user crafting
  XSTATE_BV=0 in a sigreturn frame simply re-inits its own FP regs — benign, no
  leak.)

---

## 3. XSAVE / XRSTOR vs FXSAVE / FXRSTOR

| | saves/restores | alignment | area |
|--|--|--|--|
| `FXSAVE`/`FXRSTOR` | x87 + MXCSR + XMM0–15 (no YMM upper) | 16-byte | 512 B |
| `XSAVE`/`XRSTOR`   | everything in RFBM ∩ XCR0 (x87+SSE+AVX here) | **64-byte** | ≥ CPUID.0Dh size |

`XSAVE`/`XRSTOR` take a **requested-feature bitmap (RFBM)** in `EDX:EAX`; the
effective set is `RFBM ∩ XCR0`. AstryxOS passes `EDX:EAX = 0xFFFF_FFFF_FFFF_FFFF`
(all-ones) so every XCR0-enabled component is saved/restored; the AND with XCR0
restricts it to x87|SSE|AVX. Because `FpuState` is `#[repr(align(64))]` it
satisfies *both* the 64-byte (XSAVE) and 16-byte (FXSAVE) operand-alignment
requirements — a misaligned operand is `#GP` for either.

---

## 4. Enablement: OSXSAVE, XSETBV/XCR0, and the CPUID sizing assert

`arch::x86_64::enable_sse()` (BSP `init()`; **each AP** via `apic.rs`) does,
after the legacy SSE setup:

1. `CPUID.1:ECX` — check bit 26 (XSAVE) and bit 28 (AVX). If either is absent,
   leave the legacy FXSAVE path in place and never set `XSAVE_AVX_ENABLED`.
2. `CR4.OSXSAVE` (bit 18) = 1. This enables `XGETBV`/`XSETBV`/`XSAVE`/`XRSTOR`
   **and** makes `CPUID.1:ECX.OSXSAVE` (bit 27) report OS support so userspace
   feature detection works.
3. `XSETBV` with `ECX=0`, `EDX:EAX = XCR0 = x87|SSE|AVX` (bits 0,1,2).
   SDM Vol. 1 §13.3: bit 0 (x87) is mandatory, and bit 1 (SSE) **must** be set
   whenever bit 2 (AVX) is — an inconsistent XCR0 is `#GP` on `XSETBV`.
4. Assert `CPUID.(EAX=0Dh,ECX=0).EBX <= XSAVE_AREA_SIZE`. `EBX` at sub-leaf 0 is
   the XSAVE-area size for the state set now enabled in XCR0. A `FpuState`
   smaller than that would let `XSAVE` write past the allocation — so this fails
   **loudly at boot** rather than corrupting memory later.
5. Publish `XSAVE_AVX_ENABLED = true` (Release ordering).

> **`CR4` and `XCR0` are per-logical-processor and do not propagate.** Enabling
> them on the BSP only would leave every AP running with AVX disabled — a
> classic bug. AstryxOS runs `enable_sse()` on the BSP and on each AP; verify
> both paths whenever you touch this code.

### CPUID.(EAX=0Dh) reference — SDM Vol. 1 §13.2, Vol. 2A (CPUID)

| leaf | field | meaning |
|------|-------|---------|
| `ECX=0` | EAX/EDX | low/high bits of XCR0 the CPU supports (user state) |
| `ECX=0` | **EBX** | size of XSAVE area for features **currently enabled in XCR0** |
| `ECX=0` | ECX | max size for **all** XCR0-supported features |
| `ECX=1` | EAX | XSAVEOPT/XSAVEC/XGETBV(ECX=1)/XSAVES support bits |
| `ECX=1` | EBX | size for enabled features in `XCR0 | IA32_XSS` (compacted) |
| `ECX=n≥2` | EAX/EBX | per-component size / (standard-form) offset |

### XCR0 component bits (for future extension)

`0`=x87 (mandatory), `1`=SSE/XMM, `2`=AVX/YMM_Hi128, `3`=BNDREG, `4`=BNDCSR
(MPX), `5`=opmask (AVX-512 k0–k7), `6`=ZMM_Hi256, `7`=Hi16_ZMM, `9`=PKRU.
AstryxOS enables only bits 0–2. To add AVX-512 you must set bits 5,6,7 *as a
group* and grow `XSAVE_AREA_SIZE` — the boot assert will otherwise trip.

---

## 5. The IFUNC / OSXSAVE dependency (why AVX-without-OSXSAVE = #UD)

This is the exact failure #711 fixed on the userspace side, and it is the #1
question a teammate will ask.

The architecturally-correct AVX detection sequence (Intel; used by glibc/musl
IFUNC resolvers for memcpy/memset/strlen/etc.) is:

1. `CPUID.1:ECX.OSXSAVE` (bit 27) == 1 — the **OS** has enabled XGETBV and
   extended-state management. *This bit reflects `CR4.OSXSAVE`.*
2. `XGETBV` with ECX=0, then verify `XCR0[2:1] == 11b` — the OS has enabled both
   XMM and YMM state.
3. `CPUID.1:ECX.AVX` (bit 28) == 1 — the CPU supports AVX.

A VEX-encoded (AVX) instruction is **only legal** when `CR4.OSXSAVE=1` and
`XCR0.SSE` **and** `XCR0.AVX` are both set; otherwise it raises **#UD**
(SDM Vol. 2, VEX exception tables). So if the kernel advertises AVX in CPUID
(host passthrough) but never sets OSXSAVE/XCR0:

- a **careful** resolver checks step 1/2 and falls back to SSE — no crash, but
  no AVX;
- a resolver that trusts the AVX bit alone (or any hand-written AVX in the
  binary) executes a VEX instruction and takes `#UD`.

Setting `CR4.OSXSAVE` + `XCR0.AVX` makes both the CPUID `OSXSAVE` report and the
`XGETBV` result correct, so userspace dispatch selects (and may legally run) the
AVX paths. `XGETBV`/`XSETBV`/`XSAVE`/`XRSTOR` themselves `#UD` if
`CR4.OSXSAVE=0`.

**AVX-512 caveat:** an AVX-512 resolver additionally requires `XCR0[7:5]` all
set (opmask + ZMM_Hi256 + Hi16_ZMM). Since AstryxOS does **not** set those,
AVX-512 IFUNC variants must not be selected — the OSXSAVE/XGETBV gate correctly
steers a well-behaved resolver away from ZMM. If a binary force-uses AVX-512 it
will `#UD`; that is the intended behaviour until we grow XCR0/the area.

---

## 6. Context-switch FPU (eager)

AstryxOS is an **eager**-FPU kernel: `sched::mod.rs` unconditionally
`fpu_save`s the outgoing thread's state and `fpu_restore`s the incoming
thread's on every switch. It does **not** use the lazy `CR0.TS`/#NM trap scheme.

- Eager is the modern default; lazy FPU was abandoned industry-wide after the
  **LazyFP** speculative side channel (CVE-2018-3665) let one task read another
  task's FPU registers through a lazily-restored state. Eager save/restore has
  no such window.
- `CR0.EM=0`, `CR0.MP=1`, and `CR0.TS` is never set, so x87/SSE/AVX
  instructions never raise `#NM` (device-not-available) in normal operation.
- `fpu_save`/`fpu_restore` branch on `XSAVE_AVX_ENABLED`: `XSAVE`/`XRSTOR` when
  AVX is on, `FXSAVE`/`FXRSTOR` otherwise. The self-test
  (`test_xsave_avx_ymm_roundtrip`) round-trips a 256-bit YMM0 sentinel through
  save→clobber→restore to prove the upper 128 bits survive; it is a vacuous pass
  when AVX is unavailable (TCG).

---

## 7. Signal-frame FPU and the ring-3→ring-0 security boundary

### Save path

Both delivery paths (`signal_check_on_syscall_return` on the syscall-return
path, `deliver_fault_signal_from_isr` on the fault path) now:

1. Reserve a **64-byte-aligned** `XSAVE_AREA_SIZE` block at the top of the
   signal frame, just below the interrupted RSP (`fpstate_va = rsp - size & !0x3F`).
2. `fpu_save` the interrupted register file into it **under the active SMAP
   `UserGuard` (EFLAGS.AC=1)** — `XSAVE` is a supervisor store to a user page,
   so AC must be lifted or SMAP faults.
3. Record `fpstate_va` in `SignalFrame.fpstate` (this slot replaced the former
   `_pad`; the struct stays 160 bytes / 16-aligned — psABI signal-return
   contract, x86-64 psABI §3.2.3 / §3.4).

`fpstate == 0` means "no FPU state saved" and `sigreturn` skips the restore.

### Restore path — `fpu_restore_from_user`

The `fpstate` pointer is on the **user stack** and therefore fully attacker
controllable. Executing `XRSTOR` at CPL0 directly on that image is a
**ring-3 → ring-0 crash (and disclosure) primitive**, because:

- a malformed header `#GP`s **in the kernel** (see §8), and
- a range-valid-but-unmapped page `#PF`s in the kernel;
- AstryxOS has **no exception-fixup / extable**, and `idt.rs` only kills the
  process for CPL3 faults — a CPL0 fault here is an unrecoverable bugcheck
  reachable by any process crafting a `SignalFrame` and calling `sigreturn`.

`fpu_restore_from_user(user_va)` closes this with four gates, in order:

1. **`validate_user_ptr(user_va, XSAVE_AREA_SIZE)`** — the whole range must lie
   below `USER_VA_LIMIT` (0x0000_8000_0000_0000) with no wrap, and be non-null.
   *This is a security check, not cosmetic:* `virt_to_phys_in` (step 3) confirms
   only a PTE's PRESENT bit, **not** its US (user/supervisor) bit, and the
   kernel half + direct map are present in every process CR3 (shared
   PML4[256..512]). Without this gate a process could point `fpstate` at a
   64-aligned **kernel** VA and exfiltrate 1 KiB of kernel memory (via PHYS_OFF,
   effectively arbitrary physical memory) into its own XMM/YMM. SDM Vol. 3A §4.6
   (US bit / page-level protection).
2. **64-byte alignment** (`user_va & 0x3F == 0`) — else `XRSTOR` `#GP`.
3. **Copy through the fault-immune direct map** — for each page, translate via
   `virt_to_phys_in(cr3, page)` (an unmapped page returns a clean reject, never
   a `#PF`) and read through `PHYS_OFF`. This copies the untrusted image into a
   64-aligned **kernel** scratch buffer and removes the TOCTOU a
   validate-then-XRSTOR-in-place scheme would carry (a sibling unmapping the
   page between check and use).
4. **Header + MXCSR validation on the kernel copy** so `XRSTOR` cannot `#GP`
   (see §8): `MXCSR & 0xFFFF_0000 == 0`; and when AVX is enabled, standard-form
   checks `XSTATE_BV ⊆ XCR0`, `XCOMP_BV == 0`, and header reserved bytes
   [528,576) all zero.

Only then does it `XRSTOR` (via `fpu_restore`) **from the kernel buffer** —
which cannot `#PF` (kernel memory, always mapped) and cannot `#GP` (validated).
A rejected image leaves the current FPU untouched.

This mirrors how a mainstream kernel handles an untrusted sigframe XSTATE image
(header validation + a fault-tolerant copy), adapted to AstryxOS's
no-extable, direct-map-read idiom.

---

## 8. Fault-condition reference (#UD / #GP / #NM / #PF)

Consolidated from SDM Vol. 1 §13.7–13.8 (XSAVE/XRSTOR), §10.5, and Vol. 2/3.

**#UD** (illegal — feature not enabled):
- Any VEX-encoded (AVX) instruction when `CR4.OSXSAVE=0` or `XCR0.SSE`/`XCR0.AVX`
  not both set.
- `XSAVE`/`XRSTOR`/`XGETBV`/`XSETBV` when `CR4.OSXSAVE=0`.

**#GP** (malformed operand/state):
- `XSETBV` at CPL>0; or setting an invalid `XCR0` (clearing bit 0; AVX set with
  SSE clear; a reserved/unsupported bit).
- `XSAVE`/`XRSTOR`/`FXSAVE`/`FXRSTOR` operand not correctly aligned
  (64-byte for XSAVE/XRSTOR, 16-byte for FXSAVE/FXRSTOR).
- `XRSTOR` **standard form**: `XSTATE_BV` sets a bit not in `XCR0`; `XCOMP_BV`
  nonzero; header reserved bytes [528,576) nonzero.
- `XRSTOR` **compacted form** (XCOMP_BV[63]=1): additionally, `XCOMP_BV[62:0]`
  sets a bit not in XCR0, or `XSTATE_BV` sets a bit not in `XCOMP_BV`.
- Loading **MXCSR** with a reserved bit set (any architected reserved bit
  31:16, **or** a bit 15:0 not in the CPU's `MXCSR_MASK`).

**#NM**: `XSAVE`/`XRSTOR`/x87/SSE/AVX when `CR0.TS=1` (lazy-FPU trap). Not used
by AstryxOS (eager; TS clear).

**#PF**: `XSAVE` to a non-writable/unmapped page, or `XRSTOR` from an
unmapped page. At CPL0 on a user image this is the crash primitive §7 defends
against.

---

## 9. MXCSR and MXCSR_MASK — and the known follow-up

- **MXCSR** (legacy offset 24) is the SSE control/status word: rounding mode,
  flush-to-zero (FTZ, bit 15), denormals-are-zero (DAZ, bit 6), exception masks
  (bits 12:7), exception flags (bits 5:0). Default `0x1F80` (all exceptions
  masked, round-to-nearest). Architected **reserved** bits are 31:16.
- **MXCSR_MASK** (legacy offset 28) is written by `FXSAVE`: a 1 bit means that
  MXCSR bit is writable on this CPU. A `0` bit in the mask means that MXCSR bit
  is reserved *on this CPU* even within 15:0 (e.g. DAZ, bit 6, is only available
  when the mask says so). Loading MXCSR with any bit set that is 0 in the mask
  `#GP`s. SDM Vol. 1 §10.5.1.1.

**Follow-up (documented, not yet done):** `fpu_restore_from_user` validates
MXCSR against a **fixed** `0xFFFF_0000` reserved mask — it rejects a set bit in
31:16 but does **not** reject a set bit in 15:0 that is outside the CPU's real
`MXCSR_MASK`. This is provably `#GP`-free **only** because every SSE2+/AVX CPU
(our target — see §11) has `MXCSR_MASK` covering all of 15:0, so a
15:0-only-bits image cannot `#GP`. A fully CPU-general fix snapshots
`MXCSR_MASK` at boot (from `FXSAVE+28`) and validates
`mxcsr & !(0xFFFF | boot_mxcsr_mask_low)` — cheap, one-time, and closes the last
theoretical `XRSTOR #GP`. Worth doing if we ever run on hardware with a
restricted mask.

---

## 10. Operational: AVX amplified the W215 flake

Enabling AVX **increased** the observed flake rate of the parked W215
content-corruption saga in the kernel-smoke boot (roughly ~43% → ~83%). This is
**expected** and is *not* a defect in the XSAVE path:

- AVX-enabled glibc dispatches its hot string/memory routines
  (memcpy/memset/strlen/…) to **vector** implementations that touch far more
  memory per call and are used pervasively.
- W215 is a live-frame / page-recycle corruption. When more of the workload
  flows through wide vector loads/stores, any corrupted live frame is *read*
  more often and with a wider blast radius, so the latent corruption surfaces
  more frequently.

Takeaway for the W215 team: the amplification is a **sensitivity** change, not a
new failure mode — treat AVX-on as a *stronger reproducer* of the existing bug,
not as a regression introduced by #711. If you need a *lower*-sensitivity repro
you can force the FXSAVE fallback by masking AVX in CPUID (TCG, or `-cpu` tuning
under KVM), but the corruption itself is upstream of the FPU path.

---

## 11. Virtualization notes

- **KVM `-cpu host`** passes the host's AVX/XSAVE CPUID and XCR0 through to the
  guest; AstryxOS then sets `OSXSAVE`/`XCR0` for real. This is the path where
  the AVX self-test and the AVX-enabled Firefox runs exercise the full XSAVE
  path.
- **TCG (`--no-kvm`)** frequently does **not** advertise AVX. On such a run
  `have_avx` is false, `XSAVE_AVX_ENABLED` stays false, and the kernel uses the
  `FXSAVE`/`FXRSTOR` fallback — correct, since there is no YMM state to preserve.
  The self-test passes vacuously. **Do not assume the XSAVE path is exercised
  under TCG.** CI that must cover XSAVE needs a KVM (or AVX-advertising) runner.
- Because area sizing is asserted against live `CPUID.(EAX=0Dh,ECX=0).EBX`, a
  host exposing a larger XCR0 set than we enable is fine (EBX reflects only
  what we put in XCR0), but a host/config that would need > 1 KiB for x87|SSE|AVX
  is impossible — the assert exists to catch a future XCR0 expansion, not host
  variance.

---

## 12. AstryxOS invariants to memorise

- `XSAVE_AREA_SIZE = 1024`, 64-byte aligned, **standard (non-compacted)** form
  only. `FpuState` is `#[repr(C, align(64))]`.
- `XCR0 = x87 | SSE | AVX` (bits 0,1,2). No MPX / AVX-512 / PKRU.
- `OSXSAVE` + `XSETBV` are set on the **BSP and every AP** — per-logical-CPU, do
  not propagate.
- Eager FPU: `fpu_save`/`fpu_restore` run on **every** context switch; `CR0.TS`
  is never set (no lazy `#NM`).
- All FPU asm is gated on `XSAVE_AVX_ENABLED` — XSAVE/XRSTOR when true, FXSAVE/
  FXRSTOR when false. A zeroed area is a valid initial XRSTOR/FXRSTOR state.
- `sigreturn` restores FPU via `fpu_restore_from_user`, **never** a raw XRSTOR on
  the user image — that function is the security boundary. Any new path that
  restores FPU from user-controlled memory must go through it (or replicate all
  four gates in §7).
- `SignalFrame.fpstate` (offset of the former `_pad`) holds the user VA of the
  saved area, or 0 for "none". Struct stays 160 bytes.

## Known follow-ups

1. **MXCSR_MASK snapshot** (§9) — validate 15:0 against the boot-snapshotted
   CPU mask, not a fixed `0xFFFF_0000`. Hardening; unreachable on the current
   target.
2. **AVX-512** — would need `XCR0[7:5]`, a larger `XSAVE_AREA_SIZE`, and updated
   header validation (the boot assert already guards the size). Not planned.
3. **CI coverage** — ensure at least one KVM/AVX runner so the XSAVE path (not
   just the FXSAVE fallback) is exercised.

---

### Primary sources

- Intel® 64 and IA-32 Architectures SDM — Vol. 1 §10.5 (FXSAVE/MXCSR),
  §13.1–13.8 (XSAVE feature set, area layout, XSAVE/XRSTOR, init/modified
  optimizations); Vol. 2 (CPUID leaf 0Dh, XSAVE/XRSTOR/XGETBV/XSETBV,
  VEX exception tables); Vol. 3A §2.5–2.6 (CR4.OSXSAVE, XCR0), §4.6
  (page-level US protection).
- AMD64 Architecture Programmer's Manual — Vol. 2 (system programming;
  XSAVE/XCR0) and Vol. 4 (XSAVE/XRSTOR instruction reference) for the AMD
  equivalents; semantics match the SDM for the state we use.
- x86-64 System V psABI §3.2.3 / §3.4 — signal-return register contract.
- POSIX.1-2017 `sigaction(2)` — signal-handler argument/return semantics.
- The GNU C Library manual, "X86" node — IFUNC-based CPU-feature dispatch.
