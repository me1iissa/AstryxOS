# Firefox on AstryxOS — X11 Path Plan

> Baseline: 95/95 tests, Firefox binary compiled (glibc ESR 115), runs 1481 syscalls before crash

---

## Current State

**Binary:** `/disk/lib/firefox/firefox-bin` — ELF64 PIE, glibc `ld-linux-x86-64.so.2`, 2.7 MB
**Resources:** `/disk/lib/firefox/` — 216 MB (libxul.so ~194 MB, NSS, SQLite, GTK, etc.)
**Data disk:** 512 MiB FAT32 with Firefox + glibc + musl + TCC

**Works today:**
- ld-linux resolves 30+ shared .so files via file-backed mmap demand-paging (1476 page faults handled)
- arch_prctl(ARCH_SET_FS), set_tid_address, futex, clone, wait4 all dispatch correctly
- 1481 syscalls execute before crash
- X11 server ready on `/tmp/.X11-unix/X0` (fd=0), DISPLAY=:0, GDK_BACKEND=x11 in envp

**Crashes today:**
1. Syscall 187 → ENOSYS ×13 (harmless, just noisy — it's `readahead()`)
2. Fork child process (`clone(SIGCHLD|CHILD_SETTID|CHILD_CLEARTID)`) immediately crashes at **RIP=0x0**
3. Parent process also crashes at **RIP=0x0** shortly after (at getpid return)

---

## Root Cause Analysis

**Primary cause — incomplete AT_HWCAP:**

glibc uses IFUNC (indirect function) resolvers to pick optimized implementations of
`memcpy`, `memset`, `strlen`, `strcmp`, etc. based on CPU capabilities reported in AT_HWCAP.

Current `AT_HWCAP = 0x3200200` is missing critical bits:
- `HWCAP_FPU (0x1)` — x87 FPU
- `HWCAP_TSC (0x10)` — RDTSC
- `HWCAP_CX8 (0x100)` — CMPXCHG8B (required by many glibc IFUNC resolvers)
- `HWCAP_SEP (0x400)` — SYSENTER
- `HWCAP_CMOV (0x4000)` — conditional moves (required for optimized string ops)
- `HWCAP_FXSR (0x400000)` — FXSAVE/FXRSTOR
- `HWCAP_XMM (0x800000)` — SSE (NOT the same as SSE2!)

When an IFUNC resolver can't find its expected feature bits, it leaves the function
pointer as NULL. Any call to that function → crash at 0x0. This explains BOTH the
child crash (in glibc fork handler calling optimized memset/memcpy) and the parent
crash (eventually hitting the same NULL function pointer).

**Secondary cause — missing syscall 187:**
`readahead(fd, offset, count)` — called by ld-linux to pre-cache each .so file.
Returns ENOSYS today. Harmless (glibc ignores it), but clutters the log.

---

## Phase 1 — Fix the Crashes (COMPLETE)

### 1a. Fix AT_HWCAP in auxvec
**File:** `kernel/src/proc/elf.rs` — line ~983 (auxvec construction in `load_elf_with_args`)

```rust
// Complete x86_64 baseline — FPU|TSC|MSR|CX8|APIC|SEP|CMOV|CLFLUSH|MMX|FXSR|SSE|SSE2|HT
let at_hwcap: u64 = 0x1 | 0x10 | 0x20 | 0x100 | 0x200 | 0x400
                  | 0x4000 | 0x40000 | 0x200000 | 0x400000
                  | 0x800000 | 0x1000000 | 0x4000000;
```

### 1b. Map syscall 187 → readahead stub
**File:** `kernel/src/syscall/mod.rs`

```rust
187 => 0,  // readahead(fd, offset, count) — no page cache, return success
```

### 1c. Add /etc/ files to data disk
**File:** `scripts/create-data-disk.sh`

Creates: hostname, hosts, resolv.conf (nameserver 10.0.2.3), nsswitch.conf

### 1d. Fix Firefox envp
**File:** `kernel/src/gui/terminal.rs`

Added: HOME=/home/user, LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/disk/lib/firefox,
XDG_RUNTIME_DIR=/tmp, XDG_CONFIG_HOME=/tmp/.config

### 1e. Firefox launch arguments
**File:** `kernel/src/main.rs` (firefox-test feature) and `gui/content.rs`

Added: `--no-remote --profile /tmp/ff-profile --new-instance`

---

## Phase 2 — X11 Window Creation (0.5 sessions)

### 2a. ClientMessage handler (opcode 33)
**File:** `kernel/src/x11/mod.rs`

GTK sends ClientMessage for `_NET_WM_STATE`, WM_PROTOCOLS, etc.
No reply needed — minimal no-op handler is safe.

---

## Phase 3 — RENDER Glyph Sets for Text (1-2 sessions)

Cairo uses `RenderCompositeGlyphs8/16/32` for ALL text rendering.
Without this, Firefox window renders but all text is blank.

### 3a. GlyphSet resource type
**File:** `kernel/src/x11/resource.rs`

```rust
pub struct GlyphInfo { width, height: u16; x_off, y_off, x_adv, y_adv: i16 }
pub struct GlyphSet { format: u32, glyphs: Vec<(u32, GlyphInfo, Vec<u8>)> }
```

### 3b. RENDER minor opcodes 17-25
**File:** `kernel/src/x11/proto.rs`

### 3c-3e. CreateGlyphSet / AddGlyphs / CompositeGlyphs handlers
**File:** `kernel/src/x11/mod.rs`

CompositeGlyphs: alpha-blend src Picture at each glyph position using A8 alpha mask.

---

## Phase 4 — Firefox Profile + Fonts (0.5 sessions)

- Profile: `FONTCONFIG_PATH=/disk/lib/firefox/fonts`
- /tmp already RamFS (writable) — no change needed

---

## Phase 5 — Browsing (2+ sessions)

TCP stack already done. DNS via SLIRP (10.0.2.3). NSS handles TLS internally.

---

## Test Commands

```bash
bash scripts/run-test.sh                          # must stay 95/95
bash scripts/run-firefox-test.sh                  # check for progress
grep -c "RIP: 0x000000000*0$" build/firefox-test-serial.log   # should be 0
```

## Risk: If AT_HWCAP doesn't fix the crash

1. Check fork child register inheritance (CRT Phase 0):
   - `fork_child_entry` must restore RBP, RBX, R12-R15 from parent
   - glibc `__fork` epilogue checks stack canary via `mov -0x38(%rbp), %rax`
   - If RBP=0 → SIGSEGV in __fork → may manifest as crash at 0x0
2. Add `LIBC_FATAL_STDERR_=1` to envp to surface glibc error messages
3. Add AT_EXECFN and AT_PLATFORM to auxvec
