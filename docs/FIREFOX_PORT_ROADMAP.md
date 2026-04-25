# AstryxOS Firefox Port — Master Roadmap

**Goal:** Compile and run Mozilla Firefox inside AstryxOS desktop mode.

**Date:** 2026-03-01
**Current State:** Kernel has dual-ABI syscalls (native + Linux x86_64), CoW fork, demand paging,
TCP/IP stack, NT-style WM/GDI — but no usable userspace (3 hand-assembled ELFs, no libc,
no dynamic linker, no threading, no userspace graphics).

---

## Progression Log

Running tally of where `firefox-test` stalls. Tick = 10 ms at the 100 Hz kernel timer.

| Date       | Ticks | Blocker                                                               | Resolution / tracking                                                        |
|------------|-------|-----------------------------------------------------------------------|------------------------------------------------------------------------------|
| 2026-04-23 | 2071  | `libgtk-3.so.0` missing during `XPCOMGlueLoad` (post-sysfs-st_size fix) | Resolved: host-lib staging — commit `c86b9a5` stages 67 real GTK3/X11/Pango/Cairo libs. |
| 2026-04-23 | 29500 | Scheduler watchdog `BUGCHECK 0xdead0004` at tick 43401 during NSS/ICU/fontcache init | New issue — watchdog raise / runtime config. See GitHub issue for scheduler watchdog P1. |

- 2026-04-24: tick 75002 (post-WATCHDOG_LIMIT bump to 60000 under firefox-test).
  Firefox now enters a 70k-tick pure-userspace CPU loop after reading
  `/proc/mounts`; watchdog still fires despite raised limit. Root cause is
  in userspace, not the kernel. Trace flags (`syscall-trace`, `pf-trace`)
  landed in 2911a10 to support the next round of bisection. See issue #40.

Design pivot captured on 2026-04-23: for GTK3 core we now use real host libraries rather than stubs, because `libmozgtk` calls into real GTK3 APIs for widget creation and event-loop integration (not just symbol resolution). Stubs remain the right answer for D-Bus / accessibility / IM module adapters.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         Firefox (Gecko)                          │
├──────────────┬──────────────┬──────────────┬─────────────────────┤
│ SpiderMonkey │   Networking  │   Graphics   │   Content/Layout   │
│  (JS engine) │  (Necko/NSS) │  (WebRender) │                    │
├──────────────┴──────────────┴──────────────┴─────────────────────┤
│               Firefox Dependencies Layer                         │
│  zlib, libpng, freetype, fontconfig, harfbuzz, libffi,          │
│  pixman, cairo (or skia), NSS/NSPR, ICU, sqlite                 │
├──────────────────────────────────────────────────────────────────┤
│               AstryxOS Userspace Libraries                       │
│  musl libc (static) → musl libc (dynamic)                       │
│  libastryxgfx (framebuffer/window client library via ALPC)      │
│  libastryxinput (keyboard/mouse events via ALPC)                │
├──────────────────────────────────────────────────────────────────┤
│               AstryxOS Kernel (Linux x86_64 ABI)                 │
│  Syscalls, VFS, TCP/IP, e1000, Scheduler, VMM, Signals          │
│  WM/GDI compositor, ALPC IPC, Device drivers                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Phase Summary

| Phase | Description | Milestone | Est. Scope |
|-------|-------------|-----------|------------|
| **1** | Bootstrap: musl hello world | First C program runs on AstryxOS | Small |
| **2** | Core POSIX: threading + memory | pthreads, mprotect, poll work | Large |
| **3** | Filesystem & device maturity | /proc, /dev/null, /dev/urandom, tmpfs | Medium |
| **4** | Network sockets as file descriptors | socket→fd unification, accept, poll on sockets | Medium |
| **5** | Dynamic linker & PIE support | ET_DYN, PT_INTERP, ld-musl-x86_64.so.1 | Large |
| **6** | Userspace graphics protocol (ALPC) | Framebuffer sharing, window creation, input events | Large |
| **7** | Firefox dependency libraries | zlib, libpng, freetype, pixman, NSS, ICU, sqlite | Large |
| **8** | Firefox build & integration | moz.build + AstryxOS backend, WebRender→fbdev | Very Large |
| **9** | Polish & optimization | GPU accel, audio, clipboard, DnD, printing | Ongoing |

---

## Phase 1: Bootstrap — Static musl Hello World

**Goal:** Compile a C program with musl libc, load it from the FAT32 disk, and see
its output on the serial console. Proves the full toolchain → kernel → userspace path.

### 1.1 Install cross-compiler (host side)

```bash
sudo apt install musl-tools    # provides musl-gcc wrapper
```

Compile with:
```bash
musl-gcc -static -no-pie -O2 -o hello hello.c
```

This produces an `ET_EXEC` x86_64 ELF statically linked against musl, using Linux
syscall numbers. AstryxOS's `dispatch_linux()` already handles these.

### 1.2 Set up argc/argv/envp/auxvec on user stack

**File:** `kernel/src/proc/elf.rs`

musl's `_start` expects this stack layout (RSP points to argc):

```
[high]
  16 random bytes (for AT_RANDOM)
  program path string: "/bin/hello\0"
  env strings: "HOME=/\0", "PATH=/bin\0", etc.
  argv strings: "hello\0"
  padding to 16-byte align
  ─── auxvec ───
  AT_NULL(0), 0
  AT_RANDOM(25), ptr_to_random_bytes
  AT_PAGESZ(6), 4096
  ─── envp ───
  NULL
  ptr to "PATH=/bin\0"
  ptr to "HOME=/\0"
  ─── argv ───
  NULL
  ptr to "hello\0"
  ─── argc ───
  1                      ← RSP at _start
[low]
```

**Implementation:**
- Add a `setup_user_stack()` function in `elf.rs` that writes this layout into
  the already-allocated stack pages.
- Accept `argv: &[&str]` and `envp: &[&str]` parameters in `load_elf()` or in
  a new wrapper `prepare_process_stack()`.
- Write strings at the top of the stack area, then the auxvec/envp/argv/argc
  below them, and return the adjusted RSP.
- Ensure final RSP is 16-byte aligned.

### 1.3 Enable Linux ABI for loaded ELF binaries

**File:** `kernel/src/syscall/mod.rs`

Currently `linux_abi` is set only for specific embedded test binaries. ELF binaries
loaded from disk via `exec` need `linux_abi = true` set based on:
- ELF OS/ABI field (`ELFOSABI_NONE` or `ELFOSABI_LINUX`), OR
- A kernel policy (all disk-loaded programs use Linux ABI), OR
- An exec flag

### 1.4 Verify required syscalls work correctly

musl static hello world needs exactly these syscalls:

| Syscall | Linux # | Current Status | Action Needed |
|---------|---------|----------------|---------------|
| `arch_prctl(SET_FS)` | 158 | ✅ Works | None |
| `set_tid_address` | 218 | ✅ Works | None |
| `ioctl(TIOCGWINSZ)` | 16 | ✅ Works | Returns -ENOTTY for non-tty (OK) |
| `writev` | 20 | ✅ Works | None |
| `exit_group` | 231 | ✅ Works | None |

### 1.5 Copy ELF to disk image and load via exec

- Place the compiled `hello` binary into the FAT32 data disk image at `/bin/hello`.
- Shell command `exec /bin/hello` should load it via `sys_exec()`.
- Verify serial output: `Hello, world!`

### 1.6 Test automation

Add a test that:
1. Loads the musl hello-world from `/bin/hello`
2. Captures its serial output
3. Verifies exit code 0

### Phase 1 Deliverables
- [ ] `setup_user_stack()` in elf.rs (argc/argv/envp/auxvec)
- [ ] Linux ABI auto-detection for loaded ELFs
- [ ] musl-gcc hello.c compiled and placed on disk image
- [ ] Successful execution with serial output
- [ ] Test case added to test suite

---

## Phase 2: Core POSIX — Threading + Memory Protection

**Goal:** Implement real threads (`clone(CLONE_VM|CLONE_THREAD)`), `mprotect`,
and I/O multiplexing (`poll`/`epoll`). These are prerequisites for nearly every
non-trivial program, especially Firefox's SpiderMonkey JIT and multi-process architecture.

### 2.1 Real `clone` with `CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND`

**File:** `kernel/src/proc/mod.rs`, `kernel/src/syscall/mod.rs`

Current `clone` = `fork` (full address space copy). Need:

- **`CLONE_VM`**: Child shares parent's `VmSpace` and CR3 (no CoW, same page tables).
- **`CLONE_THREAD`**: Child is a thread in the same process (same PID, new TID).
  Shares file descriptor table, signal handlers, CWD.
- **`CLONE_SETTLS`**: Set child's FS base (TLS) from a clone argument.
- **`CLONE_PARENT_TIDPTR`** / **`CLONE_CHILD_TIDPTR`**: Write TID to user-space
  pointers (needed for `pthread_create` in musl).
- **New thread stack**: The child uses the stack pointer passed in `clone()`'s
  `child_stack` argument (RSI in Linux ABI).

**Thread lifecycle:**
- Thread has its own kernel stack, saved registers, TLS (FS base), signal mask.
- Shares: address space, file descriptors, PID, signal actions.
- `exit()` from a thread should only exit that thread (decrement thread count).
  When last thread exits, process is destroyed.

### 2.2 `futex` enhancements

**File:** `kernel/src/syscall/mod.rs`

Current futex supports `FUTEX_WAIT` and `FUTEX_WAKE`. Need:

- **Timeout support** for `FUTEX_WAIT` (timeout argument, wake on timer).
- **`FUTEX_REQUEUE`**: Move waiters from one futex to another (used by
  `pthread_cond_broadcast`).
- Key hashing by virtual address (not pid+vaddr) for shared futexes.

### 2.3 Real `mprotect`

**File:** `kernel/src/syscall/mod.rs`, `kernel/src/mm/vma.rs`

Currently a no-op stub. Need:

- Walk the page tables for the given virtual address range.
- Update PTE flags: set/clear `PAGE_WRITABLE`, `PAGE_NO_EXECUTE`, `PAGE_PRESENT`.
- Split VMAs at protection boundaries if needed.
- Flush TLB for affected pages (`invlpg` or full `mov cr3, cr3`).
- **Critical for SpiderMonkey JIT**: allocate RW pages, write code, then
  `mprotect(PROT_READ|PROT_EXEC)` to make executable.

### 2.4 `poll` / `ppoll`

**File:** new `kernel/src/syscall/poll.rs`

Implement `poll(struct pollfd *fds, nfds_t nfds, int timeout)` (Linux #7):

- For each fd, check readiness: `POLLIN` (data to read), `POLLOUT` (can write),
  `POLLERR`, `POLLHUP`.
- File types: pipe (check ring buffer), socket (check rx queue), regular file
  (always ready), tty (check input buffer).
- If no fds ready, block with timeout (or return immediately if timeout=0).
- Later: `epoll_create`/`epoll_ctl`/`epoll_wait` for scalable I/O multiplexing.

### 2.5 `pipe2` and `eventfd`

- `pipe2(fds, flags)`: Like existing `pipe()` but with `O_CLOEXEC`, `O_NONBLOCK`.
- `eventfd(initval, flags)`: Simple counter-based signaling fd. Needed for
  event loops, inter-thread wakeup.

### Phase 2 Deliverables
- [ ] `clone()` with CLONE_VM|CLONE_THREAD|CLONE_SETTLS|CLONE_*TIDPTR
- [ ] Per-thread TLS (FS base) on context switch (already exists)
- [ ] Thread-safe file descriptor sharing
- [ ] `futex` with timeout and FUTEX_REQUEUE
- [ ] Real `mprotect` with page table walks and TLB flush
- [ ] `poll` / `ppoll` syscall
- [ ] `pipe2`, `eventfd`
- [ ] Test: multi-threaded C program using pthreads via musl

---

## Phase 3: Filesystem & Device Maturity

**Goal:** Programs expect a standard Linux-like filesystem with `/proc`, `/dev`
devices, and temporary storage.

### 3.1 `/proc` filesystem (VFS-mounted)

**File:** `kernel/src/vfs/procfs.rs` (exists but shell-only, not VFS-mounted)

Mount procfs at `/proc`. Provide at least:
- `/proc/self/exe` → symlink to current executable path
- `/proc/self/maps` → memory map (VMA listing)
- `/proc/self/fd/` → directory of open fds
- `/proc/self/status` → process status
- `/proc/cpuinfo` → CPU info
- `/proc/meminfo` → memory stats
- `/proc/sys/` → sysctl-like interface

### 3.2 Device nodes in `/dev`

**File:** `kernel/src/vfs/devfs.rs` (new)

Replace the current ramfs-backed `/dev` with proper device nodes:

| Device | Behavior |
|--------|----------|
| `/dev/null` | Reads return 0 bytes; writes are discarded |
| `/dev/zero` | Reads return zero bytes; writes discarded |
| `/dev/urandom` | Reads return random bytes (use RDRAND or seed) |
| `/dev/random` | Same as urandom (modern Linux behavior) |
| `/dev/tty` | Current process's controlling terminal |
| `/dev/console` | Serial console |
| `/dev/fb0` | Framebuffer device (mmap-able) |

### 3.3 `tmpfs`

Mount a ramfs instance at `/tmp` with no persistence. Programs expect `/tmp` to
be writable.

### 3.4 Additional VFS syscalls

- `readlink` (89) — for `/proc/self/exe`
- `access` / `faccessat` (21/269) — already partially implemented
- `statfs` / `fstatfs` (137/138) — filesystem statistics
- `ftruncate` (77) — truncate file to length
- `rename` / `renameat` (82/264) — rename files
- `symlink` / `symlinkat` (88/266) — create symlinks (VFS supports it, syscall missing)
- `utimensat` (280) — set file timestamps

### Phase 3 Deliverables
- [ ] procfs mounted at /proc with self/exe, self/maps, cpuinfo
- [ ] devfs with functional null, zero, urandom, tty, console
- [ ] tmpfs at /tmp
- [ ] readlink, access, statfs, ftruncate, rename, symlink syscalls
- [ ] Test: C program reads /proc/self/maps, writes to /dev/null

---

## Phase 4: Network Socket Unification

**Goal:** Sockets become file descriptors. Programs can `read()`/`write()` on
sockets, and `poll()` works on them.

### 4.1 Socket-as-fd

**File:** `kernel/src/net/socket.rs`, `kernel/src/vfs/mod.rs`

Currently sockets have their own ID space separate from fds. Unify:

- `socket()` returns an fd (allocates in the process fd table).
- fd has a type tag: `FdType::File`, `FdType::Pipe`, `FdType::Socket`.
- `read(fd)` on a socket fd → `recv()`.
- `write(fd)` on a socket fd → `send()`.
- `close(fd)` on a socket fd → close the socket.
- `poll(fd)` on a socket fd → check socket rx/tx queues.

### 4.2 `accept()`

Implement TCP `accept()`:
- `listen()` marks socket as listening.
- Incoming SYN → kernel completes 3-way handshake, queues connection.
- `accept()` dequeues a connection, returns new fd for the connected socket.

### 4.3 Socket options

- `setsockopt` / `getsockopt` — at minimum:
  - `SO_REUSEADDR`
  - `SO_KEEPALIVE`
  - `TCP_NODELAY`
  - `SO_RCVBUF` / `SO_SNDBUF`
  - `SO_ERROR`

### 4.4 `sendmsg` / `recvmsg`

Needed for ancillary data (fd passing), scatter-gather I/O.

### 4.5 Unix domain sockets (`AF_UNIX`)

Firefox uses Unix sockets for IPC between processes. Need at least:
- `SOCK_STREAM` and `SOCK_DGRAM` variants
- `connect`, `bind`, `listen`, `accept`
- fd passing via `SCM_RIGHTS` (later, for multi-process Firefox)

### Phase 4 Deliverables
- [ ] Socket fds unified with file fds
- [ ] read/write/poll work on socket fds
- [ ] TCP accept() with connection queue
- [ ] Basic setsockopt/getsockopt
- [ ] sendmsg/recvmsg with iovec
- [ ] AF_UNIX basic support
- [ ] Test: C program opens TCP connection, reads response via read()

---

## Phase 5: Dynamic Linker & PIE Support

**Goal:** Load dynamically-linked ELF binaries, resolve shared libraries,
support position-independent executables.

### 5.1 `ET_DYN` support in ELF loader

**File:** `kernel/src/proc/elf.rs`

- Accept `ET_DYN` (type 3) in addition to `ET_EXEC` (type 2).
- For `ET_DYN`: pick a random-ish load base (e.g., `0x5555_5555_0000`) and
  add it to all segment virtual addresses.
- Apply relocations for a standalone PIE (no interp), or...

### 5.2 `PT_INTERP` handling

- If the ELF has a `PT_INTERP` segment, read the interpreter path
  (e.g., `/lib/ld-musl-x86_64.so.1`).
- Load the interpreter ELF first (it's also `ET_DYN`), then the main program.
- Set entry point to the interpreter's entry.
- Pass `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_ENTRY`, `AT_BASE` in auxvec
  so the interpreter can find the main program's headers.

### 5.3 Dynamic linker (`ld-musl-x86_64.so.1`)

musl's dynamic linker is part of `libc.so` itself. When building musl:

```bash
# Build musl shared
./configure --prefix=/opt/musl --syslibdir=/lib
make && make install
# This produces ld-musl-x86_64.so.1 and libc.so
```

Place `ld-musl-x86_64.so.1` at `/lib/ld-musl-x86_64.so.1` on the disk image.

### 5.4 Shared library loading support

The dynamic linker will call `mmap` to map `.so` files. Requirements:
- `mmap(fd, offset, ...)` with file-backed mappings must work for executables.
- `mprotect` must work (to set segment permissions after mapping).
- `MAP_FIXED` must work reliably.

### Phase 5 Deliverables
- [ ] ET_DYN loading with base address relocation
- [ ] PT_INTERP: load interpreter, hand off control
- [ ] auxvec entries: AT_PHDR, AT_BASE, AT_ENTRY, AT_PHENT, AT_PHNUM
- [ ] musl dynamic linker built and placed on disk
- [ ] Test: dynamically-linked C program loads and runs

---

## Phase 6: Userspace Graphics Protocol via ALPC

**Goal:** Userspace programs can create windows, draw to them, and receive
input events via AstryxOS's existing ALPC IPC infrastructure.

### 6.1 Display Server (kernel-side ALPC service)

**ALPC port:** `\ALPC\DisplayServer`

The kernel's existing Window Manager and GDI compositor become a display server
that userspace programs communicate with via ALPC messages.

**Protocol messages (client → server):**

| Message | Parameters | Response |
|---------|------------|----------|
| `CreateWindow` | title, x, y, w, h, class | window_handle, shm_id |
| `DestroyWindow` | handle | ack |
| `MoveWindow` | handle, x, y | ack |
| `ResizeWindow` | handle, w, h | new shm_id |
| `SetTitle` | handle, title | ack |
| `ShowWindow` | handle, show/hide | ack |
| `InvalidateRect` | handle, rect | (compositor redraws) |
| `SetCursor` | cursor_type | ack |

**Protocol messages (server → client, via event channel):**

| Event | Parameters |
|-------|------------|
| `Paint` | handle, damage_rect |
| `KeyDown` / `KeyUp` | handle, vkey, scancode, modifiers |
| `MouseMove` | handle, x, y, buttons |
| `MouseButton` | handle, button, pressed, x, y |
| `Resize` | handle, new_w, new_h |
| `Close` | handle |
| `Focus` / `Blur` | handle |

### 6.2 Shared memory framebuffer

Each window gets a shared memory region:
- Server allocates physical pages for the window's pixel buffer.
- Client maps them via `mmap` of a special device or shared memory fd.
- Client draws directly to the buffer (ARGB32, stride = width * 4).
- Client sends `InvalidateRect` to tell the compositor to redraw.

**Implementation:** Use `MAP_SHARED` with a device fd (`/dev/shm/window_<handle>`)
or a new `shm_open` / `shm_unlink` syscall pair.

### 6.3 `libastryxgfx` — userspace client library

A C library that wraps the ALPC protocol:

```c
#include <astryx/gfx.h>

AstryxWindow *astryx_create_window(const char *title, int w, int h);
void *astryx_get_framebuffer(AstryxWindow *win);  // returns ARGB32 pixel buffer
void astryx_invalidate(AstryxWindow *win, int x, int y, int w, int h);
AstryxEvent astryx_next_event(AstryxWindow *win);
void astryx_destroy_window(AstryxWindow *win);
```

### 6.4 Firefox graphics backend

Firefox's WebRender needs a "widget" backend to put pixels on screen.
Options:
- **Framebuffer backend**: WebRender renders to a CPU buffer, then
  `memcpy` to the shared memory framebuffer. Simple but slow.
- **Custom Wayland-like**: More complex but potentially GPU-accelerated later.

For initial port, use the framebuffer approach.

### Phase 6 Deliverables
- [ ] DisplayServer ALPC service in kernel
- [ ] Shared memory window buffers
- [ ] libastryxgfx C library
- [ ] Input event delivery to userspace
- [ ] Test: C program creates window, draws gradient, handles key events
- [ ] Demo: terminal emulator running in a window

---

## Phase 7: Firefox Dependency Libraries

**Goal:** Cross-compile all Firefox dependencies against musl for AstryxOS.

### Build system

Create a `toolchain/` directory with:
- `x86_64-astryx-linux-musl` sysroot (musl headers + libs)
- Cross-compilation wrapper scripts
- pkg-config cross files

### Required libraries (in build order)

| Library | Version | Purpose | Complexity |
|---------|---------|---------|------------|
| **zlib** | 1.3+ | Compression | Trivial (no deps) |
| **libffi** | 3.4+ | Foreign function interface | Small |
| **ICU** | 73+ | Unicode/i18n | Medium (large but self-contained) |
| **SQLite** | 3.40+ | Database (Firefox profiles, etc.) | Small (amalgamation build) |
| **libevent** | 2.1+ | Event loop | Small (needs poll) |
| **NSPR** | 4.35+ | Mozilla platform runtime | Medium |
| **NSS** | 3.90+ | Crypto/TLS | Large (needs NSPR) |
| **libpng** | 1.6+ | PNG decoding | Small (needs zlib) |
| **libjpeg-turbo** | 3.0+ | JPEG decoding | Medium |
| **libwebp** | 1.3+ | WebP decoding | Small |
| **freetype** | 2.13+ | Font rendering | Medium |
| **harfbuzz** | 8.0+ | Text shaping | Medium (needs freetype) |
| **fontconfig** | 2.14+ | Font discovery | Medium (needs freetype, expat) |
| **pixman** | 0.42+ | Pixel manipulation | Small |
| **cairo** | 1.18+ | 2D graphics | Medium (needs pixman, freetype, fontconfig) |
| **libvpx** | 1.13+ | VP8/VP9 video codec | Medium |
| **dav1d** | 1.2+ | AV1 video codec | Medium (needs meson) |
| **opus** | 1.4+ | Audio codec | Small |

### Phase 7 Deliverables
- [ ] Sysroot with musl + all dependency headers/libs
- [ ] Build scripts for each library (reproducible)
- [ ] All libraries compile and pass basic sanity checks
- [ ] pkg-config .pc files for all libraries

---

## Phase 8: Firefox Build & Integration

**Goal:** Build Firefox (Gecko) targeting AstryxOS.

### 8.1 AstryxOS widget backend

Firefox's widget layer (`widget/`) abstracts the platform. Create `widget/astryx/`:

- `nsWindow` — wraps `libastryxgfx` window
- `nsAppShell` — event loop using `poll()` + ALPC events
- `nsScreenManager` — reports display resolution
- `nsClipboard` — clipboard via ALPC (can be stubbed initially)
- `nsLookAndFeel` — UI theme constants

### 8.2 GFX backend

- `gfx/thebes/gfxAstryxPlatform.cpp` — platform font discovery
- WebRender software backend → `memcpy` to window framebuffer
- No GPU acceleration initially

### 8.3 mozconfig

```bash
ac_add_options --target=x86_64-linux-musl
ac_add_options --disable-jemalloc     # use musl malloc
ac_add_options --disable-crashreporter
ac_add_options --disable-updater
ac_add_options --disable-tests
ac_add_options --disable-debug
ac_add_options --enable-optimize
ac_add_options --disable-pulseaudio
ac_add_options --disable-alsa
ac_add_options --disable-dbus
ac_add_options --disable-gconf
ac_add_options --disable-necko-wifi
ac_add_options --without-wasm-sandboxed-libraries
ac_add_options --enable-application=browser
```

### 8.4 Static vs dynamic build

- **Static first**: Build Firefox as a single monolithic static binary.
  (--enable-linker=bfd, -static). Will be ~150-200 MB but avoids needing
  the dynamic linker to work perfectly.
- **Dynamic later**: Switch to shared libs once Phase 5 is solid.

### Phase 8 Deliverables
- [ ] widget/astryx/ backend compiles
- [ ] mozconfig for AstryxOS cross-compile
- [ ] Firefox links successfully
- [ ] Firefox binary loads on AstryxOS
- [ ] Firefox displays its first window (even if broken)
- [ ] Basic web page rendering works

---

## Phase 9: Polish & Optimization

Ongoing work after Firefox renders its first page:

- **GPU acceleration**: VMware SVGA II 3D support for WebRender
- **Audio**: AC97 driver → Firefox audio output
- **Clipboard**: Full copy/paste between windows
- **Drag and drop**: Window-level DnD protocol
- **Font rendering**: System font directory, fontconfig integration
- **Printing**: PDF generation (print to file)
- **Multi-process**: Firefox Fission (separate content processes)
  requires `fork`+`exec`, AF_UNIX fd passing, shared memory
- **Sandboxing**: seccomp-like syscall filtering
- **Performance**: Huge pages, io_uring-style async I/O

---

## Dependency Graph

```
Phase 1 (musl hello)
    │
    ├── Phase 2 (threads + mprotect + poll)
    │       │
    │       ├── Phase 3 (filesystem maturity)
    │       │       │
    │       │       └── Phase 7 (Firefox deps) ──┐
    │       │                                     │
    │       ├── Phase 4 (socket unification)      │
    │       │       │                             │
    │       │       └── Phase 7 (Firefox deps) ──┤
    │       │                                     │
    │       └── Phase 5 (dynamic linker)          │
    │               │                             │
    │               └── Phase 7 (Firefox deps) ──┤
    │                                             │
    └── Phase 6 (graphics protocol)               │
            │                                     │
            └─────────────────────────────────────┤
                                                  │
                                            Phase 8 (Firefox build)
                                                  │
                                            Phase 9 (polish)
```

Phases 2–6 can be worked on in parallel after Phase 1.
Phase 7 depends on 2, 3, 4, 5 being mostly complete.
Phase 8 depends on all of 1–7.

---

## Quick Start: Phase 1 Implementation Checklist

1. `sudo apt install musl-tools`
2. Write `hello.c`:
   ```c
   #include <stdio.h>
   int main(void) {
       printf("Hello from AstryxOS userspace!\n");
       return 0;
   }
   ```
3. Compile: `musl-gcc -static -no-pie -O2 -o hello hello.c`
4. Modify `kernel/src/proc/elf.rs`:
   - Add `setup_user_stack(stack_pages, argv, envp) -> adjusted_rsp`
   - Write argc/argv/envp/auxvec layout
5. Modify `kernel/src/syscall/mod.rs`:
   - Set `linux_abi = true` for ELFs loaded via exec
6. Copy `hello` binary into FAT32 data disk image
7. Boot AstryxOS, run `exec /bin/hello`
8. Verify: `Hello from AstryxOS userspace!` on serial console
