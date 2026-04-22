# Aether Native C Runtime (libaether)

> The AstryxOS-native C runtime for programs targeting the Aether ABI directly.
> This is analogous to libc on Linux or ntdll on NT, but purpose-built for AstryxOS.

---

## Why a Native Runtime?

AstryxOS tools — the Orbit shell, OS utilities, GUI apps, kernel loader helpers — should
not need to choose between Win32 compatibility and Linux compatibility. They should target
a clean, first-class Aether ABI that:

1. Uses POSIX-compatible calling conventions (same as musl — zero learning curve)
2. Wraps Aether-native syscalls (the `SYS_*` constants in `syscall/mod.rs`)
3. Can be statically linked into any Aether ELF
4. Exposes AstryxOS-specific APIs: window creation, IPC, compositor

The Aether native runtime is `libaether` — a small Rust crate that can also expose a
C-compatible API via `#[no_mangle]` and `extern "C"`.

---

## What libaether Provides

```
Layer 1: Syscall wrappers (thin, zero-overhead)
  aether_read(fd, buf, len) → sys_read(fd, buf, len)
  aether_write(fd, buf, len) → sys_write(fd, buf, len)
  aether_open(path, flags, mode) → sys_open(path, flags, mode)
  aether_close(fd) → sys_close(fd)
  aether_fork() → sys_fork()
  aether_exec(path, argv, envp) → sys_exec(path, argv, envp)
  aether_exit(code) → sys_exit(code)
  aether_mmap(addr, len, prot, flags, fd, offset) → sys_mmap(...)
  aether_kill(pid, sig) → sys_kill(pid, sig)
  aether_getpid() → sys_getpid()
  ... one per Aether syscall

Layer 2: Standard C library (POSIX-compatible subset)
  malloc() / free() / realloc() / calloc()
    → sys_mmap(MAP_ANONYMOUS) for large, slab for small
  printf() / sprintf() / snprintf() / fprintf()
  memcpy() / memset() / memmove() / memcmp()
  strlen() / strcpy() / strcat() / strcmp() / strncmp()
  strchr() / strstr() / strtol() / strtod() / atoi() / atof()
  fopen() / fread() / fwrite() / fclose() / fseek() / ftell()
  read() / write() / open() / close() / lseek()
  signal() / sigaction() / kill()
  getpid() / getppid() / fork() / exec() / waitpid()
  time() / clock() / gettimeofday()
  exit() / abort() / atexit()
  getenv() / putenv() / setenv()
  errno (thread-local, set by syscall wrappers)

Layer 3: AstryxOS extensions (Aether-specific)
  aether_create_window(title, w, h) → x11_socket + CreateWindow
  aether_draw_rect(win, x, y, w, h, color)
  aether_draw_text(win, x, y, text, color)
  aether_poll_events(win, events, max) → X11 event loop
  aether_ipc_connect(port_name) → LPC/ALPC connect
  aether_ipc_send(port, msg, len) → ALPC send
  aether_ipc_recv(port, buf, max_len) → ALPC receive
```

---

## Architecture: Rust crate with C ABI

```
libaether/
  Cargo.toml        (no_std, crate-type = ["staticlib", "cdylib"])
  src/
    lib.rs           re-exports all modules
    syscall.rs       raw syscall(n, a,b,c,d,e,f) → asm!("syscall")
    io.rs            read/write/open/close wrappers
    mem.rs           malloc/free using mmap + buddy allocator
    string.rs        memcpy/strlen/strcmp/etc.
    stdio.rs         printf/fwrite/fread/FILE struct
    process.rs       fork/exec/waitpid/exit/signal
    time.rs          clock_gettime/gettimeofday
    math.rs          sin/cos/sqrt/etc. (may delegate to FPU intrinsics)
    thread.rs        pthread_create (clone syscall) / pthread_mutex (futex)
    aether/
      window.rs      window creation via X11 socket
      ipc.rs         ALPC port connect/send/recv
      events.rs      input event polling
```

---

## Startup Sequence for Aether Native ELF

```
Kernel:
  Load ELF sections, set up user stack
  Push argc/argv/envp/auxv per ELF ABI
  Jump to _start (from ELF e_entry)

_start (in libaether/src/start.s or start.rs):
  ; Clear frame pointer (ABI requirement)
  xor   rbp, rbp
  ; Extract argc, argv, envp from stack
  mov   rdi, [rsp]           ; argc
  lea   rsi, [rsp+8]         ; argv
  lea   rdx, [rsi+rdi*8+8]   ; envp = argv+argc+1
  ; Initialize TLS if needed
  call  __aether_init_tls
  ; Run constructors (.init_array)
  call  __aether_run_ctors
  ; Call main
  call  main
  ; Call destructors (.fini_array)
  call  __aether_run_dtors
  ; Exit with main's return value
  mov   rdi, rax
  call  aether_exit
```

This is essentially identical to musl's `crt1.c` — same ELF ABI.

---

## Memory Allocator Design

The libaether allocator should be two-tier:

```
Small objects (< 2 KiB):  slab allocator
  Backing: mmap(MAP_ANONYMOUS, 512 KiB) → carve into fixed-size slots
  Sizes: 8, 16, 32, 64, 128, 256, 512, 1024, 2048 bytes
  Free list per size class (intrusive linked list in the freed block)
  Thread safety: per-thread slab or spinlock-protected global

Large objects (≥ 2 KiB): mmap directly
  mmap(MAP_ANONYMOUS, round_up_page(size + header))
  Header stores size for free()
  munmap on free

Realloc:
  Small→Small: allocate new slot, copy, free old
  Small→Large: mmap new, copy, free slot
  Large→Large: try mremap first; else mmap+copy+munmap
```

This is the same design as musl's allocator (`src/malloc/mallocng/`). Reference:
`linux/lib/` (memory allocator patterns) and musl source.

---

## C++ Support for Aether Native

C++ requires on top of libaether:

```
libaetherc++ (or just statically link libc++):
  operator new  → malloc()
  operator delete → free()
  __cxa_atexit  → register destructor
  __cxa_throw   → DWARF2 unwind (or SEH-style for NT compat)
  __cxa_guard_acquire / release → once-initialization (thread-local guard)
  typeid / dynamic_cast → RTTI table walks
  std::terminate → abort()

RTTI:
  __type_info structs in .rodata
  dynamic_cast via RTTI tree walk
  typeid(x).name() → demangled type name

Stack unwinding:
  .eh_frame section in ELF (DWARF2 unwind tables)
  __cxa_throw → calls _Unwind_RaiseException → walks .eh_frame
  Each catch block is a "landing pad" in .eh_frame
```

For Aether native, **statically linking LLVM libc++** is the simplest path. libc++ is clean,
header-only for most of STL, and needs only the ABI layer listed above.

---

## Integration with Orbit Shell

The Orbit shell (`kernel/src/shell/mod.rs`) currently runs in kernel mode. The eventual goal:
migrate Orbit to a user-mode ELF binary linked against libaether.

```
/sbin/orbit (ELF, linked with libaether.a)
  Uses: printf, malloc, fork/exec, waitpid, open/read/write
  Accesses: /proc/self/status, /dev/tty, /dev/input/event0
  IPC: aether_ipc_connect("/AstryxOS/Desktop") for GUI shell
```

This migration is Phase 13 of ROADMAP.md (Userspace & Toolchain). libaether is the prerequisite.

---

## Comparison: libaether vs musl vs ntdll

| Aspect | libaether | musl | ntdll |
|--------|-----------|------|-------|
| Language | Rust + C ABI | C | C/ASM |
| Syscall ABI | Aether (SYS_* constants) | Linux (int numbers) | NT (INT 2E) |
| Size goal | < 200 KB | ~450 KB | ~1 MB |
| Threading | Rust std::sync or futex | POSIX pthread | Win32 CRITICAL_SECTION |
| Startup | _start → main | crt1.c → __libc_start_main | LdrInitializeThunk → mainCRTStartup |
| Exception model | Rust panic / C++ DWARF | C++ DWARF | SEH |
| Special sauce | AstryxOS window/IPC API | POSIX extensions | Win32 extensions |

---

## Implementation Priority

libaether is **not blocking Firefox or current tests** — those use the musl/Linux path.
It becomes important when:
1. Orbit shell is migrated to user-mode (Phase 13)
2. Native AstryxOS apps are written (text editor, calculator, etc.)
3. The Win32 path requires a low-level Aether CRT to bridge native→Win32

**Suggested implementation order**:
1. `syscall.rs` — raw syscall wrapper (5 min, trivial asm)
2. `io.rs` — read/write/open/close (30 min)
3. `mem.rs` — malloc/free using mmap (2 hours)
4. `string.rs` — memcpy/strlen/strcmp (1 hour)
5. `stdio.rs` — printf/puts (2 hours)
6. `process.rs` — fork/exec/exit (1 hour)
7. `start.s` — _start entry point (30 min)
8. Build a static libaether.a, link against it, test with a "Hello World" ELF
