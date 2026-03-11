# Aether Subsystem — Design Document

> Last updated: 2026-03-05

## 1. Purpose

Aether is the **native** environment subsystem of AstryxOS. It defines the canonical
kernel API surface. All other subsystems (Linux, Win32) are translation layers that
ultimately call Aether primitives.

## 2. Syscall ABI

| Register | Purpose |
|----------|---------|
| RAX | Syscall number (Aether numbering; `shared/src/lib.rs::syscall`) |
| RDI | arg1 |
| RSI | arg2 |
| RDX | arg3 |
| R10 | arg4 |
| R8  | arg5 |
| R9  | arg6 |
| RAX (return) | Result (≥0 success, <0 negated NtStatus error) |

Entry: `SYSCALL` instruction → `syscall_entry` stub.

## 3. Current Syscall Table (50 calls)

```
 0  exit         1  write        2  read         3  open
 4  close        5  fork         6  exec         7  waitpid
 8  getpid       9  mmap        10  munmap       11  brk
12  ioctl       13  yield       14  getppid      15  getcwd
16  chdir       17  mkdir       18  rmdir        19  stat
20  fstat       21  lseek       22  dup          23  dup2
24  pipe        25  uname       26  nanosleep    27  getuid
28  getgid      29  geteuid     30  getegid      31  umask
32  chmod       33  chown       34  unlink       35  getrandom
36  kill        37  sigaction   38  sigprocmask  39  sigreturn
40  socket      41  bind        42  connect      43  sendto
44  recvfrom    45  listen      46  accept       47  clone
48  futex       49  sync
```

## 4. Path Convention

Aether syscalls use **pointer + length** pairs for strings (Rust-native), not
null-terminated C strings:
- `SYS_OPEN(path_ptr, path_len, flags)` — `arg1` = ptr, `arg2` = len
- This differs from Linux which uses null-terminated `const char*` paths.

## 5. Error Model

Returns negated `NtStatus` codes (from `shared/src/ntstatus.rs`). Common values:
- `0` = success
- `-14` = EFAULT (bad user pointer)
- `-9` = EBADF (bad file descriptor)

## 6. Process Model

- Aether processes are created by `fork()` + `exec()` or `clone()`.
- Default `SubsystemType::Aether`.
- Use the Aether syscall number table.
- Link against `libsys` (Rust userspace syscall wrapper crate).

## 7. Userspace Libraries

| Library | Purpose | Location |
|---------|---------|----------|
| `libsys` | Raw syscall wrappers | `userspace/libsys/` |
| (future) `libstd` | Aether standard library | `userspace/libstd/` |

## 8. Key Differences from Linux

| Aspect | Aether | Linux |
|--------|--------|-------|
| String passing | ptr + len | null-terminated |
| Syscall numbers | 0–49 (compact) | 0–547 (sparse, 385 defined) |
| Error codes | NtStatus (negative) | -errno (negative) |
| Object model | NT-style handles + OB namespace | fd-only |
| IPC | ALPC (message-passing) | pipes, Unix sockets, shmem |
| Security | Tokens + ACLs + SIDs | uid/gid/capabilities |

## 9. Future Extensions

- `SYS_NT_CREATE_FILE` — NT-style file open with full access mask + share mode
- `SYS_NT_QUERY_OBJECT` — Query object attributes via handle
- `SYS_ALPC_SEND` / `SYS_ALPC_RECEIVE` — ALPC messaging from userspace
- `SYS_CREATE_SECTION` — Memory-mapped file sections (NT-style)
- Window manager syscalls for native GUI apps
