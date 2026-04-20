# Security Subsystem Gaps

> Reference: Windows XP `base/ntos/se/` (50 C files), Linux `security/` (SELinux, AppArmor, capabilities)
>             ReactOS `ntoskrnl/se/`
> AstryxOS: `security/mod.rs`, `security/token.rs`, `security/sid.rs`, `security/privilege.rs`

---

## What We Have

- Security IDs (SIDs): simplified u32 (0=root, 65534=nobody)
- Access mask with generic/standard/object-specific bits
- ACE (Access Control Entry) and ACL structs — defined but not enforced
- Security descriptor struct: owner, group, DACL presence flag
- Token struct: primary/impersonation type, SID list, privilege bitmask
- `check_access()` function — **stub returning true unconditionally**
- FILE_READ/WRITE/EXECUTE mapped to access bits in VFS ops

---

## Missing (Critical)

### ACL Enforcement in VFS
**What**: `check_access(token, security_descriptor, access_mask)` currently returns `true` always.
Every file open, directory create, and socket bind should pass the requesting token + file SD
through this check. Without it, every process has full access to every file.

**Why critical**: Any multi-user or sandboxed scenario requires this. Firefox plugin sandbox,
setuid helpers (sudo, passwd), and anything running as non-root depends on ACL checks.

**Implementation**:
1. In `vfs/mod.rs` `open()` → call `se::check_access(current_token(), file_sd, GENERIC_READ)`
2. In `vfs/mod.rs` `write()` → check GENERIC_WRITE
3. Build actual ACL comparison loop in `se::check_dacl()`

**Reference**: `reactos/ntoskrnl/se/access.c` (`SeAccessCheck`);
`linux/security/commoncap.c`

---

### setuid / setgid Execution (Privilege Escalation)
**What**: When an executable file has the setuid bit set (mode bit 04000), executing it should set
the process's EUID to the file owner's UID. This is how `sudo`, `passwd`, `ping`, `su` work.

**Current state**: `exec()` in `proc/mod.rs` loads the ELF but ignores the setuid/setgid bits
on the file.

**Reference**: `linux/fs/exec.c` (`apply_creds_binprm`); `linux/kernel/cred.c`

---

### Privilege Checks for Privileged Operations
**What**: Operations like raw socket creation (`SOCK_RAW`), `chroot()`, changing UID, loading
kernel modules, and setting system time should require `CAP_NET_RAW`, `CAP_SYS_CHROOT`,
`CAP_SETUID`, `CAP_SYS_MODULE`, `CAP_SYS_TIME` respectively.

**Current state**: All privileged operations succeed for any process.

**Reference**: `linux/security/commoncap.c` (`cap_capable`); `capabilities(7)` man page

---

## Missing (High)

### POSIX Capabilities
**What**: Linux capability model divides root privileges into 38 distinct capabilities
(CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_NET_ADMIN, CAP_SYS_PTRACE, etc.). A process can have
a subset of capabilities. `capget()/capset()` (syscalls 125/126) manipulate the per-thread
capability sets: effective, permitted, inheritable, ambient.

**Why high**: Chrome/Firefox sandbox drops all capabilities to run content processes with minimal
privilege. Without this, sandboxing is impossible.

**Reference**: `linux/security/commoncap.c`; `linux/include/uapi/linux/capability.h`

---

### Token Propagation on `fork()` / `exec()`
**What**: Child process inherits parent's token on fork. On exec, if setuid: create new token
with file owner's UID. On exec, if not setuid: inherit parent token. On `setuid()` syscall:
modify effective UID in token.

**Reference**: `reactos/ntoskrnl/ps/security.c` (`PspInitializeProcessSecurity`);
`linux/kernel/cred.c` (`copy_creds`)

---

### `seccomp` Filter (BPF-based Syscall Filtering)
**What**: `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)` installs a BPF program that runs
before every syscall. Chrome/Firefox use this to sandbox renderer processes to a whitelist of
~50 syscalls. Any syscall not in the whitelist is killed.

**Why high**: Browser sandboxing fundamentally requires seccomp. Without it, a compromised
renderer can call any syscall.

**Reference**: `linux/kernel/seccomp.c`; `linux/arch/x86/kernel/syscall.c` (seccomp hook)

---

### `prctl(PR_SET_NO_NEW_PRIVS)`
**What**: Irreversible flag that prevents the process from gaining new privileges via setuid exec
or capabilities. Enables sandboxing without requiring a full seccomp filter. Chrome sets this before
the renderer process reduces privileges.

**Reference**: `linux/kernel/sys.c` (`prctl_set_no_new_privs`); `prctl(2)` PR_SET_NO_NEW_PRIVS

---

## Missing (Medium)

| Feature | Description | Reference |
|---------|-------------|-----------|
| SELinux labels | Mandatory access control via labels on objects | `linux/security/selinux/` |
| AppArmor profiles | Path-based MAC confinement | `linux/security/apparmor/` |
| User namespaces | Isolated UID/GID maps for containers | `linux/kernel/user_namespace.c` |
| Mount namespace | Separate mount table per container | `linux/fs/namespace.c` |
| PID namespace | Isolated PID numbering | `linux/kernel/pid_namespace.c` |
| IPC namespace | Separate SysV/POSIX IPC per container | `linux/ipc/namespace.c` |
| File ACL (POSIX) | Per-file ACL beyond mode bits | `linux/fs/posix_acl.c` |
| Audit log | Record privileged operations | `linux/kernel/audit.c` |

---

## Missing (Low)

| Feature | Description |
|---------|-------------|
| Mandatory Access Control (MAC) | Rules-based enforcement beyond DAC |
| Role-based access control (RBAC) | Role-to-permission mapping |
| TPM integration | Hardware key storage |
| Encrypted swap | Swap pages encrypted with per-boot key |
| Kernel address space isolation (KASLR) | Randomize kernel text base |
| Stack canaries | Stack smashing detection in kernel |

---

## Implementation Order

1. **Real rlimit check** — already partially wired; enforce RLIMIT_NOFILE in fd alloc
2. **Capability bitmask in Token** — add `cap_effective: u64`, `cap_permitted: u64` (64 caps)
3. **`capget`/`capset` syscalls** — read/write capability sets from current_token()
4. **`prctl(PR_SET_NO_NEW_PRIVS)`** — set no_new_privs bit in PCB; checked in exec
5. **ACL enforcement skeleton** — change `check_access()` to compare SID against DACL ACEs
6. **Token on fork/exec** — clone token on fork; modify on exec for setuid
7. **seccomp** — add seccomp_filter field to PCB; check in syscall dispatch prologue
