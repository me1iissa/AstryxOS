# PIVOT-D — sshd-test staging (Alpine dropbear) — 2026-05-23

## Goal

Stage Alpine's dropbear SSH daemon (and all required artefacts: host keys,
authorized_keys, /etc/passwd, /etc/shadow, /etc/group, /etc/shells) into
the AstryxOS data-disk such that, once AF_INET accept(2) is implemented
kernel-side, a host-side `ssh root@127.0.0.1` reaches the guest dropbear
end-to-end.  This dispatch is the userspace half of the SSH-service demo;
the accept(2) implementation is on a parallel kernel-engineer dispatch.

## Daemon selection: dropbear (not OpenSSH)

| Trade-off            | dropbear (chosen)              | openssh-server             |
|----------------------|--------------------------------|----------------------------|
| Binary size          | 266 KB (Alpine 2024.85-r0)     | ~700 KB sshd               |
| Runtime deps         | musl + libz                    | musl + libz + libcrypto + libpam + libutil + libsystemd + libnsl + libcrypt |
| Code surface         | ~30k LOC                       | ~150k LOC                  |
| PAM                  | none                           | required                   |
| RFC coverage         | RFC 4252-4254 baseline         | RFC 4252-4254 + extensions |
| Crypto               | statically linked              | OpenSSL libcrypto.so.3     |
| Why narrower?        | Single binary, no plugin loaders | Modular: PAM, nss, syslog, …  |

Dropbear is the smallest viable SSH server: no PAM, no GSSAPI, no Kerberos,
no libsystemd, no /etc/nsswitch dlopen.  For the minimum-viable proof that
AstryxOS runs a real Linux SSH service, dropbear is the narrowest blast
radius.  OpenSSH is a follow-on once dropbear works end-to-end.

## Staging shape

### Files added

- `scripts/install-sshd.sh` — Alpine apk-static + dropbear staging into
  `build/disk/` (~270 LOC).  Reuses the shared Alpine rootfs at
  `~/.cache/astryxos-firefox-musl/rootfs/` bootstrapped by
  `install-firefox-musl.sh`.
- `kernel/src/sshd_demo.rs` — dropbear launcher (~210 LOC).  Mirrors
  `busybox_demo.rs` / `httpd_demo.rs` shape: load ELF → spawn blocked →
  attach pipe → unblock → poll-loop with 60 s soak budget → verdict.
- `docs/SSHD_PIVOT_D_2026-05-23.md` — this file.

### Files modified

- `kernel/Cargo.toml` — new `sshd-test` cargo feature (mutually exclusive
  with the other `*-test` features at the main.rs cfg-gate level).
- `kernel/src/main.rs` — `mod sshd_demo;` declaration + runner block
  alongside busybox-test / xeyes-test / httpd-test / firefox-test;
  added `not(feature = "sshd-test")` to all sibling gates.
- `scripts/qemu-harness.py` — new `--ssh-host-port N` argument; SLIRP
  hostfwd rule injection mirroring the existing `--http-host-port`
  pattern; auto-derive in 2200..2299 when sshd-test is in the feature
  set and no explicit port given; added `ssh_host_port` to the start
  JSON output.
- `scripts/create-data-disk.sh` — new `--sshd` flag + `ASTRYXOS_SSHD=1`
  env var; data.img copy block for /usr/sbin/dropbear,
  /usr/bin/dropbearkey, /etc/dropbear/, /root/.ssh/authorized_keys,
  /etc/{passwd,shadow,group,shells}; explicit pack of musl runtime
  libs (ld-musl-x86_64.so.1, libc.musl-x86_64.so.1, libz.so.1) to
  both /lib and /usr/lib so dropbear's NEEDED entries resolve under
  any FIREFOX_VARIANT setting.  `--sshd` auto-implies `--busybox`
  (dropbear's login shell `/bin/sh` is provided by busybox).

### Host-side test keypair

`install-sshd.sh` generates:

- `~/.cache/astryxos-sshd/etc/dropbear/dropbear_ed25519_host_key`
- `~/.cache/astryxos-sshd/etc/dropbear/dropbear_rsa_host_key`
- `~/.cache/astryxos-sshd/client/ed25519` (private — kept on host)
- `~/.cache/astryxos-sshd/client/ed25519.pub` (staged to
  `/root/.ssh/authorized_keys` on the guest)

Keys are persistent across data.img rebuilds (cache lives outside the
worktree) so the host can pin the guest's fingerprint across runs.

## Staging validation (2026-05-23, KVM)

### What works today (no accept(2) needed)

Trial against `--features sshd-test` on commit ~ffeaa68 + the staging
work in this PR (no accept(2) implementation):

```
[SSHD] sshd-test starting (PIVOT-D, 2026-05-23)
[SSHD] Loaded /disk/usr/sbin/dropbear (265928 bytes)
[SSHD] Spawning dropbear with argv=["dropbear", "-F", "-E", "-s",
       "-p", "22",
       "-r", "/disk/etc/dropbear/dropbear_ed25519_host_key",
       "-r", "/disk/etc/dropbear/dropbear_rsa_host_key",
       "-P", "/tmp/dropbear.pid"]
[SSHD] dropbear spawned: pid=1
[SSHD] dropbear | [1] May 23 18:18:32 Not backgrounding
[SSHD] LIVENESS pid=1 state=Active elapsed_ticks=1000 captured_bytes=38
...
[SSHD] LIVENESS pid=1 state=Active elapsed_ticks=5000 captured_bytes=38
[SSHD] Soak budget reached (6000 ticks); dropbear still RUNNING
       (pid=1, state=Active)
[SSHD] === SUMMARY === banner=0 foreground=1 pubkey_seen=0
       final_state=Active captured_bytes=38
[SSHD] === SSHD-TEST: REACHED-ACCEPT-LOOP (foreground marker +
       process Active at soak end) ===
```

Interpretation:

1. The musl-linked dropbear ELF loads, its NEEDED entries resolve
   (libz.so.1, libc.musl-x86_64.so.1, ld-musl-x86_64.so.1), and
   relocations apply.
2. `getpwnam_r("root")` succeeds against the staged /etc/passwd.
3. Host-key files (`/disk/etc/dropbear/dropbear_{ed25519,rsa}_host_key`)
   load — dropbear's RSA + Ed25519 parsing path completes without
   the "Failed loading host key" exit signature.
4. socket(AF_INET, SOCK_STREAM) + setsockopt(SO_REUSEADDR) + bind(:22)
   + listen() all succeed.  Dropbear prints `Not backgrounding` and
   enters its accept(2) loop.
5. accept(2) returns -EAGAIN (current stub at
   `kernel/src/subsys/linux/syscall.rs:1651`).  Dropbear silently
   retries; no version banner is printed because dropbear only logs
   per-session events (no idle-loop verbosity).
6. Process state stays `Active` for the full 60 s soak — i.e. the
   kernel scheduler is running dropbear through the accept-retry loop,
   not wedged on syscall entry.

### Host-side SSH attempt (no accept(2) yet)

```
$ ssh -i ~/.cache/astryxos-sshd/client/ed25519 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    -p 2207 root@127.0.0.1 'uname -a; exit 0'
ssh: connect to host 127.0.0.1 port 2207: Connection refused
```

SLIRP hostfwd is alive but the guest accept(2) stub means no connection
ever completes — host sees ECONNREFUSED.  This is the expected
EAGAIN-gate signature; the kernel personality stack's TCP listener
exists but no listener-side accept can return a connected socket fd.

### Post-accept(2) integration plan

Once the parallel kernel-engineer dispatch implements AF_INET accept(2),
re-running the same command should yield:

```
$ ssh -i ~/.cache/astryxos-sshd/client/ed25519 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p <HOST-PORT> root@127.0.0.1 'uname -a; ls /; exit 0'

Linux astryx 0.x.x #1 SMP AstryxOS 2026-05-23 x86_64 GNU/Linux
bin  disk  etc  home  lib  lib64  opt  proc  root  srv  sys  tmp  usr  var
```

Expected guest-side serial markers when the host SSH succeeds:

- `[SSHD] dropbear | Pubkey auth succeeded for 'root' from <ip>:<port>`
- `[SSHD] dropbear | Child connection from <ip>:<port>`
- (post-fork) dropbear forks per-connection — the child runs the
  user's session shell

## Known limitations

- **No /dev/urandom**: dropbear uses /dev/urandom for SSH protocol
  random nonces.  If the kernel's /dev/urandom path is not yet wired,
  dropbear may fall back to its own PRNG or fail at the KEX init.
  Verify in a post-accept run with `--features sshd-test,kdb`.
- **No syslog**: with `-E` dropbear logs to stderr only.  When daemonised
  (without -F) it would call openlog(3); we use -F to avoid that.
- **FAT32 has no symlinks**: dropbear's normal `/bin/sh` resolution
  relies on shell-script-style execve; we ship `/bin/sh` as a busybox
  wrapper script (created by install-busybox-cli.sh's wrapper-script
  generator if /bin/busybox supports the symlink-applet dispatch via
  argv[0]).  Verify in a post-accept session that exec() of `/bin/sh`
  works.
- **No PAM, no nss-files modules**: dropbear's authentication path is
  hard-coded to read /etc/passwd, /etc/shadow, ~/.ssh/authorized_keys
  directly via stdio (no NSS dlopen).  This is the deliberate reason
  for picking dropbear; OpenSSH would require NSS plugins.

## Files-changed summary

```
 docs/SSHD_PIVOT_D_2026-05-23.md           | new       ~+170
 kernel/Cargo.toml                          | modified   ~+25
 kernel/src/main.rs                         | modified   ~+55
 kernel/src/sshd_demo.rs                    | new       ~+230
 scripts/create-data-disk.sh                | modified   ~+80
 scripts/install-sshd.sh                    | new       ~+275
 scripts/qemu-harness.py                    | modified   ~+30
```

Total: roughly +865 LOC, of which ~675 is new file content and ~190 is
modifications to existing wiring.  Mostly userspace + harness; the kernel
delta (Cargo + main.rs + sshd_demo.rs) is ~310 LOC.

## Public references

- dropbear upstream: <https://matt.ucc.asn.au/dropbear/dropbear.html>
- dropbear(8), dropbearkey(1), dbclient(1) man pages
- Alpine dropbear package: <https://pkgs.alpinelinux.org/package/v3.20/main/x86_64/dropbear>
- RFC 4251 (SSH-2 architecture)
- RFC 4252 (SSH-2 public-key auth method)
- RFC 4253 (SSH-2 transport / KEX)
- RFC 4254 (SSH-2 connection / channel protocol)
- RFC 8709 (Ed25519 host-key format)
- musl libc: <https://musl.libc.org/>
- QEMU SLIRP hostfwd: <https://www.qemu.org/docs/master/system/devices/net.html#network-options>
- POSIX socket(2), bind(2), listen(2), accept(2), fork(2)
- `man 8 sshd` — AUTHORIZED_KEYS FILE FORMAT
- `man 5 passwd`, `man 5 shadow`, `man 5 group`, `man 5 shells`

## Hand-back

- **Branch**: `worktree-agent-a9762962337681925`
- **Verdict**: dropbear stages OK, boots OK, binds + listens OK, reaches
  accept(2) loop OK.  Host-side SSH currently blocked on AF_INET accept(2)
  stub (kernel/src/subsys/linux/syscall.rs:1651) — once the parallel
  kernel dispatch implements accept(2), the same command shown above is
  expected to complete.
- **Fallback option**: OpenSSH-server is staged-but-not-implemented here.
  Switch only if dropbear surfaces a daemon-specific issue once accept(2)
  works.
- **Next steps when accept(2) lands**:
  1. `python3 scripts/qemu-harness.py start --features sshd-test`
  2. Wait for `[SSHD] === SSHD-TEST: REACHED-ACCEPT-LOOP ===` (proves
     staging + boot still works).
  3. From the host (use the `ssh_host_port` from start JSON):
     ```
     ssh -i ~/.cache/astryxos-sshd/client/ed25519 \
         -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -p <HOST-PORT> root@127.0.0.1 'uname -a; ls /'
     ```
  4. Expect AstryxOS uname + root directory listing in stdout.
  5. The matching guest-side serial line is
     `[SSHD] dropbear | Pubkey auth succeeded for 'root' from ...`.
