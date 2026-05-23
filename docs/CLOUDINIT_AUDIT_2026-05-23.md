# CLOUD-INIT — AstryxOS readiness audit + phased roadmap (2026-05-23)

## TL;DR

- **Phase C1 (NoCloud bash-only) is recommended as the first cloud-init
  deliverable.**  It needs roughly **~1.7 kLOC kernel + ~250 LOC scripts**
  (ISO 9660 read-only driver + virtio-blk-pci CD/ISO attach + ascension
  glue + harness `--cidata` knob) and lands a credible "this VM accepts
  cloud-init payloads" demo without any Python on the guest.
- **Phase C2 (cloud-init-rs-shaped subset)** adds the five most-used
  `#cloud-config` directives (`write_files`, `runcmd`, `users`,
  `ssh_authorized_keys`, `hostname`) in native Rust running under the
  Aether kernel.  Estimated ~3-5 kLOC across one new userspace binary +
  one tiny YAML reader.  No Python on the guest.
- **Phase C3 (real cloud-init under upstream Python)** is multi-week.
  Cloud-init upstream pins Python ≥ 3.8 and pulls in `jinja2`, `pyyaml`,
  `requests`, `jsonschema`, `jsonpatch`, `configobj`, `oauthlib` — i.e.
  CPython + ssl + sqlite3 + thread + asyncio + setuptools.  Staging
  CPython 3.x on the data disk is itself a ~30-60 MiB rootfs delta and
  exercises a wide envelope of the Linux subsystem (epoll, eventfd,
  signalfd, pselect6, prlimit, getrandom flags, /proc/self/* file
  shape).  Not recommended as a near-term gate.

The rest of the doc walks the runtime requirements, the AstryxOS state
today, the phased roadmap, and the per-phase subsystem deltas.

References (public specs cited inline):
[cloud-init NoCloud datasource][nocloud-spec],
[cloud-init runtime requirements][cloud-init-reqs],
[ECMA-119 / ISO 9660][iso9660-wiki],
[NoCloud second source][nocloud-spec-2],
[tinycloudinit (shell-only alternative)][tinycloudinit],
[freedesktop os-release(5)][osrelease-spec],
[busybox sh(1)][busybox-sh],
[POSIX execve(2)][posix-execve].

---

## 1. Cloud-init runtime requirements

### 1.1 Language + interpreter

Cloud-init upstream is Python.  Current supported floor is **Python 3.8**;
the project moves the floor forward by deprecating older Python releases
roughly every 6 years.  PyPI dependencies declared in
`requirements.txt`:

| Package      | Purpose (per upstream comment)                                  |
|--------------|------------------------------------------------------------------|
| `jinja2`     | Templating user-data / cloud-config fragments                   |
| `pyyaml`     | New-style YAML parsing for `#cloud-config` documents            |
| `requests`   | HTTP for metadata-service datasources (EC2/GCP/Azure/OpenStack) |
| `oauthlib`   | MAAS + webhook auth                                              |
| `jsonpatch`  | Stitching multipart cloud-config                                |
| `jsonschema` | Validating cloud-config sections                                |
| `configobj`  | Legacy config sections                                          |

In addition cloud-init exercises CPython stdlib `subprocess`, `os`,
`logging`, `socket`, `ssl`, `json`, `re`, `email` (MIME), `urllib`,
`hashlib`, `contextlib`, `tempfile`, `signal`, `argparse`, `gzip`,
`base64`, `binascii`.  CPython itself further pulls in `sqlite3`,
`_ssl`, `_socket`, `select` (epoll), `posix`, `pwd`, `grp`, `termios`,
`fcntl`, `_thread`, `_asyncio`, `mmap`, and the dynamic-loader glue.

### 1.2 Boot sequence (when Python cloud-init is in charge)

Cloud-init runs in **four stages**, traditionally driven by systemd
unit dependencies but equally serviceable under a sysvinit-style
sequencer:

1. **local** (datasource without network) — finds the datasource
   (NoCloud / ConfigDrive on a local disk or virtual CD; EC2/Azure
   metadata-service if a network is already up; SMBIOS hints).
2. **network** — brings up the network, refreshes datasource if the
   metadata service is HTTP.
3. **config** — applies most `#cloud-config` modules (users, ssh,
   write_files, hostname, locale, timezone, packages).
4. **final** — `runcmd`, `bootcmd`, freeform user-data shell scripts.

Each stage records state under `/var/lib/cloud/instance/` so the
instance-id is remembered across reboots.  A first-boot run is
triggered iff the recorded instance-id differs from the meta-data
`instance-id` (see [NoCloud spec][nocloud-spec]).

### 1.3 Datasource taxonomy

| Datasource    | Transport                                  | Network needed | Complexity |
|---------------|--------------------------------------------|----------------|------------|
| **NoCloud**   | ISO 9660 / vfat labelled `CIDATA`          | **No**         | Lowest     |
| ConfigDrive   | ISO 9660 / vfat labelled `config-2`        | No             | Low        |
| EC2           | HTTP `http://169.254.169.254/latest/...`   | Yes            | Medium     |
| GCE/Azure     | HTTP magic IP + auth headers               | Yes            | Medium     |
| OpenStack     | HTTP magic IP or ConfigDrive               | Yes            | Medium     |
| MAAS / others | HTTP + OAuth                               | Yes            | High       |

NoCloud is the unanimously-recommended first target — every public
guide on getting cloud-init working under bare QEMU uses it, the spec
is one page, and it requires zero network stack involvement.

### 1.4 NoCloud — the minimum data shape

From the [NoCloud datasource spec][nocloud-spec]:

- **Volume label** must be `CIDATA` (upper-case).  Filesystem must be
  `iso9660` or `vfat`.
- **`meta-data`** (REQUIRED) — YAML.  At minimum:
  ```yaml
  instance-id: iid-local01
  ```
  `local-hostname:` is conventional but optional.
- **`user-data`** (OPTIONAL) — either a `#cloud-config` YAML document,
  a `#!/bin/sh` script, a MIME multipart blob, or one of cloud-init's
  other supported handlers (`#include`, `#part-handler`, etc.).
- **`vendor-data`**, **`network-config`** — optional.

`meta-data` may be a zero-byte file if the kernel command line or
SMBIOS supplies `ds=nocloud;instance-id=…`, but the canonical case is
a populated file.

### 1.5 System mutations cloud-init typically performs

| Operation                              | Syscalls / files needed                              |
|----------------------------------------|------------------------------------------------------|
| Write `/etc/hostname`                  | open(O_CREAT) / write / rename / fsync               |
| Append `/etc/hosts`                    | open(O_RDWR) / read / write                          |
| Drop `~user/.ssh/authorized_keys`      | mkdir / chmod / chown / open / write                 |
| Add user (`useradd` / shadow edit)     | exec of `useradd`, or direct edits of `/etc/passwd`, `/etc/shadow`, `/etc/group` |
| `write_files: ...`                     | open / write / chmod / chown                         |
| `runcmd: [ ... ]`                      | fork + execve + waitpid                              |
| Bring up network (`netplan apply`)     | ioctl(SIOCSIFADDR), rtnetlink, dhclient exec        |
| Install packages (`apt`, `dnf`)        | exec + full package-manager stack                    |
| Output log                             | `/var/log/cloud-init.log` (open/write)               |

Phase C1 (bash-only user-data via NoCloud) needs only the green cells:
**read the cidata ISO, fork+exec busybox-sh on the embedded
`user-data` script**.  Everything else can come later.

---

## 2. AstryxOS current state

### 2.1 Existing storage stack

| Capability                        | Status in tree                                          |
|-----------------------------------|---------------------------------------------------------|
| ATA PIO (IDE HDD)                 | `kernel/src/drivers/ata.rs` (28-bit LBA, PIO only)      |
| virtio-blk-pci                    | `kernel/src/drivers/virtio_blk.rs`; used for data disk  |
| AHCI                              | `kernel/src/drivers/ahci.rs`                            |
| **ATAPI / CD-ROM**                | **None** — only the IDENTIFY-failure comment in `ata.rs:134` mentions ATAPI; no command path. |
| **virtio-scsi**                   | **None.**                                               |
| **ISO 9660 / Joliet / Rock Ridge**| **None.**                                               |
| FAT32 read+write                  | `kernel/src/vfs/fat32.rs` (2510 lines)                  |
| Other filesystems                 | ext2, ntfs, ramfs, tmpfs, procfs, sysfs                 |

Confirmed by:
```
grep -rn 'iso9660\|ISO9660\|cdrom\|CDROM\|atapi\|ATAPI' kernel/src/
# → drivers/ata.rs only (one comment line)
```

The QEMU command line is built by `scripts/astryx_qemu.py`; the data
disk is attached as **virtio-blk-pci** with `format=raw,snapshot=on`.
There is no second drive line or `-cdrom`/`-drive media=cdrom` arg.
**Adding a CIDATA disk is a single argv addition.**

### 2.2 Python on guest

```
ls build/disk/usr/bin/python*   # → no match
ls build/disk/usr/lib/python*   # → no match
```

There is no Python interpreter, no `libpython*.so`, no stdlib `.py` files.
The Linux personality layer runs unmodified Alpine/Debian binaries via
`musl` (PR #298 + descendants); Python could in principle be added via
`apk add python3` into the shared Alpine rootfs (analogous to
`install-busybox-cli.sh`), but the runtime envelope it requires (epoll,
signalfd, prlimit64, getrandom GRND_INSECURE flag handling, /proc/self
introspection) is significantly broader than what we exercise today.

### 2.3 Init + service-runner

`kernel/src/init/mod.rs` (the "Ascension" init) already supports:

- Parsing `/etc/ascension.conf` (`service`, `service-restart`,
  `service-onfail` directives).
- Launching each registered service as a userspace ELF via
  `proc::usermode::create_user_process_with_args`.
- Polling for service exit and restarting per policy.

It is **not** systemd, but for staged ordering and `runcmd`-style
sequential execution it is sufficient: a cloud-init shim can be
registered as a single `service-onfail cloud-init-c1 /bin/cloud-init-c1`
entry that runs once at boot.

PR #430 added the **busybox-static binary** at `/bin/busybox` (Alpine
1.36.1, statically linked, ~400 applets including `sh`, `mount`,
`mkdir`, `chmod`, `chown`, `cat`, `cp`, `mv`, `sed`, `awk`, `wget`,
`base64`).  This is the user-data interpreter for Phase C1 — no
interpreter work needed.

### 2.4 Networking

Required only from Phase C2 onward (and only if HTTP-metadata
datasources are chased).  Current state:

| Capability                      | Status                                          |
|---------------------------------|-------------------------------------------------|
| virtio-net / e1000              | `kernel/src/net/{virtio_net.rs,e1000.rs}`       |
| IPv4 + IPv6 + ICMP              | Present                                         |
| TCP                             | `kernel/src/net/tcp.rs` (1313 lines); listen / accept / send proven by PR #431 httpd demo |
| UDP                             | `kernel/src/net/udp.rs`                         |
| DHCP client                     | `kernel/src/net/dhcp.rs` (DISCOVER/REQUEST/RENEW/RELEASE) |
| DNS resolver                    | `kernel/src/net/dns.rs`                         |
| Socket syscalls 41-50           | `kernel/src/subsys/linux/syscall.rs` lines 1501-2236 (socket / connect / accept / sendto / recvfrom / sendmsg / recvmsg / shutdown / bind / listen) |

The 169.254.169.254 magic-IP metadata path (EC2/GCP/Azure) is purely
HTTP-over-virtio-net; PIVOT-C already proved we can serve HTTP from
inside the kernel, and DHCP-leased addressing means we can route to a
host-side mock metadata service.  This is in scope for C2 if/when we
choose to chase EC2-style datasources.

### 2.5 Process + exec + sysadmin syscalls

The Linux subsystem dispatches ~188 syscall arms.  Cloud-init-relevant
coverage:

| Group                                | Status                                              |
|--------------------------------------|-----------------------------------------------------|
| open/read/write/close/fstat/lseek    | Present (syscall/mod.rs)                            |
| mkdir/rmdir/unlink/rename/symlink    | Present                                             |
| chmod/chown                          | Present (Linux-subsys dispatch + VFS hooks)         |
| fork/vfork/clone/execve/waitpid      | Present (multi-iteration hardened; see W215 saga)   |
| pipe/dup/dup2                        | Present                                             |
| mmap/munmap/brk/mprotect             | Present                                             |
| uname                                | Present                                             |
| **mount(2)**                         | Present for `tmpfs`/`ramfs`/`procfs`; `fat32` is a stub returning `-ENODEV`; `iso9660` would need a new arm |
| chroot                               | Returns `-ENOSYS` (per `syscall.rs:4501`)           |
| setuid/setgid                        | Stub — always root (`syscall.rs:4444-4446`)         |
| reboot                               | Not in dispatch table                               |
| sethostname/gethostname              | Not in dispatch table (uname uses static node name) |

For Phase C1 nothing in the table above is a blocker: cloud-init-c1
runs as the boot service (already root in AstryxOS), reads
`/cidata/user-data`, and exec's busybox sh.

For Phase C2 we additionally want **`sethostname(2)`** to honour
`#cloud-config:hostname:` and **`reboot(2)`** so user-data scripts can
declare a reboot intent.  Both are ~30-LOC additions.

For Phase C3 (real Python cloud-init) the ABI surface widens
substantially — see §6 below.

---

## 3. Phased roadmap

### Phase C1 — NoCloud bash-only datasource

**Goal:** Boot AstryxOS with a QEMU `-cdrom` argument pointing at a
CIDATA ISO containing `user-data` as a `#!/bin/sh` script; the script
runs as root at boot; observable side-effects (files created, lines
appended) appear on the data disk.

**LOC budget** (kernel + scripts + tests, by component):

| Component                                                    | LOC est. | Note |
|--------------------------------------------------------------|---------:|------|
| `kernel/src/drivers/atapi.rs` — ATA PACKET / IDENTIFY PACKET DEVICE / SCSI READ(10) | ~450 | OR use second virtio-blk for ISO and skip ATAPI |
| Alternative: second `-drive ... if=none,id=cidata` + virtio-blk-pci binding | ~100 | preferred — sidesteps ATAPI entirely |
| `kernel/src/vfs/iso9660.rs` — read-only ISO 9660 + Joliet  | ~900 | Rock Ridge optional in C1 |
| VFS registry: `mount(... "iso9660", ...)` arm                | ~50  | `vfs/mod.rs:2454 sys_mount` extension |
| `kernel/src/init/cloud_init_c1.rs` — boot shim that mounts cidata, locates `user-data`, exec's busybox sh | ~200 | |
| `/etc/ascension.conf` seed line                              | ~1   | |
| `scripts/build-cidata-iso.sh` — host-side helper using `mkisofs -V CIDATA` | ~120 | tooling already on host (`/usr/bin/mkisofs`) |
| `scripts/qemu-harness.py` — `--cidata <iso>` flag, threads through to `astryx_qemu.build_qemu_cmd` extra args | ~80 | additive |
| `kernel/src/test_runner.rs` — `test_cloudinit_c1_nocloud_bash` end-to-end | ~150 | mount cidata, exec script, assert `/data/touch.flag` exists |
| **TOTAL**                                                     | **~1.7 kLOC** | excluding ATAPI; +450 if ATAPI route chosen |

**Recommended driver choice:** attach the CIDATA ISO as a **second
virtio-blk-pci device** with `format=raw`, **not** as `-cdrom`.  This
sidesteps ATAPI altogether and reuses the proven virtio-blk path
(`kernel/src/drivers/virtio_blk.rs`).  ISO 9660 layers cleanly on any
block device — the sector size is 2048 and the filesystem driver does
not care whether the underlying transport is IDE-PIO or virtio.
QEMU happily accepts an `.iso` file as a virtio-blk `format=raw`
drive; the only awkwardness is that some upstream cloud-init
documentation phrases the disk as a "CD" — semantically this is just a
filesystem label match (`CIDATA`), not a transport requirement
([NoCloud spec][nocloud-spec] explicitly says `iso9660` *or* `vfat`).

**Validation:**
```
# Host side, one-shot
mkdir -p /tmp/cidata && cat > /tmp/cidata/meta-data <<'EOF'
instance-id: iid-local01
local-hostname: astryx-cloud-c1
EOF
cat > /tmp/cidata/user-data <<'EOF'
#!/bin/sh
echo HELLO > /tmp/greeting
busybox touch /tmp/cloud-init-worked
EOF
mkisofs -V CIDATA -J -r -o /tmp/cidata.iso /tmp/cidata

# Then in AstryxOS harness:
python3 scripts/qemu-harness.py start --features cloud-init-test \
    --cidata /tmp/cidata.iso
python3 scripts/qemu-harness.py wait <sid> '\[CLOUDINIT-C1\] complete'
python3 scripts/qemu-harness.py grep <sid> 'HELLO'
```

`/tmp/greeting` and `/tmp/cloud-init-worked` exist inside the running
guest after the boot service finishes; the test runner asserts on
their presence via the existing `tmpfs` mount.

**Soft cap:** ~1.7 kLOC + 250 LOC scripts; one PR per (driver,
fs, init shim, harness) with a top-level coordination PR, or one
end-to-end bundle if the diff stays clean.

### Phase C2 — Native Rust cloud-init subset

**Goal:** Process a real `#cloud-config` YAML document and apply the
**five most-used directives** without Python on the guest:

1. `hostname:` → write `/etc/hostname` + call `sethostname(2)`
2. `users:` → append to `/etc/passwd` / `/etc/group` / `/etc/shadow`
3. `ssh_authorized_keys:` → drop the key into `~user/.ssh/authorized_keys`
4. `write_files:` → array of `{path, content, owner, permissions, encoding}`
5. `runcmd:` → array of shell commands, exec via `busybox sh -c`

**LOC budget:**

| Component                                                          | LOC est. |
|--------------------------------------------------------------------|---------:|
| `userspace/cloud-init-c2/` — new native Rust binary (no_std-ish, links libsys), reuses C1 ISO mount | ~2.0 kLOC |
| Tiny YAML reader (only the document shape cloud-config uses — block scalars, lists, key:value maps, no anchors/aliases) | ~600 |
| Module: hostname                                                   | ~80   |
| Module: users + ssh_authorized_keys                                | ~250  |
| Module: write_files                                                | ~200  |
| Module: runcmd                                                     | ~150  |
| `sethostname(2)` Linux dispatch arm + per-task hostname field      | ~60   |
| `reboot(2)` Linux dispatch arm                                     | ~40   |
| Optional metadata HTTP fetch for EC2 magic IP                      | ~400  |
| Tests (runner + integration ISO)                                   | ~400  |
| **TOTAL**                                                          | **~3-5 kLOC** |

This phase is bigger than C1 by a factor of ~2-3 but is still
self-contained: no Python on the guest, no new external dependency
shipped in the data disk.  Recommended only after C1 has proven
end-to-end ISO mount + script exec.

### Phase C3 — Real cloud-init under upstream Python

**Goal:** Run the canonical upstream cloud-init Python codebase
unmodified on AstryxOS.

**Effort:** Multi-week.  Categories:

1. **Stage CPython 3.x + stdlib on the data disk.**  Reuse the shared
   Alpine rootfs (`~/.cache/astryxos-firefox-musl/rootfs/`) and the
   `apk add python3 py3-yaml py3-jinja2 py3-requests py3-jsonpatch
   py3-jsonschema py3-configobj py3-oauthlib` route.  Rootfs cost:
   ~30-60 MiB.
2. **Backfill the Linux ABI Python exercises** beyond what Firefox
   already covers: `epoll_create1` (probably present from FF), full
   `signalfd`/`eventfd` semantics, `prlimit64`, `getrandom`
   `GRND_INSECURE`, `/proc/self/{stat,status,cmdline,limits}` shape,
   `setresuid`/`setresgid`, `mknod(S_IFCHR)`, `chroot` (real),
   `umount2`, `reboot`, `sethostname`, `pivot_root`.  Each is a small
   per-syscall PR.
3. **Add a sysvinit-style staged runner** that wraps cloud-init's
   `cloud-init init --local`, `cloud-init init`, `cloud-init modules
   --mode config`, `cloud-init modules --mode final`.  This can live
   in `init/mod.rs` (Ascension already supports the necessary
   sequencing primitives — add a `service-after <name>` ordering
   directive).
4. **Polish:** `/var/log/cloud-init.log` rotation, `/var/lib/cloud/`
   instance state, datasource SMBIOS hint reading.

Effort estimate: 6-10 weeks of focused work, broadly proportional to
how complete the Linux personality syscall coverage already is at
that point.

---

## 4. Subsystem deltas per phase

### C1 deltas (single-PR-sized once driver work lands)

| Subsystem | Change |
|-----------|--------|
| `kernel/src/drivers/` | Bind a second virtio-blk-pci device.  Trivial extension: `virtio_blk.rs` already enumerates PCI; add support for *N* devices (currently asserts N=1 in practice). |
| `kernel/src/vfs/` | New `iso9660.rs` implementing `FileSystemOps`.  Read-only, sector size 2048, Joliet for long filenames.  Rock Ridge optional. |
| `kernel/src/vfs/mod.rs` | Add `"iso9660"` arm to `sys_mount` (line 2454).  Resolves the source path to a block device (need a small `block_device_by_path` helper since current mount only takes filesystem types, not source). |
| `kernel/src/init/` | New `cloud_init_c1` boot service (in-kernel for now; later C2 promotes to userspace).  Mounts `/cidata`, reads `/cidata/meta-data` (parse `instance-id:`), reads `/cidata/user-data` and exec's `/bin/busybox sh` on it. |
| `kernel/src/test_runner.rs` | New `test_cloudinit_c1_nocloud_bash` feature-gated test. |
| `scripts/build-cidata-iso.sh` | New helper using host `mkisofs`. |
| `scripts/qemu-harness.py` | New `--cidata <path>` flag on `start`; threads through `extra_qemu_args` already plumbed. |

### C2 deltas

| Subsystem | Change |
|-----------|--------|
| `userspace/cloud-init-c2/` | New native Rust binary (links libsys), processes YAML. |
| `kernel/src/subsys/linux/syscall.rs` | Implement `sethostname(2)`, `reboot(2)` proper.  Currently both are stubs / absent. |
| `kernel/src/proc/` | Per-task hostname field (currently a single static node name in `uname`). |
| `kernel/src/security/` | Honour real UIDs when `setuid(2)` is implemented (currently always root). |
| Optional networking | If chasing EC2: virtio-net is already wired, DHCP works; need an HTTP/1.1 client in libsys (~200 LOC). |

### C3 deltas

| Subsystem | Change |
|-----------|--------|
| Data disk | Stage CPython + ~5 MiB of `.py` stdlib + ~30 MiB of cloud-init's pip deps. |
| `kernel/src/subsys/linux/syscall.rs` | Likely 10-20 new syscall arms; widen flag handling on existing arms; honour `O_TMPFILE`, `O_PATH`. |
| `kernel/src/vfs/procfs.rs` | Backfill any `/proc/self/*` paths cloud-init reads but FF doesn't (likely `/proc/self/loginuid`, `/proc/self/sessionid`, `/proc/cpuinfo` shape). |
| `kernel/src/init/` | Add `service-after` ordering directive; stage transitions (`local`/`network`/`config`/`final`). |
| `kernel/src/proc/` | Real UID/GID semantics; supplementary groups; namespaces optional. |

---

## 5. Risks and unknowns

1. **virtio-blk multi-device.**  Today the data disk is the single
   virtio-blk-pci device.  Adding a second instance is a small change
   to `virtio_blk.rs`, but the driver may have implicit
   "first-device-only" assumptions worth auditing before C1 commits.
2. **ISO 9660 corner cases.**  A minimum NoCloud-only reader can be
   ~900 LOC; full Joliet + Rock Ridge support is ~1600.  Joliet alone
   suffices for `meta-data`, `user-data`, `vendor-data`,
   `network-config` filenames (all short ASCII).  Rock Ridge unlocks
   long filenames + Unix permissions — needed for C2 directives like
   `write_files` if cloud-init author chose long filenames inside the
   ISO; defer to C2.
3. **`mount(2)` from a block-device source.**  Current `sys_mount`
   ignores its `source` argument for the FS types it supports.  C1
   needs to resolve `source` → block device.  We have a clean place
   to wire this (the existing `drivers::block` registry); estimate
   ~50-100 LOC.
4. **Hostname mutation visibility.**  `sethostname(2)` is C2 — until
   then, cloud-init-c1 simply ignores the meta-data `local-hostname`
   key.  This is acceptable for C1 demo purposes (we're showing
   user-data exec, not full configuration).
5. **Volume label matching.**  ISO 9660 stores the label in the
   Primary Volume Descriptor (sector 16, offset 40, 32-byte D-string).
   `cloud_init_c1` should reject any volume whose label is not
   `CIDATA` so the demo cannot accidentally interpret an unrelated ISO
   as cidata.  ~30 LOC including padding/trim discipline.
6. **No conflict with concurrent dispatches.**  This audit touches no
   files outside `docs/`.  The accept(2), sshd, and eBPF audits in
   flight are also in `docs/` (per their dispatch briefs) but each
   under a distinct filename — no overlap.
7. **Saga risk.**  Reuse of the W215 antipattern lesson: phys-provenance
   first before any aliasing-shaped bug, frame-identity before
   corruption claims.  Not relevant to C1 (read-only path), but if C2
   write-back patterns surface raciness we should `autopsy` rather
   than printk-grep.

---

## 6. Strategic recommendation

**Greenlight Phase C1 next.**  It's the smallest credible "AstryxOS as
a cloud VM" deliverable:

- **No Python on the guest.**
- **No new networking work** (Phase C1 datasource is local).
- **Two new kernel modules** (`drivers/atapi.rs` is *not* required —
  attach the ISO as a second virtio-blk-pci device; just write
  `vfs/iso9660.rs` and the init shim).
- **One harness flag** (`--cidata`) and **one host helper script**
  (`build-cidata-iso.sh`) to round it out.
- **Tied off by one new test_runner case** plus a `firefox-test`-style
  soak that boots, observes the user-data script's side effects, and
  reports JSON via the harness.

Estimated time-to-demo: **2-3 dispatches** (driver + init shim + harness),
plus a verification soak.  Resulting credibility step: "this VM consumes a
standard cloud-init NoCloud ISO" — the same payload shape that EC2,
OpenStack, Proxmox, and every Linux VM tutorial in the last decade ships
to bootstrap an instance.

Phase C2 is the natural next step once C1 demonstrates the wire
mechanism.  Phase C3 should be revisited after C2 + the Linux personality
syscall coverage stabilises further — at the current rate of ABI
hardening, ~6-12 months out.

---

## 7. Out of scope

This audit explicitly does **not**:

- propose any kernel implementation;
- touch any file outside `docs/CLOUDINIT_AUDIT_2026-05-23.md`;
- recommend changes to the three concurrent dispatches (accept(2), sshd,
  eBPF) — those targets are orthogonal and their roadmaps stand on their
  own merits;
- declare a delivery date — phasing is offered to inform planning, not to
  commit a schedule.

---

## References (public specifications and upstream documentation)

[nocloud-spec]: https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html
[nocloud-spec-2]: https://cloudinit.readthedocs.io/en/20.4.1/topics/datasources/nocloud.html
[cloud-init-reqs]: https://cloudinit.readthedocs.io/en/latest/development/contribute_code.html
[iso9660-wiki]: https://en.wikipedia.org/wiki/ISO_9660
[tinycloudinit]: https://github.com/spinto/tinycloudinit
[osrelease-spec]: https://www.freedesktop.org/software/systemd/man/os-release.html
[busybox-sh]: https://busybox.net/
[posix-execve]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/execve.html

- Cloud-init NoCloud datasource: <https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html>
- Cloud-init runtime requirements / Python floor:
  <https://cloudinit.readthedocs.io/en/latest/development/contribute_code.html>
- ECMA-119 (ISO 9660) overview: <https://en.wikipedia.org/wiki/ISO_9660>
- tinycloudinit (shell-only cloud-init alternative): <https://github.com/spinto/tinycloudinit>
- BusyBox sh(1): <https://busybox.net/>
- freedesktop os-release(5):
  <https://www.freedesktop.org/software/systemd/man/os-release.html>
- POSIX execve(2):
  <https://pubs.opengroup.org/onlinepubs/9699919799/functions/execve.html>
