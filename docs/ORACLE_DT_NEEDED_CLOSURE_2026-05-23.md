# Oracle DT_NEEDED Transitive Closure — 2026-05-23

## TL;DR

`scripts/install-oracle.sh` now walks the oracle binary's full DT_NEEDED
transitive closure with a BFS over `readelf -d` output, staging every
reachable `.so` into `build/disk/lib/x86_64-linux-gnu/` (the canonical
Debian multiarch path that `create-data-disk.sh` mcopies into
`/lib/x86_64-linux-gnu/` on the FAT32 data image).

After the walker landed, oracle reached its **actual init path** on
AstryxOS for the first time:

```
[ORACLE] oracle | <6>Oracle agent starting in console mode
[ORACLE] oracle | <6>Running single network adapter poll
[ORACLE] oracle | Error: "Linux network interface directory /sys/class/net not found"
[ORACLE] === ORACLE-TEST: PASS-INIT (reached banner/collector init; exit=1 — name the gate above) ===
```

That is the first time oracle has printed anything past `ld-linux`
"cannot open shared object file" wedges.  The new gate is procfs/sysfs,
not a missing library.

## Why the previous oracle staging was insufficient

`install-oracle.sh` previously hard-coded staging of `libssl.so.3` and
`libcrypto.so.3` only.  That covered oracle's *direct* DT_NEEDED but
missed `libcrypto.so.3`'s own dependencies on `libz.so.1` and
`libzstd.so.1`.

```
$ readelf -d /usr/lib/x86_64-linux-gnu/libcrypto.so.3 | grep NEEDED
 NEEDED  Shared library: [libz.so.1]
 NEEDED  Shared library: [libzstd.so.1]
 NEEDED  Shared library: [libc.so.6]
```

When `ld-linux` opened `libcrypto.so.3` it then looked up `libzstd.so.1`
on the default search path (per ld.so(8) — DT_RUNPATH absent on oracle),
failed, and exited 127 with:

```
oracle: error while loading shared libraries: libzstd.so.1:
  cannot open shared object file: No such file or directory
```

## What the walker does

`walk_dt_needed_closure(root)` (BFS):

1. Start the queue with the oracle binary.
2. Pop a file, run `readelf -d` to enumerate its DT_NEEDED entries.
3. For each SONAME:
   - Skip base glibc names (`libc.so.6 libm.so.6 libpthread.so.0
     libdl.so.2 librt.so.1 libresolv.so.2 ld-linux-x86-64.so.2`) — those
     are owned by `install-glibc.sh`.
   - Resolve via `ldconfig -p` first; fall back to a fixed search
     dir list (`/lib/x86_64-linux-gnu`, `/usr/lib/x86_64-linux-gnu`,
     `/lib64`, `/usr/lib64`, `/lib`, `/usr/lib`).
   - Stage as a real file under `${DISK_GLIBC_LIB}/${soname}` (FAT32
     has no symlinks, so `cp -L` dereferences host symlinks).
   - When the host symlink resolves to a differently-named file
     (`libzstd.so.1 -> libzstd.so.1.5.7`), stage **both names** as real
     files so DT_NEEDED resolution (`libzstd.so.1`) AND any runtime
     dlopen of the versioned name both succeed.
   - Enqueue the real path for further walking.
4. Visited-set keyed by `readlink -f` real path so the walk terminates.

The walk runs to fixed point in O(deps) host-side time — for oracle that
is 5 libraries plus 9 skipped base-glibc references, completing in well
under a second.

## Libraries staged by the walker

```
[ORACLE]   staged libssl.so.3 (1106088 bytes, src=/usr/lib/x86_64-linux-gnu/libssl.so.3)
[ORACLE]   staged libcrypto.so.3 (6382432 bytes, src=/usr/lib/x86_64-linux-gnu/libcrypto.so.3)
[ORACLE]   staged libgcc_s.so.1 (187120 bytes, src=/usr/lib/x86_64-linux-gnu/libgcc_s.so.1)
[ORACLE]   staged libz.so.1 (+libz.so.1.3.1) (121272 bytes, src=/usr/lib/x86_64-linux-gnu/libz.so.1)
[ORACLE]   staged libzstd.so.1 (+libzstd.so.1.5.7) (796824 bytes, src=/usr/lib/x86_64-linux-gnu/libzstd.so.1)
[ORACLE] DT_NEEDED closure: 5 staged, 9 skipped (base glibc), 0 missing
```

Total fresh disk footprint added: ~8.7 MiB across 7 real-ELF files (5
SONAMEs, of which 2 also carry a versioned-name copy).

## Path coherence (why /lib/x86_64-linux-gnu/)

Oracle uses the standard glibc dynamic linker
`/lib64/ld-linux-x86-64.so.2` per PT_INTERP and has no DT_RPATH /
DT_RUNPATH.  Per ld.so(8) the search order without an explicit RPATH is:

1. `LD_LIBRARY_PATH` (oracle is launched with
   `LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/lib64:/usr/lib/x86_64-linux-gnu`
   per `kernel/src/oracle_demo.rs:110`)
2. `/etc/ld.so.cache` (kernel pre-stages `/etc/ld.so.conf` listing those
   same paths per `create-data-disk.sh:614`)
3. Default `/lib`, `/usr/lib`

We stage to `/lib/x86_64-linux-gnu/` because:

- It is the first explicit hit on the LD_LIBRARY_PATH.
- `install-glibc.sh` already targets the same path for the base glibc
  libraries, so a single mcopy in `create-data-disk.sh` lines 718-723
  captures everything for the glibc track in one pass.
- The Alpine musl staging under `/usr/lib/` is incompatible with a
  glibc binary (different libc, different TLS layout, different
  relocation semantics — verified by prior soak attempts), so we do NOT
  reuse the musl track even when libssl/libcrypto/libzstd are already
  present there.

## Verification

```bash
ASTRYXOS_ORACLE=1 bash scripts/create-data-disk.sh --oracle --force
ASTRYXOS_ORACLE=1 python3 scripts/qemu-harness.py start --features oracle-test
python3 scripts/qemu-harness.py wait <sid> '\[ORACLE\] DONE|\[ORACLE\] === ORACLE-TEST:'
python3 scripts/qemu-harness.py grep <sid> '\[ORACLE\]' --tail 40
python3 scripts/qemu-harness.py stop <sid>
```

Captured serial transcript at the new gate:

```
[ORACLE] oracle-test starting (PIVOT-I2, 2026-05-23)
[ORACLE] Loaded /disk/usr/bin/oracle (5042136 bytes)
[ORACLE] Spawning oracle with argv=["oracle", "--mode", "console", "--once",
                                    "--log-level", "debug",
                                    "--config", "/etc/oracle/config.toml"]
[ORACLE] oracle spawned: pid=1
[ORACLE] oracle | <6>Oracle agent starting in console mode
[ORACLE] oracle | <6>Running single network adapter poll
[ORACLE] oracle | Error: "Linux network interface directory /sys/class/net not found"
[ORACLE] === SUMMARY === banner=1 collector_init=0 observation=1 sys_class_net=1
                         panic=0 enosys=0 libssl_fail=0 exit=1 state=Zombie
                         captured_bytes=148 timed_out=0
[ORACLE] === ORACLE-TEST: PASS-INIT (reached banner/collector init; exit=1
                                     — name the gate above) ===
[ORACLE] DONE
```

Note the summary fields: `panic=0 enosys=0 libssl_fail=0` confirms the
lib-load chain is fully satisfied and oracle reached its tokio runtime
intact.  `banner=1 observation=1` confirms oracle's own init code ran
through to its first collector poll.  `sys_class_net=1` names the next
gate: the network collector wants `/sys/class/net/<iface>/` and the
kernel does not yet expose sysfs.

## Next gate (out of scope for this dispatch)

Oracle's network adapter collector calls `glob("/sys/class/net/*")` and
expects per-iface directories with files like `address`, `operstate`,
`speed`, `mtu`, `carrier`.  AstryxOS does not currently mount a sysfs.

Two paths forward:

1. **Stub `/sys/class/net/` on the data disk** with a single `lo`
   directory containing static files (`address=00:00:00:00:00:00`,
   `operstate=unknown`, `mtu=65536`, `carrier=1`).  ~5 LOC in
   `create-data-disk.sh`, lets oracle complete its first observation
   cycle with a synthetic loopback interface.

2. **Implement a minimal sysfs in the kernel** mounted at `/sys/`,
   driven by the existing AF_INET/network-interface introspection
   surface.  Larger; would also unblock cloud-init's
   network-detection code paths (per
   `docs/CLOUDINIT_AUDIT_2026-05-23.md`).

Recommendation: do (1) first as a 30-minute follow-up so oracle prints
its first full observation cycle (Discord-major-win bar fully cleared);
schedule (2) into the C-track (cloud-init) roadmap.

## References (public)

- ELF gABI (System V ABI §5.4 "Dynamic Linking — Shared Object
  Dependencies"): https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html
- `ld.so(8)`: https://man7.org/linux/man-pages/man8/ld.so.8.html
- `readelf(1)`: https://man7.org/linux/man-pages/man1/readelf.1.html
- `ldconfig(8)`: https://man7.org/linux/man-pages/man8/ldconfig.8.html
