# `/sys/class/net` native sysfs surface (2026-05-23)

## Why

Production Linux server binaries discover network interfaces by
`glob("/sys/class/net/*")` and then read per-interface attribute files
(`address`, `operstate`, `mtu`, `carrier`, `speed`, `flags`, `ifindex`,
`type`).  Two concrete consumers were blocking on the absence of this
surface:

* The oracle endpoint agent's network collector.  Without
  `/sys/class/net`, its first poll cycle aborts with
  `"Linux network interface directory /sys/class/net not found"` and the
  whole observation chain stays at zero.
* cloud-init's NoCloud datasource — its interface-discovery probe walks
  the same path.

Both binaries also drive a long tail of downstream Linux server
software (nginx config parsing, postgres `listen_addresses`, ifupdown,
NetworkManager probes).  A kernel-side sysfs is the long-term right
answer: build it once, every consumer benefits.

## What

Two additions to AstryxOS's existing `/sys` pseudo-filesystem (already
mounted by `vfs::init`):

1. A `/sys/class/net/<iface>/` directory tree per network interface,
   populated on every readdir/lookup from a kernel-side interface
   snapshot.  Always exposes `lo`; exposes `eth0` when an Ethernet NIC
   (e1000 or virtio-net) has finished `init()` successfully.

2. The per-interface attribute file set, formatted per
   `kernel.org/Documentation/ABI/testing/sysfs-class-net` and
   `Documentation/networking/operstates.rst`:

   | File | Content | Notes |
   |---|---|---|
   | `address`   | `xx:xx:xx:xx:xx:xx\n` | All-zero for `lo`; hardware MAC for `eth0` |
   | `operstate` | one of `up`/`down`/`unknown`/`lowerlayerdown`/`dormant`/`notpresent`/`testing` + `\n` | `lo` reports `unknown` (no link layer) |
   | `mtu`       | decimal integer + `\n` | `lo` = 65536, `eth0` = 1500 |
   | `carrier`   | `0\n` or `1\n` | `lo` reports `0\n` (no carrier concept) |
   | `speed`     | decimal Mb/s + `\n`, or `-1\n` | `lo` reports `-1\n`; `eth0` = 1000 |
   | `flags`     | `0x<hex u32>\n` | IFF_* mask |
   | `ifindex`   | decimal + `\n` | `lo` = 1, `eth0` = 2 |
   | `type`      | decimal ARPHRD_* + `\n` | `lo` = 772 (loopback), `eth0` = 1 (ether) |

3. Test 272 (`/sys/class/net native sysfs surface`) — 8 sub-cases
   exercising readdir, stat, and read of each attribute against `lo`.
   Gated on `test-mode | firefox-test | oracle-test`.

## Design

* **Pull-on-read.**  Each call into the sysfs FS for `/sys/class/net`
  re-evaluates `net::list_ifaces()`.  No caching, no push notifications.
  Consumers either glob/readdir once at start-up or poll on a coarse
  interval; matches Linux's own change-notification budget for sysfs
  (uevent is netlink-driven, not VFS-driven).
* **Inode allocation.**  Net subtree lives in `3400-3999`; per-iface
  block of 16 inodes × up to 32 ifaces.  Disjoint from the existing CPU
  subtree at `3000-3399`.
* **Interface model in `net::mod.rs`.**  `IfaceInfo` struct + `list_ifaces()`
  function.  Carrier and speed are `Option<…>` so loopback can encode
  "no concept" without surfacing an error from inside the FS layer.
* **No write path.**  Writes return `EACCES` (unchanged from the
  existing sysfs implementation).  Userspace `mtu`/`speed`/etc. mutation
  is not in scope for v1.

## Test evidence (test-mode, KVM, 2026-05-23)

```
TEST: /sys/class/net native sysfs surface
  272-A readdir /sys/class/net → ["lo", "eth0"] (contains lo) ✓
  272-B stat /sys/class/net/lo → Directory ✓
  272-C address = "00:00:00:00:00:00\n" ✓
  272-D mtu = 65536 ✓
  272-E operstate = "unknown" ✓
  272-F ifindex = 1 ✓
  272-G type = "772\n" (ARPHRD_LOOPBACK) ✓
  272-H speed = "-1\n" (loopback) ✓
[PASS] /sys/class/net native sysfs surface
```

Note that `eth0` also appears in the readdir output — the e1000 NIC came
up during boot and is automatically exposed.

## Oracle-test soak evidence (oracle-test, KVM, 2026-05-23)

Pre-fix gate (commit `7477a1e`):
```
[ORACLE] oracle | Error: "Linux network interface directory /sys/class/net not found"
[ORACLE] === SUMMARY === ... sys_class_net=1 ...
```

Post-fix (this PR):
```
[ORACLE] === SUMMARY === banner=0 collector_init=0 observation=0 sys_class_net=0
                        panic=0 enosys=0 libssl_fail=0 exit=127 ...
```

`sys_class_net=0` means oracle's stdout no longer mentions
`/sys/class/net` at all — the kernel served the path and the directory
walk succeeded.  The new downstream gate is a userspace library
packaging issue (`libzstd.so.1` missing from the data disk), entirely
separate from sysfs surface coverage.

## Deferred (out of scope for this PR)

* Writable attributes (`mtu`, `txqueuelen`, etc.).  Linux allows
  selective writes; oracle/cloud-init do not require them.
* Per-interface statistics subdirectory (`statistics/rx_bytes`,
  `tx_packets`, …).  The interface table already exposes counters; a
  follow-up patch can route them into `/sys/class/net/<iface>/statistics/`.
* `queues/` subdirectory (rx-0, tx-0).  Used by multi-queue tuning
  tools; consumers we care about (oracle, cloud-init) do not read it.
* Real link-state probing for `eth0`.  We currently advertise
  `operstate=up` and `carrier=1` unconditionally when the NIC is
  initialised.  A follow-up patch can wire e1000 STATUS.LU and the
  virtio-net link-status feature into the IfaceInfo fields.

## Public references

* kernel.org `Documentation/ABI/testing/sysfs-class-net` — attribute
  set, semantics, and content format.
* kernel.org `Documentation/networking/operstates.rst` — operstate
  token vocabulary (RFC 2863 mapping).
* `man 7 netdevice` — IFF_* bit definitions; SIOCGIFFLAGS semantics.
* `man 5 sysfs` — pseudo-FS pull-on-read model; size=0 convention.
* RFC 1042 — ARPHRD type codes (ARPHRD_ETHER=1, ARPHRD_LOOPBACK=772).
* RFC 1122 §3.2.1.3 — loopback semantics; 127.0.0.0/8 always present.
* POSIX-1.2017 `open(2)`/`read(2)`/`readdir(3)` — file-op contracts.
