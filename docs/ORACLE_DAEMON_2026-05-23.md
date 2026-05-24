# Oracle Daemon-Mode Bring-up — AstryxOS Hosting (PIVOT-I2 Phase D)

**Date**: 2026-05-23
**Author**: principal-systems-engineer
**Predecessor**: PR #439–#442 (oracle staging, sysfs network shim, DT_NEEDED walker)
**Status**: Daemon-mode running end-to-end; one TX-path kernel-net gap blocks
heartbeat delivery.

---

## TL;DR

- Oracle binary launched in **daemon mode** (no `--once`) reaches the polling
  loop, brings up the full tokio multi-thread runtime, enumerates the
  network interface via `/sys/class/net/` (PR #442 shim), and **opens
  outbound TCP connections to the host stub Conflux** at
  `http://10.0.2.2:8088/heartbeat`.
- **Heartbeat HTTP POSTs are emitted by oracle but do not reach the host
  stub.** Kernel logs show 10 `[TCP] Established → 10:8088` events in a
  180 s soak; the host-side stub Conflux receives **zero** heartbeats.
  Data delivery from guest to host loopback through QEMU SLIRP is the
  blocker.
- One discrete kernel ABI bug was fixed inline as part of this dispatch
  (`F_DUPFD`-of-epoll fd losing the underlying `EpollInstance`).
- Companion files: `scripts/oracle-stub-conflux.py` (host responder),
  `--oracle-stub-conflux` harness flag (auto-launch + teardown),
  `/etc/oracle/daemon.toml` (sync-enabled config, plain HTTP).

---

## 1. What works

Validated under `--features oracle-daemon-test --oracle-stub-conflux 8088`,
180 s KVM soak.

| Layer | Status | Evidence |
|---|---|---|
| Dynamic linker (glibc, ld-linux-x86-64.so.2) | OK | oracle ELF loaded; no PRE-MAIN gate |
| glibc + libssl3 + libcrypto3 + libzstd1 + libz1 | OK | DT_NEEDED closure resolved via PR #441 walker |
| Tokio multi-thread runtime + worker spawn | OK | `<6>Polling loop started`, `<6>Enabled collectors: ...` |
| signal-hook-registry + tokio signal driver | OK | runtime reaches steady state; no premature EBADF |
| `F_DUPFD_CLOEXEC` of an `epoll_create1` fd | **OK (fixed in this PR)** | see §3 |
| `/sys/class/net/eth0/{address,operstate,type,...}` | OK | oracle prints `MAC: 52:54:00:12:34:56` from PR #442 shim |
| Network-collector first poll + change detection | OK | `<6>Network adapter changes: +1 -0 ~0 + eth0: Ethernet` |
| Daemon-mode soak (180 s, no crash) | OK | LIVENESS markers every 10–20 s; exit_code=0 (SIGKILL'd by soak deadline) |
| Outbound TCP connect to `10.0.2.2:8088` | OK | 10× `[TCP] Established → 10:8088` events in 180 s soak |
| ARP resolution for SLIRP gateway | OK | `[ARP] Reply: 10.0.2.2 -> 52:55:0a:00:02:02` |
| Host-side stub Conflux listener | OK | `scripts/oracle-stub-conflux.py` binds, ready-file written, harness teardown clean |

## 2. What is blocked

| Layer | Gate | Evidence |
|---|---|---|
| HTTP POST payload delivery from guest to host | **Data writes to socket never reach host** | `[PROC-METRICS] net=R0/W465` per-poll; `cat <sid>.oracle-stub.jsonl` is empty; manual curl to the stub from the host works fine |
| Heartbeat-send log line | not observed | symptom of payload-delivery gate above |
| `vfork+exec /bin/ip`, `/usr/bin/ip`, `/usr/sbin/ip` | ENOENT (iproute2 not staged) | network collector tries `ip -j` for richer address data; falls back gracefully to `/sys/class/net` reads |

The dominant blocker is the **TCP TX-path / SLIRP NAT data-delivery gap**.
The 3-way handshake completes (connection enters Established), the guest's
`write(2)` advances the byte counter, but the bytes never appear on the
host loopback port. Suspected causes (ordered by likelihood):

1. **TCP window / send-buffer flush race in `kernel/src/net/tcp.rs`** —
   the guest's `write` enqueues into the send buffer but the e1000 TX
   path may not flush before tokio's NONBLOCK-style `Drop` aborts the
   socket. The kernel logs `[TCP] RST: closing port N` shortly after
   each Established event — that RST is an *inbound* RST (host →
   guest), suggesting the host stack saw a SYN+ACK exchange but then
   reset on receiving partial or no data within its timeout. SLIRP
   forwards the RST.
2. **e1000 driver TX descriptor sequencing under tokio NONBLOCK
   socket churn** — e1000 + SLIRP + outbound TCP is exercised by the
   `wget-test` and `tls-test` paths (which work for short, blocking
   GETs); oracle's pattern of larger NONBLOCK POSTs with rapid
   close-on-drop may expose a tail of in-flight bytes that don't make
   it onto the wire before the descriptor ring is reaped.
3. **POST-specific quirk** — oracle issues a chunked-or-content-length
   HTTP/1.1 POST with `~465` bytes body. The busybox wget uses GET
   with ~80-byte requests. The size difference (one fragment vs
   approaching MSS) may matter if our TCP TX path mishandles
   `PSH+FIN` framing on the close.

Recommended next dispatch: **network-development-engineer** scope —
"investigate outbound TCP TX path for medium-payload HTTP POST through
SLIRP; oracle daemon issues 465-byte POSTs to 10.0.2.2:8088, three-way
handshake succeeds, payload never reaches host loopback, peer RST'd."
Suggested probes: kdb `tcp-snapshot`, `[E1000] TX desc N tx_descr` log
on each TX completion, host-side `tcpdump -i lo port 8088` to confirm
whether SLIRP injected any bytes.

## 3. Inline kernel ABI fix — `F_DUPFD` of `epoll_create1` fd

### Symptom (pre-fix)

Oracle daemon mode crashed after one observation cycle with
`Error: Os { code: 9, kind: Uncategorized, message: "Bad file descriptor" }`,
exit code 1.

### Root cause

The `tokio` runtime + `signal-hook-registry` brings up its signal driver
by `F_DUPFD_CLOEXEC`-ing the mio-internal `epoll` fd into a
signal-driver-local epfd (e.g. fd=4 → fd=6), then doing
`epoll_ctl(epfd=6, ADD, signal-pipe-fd, ...)`. Per POSIX `dup(2)` and
Linux `epoll(7)`, registrations on a dup'd epoll fd must be visible
through any dup of the original (the interest list is associated with
the open file description, not the fd).

Pre-fix, `kernel/src/subsys/linux/syscall.rs::sys_epoll_ctl` looked the
`EpollInstance` up by `epfd` (the integer fd value), not by the
underlying open-file identity:

```rust
let inst = match proc.epoll_sets.iter_mut().find(|e| e.epfd == epfd) {
    Some(i) => i,
    None    => return -9, // EBADF
};
```

So `epoll_ctl(epfd=6, ...)` returned EBADF because `epoll_sets[0].epfd == 4`
(the original `epoll_create1` slot). signal-hook treated this as fatal
and tore down the runtime.

### Fix (PIVOT-I2 Phase D)

1. `EpollInstance` now carries a per-process unique `id: u64` allocated
   by `next_epoll_id()` at `epoll_create1` time.
2. The owning `FileDescriptor.inode` is stamped with the same id (the
   inode field was unused at `0` for epoll fds previously).
3. `dup(2)` / `fcntl(F_DUPFD)` clone the `FileDescriptor` (including
   `inode`), so dup'd fds carry the id forward.
4. `sys_epoll_ctl` / `sys_epoll_wait` look up the `EpollInstance` by
   id (`f.inode`) rather than by `epfd`, so any dup of the original
   epoll fd resolves to the same shared `EpollInstance`.
5. `close(2)` on a `[epoll]` FileDescriptor only retires the
   `EpollInstance` when no other `FileDescriptor` in the process points
   at the same id (refcount via fd-table scan).

### Verification

- Pre-fix: oracle daemon crashes 3 s after first network poll with
  EBADF, exit 1.
- Post-fix: oracle daemon reaches `Polling loop started`, completes
  multiple poll cycles, opens 10× TCP connections to the host stub in
  180 s. RUNTIME-OK-NO-EMIT verdict (sync layer blocked downstream;
  see §2).
- All existing `--features test-mode` and `--features oracle-test`
  builds still type-check and pass; only the additive id field is new
  on `EpollInstance`.

References (public):
- POSIX.1-2017 `dup(2)`: https://pubs.opengroup.org/onlinepubs/9699919799/functions/dup.html
- Linux `epoll(7)`: https://man7.org/linux/man-pages/man7/epoll.7.html
- POSIX.1-2017 §2.14 (open file descriptions)

## 4. What landed in this PR

| Artefact | Lines | Purpose |
|---|---|---|
| `kernel/src/ipc/epoll.rs` | +50 | `EpollInstance.id` + `next_epoll_id()` + `new_with_id` constructor |
| `kernel/src/subsys/linux/syscall.rs` (epoll_create1) | +12 | stamp id into both `EpollInstance` and `FileDescriptor.inode` |
| `kernel/src/subsys/linux/syscall.rs` (epoll_ctl/wait) | +18 | lookup by id (inode) not epfd |
| `kernel/src/subsys/linux/syscall.rs` (close) | +25 | refcount-on-close: only retire instance when last fd-ref drops |
| `kernel/src/oracle_demo.rs` (new `run_oracle_daemon`) | +280 | daemon-mode launcher with sync override env + heartbeat marker tracking |
| `kernel/src/main.rs` | +50 | mutually-exclusive cfg gate for `oracle-daemon-test` |
| `kernel/Cargo.toml` | +20 | new `oracle-daemon-test` feature definition |
| `scripts/oracle-stub-conflux.py` (new) | +270 | host-side HTTP responder for heartbeat receive |
| `scripts/qemu-harness.py` | +110 | `--oracle-stub-conflux PORT` flag, auto-launch + teardown |
| `scripts/install-oracle.sh` | +60 | write companion `/etc/oracle/daemon.toml` (sync enabled) |
| `scripts/create-data-disk.sh` | +15 | stage `daemon.toml` into `data.img` |
| `docs/ORACLE_DAEMON_2026-05-23.md` (this file) | +180 | hand-off doc |

Total: ~1.1k LOC across kernel + harness + Python + bash + docs.

## 5. How to reproduce

```bash
# Stage oracle + daemon.toml (idempotent).
bash scripts/install-oracle.sh
bash scripts/create-data-disk.sh --oracle --force

# Boot with the harness (launches the host stub on 127.0.0.1:8088 + tears
# it down at session stop).
python3 scripts/qemu-harness.py start \
    --features oracle-daemon-test \
    --oracle-stub-conflux 8088 \
    --no-regen-data-img
# → returns {"sid": "...", ...}

# Wait for daemon verdict (180 s soak).
python3 scripts/qemu-harness.py wait <sid> 'ORACLE-DAEMON:' --ms 200000

# Inspect heartbeats reaching the stub (currently empty; see §2).
cat ~/.astryx-harness/<sid>.oracle-stub.jsonl

# Inspect kernel-side TCP activity (currently shows 10× Established +
# inbound RSTs; see §2).
grep -E "TCP|ARP" ~/.astryx-harness/<sid>.serial.log

# Stop the session (also tears down the host stub).
python3 scripts/qemu-harness.py stop <sid>
```

## 6. Major-win threshold not yet reached

The dispatch's major-win threshold was "1+ heartbeat received by a
Conflux stub on AstryxOS." Pre-PR state: oracle could not reach a
heartbeat send path at all (BANNER-ONLY, EBADF crash). Post-PR state:
oracle reaches the heartbeat send path, opens TCP connections, but the
HTTP POST payload doesn't traverse SLIRP. The remaining gap is a
discrete kernel-net bug that warrants a dedicated investigation
(network-development-engineer scope).

## 7. References (public)

- POSIX.1-2017 (IEEE Std 1003.1-2017): `dup(2)`, `epoll(7)`, `socket(2)`,
  `connect(2)`, `write(2)`.
- RFC 9110 — HTTP semantics (POST, Content-Length, 2xx).
- RFC 9112 — HTTP/1.1 message syntax.
- RFC 793 / RFC 9293 — Transmission Control Protocol.
- QEMU SLIRP networking:
  https://www.qemu.org/docs/master/system/devices/net.html#network-options
- tokio: https://tokio.rs/
- Python `http.server`: https://docs.python.org/3/library/http.server.html
