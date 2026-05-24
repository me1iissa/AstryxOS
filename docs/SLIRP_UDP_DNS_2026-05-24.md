# Outbound UDP DNS substrate (2026-05-24)

NDE deliverable that closes the userspace DNS-resolution gap reported in
the I1a TLS dispatch hand-back and the infrasvc oracle audit
(PR #436, docs/INFRASVC_ORACLE_AUDIT_2026-05-23.md).  Any glibc/musl
client that calls `getaddrinfo("hostname", ...)` or `BIO_lookup_ex` can
now resolve names through SLIRP's DNS forwarder at 10.0.2.3.

## Gate state

- Before: `nslookup example.com 10.0.2.3` exited 1 with
  `";; connection timed out; no servers could be reached"` even though
  the in-kernel `dns::resolve()` path against the same forwarder
  returned a real address (validated by `test_dns_resolution` in
  `kernel/src/test_runner.rs`).
- After: `nslookup example.com 10.0.2.3` exits 0 with two A records
  (172.66.x, 104.20.x) and two AAAA records (2606:4700::) — the full
  resolver chain works end-to-end.

## Root-cause chain

The userspace-side gap was a four-layer interaction between the AF_INET
SOCK_DGRAM socket layer, the connect/sendto syscall stubs, the poll
wait loop, and the absence of a wake hook on the inbound UDP path.
The kernel-side UDP module (`net/udp.rs`), the kernel-side DNS resolver
(`net/dns.rs`), and the syscall-level socket surface
(`subsys/linux/syscall.rs`) were each individually correct; the
composition was broken.

### Layer 1 — `socket_connect(2)` on UDP did not allocate a local port

`socket_connect(SOCK_DGRAM, ...)` set `remote_ip`/`remote_port`,
flagged the socket connected, and returned `Ok(())` without touching
`local_port`.  The subsequent UDP datagram went out with
`source_port == 0`; the SLIRP-side DNS reply targeted port 0, matched
no per-port binding in `udp::handle_udp`, and was silently dropped.

Fix: `socket_connect` now auto-binds a 49152–65535 ephemeral when the
caller has not already called `bind(2)`.  Mirrors the implicit-bind
behaviour every Berkeley-derived stack provides per `man 2 connect`
(IEEE 1003.1 §connect) and RFC 6335 §6 ephemeral allocation.

### Layer 2 — connect(2) syscall stub waited for TCP state on UDP

The Linux personality's connect(2) implementation in
`subsys/linux/syscall.rs` post-`socket_connect` ran a 3-second wait
loop calling `tcp::get_state(local_port)`, expecting an Established
transition.  For UDP, `tcp::get_state` returns `None` forever, so
every UDP `connect(2)` returned `-110 ETIMEDOUT` after 3 s.  Userspace
resolvers treat this as "DNS server unreachable" and either retry or
abort.

Fix: connect(2) now samples the socket type via
`socket::SOCKETS.lock()` and returns `0` immediately for UDP, matching
IEEE 1003.1 §connect: only connection-mode transports perform a
handshake.

### Layer 3 — `socket_sendto` / `socket_send` on an unbound UDP socket

Same shape as Layer 1: an unbound UDP socket whose source port was
zero on the wire.  POSIX `man 2 sendto` and `man 2 send` permit
sending on an un-bound SOCK_DGRAM and require the protocol to assign
a port automatically.

Fix: `socket_sendto` and `socket_send` (the latter via the connected
path) lazily allocate an ephemeral port and call `udp::bind` before
emitting the wire datagram.  The race window between two concurrent
unbound sends on the same socket id is resolved under the SOCKETS
mutex — the loser unbinds the just-reserved port and reuses the
winner's `local_port`.

### Layer 4 — UDP RX did not ring the poll bell + poll wait loop did not pump net::poll

Even with the per-socket bindings correctly demultiplexing replies,
two cooperative gaps kept the reply invisible to `poll(2)`:

1. **`udp::handle_udp` had no wake hook.**  Pipes, eventfds, AF_UNIX
   sockets all call `ipc::waitlist::ring_poll_bell_for(...)` after
   writing into the receiver-side queue, so any thread parked in
   `wait_poll_event` rescans its fd set within ~1 µs.  UDP and TCP
   never rang the bell, so the only wake source was the 1 s resync
   floor in `wait_poll_event` — far longer than the 2.5 s default
   timeout musl's stub resolver uses (and shorter than busybox
   nslookup's 5 s budget by ~50%, making it brittle).
2. **The poll(2) wait loop in `subsys/linux/syscall.rs` never called
   `net::poll()`.**  e1000 RX descriptors land in the ring on DMA from
   QEMU's SLIRP backend but are only drained by `e1000::poll_rx`,
   itself only invoked from `net::poll`.  The only sites that pump
   `net::poll` are: the BSP idle loop (rare in a busy guest), the
   shell, the DHCP loop, and the httpd-test pump thread.  A
   poll-waiting userspace process pre-empted the BSP idle loop and
   blocked indefinitely for its own data.

Fix: `udp::handle_udp` now rings `PollBellSource::InetRx` after
queueing a datagram, and the poll(2) wait loop calls `net::poll()`
on every re-check (both the pre-wait fast path and the post-bell
re-evaluation).  TCP gets the same wake-hook treatment in a follow-up.

## Public-spec citations

- RFC 768 — User Datagram Protocol — connectionless transport,
  source-port demultiplexing.
- RFC 1035 §4.2.1 — Domain Implementation and Specification, UDP
  query/response timing budget.
- RFC 6335 §6 — IANA Service Name and Transport Protocol Port Number
  Registry — ephemeral allocation range 49152–65535.
- IEEE 1003.1 §connect, §sendto, §send, §recvfrom — POSIX socket
  function semantics, including the "implicit bind" requirement for
  SOCK_DGRAM connect.
- `man 2 sendto` / `man 2 connect` — Linux man-page surface for the
  ABI userspace expects.

## Verification

- **Unit test**: `kernel/src/test_runner.rs::test_274_udp_connect_auto_bind`
  drives the three socket-layer fixes against the loopback path:
  - 274-A: `socket_connect` auto-binds an ephemeral port in the
    49152–65535 range.
  - 274-B: `socket_sendto` on an un-bound UDP socket also auto-binds;
    the probe datagram lands at the peer port with the auto-bound
    source.
  - 274-C: a reply datagram from the peer lands on the socket's
    `recvfrom` path with the correct (src_ip, src_port).
- **End-to-end soak**: `--features busybox-test` runs `busybox
  nslookup example.com 10.0.2.3` and exits 0 with the resolved A and
  AAAA records.  See the `nslookup` applet in `kernel/src/busybox_demo.rs`.

## Files touched

| File | Change |
|---|---|
| `kernel/src/net/socket.rs` | `socket_connect`/`socket_sendto`/`socket_send` auto-bind ephemeral UDP ports; refactor ephemeral allocator out of `socket_bind` |
| `kernel/src/net/udp.rs` | `handle_udp` rings the `InetRx` poll bell after queueing |
| `kernel/src/ipc/waitlist.rs` | New `PollBellSource::InetRx` variant + array slot |
| `kernel/src/subsys/linux/syscall.rs` | connect(2) skips TCP wait for UDP; recvfrom(2) honours fd O_NONBLOCK + MSG_DONTWAIT and blocks correctly on blocking UDP; poll(2) wait loop pumps `net::poll` so e1000 RX gets drained pre-wait and post-bell |
| `kernel/src/busybox_demo.rs` | `nslookup` applet added to demo battery |
| `kernel/src/test_runner.rs` | Test 274 (UDP connect/sendto auto-bind + loopback echo) |
| `docs/SLIRP_UDP_DNS_2026-05-24.md` | This document |

## Follow-ups

- TCP wake hook (`tcp::handle_tcp` should also ring `PollBellSource::InetRx`
  on segment arrival).  Out of scope here because PR #444 covered TCP TX
  and PR #435 covered AF_INET accept(2), neither of which exercise the
  RX-side poll wake.
- `read(2)` / `recv(2)` on a blocking AF_INET socket also returns 0 on
  empty queue (mis-reported as EOF).  Same blocking treatment as
  recvfrom(2) is straightforward but adds churn outside the DNS path.
