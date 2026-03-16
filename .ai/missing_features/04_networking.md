# Networking / TCP-IP Stack Gaps

> Reference: Windows XP (TCP: ~3,000 LOC in tcp/), Linux `net/ipv4/tcp.c` (7,000 LOC),
>             Linux `net/ipv4/tcp_input.c` (7,400 LOC), `net/ipv4/tcp_output.c` (4,100 LOC)
> AstryxOS: `net/tcp.rs`, `net/socket.rs`, `net/unix.rs`, `net/ipv4.rs`, `net/udp.rs`

---

## What We Have

- Ethernet frame parsing + ARP + IPv4 + IPv6 headers
- ICMP echo/reply + ICMPv6 echo/reply
- UDP connect/send/recv (no checksum verify)
- TCP state enum (Closed/Listen/SynSent/SynReceived/Established/FinWait*/CloseWait/LastAck/TimeWait)
- Unix domain sockets (AF_UNIX SOCK_STREAM, connect/accept/read/write)
- DNS A-record + AAAA resolver (UDP-based, iterative)
- DHCP discover/request/renew client
- Socket layer: socket/bind/connect/listen/accept/sendto/recvfrom
- Intel e1000 + virtio-net driver (ring descriptor TX/RX)
- IPv4 routing table (single default gateway)
- Loopback interface (127.0.0.1)

---

## Missing (Critical — Firefox Blocker)

### Full TCP State Machine with Payload Transmission
**What**: TCP in AstryxOS has the state enum but no actual data movement:
- No SYN/SYN-ACK sequence number tracking
- No receive buffer (data is dropped after accept)
- No send buffer (write() returns immediately without queuing)
- No ACK generation for received data
- No FIN exchange (close() doesn't send FIN)

**Why critical**: Every HTTP/HTTPS request Firefox makes is TCP. A TCP that can't move data
is a TCP that can't be used.

**Reference**: `linux/net/ipv4/tcp.c` (`tcp_sendmsg`, `tcp_recvmsg`);
`linux/net/ipv4/tcp_input.c` (`tcp_rcv_state_process`);
`XP/base/ntos/tcpip/tcp/` (tcpconn.c, tcpdata.c, tcpsend.c)

---

### TCP Congestion Control (Slow Start + Congestion Avoidance)
**What**: TCP must not flood the network. RFC 5681 congestion control:
- `cwnd` (congestion window): starts at 1 MSS, doubles each RTT (slow start) until ssthresh
- Congestion avoidance: +1 MSS per RTT after ssthresh
- On loss: ssthresh = cwnd/2, cwnd = 1 MSS (or fast recovery)

**Reference**: `linux/net/ipv4/tcp_cong.c`; `linux/net/ipv4/tcp_cubic.c` (CUBIC)

---

### TCP Retransmission & RTO
**What**: When a segment is not ACKed within RTO (Retransmission Timeout), resend it.
RTO calculation: Karn's algorithm (don't include retransmitted segments in RTT estimate).
Exponential backoff on repeated failure. Fast retransmit on 3 duplicate ACKs.

**Reference**: `linux/net/ipv4/tcp_timer.c` (`tcp_retransmit_timer`);
`linux/net/ipv4/tcp_input.c` (`tcp_fastretrans_alert`)

---

### Socket Options (`setsockopt` / `getsockopt`)
**What**: Firefox and every real application sets socket options before connecting.
Critical missing options:
- `SO_REUSEADDR` — rebind port immediately after close
- `SO_REUSEPORT` — multiple listeners on same port (Chrome multi-process)
- `SO_KEEPALIVE` — detect dead connections
- `TCP_NODELAY` — disable Nagle for interactive connections (used by HTTP/2, WebSocket)
- `TCP_CORK` — batch sends
- `SO_SNDBUF` / `SO_RCVBUF` — adjust buffer sizes
- `IPV6_V6ONLY` — IPv6-only socket mode
- `SO_ERROR` — get async connect error

**Reference**: `linux/net/core/sock.c` (`sock_setsockopt`);
`linux/net/ipv4/tcp.c` (`tcp_setsockopt`)

---

### `sendmsg` / `recvmsg` with Ancillary Data
**What**: `sendmsg()/recvmsg()` pass `struct msghdr` containing scatter-gather iovec arrays
AND ancillary data (`struct cmsghdr`). The critical use case: SCM_RIGHTS to pass file descriptors
over Unix domain sockets (used by Wayland/Weston, D-Bus, systemd socket activation).

**Without this**: D-Bus won't work; any IPC that passes fds is broken.

**Reference**: `linux/net/core/sock.c` (`sock_sendmsg`);
`linux/net/unix/af_unix.c` (`unix_stream_sendmsg`); `cmsg(3)` man page

---

### `poll()` / `select()` / `pselect6()`
**What**: `poll(fds, nfds, timeout)` waits for any of an array of file descriptors to become
readable/writable/exceptional. This is distinct from `epoll` (which is already implemented).
Many apps (Python, Ruby, older C code) use `select()`/`poll()` rather than `epoll()`.

**Without this**: Any app using `select()` or `poll()` will get ENOSYS and fail.

**Reference**: `linux/fs/select.c` (`do_sys_poll`, `core_sys_select`); syscalls 7, 23

---

### `getsockname()` / `getpeername()`
**What**: Return the local/remote address of a connected socket. Chrome / Firefox use these
after connect() to determine which local port was chosen by the OS.

**Reference**: `linux/net/socket.c` (`sys_getsockname`); syscalls 51, 52

---

## Missing (High)

### TCP Window Scaling (RFC 1323)
**What**: The receive window field in TCP headers is 16-bit (max 65,535 bytes). Window scaling
allows up to 1 GiB receive windows by using a multiplier negotiated in the SYN handshake.
Without this, throughput is capped at 65 KB in-flight (RTT-limited).

**Reference**: `linux/net/ipv4/tcp_input.c` (`tcp_parse_options`, `TCP_OPT_WSCALE`)

---

### TCP SACK (Selective ACK, RFC 2018)
**What**: Instead of acknowledging only in-order data, SACK lets the receiver tell the sender
exactly which segments arrived. Avoids re-sending data that was received correctly but out-of-order.

**Reference**: `linux/net/ipv4/tcp_input.c` (`tcp_sacktag_write_queue`)

---

### Multicast (IGMP)
**What**: `setsockopt(IP_ADD_MEMBERSHIP)` to join a multicast group. mDNS (Bonjour, Avahi)
uses 224.0.0.251 for local service discovery. Firefox uses mDNS for LAN service discovery.

**Reference**: `linux/net/ipv4/igmp.c`; `linux/net/ipv4/ip_sockglue.c`

---

### Raw Sockets (`SOCK_RAW`)
**What**: Send/receive raw IP packets with full header control. Required for: ping, traceroute,
custom ICMP handling, network diagnostics.

**Reference**: `linux/net/ipv4/raw.c`

---

### Netlink Sockets (`AF_NETLINK`)
**What**: Kernel-to-userspace communication channel for network configuration.
`ip link`, `ip route`, `ss` (socket statistics) all use netlink. Without it, no standard
network configuration tools will work.

**Reference**: `linux/net/netlink/af_netlink.c`

---

## Missing (Medium)

| Feature | Description | Reference |
|---------|-------------|-----------|
| TCP Nagle algorithm | Batch small writes into one segment | `linux/net/ipv4/tcp_output.c` |
| MTU path discovery | Avoid IP fragmentation | `linux/net/ipv4/route.c` |
| TCP timestamps (RFC 1323) | PAWS, RTT measurement | `linux/net/ipv4/tcp_input.c` |
| IPv6 full stack | DHCPv6, RA, NDP neighbor discovery | `linux/net/ipv6/` |
| SO_LINGER | Block close until data sent | `linux/net/core/sock.c` |
| Blocking connect() | Currently connect() returns immediately | `linux/net/ipv4/tcp.c` |
| Non-blocking I/O (O_NONBLOCK) | EAGAIN on socket ops | `linux/net/socket.c` |
| Network namespaces | Isolated routing per process group | `linux/net/core/net_namespace.c` |

---

## Missing (Low)

| Feature | Description |
|---------|-------------|
| QUIC / HTTP/3 | UDP-based, needed for modern Firefox |
| TLS in-kernel (kTLS) | Offload TLS to NIC |
| eBPF socket filters | Attach BPF programs to sockets |
| TCP Fast Open | 0-RTT connection establishment |
| Multipath TCP | Multiple interfaces per connection |
| SCTP | Stream Control Transmission Protocol |

---

## TCP Implementation Roadmap

The minimum viable TCP for Firefox (HTTP/HTTPS):

```
Phase 1 — Data transfer
  - Send buffer: ring buffer per TCB, write() enqueues bytes
  - Recv buffer: ring buffer per TCB, read() dequeues bytes
  - ACK generation: send cumulative ACK after receiving data
  - PSH/ACK segment sending after write()

Phase 2 — Connection lifecycle
  - Proper ISN: use TSC-based initial sequence number
  - 3WHS completion: track snd_una, snd_nxt, rcv_nxt
  - FIN/FIN-ACK/ACK: close() sends FIN, drives state machine
  - TIME_WAIT: 2*MSL = 120s wait before port reuse

Phase 3 — Reliability
  - Retransmit timer (RTO using RFC 6298 Jacobson/Karels)
  - Retransmit queue: keep sent-unacked segments
  - Fast retransmit on 3 dup ACKs
  - Exponential backoff

Phase 4 — Congestion control
  - Slow start (cwnd doubling)
  - Congestion avoidance (+1 MSS/RTT)
  - ssthresh halving on loss
```

Reference files to read:
- `linux/net/ipv4/tcp.c` lines 1-300 (socket interface)
- `linux/net/ipv4/tcp_output.c` lines 1-200 (segment building)
- `linux/net/ipv4/tcp_input.c` lines 1-200 (ACK processing)
- `XP/base/ntos/tcpip/tcp/tcpsend.c` (simpler, 800 LOC)
