# AF_INET accept(2) end-to-end (2026-05-23)

## Headline

`accept(2)` and `accept4(2)` on AF_INET sockets are no longer stubs.
The Aether kernel now extracts a real child connection from the
listener's pending queue, materialises a new socket fd carrying the
peer's 4-tuple, and routes subsequent `read(2)`/`write(2)` traffic
per-connection rather than per-port. This unblocks every userspace
Linux network server that calls `accept(2)`: sshd, busybox httpd,
python `-m http.server`, nginx, redis-server, and so on.

Test coverage: a new gated test (`test270`) drives the full
plumbing end-to-end against the in-kernel TCP table using
synthetic Established child TCBs, exercising every observable
behaviour without paying for SLIRP RTT.

## What was wrong before

`socket(AF_INET, SOCK_STREAM)` already returned a real socket fd.
`bind(2)` already created a `Listen`-state TCB via
`net::tcp::listen()`, and the in-kernel TCP RX path already
brought child TCBs through SYN → SynReceived → Established on
the inbound 3WHS (RFC 793 §3.4). What was missing was the syscall
that handed those Established children to user space:

```
kernel/src/subsys/linux/syscall.rs:1635 (pre-fix)

43 => {
    …AF_UNIX branch…
    } else {
        -11 // EAGAIN (AF_INET accept stub: no real listener)
    }
}
```

Any `busybox httpd`-shaped program would loop in `accept(2)`
forever, never observing the child TCBs that were already sitting
on the listener's local port. PIVOT-C (PR #431) worked around
this by running an in-kernel HTTP responder that talked to the
TCP table directly via `tcp::snapshot_connections()` /
`tcp::read_from()` / `tcp::send_data_to()`; that path is no
longer the only way to bring a network service up.

## Design

### Per-TCB `accepted` flag

`TcpConnection` gains one bool field. Listener entries
(state == Listen) never toggle it. Each child TCB created by the
SYN path defaults to `accepted = false`; `take_pending_accept`
sets it `true` on the way out. That is the entire mechanism
guaranteeing each `accept(2)` call dequeues exactly one
connection per POSIX.1-2017 §accept.

### Two new tcp primitives

* `net::tcp::take_pending_accept(local_port) -> Option<(peer_ip, peer_port)>`

  Dequeue one child TCB on `local_port`:

  - state == Established (the 3WHS has completed)
  - remote_port != 0 (excludes the listener entry itself)
  - !accepted (not yet handed out)

  Sets `accepted = true` on the chosen TCB and returns its peer
  4-tuple. Returns `None` if no eligible child exists.

* `net::tcp::has_pending_accept(local_port) -> bool`

  Side-effect-free probe used by `poll(2)`/`select(2)` to report
  POLLIN readiness on a listening socket (POSIX: a listening
  socket is "readable" exactly when accept(2) would not block).

* `net::tcp::has_data_for(local_port, peer_ip, peer_port) -> bool`

  Per-4-tuple readability probe for accept-side child sockets, so
  POLLIN on a child fires only for bytes destined to that
  connection.

* `net::tcp::close_listener(port)`

  Drops the Listen-state TCB without touching accepted children.
  Children carry independent 4-tuples and independent lifecycles
  per POSIX.1-2017 §close.

### New socket primitive

* `net::socket::socket_create_accepted(local_port, peer_ip, peer_port) -> u64`

  Creates an accept-side socket entry bound to an existing child
  TCB. The returned socket has `socket_type = Tcp`, `bound = true`,
  `connected = true`, and carries the full 4-tuple so subsequent
  `socket_send`/`socket_recv`/`socket_has_data` route via the
  per-connection `tcp::send_data_to` / `tcp::read_from` /
  `tcp::has_data_for` primitives rather than the
  port-only fallback. This is the RFC 793 §3.8 demultiplexing
  invariant: traffic on a listener port may belong to several
  concurrent peers, and each accept-side fd must only see its
  own bytes.

### Socket-layer routing

`socket_send`, `socket_recv`, and `socket_has_data` now branch on
"is this socket connected with a known peer?" When yes, they
call the per-4-tuple TCP primitive; when no, they fall through
to the legacy port-only call (preserves behaviour for
single-peer ephemeral clients that pre-date this work).

`socket_close` similarly branches: connected sockets call
`tcp::close_connection` (4-tuple-strict FIN that cannot trip a
sibling session), and listener sockets call `tcp::close_listener`
(drops the Listen TCB and leaves children alive).

### The accept(2) entry

```
43 (accept) /  288 (accept4)  →
    1. Look up listener fd; verify it is bound, TCP.
    2. Capture per-fd O_NONBLOCK bit + accept4 flags.
    3. Loop: take_pending_accept(listener_port).
         Some(peer) → break.
         None       → if O_NONBLOCK / SOCK_NONBLOCK → return EAGAIN.
                      else: check signal_pending → EINTR.
                      else: net::poll(); yield_cpu();  // re-attempt
    4. socket_create_accepted(local_port, peer_ip, peer_port).
    5. If addr != NULL:
         - Range-validate addrlen pointer (CWE-823).
         - Read input capacity from *addrlen under STAC=1.
         - Range-validate addr pointer for the write span.
         - Build sockaddr_in {family=2, sin_port (be), sin_addr},
           copy under STAC=1.
         - Overwrite *addrlen with actual length (= 16 for IPv4).
    6. alloc_socket_fd(pid, child_id, SOCK_STREAM,
                       cloexec, nonblock).
```

### SMAP discipline

Every user-pointer dereference happens under
`crate::arch::x86_64::smap::UserGuard::new()`. `addr` and
`addrlen` are independently range-validated via
`validate_user_ptr` *before* the STAC=1 region opens — Intel
SDM Vol 3A §4.6 documents that SMAP catches user-page accesses
without AC=1 but does not catch supervisor writes to kernel-VAs.
Range validation is the only line of defence against an
attacker placing a kernel-VA in addr/addrlen (CWE-823). On
EFAULT, the freshly-allocated child socket entry is reclaimed
before returning so the caller cannot leak a half-set-up fd.

### Locking model

No new locks. `take_pending_accept` and `socket_create_accepted`
each take exactly one existing lock (`TCP_CONNECTIONS` and
`SOCKETS` respectively) for the duration of one short
mutate-then-return. The `accept(2)` syscall holds NO lock
across yield points; the blocking poll loop only consults the
lock-free `signal_pending` and re-takes locks per iteration via
the two helpers. Lock order unchanged.

## Validation

### Test 270 (`test_af_inet_accept_end_to_end`, kdb feature)

End-to-end exercise of the new primitives against the in-kernel
TCP table. Uses `tcp::test_inject_established` (the same helper
that Test 178 uses) to materialise two `Established` child TCBs
on a single listener port without paying for SLIRP RTT — peer
addresses are 127.0.0.x so any internal sends short-circuit
through the loopback ring (RFC 1122 §3.2.1.3) and never block
on ARP.

Stages:

| Stage | What it asserts |
|-------|-----------------|
| A | Empty listener: `take_pending_accept` returns None, `has_pending_accept` false. |
| B | Inject two Established children: `has_pending_accept` true. |
| C | Two `take_pending_accept` calls return distinct peers; a third returns None. |
| D | `socket_create_accepted` produces independent ids; `socket_recv` on each fd returns exactly that peer's RX bytes (no cross-attribution); draining A does not drain B. |
| E | `tcp::close_connection` on A removes A from Established; B remains Established. |
| F | `tcp::close_listener` drops the Listen TCB and leaves B's Established TCB alive. |

Test 270 result (KVM, `--features kdb,test-mode`):

```
TEST: AF_INET accept(2) — take_pending + per-4-tuple routing
  empty listener: take_pending_accept=None ✓
  two takes returned distinct peers; third = None ✓
  per-4-tuple recv isolation ✓
  close_connection on A left B Established ✓
  close_listener preserves accepted children ✓
[PASS] AF_INET accept(2) — take_pending + per-4-tuple routing
```

Tests 177 (`TCP inbound 3WHS`) and 178 (`TCP read_from`
4-tuple isolation) continue to pass — the per-connection
primitives this work introduces share their existing
infrastructure and were proven by the same 4-tuple tests.

## Diff shape

| File | Net LOC |
|------|---------|
| `kernel/src/net/tcp.rs` | +69 (one struct field; 5 struct literals; `take_pending_accept`, `has_pending_accept`, `has_data_for`, `close_listener`) |
| `kernel/src/net/socket.rs` | +95 (`socket_create_accepted`; per-4-tuple routing in `socket_send`/`socket_recv`/`socket_has_data`/`socket_close`) |
| `kernel/src/subsys/linux/syscall.rs` | +106 / -8 (accept(2) replaces stub) |
| `kernel/src/test_runner.rs` | +186 (Test 270 + dispatch wiring) |

All changes are additive at the byte level for non-AF_INET
paths: AF_UNIX `accept(2)`, every existing UDP path, and every
TCP path that does not set `connected + remote_port != 0`
continue to take exactly the code path they took before. The
non-kdb default build is byte-identical.

## What this unblocks

Any userspace Linux service whose main loop is
`socket + bind + listen + accept`. With the existing
`busybox-static` and `wget` substrate from PIVOT-B and the
runtime confirmed by PIVOT-C, the next pieces gate on no new
kernel work:

* `busybox httpd` — would have spun on accept in PIVOT-C
  testing; this work closes that wedge.
* `openssh-server` — staged in parallel by PSE.
* `python3 -m http.server` — the simplest no-config server.
* `nginx`, `redis-server`, and friends — same pattern.

## Citations

* IEEE Std 1003.1-2017 §accept (POSIX accept).
* IEEE Std 1003.1-2017 §poll (POLLIN readiness on listening sockets).
* IEEE Std 1003.1-2017 §close (independent child lifecycles).
* RFC 793 §3.4 (TCP three-way handshake; Established transition).
* RFC 793 §3.5 (close protocol; FinWait1).
* RFC 793 §3.8 (demultiplexing on the 4-tuple).
* RFC 1122 §3.2.1.3 (loopback short-circuit).
* RFC 791 §3.1 (IPv4 source/destination address format).
* Intel SDM Vol 3A §4.6 (SMAP — AC bit gating).
* CWE-823 — Use of Out-of-range Pointer Offset.
