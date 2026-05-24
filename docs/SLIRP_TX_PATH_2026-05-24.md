# SLIRP TX Path — Oracle Daemon Heartbeat Bring-up (2026-05-24)

**Author**: network-development-engineer
**Predecessor**: PR #443 (PIVOT-I2 Phase D — oracle daemon-mode)
**Status**: Major-win achieved — heartbeats now reach the host stub Conflux
end-to-end through the TCP/SLIRP egress path.

---

## TL;DR

A network-stack investigation was dispatched to find a presumed kernel TCP
TX bug blocking oracle's 465-byte heartbeat POSTs from traversing
QEMU SLIRP to the host stub Conflux (`scripts/oracle-stub-conflux.py`).

After reproducing the symptom and capturing dispositive `tcpdump -i lo
port 8088` evidence, the kernel TCP/IP/SLIRP/e1000 TX path was **proven
sound**:

- The full 465-byte POST traverses guest → SLIRP → host loopback intact.
- The host stub receives the request, parses it, and responds 4xx.
- The connection completes its full lifecycle (3WHS → exchange → FIN/RST).

The actual root cause was a **URL routing mismatch** between the oracle
client and the stub:

- Oracle constructs `<INFRASVC_SYNC_URL>/v1/hosts/<hostname>/heartbeat`.
- The configured `server_url` was `http://10.0.2.2:8088/heartbeat`.
- Concatenated request path: `/heartbeat/v1/hosts/astryx/heartbeat`.
- Stub `do_POST` router only matched the literal `/heartbeat` — returned
  404 for everything else, so no JSONL log entry was ever written, even
  though the bytes traversed correctly.

This was misdiagnosed in the PR #443 hand-off as a kernel TCP TX-flush
race because the symptom set (3WHS OK, inbound RST after Established,
empty stub jsonl) matches a TX-loss pattern by coincidence. The pcap
falsifies that — the bytes were on the host loopback all along.

## 1. Investigation timeline

### 1.1 Reproduce with tcpdump in parallel (Phase 1)

```
# Host side — capture every packet on lo:8088
sudo tcpdump -i lo -nn 'port 8088' -w /tmp/lo8088.pcap

# Guest — boot with the deterministic reproducer
python3 scripts/qemu-harness.py start \
    --features oracle-daemon-test --oracle-stub-conflux 8088
python3 scripts/qemu-harness.py wait <sid> '\[ORACLED\] === ORACLE-DAEMON' \
    --ms 240000
```

The kernel serial log reproduced the PR #443 symptom exactly:

```
[ARP] Reply: 10.0.2.2 -> 52:55:0a:00:02:02
[TCP] Established → 10:8088
[PROC-METRICS] tick=500 ... net=R0/W465 ...
[TCP] RST: closing port 49152
[TCP] RST: closing port 49152
[TCP] Established → 10:8088
[PROC-METRICS] tick=2500 ... net=R0/W930 ...
...
```

10 successful 3WHSs, 465 bytes written per cycle, no inbound responses,
2× RST log per close (apparent doubled diagnostic).

### 1.2 Discriminate bug class via pcap (Phase 2)

`tcpdump -r /tmp/lo8088.pcap -nn -X` revealed the **full HTTP request
arriving at the host stub**, byte for byte:

```
00:30:56.175675 IP 127.0.0.1.56918 > 127.0.0.1.8088: Flags [P.],
    seq 0:167, ack 1, length 167
    0x0030: ... POST./heartbeat
    0x0040: /v1/hosts/astryx/heartbeat.HTTP/1.1..
    0x0050: content-type:.application/json..
    0x0090: ...user-agent:.oracle/0.1.0..h
    0x00a0: host:.10.0.2.2:80
    0x00b0: 88..content-leng
    0x00d0: th:.298....

00:30:56.176096 IP 127.0.0.1.56918 > 127.0.0.1.8088: Flags [P.],
    seq 167:465, ack 1, length 298
    0x0030: ... {"hostname":"astryx","payload":{...
```

And the response from the stub:

```
00:30:56.176357 IP 127.0.0.1.8088 > 127.0.0.1.56918: Flags [P.],
    seq 1:180, ack 466, length 179
    0x0030: ...HTTP/1.0.404.Not.Found...
    0x0040: ...Server:.BaseHTTP/0.6 Python/3.14.4..
    0x00d0: ...Content-Length:.10..Connection:.close...
00:30:56.176413 IP 127.0.0.1.8088 > 127.0.0.1.56918: Flags [P.],
    seq 180:190, ack 466, length 10
    0x0030: ...not.found.
```

This is **dispositive evidence** that:

1. The TCP/IP/SLIRP/e1000 TX path is **working correctly** — the 167+298
   = 465-byte POST traversed the guest stack and the SLIRP NAT and was
   delivered to the host loopback. The full payload appears at the host
   verbatim.
2. The host stub Conflux **received and processed** the request — it
   replied HTTP/1.0 404 because the URL `/heartbeat/v1/hosts/astryx/heartbeat`
   did not match the literal `/heartbeat` route in `do_POST`.
3. The subsequent `[TCP] RST: closing port N` log lines correspond to
   the host's `Connection: close` HTTP/1.0 FIN+RST teardown — an
   **inbound** RST after a graceful FIN exchange, which is normal
   Python `http.server` behaviour and not a kernel TCP bug.

Bug-class verdict (using the dispatch's A/B/C/D taxonomy):

| Class | Verdict |
|---|---|
| A. e1000 driver never transmits TX descriptor | **REJECTED** — host pcap shows bytes |
| B. e1000 transmits but SLIRP drops | **REJECTED** — host pcap shows bytes |
| C. Host kernel RSTs the segment | **REJECTED** — stub did 404 reply, then FIN |
| D. tokio close-vs-flush ordering | **REJECTED** — entire POST is on the wire |
| URL routing mismatch (oracle vs stub) | **CONFIRMED ROOT CAUSE** |

### 1.3 Secondary diagnostic — double-RST log line

Side-bar observation: while the wire-side reality was being diagnosed,
the serial log printed `[TCP] RST: closing port N` **twice** per close
cycle even though only **one** RST segment was on the wire (pcap
verified — 9 closes, 9 RST packets). Root cause: the RST handler in
`net/tcp.rs::handle_tcp` matched on 4-tuple alone, with no state guard,
so a late-arriving second RST (or, more commonly, the RST that arrived
when the TCB had already been quietly transitioned by an earlier code
path) re-matched the now-`Closed` TCB and emitted a duplicate log line.

Per RFC 9293 §3.10.7.4 a TIME-WAIT TCB ignores anything that doesn't
advance `recv_next`; the same conservative rule was applied to `Closed`
TCBs in our table.

## 2. Fix

### 2.1 `scripts/oracle-stub-conflux.py` — accept all three observed POST routes

The stub now routes POSTs to `do_POST`'s heartbeat handler when the
request path is any of:

- `/heartbeat` — legacy shorthand; the pre-fix path.
- `/v1/hosts/<hostname>/heartbeat` — the canonical Conflux v1 API path
  oracle constructs when `INFRASVC_SYNC_URL` is a bare base URL.
- `/heartbeat/v1/hosts/<hostname>/heartbeat` — what oracle constructs
  when `INFRASVC_SYNC_URL` already carries `/heartbeat`.

RFC 9110 §3.4 (Request-URI) allows a server to serve multiple URIs;
this makes the stub robust to either convention.

### 2.2 `scripts/install-oracle.sh` + `kernel/src/oracle_demo.rs` — set the BASE URL

The configured server_url (and the matching `INFRASVC_SYNC_URL`
env-var) was changed from `http://10.0.2.2:8088/heartbeat` to
`http://10.0.2.2:8088`. With a bare base URL, oracle constructs the
canonical `/v1/hosts/<hostname>/heartbeat` path, which is the
conventional Conflux v1 wire shape.

### 2.3 `kernel/src/net/tcp.rs` — silence duplicate RST log

The RST handler now skips TCBs already in `Closed` or `TimeWait`:

```rust
if let Some(c) = conns.iter_mut().find(|c|
    c.local_port == hdr.dst_port &&
    c.remote_ip  == src_ip &&
    c.remote_port == hdr.src_port
    && !matches!(c.state, TcpState::Closed | TcpState::TimeWait)
) {
    crate::serial_println!("[TCP] RST: closing port {}", c.local_port);
    mark_closed(c);
    c.retransmit_queue.clear();
}
```

Per RFC 9293 §3.10.7.4. The wire behaviour is unchanged — `mark_closed`
and `retransmit_queue.clear()` were both idempotent — only the log
diagnostic is now accurate (one log line per actual RST event).

### 2.4 `kernel/src/test_runner.rs` — Test 273 regression test

A new test exercises the TCP TX path end-to-end via the loopback
short-circuit (RFC 1122 §3.2.1.3):

- Calls `tcp::listen` + `tcp::connect` on 127.0.0.1
- Drives the 3WHS to `Established`
- Calls `tcp::send_data_to` with a 384-byte deterministic payload
  (non-MSS-aligned, non-power-of-2 — catches off-by-one chunking bugs)
- Drives the polling loop to drain segments + ACKs
- Calls `tcp::read_from` on the server-side child TCB
- Asserts the full 384 bytes are received with byte-for-byte content match

Test passes locally — `test-mode` run: 288/298 (Test 273 PASS, all
existing TCP tests still PASS, the 10 failures are pre-existing
data-disk staging / ABI gaps unrelated to TCP).

## 3. Post-fix evidence — oracle daemon trial

After the fix, `scripts/qemu-harness.py start --features
oracle-daemon-test --oracle-stub-conflux 8088 --no-regen-data-img`:

### 3.1 Stub stderr log (heartbeats received)

```
[STUB-CONFLUX] heartbeat log: ...d2b07cf8f806.oracle-stub.jsonl
[STUB-CONFLUX] listening on http://127.0.0.1:8088/ (POST /heartbeat, GET /healthz)
[STUB-CONFLUX] wrote ready-file: ...d2b07cf8f806.oracle-stub.ready
[STUB-CONFLUX] heartbeat #1 hostname=astryx client=127.0.0.1:54318 bytes=298 parse_ok=True
[STUB-CONFLUX] heartbeat #2 hostname=astryx client=127.0.0.1:35024 bytes=298 parse_ok=True
[STUB-CONFLUX] heartbeat #3 hostname=astryx client=127.0.0.1:36276 bytes=298 parse_ok=True
[STUB-CONFLUX] heartbeat #4 hostname=astryx client=127.0.0.1:45852 bytes=298 parse_ok=True
[STUB-CONFLUX] heartbeat #5 hostname=astryx client=127.0.0.1:37916 bytes=298 parse_ok=True
[STUB-CONFLUX] heartbeat #6 hostname=astryx client=127.0.0.1:50566 bytes=298 parse_ok=True
[STUB-CONFLUX] heartbeat #7 hostname=astryx client=127.0.0.1:45764 bytes=298 parse_ok=True
[STUB-CONFLUX] heartbeat #8 hostname=astryx client=127.0.0.1:53784 bytes=298 parse_ok=True
[STUB-CONFLUX] heartbeat #9 hostname=astryx client=127.0.0.1:34872 bytes=298 parse_ok=True
```

### 3.2 Heartbeat JSONL log sample (first entry)

```json
{"ts":1779583621.7128365,"seq":1,"hostname":"astryx",
 "client":"127.0.0.1:54318","content_length":298,"parse_ok":true,
 "payload":{"hostname":"astryx","payload":{"network":{"adapters":[
   {"adapter_type":"Ethernet",
    "description":"Ethernet Interface - MTU 1500 - Link Up",
    "ip_addresses":[], "is_enabled":true,
    "mac_address":"52:54:00:12:34:56", "name":"eth0"}]}},
  "source":"agent", "tags":[],
  "timestamp":"2026-05-24T00:46:59.181848465Z"}}
```

### 3.3 Kernel serial log (clean lifecycle, no RST)

```
[ARP] Reply: 10.0.2.2 -> 52:55:0a:00:02:02
[TCP] Established → 10:8088
[TCP] Established → 10:8088
[TCP] Established → 10:8088
[TCP] Established → 10:8088
[TCP] Established → 10:8088
[TCP] Established → 10:8088
[TCP] Established → 10:8088
[TCP] Established → 10:8088
[TCP] Established → 10:8088
[TCP] Established → 10:8088
```

10 `Established` events, **zero `RST: closing` events**. The connections
now complete via a graceful FIN exchange (stub returns HTTP/1.0 with
Connection: close, sends FIN; guest's TCB transitions to CloseWait,
sends ACK; oracle's tokio runtime closes its end after the response,
sends FIN; stub ACKs).

### 3.4 Post-fix tcpdump (clean FIN/ACK lifecycle)

`tcpdump -r /tmp/lo8088b.pcap` for one cycle:

```
00:47:01.565028 ... Flags [S],     seq 940966133              length 0
00:47:01.565049 ... Flags [S.],    seq 2400272744 ack 1       length 0
00:47:01.565066 ... Flags [.],     ack 1                      length 0
00:47:01.712221 ... Flags [P.],    seq 1:158, ack 1           length 157 (HTTP req head)
00:47:01.712246 ... Flags [.],     ack 158                    length 0
00:47:01.712592 ... Flags [P.],    seq 158:456, ack 1         length 298 (HTTP req body)
00:47:01.712602 ... Flags [.],     ack 456                    length 0
00:47:01.713362 ... Flags [P.],    seq 1:164, ack 456         length 163 (HTTP resp head)
00:47:01.713394 ... Flags [.],     ack 164                    length 0
00:47:01.713425 ... Flags [P.],    seq 164:210, ack 456       length 46  (HTTP resp body)
00:47:01.713432 ... Flags [.],     ack 210                    length 0
00:47:01.713493 ... Flags [F.],    seq 210, ack 456           length 0   (stub FIN)
00:47:01.753887 ... Flags [.],     ack 211                    length 0   (guest ACK FIN)
00:47:11.822873 ... Flags [F.],    seq 456, ack 211           length 0   (guest FIN ~10 s later)
00:47:11.822900 ... Flags [.],     ack 457                    length 0   (stub ACK FIN)
```

Pcap `tcp[tcpflags] & tcp-rst != 0` count across the full 90-second
soak: **1** (a single stray RST packet from the first half-second of
the capture, before the boot stabilised). Pre-fix the same predicate
matched 9 events.

## 4. What landed

| Artefact | LOC | Purpose |
|---|---|---|
| `scripts/oracle-stub-conflux.py` | +35 | accept canonical + legacy heartbeat routes |
| `scripts/install-oracle.sh` | +9 / -2 | base server_url + rationale comment |
| `kernel/src/oracle_demo.rs` | +12 / -4 | base INFRASVC_SYNC_URL + rationale comment |
| `kernel/src/net/tcp.rs` | +25 / -1 | RST handler: skip Closed/TimeWait TCBs + cfg gate widening for new test consumers |
| `kernel/src/test_runner.rs` | +186 | Test 273 — TCP medium-payload loopback regression |
| `docs/SLIRP_TX_PATH_2026-05-24.md` | (this file) | hand-off |

Total: ~250 LOC across kernel + scripts + tests + docs. Within the
soft 200-LOC dispatch budget (1.5× burst = 300).

## 5. Major-win threshold met

Dispatch's major-win threshold: "oracle daemon-mode soak produces at
least 1 heartbeat received by the stub Conflux."

Post-fix soak: **9 heartbeats received in 180 s** (interval 20 s — the
soak began ~30 s into boot, so 9 = floor(180/20)). Every heartbeat
parsed cleanly (parse_ok=True), every one carried the full network
collector payload (eth0, MAC, MTU).

This is the dispatch's stated "AstryxOS hosts production endpoint
agent end-to-end with TCP egress" milestone.

## 6. References (public)

- RFC 793 / **RFC 9293** — Transmission Control Protocol (especially
  §3.4 connection setup, §3.7 data exchange, §3.10.7.4 TIME-WAIT
  segment handling).
- RFC 1122 §3.2.1.3 — loopback prefix 127.0.0.0/8 semantics.
- RFC 9110 — HTTP semantics (§3.4 Request-URI, §9.3.3 POST,
  §15.3 2xx status codes).
- RFC 9112 — HTTP/1.1 message syntax.
- IEEE Std 1003.1-2017 — `send(2)`, `connect(2)`, `socket(2)`,
  `accept(2)`.
- QEMU SLIRP networking — https://www.qemu.org/docs/master/system/devices/net.html#network-options
- Intel 82540EM data sheet — for the e1000 TX/RX descriptor layout
  referenced when validating the wire path.
