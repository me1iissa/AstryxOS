# Oracle Endpoint Agent (infrasvc) — AstryxOS Hosting Audit

**Date**: 2026-05-23
**Author**: principal-systems-engineer (dispatched, read-only scoping)
**Status**: Roadmap proposal — no kernel changes in this PR
**Repo of agent**: `infrastructure-services/infrasvc` (internal GitLab)

---

## TL;DR

- Oracle is a Rust async observability agent (`oracle` binary, ships `.deb`/`.rpm`,
  driven by systemd) that polls `/sys`, `/proc`, DMI, file integrity, and process
  chains on the host, then ships heartbeats over a persistent
  WebSocket-over-TLS to the Conflux server in the Sentinel family.
- **The dependency graph reduces to four blocking subsystems**: TLS substrate,
  tokio runtime requirements (mostly already present), procfs/sysfs surface
  expansion (mostly already present), and systemd-unit lifecycle honoring.
- **Recommended path**: host the production Linux binary via the Linux
  subsystem (Alpine musl track). Avoid Aether-native port.
- **Recommended first phase**: **I1 — TLS substrate** (~1500–3000 LOC, mostly
  staging + ABI plumbing). It is the largest single unblock because it is
  shared with `curl`, `wget`, `sshd`-on-public-net, and the cloud-init
  metadata-service paths (C2/C3).
- A "minimum viable demo" path exists that defers I1: a plain-TCP dev mode
  against a custom Conflux dev-server. Documented in §7.

---

## 1. What oracle is and what it observes

### 1.1 Three binaries

Per `infrasvc:Cargo.toml`:

| Binary | Path | Purpose |
|---|---|---|
| `oracle` | `src/main.rs` | Main agent. Heartbeats over WS to Conflux. |
| `conflux-session-recorder` | `src/bin/conflux_session_recorder.rs` | sshd `ForceCommand` wrapper; runs `script(1)`; writes ed25519-signed manifest. |
| `conflux-session-recording-installer` | `src/bin/conflux_session_recording_installer.rs` | Postinst helper: creates `recorded-sessions` group + sshd drop-in. |

Packaging: `oracle_<version>_amd64.deb` (cargo-deb) + RPM equivalent. systemd
notify-type service, watchdog 120 s, `Type=notify`,
`Restart=on-failure`, `ProtectSystem=false`, `ProtectHome=true`,
`NoNewPrivileges=true`. See `infrasvc:deploy/oracle.service`.

### 1.2 What `oracle` does in steady state

Per `infrasvc:src/main.rs` and `infrasvc:src/sync/ws_client.rs`:

1. Parses CLI (`clap`), loads `/etc/oracle/config.toml`, starts a `tokio`
   multi-thread runtime.
2. Brings up a `WebSocketStream<TlsStream<TcpStream>>` to
   `wss://conflux.inside.hyperlxc.co.uk` via `tokio-tungstenite` + `native-tls`.
3. Sends `Identify { protocol_version=2, hostname, instance_id, agent_version }`.
4. On `IdentifyAck`, spawns a heartbeat-emitter task; main loop reads frames
   (`Command`, `EnterLiveMode`, `Ping`, `HeartbeatAck`).
5. Per-collector tokio tasks poll on cadences from `infrasvc:deploy/oracle.toml`:
   - `network` (60 s) — walks `/sys/class/net/*`, reads `operstate`, `address`,
     `type`, `mtu`, `carrier`, plus `ip` shell-out for routes/addresses
     (per `infrasvc:src/linux/network/interface_reader.rs`).
   - `system` (300 s) — `gethostname`, `uname`, `/etc/os-release`,
     `/proc/uptime`, `/proc/loadavg`, `/proc/meminfo`.
   - `hardware` (3600 s) — DMI/SMBIOS via `/sys/class/dmi/id/*`, CPU info via
     `/proc/cpuinfo`.
   - `process` (120 s) — walks `/proc/[pid]/{cmdline,stat,status,comm,exe}`,
     applies `regex`-based process-chain rules.
   - `security` (600 s) — file-integrity SHA-256 over a curated watchlist
     (`/etc/sshd_config`, `/etc/sudoers`, `/etc/passwd`, `/etc/group`,
     `/etc/shadow`, `/etc/pam.d/`, `~root/.ssh/authorized_keys`).
6. Optional collectors (default off): EDR-lite `audit_stream` (tails
   `/var/log/audit/audit.log`), compliance-as-code (sysctl/ufw/dpkg state),
   user-management (sudo grant/revoke), patching (apt/dnf), session-recording
   ed25519 manifest signing.

### 1.3 Wire protocol summary

- `tokio-tungstenite` 0.24 with `native-tls` feature → links `libssl.so.3` /
  `libcrypto.so.3` via the `native-tls` crate (which wraps OpenSSL on Linux).
- WS protocol version `2`. Frames are JSON. Reconnect with exponential backoff
  (1 s → 60 s cap).
- `reqwest` 0.12 with `json`+`native-tls`+`multipart`+`stream` is used for the
  fallback `/v1/hosts/:name/heartbeat` HTTP POST and for streaming command
  output. Same OpenSSL link path as tungstenite.

---

## 2. Cargo.toml dep → AstryxOS state gap matrix

Each dep mapped to its support state. "Works" means the AstryxOS kernel +
staged libraries already host the dep's runtime needs.

| Dep | Runtime ABI need | AstryxOS state | LOC to host |
|---|---|---|---|
| `tokio = "1"` (full) | epoll, eventfd, signalfd, timerfd, pipe2(O_CLOEXEC\|O_NONBLOCK), pthread, futex, clock_gettime | **Works** — epoll_create1, epoll_wait, epoll_ctl, epoll_pwait, eventfd2, signalfd already plumbed in `kernel/src/subsys/linux/syscall.rs` (sc 232/233/281/291). timerfd is partial (PR coverage exists). | ~0 |
| `tokio-tungstenite = "0.24"` (connect+native-tls) | TLS handshake via OpenSSL libssl.so.3, plus TCP connect, getaddrinfo, getsockopt(SO_ERROR) | **Partial** — `libssl.so.3` + `libcrypto.so.3` are *staged in build/disk/lib* but ca-certificates bundle is NOT (the `etc/ssl/certs` dir is empty per scan). TCP outbound works (PR #431). `getaddrinfo` via musl libc works for IP literals; DNS path depends on `/etc/resolv.conf` + UDP socket support. | ~500 (ca-bundle + resolv.conf wiring) |
| `reqwest = "0.12"` (json, native-tls, multipart, stream) | Same TLS path as tungstenite + HTTP/1.1 framing in-crate (`hyper`) | **Partial** — depends on TLS being live. Otherwise pure-Rust. | shared with tungstenite |
| `serde = "1"` | None (pure Rust) | **Works** | 0 |
| `serde_json = "1"` | None | **Works** | 0 |
| `clap = "4"` | argv read, environ, `isatty(fileno(stdin))` for help formatting | **Works** | 0 |
| `chrono = "0.4"` | `clock_gettime(CLOCK_REALTIME)`, `localtime_r` via libc tzdata | **Works** — sc 228 + vDSO path. `localtime_r` needs `/usr/share/zoneinfo/UTC` at minimum (currently unstaged — small fix). | ~5 (stage tzdata-utc) |
| `gethostname = "0.5"` | `gethostname(2)` (libc shim over `uname.nodename`) | **Works** — uname is plumbed (PR #320). | 0 |
| `uuid = "1"` (v4, v7) | `getrandom(2)` flags=0 (v4) + `clock_gettime` (v7 timestamp) | **Works** — getrandom plumbed (sc 318, AT_RANDOM entropy PR #309). | 0 |
| `sha2 = "0.10"` | None (pure Rust) | **Works** | 0 |
| `hex = "0.4"` | None | **Works** | 0 |
| `regex = "1"` | None | **Works** | 0 |
| `ed25519-dalek = "2"` | `getrandom(2)` for key generation; verify is pure-Rust | **Works** (no OpenSSL link) | 0 |
| `rand = "0.8"` | `getrandom(2)` (via `getrandom` crate) | **Works** | 0 |
| `thiserror = "1"` | None | **Works** | 0 |

### 2.1 Implicit syscall surface (oracle runtime)

Pulled from `tokio = "1"` full feature, observed Rust async patterns, and
`infrasvc:src/linux/*/`:

| Syscall | AstryxOS support |
|---|---|
| `read`, `write`, `readv`, `writev`, `pread64`, `pwrite64` | Works |
| `open`, `openat`, `close`, `dup`, `dup2`, `dup3`, `fcntl(F_SETFD/F_SETFL)` | Works |
| `pipe2(O_NONBLOCK\|O_CLOEXEC)` | Works (sc 293) |
| `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` | Works |
| `eventfd2(0, EFD_NONBLOCK\|EFD_CLOEXEC)` | Works |
| `signalfd4` | Works |
| `timerfd_create`, `timerfd_settime`, `timerfd_gettime` | Partial — verify on Alpine musl build |
| `socket(AF_INET, SOCK_STREAM\|SOCK_NONBLOCK\|SOCK_CLOEXEC, 0)` | Works |
| `connect`, `getsockopt(SO_ERROR)`, `setsockopt(SO_REUSEADDR, TCP_NODELAY)` | Works (PR #431 proven outbound) |
| `getaddrinfo` (via musl) | IP-literal works; DNS path needs UDP socket + `/etc/resolv.conf` |
| `clone3` + `CLONE_VM\|CLONE_THREAD\|CLONE_SIGHAND` (tokio worker threads) | Works (PR #298 musl ABI fixes) |
| `futex(FUTEX_WAIT, FUTEX_WAKE, FUTEX_REQUEUE)` | Works (post-FUTEX_WAKE_GHOST closure) |
| `clock_gettime(CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_BOOTTIME)` | Works (CLOCK_BOOTTIME may need verify) |
| `sched_getaffinity`, `sched_yield` | Works |
| `mmap(MAP_ANONYMOUS\|MAP_PRIVATE)`, `mprotect`, `munmap` | Works |
| `set_robust_list`, `set_tid_address` | Works |
| `rseq` | Stub-returns-0 — fine for tokio (graceful fallback path) |
| `getrandom(GRND_NONBLOCK)` | Works |
| `prctl(PR_SET_NAME, PR_SET_PDEATHSIG)` | Works |
| `prlimit64(RLIMIT_NOFILE, RLIMIT_STACK)` | Verify — likely partial |
| `getpid`, `gettid`, `getuid`, `geteuid`, `getgid`, `getegid` | Works |
| `sigaltstack`, `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn` | Works |
| `exit_group` | Works |
| `nanosleep`, `clock_nanosleep` | Works |
| `sendto`, `recvfrom`, `recvmsg`, `sendmsg` (for UDP DNS) | Works |
| `sysinfo` | Works (PR #320) |
| `getdents64` (procfs walk) | Works |
| `readlink`/`readlinkat` (`/proc/self/exe`, `/proc/[pid]/exe`) | Verify on Alpine musl build |

**Not needed at this scope**: AF_NETLINK (oracle uses `/sys/class/net` reads
not netlink), inotify (file-integrity is poll-based not watch-based),
io_uring, perf_event_open, BPF, capset/capget, keyctl, mount, swapon.

### 2.2 Filesystem surface gap

Oracle reads, from `infrasvc:src/linux/`:

| Path | AstryxOS coverage | Gap |
|---|---|---|
| `/sys/class/net/<iface>/{operstate,address,type,mtu,carrier,flags,statistics/*}` | **Missing** — only `/sys/devices/system/cpu/` is implemented in `kernel/src/vfs/sysfs.rs`. | Need a `/sys/class/net/` shim backed by `kernel/src/net/` device-table enumeration. ~150 LOC. |
| `/sys/class/dmi/id/{sys_vendor,product_name,bios_version,...}` | **Missing** | Synthesise from kernel DMI/SMBIOS readback (already done internally for some banner paths). ~80 LOC. |
| `/proc/cpuinfo`, `/proc/meminfo`, `/proc/version`, `/proc/uptime`, `/proc/loadavg` | Works | 0 |
| `/proc/self/{maps,status,stat,auxv,environ,cmdline,exe,fd/}` | Works | 0 |
| `/proc/[pid]/{cmdline,stat,status,comm,exe}` | Works (via `/proc/<N>` → `/proc/self` redirect for own PID; cross-PID needs per-PID dir walk — verify) | Possibly ~50 LOC if cross-PID procfs is not fully fleshed out for non-self PIDs. |
| `/proc/[pid]/oom_score`, `/proc/[pid]/io`, `/proc/[pid]/smaps` | **Missing** | Stub with zero-content files or implement; oracle doesn't hard-require these. ~30 LOC if stubbed. |
| `/etc/os-release`, `/etc/passwd`, `/etc/group`, `/etc/sshd_config`, `/etc/sudoers`, `/etc/pam.d/*` | Works (regular files on disk image; need to be staged). | Stage during disk image build. |
| `/var/log/audit/audit.log` | **Missing** (auditd not present) | EDR-lite `audit_stream` collector defaults off; not a blocker. |
| `/var/lib/oracle/`, `/var/log/oracle/` | Works (writable mounts). | Ensure directories created at boot — Ascension init script. |
| `/etc/oracle/config.toml` | Works (regular file). | Stage during build. |
| `/etc/resolv.conf` | Works (regular file). | Stage with a single resolver IP (e.g. `nameserver 10.0.2.3` for QEMU SLIRP). |
| `/etc/ssl/certs/ca-certificates.crt` | **Missing — TLS BLOCKER** | Stage from Alpine `ca-certificates` package. ~200 KB. |

### 2.3 External shell-outs

Oracle's `infrasvc:src/linux/network/collector.rs` runs `ip -j addr` /
`ip -j route` for addresses + routes (per the legacy README's "uses
/sys/class/net and ip commands"). **AstryxOS gap**: BusyBox provides `ip` but
its `-j` (JSON) flag does not exist on the BusyBox build (`ip` from
`iproute2` is the de-facto). Either stage `iproute2`'s `ip` (small static
binary, ~500 KB) or patch oracle to fall back to parsing `ip` text output
(upstream-side change, not in scope of this audit).

---

## 3. Linux subsystem vs Aether-native vs hybrid

### 3.1 Linux subsystem (recommended)

**Run the as-shipped Alpine-musl-compiled `oracle` binary on the Linux
subsystem.**

- **Pros**:
  - Zero porting work. Validates the production binary against the
    AstryxOS Linux compat surface — high-value coverage exercise.
  - Stays in lockstep with upstream — every infrasvc release just gets a
    fresh staging copy into `build/disk/usr/local/bin/oracle`. Versioning
    discipline (semver per `infrasvc:README.md` §"Versioning and releases")
    is preserved end-to-end.
  - Shares the TLS substrate with `curl`, `wget`, `sshd` public-key crypto,
    cloud-init metadata fetch — leverage is high.
  - Linux subsystem has had the heaviest investment (PR #270 W215, #298
    musl ABI, #305 musl FF gates, sc 1976+). Adding oracle exercises the
    Rust/tokio side rather than libxul's C++/JS side, which is a different
    failure surface — useful diversification.
- **Cons**:
  - TLS substrate is the heaviest single piece (~1500–3000 LOC including
    syscall backfills and ca-cert staging). This is shared cost (§4.I1),
    not oracle-specific.
  - systemd-unit semantics need partial honoring. `Type=notify` requires
    `sd_notify(3)` over `$NOTIFY_SOCKET` (AF_UNIX SOCK_DGRAM). `WatchdogSec`
    needs `sd_notify("WATCHDOG=1")` ack within the deadline. Currently
    Ascension doesn't speak `sd_notify`. ~200 LOC to implement a minimal
    systemd-equivalent in Ascension (oracle's `Type=notify` is satisfiable
    by recognising `READY=1` and `WATCHDOG=1` only — no need for the full
    systemd protocol).
  - Process namespaces (`ProtectSystem`, `ReadWritePaths`) are unenforceable
    on AstryxOS today — but `oracle.service` uses `ProtectSystem=false`,
    so it's permissive.

### 3.2 Aether-native (not recommended)

Port oracle to a native Aether crate that uses kernel-internal interfaces
directly.

- **Pros**:
  - No Linux compat overhead. Direct access to `kernel::net::` for interface
    enumeration. Cleaner debugging — kernel-side panics surface in serial.
  - Could be smaller binary (no tokio runtime, no libssl).
- **Cons**:
  - **Maintenance fork forever**. Upstream infrasvc moves; Aether port lags.
    Every Conflux wire-protocol bump (per `infrasvc:README.md` pre-1.0
    caveat) requires a coordinated Aether-port edit.
  - **Loses production credibility**. The pitch of running infrasvc on
    AstryxOS is that the *same* binary deploys to fleet machines. Native
    port is a different program with the same name.
  - **Need Aether-side TLS, WebSocket, HTTPS client**. These are large.
    `rustls` (pure-Rust TLS) is the obvious pick but pulling it into
    `no_std` Aether is non-trivial; it depends on `ring` which has C and
    assembly. `tokio-tungstenite` is async-runtime-bound; you'd be
    rewriting it on top of Aether's async substrate (which doesn't exist
    today; Ascension is sync).
  - **Verdict: only pursue if the Linux subsystem path proves intractable.**
    It hasn't — every gap below is bounded.

### 3.3 Hybrid (defer; revisit if I3 is heavy)

Run `oracle` as a Linux-subsystem binary, but back specific reads (e.g.
`/sys/class/net/*`) with a thin native shim instead of synthesising static
file content.

- **Pros**: tighter integration where the procfs/sysfs surface is
  expensive to fake (e.g. live interface counters that update per packet).
- **Cons**: API stability burden — the shim's "file content shape" is now
  an ABI between oracle (upstream) and the kernel (AstryxOS).
- **When to take it**: only if I3 (polling collectors) reveals that
  synthesising plausible `/sys/class/net/<iface>/statistics/rx_bytes`
  content needs more in-kernel hooks than building the procfs path directly.

---

## 4. Phased roadmap (Linux subsystem path)

LOC estimates are **net new kernel + userspace + staging code**. Stages are
defined to be **independently demonstrable**: each one ends with a measurable
oracle-side milestone.

### I1 — TLS substrate (~1500–3000 LOC, ~2–3 weeks)

**Goal**: `curl https://example.com` and `oracle --once --collector network`
both succeed end-to-end with TLS up.

Components:

1. **Stage ca-certificates** from Alpine's `ca-certificates` package into
   `build/disk/etc/ssl/certs/ca-certificates.crt` (single bundle, OpenSSL
   format). ~10 LOC of disk-image build script.
2. **Stage `/etc/resolv.conf`** with a working resolver (QEMU SLIRP gives
   `10.0.2.3`; bare-metal targets the local DHCP-issued resolver). ~5 LOC.
3. **Verify `libssl.so.3` + `libcrypto.so.3` work end-to-end on AstryxOS**
   — they're staged but not soak-validated. The first call will exercise:
   - `getrandom(GRND_NONBLOCK)` repeatedly (already works).
   - `clock_gettime(CLOCK_REALTIME)` for cert validity (works).
   - `clock_gettime(CLOCK_MONOTONIC)` for OpenSSL's internal pseudo-RNG
     entropy gathering (works).
   - File reads against `/etc/ssl/openssl.cnf`, the ca-bundle, optionally
     `/dev/urandom` (verify staged; if missing add to `kernel/src/vfs/` —
     ~30 LOC for a `/dev/urandom` that wraps `getrandom`).
   - `mmap(MAP_PRIVATE)` of the ca-bundle (works).
4. **Syscall backfills** likely surfaced by OpenSSL + reqwest:
   - `prlimit64(RLIMIT_NOFILE)` get path (verify; ~20 LOC if absent).
   - `socketpair(AF_UNIX, SOCK_STREAM, 0)` (verify).
   - `recvmmsg`, `sendmmsg` (used by some hyper paths; ~50 LOC each if
     absent — fall back to recvmsg/sendmsg loop).
   - `fadvise64` (no-op acceptable; ~10 LOC).
5. **DNS resolution** if not literal-IP: oracle reads `/etc/resolv.conf` via
   musl; musl does UDP→TCP fallback against the resolver. Need UDP socket
   send/recv to work for resolver IPs (verify on current build; net
   subsystem has UDP per `kernel/src/net/udp.rs`).
6. **TLS smoke test** — add a userspace test binary `userspace/curl_tls/`
   (or just stage `curl` from Alpine) that fetches `https://example.com`.
   This is the demo gate for I1.

**Why I1 first**: it unblocks `curl`, `wget`, `sshd`-on-public-net,
cloud-init metadata-service (the C2/C3 cloud-init dispatch the user
mentioned), AND oracle. Highest leverage per LOC.

**Risk**: OpenSSL is a complex link target. If `libssl.so.3` doesn't
initialise cleanly under AstryxOS musl, the fallback is `rustls` — but
`rustls` does not directly help oracle because oracle's `native-tls`
feature on Linux specifically wraps OpenSSL. Patching upstream oracle to
use `rustls-tls` instead is a one-line change (`features = ["rustls-tls"]`)
that AstryxOS could carry as a build flag override. Document this as the
fallback.

### I2 — Tokio runtime + sd_notify (~300 LOC, ~3–5 days)

**Goal**: `oracle --mode service` starts, sends `sd_notify(READY=1)`,
runs heartbeat loop without TLS (falls back to HTTP `/v1/.../heartbeat` if
TLS disabled in config — except oracle 0.8.x always uses WS… so this stage
is gated on either I1 or a custom dev Conflux that speaks plain TCP — see §7).

Components:

1. **`sd_notify` substrate in Ascension**: open `AF_UNIX` `SOCK_DGRAM` on
   `$NOTIFY_SOCKET`, recv loop, recognise `READY=1`, `WATCHDOG=1`,
   `STATUS=...`, `STOPPING=1`. Ignore unknown keys. ~100 LOC in
   `userspace/ascension/src/systemd_notify.rs`.
2. **Watchdog implementation**: if a unit declares `WatchdogSec=N`, Ascension
   expects `WATCHDOG=1` every N/2 seconds, SIGKILLs on miss. ~50 LOC.
3. **Verify tokio multi-thread runtime**: tokio spawns N worker threads via
   `clone3`. PR #298 closed the musl R9 clone clobber; verify under a
   2-worker oracle that no GP/fault fires. If something does, narrow to
   the worker bring-up path.
4. **`prctl(PR_SET_NAME)`** for tokio's worker thread naming. Already works
   per syscall.rs scan; verify thread-name shows up in `/proc/[pid]/comm`.

### I3 — Polling collectors substrate (~600 LOC, ~1 week)

**Goal**: `oracle --once --collector network` and `oracle --once --collector
system` print sensible JSON to stdout (no Conflux connection needed).

Components:

1. **`/sys/class/net/` shim** in `kernel/src/vfs/sysfs.rs`. Enumerate from
   `kernel/src/net/` device table. Per-iface files:
   - `operstate` → `"up\n"` or `"down\n"`
   - `address` → MAC as `xx:xx:xx:xx:xx:xx`
   - `type` → `"1\n"` (ARPHRD_ETHER) — per RFC 1700 + `if_arp.h`
   - `mtu` → decimal
   - `carrier` → `"1\n"` / `"0\n"`
   - `flags` → hex (IFF_UP=0x1, IFF_BROADCAST=0x2, IFF_RUNNING=0x40, etc.)
   - `statistics/{rx,tx}_{bytes,packets,dropped,errors}` → decimal counters
     synthesised from `kernel::net::` per-device counters (~80 LOC).
   ~150 LOC total for the sysfs walker + per-file generators.
2. **`/sys/class/dmi/id/` shim** in `kernel/src/vfs/sysfs.rs`. Fields:
   `sys_vendor`, `product_name`, `bios_version`, `bios_date`,
   `board_vendor`, `board_name`, `chassis_type`. Source: SMBIOS table
   parser (need to verify the kernel already reads SMBIOS at boot; if not,
   ~100 LOC for a minimal SMBIOS parser per DMTF DSP0134). ~80 LOC for
   the sysfs surface.
3. **`/proc/[pid]/oom_score`, `/proc/[pid]/io`** — stub with synthesised
   zero values (oracle's process collector doesn't error on these; verify
   in `infrasvc:src/linux/process/collector.rs`). ~30 LOC.
4. **Cross-PID procfs walk** — verify `/proc/<N>/cmdline` works for `N` other
   than self. The codebase has `proc_target_pid()` redirect logic; needs
   coverage check. If broken, ~50 LOC fix.
5. **Stage Alpine `iproute2`** package (`ip` binary, ~500 KB) OR rely on
   BusyBox `ip` (no `-j`/JSON, parse text). Easier path: stage iproute2.
   Trade ~500 KB disk for clean JSON. ~5 LOC disk script.

### I4 — Service lifecycle + integration smoke (~200 LOC, ~3 days)

**Goal**: `oracle --mode service` runs for 10 minutes under Ascension's
systemd-equivalent, sends 6 heartbeats, exits cleanly on SIGTERM.

Components:

1. **systemd unit honoring in Ascension**: parse `oracle.service` (a small
   `[Service]` section subset: `ExecStart`, `ExecStartPre`, `Type=notify`,
   `Restart=on-failure`, `RestartSec`, `WatchdogSec`, `TimeoutStopSec`).
   Ignore namespacing directives (`ProtectSystem`, `ReadWritePaths`,
   `NoNewPrivileges`) with a one-line log. ~100 LOC.
2. **Create runtime dirs** (`/var/lib/oracle`, `/var/log/oracle`,
   `/etc/oracle`) at boot via Ascension's pre-start hook (mirrors the
   `ExecStartPre=install -d` lines in the unit). ~30 LOC.
3. **SIGTERM handling**: oracle responds to SIGTERM via its tokio
   `signal::ctrl_c` equivalent → Ctrl+C path. Verify signalfd delivers
   SIGTERM correctly under tokio. ~0 LOC if signalfd path is intact.
4. **Smoke test fixture**: a fake Conflux that accepts WS connections,
   replies with `IdentifyAck { accepted: true, protocol_version: 2 }`,
   echoes heartbeats. Add as `tests/conflux_fake.py` (~70 LOC).

### I5 — Session recording (~100 LOC, ~1 day) — optional

**Goal**: `conflux-session-recorder` runs under sshd's `ForceCommand`,
records a TTY session via `script(1)`, writes signed manifest.

Components:

- `ed25519-dalek` is pure-Rust — no kernel work needed.
- `script(1)` runs in a PTY — the concurrent sshd dispatch is already
  bringing up PTY support. Reuse.
- `setgid(recorded-sessions)` group lookup — needs `/etc/group` parsing,
  which musl does (works once `/etc/group` is staged).

**Cut decision**: defer until after I4 unless the Conflux team needs the
recorder demoed. Independent of oracle's main flow.

---

## 5. Strategic recommendation

**Greenlight I1 (TLS substrate) as the next implementation push.**

Reasons:

1. **Shared cost amortised**. TLS substrate unblocks:
   - `oracle` (this dispatch's target).
   - `curl https://`, `wget https://` (PIVOT-B already merged BusyBox+wget
     plain-HTTP; HTTPS is the next gate).
   - `sshd` host-key crypto + KEX-on-public-net (the concurrent sshd
     staging dispatch will hit this).
   - cloud-init metadata-service paths (Conflux fleet provisioning).
   - Eventually, any Mozilla NSS-dependent stub replacement
     (libipcclientcerts.so was a W101 plateau in the FF demo path —
     cleanly hosting OpenSSL/NSS removes that whole category of stub).
2. **All other phases are bounded and small** once I1 is done. I2 (~300
   LOC), I3 (~600 LOC), I4 (~200 LOC), I5 (~100 LOC) total ~1200 LOC of
   incremental work; each independently demonstrable.
3. **I1 is the riskiest phase**. Better to absorb the risk early than to
   plumb I2–I4 and then find that OpenSSL doesn't initialise.

### Sequence

```
I1 (TLS substrate)
   │
   ├─→ curl/wget HTTPS demo gate    [demonstrable end of I1]
   │
   └─→ I2 (tokio + sd_notify)
          │
          └─→ I3 (polling collectors substrate)
                 │
                 └─→ I4 (service lifecycle + smoke)
                        │
                        ├─→ oracle --mode service for 10 min demo gate
                        │
                        └─→ I5 (session recording) — optional
```

---

## 6. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **OpenSSL init under AstryxOS musl fails** | High — would force fallback | Pre-flight with a 50-LOC userspace test binary that calls `SSL_library_init()` + `SSL_CTX_new(TLS_client_method())`. If it fails, switch oracle to `rustls-tls` feature (1-line upstream-side change). |
| **tokio runtime depth — undiscovered syscall gaps** | Medium | Run oracle under `--features syscall-trace` and `--features firefox-trace-verbose` first; the existing `[SC]` log will surface unsupported syscalls within the first 10 s of runtime. Same harness pattern that caught the musl 3-gap (PR #298). |
| **systemd `Type=notify` semantic gap** | Low | Minimal `sd_notify` server (~100 LOC). The full systemd protocol is huge but oracle only uses `READY=1` and `WATCHDOG=1`. |
| **`ip` command JSON shellout incompatible with BusyBox `ip`** | Low | Stage Alpine `iproute2` (~500 KB). |
| **WS reconnect storm under DNS hiccup** | Low | Oracle has exponential backoff (1 s → 60 s). The risk is on the AstryxOS DNS resolver path — if UDP DNS hangs instead of returning ECONNREFUSED, oracle could pile up. Verify UDP recv timeout works. |
| **systemd watchdog kills oracle if tokio worker stalls** | Medium | The `WatchdogSec=120s` is generous; tokio's heartbeat task sends `WATCHDOG=1` every 60 s. If a worker stalls inside a futex (similar to W101 cliff), watchdog will SIGKILL oracle. This is correct behaviour — surface as a kernel bug if hit, fix root cause, don't disable watchdog. |
| **`/sys/class/dmi/id/*` faked content is implausible** | Low | Use static QEMU/KVM-shape vendor names (`"QEMU"`/`"Standard PC (i440FX + PIIX, 1996)"`); Conflux just stores them. Operators rarely query DMI in fleet view. |
| **Cross-PID procfs walk hits stale-state races** | Medium | Process collector polls every 120 s; OK to return slightly stale data. The bigger risk is a PID-reuse race (oracle reads `/proc/123/cmdline` after PID 123 has exited and been reused) — same problem Linux has, and oracle is expected to tolerate it (the per-PID `comm` + `start_time` is what disambiguates). |
| **Wire-protocol drift** | Low-Medium | `WS_PROTOCOL_VERSION = 2`. If Conflux bumps to 3, AstryxOS-hosted oracle is rejected by `IdentifyAck { accepted: false }`. Operator-visible failure — they re-roll the staged binary. Per `infrasvc:README.md` pre-1.0 caveat; documented. |

---

## 7. Minimum viable demo — defer I1 path

If "oracle logs in" is the bar (not full TLS), shortcut I1 by:

1. **Custom Conflux dev-server** speaking plain TCP WebSocket (`ws://` not
   `wss://`). The Conflux server already supports this for local-dev
   workflows — flip a config flag.
2. **Build oracle with TLS disabled** by overriding `tokio-tungstenite` and
   `reqwest` features at the workspace-level:
   ```toml
   tokio-tungstenite = { version = "0.24", default-features = false, features = ["connect"] }
   reqwest = { version = "0.12", default-features = false, features = ["json"] }
   ```
   This drops the `native-tls` link entirely. Upstream-side change, ~3
   lines in `infrasvc:Cargo.toml`.
3. **Configure oracle** with `server_url = "ws://conflux-dev.local:8443"`.
4. **Skip collectors** that need shellouts — `[polling.collectors.process]
   enabled = false`, `[polling.collectors.security] enabled = false`. Just
   run `network` + `system` collectors.

This path lets the user demo oracle hitting Conflux in **~2 days of
disk-image staging + Ascension `sd_notify` work** (the I2 + I4 subset
without I1).

**Trade-off**: it does not exercise the TLS surface that the rest of the
project benefits from. Recommend only as a milestone-pressure escape valve.

---

## 8. Out of scope (explicitly)

- Windows oracle support (`oracle.exe` on AstryxOS NT subsystem). Not on
  the dispatch and not on the Firefox-demo critical path.
- Conflux server-side changes (other than the dev-mode plain-WS flag in §7).
- Hardening oracle's own code (it ships as-is from upstream).
- macOS — not supported by oracle per `infrasvc:Cargo.toml` compile_error.
- `audit_stream` EDR-lite collector (defaults off; requires auditd).

---

## 9. Hand-back summary

- **Top-line recommendation**: greenlight **I1 (TLS substrate)** next.
  Largest single unblock (~1500–3000 LOC) but amortised across `curl`,
  `wget`, `sshd`, cloud-init, and any future NSS-dependent stub
  replacement.
- **Oracle's biggest blockers vs current AstryxOS state**:
  1. ca-certificates bundle missing in `build/disk/etc/ssl/certs/`.
  2. `libssl.so.3`/`libcrypto.so.3` staged but not soak-validated.
  3. `/sys/class/net/` not yet exposed in sysfs (only `/sys/devices/system/cpu/`).
  4. `sd_notify` `Type=notify` not yet honored by Ascension.
- **Minimum viable demo path** (§7): swap to `ws://` + drop `native-tls`
  features upstream-side + bring up Ascension `sd_notify`. ~2 days. Does
  not amortise.
- **Everything else** (tokio runtime, syscall surface, procfs surface) is
  already there or one bounded patch away.

---

## References (public specs only)

- POSIX.1-2017: `gethostname(2)`, `clock_gettime(2)`, `getaddrinfo(3)`,
  `epoll_wait(2)`, `signalfd(2)`, `eventfd(2)`, `timerfd_create(2)`,
  `prctl(2)`, `prlimit64(2)`.
- RFC 6455 — WebSocket Protocol.
- RFC 8446 — TLS 1.3 (and RFC 5246 — TLS 1.2 for fallback).
- RFC 1700 — ARPHRD_ETHER and related constants (current values in IANA
  registry).
- DMTF DSP0134 — System Management BIOS (SMBIOS) Reference Specification.
- systemd `sd_notify(3)` man page — `READY=1`, `WATCHDOG=1`, `STATUS=`,
  `STOPPING=1`.
- systemd `systemd.service(5)` — `Type=notify`, `WatchdogSec`,
  `Restart=on-failure`, `ExecStartPre=`.
- Alpine Linux package metadata: `ca-certificates`, `iproute2`,
  `openssl-libs` (versions tracked at https://pkgs.alpinelinux.org/).
- crates.io: `tokio`, `tokio-tungstenite`, `reqwest`, `ed25519-dalek`,
  `rustls`, `native-tls`.
- ECMA-119 — ISO 9660 (referenced for disk-image build paths).
- IETF `https://example.com` is the IETF documentation literal (RFC 6761).

Internal references: `infrasvc:Cargo.toml`, `infrasvc:src/main.rs`,
`infrasvc:src/sync/ws_client.rs`, `infrasvc:src/linux/network/interface_reader.rs`,
`infrasvc:src/lib.rs`, `infrasvc:deploy/oracle.toml`,
`infrasvc:deploy/oracle.service`, `infrasvc:README.md`.
