# eBPF Support Audit + Phased Roadmap

**Audit date:** 2026-05-23
**Scope:** Linux subsystem layer (`kernel/src/subsys/linux/`) and Aether native
kernel layer (`kernel/src/{net,sched,signal,perf,syscall,vfs,...}`).
**Mode:** READ-ONLY scoping. No kernel source files were modified.
**Output:** This document; one PR; zero kernel diff.

## Sources cited

All material in this audit is sourced from public references only. No
internal-corpus material is cited. Public references used:

- `bpf(2)` man page — kernel.org/doc/man-pages
- `bpf-helpers(7)` man page — kernel.org/doc/man-pages
- `seccomp(2)` man page — kernel.org/doc/man-pages
- `socket(7)` and `SO_ATTACH_FILTER` documentation — kernel.org/doc/man-pages
- `kernel.org/doc/html/latest/bpf/` — official eBPF subsystem docs
- `kernel.org/doc/html/latest/bpf/instruction-set.html` — eBPF ISA spec
- `kernel.org/doc/html/latest/bpf/verifier.html` — verifier design
- iovisor BPF compiler collection wiki — github.com/iovisor/bcc
- LWN "A thorough introduction to eBPF" — lwn.net/Articles/740157/
- LWN "BPF: a tour of program types" — lwn.net/Articles/740157/
- IETF draft-ietf-bpf-isa — eBPF ISA standardisation
- Cilium "eBPF reference guide" — docs.cilium.io/en/stable/bpf/

---

## 1. Linux eBPF surface catalogue

Linux exposes eBPF through one syscall (`bpf(2)`, x86_64 number **321**)
plus a small constellation of related syscalls (`perf_event_open(2)` 298,
`prctl(2)` `PR_SET_SECCOMP` + `SECCOMP_MODE_FILTER`, `setsockopt(SO_ATTACH_BPF)`,
plus a `bpf()` file-descriptor table for maps and programs).

### 1.1 The `bpf(2)` syscall surface

`bpf(2)` is a multiplexor:

```
long bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

Per `bpf(2)`, the kernel supports ~40 commands. The **MVP-relevant subset** is:

| cmd | Purpose | MVP? |
|---|---|---|
| `BPF_MAP_CREATE` | Allocate a map; return fd | Yes (E1) |
| `BPF_MAP_LOOKUP_ELEM` | Read map by key | Yes (E1) |
| `BPF_MAP_UPDATE_ELEM` | Write map | Yes (E1) |
| `BPF_MAP_DELETE_ELEM` | Delete entry by key | Yes (E1) |
| `BPF_MAP_GET_NEXT_KEY` | Iterate keys | Defer |
| `BPF_PROG_LOAD` | Verify + admit program; return fd | Yes (E1) |
| `BPF_PROG_ATTACH` | Attach program to hook | Yes (E2/E3) |
| `BPF_PROG_DETACH` | Detach program | Yes (E2/E3) |
| `BPF_PROG_TEST_RUN` | Execute program on user-supplied input | Yes (E1 — validation) |
| `BPF_OBJ_PIN` / `BPF_OBJ_GET` | Pin to bpffs path | Defer |
| `BPF_RAW_TRACEPOINT_OPEN` | Tracing attach (newer ABI) | Defer |
| `BPF_LINK_CREATE` | Link-style attachment | Defer |
| `BPF_BTF_LOAD` | Load BTF type info | Defer |
| `BPF_PROG_QUERY` / `BPF_*_GET_NEXT_ID` | Introspection | Defer |

ENOSYS on the rest is acceptable; standard libbpf code paths probe with the
expected fallback shape.

### 1.2 BPF program types

Per `bpf(2)`, ~32 program types exist. Sorted by demo and ops value:

| Program type | What it hooks | MVP phase |
|---|---|---|
| `BPF_PROG_TYPE_UNSPEC` | Never valid (return EINVAL) | E1 |
| `BPF_PROG_TYPE_SOCKET_FILTER` | Per-socket packet filter; equiv. to `SO_ATTACH_FILTER` | **E2** |
| `BPF_PROG_TYPE_KPROBE` | Hook on kernel functions / syscall entry | **E3** |
| `BPF_PROG_TYPE_TRACEPOINT` | Hook on static tracepoints | E3 (if E3 lands) |
| `BPF_PROG_TYPE_PERF_EVENT` | Bound to a `perf_event_open()` fd | Defer (E5+) |
| `BPF_PROG_TYPE_SCHED_CLS` | tc classifier | Defer |
| `BPF_PROG_TYPE_SCHED_ACT` | tc action | Defer |
| `BPF_PROG_TYPE_XDP` | Pre-stack RX (driver-level) | Defer (E5+) |
| `BPF_PROG_TYPE_RAW_TRACEPOINT` | Newer raw tracepoint ABI | Defer |
| `BPF_PROG_TYPE_LSM` | LSM hooks | Defer |
| `BPF_PROG_TYPE_CGROUP_*` (10 variants) | cgroup-scoped network/syscall hooks | Defer |
| `BPF_PROG_TYPE_SOCK_OPS` / `SK_SKB` / `SK_MSG` | Socket-state callbacks | Defer |
| `BPF_PROG_TYPE_FLOW_DISSECTOR` | Custom flow hashing | Defer |
| `BPF_PROG_TYPE_SK_LOOKUP` | Listener selection | Defer |
| `BPF_PROG_TYPE_SYSCALL` | Run BPF in user-issued `BPF_PROG_TEST_RUN` | E1 (the validation path) |
| `BPF_PROG_TYPE_NETFILTER` | Netfilter hook | Defer |
| `BPF_PROG_TYPE_STRUCT_OPS` / `EXT` / `TRACING` | BTF-driven attach (need BTF first) | Defer |

The deferred set is ~80 % of the surface and not on the demo or ops critical
path. Anyone porting Cilium / Calico / bpftrace would need the deferred set;
that is not a near-term goal.

### 1.3 Map types

~30 map types are defined. The MVP-relevant subset:

| Map type | Storage shape | MVP phase |
|---|---|---|
| `BPF_MAP_TYPE_ARRAY` | Fixed-length array indexed by `u32` | **E1** |
| `BPF_MAP_TYPE_HASH` | Open-addressed hash | E2 (filters often want hash) |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU fixed-length array | E3 (kprobe counters) |
| `BPF_MAP_TYPE_PERCPU_HASH` | Per-CPU hash | Defer |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Ring of perf events | Defer |
| `BPF_MAP_TYPE_RINGBUF` | Lock-free MPSC ring (preferred over PERF_EVENT_ARRAY) | E3 (if userspace consumer wired) |
| `BPF_MAP_TYPE_LRU_HASH` | LRU-evicting hash | Defer |
| `BPF_MAP_TYPE_LPM_TRIE` | Longest-prefix match (CIDR) | Defer |
| `BPF_MAP_TYPE_STACK_TRACE` | Recorded stacks | Defer |
| `BPF_MAP_TYPE_PROG_ARRAY` | For `tail_call()` helper | Defer |
| All `SOCKMAP / SOCKHASH / DEVMAP / XSKMAP / CPUMAP` | Specialised | Defer |
| All `*_STORAGE` (sk / inode / task / cgrp) | Local-storage | Defer |

### 1.4 Helper functions

Per `bpf-helpers(7)`, **~206 helper functions** exist. The MVP-relevant
subset (per phase):

| Helper | Purpose | MVP phase |
|---|---|---|
| `bpf_map_lookup_elem(map, key)` | Lookup; returns `value *` or NULL | **E1** |
| `bpf_map_update_elem(map, key, val, flags)` | Insert / update | **E1** |
| `bpf_map_delete_elem(map, key)` | Delete | **E1** |
| `bpf_ktime_get_ns()` | Monotonic ns since boot | **E1** |
| `bpf_trace_printk(fmt, fmt_size, args...)` | Debug print to trace pipe | **E1** |
| `bpf_get_prandom_u32()` | Pseudo-random u32 | E1 (trivial) |
| `bpf_get_smp_processor_id()` | Current CPU id | E1 (trivial) |
| `bpf_get_current_pid_tgid()` | Current pid \| tgid << 32 | **E3** |
| `bpf_get_current_uid_gid()` | Current uid \| gid << 32 | E3 |
| `bpf_get_current_comm(buf, size)` | Current task name | E3 |
| `bpf_probe_read(dst, size, src)` | Safe read from kernel addr | E3 |
| `bpf_probe_read_user(dst, size, src)` | Safe read from user addr | E3 |
| `bpf_probe_read_str` / `_user_str` | Bounded C-string copy | E3 |
| `bpf_perf_event_output` | Write to `PERF_EVENT_ARRAY` map | Defer |
| `bpf_ringbuf_output` / `_reserve` / `_submit` | Ringbuf publish | E3 (if ringbuf landed) |
| `bpf_skb_load_bytes(skb, off, to, len)` | Read packet bytes | **E2** |
| `bpf_skb_store_bytes` / `_csum_replace` | Packet mutation | Defer (filter-only E2) |
| `bpf_tail_call` | Indirect program call via PROG_ARRAY map | Defer |
| `bpf_redirect` / `bpf_clone_redirect` | XDP / tc action | Defer |

Helpers numbered 1-7 (lookup, update, delete, probe_read, ktime, trace_printk,
prandom) are sufficient for the canonical "hello world" BPF program. Helper 8
(smp_processor_id) is one line. Helpers 14-16 (pid_tgid, uid_gid, comm) bring
the kprobe gate to life in E3.

### 1.5 Verifier

Per kernel.org/doc/html/latest/bpf/verifier.html the Linux verifier is a
~25,000 LOC interpreter-style symbolic executor. It tracks:

- Register types (scalar, pointer-to-map-value, pointer-to-packet, pointer-to-stack, pointer-to-ctx)
- Value ranges (min/max, known bits)
- Pointer arithmetic bounds
- Stack depth (≤512 B)
- Termination (no unbounded loops pre-5.3; bounded loops post-5.3 via `BPF_JCOND`)
- Helper signatures (each helper declares arg types; verifier enforces)
- Type-safe map access (`bpf_map_lookup_elem` result must be NULL-checked before deref)

The verifier is the **single most expensive component** of an eBPF
implementation, by an order of magnitude. The MVP roadmap deliberately ships
no verifier in E1 — instead, the loader is "trusted" (only root, only signed
programs, only programs from a closed list). This is acceptable for a demo
gate; it is not acceptable for an untrusted-user surface.

### 1.6 JIT vs interpreter

Per kernel.org docs, Linux ships:

- **Interpreter**: portable C implementation of the eBPF ISA (~1500 LOC)
- **JIT** per architecture: x86_64 JIT is ~3500 LOC; ARM64 / RISC-V / ppc64
  have their own

The interpreter is enabled by default; the JIT is opt-in via
`/proc/sys/net/core/bpf_jit_enable=1` (or `=2` for hardened mode with
constant blinding).

MVP ships **interpreter only**. JIT is a Phase E5+ concern.

### 1.7 Classic BPF (cBPF) and seccomp

Classic BPF predates eBPF and uses a different instruction set
(`struct sock_filter` per `<linux/filter.h>`):

```
struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; };
struct sock_fprog  { u16 len; struct sock_filter *filter; };
```

cBPF is the only flavour accepted by:

- `setsockopt(SO_ATTACH_FILTER, ...)` (legacy socket filters)
- `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` (seccomp-bpf)

The kernel internally **transpiles cBPF to eBPF** at load time. AstryxOS
currently stubs `PR_SET_SECCOMP` to return success without parsing the
filter (`kernel/src/subsys/linux/syscall.rs:test_runner.rs` comment at
the prctl path notes "AstryxOS does not interpret the BPF"). That stub is
adequate for Firefox sandbox-init but does not enforce any policy.

A real seccomp implementation can be built on top of either:

- (a) a pure cBPF interpreter (~300 LOC, simpler ISA), OR
- (b) the eBPF interpreter once it exists, with a cBPF→eBPF transpiler (~150 LOC).

Option (b) shares code with Phase E1 and is preferred if E1 lands first.

---

## 2. AstryxOS current state

### 2.1 What we have today

- **No `bpf(2)` syscall**: number 321 hits the generic `_ => ENOSYS` arm at
  `kernel/src/subsys/linux/syscall.rs:4642`. No BPF data structures exist.
- **No `perf_event_open(2)`**: number 298 also ENOSYS.
- **No kprobes / uprobes / tracepoints** anywhere in the tree. Grep:
  `grep -r 'kprobe\|uprobe\|tracepoint\|perf_event' kernel/src/` returns
  zero matches.
- **No JIT infrastructure**. The kernel never allocates W+X memory and the
  page tables don't carry the bookkeeping for code pages.
- **One stubbed cBPF entry point**: `prctl(PR_SET_SECCOMP, MODE_FILTER)`
  accepts any filter blob without parsing it.

### 2.2 What we have that is reusable

- **`kernel/src/perf/` (447 LOC)**: a perfmon-style counter / ring system.
  Already wires:
  - `record_interrupt(vec)` from `arch/x86_64/irq.rs`
  - `record_syscall(nr)` from the NT subsystem (Linux syscall dispatch does
    not yet record per-syscall counters here, only into the `SYSCALL_RING`)
  - `record_context_switch()` from `sched/mod.rs`
  - `record_heap_alloc/free()` from `mm/heap.rs`
  - `record_page_fault()` from the PF handler

  The `SYSCALL_RING` (16384-entry lock-free MPMC ring at `perf/mod.rs:108-135`)
  is the closest thing AstryxOS has to a tracepoint: every Linux syscall is
  already recorded with `(tick, pid, nr)` packed into one `u64`. Adding a
  BPF dispatch tap parallel to this ring is straightforward and matches
  the locking model already proven on the SMP path.

- **`kernel/src/net/socket.rs` (Socket abstraction)**: clean per-socket
  state object. The natural attach point for `BPF_PROG_TYPE_SOCKET_FILTER`
  is a new `Socket::attached_filter: Option<Arc<BpfProgram>>` field
  consulted by `socket_recv()` and `socket_recvfrom()` before delivering
  to userspace.

- **`kernel/src/net/ipv4.rs:handle_ipv4()`** and
  **`kernel/src/net/ethernet.rs:handle_frame()`**: single funnels for all
  RX. An XDP-equivalent hook (Phase E5+) would slot in before
  `handle_ipv4()` calls the L4 demux.

- **`kernel/src/subsys/linux/syscall.rs:dispatch()`** at line 850: the
  single Linux-personality syscall entry. Adding a tracepoint-equivalent
  `bpf_syscall_enter(num, args...)` hook is a one-line `cfg`-gated call
  near the existing `record_replay::record_syscall_entry` call at line
  915. The shape is established.

- **`kernel/src/perf/mod.rs:syscall_name()` / `linux_syscall_name()`**:
  already maps syscall numbers to strings — useful for `bpf_get_current_comm`
  and for the trace output format.

- **The `cfg`-gated diagnostic pattern** (see `vfork-canary-diag`,
  `d15-mthread-watch`, `d16-canary-watch`, `record-replay` cfgs at
  `subsys/linux/syscall.rs:857-919`): existing precedent for adding
  zero-cost-when-off taps on the syscall path. eBPF tracing should follow
  the same pattern (`#[cfg(feature = "ebpf")]`).

### 2.3 Gap summary

| Component | Status | LOC estimate to MVP |
|---|---|---|
| `bpf(2)` syscall dispatcher | absent | ~200 LOC (arg copyin, cmd dispatch, fd alloc) |
| `bpf_attr` struct definitions | absent | ~150 LOC (port from UAPI shape) |
| Map allocator + ARRAY type | absent | ~250 LOC |
| Map fd table integration | partial (fd table exists; bpf objects need to plug in) | ~80 LOC |
| eBPF interpreter | absent | ~1200 LOC (ISA decode + 100+ opcodes + helper dispatch) |
| Helper dispatch table | absent | ~150 LOC (E1 set) + ~300 LOC (E3 set) |
| Verifier (real) | absent | ~5000-25000 LOC (out of MVP) |
| Verifier (trust-the-loader stub) | absent | ~50 LOC (sanity: insn count, return path) |
| JIT | absent | ~2000-4000 LOC (out of MVP; defer to E5+) |
| Socket filter hook | absent | ~80 LOC (Socket field + `socket_recv` call) |
| Syscall-entry tracing hook | absent | ~40 LOC (cfg-gated dispatch tap) |
| Per-CPU map (E3 dep) | absent | ~150 LOC |
| `BPF_PROG_TEST_RUN` (validation path) | absent | ~80 LOC |

---

## 3. Phased roadmap

Each phase is independently mergeable, independently testable, and adds
demonstrable value. Estimates are LOC at the kernel layer **only**.
Userspace tooling (libbpf-shim, a minimal `bpftool`) is out of scope —
existing Linux-userspace tooling running under our subsystem should work
unmodified once each phase lands.

### Phase E1 — Interpreter + skeleton + ARRAY map (~2000 LOC)

**Goal:** a hand-written BPF program loaded via `bpf(BPF_PROG_LOAD, ...)`
can be executed via `bpf(BPF_PROG_TEST_RUN, ...)` and returns a defined
value. ARRAY maps work. `bpf_trace_printk` writes to the kernel serial
log.

**Deliverables:**

- `kernel/src/bpf/mod.rs` — top-level subsystem; types and constants.
- `kernel/src/bpf/syscall.rs` — `sys_bpf(cmd, attr, size)` dispatcher;
  wired from `subsys/linux/syscall.rs:dispatch()` arm `321 => bpf::sys_bpf(...)`.
- `kernel/src/bpf/interpreter.rs` — eBPF ISA decoder + executor.
  Per the IETF draft eBPF ISA, ~100 opcodes split across 8 instruction
  classes (LD, LDX, ST, STX, ALU, JMP, ALU64, JMP32). MVP can ship the
  full opcode table — none of them are individually hard; the work is in
  exhaustively mapping them. Stack scratch space: 512 B per call frame.
- `kernel/src/bpf/map.rs` — `Map` trait + `ArrayMap` impl. fd table
  integration so `BPF_MAP_LOOKUP_ELEM` on a map fd resolves the map.
- `kernel/src/bpf/helpers.rs` — helper dispatch table indexed by function
  id. E1 set: ids 1-3 (map ops), 5 (ktime), 6 (trace_printk), 7
  (prandom), 8 (smp_processor_id). Each is ~10 LOC.
- `kernel/src/bpf/loader.rs` — "trust the loader" path: count instructions,
  verify last instruction is `BPF_EXIT`, verify all jumps stay in bounds,
  verify max stack depth ≤512 B by tracing CFG. No type-tracking. ~150 LOC.
- `kernel/src/bpf/prog.rs` — `BpfProgram` struct (refcounted Arc), holds
  the instruction Vec, the map fds it references, the attached helpers.

**Hook points required in the Aether layer:** NONE for E1. The syscall
itself is the only attach point in this phase.

**Validation:** new test in `kernel/src/test_runner.rs`:

1. Construct a 3-instruction BPF program by hand: `BPF_MOV imm 0x42`,
   `BPF_EXIT`.
2. `BPF_PROG_LOAD` it (returns a prog fd).
3. `BPF_PROG_TEST_RUN` it with a zeroed context (returns 0x42).
4. `BPF_MAP_CREATE` an array map of 4 u64 slots.
5. `BPF_MAP_UPDATE_ELEM` writes 0xdead at key 2.
6. `BPF_MAP_LOOKUP_ELEM` at key 2 returns 0xdead.
7. Load a 6-instruction program that calls `bpf_map_lookup_elem`,
   dereferences, returns the value. `TEST_RUN` returns 0xdead.

These tests run in `cargo test`-equivalent under the in-kernel test
runner; no Firefox / userspace integration needed.

**LOC budget:** ~2000. The opcode table dominates; allow 1.5× soft
budget = 3000.

**Risks:**

- eBPF ISA has subtle semantics around sign extension, atomic ops, and
  pointer arithmetic — easy to get wrong without a verifier to catch it.
  Mitigation: skip atomic ops (BPF_ATOMIC class) in E1; emit -EINVAL.
- Per Cilium/iovisor docs, helper-arg type checking is mandatory for
  safety. Without a verifier, the loader stub must restrict helpers to
  the "safe-on-any-arg" set: ktime, trace_printk, prandom, smp_processor_id.
  Map helpers (lookup/update/delete) require the loader to pre-resolve
  map fds and rewrite the `imm` field of `BPF_PSEUDO_MAP_FD` instructions
  — straightforward, ~30 LOC.

**Value:** establishes the BPF subsystem skeleton; no immediate ops or
demo value. Enables E2/E3.

### Phase E2 — Socket filter attach (~400 LOC on top of E1)

**Goal:** a userspace process can `setsockopt(SO_ATTACH_BPF, ...)` or
`bpf(BPF_PROG_ATTACH, ..., BPF_SK_LOOKUP)` to bind a `SOCKET_FILTER`
program to a socket. Incoming packets are evaluated by the filter before
being made available via `recv()`; the filter's return value is the
maximum length accepted (0 = drop the packet).

**Deliverables:**

- `kernel/src/net/socket.rs`: add `attached_filter: RwLock<Option<Arc<BpfProgram>>>`
  field to `Socket`.
- `kernel/src/subsys/linux/syscall.rs`: `setsockopt` arm for level
  `SOL_SOCKET=1` optname `SO_ATTACH_BPF=50` reads the prog fd, resolves
  to `BpfProgram`, calls `socket.attach_filter(prog)`.
- `kernel/src/net/tcp.rs` and `kernel/src/net/udp.rs`: where the
  per-socket RX queue is appended-to, first run the filter on the packet.
  If the filter returns 0, drop. If it returns >0, truncate to that
  length and enqueue.
- `kernel/src/bpf/helpers.rs`: add helper `bpf_skb_load_bytes` (helper id 9)
  bounded to packet length.
- `kernel/src/bpf/prog.rs`: program type `SOCKET_FILTER` is wired so the
  loader admits the right helper subset.

**Hook points required in the Aether layer:**

- The per-socket RX enqueue point becomes a BPF-attach site. This is
  already a centralised spot in `net/tcp.rs` and `net/udp.rs`; the
  change is a function-pointer-style call with the locking model
  preserved (read-lock on `attached_filter`, BPF runs to completion
  under the read lock, no blocking).

**Validation:**

1. Build a BPF program that returns 0 if the packet's IP source matches
   a configured value (kept in a 1-element ARRAY map), else returns
   max length.
2. Attach to a UDP socket bound to 127.0.0.1:9999.
3. Send a packet from a "blocked" source — `recv()` does not see it.
4. Send from any other source — `recv()` returns the bytes.

In the Linux subsystem this is the "tcpdump filter" pattern. In the
AstryxOS test harness we wire it as a loopback-only test (no NIC required).

**LOC budget:** ~400 incremental. Soft 1.5× = 600.

**Risks:**

- BPF programs evaluating packets are **highly trusted** in the absence
  of a verifier. The loader stub MUST forbid arbitrary helper calls
  from `SOCKET_FILTER` programs and MUST enforce that all packet reads
  go through `bpf_skb_load_bytes` (bounds-checked) rather than direct
  pointer arithmetic. Even with that restriction, an unverified program
  can read arbitrary 0..max-stack-depth values via constructed pointer
  arithmetic; in E2 we accept this and gate the attach syscall on
  `capable(CAP_NET_ADMIN)` (which AstryxOS currently grants liberally;
  see the security audit doc dated 2026-05-16 for the broader cap story).
- Performance: BPF on RX is a per-packet cost. The ARRAY-map lookup is
  ~5 ns; full filter evaluation is ~50-200 ns/packet for typical
  programs. Acceptable for the demo (1 Gbps loopback) — would matter
  at 10 Gbps+.

**Value:** classic eBPF demo (tcpdump, simple firewall). High user
recognition. Medium ops value.

### Phase E3 — Syscall-entry tracing (~600 LOC on top of E1)

**Goal:** a userspace process can attach a `KPROBE` (or
`TRACEPOINT`-shaped) program to syscall entry. The program receives a
context object with the syscall number and args; it can write to a map.
The canonical example — counting `execve()` system-wide — works.

**Deliverables:**

- `kernel/src/bpf/tracing.rs` — per-syscall attach table: a per-syscall
  `Option<Arc<BpfProgram>>` (or short Vec for multi-attach). 512 entries
  (covers all Linux x86_64 syscall numbers including the 424-461 gap).
- `kernel/src/subsys/linux/syscall.rs:dispatch()`: gated tap that, if
  any program is attached to syscall `num`, builds a tracing context
  (regs + syscall args) and invokes the BPF interpreter. Sits parallel
  to the existing `record_replay::record_syscall_entry` call (line 915).
  Same return-value-ignored pattern — the BPF program cannot block the
  syscall from progressing (that is what LSM is for; LSM is deferred).
- `kernel/src/bpf/helpers.rs`: add helpers 14-16 (`get_current_pid_tgid`,
  `get_current_uid_gid`, `get_current_comm`) and helpers 4, 117
  (`probe_read`, `probe_read_user_str`).
- `kernel/src/bpf/map.rs`: `PercpuArrayMap` impl (one ARRAY per online
  CPU; per-CPU indexing is `cpu_index()` from
  `kernel/src/arch/x86_64/cpu.rs`). Avoids the cache-line ping that
  plain HASH would cause on the counting path.
- `kernel/src/bpf/prog.rs`: program type `KPROBE` wired; loader admits
  the tracing helper subset.

**Hook points required in the Aether layer:**

- One `cfg`-gated function call at the top of `subsys/linux/syscall.rs:dispatch()`.
  When the `ebpf` feature is off, the call site vanishes.
- The handler runs in **syscall context** — the calling thread holds the
  syscall stack and any locks the kernel had before entering syscall
  dispatch (currently: none, syscall entry is lock-clean). The BPF
  program runs **non-preemptibly** until it returns. No allocations,
  no blocking calls. The interpreter must therefore be allocation-free
  on the hot path; map ops are O(1) and lock-clean by design.

**Validation:**

1. Build a BPF program that increments `map[0]` at key=syscall_nr.
2. Attach to syscall 59 (`execve`).
3. From userspace, run `/bin/true` twice.
4. `BPF_MAP_LOOKUP_ELEM` at key=59 returns 2.

**LOC budget:** ~600 incremental. Soft 1.5× = 900.

**Risks:**

- A buggy or malicious BPF program in syscall context can stall every
  syscall on the system. Until a verifier exists, the loader stub must
  bound program runtime (instruction count limit, no loops, ≤4096
  insns). The loader currently in E1 enforces these.
- The "syscall args" context shape (`struct trace_event_raw_sys_enter`
  per public Linux tracepoint ABI) is sensitive to ordering. Document
  the exact layout we offer in `kernel/src/bpf/tracing.rs`; downstream
  BPF programs are sensitive to it.
- Counter wrap, lost updates: ARRAY maps update atomically via
  `compare_exchange`. Per-CPU ARRAY avoids contention entirely; recommend
  PERCPU_ARRAY as the canonical pattern for E3 counters.

**Value:** very high. The "count syscalls by type system-wide" pattern is
the workhorse of bpftrace, bcc, and BPF-based observability tooling. Even
without a userspace `bpftrace` (out of scope for E3), the in-kernel test
provides immediate value as a kernel debug primitive — equivalent to the
existing `perf::SYSCALL_RING` but programmable.

### Phase E4 — cBPF transpiler + real seccomp (~200 LOC on top of E1)

**Goal:** `prctl(PR_SET_SECCOMP, MODE_FILTER)` actually enforces the
provided cBPF filter rather than no-op accepting it. Closes a real
sandbox-escape concern (Firefox content processes pass non-trivial
seccomp filters that we currently ignore).

**Deliverables:**

- `kernel/src/bpf/cbpf.rs` — cBPF ISA decoder (`struct sock_filter`),
  transpile to eBPF on load (~150 LOC; cBPF is much simpler than eBPF —
  fewer opcodes, no maps, no helpers in the cBPF flavour).
- `kernel/src/subsys/linux/syscall.rs` — `prctl(PR_SET_SECCOMP, MODE_FILTER)`
  arm copies the filter, transpiles, installs as a per-task BPF program
  that runs at syscall entry and inspects `seccomp_data` (syscall nr +
  arch + args + IP). Return value determines action: KILL / ALLOW / TRAP
  / ERRNO / TRACE / LOG.
- The per-task hook is the same dispatch tap added in E3 but invoked
  **before** the syscall-tracing hook and with the ability to abort
  the syscall (return -EPERM or kill the task). Adding "abort" to the
  E3 tap is a 20-LOC change; everything else reuses E1.

**Hook points required in the Aether layer:**

- The syscall-entry tap from E3, plus the ability to early-return from
  `dispatch()` with the seccomp-mandated errno.

**Validation:**

1. cBPF filter that ALLOWS all syscalls except `write` (syscall 1),
   which is replaced with -EPERM.
2. `prctl(PR_SET_SECCOMP, MODE_FILTER, &filter)`.
3. `write(1, "x", 1)` returns -1, errno EPERM.
4. `getpid()` succeeds.

**LOC budget:** ~200. Soft 1.5× = 300.

**Risks:** seccomp is a security primitive. Bugs let sandboxed
processes escape. Recommend that this phase is gated on a real
verifier (or on a much-more-careful loader stub specific to cBPF —
cBPF's simpler ISA means stub verification is tractable, ~80 LOC for
bounds + termination).

**Value:** closes a real gap that exists today (stubbed seccomp).
Cheap once E1 lands. Strongly recommended as the immediate follow-up
to E1.

### Phase E5+ — out of MVP

Listed here for completeness, not recommended as near-term work:

- **Real verifier** (~5000-25000 LOC) — non-negotiable for any
  untrusted-user BPF surface. Until this exists, BPF should require root.
- **JIT** (~2000-4000 LOC per architecture) — interpreter is ~5-20×
  slower than JIT. Acceptable for E1-E4 since hot paths are short.
- **XDP** — driver-level RX hook; requires driver buy-in (e1000 / virtio-net).
- **`PERF_EVENT_ARRAY` / real `perf_event_open(2)`** — for stack-trace
  collection. ~1500 LOC.
- **`RINGBUF` consumer in userspace** — the producer side is small;
  the consumer is a userspace responsibility (mmap a shared region).
- **`BTF` (BPF Type Format)** — required for modern (CO-RE) BPF
  programs. ~1000 LOC just to parse. Out of MVP.
- **LSM hooks** — would let BPF programs make policy decisions on
  capability checks, file opens, etc. Requires an LSM framework in
  AstryxOS first.
- **cgroup-* program types** — require cgroups, which AstryxOS does not
  meaningfully implement.
- **`sockmap` / `sockhash` / `sk_msg`** — sk-skb redirection between
  sockets; requires the bypass-the-stack splice infra.

---

## 4. Aether layer requirements

### 4.1 Hook points (by phase)

| Phase | Hook | File | Locking | Allocation |
|---|---|---|---|---|
| E1 | none (syscall only) | `subsys/linux/syscall.rs` | unchanged | unchanged |
| E2 | per-socket RX filter | `net/socket.rs` (new field) + call sites in `net/{tcp,udp}.rs` | `RwLock` read-lock; BPF runs to completion under it | no |
| E3 | syscall entry tap | `subsys/linux/syscall.rs:dispatch()` line 850-ish | none added; BPF runs in syscall context (already lock-clean) | no |
| E4 | per-task seccomp filter | same as E3, plus per-task program slot | per-task slot is `Mutex` for set; lock-free atomic for read | no |
| E5+ | XDP driver hook | `net/{e1000,virtio_net}.rs:rx` | driver RX context (already IRQ-safe) | no |
| E5+ | tracepoint static markers | scattered (mm, sched, fs) | varies; tracepoints must be IRQ-safe at attach sites | no |

### 4.2 Locking model

BPF programs run in **atomic context** in Linux and we propose the
same constraint. The interpreter must:

1. Disable preemption for the duration of `BpfProgram::run()` — already
   the case at syscall-entry (no scheduler tick during early dispatch);
   need an explicit `preempt_disable` shim at the socket-filter call
   site (RX is already non-preemptible under most paths).
2. Forbid allocations on the BPF path. Map values are pre-allocated at
   `MAP_CREATE` time; the per-program stack (≤512 B) lives in a
   per-CPU scratch buffer that the interpreter rents at run time
   (lock-free via `cpu_index()` indexing).
3. Forbid blocking helpers. Helpers in the E1/E3 set are all
   non-blocking; document this requirement in `kernel/src/bpf/helpers.rs`.

### 4.3 Memory model

- **Map storage**: allocated at `BPF_MAP_CREATE` time, lives until the
  last reference (program fd or pinned fd) drops. Uses
  `kernel/src/mm` heap; not page-aligned (per-key access, not
  page-mapped).
- **Program storage**: instructions live in kernel heap, refcounted by
  `Arc<BpfProgram>`. Multiple attach sites share the same `Arc`.
- **Stack**: per-CPU 512 B scratch in BSS (`static`), zeroed before
  each `run()`. No dynamic stack.
- **Per-CPU maps**: each CPU gets its own slot; aggregation is on
  read. Indexing via `crate::arch::x86_64::cpu::cpu_index()` (RDTSCP
  per PR #157).
- **W^X**: no JIT in MVP, so no W+X mappings. Interpreter only.

### 4.4 Helper dispatch ABI

Helpers are called from the interpreter via a single dispatch table
indexed by helper id (per `bpf-helpers(7)`):

```rust
type BpfHelperFn = fn(
    arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64,
    prog: &BpfProgram,
) -> u64;

static HELPERS: [Option<BpfHelperFn>; 256] = ...;
```

`prog` is passed so helpers like `bpf_map_lookup_elem` can resolve the
map fd to the actual `Arc<Map>` via the program's fd table (the
loader pre-resolves these so the hot path is array-indexed, not
fd-table-walked).

This is a clean cross-layer ABI: the Linux subsystem owns the helper
implementations; the BPF subsystem owns the interpreter and the
dispatch table; the Aether layer provides the primitives that helpers
call (`get_current_pid_tgid` → `proc::current_pid_lockless()`;
`ktime_get_ns` → `vdso::now_ns()`).

### 4.5 fd table integration

BPF programs and maps are addressable via integer file descriptors.
AstryxOS already has a per-process fd table
(`kernel/src/proc/...`). The BPF subsystem registers two new fd
kinds:

- `FdKind::BpfProg(Arc<BpfProgram>)`
- `FdKind::BpfMap(Arc<dyn Map>)`

Lookup, refcount, close paths are reused. Roughly ~30 LOC of
boilerplate.

---

## 5. Strategic recommendation

### 5.1 Highest-value-per-LOC ordering

Recommended order:

1. **E1 first** (~2000 LOC). Unblocks everything else; pure
   substrate. No demo gate immediately moves, but the cost is
   amortised across E2+E3+E4.
2. **E4 next** (~200 LOC after E1). Cheapest meaningful win.
   Replaces the current "stub-accept-any-seccomp-filter" with real
   enforcement. Closes a real Firefox sandbox concern. Best
   bang-per-LOC by an order of magnitude.
3. **E3 third** (~600 LOC after E1). High ops value
   (programmable observability), unblocks future bpftrace-style
   work. Modest LOC.
4. **E2 last of the MVP** (~400 LOC after E1). The classic
   "tcpdump filter" demo — high recognition, but the only thing it
   demonstrates that AstryxOS does not already do is *attached*
   filtering — and Firefox does not need it. Skip unless there is
   a specific demo ask.

### 5.2 Alternative ordering — fastest demo

If the goal is **a single visible demo**, do **E1+E2 only** (~2400
LOC). A working "tcpdump-style" BPF filter on a loopback socket is
the canonical eBPF screenshot. Skip E3/E4. Total ~3 weeks at
specialist velocity (the bulk is the opcode table).

### 5.3 Alternative ordering — fastest security win

If the goal is **closing the real Firefox sandbox gap**, do
**E1+E4 only** (~2200 LOC). Seccomp enforcement closes a known
stub. Skip the demo dressing. Total ~3 weeks.

### 5.4 What I would do

E1 + E4. Skip E2 unless a demo ask materialises (the eBPF screenshot
is recognisable but does not move the Firefox PNG demo); skip E3
unless an ops use-case appears (the existing `perf::SYSCALL_RING` covers
"what was this process doing" without BPF). E4 is the smallest possible
real-functionality win and it closes a security stub that the audit
dated 2026-05-16 has already flagged.

---

## 6. Risks

### 6.1 Verifier complexity is the elephant

The Linux verifier is 25,000 LOC and represents 5+ years of hardening.
**MVP ships no verifier** and the "trusted loader" pattern is
acceptable **only** if BPF load is restricted to root and the loaded
programs come from a closed list (e.g., a few hand-built ones for
testing + the seccomp programs that the kernel itself transpiles from
known-good cBPF). Opening BPF to untrusted users without a verifier is
a kernel exploit primitive — do not do this.

Concrete mitigation: gate all `bpf(2)` commands except seccomp
transpilation on a capability check that the security-engineer can
audit. The current AstryxOS cap model is permissive (see the
2026-05-16 security audit doc); the gating should be tightened in
parallel with E1.

### 6.2 Program portability across kernels

BPF programs compiled for upstream Linux assume the upstream helper
set, the upstream context layouts (e.g., `struct __sk_buff`,
`struct pt_regs`), and BTF for CO-RE. Our MVP supports a small,
explicitly enumerated subset. Programs that work on AstryxOS will
work on Linux; the reverse is not generally true. Userspace tooling
that uses libbpf with CO-RE will fail to load programs at all.

Mitigation: clearly document in `docs/EBPF_SUBSET.md` (to be written
when E1 lands) which helpers, program types, and context fields are
supported. Recommend hand-written BPF or `-fno-target-bpf-features` for
AstryxOS-targeted programs in the MVP.

### 6.3 Security of letting userspace load BPF

In short: BPF is a kernel-attached interpreter executing user-supplied
bytecode. Without a verifier this is equivalent to letting userspace
write to kernel memory through a thin syntactic wrapper. The set of
known Linux CVEs against the BPF verifier alone is in the dozens; the
set against the helpers and JIT is larger.

For an MVP intended to gate behind capability checks and serve a
small, well-known set of programs, the risk is bounded but non-zero.
For any future opening of the surface to untrusted users, the verifier
work is mandatory and represents the single largest item in the
roadmap.

### 6.4 Performance of interpreter-only

Per kernel.org docs, interpreter overhead is ~5-20× JIT. For E2
socket-filter on a loopback test, this is invisible. For E3 syscall
tracing, a typical 50-instruction program adds ~500-2000 ns per
syscall — on a syscall-heavy workload (Firefox at 120k syscalls/sec)
that is 60-240 ms/sec of overhead, i.e. 6-24 % CPU. Acceptable for
debug-on builds; not acceptable for always-on tracing.

Mitigation: keep the tracing tap `cfg`-gated (`#[cfg(feature = "ebpf-trace")]`)
so the overhead is purely opt-in. The fast path when no programs are
attached is one atomic load of an `AtomicUsize` "attached count" + a
branch; cost ≪ 10 ns.

### 6.5 Cross-subsystem ownership

eBPF touches: the Linux personality (`bpf(2)` syscall), the native
kernel (`bpf` subsystem itself), the net stack (E2 hook), the
scheduler (E3 hook conceptually in syscall path which the scheduler
governs), the fd table (`proc`), the memory subsystem (map allocs).
No existing specialist owns it cleanly.

Mitigation: the `bpf/` subsystem should be owned by the `principal-systems-engineer`
role through MVP; once E1 lands and the surface stabilises, ownership
can move to a hypothetical `bpf-engineer` or stay with the network
specialist (E2 hooks are net-heavy, E3 hooks are syscall-heavy).

---

## 7. Decision matrix for the user

| If you want... | Pursue | LOC | Wall-time (1 IC) |
|---|---|---|---|
| Substrate for any future BPF work | **E1** | 2000 | 2-3 weeks |
| Cheapest meaningful functional win | **E1+E4** (real seccomp) | 2200 | 3-4 weeks |
| Recognisable demo screenshot | **E1+E2** (tcpdump filter) | 2400 | 3-4 weeks |
| Best ops/observability story | **E1+E3** (syscall tracing) | 2600 | 4-5 weeks |
| Full MVP | **E1+E2+E3+E4** | 3200 | 5-7 weeks |
| Production-grade BPF | E1+E2+E3+E4+verifier+JIT | 30,000+ | 6+ months |

**Recommended green-light:** E1+E4. Best value-per-LOC; closes a
real gap. Defer E2/E3 until a concrete need surfaces.

---

## 8. Out-of-scope (intentional)

- libbpf shim or compatibility layer in userspace.
- `bpftool` port.
- bpftrace, bcc, or any DSL.
- BTF support.
- The 80 % of BPF program types and 90 % of map types listed in
  Section 1 as "Defer".
- Any verifier work beyond the trivial loader stub.
- Any JIT.

---

## 9. Hand-back checklist (for whoever picks up E1)

If the user green-lights E1:

1. Read `kernel/src/perf/mod.rs` end-to-end (the `SYSCALL_RING` is the
   template for the BPF dispatch tap).
2. Read `kernel/src/subsys/linux/syscall.rs:850-919` (the existing
   diagnostic taps establish the cfg-gated tap pattern).
3. Read the public eBPF ISA at kernel.org/doc/html/latest/bpf/instruction-set.html
   end-to-end before writing a line of the interpreter.
4. Sketch the helper dispatch table first; the opcode table is
   mechanical once the dispatch shape is fixed.
5. Land in three PRs: PR #N = ISA + interpreter + `BPF_PROG_TEST_RUN`;
   PR #N+1 = ARRAY map + `BPF_MAP_*` cmds; PR #N+2 = `bpf(2)` wiring
   + test_runner integration test.
6. Do **not** ship E1 with helpers beyond the safe-on-any-arg set
   (ktime, trace_printk, prandom, smp_processor_id, and the three map
   ops). Other helpers wait for E3.
