//! FS_BASE preserve-across-execution probe.
//!
//! Records every kernel-side write to the `IA32_FS_BASE` MSR
//! (Intel SDM Vol. 3A §3.4.4.1, MSR `0xC000_0100`) into a fixed-capacity
//! ring keyed by `(cpu, pid, tid)`.  When the SSP-canary `#GP` fires from
//! CPL 3 at the musl `__stack_chk_fail` `HLT;RET` stub (Intel SDM Vol. 2A
//! `HLT`/`RET`, Vol. 3A §6.15 `#GP`), the existing `[SSP-DIAG]` block is
//! followed by `[FS-BASE-TRACE]` lines dumping the trapping TID's last
//! events.  This dispositively distinguishes:
//!
//!   * **Preserved-across-execution**: every event for the trapping TID
//!     since `execve` shows the same FS.base value (the userspace
//!     `arch_prctl(ARCH_SET_FS, X)` write); the canary fail cannot be
//!     a kernel FS.base shift.
//!
//!   * **Shifted**: a kernel write between the libxul function's
//!     prologue (`mov %fs:0x28, %rax`) and its epilogue (`cmp 0x50(%rsp),
//!     %fs:0x28`) changed FS.base for this TID — e.g. an out-of-order
//!     restore on a context switch, a stale fork-child slot, or a
//!     direct WRMSR from another path that doesn't go through
//!     `proc::write_fs_base`.
//!
//! ## Why this probe exists despite K2b / U2
//!
//! K2b's "32 fires all CPL 3, ZERO kernel writes" verdict (see
//! `k2b-f3-user-writer-2026-05-20`) only audited writes to the
//! **canary slot** at the user VA `0x7ffffffee4c0`.  It did not audit
//! writes to the **MSR**.  Similarly U2's audit covered the value-shape
//! of the FS.base the kernel writes — it did not audit the *time-order*
//! of those writes against the libxul prologue/epilogue.  An FS.base
//! that was X at prologue (`canary_stored = *fs:0x28` reads phys page
//! of `X+0x28`) and Y at epilogue (`live_canary = *fs:0x28` reads phys
//! page of `Y+0x28`) makes the SSP compare fail AND still satisfies
//! `ax_eq_fs28 == 1` at trap time (the trap-time re-read trivially
//! agrees with itself).  Only an event history of MSR writes can rule
//! this out.
//!
//! ## Sites instrumented
//!
//! Each site calls `record_event(kind, old_fs, new_fs, caller_rip)`
//! BEFORE the WRMSR (so `old_fs = rdmsr` reflects what was loaded
//! *before* the new write):
//!
//!   - `proc::write_fs_base()` — the canonical kernel API; covers
//!     `restore_tls_for_current()` (scheduler context-switch
//!     in `sched/mod.rs`) AND `enter_user_mode()` (boot, exec, and
//!     fork-child bootstrap via `user_mode_bootstrap`).  Kind:
//!     `KIND_WRITE_FS_BASE`.
//!
//!   - `subsys/linux/syscall::sys_arch_prctl(ARCH_SET_FS)` — explicit
//!     userspace request via `arch_prctl(2)` system call (musl uses
//!     this for the master TCB setup).  Kind: `KIND_ARCH_PRCTL`.
//!
//! Not instrumented:
//!
//!   - `proc/thread.rs::ret_from_fork_asm` — pure `naked_asm` WRMSR.
//!     Per the surrounding comments in `proc/mod.rs::create_fork_process_impl`
//!     the current vfork path uses `user_mode_bootstrap` (which DOES
//!     route through `write_fs_base`) instead of `ret_from_fork_asm`,
//!     so this is a paper-only gap unless the legacy fork path is
//!     re-enabled.  Flagged in the dispatch report.
//!
//!   - Test-runner test cases that round-trip FS.base via raw
//!     `hal::wrmsr(0xC000_0100, _)` — not on the firefox-test path.
//!
//! ## Ring sizing
//!
//! 1024 entries × 40 bytes = 40 KiB BSS, only when the
//! `fs-base-trace` feature is enabled.  At typical firefox-test sc rate
//! (~2000 syscalls per boot, of which only a fraction WRMSR FS.base —
//! arch_prctl is one-shot, context-switches are scheduler-bounded), 1024
//! is comfortably oversized.  The ring is lossy via monotonic
//! `WRITE_IDX.fetch_add`; if it ever wraps, the dump's `events_total`
//! vs `events_emitted` gap calls it out.
//!
//! ## Output volume + safety
//!
//! - One `[FS-BASE-TRACE-START] tid=N events_total=M events_in_ring=K`
//!   header line per trap, then up to `FS_BASE_DUMP_MAX` event lines
//!   matching the TID filter.  Capped at 8 dumps per boot via
//!   `AtomicU32::fetch_add` (matches the SSP-DIAG cap so the two
//!   diagnostics emit as a synchronised batch).
//! - All ring access is under `spin::Mutex` with `try_lock` on the
//!   trap-time read path; a lock-contended trap drops the dump and emits
//!   a single `[FS-BASE-TRACE] reject reason=ring_locked` line.
//! - Writers (`record_event`) hold the lock briefly (one store + index
//!   bump).  The scheduler context-switch path runs with interrupts
//!   disabled per `sched/mod.rs`, so re-entry is impossible there.  The
//!   `arch_prctl` path runs with interrupts enabled but the WRMSR is
//!   uninterruptible so the recording window is the same code section
//!   as the MSR write itself.
//!
//! ## Refs
//!
//! - Intel SDM Vol. 3A §3.4.4.1 (`IA32_FS_BASE` MSR, 0xC000_0100)
//! - Intel SDM Vol. 3A §6.15 (`#GP`)
//! - Intel SDM Vol. 2B (`SYSRETQ` — does NOT auto-reload MSRs;
//!   FS_BASE persists across the syscall fast-path return)
//! - System V AMD64 ABI §6.4 (TLS variant II — `__stack_chk_guard`
//!   at TCB offset `0x28`)
//! - POSIX vfork(2), clone(2) (FS.base inheritance for CLONE_VM
//!   children)
//! - musl libc public docs — `arch_prctl(2)` usage for TCB setup

#![cfg(feature = "fs-base-trace")]

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Kind tag — `proc::write_fs_base` (covers context-switch, exec, boot,
/// fork bootstrap via `user_mode_bootstrap`).
pub const KIND_WRITE_FS_BASE: u8 = 1;

/// Kind tag — explicit `arch_prctl(ARCH_SET_FS, addr)` from CPL 3.
pub const KIND_ARCH_PRCTL: u8 = 2;

/// Kind tag — currently unused; reserved for `ret_from_fork_asm` if
/// future asm-side instrumentation is added.
pub const KIND_RET_FROM_FORK: u8 = 3;

/// Maximum events recorded per boot — sized to cover a firefox-test
/// soak (typically <100 FS.base writes per boot per TID; 1024 is ~10×
/// safety margin even with multi-thread libxul).
const RING_CAPACITY: usize = 1024;

/// Maximum per-TID events dumped per trap (last-N from the ring).
const FS_BASE_DUMP_PER_TID: usize = 32;

/// Maximum dump events per boot.
const FS_BASE_DUMP_MAX: u32 = 8;

#[derive(Clone, Copy)]
struct Event {
    valid: bool,
    cpu: u8,
    kind: u8,
    pid: u64,
    tid: u64,
    old_fs: u64,
    new_fs: u64,
    caller_rip: u64,
    sc_count: u64,
    seq: u64,
}

impl Event {
    const EMPTY: Self = Self {
        valid: false,
        cpu: 0, kind: 0,
        pid: 0, tid: 0,
        old_fs: 0, new_fs: 0,
        caller_rip: 0,
        sc_count: 0, seq: 0,
    };
}

/// The ring buffer.  Lossy via the monotonic `WRITE_IDX` increment; if
/// `WRITE_IDX > RING_CAPACITY`, older events have been overwritten and
/// the dump's header reports the gap.
static RING: spin::Mutex<[Event; RING_CAPACITY]> =
    spin::Mutex::new([Event::EMPTY; RING_CAPACITY]);

/// Monotonic event sequence; also indexes into RING via `mod RING_CAPACITY`.
static WRITE_IDX: AtomicU64 = AtomicU64::new(0);

/// Per-boot dump emission counter.
static DUMP_COUNT: AtomicU32 = AtomicU32::new(0);

/// Per-boot reject (lock-contention) counter — keeps reject lines bounded.
static REJECT_COUNT: AtomicU32 = AtomicU32::new(0);
const REJECT_MAX: u32 = 4;

/// Record one FS.base write event into the ring.  Called from each
/// WRMSR site BEFORE the actual MSR write so `old_fs = rdmsr` captures
/// the value being replaced.
///
/// `caller_rip` is the kernel `RIP` of the WRMSR site for post-mortem
/// attribution against `kernel.elf` via `addr2line`; pass the result
/// of `core::intrinsics::caller_location()` or equivalently a hard-
/// coded label.
///
/// SAFETY: This function may be called with interrupts disabled (the
/// scheduler context-switch path) — the spin::Mutex is brief and bounded.
pub fn record_event(kind: u8, old_fs: u64, new_fs: u64, caller_rip: u64) {
    let seq = WRITE_IDX.fetch_add(1, Ordering::Relaxed);
    let idx = (seq as usize) % RING_CAPACITY;

    let cpu = crate::arch::x86_64::apic::cpu_index();
    let tid = crate::proc::current_tid();
    let pid = crate::proc::current_pid_lockless();
    let sc_count = crate::syscall::FIREFOX_SYSCALL_COUNT.load(Ordering::Relaxed);

    // try_lock — never block the WRMSR path on a concurrent dump.  Loss
    // here is acceptable: this entry is dropped, the next event lands at
    // the next index.
    if let Some(mut ring) = RING.try_lock() {
        ring[idx] = Event {
            valid: true,
            cpu: cpu as u8,
            kind,
            pid,
            tid,
            old_fs,
            new_fs,
            caller_rip,
            sc_count,
            seq,
        };
    }
    // else: dropped; the dump can detect this via the `events_total`
    // vs filled-entry-count gap.
}

/// Emit the last ≤`FS_BASE_DUMP_PER_TID` ring events for the given TID
/// at trap time.  Called from `idt.rs` immediately after the existing
/// `[SSP-DIAG]` block.
///
/// The output is a header line followed by one event per line:
///
/// ```text
/// [FS-BASE-TRACE-START] tid=N events_total=M events_in_ring=K wrapped={0|1}
/// [FS-BASE-TRACE]   seq=… cpu=… kind=… pid=… tid=… old_fs=… new_fs=… delta_changed=… rip=… sc=…
/// ```
pub fn dump_for_tid(tid: u64) {
    if DUMP_COUNT.fetch_add(1, Ordering::Relaxed) >= FS_BASE_DUMP_MAX {
        return;
    }

    let total = WRITE_IDX.load(Ordering::Relaxed);
    let wrapped = total > RING_CAPACITY as u64;
    let ring_view = match RING.try_lock() {
        Some(g) => g,
        None => {
            if REJECT_COUNT.fetch_add(1, Ordering::Relaxed) < REJECT_MAX {
                crate::serial_println!(
                    "[FS-BASE-TRACE] reject reason=ring_locked tid={}",
                    tid,
                );
            }
            return;
        }
    };

    // Pass 1: count TID-matching entries to compute the events_in_ring
    // header field.
    let mut matched = 0u64;
    for e in ring_view.iter() {
        if e.valid && e.tid == tid {
            matched += 1;
        }
    }

    crate::serial_println!(
        "[FS-BASE-TRACE-START] tid={} events_total={} events_for_tid={} wrapped={}",
        tid, total, matched, if wrapped { 1 } else { 0 },
    );

    // Pass 2: collect TID-matching entries into a small bounded heap
    // ordered by seq (ascending), keep only the last `FS_BASE_DUMP_PER_TID`.
    // We do this in a single pass with a fixed-size scan.
    let mut latest_seqs = [0u64; FS_BASE_DUMP_PER_TID];
    let mut latest_count: usize = 0;
    for e in ring_view.iter() {
        if !e.valid || e.tid != tid {
            continue;
        }
        if latest_count < FS_BASE_DUMP_PER_TID {
            latest_seqs[latest_count] = e.seq;
            latest_count += 1;
        } else {
            // Find smallest seq slot, replace if e.seq is bigger.
            let (min_idx, min_val) = latest_seqs.iter().enumerate()
                .min_by_key(|(_, v)| **v)
                .map(|(i, v)| (i, *v))
                .unwrap_or((0, 0));
            if e.seq > min_val {
                latest_seqs[min_idx] = e.seq;
            }
        }
    }

    // Sort the captured seqs ascending (small N, insertion sort).
    let slice = &mut latest_seqs[..latest_count];
    for i in 1..slice.len() {
        let mut j = i;
        while j > 0 && slice[j - 1] > slice[j] {
            slice.swap(j - 1, j);
            j -= 1;
        }
    }

    // Pass 3: emit in seq order.  Each emitted line names the source
    // event; the reviewer reconstructs prologue-vs-epilogue FS.base
    // by reading old_fs/new_fs from the timeline.
    for &target_seq in slice.iter() {
        if let Some(e) = ring_view.iter().find(|e| e.valid && e.seq == target_seq) {
            let kind_str = match e.kind {
                KIND_WRITE_FS_BASE => "write_fs_base",
                KIND_ARCH_PRCTL    => "arch_prctl_set_fs",
                KIND_RET_FROM_FORK => "ret_from_fork_asm",
                _                  => "unknown",
            };
            let changed = if e.old_fs == e.new_fs { 0 } else { 1 };
            crate::serial_println!(
                "[FS-BASE-TRACE] seq={} cpu={} kind={} pid={} tid={} \
                 old_fs={:#x} new_fs={:#x} changed={} rip={:#x} sc={}",
                e.seq, e.cpu, kind_str, e.pid, e.tid,
                e.old_fs, e.new_fs, changed, e.caller_rip, e.sc_count,
            );
        }
    }

    crate::serial_println!(
        "[FS-BASE-TRACE-END] tid={} emitted={}",
        tid, latest_count,
    );
}
